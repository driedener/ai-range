"""Blue agent tools for SentinelOne: telemetry via PowerQuery, alerts via Unified Alert Management
(GraphQL), incidents, response, vulnerabilities (xSPM GraphQL).

Same tool names as the Elastic variant (list_alerts, get_alert, update_alerts, create_case,
response_action), so that prompts, trace and scorer (triage counting) stay the same for both platforms.
Telemetry tool: `powerquery` instead of `esql`.

Alerts come from UAM (all sources: EDR, STAR/custom rules, Identity, …), IDs are UAM UUIDs. Host isolation
and agent status go through the REST API (/agents), threat mitigation through UAM actions (S1/kill …).
Permissions are enforced by the S1 console (role of the service user); in addition everything is limited to the
range site (S1_SITE_ID) and the known range hosts.
"""
from __future__ import annotations

import asyncio
import functools
import re
from typing import Any, Awaitable, Callable

from claude_agent_sdk import SdkMcpTool

from ..config import RANGE_HOSTS, settings
from ..runner import make_tool, text_result
from ..topology import TOPOLOGY
from ..sentinelone import S1Error, SentinelOne, to_iso
from ..uam import (ACTION_INCIDENT_ADD, ACTION_INCIDENT_CREATE, ACTION_NOTE, ACTION_STATUS, ACTION_VERDICT,
                   MITIGATION_ACTIONS, STATUS_TO_UAM, UAM, VERDICT_SHORT, VERDICTS, alert_hosts, f_contains, f_in,
                   f_range, mitre_ids, parse_ts, rule_name, short_host, summary)
from ..xspm import SEVERITIES as XSPM_SEVERITIES
from ..xspm import (GROUP_FIELDS, SORT_FIELDS, STATUS_TO_XSPM, VERDICT_TO_XSPM, XSPM, XSPM_TO_STATUS, by_cve, f_bool,
                    f_match, group_row)
from ..xspm import summary as summary_vuln
from .blue import SEVERITIES, ToolError, compact_lines, format_esql, trunc

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
PQ_MAX_ROWS = 200
PQ_DEFAULT_ROWS = 100
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
RANGE_HOSTNAMES = set(RANGE_HOSTS.values())
# Example hostnames for tool descriptions (from range.yaml)
EX_CLIENT, DC_NAME = TOPOLOGY.example("client"), TOPOLOGY.dc.name
UUID_RE = re.compile(r"^[0-9a-fA-F-]{20,64}$")


def safe(handler: Callable[[dict], Awaitable[Any]]) -> Callable[[dict], Awaitable[dict]]:
    """Exceptions -> tool errors (is_error), so the agent sees the message and can correct itself."""
    @functools.wraps(handler)
    async def wrapper(args: dict) -> dict:
        try:
            res = await handler(args or {})
        except S1Error as e:
            return text_result(f"SentinelOne error: {e}", is_error=True)
        except ToolError as e:
            return text_result(str(e), is_error=True)
        except Exception as e:  # noqa: BLE001 – never abort the agent run
            return text_result(f"{type(e).__name__}: {e}", is_error=True)
        if isinstance(res, dict) and "content" in res:
            return res
        return text_result(res if isinstance(res, str) else compact_lines(res))
    return wrapper


# --------------------------------------------------------------------------- PowerQuery

PQ_DESCRIPTION = f"""PowerQuery against the SentinelOne telemetry (Deep Visibility / Singularity Data Lake, read-only).
Result: column names + rows, at most {PQ_MAX_ROWS} rows (a `| limit` is appended or reduced if needed) –
aggregate with `| group … by …` instead of pulling raw data. The range site is automatically prepended as a filter.

Structure: <filter> | <command> | <command> …   Filter: field = 'x', field contains 'x', field in ('a','b'),
field matches 'regex', and/or/not, strings in single quotes; contains is case-insensitive.
Commands: columns a, b | group n = count() by a, b | sort -n | limit 50 | filter … | let x = …

Important fields (EDR schema):
- event.type: 'Process Creation', 'IP Connect', 'IP Listen', 'DNS Resolved', 'Login', 'Logout', 'File Creation',
  'File Modification', 'File Deletion', 'Registry Value Modified', 'Registry Key Create', 'Open Remote Process Handle',
  'Duplicate Process Handle', 'Behavioral Indicators', 'Command Script', 'Task Register', 'Named Pipe Creation'
- endpoint.name (hostname, e.g. '{EX_CLIENT.upper()}'), endpoint.os, agent.uuid, event.time, site.id
- src.process.name, .cmdline, .user, .pid, .storyline.id, .image.path, .parent.name, .parent.cmdline, .integrityLevel
- tgt.process.name, .cmdline, .user, .pid  (process start: child = tgt.process, parent = src.process)
- tgt.file.path, tgt.file.sha1  |  registry.keyPath, registry.value
- src.ip.address, src.port.number, dst.ip.address, dst.port.number, event.network.direction  |  event.dns.request
- event.login.userName, event.login.type, event.login.loginIsSuccessful, event.login.accountDomain
- indicator.name, indicator.category, indicator.description  (for event.type = 'Behavioral Indicators')
Hosts: {', '.join(sorted(set(RANGE_HOSTS.values())))} (endpoint.name mostly uppercase, contains does not care);
domain {settings.domain}. Attacker IPs e.g. in src.ip.address / dst.ip.address.

Examples:
  event.type = 'Process Creation' and endpoint.name contains '{EX_CLIENT}'
    | columns event.time, endpoint.name, src.process.user, src.process.name, tgt.process.cmdline | sort -event.time | limit 50
  event.type = 'Login' and event.login.loginIsSuccessful = false
    | group fails = count() by src.ip.address, event.login.userName | sort -fails
  tgt.process.cmdline contains 'mimikatz' or tgt.process.name in ('rubeus.exe', 'procdump.exe')
Time range via start/end (default: last 24 h)."""

_PQ_LIMIT_RE = re.compile(r"\|\s*limit\s+(\d+)\s*$", re.IGNORECASE)


def enforce_pq_limit(query: str, max_rows: int) -> str:
    q = query.strip().rstrip(";").strip()
    m = _PQ_LIMIT_RE.search(q)
    if m and int(m.group(1)) <= max_rows:
        return q
    if m:
        return q[: m.start()] + f"| limit {max_rows}"
    return f"{q} | limit {max_rows}"


def format_pq(data: dict, max_rows: int) -> str:
    """Table result in the same compact format as the ES|QL tool."""
    res = {"columns": [{"name": c.get("name")} for c in data.get("columns") or []],
           "values": data.get("values") or []}
    txt = format_esql(res, max_rows)
    extras = []
    if data.get("matchCount") is not None:
        extras.append(f"matchCount: {data['matchCount']:.0f}")
    if data.get("partialResultsDueToTimeLimit"):
        extras.append("WARNING: partial result (time limit) – narrow down time range/query.")
    if data.get("omittedEvents"):
        extras.append(f"WARNING: {data['omittedEvents']:.0f} events omitted due to memory/cardinality limit.")
    for w in data.get("warnings") or []:
        extras.append(f"Note: {w}")
    return "\n".join([txt, *extras])


def build_pq_tool(s1: SentinelOne) -> SdkMcpTool:
    @safe
    async def powerquery(args: dict) -> dict:
        query = (args.get("query") or "").strip()
        if not query:
            raise ToolError("query missing")
        max_rows = max(1, min(int(args.get("max_rows") or PQ_DEFAULT_ROWS), PQ_MAX_ROWS))
        data = await s1.powerquery(enforce_pq_limit(query, max_rows), args.get("start") or "24h", args.get("end"))
        return text_result(format_pq(data, max_rows))

    return make_tool("powerquery", PQ_DESCRIPTION, {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "PowerQuery: <filter> | <commands>"},
            "start": {"type": "string", "description": "Start: relative (e.g. 2h, 30m, now-1h) or ISO time; default 24h"},
            "end": {"type": "string", "description": "End (ISO or relative); default now"},
            "max_rows": {"type": "integer", "minimum": 1, "maximum": PQ_MAX_ROWS,
                         "description": f"Max. rows (default {PQ_DEFAULT_ROWS}, at most {PQ_MAX_ROWS})"},
        },
        "required": ["query"],
    }, powerquery)



# --------------------------------------------------------------------------- Alerts (UAM)

def check_ids(ids: list[str]) -> list[str]:
    ids = [str(i).strip() for i in ids if i]
    bad = [i for i in ids if not UUID_RE.match(i)]
    if bad:
        raise ToolError(f"Invalid alert ID(s) {bad[:3]} – use IDs from list_alerts (UUID)")
    if not ids:
        raise ToolError("ids missing")
    return ids


def verdict_value(v: str) -> str:
    val = VERDICT_SHORT.get(str(v).lower(), str(v).upper())
    if val not in VERDICTS:
        raise ToolError(f"verdict: short form {list(VERDICT_SHORT)} or one of {VERDICTS}")
    return val


def check_range_alert(a: dict) -> None:
    """Actions affecting endpoints only for alerts on range hosts."""
    hosts = alert_hosts(a)
    if not hosts or not set(hosts) <= RANGE_HOSTNAMES:
        raise ToolError(f"Alert {a.get('id')}: host(s) {hosts or '?'} do not belong to the range – refused.")


def _trigger_result(res: dict) -> dict:
    if "scheduled" in res:
        return {"scheduled": True, "execution_id": res["scheduled"],
                "note": "Scheduled asynchronously – check the result later via get_alert."}
    return res


def build_alert_tools(s1: SentinelOne, uam: UAM) -> list[SdkMcpTool]:
    @safe
    async def list_alerts(args: dict) -> dict:
        statuses = args.get("status") or ["open", "acknowledged"]
        if isinstance(statuses, str):
            statuses = [statuses]
        if any(s not in STATUS_TO_UAM for s in statuses):
            raise ToolError("status: only open | acknowledged | closed")
        limit = max(1, min(int(args.get("limit") or 50), 200))
        since = to_iso(args.get("since"), "now-24h")
        filters = [f_in("status", [STATUS_TO_UAM[s] for s in statuses]),
                   f_range("createdAt", parse_ts(since))]
        if args.get("host"):
            filters.append(f_contains("assetName", short_host(args["host"])))
        if args.get("min_severity"):
            sev = args["min_severity"].lower()
            if sev not in SEVERITIES:
                raise ToolError(f"min_severity must be one of {SEVERITIES}")
            filters.append(f_in("severity", [s.upper() for s in SEVERITIES[SEVERITIES.index(sev):]]))
        if args.get("rule"):
            filters.append(f_contains("alertName", args["rule"]))
        if args.get("source"):
            filters.append(f_in("detectionProduct", [args["source"]]))
        alerts, total = await uam.alerts(filters, limit=limit)
        rows = [summary(a) for a in alerts]
        by_rule: dict[str, int] = {}
        by_host: dict[str, int] = {}
        for a, r in zip(alerts, rows):
            by_rule[rule_name(a)] = by_rule.get(rule_name(a), 0) + 1
            by_host[r.get("host", "?")] = by_host.get(r.get("host", "?"), 0) + 1
        return {"total": total, "returned": len(rows),
                "by_rule": dict(sorted(by_rule.items(), key=lambda x: -x[1])[:15]),
                "by_host": dict(sorted(by_host.items(), key=lambda x: -x[1])[:15]),
                "alerts": rows}

    @safe
    async def get_alert(args: dict) -> dict:
        aid = check_ids([args.get("id")])[0]
        a = await uam.detail(aid)
        if not a:
            raise ToolError(f"Alert {aid} not found (or not in the range site)")
        out: dict[str, Any] = summary(a)
        out["description"] = trunc(a.get("description"), 1500)
        proc = a.get("process") or {}
        user = proc.get("username") or ""
        out["process_user"] = (user if "\\" in user or not proc.get("userDomain")
                               else proc["userDomain"] + "\\" + user) or None
        f = proc.get("file") or {}
        out["process_file"] = {k: f.get(k) for k in ("path", "sha1", "sha256", "isSignatureValid", "certSubject")
                               if f.get(k) not in (None, "")}
        out["command_line"] = trunc(proc.get("cmdLine"), 2000)
        out["mitre"] = mitre_ids(a, a)
        out["indicators"] = [{
            "time": i.get("eventTime"), "type": i.get("type"), "title": i.get("title"),
            "message": trunc((i.get("message") or "").strip(), 300) or None, "severity": i.get("severity"),
            "attacks": [f"{(x.get('tactic') or {}).get('name')}: {(x.get('technique') or {}).get('uid')}"
                        for x in i.get("attacks") or []],
            "observables": [f"{o.get('name')}={trunc(o.get('value'), 200)}" for o in i.get("observables") or []][:10],
            "powerquery_filter": trunc((i.get("eventSearchParams") or {}).get("filter"), 600),
        } for i in a.get("indicators") or []][:30]
        out["observables"] = [f"{o.get('name')}={trunc(o.get('value'), 200)}" for o in a.get("observables") or []][:20]
        out["related_alerts"] = [f"{r.get('id')} {r.get('name')}" for r in a.get("relatedAlerts") or []][:20]
        out["notes"] = [{"at": n.get("createdAt"), "text": trunc(n.get("text"), 800)} for n in await uam.notes(aid)]
        out["timeline"] = [f"{t.get('createdAt')} [{t.get('eventType')}] {trunc(t.get('eventText'), 300)}"
                           for t in await uam.timeline(aid)]
        if a.get("storylineId"):
            out["hint"] = f"Process tree/activity: powerquery with src.process.storyline.id = '{a['storylineId']}'"
        return {k: v for k, v in out.items() if v not in (None, [], "", {})}

    @safe
    async def update_alerts(args: dict) -> dict:
        ids = check_ids(args.get("ids") or [])
        status, verdict, note = args.get("status"), args.get("verdict"), (args.get("note") or "").strip()
        if not status and not verdict and not note:
            raise ToolError("Nothing to do: specify status, verdict and/or note")
        actions: list[dict] = []
        if status:
            if status not in STATUS_TO_UAM:
                raise ToolError("status must be open|acknowledged|closed")
            actions.append({"id": ACTION_STATUS, "payload": {"status": {"value": STATUS_TO_UAM[status]}}})
        if verdict:
            actions.append({"id": ACTION_VERDICT, "payload": {"analystVerdict": {"value": verdict_value(verdict)}}})
        result: dict[str, Any] = {"ids": ids}
        if actions:
            result["actions"] = _trigger_result(await uam.trigger(ids, actions))
        if note:
            for aid in ids:
                await uam.add_note(aid, note[:10000])
            result["notes_added"] = len(ids)
        return result

    return [
        make_tool("list_alerts", (
            "SentinelOne alerts from Unified Alert Management (all sources: EDR, STAR/custom rules, Identity …), "
            "newest first, compact: id, time, name, source, analytic, severity, status (open=NEW, "
            "acknowledged=IN_PROGRESS, closed=RESOLVED), verdict, host, user, process/command line, storyline, "
            "incident – plus counts per rule/host. Details: get_alert."), {
            "type": "object",
            "properties": {
                "status": {"type": "array", "items": {"type": "string", "enum": list(STATUS_TO_UAM)},
                           "description": "Workflow status (default: open + acknowledged)"},
                "since": {"type": "string", "description": "Start time: now-24h, -90m, 2h or ISO (default now-24h)"},
                "host": {"type": "string", "description": f"Only this host (substring, e.g. {EX_CLIENT})"},
                "min_severity": {"type": "string", "enum": SEVERITIES, "description": "Minimum severity"},
                "rule": {"type": "string", "description": "Substring in the alert name"},
                "source": {"type": "string", "description": "Only this product, e.g. EDR, STAR, Identity"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200, "description": "Max. alerts (default 50)"},
            },
        }, list_alerts),
        make_tool("get_alert", (
            "Details of an alert: description, process (user, file, hash, command line), indicators with time, "
            "MITRE attacks, observables and a ready-made PowerQuery filter, related alerts, notes, timeline."), {
            "type": "object",
            "properties": {"id": {"type": "string", "description": "Alert ID from list_alerts"}},
            "required": ["id"],
        }, get_alert),
        make_tool("update_alerts", (
            "Set status (open|acknowledged|closed), analyst verdict and/or note (Markdown) for alerts. "
            f"Verdict short forms: {', '.join(VERDICT_SHORT)} – or an exact value such as "
            "TRUE_POSITIVE_UNAUTHORIZED_ACCESS / FALSE_POSITIVE_BENIGN. Convention: set the verdict after triage; "
            "leave confirmed incidents acknowledged or document them via create_case, false positives closed."), {
            "type": "object",
            "properties": {
                "ids": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                "status": {"type": "string", "enum": list(STATUS_TO_UAM)},
                "verdict": {"type": "string"},
                "note": {"type": "string", "description": "Note (Markdown) on every alert"},
            },
            "required": ["ids"],
        }, update_alerts),
    ]


# --------------------------------------------------------------------------- Case = UAM-Incident

def build_case_tool(s1: SentinelOne, uam: UAM) -> SdkMcpTool:
    @safe
    async def create_case(args: dict) -> dict:
        title = (args.get("title") or "").strip()
        description = (args.get("description") or "").strip()
        if not title or not description:
            raise ToolError("title and description are mandatory")
        severity = (args.get("severity") or "medium").lower()
        if severity not in SEVERITIES:
            raise ToolError(f"severity must be one of {SEVERITIES}")
        ids = check_ids(args.get("alert_ids") or [])
        name = f"[ai-range] {title}"[:200]
        out: dict[str, Any] = {"title": name, "severity": severity, "alert_ids": ids}
        if args.get("incident_id"):
            act = {"id": ACTION_INCIDENT_ADD, "payload": {"addToIncident": {"id": args["incident_id"], "name": name}}}
        else:
            act = {"id": ACTION_INCIDENT_CREATE, "payload": {"createIncident": {"name": name,
                                                                                "severity": severity.upper()}}}
        out["incident"] = _trigger_result(await uam.trigger(ids, [act]))
        # Case text as a note (the incident description is deprecated in UAM)
        md = f"## {name}\n\n**Severity:** {severity}\n\n{description}"
        for aid in ids:
            await uam.add_note(aid, md[:10000])
        out["notes_added"] = len(ids)
        await uam.trigger(ids, [{"id": ACTION_STATUS, "payload": {"status": {"value": "IN_PROGRESS"}}}])
        alerts, _ = await uam.alerts([f_in("id", ids)], limit=len(ids))
        out["incidents"] = sorted({f"{a['incident']['id']} {a['incident']['name']}" for a in alerts if a.get("incident")})
        return out

    return make_tool("create_case", (
        "Document a confirmed incident as a SentinelOne incident: creates an incident '[ai-range] <title>' "
        "(or attaches to an existing one via incident_id), adds the alerts, writes the case text as a "
        "Markdown note on every alert and sets them to acknowledged (IN_PROGRESS). description: summary, "
        "affected hosts/users, timeline, IOCs, MITRE techniques, actions taken or recommended."), {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "description": {"type": "string", "description": "Markdown"},
            "severity": {"type": "string", "enum": SEVERITIES, "description": "Default medium"},
            "alert_ids": {"type": "array", "items": {"type": "string"}, "minItems": 1,
                          "description": "Alert IDs from list_alerts"},
            "incident_id": {"type": "string", "description": "Optional: existing incident (from list_alerts/get_alert)"},
            "tags": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["title", "description", "alert_ids"],
    }, create_case)


# --------------------------------------------------------------------------- Response Actions

RESPONSE_ACTIONS = ["isolate", "release", "mitigate", "status"]


def check_range_agent(agent: dict, site_id: str) -> None:
    name = short_host(agent.get("computerName"))
    if name not in RANGE_HOSTNAMES:
        raise ToolError(f"{agent.get('computerName')}: not a range host – refused.")
    if site_id and str(agent.get("siteId")) != site_id:
        raise ToolError(f"{agent.get('computerName')}: agent is not in the range site – refused.")


def _agent_info(a: dict) -> dict:
    return {k: a.get(k) for k in ("id", "computerName", "networkStatus", "isActive", "lastActiveDate",
                                  "infected", "activeThreats", "mitigationMode", "agentVersion", "lastIpToMgmt")}


def _recommend(action: str, host: Any, reason: str, detail: str = "") -> dict:
    return {"executed": False, "recommended_only": True, "action": action, "host": host, "reason": reason,
            "message": f"Response mode is '{settings.blue_response_mode}': action '{action}' {detail} on {host} "
                       "was NOT executed, only logged as a recommendation. "
                       "List it as a recommended action in the report/case."}


def build_response_tool(s1: SentinelOne, uam: UAM) -> SdkMcpTool:
    async def resolve(host: str) -> dict:
        short = short_host(host)
        if not short or not re.fullmatch(r"[a-z0-9-]+", short):
            raise ToolError(f"Invalid hostname: {host!r}")
        matches = await s1.find_agents(short)
        if not matches:
            raise ToolError(f"{host}: no SentinelOne agent with this name in the range site")
        if len(matches) > 1:
            active = [a for a in matches if a.get("isActive")]
            if len(active) != 1:
                raise ToolError(f"{host}: ambiguous ({len(matches)} agents, e.g. after a reinstall)")
            matches = active
        check_range_agent(matches[0], s1.site_id)
        return matches[0]

    async def wait_network(agent_id: str, target: str, wait_s: int) -> dict:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + wait_s
        while True:
            agents = await s1.paged("/agents", {"ids": [agent_id]}, limit=1)
            a = agents[0] if agents else {}
            if a.get("networkStatus") == target or loop.time() >= deadline:
                return a
            await asyncio.sleep(3)

    @safe
    async def response_action(args: dict) -> dict:
        action = args.get("action")
        if action not in RESPONSE_ACTIONS:
            raise ToolError(f"action must be one of {RESPONSE_ACTIONS}")
        reason = (args.get("reason") or "").strip()
        if action != "status" and not reason:
            raise ToolError("reason is mandatory (justification)")
        wait_s = max(0, min(int(args.get("wait_seconds", 45)), 120))

        if action == "mitigate":
            aid = check_ids([args.get("alert_id")])[0]
            mitigation = args.get("mitigation") or "kill"
            if mitigation not in MITIGATION_ACTIONS:
                raise ToolError(f"mitigation must be one of {list(MITIGATION_ACTIONS)}")
            alerts, _ = await uam.alerts([f_in("id", [aid])], limit=1)
            if not alerts:
                raise ToolError(f"Alert {aid} not found (or not in the range site)")
            check_range_alert(alerts[0])
            host = ", ".join(alert_hosts(alerts[0]))
            if settings.blue_response_mode != "auto":
                return _recommend(action, host, reason, f"{mitigation} alert {aid}")
            res = await uam.trigger([aid], [{"id": MITIGATION_ACTIONS[mitigation]}])
            await uam.add_note(aid, f"[ai-range blue] {mitigation}: {reason}")
            return {"executed": True, "action": f"mitigate/{mitigation}", "alert": aid, "host": host,
                    "result": _trigger_result(res),
                    "note": "Mitigation runs asynchronously on the agent – check the result via get_alert (result/timeline)."}

        agent = await resolve(args.get("host") or "")
        if action == "status":
            return {"executed": True, "action": "status", **_agent_info(agent)}
        if settings.blue_response_mode != "auto":
            return _recommend(action, agent.get("computerName"), reason)
        path, target = {"isolate": ("disconnect", "disconnected"), "release": ("connect", "connected")}[action]
        r = await s1.api("POST", f"/agents/actions/{path}", json={"filter": {"ids": [agent["id"]]}})
        after = await wait_network(agent["id"], target, wait_s) if wait_s else agent
        out = {"executed": True, "action": action, "affected": (r.get("data") or {}).get("affected"),
               "reason": reason, **_agent_info(after)}
        if after.get("networkStatus") != target:
            out["note"] = f"networkStatus still {after.get('networkStatus')!r} – check later with action=status."
        return out

    return make_tool("response_action", (
        "SentinelOne response on a range endpoint: isolate (Disconnect from Network – only the connection to the "
        "S1 console remains), release (reconnect to the network), status (agent/network status, read-only; host), "
        "mitigate (alert mitigation via UAM: alert_id + mitigation kill|quarantine|remediate|rollback). "
        "Arbitrary PIDs cannot be killed with S1 – only detected threats. Isolate/mitigate only on "
        f"confirmed compromise and with a justification (reason) – isolating {DC_NAME}/servers interrupts the "
        "domain. If the response mode is 'off', nothing is executed, it is only logged as a recommendation."), {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": RESPONSE_ACTIONS},
            "host": {"type": "string", "description": f"Hostname (isolate/release/status), e.g. {EX_CLIENT}"},
            "alert_id": {"type": "string", "description": "Alert ID for mitigate"},
            "mitigation": {"type": "string", "enum": list(MITIGATION_ACTIONS), "description": "Default kill"},
            "reason": {"type": "string", "description": "Justification (mandatory except for status)"},
            "wait_seconds": {"type": "integer", "minimum": 0, "maximum": 120,
                             "description": "Max. time to wait for the network status (default 45)"},
        },
        "required": ["action"],
    }, response_action)


# --------------------------------------------------------------------------- Vulnerabilities (xSPM)

VULN_MAX_ROWS = 100
VULN_SCAN_ROWS = 500        # at most this many findings are fetched and summarized for the CVE view
VULN_UPDATE_MAX = 200       # upper limit per update_vulnerabilities call
VULN_AGENT_STATUSES = ["new", "in_progress"]


def range_host_filter(host: str | None = None) -> dict:
    """Always limit findings to range hosts – the site may also contain other assets."""
    if not host:
        return f_match("assetName", sorted(RANGE_HOSTNAMES))
    short = short_host(host)
    if short not in RANGE_HOSTNAMES:
        raise ToolError(f"{host}: not a range host ({', '.join(sorted(RANGE_HOSTNAMES))})")
    return f_match("assetName", [short])


def check_cve(cve: str) -> str:
    cve = str(cve or "").strip().upper()
    if not CVE_RE.match(cve):
        raise ToolError(f"Invalid CVE ID {cve!r} (format CVE-YYYY-NNNN)")
    return cve


def vuln_filters(args: dict) -> list[dict]:
    filters = [range_host_filter(args.get("host"))]
    statuses = args.get("status") or ["new", "in_progress"]
    if isinstance(statuses, str):
        statuses = [statuses]
    if any(s not in STATUS_TO_XSPM for s in statuses):
        raise ToolError(f"status: only {' | '.join(STATUS_TO_XSPM)}")
    filters.append(f_in("status", [STATUS_TO_XSPM[s] for s in statuses]))
    if args.get("min_severity"):
        sev = args["min_severity"].upper()
        if sev not in XSPM_SEVERITIES:
            raise ToolError(f"min_severity must be one of {SEVERITIES}")
        filters.append(f_in("severity", XSPM_SEVERITIES[XSPM_SEVERITIES.index(sev):]))
    if args.get("cve"):
        filters.append(f_in("cveId", [check_cve(args["cve"])]))
    if args.get("software"):
        filters.append(f_match("softwareName", [str(args["software"])], "contains"))
    for arg, field in (("exploited_in_wild", "cveExploitedInTheWild"), ("kev", "cveKevAvailable"),
                       ("fix_available", "softwareFixVersionAvailable")):
        if args.get(arg) is not None:
            filters.append(f_bool(field, args[arg]))
    if args.get("since"):
        filters.append(f_range("detectedAt", parse_ts(to_iso(args["since"]))))
    return filters


def build_vuln_tools(xspm: XSPM) -> list[SdkMcpTool]:
    @safe
    async def list_vulnerabilities(args: dict) -> dict:
        filters = vuln_filters(args)
        group_by = args.get("group_by") or "cve"
        if group_by not in ("cve", "none", *GROUP_FIELDS):
            raise ToolError(f"group_by: cve | none | {' | '.join(GROUP_FIELDS)}")
        sort = args.get("sort") or "risk"
        if sort not in SORT_FIELDS:
            raise ToolError(f"sort: {' | '.join(SORT_FIELDS)}")
        limit = max(1, min(int(args.get("limit") or 30), VULN_MAX_ROWS))
        counts = await xspm.counts(filters, ["severity", "status", "cveExploitedInTheWild"])
        out: dict[str, Any] = {
            "by_severity": {k.lower(): v for k, v in counts.get("severity", {}).items()},
            "by_status": {XSPM_TO_STATUS.get(k, k): v for k, v in counts.get("status", {}).items()},
            "exploited_in_wild": counts.get("cveExploitedInTheWild", {}).get("true", 0),
        }
        if group_by in GROUP_FIELDS:
            nodes, total = await xspm.groups(filters, GROUP_FIELDS[group_by], limit, ["severity", "cveId"])
            out.update(groups_total=total, groups=[group_row(n) for n in nodes])
            return out
        rows, total = await xspm.vulnerabilities(filters, VULN_SCAN_ROWS if group_by == "cve" else limit,
                                                 SORT_FIELDS[sort])
        out = {"total_findings": total, **out}
        if group_by == "none":
            out.update(returned=len(rows), vulnerabilities=[summary_vuln(v) for v in rows])
            return out
        cves = by_cve(rows)
        out.update(scanned_findings=len(rows), cves_in_scan=len(cves), cves=cves[:limit])
        if total > len(rows):
            out["note"] = (f"Only the first {len(rows)} of {total} findings (sort: {sort}) are summarized – "
                           "narrow the filters (host, min_severity, exploited_in_wild, kev, software).")
        return out

    @safe
    async def get_vulnerability(args: dict) -> dict:
        vid = check_ids([args.get("id")])[0]
        v = await xspm.detail(vid)
        if not v:
            raise ToolError(f"Finding {vid} not found (or not in the range site)")
        if short_host((v.get("asset") or {}).get("name")) not in RANGE_HOSTNAMES:
            raise ToolError(f"Finding {vid}: host {(v.get('asset') or {}).get('name')!r} does not belong to the range – refused.")
        cve, sw, asset = v.get("cve") or {}, v.get("software") or {}, v.get("asset") or {}
        out: dict[str, Any] = summary_vuln(v)
        out["description"] = trunc(cve.get("description"), 1500)
        out["asset"] = {k: asset.get(k) for k in ("type", "category", "osType", "criticality", "riskFactors", "status")
                        if asset.get(k) not in (None, [], "")}
        out["software_detail"] = {k: sw.get(k) for k in ("vendor", "type", "paths") if sw.get(k) not in (None, [], "")}
        out["cve_detail"] = {k: cve.get(k) for k in ("epssPercentile", "kevAvailable", "remediationLevel",
                                                     "reportConfidence", "publishedDate", "nvdReferenceUrl")
                             if cve.get(k) is not None}
        out["cvss_vector"] = {k: val for k, val in (cve.get("s1BaseValues") or {}).items() if val}
        out["risk_indicators"] = {str(r.get("severity")).lower(): r.get("values") for r in cve.get("riskIndicators") or []}
        out["cve_timeline"] = [f"{t.get('date')} {t.get('key')}" for t in cve.get("timeline") or []]
        out["assignee"] = (v.get("assignee") or {}).get("fullName")
        out["attack_path"] = v.get("attackPathExists")
        out["link"] = v.get("selfLink")
        if cve.get("id"):
            rel = await xspm.related([f_in("cveId", [cve["id"]]), range_host_filter()])
            out["same_cve_on"] = [f"{short_host(r['asset'].get('name'))} ({r['software'].get('name')} "
                                  f"{r['software'].get('version')}) id={r['vulnerabilityId']}" for r in rel][:40]
        out["notes"] = [{"at": n.get("createdAt"), "by": (n.get("author") or {}).get("fullName"),
                         "text": trunc(n.get("text"), 800)} for n in await xspm.notes(vid)]
        out["history"] = [f"{h.get('createdAt')} [{h.get('eventType')}] {trunc(h.get('eventText'), 300)}"
                          for h in await xspm.history(vid)]
        return {k: val for k, val in out.items() if val not in (None, [], "", {})}

    @safe
    async def update_vulnerabilities(args: dict) -> dict:
        status, verdict, note = args.get("status"), args.get("verdict"), (args.get("note") or "").strip()
        if not status and not verdict and not note:
            raise ToolError("Nothing to do: specify status, verdict and/or note")
        if status and status not in VULN_AGENT_STATUSES:
            raise ToolError(f"status: only {' | '.join(VULN_AGENT_STATUSES)} – accepting the risk or marking as resolved "
                            "is decided by the human (write it as a recommendation in the note).")
        if verdict and verdict not in VERDICT_TO_XSPM:
            raise ToolError(f"verdict: {' | '.join(VERDICT_TO_XSPM)}")
        ids, cve = args.get("ids") or [], args.get("cve")
        if bool(ids) == bool(cve):
            raise ToolError("Specify either ids OR cve (optionally with host)")
        # The range host filter also applies to IDs: findings of other assets are thus never modified
        filters = [range_host_filter(args.get("host"))]
        filters.append(f_in("id", check_ids(ids)) if ids else f_in("cveId", [check_cve(cve)]))
        _, total = await xspm.vulnerabilities(filters, limit=1)
        if not total:
            raise ToolError("No finding on range hosts matches this selection")
        if total > VULN_UPDATE_MAX:
            raise ToolError(f"{total} findings affected (limit {VULN_UPDATE_MAX}) – narrow the selection with host")
        res = await xspm.update(filters, STATUS_TO_XSPM.get(status), VERDICT_TO_XSPM.get(verdict),
                                f"[ai-range blue] {note}"[:10000] if note else None)
        return {"matched_findings": total, **res}

    flt = {
        "host": {"type": "string", "description": f"Only this range host (e.g. {EX_CLIENT})"},
        "min_severity": {"type": "string", "enum": SEVERITIES, "description": "Minimum severity"},
        "status": {"type": "array", "items": {"type": "string", "enum": list(STATUS_TO_XSPM)},
                   "description": "Default: new + in_progress"},
        "cve": {"type": "string", "description": "Exactly this CVE (CVE-YYYY-NNNN)"},
        "software": {"type": "string", "description": "Substring in the software/package name"},
        "exploited_in_wild": {"type": "boolean", "description": "Only actively exploited CVEs (true) or only not exploited (false)"},
        "kev": {"type": "boolean", "description": "Only CVEs in the CISA KEV catalog"},
        "fix_available": {"type": "boolean", "description": "Only findings with an available fix version"},
        "since": {"type": "string", "description": "Detected only since this time: now-24h, -90m or ISO"},
    }
    return [
        make_tool("list_vulnerabilities", (
            "Vulnerability findings of the range hosts from Singularity Vulnerability Management (xSPM). One finding = "
            "one CVE on one host in one piece of software; there are tens of thousands, mostly low. Always returns the "
            "counts per severity/status plus – depending on group_by – cve (default): per CVE risk score (S1, 0–10), CVSS, "
            "EPSS, exploited_in_wild, affected hosts/software, fix, example_id; host/software: number of findings per "
            "host or package with severity distribution; none: individual findings with id. Sorted by sort "
            "(default risk, descending). Details of a finding: get_vulnerability."), {
            "type": "object",
            "properties": {
                **flt,
                "group_by": {"type": "string", "enum": ["cve", "host", "software", "none"], "description": "Default cve"},
                "sort": {"type": "string", "enum": list(SORT_FIELDS), "description": "Default risk (not for host/software)"},
                "limit": {"type": "integer", "minimum": 1, "maximum": VULN_MAX_ROWS,
                          "description": "Max. rows (default 30)"},
            },
        }, list_vulnerabilities),
        make_tool("get_vulnerability", (
            "Details of a finding: CVE description, CVSS vector, EPSS, KEV, risk indicators (threat intel), "
            "CVE timeline, software/paths and fix version, the same CVE on other range hosts (with finding IDs), "
            "notes and history."), {
            "type": "object",
            "properties": {"id": {"type": "string", "description": "Finding ID (id/example_id from list_vulnerabilities)"}},
            "required": ["id"],
        }, get_vulnerability),
        make_tool("update_vulnerabilities", (
            "Record the triage result on findings: verdict (true_positive = applies and is relevant, "
            "false_positive = does not apply on the host), status (in_progress = should be patched/mitigated, "
            "new = reset) and/or a note with justification and recommended action. Selection via ids OR via "
            f"cve (then all findings of this CVE on the range hosts, optionally only on host); at most {VULN_UPDATE_MAX} "
            "findings per call. Only the human sets resolved/risk accepted."), {
            "type": "object",
            "properties": {
                "ids": {"type": "array", "items": {"type": "string"}, "minItems": 1, "description": "Finding IDs"},
                "cve": {"type": "string", "description": "Alternative to ids: all findings of this CVE"},
                "host": {"type": "string", "description": "Additionally limit the selection to this range host"},
                "status": {"type": "string", "enum": VULN_AGENT_STATUSES},
                "verdict": {"type": "string", "enum": list(VERDICT_TO_XSPM)},
                "note": {"type": "string", "description": "Justification/recommendation (text)"},
            },
        }, update_vulnerabilities),
    ]


# --------------------------------------------------------------------------- Entry point

def build_blue_tools_s1(s1: SentinelOne) -> list[SdkMcpTool]:
    from .blue_s1_network import build_device_tool, build_firewall_tool  # noqa: PLC0415 – avoid circular import

    uam = UAM(s1)
    return [build_pq_tool(s1), *build_alert_tools(s1, uam), build_case_tool(s1, uam), build_response_tool(s1, uam),
            build_device_tool(s1), build_firewall_tool(s1), *build_vuln_tools(XSPM(s1))]
