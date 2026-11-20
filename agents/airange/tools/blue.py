"""Blue agent tools (SOC analyst): telemetry via ES|QL, alert triage, cases, response.

All calls run as the Elastic user blue-agent (role range_blue) – whatever the role
is not allowed to do (e.g. read range-groundtruth) fails in Elastic, not only here.
"""
from __future__ import annotations

import asyncio
import functools
import json
import re
from typing import Any, Awaitable, Callable

from claude_agent_sdk import SdkMcpTool

from ..config import settings
from ..elastic import Elastic, ElasticError
from ..runner import make_tool, text_result
from ..topology import TOPOLOGY

# Example hostnames for tool descriptions (from range.yaml)
EX_CLIENT, EX_LINUX, DC_NAME = TOPOLOGY.example("client"), TOPOLOGY.example("linux_server"), TOPOLOGY.dc.name

ALERTS_INDEX = ".alerts-security.alerts-default"
ESQL_MAX_ROWS = 200
ESQL_DEFAULT_ROWS = 100
CELL_MAX_CHARS = 1000
RESULT_MAX_CHARS = 40000
SEVERITIES = ["low", "medium", "high", "critical"]
# Only endpoints with these agent policies count as range endpoints (response actions)
RANGE_AGENT_POLICIES = {"range-windows", "range-linux"}


# --------------------------------------------------------------------------- Helpers

def safe(handler: Callable[[dict], Awaitable[Any]]) -> Callable[[dict], Awaitable[dict]]:
    """Exceptions -> tool errors (is_error), so the agent sees the message and can correct itself."""
    @functools.wraps(handler)
    async def wrapper(args: dict) -> dict:
        try:
            res = await handler(args or {})
        except ElasticError as e:
            return text_result(f"Elastic error: {e}", is_error=True)
        except ToolError as e:
            return text_result(str(e), is_error=True)
        except Exception as e:  # noqa: BLE001 – never abort the agent run
            return text_result(f"{type(e).__name__}: {e}", is_error=True)
        if isinstance(res, dict) and "content" in res:
            return res
        return text_result(res if isinstance(res, str) else compact_lines(res))
    return wrapper


class ToolError(RuntimeError):
    """Expected error with a message for the agent."""


def trunc(v: Any, n: int = CELL_MAX_CHARS) -> Any:
    if isinstance(v, str) and len(v) > n:
        return v[:n] + f"…[+{len(v) - n}]"
    return v


def flatten(obj: Any, prefix: str = "", out: dict | None = None) -> dict:
    """Nested dicts -> dotted keys (lists stay lists)."""
    out = {} if out is None else out
    if isinstance(obj, dict):
        for k, v in obj.items():
            flatten(v, f"{prefix}.{k}" if prefix else k, out)
    else:
        out[prefix] = obj
    return out


def get(src: dict, dotted: str) -> Any:
    """Read a field from _source – alerts mix flat ("kibana.alert.x") and nested keys."""
    if dotted in src:
        return src[dotted]
    cur: Any = src
    parts = dotted.split(".")
    i = 0
    while i < len(parts):
        if not isinstance(cur, dict):
            return None
        # take the longest matching (possibly itself dotted) key
        for j in range(len(parts), i, -1):
            key = ".".join(parts[i:j])
            if key in cur:
                cur, i = cur[key], j
                break
        else:
            return None
    return cur


def compact_json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"), default=str)


def compact_lines(data: Any) -> str:
    """Token-efficient but readable: one top-level key per line, lists of objects one line per element."""
    if not isinstance(data, dict):
        return compact_json(data)
    lines = []
    for k, v in data.items():
        if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
            lines.append(f"{k}: [")
            lines.extend(f"  {compact_json(x)}," for x in v)
            lines.append("]")
        else:
            lines.append(f"{k}: {compact_json(v)}")
    return "\n".join(lines)


def mitre_ids(threat: Any) -> list[str]:
    ids: list[str] = []
    for th in threat or []:
        for te in th.get("technique") or []:
            subs = [st.get("id") for st in te.get("subtechnique") or []]
            ids.extend(subs or [te.get("id")])
    return [i for i in ids if i]


# --------------------------------------------------------------------------- ES|QL

ESQL_DESCRIPTION = f"""ES|QL query against the range telemetry (read-only). Result: column names + rows.
At most {ESQL_MAX_ROWS} rows are returned (a LIMIT is appended or reduced if needed) –
aggregate with STATS ... BY instead of pulling raw data. Long values are truncated.

Sources (namespace "range"; patterns with * allowed):
- logs-endpoint.events.process-*  (Elastic Defend: process.name, process.command_line, process.pid,
  process.entity_id, process.parent.name, process.parent.command_line, process.executable, user.name, event.action start/end)
- logs-endpoint.events.network-*, .file-*, .registry-*, .library-*, .security-* (logon), .api-*
- logs-windows.sysmon_operational-*  (Sysmon; event.code "1"=ProcessCreate, "3"=Network, "7"=ImageLoad,
  "8"=CreateRemoteThread, "10"=ProcessAccess e.g. LSASS, "11"=FileCreate, "13"=Registry, "22"=DNS; fields winlog.event_data.*)
- logs-system.security-*  (Windows Security log: event.code "4624"/"4625" logon, "4688" process, "4768"/"4769" Kerberos,
  "4720" user created, "4732"/"4728" groups; winlog.event_data.TargetUserName, winlog.logon.type, source.ip)
- logs-windows.powershell-*, logs-windows.powershell_operational-*  (event.code "4104" ScriptBlock: powershell.file.script_block_text)
- logs-system.auth-*, logs-system.syslog-*  (Linux: SSH logins, sudo), logs-auditd_manager.auditd-*  (Linux auditd)
- metrics-*  (system metrics)
- {ALERTS_INDEX}  (security alerts: kibana.alert.rule.name, kibana.alert.severity, kibana.alert.workflow_status,
  kibana.alert.risk_score, kibana.alert.reason)
Hosts: host.name is lowercase ({', '.join(v.host for v in TOPOLOGY.targets)});
domain {TOPOLOGY.domain}. Attacker IPs show up e.g. in source.ip / destination.ip.

Syntax examples:
  FROM logs-endpoint.events.process-* | WHERE @timestamp > NOW() - 1 hour AND host.name == "{EX_CLIENT}"
    | KEEP @timestamp, host.name, user.name, process.name, process.command_line | SORT @timestamp DESC | LIMIT 50
  FROM logs-system.security-* | WHERE event.code == "4625" AND @timestamp > NOW() - 24 hours
    | STATS fails = COUNT(*) BY source.ip, winlog.event_data.TargetUserName | SORT fails DESC
  FROM logs-* | WHERE process.command_line LIKE "*mimikatz*" OR TO_LOWER(process.name) == "rubeus.exe"
Notes: strings in double quotes; equality "=="; wildcards only with LIKE/RLIKE;
time: NOW() - 30 minutes; field names with special characters in backticks."""

_LIMIT_RE = re.compile(r"\|\s*LIMIT\s+(\d+)\s*$", re.IGNORECASE)


def enforce_limit(query: str, max_rows: int) -> str:
    q = query.strip().rstrip(";").strip()
    m = _LIMIT_RE.search(q)
    if m and int(m.group(1)) <= max_rows:
        return q
    if m:
        return q[: m.start()] + f"| LIMIT {max_rows}"
    return f"{q}\n| LIMIT {max_rows}"


def format_esql(res: dict, max_rows: int) -> str:
    cols = [c["name"] for c in res.get("columns", [])]
    rows = [[trunc(v) for v in row] for row in res.get("values", [])][:max_rows]
    lines = [f"columns: {compact_json(cols)}", f"rows: {len(rows)}"]
    size = sum(len(l) for l in lines)
    shown = 0
    for row in rows:
        line = compact_json(row)
        if size + len(line) > RESULT_MAX_CHARS:
            lines.append(f"…[{len(rows) - shown} more rows truncated – narrow down/aggregate the query]")
            break
        lines.append(line)
        size += len(line)
        shown += 1
    if res.get("is_partial"):
        lines.append("WARNING: result is partial (is_partial=true).")
    return "\n".join(lines)


def build_esql_tool(es: Elastic) -> SdkMcpTool:
    @safe
    async def esql(args: dict) -> dict:
        query = (args.get("query") or "").strip()
        if not query:
            raise ToolError("query missing")
        max_rows = max(1, min(int(args.get("max_rows") or ESQL_DEFAULT_ROWS), ESQL_MAX_ROWS))
        q = enforce_limit(query, max_rows)
        res = await es.esql(q)
        return text_result(format_esql(res, max_rows))

    return make_tool("esql", ESQL_DESCRIPTION, {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "ES|QL query, starting with FROM <index-pattern>"},
            "max_rows": {"type": "integer", "minimum": 1, "maximum": ESQL_MAX_ROWS,
                         "description": f"Max. rows (default {ESQL_DEFAULT_ROWS}, at most {ESQL_MAX_ROWS})"},
        },
        "required": ["query"],
    }, esql)


# --------------------------------------------------------------------------- Alerts

def alert_summary(hit: dict) -> dict:
    s = hit.get("_source", {})
    out = {
        "id": hit.get("_id"),
        "@timestamp": get(s, "@timestamp"),
        "rule": get(s, "kibana.alert.rule.name"),
        "severity": get(s, "kibana.alert.severity"),
        "risk_score": get(s, "kibana.alert.risk_score"),
        "status": get(s, "kibana.alert.workflow_status"),
        "host": get(s, "host.name"),
        "user": get(s, "user.name"),
        "process": get(s, "process.name"),
        "pid": get(s, "process.pid"),
        "command_line": trunc(get(s, "process.command_line"), 400),
        "source_ip": get(s, "source.ip"),
        "mitre": mitre_ids(get(s, "kibana.alert.rule.threat")),
        "tags": get(s, "kibana.alert.workflow_tags") or None,
    }
    return {k: v for k, v in out.items() if v not in (None, [], "")}


async def search_alerts(es: Elastic, body: dict) -> dict:
    return await es.kibana("POST", "/api/detection_engine/signals/search", json=body)


async def fetch_alerts_by_id(es: Elastic, ids: list[str]) -> list[dict]:
    r = await search_alerts(es, {"size": len(ids), "query": {"ids": {"values": ids}}})
    return r["hits"]["hits"]


def build_alert_tools(es: Elastic) -> list[SdkMcpTool]:
    @safe
    async def list_alerts(args: dict) -> dict:
        statuses = args.get("status") or ["open", "acknowledged"]
        if isinstance(statuses, str):
            statuses = [statuses]
        limit = max(1, min(int(args.get("limit") or 50), 200))
        filters: list[dict] = [
            {"terms": {"kibana.alert.workflow_status": statuses}},
            {"range": {"@timestamp": {"gte": args.get("since") or "now-24h"}}},
            # Building block alerts are intermediate results, not analyst alerts
            {"bool": {"must_not": {"exists": {"field": "kibana.alert.building_block_type"}}}},
        ]
        if args.get("host"):
            filters.append({"term": {"host.name": {"value": args["host"].split(".")[0], "case_insensitive": True}}})
        if args.get("min_severity"):
            sev = args["min_severity"].lower()
            if sev not in SEVERITIES:
                raise ToolError(f"min_severity must be one of {SEVERITIES}")
            filters.append({"terms": {"kibana.alert.severity": SEVERITIES[SEVERITIES.index(sev):]}})
        if args.get("rule"):
            filters.append({"match_phrase": {"kibana.alert.rule.name": args["rule"]}})
        body = {
            "size": limit,
            "query": {"bool": {"filter": filters}},
            "sort": [{"@timestamp": {"order": "desc"}}],
            "_source": ["@timestamp", "kibana.alert.*", "host.name", "user.name", "process.name", "process.pid",
                        "process.command_line", "source.ip"],
            "aggs": {
                "rules": {"terms": {"field": "kibana.alert.rule.name", "size": 15}},
                "hosts": {"terms": {"field": "host.name", "size": 15}},
            },
            "track_total_hits": True,
        }
        r = await search_alerts(es, body)
        aggs = r.get("aggregations", {})
        return {
            "total": r["hits"]["total"]["value"],
            "returned": len(r["hits"]["hits"]),
            "by_rule": {b["key"]: b["doc_count"] for b in aggs.get("rules", {}).get("buckets", [])},
            "by_host": {b["key"]: b["doc_count"] for b in aggs.get("hosts", {}).get("buckets", [])},
            "alerts": [alert_summary(h) for h in r["hits"]["hits"]],
        }

    drop_prefixes = (
        "kibana.alert.rule.parameters", "kibana.alert.rule.actions", "kibana.alert.rule.exceptions_list",
        "kibana.alert.rule.note", "kibana.alert.rule.references", "kibana.alert.rule.false_positives",
        "kibana.alert.rule.risk_score_mapping", "kibana.alert.rule.severity_mapping", "kibana.alert.rule.threat",
        "kibana.alert.ancestors", "kibana.alert.rule.execution", "kibana.alert.rule.created",
        "kibana.alert.rule.updated", "kibana.alert.rule.producer", "kibana.alert.rule.consumer",
        "kibana.alert.rule.rule_type_id", "kibana.alert.rule.revision", "kibana.alert.rule.license",
        "kibana.space_ids", "kibana.version", "kibana.alert.url", "elastic_agent.", "agent.build", "ecs.",
        "data_stream.", "input.", "kibana.alert.original_data_stream", "kibana.alert.rule.timestamp_override",
        "kibana.alert.rule.author", "kibana.alert.rule.category", "kibana.alert.intended_timestamp",
    )

    @safe
    async def get_alert(args: dict) -> dict:
        aid = (args.get("id") or "").strip()
        if not aid:
            raise ToolError("id missing")
        hits = await fetch_alerts_by_id(es, [aid])
        if not hits:
            raise ToolError(f"Alert {aid} not found")
        src = hits[0]["_source"]
        flat = flatten(src)
        out: dict[str, Any] = {"id": hits[0]["_id"], "index": hits[0]["_index"]}
        for k in sorted(flat):
            if k.startswith(drop_prefixes):
                continue
            v = flat[k]
            if isinstance(v, list):
                v = [trunc(x, 500) if not isinstance(x, (dict, list)) else trunc(compact_json(x), 500) for x in v[:20]]
            out[k] = trunc(v, 2000)
        params = get(src, "kibana.alert.rule.parameters") or {}
        if params.get("query"):
            out["rule.query"] = trunc(params["query"], 1500)
        if params.get("index"):
            out["rule.index"] = params["index"]
        out["mitre"] = [
            f"{th.get('tactic', {}).get('id')} {th.get('tactic', {}).get('name')}: "
            + ", ".join(f"{te.get('id')} {te.get('name')}" for te in th.get("technique") or [])
            for th in get(src, "kibana.alert.rule.threat") or []
        ]
        desc = get(src, "kibana.alert.rule.description")
        if desc:
            out["kibana.alert.rule.description"] = trunc(desc, 800)
        return out

    @safe
    async def update_alerts(args: dict) -> dict:
        ids = [i for i in (args.get("ids") or []) if i]
        if not ids:
            raise ToolError("ids missing")
        status = args.get("status")
        add = args.get("add_tags") or []
        remove = args.get("remove_tags") or []
        if not status and not add and not remove:
            raise ToolError("Nothing to do: specify status and/or add_tags/remove_tags")
        result: dict[str, Any] = {"ids": ids}
        if status:
            if status not in ("open", "acknowledged", "closed"):
                raise ToolError("status must be open|acknowledged|closed")
            body: dict[str, Any] = {"signal_ids": ids, "status": status}
            r = await es.kibana("POST", "/api/detection_engine/signals/status", json=body)
            result["status"] = {"set": status, "updated": r.get("updated"), "failures": r.get("failures") or None}
        if add or remove:
            r = await es.kibana("POST", "/api/detection_engine/signals/tags", json={
                "ids": ids, "tags": {"tags_to_add": add, "tags_to_remove": remove}})
            result["tags"] = {"added": add, "removed": remove, "updated": r.get("updated"),
                              "failures": r.get("failures") or None}
        return result

    return [
        make_tool("list_alerts", (
            "List security alerts of the detection engine (newest first), compact: id, time, rule, severity, "
            "risk score, status, host, user, process/command line, MITRE IDs, tags – plus counts per rule/host. "
            "Building block alerts are hidden. Details of an alert: get_alert."), {
            "type": "object",
            "properties": {
                "status": {"type": "array", "items": {"type": "string", "enum": ["open", "acknowledged", "closed"]},
                           "description": "Workflow status (default: open + acknowledged)"},
                "since": {"type": "string", "description": "Start time, date math or ISO (default now-24h, e.g. now-1h)"},
                "host": {"type": "string", "description": f"Only alerts of this host (e.g. {EX_CLIENT}; case-insensitive)"},
                "min_severity": {"type": "string", "enum": SEVERITIES, "description": "Minimum severity"},
                "rule": {"type": "string", "description": "Only alerts of this rule (name, phrase match)"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200, "description": "Max. alerts (default 50)"},
            },
        }, list_alerts),
        make_tool("get_alert", (
            "Full (truncated) details of an alert by id: event fields (process.*, user.*, host.*, "
            "winlog.*, file.*, network ...), kibana.alert.reason, rule query, MITRE mapping."), {
            "type": "object",
            "properties": {"id": {"type": "string", "description": "Alert ID (field id from list_alerts)"}},
            "required": ["id"],
        }, get_alert),
        make_tool("update_alerts", (
            "Set the workflow status of alerts (open|acknowledged|closed) and/or add/remove tags. "
            "Convention: after triage set tag 'ai-range:true-positive' or 'ai-range:false-positive'; "
            "leave confirmed incidents acknowledged or document them via a case, false positives closed."), {
            "type": "object",
            "properties": {
                "ids": {"type": "array", "items": {"type": "string"}, "minItems": 1, "description": "Alert IDs"},
                "status": {"type": "string", "enum": ["open", "acknowledged", "closed"]},
                "add_tags": {"type": "array", "items": {"type": "string"}},
                "remove_tags": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["ids"],
        }, update_alerts),
    ]


# --------------------------------------------------------------------------- Cases

def build_case_tool(es: Elastic) -> SdkMcpTool:
    @safe
    async def create_case(args: dict) -> dict:
        title = (args.get("title") or "").strip()
        description = (args.get("description") or "").strip()
        if not title or not description:
            raise ToolError("title and description are mandatory")
        severity = (args.get("severity") or "medium").lower()
        if severity not in SEVERITIES:
            raise ToolError(f"severity must be one of {SEVERITIES}")
        tags = list(dict.fromkeys(["ai-range", *(args.get("tags") or [])]))
        case = await es.kibana("POST", "/api/cases", json={
            "title": title[:160],
            "description": description[:30000],
            "severity": severity,
            "tags": tags,
            "owner": "securitySolution",
            "connector": {"id": "none", "name": "none", "type": ".none", "fields": None},
            "settings": {"syncAlerts": True},
        })
        out: dict[str, Any] = {"case_id": case["id"], "title": case["title"], "status": case["status"],
                               "severity": case.get("severity"), "tags": case.get("tags")}
        ids = [i for i in (args.get("alert_ids") or []) if i]
        if ids:
            hits = await fetch_alerts_by_id(es, ids)
            found = {h["_id"] for h in hits}
            # One alert attachment per rule (alertId/index are parallel lists, rule is singular)
            by_rule: dict[str, dict] = {}
            for h in hits:
                s = h["_source"]
                rid = get(s, "kibana.alert.rule.uuid")
                g = by_rule.setdefault(rid, {"name": get(s, "kibana.alert.rule.name"), "ids": [], "idx": []})
                g["ids"].append(h["_id"])
                g["idx"].append(h["_index"])
            for rid, g in by_rule.items():
                await es.kibana("POST", f"/api/cases/{case['id']}/comments", json={
                    "type": "alert", "alertId": g["ids"], "index": g["idx"],
                    "rule": {"id": rid, "name": g["name"]}, "owner": "securitySolution"})
            out["attached_alerts"] = sorted(found)
            missing = [i for i in ids if i not in found]
            if missing:
                out["not_found_alerts"] = missing
        return out

    return make_tool("create_case", (
        "Create a Kibana case (Security) and attach alerts – to document a confirmed incident. "
        "description: Markdown with summary, affected hosts/users, timeline, IOCs, MITRE techniques, "
        "actions taken or recommended. Tag 'ai-range' is set automatically."), {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "description": {"type": "string", "description": "Markdown"},
            "severity": {"type": "string", "enum": SEVERITIES, "description": "Default medium"},
            "tags": {"type": "array", "items": {"type": "string"}},
            "alert_ids": {"type": "array", "items": {"type": "string"}, "description": "Alert IDs to attach"},
        },
        "required": ["title", "description"],
    }, create_case)


# --------------------------------------------------------------------------- Response Actions

RESPONSE_ACTIONS = {
    # name -> (API path, modifies the host?)
    "isolate": ("isolate", True),
    "release": ("unisolate", True),
    "kill-process": ("kill_process", True),
    "suspend-process": ("suspend_process", True),
    "running-processes": ("running_procs", False),
}


async def resolve_endpoint(es: Elastic, host: str) -> dict:
    """Hostname -> endpoint metadata; only range endpoints (agent policy range-windows/-linux)."""
    short = host.strip().split(".")[0].lower()
    if not short or not re.fullmatch(r"[a-z0-9-]+", short):
        raise ToolError(f"Invalid hostname: {host!r}")
    r = await es.kibana("GET", "/api/endpoint/metadata", params={"page": 0, "pageSize": 100})
    matches = []
    for ep in r.get("data", []):
        h = ep["metadata"]["host"]
        names = {str(h.get("hostname", "")).lower(), str(h.get("name", "")).lower().split(".")[0]}
        if short in names:
            matches.append(ep)
    if not matches:
        raise ToolError(f"{host}: no Elastic Defend endpoint with this name – response actions are only possible on "
                        "range endpoints with Elastic Defend.")
    if len(matches) > 1:
        raise ToolError(f"{host}: ambiguous ({len(matches)} endpoints)")
    ep = matches[0]
    policy = ((ep.get("policy_info") or {}).get("agent") or {}).get("configured", {}).get("id") \
        or ((ep.get("policy_info") or {}).get("agent") or {}).get("applied", {}).get("id")
    if policy not in RANGE_AGENT_POLICIES:
        raise ToolError(f"{host}: agent policy {policy!r} does not belong to the range – refused.")
    return ep


def _compact_action(a: dict) -> dict:
    out = {k: a.get(k) for k in ("id", "command", "isCompleted", "wasSuccessful", "status", "startedAt",
                                 "completedAt", "isExpired", "comment")}
    if a.get("errors"):
        out["errors"] = a["errors"]
    return {k: v for k, v in out.items() if v is not None}


def build_response_tool(es: Elastic) -> SdkMcpTool:
    @safe
    async def response_action(args: dict) -> dict:
        action = args.get("action")
        if action not in RESPONSE_ACTIONS:
            raise ToolError(f"action must be one of {list(RESPONSE_ACTIONS)}")
        host = args.get("host") or ""
        path, disruptive = RESPONSE_ACTIONS[action]
        reason = (args.get("reason") or "").strip()
        if disruptive and not reason:
            raise ToolError("reason is mandatory (justification, ends up in the action comment)")
        if disruptive and settings.blue_response_mode != "auto":
            return {"executed": False, "recommended_only": True, "action": action, "host": host, "reason": reason,
                    "message": f"Response mode is '{settings.blue_response_mode}': action '{action}' on {host} "
                               "was NOT executed, only logged as a recommendation. "
                               "List it as a recommended action in the report/case."}
        ep = await resolve_endpoint(es, host)
        meta = ep["metadata"]
        agent_id = meta["agent"]["id"]
        hostname = meta["host"]["hostname"]
        caps = set((meta.get("Endpoint") or {}).get("capabilities") or [])
        need_cap = {"isolate": "isolation", "release": "isolation", "kill-process": "kill_process",
                    "suspend-process": "suspend_process", "running-processes": "running_processes"}[action]
        if caps and need_cap not in caps:
            raise ToolError(f"{hostname} does not support '{need_cap}' (capabilities: {sorted(caps)})")

        body: dict[str, Any] = {"endpoint_ids": [agent_id],
                                "comment": f"[ai-range blue] {reason}" if reason else "[ai-range blue]"}
        if action in ("kill-process", "suspend-process"):
            if args.get("entity_id"):
                body["parameters"] = {"entity_id": str(args["entity_id"])}
            elif args.get("pid") is not None:
                body["parameters"] = {"pid": int(args["pid"])}
            else:
                raise ToolError("specify pid or entity_id (from alert/telemetry or running-processes)")

        r = await es.kibana("POST", f"/api/endpoint/action/{path}", json=body)
        act = r.get("data", r)
        action_id = act["id"]
        wait_s = max(0, min(int(args.get("wait_seconds", 45)), 120))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + wait_s
        while not act.get("isCompleted") and loop.time() < deadline:
            await asyncio.sleep(3)
            act = (await es.kibana("GET", f"/api/endpoint/action/{action_id}")).get("data", act)

        out: dict[str, Any] = {"executed": True, "host": hostname, "endpoint_agent_id": agent_id,
                               **_compact_action(act)}
        if not act.get("isCompleted"):
            out["note"] = "Not completed yet – check the status again later (endpoint may be offline/slow)."
        if action == "running-processes" and act.get("isCompleted"):
            entries = (((act.get("outputs") or {}).get(agent_id) or {}).get("content") or {}).get("entries") or []
            flt = (args.get("process_filter") or "").lower()
            if flt:
                entries = [e for e in entries if flt in str(e.get("command", "")).lower()
                           or flt in str(e.get("user", "")).lower()]
            out["process_count"] = len(entries)
            out["processes"] = [{"pid": e.get("pid"), "user": e.get("user"), "entity_id": e.get("entity_id"),
                                 "command": trunc(e.get("command"), 300)} for e in entries[:300]]
            if len(entries) > 300:
                out["note"] = f"{len(entries) - 300} more processes omitted – use process_filter."
        elif act.get("outputs"):
            o = (act["outputs"].get(agent_id) or {}).get("content")
            if o:
                out["output"] = trunc(compact_json(o), 2000)
        return out

    return make_tool("response_action", (
        f"Elastic Defend response action on a range endpoint (by hostname, e.g. {EX_CLIENT}). "
        "Actions: isolate (network isolation, only Elastic communication remains), release (lift isolation), "
        "kill-process / suspend-process (pid OR entity_id, e.g. process.entity_id from the alert), "
        "running-processes (process list, read-only; optional process_filter). "
        "Isolate/kill/suspend only on confirmed compromise and with a justification (reason) – isolating "
        f"{DC_NAME}/servers interrupts the domain. Waits briefly for completion and returns action ID + status. "
        "If the response mode is 'off', nothing is executed, it is only logged as a recommendation."), {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": list(RESPONSE_ACTIONS)},
            "host": {"type": "string", "description": f"Hostname of the endpoint (e.g. {EX_CLIENT}, {EX_LINUX})"},
            "reason": {"type": "string", "description": "Justification (mandatory except for running-processes)"},
            "pid": {"type": "integer", "description": "Process ID for kill-/suspend-process"},
            "entity_id": {"type": "string", "description": "process.entity_id for kill-/suspend-process (preferred)"},
            "process_filter": {"type": "string", "description": "running-processes: substring in command/user"},
            "wait_seconds": {"type": "integer", "minimum": 0, "maximum": 120,
                             "description": "Max. time to wait for completion (default 45)"},
        },
        "required": ["action", "host"],
    }, response_action)


# --------------------------------------------------------------------------- Entry point

def build_blue_tools(es: Elastic) -> list[SdkMcpTool]:
    return [build_esql_tool(es), *build_alert_tools(es), build_case_tool(es), build_response_tool(es)]
