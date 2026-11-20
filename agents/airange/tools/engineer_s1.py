"""Engineer agent tools for SentinelOne: telemetry via PowerQuery, search/read STAR/custom detection rules,
"preview" them via PowerQuery, create, update and disable them.

Guardrails (enforced in code):
- New rules are always named "ai-range: …", live in the range site (S1_SITE_ID) and have no
  automatic response (networkQuarantine=false, treatAsThreat=UNDEFINED).
- MITRE techniques are written into the description as a line "MITRE ATT&CK: T…" (STAR alerts have no
  MITRE field; the scorer reads the IDs from there).
- update_rule/disable_rule only act on rules with prefix "ai-range:" – other rules stay untouched.
"""
from __future__ import annotations

import re
from typing import Any

from claude_agent_sdk import SdkMcpTool

from ..runner import make_tool
from ..sentinelone import SentinelOne
from .blue import SEVERITIES, ToolError, trunc
from .blue_s1 import TECH_RE, build_pq_tool, format_pq, safe

NAME_PREFIX = "ai-range: "
QUERY_TYPES = ["events", "scheduled"]
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
MITRE_LINE = "MITRE ATT&CK:"


def _sev(value: str | None) -> str:
    sev = (value or "medium").lower()
    if sev not in SEVERITIES:
        raise ToolError(f"severity must be one of {SEVERITIES}")
    return sev.capitalize()


def _mitre(specs: list[str] | None) -> list[str]:
    out = []
    for raw in specs or []:
        tid = str(raw).strip().upper().rpartition(":")[2]
        if not TECHNIQUE_RE.match(tid):
            raise ToolError(f"Invalid technique ID {raw!r} – format T1234 or T1234.001")
        out.append(tid)
    return list(dict.fromkeys(out))


def _description(text: str, mitre: list[str]) -> str:
    """Description + exactly one MITRE line (an existing one is replaced)."""
    lines = [l for l in (text or "").strip().splitlines() if not l.startswith(MITRE_LINE)]
    if mitre:
        lines.append(f"{MITRE_LINE} {', '.join(mitre)}")
    return "\n".join(lines).strip()


def _own(rule: dict) -> bool:
    return str(rule.get("name", "")).startswith(NAME_PREFIX)


def compact_rule(r: dict, full: bool = False) -> dict:
    out: dict[str, Any] = {
        "id": r.get("id"), "name": r.get("name"), "type": r.get("queryType"), "status": r.get("status"),
        "severity": str(r.get("severity") or "").lower() or None, "scope": r.get("scope") or r.get("scopeName"),
        "ai_range": _own(r), "mitre": sorted(set(TECH_RE.findall(f"{r.get('name')} {r.get('description')}"))),
        "generated_alerts": r.get("generatedAlerts"), "last_alert": r.get("lastAlertTime"),
    }
    if r.get("statusReason"):
        out["status_reason"] = trunc(r["statusReason"], 300)
    if r.get("reachedLimit"):
        out["reached_limit"] = True
    if full:
        sp = r.get("scheduledParams") or {}
        out.update({
            "description": trunc(r.get("description"), 2000),
            "query": trunc(r.get("s1ql") or sp.get("query"), 3000),
            "query_lang": r.get("queryLang"),
            "scheduled": {k: sp.get(k) for k in ("runIntervalMinutes", "lookbackWindowMinutes", "threshold",
                                                 "alertPerRow")} if sp else None,
            "treat_as_threat": r.get("treatAsThreat"), "network_quarantine": r.get("networkQuarantine"),
            "creator": r.get("creator"), "created_at": r.get("createdAt"), "updated_at": r.get("updatedAt"),
            "editable": r.get("editable"),
        })
    return {k: v for k, v in out.items() if v not in (None, [], "", {})}


def _rule_data(args: dict, base: dict | None = None) -> dict:
    """Complete data object for POST/PUT (PUT requires all mandatory fields)."""
    base = base or {}
    qtype = args.get("type") or base.get("queryType")
    if qtype not in QUERY_TYPES:
        raise ToolError(f"type must be one of {QUERY_TYPES}")
    name = (args.get("name") or str(base.get("name", "")).removeprefix(NAME_PREFIX)).strip()
    if not name:
        raise ToolError("name is mandatory")
    old_desc = base.get("description") or ""
    mitre = _mitre(args["mitre"]) if args.get("mitre") is not None else sorted(set(TECH_RE.findall(old_desc)))
    desc = args.get("description") if args.get("description") is not None else old_desc
    if not desc:
        raise ToolError("description is mandatory")
    data: dict[str, Any] = {
        "name": (NAME_PREFIX + name.removeprefix(NAME_PREFIX))[:200],
        "description": _description(desc, mitre),
        "severity": _sev(args.get("severity") or base.get("severity")),
        "expirationMode": "Permanent",
        "queryType": qtype,
        "queryLang": "2.0",
        "status": "Active",
        "networkQuarantine": False,
        "treatAsThreat": "UNDEFINED",
    }
    query = args.get("query")
    if qtype == "events":
        data["s1ql"] = query or base.get("s1ql")
        if not data["s1ql"]:
            raise ToolError("query is mandatory")
        if "|" in data["s1ql"]:
            raise ToolError("events rules are a pure filter (S1QL 2.0) without '|' – for aggregations "
                            "use type=scheduled with PowerQuery")
    else:
        sp = dict(base.get("scheduledParams") or {})
        sp["query"] = query or sp.get("query")
        if not sp["query"]:
            raise ToolError("query is mandatory")
        sp["runIntervalMinutes"] = int(args.get("run_interval_minutes") or sp.get("runIntervalMinutes") or 5)
        sp["lookbackWindowMinutes"] = int(args.get("lookback_minutes") or sp.get("lookbackWindowMinutes") or 10)
        if args.get("threshold") is not None:
            sp["threshold"] = {"value": int(args["threshold"]), "operator": "Greater"}
        sp.setdefault("alertPerRow", True)
        data["scheduledParams"] = {k: v for k, v in sp.items() if v is not None}
    return data


_PROPS: dict[str, Any] = {
    "name": {"type": "string", "description": "Name (prefix 'ai-range: ' is added)"},
    "description": {"type": "string", "description": "What the rule detects, why, triage notes"},
    "type": {"type": "string", "enum": QUERY_TYPES,
             "description": "events: real-time rule, query = pure S1QL 2.0 filter (like the part before the first '|' "
                            "of a PowerQuery), one alert per matching event. scheduled: PowerQuery with "
                            "aggregation, runs every run_interval_minutes over lookback_minutes, one alert per row."},
    "query": {"type": "string"},
    "severity": {"type": "string", "enum": SEVERITIES},
    "mitre": {"type": "array", "items": {"type": "string"},
              "description": "ATT&CK techniques, e.g. ['T1003.001'] – end up as the MITRE line in the description"},
    "run_interval_minutes": {"type": "integer", "minimum": 1, "maximum": 1440, "description": "scheduled, Default 5"},
    "lookback_minutes": {"type": "integer", "minimum": 1, "maximum": 1440, "description": "scheduled, Default 10"},
    "threshold": {"type": "integer", "minimum": 0,
                  "description": "scheduled: alert only if the number of rows > threshold (default 0)"},
}


def build_engineer_tools_s1(s1: SentinelOne) -> list[SdkMcpTool]:
    async def _get(rule_id: str) -> dict:
        if not str(rule_id or "").isdigit():
            raise ToolError("id missing or invalid (numeric rule ID from list_rules)")
        rules = await s1.paged("/cloud-detection/rules", {"ids": [rule_id], "includeScheduledRules": True, "isLegacy": False}, limit=1)
        if not rules:
            raise ToolError(f"Rule {rule_id} not found")
        return rules[0]

    async def _get_own(rule_id: str) -> dict:
        rule = await _get(rule_id)
        if not _own(rule):
            raise ToolError(f"Rule '{rule.get('name')}' is not an ai-range rule (prefix '{NAME_PREFIX}' missing) – "
                            "changes are only allowed on own rules. Create a new rule for adjustments.")
        return rule

    def _scope() -> dict:
        if not s1.site_id:
            raise ToolError("S1_SITE_ID is not set – rules are only created in the range site.")
        return {"siteIds": [s1.site_id]}

    @safe
    async def list_rules(args: dict) -> dict:
        limit = max(1, min(int(args.get("limit") or 25), 100))
        p: dict[str, Any] = {"sortBy": "name", "sortOrder": "asc", "includeScheduledRules": True, "isLegacy": False}
        if args.get("search"):
            p["name__contains"] = args["search"]
        if args.get("query_contains"):
            p["s1ql__contains"] = args["query_contains"]
        if args.get("only_ai_range"):
            p["name__contains"] = NAME_PREFIX.strip()
        if args.get("enabled") is not None:
            p["status"] = ["Active", "Activating"] if args["enabled"] else ["Disabled", "Disabling", "Draft"]
        rules = await s1.paged("/cloud-detection/rules", p, limit=limit)
        return {"returned": len(rules), "rules": [compact_rule(r) for r in rules]}

    @safe
    async def get_rule(args: dict) -> dict:
        return compact_rule(await _get(args.get("id")), full=True)

    @safe
    async def create_rule(args: dict) -> dict:
        data = _rule_data(args)
        r = await s1.api("POST", "/cloud-detection/rules", json={"data": data, "filter": _scope()})
        return {"created": True, **compact_rule(r.get("data") or {})}

    @safe
    async def update_rule(args: dict) -> dict:
        rule = await _get_own(args.get("id"))
        if args.get("type") and args["type"] != rule.get("queryType"):
            raise ToolError("type cannot be changed – create a new rule")
        data = _rule_data({k: v for k, v in args.items() if k not in ("id", "enabled")}, rule)
        if args.get("enabled") is not None:
            data["status"] = "Active" if args["enabled"] else "Disabled"
        r = await s1.api("PUT", f"/cloud-detection/rules/{rule['id']}", json={"data": data, "filter": _scope()})
        return {"updated": True, **compact_rule(r.get("data") or {})}

    @safe
    async def disable_rule(args: dict) -> dict:
        rule = await _get_own(args.get("id"))
        r = await s1.api("PUT", "/cloud-detection/rules/disable", json={"filter": {"ids": [rule["id"]]}})
        return {"disabled": True, "affected": (r.get("data") or {}).get("affected"), "id": rule["id"],
                "name": rule.get("name")}

    @safe
    async def preview_rule(args: dict) -> dict:
        """No preview API for STAR: run the rule logic as a PowerQuery over the time window."""
        data = _rule_data({**args, "name": args.get("name") or "preview",
                           "description": args.get("description") or "preview"})
        hours = max(1, min(int(args.get("lookback_hours") or 24), 168))
        samples = max(0, min(int(args.get("samples") or 5), 20))
        out: dict[str, Any] = {"lookback_hours": hours, "type": data["queryType"]}
        if data["queryType"] == "events":
            flt = data["s1ql"]
            agg = await s1.powerquery(f"{flt} | group hits = count() by endpoint.name | sort -hits | limit 20",
                                      f"{hours}h")
            by_host = {str(row[0]): int(row[1]) for row in agg.get("values") or []}
            out["hits"] = sum(by_host.values())
            out["by_host"] = by_host
            users = await s1.powerquery(f"{flt} | group hits = count() by src.process.user | sort -hits | limit 10",
                                        f"{hours}h")
            out["by_user"] = {str(row[0]): int(row[1]) for row in users.get("values") or []}
            if samples:
                smp = await s1.powerquery(
                    f"{flt} | columns event.time, endpoint.name, event.type, src.process.user, src.process.name, "
                    f"src.process.cmdline, tgt.process.cmdline, tgt.file.path, dst.ip.address | sort -event.time "
                    f"| limit {samples}", f"{hours}h")
                out["samples"] = format_pq(smp, samples)
            out["note"] = "Hits = events for which the rule would have created one alert each in this time range."
        else:
            sp = data["scheduledParams"]
            res = await s1.powerquery(sp["query"], f"{hours}h")
            rows = res.get("values") or []
            out["rows_over_window"] = len(rows)
            out["result"] = format_pq(res, max(samples, 1))
            out["note"] = (f"Evaluated over {hours} h in one piece; the real rule runs every "
                           f"{sp['runIntervalMinutes']} min over {sp['lookbackWindowMinutes']} min and alerts per "
                           f"row if rows > {(sp.get('threshold') or {}).get('value', 0)}. For a "
                           "realistic estimate, group by time windows in the query (e.g. timebucket).")
        return out

    rule_ref = {"id": {"type": "string", "description": "Rule ID (field id from list_rules)"}}
    draft_required = ["name", "description", "type", "query"]
    return [
        build_pq_tool(s1),
        make_tool("list_rules", (
            "Search STAR/custom detection rules (incl. scheduled), compact: id, name, type, status, severity, "
            "scope, MITRE (from name/description), generated alerts. Check before creating whether one already exists."), {
            "type": "object",
            "properties": {
                "search": {"type": "string", "description": "Substring in the name"},
                "query_contains": {"type": "string", "description": "Substring in the rule query"},
                "only_ai_range": {"type": "boolean", "description": "Only rules with prefix 'ai-range:'"},
                "enabled": {"type": "boolean", "description": "Only enabled (true) or disabled (false)"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "description": "Default 25"},
            },
        }, list_rules),
        make_tool("get_rule", "Details of a rule: query, type, scheduled parameters, status, auto response, MITRE.", {
            "type": "object", "properties": rule_ref, "required": ["id"],
        }, get_rule),
        make_tool("create_rule", (
            "Create and enable a STAR rule in the range site. Test it with preview_rule first! Enforced: name prefix "
            "'ai-range: ', S1QL 2.0, permanent, no auto response (no network quarantine, no treat-as-threat), "
            "MITRE line in the description. Returns the rule ID."), {
            "type": "object", "properties": _PROPS, "required": draft_required,
        }, create_rule),
        make_tool("update_rule", (
            "Update an own rule (prefix 'ai-range:') – fields not given stay unchanged. mitre replaces the MITRE line. "
            "enabled=false disables it. Other rules are rejected."), {
            "type": "object",
            "properties": {**rule_ref, **{k: v for k, v in _PROPS.items() if k != "type"}, "enabled": {"type": "boolean"}},
            "required": ["id"],
        }, update_rule),
        make_tool("preview_rule", (
            "Test a rule draft without creating it: the logic runs as a PowerQuery over the last lookback_hours "
            "(default 24, max 168). events: number of hits, distribution by host/user, sample events. scheduled: "
            "result table over the whole window. Goal: hit real attack activity, hardly any noise."), {
            "type": "object",
            "properties": {**{k: v for k, v in _PROPS.items() if k not in ("name", "description")},
                           "name": {"type": "string"}, "description": {"type": "string"},
                           "lookback_hours": {"type": "integer", "minimum": 1, "maximum": 168},
                           "samples": {"type": "integer", "minimum": 0, "maximum": 20,
                                       "description": "Sample hits (default 5)"}},
            "required": ["type", "query"],
        }, preview_rule),
        make_tool("disable_rule", "Disable an own rule (prefix 'ai-range:'), e.g. if there are too many false positives.", {
            "type": "object", "properties": rule_ref, "required": ["id"],
        }, disable_rule),
    ]
