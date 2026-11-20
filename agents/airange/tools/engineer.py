"""Engineer agent tools (detection engineer): telemetry via ES|QL, search/read rules,
design own rules (preview), create, update and disable them.

Guardrails (enforced here in code, not in the prompt):
- New rules always carry the tags "ai-range" + "Author: AI Engineer" and a rule_id "ai-range-…".
- update_rule/disable_rule only act on rules with tag "ai-range" – prebuilt/other rules stay untouched.
- Runs as blue-agent (role range_blue) – no access to range-groundtruth.
"""
from __future__ import annotations

import datetime as dt
import re
import secrets
from typing import Any

from claude_agent_sdk import SdkMcpTool

from ..elastic import Elastic
from ..runner import make_tool
from .blue import SEVERITIES, ToolError, alert_summary, build_esql_tool, mitre_ids, safe, trunc

AI_TAG = "ai-range"
AUTHOR_TAG = "Author: AI Engineer"
RULE_ID_PREFIX = "ai-range-"
PREVIEW_INDEX = ".preview.alerts-security.alerts-default"
RULE_TYPES = ["eql", "esql", "query", "threshold"]
LANGUAGE = {"eql": "eql", "esql": "esql", "query": "kuery", "threshold": "kuery"}
DEFAULT_RISK = {"low": 21, "medium": 47, "high": 73, "critical": 99}
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
TACTIC_RE = re.compile(r"^TA\d{4}$")

# MITRE ATT&CK Enterprise – tactics (stable, therefore hardcoded)
TACTICS = {
    "TA0043": "Reconnaissance", "TA0042": "Resource Development", "TA0001": "Initial Access",
    "TA0002": "Execution", "TA0003": "Persistence", "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion", "TA0006": "Credential Access", "TA0007": "Discovery",
    "TA0008": "Lateral Movement", "TA0009": "Collection", "TA0011": "Command and Control",
    "TA0010": "Exfiltration", "TA0040": "Impact",
}


def _mitre_url(tid: str) -> str:
    if tid.startswith("TA"):
        return f"https://attack.mitre.org/tactics/{tid}/"
    return f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"


class MitreCatalog:
    """Technique names and default tactic from the installed prebuilt rules (loaded once per process)."""

    def __init__(self, es: Elastic):
        self.es = es
        self.techniques: dict[str, tuple[str, str]] | None = None  # id -> (name, tactic_id)

    async def load(self) -> dict[str, tuple[str, str]]:
        if self.techniques is None:
            tech: dict[str, tuple[str, str]] = {}
            page = 1
            while True:
                r = await self.es.kibana("GET", "/api/detection_engine/rules/_find",
                                         params={"per_page": 1000, "page": page})
                for rule in r.get("data", []):
                    for th in rule.get("threat") or []:
                        ta = (th.get("tactic") or {}).get("id", "")
                        for te in th.get("technique") or []:
                            tech.setdefault(te["id"], (te.get("name", te["id"]), ta))
                            for st in te.get("subtechnique") or []:
                                tech.setdefault(st["id"], (st.get("name", st["id"]), ta))
                if page * 1000 >= r.get("total", 0) or not r.get("data"):
                    break
                page += 1
            self.techniques = tech
        return self.techniques

    async def threat(self, specs: list[str]) -> list[dict]:
        """["T1003.001", "TA0008:T1021.002", ...] -> Kibana threat array (grouped by tactic)."""
        cat = await self.load()
        tactics: dict[str, dict[str, dict]] = {}
        for raw in specs:
            spec = str(raw).strip().upper()
            tactic, _, tech = spec.rpartition(":")
            if not TECHNIQUE_RE.match(tech):
                raise ToolError(f"Invalid technique ID {raw!r} – format T1234 or T1234.001 "
                                "(optionally with tactic: TA0006:T1003.001)")
            if tactic and (not TACTIC_RE.match(tactic) or tactic not in TACTICS):
                raise ToolError(f"Invalid tactic ID in {raw!r} – allowed: {', '.join(sorted(TACTICS))}")
            parent = tech.split(".")[0]
            if not tactic:
                known = cat.get(tech) or cat.get(parent)
                if not known or known[1] not in TACTICS:
                    raise ToolError(f"Tactic for {tech} unknown – please specify as 'TA00xx:{tech}'")
                tactic = known[1]
            techs = tactics.setdefault(tactic, {})
            te = techs.setdefault(parent, {
                "id": parent, "name": cat.get(parent, (parent, ""))[0], "reference": _mitre_url(parent),
                "subtechnique": []})
            if tech != parent and not any(s["id"] == tech for s in te["subtechnique"]):
                te["subtechnique"].append({"id": tech, "name": cat.get(tech, (tech, ""))[0],
                                           "reference": _mitre_url(tech)})
        out = []
        for ta, techs in tactics.items():
            tlist = []
            for te in techs.values():
                if not te["subtechnique"]:
                    te = {k: v for k, v in te.items() if k != "subtechnique"}
                tlist.append(te)
            out.append({"framework": "MITRE ATT&CK",
                        "tactic": {"id": ta, "name": TACTICS[ta], "reference": _mitre_url(ta)},
                        "technique": tlist})
        return out


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40] or "rule"


def compact_rule(r: dict, full: bool = False) -> dict:
    out: dict[str, Any] = {
        "id": r.get("id"), "rule_id": r.get("rule_id"), "name": r.get("name"), "type": r.get("type"),
        "enabled": r.get("enabled"), "severity": r.get("severity"), "risk_score": r.get("risk_score"),
        "prebuilt": r.get("immutable"), "mitre": mitre_ids(r.get("threat")),
    }
    ex = (r.get("execution_summary") or {}).get("last_execution") or {}
    if ex:
        out["last_execution"] = {"status": ex.get("status"), "date": ex.get("date"),
                                 "message": trunc(ex.get("message"), 300 if not full else 1500)}
    if not full:
        out["tags"] = [t for t in r.get("tags") or [] if not t.startswith(("Resources:", "Use Case:", "Domain:"))]
        return {k: v for k, v in out.items() if v not in (None, [], "")}
    for k in ("description", "query", "language", "index", "filters", "interval", "from", "to", "max_signals",
              "threshold", "tags", "false_positives", "references", "note", "version", "revision",
              "created_by", "created_at", "updated_at", "timestamp_override"):
        if r.get(k) not in (None, [], ""):
            out[k] = trunc(r[k], 3000) if k in ("note", "query", "description") else r[k]
    out["threat"] = [
        f"{th['tactic']['id']} {th['tactic']['name']}: "
        + ", ".join(f"{te['id']} {te['name']}" + "".join(f", {s['id']} {s['name']}" for s in te.get("subtechnique") or [])
                    for te in th.get("technique") or [])
        for th in r.get("threat") or []
    ]
    return out


def _force_tags(tags: list[str] | None) -> list[str]:
    return list(dict.fromkeys([AI_TAG, AUTHOR_TAG, *[str(t) for t in tags or []]]))


async def _rule_body(args: dict, catalog: MitreCatalog, *, partial: bool) -> dict:
    """Shared construction for create/preview (partial=False) and update (partial=True)."""
    body: dict[str, Any] = {}
    rtype = args.get("type")
    if rtype is not None or not partial:
        if rtype not in RULE_TYPES:
            raise ToolError(f"type must be one of {RULE_TYPES}")
        body["type"] = rtype
        body["language"] = LANGUAGE[rtype]
    for k in ("name", "description", "query"):
        if args.get(k):
            body[k] = args[k]
        elif not partial:
            raise ToolError(f"{k} is mandatory")
    if rtype == "esql" and "index" in args and args["index"]:
        raise ToolError("ES|QL rules have no index field – indices go in the FROM of the query")
    if rtype and rtype != "esql":
        body["index"] = args.get("index") or ["logs-*"]
    elif partial and args.get("index"):
        body["index"] = args["index"]
    if args.get("severity") or not partial:
        sev = (args.get("severity") or "medium").lower()
        if sev not in SEVERITIES:
            raise ToolError(f"severity must be one of {SEVERITIES}")
        body["severity"] = sev
        body["risk_score"] = int(args.get("risk_score") or DEFAULT_RISK[sev])
    elif args.get("risk_score") is not None:
        body["risk_score"] = int(args["risk_score"])
    if "risk_score" in body and not 0 <= body["risk_score"] <= 100:
        raise ToolError("risk_score must be 0..100")
    if args.get("mitre") is not None:
        body["threat"] = await catalog.threat(args["mitre"])
    if args.get("threshold") is not None:
        th = args["threshold"]
        fields = th.get("field") or []
        body["threshold"] = {"field": [fields] if isinstance(fields, str) else fields, "value": int(th["value"])}
        if th.get("cardinality_field"):
            body["threshold"]["cardinality"] = [{"field": th["cardinality_field"],
                                                 "value": int(th.get("cardinality_value") or 1)}]
    if rtype == "threshold" and "threshold" not in body:
        raise ToolError("threshold rules need threshold {field, value}")
    for k in ("false_positives", "references", "note", "max_signals"):
        if args.get(k) is not None:
            body[k] = args[k]
    if args.get("interval") or not partial:
        body["interval"] = args.get("interval") or "5m"
    if args.get("from") or not partial:
        body["from"] = args.get("from") or "now-6m"
    if args.get("tags") is not None or not partial:
        body["tags"] = _force_tags(args.get("tags"))
    if not partial:
        body["author"] = ["AI Engineer (ai-range)"]
        body["license"] = "ai-range"
    return body


_COMMON_PROPS: dict[str, Any] = {
    "name": {"type": "string"},
    "description": {"type": "string", "description": "What the rule detects and why"},
    "type": {"type": "string", "enum": RULE_TYPES,
             "description": "eql (EQL, e.g. 'process where ...' or sequence), esql (ES|QL), "
                            "query (KQL), threshold (KQL + threshold)"},
    "query": {"type": "string",
              "description": "Rule query. ES|QL without aggregation needs 'FROM logs-* METADATA _id, _index, _version'; "
                             "with STATS one alert is created per result row."},
    "index": {"type": "array", "items": {"type": "string"},
              "description": "Index patterns (default ['logs-*']; not allowed for esql)"},
    "severity": {"type": "string", "enum": SEVERITIES},
    "risk_score": {"type": "integer", "minimum": 0, "maximum": 100,
                   "description": "Default from severity: low 21, medium 47, high 73, critical 99"},
    "mitre": {"type": "array", "items": {"type": "string"},
              "description": "ATT&CK techniques: 'T1003.001' (tactic is added) or 'TA0006:T1003.001'"},
    "threshold": {"type": "object", "description": "Only type=threshold",
                  "properties": {"field": {"type": "array", "items": {"type": "string"}},
                                 "value": {"type": "integer", "minimum": 1},
                                 "cardinality_field": {"type": "string"},
                                 "cardinality_value": {"type": "integer", "minimum": 1}},
                  "required": ["value"]},
    "interval": {"type": "string", "description": "Execution interval (default 5m)"},
    "from": {"type": "string", "description": "Lookback per run (default now-6m)"},
    "tags": {"type": "array", "items": {"type": "string"},
             "description": "Additional tags (ai-range + 'Author: AI Engineer' are always set)"},
    "false_positives": {"type": "array", "items": {"type": "string"}},
    "references": {"type": "array", "items": {"type": "string"}},
    "note": {"type": "string", "description": "Investigation Guide (Markdown)"},
    "max_signals": {"type": "integer", "minimum": 1, "maximum": 1000},
}


def build_engineer_tools(es: Elastic) -> list[SdkMcpTool]:
    catalog = MitreCatalog(es)

    async def _get(args: dict) -> dict:
        if args.get("id"):
            return await es.kibana("GET", "/api/detection_engine/rules", params={"id": args["id"]})
        if args.get("rule_id"):
            return await es.kibana("GET", "/api/detection_engine/rules", params={"rule_id": args["rule_id"]})
        raise ToolError("specify id or rule_id")

    async def _get_own(args: dict) -> dict:
        rule = await _get(args)
        if AI_TAG not in (rule.get("tags") or []) or rule.get("immutable"):
            raise ToolError(f"Rule '{rule.get('name')}' is not an ai-range rule (tag '{AI_TAG}' missing) – "
                            "changes are only allowed on own rules. Create a new rule for adjustments.")
        return rule

    @safe
    async def list_rules(args: dict) -> dict:
        parts = []
        if args.get("search"):
            term = str(args["search"]).replace('"', '\\"')
            parts.append(f'(alert.attributes.name: "{term}" OR alert.attributes.tags: "{term}")')
        if args.get("only_custom"):
            parts.append("alert.attributes.params.immutable: false")
        if args.get("only_ai_range"):
            parts.append(f'alert.attributes.tags: "{AI_TAG}"')
        if args.get("enabled") is not None:
            parts.append(f"alert.attributes.enabled: {str(bool(args['enabled'])).lower()}")
        limit = max(1, min(int(args.get("limit") or 25), 100))
        params: dict[str, Any] = {"per_page": limit, "page": 1, "sort_field": "name", "sort_order": "asc"}
        if parts:
            params["filter"] = " AND ".join(parts)
        r = await es.kibana("GET", "/api/detection_engine/rules/_find", params=params)
        return {"total": r.get("total"), "returned": len(r.get("data", [])),
                "rules": [compact_rule(x) for x in r.get("data", [])]}

    @safe
    async def get_rule(args: dict) -> dict:
        return compact_rule(await _get(args), full=True)

    @safe
    async def create_rule(args: dict) -> dict:
        body = await _rule_body(args, catalog, partial=False)
        rid = str(args.get("rule_id") or "").strip().lower()
        rid = re.sub(r"[^a-z0-9-]+", "-", rid).strip("-")
        if not rid:
            rid = f"{_slug(body['name'])}-{secrets.token_hex(3)}"
        body["rule_id"] = rid if rid.startswith(RULE_ID_PREFIX) else RULE_ID_PREFIX + rid
        body["enabled"] = True
        r = await es.kibana("POST", "/api/detection_engine/rules", json=body)
        return {"created": True, **compact_rule(r)}

    @safe
    async def update_rule(args: dict) -> dict:
        rule = await _get_own(args)
        patch = await _rule_body({k: v for k, v in args.items() if k not in ("id", "rule_id")}, catalog, partial=True)
        if "type" in patch and patch["type"] != rule.get("type"):
            raise ToolError("type cannot be changed – create a new rule")
        patch.pop("type", None)
        patch.pop("language", None)
        if rule.get("type") == "esql":
            patch.pop("index", None)
        if args.get("enabled") is not None:
            patch["enabled"] = bool(args["enabled"])
        if "tags" in patch:
            patch["tags"] = _force_tags(patch["tags"])
        if not patch:
            raise ToolError("No changes specified")
        patch["id"] = rule["id"]
        r = await es.kibana("PATCH", "/api/detection_engine/rules", json=patch)
        return {"updated": sorted(k for k in patch if k != "id"), **compact_rule(r)}

    @safe
    async def disable_rule(args: dict) -> dict:
        rule = await _get_own(args)
        r = await es.kibana("PATCH", "/api/detection_engine/rules", json={"id": rule["id"], "enabled": False})
        return {"disabled": True, **compact_rule(r)}

    @safe
    async def preview_rule(args: dict) -> dict:
        hours = max(1, min(int(args.get("lookback_hours") or 24), 168))
        body = await _rule_body(args, catalog, partial=False)
        # Split the time range into hourly steps: 1h lookback per invocation, end = now
        body.update({"interval": "1h", "from": "now-1h", "invocationCount": hours,
                     "timeframeEnd": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
                     .replace("+00:00", "Z")})
        r = await es.kibana("POST", "/api/detection_engine/rules/preview", json=body)
        pid = r.get("previewId")
        errors = [e for log in r.get("logs") or [] for e in log.get("errors") or []]
        warnings = [w for log in r.get("logs") or [] for w in log.get("warnings") or []]
        out: dict[str, Any] = {"preview_id": pid, "lookback_hours": hours, "aborted": r.get("isAborted", False)}
        if errors:
            out["errors"] = list(dict.fromkeys(trunc(e, 500) for e in errors))[:5]
        if warnings:
            out["warnings"] = list(dict.fromkeys(trunc(w, 500) for w in warnings))[:5]
        if not pid:
            out["note"] = "No previewId – check the rule definition."
            return out
        try:
            await es.es("POST", f"/{PREVIEW_INDEX}/_refresh")
        except Exception:  # noqa: BLE001 – refresh is only a speed-up
            pass
        res = await es.es("POST", f"/{PREVIEW_INDEX}/_search", json={
            "size": int(args.get("samples") or 5),
            "track_total_hits": True,
            "query": {"bool": {"filter": [{"term": {"kibana.alert.rule.uuid": pid}}]}},
            "sort": [{"@timestamp": {"order": "desc"}}],
            "aggs": {"hosts": {"terms": {"field": "host.name", "size": 15}},
                     "users": {"terms": {"field": "user.name", "size": 10}}},
        })
        out["hits"] = res["hits"]["total"]["value"]
        if any("maximum alert limit" in w for w in warnings):
            out["hits_capped"] = (f"At least one execution reached max_signals ({body.get('max_signals', 100)}) "
                                  "– the real number of hits is higher; narrow the query.")
        out["by_host"] = {b["key"]: b["doc_count"] for b in res["aggregations"]["hosts"]["buckets"]}
        out["by_user"] = {b["key"]: b["doc_count"] for b in res["aggregations"]["users"]["buckets"]}
        samples = []
        for h in res["hits"]["hits"]:
            s = alert_summary(h)
            for k in ("id", "rule", "severity", "risk_score", "status", "mitre", "tags"):
                s.pop(k, None)
            if h["_source"].get("kibana.alert.original_time"):
                s["original_time"] = h["_source"]["kibana.alert.original_time"]
            s["reason"] = trunc(h["_source"].get("kibana.alert.reason"), 300)
            samples.append(s)
        out["samples"] = samples
        return out

    rule_ref = {
        "id": {"type": "string", "description": "Internal rule ID (field id)"},
        "rule_id": {"type": "string", "description": "Stable rule_id (alternative to id)"},
    }
    draft_required = ["name", "description", "type", "query"]

    return [
        build_esql_tool(es),
        make_tool("list_rules", (
            "Search detection rules (prebuilt + own), compact: id, rule_id, name, type, enabled, severity, MITRE, "
            "tags, last execution status. Useful to check before creating whether a rule already exists."), {
            "type": "object",
            "properties": {
                "search": {"type": "string", "description": "Words in the rule name or exact tag"},
                "only_custom": {"type": "boolean", "description": "Only non-prebuilt rules"},
                "only_ai_range": {"type": "boolean", "description": "Only rules with tag ai-range"},
                "enabled": {"type": "boolean", "description": "Only enabled (true) or disabled (false)"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "description": "Default 25"},
            },
        }, list_rules),
        make_tool("get_rule", "Details of a rule: query, index, time window, MITRE, tags, last execution status.", {
            "type": "object", "properties": rule_ref,
        }, get_rule),
        make_tool("create_rule", (
            "Create and enable an own detection rule. Test it with preview_rule first! Enforced: tags "
            "'ai-range' + 'Author: AI Engineer', rule_id prefix 'ai-range-', index default ['logs-*'] (not for "
            "esql), interval 5m / from now-6m, enabled. MITRE mapping from technique IDs. Returns id + rule_id."), {
            "type": "object",
            "properties": {**_COMMON_PROPS,
                           "rule_id": {"type": "string", "description": "Optional; gets prefixed with 'ai-range-'"}},
            "required": draft_required,
        }, create_rule),
        make_tool("update_rule", (
            "Partially update an own rule (tag ai-range) – only the given fields. Prebuilt/other rules are "
            "rejected. tags replaces the tag list (ai-range tags stay enforced), mitre replaces the mapping."), {
            "type": "object",
            "properties": {**rule_ref, **{k: v for k, v in _COMMON_PROPS.items() if k != "type"},
                           "enabled": {"type": "boolean"}},
        }, update_rule),
        make_tool("preview_rule", (
            "Test-run a rule draft over the last lookback_hours (default 24, max 168) without "
            "creating it. Returns number of hits, distribution by host/user, sample hits and errors/warnings of the "
            "execution. Goal: hit real attack activity, but hardly any noise."), {
            "type": "object",
            "properties": {**{k: v for k, v in _COMMON_PROPS.items() if k not in ("interval", "from")},
                           "lookback_hours": {"type": "integer", "minimum": 1, "maximum": 168},
                           "samples": {"type": "integer", "minimum": 0, "maximum": 20,
                                       "description": "Number of sample hits (default 5)"}},
            "required": draft_required,
        }, preview_rule),
        make_tool("disable_rule", "Disable an own rule (tag ai-range), e.g. if there are too many false positives.", {
            "type": "object", "properties": rule_ref,
        }, disable_rule),
    ]
