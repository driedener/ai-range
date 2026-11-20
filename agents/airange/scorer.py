"""Deterministic scorer: match ground truth (range-groundtruth) against security alerts.

No LLM. Flow:
  1. Load the ground-truth steps of a run (one document per Red step, written by the tool).
  2. Load alerts in the run window (first step - 1 min .. last event.end + grace).
  3. Assign each alert to exactly ONE step: host/IP must match, and the time of the triggering event
     (kibana.alert.original_time) decides. If it falls within a step, the step with a matching technique
     wins there; otherwise the closest preceding step (<= 10 min, technique preferred).
     This yields detection, technique match and TTD (alert creation - step start). The old, lenient
     count (every alert in the window [start - 1 min, end + grace] counts for every step) is kept as
     "detected_window" for comparison.
  4. Add triage (workflow status of the matched alerts, Blue tool calls) and cost (run-summary).

Fetching and computation are separate: `compute_report()` is a pure function (testable offline).
"""
from __future__ import annotations

import datetime as dt
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from .config import RANGE_HOSTS, RANGE_IPS, settings
from .elastic import Elastic, ElasticError
from .trace import GROUNDTRUTH_STREAM, TRACE_STREAM, now_iso

ALERTS_INDEX = ".alerts-security.alerts-default"
SCORES_INDEX = "range-scores"
REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"   # /app/reports in the container

PRE_SLACK = dt.timedelta(minutes=1)      # alerts shortly before the step start still count (clock skew)
EVENT_SLACK = dt.timedelta(seconds=10)   # an event belongs to the step if it lies in [start, end] +/- slack
NEAREST_MAX = dt.timedelta(minutes=10)   # otherwise: preceding step, at most this long before the event
ENGINEER_TAG = "ai-range"                # tag of the rules created by the engineer
CASE_TOOLS = {"create_case"}
RESPONSE_TOOLS = {"response_action", "network_device", "firewall"}
READONLY_ACTIONS = {"status", "list"}       # do not count as a response
MAX_ALERTS = 10000
# Management host(s) (controller: Ansible/agents) - their alerts are operational noise, not detections
MGMT_IPS = set(settings.mgmt_ips)          # controller from range.yaml (override: AIRANGE_MGMT_IPS)

ALERT_SOURCE = [
    "@timestamp", "host.name", "host.hostname", "host.ip", "source.ip", "destination.ip",
    "kibana.alert.uuid", "kibana.alert.rule.name", "kibana.alert.rule.uuid", "kibana.alert.rule.tags",
    "kibana.alert.rule.threat", "kibana.alert.severity", "kibana.alert.risk_score",
    "kibana.alert.workflow_status", "kibana.alert.workflow_status_updated_at", "kibana.alert.workflow_user",
    "kibana.alert.original_time", "kibana.alert.building_block_type", "threat",
]


# --------------------------------------------------------------------------- helpers

def _vals(obj: Any, path: str | list[str]) -> list[Any]:
    """All leaf values under `path` - whether nested, with dotted keys or in lists."""
    parts = path.split(".") if isinstance(path, str) else path
    if isinstance(obj, list):
        return [v for item in obj for v in _vals(item, parts)]
    if not parts:
        return [] if obj is None else [obj]
    if not isinstance(obj, dict):
        return []
    out: list[Any] = []
    for i in range(len(parts), 0, -1):
        key = ".".join(parts[:i])
        if key in obj:
            out.extend(_vals(obj[key], parts[i:]))
    return out


def _first(obj: Any, path: str, default: Any = None) -> Any:
    v = _vals(obj, path)
    return v[0] if v else default


def _ts(value: Any) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _iso(t: dt.datetime | None) -> str | None:
    return t.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z") if t else None


def _short_host(name: Any) -> str:
    """'DC01.corp.internal' -> 'dc01'"""
    return str(name).strip().lower().split(".")[0] if name else ""


def _base_tech(tid: Any) -> str:
    return str(tid).strip().upper().split(".")[0] if tid else ""


def _rate(num: int, den: int) -> float | None:
    return round(num / den, 3) if den else None


def _stats(values: Iterable[float]) -> dict[str, float | None]:
    vals = [v for v in values if v is not None]
    if not vals:
        return {"count": 0, "median": None, "mean": None, "min": None, "max": None}
    return {"count": len(vals), "median": round(statistics.median(vals), 1), "mean": round(statistics.fmean(vals), 1),
            "min": round(min(vals), 1), "max": round(max(vals), 1)}


def alert_techniques(alert: dict) -> set[str]:
    """MITRE IDs (technique + sub-technique) from the rule threat list and, if present, from the source event."""
    ids: set[str] = set()
    for prefix in ("kibana.alert.rule.threat", "threat"):
        for p in ("technique.id", "technique.subtechnique.id"):
            ids.update(str(x).upper() for x in _vals(alert, f"{prefix}.{p}") if x)
    return ids


# --------------------------------------------------------------------------- normalization

def _norm_alert(hit: dict) -> dict | None:
    src = hit.get("_source", hit)
    ts = _ts(_first(src, "@timestamp"))
    if ts is None:
        return None
    hosts = {_short_host(h) for h in _vals(src, "host.name") + _vals(src, "host.hostname") if h}
    return {
        "id": hit.get("_id") or _first(src, "kibana.alert.uuid"),
        "ts": ts,
        # time of the triggering event (missing e.g. for ES|QL aggregations -> alert time)
        "event_ts": _ts(_first(src, "kibana.alert.original_time")) or ts,
        "event_known": _ts(_first(src, "kibana.alert.original_time")) is not None,
        "rule": _first(src, "kibana.alert.rule.name", "?"),
        "rule_tags": [str(t) for t in _vals(src, "kibana.alert.rule.tags")],
        "severity": _first(src, "kibana.alert.severity"),
        "hosts": hosts,
        "host_ips": {str(x) for x in _vals(src, "host.ip")},
        "source_ips": {str(x) for x in _vals(src, "source.ip")},
        "dest_ips": {str(x) for x in _vals(src, "destination.ip")},
        "techniques": alert_techniques(src),
        "building_block": bool(_first(src, "kibana.alert.building_block_type")),
        "workflow_status": _first(src, "kibana.alert.workflow_status", "open"),
        "workflow_updated": _ts(_first(src, "kibana.alert.workflow_status_updated_at")),
        "workflow_user": _first(src, "kibana.alert.workflow_user"),
    }


def norm_s1(hit: dict) -> dict | None:
    """SentinelOne UAM alert -> normalized alert (same keys as _norm_alert).

    hit = UAM alert node (uam.ALERT_FIELDS), optionally with "_detail" (indicators with MITRE attacks).
    """
    from .uam import UAM_TO_STATUS, alert_hosts, mitre_ids, parse_ts, rule_name  # noqa: PLC0415

    ts = parse_ts(hit.get("createdAt")) or parse_ts(hit.get("detectedAt"))
    if ts is None:
        return None
    detected = parse_ts(hit.get("detectedAt"))
    status = UAM_TO_STATUS.get(hit.get("status"), "open")
    det = hit.get("detectionTime") or {}
    asset = det.get("asset") or {}
    name = rule_name(hit)
    ips = set(asset.get("ipV4Addresses") or []) | ({asset["ipV4"]} if asset.get("ipV4") else set())
    attacker = (det.get("attacker") or {}).get("ip")
    return {
        "id": hit.get("id"),
        # createdAt = alert creation at the source (TTD), detectedAt = time of the detected activity
        "ts": ts,
        "event_ts": detected or ts,
        "event_known": detected is not None,
        "rule": name,
        "rule_tags": [ENGINEER_TAG] if name.startswith(f"{ENGINEER_TAG}:") else [],
        "severity": str(hit.get("severity") or "").lower(),
        "hosts": set(alert_hosts(hit)),
        "host_ips": ips,
        "source_ips": {attacker} if attacker else set(),
        "dest_ips": set(),
        "techniques": set(mitre_ids(hit.get("_detail"), hit)),
        "building_block": False,
        "workflow_status": status,
        "workflow_updated": parse_ts(hit.get("updatedAt")) if status != "open" else None,
        "workflow_user": None,
    }


def _norm_step(hit: dict, idx: int, kali_ip: str) -> dict:
    src = hit.get("_source", hit)
    start = _ts(_first(src, "@timestamp"))
    end = _ts(_first(src, "event.end")) or start
    hosts = {_short_host(h) for h in _vals(src, "range.target_hosts") + _vals(src, "host.name") if h}
    ips = {str(x) for x in _vals(src, "range.target_ips") + _vals(src, "destination.ip") if x}
    hosts |= {RANGE_HOSTS[ip] for ip in ips if ip in RANGE_HOSTS}
    ips |= {RANGE_IPS[h] for h in hosts if h in RANGE_IPS}
    return {
        "n": idx,
        "start": start,
        "end": end,
        "technique": str(_first(src, "threat.technique.id", "") or "").upper(),
        "technique_name": _first(src, "threat.technique.name", ""),
        "tactic": _first(src, "threat.tactic.name", ""),
        "outcome": _first(src, "event.outcome", "unknown"),
        "command": _first(src, "process.command_line", ""),
        "hosts": hosts,
        "ips": ips,
        "kali_ip": str(_first(src, "source.ip", kali_ip) or kali_ip),
    }


def _match_reason(step: dict, alert: dict) -> str | None:
    # alerts triggered by the management host (Ansible WinRM/SSH from the controller) never count as detections
    if alert["source_ips"] & MGMT_IPS and step["kali_ip"] not in alert["source_ips"]:
        return None
    if step["hosts"] & alert["hosts"]:
        return "host"
    if step["ips"] & (alert["host_ips"] | alert["source_ips"] | alert["dest_ips"]):
        return "ip"
    if step["kali_ip"] in (alert["source_ips"] | alert["dest_ips"]):
        return "kali-ip"
    return None


def _assign(alerts: list[dict], steps: list[dict], grace: dt.timedelta
            ) -> tuple[dict[int, list[tuple]], dict[int, list[tuple]]]:
    """-> (strict: step no. -> [(alert, reason, tech)], window: same, every alert for every step)."""
    strict: dict[int, list[tuple]] = defaultdict(list)
    window: dict[int, list[tuple]] = defaultdict(list)
    for a in alerts:
        cands = []
        for s in steps:
            if not (s["start"] - PRE_SLACK <= a["ts"] <= s["end"] + grace):
                continue
            if not (reason := _match_reason(s, a)):
                continue
            tech = bool(s["technique"]) and _base_tech(s["technique"]) in {_base_tech(t) for t in a["techniques"]}
            cands.append((s, reason, tech))
            window[s["n"]].append((a, reason, tech))
        if not cands:
            continue
        t = a["event_ts"]
        # only check "within the step" with a real event time; otherwise t is the alert creation (after the event)
        pool = [c for c in cands if a["event_known"]
                and c[0]["start"] - EVENT_SLACK <= t <= c[0]["end"] + EVENT_SLACK]
        if not pool:
            # preceding steps, at most NEAREST_MAX before the event; events shortly before the first candidate
            # (clock skew, PRE_SLACK) belong to it. Everything else is noise, not detection.
            pool = [c for c in cands if dt.timedelta(0) <= t - c[0]["start"] <= NEAREST_MAX]
            if not pool:
                first = min(cands, key=lambda c: c[0]["start"])
                pool = [first] if first[0]["start"] - PRE_SLACK <= t < first[0]["start"] else []
        if not pool:
            continue
        # technique match > event within the step > step started before the event > closest in time
        s, reason, tech = min(pool, key=lambda c: (
            not c[2], not (c[0]["start"] <= t <= c[0]["end"]), c[0]["start"] > t,
            abs((c[0]["start"] - t).total_seconds())))
        strict[s["n"]].append((a, reason, tech))
    return strict, window


# --------------------------------------------------------------------------- computation (pure)

def compute_report(run_id: str, gt_hits: list[dict], alert_hits: list[dict], trace_hits: list[dict], *,
                   grace_minutes: int = 30, kali_ip: str | None = None, platform: str = "elastic") -> dict:
    """platform: elastic (alert_hits = ES hits from .alerts-security*) | sentinelone (threats + STAR alerts)."""
    kali_ip = kali_ip or settings.kali_host
    normalize = norm_s1 if platform == "sentinelone" else _norm_alert
    grace = dt.timedelta(minutes=grace_minutes)
    steps = [_norm_step(h, i + 1, kali_ip) for i, h in enumerate(gt_hits)]
    steps = [s for s in steps if s["start"] is not None]
    steps.sort(key=lambda s: s["start"])
    for i, s in enumerate(steps, 1):
        s["n"] = i

    report: dict[str, Any] = {"run_id": run_id, "generated_at": now_iso(), "grace_minutes": grace_minutes,
                              "scorer_version": 2, "platform": platform}
    if not steps:
        report.update(window={"start": None, "end": None, "first_step": None, "last_step_end": None}, steps=[], techniques=[], summary={"steps_total": 0}, noise={},
                      engineer_rules=[], triage={}, cost=_cost(run_id, trace_hits))
        return report

    win_start = min(s["start"] for s in steps) - PRE_SLACK
    win_end = max(s["end"] for s in steps) + grace
    report["window"] = {"start": _iso(win_start), "end": _iso(win_end),
                        "first_step": _iso(steps[0]["start"]), "last_step_end": _iso(max(s["end"] for s in steps))}

    alerts = [a for a in (normalize(h) for h in alert_hits) if a and win_start <= a["ts"] <= win_end]
    alerts.sort(key=lambda a: a["ts"])
    matched_ids: set[str] = set()

    strict, window = _assign(alerts, steps, grace)
    step_rows = []
    for s in steps:
        hits = sorted(strict.get(s["n"], []), key=lambda h: h[0]["ts"])
        whits = window.get(s["n"], [])
        matched_ids.update(a["id"] for a, _, _ in hits)
        first = hits[0][0] if hits else None
        first_tech = next((a for a, _, t in hits if t), None)
        step_rows.append({
            "n": s["n"], "start": _iso(s["start"]), "end": _iso(s["end"]),
            "technique": s["technique"], "technique_name": s["technique_name"], "tactic": s["tactic"],
            "outcome": s["outcome"], "targets": sorted(s["hosts"]) or sorted(s["ips"]),
            "command": (s["command"] or "")[:300],
            "detected": bool(hits), "technique_match": first_tech is not None,
            "detected_window": bool(whits), "technique_match_window": any(t for _, _, t in whits),
            "ttd_s": round((first["ts"] - s["start"]).total_seconds(), 1) if first else None,
            "ttd_technique_s": round((first_tech["ts"] - s["start"]).total_seconds(), 1) if first_tech else None,
            "alerts": len(hits),
            "alerts_by_reason": dict(Counter(r for _, r, _ in hits)),
            "rules": sorted({a["rule"] for a, _, _ in hits}),
            "matched_alert_ids": [a["id"] for a, _, _ in hits][:100],
        })
    report["steps"] = step_rows

    # per technique
    by_tech: dict[str, list[dict]] = defaultdict(list)
    for r in step_rows:
        by_tech[r["technique"] or "?"].append(r)
    tech_rows = []
    for tid, rows in sorted(by_tech.items()):
        succ = [r for r in rows if r["outcome"] == "success"]
        tech_rows.append({
            "technique": tid, "name": rows[0]["technique_name"], "tactic": rows[0]["tactic"],
            "steps": len(rows), "successful": len(succ),
            "detected": sum(r["detected"] for r in rows), "detected_successful": sum(r["detected"] for r in succ),
            "technique_match": sum(r["technique_match"] for r in rows),
            "best_ttd_s": min((r["ttd_s"] for r in rows if r["ttd_s"] is not None), default=None),
            "rules": sorted({x for r in rows for x in r["rules"]}),
        })
    report["techniques"] = tech_rows

    succ_steps = [r for r in step_rows if r["outcome"] == "success"]
    succ_techs = [t for t in tech_rows if t["successful"]]
    matched = [a for a in alerts if a["id"] in matched_ids]
    unmatched = [a for a in alerts if a["id"] not in matched_ids]
    report["summary"] = {
        "steps_total": len(step_rows),
        "steps_successful": len(succ_steps),
        "steps_detected": sum(r["detected"] for r in step_rows),
        "steps_detected_successful": sum(r["detected"] for r in succ_steps),
        "detection_rate": _rate(sum(r["detected"] for r in succ_steps), len(succ_steps)),
        "detection_rate_all": _rate(sum(r["detected"] for r in step_rows), len(step_rows)),
        "technique_match_rate": _rate(sum(r["technique_match"] for r in succ_steps), len(succ_steps)),
        "detection_rate_window": _rate(sum(r["detected_window"] for r in succ_steps), len(succ_steps)),
        "technique_match_rate_window": _rate(sum(r["technique_match_window"] for r in succ_steps), len(succ_steps)),
        "techniques_total": len(tech_rows),
        "techniques_successful": len(succ_techs),
        "techniques_detected": sum(1 for t in succ_techs if t["detected_successful"]),
        "technique_detection_rate": _rate(sum(1 for t in succ_techs if t["detected_successful"]), len(succ_techs)),
        "ttd_s": _stats(r["ttd_s"] for r in succ_steps),
        "ttd_technique_s": _stats(r["ttd_technique_s"] for r in succ_steps),
        "alerts_in_window": len(alerts),
        "alerts_matched": len(matched),
        "alerts_unmatched": len(unmatched),
    }
    report["noise"] = dict(Counter(a["rule"] for a in unmatched).most_common())

    eng = defaultdict(lambda: {"alerts": 0, "matched": 0})
    for a in alerts:
        if ENGINEER_TAG in a["rule_tags"]:
            eng[a["rule"]]["alerts"] += 1
            eng[a["rule"]]["matched"] += a["id"] in matched_ids
    report["engineer_rules"] = [{"rule": k, **v} for k, v in sorted(eng.items())]

    report["triage"] = _triage(run_id, matched, trace_hits, win_start, win_end)
    report["cost"] = _cost(run_id, trace_hits)
    return report


def _triage(run_id: str, matched: list[dict], trace_hits: list[dict], win_start: dt.datetime,
            win_end: dt.datetime) -> dict:
    status = Counter(a["workflow_status"] or "open" for a in matched)
    handled = [a for a in matched if (a["workflow_status"] or "open") != "open"]
    ttt = [(a["workflow_updated"] - a["ts"]).total_seconds() for a in handled if a["workflow_updated"]]
    users = Counter(str(a["workflow_user"]) for a in handled if a["workflow_user"])

    # Blue tool calls: same run OR a Blue run with its own run ID within the window
    blue = []
    for h in trace_hits:
        src = h.get("_source", h)
        if _first(src, "agent.role") != "blue" or _first(src, "tool.name") == "run-summary":
            continue
        ts = _ts(_first(src, "@timestamp"))
        if _first(src, "run.id") == run_id or (ts and win_start <= ts <= win_end):
            blue.append((ts, src))
    blue.sort(key=lambda x: x[0] or win_start)

    def _calls(names: set[str]) -> list[dict]:
        out = []
        for ts, src in blue:
            if _first(src, "tool.name") in names:
                inp = _first(src, "tool.input") or {}
                out.append({"@timestamp": _iso(ts), "tool": _first(src, "tool.name"),
                            "outcome": _first(src, "event.outcome"), "run_id": _first(src, "run.id"),
                            "input": inp if isinstance(inp, dict) else str(inp)})
        return out

    first_status = min((a["workflow_updated"] for a in handled if a["workflow_updated"]), default=None)
    return {
        "blue_ran": bool(blue),
        "blue_runs": sorted({str(_first(s, "run.id")) for _, s in blue}),
        "blue_tool_calls": len(blue),
        "blue_tools": dict(Counter(str(_first(s, "tool.name")) for _, s in blue).most_common()),
        "matched_alerts": len(matched),
        "workflow_status": dict(status),
        "handled_alerts": len(handled),
        "handled_rate": _rate(len(handled), len(matched)),
        "time_to_triage_s": _stats(ttt),
        "first_triage_at": _iso(first_status),
        "workflow_users": dict(users),
        "cases": _calls(CASE_TOOLS),
        "response_actions": [c for c in _calls(RESPONSE_TOOLS)
                             if not (isinstance(c["input"], dict) and c["input"].get("action") in READONLY_ACTIONS)],
    }


def _cost(run_id: str, trace_hits: list[dict]) -> dict:
    by_role: dict[str, dict[str, float]] = defaultdict(lambda: {"cost_usd": 0.0, "tokens": 0, "runs": 0})
    for h in trace_hits:
        src = h.get("_source", h)
        if _first(src, "tool.name") != "run-summary" or _first(src, "run.id") != run_id:
            continue
        role = str(_first(src, "agent.role", "?"))
        by_role[role]["cost_usd"] += float(_first(src, "llm.cost_usd") or 0)
        by_role[role]["tokens"] += int(_first(src, "llm.tokens.total") or 0)
        by_role[role]["runs"] += 1
    roles = {k: {**v, "cost_usd": round(v["cost_usd"], 4)} for k, v in sorted(by_role.items())}
    return {"by_role": roles, "total_usd": round(sum(v["cost_usd"] for v in roles.values()), 4)}


# --------------------------------------------------------------------------- Elastic access

async def _search_all(es: Elastic, index: str, query: dict, sort: list, source: Any = True,
                      limit: int = MAX_ALERTS) -> list[dict]:
    """search_after paging; missing index -> empty list."""
    out: list[dict] = []
    after = None
    while len(out) < limit:
        body: dict[str, Any] = {"size": min(1000, limit - len(out)), "query": query, "sort": sort, "_source": source}
        if after:
            body["search_after"] = after
        try:
            r = await es.es("POST", f"/{index}/_search", json=body, params={"ignore_unavailable": "true"})
        except ElasticError as exc:
            if exc.status == 404:
                return out
            raise
        hits = r["hits"]["hits"]
        out.extend(hits)
        if len(hits) < body["size"]:
            break
        after = hits[-1]["sort"]
    return out


async def score_run(run_id: str, *, grace_minutes: int = 30, es: Elastic | None = None) -> dict:
    own = es is None
    es = es or Elastic("orchestrator")
    try:
        gt = await _search_all(es, GROUNDTRUTH_STREAM, {"term": {"run.id": run_id}}, [{"@timestamp": "asc"}],
                               limit=5000)
        alerts: list[dict] = []
        if gt:
            starts = [t for t in (_ts(_first(h["_source"], "@timestamp")) for h in gt) if t]
            ends = [_ts(_first(h["_source"], "event.end")) or _ts(_first(h["_source"], "@timestamp")) for h in gt]
            lo = min(starts) - PRE_SLACK
            hi = max(e for e in ends if e) + dt.timedelta(minutes=grace_minutes)
            if settings.use_s1:
                alerts = await _fetch_s1_detections(lo, hi)
            else:
                alerts = await _search_all(
                    es, ALERTS_INDEX,
                    {"range": {"@timestamp": {"gte": _iso(lo), "lte": _iso(hi)}}},
                    [{"@timestamp": "asc"}, {"_doc": "asc"}], source=ALERT_SOURCE)
            trace_q: dict = {"bool": {"should": [
                {"term": {"run.id": run_id}},
                {"bool": {"filter": [{"term": {"agent.role": "blue"}},
                                     {"range": {"@timestamp": {"gte": _iso(lo), "lte": _iso(hi)}}}]}},
            ], "minimum_should_match": 1}}
        else:
            trace_q = {"term": {"run.id": run_id}}
        traces = await _search_all(es, TRACE_STREAM, trace_q, [{"@timestamp": "asc"}],
                                   source={"excludes": ["tool.output"]}, limit=5000)
        return compute_report(run_id, gt, alerts, traces, grace_minutes=grace_minutes, platform=settings.edr)
    finally:
        if own:
            await es.close()


async def _fetch_s1_detections(lo: dt.datetime, hi: dt.datetime) -> list[dict]:
    """UAM alerts of the range site in the window (createdAt) incl. MITRE indicators; normalized in compute_report."""
    from .sentinelone import SentinelOne  # noqa: PLC0415
    from .uam import UAM, f_range  # noqa: PLC0415

    async with SentinelOne("orchestrator") as s1:
        uam = UAM(s1)
        alerts, _ = await uam.alerts([f_range("createdAt", lo, hi)], limit=MAX_ALERTS, sort_by="createdAt",
                                     order="ASC")
        details = await uam.details([a["id"] for a in alerts])
    for a in alerts:
        a["_detail"] = details.get(a["id"])
    return alerts


async def list_runs(limit: int = 20, es: Elastic | None = None) -> list[dict]:
    own = es is None
    es = es or Elastic("orchestrator")
    try:
        r = await es.es("POST", f"/{GROUNDTRUTH_STREAM}/_search", json={
            "size": 0,
            "aggs": {"runs": {"terms": {"field": "run.id", "size": limit, "order": {"last": "desc"}},
                              "aggs": {"first": {"min": {"field": "@timestamp"}},
                                       "last": {"max": {"field": "@timestamp"}},
                                       "last_end": {"max": {"field": "event.end"}},
                                       "success": {"filter": {"term": {"event.outcome": "success"}}}}}}})
    except ElasticError as exc:
        if exc.status == 404:
            return []
        raise
    finally:
        if own:
            await es.close()
    return [{"run_id": b["key"], "steps": b["doc_count"], "successful": b["success"]["doc_count"],
             "first": b["first"].get("value_as_string"),
             "last": b["last_end"].get("value_as_string") or b["last"].get("value_as_string")}
            for b in r["aggregations"]["runs"]["buckets"]]


def summary_doc(report: dict) -> dict:
    """Compact document for range-scores (without step details)."""
    s = report.get("summary", {})
    tri = report.get("triage", {})
    return {
        "@timestamp": report.get("generated_at") or now_iso(),
        "run": {"id": report["run_id"]},
        "event": {"kind": "metric", "dataset": "range.score"},
        "platform": report.get("platform", "elastic"),
        "range": {"window": report.get("window"), "grace_minutes": report.get("grace_minutes")},
        "score": {
            **{k: v for k, v in s.items() if not isinstance(v, dict)},
            "ttd_median_s": s.get("ttd_s", {}).get("median"), "ttd_mean_s": s.get("ttd_s", {}).get("mean"),
            "noise_rules": len(report.get("noise", {})),
        },
        "techniques": [{k: t[k] for k in ("technique", "name", "tactic", "steps", "successful", "detected",
                                          "detected_successful", "technique_match", "best_ttd_s")}
                       for t in report.get("techniques", [])],
        "engineer_rules": report.get("engineer_rules", []),
        "triage": {"blue_ran": tri.get("blue_ran"), "handled_alerts": tri.get("handled_alerts"),
                   "handled_rate": tri.get("handled_rate"), "cases": len(tri.get("cases", [])),
                   "response_actions": len(tri.get("response_actions", [])),
                   "ttt_median_s": (tri.get("time_to_triage_s") or {}).get("median")},
        "cost": report.get("cost"),
    }


SCORES_MAPPING = {
    "dynamic_templates": [
        {"strings": {"match_mapping_type": "string", "mapping": {"type": "keyword", "ignore_above": 1024}}},
        {"numbers": {"match_mapping_type": "long", "mapping": {"type": "double"}}},
    ],
    "properties": {
        "@timestamp": {"type": "date"},
        "run": {"properties": {"id": {"type": "keyword"}}},
        "range": {"properties": {"window": {"properties": {k: {"type": "date"} for k in
                                                            ("start", "end", "first_step", "last_step_end")}}}},
        "techniques": {"type": "nested"},
        "engineer_rules": {"type": "nested"},
        "cost": {"properties": {"total_usd": {"type": "double"}, "by_role": {"type": "flattened"}}},
    },
}


async def ensure_scores_index(es: Elastic) -> None:
    """Create range-scores with a fixed mapping (otherwise dynamic mapping would turn run.id into text)."""
    try:
        await es.es("PUT", f"/{SCORES_INDEX}", json={"mappings": SCORES_MAPPING})
    except ElasticError as exc:
        if "resource_already_exists" not in exc.body:
            raise


async def save_report(report: dict, es: Elastic | None = None, out_dir: Path | None = None) -> dict:
    out_dir = out_dir or REPORTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in report["run_id"])
    paths = {"json": out_dir / f"{safe}.json", "md": out_dir / f"{safe}.md"}
    paths["json"].write_text(json.dumps(report, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    paths["md"].write_text(render_markdown(report), encoding="utf-8")
    own = es is None
    es = es or Elastic("orchestrator")
    try:
        await ensure_scores_index(es)
        # one document per run (re-scoring replaces it); remove older entries with auto IDs (scorer v1)
        await es.es("PUT", f"/{SCORES_INDEX}/_doc/{safe}", json=summary_doc(report))
        await es.es("POST", f"/{SCORES_INDEX}/_delete_by_query", json={"query": {"bool": {
            "filter": [{"term": {"run.id": report["run_id"]}}], "must_not": [{"ids": {"values": [safe]}}]}}})
    finally:
        if own:
            await es.close()
    return {k: str(v) for k, v in paths.items()}


# --------------------------------------------------------------------------- Markdown

def _pct(v: float | None) -> str:
    return "-" if v is None else f"{v * 100:.0f} %"


def _sec(v: float | None) -> str:
    if v is None:
        return "-"
    return f"{v:.0f} s" if abs(v) < 120 else f"{v / 60:.1f} min"


def _cell(v: Any) -> str:
    return str(v).replace("|", "\\|").replace("\n", " ")


def render_markdown(report: dict) -> str:
    s = report.get("summary", {})
    L = [f"# Score {report['run_id']}", ""]
    w = report.get("window") or {}
    if not w.get("start"):
        L += ["No ground truth found for this run.", ""]
        return "\n".join(L)
    platform = {"sentinelone": "SentinelOne"}.get(report.get("platform", "elastic"), "Elastic Security")
    L += [f"Window: {w['start']} - {w['end']} (grace {report['grace_minutes']} min), generated {report['generated_at']}, "
          f"platform {platform}", "",
          "## Overview", "",
          "| Metric | Value |", "|---|---|",
          f"| Steps (successful) | {s['steps_total']} ({s['steps_successful']}) |",
          f"| Detection rate (successful / all) | {_pct(s['detection_rate'])} / {_pct(s['detection_rate_all'])} |",
          f"| Technique match (successful steps) | {_pct(s['technique_match_rate'])} |",
          f"| for comparison, lenient (every alert in the window counts for every step): detection / technique | "
          f"{_pct(s.get('detection_rate_window'))} / {_pct(s.get('technique_match_rate_window'))} |",
          f"| Techniques detected | {s['techniques_detected']}/{s['techniques_successful']} ({_pct(s['technique_detection_rate'])}) |",
          f"| TTD median / mean | {_sec(s['ttd_s']['median'])} / {_sec(s['ttd_s']['mean'])} |",
          f"| Alerts in window (matched / unmatched) | {s['alerts_in_window']} ({s['alerts_matched']} / {s['alerts_unmatched']}) |",
          "", "## Steps", "",
          "| # | Start | Technique | Target | Outcome | Detected | Technique ok | TTD | Alerts | Rules |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for r in report["steps"]:
        rules = ", ".join(r["rules"][:3]) + (f" (+{len(r['rules']) - 3})" if len(r["rules"]) > 3 else "")
        L.append(f"| {r['n']} | {r['start'][11:19]} | {r['technique']} {_cell(r['technique_name'])} | "
                 f"{_cell(', '.join(r['targets']))} | {r['outcome']} | {'yes' if r['detected'] else 'no'} | "
                 f"{'yes' if r['technique_match'] else 'no'} | {_sec(r['ttd_s'])} | {r['alerts']} | {_cell(rules)} |")
    L += ["", "## Techniques", "", "| Technique | Tactic | Steps (successful) | Detected | Technique ok | Best TTD |",
          "|---|---|---|---|---|---|"]
    for t in report["techniques"]:
        L.append(f"| {t['technique']} {_cell(t['name'])} | {_cell(t['tactic'])} | {t['steps']} ({t['successful']}) | "
                 f"{t['detected']} | {t['technique_match']} | {_sec(t['best_ttd_s'])} |")
    if report.get("noise"):
        L += ["", "## Unmatched alerts (noise)", "", "| Rule | Count |", "|---|---|"]
        L += [f"| {_cell(k)} | {v} |" for k, v in list(report["noise"].items())[:15]]
    if report.get("engineer_rules"):
        L += ["", "## Engineer rules (tag ai-range)", "", "| Rule | Alerts | Matched |", "|---|---|---|"]
        L += [f"| {_cell(e['rule'])} | {e['alerts']} | {e['matched']} |" for e in report["engineer_rules"]]
    t = report.get("triage", {})
    L += ["", "## Triage", "", "| Metric | Value |", "|---|---|",
          f"| Blue ran | {'yes' if t.get('blue_ran') else 'no'} ({t.get('blue_tool_calls', 0)} tool calls) |",
          f"| Handled alerts | {t.get('handled_alerts', 0)}/{t.get('matched_alerts', 0)} ({_pct(t.get('handled_rate'))}) |",
          f"| Workflow status | {_cell(', '.join(f'{k}: {v}' for k, v in (t.get('workflow_status') or {}).items()) or '-')} |",
          f"| Time to triage, median | {_sec((t.get('time_to_triage_s') or {}).get('median'))} |",
          f"| Cases / response actions | {len(t.get('cases', []))} / {len(t.get('response_actions', []))} |"]
    c = report.get("cost", {})
    L += ["", "## Cost", "", "| Role | Runs | Tokens | USD |", "|---|---|---|---|"]
    for role, v in (c.get("by_role") or {}).items():
        L.append(f"| {role} | {v['runs']} | {v['tokens']} | {v['cost_usd']:.2f} |")
    L.append(f"| **Total** | | | **{c.get('total_usd', 0):.2f}** |")
    L.append("")
    return "\n".join(L)
