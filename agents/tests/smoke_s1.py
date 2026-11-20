"""Smoke test of the SentinelOne integration.

offline: pure functions (time, PowerQuery scoping/limit, normalization, scorer with synthetic S1 detections,
         the engineer's rule body) - needs neither the console nor Elastic. Uses the fixture topology
         tests/range.test.yaml, not your range.yaml.
read:    live, read-only (S1_* set): PowerQuery, UAM list_alerts/get_alert,
         list_rules, response_action status. Uses your range.yaml.

Usage: cd docker && docker compose --env-file .env run --rm -T --entrypoint python agents tests/smoke_s1.py [offline|read]
"""
from __future__ import annotations

import asyncio
import datetime as dt
import sys

MODE = sys.argv[1] if len(sys.argv) > 1 else "offline"
if MODE == "offline":
    from offline_fixture import use_fixture
    use_fixture()

from airange import scorer  # noqa: E402
from airange.config import settings  # noqa: E402
from airange.sentinelone import scope_query, split_pipeline, to_iso, to_pq_time  # noqa: E402
from airange.topology import TOPOLOGY  # noqa: E402

KALI = settings.kali_host           # attacker from the topology (as used by the scorer)


def iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def offline() -> None:
    from airange.tools.blue_s1 import check_ids, enforce_pq_limit, verdict_value
    from airange.tools.engineer_s1 import NAME_PREFIX, _rule_data
    from airange.uam import mitre_ids, rule_name, summary

    # --- PowerQuery helpers
    assert split_pipeline("a = 'x|y' | group count()") == ("a = 'x|y'", "| group count()")
    assert split_pipeline("| limit 5") == ("", "| limit 5")
    assert scope_query("event.type = 'Login' | limit 5", "123") == "site.id = '123' and (event.type = 'Login') | limit 5"
    assert scope_query("| limit 5", "123") == "site.id = '123' | limit 5"
    assert scope_query("x = 1", "") == "x = 1"
    assert enforce_pq_limit("a = 1", 100) == "a = 1 | limit 100"
    assert enforce_pq_limit("a = 1 | limit 500", 100) == "a = 1 | limit 100"
    assert enforce_pq_limit("a = 1 | limit 5", 100) == "a = 1 | limit 5"
    assert to_pq_time("now-2h") == "2h" and to_pq_time("-90m") == "90m" and to_pq_time(None) is None
    assert to_pq_time("2026-01-01T00:00:00Z") == "1767225600000"
    assert to_iso("2026-01-01T00:00:00Z") == "2026-01-01T00:00:00.000Z"
    assert to_iso("now-1h") < to_iso("now")
    assert verdict_value("true_positive") == "TRUE_POSITIVE_UNDEFINED"
    assert verdict_value("false_positive_benign") == "FALSE_POSITIVE_BENIGN"
    assert check_ids(["019dd7eb-3d33-7608-b636-8cc43be9c4fc"])
    try:
        check_ids(["threat:1"])
        raise AssertionError("an invalid ID must fail")
    except Exception as exc:  # noqa: BLE001
        assert "Invalid" in str(exc), exc

    # --- engineer rule body
    d = _rule_data({"name": "LSASS access", "description": "x\nMITRE ATT&CK: T9999", "type": "events",
                    "query": "event.type = 'Open Remote Process Handle' and tgt.process.name = 'lsass.exe'",
                    "severity": "high", "mitre": ["TA0006:T1003.001"]})
    assert d["name"] == NAME_PREFIX + "LSASS access" and d["severity"] == "High"
    assert d["description"].endswith("MITRE ATT&CK: T1003.001") and "T9999" not in d["description"]
    assert d["networkQuarantine"] is False and d["treatAsThreat"] == "UNDEFINED" and d["queryLang"] == "2.0"
    d2 = _rule_data({"severity": "low"}, {**d, "queryType": "events"})
    assert d2["name"] == d["name"] and d2["s1ql"] == d["s1ql"] and "T1003.001" in d2["description"]
    ds = _rule_data({"name": "spray", "description": "y", "type": "scheduled", "threshold": 5,
                     "query": "event.type = 'Login' | group n = count() by src.ip.address | filter n > 10"})
    assert ds["scheduledParams"]["runIntervalMinutes"] == 5 and ds["scheduledParams"]["threshold"]["value"] == 5
    try:
        _rule_data({"name": "x", "description": "y", "type": "events", "query": "a = 1 | limit 1"})
        raise AssertionError("an events rule with a pipe must fail")
    except Exception as exc:  # noqa: BLE001
        assert "scheduled" in str(exc)

    # --- normalization + scorer (UAM alerts as returned by alerts{...})
    t0 = dt.datetime(2026, 11, 14, 10, 0, tzinfo=dt.timezone.utc)

    def uam(aid, name, product, host, created, detected, status="NEW", desc=None, attacker=None, ips=None,
            detail=None, sev="HIGH"):
        return {"id": aid, "name": name, "description": desc, "severity": sev, "status": status,
                "analystVerdict": "UNDEFINED", "createdAt": iso(created), "detectedAt": iso(detected),
                "updatedAt": iso(created + dt.timedelta(minutes=5)), "detectionSource": {"product": product},
                "assets": [{"name": host, "primary": True}],
                "detectionTime": {"asset": {"ipV4Addresses": ips or []}, "attacker": {"ip": attacker} if attacker else None},
                "process": {"cmdLine": "x", "file": {"name": "mimi.exe"}}, "_detail": detail}

    edr = uam("aaaaaaaa-0000-0000-0000-000000000001", "mimi.exe (CLI 1a2b) - Credential Dumping detected", "EDR",
              "WS01", t0 + dt.timedelta(seconds=40), t0 + dt.timedelta(seconds=5), status="IN_PROGRESS",
              ips=["10.0.21.51"],
              detail={"indicators": [{"attacks": [{"tactic": {"uid": "Credential Access"},
                                                   "technique": {"uid": "T1003.001"}}]},
                                     {"attacks": [{"tactic": {"uid": "PowerShell"}, "technique": {"uid": "PowerShell"}}]}]})
    star = uam("aaaaaaaa-0000-0000-0000-000000000002", "ai-range: Password Spray", "STAR", "DC01.corp.internal",
               t0 + dt.timedelta(minutes=10, seconds=30), t0 + dt.timedelta(minutes=10, seconds=3),
               desc="MITRE ATT&CK: T1110.003", attacker=KALI, sev="MEDIUM")
    noise = uam("aaaaaaaa-0000-0000-0000-000000000003", "Some Vendor Rule", "STAR", "lnx-db01",
                t0 + dt.timedelta(minutes=2), t0 + dt.timedelta(minutes=2), sev="INFO")
    assert rule_name(edr) == "Credential Dumping detected" and rule_name(star) == "ai-range: Password Spray"
    assert mitre_ids(edr["_detail"], edr) == ["T1003.001"]
    n = scorer.norm_s1(edr)
    assert n["hosts"] == {"ws01"} and n["host_ips"] == {"10.0.21.51"} and n["techniques"] == {"T1003.001"}
    assert n["workflow_status"] == "acknowledged" and n["event_known"]
    a = scorer.norm_s1(star)
    assert a["hosts"] == {"dc01"} and a["techniques"] == {"T1110.003"} and a["rule_tags"] == ["ai-range"]
    assert a["source_ips"] == {KALI} and a["workflow_status"] == "open"
    sm = summary(edr)
    assert sm["status"] == "acknowledged" and sm["host"] == "ws01" and sm["severity"] == "high"

    def gt(start, end, tech, hosts, ips):
        return {"_source": {"@timestamp": iso(start), "run": {"id": "t"}, "source": {"ip": KALI},
                            "threat": {"technique": {"id": tech, "name": tech}, "tactic": {"name": "x"}},
                            "process": {"command_line": "x"}, "event": {"outcome": "success", "end": iso(end)},
                            "range": {"target_hosts": hosts, "target_ips": ips}}}

    gts = [gt(t0, t0 + dt.timedelta(seconds=20), "T1003.001", ["ws01"], ["10.0.21.51"]),
           gt(t0 + dt.timedelta(minutes=10), t0 + dt.timedelta(minutes=10, seconds=20), "T1110.003", ["dc01"],
              ["10.0.21.10"]),
           gt(t0 + dt.timedelta(minutes=20), t0 + dt.timedelta(minutes=20, seconds=5), "T1046", ["fs01"],
              ["10.0.21.13"])]
    rep = scorer.compute_report("t", gts, [edr, star, noise], [], platform="sentinelone")
    s = rep["summary"]
    assert rep["platform"] == "sentinelone"
    assert [r["detected"] for r in rep["steps"]] == [True, True, False], rep["steps"]
    assert [r["technique_match"] for r in rep["steps"]] == [True, True, False]
    assert s["alerts_matched"] == 2 and s["alerts_unmatched"] == 1 and rep["noise"] == {"Some Vendor Rule": 1}
    assert rep["steps"][0]["ttd_s"] == 40.0
    assert rep["engineer_rules"] == [{"rule": "ai-range: Password Spray", "alerts": 1, "matched": 1}]
    assert rep["triage"]["workflow_status"] == {"acknowledged": 1, "open": 1}
    assert "platform SentinelOne" in scorer.render_markdown(rep)

    # --- vulnerabilities (xSPM): filters, range guard, summary per CVE
    from airange.tools.blue_s1 import check_cve, range_host_filter, vuln_filters
    from airange.xspm import by_cve, group_row
    from airange.xspm import summary as vsum

    assert range_host_filter("WS01.corp.internal") == {"fieldId": "assetName",
                                                         "match": {"operator": "exactMatch", "values": ["ws01"]}}
    assert "dc01" in range_host_filter()["match"]["values"] and "test01" not in range_host_filter()["match"]["values"]
    for bad in (lambda: range_host_filter("test01"), lambda: check_cve("CVE-1"), lambda: vuln_filters({"status": ["x"]})):
        try:
            bad()
            raise AssertionError("must fail")
        except Exception as exc:  # noqa: BLE001
            assert "must fail" not in str(exc)
    fl = vuln_filters({"host": "ws01", "min_severity": "high", "cve": "cve-2026-32202", "kev": True, "software": "win"})
    assert {"fieldId": "severity", "stringIn": {"values": ["HIGH", "CRITICAL"]}} in fl
    assert {"fieldId": "status", "stringIn": {"values": ["NEW", "IN_PROGRESS"]}} in fl
    assert {"fieldId": "cveId", "stringIn": {"values": ["CVE-2026-32202"]}} in fl
    assert {"fieldId": "cveKevAvailable", "booleanEqual": {"value": True}} in fl

    def vuln(vid, cve, host, risk, sev="HIGH"):
        return {"id": vid, "name": "Title\nsecond line", "severity": sev, "status": "NEW", "analystVerdict": None,
                "asset": {"name": host}, "cve": {"id": cve, "riskScore": risk, "epssScore": 0.713244,
                                                 "exploitedInTheWild": True},
                "software": {"name": "Windows 11 Pro", "version": "10.0", "fixVersion": "kb1", "fixVersionAvailable": True}}

    v = vsum(vuln("1", "CVE-2026-1", "WS01.corp.internal", "7.3"))
    assert v["host"] == "ws01" and v["risk_score"] == 7.3 and v["epss"] == 0.7132 and v["title"] == "Title"
    assert v["status"] == "new" and v["fix"] == "kb1" and "verdict" not in v
    g = by_cve([vuln("1", "CVE-2026-1", "WS01", 7.3), vuln("2", "CVE-2026-2", "DC01", 6.0), vuln("3", "CVE-2026-1", "ws02", 7.3)])
    assert [x["cve"] for x in g] == ["CVE-2026-1", "CVE-2026-2"]
    assert g[0]["findings"] == 2 and g[0]["hosts"] == ["ws01", "ws02"] and g[0]["example_id"] == "1"
    assert group_row({"value": "DC01", "count": 5, "fieldSummaries": [
        {"__typename": "ValueCountSummary", "fieldId": "severity", "values": [{"value": "LOW", "count": 5}]},
        {"__typename": "DistinctCountSummary", "fieldId": "cveId", "distinctCount": 4},
        {"__typename": "SampleSummary", "fieldId": "cveId"}]}) == {
            "value": "DC01", "findings": 5, "severity": {"low": 5}, "cveId_distinct": 4}
    print("offline: all checks ok")


def show(name: str, res: dict, n: int = 1500) -> str:
    txt = res["content"][0]["text"]
    print(f"=== {name} is_error={res.get('is_error')} len={len(txt)}\n{txt[:n]}\n")
    return txt


async def read() -> None:
    from airange.sentinelone import SentinelOne
    from airange.tools.blue_s1 import build_blue_tools_s1
    from airange.tools.engineer_s1 import build_engineer_tools_s1

    client = TOPOLOGY.example("client")         # e.g. ws01
    attacker = TOPOLOGY.attacker.host           # not a target -> must be refused
    async with SentinelOne("blue") as s1:
        T = {t.name: t.handler for t in build_blue_tools_s1(s1)}
        E = {t.name: t.handler for t in build_engineer_tools_s1(s1)}
        show("powerquery agg", await T["powerquery"]({
            "query": "event.type = 'Process Creation' | group n = count() by endpoint.name | sort -n", "start": "2h"}))
        show("powerquery rows", await T["powerquery"]({
            "query": "event.type = 'Process Creation' | columns event.time, endpoint.name, src.process.user, "
                     "tgt.process.cmdline | sort -event.time", "start": "1h", "max_rows": 3}))
        show("powerquery bad syntax", await T["powerquery"]({"query": "event.type = | limit 1"}), 500)
        txt = show("list_alerts", await T["list_alerts"]({"since": "now-365d", "limit": 5,
                                                           "status": ["open", "acknowledged", "closed"]}), 3000)
        first = next((line.split('"id":"')[1].split('"')[0] for line in txt.splitlines() if '"id":"' in line), None)
        if first:
            show(f"get_alert {first}", await T["get_alert"]({"id": first}), 5000)
        show("list_rules", await E["list_rules"]({"limit": 5}), 2000)
        show(f"status {client}", await T["response_action"]({"action": "status", "host": client}), 800)
        show("bad alert id (must fail)", await T["get_alert"]({"id": "threat:1"}), 300)
        show("not range host (must fail)", await T["response_action"]({"action": "status", "host": attacker}), 400)
        # --- vulnerabilities (xSPM), read-only
        txt = show("list_vulnerabilities exploited", await T["list_vulnerabilities"]({"exploited_in_wild": True,
                                                                                       "limit": 5}), 3500)
        vid = next((line.split('"example_id":"')[1].split('"')[0] for line in txt.splitlines()
                    if '"example_id":"' in line), None)
        show("list_vulnerabilities by host", await T["list_vulnerabilities"]({"group_by": "host"}), 2500)
        show(f"list_vulnerabilities rows {client}", await T["list_vulnerabilities"]({
            "host": client.upper(), "min_severity": "high", "group_by": "none", "sort": "epss", "limit": 3}), 2500)
        show("list_vulnerabilities since/kev/software", await T["list_vulnerabilities"]({
            "kev": True, "software": "windows", "since": "now-30d", "fix_available": True, "limit": 2}), 2000)
        if vid:
            show(f"get_vulnerability {vid}", await T["get_vulnerability"]({"id": vid}), 6000)
        show("vuln not range host (must fail)", await T["list_vulnerabilities"]({"host": "test01"}), 300)
        show("vuln update without selection (must fail)", await T["update_vulnerabilities"]({"verdict": "true_positive"}), 300)
        show("vuln update resolved (must fail)", await T["update_vulnerabilities"]({
            "cve": "CVE-2026-32202", "status": "resolved"}), 400)
        show("vuln update unknown cve (must fail, no write access)", await T["update_vulnerabilities"]({
            "cve": "CVE-1999-0001", "verdict": "false_positive"}), 300)


if __name__ == "__main__":
    if MODE == "offline":
        offline()
    else:
        asyncio.run(read())
