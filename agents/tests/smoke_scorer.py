"""Smoke test for airange.scorer.

Part 1 (offline): synthetic ground truth + synthetic alerts -> compute_report, numbers checked by assert.
                  Uses the fixture topology tests/range.test.yaml, not your range.yaml.
Part 2 (live):    write synthetic ground truth (run.id test-scorer-*) matching REAL alerts, run
                  score_run + save_report, verify expectations independently via ES queries, then clean up.
                  Alerts are only read. Uses your range.yaml.

Usage: cd docker && docker compose --env-file .env run --rm -T --entrypoint python agents tests/smoke_scorer.py [--offline]
  --offline   part 1 only (no Elastic needed); without it, part 1 runs in a subprocess, then part 2.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import json
import secrets
import subprocess
import sys
from pathlib import Path

if "--offline" in sys.argv:
    from offline_fixture import use_fixture
    use_fixture()

from airange import scorer  # noqa: E402
from airange.config import settings  # noqa: E402
from airange.elastic import Elastic  # noqa: E402
from airange.topology import TOPOLOGY  # noqa: E402
from airange.trace import GROUNDTRUTH_STREAM, TRACE_STREAM  # noqa: E402

KALI = settings.kali_host           # attacker from the topology (as used by the scorer)


def iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def gt(start, end, tech, hosts=(), ips=(), outcome="success"):
    d = {"@timestamp": iso(start), "run": {"id": RUN}, "agent": {"name": "smoke"}, "source": {"ip": KALI},
         "threat": {"technique": {"id": tech, "name": f"name-{tech}"}, "tactic": {"name": "test"}},
         "process": {"command_line": "echo smoke"}, "event": {"outcome": outcome, "end": iso(end)},
         "message": "smoke", "range": {}}
    if ips:
        d["destination"] = {"ip": ips[0]}
        d["range"]["target_ips"] = list(ips)
    if hosts:
        d["host"] = {"name": hosts[0]}
        d["range"]["target_hosts"] = list(hosts)
    return d


RUN = f"test-scorer-{dt.datetime.now(dt.timezone.utc):%Y%m%d-%H%M%S}-{secrets.token_hex(2)}"


# --------------------------------------------------------------------------- part 1: offline

def offline() -> None:
    t0 = dt.datetime(2026, 11, 1, 10, 0, tzinfo=dt.timezone.utc)
    m = dt.timedelta(minutes=1)
    gts = [
        {"_source": gt(t0, t0 + m, "T1558.003", hosts=["DC01"])},                  # host match + technique
        {"_source": gt(t0 + 10 * m, t0 + 11 * m, "T1021.002", ips=["10.0.21.13"])},  # IP->fs01, wrong technique
        {"_source": gt(t0 + 20 * m, t0 + 21 * m, "T1110", ips=["10.0.21.101"], outcome="failure")},  # nothing
    ]
    # avoid Kali IP matches: step 3 targets lnx-db01, the alerts below have no source.ip=Kali
    alerts = [
        {"_id": "a1", "_source": {"@timestamp": iso(t0 + 2 * m), "host": {"name": "dc01"},
                                  "kibana.alert.rule.name": "Kerberoasting",
                                  "kibana.alert.rule.threat": [{"technique": [{"id": "T1558", "subtechnique": [{"id": "T1558.003"}]}]}],
                                  "kibana.alert.workflow_status": "acknowledged",
                                  "kibana.alert.workflow_status_updated_at": iso(t0 + 7 * m),
                                  "kibana.alert.workflow_user": "u-blue"}},
        {"_id": "a2", "_source": {"@timestamp": iso(t0 + 12 * m), "host": {"name": "FS01.corp.internal"},
                                  "kibana.alert.rule.name": "Something",
                                  "kibana.alert.rule.tags": ["ai-range"],
                                  "kibana.alert.rule.threat": [{"technique": [{"id": "T1059"}]}],
                                  "kibana.alert.workflow_status": "open"}},
        {"_id": "a3", "_source": {"@timestamp": iso(t0 + 15 * m), "host": {"name": "ws02"},
                                  "kibana.alert.rule.name": "Noise", "kibana.alert.workflow_status": "open"}},
        {"_id": "a4", "_source": {"@timestamp": iso(t0 - 30 * m), "host": {"name": "dc01"},
                                  "kibana.alert.rule.name": "Before window"}},
    ]
    traces = [
        {"_source": {"@timestamp": iso(t0 + 30 * m), "run": {"id": RUN}, "agent": {"role": "red"},
                     "tool": {"name": "run-summary"}, "llm": {"cost_usd": 1.25, "tokens": {"total": 1000}}}},
        {"_source": {"@timestamp": iso(t0 + 40 * m), "run": {"id": "blue-x"}, "agent": {"role": "blue"},
                     "tool": {"name": "create_case", "input": {"title": "Kerberoasting"}}, "event": {"outcome": "success"}}},
        {"_source": {"@timestamp": iso(t0 + 41 * m), "run": {"id": "blue-x"}, "agent": {"role": "blue"},
                     "tool": {"name": "run-summary"}, "llm": {"cost_usd": 0.5}}},
    ]
    r = scorer.compute_report(RUN, gts, alerts, traces, grace_minutes=30)
    s = r["summary"]
    st = r["steps"]
    assert [x["detected"] for x in st] == [True, True, False], st
    assert [x["technique_match"] for x in st] == [True, False, False], st
    assert st[0]["ttd_s"] == 120.0 and st[1]["ttd_s"] == 120.0, st
    # step 1 window until t0+1m+30m -> a2 (fs01) does not belong to dc01; a3 ws02 is noise
    assert st[0]["alerts"] == 1 and st[1]["alerts"] == 1, st
    assert s["steps_total"] == 3 and s["steps_successful"] == 2
    assert s["detection_rate"] == 1.0 and s["detection_rate_all"] == 0.667
    assert s["technique_match_rate"] == 0.5 and s["technique_detection_rate"] == 1.0
    assert s["alerts_in_window"] == 3 and s["alerts_unmatched"] == 1 and r["noise"] == {"Noise": 1}
    assert r["engineer_rules"] == [{"rule": "Something", "alerts": 1, "matched": 1}]
    t = r["triage"]
    assert t["handled_alerts"] == 1 and t["time_to_triage_s"]["median"] == 300.0 and len(t["cases"]) == 1, t
    assert r["cost"]["total_usd"] == 1.25 and "blue" not in r["cost"]["by_role"]  # Blue cost: different run
    md = scorer.render_markdown(r)
    assert "## Steps" in md and "## Cost" in md
    print("[offline] OK")
    offline_assign()


def offline_assign() -> None:
    """One alert -> exactly one step (event_ts decides, technique preferred)."""
    t0 = dt.datetime(2026, 11, 1, 12, 0, tzinfo=dt.timezone.utc)
    s = dt.timedelta(seconds=1)
    gts = [
        {"_source": gt(t0, t0 + 5 * s, "T1046", hosts=["DC01"])},
        {"_source": gt(t0 + 20 * s, t0 + 25 * s, "T1087.002", hosts=["DC01"])},
        {"_source": gt(t0 + 40 * s, t0 + 45 * s, "T1649", hosts=["DC01"])},
        {"_source": gt(t0 + 60 * s, t0 + 65 * s, "T1069", hosts=["DC01"])},   # nothing of its own
    ]
    th = lambda tid: [{"technique": [{"id": tid}]}]  # noqa: E731
    alerts = [
        # event in step 2, alert created only 3 min later -> step 2 only, TTD 180 s
        {"_id": "b1", "_source": {"@timestamp": iso(t0 + 200 * s), "host": {"name": "dc01"},
                                  "kibana.alert.original_time": iso(t0 + 21 * s),
                                  "kibana.alert.rule.name": "Account Disc", "kibana.alert.rule.threat": th("T1087")}},
        # without original_time (ES|QL aggregation): alert time 70 s -> preceding steps <=10 min,
        # technique match (T1649) wins over the closer step 4
        {"_id": "b2", "_source": {"@timestamp": iso(t0 + 70 * s), "host": {"name": "dc01"},
                                  "kibana.alert.rule.name": "ADCS", "kibana.alert.rule.threat": th("T1649")}},
        # broad alert without technique, event between steps -> closest preceding step (1)
        {"_id": "b3", "_source": {"@timestamp": iso(t0 + 300 * s), "host": {"name": "dc01"},
                                  "kibana.alert.original_time": iso(t0 + 12 * s),
                                  "kibana.alert.rule.name": "Sweep"}},
    ]
    r = scorer.compute_report(RUN, gts, alerts, [], grace_minutes=30)
    st = r["steps"]
    assert [x["detected"] for x in st] == [True, True, True, False], st
    assert [x["technique_match"] for x in st] == [False, True, True, False], st
    assert [x["alerts"] for x in st] == [1, 1, 1, 0], st
    assert st[1]["ttd_s"] == 180.0 and st[2]["ttd_s"] == 30.0, st
    # lenient count: all 4 steps "detected"
    assert all(x["detected_window"] for x in st) and r["summary"]["detection_rate_window"] == 1.0
    assert r["summary"]["detection_rate"] == 0.75 and r["summary"]["alerts_unmatched"] == 0
    print("[offline-assign] OK")


# --------------------------------------------------------------------------- part 2: live

def unused_ip() -> str:
    """An address in the range network without a VM (no agent there, so no alerts expected)."""
    used = {v.ip for v in TOPOLOGY.vms} | {TOPOLOGY.gateway, TOPOLOGY.controller_ip}
    hosts = list(ipaddress.ip_network(TOPOLOGY.cidr).hosts())
    return next(str(ip) for ip in reversed(hosts) if str(ip) not in used)


async def live() -> int:
    async with Elastic("orchestrator") as es:
        # look for real alerts with host + technique from the last 7 days
        r = await es.es("POST", f"/{scorer.ALERTS_INDEX}/_search", json={
            "size": 500, "sort": [{"@timestamp": "desc"}], "_source": scorer.ALERT_SOURCE,
            "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": "now-7d"}}},
                                          {"exists": {"field": "host.name"}}]}}})
        hits = r["hits"]["hits"]
        print(f"[live] alerts (7 d, with host.name): {len(hits)} loaded, total {r['hits']['total']}")
        if not hits:
            print("[live] no alerts -> skipped")
            return 0
        norm = [a for a in (scorer._norm_alert(h) for h in hits) if a]
        print("[live] example alert fields:", json.dumps({k: (sorted(v) if isinstance(v, set) else str(v))
                                                        for k, v in norm[0].items()}, ensure_ascii=False)[:800])
        with_tech = [a for a in norm if a["techniques"] and a["hosts"]]
        a1 = with_tech[0] if with_tech else norm[0]
        a2 = next((a for a in norm if a["hosts"].isdisjoint(a1["hosts"])), None)
        host1 = sorted(a1["hosts"])[0]
        tech1 = sorted(a1["techniques"])[0] if a1["techniques"] else "T9999"
        # sub-technique variant, to test the base comparison
        tech1_q = tech1 if "." in tech1 else tech1 + ".001"
        m = dt.timedelta(minutes=1)
        docs = [gt(a1["ts"] - 3 * m, a1["ts"] - 2 * m, tech1_q, hosts=[host1.upper()])]
        if a2:
            host2 = sorted(a2["hosts"])[0]
            ip2 = scorer.RANGE_IPS.get(host2)
            docs.append(gt(a2["ts"] - 2 * m, a2["ts"] - m, "T9998", ips=[ip2] if ip2 else (), hosts=() if ip2 else [host2]))
        # step without (expected) alerts: 6 h earlier, address without a VM/agent, failed
        t_old = a1["ts"] - 6 * 60 * m
        docs.append(gt(t_old, t_old + m, "T1046", ips=[unused_ip()], outcome="failure"))
        # refresh=wait_for instead of _refresh (the orchestrator has no maintenance privilege)
        for d in docs:
            await es.es("POST", f"/{GROUNDTRUTH_STREAM}/_doc", json=d, params={"refresh": "wait_for"})
        print(f"[live] {len(docs)} GT documents written, run.id={RUN}")
        rc = 0
        try:
            grace = 5
            rep = await scorer.score_run(RUN, grace_minutes=grace, es=es)
            print(json.dumps({"summary": rep["summary"], "techniques": rep["techniques"], "noise_top": dict(list(rep["noise"].items())[:5]),
                              "engineer_rules": rep["engineer_rules"], "triage": {k: v for k, v in rep["triage"].items() if k not in ("cases", "response_actions")},
                              "cost": rep["cost"]}, indent=1, ensure_ascii=False, default=str))
            for row in rep["steps"]:
                print("[live] step", {k: row[k] for k in ("n", "start", "technique", "targets", "outcome", "detected",
                                                            "technique_match", "ttd_s", "alerts", "alerts_by_reason")}, row["rules"][:5])

            # independent expectation per step via ES _count: host/IP/Kali IP in [start-1m, end+grace]
            async def expected(d: dict) -> int:
                hosts = [h.lower() for h in d.get("range", {}).get("target_hosts", [])]
                ips = list(d.get("range", {}).get("target_ips", []))
                hosts += [scorer.RANGE_HOSTS[i] for i in ips if i in scorer.RANGE_HOSTS]
                ips += [scorer.RANGE_IPS[h] for h in hosts if h in scorer.RANGE_IPS]
                lo = dt.datetime.fromisoformat(d["@timestamp"].replace("Z", "+00:00")) - m
                hi = dt.datetime.fromisoformat(d["event"]["end"].replace("Z", "+00:00")) + grace * m
                should = [{"terms": {"source.ip": ips + [KALI]}}, {"terms": {"destination.ip": ips + [KALI]}}]
                if hosts:
                    should += [{"terms": {"host.name": hosts + [h.upper() for h in hosts]}}]
                    should += [{"prefix": {"host.name": h + "."}} for h in hosts]
                if ips:
                    should.append({"terms": {"host.ip": ips}})
                c = await es.es("POST", f"/{scorer.ALERTS_INDEX}/_count", json={"query": {"bool": {
                    "filter": [{"range": {"@timestamp": {"gte": iso(lo), "lte": iso(hi)}}}],
                    "should": should, "minimum_should_match": 1}}})
                return c["count"]

            by_tech = {row["technique"]: row for row in rep["steps"]}
            checks = {"steps_total": rep["summary"]["steps_total"] == len(docs),
                      "matched+unmatched == in_window": rep["summary"]["alerts_matched"] + rep["summary"]["alerts_unmatched"]
                      == rep["summary"]["alerts_in_window"]}
            for d in docs:
                tid = d["threat"]["technique"]["id"]
                row = by_tech[tid]
                exp = await expected(d)
                checks[f"{tid}: alerts {row['alerts']} == ES count {exp}"] = row["alerts"] == exp
                checks[f"{tid}: detected == (count>0)"] = row["detected"] == (exp > 0)
            s1 = by_tech[tech1_q]
            checks[f"{tech1_q}: technique_match (alert has {tech1})"] = s1["technique_match"] is (tech1 != "T9999")
            checks[f"{tech1_q}: ttd 0..180 s (step 3 min before alert)"] = s1["ttd_s"] is not None and 0 <= s1["ttd_s"] <= 180
            if a2:
                checks["T9998: technique_match False"] = by_tech["T9998"]["technique_match"] is False
            for k, ok in checks.items():
                print(f"[live] {'OK ' if ok else 'FAIL'} {k}")
            rc = 0 if all(checks.values()) else 1

            paths = await scorer.save_report(rep, es=es)
            print("[live] saved:", paths)
            print(Path(paths["md"]).read_text(encoding="utf-8")[:3000])
            runs = await scorer.list_runs(5, es=es)
            print("[live] list_runs:", runs)
            assert any(x["run_id"] == RUN and x["steps"] == len(docs) for x in runs), runs
            for p in paths.values():
                Path(p).unlink(missing_ok=True)
        finally:
            await asyncio.sleep(2)   # let the range-scores document become visible (no _refresh privilege)
            for idx in (GROUNDTRUTH_STREAM, scorer.SCORES_INDEX):
                try:
                    d = await es.es("POST", f"/{idx}/_delete_by_query", json={"query": {"bool": {"should": [
                        {"prefix": {"run.id": "test-scorer-"}}, {"prefix": {"run.id.keyword": "test-scorer-"}}]}}},
                                    params={"ignore_unavailable": "true", "conflicts": "proceed"})
                    print(f"[cleanup] {idx}: {d.get('deleted')} deleted")
                except Exception as exc:  # noqa: BLE001
                    print(f"[cleanup] {idx} ERROR: {exc}")
                    rc = 1
        return rc


if __name__ == "__main__":
    if "--offline" in sys.argv:
        offline()
        sys.exit(0)
    # part 1 needs the fixture topology, which must be set before airange is imported -> separate process
    rc = subprocess.call([sys.executable, __file__, "--offline"])
    if rc:
        sys.exit(rc)
    sys.exit(asyncio.run(live()))
