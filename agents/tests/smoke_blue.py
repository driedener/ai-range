"""Live smoke test of the Blue tools (without an LLM). Hosts come from your range.yaml. Usage:
  docker compose --env-file .env run --rm -T --entrypoint python agents tests/smoke_blue.py [read|mutate|isolate|kill-off]
"""
import asyncio, json, sys
from airange.elastic import Elastic
from airange.tools.blue import build_blue_tools
from airange.topology import TOPOLOGY

# Test client (the last one - isolate/release hits it) and the attacker, which is not a valid target
CLIENT = (TOPOLOGY.by_role("client") or TOPOLOGY.targets)[-1]
HOST, HOST_UP = CLIENT.host, CLIENT.name.upper()
ATTACKER = TOPOLOGY.attacker.host

def parse(txt):
    """Parse the compact_lines format back into a dict."""
    try:
        return json.loads(txt)
    except ValueError:
        pass
    out, cur = {}, None
    for line in txt.splitlines():
        if cur is not None:
            if line == "]":
                cur = None
            else:
                out[key].append(json.loads(line.strip().rstrip(",")))
            continue
        key, _, val = line.partition(": ")
        if val == "[":
            out[key], cur = [], key
        else:
            out[key] = json.loads(val)
    return out

def show(name, res, n=1500):
    txt = res["content"][0]["text"]
    print(f"=== {name} is_error={res.get('is_error')} len={len(txt)}\n{txt[:n]}\n")
    return txt

async def main(mode):
    async with Elastic("blue") as es:
        T = {t.name: t.handler for t in build_blue_tools(es)}
        print("TOOLS", list(T))
        if mode == "read":
            show("esql", await T["esql"]({"query": "FROM logs-endpoint.events.process-* | WHERE host.name == \"" + HOST + "\" | KEEP @timestamp, host.name, user.name, process.name, process.command_line | SORT @timestamp DESC", "max_rows": 5}))
            show("esql big limit", await T["esql"]({"query": "FROM logs-* | STATS c=COUNT(*) BY data_stream.dataset | LIMIT 5000"}), 600)
            show("esql alerts", await T["esql"]({"query": "FROM .alerts-security.alerts-default | STATS c=COUNT(*) BY kibana.alert.workflow_status"}))
            show("esql groundtruth (must fail)", await T["esql"]({"query": "FROM range-groundtruth* | LIMIT 1"}), 400)
            show("esql bad syntax", await T["esql"]({"query": "FROM logs-* | WHERE foo = "}), 400)
            txt = show("list_alerts", await T["list_alerts"]({"since": "now-7d", "limit": 3, "min_severity": "medium"}), 2500)
            aid = parse(txt)["alerts"][0]["id"]
            show("list_alerts host", await T["list_alerts"]({"since": "now-7d", "limit": 2, "host": HOST_UP}), 800)
            show("get_alert", await T["get_alert"]({"id": aid}), 6000)
            show(f"running-processes {HOST_UP}", await T["response_action"]({"action": "running-processes", "host": HOST_UP, "process_filter": "svchost"}), 1500)
            show("not range host", await T["response_action"]({"action": "running-processes", "host": ATTACKER}), 400)
        elif mode == "mutate":
            r = parse(show("list_alerts", await T["list_alerts"]({"since": "now-7d", "limit": 1, "status": ["open"]}), 800))
            aid = r["alerts"][0]["id"]
            show("ack+tag", await T["update_alerts"]({"ids": [aid], "status": "acknowledged", "add_tags": ["ai-range:smoke-test"]}))
            a = parse(show("get_alert after", await T["get_alert"]({"id": aid}), 0))
            print("after:", a.get("kibana.alert.workflow_status"), a.get("kibana.alert.workflow_tags"))
            show("revert", await T["update_alerts"]({"ids": [aid], "status": "open", "remove_tags": ["ai-range:smoke-test"]}))
            a = parse(show("get_alert reverted", await T["get_alert"]({"id": aid}), 0))
            print("reverted:", a.get("kibana.alert.workflow_status"), a.get("kibana.alert.workflow_tags"))
            ids = [x["id"] for x in r["alerts"]]
            c = parse(show("create_case", await T["create_case"]({"title": "ai-range smoke test (please ignore)", "description": "Automated test of the create_case tool.", "severity": "low", "tags": ["smoke-test"], "alert_ids": ids + ["does-not-exist"]})))
            case = await es.kibana("GET", f"/api/cases/{c['case_id']}")
            print("case totalAlerts", case.get("totalAlerts"), "comments", case.get("totalComment"))
            # close the case: syncAlerts also closes the attached alerts (may return a version_conflict 500,
            # the case is closed anyway) -> reopen the alert afterwards
            try:
                await es.kibana("PATCH", "/api/cases", json={"cases": [{"id": case["id"], "version": case["version"], "status": "closed"}]})
            except Exception as e:
                print("case close reported:", str(e)[:150])
            print("case status:", (await es.kibana("GET", f"/api/cases/{case['id']}"))["status"])
            await asyncio.sleep(2)
            await T["update_alerts"]({"ids": ids, "status": "open"})
            a = parse(show("alert after case close + reopen", await T["get_alert"]({"id": aid}), 0))
            print("alert status:", a.get("kibana.alert.workflow_status"))
        elif mode == "isolate":
            show(f"isolate {HOST_UP}", await T["response_action"]({"action": "isolate", "host": HOST, "reason": "Smoke test isolate", "wait_seconds": 90}))
            show(f"release {HOST_UP}", await T["response_action"]({"action": "release", "host": HOST, "reason": "Smoke test release", "wait_seconds": 120}))
            # metadata lags behind the action status a bit -> poll for up to 5 min
            for _ in range(15):
                await asyncio.sleep(20)
                ep = await es.kibana("GET", "/api/endpoint/metadata", params={"kuery": f'united.endpoint.host.hostname:"{HOST_UP}"'})
                state = ep["data"][0]["metadata"]["Endpoint"]["state"]
                print(f"{HOST_UP} isolation state:", state)
                if not state["isolation"]:
                    print("RELEASE CONFIRMED")
                    break
            else:
                print(f"ERROR: {HOST_UP} still reports isolation=true!")
        elif mode == "kill-off":
            import airange.config as c
            object.__setattr__(c.settings, "blue_response_mode", "off")
            show("kill off-mode", await T["response_action"]({"action": "kill-process", "host": HOST, "pid": 1, "reason": "test"}))

if __name__ == "__main__":
    asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "read"))
