"""Live smoke test of the engineer tools (without an LLM). Creates a test rule and deletes it again.
  docker compose --env-file .env run --rm -T --entrypoint python agents tests/smoke_engineer.py
"""
import asyncio, sys
from airange.elastic import Elastic
from airange.tools.engineer import build_engineer_tools
sys.path.insert(0, "/app/tests")
from smoke_blue import parse, show  # noqa: E402

async def main():
    async with Elastic("engineer") as es:
        T = {t.name: t.handler for t in build_engineer_tools(es)}
        print("TOOLS", list(T))
        show("esql", await T["esql"]({"query": "FROM logs-windows.sysmon_operational-* | STATS c=COUNT(*) BY event.code | SORT c DESC", "max_rows": 5}))
        show("list_rules search", await T["list_rules"]({"search": "LSASS", "limit": 3}))
        r = parse(show("list_rules enabled", await T["list_rules"]({"search": "powershell", "enabled": True, "limit": 2})))
        prebuilt = r["rules"][0]
        show("list_rules only_custom", await T["list_rules"]({"only_custom": True}))
        show("get_rule", await T["get_rule"]({"rule_id": prebuilt["rule_id"]}), 2500)
        show("bad mitre", await T["preview_rule"]({"name": "x", "description": "x", "type": "eql", "query": "process where true", "mitre": ["T12"]}))
        show("unknown tactic", await T["preview_rule"]({"name": "x", "description": "x", "type": "eql", "query": "process where true", "mitre": ["T9999"]}))
        draft = {"name": "AI Smoke - PowerShell Execution", "description": "Smoke test: PowerShell process start",
                 "type": "eql", "query": 'process where event.type == "start" and process.name : ("powershell.exe", "pwsh.exe")',
                 "severity": "low", "mitre": ["T1059.001", "TA0005:T1562.001"]}
        show("preview eql 24h", await T["preview_rule"]({**draft, "lookback_hours": 24, "samples": 2}), 2500)
        show("preview esql", await T["preview_rule"]({"name": "AI Smoke ESQL", "description": "x", "type": "esql", "lookback_hours": 6,
             "query": 'FROM logs-system.security-* | WHERE event.code == "4625" | STATS fails = COUNT(*) BY host.name, source.ip | WHERE fails > 3'}), 1500)
        show("preview esql agg", await T["preview_rule"]({"name": "AI Smoke ESQL agg", "description": "x", "type": "esql", "lookback_hours": 2,
             "query": 'FROM logs-system.security-* | WHERE event.code == "4624" | STATS logons = COUNT(*) BY host.name | WHERE logons > 10'}), 1200)
        show("preview kql", await T["preview_rule"]({"name": "AI Smoke KQL", "description": "x", "type": "query", "lookback_hours": 2,
             "query": 'event.code: "4104" and powershell.file.script_block_text: *Invoke*'}), 1200)
        show("preview threshold", await T["preview_rule"]({"name": "AI Smoke threshold", "description": "x", "type": "threshold", "lookback_hours": 24,
             "query": 'event.code: "4625"', "threshold": {"field": ["source.ip"], "value": 5}}), 1200)
        show("preview broken", await T["preview_rule"]({"name": "x", "description": "x", "type": "eql", "query": "process where foo ==", "lookback_hours": 1}), 800)
        c = parse(show("create_rule", await T["create_rule"]({**draft, "tags": ["smoke-test"]})))
        try:
            show("get own rule", await T["get_rule"]({"id": c["id"]}), 2500)
            show("update own", await T["update_rule"]({"id": c["id"], "severity": "medium", "tags": ["smoke-test", "v2"], "description": "Smoke test v2"}))
            show("update prebuilt (must refuse)", await T["update_rule"]({"rule_id": prebuilt["rule_id"], "severity": "low"}))
            show("disable prebuilt (must refuse)", await T["disable_rule"]({"rule_id": prebuilt["rule_id"]}))
            show("disable own", await T["disable_rule"]({"rule_id": c["rule_id"]}))
            show("list ai-range", await T["list_rules"]({"only_ai_range": True}))
        finally:
            await es.kibana("DELETE", "/api/detection_engine/rules", params={"id": c["id"]})
            print("Test rule deleted:", c["rule_id"])

asyncio.run(main())
