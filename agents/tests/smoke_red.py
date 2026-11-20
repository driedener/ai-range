"""Live smoke test of the Red tools without an LLM (needs Kali + Elastic). Writes ground truth under
run.id test-red-* and cleans up afterwards. Targets come from your range.yaml.
  docker compose --env-file .env run --rm -T --entrypoint python agents tests/smoke_red.py
"""
import asyncio
from urllib.parse import urlparse

from airange.config import settings
from airange.elastic import Elastic
from airange.tools.red import KaliSession, build_red_tools
from airange.topology import TOPOLOGY
from airange.trace import new_run_id

CONTROLLER = TOPOLOGY.controller_ip
# Some address outside the range: the Proxmox host if known, otherwise TEST-NET-3
OUTSIDE = urlparse(settings.pve_endpoint).hostname if settings.pve_endpoint else "203.0.113.11"
FOREIGN_NET = "198.51.100.0/24"     # TEST-NET-2, never part of the range
DC = TOPOLOGY.dc
DC_FQDN = f"{DC.host}.{TOPOLOGY.domain}"


async def main() -> None:
    run_id = new_run_id("test-red")
    async with Elastic("red") as es, Elastic("orchestrator") as orch:
        kali = KaliSession()
        tools = {t.name: t.handler for t in build_red_tools(es, kali, run_id, "red-smoke")}
        base = dict(technique_id="T1046", technique_name="Network Service Discovery", tactic="Discovery", purpose="smoke")
        cases = [
            ("outside (controller)", dict(base, command=f"nmap -p 9200 {CONTROLLER}", targets=[CONTROLLER])),
            ("IP in command outside", dict(base, command=f"curl http://{OUTSIDE}:8006", targets=[DC.host])),
            ("gateway", dict(base, command=f"nmap {TOPOLOGY.gateway}", targets=[TOPOLOGY.gateway])),
            ("touch firewall", dict(base, command="sudo nft flush ruleset", targets=[DC.host])),
            ("wrong network", dict(base, command=f"nmap -sn {FOREIGN_NET}", targets=[FOREIGN_NET])),
            ("invalid technique", dict(base, technique_id="1046", command="id", targets=[DC.host])),
            (f"ok: port check {DC.name}", dict(base, command=f"nmap -Pn -p 88,389,445 {DC_FQDN} {DC.ip} | tail -8", targets=[DC_FQDN])),
        ]
        for name, args in cases:
            r = await tools["kali_exec"](args)
            txt = r["content"][0]["text"].replace("\n", " | ")[:220]
            print(f"{name:26} is_error={r['is_error']!s:5} {txt}")
        r = await tools["kali_write_file"]({"filename": "users.txt", "content": "a\nb\n"})
        print("write_file", r["content"][0]["text"])
        r = await tools["kali_write_file"]({"filename": "../x", "content": "a"})
        print("write_file ../x", r["is_error"])
        await kali.close()

        await asyncio.sleep(2)  # no _refresh privilege for the orchestrator
        res = await orch.es("POST", "/range-groundtruth/_search", json={"query": {"term": {"run.id": run_id}}})
        for h in res["hits"]["hits"]:
            s = h["_source"]
            print("GT:", s["threat"]["technique"]["id"], s.get("host", {}).get("name"), s["range"].get("target_ips"), s["event"]["outcome"], s["range"].get("exit_code"))
        d = await orch.es("POST", "/range-groundtruth/_delete_by_query", json={"query": {"prefix": {"run.id": "test-red-"}}})
        print("cleaned up:", d.get("deleted"))

asyncio.run(main())
