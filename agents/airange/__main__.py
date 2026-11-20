"""CLI: docker compose --env-file .env run --rm agents <command> …"""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import os
import re
import sys

from .config import settings
from .trace import new_run_id


def _since(value: str) -> str:
    """'-90m', '-2h' or ISO time -> ISO (UTC)."""
    m = re.fullmatch(r"-(\d+)([mh])", value)
    if m:
        delta = dt.timedelta(minutes=int(m.group(1))) if m.group(2) == "m" else dt.timedelta(hours=int(m.group(1)))
        return (dt.datetime.now(dt.timezone.utc) - delta).isoformat(timespec="seconds").replace("+00:00", "Z")
    return value


def _require_llm() -> None:
    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")):
        raise SystemExit("No LLM access: set ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN in docker/.env.")


async def cmd_check(_a) -> None:
    from .elastic import Elastic  # noqa: PLC0415
    from .tools.red import KaliSession  # noqa: PLC0415

    print("LLM access:", "ok" if (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"))
          else "MISSING (ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN)")
    print("Model:", settings.model, "(Blue:", settings.model_for("blue") + ")", "| Budget per run:", settings.max_budget_usd, "USD (Red:", settings.budget_for("red"), ") USD | Blue-Response:",
          settings.blue_response_mode, "| Platform:", settings.edr, "| Exercise mode:", settings.exercise_mode)
    for role in ("red", "blue", "orchestrator"):
        try:
            async with Elastic(role) as es:
                who = await es.es("GET", "/_security/_authenticate")
                print(f"Elastic {role:12} ok ({who['username']}: {', '.join(who['roles'])})")
        except Exception as exc:  # noqa: BLE001
            print(f"Elastic {role:12} ERROR {exc}")
    try:
        async with Elastic("blue") as es:
            await es.es("POST", "/range-groundtruth/_search", json={"size": 0})
            print("Isolation      ERROR: blue-agent can read range-groundtruth!")
    except Exception as exc:  # noqa: BLE001
        print("Isolation      ok (blue-agent cannot read range-groundtruth)" if "403" in str(exc) else f"Isolation ? {exc}")
    if settings.use_s1:
        await _check_s1()
    kali = KaliSession()
    try:
        conn = await kali.conn()
        r = await conn.run("hostname && sudo -n nft list tables", check=False)
        print("Kali           ok", r.stdout.replace("\n", " "))
    except Exception as exc:  # noqa: BLE001
        print("Kali           ERROR", exc)
    finally:
        await kali.close()


async def _check_s1() -> None:
    from .config import RANGE_HOSTS  # noqa: PLC0415
    from .sentinelone import SentinelOne  # noqa: PLC0415

    print("Platform:       SentinelOne", settings.s1_url, "| Site:", settings.s1_site_id or "MISSING (S1_SITE_ID)")
    for role in ("blue", "orchestrator"):
        try:
            async with SentinelOne(role) as s1:
                info = await s1.api("GET", "/system/info")
                exp = (await s1.token_details()).get("expiresAt", "?")
                ver = (info.get("data") or {})
                print(f"S1 {role:12} ok (Console {ver.get('release', '?')} {ver.get('version', '')}, "
                      f"token valid until {exp})")
        except Exception as exc:  # noqa: BLE001
            print(f"S1 {role:12} ERROR {exc}")
    try:
        async with SentinelOne("blue") as s1:
            if s1.site_id:
                sites = await s1.paged("/sites", {"siteIds": [s1.site_id]}, limit=1)
                print("S1 Site        ", f"ok ({sites[0].get('name')}, {sites[0].get('state')})" if sites
                      else "ERROR: site not found / no access")
            agents = await s1.paged("/agents", s1.site_params(), limit=500)
            names = {str(a.get("computerName", "")).split(".")[0].lower(): a for a in agents}
            missing = sorted(set(RANGE_HOSTS.values()) - set(names))
            print(f"S1 Agents       {len(agents)} in the site, active: "
                  f"{sum(1 for a in agents if a.get('isActive'))}; missing: {', '.join(missing) or '-'}")
            from .uam import UAM, f_in  # noqa: PLC0415

            _, total = await UAM(s1).alerts([f_in("status", ["NEW", "IN_PROGRESS"])], limit=1)
            print(f"S1 UAM GraphQL  ok, open alerts in the site: {total}")
            data = await s1.powerquery("event.type = 'Process Creation' | group n = count() by endpoint.name "
                                       "| sort -n | limit 20", "1h")
            print("S1 PowerQuery   ok, process starts in the last hour:",
                  ", ".join(f"{r[0]}={r[1]}" for r in data.get("values") or []) or "none")
    except Exception as exc:  # noqa: BLE001
        print("S1 queries      ERROR", exc)


async def cmd_s1_schema(a) -> None:
    """Fetch the GraphQL schema (Unified Alert Management) via introspection and store it in /app/schema
    (git-ignored, regenerated on demand)."""
    import json  # noqa: PLC0415

    from .sentinelone import INTROSPECTION_QUERY, UAM_GRAPHQL, SentinelOne, schema_to_sdl  # noqa: PLC0415

    async with SentinelOne(a.role) as s1:
        res = await s1.graphql(INTROSPECTION_QUERY, path=a.path or UAM_GRAPHQL)
    schema = (res.get("data") or {}).get("__schema")
    if not schema:
        raise SystemExit(f"No introspection data (possibly disabled): {str(res)[:800]}")
    os.makedirs("/app/schema", exist_ok=True)
    with open("/app/schema/s1_uam_schema.json", "w", encoding="utf-8") as fh:
        json.dump(res, fh, ensure_ascii=False, indent=1)
    sdl = schema_to_sdl(schema)
    with open("/app/schema/s1_uam_schema.graphql", "w", encoding="utf-8") as fh:
        fh.write(sdl)
    roots = {k: (schema.get(k) or {}).get("name") for k in ("queryType", "mutationType")}
    by_name = {t["name"]: t for t in schema["types"]}
    print(f"{len(schema['types'])} types -> agents/schema/s1_uam_schema.{{json,graphql}}")
    for kind, name in roots.items():
        if name:
            fields = [f["name"] for f in by_name[name].get("fields") or []]
            print(f"{kind} {name}: {', '.join(fields)}")
    if res.get("errors"):
        print("Warnings:", str(res["errors"])[:500])


def _load_checked(name: str, ignore_requires: bool) -> dict:
    """Load a scenario and check that the required vuln_* profiles are applied to the range."""
    from .agents import VULN_STATE, applied_profiles, load_scenario, missing_requirements  # noqa: PLC0415

    scenario = load_scenario(name)
    missing = missing_requirements(scenario)
    if missing:
        state = "unknown (no agents/state/vuln_profiles.json)" if applied_profiles() is None else \
            ", ".join(sorted(applied_profiles() or [])) or "none"
        msg = (f"Scenario {name} needs the vulnerability profiles {', '.join(missing)}.\n"
               f"Applied according to {VULN_STATE.name}: {state}.\n"
               "Apply: docker compose --env-file .env run --rm tools sh -c \"cd ansible && ansible-playbook "
               f"playbooks/vulns.yml --tags {','.join(missing)}\"")
        if not ignore_requires:
            raise SystemExit(msg + "\nOr deliberately without them: --ignore-requires")
        print("WARNING: " + msg)
    return scenario


async def cmd_scenarios(_a) -> None:
    from .agents import applied_profiles, list_scenarios  # noqa: PLC0415

    have = applied_profiles()
    print("Applied profiles:", "unknown (agents/state/vuln_profiles.json missing)" if have is None
          else ", ".join(sorted(have)) or "none")
    for s in list_scenarios():
        status = "ready" if not s["missing"] else f"missing: {', '.join(s['missing'])}"
        print(f"\n{s['name']:22} {s['description']}\n{'':22} requires: {', '.join(s['requires']) or '-'} ({status})")


async def cmd_red(a) -> None:
    from .agents import run_red  # noqa: PLC0415

    _require_llm()
    scenario = _load_checked(a.scenario, a.ignore_requires)
    run_id = a.run_id or new_run_id(a.scenario)
    print(f"Run-ID: {run_id}")
    res = await run_red(run_id, scenario, max_budget_usd=a.budget)
    _save_text(run_id, "red", res.final_text)


async def cmd_blue(a) -> None:
    from .agents import run_blue  # noqa: PLC0415

    _require_llm()
    run_id = a.run_id or new_run_id("blue")
    print(f"Run-ID: {run_id}")
    res = await run_blue(run_id, _since(a.since), _since(a.until) if a.until else None, max_budget_usd=a.budget)
    _save_text(run_id, "blue", res.final_text)


async def cmd_score(a) -> None:
    from .scorer import render_markdown, save_report, score_run  # noqa: PLC0415

    report = await score_run(a.run_id, grace_minutes=a.grace)
    await save_report(report)
    print(render_markdown(report))


async def cmd_runs(a) -> None:
    from .scorer import list_runs  # noqa: PLC0415

    for r in await list_runs(a.limit):
        print(r)


async def cmd_engineer(a) -> None:
    from .agents import run_engineer  # noqa: PLC0415
    from .scorer import render_markdown, score_run  # noqa: PLC0415

    _require_llm()
    report = await score_run(a.run_id)
    window = (report["window"]["start"], report["window"]["end"])
    res = await run_engineer(a.run_id, render_markdown(report), window, max_rules=a.max_rules,
                             max_budget_usd=a.budget)
    _save_text(a.run_id, "engineer", res.final_text)


async def cmd_exercise(a) -> None:
    from .agents import run_blue, run_engineer  # noqa: PLC0415
    from .agents import run_red  # noqa: PLC0415
    from .scorer import render_markdown, save_report, score_run  # noqa: PLC0415

    _require_llm()
    mode = (a.mode or settings.exercise_mode).lower()
    if mode not in ("sequential", "parallel"):
        raise SystemExit(f"Exercise mode {mode!r} - allowed: sequential | parallel (AIRANGE_EXERCISE_MODE / --mode)")
    scenario = _load_checked(a.scenario, a.ignore_requires)
    run_id = a.run_id or new_run_id(a.scenario)
    start = dt.datetime.now(dt.timezone.utc)
    since = (start - dt.timedelta(minutes=2)).isoformat(timespec="seconds").replace("+00:00", "Z")

    if mode == "parallel" and not a.no_blue:
        await _parallel(run_id, scenario, since, a)
    else:
        print(f"=== Exercise {run_id} (sequential) - phase 1: Red ===")
        red = await run_red(run_id, scenario, max_budget_usd=a.budget)
        _save_text(run_id, "red", red.final_text)

        if a.wait_min > 0 and not a.no_blue:
            print(f"\n=== Waiting {a.wait_min} min for the detection rules to run ===")
            await asyncio.sleep(a.wait_min * 60)

        if not a.no_blue:
            print("\n=== Phase 2: Blue ===")
            blue = await run_blue(run_id, since, max_budget_usd=a.budget)
            _save_text(run_id, "blue", blue.final_text)

    print("\n=== Phase 3: Scoring ===")
    report = await score_run(run_id)
    await save_report(report)
    md = render_markdown(report)
    print(md)

    if a.engineer:
        print("\n=== Phase 4: Detection Engineering ===")
        window = (report["window"]["start"], report["window"]["end"])
        eng = await run_engineer(run_id, md, window, max_budget_usd=a.budget)
        _save_text(run_id, "engineer", eng.final_text)
    print(f"\nReports: agents/reports/{run_id}.*")


async def _parallel(run_id: str, scenario: dict, since: str, a) -> None:
    """Red and Blue at the same time: Blue monitors live (wait_for_alerts); end of shift (shift_end) = Red done + settle time."""
    from .agents import run_blue, run_red  # noqa: PLC0415
    from .tools.live import LiveShift  # noqa: PLC0415

    shift = LiveShift(settle_s=max(a.wait_min, 0) * 60)
    print(f"=== Exercise {run_id} (parallel) - Red and Blue at the same time; end of shift {a.wait_min} min after Red ===")

    async def red_task():
        try:
            return await run_red(run_id, scenario, max_budget_usd=a.budget)
        finally:
            shift.red_finished()
            print(f"\n=== Red finished - Blue keeps monitoring for {a.wait_min} min ===")

    red, blue = await asyncio.gather(red_task(), run_blue(run_id, since, max_budget_usd=a.budget, live=shift),
                                     return_exceptions=True)
    for role, res in (("red", red), ("blue", blue)):
        if isinstance(res, BaseException):
            print(f"\n[{role}-agent] aborted: {type(res).__name__}: {res}")
        else:
            _save_text(run_id, role, res.final_text)


async def cmd_cleanup(a) -> None:
    """Reset the console state after an exercise (it survives a VM rollback)."""
    if not settings.use_s1:
        raise SystemExit("cleanup is only available for AIRANGE_EDR=sentinelone")
    from .sentinelone import SentinelOne  # noqa: PLC0415
    from .tools.blue_s1_network import cleanup  # noqa: PLC0415

    async with SentinelOne("blue") as s1:
        res = await cleanup(s1, dry_run=a.dry_run)
    print(("Would reset" if a.dry_run else "Reset") + ":")
    for k, v in res.items():
        print(f"  {k:18} {', '.join(map(str, v)) or '-'}")


async def cmd_snapshot(a) -> None:
    from .proxmox import Proxmox  # noqa: PLC0415

    import shutil  # noqa: PLC0415

    from .agents import STATE_DIR, VULN_STATE  # noqa: PLC0415

    # Which vuln_* profiles a snapshot contains is stored next to the state in state/snapshots/<name>.json
    saved = STATE_DIR / "snapshots" / f"{a.name}.json"
    async with Proxmox() as p:
        if a.action == "create":
            await p.snapshot(a.name, "ai-range Baseline")
            if VULN_STATE.exists():
                saved.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(VULN_STATE, saved)
            else:
                saved.unlink(missing_ok=True)
        elif a.action == "rollback":
            await p.rollback(a.name)
            if saved.exists():
                shutil.copyfile(saved, VULN_STATE)
            else:
                VULN_STATE.unlink(missing_ok=True)
            print("Vulnerability profiles now:", (saved.read_text(encoding="utf-8").strip() if saved.exists()
                                                    else "none (snapshot without vuln_* profiles)"))
        elif a.action == "delete":
            await p.delete(a.name)
            saved.unlink(missing_ok=True)
        else:
            await p.list_snapshots()


async def cmd_vms(a) -> None:
    from .proxmox import Proxmox  # noqa: PLC0415

    async with Proxmox() as p:
        if a.action == "start":
            await p.power("start")
        elif a.action == "stop":
            await p.power("shutdown", timeout=a.timeout)
        await p.list_snapshots()


def _save_text(run_id: str, agent: str, text: str) -> None:
    os.makedirs("/app/reports", exist_ok=True)
    path = f"/app/reports/{run_id}.{agent}.md"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text or "")
    print(f"\n[{agent}] Report: agents/reports/{run_id}.{agent}.md")


def main() -> None:
    p = argparse.ArgumentParser(prog="airange", description="ai-range: AI purple-team agents")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("check", help="Check access (LLM, Elastic users, isolation, Kali)")

    sub.add_parser("scenarios", help="List scenarios and their required vulnerability profiles (vuln_*)")

    s = sub.add_parser("red", help="Run the Red agent")
    s.add_argument("--scenario", default="assumed-breach")
    s.add_argument("--run-id")
    s.add_argument("--budget", type=float, help="USD limit for this run")
    s.add_argument("--ignore-requires", action="store_true", help="start even without the scenario's vuln_* profiles")

    s = sub.add_parser("blue", help="Run the Blue agent (SOC triage)")
    s.add_argument("--since", default="-60m", help="ISO time or -90m/-2h")
    s.add_argument("--until")
    s.add_argument("--run-id")
    s.add_argument("--budget", type=float)

    s = sub.add_parser("score", help="Score an exercise (deterministic)")
    s.add_argument("run_id")
    s.add_argument("--grace", type=int, default=30, help="minutes after a step during which an alert counts")

    s = sub.add_parser("runs", help="List previous exercises")
    s.add_argument("--limit", type=int, default=20)

    s = sub.add_parser("engineer", help="Detection engineer for a scored exercise")
    s.add_argument("run_id")
    s.add_argument("--max-rules", type=int, default=8)
    s.add_argument("--budget", type=float)

    s = sub.add_parser("exercise", help="Full exercise: Red + Blue (sequential or parallel) -> scoring [-> engineer]")
    s.add_argument("--scenario", default="assumed-breach")
    s.add_argument("--run-id")
    s.add_argument("--mode", choices=["sequential", "parallel"],
                   help="exercise flow (default: AIRANGE_EXERCISE_MODE, otherwise sequential)")
    s.add_argument("--wait-min", type=int, default=8,
                   help="sequential: wait before Blue; parallel: settle time after Red until the end of shift "
                        "(Elastic rules run every 5 min; with SentinelOne 3 is usually enough)")
    s.add_argument("--no-blue", action="store_true")
    s.add_argument("--engineer", action="store_true")
    s.add_argument("--budget", type=float, help="USD limit per agent run")
    s.add_argument("--ignore-requires", action="store_true", help="start even without the scenario's vuln_* profiles")

    s = sub.add_parser("cleanup", help="Reset the S1 console: agent isolations, Ranger blocks, Blue firewall rules, open alerts/incidents -> RESOLVED")
    s.add_argument("--dry-run", action="store_true", help="show only")

    s = sub.add_parser("snapshot", help="Proxmox snapshots of the range (create/rollback/list)")
    s.add_argument("action", choices=["create", "rollback", "delete", "list"])
    s.add_argument("name", nargs="?", default="baseline")

    s = sub.add_parser("s1-schema", help="Save the SentinelOne GraphQL schema (Unified Alert Management) via introspection to agents/schema/ (git-ignored)")
    s.add_argument("--role", default="blue", choices=["blue", "orchestrator"], help="token role")
    s.add_argument("--path", help="different GraphQL path (default /web/api/v2.1/unifiedalerts/graphql)")

    s = sub.add_parser("vms", help="Start range VMs / shut them down cleanly / status")
    s.add_argument("action", choices=["start", "stop", "status"])
    s.add_argument("--timeout", type=int, default=180, help="stop: seconds until hard power-off")

    from .api_cli import add_parser as add_api_parser, cmd_api  # noqa: PLC0415
    add_api_parser(sub)

    a = p.parse_args()
    handler = {"check": cmd_check, "scenarios": cmd_scenarios, "red": cmd_red, "blue": cmd_blue, "score": cmd_score, "runs": cmd_runs,
               "engineer": cmd_engineer, "exercise": cmd_exercise, "snapshot": cmd_snapshot,
               "s1-schema": cmd_s1_schema, "cleanup": cmd_cleanup, "vms": cmd_vms, "api": cmd_api}[a.cmd]
    try:
        asyncio.run(handler(a))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
