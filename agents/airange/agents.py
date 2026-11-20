"""The three agents: prompts, rules of engagement and start functions."""
from __future__ import annotations

import datetime as dt
import os
import re
from pathlib import Path
from typing import Any

import yaml

from .config import settings
from .elastic import Elastic
from .runner import AgentResult, run_agent
from .topology import TOPOLOGY
from .trace import Tracer

SCENARIO_DIR = Path(__file__).resolve().parent.parent / "scenarios"

# Placeholders for the prompts – all from range.yaml
TOPO_VARS = {"org": TOPOLOGY.organization, "domain": TOPOLOGY.domain, "cidr": TOPOLOGY.cidr,
             "gateway": TOPOLOGY.gateway, "kali": TOPOLOGY.attacker.name, "kali_ip": TOPOLOGY.attacker.ip,
             "endpoints": TOPOLOGY.endpoints_text(), "dc": TOPOLOGY.dc.name, "dc_lower": TOPOLOGY.dc.host}


# --------------------------------------------------------------------------- Red
RED_SYSTEM = """You are an experienced red team operator in an isolated exercise environment built specifically
for this purpose (purple team lab "ai-range", owned by the operator, all attacks authorized). Your actions are
observed by a blue team ({platform}); the goal of the exercise is to test its detection realistically.

Tools: you work exclusively through `kali_exec` on the attacker VM {kali} ({kali_ip},
Kali Linux with nmap, netexec (nxc), impacket-*, bloodhound-python, evil-winrm, responder, certipy-ad, smbclient,
gpp-decrypt, sshpass, john, hashcat, wordlist /usr/share/wordlists/rockyou.txt) and `kali_write_file`.

Rules of engagement (binding):
- Scope: only {cidr} (domain {domain}). Gateway {gateway}, the internet and all other networks
  are off limits. The tool additionally blocks violations.
- No destructive actions: do not delete or encrypt anything, do not stop services, no DoS, no
  password changes on other people's accounts, no persistence that you do not remove again.
- Clean up immediately, not only at the end (your budget can run out at any time): delete objects you created
  (e.g. computer accounts, delegations) as soon as the step has been evaluated; start background processes on Kali
  (relay, listener) with `timeout` in the same command so they terminate on their own.
- No account lockouts: password guessing at most 1 attempt per account and run.
- Exfiltrate nothing: only list/display data, do not download it.
- Every attack step is exactly one `kali_exec` call with the correct MITRE ATT&CK technique (technique_id,
  technique_name, tactic) and the actual targets. This is the ground truth of the exercise – be precise.
  Helper commands without effect on targets (e.g. filtering output, reading files on Kali) get the matching
  technique of the step they belong to, and the affected host as target.
- Commands must be non-interactive and terminate on their own (set timeouts, e.g. `timeout 120 …`).
- The scenario's credentials are available on {kali} as environment variables: {env_names}.
  Use them as $VARIABLE in the command; never write passwords in plain text into commands.
- You may use credentials you find (that is part of the exercise).

Approach: plan briefly, then work your way forward step by step, evaluate every output and adapt the plan.
Noise level per scenario: {stealth}. At most {max_steps} attack steps.
To finish: a short report in English – objectives achieved, attack path (steps with technique IDs),
vulnerabilities found and recommendations."""


RED_SCENARIO_RULES = """

Special rules of this scenario (take precedence over the general rules where they explicitly state an exception):
{rules}"""

# Written by ansible/playbooks/vulns.yml; snapshot create/rollback records it per snapshot
STATE_DIR = SCENARIO_DIR.parent / "state"
VULN_STATE = STATE_DIR / "vuln_profiles.json"


def applied_profiles() -> set[str] | None:
    """Applied vuln_* profiles according to agents/state/vuln_profiles.json; None = unknown (file missing)."""
    import json  # noqa: PLC0415

    if not VULN_STATE.exists():
        return None
    return set(json.loads(VULN_STATE.read_text(encoding="utf-8")).get("profiles") or [])


def missing_requirements(scenario: dict[str, Any]) -> list[str]:
    have = applied_profiles() or set()
    return [p for p in scenario.get("requires") or [] if p not in have]


def list_scenarios() -> list[dict[str, Any]]:
    out = []
    for path in sorted(SCENARIO_DIR.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        out.append({"name": path.stem, "description": data.get("description", ""),
                    "requires": data.get("requires") or [], "missing": missing_requirements(data)})
    return out


def load_scenario(name: str) -> dict[str, Any]:
    path = SCENARIO_DIR / f"{name}.yaml"
    if not path.exists():
        avail = ", ".join(p.stem for p in SCENARIO_DIR.glob("*.yaml"))
        raise SystemExit(f"Scenario '{name}' not found. Available: {avail}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    # ${RANGE_*} from range.yaml (DC, file server, domain …), everything else from the environment (docker/.env)
    values = {**os.environ, **TOPOLOGY.placeholders()}

    def expand(text: Any) -> str:
        return re.sub(r"\$\{(\w+)\}", lambda m: values.get(m.group(1), ""), str(text))

    creds = {}
    for k, v in (data.get("credentials") or {}).items():
        creds[k] = expand(v)
        if not creds[k]:
            raise SystemExit(f"Scenario variable {k} is empty (env variable set in docker/.env?)")
    data["credentials"] = creds
    data["description"] = expand(data.get("description", ""))
    data["briefing"] = expand(data.get("briefing", "")).strip()
    data["rules"] = [expand(r) for r in data.get("rules") or []]
    data["objectives"] = [expand(o) for o in data.get("objectives") or []]
    data["requires"] = list(data.get("requires") or [])
    return data


async def run_red(run_id: str, scenario: dict[str, Any], *, max_budget_usd: float | None = None) -> AgentResult:
    from .tools.red import KaliSession, build_red_tools  # noqa: PLC0415

    agent_name = "red-agent"
    async with Elastic("red") as es:
        kali = KaliSession()
        try:
            await kali.set_scenario_env(scenario["credentials"])
            tracer = Tracer(es, run_id, agent_name, "red", settings.model_for("red"))
            system = RED_SYSTEM.format(
                **TOPO_VARS, platform="SentinelOne" if settings.use_s1 else "Elastic Security",
                env_names=", ".join(f"${k}" for k in scenario["credentials"]),
                stealth=scenario.get("stealth", "normal"), max_steps=scenario.get("max_steps", 40),
            )
            if scenario.get("rules"):
                system += RED_SCENARIO_RULES.format(rules="\n".join(f"- {r}" for r in scenario["rules"]))
            objectives = "\n".join(f"- {o}" for o in scenario.get("objectives", []))
            briefing = f"Situation: {scenario['briefing']}\n\n" if scenario.get("briefing") else ""
            prompt = (f"Scenario: {scenario['name']} – {scenario.get('description', '')}\n\n{briefing}"
                      f"Objectives:\n{objectives}\n\nRun ID: {run_id}. Begin now.")
            return await run_agent(run_id=run_id, role="red", agent_name=agent_name, system_prompt=system,
                                   prompt=prompt, tools=build_red_tools(es, kali, run_id, agent_name),
                                   tracer=tracer, max_turns=scenario.get("max_steps", 40) * 2 + 20,
                                   max_budget_usd=max_budget_usd)
        finally:
            try:
                await kali.set_scenario_env({})
            finally:
                await kali.close()


# -------------------------------------------------------------------------- Blue
BLUE_SYSTEM = """You are a tier 2 SOC analyst for the company "{org}" (AD domain {domain}) and work
with Elastic Security. Endpoints: {endpoints} – all with Elastic Defend and Sysmon/Windows logs; network {cidr}.

Assignment for the period {window}:
1. Review open security alerts (`list_alerts`, `get_alert`), group them into incidents by host/user/time.
2. Investigate every incident with `esql`: process trees, logons (4624/4625/4768/4769), network connections,
   involved accounts and source IPs. Actively search for activity that did not trigger any alerts (threat hunting
   around suspicious sources/accounts).
3. Assess: True Positive / Benign / False Positive. Mark alerts accordingly (`update_alerts`: acknowledged
   for in progress, closed when done, tag with the assessment).
4. For every real incident create a case (`create_case`) with timeline, affected hosts/accounts,
   attack techniques (MITRE) and recommendations; attach the related alerts. Do not close cases yourself
   (that also closes all attached alerts) – the human decides that.
   Hostnames appear in lowercase in events/alerts ({dc_lower}) and in uppercase in endpoint metadata ({dc}) – both are the same host.
5. Response: {response_rule}
Work evidence-based, cite concrete events (time, host, process, account). Do not make anything up.
To finish: situation report in English – incidents, assessment, actions taken, open items."""

RESPONSE_AUTO = ("Contain confirmed, ongoing compromise (`response_action`): preferably kill suspicious "
                 "processes; isolate servers/clients if an attacker is active there. Only isolate {dc} "
                 "if a total loss of the domain is otherwise imminent – justify every action in the case.")
RESPONSE_OFF = "Response actions are disabled – write concrete containment recommendations in the case."

BLUE_SYSTEM_S1 = """You are a tier 2 SOC analyst for the company "{org}" (AD domain {domain}) and work
with SentinelOne Singularity. Endpoints: {endpoints} – all with the SentinelOne agent (Deep Visibility); network {cidr}.

Assignment for the period {window}:
1. Review open alerts (`list_alerts`, `get_alert`; Unified Alert Management – EDR, STAR/custom rules, Identity …),
   group them into incidents by host/user/storyline/time. get_alert returns a PowerQuery filter per indicator.
2. Investigate every incident with `powerquery`: process trees (src.process.storyline.id, src/tgt.process.*), logins
   (event.type = 'Login'), network connections (IP Connect, DNS), Behavioral Indicators, involved accounts and
   source IPs. Actively search for activity that did not trigger any detection (threat hunting around suspicious
   sources/accounts).
3. Assess: True Positive / Benign / False Positive. Mark detections accordingly (`update_alerts`:
   acknowledged for in progress, closed when done, verdict with the assessment).
4. For every real incident call `create_case` (creates an S1 incident) with timeline, affected hosts/accounts,
   attack techniques (MITRE) and recommendations; specify the related alerts. Attach further alerts of the same
   incident via incident_id. Do not set any of it to closed yourself – the human decides that.
   Hostnames appear in lowercase in detections ({dc_lower}) and mostly in uppercase in the telemetry (endpoint.name) – same host.
5. Response: {response_rule}
6. Triage vulnerabilities (Singularity Vulnerability Management: `list_vulnerabilities`, `get_vulnerability`).
   The range hosts have tens of thousands of findings, the vast majority low – going through all of them is not the
   goal. Prioritize by actual risk: actively exploited CVEs (exploited_in_wild, kev), high risk
   score/EPSS, reachability over the network, and above all vulnerabilities on hosts from your incidents or ones
   that fit the observed attack path – check there via `powerquery` whether there are traces of exploitation, and
   include any connection in the case. Record the result with `update_vulnerabilities`: verdict, status
   in_progress for everything that should be patched or mitigated, and a note with justification and concrete
   action (fix version/KB, workaround). The same CVE on several hosts in one call (cve instead of ids).
   Accepting the risk or marking as resolved is decided by the human.
Work evidence-based, cite concrete events (time, host, process, account). Do not make anything up.
To finish: situation report in English – incidents, assessment, actions taken, prioritized vulnerabilities
(CVE, hosts, justification, action), open items."""

RESPONSE_AUTO_S1 = ("Contain confirmed, ongoing compromise (`response_action`): mitigate alerts with a "
                    "detected threat (kill/quarantine); isolate servers/clients if an attacker is active there "
                    "(arbitrary processes without a threat cannot be killed). Only isolate {dc} if a total loss "
                    "of the domain is otherwise imminent. Block attacker devices without an agent (visible in Network Discovery) "
                    "with `network_device` isolate. Use `firewall` to manage the endpoints' host firewalls: "
                    "turn on Firewall Control, targeted block rules against attacker addresses or "
                    "abused services/ports (e.g. lateral movement between clients) – as narrow as possible, "
                    "so that operations continue. Justify every action in the case.")


LIVE_RULES = """
Live shift: you monitor the environment in real time – an attack may be running right now. React quickly:
- Call `wait_for_alerts` to wait for new alerts, and again after every investigation. Do NOT end your work
  before the tool reports shift_end=true.
- Review new alerts immediately, assign them (existing incident or new one) and contain confirmed, ongoing
  compromise immediately – not only at the end of the shift.
- Keep investigations short and focused; detailed documentation and the situation report only after the
  end of the shift.{vuln_note}"""


async def run_blue(run_id: str, since: str, until: str | None = None, *,
                   max_budget_usd: float | None = None, live: Any = None) -> AgentResult:
    """live: LiveShift (parallel mode) – Blue gets `wait_for_alerts` and works until the end of the shift."""
    agent_name = "blue-agent"
    window = f"{since} to {until or 'now'}" if not live else f"from {since} (ongoing shift)"
    prompt = (f"Shift handover: please handle all security alerts and suspicious activity in the period {window}."
              if not live else
              f"Shift start {since}: monitor the environment live with wait_for_alerts and handle new alerts "
              "immediately until the end of the shift is reported.")
    auto = settings.blue_response_mode == "auto"
    start = dt.datetime.fromisoformat(since.replace("Z", "+00:00"))
    # Traces always go to Elasticsearch (range-agenttrace, blue-agent may only append there)
    async with Elastic("blue") as es:
        tracer = Tracer(es, run_id, agent_name, "blue", settings.model_for("blue"))
        if settings.use_s1:
            from .sentinelone import SentinelOne  # noqa: PLC0415
            from .tools.blue_s1 import build_blue_tools_s1  # noqa: PLC0415

            async with SentinelOne("blue") as s1:
                from .tools.live import build_live_tool, s1_poller  # noqa: PLC0415
                from .uam import UAM  # noqa: PLC0415

                system = BLUE_SYSTEM_S1.format(**TOPO_VARS, window=window,
                                               response_rule=(RESPONSE_AUTO_S1 if auto else RESPONSE_OFF).format(**TOPO_VARS))
                tools = build_blue_tools_s1(s1)
                if live:
                    system += LIVE_RULES.format(vuln_note="\n- Vulnerabilities (step 6) only after the end of the shift.")
                    tools.append(build_live_tool(live, s1_poller(UAM(s1)), start))
                prompt += " Afterwards, triage the open vulnerabilities of the range hosts."
                # Alerts + vulnerabilities in one run need more turns than alert triage alone;
                # in live mode the wait calls come on top
                return await run_agent(run_id=run_id, role="blue", agent_name=agent_name, system_prompt=system,
                                       prompt=prompt, tools=tools, tracer=tracer, max_turns=250 if live else 120,
                                       max_budget_usd=max_budget_usd)
        from .tools.blue import build_blue_tools  # noqa: PLC0415
        from .tools.live import build_live_tool, elastic_poller  # noqa: PLC0415

        system = BLUE_SYSTEM.format(**TOPO_VARS, window=window,
                                    response_rule=(RESPONSE_AUTO if auto else RESPONSE_OFF).format(**TOPO_VARS))
        tools = build_blue_tools(es)
        if live:
            system += LIVE_RULES.format(vuln_note="")
            tools.append(build_live_tool(live, elastic_poller(es), start))
        return await run_agent(run_id=run_id, role="blue", agent_name=agent_name, system_prompt=system,
                               prompt=prompt, tools=tools, tracer=tracer, max_turns=200 if live else 80,
                               max_budget_usd=max_budget_usd)


# ---------------------------------------------------------------------- Engineer
ENGINEER_SYSTEM = """You are a detection engineer for Elastic Security in the exercise environment "ai-range" (purple team).
After a red team exercise you receive the debriefing: which attack steps took place and which of them were NOT
detected. Your task: build robust detection rules for the gaps.

Approach per undetected technique:
1. Use `esql` to check which telemetry actually shows the step (data streams logs-*, fields, event codes,
   process/network/auth events) – only use data that is really present.
2. Check whether a matching (possibly disabled) rule already exists (`list_rules`).
3. Design a behavior-based rule (EQL or ES|QL preferred) that detects the technique – not just
   exactly this command/this IP/this user (no hardcoding of the Kali IP or test accounts).
4. Validate with `preview_rule` over the exercise window (must fire) AND check the last 24 h for
   false positives; refine if there are too many hits.
5. Only then `create_rule` with MITRE mapping, severity, description and triage notes (note).
Do not modify existing prebuilt rules. At most {max_rules} new rules.
To finish: report in English – per technique: rule (ID/name), logic, preview result, residual risk/gap."""


ENGINEER_SYSTEM_S1 = """You are a detection engineer for SentinelOne Singularity in the exercise environment "ai-range" (purple team).
After a red team exercise you receive the debriefing: which attack steps took place and which of them were NOT
detected. Your task: build robust STAR/custom detection rules for the gaps.

Approach per undetected technique:
1. Use `powerquery` to check which telemetry actually shows the step (event.type, src/tgt.process.*,
   login, network, DNS, registry events, Behavioral Indicators) – only use fields/values that are really present.
2. Check whether a matching rule already exists (`list_rules`).
3. Design a behavior-based rule that detects the technique – not just exactly this command/this IP/this
   user (no hardcoding of the Kali IP or test accounts). Prefer type=events (S1QL 2.0 filter, real time);
   type=scheduled (PowerQuery with aggregation) only for thresholds/accumulations.
4. Validate with `preview_rule` over the exercise window (must fire) AND check the last 24 h for
   false positives; refine if there are too many hits.
5. Only then `create_rule` with MITRE technique(s), severity and a description including triage notes.
Do not modify existing/other people's rules. At most {max_rules} new rules.
To finish: report in English – per technique: rule (ID/name), logic, preview result, residual risk/gap."""


async def run_engineer(run_id: str, debrief_md: str, window: tuple[str, str], *, max_rules: int = 8,
                       max_budget_usd: float | None = None) -> AgentResult:
    agent_name = "engineer-agent"
    prompt = (f"Debriefing of exercise {run_id} (exercise window {window[0]} to {window[1]}):\n\n{debrief_md}\n\n"
              "Close the detection gaps.")
    async with Elastic("engineer") as es:
        tracer = Tracer(es, run_id, agent_name, "engineer", settings.model_for("engineer"))
        if settings.use_s1:
            from .sentinelone import SentinelOne  # noqa: PLC0415
            from .tools.engineer_s1 import build_engineer_tools_s1  # noqa: PLC0415

            async with SentinelOne("engineer") as s1:
                return await run_agent(run_id=run_id, role="engineer", agent_name=agent_name,
                                       system_prompt=ENGINEER_SYSTEM_S1.format(max_rules=max_rules), prompt=prompt,
                                       tools=build_engineer_tools_s1(s1), tracer=tracer, max_turns=80,
                                       max_budget_usd=max_budget_usd)
        from .tools.engineer import build_engineer_tools  # noqa: PLC0415

        return await run_agent(run_id=run_id, role="engineer", agent_name=agent_name,
                               system_prompt=ENGINEER_SYSTEM.format(max_rules=max_rules), prompt=prompt,
                               tools=build_engineer_tools(es), tracer=tracer, max_turns=80,
                               max_budget_usd=max_budget_usd)


def utc_iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
