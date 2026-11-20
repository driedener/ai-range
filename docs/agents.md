# Agents & scoring

Code: `agents/` (Python, Claude Agent SDK). Runs as the Compose service `agents` on the controller. Hosts,
network, DC, attacker VM and controller come from `range.yaml` (`agents/airange/topology.py`, see
[Configuration](configuration.md)); prompts, scope guard and tool descriptions adapt to it.

```sh
cd docker
docker compose --env-file .env --profile agents build agents     # once / after requirements change
docker compose --env-file .env run --rm agents check             # check access
docker compose --env-file .env run --rm agents exercise --scenario assumed-breach [--engineer]
```

**LLM access:** `ANTHROPIC_API_KEY` **or** `CLAUDE_CODE_OAUTH_TOKEN` (`claude setup-token`, subscription) in
`docker/.env`.

**Models:** all roles use `AIRANGE_MODEL` (default `claude-opus-5-5`). Set `AIRANGE_RED_MODEL`,
`AIRANGE_BLUE_MODEL` or `AIRANGE_ENGINEER_MODEL` to use a different model for one role.

**Security platform:** `AIRANGE_EDR=elastic` (default) or `sentinelone`. With `sentinelone`, Blue, Engineer
and scorer work against the SentinelOne console instead of Elastic Security ([SentinelOne](sentinelone.md)), and
Blue also triages the vulnerabilities of the range hosts (Singularity Vulnerability Management). Elastic has no
vulnerability source.

## Commands

| Command | Purpose |
|---|---|
| `check` | LLM access, Elastic users, ground-truth isolation, Kali SSH and egress guard (with SentinelOne also the console) |
| `scenarios` | Scenarios, the vulnerability profiles they need and whether these are applied on the range |
| `exercise --scenario X [--mode sequential\|parallel] [--engineer] [--wait-min 8] [--no-blue] [--budget 5] [--ignore-requires]` | Red + Blue (see mode below) -> scoring [-> Engineer] |
| `red --scenario X [--budget N] [--ignore-requires]` | Attack only |
| `blue --since -90m [--until ...]` | SOC triage of a time window only |
| `score <run-id> [--grace 30]` | Deterministic scoring (no LLM) |
| `engineer <run-id> [--max-rules 8]` | Detection Engineer closes the gaps of a scored exercise |
| `runs [--limit 20]` | Past exercises |
| `s1-schema [--path ...]` | SentinelOne GraphQL schema by introspection into `agents/schema/` |
| `snapshot create\|rollback\|delete\|list [name]` | Proxmox snapshots of all VMs in `range.yaml` (by VMID), default name `baseline`. Records the applied `vuln_*` profiles per snapshot and restores them on rollback. |
| `cleanup [--dry-run]` | Reset the S1 console: lift agent isolations, release Ranger blocks ("Isolated"), delete Blue's firewall rules, set all open alerts and incidents of the range site to *Resolved*. Belongs to every rollback, because the console state survives it. |
| `vms start\|stop\|status [--timeout 180]` | Start the range VMs or shut them down cleanly (hard stop after `--timeout` seconds), then show status |
| `api s1\|gql\|pq\|es\|kb\|esql ...` | Direct API access for the operator (not for the agents): S1 REST, UAM/UIM/xSPM GraphQL, PowerQuery, Elasticsearch, Kibana, ES\|QL. `{SITE}` = `S1_SITE_ID`. Examples: `.claude/skills/range-api/SKILL.md` |

### Exercise mode

`AIRANGE_EXERCISE_MODE` (default `sequential`) sets the flow; `exercise --mode` overrides it per call.

- **sequential:** Red attacks -> wait `--wait-min` minutes (rules run) -> Blue triages the exercise window
  afterwards. Measures detection, not response time.
- **parallel:** Red and Blue start at the same time. Blue additionally gets `wait_for_alerts`: the tool waits
  (at most 5 minutes per call, polling every 20 s) for alerts since the last call. Blue investigates and contains
  live while the exercise runs. After Red finishes, the shift continues for `--wait-min` minutes, then the tool
  reports `shift_end=true` and Blue writes its situation report (with SentinelOne after the
  vulnerability triage). Blue learns nothing about Red except the end of shift. An isolation by Blue immediately
  affects Red's next steps; with SentinelOne Blue can also block the attacker device via Ranger and set firewall
  rules. Blue's turn limit: 250 (S1) or 200 (Elastic). The budget is not always enough for long attacks, so raise
  `--budget`.

Reports (in English): `agents/reports/<run-id>.{red,blue,engineer}.md`, scoring `<run-id>.md/.json` (sections
such as *Steps*, *Cost*, *Unmatched alerts (noise)*) and the index
`range-scores`. All tool calls and costs: data stream `range-agenttrace`. Ground truth: `range-groundtruth`.

## Security model

- **No built-in tools.** The agents have no Bash, file system or web access (`tools=[]`,
  `permission_mode=dontAsk`, no settings/CLAUDE.md). They can only call the MCP tools in `agents/airange/tools/`.
- **Permissions through Elastic roles, not prompts.** Blue/Engineer use `blue-agent` (no read access to
  `range-groundtruth`), Red uses `red-agent` (may only append ground truth/traces), the scorer `orchestrator`.
- **Red scope, enforced twice:** `kali_exec` rejects targets/IPs outside the range network (`network.cidr`,
  excluding the gateway and Kali itself) as well as firewall/routing commands. In addition, nftables on the Kali VM
  (Ansible role `kali`, table `airange_guard`) blocks all private networks except the range network, so the
  controller and Proxmox are unreachable from Kali.
- **Ground truth from the tool:** every `kali_exec` call records technique, targets, command and exit code, not
  the model's own account. Scenario credentials are stored as an env file (0600) on Kali, not in the prompt.
- **Cost:** `AIRANGE_MAX_BUDGET_USD` (default 5) per agent run, Red `AIRANGE_RED_MAX_BUDGET_USD` (default 10),
  `--budget` per call (then applies to all roles). Hitting the budget or turn limit ends a run normally; the
  exercise continues.
- **Response:** `AIRANGE_BLUE_RESPONSE=auto` lets Blue isolate hosts and kill processes (range endpoints only,
  with justification); `off` = recommendations only.
- **Network response (S1):** `network_device` and `firewall` are limited to the range site and addresses in the
  range network. The gateway, the DC and management IPs (`AIRANGE_MGMT_IPS`, default the controller) can never be
  blocked, not even through a CIDR that contains them. Block rules need concrete addresses (no `any`). Blue may
  only change its own rules with the prefix `ai-range blue:`. Managed range hosts are isolated only through
  `response_action`.
- **SentinelOne:** permissions through the site scope of the service user token; in addition the code filters
  every query and action by `S1_SITE_ID` and the range host names. Blue has no Elastic read access there but still
  writes traces (`create_doc`).

## Tools

| Agent | Tools |
|---|---|
| Red | `kali_exec`, `kali_write_file` |
| Blue | `esql`, `list_alerts`, `get_alert`, `update_alerts`, `create_case`, `response_action` |
| Engineer | `esql`, `list_rules`, `get_rule`, `create_rule`, `update_rule`, `preview_rule`, `disable_rule` (only rules tagged `ai-range`) |
| Blue (S1) | `powerquery`, `list_alerts`, `get_alert`, `update_alerts` (UAM GraphQL), `create_case` (UAM incident), `response_action` (isolate/release/mitigate/status), `list_vulnerabilities`, `get_vulnerability`, `update_vulnerabilities` (xSPM GraphQL) |
| Blue (S1, network) | `network_device` (Ranger: list devices without an agent, block/release via device review "Isolated"), `firewall` (Firewall Control: status, enable, create/enable/delete own rules) |
| Blue (parallel) | additionally `wait_for_alerts` (live monitoring until end of shift) |
| Engineer (S1) | `powerquery`, `list_rules`, `get_rule`, `create_rule`, `update_rule`, `preview_rule`, `disable_rule` (only STAR rules with prefix `ai-range:`) |

## Scoring (`scorer.py`)

Each alert is assigned to **exactly one** ground-truth step (scorer v2):

- Candidates: target host/IP or Kali IP matches, alert within [start - 1 min, end + grace].
- The time of the triggering event (`kibana.alert.original_time`) decides: if it falls inside a step (± 10 s),
  the step with the same MITRE base technique wins. Otherwise (or without event time, e.g. ES|QL aggregations)
  the previous step within 10 minutes, preferring a technique match. Everything else is noise.
- *Detected* = the step has at least one alert; *technique match* = one of them has the same technique;
  TTD (time to detect) = creation of the first alert - start of the step.
- For comparison the report also shows the old, generous count (every alert counts for every step in its window).

Alerts whose source is the management host (the controller, `controller.ip` from `range.yaml`) never count as
detections. The report also contains noise (unmatched alerts per rule), triage (workflow status, cases, Blue's
response actions) and cost per role. `score` replaces the run's document in `range-scores` (doc ID = run ID).

## Scenarios

`agents/scenarios/*.yaml`, fields:

| Field | Meaning |
|---|---|
| `name`, `description` | Name and short description |
| `requires` | Required vulnerability profiles (`vuln_*`); if missing, `exercise`/`red` abort |
| `briefing` | Starting situation for Red (part of the prompt) |
| `rules` | Special rules that extend or explicitly relax the general rules of engagement (e.g. exfiltration into the Kali working directory) |
| `credentials` | Environment variables on Kali (not in the prompt); `${ENV}` from `docker/.env` |
| `objectives`, `stealth`, `max_steps` | Objectives, noise level (noisy/normal/stealthy), maximum attack steps |

All text fields can use `${RANGE_*}` placeholders from `range.yaml`: `RANGE_DOMAIN`, `RANGE_NETBIOS`,
`RANGE_CIDR`, `RANGE_ORGANIZATION`, `RANGE_DC`, `RANGE_ATTACKER`, `RANGE_FILESERVER`, `RANGE_CA`, `RANGE_WEB`,
`RANGE_SQL`, `RANGE_CLIENT` (first client), `RANGE_LINUX_WEB`, `RANGE_LINUX_DB`, each host placeholder also with
`_IP`.

| Scenario | Starting point | Mainly tests | Requires |
|---|---|---|---|
| `assumed-breach` | Standard user (helpdesk) | Broad detection | - (richer with profiles) |
| `external-no-creds` | Network access only | Network/identity layer: spraying, LLMNR, Ranger | `vuln_weak_passwords`, `vuln_llmnr`, `vuln_smb` |
| `workstation-beachhead` | Local admin on the first client | Endpoint EDR (LSASS, LSA secrets), isolation by Blue | `vuln_local_admin` |
| `web-compromise` | Network access only, target intranet app | Server detection (w3wp -> cmd), pivot | `vuln_webapp`, `vuln_delegation` |
| `insider-exfil` | Own account (finance), quiet | Data exfiltration without exploits | `vuln_data` |
| `pre-ransomware` | Domain Admin | Response time (parallel mode); only renames dummy files | `vuln_data` |
| `identity-attack` | Standard user | S1 Identity: Kerberos, ACL, AD CS, DCSync | `vuln_kerberoast`, `vuln_asrep`, `vuln_acl`, `vuln_dcsync`, `vuln_adcs` |
| `linux-path` | SSH account on the Linux web server | Linux agents, path back into AD | `vuln_linux` |
| `atomic-sweep` | Standard user | Coverage per technique (fixed list, one step per technique) | - |

Vulnerability profiles: [Vulnerability profiles](vulnerability-profiles.md). The base range stays clean; you get
back to it only by snapshot rollback.

## Tests

Smoke tests live in `agents/tests/` and run in the `agents` container (from `docker/`):

```sh
docker compose --env-file .env run --rm -T --entrypoint python agents tests/smoke_scorer.py --offline
docker compose --env-file .env run --rm -T --entrypoint python agents tests/smoke_s1.py
```

These two run offline against the fixture topology `agents/tests/range.test.yaml`, not your `range.yaml`.
`smoke_scorer.py` without `--offline`, `smoke_s1.py read` and the other smoke tests (`smoke_red.py`,
`smoke_blue.py`, `smoke_engineer.py`) run against the live lab.

## Known quirks (Kibana 9.2)

- Rule preview runs synchronously; results go to `.preview.alerts-security*` (role `range_blue` has access).
- Response actions need the Defend sub-features (`host_isolation_all`, `process_operations_all`, ...);
  `siemV4: all` does not include them (`range_blue_siem_subfeatures`).
- If a host is missing from the endpoint list (the transform missed the metadata document):
  `POST _transform/endpoint.metadata_current-default-<ver>/_stop` -> `_reset` -> `_start` (as `elastic`).
