# ai-range

ai-range is an AI-driven purple-team lab that you run on your own Proxmox VE cluster.

- A **Red agent** attacks a replica corporate network: an Active Directory domain with servers, Windows 11
  clients and Linux servers. It works from a Kali VM inside the range.
- A **Blue agent** acts as SOC analyst. It triages alerts, investigates telemetry, opens cases and, if allowed,
  isolates hosts. It works against **Elastic Security** (default) or **SentinelOne**.
- A **Detection Engineer** agent reviews a graded exercise and writes detection rules for the gaps.
- A deterministic **scorer** (no LLM) grades each exercise against ground truth that the attack tooling records
  for every command Red runs.

!!! danger "Intentionally vulnerable"
    The range is built to be attacked. The optional vulnerability profiles add weak passwords, roastable
    accounts, vulnerable AD CS templates, a command-injection web app and more. The Red agent runs real attack
    tools. Run the range only on an isolated network, never expose Kibana or Elasticsearch to the internet,
    and keep it away from production systems and credentials.

## Architecture

```
Controller (any Docker host)                 Proxmox VE cluster (1..n nodes)
  Elastic: es01 :9200, kibana :5601             Range network: one VLAN on a bridge
  fleet-server :8220                  <--->       DC01, CA01, FS01, SQL01, WEB01 (Server 2022)
  tools  (terraform, packer, ansible)             WS01-WS03 (Windows 11)
  agents (Red, Blue, Engineer, scorer)            lnx-web01, lnx-db01 (Ubuntu 24.04)
                                                  kali01 (attacker)
```

The environment always has three parts:

| Part | What it is |
|---|---|
| Controller | Any machine with Docker (Linux, or Windows with Docker Desktop). Runs the Elastic stack (telemetry, ground truth, scores), the `tools` container (Terraform, Packer, Ansible) and the `agents` container. |
| Proxmox VE | A cluster with one or more nodes. Packer builds the templates, Terraform creates linked clones, Ansible configures AD, AD CS, file server, IIS, logging and the EDR agents. |
| Range network | One VLAN on a Proxmox bridge for all VMs. The controller must reach it and be reachable from it. |

Names, networks and IPs of all three parts are defined in one file, `range.yaml` (copied from
`range.example.yaml`). Secrets live in `docker/.env`. The host names and addresses in this documentation are
the defaults from `range.example.yaml` (domain `corp.internal`, range network `10.0.21.0/24`, controller
`10.0.10.5`).

## How an exercise works

1. Red receives a scenario briefing (for example "you are a helpdesk user with these credentials") and attacks
   through `kali_exec`. Each call writes a ground-truth record: MITRE technique, targets, command, exit code.
2. Blue triages the alerts of the exercise window, either afterwards (sequential mode) or live while Red is
   attacking (parallel mode).
3. The scorer maps each alert to exactly one attack step and reports detection rate, technique matches,
   time to detect, noise, triage actions and cost per role.
4. Optionally the Detection Engineer writes rules for the undetected steps.

Reports end up in `agents/reports/`, scores in the Elasticsearch index `range-scores`.

## Repository layout

| Path | Contents |
|---|---|
| `range.example.yaml` | Example topology; copy to `range.yaml` (git-ignored) |
| `scripts/configure.py` | Validates `range.yaml`, generates the Ansible inventory and `docker/range.env` |
| `docker/` | Compose stack (Elasticsearch, Kibana, Fleet Server, `tools`, `agents`) |
| `packer/` | VM templates (Windows Server 2022, Windows 11, Ubuntu 24.04, Kali) |
| `terraform/range/` | The range VMs |
| `ansible/` | VM configuration, vulnerability profiles, Elastic and SentinelOne configuration |
| `agents/` | AI agents, scenarios, scorer, reports |
| `scripts/` | Helpers: controller firewall, ISO download, Proxmox console/guest-agent tools |
| `sources/` | Vendor installers and API specs (local only, not in git), e.g. SentinelOne |

## Where to go next

- [Prerequisites](prerequisites.md): hardware, network, Proxmox API token
- [Getting started](getting-started.md): from an empty controller to the first exercise
- [Configuration](configuration.md): everything `range.yaml` controls
- [Agents & scoring](agents.md): commands, scenarios, security model, scoring rules
