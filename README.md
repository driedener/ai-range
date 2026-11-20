# ai-range

An AI-driven purple-team lab. A **Red agent** attacks a replica corporate network (an Active Directory domain
on Proxmox VE), a **Blue agent** acting as SOC analyst detects and responds through Elastic Security or
SentinelOne, and a **Detection Engineer** agent writes rules for what was missed. A deterministic **scorer**
grades every exercise against ground truth recorded by the attack tooling itself.

> [!WARNING]
> The range contains **intentionally vulnerable configurations** (weak passwords, Kerberoastable accounts,
> vulnerable AD CS templates, a command-injection web app, ...). Run it only on an **isolated network** that
> you control, never expose Kibana or Elasticsearch to the internet, and do not connect it to production
> systems. The Red agent executes **real attack tools** (impacket, NetExec, Responder, Certipy, ...) from a
> Kali VM against the range. See [SECURITY.md](SECURITY.md).

## Architecture

```
Controller (any Docker host)                 Proxmox VE cluster (1..n nodes)
  Elastic: es01 :9200, kibana :5601             Range network: one VLAN on a bridge
  fleet-server :8220                  <--->       domain controller, servers, Windows 11 clients,
  tools  (terraform, packer, ansible)             Linux servers, attacker VM (Kali)
  agents (Red, Blue, Engineer, scorer)
```

- **Controller:** runs the Elastic stack (telemetry, ground truth, scores), all tooling and the agents in Docker
  containers. Nothing else needs to be installed on it.
- **Proxmox:** Packer builds the templates, Terraform clones the VMs, Ansible configures them (AD, AD CS, file
  server, IIS, logging, EDR agents).
- **One file describes your environment:** `range.yaml` (names, networks, IPs, VM roles and services).

## Features

- Exercises from scenario files (assumed breach, no credentials, web compromise, identity attacks, Linux path, ...)
- Sequential (Red, then Blue) or parallel mode (Blue watches live and can isolate hosts while Red attacks)
- Security platform: Elastic Security (default) or SentinelOne
- Opt-in vulnerability profiles (`vuln_*`) applied on top of a clean baseline, reset by Proxmox snapshot rollback
- Least-privilege agents: no shell, no file system, only purpose-built tools; Red is scope-limited twice
- Deterministic scoring: detection per attack step, technique match, time to detect, noise, triage, cost

## Documentation

The full documentation lives in [`docs/`](docs/index.md) and is published as a website with Zensical
(`zensical.toml`). Start with [Prerequisites](docs/prerequisites.md) and [Getting started](docs/getting-started.md).

## Quickstart

On the controller, from `docker/` (details and Windows variants in [Getting started](docs/getting-started.md)):

```sh
cp .env.example .env && cp ../range.example.yaml ../range.yaml   # fill in secrets, adapt the topology
docker compose --env-file .env build tools
docker compose --env-file .env run --rm tools python3 scripts/configure.py
docker compose --env-file .env up -d                             # Elastic, Kibana, Fleet
docker compose --env-file .env run --rm tools sh packer/windows/build.sh   # + Linux templates, see docs
docker compose --env-file .env run --rm tools sh -c "cd terraform/range && terraform init && terraform apply"
docker compose --env-file .env run --rm tools sh -c "cd ansible && ansible-playbook site.yml"
docker compose --env-file .env run --rm agents snapshot create baseline
docker compose --env-file .env run --rm tools sh -c "cd ansible && ansible-playbook playbooks/vulns.yml"
docker compose --env-file .env run --rm agents exercise --scenario assumed-breach --engineer
```

## Licence

[Apache License 2.0](LICENSE). Vendor installers, ISOs and API specifications are not part of this repository.
