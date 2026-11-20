# Getting started

This guide takes you from an empty controller to the first exercise. Check the
[prerequisites](prerequisites.md) first.

All commands run **on the controller from the `docker/` directory** unless stated otherwise. The tools
(Terraform, Packer, Ansible) run in containers; the controller itself only needs Docker. Commands are the same
in PowerShell and in a POSIX shell except where both variants are shown.

Overview:

1. [Prepare the controller](#1-prepare-the-controller)
2. [Configure](#2-configure)
3. [Open the controller firewall](#3-open-the-controller-firewall)
4. [Start the Elastic stack](#4-start-the-elastic-stack)
5. [Prepare Proxmox and download the ISOs](#5-prepare-proxmox-and-download-the-isos)
6. [Build the templates (Packer)](#6-build-the-templates-packer)
7. [Create the VMs (Terraform)](#7-create-the-vms-terraform)
8. [Configure the VMs (Ansible)](#8-configure-the-vms-ansible)
9. [Snapshot the clean range](#9-snapshot-the-clean-range)
10. [Apply the vulnerability profiles](#10-apply-the-vulnerability-profiles)
11. [Run exercises](#11-run-exercises)
12. [Clean up after an exercise](#12-clean-up-after-an-exercise)

## 1. Prepare the controller

Elasticsearch needs `vm.max_map_count >= 262144` and enough memory.

=== "Windows (Docker Desktop / WSL2)"

    Create or edit `%UserProfile%\.wslconfig` (adapt the values to your hardware):

    ```ini
    [wsl2]
    memory=32GB
    processors=8
    kernelCommandLine = "sysctl.vm.max_map_count=262144"
    ```

    Then run `wsl --shutdown` and restart Docker Desktop. Disable sleep and hibernation on the controller,
    otherwise running exercises and Fleet connections break.

=== "Linux"

    ```sh
    echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-ai-range.conf
    sudo sysctl --system
    ```

## 2. Configure

Copy the two templates:

=== "PowerShell"

    ```powershell
    cd docker
    copy .env.example .env
    copy ..\range.example.yaml ..\range.yaml
    ```

=== "sh"

    ```sh
    cd docker
    cp .env.example .env
    cp ../range.example.yaml ../range.yaml
    ```

**`docker/.env`** holds secrets and runtime settings: Elastic passwords, `PROXMOX_VE_API_TOKEN` (see
[Proxmox API token](prerequisites.md#proxmox-api-token)), the range passwords, the passwords of the agents'
Elastic users and `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN`. Replace every `change-me` value. Random
values:

=== "PowerShell"

    ```powershell
    -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 40 | % {[char]$_})
    ```

=== "sh"

    ```sh
    openssl rand -base64 30 | tr -d '/+=' | cut -c1-32
    ```

`RANGE_ADMIN_PASSWORD`, `RANGE_DSRM_PASSWORD`, `RANGE_USER_PASSWORD` and `RANGE_TIER0_PASSWORD` must satisfy the
Windows password complexity rules. `KIBANA_ENCRYPTION_KEY` needs at least 32 characters. Check the current
Elastic 9.x release and set `ELASTIC_VERSION` before the first start.

**`range.yaml`** describes your environment: controller IP and admin networks, Proxmox endpoint, nodes, bridge
and storages, the range VLAN, network and gateway, domain, locale and the VMs. See
[Configuration](configuration.md) for every key.

Build the tools image, then validate `range.yaml` and generate the derived files (`ansible/inventory/range.yml`,
`docker/range.env`):

```sh
docker compose --env-file .env build tools
docker compose --env-file .env run --rm tools python3 scripts/configure.py
```

Re-run `configure.py` after every change to `range.yaml`.

## 3. Open the controller firewall

The range VMs must reach Elasticsearch (9200), Fleet (8220) and the Packer HTTP server (8100-8110); Kibana
(5601) is opened for the range network and `controller.admin_networks`. Both scripts read the networks from
`docker/range.env`, so run them after `configure.py` and again when the networks change.

=== "Windows controller"

    PowerShell as Administrator:

    ```powershell
    ..\scripts\controller\firewall.ps1
    ```

    Creates three inbound Windows Firewall rules (`ai-range Elastic/Fleet`, `ai-range Kibana`,
    `ai-range Packer HTTP`).

=== "Linux controller"

    ```sh
    sudo bash ../scripts/controller/firewall.sh            # apply
    sudo bash ../scripts/controller/firewall.sh --remove   # remove again
    ```

    Docker publishes container ports with its own iptables rules, which bypass ufw and firewalld. The script
    therefore restricts the published ports in the `DOCKER-USER` chain (its own chain `AIRANGE`). The rules
    are **not persistent**: re-run the script after a reboot or save the rules, e.g. with
    `netfilter-persistent save`.

## 4. Start the Elastic stack

```sh
docker compose --env-file .env up -d
docker compose --env-file .env logs -f setup fleet-server
```

The first start creates a CA and certificates (with the controller IP as SAN), sets the `kibana_system`
password and enrolls the Fleet Server. Open Kibana at `https://<controller.ip>:5601` (user `elastic`). Under
*Fleet* you should see the Fleet Server and the agent policies `range-windows` and `range-linux`.

## 5. Prepare Proxmox and download the ISOs

Create the API token as described in [Prerequisites](prerequisites.md#proxmox-api-token) and put it into
`docker/.env`.

Copy `scripts/proxmox/download-isos.sh` to a Proxmox node and run it as root. It downloads the Windows
evaluation ISOs, virtio-win, Ubuntu 24.04 and Kali into `/var/lib/vz/template/iso` (= storage `local`) and
verifies the SHA256 checksums of the Linux ISOs. With `PEER` it also copies them to another node via rsync over
SSH; run it once per additional node otherwise.

```bash
PEER=10.0.10.12 bash download-isos.sh      # download here, copy to the second node
bash download-isos.sh                      # this node only
```

Existing files are skipped (`FORCE=1` downloads again). The storage `local` exists separately on each node, so
every node that builds templates needs the ISOs. If you keep ISOs on another storage (for example a shared NFS
storage with content `iso`), set `proxmox.iso_storage` in `range.yaml` accordingly and point the script at that
storage's directory with `ISO_DIR`; a shared storage needs no `PEER`:

```bash
ISO_DIR=/mnt/pve/<storage>/template/iso bash download-isos.sh
```

| File | Used by |
|---|---|
| `SERVER_EVAL_x64FRE_en-us.iso` | `win2022` |
| `WIN11_ENTERPRISE_EVAL_x64FRE_en-us.iso` | `win11` |
| `virtio-win.iso` | both Windows templates |
| `ubuntu-24.04-live-server-amd64.iso` | `ubuntu2404` |
| `kali-linux-installer-amd64.iso` | `kali` |

To use other media or editions, see [Templates (Packer)](packer.md#other-isos-and-editions).

## 6. Build the templates (Packer)

Each template is built **once per node** that hosts VMs using it, because Terraform creates linked clones and
a linked clone must live on the same node as its template. VMIDs, bridge, VLAN and storages come from
`range.yaml` (`proxmox.templates`).

```sh
# all Windows templates on all nodes
docker compose --env-file .env run --rm tools sh packer/windows/build.sh

# Ubuntu and Kali on one node (repeat per node)
docker compose --env-file .env run --rm --service-ports tools sh -c "cd packer/linux && packer init . && packer build -var proxmox_node=pve1 ."
```

Builds take a while; Packer waits up to 45 minutes (Ubuntu) or 90 minutes (Kali) for the installation to finish. Details, options and
troubleshooting: [Templates (Packer)](packer.md).

## 7. Create the VMs (Terraform)

```sh
docker compose --env-file .env run --rm tools sh -c "cd terraform/range && terraform init && terraform plan"
docker compose --env-file .env run --rm tools sh -c "cd terraform/range && terraform apply"
```

Terraform reads `range.yaml` directly. A `terraform.tfvars` is only needed for optional SSH public keys for the
Linux VMs (copy `terraform/range/terraform.tfvars.example`).

## 8. Configure the VMs (Ansible)

```sh
docker compose --env-file .env run --rm tools sh -c "cd ansible && ansible-playbook site.yml"
```

`site.yml` runs: Active Directory (forest, objects, domain join, server roles), base configuration (CA trust,
logging, Sysmon), Elastic configuration (Defend, rules, users), EDR agents and finally the attacker VM. For
SentinelOne additional playbooks follow, see [SentinelOne](sentinelone.md). Details: [Ansible](ansible.md).

Then build the agents image and check that everything is reachable:

```sh
docker compose --env-file .env --profile agents build agents
docker compose --env-file .env run --rm agents check
```

## 9. Snapshot the clean range

Save the clean state before adding vulnerabilities:

```sh
docker compose --env-file .env run --rm agents snapshot create baseline
```

Snapshots cover exactly the VMs in `range.yaml` (by VMID).

## 10. Apply the vulnerability profiles

The base range is deliberately clean. Most scenarios need one or more vulnerability profiles (`vuln_*`), which
you apply separately, either all or selected ones by tag:

```sh
# all profiles
docker compose --env-file .env run --rm tools sh -c "cd ansible && ansible-playbook playbooks/vulns.yml"
# selected profiles
docker compose --env-file .env run --rm tools sh -c "cd ansible && ansible-playbook playbooks/vulns.yml --tags vuln_kerberoast,vuln_adcs"
```

Show which scenarios are ready with the applied profiles, then snapshot this state as well:

```sh
docker compose --env-file .env run --rm agents scenarios
docker compose --env-file .env run --rm agents snapshot create vulns
```

There is no "remove" for a profile; you go back by snapshot rollback. Profiles and attack paths:
[Vulnerability profiles](vulnerability-profiles.md).

## 11. Run exercises

```sh
docker compose --env-file .env run --rm agents exercise --scenario assumed-breach --engineer
```

- **Mode:** sequential (Red, then Blue) or parallel (Blue monitors live while Red attacks). The default comes
  from `AIRANGE_EXERCISE_MODE` in `docker/.env`; `--mode` overrides it per call.
- **Reports and scores** are written to `agents/reports/` and the index `range-scores`.
- **Cost:** each agent run is limited by `AIRANGE_MAX_BUDGET_USD` (Red: `AIRANGE_RED_MAX_BUDGET_USD`);
  `--budget` overrides it.

All commands and scenarios: [Agents & scoring](agents.md).

## 12. Clean up after an exercise

Roll back to the snapshot the exercise started from, for example:

```sh
docker compose --env-file .env run --rm agents snapshot rollback vulns
```

With SentinelOne also run `cleanup`. Isolations, Ranger blocks and firewall rules live in the console and
survive the rollback; `cleanup` lifts them and sets all open alerts and incidents of the range site to
*Resolved*:

```sh
docker compose --env-file .env run --rm agents cleanup
```

To stop the range VMs between sessions: `agents vms stop` (and `agents vms start`).
