# Prerequisites

## Proxmox VE

- A Proxmox VE cluster with **one or more nodes**. A single node works; with several nodes you spread the VMs
  across them in `range.yaml`. High availability is not used.
- **CPU with x86-64-v3** support. Terraform creates the VMs with CPU type `x86-64-v3` (roughly Intel Haswell /
  AMD Zen or newer). Templates are built with CPU type `host`.
- A storage for VM disks (`proxmox.datastore`, default `local-lvm`) and a storage with content type `iso` on
  **every node** (`proxmox.iso_storage`, default `local`) for the installer ISOs and the CDs Packer generates.

### Resources for the default topology

The VMs in `range.example.yaml` add up to **32 vCPU and 52 224 MB (~51 GB) RAM**:

| VMs | vCPU | RAM |
|---|---|---|
| DC01, CA01, FS01, WEB01 (Server 2022) | 2 each | 4 / 3 / 4 / 4 GB |
| SQL01 (Server 2022) | 4 | 6 GB |
| WS01-WS03 (Windows 11) | 4 each | 6 GB each |
| lnx-web01, lnx-db01 (Ubuntu 24.04) | 2 each | 2 GB each |
| kali01 (Kali) | 4 | 8 GB |

vCPUs can be overcommitted, RAM should not be. The VMs are **linked clones** of the templates (`full_clone:
false`), so disk usage stays low: the templates have 60 GB (Server 2022), 64 GB (Windows 11) and 32 GB (Ubuntu,
Kali) disks, and the clones only store their changes. You can remove VMs or reduce their size in `range.yaml`;
some scenarios need specific roles or services (see [Agents & scoring](agents.md#scenarios)).

## Controller

- A **Docker host**: Linux with Docker Engine, or Windows with Docker Desktop (WSL2 backend).
- **Docker Compose v2.24 or newer** (the compose file uses the `env_file` syntax with `required:`).
- About **32 GB RAM** recommended: Elasticsearch is limited to `ES_MEM_LIMIT=24g` (heap `ES_HEAP=12g`), Kibana
  to 2 GB, Fleet Server to 1 GB, plus the `tools` and `agents` containers. On a smaller host lower `ES_HEAP` and
  `ES_MEM_LIMIT` in `docker/.env`.
- `vm.max_map_count >= 262144` for Elasticsearch (see [Getting started](getting-started.md#1-prepare-the-controller)).
- Disk space for Elasticsearch data (the range retains data for about 14 days by default).

## Range network

All VMs live in **one VLAN on a Proxmox bridge** (`proxmox.bridge`, `network.vlan_id`). The network needs:

- **DHCP.** Packer build VMs get their address by DHCP. The range VMs themselves get static IPs through
  cloud-init / cloudbase-init.
- **A router** (`network.gateway`) that provides **DNS** and **internet access**. The VMs download Windows
  components, cloudbase-init, Sysmon and its configuration, Elastic Agent artifacts and Linux packages. The domain
  controller uses the gateway as DNS forwarder. The gateway is never an attack or block target.
- **Routing between controller and range in both directions**:

| From | To | Ports | Purpose |
|---|---|---|---|
| Range VMs | Controller | TCP 8220 | Fleet Server (Elastic Agent enrollment and check-in) |
| Range VMs | Controller | TCP 9200 | Elasticsearch (agent data) |
| Build VMs | Controller | TCP 8100-8110 | Packer HTTP server (Kali preseed) |
| Controller | Range VMs | TCP 5985 | WinRM (Packer, Ansible) |
| Controller | Range VMs | TCP 22 | SSH (Packer, Ansible, Red agent to Kali) |
| Admin networks | Controller | TCP 5601 | Kibana |
| Controller | Proxmox nodes | TCP 8006 | Proxmox API (Packer, Terraform, snapshots) |

No firewall inside the range is required or deployed. Keep the range isolated from your other networks except
for the paths above; the Kali VM additionally blocks all private networks except the range network (see
[Agents & scoring](agents.md#security-model)).

## Accounts and licences

- **Anthropic API key** (`ANTHROPIC_API_KEY`) or a **Claude subscription token** (`CLAUDE_CODE_OAUTH_TOKEN`,
  created with `claude setup-token`).
- **Elastic:** no licence needed. The stack starts with a 30-day trial (`LICENSE=trial`) and falls back to Basic;
  see [Elastic](elastic.md#licence-basic-vs-trial) for what Basic lacks.
- **Windows:** the default ISOs are evaluation editions (Server 2022: 180 days, Windows 11 Enterprise: 90 days).
- **Optional:** a SentinelOne tenant, if you want to use SentinelOne instead of Elastic Security
  ([SentinelOne](sentinelone.md)).

## Proxmox API token

Packer, Terraform and the `agents` container (snapshots, VM start/stop) use one API token. Its value goes into
`docker/.env` as `PROXMOX_VE_API_TOKEN=terraform@pve!tf=<secret>`.

### Simple: PVEAdmin

On one node, as root:

```bash
pveum user add terraform@pve
pveum aclmod / -user terraform@pve -role PVEAdmin
pveum user token add terraform@pve tf --privsep 0
```

The last command prints the secret once.

### Optional: least-privilege role

!!! note "Starting point, not verified on every version"
    The role below is a starting point for a token with fewer rights than PVEAdmin. Privilege names differ
    between Proxmox VE versions. If a Packer or Terraform run fails with HTTP 403, add the missing privilege or
    fall back to PVEAdmin.

Guest-agent privileges (Packer reads the VM's IP through the QEMU guest agent):

- Proxmox VE 8: `VM.Monitor`
- Proxmox VE 9: `VM.GuestAgent.Audit VM.GuestAgent.Unrestricted`

Example for Proxmox VE 9:

```bash
pveum role add AIRange -privs "Datastore.Allocate Datastore.AllocateSpace Datastore.AllocateTemplate \
Datastore.Audit Pool.Audit SDN.Use Sys.Audit Sys.Console Sys.Modify VM.Allocate VM.Audit VM.Clone \
VM.Config.CDROM VM.Config.CPU VM.Config.Cloudinit VM.Config.Disk VM.Config.HWType VM.Config.Memory \
VM.Config.Network VM.Config.Options VM.Console VM.PowerMgmt VM.Snapshot VM.Snapshot.Rollback \
VM.GuestAgent.Audit VM.GuestAgent.Unrestricted"
pveum user add terraform@pve
pveum aclmod / -user terraform@pve -role AIRange
pveum user token add terraform@pve tf --privsep 0
```

On Proxmox VE 8 replace the last two privileges with `VM.Monitor`.
