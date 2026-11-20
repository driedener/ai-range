# Configuration (`range.yaml`)

The environment always consists of a controller (any Docker host), a Proxmox VE cluster and a range network (one
VLAN on a Proxmox bridge). **Names, networks and IPs** of these parts are defined in a single file,
`range.yaml` in the repository root. Secrets (passwords, API tokens) stay in `docker/.env`.

`range.yaml` is git-ignored. Create it from the example and adapt it:

```sh
cp range.example.yaml range.yaml
```

## Who reads what

| Consumer | Source | How |
|---|---|---|
| Terraform (`terraform/range`) | `range.yaml` | `yamldecode()`: VMs, nodes, bridge, VLAN, storage, templates, endpoint |
| Packer (`packer/linux`, `packer/windows`) | `range.yaml` | `locals`: node, template VMIDs, bridge, VLAN, storages, endpoint, domain, controller IP (HTTP server), locale. Packer variables remain as overrides. |
| Agents (Red/Blue/Engineer, scorer, snapshots) | `range.yaml` | mounted as `/range.yaml` (`agents/airange/topology.py`): scope, host list, prompts, snapshot VMs, scenario placeholders |
| Ansible | `ansible/inventory/range.yml` | **generated**: hosts, groups, topology variables `range_*` |
| Compose (Elastic certificates, Kibana/Fleet URLs, tools) | `docker/range.env` | **generated**: `CONTROLLER_IP`, `PROXMOX_VE_ENDPOINT`, networks |
| Controller firewall (`scripts/controller/firewall.ps1`, `firewall.sh`) | `docker/range.env` | **generated** |

After every change to `range.yaml` (from `docker/`):

```sh
docker compose --env-file .env run --rm tools python3 scripts/configure.py          # validate + generate
docker compose --env-file .env run --rm tools python3 scripts/configure.py --check  # validate only
```

`configure.py` checks among other things: IPs inside the range network and unique (VMIDs too), not the gateway,
network or broadcast address; gateway inside the network; nodes and templates known; template VMID present on
the chosen node; exactly one `dc` and one `attacker`; `ca` and `identity_connector` at most once; identity
connector not on the DC; controller IP not used by a VM; known `locale` keys. All errors are reported in one
list.

## Structure

The values below are those of `range.example.yaml`.

```yaml
organization: Example Corp          # company name in the agent prompts
domain: corp.internal               # AD domain (FQDN)
netbios: CORP                       # NetBIOS name of the domain

controller:                         # Docker host with Elastic, tools, agents
  name: controller
  ip: 10.0.10.5                     # how the VMs reach the controller (Fleet, certificate SAN, Packer HTTP)
  admin_networks: [10.0.10.0/24]    # may open Kibana (controller firewall)

proxmox:
  endpoint: https://10.0.10.11:8006/
  bridge: vmbr0
  datastore: local-lvm              # VM disks and cloud-init drives (e.g. local-zfs on ZFS installs)
  iso_storage: local                # content "iso" on every node: installer ISOs + generated CDs
  full_clone: false                 # false = linked clone (template must be on the same node)
  nodes: { pve1: 10.0.10.11, pve2: 10.0.10.12 }
  templates:                        # Packer templates: OS + VMID per node
    win2022: { os: windows, vm_ids: { pve1: 9000, pve2: 9100 } }
    # win11, ubuntu2404, kali ...

network:                            # the one range network
  vlan_id: 21
  cidr: 10.0.21.0/24
  gateway: 10.0.21.1                # DNS forwarder of the DC; never an attack or block target
  vm_id_base: 21000                 # VMID = base + last octet of the IP (if vm_id is not set)

locale:                             # optional, defaults shown
  language: en-US
  keyboard: us
  windows_input_locale: en-US
  timezone: Etc/UTC
  windows_timezone: UTC

vms:
  DC01: { ip: 10.0.21.10, node: pve1, template: win2022, role: dc, cores: 2, memory_mb: 4096 }
  FS01: { ip: 10.0.21.13, node: pve2, template: win2022, role: server, cores: 2, memory_mb: 4096,
          disk_gb: 80, services: [fileserver] }
```

### Top level

| Key | Required | Meaning |
|---|---|---|
| `organization` | no (default `Example Corp`) | Company name used in the agent prompts |
| `domain` | yes | AD domain (FQDN) |
| `netbios` | yes | NetBIOS name of the domain |

### `controller`

| Key | Meaning |
|---|---|
| `name` | Host name of the controller (used in prompts and the inventory) |
| `ip` | Address the range VMs use to reach the controller. Ends up in the Elastic certificate SAN, the Fleet URL and the Packer HTTP URL. |
| `admin_networks` | Networks allowed to open Kibana through the controller firewall (optional) |

Alerts whose source is the controller never count as detections, and Blue can never block it.

### `proxmox`

| Key | Meaning |
|---|---|
| `endpoint` | Proxmox API URL (`/api2/json` is appended where needed) |
| `bridge` | Bridge that carries the range VLAN |
| `datastore` | Storage for VM disks, EFI/TPM disks and cloud-init drives |
| `iso_storage` | Storage with content `iso` on every node (default `local`). Packer expects the installer ISOs there and uploads the CDs it generates (Windows autounattend, Ubuntu `cidata`). |
| `full_clone` | `false` = linked clones (fast, small; template must be on the VM's node), `true` = full clones |
| `nodes` | Node name -> IP. One node is enough. |
| `templates` | Per template: `os` (`windows` or `linux`) and `vm_ids` (template VMID per node) |

### `network`

| Key | Meaning |
|---|---|
| `vlan_id` | VLAN tag of the range network on `proxmox.bridge` |
| `cidr` | Range network |
| `gateway` | Router with DNS and internet access; DNS forwarder of the DC, never an attack or block target |
| `vm_id_base` | VMID of a VM = base + last octet of its IP, unless the VM sets `vm_id` |

### `locale` (optional)

| Key | Default | Used for |
|---|---|---|
| `language` | `en-US` | Windows UI and system locale (the language must exist on the ISO); the country part also sets the Kali installer country. Linux uses `en_US.UTF-8`. |
| `keyboard` | `us` | Linux XKB keyboard layout (e.g. `de`, `ch`, `fr`) |
| `windows_input_locale` | `en-US` | Windows keyboard (e.g. `de-DE`, `de-CH`, `fr-FR`) |
| `timezone` | `Etc/UTC` | IANA time zone for Linux (e.g. `Europe/Berlin`) |
| `windows_timezone` | `UTC` | Windows time zone ID (e.g. `W. Europe Standard Time`) |

Packer uses these values for keyboard, time zone and input locale of the templates. `configure.py` writes the
time zones into the inventory as `range_timezone_linux` and `range_timezone_windows` for Ansible. Unknown keys
are rejected.

!!! note
    Ansible sets the Windows audit subcategories by their English names. A non-English Windows UI language is
    therefore untested.

### `vms`

Each entry is keyed by the host name and needs `ip`, `node`, `template`, `role`, `cores` and `memory_mb`.
Optional: `vm_id`, `disk_gb`, `dns` (list), `services`.

**Roles** (`role`, exactly one per VM): `dc`, `server`, `client`, `linux_server`, `attacker`. They determine the
inventory groups, DNS (DC and attacker resolve via the gateway, everything else via the DC), the endpoint list
in the Blue prompts and the Red scope (the attacker is never a target). Exactly one `dc` and one `attacker` are
required.

**Services** (`services`, any number): `ca`, `web`, `fileserver`, `sql`, `identity_connector`. Ansible plays
target these groups (`playbooks/ad.yml`: AD CS -> `ca`, IIS -> `web`, ...; SentinelOne Identity ->
`identity_connector`). Scenarios refer to them through placeholders. `ca` and `identity_connector` may appear
at most once; the identity connector must not be the DC.

## Ansible variables from the inventory

`range_organization`, `range_domain`, `range_netbios`, `range_domain_dn`, `range_dc_name`, `range_dc_ip`,
`range_dc_fqdn`, `range_gateway`, `range_cidr`, `range_prefix_length`, `range_reverse_zone`,
`range_dns_forwarders`, `range_attacker_ip`, `range_controller_name`, `range_controller_ip`,
`range_timezone_linux`, `range_timezone_windows`.

Do not override them in `group_vars`: `group_vars/all.yml` takes precedence over the inventory.

## Scenario placeholders

Available in `agents/scenarios/*.yaml` (credentials, description, objectives): `${RANGE_DOMAIN}`,
`${RANGE_NETBIOS}`, `${RANGE_CIDR}`, `${RANGE_DC}`, `${RANGE_DC_IP}`, `${RANGE_ATTACKER}`,
`${RANGE_ATTACKER_IP}`, `${RANGE_ORGANIZATION}` and per service `${RANGE_FILESERVER}`, `${RANGE_CA}`,
`${RANGE_WEB}`, `${RANGE_SQL}` (each also with `_IP`). See [Agents & scoring](agents.md#scenarios) for the full
list. All other `${...}` values come from `docker/.env`.

## Changing a running range

- **Add/remove a VM, change resources:** edit `range.yaml` -> `configure.py` -> `terraform plan/apply` ->
  Ansible for the new hosts.
- **Rename a VM or change its IP:** Terraform rebuilds the VM (name and IP are part of cloud-init). Afterwards
  re-run the domain join and EDR roll-out; with SentinelOne new agent entries appear (decommission the old ones).
- **Domain, network or controller IP:** effectively a rebuild. For a new controller IP also regenerate the
  Elastic certificates (delete the `certs` volume) and re-enroll the agents.
- Snapshots (`agents snapshot ...`) cover exactly the VMs in `range.yaml` (by VMID).

Environment variables such as `AIRANGE_KALI_HOST`, `AIRANGE_TARGET_CIDR`, `AIRANGE_TARGET_EXCLUDE`,
`AIRANGE_DOMAIN` and `AIRANGE_MGMT_IPS` override values from `range.yaml` for special cases only.
