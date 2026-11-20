# Templates (Packer)

Packer builds four Proxmox templates with the `proxmox-iso` builder (plugin `hashicorp/proxmox` ~> 1.2,
Packer 1.11.2 in the `tools` container). Terraform then creates the range VMs as clones of these templates.

| Template | OS | Directory | Communicator | Default VMIDs (pve1 / pve2) |
|---|---|---|---|---|
| `win2022` | Windows Server 2022 Standard Evaluation (Desktop Experience) | `packer/windows` | WinRM | 9000 / 9100 |
| `win11` | Windows 11 Enterprise Evaluation | `packer/windows` | WinRM | 9001 / 9101 |
| `ubuntu2404` | Ubuntu 24.04 Server | `packer/linux` | SSH | 9002 / 9102 |
| `kali` | Kali Linux | `packer/linux` | SSH | 9003 / 9103 |

Endpoint, nodes, template VMIDs, bridge, VLAN, storages, controller IP and locale come from `range.yaml`.
Packer variables only override them. With linked clones (`proxmox.full_clone: false`) every node that hosts VMs
of a template needs its own copy of that template.

## Requirements

- **ISOs on every building node** in `proxmox.iso_storage` (default `local`, which is node-local). Download
  them with `scripts/proxmox/download-isos.sh` (see [Getting started](getting-started.md#5-prepare-proxmox-and-download-the-isos)):

    | Default path | Template |
    |---|---|
    | `<iso_storage>:iso/SERVER_EVAL_x64FRE_en-us.iso` | `win2022` |
    | `<iso_storage>:iso/WIN11_ENTERPRISE_EVAL_x64FRE_en-us.iso` | `win11` |
    | `<iso_storage>:iso/virtio-win.iso` | both Windows templates (current stable virtio-win, includes `virtio-win-guest-tools.exe`) |
    | `<iso_storage>:iso/ubuntu-24.04-live-server-amd64.iso` | `ubuntu2404` |
    | `<iso_storage>:iso/kali-linux-installer-amd64.iso` | `kali` (the *installer* ISO, not live or netinst) |

- `iso_storage` must also accept uploads: Packer uploads the generated CDs there (Windows autounattend,
  Ubuntu `cidata`). `proxmox.datastore` holds the disks.
- `docker/.env` with `PROXMOX_VE_API_TOKEN` (`user@realm!tokenid=secret`), `PROXMOX_VE_INSECURE` and
  `RANGE_ADMIN_PASSWORD`. Token rights: see [Prerequisites](prerequisites.md#proxmox-api-token).
- **DHCP and internet access in the range VLAN.** The build VM gets an address by DHCP; Packer learns it through
  the QEMU guest agent. Windows downloads cloudbase-init, Linux installs packages.
- **Kali only:** the build VM loads its preseed file from the Packer HTTP server on the controller (ports
  8100-8110, published with `--service-ports`). The controller firewall must allow these ports from the range
  network (`scripts/controller/firewall.ps1` / `firewall.sh` do this).

If the target VMID already exists (old template), the build fails. Delete the old template in Proxmox first.

## Building

All commands from `docker/`.

### Windows

```sh
# all Windows templates on all nodes
docker compose --env-file .env run --rm tools sh packer/windows/build.sh

# one template on one node
docker compose --env-file .env run --rm tools sh packer/windows/build.sh win2022 pve1

# with Windows updates (takes much longer)
docker compose --env-file .env run --rm -e PACKER_EXTRA_ARGS="-var install_updates=true" tools sh packer/windows/build.sh win11 pve2

# manually, without build.sh
docker compose --env-file .env run --rm tools sh -c "cd packer/windows && packer init . && packer build -var proxmox_node=pve1 -var-file=win2022.pkrvars.hcl ."
```

`build.sh [win2022|win11|all] [<node>|all]` runs `packer init` and then one build per template and node. It
loads `<template>.pkrvars.hcl` and, if present, `<template>.pkrvars.local.hcl` after it. Extra Packer arguments
go into `PACKER_EXTRA_ARGS` (e.g. `-on-error=abort`). Windows builds need no HTTP server, so
`--service-ports` is not required.

### Linux

`--service-ports` is required for Kali (preseed over HTTP) and harmless for Ubuntu. Every call starts a fresh
container, so always run `packer init .` first (it downloads the plugin).

```sh
# both templates on one node in one run (parallel builds)
docker compose --env-file .env run --rm --service-ports tools sh -c "cd packer/linux && packer init . && packer build -var proxmox_node=pve1 ."

# one template on one node
docker compose --env-file .env run --rm --service-ports tools sh -c "cd packer/linux && packer init . && packer build -only='proxmox-iso.ubuntu2404' -var proxmox_node=pve2 ."
docker compose --env-file .env run --rm --service-ports tools sh -c "cd packer/linux && packer init . && packer build -only='proxmox-iso.kali' -var proxmox_node=pve2 ."

# validate only, without Proxmox access
docker compose --env-file .env run --rm tools sh -c "cd packer/linux && packer init . && packer validate ."
```

## Other ISOs and editions

Do not edit the tracked var-files. Put overrides into git-ignored local files instead:

- **Windows:** `packer/windows/<template>.pkrvars.local.hcl` (e.g. `win2022.pkrvars.local.hcl`). `build.sh`
  loads it after the main var-file. Examples are in the comments of `win2022.pkrvars.hcl` and
  `win11.pkrvars.hcl`:

    ```hcl
    # win2022.pkrvars.local.hcl - volume licence media
    iso_name    = "en-us_windows_server_2022_..._x64_dvd_....iso"
    image_name  = "Windows Server 2022 Standard (Desktop Experience)"
    product_key = "VDYBN-27WPP-V4HQT-9VMD4-VMK7H"   # public KMS client key (GVLK), activates nothing
    ```

    The default var-files set `iso_name`, `image_name` (the evaluation editions) and `product_key = ""`
    (evaluation ISOs need no key). `win2022` also selects `image_index = 2`; an index > 0 takes precedence over
    `image_name`, which is more robust ("There are no matching OS images"). Set `image_index = 0` in your local
    file if you select by name. List the images of an ISO with
    `dism /Get-WimInfo /WimFile:X:\sources\install.wim`.

- **Linux:** `packer/linux/local.auto.pkrvars.hcl`. Packer loads `*.auto.pkrvars.hcl` automatically:

    ```hcl
    ubuntu_iso_file = "local:iso/ubuntu-24.04.1-live-server-amd64.iso"
    kali_iso_file   = "local:iso/kali-linux-2026.3-installer-amd64.iso"
    ```

Evaluation licences: Windows Server 180 days, Windows 11 Enterprise 90 days, counted from the deployment of a
clone (`slmgr /rearm` extends them).

## Variables

Pass with `-var name=value` (Linux) or `PACKER_EXTRA_ARGS` / local var-file (Windows). Empty defaults fall back
to `range.yaml`.

### Common

| Variable | Default | Meaning |
|---|---|---|
| `proxmox_node` | first node in `range.yaml` | Target node (name from `proxmox.nodes`) |
| `vm_id` | from `proxmox.templates` | VMID override (Linux: only together with `-only=<one build>`) |
| `proxmox_endpoint` | `proxmox.endpoint` | API endpoint override |
| `disk_storage` | `proxmox.datastore` | Storage for disks (and cloud-init drive) |
| `iso_storage` | `proxmox.iso_storage` | Storage for the generated CDs |
| `bridge` / `vlan_tag` | `proxmox.bridge` / `network.vlan_id` | Network |
| `cores` / `memory` / `disk_size` | 2 / 4096 / see below | Hardware of the template |

### Windows

| Variable | Default | Meaning |
|---|---|---|
| `iso_name` | set in var-file | Windows ISO file name on `iso_storage` |
| `iso_file` | `<iso_storage>:iso/<iso_name>` | Full override `<storage>:iso/<file>` |
| `virtio_iso_file` | `<iso_storage>:iso/virtio-win.iso` | virtio-win ISO |
| `image_name` / `image_index` | set in var-file | Image in `install.wim` |
| `product_key` | `""` | Empty for evaluation ISOs |
| `ui_language` / `input_locale` / `timezone` | `locale.language` / `locale.windows_input_locale` / `locale.windows_timezone` | Windows locale |
| `install_updates` | `false` | Install Windows updates during the build |
| `cpu_type` | `host` | CPU type of the build VM |
| `disk_size` | `60G` (win2022), `64G` (win11) | |
| `cloudbase_init_msi_url` | cloudbase.it stable x64 MSI | cloudbase-init installer |

### Linux

| Variable | Default | Meaning |
|---|---|---|
| `ubuntu_iso_file` / `kali_iso_file` | `<iso_storage>:iso/<default name>` | ISO per distribution |
| `iso_file` | empty | ISO override for the selected build (only with `-only`) |
| `disk_size` | `32G` | |
| `http_ip` | `controller.ip` | IP of the Packer HTTP server as seen by the VM |
| `kali_metapackage` | `kali-linux-headless` | or `kali-linux-default` (with desktop tools) |

Keyboard and time zone come from `locale.keyboard` and `locale.timezone`.

## What the Windows build does

Both Windows templates: q35, OVMF (EFI disk, Secure Boot keys pre-enrolled), vTPM 2.0, `scsi0` on
`virtio-scsi-single`, virtio NIC on the range VLAN, QEMU guest agent, cloud-init drive, cloudbase-init, WinRM
HTTP 5985, local `Administrator` with `RANGE_ADMIN_PASSWORD`. Microsoft Defender stays enabled.

1. The Windows ISO (sata0), virtio-win (sata1) and a generated CD (sata2: `autounattend.xml` from
   `files/autounattend.xml.pkrtpl` plus `scripts/bootstrap.ps1`) are attached. The boot command presses a key for
   "Press any key to boot from CD".
2. WinPE loads vioscsi/NetKVM/Balloon/vioserial, partitions the disk as GPT (no recovery partition at the end,
   so C: can be extended) and installs the selected image. Windows 11's hardware checks are bypassed via
   LabConfig.
3. Autologon runs `bootstrap.ps1`: network profile Private, virtio-win guest tools (including the QEMU guest
   agent), WinRM (Basic, unencrypted over HTTP, firewall rule for port 5985 on all profiles).
4. Packer connects via WinRM: optional updates (`install_updates`), cloudbase-init (MSI, service as
   LocalSystem, configuration from `files/cloudbase-init/`), Sysprep `/generalize /oobe /mode:vm /quit` with
   `files/sysprep-unattend.xml.pkrtpl`. Packer then shuts the VM down and converts it into a template.

### Windows clones (Terraform)

- `citype = configdrive2` (cloudbase-init only reads ConfigDrive, `ConfigDriveService`).
- Static IP, gateway and DNS (`ipconfig0`, `nameserver`) are applied by `NetworkConfigPlugin`.
- Host name: `SetHostNamePlugin`; because Proxmox writes the name only into `user_data` with configdrive2, the
  local script `set-hostname-network.ps1` also sets it from there (one reboot).
- A larger disk is picked up by `ExtendVolumesPlugin`, which extends C:.
- Logs on the guest: `C:\Program Files\Cloudbase Solutions\Cloudbase-Init\log\`.

## What the Linux build does

Both Linux templates: SeaBIOS, disk `scsi0` (virtio-scsi-single, raw, iothread, discard), virtio NIC on the
range VLAN, QEMU guest agent, cloud-init (datasource `NoCloud, ConfigDrive`) plus cloud-init drive, user `range`
(password `RANGE_ADMIN_PASSWORD`, sudo NOPASSWD, SSH password login enabled). At the end
`scripts/cleanup.sh` runs (cloud-init clean, empty machine-id, delete SSH host keys, apt clean, remove the
installer network configuration).

- **Ubuntu:** Subiquity autoinstall. The `user-data` (`http/ubuntu/user-data.pkrtpl`) is delivered as a NoCloud
  CD with label `cidata`, uploaded to `iso_storage`; no network connection to the controller is needed. Boot
  command: GRUB -> `c` -> `linux /casper/vmlinuz autoinstall ---`, `initrd /casper/initrd`, `boot`.
- **Kali:** Debian installer with preseed (`http/kali/preseed.cfg.pkrtpl`) served by the Packer HTTP server
  (`http_bind_address 0.0.0.0`, ports 8100-8110). The boot command uses `controller.ip` (`local.http_ip`)
  instead of `{{ .HTTPIP }}`, because Packer would otherwise insert the container IP. Boot command: ISOLINUX ->
  `ESC` -> `/install.amd/vmlinuz initrd=/install.amd/initrd.gz auto=true priority=critical url=...`. Kali does
  not enable network services automatically, so `ssh` is enabled in the preseed `late_command`.
- **Secrets:** the templates are rendered with `templatefile()` in memory. The password is passed as a bcrypt
  hash (`$2a$`, Packer `bcrypt()`), which libxcrypt in Ubuntu 24.04 and Kali accepts as crypt(3) hash. For Kali
  the hash can be fetched over HTTP from the range network during the build (lab trade-off).
- **SSH:** Packer finds the IP through the guest agent only after the reboot into the installed system;
  `ssh_timeout` is 45 min (Ubuntu) and 90 min (Kali, the metapackage is large).
- **Clones:** Terraform sets IP and user data through the cloud-init drive; host keys and machine-id are
  regenerated on first boot.

## Troubleshooting

- **Build hangs in the boot menu:** watch the Proxmox console. If the boot command is typed too early, increase
  `boot_wait` in the respective `.pkr.hcl`.
- **Console and guest without the GUI:** the helpers in `scripts/proxmox/` use only the Proxmox API (see
  [Reference](conventions.md#proxmox-helpers)): `screenshot.py` takes a console screenshot, `guestexec.py` runs
  a command through the guest agent.
- **"There are no matching OS images":** select the image by `image_index` instead of `image_name`.
- **HTTP 403 from Proxmox:** the token lacks a privilege, see [Prerequisites](prerequisites.md#proxmox-api-token).
- **Kali cannot load the preseed:** check `--service-ports`, the controller firewall (8100-8110) and routing from
  the range network to `controller.ip`.
