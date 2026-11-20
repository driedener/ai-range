# Template "kali" - Kali Linux (Debian installer + preseed, SeaBIOS)

source "proxmox-iso" "kali" {
  # Proxmox connection
  proxmox_url              = local.proxmox_url
  username                 = local.proxmox_username
  token                    = local.proxmox_token
  insecure_skip_tls_verify = local.proxmox_insecure
  node                     = local.node
  task_timeout             = "10m"

  # VM
  vm_id                = local.kali_vm_id
  vm_name              = "packer-kali"
  template_name        = "kali"
  template_description = "Kali Linux (${var.kali_metapackage}) - Packer build ${local.build_time} (cloud-init NoCloud, qemu-guest-agent, user range)"
  os                   = "l26"
  bios                 = "seabios"
  cpu_type             = "host"
  cores                = var.cores
  memory               = var.memory
  qemu_agent           = true
  scsi_controller      = "virtio-scsi-single"
  boot                 = "order=scsi0;ide2"

  boot_iso {
    type     = "ide"
    index    = "2"
    iso_file = local.kali_iso
    unmount  = true
  }

  disks {
    type         = "scsi"
    disk_size    = var.disk_size
    storage_pool = local.disk_storage
    format       = "raw"
    io_thread    = true
    discard      = true
    ssd          = true
  }

  network_adapters {
    model    = "virtio"
    bridge   = local.bridge
    vlan_tag = local.vlan_tag
    firewall = false
  }

  cloud_init              = true
  cloud_init_storage_pool = local.disk_storage

  # Packer HTTP server in the container; the VM reaches it via controller.ip from range.yaml (local.http_ip)
  http_bind_address = "0.0.0.0"
  http_port_min     = 8100
  http_port_max     = 8110
  http_content = {
    "/kali/preseed.cfg" = templatefile("${path.root}/http/kali/preseed.cfg.pkrtpl", {
      password_hash    = local.range_password_hash
      kali_metapackage = var.kali_metapackage
      domain           = local.domain
      keyboard         = local.keyboard
      timezone         = local.timezone
      country          = local.country
    })
  }

  # ISOLINUX (BIOS): ESC -> boot: prompt, start the installer kernel with the preseed URL
  boot_wait         = "10s"
  boot_key_interval = "100ms"
  boot_command = [
    "<esc><wait2s>",
    # Keep it short (ISOLINUX line limit): auto=true defers the locale/keyboard/hostname
    # questions until after the preseed file is loaded, which holds all the values.
    "/install.amd/vmlinuz initrd=/install.amd/initrd.gz auto=true priority=critical",
    " url=http://${local.http_ip}:{{ .HTTPPort }}/kali/preseed.cfg --- quiet<enter>"
  ]

  # Communicator (after installation + reboot, IP via qemu-guest-agent)
  communicator           = "ssh"
  ssh_username           = "range"
  ssh_password           = var.range_admin_password
  ssh_timeout            = "90m"
  ssh_handshake_attempts = 100
}

build {
  sources = ["source.proxmox-iso.kali"]

  provisioner "shell" {
    inline = ["sudo cloud-init status --wait || true"]
  }

  provisioner "shell" {
    script          = "${path.root}/scripts/cleanup.sh"
    execute_command = "chmod +x {{ .Path }}; sudo -E sh '{{ .Path }}'"
  }
}
