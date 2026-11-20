# Template "ubuntu2404" - Ubuntu 24.04 Server (Subiquity autoinstall, SeaBIOS)

source "proxmox-iso" "ubuntu2404" {
  # Proxmox connection
  proxmox_url              = local.proxmox_url
  username                 = local.proxmox_username
  token                    = local.proxmox_token
  insecure_skip_tls_verify = local.proxmox_insecure
  node                     = local.node
  task_timeout             = "10m"

  # VM
  vm_id                = local.ubuntu_vm_id
  vm_name              = "packer-ubuntu2404"
  template_name        = "ubuntu2404"
  template_description = "Ubuntu 24.04 Server - Packer build ${local.build_time} (cloud-init NoCloud, qemu-guest-agent, user range)"
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
    iso_file = local.ubuntu_iso
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

  # Autoinstall data as a NoCloud CD (label "cidata") - no HTTP/network to the controller needed.
  # Subiquity finds the CD automatically; "autoinstall" on the kernel line skips the confirmation prompt.
  additional_iso_files {
    type             = "ide"
    index            = "3"
    iso_storage_pool = local.cd_storage
    unmount          = true
    cd_label         = "cidata"
    cd_content = {
      "user-data" = templatefile("${path.root}/http/ubuntu/user-data.pkrtpl", {
        password_hash = local.range_password_hash
        keyboard      = local.keyboard
        timezone      = local.timezone
      })
      "meta-data" = file("${path.root}/http/ubuntu/meta-data")
    }
  }

  # GRUB (BIOS) -> command line, start the kernel with a short autoinstall line
  boot_wait         = "15s"
  boot_key_interval = "100ms"
  boot_command = [
    "c<wait5s>",
    "linux /casper/vmlinuz autoinstall ---<enter><wait3s>",
    "initrd /casper/initrd<enter><wait3s>",
    "boot<enter>"
  ]

  # Communicator (after installation + reboot, IP via qemu-guest-agent)
  communicator           = "ssh"
  ssh_username           = "range"
  ssh_password           = var.range_admin_password
  ssh_timeout            = "45m"
  ssh_handshake_attempts = 100
}

build {
  sources = ["source.proxmox-iso.ubuntu2404"]

  provisioner "shell" {
    inline = ["sudo cloud-init status --wait || true"]
  }

  provisioner "shell" {
    script          = "${path.root}/scripts/cleanup.sh"
    execute_command = "chmod +x {{ .Path }}; sudo -E sh '{{ .Path }}'"
  }
}
