locals {
  # --- Topology from range.yaml (variables are only overrides) -------------
  range        = yamldecode(file("${path.root}/../../range.yaml"))
  node         = var.proxmox_node != "" ? var.proxmox_node : keys(local.range.proxmox.nodes)[0]
  vm_id        = var.vm_id != null ? var.vm_id : local.range.proxmox.templates[var.template_name].vm_ids[local.node]
  bridge       = var.bridge != "" ? var.bridge : local.range.proxmox.bridge
  vlan_tag     = var.vlan_tag != "" ? var.vlan_tag : "${local.range.network.vlan_id}"
  disk_storage = var.disk_storage != "" ? var.disk_storage : local.range.proxmox.datastore
  ci_storage   = var.cloud_init_storage_pool != "" ? var.cloud_init_storage_pool : local.disk_storage

  # --- Installation media: override > default name on proxmox.iso_storage -----
  iso_storage = try(local.range.proxmox.iso_storage, "local")
  iso_file    = var.iso_file != "" ? var.iso_file : "${local.iso_storage}:iso/${var.iso_name}"
  virtio_iso  = var.virtio_iso_file != "" ? var.virtio_iso_file : "${local.iso_storage}:iso/virtio-win.iso"
  cd_storage  = var.iso_storage != "" ? var.iso_storage : local.iso_storage

  # --- Locale from range.yaml (locale.*), variables override ---------------
  locale       = try(local.range.locale, {})
  ui_language  = var.ui_language != "" ? var.ui_language : try(local.locale.language, "en-US")
  input_locale = var.input_locale != "" ? var.input_locale : try(local.locale.windows_input_locale, "en-US")
  timezone     = var.timezone != "" ? var.timezone : try(local.locale.windows_timezone, "UTC")

  # --- Proxmox access --------------------------------------------------------
  pve_endpoint = trimsuffix(var.proxmox_endpoint != "" ? var.proxmox_endpoint : local.range.proxmox.endpoint, "/")
  proxmox_url  = length(regexall("/api2/json$", local.pve_endpoint)) > 0 ? local.pve_endpoint : "${local.pve_endpoint}/api2/json"
  # "user@realm!tokenid=secret" -> username "user@realm!tokenid", token "secret"
  pve_token_parts = split("=", var.proxmox_api_token)
  pve_username    = local.pve_token_parts[0]
  pve_token       = try(join("=", slice(local.pve_token_parts, 1, length(local.pve_token_parts))), "")
  pve_insecure    = contains(["true", "1", "yes"], lower(var.proxmox_insecure))

  build_date = formatdate("YYYY-MM-DD hh:mm 'UTC'", timestamp())

  # Escape the password for XML (inserted into autounattend/Unattend)
  admin_password_xml = replace(replace(replace(replace(replace(var.admin_password, "&", "&amp;"), "<", "&lt;"), ">", "&gt;"), "\"", "&quot;"), "'", "&apos;")

  unattend_vars = {
    admin_password = local.admin_password_xml
    image_name     = var.image_name
    image_index    = var.image_index
    product_key    = var.product_key
    virtio_os      = var.virtio_os
    is_client      = var.is_client
    ui_language    = local.ui_language
    input_locale   = local.input_locale
    timezone       = local.timezone
  }
}

source "proxmox-iso" "windows" {
  # --- Connection ------------------------------------------------------------
  proxmox_url              = local.proxmox_url
  username                 = local.pve_username
  token                    = local.pve_token
  insecure_skip_tls_verify = local.pve_insecure
  node                     = local.node
  task_timeout             = "10m"

  # --- VM / Template ---------------------------------------------------------
  vm_id                = local.vm_id
  vm_name              = var.template_name
  template_name        = var.template_name
  template_description = "${var.template_name} - Packer build ${local.build_date} (ai-range, ${var.image_name})"
  tags                 = "ai-range;template;windows;${var.template_name}"

  os       = "win11"
  machine  = "q35"
  bios     = "ovmf"
  cpu_type = var.cpu_type
  cores    = var.cores
  sockets  = 1
  memory   = var.memory

  efi_config {
    efi_storage_pool  = local.disk_storage
    efi_type          = "4m"
    pre_enrolled_keys = true
  }

  tpm_config {
    tpm_storage_pool = local.disk_storage
    tpm_version      = "v2.0"
  }

  scsi_controller = "virtio-scsi-single"

  disks {
    type         = "scsi"
    storage_pool = local.disk_storage
    disk_size    = var.disk_size
    format       = "raw"
    cache_mode   = "none"
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

  qemu_agent              = true
  cloud_init              = true
  cloud_init_storage_pool = local.ci_storage

  # --- Installation media ---------------------------------------------------
  boot_iso {
    type     = "sata"
    index    = 0
    iso_file = local.iso_file
    unmount  = true
  }

  additional_iso_files {
    type     = "sata"
    index    = 1
    iso_file = local.virtio_iso
    unmount  = true
  }

  # Autounattend CD (xorriso in the tools container), attached after upload
  additional_iso_files {
    type             = "sata"
    index            = 2
    iso_storage_pool = local.cd_storage
    cd_label         = "UNATTEND"
    cd_files         = ["${path.root}/scripts/bootstrap.ps1"]
    cd_content = {
      "autounattend.xml" = templatefile("${path.root}/files/autounattend.xml.pkrtpl", local.unattend_vars)
    }
    unmount = true
  }

  # Empty disk first -> OVMF falls through to the DVD; after installation scsi0 boots.
  boot = "order=scsi0;sata0"
  # Catch "Press any key to boot from CD or DVD..."
  boot_wait = "3s"
  boot_command = [
    "<spacebar><wait1s><spacebar><wait1s><spacebar><wait1s><spacebar><wait1s><spacebar>"
  ]

  # --- Communicator ----------------------------------------------------------
  communicator   = "winrm"
  winrm_username = "Administrator"
  winrm_password = var.admin_password
  winrm_port     = 5985
  winrm_use_ssl  = false
  winrm_insecure = true
  winrm_timeout  = "2h"
}

build {
  name    = "windows"
  sources = ["source.proxmox-iso.windows"]

  # --- optional Windows updates (2 passes, no extra plugin) -----------------
  # Runs as a scheduled task (elevated), since the WU COM API does not work over WinRM.
  provisioner "powershell" {
    environment_vars  = ["INSTALL_UPDATES=${var.install_updates}"]
    elevated_user     = "Administrator"
    elevated_password = var.admin_password
    script            = "${path.root}/scripts/windows-update.ps1"
  }

  provisioner "windows-restart" {
    restart_timeout = "30m"
  }

  provisioner "powershell" {
    environment_vars  = ["INSTALL_UPDATES=${var.install_updates}"]
    elevated_user     = "Administrator"
    elevated_password = var.admin_password
    script            = "${path.root}/scripts/windows-update.ps1"
  }

  provisioner "windows-restart" {
    restart_timeout = "30m"
  }

  # --- cloudbase-init ---------------------------------------------------------
  provisioner "file" {
    source      = "${path.root}/files/cloudbase-init/"
    destination = "C:/Windows/Temp/packer-cbi"
  }

  provisioner "file" {
    content     = templatefile("${path.root}/files/sysprep-unattend.xml.pkrtpl", local.unattend_vars)
    destination = "C:/Windows/Temp/packer-cbi/Unattend.xml"
  }

  provisioner "powershell" {
    environment_vars = ["CBI_MSI_URL=${var.cloudbase_init_msi_url}"]
    script           = "${path.root}/scripts/install-cloudbase-init.ps1"
  }

  # --- Cleanup + Sysprep /generalize /quit; Packer then shuts down via the API
  provisioner "powershell" {
    environment_vars = ["IS_CLIENT=${var.is_client}"]
    script           = "${path.root}/scripts/sysprep.ps1"
  }
}
