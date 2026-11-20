# Range VMs. Topology (nodes, network, VMs, templates) comes from range.yaml in the repo root -
# scripts/configure.py generates the Ansible inventory from the same file.
locals {
  range  = yamldecode(file("${path.module}/../../range.yaml"))
  net    = local.range.network
  prefix = tonumber(split("/", local.net.cidr)[1])
  dc_ip  = one([for name, vm in local.range.vms : vm.ip if vm.role == "dc"])

  vms = {
    for name, vm in local.range.vms : name => {
      vm_id     = try(vm.vm_id, local.net.vm_id_base + tonumber(element(split(".", vm.ip), 3)))
      node      = vm.node
      template  = vm.template
      os        = local.range.proxmox.templates[vm.template].os
      role      = vm.role
      ip        = vm.ip
      cores     = vm.cores
      memory_mb = vm.memory_mb
      disk_gb   = try(vm.disk_gb, null)
      # DC and attacker resolve via the router, everything else via the DC
      dns = try(vm.dns, contains(["dc", "attacker"], vm.role) ? [local.net.gateway] : [local.dc_ip])
    }
  }
}

resource "proxmox_virtual_environment_vm" "vm" {
  for_each = local.vms

  name      = each.key
  node_name = each.value.node
  vm_id     = each.value.vm_id
  tags      = ["ai-range", each.value.role]
  on_boot   = false
  started   = true

  clone {
    vm_id = local.range.proxmox.templates[each.value.template].vm_ids[each.value.node]
    full  = local.range.proxmox.full_clone
    # Linked clones stay on the template's storage - Proxmox rejects 'storage' there
    datastore_id = local.range.proxmox.full_clone ? local.range.proxmox.datastore : null
  }

  agent {
    enabled = true
  }

  cpu {
    cores = each.value.cores
    type  = "x86-64-v3"
  }

  memory {
    dedicated = each.value.memory_mb
  }

  network_device {
    bridge  = local.range.proxmox.bridge
    vlan_id = local.net.vlan_id
    model   = "virtio"
  }

  dynamic "disk" {
    for_each = each.value.disk_gb == null ? [] : [each.value.disk_gb]
    content {
      datastore_id = local.range.proxmox.datastore
      interface    = "scsi0"
      size         = disk.value
    }
  }

  # Proxmox automatically generates configdrive2 for Windows templates (cloudbase-init),
  # nocloud for Linux (cloud-init).
  initialization {
    datastore_id = local.range.proxmox.datastore
    # Packer templates have the cloud-init drive on ide0 (the bpg default would be ide2)
    interface = "ide0"

    ip_config {
      ipv4 {
        address = "${each.value.ip}/${local.prefix}"
        gateway = local.net.gateway
      }
    }

    dns {
      servers = each.value.dns
      domain  = local.range.domain
    }

    dynamic "user_account" {
      for_each = each.value.os == "linux" ? [1] : []
      content {
        username = var.linux_user
        password = var.linux_password
        keys     = var.ssh_public_keys
      }
    }
  }

  lifecycle {
    ignore_changes = [clone]
  }
}
