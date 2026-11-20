output "vms" {
  description = "Name -> IP / node / role / VMID"
  value = {
    for name, vm in local.vms : name => {
      ip    = vm.ip
      node  = vm.node
      role  = vm.role
      vm_id = vm.vm_id
    }
  }
}
