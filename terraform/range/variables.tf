# Topology (nodes, bridge, VLAN, network, VMs, templates) lives in range.yaml in the repo root.
# Only credentials and the Linux login remain here.

variable "linux_user" {
  type    = string
  default = "range"
}

# Without a password, cloud-init locks the user's password (set by Packer)
# -> Ansible SSH login fails. Comes from RANGE_ADMIN_PASSWORD (compose: TF_VAR_linux_password).
variable "linux_password" {
  type      = string
  sensitive = true
}

variable "ssh_public_keys" {
  description = "SSH keys for Linux VMs (cloud-init)"
  type        = list(string)
  default     = []
}
