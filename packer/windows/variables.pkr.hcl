# ---------------------------------------------------------------------------
# Proxmox access (from the tools container env, see docs/conventions.md)
# ---------------------------------------------------------------------------
variable "proxmox_endpoint" {
  type        = string
  default     = ""
  description = "Override (empty = proxmox.endpoint from range.yaml; \"/api2/json\" is appended if needed)"
}

variable "proxmox_api_token" {
  type        = string
  default     = env("PROXMOX_VE_API_TOKEN")
  sensitive   = true
  description = "Format user@realm!tokenid=secret"
}

variable "proxmox_insecure" {
  type        = string
  default     = env("PROXMOX_VE_INSECURE")
  description = "true/false - do not verify the Proxmox TLS certificate"
}

variable "admin_password" {
  type        = string
  default     = env("RANGE_ADMIN_PASSWORD")
  sensitive   = true
  description = "Password of the local Administrator (WinRM)"
}

# ---------------------------------------------------------------------------
# Target node / VM
# ---------------------------------------------------------------------------
variable "proxmox_node" {
  type        = string
  default     = ""
  description = "Target node (empty = first node from range.yaml)"
}

variable "vm_id" {
  type        = number
  default     = null
  description = "VMID of the template (empty = proxmox.templates.<template_name>.vm_ids from range.yaml)"
}

variable "template_name" {
  type        = string
  description = "win2022 | win11"
}

variable "cpu_type" {
  type    = string
  default = "host"
}

variable "cores" {
  type    = number
  default = 2
}

variable "memory" {
  type    = number
  default = 4096
}

variable "disk_size" {
  type    = string
  default = "60G"
}

# ---------------------------------------------------------------------------
# Storage / network
# ---------------------------------------------------------------------------
variable "iso_name" {
  type        = string
  description = "Windows ISO file name on proxmox.iso_storage (set in <template>.pkrvars.hcl)"
}

variable "iso_file" {
  type        = string
  default     = ""
  description = "Full override as <storage>:iso/<file> (empty = <proxmox.iso_storage>:iso/<iso_name>)"
}

variable "virtio_iso_file" {
  type        = string
  default     = ""
  description = "virtio-win ISO as <storage>:iso/<file> (empty = <proxmox.iso_storage>:iso/virtio-win.iso)"
}

variable "iso_storage" {
  type        = string
  default     = ""
  description = "Storage (content iso) for the generated autounattend CD (empty = proxmox.iso_storage from range.yaml)"
}

# Empty = value from range.yaml (proxmox.datastore, proxmox.bridge, network.vlan_id)
variable "disk_storage" {
  type    = string
  default = ""
}

variable "cloud_init_storage_pool" {
  type    = string
  default = ""
}

variable "bridge" {
  type    = string
  default = ""
}

variable "vlan_tag" {
  type    = string
  default = ""
}

# ---------------------------------------------------------------------------
# Windows setup
# ---------------------------------------------------------------------------
variable "image_name" {
  type        = string
  description = "Image name in install.wim (/IMAGE/NAME)"
}

variable "image_index" {
  type        = number
  default     = 0
  description = "Index in install.wim (/IMAGE/INDEX). > 0 takes precedence over image_name (more robust with volume ISOs)"
}

variable "product_key" {
  type        = string
  default     = ""
  description = "Empty for evaluation ISOs; for retail ISOs e.g. a KMS client / generic key"
}

variable "virtio_os" {
  type        = string
  description = "Driver subfolder on the virtio-win ISO: 2k22 | w11"
}

variable "is_client" {
  type        = bool
  default     = false
  description = "true for Windows 11 (LabConfig bypass, Appx cleanup before Sysprep)"
}

# Empty = range.yaml locale.language / locale.windows_input_locale / locale.windows_timezone
variable "ui_language" {
  type    = string
  default = ""
}

variable "input_locale" {
  type    = string
  default = ""
}

variable "timezone" {
  type    = string
  default = ""
}

variable "install_updates" {
  type    = bool
  default = false
}

variable "cloudbase_init_msi_url" {
  type    = string
  default = "https://www.cloudbase.it/downloads/CloudbaseInitSetup_Stable_x64.msi"
}
