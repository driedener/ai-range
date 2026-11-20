# ---------------------------------------------------------------------------
# Proxmox connection (from the tools container env, see docs/conventions.md)
# ---------------------------------------------------------------------------

variable "proxmox_endpoint" {
  type        = string
  description = "Override for the Proxmox API endpoint (empty = proxmox.endpoint from range.yaml)."
  default     = ""
}

variable "proxmox_api_token" {
  type        = string
  description = "API token in the format user@realm!tokenid=secret (from PROXMOX_VE_API_TOKEN)."
  default     = env("PROXMOX_VE_API_TOKEN")
  sensitive   = true

  validation {
    condition     = can(regex("^[^!]+![^=]+=.+$", var.proxmox_api_token))
    error_message = "PROXMOX_VE_API_TOKEN must have the format user@realm!tokenid=secret."
  }
}

variable "proxmox_insecure" {
  type        = string
  description = "Do not verify the Proxmox TLS certificate (from PROXMOX_VE_INSECURE, default true)."
  default     = env("PROXMOX_VE_INSECURE")
}

variable "proxmox_node" {
  type        = string
  description = "Target node for build and template (empty = first node from range.yaml)."
  default     = ""
}

# ---------------------------------------------------------------------------
# VM / Template
# ---------------------------------------------------------------------------

variable "vm_id" {
  type        = number
  description = "VMID of the template. Empty (null) = per proxmox.templates in range.yaml. Only set together with -only=<one build>."
  default     = null
}

variable "ubuntu_iso_file" {
  type        = string
  description = "Ubuntu ISO as <storage>:iso/<file>. Empty = <proxmox.iso_storage>:iso/ubuntu-24.04-live-server-amd64.iso (name used by scripts/proxmox/download-isos.sh)."
  default     = ""
}

variable "kali_iso_file" {
  type        = string
  description = "Kali installer ISO as <storage>:iso/<file>. Empty = <proxmox.iso_storage>:iso/kali-linux-installer-amd64.iso (name used by scripts/proxmox/download-isos.sh)."
  default     = ""
}

variable "iso_file" {
  type        = string
  description = "Optional override for the ISO (only together with -only=<one build>); otherwise ubuntu_iso_file/kali_iso_file."
  default     = ""
}

variable "disk_storage" {
  type        = string
  description = "Storage for the system disk and cloud-init drive (empty = proxmox.datastore from range.yaml)."
  default     = ""
}

variable "disk_size" {
  type    = string
  default = "32G"
}

variable "cores" {
  type    = number
  default = 2
}

variable "memory" {
  type    = number
  default = 4096
}

variable "bridge" {
  type        = string
  description = "empty = proxmox.bridge from range.yaml"
  default     = ""
}

variable "vlan_tag" {
  type        = string
  description = "empty = network.vlan_id from range.yaml"
  default     = ""
}

variable "kali_metapackage" {
  type        = string
  description = "Kali metapackage: kali-linux-headless (default, agents use SSH) or kali-linux-default."
  default     = "kali-linux-headless"

  validation {
    condition     = contains(["kali-linux-headless", "kali-linux-default"], var.kali_metapackage)
    error_message = "The variable kali_metapackage must be kali-linux-headless or kali-linux-default."
  }
}

# ---------------------------------------------------------------------------
# Packer HTTP server (runs in the Docker container; the VM reaches it via controller.ip)
# ---------------------------------------------------------------------------

variable "http_ip" {
  type        = string
  description = "IP at which the build VM reaches the Packer HTTP server (empty = controller.ip from range.yaml)."
  default     = ""

  validation {
    condition     = var.http_ip == "" || can(regex("^\\d+\\.\\d+\\.\\d+\\.\\d+$", var.http_ip))
    error_message = "The variable http_ip must be empty or an IPv4 address."
  }
}

# ---------------------------------------------------------------------------
# Local user "range"
# ---------------------------------------------------------------------------

variable "range_admin_password" {
  type        = string
  description = "Password of the user range (from RANGE_ADMIN_PASSWORD)."
  default     = env("RANGE_ADMIN_PASSWORD")
  sensitive   = true

  validation {
    condition     = length(var.range_admin_password) > 0
    error_message = "RANGE_ADMIN_PASSWORD is not set."
  }
}

# ---------------------------------------------------------------------------
# Derived values
# ---------------------------------------------------------------------------

locals {
  # Topology from range.yaml (repo root); the variables above are only overrides
  range        = yamldecode(file("${path.root}/../../range.yaml"))
  node         = var.proxmox_node != "" ? var.proxmox_node : keys(local.range.proxmox.nodes)[0]
  bridge       = var.bridge != "" ? var.bridge : local.range.proxmox.bridge
  vlan_tag     = var.vlan_tag != "" ? var.vlan_tag : "${local.range.network.vlan_id}"
  disk_storage = var.disk_storage != "" ? var.disk_storage : local.range.proxmox.datastore
  http_ip      = var.http_ip != "" ? var.http_ip : local.range.controller.ip
  domain       = local.range.domain
  endpoint     = var.proxmox_endpoint != "" ? var.proxmox_endpoint : local.range.proxmox.endpoint

  proxmox_url = "${trimsuffix(trimsuffix(local.endpoint, "/"), "/api2/json")}/api2/json"

  # user@realm!tokenid=secret  ->  username = user@realm!tokenid, token = secret
  proxmox_username = regex("^([^=]+)=(.*)$", var.proxmox_api_token)[0]
  proxmox_token    = regex("^([^=]+)=(.*)$", var.proxmox_api_token)[1]

  proxmox_insecure = lower(var.proxmox_insecure) != "false" && var.proxmox_insecure != "0"

  ubuntu_vm_id = var.vm_id != null ? var.vm_id : local.range.proxmox.templates.ubuntu2404.vm_ids[local.node]
  kali_vm_id   = var.vm_id != null ? var.vm_id : local.range.proxmox.templates.kali.vm_ids[local.node]

  # ISOs: explicit override > per-distro variable > default name on proxmox.iso_storage
  iso_storage = try(local.range.proxmox.iso_storage, "local")
  ubuntu_iso = var.iso_file != "" ? var.iso_file : (
    var.ubuntu_iso_file != "" ? var.ubuntu_iso_file : "${local.iso_storage}:iso/ubuntu-24.04-live-server-amd64.iso")
  kali_iso = var.iso_file != "" ? var.iso_file : (
    var.kali_iso_file != "" ? var.kali_iso_file : "${local.iso_storage}:iso/kali-linux-installer-amd64.iso")
  # Storage for generated CDs (cidata); empty = proxmox.iso_storage
  cd_storage = var.iso_storage != "" ? var.iso_storage : local.iso_storage

  # Keyboard, time zone and country from range.yaml (locale.*), optional
  locale   = try(local.range.locale, {})
  keyboard = try(local.locale.keyboard, "us")
  timezone = try(local.locale.timezone, "Etc/UTC")
  country  = upper(element(split("-", try(local.locale.language, "en-US")), 1))

  # crypt(3) hash (bcrypt, $2a$) - libxcrypt in Ubuntu 24.04 and Kali supports it.
  # Note: bcrypt() generates a new salt on every run. Kali gets the hash via the Packer HTTP
  # server (memory only); Ubuntu via the generated cidata CD on the ISO storage (during the build).
  range_password_hash = bcrypt(var.range_admin_password)

  build_time = formatdate("YYYY-MM-DD hh:mm ZZZ", timestamp())
}

variable "iso_storage" {
  type        = string
  description = "Storage (content iso) for generated CDs (cidata). Empty = proxmox.iso_storage from range.yaml."
  default     = ""
}
