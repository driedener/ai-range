terraform {
  required_version = ">= 1.6"

  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "~> 0.66"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}

# Endpoint from range.yaml; credentials from the environment (docker/.env -> tools container):
# PROXMOX_VE_API_TOKEN, PROXMOX_VE_INSECURE
provider "proxmox" {
  endpoint = local.range.proxmox.endpoint
}
