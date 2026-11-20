packer {
  required_version = ">= 1.11.2"

  required_plugins {
    proxmox = {
      source  = "github.com/hashicorp/proxmox"
      version = "~> 1.2.1"
    }
  }
}
