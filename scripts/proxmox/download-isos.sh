#!/usr/bin/env bash
# Downloads all ISOs for the ai-range templates to local:iso/ and copies them
# to the second node. Run as root on a Proxmox node:
#
#   PEER=<ip> bash download-isos.sh      # downloads to this node, copies to the second node
#   bash download-isos.sh                # local only, no copy
# PEER = IP of another node from range.yaml (proxmox.nodes).
#
# The file names match the defaults in packer/windows/*.pkrvars.hcl and
# packer/linux/variables.pkr.hcl. Existing files are skipped
# (FORCE=1 forces a fresh download).
#
# The default ISO_DIR is the directory of the storage "local" (proxmox.iso_storage: local in
# range.yaml). If proxmox.iso_storage points to another storage, set ISO_DIR to its iso
# directory, e.g. ISO_DIR=/mnt/pve/<storage>/template/iso (see: pvesm path <storage>:iso/x.iso).
# For shared storage (NFS/CIFS) PEER is not needed.
set -euo pipefail

ISO_DIR=${ISO_DIR:-/var/lib/vz/template/iso}
PEER=${PEER-}
FORCE=${FORCE:-0}

# Official sources (Microsoft Evaluation Center, as of 2026-11)
WIN2022_URL="https://go.microsoft.com/fwlink/p/?LinkID=2195280&clcid=0x409&culture=en-us&country=US"
WIN11_URL="https://go.microsoft.com/fwlink/?LinkId=2382600&clcid=0x409&culture=en-us&country=us"
VIRTIO_URL="https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"
UBUNTU_BASE="https://releases.ubuntu.com/24.04"
KALI_BASE="https://cdimage.kali.org/current"

mkdir -p "$ISO_DIR"
cd "$ISO_DIR"

log() { printf '\n==> %s\n' "$*"; }

fetch() { # fetch <dest> <url>
  local dest=$1 url=$2
  if [[ -s $dest && $FORCE != 1 ]]; then
    log "$dest exists - skipped"
    return 0
  fi
  log "Downloading $dest"
  wget --progress=dot:giga -O "$dest.part" "$url"
  mv "$dest.part" "$dest"
}

fetch_verified() { # fetch_verified <dest> <base-url> <grep-pattern>
  local dest=$1 base=$2 pattern=$3 sums line hash name
  sums=$(wget -qO- "$base/SHA256SUMS")
  line=$(grep -E "$pattern" <<<"$sums" | head -n1)
  [[ -n $line ]] || { echo "No entry for '$pattern' in $base/SHA256SUMS" >&2; exit 1; }
  hash=${line%% *}
  name=$(awk '{print $2}' <<<"$line"); name=${name#\*}
  fetch "$dest" "$base/$name"
  log "Verifying SHA256 of $dest ($name)"
  echo "$hash  $dest" | sha256sum -c -
}

fetch SERVER_EVAL_x64FRE_en-us.iso          "$WIN2022_URL"
fetch WIN11_ENTERPRISE_EVAL_x64FRE_en-us.iso "$WIN11_URL"
fetch virtio-win.iso                        "$VIRTIO_URL"
fetch_verified ubuntu-24.04-live-server-amd64.iso "$UBUNTU_BASE" 'live-server-amd64\.iso$'
fetch_verified kali-linux-installer-amd64.iso     "$KALI_BASE"   'installer-amd64\.iso$'

log "ISOs on this node:"
ls -lh "$ISO_DIR"/{SERVER_EVAL,WIN11_ENTERPRISE_EVAL}_x64FRE_en-us.iso \
       "$ISO_DIR"/virtio-win.iso "$ISO_DIR"/ubuntu-24.04-live-server-amd64.iso \
       "$ISO_DIR"/kali-linux-installer-amd64.iso

if [[ -n $PEER ]]; then
  log "Copying to $PEER:$ISO_DIR (rsync, changes only)"
  rsync -ah --info=progress2 \
    SERVER_EVAL_x64FRE_en-us.iso WIN11_ENTERPRISE_EVAL_x64FRE_en-us.iso virtio-win.iso \
    ubuntu-24.04-live-server-amd64.iso kali-linux-installer-amd64.iso \
    "root@$PEER:$ISO_DIR/"
fi

log "Done."
