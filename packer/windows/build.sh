#!/bin/sh
# Builds the Windows templates in the tools container. Nodes and VMIDs come from range.yaml
# (proxmox.nodes / proxmox.templates.<name>.vm_ids).
#   Usage from docker/:
#     docker compose --env-file .env run --rm tools sh packer/windows/build.sh [win2022|win11|all] [<node>|all]
#   Extra Packer arguments via env, e.g.
#     -e PACKER_EXTRA_ARGS="-var install_updates=true -on-error=abort"
#   Local overrides (other ISO, edition, key): <template>.pkrvars.local.hcl next to this script (git-ignored).
set -eu

TEMPLATES="${1:-all}"
NODES="${2:-all}"
[ "$TEMPLATES" = "all" ] && TEMPLATES="win2022 win11"
if [ "$NODES" = "all" ]; then
  NODES=$(python3 -c 'import yaml; print(" ".join(yaml.safe_load(open("/work/range.yaml"))["proxmox"]["nodes"]))')
fi

cd "$(dirname "$0")"
packer init .

for t in $TEMPLATES; do
  VARFILES="-var-file=$t.pkrvars.hcl"
  if [ -f "$t.pkrvars.local.hcl" ]; then
    VARFILES="$VARFILES -var-file=$t.pkrvars.local.hcl"
    echo "==> Using local override $t.pkrvars.local.hcl"
  fi
  for n in $NODES; do
    echo "==> Building $t on $n (VMID from range.yaml)"
    # shellcheck disable=SC2086
    packer build -var "proxmox_node=$n" $VARFILES ${PACKER_EXTRA_ARGS:-} .
  done
done
