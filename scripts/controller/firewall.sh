#!/usr/bin/env bash
# Restricts the ports ai-range publishes on a Linux Docker controller (idempotent). Run as root.
#
#   sudo bash scripts/controller/firewall.sh            # apply
#   sudo bash scripts/controller/firewall.sh --remove   # remove the rules again
#
# Docker publishes container ports through its own iptables rules, which bypass ufw/firewalld INPUT rules.
# Filtering therefore happens in the DOCKER-USER chain (evaluated before Docker's own rules):
#   Elasticsearch 9200, Fleet 8220, Packer HTTP 8100-8110  <- range network only
#   Kibana 5601                                            <- range network + controller.admin_networks
# Networks come from docker/range.env (scripts/configure.py from range.yaml): RANGE_CIDR, RANGE_ADMIN_NETWORKS.
# Only traffic to published ports (conntrack state DNAT) is affected; container-to-container traffic is not.
# The rules are not persistent: re-run after a reboot or save them (e.g. netfilter-persistent save).
set -euo pipefail

CHAIN=AIRANGE
ENV_FILE="$(cd "$(dirname "$0")/../.." && pwd)/docker/range.env"

if ! iptables -L DOCKER-USER -n >/dev/null 2>&1; then
  echo "Chain DOCKER-USER not found - is Docker running on this host?" >&2
  exit 1
fi

if [[ ${1:-} == --remove ]]; then
  while iptables -D DOCKER-USER -j "$CHAIN" 2>/dev/null; do :; done
  iptables -F "$CHAIN" 2>/dev/null || true
  iptables -X "$CHAIN" 2>/dev/null || true
  echo "Removed chain $CHAIN"
  exit 0
fi

[[ -f $ENV_FILE ]] || { echo "$ENV_FILE missing - run scripts/configure.py first (docs/configuration.md)" >&2; exit 1; }
RANGE_CIDR=$(sed -n 's/^RANGE_CIDR=//p' "$ENV_FILE" | tr -d '\r')
ADMIN_NETWORKS=$(sed -n 's/^RANGE_ADMIN_NETWORKS=//p' "$ENV_FILE" | tr -d '\r' | tr ',' ' ')
[[ -n $RANGE_CIDR ]] || { echo "RANGE_CIDR missing in $ENV_FILE" >&2; exit 1; }

iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"
iptables -C DOCKER-USER -j "$CHAIN" 2>/dev/null || iptables -I DOCKER-USER 1 -j "$CHAIN"

# Replies and established connections are decided by their first packet
iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

restrict() { # restrict <name> <port|from:to> <source>...
  local name=$1 port=$2; shift 2
  local src
  for src in "$@"; do
    iptables -A "$CHAIN" -p tcp -s "$src" -m conntrack --ctstate DNAT --ctorigdstport "$port" -j RETURN
  done
  iptables -A "$CHAIN" -p tcp -m conntrack --ctstate DNAT --ctorigdstport "$port" -j DROP
  echo "OK: $name -> $port from $*"
}

# shellcheck disable=SC2086
{
  restrict "Elasticsearch" 9200      "$RANGE_CIDR"
  restrict "Fleet"         8220      "$RANGE_CIDR"
  restrict "Packer HTTP"   8100:8110 "$RANGE_CIDR"
  restrict "Kibana"        5601      "$RANGE_CIDR" $ADMIN_NETWORKS
}
iptables -A "$CHAIN" -j RETURN
