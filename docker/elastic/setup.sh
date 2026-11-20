#!/usr/bin/env bash
# Mode "certs":    create CA + certificates (once), then exit -> es01 starts afterwards.
# Mode "password": wait for Elasticsearch and set the kibana_system password -> Kibana starts afterwards.
set -euo pipefail
MODE="${1:-all}"

: "${ELASTIC_PASSWORD:?ELASTIC_PASSWORD missing in .env}"
: "${KIBANA_PASSWORD:?KIBANA_PASSWORD missing in .env}"
: "${CONTROLLER_IP:?CONTROLLER_IP missing (docker/range.env, scripts/configure.py)}"

cd /usr/share/elasticsearch
CERTS=config/certs

if [ ! -f "$CERTS/ca.zip" ]; then
  echo "==> Creating CA"
  bin/elasticsearch-certutil ca --silent --pem -out "$CERTS/ca.zip"
  unzip -o -q "$CERTS/ca.zip" -d "$CERTS"
fi

if [ ! -f "$CERTS/certs.zip" ]; then
  echo "==> Creating certificates (SAN incl. ${CONTROLLER_IP})"
  cat > "$CERTS/instances.yml" <<EOF
instances:
  - name: es01
    dns: [es01, localhost]
    ip: [127.0.0.1, ${CONTROLLER_IP}]
  - name: kibana
    dns: [kibana, localhost]
    ip: [127.0.0.1, ${CONTROLLER_IP}]
  - name: fleet-server
    dns: [fleet-server, localhost]
    ip: [127.0.0.1, ${CONTROLLER_IP}]
EOF
  bin/elasticsearch-certutil cert --silent --pem \
    --in "$CERTS/instances.yml" \
    --ca-cert "$CERTS/ca/ca.crt" --ca-key "$CERTS/ca/ca.key" \
    -out "$CERTS/certs.zip"
  unzip -o -q "$CERTS/certs.zip" -d "$CERTS"
fi

chown -R root:root "$CERTS"
find "$CERTS" -type d -exec chmod 750 {} \;
find "$CERTS" -type f -exec chmod 640 {} \;
# The CA certificate is public: readable for containers with a non-root user (agents, uid 1000).
# Private keys (ca.key, <service>.key) stay root-only (640).
chmod 755 "$CERTS" "$CERTS/ca"
chmod 644 "$CERTS/ca/ca.crt"

if [ "$MODE" = "certs" ]; then
  echo "==> Certificates ready"
  exit 0
fi

echo "==> Waiting for Elasticsearch"
until curl -s --cacert "$CERTS/ca/ca.crt" https://es01:9200 | grep -q "missing authentication credentials"; do
  sleep 5
done

echo "==> Setting kibana_system password"
until curl -s -X POST --cacert "$CERTS/ca/ca.crt" -u "elastic:${ELASTIC_PASSWORD}" \
  -H "Content-Type: application/json" \
  https://es01:9200/_security/user/kibana_system/_password \
  -d "{\"password\":\"${KIBANA_PASSWORD}\"}" | grep -q "^{}"; do
  sleep 5
done

echo "==> Setup done"
