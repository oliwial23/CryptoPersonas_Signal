#!/usr/bin/env bash
# TLS-terminating reverse proxy in front of the test-server's cleartext :8080 connector.
#
# The modified Signal client (presage / libsignal-service-rs) always speaks TLS + wss://
# and pins a configured CA; the test-server's app connector is cleartext h2c on :8080.
# This runs a Caddy container (via the Colima docker daemon — no host install) that
# terminates TLS on 127.0.0.1:8443 with a self-signed cert and reverse-proxies to the
# host's :8080. `SignalServers::Staging` is repointed at https://127.0.0.1:8443 with our
# CA baked in (third_party/libsignal-service-rs/src/configuration.rs), so the whole
# messaging hot path — including the registration + receive websockets — rides through here.
#
# Usage:  ./tls-proxy.sh [up|down|status]   (default: up)
# Certs live in ./.local/tls (gitignored); regenerated only if missing. If you regenerate
# the CA, re-copy ca.crt -> third_party/libsignal-service-rs/certs/personas-test-server-ca.pem.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TLS="$HERE/.local/tls"
NAME="personas-tls-proxy"
LISTEN_PORT="${LISTEN_PORT:-8443}"
UPSTREAM="${UPSTREAM:-host.docker.internal:8080}"
# GroupsV2 + contact-storage endpoints are served by the separate storage-service
# (deploy/storage-service), not the chat Signal-Server. Path-route them there so
# Desktop's storageUrl (also 127.0.0.1:8443) transparently reaches it. If the
# storage-service is not running these paths just fail as before.
STORAGE_UPSTREAM="${STORAGE_UPSTREAM:-host.docker.internal:8090}"
IMAGE="caddy:2"

# Docker via Colima; sidestep the dangling Docker-Desktop credential helper.
export DOCKER_HOST="${DOCKER_HOST:-unix://$HOME/.colima/default/docker.sock}"
CLEAN_CFG="$HERE/.local/dockercfg"; mkdir -p "$CLEAN_CFG"; printf '{}' > "$CLEAN_CFG/config.json"
export DOCKER_CONFIG="$CLEAN_CFG"

action="${1:-up}"

case "$action" in
  down)   docker rm -f "$NAME" >/dev/null 2>&1 && echo "stopped $NAME" || echo "$NAME not running"; exit 0 ;;
  status) docker ps --filter "name=$NAME" --format '{{.Names}} {{.Status}} {{.Ports}}'; exit 0 ;;
  up)     : ;;
  *)      echo "usage: $0 [up|down|status]" >&2; exit 2 ;;
esac

# --- certs (self-signed CA + leaf with SAN 127.0.0.1) ---
if [ ! -f "$TLS/leaf.crt" ] || [ ! -f "$TLS/ca.crt" ]; then
  echo "generating self-signed CA + leaf in $TLS"
  mkdir -p "$TLS"; cd "$TLS"
  openssl genrsa -out ca.key 4096 2>/dev/null
  openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -subj "/CN=personas-test-server-ca" -out ca.crt 2>/dev/null
  cat > leaf.cnf <<'EOF'
[req]
distinguished_name = dn
req_extensions = ext
prompt = no
[dn]
CN = 127.0.0.1
[ext]
subjectAltName = @alt
[alt]
IP.1 = 127.0.0.1
DNS.1 = localhost
DNS.2 = host.docker.internal
EOF
  openssl genrsa -out leaf.key 2048 2>/dev/null
  openssl req -new -key leaf.key -out leaf.csr -config leaf.cnf 2>/dev/null
  openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out leaf.crt -days 3650 -sha256 -extfile leaf.cnf -extensions ext 2>/dev/null
  echo "NOTE: copy $TLS/ca.crt -> third_party/libsignal-service-rs/certs/personas-test-server-ca.pem if this is a fresh CA"
fi

# --- Caddyfile ---
cat > "$TLS/Caddyfile" <<EOF
{
	auto_https off
	admin off
}
https://:$LISTEN_PORT {
	tls /certs/leaf.crt /certs/leaf.key
	@storage path /v1/groups* /v2/groups* /v1/storage*
	reverse_proxy @storage http://$STORAGE_UPSTREAM
	reverse_proxy http://$UPSTREAM
}
EOF

docker rm -f "$NAME" >/dev/null 2>&1
echo "starting $NAME: https://127.0.0.1:$LISTEN_PORT -> $UPSTREAM"
docker run -d --name "$NAME" \
  -p "127.0.0.1:$LISTEN_PORT:$LISTEN_PORT" \
  -v "$TLS/leaf.crt:/certs/leaf.crt:ro" \
  -v "$TLS/leaf.key:/certs/leaf.key:ro" \
  -v "$TLS/Caddyfile:/etc/caddy/Caddyfile:ro" \
  "$IMAGE" caddy run --config /etc/caddy/Caddyfile >/dev/null

sleep 2
docker ps --filter "name=$NAME" --format '{{.Names}} {{.Status}} {{.Ports}}'
echo "verify:  curl --cacert $TLS/ca.crt https://127.0.0.1:$LISTEN_PORT/v1/config  (expect 404, TLS OK)"
