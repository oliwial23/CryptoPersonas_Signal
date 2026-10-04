#!/usr/bin/env bash
# Plain (non-TLS) reverse proxy in front of the test-server's cleartext :8080 connector,
# for deployments where TLS is terminated *upstream* of this host (e.g. an institutional
# fronting proxy sitting in front of the whole machine) rather than by us. See
# tls-proxy.sh for the self-terminating variant used in local dev, where nothing sits in
# front of us and we have to speak TLS ourselves.
#
# Path-routes /v1/groups*, /v2/groups*, /v1/storage* to the storage-service (:8090);
# everything else to the chat server (:8080) — same routing as tls-proxy.sh, just no TLS.
# Listens on all interfaces (not just loopback): the fronting proxy reaches this over the
# network, not from localhost.
#
# Usage:  ./plain-proxy.sh [up|down|status]   (default: up)
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NAME="personas-plain-proxy"
LISTEN_PORT="${LISTEN_PORT:-8443}"
UPSTREAM="${UPSTREAM:-host.docker.internal:8080}"
STORAGE_UPSTREAM="${STORAGE_UPSTREAM:-host.docker.internal:8090}"
IMAGE="caddy:2"

CFG="$HERE/.local/plain"
mkdir -p "$CFG"

action="${1:-up}"

case "$action" in
  down)   docker rm -f "$NAME" >/dev/null 2>&1 && echo "stopped $NAME" || echo "$NAME not running"; exit 0 ;;
  status) docker ps --filter "name=$NAME" --format '{{.Names}} {{.Status}} {{.Ports}}'; exit 0 ;;
  up)     : ;;
  *)      echo "usage: $0 [up|down|status]" >&2; exit 2 ;;
esac

cat > "$CFG/Caddyfile" <<EOF
{
	auto_https off
	admin off
}
:$LISTEN_PORT {
	@storage path /v1/groups* /v2/groups* /v1/storage*
	reverse_proxy @storage http://$STORAGE_UPSTREAM
	reverse_proxy http://$UPSTREAM
}
EOF

docker rm -f "$NAME" >/dev/null 2>&1
echo "starting $NAME: http://0.0.0.0:$LISTEN_PORT -> $UPSTREAM (chat), $STORAGE_UPSTREAM (groups/storage)"
docker run -d --name "$NAME" \
  --add-host host.docker.internal:host-gateway \
  -p "0.0.0.0:$LISTEN_PORT:$LISTEN_PORT" \
  -v "$CFG/Caddyfile:/etc/caddy/Caddyfile:ro" \
  "$IMAGE" caddy run --config /etc/caddy/Caddyfile >/dev/null

sleep 2
docker ps --filter "name=$NAME" --format '{{.Names}} {{.Status}} {{.Ports}}'
echo "verify (from the VM itself):  curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:$LISTEN_PORT/v1/config   # expect 404 (plain HTTP, no TLS error) = OK"
