#!/usr/bin/env bash
# Local S3-compatible substitute for the test-server's `pagedSingleUseKEMPreKeyStore`
# (PQ one-time-prekey pages are stored in S3 — see docs/FINDINGS.md O13). Nothing else in
# Signal-Server's test-server profile gets a working local stand-in for its S3 dependency
# ("many features are non-functional" per upstream's own docs); this fixes it for the one
# store that's on the hot path of `PUT /v2/keys`, which `receive_messages()` calls in the
# background on every connect.
#
# Runs a MinIO container (via the Colima docker daemon) on 127.0.0.1:9110, using the exact
# static credentials test-server's shared `awsCredentialsProvider` already supplies
# (config/test-secrets-bundle.yml: aws.accessKeyId=accessKey, aws.secretAccessKey=secretAccess)
# — no credential plumbing to change, just an endpoint to point at (patches/0003 does that,
# plus the path-style-addressing source patch a plain localhost endpoint needs).
#
# Usage:  ./minio.sh [up|down|status]   (default: up)
set -uo pipefail

NAME="personas-minio"
# Not 9100: that is Prometheus node_exporter's port, and UMIACS VMs run it (it answers 200 on
# every path, so a MinIO health check against 9100 passes while MinIO is not even running).
PORT="${PORT:-9110}"
BUCKET="prekey-bucket"
ACCESS_KEY="accessKey"
SECRET_KEY="secretAccess"
# MinIO stopped publishing its community images in late 2025: docker.io/minio/minio now
# answers "access denied" and quay.io has no tags, so a machine without a cached copy
# cannot pull it. Bitnami's legacy archive still serves multi-arch builds (amd64 + arm64),
# and its image creates buckets from MINIO_DEFAULT_BUCKETS, so no separate `mc` container.
IMAGE="${MINIO_IMAGE:-docker.io/bitnamilegacy/minio:2025.7.23}"

# Docker via Colima; sidestep the dangling Docker-Desktop credential helper.
HERE="$(cd "$(dirname "$0")" && pwd)"
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

docker rm -f "$NAME" >/dev/null 2>&1
echo "starting $NAME: http://127.0.0.1:$PORT"
docker run -d --name "$NAME" \
  -p "127.0.0.1:$PORT:9000" \
  -e "MINIO_ROOT_USER=$ACCESS_KEY" \
  -e "MINIO_ROOT_PASSWORD=$SECRET_KEY" \
  -e "MINIO_DEFAULT_BUCKETS=$BUCKET" \
  "$IMAGE" >/dev/null || { echo "failed to start $NAME" >&2; exit 1; }

echo "waiting for $NAME to become healthy…"
healthy=0
for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:$PORT/minio/health/live" >/dev/null 2>&1 && { healthy=1; break; }
  sleep 1
done
[[ "$healthy" == 1 ]] || { echo "$NAME never became healthy; see: docker logs $NAME" >&2; exit 1; }

# The image creates the bucket during its own startup, which can trail the health check.
echo "checking bucket $BUCKET"
for _ in $(seq 1 30); do
  docker exec "$NAME" mc ls "local/$BUCKET" >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$NAME" mc ls local/ 2>/dev/null | grep -q "$BUCKET" \
  && echo "bucket $BUCKET: present" \
  || { echo "bucket $BUCKET MISSING — registration will hang ~90s and fail" >&2; exit 1; }

docker ps --filter "name=$NAME" --format '{{.Names}} {{.Status}} {{.Ports}}'
echo "verify:  curl -s http://127.0.0.1:$PORT/minio/health/live -o /dev/null -w '%{http_code}\n'  (expect 200)"
