#!/usr/bin/env bash
# Local S3-compatible substitute for the test-server's `pagedSingleUseKEMPreKeyStore`
# (PQ one-time-prekey pages are stored in S3 — see docs/FINDINGS.md O13). Nothing else in
# Signal-Server's test-server profile gets a working local stand-in for its S3 dependency
# ("many features are non-functional" per upstream's own docs); this fixes it for the one
# store that's on the hot path of `PUT /v2/keys`, which `receive_messages()` calls in the
# background on every connect.
#
# Runs a MinIO container (via the Colima docker daemon) on 127.0.0.1:9100, using the exact
# static credentials test-server's shared `awsCredentialsProvider` already supplies
# (config/test-secrets-bundle.yml: aws.accessKeyId=accessKey, aws.secretAccessKey=secretAccess)
# — no credential plumbing to change, just an endpoint to point at (patches/0003 does that,
# plus the path-style-addressing source patch a plain localhost endpoint needs).
#
# Usage:  ./minio.sh [up|down|status]   (default: up)
set -uo pipefail

NAME="personas-minio"
PORT="${PORT:-9100}"
BUCKET="prekey-bucket"
ACCESS_KEY="accessKey"
SECRET_KEY="secretAccess"
IMAGE="minio/minio"
MC_IMAGE="minio/mc"

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
  "$IMAGE" server /data >/dev/null

echo "waiting for $NAME to become healthy…"
for _ in $(seq 1 30); do
  docker exec "$NAME" curl -sf http://127.0.0.1:9000/minio/health/live >/dev/null 2>&1 && break
  sleep 1
done

echo "creating bucket $BUCKET (idempotent)"
docker run --rm --entrypoint sh "$MC_IMAGE" \
  -c "mc alias set local http://host.docker.internal:$PORT $ACCESS_KEY $SECRET_KEY >/dev/null && mc mb --ignore-existing local/$BUCKET"

docker ps --filter "name=$NAME" --format '{{.Names}} {{.Status}} {{.Ports}}'
echo "verify:  curl -s http://127.0.0.1:$PORT/minio/health/live -o /dev/null -w '%{http_code}\n'  (expect 200)"
