#!/usr/bin/env bash
# Generate the canonical Groth16 proving keys once, on the server, and pin them.
#
# Installed clients (and the browser members, once pinned) download these from the
# gateway at /personas/keys/merkle_groth16_keys.bin and accept them only if their SHA-256
# matches PERSONAS_KEYS_SHA256. This script:
#   1. generates the keys into the compose `keys` volume (only if absent),
#   2. prints their SHA-256 and writes it to .env as PERSONAS_KEYS_SHA256.
#
# TRUST: whoever generates these keys could forge proofs. Running this on the server puts
# that trust in one known place. Re-running it never regenerates existing keys, unless you
# ask for a new set with --new (every client must then be updated with the new hash —
# needed whenever the circuits change, e.g. protocol version 3 added the join and reset
# proofs).
#
#   ./keys.sh          # generate if absent, then pin
#   ./keys.sh --new    # replace the keys with a freshly generated set, then pin
set -euo pipefail
cd "$(dirname "$0")"

VOLUME="${COMPOSE_PROJECT_NAME:-play}_keys"
IMAGE="${PERSONAS_IMAGE:-personas-play}"
KEYS="/shared/keys/params/serverless-merkle/merkle_groth16_keys.bin"

docker volume inspect "$VOLUME" >/dev/null 2>&1 || docker volume create "$VOLUME" >/dev/null

if [[ "${1:-}" == "--new" ]]; then
  echo "removing the old proving keys from volume $VOLUME (a new set follows)..."
  docker run --rm -v "$VOLUME:/shared/keys" --entrypoint rm "$IMAGE" -f "$KEYS"
fi

if ! docker run --rm -v "$VOLUME:/shared/keys" --entrypoint test "$IMAGE" -s "$KEYS"; then
  echo "generating the proving keys into volume $VOLUME (one-time)..."
  docker run --rm -v "$VOLUME:/shared/keys" --entrypoint node "$IMAGE" \
    -e "new (require('/app/packages/personas-engine/index.cjs').Engine)({ dataDir: '/shared/keys', member: false })"
fi

SHA="$(docker run --rm -v "$VOLUME:/shared/keys" --entrypoint sha256sum "$IMAGE" "$KEYS" | cut -d' ' -f1)"
[[ "$SHA" =~ ^[0-9a-f]{64}$ ]] || { echo "could not hash the keys" >&2; exit 1; }

touch .env && chmod 600 .env
grep -v '^PERSONAS_KEYS_SHA256=' .env > .env.tmp || true
echo "PERSONAS_KEYS_SHA256=$SHA" >> .env.tmp
mv .env.tmp .env

echo "proving keys: $SHA"
echo "pinned in .env. Recreate the gateway and members to use it:"
echo "  docker compose up -d --force-recreate gateway alice bob carol"
