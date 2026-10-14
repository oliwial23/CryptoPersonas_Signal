#!/usr/bin/env bash
# Set the shared /play password: writes PLAY_USER and a bcrypt PLAY_PASSWORD_HASH into
# .env (gitignored), which
# `docker compose` reads automatically.
#
#   ./set-password.sh            # prompts
#   ./set-password.sh demo       # username (default: demo)
set -euo pipefail
cd "$(dirname "$0")"
USER_NAME="${1:-demo}"
read -rsp "password for '$USER_NAME': " PW; echo
[[ -n "$PW" ]] || { echo "empty password" >&2; exit 1; }
HASH="$(docker run --rm caddy:2 caddy hash-password --plaintext "$PW")"
touch .env && chmod 600 .env
grep -vE '^(PLAY_USER|PLAY_PASSWORD_HASH)=' .env > .env.tmp || true
# $ in a bcrypt hash would be interpolated by compose; $$ escapes it.
printf 'PLAY_USER=%s\nPLAY_PASSWORD_HASH=%s\n' "$USER_NAME" "${HASH//\$/\$\$}" >> .env.tmp
mv .env.tmp .env
echo "wrote .env — restart the gateway: docker compose up -d gateway"
