#!/usr/bin/env bash
# Smoke-test a running test-server: liveness + the stubbed registration flow
# (session -> noop captcha -> arbitrary code -> verified:true). Proves the server
# is serving and the registration stub behaves. Usage: ./verify.sh [+E164NUMBER]
set -uo pipefail

BASE="${BASE:-http://127.0.0.1:8080}"
ADMIN="${ADMIN:-http://127.0.0.1:8081}"
UA='User-Agent: Signal-Android/7.0.0'
NUM="${1:-+1202555${RANDOM:0:4}}"

echo "# liveness ($ADMIN/ping)"
curl -fsS -m5 "$ADMIN/ping" && echo "  <- pong" || { echo "server not responding"; exit 1; }

echo "# create verification session for $NUM"
S=$(curl -fsS -m8 -X POST "$BASE/v1/verification/session" \
      -H 'Content-Type: application/json' -H "$UA" -d "{\"number\":\"$NUM\"}")
echo "  $S"
ID=$(printf '%s' "$S" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
IDE=$(printf '%s' "$ID" | sed 's/=/%3D/g; s#/#%2F#g; s/+/%2B/g')

echo "# submit noop captcha"
curl -fsS -m8 -X PATCH "$BASE/v1/verification/session/$IDE" \
     -H 'Content-Type: application/json' -H "$UA" \
     -d '{"captcha":"noop.noop.registration.noop"}'; echo

echo "# submit an arbitrary code -> expect \"verified\":true"
curl -fsS -m8 -X PUT "$BASE/v1/verification/session/$IDE/code" \
     -H 'Content-Type: application/json' -H "$UA" -d '{"code":"999999"}'; echo
