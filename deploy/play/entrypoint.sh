#!/usr/bin/env bash
# Container entrypoint: one demo member (Signal-Persona Desktop) on a virtual display,
# exported over noVNC on :6080.
#
# Env:
#   PERSONAS_INSTANCE   member name, e.g. alice (required)
#   PERSONAS_NUMBER     phone number to auto-register as (required), e.g. +12025550001
#   PERSONAS_SERVER_URL backend the client talks to (default: the UMIACS public endpoint)
#   PERSONAS_CA_FILE    PEM of a private CA, only if PERSONAS_SERVER_URL is NOT publicly
#                       trusted. Node's `ca` REPLACES the trust store, so never set it for
#                       the public endpoint.
#   PERSONAS_RESET=1    wipe this member's userData first (needed after a backend reset)
#   SCREEN_GEOMETRY     Xvfb size (default 1440x900x24)
set -euo pipefail

: "${PERSONAS_INSTANCE:?set PERSONAS_INSTANCE}"
: "${PERSONAS_NUMBER:?set PERSONAS_NUMBER}"
SERVER_URL="${PERSONAS_SERVER_URL:-https://signalserver.umiacs.umd.edu}"
GEOMETRY="${SCREEN_GEOMETRY:-1440x900x24}"
APP=/app
CONFIG_DIR="$APP/config"
USER_DATA="$HOME/.config/Signal-development-$PERSONAS_INSTANCE"

# --- client config (same shape personas-demo-setup.sh writes on a laptop) -------------
CA_JSON=null
if [[ -n "${PERSONAS_CA_FILE:-}" ]]; then
  CA_JSON="$(jq -Rs . < "$PERSONAS_CA_FILE")"
fi
jq -n \
  --arg url "$SERVER_URL" \
  --arg params "$(cat "$CONFIG_DIR/.server-public-params")" \
  --argjson ca "$CA_JSON" \
  '{
     serverUrl: $url, storageUrl: $url,
     cdn: { "0": $url, "2": $url, "3": $url },
     serverTrustRoots: ["BS/lfaNHzWJDFSjarF+7KQcw//aEr8TPwu2QmV9Yyzt0"],
     serverPublicParams: $params,
     openDevTools: false
   } + (if $ca == null then {} else { certificateAuthority: $ca } end)' \
  > "$CONFIG_DIR/local-development.json"
echo "{\"storageProfile\": \"development-$PERSONAS_INSTANCE\"}" \
  > "$CONFIG_DIR/local-development-$PERSONAS_INSTANCE.json"

if [[ "${PERSONAS_RESET:-0}" == "1" && -d "$USER_DATA" ]]; then
  echo "reset: removing $USER_DATA"
  rm -rf "$USER_DATA"
fi

# --- display + VNC ---------------------------------------------------------------------
rm -f /tmp/.X1-lock /tmp/.X11-unix/X1
Xvfb :1 -screen 0 "$GEOMETRY" -nolisten tcp &
for _ in $(seq 50); do [[ -e /tmp/.X11-unix/X1 ]] && break; sleep 0.1; done
openbox &
# No VNC password: the gateway (Caddy basic_auth) is the access control, and :5900 is
# bound to localhost so only websockify in this container can reach it.
x11vnc -display :1 -localhost -forever -shared -nopw -quiet -rfbport 5900 &
websockify --web /usr/share/novnc 6080 localhost:5900 &

# --- the app -----------------------------------------------------------------------------
# Same env personas-run.sh sets; see the comments there for why each one exists.
export NODE_ENV=development
export NODE_APP_INSTANCE="$PERSONAS_INSTANCE"
export PERSONAS_AUTO_REGISTER="$PERSONAS_NUMBER"
export PERSONAS_SKIP_EMPTY_QUEUE_WAIT="${PERSONAS_SKIP_EMPTY_QUEUE_WAIT:-1}"
export PERSONAS_FORCE_ACCESS_KEYS="${PERSONAS_FORCE_ACCESS_KEYS:-0}"
mkdir -p "$PERSONAS_ROSTER_DIR" "$PERSONAS_KEYS_DIR"

cat <<EOF
personas-play: $PERSONAS_INSTANCE ($PERSONAS_NUMBER)
  server     $SERVER_URL
  roster     $PERSONAS_ROSTER_DIR
  keys       $PERSONAS_KEYS_DIR
  userData   $USER_DATA
EOF

# Proving keys: exactly ONE member may generate them. ensure_merkle_keys draws fresh
# random keys whenever the file is missing, so members booting together on an empty
# keys volume would each keep a different key set in memory and reject each other's
# proofs. The leader (alice) generates; everyone else waits for the finished file,
# which is published by rename, so its existence means it is complete.
KEYS_FILE="$PERSONAS_KEYS_DIR/params/serverless-merkle/merkle_groth16_keys.bin"
if [[ "${PERSONAS_KEYGEN_LEADER:-0}" != "1" ]]; then
  waited=0
  until [[ -s "$KEYS_FILE" ]]; do
    (( waited % 30 == 0 )) && echo "waiting for the keygen leader to publish $KEYS_FILE (${waited}s)"
    sleep 5; waited=$((waited + 5))
  done
fi

cd "$APP"
# Relaunch if the app exits (e.g. the user picks Quit), so the slot never goes dead.
while true; do
  dbus-launch --exit-with-session ./node_modules/.bin/electron . --no-sandbox || true
  echo "electron exited; restarting in 3s"
  sleep 3
done
