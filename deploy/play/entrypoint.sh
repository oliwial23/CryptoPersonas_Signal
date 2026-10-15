#!/usr/bin/env bash
# Container entrypoint: one demo member (Signal-Persona Desktop) on a virtual display,
# exported over noVNC on :6080.
#
# Env:
#   PERSONAS_INSTANCE   member name, e.g. alice (required)
#   PERSONAS_NUMBER     phone number to auto-register as (required), e.g. +12025550001
#   PERSONAS_UPSTREAM   host:port of the backend gateway (default gateway:8443, plain HTTP)
#   PERSONAS_UPSTREAM_TLS=1  dial the upstream over TLS instead, e.g. for
#                       PERSONAS_UPSTREAM=signalserver.umiacs.umd.edu:443
#   PERSONAS_KEYS_SHA256  pin of the server's proving keys (keys.sh): the app downloads
#                       and verifies them; without it, alice generates a shared set
#   PERSONAS_RESET=1    wipe this member's userData first (needed after a backend reset)
#   SCREEN_GEOMETRY     Xvfb size (default 1440x900x24)
set -euo pipefail

: "${PERSONAS_INSTANCE:?set PERSONAS_INSTANCE}"
: "${PERSONAS_NUMBER:?set PERSONAS_NUMBER}"
UPSTREAM="${PERSONAS_UPSTREAM:-gateway:8443}"
GEOMETRY="${SCREEN_GEOMETRY:-1440x900x24}"
APP=/app
CONFIG_DIR="$APP/config"
USER_DATA="$HOME/.config/Signal-development-$PERSONAS_INSTANCE"

# --- local TLS relay ---------------------------------------------------------------------
# The client MUST see its server as https://127.0.0.1:<port> with a private CA: that is
# the only shape libsignal-net accepts for a self-hosted server. Anything else (e.g. the
# public https://signalserver.umiacs.umd.edu) silently selects PRODUCTION Signal.
# tls-relay.js terminates TLS on localhost and forwards to the gateway.
RELAY_PORT=8443
TLS_DIR="$HOME/.personas-tls"
if [[ ! -s "$TLS_DIR/leaf.pem" ]]; then
  mkdir -p "$TLS_DIR" && chmod 700 "$TLS_DIR"
  (
    cd "$TLS_DIR"
    # rustls (inside libsignal) wants a proper v3 CA and a non-CA leaf with SANs.
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -keyout ca.key -out ca.pem \
      -subj "/CN=personas-play-$PERSONAS_INSTANCE-ca" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
    openssl req -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr -subj "/CN=localhost" 2>/dev/null
    printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n' > leaf.ext
    openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 \
      -extfile leaf.ext -out leaf.pem 2>/dev/null
    rm -f leaf.csr leaf.ext ca.srl
  )
fi
node /usr/local/lib/personas/tls-relay.js "$RELAY_PORT" "$UPSTREAM" "$TLS_DIR" \
  ${PERSONAS_UPSTREAM_TLS:+--upstream-tls} &
for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/$RELAY_PORT) 2>/dev/null && break; sleep 0.1; done

# --- client config (same shape personas-demo-setup.sh writes on a laptop) -------------
SERVER_URL="https://127.0.0.1:$RELAY_PORT"
jq -n \
  --arg url "$SERVER_URL" \
  --arg params "$(cat "$CONFIG_DIR/.server-public-params")" \
  --arg ca "$(cat "$TLS_DIR/ca.pem")" \
  '{
     serverUrl: $url, storageUrl: $url,
     cdn: { "0": $url, "2": $url, "3": $url },
     certificateAuthority: $ca,
     serverTrustRoots: ["BS/lfaNHzWJDFSjarF+7KQcw//aEr8TPwu2QmV9Yyzt0"],
     serverPublicParams: $params,
     openDevTools: false
   }' \
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
mkdir -p "$PERSONAS_KEYS_DIR"

cat <<EOF
personas-play: $PERSONAS_INSTANCE ($PERSONAS_NUMBER)
  server     $SERVER_URL (relay -> $UPSTREAM)
  discovery  member directory (via the relay)
  keys       $PERSONAS_KEYS_DIR
  userData   $USER_DATA
EOF

# Proving keys: exactly ONE member may generate them. ensure_merkle_keys draws fresh
# random keys whenever the file is missing, so members booting together on an empty
# keys volume would each keep a different key set in memory and reject each other's
# proofs. The leader (alice) generates; everyone else waits for the finished file,
# which is published by rename, so its existence means it is complete.
KEYS_FILE="$PERSONAS_KEYS_DIR/params/serverless-merkle/merkle_groth16_keys.bin"
if [[ -n "${PERSONAS_KEYS_SHA256:-}" ]]; then
  # Pinned keys (keys.sh): the app downloads them from the gateway and verifies the hash
  # itself (ts/services/personasKeys.preload.ts), into a folder of its own -- exactly what
  # an installed client does. No leader, no waiting on the shared volume.
  export PERSONAS_KEYS_DIR="$HOME/.personas-keys"
  mkdir -p "$PERSONAS_KEYS_DIR"
  echo "proving keys: downloaded by the app, pinned to ${PERSONAS_KEYS_SHA256:0:12}..."
elif [[ "${PERSONAS_KEYGEN_LEADER:-0}" == "1" && ! -s "$KEYS_FILE" ]]; then
  # Generate them HERE, before the app starts. Inside the app, keygen is a side effect of
  # building the ZK engine, and the engine now waits for the phantom bundle -- which only
  # exists once this member creates a group, which needs the other members to be up,
  # which needs these keys. Building a throwaway observer engine runs the same keygen
  # (ensure_merkle_keys) and publishes the file the others are waiting for.
  echo "generating the shared proving keys into $PERSONAS_KEYS_DIR"
  node -e "new (require('$APP/packages/personas-engine/index.cjs').Engine)({ dataDir: process.env.PERSONAS_KEYS_DIR, member: false })"
fi
if [[ -z "${PERSONAS_KEYS_SHA256:-}" && "${PERSONAS_KEYGEN_LEADER:-0}" != "1" ]]; then
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
