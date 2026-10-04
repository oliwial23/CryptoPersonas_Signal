#!/usr/bin/env bash
# Boot the Signal storage-service (groups backend) for the personas test server.
#
# Serves /v1/groups + /v2/groups (and the contacts StorageController) on :8090,
# backed by the local Bigtable emulator. The test-server Caddy proxy path-routes
# these endpoints from :8443 here, so Desktop's storageUrl (already 127.0.0.1:8443)
# reaches it with no client change.
#
# The zkgroup ServerSecretParams is pulled from the CHAT server's own secrets
# bundle so the two services cannot drift — group-auth credentials the chat server
# issues verify here, and Desktop's serverPublicParams already derives from it.
#
# Prereqs (no gcloud/Docker/Python needed — the emulator is pure Java/Maven):
#   - Java 25 active (Temurin 25 — same as the chat test server). `java -version` = 25.
#   - The storage-service repo + the Signal-Server repo cloned (paths below).
#
# Usage: ./boot.sh        (Ctrl-C to stop; run bigtable.sh down separately)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL="$HERE/.local"
mkdir -p "$LOCAL"

STORAGE_SERVICE_DIR="${STORAGE_SERVICE_DIR:-$HOME/Repos/personas2/storage-service}"
SIGNAL_SERVER_SECRETS="${SIGNAL_SERVER_SECRETS:-$HOME/Repos/Signal-Server/service/src/test/resources/config/test-secrets-bundle.yml}"

[ -d "$STORAGE_SERVICE_DIR" ] || { echo "storage-service repo not found at $STORAGE_SERVICE_DIR (set STORAGE_SERVICE_DIR)"; exit 1; }
[ -f "$SIGNAL_SERVER_SECRETS" ] || { echo "Signal-Server secrets not found at $SIGNAL_SERVER_SECRETS (set SIGNAL_SERVER_SECRETS)"; exit 1; }

# 1. Pull the chat server's groups zkgroup secret (single source of truth).
SECRET="$(grep -E '^zkConfig-libsignal-0\.42\.serverSecret:' "$SIGNAL_SERVER_SECRETS" | sed 's/^[^:]*:[[:space:]]*//')"
[ -n "$SECRET" ] || { echo "could not read zkConfig-libsignal-0.42.serverSecret from $SIGNAL_SERVER_SECRETS"; exit 1; }

# 2. Render config.yml with the secret injected ('|' delimiter — base64 has no '|').
sed "s|__ZK_SERVER_SECRET__|$SECRET|" "$HERE/config.yml.template" > "$LOCAL/config.yml"
echo "rendered $LOCAL/config.yml (zkgroup secret injected from chat server)"

# 3. Ensure the Bigtable emulator is up and the tables exist (pure Java/Maven).
"$HERE/bigtable.sh" up
BIGTABLE_EMULATOR_HOST_VALUE="$(cat "$LOCAL/bigtable-emulator-host")"
[ -n "$BIGTABLE_EMULATOR_HOST_VALUE" ] || { echo "no emulator host reported; see bigtable emulator log"; exit 1; }

# 4. Run the storage-service against the emulator (thin jar → Maven exec:java).
export BIGTABLE_EMULATOR_HOST="$BIGTABLE_EMULATOR_HOST_VALUE"
echo "starting storage-service on :8090 (BIGTABLE_EMULATOR_HOST=$BIGTABLE_EMULATOR_HOST)"
cd "$STORAGE_SERVICE_DIR"
exec ./mvnw -q compile exec:java \
  -Dexec.mainClass=org.signal.storageservice.StorageService \
  -Dexec.args="server $LOCAL/config.yml"
