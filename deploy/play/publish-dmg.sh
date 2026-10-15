#!/usr/bin/env bash
# Put a freshly built Signal Personas .dmg on the download page.
#
# Run on your Mac, from this directory, after scripts/personas-package.mjs:
#   ./publish-dmg.sh ../../Signal-Desktop-Persona-main/release-personas/Signal-Personas-*-arm64.dmg
#
# Copies it to the VM as download/Signal-Personas.dmg (the stable name the guide links to)
# through the nexus jump host. Override the hosts with PUBLISH_SSH / PUBLISH_JUMP.
set -euo pipefail
cd "$(dirname "$0")"

DMG="${1:?usage: ./publish-dmg.sh path/to/Signal-Personas-<version>-arm64.dmg}"
[[ -f "$DMG" ]] || { echo "no such file: $DMG" >&2; exit 1; }
SSH_TARGET="${PUBLISH_SSH:-rthomase@signalserver00.umiacs.umd.edu}"
JUMP="${PUBLISH_JUMP:-rthomase@nexusmc201.umiacs.umd.edu}"
REMOTE_DIR="${PUBLISH_DIR:-/srv/signalserver00/personas/repos/CryptoPersonas_Signal/deploy/play/download}"

# Upload under a temporary name and rename, so nobody downloads a half-copied file.
scp -J "$JUMP" "$DMG" "$SSH_TARGET:$REMOTE_DIR/.Signal-Personas.dmg.part"
ssh -J "$JUMP" "$SSH_TARGET" \
  "mv '$REMOTE_DIR/.Signal-Personas.dmg.part' '$REMOTE_DIR/Signal-Personas.dmg' && ls -la '$REMOTE_DIR/Signal-Personas.dmg'"
echo "published: https://signalserver.umiacs.umd.edu/download/"
