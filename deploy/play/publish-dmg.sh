#!/usr/bin/env bash
# Put freshly built Signal Personas .dmgs on the download page.
#
# Run on your Mac, from this directory, after scripts/personas-package.mjs (once per arch):
#   ./publish-dmg.sh ../../Signal-Desktop-Persona-main/release-personas/Signal-Personas-*.dmg
#
# Each file is copied to the VM as download/Signal-Personas-<arch>.dmg (arm64 or x64, the
# stable names the guide links to) through the nexus jump host. Override the hosts with
# PUBLISH_SSH / PUBLISH_JUMP.
set -euo pipefail
cd "$(dirname "$0")"

[[ $# -ge 1 ]] || { echo "usage: ./publish-dmg.sh path/to/Signal-Personas-<version>-<arch>.dmg ..." >&2; exit 1; }
SSH_TARGET="${PUBLISH_SSH:-rthomase@signalserver00.umiacs.umd.edu}"
JUMP="${PUBLISH_JUMP:-rthomase@nexusmc201.umiacs.umd.edu}"
REMOTE_DIR="${PUBLISH_DIR:-/srv/signalserver00/personas/repos/CryptoPersonas_Signal/deploy/play/download}"

for DMG in "$@"; do
  [[ -f "$DMG" ]] || { echo "no such file: $DMG" >&2; exit 1; }
  case "$DMG" in
    *-arm64.dmg) ARCH=arm64 ;;
    *-x64.dmg) ARCH=x64 ;;
    *) echo "cannot tell the architecture of $DMG (expected ...-arm64.dmg or ...-x64.dmg)" >&2; exit 1 ;;
  esac
  NAME="Signal-Personas-$ARCH.dmg"
  # Upload under a temporary name and rename, so nobody downloads a half-copied file.
  scp -J "$JUMP" "$DMG" "$SSH_TARGET:$REMOTE_DIR/.$NAME.part"
  ssh -J "$JUMP" "$SSH_TARGET" "mv '$REMOTE_DIR/.$NAME.part' '$REMOTE_DIR/$NAME' && ls -la '$REMOTE_DIR/$NAME'"
  echo "published $NAME  <-  $(basename "$DMG")"
done
echo "download page: https://signalserver.umiacs.umd.edu/download/"
