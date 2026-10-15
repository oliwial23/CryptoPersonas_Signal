#!/usr/bin/env bash
# Install the personas services as systemd USER units (no root), so the backend, the
# gateway and the directory come back after a reboot of the VM.
#
#   source ~/.bashrc && deploy/systemd/install.sh            # gateway + directory only
#   PERSONAS_PLAY_MEMBERS="alice bob carol" deploy/systemd/install.sh   # plus browser members
#
# Needs the personas env from ~/.bashrc (PERSONAS_SERVER_DEPLOY.md §1) and lingering
# (`loginctl enable-linger $USER`), which lets user units start at boot without a login.
#
# Afterwards:  systemctl --user status 'personas-*'
#              journalctl --user -u personas-chat -f
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

for var in WORK JAVA_HOME SIGNAL_SERVER_DIR STORAGE_SERVICE_DIR SIGNAL_SERVER_SECRETS DOCKER_HOST; do
  [[ -n "${!var:-}" ]] || { echo "$var is not set; run: source ~/.bashrc" >&2; exit 1; }
done
loginctl show-user "$USER" -p Linger 2>/dev/null | grep -q 'Linger=yes' ||
  echo "warning: lingering is off; units will not start until you log in (loginctl enable-linger $USER)" >&2

# Everything the services need, captured from this (already configured) shell.
mkdir -p ~/.config/personas
cat > ~/.config/personas/env <<ENV
WORK=$WORK
JAVA_HOME=$JAVA_HOME
PATH=$JAVA_HOME/bin:$WORK/tools:/usr/local/bin:/usr/bin:/bin
MAVEN_OPTS=$MAVEN_OPTS
SIGNAL_SERVER_DIR=$SIGNAL_SERVER_DIR
STORAGE_SERVICE_DIR=$STORAGE_SERVICE_DIR
SIGNAL_SERVER_SECRETS=$SIGNAL_SERVER_SECRETS
DOCKER_HOST=$DOCKER_HOST
TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=${TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE:-}
TESTCONTAINERS_RYUK_DISABLED=true
TMPDIR=${TMPDIR:-$WORK/tmp}
PERSONAS_PLAY_MEMBERS=${PERSONAS_PLAY_MEMBERS:-}
ENV
chmod 600 ~/.config/personas/env

mkdir -p ~/.config/systemd/user
for unit in "$HERE"/personas-*.service; do
  sed -e "s#@REPO@#$REPO#g" -e "s#@WORK@#$WORK#g" "$unit" > ~/.config/systemd/user/"$(basename "$unit")"
done
systemctl --user daemon-reload
systemctl --user enable personas-minio personas-chat personas-storage personas-play
echo "installed. Stop anything you started by hand first (it holds the same ports), then:"
echo "  systemctl --user start personas-minio personas-chat personas-storage personas-play"
