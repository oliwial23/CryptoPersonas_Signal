#!/usr/bin/env bash
# Boot a private, isolated Signal-Server in upstream "test-server" mode (see
# README.md). Fully local: stubbed registration, throwaway datastores spun up by
# Testcontainers, no production Signal. Runs in the foreground and BLOCKS while
# serving — Ctrl-C to stop. Everything is ephemeral: re-register accounts each boot.
#
# Env overrides:
#   SIGNAL_SERVER_DIR   path to the Signal-Server checkout (default ~/Repos/Signal-Server)
#   FDB_C_DYLIB         path to libfdb_c.dylib (default ./.local/libfdb_c.dylib; macOS)
#   JAVA_HOME           JDK 25 home (default: /usr/libexec/java_home -v 25 on macOS)
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SIGNAL_SERVER_DIR="${SIGNAL_SERVER_DIR:-$HOME/Repos/Signal-Server}"
FDB_C_DYLIB="${FDB_C_DYLIB:-$HERE/.local/libfdb_c.dylib}"

# --- JDK 25 ---
if [ -z "${JAVA_HOME:-}" ] && [ -x /usr/libexec/java_home ]; then
  JAVA_HOME="$(/usr/libexec/java_home -v 25 2>/dev/null || true)"
fi
[ -n "${JAVA_HOME:-}" ] && export JAVA_HOME
export PATH="${JAVA_HOME:+$JAVA_HOME/bin:}/opt/homebrew/bin:/usr/local/bin:$PATH"

# --- Docker runtime (Colima). Skip these if you use another daemon whose socket
#     is already the default. Testcontainers needs to find the socket. ---
if [ -S "$HOME/.colima/default/docker.sock" ] && [ -z "${DOCKER_HOST:-}" ]; then
  export DOCKER_HOST="unix://$HOME/.colima/default/docker.sock"
fi
export TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE="${TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE:-/var/run/docker.sock}"

# --- FoundationDB host client lib (macOS): point fdb-java at our extracted arm64
#     dylib. JAVA_TOOL_OPTIONS so the property reaches the forked exec:java JVM.
#     On Linux, libfdb_c.so is on the loader path already, so we skip this. ---
if [ -f "$FDB_C_DYLIB" ]; then
  export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:-} -DFDB_LIBRARY_PATH_FDB_C=$FDB_C_DYLIB"
elif [ "$(uname -s)" = "Darwin" ]; then
  echo "!! $FDB_C_DYLIB missing — run ./setup-fdb-client.sh first" >&2; exit 1
fi

if [ ! -x "$SIGNAL_SERVER_DIR/mvnw" ]; then
  echo "!! Signal-Server not found at $SIGNAL_SERVER_DIR (set SIGNAL_SERVER_DIR)" >&2; exit 1
fi

# --- personas patches (see patches/README) ---
# Apply our test-server modifications idempotently. Currently: allow the authenticated
# /v1/websocket/ to UPGRADE with unresolved credentials (return empty instead of 403) so
# presage can register — the account does not exist yet at that point. Without this the
# e2 A1 send/receive wiring cannot register an account. Isolated single-tenant server only.
for patch in "$HERE"/patches/*.patch; do
  [ -f "$patch" ] || continue
  if git -C "$SIGNAL_SERVER_DIR" apply --reverse --check "$patch" >/dev/null 2>&1; then
    echo "patch already applied: $(basename "$patch")"
  elif git -C "$SIGNAL_SERVER_DIR" apply --check "$patch" >/dev/null 2>&1; then
    git -C "$SIGNAL_SERVER_DIR" apply "$patch" && echo "applied patch: $(basename "$patch")"
  else
    echo "!! patch does not apply cleanly (already modified?): $(basename "$patch")" >&2
  fi
done

echo "SIGNAL_SERVER_DIR = $SIGNAL_SERVER_DIR"
echo "JAVA_HOME         = ${JAVA_HOME:-<unset>}"
echo "FDB_C_DYLIB       = $FDB_C_DYLIB"
echo "DOCKER_HOST       = ${DOCKER_HOST:-<default>}"
echo "Booting test-server (Ctrl-C to stop). First run downloads a large maven tree (one-time)."
cd "$SIGNAL_SERVER_DIR"
chmod +x ./mvnw
exec ./mvnw integration-test -Ptest-server -DskipTests=true
