#!/usr/bin/env bash
# Local Cloud Bigtable emulator for the storage-service (groups backend) — pure
# Java/Maven, NO gcloud / cbt / Docker / Python.
#
# Uses the emulator bundled in the storage-service's own google-cloud-bigtable-
# emulator dependency. We resolve the repo's classpath (compile + test scope, so
# the test-scoped emulator dep is included), compile EmulatorMain.java against it,
# and run it: it starts the emulator on a free port, creates the four tables, and
# writes 127.0.0.1:<port> to .local/bigtable-emulator-host (boot.sh reads it into
# BIGTABLE_EMULATOR_HOST). The storage-service's Bigtable client auto-targets the
# emulator when that env var is set.
#
# Prereq: Java 25 + the storage-service repo (same as boot.sh). No other installs.
#
# Usage: ./bigtable.sh [up|down|status]   (default: up)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL="$HERE/.local"
STORAGE_SERVICE_DIR="${STORAGE_SERVICE_DIR:-$HOME/Repos/personas2/storage-service}"

HOSTFILE="$LOCAL/bigtable-emulator-host"
PIDFILE="$LOCAL/bigtable-emulator.pid"
LOGFILE="$LOCAL/bigtable-emulator.log"
CPFILE="$LOCAL/classpath.txt"
CLASSESDIR="$LOCAL/classes"

mkdir -p "$LOCAL" "$CLASSESDIR"

emulator_running() {
  [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

up() {
  [ -d "$STORAGE_SERVICE_DIR" ] || { echo "storage-service repo not found at $STORAGE_SERVICE_DIR (set STORAGE_SERVICE_DIR)"; exit 1; }

  if emulator_running; then
    echo "bigtable emulator already running (pid $(cat "$PIDFILE")): $(cat "$HOSTFILE" 2>/dev/null)"
    return
  fi

  # 1. Resolve the storage-service's dependency classpath incl. the test-scoped
  #    emulator (one-time large download on first run, like the chat server).
  echo "resolving storage-service classpath ..."
  ( cd "$STORAGE_SERVICE_DIR" && ./mvnw -q dependency:build-classpath \
      -DincludeScope=test -Dmdep.outputFile="$CPFILE" )
  local cp
  cp="$(cat "$CPFILE")"

  # 2. Compile the launcher against it.
  echo "compiling EmulatorMain ..."
  javac -cp "$cp" -d "$CLASSESDIR" "$HERE/EmulatorMain.java"

  # 3. Run it (background); it writes host:port to HOSTFILE and blocks.
  rm -f "$HOSTFILE"
  echo "starting bigtable emulator ..."
  nohup java -cp "$CLASSESDIR:$cp" EmulatorMain "$HOSTFILE" >"$LOGFILE" 2>&1 &
  echo $! >"$PIDFILE"

  for _ in $(seq 1 60); do
    [ -s "$HOSTFILE" ] && break
    if ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "emulator process exited early; see $LOGFILE"; tail -20 "$LOGFILE"; exit 1
    fi
    sleep 0.5
  done
  [ -s "$HOSTFILE" ] || { echo "emulator did not report a port in time; see $LOGFILE"; exit 1; }

  echo "bigtable emulator up: $(cat "$HOSTFILE") (pid $(cat "$PIDFILE"))"
  grep -E "created table|already exists" "$LOGFILE" || true
}

down() {
  if emulator_running; then
    kill "$(cat "$PIDFILE")" 2>/dev/null || true
    rm -f "$PIDFILE" "$HOSTFILE"
    echo "bigtable emulator stopped"
  else
    echo "bigtable emulator not running"
  fi
}

status() {
  if emulator_running; then
    echo "running (pid $(cat "$PIDFILE")): $(cat "$HOSTFILE" 2>/dev/null)"
  else
    echo "not running"
  fi
}

case "${1:-up}" in
  up) up ;;
  down) down ;;
  status) status ;;
  *) echo "usage: $0 [up|down|status]"; exit 1 ;;
esac
