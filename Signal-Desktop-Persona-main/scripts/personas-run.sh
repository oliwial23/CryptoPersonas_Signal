#!/usr/bin/env bash
# Copyright 2026 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#
# Launch one demo instance with the env the personas stack expects.
#
# Usage:
#   ./scripts/personas-run.sh alice        # one terminal per member
#   ./scripts/personas-run.sh bob
#   ./scripts/personas-run.sh carol
#
# All members MUST share one roster dir and one keys dir:
#
#   PERSONAS_ROSTER_DIR  how instances discover each other without CDSI (which is
#                        disabled in localTestServer mode), and how they share the
#                        phantom bundle and the barrier schedule. Different roster dirs
#                        means they cannot see each other at all.
#   PERSONAS_KEYS_DIR    the ~51MB Groth16 proving keys. All members must prove against
#                        an IDENTICAL key set or every proof is rejected on ingest.
#
# PERSONAS_AUTO_REGISTER is the phone number this instance registers as, and is also
# the flag that turns the whole demo path on (see isPersonasEngineEnabled).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

RESET=0
NO_PERSONAS=0
ARGS=()
for a in "$@"; do
  case "$a" in
    --reset) RESET=1 ;;
    --no-personas) NO_PERSONAS=1 ;;
    *) ARGS+=("$a") ;;
  esac
done
set -- "${ARGS[@]+"${ARGS[@]}"}"

INSTANCE="${1:-}"
if [[ -z "$INSTANCE" ]]; then
  cat >&2 <<'EOF'
usage: personas-run.sh <instance> [--reset] [--no-personas]

  <instance>      alice | bob | carol | dave | erin, or a name plus an explicit
                  number: personas-run.sh frank +12025550006
  --reset         Delete this instance's userData first, forcing a fresh
                  auto-registration.
  --no-personas   Run plain Signal Desktop on this account: no ZK engine, no
                  proving, no barrier ticker. The control case for diagnosing a
                  crash — if it still happens, the personas code is not the cause.
                  Requires an already-registered userData; do not use with --reset.

Use --reset whenever the backend has been restarted, or when the client boots
into an account you did not expect. Registration only runs when Desktop has
never registered in that userData dir, so a stale directory silently keeps an
old identity no matter what the config now says.
EOF
  exit 2
fi

# Phone numbers matching PERSONAS_DEMO.md §7. Add more here to run more members.
case "$INSTANCE" in
  alice) NUMBER="+12025550001" ;;
  bob)   NUMBER="+12025550002" ;;
  carol) NUMBER="+12025550003" ;;
  dave)  NUMBER="+12025550004" ;;
  erin)  NUMBER="+12025550005" ;;
  *)
    # Allow an explicit number for ad-hoc members: personas-run.sh frank +12025550006
    NUMBER="${2:-}"
    if [[ -z "$NUMBER" ]]; then
      echo "unknown instance '$INSTANCE' — pass a number: $0 $INSTANCE +1202555XXXX" >&2
      exit 2
    fi
    ;;
esac

CONFIG="$REPO/config/local-development-${INSTANCE}.json"
BASE_CONFIG="$REPO/config/local-development.json"

if [[ ! -f "$BASE_CONFIG" ]]; then
  echo "ERROR: $BASE_CONFIG missing. Run ./scripts/personas-demo-setup.sh first." >&2
  exit 1
fi
if [[ ! -f "$CONFIG" ]]; then
  echo "ERROR: $CONFIG missing." >&2
  echo "Run: ./scripts/personas-demo-setup.sh --instances $INSTANCE" >&2
  exit 1
fi

# `pnpm start` is bare `electron .`, which runs whatever is ALREADY built — it does not
# build anything. package.json's "main" is bundles/main.js, so with no bundle Electron
# fails with "Unable to find Electron app" / "Cannot find module .../bundles/main.js",
# which says nothing about the actual cause. Catch it here instead.
if [[ ! -f "$REPO/bundles/main.js" ]]; then
  cat >&2 <<EOF
ERROR: the app has not been built — $REPO/bundles/main.js is missing.

'pnpm start' only launches Electron against an existing bundle. Build it first:

  pnpm install        # if you have not already
  pnpm run build:dev  # codegen (protobufs, locales, styles) + the rolldown bundle

That takes a few minutes the first time. Afterwards, for TypeScript-only changes,
'pnpm run build:rolldown' is much faster because it skips codegen.
EOF
  exit 1
fi

# Fail fast on the placeholder rather than letting Electron start and die on a TLS
# handshake with a confusing error.
if grep -q 'REPLACE_ME' "$BASE_CONFIG"; then
  echo "ERROR: certificateAuthority in $BASE_CONFIG is still a placeholder." >&2
  echo "Boot the TLS proxy (./tls-proxy.sh up), then re-run:" >&2
  echo "  ./scripts/personas-demo-setup.sh" >&2
  exit 1
fi

# userData location, mirroring app/user_config.main.ts: a storageProfile becomes
# <appData>/Signal-<storageProfile>. This is what must be wiped to force a fresh
# registration — the config alone cannot do it, because a registered account lives in
# here and `Registration.everDone()` short-circuits auto-register.
STORAGE_PROFILE="$(python3 -c "import json,sys; print(json.load(open('$CONFIG'))['storageProfile'])")"
case "$(uname -s)" in
  Darwin) APPDATA="$HOME/Library/Application Support" ;;
  Linux)  APPDATA="${XDG_CONFIG_HOME:-$HOME/.config}" ;;
  *)      APPDATA="$HOME/.config" ;;
esac
USER_DATA="$APPDATA/Signal-$STORAGE_PROFILE"

if [[ "$RESET" == "1" ]]; then
  # Guard hard. "$APPDATA/Signal" with no suffix is the REAL Signal Desktop install;
  # deleting it would destroy the user's actual account and message history. Only ever
  # remove a path with the Signal-<profile> suffix.
  if [[ -z "$STORAGE_PROFILE" || "$USER_DATA" == "$APPDATA/Signal" || "$USER_DATA" != "$APPDATA/Signal-"* ]]; then
    echo "REFUSING to reset: '$USER_DATA' is not a Signal-<profile> demo directory." >&2
    exit 1
  fi
  if [[ -d "$USER_DATA" ]]; then
    echo "Resetting userData: $USER_DATA"
    rm -rf "$USER_DATA"
  else
    echo "Nothing to reset (no $USER_DATA)"
  fi
fi

# ---------------------------------------------------------------------------
# Pre-flight: is there enough memory to launch another Electron instance?
#
# A Signal instance needs roughly 1 GB across its main/renderer/GPU/utility
# processes, plus this demo holds a ~51 MB proving-key set resident per instance. When
# the machine is short, macOS's jetsam kills the new RENDERER and Electron reports only
# "Render process is gone / Exit Code: 9" — a SIGKILL with no cause attached, no stack,
# and no crash report. That message has had five unrelated root causes on this project,
# so it is worth almost nothing as a diagnostic and has cost days.
#
# Checking here turns that into an immediate, named answer BEFORE a 200-line boot log.
# Override with PERSONAS_SKIP_MEM_CHECK=1 if you want to try anyway.
# ---------------------------------------------------------------------------
if [[ "${PERSONAS_SKIP_MEM_CHECK:-}" != "1" ]] && command -v vm_stat >/dev/null 2>&1; then
  mem_report="$(python3 - <<'PYMEM' 2>/dev/null || true
import re, subprocess
vm = subprocess.check_output(["vm_stat"], text=True)
page = int(re.search(r"page size of (\d+)", vm).group(1))
def pages(label):
    m = re.search(rf"{label}:\s+(\d+)", vm)
    return int(m.group(1)) if m else 0
free_gb = (pages("Pages free") + pages("Pages speculative")) * page / 1024**3
swap = subprocess.check_output(["sysctl", "-n", "vm.swapusage"], text=True)
m = re.search(r"total = ([\d.]+)M.*used = ([\d.]+)M", swap)
total, used = (float(m.group(1)), float(m.group(2))) if m else (0.0, 0.0)
pct = (100 * used / total) if total else 0.0
# Tight = under ~1.2 GB free, or swap over 80% full. Either alone is enough to get a
# fresh renderer killed.
tight = free_gb < 1.2 or pct > 80
print(f"{free_gb:.2f}|{used/1024:.1f}|{total/1024:.1f}|{pct:.0f}|{int(tight)}")
PYMEM
)"
  if [[ -n "$mem_report" ]]; then
    IFS='|' read -r MEM_FREE SWAP_USED SWAP_TOTAL SWAP_PCT MEM_TIGHT <<< "$mem_report"
    if [[ "${MEM_TIGHT:-0}" == "1" ]]; then
      cat >&2 <<EOF

!! NOT ENOUGH MEMORY to safely launch another Signal instance.

   free RAM   ${MEM_FREE} GB
   swap       ${SWAP_USED} GB used of ${SWAP_TOTAL} GB (${SWAP_PCT}% full)

   An instance needs ~1 GB. Launching now will most likely end with
   "Render process is gone / Exit Code: 9" — macOS killing the new renderer.
   That is not a bug in this repo and no code change fixes it.

   Biggest wins, usually:
     * quit VS Code (several hundred MB per renderer, plus any language-server JVMs)
     * quit other Electron apps and browsers
     * close any VM / container runtime you are not using
     * run fewer instances: the demo works with two

   See what is actually holding memory:
     ps -Ao rss,pid,comm -m | head -20

   To launch anyway:  PERSONAS_SKIP_MEM_CHECK=1 $0 $INSTANCE${RESET:+ --reset}

EOF
      exit 1
    fi
    echo "memory      ${MEM_FREE} GB free, swap ${SWAP_PCT}% full"
  fi
fi

export NODE_ENV=development
export NODE_APP_INSTANCE="$INSTANCE"
export PERSONAS_AUTO_REGISTER="$NUMBER"

if [[ "$NO_PERSONAS" == "1" ]]; then
  # The engine is enabled by the PRESENCE of PERSONAS_KEYS_DIR or
  # PERSONAS_AUTO_REGISTER (see isPersonasEngineEnabled). Clearing both gives a plain
  # Signal Desktop on the same account and bundle: no engine construction, no proving,
  # no barrier ticker, no scan loop. It is the control case — if a crash still happens
  # here, nothing in the personas integration can be responsible for it.
  unset PERSONAS_AUTO_REGISTER
  unset PERSONAS_KEYS_DIR
  unset PERSONAS_ROSTER_DIR
  cat <<EOF
Starting instance: $INSTANCE   [PERSONAS DISABLED — control run]
  userData    $USER_DATA

The ZK engine will not be constructed. Auto-registration is off too, so this only
works on a userData that is ALREADY registered — do not combine with --reset.
EOF
else
  export PERSONAS_ROSTER_DIR="${PERSONAS_ROSTER_DIR:-/tmp/personas-roster}"
  export PERSONAS_KEYS_DIR="${PERSONAS_KEYS_DIR:-$HOME/.personas-demo-keys}"

  mkdir -p "$PERSONAS_ROSTER_DIR" "$PERSONAS_KEYS_DIR"

  cat <<EOF
Starting personas demo instance: $INSTANCE
  number      $PERSONAS_AUTO_REGISTER
  userData    $USER_DATA
  roster dir  $PERSONAS_ROSTER_DIR
  keys dir    $PERSONAS_KEYS_DIR
  barrier     ${PERSONAS_BARRIER_PERIOD_MS:-10000}ms per settlement barrier
  auto-scan   ${PERSONAS_AUTO_SCAN:-off - use the Scan now menu item}

First launch on a fresh keys dir generates ~51MB of proving keys and takes minutes.
EOF
fi

if [[ -d "$USER_DATA" && "$RESET" != "1" ]]; then
  echo
  echo "NOTE: userData already exists, so this instance will reuse whatever account is"
  echo "      in it and SKIP auto-registration. If it boots into an unexpected account"
  echo "      (or the backend has restarted since), re-run with --reset."
fi
echo

cd "$REPO"
exec pnpm start
