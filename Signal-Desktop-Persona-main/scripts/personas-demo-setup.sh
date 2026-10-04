#!/usr/bin/env bash
# Copyright 2026 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#
# Generate the gitignored `config/local-*` files the CryptoPersonas demo needs.
#
# Two of the required values are NOT in this repo and cannot be:
#
#   serverPublicParams   the zkgroup params of the personas TEST server, which live in
#                        CryptoPersonas_Signal's configuration.rs. These are NOT Signal
#                        staging's params (config/default.json has those) — using the
#                        wrong ones fails at group creation with an opaque credential
#                        error, so they are pulled from the Rust source, never guessed.
#
#   certificateAuthority the TLS root the Caddy proxy MINTS ON FIRST BOOT. It does not
#                        exist until you have run `./tls-proxy.sh up` once, and it is
#                        different on every machine.
#
# Both come out of the CryptoPersonas_Signal checkout, so this script needs to know
# where that is. Re-running is safe and expected: run it once now to lay down the
# configs, then again after the TLS proxy's first boot to inject the CA.
#
# Usage:
#   ./scripts/personas-demo-setup.sh
#   PERSONAS_RUST_DIR=/path/to/CryptoPersonas_Signal ./scripts/personas-demo-setup.sh
#   ./scripts/personas-demo-setup.sh --instances alice,bob,carol,dave

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
CONFIG_DIR="$REPO/config"

INSTANCES="alice,bob,carol"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --instances) INSTANCES="$2"; shift 2 ;;
    -h|--help) sed -n '2,30p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------------------
# Fixed TEST values. Safe to hardcode: they are not secrets and every member of a
# demo group must agree on them.
# ---------------------------------------------------------------------------

# The personas test server's sender-certificate trust root (from configuration.rs's
# Staging arm). Deliberately NOT Signal staging's trust roots.
TRUST_ROOT="BS/lfaNHzWJDFSjarF+7KQcw//aEr8TPwu2QmV9Yyzt0"

# The first bytes of the test server's serverPublicParams. Used only as a SEARCH KEY to
# find the full value in the Rust source — it is far too long to carry here, and a
# truncated value would be worse than none.
PARAMS_PREFIX="AAp8oB0D4EV2q7hSue3Kxzh1Vc88"

# Signal staging's serverPublicParams is 900 chars; the test server's is the same
# construction, so anything much shorter means we matched a wrapped/split literal.
PARAMS_MIN_LEN=600

# ---------------------------------------------------------------------------
# Locate the Rust workspace.
# ---------------------------------------------------------------------------

find_rust_dir() {
  local c
  for c in "$@"; do
    # Check the MARKER, not just that the directory exists. A folder named
    # CryptoPersonas_Signal that is an empty or half-finished clone would otherwise be
    # accepted here and then fail much later with a confusing cargo error.
    [[ -d "$c" ]] && looks_like_workspace "$c" && { echo "$c"; return; }
  done
}

# Identify the workspace by CONTENT rather than by folder name — the name is the least
# reliable thing about it (it can be renamed, nested, or cloned under a different
# name). These are the markers build.sh and the runbook actually depend on.
looks_like_workspace() {
  [[ -f "$1/crates/personas-node/Cargo.toml" ]] ||
    [[ -d "$1/deploy/signal-test-server" ]] ||
    [[ -f "$1/Cargo.toml" && -d "$1/crates" ]]
}

# Search by marker file, so a differently-named clone is still found.
search_for_workspace() {
  local root
  for root in "$HOME/Documents" "$HOME/Repos" "$HOME/Developer" "$HOME/src" "$HOME"; do
    [[ -d "$root" ]] || continue
    find "$root" -maxdepth 6 -type d -name personas-node \
      -not -path '*/node_modules/*' -not -path '*/target/*' 2>/dev/null |
      while read -r hit; do
        # .../<workspace>/crates/personas-node -> <workspace>
        printf '%s\n' "$(cd "$hit/../.." && pwd)"
      done
  done | sort -u
}

EXPLICIT="${PERSONAS_RUST_DIR:-}"
RUST_DIR=""

if [[ -n "$EXPLICIT" ]]; then
  if [[ -d "$EXPLICIT" ]]; then
    RUST_DIR="$EXPLICIT"
  fi
else
  # Two-level walk up from the Signal checkout covers the common layouts: the Rust
  # workspace as a sibling, or the two repos in sibling folders under one parent
  # (which is the real layout here — gabe_test_repo_with_frontend/Signal-Desktop-Persona
  # alongside oliwia_test_repo/CryptoPersonas_Signal).
  RUST_DIR="$(find_rust_dir \
    "$REPO/../CryptoPersonas_Signal" \
    "$REPO/../../CryptoPersonas_Signal" \
    "$REPO/../../oliwia_test_repo/CryptoPersonas_Signal" \
    "$HOME/Documents/Anon_Group_Chat/Signal_Integration_Code_2026/oliwia_test_repo/CryptoPersonas_Signal" \
    "$HOME/Documents/Anon_Group_Chat/Signal_Integration_Code_2026_oliwia_test_repo/CryptoPersonas_Signal" \
    "$HOME/Repos/personas2/CryptoPersonas_Signal")"
fi

if [[ -z "$RUST_DIR" ]]; then
  {
    echo "ERROR: could not find the CryptoPersonas_Signal workspace."
    echo
    if [[ -n "$EXPLICIT" ]]; then
      echo "PERSONAS_RUST_DIR was set to:"
      echo "    $EXPLICIT"
      echo "but no directory exists there."
      echo
      # Walk the path down to the last component that DOES exist, so it is obvious
      # exactly where the path stops being real.
      probe="$EXPLICIT"; deepest=""
      while [[ "$probe" != "/" && -n "$probe" ]]; do
        if [[ -d "$probe" ]]; then deepest="$probe"; break; fi
        probe="$(dirname "$probe")"
      done
      if [[ -n "$deepest" ]]; then
        echo "Deepest part of that path that DOES exist:"
        echo "    $deepest"
        echo
        echo "Its contents:"
        ls -1 "$deepest" 2>/dev/null | sed 's/^/    /' | head -30
        echo
      fi
    else
      echo "PERSONAS_RUST_DIR was not set, and none of the default locations matched."
      echo
    fi

    echo "Searching for the workspace by marker file (crates/personas-node) ..."
    hits="$(search_for_workspace || true)"
    if [[ -n "$hits" ]]; then
      echo
      echo "FOUND — re-run with one of these:"
      while read -r h; do
        [[ -z "$h" ]] && continue
        echo "    PERSONAS_RUST_DIR=$h $0"
      done <<< "$hits"
    else
      echo "    no match found under \$HOME."
      echo
      echo "The workspace does not appear to be on this machine. It holds the two"
      echo "values this script cannot invent (serverPublicParams and the TLS CA) AND"
      echo "the backend itself — the chat test-server, storage-service and TLS proxy"
      echo "all live in its deploy/ directory. Clone it before going further."
    fi
  } >&2
  exit 1
fi

RUST_DIR="$(cd "$RUST_DIR" && pwd)"
echo "Rust workspace: $RUST_DIR"

# The directory existing is not the same as it being the right directory. Warn loudly
# rather than failing, in case the layout has moved — but say so, because the
# extraction below will otherwise fail with a much less obvious message.
if ! looks_like_workspace "$RUST_DIR"; then
  echo "  WARNING: no crates/personas-node or deploy/signal-test-server in there." >&2
  echo "  That path may not be the CryptoPersonas_Signal workspace root." >&2
fi

# ---------------------------------------------------------------------------
# Extract serverPublicParams from the Rust source.
# ---------------------------------------------------------------------------
# Matched by content (the known leading bytes) rather than by parsing Rust, so this
# keeps working whether the literal is a const, a match arm, or moves file.

# An explicit value always wins, and is checked BEFORE the search so it remains usable
# precisely when the search cannot work (params stored as a byte array, assembled at
# runtime, wrapped across lines...) — which is the only reason the override exists.
if [[ -n "${PERSONAS_SERVER_PUBLIC_PARAMS:-}" ]]; then
  SERVER_PUBLIC_PARAMS="$PERSONAS_SERVER_PUBLIC_PARAMS"
  echo "Using serverPublicParams from the environment (${#SERVER_PUBLIC_PARAMS} chars)"
else
  echo "Searching for serverPublicParams (prefix ${PARAMS_PREFIX}…) ..."
  SERVER_PUBLIC_PARAMS="$(
    grep -rhoE "${PARAMS_PREFIX}[A-Za-z0-9+/=]*" "$RUST_DIR" \
      --include='*.rs' --include='*.toml' --include='*.json' --include='*.env' \
      2>/dev/null | sort -u | awk '{ print length, $0 }' | sort -rn | head -1 | cut -d' ' -f2- || true
  )"
  if [[ -n "$SERVER_PUBLIC_PARAMS" ]]; then
    echo "  found serverPublicParams (${#SERVER_PUBLIC_PARAMS} chars)"
  fi
fi

if [[ -z "$SERVER_PUBLIC_PARAMS" ]]; then
  cat >&2 <<EOF

ERROR: no serverPublicParams found under $RUST_DIR.

Expected a base64 literal beginning ${PARAMS_PREFIX} (configuration.rs, Staging arm).
If it is stored as a byte array or assembled at runtime, copy the base64 out by hand
and set it directly:

  PERSONAS_SERVER_PUBLIC_PARAMS='AAp8oB0D...' $0

Do NOT substitute config/default.json's serverPublicParams — those are Signal
staging's and will fail group creation.
EOF
  exit 1
fi

if (( ${#SERVER_PUBLIC_PARAMS} < PARAMS_MIN_LEN )); then
  cat >&2 <<EOF

ERROR: the serverPublicParams found is only ${#SERVER_PUBLIC_PARAMS} chars, expected
>= ${PARAMS_MIN_LEN}. That usually means the literal is wrapped across lines in the Rust
source and only the first fragment matched. Copy the whole value and pass it via
PERSONAS_SERVER_PUBLIC_PARAMS=... instead.
EOF
  exit 1
fi

# ---------------------------------------------------------------------------
# The TLS CA — present only after the proxy's first boot.
# ---------------------------------------------------------------------------

CA_PATH="${PERSONAS_CA_PATH:-$RUST_DIR/deploy/signal-test-server/.local/tls/ca.crt}"
CA_READY=0
if [[ -f "$CA_PATH" ]]; then
  CA_READY=1
  echo "TLS CA: $CA_PATH"
else
  echo "TLS CA: NOT YET PRESENT ($CA_PATH)"
fi

# ---------------------------------------------------------------------------
# Write the configs.
# ---------------------------------------------------------------------------

mkdir -p "$CONFIG_DIR"

# Build the shared base with python so the CA PEM gets correctly JSON-escaped
# (embedded newlines become \n) instead of hand-rolling quoting in shell.
CA_READY="$CA_READY" \
CA_PATH="$CA_PATH" \
TRUST_ROOT="$TRUST_ROOT" \
SERVER_PUBLIC_PARAMS="$SERVER_PUBLIC_PARAMS" \
CONFIG_DIR="$CONFIG_DIR" \
python3 <<'PY'
import json, os

ca_ready = os.environ['CA_READY'] == '1'
ca_path = os.environ['CA_PATH']
config_dir = os.environ['CONFIG_DIR']

PLACEHOLDER = (
    'REPLACE_ME: run scripts/personas-demo-setup.sh again after '
    './tls-proxy.sh up has generated deploy/signal-test-server/.local/tls/ca.crt'
)

ca = open(ca_path, encoding='utf-8').read() if ca_ready else PLACEHOLDER

base = {
    # Everything on the loopback TLS proxy. `127.0.0.1` + a certificateAuthority is
    # what flips libsignal-net into localTestServer mode (isMockServer() matches
    # localhost / 127.0.0.1 / [::1]); the port is read straight off this URL.
    # Keep the substring "staging" OUT of these URLs or isStagingServer() wins and
    # the client will try to reach real Signal staging.
    'serverUrl': 'https://127.0.0.1:8443',
    'storageUrl': 'https://127.0.0.1:8443',
    'cdn': {
        '0': 'https://127.0.0.1:8443',
        '2': 'https://127.0.0.1:8443',
        '3': 'https://127.0.0.1:8443',
    },
    'certificateAuthority': ca,
    'serverTrustRoots': [os.environ['TRUST_ROOT']],
    'serverPublicParams': os.environ['SERVER_PUBLIC_PARAMS'],
    'openDevTools': True,
}

path = os.path.join(config_dir, 'local-development.json')
with open(path, 'w', encoding='utf-8') as f:
    json.dump(base, f, indent=2)
    f.write('\n')
print(f'  wrote {path}')
PY

# One file per instance. Distinct storageProfile => distinct userData dir, which is
# what lets several instances run at once instead of tripping the single-instance lock.
IFS=',' read -r -a NAMES <<< "$INSTANCES"
for name in "${NAMES[@]}"; do
  name="$(echo "$name" | tr -d '[:space:]')"
  [[ -z "$name" ]] && continue
  path="$CONFIG_DIR/local-development-${name}.json"
  printf '{\n  "storageProfile": "development-%s"\n}\n' "$name" > "$path"
  echo "  wrote $path"
done

# ---------------------------------------------------------------------------
# Report.
# ---------------------------------------------------------------------------

echo
if [[ "$CA_READY" == "1" ]]; then
  echo "Configs complete. Next: boot the backend (PERSONAS_DEMO.md §6), then"
  echo "  ./scripts/personas-run.sh alice     # and bob / carol in their own terminals"
else
  cat <<EOF
Configs written, but certificateAuthority is still a PLACEHOLDER — the proxy has not
minted its CA yet. Sequence from here:

  1. cd $RUST_DIR/deploy/signal-test-server
     ./boot.sh          # chat test-server on :8080  (own terminal; blocks)
     ./minio.sh up      # CDN
     ./tls-proxy.sh up  # mints .local/tls/ca.crt

  2. cd $REPO && ./scripts/personas-demo-setup.sh     # re-run: injects the CA

  3. Bring up the storage-service, then RE-RUN tls-proxy.sh up so Caddy picks up
     the /v2/groups route (PERSONAS_DEMO.md §6b). Verify with:
       curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:8443/v2/groups
     401 is correct. 404 means the route is missing.

  4. ./scripts/personas-run.sh alice   # and bob / carol
EOF
fi
