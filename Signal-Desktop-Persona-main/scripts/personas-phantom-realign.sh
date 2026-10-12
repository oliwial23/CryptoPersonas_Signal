#!/usr/bin/env bash
# Copyright 2026 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#
# Realign the shared phantom sender-key chains after they have drifted apart.
#
# WHEN TO USE THIS
#
# Recipients log `DuplicatedMessage: message with old counter N / M` with M < N. That
# means the SEND chain is BEHIND the RECEIVE chains: a sender-key receive chain only
# ever moves forward, so a rewound sender replays counters that recipients have already
# consumed, and libsignal rejects them as duplicates.
#
# Drift happens when one side is reset without the other — for example a send chain
# restarted from the bundle while recipients kept chains they had already ratcheted.
#
# WHAT IT DOES
#
# Deletes the shared send state and every per-account receive marker, so that on the
# next boot BOTH sides reinstall from the bundle's initial record and start together at
# counter 0. It does NOT touch the bundle itself: the phantom identity, certificate and
# trust root are preserved, so no account needs re-registering and no group needs
# recreating.
#
# Run with EVERY instance quit. Chains are read once at boot.

#
# --new-bundle  Also discard the bundle, so a fresh one is minted with a NEW sender-key
#               chain id. Use when realigning alone does not help: libsignal ADDS a
#               state to a SenderKeyRecord rather than replacing it, so a reinstall of
#               the same SKDM can leave a stale ratcheted state under the same chain id
#               shadowing the new one. A new chain id cannot collide with anything.
#               Accounts, the group and message history are untouched either way.

set -euo pipefail

NEW_BUNDLE=0
for arg in "$@"; do
  case "$arg" in
    --new-bundle) NEW_BUNDLE=1 ;;
    -h|--help) sed -n '3,30p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

ROSTER="${PERSONAS_ROSTER_DIR:-$HOME/.personas-roster}"
BUNDLE="$ROSTER/phantom-bundle.json"

echo "roster dir: $ROSTER"
[ "$NEW_BUNDLE" = 1 ] && echo "mode:       --new-bundle (the phantom bundle will be REMINTED)"

if [ ! -f "$BUNDLE" ]; then
  echo
  echo "ERROR: no phantom bundle at $BUNDLE" >&2
  echo "Nothing to realign to. Check PERSONAS_ROSTER_DIR is the dir your instances use" >&2
  echo "(./scripts/personas-phantom-check.sh prints what each one actually loaded)." >&2
  exit 1
fi

# Refuse while instances are running: deleting state under a live instance achieves
# nothing, because it holds its chain in memory and will write it back out.
if pgrep -f "Signal-development-" >/dev/null 2>&1; then
  echo
  echo "ERROR: a Signal instance is still running." >&2
  echo "Quit alice, bob AND carol first, then re-run. An instance that is already up" >&2
  echo "holds its chain in memory and would simply rewrite the files." >&2
  exit 1
fi

echo
echo "This will reset the shared phantom SEND chain and all RECEIVE chains to the"
echo "bundle's initial state. The bundle, phantom identity and certificate are kept,"
echo "so accounts and the group are unaffected."
echo
printf 'Proceed? [y/N] '
read -r reply
case "$reply" in
  y|Y|yes|YES) ;;
  *) echo "Aborted."; exit 0 ;;
esac

removed=0
if [ -f "$ROSTER/phantom-sendkey-state.b64" ]; then
  rm -f "$ROSTER/phantom-sendkey-state.b64"
  echo "  removed shared send state"
  removed=$((removed + 1))
fi
for marker in "$ROSTER"/phantom-receive-*.id; do
  [ -f "$marker" ] || continue
  rm -f "$marker"
  echo "  removed receive marker $(basename "$marker")"
  removed=$((removed + 1))
done

if [ "$NEW_BUNDLE" = 1 ]; then
  # Keep a copy: the bundle holds the phantom's private identity key, and if anything
  # depended on the old trust root we want to be able to put it back.
  backup="$BUNDLE.$(date +%Y%m%d-%H%M%S).bak"
  mv "$BUNDLE" "$backup"
  echo "  moved the bundle aside -> $(basename "$backup")"
  echo "    the first instance to start will mint a new one; the others adopt it,"
  echo "    so START THEM ONE AT A TIME, waiting for each to finish booting."
  removed=$((removed + 1))
fi

# Stale leftovers in the pre-durable location cause the same confusion later.
if [ -d /tmp/personas-roster ] && [ "$ROSTER" != /tmp/personas-roster ]; then
  rm -f /tmp/personas-roster/phantom-sendkey-state.b64 2>/dev/null || true
  echo "  cleared the stale send state in /tmp/personas-roster"
fi

if [ "$removed" = 0 ]; then
  echo "  nothing to remove — chains are already at their initial state"
fi

cat <<'EOF'

Done. Now, in this order:

  1. start ALL instances (same roster dir in every terminal):
       export PERSONAS_ROSTER_DIR="$HOME/.personas-roster"
       ./scripts/personas-run.sh alice
       ./scripts/personas-run.sh bob
       ./scripts/personas-run.sh carol

  2. each recipient should log:
       installPhantomReceiveKey: ... Reinstalling
     (because its marker is gone, so the chain is treated as stale)

  3. send ONE pseudonymous post, then:
       python3 scripts/personas-decrypt-errors.py

     Expect 0 decrypt failures. If 'DuplicatedMessage' appears again, the chains
     drifted apart a second time and the cause is a send that advanced the shared
     state while an instance was down — report the counters.
EOF
