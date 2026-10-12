#!/usr/bin/env bash
# Copyright 2026 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#
# Diagnose anonymous / pseudonymous posts that RENDER on the sender and never ARRIVE.
#
# Those posts are the only ones that ride the shared "phantom" sender identity, so when
# they alone fail, the fault is in the phantom path. There are three ways it breaks, and
# none of them produces an error on the SENDING side:
#
#   1. TRUST ROOT MISMATCH. The phantom's sender certificate is signed by a trust root
#      this demo mints itself and stores in the roster dir. Instances append it to the
#      set MessageReceiver validates against. Different bundles => the recipient rejects
#      the certificate.  => "Sealed sender certificate validation failed"
#
#   2. STALE RECEIVE CHAIN. SHARED_DISTRIBUTION_ID is a hardcoded constant, so a newly
#      minted bundle reuses the same distribution id with a DIFFERENT chain key. An
#      instance that already had a chain installed keeps the old one and cannot decrypt.
#      => no certificate error, no send error, message silently dropped
#
#   3. TWO ROSTER DIRS. Instances launched either side of a PERSONAS_ROSTER_DIR change
#      read different bundles, which then presents as (1) or (2).
#
# Read-only.

set -uo pipefail

SUPPORT="$HOME/Library/Application Support"
CANDIDATES=("${PERSONAS_ROSTER_DIR:-}" "$HOME/.personas-roster" "/tmp/personas-roster")

fingerprint_of() {
  # Must match bundleFingerprint() in personasPhantom.preload.ts: sha256 of the
  # base64 trust root, first 16 hex chars.
  python3 -c '
import json,sys,hashlib
try:
    b=json.load(open(sys.argv[1]))
except Exception:
    print("UNREADABLE"); raise SystemExit
k=b.get("trustRootPublic") or b.get("trustRootPublicBase64") or ""
print(hashlib.sha256(k.encode()).hexdigest()[:16] if k else "NO-TRUST-ROOT")
' "$1" 2>/dev/null || echo "UNREADABLE"
}

echo "=== roster dirs on this machine ================================="
seen=""
declare -a FPS=()
for d in "${CANDIDATES[@]}"; do
  [ -n "$d" ] || continue
  case " $seen " in *" $d "*) continue ;; esac
  seen="$seen $d"
  b="$d/phantom-bundle.json"
  if [ -f "$b" ]; then
    fp="$(fingerprint_of "$b")"
    FPS+=("$fp")
    printf '  %-34s bundle %s  (%s)\n' "$d" "$fp" "$(date -r "$b" '+%m-%d %H:%M' 2>/dev/null)"
    for m in "$d"/phantom-receive-*.id; do
      [ -f "$m" ] || continue
      mv="$(cat "$m" 2>/dev/null)"
      if [ "$mv" = "$fp" ]; then mark="ok"; else mark="STALE"; fi
      printf '  %-34s   receive-chain marker %s  [%s]\n' "" "$mv" "$mark"
    done
    s="$d/phantom-sendkey-state.b64"
    if [ -f "$s" ]; then
      tag="$(cut -d: -f1 < "$s" 2>/dev/null)"
      case "$tag" in
        "$fp") printf '  %-34s   send state tagged %s  [ok]\n' "" "$tag" ;;
        *)     printf '  %-34s   send state tagged %s  [STALE/untagged]\n' "" "${tag:0:16}" ;;
      esac
    fi
  else
    printf '  %-34s (no bundle)\n' "$d"
  fi
done

# Divergence across dirs is only a problem if instances actually USED different ones;
# the log check below is what decides that.
uniq_fps="$(printf '%s\n' "${FPS[@]:-}" | sort -u | grep -c . || true)"
if [ "${uniq_fps:-0}" -gt 1 ]; then
  echo
  echo "  !! More than one bundle exists on this machine. Any two instances that read"
  echo "     different ones CANNOT exchange anonymous posts."
fi

echo
echo "=== what each instance USED (from its own log) =================="
for dir in "$SUPPORT"/Signal-development-*; do
  [ -d "$dir" ] || continue
  name="$(basename "$dir" | sed 's/^Signal-development-//')"
  logs="$dir/logs"
  [ -d "$logs" ] || continue

  echo "-- $name"
  # The authoritative line: dir + fingerprint together.
  used="$(grep -rh "ensurePhantomMaterial: using bundle" "$logs" 2>/dev/null | tail -1 \
          | sed 's/.*using bundle //; s/".*//')"
  if [ -n "$used" ]; then
    echo "     bundle/dir : $used"
  else
    echo "     bundle/dir : (not logged — this build predates the fix; REBUILD and restart)"
  fi

  for pat in "installPhantomReceiveKey" "loadPhantomSendStore"; do
    grep -rh "$pat" "$logs" 2>/dev/null | tail -1 \
      | sed 's/.*"msg":"\[personasPhantom\] /     /; s/"}$//'
  done

  certfail=$(grep -rh "Sealed sender certificate validation failed" "$logs" 2>/dev/null | wc -l | tr -d ' ')
  decfail=$(grep -rh "decryptAndCacheBatch error when processing the envelope" "$logs" 2>/dev/null | wc -l | tr -d ' ')
  [ "${certfail:-0}" -gt 0 ] && echo "     *** $certfail sealed-sender CERTIFICATE failures  => cause 1"
  [ "${decfail:-0}" -gt 0 ]  && echo "     *** $decfail envelope DECRYPT failures           => cause 2 (stale chain)"
  [ "${certfail:-0}" = 0 ] && [ "${decfail:-0}" = 0 ] && echo "     no certificate or decrypt failures logged"
  echo
done

echo "=== verdict ======================================================"
allcert=$(grep -rh "Sealed sender certificate validation failed" "$SUPPORT"/Signal-development-*/logs 2>/dev/null | wc -l | tr -d ' ')
alldec=$(grep -rh "decryptAndCacheBatch error when processing the envelope" "$SUPPORT"/Signal-development-*/logs 2>/dev/null | wc -l | tr -d ' ')
reinstalls=$(grep -rh "installPhantomReceiveKey.*Reinstalling" "$SUPPORT"/Signal-development-*/logs 2>/dev/null | wc -l | tr -d ' ')

if [ "${allcert:-0}" -gt 0 ]; then
  echo "  CAUSE 1 — trust root mismatch. The instances are not on one bundle."
  echo "  Check the 'bundle/dir' lines above: they must be IDENTICAL for every instance."
elif [ "${alldec:-0}" -gt 0 ]; then
  echo "  CAUSE 2 — decryption is failing with a matching certificate, i.e. a stale"
  echo "  receive chain. Reinstalls seen so far: ${reinstalls:-0}."
  echo "  If that is 0, the fix is not in the running bundle: pnpm run build:rolldown."
else
  echo "  Neither failure is in the logs. If posts still are not arriving, the problem is"
  echo "  UPSTREAM of decryption — the send may not be leaving at all. On the SENDER:"
  echo
  echo "    grep -rhE 'conversationQueue|sendNormalMessage|409|410|428' \\"
  echo "      \"$SUPPORT/Signal-development-alice/logs\" | tail -40"
fi

cat <<'EOF'

=== the rule that makes a real fix look like a failed one ========
Every instance must be launched with the SAME roster dir, and ALL of them must be
restarted together. The bundle and its trust root are read ONCE at boot, so an instance
started before a change keeps the old values in memory no matter what is on disk.

  export PERSONAS_ROSTER_DIR="$HOME/.personas-roster"   # same value in every terminal
  # quit alice, bob AND carol, then start all three again
EOF
