#!/usr/bin/env python3
# Copyright 2026 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only

"""Show what the phantom decrypt failures ACTUALLY say, scoped to the current boot.

Why this exists: the shell check script counted decrypt failures across the whole log
history and reported the total as if it were current. Failures from before a fix then
look like the fix not working. It also never printed the error TEXT, so the diagnosis
rested on a count -- which cannot distinguish "no sender key state" (a stale chain) from
any other decryption failure, and those have completely different causes.

Signal writes one JSON object per line with a `time` field, so the log can be filtered
properly rather than grepped.

Usage:  python3 scripts/personas-decrypt-errors.py [instance ...]
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

SUPPORT = Path.home() / "Library" / "Application Support"

# The line Desktop logs when the receiver is constructed. Everything after the LAST one
# belongs to the current boot; anything earlier is a previous run.
BOOT_MARKER = "Initializing MessageReceiver"

INTERESTING = (
    "decryptAndCacheBatch error when processing the envelope",
    "Sealed sender certificate validation failed",
    "ensurePhantomMaterial:",
    "installPhantomReceiveKey:",
    "loadPhantomSendStore:",
    "decryptSealedSender",
)

# Substrings in a libsignal decrypt error that point at a specific cause. The whole
# point of printing the text is that these are NOT interchangeable.
# SEND SIDE. A persona post may only go out via the sender-key path, because that is
# what carries the shared phantom identity. sendToGroup.preload.ts:241 FAILS CLOSED when
# that send errors: it refuses the normal per-recipient fallback, because the fallback
# would deliver the message under the real identity and de-anonymize the sender.
#
# So a failed sender-key send means the post never leaves, recipients log nothing at all,
# and the sender still sees its own copy. That is indistinguishable, from the outside,
# from "sent but not received" — which is why this section exists.
SEND_FAILURE = "failing closed"

SEND_PATTERNS = (
    "sendToGroupViaSenderKey",
    "Sender Key send failed",
    "failing closed",
    "Not enough recipients",
    "does not have endorsements",
    "Keys are out of date",
    "is unregistered",
    "Failing over",
)

# Why the sender-key send itself failed. These are the reachable causes in a 3-instance
# demo, in rough order of likelihood.
SEND_CAUSE_HINTS = {
    "not enough recipients": (
        "FEWER THAN 2 sender-key-eligible recipients. Sender key needs >= 2, so in a "
        "3-member group every other member must be registered AND reachable. If one "
        "instance is not running or its account is stale, posting breaks for everyone."
    ),
    "does not have endorsements": (
        "a group member has no send endorsement — usually a group created against a "
        "different server, or storage-service/GroupV2 not reachable"
    ),
    "is unregistered": (
        "a member's account does not exist on the CURRENT server — the usual result of "
        "pointing clients at a new backend without re-registering all of them"
    ),
    "keys are out of date": "prekeys need refreshing; often clears on retry",
    "untrusted identity": "a member's identity key changed (a --reset elsewhere)",
}

CAUSE_HINTS = {
    "no sender key state": "STALE / MISSING RECEIVE CHAIN for this distribution id",
    "SenderKey": "sender-key path",
    "Invalid message": "malformed or wrong-key ciphertext",
    "Bad MAC": "WRONG KEY — chains disagree",
    "invalid MAC": "WRONG KEY — chains disagree",
    # NOT harmless on the shared phantom chain. "old counter N / M" with M < N means the
    # SEND chain is BEHIND the receive chains: a receive chain only moves forward, so a
    # rewound sender replays counters recipients already consumed and every post is
    # rejected. On an ordinary 1:1 chain a duplicate really is benign; here it is the bug.
    # Fix with scripts/personas-phantom-realign.sh (resets BOTH sides together).
    "Duplicate": (
        "CHAIN REWIND — the shared send chain is behind the receive chains. "
        "Compare the two counters in 'old counter N / M': M < N confirms it. "
        "Run scripts/personas-phantom-realign.sh with all instances quit"
    ),
    "Unsupported": "version mismatch between sender and receiver",
    "untrusted identity": "identity key changed for this address",
    "certificate": "sealed-sender certificate problem",
}


def load_lines(logs: Path) -> list[dict]:
    out: list[dict] = []
    if not logs.is_dir():
        return out
    # Signal rotates logs; read them all and sort by time rather than trusting names.
    for path in sorted(logs.iterdir()):
        if not path.is_file():
            continue
        try:
            with path.open("r", errors="replace") as handle:
                for raw in handle:
                    raw = raw.strip()
                    if not raw.startswith("{"):
                        continue
                    try:
                        entry = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(entry, dict) and "msg" in entry:
                        out.append(entry)
        except OSError:
            continue
    out.sort(key=lambda e: str(e.get("time", "")))
    return out


def report(instance: str) -> None:
    logs = SUPPORT / f"Signal-development-{instance}" / "logs"
    entries = load_lines(logs)
    print(f"\n=== {instance} " + "=" * (62 - len(instance)))
    if not entries:
        print("  no parseable log lines")
        return

    boots = [i for i, e in enumerate(entries) if BOOT_MARKER in str(e.get("msg", ""))]
    if boots:
        start = boots[-1]
        print(f"  current boot started at {entries[start].get('time')}")
        print(f"  ({len(boots)} boot(s) in these logs; ignoring the earlier ones)")
    else:
        start = 0
        print("  no boot marker found — showing everything")

    current = entries[start:]
    before = entries[:start]

    def count(entries_, needle):
        return sum(1 for e in entries_ if needle in str(e.get("msg", "")))

    dec_now = count(current, "decryptAndCacheBatch error when processing the envelope")
    dec_old = count(before, "decryptAndCacheBatch error when processing the envelope")
    cert_now = count(current, "Sealed sender certificate validation failed")

    print(f"\n  decrypt failures THIS boot    : {dec_now}")
    print(f"  decrypt failures in past runs : {dec_old}   <- not evidence about now")
    print(f"  certificate failures this boot: {cert_now}")

    print("\n  phantom lines this boot:")
    found = False
    for e in current:
        msg = str(e.get("msg", ""))
        if any(k in msg for k in ("ensurePhantomMaterial:", "installPhantomReceiveKey:", "loadPhantomSendStore:")):
            print(f"    {e.get('time','')[11:19]}  {msg.strip()}")
            found = True
    if not found:
        print("    (none — persona mode off, or the log rotated)")

    print("\n  decrypt error TEXT this boot (what actually matters):")
    shown = 0
    for e in current:
        msg = str(e.get("msg", ""))
        if "decryptAndCacheBatch error when processing the envelope" not in msg:
            continue
        shown += 1
        if shown > 5:
            continue
        print(f"    --- #{shown} at {e.get('time','')[11:19]}")
        for line in msg.splitlines():
            line = line.strip()
            if line:
                print(f"      {line[:300]}")
        hits = [v for k, v in CAUSE_HINTS.items() if k.lower() in msg.lower()]
        if hits:
            print(f"      >> points at: {'; '.join(sorted(set(hits)))}")
        else:
            print("      >> no known cause substring — read the text above literally")
    if shown == 0:
        print("    NONE. Decryption is not failing on this boot.")
    elif shown > 5:
        print(f"    ... {shown - 5} more")

    # ---- PERSONA POSTS: sent and received, with their context labels -----------
    # The question "is it not arriving, or arriving and not rendering?" cannot be
    # answered from decrypt failures alone: zero failures and an empty timeline are
    # consistent with both. These two lines settle it, and carry the context name.
    print("\n  persona posts this boot (context label in brackets):")
    sent = [e for e in current if "personas: sending post" in str(e.get("msg", ""))]
    recv = [e for e in current if "personas: received post" in str(e.get("msg", ""))]
    if not sent and not recv:
        print("    none logged. If you did post, this build predates the diagnostic:")
        print("    pnpm run build:rolldown, restart, resend.")
    for e in sent[-6:]:
        msg = " ".join(str(e.get("msg", "")).split())
        print(f"    {str(e.get('time',''))[11:19]}  SENT     {msg.split('sending post ',1)[-1][:150]}")
    for e in recv[-6:]:
        msg = " ".join(str(e.get("msg", "")).split())
        print(f"    {str(e.get('time',''))[11:19]}  RECEIVED {msg.split('received post ',1)[-1][:150]}")
    if sent or recv:
        print(f"    totals: sent {len(sent)}, received {len(recv)}")
        no_context = [
            e for e in sent if "context=(none)" in str(e.get("msg", ""))
        ]
        if no_context:
            print(f"    >> {len(no_context)} of {len(sent)} sends had NO context attached.")
            print("       The chip cannot render what was never sent. Either no context")
            print("       was selected in the composer, or the selection was lost.")
        recv_no_context = [
            e for e in recv if "context=(none)" in str(e.get("msg", ""))
        ]
        if recv_no_context and not no_context:
            print(f"    >> {len(recv_no_context)} received posts lost their context in transit —")
            print("       sent WITH a context but decoded without one. That is a carriage bug.")

    # ---- SEND SIDE -------------------------------------------------------------
    print("\n  SEND side this boot (did the post even leave?):")
    send_lines = [
        e for e in current
        if any(p.lower() in str(e.get("msg", "")).lower() for p in SEND_PATTERNS)
    ]
    failed_closed = [
        e for e in current if SEND_FAILURE in str(e.get("msg", ""))
    ]
    if not send_lines:
        print("    no sender-key send activity logged — was a persona post actually")
        print("    SENT from this instance since 'current boot started' above?")
    else:
        for e in send_lines[-8:]:
            msg = " ".join(str(e.get("msg", "")).split())
            print(f"    {str(e.get('time',''))[11:19]}  {msg[:260]}")

    if failed_closed:
        print(f"\n    *** {len(failed_closed)} PERSONA SEND(S) FAILED CLOSED.")
        print("    The post never left this machine. Recipients are innocent.")
        # Scan ALL send-side lines, not just the fail-closed one. The fail-closed
        # message says only that the send was refused; WHY the sender-key send failed
        # is in the lines just before it ("Not enough recipients", "is unregistered").
        blob = " ".join(str(e.get("msg", "")) for e in send_lines).lower()
        named = False
        for key, explanation in SEND_CAUSE_HINTS.items():
            if key in blob:
                print(f"    >> {explanation}")
                named = True
        if not named:
            print("    >> cause not in the known set; read the lines above literally")


def chain_report(all_entries: dict[str, list[dict]]) -> None:
    """Cross-instance view of the SHARED send chain.

    All instances read and write one state file, so the chain is only coherent if every
    load picks up the digest that the previous save wrote. Two failure modes look
    identical from a recipient's `DuplicatedMessage` error but need different fixes:

      LOST SAVE  -- every load reports "no state file" or a save error, so the chain
                    restarts at the bundle's initial record on each send.
      RACE       -- two instances load the SAME digest, encrypt at the same counter,
                    and the second save overwrites the first.

    Telling them apart needs every instance's loads and saves on one timeline, which no
    single instance's log can show. Hence this section.
    """
    events: list[tuple[str, str, str]] = []
    for name, entries in all_entries.items():
        for e in entries:
            msg = " ".join(str(e.get("msg", "")).split())
            if "loadPhantomSendStore" in msg:
                events.append((str(e.get("time", "")), name, msg))
    events.sort()

    print("\n=== SHARED SEND CHAIN (all instances, one timeline) " + "=" * 14)
    if not events:
        print("  no chain activity logged.")
        print("  If posts are failing with DuplicatedMessage, this build predates the")
        print("  chain instrumentation: pnpm run build:rolldown, restart, resend.")
        return

    loads_from_bundle = 0
    save_failures = 0
    loaded_digests: dict[str, list[str]] = {}
    for time, name, msg in events:
        short = msg.split("] ", 1)[-1]
        print(f"  {time[11:19]}  {name:6} {short[:150]}")
        if "BUNDLE INITIAL" in msg:
            loads_from_bundle += 1
        if "FAILED to persist" in msg or "no record to persist" in msg:
            save_failures += 1
        if "loaded chain" in msg:
            digest = msg.split("loaded chain ", 1)[1].split(" ", 1)[0]
            loaded_digests.setdefault(digest, []).append(name)

    print("\n  interpretation:")
    if save_failures:
        print(f"    LOST SAVE — {save_failures} save failure(s). The chain cannot advance,")
        print("    so every send reuses the same counter. Fix the write error above;")
        print("    it is usually permissions on the roster dir.")
    if loads_from_bundle > 1:
        print(f"    CHAIN RESTARTING — {loads_from_bundle} loads fell back to the bundle's")
        print("    initial record. After the first send there should always be a state")
        print("    file, so repeated fallbacks mean saves are not landing or something")
        print("    is deleting the file between sends.")
    # GAPS. Every load should pick up exactly what the previous save wrote. A load of a
    # digest nobody saved means a write was lost, or an instance whose log we are not
    # reading also writes the file. Only checking for DUPLICATE loads missed this
    # entirely, and a gap is as fatal to the chain as a repeat.
    saved: set[str] = set()
    gaps: list[tuple[str, str, str]] = []
    first_load = True
    for time, name, msg in events:
        if "/save: advanced" in msg and " -> " in msg:
            saved.add(msg.rsplit(" -> ", 1)[1].split()[0])
        elif "loaded chain" in msg:
            digest = msg.split("loaded chain ", 1)[1].split(" ", 1)[0]
            from_bundle = "BUNDLE INITIAL" in msg
            if not from_bundle and not first_load and digest not in saved:
                gaps.append((time, name, digest))
            first_load = False
    if gaps:
        print("    GAP — a chain state was loaded that no logged save produced:")
        for time, name, digest in gaps:
            print(f"      {time[11:19]} {name} loaded {digest}, never saved above")
        print("    Either a save was lost, or an instance not in this report is also")
        print("    writing the file. Check that every running instance appears above.")

    repeats = {d: n for d, n in loaded_digests.items() if len(n) > 1}
    if repeats:
        print("    RACE — the same chain state was loaded more than once:")
        for digest, names in repeats.items():
            print(f"      {digest} loaded by {', '.join(names)}")
        print("    Those sends encrypted at the same counter, so all but one are")
        print("    duplicates at the receiver. The shared state is read-modify-written")
        print("    with no cross-process lock ('serial posting is assumed'), so two")
        print("    instances posting close together corrupt the chain. Until that is")
        print("    fixed, POST FROM ONE INSTANCE AT A TIME and wait for delivery.")
    if not (save_failures or loads_from_bundle > 1 or repeats or gaps):
        print("    chain looks coherent: each load picked up a distinct state.")


def bundle_freshness() -> None:
    """Is the app actually running the code in ts/?

    `pnpm test-node` runs from SOURCE via tsx; the Electron app runs the bundle in
    bundles/. So the suite can pass while the app runs week-old code, and a UI fix then
    looks like it failed. This has cost real debugging time more than once, so it is
    checked here rather than remembered.
    """
    root = Path.cwd()
    src = root / "ts"
    bundles = root / "bundles"
    print("\n=== IS THE APP RUNNING YOUR CODE? " + "=" * 31)
    if not src.is_dir() or not bundles.is_dir():
        print("  run this from the repo root (ts/ and bundles/ must exist)")
        return

    def newest(path: Path, suffixes: tuple[str, ...]) -> tuple[float, str]:
        best, name = 0.0, "(none)"
        for p in path.rglob("*"):
            if p.is_file() and p.suffix in suffixes:
                try:
                    m = p.stat().st_mtime
                except OSError:
                    continue
                if m > best:
                    best, name = m, str(p.relative_to(root))
        return best, name

    src_time, src_file = newest(src, (".ts", ".tsx"))
    # Compare against the APP bundle specifically. Taking the newest file anywhere under
    # bundles/ picks up independent artifacts (mp3Encoder.js and friends) that a partial
    # build can touch, which made a stale app look fresh.
    app_bundle = bundles / "preload" / "main.js"
    if app_bundle.is_file():
        bundle_time, bundle_file = app_bundle.stat().st_mtime, str(
            app_bundle.relative_to(root)
        )
    else:
        bundle_time, bundle_file = newest(bundles, (".js",))
    import datetime

    def fmt(t: float) -> str:
        return datetime.datetime.fromtimestamp(t).strftime("%m-%d %H:%M:%S") if t else "?"

    print(f"  newest source : {fmt(src_time)}  {src_file}")
    print(f"  newest bundle : {fmt(bundle_time)}  {bundle_file}")
    if src_time > bundle_time:
        print("\n  *** THE BUNDLE IS OLDER THAN YOUR SOURCE. The app is NOT running your")
        print("      latest changes. Run:  pnpm run build:rolldown   then restart.")
    else:
        print("  bundle is newer than source — the app has your changes.")

    # Markers must be STRING LITERALS, never identifiers. The bundler renames
    # identifiers, so searching for `DEFAULT_RATE_INDEX` reported a feature as missing
    # when it was present — a false negative that would have sent us chasing a rebuild
    # that had already happened. Strings in source survive into the bundle verbatim.
    markers = {
        "context chip": "Context label. The context number is bound",
        "context->rate coercion": "posting as rate-limited #",
        "persona post logging": "personas: sending post",
        "sender-key chain logging": "loadPhantomSendStore: loaded chain",
        "stale-chain removal fix": "removed the stale sender key record",
    }
    print("\n  features present in the built bundle:")
    for label, needle in markers.items():
        found = False
        for p in bundles.rglob("*.js"):
            try:
                if needle in p.read_text(errors="ignore"):
                    found = True
                    break
            except OSError:
                continue
        print(f"    {'yes' if found else 'NO '}  {label}")


def main() -> int:
    # FIRST, and before anything that can exit early: every other reading in this report
    # is meaningless if the app is running stale code, and this check needs no logs.
    bundle_freshness()

    wanted = sys.argv[1:]
    if not wanted:
        wanted = sorted(
            p.name.replace("Signal-development-", "")
            for p in SUPPORT.glob("Signal-development-*")
            if p.is_dir()
        )
    if not wanted:
        print("\nNo Signal-development-* profiles found — no logs to analyze.")
        return 0

    collected: dict[str, list[dict]] = {}
    for instance in wanted:
        report(instance)
        entries = load_lines(SUPPORT / f"Signal-development-{instance}" / "logs")
        boots = [i for i, e in enumerate(entries) if BOOT_MARKER in str(e.get("msg", ""))]
        collected[instance] = entries[boots[-1]:] if boots else entries
    chain_report(collected)
    print(
        "\n"
        "HOW TO READ THIS\n"
        "  decrypt failures 0 everywhere + a FAILED CLOSED send\n"
        "      -> the post never left the sender. Fix the sender-key send; the\n"
        "         recipients are fine. This is the common case.\n"
        "  decrypt failures 0 everywhere + no send activity at all\n"
        "      -> no persona post was sent during this boot, so there is nothing to\n"
        "         diagnose yet. Send one, then re-run.\n"
        "  decrypt failures non-zero\n"
        "      -> the error TEXT names the cause. A stale chain says 'no sender key\n"
        "         state' or fails the MAC; nothing else does.\n"
        "\n"
        "Failing closed is deliberate (sendToGroup.preload.ts:241): a persona post is\n"
        "never allowed to fall back to an attributable send, because that would deliver\n"
        "it while de-anonymizing the sender. Delivery is the symptom; the sender-key\n"
        "failure is the bug.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
