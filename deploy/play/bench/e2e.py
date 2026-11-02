#!/usr/bin/env python3
"""End-to-end latencies from the app's experiment log.

Start the desktop app (and its extra members) with PERSONAS_BENCH_LOG=<file>, use the
group, then run:

    python3 deploy/play/bench/e2e.py <file> [--json out.json]

Each line of the log is one event (see ts/services/personasBenchLog.node.ts). This
joins a sender's `emit` with every other instance's `receive` (records) or `verify`
(standalone authorship / badge proofs) by `key`, and reports per operation:

  prove      the sender's proving time (engine-measured)
  client     sender start -> ready to hand to Signal (prove + self-ingest + persist)
  handle     a receiver's verify + order + apply of the record
  e2e        sender start -> receiver done, per (sender, receiver) pair; includes
             Signal transport, so run every instance on one machine, or NTP-sync them

and, from `settle` events, the callback invocation and epoch-update costs.
"""

import argparse
import json
import statistics
import sys
from collections import defaultdict


def stats(xs):
    xs = sorted(x for x in xs if x is not None)
    if not xs:
        return None
    p95 = xs[min(len(xs) - 1, int(round(0.95 * (len(xs) - 1))))]
    return {
        "n": len(xs),
        "mean": statistics.fmean(xs),
        "median": statistics.median(xs),
        "stdev": statistics.stdev(xs) if len(xs) > 1 else 0.0,
        "p95": p95,
        "min": xs[0],
        "max": xs[-1],
    }


def load(path):
    events = []
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"skipping malformed line {n}", file=sys.stderr)
    return events


def analyse(events):
    emits = {}
    for e in events:
        if e.get("event") == "emit" and e.get("key"):
            # First emit wins: a key is produced once.
            emits.setdefault(e["key"], e)

    # First arrival per (key, receiving instance), excluding the sender's own instance.
    arrivals = {}
    for e in events:
        if e.get("event") not in ("receive", "verify") or not e.get("key"):
            continue
        if e.get("event") == "receive" and e.get("status") == "rejected":
            continue
        k = (e["key"], e.get("instance"))
        if k not in arrivals:
            arrivals[k] = e

    per_op = defaultdict(lambda: defaultdict(list))
    for em in emits.values():
        op = em.get("op", "?")
        per_op[op]["prove"].append(em.get("proveMs"))
        per_op[op]["client"].append(em["endMs"] - em["startMs"])
        per_op[op]["bytes"].append(em.get("bytes"))
    for (key, inst), a in arrivals.items():
        em = emits.get(key)
        if em is None or em.get("instance") == inst:
            continue
        op = em.get("op", "?")
        per_op[op]["handle"].append(a.get("ingestMs", a.get("ms")))
        per_op[op]["e2e"].append(a["doneMs"] - em["startMs"])

    settles = [e for e in events if e.get("event") == "settle"]
    # One barrier settles on every instance; keep each (instance, barrier) once.
    seen, invoke, epoch = set(), [], []
    for s in settles:
        k = (s.get("instance"), s.get("group"), s.get("barrier"))
        if k in seen:
            continue
        seen.add(k)
        if s.get("invoked"):
            invoke.append(s["invokeMs"] / s["invoked"])
        epoch.append(s.get("epochUpdateMs"))

    report = {
        op: {m: stats(v) for m, v in metrics.items()} for op, metrics in sorted(per_op.items())
    }
    report["_callbacks"] = {
        "post_callback_per_invocation": stats(invoke),
        "update_epoch": stats(epoch),
    }
    return report


def fmt(s, key="median"):
    return "--" if s is None else f"{s[key]:.1f}"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log")
    ap.add_argument("--json", help="write the full report here")
    ap.add_argument("--stat", default="median", choices=["mean", "median", "p95"])
    args = ap.parse_args()

    report = analyse(load(args.log))
    cols = ["prove", "client", "handle", "e2e"]
    print(f"{'operation':<20}" + "".join(f"{c + ' ms':>12}" for c in cols) + f"{'n e2e':>8}")
    for op, m in report.items():
        if op.startswith("_"):
            continue
        n = m.get("e2e")["n"] if m.get("e2e") else 0
        print(f"{op:<20}" + "".join(f"{fmt(m.get(c), args.stat):>12}" for c in cols) + f"{n:>8}")
    cb = report["_callbacks"]
    print(f"\npost callback (per invocation): {fmt(cb['post_callback_per_invocation'], args.stat)} ms")
    print(f"update epoch:                   {fmt(cb['update_epoch'], args.stat)} ms")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)


if __name__ == "__main__":
    main()
