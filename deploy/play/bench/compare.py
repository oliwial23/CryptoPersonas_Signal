#!/usr/bin/env python3
"""Serverless vs server-based (Privacy Pass + folding), from two benchmark runs on one machine.

    python3 deploy/play/bench/compare.py --serverless <personas-bench JSON> \
        --server <personas-bench --server JSON> [--members 20] [--per-day 17.5]

The serverless file is an ordinary `personas-bench` run (with `scan` and `anon_post`);
the server file is `personas-bench --server`. Use the same `--history` for both.

Prints what each design costs per post and per settlement of K callbacks, who pays it,
and a group-wide daily total for `--members` members posting `--per-day` times each.
"""
import argparse
import json


def mean(op, field):
    s = (op or {}).get(field)
    return s["mean_ms"] if s else None


def ms(x):
    return "—" if x is None else f"{x:,.1f}"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--serverless", required=True)
    ap.add_argument("--server", required=True)
    ap.add_argument("--members", type=int, default=20)
    ap.add_argument("--per-day", type=float, default=17.5, help="posts per member per day")
    ap.add_argument("--scan-from", help="serverless file to take `scan` from, if --serverless lacks it")
    ap.add_argument("--json", help="also write the comparison here")
    args = ap.parse_args()

    sl = json.load(open(args.serverless))
    sv = json.load(open(args.server))
    slo, svo = sl["operations"], sv["operations"]
    n, k = args.members, sv["callbacks"]
    if sl["history"] != sv["history"]:
        print(f"warning: histories differ (serverless {sl['history']}, server {sv['history']})\n")

    post = slo["anon_post"]
    sl_prove, sl_self, sl_handle = mean(post, "prove"), mean(post, "self_ingest"), mean(post, "handle")
    scan = slo.get("scan")
    if scan is None:
        if not args.scan_from:
            raise SystemExit("--serverless has no `scan`; rerun with it or pass --scan-from")
        other = json.load(open(args.scan_from))
        scan = other["operations"]["scan"]
        print(f"warning: serverless scan taken from history {other['history']}\n")
    sl_scan_prove, sl_scan_handle = mean(scan, "prove"), mean(scan, "handle")

    pp_req, pp_unblind, pp_issue = (
        mean(svo["pp_request"], "client"),
        mean(svo["pp_request"], "client_after"),
        mean(svo["pp_request"], "server"),
    )
    pp_redeem, pp_check, pp_rt = (
        mean(svo["pp_post"], "client"),
        mean(svo["pp_post"], "server"),
        mean(svo["pp_post"], "round_trip"),
    )
    sv_prove, sv_verify = mean(svo["post"], "client"), mean(svo["post"], "server")
    scan_client, scan_server = mean(svo["scan"], "client"), mean(svo["scan"], "server")
    fold_client, fold_server = mean(svo["fold"], "client"), mean(svo["fold"], "server")

    print(f"history {sv['history']} records, {sl['machine']['cpu']}, means in ms\n")
    rows = [
        ("POSTING", None, None, None),
        ("  sender, at send time", sl_prove + sl_self, pp_redeem, "serverless proves; server redeems a ticket"),
        ("  sender, ahead of time", None, pp_req + pp_unblind, "one ticket per future post"),
        ("  checking the post", sl_handle, pp_check, "serverless: EVERY other member; server: once"),
        ("  server, ahead of time", None, pp_issue, "verify + blind-issue each ticket"),
        ("  (server, no ticket)", None, sv_verify, f"a proved post; client proves in {ms(sv_prove)}"),
        (f"SETTLING {k} CALLBACKS", None, None, None),
        ("  member proves", k * sl_scan_prove, fold_client, "serverless: one scan each; server: one fold"),
        ("  checking", k * sl_scan_handle, fold_server, "serverless: every other member"),
        ("  (server, scan each)", None, k * scan_client, f"client; server checks {k} x {ms(scan_server)}"),
    ]
    print(f"{'':<28}{'serverless':>12}{'server+PP+fold':>17}   note")
    for name, a, b, note in rows:
        if a is None and b is None and note is None:
            print(name)
            continue
        print(f"{name:<28}{ms(a):>12}{ms(b):>17}   {note}")

    # A day in a group: every member posts per_day times and settles once per K posts.
    posts = n * args.per_day
    settles = posts / k
    sl_member = args.per_day * (sl_prove + sl_self) + (posts - args.per_day) * sl_handle \
        + (args.per_day / k) * k * sl_scan_prove + (settles - args.per_day / k) * k * sl_scan_handle
    sv_member = args.per_day * (pp_redeem + pp_req + pp_unblind) + (args.per_day / k) * fold_client
    sv_server = posts * (pp_check + pp_issue) + settles * fold_server
    print(f"\nA DAY: {n} members x {args.per_day} posts, settling every {k} posts (CPU seconds)")
    print(f"  each member     serverless {sl_member / 1e3:8.1f}    server-based {sv_member / 1e3:8.1f}")
    print(f"  the server      serverless {0:8.1f}    server-based {sv_server / 1e3:8.1f}")
    print(f"  whole group     serverless {n * sl_member / 1e3:8.1f}    server-based {(n * sv_member + sv_server) / 1e3:8.1f}")
    print(f"\nServer round trip to redeem a ticket (loopback, stash load/save included): {ms(pp_rt)} ms")

    if args.json:
        out = {
            "history": sv["history"],
            "callbacks": k,
            "members": n,
            "per_day": args.per_day,
            "rows": [{"what": r[0].strip(), "serverless_ms": r[1], "server_ms": r[2], "note": r[3]} for r in rows if r[3]],
            "day_cpu_s": {
                "serverless_member": sl_member / 1e3,
                "server_member": sv_member / 1e3,
                "server": sv_server / 1e3,
            },
        }
        with open(args.json, "w") as f:
            json.dump(out, f, indent=2)


if __name__ == "__main__":
    main()
