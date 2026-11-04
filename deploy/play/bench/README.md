# Running the evaluation experiments

There are two ways to measure:

| What | Tool | Measures |
|---|---|---|
| Per-operation costs, R1CS sizes, callbacks | `personas-bench` (Rust, no app, no network) | prove, verify, handle, proof size, constraints, post callback, update epoch |
| End-to-end latency in the real app | `PERSONAS_BENCH_LOG` + `e2e.py` | sender click → every other member has applied it, through real Signal |

Both use the **production circuits and production keys** (heights 32/32/32), so the
numbers describe what testers actually run.

## 1. Micro-benchmarks: `personas-bench`

Build in release mode, always:

```bash
cargo build --release -p personas-bench
```

`--keys` is a directory containing `params/serverless-merkle/merkle_groth16_keys.bin`
(the same file the app downloads; its SHA-256 is the pinned `--keys-sha256`).

```bash
./target/release/personas-bench --keys <keys-dir> --iters 30 --warmup 3 --history 150 --label "M2-arm64" --out results-m2.json
```

- `--iters` timed repetitions per operation (default 20); `--warmup` untimed first runs.
- `--history N` pre-fills the group with N records first, so `handle` and `scan`
  reflect a group that has been in use rather than an empty one. Report the value you used.
- `--only anon_post,scan,moderation` runs a subset; ops: `join, anon_post, pseudo_post,
  rate_limited_post, authorship, vote, rating, badge_request, badge_proof, scan,
  not_banned, moderation`.
- `--skip-constraints` skips the R1CS count (it is deterministic; run it once).

Output: a printed table plus a JSON file with machine info and mean / median / stdev /
p95 / min / max for every measurement. What each field measures:

| Quantity | Bench field |
|---|---|
| Proof generation (client) | `prove` |
| Verification | `verify` (a receiver checking the proof alone) |
| Handle / server work | `handle` — the receiver's verify + order + apply. In this serverless design every member's replica does what the server did. |
| Proof size | `bytes_mean` |
| R1CS | `constraints` section |
| Post callback | `moderation` → `invoke_per_callback`, invocation at the settlement barrier |
| Update epoch | `moderation` → `epoch_update`, re-pin of the non-membership tree |

### Modern vs legacy hardware

Run the same command on each machine, with its own `--label`. For an Intel Mac, build
there (or cross-build `--target x86_64-apple-darwin`). To approximate a phone on an Apple
Silicon Mac, confine the run to the efficiency cores (background QoS) with as many threads
as there are efficiency cores:

```bash
taskpolicy -b env RAYON_NUM_THREADS=4 ./target/release/personas-bench --keys <keys-dir> --label "4 efficiency cores"
```

A single thread (`RAYON_NUM_THREADS=1`) is not a phone model: current phones have 6–8 cores.

Good practice: plug in the laptop, close other apps, disable Low Power Mode, and run
each configuration at least twice; report the median.

### Nova folding across batch sizes

```bash
./target/release/personas-bench --keys <keys-dir> --fold --iters 5 --label "M3 Max" --out fold-m3.json
```

A member with `k` outstanding callbacks absorbs them with one Nova-folded scan: `k/N` fold
steps of `N` callbacks each, a randomized IVC proof, and a Groth16 proof tying the fold to
the member's object. The verifier makes the same three checks as the centralized server's
`fold_scan`. Defaults: `--fold-batches 1,2,4,8,16` and `--fold-k 1,2,4,8,16,32,64`; a cell
runs only when `k` is a multiple of `N`.

Reported per `N`: step-circuit R1CS, Nova preprocessing (setup), and per `(N, k)`: witness
and tie-in time, `Nova::init`, all fold steps, per step, randomization, client total,
verify, and the record size. Every run asserts the proof verifies and that the fold's
output is the member's scanned object.

This is benchmark-only: serverless keeps folding off (`docs/SERVERLESS_PROTOCOL.md` §13),
and the run generates its own Nova parameters and tie-in key, leaving production keys
alone. On the serverless stores the callback roots are circuit constants of the fold
step and the object root is a constant of the tie-in key, so a deployment would repeat
the setup whenever the roots change (every barrier). That is why setup is reported
separately.

## 2. Serverless against the server-based implementation

`personas-bench --server` runs the real validation server with both of its optimizations
(Privacy Pass tickets and folded scans) and drives it with the real client library:
proved posts, ticket requests and redemptions, K callbacks scanned one by one or folded.

```bash
cargo build --release -p personas-bench --bin personas-bench -p personas-server --bin server
./target/release/personas-bench --server --history 1000 --iters 20 --warmup 3 --callbacks 16 --out server.json
python3 deploy/play/bench/compare.py --serverless serverless.json --server server.json
```

`compare.py` puts it beside an ordinary `personas-bench` run with the same `--history`: what
the sender pays and when, who checks each post, and CPU per day for a group.

- `--server-url URL` drives a server that is already running, instead of starting one, so
  a real network sits between client and server. The server's own timings stay on that
  server; only the client's and the round trips are reported.
- `--load` measures capacity: for each `--load-concurrency` level it sends
  `--load-requests` prepared requests that many at a time, and reports posts per second and
  latency. Proofs and tickets are made first, so client proving is not measured.

### On the VM

`compose.yml` has the validation server and the benchmarks under the profile `compare`, so
they stay out of the demo. The server's chat is the in-process mock: nothing reaches Signal.
On the VM, from `deploy/play`:

```bash
docker compose --profile compare build validator
docker compose up -d validator
docker compose up -d --force-recreate gateway     # once, for the /validator/ route
./bench/vm-compare.sh quick
nohup ./bench/vm-compare.sh long > ~/vm-compare-long.log 2>&1 &
```

Then, from a laptop, the same measurements with the real network in the way, through the
load balancer and the gateway. `/validator/` takes the `/play` password; percent-encode it
if it has special characters:

```bash
U="https://demo:PASSWORD@signalserver.umiacs.umd.edu/validator/"
./target/release/personas-bench --server --server-url "$U" --iters 20 --warmup 3 --callbacks 16 --label "laptop to VM" --server-dir target/server-bench-remote --out remote.json
./target/release/personas-bench --server --load --server-url "$U" --label "laptop to VM" --server-dir target/server-bench-remote --out remote-load.json
```

A server restart forgets its bulletin (`docker compose restart validator`); otherwise each
run adds to it. Stop it with `docker compose stop validator`.

The client downloads the whole user bulletin for every proof (`BulNet::get_membership_data`),
so with a real network and a long history, `client` includes that transfer.

## 3. End-to-end in the real app

Start each desktop instance with the log variable set. Every extra member opened from
that app inherits it, and all instances append to the same file:

```bash
PERSONAS_BENCH_LOG="$HOME/personas-e2e.jsonl" "/Applications/Signal Personas.app/Contents/MacOS/Signal Personas"
```

Then use the group normally: send anonymous / pseudonymous / topic posts, rate, vote,
scan, send authorship and badge proofs. Each action writes one `emit` line on the sender
and one `receive` (or `verify`) line on every other member; barriers that invoke
callbacks write `settle` lines. Nothing is logged when the variable is unset.

Analyse:

```bash
python3 deploy/play/bench/e2e.py "$HOME/personas-e2e.jsonl" --json e2e.json
```

Columns: `prove` (engine), `client` (click → ready to hand to Signal), `handle`
(receiver apply), `e2e` (sender start → receiver done, per sender/receiver pair).

Clock note: `e2e` subtracts timestamps from different instances. Instances on one Mac
share a clock. Across machines, sync with NTP and state the expected skew. Browser
members (alice, bob, carol) do not write this log, so use desktop instances for
end-to-end runs.

The log holds envelope hashes, timings and a short group tag. It never holds message
text, names or group IDs.
