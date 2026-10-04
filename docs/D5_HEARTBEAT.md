# d5 — the settlement-heartbeat cadence

**Status:** implemented across `transport-api` (`Incoming::Message::received_at`),
`personas-bulletin::replica` (`Replica::ingest_at` / `advance_to`), and
`personas-messenger` (`heartbeat::Heartbeat`, `Messenger::tick` / `run_heartbeat`). New
fast tests for the cadence path (replica + messenger) plus a real-Groth16
skewed-delivery convergence test, all green; `fmt`/`clippy` clean on the new code; the
workspace builds; `personas messenger demo` still runs end to end.

Read `SERVERLESS_PROTOCOL.md` (d2) §4/§5.2/§14 and `D3_REPLICA_ENGINE.md` (d3) §4
first. d3 built the barrier **mechanism** and deliberately left it clock-free ("a
barrier is an event, not a clock tick"). **d5 is the clock.**

---

## 1. What it is

A barrier is the settlement heartbeat: the event at which due tickets settle, ban polls
close, and the callback root re-pins (`D3_REPLICA_ENGINE.md` §4). d3 exposed
`Replica::barrier()` but nothing decided *when* it fires or *which barrier a record
belongs to*. Those are the two questions d5 answers, and it answers them from a **shared
time reference** so the answer is the same on every replica.

| Piece | Where | Contents |
|---|---|---|
| `received_at` | `transport-api::Incoming::Message` | the **service-assigned** receive timestamp (ms) — Signal's `serverReceivedTimestamp`, Slack's `ts`, the mock's own clock. Stamped by the provider, delivered identically to every recipient. |
| `Heartbeat` | `personas-messenger::heartbeat` | maps a `received_at` to a barrier index: `(received_at − genesis_ms) / period_ms`. Shared across the group (anchor + period), like the genesis pin. |
| `Replica::ingest_at` | `personas-bulletin::replica` | ingest a record at a **caller-supplied** barrier (the bucket), rather than the replica's local one. |
| `Replica::advance_to` | `personas-bulletin::replica` | advance "how far has *now* got", settling everything now due — the heartbeat's settle trigger. |
| `Messenger::tick` / `run_heartbeat` | `personas-messenger` | the wall-clock driver: every `period_ms`, advance the replica to the current barrier. Shares the receive loop's `Arc<Mutex<_>>`. |

---

## 2. Why the clock is the service timestamp, not the device's

Two replicas that ingest the same records must agree on each record's settlement
barrier, or they settle its ticket at different times and their callback roots fork
(`SERVERLESS_PROTOCOL.md` §5.2's determinism caveat — the seam d3 left open). If each
replica bucketed a record by *its own* wall clock at the instant it happened to receive
it, ordinary delivery jitter across a barrier boundary would fork honest replicas: A
receives a record at 10:00:59 (barrier *k*), B receives the same record at 10:01:01
(barrier *k+1*), and they never agree.

So the bucket is a function of the **service-assigned** `received_at`, which the
provider stamps once and delivers identically to everyone. Every replica computes the
identical record→barrier map, so convergence is **exact**, not merely eventual. Three
properties make this the right clock, and they were reviewed and signed off (see
`FINDINGS` D9):

1. **It is not the sender's timestamp.** A Signal message *id* is
   `dataMessage.timestamp`, written by the sending client and therefore forgeable (§4).
   `received_at` is the provider's stamp, so a **member cannot backdate** a record into
   an old barrier. That is the security win over bucketing by the message id.
2. **It grants the provider no new power.** §4 already puts the provider inside the trust
   boundary for *delivery* ("delay, withhold, or censor"). Stamping a coarse bucket is
   within powers it already has — it could shove a record across a boundary by delaying
   delivery anyway — and it still cannot forge a proof, mint a member, or invoke a
   callback.
3. **It is only ever a cadence clock.** Never the ordering mechanism (that is
   prefix-order, §4) and never an input to proof acceptance (roots are self-computed,
   §5).

The one thing that still reads a *local* clock is `Messenger::tick`: advancing the
monotone "how far has *now* got" counter so tickets settle even with no traffic. That
never re-assigns a record's bucket, so a skewed local clock settles *late* at worst
(bounded by `W`, self-healing), never at a barrier a peer disagrees with (§5.2(a)).

**Residual caveat (the sign-off item, `FINDINGS` D9).** A malicious provider that hands
*different recipients different* `received_at`s for the same message is a fork vector —
but it is the same class as selective delivery, which §4 already declares out of scope.
Accepted for now; if censorship-resistance is ever pursued, this is one place the
provider's timestamp would need cross-checking.

---

## 3. How it sits on d3, without disturbing it

The engine is unchanged in spirit; d5 adds two entry points and keeps the old ones as
thin wrappers, so every d3/d4 test is byte-identical:

- `ingest(bytes)` still stamps the record with the replica's *local* `current_barrier`
  (delivery-timing dependent — the best-effort path).
- **`ingest_at(bytes, first_barrier)`** stamps it with the caller's bucket. A record
  serviced in a bucket ahead of where the replica has reached pulls `current_barrier`
  forward to it (the provider's stamp is proof time advanced that far). This path is
  **authoritative**: if the record was already present under a *provisional* barrier — a
  sender's optimistic self-fold via `ingest`, which cannot yet know the service
  timestamp — the service-stamped barrier replaces it. That is the "emit-then-ingest-
  own-echo" finalisation (d4/§5.4): a sender's own record converges to the same barrier
  every peer buckets it into.
- `barrier()` is now `advance_to(current_barrier + 1)`; **`advance_to(b)`** is the
  general form the heartbeat drives.

The messenger routes by the presence of a stamp: `received_at == 0` (the sentinel a
transport uses when it has no service clock) falls back to `ingest` (local, best-effort);
a real stamp takes `ingest_at`. The demo and the d3/d4 tests deliver with `received_at =
0` and drive barriers by hand, so they are unaffected; live transports (mock, Signal,
Slack) all stamp a real value.

---

## 4. What the tests establish

Fast (no Groth16):

- **`heartbeat`** — bucketing is relative to the anchor and period; a pre-genesis or
  zero-period input does not panic.
- **replica** — `ingest_at` places a record by its supplied barrier, not the replica's
  current one; an authoritative arrival reconciles a provisional self-fold;
  `advance_to` closes a ban poll on cadence and never rewinds.
- **messenger** — `tick` closes a poll on the shared schedule, driving the whole
  `ingest_incoming` (bucket) → `advance_to` (settle) path with no proofs.

End-to-end with **real Groth16 proofs** (`#[ignore]`,
`cargo test -p personas-messenger --release -- --ignored`):

- **`e2e_skewed_delivery_still_converges_exactly`** — the d5 proof. Four replicas
  receive the same records in different arrival orders and run their heartbeats out of
  step, yet converge on byte-identical roots. The load-bearing replica is an **observer**
  whose clock crosses the poll-close barrier while the ban poll is still tied 0–0; the
  two ban votes then arrive *late*. Because they are bucketed by their service timestamp
  into the barrier they were cast in — not the observer's current one — the from-scratch
  rebuild counts them before the close, the outcome flips from no-ban to ban, and the
  observer converges with everyone. (A device-clock cadence would have stamped the late
  votes past the close and forked.)

The four existing d4 e2e tests and the three d3 e2e tests still pass unchanged.

---

## 5. Scope, and what is deferred

**Built (d5):** the service-timestamp field on the transport boundary; the
`Heartbeat` schedule and bucketing; `Replica::ingest_at` / `advance_to` with provisional
→ authoritative reconciliation; `Messenger::tick` / `run_heartbeat` sharing the receive
loop's lock; fast + real-proof convergence tests.

**Deferred, with seams left:**

- **e2** — a real deployment sets a real `genesis_ms` (out of band, like the genesis pin)
  so barrier indices stay small; the demo/tests use `0`. `run_heartbeat` is the driver a
  live client spawns alongside `receive_loop`; e2's Signal client wires the two together
  and reads `serverReceivedTimestamp` off the real envelope (the parser already does).
- **Incremental rebuild.** The engine still rebuilds from scratch on every ingest and
  every barrier (`O(barriers · n²)`, `D3_REPLICA_ENGINE.md` §2). Fine at demo scale; with
  a live heartbeat driving many barriers over a long-lived stream this is the first thing
  to incrementalise. d5 does not change the rebuild; it only decides when it runs.
- **Journal barrier fidelity.** The append-only journal stores record bytes, not each
  record's first-seen barrier, so a `Replica::open` replay re-buckets at barrier 0. The
  barrier-faithful restore path is the d4 snapshot (`from_records`), which carries the
  schedule; unifying the two is future work.
