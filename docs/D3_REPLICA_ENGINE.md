# d3 — the serverless replica engine

**Status:** implemented in `crates/personas-bulletin/src/replica/`. 14 fast tests +
3 `#[ignore]` end-to-end tests with real Groth16 proofs, all green; `fmt`/`clippy`
clean; the workspace builds. This is the engine that consumes d1's Merkle stores
and enforces the d2 accept rule (`docs/SERVERLESS_PROTOCOL.md`).

Read `SERVERLESS_PROTOCOL.md` first — this document says how the design there is
realised in code, and what is deliberately left to d4/d5.

---

## 1. What it is

Serverless mode has no server: every member runs a **replica** that ingests the
group chat as an ordered log of records and applies the same deterministic accept
rule, computing the same bulletin. *The accept rule is the protocol* (§1). d3 is
that rule plus the state it maintains.

| File | Contents |
|---|---|
| `replica/record.rs` | The serverless `Record` model, the `Ark<T>` arkworks↔serde bridge, the CBOR envelope codec, the envelope hash `Eh`, and `Eh::context()` (`H(eh)`). |
| `replica/tally.rs` | The derived, non-cryptographic state: polls + ballots, the outstanding-ticket settlement set, rating dedup, the persona cache, the rendered log. |
| `replica/mod.rs` | The `Replica` engine: `ingest`, `barrier`, the accept rules, the object-root window, the settlement logic, and journal persistence. |

The engine is generic over the three d1 tree heights (`Replica<OH, MH, NH>`,
defaults 32/32/32), a type-level contract with the verifying keys exactly as in
d1. It takes a `ReplicaKeys` bundle (the Merkle-mode verifying keys from
`generate_merkle_server_keys`) and a `Config` (§14's knobs).

---

## 2. The core idea: convergence by deterministic replay

Convergence (§1) is the whole game: two replicas that have ingested the **same**
records must compute the **same** roots. Two things make that non-trivial, handled
separately:

- **Tree shape is order-free by construction.** The d1 object tree is
  **set-committing** (leaves sorted by commitment; root = a function of the set),
  so the same objects in any order give the same root, and a double-spend is
  arbitrated by the nullifier set (first-reveal-wins), not by ordering. So the
  *final* root converges regardless of arrival order.
- **The buffered-root window still needs the root *sequence* to converge.** A proof
  is pinned to the root of a specific recent subset (§5.1), and two replicas that
  saw the same records in different orders pass through different intermediate
  subsets. Until the Bloom-filter reconciliation lands (deferred — see
  `SERVERLESS_PROTOCOL.md` §5), the engine converges these the blunt way: it
  **replays the whole seen set in a canonical order**, so every replica computes the
  identical sequence of intermediate roots.

The canonical order is §4's: **causal order, tiebroken by ascending envelope
hash.** A record names the object root it was built on, so "root `r` was produced"
is the causal predicate and the smaller `eh` breaks a genuine tie. The engine
realises it by replaying the whole seen set whenever it changes:

```
for each barrier b = 0 .. current_barrier:
    settle_barrier(b)                       # the barrier event fires first (§5.2)
    loop:
        pick the smallest-eh unapplied record whose named root is produced
              (and whose barrier ≤ b); apply it; repeat until none remain
```

This is a pure function of `(the record set, each record's first-seen barrier,
current_barrier)`, so replicas that saw the same records under the same barrier
schedule converge **exactly**, and the rest converge as the schedule catches up
(§5.2's transient-then-closed divergence). Groth16 verification is **memoised by
`eh`** — a proof's validity against the root it names is a fixed fact — so replay
costs one verification per record, not one per rebuild.

**Cost / known limitation.** The rebuild is from-scratch on every ingest:
`O(barriers · n²)` cheap tree/tally operations (the expensive Groth16 is
memoised). That is fine at demo scale (tens–hundreds of records, the M3 target)
but is the obvious thing to incrementalise before d4 drives a long-lived live
stream. The correctness argument does not depend on the rebuild being from-scratch;
an incremental version must reproduce the same canonical order.

---

## 3. The root discipline (the security claim d1 rests on)

d1 assumption 3: *the replica pins a root it derived itself, never a root from a
proof or a peer.* In d3 that is literal:

- **Object membership (monotone).** A post/scan proof is verified against
  `Some(root)` where `root` is one this replica **produced** — held in a window of
  the last `K` roots (`Config::root_window`, default 256). A record naming a root
  outside the window is buffered, then dropped (the prover is too far behind, §5.1).
  The named root is a *hint* telling the verifier which of its own roots to pin; the
  proof only verifies if the prover used that same root.
- **Callback nonmembership (anti-monotone).** A scan's callback roots are the
  replica's **own current-barrier** roots, rebuilt from its own called set. The
  scan record names the barrier it proved against; the engine checks those named
  roots equal its current callback roots and rejects otherwise
  (`"scan names a superseded barrier"`). A stale, pre-ban scan therefore has no
  matching root the instant a replica crosses the ban barrier — the structural O10
  fix, carried into the engine.

The predicate statements (vote, proof-carrying rating) are checked the same way:
their public-input vector `[context, claimed, obj_root]` is assembled **by the
replica** — `context` derived from the referenced record (`Eh::context`), `obj_root`
pinned to a produced root — so a forged context or a stale root simply fails to
verify. `claimed` is the only element the record supplies, and revealing it is the
point (it is what deduplicates one member's votes/ratings).

---

## 4. The barrier, and how a ban becomes enforceable

`Replica::barrier()` is the settlement heartbeat / ban / authority event (§5.2,
§7) — the only thing that advances the callback tree. It is an **event**, not a
clock tick here: the cadence that fires it (§14's `heartbeat_secs`) is the
messenger's business (d4/d5). Each barrier, in order (`settle_barrier`):

1. **Close ban polls** whose window has elapsed (`opened_barrier +
   poll_close_barriers`); a poll that closes `yes > no` marks its target's ticket
   banned. Ban strictly precedes reputation (§7 property 1).
2. **Settle every due or banned ticket, once.** The argument is `BAN_FLAG` if
   banned, else `arg_rep(clamped_rep)` (clamped so reputation can never reach
   `BAN_FLAG`, §7/R8). The call mirrors `ServiceProvider::call`: the additive-OTP
   ciphertext of the argument under the ticket's key, appended to the called set —
   a deterministic function of public data (§6), so every replica computes the
   identical leaf. Every ticket is retired within `W` (`settlement_barriers`),
   including with `arg_rep(0)`, which bounds the outstanding set (§7 property 2).
3. **Re-pin the nonmembership root** over the grown called set.

The barrier event fires **before** the records that arrive at that barrier, so a
scan ingested after a ban is checked against the post-ban callback set — which is
exactly what makes a ban enforceable the moment a replica crosses its barrier.
(This ordering was the one non-obvious bug found in testing: settling *after* the
barrier's records let a stale scan slip through.)

---

## 5. What the tests establish

Fast (no Groth16, always run):

- **codec** — records round-trip; `eh` is a stable function of bytes; distinct
  records get distinct `eh`/context; a future version is refused.
- **tally** — ban polls need strictly more bans than keeps; one member one vote
  (replace-on-recast); one rating per `(target, claimed)`; petnames stable/cached;
  the rendering-gate flag hits only the banned author's posts.
- **engine** — joins converge regardless of arrival order (the canonical ordering);
  a duplicate record is ingested once; a record naming an unproduced root buffers
  without running its proof; the journal replays into an identical tree after a
  restart.

End-to-end with **real Groth16 proofs** (`#[ignore]`, run with
`cargo test -p personas-bulletin --release -- --ignored replica::e2e`):

- `e2e_convergence_out_of_order_delivery` — a join and a post delivered in both
  orders converge; the post applies even when it arrives before the join that
  produces its root.
- `e2e_double_spend_resolves_to_one_winner_everywhere` — two posts spending the
  same object, three arrival orders: the smaller-`eh` one wins on every replica,
  the other is dropped, all roots equal (§4).
- `e2e_ban_propagates_and_absorbs_and_stale_scan_rejected` — the **M3 flagship**: a
  ban poll passes; three replicas cross a barrier and converge on identical object
  *and* callback roots (the ban is visible identically to all); a pre-ban scan is
  rejected as stale (O10); and the banned member's honest post-ban scan **absorbs**
  the ban (`banned = 1`). That absorb is the callback-membership branch d1's review
  package listed as an untested path — d3 now exercises it end to end.

---

## 6. Scope, and what is deferred

**Built (d3):** the accept rules for `Join`, `Post`/`PostPseudo`/`PostPseudoRate`,
`Scan`, `Vote`, `Rate`, `PollOpen`; the object-root window with buffer-vs-drop; the
nullifier-first-wins linearisation; the event-driven barrier with the **derived**
triggers (poll-ban close + reputation settlement); the poll/rating tallies and
persona cache; and append-only journal persistence (a log of records, replayed on
open — `CentralStore` and a live replica are not `CanonicalSerialize`, so the
records that produced the state are what persists).

**Deferred, with seams left:**

- **d4** — the messenger receive loop, full rendering (identicons/chrome/
  threading), and `Snapshot` late-join. `Replica::record_bytes` and `log()` are the
  hooks. `FoldScan` (off by default, §13) is not wired.
- **d5** — the settlement-heartbeat *cadence* that decides when to call `barrier()`.
  d3 builds the barrier mechanism it drives. **Done** (`docs/D5_HEARTBEAT.md`): d5 added
  `Replica::ingest_at` (place a record at a service-timestamp-bucketed barrier) and
  `advance_to` (the heartbeat's settle trigger); `barrier()` is now `advance_to(+1)`. The
  determinism caveat below is **closed** for replicas sharing the heartbeat schedule —
  which, bucketing by the provider's stamp, is all of them.
- **Authorized triggers** `BanInvoke` / `BadgeGrant` (§7, §11) — they need the
  config authority-key list; only their derived cousin, the poll-ban, is
  implemented. Adding them is a record kind plus a signature check against that
  list.
- **Wire unification** — the serverless record model is self-contained rather than
  bumping `personas_wire::VERSION` to 2; that reconciliation belongs to e2, when
  records actually ride Signal.

**Determinism caveat to keep in view (§5.2).** Exact convergence holds for replicas
that assign the same first-seen barrier to each record — i.e. that share the
heartbeat schedule. Replicas whose delivery skews across a barrier boundary diverge
transiently and re-converge once both are past the affected settlements; only a
*persistent* fork on an identical record set is a bug (the fast convergence tests
pin the exact case; g's 3-client integration test should pin the skewed one).
