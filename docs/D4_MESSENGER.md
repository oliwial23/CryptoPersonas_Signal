# d4 — the serverless messenger

**Status:** implemented in `crates/personas-messenger/` (a new crate) plus a small
d3 extension and a `personas messenger` CLI subcommand. 13 fast tests + 4 `#[ignore]`
end-to-end tests with real Groth16 proofs, all green; `fmt`/`clippy` clean on the new
code; the workspace builds; the `personas messenger demo` runs end to end.

Read `SERVERLESS_PROTOCOL.md` (d2) and `D3_REPLICA_ENGINE.md` (d3) first — d3 is the
accept rule and the state it derives; **d4 is what makes that a messenger.**

---

## 1. What it is

d3 gave us a `Replica`: feed it an ordered log of record *bytes*, it applies the
deterministic accept rule and converges on the same bulletin as everyone else — but
it is receive-only, speaks only in bytes, and has no way to *make* the records a
member sends. d4 closes all three gaps by tying a `Transport` (the mock today, real
Signal under e2) to a replica.

| File | Contents |
|---|---|
| `carriage.rs` | Records ⇄ chat messages: a record's bytes are base64'd behind a marker (`PZR2:`) in the message body, or ride as an attachment above ~32 KB (only `FoldScan`, which is off). `decode` cleanly separates protocol records from human chatter. |
| `member.rs` | The **send side**: a `Member` (a zk `User` + the Merkle-mode *proving* keys) that produces every serverless record — `Join`, anon/pseudo/pseudo-rate `Post`, `Vote`, `Rate`, `PollOpen`, `Scan` — proving against the replica's own trees. The mirror of d3's `ReplicaKeys` (the verifying halves). |
| `render.rs` | Headless rendering: the accepted log as `~petname: message`, with the `~` sigil so a persona is never mistaken for a messenger account, and a `⚠ [revoked persona]` flag for the rendering gate (§9). |
| `snapshot.rs` | Late join (§12): a `Snapshot` is the seen record log + barrier + a genesis pin; a joiner adopts it TOFU-pinned to its inviter and re-derives all roots itself. |
| `lib.rs` | The `Messenger`: `emit_*` (produce a record, fold it into the sender's own replica), `broadcast`/`send_*` (async, over the transport), `ingest_incoming`, `barrier`, `snapshot`/`adopt`, `render`, and a `receive_loop`. |

`Messenger<OH, MH, NH>` is generic over the three d1 tree heights, defaulting to the
production heights; tests instantiate it at tiny heights with in-process keygen,
exactly as d3's e2e tests do.

---

## 2. The send side, and why it can't reuse the service `exec_*` helpers

Serverless has no server to prove against: a `Member` proves membership against the
**Merkle trees the replica derived itself** (`Replica::obj_store` /
`callback_store`, two read-only accessors this workstream added to d3). The proof it
produces is then re-verified on ingest like any other record — the co-located member
gets no trust; it just reads state to build a witness.

The one non-obvious constraint: `personas_core`'s `exec_standint` /
`exec_pseudo_standint` / … all pass `is_memb_data_const = true`. That is correct when
the object bulletin's public data is a fixed verification *key*, and **wrong** for
Merkle mode, where it is a **root** that changes every append and must be a public
input (`SERVERLESS_PROTOCOL.md` §5.3). So `member.rs` calls `exec_method_create_cb` /
`interact` / `prove_statement_and_in` directly with `false`, matching d3's e2e tests.
Two upstream footguns are pre-guarded rather than hit: `exec_method_create_cb`
`unwrap`s an absent membership witness (→ `MemberError::NotJoined` first), and
`get_scan_arguments` asserts there is at least one outstanding callback (→
`NothingToScan`).

**Optimistic object state (a left seam).** A post advances the member's object
immediately, before the record is accepted. On the serial path — post, let it land,
post again — that optimism always holds. Under real concurrency a post can be reorged
out or lose a double-spend linearisation (§5.4/§13) and the member must **re-base**
its in-flight object; that state machine is d4's acknowledged seam (`FINDINGS` O2).
This client produces one interaction at a time and lets it land (the `emit`-then-
ingest-own-echo flow).

---

## 3. Snapshot late join = record-log replay, not a roots checkpoint

§12 describes a snapshot as "an epoch, the roots, the nullifier set, the called set,
the open tallies." In this codebase the replica **derives** every one of those from
the record log (d3), so the faithful snapshot is the log itself: the
`(first_barrier, bytes)` of every seen record plus the barrier it was taken at. The
joiner feeds them to `Replica::from_records` (a d3 extension) and **re-derives the
roots itself**. This is stronger than trusting peer-supplied roots:

- **Not a soundness break (§12).** A forged snapshot cannot make the joiner accept a
  forged proof — the proof still verifies against roots the joiner computed, and a
  root the group does not share makes the joiner's *own* later proofs unacceptable to
  everyone, loudly.
- **It is a view-integrity assumption**, answered by TOFU over the inviter. The
  genesis pin is a digest over the snapshot's records (in canonical order); the
  inviter shares its hex out of band, and `adopt` refuses a snapshot that does not
  match — closing the in-transit tampering gap, so the residual trust is exactly "my
  inviter vouched for this state."

The faithful snapshot carries each record's **first-seen barrier** because d3's state
is a function of `(record set, per-record first_barrier, current_barrier)` — dropping
the barrier schedule would diverge on settlement timing (§5.2's determinism caveat).

---

## 4. The d3 extensions this needed

d4 added four small, read-only-ish methods to `Replica` (d3's engine is otherwise
untouched):

- `obj_store()` / `callback_store()` — read-only views a co-located member proves
  against (§2).
- `seen_with_barriers()` — the `(first_barrier, bytes)` list a snapshot is built from,
  in canonical order.
- `from_records(keys, config, records, current_barrier)` — rebuild a replica from a
  snapshot, reproducing the barrier schedule so an adopted snapshot computes
  byte-identical roots to its source (§3).

It also wired `ensure_merkle_keys(data_dir)` in `merkle::params` — the
`MERKLE_BULLETIN_MODE` disk cache d1 defined but left unused. The messenger needs a
warm boot to be usable; merkle keys depend only on the circuits (not any store's
contents), so the mode-tagged subdir is the whole cache key. First run generates the
51 MB bundle (height-32 keygen, minutes); later runs load it in ~100 ms.

---

## 5. What the tests establish

Fast (no Groth16, always run — carriage / render / snapshot modules + one
lib-level carriage round-trip of a no-proof `PollOpen`):

- **carriage** — small records ride inline and round-trip; large ones become an
  attachment; chatter and corrupt payloads decode to `None`, never a panic.
- **render** — a pseudonym renders with the `~` sigil, an anon post as `(anonymous)`,
  a banned author's post is **flagged not dropped**, scans are omitted from the chat.
- **snapshot** — round-trips, the pin is stable, a wrong pin / tampering / a future
  version are all refused.

End-to-end with **real Groth16 proofs** (`#[ignore]`, run with
`cargo test -p personas-messenger --release -- --ignored`):

- `e2e_convergence_ban_and_flag` — the **M3 flagship** through the full pipeline:
  three members join, one posts under a persona, a ban poll passes, and after a
  barrier all three replicas converge on identical object *and* callback roots, render
  the offending post **flagged identically**, and the banned member's honest scan
  absorbs the ban (`banned = 1`).
- `e2e_stale_scan_is_rejected_after_the_ban` — O10 carried through the messenger: a
  pre-ban scan (nonmembership against the empty callback set) is `Rejected("scan
  names a superseded barrier")` once a replica has crossed the ban barrier (§5.2).
- `e2e_snapshot_late_join` — a joiner adopts a snapshot with the right pin and
  re-derives identical roots and an identical view; a wrong pin is refused.
- `e2e_poll_rides_the_live_transport` — a poll sent over the real mock transport
  reaches an observer through `subscribe` + carriage + ingest (the live wiring).

And `personas messenger demo` runs the M3 scenario from the CLI, printing each
replica's converging view and the ban taking effect.

---

## 6. Scope, and what is deferred

**Built (d4):** the carriage codec; the `Member` send side for every serverless
record with real proofs; headless rendering with the persona sigil and the flag gate;
`Snapshot` late-join (record-log TOFU); the `Messenger` (produce/broadcast/ingest/
render/snapshot/adopt + a receive loop); the merkle-key disk cache; and the
`personas messenger demo` CLI.

**Deferred, with seams left:**

- **d5** — the barrier **cadence** (when `barrier()` fires). d4 exposes the trigger;
  d5 decides the settlement heartbeat. **Done** (`docs/D5_HEARTBEAT.md`): a `Heartbeat`
  buckets each incoming record by its service-assigned `received_at`, and
  `Messenger::tick` / `run_heartbeat` drive settlement on a shared schedule — sharing the
  `receive_loop`'s lock.
- **e2** — the real Signal transport (`transport-presage`) plugs in behind the same
  `Transport` trait; the interactive multi-process client, the persona-state
  persistence, and the Signal-Desktop rendering patch live there. `FoldScan` (off by
  default, §13) uses the carriage attachment path, which exists but is unexercised on
  the demo path.
- **Re-base loop** (§13/O2) — the optimistic-object state machine for concurrent
  posting (§2). This client posts serially and lets each record land.
- **Authorized triggers** `BanInvoke`/`BadgeGrant` (§7/§11) remain d3/config work; the
  messenger sends the derived poll-ban path only.
