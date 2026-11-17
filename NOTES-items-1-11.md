# Items 1 and 11: server epochs on a public schedule; clients check key rotations

Branch `protocol-alignment-items-1-11`, off `protocol-alignment`. No circuit, constraint
system, or proving/verifying key changed, and no key was regenerated. Nothing under
`deploy/`, `Signal-Desktop-Persona-main/`, or `third_party/` was edited. The serverless
deployment (`personas-bulletin` replica, `personas-messenger`) is untouched.

## What changed

### Item 1: the server's epoch follows a public schedule

- **Config** (`crates/personas-config/src/lib.rs`): `ServerConfig` gains `epoch_start`
  (`PERSONAS_EPOCH_START`: unix seconds or RFC 3339) and `epoch_secs`
  (`PERSONAS_EPOCH_SECS`, default 86400). `epoch_start_unix()` parses the start, and
  `validate()` rejects a zero length or an unparseable start. The new fields are read the
  same way as the other legacy env vars (env overrides profile). Adds a `chrono` dependency
  (already in the workspace).
- **Shared types** (`crates/personas-core/src/schedule.rs`, new): `EpochSchedule {start,
  length}` with `epoch_at(now) = floor((now - start) / length)` (0 before the start),
  `boundary(e)`, `current()`; and the rotation-log types `RotationEntry`,
  `RotationReason {genesis, epoch, ban}`, `BanRef`.
- **Epoch clock** (`crates/personas-server/src/epoch.rs`, new):
  - `resolve_schedule`: the configured start, or else the server's first start, written to
    `data_dir/epoch_start` and reread on later starts. Either choice is logged.
  - `catch_up`: under the state write lock, turns the callback bulletin
    (`callback_bul.update_epoch`, timed through `bench::epoch_updated` as before) as many
    times as it is behind the schedule. Then, if the rotation log has no key for the
    target epoch yet, it rotates the ticket key **once**.
  - `spawn`: a tokio task that sleeps until the next boundary (capped at 60 s, so a clock
    moved backwards is noticed) and calls `catch_up`. This does what
    `moderation::update_epoch` did: the bulletin turn plus `rotate_ticket_key`.
  - `main.rs` resolves the schedule, checks the rotation log against the key on disk
    (below), catches up, then spawns the clock before serving.
- **Route removed**: `GET /api/epoch` and its handler (`moderation::update_epoch`) are
  deleted. Nothing reachable over HTTP turns the epoch any more.
- **Schedule published**: `/api/get_epoch` returns `{epoch, start, length}`.
- **Client** (`crates/personas-client/src/flows.rs`, `rotation.rs`):
  - `epoch()` pins the schedule in `<state dir>/epoch_schedule.json` the first time it sees
    it, and refuses a different schedule later.
  - It checks the served epoch equals `epoch_at(now)` by the client's clock, accepting
    either side of a boundary within `CLOCK_SKEW_SECS = 30` s (capped at a quarter epoch).
    Otherwise it fails with a clear error.
  - `epoch_schedule()` exposes the pinned schedule.
  - `wait_for_next_epoch(max_wait)` sleeps to the next boundary and returns once the server
    reports the new epoch.
- **Callers of `/api/epoch`**:
  - The bench's `turn_epoch` is replaced by `next_epoch`; details under "The bench" below.
  - The CLI's `update-epoch` (`personas-cli/src/{signal,slack,parse}.rs`) keeps its name,
    because `crypto_personas/experiment_script.py` calls it. It now waits at most 15 min for
    the next boundary and prints the new epoch; if the boundary is further away it fails
    at once.
  - Docs updated: `docs/ARCHITECTURE.md`, `docs/FINDINGS.md`, `docs/RUNNING_CLI.md`,
    `docs/SERVERLESS_PROTOCOL.md`, `crypto_personas/README.md`.

**Catch-up turns rather than setting the epoch.** zk-callbacks has no setter: each
`update_epoch` increments the epoch and re-signs the nonmembership ranges. The server
keeps no bulletin across restarts (FINDINGS A1), so start-up catch-up turns an empty
bulletin `n` times. That is cheap and ends in the same state as a server that stayed up.
Setting the field directly would have meant editing `third_party/`.

The key rotates once per catch-up, not `n` times: the intermediate keys would never be
served, and the client allows at most one epoch rotation per boundary. A schedule more
than 1,000,000 epochs ahead of the bulletin is refused as a misconfiguration (for example,
a start given in milliseconds).

### Item 11: every issuer-key rotation is logged, and clients check it

- **Server**:
  - `RotationLog` (`state/ledger.rs`) is an append-only, fsynced
    `data_dir/privpass_rotations.jsonl`. Each line is `{seq, epoch, reason, ban?, pubkey}`,
    where `pubkey` is hex of exactly the bytes `/api/privpass/pubkey` serves. The log is
    served whole at the new `GET /api/privpass/rotations`.
  - Unlike the other ledgers, an unreadable or out-of-order row is a start-up error, not a
    skipped row.
  - `rotate_ticket_key(st, RotationCause)` appends each rotation.
  - The first start logs its key as `genesis`. If the key on disk is not the log's last
    entry (the server stopped between replacing the key file and logging), the server
    refuses to start and names the files, rather than serve a key every client would refuse.
  - On a ban, `moderation::ban` cites the ban's entry in the public callback bulletin: the
    `index` in `callback_bul.memb_called_cbs` (the order `/api/callbacks/bulletin` serves)
    and the `ticket` as uncompressed hex. `call` has just appended that entry.
- **Client**:
  - `privpass_issuer_pubkey` now returns `Result` and never panics on a bad key.
  - It keeps the last accepted key in `<state dir>/privpass_issuer_key.hex`. When the served
    key differs, it fetches the log and the pinned schedule and runs
    `rotation::check_rotations`; only then does it save and use the key.
  - That check requires:
    - The served key equals the log's last entry.
    - The log is well formed:
      - `seq` runs consecutively from 0, starting with a single genesis entry.
      - Epoch rotations are strictly increasing, so at most one per epoch.
      - No entry is ahead of the schedule by the client's clock (skew allowed).
      - Each ban rotation falls in the epoch of the last turn before it.
      - No bulletin entry is cited twice.
    - Every ban rotation after the last accepted key cites a callback-bulletin entry that
      exists, holds the named ticket, and was called in that epoch.
    - The last accepted key appears in the log; if it is missing, the log was rewritten and
      the key is refused.
  - On first use (no accepted key) the served key is accepted if it ends a well-formed log
    (trust on first use).
  - `request_and_validate` now checks the key **before** proving and submitting the ticket
    request. The live run found that a refusal after submission left the member's saved
    object behind the bulletin, because the server had already appended the interaction.
- **Unit tests** (`crates/personas-client/src/rotation.rs`):
  - `accepts_a_valid_sequence`.
  - `rejects_an_unexplained_extra_rotation`: a ban the bulletin does not show, a ban citing
    nothing, an epoch rotation ahead of the schedule, a second genesis, a rewritten log.
  - `rejects_a_key_that_is_not_the_logs_last_entry`.
  - `rejects_two_epoch_rotations_in_one_epoch`.
  - Also: the epoch/skew check and schedule pinning.
- Other new tests: `schedule.rs` (epoch arithmetic, log entry serde) and `personas-config`
  (`the_epoch_start_reads_unix_seconds_or_rfc3339`).

### The bench

- `personas-bench --server` starts its server with `PERSONAS_EPOCH_START=<now>` and
  `PERSONAS_EPOCH_SECS=--epoch-secs` (new flag, default 120).
- `next_epoch` replaces `turn_epoch`: it calls `PersonaClient::wait_for_next_epoch`.
- The epoch rule means a member must sweep before its first interaction in each epoch, so
  every stretch of posting must stay inside one epoch. The run starts each stretch at a
  boundary:
  1. Wait for a boundary; then posts, vote, claims and Privacy Pass.
  2. Wait; the scanning member posts.
  3. Wait; the sweep, then the folding member joins and posts.
  4. Wait; the fold.
- Waiting adds about 4 × 120 s to a run.
- With `--server-url`, the run refuses a server whose epochs exceed 15 min, and says to
  start that server with a short `PERSONAS_EPOCH_SECS`.

## Test commands and results

All run on this branch, 4-core container, nightly from `rust-toolchain.toml`. The
container needed `apt-get install protobuf-compiler` first (see question 8).

| command | result |
|---|---|
| `cargo build --workspace` | builds; the only warning is the pre-existing `zk-callbacks` `unused_features` one |
| `cargo test --workspace --release` | all pass: 174 passed, 40 ignored, 0 failed (includes the 6 `rotation::tests`, 2 `schedule::tests`, and the config test) |
| `cargo test --release -p personas-bulletin -- --ignored` | 15 passed, 0 failed |
| `cargo test --release -p personas-messenger -- --ignored --skip e2e_record_converges_over_signal` | 23 passed, 0 failed |
| `cargo build --release -p personas-bench -p personas-server` then `target/release/personas-bench --server --callbacks 5 --iters 1 --server-dir <fresh> --out <tmp>/out.json` | every op finished: post, vote, merge_personas, rep_at_least, pp_request, pp_post, scan (5 callbacks), fold (5 callbacks). The server log shows the epoch turning exactly on each 120 s boundary (06:02:48, 06:04:48, …) with one `Epoch` rotation each. Wall time 8m09s, about 8 min of it waiting for boundaries.  Re-run on the final commit: see the line below. |

Final-commit bench re-run (after the last client change): every op finished again, exit 0, wall time 8m09s; numbers within noise of the table below.

Excerpt of the first run's table (ms):

```
operation        client ms   server ms    round trip  client after   proof bytes
fold               8812.98       17.68        136.21             —       4930768
merge_personas      235.28        5.49          6.83             —             —
post                247.03        4.79          7.82             —             —
pp_post               0.12        1.07          2.70             —             —
pp_request          359.76        7.63             —          1.30             —
scan                459.19        2.34          5.41             —           248
vote                228.66        5.11          7.59             —             —
```

**Manual rotation run** (CLI against a server with `PERSONAS_EPOCH_SECS=90`):
1. Member A joins and requests a ticket: first use, key `fb44…`.
2. B posts and is banned. The log gains `ban` entry seq 2, citing bulletin index 0.
3. A requests again. It fetches key `3dd0…`, checks the ban against
   `/api/callbacks/bulletin`, and accepts it.
4. `update-epoch` waits for the boundary to epoch 2. A scans (both scans verified),
   requests again, and accepts key `3167…` (an `epoch` rotation).
5. The server is restarted. It catches up to epoch 2 with no new rotation (still 4 log
   entries).
6. A then redeemed a ticket. The stash handed out its oldest ticket, issued under the
   pre-ban key, and the server refused it as expired. That is the expected behaviour: the
   client drops refused tickets, and the bench shows fresh tickets redeem.

An earlier attempt with 40 s epochs crossed boundaries mid-sequence. It surfaced two real
issues, both fixed in the last commit:
- The ban-reference check first required the bulletin argument to be `BAN_FLAG`, but the
  bulletin stores arguments encrypted (question 1).
- A key refused after the ticket request had been submitted left the member's saved object
  behind the bulletin; the key is now checked before the request.

## What I could not verify

- **No automated test covers a ban rotation end to end.** The bench never bans. I checked
  it by hand instead (the manual run in the results): a member accepted the key after a ban
  rotation, which needs the bulletin lookup, and after an epoch rotation. A server restart
  caught up to the schedule without a spurious rotation. There is no HTTP-level test
  harness for `personas-server` to make this an automated test.
- `deploy/`: no script there calls `/api/epoch` directly. `deploy/play/bench/e2e.py` reads
  `update_epoch` timings from the server's `json_files`. The server still writes those (each
  scheduled turn is timed under the same label), but I did not run that script. Deployments
  should set `PERSONAS_EPOCH_START` explicitly. The `deploy/` profiles do not set it, so a
  fresh deployment uses its first start, logged and persisted.
- The Signal-Desktop app was not built or run. It talks to the serverless path, which this
  branch does not touch.

## Open questions for the maintainer

1. **Ban references cannot prove "this was a ban".** *Resolved after review: bans are now
   signed by the group admin.* The callback bulletin stores each call's argument encrypted
   to the ticket's owner, so a bulletin entry alone could not show a call was a ban; the
   server could have rotated once per public callback invocation (ratings included). Now:
   - The admin makes an Ed25519 key pair (`personas admin-keygen --out <file>`). The server
     gets the public key (`PERSONAS_ADMIN_PK`) and publishes it at `/api/admin_key`; the
     admin's client signs with the secret (`PERSONAS_ADMIN_KEY_FILE`).
   - `/api/ban` refuses a request without the admin's signature over
     `("personas/ban/v1", epoch, ticket)` (`personas_core::moderation`). Before this the
     route had no authentication at all: anyone could fetch a message's callback from
     `/api/cb` and ban its author.
   - The ban rotation's `BanRef` carries the signature. Clients pin the admin key
     (`PERSONAS_ADMIN_PK` if set, else the first one the server publishes) and check every
     ban rotation in the log against it: right ticket, right epoch, admin's key.
   - So the issuer key rotates only on the published schedule or on a ban the admin
     signed; the server alone cannot add a rotation.
   - Checked live: an unsigned ban and a ban signed with another key got 403, the admin's
     ban went through, a member accepted the post-ban key after checking the signature,
     and a client trusting a different admin key refused the server.
2. **Restarts and old bans.** The bulletin is not persisted (A1), but the rotation log is.
   A client whose last accepted key predates a restart, with a ban rotation in between,
   will find that ban's entry gone and refuse the key. Its object is gone too (A1), so it
   has to rejoin anyway. Deleting `privpass_issuer_key.hex` (or a fresh state dir) resets
   it to trust on first use. Persisting the callback bulletin would fix this properly.
3. **Clock skew.** 30 s either side of a boundary, capped at a quarter of an epoch so short
   test epochs stay meaningful. Is 30 s right for daily epochs? Proofs straddling a boundary
   are rejected by the server regardless, since the epoch is a public input.
4. **Trust on first use.** A brand-new client accepts whatever key ends a well-formed log.
   A server that serves a different log to a newcomer is caught only by comparing logs
   across members, out of band. Worth stating in the paper's threat model.
5. **Default start.** With no `PERSONAS_EPOCH_START`, epoch 0 is the server's first start.
   For the "publicly computable" property, a deployment should publish an explicit start
   (for example, midnight UTC of launch day); the paper text could say so.
6. **Catch-up rotates once.** After downtime of several epochs, the log shows one epoch
   rotation for the new epoch, not one per missed boundary. The client accepts this, since
   at most one rotation per boundary is allowed and fewer is fine. The paper might note that
   rotations may be skipped during downtime.
7. **CLI `update-epoch`.** Kept for `crypto_personas/experiment_script.py`, now a wait. With
   daily epochs that script will fail at that step unless its server runs with a short
   `PERSONAS_EPOCH_SECS`.
8. **Build prerequisite.** A fresh environment needs `protoc` (`apt-get install
   protobuf-compiler`) for the `spqr` dependency of the Signal transport. This is not
   related to these items, but the workspace build fails without it.
