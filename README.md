# Cryptographic Personas

An implementation of [*Cryptographic Personas*](https://eprint.iacr.org/2025/1969): anonymous
group chat where a member can post under a persona, be rated, and be banned, all without anyone
learning who they are. Reputation and revocation are enforced by zero-knowledge proofs against a
bulletin board, not by anyone's goodwill.

The repository holds two implementations of one protocol.

- **Serverless Signal (the main implementation).** Every member's Signal Desktop runs a local
  validator: it proves its own actions and verifies, orders and applies everyone else's.
  Signal delivers end-to-end encrypted group messages as usual and is unaware of personas.
  Nobody is trusted with the group's state. Persona posts travel under a shared "phantom"
  identity, so Signal cannot tell members apart. Optionally (`PERSONAS_VIEW_CHECKS=1`, off by
  default while its privacy cost is reviewed), every record carries a hash of its sender's
  view of the group, so a Signal service that shows members different messages is detected
  (`docs/SERVERLESS_PROTOCOL.md` §5.5).
- **Server-based (cryptographic personas as a service).** A validation server verifies each
  request and relays it to Slack or Signal. It enables the two optimizations that need a
  trusted party: precomputed tickets (Privacy Pass) and server-side verification of folded scans.

Nightly Rust, pinned by `rust-toolchain.toml` (`zk-callbacks` needs `generic_const_exprs`).
Build with `--release`: debug Groth16 proving is impractically slow. Proving keys are generated
on first run (tens of MB, a few minutes) and cached; they are not committed.

## Serverless Signal

| Where | What |
|---|---|
| `crates/personas-core` | Circuits, types and proving keys (shared with the server-based code). |
| `crates/personas-bulletin` | The Merkle bulletin and the **replica engine**: the deterministic accept rule every member runs, barriers, view digests. |
| `crates/personas-messenger` | A member: replica + proving, record carriage, heartbeat, late join, relays. |
| `crates/personas-node` | The native addon that puts the messenger inside Signal Desktop. |
| `Signal-Desktop-Persona-main/` | Modified Signal Desktop (`ts/services/personas*.ts`). |
| `deploy/play/` | The hosted demo (browser-playable members, downloadable app). |
| `PERSONAS_SERVER_DEPLOY.md` | Deploying the private Signal test server the demo runs on (UMIACS VM). |
| `deploy/play/bench/` | Benchmarks: the operation, history and folding runs, and end-to-end timing from the app. |
| `docs/SERVERLESS_PROTOCOL.md` | **The protocol.** Records, order, roots, barriers, views (§5.5), moderation. |
| `docs/SERVERLESS_SIGNAL_DESIGN.md`, `docs/D*.md` | Design notes per workstream (bulletin, replica, messenger, heartbeat). |

Tests:

```sh
cargo test -p personas-bulletin -p personas-messenger --release -- --include-ignored \
    --skip e2e_record_converges_over_signal      # that one needs a live Signal server

# Four members as separate processes, running the Desktop addon at production sizes,
# with Signal simulated (including a Signal that withholds messages):
node Signal-Desktop-Persona-main/packages/personas-engine/test/views.mjs <keys dir>
```

Rebuild the addon after changing Rust code: `Signal-Desktop-Persona-main/packages/personas-engine/build.sh`.
Running the app against a private Signal server is described in `deploy/play/README.md` and
`deploy/signal-test-server/README.md`.

## Server-based (as a service)

| Where | What |
|---|---|
| `crates/personas-server` | The validation server. |
| `crates/personas-client`, `crates/personas-cli` | The client library and the `personas` command-line client. |
| `crates/personas-wire`, `crates/personas-config` | Wire format; layered configuration (`deploy/profiles/*.toml`). |
| `crates/transports/` | Delivery to Slack, Signal (`signal-cli`) and a mock chat. |
| `batch-zkc/` | Precomputed tickets (batched Privacy Pass issuance). |
| `crypto_personas/` | Experiment scripts and notebooks for the server-based evaluation. |
| `instr.md` | Walkthrough of the precomputed-ticket commands. |
| `docs/ARCHITECTURE.md`, `docs/FINDINGS.md` | Crate map and route table; bugs found and open decisions. |

Running it locally:

```sh
cargo build --release --bin server --bin personas

# The `local` profile relays to an in-process mock chat and needs no credentials.
PERSONAS_PROFILE=local PERSONAS_BIND=127.0.0.1:3010 ./target/release/server &

P=(--transport signal --api http://127.0.0.1:3010 --data-dir /tmp/d/client)
./target/release/personas "${P[@]}" join
./target/release/personas "${P[@]}" post -m "hello" -g demo-group          # anonymous
./target/release/personas "${P[@]}" gen-pseudo
./target/release/personas "${P[@]}" post-pseudo -m "hello" -g demo-group -i 1   # as a persona
```

`--transport signal|slack` picks the route family. Configuration is layered: built-in
defaults, then `deploy/profiles/<name>.toml` (via `--profile`), then the `PERSONAS_*`
environment variables, then CLI flags. The mock's chat lands in
`$PERSONAS_DATA_DIR/signal_chat.jsonl`, with the callback ledger beside it in
`signal_records.jsonl`.

The end-to-end check worth running is `join` → `post` → `reaction` → `rep` → `scan` → `ban` →
`scan` → `post`, where the last post must be **rejected** ("proof failed. Check if you are
banned").

Two traps: a restart forgets who joined (the bulletin is in memory,
[FINDINGS O1](docs/FINDINGS.md)), and `personas scan` answers one callback at a time
([O2](docs/FINDINGS.md)). Use `--profile signal` (with `SIGNAL_BOT_NUMBER` and a `signal-cli`
daemon) or `--profile slack` (with `SLACK_BOT_TOKEN`/`SLACK_APP_TOKEN`) to relay to a real
messenger.

## Shared and vendored

- `third_party/zk-callbacks`: zk-promises (the paper's base library), vendored.
- `third_party/presage`, `third_party/libsignal-service-rs`: patched Signal libraries for
  `transport-presage`, the headless Signal client used by the messenger's live-network test.
- `crates/personas-group-crypto`: the shelved "A2" phantom-key design, still used by
  `transport-presage`; Signal Desktop does not use it.
