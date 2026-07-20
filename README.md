# Cryptographic Personas

An implementation of [*Cryptographic Personas*](https://eprint.iacr.org/2025/1969) — anonymous
group chat where a member can post under a persona, be rated, and be banned, all without anyone
learning who they are. Reputation and revocation are enforced by zero-knowledge proofs against a
public bulletin, not by a server's goodwill.

Two deployments, one protocol:

- **As-a-service** (what runs today): a server verifies each proof and relays the message to
  Signal or Slack through a phantom bot account. The server is trusted to *deliver*, never to
  vouch — it cannot forge a post, ban a member it holds no callback ticket for, or apply a
  rating twice.
- **Serverless** (in progress, workstreams d/e): every member verifies locally against a
  replicated Merkle bulletin, and the messenger is the only infrastructure.

## Running it

Nightly Rust, pinned by `rust-toolchain.toml` (`zk-callbacks` needs `generic_const_exprs`).
Build `--release` — debug Groth16 proving is impractically slow.

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

`personas` is one binary with one flat command set; `--transport signal|slack` picks the route
family. Configuration is layered — built-in defaults, then `deploy/profiles/<name>.toml` (via
`--profile`), then the legacy `PERSONAS_*` env vars, then these CLI flags.

The mock's chat lands in `$PERSONAS_DATA_DIR/signal_chat.jsonl`; the callback ledger sits beside
it in `signal_records.jsonl`. First boot generates ~103 MB of proving keys into a
content-addressed cache; later boots load it in milliseconds.

The end-to-end test worth running is `join` → `post` → `reaction` → `rep` → `scan` → `ban` →
`scan` → `post`, where that last post must be **rejected** ("proof failed. Check if you are
banned"). That rejection is the whole system working.

**Two traps.** A restart forgets who joined (the bulletin's contents are in memory —
[FINDINGS O1](docs/FINDINGS.md)), and `personas scan` answers *one* callback at a time, panicking
if you interact mid-sweep ([O2](docs/FINDINGS.md)).

Use `--profile signal` (with `SIGNAL_BOT_NUMBER` and a `signal-cli` daemon) or `--profile slack`
(with `SLACK_BOT_TOKEN`/`SLACK_APP_TOKEN`) to relay to a real messenger instead.

## Where things are

- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — the crate map, the two kinds of state, the
  wire format, the transports, the route table.
- **[docs/FINDINGS.md](docs/FINDINGS.md)** — bugs fixed, bugs still open, and the decisions that
  want a second opinion. Read this before changing anything.
- **[docs/SERVERLESS_PROTOCOL.md](docs/SERVERLESS_PROTOCOL.md)** — the serverless design: the
  record kinds, the total order, the epoch, the root discipline, and why callbacks are derived
  rather than sent. **Design only; nothing in it is implemented.**
- `crates/personas-core` — types, circuits, proving-key cache.
- `crates/personas-config` — the layered config; `deploy/profiles/*.toml` is the profile matrix.
- `crates/personas-server` — the as-a-service server.
- `crates/personas-client` — one client for both messengers.
- `crates/personas-cli` — the `personas` binary: one flat command set, transport-branched.
- `crates/transports/` — the `Transport` trait and its implementations, including the mock.
- `batch-zkc/` — Privacy Pass, standalone, not yet wired in.
