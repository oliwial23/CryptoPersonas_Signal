# Running the e2 (modified Signal client) locally

A step-by-step guide to actually running `transport-presage` — the PPRF-encrypted
content cipher (Phase A2) riding over a real, private Signal server — on your own
machine. This is **not** a walkthrough of the design; see
[`SERVERLESS_SIGNAL_DESIGN.md`](SERVERLESS_SIGNAL_DESIGN.md) for that. This is purely
the "how do I get this to run" checklist.

You do **not** need a pre-existing Signal account, phone number, or group id for any
of this. Every account, number, and group secret used below is a throwaway, created
fresh by the code each time you run it.

---

## Two ways to run this, from lightest to heaviest

|                               | What it proves                                          | What it needs                                            |
| ----------------------------- | ------------------------------------------------------- | -------------------------------------------------------- |
| **Track 1 — unit tests**      | The PPRF encryption/decryption logic itself is correct  | Just Rust                                                |
| **Track 2 — full end-to-end** | A real record rides over a real (private) Signal server | Rust + Docker + a JDK + a private Signal-Server checkout |

Start with Track 1. It's fast, needs no extra installs, and directly tests the
crypto. Only move to Track 2 if you want to see it actually talk to a (fake, private)
Signal server.

---

## Track 1 — just the crypto (one terminal, a few minutes)

**Install:** Rust, via [rustup](https://rustup.rs):

```sh
curl https://sh.rustup.rs -sSf | sh
```

The repo pins its own toolchain version (`rust-toolchain.toml`), so you don't need to
select one manually — `cargo`/`rustc` will fetch the right one automatically the
first time you build inside the repo.

**Run:**

```sh
cd personas-main
cargo test -p transport-presage --lib pprf_cipher
```

If everything passes, the PPRF cipher's encrypt/decrypt, concurrency-safety, replay
rejection, re-key exclusion, and tamper detection all check out. Done — no server,
no Docker, no accounts.

---

## Track 2 — the full thing, over a real (private, self-hosted) Signal server

### What gets installed, once

1. **Rust** — same as Track 1, if you haven't already.

2. **A JDK (version 25).** Signal-Server (the software this stands up locally) is a
   Java project.

   ```sh
   brew install --cask temurin@25
   ```

3. **Colima + Docker.** The server's dependencies (databases etc.) run in disposable
   Docker containers. Use Colima, not Docker Desktop.

   ```sh
   brew install colima docker
   colima start --cpu 4 --memory 8 --disk 60
   ```

4. **The Docker Compose v2 plugin** (one of the test dependencies needs `docker
compose` specifically):

   ```sh
   brew install docker-compose
   mkdir -p ~/.docker/cli-plugins
   ln -sfn "$(brew --prefix)/opt/docker-compose/bin/docker-compose" ~/.docker/cli-plugins/docker-compose
   docker compose version    # should print v2.x.x
   ```

5. **A local checkout of Signal's own server code** (a separate project, not part of
   this repo — this repo only vendors config to point at it):

   ```sh
   git clone https://github.com/signalapp/Signal-Server.git ~/Repos/Signal-Server
   git -C ~/Repos/Signal-Server checkout ed90c1c15c1dcd72b7adfec25d92cafc6b61da22
   ```

   The specific commit matters — this repo's setup was validated against exactly
   that revision.

6. **The FoundationDB client library** (macOS only — Linux gets this from a package
   instead; see `deploy/signal-test-server/README.md` if you're on Linux):
   ```sh
   cd personas-main/deploy/signal-test-server
   ./setup-fdb-client.sh
   ```

None of steps 2–6 need to be repeated on future runs — they're one-time machine
setup. Step 7 below (building the fake server + generating TLS certs) also only
needs to be redone if you delete `.local/`.

### The 3-terminal layout

Everything in this project (the fake Signal server, the TLS proxy in front of it,
and the actual test/example you're running) needs to stay up simultaneously, so you
need **three terminal windows/tabs**, each left running:

```
┌─────────────────────────┐   ┌─────────────────────────┐   ┌─────────────────────────┐
│ Terminal 1               │   │ Terminal 2               │   │ Terminal 3               │
│                           │   │                           │   │                           │
│ The fake Signal server    │   │ The TLS proxy in front    │   │ Whatever you're actually │
│ itself (Java process).    │   │ of it (a Caddy container  │   │ running: the example or  │
│ Runs in the foreground,   │   │ terminating HTTPS on      │   │ the test. Runs once,     │
│ blocks the terminal.      │   │ :8443, since the modified │   │ finishes, exits — this   │
│                           │   │ client always speaks TLS).│   │ terminal is free between │
│ Leave running.            │   │ Runs detached (a Docker   │   │ runs.                    │
│                           │   │ container); the command   │   │                           │
│                           │   │ itself returns.           │   │                           │
└─────────────────────────┘   └─────────────────────────┘   └─────────────────────────┘
```

**Terminal 1 — boot the fake Signal server:**

```sh
cd personas-main/deploy/signal-test-server
./boot.sh
```

First boot is slow (Maven downloads a large dependency tree — cached afterward).
Later boots take about 1–2 minutes. Wait for a line like:

```
Started application@...{HTTP/1.1, (http/1.1, h2c)}{0.0.0.0:8080}
```

You'll also see a background job repeatedly fail trying to reach `a-bucket.s3.a-region.amazonaws.com`
— that's expected noise (a placeholder S3 config for a badge/remote-config poller
that test-server mode never wires up to anything real). Ignore it.

**Optional sanity check**, from any other terminal, once Terminal 1 says it's started:

```sh
cd personas-main/deploy/signal-test-server
./verify.sh
```

Expect `pong`, a session id, then `"verified":true`.

**Terminal 2 — start the TLS proxy:**

```sh
cd deploy/signal-test-server
./tls-proxy.sh up
```

This prints a `NOTE:` about copying a freshly generated CA certificate the **first**
time it creates one (i.e., the first time you ever run this, or any time you delete
`.local/tls/`). If it prints that note, do the copy it tells you to:

```sh
cp deploy/signal-test-server/.local/tls/ca.crt third_party/libsignal-service-rs/certs/personas-test-server-ca.pem
```

Skip this if the note doesn't appear (it means the proxy reused an existing CA that
the client already trusts).

You can check its status later with `./tls-proxy.sh status`, and stop it with
`./tls-proxy.sh down` when you're done for the day.

**Also in Terminal 2 (or any terminal, once): start the local S3 stand-in.** The test-server's
`pagedSingleUseKEMPreKeyStore` (PQ one-time-prekey storage) needs a working S3-compatible
endpoint, which upstream's `test-server` profile doesn't provide (see
[`FINDINGS.md`](FINDINGS.md), entry O13). Without this, any flow that keeps a connection open
past a few hundred milliseconds — which is any real usage — hits a `PUT /v2/keys` 500 in the
background.

```sh
cd deploy/signal-test-server
./minio.sh up
```

One-shot (the command returns; nothing to leave running interactively, though the container
stays up in the background same as the TLS proxy). Check with `./minio.sh status`, stop with
`./minio.sh down`.

**Terminal 3 — run something**, from the repo root (`personas-main`, not the
`deploy/signal-test-server` subfolder):

- Plumbing check (registers two throwaway accounts, sends one 1:1 message):
  ```sh
  cargo run -p transport-presage --example a1_smoke
  ```
- The real thing — a persona post, encrypted under the PPRF cipher, ridden over
  Signal, proof-verified on the receiving end:
  ```sh
  cargo test -p personas-messenger --release -- --ignored --nocapture e2e_record_converges_over_signal
  ```
- The **key distribution** check (e2c): a creator distributes a fresh group
  secret to a member over a real 1:1 Signal message (X3DH + Double Ratchet, not
  an in-process hand-off), the member recovers it, and both sides exchange one
  real PPRF-encrypted content message under their own copy:
  ```sh
  cargo run -p transport-presage --example e2c_key_distribution
  ```
- The **shared phantom identity** check (B2/D1): two members register two fully
  independent accounts but with the same identity keypair (derived from the
  group secret), and an independent observer confirms both real accounts'
  messages carry the *same* certificate-embedded identity key while still
  showing *different* real uuids (not device linking):
  ```sh
  cargo run -p transport-presage --example b2_shared_identity
  ```

All four create their own fresh throwaway accounts/numbers/group secrets every
run — nothing to set up beforehand, and nothing persists between runs (the fake
server's datastores are in-memory and reset when Terminal 1's process stops).
The `b2_shared_identity` example additionally exercises the `third_party/presage`
fork — no separate setup needed, `cargo build`/`cargo run` picks it up
automatically via the workspace `[patch]`, same as `third_party/libsignal-service-rs`
already does.

### If something in Terminal 3 fails

- **"Websocket error: reqwest error" during registration** — almost always means
  Terminal 2 (the TLS proxy) isn't actually up, or a certificate mismatch (see the
  `NOTE:` step above). Check `./tls-proxy.sh status`.
- **`send_message returned ServiceError(WsClosing ...)` followed by the message still
  arriving** — a known, intermittent timing race in presage's post-send bookkeeping
  (documented in [`FINDINGS.md`](FINDINGS.md), entry O12). Harmless — the receiver's own
  decrypt is the real check, and every example already treats this as non-fatal.
- **`b2_shared_identity` fails at step 4 with `observer receiving B's bootstrap` /
  `timed out waiting to receive`** — if you haven't run `./minio.sh up` (above), do that
  first: this used to be caused by every `receive_messages()` call's background prekey
  refresh hitting a broken S3 dependency (`FINDINGS.md` entry O13), which is fixed. A
  second, deeper bug behind the same symptom (`FINDINGS.md` entry O14 — the example's
  `receive_one` helper was reopening `receive_messages()`, and therefore the websocket,
  once per message instead of once per receive burst) is also now fixed. If you still
  see this failure on current code, it's a new regression, not O13/O14 — re-run with
  verbose logging (below) and check `FINDINGS.md` for whether it matches either entry's
  symptoms before assuming it's the same thing.
- **`a1_smoke` fails on the first `cargo run` after the server boots, then passes on a
  retry** — a distinct, not-yet-root-caused cold-connection race (`FINDINGS.md` entry
  O15): the identified websocket can get a clean `code=1000` close from the remote while
  `send_message` is still awaiting a response, and — unlike O12 — the message can
  genuinely fail to arrive. `a1_smoke` now retries the send/receive round trip up to 3
  times on its own, so a single `cargo run` should no longer need a manual re-run. If it
  still fails after 3 attempts in a row, that's not this known flakiness — treat it as a
  real error.
- **Anything else** — re-run with verbose logging to see the real underlying error:
  ```sh
  RUST_LOG=presage=debug,libsignal_service=debug cargo run -p transport-presage --example a1_smoke
  ```

### Shutting everything down

```sh
# Terminal 2:
cd personas-main/deploy/signal-test-server && ./tls-proxy.sh down

# Terminal 1: Ctrl-C
```
