# Architecture

The state of the system after **a5**. This describes what exists, not what is planned; the
plan lives in `~/.claude/plans/take-a-look-at-shimmying-dolphin.md`.

## The shape of it

```
crates/
  personas-core/       types, circuits, params (content-addressed disk cache), persona, timing
  personas-config/     the layered config: defaults + profile.toml + PERSONAS_* env + CLI flags
  personas-wire/       the byte format: versioned CBOR envelope + kind registry
  personas-bulletin/   BulNet — the client's HTTP view of the server's bulletin
  personas-client/     PersonaClient: one client for both messengers
  personas-cli/        the `personas` CLI: one flat command set, transport-branched
  personas-server/     the as-a-service server (bin: `server`)
  transports/
    transport-api/         the Transport trait: send / react / subscribe
    transport-mock/        an in-process chat log — no messenger, no credentials
    transport-signal-cli/  signal-cli's JSON-RPC, in process
    transport-slack/       slack-morphism, incl. socket mode
    signal-cli-client/     the signal-cli JSON-RPC client crate (bin + lib)
deploy/profiles/       local.toml, signal.toml, slack.toml — the mode × transport matrix
crypto_personas/
  *.py                 the benchmark harness (drives `--bin personas`)
batch-zkc/             Privacy Pass (standalone; not yet wired in — workstream b)
```

Nightly is required, and pinned: `zk-callbacks` uses `generic_const_exprs`. There was never
a stable build.

## Configuration

`personas-config` resolves one `Config` for every binary from four layers, later winning:
built-in [`Config::default`] (each default equals the value the pre-a5 code hardcoded) →
`deploy/profiles/<name>.toml` (selected by `--profile` / `PERSONAS_PROFILE`) → the legacy
`PERSONAS_*` / `SIGNAL_*` / `SLACK_*` env vars (kept working verbatim) → CLI flags. A checkout
with no profile and no env behaves exactly as it did before a5. `mode` is `service` (serverless
is workstream d and is refused); the server reads `[server]` and `[transport]`, the client
reads `[client]` and its `transport` (which route family to talk to).

## Who is trusted for what

The server is trusted to **deliver**. In the as-a-service deployment every message the group
sees comes from one phantom account, so the server necessarily knows who asked for what to be
posted. Removing that is the whole point of the serverless design (workstreams d/e).

The server is **not** trusted for anything cryptographic. It cannot forge a post (a post is a
proof against a bulletin every client can fetch), cannot ban a member it holds no callback
ticket for, cannot apply a rating twice, and cannot apply an argument the circuit forbids.
What it can do is refuse — and a refusal is visible.

## The two kinds of state

**The bulletin** (`ServerState::db`) is the protocol's state: the object bulletin, the
callback bulletin, the epoch. Proofs are checked against it. zk-callbacks owns it.

**The ledger** (`personas_server::state`) is the server's own bookkeeping: which callback
belongs to which posted message, what its rating stands at, which polls are open, what context
a thread was assigned. None of it is cryptographic. It exists because **a poster commits to a
callback before their message has an id** — the messenger only assigns one on delivery — so
something has to join the two afterwards. Losing the ledger loses the ability to attribute a
rating to a post; it does not lose the ability to verify a proof.

Each messenger gets a `Channel` (a transport + a record log + a context log). `/api/x` and
`/api/slack/x` are the same protocol over the same bulletin and the same circuits; the channel
is the only difference.

Files, all under `PERSONAS_DATA_DIR` (default `server/data`):

| file | what |
|---|---|
| `store_seed.bin` | the 32-byte secret the store's genesis is rebuilt from (mode 0600) |
| `params/<hash>/` | the content-addressed proving-key cache (~103 MB) |
| `{signal,slack}_records.jsonl` | message id → callback commitment, and its accrued rating |
| `{signal,slack}_contexts.jsonl` | thread → context field element (+ ts, on Slack) |
| `polls.jsonl` | Signal polls and their ballots |
| `badge_requests.jsonl` | badges awaiting an admin |
| `{signal,slack}_chat.jsonl` | the mock transport's chat log, when it is in use |

**The bulletin's contents are not persisted.** A restart keeps the store's keys and the params
cache but forgets who joined. See `docs/FINDINGS.md` (A1).

## The order a post happens in

1. Verify the proof and append the interaction to the bulletin.
2. Relay the message — and only now does it have an id.
3. File the callback the poster committed to, under that id.

(1) is not undone if (2) fails: the bulletin has accepted the interaction and the bulletin
cannot roll back. That was true before a4 and is true now. What *is* new is that nothing is
filed before the id exists — see FINDINGS F1 for the bug that fixed.

The bulletin write lock is **not** held across the relay. It is safe to release it only because
callbacks are keyed by message id rather than by "the last line of the file", so two posts may
interleave without stealing each other's rows.

## The wire

`personas-wire` owns the byte format, and it is the only place that names it.

A **record** — a proof, a scan, a join, a callback commitment — is a CBOR envelope
(`{v, kind, payload}`) around an arkworks payload serialized with `Compress::Yes`. The `kind`
matters: every payload is a sequence of field elements and curve points, so a `Scan` fed to a
`Post` reader will often *deserialize*, into garbage that then fails proof verification with an
error that says nothing. And in serverless mode a record arrives as a chat message, where the
route is no longer available as an implicit type tag.

**Proving keys and bulletin dumps are not records** and carry no envelope and no compression.
The client refetches them on every invocation, over localhost, with `Validate::No`, and the
benchmark harness spawns the client hundreds of times. Compressing tens of megabytes of curve
points would add a modular square root per point to every client start, to save bandwidth that
costs nothing. `personas_wire::raw` is where that decision is written down so the two
conventions cannot be mistaken for an oversight.

Callback commitments are keyed in the ledger by the hex of their canonical *uncompressed*
bytes. (For `CallbackCom` this is moot — it is all field elements, which serialize identically
either way. That is why the client's `deserialize_compressed` against the server's
`Compress::No` has always worked.)

## Transports

`Transport` is `send` / `react` / `subscribe`. Only what more than one messenger can honestly
implement crosses that boundary; Slack's block kit and Signal's quote semantics stay inside
their own crates. A messenger that genuinely cannot do something returns
`TransportError::Unsupported` rather than pretending.

- **mock** — an in-process chat log. The server boots with **no credentials at all** and
  relays to it. `PERSONAS_TRANSPORT=mock` forces it even when credentials are present. This is
  what makes the system demonstrable and testable; before it, a post could only be verified as
  far as the bulletin append, because the relay always failed with no `signal-cli` installed.
- **signal-cli** — the phantom bot. Signal has no per-message sender override, so a persona
  becomes `FROM: <petname>` prefixed to the body, and a "reaction" is a quoted message (a real
  reaction would come from the bot, not the rater).
- **slack** — a persona becomes a real `username` override, and a rating a real reaction.

Polls are **never** interactive. See FINDINGS D1.

## Routes

All 58 paths are preserved from the pre-a4 server: `bench/*.py` drives `personas` and the CLI
hardcodes them.

| group | routes |
|---|---|
| proving keys | `/api/interaction/{standard,standard/pseudo,standard/pseudor,scan,fold,fold/pre,badge/request}/proving_key`, `/api/user/arbitrary_pred_proving_key{,2,3}` |
| bulletin | `/api/user/{pubkey,bulletin,join}`, `/api/callbacks/{membership_pubkey,nonmembership_pubkey,bulletin,nmemb_bulletin}`, `/api/get_epoch` |
| interact (no relay) | `/api/interact/{standard,scan,foldscan,arbitrary_pred}` |
| post (Signal) | `/api/jsonrpc{,/pseudo,/pseudo/rate}`, `/api/reply{,/pseudo}`, `/api/react`, `/api/authorship`, `/api/badges` |
| post (Slack) | `/api/slack/post/{anon,pseudo,pseudo/rate}`, `/api/slack/react`, `/api/slack/{request,claim}/badges`, `/api/slack/claim/authorship` |
| polls | `/api/{poll,banpoll,vote,votecount,context}`, `/api/slack/{poll,banpoll,poll/context,poll/results,vote}` |
| callbacks | `/api/{ban,reputation,epoch,approve/badge,cb}`, `/api/slack/reputation`, `/api/slack_cb`, `/api/cb/{signal/all,slack/all,badge/requests}` |
| contexts | `/api/{,slack/}pseudo/{new_thread_context,get_all_contexts}` |

`/api/interact/foldscan` carries its own 100 MB body limit; a folded Nova proof is megabytes.

## The CLI

`personas` is one binary with one flat command set. Which route family a command posts to, and
the exact request it sends, is chosen by the configured transport (`--transport signal|slack`),
not by the command name — the two former binaries (`client`, `slack-client`) are gone. The
short-flag letters are the Signal CLI's (`-m` message, `-g` channel/group, `-c` thread, `-i`
index, `-t` timestamp, `-e` emoji, `-b` claimed, `-j` second index), so the `bench/*.py`
harness runs unchanged but for `--bin personas`. A few commands are transport-specific (`reply`
is Signal-only; `get-rep`, `request-badge`, `approve-badge` are Slack-only) and return a clear
error against the other transport. `personas-cli` builds its tokio runtime by hand and drops it
before `PersonaClient` — `reqwest::blocking::Client` owns a runtime that panics if dropped
inside any tokio context.

## Running it

See `docs/FINDINGS.md` for the traps. In short:

```sh
cargo build --release --bin server --bin personas
PERSONAS_PROFILE=local PERSONAS_BIND=127.0.0.1:3010 ./target/release/server &
P=(--transport signal --api http://127.0.0.1:3010 --data-dir /tmp/d/client)
./target/release/personas "${P[@]}" join
./target/release/personas "${P[@]}" post -m "hello" -g demo-group
```

The `local` profile forces the mock transport; `PERSONAS_TRANSPORT=mock` still does too. Build
`--release`: debug Groth16 proving is impractically slow.
