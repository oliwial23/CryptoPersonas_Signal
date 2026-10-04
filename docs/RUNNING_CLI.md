# Running everything: as-a-service vs. serverless

A practical "what do I type" reference for this repo's two architectures. See
[`ARCHITECTURE.md`](ARCHITECTURE.md) for the design behind the split; this is
purely the command list.

```sh
cd /Users/oliwiakempinski/Documents/GitHub/CryptoPersonas_Signal
cargo build --release -p personas-server -p personas-cli
```

builds both binaries once, into `target/release/server` and
`target/release/personas`. Rebuild after pulling changes; everything below
assumes these two binaries already exist.

---

## As-a-service (`personas-server`)

A central server (`target/release/server`) holds the bulletin and relays
under personas; each member runs the `personas` CLI against it. This is the
architecture every command below other than `messenger demo` talks to.

Two terminals: **Terminal 1** stays up running the server; **Terminal 2** is
where you run one `personas ... ` command per action (it exits after each
one — there's no long-running client process).

### Terminal 1 — start the server

```sh
cd /Users/oliwiakempinski/Documents/GitHub/CryptoPersonas_Signal
rm -rf /tmp/pp-test          # fresh state; skip to keep what's there
PERSONAS_PROFILE=local PERSONAS_BIND=127.0.0.1:3095 PERSONAS_DATA_DIR=/tmp/pp-test ./target/release/server
```

Leave it running. First boot is slower (generates and caches Groth16 proving
keys + Nova folding params); later boots reuse the cache and are fast.

`PERSONAS_PROFILE=local` uses the in-process mock transport (no signal-cli
daemon, no Slack tokens needed — see [deploy/profiles/local.toml](../deploy/profiles/local.toml)).
Swap in `PERSONAS_PROFILE=signal` or `PERSONAS_PROFILE=slack` to relay over a
real signal-cli daemon or Slack workspace instead (needs `SIGNAL_BOT_NUMBER`
or `SLACK_BOT_TOKEN`/`SLACK_APP_TOKEN` in the environment — see
[deploy/profiles/](../deploy/profiles/)).

### Terminal 2 — run client commands

Set the connection once per shell so every command below can just be
`./target/release/personas "${P[@]}" <command>`:

```sh
cd /Users/oliwiakempinski/Documents/GitHub/CryptoPersonas_Signal
P=(--transport signal --api http://127.0.0.1:3095 --data-dir /tmp/pp-test-client)
```

Swap `--transport signal` for `--transport slack` to talk to the Slack route
family instead (needs `--data-dir` pointed at its own directory — a Signal
identity and a Slack identity are different `user.bin` files, don't share a
data dir between them). Each command below is annotated **[both]**,
**[Signal only]**, or **[Slack only]**.

Every command proves something locally (can take a few seconds) before
posting to the server, and persists updated state (`user.bin`, logs) to
`--data-dir` on success.

#### Join and post

```sh
./target/release/personas "${P[@]}" join                                          # [both]  mint the callback object + first pseudonym
./target/release/personas "${P[@]}" post -m "hello" -g "1"                          # [both]  anonymous post (callback attached)
./target/release/personas "${P[@]}" post-pseudo -m "hello" -g "1" -i 1              # [both]  post under pseudonym #1
./target/release/personas "${P[@]}" post-pseudo-rate -m "hello" -g "1" -c thread1 -i 1  # [both]  post under a rate-limited, per-thread pseudonym
./target/release/personas "${P[@]}" new-thread-cxt -c thread1                       # [both]  open a thread context (Slack also needs -g channel)
./target/release/personas "${P[@]}" get-contexts                                    # [both]  pull thread contexts down from the server
```

#### Pseudonyms

```sh
./target/release/personas "${P[@]}" gen-pseudo                                      # [both]  generate a fresh pseudonym
./target/release/personas "${P[@]}" pseudo-index                                    # [both]  print the pseudonym log (1-based index used by -i above)
```

#### Scanning outstanding callbacks

```sh
./target/release/personas "${P[@]}" scan                                            # [both]  scan the next outstanding callback
./target/release/personas "${P[@]}" scan-folding                                    # [both]  fold-scan everything outstanding at once (leaks the count)
```

#### Polls, voting, banning

```sh
# Signal:
./target/release/personas "${P[@]}" poll -m "pineapple on pizza?" -g "1"            # [Signal] open a poll
./target/release/personas "${P[@]}" vote -g "1" -t <poll-timestamp> -e "👍"          # [Signal] vote by reacting
./target/release/personas "${P[@]}" count-votes -g "1" -t <poll-timestamp>          # [both]   tally a poll

# Slack:
./target/release/personas "${P[@]}" poll -q "pineapple on pizza?" -g "C123" --option1 yes --option2 no   # [Slack] open a poll
./target/release/personas "${P[@]}" vote -g "C123" --vote-id <id> --vote yes        # [Slack] vote
./target/release/personas "${P[@]}" count-votes -g "C123" --vote-id <id>            # [both]  tally a poll

./target/release/personas "${P[@]}" ban-poll -g "1" -t <message-timestamp>          # [both]  open a ban poll against a message
./target/release/personas "${P[@]}" ban -t <message-timestamp>                      # [both]  invoke the ban callback the poster committed to (after the poll passes)
```

#### Reputation

```sh
./target/release/personas "${P[@]}" single-rep -t <message-timestamp>               # [Signal only]  apply reputation delta from one message
./target/release/personas "${P[@]}" rep                                             # [both]  apply every outstanding reputation callback
./target/release/personas "${P[@]}" get-rep                                         # [Slack only]  print your reputation score
```

#### Reactions and replies

```sh
./target/release/personas "${P[@]}" reaction -g "1" -e "👍" -t <message-timestamp>  # [both]  react to / rate a message (👍 👎 🤬 ❌ ✅)
./target/release/personas "${P[@]}" reply -g "1" -m "reply text" -t <message-timestamp>          # [Signal only]  reply
./target/release/personas "${P[@]}" reply-pseudo -g "1" -m "reply text" -t <message-timestamp> -i 1  # [Signal only]  reply under a pseudonym
```

#### Authorship proof

```sh
./target/release/personas "${P[@]}" authorship -i 1 -j 2 -g "1"                     # [both]  prove one member authored pseudonyms #1 and #2
```

#### Badges

```sh
./target/release/personas "${P[@]}" request-badge -g "C123" -i 1                    # [Slack only]  request a badge (1 Faculty / 2 Student / 3 Industry) from the moderator
./target/release/personas "${P[@]}" approve-badge                                   # [Slack only]  moderator: approve every outstanding badge request
./target/release/personas "${P[@]}" badge -i 1 -g "1"                               # [Signal: also pass -b <claimed-pseudonym>]  claim a granted badge under a pseudonym
```

#### Epoch

```sh
./target/release/personas "${P[@]}" update-epoch                                    # [both]  turn the epoch
```

#### Privacy Pass (anonymous, unlinkable tickets — see [`FINDINGS.md`](FINDINGS.md) O7)

Requesting and redeeming are separate steps — request once, redeem later
(even in a completely different terminal session), one ticket per redeem:

```sh
./target/release/personas "${P[@]}" priv-pass-request                               # [both]  request one ticket, stash it locally
./target/release/personas "${P[@]}" priv-pass-badge -i 1                            # [both]  redeem a stashed ticket for a badge (1/2/3, no eligibility check)
./target/release/personas "${P[@]}" priv-pass-post -m "hi" -g "1"                   # [both, -t reply_to is Signal only]  redeem for an anonymous post, no persona
./target/release/personas "${P[@]}" priv-pass-pseudo-post -m "hi" -g "1"            # [both, -t reply_to is Signal only]  redeem for a post under a fresh ticket-derived pseudonym
./target/release/personas "${P[@]}" priv-pass-reputation                            # [both]  redeem for a fixed +1 reputation bump
```

Redeeming with nothing stashed fails cleanly:
`Error: no Privacy Pass ticket available to redeem — run priv-pass-request first`.
Each `priv-pass-request` stashes exactly one ticket; run it again for another.

---

## Serverless (`personas messenger`)

No server at all — each member runs a local replica of the group log
(`personas_bulletin::replica`) over a messenger transport and verifies
everything itself. See [`D4_MESSENGER.md`](D4_MESSENGER.md) and
[`SERVERLESS_PROTOCOL.md`](SERVERLESS_PROTOCOL.md) for the design.

Only the in-process **mock** transport is wired up today, so there is one
runnable command — a scripted demo that simulates three members inside a
single process (not three real terminals/accounts):

```sh
cd /Users/oliwiakempinski/Documents/GitHub/CryptoPersonas_Signal
./target/release/personas messenger demo
```

One terminal, no server, no second process. It:

1. joins three members (poster, voter-1, voter-2),
2. has the poster post under a persona,
3. opens and passes a ban poll against that post,
4. crosses a settlement barrier so the ban takes effect and the post is
   flagged on every replica,
5. checks all three replicas converged on the same roots,
6. hands a late joiner a pinned snapshot and confirms it re-derives the same
   view.

First run is slower (generates and caches Merkle-mode keys under
`messenger-data/` or `--data-dir`, if set); later runs reuse the cache.

Real Signal for serverless mode (each member as a genuinely separate
process/account, over `transport-presage`) is a different, lower-level track
— see [`RUNNING_E2_LOCALLY.md`](RUNNING_E2_LOCALLY.md), which is about the
PPRF-encrypted transport itself, not the `personas` CLI.

---

## Quick reference: which architecture do I want?

| | As-a-service | Serverless |
|---|---|---|
| Binary | `server` + `personas` | `personas messenger demo` only |
| Terminals | 2 (server, then one-shot client calls) | 1 |
| Trust model | Central server relays and stores the bulletin | Every client verifies everything itself |
| Feature coverage | Everything above | The M3 scenario only (join, persona post, ban poll, ban) |
| Privacy Pass | Yes | Not wired up |
