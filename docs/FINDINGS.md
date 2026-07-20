# Findings

A running log of bugs, quirks, and decisions that a reader would otherwise have to
rediscover. Each entry says what is wrong (or what was decided), why it matters, and where to
look. Entries are numbered so they can be cited from commits and reviews.

Sections: **F** fixed, **O** open, **D** decisions that want a second opinion.

---

## F — Fixed

### F1. A failed relay filed one member's callback against another member's message

*Found and fixed in a4. Severity: high — silent misattribution of moderation power.*

A poster commits to a callback ticket **before** their message has an id; the messenger only
assigns one on delivery. So the two must be joined afterwards.

The old code joined them like this: append a half-row (`{"callback_com": …, "type": "cb"}`) to
`server/*_zkpair_log.jsonl`, relay the message, then re-read the file and rewrite **the last
line of it** into a real row carrying the message id ([old `server.rs`, e.g.
`forward_jsonrpc`]). Two things go wrong.

- If the relay failed, the half-row stayed. The **next** member's post then rewrote *that* row
  as its own — filing one member's callback against another member's message. A rating on the
  second message would then be applied to the first member's object.
- Two concurrent posts could interleave between the append and the rewrite, with the same
  result.

This was not hypothetical on this machine: without a `signal-cli` daemon **every** relay failed,
so every post left a half-row behind.

Fixed by never filing anything until the id exists: `routes/post.rs::relay` calls
`RecordLog::record(&sent.id, cb)` after the transport returns. `state/ledger.rs::RecordLog`
keys rows by message id rather than by file position.

### F2. Every rating would have been applied twice

*Introduced and caught during a4. Severity: high (had it shipped).*

`/api/react` records a rating **and** asks the messenger to add the emoji. The messenger then
reports that emoji back to us as a `reaction_added` event. The obvious thing — "a reaction
event is a rating" — therefore counts every rating twice.

The event listener now *acknowledges* reactions and does not count them; only ratings that came
through the personas layer (`/api/react`, and the 👍/👎 buttons, which add no messenger
reaction) count. See `main.rs::events`, which spells this out. Inherited consequence: see O4.

### F3. A member could crash the server with a well-formed request

*Fixed in a4. Severity: medium — remote DoS by any member.*

Handlers read `pub_inputs[1]` straight off the wire. A proof carrying a shorter public-input
vector than the route expected — for instance, the *right* record posted to the *wrong* route —
panicked the handler. More generally the handlers `unwrap()`ed on deserialization (~500 unwraps
across `server.rs`/`helpers.rs`).

Now: `routes/post.rs::pub_inputs` checks the length; `personas-wire` refuses a record whose
`kind` is not the one the route expects; everything fallible returns `AppError` (`error.rs`).

### F4. The signal-cli shell-out panicked when signal-cli was not running

*Fixed in a4 (by deleting it). Severity: medium.*

The relay was 12 copies of `Command::new("signal-cli-client")` followed by
`serde_json::from_str(&stdout).unwrap()`. With no daemon, stdout is empty and the parse
panics. The binary being spawned was a crate **in this same workspace**; its JSON-RPC client is
now called in process (`transport-signal-cli`), and an unreachable daemon is a typed
`TransportError::NotConnected` naming the address and the command to start it.

### F5. A missing benchmark stamp returned 409 and refused the post

*Fixed in a4. Severity: low, but it made the system untestable.*

The post handlers called `load_start_time(label)` and, if the file was absent, returned
`409 Conflict` **instead of posting the message**. So posting with anything other than the
benchmarked client — curl, a test, the mock transport — failed. Instrumentation that cannot
measure something must not prevent it from happening: `bench.rs::close_latency` now warns and
continues.

### F6. A poll's id was unreachable

*Fixed in a4, as a consequence of D1. Severity: medium (it made CLI voting impossible).*

The vote id lived only in a Slack `block_id` and in button `action_id`s — invisible to a human.
That was survivable while a button press carried it back. With buttons gone (D1), a member had
no way to learn the id they must pass to their own client in order to vote. Polls now print
their id and the command to vote with (`transport-slack::blocks::how_to_vote`,
`transport-signal-cli::render_poll`).

### F7. `BulNet::verify_in` fetched the wrong route

*Fixed in a3, recorded here for completeness.* It requested `user/bulletin` instead of
`api/user/bulletin` — a 404 into an `.unwrap()`. That path could never have worked.

---

## O — Open

### O1. The bulletin's contents are not persisted

*Severity: high for any demo that must survive a restart. The plan expected a4 to fix this; it
does not.*

The store's **keys** survive a restart (a2: genesis is rebuilt deterministically from
`store_seed.bin`) and so does the params cache. The bulletin's **contents** — who joined, which
callbacks were invoked, the epoch — live in memory and are lost. After a restart every client
must `join` again; an existing `user.bin` fails every proof.

Why it is not a one-liner: `CentralStore` is not `CanonicalSerialize` and its private keys are
unreachable (the a2 finding). Persisting means replaying `obj_bul`, `callback_bul`,
`nmemb_bul` and the epoch into a store that cannot be deserialized directly — the entries
themselves *are* serializable (we serve them over `/api/user/bulletin`), so a replay-on-boot is
plausible, but the nullifier set and the epoch have to come back consistently or proofs will
fail in ways that look like corruption.

Should be its own commit, before any demo (M0) that a human restarts.

### O2. `client scan` answers one callback, and interacting mid-sweep panics

*Severity: medium. Pre-existing; a4 did not touch it.*

A member with *k* outstanding callbacks needs *k* invocations of `client scan`. Interacting
before the sweep completes trips `assert!(self.scan_index.is_none())` inside zk-callbacks, so
the client **panics** —

```
Error: task 11 panicked with message "assertion failed: self.scan_index.is_none()"
```

— rather than saying "you have N callbacks left to scan". Anyone who hits this will think the
system is broken. The fix is client-side: loop until `num_outstanding_callbacks()` is zero, or
report the remaining count. (The protocol behaviour is correct: this is only about the message.)

### O3. The epoch a callback is filed at is inconsistent across routes

*Severity: dormant today, latent trap tomorrow. Judged during a5; the investigation surfaced
O10, which is the real problem. Preserved as-is in a4.*

`approve_interaction_and_store` takes the epoch that the interaction's callback tickets are
stored at. The old routes disagreed, and the disagreement is inherited:

| route | epoch passed |
|---|---|
| anonymous post, reply | `Time::from(0)` |
| rate-limited pseudonymous post | `Time::from(0)` |
| pseudonymous post, reply-pseudo | the live epoch |
| badge request | the live epoch |
| scan | the live epoch |

**The disagreement is currently unobservable.** The only place a stored `expiration` is
consulted at scan time is inside `expirable`-gated branches (zk-callbacks `scan.rs:656/676` and
the circuit at `823/840`), and our sole callback is `expirable: false` (`circuits.rs`), a flag
the server enforces on post (`service.rs:204`). So whether a route files at `0` or the live
epoch changes nothing a scan can see today. Unifying the routes is safe but a no-op.

**It becomes a live bug the day any callback is made `expirable: true`.** The post-side check
`cb.expiration == def.expiration + cur_time` (`service.rs:208`) fires regardless of the flag, so
the `Time::from(0)` routes store `expiration = 10` (absolute) while the live-epoch routes store
`10 + epoch`. A live-epoch scan would then read the `Time::from(0)` tickets as already expired
(`cur_time > 10`) and **silently drop them** — exactly "a callback nobody can ever scan," landing
on the anonymous and rate-limited paths. Unify the routes (or bind `expiration` relative to the
scan epoch) *before* introducing any expirable callback. Flagged in `bulletin::verify_and_store`.

The deeper reason the inconsistency is invisible — that the epoch isn't cryptographically bound
into a scan at all — is **O10**, and that one is not dormant.

*Update (d2).* Serverless has no analogue: every record files its tickets at the epoch it was
posted in, uniformly, so the `expiration == def.expiration + cur_time` check is consistent by
construction. This is a fix by not inheriting, not a fix.

### O4. An emoji added by hand in the Slack UI changes nobody's reputation

*Severity: low. Inherited; now explicit.*

Only ratings that arrive through the personas layer count: `/api/react` and the 👍/👎 buttons.
An emoji a human adds directly in Slack is announced ("Message has been marked for an increase
in reputation") but is **not** counted — see F2 for why counting it would double every rating
that came from `/api/react`. The announcement therefore lies a little. Either the announcement
should go, or the UI reaction should be counted *and* `/api/react` should stop counting its own
echo. Wants a decision.

### O5. Slack polls are forgotten on restart

*Severity: medium for the moderation story.*

Signal polls are a file; Slack polls are a `HashMap` in memory, as they always have been. So a
Slack ban poll's tally cannot be the input to `AllowedToRevoke` — it may not exist by the time
anyone acts on it. Serverless (workstream d) dissolves this by making the tally a client-side
count over the chat log.

### O6. A folded scan silently drops `k mod N` callbacks

*Known; workstream c3 owns it.* `PersonaClient::fold` folds `k / NUM_SCANS_PER_FOLD` steps and
ignores the remainder. **c1 landed the mechanism this needs** — the scan/fold circuits are now
const-generic over the fold size and `dispatch_fold_size!` selects one at runtime (see D8) — but
c1 deliberately left the client pinned to a single size, so the drop is unchanged until c3 does
the greedy decomposition over the menu.

### O7. `join` is ungated

Anyone can join. What stops a banned member from rejoining is that they start over with no
standing — which is also what stops anyone else. A real deployment gates this on an invite;
that is workstream b's Privacy Pass ticket, and it is why tickets are a service-mode feature.

### O8. Two Slack capabilities cannot be given a message id

*Severity: low, documented at the call sites.* `files.completeUploadExternal` returns file ids,
never the ts of the message Slack wraps the file in; `chat.postEphemeral` returns nothing at
all. Both therefore return `Sent { id: MessageId("") }`. Nothing downstream rates a badge image
or an ephemeral, so nothing breaks — but an attachment post that someone *does* want to rate
would need a follow-up `conversations.history` lookup.

### O9. Dropped: the Slack "🧩 Topic" banner

The old socket handler echoed a thread's topic into the thread whenever someone replied. It
guarded against echoing its own echo by inspecting the message's `block_id`s, which the
transport abstraction does not expose — so a naive port loops forever. Dropped rather than
half-ported. Cosmetic; restore with an echo-once-per-thread guard if it is missed.

### O10. A called-back callback (a ban) can be evaded forever by replaying a stale nonmembership range

*Severity: high — defeats the moderation/reputation mechanism. Upstream soundness gap in
zk-callbacks `d661879`, inherited; confirmed a divergence from the 2025/1969 construction (which
binds the epoch). Not introduced by a4. Fix is a circuit change → external crypto-review gate.
Found by following O3 during a5.*

A scan proves, per in-progress callback ticket, either **membership** in the called-back set
(apply the callback method — e.g. absorb a ban) or **nonmembership** (keep the ticket
in-progress). The epoch is supposed to bound this: turning the epoch is what forces absorption
(`moderation.rs:152–154`; `interact.rs:216–217` says a stale-epoch fold "would let a member
re-absorb callbacks they have already" scanned away). But the epoch is never bound into the
proof, so the forcing function does nothing.

The centralized nonmembership store signs each not-called range as `sign_K(hash(lo, hi, epoch))`
(`impls/centralized/ds/sigrange.rs`). In-circuit, `enforce_nonmembership_of` verifies that
signature over `hash(range.0, range.1, extra_witness.epoch)` — where **`epoch` is a private
witness**, never compared to the public `cur_time` the server pins (`sigrange.rs:296–318`).
`epoch` occurs in all of `src/generic/` exactly once, in a doc comment. And `enforce_memb_nmemb`
enforces only membership XOR nonmembership (`generic/bulletin.rs:1032–1044`), so a prover pairs a
garbage membership witness (→ false) with a valid-but-stale range (→ true).

The exploit, undetectable at verify time:

1. Before being banned, the member GETs `api/callbacks/nmemb_bulletin` (the signed ranges are
   served publicly, `personas-bulletin/src/http.rs:218`) and keeps the range covering their
   callback ticket.
2. The server bans them: the ticket is called, `update_epoch` re-splits the ranges to exclude it
   and re-signs at the new epoch **with the same key** — `update_epoch` never rotates it; only
   `rotate_key`, which the server never calls (`sigrange.rs:200–262`, `moderation.rs`).
3. On the next scan the member supplies the archived range. It covers the tik ✓ and its signature
   under `K` still verifies ✓ → nonmembership true; garbage membership witness → membership false;
   XOR holds. The ticket is treated as not-called, so the ban is never absorbed. The ticket stays
   in-progress, and the stale range stays valid, so they replay it on every future scan.

The proof's public inputs (`new_object`, `old_nullifier`, `cur_time = live epoch`, cb coms) are
identical to an honest scan's, so the server cannot distinguish it. This breaks bans and
reputation callbacks alike.

Fix direction (crypto-review gate, do **not** slip into a5): constrain `witness.epoch ==
cur_time` in `enforce_nonmembership_of`, which forces per-epoch re-fetch of ranges and makes stale
ones fail — combined with per-epoch key rotation so archived signatures cannot outlive their
epoch. Both are upstream circuit changes. Until then, moderation is advisory against a motivated
member.

*Update (d2).* The **serverless** design routes around this structurally rather than patching the
circuit. A Merkle bulletin's public data is a *root*, not a verification key, and a root cannot be
a circuit constant — so `is_memb_data_const` must become `false`, which forces the roots into the
proof's **public inputs**, where every replica pins them against roots it computed itself. A stale
range has no root to hash up to. The general law, and the reason the object tree can safely do the
opposite, is in [SERVERLESS_PROTOCOL.md](SERVERLESS_PROTOCOL.md) §5. **This does not fix service
mode**, which stays on the signature stores and stays exposed; the upstream circuit fix is still
owed.

### O11. A callback ticket carries no authorization whatsoever

*Severity: none as-a-service (the server is the sole writer of the callback bulletin). Structural
for serverless. Found while writing d2.*

Personas instantiates `Cr = NoSigOTP<F>` (`personas-core/src/types.rs:27`), and upstream every one
of `FakeSigPubkey`, `FakeSigPrivkey`, `OTPEncKey` and `NoSigOTP` is a type alias for the *same*
one-field-element struct, `PlainTikCrypto<F>` (`impls/centralized/crypto.rs`). It has
`sk_to_pk(&self) -> self.clone()` — the public key **is** the private key — `type Sig = ()`,
`verify(_, _) -> true`, and `encrypt(m) = m + k`. The service's signing key,
`FakeSigPrivkey::sk()`, is **the constant zero** (`crypto.rs:182`). Upstream says so outright:
*"As signatures are not necessary in the centralized setting, any private key can be used to
verify tickets."*

So a callback ticket `tik` is one field element that is at once the ticket's identity, the OTP key
its argument is encrypted under, and the whole authority needed to invoke it. Nothing signs a
call. **The only thing that stops anyone from invoking any callback today is that the server is
the sole writer of the bulletin.**

That is fine as-a-service and it is a load-bearing constraint on serverless, where the ticket
travels in `cb_tik_list` to *every* member. Left naive, any member could ban anyone — or, worse,
*burn* every ticket by calling it with a harmless argument the moment they see the post
(`has_never_received_tik` permits one call, ever), permanently disarming moderation; the poster
can do this to their own ticket. The d2 answer is that invocations are **derived from the log by
rule and never sent as records**, so there is no message to forge. See
[SERVERLESS_PROTOCOL.md](SERVERLESS_PROTOCOL.md) §6–§7.

---

### O12. presage's `send_message` can report an error *after* delivery already succeeded

**What.** When `PresageTransport::send` fans a message out, presage's `send_message` does the
`PUT /v1/messages` (which returns 200 — the message is queued for the recipient) and *then* does
post-send bookkeeping (`save_message`, a self-sync, and a recipient/self profile fetch). That
bookkeeping runs on a short-lived websocket that can close before the follow-up request gets a
response, so `send_message` returns `Err("Websocket closing while waiting for a response" /
"responder was canceled")` even though the record was delivered. It is intermittent (timing-
dependent) and depends only on the teardown race, not on anything the caller controls.

**Current handling.** The A1 tests treat it as non-fatal: the receiver's `subscribe`/`ingest` is
the source of truth, and delivery is confirmed there (`a1_smoke`, `a1_transport`,
`e2e_record_converges_over_signal` all pass with it tolerated). `PresageTransport::send` still
surfaces the error to its caller, so the messenger currently sees an occasional spurious send
failure.

**To fix (A2-ish).** Either keep the send websocket alive for the bookkeeping (own a longer-lived
message sender in the actor), or classify "PUT succeeded, bookkeeping raced" as success. The A2
rework of the send path (personas AEAD under `mk`, §5 of the design doc) is the natural place to
make send delivery-truthful rather than tied to presage's post-send housekeeping.

## D — Decisions that want a second opinion

### D1. Polls carry no buttons, because a button press deanonymizes the voter

*Decided by the user during a4.*

A vote is proof-carrying: the voter proves they are an unbanned member voting under a pseudonym
derived from that poll's context. A messenger button press carries **no proof**, and the server
cannot make one (a proof needs the voter's `user.bin`). The old code faked it by spawning the
`slack-client` binary on every click, against whatever `slack-client/user.bin` sat next to the
server — so every click voted as one shared identity, and the second click by *anyone* was
rejected as "already voted".

Worse, the press is a deanonymization channel: it tells the server "Slack user U clicked"
*before* the pseudonymous proof arrives, so correlating the two by timing links the pseudonym to
the account. That is exactly what the pseudonym exists to prevent.

So: no vote buttons anywhere. Polls display their id; members vote from their own client, with
their own key. The 👍/👎 **rating** buttons stay — a rating needs no proof and says nothing
about who its subject is.

### D2. `Compress::Yes` for records, not for proving keys

*Deviates from the plan, which said "everywhere".*

Records (proofs, scans, callbacks) are compressed: point compression nearly halves a proof
(2×G1 + 1×G2), a record is stored forever, and in serverless mode **every member** downloads
it, so the saving is per-member.

Proving keys and bulletin dumps are **not**. The client refetches them on every CLI invocation
(no client-side cache, `Validate::No` deliberately), over localhost, and `bench/*.py` spawns the
client hundreds of times. Compressing tens of megabytes of curve points would put a modular
square root per point on every client start, to save bandwidth that costs nothing. Note field
elements do not compress at all, so a public-input-only payload pays the envelope's ~15 bytes
for no saving — a fine trade for knowing what a record *is*, but not compression.

Reversible in one place if you disagree: `personas_wire::RECORD_COMPRESS` and
`personas_wire::raw::COMPRESS`.

### D3. The server falls back to the mock transport

With no `SLACK_BOT_TOKEN` / `SIGNAL_BOT_NUMBER`, the server used to **exit**. It now relays to
an in-process chat log and says so. `PERSONAS_TRANSPORT=mock` forces it even when credentials
are present, so a test or a demo can be sure it will not talk to a real messenger.

This is what makes the system runnable on a fresh checkout — and it is what made the ban and
reputation paths reachable locally for the first time (with no daemon, every relay failed, so
the timestamp→callback row was never written and `/api/cb` had nothing to return).

### D4. `/api/slack/vote` is synchronous

It used to spawn verification onto a background task and answer `{"status":"received"}` before
checking anything — so a voter whose proof was rejected learned about it from a message in the
channel, and the CLI that sent it exited 0. The caller now gets the verdict it asked for.

### D5. Config lives in its own crate, not `personas-core::config`

*Deviates from the plan, which named `personas-core::config`. Decided in a5.*

The layered config (figment + toml + the legacy env vars) is `personas-config`, a dedicated
crate, rather than a module of `personas-core`. `personas-core` is the circuit/crypto crate that
every proving path compiles; adding figment, toml, and their transitive parser trees to it would
put a config dependency on the critical build path for no benefit. `personas-config` depends on
nothing cryptographic and is depended on only by the binaries and the thin client config. Every
built-in default equals the value the pre-a5 code hardcoded, and the old `PERSONAS_*` /
`SIGNAL_*` / `SLACK_*` env vars still work, so this is transparent to anything that set them.

### D6. The flat `personas` CLI keeps the Signal flag letters; Slack's short flags changed

*Decided in a5, when the two client binaries merged.*

`personas` is one flat command set; the configured transport picks the route family and request
shape. The two old CLIs had assigned the same short letters to different meanings (Slack's `-c`
was *channel*; Signal's `-c` was *thread*), so a single schema cannot honor both. The Signal
letters win, because `bench/*.py` depends on them and is the only automated acceptance test —
`-g` is the channel/group everywhere (Slack's `-c` for channel is gone), `-c` is the thread
everywhere, `-t` is the (now string) timestamp. Commands that exist on only one transport
(`reply`/`reply-pseudo`/`single-rep` on Signal; `get-rep`/`request-badge`/`approve-badge` on
Slack) live in the one enum and error clearly against the other side. Poll and vote take a
superset of flags (`-m` vs `-q`+`--option*`; `-t`/`-e` vs `--vote-id`/`--vote`), validated per
transport. The Slack path has no bench, so it is covered only by the a5 mock smoke test.

### D7. Serverless: banned members may still vote and rate (spite-downvoting tolerated)

*Decided by the user 2026-07-14, during the d2 redline. Applies to the serverless design only.*

In serverless mode a vote and a rating both carry a `pseudonym_pred` proof, which establishes
bulletin membership and a pseudonym derivation but **deliberately does not check `banned`** (the
predicate never reads the field; only the four *post* predicates do). So a banned member keeps a
voice in moderating their own chat — including the ability to downvote out of spite.

This is a **committed choice, not a default.** The alternative — a `banned == 0` variant of
`pseudonym_pred` and a new proving/verifying key set — was considered and declined, because for the
applications in view a banned member retaining a rating/voting voice is acceptable and spite
ratings are not a threat worth a circuit change. What a ban *does* still prevent is posting
anonymously or pseudonymously (the post predicates enforce `banned == 0`), which is the property
that matters. Recorded so a future reader surprised by "a banned user just downvoted me" knows it
was intended. Revisit only if a deployment's threat model makes spite ratings load-bearing. See
`SERVERLESS_PROTOCOL.md` §8, §10.

### D8. The fold-size menu is a closed compile-time set, not an arbitrary runtime N

*Landed by workstream c1 (2026-07-15).* The scan and fold circuits are const-generic over `N`, the
number of callback scans a single proof accounts for (`NF<N>`, `PubScan<_, N>`, `ScanInt<_, N>`,
`scan_predicate<_, N>`, `exec_scanint::<_, N>`, all in `personas-core::circuits`). Const generics
are a compile-time property, so a proof can only ever be produced for an `N` the binary was
*monomorphized* for. That set is fixed in one place — `FOLD_SIZES` (currently `[1, 2, 4, 8, 16]`) —
and `dispatch_fold_size!(n, N => …, fallback)` maps a runtime `n` to the matching monomorphization,
falling through to `fallback` for anything off the menu. This is the deliberate decision: **the menu
is closed.** Supporting a new fold size means adding it to `FOLD_SIZES` *and* the macro's match arms
(a unit test panics if they drift) and recompiling — you cannot ask for an arbitrary `N` at runtime,
and c2/c3/c4 (per-`N` param cache, client auto-select, verify-side dispatch) all pick from this
closed set. Each menu size also multiplies keygen and param-cache cost, so the menu is kept short on
purpose. c1 made the layer generic but left every concrete caller pinned to `NUM_SCANS_PER_FOLD`
(= 1) via const-generic type-alias defaults, so behavior is byte-identical to before until a later
workstream opts a caller into a different size.

### D9. The barrier cadence buckets records by the provider's `serverReceivedTimestamp`

*Landed by workstream d5 (2026-07-15); accepted by the cryptographer "for now, but make a note of
it."* A record's settlement barrier (the bucket its ticket settles in, its ban poll closes in) is a
deterministic function of a **service-assigned** receive timestamp — Signal's
`serverReceivedTimestamp`, surfaced as `transport_api::Incoming::Message::received_at` and bucketed
by `personas_messenger::Heartbeat` as `(received_at − genesis) / period`. See `docs/D5_HEARTBEAT.md`
and `SERVERLESS_PROTOCOL.md` §14 / sign-off item 11.

**Why not the alternatives.** (a) *The device clock* — each replica bucketing by its own wall clock
at the instant it received the record — forks honest replicas on ordinary delivery jitter across a
barrier boundary (A sees a record in barrier *k*, B sees the same record 2 s later in barrier *k+1*;
they settle its ticket at different times, roots diverge). (b) *The sender-set message id*
(`dataMessage.timestamp`) is forgeable — a member could backdate a record into an old barrier (the
same reason §4 orders by prefix, not by that field). The provider's stamp is assigned once and
delivered identically to every recipient, so the record→barrier map is identical everywhere and
convergence is **exact** (`e2e_skewed_delivery_still_converges_exactly` is the proof: four replicas,
skewed arrival + out-of-step heartbeats, identical roots). The device clock still advances the
monotone "how far has now got" counter (`Messenger::tick`), but that only settles late at worst
(bounded by `W`), never at a barrier a peer disagrees with.

**Why it adds no meaningful trust.** The provider is already inside the trust boundary for delivery
(§4: delay, withhold, censor). Stamping a coarse bucket is within powers it already has (it could
move a record across a boundary by delaying delivery), and it still cannot forge a proof, mint a
member, or invoke a callback. The stamp is used only for cadence — never for ordering (prefix-order,
§4) or proof acceptance (self-computed roots, §5).

**The residual caveat (the thing to revisit).** A malicious provider that hands *different
recipients different* stamps for the same message is a fork vector. But it is the same class as
selective delivery/censorship, which §4 already declares out of scope ("Censorship resistance is a
messenger property we do not try to add"). If that is ever pursued, cross-checking the provider's
timestamp — e.g. members gossiping the stamp each saw — is where this would be hardened.

### D10. The staging Signal-Server needs a one-line auth relaxation so presage can register

**Context.** e2 A1's send/receive wiring runs the modified client (`transport-presage`, on presage)
against our *own* isolated Signal-Server in upstream `test-server` mode — not production. presage
registers a new account over the **authenticated** `/v1/websocket/` using the provisional
`(e164, registration-password)` **before the account exists**, so Signal-Server's
`WebSocketAccountAuthenticator` finds no account and stock-throws `InvalidCredentialsException` →
HTTP 403 at the upgrade. Registration cannot proceed.

**Decision.** Patch that one authenticator to return the account lookup's `Optional` directly
(empty ⇒ an *unauthenticated* upgrade) instead of throwing. The upgrade's `Authorization` header is
still forwarded onto the `POST /v1/registration` request frame
(`WebSocketResourceProvider.getCombinedHeaders` merges upgrade + frame headers, and `Authorization`
is not in `EXCLUDED_UPGRADE_REQUEST_HEADERS`), so `RegistrationController` still reads the basic-auth
and creates the account. After registration presage reconnects with now-valid credentials and
authenticates normally. Lives as `deploy/signal-test-server/patches/0001-*.patch`, applied
idempotently by `boot.sh`.

**Why it is acceptable.** The server is single-tenant, ephemeral, and only ever holds our own test
accounts; the relaxation only affects the *upgrade-time* hard-fail, and authenticated resources
(send/receive) still reject an unauthenticated connection at the resource layer. **Not for
production** — it would let any bad credential open an unauthenticated socket there. This is a
staging-only accommodation, orthogonal to the personas protocol.

### D11. The modified Signal client pins the rustls TLS backend explicitly

**What broke.** libsignal-service's `PushService::new` builds its `reqwest` client for rustls
(`tls_built_in_root_certs(false)` + a manual `add_root_certificate`) but never *forces* the backend.
The workspace `reqwest` is declared with default features (which enable `default-tls` = native-tls).
In any build that also pulls another reqwest user with those defaults — e.g. `personas-bulletin`,
so the `personas-messenger` convergence test — Cargo unifies reqwest to compile **both** backends,
and reqwest's builder default flips to native-tls. The client then speaks the wrong TLS stack and
every request fails as an opaque "reqwest error". The standalone `transport-presage` examples never
showed it because their graph is pure-rustls.

**Decision.** Add `.use_rustls_tls()` to the vendored `PushService::new` builder — deterministic
regardless of feature unification, a no-op when only rustls is compiled in. (Alternative — set
`default-features = false` on the workspace reqwest — was rejected: it would change the *as-a-service*
`personas-client`/`personas-bulletin` HTTP path's TLS backend, a wider blast radius than pinning the
one client that actually cares.)

### D12. `PresageTransport` drives presage on a dedicated actor thread

**Why.** presage is awkward to place behind the `Transport` trait (which is `Send + Sync` with
`Send` futures): `receive_messages` uses `tokio::task::spawn_local` (so it needs a `LocalSet`, i.e. a
current-thread driver), while libsignal pumps its websockets with `tokio::spawn` (so it needs
**worker threads**). A plain current-thread runtime starves the pumps and connections drop
mid-request; a plain multi-thread runtime has no `LocalSet` for `spawn_local`.

**Decision.** `PresageTransport::start` spawns one **dedicated OS thread** that runs a *multi-thread*
Tokio runtime and drives a `LocalSet` on it (`LocalSet::block_on`) — mirroring presage-cli's
`#[tokio::main]` + `run_until`. That thread **owns** the registered `Manager` and the content cipher
(originally `GroupContentCipher`, now `PprfContentCipher` — see D13); the `Transport` (on the
caller's runtime) talks to it over `Send` channels (a command channel for sends, a broadcast channel
for decoded `Incoming`). The cipher never crosses a thread boundary. Two further sharp edges are
handled there: the thread needs a large stack (32 MiB — presage's receive future overflows the
2 MiB default), and the `Manager` clones must be dropped *inside* the runtime before it tears down
(sqlx's pool `Drop` needs a Tokio context, else a teardown panic). Callers using this transport must
run on a **multi-thread** runtime for the same `tokio::spawn`-pump reason (`#[tokio::test]` defaults
to current-thread and must opt into `flavor = "multi_thread"`).

### D13. Phase A2 replaces the Phase A1 content cipher: `PprfContentCipher` (K2/PPRF) is what `PresageTransport` runs

**What changed.** `transport-presage/src/content_cipher.rs` (Phase A1 — one shared, non-rotating
`SenderKeyRecord`, Signal's own `group_encrypt`/`group_decrypt`) is no longer what
`PresageTransport::send`/`subscribe` call. A new module, `transport-presage/src/pprf_cipher.rs`,
wraps `e2a`'s `personas_group_crypto::KeyManager` directly: `send` derives a fresh single-use `mk`
via `KeyManager::seal` (random nonce, puncture on the way out — even the sender cannot recover it
afterward), AEAD-seals the record bytes under it with AES-256-GCM-SIV, and prepends the
`MessageTag {epoch, nonce}` in the clear (`[epoch: u64 LE][nonce: 16 bytes][ciphertext]`); `subscribe`
reverses it via `KeyManager::open`, puncturing on receipt too. This is design doc §5's A2, and it is
what lifts A1's two accepted limitations (§4): concurrent sends from different members no longer
collide (independent random nonces, not a shared chain counter), and a message's key is genuinely
gone after one use (forward secrecy), not just hash-ratcheted forward.

**What did not change.** `content_cipher.rs`/`GroupContentCipher` is left in the tree, unused by the
transport, as the A1 reference implementation and its own characterization tests (why full private
state is distributed rather than an SKDM, the accepted concurrency limitation, etc.) are still worth
having on file. `PresageTransport::create_shared_key` became `create_group_secret` (returns a
`personas_group_crypto::DistributedSecret` instead of a `content_cipher::SharedSenderKey`); callers
in `transport-presage`'s examples and `personas-messenger`'s `e2e_record_converges_over_signal` test
were updated to match.

**What is deliberately still open, not touched by this change.**

- **Real pairwise distribution of the group secret (e2c).** `PprfContentCipher::create` hands back
  the `DistributedSecret` wire bytes exactly the way A1's `GroupContentCipher::create` handed back
  `SharedSenderKey` bytes — for the caller to distribute. Today that is still the bring-up stand-in
  (the caller passes the bytes directly, e.g. `shared.clone()` in the account-gated examples), not a
  real send over each member's pairwise Double Ratchet session. That plumbing is e2c, unstarted.
- **Re-key triggers (e2d).** `PprfContentCipher::rekey`/`install_rekey` expose the mechanism (install
  a fresh epoch, delete the old one wholesale — pinned by the new `rekey_excludes_the_old_epoch`
  test) but nothing calls them from a ban/leave/epoch-boundary event yet. Until e2d wires the
  triggers, a banned member who kept the group secret can still decrypt new content at the Signal
  layer — their authorisation is still revoked at the proof layer regardless (design doc §7), so
  this is a content-layer-only gap, the same one A1 always had.
- **The AEAD primitive choice** (AES-256-GCM-SIV via RustCrypto's `aes-gcm-siv`, chosen here for its
  misuse resistance and because it needed no new primitive already absent from the dependency tree)
  is implemented but not yet the subject of an actual cryptographer sign-off — design doc §10 still
  lists "confirm the AEAD primitive choice" as open, and this decision doesn't close it, only
  proposes an answer.
- **The delivery-layer phantom certificate (B2/D1, §6)** is untouched — this is purely the content
  layer. Every message under the new cipher still rides inside a real per-account sealed-sender
  envelope, so a recipient still learns the real sending account, same as before this change.

**Build/test status.** Written in a sandbox with no `cargo`/`rustc`, so it went unverified at the time
of writing. Since then, built and run on a real machine against a real (private, self-hosted staging)
Signal-Server: `cargo run -p transport-presage --example a1_smoke` passes (confirms the
registration/TLS/messaging plumbing this change rides on top of is unaffected), and
`cargo test -p personas-messenger --release -- --ignored --nocapture e2e_record_converges_over_signal`
passes — a real Groth16 ban-poll record travels over real Signal encrypted under this cipher, and the
observer's `Replica::ingest` verifies and folds it. `pprf_cipher`'s own in-process unit tests
(round trip, concurrent non-collision, replay rejection, re-key exclusion, tamper detection) have not
been separately confirmed to pass in isolation but exercise the same code paths the e2e test does.
Not independently crypto-reviewed — see the open items above (AEAD choice sign-off, e2c, e2d, B2).

### D14. B2's shared phantom identity is realized via Signal device linking, not certificate substitution — presage's `Manager` has no path to the latter

**What was tried first, and why it doesn't work.** The design as specced (§6, pre-revision): fetch the
phantom account's own `SenderCertificate` and have every member sealed-send under it directly — "a
*use* of a stock API, not a fork." Checking presage's actual public API before writing any code (its
published method list for `Manager<S, Registered>`) shows this isn't reachable: there is no method to
fetch a `SenderCertificate` anywhere on `Manager`, and no parameter on `send_message`/
`send_message_to_group` to pass one in. The vendored `libsignal-service-rs` *does* have the pieces
(`SignalWebSocket<Identified>::get_sender_certificate`, `sealed_sender_encrypt`/
`sealed_sender_decrypt_to_usmc` in `cipher.rs`), but nothing in presage exposes the authenticated
`SignalWebSocket` needed to reach them. Getting there for real would mean either forking presage (to
add the missing accessor/override) or bypassing `Manager` entirely and hand-rolling delivery directly
against `libsignal-service-rs` — a materially bigger undertaking than the original "just pass a
different certificate" framing suggested.

**What is built instead.** Signal's own multi-device linking, which presage *does* expose end to end:
`Manager::<S, Linking>::link_secondary_device` (the new device's half: generates a provisioning
request, yields its URL over a `futures_channel::oneshot::Sender<Url>`) and
`Manager::<S, Registered>::link_secondary` (the primary's half: approves a given URL). Every member
calls the former against their own fresh store; whoever holds the phantom's already-registered
`Manager` calls the latter with the resulting URL. The member ends up with their own genuine,
independent device of the *same* phantom account — own real identity key, own real device-specific
certificate — rather than borrowing the phantom's. `send_message` and every existing
`PresageTransport` code path are consequently **untouched**: a linked device's own certificate simply
names the phantom's ACI, because that's genuinely which account it now is. Implemented as
`PresageTransport::link_as_phantom_device` (`transport-presage/src/lib.rs`).

**Proof structure, not yet run.** `transport-presage/examples/b2_phantom_link.rs`: register a phantom,
register a wholly independent third "observer" account, link a member as the phantom's device, send
from the linked member to the observer, and check that the observer's decrypted sender ACI is the
phantom's — not the member's, and not some third value. That's the actual anonymity property; the
example fails loudly (`bail!`) if the observer sees anything other than the phantom's ACI.

**What's still open, deliberately not addressed here.**

- **The provisioning-URL handoff is a bring-up stand-in**, exactly like `create_group_secret`'s
  `DistributedSecret` already is: the caller passes the URL from the new device's half to the
  primary's half directly, in-process, rather than over an encrypted pairwise channel. Decided with
  the user: once e2c (real pairwise Double Ratchet distribution) exists, this URL should travel over
  the *same* pairwise session already carrying the K2/PPRF group secret, so only someone who already
  holds the group secret can ever get a device linked as the phantom.
- **Different blast radius than the original design anticipated.** A member linked as a phantom
  device is now a genuine Signal-protocol device of that account — not merely holding a copy of a
  certificate. Flagged as a new §10 sign-off item: whether that distinction (e.g., a linked-but-later-
  banned member remaining a *device* until explicitly unlinked, versus merely holding a revocable
  certificate) matters for this threat model wants explicit review.
- **Unlinking on ban/leave** is not implemented. `Manager::unlink_secondary` exists and is the
  obvious mechanism, but nothing currently calls it — this is a natural companion to the e2d re-key
  triggers, not yet wired to any ban/leave event.
- **A persistently linked device leaks a stable per-member tag** (`content.metadata.sender_device`
  is visible to every recipient and stays fixed for as long as a member remains linked, so two posts
  from the same member are linkable to each other even though they share the phantom's account id —
  see `docs/B2_DEVICE_ID_LINKABILITY_ISSUE.md`). **Still open.** Per-message rotation
  (`send_as_rotating_phantom_device`, D15) was implemented as the fix but does not close the gap on
  this server: it reuses the same freed device-id slot on every rotation, so two rotated sends still
  show the same `sender_device`. See D15's build/test status for the confirmed failure.

**Build/test status.** Written and reasoned against presage's *published* method list (fetched
directly, not guessed). Run against the staging server on the first real attempt (one small type
error fixed — `send_message` wanted the already-complete `ServiceId` the example had, not a re-wrapped
one, a copy-paste mismatch from `a1_smoke.rs`'s different variable shape): **`b2_phantom_link`
passes.** The linked member registered as an additional `device_id` of the phantom's ACI, sent
through it, and the independent observer's decrypt showed the phantom's ACI as sender — the actual
anonymity property, confirmed, not just plausible. The `LocalSet` concern flagged above as an open
unknown turned out not to be an issue: linking worked fine on the caller's ordinary runtime, no actor
thread needed.

### D15. Per-message phantom device rotation, closing D14's device-id linkability gap

**The gap, restated.** D14's `link_as_phantom_device` gives a member a *persistent* device of the
phantom account. `content.metadata.sender_device` is visible to every recipient on every message and
stays fixed for as long as that device stays linked — a stable per-member tag that lets a recipient
group every message from the same member together, even though they all share the phantom's account
id. Full writeup, requested in exactly this shape for external review:
`docs/B2_DEVICE_ID_LINKABILITY_ISSUE.md`.

**The fix.** `PresageTransport::send_as_rotating_phantom_device` (`transport-presage/src/lib.rs`):
link a brand-new, in-memory, single-use device of the phantom account, send exactly one message
through it, then unlink it — unconditionally, whether the send succeeded or failed. Mirrors the
content layer's own single-use-key discipline (`PprfContentCipher`'s `mk`, punctured the moment it's
used) at the delivery layer instead: a device id, like a message key, exists for one message and is
then gone.

**Cost.** Three network round trips per message instead of one (link is itself two round trips, one
per side of the handshake, plus the send, plus unlink) — `link_as_phantom_device`'s persistent device
pays that cost once per member for an entire session; this pays it on every single message. This is
the per-message option from the tradeoff `B2_DEVICE_ID_LINKABILITY_ISSUE.md` lays out (against the
cheaper but weaker per-epoch alternative, which is not implemented — nothing currently re-links on the
content layer's re-key cadence).

**Unlink failure handling.** If the unlink call itself fails after a send, that's logged as a warning,
not surfaced as the function's error — the caller asked about the send, and got that answer; a failed
unlink means a device may be left linked and reusable until removed some other way, which is worth
monitoring for, not something this function pretends can't happen.

**Proof structure.** `transport-presage/examples/b2_rotating_phantom.rs`: send two messages through
this function to an independent observer account, and fail loudly unless the observer sees two
**different** `sender_device` values. (`b2_phantom_link` only proves the account id is shared; it
doesn't touch this property, since it links one persistent device and never sends twice.)

**Build/test status.** Run against the staging server — it compiles and completes, but **the core
assertion fails**: both sequential rotated sends came back with the identical `sender_device`
(`DeviceId(2)` on both, in the real run). Root cause is not a bug in this implementation — it is the
server's device-id allocation policy. The server hands out the lowest free device-id slot; `unlink`
frees a slot immediately; so the very next `link` call gets that same freed slot straight back. Link →
send → unlink therefore does not achieve single-use device ids on this server, and the linkability gap
this was meant to close (see the "Still open" note added to D14's open-issues list) remains. This is a
genuine design-level finding, not something a small patch fixes: any fix needs either a different
rotation shape (e.g. a pre-linked pool of several devices, sent from at random, trading a hard
guarantee for a k-anonymity one and reintroducing a diluted version of A1's collision hazard — see the
pool-based design appended to `docs/B2_DEVICE_ID_LINKABILITY_ISSUE.md`) or accepting the persistent-
device leak as a documented residual limitation, the way sealed sender's own NDSS'21 timing leak is
accepted. Not yet decided; no implementation change has been made in response.

A related, still-unresolved question: `transport-presage/examples/b2_device_cap_probe.rs` (link
additional devices without ever unlinking, until the server's typed `DeviceLimitReached` error
surfaces, to learn the real per-account device cap — directly informs whether a pool-based pool size is
even viable) hung on a real run after successfully linking 6 additional devices, and was killed rather
than left running. Not yet debugged to a confirmed root cause; the leading hypothesis is the missing
`tokio::time::timeout` around `link_as_phantom_device`'s internal `join!` (every other network call in
this module is timeout-bounded; this one and `send_as_rotating_phantom_device`'s equivalent are not),
possibly compounded by reopening the phantom's store fresh every loop iteration with no delay between
iterations. Proposed fixes (add the timeout; reuse one phantom connection across iterations; add an
inter-iteration delay) have not been applied.

### D16. e2c: real pairwise distribution of the K2 group secret over the Double Ratchet

**What was open.** Every earlier example and the `personas-messenger` e2e test installed the K2 group
secret by handing `DistributedSecret` wire bytes across directly in a Rust variable
(`PresageTransport::create_group_secret`'s return value, passed straight to `start`) — a bring-up
stand-in explicitly flagged as such everywhere it appeared (D13, D14, `SERVERLESS_SIGNAL_DESIGN.md` §5
step 2). The design has always called for this to travel over the pairwise Double Ratchet instead
(`group.rs`'s own module doc: "hands its `DistributedSecret` wire form to every other member over the
pairwise Double Ratchet").

**What is built.** `PresageTransport::distribute_group_secret` / `receive_group_secret`
(`transport-presage/src/lib.rs`). The key realization: this needs no new cryptographic mechanism.
Sending the secret as the body of one ordinary 1:1 Signal message — `Manager::send_message`, the exact
same call the content path already uses — already runs Signal's full pairwise handshake (X3DH on first
contact, the Double Ratchet on every message after) inside `libsignal-service-rs`/`libsignal`. The
group secret's raw seed is therefore encrypted end-to-end by the time it leaves the process, satisfying
`GroupSecret::to_wire`'s documented requirement without building a second encryption layer on top. What
this function actually adds is small: JSON-serializing `DistributedSecret` (already
`Serialize`/`Deserialize`), and a body-prefix tag (`KEY_DISTRIBUTION_TAG = "personas/group-secret/v1:"`,
not valid base64) so a receiver can tell a key-distribution message apart from ordinary content
ciphertext with a `starts_with` check, before ever attempting to parse or decrypt it as either.

`receive_group_secret` drives `receive_messages` directly on a freshly loaded `Manager` (not through the
actor thread — there is no cipher to install into yet, that's the whole point of this call), filters for
the tag, and returns the decoded secret or times out.

**Proof structure.** `transport-presage/examples/e2c_key_distribution.rs`: a creator and a member
register two wholly independent accounts (no shared process state beyond ACIs), the creator distributes
a fresh secret to the member, the member recovers it with `receive_group_secret` and the example asserts
the recovered `epoch`/`seed` match byte-for-byte, and then — the part that actually matters — both sides
`PresageTransport::start` with their own copy (creator's original, member's received) and exchange one
real PPRF-encrypted content message end to end. That last step is what distinguishes this from merely
checking the bytes match: it proves the *received* secret installs a `KeyManager` that genuinely
interoperates with the creator's, not just that transit preserved the bytes.

**What's still open.** The phantom-linking provisioning URL (D14) is not yet routed over this channel,
even though the channel this finding built is exactly the one D14 called for reusing — a small follow-up
to `link_as_phantom_device`, not a new distribution mechanism. The e2d re-key triggers (when to call
`rekey`) are unrelated and remain open.

**Build/test status.** Run against the staging server: **`e2c_key_distribution` passes.** The member's
received `epoch`/`seed` matched the creator's byte-for-byte, and both sides' `KeyManager`s — one
installed from the original secret, one from the pairwise-delivered copy — interoperated end to end (the
member decrypted the creator's real content message).

The first real run showed an `ERROR ... Websocket closing: request handler failed` / `failed to upsert
newly seen contact!` pair mid-run (presage's background "newly seen contact" bookkeeping losing its
response because `distribute_group_secret`/`receive_group_secret` dropped their short-lived `Manager`
immediately after use, tearing the websocket down mid-bookkeeping) — the same intermittent race already
documented as O12, non-fatal, delivery and decryption already succeeded either way. Mitigated (not a
presage patch, just not racing the teardown): both functions now `tokio::time::sleep` 300ms after their
last network call, before `manager` drops, giving that background call time to land. Confirmed on a
second real run: that specific error pair no longer appears. A milder, different-shaped one
(`could not generate response to a Signal request; responder was canceled. continuing.`) still shows up
occasionally — same request/response-losing-its-pairing family, but presage itself logs it as
non-blocking ("continuing") rather than cascading into a bookkeeping failure, and it hasn't affected a
pass/fail result. Left alone rather than chased further.
