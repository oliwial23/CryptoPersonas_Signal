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

---

### O13. Every `receive_messages()` call races a doomed prekey refresh against process lifetime; `b2_shared_identity` is just the example that loses

**Status: fixed** (`deploy/signal-test-server/minio.sh` + patches `0003-paged-kem-prekey-store-local-s3.patch`).
The refresh itself no longer fails — verified below. Left under `O` rather than moved to the `F`
section because fixing it did not make `b2_shared_identity` pass; it uncovered a second, previously
masked bug. See **O14**.

**What.** Running `cargo run -p transport-presage --example b2_shared_identity` against the local
test-server (`docs/RUNNING_E2_LOCALLY.md` Track 2) fails at step 4 (the bootstrap round) with
`Error: observer receiving B's bootstrap — timed out waiting to receive`, on every run (5/5
observed, not intermittent). `a1_smoke` and `e2c_key_distribution` never show the failure (6/6 clean
runs combined) — but, importantly, **not because they avoid the underlying bug**. See below.

**Root cause, corrected twice — read this before trusting an earlier theory in this entry's git
history.** `third_party/presage`'s `Manager::receive_messages()`
(`presage/src/manager/registered.rs:~616`) unconditionally spawns a background task on *every* call,
for *every* account, that re-sets account attributes and then calls `register_pre_keys` →
`update_pre_key_bundle` → `PUT /v2/keys`. This is not conditional on prekey count, not triggered by a
reconnect, and not specific to any one account in the example — it is fire-and-forget, started fresh
every time `receive_messages()` is invoked.

For the PQ (Kyber) keys, that upload routes through `KeysManager::storeKemOneTimePreKeys` →
`PagedSingleUseKEMPreKeyStore`
(`~/Repos/Signal-Server/service/src/main/java/.../storage/PagedSingleUseKEMPreKeyStore.java`).
Unlike every other datastore in the test harness (DynamoDB/FoundationDB, both real Testcontainers),
this one is backed by a real `S3AsyncClient` — Kyber public keys are large enough that Signal-Server
pages them into S3 objects rather than DynamoDB rows. `test.yml`'s `pagedSingleUseKEMPreKeyStore`
block (`bucket: preKeyBucket`, `region: us-west-2`) sets no `endpointOverride`, so this client always
targets real AWS with placeholder credentials and always gets back a 403
(`The AWS Access Key Id you provided does not exist in our records`), which `KeysController.setKeys`
surfaces as an HTTP 500. Confirmed by reading `KeysController.setKeys`/`KeysManager` source directly:
this part is a synchronous, deterministic dependency of the request path, not a race.

**But whether the *background task* gets far enough to hit it is a race against the process exiting**
— and that part *is* about timing, just not the timing anyone would guess. `a1_smoke`/
`e2c_key_distribution` each decrypt one message and return almost immediately; the background refresh
(two sequential requests, ~400ms in the logs) usually hasn't reached the S3 call before `main()`
returns and the whole tokio runtime — background task included — is dropped. `b2_shared_identity`'s
**observer** account has to stay connected through four sequential exchanges (two bootstrap + two
real sends), which is enough wall-clock time for its copy of that same background task to run to
completion and fail. It is the observer, not member B — traced by `local_address` in the decrypt
spans, corrected after an earlier pass misattributed it. The observer registers via plain
`PresageTransport::register`, not `register_as_phantom` — **it isn't one of the phantom-identity
accounts at all**, which is itself evidence this has nothing to do with the shared-identity scheme.

Two wrong theories preceded this one, in order: (1) a race with `asnTable`'s S3 poller (patches
`README.md` 0002) — disproved by widening `asnTable`'s refresh interval and rebuilding; the failure
still reproduced 4/4. (2) member B's websocket dropping and reconnecting — disproved by re-tracing a
fresh run's `local_address` fields end to end instead of eyeballing nearby log lines.

**Blast radius — wider than it looks.** This is not confined to `b2_shared_identity` or to anything
resembling a reconnect. It is latent in *every* example and in the real `PresageTransport` actor:
any account whose `receive_messages()` stream stays alive for a few hundred milliseconds will trigger
the same background refresh and lose the same race. `a1_smoke`/`e2c_key_distribution` are not immune,
they are just fast enough to usually win it (verified: grepped three-then-six fresh runs of each for
`Uploading pre-keys`/`PUT /v2/keys` — zero hits so far, but "usually wins a race" is not "structurally
can't lose it"; a slower machine, a busier bootstrap, or a longer-lived manager would flip this).
Registration's own account-creation call does not go through this path (accounts register cleanly
every time). Not a production concern — real Signal infrastructure has a real S3 bucket configured;
this is a gap specific to Signal-Server's own `test-server` Maven profile, which upstream already
documents as partial ("many features are non-functional, especially those that depend on external
services").

Unrelated to the shared-phantom-identity mechanism `b2_shared_identity` actually tests (D15) — doubly
so, now that the failing account is confirmed to be the non-phantom observer.
`GET /v1/certificate/delivery` (sealed-sender certificate issuance) succeeds in every run, including
the failing ones. Steps 1–3 (independent registration under the shared ACI keypair, distinct uuids,
certificate issuance) pass every time; only the later real-send comparison is blocked. That leaves
D15's core claim — two independently-registered phantom accounts produce identical
certificate-embedded identity keys on real sealed-sender sends — without a locally-automated,
end-to-end green run (still true after the fix below — see O14).

**Fix, verified.** `deploy/signal-test-server/minio.sh` runs a local MinIO container on
`127.0.0.1:9100`, credentialed with the exact static `accessKey`/`secretAccess` pair
`test-secrets-bundle.yml` already supplies everywhere (no credential plumbing to change). Patch
`0003-paged-kem-prekey-store-local-s3.patch` does three things: points
`pagedSingleUseKEMPreKeyStore.endpointOverride` at it, enables path-style S3 addressing on that
store's `S3AsyncClient` (`WhisperServerService.java` — a plain localhost endpoint doesn't resolve
under virtual-hosted-style addressing, which is what the client defaults to), and lowercases the
bucket name from `preKeyBucket` to `prekey-bucket` (the original name is invalid under S3's
bucket-naming rules — real AWS would have rejected it too with `InvalidBucketName`; test-server's
placeholder credentials just always failed auth first, so upstream never noticed). Confirmed against
4 fresh `b2_shared_identity` runs post-fix: `Uploading pre-keys` for both ACI and PNI now completes
with no error every time (previously: `failed to register pre-keys, this is problematic and should
never happen!` / HTTP 500, every time). `a1_smoke`/`e2c_key_distribution` still pass cleanly
afterward — no regression.

---

### O14. A pre-existing websocket-teardown race — same family as O12, different request — was always there; O13 just always killed the run first

**What.** Fixing O13 did not make `b2_shared_identity` pass. It still fails identically —
`Error: observer receiving B's bootstrap — timed out waiting to receive` — on 4/4 post-fix runs.
What changed is *why*: the prekey refresh that used to 500 now succeeds cleanly every time, which
means this failure was always here, one layer down, masked because O13 reliably ended the run at
almost the same point before this could matter.

**What actually happens now (traced from a clean post-fix run).** The observer's
`receive_messages()` decrypts member A's first message fine. Immediately after, its own automatic
prekey-count-check response (`Ok(WebSocketResponseMessage { status: 200/204, body:
{"count":0,"pqCount":0}, .. })` or similar) arrives too late — `Could not deliver response for id
...` — and `SignalWebSocket: Websocket closing: request handler failed` tears the connection down.
Presage logs `failed to upsert newly seen contact!` and (now successfully) starts the prekey
refresh. But whatever reads B's subsequent message never sees it: the run sits idle until the
45-second `receive_one` timeout, with nothing in between but two `could not generate response to a
Signal request; responder was canceled` lines around the 45s mark.

This is architecturally the same shape of bug as O12 — a response to a request riding the
identified websocket arrives after the channel that was waiting for it has already been torn
down/replaced — just on a different request (an automatic count-check inside `receive_messages()`'s
background task, not `send_message`'s post-send bookkeeping) and with a worse outcome: O12's send
path is proven non-fatal (the receiver's own decrypt is the source of truth, and delivery is
confirmed independently). Here, nothing re-establishes the observer's ability to receive after the
teardown within the test's window — whether that's because `b2_shared_identity`'s `receive_one`
helper opens a **fresh** `receive_messages()` call per message (plausible: it calls
`receiver.receive_messages().await` fresh on every invocation, so an in-flight message could be
delivered to a stream a *previous* `receive_one` call already returned from and dropped) or because
presage's own reconnect doesn't resume the message stream, is not yet determined — this needs the
same level of source-verification O13 got before committing to an explanation, not another
timing-correlation guess.

**Not yet diagnosed to the same confidence as O13.** Flagging the open question rather than a
theory: is this a bug in the test harness's example code (`receive_one`'s re-call pattern), in
`third_party/presage`'s reconnect handling, or in the test-server's response-delivery timing under
load? The real `PresageTransport` actor (`transport-presage/src/lib.rs`) calls `receive_messages()`
exactly once per actor lifetime, not per-message, and has no reconnect logic if that single stream
ends — so this specific manifestation may be test-harness-specific, but the underlying "response
arrives after the waiting channel is gone" race is not.

**To fix.** `PagedSingleUseKEMPreKeyStoreConfiguration` already supports an `endpointOverride`
(nullable `URI`, unset here). Standing up a local S3-compatible mock (e.g. MinIO, alongside the
existing TLS-proxy container in `deploy/signal-test-server`) and pointing `endpointOverride` at it
via a new patch would close this — except the `S3AsyncClient.builder()` call for this store
(`WhisperServerService.java`, `asyncKeysS3Client`) doesn't enable path-style addressing the way
`asnTable`'s alternate constructor does, so redirecting it needs a small source patch
(`S3Configuration.builder().pathStyleAccessEnabled(true)`) in addition to the config change and the
new container. Not yet implemented — a real (if bounded) scope decision, not a quick fix.

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

### D14. e2c: real pairwise distribution of the K2 group secret over the Double Ratchet

**What was open.** Every earlier example and the `personas-messenger` e2e test installed the K2 group
secret by handing `DistributedSecret` wire bytes across directly in a Rust variable
(`PresageTransport::create_group_secret`'s return value, passed straight to `start`) — a bring-up
stand-in explicitly flagged as such everywhere it appeared (D13, `SERVERLESS_SIGNAL_DESIGN.md` §5
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

**What's still open.** This finding is unrelated to B2 (D1, §6 — the shared phantom sealed-sender
identity), which was open at the time this was written and is now built — see D15. The e2d re-key
triggers (when to call `rekey`) remain open.

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

### D15. B2/D1 realized as a shared ACI identity keypair — a `presage` fork, not certificate substitution
or device linking

**Why the two earlier approaches don't work.** Certificate substitution alone (attach the phantom's
`SenderCertificate` while continuing to encrypt under a member's own identity key) is not an
implementation gap — it is cryptographically incoherent. Checked directly against
`signalapp/libsignal`'s `sealed_sender_decrypt` (`rust/protocol/src/sealed_sender.rs`): the recipient
decrypts using the Double Ratchet session stored under `ProtocolAddress::new(cert.sender_uuid(),
cert.sender_device_id())` — the address the *certificate* names, not whatever the sender actually used.
Attach a certificate naming the phantom while encrypting under a different identity key, and the
recipient looks up a session keyed to a different ratchet chain entirely; decryption fails outright, it
doesn't just misattribute. Device linking (D14) sidesteps this correctly — a linked device genuinely
receives the phantom's real identity key during linking — but leaks a persistent per-member `device_id`
tag (`docs/FINDINGS.md`'s D14/D15 history, both reverted in this session before this entry).

**The unblocking insight (credit: external/professor review, not found independently at first).** The
identity keypair backing an account's Double Ratchet sessions is not fixed to "whatever was randomly
generated at registration" — it is just a Curve25519 keypair, freely choosable, and nothing requires it
to be unique per account. So: give every member their own, completely independent real Signal account
(own phone number, uuid, device id, prekeys, sessions) — except register with the **same** ACI identity
keypair instead of a random one. Signal's server, seeing an ordinary registration, legitimately signs
that account's own `SenderCertificate` — which now embeds the same public identity key as every other
member's. Nothing about certificate issuance or session establishment changes; `Manager::send_message`
and every existing `PresageTransport` code path are untouched.

**Why this doesn't collide.** X3DH still mixes in each member's own distinct signed-prekey and
one-time-prekey (fetched from *that account's own* published bundle) even though the identity-key input
is shared, so two members' sessions with a given recipient stay entirely independent ratchet chains —
unlike sharing a sender-key chain (A1's own accepted limitation) or sharing a device id (D14's rotation
attempt), which collide because they share *mutable, sequentially-advanced* state. A shared identity key
is static input to independent handshakes, not shared mutable state.

**What's built.**

- `crates/personas-group-crypto/src/group.rs`: `DistributedSecret::derive_phantom_identity_seed` — HKDF
  over `(seed, epoch)`, domain-separated (`personas/phantom-identity-seed/v1`) from the epoch-key and
  message-key derivations so the three can never be confused. Returns raw bytes — the crate stays
  libsignal-free by design (its own module doc). Epoch-scoped like the rest of the secret: a re-key
  produces a *different* phantom identity, which is semantically right (a banned member shouldn't stay
  bound to the shared identity any more than they stay able to decrypt) but costly — an identity-key
  change means re-registration, not just installing a new `KeyManager`. Three new unit tests: determinism
  across members, difference across epochs/secrets, domain-separation from the epoch key.
- `third_party/presage` (**newly vendored** — mirrors the existing `libsignal-service-rs` vendoring
  pattern: cloned at the same pinned rev already used elsewhere in this workspace,
  `63482efd0cbdc0780baf0650517c7d55f1cac05d`, root workspace Cargo.toml stripped so it doesn't create a
  nested-workspace conflict, patched in via `[patch."https://github.com/whisperfish/presage"]`). The
  actual fork, in `presage/src/manager/confirmation.rs`: `Manager::confirm_verification_code` always
  called `IdentityKeyPair::generate(&mut rng)` inline with no seam to override it. Refactored into a
  private `confirm_verification_code_impl(self, code, aci_identity_key_pair: Option<IdentityKeyPair>)`,
  with the original public method delegating with `None` (unchanged behavior for every existing caller)
  and a new `confirm_verification_code_with_identity` delegating with `Some(...)`. PNI identity is
  unaffected — still always random — since PNI is unrelated to what this scheme shares.
- `third_party/libsignal-service-rs`'s `cipher.rs`/`content.rs`: `Metadata` gains
  `sender_identity_key: Option<PublicKey>`, populated only on sealed-sender deliveries. The private
  `sealed_sender_decrypt` helper already had the validated `UnidentifiedSenderMessageContent` (and thus
  `usmc.sender()?.key()?`, the certificate's embedded key) in scope and was simply discarding it after
  building `SealedSenderDecryptionResult` — changed its return type to also hand back the key, no new
  decrypt call needed. Every other `Metadata` construction/destructuring site in both vendored trees
  (9 total across `libsignal-service-rs` and `presage`/`presage-store-sqlite`) updated to set/ignore the
  new field — the SQLite persistence layer doesn't have a column for it yet, so a message reloaded from
  disk reports `None` regardless of how it originally arrived; a real limitation, not silently patched
  over.
- `transport-presage/src/lib.rs`: `PresageTransport::register_as_phantom` (derive the seed, build the
  `IdentityKeyPair` via `PrivateKey::deserialize` + `.public_key()`, call the forked confirmation method)
  and the receive loop now reports `content.metadata.sender_identity_key` (base64, `phantom:` prefix)
  in place of the uuid whenever it's present, falling back to the real uuid otherwise — sealed sender
  itself is conditional here (`Manager::send_message` only attempts it once the sender's store already
  holds the recipient's profile key, which presage learns automatically from one prior identified
  message in each direction), so the fallback is a real, not theoretical, path.

**What's still open.** Making sealed-sender delivery *reliably* engaged — today it depends on an earlier
identified round trip having happened in each direction; nothing forces that ahead of time. The e2d
re-key triggers, and what rotating the phantom identity on re-key would actually require operationally
(re-registration is not something that can happen silently). Interop with real, unmodified Signal clients
is untested and unspecified given the shared-identity-key deviation from Signal's normal one-key-per-
account trust model — flagged as a new §10 sign-off item, not something this document can resolve alone.

**Proof structure.** `transport-presage/examples/b2_shared_identity.rs`: two members register
independently via `register_as_phantom` with the same group secret; an independent observer registers
normally; a bootstrap round (each member → observer, observer → each member) lets profile keys exchange
so the real test sends go out sealed-sender; each member then sends the observer one more message. Passes
only if the observer sees two *different* `sender` uuids (not device linking) and two *identical*
`sender_identity_key` values (the actual property this scheme needs).

**Build/test status.** Written and reasoned against `signalapp/libsignal` v0.94.4 and the exact pinned
`presage`/`libsignal-service-rs` revisions already used elsewhere in this workspace, checked directly
against source (not guessed) for every claim above about how `sealed_sender_decrypt`, `IdentityKeyPair`,
`PrivateKey::deserialize`, and `confirm_verification_code` actually work. Not yet independently run
against the staging server — same caution as any unverified entry here applies until it is.
