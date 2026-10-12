<!-- Copyright 2026 Signal Messenger, LLC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Making badges, authorship and ratings real in ZK

Ordered work plan. Written against the source in both repos, with file and line
references. Companion to `PERSONAS_SERVERLESS_TODO.md` (which describes the gaps) and
`PERSONAS_DEMO.md` §8.0 (which records the crash that gates all of it).

---

## Step 0 — Run what exists

Three processes, in order. Paths assume the CryptoPersonas workspace at `$RUST`.

```sh
# 1. chat server + storage service + TLS proxy
cd $RUST/deploy/signal-test-server  && ./boot.sh
cd $RUST/deploy/storage-service     && ./boot.sh
cd $RUST/deploy/signal-test-server  && ./tls-proxy.sh up   # not plain-proxy.sh: that
                                                           # is for TLS terminated
                                                           # upstream of this host
./verify.sh                                                # expect pong / 422 / 405 / 400

# 2. client config (once, per instance)
cd <desktop>
PERSONAS_RUST_DIR=$RUST ./scripts/personas-demo-setup.sh

# 3. instances
pnpm install && pnpm run build:dev
./scripts/personas-run.sh alice --reset
./scripts/personas-run.sh bob   --reset
```

`--reset` after **any** backend restart: accounts and joins are ephemeral, so a stale
`userData` leaves a client that looks logged in holding an account the server forgot.

Then confirm the baseline works before changing anything: post anonymously, post under a
pseudonym, open a poll, vote, open a ban poll, watch the flag land. Persona menu →
**Persona status…** should show the same barrier and fingerprint on every instance. A
differing fingerprint means the replicas have diverged and every tally is unreliable.

---

## Step 1 — Reactions: already ZK, the UX is what's broken

**No Rust needed.** `emitRate` produces a real Groth16 rating that rides the phantom
identity, and the rating is pseudonymous in-circuit (`member.rate` uses
`context = target.context()`, giving one rating per member per target). This is done.

What is actually wrong, all TypeScript:

1. **No feedback.** 👍/👎 on a persona post are intercepted
   (`personasActions.preload.ts` `maybeSendPersonaRateForReaction`) and become rate
   records instead of visible reactions — correct, because showing them would attach your
   real account to a pseudonymous rating. But nothing tells the user anything happened, so
   the gesture looks broken. Add a toast ("Rated +1 as a persona").
2. **You cannot rate your own posts.** `canReplyOrReact` (`state/selectors/message.preload.ts:2382`)
   requires, for outgoing messages, a recipient in `isSent` state — which a phantom-routed
   send does not record the usual way. So `canReact` is false on your own persona posts.
   Fix the send-state bookkeeping, or decide self-rating should be disallowed and say so.
3. **Non-thumbs reactions leak the reactor.** ❤️ on an anonymous post goes out from your
   **real** account, publicly linking you to that post. Nothing currently prevents this.
   Either block non-thumbs reactions on persona posts, or warn.

Reputation *read-back* is a separate problem — see Step 2.

---

## Step 2 — `get_reputation`: **DONE. And the exit-9 gate is resolved.**

> **RESOLVED 2026-10-11.** Exit 9 was a **build** problem, not a limit on this layer.
>
> Adding `ark-ff` as a direct dependency of `personas-node` — to get `PrimeField` for a
> field-to-number conversion — produced an addon that killed the Electron renderer **at
> load**, before `background.html` rendered and before any method in the crate ran. The
> decisive evidence was a stage-1 build whose body was the byte-identical `Some(0.0)`
> stub that had always been stable: it crashed the same way. That isolates the fault to
> the dependency graph, where `Cargo.lock` showed exactly one new edge (`+ "ark-ff"`).
> One extra edge changed Cargo's feature unification and the result would not initialise.
>
> **Fix:** put the conversion in `personas-core`, which already depends on `ark-ff`, and
> leave `personas-node`'s dependency graph identical to the known-good one. With that,
> the real read works:
>
> ```rust
> self.inner.member().map(|m| personas_core::field_to_f64_signed(&m.user.data.reputation))
> ```
>
> **Consequences for the rest of this plan:**
> * Adding napi methods to `personas-node` is **not** inherently unsafe. Authorship
>   (~60 lines) and badges are no longer gated on this question.
> * The rule that matters is narrower and easy to follow: **do not add dependencies to
>   `personas-node`.** Put anything needing a new crate behind a helper in a crate that
>   already has it.
> * A SIGKILL at *startup* means the addon, not your code. A SIGKILL later, under load,
>   is the separate memory problem (see `personas-run.sh`'s pre-flight check).
>
> The four-stage ladder survives as a runtime switch (`PERSONAS_REPUTATION_STAGE`,
> default 4) for the next bisect of this kind. One build, four behaviours.

### The trap this stub was hiding

The placeholder returned a constant `Some(0.0)`. On a fresh member a *correct*
implementation also reads zero, so the panel showed a plausible `0` that never moved —
and there was no way to tell "working, nothing to report" from "not implemented". That is
exactly the failure mode the status panel exists to prevent, and it is why the panel now
logs the raw value and type (`personas: getReputation -> 2 (typeof number)`).

### One correctness detail worth keeping

Reputation is a running sum of +1/-1 ratings, so it can go negative, and field
arithmetic has no negatives: `-1` is stored as `p - 1`. Reading the limbs naively reports
a reputation of -1 as roughly `2.7e76`. `field_to_f64_signed` treats values above
`(p-1)/2` as `v - p`.

### Historical: the bisect procedure (kept for reuse)

```rust
// crates/personas-node/src/lib.rs, inside #[napi] impl Engine
#[napi]
pub fn get_reputation(&self) -> Option<f64> { Some(0.0) }
```

**Stage 1 is already written** into `crates/personas-node/src/lib.rs` (`bisect_ping` plus
`get_reputation` returning `Some(0.0)`), with the full four-stage ladder documented in a
comment block beside it. Rebuild and launch:

```sh
PERSONAS_RUST_DIR=$RUST pnpm --filter @signalapp/personas-engine build
./scripts/personas-run.sh alice
```

**Launching is itself the test.** The original crash happened at startup — before
`background.html` loaded — so it was at addon load / napi registration time, not when
anything called the method. You do not need to invoke the probes: if the app reaches the
conversation list, registration survived. Then persona menu → **Persona status…**: a
reputation row reading `0` (rather than `—`) confirms the call and `Option<f64>`
marshalling also work.

If it crashes, restore the known-good binary and you are back where you started:

```sh
git checkout -- packages/personas-engine/personas-engine.darwin-arm64.node
```

| Outcome | Meaning | Next |
|---|---|---|
| Crashes at stage 1 | Adding *any* napi method to this crate breaks the addon | **Stop.** Suspect napi-derive/codegen, the Electron ABI, or the build itself. Authorship and badges are unreachable until this is understood |
| Stable at stage 1 | Codegen and `Option<f64>` marshalling are fine | Stage 2: `self.inner.member().map(\|_\| 0.0)` |
| Crashes at stage 2 | Reaching into `inner`/`Member` is at fault, not arithmetic | Look at the borrow and at `Messenger::member()` |
| Crashes at stage 3 | `field_to_f64` is at fault — my code, `into_bigint().to_bytes_le()` and a negation | Rewrite to avoid field arithmetic entirely; return a decimal string instead |
| All four stable | The original crash was environmental, not the code | Re-test the original patch in `stash@{0}` |

Capture the kill reason while it is reproducible — this was never obtained:

```sh
log stream --predicate 'eventMessage CONTAINS "Signal"' --info   # in a second terminal
```

---

## Step 3 — Authorship for real

Prove one member owns two pseudonyms without revealing which member.

### Already done

| Piece | Location | Status |
|---|---|---|
| Circuit | `personas-core/src/circuits.rs:341` `authorship_pred` | done |
| Proving key generated | `personas-bulletin/src/merkle/params.rs:214-225` | done |
| Key in `ServerKeys` | `personas-core/src/params.rs:83-84` | **already ships** |
| **Working prover** | `personas-client/src/flows.rs:386` `make_authorship_proof` | **already written** |
| **Working verifier** | `personas-server/src/routes/post.rs:692` `verify_predicate` | **already written** |

The key is in the ~51 MB bundle every instance already generates, so **no keygen change
and no regeneration for existing users.** This is what makes authorship the cheap one.

The last two rows matter more than the rest: both halves already exist in the
**as-a-service** crates. `make_authorship_proof` builds the `PseudonymArgsPair`, calls
`prove_statement_and_in` with `authorship_pred`, and encodes a `Kind::Predicate` record
with public inputs **`[context1, claimed1, context2, claimed2]`**. `verify_predicate` is
ten lines of `Snark::verify` against the verifying key. Neither has to be invented — the
serverless path needs them ported, not designed.

### Missing

1. **`MemberKeys` does not carry it.** `personas-messenger/src/member.rs:76-82` has
   `{ standard, pseudo, pseudo_rate, scan, pseudonym_pred }`. Add `authorship_pred` and
   extract it in `from_server_keys` (same file, ~line 88).
2. **No `Member::authorship()`.** Model on `pseudonym_statement` (`member.rs`, which
   builds a `PseudonymArgs { context, claimed }` proof around line 192). Authorship is the
   same shape with `PseudonymArgsPair` — already imported at `member.rs:34`.
3. **Decide record-vs-not.**
   - *Not a record* (recommended): the proof rides as a message, recipients verify it.
     Touches no accept rules, no `Record` enum, no convergence concerns. It is a claim
     *shown*, not state folded in.
   - *A record*: `Record::Authorship` + accept rule + tally handling. Only worth it if
     authorship must be part of the convergent log.
4. **napi binding:** `emit_authorship(nonce_a, nonce_b) -> JsEmitted`.
5. **Desktop:** replace the mock. `personasAuthorship.preload.ts` already has the send
   path and the pseudonym log already remembers nonces, so this is mostly deleting the
   disclaimer and calling the real binding. Delete `AUTHORSHIP_DISCLAIMER` in the same
   commit that makes it false — do not soften it.

6. **A verify binding, not just a prove one.** `verify_authorship(record) -> Option<[F;4]>`
   wrapping `Snark::verify` against `authorship_pred_verifying_key`, modelled on
   `verify_predicate`. Without this the recipient has a proof it cannot check, which is
   no better than today's unverified claim.

### The trap that makes a "verified" badge a lie

**The proof's public inputs are field elements; the UI shows petnames.** A verified
authorship proof asserts a statement about `claimed1` and `claimed2` — the pseudonym
field elements. It says nothing about the two NAMES the bubble happens to display.

So this is not sufficient:

```
verify(proof) == true   →   render "✓ verified: ~alice-1 = ~alice-2"
```

A sender could carry a valid proof about two pseudonyms they do own, alongside display
names belonging to someone else's personas, and the UI would vouch for it. The checkmark
would be real and the statement false.

The recipient must therefore **derive the displayed names from the proof's own public
inputs** — map `claimed1`/`claimed2` to petnames the same way a post's petname is
derived — and render those, ignoring any names carried in the carriage. Equivalently:
verify, then recompute the labels; never verify and then trust labels.

This is the one place where an incremental "make it verified" change can produce
something worse than the honest unverified version, because a wrong checkmark is
believed. It is also why `AUTHORSHIP_DISCLAIMER` must not be deleted until the label
derivation is in place, not merely when the proof verifies.

**Estimate:** ~60 lines of Rust across two crates, plus the verify binding, the petname
derivation, and the UI. The proving and verifying logic is a port of existing code; the
petname binding is the part that needs thought.

---

## Step 3b — Outright admin ban (no poll)

**Correction to an earlier claim in this document.** "The protocol has no unilateral
ban" was wrong. Banning is not a `Record` variant — it is a **callback invocation**, and
the serverless replica already performs it. The as-a-service server did:

```rust
let arg = F::from(BAN_FLAG);
let called = db.call(cb, arg, FakeSigPrivkey::sk())?;   // handle_send_ban_request
CStore::verify_call_and_append(&mut db.callback_bul, called.0, called.1, called.2, epoch)?;
```

The replica's own settlement does the same thing (`replica/mod.rs:862-890`):

```rust
let arg = if out.banned { F::from(BAN_FLAG) } else { arg_rep(out.clamped_rep()) };
if invoke(cbs, &out, arg) { /* ... */ }
if out.banned { derived.flag_author(&author); }   // rendering gate, §9
```

Proven end to end in `replica/e2e_tests.rs:504-520`: `invoke_into(.., F::from(BAN_FLAG))`
and then "T's object, having absorbed BAN_FLAG, is now banned."

### So what is actually missing

Only the TRIGGER. `out.banned = true` is set in exactly one place
(`replica/mod.rs:843`), reachable only from a ban poll that closed `yes > no`.

1. **`Record::Ban { target: Eh, sig }`** — a new variant whose accept rule sets
   `derived.outstanding.get_mut(&target).banned = true`. Everything downstream is
   untouched: the next barrier invokes `BAN_FLAG`, the target's next scan absorbs it,
   `circuits.rs:588/616` sets `banned` in their object, and their post proofs stop being
   satisfiable. The author's existing posts get flagged by `flag_author` on sight.
2. **An admin identity in the protocol** — the one real gap. Nothing today distinguishes
   an admin, so any member could emit `Record::Ban`. Two options:
   * **`admin_pubkey` in `ReplicaConfig`** plus a signature check in the accept rule.
     Every replica knows the key, so the rule is deterministic and convergent — which is
     the hard requirement (§d1). This makes the ban genuinely enforced.
   * **Client-side gate only** (what the menu item does today). Unenforced: a modified
     client ignores it.
3. **The banned user's notification.** Their scan is where they learn, because that is
   when `banned` flips. Surface it from the scan result, not from the ban record — a
   banned member may never see the record, but they cannot avoid the scan.
4. **Composer gate.** With `banned` set, persona sends must be refused *before*
   attempting a proof, so the user gets the notification rather than an opaque failure.
   Real-identity sends stay allowed.

**Estimate:** much smaller than previously written here. One record variant, one accept
rule, one config field and a signature check. No new circuit, no new callback mechanism,
no change to settlement timing.

**Note on timing, which the UI must not misrepresent:** the ban takes effect at the next
*barrier* (invocation) and bites at the target's next *scan*. It is not instantaneous,
so "banned" in the admin's UI means "ban recorded", not "already powerless".

---

## Step 4 — Badges for real

**The blocker is a design decision, not code.** More exists than previously documented.

### Already done

| Piece | Location |
|---|---|
| Three badge slots on the user object | `circuits.rs:120` `MsgUser { badge1, badge2, badge3 }` |
| Request predicate | `circuits.rs:492` `standard_badge_request_predicate` (**private — needs `pub`**) |
| Request interaction | `circuits.rs:742` `get_badge_request_interaction` |
| Proving keys | `params.rs:85-86` `badge_pred_*`, `params.rs:91-92` `badge_request_*` — **already ship** |
| Full client flow | `personas-client/src/badges.rs` (~181 lines) — **as-a-service only** |
| Moderator approval route | `personas-server/src/routes/moderation.rs` — **server only** |

Post predicates already carry the badge slots through unchanged (`circuits.rs:417,443,475`),
so state is preserved — it is simply never *set* in the serverless model.

### Missing

`grep -ri badge crates/personas-messenger/src/` → effectively nothing.

1. **An approval authority — decide this first.** As-a-service has a moderator endpoint.
   Serverless has no server. Who grants a badge, and how does every replica agree they
   did? Options:
   - a designated approver public key, fixed at group creation;
   - an admin badge bootstrapped from the group creator, which then grants others;
   - a threshold of existing badge holders.
   This choice determines the record kinds and accept rules, so nothing below can be
   written until it is settled.
2. `Record::BadgeRequest` / `Record::BadgeGrant`, with accept rules.
3. `Member::request_badge()` / `claim_badge()`, modelled on `personas-client/src/badges.rs`.
4. Badge state in the replica so a member's badges are verifiable by others.
5. napi bindings, then replace the Desktop mock (`personasBadges.std.ts`,
   `PersonaBadgeChip.dom.tsx`) and delete `BADGE_DISCLAIMER`.

### Why badges are also the admin answer

Signal's GroupV2 admin role is server-enforced for Signal's *own* group operations, but
persona records are ordinary message bodies the storage-service never inspects. A
client-side `areWeAdmin()` check is therefore advisory — a modified client ignores it.

Worse, it cannot apply to the actions that most need it. A ban poll rides the phantom
precisely so nobody learns who called for a revocation, so checking "is the opener an
admin" means learning who the opener is. **"Only admins can ban" and "bans are anonymous"
are mutually exclusive** unless the credential lives inside the proof. That is what a
badge is.

---

## Step 5 — Other critical issues

| Issue | Severity | Notes |
|---|---|---|
| **Replica state is in-memory only** | high | A restart forgets every record while chat history survives, leaving a populated UI over an empty replica: tallies read zero and bans cannot settle. The status panel reports this as *state lost*. `personas-bulletin` already has a journal (`replica/tests.rs` `the_journal_survives_a_restart`) — wire it up in `personas-node`. |
| **Addon ships darwin-arm64 only** | medium | `personas-engine.darwin-arm64.node` is the sole committed binary. Any collaborator not on Apple Silicon must build from `crates/personas-node`. |
| **Folded scan unavailable** | low | The proving-key cache is single-size with the fold size in the cache key. Supporting the real menu (1,2,4,8,16) needs five Nova-preprocessing + Groth16 keygens cached simultaneously. Architectural, not a binding. |
| **~115 MB of generated keys committed** | low | `nova_params.bin` (64 MB) and `merkle_groth16_keys.bin` (52 MB) exceed GitHub's recommended size. Both are regenerable. Moving them out needs a history rewrite, so decide with the repo owner. |
| **Two canonical trees** | process | `CryptoPersonas_Signal/main` now vendors a ZIP snapshot of Desktop in `Signal-Desktop-Persona-main/`. It has no history and cannot pull upstream changes. Agree on one source of truth; a snapshot that silently goes stale is how `main` lost its Rust workspace. |

---

## Recommended order

1. **Step 0** — confirm the baseline works.
2. **Step 1** — reaction UX. TypeScript only, zero risk to the addon, immediate payoff.
3. ~~**Step 2** — bisect `get_reputation`.~~ **DONE** — exit 9 was the `ark-ff`
   dependency edge, not this layer. No longer gates anything.
4. **Step 3** — authorship. **Now the next piece of real work.** Cheapest real ZK: the
   proving key already ships, and both a reference prover
   (`personas-client::make_authorship_proof`) and a reference verifier
   (`personas-server::verify_predicate`) already exist to port.
5. **Step 4** — badges. Settle the approval authority before writing code.
6. **Step 5** — persistence first among the rest; it undermines every demo.

Keep the known-good `.node` committed throughout, so there is always a one-command way
back: `git checkout -- packages/personas-engine/personas-engine.darwin-arm64.node`.
