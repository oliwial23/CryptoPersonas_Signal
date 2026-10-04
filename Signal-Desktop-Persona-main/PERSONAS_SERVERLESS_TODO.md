<!-- Copyright 2026 Signal Messenger, LLC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Serverless gaps: badges, authorship, folded scan

What each missing feature actually needs in `CryptoPersonas_Signal` before Signal-Desktop
can show it. Written against the source, with file and line references.

**The shared reason none of these are "just a napi binding":** `personas-node` wraps the
**serverless `Messenger`**, whose entire public surface is

```
emit_join  emit_post_anon  emit_post_pseudo  emit_post_pseudo_rate
emit_poll  emit_vote  emit_rate  emit_scan
ingest_incoming  render  render_polls  barrier  tick  snapshot  adopt
```

Badges, authorship and replies live in `personas-client` — the **as-a-service** client
that talks to `personas-server` over HTTP. They were never implemented in the serverless
model, so the work is protocol work, not glue.

Ordered by effort ascending. Authorship is much closer than it looks.

---

## 1. Authorship — the cheap one

> **A UI-only mock now exists.** Persona menu → *Claim authorship… (unverified)* picks two
> of your posted pseudonyms and sends "these two are the same person" as a `PZU2:` claim.
> It is **not a proof**: no `authorship_pred` statement is built, nothing is verified, and
> any client can claim any pair of petnames — including two that are not its own. The
> bubble carries the disclaimer inline and permanently (not in a tooltip) because the
> claim is persuasive: it tells a reader that two anonymous voices are one person, which
> changes how the whole conversation reads.
>
> Files: `personasAuthorship.std.ts` (wording), `personasAuthorship.preload.ts` (send),
> `PersonaAuthorshipMessage.dom.tsx` (bubble), `PZU2:` in `personasCarriage.std.ts`.
> The claim is sent **attributably** on purpose — the claimant is voluntarily linking
> their own personas, so routing it over the phantom would falsely imply the link itself
> is protected.
>
> When the real proof lands, delete the disclaimer in the same commit that makes it false.

**Prove one member owns two pseudonyms**, without revealing which member.

### What already exists

| Piece | Where | Status |
|---|---|---|
| The circuit | `personas-core/src/circuits.rs:341` `authorship_pred` | ✅ done |
| Merkle-mode **proving key** | `personas-bulletin/src/merkle/params.rs:214-225` | ✅ **already generated** |
| Key in the bundle | same file, `:247-248` | ✅ in `ServerKeys` |

The predicate is small — it proves both claims under one `sk`:

```rust
let derived  = Poseidon::<2>::hash_in_zk(&[tu.data.sk.clone(), context.clone()])?;
let x1 = derived.is_eq(&claimed)?;
let derived2 = Poseidon::<2>::hash_in_zk(&[tu.data.sk.clone(), context2.clone()])?;
let x2 = derived2.is_eq(&claimed2)?;
Ok(x1 & x2)
```

**The proving key is already in the ~51 MB bundle every Desktop instance generates.** So
this needs no keygen change and no re-generation for existing users — which is what makes
it far cheaper than badges.

### What's missing

1. **`MemberKeys` doesn't carry it.** `personas-messenger/src/member.rs` has
   `{ standard, pseudo, pseudo_rate, scan, pseudonym_pred }`. Add `authorship_pred` and
   extract it in `from_server_keys`.

2. **No `Member::authorship()`.** Model it on `pseudonym_statement` (`member.rs:351`),
   which already builds a `PseudonymArgs { context, claimed }` proof — authorship is the
   same shape with `PseudonymArgsPair`.

3. **Decide whether it is a record.** Two options:
   - **Not a record** (recommended for the demo): the proof rides as a message and
     recipients verify it. Touches no replica accept rules, no `Record` enum, no
     convergence concerns. It is a *claim shown*, not state folded in.
   - **A record**: add `Record::Authorship`, an accept rule, and tally handling. Only
     worth it if authorship needs to be part of the convergent log.

4. **napi binding**: `emit_authorship(nonce_a, nonce_b) -> JsEmitted`.

5. **Desktop UI**: the pseudonym log already exists
   (`ts/services/personasPseudonyms.preload.ts`) and remembers nonces, so the picker for
   "prove these two are me" is a small addition to the persona menu.

**Estimated:** ~60 lines of Rust across two crates, plus the binding and UI.

---

## 2. Badges — the admin mechanism

> **A UI-only mock now exists.** Persona menu → *Badge: … (unverified)* attaches a label
> to your posts, and recipients render it as a dashed, question-marked chip. It is a
> display claim: it rides beside the record as untrusted metadata, nothing grants it and
> nothing verifies it, and any client can send any label. It demonstrates the intended UX
> and nothing about the security property. Files: `personasBadges.std.ts` (labels +
> disclaimer), `personasBadgeState.preload.ts` (the selection), `PersonaBadgeChip.dom.tsx`
> (the chip), and the `{r, b}` post envelope in `personasCarriage.std.ts`. The real
> implementation below replaces all of it; when it lands, delete the disclaimer in the
> same commit that makes it untrue.

**Prove you hold a credential (Faculty / Student / Industry) without revealing who you
are.** This is also the answer to *"how do I enforce admin?"* — see below.

### What already exists

| Piece | Where | Status |
|---|---|---|
| Three slots on the user object | `circuits.rs` `MsgUser { …, badge1, badge2, badge3 }` | ✅ |
| The predicate | `circuits.rs` `standard_badge_request_predicate` | ✅ |
| Credential constants | `circuits.rs` `FACULTY_F`, `STUDENT_F`, `INDUSTRY_F` | ✅ |
| Request interaction | `circuits.rs` `get_badge_request_interaction` | ✅ |
| Full client flow | `personas-client/src/badges.rs` (181 lines) | ✅ **as-a-service only** |
| Moderator approval route | `personas-server/src/routes/moderation.rs` | ✅ **server only** |

The circuit carries the badge slots through every post unchanged (`x6`/`x7`/`x8` in the
post predicates), so the state is preserved — it is simply never *set* in serverless.

### What's missing

`grep -ri badge crates/personas-messenger/src/` → **effectively nothing.**

1. **An approval authority.** As-a-service has a moderator endpoint. Serverless has no
   server, so this is the real design question: who grants a badge, and how does every
   replica agree that they did? Options: a designated approver key, an admin badge that
   bootstraps from the group creator, or a threshold of existing badge holders.
2. **Record kinds**: `BadgeRequest` and `BadgeGrant`, with accept rules.
3. **`Member::request_badge()` / `claim_badge()`**, modelled on `personas-client/src/badges.rs`.
4. **Badge state in the replica** so a member's badges are verifiable by others.
5. napi bindings + UI.

**Estimated:** substantially larger than authorship — a new approval flow plus two record
kinds and their accept rules.

### Why this is the admin answer

Signal's GroupV2 admin role is **server-enforced for Signal's own group operations**, but
persona records are ordinary message bodies the storage-service never inspects. So a
client-side `areWeAdmin()` check is advisory: a modified client ignores it.

Worse, it cannot be applied to the actions that most need it. Ban polls ride the phantom
precisely so nobody learns who called for a revocation — checking "is the opener an
admin" means learning who the opener is. **"Only admins can ban" and "bans are anonymous"
are mutually exclusive**, unless the admin credential lives *inside the proof*.

That is exactly what a badge is. With badges, a ban poll can carry "opened by a holder of
the moderator badge" while revealing nothing about which holder.

Desktop today gates only **attributable** actions (topic creation) on `areWeAdmin()`, and
the status panel says plainly that this is a convenience rather than enforcement.

---

## 3. Folded scan — blocked on key architecture

Plain scanning is **done**: `emit_scan` works, Desktop runs it on a 30 s loop, and the
persona menu now has a **Scan now** item for demos. What is missing is *folded* scanning —
`scan_folding`, which absorbs everything outstanding in one proof. It is **not** in the
addon, and the blocker is structural rather than a missing binding:

The proving-key cache is single-size, with the fold size baked into the cache key.
Supporting the real menu (1, 2, 4, 8, 16) means **five separate Nova-preprocessing +
Groth16 keygens**, all cached simultaneously — a large change to key generation and to
the ~51 MB bundle, not a binding.

Until then a folded scan silently drops callbacks whose fold size doesn't match, which is
why it is listed in the Desktop status panel's known limitations.

---

## Suggested order

1. **Authorship** — proving key already exists, no keygen change, ~60 lines. Best
   effort-to-payoff, and demos well (voluntarily linking two personas shows the binding
   is real).
2. **Badges** — unlocks genuine admin gating, which is the thing UI checks cannot give.
3. **Folded scan** — largest, least demo value.

---

## 0. Reputation — written, and BACKED OUT

`Engine::get_reputation()` is in `crates/personas-node/src/lib.rs` and the Desktop status
panel renders it. It is **not in the shipped binary**, because an addon built with it
SIGKILLs the render process at startup (exit code 9, no catchable error). Isolated by
rebuilding from unmodified upstream Rust, which is stable — see PERSONAS_DEMO.md §8.0.

It compiles cleanly. The runtime mechanism is unknown; signing and Cargo feature
unification were both checked and match the working build exactly.

**This is the cautionary note for everything below.** Fifteen lines of straightforward
Rust — an accessor and a field-to-f64 conversion, no `unsafe` — passed review, passed the
compiler, and killed the renderer. Every item in this document is larger than that. Budget
for the same class of failure, keep the known-good `.node` committed so there is always a
one-command way back, and change one variable at a time.

Next step is a bisect, not a re-read: replace the body with `Some(0.0)` and rebuild. Crash
means the napi binding; stable means `member()` access or `field_to_f64`.
