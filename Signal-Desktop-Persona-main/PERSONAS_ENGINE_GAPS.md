<!-- Copyright 2026 Signal Messenger, LLC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Desktop vs. the CryptoPersonas engine — what is and isn't wired

Written against the actual `CryptoPersonas_Signal` source, not inferred. Every claim
below cites the file it came from.

**An earlier version of this document was wrong on three counts** — it was written
without access to the Rust workspace, from binary symbols and the napi `.d.ts`. Those
errors and their corrections are recorded at the bottom, because two of them were
"this is not enforced" claims that were false and would have been embarrassing to
repeat in a talk.

---

## Enforced end to end

| Behaviour | Where |
|---|---|
| **One vote per member, unlinkable to the account** | `member.vote` sets `context = poll.context()` and derives `claimed = pseudonym(sk, context) = H(sk, context)` — **no nonce**, so exactly one pseudonym per poll. (`personas-messenger/src/member.rs`, `personas-core/src/persona.rs`) |
| **One rating per member per target** | `member.rate` does the same with `context = target.context()`. |
| **Unpredictable poll/rating contexts** | `Eh::context() = Poseidon(eh)` — "unpredictable until the record exists (which is what stops a member pre-computing a pseudonym), and unique per record… **It replaces the service's `fresh_context()`**." (`personas-bulletin/src/replica/record.rs`) |
| **Topic-scoped rate-limited personas** | `pseudonym_rate(sk, context, i) = H(sk, context, i)`, enforced by `standard_pseudo_rate_predicate`. Desktop passes a real per-topic context. |
| **Unlimited plain pseudonyms** | `emit_post_pseudo` does `F::from(context as u64)` — the argument is an opaque field element, so Desktop's random nonce per persona is valid. |
| **Author anonymity on the wire** | Signal-side, via the shared phantom identity. Independent of the circuit. |
| **Ban settlement / revocation flagging** | Engine accept rules + the shared barrier schedule. |

---

## The complete feature surface, and where each one stops

`personas-cli`'s `MessengerCmd` is the full serverless feature list (26 commands).
`personas-node` exposes **18 napi methods**, of which 8 are emitters. Everything not in
that column is unreachable from Desktop no matter what the UI does.

Addon surface, verbatim:

```
emit_join  emit_post_anon  emit_post_pseudo  emit_post_pseudo_rate
emit_poll  emit_vote  emit_rate  emit_scan
ingest  render  render_polls  log  log_entry
barrier  tick  fingerprint  current_barrier  new
```

| CLI command | In addon | In Desktop | Notes |
|---|---|---|---|
| `Join` | `emit_join` | ✅ auto-join | |
| `Post` (anon) | `emit_post_anon` | ✅ Anonymous | |
| `PostPseudo` | `emit_post_pseudo` | ✅ New persona | unlimited, no topic |
| `PostPseudoRate` | `emit_post_pseudo_rate` | ✅ Persona #1–4 | topic-scoped |
| `Poll` | `emit_poll` | ✅ composer poll modal | |
| `BanPoll` | via `emit_poll(kind='ban')` | ✅ context menu | no dedicated method |
| `Vote` | `emit_vote` | ✅ poll bubble | |
| `Reaction` | `emit_rate` | ✅ 👍/👎 | |
| `Scan` | `emit_scan` | ✅ automatic loop | |
| `NewThreadCxt` | ❌ | ⚠️ client-side stand-in | `personasTopics.preload.ts` |
| `GetContexts` | ❌ | ⚠️ topic announcements | same stand-in |
| `CountVotes` | ❌ | ⚠️ `render_polls` status line only | no structured tally |
| **`Rep` / `SingleRep` / `GetRep`** | ❌ | ❌ | **reputation is invisible** |
| **`RequestBadge` / `ApproveBadge` / `Badge`** | ❌ | ❌ | see below |
| **`Reply` / `ReplyPseudo`** | ❌ | ❌ | threaded replies under a persona |
| **`Authorship`** | ❌ | ❌ | proving you wrote a post |
| `Ban` (direct) | ❌ | ❌ | only via ban poll |
| `GenPseudo` / `PseudoIndex` | ❌ | ❌ | no pseudonym log |
| `UpdateEpoch` | ❌ | ❌ | |
| `ScanFolding` | ❌ | ❌ | Nova folding scan |

### Priority, if the aim is a complete demo

1. **Reputation.** `MsgUser` carries `reputation`, `emit_rate` moves it, and Desktop
   already has the 👍/👎 gesture wired — but `JsLogEntry` is
   `{ eh, kind, author, body, flagged }` with no reputation field, so **members can rate
   each other and nobody can ever see the result**. The loop the paper is built around is
   half-connected: input works, output does not exist. Cheapest high-value fix — likely
   one field on `JsLogEntry` plus a getter.
2. **Badges.** Biggest surface, fully built in Rust (below), zero Desktop reach.
3. **Replies** (`ReplyPseudo`). Threading is the most conspicuous *chat* feature missing;
   a group chat without replies reads as a prototype.
4. **Authorship.** Voluntary de-anonymisation — narratively strong for a demo, since it
   shows the persona binding is real and the author can choose to reveal it.
5. Everything else is nice-to-have.

All of these need the same kind of work: **napi bindings in `personas-node`**.
`personas-client` is the reference implementation for each.

---

## Implemented in Rust, NOT reachable from Desktop

### Badges — the big one

Badges are **fully built** and completely invisible to Desktop.

- `MsgUser { sk, reputation, num_interactions_since_last_scan, pseudo_counter, banned, badge1, badge2, badge3 }` — three slots (`personas-core/src/circuits.rs`).
- `standard_badge_request_predicate` + `BadgesArgs`, with credential constants `FACULTY_F`, `STUDENT_F`, `INDUSTRY_F`.
- `personas-client/src/badges.rs` (181 lines): claim/show flows, `badges.jsonl`, `BADGE_SLOTS = 3`, `badge_name()` → "Faculty" / "Student" / "Industry". Each slot records **which pseudonym it was claimed under** — "that binding is local, and it is the only thing linking the badge to a persona."
- Reachable from `personas-cli` and the **Slack transport**; there is a server moderation route.

**Why Desktop can't see them:** `personas-node` exposes 18 napi methods —
`emit_join`, `emit_post_pseudo`, `emit_post_anon`, `emit_post_pseudo_rate`, `emit_poll`,
`emit_vote`, `emit_rate`, `emit_scan`, `ingest`, `render`, `render_polls`, `log`,
`log_entry`, `barrier`, `tick`, `fingerprint`, `current_barrier`, plus the constructor.
**None of them touch badges.** So a Desktop member can never claim or show one, and no
UI can display one. The circuit carries the slots through every post unchanged
(`x6`/`x7`/`x8`), so the state is preserved but inert.

**To fix:** add napi bindings for the badge request/show flows in `personas-node` —
`personas-client/src/badges.rs` is the reference implementation. Then Desktop needs a UI
and a policy for who grants a badge (moderator route exists server-side).

### Scope-limited personas (`AllowedContexts`)

The paper's `PersonaLimited` asserts `context ∈ AllowedContexts`. No such check exists
in `circuits.rs`. A persona minted for one topic can be replayed in another.

---

## Fixed since this document was written

**`MAX_PSEUDO` was an inequality, not a range check — now fixed (`CryptoPersonas_Signal`
FINDINGS.md F8).** The circuit used to check `i != 4` (excludes exactly 4, accepts
`i = 5` and anything else off the intended range) instead of `i < 4`. `circuits.rs`'s
`standard_pseudo_rate_predicate` now enumerates `i ∈ {0, 1, 2, 3}` explicitly, matching the
paper's `assert(i < k)`. Desktop's own constant and slot offering (`0..3`) were already
correct, so this required no Desktop-side change — the circuit now enforces what Desktop
always assumed. Needs a fresh proving/verifying key (constraint count changed); the
content-addressed key cache regenerates it automatically on next boot.

---

## Desktop-side limits

- **Topic contexts are client-drawn.** `personasTopics.preload.ts` draws a CSPRNG context
  and announces it over the group. A malicious client could announce a context it chose.
  Swapping in a server registry is a one-function change (`resolveTopicContext`).
- **Late joiners miss topics** — no backfill. Re-creating a topic re-announces it.
- **Poll option labels are display metadata** carried beside the record. A peer can
  mislabel its own options; the proof is over the option *index*, so tallies and bans are
  unaffected, but the label a voter sees is not attested.

---

## Corrections to the earlier version of this file

| Claim I made | Reality |
|---|---|
| "`AnonVote` is the important gap — one-vote-per-member is NOT enforced; a member may be able to vote more than once, anonymously." | **False.** `member.vote` derives `H(sk, poll.context())` with no nonce. One vote per member is enforced. |
| "Ratings are attributable — asymmetric with posts/polls/votes." | Half right. They *were* attributable **on the wire in Desktop**, which leaked the rater — but they are pseudonymous in-circuit exactly like ballots. Fixed: ratings now ride the phantom (`PZE2:`). |
| "The poll needs a client-drawn random `poll_id`; the addon takes none, so the pseudonym can't be bound." | **False premise.** The poll's envelope hash *is* the poll_id, deliberately (`record.rs` says it "replaces the service's `fresh_context()`"). The random `pollId` I added was dead weight and has been removed. |
| "`MAX_PSEUDO` is 3." | It is 4. Desktop's constant now matches. |
