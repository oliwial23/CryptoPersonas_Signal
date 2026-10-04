<!-- Copyright 2026 Signal Messenger, LLC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# CryptoPersonas × Signal-Desktop — feature test plan

Work top to bottom: each section assumes the previous one passed. Every step lists what
you should **see**, and what it means when you don't — the failure modes here are mostly
silent, so "nothing obviously broke" is not the same as "it worked".

Devtools open automatically (`openDevTools: true`). Filter the console by the logger
name in the "check" column.

---

## 0. Bring everything up

**Backend** (each in its own terminal, in order — see `PERSONAS_DEMO.md` §6):

```sh
cd $CRYPTO/deploy/signal-test-server && ./boot.sh      # blocks
cd $CRYPTO/deploy/signal-test-server && ./minio.sh up
cd $CRYPTO/deploy/storage-service   && ./boot.sh       # blocks
cd $CRYPTO/deploy/signal-test-server && ./tls-proxy.sh up   # RE-RUN, after storage-service
```

Verify routing before launching any client:

```sh
curl -sk -o /dev/null -w 'chat    %{http_code}\n' https://127.0.0.1:8443/v1/config
curl -sk -o /dev/null -w 'groups  %{http_code}\n' https://127.0.0.1:8443/v2/groups   # want 401, NOT 404
```

`404` on `/v2/groups` means Caddy has not picked up the storage-service route — re-run
`tls-proxy.sh up`. Group creation will fail with an opaque error otherwise.

**Clients** — one terminal each:

```sh
./scripts/personas-run.sh alice --reset
./scripts/personas-run.sh bob   --reset
./scripts/personas-run.sh carol --reset
```

`--reset` wipes that instance's userData so it re-registers. Use it after **any** backend
restart: accounts, groups and joins are all ephemeral, and a stale userData will quietly
boot an account the server no longer knows about.

---

## 1. Registration and discovery

| # | Do | Expect | If not |
|---|---|---|---|
| 1.1 | Watch each instance boot | Lands directly in the inbox. No QR / phone-number screen | `personaAutoRegister failed; falling back to the installer` in console — the last successful log line names the failing call |
| 1.2 | Check each window's own number | alice `+12025550001`, bob `…02`, carol `…03` | Wrong number ⇒ stale userData; re-run with `--reset` |
| 1.3 | Console, any instance | `writeMyRosterEntry: published …` then `seedPeersFromRoster: seeded …` for the other two | All three must share `PERSONAS_ROSTER_DIR` (the script handles this) |
| 1.4 | Look at the conversation list | The other two members appear | Roster re-polls every 5s; give it a moment. CDSI is disabled, so this dir is the *only* discovery path |
| 1.5 | Console | `installPhantomReceiveKey: installed shared phantom receive key` | Without this, incoming persona posts cannot be decrypted |

---

## 2. Group and baseline messaging

| # | Do | Expect | If not |
|---|---|---|---|
| 2.1 | In alice: **New chat → New group**, add bob + carol, create | Group is created | Fails ⇒ storage-service down, or `/v2/groups` returned 404 (step 0) |
| 2.2 | Send an ordinary message in the group | Arrives on bob and carol, attributed to alice normally | — |

Step 2.2 is not optional: it establishes sessions with the members. The first persona
post needs them to already exist.

---

## 3. Auto-join

The old runbook required `await window.SignalDebug.personasJoin()` in every instance
before posting. That is now automatic — this section verifies it.

| # | Do | Expect | Check |
|---|---|---|---|
| 3.1 | In alice, pick **Persona** in the composer's persona menu (person-circle button) and send "hello" | Console shows `sendJoin: join broadcast (eh …)` **before** the post goes out | `personasMembership` |
| 3.2 | Same instance, post again | No second join — one membership per account is the anti-Sybil invariant | `personasMembership` |
| 3.3 | Repeat 3.1 on bob and carol | Each broadcasts its own join once | |

**The failure this prevents:** posting un-joined used to throw inside the engine, and the
composer would silently fall back to sending your text as a *plain* message under your
real account. If you ever see a persona-menu send arrive as a normal attributed message,
that is the bug — capture the console.

---

## 4. Posting

| # | Do | Expect |
|---|---|---|
| 4.1 | Persona menu → **Persona**, send | Renders as `~two-word-petname` on **all three** instances, including the sender |
| 4.2 | Post again as **Persona** | Same petname as 4.1 — one stable persona per context |
| 4.3 | Persona menu → **Persona #1**, then **#2** | Each gets a *different* petname (rate-limited personas) |
| 4.4 | Persona menu → **Anonymous** | No petname at all |
| 4.5 | Persona menu → **Normal message** | Ordinary Signal message attributed to your real account |
| 4.6 | Two posts in a row under different personas | They do **not** visually group into one bubble |

Proof generation is real Groth16 — a post takes seconds. That is expected.

---

## 5. The anonymity property (the point of the whole system)

Every persona post must arrive under **one shared phantom sender**, so a recipient can
attribute a post only by its persona — never to the member who sent it.

Post from **alice, bob and carol** as personas, then in **carol's** devtools console:

```js
Object.values(window.reduxStore.getState().conversations.messagesLookup)
  .filter(m => m.persona)
  .map(m => ({ persona: m.persona, from: m.sourceServiceId }))
```

**Expect:** every row shows the *same* `from` — the phantom ACI
`9f9f9f9f-0000-4000-8000-00000000face` — while `persona` differs. Distinct real ACIs
would mean the phantom splice did not engage, and authorship is leaking.

Contrast with joins, which are attributable **by design**: a join arrives from the real
member, because one-membership-per-account is what makes a ban impossible to evade by
re-joining.

**Fail-closed check.** A persona post must never silently downgrade to an attributable
send. If a post never leaves, search the console for `failing closed` — that is the guard
working correctly, not a crash.

---

## 6. Rating

Thumbs on a persona post are re-routed to the engine's `emitRate`; every other emoji
stays an ordinary Signal reaction.

| # | Do | Expect | Check |
|---|---|---|---|
| 6.1 | 👍 a persona post | `maybeSendPersonaRateForReaction: routing 👍 to a rate of 1` then `sendPersonaRate: rated …` | `personasActions` |
| 6.2 | 👎 a persona post | Same, delta `-1` | `personasActions` |
| 6.3 | Remove the 👍 | Emits `-1` — ratings accumulate rather than retract; the log is append-only | `personasActions` |
| 6.4 | ❤️ a persona post | Normal Signal reaction, **no** persona log lines | |
| 6.5 | 👍 an *ordinary* message | Normal Signal reaction | |

---

## 7. Polls and voting

| # | Do | Expect |
|---|---|---|
| 7.1 | Select a persona in the persona menu, then open the composer's poll modal, add a question + 2 options, send | A poll bubble appears on all three instances, marked *"Enforced by zero-knowledge proof. Votes are unlinkable to voters."* |
| 7.2 | With persona menu **off**, create a poll | An ordinary Signal poll (voter names visible) — the two paths must stay distinct |
| 7.3 | On bob, click an option in the ZK poll | `sendPersonaVote: voted option N` (`personasActions`) |
| 7.4 | On bob, try to vote again | Options are locked — a ZK ballot is already folded into every replica and cannot be recast |
| 7.5 | Any instance console: `window.SignalDebug.personasPolls()` | Status line(s) for the open poll |

The ZK poll bubble deliberately shows **no voter list**. There is nothing to show: ballots
are unlinkable by construction. A Signal poll naming who voted for what is the other path.

---

## 8. Ban / revocation — the full loop

This exercises the barrier schedule, which is what makes settlement possible at all.

1. Have alice post something as a persona. Note its petname.
2. On **bob**, right-click that post → **Open revocation poll**.
   → a ban poll appears, titled `Revoke ~<petname>?`, options **Ban** / **Keep**.
   → console (`personasActions`): `sendPersonaPoll: opened ban poll (eh …)`
3. On **bob and carol**, vote **Ban**.
4. **Wait.** Settlement takes roughly `settlementBarriers × barrier period` — about
   30–40s at the default 10s period. Watch it advance:

   ```js
   window.SignalDebug.personasBarrier()   // increments about every 10s
   ```

   Console (`personasBarrier`): `startBarrierTicker: crossed to barrier N`.

5. **Expect:** the offending post now renders **flagged (⚠)** on *all* instances —
   including alice's own copy — and is **still present**. Revoked posts are flagged,
   never deleted; that is the rendering gate.

   Console (`personasFlags`): `refreshPersonaFlags: … flagged=true (persona revoked)`

**If the flag never appears**, in order: is `personasBarrier()` incrementing (if it is
stuck, the shared schedule is not active — check for `personas-heartbeat.json` in the
roster dir); did both votes actually send; does `window.SignalDebug.personasLog()` show
the entry with `flagged: true` (engine says yes, UI didn't update ⇒ flag refresher) or
`false` (engine has not settled ⇒ barriers/votes).

---

## 9. Convergence

The strongest single check that every replica agrees. In **all three** consoles:

```js
window.SignalDebug.personasFingerprint()
```

**All three strings must be identical.** They are the three Merkle roots — if they differ,
some record was not ingested everywhere, and every downstream claim (tallies, bans,
flags) is unreliable on at least one instance.

Re-check after each phase: after all joins, after posting, after the ban settles.

Supporting views:

```js
window.SignalDebug.personasRender()   // accepted chat log, '~petname: body'
window.SignalDebug.personasLog()      // structured entries incl. flagged
window.SignalDebug.personasPolls()    // open / recently closed polls
```

---

## 10. Known limits (expected, not bugs)

- **Post one at a time across instances.** Persona posts advance one shared sender-key
  chain that is not locked across processes; two simultaneous posts collide. A delivery
  glitch only — anonymity is unaffected.
- **Persona messages cannot be edited.** An edit would re-send the plaintext under your
  real account, publishing the very link the phantom exists to hide.
- **Poll option labels are display metadata** and travel beside the record. A peer could
  mislabel its own poll's options. Not a soundness issue: the proof is over the option
  *index*, so the tally and any resulting ban are exactly what the ZK system decided.
- **Everything is ephemeral.** After a backend restart: `--reset` all three instances and
  recreate the group.
