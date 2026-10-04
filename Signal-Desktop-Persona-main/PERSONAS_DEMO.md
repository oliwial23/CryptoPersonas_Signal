# CryptoPersonas × Signal-Desktop — demo runbook

Signal-Desktop, modified to be the demo/benchmark client for **CryptoPersonas**
(eprint 2025/1969 — anonymous group chat with ZK-enforced reputation/banning). It
registers against a self-hosted Signal test server, carries CryptoPersonas ZK records
as message bodies, and delivers **persona posts under one shared "phantom" sender
identity** so a recipient — even an instrumented member — cannot tell which member
authored a post. Attribution is only the persona in the ZK proof.

This document is the full replication guide: toolchain, build, config, standing up the
backend, running N instances, and the demo workflow. It is Desktop-centric and points
at the two server READMEs for backend detail.

---

## 1. Architecture — what actually runs

```
  ┌ Desktop "alice" ┐   ┌ Desktop "bob" ┐   ┌ Desktop "carol" ┐   … N instances
  │  real account   │   │ real account  │   │  real account   │   each its own userData
  └────────┬────────┘   └───────┬───────┘   └────────┬────────┘
           └──────────────┬─────┴────────────────────┘
                          ▼  https://127.0.0.1:8443  (Caddy TLS proxy)
        ┌─────────────────┴──────────────────────────────────┐
        │  path /v1|v2/groups,/v1/storage → storage-service :8090   (GroupV2 backend)
        │  everything else               → chat test-server  :8080   (accounts/msgs/keys/profiles)
        └────────────────────────────────────────────────────┘
        + MinIO (attachment/profile CDN)   + Bigtable emulator (behind storage-service)
```

- **Three local, ephemeral backend services**: the chat test-server (Signal-Server in
  `test-server` mode), the storage-service (GroupV2 backend), and a Caddy TLS proxy
  that fronts both on `:8443`; plus MinIO for the CDN and a bundled Bigtable emulator.
- **N Desktop instances**, each registered as its own real receiving account. Every
  member *receives* on its own account but *sends persona posts as the shared phantom*.
- Everything is on `127.0.0.1`, throwaway, and never touches the real Signal network.

---

## 2. Prerequisites (pinned)

| Component | Version | Needed for |
|---|---|---|
| macOS Apple Silicon | — | the prebuilt native addon (`darwin-arm64`); other platforms must rebuild it (§4) |
| Node | **24.17.0** (`.nvmrc` / volta) | building & running the client |
| pnpm | **11.5.2** | client package manager |
| JDK | Temurin **25** | chat test-server **and** storage-service |
| Docker / Colima + compose v2 | any recent | test-server datastores (Testcontainers), Caddy, MinIO |
| Rust nightly | per `CryptoPersonas_Signal` `rust-toolchain.toml` | **only** if rebuilding the addon off `darwin-arm64` |

**Repos, checked out as siblings** (default layout the scripts assume,
`~/Repos/personas2/`):

- `Signal-Desktop`  — this repo (the client).
- `CryptoPersonas_Signal` — the Rust workspace (ZK engine) + `deploy/` server harnesses.
- `Signal-Server` — upstream, pinned to the commit in
  `CryptoPersonas_Signal/deploy/signal-test-server/README.md` (chat server + the shared
  zkgroup secret the storage-service reuses).
- `storage-service` — upstream `signalapp/storage-service` (the GroupV2 backend).

> The addon build script and the storage-service boot script take
> `PERSONAS_RUST_DIR` / `STORAGE_SERVICE_DIR` / `SIGNAL_SERVER_SECRETS` overrides if
> your layout differs.

---

## 3. Build the client (one-time)

```sh
cd Signal-Desktop
pnpm install                 # postinstall builds acknowledgments + native app deps
pnpm run build:dev           # = generate (protobufs/codegen) + rolldown bundle
```

Iterating after a code change: `pnpm run build:dev` again, or — for TS-only changes —
just re-bundle with `pnpm run build:rolldown` (skips codegen; faster). Then relaunch
the instances.

---

## 4. The native ZK-engine addon

The CryptoPersonas engine is a napi-rs addon at
`packages/personas-engine/personas-engine.<platform>.node`. **The `darwin-arm64`
binary is committed**, so on Apple Silicon there is nothing to build.

Rebuild it from the Rust workspace on any other platform — or on Apple Silicon after
changing Rust code, since the committed binary is a build artifact and will not pick up
crate edits on its own:

```sh
pnpm --filter @signalapp/personas-engine build
# → cargo build -p personas-node --release, then copies the platform .node into
#   packages/personas-engine/.
```

`build.sh` finds the workspace by looking for `crates/personas-node/Cargo.toml` in a few
likely places (sibling of this repo, one level up, the `oliwia_test_repo` layout). If it
cannot find it, it searches `$HOME` and prints the exact command to re-run. You can
always be explicit:

```sh
PERSONAS_RUST_DIR=~/Documents/Anon_Group_Chat/Signal_Integration_Code_2026/oliwia_test_repo/CryptoPersonas_Signal \
  pnpm --filter @signalapp/personas-engine build
```

Two failure modes worth naming:

- **`personas-node crate not found under …`** — a path problem, not a build problem.
  It never reached `cargo`. Set `PERSONAS_RUST_DIR` as above.
- **`cargo is not on PATH`** — install rustup; it reads
  `rust-toolchain.toml` and pulls the pinned nightly (`nightly-2026-07-12`, required
  because zk-callbacks uses `generic_const_exprs`) on the first build. The first
  compile of the full workspace takes a while.

Merkle keys: the first time the engine is constructed it generates ~51 MB of proving
keys (minutes), cached afterwards. All members of a group must share one key set —
they do automatically via `PERSONAS_KEYS_DIR` (default `~/.personas-demo-keys`).

---

## 5. Client config (per instance — gitignored)

`config/local-*` is gitignored, so these are **not** in the repo. **Do not write them by
hand** — `scripts/personas-demo-setup.sh` generates all four:

```sh
PERSONAS_RUST_DIR=/path/to/CryptoPersonas_Signal ./scripts/personas-demo-setup.sh
```

It pulls `serverPublicParams` out of the Rust workspace's `configuration.rs` (these are
the personas **test** values — NOT Signal staging's, which live in `config/default.json`
and will fail group creation), injects the machine-specific TLS CA with correct `\n`
escaping, and writes one file per instance with a distinct `storageProfile`.

Run it **twice**: once now, and again after the TLS proxy's first boot (§6) has minted
`deploy/signal-test-server/.local/tls/ca.crt`. Until then `certificateAuthority` is a
visible `REPLACE_ME` placeholder and `personas-run.sh` refuses to launch.

If the script can't find the workspace it prints the path it tried, lists what does
exist there, and searches for the workspace by marker file — so a wrong `PERSONAS_RUST_DIR`
tells you what to use instead.

<details>
<summary>What it writes (for reference — you should not need to edit this)</summary>

```jsonc
// config/local-development.json — the shared base
{
  "serverUrl": "https://127.0.0.1:8443",
  "storageUrl": "https://127.0.0.1:8443",
  "cdn": { "0": "https://127.0.0.1:8443", "2": "https://127.0.0.1:8443", "3": "https://127.0.0.1:8443" },
  "certificateAuthority": "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----\n",
  "serverTrustRoots": ["BS/lfaNHzWJDFSjarF+7KQcw//aEr8TPwu2QmV9Yyzt0"],
  "serverPublicParams": "AAp8oB0D4EV2q7hSue3Kxzh1Vc88…",
  "openDevTools": true
}
// config/local-development-alice.json — one per instance, distinct userData
{ "storageProfile": "development-alice" }
```

</details>

> `127.0.0.1` + a `certificateAuthority` is what flips libsignal-net into
> `localTestServer` mode (`ts/textsecure/preconnect.preload.ts`). Keep `staging` out of
> the URLs, or `isStagingServer()` wins and the client tries to reach real Signal staging.

**If the CA is ever re-minted** (you wiped `.local/tls/`), the config goes stale and the
client fails at startup with a TLS handshake error. Check and fix:

```sh
python3 -c "
import json
CA='/path/to/CryptoPersonas_Signal/deploy/signal-test-server/.local/tls/ca.crt'
cfg = json.load(open('config/local-development.json'))['certificateAuthority']
print('MATCH' if cfg.strip()==open(CA).read().strip() else 'STALE — re-run personas-demo-setup.sh')
"
```

---

## 6. Boot the backend (order matters)

All three server pieces are ephemeral — **accounts, groups, and joins are lost on every
restart** and must be recreated. Full detail in each README; the essential sequence:

**a. Chat test-server** — see
`../CryptoPersonas_Signal/deploy/signal-test-server/README.md` (prereqs: the pinned
Signal-Server checkout, Temurin 25, FoundationDB, a Docker daemon).

```sh
cd ../CryptoPersonas_Signal/deploy/signal-test-server
./boot.sh          # Signal-Server test-server on :8080  (own terminal; blocks)
./minio.sh up      # CDN
./tls-proxy.sh up  # Caddy TLS on :8443  → generates .local/tls/ca.crt on first run
```

Copy `.local/tls/ca.crt` into your `config/local-development.json` `certificateAuthority`
(§5) the first time.

**b. Storage-service (GroupV2 backend)** — see
`../CryptoPersonas_Signal/deploy/storage-service/README.md` (prereq: Temurin 25 only —
Bigtable runs as a bundled Java emulator, no gcloud/Docker/Python).

```sh
cd ../CryptoPersonas_Signal/deploy/storage-service
./boot.sh                                   # storage-service on :8090 (own terminal; blocks)
cd ../signal-test-server && ./tls-proxy.sh up   # RE-RUN so Caddy picks up the /v2/groups route
```

**Verify** routing (should be `401`, not `404`):

```sh
curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:8443/v2/groups
```

---

## 7. Run the client instances

One terminal per member:

```sh
./scripts/personas-run.sh alice --reset
./scripts/personas-run.sh bob   --reset
./scripts/personas-run.sh carol --reset
```

The script sets everything the demo needs and fails fast on the mistakes that otherwise
produce confusing symptoms:

| It sets | Why |
|---|---|
| `NODE_APP_INSTANCE` + number | picks `config/local-development-<name>.json`, so each instance gets its own userData and can run alongside the others |
| `PERSONAS_ROSTER_DIR` (shared) | how instances discover each other — CDSI is disabled in `localTestServer` mode, so this is the **only** discovery path. Different roster dirs means they never see each other |
| `PERSONAS_KEYS_DIR` (shared) | all members must prove against an **identical** ~51 MB key set, or every proof is rejected on ingest |

and it refuses to start when the bundle is missing (`pnpm run build:dev` first) or when
`certificateAuthority` is still a placeholder.

### `--reset` — when and why

`--reset` deletes that instance's userData, forcing fresh auto-registration.

**Use it after any backend restart.** Accounts, groups and joins are all ephemeral, so a
stale userData leaves a client that looks logged in but holds an account the server no
longer knows about — it boots to a dead inbox and never re-registers, because
registration only runs when Desktop has never registered in that directory.

Without `--reset` the instance reuses whatever account is there, and the script prints a
note saying so. That is the right choice when the backend has been up the whole time.

It only ever removes `Signal-<storageProfile>` and refuses anything else — your real
Signal Desktop account at `~/Library/Application Support/Signal` is never touched.

Ad-hoc extra members take a number:

```sh
./scripts/personas-run.sh dave +12025550004
```

First launch on a fresh keys dir generates ~51 MB of proving keys and takes minutes;
after that it is cached.

---

## 8. Demo workflow

Every persona feature is now a native Signal gesture — there is no devtools step in
the happy path.

1. **Create the group** in one instance (New group → add the others → create). It hits
   the real storage-service `/v2/groups`.
2. **Post as a persona** — pick a persona in the composer's persona menu (the
   person-circle button) and send. **Joining and sealed-sender warm-up are automatic**:
   the first persona action sends one plain warm-up message to the group (so peers learn
   your profile key), then emits and broadcasts a join, then proceeds. If the join fails
   the action is abandoned rather than downgraded, so the old "why is it a normal post
   from alice?" failure is no longer reachable from the UI.
3. **Check status before claiming anonymity** — persona menu → **Persona status…**.
   *Sealed sender: Ready* is the row that matters: until peers have replied it reads
   **Not ready** and names who you are waiting on, and a persona post sent in that state
   is not protected. The same panel shows join state, the settlement barrier, and the
   replica fingerprint to compare across instances.
4. **Rate a post** — 👍 or 👎 on a persona post, from the ordinary reaction picker.
   Thumbs on a persona post become `emitRate` (±1) instead of a Signal reaction; every
   other emoji stays a normal reaction.
5. **Open a poll** — the composer's poll modal, with a persona selected in the persona
   menu. Ballots are ZK and unlinkable; with the persona menu off you get a normal
   Signal poll instead.
6. **Vote** — click an option in the poll bubble. Options lock after voting: a ZK
   ballot is already folded into every replica and cannot be recast.
7. **Ban someone** — right-click a persona post → **Open revocation poll**. That opens
   a ban poll naming that post (`emitPoll(..., 'ban', eh)`), with **Ban** as option 0.
8. **Watch the ban land.** Once the poll's settlement barriers pass, the revoked
   persona's posts render flagged (⚠) — including on the author's own instance — and are
   never deleted. Scans run automatically; barriers advance on the shared schedule
   (§8.1), so this happens on a clock rather than on a keystroke. If you would rather
   not wait out the 30 s scan interval in front of an audience, persona menu →
   **Scan now** emits a scan immediately. It changes nothing about the outcome — the
   ban still cannot settle before its barriers pass — it only stops you standing there
   watching an unflagged post that is already doomed.
9. **Observe the anonymity property.** A post renders as `~two-word-petname` on the
   other instances, and every persona post arrives under the **same** phantom Signal
   sender, so a recipient can attribute only by persona. Joins, votes, ratings and
   polls, by contrast, arrive from the real member.

### 8.0 If the app dies with "Render process is gone / Exit Code: 9"

**Known cause: a locally rebuilt native addon containing `get_reputation`.** Exit code 9
is SIGKILL — nothing threw, the process was killed — and Electron reports that fact with
no cause attached, so this same message appears whatever the underlying reason. It is
therefore worth almost nothing as a diagnostic on its own.

The committed `packages/personas-engine/personas-engine.darwin-arm64.node` is known
good. If you are crashing, restore it first and confirm you are stable again:

```sh
git checkout -- packages/personas-engine/personas-engine.darwin-arm64.node
```

This was isolated by changing one variable at a time (§8.0.1). If you have rebuilt the
addon and are now crashing, that is the first thing to undo.

#### 8.0.1 What was ruled out, and how

Recorded because each of these looked convincing and was wrong — and because the same
SIGKILL message will appear again for some future reason.

| Hypothesis | How it was tested | Result |
|---|---|---|
| Overlapping scans (the "Scan now" button queuing Groth16 proofs) | Added an in-flight guard | Real defect, **not the cause** |
| Stale barrier anchor making `rebuild()` loop over thousands of barriers | Deleted `personas-heartbeat.json`, re-anchored | Real issue, **not the cause** |
| Machine out of memory (swap was 91% full) | Rebooted; re-checked `vm_stat` / `swapusage` | Crashed again with memory healthy — **not the cause** |
| Addon signing / Cargo feature unification | Compared Mach-O flags and signature blobs; checked `ark-ff` features across crates | Identical — **not the cause** |
| **Local rebuild containing `get_reputation`** | Rebuilt with the change → crash. Rebuilt from unmodified upstream Rust → **stable** | **This is the cause** |

Two notes on method, because they are the transferable part:

- **`--no-personas` was not a valid control at first.** `personasEngine.preload.ts`
  imports the addon statically, so the `.node` is `dlopen`'d during renderer startup no
  matter what; `isPersonasEngineEnabled()` gates only *construction*. A run with the flag
  therefore proved nothing about whether the addon was involved.
- **Only the one-variable-at-a-time test settled it.** Comparing "committed binary" with
  "my rebuild" left two variables (the code change AND the act of rebuilding). Rebuilding
  from clean upstream source separated them.

#### 8.0.2 The reputation binding is disabled

`Engine::get_reputation()` exists in `crates/personas-node/src/lib.rs` but is **not in
the shipped binary**. It compiles; it kills the render process at runtime, mechanism
unknown. The status panel guards it (`typeof engine.getReputation === 'function'`) and
shows *Unavailable*, so nothing breaks — you simply get no reputation row.

`packages/personas-engine/index.d.ts` still declares the method. That is a harmless lie:
TypeScript believes in it, the runtime guard catches its absence.

To pick this up later, **bisect rather than re-read the code** — the change has two
halves and the failure is in one of them:

```rust
#[napi]
pub fn get_reputation(&self) -> Option<f64> { Some(0.0) }
```

Rebuild with that body. Still crashes → the napi binding itself is wrong. Stable → the
fault is in `member()` access or `field_to_f64`, and that half should be rewritten to
avoid the field arithmetic entirely.

#### 8.0.3 Other things that genuinely can SIGKILL the renderer

Fixed, but worth knowing if the symptom returns:

- **A stale barrier anchor.** `Replica::rebuild()` loops `for b in 0..=current_barrier`,
  and `current_barrier` is `(now - anchorMs) / periodMs`. The anchor lives in
  `personas-heartbeat.json` in the roster dir (default `/tmp/personas-roster`), which
  survives `--reset`. A week-old anchor means ~60,000 iterations per rebuild, every 10 s.
  The client now re-anchors when the file has been untouched for five minutes (running
  instances touch it every minute, so a live session is never re-anchored underneath it —
  two members on different anchors diverge **silently**, which is worse than being slow).
  To clear it by hand, stop everything and
  `rm -f "${PERSONAS_ROSTER_DIR:-/tmp/personas-roster}/personas-heartbeat.json"`.
  Check it in **Persona status…**: the barrier should be small and climbing slowly.
- **Real memory exhaustion.** Three Electron instances need ~1 GB each. Run
  `./scripts/personas-diagnose.sh`, which prints a memory verdict and the top consumers.

### 8.1 Barriers: the shared heartbeat schedule

The replica advances on a **shared barrier schedule** rather than the local-barrier
cadence used during bring-up. Both matter for the demo:

- Each record is bucketed onto a barrier by its **service timestamp** (the server's
  clock, identical for every recipient), so replicas stay converged regardless of local
  arrival order.
- A ticker calls `tick(now)` every second, so settlement barriers pass even in a silent
  group. Without this a ban poll could never close.

The anchor + period are published once to the roster dir as `personas-heartbeat.json`
(same exclusive-link publish as the phantom bundle, so a boot race converges on one
winner). Period defaults to 10 s; override with `PERSONAS_BARRIER_PERIOD_MS`. A ban
therefore takes roughly `settlementBarriers × period` (~30 s by default) from the poll
opening to the flag appearing.

### What's anonymous vs attributable (by design)

| Record | Wire routing | Why |
|---|---|---|
| **Post** (pseudo / rate-limited / anon) | shared **phantom** identity | authorship must be unlinkable to the real sender |
| **Join**, **vote**, **rate**, **poll**, **scan** | **real** account | one-membership-per-account must be enforceable — an anonymous join would let a banned member silently re-join and evade the ban |

Note the asymmetry inside the poll flow: **opening** a ban poll is attributable (you
cannot anonymously call for someone's revocation) while the **ballots** cast in it are
not.

Routing is chosen by the carriage marker (`ts/services/personasCarriage.std.ts`):
posts use `PZP2:`, polls `PZQ2:` (record **plus** a display descriptor, since the engine
returns no option labels), everything else `PZR2:`.

### Console helpers (optional)

Kept for scripted/benchmark runs; not needed for the demo:

```js
await window.SignalDebug.personasJoin()                   // idempotent; UI does this
await window.SignalDebug.personasPost('hi')               // or { anon: true }
await window.SignalDebug.personasRate(eh, -1)
await window.SignalDebug.personasBanPoll(eh, 'quiet-otter')
await window.SignalDebug.personasVote(pollEh, 0)          // 0 = ban
await window.SignalDebug.personasScan()
window.SignalDebug.personasRender()      // chat log
window.SignalDebug.personasPolls()       // poll status lines
window.SignalDebug.personasBarrier()     // current barrier
window.SignalDebug.personasFingerprint() // convergence check across instances
```

---

## 9. Constraints & gotchas

- **Post one at a time across instances.** Persona posts advance one shared, roster-dir
  sender-key chain that is not locked across processes; two simultaneous posts collide
  (a delivery glitch — the anonymity is not affected). Low-rate/serial posting is the
  accepted demo limit.
- **Everything ephemeral.** After any backend restart: re-register (automatic on
  launch) and re-create the group. Joining is automatic again on the next persona
  action, since membership is per-process and not persisted.
- **Persona messages cannot be edited.** Deliberate: an edit re-sends `message.body`,
  which on a persona post is the *plaintext* (the record only exists on the wire), so
  editing would publish the cleartext under your real account. Enforced in
  `ts/util/canEditMessage.dom.ts`.
- **Poll option labels are display-only.** They ride next to the record in the `PZQ2:`
  carriage because the engine returns no labels. A peer could mislabel its own poll's
  options — a display-integrity limit, not a soundness one: a mislabelled option still
  resolves to the same option *index* inside the proof, so the tally and any resulting
  ban are exactly what the ZK system says they are.
- **Ratings accumulate.** Un-thumbs-upping emits a −1 rather than retracting the
  original; the log is append-only by design.
- **A persona post fails closed.** If the sender-key send errors, a persona post throws
  rather than falling back to an attributable per-recipient send (which would silently
  de-anonymize). If a post never leaves, check the log for `failing closed`.
- **Sealed sender warms up automatically.** A persona post is only protected if it goes
  out SEALED, which needs each member's profile key — and Desktop only learns that after
  an ordinary message has been exchanged in each direction. The first persona action now
  sends one plain warm-up message to the group by itself (once per conversation), so the
  old manual "send a normal message first" step is gone.

  It is not instant: peers must still reply before their key is known. Check
  **Persona status…** in the persona menu — if *Sealed sender* reads **Not ready**, it
  names who you are waiting on, and a persona post sent in that state is not protected.

---

## 10. Where the code lives (map)

### Phase 6 — the native feature integration

- `ts/services/personasBarrier.preload.ts` — the shared barrier schedule (roster-dir
  anchor, service-timestamp bucketing, the `tick` driver). This is what makes
  settlement — and therefore ban — reachable at all.
- `ts/services/personasMembership.preload.ts` — join state and `ensurePersonaJoined`,
  the auto-join every persona action funnels through.
- `ts/services/personasActions.preload.ts` — the one place a UI gesture becomes a
  record: rate, poll, ban poll, vote, scan, plus the two interception helpers
  (`maybeSendPersonaRateForReaction`, `maybeSendPersonaVote`).
- `ts/services/personasFlags.preload.ts` — the scan loop and the flag refresher that
  make a *later*-settling ban actually appear on already-rendered posts.
- `ts/components/conversation/PersonaPollMessage.dom.tsx` — the ZK poll bubble. Shaped
  like Signal's own but with no voter list, because a ZK ballot has no voters to name.
- `ts/services/personasSealedSender.preload.ts` — sealed-sender readiness and the
  automatic warm-up. A persona post is only protected if it goes out sealed, which needs
  each peer's profile key; this removes the manual "send a normal message first" step
  that was easy to skip and whose omission was silent.
- `ts/services/personasStatus.preload.ts` + `ts/components/PersonaStatusDialog.dom.tsx`
  — the status panel. Sealed-sender readiness, join state, barrier, topics and the
  replica fingerprint, which were previously visible only through `SignalDebug` in
  devtools.
- Interception points, each chosen so Signal's own plumbing is reused rather than
  duplicated: `reactToMessage` and `sendPoll` (`ts/state/ducks/composer.preload.ts`),
  `sendPollVote` and `personaBanPoll` (`ts/state/ducks/conversations.preload.ts`).
- Guards worth knowing about: `ts/util/isMessageEmpty.preload.ts` (a poll has no body
  and would otherwise be dropped on receive) and `ts/util/canEditMessage.dom.ts` (an
  edit would leak the plaintext attributably).

### Phase 5 — the anonymity crypto

- `ts/services/personasPhantom.preload.ts` — the shared phantom bundle (identity keypair,
  sender certificate, sender-key), roster-dir sharing, trust-root export, and the
  boot-time receive-key install.
- `ts/util/sendToGroup.preload.ts` `encryptForSenderKey` — the send splice: a persona
  post swaps sender address / sender-key chain / certificate / local identity for the
  phantom's (recipient info still from the real session/identity stores); plus the
  fail-closed guard in `sendContentMessageToGroup`.
- `ts/services/personasCarriage.std.ts` — the two carriage markers (post vs attributable).
- `ts/messages/handleDataMessage.preload.ts` — receive-side membership-drop exemption for
  the phantom sender.
- `ts/background.preload.ts` — trust-root injection into MessageReceiver + boot receive
  install.
- `packages/personas-engine/` — the napi ZK engine (record emit/ingest/render).
- Standalone libsignal proofs of the anonymity mechanism (`personas-proofs/`):
  `phantom-gate.mjs` (single-recipient) and `phantom-gate-multi.mjs` (the real
  multi-recipient group send API). Run them with the repo's Node; see that dir's README.
