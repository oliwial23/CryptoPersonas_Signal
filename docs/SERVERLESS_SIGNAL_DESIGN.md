# The modified Signal client (e2) — serverless Signal design

The canonical design for **e2**, the modified Signal client that carries personas
records over real Signal. It is the crux of the serverless deployment and the
easiest part to get cryptographically wrong, so it is specified here to be
reviewed before the fork is opened. It expands the *Signal client modification —
detailed design* section of the approved plan and is the document `e2a`'s crate
already points at.

**One-sentence statement of what we change:** only the **provenance of the group
sender key**, the **identity metadata at the delivery layer**, and the
**per-message key schedule**. We never touch the transport's confidentiality
primitives, and **we never implement our own cipher** — encryption stays
libsignal's (or a standard vetted AEAD), keyed by material we control.

**Status.** Spec, with the fork open and **Phase A2 + B1 wired and proven end to end
over the isolated self-hosted Signal-Server** (the sanctioned staging venue, not
production). `e2a` (`personas-group-crypto`) is built and is now the content path in
active use, not just Phase-2 machinery sitting ahead of it. libsignal is in the tree
(§8). The Phase A1 static-shared-sender-key content cipher is still built and tested
in-process
([`content_cipher`](../crates/transports/transport-presage/src/content_cipher.rs))
and kept as a historical/reference implementation, but the transport no longer uses
it — it has been superseded by the K2/PPRF cipher
([`pprf_cipher`](../crates/transports/transport-presage/src/pprf_cipher.rs)), which is
**wired into the `Transport` trait** as
[`PresageTransport`](../crates/transports/transport-presage/src/lib.rs):

- **`send`** = `PprfContentCipher::encrypt` (derive a fresh single-use `mk` from a
  random nonce via `KeyManager::seal`, puncture it immediately, AEAD-seal under it,
  prepend the `MessageTag {epoch, nonce}` in the clear) → base64 in a Signal
  `DataMessage` → **per-member 1:1 fan-out** (B1 bring-up delivery); **`subscribe`** =
  presage receive websocket → `PprfContentCipher::decrypt` (re-derive `mk` from the
  wire `MessageTag` via `KeyManager::open`, puncture, AEAD-open) → `Incoming::Message`.
  A dedicated actor thread (current-thread work on a multi-thread runtime +
  `LocalSet`, since presage's receive path spawns local tasks) owns the registered
  `Manager` + the cipher; the `Transport` talks to it over `Send` channels.
- **AEAD.** AES-256-GCM-SIV (RustCrypto's `aes-gcm-siv`, misuse-resistant even if the
  single-use-`mk` assumption is ever violated by a future bug) keyed by `mk`, with a
  fixed all-zero nonce — safe specifically because `mk` never repeats. This is still
  the design doc §10 sign-off item ("confirm the AEAD primitive choice") awaiting
  cryptographer confirmation, not yet a locked decision.
- **Proven** against the staging server by two examples — `a1_smoke` (presage
  registers two accounts and does a 1:1 send/receive) and `a1_transport` (two
  `PresageTransport`s exchange a payload A→B through the trait, now over the PPRF
  cipher) — and by the **real-`Record` convergence test**
  `e2e_record_converges_over_signal` (`personas-messenger`): a member emits a real
  Groth16 ban poll, it rides Signal via `PresageTransport`, and the observer's
  `Replica::ingest` verifies the proof and folds it. **That is the A2 + B1 "M3
  correctness demo over Signal."** `pprf_cipher` also carries its own in-process unit
  tests pinning the two properties A1 lacked: concurrent sends from different members
  no longer collide (`concurrent_sends_do_not_collide`), and a re-key excludes the old
  epoch's messages (`rekey_excludes_the_old_epoch`).
- **Staging plumbing** (all in `deploy/signal-test-server` + the vendored
  `third_party/libsignal-service-rs`): `SignalServers::Staging` repointed at a local
  TLS proxy → the test-server's cleartext `:8080`, with the test-server's CA / UD trust
  root / zkgroup params; and a one-file server patch so presage can register (the
  authenticated websocket must upgrade before the account exists).

**B2 status.** Wired and **confirmed passing** against the staging server. §6 has
the full account: the original certificate-substitution design turned out not to
be reachable through presage's public API at all, so it's realized instead via
Signal's stock multi-device linking — [`PresageTransport::link_as_phantom_device`]
plus the [`b2_phantom_link`] example, which registers a phantom, links a member as
its device, sends, and checks that an independent observer account sees the
phantom's identity rather than the member's. `cargo run -p transport-presage
--example b2_phantom_link` passed clean on the first real run: the linked device
registered as an additional `device_id` of the phantom's ACI, and the observer's
decrypt showed the phantom's ACI as sender, not a distinct one for the member.

**e2c status.** Wired. `PresageTransport::distribute_group_secret` /
`receive_group_secret` send the `DistributedSecret` as the body of an ordinary 1:1
Signal message — the same `send_message`/`receive_messages` path content already
uses — so establishing it runs Signal's real pairwise handshake (X3DH once, then
the Double Ratchet on every message after) inside `libsignal-service-rs`/`libsignal`
itself; nothing new was built for encryption, only serialization + a body-prefix tag
distinguishing a key-distribution message from a content message
(`KEY_DISTRIBUTION_TAG`). **Confirmed passing** against the staging server by the
[`e2c_key_distribution`](../crates/transports/transport-presage/examples/e2c_key_distribution.rs)
example: creator and member register independently, the creator distributes a fresh
secret, the member recovers it with no in-process hand-off, and both sides then
exchange one real PPRF-encrypted content message using their own (creator's
original / member's received) copy — proving the distributed secret is not just
byte-identical but installs a working `KeyManager` on both ends.
`PresageTransport::create_group_secret` still exists for tests/bring-up that want
the bytes directly without a network round trip.

**Remaining:** the re-key *triggers* (e2d — deciding when to call
`PprfContentCipher::rekey`: epoch boundary, ban, leave, or a time/message-count
cadence; the mechanism is wired, the triggers from the replica's/messenger's event
stream are not); the phantom-linking provisioning URL (§6) is still handed across
in-process rather than over this same now-real pairwise channel — a follow-up, not
a blocker, since e2c's channel now exists to carry it; and unlinking a device on
ban/leave (`Manager::unlink_secondary` exists but nothing calls it yet). Live
*production* Signal remains cryptographer-sign-off-gated (§10); the isolated
self-host is not that.

[`PresageTransport::link_as_phantom_device`]: ../crates/transports/transport-presage/src/lib.rs
[`b2_phantom_link`]: ../crates/transports/transport-presage/examples/b2_phantom_link.rs

---

## 1. The two layers that carry "who sent this"

A Signal group message attributes its author in two independent layers, and
pseudonymity needs **both** neutralised:

1. **Content layer — Sender Keys.** Each member normally holds *their own* sender
   key: a symmetric chain key **plus a Curve25519 signing key pair**. To send, a
   member hash-ratchets the chain key, AES-256-CBC-encrypts, and **signs the
   ciphertext with their private signing key**; recipients verify with that
   member's public signing key. *Attribution lives in the per-member signing key.*
2. **Delivery layer — Sealed Sender.** The ciphertext is wrapped in a
   `UnidentifiedSenderMessageContent` carrying a server-signed `SenderCertificate`.
   The server learns only "deliver to X"; the **recipient decrypts the cert and
   learns the real author.**

The modification, layer by layer (locked in review):

| Layer | Stock Signal | Personas modification |
|---|---|---|
| Content / message key | per-member key + per-member signing key → **attributable** | **one shared group secret**; no per-sender signing key → recipients cannot attribute or link |
| Delivery / sealed sender | real per-account `SenderCertificate` → recipient learns author | one **shared phantom `SenderCertificate`** (D1) → recipient sees only "phantom" |

Authorisation is **not** a Signal-layer property. Once the group key is shared,
nothing at the Signal layer stops a member claiming any persona or a non-member
injecting. Authorisation comes entirely from the **Groth16 proof** the receiving
replica checks before rendering (§7). The Signal layer provides transport,
confidentiality, and author-anonymity — never authorisation.

---

## 2. The layering — what lives where (the part to get exactly right)

This is the question that motivated the doc: *if encryption is libsignal's job,
what is the personas crypto for, and where does each byte live?* The stack, top
to bottom:

```
┌─────────────────────────────────────────────────────────────────┐
│ replica + messenger (d3/d4)         TRANSPORT-AGNOSTIC, BUILT     │
│   Record  ⇄  record bytes (CBOR)                                  │
│   Replica::ingest(bytes) = decode + Groth16-verify + fold         │  ← ZK verify
│   already lives here; e2 does not re-implement it                 │    is HERE
├─────────────────────────────────────────────────────────────────┤
│ personas content-crypto             KEY SCHEDULE ONLY (e2a)       │
│   Phase 2: mk = PPRF.Eval(K_epoch, nonce); MessageTag{epoch,nonce}│  ← outputs
│   outputs a 32-byte MessageKey. NEVER produces ciphertext.        │    KEYS
├─────────────────────────────────────────────────────────────────┤
│ Signal client  (libsignal via presage)   ENCRYPTION + DELIVERY    │
│   Phase 1: group_encrypt under a shared sender key  (Signal AEAD) │  ← the CIPHER
│   Phase 2: standard AEAD keyed by mk, blob → sealed-sender (D1)   │    is HERE
├─────────────────────────────────────────────────────────────────┤
│ Signal service                                                    │
└─────────────────────────────────────────────────────────────────┘
```

Four clarifications this stack pins down:

- **The plan's `PersonaEnvelope {msg, context, claimed, groth16_proof,
  callbacks}` already exists — it is the d3 `Record`.** The serverless record
  (`personas_bulletin::replica::record::Record`) already carries exactly the body,
  context, claimed persona, Groth16 proof, and callback tickets, CBOR-encoded to
  bytes. There is **no new envelope struct to invent**; the record bytes are the
  plaintext that gets encrypted.
- **The only genuinely new wire element (Phase 2) is the `MessageTag
  {epoch, nonce}`** that must ride *beside* the ciphertext so the receiver knows
  which PPRF leaf to derive. In Phase 1 there is no tag — Signal's own sender-key
  iteration counter does that job inside the `SenderKeyMessage`.
- **`e2a` outputs keys, not ciphertext.** `KeyManager::seal`/`open` return a
  32-byte `MessageKey`; the cipher that turns a record into bytes-on-the-wire is
  libsignal's (Phase 1) or a standard AEAD invoked with that key (Phase 2). We do
  not add or hand-roll an AEAD. "Personas-owned AEAD" in the plan means *personas
  chooses the key and invokes a standard cipher*, not *personas designs a cipher*.
- **Receive-side ZK verify is already built.** `Replica::ingest` decodes and
  Groth16-verifies every record (d3). e2's receive handler decrypts to record
  bytes and then calls it — it adds a decrypt step in front, nothing more.

### Why `presage`, not `signal-cli`

The current "Signal transport" (`transport-signal-cli`) drives the **signal-cli
daemon over JSON-RPC**. signal-cli does the Signal group encryption *inside its
own process, per-member*, and exposes only "send this text / receive this text."
We cannot make it share a sender key, substitute our message key, or deliver
under a phantom cert — the whole content-layer modification is invisible to it.

So the modified client **must be built on an in-process libsignal**
(`presage` + `libsignal-service-rs`), where we hold the sender-key state and the
sealed-sender call. This retires `transport-signal-cli` for e2 (it remains the
as-a-service path, M4). Getting presage into the tree is §8.

---

## 3. Phasing (decided 2026-07-15)

We reach a working demo with the **simplest** content-key story, then rework it.
The two axes phase independently:

**Axis A — content key schedule**

- **Phase A1 — static shared sender key.** One shared `SenderKeyRecord` (chain key
  + signing key pair) distributed to every member; stock `group_encrypt`/
  `group_decrypt`; **no rotation**, and we **assume no concurrent sends**. This has
  the *same cryptographic properties as stock Signal group messaging* — minus
  per-member attribution, because everyone signs under the one shared key. First
  working demo. **`e2a`'s K2/PPRF is not used here.**
- **Phase A2 — K2 + PPRF rework. `wired`.** Swap the content path to a personas
  AEAD keyed by `mk = PPRF.Eval(K_epoch, nonce)`, put the `MessageTag` on the wire,
  puncture on ingest — done, in `transport-presage/src/pprf_cipher.rs`, replacing
  Phase A1 as what `PresageTransport` actually runs. This is where `e2a` lands and
  where concurrency-safety and genuine forward secrecy come from. **Ban-exclusion
  via rotation is not yet live**: the mechanism (`rekey`) exists but nothing calls
  it yet — that trigger wiring is e2d, still open.

**Axis B — delivery identity**

- **Phase B1 — bring-up delivery.** Stock sealed sender under the real per-account
  cert (or even a plain group send) to prove the content path end-to-end over real
  Signal. Delivery-layer anonymity is *incomplete* here (recipients still see the
  account), so this is a bring-up step only.
- **Phase B2 — D1 shared phantom identity.** All members deliver as one shared
  phantom account; recipients see only "phantom." Full delivery anonymity.
  **Revised from a shared `SenderCertificate` to device linking — see §6.**

What each phase buys, and which sub-workstream owns it:

| Phase | Property gained | Owner | Status |
|---|---|---|---|
| A1 | content unattributable within group (shared key), Signal-equivalent otherwise | Phase-1 fork | superseded by A2 |
| A2 | + concurrency-safe, + genuine per-message FS | e2a (done) + A2 rework | **wired, confirmed passing** |
| A2 (ban-exclusion re-key) | banned member's key stops working at the Signal layer | e2d | open (mechanism exists, no trigger) |
| B1 | record rides real Signal; own-account receive; replica converges over the wire | Phase-1 fork | **wired, confirmed passing** |
| B2 | server + recipients cannot attribute the account | e2c (D1, via device linking) | **wired, confirmed passing** |
| K2 secret distribution | group secret reaches every member over a real pairwise session, not an in-process hand-off | e2c | **wired, confirmed passing** |

The first end-to-end milestone, **A1 + B1**, has already been superseded by **A2 +
B1** (the currently wired and confirmed state): the record travels over real
Signal, each client decrypts, `Replica::ingest` verifies the proof, and replicas
converge — the M3 correctness demo, now over Signal instead of the mock. Neither
A2 nor B2 touched the replica/messenger to get here, and B2 won't either.

---

## 4. Phase 1 in detail (the first fork target)

**Shared sender key.** One member generates a single `SenderKeyRecord` and
distributes its **full private state** (chain key + private signing key) to every
member over the pairwise Double Ratchet. This is *more* than the stock
`SenderKeyDistributionMessage`, which conveys only the public signing key — for
everyone to *send* under the shared key, everyone needs its private half. All
members load it as the group's sending key.

**Send.** `group_encrypt(record_bytes)` under the shared key — Signal's own AEAD.
The record bytes are exactly what d4's `carriage`/`Record` already produce.

**Receive.** `group_decrypt` → record bytes → `Replica::ingest` (verify + fold) →
render the persona. Identical to the d4 receive path, with a real Signal decrypt
where the mock transport used to hand bytes over directly.

**Delivery.** Start at B1; move to B2 (D1) when ready — orthogonal.

**Accepted Phase-1 limitations** (all lifted in Phase 2):

- *Concurrency:* two members sending before seeing each other advance the shared
  chain to the same iteration and derive the same message key → the second is
  dropped. Assumed away for the demo (low-rate, mostly-serial posting).
- *No rotation:* a banned member who keeps the shared key can still *read* new
  content at the Signal layer. Their **authorisation is still revoked** — their
  posts fail the ZK/rendering gate at every replica (§7) — but content-layer read
  exclusion waits for A2's re-key.
- *Forward secrecy:* only the sender-key chain's hash-ratchet; no per-message
  puncture, no epoch-secret deletion. Genuine FS is an A2 property.

**Phase-1 fork checklist** (§8 has the presage-plumbing prerequisites):

1. ~~Generate one shared `SenderKeyRecord`; serialise its full private state.~~ **Done** — `GroupContentCipher::create` → `SharedSenderKey`.
2. ~~Distribute it over pairwise sessions to all members; load on each.~~ **Done** — `PprfContentCipher::install` (successor to `GroupContentCipher::install`) installs the secret; real pairwise distribution over the Double Ratchet is `PresageTransport::distribute_group_secret`/`receive_group_secret` (e2c), proven by the `e2c_key_distribution` example.
3. ~~`group_encrypt`/`group_decrypt` the record bytes under it.~~ **Done** — `encrypt`/`decrypt` on opaque bytes.
4. ~~Wire behind the existing `Transport` trait as `transport-presage` so the
   messenger/replica are unchanged.~~ **Done** — `PresageTransport` (`send` =
   `group_encrypt` + 1:1 fan-out; `subscribe` = receive + `group_decrypt`), proven
   over the staging server by the `a1_transport` example.
5. Delivery B1 (per-member 1:1 fan-out) **done**; B2 (D1 phantom cert) remains.

Steps 1–3 are the **content cipher**, built and tested in-process against real
libsignal (no network, so not sign-off-gated — Layer-0, like `e2a`) in
`transport-presage`'s `content_cipher` module. Its tests pin the two things a
reviewer should see: full-private-state distribution lets *every* member send
(vs. an SKDM recipient, which can read but not sign — §10's second sign-off item,
made concrete), and the accepted A1 no-concurrency limit (two same-iteration sends
→ the second is dropped). Steps 4–5 need a registered account (§8 item 3).

---

## 5. Phase 2 in detail (the K2/PPRF rework)

Replace the static shared sender key with `e2a`'s `KeyManager`:

- **Key schedule.** `Sᵢ` (a freshly generated, deletable group secret) distributed
  over pairwise; `K_epoch = HKDF(Sᵢ, epoch)`; `mk = PPRF.Eval(K_epoch, nonce)`.
  Everything in `personas-group-crypto` already.
- **Wire format.** Each message carries `MessageTag {epoch, nonce}` in the clear
  beside the ciphertext, plus the AEAD ciphertext of the record bytes under `mk`.
- **AEAD primitive.** A **standard, vetted** AEAD keyed by `mk` — recommend
  libsignal's own (`signal-crypto`'s AES-256-GCM-SIV, or whatever the presage dep
  tree already vendors) so we add no new cipher crate. `mk` is **single-use**
  (punctured after one message), so nonce management is trivial (a fixed/derived
  nonce is safe — the key never repeats). This is the whole reason we don't need
  and shouldn't add a bespoke construction.
- **Delivery.** The `{tag, ciphertext}` blob rides inside the sealed-sender
  `UnidentifiedSenderMessageContent` under the D1 phantom cert.

**Full receive handler** (this is the plan's line-197 handler, made concrete):

1. libsignal sealed-sender-decrypt → `UnidentifiedSenderMessageContent` (phantom).
2. Extract `{MessageTag, ciphertext}`.
3. `mk = KeyManager::open(tag)` — derive the message key; **drop** if the tag is
   punctured/unavailable (already consumed, or not for this epoch).
4. AEAD-decrypt `ciphertext` under `mk` → record bytes.
5. `Replica::ingest(record_bytes)` → decode + Groth16-verify + fold (built).
6. Render the persona if accepted; drop/flag if the proof failed.
7. **Puncture** `mk` at `tag.nonce` — forward secrecy.

Sender side mirrors it: `KeyManager::seal` samples a nonce, derives `mk`,
punctures immediately (even the sender can't recover the key), and returns
`(tag, mk)`; the record is AEAD'd under `mk` and the tag rides alongside.

**Re-key / delete cadence (e2d).** Personas drives its own rotation — fresh
`Sᵢ₊₁` distributed over pairwise, `Sᵢ` deleted — on the revocation epoch
boundary, on ban/leave (so a removed member cannot derive `Sᵢ₊₁`), and optionally
on a time/message-count cadence. `KeyManager::rekey` is the (strictly
epoch-monotone) hook; wiring the *triggers* to the replica's epoch/membership
events is e2d.

Maps to: **e2a** (schedule — done), **e2b** (wire format + tag + the
decrypt→ingest→puncture seam), **e2d** (re-key triggers).

---

## 6. Delivery layer — D1 shared phantom identity — **realized via device linking,
## not certificate substitution (revised; see FINDINGS D14)**

**Original design, and why it changed.** The design as first specced: all members
hold one shared phantom account identity and its short-lived, server-signed
`SenderCertificate`, and deliver sealed-sender under it directly — "this is the
`SenderCertificate` argument to `sealed_sender_encrypt` — a *use* of a stock API,
not a fork." That assumed `presage`'s `Manager` would expose (a) a way to fetch a
`SenderCertificate` and (b) a way to pass one into the send path. Neither exists:
`Manager<S, Registered>`'s complete public method list (checked against its
published docs) has no certificate accessor and no override parameter on
`send_message`/`send_message_to_group`. Reaching the stock `SenderCertificate`
argument for real would mean forking presage or hand-rolling delivery directly
against the vendored `libsignal-service-rs`, bypassing `Manager` — the "no fork"
framing of the original plan didn't survive contact with presage's actual surface.

**What is built instead.** Signal's own multi-device linking, which presage does
expose (`Manager::link_secondary_device` / `Manager::link_secondary`, both stock,
undocumented-as-relevant-here but present in the public API). Every member becomes
their own independent **device** of one shared phantom account — own real identity
key, own real device-specific certificate, entirely unmodified — rather than
borrowing the phantom's certificate. `send_message` and every downstream
`PresageTransport` code path are **untouched**: the certificate a linked device
fetches for itself simply names the phantom's ACI, because that is genuinely which
account it now is. This achieves the identical externally-visible property
("recipients see a single 'phantom' sender") without touching a certificate at
all. Implemented as
[`PresageTransport::link_as_phantom_device`](../crates/transports/transport-presage/src/lib.rs),
proven end to end (phantom registers → member links as its device → member sends
→ an independent third "observer" account decrypts and confirms the sender ACI is
the phantom's, not the member's own) by the
[`b2_phantom_link`](../crates/transports/transport-presage/examples/b2_phantom_link.rs)
example.

**What is still a bring-up stand-in.** The provisioning URL that authorizes a link
(`link_secondary_device`'s output, consumed by the primary's `link_secondary`) is
still handed across **directly, in-process** by the caller today, even though e2c
(real pairwise Double Ratchet distribution) now exists and proves the mechanism
works — `distribute_group_secret`/`receive_group_secret` just haven't been reused
for this second payload yet. The decision the user made explicitly when this was
revised stands: the provisioning URL should travel over the *same* pairwise
channel already carrying the K2/PPRF group secret to each member, so only someone
who already legitimately holds the group secret can ever get a device linked as
the phantom — a follow-up change to `link_as_phantom_device`, not a new mechanism
to design.

**Unaffected by this change.** The recipient-access-key point (a sender needs each
recipient's access key from the group-shared profile keys to sealed-send) and the
accepted NDSS'21 residual timing/receipt-leakage limitation both still apply —
this revision only changes *whose* certificate gets used, not sealed sender's
other properties. The rejected D2 alternative (a certless custom content type) is
now doubly moot: it was rejected for being a deeper client modification with no
payoff, and device linking turns out to need no client modification at all.

---

## 7. Where authorisation lives (why Phase 1's weaker key story is still safe)

The Signal layer gives transport, confidentiality, and author-anonymity — **not
authorisation**. The message payload is the personas record, and each receiving
client runs the ZK verify (`Replica::ingest`) against its local Merkle-bulletin
replica **before rendering**. A failed proof ⇒ dropped/flagged, never shown as a
valid persona. Revocation is global and independent: a banned persona's proof
fails at *every* client.

This is why Phase 1 is a legitimate first step even though its key story is thin:
a banned member holding the static shared key gains nothing, because **their
authorisation is revoked at the proof layer regardless of the key.** The shared
key buys anonymity; the proof buys authorisation; the two are orthogonal.

Trust boundaries (the verification centrepiece — unchanged from the approved
design):

| Question | Signal server | Recipient member | Enforced by |
|---|---|---|---|
| Which *account* sent it | hidden (sealed sender; residual leakage ⚠) | hidden (D1: "phantom") | sealed sender + D1 |
| Which *persona* | hidden | learns persona (from `claimed`) | ZK payload |
| Message content | hidden (E2EE) | learns (is a member) | Signal AEAD |
| Author unlinkable across two posts | n/a | **yes** (shared key, random nonce, no per-sender sig) | shared secret + PPRF (A2) |
| Persona authorised / not revoked | n/a | **yes** (proof fails if revoked) | replica + Groth16 verify |

---

## 8. The fork — getting libsignal into the tree (option 3)

The modified client needs an **in-process** libsignal. The approved stack is
`presage` + `libsignal-service-rs`, pinned alongside the `zk-callbacks`/`sonobe`
pins and mirrored in `third_party/`.

**Stock (reused as-is):** registration/linking, **pairwise Double Ratchet
sessions** (distribute the shared sender key in Phase 1, `Sᵢ` in Phase 2), GroupV2
fetch, attachment upload/download, `sealed_sender_encrypt`/`decrypt`, and — Phase 1
only — `group_encrypt`/`group_decrypt`.

**Patched / added (minimal, pinned fork surface, mostly *use* of stock APIs):**

- Phase 1: shared `SenderKeyRecord` generation + full-private-state distribution +
  load.
- Phase 2 send: standard AEAD over the record bytes under `mk`, `{tag, ct}`
  delivered via `sealed_sender_encrypt` under the D1 phantom cert.
- Phase 2 receive: sealed-sender-decrypt → derive `mk` → AEAD-decrypt → feed the
  replica → render → puncture.
- Re-key hook: fresh `Sᵢ₊₁` + delete `Sᵢ` on epoch / membership change / cadence.

**Checklist to open the fork:**

1. ~~Add `presage` + `libsignal-service-rs` to the workspace; pin + mirror in
   `third_party/`; confirm they build against the pinned nightly.~~ **Done** (e2 fork; `libsignal-protocol` is now also a direct workspace pin — `tag = v0.94.4`, already in the lockfile via presage, so additive).
2. ~~Implement `transport-presage` behind the existing `transport_api::Transport`
   trait — so the d3/d4 messenger/replica are untouched.~~ **Done** —
   `PresageTransport` (`send`/`subscribe` real; `react` permanently `Unsupported`).
3. Land **A1 + B1** (§4): shared sender key + bring-up delivery → the M3
   correctness demo over real Signal. *(**Done at the transport layer** and proven
   over the isolated self-hosted staging server — `a1_smoke` + `a1_transport`
   examples. The remaining piece of the "M3 correctness demo" is driving a real d3
   `Record` through it end to end so the receiver's `Replica::ingest` verifies —
   a messenger-layer convergence test.)*
4. ~~Land **A2** (§5): wire `e2a`'s `KeyManager` in, add the `MessageTag` wire
   format + puncture-on-ingest.~~ **Done** — `transport-presage/src/pprf_cipher.rs`,
   proven by `e2e_record_converges_over_signal` and `pprf_cipher`'s own unit tests.
   The **e2d re-key triggers** (deciding *when* to call `rekey` — epoch boundary,
   ban, leave, cadence — from the replica's/messenger's event stream) remain.
5. ~~Land **B2** (§6, D1 phantom identity).~~ **Done** —
   `PresageTransport::link_as_phantom_device` (device linking, not certificate
   substitution — presage's `Manager` has no path to the latter; §6 has the full
   story) + the `b2_phantom_link` example, confirmed passing against the staging
   server. The phantom-linking provisioning URL is still handed across directly by
   the caller (a follow-up to reuse e2c's now-real channel), as does unlinking a
   device on ban/leave.
6. ~~Land **e2c** (real pairwise Double Ratchet distribution of the group secret).~~
   **Done** — `PresageTransport::distribute_group_secret`/`receive_group_secret`,
   proven by the `e2c_key_distribution` example (creator distributes, member
   recovers with no in-process hand-off, both sides exchange a real content
   message under their own copy).
7. Layer-0 adversarial gate (e2e) + cryptographer sign-off **before any live
   Signal** — staging only (e2f/g).

---

## 9. How the e2 sub-workstreams re-slice under phasing

- **e2a — done, and now in use.** `personas-group-crypto`: the K2 secret + GGM
  puncturable-PRF message-key schedule. Originally built as **Phase-2 machinery
  ahead of Phase 1** — a clean, auditable reference of the schedule (concurrency,
  FS, reorder-convergence proved in-process) — it has since been *ported into* the
  modified client's send/receive path by `transport-presage/src/pprf_cipher.rs`,
  which is what `PresageTransport` now runs. It is no longer just a standalone
  reference implementation that "correctly outputs keys and stops."
- **e2b — this doc + the seam.** The substantive content of e2b as originally
  scoped ("PersonaEnvelope + AEAD + receive ZK-verify + replica ingest") resolves
  to: (a) the record *is* the envelope — no new struct; (b) the AEAD is libsignal's
  — fork-gated, not built here; (c) receive ZK-verify already exists in d3. What is
  genuinely e2b's own is the **wire-format decision** (record bytes + `MessageTag`)
  and the **decrypt→ingest→puncture receive seam** — specified here (§2, §5),
  implemented against real libsignal in the fork. There is no well-layered e2b code
  to write in the current mock build; e2b **is** the spec plus the seam it defines.
- **e2c — mostly realized.** D1 delivery (§6) is `link_as_phantom_device` (device
  linking, wired, confirmed passing). Real pairwise distribution of the K2/PPRF
  group secret over the Double Ratchet is done —
  `distribute_group_secret`/`receive_group_secret`, confirmed passing via
  `e2c_key_distribution`. What's still open is reusing that same channel for the
  phantom-linking provisioning URL, which today is still modelled in-process by
  handing the URL across directly.
- **e2d** — the re-key triggers (§5).
- **e2e** — Layer-0 adversarial gate; concurrency/FS/outsider-key-secrecy already
  landed in `e2a`; non-member forgery + banned-persona rejection need the fork's
  wired receive path + the replica.
- **e2f/g** — staging then live Signal, cryptographer-sign-off-gated.
- **e2h** — Signal-Desktop rendering patch (stretch).

---

## 10. Sign-off items (for the cryptographer)

- **K2 realises the paper's "share a sender key" as "share a group secret + use
  Signal as anonymous transport."** It departs from literally reusing Signal's
  sender-key machinery (Phase 2 uses a personas AEAD keyed by the PPRF rather than
  `group_encrypt`). Flagged in the approved plan; still the one open design
  sub-point.
- **Phase-1 shared *private signing key*.** Distributing the full shared
  `SenderKeyRecord` means every member can sign as the shared key. That is
  intended — attribution is what we are removing, and authorisation is the ZK
  proof, not the signature — but it is a real departure from Signal's per-member
  signing and should be signed off as acceptable for the demo.
- **AEAD primitive choice (Phase 2).** Use libsignal's own vetted AEAD keyed by the
  single-use `mk`; confirm the choice and that a `{MessageTag, ciphertext}`
  content-type rides cleanly inside `UnidentifiedSenderMessageContent`.
- **presage / libsignal-service-rs fork pinning** alongside the existing pins,
  mirrored in `third_party/`; CI builds from the lockfile only.
- **Accepted limitations, restated:** sealed-sender residual timing/receipt
  leakage (NDSS'21) not addressed; PCS is re-key-only, same as stock groups;
  Phase-1 no-concurrency and no-content-layer-ban-exclusion.
- **D1 realized as device linking, not certificate substitution (new — see §6,
  FINDINGS D14).** Every member is now a genuine additional *device* of the
  phantom account, each with its own real identity key, rather than borrowing a
  single shared certificate. Worth explicit sign-off: this means Signal's server
  itself treats every member as a legitimate device of one account (able to
  receive that account's fanned-out messages, appear in `devices()`, etc.), which
  is a different trust/blast-radius shape than "many senders reuse one
  certificate" — e.g. a malicious member who links is a *device* of the phantom,
  not merely a certificate-holder, until unlinked. Whether that distinction
  matters for this threat model wants a second opinion before B2 is considered
  closed.
