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

**B2 status.** Wired, via a fork — `docs/FINDINGS.md`'s newest entry has the full
account. §6 explains why: certificate substitution alone is cryptographically
unsound (not an API gap), and device linking (built, then reverted) closes that
gap but leaks a stable per-member device-id tag. What's built instead is a
**shared ACI identity keypair**: every member registers their own fully
independent Signal account, but with an identity keypair deterministically
derived from the group secret instead of a random one
(`PresageTransport::register_as_phantom`, `DistributedSecret::derive_phantom_identity_seed`).
Needed a fork of `presage` itself (vendored at `third_party/presage`, patched in
the same way `libsignal-service-rs` already is) — `Manager::confirm_verification_code`
had no seam to override the internally-generated identity keypair — plus a small
addition to the already-vendored `libsignal-service-rs` to surface the
certificate's embedded identity key on receive. Proof:
[`b2_shared_identity`](../crates/transports/transport-presage/examples/b2_shared_identity.rs).

**Remaining:** the re-key *triggers* (e2d — deciding when to call
`PprfContentCipher::rekey`: epoch boundary, ban, leave, or a time/message-count
cadence; the mechanism is wired, the triggers from the replica's/messenger's event
stream are not) — which, per §6, would now also need to rotate the phantom
identity (re-registration, not a cheap operation) once wired. Live *production*
Signal remains cryptographer-sign-off-gated (§10); the isolated self-host is not
that.

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

What each phase buys, and which sub-workstream owns it:

| Phase | Property gained | Owner | Status |
|---|---|---|---|
| A1 | content unattributable within group (shared key), Signal-equivalent otherwise | Phase-1 fork | superseded by A2 |
| A2 | + concurrency-safe, + genuine per-message FS | e2a (done) + A2 rework | **wired, confirmed passing** |
| A2 (ban-exclusion re-key) | banned member's key stops working at the Signal layer | e2d | open (mechanism exists, no trigger) |
| B1 | record rides real Signal; own-account receive; replica converges over the wire | Phase-1 fork | **wired, confirmed passing** |
| B2 | server + recipients cannot attribute the account | e2c (D1, shared identity keypair) | **wired** (via a presage fork) |
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

## 6. Delivery layer — D1 shared phantom identity — realized as a shared ACI
## identity keypair, not certificate substitution or device linking

**Two designs that don't work, ruled out first.**

Naively swapping the outer `SenderCertificate` on an otherwise-normal send does
not work, and this is a protocol fact, not an implementation gap: a recipient's
`sealed_sender_decrypt` looks up the Double Ratchet session to decrypt *with*
using the address named in the certificate
(`ProtocolAddress::new(cert.sender_uuid(), cert.sender_device_id())` —
`signalapp/libsignal`, `rust/protocol/src/sealed_sender.rs`). If a member
encrypts under their own identity key but attaches the phantom's certificate, the
recipient decrypts against the *phantom's* session — a different ratchet chain
entirely — and decryption fails outright, not just misattributes.

Device linking (every member becomes a real, additional Signal *device* of the
phantom account) sidesteps that correctly, because a linked device genuinely
receives the phantom's real identity key during the linking handshake. It was
built and confirmed working (`docs/FINDINGS.md` D14), but introduces its own
problem: a linked device's `device_id` is a stable, persistent per-member tag
visible to every recipient on every message (`docs/B2_DEVICE_ID_LINKABILITY_ISSUE.md`,
no longer in the tree — reverted alongside the rest of that approach), breaking
post-to-post unlinkability. A fix (per-message device rotation) was attempted and
found not to work on this server, which reuses freed device-id slots immediately.
Both device-linking and its rotation fix were reverted; see `docs/FINDINGS.md`'s
history for the full account.

**What's actually built: a shared ACI identity keypair.**

The insight that unblocks this (credit: external review) is that "encrypt under
your own identity key" was never a fixed constraint — the identity keypair
backing an account's Double Ratchet sessions is *just a Curve25519 keypair*,
freely choosable at registration. Nothing requires it to be randomly generated,
and nothing requires it to be unique per account.

So every member registers their **own, completely independent** real Signal
account — own phone number, own uuid, own device id, own prekeys, own sessions
with every recipient — except the **ACI identity keypair** is not randomly
generated. It is deterministically derived from the group secret
(`personas_group_crypto::DistributedSecret::derive_phantom_identity_seed`,
HKDF over `(seed, epoch)`, domain-separated from the message-key schedule),
turned into a Curve25519 keypair
(`PrivateKey::deserialize` on the derived 32 bytes, then `.public_key()`), and
passed into registration
(`transport_presage::PresageTransport::register_as_phantom`). Every member who
installed the same group secret derives the identical keypair, with zero extra
network round trips — the derivation is entirely local, riding on e2c's
already-distributed secret.

Signal's server, seeing nothing unusual (a normal account registering with a
normal-looking identity key), legitimately signs that account's own
`SenderCertificate` — which now just happens to embed the same public identity
key as every other member's. Nothing about certificate issuance, session
establishment, or delivery needed to change; `Manager::send_message` and every
existing `PresageTransport` code path are untouched. The one real fork was
upstream of all of that: `Manager<S, Confirmation>::confirm_verification_code`
always calls `IdentityKeyPair::generate(&mut rng)` inline, with no way to
override it — see `third_party/presage/presage/src/manager/confirmation.rs`'s
`confirm_verification_code_with_identity`, added specifically for this.

**Why this doesn't reintroduce a collision hazard.** Each member's Double Ratchet
sessions with any given recipient stay entirely independent: X3DH mixes in each
member's own distinct signed-prekey and one-time-prekey (fetched from *their*
account's own, real prekey bundle) even though the identity-key input to that
handshake happens to be shared. Two members are never advancing the same ratchet
chain, unlike sharing an actual sender-key chain (Phase A1's own accepted
limitation) or sharing a device id (the reverted device-linking rotation
attempt) — both of those collide because they share *mutable, sequentially
advanced* state; a shared identity key is neither mutable nor sequential, it is
static input to independent handshakes.

**What the receive side has to do differently.** Sealed sender was never designed
to hide the sender from the *recipient* — `sealed_sender_decrypt` always exposes
`cert.sender_uuid()` to whoever decrypts, that's how the recipient's client knows
who to attribute the message to. So even with every member sharing an identity
key, `content.metadata.sender` (the uuid) still reports each member's own,
genuinely distinct real account — nothing hides that field, and this scheme does
not try to. What's actually shared is the certificate's **embedded identity
public key**, a field the recipient never previously had a reason to look at.
`third_party/libsignal-service-rs`'s `Metadata` struct now carries it
(`sender_identity_key: Option<PublicKey>`, populated only on sealed-sender
deliveries — see the fork in `src/cipher.rs`/`src/content.rs`), and
`PresageTransport`'s receive loop reports *that* (base64-encoded, `phantom:`
prefix) as `Incoming::Message::sender` whenever it's present, falling back to the
real uuid otherwise (identified bring-up delivery, or a group not using this
scheme). That fallback matters: sealed sender itself is conditional in this
codebase — `Manager::send_message` only attempts unidentified delivery once the
sender's store already holds the recipient's profile key, which presage learns
automatically from one prior identified message in each direction (already
happens naturally in every multi-message example here). Before that point, a
send is identified and this scheme has nothing to hide behind.

**Cost, stated plainly.** The identity keypair is scoped to the epoch, like the
rest of the group secret — a re-key rotates it. Unlike a content-layer re-key,
rotating an *identity* keypair is not cheap: it means every member re-registering
their Signal account identity, not just installing a new `KeyManager`. Not yet
wired to any re-key trigger (e2d, the same open item the message-key schedule
already has).

**Proof structure.** `transport-presage/examples/b2_shared_identity.rs`: two
members register independently (`register_as_phantom`, same group secret), an
independent observer registers normally, a bootstrap round gets profile keys
exchanged so the real test sends actually go sealed-sender, then each member
sends the observer one more message. The observer must see two *different*
`sender` uuids (proving this is not device linking) and two *identical*
`sender_identity_key` values (proving the shared-identity property actually
holds where it matters).

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
5. ~~Land **B2** (§6, D1 phantom identity).~~ **Done, via a fork** —
   `PresageTransport::register_as_phantom` (shared ACI identity keypair, derived
   from the group secret; `third_party/presage`'s `confirm_verification_code_with_identity`
   is the actual fork point) + a small addition to the already-vendored
   `libsignal-service-rs` exposing the certificate's embedded identity key on
   receive. Proven by `b2_shared_identity`: two independent members, two
   different real uuids, the same certificate-embedded identity key on both.
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
- **e2c — done.** Real pairwise distribution of the K2/PPRF group secret over the
  Double Ratchet — `distribute_group_secret`/`receive_group_secret`, confirmed
  passing via `e2c_key_distribution`. D1 delivery (§6, the shared phantom
  sealed-sender identity) is also done, via the shared-ACI-identity-keypair
  scheme (a `presage` fork) — confirmed passing via `b2_shared_identity`.
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
- **Shared ACI identity keypair across accounts (new — see §6).** Multiple real,
  independently-registered Signal accounts now intentionally hold the *same*
  identity keypair. Signal's own trust model (TOFU identity pinning, safety
  numbers) generally assumes one identity key maps to one account; this scheme
  deliberately breaks that assumption for every member of a group. It has no
  effect on *this* system's own clients (which don't need or check that
  invariant), but is worth explicit sign-off before any interop with real,
  unmodified Signal clients is on the table — an unmodified client seeing the
  same identity key across what look like unrelated contacts is untested,
  unspecified behavior from Signal's own point of view, not something this
  design doc can vouch for.
