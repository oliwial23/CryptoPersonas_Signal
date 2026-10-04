# e2a — content-layer group crypto (K2 secret + puncturable-PRF message keys)

The first slice of **e2** (the modified Signal client). It implements the
*content-layer* key schedule that lets any group member post without attribution:
a freshly generated, deletable shared group secret (**K2**) and a **GGM
puncturable-PRF** message-key schedule driven from it. Everything here is native
symmetric crypto — no libsignal, no async, no arkworks — so it can be audited as a
single unit, which is the e2a crypto sign-off gate.

Code: `crates/personas-group-crypto/` (`kdf.rs`, `pprf.rs`, `group.rs`, `lib.rs`).
Design context: the *Signal client modification — detailed design* section of the
approved plan. This doc is the implementation companion to that design.

## 1. The problem it solves

A Signal group message carries "who sent this" in two independent layers, and
pseudonymity needs both neutralised:

1. **Content layer — per-member sender key.** Each member signs its ciphertext
   with its own signing key; recipients verify and thereby *attribute* the message.
2. **Delivery layer — sealed sender.** The recipient decrypts a server-signed
   `SenderCertificate` and learns the real account.

e2a handles layer 1: replace per-member keys with **one shared group secret**, so
there is no per-sender signature to attribute or link. Layer 2 (sealed sender under
a shared phantom certificate, D1) is **e2c**. Authorisation — the thing that stops
a non-member injecting or a member claiming any persona — is **not** a Signal-layer
property; it is the Groth16 proof the receiving replica checks before rendering
(**e2b**). e2a provides only anonymity + confidentiality of the content channel.

## 2. K2: a freshly generated, deletable shared secret

`GroupSecret` (`group.rs`) is `Sᵢ`, a 32-byte seed sampled per epoch. One member
distributes its wire form (`DistributedSecret`) to every other member **over the
pairwise Double Ratchet** — in e2a's tests this is modeled by handing each member
the same bytes; the real pairwise wiring is e2c. Each member calls
`KeyManager::install`, which derives

```
K_epoch = HKDF-SHA256(salt, ikm = Sᵢ ‖ epoch_le, info = "personas/group-epoch-key/v1")
```

into the puncturable-PRF root — **and then drops `Sᵢ`**. Retaining `Sᵢ` would let a
device snapshot recompute `K_epoch` un-punctured and recover every consumed message
key, so deletion is load-bearing.

This is exactly why **K1 was rejected**: deriving the epoch key from the persistent
`GroupMasterKey` (held by every member to be in the Signal group) means the seed can
never be deleted — a compromise recomputes all epoch keys and forward secrecy is
gone. K2's freshness + deletability is what makes FS real. Re-key cadence is
personas-owned (`KeyManager::rekey`, strictly epoch-monotone), not Signal's
membership-only rotation; the *triggers* (epoch boundary / ban / leave) are e2d.

## 3. The puncturable PRF (`pprf.rs`)

Message keys are indexed by a random **nonce**, not a counter. Under a shared secret
a counter would collide the instant two members send before seeing each other (both
derive the key for iteration *i*, the second decrypt fails — an observable dropped
message). Random nonces remove the collision. But a plain `KDF(root, nonce)` forces
keeping `root` all epoch (you can't predict future nonces), so no within-epoch FS.

A puncturable PRF gives both. `Eval(k, nonce)` is a normal PRF; `Puncture(k, nonce)`
keeps every other point evaluable but makes that one unrecoverable.

- **Construction:** classic GGM over a depth-128 binary tree. PRG =
  `G(seed) = (SHA256(0x00‖seed), SHA256(0x01‖seed))`; a nonce's 128 bits (MSB-first)
  pick the root-to-leaf path; the leaf seed is the PRF value. The tree is never
  materialised.
- **Punctured key = a set of cover nodes:** interior seeds whose subtrees are wholly
  un-punctured, tiling the domain minus the punctured leaves. Puncturing a leaf
  replaces its one covering node with the ≤128 sibling seeds along the co-path and
  **drops the on-path leaf seed** (zeroized). All siblings survive; the point is
  gone. Standard multi-puncture GGM.
- **Properties that matter here:** puncturing is **commutative** and each member
  punctures only nonces it actually consumed, so out-of-order delivery converges to
  the same key state — the serverless requirement. Depth 128 makes two independently
  sampled nonces collide with probability `m²/2¹²⁸` (negligible). Cost is `≤128` PRG
  calls per op; key state grows `O(consumed · 128 · λ)` within an epoch and is
  discarded wholesale at re-key. The naïve `Vec<CoverNode>` lookup is `O(cover
  count)` — fine at demo scale; a prefix trie is the obvious later optimisation.

`KeyManager::seal` (send) samples a nonce, evaluates, **punctures immediately** (so
even the sender can't recover the key), and returns a `MessageTag {epoch, nonce}`
(rides in the e2b envelope) plus the `MessageKey` (the e2b AEAD key).
`KeyManager::open` (receive) re-derives from the tag and punctures. Both derive the
final AEAD key by a labeled HKDF-Expand of the PPRF leaf, domain-separating it from
the tree's internal seeds.

## 4. Forward secrecy, precisely

The FS claim is: **a snapshot of a member's key state cannot recover an
already-consumed message key.** It holds at the persisted-state level — after
puncturing a nonce, no remaining cover node can reach that leaf, and `Sᵢ` (which
could otherwise recompute the un-punctured root) was deleted at install.
`forward_secrecy_snapshot_cannot_recover_consumed_keys` proves it by serialising the
*entire* post-consume `KeyManager`, restoring it, and confirming the consumed key is
`Consumed`. Seed material is `zeroize`d on drop throughout (`GroupSecret`,
`MessageKey`, `PrfOutput`, cover nodes, the discarded leaf); stack-residue scrubbing
of intermediates is best-effort given Rust's moves/copies — the guarantee rests on
the persisted state, not on wiping every transient.

PCS (recovery *after* compromise) still comes only from re-keying with fresh entropy
from an uncompromised distributor — same as stock groups; continuous PCS would need
MLS-style per-epoch agreement, out of scope.

## 5. What the tests establish

`cargo test -p personas-group-crypto` (20 tests, all fast — no proving):

- **KDF vectors:** HMAC-SHA256 against RFC 4231 cases 1/2/6 (incl. the >block-size
  key path); HKDF-SHA256 against RFC 5869 A.1. These pin the hand-rolled primitives
  to the published standards.
- **PPRF:** determinism; distinct-nonce separation; puncture removes only its target
  and leaves all others intact; idempotent puncture; **commutativity** (puncture
  order doesn't change surviving values); serde round-trip preserves evaluation.
- **Schedule:** sender/receiver derive the same key; **concurrent sends at distinct
  nonces both decrypt**; re-opening a consumed message fails; **forward-secrecy
  snapshot** test; re-key deletes the old epoch and advances; non-monotone re-key
  and wrong-epoch are rejected.
- **End-to-end harness (`lib.rs`):** a 5-member group where every member ingests
  every post in a *different* order and all converge on the same per-message keys;
  an outsider without `Sᵢ` derives different keys.

Several of these are the in-process half of **e2e's Layer-0 adversarial gate**
(concurrency, FS, outsider key-secrecy). The rest of e2e — non-member *forgery*
rejection and banned-persona rejection — needs the e2b ZK payload and the replica,
so it lands once those exist.

## 6. Scope and what's deferred

- **e2b:** `PersonaEnvelope` (`{msg, context, claimed, groth16_proof, callbacks,
  MessageTag}`), the AEAD under `MessageKey`, receive-side ZK verify, and feeding the
  d3 replica — puncturing key state on ingest.
- **e2c:** sealed-sender delivery under the shared phantom cert (D1); the real
  pairwise-session distribution of `DistributedSecret`; verify the custom content
  type rides in `UnidentifiedSenderMessageContent`.
- **e2d:** the re-key *cadence* — wiring `rekey` to the personas epoch boundary,
  ban/leave, and an optional time/message-count trigger.
- **Perf:** cover-node lookup is linear; a trie makes eval/puncture `O(depth)`. Key
  growth per consumed message is the accepted cost of per-message FS, bounded by
  re-key cadence.

## 7. Sign-off notes (for the cryptographer)

- **Hand-rolled HMAC/HKDF over the pinned `sha2 0.10`** rather than the `hkdf` crate
  — avoids dragging a second `digest` version in to pair with the lockfile's
  `hmac 0.13`, and keeps the audited surface one small file pinned to RFC vectors.
- **PRG = domain-separated SHA-256 doubling.** Security = SHA-256
  collision/pre-image resistance (native, no circuit).
- **One open design point already flagged in the plan:** K2 realises the paper's
  "share a sender key" as "share a group secret + use Signal as anonymous
  transport," departing from literally reusing Signal's sender-key machinery. Called
  out for sign-off.
