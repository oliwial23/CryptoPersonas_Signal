//! The K2 group-key layer: a freshly generated, deletable shared secret and the
//! per-message key schedule driven from it.
//!
//! # Flow
//!
//! 1. A member (creator or re-keyer) samples a fresh [`GroupSecret`] `Sᵢ` for a new
//!    epoch and hands its [`DistributedSecret`] wire form to every other member
//!    **over the pairwise Double Ratchet** (in-process in e2a's harness; libsignal
//!    pairwise sessions in e2c). The wire form carries the raw seed, so it must
//!    only ever travel inside that already-encrypted pairwise channel.
//! 2. Each member (creator included) calls [`KeyManager::install`], which derives
//!    the epoch key `K_epoch = HKDF(Sᵢ, epoch)` into a [`PuncturableKey`] root and
//!    then **drops `Sᵢ`**. Retaining `Sᵢ` would let a device snapshot recompute
//!    `K_epoch` un-punctured and recover every consumed message key — so deleting
//!    it is what makes forward secrecy real (this is the K2-over-K1 argument: a
//!    persistent `GroupMasterKey` could never be deleted, so it could never be FS).
//! 3. To post, [`KeyManager::seal`] samples a random nonce, evaluates the PPRF,
//!    punctures it, and returns a [`MessageTag`] (epoch + nonce, rides in the
//!    envelope) and the [`MessageKey`] (the AEAD key e2b encrypts under). To
//!    receive, [`KeyManager::open`] re-derives the same key from the tag and
//!    punctures. Because puncturing is commutative and each member punctures only
//!    what it consumed, all members converge to the same key state under reordering.
//! 4. On the personas re-key cadence (epoch boundary / ban / leave — the *triggers*
//!    are e2d), [`KeyManager::rekey`] installs a fresh secret and drops the old
//!    epoch's key wholesale.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::kdf::{HASH_LEN, hkdf_expand_32, hkdf_sha256};
use crate::pprf::{Nonce, PuncturableKey};

/// Domain-separation labels. Versioned so a future scheme change is a distinct KDF.
const EPOCH_KEY_INFO: &[u8] = b"personas/group-epoch-key/v1";
const EPOCH_KEY_SALT: &[u8] = b"personas/group-epoch-key/salt/v1";
const MESSAGE_KEY_INFO: &[u8] = b"personas/message-key/v1";

/// What a recipient needs to re-derive a message key: the epoch that was installed
/// and the sender's random nonce. Rides in the `PersonaEnvelope` header (e2b);
/// public, carries no secret (the nonce indexes the key, it is not the key).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageTag {
    pub epoch: u64,
    pub nonce: Nonce,
}

/// The freshly generated shared group secret `Sᵢ` for one epoch (K2).
///
/// Not `Clone`: the seed is sensitive and should exist in as few places as
/// possible. Zeroized on drop. Use [`Self::to_wire`] to obtain the byte payload
/// that travels (encrypted) over the pairwise channel.
pub struct GroupSecret {
    epoch: u64,
    seed: Zeroizing<[u8; HASH_LEN]>,
}

impl GroupSecret {
    /// Sample a fresh secret for `epoch`.
    pub fn generate(epoch: u64, rng: &mut impl rand::RngCore) -> Self {
        let mut seed = [0u8; HASH_LEN];
        rng.fill_bytes(&mut seed);
        GroupSecret {
            epoch,
            seed: Zeroizing::new(seed),
        }
    }

    /// The epoch this secret keys.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The byte payload to distribute over the pairwise sessions. Carries the raw
    /// seed — only ever send it inside the Double-Ratchet-encrypted pairwise channel.
    pub fn to_wire(&self) -> DistributedSecret {
        DistributedSecret {
            epoch: self.epoch,
            seed: *self.seed,
        }
    }

    /// Reconstruct a secret received (decrypted) from a pairwise session.
    pub fn from_wire(wire: DistributedSecret) -> Self {
        let mut wire = wire;
        let secret = GroupSecret {
            epoch: wire.epoch,
            seed: Zeroizing::new(wire.seed),
        };
        wire.seed.zeroize();
        secret
    }

    /// Derive the epoch key = the PPRF root seed. Binds the epoch number so two
    /// epochs never share a schedule even in the (negligible) event of a seed clash.
    fn epoch_key(&self) -> [u8; HASH_LEN] {
        let mut ikm = [0u8; HASH_LEN + 8];
        ikm[..HASH_LEN].copy_from_slice(self.seed.as_ref());
        ikm[HASH_LEN..].copy_from_slice(&self.epoch.to_le_bytes());
        let root = hkdf_sha256(EPOCH_KEY_SALT, &ikm, EPOCH_KEY_INFO);
        ikm.zeroize();
        root
    }
}

/// The wire form of a [`GroupSecret`] — what a distributor sends each member over
/// the pairwise channel. Zeroized on drop; treat every copy as key material.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct DistributedSecret {
    pub epoch: u64,
    pub seed: [u8; HASH_LEN],
}

/// A per-message AEAD key handed to e2b. Zeroized on drop; never logged.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MessageKey([u8; HASH_LEN]);

impl MessageKey {
    /// The 32-byte key material for the e2b AEAD.
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for MessageKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MessageKey(..)")
    }
}

/// Failure to derive a message key from a received tag.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OpenError {
    /// The tag names a different epoch than the one currently installed. After a
    /// re-key the previous epoch's key is deleted, so its messages cannot be opened.
    #[error("message is for epoch {got}, current epoch is {expected}")]
    WrongEpoch { expected: u64, got: u64 },

    /// This nonce was already consumed (punctured) — a replay, or a message this
    /// member already processed. Its key is gone by construction (forward secrecy).
    #[error("message key already consumed (replay or already processed)")]
    Consumed,
}

/// Rejecting a re-key.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RekeyError {
    /// The new secret does not advance the epoch. Re-keys must be strictly
    /// monotone so a stale secret can never roll the schedule backward.
    #[error("re-key epoch {got} does not advance current epoch {current}")]
    NonMonotonic { current: u64, got: u64 },
}

/// One member's view of the shared message-key schedule for the current epoch.
///
/// Holds only the epoch number and the (progressively punctured) [`PuncturableKey`]
/// — never `Sᵢ`, which was dropped at install. Zeroizes on drop.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct KeyManager {
    #[zeroize(skip)]
    epoch: u64,
    keys: PuncturableKey,
}

impl KeyManager {
    /// Install a shared secret: derive the epoch key, seed the PPRF, and drop `Sᵢ`.
    pub fn install(secret: GroupSecret) -> Self {
        let epoch = secret.epoch();
        let root = secret.epoch_key();
        // `secret` is dropped here → `Sᵢ` zeroized. We keep only the PPRF key.
        KeyManager {
            epoch,
            keys: PuncturableKey::new(root),
        }
    }

    /// The currently installed epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Sender path: derive a fresh message key and the tag that lets recipients
    /// re-derive it. Punctures the key on the way out, so even the sender cannot
    /// recover it afterward.
    pub fn seal(&mut self, rng: &mut impl rand::RngCore) -> (MessageTag, MessageKey) {
        loop {
            let nonce = Nonce::random(rng);
            // A collision with an already-consumed nonce is astronomically unlikely
            // (128-bit); if it happens, `eval` is `None` and we simply resample.
            if let Some(out) = self.keys.eval(&nonce) {
                self.keys.puncture(&nonce);
                let mk = derive_message_key(out.0);
                return (
                    MessageTag {
                        epoch: self.epoch,
                        nonce,
                    },
                    mk,
                );
            }
        }
    }

    /// Receiver path: re-derive the message key named by `tag`, then puncture it.
    pub fn open(&mut self, tag: &MessageTag) -> Result<MessageKey, OpenError> {
        if tag.epoch != self.epoch {
            return Err(OpenError::WrongEpoch {
                expected: self.epoch,
                got: tag.epoch,
            });
        }
        let out = self.keys.eval(&tag.nonce).ok_or(OpenError::Consumed)?;
        self.keys.puncture(&tag.nonce);
        Ok(derive_message_key(out.0))
    }

    /// Re-key to a fresh epoch, deleting the old epoch's schedule wholesale. The new
    /// secret must strictly advance the epoch.
    pub fn rekey(&mut self, secret: GroupSecret) -> Result<(), RekeyError> {
        if secret.epoch() <= self.epoch {
            return Err(RekeyError::NonMonotonic {
                current: self.epoch,
                got: secret.epoch(),
            });
        }
        // Overwrite self: the old `PuncturableKey` drops → all seeds zeroized.
        *self = KeyManager::install(secret);
        Ok(())
    }

    /// Whether `tag`'s key is still available (not yet consumed and same epoch).
    pub fn is_available(&self, tag: &MessageTag) -> bool {
        tag.epoch == self.epoch && !self.keys.is_punctured(&tag.nonce)
    }
}

/// Turn a raw PPRF leaf into an AEAD message key. The leaf is already
/// pseudorandom, so a labeled HKDF-Expand suffices to domain-separate the AEAD key
/// from the PRF's internal seeds.
fn derive_message_key(mut leaf: [u8; HASH_LEN]) -> MessageKey {
    let mk = hkdf_expand_32(&leaf, MESSAGE_KEY_INFO);
    leaf.zeroize();
    MessageKey(mk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rng(seed: u64) -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(seed)
    }

    /// Build `n` members that all installed the same freshly distributed secret —
    /// the in-process stand-in for pairwise distribution.
    fn group(epoch: u64, n: usize, rng: &mut impl rand::RngCore) -> Vec<KeyManager> {
        let secret = GroupSecret::generate(epoch, rng);
        let wire = secret.to_wire();
        let mut members: Vec<KeyManager> = (0..n)
            .map(|_| KeyManager::install(GroupSecret::from_wire(wire.clone())))
            .collect();
        // The distributor also installs (and drops its own `secret`).
        members.push(KeyManager::install(secret));
        members
    }

    #[test]
    fn sender_and_receiver_derive_the_same_key() {
        let mut r = rng(1);
        let mut m = group(0, 2, &mut r);
        let (mut recv, mut send) = (m.remove(0), m.remove(0));

        let (tag, sender_key) = send.seal(&mut r);
        let receiver_key = recv.open(&tag).unwrap();
        assert_eq!(sender_key, receiver_key);
    }

    #[test]
    fn concurrent_sends_do_not_collide() {
        // Two members each send before seeing the other; a third opens both.
        let mut r = rng(2);
        let mut m = group(0, 3, &mut r);
        let (mut a, mut b, mut c) = (m.remove(0), m.remove(0), m.remove(0));

        let (tag_a, key_a) = a.seal(&mut r);
        let (tag_b, key_b) = b.seal(&mut r);
        assert_ne!(tag_a.nonce, tag_b.nonce);

        // Reader opens them out of order; both succeed and match.
        assert_eq!(c.open(&tag_b).unwrap(), key_b);
        assert_eq!(c.open(&tag_a).unwrap(), key_a);
    }

    #[test]
    fn reopening_a_consumed_message_fails() {
        let mut r = rng(3);
        let mut m = group(0, 2, &mut r);
        let (mut recv, mut send) = (m.remove(0), m.remove(0));

        let (tag, _) = send.seal(&mut r);
        recv.open(&tag).unwrap();
        // Second open of the same tag: key was punctured on first open.
        assert_eq!(recv.open(&tag), Err(OpenError::Consumed));
    }

    #[test]
    fn forward_secrecy_snapshot_cannot_recover_consumed_keys() {
        let mut r = rng(4);
        let mut m = group(0, 2, &mut r);
        let (mut recv, mut send) = (m.remove(0), m.remove(0));

        let (tag, consumed) = send.seal(&mut r);
        let rederived = recv.open(&tag).unwrap();
        assert_eq!(consumed, rederived);

        // Snapshot the receiver's *entire* post-consume key state and try to recover
        // the message key from it — it must be gone.
        let snapshot = serde_json::to_vec(&recv).unwrap();
        let mut restored: KeyManager = serde_json::from_slice(&snapshot).unwrap();
        assert!(!restored.is_available(&tag));
        assert_eq!(restored.open(&tag), Err(OpenError::Consumed));
    }

    #[test]
    fn rekey_deletes_the_old_epoch_and_advances() {
        let mut r = rng(5);
        let mut m = group(0, 2, &mut r);
        let (mut recv, mut send) = (m.remove(0), m.remove(0));

        // A message sealed under epoch 0, held in flight.
        let (old_tag, _) = send.seal(&mut r);

        // Both re-key to epoch 1 with a fresh secret.
        let next = GroupSecret::generate(1, &mut r);
        let next_wire = next.to_wire();
        recv.rekey(GroupSecret::from_wire(next_wire.clone()))
            .unwrap();
        send.rekey(next).unwrap();

        // The in-flight epoch-0 message can no longer be opened (key deleted).
        assert_eq!(
            recv.open(&old_tag),
            Err(OpenError::WrongEpoch {
                expected: 1,
                got: 0
            })
        );

        // Epoch 1 works end to end.
        let (tag1, k1) = send.seal(&mut r);
        assert_eq!(recv.open(&tag1).unwrap(), k1);
    }

    #[test]
    fn rekey_rejects_non_advancing_epoch() {
        let mut r = rng(6);
        let mut m = group(5, 1, &mut r);
        let mut mgr = m.remove(0);
        let stale = GroupSecret::generate(5, &mut r);
        assert_eq!(
            mgr.rekey(stale),
            Err(RekeyError::NonMonotonic { current: 5, got: 5 })
        );
    }

    #[test]
    fn wrong_epoch_is_reported() {
        let mut r = rng(7);
        let mut m = group(2, 1, &mut r);
        let mut mgr = m.remove(0);
        let tag = MessageTag {
            epoch: 9,
            nonce: Nonce([0u8; crate::pprf::NONCE_LEN]),
        };
        assert_eq!(
            mgr.open(&tag),
            Err(OpenError::WrongEpoch {
                expected: 2,
                got: 9
            })
        );
    }
}
