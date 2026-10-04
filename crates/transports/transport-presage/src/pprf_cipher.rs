//! Phase A2 content cipher — the K2/PPRF per-message key (design doc §5).
//!
//! This replaces [`content_cipher`](crate::content_cipher)'s Phase A1 static shared
//! `SenderKeyRecord` with `e2a`'s [`KeyManager`](personas_group_crypto::KeyManager)
//! schedule: a freshly generated, deletable group secret `Sᵢ` seeds a puncturable PRF,
//! and every message gets its own single-use key derived from a random nonce and
//! punctured the moment it is sealed or opened. That lifts the two Phase A1
//! limitations recorded in `content_cipher`'s module docs:
//!
//! - **Concurrency.** A1 shared one hash-ratcheted chain, so two members sending
//!   before seeing each other collided on the same chain iteration and the second
//!   message was dropped. Here every message key is indexed by an independently
//!   random nonce, so concurrent sends from different members essentially never
//!   collide (`e2a`'s `concurrent_sends_do_not_collide`), and both are readable
//!   regardless of delivery order.
//! - **Forward secrecy.** A1 had no per-message puncture and no deletable epoch
//!   secret — only the sender chain's ordinary hash-ratchet. Here `mk` is punctured
//!   on both the sender's and each receiver's side the moment it is used (even the
//!   sender cannot recover it afterward), and `Sᵢ` itself is never retained past
//!   `KeyManager::install` — see `personas_group_crypto::group` for the forward-
//!   secrecy argument in full.
//!
//! # What this module does *not* yet do
//!
//! - **Distribution of `Sᵢ`.** [`create`](PprfContentCipher::create) hands back the
//!   [`DistributedSecret`] wire bytes the same way `content_cipher::GroupContentCipher
//!   ::create` hands back a [`SharedSenderKey`](crate::content_cipher::SharedSenderKey)
//!   — for the caller to distribute out of band. Real per-member delivery over the
//!   pairwise Double Ratchet is **e2c**, not this module; today, as with A1, it is
//!   the caller's job (in the account-gated examples, the same in-process handoff
//!   A1 uses).
//! - **Re-key triggers.** [`rekey`](PprfContentCipher::rekey) exposes the mechanism;
//!   *deciding when* to call it (epoch boundary, ban, leave, or a time/message-count
//!   cadence) is **e2d**, wired from the replica's/messenger's event stream, not here.
//! - **Delivery under a phantom certificate.** This module only replaces the
//!   *content* key. It still rides inside the same real-per-account sealed-sender
//!   delivery `PresageTransport` already uses (B1); the shared phantom certificate
//!   (B2/D1) is a separate, delivery-layer change.
//!
//! # AEAD choice
//!
//! `mk` (32 bytes, single-use) keys AES-256-GCM-SIV. Because `mk` is never reused —
//! it is punctured at the moment it is consumed, on both the seal and the open side —
//! a fixed AEAD nonce is safe: the (key, nonce) pair never repeats, which is the
//! property AEAD security actually requires. This is flagged as a design-doc §10
//! sign-off item ("confirm the AEAD primitive choice"); AES-256-GCM-SIV specifically
//! is misuse-resistant even in the event that assumption is ever violated by a future
//! bug, which is why it — rather than plain AES-GCM — is used here.
//!
//! # Wire format
//!
//! `[epoch: u64 LE][nonce: NONCE_LEN bytes][AEAD ciphertext]` — the [`MessageTag`]
//! (epoch + nonce) travels in the clear beside the ciphertext, exactly as design doc
//! §5 specifies ("Each message carries `MessageTag {epoch, nonce}` in the clear
//! beside the ciphertext"). It carries no secret: the nonce indexes the key, it is
//! not the key.

use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::{Aes256GcmSiv, Key, KeyInit, Nonce as AeadNonce};
use anyhow::{Context, Result, bail};
use personas_group_crypto::{
    DistributedSecret, GroupSecret, KeyManager, MessageTag, NONCE_LEN, Nonce, OpenError,
    RekeyError,
};

/// `MessageTag`'s wire header size: an 8-byte little-endian epoch plus the PPRF nonce.
const HEADER_LEN: usize = 8 + NONCE_LEN;

/// AES-256-GCM-SIV's nonce size. Fixed and all-zero — see the module doc's AEAD
/// section for why that is safe here (the AEAD key `mk` is single-use by construction).
const AEAD_NONCE: [u8; 12] = [0u8; 12];

/// One member's view of the PPRF content cipher for the current epoch.
///
/// Wraps a [`KeyManager`]; [`encrypt`](Self::encrypt) and [`decrypt`](Self::decrypt)
/// turn opaque plaintext bytes into a `{MessageTag, AEAD ciphertext}` wire payload and
/// back, mirroring [`content_cipher::GroupContentCipher`](crate::content_cipher::GroupContentCipher)'s
/// shape so `lib.rs`'s actor changes minimally.
pub struct PprfContentCipher {
    keys: KeyManager,
}

impl PprfContentCipher {
    /// Create the group's first secret, at epoch 0.
    ///
    /// Returns the creator's cipher (ready to send immediately) plus the
    /// [`DistributedSecret`] wire form to hand to every other member — over the
    /// pairwise Double Ratchet in the live client (e2c); the caller distributes it,
    /// this module does not.
    pub fn create(rng: &mut impl rand08::RngCore) -> (Self, DistributedSecret) {
        let secret = GroupSecret::generate(0, rng);
        let wire = secret.to_wire();
        (
            Self {
                keys: KeyManager::install(secret),
            },
            wire,
        )
    }

    /// Install a [`DistributedSecret`] received (decrypted, over the pairwise
    /// channel) from the group's creator or a re-keyer.
    pub fn install(wire: DistributedSecret) -> Self {
        Self {
            keys: KeyManager::install(GroupSecret::from_wire(wire)),
        }
    }

    /// The epoch this cipher currently has installed.
    pub fn epoch(&self) -> u64 {
        self.keys.epoch()
    }

    /// Generate the *next* epoch's secret and install it locally, deleting the
    /// current epoch's key schedule wholesale.
    ///
    /// Returns the [`DistributedSecret`] wire form to distribute to every other
    /// member the same way [`create`](Self::create)'s does. This is only the
    /// mechanism — *deciding when* to call it (epoch boundary, ban, leave, a
    /// time/message-count cadence) is e2d, not this module.
    pub fn rekey(&mut self, rng: &mut impl rand08::RngCore) -> Result<DistributedSecret, RekeyError> {
        let next_epoch = self.keys.epoch() + 1;
        let secret = GroupSecret::generate(next_epoch, rng);
        let wire = secret.to_wire();
        self.keys.rekey(secret)?;
        Ok(wire)
    }

    /// Install a re-key [`DistributedSecret`] received from whoever generated it.
    pub fn install_rekey(&mut self, wire: DistributedSecret) -> Result<(), RekeyError> {
        self.keys.rekey(GroupSecret::from_wire(wire))
    }

    /// Encrypt opaque plaintext bytes into a wire payload.
    ///
    /// Derives a fresh, single-use `mk` from a random nonce, punctures it (even this
    /// sender cannot recover it afterward — forward secrecy holds immediately, not
    /// only after delivery), AEAD-seals under `mk`, and prepends the `MessageTag` the
    /// wire format specifies.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut rng = rand08::rngs::OsRng;
        let (tag, mk) = self.keys.seal(&mut rng);

        let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(mk.as_bytes()));
        let ciphertext = cipher
            .encrypt(AeadNonce::from_slice(&AEAD_NONCE), plaintext)
            .map_err(|e| anyhow::anyhow!("AEAD seal under the single-use message key: {e}"))?;

        Ok(encode_wire(&tag, &ciphertext))
    }

    /// Decrypt a wire payload back to the opaque plaintext bytes.
    ///
    /// Re-derives `mk` from the tag's epoch/nonce and punctures it — a second
    /// decrypt of the same tag (replay, or a message this member already processed)
    /// fails with [`OpenError::Consumed`], and a tag from a since-rotated-away epoch
    /// fails with [`OpenError::WrongEpoch`]; both are forward-secrecy properties, not
    /// bugs. The recovered bytes are handed to `Replica::ingest` by the messenger,
    /// exactly as in Phase A1 — this cipher only removes the Signal layer.
    pub fn decrypt(&mut self, wire: &[u8]) -> Result<Vec<u8>> {
        let (tag, ciphertext) = decode_wire(wire)?;
        let mk = self
            .keys
            .open(&tag)
            .map_err(pprf_open_error_context)?;

        let cipher = Aes256GcmSiv::new(Key::<Aes256GcmSiv>::from_slice(mk.as_bytes()));
        cipher
            .decrypt(AeadNonce::from_slice(&AEAD_NONCE), ciphertext)
            .map_err(|e| anyhow::anyhow!("AEAD open under mk (tampered, foreign, or wrong-key ciphertext): {e}"))
    }
}

/// Turn an [`OpenError`] into an `anyhow::Error` that keeps the two forward-secrecy
/// outcomes ([`OpenError::WrongEpoch`], [`OpenError::Consumed`]) distinguishable from
/// an actual AEAD failure, since a caller may want to treat them differently (both
/// are "silently drop this message", not "the group secret is wrong").
fn pprf_open_error_context(err: OpenError) -> anyhow::Error {
    anyhow::Error::new(err).context("deriving the message key from the wire MessageTag")
}

fn encode_wire(tag: &MessageTag, ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&tag.epoch.to_le_bytes());
    out.extend_from_slice(&tag.nonce.0);
    out.extend_from_slice(ciphertext);
    out
}

fn decode_wire(wire: &[u8]) -> Result<(MessageTag, &[u8])> {
    if wire.len() < HEADER_LEN {
        bail!(
            "wire payload ({} bytes) is shorter than a MessageTag header ({HEADER_LEN} bytes)",
            wire.len()
        );
    }
    let (epoch_bytes, rest) = wire.split_at(8);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);

    let epoch = u64::from_le_bytes(
        epoch_bytes
            .try_into()
            .context("epoch header is exactly 8 bytes by construction")?,
    );
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(nonce_bytes);

    Ok((
        MessageTag {
            epoch,
            nonce: Nonce(nonce),
        },
        ciphertext,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng() -> rand08::rngs::mock::StepRng {
        // Deterministic in tests only; production paths use `OsRng` (see `encrypt`).
        rand08::rngs::mock::StepRng::new(0x1234_5678_9abc_def0, 0x9e37_79b9_7f4a_7c15)
    }

    /// The core round trip: creator shares `Sᵢ`, another member installs it, and a
    /// message encrypted by the creator decrypts back to the same bytes.
    #[test]
    fn create_install_encrypt_decrypt_roundtrip() {
        let (mut creator, wire) = PprfContentCipher::create(&mut rng());
        let mut member = PprfContentCipher::install(wire);

        let plaintext = b"opaque record bytes";
        let wire_msg = creator.encrypt(plaintext).unwrap();
        assert_ne!(wire_msg.as_slice(), plaintext.as_slice());

        let recovered = member.decrypt(&wire_msg).unwrap();
        assert_eq!(recovered, plaintext);
    }

    /// The A2 crux: unlike A1's shared hash-ratchet, two members sending before
    /// seeing each other do **not** collide — each gets an independently random
    /// nonce, so both are decryptable regardless of order.
    #[test]
    fn concurrent_sends_do_not_collide() {
        let mut r = rng();
        let (creator, wire) = PprfContentCipher::create(&mut r);
        let mut alice = creator;
        let mut bob = PprfContentCipher::install(wire.clone());
        let mut carol = PprfContentCipher::install(wire);

        let from_alice = alice.encrypt(b"concurrent A").unwrap();
        let from_bob = bob.encrypt(b"concurrent B").unwrap();

        // Both decrypt, in either order — no dropped message, unlike A1.
        assert_eq!(carol.decrypt(&from_bob).unwrap(), b"concurrent B");
        assert_eq!(carol.decrypt(&from_alice).unwrap(), b"concurrent A");
    }

    /// A tag's key is punctured the moment it's consumed — replaying the same wire
    /// payload at a second recipient-side decrypt must fail, not silently re-decrypt.
    #[test]
    fn replaying_a_consumed_tag_fails() {
        let (mut creator, wire) = PprfContentCipher::create(&mut rng());
        let mut member = PprfContentCipher::install(wire);

        let wire_msg = creator.encrypt(b"once").unwrap();
        assert_eq!(member.decrypt(&wire_msg).unwrap(), b"once");
        assert!(
            member.decrypt(&wire_msg).is_err(),
            "a second decrypt of the same wire payload must fail — the key was punctured on first open"
        );
    }

    /// After a re-key, a message sealed under the old epoch can no longer be opened —
    /// content-layer exclusion, the property A1 explicitly lacked.
    #[test]
    fn rekey_excludes_the_old_epoch() {
        let mut r = rng();
        let (mut creator, wire) = PprfContentCipher::create(&mut r);
        let mut member = PprfContentCipher::install(wire);

        let stale = creator.encrypt(b"before the rekey").unwrap();

        let rekey_wire = creator.rekey(&mut r).unwrap();
        member.install_rekey(rekey_wire).unwrap();

        assert!(
            member.decrypt(&stale).is_err(),
            "a message from the deleted epoch must not decrypt after rekey"
        );

        let fresh = creator.encrypt(b"after the rekey").unwrap();
        assert_eq!(member.decrypt(&fresh).unwrap(), b"after the rekey");
    }

    /// A tampered ciphertext must fail AEAD authentication, not silently decrypt.
    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut creator, wire) = PprfContentCipher::create(&mut rng());
        let mut member = PprfContentCipher::install(wire);

        let mut wire_msg = creator.encrypt(b"authentic").unwrap();
        *wire_msg.last_mut().unwrap() ^= 0xff;

        assert!(member.decrypt(&wire_msg).is_err());
    }
}
