//! **e2a — content-layer group crypto for the modified Signal client.**
//!
//! Personas posts must be *unattributable within the group*: any member can post,
//! recipients learn only the persona (from the ZK payload), never which account or
//! which other post came from the same author. Signal carries authorship in two
//! layers — a per-member sender-key signature (content layer) and a per-account
//! sealed-sender certificate (delivery layer). This crate neutralises the first;
//! e2c's sealed sender under a shared phantom certificate neutralises the second.
//!
//! The scheme (locked in review — see `docs/SERVERLESS_SIGNAL_DESIGN.md` and the
//! project plan):
//!
//! - **K2 — a freshly generated, deletable shared group secret.** One member
//!   samples `Sᵢ` per epoch and distributes it over the pairwise Double Ratchet.
//!   Every member derives `K_epoch = HKDF(Sᵢ, epoch)` and then *deletes `Sᵢ`*. It
//!   is deliberately **not** derived from the persistent `GroupMasterKey` (that
//!   could never be deleted, so a device compromise would recompute every epoch
//!   key un-punctured and negate forward secrecy).
//! - **GGM puncturable-PRF message keys.** Each message carries a random nonce;
//!   `mk = PPRF.Eval(K_epoch, nonce)`, punctured on consume. Random nonces make
//!   concurrent sends collision-free (the stock shared-counter hazard), and
//!   puncturing gives genuine within-epoch forward secrecy that is reorder-safe
//!   (commutative, per-consumer).
//!
//! This crate is transport-, async-, and arkworks-free on purpose: it is the unit
//! the e2a crypto sign-off audits. The AEAD over the `PersonaEnvelope` under the
//! [`MessageKey`] and the ZK verify are e2b; sealed-sender delivery is e2c.
//!
//! # Shape of the API
//!
//! [`GroupSecret`] is the K2 secret; [`KeyManager`] is one member's per-epoch view
//! of the schedule. [`KeyManager::seal`] is the send path (→ [`MessageTag`] +
//! [`MessageKey`]), [`KeyManager::open`] the receive path, [`KeyManager::rekey`]
//! the cadence hook. The underlying primitive lives in [`pprf`].

pub mod group;
mod kdf;
pub mod pprf;

pub use group::{
    DistributedSecret, GroupSecret, KeyManager, MessageKey, MessageTag, OpenError, RekeyError,
};
pub use pprf::{DEPTH, NONCE_LEN, Nonce, PrfOutput, PuncturableKey};

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// End-to-end e2a harness: a group forms, several members post concurrently,
    /// and every member ingests every post in a *different* order yet derives the
    /// same key for each — the reorder-convergence property the serverless setting
    /// needs. No network, no libsignal: pairwise distribution is modeled by handing
    /// each member the same `DistributedSecret`.
    #[test]
    fn group_converges_under_reordered_delivery() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xE2A_0000);
        const N: usize = 5;

        // 1. Creator distributes a fresh epoch-0 secret over "pairwise".
        let secret = GroupSecret::generate(0, &mut rng);
        let wire = secret.to_wire();
        let mut members: Vec<KeyManager> = (0..N)
            .map(|_| KeyManager::install(GroupSecret::from_wire(wire.clone())))
            .collect();
        drop(secret); // creator deletes Sᵢ after distributing

        // 2. Every member posts one message: (tag, expected key).
        let mut posts: Vec<(MessageTag, MessageKey)> = Vec::new();
        for m in members.iter_mut() {
            posts.push(m.seal(&mut rng));
        }

        // 3. Each member opens all posts (including, effectively, echoes of its own)
        //    in a rotated order. Every member must recover every sender's key.
        for (i, m) in members.iter_mut().enumerate() {
            for k in 0..N {
                let (tag, expected) = &posts[(i + k) % N];
                if m.is_available(tag) {
                    assert_eq!(&m.open(tag).unwrap(), expected);
                } else {
                    // The member's own message: already punctured on seal. Its key
                    // is unrecoverable — that is the sender-side FS, not a bug.
                    assert_eq!(m.open(tag), Err(OpenError::Consumed));
                }
            }
        }

        // 4. After everyone consumed everything, all keys are punctured everywhere.
        for m in &members {
            for (tag, _) in &posts {
                assert!(!m.is_available(tag));
            }
        }
    }

    /// A member outside the group (a different secret) derives different keys, so it
    /// can neither read nor forge readable posts — content-layer confidentiality
    /// with no shared `Sᵢ`. (Full non-member *forgery* rejection is the ZK layer's
    /// job in e2b; this is the key-secrecy half.)
    #[test]
    fn outsider_without_the_secret_derives_different_keys() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xE2A_0001);
        let insider_secret = GroupSecret::generate(0, &mut rng);
        let mut insider = KeyManager::install(GroupSecret::from_wire(insider_secret.to_wire()));

        let outsider_secret = GroupSecret::generate(0, &mut rng);
        let mut outsider = KeyManager::install(outsider_secret);

        let (tag, insider_key) = insider.seal(&mut rng);
        // Same epoch + nonce, different Sᵢ ⇒ different key.
        let outsider_key = outsider.open(&tag).unwrap();
        assert_ne!(insider_key, outsider_key);
    }
}
