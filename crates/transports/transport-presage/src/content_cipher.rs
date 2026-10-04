//! Phase A1 content cipher — the **static shared sender key** (design doc §4).
//!
//! This is the first half of the e2 content-layer modification, built entirely
//! **in-process against real libsignal, with no network** (like `e2a`, this is
//! Layer-0 work — not the account/staging path that is sign-off-gated). It drives
//! libsignal's group cipher directly rather than presage's account-oriented
//! `Manager`, exactly as libsignal's own group tests do: sessions between in-memory
//! stores, no registration.
//!
//! # What A1 changes about Signal group messaging
//!
//! Stock Signal gives every member *their own* sender key — a symmetric chain key
//! **plus a per-member Curve25519 signing key pair** — and every group message is
//! signed under the sender's private key, so recipients can attribute it. Phase A1
//! removes attribution by giving the whole group **one** [`SenderKeyRecord`]: one
//! chain key and one signing key pair, distributed as **full private state** to
//! every member. Because the private signing half is shared, *every* member can
//! send under the single key, and no recipient can tell which member signed — the
//! anonymity property we need. Authorisation is unaffected: it lives entirely in
//! the Groth16 proof the receiving replica checks before rendering (design doc §7),
//! never in the Signal signature.
//!
//! This is *more* than stock Signal's [`SenderKeyDistributionMessage`], which
//! conveys only the **public** signing key: an SKDM recipient can decrypt but
//! cannot sign, so it cannot send under the shared key. That distinction is the
//! reason we distribute the serialised record rather than an SKDM, and it is pinned
//! by a characterisation test below (`skdm_recipient_can_read_but_cannot_send`).
//!
//! # Layering
//!
//! This cipher operates on **opaque plaintext bytes**. It has no knowledge of the
//! personas `Record`: the messenger hands it record bytes and it hands back Signal
//! ciphertext (and vice versa). That keeps the transport doing Signal crypto on
//! bytes and the replica/messenger doing personas semantics, matching the stack in
//! design doc §2. A convergence test where those bytes are real `Record`s feeding
//! `Replica::ingest` is a deliberately separate follow-on (it would pull the
//! bulletin/messenger crates in and belongs at that layer).
//!
//! # Accepted Phase A1 limitations (lifted in Phase A2's K2/PPRF rework)
//!
//! - **Concurrency.** All members share one chain. Two members who both send before
//!   seeing each other's message advance to the same iteration and derive the same
//!   message key; libsignal drops the second as a `DuplicatedMessage`. A1 therefore
//!   assumes low-rate, effectively serial posting — each message reaches everyone
//!   before the next is sent. Pinned by `concurrent_send_at_same_iteration_is_dropped`.
//! - **No rotation.** A banned member who keeps the shared key can still *read* new
//!   content at the Signal layer; their authorisation is still revoked at the proof
//!   layer. Content-layer read exclusion is an A2 re-key property.
//! - **Forward secrecy** is only the sender chain's hash ratchet — no per-message
//!   puncture, no epoch-secret deletion. Genuine FS is an A2 property.

use anyhow::{Context, Result};
use libsignal_protocol::{
    DeviceId, InMemSenderKeyStore, ProtocolAddress, SenderKeyRecord, SenderKeyStore,
    create_sender_key_distribution_message, group_decrypt, group_encrypt,
};
use rand::TryRngCore as _;
use rand::rngs::OsRng;
use uuid::Uuid;

/// The `(sender, distribution_id)` pair every member keys the shared record by.
///
/// These are **not secret** — they are the shared store coordinates, analogous to a
/// group id. The secret is the [`SenderKeyRecord`] itself ([`SharedSenderKey`]). A
/// "phantom" address matches the delivery-layer phantom identity (design doc §6);
/// keeping it constant is sufficient for A1. A future deployment could randomise the
/// distribution id per group and share it out of band — a one-line change here.
const PHANTOM_NAME: &str = "personas.phantom";
const DISTRIBUTION_ID: Uuid = Uuid::from_u128(0x9e2a_0001_7000_11f0_b32a_0da5_c0ff_ee11);

/// The phantom sender address the shared record is stored under. Constant across
/// members (see [`DISTRIBUTION_ID`]).
fn phantom_address() -> ProtocolAddress {
    ProtocolAddress::new(
        PHANTOM_NAME.to_owned(),
        DeviceId::new(1).expect("device id 1 is valid"),
    )
}

/// An OS-backed CSPRNG satisfying libsignal's `Rng + CryptoRng` (rand 0.9).
///
/// In rand 0.9 `OsRng` is only a *fallible* `TryRngCore`; `unwrap_err()` adapts it to
/// the infallible `RngCore` the group cipher requires (the idiom libsignal's own
/// tests use). OS randomness cannot realistically fail, so the unwrap never panics.
fn csprng() -> impl rand::Rng + rand::CryptoRng {
    OsRng.unwrap_err()
}

/// The shared group sender key in serialised, distributable form.
///
/// This is the **full private state** of the one [`SenderKeyRecord`] — chain key
/// *and* private signing key — so any holder can both read and send. In A1 the group
/// creator produces it with [`GroupContentCipher::create`] and distributes these
/// bytes to every member over their pairwise Double Ratchet session (modelled
/// in-process here by handing the bytes across; real pairwise distribution is e2c).
/// Treat it as sensitive key material: whoever holds it can send as the group.
#[derive(Clone)]
pub struct SharedSenderKey(Vec<u8>);

impl SharedSenderKey {
    /// The serialised record bytes, to distribute over a pairwise session.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Reconstruct from bytes received over a pairwise session.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
}

impl core::fmt::Debug for SharedSenderKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print the key material — it holds the private signing key.
        write!(f, "SharedSenderKey({} bytes, redacted)", self.0.len())
    }
}

/// One member's view of the shared-sender-key content cipher.
///
/// Wraps that member's in-memory sender-key store, which — after [`create`] or
/// [`install`] — holds the single shared record. [`encrypt`] and [`decrypt`]
/// turn opaque plaintext bytes into Signal group ciphertext and back.
///
/// [`create`]: GroupContentCipher::create
/// [`install`]: GroupContentCipher::install
/// [`encrypt`]: GroupContentCipher::encrypt
/// [`decrypt`]: GroupContentCipher::decrypt
pub struct GroupContentCipher {
    store: InMemSenderKeyStore,
}

impl GroupContentCipher {
    /// Create the group's shared sender key.
    ///
    /// Generates one fresh [`SenderKeyRecord`] (chain key + signing key pair) and
    /// returns the creator's cipher plus the [`SharedSenderKey`] to distribute to
    /// every other member. The creator can send immediately.
    pub async fn create() -> Result<(Self, SharedSenderKey)> {
        let mut store = InMemSenderKeyStore::new();
        let sender = phantom_address();
        let mut rng = csprng();

        // Populate the store with a fresh record. We distribute the record's full
        // private state (below), not this SKDM — the SKDM carries only the public
        // signing key, so an SKDM-only recipient could not send.
        create_sender_key_distribution_message(&sender, DISTRIBUTION_ID, &mut store, &mut rng)
            .await
            .context("generating the shared sender key")?;

        let record = store
            .load_sender_key(&sender, DISTRIBUTION_ID)
            .await
            .context("loading the freshly created sender key")?
            .context("sender key missing immediately after creation")?;
        let shared = SharedSenderKey(
            record
                .serialize()
                .context("serialising the shared record")?,
        );

        Ok((Self { store }, shared))
    }

    /// Install a [`SharedSenderKey`] received from the group creator.
    ///
    /// After this the member holds the identical full record and can both read and
    /// send under the shared key.
    pub async fn install(shared: &SharedSenderKey) -> Result<Self> {
        let record =
            SenderKeyRecord::deserialize(shared.as_bytes()).context("deserialising shared key")?;
        let mut store = InMemSenderKeyStore::new();
        store
            .store_sender_key(&phantom_address(), DISTRIBUTION_ID, &record)
            .await
            .context("installing the shared sender key")?;
        Ok(Self { store })
    }

    /// Encrypt opaque plaintext bytes into a wire payload (a serialised
    /// `SenderKeyMessage`).
    ///
    /// Signs under the shared signing key and advances the shared chain by one
    /// iteration. The caller (messenger) supplies record bytes and broadcasts the
    /// returned bytes; the sender does not decrypt its own echo (it already holds
    /// the plaintext).
    pub async fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut rng = csprng();
        let skm = group_encrypt(
            &mut self.store,
            &phantom_address(),
            DISTRIBUTION_ID,
            plaintext,
            &mut rng,
        )
        .await
        .context("group_encrypt under the shared sender key")?;
        Ok(skm.serialized().to_vec())
    }

    /// Decrypt a wire payload back to the opaque plaintext bytes.
    ///
    /// The recovered bytes are handed to `Replica::ingest` (decode + Groth16-verify +
    /// fold) by the messenger — this cipher only removes the Signal layer.
    pub async fn decrypt(&mut self, wire: &[u8]) -> Result<Vec<u8>> {
        group_decrypt(wire, &mut self.store, &phantom_address())
            .await
            .context("group_decrypt under the shared sender key")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The core round trip: creator shares the key, another member installs it, and
    /// a message encrypted by the creator decrypts back to the same bytes.
    #[tokio::test]
    async fn create_share_encrypt_decrypt_roundtrip() {
        let (mut creator, shared) = GroupContentCipher::create().await.unwrap();
        let mut member = GroupContentCipher::install(&shared).await.unwrap();

        let plaintext = b"opaque record bytes";
        let wire = creator.encrypt(plaintext).await.unwrap();
        // The wire payload is not the plaintext (it is signed + AES-CBC ciphertext).
        assert_ne!(wire.as_slice(), plaintext.as_slice());

        let recovered = member.decrypt(&wire).await.unwrap();
        assert_eq!(recovered, plaintext);
    }

    /// The A1 crux: because full private state is distributed, *every* member can
    /// send, not just the creator. A message authored by an installed member
    /// decrypts at the creator and at other members.
    #[tokio::test]
    async fn every_member_can_send_under_the_shared_key() {
        let (mut creator, shared) = GroupContentCipher::create().await.unwrap();
        let mut alice = GroupContentCipher::install(&shared).await.unwrap();
        let mut bob = GroupContentCipher::install(&shared).await.unwrap();

        // Alice (an installed member, not the creator) sends.
        let plaintext = b"a post from alice";
        let wire = alice.encrypt(plaintext).await.unwrap();

        // Both the creator and another member decrypt it — attribution is gone, but
        // authorisation (checked elsewhere, at the proof layer) is unaffected.
        assert_eq!(creator.decrypt(&wire).await.unwrap(), plaintext);
        assert_eq!(bob.decrypt(&wire).await.unwrap(), plaintext);
    }

    /// A serial broadcast among N members converges: each member takes a turn
    /// sending; the message is delivered to everyone *except* the sender (who does
    /// not decrypt its own echo) before the next send. This is the A1 usage the
    /// design assumes.
    #[tokio::test]
    async fn serial_broadcast_keeps_every_member_in_lockstep() {
        let (creator, shared) = GroupContentCipher::create().await.unwrap();
        let mut members = vec![creator];
        for _ in 0..3 {
            members.push(GroupContentCipher::install(&shared).await.unwrap());
        }

        let posts = [
            b"m0".as_slice(),
            b"m1".as_slice(),
            b"m2".as_slice(),
            b"m3".as_slice(),
        ];
        for (sender_idx, post) in posts.iter().enumerate() {
            let wire = members[sender_idx].encrypt(post).await.unwrap();
            for (recipient_idx, recipient) in members.iter_mut().enumerate() {
                if recipient_idx == sender_idx {
                    continue; // sender does not decrypt its own echo
                }
                let recovered = recipient.decrypt(&wire).await.unwrap();
                assert_eq!(
                    &recovered.as_slice(),
                    post,
                    "member {recipient_idx} diverged"
                );
            }
        }
    }

    /// Documents the accepted A1 concurrency limitation (design doc §4). Two members
    /// who both send while still at the same chain iteration produce two messages at
    /// that iteration; a recipient decrypts the first and libsignal drops the second
    /// as a duplicate. A2's per-message keys remove this.
    #[tokio::test]
    async fn concurrent_send_at_same_iteration_is_dropped() {
        let (_creator, shared) = GroupContentCipher::create().await.unwrap();
        let mut alice = GroupContentCipher::install(&shared).await.unwrap();
        let mut bob = GroupContentCipher::install(&shared).await.unwrap();
        let mut carol = GroupContentCipher::install(&shared).await.unwrap();

        // Alice and Bob both send before seeing each other — both at iteration 0.
        let from_alice = alice.encrypt(b"concurrent A").await.unwrap();
        let from_bob = bob.encrypt(b"concurrent B").await.unwrap();

        // Carol decrypts the first message fine...
        assert_eq!(carol.decrypt(&from_alice).await.unwrap(), b"concurrent A");
        // ...but the second, at the same iteration, is dropped.
        assert!(
            carol.decrypt(&from_bob).await.is_err(),
            "the second concurrent message at the same iteration must be dropped in A1"
        );
    }

    /// Why we distribute the full record and not an SKDM: a member who only
    /// *processed* a `SenderKeyDistributionMessage` (public signing key only) can
    /// **read** but cannot **send**. Raw-libsignal characterisation of the design
    /// decision behind [`SharedSenderKey`] carrying full private state.
    #[tokio::test]
    async fn skdm_recipient_can_read_but_cannot_send() {
        use libsignal_protocol::{
            SenderKeyDistributionMessage, process_sender_key_distribution_message,
        };

        let sender = phantom_address();
        let mut rng = csprng();

        // Creator makes the key and its SKDM (public half only).
        let mut creator_store = InMemSenderKeyStore::new();
        let skdm = create_sender_key_distribution_message(
            &sender,
            DISTRIBUTION_ID,
            &mut creator_store,
            &mut rng,
        )
        .await
        .unwrap();

        // A recipient processes the SKDM into its own store.
        let mut skdm_store = InMemSenderKeyStore::new();
        let recv = SenderKeyDistributionMessage::try_from(skdm.serialized()).unwrap();
        process_sender_key_distribution_message(&sender, &recv, &mut skdm_store)
            .await
            .unwrap();

        // The creator sends; the SKDM recipient can READ it.
        let wire = group_encrypt(
            &mut creator_store,
            &sender,
            DISTRIBUTION_ID,
            b"readable",
            &mut rng,
        )
        .await
        .unwrap();
        let read = group_decrypt(wire.serialized(), &mut skdm_store, &sender)
            .await
            .unwrap();
        assert_eq!(read, b"readable");

        // But the SKDM recipient CANNOT send — it holds no private signing key.
        let cannot_send = group_encrypt(
            &mut skdm_store,
            &sender,
            DISTRIBUTION_ID,
            b"forbidden",
            &mut rng,
        )
        .await;
        assert!(
            cannot_send.is_err(),
            "an SKDM-only member must not be able to send — that is why A1 shares full private state"
        );
    }
}
