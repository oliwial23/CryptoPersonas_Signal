//! Late join by snapshot, TOFU-pinned to your inviter (workstream **d4**).
//!
//! A member added to a Signal group **cannot read its history**
//! (`SERVERLESS_PROTOCOL.md` §12), so a joiner cannot replay the log and cannot
//! compute the roots — and therefore can neither make a proof anyone accepts nor
//! check one. A [`Snapshot`] is the bridge, and §12 is honest that it is the weakest
//! part of the design.
//!
//! # This realises §12 as a record-log replay
//!
//! §12 describes a snapshot as "an epoch, the object and callback roots, the
//! nullifier set, the called set, the open tallies." In this codebase the replica
//! **derives** all of those from the record log (d3), so the faithful snapshot is
//! the log itself: the `(first_barrier, bytes)` of every seen record, plus the
//! barrier it was taken at. The joiner feeds them to
//! [`Replica::from_records`](personas_bulletin::replica::Replica::from_records) and
//! **re-derives the roots itself**. This is strictly better than trusting
//! peer-supplied roots:
//!
//! - **Not a soundness break (§12).** A forged snapshot cannot make the joiner
//!   accept a forged proof — the proof still has to verify against roots the joiner
//!   computed from the snapshot's records, and a root the group does not share makes
//!   the *joiner's own* later proofs unacceptable to everyone, loudly.
//! - **It is a view-integrity assumption.** A forged snapshot can omit a post or
//!   show a banned member as unbanned. Nothing cryptographic prevents that; §12's
//!   answer is **trust-on-first-use over your inviter**, pinned to a genesis digest
//!   carried out-of-band with the invitation (the shape of a Signal safety number).
//!
//! [`digest`](Snapshot::digest) is that pin: the inviter shares
//! [`digest_hex`](Snapshot::digest_hex) out of band, and [`Snapshot::verify`]
//! refuses a snapshot that does not hash to it — closing the in-transit tampering
//! gap, so the residual trust is exactly "my inviter vouched for this state," no more.

use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};

use personas_bulletin::replica::record::{Eh, SERVERLESS_VERSION};

/// One record in a snapshot: its bytes and the barrier the source replica first saw
/// it at (which the joiner must reproduce, §5.2 determinism caveat).
#[derive(Clone, Serialize, Deserialize)]
pub struct SnapshotRecord {
    pub first_barrier: u64,
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
}

/// A replica checkpoint a late joiner adopts: the whole seen record log in canonical
/// order, plus the barrier it was taken at.
#[derive(Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// The serverless protocol version, so a joiner refuses a snapshot it cannot read.
    pub version: u16,
    /// The barrier the source replica had reached (settlement timing depends on it).
    pub barrier: u64,
    /// Every seen record, in ascending-`eh` order.
    pub records: Vec<SnapshotRecord>,
}

/// A snapshot could not be adopted.
#[derive(Debug, thiserror::Error)]
pub enum AdoptError {
    #[error("snapshot is version {found}, this build speaks version {expected}")]
    Version { found: u16, expected: u16 },
    #[error(
        "snapshot does not match the pinned genesis digest — refusing (tampering in transit, or the wrong group)"
    )]
    GenesisMismatch,
    #[error("could not decode snapshot: {0}")]
    Decode(String),
}

impl Snapshot {
    /// Build a snapshot from a replica's seen records and current barrier. `records`
    /// must be in canonical (ascending-`eh`) order — which
    /// [`Replica::seen_with_barriers`](personas_bulletin::replica::Replica::seen_with_barriers)
    /// guarantees — so the [`digest`](Self::digest) is stable across replicas.
    pub fn new(records: Vec<(u64, Vec<u8>)>, barrier: u64) -> Self {
        Self {
            version: SERVERLESS_VERSION,
            barrier,
            records: records
                .into_iter()
                .map(|(first_barrier, bytes)| SnapshotRecord {
                    first_barrier,
                    bytes,
                })
                .collect(),
        }
    }

    /// The genesis pin: a collision-resistant digest over the version, barrier, and
    /// every record (by content-address, in order). This is what an inviter shares
    /// out-of-band and what [`verify`](Self::verify) checks. Reordering, adding, or
    /// dropping any record changes it.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Blake2s256::new();
        h.update(b"personas/snapshot/v1");
        h.update(self.version.to_le_bytes());
        h.update(self.barrier.to_le_bytes());
        h.update((self.records.len() as u64).to_le_bytes());
        for r in &self.records {
            h.update(r.first_barrier.to_le_bytes());
            // Content-address each record so the pin binds the bytes, not their offset.
            h.update(Eh::of_bytes(&r.bytes).0);
        }
        h.finalize().into()
    }

    /// The genesis pin as a lower-hex string, for out-of-band sharing (the "safety
    /// number" a joiner compares against, §12).
    pub fn digest_hex(&self) -> String {
        let d = self.digest();
        let mut s = String::with_capacity(64);
        for b in d {
            s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
        }
        s
    }

    /// Check the version and the genesis pin. `expected` is the digest the inviter
    /// vouched for out-of-band; a mismatch means the snapshot was tampered with in
    /// transit or is for the wrong group, and is refused.
    pub fn verify(&self, expected: &[u8; 32]) -> Result<(), AdoptError> {
        if self.version != SERVERLESS_VERSION {
            return Err(AdoptError::Version {
                found: self.version,
                expected: SERVERLESS_VERSION,
            });
        }
        // Constant-time compare is not needed (this is a public integrity pin, not a
        // secret), but equality is the whole check.
        if self.digest() != *expected {
            return Err(AdoptError::GenesisMismatch);
        }
        Ok(())
    }

    /// The `(first_barrier, bytes)` list a replica rebuilds from.
    pub fn into_records(self) -> Vec<(u64, Vec<u8>)> {
        self.records
            .into_iter()
            .map(|r| (r.first_barrier, r.bytes))
            .collect()
    }

    /// Encode for out-of-band transfer (CBOR).
    pub fn encode(&self) -> Result<Vec<u8>, AdoptError> {
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes).map_err(|e| AdoptError::Decode(e.to_string()))?;
        Ok(bytes)
    }

    /// Decode a snapshot received out-of-band.
    pub fn decode(bytes: &[u8]) -> Result<Self, AdoptError> {
        ciborium::from_reader(bytes).map_err(|e| AdoptError::Decode(e.to_string()))
    }

    /// Parse a hex genesis pin into the 32-byte digest [`verify`](Self::verify) wants.
    pub fn parse_pin(hex: &str) -> Option<[u8; 32]> {
        let hex = hex.trim();
        if hex.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let hi = (chunk[0] as char).to_digit(16)?;
            let lo = (chunk[1] as char).to_digit(16)?;
            out[i] = ((hi << 4) | lo) as u8;
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap() -> Snapshot {
        Snapshot::new(
            vec![(0, vec![1, 2, 3]), (0, vec![4, 5, 6]), (1, vec![7, 8, 9])],
            2,
        )
    }

    #[test]
    fn a_snapshot_round_trips_and_its_pin_is_stable() {
        let s = snap();
        let bytes = s.encode().unwrap();
        let back = Snapshot::decode(&bytes).unwrap();
        assert_eq!(s.digest(), back.digest(), "encoding preserves the pin");
        // The hex pin parses back to the digest.
        assert_eq!(Snapshot::parse_pin(&s.digest_hex()), Some(s.digest()));
    }

    #[test]
    fn verify_accepts_the_matching_pin_and_refuses_others() {
        let s = snap();
        let pin = s.digest();
        assert!(s.verify(&pin).is_ok());
        assert!(matches!(
            s.verify(&[0u8; 32]),
            Err(AdoptError::GenesisMismatch)
        ));
    }

    #[test]
    fn tampering_changes_the_pin() {
        let s = snap();
        let pin = s.digest();
        // Drop a record — a different set, a different pin, refused against the old pin.
        let mut tampered = s.clone();
        tampered.records.pop();
        assert_ne!(tampered.digest(), pin);
        assert!(matches!(
            tampered.verify(&pin),
            Err(AdoptError::GenesisMismatch)
        ));
        // Reordering is likewise caught (the pin hashes records in sequence).
        let mut reordered = s.clone();
        reordered.records.swap(0, 1);
        assert_ne!(reordered.digest(), pin);
    }

    #[test]
    fn a_future_version_is_refused() {
        let mut s = snap();
        s.version = SERVERLESS_VERSION + 1;
        let pin = s.digest();
        assert!(matches!(s.verify(&pin), Err(AdoptError::Version { .. })));
    }
}
