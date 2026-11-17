//! The server-backed deployment's public epoch schedule, and the log of issuer-key
//! rotations a client checks against it.
//!
//! Epochs are **publicly computable**: `epoch(now) = floor((now - start) / length)` from a
//! published start time and length (a day, by default). The server turns its epoch on that
//! schedule and nothing else — no route can turn it — and serves the schedule beside the
//! epoch (`/api/get_epoch`), so a client or an auditor can compute the epoch itself and
//! notice a server that is ahead of or behind its own schedule.
//!
//! The Privacy Pass issuer key rotates at each epoch boundary and at each ban. Every
//! rotation is appended to a public log (`/api/privpass/rotations`), and a client accepts a
//! new key only if the log explains it (`personas_client`'s rotation check). Both sides
//! share the types here so the log has one serialization.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// A published epoch schedule: epoch `e` covers `[start + e·length, start + (e+1)·length)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochSchedule {
    /// Unix seconds at which epoch 0 begins.
    pub start: u64,
    /// Seconds per epoch. Never zero.
    pub length: u64,
}

impl EpochSchedule {
    pub fn new(start: u64, length: u64) -> Self {
        assert!(length > 0, "an epoch must last at least one second");
        Self { start, length }
    }

    /// The epoch at unix time `now`. Before `start` it is epoch 0: the store starts there.
    pub fn epoch_at(&self, now: u64) -> u64 {
        now.saturating_sub(self.start) / self.length
    }

    /// The unix time at which `epoch` begins.
    pub fn boundary(&self, epoch: u64) -> u64 {
        self.start.saturating_add(epoch.saturating_mul(self.length))
    }

    /// The epoch now, by this machine's clock.
    pub fn current(&self) -> u64 {
        self.epoch_at(now_unix())
    }
}

/// This machine's clock, in unix seconds.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Why the issuer key rotated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RotationReason {
    /// The first key the log records: not a rotation, the key the server started with.
    Genesis,
    /// The epoch turned to `epoch`.
    Epoch,
    /// A member was banned in `epoch`.
    Ban,
}

/// What a ban rotation points at: the ban's entry in the public callback bulletin
/// (`/api/callbacks/bulletin`), and the group admin's signature on the ban.
///
/// The bulletin alone cannot show a call was a ban (it holds the argument encrypted to the
/// ticket's owner), so a server could otherwise pass off any callback invocation, a rating
/// included, as a reason to rotate. The signature closes that: a client checks the entry
/// exists, holds this ticket and was called in the rotation's epoch, *and* that the admin
/// signed a ban of this ticket in this epoch (`crate::moderation`). The server cannot make
/// that signature, so it cannot rotate the key except on the schedule or on a real ban.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BanRef {
    /// The entry's position in the callback bulletin.
    pub index: u64,
    /// The called ticket, as hex of its canonical uncompressed bytes.
    pub ticket: String,
    /// The admin's Ed25519 signature over [`crate::moderation::ban_message`] for this ticket
    /// and the rotation's epoch, as hex.
    pub signature: String,
}

/// One line of the rotation log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationEntry {
    /// Position in the log, from 0. The log is append-only, so these are consecutive.
    pub seq: u64,
    /// The epoch the key belongs to: the epoch turned to, or the epoch the ban was in.
    pub epoch: u64,
    pub reason: RotationReason,
    /// Set for a [`RotationReason::Ban`], and only then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ban: Option<BanRef>,
    /// The new public key, as hex of exactly the bytes `/api/privpass/pubkey` serves.
    pub pubkey: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epochs_follow_the_schedule() {
        let s = EpochSchedule::new(1_000, 10);
        assert_eq!(s.epoch_at(0), 0);
        assert_eq!(s.epoch_at(1_000), 0);
        assert_eq!(s.epoch_at(1_009), 0);
        assert_eq!(s.epoch_at(1_010), 1);
        assert_eq!(s.epoch_at(1_105), 10);
        assert_eq!(s.boundary(10), 1_100);
    }

    #[test]
    fn a_log_entry_round_trips() {
        let e = RotationEntry {
            seq: 3,
            epoch: 7,
            reason: RotationReason::Ban,
            ban: Some(BanRef { index: 2, ticket: "ab".into(), signature: "ef".into() }),
            pubkey: "cd".into(),
        };
        let text = serde_json::to_string(&e).unwrap();
        assert!(text.contains("\"reason\":\"ban\""));
        assert_eq!(serde_json::from_str::<RotationEntry>(&text).unwrap(), e);
    }
}
