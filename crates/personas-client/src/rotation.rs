//! Checking the server's epoch schedule, and every Privacy Pass issuer-key rotation.
//!
//! The server rotates the ticket issuer key at each epoch boundary and on each ban
//! (`personas_core::schedule`). A server free to rotate at will could hand different
//! members different keys and link their tickets by which key unblinds them, or expire
//! tickets whenever it liked. So a client keeps the last key it accepted, next to its
//! other state, and accepts a different key only if the server's public, append-only
//! rotation log explains every rotation since: at most one per epoch boundary, none ahead
//! of the published schedule, and each ban rotation tied to its own call in the public
//! callback bulletin, made in that epoch. (The bulletin holds each call's argument
//! encrypted to the ticket's owner, so a client sees that a call was made, not that it
//! was a ban.) Every member fetches the same log, so a key served to only some of them is
//! one the log cannot explain to the rest.
//!
//! The epoch itself is checked the same way: the server publishes its schedule with the
//! epoch, the client pins the schedule the first time it sees it, and refuses an epoch
//! its own clock does not agree with.

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use personas_core::schedule::{BanRef, EpochSchedule, RotationEntry, RotationReason};

/// How far apart the client's clock and the server's may be, in seconds. Near a boundary
/// either side of it is accepted; never more than a quarter of an epoch.
pub const CLOCK_SKEW_SECS: u64 = 30;

fn skew(schedule: &EpochSchedule) -> u64 {
    CLOCK_SKEW_SECS.min(schedule.length / 4)
}

/// The epochs a clock reading `now` accepts from the server, allowing for skew.
fn plausible_epochs(schedule: &EpochSchedule, now: u64) -> (u64, u64) {
    let s = skew(schedule);
    (
        schedule.epoch_at(now.saturating_sub(s)),
        schedule.epoch_at(now.saturating_add(s)),
    )
}

/// Refuse a server epoch that this client's clock, read against the schedule, does not
/// agree with.
pub fn check_epoch(schedule: &EpochSchedule, served: u64, now: u64) -> Result<()> {
    let (lo, hi) = plausible_epochs(schedule, now);
    if served < lo || served > hi {
        bail!(
            "the server says it is epoch {served}, but its published schedule (start {}, \
             {} s epochs) puts this client's clock in epoch {}; refusing to prove against \
             an epoch off its schedule (check this machine's clock)",
            schedule.start,
            schedule.length,
            schedule.epoch_at(now)
        );
    }
    Ok(())
}

/// Pin the schedule: the first one a client sees is saved in `path`, and a server that
/// later publishes a different one is refused. A schedule that moved would let the server
/// turn the epoch whenever it liked, as long as it said so.
pub fn pin_schedule(path: &Path, served: EpochSchedule) -> Result<()> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let pinned: EpochSchedule = serde_json::from_str(&text)
                .with_context(|| format!("{} is not an epoch schedule", path.display()))?;
            if pinned != served {
                bail!(
                    "the server changed its published epoch schedule (from start {}, {} s \
                     epochs to start {}, {} s epochs); refusing it. If this is a new \
                     deployment, remove {}",
                    pinned.start,
                    pinned.length,
                    served.start,
                    served.length,
                    path.display()
                );
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(path, serde_json::to_string(&served)?)
                .with_context(|| format!("could not write {}", path.display()))
        }
        Err(e) => Err(e).with_context(|| format!("could not read {}", path.display())),
    }
}

/// Accept `served` (hex of the issuer key's bytes) only if `log` explains it.
///
/// - The served key must be the log's last entry.
/// - The log must be well formed: consecutive `seq` from 0, a genesis entry first and only
///   there, at most one epoch rotation per epoch and in increasing order, none ahead of
///   the schedule (by this client's clock, allowing skew), and every ban rotation in the
///   epoch of the turn before it, each citing a different bulletin entry.
/// - Every rotation after `last_accepted` that is a ban must cite a call `ban_is_public`
///   finds in the public callback bulletin (its arguments: the reference and the
///   rotation's epoch).
///
/// With no `last_accepted` (a client's first ticket) there is nothing to have rotated
/// from, so the served key is accepted on first use if it ends a well-formed log. A
/// `last_accepted` key the log does not contain means the log was rewritten.
pub fn check_rotations(
    last_accepted: Option<&str>,
    served: &str,
    log: &[RotationEntry],
    schedule: &EpochSchedule,
    now: u64,
    mut ban_is_public: impl FnMut(&BanRef, u64) -> Result<bool>,
) -> Result<()> {
    let last = log
        .last()
        .ok_or_else(|| anyhow!("the server's key rotation log is empty"))?;
    if last.pubkey != served {
        bail!(
            "the server's ticket issuer key is not the last key in its rotation log; \
             refusing a key the log does not explain"
        );
    }

    let (_, newest) = plausible_epochs(schedule, now);
    let mut turn: Option<u64> = None;
    let mut cited = std::collections::HashSet::new();
    for (n, entry) in log.iter().enumerate() {
        if entry.seq != n as u64 {
            bail!("the rotation log is not append-only: entry {n} has seq {}", entry.seq);
        }
        if entry.epoch > newest {
            bail!(
                "rotation {n} is for epoch {}, ahead of the schedule (epoch {})",
                entry.epoch,
                schedule.epoch_at(now)
            );
        }
        match (entry.reason, n) {
            (RotationReason::Genesis, 0) => turn = Some(entry.epoch),
            (RotationReason::Genesis, _) => bail!("rotation {n} claims to be a second genesis"),
            (_, 0) => bail!("the rotation log does not start with its genesis key"),
            (RotationReason::Epoch, _) => {
                if turn.is_some_and(|t| entry.epoch <= t) {
                    bail!(
                        "rotation {n} turns to epoch {}, but the key was already rotated for \
                         epoch {}: at most one epoch rotation per boundary",
                        entry.epoch,
                        turn.unwrap_or_default()
                    );
                }
                if entry.ban.is_some() {
                    bail!("epoch rotation {n} cites a ban");
                }
                turn = Some(entry.epoch);
            }
            (RotationReason::Ban, _) => {
                if Some(entry.epoch) != turn {
                    bail!(
                        "ban rotation {n} is in epoch {}, not the current epoch {:?}",
                        entry.epoch,
                        turn
                    );
                }
                let ban = entry
                    .ban
                    .as_ref()
                    .ok_or_else(|| anyhow!("ban rotation {n} cites no ban"))?;
                if !cited.insert(ban.index) {
                    bail!("ban rotation {n} cites a ban an earlier rotation already cited");
                }
            }
        }
    }

    let Some(accepted) = last_accepted else {
        return Ok(());
    };
    if accepted == served {
        return Ok(());
    }
    let from = log
        .iter()
        .rposition(|e| e.pubkey == accepted)
        .ok_or_else(|| {
            anyhow!(
                "the rotation log does not contain the key this client last accepted; \
                 refusing a log that has been rewritten"
            )
        })?;
    for entry in &log[from + 1..] {
        if let (RotationReason::Ban, Some(ban)) = (entry.reason, &entry.ban)
            && !ban_is_public(ban, entry.epoch)?
        {
            bail!(
                "ban rotation {} cites callback bulletin entry {}, which is not a call on \
                 that ticket made in epoch {}; refusing the key",
                entry.seq,
                ban.index,
                entry.epoch
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEDULE: EpochSchedule = EpochSchedule { start: 1_000, length: 100 };
    /// Epoch 5, well inside it.
    const NOW: u64 = 1_550;

    fn entry(seq: u64, epoch: u64, reason: RotationReason, key: &str) -> RotationEntry {
        let ban = (reason == RotationReason::Ban).then(|| BanRef {
            index: seq,
            ticket: format!("t{seq}"),
        });
        RotationEntry { seq, epoch, reason, ban, pubkey: key.into() }
    }

    /// Genesis in epoch 2, a ban in it, turns to 3 and 5 (the server was down for 4), and
    /// a ban in 5.
    fn valid_log() -> Vec<RotationEntry> {
        vec![
            entry(0, 2, RotationReason::Genesis, "k0"),
            entry(1, 2, RotationReason::Ban, "k1"),
            entry(2, 3, RotationReason::Epoch, "k2"),
            entry(3, 5, RotationReason::Epoch, "k3"),
            entry(4, 5, RotationReason::Ban, "k4"),
        ]
    }

    fn all_bans_public(_: &BanRef, _: u64) -> Result<bool> {
        Ok(true)
    }

    #[test]
    fn accepts_a_valid_sequence() {
        let log = valid_log();
        let mut checked = Vec::new();
        check_rotations(Some("k0"), "k4", &log, &SCHEDULE, NOW, |ban, epoch| {
            checked.push((ban.index, epoch));
            Ok(true)
        })
        .unwrap();
        // Both bans since k0 were checked against public state, in their epochs.
        assert_eq!(checked, vec![(1, 2), (4, 5)]);
        // First use, and an unchanged key, need no ban lookups.
        check_rotations(None, "k4", &log, &SCHEDULE, NOW, |_, _| unreachable!()).unwrap();
        check_rotations(Some("k4"), "k4", &log, &SCHEDULE, NOW, |_, _| unreachable!()).unwrap();
    }

    #[test]
    fn rejects_an_unexplained_extra_rotation() {
        // A ban rotation whose ban is not in the public bulletin.
        let log = valid_log();
        let err = check_rotations(Some("k2"), "k4", &log, &SCHEDULE, NOW, |ban, _| {
            Ok(ban.index != 4)
        })
        .unwrap_err();
        assert!(err.to_string().contains("not a call"), "{err}");

        // A rotation that claims to be a ban but cites nothing.
        let mut log = valid_log();
        log[4].ban = None;
        assert!(check_rotations(Some("k2"), "k4", &log, &SCHEDULE, NOW, all_bans_public).is_err());

        // An epoch rotation ahead of the schedule.
        let mut log = valid_log();
        log.push(entry(5, 6, RotationReason::Epoch, "k5"));
        let err =
            check_rotations(Some("k4"), "k5", &log, &SCHEDULE, NOW, all_bans_public).unwrap_err();
        assert!(err.to_string().contains("ahead of the schedule"), "{err}");

        // A second genesis.
        let mut log = valid_log();
        log.push(entry(5, 5, RotationReason::Genesis, "k5"));
        assert!(check_rotations(Some("k4"), "k5", &log, &SCHEDULE, NOW, all_bans_public).is_err());

        // A log rewritten so the key this client accepted is gone.
        assert!(
            check_rotations(Some("kX"), "k4", &valid_log(), &SCHEDULE, NOW, all_bans_public)
                .is_err()
        );
    }

    #[test]
    fn rejects_a_key_that_is_not_the_logs_last_entry() {
        let err = check_rotations(Some("k0"), "k3", &valid_log(), &SCHEDULE, NOW, all_bans_public)
            .unwrap_err();
        assert!(err.to_string().contains("not the last key"), "{err}");
        // Even on first use.
        assert!(check_rotations(None, "kX", &valid_log(), &SCHEDULE, NOW, all_bans_public).is_err());
    }

    #[test]
    fn rejects_two_epoch_rotations_in_one_epoch() {
        let mut log = valid_log();
        log.push(entry(5, 5, RotationReason::Epoch, "k5"));
        let err =
            check_rotations(Some("k4"), "k5", &log, &SCHEDULE, NOW, all_bans_public).unwrap_err();
        assert!(err.to_string().contains("at most one epoch rotation"), "{err}");
    }

    #[test]
    fn the_epoch_must_match_the_clock_within_the_skew() {
        // Epoch 5 is [1500, 1600). Well inside it only 5 is accepted.
        check_epoch(&SCHEDULE, 5, 1_550).unwrap();
        assert!(check_epoch(&SCHEDULE, 4, 1_550).is_err());
        assert!(check_epoch(&SCHEDULE, 6, 1_550).is_err());
        // Near a boundary, either side of it (skew is 25 s for a 100 s epoch).
        check_epoch(&SCHEDULE, 4, 1_510).unwrap();
        check_epoch(&SCHEDULE, 6, 1_590).unwrap();
        assert!(check_epoch(&SCHEDULE, 6, 1_570).is_err());
    }

    #[test]
    fn a_pinned_schedule_cannot_move() {
        let dir = std::env::temp_dir().join(format!("personas-schedule-{}", std::process::id()));
        let path = dir.join("epoch_schedule.json");
        let _ = std::fs::remove_file(&path);
        pin_schedule(&path, SCHEDULE).unwrap();
        pin_schedule(&path, SCHEDULE).unwrap();
        assert!(pin_schedule(&path, EpochSchedule { start: 1_000, length: 50 }).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
