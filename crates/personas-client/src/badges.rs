//! The three badge slots and the pseudonym each is claimed under.
//!
//! A badge is a credential ("Faculty", "Student", "Industry") granted by a moderator and
//! recorded in the user object as one of `badge1..badge3`. To *show* a badge the member
//! proves `badge_pred` under a pseudonym, which is why each slot remembers which
//! pseudonym it was claimed under — that binding is local, and it is the only thing
//! linking the badge to a persona.

use anyhow::{anyhow, Context, Result};
use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    path::Path,
};

use crate::PersonaClient;

/// How many badges a member can hold, fixed by `MsgUser`'s `badge1..badge3` fields.
pub const BADGE_SLOTS: u32 = 3;

/// An unclaimed slot. Field elements are stored as decimal strings, so zero is `"0"`.
const UNCLAIMED: &str = "0";

/// One line of `badges.jsonl`: a slot and the pseudonym it is claimed under.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StoredBadge {
    pub i: u32,
    pub claimed: String,
}

/// The credential a slot carries. These strings are the preimages of `FACULTY_F`,
/// `STUDENT_F` and `INDUSTRY_F` in `personas_core::circuits`, so they must match exactly.
pub fn badge_name(index: u32) -> &'static str {
    match index {
        1 => "Faculty",
        2 => "Student",
        3 => "Industry",
        _ => "Unknown",
    }
}

impl PersonaClient {
    /// Seed the badge log with the three slots, all unclaimed.
    pub fn init_badge_log(&self) -> Result<()> {
        let slots: Vec<StoredBadge> = (1..=BADGE_SLOTS)
            .map(|i| StoredBadge {
                i,
                claimed: UNCLAIMED.to_string(),
            })
            .collect();

        self.write_badges(&slots)
    }

    pub fn read_badges(&self) -> Result<Vec<StoredBadge>> {
        let path = self.cfg.badge_log();
        if !Path::new(&path).exists() {
            return Ok(vec![]);
        }

        let mut badges = Vec::new();
        for line in BufReader::new(File::open(&path)?).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            badges.push(
                serde_json::from_str::<StoredBadge>(&line)
                    .with_context(|| format!("malformed badge in {}", path.display()))?,
            );
        }
        Ok(badges)
    }

    fn write_badges(&self, badges: &[StoredBadge]) -> Result<()> {
        fs::create_dir_all(&self.cfg.data_dir)?;

        let mut file = File::create(self.cfg.badge_log())?;
        for badge in badges {
            writeln!(file, "{}", serde_json::to_string(badge)?)?;
        }
        Ok(())
    }

    /// Reconcile the badge log with the user object, which the server updates by
    /// invoking a badge callback. Returns the slots that were newly granted.
    ///
    /// This is how a member learns a badge request was approved: the grant arrives as a
    /// callback that mutates `badge1..badge3`, and nothing else tells them.
    pub fn sync_user_badges(&self) -> Result<Vec<u32>> {
        let user = self.load_user()?;

        let mut stored = self.read_badges()?;
        for i in 1..=BADGE_SLOTS {
            if !stored.iter().any(|b| b.i == i) {
                stored.push(StoredBadge {
                    i,
                    claimed: UNCLAIMED.to_string(),
                });
            }
        }

        let granted = [user.data.badge1, user.data.badge2, user.data.badge3];
        let mut newly_granted = Vec::new();

        for (slot, value) in granted.iter().enumerate() {
            let index = slot as u32 + 1;
            let claimed = value.into_bigint().to_string();

            let Some(entry) = stored.iter_mut().find(|b| b.i == index) else {
                continue;
            };

            if entry.claimed != claimed {
                println!(
                    "badge {index} ({}): {} -> {}",
                    badge_name(index),
                    entry.claimed,
                    claimed
                );
                entry.claimed = claimed.clone();
            }

            if claimed != UNCLAIMED {
                newly_granted.push(index);
            }
        }

        self.write_badges(&stored)?;

        #[cfg(feature = "render")]
        for index in &newly_granted {
            if let Err(e) = self.render_badge(*index) {
                eprintln!("failed to render badge {index}: {e}");
            }
        }

        Ok(newly_granted)
    }

    /// The pseudonym a slot is claimed under, if any.
    pub fn claimed_by_badge_index(&self, index: u32) -> Result<Option<String>> {
        Ok(self
            .read_badges()?
            .into_iter()
            .find(|b| b.i == index)
            .map(|b| b.claimed))
    }

    /// The slot claimed under a given pseudonym. If a pseudonym somehow claims more than
    /// one slot, the first wins.
    pub fn badge_index_by_claimed(&self, claimed: &str) -> Result<Option<u32>> {
        Ok(self
            .read_badges()?
            .iter()
            .find(|b| b.claimed == claimed)
            .map(|b| b.i))
    }

    /// Record that slot `index` is now claimed under pseudonym `claimed`.
    pub fn claim_badge(&self, index: u32, claimed: &str) -> Result<()> {
        if !(1..=BADGE_SLOTS).contains(&index) {
            return Err(anyhow!(
                "badge slot {index} does not exist (there are {BADGE_SLOTS})"
            ));
        }

        let mut badges = self.read_badges()?;
        match badges.iter_mut().find(|b| b.i == index) {
            Some(entry) => entry.claimed = claimed.to_string(),
            None => badges.push(StoredBadge {
                i: index,
                claimed: claimed.to_string(),
            }),
        }

        self.write_badges(&badges)
    }
}
