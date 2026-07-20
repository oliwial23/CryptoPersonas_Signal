//! On-disk client state: the `User` object, the pseudonym log, and thread contexts.

use anyhow::{anyhow, Context, Result};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::UniformRand;
use personas_core::{
    circuits::MsgUser,
    persona::{self, petname_from_str},
    F, H,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Write},
};
use zk_callbacks::generic::{object::Com, user::User};

use crate::PersonaClient;

/// One line of `pseudo_log.jsonl`: a pseudonym and the context it was derived for.
#[derive(Serialize, Deserialize)]
pub struct PseudonymProofEntry {
    pub context: String,
    pub claimed: String,
}

/// A pseudonym scoped to a poll, so a vote can be shown to be one-per-member.
#[derive(Serialize, Deserialize)]
pub struct PollPseudonymProofEntry {
    pub context: String,
    pub claimed: String,
    pub timestamp: u64,
}

/// One line of `contexts.jsonl`: a thread id and the context the server assigned it.
#[derive(Deserialize)]
struct ContextJson {
    thread: String,
    context: String,
}

impl PersonaClient {
    pub fn save_user(&self, user: &User<F, MsgUser>) -> Result<()> {
        fs::create_dir_all(&self.cfg.data_dir)?;

        let file = File::create(self.cfg.user_file())?;
        let mut writer = BufWriter::new(file);
        user.serialize_with_mode(&mut writer, Compress::No)
            .map_err(|e| anyhow!("failed to serialize user: {e}"))?;
        writer.flush()?;
        Ok(())
    }

    pub fn load_user(&self) -> Result<User<F, MsgUser>> {
        let path = self.cfg.user_file();
        let file = File::open(&path)
            .with_context(|| format!("no user state at {}; run `join` first", path.display()))?;

        let mut reader = BufReader::new(file);
        User::<F, MsgUser>::deserialize_with_mode(&mut reader, Compress::No, Validate::Yes)
            .map_err(|e| anyhow!("user state at {} is corrupt: {e}", path.display()))
    }

    /// Register a fresh member: mint a secret key, commit to it, post the commitment to
    /// the bulletin, and reset all local state derived from any previous identity.
    pub fn join(&self) -> Result<()> {
        let mut rng = OsRng;

        let user = User::create(
            MsgUser {
                sk: F::rand(&mut rng),
                reputation: F::from(0),
                num_interactions_since_last_scan: F::from(0),
                pseudo_counter: F::from(0),
                banned: F::from(0),
                badge1: F::from(0),
                badge2: F::from(0),
                badge3: F::from(0),
            },
            &mut rng,
        );

        let commit: Com<F> = user.commit::<H>();
        self.bul
            .join_bul(commit)
            .map_err(|e| anyhow!("bulletin rejected the join: {e}"))?;

        self.save_user(&user)?;

        // The old identity's pseudonyms and badges are meaningless under the new key.
        let _ = fs::remove_file(self.cfg.pseudo_log());
        let _ = fs::remove_file(self.cfg.contexts());
        let _ = fs::remove_file(self.cfg.badge_log());
        let _ = fs::remove_dir_all(self.cfg.badge_dir());

        self.init_badge_log()?;
        self.gen_pseudo()?;

        Ok(())
    }

    /// Mint a pseudonym for a fresh random context and append it to the pseudonym log.
    pub fn gen_pseudo(&self) -> Result<()> {
        let mut rng = OsRng;
        let user = self.load_user()?;

        let context = F::rand(&mut rng);
        let claimed = persona::pseudonym(&user.data.sk, &context);

        let entry = PseudonymProofEntry {
            context: context.into_bigint().to_string(),
            claimed: claimed.into_bigint().to_string(),
        };

        fs::create_dir_all(&self.cfg.data_dir)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.cfg.pseudo_log())?;

        writeln!(file, "{}", serde_json::to_string(&entry)?)?;
        Ok(())
    }

    /// The pseudonym for a poll: derived from the poll's context, so one member can
    /// cast exactly one vote without revealing which.
    pub fn pseudo_for_poll(&self, context: &F) -> Result<F> {
        let user = self.load_user()?;
        Ok(persona::pseudonym(&user.data.sk, context))
    }

    /// The `i`-th rate-limited pseudonym for `context`.
    pub fn pseudo_rate(&self, context: &F, i: &F) -> Result<F> {
        let user = self.load_user()?;
        Ok(persona::pseudonym_rate(&user.data.sk, context, i))
    }

    /// Print every pseudonym in the log with the index the CLI expects.
    pub fn list_pseudos(&self) -> Result<()> {
        for (i, entry) in self.pseudo_log_entries()?.into_iter().enumerate() {
            println!("\"{}\"; index = {}", petname_from_str(&entry.1), i + 1);
        }
        Ok(())
    }

    /// The `(claimed, context)` pair at the given 1-based index in the pseudonym log.
    pub fn claimed_context_by_index(&self, index: usize) -> Result<(String, String)> {
        self.pseudo_log_entries()?
            .into_iter()
            .nth(index.saturating_sub(1))
            .map(|(context, claimed)| (claimed, context))
            .ok_or_else(|| anyhow!("no pseudonym at index {index}; run `gen-pseudo` first"))
    }

    /// Every `(context, claimed)` pair in the pseudonym log, in order.
    fn pseudo_log_entries(&self) -> Result<Vec<(String, String)>> {
        let path = self.cfg.pseudo_log();
        let file = File::open(&path)
            .with_context(|| format!("no pseudonym log at {}", path.display()))?;

        let mut out = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let json: Value = serde_json::from_str(&line)
                .with_context(|| format!("malformed line in {}", path.display()))?;

            match (json["context"].as_str(), json["claimed"].as_str()) {
                (Some(c), Some(k)) => out.push((c.to_string(), k.to_string())),
                _ => return Err(anyhow!("line in {} is missing context/claimed", path.display())),
            }
        }
        Ok(out)
    }

    /// The context the server assigned to `thread`, from the mirrored context log.
    pub fn lookup_context(&self, thread: &str) -> Option<F> {
        let file = File::open(self.cfg.contexts()).ok()?;

        for line in BufReader::new(file).lines() {
            let line = line.ok()?;
            if let Ok(entry) = serde_json::from_str::<ContextJson>(&line) {
                if entry.thread == thread {
                    return persona::field_from_str(&entry.context);
                }
            }
        }
        None
    }

    /// Overwrite the local context mirror with the server's copy.
    pub fn save_contexts(&self, body: &str) -> Result<()> {
        fs::create_dir_all(&self.cfg.data_dir)?;
        fs::write(self.cfg.contexts(), body)?;
        Ok(())
    }
}
