//! The four JSONL-backed stores, and the in-memory one.
//!
//! Each keeps its rows in memory and rewrites its file when they change. That is the same
//! durability the old code had — a rewritten file, no fsync, no atomic rename — but it
//! re-read and re-parsed the entire file on *every* lookup, and there were ten such
//! functions. Reading is now a map lookup; only a mutation touches the disk.
//!
//! None of this is the bulletin. Losing it loses the service's ability to attribute a rating
//! to a post, not the ability to verify a proof.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use transport_api::MessageId;

/// A message the server relayed, and the callback its poster committed to.
///
/// The join is the whole point. A poster proves, as part of posting, that they have
/// committed to a callback the service may later invoke to change their reputation — but the
/// commitment is made *before* the message exists, so it cannot name the message. The
/// messenger assigns an id only once the message is delivered. This row is where the two
/// meet: a rating on message `id` becomes an argument to callback `cb`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    /// The messenger's id. A Signal millisecond timestamp or a Slack `1699…000100` — a
    /// string either way, so one store serves both.
    pub id: String,
    /// Hex-encoded `CallbackCom`.
    pub cb: String,
    /// The rating accumulated so far, applied and reset when the callback is invoked.
    pub reputation: i64,
}

pub struct RecordLog {
    path: PathBuf,
    rows: Vec<Record>,
}

impl RecordLog {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        Ok(Self {
            rows: read_jsonl(&path)?,
            path,
        })
    }

    /// File the callback a poster committed to under the id their message was given.
    ///
    /// The old code did this in two steps: append a `{"callback_com": …}` line *before*
    /// relaying, then, once the messenger answered with a timestamp, reread the file and
    /// rewrite `lines[len-1]` into a real row. Two things went wrong with that. A failed
    /// relay left the half-row behind, and the *next* post's rewrite would then adopt it as
    /// its own — silently attributing one member's callback to another member's message. And
    /// a concurrent post could interleave between the append and the rewrite. Recording only
    /// once the id exists makes both impossible.
    pub fn record(&mut self, id: &MessageId, cb_hex: String) -> Result<()> {
        self.rows.push(Record {
            id: id.0.clone(),
            cb: cb_hex,
            reputation: 0,
        });
        self.flush()
    }

    /// Rate a message. Ratings clamp at zero: reputation is a field element compared against
    /// a threshold in-circuit, and a negative one would wrap to something enormous.
    pub fn rate(&mut self, id: &MessageId, delta: i64) -> Result<()> {
        let Some(row) = self.rows.iter_mut().find(|r| r.id == id.0) else {
            // A reaction to something the server did not post — a member's own message, a
            // bot notice. Not an error; there is simply no callback to rate.
            tracing::debug!("rating for unknown message {id} ignored");
            return Ok(());
        };

        row.reputation = (row.reputation + delta).max(0);
        self.flush()
    }

    pub fn callback_for(&self, id: &MessageId) -> Option<&str> {
        self.rows
            .iter()
            .find(|r| r.id == id.0)
            .map(|r| r.cb.as_str())
    }

    pub fn reputation_of(&self, cb_hex: &str) -> Result<i64> {
        self.rows
            .iter()
            .find(|r| r.cb == cb_hex)
            .map(|r| r.reputation)
            .with_context(|| format!("no record for callback {cb_hex}"))
    }

    /// Every callback with a rating waiting to be applied. This is what the client polls to
    /// find out which of its callbacks are worth spending an interaction on.
    pub fn pending(&self) -> Vec<String> {
        self.rows
            .iter()
            .filter(|r| r.reputation != 0)
            .map(|r| r.cb.clone())
            .collect()
    }

    /// Zero a rating once its callback has been invoked, so it is not applied twice.
    pub fn settle(&mut self, cb_hex: &str) -> Result<()> {
        let Some(row) = self.rows.iter_mut().find(|r| r.cb == cb_hex) else {
            bail!("no record for callback {cb_hex}");
        };
        row.reputation = 0;
        self.flush()
    }

    fn flush(&mut self) -> Result<()> {
        write_jsonl(&self.path, &self.rows)
    }
}

/// A thread, and the context field element pseudonyms in it are derived from.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreadContext {
    pub thread: String,
    /// A field element, decimal. The client parses it back with `F::from_str`.
    pub context: String,
    /// The messenger id of the message that opened the thread. Signal has no threads, so it
    /// has no ts; Slack replies into one, so it does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts: Option<String>,
    /// Whether the topic banner has already been echoed once into this thread
    /// (FINDINGS O9). `#[serde(default)]` so rows written before this field existed still
    /// parse — they read as not-yet-echoed, which just means one banner gets replayed.
    #[serde(default)]
    pub topic_echoed: bool,
}

pub struct ContextLog {
    path: PathBuf,
    rows: Vec<ThreadContext>,
}

impl ContextLog {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        Ok(Self {
            rows: read_jsonl(&path)?,
            path,
        })
    }

    pub fn by_thread(&self, thread: &str) -> Option<&ThreadContext> {
        self.rows.iter().find(|r| r.thread == thread)
    }

    /// The thread a context belongs to — the lookup a rate-limited pseudonymous post needs,
    /// since the proof names a context and the message has to land in the right thread.
    pub fn by_context(&self, context: &str) -> Option<&ThreadContext> {
        self.rows.iter().find(|r| r.context == context)
    }

    pub fn add(&mut self, entry: ThreadContext) -> Result<&ThreadContext> {
        let thread = entry.thread.clone();
        self.rows.push(entry);
        write_jsonl(&self.path, &self.rows)?;
        Ok(self
            .rows
            .iter()
            .find(|r| r.thread == thread)
            .expect("just pushed"))
    }

    /// If `ts` names a thread whose topic has not been echoed yet, marks it echoed and
    /// returns the topic text to post; otherwise (unknown thread, or already echoed)
    /// returns `None` and does nothing. Checking and marking happen together so two
    /// near-simultaneous first replies into a thread cannot both see "not yet echoed"
    /// and both post the banner. See FINDINGS O9.
    pub fn topic_to_echo(&mut self, ts: &str) -> Result<Option<String>> {
        let Some(row) = self.rows.iter_mut().find(|r| r.ts.as_deref() == Some(ts)) else {
            return Ok(None);
        };
        if row.topic_echoed {
            return Ok(None);
        }
        row.topic_echoed = true;
        let topic = row.thread.clone();
        write_jsonl(&self.path, &self.rows)?;
        Ok(Some(topic))
    }

    /// The file the client downloads wholesale and parses line by line.
    pub fn as_jsonl(&self) -> String {
        self.rows
            .iter()
            .filter_map(|r| serde_json::to_string(r).ok())
            .map(|line| line + "\n")
            .collect()
    }
}

/// A vote cast in a Signal poll.
///
/// `seed` is the claimed pseudonym: it is what makes one-member-one-vote checkable without
/// knowing who the member is. Two ballots with the same seed are the same person voting
/// twice, and that is all anyone can tell.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ballot {
    pub poll_pseudonym: String,
    pub seed: String,
    pub emoji: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PollEntry {
    /// The messenger id of the poll message; a vote quotes it.
    pub timestamp: u64,
    pub votes: Vec<Ballot>,
    /// The message under review, or 0 for a poll that is not about banning anyone.
    pub ban: i64,
    pub context: String,
}

impl PollEntry {
    pub fn is_ban(&self) -> bool {
        self.ban != 0
    }

    /// `(for, against)` — ban/keep for a ban poll, up/down otherwise.
    pub fn tally(&self) -> (usize, usize) {
        let (mut yes, mut no) = (0, 0);
        for ballot in &self.votes {
            match (self.is_ban(), emoji_name(&ballot.emoji)) {
                (true, "ban") => yes += 1,
                (true, "not ban") => no += 1,
                (false, "upvote") => yes += 1,
                (false, "downvote") => no += 1,
                _ => {}
            }
        }
        (yes, no)
    }
}

pub struct PollLog {
    path: PathBuf,
    rows: Vec<PollEntry>,
}

impl PollLog {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        Ok(Self {
            rows: read_jsonl(&path)?,
            path,
        })
    }

    pub fn open_poll(&mut self, entry: PollEntry) -> Result<()> {
        self.rows.push(entry);
        self.flush()
    }

    pub fn get(&self, timestamp: u64) -> Option<&PollEntry> {
        self.rows.iter().find(|p| p.timestamp == timestamp)
    }

    /// Record a ballot, replacing any this pseudonym already cast.
    ///
    /// Replacing rather than rejecting is what the old code did: a member may change their
    /// mind, and the pseudonym is what stops them from voting *twice*, not from voting again.
    pub fn cast(&mut self, timestamp: u64, ballot: Ballot) -> Result<()> {
        let Some(poll) = self.rows.iter_mut().find(|p| p.timestamp == timestamp) else {
            tracing::warn!("vote for unknown poll {timestamp} dropped");
            return Ok(());
        };

        poll.votes
            .retain(|v| !(v.poll_pseudonym == ballot.poll_pseudonym && v.seed == ballot.seed));
        poll.votes.push(ballot);
        self.flush()
    }

    pub fn close(&mut self, timestamp: u64) -> Result<()> {
        self.rows.retain(|p| p.timestamp != timestamp);
        self.flush()
    }

    /// The context assigned to the poll posted at `timestamp`, which is what a voter derives
    /// their poll pseudonym from.
    pub fn context_of(&self, timestamp: i64) -> Option<&str> {
        self.rows
            .iter()
            .find(|p| p.timestamp as i64 == timestamp)
            .map(|p| p.context.as_str())
    }

    fn flush(&mut self) -> Result<()> {
        write_jsonl(&self.path, &self.rows)
    }
}

/// A badge a member has asked for and an admin has not yet granted.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredBadge {
    /// Badge index: 1 Faculty, 2 Student, 3 Industry.
    pub i: u32,
    pub claimed: String,
    pub cb: String,
    pub timestamp: String,
}

pub struct BadgeLog {
    path: PathBuf,
    rows: Vec<StoredBadge>,
}

impl BadgeLog {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        Ok(Self {
            rows: read_jsonl(&path)?,
            path,
        })
    }

    pub fn request(&mut self, badge: StoredBadge) -> Result<()> {
        self.rows.push(badge);
        self.flush()
    }

    pub fn by_callback(&self, cb_hex: &str) -> Option<&StoredBadge> {
        self.rows.iter().find(|b| b.cb == cb_hex)
    }

    /// Every outstanding request, for the admin's approval queue.
    pub fn pending(&self) -> Vec<String> {
        self.rows.iter().map(|b| b.cb.clone()).collect()
    }

    pub fn grant(&mut self, cb_hex: &str) -> Result<()> {
        let before = self.rows.len();
        self.rows.retain(|b| b.cb != cb_hex);
        if self.rows.len() == before {
            bail!("no badge request for callback {cb_hex}");
        }
        self.flush()
    }

    fn flush(&mut self) -> Result<()> {
        write_jsonl(&self.path, &self.rows)
    }
}

/// The name of a badge index, as it is shown to the group.
pub fn badge_name(index: &str) -> &'static str {
    match index {
        "1" => "Faculty",
        "2" => "Student",
        "3" => "Industry",
        _ => "Unknown",
    }
}

/// Slack polls, persisted so a tally survives a restart (FINDINGS O5).
///
/// `votes` stays public and keyed exactly as it always was (callers still do
/// `state.votes.votes.insert/get/get_mut`) — the only new obligation on a caller that
/// mutates a poll is to call [`VoteState::flush`] afterward, the same discipline
/// `RecordLog`/`PollLog`/`BadgeLog` already impose via their own mutating methods.
pub struct VoteState {
    path: PathBuf,
    pub votes: HashMap<String, SlackPoll>,
}

impl VoteState {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let rows: Vec<(String, SlackPoll)> = read_jsonl(&path)?;
        Ok(Self {
            votes: rows.into_iter().collect(),
            path,
        })
    }

    /// Write every poll's current state back to disk. Cheap enough to call after every
    /// mutation — the same tradeoff `RecordLog`/`PollLog`/`BadgeLog` already make.
    pub fn flush(&mut self) -> Result<()> {
        let rows: Vec<(&String, &SlackPoll)> = self.votes.iter().collect();
        write_jsonl(&self.path, &rows)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SlackPoll {
    /// The Slack ts of the poll message.
    ///
    /// Nothing reads it — a Slack vote names the poll by its printed id, not by the message
    /// it was announced in. It is kept because it is the only link back from a poll to the
    /// message that announced it, and a Slack poll that survives a restart needs it.
    #[allow(dead_code)]
    pub timestamp: String,
    /// The field element voters derive their poll pseudonym from.
    pub context: String,
    /// Claimed pseudonyms that have already voted — one entry per member, and it says
    /// nothing about which member.
    pub voted: HashSet<String>,
    pub counts: HashMap<String, u32>,
    pub is_ban: bool,
}

/// The word for an emoji, in the vocabulary the vote and reputation paths speak.
pub fn emoji_name(emoji: &str) -> &'static str {
    if emoji.starts_with('👍') {
        return "upvote";
    }
    if emoji.starts_with('👎') {
        return "downvote";
    }
    match emoji {
        "🤬" => "hatespeech",
        "❌" => "ban",
        "✅" => "not ban",
        _ => "unknown",
    }
}

/// The emoji for a word, so a client may send either.
pub fn emoji_for(input: &str) -> &str {
    if input.starts_with('👍') || input.starts_with('👎') {
        return input;
    }
    match input {
        "🤬" | "❌" | "✅" => input,
        "upvote" => "👍",
        "downvote" => "👎",
        "hatespeech" => "🤬",
        "ban" => "❌",
        "not ban" => "✅",
        _ => "❓",
    }
}

fn read_jsonl<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
    let Ok(content) = std::fs::read_to_string(path) else {
        // No file yet is the normal state of a fresh deployment.
        return Ok(Vec::new());
    };

    Ok(content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| match serde_json::from_str(line) {
            Ok(row) => Some(row),
            Err(e) => {
                // Skip rather than fail: one corrupt row should not make the server refuse to
                // start, and the row it cannot read is a rating, not a proof.
                tracing::warn!("skipping unreadable row in {}: {e}", path.display());
                None
            }
        })
        .collect())
}

/// Which Privacy Pass tickets have already been redeemed.
///
/// `verify_ticket` (`personas_core::privpass`) is a stateless well-formedness check — it
/// carries no memory of past redemptions on its own, so replaying the same redemption would
/// otherwise verify every time. Keyed by [`personas_core::privpass::redemption_key`], the
/// canonical bytes of the redeemed callback entry: `verify_ticket` derives everything else
/// deterministically from that plus the (fixed) issuer key, so the same ticket redeemed twice
/// always produces the same key here.
pub struct SpentTicketLog {
    path: PathBuf,
    spent: HashSet<String>,
}

impl SpentTicketLog {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let rows: Vec<String> = read_jsonl(&path)?;
        Ok(Self {
            spent: rows.into_iter().collect(),
            path,
        })
    }

    pub fn is_spent(&self, key: &str) -> bool {
        self.spent.contains(key)
    }

    /// Marks `key` spent. Returns `false` (and does not write) if it already was — the
    /// caller's cue to reject the redemption as a replay.
    pub fn mark_spent(&mut self, key: String) -> Result<bool> {
        if !self.spent.insert(key) {
            return Ok(false);
        }
        let rows: Vec<&String> = self.spent.iter().collect();
        write_jsonl(&self.path, &rows)?;
        Ok(true)
    }
}

fn write_jsonl<T: Serialize>(path: &Path, rows: &[T]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }

    // Write beside the target and rename over it: a rewrite that is interrupted halfway
    // through — and this rewrites the whole file on every rating — must not leave a
    // truncated ledger behind.
    let tmp = path.with_extension("jsonl.tmp");
    let mut file = std::fs::File::create(&tmp)
        .with_context(|| format!("could not write {}", tmp.display()))?;

    for row in rows {
        writeln!(file, "{}", serde_json::to_string(row)?)?;
    }
    file.sync_all()?;
    drop(file);

    std::fs::rename(&tmp, path)
        .with_context(|| format!("could not replace {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "personas-ledger-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_rating_finds_the_callback_its_poster_committed_to() {
        let mut log = RecordLog::open(temp_dir().join("records.jsonl")).unwrap();
        let id = MessageId("1700000000000".into());

        log.record(&id, "deadbeef".into()).unwrap();
        log.rate(&id, 1).unwrap();
        log.rate(&id, 1).unwrap();

        assert_eq!(log.callback_for(&id), Some("deadbeef"));
        assert_eq!(log.reputation_of("deadbeef").unwrap(), 2);
        assert_eq!(log.pending(), vec!["deadbeef".to_string()]);
    }

    /// Reputation is compared against a threshold *in-circuit*, as a field element. A
    /// negative value would wrap to a number larger than any threshold, turning a pile of
    /// downvotes into perfect standing.
    #[test]
    fn ratings_clamp_at_zero() {
        let mut log = RecordLog::open(temp_dir().join("clamp.jsonl")).unwrap();
        let id = MessageId("1".into());

        log.record(&id, "cb".into()).unwrap();
        log.rate(&id, -5).unwrap();

        assert_eq!(log.reputation_of("cb").unwrap(), 0);
    }

    #[test]
    fn settling_a_callback_stops_it_being_applied_twice() {
        let mut log = RecordLog::open(temp_dir().join("settle.jsonl")).unwrap();
        let id = MessageId("1".into());

        log.record(&id, "cb".into()).unwrap();
        log.rate(&id, 3).unwrap();
        log.settle("cb").unwrap();

        assert_eq!(log.reputation_of("cb").unwrap(), 0);
        assert!(log.pending().is_empty());
    }

    #[test]
    fn a_rating_for_a_message_the_server_did_not_post_is_not_an_error() {
        let mut log = RecordLog::open(temp_dir().join("unknown.jsonl")).unwrap();
        assert!(log.rate(&MessageId("nope".into()), 1).is_ok());
    }

    #[test]
    fn the_ledger_survives_a_restart() {
        let path = temp_dir().join("restart.jsonl");
        let id = MessageId("1700000000000".into());

        {
            let mut log = RecordLog::open(&path).unwrap();
            log.record(&id, "cb".into()).unwrap();
            log.rate(&id, 2).unwrap();
        }

        let reopened = RecordLog::open(&path).unwrap();
        assert_eq!(reopened.reputation_of("cb").unwrap(), 2);
        assert_eq!(reopened.callback_for(&id), Some("cb"));
    }

    #[test]
    fn a_member_who_votes_twice_has_voted_once() {
        let mut polls = PollLog::open(temp_dir().join("polls.jsonl")).unwrap();
        polls
            .open_poll(PollEntry {
                timestamp: 100,
                votes: vec![],
                ban: 0,
                context: "ctx".into(),
            })
            .unwrap();

        let ballot = |emoji: &str| Ballot {
            poll_pseudonym: "able-mongoose".into(),
            seed: "12345".into(),
            emoji: emoji.into(),
        };

        polls.cast(100, ballot("👍")).unwrap();
        polls.cast(100, ballot("👎")).unwrap();

        let poll = polls.get(100).unwrap();
        assert_eq!(poll.votes.len(), 1, "the second ballot replaces the first");
        assert_eq!(poll.tally(), (0, 1), "and it is the later one that counts");
    }

    #[test]
    fn a_ban_poll_counts_bans_not_upvotes() {
        let poll = PollEntry {
            timestamp: 1,
            ban: 1700000000000,
            context: "ctx".into(),
            votes: vec![
                Ballot {
                    poll_pseudonym: "a".into(),
                    seed: "1".into(),
                    emoji: "❌".into(),
                },
                Ballot {
                    poll_pseudonym: "b".into(),
                    seed: "2".into(),
                    emoji: "❌".into(),
                },
                Ballot {
                    poll_pseudonym: "c".into(),
                    seed: "3".into(),
                    emoji: "✅".into(),
                },
                // An upvote is not a vote to keep. It is not a ballot in this poll at all.
                Ballot {
                    poll_pseudonym: "d".into(),
                    seed: "4".into(),
                    emoji: "👍".into(),
                },
            ],
        };

        assert!(poll.is_ban());
        assert_eq!(poll.tally(), (2, 1));
    }

    #[test]
    fn emoji_and_their_names_round_trip() {
        for name in ["upvote", "downvote", "hatespeech", "ban", "not ban"] {
            assert_eq!(emoji_name(emoji_for(name)), name);
        }
        // Skin-tone modifiers: 👍🏽 is still an upvote.
        assert_eq!(emoji_name("👍🏽"), "upvote");
        assert_eq!(emoji_name("🎉"), "unknown");
    }
}
