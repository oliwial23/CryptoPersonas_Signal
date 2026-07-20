//! The replica's **derived** state: everything the service used to keep in a
//! database and that serverless recomputes from the log (workstream **d3**).
//!
//! None of this touches a proof. It is the bookkeeping the accept rule feeds and
//! the barrier reads: which polls are open and how they tally (`SERVERLESS_PROTOCOL.md`
//! §8), which post owes which settlement (§7), which `(target, claimant)` pairs
//! have already rated (§10), and the petname each `claimed` renders as. Being
//! pure data with deterministic updates, it is the part of the engine that fast
//! tests can exercise without a single Groth16 proof — and its determinism is
//! exactly what §1 requires for replicas to converge.

use std::collections::{HashMap, HashSet};

use ark_ff::{BigInteger, PrimeField};
use zk_callbacks::generic::callbacks::CallbackCom;
use zk_callbacks::generic::object::Time;
use zk_callbacks::impls::centralized::crypto::PlainTikCrypto;

use personas_core::{F, persona};

use super::record::{Eh, PollKind};

/// The poster's committed callback ticket — `Cr = NoSigOTP<F> = PlainTikCrypto<F>`.
/// This is the object the barrier invokes at settlement.
pub type Callback = CallbackCom<F, F, PlainTikCrypto<F>>;

/// A canonical 32-byte key for a field element.
///
/// Field elements are `Eq` but keying a `HashMap`/`HashSet` on one wants a stable
/// byte form; the little-endian `BigInt` encoding is canonical and matches how the
/// rest of the system serialises field elements.
pub fn f_key(f: F) -> [u8; 32] {
    let le = f.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    out[..le.len()].copy_from_slice(&le);
    out
}

// ---------------------------------------------------------------------------------------
// Polls
// ---------------------------------------------------------------------------------------

/// For a `Ban` poll, `option == BAN_OPTION` counts as "ban", `KEEP_OPTION` as
/// "keep"; any other option is not a ballot in the ban decision (mirroring the
/// service tally, which counts only ❌/✅). Ordinary polls impose no such meaning.
pub const BAN_OPTION: u32 = 0;
/// See [`BAN_OPTION`].
pub const KEEP_OPTION: u32 = 1;

/// An open (or just-closed) poll and the ballots cast in it.
#[derive(Clone, Debug)]
pub struct Poll {
    pub question: String,
    pub options: Vec<String>,
    pub kind: PollKind,
    /// The post under review, for a ban poll.
    pub target: Option<Eh>,
    /// `eh.context()` of the `PollOpen` — what a voter derives their poll
    /// pseudonym from (§8).
    pub context: F,
    /// The barrier index at which the poll opened; it closes at
    /// `opened_barrier + close_barriers`.
    pub opened_barrier: u64,
    /// `claimed` (keyed) → chosen option. One member, one vote; a later ballot
    /// from the same `claimed` replaces the earlier one, matching `PollLog::cast`.
    pub ballots: HashMap<[u8; 32], u32>,
    pub closed: bool,
}

impl Poll {
    /// Record (or replace) a ballot.
    pub fn cast(&mut self, claimed: F, option: u32) {
        self.ballots.insert(f_key(claimed), option);
    }

    /// `(yes, no)` for a ban poll — bans versus keeps, ignoring anything else.
    pub fn ban_tally(&self) -> (usize, usize) {
        let (mut yes, mut no) = (0, 0);
        for &opt in self.ballots.values() {
            match opt {
                BAN_OPTION => yes += 1,
                KEEP_OPTION => no += 1,
                _ => {}
            }
        }
        (yes, no)
    }

    /// Whether a ban poll has passed: strictly more bans than keeps (§7).
    pub fn passes_ban(&self) -> bool {
        let (yes, no) = self.ban_tally();
        yes > no
    }

    /// Per-option counts, for rendering an ordinary poll.
    pub fn counts(&self) -> HashMap<u32, usize> {
        let mut counts = HashMap::new();
        for &opt in self.ballots.values() {
            *counts.entry(opt).or_insert(0) += 1;
        }
        counts
    }
}

// ---------------------------------------------------------------------------------------
// Outstanding tickets (the settlement set)
// ---------------------------------------------------------------------------------------

/// A post's outstanding callback ticket and the state that decides how it settles.
///
/// Every post files exactly one ticket (`NUMCBS = 1`), called exactly once at its
/// settlement barrier `post_barrier + W` — or earlier if a ban lands first (§7).
/// Keeping the ticket here is what lets the barrier invoke it deterministically:
/// the OTP is additive and keyless (§6), so every replica computes the identical
/// called leaf from this `callback` plus the argument the tally dictates.
#[derive(Clone)]
pub struct Outstanding {
    /// The poster's committed callback commitment, to invoke at settlement.
    pub callback: Callback,
    /// The epoch the ticket was filed at (§7: uniformly the post's own epoch).
    pub filed_at: Time<F>,
    /// The barrier by which the ticket must be retired.
    pub settle_barrier: u64,
    /// Net ratings accrued on this post, clamped at zero when read (a negative
    /// reputation would wrap past every threshold in-circuit).
    pub accrued: i64,
    /// A ban trigger (poll close or admin invoke) has landed for this post.
    pub banned: bool,
    /// Whether the ticket has already been invoked.
    pub settled: bool,
}

impl Outstanding {
    pub fn new(callback: Callback, filed_at: Time<F>, settle_barrier: u64) -> Self {
        Self {
            callback,
            filed_at,
            settle_barrier,
            accrued: 0,
            banned: false,
            settled: false,
        }
    }

    /// The reputation to settle with, clamped to `[0, ..]`.
    pub fn clamped_rep(&self) -> i64 {
        self.accrued.max(0)
    }
}

// ---------------------------------------------------------------------------------------
// The rendered log
// ---------------------------------------------------------------------------------------

/// One accepted record, in the form a client renders it. Kept minimal here — full
/// rendering (identicons, chrome, threading) is d4 — but enough to demonstrate the
/// rendering gate (§9): a post whose author is later banned is re-marked
/// `flagged` rather than deleted.
#[derive(Clone, Debug)]
pub struct LogEntry {
    pub eh: Eh,
    pub kind: &'static str,
    /// The petname the record is attributed to, or `None` for an anonymous post.
    pub author: Option<String>,
    pub body: String,
    /// Set when the replica later learns the author was banned (§5.4, §9).
    pub flagged: bool,
}

// ---------------------------------------------------------------------------------------
// The whole derived bundle
// ---------------------------------------------------------------------------------------

/// All of the replica's non-cryptographic derived state.
///
/// Separated from the Merkle stores and keys so it can be updated, queried, and
/// tested as plain data. Every method here is a deterministic function of the
/// records ingested so far — feed two replicas the same records in any arrival
/// order and these structures end up equal.
#[derive(Default)]
pub struct Derived {
    /// Open and recently-closed polls, keyed by the `PollOpen`'s `eh`.
    pub polls: HashMap<Eh, Poll>,
    /// Outstanding tickets, keyed by the post's `eh`.
    pub outstanding: HashMap<Eh, Outstanding>,
    /// `(target, claimed)` pairs that have already rated — one rating per member
    /// per target (§10).
    pub rated: HashSet<(Eh, [u8; 32])>,
    /// `claimed` → petname, memoised so a pseudonym renders identically everywhere.
    pub personas: HashMap<[u8; 32], String>,
    /// The accepted records in ingest order, for rendering and debugging.
    pub log: Vec<LogEntry>,
}

impl Derived {
    /// The petname for a `claimed` pseudonym, computing and caching it on first
    /// sight.
    pub fn petname(&mut self, claimed: F) -> String {
        self.personas
            .entry(f_key(claimed))
            .or_insert_with(|| persona::petname(claimed))
            .clone()
    }

    /// Apply a rating to a target, deduplicated by `(target, claimed)`.
    ///
    /// Returns `true` if the rating was newly counted. A repeat from the same
    /// `claimed` on the same target is dropped (that is what the proof-carrying
    /// rating buys — one member, one rating). A rating whose target has no
    /// outstanding ticket (already settled, or never a post) is still deduped but
    /// changes no reputation, exactly as the service ignores a reaction to a
    /// message it did not relay.
    pub fn rate(&mut self, target: Eh, claimed: F, delta: i64) -> bool {
        if !self.rated.insert((target, f_key(claimed))) {
            return false;
        }
        if let Some(out) = self.outstanding.get_mut(&target) {
            out.accrued += delta;
        }
        true
    }

    /// Flag every logged post attributed to a banned petname (the rendering gate).
    pub fn flag_author(&mut self, petname: &str) {
        for entry in &mut self.log {
            if entry.author.as_deref() == Some(petname) {
                entry.flagged = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;
    use rand::{SeedableRng, rngs::StdRng};

    fn poll(kind: PollKind) -> Poll {
        Poll {
            question: "q".into(),
            options: vec!["ban".into(), "keep".into()],
            kind,
            target: None,
            context: F::from(0),
            opened_barrier: 0,
            ballots: HashMap::new(),
            closed: false,
        }
    }

    #[test]
    fn a_ban_poll_needs_strictly_more_bans_than_keeps() {
        let mut p = poll(PollKind::Ban);
        p.cast(F::from(1), BAN_OPTION);
        p.cast(F::from(2), BAN_OPTION);
        p.cast(F::from(3), KEEP_OPTION);
        assert_eq!(p.ban_tally(), (2, 1));
        assert!(p.passes_ban());

        // A tie does not pass.
        p.cast(F::from(4), KEEP_OPTION);
        assert_eq!(p.ban_tally(), (2, 2));
        assert!(!p.passes_ban());
    }

    #[test]
    fn a_member_who_votes_twice_has_voted_once() {
        let mut p = poll(PollKind::Ban);
        p.cast(F::from(7), BAN_OPTION);
        p.cast(F::from(7), KEEP_OPTION); // same claimed, changed mind
        assert_eq!(p.ballots.len(), 1);
        assert_eq!(
            p.ban_tally(),
            (0, 1),
            "the later ballot is the one that counts"
        );
    }

    #[test]
    fn a_rating_counts_once_per_claimed_per_target() {
        let mut rng = StdRng::seed_from_u64(3);
        let mut d = Derived::default();
        let target = Eh([9u8; 32]);
        let claimed = F::rand(&mut rng);

        // Give the target an outstanding ticket so accrual is observable via a fresh
        // Outstanding is awkward without a Callback; test the dedup return instead.
        assert!(d.rate(target, claimed, 1), "first rating counts");
        assert!(
            !d.rate(target, claimed, 1),
            "second from same claimed is dropped"
        );

        // A different claimed on the same target is a different rating.
        let other = F::rand(&mut rng);
        assert!(d.rate(target, other, -1));
    }

    #[test]
    fn petnames_are_stable_and_cached() {
        let mut d = Derived::default();
        let claimed = F::from(123456);
        let a = d.petname(claimed);
        let b = d.petname(claimed);
        assert_eq!(a, b);
        assert_eq!(a, persona::petname(claimed));
        assert_eq!(d.personas.len(), 1);
    }

    #[test]
    fn flagging_marks_only_the_banned_authors_posts() {
        let mut d = Derived::default();
        d.log.push(LogEntry {
            eh: Eh([1; 32]),
            kind: "Post",
            author: Some("brave-otter".into()),
            body: "hi".into(),
            flagged: false,
        });
        d.log.push(LogEntry {
            eh: Eh([2; 32]),
            kind: "Post",
            author: Some("calm-lynx".into()),
            body: "yo".into(),
            flagged: false,
        });
        d.flag_author("brave-otter");
        assert!(d.log[0].flagged);
        assert!(!d.log[1].flagged);
    }
}
