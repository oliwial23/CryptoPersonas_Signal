//! Everything the server remembers.
//!
//! Two kinds of state live here, and they are not the same kind of thing.
//!
//! **The bulletin** (`db`) is the protocol's state: the object bulletin, the callback
//! bulletin, the epoch. It is what proofs are checked against, and zk-callbacks owns it.
//!
//! **The ledger** is the server's own bookkeeping: which callback belongs to which posted
//! message, how many people upvoted it, which polls are open, what context a thread was
//! assigned. None of it is cryptographic — it is the *service's* memory of what it relayed,
//! and it exists because a callback is committed to before the message has an id, so
//! something has to join the two afterwards.
//!
//! This module is the second kind. It replaces `helpers.rs`, which was eight near-duplicate
//! functions — one signal-flavoured and one slack-flavoured copy of each — reading and
//! rewriting five hardcoded `server/*.jsonl` paths on every call, each one re-parsing the
//! whole file and `expect`ing its way through the result. Every path is now under
//! `PERSONAS_DATA_DIR`, every store is one type, and the signal/slack split is a
//! [`Channel`], not a copy of the code.

mod ledger;

pub use ledger::{
    Ballot, BadgeLog, ContextLog, PollEntry, PollLog, RecordLog, SlackPoll, SpentTicketLog,
    StoredBadge, ThreadContext, VoteState, badge_name, emoji_for, emoji_name,
};

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use personas_core::Store;
use personas_core::params::{FoldingParams, ServerKeys};
use personas_core::privpass::IssuerKeys;
use personas_core::{PK, VK};
use transport_api::Transport;

/// Privacy Pass: the issuer keypair, the (additive, separately-cached) batch-ticket
/// Groth16 keys, and which tickets have already been redeemed. See `docs/FINDINGS.md`
/// O7 and `personas_core::privpass`.
pub struct PrivPassState {
    pub issuer: IssuerKeys,
    pub batch_proving_key: PK,
    pub batch_verifying_key: VK,
    pub spent: SpentTicketLog,
}

/// One messenger, and the server's memory of what it relayed there.
///
/// The Signal and Slack deployments run side by side over the same bulletin and the same
/// circuits — the client picks between them with a route prefix (`/api/…` vs
/// `/api/slack/…`). What differs is the messenger and the ledger of message ids that
/// messenger handed out, so that is exactly what a `Channel` holds.
pub struct Channel {
    pub transport: Arc<dyn Transport>,
    /// Which callback was committed to by the poster of which message, and what its rating
    /// currently stands at.
    pub records: RecordLog,
    /// Thread topics and the context field element each was assigned. A pseudonym is derived
    /// from a context, so the context is what scopes "the same person, in this thread".
    pub contexts: ContextLog,
}

pub struct ServerState {
    /// The protocol's state. Proofs are verified against this and nothing else.
    pub db: Store,
    pub keys: ServerKeys,
    pub folding_keys: FoldingParams,

    pub signal: Channel,
    pub slack: Channel,

    /// Signal polls: a file, because a Signal vote arrives as a message and the tally has to
    /// survive a restart.
    pub polls: PollLog,
    /// Slack polls: a file (FINDINGS O5), mirroring `polls` above. Signal polls always had
    /// this; a Slack poll's tally used to live only in memory and be forgotten on restart.
    pub votes: VoteState,
    /// Badge requests awaiting an admin's approval.
    pub badges: BadgeLog,

    pub privpass: PrivPassState,
}

/// Which messenger's routes a request came in on.
///
/// `/api/x` and `/api/slack/x` are the same protocol over the same bulletin; what differs is
/// the messenger and the ledger of ids it handed out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Namespace {
    Signal,
    Slack,
}

impl ServerState {
    pub fn channel(&self, ns: Namespace) -> &Channel {
        match ns {
            Namespace::Signal => &self.signal,
            Namespace::Slack => &self.slack,
        }
    }

    pub fn channel_mut(&mut self, ns: Namespace) -> &mut Channel {
        match ns {
            Namespace::Signal => &mut self.signal,
            Namespace::Slack => &mut self.slack,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        data_dir: &Path,
        db: Store,
        keys: ServerKeys,
        folding_keys: FoldingParams,
        signal: Arc<dyn Transport>,
        slack: Arc<dyn Transport>,
        privpass_issuer: IssuerKeys,
        privpass_batch_proving_key: PK,
        privpass_batch_verifying_key: VK,
    ) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;

        Ok(Self {
            db,
            keys,
            folding_keys,
            signal: Channel {
                transport: signal,
                records: RecordLog::open(data_dir.join("signal_records.jsonl"))?,
                contexts: ContextLog::open(data_dir.join("signal_contexts.jsonl"))?,
            },
            slack: Channel {
                transport: slack,
                records: RecordLog::open(data_dir.join("slack_records.jsonl"))?,
                contexts: ContextLog::open(data_dir.join("slack_contexts.jsonl"))?,
            },
            polls: PollLog::open(data_dir.join("polls.jsonl"))?,
            votes: VoteState::open(data_dir.join("slack_votes.jsonl"))?,
            badges: BadgeLog::open(data_dir.join("badge_requests.jsonl"))?,
            privpass: PrivPassState {
                issuer: privpass_issuer,
                batch_proving_key: privpass_batch_proving_key,
                batch_verifying_key: privpass_batch_verifying_key,
                spent: SpentTicketLog::open(data_dir.join("privpass_spent.jsonl"))?,
            },
        })
    }
}

/// The lock every handler takes. A write lock, mostly: appending to the bulletin needs one,
/// and appending to the bulletin is what most routes do.
pub type ServerLock = Arc<tokio::sync::RwLock<ServerState>>;
