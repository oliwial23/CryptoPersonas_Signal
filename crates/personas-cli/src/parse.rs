//! The flat command surface for `personas`.
//!
//! There is one command set. Which route family a command posts to, and the exact shape of the
//! request, is chosen by the configured transport (`--transport signal|slack`), not by the
//! command name. The short-flag letters are the ones the Signal CLI (and the `bench/*.py`
//! harness) used — `-m` message, `-g` channel/group, `-c` thread/context, `-i` index,
//! `-t` timestamp, `-e` emoji, `-b` claimed, `-j` second index — so the harness keeps working
//! with nothing changed but `--bin`.
//!
//! Some commands only make sense on one transport (`reply` is Signal-only; `get-rep`,
//! `request-badge`, `approve-badge` are Slack-only). They live in the one flat enum; invoking
//! one against the other transport is a clear error, not a parse failure.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// The `personas` CLI: prove locally, hand the proof to the server, which relays under a
/// persona.
#[derive(Parser)]
#[command(name = "personas", version, about)]
pub struct Cli {
    /// Which route family (and messenger) to talk to. Overrides the profile/config.
    #[arg(long, short = 'T', global = true, value_enum)]
    pub transport: Option<TransportArg>,

    /// Config profile to load (`deploy/profiles/<name>.toml`). Overrides `PERSONAS_PROFILE`.
    #[arg(long, global = true)]
    pub profile: Option<String>,

    /// Server URL. Overrides the profile/config (and `PERSONAS_API`).
    #[arg(long, global = true)]
    pub api: Option<String>,

    /// Client state directory. Overrides the profile/config (and `PERSONAS_DATA_DIR`).
    #[arg(long, global = true)]
    pub data_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

/// The transport a `--transport` flag selects.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum TransportArg {
    Signal,
    Slack,
}

/// Serverless-mode subcommands (workstream d4).
///
/// Serverless has no server to talk to, so these do not use the `--transport`/`--api`
/// HTTP path at all — they drive a local [`Replica`](personas_bulletin::replica) over
/// a messenger transport. Today only the in-process `mock` transport is wired; real
/// Signal arrives with the modified client (e2).
#[derive(Subcommand)]
pub enum MessengerCmd {
    /// Run the flagship serverless demo over the in-process mock transport (M3):
    /// three members converge on a shared log, a ban poll passes, and the banned
    /// persona's post is flagged at every client. Prints each replica's view.
    Demo,
}

impl From<TransportArg> for personas_config::Transport {
    fn from(t: TransportArg) -> Self {
        match t {
            TransportArg::Signal => personas_config::Transport::Signal,
            TransportArg::Slack => personas_config::Transport::Slack,
        }
    }
}

#[derive(Subcommand)]
pub enum Command {
    /// Serverless mode (workstream d4): no server — every client runs a replica of
    /// the group log and verifies locally. Records ride the group chat as messages.
    #[command(subcommand)]
    Messenger(MessengerCmd),

    /// Join as a cryptographic-personas user (mint the callback object, first pseudonym).
    Join,

    /// Post a message anonymously with a callback.
    Post {
        #[arg(long, short = 'm')]
        message: String,
        /// Channel / group id.
        #[arg(long = "channel", short = 'g', alias = "group-id")]
        channel: String,
    },

    /// Post a message under a pseudonym.
    PostPseudo {
        #[arg(long, short = 'm')]
        message: String,
        #[arg(long = "channel", short = 'g', alias = "group-id")]
        channel: String,
        #[arg(long = "pseudo-idx", short = 'i')]
        pseudo_idx: usize,
    },

    /// Post a message under a rate-limited (per-thread) pseudonym.
    PostPseudoRate {
        #[arg(long, short = 'm')]
        message: String,
        #[arg(long = "channel", short = 'g', alias = "group-id")]
        channel: String,
        /// Thread / context id.
        #[arg(long = "thread", short = 'c')]
        thread: String,
        #[arg(long = "pseudo-idx", short = 'i')]
        pseudo_idx: usize,
    },

    /// Open a new thread context. On Signal `-c` is the context string; on Slack pass the
    /// channel with `-g` as well.
    NewThreadCxt {
        /// The thread / context string.
        #[arg(long = "thread", short = 'c')]
        thread: String,
        /// Channel (Slack only).
        #[arg(long = "channel", short = 'g', alias = "group-id")]
        channel: Option<String>,
    },

    /// Download all thread contexts from the server.
    GetContexts,

    /// Generate a new pseudonym.
    GenPseudo,

    /// Print the pseudonym log.
    PseudoIndex,

    /// Scan the next outstanding callback.
    Scan,

    /// Scan all outstanding callbacks via folding. Leaks the number scanned.
    ScanFolding,

    /// Open a poll. Signal takes `-m` (a message); Slack takes `-q` plus `--option1/2[/3/4]`.
    Poll {
        #[arg(long, short = 'm')]
        message: Option<String>,
        #[arg(long, short = 'q')]
        question: Option<String>,
        #[arg(long)]
        option1: Option<String>,
        #[arg(long)]
        option2: Option<String>,
        #[arg(long)]
        option3: Option<String>,
        #[arg(long)]
        option4: Option<String>,
        #[arg(long = "channel", short = 'g', alias = "group-id")]
        channel: String,
    },

    /// Open a ban poll against a message.
    BanPoll {
        #[arg(long, short = 'm')]
        message: Option<String>,
        #[arg(long = "channel", short = 'g', alias = "group-id")]
        channel: String,
        /// Timestamp of the message to ban.
        #[arg(long, short = 't')]
        timestamp: String,
    },

    /// Vote in a poll. Signal binds by `-t` (timestamp) and `-e` (emoji); Slack binds by
    /// `--vote-id` and `--vote`.
    Vote {
        #[arg(long = "channel", short = 'g', alias = "group-id")]
        channel: String,
        #[arg(long, short = 't')]
        timestamp: Option<String>,
        #[arg(long, short = 'e')]
        emoji: Option<String>,
        #[arg(long = "vote-id")]
        vote_id: Option<String>,
        #[arg(long)]
        vote: Option<String>,
    },

    /// Count the votes in a poll. Signal by `-t`; Slack by `--vote-id`.
    CountVotes {
        #[arg(long = "channel", short = 'g', alias = "group-id")]
        channel: String,
        #[arg(long, short = 't')]
        timestamp: Option<String>,
        #[arg(long = "vote-id")]
        vote_id: Option<String>,
    },

    /// Invoke the ban callback the message's poster committed to.
    Ban {
        /// Timestamp of the message to ban.
        #[arg(long, short = 't')]
        t: String,
    },

    /// Apply the reputation delta accumulated on one message (Signal only).
    SingleRep {
        #[arg(long, short = 't')]
        t: String,
    },

    /// Apply every outstanding reputation callback.
    Rep,

    /// Print your reputation score (Slack only).
    GetRep,

    /// Approve every outstanding badge request (Slack only).
    ApproveBadge,

    /// Turn the epoch.
    UpdateEpoch,

    /// React to a message (rate it). Emojis: 👍 up, 👎 down, 🤬 hate, ❌ ban, ✅ not-ban.
    Reaction {
        #[arg(long = "channel", short = 'g', alias = "group-id")]
        channel: String,
        #[arg(long, short = 'e')]
        emoji: String,
        #[arg(long, short = 't')]
        timestamp: String,
    },

    /// Reply to a message (Signal only).
    Reply {
        #[arg(long = "channel", short = 'g', alias = "group-id")]
        channel: String,
        #[arg(long, short = 'm')]
        message: String,
        #[arg(long, short = 't')]
        timestamp: String,
    },

    /// Reply to a message under a pseudonym (Signal only).
    ReplyPseudo {
        #[arg(long = "channel", short = 'g', alias = "group-id")]
        channel: String,
        #[arg(long, short = 'm')]
        message: String,
        #[arg(long, short = 't')]
        timestamp: String,
        #[arg(long = "pseudo-idx", short = 'i')]
        pseudo_idx: usize,
    },

    /// Prove one member authored two pseudonymous messages.
    Authorship {
        #[arg(long = "pseudo-idx1", short = 'i')]
        pseudo_idx1: usize,
        #[arg(long = "pseudo-idx2", short = 'j')]
        pseudo_idx2: usize,
        #[arg(long = "channel", short = 'g', alias = "group-id")]
        channel: String,
    },

    /// Request a badge credential from the moderator (Slack only).
    RequestBadge {
        #[arg(long = "channel", short = 'g', alias = "group-id")]
        channel: String,
        /// Badge index (1 = Faculty, 2 = Student, 3 = Industry).
        #[arg(long, short = 'i')]
        i: u32,
    },

    /// Claim a granted badge under a pseudonym. On Signal pass the claimed string with `-b`;
    /// on Slack it is looked up from the badge log.
    Badge {
        #[arg(long, short = 'i')]
        i: u32,
        /// Claimed pseudonym string (Signal).
        #[arg(long, short = 'b')]
        claimed: Option<String>,
        #[arg(long = "channel", short = 'g', alias = "group-id")]
        channel: String,
    },
}
