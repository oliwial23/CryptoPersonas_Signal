//! The messenger abstraction: everything the personas layer needs from Signal, Slack,
//! or a test double, and nothing else.
//!
//! The personas protocol never depends on *which* messenger carries a post. It needs to
//! put a persona-attributed message into a conversation, learn the id the messenger
//! assigned it (that id keys the callback the poster will later be rated on), react to a
//! message, and observe what comes back. That is this trait.
//!
//! Before this existed the server shelled out to `signal-cli-client` at 12 call sites and
//! parsed its stdout as JSON, which meant a post could only be verified as far as the
//! bulletin append: with no `signal-cli` daemon installed the relay always failed. An
//! in-process trait makes [`transport_mock`](../transport_mock) possible, and with it the
//! whole system is testable with no live messenger.
//!
//! # What belongs here
//!
//! Only what more than one messenger can honestly implement. Slack's block kit, Signal's
//! quote semantics, and the socket-mode event envelope stay inside their own crates; what
//! crosses this boundary is "a poll with these options", "a reply to that message". Where a
//! messenger genuinely cannot do something ([`Transport::subscribe`] on a send-only
//! transport), it returns [`TransportError::Unsupported`] rather than pretending.

use async_trait::async_trait;
use futures_util::stream::BoxStream;
use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, TransportError>;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The messenger daemon/API is unreachable — e.g. no `signal-cli` on `127.0.0.1:7583`.
    #[error("transport {transport} is not reachable: {source}")]
    NotConnected {
        transport: &'static str,
        source: anyhow::Error,
    },

    /// The messenger accepted the request and refused it.
    #[error("transport {transport} rejected the message: {source}")]
    Send {
        transport: &'static str,
        source: anyhow::Error,
    },

    /// A capability this messenger does not have. Callers decide whether that is fatal.
    #[error("transport {transport} does not support {capability}")]
    Unsupported {
        transport: &'static str,
        capability: &'static str,
    },

    /// The messenger replied with something we could not interpret.
    #[error("transport {transport} returned an unexpected response: {source}")]
    Protocol {
        transport: &'static str,
        source: anyhow::Error,
    },
}

/// Where a message goes: a Signal group id, a Slack channel id, a mock room name.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConversationId(pub String);

impl From<String> for ConversationId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl std::fmt::Display for ConversationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The id the messenger assigned to a delivered message.
///
/// Signal uses the send timestamp in milliseconds (`1699999999123`); Slack uses a
/// dotted string (`1699999999.000100`). Both are opaque here, so a single server-side
/// record log can key messages from either without a per-transport id type. The one
/// place the distinction resurfaces is `/api/cb` (u64) vs `/api/slack_cb` (string) —
/// both routes exist for compatibility and both land in the same log.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub String);

impl MessageId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Signal ids only: the millisecond timestamp signal-cli quotes messages by.
    pub fn as_u64(&self) -> Option<u64> {
        self.0.parse().ok()
    }
}

impl From<u64> for MessageId {
    fn from(ts: u64) -> Self {
        Self(ts.to_string())
    }
}

impl From<String> for MessageId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A message the personas layer wants delivered.
#[derive(Clone, Debug, Default)]
pub struct Outgoing {
    pub conversation: ConversationId,
    pub body: String,

    /// The persona the post is attributed to (a petname like `capable-mongoose`).
    ///
    /// Slack can set a per-message username, so the post *appears* to come from the
    /// persona. Signal cannot — every message comes from the phantom bot account — so
    /// `transport-signal-cli` prefixes `FROM: <persona>` to the body, which is what the
    /// as-a-service deployment has always done. `None` means an anonymous post.
    pub persona: Option<String>,

    /// Quote it (Signal) / thread it (Slack).
    pub reply_to: Option<MessageId>,

    /// Carries proofs too large to inline; folded Nova scans are MB-scale.
    pub attachments: Vec<Attachment>,

    /// A poll to display. Never interactive — see [`Poll`].
    pub poll: Option<Poll>,

    /// Show this only to one user (Slack ephemeral). Ignored by transports without a
    /// notion of per-user visibility.
    pub ephemeral_to: Option<String>,
}

impl Outgoing {
    pub fn new(conversation: ConversationId, body: impl Into<String>) -> Self {
        Self {
            conversation,
            body: body.into(),
            ..Default::default()
        }
    }

    pub fn as_persona(mut self, persona: impl Into<String>) -> Self {
        self.persona = Some(persona.into());
        self
    }

    pub fn replying_to(mut self, target: MessageId) -> Self {
        self.reply_to = Some(target);
        self
    }

    pub fn with_poll(mut self, poll: Poll) -> Self {
        self.poll = Some(poll);
        self
    }

    pub fn with_attachment(mut self, attachment: Attachment) -> Self {
        self.attachments.push(attachment);
        self
    }
}

#[derive(Clone, Debug)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub bytes: Vec<u8>,
}

/// A vote the group runs among themselves.
///
/// `Ban` polls are the moderation path from the paper: the group votes on whether to
/// revoke a persona, and `target` is the message that prompted it. The distinction is
/// not cosmetic — a ban poll's tally is what `AllowedToRevoke` consults.
///
/// # Why a poll is never a button
///
/// A vote is proof-carrying: the voter proves they are an unbanned member voting under a
/// pseudonym derived from this poll's context, and that proof needs a secret only the voter
/// has. A messenger's button click carries no such proof — and worse, it identifies the
/// clicker to the server *before* the proof arrives, so correlating the two by timing links
/// the pseudonym to the messenger identity, which is precisely what the pseudonym exists to
/// prevent. Slack's block kit could render buttons here; it must not. A transport renders a
/// poll as a *readable* message, including its [`id`](Poll::id), and the member votes from
/// their own client.
#[derive(Clone, Debug)]
pub struct Poll {
    /// Displayed to the group: it is the handle a member passes to their own client to cast
    /// a proof-carrying vote, so it has to be visible, not hidden in messenger metadata.
    pub id: String,
    pub question: String,
    pub options: Vec<String>,
    pub kind: PollKind,
    /// The message under review, for a ban poll.
    pub target: Option<MessageId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PollKind {
    Standard,
    Ban,
}

/// A message that was delivered, and the id the messenger gave it.
#[derive(Clone, Debug)]
pub struct Sent {
    pub id: MessageId,
    pub conversation: ConversationId,
}

/// Something the group did, surfaced to whoever is listening.
///
/// Slack delivers these over socket mode; Signal over `subscribeReceive`; the mock
/// transport by fiat. A serverless client (workstream d) reads persona posts out of
/// exactly this stream.
#[derive(Clone, Debug)]
pub enum Incoming {
    Message {
        id: MessageId,
        conversation: ConversationId,
        /// The messenger's id for the human who sent it — *not* a persona. Personas are
        /// established by proof at the personas layer, never by the transport.
        sender: String,
        body: String,
        reply_to: Option<MessageId>,
        attachments: Vec<Attachment>,
        /// The **service-assigned** receive time, in milliseconds since the Unix epoch —
        /// Signal's `serverReceivedTimestamp`, Slack's `ts`, the mock's own clock. Set by
        /// the *provider* when it received the message, and delivered identically to every
        /// recipient, so all replicas see the same value for the same message.
        ///
        /// This is deliberately **not** [`id`](Incoming::Message::id): a Signal message id
        /// is `dataMessage.timestamp`, which the *sending client* writes and can therefore
        /// backdate (`SERVERLESS_PROTOCOL.md` §4). The serverless barrier cadence buckets a
        /// record by `received_at` precisely because the sender cannot forge it — it is only
        /// ever a coarse settlement-window clock, never the ordering mechanism (that is
        /// prefix-order, §4). `0` when a transport genuinely has no such stamp.
        received_at: u64,
    },
    /// An emoji reaction on a message — the reputation signal.
    Reaction {
        conversation: ConversationId,
        target: MessageId,
        emoji: String,
        sender: String,
    },
    /// The 👍/👎 buttons under a persona post.
    Feedback {
        conversation: ConversationId,
        target: MessageId,
        positive: bool,
        voter: String,
    },
}

/// A messenger, as the personas layer sees it.
#[async_trait]
pub trait Transport: Send + Sync + 'static {
    /// Short name for logs and errors: `signal-cli`, `slack`, `mock`.
    fn name(&self) -> &'static str;

    /// Deliver a message and return the id the messenger assigned it.
    ///
    /// That id is load-bearing: the callback the poster committed to is filed under it,
    /// so a rating on this message can later be applied to the right persona.
    async fn send(&self, msg: Outgoing) -> Result<Sent>;

    /// React to a message.
    ///
    /// Slack adds a real reaction; Signal's as-a-service path posts the emoji as a quoted
    /// message, because the reaction must come from the phantom bot rather than the rater.
    async fn react(&self, conversation: &ConversationId, target: &MessageId, emoji: &str)
    -> Result<()>;

    /// Everything the group does, as it happens.
    ///
    /// Send-only transports return [`TransportError::Unsupported`].
    async fn subscribe(&self) -> Result<BoxStream<'static, Incoming>> {
        Err(TransportError::Unsupported {
            transport: self.name(),
            capability: "subscribe",
        })
    }
}
