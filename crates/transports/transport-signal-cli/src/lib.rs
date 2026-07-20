//! Signal, as-a-service: a phantom bot account relays every persona's post.
//!
//! This is the deployment from the paper's prototype. One Signal account (the "phantom
//! bot") is a member of the group; clients never talk to Signal at all. They send a proof
//! to the personas server, the server verifies it, and — if it verifies — the bot posts the
//! message. Anonymity at the Signal layer is therefore trivial (every message has the same
//! sender) and the server is trusted for delivery. The modified-client design (workstream
//! e2) is what removes that trust; this crate is the honest as-a-service path.
//!
//! # Two consequences of the phantom bot worth knowing
//!
//! **Personas are text, not identity.** Signal has no per-message sender override, so a
//! persona-attributed post is delivered as `FROM: <petname>` prefixed to the body. Nothing
//! at the Signal layer *enforces* that attribution — the proof does, and clients that verify
//! it locally (workstream d) are what make the label meaningful. Slack, which does have a
//! per-message username, renders the same `Outgoing` with a real username override.
//!
//! **Reactions are quoted replies.** A real Signal reaction would come from the bot, not
//! from the member who rated the post, which reveals nothing but also renders as the bot
//! reacting to itself. The as-a-service path has always sent the emoji as a quoted message
//! instead, and this crate keeps that behavior.
//!
//! # What changed in a4b
//!
//! The server used to reach signal-cli by spawning `signal-cli-client` — a binary in this
//! same workspace — at 12 call sites, then parsing its stdout as JSON to recover the message
//! timestamp. This crate calls that crate's JSON-RPC client in-process over one long-lived
//! connection. Same daemon, same wire protocol; no subprocess, no stdout parsing, and a
//! failure to reach the daemon is now a typed error instead of a `serde_json` panic on an
//! empty stdout.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::stream::BoxStream;
use jsonrpsee::async_client::Client;
use serde_json::Value;
use signal_cli_client::jsonrpc::{self, RpcClient};
use tokio::sync::Mutex;
use transport_api::{
    ConversationId, Incoming, MessageId, Outgoing, Poll, PollKind, Result, Sent, Transport,
    TransportError,
};

const NAME: &str = "signal-cli";

/// The signal-cli daemon's default JSON-RPC TCP endpoint (`signal-cli daemon --tcp`).
pub const DEFAULT_DAEMON: &str = "127.0.0.1:7583";

#[derive(Clone, Debug)]
pub struct SignalCliConfig {
    /// The phantom bot's number (`+15551234567`). Every persona post is delivered from it.
    pub account: String,
    pub daemon: SocketAddr,
}

impl SignalCliConfig {
    pub fn new(account: impl Into<String>, daemon: SocketAddr) -> Self {
        Self {
            account: account.into(),
            daemon,
        }
    }
}

pub struct SignalCliTransport {
    config: SignalCliConfig,
    /// Lazily connected and reconnected on drop: the signal-cli daemon is a separate process
    /// with its own lifecycle, and it is entirely normal for it to come up after the server.
    /// Connecting eagerly in `new()` would make server startup depend on daemon startup.
    client: Mutex<Option<Arc<Client>>>,
}

impl SignalCliTransport {
    pub fn new(config: SignalCliConfig) -> Self {
        Self {
            config,
            client: Mutex::new(None),
        }
    }

    /// The live JSON-RPC connection, dialing the daemon if we have none or the last one died.
    async fn client(&self) -> Result<Arc<Client>> {
        let mut guard = self.client.lock().await;

        if let Some(existing) = guard.as_ref() {
            if existing.is_connected() {
                return Ok(existing.clone());
            }
            tracing::warn!("signal-cli daemon connection dropped; reconnecting");
        }

        let client = jsonrpc::connect_tcp(self.config.daemon)
            .await
            .map_err(|e| TransportError::NotConnected {
                transport: NAME,
                source: anyhow::Error::new(e).context(format!(
                    "could not reach the signal-cli daemon at {}; start it with \
                     `signal-cli -a {} daemon --tcp`",
                    self.config.daemon, self.config.account
                )),
            })?;

        let client = Arc::new(client);
        *guard = Some(client.clone());
        Ok(client)
    }

    /// signal-cli returns `{"timestamp": 1699999999123, ...}`; that timestamp *is* the
    /// message id — it is what a later quote or reaction targets, and what the server files
    /// the post's callback under.
    fn message_id(response: &Value) -> Result<MessageId> {
        response
            .get("timestamp")
            .and_then(Value::as_i64)
            .map(|ts| MessageId::from(ts as u64))
            .ok_or_else(|| TransportError::Protocol {
                transport: NAME,
                source: anyhow::anyhow!("send response has no timestamp field: {response}"),
            })
    }
}

#[async_trait]
impl Transport for SignalCliTransport {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn send(&self, msg: Outgoing) -> Result<Sent> {
        if msg.ephemeral_to.is_some() {
            return Err(TransportError::Unsupported {
                transport: NAME,
                capability: "ephemeral (per-user) messages",
            });
        }

        let body = render(&msg);
        let client = self.client().await?;

        // signal-cli quotes by (timestamp, author). The author is always the phantom bot,
        // because the bot is what posted the message being quoted. An empty quote-message is
        // what the shell-out passed and what signal-cli expects when the quoted text is not
        // being echoed back.
        let (quote_timestamp, quote_author, quote_message) = match &msg.reply_to {
            Some(target) => {
                let ts = target.as_u64().ok_or_else(|| TransportError::Protocol {
                    transport: NAME,
                    source: anyhow::anyhow!(
                        "cannot quote {target}: Signal message ids are millisecond timestamps"
                    ),
                })?;
                (
                    Some(ts),
                    Some(self.config.account.clone()),
                    Some(String::new()),
                )
            }
            None => (None, None, None),
        };

        let attachments = msg
            .attachments
            .iter()
            .map(|a| encode_attachment(a))
            .collect::<Vec<_>>();

        let response = client
            .send(
                Some(self.config.account.clone()),
                vec![],                       // recipients: unused, we send to a group
                vec![msg.conversation.0.clone()], // groupIds
                false,                        // noteToSelf
                false,                        // endSession
                body,
                attachments,
                vec![], // mentions
                vec![], // textStyle
                quote_timestamp,
                quote_author,
                quote_message,
                vec![], // quoteMention
                vec![], // quoteTextStyle
                vec![], // quoteAttachment
                None,   // preview_url
                None,   // preview_title
                None,   // preview_description
                None,   // preview_image
                None,   // sticker
                None,   // storyTimestamp
                None,   // storyAuthor
                None,   // editTimestamp
            )
            .await
            .map_err(|e| TransportError::Send {
                transport: NAME,
                source: anyhow::anyhow!("{e:?}"),
            })?;

        Ok(Sent {
            id: Self::message_id(&response)?,
            conversation: msg.conversation,
        })
    }

    async fn react(
        &self,
        conversation: &ConversationId,
        target: &MessageId,
        emoji: &str,
    ) -> Result<()> {
        // Quoted message, not `sendReaction` — see the module docs: a real reaction would be
        // attributed to the phantom bot, which is both misleading and useless as a rating.
        let quote = Outgoing::new(conversation.clone(), emoji).replying_to(target.clone());
        self.send(quote).await.map(|_| ())
    }

    async fn subscribe(&self) -> Result<BoxStream<'static, Incoming>> {
        let client = self.client().await?;

        let subscription = client
            .subscribe_receive(Some(self.config.account.clone()))
            .await
            .map_err(|e| TransportError::NotConnected {
                transport: NAME,
                source: anyhow::anyhow!("subscribeReceive failed: {e:?}"),
            })?;

        // Hold the client alive for as long as the stream: dropping the last `Arc<Client>`
        // closes the connection out from under the subscription.
        let state = (subscription, client);

        Ok(Box::pin(futures_util::stream::unfold(
            state,
            |(mut subscription, client)| async move {
                loop {
                    match subscription.next().await {
                        Some(Ok(envelope)) => match parse_envelope(&envelope) {
                            Some(event) => return Some((event, (subscription, client))),
                            // Receipts, typing indicators, sync messages: not persona traffic.
                            None => continue,
                        },
                        Some(Err(e)) => {
                            tracing::warn!("signal-cli sent an envelope we could not read: {e}");
                            continue;
                        }
                        None => return None,
                    }
                }
            },
        )))
    }
}

/// How an `Outgoing` reads once Signal has flattened it to text.
fn render(msg: &Outgoing) -> String {
    let mut body = String::new();

    if let Some(poll) = &msg.poll {
        body.push_str(&render_poll(poll));
        body.push_str("\n\n");
    }

    // The persona label. Signal cannot set a per-message sender, so the attribution the
    // proof establishes has to live in the body.
    if let Some(persona) = &msg.persona {
        body.push_str("FROM: ");
        body.push_str(persona);
        body.push_str("\n\n");
    }

    body.push_str(&msg.body);
    body
}

/// Signal has no buttons, so a poll is instructions plus the emoji to react with. The
/// reaction is the vote: `forward_vote` turns 👍/👎/❌/✅ into a ballot.
fn render_poll(poll: &Poll) -> String {
    match poll.kind {
        PollKind::Ban => {
            let mut s = String::from("📊 *Ban Poll Initiated*\n");
            s.push_str("React with ❌ to *Ban* or ✅ to *Keep* this user.\n\n");
            s.push_str(
                "This poll was triggered because the following message may contain harmful, \
                 inappropriate, or spam content:",
            );
            s
        }
        PollKind::Standard => {
            let mut s = String::from("📊 *Poll Time!*\n");
            s.push_str("React with 👍 for *Yes*, 👎 for *No*\n");
            s
        }
    }
}

/// signal-cli takes attachments inline as `data:<mime>;base64,<...>`, which is how an
/// MB-scale folded proof rides along without a file on disk that both processes can see.
fn encode_attachment(attachment: &transport_api::Attachment) -> String {
    use base64::Engine as _;
    format!(
        "data:{};base64,{}",
        attachment.content_type,
        base64::engine::general_purpose::STANDARD.encode(&attachment.bytes)
    )
}

/// A signal-cli receive envelope, as much of it as the personas layer cares about.
///
/// `None` for everything that isn't a group message or a reaction: receipts, typing
/// indicators, and sync messages carry no persona traffic.
fn parse_envelope(value: &Value) -> Option<Incoming> {
    let envelope = value.get("envelope")?;
    let sender = envelope
        .get("sourceNumber")
        .or_else(|| envelope.get("source"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    let data = envelope.get("dataMessage")?;
    let conversation = ConversationId(
        data.get("groupInfo")?
            .get("groupId")?
            .as_str()?
            .to_string(),
    );

    if let Some(reaction) = data.get("reaction") {
        return Some(Incoming::Reaction {
            conversation,
            target: MessageId::from(reaction.get("targetSentTimestamp")?.as_u64()?),
            emoji: reaction.get("emoji")?.as_str()?.to_string(),
            sender,
        });
    }

    let sent_timestamp = data.get("timestamp").and_then(Value::as_u64)?;
    Some(Incoming::Message {
        id: MessageId::from(sent_timestamp),
        conversation,
        sender,
        body: data
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        reply_to: data
            .get("quote")
            .and_then(|q| q.get("id"))
            .and_then(Value::as_u64)
            .map(MessageId::from),
        attachments: vec![],
        // The serverless barrier clock (§4/§14): the provider stamps `serverReceivedTimestamp`
        // when *it* received the message and delivers the same value to everyone, so it is safe
        // to bucket by — unlike `dataMessage.timestamp` (the id above), which the sender writes
        // and could backdate. Fall back to the sent timestamp only if an older signal-cli omits
        // it; a demo over the mock never hits that path.
        received_at: envelope
            .get("serverReceivedTimestamp")
            .and_then(Value::as_u64)
            .unwrap_or(sent_timestamp),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persona_becomes_a_from_line_because_signal_has_no_username_override() {
        let msg = Outgoing::new(ConversationId("g".into()), "hello").as_persona("able-mongoose");
        assert_eq!(render(&msg), "FROM: able-mongoose\n\nhello");
    }

    #[test]
    fn anonymous_posts_carry_no_attribution() {
        let msg = Outgoing::new(ConversationId("g".into()), "hello");
        assert_eq!(render(&msg), "hello");
    }

    #[test]
    fn send_response_timestamp_is_the_message_id() {
        let response = serde_json::json!({ "timestamp": 1699999999123i64 });
        assert_eq!(
            SignalCliTransport::message_id(&response).unwrap(),
            MessageId("1699999999123".into())
        );
    }

    #[test]
    fn a_send_with_no_timestamp_is_a_protocol_error_not_a_panic() {
        // The shell-out did `serde_json::from_str(&stdout).unwrap()` here, so a daemon that
        // was not running took the whole request down with a parse panic on empty stdout.
        let response = serde_json::json!({ "error": "no such group" });
        assert!(SignalCliTransport::message_id(&response).is_err());
    }

    #[test]
    fn group_messages_parse_out_of_receive_envelopes() {
        let envelope = serde_json::json!({
            "envelope": {
                "sourceNumber": "+15551112222",
                "dataMessage": {
                    "timestamp": 1700000000000i64,
                    "message": "hi",
                    "groupInfo": { "groupId": "abc=" }
                }
            }
        });

        match parse_envelope(&envelope).expect("a group message is persona traffic") {
            Incoming::Message {
                id,
                conversation,
                body,
                sender,
                ..
            } => {
                assert_eq!(id, MessageId("1700000000000".into()));
                assert_eq!(conversation, ConversationId("abc=".into()));
                assert_eq!(body, "hi");
                assert_eq!(sender, "+15551112222");
            }
            other => panic!("expected a message, got {other:?}"),
        }
    }

    #[test]
    fn receipts_and_typing_indicators_are_not_persona_traffic() {
        let receipt = serde_json::json!({
            "envelope": { "sourceNumber": "+1", "receiptMessage": { "when": 1 } }
        });
        assert!(parse_envelope(&receipt).is_none());
    }

    #[test]
    fn attachments_ride_inline_as_data_uris() {
        let attachment = transport_api::Attachment {
            filename: "scan.bin".into(),
            content_type: "application/octet-stream".into(),
            bytes: b"foobar".to_vec(),
        };
        assert_eq!(
            encode_attachment(&attachment),
            "data:application/octet-stream;base64,Zm9vYmFy"
        );
    }
}
