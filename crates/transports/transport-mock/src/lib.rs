//! A messenger that isn't one: the chat log lives in memory and, optionally, in a file.
//!
//! This is what makes the system demonstrable and testable with no external account. Until
//! it existed, a post could only be verified as far as the bulletin append — the relay step
//! shelled out to `signal-cli-client`, which is not installed on a fresh checkout, so every
//! post ended in a failed subprocess even though the proof had verified. `docker compose
//! --profile local-mock up` and the integration tests both run against this.
//!
//! It is a *faithful* stand-in, not a stub: it assigns Signal-shaped millisecond message
//! ids, so ids round-trip through the same `MessageId` -> callback-log path as the real
//! thing, and it publishes to [`Transport::subscribe`] so a listener sees its own traffic.
//!
//! What it deliberately does not model: delivery failure, reordering, and latency. The
//! serverless convergence test (workstream d) needs all three, and will drive them through
//! [`MockTransport::inject`] rather than by making the happy path unreliable.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use futures_util::stream::BoxStream;
use tokio::sync::broadcast;
use transport_api::{
    ConversationId, Incoming, MessageId, Outgoing, Result, Sent, Transport, TransportError,
};

/// One delivered message, as the mock recorded it.
#[derive(Clone, Debug, serde::Serialize)]
pub struct MockMessage {
    pub id: String,
    pub conversation: String,
    /// The persona the post was attributed to, if any.
    pub persona: Option<String>,
    pub body: String,
    pub reply_to: Option<String>,
    /// Attachments are recorded by name and size only — a folded Nova proof is megabytes,
    /// and the chat log is meant to stay readable.
    pub attachments: Vec<(String, usize)>,
    pub poll: Option<String>,
}

pub struct MockTransport {
    sent: Mutex<Vec<MockMessage>>,
    events: broadcast::Sender<Incoming>,
    /// Monotonic tiebreaker so two messages sent in the same millisecond get distinct ids.
    seq: AtomicU64,
    /// Mirrors the chat to a JSONL file so a human can watch the demo, and so a test can
    /// assert against it after the process exits.
    log: Option<std::path::PathBuf>,
    /// Echo each message to stdout — the "chat window" of the local-mock profile.
    echo: bool,
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MockTransport {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(1024);
        Self {
            sent: Mutex::new(Vec::new()),
            events,
            seq: AtomicU64::new(0),
            log: None,
            echo: false,
        }
    }

    /// Also append every message to `path` as JSONL.
    pub fn with_log(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.log = Some(path.into());
        self
    }

    /// Also print every message, so `docker compose up` shows a readable conversation.
    pub fn with_echo(mut self) -> Self {
        self.echo = true;
        self
    }

    /// Everything sent so far, in order.
    pub fn history(&self) -> Vec<MockMessage> {
        self.sent.lock().expect("mock chat log poisoned").clone()
    }

    /// Publish an event to every subscriber, as if the group had done it.
    ///
    /// This is how a test drives the receive half: a reaction that should raise reputation,
    /// a vote on a ban poll, a member's reply. Returns the number of subscribers that saw
    /// it — zero is not an error (nobody is listening yet), which is why the send result is
    /// discarded rather than unwrapped.
    pub fn inject(&self, event: Incoming) -> usize {
        self.events.send(event).unwrap_or(0)
    }

    /// Signal-shaped: milliseconds since the epoch. The low bits carry a counter so that
    /// two sends inside one millisecond still get distinct ids; real Signal has the same
    /// property by construction, and the server's callback log assumes ids are unique.
    fn next_id(&self) -> MessageId {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        MessageId::from(now_millis().wrapping_add(n))
    }
}

/// Milliseconds since the Unix epoch — the mock's stand-in for a provider's
/// service-assigned clock (`Incoming::Message::received_at`).
fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the unix epoch")
        .as_millis() as u64
}

#[async_trait]
impl Transport for MockTransport {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn send(&self, msg: Outgoing) -> Result<Sent> {
        let id = self.next_id();

        let record = MockMessage {
            id: id.0.clone(),
            conversation: msg.conversation.0.clone(),
            persona: msg.persona.clone(),
            body: msg.body.clone(),
            reply_to: msg.reply_to.as_ref().map(|m| m.0.clone()),
            attachments: msg
                .attachments
                .iter()
                .map(|a| (a.filename.clone(), a.bytes.len()))
                .collect(),
            poll: msg.poll.as_ref().map(|p| p.id.clone()),
        };

        if self.echo {
            let who = msg.persona.as_deref().unwrap_or("anonymous");
            println!("[{}] {who}: {}", msg.conversation, msg.body);
            if let Some(poll) = &msg.poll {
                println!("        poll {} — {:?}", poll.id, poll.options);
            }
        }

        if let Some(path) = &self.log {
            append_jsonl(path, &record).map_err(|e| TransportError::Send {
                transport: "mock",
                source: e,
            })?;
        }

        self.sent
            .lock()
            .expect("mock chat log poisoned")
            .push(record);

        // A real messenger's own traffic comes back down the receive stream; mirroring it
        // here is what lets a serverless client see its own posts and reach the same
        // replica state as everyone else. `received_at` is the mock standing in for the
        // provider's clock: one value, delivered to every subscriber, so all replicas
        // bucket this message into the same serverless barrier (§4/§14).
        let _ = self.events.send(Incoming::Message {
            id: id.clone(),
            conversation: msg.conversation.clone(),
            sender: "mock-bot".to_string(),
            body: msg.body,
            reply_to: msg.reply_to,
            attachments: msg.attachments,
            received_at: now_millis(),
        });

        Ok(Sent {
            id,
            conversation: msg.conversation,
        })
    }

    async fn react(
        &self,
        conversation: &ConversationId,
        target: &MessageId,
        emoji: &str,
    ) -> Result<()> {
        if self.echo {
            println!("[{conversation}] reaction {emoji} on {target}");
        }
        let _ = self.events.send(Incoming::Reaction {
            conversation: conversation.clone(),
            target: target.clone(),
            emoji: emoji.to_string(),
            sender: "mock-bot".to_string(),
        });
        Ok(())
    }

    async fn subscribe(&self) -> Result<BoxStream<'static, Incoming>> {
        let rx = self.events.subscribe();
        Ok(Box::pin(futures_util::stream::unfold(rx, |mut rx| async {
            loop {
                match rx.recv().await {
                    Ok(event) => return Some((event, rx)),
                    // A slow subscriber missed messages. Dropping them is right for a test
                    // double: the alternative is stalling the sender to preserve a history
                    // that `history()` already has in full.
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("mock transport subscriber lagged, dropped {n} events");
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        })))
    }
}

/// Shared handle, since the server holds one transport behind an `Arc<dyn Transport>` but a
/// test also wants to call `history()` / `inject()` on the concrete type.
pub fn shared() -> (Arc<MockTransport>, Arc<dyn Transport>) {
    let mock = Arc::new(MockTransport::new());
    (mock.clone(), mock)
}

fn append_jsonl(path: &std::path::Path, record: &MockMessage) -> anyhow::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{}", serde_json::to_string(record)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use transport_api::Outgoing;

    #[tokio::test]
    async fn send_assigns_unique_ids_and_records_history() {
        let mock = MockTransport::new();
        let conv = ConversationId("room".into());

        let a = mock
            .send(Outgoing::new(conv.clone(), "first").as_persona("able-mongoose"))
            .await
            .unwrap();
        let b = mock.send(Outgoing::new(conv.clone(), "second")).await.unwrap();

        assert_ne!(a.id, b.id, "message ids key the callback log; they must differ");

        let history = mock.history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].persona.as_deref(), Some("able-mongoose"));
        assert_eq!(history[1].persona, None);
    }

    #[tokio::test]
    async fn subscribers_see_sends_and_injected_events() {
        let mock = MockTransport::new();
        let mut stream = mock.subscribe().await.unwrap();
        let conv = ConversationId("room".into());

        let sent = mock.send(Outgoing::new(conv.clone(), "hello")).await.unwrap();

        match stream.next().await.expect("send should reach subscribers") {
            Incoming::Message { id, body, .. } => {
                assert_eq!(id, sent.id);
                assert_eq!(body, "hello");
            }
            other => panic!("expected a message, got {other:?}"),
        }

        mock.inject(Incoming::Reaction {
            conversation: conv,
            target: sent.id.clone(),
            emoji: "👍".into(),
            sender: "member-1".into(),
        });

        match stream.next().await.expect("injected event should arrive") {
            Incoming::Reaction { target, emoji, .. } => {
                assert_eq!(target, sent.id);
                assert_eq!(emoji, "👍");
            }
            other => panic!("expected a reaction, got {other:?}"),
        }
    }
}
