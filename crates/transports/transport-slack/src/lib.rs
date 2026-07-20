//! Slack as a [`Transport`].
//!
//! Slack renders personas better than Signal can: it puts an arbitrary `username` on a bot
//! post, so a persona's petname *is* the author line rather than a `FROM:` prefix bolted
//! onto the body (which is all Signal permits), and it has a real reaction API, so a rating
//! is a rating. What it must not do is let a member *vote* by pressing a button — see
//! [`blocks`] for why that is a deanonymization channel and not a convenience.
//!
//! Everything here is translation. This crate does not know what a proof, a bulletin, or a
//! reputation score is; it turns [`Outgoing`] into a Slack API call and Slack's socket-mode
//! events into [`Incoming`]. The JSONL bookkeeping the as-a-service server keeps alongside
//! these calls stays in the server, where the state it belongs to lives.
//!
//! ```no_run
//! # use transport_slack::{SlackConfig, SlackTransport};
//! # use transport_api::{ConversationId, Outgoing, Transport};
//! # async fn example() -> anyhow::Result<()> {
//! let slack = SlackTransport::new(SlackConfig {
//!     bot_token: std::env::var("SLACK_BOT_TOKEN")?,
//!     app_token: std::env::var("SLACK_APP_TOKEN")?,
//! })?;
//!
//! let sent = slack
//!     .send(
//!         Outgoing::new(ConversationId("C0123456789".into()), "hello")
//!             .as_persona("capable-mongoose"),
//!     )
//!     .await?;
//! println!("posted as {}", sent.id);
//! # Ok(())
//! # }
//! ```

pub mod blocks;
mod emoji;
mod events;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use futures_util::StreamExt;
use futures_util::stream::BoxStream;
use slack_morphism::prelude::*;
use tokio::sync::broadcast;
use tracing::{error, info, warn};
use transport_api::{
    ConversationId, Incoming, MessageId, Outgoing, Result, Sent, Transport, TransportError,
};

pub use emoji::slack_reaction_name;

const NAME: &str = "slack";

/// How many events may pile up before a slow subscriber starts missing them.
///
/// A subscriber that lags is told so (`RecvError::Lagged`) and we log it; we do not block
/// the socket-mode listener waiting for it, because a stalled listener means Slack starts
/// re-delivering everything.
const EVENT_BUFFER: usize = 256;

/// The two tokens a Slack app needs: `xoxb-…` to act, `xapp-…` to listen.
#[derive(Clone, Debug)]
pub struct SlackConfig {
    /// Bot token (`xoxb-…`). Authorises `chat.postMessage`, `reactions.add`, the files API.
    pub bot_token: String,
    /// App-level token (`xapp-…`). Only good for opening a socket-mode connection, which is
    /// why [`Transport::subscribe`] is the only method that touches it.
    pub app_token: String,
}

/// A live Slack connection.
///
/// The socket-mode listener is started lazily by the first
/// [`subscribe`](Transport::subscribe) call and then runs for the life of the process —
/// Slack counts open socket connections, and a second listener would deliver every event
/// twice.
pub struct SlackTransport {
    client: Arc<SlackHyperClient>,
    bot_token: SlackApiToken,
    app_token: SlackApiToken,
    events: broadcast::Sender<Incoming>,
    listening: AtomicBool,
}

impl SlackTransport {
    pub fn new(config: SlackConfig) -> Result<Self> {
        let connector = SlackClientHyperConnector::new().map_err(not_connected)?;
        let (events, _) = broadcast::channel(EVENT_BUFFER);

        Ok(Self {
            client: Arc::new(SlackClient::new(connector)),
            bot_token: SlackApiToken::new(config.bot_token.into()),
            app_token: SlackApiToken::new(config.app_token.into()),
            events,
            listening: AtomicBool::new(false),
        })
    }

    /// Post the first attachment, with the body as its comment.
    ///
    /// Slack's external-upload dance is three calls: ask for a URL, PUT the bytes at it,
    /// then tell Slack to share the now-uploaded file into a channel. Only the last of the
    /// three takes a channel and a comment, which is why the body rides along as
    /// `initial_comment` rather than being posted separately — one message, not two.
    async fn send_attachment(&self, msg: &Outgoing) -> std::result::Result<Sent, TransportError> {
        let session = self.client.open_session(&self.bot_token);
        let attachment = &msg.attachments[0];

        if msg.attachments.len() > 1 {
            // `files.completeUploadExternal` would take several files, but each needs its
            // own upload URL and its own PUT. Nothing upstream sends more than one, so
            // rather than half-implement the loop we are loud about ignoring the rest.
            warn!(
                "slack transport: {} attachments given, only the first is sent",
                msg.attachments.len()
            );
        }

        let url_req = SlackApiFilesGetUploadUrlExternalRequest::new(
            attachment.filename.clone(),
            attachment.bytes.len(),
        );
        let url_resp = session
            .get_upload_url_external(&url_req)
            .await
            .map_err(send_failed)?;

        let upload_req = SlackApiFilesUploadViaUrlRequest::new(
            url_resp.upload_url,
            attachment.bytes.clone(),
            attachment.content_type.clone(),
        );
        session
            .files_upload_via_url(&upload_req)
            .await
            .map_err(send_failed)?;

        let complete_req = SlackApiFilesCompleteUploadExternalRequest {
            files: vec![SlackApiFilesComplete::new(url_resp.file_id)],
            channel_id: Some(SlackChannelId::new(msg.conversation.0.clone())),
            initial_comment: (!msg.body.is_empty()).then(|| msg.body.clone()),
            thread_ts: msg.reply_to.as_ref().map(|id| SlackTs::new(id.0.clone())),
        };
        session
            .files_complete_upload_external(&complete_req)
            .await
            .map_err(send_failed)?;

        // `files.completeUploadExternal` answers with file ids, never with the ts of the
        // message Slack wraps the file in. Handing the file id back as a `MessageId` would
        // be a lie — nothing downstream could react to it or thread under it — so the id is
        // empty, exactly as for an ephemeral. The only caller today (the badge claim) posts
        // an image nobody rates and never looks at the id.
        Ok(Sent {
            id: MessageId(String::new()),
            conversation: msg.conversation.clone(),
        })
    }

    /// Show a message to exactly one user.
    ///
    /// `chat.postEphemeral` answers with an empty body — there is no ts, because there is no
    /// message: Slack renders it client-side for one viewer and forgets it. So the [`Sent`]
    /// carries an empty [`MessageId`]. That is honest rather than convenient: an ephemeral
    /// cannot be reacted to, threaded under, or rated, and a caller that tries will find it
    /// has nothing to try with.
    async fn send_ephemeral(
        &self,
        msg: &Outgoing,
        user: &str,
    ) -> std::result::Result<Sent, TransportError> {
        let session = self.client.open_session(&self.bot_token);

        let mut req = SlackApiChatPostEphemeralRequest::new(
            SlackChannelId::new(msg.conversation.0.clone()),
            SlackUserId::new(user.to_string()),
            self.content_for(msg),
        );
        req.username = msg.persona.clone();
        req.thread_ts = msg.reply_to.as_ref().map(|id| SlackTs::new(id.0.clone()));

        session
            .chat_post_ephemeral(&req)
            .await
            .map_err(send_failed)?;

        Ok(Sent {
            id: MessageId(String::new()),
            conversation: msg.conversation.clone(),
        })
    }

    /// A poll becomes a readable ballot; anything else becomes the persona-post layout.
    fn content_for(&self, msg: &Outgoing) -> SlackMessageContent {
        match &msg.poll {
            Some(poll) => blocks::poll(poll, &msg.body),
            None => blocks::persona_post(&msg.body),
        }
    }

    /// Open the socket-mode connection and pump its events into the broadcast channel.
    ///
    /// The listener owns the connection for the life of the process: `serve()` only returns
    /// on SIGINT/SIGTERM. It reaches the event `Sender` through Slack's `user_state` bag,
    /// which is the sole channel by which a socket-mode callback can touch anything we own.
    fn spawn_listener(&self) {
        let client = self.client.clone();
        let app_token = self.app_token.clone();
        let tx: events::Events = self.events.clone();

        tokio::spawn(async move {
            let environment = Arc::new(
                SlackClientEventsListenerEnvironment::new(client.clone())
                    .with_error_handler(events::error_handler)
                    .with_user_state(tx),
            );

            let callbacks = SlackSocketModeListenerCallbacks::new()
                .with_interaction_events(events::interaction_handler)
                .with_push_events(events::push_handler);

            let listener = SlackClientSocketModeListener::new(
                &SlackClientSocketModeConfig::new(),
                environment,
                callbacks,
            );

            if let Err(err) = listener.listen_for(&app_token).await {
                error!("slack socket mode connection failed: {err:?}");
                return;
            }

            info!("slack socket mode listener started");
            listener.serve().await;
        });
    }
}

#[async_trait]
impl Transport for SlackTransport {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn send(&self, msg: Outgoing) -> Result<Sent> {
        if !msg.attachments.is_empty() {
            return self.send_attachment(&msg).await;
        }
        if let Some(user) = msg.ephemeral_to.clone() {
            return self.send_ephemeral(&msg, &user).await;
        }

        let session = self.client.open_session(&self.bot_token);
        let mut req = SlackApiChatPostMessageRequest::new(
            SlackChannelId::new(msg.conversation.0.clone()),
            self.content_for(&msg),
        );

        // This is why Slack is the good deployment: the persona is not a prefix on the text,
        // it is the author. Slack lets a bot override `username` per message, so
        // `capable-mongoose` appears to have said this — while the account that actually
        // said it is the same bot for every persona, which is exactly the unlinkability the
        // protocol wants. (`None` leaves the bot's own name, i.e. an anonymous post.)
        req.username = msg.persona.clone();
        req.thread_ts = msg.reply_to.as_ref().map(|id| SlackTs::new(id.0.clone()));

        let response = session.chat_post_message(&req).await.map_err(send_failed)?;

        // Slack echoes the channel back; use its answer rather than the request's, since a
        // caller may have addressed a user id and had it resolved to a DM channel.
        Ok(Sent {
            id: MessageId(response.ts.to_string()),
            conversation: ConversationId(response.channel.to_string()),
        })
    }

    async fn react(
        &self,
        conversation: &ConversationId,
        target: &MessageId,
        emoji: &str,
    ) -> Result<()> {
        let name = slack_reaction_name(emoji).ok_or_else(|| TransportError::Send {
            transport: NAME,
            source: anyhow::anyhow!("no Slack reaction name for {emoji:?}"),
        })?;

        let session = self.client.open_session(&self.bot_token);
        let req = SlackApiReactionsAddRequest::new(
            SlackChannelId::new(conversation.0.clone()),
            SlackReactionName::new(name),
            SlackTs::new(target.0.clone()),
        );

        session.reactions_add(&req).await.map_err(send_failed)?;
        Ok(())
    }

    async fn subscribe(&self) -> Result<BoxStream<'static, Incoming>> {
        // Start the socket exactly once, however many streams are asked for: a second Slack
        // socket connection is a second copy of every event, and a doubled reaction is a
        // doubled reputation delta.
        if self
            .listening
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.spawn_listener();
        }

        // `broadcast` rather than `mpsc` so several consumers (a relay and a serverless
        // client, say) can each see the whole stream. Unfolded by hand because tokio-stream
        // is not a dependency of this workspace.
        let rx = self.events.subscribe();
        let stream = futures_util::stream::unfold(rx, |mut rx| async move {
            loop {
                match rx.recv().await {
                    Ok(event) => return Some((event, rx)),
                    // The subscriber fell behind the socket. Skipping is the only option
                    // available — the events are already gone — but a skipped event is a
                    // lost rating, so it is an error, not a debug line.
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        error!("slack subscriber lagged; {skipped} events dropped");
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        });

        Ok(stream.boxed())
    }
}

fn not_connected(err: impl std::fmt::Debug) -> TransportError {
    TransportError::NotConnected {
        transport: NAME,
        source: anyhow::anyhow!("{err:?}"),
    }
}

/// Slack refused the call.
///
/// `SlackClientError` distinguishes API errors from HTTP ones, but the personas layer cannot
/// do anything different about either, so both arrive as [`TransportError::Send`] with the
/// original text kept for the log.
fn send_failed(err: impl std::fmt::Debug) -> TransportError {
    TransportError::Send {
        transport: NAME,
        source: anyhow::anyhow!("{err:?}"),
    }
}
