//! Socket mode in, [`Incoming`] out.
//!
//! Slack hands its callbacks a `SlackClientEventsUserState` — a type-keyed bag the listener
//! environment was built with. That is the only channel through which a callback can reach
//! anything we own, so the bag holds the [`broadcast::Sender`] that feeds
//! [`SlackTransport::subscribe`](crate::SlackTransport::subscribe). The callbacks are plain
//! functions, not closures, because `with_interaction_events` wants a function pointer.
//!
//! Everything the callbacks do is translation. No reputation, no bulletin, no proofs: a
//! reaction leaves here as "someone put 👍 on message M" and it is the personas layer's job
//! to decide what, if anything, that is worth.

use std::error::Error;
use std::sync::Arc;

use slack_morphism::prelude::*;
use tokio::sync::broadcast;
use tracing::{debug, warn};
use transport_api::{ConversationId, Incoming, MessageId};

use crate::blocks::{ACTION_FEEDBACK_NEGATIVE, ACTION_FEEDBACK_POSITIVE};

pub(crate) type Events = broadcast::Sender<Incoming>;

type SocketResult = std::result::Result<(), Box<dyn Error + Send + Sync>>;

/// Publish, and shrug if nobody is listening.
///
/// A `broadcast::Sender` errors when there are zero receivers, which happens whenever the
/// consumer has dropped its stream but the socket is still open. That is not an error worth
/// tearing the listener down for — the next `subscribe()` will see subsequent events.
fn publish(tx: &Events, event: Incoming) {
    if tx.send(event).is_err() {
        debug!("slack event dropped: no subscribers");
    }
}

pub(crate) fn error_handler(
    err: Box<dyn Error + Send + Sync>,
    _client: Arc<SlackHyperClient>,
    _state: SlackClientEventsUserState,
) -> HttpStatusCode {
    warn!("slack socket listener error: {err:?}");
    HttpStatusCode::BAD_REQUEST
}

/// Button presses: poll votes and the 👍/👎 feedback buttons.
pub(crate) async fn interaction_handler(
    event: SlackInteractionEvent,
    _client: Arc<SlackHyperClient>,
    state: SlackClientEventsUserState,
) -> SocketResult {
    let guard = state.read().await;
    let Some(tx) = guard.get_user_state::<Events>() else {
        warn!("slack interaction arrived with no event sender in user state");
        return Ok(());
    };

    let SlackInteractionEvent::BlockActions(block_action) = &event else {
        debug!("unhandled slack interaction");
        return Ok(());
    };

    let Some(actions) = block_action.actions.as_ref() else {
        return Ok(());
    };

    // Whoever pressed the button is identified to *Slack*, not to the personas layer: this
    // is a Slack user id and it proves nothing. It is usable for a rating, which is not a
    // claim about who the rater is, and useless for a vote, which is.
    let voter = block_action
        .user
        .as_ref()
        .map(|u| u.id.to_string())
        .unwrap_or_default();
    let conversation = block_action
        .channel
        .as_ref()
        .map(|c| ConversationId(c.id.to_string()));

    for action in actions {
        let action_id = action.action_id.0.as_str();
        let Some(conversation) = conversation.clone() else {
            warn!("slack block action {action_id} has no channel; dropped");
            continue;
        };

        // Polls no longer render buttons (see `blocks`), but a poll posted before this
        // change still has live ones. A press is deliberately inert: turning it into a vote
        // would mean the server casting a ballot nobody proved, and would leak the presser's
        // Slack identity into the timing of the pseudonymous proof that followed.
        if action_id.starts_with("vote_") {
            debug!("ignoring a vote button press: a vote must carry a proof from its voter");
            continue;
        }

        let positive = match action_id {
            ACTION_FEEDBACK_POSITIVE => true,
            ACTION_FEEDBACK_NEGATIVE => false,
            _ => continue,
        };

        // Feedback is a rating *of a message*, so it is worthless without the message's ts:
        // that ts is what the poster's callback was filed under.
        let Some(target) = block_action
            .message
            .as_ref()
            .map(|m| MessageId(m.origin.ts.to_string()))
        else {
            warn!("slack feedback button pressed with no message ts; dropped");
            continue;
        };

        publish(
            tx,
            Incoming::Feedback {
                conversation,
                target,
                positive,
                voter: voter.clone(),
            },
        );
    }

    Ok(())
}

/// Messages and reactions.
pub(crate) async fn push_handler(
    event: SlackPushEventCallback,
    _client: Arc<SlackHyperClient>,
    state: SlackClientEventsUserState,
) -> SocketResult {
    let guard = state.read().await;
    let Some(tx) = guard.get_user_state::<Events>() else {
        warn!("slack push event arrived with no event sender in user state");
        return Ok(());
    };

    match event.event {
        SlackEventCallbackBody::Message(message) => {
            if let Some(incoming) = message_to_incoming(message) {
                publish(tx, incoming);
            }
        }
        SlackEventCallbackBody::ReactionAdded(reaction) => {
            // Reactions on files are not reactions on messages, and only a message has the
            // ts a callback is keyed by, so there is nothing to report for the file case.
            let SlackReactionsItem::Message(history) = reaction.item else {
                debug!("reaction on a non-message item ignored");
                return Ok(());
            };
            let Some(channel) = history.origin.channel else {
                warn!("slack reaction with no channel; dropped");
                return Ok(());
            };

            publish(
                tx,
                Incoming::Reaction {
                    conversation: ConversationId(channel.to_string()),
                    target: MessageId(history.origin.ts.to_string()),
                    // Slack's own shortname (`+1`, `thumbsdown`, …), not a codepoint.
                    // `SlackTransport::react` accepts these verbatim, so a reaction observed
                    // here can be echoed back without a translation table.
                    emoji: reaction.reaction.0,
                    sender: reaction.user.to_string(),
                },
            );
        }
        _ => {}
    }

    Ok(())
}

/// A Slack message event as the personas layer sees it, or `None` if it is not really a
/// message.
///
/// Edits and deletions carry a different ts than the message they concern, so treating them
/// as new messages would attribute a rating to the wrong post. They are dropped rather than
/// half-modelled. Bot posts are *not* dropped: a persona's own message comes back as a bot
/// message with the persona in `username`, and a serverless client reads persona posts out
/// of this very stream.
fn message_to_incoming(message: SlackMessageEvent) -> Option<Incoming> {
    if matches!(
        message.subtype,
        Some(SlackMessageEventType::MessageChanged) | Some(SlackMessageEventType::MessageDeleted)
    ) {
        return None;
    }

    let conversation = ConversationId(message.origin.channel?.to_string());
    let ts = message.origin.ts.to_string();
    let id = MessageId(ts.clone());

    // A thread parent repeats its own ts in `thread_ts`; only a genuine reply points
    // elsewhere.
    let reply_to = message
        .origin
        .thread_ts
        .filter(|t| t != &message.origin.ts)
        .map(|t| MessageId(t.to_string()));

    let sender = message
        .sender
        .user
        .map(|u| u.to_string())
        .or_else(|| message.sender.bot_id.map(|b| b.to_string()))
        .or_else(|| message.sender.username.clone())
        .unwrap_or_default();

    let body = message
        .content
        .as_ref()
        .and_then(|c| c.text.clone())
        .unwrap_or_default();

    Some(Incoming::Message {
        id,
        conversation,
        sender,
        body,
        reply_to,
        // Slack does not push file *bytes*, only metadata with a `url_private` that needs a
        // second, bot-token-authenticated GET. Downloading megabyte-scale proofs on every
        // message event is not something a transport should decide to do, so attachments
        // are reported as absent until a caller asks for them explicitly.
        attachments: Vec::new(),
        // Slack's `ts` (`1699999999.000100`) is assigned by Slack's servers and is the same
        // for every recipient, so it is the service clock the serverless barrier cadence
        // buckets by (§4/§14).
        received_at: slack_ts_millis(&ts),
    })
}

/// Convert a Slack `ts` (`"<seconds>.<microseconds>"`) to milliseconds since the
/// Unix epoch. A malformed ts (never expected from Slack) buckets at `0`.
fn slack_ts_millis(ts: &str) -> u64 {
    ts.parse::<f64>().map(|s| (s * 1000.0) as u64).unwrap_or(0)
}
