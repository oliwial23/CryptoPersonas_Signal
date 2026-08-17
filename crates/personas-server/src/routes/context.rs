//! Thread contexts.
//!
//! A pseudonym is derived from a *context* — a random field element the server assigns to a
//! thread. That is what makes a pseudonym mean "the same member, in this thread": posts under
//! one context are linkable to each other, and posts under different contexts are not
//! linkable at all, because the pseudonym is a PRF of the member's key under the context.
//!
//! So a context is not a session token or an id. It is the domain separator that decides
//! *what a pseudonym is scoped to*, and handing out the same context twice would silently
//! link two threads.

use ark_ff::PrimeField;
use ark_std::UniformRand;
use axum::body::Bytes;
use axum::extract::{Json, State};
use personas_core::F;
use serde::Deserialize;
use transport_api::{ConversationId, Outgoing};

use crate::error::{AppError, AppResult};
use crate::state::{ServerLock, ThreadContext};

#[derive(Deserialize)]
pub struct SignalThread {
    pub thread: String,
}

#[derive(Deserialize)]
pub struct SlackThread {
    pub channel: String,
    pub thread: String,
}

/// Open a thread on Signal: assign it a context. Signal has no threads of its own, so nothing
/// is posted — the context is the whole of it.
pub async fn signal_new_thread(
    State(state): State<ServerLock>,
    Json(input): Json<SignalThread>,
) -> AppResult<Bytes> {
    let mut st = state.write().await;

    // Asking twice for the same thread gets the same context back. Assigning a fresh one
    // would make the member's *existing* pseudonym in that thread unreachable, and would
    // silently unlink their earlier posts from their later ones.
    if let Some(existing) = st.signal.contexts.by_thread(&input.thread) {
        return Ok(line(existing)?);
    }

    let entry = st.signal.contexts.add(ThreadContext {
        thread: input.thread,
        context: fresh_context(),
        ts: None,
        topic_echoed: false,
    })?;

    Ok(line(entry)?)
}

/// Open a thread on Slack: post the topic, and remember the message it was posted as, so
/// replies can be threaded under it.
pub async fn slack_new_thread(
    State(state): State<ServerLock>,
    Json(input): Json<SlackThread>,
) -> AppResult<Bytes> {
    if let Some(existing) = state.read().await.slack.contexts.by_thread(&input.thread) {
        return Ok(line(existing)?);
    }

    let transport = state.read().await.slack.transport.clone();
    let sent = transport
        .send(Outgoing::new(
            ConversationId(input.channel),
            format!(
                "🧵 *Thread started:* {} \n Reply in thread here to participate in this \
                 discussion.",
                input.thread
            ),
        ))
        .await?;

    let mut st = state.write().await;
    let entry = st.slack.contexts.add(ThreadContext {
        thread: input.thread,
        context: fresh_context(),
        ts: Some(sent.id.0),
        // Left false: the first reply is what triggers the one reminder echo
        // (FINDINGS O9) — Slack collapses threads, so the opening banner above is easy
        // to miss once replies start arriving.
        topic_echoed: false,
    })?;

    Ok(line(entry)?)
}

/// Every thread and its context — the client downloads this wholesale.
pub async fn signal_contexts(State(state): State<ServerLock>) -> Bytes {
    state.read().await.signal.contexts.as_jsonl().into()
}

pub async fn slack_contexts(State(state): State<ServerLock>) -> Bytes {
    state.read().await.slack.contexts.as_jsonl().into()
}

/// One JSONL line, which is what the client appends to its own `contexts.jsonl`.
fn line(entry: &ThreadContext) -> AppResult<Bytes> {
    let mut json = serde_json::to_string(entry)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("could not encode the context: {e}")))?;
    json.push('\n');
    Ok(json.into())
}

/// A context nobody can predict. `OsRng` rather than a thread RNG: a predictable context is a
/// predictable pseudonym.
fn fresh_context() -> String {
    let mut rng = rand::rngs::OsRng;
    F::rand(&mut rng).into_bigint().to_string()
}
