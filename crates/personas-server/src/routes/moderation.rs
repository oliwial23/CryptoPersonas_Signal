//! Invoking callbacks: banning, applying reputation, granting badges, turning the epoch.
//!
//! This is the only place a member's object is changed by anyone other than the member. It is
//! not a back door — it is the mechanism the paper is about. When a member posts, they hand
//! the service a *callback ticket*: a commitment to a one-shot token that can be redeemed
//! once, to apply one argument to their object, with the change taking effect the next time
//! they scan. The service cannot invent tickets, cannot use one twice, and cannot apply an
//! argument the circuit does not allow. What it can do is decide *whether* to invoke a ticket
//! it holds — and that decision is what these routes are.
//!
//! So a ban is not the server reaching into a member's object. It is the server redeeming a
//! token the member gave it when they posted.

use axum::body::Bytes;
use axum::extract::{Json, State};
use axum::response::Response;
use personas_core::circuits::{BADGE1_FLAG, BADGE2_FLAG, BADGE3_FLAG, BAN_FLAG, arg_rep};
use personas_core::{CStore, Cr, F};
use personas_wire::raw;
use serde::Deserialize;
use transport_api::MessageId;
use zk_callbacks::generic::bulletin::CallbackBul;
use zk_callbacks::generic::callbacks::CallbackCom;
use zk_callbacks::generic::service::ServiceProvider;
use zk_callbacks::impls::centralized::crypto::{FakeSigPrivkey, PlainTikCrypto};

use crate::bench;
use crate::bulletin::epoch;
use crate::error::{AppError, AppResult, ok};
use crate::state::{Namespace, ServerLock, ServerState};

pub(crate) type Callback = CallbackCom<F, F, PlainTikCrypto<F>>;

/// Invoke a callback with an argument.
///
/// The argument is not free-form: `get_callbacks()` fixes what a callback may do to an
/// object, and the circuit the member will later scan with enforces it. A service that
/// invoked a ban ticket with a "make me an admin" argument would produce a callback no scan
/// would accept.
///
/// `pub(crate)`: also used by `routes::privpass::redeem_badge`, which invokes the badge
/// flag directly rather than going through `approve_badge`'s admin-approval step — see
/// that route's docs for why that's an accepted, disclosed simplification for now.
pub(crate) fn call(st: &mut ServerState, cb: Callback, arg: F) -> AppResult<()> {
    let called = st
        .db
        .call(cb, arg, FakeSigPrivkey::sk())
        .map_err(|e| AppError::Internal(anyhow::anyhow!("could not invoke the callback: {e:?}")))?;

    let current = epoch(&st.db);

    <CStore as CallbackBul<F, F, Cr>>::verify_call_and_append(
        &mut st.db.callback_bul,
        called.0,
        called.1,
        called.2,
        current,
    )
    .map_err(|e| {
        AppError::Internal(anyhow::anyhow!(
            "the callback bulletin refused the call: {e:?}"
        ))
    })?;

    Ok(())
}

/// The bytes a client hands back to name a callback it wants invoked.
fn parse_callback(bytes: &[u8]) -> AppResult<(Callback, String)> {
    let cb: Callback = raw::decode(bytes)
        .map_err(|e| AppError::BadRequest(format!("that is not a callback: {e}")))?;

    // The ledger keys callbacks by the hex of exactly these bytes.
    Ok((cb, hex::encode(bytes)))
}

/// Ban a member: invoke the callback their offending post committed to, with `BAN_FLAG`.
///
/// Global and permanent: the next scan the member performs absorbs it, and from then on every
/// proof they try to make fails the `not banned` predicate. They cannot decline to scan
/// forever — an unscanned member runs out of interactions and cannot post either.
pub async fn ban(State(state): State<ServerLock>, body: Bytes) -> AppResult<Response> {
    let (cb, _hex) = parse_callback(&body)?;

    let mut st = state.write().await;
    call(&mut st, cb, F::from(BAN_FLAG))?;

    tracing::info!("a member has been banned");
    Ok(ok())
}

/// Apply the ratings a message accumulated, then zero them so they cannot be applied twice.
pub async fn reputation(State(state): State<ServerLock>, body: Bytes) -> AppResult<Response> {
    apply_reputation(state, Namespace::Signal, body).await
}

pub async fn slack_reputation(State(state): State<ServerLock>, body: Bytes) -> AppResult<Response> {
    apply_reputation(state, Namespace::Slack, body).await
}

async fn apply_reputation(
    state: ServerLock,
    ns: Namespace,
    body: Bytes,
) -> AppResult<Response> {
    let (cb, cb_hex) = parse_callback(&body)?;

    let mut st = state.write().await;
    let rep = st.channel(ns).records.reputation_of(&cb_hex)?;

    let (result, start, millis) = bench::time(|| call(&mut st, cb, arg_rep(rep)));
    bench::called("rep", start, millis);
    result?;

    // Zero it only once the call has succeeded. Settling first would lose the rating if the
    // bulletin refused the call.
    st.channel_mut(ns).records.settle(&cb_hex)?;

    tracing::info!("reputation {rep} applied");
    Ok(ok())
}

/// Grant a badge an admin has approved.
pub async fn approve_badge(State(state): State<ServerLock>, body: Bytes) -> AppResult<Response> {
    let (cb, cb_hex) = parse_callback(&body)?;

    let mut st = state.write().await;

    let badge = st
        .badges
        .by_callback(&cb_hex)
        .ok_or_else(|| AppError::NotFound(format!("no badge request for callback {cb_hex}")))?;

    // The flag has to match what was *asked for*. A request for a Student badge that gets
    // granted with the Faculty flag would hand the member a badge they never proved they
    // could hold — and the badge-request circuit is what enforces "not both".
    let flag = match (badge.i, badge.claimed.as_str()) {
        (1, "Faculty") => F::from(BADGE1_FLAG),
        (2, "Student") => F::from(BADGE2_FLAG),
        (3, "Industry") => F::from(BADGE3_FLAG),
        (i, claimed) => {
            tracing::warn!("badge request {i}/{claimed} matches no badge; granting nothing");
            F::from(0)
        }
    };

    call(&mut st, cb, flag)?;
    st.badges.grant(&cb_hex)?;

    tracing::info!("badge granted");
    Ok(ok())
}

/// Turn the epoch.
///
/// An epoch bounds how long a callback ticket is good for. Turning it is what stops a service
/// from sitting on a ticket indefinitely and redeeming it long after the post that produced
/// it — and it is why a scan proves against a *specific* epoch.
pub async fn update_epoch(State(state): State<ServerLock>) -> AppResult<Response> {
    let mut st = state.write().await;
    let mut rng = rand::thread_rng();

    let (_, start, millis) = bench::time(|| st.db.callback_bul.update_epoch(&mut rng));
    bench::epoch_updated(start, millis);

    tracing::info!("epoch updated");
    Ok(ok())
}

// ---------------------------------------------------------------------------------------
// Looking callbacks up
// ---------------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SignalTimestamp {
    pub timestamp: u64,
}

#[derive(Deserialize)]
pub struct SlackTimestamp {
    pub timestamp: String,
}

/// The callback filed against a message — what a rater needs in order to ask for it to be
/// invoked.
pub async fn callback_for(
    State(state): State<ServerLock>,
    Json(input): Json<SignalTimestamp>,
) -> AppResult<Bytes> {
    lookup(state, Namespace::Signal, MessageId::from(input.timestamp)).await
}

pub async fn slack_callback_for(
    State(state): State<ServerLock>,
    Json(input): Json<SlackTimestamp>,
) -> AppResult<Bytes> {
    lookup(state, Namespace::Slack, MessageId(input.timestamp)).await
}

async fn lookup(state: ServerLock, ns: Namespace, id: MessageId) -> AppResult<Bytes> {
    let st = state.read().await;

    let cb_hex = st
        .channel(ns)
        .records
        .callback_for(&id)
        .ok_or_else(|| AppError::NotFound(format!("no callback for message {id}")))?;

    let bytes = hex::decode(cb_hex)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("corrupt callback in the ledger: {e}")))?;

    Ok(bytes.into())
}

/// Every callback with a rating waiting to be applied.
pub async fn pending_signal(State(state): State<ServerLock>) -> Json<Vec<String>> {
    Json(state.read().await.signal.records.pending())
}

pub async fn pending_slack(State(state): State<ServerLock>) -> Json<Vec<String>> {
    Json(state.read().await.slack.records.pending())
}

/// Every badge request awaiting an admin.
pub async fn pending_badges(State(state): State<ServerLock>) -> Json<Vec<String>> {
    Json(state.read().await.badges.pending())
}
