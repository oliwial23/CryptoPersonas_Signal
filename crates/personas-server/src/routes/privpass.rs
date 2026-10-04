//! Privacy Pass: request an anonymous, unlinkable ticket now, redeem it later for a
//! callback, without the redemption revealing which request produced it. See
//! `personas_core::privpass` and `docs/FINDINGS.md` O7.

use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use personas_core::circuits::arg_rep;
use personas_core::privpass::{
    badge_flag, clone_exec_meth, decode_badge_redemption, decode_post_redemption,
    decode_redemption, decode_ticket_request, encode_validated_tickets, issue_tickets,
    redemption_key, ticket_pseudonym, verify_redemption,
};
use personas_core::{persona, F};
use transport_api::{ConversationId, MessageId, Outgoing};

use crate::bulletin::{self, bulk, epoch, verify_and_store};
use crate::error::{AppError, AppResult, ok};
use crate::routes::moderation::call;
use crate::state::{Namespace, ServerLock};

/// The batch-ticket proving key a client needs to build a [`TicketRequest`]
/// (`personas_core::privpass::request_ticket`).
pub async fn batch_proving_key(State(state): State<ServerLock>) -> AppResult<Bytes> {
    bulk(&state.read().await.privpass.batch_proving_key)
}

/// Request one anonymous ticket: prove the standard interaction (the same proof an
/// anonymous post already makes) and, in the same call, blind one resulting callback
/// ticket for redemption later. No message is relayed — proof-only, like
/// `/api/interact/standard`, whose comment names this exact route as workstream b's
/// answer to O7.
pub async fn issue(State(state): State<ServerLock>, body: Bytes) -> AppResult<Response> {
    let request = decode_ticket_request(&body)
        .map_err(|e| AppError::BadRequest(format!("that is not a ticket request: {e}")))?;

    let mut st = state.write().await;
    let standard_vk = st.keys.standard_verifying_key.clone();
    let current = epoch(&st.db);

    let object = request.exec_meth.new_object;
    let old_nul = request.exec_meth.old_nullifier;

    // `issue_tickets`'s internal check looks the new object up in the bulletin, so the
    // interaction has to actually be appended first — `ExecutedMethod` can't be cloned
    // via `derive(Clone)` (it requires `Snark: Clone`, which `Groth16` doesn't
    // implement), hence the manual `clone_exec_meth`.
    let exec_meth_for_append = clone_exec_meth(&request.exec_meth);
    verify_and_store(
        &mut st.db,
        &standard_vk,
        exec_meth_for_append,
        F::from(0),
        current,
        bulletin::INTERACTION,
    )?;

    let memb_data = st.db.obj_bul.get_pubkey();
    let batch_vk = st.privpass.batch_verifying_key.clone();
    let validated = issue_tickets(
        &request,
        object,
        old_nul,
        memb_data,
        &standard_vk,
        &batch_vk,
        &st.db.obj_bul,
        &st.privpass.issuer,
    )
    .map_err(|e| AppError::Rejected(format!("ticket blinding rejected: {e}")))?;

    tracing::info!("issued a privacy-pass ticket");
    let bytes = encode_validated_tickets(&validated)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("could not encode the ticket: {e}")))?;
    Ok((axum::http::StatusCode::OK, bytes).into_response())
}

/// Redeem a ticket for a specific badge — `1` Faculty, `2` Student, `3` Industry,
/// matching `approve_badge`'s own numbering. Not a free-form argument: unlike a real
/// badge request, this skips `badge_pred`'s eligibility proof entirely, applying the
/// flag on possession of a valid, unspent ticket alone — an accepted simplification
/// for now (no admin gate), not something to read as "eligibility-checked."
pub async fn redeem_badge(State(state): State<ServerLock>, body: Bytes) -> AppResult<Response> {
    let request = decode_badge_redemption(&body)
        .map_err(|e| AppError::BadRequest(format!("that is not a badge redemption: {e}")))?;
    let flag = badge_flag(request.index)
        .ok_or_else(|| AppError::BadRequest("badge index must be 1, 2, or 3".into()))?;
    let redemption = request.redemption;

    let mut st = state.write().await;
    if !verify_redemption(&st.privpass.issuer, &redemption) {
        return Err(AppError::Rejected("the ticket did not verify".into()));
    }
    let key = hex::encode(redemption_key(&redemption));
    if !st.privpass.spent.mark_spent(key)? {
        return Err(AppError::Rejected(
            "this ticket has already been redeemed".into(),
        ));
    }

    call(&mut st, redemption.callback, flag)?;

    tracing::info!("a privacy-pass ticket was redeemed for a badge");
    Ok(ok())
}

/// Redeem a ticket to post one message, optionally threaded as a reply
/// (Signal-only in practice — Slack callers never set `reply_to`, since Slack
/// replies work by thread context, not a quoted message id, and nothing in the CLI
/// exposes it there). `use_persona` picks a fresh, ticket-derived pseudonym (see
/// `personas_core::privpass::ticket_pseudonym` for why it's derived from the ticket
/// rather than chosen freely) or posts with none at all. Shared by all four
/// posting routes; `ns` picks which channel/transport actually relays it.
async fn redeem_post(
    state: ServerLock,
    ns: Namespace,
    use_persona: bool,
    body: Bytes,
) -> AppResult<Response> {
    let request = decode_post_redemption(&body)
        .map_err(|e| AppError::BadRequest(format!("that is not a post redemption: {e}")))?;

    let mut st = state.write().await;
    if !verify_redemption(&st.privpass.issuer, &request.redemption) {
        return Err(AppError::Rejected("the ticket did not verify".into()));
    }
    let key = hex::encode(redemption_key(&request.redemption));
    if !st.privpass.spent.mark_spent(key)? {
        return Err(AppError::Rejected(
            "this ticket has already been redeemed".into(),
        ));
    }
    drop(st);

    let mut msg = Outgoing::new(ConversationId(request.channel), request.message);
    if use_persona {
        msg.persona = Some(persona::petname(ticket_pseudonym(&request.redemption)));
    }
    if let Some(ts) = request.reply_to {
        msg.reply_to = Some(MessageId::from(ts));
    }

    let transport = state.read().await.channel(ns).transport.clone();
    transport.send(msg).await?;

    tracing::info!(use_persona, "a privacy-pass ticket was redeemed for a post");
    Ok(ok())
}

pub async fn redeem_post_signal(State(state): State<ServerLock>, body: Bytes) -> AppResult<Response> {
    redeem_post(state, Namespace::Signal, false, body).await
}

pub async fn redeem_post_slack(State(state): State<ServerLock>, body: Bytes) -> AppResult<Response> {
    redeem_post(state, Namespace::Slack, false, body).await
}

pub async fn redeem_pseudo_post_signal(
    State(state): State<ServerLock>,
    body: Bytes,
) -> AppResult<Response> {
    redeem_post(state, Namespace::Signal, true, body).await
}

pub async fn redeem_pseudo_post_slack(
    State(state): State<ServerLock>,
    body: Bytes,
) -> AppResult<Response> {
    redeem_post(state, Namespace::Slack, true, body).await
}

/// Redeem a ticket for a small, fixed reputation bump (+1) — reusing `call()`, the
/// same mechanism `reputation`'s own route uses, just with a fixed amount instead of
/// the ledger's accumulated rating. Fixed rather than free-form for the same reason
/// badge redemption is limited to three flags: an arbitrary caller-chosen amount
/// would let anyone inflate their own reputation without limit.
pub async fn redeem_reputation(State(state): State<ServerLock>, body: Bytes) -> AppResult<Response> {
    let redemption = decode_redemption(&body)
        .map_err(|e| AppError::BadRequest(format!("that is not a redemption: {e}")))?;

    let mut st = state.write().await;
    if !verify_redemption(&st.privpass.issuer, &redemption) {
        return Err(AppError::Rejected("the ticket did not verify".into()));
    }
    let key = hex::encode(redemption_key(&redemption));
    if !st.privpass.spent.mark_spent(key)? {
        return Err(AppError::Rejected(
            "this ticket has already been redeemed".into(),
        ));
    }

    call(&mut st, redemption.callback, arg_rep(1))?;

    tracing::info!("a privacy-pass ticket was redeemed for a reputation bump");
    Ok(ok())
}

/// The issuer's public key — every client needs it to unblind a validated batch
/// (`store_validated_tickets`).
pub async fn issuer_pubkey(State(state): State<ServerLock>) -> AppResult<Bytes> {
    bulk(&state.read().await.privpass.issuer.pubkey)
}
