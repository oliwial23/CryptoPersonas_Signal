//! Privacy Pass: request an anonymous, unlinkable ticket now, redeem it later for a
//! callback, without the redemption revealing which request produced it. See
//! `personas_core::privpass` and `docs/FINDINGS.md` O7.

use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use personas_core::privpass::{
    clone_exec_meth, decode_post_redemption, decode_ticket_request, encode_validated_tickets,
    issue_tickets, redemption_key, rotate_issuer_keys, ticket_pseudonym, verify_redemption,
};
use personas_core::{F, persona};
use transport_api::{ConversationId, MessageId, Outgoing};

use crate::bench;
use crate::bulletin::{bulk, callback_hex, verify_and_append_blind};
use crate::error::{AppError, AppResult, ok};
use crate::state::{Namespace, ServerLock, ServerState};

/// Rotate the ticket issuer key, expiring every unredeemed ticket (`construction`, "Key
/// rotation"). Called at each epoch boundary and on each ban: a ticket's statement was
/// proven at issuance, so without this a member could post with tickets issued before a
/// ban. Clients fetch the new public key with their next request.
pub(crate) fn rotate_ticket_key(st: &mut ServerState) -> AppResult<()> {
    let keys = rotate_issuer_keys(&mut rand::thread_rng(), &st.privpass.data_dir)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("could not rotate the ticket key: {e}")))?;
    st.privpass.issuer = keys;
    tracing::info!("ticket issuer key rotated; unredeemed tickets expired");
    Ok(())
}

/// The batch-ticket proving key a client needs to build a [`TicketRequest`]
/// (`personas_core::privpass::request_ticket`).
pub async fn batch_proving_key(State(state): State<ServerLock>) -> AppResult<Bytes> {
    bulk(&state.read().await.privpass.keys.batch_pk)
}

/// The ticket-interaction proving key (`TICKET_BATCH_SIZE` callbacks per request).
pub async fn interaction_proving_key(State(state): State<ServerLock>) -> AppResult<Bytes> {
    bulk(&state.read().await.privpass.keys.interaction_pk)
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
    let interaction_vk = st.privpass.keys.interaction_vk.clone();

    let object = request.exec_meth.new_object;
    let old_nul = request.exec_meth.old_nullifier;

    // `issue_tickets`'s internal check looks the new object up in the bulletin, so the
    // interaction has to actually be appended first — `ExecutedMethod` can't be cloned
    // via `derive(Clone)` (it requires `Snark: Clone`, which `Groth16` doesn't
    // implement), hence the manual `clone_exec_meth`.
    let exec_meth_for_append = clone_exec_meth(&request.exec_meth);
    let start = std::time::SystemTime::now();
    verify_and_append_blind(&mut st.db, &interaction_vk, exec_meth_for_append, F::from(0))?;

    let memb_data = st.db.obj_bul.get_pubkey();
    let batch_vk = st.privpass.keys.batch_vk.clone();
    let validated = issue_tickets(
        &request,
        object,
        old_nul,
        memb_data,
        &interaction_vk,
        &batch_vk,
        &st.db.obj_bul,
        &st.privpass.issuer,
        crate::bulletin::epoch(&st.db),
    )
    .map_err(|e| AppError::Rejected(format!("ticket blinding rejected: {e}")))?;
    let millis = start
        .elapsed()
        .map(|d| d.as_secs_f64() * 1e3)
        .unwrap_or_default();
    bench::verified("pp_issue", start, millis);

    tracing::info!("issued a privacy-pass ticket");
    let bytes = encode_validated_tickets(&validated)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("could not encode the ticket: {e}")))?;
    Ok((axum::http::StatusCode::OK, bytes).into_response())
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

    // The ticket's MAC must cover this message, so a post cannot be detached from the
    // redemption and replayed with different content.
    let reply = request.reply_to.map(|ts| ts.to_string());
    let payload = persona::server_post_payload(&request.channel, reply.as_deref(), &request.message);
    if request.redemption.data != [payload] {
        return Err(AppError::Rejected(
            "the ticket's MAC does not cover this message".into(),
        ));
    }

    let mut st = state.write().await;
    let start = std::time::SystemTime::now();
    if !verify_redemption(&st.privpass.issuer, &request.redemption) {
        return Err(AppError::Rejected(
            "the ticket did not verify (tickets expire when the epoch turns or a member is banned)"
                .into(),
        ));
    }
    let key = hex::encode(redemption_key(&request.redemption));
    if !st.privpass.spent.mark_spent(key)? {
        return Err(AppError::Rejected(
            "this ticket has already been redeemed".into(),
        ));
    }
    let millis = start
        .elapsed()
        .map(|d| d.as_secs_f64() * 1e3)
        .unwrap_or_default();
    bench::verified("pp_redeem", start, millis);
    drop(st);

    let mut msg = Outgoing::new(ConversationId(request.channel), request.message);
    if use_persona {
        msg.persona = Some(persona::petname(ticket_pseudonym(&request.redemption)));
    }
    if let Some(ts) = request.reply_to {
        msg.reply_to = Some(MessageId::from(ts));
    }

    // Filed against the message like a proved post's callback, so a ticketed post can be
    // banned or rated: the ticket's callback is in the poster's object, and their next scan
    // absorbs whatever is invoked on it.
    let cb_hex = callback_hex(&request.redemption.callback)?;

    let transport = state.read().await.channel(ns).transport.clone();
    let sent = transport.send(msg).await?;
    state
        .write()
        .await
        .channel_mut(ns)
        .records
        .record(&sent.id, cb_hex)?;

    tracing::info!(use_persona, "a privacy-pass ticket was redeemed for a post");
    Ok(ok())
}

pub async fn redeem_post_signal(
    State(state): State<ServerLock>,
    body: Bytes,
) -> AppResult<Response> {
    redeem_post(state, Namespace::Signal, false, body).await
}

pub async fn redeem_post_slack(
    State(state): State<ServerLock>,
    body: Bytes,
) -> AppResult<Response> {
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

/// The issuer's public key — every client needs it to unblind a validated batch
/// (`store_validated_tickets`).
pub async fn issuer_pubkey(State(state): State<ServerLock>) -> AppResult<Bytes> {
    bulk(&state.read().await.privpass.issuer.pubkey)
}
