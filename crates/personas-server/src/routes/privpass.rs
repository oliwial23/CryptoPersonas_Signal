//! Privacy Pass: request an anonymous, unlinkable ticket now, redeem it later for a
//! callback, without the redemption revealing which request produced it. See
//! `personas_core::privpass` and `docs/FINDINGS.md` O7.

use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use personas_core::privpass::{
    clone_exec_meth, decode_redemption, decode_ticket_request, encode_validated_tickets,
    issue_tickets, redemption_key, verify_redemption,
};
use personas_core::F;

use crate::bulletin::{self, bulk, epoch, verify_and_store};
use crate::error::{AppError, AppResult, ok};
use crate::state::ServerLock;

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

/// Redeem a previously validated ticket. Anonymous: nothing here names which
/// `issue` call produced it, or which member requested it.
pub async fn redeem(State(state): State<ServerLock>, body: Bytes) -> AppResult<Response> {
    let redemption = decode_redemption(&body)
        .map_err(|e| AppError::BadRequest(format!("that is not a ticket redemption: {e}")))?;

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

    tracing::info!("a privacy-pass ticket was redeemed");
    Ok(ok())
}

/// The issuer's public key — every client needs it to unblind a validated batch
/// (`store_validated_tickets`).
pub async fn issuer_pubkey(State(state): State<ServerLock>) -> AppResult<Bytes> {
    bulk(&state.read().await.privpass.issuer.pubkey)
}
