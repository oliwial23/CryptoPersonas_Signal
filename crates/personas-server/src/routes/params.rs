//! Everything the client downloads before it can prove anything: proving keys, the bulletin
//! public keys, the bulletin itself, the epoch.
//!
//! All read-only, all bulk. None of it goes through `personas-wire`'s envelope — see
//! `personas_wire::raw` for why compressing a proving key would be a bad trade.

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use ark_ff::{BigInteger, PrimeField};
use personas_core::F;
use serde::Serialize;

use crate::bulletin::{bulk, epoch};
use crate::error::AppResult;
use crate::state::ServerLock;

/// Each key answers a different question the client may need to prove.
macro_rules! proving_key {
    ($(#[$doc:meta])* $name:ident => $field:ident) => {
        $(#[$doc])*
        pub async fn $name(State(state): State<ServerLock>) -> AppResult<Bytes> {
            bulk(&state.read().await.keys.$field)
        }
    };
}

proving_key!(
    /// Posting: not banned, within the rate limit.
    standard => standard_proving_key
);
proving_key!(
    /// Posting under a pseudonym.
    standard_pseudo => standard_pseudo_proving_key
);
proving_key!(
    /// Posting under a rate-limited pseudonym.
    standard_pseudor => standard_pseudor_proving_key
);
proving_key!(
    /// Asking for a badge.
    badge_request => badge_request_proving_key
);
proving_key!(
    /// Scanning one callback.
    scan => scan_proving_key
);
proving_key!(
    /// Proving a pseudonym — the key a vote is proved under.
    pseudonym_pred => pseudonym_pred_proving_key
);
proving_key!(
    /// Proving two pseudonyms share an author.
    authorship_pred => authorship_pred_proving_key
);
proving_key!(
    /// Proving a badge is held under a pseudonym.
    badge_pred => badge_pred_proving_key
);

/// The Nova parameters for a folded scan. Tens of megabytes.
pub async fn fold(State(state): State<ServerLock>) -> AppResult<Bytes> {
    bulk(&state.read().await.folding_keys.folding_key)
}

/// The Groth16 key for the single step Nova folds.
pub async fn fold_pre(State(state): State<ServerLock>) -> AppResult<Bytes> {
    bulk(&state.read().await.folding_keys.fold_proving_key)
}

/// The key the object bulletin signs memberships under.
pub async fn user_pubkey(State(state): State<ServerLock>) -> AppResult<Bytes> {
    bulk(&state.read().await.db.obj_bul.get_pubkey())
}

pub async fn membership_pubkey(State(state): State<ServerLock>) -> AppResult<Bytes> {
    bulk(&state.read().await.db.callback_bul.get_pubkey())
}

pub async fn nonmembership_pubkey(State(state): State<ServerLock>) -> AppResult<Bytes> {
    bulk(&state.read().await.db.callback_bul.nmemb_bul.get_pubkey())
}

/// The object bulletin: every member's committed object.
pub async fn user_bulletin(State(state): State<ServerLock>) -> AppResult<Bytes> {
    bulk(&state.read().await.db.obj_bul.get_db())
}

/// The callback bulletin: every callback that has been invoked.
pub async fn callback_bulletin(State(state): State<ServerLock>) -> AppResult<Bytes> {
    bulk(&state.read().await.db.callback_bul.get_db())
}

/// The nonmembership bulletin: what lets a scan prove a callback was *not* invoked.
pub async fn callback_nmemb_bulletin(State(state): State<ServerLock>) -> AppResult<Bytes> {
    bulk(&state.read().await.db.callback_bul.nmemb_bul.get_db())
}

#[derive(Serialize)]
pub struct EpochResponse {
    /// Little-endian hex. The client parses it straight back into a field element.
    epoch: String,
}

/// The epoch a scan must prove against.
pub async fn get_epoch(State(state): State<ServerLock>) -> Json<EpochResponse> {
    let current: F = epoch(&state.read().await.db);

    Json(EpochResponse {
        epoch: hex::encode(current.into_bigint().to_bytes_le()),
    })
}
