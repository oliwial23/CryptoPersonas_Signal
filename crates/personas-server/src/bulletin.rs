//! The one place an interaction is checked and written to the bulletin.
//!
//! Every proof-carrying route did this by hand: deserialize, `verify_interact_and_append`,
//! `approve_interaction_and_store`, loop over the callback tickets, hex-encode each. Six
//! copies for the six kinds of post, differing only in which verifying key and which public
//! arguments they passed. They are one generic function; `PubArgs` is what varies.

use ark_ff::ToConstraintField;
use ark_serialize::CanonicalSerialize;
use personas_core::{
    Args, Cr, F, H, OStore, Snark, Store, VK,
    circuits::{MsgUser, get_callbacks},
};
use personas_wire::raw;
use zk_callbacks::generic::{
    bulletin::UserBul, callbacks::CallbackCom, object::Time, service::ServiceProvider,
    user::ExecutedMethod,
};
use zk_callbacks::impls::centralized::crypto::{FakeSigPrivkey, PlainTikCrypto};

use crate::error::AppError;

/// The two magic numbers the original passed as `InteractionData`: 332 for an interaction,
/// 442 for a scan. They are opaque to the store — it records them and nothing reads them
/// back — so they are preserved rather than explained.
pub const INTERACTION: u64 = 332;
pub const SCAN: u64 = 442;

/// Verify an interaction's proof, append it to the bulletin, and store it.
///
/// Returns the hex-encoded callback commitments the poster committed to. The caller files
/// them against the message id once the messenger has assigned one — see
/// [`RecordLog::record`](crate::state::RecordLog::record) for why that has to happen in
/// that order.
///
/// `epoch` is passed in rather than read from the callback bulletin because the routes
/// disagree about it: an anonymous or rate-limited post stores its tickets at `Time::from(0)`
/// while a pseudonymous post or a badge request stores them at the *live* epoch. That
/// difference is inherited from the original code, is not obviously intentional, and is
/// preserved here rather than quietly unified — a scan proves over the epoch its callbacks
/// were stored at, so changing it changes what a client must prove.
pub fn verify_and_store<PubArgs, const N: usize>(
    db: &mut Store,
    vk: &VK,
    exec: ExecutedMethod<F, Snark, Args, Cr, N>,
    pub_args: PubArgs,
    epoch: Time<F>,
    data: u64,
) -> Result<Vec<String>, AppError>
where
    PubArgs: Clone + ToConstraintField<F>,
{
    // The tickets have to be read out before `exec` is consumed by the store.
    let callbacks = exec
        .cb_tik_list
        .iter()
        .map(|(cb_com, _)| callback_hex(cb_com))
        .collect::<Result<Vec<_>, _>>()?;

    let appended = <OStore as UserBul<F, MsgUser>>::verify_interact_and_append::<PubArgs, Snark, N>(
        &mut db.obj_bul,
        exec.new_object.clone(),
        exec.old_nullifier.clone(),
        pub_args.clone(),
        exec.cb_com_list.clone(),
        exec.proof.clone(),
        None,
        vk,
    );

    let stored = db.approve_interaction_and_store::<MsgUser, Snark, PubArgs, OStore, H, N>(
        exec,
        FakeSigPrivkey::sk(),
        pub_args,
        &db.obj_bul.clone(),
        get_callbacks(),
        epoch,
        db.obj_bul.get_pubkey(),
        true,
        vk,
        data,
    );

    match (appended, stored) {
        (Ok(()), Ok(())) => {
            tracing::info!("interaction verified and appended to the bulletin");
            Ok(callbacks)
        }
        (appended, stored) => {
            // The member gets no detail: which of the two failed, and why, is an oracle on
            // their own standing. The log gets all of it.
            tracing::info!("interaction rejected: append={appended:?} store={stored:?}");
            Err(AppError::Rejected(
                "Cannot post message: proof failed. Check if you are banned or have \
                 inadequate reputation score."
                    .into(),
            ))
        }
    }
}

/// How a callback commitment is named in the ledger, and keyed by every lookup.
///
/// Canonical, uncompressed, hex. The client hands these exact bytes back when it asks for a
/// callback to be invoked, so the encoding is a wire format: it has to be deterministic, and
/// it has to be the same on both sides. Uncompressed because that is what the client's
/// on-disk callback list already holds, and rewriting it would strand every callback a
/// member is currently holding.
pub fn callback_hex(cb: &CallbackCom<F, F, PlainTikCrypto<F>>) -> Result<String, AppError> {
    let bytes = raw::encode(cb).map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;
    Ok(hex::encode(bytes))
}

/// The current epoch of the callback bulletin.
pub fn epoch(db: &Store) -> Time<F> {
    db.callback_bul.get_epoch()
}

/// Serialize any bulk artifact — a proving key, a bulletin dump — for a GET.
///
/// Not a record: no envelope, no compression. See `personas_wire::raw`.
pub fn bulk<T: CanonicalSerialize>(value: &T) -> Result<axum::body::Bytes, AppError> {
    let bytes = raw::encode(value).map_err(|e| AppError::Internal(anyhow::anyhow!(e)))?;
    Ok(bytes.into())
}
