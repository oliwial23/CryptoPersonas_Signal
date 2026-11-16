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
/// The supplied `epoch` is the epoch at which callbacks are checked and stored.
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
        exec.new_object,
        exec.old_nullifier,
        pub_args.clone(),
        exec.cb_com_list,
        exec.proof.clone(),
        None,
        vk,
    );

    if appended.is_err() {
        tracing::info!("interaction rejected: append={appended:?}");
        return Err(interaction_rejected());
    }

    let stored = db.approve_interaction_and_store::<MsgUser, Snark, PubArgs, OStore, H, N>(
        exec,
        FakeSigPrivkey::sk(),
        pub_args,
        &db.obj_bul.clone(),
        // One expected callback per committed one: every interaction leaves the standard
        // callback, a Privacy Pass ticket request `N` of them.
        (0..N).map(|_| get_callbacks().remove(0)).collect(),
        epoch,
        db.obj_bul.get_pubkey(),
        true,
        vk,
        data,
    );

    if stored.is_err() {
        // Approval checks the newly appended entry, so reject it in both places if
        // callback validation fails. The server write lock covers both steps.
        db.obj_bul.coms.pop();
        db.obj_bul.old_nuls.pop();
        db.obj_bul.cb_com_lists.pop();
        db.obj_bul.sigs.pop();
        tracing::info!("interaction rejected: store={stored:?}");
        return Err(interaction_rejected());
    }

    tracing::info!("interaction verified and appended to the bulletin");
    Ok(callbacks)
}

/// Verify a Privacy Pass ticket request's interaction and append it to the bulletin,
/// without its callback tickets. Unlike [`verify_and_store`], nothing is checked against
/// or stored from the clear tickets: the issuer never sees them, so it cannot link the
/// request to a redemption. The blinding proof checks their shape instead, and the
/// service learns each ticket only when it is redeemed.
pub fn verify_and_append_blind<const N: usize>(
    db: &mut Store,
    vk: &VK,
    exec: batch_zkc::BlindExecutedMethod<Snark, N>,
    pub_args: F,
) -> Result<(), AppError> {
    let appended = <OStore as UserBul<F, MsgUser>>::verify_interact_and_append::<F, Snark, N>(
        &mut db.obj_bul,
        exec.new_object,
        exec.old_nullifier,
        pub_args,
        exec.cb_com_list,
        exec.proof,
        None,
        vk,
    );
    if appended.is_err() {
        tracing::info!("ticket request rejected: append={appended:?}");
        return Err(interaction_rejected());
    }
    tracing::info!("ticket request verified and appended to the bulletin");
    Ok(())
}

fn interaction_rejected() -> AppError {
    AppError::Rejected(
        "Cannot post message: proof failed. Check if you are banned or have inadequate reputation score.".into(),
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use personas_core::{
        circuits::{
            Claim, ClaimArgs, PseudonymArgs, exec_claim_standint, exec_pseudo_standint,
            get_claim_interaction, get_standard_pseudo_interaction, rep_threshold,
        },
        persona::{pseudonym, server_ballot_payload, server_claim_payload},
    };
    use zk_callbacks::generic::{bulletin::JoinableBulletin, user::User};

    #[test]
    fn an_invalid_ballot_payload_or_callback_does_not_spend_the_object() {
        let mut rng = rand::thread_rng();
        let mut db = Store::new(&mut rng);
        let (pk, vk) = get_standard_pseudo_interaction().generate_keys::<H, Snark, Cr, OStore>(
            &mut rng,
            Some(db.obj_bul.get_pubkey()),
            PseudonymArgs::default(),
            false,
        );
        let mut user = User::create(
            MsgUser {
                sk: F::from(42),
                ..Default::default()
            },
            &mut rng,
        );
        <OStore as JoinableBulletin<F, MsgUser>>::join_bul(&mut db.obj_bul, user.commit::<H>(), ())
            .unwrap();
        let context = F::from(7);
        let args = PseudonymArgs {
            context,
            claimed: pseudonym(&user.data.sk, &context),
            payload: server_ballot_payload("signal", "upvote"),
        };
        let current = epoch(&db);
        let vote = exec_pseudo_standint(
            &mut user,
            &mut rng,
            &db.obj_bul,
            &pk,
            current,
            args.clone(),
            (),
        )
        .unwrap();
        let clone_vote = || ExecutedMethod {
            new_object: vote.new_object,
            old_nullifier: vote.old_nullifier,
            cb_tik_list: vote.cb_tik_list.clone(),
            cb_com_list: vote.cb_com_list,
            cur_time: vote.cur_time,
            proof: vote.proof.clone(),
        };

        let wrong_choice = PseudonymArgs {
            payload: server_ballot_payload("signal", "downvote"),
            ..args.clone()
        };
        assert!(
            verify_and_store(
                &mut db,
                &vk,
                clone_vote(),
                wrong_choice,
                current,
                INTERACTION
            )
            .is_err()
        );
        let mut wrong_callback = clone_vote();
        wrong_callback.cb_tik_list[0].0.com_rand += F::from(1);
        assert!(
            verify_and_store(
                &mut db,
                &vk,
                wrong_callback,
                args.clone(),
                current,
                INTERACTION
            )
            .is_err()
        );
        assert_eq!(db.obj_bul.coms.len(), 1);
        assert!(db.cb_tickets.is_empty());

        assert_eq!(
            verify_and_store(&mut db, &vk, vote, args, current, INTERACTION)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(db.obj_bul.coms.len(), 2);
        assert_eq!(db.cb_tickets.len(), 1);
    }

    #[test]
    fn a_claim_proof_binds_the_message_and_destination() {
        let mut rng = rand::thread_rng();
        let mut db = Store::new(&mut rng);
        let claim = Claim::RepAtLeast;
        let (pk, vk) = get_claim_interaction(claim).generate_keys::<H, Snark, Cr, OStore>(
            &mut rng,
            Some(db.obj_bul.get_pubkey()),
            ClaimArgs::default(),
            false,
        );
        let mut user = User::create(
            MsgUser {
                sk: F::from(42),
                ..Default::default()
            },
            &mut rng,
        );
        <OStore as JoinableBulletin<F, MsgUser>>::join_bul(&mut db.obj_bul, user.commit::<H>(), ())
            .unwrap();
        let context = F::from(7);
        let args = ClaimArgs {
            post: PseudonymArgs {
                context,
                claimed: pseudonym(&user.data.sk, &context),
                payload: server_claim_payload("group-a", "my message"),
            },
            a: rep_threshold(-1),
            b: F::from(0),
        };
        let current = epoch(&db);
        let proof = exec_claim_standint(
            &mut user,
            &mut rng,
            &db.obj_bul,
            &pk,
            current,
            claim,
            args.clone(),
        )
        .unwrap();
        let check = |args| {
            <OStore as UserBul<F, MsgUser>>::verify_interaction::<_, Snark, 1>(
                &db.obj_bul,
                proof.new_object,
                proof.old_nullifier,
                args,
                proof.cb_com_list,
                proof.proof.clone(),
                None,
                &vk,
            )
        };
        for (group, message) in [("group-b", "my message"), ("group-a", "different message")] {
            let mut changed = args.clone();
            changed.post.payload = server_claim_payload(group, message);
            assert!(!check(changed));
        }
        assert!(check(args));
    }
}
