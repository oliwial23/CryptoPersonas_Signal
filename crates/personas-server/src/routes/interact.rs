//! Interactions that touch the bulletin and nothing else: joining, posting without relaying,
//! scanning callbacks.
//!
//! These are the routes the benchmark harness drives — they measure the protocol without a
//! messenger in the way — plus `join`, which every member runs once.

use std::time::SystemTime;

use ark_ff::ToConstraintField;
use ark_snark::SNARK;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use folding_schemes::arith::Arith;
use folding_schemes::commitment::pedersen::Pedersen;
use folding_schemes::folding::nova::zk::RandomizedIVCProof;

use ark_bn254::G1Projective as Projective;
use ark_grumpkin::Projective as Projective2;
use personas_core::circuits::{
    FoldingProofData, MsgUser, NUM_SCANS_PER_FOLD, get_extra_pubdata_for_scan,
};
use personas_core::{Args, CStore, Cr, F, H, OStore, Snark, Store};
use personas_wire::{Kind, decode};
use zk_callbacks::generic::bulletin::{JoinableBulletin, UserBul};
use zk_callbacks::generic::object::Com;
use zk_callbacks::generic::scan::PubScanArgs;
use zk_callbacks::generic::service::ServiceProvider;
use zk_callbacks::generic::user::ExecutedMethod;
use zk_callbacks::impls::centralized::crypto::FakeSigPrivkey;
use zk_callbacks::impls::centralized::ds::sig::gr_schnorr::GrumpkinSchnorr;
use zk_callbacks::impls::centralized::ds::sigstore::SigObjStore;

use crate::bench;
use crate::bulletin::{self, SCAN, epoch, verify_and_store};
use crate::error::{AppError, AppResult, ok};
use crate::state::ServerLock;

type PubScan = PubScanArgs<F, MsgUser, F, personas_core::ArgsVar, Cr, CStore, NUM_SCANS_PER_FOLD>;

/// A new member registers (`Register` in the paper): the payload is the committed object,
/// the account it is bound to (a hash of the member's invite code), its public key
/// `pk = H(sk, tag)`, and a `join_pred` proof that the commitment opens to a fresh object
/// whose secret key derives `pk`, in the current epoch.
///
/// The server admits the join only if the proof verifies, `pk` has never registered (so no
/// secret key backs two objects, and a banned member's key cannot be re-registered by a
/// colluder), and `AllowedToRegister` admits the account: an unused invite, when an invites
/// file is configured (`PERSONAS_INVITES_FILE`), or any account otherwise.
pub async fn join(State(state): State<ServerLock>, body: Bytes) -> AppResult<StatusCode> {
    let mut reader = decode(Kind::Join, &body)?;
    let object: Com<F> = reader.pull()?;
    let account: F = reader.pull()?;
    let pk: F = reader.pull()?;
    let proof: <Snark as SNARK<F>>::Proof = reader.pull()?;
    if !reader.is_empty() {
        return Err(AppError::BadRequest("the join has trailing data".into()));
    }

    let mut server = state.write().await;
    let current = epoch(&server.db);

    let verified = Snark::verify(
        &server.keys.join_pred_verifying_key,
        &[object, account, pk, current],
        &proof,
    )
    .unwrap_or(false);
    if !verified {
        return Err(AppError::Rejected(
            "the registration proof does not verify (is the client in the current epoch?)".into(),
        ));
    }

    let account_hex = personas_core::persona::f_hex(&account);
    let pk_hex = personas_core::persona::f_hex(&pk);
    let reg = &server.registration;
    if let Some(invites) = &reg.invites {
        if !invites.contains(&account_hex) {
            return Err(AppError::Rejected("that invite code is not valid".into()));
        }
        if reg.used_accounts.contains(&account_hex) {
            return Err(AppError::Rejected("that invite code has already been used".into()));
        }
    }
    if reg.used_pks.contains(&pk_hex) {
        return Err(AppError::Rejected(
            "this public key is already registered: a secret key can back only one object".into(),
        ));
    }

    <SigObjStore<F, GrumpkinSchnorr> as JoinableBulletin<F, MsgUser>>::join_bul(
        &mut server.db.obj_bul,
        object,
        (),
    )
    .map_err(|e| AppError::Rejected(format!("the bulletin refused the join: {e:?}")))?;

    server.registration.used_pks.mark_spent(pk_hex)?;
    if server.registration.invites.is_some() {
        server.registration.used_accounts.mark_spent(account_hex)?;
    }

    tracing::info!("a new member registered");
    Ok(StatusCode::OK)
}

/// Post to the bulletin without relaying anything. The benchmark path for a plain post.
pub async fn standard(
    State(state): State<ServerLock>,
    body: Bytes,
) -> AppResult<impl IntoResponse> {
    let mut reader = decode(Kind::Post, &body)?;
    let exec: ExecutedMethod<F, Snark, Args, Cr, 1> = reader.pull()?;

    let mut st = state.write().await;
    let vk = st.keys.standard_verifying_key.clone();
    let current = epoch(&st.db);

    // Live epoch, matching every other route (FINDINGS O3) — this is the same anonymous
    // interaction `signal_anon`/`slack_anon` verify, just without a relay.
    verify_and_store(
        &mut st.db,
        &vk,
        exec,
        F::from(0),
        current,
        bulletin::INTERACTION,
    )?;

    Ok(ok())
}

/// Verify a standalone predicate proof. Proves nothing to anyone but the caller — it exists
/// so the benchmark can time a verification in isolation.
pub async fn arbitrary_pred(
    State(state): State<ServerLock>,
    body: Bytes,
) -> AppResult<impl IntoResponse> {
    let mut reader = decode(Kind::Predicate, &body)?;
    let proof: <Snark as SNARK<F>>::Proof = reader.pull()?;
    let pub_inputs: Vec<F> = reader.pull()?;

    let verified = Snark::verify(
        &state.read().await.keys.pseudonym_pred_verifying_key,
        &pub_inputs,
        &proof,
    )
    .map_err(|e| AppError::Rejected(format!("the proof did not verify: {e:?}")))?;

    if !verified {
        return Err(AppError::Rejected("the proof did not verify".into()));
    }

    Ok(ok())
}

/// A scan: the member proves they have honestly applied every callback the service invoked
/// on them since their last scan, and that they skipped none.
///
/// This is the step that makes reputation *binding*. A post proves "my reputation is above
/// the threshold"; nothing in that proof forces the member to have absorbed the downvotes
/// they earned. The scan does — and it is why an unscanned member eventually cannot post at
/// all (`num_interactions_since_last_scan` hits the rate limit).
pub async fn scan(State(state): State<ServerLock>, body: Bytes) -> AppResult<impl IntoResponse> {
    // A single-ticket scan reveals how many tickets its sender holds (one scan per ticket),
    // so a deployment accepts only folded scans (`fold_scan`), which hide that count. The bench
    // turns this route back on to time the per-callback baseline.
    if std::env::var_os("PERSONAS_ALLOW_UNPADDED_SCAN").is_none() {
        return Err(AppError::Rejected(
            "single-ticket scans are disabled; send one folded scan (`fold`) per epoch".into(),
        ));
    }
    if body.is_empty() {
        // The client sends an empty body when it has nothing outstanding to scan.
        tracing::info!("empty scan payload; nothing to do");
        return Ok((StatusCode::OK, "Scan payload is empty. Check for errors."));
    }

    let mut reader = decode(Kind::Scan, &body)?;
    let scan_one: ExecutedMethod<F, Snark, Args, Cr, 0> = reader.pull()?;

    let mut st = state.write().await;
    let vk = st.keys.scan_verifying_key.clone();
    let ps = scan_pub_args(&st.db);

    let (verified, start, millis) = bench::time(|| {
        <OStore as UserBul<F, MsgUser>>::verify_interact_and_append::<PubScan, Snark, 0>(
            &mut st.db.obj_bul,
            scan_one.new_object,
            scan_one.old_nullifier,
            ps.clone(),
            scan_one.cb_com_list,
            scan_one.proof.clone(),
            None,
            &vk,
        )
    });
    bench::verified("scan", start, millis);

    let current = epoch(&st.db);
    let db = &mut st.db;
    let stored = db.approve_interaction_and_store::<MsgUser, Snark, PubScan, OStore, H, 0>(
        scan_one,
        FakeSigPrivkey::sk(),
        ps,
        &db.obj_bul.clone(),
        personas_core::circuits::get_callbacks(),
        current,
        db.obj_bul.get_pubkey(),
        true,
        &vk,
        SCAN,
    );

    if verified.is_ok() && stored.is_ok() {
        tracing::info!("scan verified and stored");
        Ok((StatusCode::OK, "Scan verified"))
    } else {
        tracing::info!("scan rejected: append={verified:?} store={stored:?}");
        Err(AppError::Rejected("Scan verification failed".into()))
    }
}

/// A Nova-folded scan: one proof for `NUM_SCANS_PER_FOLD` callbacks at a time.
///
/// Megabytes rather than kilobytes, which is why the route carries its own 100 MB body limit
/// and why serverless leaves folding off by default: in serverless *every member* downloads
/// every record, so an MB-scale proof is an n-fold cost rather than a single server's.
pub async fn fold_scan(
    State(state): State<ServerLock>,
    request: Request<Body>,
) -> AppResult<impl IntoResponse> {
    let latency_start = SystemTime::now();

    let (_parts, body) = request.into_parts();
    let body = axum::body::to_bytes(body, 100 * 1024 * 1024)
        .await
        .map_err(|e| AppError::BadRequest(format!("could not read the folded scan: {e}")))?;

    let params = {
        let st = state.read().await;
        let params = st.folding_keys.clone();

        constraints("fold", &params);
        params
    };

    let mut reader = decode(Kind::FoldScan, &body)?;
    let proof: FoldingProofData = reader.pull()?;

    // The state vectors come from the sender; index them only once their shape is right.
    if proof.z_0.len() != 2 || proof.z_i.len() != 2 {
        return Err(AppError::Rejected("Fold scan has a malformed state".into()));
    }

    let mut st = state.write().await;
    let current = epoch(&st.db);

    let (verified, start, millis) = bench::time(|| {
        // Three things have to hold, and all three are load-bearing.
        //
        // 1. The Nova proof itself: each folded step was a valid scan.
        let folded =
            RandomizedIVCProof::verify::<Pedersen<Projective, true>, Pedersen<Projective2, true>>(
                &params.nova_c1_r1cs,
                &params.nova_c2_r1cs,
                params.pp_hash,
                &params.pos_config,
                &params.folding_key.0.cs_pp,
                &params.folding_key.0.cf_cs_pp,
                proof.c,
                proof.z_0.clone(),
                proof.z_i.clone(),
                &proof.proof,
            )
            .is_ok();

        // 2. The folding started where it claims to have started, and at *this* epoch — a
        //    fold over a stale epoch would let a member re-absorb callbacks they have already
        //    accounted for, or skip ones invoked since.
        let bound = proof.z_0[0] == proof.extra_verif.0 && proof.z_0[1] == current;

        // 3. The Groth16 proof tying the folded output back to the member's object.
        let mut pub_inputs = Vec::new();
        if let Some(fields) = [proof.extra_verif.0, proof.extra_verif.1].to_field_elements() {
            pub_inputs.extend(fields);
        }
        let tied = Snark::verify(
            &params.fold_verifying_key,
            &pub_inputs,
            &proof.extra_verif.2,
        )
        .unwrap_or(false);

        // The step count is never sent: the proof binds only the committed counter `c`, and
        // its folded instances start from random accumulators, so nothing in it reveals how
        // many callbacks it answers (third_party/sonobe, iteration hiding).
        folded && bound && tied
    });

    personas_core::timing::append_timing_line_fold(
        "fold",
        start,
        millis,
        NUM_SCANS_PER_FOLD,
        "verify",
    )
    .ok();

    if !verified {
        tracing::info!("folded scan failed verification");
        return Err(AppError::Rejected(
            "Fold scan **failed** verification".into(),
        ));
    }

    // The object folded from is spent, like any other: without this a member could fold
    // again from an object from before a ban.
    let old_nul = proof.extra_verif.1;
    if !<OStore as UserBul<F, MsgUser>>::has_never_received_nul(&st.db.obj_bul, &old_nul) {
        return Err(AppError::Rejected("Fold scan reuses a nullifier".into()));
    }
    let ps = scan_pub_args(&st.db);
    <OStore as UserBul<F, MsgUser>>::append_value::<PubScan, Snark, 0>(
        &mut st.db.obj_bul,
        proof.z_i[0],
        old_nul,
        [],
        ps,
        <Snark as SNARK<F>>::Proof::default(),
        None,
        &<Snark as SNARK<F>>::VerifyingKey::default(),
    )
    .map_err(|e| AppError::Internal(anyhow::anyhow!("could not append the folded scan: {e:?}")))?;

    let elapsed = latency_start
        .elapsed()
        .map(|d| d.as_secs_f64() * 1e3)
        .unwrap_or(0.0);
    personas_core::timing::append_timing_line_fold(
        "fold",
        latency_start,
        elapsed,
        NUM_SCANS_PER_FOLD,
        "latency",
    )
    .ok();

    tracing::info!("folded scan verified and stored");
    Ok((StatusCode::OK, "Fold scan verified"))
}

/// The public data a scan proof is checked against: the two callback bulletins and the epoch.
fn scan_pub_args(db: &Store) -> PubScan {
    let memb = db.callback_bul.get_pubkey();
    let nmemb = db.callback_bul.nmemb_bul.get_pubkey();
    get_extra_pubdata_for_scan(&db.callback_bul, memb, nmemb, epoch(db))
}

/// Circuit sizes, for the plots in the paper.
fn constraints(label: &str, params: &personas_core::params::FoldingParams) {
    let line = serde_json::json!({
        "constraint_count_1": params.nova_c1_r1cs.n_constraints(),
        "constraint_count_2": params.nova_c2_r1cs.n_constraints(),
        "n": NUM_SCANS_PER_FOLD,
    });

    let dir = format!("json_files/{label}");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }

    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(format!("{dir}/constraints_timings.jsonl"))
    {
        let _ = writeln!(file, "{line}");
    }
}
