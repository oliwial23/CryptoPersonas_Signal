//! End-to-end replica tests with **real Groth16 proofs** (workstream d3).
//!
//! These generate real Merkle-mode keys and proofs, which is impractically slow in
//! a debug build, so they are `#[ignore]` by default. Run them with:
//!
//! ```text
//! cargo test -p personas-bulletin --release -- --ignored replica::e2e
//! ```
//!
//! They exercise the M3 flagship properties the fast tests cannot: three replicas
//! fed the same records in different arrival orders converge on identical roots
//! (§1/§4), a double-spend is resolved to the same winner everywhere (§4), and a
//! ban propagates so that every replica pins it and a stale pre-ban scan is
//! rejected (§5.2, the O10 defense).

use rand::{SeedableRng, rngs::StdRng};

use ark_ff::UniformRand;

use personas_core::circuits::{
    MsgUser, SCAN_SLOTS, PostArgs, PostArgsVar, PrivScan, PrivScanVar,
    PseudonymArgs, PseudonymArgsRate,
    PseudonymArgsRateVar, PseudonymArgsVar, PubScan, PubScanVar, ScanInt, get_callbacks,
    get_scan_interaction, get_standard_interaction, get_standard_pseudo_interaction,
    get_standard_pseudo_rate_interaction,
    pseudonym_pred,
};
use personas_core::{Args, ArgsVar, Cr, F, H, PK, Snark, VK, persona};

use zk_callbacks::generic::bulletin::PublicUserBul;
use zk_callbacks::generic::interaction::generate_keys_for_statement_in;
use zk_callbacks::generic::object::Time;
use zk_callbacks::generic::user::{ExecutedMethod, User};
use zk_callbacks::impls::centralized::crypto::FakeSigPubkey;

use super::record::{Ark, Eh, Flavour, PollKind, Record, encode};
use super::tally::BAN_OPTION;
use super::{Config, Replica, ReplicaKeys, Status};
use crate::merkle::params::merkle_scan_pubdata;
use crate::merkle::{MerkleCallbackStore, MerkleObjStore};

// Tiny heights keep the circuits small; the mechanism under test is
// height-independent (d1's e2e tests make the same choice).
const OH: usize = 32;
const MH: usize = 4;
const NH: usize = 4;
type ObjT = MerkleObjStore<F, OH>;
type CbT = MerkleCallbackStore<F, MH, NH>;

fn standard_keys(rng: &mut StdRng) -> (PK, VK) {
    get_standard_interaction().generate_keys::<H, Snark, Cr, ObjT>(rng, None, PostArgs::default(), false)
}

fn scan_keys(rng: &mut StdRng, cstore: &CbT) -> (PK, VK) {
    let si: ScanInt<CbT, SCAN_SLOTS> = get_scan_interaction();
    let dummy = merkle_scan_pubdata::<MH, NH, SCAN_SLOTS>(cstore, Time::from(0));
    si.generate_keys::<H, Snark, Cr, ObjT>(rng, None, dummy, true)
}

fn pseudo_keys(rng: &mut StdRng) -> (PK, VK) {
    get_standard_pseudo_interaction().generate_keys::<H, Snark, Cr, ObjT>(
        rng,
        None,
        PseudonymArgs::default(),
        false,
    )
}

#[allow(dead_code)]
fn pseudonym_pred_keys(rng: &mut StdRng) -> (PK, VK) {
    let dummy = PseudonymArgs::default();
    generate_keys_for_statement_in::<
        F,
        H,
        MsgUser,
        PseudonymArgs<F>,
        PseudonymArgsVar<F>,
        (),
        (),
        Snark,
        ObjT,
    >(rng, pseudonym_pred, None, dummy)
}

/// A `ReplicaKeys` where only `standard` is real; the others are placeholders for
/// a test that never exercises them.
fn standard_only_keys(vk: &VK) -> ReplicaKeys {
    ReplicaKeys {
        standard: vk.clone(),
        pseudo: vk.clone(),
        pseudo_rate: vk.clone(),
        scan: vk.clone(),
        pseudonym_pred: vk.clone(),
        badge_request: vk.clone(),
        join: vk.clone(),
        not_banned: vk.clone(),
        show_badge: vk.clone(),
        merge_personas: vk.clone(),
        rep_at_least: vk.clone(),
    }
}

/// Register a fresh user and return it plus a `Join` record committing it.
fn make_user(rng: &mut StdRng) -> (User<F, MsgUser>, Record) {
    let user = User::create(MsgUser::default(), rng);
    let join = Record::Join {
        object: Ark(user.commit::<H>()),
        old_nul: Ark(F::from(0)),
        account: Ark(user.commit::<H>()),
        pk: Ark(user.commit::<H>()),
        proof: Ark(Default::default()),
    };
    (user, join)
}

/// The object commitment a `Join` record carries.
fn join_object(join: &Record) -> F {
    match join {
        Record::Join { object, .. } => object.0,
        _ => unreachable!("not a join"),
    }
}

/// An anonymous post by `user` against `obj`'s current root.
fn anon_post(
    rng: &mut StdRng,
    user: &mut User<F, MsgUser>,
    obj: &ObjT,
    pk: &PK,
    body: &str,
) -> Record {
    let exec: ExecutedMethod<F, Snark, Args, Cr, 1> = user
        .exec_method_create_cb::<H, PostArgs<F>, PostArgsVar<F>, (), (), Args, ArgsVar, Cr, Snark, ObjT, 1>(
            rng,
            get_standard_interaction(),
            [FakeSigPubkey::pk()],
            Time::from(0),
            obj,
            false,
            pk,
            PostArgs { payload: super::record::post_payload(body), epoch: F::from(0) },
            (),
        )
        .expect("post proof");
    Record::Post {
        flavour: Flavour::Anon,
        exec: Ark(exec),
        extra: Ark(vec![]),
        body: body.into(),
        payload: Ark(super::record::post_payload(body)),
        obj_root: Ark(obj.root()),
    }
}

#[test]
#[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
fn e2e_convergence_out_of_order_delivery() {
    let mut rng = StdRng::seed_from_u64(0);
    let (pk, vk) = standard_keys(&mut rng);
    let keys = standard_only_keys(&vk);

    // One member joins and posts once.
    let (mut user, join) = make_user(&mut rng);
    let mut shadow = ObjT::new();
    shadow.push(join_object(&join), F::from(0), vec![]);
    let post = anon_post(&mut rng, &mut user, &shadow, &pk, "hello serverless");

    let (join_b, join_eh) = encode(&join).unwrap();
    let (post_b, post_eh) = encode(&post).unwrap();

    // Deliver [join, post] and [post, join] to two replicas; both must converge and
    // apply both records.
    let mut roots = Vec::new();
    for order in [vec![&join_b, &post_b], vec![&post_b, &join_b]] {
        let mut r = Replica::<OH, MH, NH>::new(keys.clone(), Config::fast())
            .trust_unproven_joins_for_tests();
        for bytes in order {
            r.ingest(bytes.clone()).unwrap();
        }
        // A root is produced when its barrier closes.
        r.barrier();
        assert_eq!(r.status(&join_eh), Some(Status::Applied));
        assert_eq!(
            r.status(&post_eh),
            Some(Status::Applied),
            "the post applies even when it arrives before the join that produces its root"
        );
        roots.push(r.obj_root());
    }
    assert_eq!(roots[0], roots[1], "arrival order must not change the root");
}

#[test]
#[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
fn e2e_double_spend_resolves_to_one_winner_everywhere() {
    let mut rng = StdRng::seed_from_u64(1);
    let (pk, vk) = standard_keys(&mut rng);
    let keys = standard_only_keys(&vk);

    let (user, join) = make_user(&mut rng);
    let mut shadow = ObjT::new();
    shadow.push(join_object(&join), F::from(0), vec![]);

    // Two posts spending the *same* joined object — a double-spend (identical old
    // nullifier, different new object/proof).
    let mut u1 = user.clone();
    let mut u2 = user.clone();
    let post_a = anon_post(&mut rng, &mut u1, &shadow, &pk, "spend A");
    let post_b = anon_post(&mut rng, &mut u2, &shadow, &pk, "spend B");

    let (join_by, _join_eh) = encode(&join).unwrap();
    let (a_by, a_eh) = encode(&post_a).unwrap();
    let (b_by, b_eh) = encode(&post_b).unwrap();
    // The §4 winner is the smaller envelope hash.
    let (winner, loser) = if a_eh < b_eh {
        (a_eh, b_eh)
    } else {
        (b_eh, a_eh)
    };

    let mut roots = Vec::new();
    for order in [
        vec![&join_by, &a_by, &b_by],
        vec![&b_by, &a_by, &join_by],
        vec![&a_by, &join_by, &b_by],
    ] {
        let mut r = Replica::<OH, MH, NH>::new(keys.clone(), Config::fast())
            .trust_unproven_joins_for_tests();
        for bytes in order {
            r.ingest(bytes.clone()).unwrap();
        }
        r.barrier();
        assert_eq!(r.status(&winner), Some(Status::Applied), "smaller eh wins");
        assert_eq!(
            r.status(&loser),
            Some(Status::Rejected("nullifier already spent")),
            "the double-spend loser is dropped, deterministically"
        );
        roots.push(r.obj_root());
    }
    assert!(
        roots.iter().all(|x| *x == roots[0]),
        "every replica picks the same winner and so the same root"
    );
}

/// The verifying keys a test of posts, votes and scans needs: votes are Persona-post
/// interactions, so `pseudo_vk` is the pseudonymous-post key.
fn full_keys(std_vk: &VK, scan_vk: &VK, pseudo_vk: &VK) -> ReplicaKeys {
    ReplicaKeys {
        standard: std_vk.clone(),
        pseudo: pseudo_vk.clone(),
        pseudo_rate: std_vk.clone(),
        scan: scan_vk.clone(),
        pseudonym_pred: std_vk.clone(),
        badge_request: std_vk.clone(),
        join: std_vk.clone(),
        not_banned: std_vk.clone(),
        show_badge: std_vk.clone(),
        merge_personas: std_vk.clone(),
        rep_at_least: std_vk.clone(),
    }
}

/// A user with a random secret key (as the real client creates them).
fn member(rng: &mut StdRng) -> User<F, MsgUser> {
    User::create(
        MsgUser {
            sk: F::rand(rng),
            ..Default::default()
        },
        rng,
    )
}

/// A `Join` record's encoded bytes and eh, plus the object it commits.
fn join_of(user: &User<F, MsgUser>) -> (F, Vec<u8>, Eh) {
    let rec = Record::Join {
        object: Ark(user.commit::<H>()),
        old_nul: Ark(F::from(0)),
        account: Ark(user.commit::<H>()),
        pk: Ark(user.commit::<H>()),
        proof: Ark(Default::default()),
    };
    let (b, eh) = encode(&rec).unwrap();
    (user.commit::<H>(), b, eh)
}

/// A vote to ban: a Persona-post interaction at the poll's context. It advances the
/// voter's object, so this also returns the `(new object, spent nullifier, callback
/// commitment)` a shadow tree must add to follow the replica's roots.
fn ban_vote(
    rng: &mut StdRng,
    voter: &mut User<F, MsgUser>,
    shadow_joined: &ObjT,
    root_joined: F,
    poll: Eh,
    pseudo_pk: &PK,
) -> (Vec<u8>, Eh, (F, F, F)) {
    let context = poll.context();
    let claimed = persona::pseudonym(&voter.data.sk, &context);
    assert_eq!(shadow_joined.root(), root_joined);
    let pseudo = PseudonymArgs {
        context,
        claimed,
        payload: super::record::ballot_payload(poll, BAN_OPTION),
        epoch: F::from(0),
    };
    let exec = voter
        .exec_method_create_cb::<H, PseudonymArgs<F>, PseudonymArgsVar<F>, (), (), Args, ArgsVar, Cr, Snark, ObjT, 1>(
            rng,
            get_standard_pseudo_interaction(),
            [FakeSigPubkey::pk()],
            Time::from(0),
            shadow_joined,
            false,
            pseudo_pk,
            pseudo,
            (),
        )
        .expect("vote proof");
    let leaf = (exec.new_object, exec.old_nullifier, exec.cb_com_list[0]);
    let rec = Record::Vote {
        poll,
        option: BAN_OPTION,
        exec: Ark(exec),
        claimed: Ark(claimed),
        obj_root: Ark(root_joined),
    };
    let (bytes, eh) = encode(&rec).unwrap();
    (bytes, eh, leaf)
}

/// A scan by `user` against callback store `cbs` and object root `obj_root`. When
/// the user's ticket is a member of `cbs` (called), this proves the membership
/// (absorb) branch; otherwise the nonmembership branch.
fn scan_of(
    rng: &mut StdRng,
    user: &mut User<F, MsgUser>,
    shadow: &ObjT,
    cbs: &CbT,
    scan_pk: &PK,
    obj_root: F,
    epoch: u64,
) -> Record {
    let (ps, prs) = user.get_scan_arguments::<Args, ArgsVar, Cr, CbT, SCAN_SLOTS>(
        cbs,
        (false, false),
        Time::from(epoch),
        get_callbacks(),
    );
    let md = <ObjT as PublicUserBul<F, MsgUser>>::get_membership_data(shadow, user.commit::<H>())
        .unwrap();
    let exec = user
        .interact::<H, PubScan<CbT, SCAN_SLOTS>, PubScanVar<CbT, SCAN_SLOTS>, PrivScan<CbT, SCAN_SLOTS>, PrivScanVar<CbT, SCAN_SLOTS>, Args, ArgsVar, Cr, Snark, ObjT, 0>(
            rng,
            get_scan_interaction::<CbT, SCAN_SLOTS>(),
            [],
            Time::from(epoch),
            md,
            false,
            scan_pk,
            ps,
            prs,
            true,
        )
        .expect("scan proof");
    Record::Scan {
        exec: Ark(exec),
        obj_root: Ark(obj_root),
        cb_memb_root: Ark(cbs.memb_root()),
        cb_nmemb_root: Ark(cbs.nmemb_root()),
    }
}

#[test]
#[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
fn e2e_ban_propagates_and_absorbs_and_stale_scan_rejected() {
    let mut rng = StdRng::seed_from_u64(2);
    let (std_pk, std_vk) = standard_keys(&mut rng);
    let (scan_pk, scan_vk) = scan_keys(&mut rng, &CbT::new());
    let (pred_pk, pred_vk) = pseudo_keys(&mut rng);
    let keys = full_keys(&std_vk, &scan_vk, &pred_vk);
    let config = Config {
        root_window: 256,
        barriers_per_epoch: 2,
        poll_close_barriers: 1,
    };

    // Three members: the target T and two voters.
    let mut t = member(&mut rng);
    let mut v1 = member(&mut rng);
    let mut v2 = member(&mut rng);

    // Joins, in the canonical (ascending-eh) order the replica will apply them.
    let mut joins = vec![join_of(&t), join_of(&v1), join_of(&v2)];
    joins.sort_by_key(|j| j.2);
    let mut shadow_joined = ObjT::new();
    for (com, _, _) in &joins {
        shadow_joined.push(*com, F::from(0), vec![]);
    }
    let root_joined = shadow_joined.root();

    // T posts the offending message (anonymous), committing a callback ticket.
    let p_exec = t
        .exec_method_create_cb::<H, PostArgs<F>, PostArgsVar<F>, (), (), Args, ArgsVar, Cr, Snark, ObjT, 1>(
            &mut rng,
            get_standard_interaction(),
            [FakeSigPubkey::pk()],
            Time::from(0),
            &shadow_joined,
            false,
            &std_pk,
            PostArgs { payload: super::record::post_payload("the offending post"), epoch: F::from(0) },
            (),
        )
        .expect("post proof");
    let p_new_object = p_exec.new_object;
    let p_old_nul = p_exec.old_nullifier;
    let p_cb_com = p_exec.cb_com_list;
    let post = Record::Post {
        flavour: Flavour::Anon,
        exec: Ark(p_exec),
        extra: Ark(vec![]),
        body: "the offending post".into(),
        payload: Ark(super::record::post_payload("the offending post")),
        obj_root: Ark(root_joined),
    };
    let (post_b, post_eh) = encode(&post).unwrap();

    // A ban poll targeting P, and two ban votes.
    let poll = Record::PollOpen {
        question: "ban the poster?".into(),
        options: vec!["ban".into(), "keep".into()],
        kind: PollKind::Ban,
        target: Some(post_eh),
    };
    let (poll_b, poll_eh) = encode(&poll).unwrap();
    let (v1_b, _, v1_leaf) = ban_vote(
        &mut rng,
        &mut v1,
        &shadow_joined,
        root_joined,
        poll_eh,
        &pred_pk,
    );
    let (v2_b, _, v2_leaf) = ban_vote(
        &mut rng,
        &mut v2,
        &shadow_joined,
        root_joined,
        poll_eh,
        &pred_pk,
    );

    // The object tree after P and the two ballots (each advances its voter's object) —
    // what T's scan will prove membership against.
    let mut shadow_after_p = shadow_joined.clone();
    shadow_after_p.push(p_new_object, p_old_nul, p_cb_com.to_vec());
    for (object, nul, cb) in [v1_leaf, v2_leaf] {
        shadow_after_p.push(object, nul, vec![cb]);
    }
    let root_after_p = shadow_after_p.root();

    let base: Vec<Vec<u8>> = joins
        .iter()
        .map(|j| j.1.clone())
        .chain([post_b, poll_b, v1_b, v2_b])
        .collect();

    // (a) Convergence, including the ban: three replicas, three arrival orders,
    //     each crosses one barrier, all agree on every root.
    let mut fingerprints = Vec::new();
    let orders: [Vec<usize>; 3] = [
        vec![0, 1, 2, 3, 4, 5, 6],
        vec![6, 5, 4, 3, 2, 1, 0],
        vec![3, 0, 5, 1, 6, 2, 4],
    ];
    for order in orders {
        let mut r =
            Replica::<OH, MH, NH>::new(keys.clone(), config).trust_unproven_joins_for_tests();
        // The joins' barrier closes, and the records proved against its root follow.
        for &i in order.iter().filter(|i| **i < 3) {
            r.ingest(base[i].clone()).unwrap();
        }
        r.barrier();
        for &i in order.iter().filter(|i| **i >= 3) {
            r.ingest(base[i].clone()).unwrap();
        }
        assert_eq!(r.status(&post_eh), Some(Status::Applied), "post applied");
        assert_eq!(
            r.poll(&poll_eh).unwrap().ban_tally(),
            (2, 0),
            "both bans counted"
        );
        // Before the barrier the callback tree is empty (no ban yet).
        assert_eq!(r.cb_memb_root(), CbT::new().memb_root());
        r.barrier();
        // After the barrier the ban has been settled into the callback tree.
        assert_ne!(
            r.cb_memb_root(),
            CbT::new().memb_root(),
            "the ban is now a called ticket"
        );
        fingerprints.push((r.obj_root(), r.cb_memb_root(), r.cb_nmemb_root()));
    }
    assert!(
        fingerprints.iter().all(|f| *f == fingerprints[0]),
        "every replica converges on the same object AND callback roots — the ban is visible identically to all"
    );

    // Prepare a replica that has seen the ban, for the scan assertions.
    let mut r = Replica::<OH, MH, NH>::new(keys.clone(), config).trust_unproven_joins_for_tests();
    for bytes in &base[..3] {
        r.ingest(bytes.clone()).unwrap();
    }
    r.barrier();
    for bytes in &base[3..] {
        r.ingest(bytes.clone()).unwrap();
    }
    r.barrier();
    // The ban was settled at barrier 2 (epoch 1). Scans prove against the callback set
    // pinned at the start of an epoch, so it reaches members at the next one: cross to
    // epoch 2, where the scans below are made.
    r.barrier();
    r.barrier();
    let scan_epoch = r.current_epoch();

    // (b) A stale, pre-ban scan (nonmembership against the empty callback set) is
    //     rejected once the replica has crossed the ban barrier — the O10 defense.
    let mut t_stale = t.clone();
    let stale = scan_of(
        &mut rng,
        &mut t_stale,
        &shadow_after_p,
        &CbT::new(),
        &scan_pk,
        root_after_p,
        scan_epoch,
    );
    let (stale_b, _) = encode(&stale).unwrap();
    assert_eq!(
        r.ingest(stale_b).unwrap(),
        Status::Rejected("scan names a superseded barrier"),
        "a scan proving the ticket was never called is stale after the ban"
    );

    // (c) T's post-ban scan, against the replica's current callback store,
    //     ABSORBS the ban (the membership branch — d1's untested path) and is
    //     accepted.
    // What an honest member proves against: the callback set the replica pinned at the
    // start of this epoch. It holds the ban (settled at barrier 2, in epoch 1) and the
    // ballots' tickets, settled with no reputation when they expired at the end of epoch 1.
    let cbs_post = r.callback_store().clone();
    assert_ne!(cbs_post.memb_root(), CbT::new().memb_root(), "the pinned set holds the ban");
    let mut t_good = t.clone();
    let good = scan_of(
        &mut rng,
        &mut t_good,
        &shadow_after_p,
        &cbs_post,
        &scan_pk,
        root_after_p,
        scan_epoch,
    );
    let (good_b, _) = encode(&good).unwrap();
    assert_eq!(
        r.ingest(good_b).unwrap(),
        Status::Applied,
        "the honest post-ban scan absorbs the ban and verifies"
    );
    // T's object, having absorbed BAN_FLAG, is now banned.
    assert_eq!(t_good.data.banned, F::from(1), "the scan set banned = 1");
}

#[test]
#[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
fn verifying_with_a_prepared_key_gives_the_same_answers() {
    // The replica verifies against keys prepared once (PreparedVk) instead of through
    // `verify_interaction` / `Snark::verify`, which re-prepare the key every call. That
    // must change nothing but the speed: same answer for a valid proof, and for every
    // way of naming the wrong public inputs.
    use zk_callbacks::generic::bulletin::UserBul;
    let mut rng = StdRng::seed_from_u64(91);
    let (pk, vk) = standard_keys(&mut rng);
    let (mut user, join) = make_user(&mut rng);
    let mut obj = ObjT::new();
    obj.push(join_object(&join), F::from(0), vec![]);
    let Record::Post {
        exec,
        obj_root,
        payload,
        ..
    } = anon_post(&mut rng, &mut user, &obj, &pk, "x")
    else {
        unreachable!()
    };
    let exec = exec.0;
    let prepared = personas_core::PreparedVk::new(&vk);
    let fresh = ObjT::new();
    let cases = [
        ("valid", exec.new_object, exec.old_nullifier, obj_root.0),
        (
            "wrong root",
            exec.new_object,
            exec.old_nullifier,
            obj_root.0 + F::from(1),
        ),
        (
            "wrong nullifier",
            exec.new_object,
            exec.old_nullifier + F::from(1),
            obj_root.0,
        ),
        (
            "wrong object",
            exec.new_object + F::from(1),
            exec.old_nullifier,
            obj_root.0,
        ),
    ];
    for (i, (label, object, nul, root)) in cases.into_iter().enumerate() {
        let library = <ObjT as UserBul<F, MsgUser>>::verify_interaction::<PostArgs<F>, Snark, 1>(
            &fresh,
            object,
            nul,
            PostArgs { payload: payload.0, epoch: F::from(0) },
            exec.cb_com_list,
            exec.proof.clone(),
            Some(root),
            &vk,
        );
        let mut cache = std::collections::HashMap::new();
        let ours = super::memo_interaction::<OH, _, 1>(
            &mut cache,
            Eh([i as u8; 32]),
            &prepared,
            object,
            nul,
            PostArgs { payload: payload.0, epoch: F::from(0) },
            exec.cb_com_list,
            &exec.proof,
            root,
        );
        assert_eq!(
            ours, library,
            "{label}: prepared and library checks must agree"
        );
        assert_eq!(ours, label == "valid", "{label}");
    }
}

/// A record's bytes after rewriting it the way a relaying member could.
fn rewrite(bytes: &[u8], mutate: &dyn Fn(&mut Record)) -> (Vec<u8>, Eh) {
    let (mut rec, _) = super::record::decode(bytes).unwrap();
    mutate(&mut rec);
    encode(&rec).unwrap()
}

/// What the audit's content tests share: two joined members, and an honest post with its
/// bytes, by the first of them.
struct AuditSetup {
    keys: ReplicaKeys,
    joins: Vec<(F, Vec<u8>, Eh)>,
    shadow: ObjT,
    root: F,
    voter: User<F, MsgUser>,
    pred_pk: PK,
    post: Vec<u8>,
    post_eh: Eh,
    rng: StdRng,
}

fn audit_setup() -> AuditSetup {
    let mut rng = StdRng::seed_from_u64(77);
    let (std_pk, std_vk) = standard_keys(&mut rng);
    let (_scan_pk, scan_vk) = scan_keys(&mut rng, &CbT::new());
    let (pred_pk, pred_vk) = pseudo_keys(&mut rng);
    let keys = full_keys(&std_vk, &scan_vk, &pred_vk);
    let mut author = member(&mut rng);
    let voter = member(&mut rng);
    let mut joins = vec![join_of(&author), join_of(&voter)];
    joins.sort_by_key(|j| j.2);
    let mut shadow = ObjT::new();
    for (com, _, _) in &joins {
        shadow.push(*com, F::from(0), vec![]);
    }
    let root = shadow.root();
    let exec = author
        .exec_method_create_cb::<H, PostArgs<F>, PostArgsVar<F>, (), (), Args, ArgsVar, Cr, Snark, ObjT, 1>(
            &mut rng,
            get_standard_interaction(),
            [FakeSigPubkey::pk()],
            Time::from(0),
            &shadow,
            false,
            &std_pk,
            PostArgs { payload: super::record::post_payload("honest text"), epoch: F::from(0) },
            (),
        )
        .expect("post proof");
    let post = Record::Post {
        flavour: Flavour::Anon,
        exec: Ark(exec),
        extra: Ark(vec![]),
        body: "honest text".into(),
        payload: Ark(super::record::post_payload("honest text")),
        obj_root: Ark(root),
    };
    let (post, post_eh) = encode(&post).unwrap();
    AuditSetup {
        keys,
        joins,
        shadow,
        root,
        voter,
        pred_pk,
        post,
        post_eh,
        rng,
    }
}

fn audit_replica(s: &AuditSetup) -> Replica<OH, MH, NH> {
    let config = Config {
        root_window: 256,
        barriers_per_epoch: 2,
        poll_close_barriers: 1,
    };
    let mut r = Replica::<OH, MH, NH>::new(s.keys.clone(), config).trust_unproven_joins_for_tests();
    for j in &s.joins {
        r.ingest_at(j.1.clone(), 0).unwrap();
    }
    r.advance_to(1);
    r
}

/// Audit C1: a member keeps a post's proof and changes its text. Neither copy of the
/// forgery may stand, whichever arrives first, and the author's post must.
#[test]
#[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
fn a_post_body_cannot_be_rewritten_under_its_proof() {
    let s = audit_setup();
    let honest = s.post_eh;
    // Same payload: the same identity, with text that does not match it.
    let (mismatched, _) = rewrite(&s.post, &|r| {
        if let Record::Post { body, .. } = r {
            *body = "FORGED text".into();
        }
    });
    // The payload rewritten to match: a new identity, and a proof about another payload.
    let (forged, forged_eh) = rewrite(&s.post, &|r| {
        if let Record::Post { body, payload, .. } = r {
            *body = "FORGED text".into();
            payload.0 = super::record::post_payload("FORGED text");
        }
    });
    let mut r = audit_replica(&s);
    r.ingest_at(mismatched, 0).unwrap();
    r.ingest_at(forged, 0).unwrap();
    r.ingest_at(s.post.clone(), 0).unwrap();
    assert_eq!(r.status(&honest), Some(Status::Applied));
    assert_eq!(r.status(&forged_eh), None);
}

/// Audit C1: changing a ballot's option under its proof must not change the tally.
#[test]
#[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
fn a_ballot_cannot_be_flipped_under_its_proof() {
    let mut s = audit_setup();
    let poll = Record::PollOpen {
        question: "ban?".into(),
        options: vec!["ban".into(), "keep".into()],
        kind: PollKind::Ban,
        target: Some(s.post_eh),
    };
    let (poll_bytes, poll_eh) = encode(&poll).unwrap();
    let (vote, _, _) = ban_vote(
        &mut s.rng,
        &mut s.voter,
        &s.shadow,
        s.root,
        poll_eh,
        &s.pred_pk,
    );
    let (flipped, _) = rewrite(&vote, &|r| {
        if let Record::Vote { option, .. } = r {
            *option = super::tally::KEEP_OPTION;
        }
    });
    let mut r = audit_replica(&s);
    r.ingest_at(s.post.clone(), 1).unwrap();
    r.ingest_at(poll_bytes, 1).unwrap();
    r.ingest_at(vote, 1).unwrap();
    assert_eq!(r.poll(&poll_eh).unwrap().ban_tally(), (1, 0));
    r.ingest_at(flipped, 1).unwrap();
    assert_eq!(r.poll(&poll_eh).unwrap().ban_tally(), (1, 0));
}

/// Beyond the audit: a Groth16 proof can be re-randomized and `view` is outside it, so a
/// copy of a post can be re-encoded. Bans and ratings aimed at the original must keep
/// working, so the copy has to be the same record.
#[test]
#[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
fn a_recoded_copy_of_a_post_is_the_same_record() {
    let s = audit_setup();
    let (rec, _) = super::record::decode(&s.post).unwrap();
    let claim = super::record::ViewClaim {
        barrier: 7,
        digest: [1; 32],
    };
    let (copy, copy_eh) = super::record::encode_with_view(&rec, Some(claim)).unwrap();
    assert_eq!(copy_eh, s.post_eh);
    let mut r = audit_replica(&s);
    r.ingest_at(copy, 0).unwrap();
    r.ingest_at(s.post.clone(), 0).unwrap();
    assert_eq!(r.status(&s.post_eh), Some(Status::Applied));
}

/// Beyond the audit: the proof covers a ticket's commitment and the replica invokes the
/// published ticket. Publishing another one would make a post that no ban can reach.
#[test]
#[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
fn a_post_cannot_publish_a_ticket_its_proof_did_not_commit_to() {
    let s = audit_setup();
    let (swapped, _) = rewrite(&s.post, &|r| {
        if let Record::Post { exec, .. } = r {
            exec.0.cb_tik_list[0].0.com_rand = F::from(12345u64);
        }
    });
    let mut r = audit_replica(&s);
    let refused = r.ingest_at(swapped, 0).unwrap();
    assert!(matches!(refused, Status::Rejected(_)));
    // A refused copy leaves the identity free for the real record.
    r.ingest_at(s.post.clone(), 0).unwrap();
    assert_eq!(r.status(&s.post_eh), Some(Status::Applied));
}

/// Audit M5: a rate-limited post is bound to its topic and its persona number. The topic a
/// client displays rests on `post_context`, so the context in the record must be the one
/// the proof was made in, and a fourth persona must not get in by editing the record.
#[test]
#[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
fn a_rate_limited_post_cannot_change_its_topic_or_persona() {
    let mut rng = StdRng::seed_from_u64(78);
    let (rate_pk, rate_vk): (PK, VK) = get_standard_pseudo_rate_interaction()
        .generate_keys::<H, Snark, Cr, ObjT>(&mut rng, None, PseudonymArgsRate::default(), false);
    let mut keys = standard_only_keys(&rate_vk);
    keys.pseudo_rate = rate_vk;

    let mut author = member(&mut rng);
    let join = join_of(&author);
    let mut shadow = ObjT::new();
    shadow.push(join.0, F::from(0), vec![]);
    let root = shadow.root();

    let body = "rate limited";
    let payload = super::record::post_payload(body);
    let context = F::from(123_456u64);
    let i = F::from(2u64);
    let claimed = persona::pseudonym_rate(&author.data.sk, &context, &i);
    let exec = author
        .exec_method_create_cb::<H, PseudonymArgsRate<F>, PseudonymArgsRateVar<F>, (), (), Args, ArgsVar, Cr, Snark, ObjT, 1>(
            &mut rng,
            get_standard_pseudo_rate_interaction(),
            [FakeSigPubkey::pk()],
            Time::from(0),
            &shadow,
            false,
            &rate_pk,
            PseudonymArgsRate {
                context,
                claimed,
                i,
                payload,
                epoch: F::from(0),
            },
            (),
        )
        .expect("post proof");
    let (post, post_eh) = encode(&Record::Post {
        flavour: Flavour::PseudoRate,
        exec: Ark(exec),
        extra: Ark(vec![context, claimed, i]),
        body: body.into(),
        payload: Ark(payload),
        obj_root: Ark(root),
    })
    .unwrap();

    let with_extra = |index: usize, value: u64| {
        rewrite(&post, &|r| {
            if let Record::Post { extra, .. } = r {
                extra.0[index] = F::from(value);
            }
        })
    };
    let (other_topic, other_topic_eh) = with_extra(0, 654_321);
    let (other_persona, other_persona_eh) = with_extra(2, 1);
    let (fourth_persona, fourth_persona_eh) = with_extra(2, 3);

    let config = Config {
        root_window: 256,
        barriers_per_epoch: 2,
        poll_close_barriers: 1,
    };
    let mut r = Replica::<OH, MH, NH>::new(keys, config).trust_unproven_joins_for_tests();
    r.ingest_at(join.1, 0).unwrap();
    r.advance_to(1);

    for forged in [other_topic, other_persona, fourth_persona] {
        assert!(matches!(
            r.ingest_at(forged, 1).unwrap(),
            Status::Rejected(_)
        ));
    }
    assert_eq!(r.ingest_at(post, 1).unwrap(), Status::Applied);

    assert_eq!(r.post_context(&post_eh), Some(123_456));
    for forged in [other_topic_eh, other_persona_eh, fourth_persona_eh] {
        assert_ne!(r.status(&forged), Some(Status::Applied));
        assert_eq!(r.post_context(&forged), None);
    }
}

// ---------------------------------------------------------------------------------------
// Every feature leaves a callback (protocol version 5): posts with a claim, and ballots
// that advance the voter's object but cannot be targeted.
// ---------------------------------------------------------------------------------------

/// A post with a claim by `author`, proved against `obj` (which must hold its object).
fn claim_post(
    rng: &mut StdRng,
    author: &mut User<F, MsgUser>,
    obj: &ObjT,
    pk: &PK,
    flavour: Flavour,
    a: F,
    b: F,
) -> Record {
    use personas_core::circuits::{ClaimArgs, ClaimArgsVar, get_claim_interaction};
    let context = F::from(41u64);
    let claimed = persona::pseudonym(&author.data.sk, &context);
    let body = "a post with a claim";
    let payload = super::record::post_payload(body);
    let exec = author
        .exec_method_create_cb::<H, ClaimArgs<F>, ClaimArgsVar<F>, (), (), Args, ArgsVar, Cr, Snark, ObjT, 1>(
            rng,
            get_claim_interaction(flavour.claim().expect("a claim flavour")),
            [FakeSigPubkey::pk()],
            Time::from(0),
            obj,
            false,
            pk,
            ClaimArgs {
                post: PseudonymArgs {
                    context,
                    claimed,
                    payload,
                    epoch: F::from(0),
                },
                a,
                b,
            },
            (),
        )
        .expect("claim post proof");
    Record::Post {
        flavour,
        exec: Ark(exec),
        extra: Ark(vec![context, claimed, a, b]),
        body: body.into(),
        payload: Ark(payload),
        obj_root: Ark(obj.root()),
    }
}

#[test]
#[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
fn posts_with_a_claim_prove_it_and_nothing_else() {
    use personas_core::circuits::{Claim, ClaimArgs, FACULTY_F, INDUSTRY_F, STUDENT_F, get_claim_interaction, rep_threshold};
    let mut rng = StdRng::seed_from_u64(55);
    let (_std_pk, std_vk) = standard_keys(&mut rng);
    let claim_keys = |rng: &mut StdRng, c| {
        get_claim_interaction(c).generate_keys::<H, Snark, Cr, ObjT>(rng, None, ClaimArgs::default(), false)
    };
    let (badge_pk, badge_vk) = claim_keys(&mut rng, Claim::ShowBadge);
    let (merge_pk, merge_vk) = claim_keys(&mut rng, Claim::MergePersonas);
    let (rep_pk, rep_vk) = claim_keys(&mut rng, Claim::RepAtLeast);
    let mut keys = standard_only_keys(&std_vk);
    keys.show_badge = badge_vk;
    keys.merge_personas = merge_vk;
    keys.rep_at_least = rep_vk;

    // Three members (joins are trusted here, so they may start with a badge and
    // reputation, standing in for ones absorbed by earlier scans).
    let mut faculty = User::create(MsgUser { sk: F::from(11u64), badge1: *FACULTY_F, ..Default::default() }, &mut rng);
    let merger = member(&mut rng);
    let mut reputable = User::create(MsgUser { sk: F::from(13u64), reputation: rep_threshold(5), ..Default::default() }, &mut rng);
    let joins = [join_of(&faculty), join_of(&merger), join_of(&reputable)];
    let mut obj = ObjT::new();
    for (com, _, _) in &joins {
        obj.push(*com, F::from(0), vec![]);
    }
    let config = Config { root_window: 256, barriers_per_epoch: 2, poll_close_barriers: 1 };
    let fresh = || {
        let mut r = Replica::<OH, MH, NH>::new(keys.clone(), config).trust_unproven_joins_for_tests();
        for j in &joins {
            r.ingest_at(j.1.clone(), 0).unwrap();
        }
        r.advance_to(1);
        r
    };

    let second = F::from(43u64);
    let records = [
        claim_post(&mut rng, &mut faculty, &obj, &badge_pk, Flavour::ShowBadge, F::from(1u64), *FACULTY_F),
        claim_post(&mut rng, &mut merger.clone(), &obj, &merge_pk, Flavour::MergePersonas, second, persona::pseudonym(&merger.data.sk, &second)),
        claim_post(&mut rng, &mut reputable.clone(), &obj, &rep_pk, Flavour::RepAtLeast, rep_threshold(3), F::from(0u64)),
    ];
    let mut r = fresh();
    for rec in &records {
        let (bytes, eh) = encode(rec).unwrap();
        r.ingest_at(bytes, 1).unwrap();
        assert_eq!(r.status(&eh), Some(Status::Applied), "{:?} applies", rec.kind());
    }

    // Changing the claim under its proof, or making a meaningless one, is refused.
    let rep_post = encode(&records[2]).unwrap().0;
    let badge_post = encode(&records[0]).unwrap().0;
    let tampered = [
        (rewrite(&rep_post, &|r| if let Record::Post { extra, .. } = r { extra.0[2] = rep_threshold(9) }), "proof failed"),
        (rewrite(&badge_post, &|r| if let Record::Post { extra, .. } = r { extra.0[3] = *STUDENT_F }), "not a badge of that slot"),
        (rewrite(&badge_post, &|r| if let Record::Post { extra, .. } = r { extra.0[2] = F::from(3u64); extra.0[3] = *INDUSTRY_F }), "proof failed"),
        (rewrite(&rep_post, &|r| if let Record::Post { extra, .. } = r { extra.0[2] = rep_threshold(1 << 21) }), "reputation threshold out of range"),
    ];
    for ((bytes, eh), why) in tampered {
        let mut r = fresh();
        let outcome = r.ingest_at(bytes, 1);
        let refused = match outcome {
            Err(_) => true,
            Ok(Status::Rejected(_)) => true,
            Ok(_) => matches!(r.status(&eh), Some(Status::Rejected(_))),
        };
        assert!(refused, "a tampered claim is refused ({why}): {outcome:?}");
    }

    // A member who does NOT hold the claim cannot even prove it.
    let mut no_badge = merger.clone();
    let prove = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        claim_post(&mut rng, &mut no_badge, &obj, &badge_pk, Flavour::ShowBadge, F::from(1u64), *FACULTY_F)
    }));
    if let Ok(rec) = prove {
        let (bytes, eh) = encode(&rec).unwrap();
        let mut r = fresh();
        let _ = r.ingest_at(bytes, 1);
        assert_ne!(r.status(&eh), Some(Status::Applied), "a badge one does not hold is not shown");
    }
    let _ = &mut reputable;
}

#[test]
#[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
fn a_ballot_files_a_ticket_but_cannot_be_targeted() {
    let mut s = audit_setup();
    let poll = Record::PollOpen {
        question: "lunch?".into(),
        options: vec!["yes".into(), "no".into()],
        kind: PollKind::Standard,
        target: None,
    };
    let (poll_bytes, poll_eh) = encode(&poll).unwrap();
    let (vote, vote_eh, _) = ban_vote(&mut s.rng, &mut s.voter, &s.shadow, s.root, poll_eh, &s.pred_pk);
    let mut r = audit_replica(&s);
    r.ingest_at(poll_bytes, 1).unwrap();
    r.ingest_at(vote, 1).unwrap();
    assert_eq!(r.status(&vote_eh), Some(Status::Applied));
    let before = r.obj_root();
    // The ballot is an interaction: its successor object is in the tree.
    assert_ne!(before, s.root, "the ballot advanced the object tree");

    // Later records, in the next barrier (within one barrier, records apply in envelope
    // order, so one could precede the ballot it names; a ban landing on a ballot is
    // refused at settlement either way, by `Derived::ban`).
    r.advance_to(2);
    let refused = |r: &mut Replica<OH, MH, NH>, rec: Record| {
        let (bytes, eh) = encode(&rec).unwrap();
        let _ = r.ingest_at(bytes, 2);
        r.status(&eh)
    };
    assert_eq!(
        refused(&mut r, Record::Ban { target: vote_eh }),
        Some(Status::Rejected(super::tally::NOT_TARGETABLE)),
        "an admin cannot ban a voter through their ballot"
    );
    assert_eq!(
        refused(&mut r, Record::BadgeApprove { target: vote_eh, slot: 1 }),
        Some(Status::Rejected(super::tally::NOT_TARGETABLE)),
        "nor approve a badge on it"
    );
    assert_eq!(
        refused(&mut r, Record::PollOpen { question: "ban the voter?".into(), options: vec!["ban".into(), "keep".into()], kind: PollKind::Ban, target: Some(vote_eh) }),
        Some(Status::Rejected(super::tally::NOT_TARGETABLE)),
        "nor open a ban poll on it"
    );
}
