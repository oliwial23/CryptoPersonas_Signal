//! Messenger tests (workstream **d4**).
//!
//! Fast tests exercise the parts that need no proof (carriage over a real
//! [`Incoming`], the no-proof `PollOpen` record). The pipeline and convergence
//! tests need real Groth16 keys/proofs, so they are `#[ignore]` and run in release:
//!
//! ```text
//! cargo test -p personas-messenger --release -- --ignored
//! ```

use super::*;
use personas_bulletin::replica::record::{self, PollKind};
use transport_api::{ConversationId, Incoming, MessageId};

/// A no-proof record survives the full record→carriage→Incoming→carriage→record
/// path — the receive wiring, without any keys.
#[test]
fn a_poll_survives_the_carriage_round_trip() {
    let poll = member::open_poll(
        "ban the poster?",
        render::ban_poll_options(),
        PollKind::Ban,
        None,
    );
    let (bytes, eh) = record::encode(&poll).unwrap();

    let carried = carriage::encode(&bytes);
    let incoming = Incoming::Message {
        id: MessageId("1".into()),
        conversation: ConversationId("room".into()),
        sender: "peer".into(),
        body: carried.body,
        reply_to: None,
        attachments: carried.attachment.into_iter().collect(),
        received_at: 0,
    };

    let recovered = carriage::decode_incoming(&incoming).expect("a record rides here");
    let (back, eh2) = record::decode(&recovered).unwrap();
    assert_eq!(eh, eh2, "carriage preserves the envelope hash");
    assert!(matches!(back, record::Record::PollOpen { .. }));
}

/// Placeholder verifying keys — fine for a proof-free test that only rides a `PollOpen`
/// and drives the heartbeat.
fn placeholder_keys() -> personas_bulletin::replica::ReplicaKeys {
    let vk = ark_groth16::VerifyingKey::default();
    personas_bulletin::replica::ReplicaKeys {
        standard: vk.clone(),
        pseudo: vk.clone(),
        pseudo_rate: vk.clone(),
        scan: vk.clone(),
        pseudonym_pred: vk,
    }
}

/// The heartbeat closes a poll on the shared schedule: a `PollOpen` bucketed into
/// barrier 0 by its service timestamp closes once [`tick`](Messenger::tick) advances the
/// replica past `poll_close_barriers` — no proofs, no manual `barrier()`.
#[test]
fn tick_closes_a_poll_on_the_shared_schedule() {
    use personas_bulletin::replica::Config;
    use transport_api::{ConversationId, Incoming, MessageId};

    let transport: std::sync::Arc<dyn transport_api::Transport> =
        std::sync::Arc::new(transport_mock::MockTransport::new());
    let config = Config::default();
    let mut m = Messenger::<4, 4, 4>::new(
        transport,
        ConversationId("room".into()),
        placeholder_keys(),
        config,
        None,
    )
    .with_heartbeat(Heartbeat::new(0, 1000));

    let poll = member::open_poll(
        "ban?",
        render::ban_poll_options(),
        record::PollKind::Ban,
        None,
    );
    let (bytes, eh) = record::encode(&poll).unwrap();
    let incoming = Incoming::Message {
        id: MessageId("p".into()),
        conversation: m.conversation().clone(),
        sender: "peer".into(),
        body: carriage::encode(&bytes).body,
        reply_to: None,
        attachments: vec![],
        received_at: 250, // barrier 0 (< 1000 ms)
    };
    m.ingest_incoming(&incoming).unwrap().unwrap();
    assert_eq!(m.replica().poll(&eh).unwrap().opened_barrier, 0);
    assert!(!m.replica().poll(&eh).unwrap().closed);

    // A tick short of the close barrier does nothing…
    m.tick((config.poll_close_barriers - 1) * 1000 + 500);
    assert!(!m.replica().poll(&eh).unwrap().closed);

    // …and one that reaches it closes the poll.
    m.tick(config.poll_close_barriers * 1000 + 500);
    assert!(
        m.replica().poll(&eh).unwrap().closed,
        "the heartbeat closed the poll on cadence"
    );
}

// ---------------------------------------------------------------------------------------
// End-to-end, real Groth16 (#[ignore])
// ---------------------------------------------------------------------------------------

mod e2e {
    use super::super::*;
    use crate::member::{Member, MemberKeys};

    use std::sync::Arc;

    use rand::{SeedableRng, rngs::StdRng};

    use personas_bulletin::merkle::params::merkle_scan_pubdata;
    use personas_bulletin::merkle::{MerkleCallbackStore, MerkleObjStore};
    use personas_bulletin::replica::record::PollKind;
    use personas_bulletin::replica::tally::BAN_OPTION;
    use personas_bulletin::replica::{Config, ReplicaKeys, Status};

    use personas_core::circuits::{
        MsgUser, NUM_SCANS_PER_FOLD, PseudonymArgs, PseudonymArgsVar, ScanInt,
        get_scan_interaction, get_standard_interaction, get_standard_pseudo_interaction,
        pseudonym_pred,
    };
    use personas_core::{Cr, F, H, PK, Snark, VK};

    use futures_util::StreamExt;
    use transport_api::{ConversationId, Incoming, MessageId, Transport};
    use transport_mock::MockTransport;
    use zk_callbacks::generic::interaction::generate_keys_for_statement_in;
    use zk_callbacks::generic::object::Time;

    // Tiny heights: the mechanism is height-independent (d3's e2e make the same call).
    const OH: usize = 4;
    const MH: usize = 4;
    const NH: usize = 4;
    type ObjT = MerkleObjStore<F, OH>;
    type CbT = MerkleCallbackStore<F, MH, NH>;
    type Msg = Messenger<OH, MH, NH>;

    /// The four real key pairs this suite needs (standard post, pseudo post, scan,
    /// and the `pseudonym_pred` statement), generated once at tiny heights.
    struct Keys {
        replica: ReplicaKeys,
        member: MemberKeys,
    }

    fn keygen(rng: &mut StdRng) -> Keys {
        let (std_pk, std_vk): (PK, VK) = get_standard_interaction()
            .generate_keys::<H, Snark, Cr, ObjT>(rng, None, F::from(0), false);
        let dummy_pseudo = PseudonymArgs {
            context: F::from(0),
            claimed: F::from(0),
        };
        let (pseudo_pk, pseudo_vk): (PK, VK) = get_standard_pseudo_interaction()
            .generate_keys::<H, Snark, Cr, ObjT>(rng, None, dummy_pseudo.clone(), false);
        let si: ScanInt<CbT> = get_scan_interaction();
        let dummy_scan =
            merkle_scan_pubdata::<MH, NH, NUM_SCANS_PER_FOLD>(&CbT::new(), Time::from(0));
        let (scan_pk, scan_vk): (PK, VK) =
            si.generate_keys::<H, Snark, Cr, ObjT>(rng, None, dummy_scan, true);
        let (pred_pk, pred_vk): (PK, VK) = generate_keys_for_statement_in::<
            F,
            H,
            MsgUser,
            PseudonymArgs<F>,
            PseudonymArgsVar<F>,
            (),
            (),
            Snark,
            ObjT,
        >(rng, pseudonym_pred, None, dummy_pseudo);

        Keys {
            replica: ReplicaKeys {
                standard: std_vk,
                pseudo: pseudo_vk,
                pseudo_rate: scan_vk.clone(), // unused by this suite
                scan: scan_vk,
                pseudonym_pred: pred_vk,
            },
            member: MemberKeys {
                standard: std_pk,
                pseudo: pseudo_pk,
                pseudo_rate: scan_pk.clone(), // unused by this suite
                scan: scan_pk,
                pseudonym_pred: pred_pk,
            },
        }
    }

    fn config() -> Config {
        Config {
            root_window: 256,
            settlement_barriers: 3,
            poll_close_barriers: 1,
        }
    }

    /// Deliver a produced record to a messenger through the full carriage → Incoming
    /// → decode → ingest path (idempotent for the sender's own record).
    fn deliver(m: &mut Msg, e: &Emitted) -> Option<Result<Status, record::CodecError>> {
        deliver_at(m, e, 0)
    }

    /// Deliver with an explicit service timestamp, so a test can straddle barrier
    /// boundaries (the skewed-delivery convergence case). The default `deliver` uses `0`
    /// (one bucket), matching the barrier()-driven flagship.
    fn deliver_at(
        m: &mut Msg,
        e: &Emitted,
        received_at: u64,
    ) -> Option<Result<Status, record::CodecError>> {
        let carried = carriage::encode(&e.bytes);
        let incoming = Incoming::Message {
            id: MessageId("delivered".into()),
            conversation: m.conversation().clone(),
            sender: "peer".into(),
            body: carried.body,
            reply_to: None,
            attachments: carried.attachment.into_iter().collect(),
            received_at,
        };
        m.ingest_incoming(&incoming)
    }

    fn fingerprint(m: &Msg) -> (F, F, F) {
        (
            m.replica().obj_root(),
            m.replica().cb_memb_root(),
            m.replica().cb_nmemb_root(),
        )
    }

    /// The M3 flagship, driven end to end through the messenger pipeline: three
    /// members join, one posts under a persona, a ban poll passes, and after a
    /// barrier every replica converges on identical roots, renders the offending
    /// post **flagged** (the rendering gate), and the banned member's honest scan
    /// absorbs the ban.
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_convergence_ban_and_flag() {
        let mut rng = StdRng::seed_from_u64(7);
        let keys = keygen(&mut rng);
        let conv = ConversationId("serverless-demo".into());
        let mock = Arc::new(MockTransport::new());
        let transport: Arc<dyn Transport> = mock;

        // Three members, three messengers over the same conversation.
        let mut poster = Msg::new(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        );
        let mut v1 = Msg::new(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        );
        let mut v2 = Msg::new(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        );

        // (1) Everyone joins; deliver all three joins to all three replicas.
        let joins = [
            poster.emit_join().unwrap(),
            v1.emit_join().unwrap(),
            v2.emit_join().unwrap(),
        ];
        for e in &joins {
            deliver(&mut poster, e);
            deliver(&mut v1, e);
            deliver(&mut v2, e);
        }

        // (2) The poster posts under a persona (so the ban has a linkable author to
        //     flag), against the full-set root everyone now holds.
        let context = F::from(0xABCD);
        let post = poster
            .emit_post_pseudo(&mut rng, "the offending post", context)
            .unwrap();
        let post_eh = post.eh;
        for m in [&mut poster, &mut v1, &mut v2] {
            deliver(m, &post);
        }

        // (3) v1 opens a ban poll targeting the post; both voters vote to ban.
        let poll = v1
            .emit_poll(
                "ban them?",
                render::ban_poll_options(),
                PollKind::Ban,
                Some(post_eh),
            )
            .unwrap();
        let poll_eh = poll.eh;
        for m in [&mut poster, &mut v1, &mut v2] {
            deliver(m, &poll);
        }
        let vote1 = v1.emit_vote(&mut rng, poll_eh, BAN_OPTION).unwrap();
        let vote2 = v2.emit_vote(&mut rng, poll_eh, BAN_OPTION).unwrap();
        for e in [&vote1, &vote2] {
            for m in [&mut poster, &mut v1, &mut v2] {
                deliver(m, e);
            }
        }

        // Before the barrier the poll tally is visible but nothing is settled.
        assert_eq!(poster.replica().poll(&poll_eh).unwrap().ban_tally(), (2, 0));

        // (4) Every replica crosses one barrier: the poll closes yes>no, the ticket
        //     settles with BAN_FLAG, the callback root advances.
        for m in [&mut poster, &mut v1, &mut v2] {
            m.barrier();
        }

        // (5) Convergence: identical object AND callback roots on all three — the ban
        //     is visible identically to everyone.
        let fp = fingerprint(&poster);
        assert_eq!(fingerprint(&v1), fp, "v1 converges with the poster");
        assert_eq!(fingerprint(&v2), fp, "v2 converges with the poster");
        assert_ne!(
            fp.1,
            CbT::new().memb_root(),
            "the ban is a called ticket now"
        );

        // (6) The rendering gate: the offending post is flagged, not deleted, and the
        //     rendered view is identical across replicas.
        let rendered = poster.render();
        assert_eq!(v1.render(), rendered, "renders converge");
        assert_eq!(v2.render(), rendered, "renders converge");
        assert!(
            rendered
                .iter()
                .any(|line| line.starts_with(render::FLAG_PREFIX)),
            "the banned persona's post is flagged: {rendered:?}"
        );

        // (7) The poster's honest post-ban scan absorbs the ban (banned = 1). It is
        //     produced against the replica's current-barrier callback set and
        //     accepted everywhere.
        let scan = poster.emit_scan(&mut rng).unwrap();
        for m in [&mut poster, &mut v1, &mut v2] {
            assert_eq!(deliver(m, &scan).unwrap().unwrap(), Status::Applied);
        }
        assert_eq!(
            poster.member().unwrap().user.data.banned,
            F::from(1),
            "the scan set banned = 1"
        );
    }

    /// **The d5 convergence proof.** Four replicas receive the same records in different
    /// arrival orders *and* run their heartbeats out of step, yet converge on
    /// byte-identical roots — because each record's settlement barrier is bucketed from
    /// its shared **service timestamp**, not from any replica's local clock (§4/§14).
    ///
    /// The load-bearing replica is the **observer** `obs`: its clock crosses the
    /// poll-close barrier while the poll is still tied 0–0, *then* both ban votes arrive
    /// late. Under a device-clock cadence those votes would be stamped into the later
    /// barrier — after the poll had already closed with no ban — so the observer would
    /// never ban, forking from everyone. Bucketing by the service timestamp keeps the
    /// votes in the barrier they were cast in, and the from-scratch rebuild counts them
    /// *before* the close: the outcome flips from no-ban to ban, and the observer
    /// converges. (Voter `d` additionally receives its votes before the poll they belong
    /// to, exercising the buffer-then-apply path.)
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_skewed_delivery_still_converges_exactly() {
        let mut rng = StdRng::seed_from_u64(43);
        let keys = keygen(&mut rng);
        let conv = ConversationId("skew".into());
        let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());

        // The shared schedule every replica buckets against: 1-second barriers anchored
        // at 0, so a record's barrier is exactly `received_at / 1000`.
        let hb = Heartbeat::new(0, 1000);
        let member = |rng: &mut StdRng| {
            Msg::new(
                transport.clone(),
                conv.clone(),
                keys.replica.clone(),
                config(),
                Some(Member::create(keys.member.clone(), rng)),
            )
            .with_heartbeat(hb)
        };
        let mut poster = member(&mut rng);
        let mut c = member(&mut rng); // voter + poll opener
        let mut d = member(&mut rng); // voter
        // The skew replica: an observer (no member key), so it holds no vote of its own —
        // the late votes genuinely decide the ban.
        let mut obs = Msg::new(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            None,
        )
        .with_heartbeat(hb);

        // (1) Joins, all in barrier 0. Every replica needs all three to hold the full-set
        //     root the coming proofs are built on; the delivery order is shuffled per
        //     replica, which the set-committing object tree converges through regardless.
        let jp = poster.emit_join().unwrap();
        let jc = c.emit_join().unwrap();
        let jd = d.emit_join().unwrap();
        let joins = [(&jp, 100u64), (&jc, 150u64), (&jd, 200u64)];
        for &(e, t) in &[joins[0], joins[1], joins[2]] {
            deliver_at(&mut poster, e, t);
        }
        for &(e, t) in &[joins[2], joins[0], joins[1]] {
            deliver_at(&mut c, e, t);
        }
        for &(e, t) in &[joins[1], joins[2], joins[0]] {
            deliver_at(&mut d, e, t);
        }
        for &(e, t) in &[joins[2], joins[1], joins[0]] {
            deliver_at(&mut obs, e, t);
        }

        // (2) The four "skew set" records, each emitted against the full-join root and
        //     each stamped with a service timestamp in barrier 0 (< 1000 ms). They are
        //     emitted now but delivered in scrambled order below.
        let post = poster
            .emit_post_pseudo(&mut rng, "hot take", F::from(0xBEEFu64))
            .unwrap();
        let poll = c
            .emit_poll(
                "ban them?",
                render::ban_poll_options(),
                PollKind::Ban,
                Some(post.eh),
            )
            .unwrap();
        let vote_c = c.emit_vote(&mut rng, poll.eh, BAN_OPTION).unwrap();
        let vote_d = d.emit_vote(&mut rng, poll.eh, BAN_OPTION).unwrap();
        let (post_t, poll_t, vote_c_t, vote_d_t) = (300u64, 400u64, 500u64, 600u64);

        // Poster: in order.
        deliver_at(&mut poster, &post, post_t);
        deliver_at(&mut poster, &poll, poll_t);
        deliver_at(&mut poster, &vote_c, vote_c_t);
        deliver_at(&mut poster, &vote_d, vote_d_t);

        // Voter d: both votes arrive before the poll they belong to (buffered), then the
        // poll, then the post — a wholly different order.
        deliver_at(&mut d, &vote_c, vote_c_t);
        deliver_at(&mut d, &vote_d, vote_d_t);
        deliver_at(&mut d, &poll, poll_t);
        deliver_at(&mut d, &post, post_t);

        // Voter c: another order.
        deliver_at(&mut c, &post, post_t);
        deliver_at(&mut c, &vote_c, vote_c_t);
        deliver_at(&mut c, &poll, poll_t);
        deliver_at(&mut c, &vote_d, vote_d_t);

        // Observer: crosses barrier 1 (the poll-close barrier) with the poll open and no
        // votes seen — the poll closes tied, no ban — then the votes arrive *late* and
        // must still count.
        deliver_at(&mut obs, &poll, poll_t);
        deliver_at(&mut obs, &post, post_t);
        obs.tick(1_500);
        assert_eq!(
            obs.replica().poll(&poll.eh).unwrap().ban_tally(),
            (0, 0),
            "the observer closed the poll early with no votes seen yet"
        );
        assert_eq!(
            obs.replica().cb_memb_root(),
            CbT::new().memb_root(),
            "and with the poll tied, nothing was banned: the callback set is still empty"
        );
        deliver_at(&mut obs, &vote_d, vote_d_t);
        deliver_at(&mut obs, &vote_c, vote_c_t);

        // (3) Every heartbeat reaches barrier 2 (past the poll close). The observer is at
        //     barrier 1 already; the others jump straight from 0.
        for m in [&mut poster, &mut c, &mut d, &mut obs] {
            m.tick(2_500);
        }

        // (4) Exact convergence: identical object AND callback roots on all four.
        let fp = fingerprint(&poster);
        assert_eq!(
            fingerprint(&obs),
            fp,
            "the observer converges though it crossed the poll-close barrier before its votes arrived"
        );
        assert_eq!(fingerprint(&c), fp, "voter c converges");
        assert_eq!(
            fingerprint(&d),
            fp,
            "voter d converges though its votes were buffered ahead of their poll"
        );
        assert_ne!(
            fp.1,
            CbT::new().memb_root(),
            "the ban settled as a called ticket"
        );
        assert_eq!(
            obs.replica().poll(&poll.eh).unwrap().ban_tally(),
            (2, 0),
            "the late votes retroactively counted (bucketed into barrier 0), flipping the outcome to a ban"
        );

        // (5) Renders converge, with the pseudonymous post flagged everywhere (§9).
        let rendered = poster.render();
        assert_eq!(obs.render(), rendered, "the observer's view matches");
        assert_eq!(c.render(), rendered, "voter c's view matches");
        assert_eq!(d.render(), rendered, "voter d's view matches");
        assert!(
            rendered
                .iter()
                .any(|line| line.starts_with(render::FLAG_PREFIX)),
            "the banned persona's post is flagged: {rendered:?}"
        );
    }

    /// A stale, pre-ban scan is rejected once a replica has crossed the ban barrier —
    /// O10, carried through the messenger layer (§5.2). Isolated from the flagship so
    /// the assertion is unambiguous.
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_stale_scan_is_rejected_after_the_ban() {
        let mut rng = StdRng::seed_from_u64(11);
        let keys = keygen(&mut rng);
        let conv = ConversationId("stale-scan".into());
        let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());

        let mut poster = Msg::new(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        );
        let mut v1 = Msg::new(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        );
        let mut v2 = Msg::new(
            transport,
            conv,
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        );

        let joins = [
            poster.emit_join().unwrap(),
            v1.emit_join().unwrap(),
            v2.emit_join().unwrap(),
        ];
        for e in &joins {
            deliver(&mut poster, e);
            deliver(&mut v1, e);
            deliver(&mut v2, e);
        }

        // The poster posts (anon is fine here) and captures a stale scan against the
        // EMPTY callback set *before* any ban — the archived nonmembership range.
        let post = poster
            .emit_post_pseudo(&mut rng, "post", F::from(1))
            .unwrap();
        for m in [&mut poster, &mut v1, &mut v2] {
            deliver(m, &post);
        }
        // Fork the poster's member to build the stale scan without consuming the
        // object it will later scan for real.
        let mut stale_member = poster.member().unwrap().clone();
        let stale = stale_member
            .scan(&mut rng, poster.replica().obj_store(), &CbT::new())
            .expect("stale scan proof");
        let (stale_bytes, _) = record::encode(&stale).unwrap();

        // Ban the post and cross the barrier on v1.
        let poll = v1
            .emit_poll(
                "ban?",
                render::ban_poll_options(),
                PollKind::Ban,
                Some(post.eh),
            )
            .unwrap();
        for m in [&mut poster, &mut v1, &mut v2] {
            deliver(m, &poll);
        }
        for e in [
            v1.emit_vote(&mut rng, poll.eh, BAN_OPTION).unwrap(),
            v2.emit_vote(&mut rng, poll.eh, BAN_OPTION).unwrap(),
        ] {
            for m in [&mut poster, &mut v1, &mut v2] {
                deliver(m, &e);
            }
        }
        v1.barrier();

        // The stale scan, delivered to the barrier-crossed replica, is rejected: it
        // names a superseded (pre-ban) callback barrier.
        let stale_incoming = Incoming::Message {
            id: MessageId("stale".into()),
            conversation: v1.conversation().clone(),
            sender: "peer".into(),
            body: carriage::encode(&stale_bytes).body,
            reply_to: None,
            attachments: vec![],
            received_at: 0,
        };
        assert_eq!(
            v1.ingest_incoming(&stale_incoming).unwrap().unwrap(),
            Status::Rejected("scan names a superseded barrier"),
        );
    }

    /// A late joiner adopts a snapshot from an inviter, TOFU-pinned (§12): with the
    /// right pin it re-derives identical roots; a wrong pin is refused.
    #[test]
    #[ignore = "generates real Groth16 keys/proofs; run with --release --ignored"]
    fn e2e_snapshot_late_join() {
        let mut rng = StdRng::seed_from_u64(23);
        let keys = keygen(&mut rng);
        let conv = ConversationId("late-join".into());
        let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());

        // One active member builds up some state.
        let mut inviter = Msg::new(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        );
        let join = inviter.emit_join().unwrap();
        deliver(&mut inviter, &join);
        let post = inviter
            .emit_post_pseudo(&mut rng, "history", F::from(9))
            .unwrap();
        deliver(&mut inviter, &post);
        inviter.barrier();

        let snapshot = inviter.snapshot();
        let pin = snapshot.digest();

        // A joiner adopts it against the correct pin and re-derives identical roots.
        let joiner = Messenger::<OH, MH, NH>::adopt(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            None,
            snapshot.clone(),
            &pin,
        )
        .expect("adopt with the right pin");
        assert_eq!(
            fingerprint(&joiner),
            fingerprint(&inviter),
            "roots re-derived"
        );
        assert_eq!(joiner.render(), inviter.render(), "same view");

        // A wrong pin is refused.
        assert!(matches!(
            Messenger::<OH, MH, NH>::adopt(
                transport,
                conv,
                keys.replica,
                config(),
                None,
                snapshot,
                &[0u8; 32],
            ),
            Err(AdoptError::GenesisMismatch),
        ));
    }

    /// The live transport wiring: a poll sent by one messenger reaches an observer
    /// through `subscribe` + carriage + ingest (no hand-delivery).
    #[tokio::test]
    #[ignore = "generates real Groth16 keys; run with --release --ignored"]
    async fn e2e_poll_rides_the_live_transport() {
        let mut rng = StdRng::seed_from_u64(31);
        let keys = keygen(&mut rng);
        let conv = ConversationId("live".into());
        let mock = Arc::new(MockTransport::new());
        let transport: Arc<dyn Transport> = mock.clone();

        let mut sender = Msg::new(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        );
        // An observer subscribes and ingests whatever the transport delivers.
        let observer = Arc::new(tokio::sync::Mutex::new(Msg::new(
            transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            None,
        )));
        let mut stream = transport.subscribe().await.unwrap();

        // Send a poll over the transport; pump the one delivered event into the observer.
        let (poll_eh, _sent) = sender
            .send_poll("live?", render::ban_poll_options(), PollKind::Ban, None)
            .await
            .unwrap();
        let event = stream.next().await.expect("the poll is delivered");
        observer.lock().await.ingest_incoming(&event);

        assert!(
            observer.lock().await.replica().poll(&poll_eh).is_some(),
            "the observer ingested the poll off the live transport"
        );
    }

    /// The **A2 + B1 milestone**: a real Groth16 `Record` converges over REAL Signal.
    ///
    /// Same shape as `e2e_poll_rides_the_live_transport`, but the mock transport is
    /// replaced by two [`PresageTransport`]s talking to the isolated self-hosted
    /// Signal-Server. The sender emits a ban poll (a real record with a real proof); the
    /// transport derives a fresh single-use PPRF message key and AEAD-seals it, then
    /// delivers it over Signal; the observer's transport re-derives the same key from
    /// the wire `MessageTag` and AEAD-opens it; and the observer's `Replica::ingest`
    /// verifies the proof and folds it — the M3 correctness demo, now over Signal.
    ///
    /// Needs the test-server **and** the TLS proxy up (deploy/signal-test-server) plus
    /// live registration, so it is `#[ignore]` even among the e2e suite. Run by hand:
    ///   cargo test -p personas-messenger --release -- --ignored --nocapture \
    ///     e2e_record_converges_over_signal
    ///
    /// Uses a **multi-thread** runtime: presage/libsignal pump their websockets with
    /// `tokio::spawn`, which a current-thread runtime (the `#[tokio::test]` default,
    /// unlike `#[tokio::main]`) starves — registration then fails with a reqwest error.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn e2e_record_converges_over_signal() {
        use transport_presage::PresageTransport;

        let mut rng = StdRng::seed_from_u64(41);
        let keys = keygen(&mut rng);
        let conv = ConversationId("personas-signal".into());

        // Two throwaway accounts (numbers varied per run so a long-lived server never
        // sees a stale account) sharing one sender key.
        let suffix = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            % 10_000) as u16;
        let tmp = tempfile::tempdir().unwrap();
        let db_a = tmp.path().join("a.db3").to_string_lossy().into_owned();
        let db_b = tmp.path().join("b.db3").to_string_lossy().into_owned();
        let a_aci = PresageTransport::register(&db_a, &format!("+1202555{suffix:04}"))
            .await
            .unwrap();
        let b_aci = PresageTransport::register(&db_b, &format!("+1203555{suffix:04}"))
            .await
            .unwrap();
        let shared = PresageTransport::create_group_secret();

        let a_transport: Arc<dyn Transport> = Arc::new(
            PresageTransport::start(db_a, vec![b_aci], shared.clone(), conv.clone(), None)
                .await
                .unwrap(),
        );
        let b_transport: Arc<dyn Transport> = Arc::new(
            PresageTransport::start(db_b, vec![a_aci], shared, conv.clone(), None)
                .await
                .unwrap(),
        );

        let mut sender = Msg::new(
            a_transport,
            conv.clone(),
            keys.replica.clone(),
            config(),
            Some(Member::create(keys.member.clone(), &mut rng)),
        );
        let observer = Arc::new(tokio::sync::Mutex::new(Msg::new(
            b_transport.clone(),
            conv.clone(),
            keys.replica.clone(),
            config(),
            None,
        )));

        // Subscribe B before A sends — the transport broadcasts to current subscribers.
        let mut stream = b_transport.subscribe().await.unwrap();

        // emit (folds into A's own replica) then broadcast separately, so a post-send
        // websocket-teardown race in presage (delivery has already succeeded) does not
        // fail the test — B's ingest is the source of truth.
        let emitted = sender
            .emit_poll("ban?", render::ban_poll_options(), PollKind::Ban, None)
            .unwrap();
        let poll_eh = emitted.eh;
        if let Err(err) = sender.broadcast(&emitted).await {
            eprintln!("broadcast returned {err:?} — delivery may still have succeeded; checking B");
        }

        let event = tokio::time::timeout(std::time::Duration::from_secs(45), stream.next())
            .await
            .expect("timed out waiting for the record to arrive over Signal")
            .expect("the transport stream ended before delivering the record");
        observer.lock().await.ingest_incoming(&event);

        assert!(
            observer.lock().await.replica().poll(&poll_eh).is_some(),
            "the observer ingested the poll off REAL Signal and its replica converged"
        );
    }
}
