//! Fast engine tests (workstream d3).
//!
//! These exercise the deterministic state machine — canonical ordering,
//! buffering, journal replay, idempotence — without a single Groth16 proof. The
//! records that carry no proof (`Join`, `PollOpen`) are enough to test the
//! *ordering* discipline, which is where convergence lives (§1/§4); the
//! proof-carrying accept rules are covered end-to-end in [`super::e2e_tests`].

use super::record::{Ark, Record, encode};
use super::{Config, Replica, Status};
use personas_core::F;

/// A concrete, small height so the const generics are pinned (the proof-free tests
/// never touch a key, so the heights are immaterial — small just keeps the
/// per-ingest rebuild's Poseidon count low in a debug build).
type TestReplica = Replica<4, 4, 4>;

/// A `Join` committing the object `x` (its value is opaque to the engine, which
/// only appends it to the tree).
fn join(x: u64) -> (Vec<u8>, super::record::Eh) {
    let rec = Record::Join {
        object: Ark(F::from(x)),
        old_nul: Ark(F::from(1_000_000 + x)),
    };
    encode(&rec).unwrap()
}

/// A replica with placeholder keys — fine because these tests only ingest records
/// that carry no proof, so no key is ever touched.
fn replica() -> TestReplica {
    TestReplica::new(placeholder_keys(), Config::default())
}

/// A `ReplicaKeys` whose verifying keys are default/empty — never used by the
/// proof-free tests here.
fn placeholder_keys() -> super::ReplicaKeys {
    use ark_groth16::VerifyingKey;
    let vk = VerifyingKey::default();
    super::ReplicaKeys {
        standard: vk.clone(),
        pseudo: vk.clone(),
        pseudo_rate: vk.clone(),
        scan: vk.clone(),
        pseudonym_pred: vk,
    }
}

#[test]
fn joins_converge_regardless_of_arrival_order() {
    let a = join(1);
    let b = join(2);
    let c = join(3);

    let mut roots = Vec::new();
    for order in [
        vec![&a, &b, &c],
        vec![&c, &b, &a],
        vec![&b, &a, &c],
        vec![&c, &a, &b],
    ] {
        let mut r = replica();
        for (bytes, eh) in order.iter().map(|x| (&x.0, x.1)) {
            r.ingest(bytes.clone()).unwrap();
            assert_eq!(r.status(&eh), Some(Status::Applied));
        }
        roots.push(r.obj_root());
    }
    assert!(
        roots.iter().all(|x| *x == roots[0]),
        "the canonical (ascending-eh) order makes the tree arrival-independent"
    );
}

#[test]
fn a_duplicate_record_is_ingested_once() {
    let (bytes, _eh) = join(7);
    let mut r = replica();

    assert_eq!(r.ingest(bytes.clone()).unwrap(), Status::Applied);
    let root_after_first = r.obj_root();

    // Delivered again — no second append, same root.
    assert_eq!(r.ingest(bytes.clone()).unwrap(), Status::Applied);
    assert_eq!(r.obj_root(), root_after_first);
}

#[test]
fn a_record_naming_an_unproduced_root_is_buffered_then_applied() {
    // A vote naming a poll that has not arrived is not applicable, so it never runs
    // its (here irrelevant) proof — it simply waits.
    let poll = Record::PollOpen {
        question: "ban?".into(),
        options: vec!["ban".into(), "keep".into()],
        kind: super::record::PollKind::Ban,
        target: None,
    };
    let (poll_b, poll_eh) = encode(&poll).unwrap();

    let vote = Record::Vote {
        poll: poll_eh,
        option: 0,
        proof: Ark(ark_groth16::Proof::default()),
        claimed: Ark(F::from(5)),
        obj_root: Ark(F::from(999)), // never produced
    };
    let (vote_b, vote_eh) = encode(&vote).unwrap();

    let mut r = replica();
    // Vote first: its object root was never produced (and its poll is absent), so it
    // buffers rather than crashing on the dummy proof.
    assert_eq!(r.ingest(vote_b.clone()).unwrap(), Status::Buffered);
    // The poll applies unconditionally; the vote still buffers because its named
    // object root is not one this replica produced (§5.1).
    r.ingest(poll_b).unwrap();
    assert_eq!(r.status(&poll_eh), Some(Status::Applied));
    assert_eq!(r.status(&vote_eh), Some(Status::Buffered));
}

/// A `Ban` poll with no target — enough to watch it open at a chosen barrier and
/// close on cadence, with no proof in sight.
fn ban_poll() -> (Vec<u8>, super::record::Eh) {
    encode(&Record::PollOpen {
        question: "ban?".into(),
        options: vec!["ban".into(), "keep".into()],
        kind: super::record::PollKind::Ban,
        target: None,
    })
    .unwrap()
}

#[test]
fn ingest_at_places_a_record_by_its_supplied_barrier_not_the_local_one() {
    // The d5 cadence path: even though this replica has already reached barrier 5, a
    // record whose service timestamp buckets to barrier 0 must be *placed* at barrier 0
    // — that is what makes two replicas agree on it regardless of when each received it.
    let (poll, eh) = ban_poll();
    let mut r = replica();
    r.advance_to(5);
    r.ingest_at(poll, 0).unwrap();
    assert_eq!(
        r.poll(&eh).unwrap().opened_barrier,
        0,
        "the record is bucketed by its own barrier, not the replica's current one"
    );
}

#[test]
fn an_authoritative_arrival_reconciles_a_provisional_self_fold() {
    // `ingest` (a sender's optimistic self-fold) stamps the local barrier; the later
    // service-stamped `ingest_at` of the same record replaces it — the emit-then-
    // ingest-own-echo finalisation.
    let (poll, eh) = ban_poll();
    let mut r = replica();
    r.advance_to(3);
    r.ingest(poll.clone()).unwrap(); // provisional: opened at the local barrier 3
    assert_eq!(r.poll(&eh).unwrap().opened_barrier, 3);
    r.ingest_at(poll, 0).unwrap(); // authoritative: the service stamp says barrier 0
    assert_eq!(
        r.poll(&eh).unwrap().opened_barrier,
        0,
        "the authoritative barrier wins the reconciliation"
    );
}

#[test]
fn advance_to_closes_a_ban_poll_on_cadence() {
    // The heartbeat's settle trigger: a poll opened at barrier 0 closes once the replica
    // reaches `poll_close_barriers`, and not before.
    let (poll, eh) = ban_poll();
    let config = Config::default();
    let close = config.poll_close_barriers;
    let mut r = Replica::<4, 4, 4>::new(placeholder_keys(), config);
    r.ingest_at(poll, 0).unwrap();
    assert!(!r.poll(&eh).unwrap().closed, "open at barrier 0");

    r.advance_to(close - 1);
    assert!(!r.poll(&eh).unwrap().closed, "still open one barrier short");

    r.advance_to(close);
    assert!(
        r.poll(&eh).unwrap().closed,
        "closed once the cadence reaches the close barrier"
    );
}

#[test]
fn advance_to_is_monotone_and_idempotent() {
    let (a, a_eh) = join(21);
    let mut r = replica();
    r.ingest_at(a, 0).unwrap();
    r.advance_to(4);
    assert_eq!(r.current_barrier(), 4);
    // A stale/duplicate advance never rewinds the barrier.
    r.advance_to(2);
    assert_eq!(r.current_barrier(), 4, "advance_to never goes backwards");
    assert_eq!(r.status(&a_eh), Some(Status::Applied));
}

#[test]
fn the_journal_survives_a_restart() {
    let dir = std::env::temp_dir().join(format!(
        "personas-replica-journal-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("log.bin");

    let (a, a_eh) = join(11);
    let (b, _) = join(12);

    let root;
    {
        let mut r = TestReplica::open(&path, placeholder_keys(), Config::default()).unwrap();
        r.ingest(a.clone()).unwrap();
        r.ingest(b.clone()).unwrap();
        root = r.obj_root();
    }

    // Reopen: the journal replays the same records into the same tree.
    let reopened = TestReplica::open(&path, placeholder_keys(), Config::default()).unwrap();
    assert_eq!(reopened.obj_root(), root, "replay reproduces the root");
    assert_eq!(reopened.status(&a_eh), Some(Status::Applied));

    let _ = std::fs::remove_dir_all(&dir);
}
