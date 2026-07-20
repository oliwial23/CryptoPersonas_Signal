//! Serverless mode on the CLI (workstream **d4**).
//!
//! Unlike every other `personas` subcommand, this one does not talk to a server —
//! serverless deletes the server. It drives a local
//! [`Messenger`](personas_messenger::Messenger) (a d3 replica plus a send side) over
//! a messenger transport. Today only the in-process `mock` transport is wired, so the
//! runnable demo orchestrates several members in one process; real multi-process
//! Signal arrives with the modified client (e2).
//!
//! `personas messenger demo` is the M3 flagship made runnable: three members converge
//! on a shared log, a ban poll passes, and the banned persona's post is flagged at
//! every client — printed so a human can watch it happen.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use rand::{SeedableRng, rngs::StdRng};

use personas_bulletin::merkle::params::ensure_merkle_keys;
use personas_bulletin::replica::record::PollKind;
use personas_bulletin::replica::tally::BAN_OPTION;
use personas_bulletin::replica::{Config as ReplicaConfig, ReplicaKeys};
use personas_config::Config;
use personas_core::F;
use personas_messenger::{Emitted, Member, MemberKeys, Messenger, SendError, carriage, render};
use transport_api::{ConversationId, Incoming, MessageId, Transport};
use transport_mock::MockTransport;

use crate::parse::MessengerCmd;

pub fn run(cmd: &MessengerCmd, cfg: &Config) -> Result<()> {
    match cmd {
        MessengerCmd::Demo => demo(cfg),
    }
}

fn demo(cfg: &Config) -> Result<()> {
    let data_dir = cfg
        .client
        .data_dir
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("messenger-data"));

    println!(
        "→ Loading Merkle-mode keys from {} (first run generates them — this is slow) …",
        data_dir.display()
    );
    let keys = ensure_merkle_keys(&data_dir).context("failed to prepare Merkle-mode keys")?;
    let replica_keys = ReplicaKeys::from_server_keys(&keys);
    let member_keys = MemberKeys::from_server_keys(&keys);
    println!("  keys ready.\n");

    // The messenger is async (the transport is), so it needs a runtime. Build it by
    // hand and drop it before returning, matching `main`'s discipline.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("could not start the async runtime")?;
    let result = rt.block_on(scenario(replica_keys, member_keys));
    drop(rt);
    result
}

/// Deliver a produced record to a messenger through the real carriage → chat-message
/// → decode → ingest path (idempotent for the sender's own record).
fn deliver(m: &mut Messenger, e: &Emitted) {
    let carried = carriage::encode(&e.bytes);
    let incoming = Incoming::Message {
        id: MessageId("demo".into()),
        conversation: m.conversation().clone(),
        sender: "peer".into(),
        body: carried.body,
        reply_to: None,
        attachments: carried.attachment.into_iter().collect(),
        // The demo drives settlement with explicit `barrier()` calls, so every record
        // shares one barrier bucket; a constant service timestamp is all that needs.
        received_at: 0,
    };
    m.ingest_incoming(&incoming);
}

fn deliver_all(members: &mut [Messenger], e: &Emitted) {
    for m in members.iter_mut() {
        deliver(m, e);
    }
}

fn se(e: SendError) -> anyhow::Error {
    anyhow!("{e}")
}

/// The M3 scenario: three members, one persona post, a ban poll that passes, and a
/// barrier that makes the ban bite — every replica converging on the same view.
async fn scenario(rk: ReplicaKeys, mk: MemberKeys) -> Result<()> {
    let mut rng = StdRng::seed_from_u64(2024);
    let conv = ConversationId("serverless-demo".into());
    let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());
    let config = ReplicaConfig {
        root_window: 256,
        settlement_barriers: 3,
        poll_close_barriers: 1,
    };

    let labels = ["poster", "voter-1", "voter-2"];
    let mut members: Vec<Messenger> = labels
        .iter()
        .map(|_| {
            Messenger::new(
                transport.clone(),
                conv.clone(),
                rk.clone(),
                config,
                Some(Member::create(mk.clone(), &mut rng)),
            )
        })
        .collect();

    // (1) Everyone joins; every replica ingests every join.
    println!("→ Three members join.");
    let mut joins = Vec::new();
    for m in members.iter_mut() {
        joins.push(m.emit_join().map_err(se)?);
    }
    for e in &joins {
        deliver_all(&mut members, e);
    }

    // (2) The poster posts under a persona (so the ban has a linkable author).
    println!("→ The poster posts under a persona.");
    let post = members[0]
        .emit_post_pseudo(&mut rng, "here is my hot take", F::from(0xABCDu64))
        .map_err(se)?;
    let post_eh = post.eh;
    deliver_all(&mut members, &post);
    print_views(&members);

    // (3) voter-1 opens a ban poll; both voters vote to ban.
    println!("→ voter-1 opens a ban poll; both voters vote to ban.");
    let poll = members[1]
        .emit_poll(
            "ban this persona?",
            render::ban_poll_options(),
            PollKind::Ban,
            Some(post_eh),
        )
        .map_err(se)?;
    let poll_eh = poll.eh;
    deliver_all(&mut members, &poll);
    let vote1 = members[1]
        .emit_vote(&mut rng, poll_eh, BAN_OPTION)
        .map_err(se)?;
    let vote2 = members[2]
        .emit_vote(&mut rng, poll_eh, BAN_OPTION)
        .map_err(se)?;
    for e in [&vote1, &vote2] {
        deliver_all(&mut members, e);
    }
    println!(
        "  tally on the poster's replica: {} ban / {} keep\n",
        members[0].replica().poll(&poll_eh).unwrap().ban_tally().0,
        members[0].replica().poll(&poll_eh).unwrap().ban_tally().1,
    );

    // (4) Every replica crosses a settlement barrier: the poll closes, the ticket
    //     settles with BAN_FLAG, the callback root advances, the post is flagged.
    println!("→ Every replica crosses a barrier (the ban settles).");
    for m in members.iter_mut() {
        m.barrier();
    }
    print_views(&members);

    // (5) Convergence check across all three replicas.
    let fp = |m: &Messenger| {
        (
            m.replica().obj_root(),
            m.replica().cb_memb_root(),
            m.replica().cb_nmemb_root(),
        )
    };
    let converged = members.iter().all(|m| fp(m) == fp(&members[0]));
    println!(
        "→ Convergence: all three replicas agree on every root: {}",
        if converged { "YES" } else { "NO" }
    );

    // (6) Late join: hand a snapshot to a fresh observer, pinned out-of-band.
    let snapshot = members[0].snapshot();
    let pin = snapshot.digest();
    let joiner = Messenger::adopt(
        transport.clone(),
        conv.clone(),
        rk.clone(),
        config,
        None,
        snapshot,
        &pin,
    )
    .map_err(|e| anyhow!("adopt failed: {e}"))?;
    println!(
        "→ A late joiner adopts the poster's snapshot (pin {}…) and re-derives the same view: {}",
        &members[0].snapshot().digest_hex()[..12],
        if fp(&joiner) == fp(&members[0]) {
            "YES"
        } else {
            "NO"
        }
    );

    Ok(())
}

/// Print each member's rendered chat view side by side, so convergence (and the
/// rendering-gate flag) is visible.
fn print_views(members: &[Messenger]) {
    let labels = ["poster", "voter-1", "voter-2"];
    for (label, m) in labels.iter().zip(members) {
        let lines = m.render();
        let shown = if lines.is_empty() {
            "(no posts yet)".to_string()
        } else {
            lines.join(" | ")
        };
        println!("  [{label}] {shown}");
    }
    println!();
}
