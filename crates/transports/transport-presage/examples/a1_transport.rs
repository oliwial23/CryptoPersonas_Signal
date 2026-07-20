//! e2 A2 + B1 milestone — the `PresageTransport` carrying an opaque payload over real
//! Signal, end to end, through the `Transport` trait.
//!
//! Two members (A, B) install the same K2/PPRF group secret. A `send`s a body; B's
//! `subscribe` stream yields it back, having gone: A derives a fresh single-use
//! message key and AEAD-seals → base64 in a Signal `DataMessage` → delivered over the
//! isolated self-hosted Signal-Server → B receive websocket → re-derives the same
//! message key from the wire `MessageTag` and AEAD-opens → `Incoming::Message`. The
//! body here is opaque bytes on purpose — that is all the transport knows; the
//! messenger/replica put real `Record`s through this same seam (the convergence
//! follow-on).
//!
//! Not a `#[test]`: it needs the server + TLS proxy up (see deploy/signal-test-server).
//! Run:  cargo run -p transport-presage --example a1_transport
//! Logs: RUST_LOG=transport_presage=debug,presage=info

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use futures_util::StreamExt as _;
use transport_api::{Incoming, Outgoing, Transport};
use transport_presage::PresageTransport;

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_millis() as u64
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,a1_transport=info".into()),
        )
        .init();

    let suffix = (now_millis() % 10_000) as u16;
    let num_a = format!("+1202555{suffix:04}");
    let num_b = format!("+1203555{suffix:04}");

    let tmp = tempfile::tempdir().context("tempdir")?;
    let db_a = tmp.path().join("a.db3").to_string_lossy().into_owned();
    let db_b = tmp.path().join("b.db3").to_string_lossy().into_owned();

    println!("[1/5] registering A ({num_a}) and B ({num_b})…");
    let a_aci = PresageTransport::register(&db_a, &num_a).await?;
    let b_aci = PresageTransport::register(&db_b, &num_b).await?;
    println!("      A={a_aci:?}  B={b_aci:?}");

    println!("[2/5] creating the group secret…");
    let shared = PresageTransport::create_group_secret();

    println!("[3/5] starting transports (A fans out to B, B to A)…");
    let conversation = format!("personas-group-{suffix:04}");
    let a = PresageTransport::start(db_a, vec![b_aci], shared.clone(), conversation.clone())
        .await
        .context("start A")?;
    let b = PresageTransport::start(db_b, vec![a_aci], shared, conversation.clone())
        .await
        .context("start B")?;

    // Subscribe B BEFORE A sends: the actor broadcasts decoded messages only to current
    // subscribers (there is no replay), so the receiver must exist first.
    println!("[4/5] B subscribes, then A sends…");
    let mut b_stream = b.subscribe().await.context("B.subscribe")?;

    let payload = format!("PZR2:opaque-record-bytes-{suffix:04}"); // stands in for a carriage-encoded Record
    match a
        .send(Outgoing::new(conversation.clone().into(), payload.clone()))
        .await
    {
        Ok(sent) => println!("      A sent id={}", sent.id),
        // Delivery (PUT /v1/messages) succeeds even when presage's post-send bookkeeping
        // races its websocket teardown; B's stream is the source of truth.
        Err(e) => println!("      ⚠ A.send returned {e:?} — continuing to check delivery"),
    }

    println!("[5/5] awaiting B's decoded stream…");
    let received = tokio::time::timeout(Duration::from_secs(45), async {
        while let Some(incoming) = b_stream.next().await {
            if let Incoming::Message { body, sender, .. } = incoming {
                return Some((body, sender));
            }
        }
        None
    })
    .await
    .context("timed out waiting for B to receive")?;

    match received {
        Some((body, sender)) if body == payload => {
            println!("\n✅ A1 TRANSPORT PASSED — B got {body:?} from sender {sender}");
            Ok(())
        }
        Some((body, _)) => bail!("B received the wrong body: {body:?} (expected {payload:?})"),
        None => bail!("B's stream ended without delivering the message"),
    }
}
