//! e2 B2/D1 per-message rotation smoke test — confirms
//! `PresageTransport::send_as_rotating_phantom_device` actually closes the
//! device-id linkability gap `docs/B2_DEVICE_ID_LINKABILITY_ISSUE.md` documents.
//!
//! `b2_phantom_link` proves a linked member's messages carry the phantom's account
//! id. It does **not** prove unlinkability across two posts, because a persistently
//! linked device keeps the same `device_id` on every message — a stable per-member
//! tag a recipient can use to group posts together. This example is the check that
//! matters for that specific property: send two messages, each through its own
//! single-use linked device, and confirm the observer sees **two different**
//! `sender_device` values with nothing connecting them — not the same device id
//! twice.
//!
//! Not a `#[test]`: it needs the server + proxy up (see deploy/signal-test-server).
//! Run:  cargo run -p transport-presage --example b2_rotating_phantom
//! Logs: RUST_LOG=transport_presage=debug,presage=info

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use futures_util::pin_mut;
use presage::Manager;
use presage::libsignal_service::content::{ContentBody, DataMessage};
use presage::libsignal_service::protocol::DeviceId;
use presage::model::identity::OnNewIdentity;
use presage::model::messages::Received;
use presage_store_sqlite::SqliteStore;
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
                .unwrap_or_else(|_| "info,b2_rotating_phantom=info".into()),
        )
        .init();

    let suffix = (now_millis() % 10_000) as u16;
    let phantom_number = format!("+1202555{suffix:04}");
    let observer_number = format!("+1203555{suffix:04}");

    let tmp = tempfile::tempdir().context("tempdir")?;
    let phantom_db = tmp.path().join("phantom.db3").to_string_lossy().into_owned();
    let observer_db = tmp
        .path()
        .join("observer.db3")
        .to_string_lossy()
        .into_owned();

    println!("[1/4] registering the phantom account ({phantom_number})…");
    let phantom_aci = PresageTransport::register(&phantom_db, &phantom_number).await?;
    println!("      phantom aci={phantom_aci:?}");

    println!("[2/4] registering the independent observer account ({observer_number})…");
    let observer_aci = PresageTransport::register(&observer_db, &observer_number).await?;
    println!("      observer aci={observer_aci:?}");

    println!("[3/4] sending two messages, each through its own single-use linked device…");
    for (i, label) in ["first", "second"].iter().enumerate() {
        let plaintext = format!("{label} rotating post — e2 B2 rotation smoke {suffix:04}");
        let ts = now_millis() + i as u64; // keep timestamps distinct
        let body = ContentBody::DataMessage(DataMessage {
            body: Some(plaintext.clone()),
            timestamp: Some(ts),
            ..Default::default()
        });
        match PresageTransport::send_as_rotating_phantom_device(
            &phantom_db,
            format!("rotating-device-{i}"),
            observer_aci,
            body,
            ts,
        )
        .await
        {
            Ok(()) => println!("      sent {label} post (ts={ts})"),
            // Same intermittent post-send-bookkeeping race as FINDINGS.md O12 — the
            // observer's receive is still the source of truth for delivery.
            Err(e) => println!("      ⚠ {label} send returned {e:?} — continuing to check delivery"),
        }
    }

    println!("[4/4] observer draining its queue, checking both messages' sender devices…");
    let observer_store = SqliteStore::open(&observer_db, OnNewIdentity::Trust).await?;
    let mut observer = Manager::load_registered(observer_store)
        .await
        .context("loading the observer's Manager")?;

    let mut seen: Vec<(String, DeviceId)> = Vec::new();
    let received = tokio::time::timeout(Duration::from_secs(60), async {
        let messages = observer
            .receive_messages()
            .await
            .context("observer.receive_messages")?;
        pin_mut!(messages);
        while let Some(event) = messages.next().await {
            match event {
                Received::Content(content) => {
                    if let ContentBody::DataMessage(DataMessage {
                        body: Some(text), ..
                    }) = &content.body
                    {
                        seen.push((text.clone(), content.metadata.sender_device));
                        if seen.len() == 2 {
                            return Ok::<(), anyhow::Error>(());
                        }
                    }
                }
                Received::QueueEmpty if seen.len() < 2 => {
                    return Ok(()); // fall through to the length check below
                }
                _ => {}
            }
        }
        Ok(())
    })
    .await
    .context("timed out waiting for the observer to receive both messages");
    received??;

    if seen.len() != 2 {
        bail!(
            "expected 2 delivered messages, observer's queue emptied after {} — \
             at least one send likely failed to actually deliver (retry the example)",
            seen.len()
        );
    }

    for (text, device) in &seen {
        println!("      observer saw {text:?} from sender_device={device:?}");
    }

    let (_, device_a) = &seen[0];
    let (_, device_b) = &seen[1];
    if device_a == device_b {
        bail!(
            "both messages arrived from the SAME sender_device ({device_a:?}) — rotation did \
             not actually give them different devices; the per-message unlinkability property \
             does not hold"
        );
    }

    println!(
        "\n✅ B2 ROTATION PASSED — the two posts used different devices ({device_a:?} vs {device_b:?}), \
         both under the same phantom account, with nothing linking them to each other"
    );
    Ok(())
}
