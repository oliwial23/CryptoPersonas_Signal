//! Probe: how many devices can one account have linked at once, on *this* server?
//!
//! Not a design assumption — the client library has a typed error for it
//! (`push_service::error::ServiceError::DeviceLimitReached { current, max }`), and
//! `max` is whatever the server is configured with, not a client-side constant. This
//! links devices to one phantom account, without ever unlinking, until it fails, and
//! reports what the server actually said. Directly informs whether per-message device
//! rotation (link → send → unlink) is viable at all, and what a safe pool size would
//! be if we keep several pre-linked devices around instead of exactly one.
//!
//! Not a `#[test]`: it needs the server + proxy up (see deploy/signal-test-server).
//! Run:  cargo run -p transport-presage --example b2_device_cap_probe
//! Logs: RUST_LOG=transport_presage=debug,presage=info

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
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
                .unwrap_or_else(|_| "warn,b2_device_cap_probe=info".into()),
        )
        .init();

    let suffix = (now_millis() % 10_000) as u16;
    let phantom_number = format!("+1202555{suffix:04}");

    let tmp = tempfile::tempdir().context("tempdir")?;
    let phantom_db = tmp.path().join("phantom.db3").to_string_lossy().into_owned();

    println!("registering the phantom account ({phantom_number})…");
    let phantom_aci = PresageTransport::register(&phantom_db, &phantom_number).await?;
    println!("phantom aci={phantom_aci:?} (this is device 1 — the primary)\n");

    println!("linking additional devices, one at a time, until the server refuses…");
    let mut linked = 0u32;
    for i in 0..25u32 {
        let device_db = tmp
            .path()
            .join(format!("device-{i}.db3"))
            .to_string_lossy()
            .into_owned();
        match PresageTransport::link_as_phantom_device(
            &phantom_db,
            &device_db,
            format!("probe-device-{i}"),
        )
        .await
        {
            Ok(aci) => {
                linked += 1;
                println!("  device #{} linked ok (aci={aci:?})", i + 2); // +2: primary is 1
            }
            Err(e) => {
                println!("\n  device #{} link FAILED: {e:#}", i + 2);
                println!(
                    "\n✅ PROBE DONE — {linked} additional device(s) linked successfully \
                     (plus the primary) before the server refused. If the error above \
                     names a 'Device limit reached: X out of Y' figure, Y is the server's \
                     configured cap; X should equal {} (linked devices, including primary).",
                    linked + 1
                );
                return Ok(());
            }
        }
    }

    println!(
        "\n⚠ linked {linked} additional devices without hitting a limit (stopped at the \
         probe's own cap of 25 — raise the loop bound in this example to keep probing)."
    );
    Ok(())
}
