//! e2c smoke test — real pairwise distribution of the K2 group secret over Signal's
//! own 1:1 sessions (`PresageTransport::distribute_group_secret` /
//! `receive_group_secret`), replacing the in-process hand-off every earlier example
//! (`a1_smoke`, the `personas-messenger` e2e test) uses via
//! `create_group_secret`'s bytes.
//!
//! What it proves, in order:
//!   1. A creator and a member register two wholly independent accounts — no shared
//!      process state between them beyond their ACIs, same as any two real users.
//!   2. The creator samples a fresh group secret and sends it to the member as the
//!      body of one ordinary 1:1 Signal message — `distribute_group_secret` — which
//!      means it travels through Signal's real pairwise handshake (X3DH + Double
//!      Ratchet), not a Rust variable.
//!   3. The member — who has never seen the creator's secret any other way — drains
//!      its queue with `receive_group_secret` and recovers the exact same
//!      `epoch`/`seed` the creator sent.
//!   4. Both sides `PresageTransport::start` with their own copy of the secret (the
//!      creator's original, the member's *received* one) and exchange one real
//!      PPRF-encrypted content message end to end, proving the distributed secret is
//!      not just byte-identical but actually usable to install a working
//!      `KeyManager` on both ends.
//!
//! Not a `#[test]`: it needs the server + proxy up (see deploy/signal-test-server).
//! Run:  cargo run -p transport-presage --example e2c_key_distribution
//! Logs: RUST_LOG=transport_presage=debug,presage=info

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
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
                .unwrap_or_else(|_| "info,e2c_key_distribution=info".into()),
        )
        .init();

    let suffix = (now_millis() % 10_000) as u16;
    let creator_number = format!("+1204555{suffix:04}");
    let member_number = format!("+1205555{suffix:04}");

    let tmp = tempfile::tempdir().context("tempdir")?;
    let creator_db = tmp
        .path()
        .join("creator.db3")
        .to_string_lossy()
        .into_owned();
    let member_db = tmp.path().join("member.db3").to_string_lossy().into_owned();

    println!("[1/5] registering the creator account ({creator_number})…");
    let creator_aci = PresageTransport::register(&creator_db, &creator_number).await?;
    println!("      creator aci={creator_aci:?}");

    println!("[2/5] registering the member account ({member_number})…");
    let member_aci = PresageTransport::register(&member_db, &member_number).await?;
    println!("      member aci={member_aci:?}");

    println!(
        "[3/5] creator samples a group secret and distributes it to the member over a real \
         1:1 Signal message (X3DH + Double Ratchet, not an in-process hand-off)…"
    );
    let secret = PresageTransport::create_group_secret();
    println!("      epoch={}", secret.epoch);
    PresageTransport::distribute_group_secret(&creator_db, &[member_aci], &secret)
        .await
        .context("distribute_group_secret")?;
    println!("      sent");

    println!("[4/5] member drains its queue and recovers the secret…");
    let received = PresageTransport::receive_group_secret(&member_db, Duration::from_secs(45))
        .await
        .context("receive_group_secret")?;
    if received.epoch != secret.epoch || received.seed != secret.seed {
        bail!(
            "member's received secret (epoch={}) does not match what the creator sent \
             (epoch={}) — distribution corrupted or mismatched something",
            received.epoch,
            secret.epoch
        );
    }
    println!("      ✓ member's copy matches byte-for-byte — recovered entirely from the pairwise channel");

    println!(
        "[5/5] both sides start a PresageTransport with their own copy of the secret and \
         exchange one real content message…"
    );
    let creator_transport = PresageTransport::start(
        &creator_db,
        vec![member_aci],
        secret,
        "e2c-key-distribution-smoke".to_string(),
    )
    .await
    .context("starting creator transport")?;
    let member_transport = PresageTransport::start(
        &member_db,
        vec![creator_aci],
        received,
        "e2c-key-distribution-smoke".to_string(),
    )
    .await
    .context("starting member transport")?;

    let mut member_incoming = member_transport.subscribe().await?;

    let plaintext = format!("hello over a distributed secret — e2c smoke {suffix:04}");
    creator_transport
        .send(Outgoing::new(
            creator_transport.conversation().clone(),
            plaintext.clone(),
        ))
        .await
        .context("creator send")?;

    let got = tokio::time::timeout(Duration::from_secs(45), async {
        while let Some(incoming) = member_incoming.next().await {
            if let Incoming::Message { body, .. } = incoming {
                return Some(body);
            }
        }
        None
    })
    .await
    .context("timed out waiting for the member to receive")?;

    match got {
        Some(body) if body == plaintext => {
            println!("      member decrypted: {body:?}");
            println!(
                "\n✅ E2C KEY DISTRIBUTION PASSED — the member's pairwise-delivered secret \
                 installed a KeyManager that actually decrypts the creator's content"
            );
            Ok(())
        }
        Some(other) => bail!("member received the wrong body: {other:?} (expected {plaintext:?})"),
        None => bail!("member's incoming stream ended without delivering the message"),
    }
}
