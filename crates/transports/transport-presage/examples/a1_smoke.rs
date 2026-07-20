//! e2 A1 account-gated smoke test — the plumbing proof that must pass before the
//! `Transport` wiring means anything.
//!
//! Drives **real presage** (registration → prekeys → 1:1 session → send → receive)
//! against the **isolated self-hosted Signal-Server `test-server`** (fronted by the
//! local TLS proxy on `https://127.0.0.1:8443`, which `SignalServers::Staging` is
//! repointed at — see `third_party/libsignal-service-rs/src/configuration.rs` and
//! `deploy/signal-test-server`). It is deliberately NOT a `#[test]`: it needs the
//! server + proxy up, so it is an example you run by hand.
//!
//! What it proves, in order:
//!   1. presage can register an account against our server (websocket verification
//!      session → noop captcha → any code → `PUT /v1/registration` + prekey upload).
//!   2. A second account registers independently.
//!   3. Account A opens a 1:1 session to B (prekey fetch) and sends a `DataMessage`.
//!   4. Account B drains its message queue over the websocket and decrypts it.
//!
//! If this is green, the TLS seam, the repoint, the vendored patch, and presage's
//! whole messaging hot path all work against our server — and wiring
//! `GroupContentCipher` into `PresageTransport` is "carry different bytes", not a
//! new integration.
//!
//! Run (server + proxy must be up — see deploy/signal-test-server):
//!   cargo run -p transport-presage --example a1_smoke
//! Turn up logs with `RUST_LOG=presage=debug,libsignal_service=debug`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use futures_util::pin_mut;
use presage::Manager;
use presage::libsignal_service::configuration::SignalServers;
use presage::libsignal_service::content::{ContentBody, DataMessage};
use presage::libsignal_service::prelude::phonenumber;
use presage::libsignal_service::protocol::ServiceId;
use presage::manager::{Registered, RegistrationOptions};
use presage::model::identity::OnNewIdentity;
use presage::model::messages::Received;
use presage_store_sqlite::SqliteStore;

/// The repointed `SignalServers::Staging` = our isolated test-server via the proxy.
const SERVER: SignalServers = SignalServers::Staging;
/// The test-server registration stub accepts this fixed captcha token and any code.
const NOOP_CAPTCHA: &str = "noop.noop.registration.noop";

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_millis() as u64
}

/// Register one fresh account against the test-server and return the ready-to-use
/// `Registered` manager. `db` is a throwaway SQLite file; `number` an E.164 string.
async fn register(db: &str, number: &str) -> Result<Manager<SqliteStore, Registered>> {
    let store = SqliteStore::open(db, OnNewIdentity::Trust)
        .await
        .with_context(|| format!("opening sqlite store {db}"))?;

    let phone_number =
        phonenumber::parse(None, number).with_context(|| format!("parsing number {number}"))?;

    // register() runs the websocket verification session; the test-server stub is
    // satisfied by the noop captcha and lets us request a code unconditionally.
    let confirm = Manager::register(
        store,
        RegistrationOptions {
            signal_servers: SERVER,
            phone_number,
            use_voice_call: false,
            captcha: Some(NOOP_CAPTCHA),
            force: true,
        },
    )
    .await
    .with_context(|| format!("register({number}) — verification session"))?;

    // Any code verifies against the stub; confirm_verification_code then does the real
    // PUT /v1/registration (identity keys) + prekey upload.
    let registered = confirm
        .confirm_verification_code("999999")
        .await
        .with_context(|| format!("confirm_verification_code({number})"))?;

    let aci = registered.registration_data().service_ids.aci;
    println!("  registered {number}: aci={aci}");
    Ok(registered)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,a1_smoke=info".into()),
        )
        .init();

    // Vary the last digits per run so a long-lived server never sees a stale account.
    let suffix = (now_millis() % 10_000) as u16;
    let num_a = format!("+1202555{suffix:04}");
    let num_b = format!("+1203555{suffix:04}");

    let tmp = tempfile::tempdir().context("tempdir")?;
    let db_a = tmp.path().join("a.db3");
    let db_b = tmp.path().join("b.db3");

    println!("[1/4] registering account A ({num_a})…");
    let mut a = register(db_a.to_str().unwrap(), &num_a).await?;
    println!("[2/4] registering account B ({num_b})…");
    let mut b = register(db_b.to_str().unwrap(), &num_b).await?;

    let b_aci = b.registration_data().service_ids.aci;
    let plaintext = format!("hello from A — e2 A1 smoke {suffix:04}");

    println!("[3/4] A → B: {plaintext:?}");
    let ts = now_millis();
    let body = ContentBody::DataMessage(DataMessage {
        body: Some(plaintext.clone()),
        timestamp: Some(ts),
        ..Default::default()
    });
    match a.send_message(ServiceId::Aci(b_aci.into()), body, ts).await {
        Ok(()) => println!("      sent (ts={ts})"),
        // The PUT /v1/messages itself returns 200 (delivery succeeds); presage can still
        // surface an error from its post-send bookkeeping (save_message / self-sync
        // profile fetch) racing the short-lived websocket teardown. Delivery is what we
        // test here, so warn and let B's receive be the source of truth.
        Err(e) => println!("      ⚠ send_message returned {e:?} — continuing to check delivery"),
    }

    println!("[4/4] B draining its queue…");
    let received = tokio::time::timeout(Duration::from_secs(45), async {
        let messages = b.receive_messages().await.context("B.receive_messages")?;
        pin_mut!(messages);
        while let Some(event) = messages.next().await {
            match event {
                Received::Content(content) => {
                    if let ContentBody::DataMessage(DataMessage {
                        body: Some(text), ..
                    }) = &content.body
                    {
                        return Ok::<Option<String>, anyhow::Error>(Some(text.clone()));
                    }
                }
                Received::QueueEmpty => {
                    // Nothing (more) queued — if we get here without the message, it
                    // was not delivered.
                    return Ok(None);
                }
                Received::Contacts => {}
            }
        }
        Ok(None)
    })
    .await
    .context("timed out waiting for B to receive")??;

    match received {
        Some(text) if text == plaintext => {
            println!("\n✅ A1 SMOKE PASSED — B decrypted: {text:?}");
            Ok(())
        }
        Some(text) => bail!("B received the wrong body: {text:?} (expected {plaintext:?})"),
        None => bail!("B's queue emptied without delivering the message"),
    }
}
