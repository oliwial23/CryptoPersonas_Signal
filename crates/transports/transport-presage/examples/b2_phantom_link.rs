//! e2 B2/D1 smoke test — the shared **phantom** Signal identity, realized via
//! device linking (`PresageTransport::link_as_phantom_device`) rather than a custom
//! `SenderCertificate`. See the doc comment on that function, and
//! `docs/SERVERLESS_SIGNAL_DESIGN.md` §6, for why linking is what actually gets
//! built here instead of the certificate-substitution design originally specced.
//!
//! What it proves, in order:
//!   1. A phantom account registers normally (nothing phantom-specific about
//!      registration itself).
//!   2. A "member" links as an independent device of that *same* phantom account —
//!      not its own account.
//!   3. A third, wholly independent "observer" account registers normally too, to
//!      play the role of a message recipient with no special knowledge.
//!   4. The member's linked device sends the observer a message.
//!   5. The observer decrypts it and inspects the sender identity: it must be the
//!      **phantom's** ACI — proving the delivery layer genuinely can't distinguish
//!      "the member, linked as a phantom device" from "the phantom itself," which is
//!      the whole point.
//!
//! Not a `#[test]`: it needs the server + proxy up (see deploy/signal-test-server).
//! Run:  cargo run -p transport-presage --example b2_phantom_link
//! Logs: RUST_LOG=transport_presage=debug,presage=info

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use futures_util::pin_mut;
use presage::Manager;
use presage::libsignal_service::content::{ContentBody, DataMessage};
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
                .unwrap_or_else(|_| "info,b2_phantom_link=info".into()),
        )
        .init();

    let suffix = (now_millis() % 10_000) as u16;
    let phantom_number = format!("+1202555{suffix:04}");
    let observer_number = format!("+1203555{suffix:04}");

    let tmp = tempfile::tempdir().context("tempdir")?;
    let phantom_db = tmp.path().join("phantom.db3").to_string_lossy().into_owned();
    let member_db = tmp.path().join("member.db3").to_string_lossy().into_owned();
    let observer_db = tmp
        .path()
        .join("observer.db3")
        .to_string_lossy()
        .into_owned();

    println!("[1/5] registering the phantom account ({phantom_number})…");
    let phantom_aci = PresageTransport::register(&phantom_db, &phantom_number).await?;
    println!("      phantom aci={phantom_aci:?}");

    println!("[2/5] registering the independent observer account ({observer_number})…");
    let observer_aci = PresageTransport::register(&observer_db, &observer_number).await?;
    println!("      observer aci={observer_aci:?}");

    println!("[3/5] linking the member as a device of the phantom account…");
    let linked_aci =
        PresageTransport::link_as_phantom_device(&phantom_db, &member_db, "member-device")
            .await?;
    println!("      linked device reports aci={linked_aci:?}");
    if linked_aci.raw_uuid() != phantom_aci.raw_uuid() {
        bail!(
            "linked device's ACI {linked_aci:?} does not match the phantom's {phantom_aci:?} — \
             linking did not attach it to the same account"
        );
    }
    println!("      ✓ same account — the member IS a device of the phantom, not a separate identity");

    // Load the member's now-linked Manager directly (bypassing PresageTransport,
    // which would also pull in the PPRF content cipher — out of scope for this
    // delivery-layer-only proof) and have it send completely normally.
    let member_store = SqliteStore::open(&member_db, OnNewIdentity::Trust).await?;
    let mut member = Manager::load_registered(member_store)
        .await
        .context("loading the linked member's Manager")?;

    let plaintext = format!("hello from a phantom device — e2 B2 smoke {suffix:04}");
    println!("[4/5] member (as the phantom) → observer: {plaintext:?}");
    let ts = now_millis();
    let body = ContentBody::DataMessage(DataMessage {
        body: Some(plaintext.clone()),
        timestamp: Some(ts),
        ..Default::default()
    });
    match member.send_message(observer_aci, body, ts).await {
        Ok(()) => println!("      sent (ts={ts})"),
        // Same intermittent post-send-bookkeeping race documented in FINDINGS.md
        // O12 — the observer's receive is the source of truth either way.
        Err(e) => println!("      ⚠ send_message returned {e:?} — continuing to check delivery"),
    }

    println!("[5/5] observer draining its queue and checking who it thinks sent this…");
    let observer_store = SqliteStore::open(&observer_db, OnNewIdentity::Trust).await?;
    let mut observer = Manager::load_registered(observer_store)
        .await
        .context("loading the observer's Manager")?;

    let received = tokio::time::timeout(Duration::from_secs(45), async {
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
                        let sender = content.metadata.sender.raw_uuid();
                        return Ok::<Option<(String, uuid::Uuid)>, anyhow::Error>(Some((
                            text.clone(),
                            sender,
                        )));
                    }
                }
                Received::QueueEmpty => return Ok(None),
                Received::Contacts => {}
            }
        }
        Ok(None)
    })
    .await
    .context("timed out waiting for the observer to receive")??;

    match received {
        Some((text, sender_uuid)) if text == plaintext => {
            println!("      observer decrypted: {text:?}");
            println!("      observer saw sender aci={sender_uuid}");
            // Same accessor `lib.rs`'s receive loop already uses on an incoming
            // `content.metadata.sender` — applied here to `phantom_aci` for a
            // like-for-like comparison.
            if sender_uuid == phantom_aci.raw_uuid() {
                println!(
                    "\n✅ B2 PHANTOM LINK PASSED — the observer saw the phantom, not the member"
                );
                Ok(())
            } else {
                bail!(
                    "observer saw sender {sender_uuid}, which is neither the phantom nor \
                     expected — the link did not produce the anonymity property"
                )
            }
        }
        Some((text, _)) => bail!("observer received the wrong body: {text:?} (expected {plaintext:?})"),
        None => bail!("observer's queue emptied without delivering the message"),
    }
}
