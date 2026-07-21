//! e2 B2/D1 smoke test — the shared **phantom** Signal identity, realized by
//! registering every member with the *same* ACI identity keypair (derived from the
//! PPRF group secret) rather than by certificate substitution (cryptographically
//! unsound — see `docs/SERVERLESS_SIGNAL_DESIGN.md` §6) or device linking
//! (reverted; see `docs/FINDINGS.md`). Requires the `third_party/presage` /
//! `third_party/libsignal-service-rs` fork: `Manager::confirm_verification_code_with_identity`
//! and `content.metadata.sender_identity_key`.
//!
//! What it proves, in order:
//!   1. Two members register two wholly independent Signal accounts — own phone
//!      number, uuid, device id, prekeys — via `PresageTransport::register_as_phantom`
//!      with the *same* group secret.
//!   2. A third, wholly independent "observer" account registers normally.
//!   3. A bootstrap round (each member → observer, observer → each member) lets
//!      presage's own automatic profile-key exchange run its course, so the *real*
//!      test sends below actually go out sealed-sender (`Manager::send_message`
//!      only attempts unidentified delivery once it already holds the recipient's
//!      profile key — see `register_as_phantom`'s docs).
//!   4. Each member sends the observer one more message. The observer decrypts
//!      both: `content.metadata.sender` (the real, per-account uuid) must differ
//!      between the two — proving this is *not* device linking, no shared account —
//!      while `content.metadata.sender_identity_key` (the certificate's embedded
//!      identity public key) must be `Some` and *identical* for both — proving the
//!      shared-identity scheme actually produces the "one phantom sender" property
//!      a recipient would use in place of the uuid.
//!
//! Not a `#[test]`: it needs the server + proxy up (see deploy/signal-test-server).
//! Run:  cargo run -p transport-presage --example b2_shared_identity
//! Logs: RUST_LOG=transport_presage=debug,presage=info

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use futures_util::pin_mut;
use futures_util::StreamExt;
use presage::libsignal_service::content::{ContentBody, DataMessage};
use presage::model::identity::OnNewIdentity;
use presage::model::messages::Received;
use presage::Manager;
use presage_store_sqlite::SqliteStore;
use transport_presage::PresageTransport;

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_millis() as u64
}

/// Send `plaintext` from `sender` to `recipient`, and drain `sender`'s own queue
/// first (a cheap way to keep sockets warm and avoid unrelated backlog interfering
/// with later `receive_messages` calls in this example).
async fn send(
    sender: &mut Manager<SqliteStore, presage::manager::Registered>,
    recipient: presage::libsignal_service::protocol::ServiceId,
    plaintext: impl Into<String>,
) -> Result<()> {
    let ts = now_millis();
    let body = ContentBody::DataMessage(DataMessage {
        body: Some(plaintext.into()),
        timestamp: Some(ts),
        ..Default::default()
    });
    match sender.send_message(recipient, body, ts).await {
        Ok(()) => {}
        // Same intermittent post-send-bookkeeping race as FINDINGS.md O12 — the
        // receiver's own decrypt is the source of truth either way.
        Err(e) => println!("      ⚠ send returned {e:?} — continuing to check delivery"),
    }
    Ok(())
}

/// Drain `receiver`'s queue until one `DataMessage` with a body arrives, and
/// return its `(sender uuid, sender_identity_key, body)`. Ignores anything else
/// (receipts, sync chatter) so the bootstrap round's replies don't need
/// hand-crafted filtering.
async fn receive_one(
    receiver: &mut Manager<SqliteStore, presage::manager::Registered>,
) -> Result<(uuid::Uuid, Option<Vec<u8>>, String)> {
    tokio::time::timeout(Duration::from_secs(45), async {
        let messages = receiver.receive_messages().await.context("receive_messages")?;
        pin_mut!(messages);
        while let Some(event) = messages.next().await {
            if let Received::Content(content) = event {
                if let ContentBody::DataMessage(DataMessage {
                    body: Some(text), ..
                }) = &content.body
                {
                    let key = content
                        .metadata
                        .sender_identity_key
                        .map(|k| k.public_key_bytes().to_vec());
                    return Ok((content.metadata.sender.raw_uuid(), key, text.clone()));
                }
            }
        }
        bail!("queue emptied without a DataMessage arriving")
    })
    .await
    .context("timed out waiting to receive")?
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,b2_shared_identity=info".into()),
        )
        .init();

    let suffix = (now_millis() % 10_000) as u16;
    let member_a_number = format!("+1206555{suffix:04}");
    let member_b_number = format!("+1207555{suffix:04}");
    let observer_number = format!("+1208555{suffix:04}");

    let tmp = tempfile::tempdir().context("tempdir")?;
    let db = |name: &str| tmp.path().join(name).to_string_lossy().into_owned();
    let (member_a_db, member_b_db, observer_db) =
        (db("member_a.db3"), db("member_b.db3"), db("observer.db3"));

    println!("[1/5] deriving the shared group secret…");
    let group_secret = PresageTransport::create_group_secret();
    println!("      epoch={}", group_secret.epoch);

    println!("[2/5] registering member A and member B, both with the shared phantom identity…");
    let member_a_aci =
        PresageTransport::register_as_phantom(&member_a_db, &member_a_number, &group_secret)
            .await?;
    let member_b_aci =
        PresageTransport::register_as_phantom(&member_b_db, &member_b_number, &group_secret)
            .await?;
    println!("      member A aci={member_a_aci:?}");
    println!("      member B aci={member_b_aci:?}");
    if member_a_aci.raw_uuid() == member_b_aci.raw_uuid() {
        bail!("member A and member B got the SAME uuid — this should never happen (each registers its own independent account, not a linked device)");
    }
    println!("      ✓ different accounts — this is not device linking");

    println!("[3/5] registering the independent observer account ({observer_number})…");
    let observer_aci = PresageTransport::register(&observer_db, &observer_number).await?;
    println!("      observer aci={observer_aci:?}");

    let member_a_store = SqliteStore::open(&member_a_db, OnNewIdentity::Trust).await?;
    let mut member_a = Manager::load_registered(member_a_store)
        .await
        .context("loading member A's Manager")?;
    let member_b_store = SqliteStore::open(&member_b_db, OnNewIdentity::Trust).await?;
    let mut member_b = Manager::load_registered(member_b_store)
        .await
        .context("loading member B's Manager")?;
    let observer_store = SqliteStore::open(&observer_db, OnNewIdentity::Trust).await?;
    let mut observer = Manager::load_registered(observer_store)
        .await
        .context("loading the observer's Manager")?;

    println!(
        "[4/5] bootstrap round — each member sends the observer, the observer replies — so \
         presage's own profile-key exchange runs before the real test sends…"
    );
    send(&mut member_a, observer_aci, "bootstrap from A").await?;
    send(&mut member_b, observer_aci, "bootstrap from B").await?;
    let (_, _, _) = receive_one(&mut observer).await.context("observer receiving A's bootstrap")?;
    let (_, _, _) = receive_one(&mut observer).await.context("observer receiving B's bootstrap")?;
    send(&mut observer, member_a_aci, "bootstrap reply to A").await?;
    send(&mut observer, member_b_aci, "bootstrap reply to B").await?;
    let (_, _, _) = receive_one(&mut member_a).await.context("A receiving observer's reply")?;
    let (_, _, _) = receive_one(&mut member_b).await.context("B receiving observer's reply")?;
    println!("      ✓ bootstrap round complete — both members now hold the observer's profile key");

    println!("[5/5] the real test: each member sends one more message, observer inspects both…");
    let plaintext_a = format!("real post from A — b2 shared-identity smoke {suffix:04}");
    let plaintext_b = format!("real post from B — b2 shared-identity smoke {suffix:04}");
    send(&mut member_a, observer_aci, plaintext_a.clone()).await?;
    send(&mut member_b, observer_aci, plaintext_b.clone()).await?;

    let mut seen = Vec::new();
    for _ in 0..2 {
        seen.push(receive_one(&mut observer).await.context("observer receiving a real post")?);
    }

    let (a_result, b_result) = if seen[0].2 == plaintext_a {
        (&seen[0], &seen[1])
    } else {
        (&seen[1], &seen[0])
    };

    let (a_uuid, a_key, a_text) = a_result;
    let (b_uuid, b_key, b_text) = b_result;
    if a_text != &plaintext_a || b_text != &plaintext_b {
        bail!("observer received unexpected bodies: {a_text:?}, {b_text:?}");
    }

    println!("      observer saw A: uuid={a_uuid} identity_key={a_key:?}");
    println!("      observer saw B: uuid={b_uuid} identity_key={b_key:?}");

    if a_uuid == b_uuid {
        bail!("A and B reported the SAME uuid on the real sends — that would mean device linking crept back in");
    }

    let (Some(a_key), Some(b_key)) = (a_key, b_key) else {
        bail!(
            "expected both real sends to arrive sealed-sender (Some(identity_key)) after the \
             bootstrap round — got A={a_key:?} B={b_key:?}. If both are None, the bootstrap \
             round didn't actually get profile keys exchanged; re-run, or check presage's \
             `save_message`/`upsert_profile_key` path for a change."
        );
    };
    if a_key != b_key {
        bail!(
            "A's and B's sealed-sender identity keys differ ({} bytes vs {} bytes, not equal) — \
             the shared-identity registration did not actually produce the same ACI identity \
             keypair for both members",
            a_key.len(),
            b_key.len()
        );
    }

    println!(
        "\n✅ B2 SHARED IDENTITY PASSED — different real accounts (different uuids), but the \
         same certificate-embedded identity key on both — the property a recipient would use \
         as \"one phantom sender\" actually holds"
    );
    Ok(())
}
