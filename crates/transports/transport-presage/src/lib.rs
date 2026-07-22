//! `transport-presage` — the modified in-process Signal client (workstream **e2**).
//!
//! This is the Signal transport for the *serverless* deployment. It replaces the
//! out-of-process `signal-cli` path (`transport-signal-cli`): signal-cli encrypts
//! per-member inside its own daemon and is opaque to us, so it can neither share a
//! sender key, substitute our message key, nor deliver under a phantom certificate
//! — the whole content-/delivery-layer anonymity modification is invisible to it
//! (`docs/SERVERLESS_SIGNAL_DESIGN.md` §2). The modified client therefore has to be
//! an **in-process** libsignal, which is what `presage` (+ `libsignal-service-rs` +
//! `signalapp/libsignal`) gives us.
//!
//! It implements the same [`Transport`] trait as every other transport, so the d3
//! replica and d4 messenger are untouched — the record bytes ride exactly as they
//! do over the mock, with a real Signal encrypt/decrypt where the mock handed bytes
//! across directly.
//!
//! # Phase A2 wiring (this module)
//!
//! [`PresageTransport`] is now the **Phase A2 + B1** wiring: opaque body bytes are
//! sealed under `e2a`'s K2/PPRF [`KeyManager`](personas_group_crypto::KeyManager),
//! via [`pprf_cipher::PprfContentCipher`], and delivered over real Signal; incoming
//! Signal messages are opened back to those bytes and surfaced as
//! [`Incoming::Message`]. Authorisation is unaffected — it lives in the Groth16 proof
//! the receiving replica checks, never in the Signal layer (design doc §7).
//!
//! This replaces the earlier **Phase A1** wiring (still available, unused by this
//! transport, in [`content_cipher`]: one shared static `SenderKeyRecord`, Signal's
//! own `group_encrypt`/`group_decrypt`). A1's two accepted limitations — same-
//! iteration collisions on concurrent sends, and no per-message forward secrecy —
//! are what A2 lifts; see `pprf_cipher`'s module docs for how.
//!
//! - **Send** ([`send`](Transport::send)): [`PprfContentCipher::encrypt`] (derive a
//!   fresh single-use `mk` from a random nonce, puncture it, AEAD-seal, prepend the
//!   `MessageTag`) → base64 inside a Signal `DataMessage` body → **fan out** to each
//!   other member as a 1:1 message (B1 bring-up delivery; GroupV2/multi-recipient
//!   delivery remains open).
//! - **Receive** ([`subscribe`](Transport::subscribe)): the Signal receive websocket
//!   → [`PprfContentCipher::decrypt`] (re-derive `mk` from the wire `MessageTag`,
//!   puncture, AEAD-open) → body bytes → [`Incoming::Message`]. The messenger then
//!   runs `Replica::ingest` (decode + Groth16-verify + fold) on those bytes (design
//!   doc §5).
//! - **Key distribution** ([`distribute_group_secret`](PresageTransport::distribute_group_secret) /
//!   [`receive_group_secret`](PresageTransport::receive_group_secret), **e2c**): the
//!   [`DistributedSecret`] travels as the body of an ordinary 1:1 Signal message —
//!   the same `send_message`/`receive_messages` path content uses — so establishing
//!   it runs Signal's real pairwise handshake (X3DH once, then the Double Ratchet)
//!   exactly as design doc §5 calls for. [`create_group_secret`](PresageTransport::create_group_secret)
//!   still exists for tests/bring-up that want the bytes directly without a network
//!   round trip.
//! - **Shared phantom identity** ([`register_as_phantom`](PresageTransport::register_as_phantom),
//!   **B2/D1**): every member registers their own real Signal account — own phone
//!   number, uuid, device id, prekeys, all independent — but with the *same* ACI
//!   identity keypair, deterministically derived from the group secret
//!   ([`DistributedSecret::derive_phantom_identity_seed`](personas_group_crypto::DistributedSecret::derive_phantom_identity_seed)).
//!   Each member's own, genuinely server-issued `SenderCertificate` then embeds
//!   that same public key. The receive loop reports it (base64, `phantom:` prefix)
//!   in place of the per-account uuid whenever a message arrives sealed-sender —
//!   see the fork in `third_party/presage` and `third_party/libsignal-service-rs`,
//!   and design doc §6 for why this, and not certificate substitution or device
//!   linking, is the realization that's actually cryptographically sound.
//! - **Still open** (not this module): the re-key *triggers* — ban/leave/epoch-
//!   boundary events calling [`PprfContentCipher::rekey`] (e2d) — which, per
//!   [`DistributedSecret::derive_phantom_identity_seed`](personas_group_crypto::DistributedSecret::derive_phantom_identity_seed)'s
//!   own docs, would also rotate the phantom identity and require every member to
//!   re-register; and making sealed-sender delivery reliably engaged (today it only
//!   activates once a recipient's profile key is already known to the sender's
//!   store — presage picks this up automatically after one prior identified
//!   exchange in each direction, which is what every example already does, but
//!   nothing forces it before that point).
//!
//! # Why an actor thread
//!
//! presage's `receive_messages` spawns **local** tasks (`tokio::task::spawn_local`), so
//! the receive loop must run inside a `LocalSet` (a current-thread runtime). The
//! [`Transport`] trait, by contrast, is `Send + Sync` and its futures are `Send`. We
//! bridge the two with a dedicated OS thread that runs a current-thread runtime +
//! `LocalSet` and **owns** the presage [`Manager`] and the [`pprf_cipher`]. The
//! `Transport` (on the caller's multi-threaded runtime) talks to that thread over
//! `Send` channels — a command channel for sends, a broadcast channel for decoded
//! [`Incoming`]. The cipher never crosses a thread boundary.
//!
//! The account/registration this needs is on the isolated self-hosted Signal-Server
//! *test-server* (staging), which `presage::libsignal_service::configuration::SignalServers::Staging`
//! is repointed at — see `third_party/libsignal-service-rs/src/configuration.rs` and
//! `deploy/signal-test-server`.

pub mod content_cipher;
pub mod pprf_cipher;

use async_trait::async_trait;
use base64::Engine as _;
use futures_util::{StreamExt as _, stream::BoxStream};
use presage::Manager;
use presage::libsignal_service::content::{ContentBody, DataMessage};
use presage::libsignal_service::protocol::ServiceId;
use presage::manager::Registered;
use presage::model::messages::Received;
use presage_store_sqlite::SqliteStore;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, broadcast, mpsc, oneshot};
use tracing::{debug, error, warn};
use transport_api::{
    ConversationId, Incoming, MessageId, Outgoing, Result, Sent, Transport, TransportError,
};

use personas_group_crypto::DistributedSecret;
use pprf_cipher::PprfContentCipher;

const BASE64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// Prefix marking a Signal `DataMessage` body as an e2c key-distribution message
/// (a serialized [`DistributedSecret`]) rather than ordinary A2 content ciphertext.
/// Contains `:`, which is not in the base64 alphabet content bodies use, so a
/// receiver can tell the two apart with a plain `starts_with` check before trying
/// to decrypt anything. See [`PresageTransport::distribute_group_secret`].
const KEY_DISTRIBUTION_TAG: &str = "personas/group-secret/v1:";

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A command the [`PresageTransport`] hands to its actor thread.
enum Command {
    /// Encrypt `plaintext` under the PPRF-derived single-use message key and fan it
    /// out to every member; reply with the send timestamp (used as the [`MessageId`])
    /// or the delivery error.
    Send {
        plaintext: Vec<u8>,
        reply: oneshot::Sender<std::result::Result<u64, anyhow::Error>>,
    },
}

/// The presage-backed Signal transport (workstream e2, Phase A2 + B1).
///
/// Construct it with [`start`](PresageTransport::start); it owns a background actor
/// thread holding the registered presage [`Manager`] and the
/// [`pprf_cipher::PprfContentCipher`]. Dropping the transport drops the command
/// channel, which ends the actor loop and lets its thread wind down.
pub struct PresageTransport {
    conversation: ConversationId,
    cmd_tx: mpsc::UnboundedSender<Command>,
    incoming_tx: broadcast::Sender<Incoming>,
    // Kept so the actor thread is owned by (and outlives no longer than) the transport.
    _actor: std::thread::JoinHandle<()>,
}

impl PresageTransport {
    /// Short name for logs and errors, matching the other transports.
    pub const NAME: &'static str = "presage";

    /// Register a fresh Signal account against the configured server and persist it to
    /// the SQLite store at `store_url`.
    ///
    /// Returns the account's ACI [`ServiceId`], which other members fan out to. The
    /// captcha token is the test-server's noop stub; any verification code verifies.
    /// This drives presage's stock registration handshake (websocket verification
    /// session → `PUT /v1/registration` + prekey upload); it needs no `LocalSet`, so it
    /// runs on the caller's runtime.
    pub async fn register(store_url: &str, number: &str) -> anyhow::Result<ServiceId> {
        use presage::libsignal_service::configuration::SignalServers;
        use presage::libsignal_service::prelude::phonenumber;
        use presage::manager::RegistrationOptions;
        use presage::model::identity::OnNewIdentity;

        let store = SqliteStore::open(store_url, OnNewIdentity::Trust).await?;
        let phone_number = phonenumber::parse(None, number)?;
        let confirm = Manager::register(
            store,
            RegistrationOptions {
                signal_servers: SignalServers::Staging,
                phone_number,
                use_voice_call: false,
                captcha: Some("noop.noop.registration.noop"),
                force: true,
            },
        )
        .await?;
        let registered = confirm.confirm_verification_code("999999").await?;
        Ok(ServiceId::Aci(
            registered.registration_data().service_ids.aci.into(),
        ))
    }

    /// e2c/D1 — register a fresh Signal account exactly like [`register`](Self::register),
    /// except its **ACI identity keypair** is derived from `group_secret` instead of
    /// randomly generated, via the forked
    /// `Manager::confirm_verification_code_with_identity`
    /// (`third_party/presage/presage/src/manager/confirmation.rs`).
    ///
    /// # The shared-phantom-identity scheme
    ///
    /// Every member who calls this with the same `group_secret` derives, entirely
    /// locally (no extra network round trip beyond distributing the secret itself —
    /// already e2c's job), the identical [`IdentityKeyPair`]
    /// ([`DistributedSecret::derive_phantom_identity_seed`] → clamp as a Curve25519
    /// scalar → derive the matching public key). Each member still registers their
    /// own real phone number, uuid, and device id completely normally — nothing
    /// shared there, no device linking, no cross-member session/ratchet collision
    /// risk. What's shared is only the identity key *material* backing each
    /// member's own independent account. Signal's server, seeing nothing unusual,
    /// legitimately signs each member's own [`SenderCertificate`] — which now just
    /// happens to embed the same public identity key for everyone.
    ///
    /// This is *not* "swap the certificate": each member's `SenderCertificate` still
    /// names their own real uuid/device id, and the encryption still rides their own
    /// entirely normal per-account Double Ratchet sessions (no shared session state,
    /// no chain-iteration collision hazard the way sharing an actual sender-key
    /// chain would reintroduce — see `docs/FINDINGS.md`). The only place the shared
    /// identity becomes visible as "one phantom sender" is the *receive* side, which
    /// has to stop reporting the per-account uuid and instead report the
    /// certificate's embedded identity public key — see `Incoming::Message`'s
    /// `sender` field and the receive loop this module's actor thread runs.
    ///
    /// [`SenderCertificate`]: presage::libsignal_service::protocol::SenderCertificate
    pub async fn register_as_phantom(
        store_url: &str,
        number: &str,
        group_secret: &DistributedSecret,
    ) -> anyhow::Result<ServiceId> {
        use presage::libsignal_service::configuration::SignalServers;
        use presage::libsignal_service::prelude::phonenumber;
        use presage::libsignal_service::protocol::{IdentityKey, IdentityKeyPair, PrivateKey};
        use presage::manager::RegistrationOptions;
        use presage::model::identity::OnNewIdentity;

        let store = SqliteStore::open(store_url, OnNewIdentity::Trust).await?;
        let phone_number = phonenumber::parse(None, number)?;
        let confirm = Manager::register(
            store,
            RegistrationOptions {
                signal_servers: SignalServers::Staging,
                phone_number,
                use_voice_call: false,
                captcha: Some("noop.noop.registration.noop"),
                force: true,
            },
        )
        .await?;

        let seed = group_secret.derive_phantom_identity_seed();
        let private_key = PrivateKey::deserialize(seed.as_slice())
            .map_err(|e| anyhow::anyhow!("deriving the phantom identity private key: {e}"))?;
        let public_key = private_key
            .public_key()
            .map_err(|e| anyhow::anyhow!("deriving the phantom identity public key: {e}"))?;
        let identity_key_pair = IdentityKeyPair::new(IdentityKey::new(public_key), private_key);

        let registered = confirm
            .confirm_verification_code_with_identity("999999", identity_key_pair)
            .await?;
        Ok(ServiceId::Aci(
            registered.registration_data().service_ids.aci.into(),
        ))
    }

    /// Create the group's first group secret (epoch 0). Returns the
    /// [`DistributedSecret`] wire bytes to hand to [`start`](PresageTransport::start)
    /// — the creator installs the same secret every other member does. Real pairwise
    /// distribution over the Double Ratchet is [`distribute_group_secret`] /
    /// [`receive_group_secret`].
    ///
    /// [`distribute_group_secret`]: Self::distribute_group_secret
    /// [`receive_group_secret`]: Self::receive_group_secret
    pub fn create_group_secret() -> DistributedSecret {
        let (_creator, secret) = PprfContentCipher::create(&mut rand08::rngs::OsRng);
        secret
    }

    /// e2c — send `secret`'s wire bytes to every member of `members`, each over its
    /// own ordinary 1:1 Signal message.
    ///
    /// # Why this counts as "over the Double Ratchet"
    ///
    /// This is not a custom channel — it is `Manager::send_message`, the exact same
    /// call [`send_fanout`] uses for content, which is presage's stock 1:1 send path.
    /// Establishing (or reusing) that path already runs Signal's full pairwise
    /// handshake — X3DH the first time two accounts talk, then the Double Ratchet on
    /// every message after — entirely inside `libsignal-service-rs`/`libsignal`. So
    /// sending the group secret as the body of one such message *is* pairwise
    /// Double-Ratchet distribution; there is no separate mechanism to build. What
    /// this function adds on top is only: serializing [`DistributedSecret`] to bytes,
    /// tagging the message body so a receiver can tell a key-distribution message
    /// apart from a content message, and doing that once per member.
    ///
    /// # Wire format
    ///
    /// The body is `"{KEY_DISTRIBUTION_TAG}{base64(json(DistributedSecret))}"`. The
    /// tag is a fixed prefix that is not valid base64 (contains `:`), so a receiver
    /// distinguishes this from a content message ([`send_fanout`]'s bare base64
    /// ciphertext) with a cheap `starts_with` check before ever trying to decrypt —
    /// see [`receive_group_secret`]. JSON (not the raw byte layout) because
    /// [`DistributedSecret`] already derives `Serialize`/`Deserialize` and this path
    /// is not performance-sensitive (once per member per epoch, not once per
    /// message).
    ///
    /// # This message is itself sealed-sender + Double-Ratchet-encrypted
    ///
    /// Signal's 1:1 send path always double-ratchet-encrypts the body before it
    /// leaves the process — the group secret's raw seed never travels in the clear,
    /// consistent with [`GroupSecret::to_wire`](personas_group_crypto::GroupSecret::to_wire)'s
    /// requirement that it only ever cross a wire inside that already-encrypted
    /// channel. This function does not add a second layer of encryption on top; the
    /// pairwise session *is* the required encryption.
    ///
    /// [`send_fanout`]: send_fanout
    pub async fn distribute_group_secret(
        distributor_store_url: &str,
        members: &[ServiceId],
        secret: &DistributedSecret,
    ) -> anyhow::Result<()> {
        use presage::model::identity::OnNewIdentity;

        let store = SqliteStore::open(distributor_store_url, OnNewIdentity::Trust).await?;
        let mut manager = Manager::load_registered(store)
            .await
            .map_err(|e| anyhow::anyhow!("loading the distributor account: {e}"))?;

        let payload = serde_json::to_vec(secret)
            .map_err(|e| anyhow::anyhow!("serializing the group secret: {e}"))?;
        let body = format!("{KEY_DISTRIBUTION_TAG}{}", BASE64.encode(&payload));

        for member in members {
            let timestamp = now_millis();
            let msg = ContentBody::DataMessage(DataMessage {
                body: Some(body.clone()),
                timestamp: Some(timestamp),
                ..Default::default()
            });
            // Same O12/O14 shape of race as the fresh-Manager receive helpers: the PUT
            // to /v1/messages can already have succeeded server-side while presage's
            // own post-send bookkeeping (self-sync, contact upsert) is still riding the
            // websocket when it closes, surfacing as `WsClosing` here even though
            // delivery went through. `receive_group_secret` on the other end is the
            // actual source of truth (it decodes the real message and has its own
            // timeout), so don't abort the whole distribution on this — warn and
            // continue, exactly like `a1_smoke`'s and `b2_shared_identity`'s `send()`
            // helpers already do for the identical error class.
            if let Err(e) = manager.send_message(*member, msg, timestamp).await {
                warn!(
                    error = %e,
                    ?member,
                    "distribute_group_secret: send_message returned an error — continuing, \
                     receive_group_secret's decode is the real check"
                );
            }
        }

        // `send_message`'s PUT already delivered the message; presage then does
        // extra post-send bookkeeping (self-sync, contact upsert) on the same
        // websocket, in the background. If `manager` drops immediately, that
        // bookkeeping can lose its response mid-flight and log a spurious
        // "Websocket closing" error (harmless — delivery already happened; see
        // FINDINGS.md O12). Giving it a moment before the connection tears down
        // avoids the noise without touching presage itself.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        Ok(())
    }

    /// e2c — the receiving half of [`distribute_group_secret`]: wait for the group
    /// secret to arrive over this member's own pairwise session and hand back the
    /// decoded [`DistributedSecret`], ready for [`start`](Self::start).
    ///
    /// Drives `receive_messages` directly on a freshly loaded [`Manager`] (not
    /// through the actor thread — no cipher exists yet to install anything into
    /// until this call returns), watching only for a message whose body starts with
    /// [`KEY_DISTRIBUTION_TAG`]; every other message (ordinary content, or Signal
    /// protocol chatter) is skipped. Bounded by `timeout` so a member who never
    /// receives one does not hang forever.
    pub async fn receive_group_secret(
        store_url: &str,
        timeout: std::time::Duration,
    ) -> anyhow::Result<DistributedSecret> {
        use presage::model::identity::OnNewIdentity;

        let store = SqliteStore::open(store_url, OnNewIdentity::Trust).await?;
        let mut manager = Manager::load_registered(store)
            .await
            .map_err(|e| anyhow::anyhow!("loading the recipient account: {e}"))?;

        tokio::time::timeout(timeout, async {
            let stream = manager
                .receive_messages()
                .await
                .map_err(|e| anyhow::anyhow!("receive_messages: {e}"))?;
            futures_util::pin_mut!(stream);
            while let Some(event) = stream.next().await {
                let Received::Content(content) = event else {
                    continue;
                };
                let ContentBody::DataMessage(DataMessage {
                    body: Some(body), ..
                }) = &content.body
                else {
                    continue;
                };
                let Some(b64) = body.strip_prefix(KEY_DISTRIBUTION_TAG) else {
                    continue; // not a key-distribution message — e.g. ordinary content
                };
                let payload = BASE64
                    .decode(b64)
                    .map_err(|e| anyhow::anyhow!("decoding key-distribution payload: {e}"))?;
                let secret: DistributedSecret = serde_json::from_slice(&payload)
                    .map_err(|e| anyhow::anyhow!("parsing the group secret: {e}"))?;
                // Same reasoning as `distribute_group_secret`: presage runs "newly
                // seen contact" bookkeeping in the background right after decrypting
                // a first-contact message, and it can lose its response if `manager`
                // (and its websocket) tears down immediately on return. See O12.
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                return Ok(secret);
            }
            anyhow::bail!("receive stream ended before a group secret arrived")
        })
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for the group secret"))?
    }

    /// Start a transport for a member already registered at `store_url`.
    ///
    /// - `members` — the ACI [`ServiceId`]s to deliver to (every *other* member; a
    ///   member does not send to itself).
    /// - `group_secret` — the group's shared secret ([`create_group_secret`] once,
    ///   then the same [`DistributedSecret`] for every member).
    /// - `conversation` — the logical conversation id these records belong to.
    ///
    /// Spawns the actor thread and waits for it to load the [`Manager`] and install the
    /// cipher before returning, so a returned transport is ready to send/subscribe.
    ///
    /// [`create_group_secret`]: PresageTransport::create_group_secret
    pub async fn start(
        store_url: impl Into<String>,
        members: Vec<ServiceId>,
        group_secret: DistributedSecret,
        conversation: impl Into<ConversationId>,
    ) -> anyhow::Result<Self> {
        let store_url = store_url.into();
        let conversation = conversation.into();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (incoming_tx, _) = broadcast::channel(256);
        let (ready_tx, ready_rx) = oneshot::channel();

        let actor_incoming = incoming_tx.clone();
        let actor_conv = conversation.clone();
        let actor = std::thread::Builder::new()
            .name("presage-transport".into())
            // presage's receive path is a deep async state machine driven on this one
            // current-thread runtime; the 2 MiB default thread stack overflows it (the
            // smoke test only survived because it ran on the 8 MiB main thread). Give it
            // room — the stack is virtual, only touched pages are resident.
            .stack_size(32 * 1024 * 1024)
            .spawn(move || {
                // A MULTI-thread runtime: presage/libsignal pump their websockets with
                // `tokio::spawn`, which needs worker threads to make progress while this
                // thread drives the `LocalSet`. A current-thread runtime starves those
                // pumps and the connections drop mid-request. This mirrors presage-cli
                // (`#[tokio::main]` multi-thread + `LocalSet::run_until`).
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .thread_stack_size(8 * 1024 * 1024)
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = ready_tx.send(Err(anyhow::anyhow!("building actor runtime: {e}")));
                        return;
                    }
                };
                let local = tokio::task::LocalSet::new();
                local.block_on(
                    &rt,
                    actor_main(
                        store_url,
                        members,
                        group_secret,
                        actor_conv,
                        cmd_rx,
                        actor_incoming,
                        ready_tx,
                    ),
                );
            })?;

        // Wait for the actor to load the Manager + install the cipher (or fail).
        ready_rx.await.map_err(|_| {
            anyhow::anyhow!("presage actor thread exited before signalling readiness")
        })??;

        Ok(Self {
            conversation,
            cmd_tx,
            incoming_tx,
            _actor: actor,
        })
    }

    /// The Signal conversation this transport posts into.
    pub fn conversation(&self) -> &ConversationId {
        &self.conversation
    }
}

/// The actor: owns the [`Manager`] and the [`pprf_cipher`], runs the receive loop
/// and the send-command loop on one current-thread runtime + `LocalSet`.
async fn actor_main(
    store_url: String,
    members: Vec<ServiceId>,
    group_secret: DistributedSecret,
    conversation: ConversationId,
    mut cmd_rx: mpsc::UnboundedReceiver<Command>,
    incoming_tx: broadcast::Sender<Incoming>,
    ready_tx: oneshot::Sender<std::result::Result<(), anyhow::Error>>,
) {
    use presage::model::identity::OnNewIdentity;

    // Load the registered account and install the group secret's key schedule.
    let store = match SqliteStore::open(&store_url, OnNewIdentity::Trust).await {
        Ok(s) => s,
        Err(e) => {
            let _ = ready_tx.send(Err(anyhow::anyhow!("opening store {store_url}: {e}")));
            return;
        }
    };
    let manager = match Manager::load_registered(store).await {
        Ok(m) => m,
        Err(e) => {
            let _ = ready_tx.send(Err(anyhow::anyhow!("load_registered: {e}")));
            return;
        }
    };
    let cipher = PprfContentCipher::install(group_secret);
    let cipher = Rc::new(Mutex::new(cipher));

    // Ready — the transport constructor can now return.
    if ready_tx.send(Ok(())).is_err() {
        return; // caller gave up
    }

    // Receive loop: decrypt incoming Signal messages and broadcast decoded Incoming.
    // Runs as a local task because receive_messages spawns local tasks internally.
    let recv_cipher = cipher.clone();
    let recv_conv = conversation;
    let recv_incoming = incoming_tx;
    let mut recv_manager = manager.clone();
    let recv_task = tokio::task::spawn_local(async move {
        let stream = match recv_manager.receive_messages().await {
            Ok(s) => s,
            Err(e) => {
                error!(%e, "presage receive_messages failed to start");
                return;
            }
        };
        futures_util::pin_mut!(stream);
        while let Some(event) = stream.next().await {
            let Received::Content(content) = event else {
                continue;
            };
            let ContentBody::DataMessage(DataMessage {
                body: Some(b64), ..
            }) = &content.body
            else {
                continue;
            };
            let ciphertext = match BASE64.decode(b64) {
                Ok(ct) => ct,
                Err(_) => continue, // not one of ours (or human chatter)
            };
            let plaintext = {
                let mut c = recv_cipher.lock().await;
                match c.decrypt(&ciphertext) {
                    Ok(p) => p,
                    Err(e) => {
                        debug!(%e, "PPRF decrypt failed — dropping (replay, wrong epoch, or foreign message)");
                        continue;
                    }
                }
            };
            let Ok(body) = String::from_utf8(plaintext) else {
                debug!("decrypted payload was not UTF-8 — dropping");
                continue;
            };
            // Shared-phantom-identity scheme (design doc §6): when this arrived
            // sealed-sender (requires the recipient already holding this sender's
            // profile key — see `register_as_phantom`'s docs), the certificate's
            // embedded identity public key is available and, if every member of
            // this group registered via `register_as_phantom` with the same group
            // secret, identical across every member — report *that* instead of the
            // per-account uuid, which stays genuinely distinct per member and is
            // not what this scheme hides. Falls back to the real uuid when the
            // identity key isn't available yet (identified bring-up delivery, or a
            // group not using this scheme at all) — never silently misreports.
            let sender = match &content.metadata.sender_identity_key {
                Some(identity_key) => {
                    format!("phantom:{}", BASE64.encode(identity_key.public_key_bytes()))
                }
                None => content.metadata.sender.raw_uuid().to_string(),
            };
            let incoming = Incoming::Message {
                id: MessageId::from(content.metadata.timestamp.timestamp_millis().max(0) as u64),
                conversation: recv_conv.clone(),
                sender,
                body,
                reply_to: None,
                attachments: Vec::new(),
                received_at: content.metadata.server_timestamp.timestamp_millis().max(0) as u64,
            };
            // No active subscriber is fine (SendError just means no receivers yet).
            let _ = recv_incoming.send(incoming);
        }
        warn!("presage receive stream ended");
    });

    // Command loop: encrypt + fan out sends. Ends when the transport (and its cmd_tx)
    // is dropped, which winds the thread down.
    let mut send_manager = manager;
    while let Some(command) = cmd_rx.recv().await {
        match command {
            Command::Send { plaintext, reply } => {
                let result = send_fanout(&mut send_manager, &cipher, &members, plaintext).await;
                let _ = reply.send(result);
            }
        }
    }

    // Transport dropped. Shut the receive task down and let the Managers (and their
    // shared SqlitePool) drop *here*, inside the runtime — sqlx's connection Drop needs
    // a Tokio context, so dropping the pool as the thread's runtime tears down would
    // panic. Aborting + awaiting the receive task drops its Manager clone in-context;
    // `send_manager`/`cipher` then drop at scope end, still inside `block_on`.
    recv_task.abort();
    let _ = recv_task.await;
    drop(send_manager);
}

/// Encrypt `plaintext` under a fresh single-use PPRF message key and deliver it to
/// every member as a 1:1 Signal message (B1 fan-out). Returns the shared send
/// timestamp.
async fn send_fanout(
    manager: &mut Manager<SqliteStore, Registered>,
    cipher: &Rc<Mutex<PprfContentCipher>>,
    members: &[ServiceId],
    plaintext: Vec<u8>,
) -> anyhow::Result<u64> {
    let ciphertext = {
        let mut c = cipher.lock().await;
        c.encrypt(&plaintext)?
    };
    let b64 = BASE64.encode(&ciphertext);
    let timestamp = now_millis();

    for member in members {
        let body = ContentBody::DataMessage(DataMessage {
            body: Some(b64.clone()),
            timestamp: Some(timestamp),
            ..Default::default()
        });
        manager
            .send_message(*member, body, timestamp)
            .await
            .map_err(|e| anyhow::anyhow!("delivering to {member:?}: {e}"))?;
    }
    Ok(timestamp)
}

#[async_trait]
impl Transport for PresageTransport {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    async fn send(&self, msg: Outgoing) -> Result<Sent> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Send {
                plaintext: msg.body.into_bytes(),
                reply: reply_tx,
            })
            .map_err(|_| TransportError::NotConnected {
                transport: Self::NAME,
                source: anyhow::anyhow!("presage actor thread is gone"),
            })?;
        let timestamp = reply_rx
            .await
            .map_err(|_| TransportError::NotConnected {
                transport: Self::NAME,
                source: anyhow::anyhow!("presage actor dropped the reply"),
            })?
            .map_err(|e| TransportError::Send {
                transport: Self::NAME,
                source: e,
            })?;
        Ok(Sent {
            id: MessageId::from(timestamp),
            conversation: self.conversation.clone(),
        })
    }

    async fn react(
        &self,
        _conversation: &ConversationId,
        _target: &MessageId,
        _emoji: &str,
    ) -> Result<()> {
        // Reactions carry no proof and are not a serverless signal — reputation is
        // proof-carrying `Rate` records (SERVERLESS_PROTOCOL.md §10). This transport
        // leaves `react` unsupported permanently, not just pre-wiring.
        Err(TransportError::Unsupported {
            transport: Self::NAME,
            capability: "react",
        })
    }

    async fn subscribe(&self) -> Result<BoxStream<'static, Incoming>> {
        // One broadcast receiver per subscriber. Decryption already happened once in the
        // actor's receive loop (group_decrypt consumes the ratchet, so it must not run
        // per-subscriber); subscribers just observe the decoded stream. `unfold` holds
        // the receiver as stream state and awaits `recv()` correctly across polls.
        let rx = self.incoming_tx.subscribe();
        let stream = futures_util::stream::unfold(rx, |mut rx| async move {
            loop {
                match rx.recv().await {
                    Ok(incoming) => return Some((incoming, rx)),
                    // Lagged: the subscriber fell behind and some messages were dropped;
                    // continue with the next available one rather than ending the stream.
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        });
        Ok(stream.boxed())
    }
}
