//! Personas Node/Electron native addon (workstream **e2**).
//!
//! A napi-rs cdylib exposing the **transport-agnostic** personas ZK engine — a
//! [`Messenger`] (a d3 [`Replica`] plus an optional [`Member`] to send as) over
//! record bytes — to Signal-Desktop. There is **no Signal crypto here**: emit
//! produces the CBOR record with its real Groth16 proof (the *plaintext* Desktop
//! then encrypts and delivers over its own libsignal), and ingest verifies + folds
//! a record that arrived over Desktop. Delivery, sealed sender, and the shared
//! phantom identity all live on the Desktop side.
//!
//! Everything the renderer touches is a plain JS value (strings, numbers, Buffers,
//! objects); `Eh` handles cross the boundary as lowercase hex. The heavy proving
//! path is synchronous today (the `Messenger` send-side used by Desktop is not the
//! async transport path) — proof-gen offloading off the main thread is layered in
//! where the renderer would otherwise stall.

use std::sync::Arc;

use ark_serialize::CanonicalSerialize;
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use rand::rngs::StdRng;
use rand::SeedableRng;

use personas_bulletin::merkle::params::ensure_merkle_keys;
use personas_bulletin::replica::record::{Eh, PollKind};
use personas_bulletin::replica::{Config as ReplicaConfig, ReplicaKeys, Status};
use personas_core::F;
use personas_messenger::{
    carriage, Emitted, Heartbeat, Member, MemberKeys, Messenger,
};
use transport_api::{ConversationId, Incoming, MessageId, Transport};
use transport_mock::MockTransport;

// The production Merkle heights `ensure_merkle_keys` generates keys for; the
// engine's `Messenger` must be instantiated at exactly these (see personas-bulletin
// obj.rs / callback.rs `DEFAULT_*_HEIGHT`).
type Engine32 = Messenger<32, 32, 32>;

/// Options for [`Engine::new`].
#[napi(object)]
pub struct EngineOptions {
    /// Directory holding (or to generate) the ~51 MB Merkle-mode Groth16 key
    /// bundle. The first engine to touch a fresh dir pays the (minutes-long) keygen;
    /// every later one loads the cache in ~100 ms. Share one dir across members.
    pub data_dir: String,
    /// Conversation id this engine's records belong to. Defaults to
    /// `"personas"`.
    pub conversation: Option<String>,
    /// `true` (default) builds a member that can emit; `false` builds an observer
    /// that can only verify + render.
    pub member: Option<bool>,
    /// Optional deterministic RNG seed (for reproducible benchmarks/tests). Omit for
    /// OS entropy.
    pub seed: Option<f64>,
    /// Replica accept-rule config; each defaults to the demo values
    /// (`root_window: 256`, `settlement_barriers: 3`, `poll_close_barriers: 1`).
    pub root_window: Option<u32>,
    pub settlement_barriers: Option<u32>,
    pub poll_close_barriers: Option<u32>,
    /// Shared barrier schedule (§14). Set both to bucket ingests by service
    /// timestamp; omit for the default (local-barrier) cadence the tests/demo drive
    /// with explicit `barrier()` calls.
    pub heartbeat_anchor_ms: Option<f64>,
    pub heartbeat_period_ms: Option<f64>,
}

/// A record produced by an `emit*` call: the CBOR bytes to carry, its envelope
/// hash (the handle for polls/ratings), and the petname to show in the sender slot.
#[napi(object)]
pub struct JsEmitted {
    pub bytes: Buffer,
    pub eh: String,
    pub persona: Option<String>,
}

/// The accept-rule outcome of an ingest.
#[napi(object)]
pub struct JsStatus {
    /// `"applied"`, `"buffered"`, or `"rejected"`.
    pub status: String,
    /// The rejection reason when `status == "rejected"`.
    pub reason: Option<String>,
    /// The ingested record's envelope hash (hex) — look up the resulting chat-log
    /// entry with [`Engine::log_entry`]. Empty if the bytes did not decode.
    pub eh: String,
}

/// One rendered chat-log line, structured for the UI (Phase 4).
#[napi(object)]
pub struct JsLogEntry {
    pub eh: String,
    pub kind: String,
    /// The persona petname, or `None` for an anonymous post.
    pub author: Option<String>,
    pub body: String,
    /// `true` once the author's persona was revoked by a settled ban — render the
    /// post flagged, never delete it (the rendering gate).
    pub flagged: bool,
}

/// The personas ZK engine: a production-height messenger plus its RNG.
#[napi]
pub struct Engine {
    inner: Engine32,
    rng: StdRng,
}

fn eh_to_hex(eh: &Eh) -> String {
    hex::encode(eh.0)
}

fn eh_from_hex(s: &str) -> napi::Result<Eh> {
    let bytes = hex::decode(s)
        .map_err(|e| napi::Error::from_reason(format!("bad eh hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| napi::Error::from_reason("eh must be 32 bytes"))?;
    Ok(Eh(arr))
}

fn to_emitted(e: Emitted) -> JsEmitted {
    JsEmitted {
        eh: eh_to_hex(&e.eh),
        persona: e.persona,
        bytes: Buffer::from(e.bytes),
    }
}

fn root_hex(root: &F) -> String {
    let mut buf = Vec::new();
    // Infallible for a field element into a Vec.
    root.serialize_compressed(&mut buf).expect("serialize F");
    hex::encode(buf)
}

#[napi]
impl Engine {
    /// Build an engine: prepare/load the Merkle keys under `data_dir`, then stand up
    /// a `Messenger<32,32,32>` with a null transport (Desktop is the real transport).
    #[napi(constructor)]
    pub fn new(options: EngineOptions) -> napi::Result<Self> {
        let keys = ensure_merkle_keys(std::path::Path::new(&options.data_dir))
            .map_err(|e| napi::Error::from_reason(format!("ensure_merkle_keys: {e}")))?;
        let replica_keys = ReplicaKeys::from_server_keys(&keys);

        let mut rng = match options.seed {
            Some(seed) => StdRng::seed_from_u64(seed as u64),
            None => StdRng::from_entropy(),
        };

        let is_member = options.member.unwrap_or(true);
        let member = if is_member {
            let member_keys = MemberKeys::from_server_keys(&keys);
            Some(Member::create(member_keys, &mut rng))
        } else {
            None
        };

        let config = ReplicaConfig {
            root_window: options.root_window.unwrap_or(256) as usize,
            settlement_barriers: options.settlement_barriers.unwrap_or(3) as u64,
            poll_close_barriers: options.poll_close_barriers.unwrap_or(1) as u64,
        };

        let transport: Arc<dyn Transport> = Arc::new(MockTransport::new());
        let conversation =
            ConversationId(options.conversation.unwrap_or_else(|| "personas".into()));

        let mut inner: Engine32 =
            Messenger::new(transport, conversation, replica_keys, config, member);

        if let (Some(anchor), Some(period)) =
            (options.heartbeat_anchor_ms, options.heartbeat_period_ms)
        {
            inner = inner.with_heartbeat(Heartbeat::new(anchor as u64, period as u64));
        }

        Ok(Self { inner, rng })
    }

    fn emit<T>(
        r: Result<Emitted, T>,
    ) -> napi::Result<JsEmitted>
    where
        T: std::fmt::Display,
    {
        r.map(to_emitted)
            .map_err(|e| napi::Error::from_reason(format!("emit failed: {e}")))
    }

    /// Emit a join record (a member advertising itself to the group).
    #[napi]
    pub fn emit_join(&mut self) -> napi::Result<JsEmitted> {
        Self::emit(self.inner.emit_join())
    }

    /// Emit a pseudonymous post under `context` (the thread/topic the persona is
    /// scoped to). Generates a real Groth16 proof — seconds at production heights.
    #[napi]
    pub fn emit_post_pseudo(
        &mut self,
        body: String,
        context: f64,
    ) -> napi::Result<JsEmitted> {
        let ctx = F::from(context as u64);
        Self::emit(self.inner.emit_post_pseudo(&mut self.rng, body, ctx))
    }

    /// Emit an anonymous post (no linkable persona).
    #[napi]
    pub fn emit_post_anon(&mut self, body: String) -> napi::Result<JsEmitted> {
        Self::emit(self.inner.emit_post_anon(&mut self.rng, body))
    }

    /// Emit a rate-limited pseudonymous post as the `i`-th persona for `context`.
    /// Different `i` values yield different persona petnames under the same context,
    /// which is how the composer's pseudonym picker offers distinct personas.
    #[napi]
    pub fn emit_post_pseudo_rate(
        &mut self,
        body: String,
        context: f64,
        i: f64,
    ) -> napi::Result<JsEmitted> {
        let ctx = F::from(context as u64);
        let idx = F::from(i as u64);
        Self::emit(
            self.inner
                .emit_post_pseudo_rate(&mut self.rng, body, ctx, idx),
        )
    }

    /// Open a poll. `kind` is `"ban"` or `"standard"`; `target` (hex `Eh`) is the
    /// post under review for a ban poll.
    #[napi]
    pub fn emit_poll(
        &mut self,
        question: String,
        options: Vec<String>,
        kind: String,
        target: Option<String>,
    ) -> napi::Result<JsEmitted> {
        let poll_kind = match kind.as_str() {
            "ban" => PollKind::Ban,
            "standard" => PollKind::Standard,
            other => {
                return Err(napi::Error::from_reason(format!(
                    "unknown poll kind: {other}"
                )))
            }
        };
        let target_eh = match target {
            Some(s) => Some(eh_from_hex(&s)?),
            None => None,
        };
        Self::emit(self.inner.emit_poll(question, options, poll_kind, target_eh))
    }

    /// Cast a ballot (`option` index) in the poll named by hex `Eh` `poll`.
    #[napi]
    pub fn emit_vote(&mut self, poll: String, option: u32) -> napi::Result<JsEmitted> {
        let poll_eh = eh_from_hex(&poll)?;
        Self::emit(self.inner.emit_vote(&mut self.rng, poll_eh, option))
    }

    /// Rate the record named by hex `Eh` `target` by `delta` (§10).
    #[napi]
    pub fn emit_rate(&mut self, target: String, delta: i32) -> napi::Result<JsEmitted> {
        let target_eh = eh_from_hex(&target)?;
        Self::emit(self.inner.emit_rate(&mut self.rng, target_eh, delta as i8))
    }

    /// Emit a scan absorbing every callback invoked on this member since its last
    /// scan (§5.2) — how a banned member's ban becomes self-evident.
    #[napi]
    pub fn emit_scan(&mut self) -> napi::Result<JsEmitted> {
        Self::emit(self.inner.emit_scan(&mut self.rng))
    }

    /// Ingest a record that arrived over Desktop. `received_at_ms` is the service
    /// receive timestamp used to bucket the record onto the shared barrier schedule;
    /// pass `0` to fall back to the local barrier (the manual-cadence path).
    #[napi]
    pub fn ingest(&mut self, record: Buffer, received_at_ms: f64) -> napi::Result<JsStatus> {
        // The record's envelope hash, so the caller can find the resulting chat-log
        // entry (a post) after a successful ingest.
        let eh = personas_bulletin::replica::record::decode(record.as_ref())
            .map(|(_, eh)| eh_to_hex(&eh))
            .unwrap_or_default();
        let carried = carriage::encode(record.as_ref());
        let incoming = Incoming::Message {
            id: MessageId("desktop".into()),
            conversation: self.inner.conversation().clone(),
            sender: "peer".into(),
            body: carried.body,
            reply_to: None,
            attachments: carried.attachment.into_iter().collect(),
            received_at: received_at_ms as u64,
        };
        match self.inner.ingest_incoming(&incoming) {
            None => Err(napi::Error::from_reason(
                "ingest: body carried no record (marker missing)",
            )),
            Some(Err(e)) => Err(napi::Error::from_reason(format!("ingest decode: {e}"))),
            Some(Ok(status)) => Ok(match status {
                Status::Applied => JsStatus {
                    status: "applied".into(),
                    reason: None,
                    eh,
                },
                Status::Buffered => JsStatus {
                    status: "buffered".into(),
                    reason: None,
                    eh,
                },
                Status::Rejected(reason) => JsStatus {
                    status: "rejected".into(),
                    reason: Some(reason.to_string()),
                    eh,
                },
            }),
        }
    }

    /// The accepted chat log as display lines (`~petname: msg`, flagged where a
    /// persona was later revoked).
    #[napi]
    pub fn render(&self) -> Vec<String> {
        self.inner.render()
    }

    /// The open and recently-closed polls as status lines.
    #[napi]
    pub fn render_polls(&self) -> Vec<String> {
        self.inner.render_polls()
    }

    /// The accepted log as structured entries for the UI.
    #[napi]
    pub fn log(&self) -> Vec<JsLogEntry> {
        self.inner
            .replica()
            .log()
            .iter()
            .map(|e| JsLogEntry {
                eh: eh_to_hex(&e.eh),
                kind: e.kind.to_string(),
                author: e.author.clone(),
                body: e.body.clone(),
                flagged: e.flagged,
            })
            .collect()
    }

    /// The chat-log entry for a given envelope hash (hex), or `None` if that record
    /// is not a rendered post (joins/votes/polls carry no log entry) or is unknown.
    #[napi]
    pub fn log_entry(&self, eh: String) -> Option<JsLogEntry> {
        let target = eh_from_hex(&eh).ok()?;
        self.inner
            .replica()
            .log()
            .iter()
            .find(|e| e.eh == target)
            .map(|e| JsLogEntry {
                eh: eh_to_hex(&e.eh),
                kind: e.kind.to_string(),
                author: e.author.clone(),
                body: e.body.clone(),
                flagged: e.flagged,
            })
    }

    /// Cross exactly one settlement barrier by hand (settle due tickets, close ban
    /// polls, re-pin the callback root). The manual-cadence counterpart of [`tick`].
    #[napi]
    pub fn barrier(&mut self) {
        self.inner.barrier();
    }

    /// Advance to the barrier the shared schedule says `now_ms` has reached; returns
    /// the barrier the replica is now at.
    #[napi]
    pub fn tick(&mut self, now_ms: f64) -> f64 {
        self.inner.tick(now_ms as u64) as f64
    }

    /// A convergence fingerprint: the three replica roots (object, callback
    /// membership, callback non-membership) as concatenated hex. Two engines that
    /// have ingested the same records across the same barriers share it exactly.
    #[napi]
    pub fn fingerprint(&self) -> String {
        let r = self.inner.replica();
        format!(
            "{}:{}:{}",
            root_hex(&r.obj_root()),
            root_hex(&r.cb_memb_root()),
            root_hex(&r.cb_nmemb_root())
        )
    }

    /// The barrier this replica is currently at.
    #[napi]
    pub fn current_barrier(&self) -> f64 {
        self.inner.replica().current_barrier() as f64
    }
}
