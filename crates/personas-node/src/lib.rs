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
/// A badge request the admin has not approved yet.
#[napi(object)]
pub struct JsBadgeRequest {
    /// Envelope hash of the request record — what `emitBadgeApprove` takes.
    pub eh: String,
    /// 1 = Faculty, 2 = Student, 3 = Industry.
    pub slot: u32,
}

/// The two petnames an authorship proof actually proves about.
///
/// Derived from the proof's own public inputs by `Engine::verify_authorship`. A caller
/// that renders these is sound; one that renders names taken from the wire is not.
#[napi(object)]
pub struct JsAuthorship {
    pub first: String,
    pub second: String,
}

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
    /// Verifying key for `authorship_pred`, kept so a RECIPIENT can check an authorship
    /// proof. It ships in the same `ServerKeys` bundle every instance already generates,
    /// so holding it costs nothing extra.
    authorship_vk: personas_core::VK,
    /// Verifying key for `badge_pred`, so a recipient can check a badge proof.
    badge_vk: personas_core::VK,
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

        let authorship_vk = keys.authorship_pred_verifying_key.clone();
        let badge_vk = keys.badge_pred_verifying_key.clone();

        let mut inner: Engine32 =
            Messenger::new(transport, conversation, replica_keys, config, member);

        if let (Some(anchor), Some(period)) =
            (options.heartbeat_anchor_ms, options.heartbeat_period_ms)
        {
            inner = inner.with_heartbeat(Heartbeat::new(anchor as u64, period as u64));
        }

        Ok(Self {
            inner,
            rng,
            authorship_vk,
            badge_vk,
        })
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

    /// Prove that two of MY pseudonyms share an author. Returns the encoded proof plus
    /// its public inputs, for the caller to ship as display payload.
    ///
    /// Both pseudonyms are named by their CONTEXT — for Desktop's unlimited pseudonyms
    /// that is the nonce the UI already stores per persona. The claimed values are
    /// derived from our secret key INSIDE the circuit, so this cannot be used to assert
    /// anything about a persona we do not own.
    ///
    /// Produces no record and folds nothing: an authorship proof is a read-only
    /// statement, which is why it needed no protocol change (see
    /// PERSONAS_ZK_WORKPLAN.md step 3).
    #[napi]
    pub fn emit_authorship(
        &mut self,
        context_a: f64,
        context_b: f64,
    ) -> napi::Result<Buffer> {
        self.guard_not_scanning("emit_authorship")?;
        if context_a == context_b {
            // A pseudonym is trivially itself; the proof would verify and say nothing.
            return napi::Result::Err(napi::Error::from_reason(
                "emit_authorship: the two contexts are identical, which claims nothing",
            ));
        }
        let a = F::from(context_a as u64);
        let b = F::from(context_b as u64);
        self.inner
            .prove_authorship(&mut self.rng, a, b)
            .map(Buffer::from)
            .map_err(|e| napi::Error::from_reason(format!("emit_authorship failed: {e}")))
    }

    /// VERIFY an authorship proof, returning the two petnames it actually proves about
    /// — or `None` if it does not verify.
    ///
    /// The returned names are derived from the proof's OWN public inputs, never from
    /// anything the sender wrote beside it. That is the difference between a checkmark
    /// that means something and one that can be attached to someone else's persona
    /// names: a sender can hold a valid proof about two pseudonyms they really own and
    /// still display any names they like next to it. Callers must render THESE.
    #[napi]
    pub fn verify_authorship(&self, proof: Buffer) -> Option<JsAuthorship> {
        let inputs = personas_core::verify_authorship_proof(&self.authorship_vk, proof.as_ref())?;
        Some(JsAuthorship {
            first: personas_core::persona::petname(inputs[1]),
            second: personas_core::persona::petname(inputs[3]),
        })
    }

    /// Badge requests that have NOT been approved yet, for an admin to act on.
    ///
    /// Derived from the replica's own log rather than from any client-side list, so
    /// every admin sees the same set and an approval that has already landed disappears
    /// for everyone. Pairing works because the approval entry names its target.
    #[napi]
    pub fn pending_badge_requests(&self) -> Vec<JsBadgeRequest> {
        let log = self.inner.replica().log();

        // Targets already approved.
        let approved: std::collections::HashSet<&str> = log
            .iter()
            .filter(|e| e.kind == "BadgeApprove")
            .filter_map(|e| e.body.rsplit(" for ").next())
            .collect();

        log.iter()
            .filter(|e| e.kind == "BadgeRequest")
            .filter_map(|e| {
                let eh = eh_to_hex(&e.eh);
                if approved.contains(eh.as_str()) {
                    return None;
                }
                // Body format is ours: "requested badge slot N".
                let slot: u32 = e.body.rsplit(' ').next()?.parse().ok()?;
                Some(JsBadgeRequest { eh, slot })
            })
            .collect()
    }

    /// Request a badge: 1=Faculty, 2=Student, 3=Industry.
    ///
    /// Files a callback for an admin to approve. The badge is NOT granted here — it
    /// lands in your object only after an approval is invoked at a settlement barrier
    /// and you then scan.
    #[napi]
    pub fn emit_badge_request(&mut self, slot: u32) -> napi::Result<JsEmitted> {
        self.guard_not_scanning("emit_badge_request")?;
        if slot < 1 || slot > 3 {
            return napi::Result::Err(napi::Error::from_reason(
                "emit_badge_request: slot must be 1 (Faculty), 2 (Student) or 3 (Industry)",
            ));
        }
        Self::emit(self.inner.emit_badge_request(&mut self.rng, slot as u8))
    }

    /// Approve a badge request, naming the request record's envelope hash.
    #[napi]
    pub fn emit_badge_approve(
        &mut self,
        request: String,
        slot: u32,
    ) -> napi::Result<JsEmitted> {
        self.guard_not_scanning("emit_badge_approve")?;
        if slot < 1 || slot > 3 {
            return napi::Result::Err(napi::Error::from_reason(
                "emit_badge_approve: slot must be 1, 2 or 3",
            ));
        }
        let target = eh_from_hex(&request)?;
        Self::emit(self.inner.emit_badge_approve(target, slot as u8))
    }

    /// Prove we hold `badge` (by NAME) in its slot. Returns the encoded proof.
    #[napi]
    pub fn emit_badge_proof(&mut self, badge: String) -> napi::Result<Buffer> {
        self.guard_not_scanning("emit_badge_proof")?;
        let (slot, value) = personas_core::badge_value(&badge).ok_or_else(|| {
            napi::Error::from_reason(format!(
                "emit_badge_proof: {badge:?} is not one of Faculty, Student, Industry. \
                 Badge values are circuit constants, so no other name can be proved."
            ))
        })?;
        self.inner
            .prove_badge(&mut self.rng, F::from(slot as u64), value)
            .map(Buffer::from)
            .map_err(|e| napi::Error::from_reason(format!("emit_badge_proof failed: {e}")))
    }

    /// VERIFY a badge proof, returning the badge NAME it actually proves — or `None`.
    ///
    /// As with authorship, render what comes back from here, never a label carried in
    /// the message: otherwise a valid Student proof could be displayed as Faculty.
    #[napi]
    pub fn verify_badge_proof(&self, proof: Buffer) -> Option<String> {
        let (_slot, value) =
            personas_core::verify_badge_proof(&self.badge_vk, proof.as_ref())?;
        // Map back through the same table the prover used, so an unrecognised value is
        // reported as unverified rather than rendered as something plausible.
        ["Faculty", "Student", "Industry"]
            .iter()
            .find(|name| {
                personas_core::badge_value(name).map(|(_, v)| v) == Some(value)
            })
            .map(|name| (*name).to_string())
    }

    /// Which badges does MY object actually hold? Empty for an observer, or for a
    /// member whose badge slots are all unset.
    ///
    /// Read from the member's own zk object, which is the only place a badge really
    /// exists. A badge arrives there exactly one way: an approver invokes this member's
    /// callback with `BADGE1/2/3_FLAG`, and the member's next SCAN writes it in-circuit
    /// (`standard_callback_method`). So this flips at the requester's next scan after
    /// approval, not at approval time — the same timing as a ban.
    ///
    /// This is what distinguishes a REAL badge from the decorative label the composer
    /// has been attaching: a label is a string on the wire, this is state in the object
    /// that `badge_pred` can prove.
    #[napi]
    pub fn get_badges(&self) -> Vec<String> {
        self.inner
            .member()
            .map(|m| {
                personas_core::badge_labels(
                    &m.user.data.badge1,
                    &m.user.data.badge2,
                    &m.user.data.badge3,
                )
            })
            .unwrap_or_default()
    }

    /// Am I banned? `None` for an observer with no member object.
    ///
    /// This is the member's OWN `banned` flag, read out of their zk user object. It is
    /// written by the circuit when a scan absorbs a `BAN_FLAG` callback
    /// (`personas-core/src/circuits.rs`), which is the only thing that sets it — so it
    /// flips at the banned member's next SCAN, not when the ban is cast. A banned
    /// member's post proofs then stop being satisfiable.
    ///
    /// Exposed because the effect was otherwise invisible: a banned member saw an
    /// unchanged UI and simply found that posting stopped working, with no explanation
    /// anywhere. The protocol makes a ban self-evident to its subject by design; the
    /// client has to actually surface it.
    ///
    /// Non-zero rather than `== 1`: the field is an `F`, and the circuit's own test is
    /// "is it the ban flag", so anything other than zero means banned here. Reading it
    /// as a strict equality against 1 would silently report `false` if the
    /// representation ever changed.
    #[napi]
    pub fn is_banned(&self) -> Option<bool> {
        self.inner
            .member()
            .map(|m| m.user.data.banned != F::from(0u64))
    }

    /// Is a callback sweep unfinished? While true, EVERY proving flow except another
    /// `emit_scan` will abort the process.
    ///
    /// The underlying callbacks crate ASSERTS `self.scan_index.is_none()` rather than
    /// returning an error (`callbacks/src/generic/user.rs:1465`). A failed assertion in
    /// Rust aborts, which from Electron's side is `Render process is gone ... Exit Code:
    /// 6` with no catchable JS error — the whole window dies.
    ///
    /// `personas-client` has guarded this since it was first found (`ensure_not_scanning`,
    /// FINDINGS O2). The serverless/messenger path that Desktop uses never got the same
    /// guard, so an interrupted scan left a member permanently unusable: every later
    /// action aborted the renderer on sight, which presents as "this one instance just
    /// keeps crashing" with nothing in the JS logs.
    #[napi]
    pub fn is_scanning(&self) -> bool {
        self.inner
            .member()
            .map(|m| m.user.is_scanning())
            .unwrap_or(false)
    }

    /// How many callbacks are still outstanding mid-sweep. Useful in the status panel:
    /// the remedy for a stuck scan is to keep scanning until this reaches zero.
    #[napi]
    pub fn outstanding_callbacks(&self) -> u32 {
        self.inner
            .member()
            .map(|m| m.user.num_outstanding_callbacks() as u32)
            .unwrap_or(0)
    }

    /// Refuse a proving flow that would hit the assertion above, with an error the JS
    /// side can catch and show. `emit_scan` is deliberately exempt: continuing the scan
    /// is the only way OUT of this state.
    fn guard_not_scanning(&self, what: &str) -> napi::Result<()> {
        if self.is_scanning() {
            return napi::Result::Err(napi::Error::from_reason(format!(
                "{what} refused: a callback scan is unfinished ({} outstanding). \
                 Scan until it completes first — proceeding would abort the process.",
                self.outstanding_callbacks()
            )));
        }
        Ok(())
    }

    /// Emit a join record (a member advertising itself to the group).
    #[napi]
    pub fn emit_join(&mut self) -> napi::Result<JsEmitted> {
        self.guard_not_scanning("emit_join")?;
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
        self.guard_not_scanning("emit_post_pseudo")?;
        let ctx = F::from(context as u64);
        Self::emit(self.inner.emit_post_pseudo(&mut self.rng, body, ctx))
    }

    /// Emit an anonymous post (no linkable persona).
    #[napi]
    pub fn emit_post_anon(&mut self, body: String) -> napi::Result<JsEmitted> {
        self.guard_not_scanning("emit_post_anon")?;
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
        self.guard_not_scanning("emit_post_pseudo_rate")?;
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
        self.guard_not_scanning("emit_poll")?;
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
        self.guard_not_scanning("emit_vote")?;
        let poll_eh = eh_from_hex(&poll)?;
        Self::emit(self.inner.emit_vote(&mut self.rng, poll_eh, option))
    }

    /// Rate the record named by hex `Eh` `target` by `delta` (§10).
    #[napi]
    pub fn emit_rate(&mut self, target: String, delta: i32) -> napi::Result<JsEmitted> {
        self.guard_not_scanning("emit_rate")?;
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

    // ==================================================================
    // BISECT STAGE 1 of 4 — see PERSONAS_ZK_WORKPLAN.md step 2.
    //
    // An earlier `get_reputation` compiled cleanly and then SIGKILLed the Electron
    // render process (exit code 9, no catchable error). Rebuilding from unmodified
    // upstream Rust is stable, so the fault is somewhere in that ~15-line change —
    // but it was never narrowed, and authorship (~60 lines) and badges (several
    // hundred) are the same shape. So before building either, find out which LAYER
    // breaks, by adding one capability at a time:
    //
    //   STAGE 1 (this)  two methods that touch no data at all.
    //                   Crash  => adding ANY napi method to this crate breaks the
    //                             addon. Nothing else should be attempted. Suspect
    //                             napi-derive/codegen, the Electron ABI, or the
    //                             build itself.
    //                   Stable => napi codegen and f64/Option marshalling are fine.
    //                             Go to stage 2.
    //
    //   STAGE 2  `self.inner.member().map(|_| 0.0)`  — borrowing the Member.
    //            Crash => the fault is in reaching into `inner`, not in arithmetic.
    //
    //   STAGE 3  return a hardcoded field element through the real conversion, e.g.
    //            `field_to_f64(&F::from(7u64))` — the arithmetic alone.
    //            Crash => `field_to_f64` is the culprit (it was my code: it does
    //            `into_bigint().to_bytes_le()` and a negation `-*value`).
    //
    //   STAGE 4  the real thing: `member().map(|m| field_to_f64(&m.user.data.reputation))`.
    //            Crash here, with 1-3 stable, means the specific field access is at
    //            fault.
    //
    // Rebuild and run between EVERY stage. One variable at a time is the only thing
    // that has produced a reliable answer on this bug so far.
    //
    // Capture the kill reason while it reproduces — this was never obtained:
    //   log stream --predicate 'eventMessage CONTAINS "Signal"' --info
    //
    // DELETE this whole block once the answer is known.

    /// Bisect probe: the simplest possible added method. Returns a constant.
    #[napi]
    pub fn bisect_ping(&self) -> f64 {
        1.0
    }

    /// This member's own reputation, or `None` for an observer (no member) — the UI
    /// renders that as "—".
    ///
    /// Reputation is a member's OWN state: it lives in their zk user object, which is
    /// why nobody can look up anyone else's. It moves when a `Rate` callback is absorbed
    /// by a scan (`personas-core/src/circuits.rs`, `u.data.reputation += argument`), NOT
    /// when the rating is sent. So the sequence that changes this value is
    /// rate -> scan, and a scan with no outstanding callbacks correctly changes nothing.
    ///
    /// This replaces a bisect stub that returned a constant `Some(0.0)`. The stub was
    /// indistinguishable from a working implementation on a fresh member — both read
    /// zero — so the status panel showed a plausible 0 that never moved, for either
    /// reason. That is the kind of "working" display this panel exists to avoid.
    /// RESOLVED: the exit-9 crash was NOT in this function.
    ///
    /// Adding `ark-ff` as a direct dependency of this crate (to get `PrimeField`) made
    /// the built `.node` kill the Electron renderer at LOAD — before `background.html`
    /// rendered and long before any method here ran. A stage-1 build, whose body was the
    /// byte-identical `Some(0.0)` stub that had always been stable, crashed the same way.
    /// That isolated it to the dependency graph: one new edge in `Cargo.lock` changed
    /// Cargo's feature unification and produced an addon that would not initialise.
    ///
    /// The conversion therefore lives in `personas-core`, which already depends on
    /// `ark-ff`, leaving this crate's dependency graph identical to the known-good one.
    /// With that change the real read below runs fine.
    ///
    /// Worth keeping, because it answers a question that blocked all Rust work on this
    /// project for weeks: exit 9 here was a BUILD problem, not a sign that this layer
    /// cannot be extended. Authorship and badges are the same shape and are not
    /// inherently unsafe to attempt — just do not add dependencies to this crate.
    ///
    /// `PERSONAS_REPUTATION_STAGE` is retained for a future bisect of the same kind:
    ///   1  constant, no data access        3  convert a hardcoded field
    ///   2  borrow the Member, ignore it    4  the real read (DEFAULT)
    #[napi]
    pub fn get_reputation(&self) -> Option<f64> {
        let stage = std::env::var("PERSONAS_REPUTATION_STAGE")
            .ok()
            .and_then(|s| s.trim().parse::<u8>().ok())
            .unwrap_or(4);

        match stage {
            1 => Some(0.0),
            2 => self.inner.member().map(|_| 0.0),
            3 => Some(personas_core::field_to_f64_signed(&F::from(7u64))),
            // The real read. `None` for an observer with no member — the UI shows "—".
            _ => self
                .inner
                .member()
                .map(|m| personas_core::field_to_f64_signed(&m.user.data.reputation)),
        }
    }
}

