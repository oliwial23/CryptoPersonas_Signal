//! The serverless headless client (workstream **d4**).
//!
//! d3 built the [`Replica`]: ingest an ordered log of record *bytes*, apply the
//! deterministic accept rule, converge on the same bulletin as everyone else. d4 is
//! what makes that a **messenger** — it ties a [`Transport`] (the mock today, real
//! Signal under e2) to a replica:
//!
//! - records ride as chat messages ([`carriage`]);
//! - incoming messages are decoded and [`ingest`](Replica::ingest)ed, and the
//!   accepted log [`render`](render)ed as `~petname: message`;
//! - a co-located [`Member`] produces the records this client sends, proving against
//!   the replica's **own** Merkle trees (`SERVERLESS_PROTOCOL.md` §5);
//! - a late joiner adopts a [`Snapshot`] from their inviter, TOFU-pinned (§12).
//!
//! `Messenger` is where the send and receive halves meet. It is generic over the
//! three d1 tree heights, defaulting to the production heights; tests instantiate it
//! at tiny heights with in-process keygen, exactly as d3's do.
//!
//! # What d4 leaves to its neighbours
//!
//! - The barrier **cadence** — when [`barrier`](Messenger::barrier) fires — is d5.
//!   d4 exposes the trigger; d5 decides the heartbeat.
//! - `FoldScan` is off by default (§13); the [`carriage`] attachment path exists for
//!   it but nothing on the demo path produces one.
//! - The optimistic-object **re-base** loop (§13/O2) is `Member`'s noted seam: this
//!   client posts one interaction at a time and lets it land.

pub mod carriage;
pub mod heartbeat;
pub mod member;
pub mod render;
pub mod snapshot;

pub use heartbeat::Heartbeat;
pub use member::{Member, MemberError, MemberKeys};
pub use snapshot::{AdoptError, Snapshot};

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use tokio::sync::Mutex;
use transport_api::{ConversationId, Incoming, Sent, Transport, TransportError};

use personas_bulletin::merkle::callback::{DEFAULT_CB_MEMB_HEIGHT, DEFAULT_CB_NMEMB_HEIGHT};
use personas_bulletin::merkle::obj::DEFAULT_OBJ_HEIGHT;
use personas_bulletin::replica::record::{self, Eh, Flavour, PollKind, Record};
use personas_bulletin::replica::{Config, Replica, ReplicaKeys, Status};
use personas_core::{F, persona};

use rand::{CryptoRng, RngCore};

/// A record could not be produced or sent.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// This messenger has no [`Member`] (an observer built from verifying keys only)
    /// and so cannot produce a proof-carrying record.
    #[error("this messenger is an observer (no member key) and cannot send")]
    Observer,
    #[error(transparent)]
    Member(#[from] MemberError),
    #[error("could not encode a record: {0}")]
    Codec(#[from] record::CodecError),
    #[error(transparent)]
    Transport(#[from] TransportError),
}

/// A record produced and folded into the sender's own replica, ready to broadcast.
///
/// Produced synchronously by the `emit_*` methods; the actual send is the async
/// [`broadcast`](Messenger::broadcast). Splitting them lets a test drive delivery
/// order by hand (the d3 convergence property) while the CLI just calls the
/// `send_*` convenience wrappers.
#[derive(Clone, Debug)]
pub struct Emitted {
    /// The encoded record bytes — what [`carriage`] packs into a chat message.
    pub bytes: Vec<u8>,
    /// Its envelope hash, the handle a caller uses to reference it (a ban poll's
    /// target, a rating's target).
    pub eh: Eh,
    /// The petname a transport shows in the sender slot, or `None` for anonymous.
    pub persona: Option<String>,
}

/// A serverless messenger: a [`Replica`], a [`Transport`], and optionally a
/// [`Member`] to send as.
pub struct Messenger<
    const OH: usize = DEFAULT_OBJ_HEIGHT,
    const MH: usize = DEFAULT_CB_MEMB_HEIGHT,
    const NH: usize = DEFAULT_CB_NMEMB_HEIGHT,
> {
    conversation: ConversationId,
    transport: Arc<dyn Transport>,
    replica: Replica<OH, MH, NH>,
    member: Option<Member>,
    /// The shared barrier schedule: how a delivered record's service timestamp maps to
    /// a settlement barrier (§14, d5). Defaults to [`Heartbeat::default`]; a live group
    /// sets its own anchor with [`with_heartbeat`](Self::with_heartbeat).
    heartbeat: Heartbeat,
}

impl<const OH: usize, const MH: usize, const NH: usize> Messenger<OH, MH, NH> {
    /// A messenger over `transport`/`conversation` with a fresh in-memory replica and
    /// an optional member. Pass `None` for an observer (verify + render only).
    pub fn new(
        transport: Arc<dyn Transport>,
        conversation: impl Into<ConversationId>,
        keys: ReplicaKeys,
        config: Config,
        member: Option<Member>,
    ) -> Self {
        Self {
            conversation: conversation.into(),
            transport,
            replica: Replica::new(keys, config),
            member,
            heartbeat: Heartbeat::default(),
        }
    }

    /// Set the barrier schedule this messenger buckets records against (§14). All
    /// members of a group must share the same [`Heartbeat`] (anchor + period), carried
    /// out of band like the genesis pin, or their settlement barriers will not line up.
    pub fn with_heartbeat(mut self, heartbeat: Heartbeat) -> Self {
        self.heartbeat = heartbeat;
        self
    }

    /// A messenger backed by a replica journal at `path` (records replayed on open).
    pub fn open(
        path: impl Into<std::path::PathBuf>,
        transport: Arc<dyn Transport>,
        conversation: impl Into<ConversationId>,
        keys: ReplicaKeys,
        config: Config,
        member: Option<Member>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            conversation: conversation.into(),
            transport,
            replica: Replica::open(path, keys, config)?,
            member,
            heartbeat: Heartbeat::default(),
        })
    }

    /// Adopt a late-join [`Snapshot`] from your inviter (§12). Verifies the snapshot
    /// against the out-of-band genesis `pin` before replaying it, and re-derives all
    /// roots itself — so a snapshot that does not match the pin is refused, and one
    /// that lies self-reveals once this client starts proving.
    pub fn adopt(
        transport: Arc<dyn Transport>,
        conversation: impl Into<ConversationId>,
        keys: ReplicaKeys,
        config: Config,
        member: Option<Member>,
        snapshot: Snapshot,
        pin: &[u8; 32],
    ) -> Result<Self, AdoptError> {
        snapshot.verify(pin)?;
        let barrier = snapshot.barrier;
        let replica = Replica::from_records(keys, config, snapshot.into_records(), barrier);
        Ok(Self {
            conversation: conversation.into(),
            transport,
            replica,
            member,
            heartbeat: Heartbeat::default(),
        })
    }

    // --- Accessors --------------------------------------------------------------

    pub fn replica(&self) -> &Replica<OH, MH, NH> {
        &self.replica
    }

    pub fn member(&self) -> Option<&Member> {
        self.member.as_ref()
    }

    pub fn conversation(&self) -> &ConversationId {
        &self.conversation
    }

    /// The accepted chat log as display lines (`~petname: msg`, flagged where a
    /// persona was later revoked). See [`render`].
    pub fn render(&self) -> Vec<String> {
        render::render_log(self.replica.log())
    }

    /// The open and recently-closed polls as status lines.
    pub fn render_polls(&self) -> Vec<String> {
        render::render_polls(self.replica.derived())
    }

    /// A [`Snapshot`] of this replica, for handing to a late joiner. Share
    /// [`Snapshot::digest_hex`] out-of-band as the genesis pin.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot::new(
            self.replica.seen_with_barriers(),
            self.replica.current_barrier(),
        )
    }

    // --- Receive ----------------------------------------------------------------

    /// Ingest an incoming messenger event. Returns the accept-rule [`Status`] if the
    /// event carried a record, or `None` for ordinary chatter / a reaction (which the
    /// serverless protocol ignores — reputation is proof-carrying `Rate` records now,
    /// §10, not messenger reactions).
    pub fn ingest_incoming(
        &mut self,
        incoming: &Incoming,
    ) -> Option<Result<Status, record::CodecError>> {
        let bytes = carriage::decode_incoming(incoming)?;
        match carriage::received_at(incoming) {
            // No service stamp (`0`, the sentinel): there is no shared clock to bucket by,
            // so fall back to the replica's local barrier — best-effort, delivery-timing
            // dependent. This is also the manual-cadence path the demo and tests drive with
            // explicit `barrier()` calls.
            0 => Some(self.replica.ingest(bytes)),
            // A real service timestamp: bucket by it, not by local receive timing — every
            // replica sees the same stamp, assigns the same barrier, and they converge
            // exactly (§4/§14, d5).
            received_at => {
                let first_barrier = self.heartbeat.barrier_at(received_at);
                Some(self.replica.ingest_at(bytes, first_barrier))
            }
        }
    }

    /// Cross exactly one barrier by hand: settle due tickets, close ban polls, re-pin
    /// the callback root (§5.2/§7). Used by tests and the CLI demo to drive settlement
    /// deterministically; the live cadence is [`tick`](Self::tick)/
    /// [`run_heartbeat`](Self::run_heartbeat).
    pub fn barrier(&mut self) {
        self.replica.barrier();
    }

    /// Advance the replica to the barrier the shared schedule says `now_ms` (a
    /// service-comparable wall-clock time, ms since the epoch) has reached, settling any
    /// tickets now due. This is the sync core of the heartbeat; it reads a *local* clock
    /// only to move the monotone "how far has now got" counter, never to place a record
    /// (§14, d5). Returns the barrier the replica is now at.
    pub fn tick(&mut self, now_ms: u64) -> u64 {
        self.replica.advance_to(self.heartbeat.barrier_at(now_ms));
        self.replica.current_barrier()
    }

    /// Drive the settlement heartbeat forever: every `heartbeat_secs` (the schedule's
    /// period) advance the replica to the current barrier and, when that actually
    /// crosses a boundary, call `on_barrier` so a UI can re-render.
    ///
    /// Shares the `Arc<Mutex<_>>` with [`receive_loop`](Self::receive_loop) — the two
    /// tasks run concurrently over one messenger, each taking the lock only briefly, so
    /// a barrier and an ingest never race. Spawn it alongside the receive loop and abort
    /// it when the client shuts down; it does not return on its own.
    pub async fn run_heartbeat(this: Arc<Mutex<Self>>, mut on_barrier: impl FnMut(&Self))
    where
        Self: Send,
    {
        let period = { this.lock().await.heartbeat.period_ms() };
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(period.max(1)));
        interval.tick().await; // the first tick fires immediately; skip it.
        loop {
            interval.tick().await;
            let now = now_ms();
            let mut m = this.lock().await;
            let before = m.replica.current_barrier();
            if m.tick(now) != before {
                on_barrier(&m);
            }
        }
    }

    // --- Send: produce (sync) ---------------------------------------------------

    /// Announce this member's join (no proof). Must land before any other send.
    pub fn emit_join(&mut self) -> Result<Emitted, SendError> {
        let record = self.member.as_ref().ok_or(SendError::Observer)?.join();
        self.emit(record)
    }

    /// Produce an anonymous post.
    pub fn emit_post_anon(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        body: impl Into<String>,
    ) -> Result<Emitted, SendError> {
        let record = {
            let (replica, member) = self.parts_mut()?;
            member.post_anon(rng, replica.obj_store(), body)?
        };
        self.emit(record)
    }

    /// Produce a pseudonymous post under `context`.
    pub fn emit_post_pseudo(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        body: impl Into<String>,
        context: F,
    ) -> Result<Emitted, SendError> {
        let record = {
            let (replica, member) = self.parts_mut()?;
            member.post_pseudo(rng, replica.obj_store(), body, context)?
        };
        self.emit(record)
    }

    /// Produce a rate-limited pseudonymous post (`i`-th persona for `context`).
    pub fn emit_post_pseudo_rate(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        body: impl Into<String>,
        context: F,
        i: F,
    ) -> Result<Emitted, SendError> {
        let record = {
            let (replica, member) = self.parts_mut()?;
            member.post_pseudo_rate(rng, replica.obj_store(), body, context, i)?
        };
        self.emit(record)
    }

    /// Open a poll (no proof). `target` is the post under review for a ban poll.
    pub fn emit_poll(
        &mut self,
        question: impl Into<String>,
        options: Vec<String>,
        kind: PollKind,
        target: Option<Eh>,
    ) -> Result<Emitted, SendError> {
        // An observer may still open a poll (it carries no proof), but for symmetry
        // we require membership — a group's polls come from its members.
        if self.member.is_none() {
            return Err(SendError::Observer);
        }
        self.emit(member::open_poll(question, options, kind, target))
    }

    /// Cast a ballot in `poll`.
    pub fn emit_vote(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        poll: Eh,
        option: u32,
    ) -> Result<Emitted, SendError> {
        let record = {
            let (replica, member) = self.parts_mut()?;
            member.vote(rng, replica.obj_store(), poll, option)?
        };
        self.emit(record)
    }

    /// Rate `target` by `delta` (§10).
    pub fn emit_rate(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        target: Eh,
        delta: i8,
    ) -> Result<Emitted, SendError> {
        let record = {
            let (replica, member) = self.parts_mut()?;
            member.rate(rng, replica.obj_store(), target, delta)?
        };
        self.emit(record)
    }

    /// Produce a scan absorbing every callback invoked on this member since its last
    /// scan, against the replica's current-barrier callback set (§5.2).
    pub fn emit_scan(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Emitted, SendError> {
        let record = {
            let (replica, member) = self.parts_mut()?;
            member.scan(rng, replica.obj_store(), replica.callback_store())?
        };
        self.emit(record)
    }

    // --- Send: broadcast (async) ------------------------------------------------

    /// Broadcast an already-[`emit`](Self::emit_join)ted record over the transport.
    pub async fn broadcast(&self, emitted: &Emitted) -> Result<Sent, SendError> {
        let carried = carriage::encode(&emitted.bytes);
        let outgoing = carried.into_outgoing(self.conversation.clone(), emitted.persona.clone());
        let transport = self.transport.clone();
        Ok(transport.send(outgoing).await?)
    }

    /// Emit and broadcast an anonymous post in one call. Returns its `eh` (to
    /// reference later) and the messenger's `Sent` id.
    pub async fn send_post_anon(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        body: impl Into<String>,
    ) -> Result<(Eh, Sent), SendError> {
        let e = self.emit_post_anon(rng, body)?;
        let sent = self.broadcast(&e).await?;
        Ok((e.eh, sent))
    }

    /// Emit and broadcast a pseudonymous post.
    pub async fn send_post_pseudo(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        body: impl Into<String>,
        context: F,
    ) -> Result<(Eh, Sent), SendError> {
        let e = self.emit_post_pseudo(rng, body, context)?;
        let sent = self.broadcast(&e).await?;
        Ok((e.eh, sent))
    }

    /// Emit and broadcast this member's join.
    pub async fn send_join(&mut self) -> Result<(Eh, Sent), SendError> {
        let e = self.emit_join()?;
        let sent = self.broadcast(&e).await?;
        Ok((e.eh, sent))
    }

    /// Emit and broadcast a poll.
    pub async fn send_poll(
        &mut self,
        question: impl Into<String>,
        options: Vec<String>,
        kind: PollKind,
        target: Option<Eh>,
    ) -> Result<(Eh, Sent), SendError> {
        let e = self.emit_poll(question, options, kind, target)?;
        let sent = self.broadcast(&e).await?;
        Ok((e.eh, sent))
    }

    /// Emit and broadcast a ballot.
    pub async fn send_vote(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        poll: Eh,
        option: u32,
    ) -> Result<(Eh, Sent), SendError> {
        let e = self.emit_vote(rng, poll, option)?;
        let sent = self.broadcast(&e).await?;
        Ok((e.eh, sent))
    }

    // --- The receive loop -------------------------------------------------------

    /// Subscribe to the transport and ingest every record it delivers, calling
    /// `on_update` after each accepted record so a UI can re-render.
    ///
    /// Shared behind an `Arc<Mutex<_>>` so a caller can hold the same messenger to
    /// send from another task; the loop takes the lock only briefly per event. Ends
    /// when the transport stream closes.
    pub async fn receive_loop(
        this: Arc<Mutex<Self>>,
        mut on_update: impl FnMut(&Self),
    ) -> Result<(), TransportError>
    where
        Self: Send,
    {
        let transport = { this.lock().await.transport.clone() };
        let mut stream = transport.subscribe().await?;
        while let Some(event) = stream.next().await {
            let mut m = this.lock().await;
            if m.ingest_incoming(&event).is_some() {
                on_update(&m);
            }
        }
        Ok(())
    }

    // --- Internals --------------------------------------------------------------

    /// Encode a produced record, fold it into the sender's *own* replica (a sender is
    /// a member of its own log), and return it ready to broadcast.
    fn emit(&mut self, record: Record) -> Result<Emitted, SendError> {
        let (bytes, eh) = record::encode(&record)?;
        let persona = persona_for(&record);
        // Idempotent by `eh`, so the echo the transport later delivers is deduped.
        let _ = self.replica.ingest(bytes.clone());
        Ok(Emitted { bytes, eh, persona })
    }

    /// Split the disjoint `replica`/`member` fields so a produce step can read the
    /// object tree while mutating the member's user state.
    fn parts_mut(&mut self) -> Result<(&Replica<OH, MH, NH>, &mut Member), SendError> {
        let member = self.member.as_mut().ok_or(SendError::Observer)?;
        Ok((&self.replica, member))
    }
}

/// Local wall-clock milliseconds since the Unix epoch — the heartbeat's tick source.
/// Comparable to a provider's service timestamps (both count from the same epoch), and
/// used only to advance the monotone barrier counter (§14, d5).
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The petname a record should render its sender as (a pseudonymous post's persona),
/// or `None` for an anonymous or non-post record.
fn persona_for(record: &Record) -> Option<String> {
    match record {
        Record::Post {
            flavour: Flavour::Pseudo | Flavour::PseudoRate,
            extra,
            ..
        } => extra.0.get(1).map(|claimed| persona::petname(*claimed)),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
