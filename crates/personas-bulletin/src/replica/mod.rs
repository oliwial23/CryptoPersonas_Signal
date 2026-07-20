//! The serverless replica engine (workstream **d3**).
//!
//! Every member runs a replica. The group chat is an ordered log of [`Record`]s;
//! each replica ingests it, applies the same deterministic accept rule, and
//! thereby computes the same bulletin. *The accept rule is the protocol*
//! (`docs/SERVERLESS_PROTOCOL.md` §1). This module is that rule, and the state it
//! maintains: the d1 Merkle object and callback trees, the nullifier set, the
//! poll/rating tallies, the outstanding-ticket settlement set, and the persona
//! cache — all derived from the log, none of it trusted from a peer.
//!
//! # Why it recomputes rather than mutates forward
//!
//! Convergence (§1) is the whole game: two replicas that have ingested the *same*
//! records must compute the *same* roots, or they have forked. Arrival order is
//! adversarial — the messenger may deliver a member's second post before their
//! first — so the engine cannot simply append as records land. The d1 object tree
//! is append-*order*-sensitive (d1 §assumption 5 punts the ordering to here), so a
//! convergent replica must impose a **canonical** order independent of arrival.
//!
//! The canonical order is §4's: **prefix (causal) order, tiebroken by ascending
//! envelope hash.** A record names the object root it was built on (§5.1), which
//! is a commitment to the prefix accepted before it, so "root `r` was produced" is
//! the causal predicate and the smaller `eh` wins a genuine tie. The engine
//! realises this by *replaying the whole seen set* on each change: at each barrier
//! it repeatedly applies the smallest-`eh` record whose named root it has already
//! produced, until none remain. This is a deterministic function of (the record
//! set, the per-record first-seen barrier, the current barrier) — so replicas that
//! saw the same records under the same barrier schedule converge exactly, and the
//! rest converge as the schedule catches up (§5.2's transient-then-closed
//! divergence). Groth16 verification is memoised by `eh` (a proof's validity
//! against the root it names is a fixed fact), so replay costs one verification per
//! record, not one per rebuild.
//!
//! # The root discipline (the security claim d1 rests on)
//!
//! d1 §assumption 3: *the replica pins a root it derived itself, never a root from
//! a proof or a peer.* Here that is literal. An object proof is verified against
//! `Some(root)` where `root` is one this replica produced (§5.1, monotone — any
//! recent produced root is safe, held in a window of the last `K`). A scan's
//! callback roots are the replica's **own current-barrier** roots, rebuilt from
//! its own called set (§5.2, anti-monotone — the latest barrier only, no grace);
//! a scan naming a superseded barrier simply has no matching root and is rejected.
//! That is the structural O10 fix carried into the engine.
//!
//! # Scope (d3)
//!
//! Built here: the accept rules for `Join`/`Post`/`Scan`/`Vote`/`Rate`/`PollOpen`,
//! the object-root window, nullifier-first-wins, the event-driven [`Replica::barrier`]
//! that fires the **derived** triggers (poll-ban close and reputation settlement,
//! §7) and re-pins the callback root, the tallies and persona cache, and
//! append-only journal persistence. Deferred to their workstreams: the messenger
//! receive loop / rendering / `Snapshot` late-join (d4); the settlement-heartbeat
//! *cadence* that drives `barrier()` (d5); `FoldScan` (off by default, §13); and
//! the *authorized* triggers `BanInvoke`/`BadgeGrant`, which need the config
//! authority-key list (their derived cousin, the poll-ban, is implemented).

pub mod record;
pub mod tally;

#[cfg(test)]
mod e2e_tests;
#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;

use ark_snark::SNARK;
use zk_callbacks::crypto::enc::AECipherSigZK;
use zk_callbacks::generic::bulletin::{CallbackBul, UserBul};
use zk_callbacks::generic::object::Time;
use zk_callbacks::impls::centralized::crypto::FakeSigPrivkey;

use personas_core::circuits::{
    BAN_FLAG, MsgUser, NUM_SCANS_PER_FOLD, PseudonymArgs, PseudonymArgsRate, arg_rep,
};
use personas_core::params::ServerKeys;
use personas_core::{Cr, F, Snark, VK};

use crate::merkle::callback::{DEFAULT_CB_MEMB_HEIGHT, DEFAULT_CB_NMEMB_HEIGHT};
use crate::merkle::obj::DEFAULT_OBJ_HEIGHT;
use crate::merkle::params::merkle_scan_pubdata;
use crate::merkle::{MerkleCallbackStore, MerkleObjStore};

use record::{Eh, Flavour, PollKind, Record};
use tally::{Derived, LogEntry, Outstanding, Poll, f_key};

/// The verifying keys a replica needs. A subset of [`ServerKeys`] — only the
/// verifying halves, and only Merkle mode.
///
/// The heights the keys were generated for are a type-level contract with the
/// [`Replica`]'s const generics, exactly as in d1: a key built for a height-32
/// object tree verifies only a proof made against one.
#[derive(Clone)]
pub struct ReplicaKeys {
    /// Standard (anonymous) post.
    pub standard: VK,
    /// Pseudonymous post.
    pub pseudo: VK,
    /// Rate-limited pseudonymous post.
    pub pseudo_rate: VK,
    /// Callback scan.
    pub scan: VK,
    /// The `pseudonym_pred` statement — a vote or a proof-carrying rating (§10).
    pub pseudonym_pred: VK,
}

impl ReplicaKeys {
    /// Take the verifying keys out of a full [`ServerKeys`] bundle (as produced by
    /// `merkle::params::generate_merkle_server_keys`).
    pub fn from_server_keys(keys: &ServerKeys) -> Self {
        Self {
            standard: keys.standard_verifying_key.clone(),
            pseudo: keys.standard_pseudo_verifying_key.clone(),
            pseudo_rate: keys.standard_pseudor_verifying_key.clone(),
            scan: keys.scan_verifying_key.clone(),
            pseudonym_pred: keys.pseudonym_pred_verifying_key.clone(),
        }
    }
}

/// Replica parameters, all with the `SERVERLESS_PROTOCOL.md` §14 defaults.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// `K`: how far behind a prover's object root may lag before it is dropped
    /// rather than buffered. Safe at any size (monotone, §5.1); bounds memory.
    pub root_window: usize,
    /// `W`: how many barriers a post's ticket lives before forced settlement (§7).
    pub settlement_barriers: u64,
    /// How many barriers a poll accepts votes for before it closes (§8).
    pub poll_close_barriers: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            root_window: 256,
            settlement_barriers: 3,
            poll_close_barriers: 2,
        }
    }
}

/// What became of a record once the replica applied the accept rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Accepted and folded into the bulletin.
    Applied,
    /// Well-formed, but it names an object root this replica has not produced —
    /// the prover is ahead, or the record is orphaned. Retried on every rebuild;
    /// dropped once its root ages past the window (§5.1).
    Buffered,
    /// Rejected: the proof failed, the nullifier was already spent (a double-spend
    /// lost the §4 linearization), the scan named a superseded barrier (§5.2), or
    /// the record referenced something that does not exist.
    Rejected(&'static str),
}

/// A record the replica has seen, with the barrier it first arrived at.
struct Seen {
    bytes: Vec<u8>,
    record: Record,
    /// The `current_barrier` when this record was first ingested. Settlement and
    /// poll-close are measured from it (§7, §8).
    first_barrier: u64,
}

/// A serverless replica: the ordered log in, a convergent bulletin out.
pub struct Replica<
    const OH: usize = DEFAULT_OBJ_HEIGHT,
    const MH: usize = DEFAULT_CB_MEMB_HEIGHT,
    const NH: usize = DEFAULT_CB_NMEMB_HEIGHT,
> {
    keys: ReplicaKeys,
    config: Config,

    /// Every record seen, keyed and *ordered* by envelope hash — the §4 tiebreak
    /// is `BTreeMap`'s ascending-key iteration.
    seen: std::collections::BTreeMap<Eh, Seen>,
    /// Memoised Groth16 results: a proof's validity against the root it names is a
    /// fixed fact, computed once and reused across every rebuild.
    verify_cache: HashMap<Eh, bool>,

    /// The barrier the replica has reached; advanced by [`Replica::barrier`].
    current_barrier: u64,

    // --- Derived by rebuild (a pure function of the fields above) --------------
    obj: MerkleObjStore<F, OH>,
    cbs: MerkleCallbackStore<F, MH, NH>,
    /// Object roots produced so far, within the last-`K` window — the set a
    /// membership proof may pin against.
    produced: HashSet<[u8; 32]>,
    produced_order: VecDeque<[u8; 32]>,
    derived: Derived,
    statuses: HashMap<Eh, Status>,

    /// Append-only journal of accepted record bytes; replayed on [`Replica::open`].
    journal: Option<PathBuf>,
}

impl<const OH: usize, const MH: usize, const NH: usize> Replica<OH, MH, NH> {
    /// A fresh in-memory replica (no persistence).
    pub fn new(keys: ReplicaKeys, config: Config) -> Self {
        let mut r = Self {
            keys,
            config,
            seen: std::collections::BTreeMap::new(),
            verify_cache: HashMap::new(),
            current_barrier: 0,
            obj: MerkleObjStore::new(),
            cbs: MerkleCallbackStore::new(),
            produced: HashSet::new(),
            produced_order: VecDeque::new(),
            derived: Derived::default(),
            statuses: HashMap::new(),
            journal: None,
        };
        r.rebuild();
        r
    }

    /// A replica backed by an append-only journal at `path`, replaying any records
    /// already there.
    ///
    /// The journal is the "persisted incrementally" of the plan, and it is
    /// deliberately a *log of records*, not a serialised bulletin: `CentralStore`
    /// is not `CanonicalSerialize` (the a2/O1 finding) and neither is a live
    /// replica, but the records that produced it are exactly the bytes that arrived
    /// over the wire. Replaying them rebuilds identical state — which is the same
    /// determinism convergence already requires.
    pub fn open(
        path: impl Into<PathBuf>,
        keys: ReplicaKeys,
        config: Config,
    ) -> std::io::Result<Self> {
        let path = path.into();
        let existing = read_journal(&path)?;
        let mut r = Self::new(keys, config);
        r.journal = Some(path);
        for bytes in existing {
            // Records already in the journal were accepted once; ingest them without
            // re-journaling (the `journal` write is skipped for replayed bytes). The
            // journal stores only bytes, not the barrier a record first arrived at, so
            // replay re-assigns `first_barrier = 0`; the barrier-faithful restore path is
            // the d4 snapshot ([`from_records`]), which carries the schedule.
            let at = r.current_barrier;
            let _ = r.ingest_inner(bytes, at, false, false);
        }
        Ok(r)
    }

    /// Rebuild a replica from a snapshot's records and barrier schedule (d4 late
    /// join, `SERVERLESS_PROTOCOL.md` §12).
    ///
    /// A [`Snapshot`](../../messenger/snapshot) is faithful only if the joiner
    /// reproduces not just the record *set* but each record's **first-seen barrier**
    /// and the current barrier — the engine's state is a function of all three (§5.2,
    /// the determinism caveat). This takes exactly that: `(first_barrier, bytes)` per
    /// record, plus the barrier the snapshot was taken at. Malformed records in the
    /// snapshot are skipped (they could not have been accepted anyway).
    ///
    /// The result is derived by the same `rebuild` as a live replica, so an adopted
    /// snapshot computes byte-identical roots to the replica it came from — which is
    /// exactly the self-revealing property §12 relies on: a tampered snapshot yields
    /// roots the group does not share, and the joiner's own proofs are then rejected.
    pub fn from_records(
        keys: ReplicaKeys,
        config: Config,
        records: Vec<(u64, Vec<u8>)>,
        current_barrier: u64,
    ) -> Self {
        let mut r = Self::new(keys, config);
        r.current_barrier = current_barrier;
        for (first_barrier, bytes) in records {
            if let Ok((record, eh)) = record::decode(&bytes) {
                r.seen.entry(eh).or_insert(Seen {
                    bytes,
                    record,
                    first_barrier,
                });
            }
        }
        r.rebuild();
        r
    }

    /// Every seen record as `(first_barrier, bytes)`, in canonical (ascending-`eh`)
    /// order — the material a [`Snapshot`](../../messenger/snapshot) hands a late
    /// joiner. Ascending order comes from the `BTreeMap` key iteration, so the list
    /// is deterministic and a digest over it is stable across replicas.
    pub fn seen_with_barriers(&self) -> Vec<(u64, Vec<u8>)> {
        self.seen
            .values()
            .map(|s| (s.first_barrier, s.bytes.clone()))
            .collect()
    }

    /// Ingest one encoded record, assigning it the replica's current barrier as its
    /// first-seen barrier. Returns its [`Status`] after re-deriving state.
    ///
    /// Idempotent by envelope hash: a record delivered twice (the messenger may)
    /// is ingested once. A malformed or wrong-version record is refused before it
    /// reaches the mempool.
    ///
    /// This uses the *local* barrier the replica has reached, which is
    /// delivery-timing-dependent. The convergent path is [`ingest_at`](Self::ingest_at),
    /// which the messenger drives with a barrier bucketed from the record's
    /// **service-assigned** timestamp so every replica agrees on it (§4/§14, d5).
    pub fn ingest(&mut self, bytes: Vec<u8>) -> Result<Status, record::CodecError> {
        let at = self.current_barrier;
        self.ingest_inner(bytes, at, true, false)
    }

    /// Ingest a record whose first-seen barrier is supplied by the caller — the d5
    /// cadence path.
    ///
    /// The messenger computes `first_barrier` by bucketing the record's
    /// service-assigned receive timestamp against the shared heartbeat schedule
    /// (`SERVERLESS_PROTOCOL.md` §14). Because that stamp is identical on every
    /// replica, the record→barrier map is identical everywhere, so two replicas that
    /// have ingested the same records **and reached the same barrier** compute
    /// byte-identical roots — the exact-convergence property (§5.2's determinism
    /// caveat closed). A record serviced in a bucket later than the replica has
    /// reached pulls `current_barrier` forward to it: the provider's stamp is proof
    /// that time advanced at least that far.
    ///
    /// This path is **authoritative**: if the record was already present under a
    /// *provisional* barrier (a sender's own optimistic self-fold via [`ingest`], which
    /// cannot yet know the service timestamp), the service-stamped barrier supplied here
    /// replaces it. That is how a sender's own record converges to the same barrier every
    /// peer buckets it into — the "emit-then-ingest-own-echo" finalisation (d4/§5.4).
    pub fn ingest_at(
        &mut self,
        bytes: Vec<u8>,
        first_barrier: u64,
    ) -> Result<Status, record::CodecError> {
        self.ingest_inner(bytes, first_barrier, true, true)
    }

    fn ingest_inner(
        &mut self,
        bytes: Vec<u8>,
        first_barrier: u64,
        journal: bool,
        authoritative: bool,
    ) -> Result<Status, record::CodecError> {
        let (rec, eh) = record::decode(&bytes)?;
        if let Some(prev) = self.seen.get(&eh) {
            // Already seen. An authoritative (service-stamped) re-arrival reconciles a
            // provisional barrier assigned by an optimistic self-fold; anything else is
            // an ordinary duplicate and is ignored.
            if authoritative && prev.first_barrier != first_barrier {
                self.seen.get_mut(&eh).expect("just found").first_barrier = first_barrier;
                self.current_barrier = self.current_barrier.max(first_barrier);
                self.rebuild();
            }
            return Ok(self.statuses.get(&eh).cloned().unwrap_or(Status::Buffered));
        }
        if journal {
            if let Some(path) = &self.journal {
                append_journal(path, &bytes);
            }
        }
        // A record whose bucket is ahead of where we've reached is itself evidence the
        // schedule advanced that far (the provider serviced it then), so cross to it.
        self.current_barrier = self.current_barrier.max(first_barrier);
        self.seen.insert(
            eh,
            Seen {
                bytes,
                record: rec,
                first_barrier,
            },
        );
        self.rebuild();
        Ok(self.statuses.get(&eh).cloned().unwrap_or(Status::Buffered))
    }

    /// Cross exactly one barrier: the settlement heartbeat, a ban, or an authority
    /// invocation (§5.2, §7). Equivalent to [`advance_to`](Self::advance_to) of the
    /// next barrier. Kept for callers that drive barriers by hand (the d4 tests and
    /// the CLI demo).
    pub fn barrier(&mut self) {
        self.advance_to(self.current_barrier + 1);
    }

    /// Advance the replica to `barrier`, settling every ticket that has since come
    /// due, closing every ban poll whose window has elapsed, and re-pinning the
    /// callback root (§5.2, §7). A no-op if already at or past `barrier`.
    ///
    /// This is the d5 heartbeat's settle trigger: the messenger calls it with the
    /// barrier its shared clock says "now" has reached, so tickets settle on cadence
    /// even when no new records arrive. `current_barrier` is monotone, so a lagging
    /// local clock only settles *late* (bounded by `W`, self-healing), never at a
    /// barrier a peer disagrees with — the divergence is transient (§5.2(a)).
    pub fn advance_to(&mut self, barrier: u64) {
        if barrier <= self.current_barrier {
            return;
        }
        self.current_barrier = barrier;
        self.rebuild();
    }

    // --- Accessors --------------------------------------------------------------

    /// The current object-tree root — the membership data a member proves against.
    pub fn obj_root(&self) -> F {
        self.obj.root()
    }

    /// The current callback membership root (called tickets).
    pub fn cb_memb_root(&self) -> F {
        self.cbs.memb_root()
    }

    /// The current callback nonmembership root (the pinned barrier, §5.2).
    pub fn cb_nmemb_root(&self) -> F {
        self.cbs.nmemb_root()
    }

    /// Read-only view of the object store, for a **co-located** member to build a
    /// membership proof against the replica's own tree (the d4 send side).
    ///
    /// This is a read of state the replica derived itself, not a root trusted from
    /// a peer — the member proves membership of *its* object against the current
    /// root, and the resulting record is then re-verified on ingest like any other.
    pub fn obj_store(&self) -> &MerkleObjStore<F, OH> {
        &self.obj
    }

    /// Read-only view of the callback store, for a co-located member to build a
    /// scan against the replica's **current-barrier** called set (§5.2). A scan is
    /// only ever valid against the latest barrier, so a member must read the live
    /// store here rather than reconstruct a stale one.
    pub fn callback_store(&self) -> &MerkleCallbackStore<F, MH, NH> {
        &self.cbs
    }

    /// The barrier the replica has reached.
    pub fn current_barrier(&self) -> u64 {
        self.current_barrier
    }

    /// The status the accept rule assigned a record, by envelope hash.
    pub fn status(&self, eh: &Eh) -> Option<Status> {
        self.statuses.get(eh).cloned()
    }

    /// The raw encoded bytes of a seen record — what a late joiner's snapshot or a
    /// re-broadcast (d4) hands back out, verbatim, so its `eh` is preserved.
    pub fn record_bytes(&self, eh: &Eh) -> Option<&[u8]> {
        self.seen.get(eh).map(|s| s.bytes.as_slice())
    }

    /// The rendered log — accepted records in canonical order, for a client to
    /// display (d4 does the actual rendering).
    pub fn log(&self) -> &[LogEntry] {
        &self.derived.log
    }

    /// An open or recently-closed poll, by its `PollOpen` envelope hash.
    pub fn poll(&self, eh: &Eh) -> Option<&Poll> {
        self.derived.polls.get(eh)
    }

    /// Read access to the derived tallies (polls, outstanding tickets, personas).
    pub fn derived(&self) -> &Derived {
        &self.derived
    }

    // --- The rebuild (the accept rule) -----------------------------------------

    /// Re-derive the entire bulletin from the seen record set and the current
    /// barrier. Deterministic: the same inputs yield byte-identical trees.
    fn rebuild(&mut self) {
        let mut obj = MerkleObjStore::<F, OH>::new();
        let mut cbs = MerkleCallbackStore::<F, MH, NH>::new();
        let mut derived = Derived::default();
        let mut statuses: HashMap<Eh, Status> = HashMap::new();

        let mut produced: HashSet<[u8; 32]> = HashSet::new();
        let mut produced_order: VecDeque<[u8; 32]> = VecDeque::new();
        let mut applied: HashSet<Eh> = HashSet::new();
        // The genesis (empty-tree) root is producible from the start.
        record_root(
            &mut produced,
            &mut produced_order,
            obj.root(),
            self.config.root_window,
        );

        for b in 0..=self.current_barrier {
            // (1) The barrier event fires *first* (§5.2): settle every ticket due or
            //     banned as of the records applied through the previous barrier, and
            //     re-pin the callback root. A scan that arrives at barrier `b` must
            //     therefore prove against the *post*-settlement callback set — which
            //     is exactly what makes a ban enforceable the moment a replica crosses
            //     its barrier. (At `b == 0` there is nothing yet to settle.)
            settle_barrier(b, &self.config, &mut cbs, &mut derived);

            // (2) Apply every record now available, smallest eh first, until the
            //     worklist stops making progress. `seen` iterates in ascending eh,
            //     so the first applicable record each pass is the §4 tiebreak
            //     winner.
            loop {
                let next = self.seen.iter().find(|(eh, s)| {
                    s.first_barrier <= b
                        && !applied.contains(*eh)
                        && is_applicable(&s.record, &produced, &derived)
                });
                let Some((&eh, _)) = next else { break };
                applied.insert(eh);
                let status = self.apply(
                    eh,
                    b,
                    &mut obj,
                    &cbs,
                    &mut derived,
                    &mut produced,
                    &mut produced_order,
                );
                statuses.insert(eh, status);
            }
        }

        // Anything never applied and never rejected is waiting on a root it has not
        // seen (a prover ahead, or an orphan) — buffered.
        for eh in self.seen.keys() {
            statuses.entry(*eh).or_insert(Status::Buffered);
        }

        self.obj = obj;
        self.cbs = cbs;
        self.derived = derived;
        self.produced = produced;
        self.produced_order = produced_order;
        self.statuses = statuses;
    }

    /// Apply one record against the state being rebuilt. Only ever called when
    /// [`is_applicable`] holds, so any named object root is already produced.
    #[allow(clippy::too_many_arguments)]
    fn apply(
        &mut self,
        eh: Eh,
        barrier: u64,
        obj: &mut MerkleObjStore<F, OH>,
        cbs: &MerkleCallbackStore<F, MH, NH>,
        derived: &mut Derived,
        produced: &mut HashSet<[u8; 32]>,
        produced_order: &mut VecDeque<[u8; 32]>,
    ) -> Status {
        let window = self.config.root_window;
        let w = self.config.settlement_barriers;
        // Borrow the record out of `seen` for the duration; `self.verify_cache` is a
        // disjoint field, so a free helper can memoise while we hold `&record`.
        let seen = &self.seen[&eh];
        match &seen.record {
            Record::Join { object, old_nul } => {
                obj.push(object.0, old_nul.0, Vec::new());
                record_root(produced, produced_order, obj.root(), window);
                Status::Applied
            }

            Record::Post {
                flavour,
                exec,
                extra,
                body,
                obj_root,
            } => {
                let exec = &exec.0;
                let root = obj_root.0;
                let ok = match flavour {
                    Flavour::Anon => memo_interaction::<OH, _, 1>(
                        &mut self.verify_cache,
                        eh,
                        &self.keys.standard,
                        exec.new_object,
                        exec.old_nullifier,
                        F::from(0),
                        exec.cb_com_list,
                        &exec.proof,
                        root,
                    ),
                    Flavour::Pseudo => {
                        let a = PseudonymArgs {
                            context: extra.0[0],
                            claimed: extra.0[1],
                        };
                        memo_interaction::<OH, _, 1>(
                            &mut self.verify_cache,
                            eh,
                            &self.keys.pseudo,
                            exec.new_object,
                            exec.old_nullifier,
                            a,
                            exec.cb_com_list,
                            &exec.proof,
                            root,
                        )
                    }
                    Flavour::PseudoRate => {
                        let a = PseudonymArgsRate {
                            context: extra.0[0],
                            claimed: extra.0[1],
                            i: extra.0[2],
                        };
                        memo_interaction::<OH, _, 1>(
                            &mut self.verify_cache,
                            eh,
                            &self.keys.pseudo_rate,
                            exec.new_object,
                            exec.old_nullifier,
                            a,
                            exec.cb_com_list,
                            &exec.proof,
                            root,
                        )
                    }
                };
                if !ok {
                    return Status::Rejected("post proof failed");
                }
                if obj.has_seen_nul(&exec.old_nullifier) {
                    // First-reveal-wins: an earlier record already spent this
                    // object's nullifier, so this one is a double-spend (or a rewind
                    // to a stale state) and its successor is refused — it can never
                    // be built upon. Only the object's owner can even produce this,
                    // so a collision is self-inflicted.
                    return Status::Rejected("nullifier already spent");
                }
                obj.push(
                    exec.new_object,
                    exec.old_nullifier,
                    exec.cb_com_list.to_vec(),
                );
                record_root(produced, produced_order, obj.root(), window);

                // File the callback ticket the poster committed to (§7).
                let callback = exec.cb_tik_list[0].0.clone();
                derived
                    .outstanding
                    .insert(eh, Outstanding::new(callback, Time::from(0), barrier + w));

                // Render (minimally). A pseudonym gets a petname; an anon post none.
                let author = match flavour {
                    Flavour::Anon => None,
                    Flavour::Pseudo | Flavour::PseudoRate => Some(derived.petname(extra.0[1])),
                };
                derived.log.push(LogEntry {
                    eh,
                    kind: "Post",
                    author,
                    body: body.clone(),
                    flagged: false,
                });
                Status::Applied
            }

            Record::Scan {
                exec,
                obj_root,
                cb_memb_root,
                cb_nmemb_root,
            } => {
                let exec = &exec.0;
                // §5.2: the scan must pin *this* replica's current-barrier callback
                // roots. If it named a superseded barrier, the roots differ and it is
                // stale — this is the whole O10 defense at the engine layer.
                if cb_memb_root.0 != cbs.memb_root() || cb_nmemb_root.0 != cbs.nmemb_root() {
                    return Status::Rejected("scan names a superseded barrier");
                }
                let ps = merkle_scan_pubdata::<MH, NH, NUM_SCANS_PER_FOLD>(cbs, Time::from(0));
                let ok = memo_interaction::<OH, _, 0>(
                    &mut self.verify_cache,
                    eh,
                    &self.keys.scan,
                    exec.new_object,
                    exec.old_nullifier,
                    ps,
                    exec.cb_com_list,
                    &exec.proof,
                    obj_root.0,
                );
                if !ok {
                    return Status::Rejected("scan proof failed");
                }
                if obj.has_seen_nul(&exec.old_nullifier) {
                    return Status::Rejected("nullifier already spent");
                }
                obj.push(exec.new_object, exec.old_nullifier, Vec::new());
                record_root(produced, produced_order, obj.root(), window);
                derived.log.push(LogEntry {
                    eh,
                    kind: "Scan",
                    author: None,
                    body: String::new(),
                    flagged: false,
                });
                Status::Applied
            }

            Record::PollOpen {
                question,
                options,
                kind,
                target,
            } => {
                derived.polls.insert(
                    eh,
                    Poll {
                        question: question.clone(),
                        options: options.clone(),
                        kind: *kind,
                        target: *target,
                        context: eh.context(),
                        opened_barrier: barrier,
                        ballots: HashMap::new(),
                        closed: false,
                    },
                );
                Status::Applied
            }

            Record::Vote {
                poll,
                option,
                proof,
                claimed,
                obj_root,
            } => {
                let context = poll.context();
                let ok = memo_predicate(
                    &mut self.verify_cache,
                    eh,
                    &self.keys.pseudonym_pred,
                    context,
                    claimed.0,
                    obj_root.0,
                    &proof.0,
                );
                if !ok {
                    return Status::Rejected("vote proof failed");
                }
                // Applicability guaranteed the poll exists.
                derived
                    .polls
                    .get_mut(poll)
                    .expect("poll present by is_applicable")
                    .cast(claimed.0, *option);
                Status::Applied
            }

            Record::Rate {
                target,
                delta,
                proof,
                claimed,
                obj_root,
            } => {
                let context = target.context();
                let ok = memo_predicate(
                    &mut self.verify_cache,
                    eh,
                    &self.keys.pseudonym_pred,
                    context,
                    claimed.0,
                    obj_root.0,
                    &proof.0,
                );
                if !ok {
                    return Status::Rejected("rating proof failed");
                }
                derived.rate(*target, claimed.0, *delta as i64);
                Status::Applied
            }
        }
    }
}

/// Whether a record can be applied now: any object root it names has been
/// produced, and any record it references (a vote's poll) exists.
fn is_applicable(record: &Record, produced: &HashSet<[u8; 32]>, derived: &Derived) -> bool {
    let holds = |root: F| produced.contains(&f_key(root));
    match record {
        // No object root: applicable the moment its barrier arrives.
        Record::Join { .. } | Record::PollOpen { .. } => true,
        Record::Post { obj_root, .. } => holds(obj_root.0),
        Record::Rate { obj_root, .. } => holds(obj_root.0),
        Record::Scan { obj_root, .. } => holds(obj_root.0),
        Record::Vote { poll, obj_root, .. } => {
            holds(obj_root.0) && derived.polls.contains_key(poll)
        }
    }
}

/// Add an object root to the produced-set, evicting the oldest once the window is
/// full (§5.1: a prover more than `K` roots behind is dropped, not buffered).
fn record_root(
    produced: &mut HashSet<[u8; 32]>,
    order: &mut VecDeque<[u8; 32]>,
    root: F,
    window: usize,
) {
    let key = f_key(root);
    if produced.insert(key) {
        order.push_back(key);
        while order.len() > window {
            if let Some(old) = order.pop_front() {
                produced.remove(&old);
            }
        }
    }
}

/// The barrier event (§7): close ban polls, then settle every due or banned
/// ticket into the callback tree, re-pinning the nonmembership root.
fn settle_barrier<const MH: usize, const NH: usize>(
    barrier: u64,
    config: &Config,
    cbs: &mut MerkleCallbackStore<F, MH, NH>,
    derived: &mut Derived,
) {
    // (a) Close ban polls whose window has elapsed; a pass marks its target banned.
    //     Ban strictly precedes reputation (§7 property 1), so this runs first.
    let mut banned_targets: Vec<Eh> = Vec::new();
    for poll in derived.polls.values_mut() {
        if poll.closed || poll.kind != PollKind::Ban {
            continue;
        }
        if barrier >= poll.opened_barrier + config.poll_close_barriers {
            poll.closed = true;
            if poll.passes_ban() {
                if let Some(target) = poll.target {
                    banned_targets.push(target);
                }
            }
        }
    }
    for target in banned_targets {
        if let Some(out) = derived.outstanding.get_mut(&target) {
            out.banned = true;
        }
    }

    // (b) Settle every ticket now due (or banned), once. The OTP is additive and
    //     keyless (§6), so this call is a deterministic function of public data —
    //     every replica computes the identical called leaf.
    let mut due: Vec<Eh> = derived
        .outstanding
        .iter()
        .filter(|(_, o)| !o.settled && (o.banned || barrier >= o.settle_barrier))
        .map(|(eh, _)| *eh)
        .collect();
    // The called-ticket tree is append-order-sensitive, and `outstanding` is a
    // HashMap (nondeterministic iteration), so the settlement order must be fixed
    // deterministically or replicas settling ≥2 tickets in one barrier would fork.
    // Ascending eh is the same tiebreak the log order uses (§4).
    due.sort();

    let mut any_called = false;
    for eh in due {
        let out = derived
            .outstanding
            .get(&eh)
            .expect("just collected")
            .clone();
        let arg = if out.banned {
            F::from(BAN_FLAG)
        } else {
            // Reputation is clamped so `r` cannot reach `BAN_FLAG` (§7 property, R8).
            arg_rep(out.clamped_rep())
        };
        if invoke(cbs, &out, arg) {
            any_called = true;
            if let Some(o) = derived.outstanding.get_mut(&eh) {
                o.settled = true;
            }
            // Rendering gate (§9): flag the banned author's posts on sight of the ban.
            if out.banned {
                if let Some(entry) = derived.log.iter().find(|e| e.eh == eh) {
                    if let Some(author) = entry.author.clone() {
                        derived.flag_author(&author);
                    }
                }
            }
        }
    }

    // Re-pin the nonmembership root over the (possibly grown) called set. The epoch
    // counter advances, but soundness rests on the range partition (d1 §3.3): a
    // grown called set yields a distinct partition and so a distinct root, which is
    // what makes a pre-ban scan stale.
    if any_called {
        cbs.update_epoch();
    }
}

/// Invoke a committed callback with `arg`, mirroring `ServiceProvider::call`: the
/// additive-OTP ciphertext of `arg` under the ticket's key, appended to the called
/// set. Returns whether the append happened (a ticket is called at most once).
fn invoke<const MH: usize, const NH: usize>(
    cbs: &mut MerkleCallbackStore<F, MH, NH>,
    out: &Outstanding,
    arg: F,
) -> bool {
    let enc_key = out.callback.cb_entry.enc_key.clone();
    let tik = out.callback.cb_entry.tik.clone();
    let (enc, sig) =
        <Cr as AECipherSigZK<F, F>>::encrypt_and_sign(arg, enc_key, FakeSigPrivkey::sk());
    <MerkleCallbackStore<F, MH, NH> as CallbackBul<F, F, Cr>>::verify_call_and_append(
        cbs,
        tik,
        enc,
        sig,
        out.filed_at,
    )
    .is_ok()
}

/// Verify an interaction proof against `obj_root`, memoised by `eh`.
///
/// The check runs on a *fresh* empty object store, so `has_never_received_nul`
/// is trivially true and `verify_interaction` reduces to the Groth16 check against
/// the named root supplied as `Some(obj_root)` — the pure, cacheable fact. The
/// real nullifier check and append happen at the call site, against the live tree.
#[allow(clippy::too_many_arguments)]
fn memo_interaction<const OH: usize, PubArgs, const NUMCBS: usize>(
    cache: &mut HashMap<Eh, bool>,
    eh: Eh,
    vk: &VK,
    new_object: F,
    old_nul: F,
    pub_args: PubArgs,
    cb_com_list: [F; NUMCBS],
    proof: &<Snark as SNARK<F>>::Proof,
    obj_root: F,
) -> bool
where
    PubArgs: ark_ff::ToConstraintField<F> + Clone,
{
    if let Some(&v) = cache.get(&eh) {
        return v;
    }
    let fresh = MerkleObjStore::<F, OH>::new();
    let v = <MerkleObjStore<F, OH> as UserBul<F, MsgUser>>::verify_interaction::<
        PubArgs,
        Snark,
        NUMCBS,
    >(
        &fresh,
        new_object,
        old_nul,
        pub_args,
        cb_com_list,
        proof.clone(),
        Some(obj_root),
        vk,
    );
    cache.insert(eh, v);
    v
}

/// Verify a `pseudonym_pred` statement proof (a vote or a rating), memoised by
/// `eh`. The public inputs are `[context, claimed, obj_root]` — `pub_args` first,
/// then the membership root, matching the statement circuit's allocation order —
/// and every one of them is supplied by the *replica* (`context` derived from the
/// referenced record, `obj_root` pinned to a produced root), so a forged context
/// or a stale root simply fails to verify.
fn memo_predicate(
    cache: &mut HashMap<Eh, bool>,
    eh: Eh,
    vk: &VK,
    context: F,
    claimed: F,
    obj_root: F,
    proof: &<Snark as SNARK<F>>::Proof,
) -> bool {
    if let Some(&v) = cache.get(&eh) {
        return v;
    }
    let inputs = vec![context, claimed, obj_root];
    let v = Snark::verify(vk, &inputs, proof).unwrap_or(false);
    cache.insert(eh, v);
    v
}

// ---------------------------------------------------------------------------------------
// Journal persistence
// ---------------------------------------------------------------------------------------

/// Read a length-prefixed record journal, tolerating a truncated tail (a crash
/// mid-append loses at most the last record, never the whole log).
fn read_journal(path: &std::path::Path) -> std::io::Result<Vec<Vec<u8>>> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let len = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
        i += 4;
        if i + len > bytes.len() {
            tracing::warn!("truncated record journal tail dropped");
            break;
        }
        out.push(bytes[i..i + len].to_vec());
        i += len;
    }
    Ok(out)
}

/// Append one record to the journal, length-prefixed. Best-effort: a failed append
/// is logged, not fatal — the record is already in memory, and a demo bulletin's
/// durability is not worth aborting a running replica over.
fn append_journal(path: &std::path::Path, bytes: &[u8]) {
    use std::io::Write;
    let write = || -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        f.write_all(&(bytes.len() as u32).to_le_bytes())?;
        f.write_all(bytes)?;
        f.sync_all()
    };
    if let Err(e) = write() {
        tracing::warn!("could not journal a record: {e}");
    }
}
