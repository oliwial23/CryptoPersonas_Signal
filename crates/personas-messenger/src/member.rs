//! The send side: a co-located member that produces serverless records with real
//! proofs (workstream **d4**).
//!
//! d3 is receive-only — it ingests record *bytes* and rebuilds. A messenger also
//! has to *make* the records this member sends, and serverless has no server to
//! prove against: the member proves against the **Merkle stores the replica derived
//! itself** ([`Replica::obj_store`](personas_bulletin::replica::Replica::obj_store),
//! [`callback_store`](personas_bulletin::replica::Replica::callback_store)). This is
//! the serverless analogue of `personas_client::flows`, but Merkle-store-based and
//! record-producing rather than HTTP-request-producing.
//!
//! # Why not reuse `personas_core`'s `exec_*` helpers
//!
//! The service `exec_standint`/`exec_pseudo_standint`/… pass
//! `is_memb_data_const = true` — correct when the object bulletin's public data is a
//! fixed verification *key*, wrong when it is a **root** that changes every append.
//! Merkle mode needs `false` so the root becomes a public input the verifier pins
//! (`SERVERLESS_PROTOCOL.md` §5.3). So this module calls `exec_method_create_cb` /
//! `interact` / `prove_statement_and_in` directly with `false`, exactly as d3's
//! end-to-end tests do.
//!
//! # Optimistic object state and re-basing (a left seam)
//!
//! A post advances the member's [`User`] object immediately (`exec_method_create_cb`
//! mutates it), before the record is accepted. On the serial demo path — one author
//! posting, letting each record land before the next — that optimism always holds.
//! Under real concurrency a post can be reorged out or lose a double-spend
//! linearisation (§5.4/§13), and the member would have to **re-base** its in-flight
//! object onto the current root. That state machine is d4's acknowledged seam (it is
//! `FINDINGS` O2 / §13); this module produces one interaction at a time and expects
//! the caller to let it land, which is what [`Messenger`](crate::Messenger)'s
//! send-then-ingest-own-echo flow does.

use ark_ff::UniformRand;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::SynthesisError;
use rand::{CryptoRng, RngCore};

use personas_bulletin::merkle::{MerkleCallbackStore, MerkleObjStore};
use personas_bulletin::replica::record::{Ark, Eh, Flavour, PollKind, Record};
use personas_core::circuits::{
    MsgUser, NUM_SCANS_PER_FOLD, PrivScan, PrivScanVar, PseudonymArgs, PseudonymArgsRate,
    PseudonymArgsVar, PubScan, PubScanVar, get_callbacks, get_scan_interaction,
    get_standard_interaction, get_standard_pseudo_interaction,
    get_standard_pseudo_rate_interaction, pseudonym_pred,
};
use personas_core::params::ServerKeys;
use personas_core::{Args, ArgsVar, Cr, F, H, PK, Snark, persona};

use zk_callbacks::generic::bulletin::PublicUserBul;
use zk_callbacks::generic::object::Time;
use zk_callbacks::generic::user::User;
use zk_callbacks::impls::centralized::crypto::FakeSigPubkey;

/// A member could not build a record.
#[derive(Debug, thiserror::Error)]
pub enum MemberError {
    /// This member's object is not (yet) in the object tree the proof would pin. A
    /// join has to land before any post/vote/rate/scan — `exec_method_create_cb`
    /// panics on a missing membership witness, so we refuse first.
    #[error("this member is not on the bulletin yet — join first and let the join land")]
    NotJoined,
    /// A scan needs at least `NUM_SCANS_PER_FOLD` outstanding callbacks to answer.
    #[error("nothing to scan: {have} outstanding callbacks, need {need}")]
    NothingToScan { have: usize, need: usize },
    /// Groth16 proving failed.
    #[error("proof generation failed: {0}")]
    Proof(#[from] SynthesisError),
}

/// The **proving** keys a member needs — the mirror of
/// [`ReplicaKeys`](personas_bulletin::replica::ReplicaKeys) (the verifying halves).
/// A member proves; a replica verifies; they are two halves of the same
/// Merkle-mode [`ServerKeys`] bundle.
#[derive(Clone)]
pub struct MemberKeys {
    pub standard: PK,
    pub pseudo: PK,
    pub pseudo_rate: PK,
    pub scan: PK,
    pub pseudonym_pred: PK,
}

impl MemberKeys {
    /// Take the proving keys out of a full [`ServerKeys`] bundle (as produced by
    /// `merkle::params::generate_merkle_server_keys`).
    pub fn from_server_keys(keys: &ServerKeys) -> Self {
        Self {
            standard: keys.standard_proving_key.clone(),
            pseudo: keys.standard_pseudo_proving_key.clone(),
            pseudo_rate: keys.standard_pseudor_proving_key.clone(),
            scan: keys.scan_proving_key.clone(),
            pseudonym_pred: keys.pseudonym_pred_proving_key.clone(),
        }
    }
}

/// A member's local secret state (its zk object) plus the proving keys, and the
/// methods that turn "I want to post / vote / rate / scan" into a signed-by-proof
/// [`Record`].
///
/// `Clone` forks the whole local state — used where two candidate interactions are
/// built from one starting object (e.g. a stale vs. fresh scan in a test), never as
/// a way to double-spend (a fork that broadcasts both loses one to the §4
/// nullifier-first-wins rule).
#[derive(Clone)]
pub struct Member {
    /// The zk user object. Public only so an integration test can inspect
    /// `data.banned` after a scan absorbs a ban; treat it as owned state.
    pub user: User<F, MsgUser>,
    keys: MemberKeys,
}

impl Member {
    /// A fresh member with a random secret key (as the real client creates them).
    pub fn create(keys: MemberKeys, rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let user = User::create(
            MsgUser {
                sk: F::rand(rng),
                ..Default::default()
            },
            rng,
        );
        Self { user, keys }
    }

    /// Wrap an existing user (e.g. restored from disk).
    pub fn from_user(user: User<F, MsgUser>, keys: MemberKeys) -> Self {
        Self { user, keys }
    }

    /// This member's current object commitment — what a `Join` commits and what
    /// every proof proves membership of.
    pub fn commitment(&self) -> F {
        self.user.commit::<H>()
    }

    /// The `Join` record committing this member's current object. Serverless carries
    /// the initial nullifier as data (`F::from(0)`) so every replica appends an
    /// identical leaf.
    pub fn join(&self) -> Record {
        Record::Join {
            object: Ark(self.commitment()),
            old_nul: Ark(F::from(0)),
        }
    }

    /// An anonymous post against the object tree's current root.
    pub fn post_anon<const OH: usize>(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        obj: &MerkleObjStore<F, OH>,
        body: impl Into<String>,
    ) -> Result<Record, MemberError> {
        self.require_member(obj)?;
        let root = obj.root();
        let exec = self
            .user
            .exec_method_create_cb::<H, F, FpVar<F>, (), (), Args, ArgsVar, Cr, Snark, MerkleObjStore<F, OH>, 1>(
                rng,
                get_standard_interaction(),
                [FakeSigPubkey::pk()],
                Time::from(0),
                obj,
                false,
                &self.keys.standard,
                F::from(0),
                (),
            )?;
        Ok(Record::Post {
            flavour: Flavour::Anon,
            exec: Ark(exec),
            extra: Ark(vec![]),
            body: body.into(),
            obj_root: Ark(root),
        })
    }

    /// A pseudonymous post: reveals `claimed = H(sk, context)` under a member-chosen
    /// `context`. The context rides in the proof's public inputs (`extra`), and the
    /// replica pins only `obj_root` (§3, `PostPseudo`).
    pub fn post_pseudo<const OH: usize>(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        obj: &MerkleObjStore<F, OH>,
        body: impl Into<String>,
        context: F,
    ) -> Result<Record, MemberError> {
        self.require_member(obj)?;
        let root = obj.root();
        let claimed = persona::pseudonym(&self.user.data.sk, &context);
        let pseudo = PseudonymArgs { context, claimed };
        let exec = self
            .user
            .exec_method_create_cb::<H, PseudonymArgs<F>, PseudonymArgsVar<F>, (), (), Args, ArgsVar, Cr, Snark, MerkleObjStore<F, OH>, 1>(
                rng,
                get_standard_pseudo_interaction(),
                [FakeSigPubkey::pk()],
                Time::from(0),
                obj,
                false,
                &self.keys.pseudo,
                pseudo,
                (),
            )?;
        Ok(Record::Post {
            flavour: Flavour::Pseudo,
            exec: Ark(exec),
            extra: Ark(vec![context, claimed]),
            body: body.into(),
            obj_root: Ark(root),
        })
    }

    /// A rate-limited pseudonymous post under the `i`-th pseudonym for `context`
    /// (`claimed = H(sk, context, i)`), capping personas per context at `MAX_PSEUDO`.
    pub fn post_pseudo_rate<const OH: usize>(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        obj: &MerkleObjStore<F, OH>,
        body: impl Into<String>,
        context: F,
        i: F,
    ) -> Result<Record, MemberError> {
        self.require_member(obj)?;
        let root = obj.root();
        let claimed = persona::pseudonym_rate(&self.user.data.sk, &context, &i);
        let pseudo = PseudonymArgsRate {
            context,
            claimed,
            i,
        };
        let exec = self
            .user
            .exec_method_create_cb::<H, PseudonymArgsRate<F>, personas_core::circuits::PseudonymArgsRateVar<F>, (), (), Args, ArgsVar, Cr, Snark, MerkleObjStore<F, OH>, 1>(
                rng,
                get_standard_pseudo_rate_interaction(),
                [FakeSigPubkey::pk()],
                Time::from(0),
                obj,
                false,
                &self.keys.pseudo_rate,
                pseudo,
                (),
            )?;
        Ok(Record::Post {
            flavour: Flavour::PseudoRate,
            exec: Ark(exec),
            extra: Ark(vec![context, claimed, i]),
            body: body.into(),
            obj_root: Ark(root),
        })
    }

    /// A ballot in a poll. Proves `pseudonym_pred` under the poll's context; does
    /// **not** advance the object (voting costs no rate-limit budget, §8), so `&self`.
    pub fn vote<const OH: usize>(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        obj: &MerkleObjStore<F, OH>,
        poll: Eh,
        option: u32,
    ) -> Result<Record, MemberError> {
        let context = poll.context();
        let (root, claimed, proof) = self.pseudonym_statement(rng, obj, context)?;
        Ok(Record::Vote {
            poll,
            option,
            proof: Ark(proof),
            claimed: Ark(claimed),
            obj_root: Ark(root),
        })
    }

    /// A rating of another record (§10): the same `pseudonym_pred` statement, under
    /// `context = target.context()`, so it is one rating per member per target and
    /// unlinkable across targets. Read-only, like a vote.
    pub fn rate<const OH: usize>(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        obj: &MerkleObjStore<F, OH>,
        target: Eh,
        delta: i8,
    ) -> Result<Record, MemberError> {
        let context = target.context();
        let (root, claimed, proof) = self.pseudonym_statement(rng, obj, context)?;
        Ok(Record::Rate {
            target,
            delta,
            proof: Ark(proof),
            claimed: Ark(claimed),
            obj_root: Ark(root),
        })
    }

    /// A callback scan against the replica's **current-barrier** callback store,
    /// absorbing every callback invoked on this member since its last scan (§5.2,
    /// §13). Advances the object.
    pub fn scan<const OH: usize, const MH: usize, const NH: usize>(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        obj: &MerkleObjStore<F, OH>,
        cbs: &MerkleCallbackStore<F, MH, NH>,
    ) -> Result<Record, MemberError> {
        self.require_member(obj)?;
        let have = self.user.num_outstanding_callbacks();
        if have < NUM_SCANS_PER_FOLD {
            return Err(MemberError::NothingToScan {
                have,
                need: NUM_SCANS_PER_FOLD,
            });
        }
        let root = obj.root();
        let (ps, prs) = self
            .user
            .get_scan_arguments::<Args, ArgsVar, Cr, MerkleCallbackStore<F, MH, NH>, NUM_SCANS_PER_FOLD>(
                cbs,
                (false, false),
                Time::from(0),
                get_callbacks(),
            );
        let md = <MerkleObjStore<F, OH> as PublicUserBul<F, MsgUser>>::get_membership_data(
            obj,
            self.commitment(),
        )
        .ok_or(MemberError::NotJoined)?;
        let exec = self
            .user
            .interact::<H, PubScan<MerkleCallbackStore<F, MH, NH>, NUM_SCANS_PER_FOLD>, PubScanVar<MerkleCallbackStore<F, MH, NH>, NUM_SCANS_PER_FOLD>, PrivScan<MerkleCallbackStore<F, MH, NH>, NUM_SCANS_PER_FOLD>, PrivScanVar<MerkleCallbackStore<F, MH, NH>, NUM_SCANS_PER_FOLD>, Args, ArgsVar, Cr, Snark, MerkleObjStore<F, OH>, 0>(
                rng,
                get_scan_interaction::<MerkleCallbackStore<F, MH, NH>, NUM_SCANS_PER_FOLD>(),
                [],
                Time::from(0),
                md,
                false,
                &self.keys.scan,
                ps,
                prs,
                true,
            )?;
        Ok(Record::Scan {
            exec: Ark(exec),
            obj_root: Ark(root),
            cb_memb_root: Ark(cbs.memb_root()),
            cb_nmemb_root: Ark(cbs.nmemb_root()),
        })
    }

    /// The shared `pseudonym_pred` proof for a vote or a rating: prove membership and
    /// `claimed = H(sk, context)`, returning `(root, claimed, proof)`.
    fn pseudonym_statement<const OH: usize>(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        obj: &MerkleObjStore<F, OH>,
        context: F,
    ) -> Result<(F, F, <Snark as ark_snark::SNARK<F>>::Proof), MemberError> {
        let (root, path) =
            <MerkleObjStore<F, OH> as PublicUserBul<F, MsgUser>>::get_membership_data(
                obj,
                self.commitment(),
            )
            .ok_or(MemberError::NotJoined)?;
        let claimed = persona::pseudonym(&self.user.data.sk, &context);
        let pseudo = PseudonymArgs { context, claimed };
        let proof = self
            .user
            .prove_statement_and_in::<H, PseudonymArgs<F>, PseudonymArgsVar<F>, (), (), Snark, MerkleObjStore<F, OH>>(
                rng,
                pseudonym_pred,
                &self.keys.pseudonym_pred,
                (path, root),
                false,
                pseudo,
                (),
            )?;
        Ok((root, claimed, proof))
    }

    /// Refuse a post/scan before it can panic inside `exec_method_create_cb`'s
    /// unconditional membership `unwrap`.
    fn require_member<const OH: usize>(
        &self,
        obj: &MerkleObjStore<F, OH>,
    ) -> Result<(), MemberError> {
        if <MerkleObjStore<F, OH> as PublicUserBul<F, MsgUser>>::get_membership_data(
            obj,
            self.commitment(),
        )
        .is_none()
        {
            return Err(MemberError::NotJoined);
        }
        Ok(())
    }
}

/// A `PollOpen` record. It carries no proof — anyone in the group may open a poll,
/// and its context is fixed by its own envelope hash (§8) — so it needs no member
/// key and is a plain constructor.
pub fn open_poll(
    question: impl Into<String>,
    options: Vec<String>,
    kind: PollKind,
    target: Option<Eh>,
) -> Record {
    Record::PollOpen {
        question: question.into(),
        options,
        kind,
        target,
    }
}
