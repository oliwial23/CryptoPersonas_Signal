//! [`MerkleCallbackStore`] — the serverless callback bulletin (d1b).
//!
//! This is the Merkle replacement for zk-callbacks' signature-based
//! `CallbackStore` + `SigRangeStore`. It carries two trees:
//!
//! - a **membership** tree over *called* tickets, leaf `H(tik, arg, time)` —
//!   append-only, so (like the object tree) it is monotone and a buffered recent
//!   root is safe. This is what a scan uses to *absorb* a ban/reputation
//!   callback.
//! - a **nonmembership** tree of *sorted ranges* covering the complement of the
//!   called set, leaf `H(lo, hi, epoch)` — rebuilt every epoch. This is what a
//!   scan uses to prove a ticket was *not* called.
//!
//! # The O10 fix, structurally (this is the crux)
//!
//! FINDINGS O10: the scan circuit proves a *signed* nonmembership range but never
//! binds its epoch to the public `cur_time`, so after a ban a member can replay a
//! pre-ban range and never absorb the callback. The signed store cannot fix this
//! itself because the signature verifies against a **stable key** the circuit
//! bakes in as a constant — a stale range still verifies.
//!
//! The Merkle store closes it by construction. Nonmembership is **anti-monotone**
//! (a ticket that was a nonmember becomes a member the instant it is called), so
//! its public data — the range-tree **root** — changes every epoch and therefore
//! *cannot* be a circuit constant. It is a **public input**, and the verifier
//! supplies the **current epoch's** root, which it recomputes itself. A pre-ban
//! range hashes up to a *past* root, so it simply has no current root to match:
//! the stale-range replay has nowhere to land. The epoch is also folded into each
//! leaf (`H(lo, hi, epoch)`), so distinct epochs always yield distinct roots even
//! if the partition is unchanged. There is **no grace/buffer** on the
//! nonmembership root — current epoch only. (Membership, being monotone, may use
//! a buffered recent root.)
//!
//! This mirrors the `SigRangeStore` range logic exactly (same complement
//! partition, same `[0, (p-1)/2 - 1)` ticket domain, same `tik >= lo && tik < hi`
//! check) so it is a like-for-like swap of the trust root, not a protocol change.

use std::cmp::Ordering;

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    fields::fp::FpVar,
    prelude::Boolean,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::distributions::{Distribution, Standard};
use std::borrow::Borrow;
use zk_callbacks::{
    crypto::hash::HasherZK,
    generic::{
        bulletin::{CallbackBul, PublicCallbackBul},
        object::{Time, TimeVar},
    },
    impls::{
        centralized::crypto::{FakeSigPubkey, FakeSigPubkeyVar, NoSigOTP},
        hash::Poseidon,
    },
};

use super::gadget::{MerklePathVar, enforce_merkle_membership};
use super::tree::{IncrementalMerkleTree, MerklePath, hash_pair};

/// Default height of the called-ticket **membership** tree.
pub const DEFAULT_CB_MEMB_HEIGHT: usize = 32;
/// Default height of the sorted-range **nonmembership** tree.
pub const DEFAULT_CB_NMEMB_HEIGHT: usize = 32;

/// The ticket domain's exclusive upper bound: `(p - 1) / 2 - 1`.
///
/// Tickets are ordered in the lower field half so the in-circuit
/// `is_cmp_unchecked` comparisons are sound; this matches the reference
/// `SigRangeStore`'s domain exactly.
fn ticket_domain_top<F: PrimeField>() -> F {
    F::from_bigint(F::MODULUS_MINUS_ONE_DIV_TWO).unwrap() - F::ONE
}

/// The membership leaf for a called ticket: `H(tik, arg, time)`.
fn memb_leaf<F: PrimeField + Absorb>(tik: F, arg: F, time: F) -> F {
    <Poseidon<2>>::hash(&[tik, arg, time])
}

/// The nonmembership leaf for a range: `H(lo, hi, epoch)`.
fn range_leaf<F: PrimeField + Absorb>(lo: F, hi: F, epoch: F) -> F {
    <Poseidon<2>>::hash(&[lo, hi, epoch])
}

/// A nonmembership witness: the range `[lo, hi)` bracketing the ticket, the epoch
/// it was committed under, and the Merkle path proving `H(lo, hi, epoch)` is a
/// leaf of the current range-tree root.
///
/// `Default` yields a full-height path (via [`MerklePath`]'s `Default`), so the
/// circuit shape is fixed at key-generation regardless of which range is later
/// proven.
#[derive(Clone, Debug, Default, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RangeWitness<F: PrimeField, const HEIGHT: usize> {
    /// Inclusive lower bound of the nonmembership range.
    pub lo: F,
    /// Exclusive upper bound of the nonmembership range.
    pub hi: F,
    /// The epoch this range was committed under.
    pub epoch: F,
    /// Path proving `H(lo, hi, epoch)` is in the range tree.
    pub path: MerklePath<F, HEIGHT>,
}

impl<F: PrimeField + Absorb, const HEIGHT: usize> RangeWitness<F, HEIGHT> {
    /// Whether `elem` lies in `[lo, hi)` (native mirror of the gadget's range check).
    pub fn is_in_range(&self, elem: F) -> bool {
        // Compare as integers in the lower field half, matching `is_cmp_unchecked`.
        self.lo <= elem && elem < self.hi
    }

    /// Recompute the range-tree root this witness attests to.
    pub fn compute_root(&self) -> F {
        self.path
            .compute_root(range_leaf(self.lo, self.hi, self.epoch))
    }
}

/// The in-circuit representation of a [`RangeWitness`].
#[derive(Clone)]
pub struct RangeWitnessVar<F: PrimeField, const HEIGHT: usize> {
    pub lo: FpVar<F>,
    pub hi: FpVar<F>,
    pub epoch: FpVar<F>,
    pub path: MerklePathVar<F, HEIGHT>,
}

impl<F: PrimeField, const HEIGHT: usize> AllocVar<RangeWitness<F, HEIGHT>, F>
    for RangeWitnessVar<F, HEIGHT>
{
    fn new_variable<T: Borrow<RangeWitness<F, HEIGHT>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let w = f()
            .map(|w| w.borrow().clone())
            .unwrap_or_else(|_| RangeWitness::<F, HEIGHT>::default());
        Ok(Self {
            lo: FpVar::new_variable(cs.clone(), || Ok(w.lo), mode)?,
            hi: FpVar::new_variable(cs.clone(), || Ok(w.hi), mode)?,
            epoch: FpVar::new_variable(cs.clone(), || Ok(w.epoch), mode)?,
            path: MerklePathVar::new_variable(cs.clone(), || Ok(w.path.clone()), mode)?,
        })
    }
}

/// Prove a ticket is a *nonmember* of the callback bulletin: it lies in a range
/// `[lo, hi)` whose leaf `H(lo, hi, epoch)` is in the range tree at `root`.
///
/// Returns true iff both hold. The caller (`enforce_nonmembership_of`) supplies
/// `root` as the **current epoch's** public-input root — that pinning is what
/// makes a stale range fail (see the module docs).
pub fn enforce_range_nonmembership<F: PrimeField + Absorb, const HEIGHT: usize>(
    tik: &FpVar<F>,
    witness: &RangeWitnessVar<F, HEIGHT>,
    root: &FpVar<F>,
) -> Result<Boolean<F>, SynthesisError> {
    // lo <= tik  (>= with equality)
    let ge_lo = tik.is_cmp_unchecked(&witness.lo, Ordering::Greater, true)?;
    // tik < hi   (strict)
    let lt_hi = tik.is_cmp_unchecked(&witness.hi, Ordering::Less, false)?;
    let in_range = ge_lo & lt_hi;

    let leaf = <Poseidon<2>>::hash_in_zk(&[
        witness.lo.clone(),
        witness.hi.clone(),
        witness.epoch.clone(),
    ])?;
    let root_ok = enforce_merkle_membership::<F, HEIGHT>(&leaf, &witness.path, root)?;

    Ok(in_range & root_ok)
}

/// The serverless callback bulletin: a membership tree over called tickets plus a
/// sorted-range nonmembership tree, rebuilt each epoch.
#[derive(Clone, Debug)]
pub struct MerkleCallbackStore<
    F: PrimeField + Absorb,
    const MH: usize = DEFAULT_CB_MEMB_HEIGHT,
    const NH: usize = DEFAULT_CB_NMEMB_HEIGHT,
> {
    /// Membership tree over called tickets; leaf `H(tik, arg, time)`.
    memb_tree: IncrementalMerkleTree<F, MH>,
    /// Called `(ticket, arg, time)` in append order, parallel to `memb_tree` leaves.
    called: Vec<(FakeSigPubkey<F>, F, Time<F>)>,
    /// Current epoch (the nonmembership checkpoint counter).
    epoch: F,
    /// Current complement ranges (sorted), parallel to `nmemb_tree` leaves.
    ranges: Vec<(F, F)>,
    /// Nonmembership tree over the current epoch's range leaves.
    nmemb_tree: IncrementalMerkleTree<F, NH>,
}

impl<F: PrimeField + Absorb, const MH: usize, const NH: usize> Default
    for MerkleCallbackStore<F, MH, NH>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField + Absorb, const MH: usize, const NH: usize> MerkleCallbackStore<F, MH, NH> {
    /// A fresh callback bulletin at epoch 0: no called tickets, and a single
    /// nonmembership range `[0, top)` covering the whole ticket domain.
    pub fn new() -> Self {
        let mut store = Self {
            memb_tree: IncrementalMerkleTree::new(),
            called: Vec::new(),
            epoch: F::ZERO,
            ranges: Vec::new(),
            nmemb_tree: IncrementalMerkleTree::new(),
        };
        store.rebuild_ranges();
        store
    }

    /// The membership (called-ticket) root — the public data for `enforce_membership_of`.
    pub fn memb_root(&self) -> F {
        self.memb_tree.root()
    }

    /// The nonmembership (range) root — the public data for `enforce_nonmembership_of`.
    pub fn nmemb_root(&self) -> F {
        self.nmemb_tree.root()
    }

    /// The current epoch.
    pub fn epoch(&self) -> F {
        self.epoch
    }

    /// Number of called tickets recorded.
    pub fn num_called(&self) -> usize {
        self.called.len()
    }

    /// Whether `tik` has never been called (the append guard).
    pub fn has_never_received_tik(&self, tik: &FakeSigPubkey<F>) -> bool {
        !self.called.iter().any(|(t, _, _)| t.to() == tik.to())
    }

    /// Record a called ticket: append `H(tik, arg, time)` to the membership tree.
    ///
    /// This does **not** touch the nonmembership tree — the range partition is
    /// only recomputed at [`Self::update_epoch`], exactly as in the reference
    /// store, so nonmembership proofs stay valid within an epoch.
    pub fn append_called(&mut self, tik: FakeSigPubkey<F>, arg: F, time: Time<F>) {
        self.memb_tree.append(memb_leaf(tik.to(), arg, time));
        self.called.push((tik, arg, time));
    }

    /// Step the epoch and rebuild the nonmembership range tree from the current
    /// called set. Every nonmembership proof must be regenerated afterward
    /// (their root changed) — that regeneration is the O10 barrier.
    pub fn update_epoch(&mut self) {
        self.epoch += F::ONE;
        self.rebuild_ranges();
    }

    /// (Re)build `ranges` and `nmemb_tree` as the sorted complement of the called
    /// set under the current epoch. Mirrors `SigRangeStore::update_epoch`.
    fn rebuild_ranges(&mut self) {
        let top = ticket_domain_top::<F>();

        let mut called: Vec<F> = self.called.iter().map(|(t, _, _)| t.to()).collect();
        called.sort();

        let mut ranges: Vec<(F, F)> = Vec::new();
        let mut bot = F::ZERO;
        for t in called {
            if bot != t {
                ranges.push((bot, t));
            }
            bot = t + F::ONE;
        }
        if bot != F::ZERO {
            ranges.push((bot, top));
        }
        // Empty called set (or the pathological all-consumed case): one full range.
        if ranges.is_empty() {
            ranges.push((F::ZERO, top));
        }

        let mut tree = IncrementalMerkleTree::<F, NH>::new();
        for &(lo, hi) in &ranges {
            tree.append(range_leaf(lo, hi, self.epoch));
        }
        self.ranges = ranges;
        self.nmemb_tree = tree;
    }

    /// Native membership witness for a called ticket, or `None` if not called.
    fn memb_witness(&self, tik: &FakeSigPubkey<F>) -> Option<MerklePath<F, MH>> {
        let i = self
            .called
            .iter()
            .position(|(t, _, _)| t.to() == tik.to())?;
        self.memb_tree.path(i)
    }

    /// Native nonmembership witness for a ticket, or `None` if it is called (a
    /// member) or somehow uncovered.
    fn nmemb_witness(&self, tik: &FakeSigPubkey<F>) -> Option<RangeWitness<F, NH>> {
        let t = tik.to();
        let i = self.ranges.iter().position(|&(lo, hi)| lo <= t && t < hi)?;
        let path = self.nmemb_tree.path(i)?;
        let (lo, hi) = self.ranges[i];
        Some(RangeWitness {
            lo,
            hi,
            epoch: self.epoch,
            path,
        })
    }
}

impl<F: PrimeField + Absorb, const MH: usize, const NH: usize> PublicCallbackBul<F, F, NoSigOTP<F>>
    for MerkleCallbackStore<F, MH, NH>
where
    Standard: Distribution<F>,
{
    type MembershipWitness = MerklePath<F, MH>;
    type MembershipWitnessVar = MerklePathVar<F, MH>;
    type NonMembershipWitness = RangeWitness<F, NH>;
    type NonMembershipWitnessVar = RangeWitnessVar<F, NH>;

    /// Both roots are field elements fed in as public inputs.
    type MembershipPub = F;
    type MembershipPubVar = FpVar<F>;
    type NonMembershipPub = F;
    type NonMembershipPubVar = FpVar<F>;

    fn verify_in(&self, tik: FakeSigPubkey<F>) -> Option<(F, (), Time<F>)> {
        self.called
            .iter()
            .find(|(t, _, _)| t.to() == tik.to())
            .map(|(_, arg, time)| (*arg, (), *time))
    }

    fn verify_not_in(&self, tik: FakeSigPubkey<F>) -> bool {
        let t = tik.to();
        self.ranges.iter().any(|&(lo, hi)| lo <= t && t < hi)
    }

    fn get_membership_data(
        &self,
        tik: FakeSigPubkey<F>,
    ) -> (
        Self::MembershipPub,
        Self::MembershipWitness,
        Self::NonMembershipPub,
        Self::NonMembershipWitness,
    ) {
        match self.memb_witness(&tik) {
            // Called: real membership witness, default (unused) nonmembership witness.
            Some(path) => (
                self.memb_root(),
                path,
                self.nmemb_root(),
                RangeWitness::default(),
            ),
            // Not called: default (unused) membership witness, real nonmembership witness.
            None => (
                self.memb_root(),
                MerklePath::default(),
                self.nmemb_root(),
                self.nmemb_witness(&tik).expect(
                    "callback bulletin inconsistent: ticket is neither called nor in any range",
                ),
            ),
        }
    }

    fn enforce_membership_of(
        tikvar: (FakeSigPubkeyVar<F>, FpVar<F>, TimeVar<F>),
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        // Leaf = H(tik, arg, time), matching `append_called` / the reference store.
        let leaf = <Poseidon<2>>::hash_in_zk(&[tikvar.0.0, tikvar.1, tikvar.2])?;
        enforce_merkle_membership::<F, MH>(&leaf, &extra_witness, &extra_pub)
    }

    fn enforce_nonmembership_of(
        tikvar: FakeSigPubkeyVar<F>,
        extra_witness: Self::NonMembershipWitnessVar,
        extra_pub: Self::NonMembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        enforce_range_nonmembership::<F, NH>(&tikvar.0, &extra_witness, &extra_pub)
    }
}

impl<F: PrimeField + Absorb, const MH: usize, const NH: usize> CallbackBul<F, F, NoSigOTP<F>>
    for MerkleCallbackStore<F, MH, NH>
where
    Standard: Distribution<F>,
{
    type Error = ();

    fn has_never_received_tik(&self, tik: &FakeSigPubkey<F>) -> bool {
        MerkleCallbackStore::has_never_received_tik(self, tik)
    }

    fn append_value(
        &mut self,
        tik: FakeSigPubkey<F>,
        enc_args: F,
        _signature: (),
        time: Time<F>,
    ) -> Result<(), Self::Error> {
        self.append_called(tik, enc_args, time);
        Ok(())
    }
}

/// The empty-tree root at a given height — handy for tests and for a replica
/// initializing its pinned roots before ingesting anything.
pub fn empty_root<F: PrimeField + Absorb>(height: usize) -> F {
    let mut z = F::zero();
    for _ in 0..height {
        z = hash_pair(z, z);
    }
    z
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr as F;
    use ark_r1cs_std::{R1CSVar, alloc::AllocVar, eq::EqGadget};
    use ark_relations::r1cs::ConstraintSystem;

    const MH: usize = 6;
    const NH: usize = 6;
    type Store = MerkleCallbackStore<F, MH, NH>;

    fn tik(x: u64) -> FakeSigPubkey<F> {
        FakeSigPubkey::new(F::from(x))
    }

    /// Every non-called ticket falls in exactly one range whose witness
    /// recomputes the current nonmembership root; every called ticket falls in
    /// none.
    #[test]
    fn ranges_partition_the_complement() {
        let mut store = Store::new();
        for t in [10u64, 20, 30] {
            store.append_called(tik(t), F::from(1), F::from(0));
        }
        store.update_epoch();

        let root = store.nmemb_root();
        // Non-called tickets are nonmembers with a valid witness.
        for t in [0u64, 9, 11, 21, 31, 1000] {
            assert!(store.verify_not_in(tik(t)), "{t} should be a nonmember");
            let w = store.nmemb_witness(&tik(t)).unwrap();
            assert!(w.is_in_range(F::from(t)));
            assert_eq!(w.compute_root(), root, "{t} witness must reach nmemb root");
        }
        // Called tickets are members: no covering range.
        for t in [10u64, 20, 30] {
            assert!(!store.verify_not_in(tik(t)), "{t} should be a member");
            assert!(store.nmemb_witness(&tik(t)).is_none());
        }
    }

    /// A called ticket has a membership witness that reaches the membership root.
    #[test]
    fn called_tickets_have_membership_witnesses() {
        let mut store = Store::new();
        store.append_called(tik(42), F::from(7), F::from(3));
        store.append_called(tik(43), F::from(8), F::from(4));
        let root = store.memb_root();
        for (t, a, ti) in [(42u64, 7u64, 3u64), (43, 8, 4)] {
            let path = store.memb_witness(&tik(t)).unwrap();
            let leaf = memb_leaf(F::from(t), F::from(a), F::from(ti));
            assert_eq!(path.compute_root(leaf), root);
        }
        assert_eq!(store.verify_in(tik(42)), Some((F::from(7), (), F::from(3))));
        assert_eq!(store.verify_in(tik(999)), None);
    }

    /// The nonmembership gadget accepts a real nonmember and produces a satisfied
    /// constraint system.
    #[test]
    fn nmemb_gadget_accepts_nonmember() {
        let mut store = Store::new();
        store.append_called(tik(50), F::from(1), F::from(0));
        store.update_epoch();
        let root = store.nmemb_root();

        for t in [0u64, 49, 51, 200] {
            let w = store.nmemb_witness(&tik(t)).unwrap();
            let cs = ConstraintSystem::<F>::new_ref();
            let tik_var = FpVar::new_witness(cs.clone(), || Ok(F::from(t))).unwrap();
            let w_var = RangeWitnessVar::<F, NH>::new_witness(cs.clone(), || Ok(w)).unwrap();
            let root_var = FpVar::new_input(cs.clone(), || Ok(root)).unwrap();
            let is_nonmember =
                enforce_range_nonmembership::<F, NH>(&tik_var, &w_var, &root_var).unwrap();
            is_nonmember.enforce_equal(&Boolean::TRUE).unwrap();
            assert!(cs.is_satisfied().unwrap(), "nonmember {t}: cs satisfied");
            assert!(is_nonmember.value().unwrap());
        }
    }

    /// The exact O10 scenario: a member (called ticket) presenting a *pre-ban*
    /// range witness fails, because that range's leaf hashes to the *old* epoch
    /// root, not the current pinned one.
    #[test]
    fn nmemb_gadget_rejects_stale_range_after_ban() {
        let mut store = Store::new();
        // Epoch 1: ticket 77 is not yet called; grab its (soon to be stale) range.
        store.update_epoch();
        let stale_witness = store.nmemb_witness(&tik(77)).unwrap();

        // Ticket 77 is called (a ban), epoch advances, nmemb root re-pins.
        store.append_called(tik(77), F::from(BAN), F::from(0));
        store.update_epoch();
        let current_root = store.nmemb_root();

        // 77 is now a member — no current range covers it.
        assert!(!store.verify_not_in(tik(77)));
        assert!(store.nmemb_witness(&tik(77)).is_none());

        // Replaying the pre-ban range against the CURRENT root fails in-circuit.
        let cs = ConstraintSystem::<F>::new_ref();
        let tik_var = FpVar::new_witness(cs.clone(), || Ok(F::from(77))).unwrap();
        let w_var =
            RangeWitnessVar::<F, NH>::new_witness(cs.clone(), || Ok(stale_witness)).unwrap();
        let root_var = FpVar::new_input(cs.clone(), || Ok(current_root)).unwrap();
        let is_nonmember =
            enforce_range_nonmembership::<F, NH>(&tik_var, &w_var, &root_var).unwrap();
        assert!(
            !is_nonmember.value().unwrap(),
            "stale pre-ban range must not verify against the current epoch root (O10)"
        );
    }

    /// A ticket outside its claimed range fails the range check even with a valid
    /// path (you cannot borrow a neighbor's range).
    #[test]
    fn nmemb_gadget_rejects_out_of_range() {
        let mut store = Store::new();
        store.append_called(tik(100), F::from(1), F::from(0));
        store.update_epoch();
        let root = store.nmemb_root();

        // Range covering 0..100; try to use it for ticket 150 (which lives in a
        // different range).
        let w = store.nmemb_witness(&tik(50)).unwrap();
        assert!(w.lo <= F::from(50) && F::from(50) < w.hi);
        assert!(!(w.lo <= F::from(150) && F::from(150) < w.hi));

        let cs = ConstraintSystem::<F>::new_ref();
        let tik_var = FpVar::new_witness(cs.clone(), || Ok(F::from(150))).unwrap();
        let w_var = RangeWitnessVar::<F, NH>::new_witness(cs.clone(), || Ok(w)).unwrap();
        let root_var = FpVar::new_input(cs.clone(), || Ok(root)).unwrap();
        let is_nonmember =
            enforce_range_nonmembership::<F, NH>(&tik_var, &w_var, &root_var).unwrap();
        assert!(!is_nonmember.value().unwrap());
    }

    /// Two replicas fed the same called tickets and epoch bumps agree on both roots.
    #[test]
    fn replicas_converge() {
        let mut a = Store::new();
        let mut b = Store::new();
        for t in [3u64, 1, 2] {
            a.append_called(tik(t), F::from(1), F::from(0));
        }
        // b ingests in a different arrival order — the sorted range rebuild and
        // the (order-sensitive) membership tree must still converge given the
        // same final set... so feed the membership tree the same order.
        for t in [3u64, 1, 2] {
            b.append_called(tik(t), F::from(1), F::from(0));
        }
        a.update_epoch();
        b.update_epoch();
        assert_eq!(a.memb_root(), b.memb_root());
        assert_eq!(a.nmemb_root(), b.nmemb_root());
    }

    pub const BAN: u64 = 999_999_999;
}
