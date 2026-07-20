//! [`MerkleObjStore`] — the serverless object (user) bulletin.
//!
//! This is the Merkle-tree replacement for zk-callbacks' signature-based
//! [`SigObjStore`]. Where the centralized store proves membership with a server
//! signature over each commitment (`MembershipWitness = Sig`,
//! `MembershipPub = pubkey`), the serverless store proves membership with a
//! Merkle path (`MembershipWitness = MerklePath`, `MembershipPub = root`). There
//! is no key, so nothing to sign and nothing to rotate.
//!
//! [`SigObjStore`]: zk_callbacks::impls::centralized::ds::sigstore::SigObjStore
//!
//! # Set-committing, not append-order
//!
//! The store commits to the **set** of registered objects, not the order they
//! arrived: leaves are the object commitments held in a `BTreeMap` (sorted by
//! commitment) and the tree is rebuilt over that sorted order on every
//! registration. So the root is a pure function of the set — any two replicas
//! that have ingested the same registrations compute the identical root
//! *regardless of arrival order*. This mirrors the sorted-range nonmembership
//! tree ([`super::callback`]) and is what lets the replica engine (d3) drop the
//! per-record total ordering it would otherwise need to make an append-only tree
//! converge. (The remaining ordering — which of two records spending the *same*
//! nullifier wins — is not a tree property; it is the first-reveal-wins rule the
//! nullifier set enforces, see [`Self::has_seen_nul`].)
//!
//! The cost of set-committing is that a registration reshuffles indices, so the
//! rebuild is `O(n · HEIGHT)` rather than an append's `O(HEIGHT)`. That is fine
//! at demo scale and is the natural home for the future Bloom-filter
//! reconciliation (a proof advertises *which* recent records its tree includes,
//! and a verifier reconstructs that exact set — only possible because the root is
//! set-determined). See `docs/SERVERLESS_PROTOCOL.md` §5.
//!
//! # Root: constant vs. public input
//!
//! Because the root changes on every registration it cannot be baked into a
//! proving key as a circuit constant. Merkle-mode key-generation therefore passes
//! `memb_data = None`, making the root a **public input** the verifier supplies
//! per proof and pins against a root it computed itself.

use std::collections::BTreeMap;

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::Boolean;
use ark_relations::r1cs::SynthesisError;
use ark_snark::SNARK;
use zk_callbacks::generic::{
    bulletin::{JoinableBulletin, PublicUserBul, UserBul},
    object::{Com, ComVar, Nul},
    user::UserData,
};

use super::gadget::{MerklePathVar, enforce_merkle_membership};
use super::tree::{IncrementalMerkleTree, MerklePath};

/// The default height of the serverless object tree.
///
/// `2^32` registration slots — far more than any messaging group — while the
/// in-circuit membership cost is only 32 Poseidon rounds. Tests use small
/// heights via the const generic; production wires this default.
pub const DEFAULT_OBJ_HEIGHT: usize = 32;

/// The per-object data the store keeps beside its commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ObjEntry<F: PrimeField> {
    /// The old nullifier this object consumed.
    old_nul: Nul<F>,
    /// The callback commitments this object issued.
    cb_com_list: Vec<Com<F>>,
}

/// A set-committing Merkle object bulletin.
///
/// The registered objects live in `entries`, keyed and ordered by commitment; the
/// `tree` is rebuilt over that sorted order so its root commits to the *set*. The
/// `nuls` list backs [`Self::has_seen_nul`] / [`UserBul::has_never_received_nul`],
/// which is what actually blocks a rewind (a stale membership root is harmless on
/// its own — see [`super::tree`]).
#[derive(Clone, Debug)]
pub struct MerkleObjStore<F: PrimeField + Absorb, const HEIGHT: usize = DEFAULT_OBJ_HEIGHT> {
    /// Registered objects, keyed and sorted by commitment.
    entries: BTreeMap<Com<F>, ObjEntry<F>>,
    /// The Merkle tree over the sorted commitments; rebuilt when `entries` changes.
    tree: IncrementalMerkleTree<F, HEIGHT>,
    /// Every nullifier ever consumed, in registration order. A nullifier that
    /// appears here has been spent; a second reveal is refused (first-reveal-wins).
    nuls: Vec<Nul<F>>,
}

impl<F: PrimeField + Absorb, const HEIGHT: usize> Default for MerkleObjStore<F, HEIGHT> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField + Absorb, const HEIGHT: usize> MerkleObjStore<F, HEIGHT> {
    /// An empty object bulletin.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            tree: IncrementalMerkleTree::new(),
            nuls: Vec::new(),
        }
    }

    /// The current Merkle root — the public membership data, a function of the set.
    pub fn root(&self) -> F {
        self.tree.root()
    }

    /// Number of registered objects.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no objects have been registered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `nul` has already been consumed — the double-spend / rewind guard.
    ///
    /// This is the whole of first-reveal-wins: the first record to reveal a
    /// nullifier registers its successor object; any later record revealing the
    /// same nullifier (a member rewinding to a stale state, or double-spending)
    /// finds it here and is refused, so its successor is never registered and can
    /// never be built upon. Nullifiers are high-entropy and object-unique, so two
    /// *distinct* members never collide — a collision is always self-inflicted.
    pub fn has_seen_nul(&self, nul: &Nul<F>) -> bool {
        self.nuls.contains(nul)
    }

    /// Register an object with its consumed nullifier and issued callback coms.
    ///
    /// Inserts into the sorted set and rebuilds the tree, so the root re-commits to
    /// the new set. Re-registering an existing commitment updates its data without
    /// double-counting its nullifier (in practice commitments are unique). The
    /// low-level primitive shared by [`UserBul::append_value`] and
    /// [`JoinableBulletin::join_bul`].
    pub fn push(&mut self, object: Com<F>, old_nul: Nul<F>, cb_com_list: Vec<Com<F>>) {
        let is_new = self
            .entries
            .insert(
                object,
                ObjEntry {
                    old_nul,
                    cb_com_list,
                },
            )
            .is_none();
        if is_new {
            self.nuls.push(old_nul);
        }
        self.rebuild();
    }

    /// Rebuild the tree over the current sorted commitment set.
    fn rebuild(&mut self) {
        let mut tree = IncrementalMerkleTree::new();
        for com in self.entries.keys() {
            tree.append(*com);
        }
        self.tree = tree;
    }

    /// The sorted position of a registered commitment (its leaf index), or `None`.
    fn position(&self, object: Com<F>) -> Option<usize> {
        self.entries.keys().position(|c| *c == object)
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>, const HEIGHT: usize> PublicUserBul<F, U>
    for MerkleObjStore<F, HEIGHT>
{
    type MembershipWitness = MerklePath<F, HEIGHT>;
    type MembershipWitnessVar = MerklePathVar<F, HEIGHT>;
    /// The Merkle root. `F: ToConstraintField<F>` feeds it in as a public input.
    type MembershipPub = F;
    type MembershipPubVar = ark_r1cs_std::fields::fp::FpVar<F>;

    fn verify_in<PubArgs, Snark: SNARK<F>, const NUMCBS: usize>(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        _args: PubArgs,
        _proof: Snark::Proof,
        _memb_data: Self::MembershipPub,
        _verif_key: &Snark::VerifyingKey,
    ) -> bool {
        match self.entries.get(&object) {
            Some(e) => e.old_nul == old_nul && e.cb_com_list == cb_com_list.to_vec(),
            None => false,
        }
    }

    fn get_membership_data(
        &self,
        object: Com<F>,
    ) -> Option<(Self::MembershipPub, Self::MembershipWitness)> {
        let i = self.position(object)?;
        let path = self.tree.path(i)?;
        Some((self.tree.root(), path))
    }

    fn enforce_membership_of(
        data_var: ComVar<F>,
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        enforce_merkle_membership::<F, HEIGHT>(&data_var, &extra_witness, &extra_pub)
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>, const HEIGHT: usize> UserBul<F, U>
    for MerkleObjStore<F, HEIGHT>
{
    type Error = ();

    fn has_never_received_nul(&self, nul: &Nul<F>) -> bool {
        !self.has_seen_nul(nul)
    }

    fn append_value<PubArgs, Snark: SNARK<F>, const NUMCBS: usize>(
        &mut self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        _args: PubArgs,
        _proof: Snark::Proof,
        _memb_data: Option<Self::MembershipPub>,
        _verif_key: &Snark::VerifyingKey,
    ) -> Result<(), Self::Error> {
        self.push(object, old_nul, cb_com_list.to_vec());
        Ok(())
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>, const HEIGHT: usize> JoinableBulletin<F, U>
    for MerkleObjStore<F, HEIGHT>
{
    /// A join supplies the object's initial nullifier deterministically.
    ///
    /// Unlike the centralized [`SigObjStore`], which samples a random nullifier
    /// on join, the serverless store takes it as data so every replica registers
    /// an identical object/nullifier pair — determinism is a hard requirement for
    /// convergent replicas.
    ///
    /// [`SigObjStore`]: zk_callbacks::impls::centralized::ds::sigstore::SigObjStore
    type PubData = Nul<F>;

    fn join_bul(&mut self, object: Com<F>, old_nul: Self::PubData) -> Result<(), Self::Error> {
        self.push(object, old_nul, Vec::new());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr as F;
    use personas_core::circuits::MsgUser;

    const H: usize = 8;
    type Store = MerkleObjStore<F, H>;

    // The store is generic over `U: UserData<F>` and never inspects it; `MsgUser`
    // is the system's real user-data type and stands in at the bulletin level.
    type U = MsgUser;

    fn nul(x: u64) -> F {
        F::from(1_000_000 + x)
    }

    #[test]
    fn membership_data_round_trips_against_the_root() {
        let mut store = Store::new();
        let coms: Vec<F> = (1u64..=10).map(F::from).collect();
        for (k, &c) in coms.iter().enumerate() {
            store.push(c, nul(k as u64), vec![]);
        }
        let root = store.root();
        for &c in &coms {
            let (pub_root, path) =
                <Store as PublicUserBul<F, U>>::get_membership_data(&store, c).unwrap();
            assert_eq!(pub_root, root);
            assert_eq!(path.compute_root(c), root);
        }
        // A commitment that was never registered has no membership data.
        assert!(
            <Store as PublicUserBul<F, U>>::get_membership_data(&store, F::from(99999)).is_none()
        );
    }

    #[test]
    fn verify_in_matches_stored_nul_and_cblist() {
        let mut store = Store::new();
        let cbs = vec![F::from(7), F::from(8)];
        store.push(F::from(42), nul(0), cbs.clone());
        let root = store.root();

        // Correct object + nul + cb list verifies.
        assert!(
            <Store as PublicUserBul<F, U>>::verify_in::<(), DummyGroth, 2>(
                &store,
                F::from(42),
                nul(0),
                [F::from(7), F::from(8)],
                (),
                (),
                root,
                &(),
            )
        );
        // Wrong nullifier fails.
        assert!(!<Store as PublicUserBul<F, U>>::verify_in::<
            (),
            DummyGroth,
            2,
        >(
            &store,
            F::from(42),
            nul(1),
            [F::from(7), F::from(8)],
            (),
            (),
            root,
            &(),
        ));
        // Wrong callback list fails.
        assert!(!<Store as PublicUserBul<F, U>>::verify_in::<
            (),
            DummyGroth,
            2,
        >(
            &store,
            F::from(42),
            nul(0),
            [F::from(7), F::from(9)],
            (),
            (),
            root,
            &(),
        ));
    }

    #[test]
    fn nullifier_set_blocks_replay() {
        let mut store = Store::new();
        store.push(F::from(1), nul(0), vec![]);
        assert!(!<Store as UserBul<F, U>>::has_never_received_nul(
            &store,
            &nul(0)
        ));
        assert!(<Store as UserBul<F, U>>::has_never_received_nul(
            &store,
            &nul(1)
        ));
    }

    #[test]
    fn join_is_deterministic() {
        let mut a = Store::new();
        let mut b = Store::new();
        for k in 0..5u64 {
            <Store as JoinableBulletin<F, U>>::join_bul(&mut a, F::from(k), nul(k)).unwrap();
            <Store as JoinableBulletin<F, U>>::join_bul(&mut b, F::from(k), nul(k)).unwrap();
        }
        // Two replicas fed the same ordered joins agree on the root.
        assert_eq!(a.root(), b.root());
    }

    /// The root commits to the *set*, not the insertion order: the same objects
    /// registered in any order produce the same root, and every element still has
    /// a membership witness against it. This is the property that lets the replica
    /// engine converge without a per-record total order.
    #[test]
    fn root_is_a_function_of_the_set_not_insertion_order() {
        let coms: Vec<F> = (1u64..=6).map(F::from).collect();

        let build = |order: &[usize]| {
            let mut s = Store::new();
            for &i in order {
                s.push(coms[i], nul(i as u64), vec![]);
            }
            s
        };
        let ascending = build(&[0, 1, 2, 3, 4, 5]);
        let descending = build(&[5, 4, 3, 2, 1, 0]);
        let shuffled = build(&[3, 0, 5, 1, 4, 2]);

        assert_eq!(ascending.root(), descending.root());
        assert_eq!(ascending.root(), shuffled.root());

        // Membership still holds for every element against the shared root.
        let root = ascending.root();
        for &com in &coms {
            let (pub_root, path) =
                <Store as PublicUserBul<F, U>>::get_membership_data(&shuffled, com).unwrap();
            assert_eq!(pub_root, root);
            assert_eq!(path.compute_root(com), root);
        }
    }

    /// A stand-in SNARK type: `verify_in` never touches the proof or key, so the
    /// associated types only need to exist (they are all the unit type). The
    /// method bodies are unreachable — `verify_in`'s membership check is pure
    /// data-structure logic.
    type DummyGroth = UnitSnark;

    struct UnitSnark;
    impl SNARK<F> for UnitSnark {
        type ProvingKey = ();
        type VerifyingKey = ();
        type Proof = ();
        type ProcessedVerifyingKey = ();
        type Error = ark_relations::r1cs::SynthesisError;

        fn circuit_specific_setup<
            C: ark_relations::r1cs::ConstraintSynthesizer<F>,
            R: ark_std::rand::RngCore + ark_std::rand::CryptoRng,
        >(
            _: C,
            _: &mut R,
        ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error> {
            unreachable!("verify_in does not run setup")
        }
        fn prove<
            C: ark_relations::r1cs::ConstraintSynthesizer<F>,
            R: ark_std::rand::RngCore + ark_std::rand::CryptoRng,
        >(
            _: &Self::ProvingKey,
            _: C,
            _: &mut R,
        ) -> Result<Self::Proof, Self::Error> {
            unreachable!("verify_in does not prove")
        }
        fn process_vk(_: &Self::VerifyingKey) -> Result<Self::ProcessedVerifyingKey, Self::Error> {
            unreachable!()
        }
        fn verify_with_processed_vk(
            _: &Self::ProcessedVerifyingKey,
            _: &[F],
            _: &Self::Proof,
        ) -> Result<bool, Self::Error> {
            unreachable!()
        }
    }
}
