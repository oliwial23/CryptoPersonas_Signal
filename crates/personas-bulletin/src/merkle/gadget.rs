//! The in-circuit half of the object bulletin: an R1CS gadget that recomputes a
//! Merkle root from a leaf and its path, mirroring [`super::tree`] exactly.
//!
//! [`enforce_merkle_membership`] is what a `PublicUserBul::enforce_membership_of`
//! implementation delegates to. It takes the leaf, the allocated path witness,
//! and a root variable — the caller decides whether that root is a circuit
//! *constant* (baked at key-generation, valid for one fixed tree) or a *public
//! input* (supplied per proof, valid across appends). Because a serverless
//! object tree grows on every registration, the root is always a public input
//! in this system; the gadget is agnostic to that choice.

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    select::CondSelectGadget,
};
use ark_relations::r1cs::{Namespace, SynthesisError};
use std::borrow::Borrow;
use zk_callbacks::{crypto::hash::HasherZK, impls::hash::Poseidon};

use super::tree::MerklePath;

/// The in-circuit representation of a [`MerklePath`].
///
/// The `leaf_index` is carried as its `HEIGHT` bits directly (bit `l` set ⇒ the
/// node at level `l` is a right child), and the `siblings` as field variables.
/// Both vectors always have length `HEIGHT`, so the constraint count is fixed
/// per circuit — the property key-generation relies on.
#[derive(Clone)]
pub struct MerklePathVar<F: PrimeField, const HEIGHT: usize> {
    /// Low `HEIGHT` bits of the leaf index, LSB first.
    pub index_bits: Vec<Boolean<F>>,
    /// Sibling variables, bottom to top. Length `HEIGHT`.
    pub siblings: Vec<FpVar<F>>,
}

impl<F: PrimeField, const HEIGHT: usize> AllocVar<MerklePath<F, HEIGHT>, F>
    for MerklePathVar<F, HEIGHT>
{
    fn new_variable<T: Borrow<MerklePath<F, HEIGHT>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();

        // Mirror the reference stores' AllocVar pattern: if the value function
        // errors (as it does during key-generation setup), fall back to the
        // default witness so the circuit still synthesizes with a fixed shape.
        let path = res
            .map(|p| p.borrow().clone())
            .unwrap_or_else(|_| MerklePath::<F, HEIGHT>::default());

        let mut index_bits = Vec::with_capacity(HEIGHT);
        for l in 0..HEIGHT {
            let bit = (path.leaf_index >> l) & 1 == 1;
            index_bits.push(Boolean::new_variable(cs.clone(), || Ok(bit), mode)?);
        }

        let mut siblings = Vec::with_capacity(HEIGHT);
        for l in 0..HEIGHT {
            let s = path.siblings.get(l).copied().unwrap_or_else(F::zero);
            siblings.push(FpVar::new_variable(cs.clone(), || Ok(s), mode)?);
        }

        Ok(Self {
            index_bits,
            siblings,
        })
    }
}

/// Recompute the Merkle root from `leaf` and `path` in-circuit and return a
/// boolean that is true iff it equals `root`.
///
/// This is the constraint-level twin of [`MerklePath::compute_root`]: at each
/// level it orders `(current, sibling)` into `(left, right)` by the index bit
/// and hashes them with the system Poseidon. The final hash is compared to the
/// supplied root.
///
/// Soundness rests on Poseidon collision resistance (the standard Merkle
/// argument): a leaf that is not in the tree cannot be hashed up to the root
/// without a second preimage. Note the gadget does *not* pin the leaf to a
/// specific position — any valid path proves the leaf is *somewhere* in the
/// tree, which is exactly what object membership requires.
pub fn enforce_merkle_membership<F: PrimeField + Absorb, const HEIGHT: usize>(
    leaf: &FpVar<F>,
    path: &MerklePathVar<F, HEIGHT>,
    root: &FpVar<F>,
) -> Result<Boolean<F>, SynthesisError> {
    debug_assert_eq!(path.index_bits.len(), HEIGHT);
    debug_assert_eq!(path.siblings.len(), HEIGHT);

    let mut cur = leaf.clone();
    for l in 0..HEIGHT {
        let is_right = &path.index_bits[l];
        let sib = &path.siblings[l];
        // is_right ? (sib, cur) : (cur, sib)
        let left = FpVar::conditionally_select(is_right, sib, &cur)?;
        let right = FpVar::conditionally_select(is_right, &cur, sib)?;
        cur = <Poseidon<2>>::hash_in_zk(&[left, right])?;
    }
    cur.is_eq(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::tree::IncrementalMerkleTree;
    use ark_bn254::Fr as F;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;

    const H: usize = 6;

    /// Build a tree, allocate a real leaf/path/root, and assert the gadget both
    /// reports membership (the returned boolean is true) and produces a fully
    /// satisfied constraint system — and that the value it computes equals the
    /// native root.
    #[test]
    fn gadget_accepts_a_real_member_and_matches_native() {
        let mut tree = IncrementalMerkleTree::<F, H>::new();
        let leaves: Vec<F> = (1u64..=13).map(F::from).collect();
        for &l in &leaves {
            tree.append(l);
        }
        let root = tree.root();

        for (i, &leaf) in leaves.iter().enumerate() {
            let path = tree.path(i).unwrap();
            assert_eq!(path.compute_root(leaf), root);

            let cs = ConstraintSystem::<F>::new_ref();
            let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
            let path_var =
                MerklePathVar::<F, H>::new_witness(cs.clone(), || Ok(path.clone())).unwrap();
            // Root as a public input, the serverless configuration.
            let root_var = FpVar::new_input(cs.clone(), || Ok(root)).unwrap();

            let is_member =
                enforce_merkle_membership::<F, H>(&leaf_var, &path_var, &root_var).unwrap();
            is_member.enforce_equal(&Boolean::TRUE).unwrap();

            assert!(
                cs.is_satisfied().unwrap(),
                "member {i}: cs must be satisfied"
            );
            assert!(
                is_member.value().unwrap(),
                "member {i}: gadget must report true"
            );
        }
    }

    /// A non-member leaf makes the membership boolean false; forcing it true
    /// makes the system unsatisfiable.
    #[test]
    fn gadget_rejects_a_non_member() {
        let mut tree = IncrementalMerkleTree::<F, H>::new();
        for l in 1u64..=8 {
            tree.append(F::from(l));
        }
        let root = tree.root();
        // Borrow leaf 3's path but claim a leaf value that was never inserted.
        let path = tree.path(3).unwrap();
        let bogus_leaf = F::from(4242);

        let cs = ConstraintSystem::<F>::new_ref();
        let leaf_var = FpVar::new_witness(cs.clone(), || Ok(bogus_leaf)).unwrap();
        let path_var = MerklePathVar::<F, H>::new_witness(cs.clone(), || Ok(path)).unwrap();
        let root_var = FpVar::new_input(cs.clone(), || Ok(root)).unwrap();

        let is_member = enforce_merkle_membership::<F, H>(&leaf_var, &path_var, &root_var).unwrap();
        assert!(
            !is_member.value().unwrap(),
            "bogus leaf must not be a member"
        );

        // Constraining membership to hold for a non-member is unsatisfiable.
        is_member.enforce_equal(&Boolean::TRUE).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    /// A stale root (from before an append) is rejected when supplied as the
    /// current public-input root for a freshly-fetched path — the anti-replay
    /// property a replica leans on when it pins the current root.
    #[test]
    fn gadget_rejects_a_stale_root_against_a_current_path() {
        let mut tree = IncrementalMerkleTree::<F, H>::new();
        tree.append(F::from(100));
        let stale_root = tree.root();
        tree.append(F::from(101));
        let current_root = tree.root();
        assert_ne!(stale_root, current_root);

        let leaf = F::from(100);
        let path = tree.path(0).unwrap(); // path against the CURRENT tree

        let cs = ConstraintSystem::<F>::new_ref();
        let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
        let path_var = MerklePathVar::<F, H>::new_witness(cs.clone(), || Ok(path)).unwrap();
        let root_var = FpVar::new_input(cs.clone(), || Ok(stale_root)).unwrap();

        let is_member = enforce_merkle_membership::<F, H>(&leaf_var, &path_var, &root_var).unwrap();
        assert!(
            !is_member.value().unwrap(),
            "current path must not verify against a stale root"
        );
    }
}
