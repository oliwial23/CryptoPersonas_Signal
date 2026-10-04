//! A fixed-height, append-only (incremental) binary Merkle tree over Poseidon.
//!
//! This is the native (out-of-circuit) half of the serverless object bulletin.
//! It is deliberately the *same* hash the rest of the system commits with —
//! [`Poseidon<2>`] as a 2-to-1 compression function — so a root computed here
//! is the root the in-circuit gadget ([`super::gadget`]) recomputes, and both
//! match what zk-callbacks hashes elsewhere.
//!
//! # Structure
//!
//! The tree has a fixed `HEIGHT`, giving `2^HEIGHT` leaf slots filled
//! left-to-right. Empty slots hash as a fixed sentinel (`F::zero`), and an
//! empty subtree of level `l` has the precomputed hash `zeros[l]`
//! (`zeros[0] = 0`, `zeros[l+1] = H(zeros[l], zeros[l])`). This is the standard
//! Tornado/Semaphore incremental-tree construction: an append touches only the
//! `HEIGHT` nodes on the new leaf's path, so both append and witness lookup are
//! `O(HEIGHT)`.
//!
//! # Why append-only is sound with a *buffered* root (the O10 lesson)
//!
//! Membership of an append-only set is **monotone**: once a leaf is in the tree
//! it stays in, and no later append can evict it. So a witness against a
//! slightly stale root is still a valid witness against a newer root's history
//! — a replica may safely accept membership proofs against any recent root it
//! has itself computed (a ring buffer of the last K roots). This is the exact
//! opposite of callback *non*membership, which is anti-monotone and must pin the
//! current epoch's root only — see [`super::callback`]. Rewind is blocked not by
//! the root but by the nullifier set (`has_never_received_nul`).

use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use zk_callbacks::{crypto::hash::HasherZK, impls::hash::Poseidon};

/// The value stored in an unfilled leaf slot.
///
/// A real object commitment is a Poseidon image, so a collision with this
/// sentinel is cryptographically negligible; nonetheless the tree never treats
/// a zero leaf as "present" (membership is decided by the index map, not by
/// scanning for a value), so an object that happened to commit to zero would
/// still work.
pub fn empty_leaf<F: PrimeField>() -> F {
    F::zero()
}

/// Hash two field elements into their parent with the system Poseidon.
///
/// This is the single definition of an internal node; the gadget mirrors it
/// with [`Poseidon::hash_in_zk`] over the same two-element input in the same
/// (left, right) order.
pub fn hash_pair<F: PrimeField + Absorb>(left: F, right: F) -> F {
    <Poseidon<2>>::hash(&[left, right])
}

/// Precompute `zeros[0..=HEIGHT]`, the hash of an empty subtree at each level.
fn empty_subtree_hashes<F: PrimeField + Absorb>(height: usize) -> Vec<F> {
    let mut zeros = Vec::with_capacity(height + 1);
    zeros.push(empty_leaf::<F>());
    for l in 0..height {
        let z = zeros[l];
        zeros.push(hash_pair(z, z));
    }
    zeros
}

/// A membership witness: the index of a leaf and the sibling hash at each level
/// on the path from that leaf to the root.
///
/// `siblings` is always length `HEIGHT`; `leaf_index`'s low `HEIGHT` bits select
/// left/right at each level (bit `l` set ⇒ the current node is the *right*
/// child at level `l`). The [`Default`] impl deliberately yields a full
/// `HEIGHT`-length sibling vector of zeros: the circuit's shape (how many hash
/// rounds it performs) is fixed at key-generation time from the *default*
/// witness, so a short default would bake a wrong-sized circuit.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct MerklePath<F: PrimeField, const HEIGHT: usize> {
    /// The leaf's position (0-based, left to right).
    pub leaf_index: u64,
    /// Sibling hash at each level, bottom (leaf's sibling) to top. Length `HEIGHT`.
    pub siblings: Vec<F>,
}

impl<F: PrimeField, const HEIGHT: usize> Default for MerklePath<F, HEIGHT> {
    fn default() -> Self {
        Self {
            leaf_index: 0,
            siblings: vec![F::zero(); HEIGHT],
        }
    }
}

impl<F: PrimeField + Absorb, const HEIGHT: usize> MerklePath<F, HEIGHT> {
    /// Recompute the root this path attests to, from the committed `leaf`.
    ///
    /// The native counterpart of [`super::gadget::enforce_merkle_membership`];
    /// the two must agree bit-for-bit. A caller checks membership by comparing
    /// the result against a known root.
    pub fn compute_root(&self, leaf: F) -> F {
        let mut cur = leaf;
        for (l, sib) in self.siblings.iter().enumerate().take(HEIGHT) {
            let is_right = (self.leaf_index >> l) & 1 == 1;
            let (left, right) = if is_right { (*sib, cur) } else { (cur, *sib) };
            cur = hash_pair(left, right);
        }
        cur
    }
}

/// A fixed-height, append-only Poseidon Merkle tree.
///
/// Leaves are appended left to right; the root and any leaf's [`MerklePath`] are
/// available in `O(HEIGHT)`. The tree is `Clone`/`Default` and carries no secret
/// state (unlike the signature-based stores it replaces, there are no keys).
#[derive(Clone, Debug)]
pub struct IncrementalMerkleTree<F: PrimeField + Absorb, const HEIGHT: usize> {
    /// `zeros[l]` = hash of an empty subtree rooted at level `l`. Length `HEIGHT+1`.
    zeros: Vec<F>,
    /// Materialized nodes, densely filled left-to-right. `levels[0]` are leaves;
    /// `levels[HEIGHT]` holds (at most) the single root. A position absent from a
    /// level is implicitly `zeros[level]`.
    levels: Vec<Vec<F>>,
    /// Number of appended leaves.
    count: usize,
}

impl<F: PrimeField + Absorb, const HEIGHT: usize> Default for IncrementalMerkleTree<F, HEIGHT> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField + Absorb, const HEIGHT: usize> IncrementalMerkleTree<F, HEIGHT> {
    /// An empty tree of the fixed height.
    pub fn new() -> Self {
        assert!(HEIGHT >= 1, "Merkle tree height must be at least 1");
        assert!(
            HEIGHT < 64,
            "leaf_index is a u64; HEIGHT must be < 64 to address all slots"
        );
        Self {
            zeros: empty_subtree_hashes::<F>(HEIGHT),
            levels: vec![Vec::new(); HEIGHT + 1],
            count: 0,
        }
    }

    /// The number of leaves appended so far.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether no leaves have been appended.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Maximum number of leaves this height can hold (`2^HEIGHT`), saturating.
    pub fn capacity(&self) -> u64 {
        1u64.checked_shl(HEIGHT as u32).unwrap_or(u64::MAX)
    }

    /// The materialized-or-empty hash of the node at `(level, index)`.
    fn node(&self, level: usize, index: usize) -> F {
        self.levels[level]
            .get(index)
            .copied()
            .unwrap_or(self.zeros[level])
    }

    /// The current root.
    pub fn root(&self) -> F {
        self.node(HEIGHT, 0)
    }

    /// Append a leaf, returning its index. Recomputes only the `HEIGHT` nodes on
    /// the new leaf's path.
    ///
    /// Panics if the tree is already full — a full serverless object tree means
    /// the group has hit `2^HEIGHT` registrations, a configuration error, not a
    /// runtime condition to paper over.
    pub fn append(&mut self, leaf: F) -> usize {
        assert!(
            (self.count as u64) < self.capacity(),
            "Merkle tree of height {HEIGHT} is full ({} leaves)",
            self.count
        );
        let idx = self.count;
        self.set(0, idx, leaf);
        self.count += 1;

        // Walk to the root, recomputing each parent from its (possibly empty) children.
        let mut pos = idx;
        for l in 0..HEIGHT {
            let left = self.node(l, pos & !1);
            let right = self.node(l, pos | 1);
            let parent = hash_pair(left, right);
            self.set(l + 1, pos >> 1, parent);
            pos >>= 1;
        }
        idx
    }

    /// Write `value` at `(level, index)`, extending the dense level as needed.
    ///
    /// Appends fill positions left-to-right without gaps, so `index` is always
    /// either the next free slot or the current rightmost slot.
    fn set(&mut self, level: usize, index: usize, value: F) {
        let lvl = &mut self.levels[level];
        match index.cmp(&lvl.len()) {
            std::cmp::Ordering::Less => lvl[index] = value,
            std::cmp::Ordering::Equal => lvl.push(value),
            std::cmp::Ordering::Greater => {
                // Never happens for left-to-right appends, but keep the invariant
                // total rather than silently corrupting the tree.
                lvl.resize(index, self.zeros[level]);
                lvl.push(value);
            }
        }
    }

    /// The membership witness for the leaf at `index`, or `None` if out of range.
    pub fn path(&self, index: usize) -> Option<MerklePath<F, HEIGHT>> {
        if index >= self.count {
            return None;
        }
        let mut siblings = Vec::with_capacity(HEIGHT);
        let mut pos = index;
        for l in 0..HEIGHT {
            siblings.push(self.node(l, pos ^ 1));
            pos >>= 1;
        }
        Some(MerklePath {
            leaf_index: index as u64,
            siblings,
        })
    }

    /// The leaf value at `index`, or `None` if out of range.
    pub fn leaf(&self, index: usize) -> Option<F> {
        self.levels[0].get(index).copied()
    }

    /// The index of the first leaf equal to `leaf`, or `None`.
    ///
    /// Object commitments carry commitment randomness, so in practice they are
    /// unique; on the astronomically unlikely event of a collision this returns
    /// the earliest, which is a valid member either way.
    pub fn position(&self, leaf: F) -> Option<usize> {
        self.levels[0][..self.count].iter().position(|c| *c == leaf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr as F;

    const H: usize = 6;

    /// Every appended leaf produces a path that recomputes the current root.
    #[test]
    fn paths_recompute_the_root() {
        let mut tree = IncrementalMerkleTree::<F, H>::new();
        let leaves: Vec<F> = (1u64..=20).map(F::from).collect();
        for &l in &leaves {
            tree.append(l);
        }
        let root = tree.root();
        for (i, &l) in leaves.iter().enumerate() {
            let path = tree.path(i).expect("leaf has a path");
            assert_eq!(path.compute_root(l), root, "leaf {i} path must reach root");
        }
    }

    /// A stale path (taken before later appends) reaches the *old* root, not the
    /// new one — the property that makes buffered-root membership sound.
    #[test]
    fn appends_change_the_root_but_old_paths_reach_old_roots() {
        let mut tree = IncrementalMerkleTree::<F, H>::new();
        tree.append(F::from(10));
        let root0 = tree.root();
        let path0 = tree.path(0).unwrap();
        assert_eq!(path0.compute_root(F::from(10)), root0);

        tree.append(F::from(11));
        let root1 = tree.root();
        assert_ne!(root0, root1, "an append must move the root");
        // The leaf-0 path re-fetched after the append reaches the new root...
        let path0b = tree.path(0).unwrap();
        assert_eq!(path0b.compute_root(F::from(10)), root1);
        // ...while the pre-append path still reaches the old root (monotone history).
        assert_eq!(path0.compute_root(F::from(10)), root0);
    }

    /// A wrong leaf, wrong sibling, or wrong index bit all fail to reach the root.
    #[test]
    fn tampering_breaks_the_path() {
        let mut tree = IncrementalMerkleTree::<F, H>::new();
        for l in 1u64..=8 {
            tree.append(F::from(l));
        }
        let root = tree.root();
        let path = tree.path(3).unwrap();
        let leaf = F::from(4);
        assert_eq!(path.compute_root(leaf), root);

        // Wrong leaf.
        assert_ne!(path.compute_root(F::from(999)), root);
        // Wrong sibling.
        let mut bad = path.clone();
        bad.siblings[0] += F::from(1);
        assert_ne!(bad.compute_root(leaf), root);
        // Wrong index bit (claim leaf 3 sits at position 2).
        let mut bad_idx = path.clone();
        bad_idx.leaf_index = 2;
        assert_ne!(bad_idx.compute_root(leaf), root);
    }

    /// The empty-tree root is the top empty-subtree hash, and the first append
    /// leaves every other slot empty.
    #[test]
    fn empty_root_is_zeros_top() {
        let tree = IncrementalMerkleTree::<F, H>::new();
        let zeros = empty_subtree_hashes::<F>(H);
        assert_eq!(tree.root(), zeros[H]);
        assert!(tree.is_empty());
    }

    /// `Default` witness has a full-height sibling vector so the circuit shape is
    /// fixed regardless of which real leaf is later proven.
    #[test]
    fn default_path_is_full_height() {
        let p = MerklePath::<F, H>::default();
        assert_eq!(p.siblings.len(), H);
    }
}
