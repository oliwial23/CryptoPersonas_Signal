//! A GGM tree-based **puncturable PRF**: the message-key schedule's engine.
//!
//! # Why a PPRF (the review concern this resolves)
//!
//! Under a *shared* group secret, every member drives the same key schedule, so a
//! naive counter-indexed chain (Signal's stock sender key) hits a collision the
//! moment two members send before seeing each other: both derive the message key
//! for iteration *i*, and the second decrypt fails — an observable dropped message.
//! Indexing message keys by a **random nonce** instead of a counter removes the
//! collision. But a plain `KDF(root, nonce)` would force retaining `root` for the
//! whole epoch (you can't predict future nonces), so a device snapshot recovers
//! every past message key — no within-epoch forward secrecy.
//!
//! A puncturable PRF gives both at once. `Eval(k, nonce)` is a normal PRF; after
//! consuming a message you `Puncture(k, nonce)`, which keeps evaluation at every
//! *other* point but makes that one key unrecoverable. Puncturing is commutative
//! and each member only punctures nonces it actually consumed, so out-of-order
//! delivery converges to the same key state — which is exactly what the serverless
//! setting needs.
//!
//! # Construction
//!
//! Classic GGM over a depth-[`DEPTH`] binary tree. The key is the root seed; a
//! leaf reached by the bits of `nonce` (MSB-first) is the PRF value. The tree is
//! never materialised — [`crate::kdf::prg`] expands a node into its two children
//! on demand. A **punctured** key is stored as a set of *cover nodes*: interior
//! node seeds whose subtrees are entirely un-punctured and which together tile the
//! domain minus the punctured leaves. Puncturing a leaf replaces the one cover
//! node above it with the ≤`DEPTH` sibling seeds along the root-to-leaf path (the
//! "co-path"), and drops the on-path leaf seed — so the punctured point can no
//! longer be evaluated, while all siblings remain. This is the standard
//! multi-puncture GGM representation; key size grows `O(punctures · DEPTH · λ)`
//! within an epoch and is discarded wholesale at re-key.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::kdf::{HASH_LEN, prg};

/// Tree depth = nonce length in **bits**. A 128-bit random nonce makes collision
/// between two independently sampled message nonces negligible (`m²/2¹²⁸` for `m`
/// messages in an epoch) while keeping per-puncture cost — at most `DEPTH` PRG
/// calls and `DEPTH` new cover nodes — cheap. Key-state growth per consumed
/// message is the accepted price of per-message-FS; re-key cadence bounds it.
pub const DEPTH: usize = 128;

/// Nonce length in bytes (`DEPTH / 8`).
pub const NONCE_LEN: usize = DEPTH / 8;

/// A per-message nonce: the PPRF evaluation point, carried in each `PersonaEnvelope`.
///
/// Public (not secret) — it indexes the key, it is not the key. Sampled uniformly
/// so concurrent senders never collide.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Nonce(pub [u8; NONCE_LEN]);

impl Nonce {
    /// Sample a uniform nonce.
    pub fn random(rng: &mut impl rand::RngCore) -> Self {
        let mut bytes = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut bytes);
        Nonce(bytes)
    }

    /// Bit `i` of the nonce, MSB-first within each byte.
    #[inline]
    fn bit(&self, i: usize) -> bool {
        (self.0[i / 8] >> (7 - (i % 8))) & 1 == 1
    }
}

/// The raw PPRF output at a leaf: 32 bytes of key material the caller turns into a
/// message key (see [`crate::group`]). Zeroized on drop so a consumed value does
/// not linger.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PrfOutput(pub [u8; HASH_LEN]);

impl core::fmt::Debug for PrfOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print key material.
        f.write_str("PrfOutput(..)")
    }
}

/// One subtree of the key: the seed at a node whose entire subtree is un-punctured.
/// Only the first `len` bits of `bits` are meaningful (the node's path from root).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct CoverNode {
    len: u16,
    bits: [u8; NONCE_LEN],
    seed: [u8; HASH_LEN],
}

impl CoverNode {
    /// Does this node's subtree contain `nonce`? True iff the node's `len`-bit path
    /// is a prefix of `nonce`.
    fn covers(&self, nonce: &Nonce) -> bool {
        (0..self.len as usize).all(|i| bit(&self.bits, i) == nonce.bit(i))
    }
}

/// Bit `i` of a raw prefix buffer, MSB-first.
#[inline]
fn bit(bytes: &[u8; NONCE_LEN], i: usize) -> bool {
    (bytes[i / 8] >> (7 - (i % 8))) & 1 == 1
}

#[inline]
fn set_bit(bytes: &mut [u8; NONCE_LEN], i: usize) {
    bytes[i / 8] |= 1 << (7 - (i % 8));
}

/// The `(upto+1)`-bit prefix `nonce[0..upto] ++ last`, zero-padded.
fn sibling_prefix(nonce: &Nonce, upto: usize, last: bool) -> [u8; NONCE_LEN] {
    let mut out = [0u8; NONCE_LEN];
    for i in 0..upto {
        if nonce.bit(i) {
            set_bit(&mut out, i);
        }
    }
    if last {
        set_bit(&mut out, upto);
    }
    out
}

/// Descend from a node seed at depth `from_level` through the remaining bits of
/// `nonce` to the leaf seed.
fn descend(mut seed: [u8; HASH_LEN], nonce: &Nonce, from_level: usize) -> [u8; HASH_LEN] {
    for level in from_level..DEPTH {
        let (left, right) = prg(&seed);
        seed.zeroize();
        seed = if nonce.bit(level) { right } else { left };
    }
    seed
}

/// A puncturable PRF key: the full key at construction, then a shrinking set of
/// cover nodes as points are punctured. Zeroizes its seeds on drop.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PuncturableKey {
    covers: Vec<CoverNode>,
}

impl PuncturableKey {
    /// A fresh, un-punctured key from a 32-byte root seed. The whole domain is one
    /// cover node at the empty prefix.
    pub fn new(root: [u8; HASH_LEN]) -> Self {
        PuncturableKey {
            covers: vec![CoverNode {
                len: 0,
                bits: [0u8; NONCE_LEN],
                seed: root,
            }],
        }
    }

    /// `F(k, nonce)`, or `None` if `nonce` has been punctured (its key is gone).
    pub fn eval(&self, nonce: &Nonce) -> Option<PrfOutput> {
        let node = self.covers.iter().find(|n| n.covers(nonce))?;
        Some(PrfOutput(descend(node.seed, nonce, node.len as usize)))
    }

    /// Puncture `nonce`: evaluation elsewhere is preserved, at `nonce` it becomes
    /// unrecoverable. Idempotent — puncturing an already-punctured point is a no-op.
    pub fn puncture(&mut self, nonce: &Nonce) {
        let Some(idx) = self.covers.iter().position(|n| n.covers(nonce)) else {
            return; // already punctured
        };
        // Take the covering node out; walk its path to `nonce`, banking each sibling.
        let node = self.covers.swap_remove(idx);
        let mut seed = node.seed;
        for level in (node.len as usize)..DEPTH {
            let (left, right) = prg(&seed);
            let on = nonce.bit(level);
            let (on_seed, off_seed) = if on { (right, left) } else { (left, right) };
            self.covers.push(CoverNode {
                len: (level + 1) as u16,
                bits: sibling_prefix(nonce, level, !on),
                seed: off_seed,
            });
            seed.zeroize(); // wipe the on-path ancestor we just expanded
            seed = on_seed;
        }
        // `seed` is now the leaf seed for `nonce` itself: drop it unbanked. Zeroizing
        // it (and `node` via ZeroizeOnDrop) is what makes the puncture forward-secret
        // at the persisted-state level — no remaining cover node can reach this leaf.
        seed.zeroize();
    }

    /// Whether `nonce` is still evaluable. `!is_punctured` iff [`Self::eval`] is `Some`.
    pub fn is_punctured(&self, nonce: &Nonce) -> bool {
        !self.covers.iter().any(|n| n.covers(nonce))
    }

    /// Number of cover nodes — the key-state size, for tests/telemetry.
    pub fn cover_count(&self) -> usize {
        self.covers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0xE2A)
    }

    #[test]
    fn eval_is_deterministic() {
        let k = PuncturableKey::new([1u8; 32]);
        let n = Nonce([2u8; NONCE_LEN]);
        assert_eq!(k.eval(&n).unwrap(), k.eval(&n).unwrap());
    }

    #[test]
    fn distinct_nonces_give_distinct_outputs() {
        let k = PuncturableKey::new([1u8; 32]);
        let a = k.eval(&Nonce([0u8; NONCE_LEN])).unwrap();
        let b = k.eval(&Nonce([0xffu8; NONCE_LEN])).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn puncture_removes_only_the_target() {
        let mut r = rng();
        let mut k = PuncturableKey::new([7u8; 32]);
        let victim = Nonce::random(&mut r);
        let others: Vec<Nonce> = (0..16).map(|_| Nonce::random(&mut r)).collect();
        let before: Vec<_> = others.iter().map(|n| k.eval(n).unwrap()).collect();

        assert!(k.eval(&victim).is_some());
        k.puncture(&victim);
        assert!(
            k.eval(&victim).is_none(),
            "punctured point must be unrecoverable"
        );
        assert!(k.is_punctured(&victim));

        for (n, was) in others.iter().zip(before) {
            assert_eq!(
                k.eval(n).unwrap(),
                was,
                "other points must survive puncture"
            );
        }
    }

    #[test]
    fn puncture_is_idempotent() {
        let mut k = PuncturableKey::new([3u8; 32]);
        let n = Nonce([9u8; NONCE_LEN]);
        k.puncture(&n);
        let count = k.cover_count();
        k.puncture(&n); // no-op
        assert_eq!(k.cover_count(), count);
        assert!(k.eval(&n).is_none());
    }

    #[test]
    fn puncture_order_does_not_change_surviving_values() {
        let mut r = rng();
        let root = [5u8; 32];
        let punctures: Vec<Nonce> = (0..8).map(|_| Nonce::random(&mut r)).collect();
        let survivors: Vec<Nonce> = (0..8).map(|_| Nonce::random(&mut r)).collect();

        let mut fwd = PuncturableKey::new(root);
        for n in &punctures {
            fwd.puncture(n);
        }
        let mut rev = PuncturableKey::new(root);
        for n in punctures.iter().rev() {
            rev.puncture(n);
        }

        // Commutativity: whichever order, survivors evaluate identically.
        for s in &survivors {
            assert_eq!(fwd.eval(s).unwrap(), rev.eval(s).unwrap());
        }
        for n in &punctures {
            assert!(fwd.eval(n).is_none() && rev.eval(n).is_none());
        }
    }

    #[test]
    fn serde_roundtrip_preserves_evaluation() {
        let mut r = rng();
        let mut k = PuncturableKey::new([11u8; 32]);
        for _ in 0..5 {
            k.puncture(&Nonce::random(&mut r));
        }
        let probe = Nonce::random(&mut r);
        let want = k.eval(&probe).unwrap();

        let bytes = serde_json::to_vec(&k).unwrap();
        let k2: PuncturableKey = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(k2.eval(&probe).unwrap(), want);
    }
}
