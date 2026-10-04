//! The symmetric primitives e2a is built from, all over the workspace-pinned
//! `sha2 = 0.10`: HMAC-SHA256, HKDF-SHA256, and the length-doubling PRG that
//! drives the GGM tree in [`crate::pprf`].
//!
//! We implement these by hand rather than pull `hkdf`/`hmac`, for two reasons.
//! First, the workspace pins `sha2 0.10` (digest 0.10) while the lockfile already
//! carries `hmac 0.13` (digest 0.11) transitively — adding the `hkdf` crate would
//! drag in a second digest version to satisfy the pairing. Second, this is the
//! crate the e2a sign-off gate audits as a single unit, and HMAC/HKDF from a hash
//! are textbook: implementing them in ~60 reviewable lines and pinning them to the
//! RFC 4231 / RFC 5869 published vectors is *more* trustworthy here than an
//! unaudited version juggle. See `docs/E2A_GROUP_KEYS.md`.

use sha2::{Digest, Sha256};

/// SHA-256 output / seed length in bytes.
pub const HASH_LEN: usize = 32;
/// SHA-256 block size in bytes (the HMAC key-padding width).
const BLOCK_LEN: usize = 64;

/// HMAC-SHA256 over `msg` with `key`, per RFC 2104.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; HASH_LEN] {
    // Keys longer than the block are hashed down; shorter keys are zero-padded.
    let mut block_key = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        block_key[..HASH_LEN].copy_from_slice(&Sha256::digest(key));
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_LEN];
    let mut opad = [0x5cu8; BLOCK_LEN];
    for i in 0..BLOCK_LEN {
        ipad[i] ^= block_key[i];
        opad[i] ^= block_key[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

/// HKDF-Extract (RFC 5869 §2.2): `PRK = HMAC(salt, IKM)`.
///
/// An empty `salt` is treated as `HashLen` zero bytes, exactly as the RFC says.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; HASH_LEN] {
    if salt.is_empty() {
        hmac_sha256(&[0u8; HASH_LEN], ikm)
    } else {
        hmac_sha256(salt, ikm)
    }
}

/// HKDF-Expand (RFC 5869 §2.3) to a single SHA-256 block.
///
/// e2a only ever needs one 32-byte output (an epoch key / PRF root), so this is
/// the `L <= HashLen` special case: `OKM = HMAC(PRK, info || 0x01)[..32]`. A
/// general multi-block expand is not needed and would be dead code.
pub fn hkdf_expand_32(prk: &[u8; HASH_LEN], info: &[u8]) -> [u8; HASH_LEN] {
    let mut buf = Vec::with_capacity(info.len() + 1);
    buf.extend_from_slice(info);
    buf.push(0x01);
    hmac_sha256(prk, &buf)
}

/// One-shot HKDF-SHA256 (extract then expand) to 32 bytes.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; HASH_LEN] {
    hkdf_expand_32(&hkdf_extract(salt, ikm), info)
}

/// The GGM length-doubling PRG: from a parent seed derive its two child seeds.
///
/// `G(seed) = ( SHA256(0x00 || seed), SHA256(0x01 || seed) )`. Domain-separating
/// the two children by a leading tag byte is the standard hash instantiation of a
/// GGM PRG; SHA-256's collision/pre-image resistance is the security assumption
/// (the same one d1 leans on for Poseidon in-circuit — here we are fully native).
pub fn prg(seed: &[u8; HASH_LEN]) -> ([u8; HASH_LEN], [u8; HASH_LEN]) {
    let mut left = Sha256::new();
    left.update([0x00u8]);
    left.update(seed);

    let mut right = Sha256::new();
    right.update([0x01u8]);
    right.update(seed);

    (left.finalize().into(), right.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4231 §4.2 — HMAC-SHA256 test case 1.
    #[test]
    fn hmac_rfc4231_case1() {
        let key = [0x0bu8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex::encode(mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    // RFC 4231 §4.3 — HMAC-SHA256 test case 2 ("Jefe" / "what do ya want ...").
    #[test]
    fn hmac_rfc4231_case2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    // RFC 4231 §4.6 — case 5: key longer than the block, exercising the hash-down path.
    #[test]
    fn hmac_rfc4231_case6_long_key() {
        let key = [0xaau8; 131];
        let mac = hmac_sha256(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            hex::encode(mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    // RFC 5869 Appendix A.1 — HKDF-SHA256 basic test vector.
    #[test]
    fn hkdf_rfc5869_a1() {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00u8..=0x0c).collect();
        let info: Vec<u8> = (0xf0u8..=0xf9).collect();

        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            hex::encode(prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        // First 32 bytes of the RFC's 42-byte OKM.
        let okm = hkdf_expand_32(&prk, &info);
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );
    }

    #[test]
    fn prg_children_differ_and_are_deterministic() {
        let seed = [7u8; HASH_LEN];
        let (l1, r1) = prg(&seed);
        let (l2, r2) = prg(&seed);
        assert_eq!(l1, l2);
        assert_eq!(r1, r2);
        assert_ne!(l1, r1, "left and right children must be domain-separated");
    }
}
