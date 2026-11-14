use ark_groth16::{Groth16, ProvingKey, VerifyingKey};

use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::Boolean;
use ark_relations::r1cs::Result as ArkResult;
use zk_callbacks::impls::{
    centralized::{
        crypto::NoSigOTP,
        ds::sigstore::{GRSchnorrCallbackStore, GRSchnorrObjStore, GRSchnorrStore},
    },
    hash::Poseidon,
};

pub type F = ark_bn254::Fr;
pub type E = ark_bn254::Bn254;
pub type Boolean2 = Boolean<F>;
pub type ArkResult2 = ArkResult<Boolean2>;

pub type Args = F;

pub type ArgsVar = FpVar<F>;

pub type Store = GRSchnorrStore<Args>;
pub type CStore = GRSchnorrCallbackStore<Args>;
pub type OStore = GRSchnorrObjStore;

pub type Cr = NoSigOTP<F>;

pub type H = Poseidon<2>;

pub type Snark = Groth16<E>;

pub type PK = ProvingKey<E>;
pub type VK = VerifyingKey<E>;

/// A field element as a JS-friendly number, interpreting the top half of the field as
/// NEGATIVE.
///
/// Lives HERE rather than in `personas-node` on purpose. The addon crate does not depend
/// on `ark-ff`, and adding it there to get `PrimeField` made the built `.node` kill the
/// Electron renderer at load (SIGKILL, exit 9) before any of its code ran — a Cargo
/// feature-unification change, not a code bug. `personas-core` already depends on
/// `ark-ff`, so putting the conversion here keeps the addon's dependency graph
/// untouched.
///
/// Why signed: a reputation is a running sum of +1/-1 ratings and can legitimately go
/// below zero. Field arithmetic has no negatives — `-1` is stored as `p - 1` — so a
/// naive read reports a reputation of -1 as roughly 2.7e76, which reads as corruption
/// rather than as a number. Values above `(p-1)/2` are therefore treated as `v - p`.
///
/// Returns 0.0 rather than panicking on anything that is not a small integer: the only
/// caller is a status display, which must never be the thing that takes down the app.
pub fn field_to_f64_signed(value: &F) -> f64 {
    use ark_ff::PrimeField;

    let is_negative = value.into_bigint() > F::MODULUS_MINUS_ONE_DIV_TWO;
    let magnitude = if is_negative {
        (-*value).into_bigint().to_string()
    } else {
        value.into_bigint().to_string()
    };
    let parsed = magnitude.parse::<f64>().unwrap_or(0.0);
    if is_negative { -parsed } else { parsed }
}

// ===========================================================================
// AUTHORSHIP PROOFS: encode, decode, verify.
//
// These live in `personas-core` rather than in the napi addon on purpose. The addon
// crate (`personas-node`) must not gain dependencies: adding one (`ark-ff`) produced a
// `.node` that killed the Electron renderer at load, before any of its code ran,
// because the extra edge changed Cargo's feature unification across the whole graph.
// `personas-core` already depends on ark-serialize and ark-snark, so putting the proof
// handling here keeps the addon's graph byte-identical to the known-good one.
// ===========================================================================

/// The badge names held in a user's object, read from the three badge slots.
///
/// Returns the human-readable label for each non-empty slot, in slot order, so the
/// caller never has to know the field-element constants. An empty slot is zero and is
/// skipped.
///
/// Lives here rather than in the addon because the constants (`FACULTY_F`, `STUDENT_F`,
/// `INDUSTRY_F`) are circuit values defined in this crate — and because the addon must
/// not gain dependencies, which is what broke the build once already.
pub fn badge_labels(badge1: &F, badge2: &F, badge3: &F) -> Vec<String> {
    use crate::circuits::{FACULTY_F, INDUSTRY_F, STUDENT_F};

    let zero = F::from(0u64);
    let mut out = Vec::new();
    // Compared against the SAME constants the in-circuit callback assigns, so a slot
    // holding something unrecognised is reported as such rather than silently dropped —
    // that would mean the circuit and this table have diverged.
    for (slot, value, expected, label) in [
        (1u8, badge1, &*FACULTY_F, "Faculty"),
        (2, badge2, &*STUDENT_F, "Student"),
        (3, badge3, &*INDUSTRY_F, "Industry"),
    ] {
        if *value == zero {
            continue;
        }
        if value == expected {
            out.push(label.to_string());
        } else {
            out.push(format!("slot {slot}: unrecognised badge value"));
        }
    }
    out
}

/// Serialize a not-banned (reset request) proof and its public inputs `[account, nul, root]`.
pub fn encode_not_banned_proof(
    proof: &<Snark as ark_snark::SNARK<F>>::Proof,
    inputs: &[F; 3],
) -> Result<Vec<u8>, ark_serialize::SerializationError> {
    use ark_serialize::CanonicalSerialize;

    let mut bytes = Vec::new();
    proof.serialize_uncompressed(&mut bytes)?;
    inputs.to_vec().serialize_uncompressed(&mut bytes)?;
    Ok(bytes)
}

/// Read a not-banned proof's bytes, returning the proof and `[account, nul, root]`.
pub fn decode_not_banned_proof(
    mut bytes: &[u8],
) -> Option<(<Snark as ark_snark::SNARK<F>>::Proof, [F; 3])> {
    use ark_serialize::CanonicalDeserialize;
    use ark_snark::SNARK;

    let proof =
        <<Snark as SNARK<F>>::Proof as CanonicalDeserialize>::deserialize_uncompressed(&mut bytes)
            .ok()?;
    let inputs = Vec::<F>::deserialize_uncompressed(&mut bytes).ok()?;
    Some((proof, inputs.try_into().ok()?))
}

/// VERIFY a not-banned proof, returning `(account, nul, root)` only if it is sound. As with a
/// badge proof, the caller MUST check the root is one its replica produced, and that the
/// account is the one asking.
pub fn verify_not_banned_proof(
    vk: &impl crate::ProofVerifier,
    bytes: &[u8],
) -> Option<(F, F, F)> {
    use ark_serialize::CanonicalDeserialize;
    use ark_snark::SNARK;

    let mut reader = bytes;
    let proof =
        <<Snark as SNARK<F>>::Proof as CanonicalDeserialize>::deserialize_uncompressed(&mut reader)
            .ok()?;
    let inputs = Vec::<F>::deserialize_uncompressed(&mut reader).ok()?;
    if inputs.len() != 3 {
        return None;
    }
    if vk.verify_proof(&inputs, &proof) {
        Some((inputs[0], inputs[1], inputs[2]))
    } else {
        None
    }
}

/// The field element standing for a Signal account in join and reset proofs: the
/// account's 16 ACI bytes, little-endian. Below the modulus, so it is invertible
/// (`account_bytes`).
pub fn account_field(aci: &[u8; 16]) -> F {
    use ark_ff::PrimeField;
    F::from_le_bytes_mod_order(aci)
}

/// The 16 ACI bytes back from [`account_field`].
pub fn account_bytes(account: &F) -> [u8; 16] {
    use ark_ff::{BigInteger, PrimeField};
    let le = account.into_bigint().to_bytes_le();
    let mut out = [0u8; 16];
    out.copy_from_slice(&le[..16]);
    out
}

/// The field element a badge NAME maps to, or `None` for an unknown name.
///
/// The circuit compares against these exact constants, so a name that is not one of the
/// three cannot be proved at all — which is why a user-supplied custom badge needs a
/// circuit change rather than a UI change.
pub fn badge_value(name: &str) -> Option<(u32, F)> {
    use crate::circuits::{FACULTY_F, INDUSTRY_F, STUDENT_F};

    match name {
        // (slot index, value). Slots are 1-based in `badge_pred`'s selector.
        "Faculty" => Some((1, *FACULTY_F)),
        "Student" => Some((2, *STUDENT_F)),
        "Industry" => Some((3, *INDUSTRY_F)),
        _ => None,
    }
}
