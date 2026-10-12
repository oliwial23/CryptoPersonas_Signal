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
