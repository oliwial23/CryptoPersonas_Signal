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
