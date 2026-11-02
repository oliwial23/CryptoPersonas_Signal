use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::Boolean};
use ark_relations::r1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{CryptoRng, RngCore};

/// A public key for a signature scheme, where verification can be done in-circuit.
pub trait Pubkey<F: PrimeField>: Default + ToConstraintField<F> {
    /// The public key in-circuit.
    type PubkeyVar: AllocVar<Self, F>;

    /// The signature type.
    type Sig;

    /// The signature in-circuit.
    type SigVar: AllocVar<Self::Sig, F>;

    /// Standard signature verification.
    ///
    /// Note that messages are field elements.
    fn verify(&self, signature: Self::Sig, msg: F) -> bool;

    /// Verification in-circuit.
    fn verify_zk(
        pubkey: Self::PubkeyVar,
        signature: Self::SigVar,
        msg: FpVar<F>,
    ) -> Result<Boolean<F>, SynthesisError>;
}

/// Private signing key for signatures.
pub trait Privkey<F: PrimeField> {
    /// A compressed private key. This should just be the randomness used to generate the private
    /// key.
    type CompressedPrivKey;

    /// The signature type.
    type Sig;

    /// The public key.
    type Pubkey: Pubkey<F, Sig = Self::Sig>;

    /// Generate a compressed key from randomness.
    fn gen_ckey(rng: &mut (impl CryptoRng + RngCore)) -> Self::CompressedPrivKey;

    /// Convert a compressed key into a standard private key.
    fn into_key(c: Self::CompressedPrivKey) -> Self;

    /// Generate a private key from randomness.
    fn gen_key(rng: &mut (impl CryptoRng + RngCore)) -> Self;

    /// Get the public verification key from the private signing key.
    fn get_pubkey(&self) -> Self::Pubkey;

    /// Sign a message (which is a single field element).
    fn sign(&self, rng: &mut (impl CryptoRng + RngCore), msg: F) -> Option<Self::Sig>;
}

/// Captures signatures with verification in-circuit.
pub trait Signature<F: PrimeField>: Clone {
    /// The signature in-circuit.
    type SigVar: Clone + AllocVar<Self::Sig, F>;
    /// The signature.
    type Sig: Clone + Default + CanonicalSerialize + CanonicalDeserialize + std::fmt::Debug;
    /// The public verification key.
    type Pubkey: Pubkey<F, Sig = Self::Sig, PubkeyVar = Self::PubkeyVar, SigVar = Self::SigVar>
        + Clone
        + Default;
    /// The public verification key in-circuit.
    type PubkeyVar: Clone + AllocVar<Self::Pubkey, F>;
    /// The compressed private key.
    type CPrivkey: Clone;
    /// The private key.
    type Privkey: Privkey<F, CompressedPrivKey = Self::CPrivkey, Pubkey = Self::Pubkey, Sig = Self::Sig>
        + Clone;

    /// Generate a compressed private key.
    fn gen_ckey(rng: &mut (impl CryptoRng + RngCore)) -> Self::CPrivkey {
        Self::Privkey::gen_ckey(rng)
    }

    /// Generate a private key.
    fn gen_key(rng: &mut (impl CryptoRng + RngCore)) -> Self::Privkey {
        Self::Privkey::gen_key(rng)
    }

    /// Convert the compressed private key into the private key.
    fn into_key(c: Self::CPrivkey) -> Self::Privkey {
        Self::Privkey::into_key(c)
    }

    /// Get the associated public key from the private signing key.
    fn get_pubkey(pk: &Self::Privkey) -> Self::Pubkey {
        pk.get_pubkey()
    }

    /// Sign a message with a private key.
    fn sign(pk: &Self::Privkey, rng: &mut (impl CryptoRng + RngCore), msg: F) -> Option<Self::Sig> {
        pk.sign(rng, msg)
    }

    /// Verify a message with a public verification key.
    fn verify(vk: Self::Pubkey, signature: Self::Sig, msg: F) -> bool {
        vk.verify(signature, msg)
    }

    /// Verify a message in-circuit.
    fn verify_zk(
        pubkey: Self::PubkeyVar,
        signature: Self::SigVar,
        msg: FpVar<F>,
    ) -> Result<Boolean<F>, SynthesisError> {
        Self::Pubkey::verify_zk(pubkey, signature, msg)
    }
}

/// UOV Signatures for fast in-circuit verification.
pub mod uov;

/// Schnorr Signatures over Jubjub and BLS for in-circuit verification.
pub mod jj_schnorr;

/// Schnorr Signatures over bls12_377 and its Twisted Edwards curve atop the scalar field for in-circuit verification.
pub mod bls377_schnorr;

/// Schnorr signatures over Grumpkin and bn254 for in-circuit verification.
pub mod gr_schnorr;
