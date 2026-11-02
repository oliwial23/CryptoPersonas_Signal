use crate::generic::object::{Ser, SerVar};
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::AllocVar};
use ark_relations::r1cs::SynthesisError;

/// Trait for hashing, which can also be represented in zero knowledge.
///
/// The hasher allows one to hash an arbitrary length message into an output. Along with this,
/// one can generate the constraints for a hash computation in zero-knowledge. This can be done
/// using the representations of the message and output as allocated variables.
///
/// # Example (Sha256)
/// ```rust
/// # use zk_callbacks::crypto::hash::HasherZK;
/// # use ark_ff::PrimeField;
/// # use ark_crypto_primitives::sponge::Absorb;
/// # use ark_crypto_primitives::crh::sha256::Sha256;
/// # use ark_crypto_primitives::crh::CRHScheme;
/// # use ark_r1cs_std::prelude::UInt8;
/// # use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
/// # use ark_relations::r1cs::SynthesisError;
/// # use ark_crypto_primitives::crh::CRHSchemeGadget;
/// # use std::marker::PhantomData;
/// # use ark_crypto_primitives::crh::sha256::constraints::UnitVar;
/// # use ark_r1cs_std::convert::ToBytesGadget;
/// # use ark_relations::ns;
/// # use ark_r1cs_std::alloc::AllocVar;
/// # use ark_r1cs_std::R1CSVar;
/// # #[derive(Clone, Default, Debug)]
/// pub struct Sha();
///
/// impl<F: PrimeField> HasherZK<F> for Sha {
///
///     type M = u8;
///
///     type C = [u8; 32];
///
///     type MV = UInt8<F>;
///
///     type CV = [UInt8<F>; 32];
///
///     fn hash(data: &[u8]) -> [u8; 32] {
///         Sha256::evaluate(&(), data).unwrap().try_into().unwrap()
///     }
///
///     fn hash_in_zk(data: &[UInt8<F>]) -> Result<[UInt8<F>; 32], SynthesisError> {
///         let unit = UnitVar::new_constant(ns!(data[0].cs(), "params"), &())?;
///         Ok(Sha256Gadget::evaluate(&unit, data)?.to_bytes_le()?.try_into().unwrap())
///     }
/// }
/// ```
pub trait HasherZK<F: PrimeField>: Send + Sync {
    /// Message unit type to be hashed (fixed length).
    type M;
    /// Output type from the hash.
    type C;
    /// Zero-knowledge representation of the message.
    type MV: AllocVar<Self::M, F>;
    /// Zero-knowledge representation of the output.
    type CV: AllocVar<Self::C, F>;

    /// Takes in an arbitrary length message and hashes it down to an output.
    fn hash(data: &[Self::M]) -> Self::C;

    /// Takes in a message in zero-knowledge and produces the output.
    fn hash_in_zk(data: &[Self::MV]) -> Result<Self::CV, SynthesisError>;
}

/// Hash from a PrimeField to the same field.
///
/// Note that the message type is a Field element [`Ser<F>`](`crate::generic::object::Ser`), and
/// the output is a Field element `F`.
///
/// For example, Poseidon or MiMC may implement FieldHash, but not Sha256.
pub trait FieldHash<F: PrimeField>:
    HasherZK<F, C = F, M = Ser<F>, MV = SerVar<F>, CV = FpVar<F>> + Clone
{
}
