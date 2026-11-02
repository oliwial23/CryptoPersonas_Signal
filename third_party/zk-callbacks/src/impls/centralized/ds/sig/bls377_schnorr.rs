//! Implements Schnorr signatures over the bls12_377 twisted edwards curve

// Adapted from SnarkBlock
// https://github.com/rozbb/snarkblock/blob/3db6736621a50d88629ce6811c2353d3bb7ed9de/src/issuance.rs

use crate::{
    crypto::hash::HasherZK,
    impls::{
        centralized::ds::sig::{Privkey, Pubkey, Signature},
        hash::Poseidon,
    },
};
use ark_bls12_377::{Fr as BlsFr, Fr as F};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, twisted_edwards::Affine};
use ark_ed_on_bls12_377::{
    EdwardsConfig, EdwardsProjective as EProj, constraints::EdwardsVar as EVar,
};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField, ToConstraintField, UniformRand};
use ark_r1cs_std::{
    R1CSVar,
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    convert::{ToBitsGadget, ToConstraintFieldGadget},
    eq::EqGadget,
    fields::fp::FpVar,
    groups::CurveVar,
    select::CondSelectGadget,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;
use std::borrow::Borrow;

type BlsFrV = FpVar<BlsFr>;

const SCHNORR_HASH_SEPARATOR: u8 = 0x03;

/// Converts an element of a curve's scalar field into an element of the base field
fn fr_to_fq<C, Fq>(x: C::ScalarField) -> Fq
where
    C: CurveGroup<BaseField = Fq>,
    Fq: PrimeField,
{
    let bits = x.into_bigint().to_bits_le();
    Fq::from_bigint(Fq::BigInt::from_bits_le(&bits)).unwrap()
}

type EProjFr = <EProj as PrimeGroup>::ScalarField;

/// A private twisted edwards BLS Schnorr signing key.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize, Default, Debug)]
pub struct BLS377SchnorrPrivkey(EProjFr);

/// A public twisted edwards BLS Schnorr verification key.
#[derive(Debug, Eq, PartialEq, Clone, Copy, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct BLS377SchnorrPubkey(EProj);

/// A public twisted edwards BLS Schnorr verification key in-circuit.
#[derive(Clone)]
pub struct BLS377SchnorrPubkeyVar(EVar);

impl Default for BLS377SchnorrPubkeyVar {
    fn default() -> Self {
        Self(EVar::new(
            FpVar::Constant(BlsFr::ZERO),
            FpVar::Constant(BlsFr::ZERO),
        ))
    }
}

/// A twisted edwards BLS Schnorr signature.
#[derive(Debug, Clone, Default, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct BLS377SchnorrSignature {
    /// Challenge
    e: EProjFr,
    /// Response to challenge
    s: EProjFr,
}

/// A twisted edwards BLS Schnorr signature in-circuit.
#[derive(Clone)]
pub struct BLS377SchnorrSignatureVar {
    /// Challenge
    e: BlsFrV,
    /// Response to challenge
    s: BlsFrV,
}

impl AllocVar<BLS377SchnorrSignature, F> for BLS377SchnorrSignatureVar {
    fn new_variable<T: Borrow<BLS377SchnorrSignature>>(
        cs: impl Into<Namespace<BlsFr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<BLS377SchnorrSignatureVar, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let res = f();
        res.and_then(|sig| {
            let sig = sig.borrow();

            // Signatures are twisted edwards scalars. In order to use them in the circuit we need to embed them
            // into the twisted edwards's scalar field (which is at least as big as the twisted edwards scalar field, so
            // this is injective)
            let lifted_s = fr_to_fq::<EProj, BlsFr>(sig.s);
            let lifted_e = fr_to_fq::<EProj, BlsFr>(sig.e);

            // Construct the lifted signature
            let s_var = BlsFrV::new_variable(ns!(cs, "sig s var"), || Ok(lifted_s), mode)?;
            let e_var = BlsFrV::new_variable(ns!(cs, "sig e var"), || Ok(lifted_e), mode)?;

            Ok(BLS377SchnorrSignatureVar { e: e_var, s: s_var })
        })
    }
}

impl<'a> From<&'a BLS377SchnorrPrivkey> for BLS377SchnorrPubkey {
    fn from(privkey: &'a BLS377SchnorrPrivkey) -> BLS377SchnorrPubkey {
        // g^privkey is the pubkey
        let g = EProj::generator();
        let pubkey = g * privkey.0;
        BLS377SchnorrPubkey(pubkey.into_affine().into())
    }
}

impl BLS377SchnorrPubkey {
    fn verify(&self, msg: &BlsFr, sig: &BLS377SchnorrSignature) -> bool {
        // g is the public generator
        // com is the commitment g^s pubkey^e
        let g = EProj::generator();
        let com = g * sig.s + self.0 * sig.e;

        // e is H(com || msg)
        let mut hash_input = vec![BlsFr::from(SCHNORR_HASH_SEPARATOR)];
        hash_input.extend(com.into_affine().xy().map(|t| vec![t.0, t.1]).unwrap());
        hash_input.push(*msg);
        let digest = <Poseidon<2>>::hash(&hash_input);

        // The hash function outputs a twisted edwards base field element, which we can't use as a twisted edwards
        // scalar. So we convert it to bytes and truncate it to as many bits as a ScalarField
        // element can hold
        let e = {
            let digest_bits = digest.into_bigint().to_bits_le();

            // We only want the first floor(log2(p)) bits of e, where r is the prime order of the
            // scalar field. We do this by finding how many bits are needed to represent r,
            // and truncating e to that many bits
            let r_bitlen = EProjFr::MODULUS_BIT_SIZE as usize;
            let truncated_bits = &digest_bits[..r_bitlen - 1];

            // The truncated bits now represent an integer that's less than r. This cannot fail.
            EProjFr::from_bigint(<EProjFr as PrimeField>::BigInt::from_bits_le(
                &truncated_bits,
            ))
            .unwrap()
        };

        e == sig.e
    }
}

impl Pubkey<F> for BLS377SchnorrPubkey {
    type PubkeyVar = BLS377SchnorrPubkeyVar;

    type Sig = BLS377SchnorrSignature;

    type SigVar = BLS377SchnorrSignatureVar;

    fn verify(&self, signature: Self::Sig, msg: F) -> bool {
        BLS377SchnorrPubkey::verify(self, &msg, &signature)
    }

    fn verify_zk(
        pubkey: Self::PubkeyVar,
        signature: Self::SigVar,
        msg: FpVar<F>,
    ) -> Result<Boolean<F>, SynthesisError> {
        BLS377SchnorrPubkeyVar::verify(&pubkey, &msg, &signature)
    }
}

impl BLS377SchnorrPrivkey {
    fn new(mut rng: impl Rng) -> BLS377SchnorrPrivkey {
        BLS377SchnorrPrivkey(EProjFr::rand(&mut rng))
    }

    /// Signs the given message under `privkey`. Return value is `(s, e)` where (using sigma
    /// protocol terminology) `e` is the challenge and `s` is the response.
    fn sign(&self, mut rng: impl Rng, msg: &BlsFr) -> BLS377SchnorrSignature {
        // g is the public generator
        // k is the secret nonce
        // g^k is the commitment
        let g = EProj::generator();
        let k = EProjFr::rand(&mut rng);
        let com = g * k;

        // e is H(com || msg)
        let mut hash_input = vec![BlsFr::from(SCHNORR_HASH_SEPARATOR)];
        hash_input.extend(com.into_affine().xy().map(|t| vec![t.0, t.1]).unwrap());
        hash_input.push(*msg);
        let digest = <Poseidon<2>>::hash(&hash_input);

        // The hash function outputs a twisted edwards base field element, which we can't use as a twisted edwards
        // scalar. So we convert it to bytes and truncate it to as many bits as a ScalarField
        // element can hold
        let e = {
            let digest_bits = digest.into_bigint().to_bits_le();

            // We only want the first floor(log2(p)) bits of e, where r is the prime order of the
            // scalar field. We do this by finding how many bits are needed to represent r,
            // and truncating e to that many bits
            let r_bitlen = EProjFr::MODULUS_BIT_SIZE as usize;
            let truncated_bits = &digest_bits[..r_bitlen - 1];

            // The truncated bits now represent an integer that's less than r. This cannot fail.
            EProjFr::from_bigint(<EProjFr as PrimeField>::BigInt::from_bits_le(
                &truncated_bits,
            ))
            .expect("couldn't convert BaseField elem to ScalarField elem")
        };

        // s is k - e * privkey
        let s = k - (e * self.0);

        BLS377SchnorrSignature { e, s }
    }
}

impl Privkey<F> for BLS377SchnorrPrivkey {
    type CompressedPrivKey = BLS377SchnorrPrivkey;

    type Sig = BLS377SchnorrSignature;

    type Pubkey = BLS377SchnorrPubkey;

    fn gen_ckey(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self::CompressedPrivKey {
        Self::new(rng)
    }

    fn into_key(c: Self::CompressedPrivKey) -> Self {
        c
    }

    fn gen_key(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        Self::new(rng)
    }

    fn get_pubkey(&self) -> Self::Pubkey {
        Self::Pubkey::from(self)
    }

    fn sign(&self, rng: &mut (impl rand::CryptoRng + rand::RngCore), msg: F) -> Option<Self::Sig> {
        Some(BLS377SchnorrPrivkey::sign(self, rng, &msg))
    }
}

impl ToConstraintField<F> for BLS377SchnorrPubkey {
    fn to_field_elements(&self) -> Option<Vec<F>> {
        let mut vector: Vec<F> = Vec::new();

        vector.extend_from_slice(&self.0.into_affine().x.to_field_elements().unwrap());
        vector.extend_from_slice(&self.0.into_affine().y.to_field_elements().unwrap());

        Some(vector)
    }
}

impl ToConstraintFieldGadget<F> for BLS377SchnorrPubkeyVar {
    fn to_constraint_field(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        self.0.to_constraint_field()
    }
}

impl R1CSVar<F> for BLS377SchnorrPubkeyVar {
    type Value = BLS377SchnorrPubkey;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.0.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(BLS377SchnorrPubkey { 0: self.0.value()? })
    }
}

impl AllocVar<BLS377SchnorrPubkey, F> for BLS377SchnorrPubkeyVar {
    fn new_variable<T: Borrow<BLS377SchnorrPubkey>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();

        res.and_then(|pk| {
            let pk = pk.borrow();

            if mode == AllocationMode::Constant {
                return Ok(Self(EVar::new_constant(cs.clone(), pk.0)?));
            }

            let aff_pk = pk.0.into_affine();

            let bls377_v = <EVar as AllocVar<Affine<EdwardsConfig>, _>>::new_variable(
                ns!(cs, "entry"),
                || Ok(&aff_pk),
                mode,
            )?;

            Ok(Self(bls377_v))
        })
    }
}

impl BLS377SchnorrPubkeyVar {
    /// Verifies the given (message, signature) pair under the given public key. All this is done in
    /// zero-knowledge.
    /// The signature is expected to have been embedded from (Fr, Fr) to (Fq, Fq). The reason we do
    /// this is because doing that let aff_pk: Affine<EdwardsConfig> = pk.0.into_affine();
    //         EVar::new_input(cs, || Ok(aff_pk)).map(SchnorrPubkeyVar) in ZK is cumbersome and unnecessary.
    fn verify(
        &self,
        msg: &BlsFrV,
        sig: &BLS377SchnorrSignatureVar,
    ) -> Result<Boolean<BlsFr>, SynthesisError> {
        let cs = self.0.cs().or(msg.cs()).or(sig.e.cs()).or(sig.s.cs());

        // Witness the group generator. This is the same across all signatures
        let g = EProj::generator();
        let gv = EVar::new_constant(ns!(cs, "EPorj gen"), g)?;

        // The signature is (s, e)
        // r is g^s pubkey^e
        let BLS377SchnorrSignatureVar { e, s } = sig;
        let r = {
            // Computs g^s
            let s_bits = s.to_bits_le()?;
            let g_s = gv.scalar_mul_le(s_bits.iter())?;
            // Compute pubkey^e
            let e_bits = e.to_bits_le()?;
            let pubkey_e = self.0.scalar_mul_le(e_bits.iter())?;

            // Add them
            g_s + pubkey_e
        };

        // e' is H(r || msg). This should be equal to the given e, up to Fr::size() many bits
        let hash_input = vec![
            FpVar::Constant(BlsFr::from(SCHNORR_HASH_SEPARATOR)),
            r.x,
            r.y,
            msg.clone(),
        ];
        let e_prime = <Poseidon<2>>::hash_in_zk(&hash_input)?;

        // Show that e' and e agree for all the bits up to the bitlength of the scalar field's modulus.
        // We check the truncation because we have to use the truncation of e as a scalar field element
        // (since e is naturally a base field element and too big to be a scalar field element).
        let e_prime_bits = e_prime.to_bits_le()?;
        let e_bits = e.to_bits_le()?;
        let scalar_mod_bitlen = EProjFr::MODULUS_BIT_SIZE as usize;
        let is_equal =
            e_prime_bits[..scalar_mod_bitlen - 1].is_eq(&e_bits[..scalar_mod_bitlen - 1])?;

        // Return whether this verified
        Ok(is_equal)
    }
}

impl CondSelectGadget<BlsFr> for BLS377SchnorrPubkeyVar {
    fn conditionally_select(
        cond: &Boolean<BlsFr>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let selected = EVar::conditionally_select(cond, &true_value.0, &false_value.0)?;
        Ok(BLS377SchnorrPubkeyVar(selected))
    }
}

/// The Schnorr signature scheme, on the BLS curve. Implements [`Signature`].
#[derive(Clone, Default, Debug)]
pub struct Bls377Schnorr;

impl Signature<F> for Bls377Schnorr {
    type SigVar = BLS377SchnorrSignatureVar;

    type Sig = BLS377SchnorrSignature;

    type Pubkey = BLS377SchnorrPubkey;

    type PubkeyVar = BLS377SchnorrPubkeyVar;

    type CPrivkey = BLS377SchnorrPrivkey;

    type Privkey = BLS377SchnorrPrivkey;
}

// TODO: FoldSer

#[cfg(test)]
mod test {
    use super::*;

    use ark_ff::UniformRand;
    use ark_relations::r1cs::ConstraintSystem;
    use rand::thread_rng;

    // Just checks that Schnorr signing doesn't panic
    #[test]
    fn schnorr_sign() {
        let mut rng = thread_rng();

        // Try signing 100 times with different randomness. There used to be an issue where the
        // value of e was invalid and it would panic some of the time. So now we run the test a lot
        // of times.
        for _ in 0..100 {
            // Make a random privkey and message
            let privkey = BLS377SchnorrPrivkey::new(&mut rng);
            let msg = BlsFr::rand(&mut rng);

            // Sign the random message under the random privkey
            privkey.sign(&mut rng, &msg);
        }
    }

    // Tests that the verification circuit is satisfied iff the signature is valid
    #[test]
    fn schnorr_verify() -> Result<(), SynthesisError> {
        let mut rng = thread_rng();

        for _ in 0..10 {
            let cs = ConstraintSystem::<BlsFr>::new_ref();

            // Make a random keypair and message
            let privkey = BLS377SchnorrPrivkey::new(&mut rng);
            let pubkey: BLS377SchnorrPubkey = (&privkey).into();
            let msg = BlsFr::rand(&mut rng);
            // Sign the message
            let sig = privkey.sign(&mut rng, &msg);

            // Witness all the values
            let msg_var = BlsFrV::new_input(cs.clone(), || Ok(msg))?;
            let sig_var = BLS377SchnorrSignatureVar::new_witness(cs.clone(), || Ok(&sig)).unwrap();
            let pubkey_var = BLS377SchnorrPubkeyVar::new_input(cs.clone(), || Ok(&pubkey)).unwrap();

            // Check Schnorr verif in ZK
            let success = pubkey_var.verify(&msg_var, &sig_var)?;
            success.enforce_equal(&Boolean::TRUE).unwrap();
            assert!(cs.is_satisfied()?);
            // Check Schnorr verif natively
            assert!(pubkey.verify(&msg, &sig));
        }
        Ok(())
    }
}
