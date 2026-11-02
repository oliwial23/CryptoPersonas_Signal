//! Implements Schnorr signatures over the Jubjub curve

// Adapted from SnarkBlock
// https://github.com/rozbb/snarkblock/blob/3db6736621a50d88629ce6811c2353d3bb7ed9de/src/issuance.rs

use crate::{
    crypto::hash::HasherZK,
    impls::{
        centralized::ds::sig::{Privkey, Pubkey, Signature},
        hash::Poseidon,
    },
};
use ark_bls12_381::{Fr as BlsFr, Fr as F};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, twisted_edwards::Affine};
use ark_ed_on_bls12_381::{
    EdwardsProjective as Jubjub, JubjubConfig, constraints::EdwardsVar as JubjubVar,
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

type JubjubFr = <Jubjub as PrimeGroup>::ScalarField;

/// A private Jubjub BLS Schnorr signing key.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize, Default, Debug)]
pub struct JJSchnorrPrivkey(JubjubFr);

/// A public Jubjub BLS Schnorr verification key.
#[derive(Debug, Eq, PartialEq, Clone, Copy, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct JJSchnorrPubkey(Jubjub);

/// A public Jubjub BLS Schnorr verification key in-circuit.
#[derive(Clone)]
pub struct JJSchnorrPubkeyVar(JubjubVar);

impl Default for JJSchnorrPubkeyVar {
    fn default() -> Self {
        Self(JubjubVar::new(
            FpVar::Constant(BlsFr::ZERO),
            FpVar::Constant(BlsFr::ZERO),
        ))
    }
}

/// A Jubjub BLS Schnorr signature.
#[derive(Debug, Clone, Default, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct JJSchnorrSignature {
    /// Challenge
    e: JubjubFr,
    /// Response to challenge
    s: JubjubFr,
}

/// A Jubjub BLS Schnorr signature in-circuit.
#[derive(Clone)]
pub struct JJSchnorrSignatureVar {
    /// Challenge
    e: BlsFrV,
    /// Response to challenge
    s: BlsFrV,
}

impl AllocVar<JJSchnorrSignature, F> for JJSchnorrSignatureVar {
    fn new_variable<T: Borrow<JJSchnorrSignature>>(
        cs: impl Into<Namespace<BlsFr>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<JJSchnorrSignatureVar, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let res = f();
        res.and_then(|sig| {
            let sig = sig.borrow();

            // Signatures are Jubjub scalars. In order to use them in the circuit we need to embed them
            // into the Jubjub's scalar field (which is at least as big as the Jubjub scalar field, so
            // this is injective)
            let lifted_s = fr_to_fq::<Jubjub, BlsFr>(sig.s);
            let lifted_e = fr_to_fq::<Jubjub, BlsFr>(sig.e);

            // Construct the lifted signature
            let s_var = BlsFrV::new_variable(ns!(cs, "sig s var"), || Ok(lifted_s), mode)?;
            let e_var = BlsFrV::new_variable(ns!(cs, "sig e var"), || Ok(lifted_e), mode)?;

            Ok(JJSchnorrSignatureVar { e: e_var, s: s_var })
        })
    }
}

impl<'a> From<&'a JJSchnorrPrivkey> for JJSchnorrPubkey {
    fn from(privkey: &'a JJSchnorrPrivkey) -> JJSchnorrPubkey {
        // g^privkey is the pubkey
        let g = Jubjub::generator();
        let pubkey = g * privkey.0;
        JJSchnorrPubkey(pubkey.into_affine().into())
    }
}

impl JJSchnorrPubkey {
    fn verify(&self, msg: &BlsFr, sig: &JJSchnorrSignature) -> bool {
        // g is the public generator
        // com is the commitment g^s pubkey^e
        let g = Jubjub::generator();
        let com = g * sig.s + self.0 * sig.e;

        // e is H(com || msg)
        let mut hash_input = vec![BlsFr::from(SCHNORR_HASH_SEPARATOR)];
        hash_input.extend(com.into_affine().xy().map(|t| vec![t.0, t.1]).unwrap());
        hash_input.push(*msg);
        let digest = <Poseidon<2>>::hash(&hash_input);

        // The hash function outputs a Jubjub base field element, which we can't use as a Jubjub
        // scalar. So we convert it to bytes and truncate it to as many bits as a ScalarField
        // element can hold
        let e = {
            let digest_bits = digest.into_bigint().to_bits_le();

            // We only want the first floor(log2(p)) bits of e, where r is the prime order of the
            // scalar field. We do this by finding how many bits are needed to represent r,
            // and truncating e to that many bits
            let r_bitlen = JubjubFr::MODULUS_BIT_SIZE as usize;
            let truncated_bits = &digest_bits[..r_bitlen - 1];

            // The truncated bits now represent an integer that's less than r. This cannot fail.
            JubjubFr::from_bigint(<JubjubFr as PrimeField>::BigInt::from_bits_le(
                &truncated_bits,
            ))
            .unwrap()
        };

        e == sig.e
    }
}

impl Pubkey<F> for JJSchnorrPubkey {
    type PubkeyVar = JJSchnorrPubkeyVar;

    type Sig = JJSchnorrSignature;

    type SigVar = JJSchnorrSignatureVar;

    fn verify(&self, signature: Self::Sig, msg: F) -> bool {
        JJSchnorrPubkey::verify(self, &msg, &signature)
    }

    fn verify_zk(
        pubkey: Self::PubkeyVar,
        signature: Self::SigVar,
        msg: FpVar<F>,
    ) -> Result<Boolean<F>, SynthesisError> {
        JJSchnorrPubkeyVar::verify(&pubkey, &msg, &signature)
    }
}

impl JJSchnorrPrivkey {
    fn new(mut rng: impl Rng) -> JJSchnorrPrivkey {
        JJSchnorrPrivkey(JubjubFr::rand(&mut rng))
    }

    /// Signs the given message under `privkey`. Return value is `(s, e)` where (using sigma
    /// protocol terminology) `e` is the challenge and `s` is the response.
    fn sign(&self, mut rng: impl Rng, msg: &BlsFr) -> JJSchnorrSignature {
        // g is the public generator
        // k is the secret nonce
        // g^k is the commitment
        let g = Jubjub::generator();
        let k = JubjubFr::rand(&mut rng);
        let com = g * k;

        // e is H(com || msg)
        let mut hash_input = vec![BlsFr::from(SCHNORR_HASH_SEPARATOR)];
        hash_input.extend(com.into_affine().xy().map(|t| vec![t.0, t.1]).unwrap());
        hash_input.push(*msg);
        let digest = <Poseidon<2>>::hash(&hash_input);

        // The hash function outputs a Jubjub base field element, which we can't use as a Jubjub
        // scalar. So we convert it to bytes and truncate it to as many bits as a ScalarField
        // element can hold
        let e = {
            let digest_bits = digest.into_bigint().to_bits_le();

            // We only want the first floor(log2(p)) bits of e, where r is the prime order of the
            // scalar field. We do this by finding how many bits are needed to represent r,
            // and truncating e to that many bits
            let r_bitlen = JubjubFr::MODULUS_BIT_SIZE as usize;
            let truncated_bits = &digest_bits[..r_bitlen - 1];

            // The truncated bits now represent an integer that's less than r. This cannot fail.
            JubjubFr::from_bigint(<JubjubFr as PrimeField>::BigInt::from_bits_le(
                &truncated_bits,
            ))
            .expect("couldn't convert BaseField elem to ScalarField elem")
        };

        // s is k - e * privkey
        let s = k - (e * self.0);

        JJSchnorrSignature { e, s }
    }
}

impl Privkey<F> for JJSchnorrPrivkey {
    type CompressedPrivKey = JJSchnorrPrivkey;

    type Sig = JJSchnorrSignature;

    type Pubkey = JJSchnorrPubkey;

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
        Some(JJSchnorrPrivkey::sign(self, rng, &msg))
    }
}

impl ToConstraintField<F> for JJSchnorrPubkey {
    fn to_field_elements(&self) -> Option<Vec<F>> {
        let mut vector: Vec<F> = Vec::new();

        vector.extend_from_slice(&self.0.into_affine().x.to_field_elements().unwrap());
        vector.extend_from_slice(&self.0.into_affine().y.to_field_elements().unwrap());

        Some(vector)
    }
}

impl ToConstraintFieldGadget<F> for JJSchnorrPubkeyVar {
    fn to_constraint_field(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        self.0.to_constraint_field()
    }
}

impl R1CSVar<F> for JJSchnorrPubkeyVar {
    type Value = JJSchnorrPubkey;

    fn cs(&self) -> ConstraintSystemRef<F> {
        self.0.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(JJSchnorrPubkey { 0: self.0.value()? })
    }
}

impl AllocVar<JJSchnorrPubkey, F> for JJSchnorrPubkeyVar {
    fn new_variable<T: Borrow<JJSchnorrPubkey>>(
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
                return Ok(Self(JubjubVar::new_constant(cs.clone(), pk.0)?));
            }

            let aff_pk = pk.0.into_affine();

            let jj_v = <JubjubVar as AllocVar<Affine<JubjubConfig>, _>>::new_variable(
                ns!(cs, "entry"),
                || Ok(&aff_pk),
                mode,
            )?;

            Ok(Self(jj_v))
        })
    }
}

impl JJSchnorrPubkeyVar {
    /// Verifies the given (message, signature) pair under the given public key. All this is done in
    /// zero-knowledge.
    /// The signature is expected to have been embedded from (Fr, Fr) to (Fq, Fq). The reason we do
    /// this is because doing that let aff_pk: Affine<JubjubConfig> = pk.0.into_affine();
    //         JubjubVar::new_input(cs, || Ok(aff_pk)).map(SchnorrPubkeyVar) in ZK is cumbersome and unnecessary.
    fn verify(
        &self,
        msg: &BlsFrV,
        sig: &JJSchnorrSignatureVar,
    ) -> Result<Boolean<BlsFr>, SynthesisError> {
        let cs = self.0.cs().or(msg.cs()).or(sig.e.cs()).or(sig.s.cs());

        // Witness the group generator. This is the same across all signatures
        let g = Jubjub::generator();
        let gv = JubjubVar::new_constant(ns!(cs, "Jubjub gen"), g)?;

        // The signature is (s, e)
        // r is g^s pubkey^e
        let JJSchnorrSignatureVar { e, s } = sig;
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
        let scalar_mod_bitlen = JubjubFr::MODULUS_BIT_SIZE as usize;
        let is_equal =
            e_prime_bits[..scalar_mod_bitlen - 1].is_eq(&e_bits[..scalar_mod_bitlen - 1])?;

        // Return whether this verified
        Ok(is_equal)
    }
}

impl CondSelectGadget<BlsFr> for JJSchnorrPubkeyVar {
    fn conditionally_select(
        cond: &Boolean<BlsFr>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let selected = JubjubVar::conditionally_select(cond, &true_value.0, &false_value.0)?;
        Ok(JJSchnorrPubkeyVar(selected))
    }
}

/// The Schnorr signature scheme, on the BLS curve. Implements [`Signature`].
#[derive(Clone, Default, Debug)]
pub struct JubjubSchnorr;

impl Signature<F> for JubjubSchnorr {
    type SigVar = JJSchnorrSignatureVar;

    type Sig = JJSchnorrSignature;

    type Pubkey = JJSchnorrPubkey;

    type PubkeyVar = JJSchnorrPubkeyVar;

    type CPrivkey = JJSchnorrPrivkey;

    type Privkey = JJSchnorrPrivkey;
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
            let privkey = JJSchnorrPrivkey::new(&mut rng);
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
            let privkey = JJSchnorrPrivkey::new(&mut rng);
            let pubkey: JJSchnorrPubkey = (&privkey).into();
            let msg = BlsFr::rand(&mut rng);
            // Sign the message
            let sig = privkey.sign(&mut rng, &msg);

            // Witness all the values
            let msg_var = BlsFrV::new_input(cs.clone(), || Ok(msg))?;
            let sig_var = JJSchnorrSignatureVar::new_witness(cs.clone(), || Ok(&sig)).unwrap();
            let pubkey_var = JJSchnorrPubkeyVar::new_input(cs.clone(), || Ok(&pubkey)).unwrap();

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
