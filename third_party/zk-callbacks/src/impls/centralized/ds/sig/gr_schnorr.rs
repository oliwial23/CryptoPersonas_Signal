//! Implements Schnorr signatures over the G curve

// Adapted from SnarkBlock
// https://github.com/rozbb/snarkblock/blob/3db6736621a50d88629ce6811c2353d3bb7ed9de/src/issuance.rs

use crate::{
    crypto::hash::HasherZK,
    impls::{
        centralized::ds::sig::{Privkey, Pubkey, Signature},
        hash::Poseidon,
    },
};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, ToConstraintField, UniformRand};
use ark_grumpkin::{Fq, Fr as F, Projective as G, constraints::GVar};
use ark_r1cs_std::{
    R1CSVar,
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    convert::{ToBitsGadget, ToBytesGadget, ToConstraintFieldGadget},
    eq::EqGadget,
    fields::fp::FpVar,
    groups::CurveVar,
    select::CondSelectGadget,
    uint8::UInt8,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, Namespace, SynthesisError},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;
use std::borrow::Borrow;

type FV = FpVar<Fq>;

const SCHNORR_HASH_SEPARATOR: u8 = 0x03;

/// A private Grumpkin BN254 Schnorr signing key.
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize, Default, Debug)]
pub struct GRSchnorrPrivkey(F);

/// A public Grumpkin BN254 Schnorr verification key.
#[derive(Debug, Eq, PartialEq, Clone, Copy, CanonicalSerialize, CanonicalDeserialize)]
pub struct GRSchnorrPubkey(G);

impl Default for GRSchnorrPubkey {
    fn default() -> Self {
        Self(G::generator())
    }
}

/// A public Grumpkin BN254 Schnorr verification key in-circuit.
#[derive(Clone)]
pub struct GRSchnorrPubkeyVar(GVar);

// impl Default for GRSchnorrPubkeyVar {
//     fn default() -> Self {
//         Self(GVar::new(
//             FpVar::Constant(Fq::ZERO),
//             FpVar::Constant(Fq::ZERO),
//             FpVar::Constant(Fq::ZERO),
//         ))
//     }
// }

/// A Grumpkin BN254 Schnorr signature.
#[derive(Debug, Clone, Default, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct GRSchnorrSignature {
    /// Challenge
    e: F,
    /// Response to challenge
    s: F,
}

/// A Grumpkin BN254 Schnorr signature in-circuit.
#[derive(Clone)]
pub struct GRSchnorrSignatureVar {
    /// Challenge
    e: Vec<UInt8<Fq>>,
    /// Response to challenge
    s: Vec<UInt8<Fq>>,
}

impl AllocVar<GRSchnorrSignature, Fq> for GRSchnorrSignatureVar {
    fn new_variable<T: Borrow<GRSchnorrSignature>>(
        cs: impl Into<Namespace<Fq>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<GRSchnorrSignatureVar, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let res = f();
        res.and_then(|sig| {
            let sig = sig.borrow();

            let mut r1 = Vec::new();
            sig.s.serialize_compressed(&mut r1).unwrap();

            let mut r2 = Vec::new();
            sig.e.serialize_compressed(&mut r2).unwrap();

            let s_var = match mode {
                AllocationMode::Constant => UInt8::constant_vec(&r1),
                AllocationMode::Input => UInt8::new_input_vec(ns!(cs, "s"), &r1)?,
                AllocationMode::Witness => UInt8::new_witness_vec(ns!(cs, "s"), &r1)?,
            };

            let e_var = match mode {
                AllocationMode::Constant => UInt8::constant_vec(&r2),
                AllocationMode::Input => UInt8::new_input_vec(ns!(cs, "e"), &r2)?,
                AllocationMode::Witness => UInt8::new_witness_vec(ns!(cs, "e"), &r2)?,
            };

            // Construct the lifted signature
            Ok(GRSchnorrSignatureVar { e: e_var, s: s_var })
        })
    }
}

impl<'a> From<&'a GRSchnorrPrivkey> for GRSchnorrPubkey {
    fn from(privkey: &'a GRSchnorrPrivkey) -> GRSchnorrPubkey {
        // g^privkey is the pubkey
        let g = G::generator();
        let pubkey = g * privkey.0;
        GRSchnorrPubkey(pubkey.into_affine().into())
    }
}

impl GRSchnorrPubkey {
    fn verify(&self, msg: &Fq, sig: &GRSchnorrSignature) -> bool {
        // g is the public generator
        // com is the commitment g^s pubkey^e
        let g = G::generator();
        let com = g * sig.s + self.0 * sig.e;

        // e is H(com || msg)
        let mut hash_input = vec![Fq::from(SCHNORR_HASH_SEPARATOR)];
        hash_input.extend(com.into_affine().xy().map(|t| vec![t.0, t.1]).unwrap());
        hash_input.push(*msg);
        let digest = <Poseidon<2>>::hash(&hash_input);

        // The hash function outputs a G base field element, which we can't use as a G
        // scalar. So we convert it to bytes and truncate it to as many bits as a ScalarField
        // element can hold
        let e = {
            let digest_bits = digest.into_bigint().to_bits_le();

            // The truncated bits now represent an integer that's less than r. This cannot fail.
            F::from_bigint(<F as PrimeField>::BigInt::from_bits_le(&digest_bits)).unwrap()
        };

        e == sig.e
    }
}

impl Pubkey<Fq> for GRSchnorrPubkey {
    type PubkeyVar = GRSchnorrPubkeyVar;

    type Sig = GRSchnorrSignature;

    type SigVar = GRSchnorrSignatureVar;

    fn verify(&self, signature: Self::Sig, msg: Fq) -> bool {
        GRSchnorrPubkey::verify(self, &msg, &signature)
    }

    fn verify_zk(
        pubkey: Self::PubkeyVar,
        signature: Self::SigVar,
        msg: FpVar<Fq>,
    ) -> Result<Boolean<Fq>, SynthesisError> {
        GRSchnorrPubkeyVar::verify(&pubkey, &msg, &signature)
    }
}

impl GRSchnorrPrivkey {
    fn new(mut rng: impl Rng) -> GRSchnorrPrivkey {
        GRSchnorrPrivkey(F::rand(&mut rng))
    }

    /// Signs the given message under `privkey`. Return value is `(s, e)` where (using sigma
    /// protocol terminology) `e` is the challenge and `s` is the response.
    fn sign(&self, mut rng: impl Rng, msg: &Fq) -> GRSchnorrSignature {
        // g is the public generator
        // k is the secret nonce
        // g^k is the commitment
        let g = G::generator();
        let k = F::rand(&mut rng);
        let com = g * k;

        // e is H(com || msg)

        let mut hash_input = vec![Fq::from(SCHNORR_HASH_SEPARATOR)];
        hash_input.extend(com.into_affine().xy().map(|t| vec![t.0, t.1]).unwrap());
        hash_input.push(*msg);
        let digest: Fq = <Poseidon<2>>::hash(&hash_input);

        // The hash function outputs a G base field element, which we can't use as a G
        // scalar. So we convert it to bytes and truncate it to as many bits as a ScalarField
        // element can hold
        let e = {
            let digest_bytes = digest.into_bigint().to_bytes_le();
            F::from_le_bytes_mod_order(&digest_bytes)
            //F::from_bigint(<F as PrimeField>::BigInt::from_bits_le(&digest_bits))
            //.expect("couldn't convert BaseField elem to ScalarField elem")
        };

        // s is k - e * privkey
        let s = k - (e * self.0);

        GRSchnorrSignature { e, s }
    }
}

impl Privkey<Fq> for GRSchnorrPrivkey {
    type CompressedPrivKey = GRSchnorrPrivkey;

    type Sig = GRSchnorrSignature;

    type Pubkey = GRSchnorrPubkey;

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

    fn sign(&self, rng: &mut (impl rand::CryptoRng + rand::RngCore), msg: Fq) -> Option<Self::Sig> {
        Some(GRSchnorrPrivkey::sign(self, rng, &msg))
    }
}

impl ToConstraintField<Fq> for GRSchnorrPubkey {
    fn to_field_elements(&self) -> Option<Vec<Fq>> {
        let mut vector: Vec<Fq> = Vec::new();

        vector.extend_from_slice(&self.0.into_affine().x.to_field_elements().unwrap());
        vector.extend_from_slice(&self.0.into_affine().y.to_field_elements().unwrap());
        vector.push(Fq::from(!self.0.into_affine().infinity));

        Some(vector)
    }
}

impl ToConstraintFieldGadget<Fq> for GRSchnorrPubkeyVar {
    fn to_constraint_field(&self) -> Result<Vec<FpVar<Fq>>, SynthesisError> {
        let mut vector: Vec<FpVar<Fq>> = Vec::new();

        vector.extend_from_slice(&self.0.to_affine()?.x.to_constraint_field()?);
        vector.extend_from_slice(&self.0.to_affine()?.y.to_constraint_field()?);
        vector.extend((!self.0.to_affine()?.infinity).to_constraint_field()?);

        Ok(vector)
    }
}

impl R1CSVar<Fq> for GRSchnorrPubkeyVar {
    type Value = GRSchnorrPubkey;

    fn cs(&self) -> ConstraintSystemRef<Fq> {
        self.0.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(GRSchnorrPubkey(self.0.value()?))
    }
}

impl AllocVar<GRSchnorrPubkey, Fq> for GRSchnorrPubkeyVar {
    fn new_variable<T: Borrow<GRSchnorrPubkey>>(
        cs: impl Into<Namespace<Fq>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();

        res.and_then(|pk| {
            let pk = pk.borrow();
            let jj_v = GVar::new_variable(ns!(cs, "entry"), || Ok(pk.0), mode)?;

            Ok(Self(jj_v))
        })
    }
}

impl GRSchnorrPubkeyVar {
    /// Verifies the given (message, signature) pair under the given public key. All this is done in
    /// zero-knowledge.
    /// The signature is expected to have been embedded from (Fr, Fr) to (Fq, Fq). The reason we do
    /// this is because doing that let aff_pk: Affine<GConfig> = pk.0.into_affine();
    //         GVar::new_input(cs, || Ok(aff_pk)).map(SchnorrPubkeyVar) in ZK is cumbersome and unnecessary.
    fn verify(&self, msg: &FV, sig: &GRSchnorrSignatureVar) -> Result<Boolean<Fq>, SynthesisError> {
        let cs = self.0.cs().or(msg.cs()).or(sig.e.cs()).or(sig.s.cs());

        // Witness the group generator. This is the same across all signatures
        let g = G::generator();
        let gv = GVar::new_constant(ns!(cs, "G gen"), g)?;

        // The signature is (s, e)
        // r is g^s pubkey^e
        let GRSchnorrSignatureVar { e, s } = sig;
        let r = {
            // Computs g^s
            let s_bits = s
                .iter()
                .flat_map(|b| b.to_bits_le().unwrap())
                .collect::<Vec<_>>();
            let g_s = gv.scalar_mul_le(s_bits.iter())?;
            // Compute pubkey^e
            let e_bits = e
                .iter()
                .flat_map(|b| b.to_bits_le().unwrap())
                .collect::<Vec<_>>();
            let pubkey_e = self.0.scalar_mul_le(e_bits.iter())?;

            // Add them
            g_s + pubkey_e
        };

        // e' is H(r || msg). This should be equal to the given e, up to Fr::size() many bits
        let hash_input = vec![
            FpVar::Constant(Fq::from(SCHNORR_HASH_SEPARATOR)),
            r.to_affine()?.x,
            r.to_affine()?.y,
            msg.clone(),
        ];
        let e_prime = <Poseidon<2>>::hash_in_zk(&hash_input)?;

        // Show that e' and e agree for all the bits up to the bitlength of the scalar field's modulus.
        // We check the truncation because we have to use the truncation of e as a scalar field element
        // (since e is naturally a base field element and too big to be a scalar field element).
        let e_prime_bytes = e_prime.to_bytes_le()?;
        // let base_mod_bitlen = F::MODULUS_BIT_SIZE as usize;
        let mut eq = Boolean::TRUE;

        for i in 0..e_prime_bytes.len() {
            eq &= e_prime_bytes[i].is_eq(&e[i])?;
        }

        // Return whether this verified
        Ok(eq)
    }
}

impl CondSelectGadget<Fq> for GRSchnorrPubkeyVar {
    fn conditionally_select(
        cond: &Boolean<Fq>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let selected = GVar::conditionally_select(cond, &true_value.0, &false_value.0)?;
        Ok(GRSchnorrPubkeyVar(selected))
    }
}

/// The Schnorr signature scheme, on the BN254 curve. Implements [`Signature`].
#[derive(Clone, Default, Debug)]
pub struct GrumpkinSchnorr;

impl Signature<Fq> for GrumpkinSchnorr {
    type SigVar = GRSchnorrSignatureVar;

    type Sig = GRSchnorrSignature;

    type Pubkey = GRSchnorrPubkey;

    type PubkeyVar = GRSchnorrPubkeyVar;

    type CPrivkey = GRSchnorrPrivkey;

    type Privkey = GRSchnorrPrivkey;
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
            let privkey = GRSchnorrPrivkey::new(&mut rng);

            let pubkey = privkey.get_pubkey();

            let msg = Fq::rand(&mut rng);

            // Sign the random message under the random privkey
            let sig = privkey.sign(&mut rng, &msg);

            assert!(pubkey.verify(&msg, &sig));
        }
    }

    // Tests that the verification circuit is satisfied iff the signature is valid
    #[test]
    fn schnorr_verify() -> Result<(), SynthesisError> {
        let mut rng = thread_rng();

        for _ in 0..10 {
            let cs = ConstraintSystem::<Fq>::new_ref();

            // Make a random keypair and message
            let privkey = GRSchnorrPrivkey::new(&mut rng);
            let pubkey: GRSchnorrPubkey = (&privkey).into();
            let msg = Fq::rand(&mut rng);
            // Sign the message
            let sig = privkey.sign(&mut rng, &msg);

            // Witness all the values
            let msg_var = FV::new_input(cs.clone(), || Ok(msg))?;
            let sig_var = GRSchnorrSignatureVar::new_witness(cs.clone(), || Ok(&sig)).unwrap();
            let pubkey_var = GRSchnorrPubkeyVar::new_input(cs.clone(), || Ok(&pubkey)).unwrap();

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
