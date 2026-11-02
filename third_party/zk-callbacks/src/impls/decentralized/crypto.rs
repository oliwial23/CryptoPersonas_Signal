use ark_crypto_primitives::sponge::{
    Absorb, CryptographicSponge,
    constraints::CryptographicSpongeVar as _,
    poseidon::{PoseidonSponge, constraints::PoseidonSpongeVar},
};
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField, ToConstraintField};
use ark_r1cs_std::{
    R1CSVar, alloc::AllocVar, convert::ToConstraintFieldGadget, fields::fp::FpVar, uint8::UInt8,
};
use ark_relations::{ns, r1cs::SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::{Blake2s256 as Blake, Digest};
use rand::{CryptoRng, Rng, RngCore, distributions::Standard, prelude::Distribution, thread_rng};
use std::marker::PhantomData;

use crate::{
    crypto::{
        enc::{AECipherSigZK, CPACipher},
        rr::{RRSigner, RRVerifier},
    },
    util::{ArrayVar, gen_poseidon_params},
};

/// Encryption key (IND-CPA) for a Poseidon-based stream cipher.
#[derive(
    Clone, Debug, PartialEq, Eq, Default, CanonicalSerialize, CanonicalDeserialize, PartialOrd, Ord,
)]
pub struct StreamKey<F: CanonicalSerialize + CanonicalDeserialize, const N: usize> {
    key: F,
    phantom_max_size: PhantomData<[(); N]>,
}

impl<F: PrimeField, const N: usize> ToConstraintField<F> for StreamKey<F, N> {
    fn to_field_elements(&self) -> Option<Vec<F>> {
        self.key.to_field_elements()
    }
}

impl<F: CanonicalDeserialize + CanonicalSerialize + Clone, const N: usize> StreamKey<F, N> {
    /// Construct a new encryption key from a field element.
    pub fn new(f: F) -> Self {
        Self {
            key: f,
            phantom_max_size: PhantomData,
        }
    }

    /// Convert an encryption key to a field element.
    pub fn to(&self) -> F {
        self.key.clone()
    }
}

/// Encryption keey in-circuit.
#[derive(Clone)]
pub struct StreamKeyVar<F: PrimeField, const N: usize> {
    key: FpVar<F>,
    phantom_max_size: PhantomData<[(); N]>,
}

impl<F: PrimeField, const N: usize> AllocVar<StreamKey<F, N>, F> for StreamKeyVar<F, N> {
    fn new_variable<T: std::borrow::Borrow<StreamKey<F, N>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();
        res.and_then(|rec| {
            let rec = rec.borrow();
            let key = FpVar::new_variable(ns!(cs, "key"), || Ok(rec.key), mode)?;
            Ok(Self {
                key,
                phantom_max_size: PhantomData,
            })
        })
    }
}

impl<F: PrimeField, const N: usize> ToConstraintFieldGadget<F> for StreamKeyVar<F, N> {
    fn to_constraint_field(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        self.key.to_constraint_field()
    }
}

/// A ciphertext (encrypted arguments).
#[derive(Clone)]
pub struct Ciphertext<F: PrimeField, const K: usize>(pub [F; K]);

impl<F: PrimeField, const K: usize> Default for Ciphertext<F, K> {
    fn default() -> Self {
        Self([F::from(0); K])
    }
}

/// The encrypted arguments in-circuit.
#[derive(Clone)]
pub struct CiphertextVar<F: PrimeField, const K: usize>(pub [FpVar<F>; K]);

impl<F: PrimeField, const K: usize> AllocVar<Ciphertext<F, K>, F> for CiphertextVar<F, K> {
    fn new_variable<T: std::borrow::Borrow<Ciphertext<F, K>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();
        res.and_then(|rec| {
            let rec = rec.borrow();
            let ct = <ArrayVar<FpVar<F>, K>>::new_variable(ns!(cs, "ct"), || Ok(rec.0), mode)?;
            Ok(Self(ct.0))
        })
    }
}

impl<F: PrimeField + Absorb, const N: usize> CPACipher<F> for StreamKey<F, N>
where
    Standard: Distribution<F>,
    [(); N + 1]:,
{
    type M = [F; N];
    type C = Ciphertext<F, { N + 1 }>;
    type MV = [FpVar<F>; N];
    type CV = CiphertextVar<F, { N + 1 }>;

    type KeyVar = StreamKeyVar<F, N>;

    fn keygen(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self {
            key: rng.r#gen(),
            phantom_max_size: PhantomData,
        }
    }

    fn encrypt(&self, message: Self::M) -> Self::C {
        let mut rng = thread_rng();
        let nonce: F = rng.r#gen();
        let mut sponge: PoseidonSponge<F> = PoseidonSponge::new(&gen_poseidon_params(2, false));
        sponge.absorb(&self.to());
        sponge.absorb(&nonce);
        let keystream: Vec<F> = sponge.squeeze_field_elements(N);
        let mut ct = (0..N)
            .map(|x| message[x] + keystream[x])
            .collect::<Vec<_>>();
        ct.push(nonce);
        Ciphertext(ct.try_into().unwrap())
    }

    fn decrypt(&self, ciphertext: Self::C) -> Self::M {
        let mut sponge: PoseidonSponge<F> = PoseidonSponge::new(&gen_poseidon_params(2, false));
        sponge.absorb(&self.to());
        sponge.absorb(&ciphertext.0[N]);
        let keystream: Vec<F> = sponge.squeeze_field_elements(N);
        let msg = (0..N)
            .map(|x| ciphertext.0[x] + keystream[x])
            .collect::<Vec<_>>();
        msg.try_into().unwrap()
    }

    fn decrypt_in_zk(key: Self::KeyVar, ciphertext: Self::CV) -> Result<Self::MV, SynthesisError> {
        let mut sponge =
            PoseidonSpongeVar::new(ciphertext.0[N].cs(), &gen_poseidon_params(2, false));
        sponge.absorb(&key.key)?;
        sponge.absorb(&ciphertext.0[N])?;
        let keystream: Vec<FpVar<F>> = sponge.squeeze_field_elements(N)?;
        let msg = (0..N)
            .map(|x| ciphertext.0[x].clone() + keystream[x].clone())
            .collect::<Vec<_>>();
        Ok(msg.try_into().unwrap())
    }
}

/// A Schnorr signing key. Implements [`RRSigner`].
pub struct SchnorrPrivkey<E: CurveGroup> {
    sk: E::ScalarField,
}

/// A Schnorr verification key. Implements [`RRVerifier`].
#[derive(Default, Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SchnorrPubkey<E: CurveGroup> {
    key: E::Affine,
}

impl<F: PrimeField, E: CurveGroup> ToConstraintField<F> for SchnorrPubkey<E> {
    fn to_field_elements(&self) -> Option<Vec<F>> {
        let mut bytes = vec![];
        self.key.serialize_compressed(&mut bytes).unwrap();
        Some(
            bytes
                .into_iter()
                .map(|x| F::from(x)) // might break if field is small, take note
                .collect::<Vec<_>>(),
        )
    }
}

/// The Schnorr public key in-circuit.
#[derive(Clone)]
pub struct SchnorrPubkeyVar<F: PrimeField> {
    key_ser: Vec<UInt8<F>>,
}

impl<F: PrimeField, E: CurveGroup> AllocVar<SchnorrPubkey<E>, F> for SchnorrPubkeyVar<F> {
    fn new_variable<T: std::borrow::Borrow<SchnorrPubkey<E>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();
        res.and_then(|rec| {
            let rec = rec.borrow();
            let mut serkey = Vec::new();
            rec.key.serialize_compressed(&mut serkey).unwrap();
            let key_ser = <Vec<UInt8<F>>>::new_variable(ns!(cs, "ser_key"), || Ok(serkey), mode)?;
            Ok(Self { key_ser })
        })
    }
}

impl<F: PrimeField> ToConstraintFieldGadget<F> for SchnorrPubkeyVar<F> {
    fn to_constraint_field(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        self.key_ser.to_constraint_field()
    }
}

/// A Schnorr signature.
#[derive(Default, Clone, Debug)]
pub struct SchnorrSig<E: CurveGroup> {
    challenge: E::ScalarField,
    response: E::ScalarField,
}

impl<E: CurveGroup, F: PrimeField, const N: usize>
    RRVerifier<SchnorrSig<E>, Ciphertext<F, N>, E::ScalarField> for SchnorrPubkey<E>
where
    Standard: Distribution<E::ScalarField>,
{
    fn verify(&self, message: Ciphertext<F, N>, signature: SchnorrSig<E>) -> bool {
        let mut claimed_com = self.key * signature.challenge;
        let full = E::generator() * signature.response;
        claimed_com += full;
        let claimed = claimed_com.into_affine();

        let mut v = vec![];
        claimed.serialize_compressed(&mut v).unwrap();
        message.0.serialize_compressed(&mut v).unwrap();
        let chall = if let Some(claimed_e) = E::ScalarField::from_random_bytes(&Blake::digest(&v)) {
            claimed_e
        } else {
            return false;
        };
        chall == signature.challenge
    }

    fn rerand(&self, rng: &mut (impl CryptoRng + RngCore)) -> (E::ScalarField, Self) {
        let f = rng.r#gen();
        (
            f,
            Self {
                key: (self.key * f).into(),
            },
        )
    }
}

impl<E: CurveGroup, F: PrimeField, const N: usize>
    RRSigner<SchnorrSig<E>, Ciphertext<F, N>, E::ScalarField, SchnorrPubkey<E>>
    for SchnorrPrivkey<E>
where
    Standard: Distribution<E::ScalarField>,
    E::ScalarField: Absorb,
    F: CanonicalSerialize,
{
    type Vk = SchnorrPubkey<E>;

    fn sign_message(&self, message: &Ciphertext<F, N>) -> SchnorrSig<E> {
        let (rand, chall) = loop {
            let mut rng = thread_rng();
            let randomness = rng.r#gen();
            let com = E::generator() * randomness;
            let mut v = vec![];
            com.serialize_compressed(&mut v).unwrap();
            message.0.serialize_compressed(&mut v).unwrap();
            if let Some(challenge) = E::ScalarField::from_random_bytes(&Blake::digest(&v)) {
                break (randomness, challenge);
            }
        };
        let resp = rand - (self.sk * chall);
        SchnorrSig {
            challenge: chall,
            response: resp,
        }
    }

    fn sk_to_pk(&self) -> SchnorrPubkey<E> {
        SchnorrPubkey {
            key: (E::generator() * self.sk).into(),
        }
    }

    fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self { sk: rng.r#gen() }
    }

    fn rerand(&self, randomness: E::ScalarField) -> Self {
        Self {
            sk: randomness * self.sk,
        }
    }
}

/// This type implements AECipherSigZK. This uses a Poseidon based stream cipher for encryption of
/// arguments, and signs arguments with a Schnorr signature (which is rerandomizable!).
///
/// This is what should be used whenever a callback ticket post is necessary in a decentralized
/// setting. This way, service providers can show authenticity of called tickets via rerandomized
/// Schnorr signatures.
#[derive(Clone, Debug)]
pub struct StreamSchnorr<F: PrimeField + Absorb, E: CurveGroup, const N: usize>
where
    [(); N + 1]:,
{
    phantom: PhantomData<[F; N]>,
    phantom_e: PhantomData<E>,
}

impl<F: PrimeField + Absorb, E: CurveGroup, const N: usize> AECipherSigZK<F, [F; N]>
    for StreamSchnorr<F, E, N>
where
    [(); N + 1]:,
    Standard: Distribution<F>,
    Standard: Distribution<E::ScalarField>,
    E::ScalarField: Absorb,
    F: Default,
{
    type Ct = Ciphertext<F, { N + 1 }>;

    type AV = [FpVar<F>; N];

    type EncKey = StreamKey<F, N>;

    type EncKeyVar = StreamKeyVar<F, N>;

    type Sig = SchnorrSig<E>;

    type Rand = E::ScalarField;

    type SigPK = SchnorrPubkey<E>;

    type SigPKV = SchnorrPubkeyVar<F>;

    type SigSK = SchnorrPrivkey<E>;
}
