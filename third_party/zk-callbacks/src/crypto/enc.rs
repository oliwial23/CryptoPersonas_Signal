use crate::crypto::rr::{RRSigner, RRVerifier};
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{convert::ToConstraintFieldGadget, prelude::AllocVar};
use ark_relations::r1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{CryptoRng, RngCore};

/// An IND-CPA encryption scheme.
///
/// This captures any encryption scheme which is IND-CPA secure, along with performing encryption
/// and decryption inside an arithmetic circuit. Encryptions are only done once per key. Note that
/// the one time pad meets the definition, and *can* be used.
///
/// This trait should be implemented on the *Key type*, as the key will be used to encrypt
/// messages.
///
/// # Example (One Time Pad)
///
/// ```rust
/// # use ark_ff::ToConstraintField;
/// # use ark_ff::PrimeField;
/// # use ark_r1cs_std::prelude::UInt8;
/// # use rand::distributions::Standard;
/// # use rand::prelude::Distribution;
/// # use zk_callbacks::crypto::enc::CPACipher;
/// # use ark_r1cs_std::prelude::AllocationMode;
/// # use ark_relations::r1cs::SynthesisError;
/// # use std::borrow::Borrow;
/// # use ark_relations::r1cs::Namespace;
/// # use ark_r1cs_std::prelude::AllocVar;
/// # use ark_relations::ns;
/// # use ark_r1cs_std::fields::fp::FpVar;
/// # use ark_r1cs_std::convert::ToConstraintFieldGadget;
/// # use ark_r1cs_std::convert::ToBitsGadget;
/// # use rand::{Rng, RngCore, CryptoRng};
/// # #[derive(Clone)]
/// struct OTP(pub u8);
///
/// # impl<F: PrimeField> ToConstraintField<F> for OTP {
/// #   fn to_field_elements(&self) -> Option<Vec<F>> {
/// #       Some(vec![F::from(self.0 & 1), F::from((self.0 >> 1) & 1), F::from((self.0 >> 2) & 1),
/// # F::from((self.0 >> 3) & 1), F::from((self.0 >> 4) & 1), F::from((self.0 >> 5) & 1),
/// # F::from((self.0 >> 6) & 1), F::from((self.0 >> 7) & 1)])
/// #   }
/// # }
/// # #[derive(Clone)]
/// struct OTPVar<F: PrimeField>(pub UInt8<F>);
/// # impl<F: PrimeField> AllocVar<OTP, F> for OTPVar<F> {
/// #   fn new_variable<T: Borrow<OTP>>(
/// #       cs: impl Into<Namespace<F>>,
/// #       f: impl FnOnce() -> Result<T, SynthesisError>,
/// #       mode: AllocationMode
/// # ) -> Result<Self, SynthesisError> {
/// #       let ns = cs.into();
/// #       let cs = ns.cs();
/// #       let res = f();
/// #       res.and_then(|rec| {
/// #           let rec = rec.borrow();
/// #           let t = UInt8::new_variable(ns!(cs, "key"), || Ok(rec.0), mode)?;
/// #           Ok(Self(t))
/// #       })
/// # }
/// # }
/// # impl<F: PrimeField> ToConstraintFieldGadget<F> for OTPVar<F> {
/// #   fn to_constraint_field(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
/// #       Ok(self.0.to_bits_le()?.iter().map(|x| x.to_constraint_field().unwrap()).flatten().collect())
/// # }
/// # }
///
/// impl<F: PrimeField> CPACipher<F> for OTP where Standard: Distribution<F> {
///     type M = u8;
///
///     type C = u8;
///
///     type MV = UInt8<F>;
///
///     type CV = UInt8<F>;
///
///     type KeyVar = OTPVar<F>;
///
///     fn keygen(rng: &mut (impl CryptoRng + RngCore)) -> Self {
///         Self(rng.gen::<u8>())
///     }
///
///     fn encrypt(&self, message: u8) -> u8 {
///         self.0 ^ message
///     }
///
///     fn decrypt(&self, ciphertext: u8) -> u8 {
///         self.0 ^ ciphertext
///     }
///
///     fn decrypt_in_zk(key: OTPVar<F>, ciphertext: UInt8<F>) -> Result<UInt8<F>, SynthesisError>
///     {
///         Ok(key.0 ^ ciphertext)
///     }
/// }
/// ```
pub trait CPACipher<F: PrimeField> {
    /// The representation of the key in-circuit.
    type KeyVar: AllocVar<Self, F> + Clone + ToConstraintFieldGadget<F>;

    /// The message type being encrypted.
    type M;

    /// The ciphertext type.
    type C;

    /// The message type in circuit.
    type MV: AllocVar<Self::M, F>;

    /// The ciphertext type in circuit.
    type CV: AllocVar<Self::C, F> + Clone;

    /// Generate a random key.
    fn keygen(rng: &mut (impl CryptoRng + RngCore)) -> Self;

    /// Encrypt a message using the key, and output a ciphertext.
    fn encrypt(&self, message: Self::M) -> Self::C;

    /// Decrypt a ciphertext with the key, and output a plaintext message.
    fn decrypt(&self, ciphertext: Self::C) -> Self::M;

    /// Decrypt a ciphertext representation in zero knowledge, using a key in circuit.
    fn decrypt_in_zk(key: Self::KeyVar, ciphertext: Self::CV) -> Result<Self::MV, SynthesisError>;
}

/// A combined trait which allows for encryption and signatures on messages. This is extremely
/// important to the system, as this is what allows for services to encrypt and sign arguments when
/// they call a callback, and furthermore users can prove correct decryption in circuit.
///
/// This trait is a combination of [`CPACipher`],
/// [`RRVerifier`](`crate::crypto::rr::RRVerifier`), and
/// [`RRSigner`](`crate::crypto::rr::RRSigner`) for authenticated encryption.
///
/// Note that the trait takes in a generic type `Args`, which is the message type being encrypted.
pub trait AECipherSigZK<F: PrimeField, Args: Clone>: Clone + std::fmt::Debug {
    /// The ciphertext type: the encrypted arguments.
    type Ct: Clone + Default;

    /// The arguments in-circuit.
    type AV: AllocVar<Args, F>;

    /// An encryption key which encrypts `Args` to `Ct`.
    type EncKey: CPACipher<F, C = Self::Ct, M = Args, MV = Self::AV, KeyVar = Self::EncKeyVar>
        + ToConstraintField<F>
        + CanonicalSerialize
        + CanonicalDeserialize
        + Clone
        + Eq
        + std::fmt::Debug
        + Default;

    /// The encryption key in-circuit.
    type EncKeyVar: AllocVar<Self::EncKey, F> + ToConstraintFieldGadget<F> + Clone;

    /// The signature on `Ct`.
    type Sig: Clone + Default;

    /// The randomness used for rerandomizing the signature public keys.
    type Rand: std::fmt::Debug + Clone + CanonicalSerialize + CanonicalDeserialize;

    /// The signature verification key, which verifies `Sig` on `Ct`. It is rerandomizable by `Rand`.
    type SigPK: RRVerifier<Self::Sig, Self::Ct, Self::Rand>
        + ToConstraintField<F>
        + CanonicalSerialize
        + CanonicalDeserialize
        + Clone
        + Eq
        + std::fmt::Debug
        + Default;

    /// The signature verification key in circuit.
    type SigPKV: AllocVar<Self::SigPK, F> + ToConstraintFieldGadget<F> + Clone;

    /// The signature secret key, which can produce signatures `Sig` on `Ct`, and can be
    /// rerandomized by `Rand`.
    type SigSK: RRSigner<Self::Sig, Self::Ct, Self::Rand, Self::SigPK>;

    /// Encrypt a message with an encryption key, and additionally sign the ciphertext.
    fn encrypt_and_sign(
        message: Args,
        enc_key: Self::EncKey,
        sig_sk: Self::SigSK,
    ) -> (Self::Ct, Self::Sig) {
        let enc = enc_key.encrypt(message);
        let sig = sig_sk.sign_message(&enc);

        (enc, sig)
    }
}
