use rand::{CryptoRng, RngCore};

/// A rerandomizable signature private key.
///
/// Specifically, the rerandomizability allows anyone with a public verification key `vk` to generate a new public
/// key `r * vk`. Given `r`, the owner of the secret key can generate the corresponding secret
/// signing key
/// `r * sk`.
///
/// One example of this is ECDSA, where the private key is a scalar x and the private key is a
/// point xG. A rerandomized pair is then (rx, (rx)G).
///
/// Here, [`RRSigner`] is a secret key with the corresponding verifying key `V`.
/// # Example (BLS Signatures):
///
/// ```rust
/// # use zk_callbacks::crypto::rr::{RRVerifier, RRSigner};
/// # use ark_bls12_381::{Fr, Fq, G1Projective, G2Projective};
/// # use rand::{Rng, CryptoRng, RngCore, thread_rng};
/// # use ark_ec::PrimeGroup;
/// # #[derive(Debug, PartialEq)]
/// struct BlsPubkey(pub G2Projective);
/// #
/// # impl RRVerifier<G1Projective, G1Projective, Fr> for BlsPubkey {
/// #     fn verify(&self, message: G1Projective, signature: G1Projective) -> bool {
/// #         todo!()
/// #     }
/// #
/// #     fn rerand(&self, rng: &mut (impl CryptoRng + RngCore)) -> (Fr, Self) {
/// #         let out = rng.gen();
/// #         (out, Self(self.0 * out))
/// #     }
/// # }
///
/// struct BlsPrivkey(pub Fr);
///
/// impl RRSigner<G1Projective, G1Projective, Fr, BlsPubkey> for BlsPrivkey {
///     fn sign_message(&self, message: &G1Projective) -> G1Projective {
///         *message * self.0
///     }
///
///     fn sk_to_pk(&self) -> BlsPubkey {
///         BlsPubkey(G2Projective::generator() * self.0)
///     }
///
///     fn gen(rng: &mut (impl CryptoRng + RngCore)) -> Self {
///         Self(rng.gen())
///     }
///
///     fn rerand(&self, randomness: Fr) -> Self {
///         Self(self.0 * randomness)
///     }
/// }
///
/// fn main() {
///     let mut rng = thread_rng();
///
///     // Generate BLS Private Key
///     let sk = BlsPrivkey::gen(&mut rng);
///
///     // Constuct associated BLS Public Key
///     let vk = sk.sk_to_pk();
///
///     // Generate rerandomized BLS public Key
///     let (rand, vk2) = vk.rerand(&mut rng);
///
///     // Identically rerandomize the BLS secret key and check that they coincide
///     assert_eq!(sk.rerand(rand).sk_to_pk(), vk2);
/// }
/// ```
pub trait RRSigner<S, M, R, V: RRVerifier<S, M, R>> {
    /// The verifying key, which implements [`RRVerifier`].
    type Vk = V;

    /// Sign a message of type `M` and return a signature `S`.
    fn sign_message(&self, message: &M) -> S;

    /// Convert the secret signing key into a public verifying key.
    fn sk_to_pk(&self) -> V;

    /// Generate a new random secret key.
    fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self;

    /// Given some randomness `R`, output the new secret key `r * sk` given by rerandomizing the
    /// current secret key.
    fn rerand(&self, randomness: R) -> Self;
}

/// A rerandomizable signature public key.
///
/// Any user with a public verification key `vk` can rerandomize the key to a new public key `r *
/// vk`.
/// # Example (BLS Signatures):
///
/// ```rust
/// # use zk_callbacks::crypto::rr::{RRVerifier, RRSigner};
/// # use ark_bls12_381::{Bls12_381 as Bls12, Fr, Fq, G1Projective, G2Projective};
/// # use rand::{Rng, CryptoRng, RngCore, thread_rng};
/// # use ark_ec::PrimeGroup;
/// # use ark_ec::pairing::Pairing;
/// struct BlsPrivkey(pub Fr);
///
/// # #[derive(Debug, PartialEq)]
/// struct BlsPubkey(pub G2Projective);
///
/// impl RRVerifier<G1Projective, G1Projective, Fr> for BlsPubkey {
///     fn verify(&self, message: G1Projective, signature: G1Projective) -> bool {
///         let p1 = Bls12::pairing(signature, G2Projective::generator());
///         let p2 = Bls12::pairing(message, self.0);
///         p1 == p2
///     }
///
///     fn rerand(&self, rng: &mut (impl CryptoRng + RngCore)) -> (Fr, Self) {
///         let out = rng.gen();
///         (out, Self(self.0 * out))
///     }
/// }
/// #
/// #
/// # impl RRSigner<G1Projective, G1Projective, Fr, BlsPubkey> for BlsPrivkey {
/// #     fn sign_message(&self, message: &G1Projective) -> G1Projective {
/// #         *message * self.0
/// #     }
/// #
/// #     fn sk_to_pk(&self) -> BlsPubkey {
/// #         BlsPubkey(G2Projective::generator() * self.0)
/// #     }
/// #
/// #     fn gen(rng: &mut (impl CryptoRng + RngCore)) -> Self {
/// #         Self(rng.gen())
/// #     }
/// #
/// #     fn rerand(&self, randomness: Fr) -> Self {
/// #         Self(self.0 * randomness)
/// #     }
/// # }
///
/// fn main() {
///     let mut rng = thread_rng();
///
///     // Generate BLS Private Key
///     let sk = BlsPrivkey::gen(&mut rng);
///
///     // Constuct associated BLS Public Key
///     let vk = sk.sk_to_pk();
///
///     // Generate rerandomized BLS public Key
///     let (rand, vk2) = vk.rerand(&mut rng);
///
///     // Identically rerandomize the BLS secret key and check that they coincide
///     assert_eq!(sk.rerand(rand).sk_to_pk(), vk2);
/// }
/// ```
pub trait RRVerifier<S, M, R> {
    /// Verify a signature on a message.
    fn verify(&self, message: M, signature: S) -> bool;

    /// Rerandomize the current verification key into a new verification key. Outputs the
    /// randomness `r` such that an [`RRSigner`] can compute the corresponding private key using
    /// `r` and `sk`.
    fn rerand(&self, rng: &mut (impl CryptoRng + RngCore)) -> (R, Self);
}
