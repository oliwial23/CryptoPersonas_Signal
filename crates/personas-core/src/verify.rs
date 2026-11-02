//! Groth16 verification against a verifying key PREPARED ONCE.
//!
//! `SNARK::verify` is `process_vk` followed by `verify_with_processed_vk`, and repeats the
//! first step — the pairing `e(α, β)` and preparing the `γ`, `δ` G2 points, none of which
//! depends on the proof — on every call. [`PreparedVk`] does it once, on first use, and
//! reuses it. Same check, same result; only the repeated work is gone.

use ark_snark::SNARK;

use crate::{F, Snark, VK};

/// Something a proof can be checked against: a plain [`VK`] (prepared on every call,
/// the old way) or a [`PreparedVk`].
pub trait ProofVerifier {
    fn verify_proof(&self, inputs: &[F], proof: &<Snark as SNARK<F>>::Proof) -> bool;
}

impl ProofVerifier for VK {
    fn verify_proof(&self, inputs: &[F], proof: &<Snark as SNARK<F>>::Proof) -> bool {
        Snark::verify(self, inputs, proof).unwrap_or(false)
    }
}

/// A verifying key with its processing cached (see the module docs).
pub struct PreparedVk {
    vk: VK,
    processed: std::sync::OnceLock<Option<<Snark as SNARK<F>>::ProcessedVerifyingKey>>,
}

impl PreparedVk {
    pub fn new(vk: &VK) -> Self {
        Self {
            vk: vk.clone(),
            processed: std::sync::OnceLock::new(),
        }
    }

    /// `Snark::verify(vk, inputs, proof)`, with the processing step cached.
    pub fn verify(&self, inputs: &[F], proof: &<Snark as SNARK<F>>::Proof) -> bool {
        match self
            .processed
            .get_or_init(|| Snark::process_vk(&self.vk).ok())
        {
            Some(pvk) => Snark::verify_with_processed_vk(pvk, inputs, proof).unwrap_or(false),
            // A key that cannot be processed verifies nothing — what `Snark::verify`
            // returns for it too.
            None => false,
        }
    }
}

impl ProofVerifier for PreparedVk {
    fn verify_proof(&self, inputs: &[F], proof: &<Snark as SNARK<F>>::Proof) -> bool {
        self.verify(inputs, proof)
    }
}
