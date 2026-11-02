//! R1CS sizes, measured on the circuit definitions the production keys come from.
//!
//! A stand-in SNARK whose "setup" synthesizes the circuit the way Groth16's setup does
//! (setup mode, optimized for constraints, finalized) and reports its size instead of
//! making keys. Run through [`generate_merkle_circuit_keys`] — the very function the
//! production keys are generated with — so the counts cannot drift from the circuits.

use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisError, SynthesisMode,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use personas_bulletin::merkle::params::{MerkleCStore, generate_merkle_circuit_keys};
use personas_core::F;
use serde::Serialize;

// ark-serialize traits only because a SNARK's proving key must have them.
#[derive(Clone, Copy, Debug, Default, Serialize, CanonicalSerialize, CanonicalDeserialize)]
pub struct CircuitSize {
    pub constraints: usize,
    pub public_inputs: usize,
    pub witnesses: usize,
}

struct CountingSnark;

impl SNARK<F> for CountingSnark {
    type ProvingKey = CircuitSize;
    type VerifyingKey = ();
    type Proof = ();
    type ProcessedVerifyingKey = ();
    type Error = SynthesisError;

    fn circuit_specific_setup<C: ConstraintSynthesizer<F>, R: RngCore + CryptoRng>(
        circuit: C,
        _rng: &mut R,
    ) -> Result<(CircuitSize, ()), SynthesisError> {
        // Exactly ark-groth16's generator: setup mode, constraint-optimized, finalized.
        let cs = ConstraintSystem::<F>::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);
        circuit.generate_constraints(cs.clone())?;
        cs.finalize();
        Ok((
            CircuitSize {
                constraints: cs.num_constraints(),
                // Minus the constant "one" variable every R1CS instance carries.
                public_inputs: cs.num_instance_variables().saturating_sub(1),
                witnesses: cs.num_witness_variables(),
            },
            (),
        ))
    }

    fn prove<C: ConstraintSynthesizer<F>, R: RngCore + CryptoRng>(
        _: &CircuitSize,
        _: C,
        _: &mut R,
    ) -> Result<(), SynthesisError> {
        unreachable!("only setup is used, to size circuits")
    }

    fn process_vk(_: &()) -> Result<(), SynthesisError> {
        Ok(())
    }

    fn verify_with_processed_vk(_: &(), _: &[F], _: &()) -> Result<bool, SynthesisError> {
        unreachable!("only setup is used, to size circuits")
    }
}

/// Every circuit's size, named as the evaluation tables name the operations.
pub fn circuit_sizes() -> Vec<(&'static str, CircuitSize)> {
    let mut rng = ark_std::rand::rngs::OsRng;
    let k = generate_merkle_circuit_keys::<CountingSnark>(&mut rng, &MerkleCStore::new());
    vec![
        ("anon_post", k.standard.0),
        ("pseudo_post", k.standard_pseudo.0),
        ("rate_limited_post", k.standard_pseudor.0),
        ("authorship", k.authorship_pred.0),
        ("vote_or_rating", k.pseudonym_pred.0),
        ("badge_request", k.badge_request.0),
        ("badge_proof", k.badge_pred.0),
        ("scan", k.scan.0),
        ("join", k.join_pred.0),
        ("not_banned", k.not_banned_pred.0),
    ]
}
