//! Iteration-hiding tests (personas fork; docs/FOLD_ITERATION_HIDING.md).
//!
//! Setup throughout: `CubicFCircuit` (`z ↦ z³ + z + 5`) with blinding Pedersen on
//! BN254/Grumpkin, modelled on `nova::tests::test_ivc_opt`.
//!
//! - **C2**, random initial accumulators: the base step is the identity on
//!   `(U_init, cf_U_init)`, openings hold after every step, `U.u` stops revealing `i`, and
//!   `randomize_initial_accumulators` is usable only at `i == 0`, once.
//! - The R1CS shape check (a real step's R1CS equals `AugmentedFCircuit::empty()`'s) is an
//!   assertion inside every test-build `prove_step`. The tests here drive it through base and
//!   non-base steps, randomized and not.
#![allow(non_snake_case)]

use ark_bn254::{Fr, G1Projective as Projective};
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use ark_ff::{BigInteger, PrimeField};
use ark_grumpkin::Projective as Projective2;
use ark_serialize::CanonicalSerialize;
use ark_std::{rand::RngCore, Zero};

use super::{
    nifs::{nova::NIFS, NIFSTrait},
    zk::RandomizedIVCProof,
    Nova, PreprocessorParam,
};
use crate::{
    commitment::{pedersen::Pedersen, CommitmentScheme},
    folding::nova::{CommittedInstance, Witness},
    frontend::{utils::CubicFCircuit, FCircuit},
    transcript::poseidon::poseidon_canonical_config,
    Curve, Error, FoldingScheme,
};

pub(crate) type CS1 = Pedersen<Projective, true>;
pub(crate) type CS2 = Pedersen<Projective2, true>;
pub(crate) type NovaT = Nova<Projective, Projective2, CubicFCircuit<Fr>, CS1, CS2, true>;
pub(crate) type Params = (
    <NovaT as FoldingScheme<Projective, Projective2, CubicFCircuit<Fr>>>::ProverParam,
    <NovaT as FoldingScheme<Projective, Projective2, CubicFCircuit<Fr>>>::VerifierParam,
);

pub(crate) fn setup(mut rng: impl RngCore) -> Result<(Params, CubicFCircuit<Fr>), Error> {
    let F_circuit = CubicFCircuit::<Fr>::new(())?;
    let prep = PreprocessorParam::new(poseidon_canonical_config::<Fr>(), F_circuit);
    Ok((NovaT::preprocess(&mut rng, &prep)?, F_circuit))
}

/// `init(z_0 = 3)`, randomize the initial accumulators, then `num_steps` steps.
pub(crate) fn randomized_nova(
    num_steps: usize,
    mut rng: impl RngCore,
) -> Result<(Params, NovaT), Error> {
    let (params, F_circuit) = setup(&mut rng)?;
    let mut nova = NovaT::init(&params, F_circuit, vec![Fr::from(3u32)])?;
    nova.randomize_initial_accumulators(&mut rng)?;
    for _ in 0..num_steps {
        nova.prove_step(&mut rng, (), None)?;
    }
    Ok((params, nova))
}

/// The zk verifier on `nova`'s own public data.
pub(crate) fn verify_randomized(
    nova: &NovaT,
    proof: &RandomizedIVCProof<Projective, Projective2>,
) -> Result<(), Error> {
    RandomizedIVCProof::verify::<CS1, CS2>(
        &nova.r1cs,
        &nova.cf_r1cs,
        nova.pp_hash,
        &nova.poseidon_config,
        &nova.cs_pp,
        &nova.cf_cs_pp,
        nova.c(),
        nova.z_0.clone(),
        nova.z_i.clone(),
        proof,
    )
}

fn assert_openings<C: Curve, CS: CommitmentScheme<C, true>>(
    pp: &CS::ProverParams,
    r1cs: &crate::arith::r1cs::R1CS<C::ScalarField>,
    W: &Witness<C>,
    U: &CommittedInstance<C>,
) -> Result<(), Error> {
    W.check_shape_and_openings(r1cs, U, |v, r| CS::commit(pp, v, r))
}

fn bits<F: PrimeField>(x: F) -> usize {
    x.into_bigint().num_bits() as usize
}

#[test]
fn c2_base_step_is_the_identity_on_the_initial_accumulators() -> Result<(), Error> {
    let mut rng = ark_std::test_rng();
    let (_, mut nova) = randomized_nova(0, &mut rng)?;
    let (W_init, U_init) = (nova.W_i.clone(), nova.U_i.clone());
    let (cf_W_init, cf_U_init) = (nova.cf_W_i.clone(), nova.cf_U_i.clone());
    // The initial accumulator really is random, not U_⊥.
    assert!(!U_init.u.is_zero() && !U_init.cmW.is_zero() && !U_init.cmE.is_zero());

    // The fold prove_step's base case performs: (U_init, W_init) ⊕ (u_⊥, w_⊥).
    let mut transcript = PoseidonSponge::<Fr>::new(&nova.poseidon_config);
    let (W_1, U_1, cmT, _) = NIFS::<Projective, CS1, PoseidonSponge<Fr>, true>::prove(
        &nova.cs_pp,
        &nova.r1cs,
        &mut transcript,
        nova.pp_hash,
        &nova.W_i,
        &nova.U_i,
        &nova.w_i,
        &nova.u_i,
    )?;
    assert!(
        cmT.is_zero(),
        "base-case cross term must commit to Com(0, 0) = 0"
    );
    assert_eq!(U_1, U_init);
    assert_eq!(W_1, W_init);

    nova.prove_step(&mut rng, (), None)?;
    assert_eq!(nova.U_i, U_init, "U_1 must equal U_init");
    assert_eq!(nova.W_i, W_init);
    assert_eq!(nova.cf_U_i, cf_U_init, "cf_U_1 must equal cf_U_init");
    assert_eq!(nova.cf_W_i, cf_W_init);
    Ok(())
}

#[test]
fn c2_openings_hold_after_every_step() -> Result<(), Error> {
    let mut rng = ark_std::test_rng();
    let (_, mut nova) = randomized_nova(0, &mut rng)?;
    for _ in 0..4 {
        nova.prove_step(&mut rng, (), None)?;
        assert_openings::<Projective, CS1>(&nova.cs_pp, &nova.r1cs, &nova.w_i, &nova.u_i)?;
        assert_openings::<Projective, CS1>(&nova.cs_pp, &nova.r1cs, &nova.W_i, &nova.U_i)?;
        assert_openings::<Projective2, CS2>(
            &nova.cf_cs_pp,
            &nova.cf_r1cs,
            &nova.cf_W_i,
            &nova.cf_U_i,
        )?;
    }
    Ok(())
}

/// The `U.u` leak (FINDINGS O19). From `U_⊥`, the 128-bit NIFS challenges sum to a small
/// field element, so `U_i.u < (i−1)·2¹²⁸` and `cf_U_i.u < 2(i−1)·2¹²⁸`: the magnitudes
/// reveal `i`. From a random `U_init`, `u` is uniform in the 254-bit field.
#[test]
fn c2_u_no_longer_reveals_the_step_count() -> Result<(), Error> {
    let mut rng = ark_std::test_rng();
    let k = 3;

    let (params, F_circuit) = setup(&mut rng)?;
    let mut plain = NovaT::init(&params, F_circuit, vec![Fr::from(3u32)])?;
    for _ in 0..k {
        plain.prove_step(&mut rng, (), None)?;
    }
    // U_3.u = r_1 + r_2 < 2^129; cf_U_3.u = sum of 4 challenges < 2^130.
    assert!(bits(plain.U_i.u) <= 129, "{}", bits(plain.U_i.u));
    assert!(bits(plain.cf_U_i.u) <= 130, "{}", bits(plain.cf_U_i.u));

    let (_, randomized) = randomized_nova(k, &mut rng)?;
    // Uniform in a 254-bit field: below 2^131 with probability about 2^-123.
    assert!(bits(randomized.U_i.u) > 131, "{}", bits(randomized.U_i.u));
    assert!(
        bits(randomized.cf_U_i.u) > 131,
        "{}",
        bits(randomized.cf_U_i.u)
    );
    Ok(())
}

#[test]
fn c2_randomize_is_only_allowed_once_and_at_i_zero() -> Result<(), Error> {
    let mut rng = ark_std::test_rng();
    let (params, F_circuit) = setup(&mut rng)?;

    let mut twice = NovaT::init(&params, F_circuit, vec![Fr::from(3u32)])?;
    twice.randomize_initial_accumulators(&mut rng)?;
    assert!(twice.randomize_initial_accumulators(&mut rng).is_err());

    let mut late = NovaT::init(&params, F_circuit, vec![Fr::from(3u32)])?;
    late.prove_step(&mut rng, (), None)?;
    assert!(late.randomize_initial_accumulators(&mut rng).is_err());
    assert!(!late.has_randomized_initial_accumulators());
    Ok(())
}

/// Every test-build `prove_step` asserts that the real step's R1CS equals the one from
/// `AugmentedFCircuit::empty()`, i.e. that every witness is allocated unconditionally. This
/// drives that assertion through base and non-base steps, with and without randomized
/// accumulators.
#[test]
fn c2_r1cs_shape_of_real_steps_matches_empty() -> Result<(), Error> {
    let mut rng = ark_std::test_rng();
    let (params, F_circuit) = setup(&mut rng)?;
    let mut plain = NovaT::init(&params, F_circuit, vec![Fr::from(3u32)])?;
    for _ in 0..3 {
        plain.prove_step(&mut rng, (), None)?;
    }
    let (_, randomized) = randomized_nova(3, &mut rng)?;
    assert_eq!(plain.r1cs, randomized.r1cs);
    assert_eq!(plain.r1cs, params.1.r1cs);
    Ok(())
}

#[test]
fn c2_honest_proofs_verify_for_several_step_counts() -> Result<(), Error> {
    let mut rng = ark_std::test_rng();
    for k in [1usize, 2, 3, 5] {
        let (params, nova) = randomized_nova(k, &mut rng)?;
        // The non-zk verifier accepts randomized runs too.
        NovaT::verify(params.1.clone(), nova.ivc_proof())?;
        let proof = RandomizedIVCProof::new(&nova, &mut rng)?;
        verify_randomized(&nova, &proof)?;
    }
    Ok(())
}

#[test]
fn c2_proof_size_is_independent_of_the_step_count() -> Result<(), Error> {
    let mut rng = ark_std::test_rng();
    let mut sizes = vec![];
    for k in [1usize, 2, 3, 5] {
        let (_, nova) = randomized_nova(k, &mut rng)?;
        let proof = RandomizedIVCProof::new(&nova, &mut rng)?;
        sizes.push((k, proof.compressed_size(), proof.uncompressed_size()));
    }
    assert!(
        sizes
            .windows(2)
            .all(|w| w[0].1 == w[1].1 && w[0].2 == w[1].2),
        "{sizes:?}"
    );
    Ok(())
}

/// Not a check: prints the augmented / CycleFold R1CS sizes so the per-change constraint
/// deltas can be recorded (`cargo test ... r1cs_sizes -- --nocapture`).
#[test]
fn report_r1cs_sizes() -> Result<(), Error> {
    use crate::arith::Arith;
    let (params, _) = setup(ark_std::test_rng())?;
    let (r1cs, cf_r1cs) = (&params.1.r1cs, &params.1.cf_r1cs);
    println!(
        "R1CS sizes (CubicFCircuit, state_len 1): augmented {} constraints / {} witnesses / {} public; \
         CycleFold {} constraints / {} witnesses",
        r1cs.n_constraints(),
        r1cs.n_witnesses(),
        r1cs.n_public_inputs(),
        cf_r1cs.n_constraints(),
        cf_r1cs.n_witnesses()
    );
    Ok(())
}

#[test]
fn c1_counter_gadget_matches_native() -> Result<(), Error> {
    use super::{circuits::committed_step_counter_var, committed_step_counter};
    use ark_crypto_primitives::sponge::{
        constraints::CryptographicSpongeVar, poseidon::constraints::PoseidonSpongeVar,
    };
    use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::UniformRand;

    let mut rng = ark_std::test_rng();
    let config = poseidon_canonical_config::<Fr>();
    let (i, rho) = (Fr::from(5u32), Fr::rand(&mut rng));
    let cs = ConstraintSystem::<Fr>::new_ref();
    let sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), &config);
    let iVar = FpVar::new_witness(cs.clone(), || Ok(i))?;
    let rhoVar = FpVar::new_witness(cs.clone(), || Ok(rho))?;
    let cVar = committed_step_counter_var(&sponge, &iVar, &rhoVar)?;
    assert!(cs.is_satisfied()?);
    assert_eq!(cVar.value()?, committed_step_counter(&config, i, rho));
    // Distinct (i, ρ) give distinct counters; the counter is not i itself.
    assert_ne!(
        committed_step_counter(&config, i, rho),
        committed_step_counter(&config, i + Fr::from(1u32), rho)
    );
    assert_ne!(committed_step_counter(&config, i, rho), i);
    Ok(())
}

#[test]
fn c1_rho_is_sampled_and_c_hides_i() -> Result<(), Error> {
    use super::committed_step_counter;
    let mut rng = ark_std::test_rng();
    let (_, a) = randomized_nova(2, &mut rng)?;
    let (_, b) = randomized_nova(2, &mut rng)?;
    assert!(!a.rho.is_zero());
    // Same i, different runs: different public counters.
    assert_eq!(a.i, b.i);
    assert_ne!(a.c(), b.c());
    // Neither is the bare count, nor the ρ = 0 counter anyone could compute from i.
    assert_ne!(a.c(), a.i);
    assert_ne!(
        a.c(),
        committed_step_counter(&a.poseidon_config, a.i, Fr::zero())
    );
    Ok(())
}

#[test]
fn c1_wrong_public_inputs_are_rejected() -> Result<(), Error> {
    use super::committed_step_counter;
    let mut rng = ark_std::test_rng();
    let (_, nova) = randomized_nova(3, &mut rng)?;
    let proof = RandomizedIVCProof::new(&nova, &mut rng)?;
    let verify = |pp_hash: Fr, c: Fr, z_0: Vec<Fr>, z_i: Vec<Fr>| {
        RandomizedIVCProof::verify::<CS1, CS2>(
            &nova.r1cs,
            &nova.cf_r1cs,
            pp_hash,
            &nova.poseidon_config,
            &nova.cs_pp,
            &nova.cf_cs_pp,
            c,
            z_0,
            z_i,
            &proof,
        )
    };
    let one = Fr::from(1u32);
    let (pp, c, z_0, z_i) = (nova.pp_hash, nova.c(), nova.z_0.clone(), nova.z_i.clone());

    verify(pp, c, z_0.clone(), z_i.clone())?; // control
    assert!(verify(pp, c + one, z_0.clone(), z_i.clone()).is_err());
    // Upstream's semantics, the bare step count, no longer verifies.
    assert!(verify(pp, nova.i, z_0.clone(), z_i.clone()).is_err());
    // Claiming one more step, or the right step with the wrong ρ.
    let c_more = committed_step_counter(&nova.poseidon_config, nova.i + one, nova.rho);
    assert!(verify(pp, c_more, z_0.clone(), z_i.clone()).is_err());
    let c_rho0 = committed_step_counter(&nova.poseidon_config, nova.i, Fr::zero());
    assert!(verify(pp, c_rho0, z_0.clone(), z_i.clone()).is_err());
    // Wrong z_0, z_i, pp_hash.
    assert!(verify(pp, c, vec![z_0[0] + one], z_i.clone()).is_err());
    assert!(verify(pp, c, z_0.clone(), vec![z_i[0] + one]).is_err());
    assert!(verify(pp + one, c, z_0, z_i).is_err());
    Ok(())
}

/// C4: the two cross-term commitments a `RandomizedIVCProof` ships are hiding. Upstream's
/// `π = Com(T, 0)` was a deterministic function of the witnesses: two proofs of the same
/// state shipped the same `π`.
#[test]
fn c4_shipped_cross_term_commitments_are_randomized() -> Result<(), Error> {
    let mut rng = ark_std::test_rng();
    let (_, nova) = randomized_nova(2, &mut rng)?;
    let p1 = RandomizedIVCProof::new(&nova, &mut rng)?;
    let p2 = RandomizedIVCProof::new(&nova, &mut rng)?;
    verify_randomized(&nova, &p1)?;
    verify_randomized(&nova, &p2)?;
    assert_ne!(p1.pi, p2.pi, "π must not be a function of the state alone");
    assert_ne!(p1.pi_prime, p2.pi_prime);

    // The deterministic π the unhiding fold would have shipped for this state.
    let mut transcript = PoseidonSponge::<Fr>::new(&nova.poseidon_config);
    let (_, _, pi_deterministic, _) = NIFS::<Projective, CS1, PoseidonSponge<Fr>, true>::prove(
        &nova.cs_pp,
        &nova.r1cs,
        &mut transcript,
        nova.pp_hash,
        &nova.w_i,
        &nova.u_i,
        &nova.W_i,
        &nova.U_i,
    )?;
    assert_ne!(p1.pi, pi_deterministic);
    assert_ne!(p2.pi, pi_deterministic);
    Ok(())
}

/// C4: `prove_hiding` keeps the fold correct. The folded witness opens the folded instance,
/// satisfies the relation, and the instance equals what the (unchanged) `NIFS::verify`
/// computes.
#[test]
fn c4_prove_hiding_folds_correctly() -> Result<(), Error> {
    use crate::arith::{ArithRelation, ArithSampler};
    let mut rng = ark_std::test_rng();
    let (_, nova) = randomized_nova(0, &mut rng)?;
    let (W1, U1) = nova
        .r1cs
        .sample_witness_instance::<CS1>(&nova.cs_pp, &mut rng)?;
    let (W2, U2) = nova
        .r1cs
        .sample_witness_instance::<CS1>(&nova.cs_pp, &mut rng)?;

    let mut tp = PoseidonSponge::<Fr>::new(&nova.poseidon_config);
    let (W, U, cmT, _) = NIFS::<Projective, CS1, PoseidonSponge<Fr>, true>::prove_hiding(
        &mut rng,
        &nova.cs_pp,
        &nova.r1cs,
        &mut tp,
        nova.pp_hash,
        &W1,
        &U1,
        &W2,
        &U2,
    )?;
    let mut tv = PoseidonSponge::<Fr>::new(&nova.poseidon_config);
    let (U_v, _) = NIFS::<Projective, CS1, PoseidonSponge<Fr>, true>::verify(
        &mut tv,
        nova.pp_hash,
        &U1,
        &U2,
        &cmT,
    )?;
    assert_eq!(U, U_v);
    nova.r1cs.check_relation(&W, &U)?;
    assert_openings::<Projective, CS1>(&nova.cs_pp, &nova.r1cs, &W, &U)?;
    Ok(())
}
