//! Attack regressions for the Nova fold path (personas fork; docs/FINDINGS.md O14–O16).
//!
//! Each test builds the attack by hand against the public parameters only and runs it
//! through the real verifier or the real augmented circuit. The commit that added this file
//! (`ccc5e1e`, "attack regressions B1-B3 against the unfixed fold path") ran the same
//! attacks against the unfixed upstream code and asserted that **each one succeeded**.
//! The fix commit flipped each assertion to "rejected" in place, so the diff between the
//! two commits is the evidence that each bug existed and is now closed. Each test also
//! carries an honest control that must keep passing.
//!
//! - **B1**: `RandomizedIVCProof::verify` and `Nova::verify` never check the commitment
//!   openings. `check_relation` compares `E` against `eval(u, x, W)`, but the prover
//!   supplies `E`, so that comparison is vacuous. A proof built from zero commitments, with
//!   `E` set to whatever the relation evaluates to, is accepted for an arbitrary `z_i`.
//! - **B2**: the augmented circuit's base case never enforces `z_i == z_0`, so a base step
//!   whose witnessed `z_i` is some other state `B` is satisfiable while the hashed `z_0`
//!   stays `A`.
//! - **B3**: an incoming witness gets a random `rE`, but `cmE = 0` because `E = 0`. The
//!   openings of every incoming and running instance are inconsistent, so honest proofs
//!   would fail as soon as B1's opening checks exist.
#![allow(non_snake_case)]

use ark_bn254::{Fr, G1Projective as Projective};
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use ark_grumpkin::Projective as Projective2;
use ark_relations::r1cs::ConstraintSystem;
use ark_std::{One, Zero};

use super::{
    circuits::AugmentedFCircuit,
    committed_step_counter,
    nifs::{nova::NIFS, NIFSTrait},
    zk::RandomizedIVCProof,
    CommittedInstance, IVCProof, Nova, PreprocessorParam, Witness,
};
use crate::{
    arith::{r1cs::R1CS, Arith},
    commitment::{pedersen::Pedersen, CommitmentScheme},
    folding::{
        circuits::cyclefold::CycleFoldCommittedInstance,
        traits::{CommittedInstanceOps, Dummy},
    },
    frontend::{
        utils::{cubic_step_native, CubicFCircuit},
        FCircuit,
    },
    transcript::poseidon::poseidon_canonical_config,
    Curve, Error, FoldingScheme,
};

type CS1 = Pedersen<Projective, true>;
type CS2 = Pedersen<Projective2, true>;
type N = Nova<Projective, Projective2, CubicFCircuit<Fr>, CS1, CS2, true>;
type NovaParams = (
    <N as FoldingScheme<Projective, Projective2, CubicFCircuit<Fr>>>::ProverParam,
    <N as FoldingScheme<Projective, Projective2, CubicFCircuit<Fr>>>::VerifierParam,
);

fn setup() -> Result<(NovaParams, CubicFCircuit<Fr>), Error> {
    let mut rng = ark_std::test_rng();
    let F_circuit = CubicFCircuit::<Fr>::new(())?;
    let prep = PreprocessorParam::new(poseidon_canonical_config::<Fr>(), F_circuit);
    Ok((N::preprocess(&mut rng, &prep)?, F_circuit))
}

/// Do `(W, U)` open correctly, i.e. `U.cmW = Com(W.W, W.rW)` and `U.cmE = Com(W.E, W.rE)`?
/// Computed with `CS::commit` directly (not `Witness::commit`, which shortcuts
/// `cmE := 0` whenever `E = 0`).
fn openings_hold<C: Curve, CS: CommitmentScheme<C, true>>(
    pp: &CS::ProverParams,
    W: &Witness<C>,
    U: &CommittedInstance<C>,
) -> Result<bool, Error> {
    Ok(CS::commit(pp, &W.W, &W.rW)? == U.cmW && CS::commit(pp, &W.E, &W.rE)? == U.cmE)
}

/// A witness with all-zero `W` and the error term `E` set to whatever the relaxed relation
/// evaluates to at `(U.u, U.x, W)`. This is the B1 trick: `check_relation` compares `E`
/// with the evaluation, and the prover chose `E`.
fn vacuous_witness<C: Curve>(
    r1cs: &R1CS<C::ScalarField>,
    U: &CommittedInstance<C>,
) -> Result<Witness<C>, Error> {
    let W = vec![C::ScalarField::zero(); r1cs.n_witnesses()];
    let E = r1cs.eval_at_z(&[&[U.u][..], &U.x, &W].concat())?;
    Ok(Witness {
        E,
        rE: C::ScalarField::zero(),
        W,
        rW: C::ScalarField::zero(),
    })
}

/// The incoming instance a forger needs for an arbitrary `(c, z_0, z_i)`: zero commitments,
/// with `x` set to the two hashes the verifier recomputes. (`c` is the value in the counter
/// slot of the instance hash: the committed step counter since C1, the bare `i` before.)
fn forged_incoming(
    nova: &N,
    c: Fr,
    z_0: &[Fr],
    z_i: &[Fr],
    U_i: &CommittedInstance<Projective>,
    cf_U_i: &CycleFoldCommittedInstance<Projective2>,
) -> CommittedInstance<Projective> {
    let sponge = PoseidonSponge::<Fr>::new(&nova.poseidon_config);
    CommittedInstance {
        cmE: Projective::zero(),
        u: Fr::one(),
        cmW: Projective::zero(),
        x: vec![
            U_i.hash(&sponge, nova.pp_hash, c, z_0, z_i),
            cf_U_i.hash_cyclefold(&sponge, nova.pp_hash),
        ],
    }
}

/// B1 against the zk verifier: a hand-built `RandomizedIVCProof` for a `z_i` that is NOT
/// `F^i(z_0)` for any `i`, and for any public counter `c` the forger likes, built from
/// nothing but the public parameters.
fn forge_randomized_proof(
    nova: &N,
    c: Fr,
    z_0: &[Fr],
    z_i: &[Fr],
) -> Result<RandomizedIVCProof<Projective, Projective2>, Error> {
    let U_i = CommittedInstance::<Projective>::dummy(2);
    let cf_U_i = CycleFoldCommittedInstance::<Projective2>::dummy(nova.cf_r1cs.n_public_inputs());
    let u_i = forged_incoming(nova, c, z_0, z_i, &U_i, &cf_U_i);
    let U_r = CommittedInstance::<Projective>::dummy(2);
    let (pi, pi_prime) = (Projective::zero(), Projective::zero());

    // Run the verifier's own two folds to learn the instance U' it will check W' against.
    let mut transcript = PoseidonSponge::<Fr>::new(&nova.poseidon_config);
    let (U_f, _) = NIFS::<Projective, CS1, PoseidonSponge<Fr>, true>::verify(
        &mut transcript,
        nova.pp_hash,
        &u_i,
        &U_i,
        &pi,
    )?;
    let (U_prime, _) = NIFS::<Projective, CS1, PoseidonSponge<Fr>, true>::verify(
        &mut transcript,
        nova.pp_hash,
        &U_f,
        &U_r,
        &pi_prime,
    )?;

    Ok(RandomizedIVCProof {
        W_i_prime: vacuous_witness(&nova.r1cs, &U_prime)?,
        cf_W_i: vacuous_witness(&nova.cf_r1cs, &cf_U_i)?,
        U_i,
        u_i,
        U_r,
        pi,
        pi_prime,
        cf_U_i,
    })
}

/// B1 against the non-zk `Nova::verify`: the same trick on the plain `IVCProof`.
fn forge_ivc_proof(
    nova: &N,
    i: Fr,
    z_0: &[Fr],
    z_i: &[Fr],
) -> Result<IVCProof<Projective, Projective2>, Error> {
    let U_i = CommittedInstance::<Projective>::dummy(2);
    let cf_U_i = CycleFoldCommittedInstance::<Projective2>::dummy(nova.cf_r1cs.n_public_inputs());
    // The non-zk verifier recomputes c = Poseidon(D_CTR, i, ρ) from the proof's (i, ρ).
    let rho = Fr::zero();
    let c = committed_step_counter(&nova.poseidon_config, i, rho);
    let u_i = forged_incoming(nova, c, z_0, z_i, &U_i, &cf_U_i);
    Ok(IVCProof {
        i,
        rho,
        z_0: z_0.to_vec(),
        z_i: z_i.to_vec(),
        W_i: vacuous_witness(&nova.r1cs, &U_i)?,
        w_i: vacuous_witness(&nova.r1cs, &u_i)?,
        cf_W_i: vacuous_witness(&nova.cf_r1cs, &cf_U_i)?,
        U_i,
        u_i,
        cf_U_i,
    })
}

#[test]
fn b1_forged_randomized_proof_is_rejected() -> Result<(), Error> {
    let (params, F_circuit) = setup()?;
    let z_0 = vec![Fr::from(3u32)];
    let nova = N::init(&params, F_circuit, z_0.clone())?;

    // The honest one-step state is F(3) = 35; claim 42 instead (with an arbitrary counter c).
    let z_i = vec![Fr::from(42u32)];
    assert_ne!(z_i, cubic_step_native(z_0.clone()));
    let c = Fr::from(7u32);
    let forged = forge_randomized_proof(&nova, c, &z_0, &z_i)?;

    let accepted = RandomizedIVCProof::verify::<CS1, CS2>(
        &nova.r1cs,
        &nova.cf_r1cs,
        nova.pp_hash,
        &nova.poseidon_config,
        &nova.cs_pp,
        &nova.cf_cs_pp,
        c,
        z_0,
        z_i,
        &forged,
    )
    .is_ok();
    assert!(!accepted, "B1: the forged zk proof must be REJECTED");
    Ok(())
}

#[test]
fn b1_forged_ivc_proof_is_rejected_by_nova_verify() -> Result<(), Error> {
    let (params, F_circuit) = setup()?;
    let z_0 = vec![Fr::from(3u32)];
    let nova = N::init(&params, F_circuit, z_0.clone())?;

    let z_i = vec![Fr::from(42u32)];
    let forged = forge_ivc_proof(&nova, Fr::from(7u32), &z_0, &z_i)?;

    let accepted = N::verify(params.1.clone(), forged).is_ok();
    assert!(!accepted, "B1: the forged IVC proof must be REJECTED");
    Ok(())
}

/// Control for both B1 tests: honest proofs still verify under the opening checks. This needs
/// B3's fix too, since the unfixed prover's openings were inconsistent.
#[test]
fn b1_honest_proofs_still_verify() -> Result<(), Error> {
    let mut rng = ark_std::test_rng();
    let (params, F_circuit) = setup()?;
    let mut nova = N::init(&params, F_circuit, vec![Fr::from(3u32)])?;
    nova.randomize_initial_accumulators(&mut rng)?;
    for _ in 0..3 {
        nova.prove_step(&mut rng, (), None)?;
    }
    N::verify(params.1.clone(), nova.ivc_proof())?;
    let proof = RandomizedIVCProof::new(&nova, &mut rng)?;
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
        &proof,
    )?;
    Ok(())
}

/// The base-case augmented circuit, exactly as `prove_step` builds it at `i = 0`, but with
/// the witnessed current state `z_i` chosen independently of the hashed `z_0`.
fn basecase_circuit(
    nova: &N,
    z_0: Vec<Fr>,
    z_i: Vec<Fr>,
) -> Result<AugmentedFCircuit<Projective, Projective2, CubicFCircuit<Fr>>, Error> {
    let mut transcript = PoseidonSponge::<Fr>::new(&nova.poseidon_config);
    let (_W_1, U_1, cmT, _) = NIFS::<Projective, CS1, PoseidonSponge<Fr>, true>::prove(
        &nova.cs_pp,
        &nova.r1cs,
        &mut transcript,
        nova.pp_hash,
        &nova.W_i,
        &nova.U_i,
        &nova.w_i,
        &nova.u_i,
    )?;
    Ok(AugmentedFCircuit {
        poseidon_config: nova.poseidon_config.clone(),
        pp_hash: Some(nova.pp_hash),
        i: Some(Fr::zero()),
        i_usize: Some(0),
        rho: Some(nova.rho),
        z_0: Some(z_0),
        z_i: Some(z_i),
        external_inputs: Some(()),
        u_i_cmW: Some(nova.u_i.cmW),
        U_i: Some(nova.U_i.clone()),
        U_i1_cmE: Some(U_1.cmE),
        U_i1_cmW: Some(U_1.cmW),
        cmT: Some(cmT),
        F: nova.F,
        cf1_u_i_cmW: None,
        cf2_u_i_cmW: None,
        cf_U_i: Some(nova.cf_U_i.clone()),
        cf1_cmT: None,
        cf2_cmT: None,
    })
}

fn is_satisfied(
    circuit: AugmentedFCircuit<Projective, Projective2, CubicFCircuit<Fr>>,
) -> Result<bool, Error> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.compute_next_state(cs.clone())?;
    Ok(cs.is_satisfied()?)
}

#[test]
fn b2_basecase_from_a_foreign_state_is_unsatisfiable() -> Result<(), Error> {
    let (params, F_circuit) = setup()?;
    let A = vec![Fr::from(3u32)];
    let B = vec![Fr::from(5u32)];
    let nova = N::init(&params, F_circuit, A.clone())?;

    // Control: the honest base case (z_i = z_0) is satisfiable.
    assert!(is_satisfied(basecase_circuit(
        &nova,
        A.clone(),
        A.clone()
    )?)?);

    // Attack: claim z_0 = A while stepping from B. Its output hashes (1, A, F(B), U_bot),
    // i.e. "one step from A reached F(B)".
    let satisfied = is_satisfied(basecase_circuit(&nova, A, B)?)?;
    assert!(!satisfied, "B2: init(B); z_0 = A must be UNSATISFIABLE");
    Ok(())
}

#[test]
fn b3_openings_are_consistent_after_honest_steps() -> Result<(), Error> {
    let mut rng = ark_std::test_rng();
    let (params, F_circuit) = setup()?;
    let mut nova = N::init(&params, F_circuit, vec![Fr::from(3u32)])?;
    // (Randomized because RandomizedIVCProof::new below requires it; the incoming and running
    // checks hold either way.)
    nova.randomize_initial_accumulators(&mut rng)?;

    // After one step the incoming (w_1, u_1) has E = 0 and cmE = 0. (Unfixed: rE != 0.)
    nova.prove_step(&mut rng, (), None)?;
    let incoming_ok = openings_hold::<Projective, CS1>(&nova.cs_pp, &nova.w_i, &nova.u_i)?;
    // After two steps, the running (W_2, U_2). (Unfixed: rE had accumulated r^2 * w_1.rE.)
    nova.prove_step(&mut rng, (), None)?;
    let running_ok = openings_hold::<Projective, CS1>(&nova.cs_pp, &nova.W_i, &nova.U_i)?;
    // The same holds for CycleFold's running pair.
    let cf_ok = openings_hold::<Projective2, CS2>(&nova.cf_cs_pp, &nova.cf_W_i, &nova.cf_U_i)?;
    // And for the folded witness an honest zk proof ships.
    let proof = RandomizedIVCProof::new(&nova, &mut rng)?;
    let mut transcript = PoseidonSponge::<Fr>::new(&nova.poseidon_config);
    let (U_f, _) = NIFS::<Projective, CS1, PoseidonSponge<Fr>, true>::verify(
        &mut transcript,
        nova.pp_hash,
        &proof.u_i,
        &proof.U_i,
        &proof.pi,
    )?;
    let (U_prime, _) = NIFS::<Projective, CS1, PoseidonSponge<Fr>, true>::verify(
        &mut transcript,
        nova.pp_hash,
        &U_f,
        &proof.U_r,
        &proof.pi_prime,
    )?;
    let shipped_ok = openings_hold::<Projective, CS1>(&nova.cs_pp, &proof.W_i_prime, &U_prime)?;

    assert!(
        incoming_ok && running_ok && cf_ok && shipped_ok,
        "B3: every honest opening must be CONSISTENT: \
         incoming={incoming_ok} running={running_ok} cyclefold={cf_ok} shipped={shipped_ok}"
    );
    Ok(())
}
