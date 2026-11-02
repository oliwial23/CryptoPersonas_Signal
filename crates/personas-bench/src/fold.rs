//! Nova folding of callback scans, on the serverless (Merkle) stores, across batch sizes.
//!
//! A member with `k` outstanding callbacks absorbs them all with ONE folded proof instead
//! of `k` Groth16 scan records: `k / N` Nova fold steps, each scanning `N` callbacks
//! (`FoldingScan<…, N>`), then one randomized IVC proof (Nova alone is not zero-knowledge)
//! plus the small Groth16 proof that ties the fold's starting commitment to the member's
//! object in the object tree. This is the same construction the centralized client uses
//! (`personas-client/src/flows.rs`, verified by `personas-server`'s `fold_scan`), with the
//! serverless Merkle stores substituted for the centralized ones.
//!
//! Benchmark-only. Serverless keeps folding off (SERVERLESS_PROTOCOL.md §13) and no
//! production keys are involved: this generates its own Nova parameters and fold key.
//!
//! One property of folding on the serverless stores shows up here and belongs in the
//! paper: `FoldingScan` bakes the callback roots in as circuit constants (it asserts
//! `is_memb_data_const`), and the tie-in proof bakes in the object root. Serverless roots
//! change every barrier, so a deployment would have to redo the Nova preprocessing and the
//! tie-in key per barrier. That cost is reported separately as `setup`.

use std::time::Instant;

use ark_bn254::G1Projective as Projective;
use ark_grumpkin::Projective as Projective2;
use ark_serialize::{CanonicalSerialize, Compress};
use ark_snark::SNARK;
use folding_schemes::FoldingScheme;
use folding_schemes::commitment::pedersen::Pedersen;
use folding_schemes::folding::nova::zk::RandomizedIVCProof;
use folding_schemes::folding::nova::{Nova, PreprocessorParam, VerifierParams};
use folding_schemes::frontend::FCircuit;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use personas_bulletin::merkle::params::{MerkleCStore, MerkleOStore};
use personas_core::circuits::{FoldingProofData, MsgUser, get_callbacks};
use personas_core::{Args, ArgsVar, Cr, F, H, PK, Snark, VK};
use rand::rngs::StdRng;
use serde::Serialize;
use zk_callbacks::generic::bulletin::PublicUserBul;
use zk_callbacks::generic::fold::{FoldingScan, gen_fold_proof_snark_key};
use zk_callbacks::generic::object::Time;
use zk_callbacks::generic::user::User;

use crate::{Summary, micros, summarize};

type Scan<const N: usize> =
    FoldingScan<F, MsgUser, Args, ArgsVar, Cr, MerkleOStore, MerkleCStore, H, N>;
type NovaM<const N: usize> = Nova<
    Projective,
    Projective2,
    Scan<N>,
    Pedersen<Projective, true>,
    Pedersen<Projective2, true>,
    true,
>;

/// What one member brings to a fold: its object (with outstanding callbacks) and the
/// replica's stores at the barrier it scans against.
pub struct Subject {
    pub user: User<F, MsgUser>,
    pub obj: MerkleOStore,
    pub cbs: MerkleCStore,
}

/// The per-`N` one-time cost: everything that depends on the circuit (and its baked-in
/// roots) but not on how many callbacks are folded.
#[derive(Serialize)]
pub struct Setup {
    pub batch: usize,
    /// R1CS constraints of one fold step (the augmented Nova step circuit).
    pub step_constraints: usize,
    /// R1CS constraints of the CycleFold circuit on the second curve.
    pub cyclefold_constraints: usize,
    /// Nova preprocessing: R1CS extraction + Pedersen parameters on both curves.
    pub preprocess_ms: f64,
}

/// One `(N, k)` cell.
#[derive(Serialize)]
pub struct Cell {
    pub batch: usize,
    pub callbacks: usize,
    pub steps: usize,
    /// Native scan witnesses + the Groth16 tie-in proof.
    pub inputs: Option<Summary>,
    /// `Nova::init`.
    pub init: Option<Summary>,
    /// All `steps` fold steps together.
    pub fold: Option<Summary>,
    /// One fold step (fold / steps).
    pub per_step: Option<Summary>,
    /// Randomizing the IVC proof.
    pub randomize: Option<Summary>,
    /// Client total: inputs + init + fold + randomize.
    pub prove: Option<Summary>,
    /// Verifier: IVC proof + start binding + Groth16 tie-in.
    pub verify: Option<Summary>,
    /// The folded record's payload (`FoldingProofData`), compressed.
    pub bytes: usize,
    /// The bare randomized IVC proof, compressed.
    pub proof_bytes: usize,
}

#[derive(Serialize)]
pub struct FoldReport {
    /// Generating the Groth16 tie-in key (independent of `N`; per object root).
    pub tie_in_keygen_ms: f64,
    pub setups: Vec<Setup>,
    pub cells: Vec<Cell>,
}

/// Run every batch size in `batches` over every `k` in `ks` (skipping `k` that are not a
/// positive multiple of `N`), `iters` timed runs per cell.
pub fn run(
    subject: &Subject,
    batches: &[usize],
    ks: &[usize],
    iters: usize,
    rng: &mut StdRng,
) -> FoldReport {
    let have = subject.user.num_outstanding_callbacks();
    let root = subject.obj.root();

    eprintln!("fold: generating the tie-in key ({have} outstanding callbacks available)");
    let t = Instant::now();
    let (tie_pk, tie_vk) =
        gen_fold_proof_snark_key::<F, H, MsgUser, Snark, MerkleOStore>(rng, Some(root));
    let tie_in_keygen_ms = micros(t) as f64 / 1000.0;

    let mut setups = Vec::new();
    let mut cells = Vec::new();
    for &n in batches {
        let ks: Vec<usize> = ks
            .iter()
            .copied()
            .filter(|&k| k >= n && k % n == 0 && k <= have)
            .collect();
        if ks.is_empty() {
            eprintln!("fold: N={n}: no k to run (need a multiple of {n} up to {have})");
            continue;
        }
        let ran = personas_core::dispatch_fold_size!(
            n,
            N => sweep::<N>(subject, &ks, iters, &tie_pk, &tie_vk, rng),
            {
                eprintln!("fold: N={n} is not a supported fold size {:?}", personas_core::circuits::FOLD_SIZES);
                continue;
            },
        );
        setups.push(ran.0);
        cells.extend(ran.1);
    }
    FoldReport {
        tie_in_keygen_ms,
        setups,
        cells,
    }
}

fn sweep<const N: usize>(
    subject: &Subject,
    ks: &[usize],
    iters: usize,
    tie_pk: &PK,
    tie_vk: &VK,
    rng: &mut StdRng,
) -> (Setup, Vec<Cell>) {
    let poseidon = poseidon_canonical_config::<F>();

    // The step circuit's constants (callback roots, callback methods) come from the scan
    // arguments; a one-step dry run on a copy yields them.
    let mut dry = subject.user.clone();
    let (params, _, _, _) = fold_inputs::<N>(&mut dry, subject, 1, tie_pk, rng);
    let circuit = Scan::<N>::new(params).expect("fold circuit");

    eprintln!("fold: N={N}: Nova preprocessing");
    let t = Instant::now();
    let nova_params = NovaM::<N>::preprocess(
        &mut *rng,
        &PreprocessorParam::new(poseidon.clone(), circuit),
    )
    .expect("Nova preprocessing");
    let preprocess_ms = micros(t) as f64 / 1000.0;
    let vp = &nova_params.1;
    let pp_hash = vp.pp_hash().expect("pp hash");
    let setup = Setup {
        batch: N,
        step_constraints: vp.r1cs.A.n_rows,
        cyclefold_constraints: vp.cf_r1cs.A.n_rows,
        preprocess_ms,
    };
    eprintln!(
        "fold: N={N}: step circuit {} constraints, preprocessing {:.1}s",
        setup.step_constraints,
        preprocess_ms / 1000.0
    );

    let mut cells = Vec::new();
    for &k in ks {
        let steps = k / N;
        let mut s = CellSamples::default();
        let mut sizes = (0, 0);
        for it in 0..iters {
            let mut user = subject.user.clone();

            let t = Instant::now();
            let (params, z_0, inputs, tie) =
                fold_inputs::<N>(&mut user, subject, steps, tie_pk, rng);
            s.inputs.push(micros(t));

            let t = Instant::now();
            let circuit = Scan::<N>::new(params).expect("fold circuit");
            let mut nova = NovaM::<N>::init(&nova_params, circuit, z_0).expect("Nova init");
            s.init.push(micros(t));

            let t = Instant::now();
            for step in inputs.into_iter().take(steps) {
                nova.prove_step(&mut *rng, step, None).expect("fold step");
            }
            let fold_us = micros(t);
            s.fold.push(fold_us);
            s.per_step.push(fold_us / steps as u64);

            let t = Instant::now();
            let proof = RandomizedIVCProof::new(&nova, &mut *rng).expect("randomize");
            s.randomize.push(micros(t));

            let data = FoldingProofData {
                proof,
                i: nova.i,
                z_0: nova.z_0.clone(),
                z_i: nova.z_i.clone(),
                extra_verif: tie,
            };
            if it == 0 {
                sizes = (size(&data), size(&data.proof));
            }

            let t = Instant::now();
            let ok = verify(&data, vp, pp_hash, tie_vk);
            s.verify.push(micros(t));
            assert!(ok, "a folded scan (N={N}, k={k}) must verify");
            // The fold's output is the member's object after absorbing all k callbacks.
            assert_eq!(
                data.z_i[0],
                user.commit::<H>(),
                "fold output is the scanned object"
            );

            let total = s.inputs.last().unwrap()
                + s.init.last().unwrap()
                + fold_us
                + s.randomize.last().unwrap();
            s.prove.push(total);
        }
        eprintln!(
            "fold: N={N} k={k}: prove {:.0} ms, verify {:.1} ms, {} B",
            mean_ms(&s.prove),
            mean_ms(&s.verify),
            sizes.0
        );
        cells.push(Cell {
            batch: N,
            callbacks: k,
            steps,
            inputs: summarize(&s.inputs),
            init: summarize(&s.init),
            fold: summarize(&s.fold),
            per_step: summarize(&s.per_step),
            randomize: summarize(&s.randomize),
            prove: summarize(&s.prove),
            verify: summarize(&s.verify),
            bytes: sizes.0,
            proof_bytes: sizes.1,
        });
    }
    (setup, cells)
}

type FoldParts<const N: usize> = (
    <Scan<N> as FCircuit<F>>::Params,
    Vec<F>,
    Vec<<Scan<N> as FCircuit<F>>::ExternalInputs>,
    (F, F, <Snark as SNARK<F>>::Proof),
);

/// The client's fold inputs, exactly as `personas-client` builds them, on Merkle stores:
/// roots as constants (`true`, `(true, true)`), the serverless scan time (0).
fn fold_inputs<const N: usize>(
    user: &mut User<F, MsgUser>,
    subject: &Subject,
    steps: usize,
    tie_pk: &PK,
    rng: &mut StdRng,
) -> FoldParts<N> {
    let memb = <MerkleOStore as PublicUserBul<F, MsgUser>>::get_membership_data(
        &subject.obj,
        user.commit::<H>(),
    )
    .expect("the member's object is in the object tree");
    user.scan_and_create_fold_proof_inputs::<Args, ArgsVar, Cr, MerkleOStore, MerkleCStore, H, Snark, N>(
        rng,
        memb,
        &subject.cbs,
        true,
        (true, true),
        Time::from(0),
        get_callbacks(),
        tie_pk,
        steps,
    )
}

/// The verifier's three checks, as `personas-server`'s `fold_scan` makes them.
fn verify(
    data: &FoldingProofData,
    vp: &VerifierParams<
        Projective,
        Projective2,
        Pedersen<Projective, true>,
        Pedersen<Projective2, true>,
        true,
    >,
    pp_hash: F,
    tie_vk: &VK,
) -> bool {
    use ark_ff::ToConstraintField;
    let folded =
        RandomizedIVCProof::verify::<Pedersen<Projective, true>, Pedersen<Projective2, true>>(
            &vp.r1cs,
            &vp.cf_r1cs,
            pp_hash,
            &poseidon_canonical_config::<F>(),
            data.i,
            data.z_0.clone(),
            data.z_i.clone(),
            &data.proof,
        )
        .is_ok();
    // Serverless scans at time 0, so the fold must start there and at the member's object.
    let bound = data.z_0[0] == data.extra_verif.0 && data.z_0[1] == F::from(0u64);
    let inputs = [data.extra_verif.0, data.extra_verif.1]
        .to_field_elements()
        .unwrap_or_default();
    let tied = Snark::verify(tie_vk, &inputs, &data.extra_verif.2).unwrap_or(false);
    folded && bound && tied
}

fn size(x: &impl CanonicalSerialize) -> usize {
    x.serialized_size(Compress::Yes)
}

fn mean_ms(us: &[u64]) -> f64 {
    us.iter().sum::<u64>() as f64 / us.len().max(1) as f64 / 1000.0
}

#[derive(Default)]
struct CellSamples {
    inputs: Vec<u64>,
    init: Vec<u64>,
    fold: Vec<u64>,
    per_step: Vec<u64>,
    randomize: Vec<u64>,
    prove: Vec<u64>,
    verify: Vec<u64>,
}
