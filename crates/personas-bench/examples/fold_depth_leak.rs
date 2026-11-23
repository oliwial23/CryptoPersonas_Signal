//! Does a randomized Nova proof reveal its depth through anything other than `i`?
//!
//! Upstream Sonobe's verifier takes the step count `i` as input, which is why folds were
//! once padded to `k_max` steps. The vendored copy (`third_party/sonobe`) binds a committed
//! counter instead and starts from random accumulators; that only helps if nothing else the
//! server receives depends on the depth. The server
//! receives a `RandomizedIVCProof`: the running instance `U_i`, the last instance `u_i`, the
//! random instance `U_r`, two cross-term commitments, the randomized witness `W_i'`, and the
//! CycleFold running instance and witness `cf_U_i`, `cf_W_i`, the last two unblinded.
//!
//! This builds many proofs at each depth with a toy step circuit (the fields in question come
//! from Nova and CycleFold, whose circuits do not depend on the step function) and, for every
//! field, records simple features: size, zero/one/identity, and for witness vectors the
//! number of zero and of small (< 2^64) entries and the positions of the zeros. A feature
//! that is the same within each depth but differs between depths is a leak; one whose ranges
//! do not overlap between depths is a statistical leak.
//!
//! Run: `cargo run --release -p personas-bench --example fold_depth_leak -- [samples] [depths]`
//! e.g. `-- 8 1,2,3,4,10,50,100`.

use std::collections::{BTreeMap, BTreeSet};
use std::hash::{DefaultHasher, Hash, Hasher};

use ark_bn254::{Fr, G1Projective as Projective};
use ark_ff::{BigInteger, PrimeField};
use ark_grumpkin::Projective as Projective2;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalSerialize, Compress};
use folding_schemes::FoldingScheme;
use folding_schemes::commitment::pedersen::Pedersen;
use folding_schemes::folding::nova::zk::RandomizedIVCProof;
use folding_schemes::folding::nova::{CommittedInstance, Nova, PreprocessorParam, Witness};
use folding_schemes::frontend::FCircuit;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use folding_schemes::{Curve, Error};
use rand::SeedableRng;
use rand::rngs::StdRng;

/// z' = z^3 + z + x, with a fresh external input x each step so step witnesses differ.
#[derive(Clone, Copy, Debug)]
struct Toy;

impl FCircuit<Fr> for Toy {
    type Params = ();
    type ExternalInputs = Fr;
    type ExternalInputsVar = FpVar<Fr>;
    fn new(_: ()) -> Result<Self, Error> {
        Ok(Toy)
    }
    fn state_len(&self) -> usize {
        1
    }
    fn generate_step_constraints(
        &self,
        _cs: ConstraintSystemRef<Fr>,
        _i: usize,
        z: Vec<FpVar<Fr>>,
        x: FpVar<Fr>,
    ) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
        let z = z[0].clone();
        Ok(vec![&z * &z * &z + &z + x])
    }
}

type N = Nova<Projective, Projective2, Toy, Pedersen<Projective, true>, Pedersen<Projective2, true>, true>;

/// Features of one proof: name -> value. Values are strings so sets of them compare easily.
type Features = BTreeMap<String, String>;

fn small<Fq: PrimeField>(x: &Fq) -> bool {
    let b = x.into_bigint().to_bytes_le();
    b[8..].iter().all(|&v| v == 0)
}

fn digest<T: Hash>(t: &T) -> String {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    format!("{:016x}", h.finish())
}

fn point<C: Curve>(f: &mut Features, name: &str, p: &C) {
    f.insert(format!("{name}.is_identity"), p.is_zero().to_string());
    f.insert(format!("{name}.is_generator"), (*p == C::generator()).to_string());
}

fn scalar<Fq: PrimeField>(f: &mut Features, name: &str, x: &Fq) {
    f.insert(format!("{name}.is_zero"), x.is_zero().to_string());
    f.insert(format!("{name}.is_one"), x.is_one().to_string());
    f.insert(format!("{name}.small"), small(x).to_string());
}

fn vector<Fq: PrimeField>(f: &mut Features, name: &str, v: &[Fq]) {
    let zeros: Vec<usize> = v.iter().enumerate().filter(|(_, x)| x.is_zero()).map(|(i, _)| i).collect();
    f.insert(format!("{name}.len"), v.len().to_string());
    f.insert(format!("{name}.zeros"), zeros.len().to_string());
    f.insert(format!("{name}.small"), v.iter().filter(|x| small(*x)).count().to_string());
    f.insert(format!("{name}.ones"), v.iter().filter(|x| x.is_one()).count().to_string());
    f.insert(format!("{name}.zero_positions"), digest(&zeros));
}

fn instance<C: Curve>(f: &mut Features, name: &str, u: &CommittedInstance<C>) {
    point(f, &format!("{name}.cmE"), &u.cmE);
    point(f, &format!("{name}.cmW"), &u.cmW);
    scalar(f, &format!("{name}.u"), &u.u);
    for (j, x) in u.x.iter().enumerate() {
        scalar(f, &format!("{name}.x[{j}]"), x);
    }
}

fn witness<C: Curve>(f: &mut Features, name: &str, w: &Witness<C>) {
    vector(f, &format!("{name}.W"), &w.W);
    vector(f, &format!("{name}.E"), &w.E);
    scalar(f, &format!("{name}.rW"), &w.rW);
    scalar(f, &format!("{name}.rE"), &w.rE);
}

fn features(p: &RandomizedIVCProof<Projective, Projective2>) -> Features {
    let mut f = Features::new();
    f.insert("proof.bytes".into(), p.serialized_size(Compress::Yes).to_string());
    instance(&mut f, "U_i", &p.U_i);
    instance(&mut f, "u_i", &p.u_i);
    instance(&mut f, "U_r", &p.U_r);
    point(&mut f, "pi", &p.pi);
    point(&mut f, "pi_prime", &p.pi_prime);
    witness(&mut f, "W_i_prime", &p.W_i_prime);
    instance(&mut f, "cf_U_i", &p.cf_U_i);
    witness(&mut f, "cf_W_i", &p.cf_W_i);
    f
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let samples: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(8);
    let depths: Vec<usize> = args
        .get(2)
        .map(|s| s.split(',').map(|d| d.parse().expect("depth")).collect())
        .unwrap_or_else(|| vec![1, 2, 3, 4, 10, 50, 100]);

    let mut rng = StdRng::from_entropy();
    let poseidon = poseidon_canonical_config::<Fr>();
    let params = N::preprocess(&mut rng, &PreprocessorParam::new(poseidon.clone(), Toy)).expect("preprocess");
    let pp_hash = params.1.pp_hash().expect("pp hash");

    // depth -> feature -> the set of values seen at that depth
    let mut seen: BTreeMap<usize, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new();
    for &d in &depths {
        eprintln!("depth {d}: {samples} proofs");
        for _ in 0..samples {
            let mut nova = N::init(&params, Toy, vec![Fr::from(3u64)]).expect("init");
            nova.randomize_initial_accumulators(&mut rng).expect("randomize init");
            for _ in 0..d {
                let x = Fr::from(rand::Rng::r#gen::<u64>(&mut rng));
                nova.prove_step(&mut rng, x, None).expect("step");
            }
            let proof = RandomizedIVCProof::new(&nova, &mut rng).expect("randomize");
            RandomizedIVCProof::verify::<Pedersen<Projective, true>, Pedersen<Projective2, true>>(
                &params.1.r1cs,
                &params.1.cf_r1cs,
                pp_hash,
                &poseidon,
                &params.0.cs_pp,
                &params.0.cf_cs_pp,
                nova.c(),
                nova.z_0.clone(),
                nova.z_i.clone(),
                &proof,
            )
            .expect("proof must verify");
            for (k, v) in features(&proof) {
                seen.entry(d).or_default().entry(k).or_default().insert(v);
            }
        }
    }

    // A feature leaks if knowing its value narrows down the depth.
    let names: BTreeSet<String> = seen.values().flat_map(|m| m.keys().cloned()).collect();
    let mut leaks = 0;
    println!("feature, then the values seen at each depth ({samples} proofs each; '*' = varies)");
    for name in &names {
        let per: Vec<(usize, &BTreeSet<String>)> =
            depths.iter().map(|d| (*d, &seen[d][name])).collect();
        let all_same = per.windows(2).all(|w| w[0].1 == w[1].1);
        if all_same && per[0].1.len() == 1 {
            continue; // the same constant everywhere: reveals nothing
        }
        // Numeric features: compare ranges; others: compare value sets.
        let nums: Option<Vec<(f64, f64)>> = per
            .iter()
            .map(|(_, s)| {
                let v: Option<Vec<f64>> = s.iter().map(|x| x.parse::<f64>().ok()).collect();
                v.map(|v| (v.iter().cloned().fold(f64::MAX, f64::min), v.iter().cloned().fold(f64::MIN, f64::max)))
            })
            .collect();
        let constant_within = per.iter().all(|(_, s)| s.len() == 1);
        let verdict = if constant_within && !all_same {
            "LEAK (fixed per depth)"
        } else if let Some(r) = &nums {
            let disjoint = r.iter().enumerate().any(|(a, ra)| {
                r.iter().enumerate().any(|(b, rb)| a != b && (ra.1 < rb.0 || rb.1 < ra.0))
            });
            if disjoint { "LEAK (ranges separate)" } else { "ok (overlapping)" }
        } else if all_same {
            "ok"
        } else {
            let sets: Vec<_> = per.iter().map(|(_, s)| *s).collect();
            let shared = sets.iter().all(|s| sets.iter().all(|t| !s.is_disjoint(t)));
            if shared { "ok (shared values)" } else { "LEAK? (values differ)" }
        };
        if verdict.starts_with("LEAK") {
            leaks += 1;
        }
        let shown: Vec<String> = per
            .iter()
            .map(|(d, s)| {
                let v = if s.len() == 1 {
                    s.iter().next().unwrap().clone()
                } else if let Some(r) = nums.as_ref() {
                    let i = depths.iter().position(|x| x == d).unwrap();
                    format!("{}..{}", r[i].0, r[i].1)
                } else {
                    "*".into()
                };
                format!("d{d}={v}")
            })
            .collect();
        println!("{verdict:24} {name:28} {}", shown.join(" "));
    }
    println!("\n{leaks} feature(s) distinguish depths {depths:?}");
}
