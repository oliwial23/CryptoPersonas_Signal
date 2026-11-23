//! The padded Groth16 scan at every cap the fold figure shows.
//!
//! The serverless deployment scans with one Groth16 proof padded to `k_max` slots
//! (`SCAN_SLOTS = K_MAX = 20`). The scan circuit is const-generic in its slot count, so this
//! builds it at each size with the production bulletin heights (`MerkleCStore`,
//! `MerkleOStore`), generates its keys, and times proving and verifying. The member has one
//! outstanding callback from one post, then scans in the next epoch, as in the bulletin's
//! end-to-end scan test. Each proof starts from a fresh copy of that member.
//!
//! Run (release; 100 slots needs about 6 GB of RAM):
//! `cargo run --release -p personas-bench --example padded_scan_sweep -- [iters] [sizes] [out.json] [label]`
//! e.g. `-- 5 1,2,4,5,10,20,25,50,100 results.json "Apple M3 Max"`.

use std::time::Instant;

use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisError, SynthesisMode,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use personas_bulletin::merkle::callback::{DEFAULT_CB_MEMB_HEIGHT as MH, DEFAULT_CB_NMEMB_HEIGHT as NH};
use personas_bulletin::merkle::params::{MerkleCStore, MerkleOStore, merkle_scan_pubdata};
use personas_core::circuits::{
    MsgUser, PostArgs, PostArgsVar, PrivScan, PrivScanVar, PubScan, PubScanVar, ScanInt,
    get_callbacks, get_scan_interaction, get_standard_interaction,
};
use personas_core::{Args, ArgsVar, Cr, F, H, PK, Snark};
use rand::{SeedableRng, rngs::StdRng};
use serde::Serialize;
use zk_callbacks::generic::bulletin::{PublicUserBul, UserBul};
use zk_callbacks::generic::object::Time;
use zk_callbacks::generic::user::User;
use zk_callbacks::impls::centralized::crypto::FakeSigPubkey;

/// R1CS size, counted exactly as ark-groth16's setup synthesizes the circuit (as the
/// bench's `constraints` module does).
#[derive(Clone, Copy, Debug, Default, Serialize, CanonicalSerialize, CanonicalDeserialize)]
struct CircuitSize {
    constraints: usize,
    public_inputs: usize,
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
        let cs = ConstraintSystem::<F>::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);
        circuit.generate_constraints(cs.clone())?;
        cs.finalize();
        Ok((
            CircuitSize {
                constraints: cs.num_constraints(),
                public_inputs: cs.num_instance_variables().saturating_sub(1),
            },
            (),
        ))
    }
    fn prove<C: ConstraintSynthesizer<F>, R: RngCore + CryptoRng>(
        _: &CircuitSize,
        _: C,
        _: &mut R,
    ) -> Result<(), SynthesisError> {
        unreachable!()
    }
    fn process_vk(_: &()) -> Result<(), SynthesisError> {
        Ok(())
    }
    fn verify_with_processed_vk(_: &(), _: &[F], _: &()) -> Result<bool, SynthesisError> {
        unreachable!()
    }
}

#[derive(Serialize)]
struct Row {
    slots: usize,
    constraints: usize,
    public_inputs: usize,
    keygen_ms: f64,
    proving_key_bytes_compressed: usize,
    proving_key_bytes_uncompressed: usize,
    proof_bytes: usize,
    prove_ms: Vec<f64>,
    verify_ms: Vec<f64>,
    prove_mean_ms: f64,
    verify_mean_ms: f64,
}

fn mean(v: &[f64]) -> f64 {
    v.iter().sum::<f64>() / v.len() as f64
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

/// A member with one outstanding callback, and the object bulletin it is in.
fn member(rng: &mut StdRng, std_pk: &PK) -> (User<F, MsgUser>, MerkleOStore) {
    let mut user = User::create(MsgUser::default(), rng);
    let mut obj = MerkleOStore::new();
    obj.push(user.commit::<H>(), F::from(0), vec![]);
    let post = user
        .exec_method_create_cb::<H, PostArgs<F>, PostArgsVar<F>, (), (), Args, ArgsVar, Cr, Snark, MerkleOStore, 1>(
            &mut *rng,
            get_standard_interaction(),
            [FakeSigPubkey::pk()],
            Time::from(0),
            &obj,
            false,
            std_pk,
            PostArgs::default(),
            (),
        )
        .expect("post");
    obj.push(post.new_object, post.old_nullifier, post.cb_com_list.to_vec());
    (user, obj)
}

fn run<const N: usize>(rng: &mut StdRng, std_pk: &PK, iters: usize) -> Row {
    let cstore = MerkleCStore::new();
    let size = {
        let si: ScanInt<MerkleCStore, N> = get_scan_interaction();
        let dummy = merkle_scan_pubdata::<MH, NH, N>(&cstore, Time::default());
        si.generate_keys::<H, CountingSnark, Cr, MerkleOStore>(&mut *rng, None, dummy, true).0
    };
    eprintln!("slots {N}: {} constraints; generating keys", size.constraints);

    let si: ScanInt<MerkleCStore, N> = get_scan_interaction();
    let dummy = merkle_scan_pubdata::<MH, NH, N>(&cstore, Time::default());
    let t = Instant::now();
    let (pk, vk) = si.generate_keys::<H, Snark, Cr, MerkleOStore>(&mut *rng, None, dummy, true);
    let keygen_ms = ms(t);

    let (base_user, obj) = member(rng, std_pk);
    let (mut prove_ms, mut verify_ms, mut proof_bytes) = (vec![], vec![], 0);
    for i in 0..iters {
        let mut user = base_user.clone();
        let (ps, prs) = user.get_scan_arguments::<Args, ArgsVar, Cr, MerkleCStore, N>(
            &cstore,
            (false, false),
            Time::from(1),
            get_callbacks(),
        );
        let t = Instant::now();
        let exec = user
            .interact::<H, PubScan<MerkleCStore, N>, PubScanVar<MerkleCStore, N>, PrivScan<MerkleCStore, N>, PrivScanVar<MerkleCStore, N>, Args, ArgsVar, Cr, Snark, MerkleOStore, 0>(
                &mut *rng,
                get_scan_interaction::<MerkleCStore, N>(),
                [],
                Time::from(1),
                <MerkleOStore as PublicUserBul<F, MsgUser>>::get_membership_data(&obj, base_user.commit::<H>())
                    .expect("member"),
                false,
                &pk,
                ps.clone(),
                prs,
                true,
            )
            .expect("scan proof");
        prove_ms.push(ms(t));
        proof_bytes = exec.proof.serialized_size(Compress::Yes);

        let t = Instant::now();
        let ok = <MerkleOStore as UserBul<F, MsgUser>>::verify_interaction::<PubScan<MerkleCStore, N>, Snark, 0>(
            &obj,
            exec.new_object,
            exec.old_nullifier,
            ps,
            exec.cb_com_list,
            exec.proof,
            Some(obj.root()),
            &vk,
        );
        verify_ms.push(ms(t));
        assert!(ok, "the padded scan must verify ({N} slots)");
        eprintln!("  run {}: prove {:.0} ms, verify {:.2} ms", i + 1, prove_ms[i], verify_ms[i]);
    }
    Row {
        slots: N,
        constraints: size.constraints,
        public_inputs: size.public_inputs,
        keygen_ms,
        proving_key_bytes_compressed: pk.serialized_size(Compress::Yes),
        proving_key_bytes_uncompressed: pk.serialized_size(Compress::No),
        proof_bytes,
        prove_mean_ms: mean(&prove_ms),
        verify_mean_ms: mean(&verify_ms),
        prove_ms,
        verify_ms,
    }
}

/// `keygen` mode: write this size's scan keys (and the post keys, once) to `dir`, so a
/// separate `prove` process can be measured on its own.
fn keygen_to<const N: usize>(rng: &mut StdRng, dir: &std::path::Path) {
    std::fs::create_dir_all(dir).expect("keys dir");
    let std_path = dir.join("post-pk.bin");
    if !std_path.exists() {
        let (std_pk, _) = get_standard_interaction().generate_keys::<H, Snark, Cr, MerkleOStore>(
            &mut *rng,
            None,
            PostArgs::default(),
            false,
        );
        let mut buf = Vec::new();
        std_pk.serialize_with_mode(&mut buf, Compress::No).unwrap();
        std::fs::write(&std_path, buf).unwrap();
    }
    let cstore = MerkleCStore::new();
    let si: ScanInt<MerkleCStore, N> = get_scan_interaction();
    let dummy = merkle_scan_pubdata::<MH, NH, N>(&cstore, Time::default());
    let t = Instant::now();
    let (pk, vk) = si.generate_keys::<H, Snark, Cr, MerkleOStore>(&mut *rng, None, dummy, true);
    eprintln!("slots {N}: keys in {:.1} s", ms(t) / 1000.0);
    for (name, bytes) in [
        (format!("scan-pk-{N}.bin"), { let mut b = Vec::new(); pk.serialize_with_mode(&mut b, Compress::No).unwrap(); b }),
        (format!("scan-vk-{N}.bin"), { let mut b = Vec::new(); vk.serialize_with_mode(&mut b, Compress::No).unwrap(); b }),
    ] {
        std::fs::write(dir.join(name), bytes).unwrap();
    }
}

/// `prove` mode: load this size's proving key from `dir` and prove (and verify) the scan,
/// as a member's device would. Peak memory of this process is the client's cost.
fn prove_from<const N: usize>(rng: &mut StdRng, dir: &std::path::Path, iters: usize) {
    use ark_serialize::Validate;
    let load = |name: String| std::fs::read(dir.join(&name)).unwrap_or_else(|_| panic!("missing {name}; run keygen first"));
    let std_pk = PK::deserialize_with_mode(&load("post-pk.bin".into())[..], Compress::No, Validate::No).unwrap();
    let (base_user, obj) = member(rng, &std_pk);
    drop(std_pk);
    let pk = PK::deserialize_with_mode(&load(format!("scan-pk-{N}.bin"))[..], Compress::No, Validate::No).unwrap();
    let vk = personas_core::VK::deserialize_with_mode(&load(format!("scan-vk-{N}.bin"))[..], Compress::No, Validate::No).unwrap();
    let cstore = MerkleCStore::new();
    for i in 0..iters {
        let mut user = base_user.clone();
        let (ps, prs) = user.get_scan_arguments::<Args, ArgsVar, Cr, MerkleCStore, N>(
            &cstore,
            (false, false),
            Time::from(1),
            get_callbacks(),
        );
        let t = Instant::now();
        let exec = user
            .interact::<H, PubScan<MerkleCStore, N>, PubScanVar<MerkleCStore, N>, PrivScan<MerkleCStore, N>, PrivScanVar<MerkleCStore, N>, Args, ArgsVar, Cr, Snark, MerkleOStore, 0>(
                &mut *rng,
                get_scan_interaction::<MerkleCStore, N>(),
                [],
                Time::from(1),
                <MerkleOStore as PublicUserBul<F, MsgUser>>::get_membership_data(&obj, base_user.commit::<H>())
                    .expect("member"),
                false,
                &pk,
                ps.clone(),
                prs,
                true,
            )
            .expect("scan proof");
        let p = ms(t);
        let ok = <MerkleOStore as UserBul<F, MsgUser>>::verify_interaction::<PubScan<MerkleCStore, N>, Snark, 0>(
            &obj, exec.new_object, exec.old_nullifier, ps, exec.cb_com_list, exec.proof, Some(obj.root()), &vk,
        );
        assert!(ok, "the padded scan must verify ({N} slots)");
        println!("slots {N}: run {}: prove {p:.0} ms", i + 1);
    }
}

macro_rules! by_size {
    ($n:expr, $f:ident, $($arg:expr),*) => {
        match $n {
            1 => $f::<1>($($arg),*), 2 => $f::<2>($($arg),*), 4 => $f::<4>($($arg),*),
            5 => $f::<5>($($arg),*), 10 => $f::<10>($($arg),*), 20 => $f::<20>($($arg),*),
            25 => $f::<25>($($arg),*), 50 => $f::<50>($($arg),*), 100 => $f::<100>($($arg),*),
            n => panic!("size {n} is not built"),
        }
    };
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    // Memory modes: `keygen <slots> <dir>` and `prove <slots> <dir> [iters]`, one size per
    // process so `/usr/bin/time -l` reports each phase's peak memory on its own.
    if matches!(a.get(1).map(String::as_str), Some("keygen" | "prove")) {
        let n: usize = a[2].parse().expect("slots");
        let dir = std::path::PathBuf::from(&a[3]);
        let mut rng = StdRng::from_entropy();
        if a[1] == "keygen" {
            by_size!(n, keygen_to, &mut rng, &dir);
        } else {
            let iters: usize = a.get(4).and_then(|s| s.parse().ok()).unwrap_or(1);
            by_size!(n, prove_from, &mut rng, &dir, iters);
        }
        return;
    }
    let iters: usize = a.get(1).and_then(|s| s.parse().ok()).unwrap_or(5);
    let sizes: Vec<usize> = a
        .get(2)
        .map(|s| s.split(',').map(|x| x.parse().expect("size")).collect())
        .unwrap_or_else(|| vec![1, 2, 4, 5, 10, 20, 25, 50, 100]);
    let out = a.get(3).cloned().unwrap_or_else(|| "padded-scan-sweep.json".into());
    let label = a.get(4).cloned().unwrap_or_default();

    let mut rng = StdRng::from_entropy();
    eprintln!("generating the post keys (to give the member a callback)");
    let (std_pk, _) = get_standard_interaction().generate_keys::<H, Snark, Cr, MerkleOStore>(
        &mut rng,
        None,
        PostArgs::default(),
        false,
    );

    let mut rows = Vec::new();
    for &n in &sizes {
        let row = match n {
            1 => run::<1>(&mut rng, &std_pk, iters),
            2 => run::<2>(&mut rng, &std_pk, iters),
            4 => run::<4>(&mut rng, &std_pk, iters),
            5 => run::<5>(&mut rng, &std_pk, iters),
            10 => run::<10>(&mut rng, &std_pk, iters),
            20 => run::<20>(&mut rng, &std_pk, iters),
            25 => run::<25>(&mut rng, &std_pk, iters),
            50 => run::<50>(&mut rng, &std_pk, iters),
            100 => run::<100>(&mut rng, &std_pk, iters),
            _ => panic!("size {n} is not built; add an arm"),
        };
        println!(
            "slots {:>3}: {:>9} constraints, prove {:>9.1} ms, verify {:>6.2} ms, pk {:>6.1} MB, keygen {:.1} s",
            row.slots,
            row.constraints,
            row.prove_mean_ms,
            row.verify_mean_ms,
            row.proving_key_bytes_uncompressed as f64 / 1e6,
            row.keygen_ms / 1000.0
        );
        rows.push(row);
        // Written after every size, so a crash at 100 keeps the rest.
        let doc = serde_json::json!({
            "label": label,
            "iterations": iters,
            "member": "one outstanding callback, scans in the next epoch",
            "bulletin": "production heights (MerkleCStore, MerkleOStore)",
            "rows": rows,
        });
        std::fs::write(&out, serde_json::to_string_pretty(&doc).unwrap()).expect("write results");
    }
}
