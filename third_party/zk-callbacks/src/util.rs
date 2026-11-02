use ark_crypto_primitives::sponge::poseidon::{
    find_poseidon_ark_and_mds, PoseidonConfig, PoseidonDefaultConfigEntry,
};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    prelude::{AllocVar, AllocationMode},
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, Field, Namespace, SynthesisError};
use core::borrow::Borrow;

// Generates Poseidon params for BLS12-381. This is copied from
//     https://github.com/arkworks-rs/crypto-primitives/blob/54b3ac24b8943fbd984863558c749997e96ff399/src/sponge/poseidon/traits.rs#L69
// and
//     https://github.com/arkworks-rs/crypto-primitives/blob/54b3ac24b8943fbd984863558c749997e96ff399/src/sponge/test.rs
//
// PERSONAS PATCH: cached. These parameters are a deterministic function of (field, rate,
// optimized_for_weights), yet were re-derived — Grain LFSR plus rejection sampling for
// every round constant and the MDS matrix — on every single hash, native and in-circuit.
// Computing them once per key and handing out clones returns the identical values.
pub(crate) fn gen_poseidon_params<F: PrimeField>(
    rate: usize,
    optimized_for_weights: bool,
) -> PoseidonConfig<F> {
    use std::any::{Any, TypeId};
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    type Cache = Mutex<HashMap<(TypeId, usize, bool), Box<dyn Any + Send + Sync>>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    let key = (TypeId::of::<F>(), rate, optimized_for_weights);
    {
        let map = cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(hit) = map.get(&key).and_then(|b| b.downcast_ref::<PoseidonConfig<F>>()) {
            return hit.clone();
        }
    }
    let fresh = derive_poseidon_params::<F>(rate, optimized_for_weights);
    cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(key, Box::new(fresh.clone()));
    fresh
}

// The original derivation, unchanged.
fn derive_poseidon_params<F: PrimeField>(
    rate: usize,
    optimized_for_weights: bool,
) -> PoseidonConfig<F> {
    let params_set = if !optimized_for_weights {
        [
            PoseidonDefaultConfigEntry::new(2, 17, 8, 31, 0),
            PoseidonDefaultConfigEntry::new(3, 5, 8, 56, 0),
            PoseidonDefaultConfigEntry::new(4, 5, 8, 56, 0),
            PoseidonDefaultConfigEntry::new(5, 5, 8, 57, 0),
            PoseidonDefaultConfigEntry::new(6, 5, 8, 57, 0),
            PoseidonDefaultConfigEntry::new(7, 5, 8, 57, 0),
            PoseidonDefaultConfigEntry::new(8, 5, 8, 57, 0),
        ]
    } else {
        [
            PoseidonDefaultConfigEntry::new(2, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(3, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(4, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(5, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(6, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(7, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(8, 257, 8, 13, 0),
        ]
    };

    for param in params_set.iter() {
        if param.rate == rate {
            let (ark, mds) = find_poseidon_ark_and_mds::<F>(
                F::MODULUS_BIT_SIZE as u64,
                rate,
                param.full_rounds as u64,
                param.partial_rounds as u64,
                param.skip_matrices as u64,
            );

            return PoseidonConfig {
                full_rounds: param.full_rounds,
                partial_rounds: param.partial_rounds,
                alpha: param.alpha as u64,
                ark,
                mds,
                rate: param.rate,
                capacity: 1,
            };
        }
    }

    panic!("could not generate poseidon params");
    // F::get_default_poseidon_parameters(rate, optimized_for_weights).unwrap()
}

#[derive(Clone)]
pub(crate) struct ArrayVar<T, const N: usize>(pub [T; N]);

impl<F: Field, T: R1CSVar<F>, const N: usize> R1CSVar<F> for ArrayVar<T, N> {
    type Value = [T::Value; N];

    fn cs(&self) -> ConstraintSystemRef<F> {
        let mut result = ConstraintSystemRef::None;
        for var in &self.0 {
            result = var.cs().or(result);
        }
        result
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(core::array::from_fn(|i| self.0[i].value().unwrap()))
    }
}

impl<I, F: Field, A: AllocVar<I, F>, const N: usize> AllocVar<[I; N], F> for ArrayVar<A, N> {
    fn new_variable<T: Borrow<[I; N]>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        Ok(ArrayVar(f().map(|v| {
            let v = v.borrow();
            core::array::from_fn(|i| A::new_variable(cs.clone(), || Ok(&v[i]), mode).unwrap())
        })?))
    }
}
