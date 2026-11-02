use std::marker::PhantomData;

use crate::{
    crypto::hash::FieldHash,
    impls::{
        centralized::ds::sig::{Privkey, Pubkey, Signature},
        hash::Poseidon,
    },
};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::Boolean};
use ark_relations::{ns, r1cs::SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use nalgebra::{DMatrix, DVector};
use rand::{Rng, distributions::Standard, prelude::Distribution};

/// A UOV signature.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq)]
pub struct UOVSig<F: PrimeField, const N: usize, const M: usize> {
    preimage: Vec<F>,
    n: PhantomData<[(); N]>,
    m: PhantomData<[(); M]>,
}

impl<F: PrimeField, const N: usize, const M: usize> Default for UOVSig<F, N, M> {
    fn default() -> Self {
        Self {
            preimage: [F::ZERO; N].to_vec(),
            n: PhantomData,
            m: PhantomData,
        }
    }
}

/// A UOV signature in-circuit.
#[derive(Clone)]
pub struct UOVSigVar<F: PrimeField, const N: usize, const M: usize> {
    preimage: Vec<FpVar<F>>,
    n: PhantomData<[(); N]>,
    m: PhantomData<[(); M]>,
}

impl<F: PrimeField, const N: usize, const M: usize> Default for UOVSigVar<F, N, M> {
    fn default() -> Self {
        let mut preimage = vec![];
        for _ in 0..N {
            preimage.push(FpVar::Constant(F::ZERO));
        }
        Self {
            preimage,
            n: PhantomData,
            m: PhantomData,
        }
    }
}

impl<F: PrimeField, const N: usize, const M: usize> AllocVar<UOVSig<F, N, M>, F>
    for UOVSigVar<F, N, M>
{
    fn new_variable<T: std::borrow::Borrow<UOVSig<F, N, M>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();
        res.and_then(|rec| {
            let rec = rec.borrow();
            let preimage = Vec::<FpVar<F>>::new_variable(
                ns!(cs, "preimage"),
                || Ok(rec.preimage.clone()),
                mode,
            )?;
            Ok(UOVSigVar {
                preimage,
                n: PhantomData,
                m: PhantomData,
            })
        })
    }
}

/// A UOV public verification key.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct UOVPubkey<F: PrimeField, H: FieldHash<F>, const N: usize, const M: usize> {
    data: Vec<F>,
    n: PhantomData<[(); N]>,
    m: PhantomData<[(); M]>,
    h: PhantomData<H>,
}

impl<F: PrimeField, H: FieldHash<F>, const N: usize, const M: usize> Default
    for UOVPubkey<F, H, N, M>
{
    fn default() -> Self {
        let mut data = vec![];
        for _ in 0..(M * N * N) {
            data.push(F::ZERO);
        }
        Self {
            data,
            n: PhantomData,
            m: PhantomData,
            h: PhantomData,
        }
    }
}

/// A public verification key in-circuit.
#[derive(Clone)]
pub struct UOVPubkeyVar<F: PrimeField, const N: usize, const M: usize> {
    data: Vec<FpVar<F>>,
    n: PhantomData<[(); N]>,
    m: PhantomData<[(); M]>,
}

impl<F: PrimeField, const N: usize, const M: usize> Default for UOVPubkeyVar<F, N, M> {
    fn default() -> Self {
        let mut data = vec![];
        for _ in 0..(M * N * N) {
            data.push(FpVar::Constant(F::ZERO));
        }
        Self {
            data,
            n: PhantomData,
            m: PhantomData,
        }
    }
}

impl<F: PrimeField, H: FieldHash<F>, const N: usize, const M: usize>
    AllocVar<UOVPubkey<F, H, N, M>, F> for UOVPubkeyVar<F, N, M>
{
    fn new_variable<T: std::borrow::Borrow<UOVPubkey<F, H, N, M>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();
        res.and_then(|rec| {
            let rec = rec.borrow();
            let data =
                Vec::<FpVar<F>>::new_variable(ns!(cs, "data"), || Ok(rec.data.clone()), mode)?;

            Ok(UOVPubkeyVar {
                data,
                n: PhantomData,
                m: PhantomData,
            })
        })
    }
}

impl<F: PrimeField, H: FieldHash<F>, const N: usize, const M: usize> ToConstraintField<F>
    for UOVPubkey<F, H, N, M>
{
    fn to_field_elements(&self) -> Option<Vec<F>> {
        Some(self.data.clone())
    }
}

impl<F: PrimeField, H: FieldHash<F>, const N: usize, const M: usize> Pubkey<F>
    for UOVPubkey<F, H, N, M>
{
    type PubkeyVar = UOVPubkeyVar<F, N, M>;

    type Sig = UOVSig<F, N, M>;

    type SigVar = UOVSigVar<F, N, M>;

    fn verify(&self, signature: Self::Sig, msg: F) -> bool {
        let mut check = true;
        let mut t = DVector::from_element(M, F::ZERO);

        t[0] = H::hash(&[msg]);
        for i in 1..M {
            t[i] = H::hash(&[t[i - 1]]);
        }

        let s = DVector::from_vec(signature.preimage);

        for i in 0..M {
            let pi = DMatrix::from_vec(N, N, self.data[(i * N * N)..((i + 1) * N * N)].to_vec());

            check &= (s.transpose() * pi * &s)[0] == t[i];
        }

        check
    }

    fn verify_zk(
        pubkey: Self::PubkeyVar,
        signature: Self::SigVar,
        msg: FpVar<F>,
    ) -> Result<Boolean<F>, SynthesisError> {
        let mut t = vec![];
        t.push(H::hash_in_zk(&[msg])?);
        for i in 1..M {
            t.push(H::hash_in_zk(&t[(i - 1)..i])?);
        }

        let mut check = Boolean::TRUE;

        for i in 0..M {
            // let mut x = FpVar::Constant(F::zero());
            let x = (0..N)
                .map(|j| {
                    let sl = &pubkey.data[(i * (N * N) + j * N)..(i * (N * N) + (j + 1) * N)];

                    &signature.preimage[j]
                        * (0..N)
                            .map(|k| &signature.preimage[k] * &sl[k])
                            .sum::<FpVar<F>>()
                })
                .sum();

            check &= (t[i].is_eq(&x))?;
        }

        Ok(check)
    }
}

/// A UOV private signing key.
#[derive(Clone, Default, Debug)]
pub struct UOVPrivkey<F: PrimeField, H: FieldHash<F>, const N: usize, const M: usize> {
    o: DMatrix<F>,
    s_i: Vec<DMatrix<F>>,
    p1s: Vec<DMatrix<F>>,
    p2s: Vec<DMatrix<F>>,
    p3s: Vec<DMatrix<F>>,
    n: PhantomData<[(); N]>,
    m: PhantomData<[(); M]>,
    h: PhantomData<H>,
}

/// A compressed UOV private key.
#[derive(Clone, Default, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct UOVCompressedPrivkey<F: PrimeField, const N: usize, const M: usize> {
    seed: Vec<F>,
    n: PhantomData<[(); N]>,
    m: PhantomData<[(); M]>,
}

impl<F: PrimeField + Absorb, H: FieldHash<F>, const N: usize, const M: usize> Privkey<F>
    for UOVPrivkey<F, H, N, M>
where
    Standard: Distribution<F>,
{
    type CompressedPrivKey = UOVCompressedPrivkey<F, N, M>;

    type Sig = UOVSig<F, N, M>;

    type Pubkey = UOVPubkey<F, H, N, M>;

    fn gen_ckey(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self::CompressedPrivKey {
        let mut out = vec![];
        for _ in 0..32 {
            out.push(rng.r#gen());
        }
        Self::CompressedPrivKey {
            seed: out,
            n: PhantomData,
            m: PhantomData,
        }
    }

    fn gen_key(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        let mut o = DMatrix::from_element(N - M, M, F::ZERO);

        for j in 0..M {
            for i in 0..(N - M) {
                o[(i, j)] = rng.r#gen();
            }
        }

        let mut p1s = vec![];
        let mut p2s = vec![];
        let mut p3s = vec![];
        let mut s_i = vec![];

        for _ in 0..(M) {
            let mut p1 = DMatrix::from_element(N - M, N - M, F::ZERO);

            for j in 0..(N - M) {
                for i in 0..(N - M) {
                    p1[(i, j)] = rng.r#gen();
                }
            }
            p1s.push(p1.clone());

            let mut p2 = DMatrix::from_element(N - M, M, F::ZERO);

            for j in 0..M {
                for i in 0..(N - M) {
                    p2[(i, j)] = rng.r#gen();
                }
            }
            p2s.push(p2.clone());

            let mut p3 = -(o.transpose() * &p1 * &o) - &o.transpose() * &p2;

            for c in 0..M {
                for r in 0..c {
                    p3[(r, c)] = p3[(r, c)] + p3[(c, r)];
                    p3[(c, r)] = F::ZERO;
                }
            }
            p3s.push(p3);

            let si = (&p1 + p1.transpose()) * &o + p2;
            s_i.push(si);
        }
        Self {
            o,
            s_i,
            p1s,
            p2s,
            p3s,
            n: PhantomData,
            m: PhantomData,
            h: PhantomData,
        }
    }

    fn into_key(c: Self::CompressedPrivKey) -> Self {
        let mut state = c.seed.clone();

        fn update_state<F: PrimeField + Absorb, H: FieldHash<F>>(state: &mut Vec<F>) -> F {
            for i in 0..state.len() {
                state[i] = H::hash(&[state[i]]);
            }
            H::hash(&state)
        }

        let mut o = DMatrix::from_element(N - M, M, F::ZERO);

        for j in 0..M {
            for i in 0..(N - M) {
                o[(i, j)] = update_state::<F, H>(&mut state);
            }
        }

        let mut p1s = vec![];
        let mut p2s = vec![];
        let mut p3s = vec![];
        let mut s_i = vec![];

        for _ in 0..(M) {
            let mut p1 = DMatrix::from_element(N - M, N - M, F::ZERO);

            for j in 0..(N - M) {
                for i in 0..(N - M) {
                    p1[(i, j)] = update_state::<F, H>(&mut state);
                }
            }
            p1s.push(p1.clone());

            let mut p2 = DMatrix::from_element(N - M, M, F::ZERO);

            for j in 0..M {
                for i in 0..(N - M) {
                    p2[(i, j)] = update_state::<F, H>(&mut state);
                }
            }
            p2s.push(p2.clone());

            let mut p3 = -(o.transpose() * &p1 * &o) - &o.transpose() * &p2;

            for c in 0..M {
                for r in 0..c {
                    p3[(r, c)] = p3[(r, c)] + p3[(c, r)];
                    p3[(c, r)] = F::ZERO;
                }
            }
            p3s.push(p3);

            let si = (&p1 + p1.transpose()) * &o + p2;
            s_i.push(si);
        }
        Self {
            o,
            s_i,
            p1s,
            p2s,
            p3s,
            n: PhantomData,
            m: PhantomData,
            h: PhantomData,
        }
    }

    fn get_pubkey(&self) -> Self::Pubkey {
        let mut pk = vec![];
        for k in 0..M {
            for r in 0..(N - M) {
                for i in 0..(N - M) {
                    pk.push(self.p1s[k][(r, i)]);
                }

                for i in 0..(M) {
                    pk.push(self.p2s[k][(r, i)]);
                }
            }

            for r in 0..(M) {
                for _ in 0..(N - M) {
                    pk.push(F::ZERO);
                }
                for i in 0..(M) {
                    pk.push(self.p3s[k][(r, i)]);
                }
            }
        }

        Self::Pubkey {
            data: pk,
            n: PhantomData,
            m: PhantomData,
            h: PhantomData,
        }
    }

    fn sign(&self, rng: &mut (impl rand::CryptoRng + rand::RngCore), msg: F) -> Option<Self::Sig> {
        let mut t = DVector::from_element(M, F::ZERO);

        t[0] = H::hash(&[msg]);
        for i in 1..M {
            t[i] = H::hash(&[t[i - 1]]);
        }

        let mut v = DVector::from_element(N - M, F::ZERO);

        for i in 0..(N - M) {
            v[i] = rng.r#gen();
        }

        let mut ml = DMatrix::from_element(M, M, F::ZERO);

        for (i, mut row) in ml.row_iter_mut().enumerate() {
            row.copy_from(&(v.transpose() * &self.s_i[i]));
        }

        let mut y: DVector<F> = DVector::from_element(M, F::ZERO);

        for i in 0..M {
            y[i] = (v.transpose() * &self.p1s[i] * &v)[0];
        }

        let mut ml = ml.insert_column(M, F::ZERO);

        for i in 0..M {
            ml[(i, M)] = t[i] - y[i];
        }

        let out = rref_solve(&ml);

        match out {
            Some(x) => {
                let mut baro = DMatrix::from_element(N, M, F::ZERO);
                baro.index_mut((0..(N - M), 0..M)).copy_from(&self.o);

                baro.index_mut(((N - M)..N, 0..M))
                    .copy_from(&DMatrix::identity(M, M));

                let mut barv = DVector::from_element(N, F::ZERO);
                barv.index_mut((0..(N - M), 0)).copy_from(&v);

                let s = barv + baro * x;
                let mut output = vec![];

                for i in 0..N {
                    output.push(s[i]);
                }

                Some(Self::Sig {
                    preimage: output,
                    n: PhantomData,
                    m: PhantomData,
                })
            }
            None => None,
        }
    }
}

fn rref_solve<F: PrimeField>(matrix: &DMatrix<F>) -> Option<DVector<F>> {
    let mut m = matrix.clone();

    let rows = m.nrows();
    let cols = m.ncols();
    let mut l = 0;

    'o: for r in 0..rows {
        if cols <= l {
            break;
        }
        let mut i = r;

        while m[(i, l)] == F::ZERO {
            i += 1;
            if rows == i {
                i = r;
                l += 1;
                if cols == l {
                    break 'o;
                }
            }
        }

        for j in 0..cols {
            let t = m[(r, j)];
            m[(r, j)] = m[(i, j)];
            m[(i, j)] = t;
        }

        if m[(r, l)] != F::ZERO {
            let t = m[(r, l)];
            for j in 0..cols {
                m[(r, j)] *= t.inverse().unwrap();
            }
        }

        for j in 0..rows {
            if j != r {
                let lv = m[(j, l)];
                for k in 0..cols {
                    let op = m[(r, k)];
                    m[(j, k)] -= lv * op;
                }
            }
        }

        l += 1;
    }

    for r in 0..rows {
        let mut ctr = 0;
        for j in 0..(cols - 1) {
            if m[(r, j)] == F::ZERO {
                ctr += 1;
            }
        }
        if ctr == (cols - 1) {
            return None;
        }
    }

    Some(m.column(cols - 1).into_owned())
}

/// The UOV Signature scheme. Implements [`Signature`].
#[derive(Clone, Default, Debug)]
pub struct UOV<F: PrimeField + Absorb, H: FieldHash<F>, const N: usize, const M: usize> {
    _f: PhantomData<F>,
    _n: PhantomData<[(); N]>,
    _m: PhantomData<[(); M]>,
    _h: PhantomData<H>,
}

impl<F: PrimeField + Absorb, H: FieldHash<F>, const N: usize, const M: usize> Signature<F>
    for UOV<F, H, N, M>
where
    Standard: Distribution<F>,
{
    type Sig = UOVSig<F, N, M>;
    type SigVar = UOVSigVar<F, N, M>;

    type Pubkey = UOVPubkey<F, H, N, M>;
    type PubkeyVar = UOVPubkeyVar<F, N, M>;

    type CPrivkey = UOVCompressedPrivkey<F, N, M>;

    type Privkey = UOVPrivkey<F, H, N, M>;
}

/// Testing setting for UOV signatures.
pub type TestUOV<F> = UOV<F, Poseidon<2>, 15, 6>;
/// Bleeding edge security.
pub type BleedingUOV<F> = UOV<F, Poseidon<2>, 80, 35>;
/// Standard L1 security. Note that while the L1 parameters are identical to UOV, the base field is
/// much larger.
pub type L1UOV<F> = UOV<F, Poseidon<2>, 112, 44>;
/// Standard L2 security.
pub type L2UOV<F> = UOV<F, Poseidon<2>, 160, 64>;
