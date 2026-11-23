/// This module contains the implementation the NIFSTrait for the
/// [Nova](https://eprint.iacr.org/2021/370.pdf) NIFS (Non-Interactive Folding Scheme).
use ark_crypto_primitives::sponge::{constraints::AbsorbGadget, Absorb, CryptographicSponge};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar};
use ark_relations::r1cs::SynthesisError;
use ark_std::rand::RngCore;
use ark_std::{UniformRand, Zero};
use std::marker::PhantomData;

use super::NIFSTrait;
use crate::arith::r1cs::R1CS;
use crate::commitment::CommitmentScheme;
use crate::constants::NOVA_N_BITS_RO;
use crate::folding::circuits::{
    cyclefold::{CycleFoldCommittedInstance, CycleFoldWitness},
    nonnative::affine::NonNativeAffineVar,
    CF1,
};
use crate::folding::nova::{CommittedInstance, Witness};
use crate::transcript::{Transcript, TranscriptVar};
use crate::utils::vec::{hadamard, mat_vec_mul, vec_add, vec_scalar_mul, vec_sub};
use crate::{Curve, Error};

/// ChallengeGadget computes the RO challenge used for the Nova instances NIFS, it contains a
/// rust-native and a in-circuit compatible versions.
pub struct ChallengeGadget<C: Curve, CI: Absorb> {
    _c: PhantomData<C>,
    _ci: PhantomData<CI>,
}
impl<C: Curve, CI: Absorb> ChallengeGadget<C, CI> {
    pub fn get_challenge_native<T: Transcript<C::ScalarField>>(
        transcript: &mut T,
        pp_hash: C::ScalarField, // public params hash
        U_i: &CI,
        u_i: &CI,
        cmT: Option<&C>,
    ) -> Vec<bool> {
        transcript.absorb(&pp_hash);
        transcript.absorb(&U_i);
        transcript.absorb(&u_i);
        // in the Nova case we absorb the cmT, in Ova case we don't since it is not used.
        if let Some(cmT_value) = cmT {
            transcript.absorb_nonnative(cmT_value);
        }
        transcript.squeeze_bits(NOVA_N_BITS_RO)
    }

    // compatible with the native get_challenge_native
    pub fn get_challenge_gadget<
        S: CryptographicSponge,
        T: TranscriptVar<CF1<C>, S>,
        CIVar: AbsorbGadget<CF1<C>>,
    >(
        transcript: &mut T,
        pp_hash: FpVar<CF1<C>>,      // public params hash
        U_i_vec: Vec<FpVar<CF1<C>>>, // apready processed input, so we don't have to recompute these values
        u_i: CIVar,
        cmT: Option<NonNativeAffineVar<C>>,
    ) -> Result<Vec<Boolean<C::ScalarField>>, SynthesisError> {
        transcript.absorb(&pp_hash)?;
        transcript.absorb(&U_i_vec)?;
        transcript.absorb(&u_i)?;
        // in the Nova case we absorb the cmT, in Ova case we don't since it is not used.
        if let Some(cmT_value) = cmT {
            transcript.absorb_nonnative(&cmT_value)?;
        }
        transcript.squeeze_bits(NOVA_N_BITS_RO)
    }
}

/// Implements the Non-Interactive Folding Scheme described in section 4 of
/// [Nova](https://eprint.iacr.org/2021/370.pdf).
/// `H` specifies whether the NIFS will use a blinding factor
pub struct NIFS<
    C: Curve,
    CS: CommitmentScheme<C, H>,
    T: Transcript<C::ScalarField>,
    const H: bool = false,
> {
    _c: PhantomData<C>,
    _cp: PhantomData<CS>,
    _t: PhantomData<T>,
}

impl<C: Curve, CS: CommitmentScheme<C, H>, T: Transcript<C::ScalarField>, const H: bool>
    NIFSTrait<C, CS, T, H> for NIFS<C, CS, T, H>
{
    type CommittedInstance = CommittedInstance<C>;
    type Witness = Witness<C>;
    type ProverAux = Vec<C::ScalarField>;
    type Proof = C;

    fn new_witness(w: Vec<C::ScalarField>, e_len: usize, rng: impl RngCore) -> Self::Witness {
        Witness::new::<H>(w, e_len, rng)
    }

    fn new_instance(
        _rng: impl RngCore,
        params: &CS::ProverParams,
        W: &Self::Witness,
        x: Vec<C::ScalarField>,
        _aux: Vec<C::ScalarField>,
    ) -> Result<Self::CommittedInstance, Error> {
        W.commit::<CS, H>(params, x)
    }

    fn fold_witness(
        r: C::ScalarField,
        W_i: &Self::Witness,
        w_i: &Self::Witness,
        aux: &Self::ProverAux, // T in Nova's notation
    ) -> Result<Self::Witness, Error> {
        // use r_T=0 since we don't need hiding property for cm(T)
        Self::fold_witness_with_rT(r, W_i, w_i, aux, C::ScalarField::zero())
    }

    fn prove(
        cs_prover_params: &CS::ProverParams,
        r1cs: &R1CS<C::ScalarField>,
        transcript: &mut T,
        pp_hash: C::ScalarField,
        W_i: &Self::Witness,
        U_i: &Self::CommittedInstance,
        w_i: &Self::Witness,
        u_i: &Self::CommittedInstance,
    ) -> Result<
        (
            Self::Witness,
            Self::CommittedInstance,
            Self::Proof,
            Vec<bool>,
        ),
        Error,
    > {
        // compute the cross terms
        let z1: Vec<C::ScalarField> = [vec![U_i.u], U_i.x.to_vec(), W_i.W.to_vec()].concat();
        let z2: Vec<C::ScalarField> = [vec![u_i.u], u_i.x.to_vec(), w_i.W.to_vec()].concat();
        let T = Self::compute_T(r1cs, U_i.u, u_i.u, &z1, &z2, &W_i.E, &w_i.E)?;

        // use r_T=0 since we don't need hiding property for cm(T)
        let cmT = CS::commit(cs_prover_params, &T, &C::ScalarField::zero())?;

        let r_bits = ChallengeGadget::<C, Self::CommittedInstance>::get_challenge_native(
            transcript,
            pp_hash,
            U_i,
            u_i,
            Some(&cmT),
        );
        let r_Fr = C::ScalarField::from_bigint(BigInteger::from_bits_le(&r_bits))
            .ok_or(Error::OutOfBounds)?;

        let w = Self::fold_witness(r_Fr, W_i, w_i, &T)?;

        let ci = Self::fold_committed_instances(r_Fr, U_i, u_i, &cmT);

        Ok((w, ci, cmT, r_bits))
    }

    fn verify(
        transcript: &mut T,
        pp_hash: C::ScalarField,
        U_i: &Self::CommittedInstance,
        u_i: &Self::CommittedInstance,
        cmT: &C, // Proof
    ) -> Result<(Self::CommittedInstance, Vec<bool>), Error> {
        let r_bits = ChallengeGadget::<C, Self::CommittedInstance>::get_challenge_native(
            transcript,
            pp_hash,
            U_i,
            u_i,
            Some(cmT),
        );
        let r = C::ScalarField::from_bigint(BigInteger::from_bits_le(&r_bits))
            .ok_or(Error::OutOfBounds)?;

        Ok((Self::fold_committed_instances(r, U_i, u_i, cmT), r_bits))
    }
}

impl<C: Curve, CS: CommitmentScheme<C, H>, T: Transcript<C::ScalarField>, const H: bool>
    NIFS<C, CS, T, H>
{
    /// Folds two witnesses, `W' = W_i + r·w_i` and `E' = E_i + r·T + r²·e_i`, where `T` was
    /// committed as `cmT = Com(T, rT)`, so `rE' = rE_i + r·rT + r²·rE_w`. This matches
    /// `fold_committed_instances`' `cmE' = cmE_i + r·cmT + r²·cmE_w` for any `rT`. (personas
    /// fork: generalised from upstream's `rT = 0` for `prove_hiding`.)
    pub fn fold_witness_with_rT(
        r: C::ScalarField,
        W_i: &Witness<C>,
        w_i: &Witness<C>,
        T: &[C::ScalarField],
        rT: C::ScalarField,
    ) -> Result<Witness<C>, Error> {
        let r2 = r * r;
        let E: Vec<C::ScalarField> = vec_add(
            &vec_add(&W_i.E, &vec_scalar_mul(T, &r))?,
            &vec_scalar_mul(&w_i.E, &r2),
        )?;
        let rE = W_i.rE + r * rT + r2 * w_i.rE;
        let W: Vec<C::ScalarField> = W_i
            .W
            .iter()
            .zip(&w_i.W)
            .map(|(a, b)| *a + (r * b))
            .collect();

        let rW = W_i.rW + r * w_i.rW;
        Ok(Witness { E, rE, W, rW })
    }

    /// compute_T: compute cross-terms T. We use the approach described in
    /// [Mova](https://eprint.iacr.org/2024/1220.pdf)'s section 5.2.
    pub fn compute_T(
        r1cs: &R1CS<C::ScalarField>,
        u1: C::ScalarField,
        u2: C::ScalarField,
        z1: &[C::ScalarField],
        z2: &[C::ScalarField],
        E1: &[C::ScalarField],
        E2: &[C::ScalarField],
    ) -> Result<Vec<C::ScalarField>, Error> {
        let z = vec_add(z1, z2)?;

        // this is parallelizable (for the future)
        let Az = mat_vec_mul(&r1cs.A, &z)?;
        let Bz = mat_vec_mul(&r1cs.B, &z)?;
        let Cz = mat_vec_mul(&r1cs.C, &z)?;
        let u = u1 + u2;
        let uCz = vec_scalar_mul(&Cz, &u);
        let AzBz = hadamard(&Az, &Bz)?;
        let lhs = vec_sub(&AzBz, &uCz)?;
        vec_sub(&vec_sub(&lhs, E1)?, E2)
    }

    pub fn compute_cyclefold_cmT(
        cs_prover_params: &CS::ProverParams,
        r1cs: &R1CS<C::ScalarField>, // R1CS over C2.Fr=C1.Fq (here C=C2)
        w1: &CycleFoldWitness<C>,
        ci1: &CycleFoldCommittedInstance<C>,
        w2: &CycleFoldWitness<C>,
        ci2: &CycleFoldCommittedInstance<C>,
    ) -> Result<(Vec<C::ScalarField>, C), Error> {
        let z1: Vec<C::ScalarField> = [vec![ci1.u], ci1.x.to_vec(), w1.W.to_vec()].concat();
        let z2: Vec<C::ScalarField> = [vec![ci2.u], ci2.x.to_vec(), w2.W.to_vec()].concat();

        // compute cross terms
        let T = Self::compute_T(r1cs, ci1.u, ci2.u, &z1, &z2, &w1.E, &w2.E)?;
        // use r_T=0 since we don't need hiding property for cm(T)
        let cmT = CS::commit(cs_prover_params, &T, &C::ScalarField::zero())?;
        Ok((T, cmT))
    }

    /// folds two committed instances with the given r and cmT. This method is used by
    /// Nova::verify, but also by Nova::prove and the CycleFoldNIFS::verify.
    pub fn fold_committed_instances(
        r: C::ScalarField,
        U_i: &CommittedInstance<C>,
        u_i: &CommittedInstance<C>,
        cmT: &C,
    ) -> CommittedInstance<C> {
        let r2 = r * r;
        let cmE = U_i.cmE + cmT.mul(r) + u_i.cmE.mul(r2);
        let u = U_i.u + r * u_i.u;
        let cmW = U_i.cmW + u_i.cmW.mul(r);
        let x = U_i
            .x
            .iter()
            .zip(&u_i.x)
            .map(|(a, b)| *a + (r * b))
            .collect::<Vec<C::ScalarField>>();

        CommittedInstance { cmE, u, cmW, x }
    }

    pub fn prove_commitments(
        tr: &mut impl Transcript<C::ScalarField>,
        cs_prover_params: &CS::ProverParams,
        w: &Witness<C>,
        ci: &CommittedInstance<C>,
        T: Vec<C::ScalarField>,
        cmT: &C,
    ) -> Result<[CS::Proof; 3], Error> {
        let cmE_proof = CS::prove(cs_prover_params, tr, &ci.cmE, &w.E, &w.rE, None)?;
        let cmW_proof = CS::prove(cs_prover_params, tr, &ci.cmW, &w.W, &w.rW, None)?;
        let cmT_proof = CS::prove(cs_prover_params, tr, cmT, &T, &C::ScalarField::zero(), None)?; // cm(T) is committed with rT=0
        Ok([cmE_proof, cmW_proof, cmT_proof])
    }
}

impl<C: Curve, CS: CommitmentScheme<C, true>, T: Transcript<C::ScalarField>> NIFS<C, CS, T, true> {
    /// personas fork (C4, docs/FOLD_ITERATION_HIDING.md): `NIFSTrait::prove` with a **hiding**
    /// cross-term commitment `cmT = Com(T, r_T)` for a fresh uniform `r_T`, and
    /// `rE' = rE₁ + r·r_T + r²·rE₂` (`fold_witness_with_rT`). Same transcript, same challenge
    /// derivation, same `fold_committed_instances`, so `NIFS::verify` (and so
    /// `RandomizedIVCProof::verify`) is unchanged.
    ///
    /// Why: `prove`'s `cmT = Com(T, 0)` is a deterministic function of both witnesses. The
    /// two folds of `RandomizedIVCProof::new` *ship* their `cmT` (`π`, `π′`), and the
    /// hiding argument for that proof (HyperNova Appendix D.4, Lemma 9) assumes hiding
    /// commitments. Used **only** there: `prove_step` must keep `r_T = 0`, because the
    /// randomized base case relies on `cmT = Com(0, 0) = 0` to make `U_1 = U_init`.
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub fn prove_hiding(
        mut rng: impl RngCore,
        cs_prover_params: &CS::ProverParams,
        r1cs: &R1CS<C::ScalarField>,
        transcript: &mut T,
        pp_hash: C::ScalarField,
        W_i: &Witness<C>,
        U_i: &CommittedInstance<C>,
        w_i: &Witness<C>,
        u_i: &CommittedInstance<C>,
    ) -> Result<(Witness<C>, CommittedInstance<C>, C, Vec<bool>), Error> {
        // compute the cross terms
        let z1: Vec<C::ScalarField> = [vec![U_i.u], U_i.x.to_vec(), W_i.W.to_vec()].concat();
        let z2: Vec<C::ScalarField> = [vec![u_i.u], u_i.x.to_vec(), w_i.W.to_vec()].concat();
        let T = Self::compute_T(r1cs, U_i.u, u_i.u, &z1, &z2, &W_i.E, &w_i.E)?;

        let rT = C::ScalarField::rand(&mut rng);
        let cmT = CS::commit(cs_prover_params, &T, &rT)?;

        let r_bits = ChallengeGadget::<C, CommittedInstance<C>>::get_challenge_native(
            transcript,
            pp_hash,
            U_i,
            u_i,
            Some(&cmT),
        );
        let r_Fr = C::ScalarField::from_bigint(BigInteger::from_bits_le(&r_bits))
            .ok_or(Error::OutOfBounds)?;

        let w = Self::fold_witness_with_rT(r_Fr, W_i, w_i, &T, rT)?;
        let ci = Self::fold_committed_instances(r_Fr, U_i, u_i, &cmT);

        Ok((w, ci, cmT, r_bits))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
    use ark_pallas::{Fr, Projective};

    use crate::arith::{r1cs::tests::get_test_r1cs, ArithRelation};
    use crate::commitment::pedersen::Pedersen;
    use crate::folding::nova::nifs::tests::test_nifs_opt;

    #[test]
    fn test_nifs_nova() -> Result<(), Error> {
        let (W, U) = test_nifs_opt::<NIFS<Projective, Pedersen<Projective>, PoseidonSponge<Fr>>>()?;

        // check the last folded instance relation
        let r1cs = get_test_r1cs();
        r1cs.check_relation(&W, &U)?;
        Ok(())
    }
}
