/// Implements the scheme described in [Nova](https://eprint.iacr.org/2021/370.pdf) and
/// [CycleFold](https://eprint.iacr.org/2023/1192.pdf).
///
/// The structure of the Nova code is the following:
/// - NIFS implementation for Nova (nifs.rs), Mova (mova.rs), Ova (ova.rs)
/// - IVC and the Decider (offchain Decider & onchain Decider) implementations for Nova
use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    Absorb, CryptographicSponge,
};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use ark_std::{cmp::max, fmt::Debug, marker::PhantomData, rand::RngCore, One, UniformRand, Zero};

use crate::folding::{circuits::CF1, traits::Dummy};
use crate::frontend::FCircuit;
use crate::transcript::{poseidon::poseidon_canonical_config, Transcript};
use crate::utils::vec::is_zero_vec;
use crate::FoldingScheme;
use crate::{
    arith::r1cs::{extract_r1cs, extract_w_x, R1CS},
    constants::NOVA_N_BITS_RO,
    utils::pp_hash,
};
use crate::{
    arith::Arith,
    folding::circuits::cyclefold::{
        fold_cyclefold_circuit, CycleFoldCircuit, CycleFoldCommittedInstance, CycleFoldConfig,
        CycleFoldWitness,
    },
};
use crate::{
    arith::{ArithRelation, ArithSampler},
    commitment::CommitmentScheme,
};
use crate::{Curve, Error};
use decider_eth_circuit::WitnessVar;

pub mod circuits;
pub mod traits;
pub mod zk;

// personas fork: hand-built attacks on the fold path (B1-B3), docs/FINDINGS.md O14-O16.
#[cfg(test)]
mod attacks;
// personas fork: iteration-hiding tests (C1/C2/C4), docs/FOLD_ITERATION_HIDING.md.
#[cfg(test)]
pub(crate) mod iterhide_tests;

// NIFS related:
pub mod nifs;

use circuits::AugmentedFCircuit;
use nifs::{nova::NIFS, nova_circuits::CommittedInstanceVar, NIFSTrait};

// personas fork: the deciders below were not updated for the iteration-hiding changes
// (committed step counter, randomized base case). They sit behind the off-by-default
// `deciders` feature; see folding-schemes/Cargo.toml. `decider_eth_circuit` stays compiled
// for its `WitnessVar`.
// offchain decider
#[cfg(feature = "deciders")]
pub mod decider;
#[cfg(feature = "deciders")]
pub mod decider_circuits;
// onchain decider
#[cfg(feature = "deciders")]
pub mod decider_eth;
// Its `TryFrom<Nova>` (the stale decider circuit) is gated, so without the feature some of its
// imports go unused.
#[cfg_attr(not(feature = "deciders"), allow(unused_imports))]
pub mod decider_eth_circuit;

use super::traits::{CommittedInstanceOps, Inputize, WitnessOps};

/// Configuration for Nova's CycleFold circuit
pub struct NovaCycleFoldConfig<C: Curve> {
    _c: PhantomData<C>,
}

impl<C: Curve> CycleFoldConfig for NovaCycleFoldConfig<C> {
    const RANDOMNESS_BIT_LENGTH: usize = NOVA_N_BITS_RO;
    // Number of points to be folded in the CycleFold circuit, in Nova's case, this is a fixed
    // amount:
    // 2 points to be folded.
    const N_INPUT_POINTS: usize = 2;
    type C = C;
}

/// CycleFold circuit for computing random linear combinations of group elements
/// in Nova instances.
pub type NovaCycleFoldCircuit<C> = CycleFoldCircuit<NovaCycleFoldConfig<C>>;

/// personas fork (C1, docs/FOLD_ITERATION_HIDING.md): domain separator of the committed step
/// counter `c_i = Poseidon(D_CTR, i, ρ)`. It is absorbed first, where every instance hash
/// absorbs `pp_hash` (a SHA3 output reduced mod p) and every NIFS transcript absorbs
/// `pp_hash`, so a counter hash and an instance hash can only collide if `pp_hash = D_CTR`.
/// That matters because the arkworks Poseidon sponge does not length-pad. 29 ASCII bytes, so
/// no modular reduction.
pub const STEP_COUNTER_DOMAIN: &[u8] = b"personas/nova/step-counter/v1";

/// `D_CTR` as a field element: [`STEP_COUNTER_DOMAIN`], little-endian.
pub fn step_counter_domain<F: PrimeField>() -> F {
    F::from_le_bytes_mod_order(STEP_COUNTER_DOMAIN)
}

/// personas fork (C1): the committed step counter `c = Poseidon(D_CTR, i, ρ)`, natively.
/// Compatible with the in-circuit `circuits::committed_step_counter_var`. With a uniform,
/// secret `ρ` (`Nova::randomize_initial_accumulators`) it hides `i` in the ROM. With `ρ = 0`
/// (a plain run) it is a deterministic function of `i`.
pub fn committed_step_counter<F: PrimeField + Absorb>(
    poseidon_config: &PoseidonConfig<F>,
    i: F,
    rho: F,
) -> F {
    let mut sponge = PoseidonSponge::<F>::new(poseidon_config);
    sponge.absorb(&step_counter_domain::<F>());
    sponge.absorb(&i);
    sponge.absorb(&rho);
    sponge.squeeze_field_elements(1)[0]
}

#[derive(Debug, Clone, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CommittedInstance<C: Curve> {
    pub cmE: C,
    pub u: C::ScalarField,
    pub cmW: C,
    pub x: Vec<C::ScalarField>,
}

impl<C: Curve> Dummy<usize> for CommittedInstance<C> {
    fn dummy(io_len: usize) -> Self {
        Self {
            cmE: C::zero(),
            u: CF1::<C>::zero(),
            cmW: C::zero(),
            x: vec![CF1::<C>::zero(); io_len],
        }
    }
}

impl<C: Curve> Dummy<&R1CS<CF1<C>>> for CommittedInstance<C> {
    fn dummy(r1cs: &R1CS<CF1<C>>) -> Self {
        Self::dummy(r1cs.n_public_inputs())
    }
}

impl<C: Curve> Absorb for CommittedInstance<C> {
    fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
        C::ScalarField::batch_to_sponge_bytes(&self.to_sponge_field_elements_as_vec(), dest);
    }

    fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
        self.u.to_sponge_field_elements(dest);
        self.x.to_sponge_field_elements(dest);
        self.cmE.to_native_sponge_field_elements(dest);
        self.cmW.to_native_sponge_field_elements(dest);
    }
}

impl<C: Curve> CommittedInstanceOps<C> for CommittedInstance<C> {
    type Var = CommittedInstanceVar<C>;

    fn get_commitments(&self) -> Vec<C> {
        vec![self.cmW, self.cmE]
    }

    fn is_incoming(&self) -> bool {
        self.cmE == C::zero() && self.u == One::one()
    }
}

impl<C: Curve> Inputize<CF1<C>> for CommittedInstance<C> {
    /// Returns the internal representation in the same order as how the value
    /// is allocated in `CommittedInstanceVar::new_input`.
    fn inputize(&self) -> Vec<CF1<C>> {
        [
            &[self.u][..],
            &self.x,
            &self.cmE.inputize_nonnative(),
            &self.cmW.inputize_nonnative(),
        ]
        .concat()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Witness<C: Curve> {
    pub E: Vec<C::ScalarField>,
    pub rE: C::ScalarField,
    pub W: Vec<C::ScalarField>,
    pub rW: C::ScalarField,
}

impl<C: Curve> Witness<C> {
    /// A fresh *incoming* witness: `E = 0`, and with `H` a random `rW`.
    ///
    /// personas fork (B3, docs/FINDINGS.md O16): `rE` is always 0. An incoming instance's
    /// `cmE` is the constant 0 (`commit` below skips an all-zero `E`, and the augmented
    /// circuit hard-codes `u_i.cmE = 0`), so its only consistent opening is
    /// `(E, rE) = (0, 0)`, since `Com(0, 0) = 0`. Upstream sampled a random `rE` here, which
    /// `fold_witness` then accumulated (`r² · w.rE`) into every running witness. That made
    /// `Com(W.E, W.rE) != U.cmE` for every honest instance, which nobody noticed because no
    /// verifier checked openings (B1). Hiding of `cmE` comes from the running side: the
    /// randomized initial accumulator, and `r_T` in `NIFS::prove_hiding`.
    pub fn new<const H: bool>(w: Vec<C::ScalarField>, e_len: usize, mut rng: impl RngCore) -> Self {
        let rW = if H {
            C::ScalarField::rand(&mut rng)
        } else {
            C::ScalarField::zero()
        };

        Self {
            E: vec![C::ScalarField::zero(); e_len],
            rE: C::ScalarField::zero(),
            W: w,
            rW,
        }
    }

    /// personas fork (B1, docs/FINDINGS.md O14). Checks that `(self, U)` has the shape
    /// `r1cs` requires, and that `self` opens `U`'s commitments:
    /// `U.cmW = Com(W, rW)` and `U.cmE = Com(E, rE)`.
    ///
    /// `check_relation` alone proves nothing about a committed instance. It compares `E`
    /// with `eval(u, x, W)`, and the prover supplies `E`, `W` and the commitments
    /// independently (`attacks.rs` builds such a forgery). The opening check is what ties
    /// the witness the relation was checked against to the instance that was folded.
    ///
    /// `commit` is the scheme's commitment function over whatever parameters the caller
    /// holds (`CS::commit` with prover params, or `CS::commit_with_verifier_params`). It is
    /// computed directly, not via [`Witness::commit`], whose `cmE := 0` shortcut for an
    /// all-zero `E` would accept `(E, rE) = (0, rE ≠ 0)` against `cmE = 0`.
    pub fn check_shape_and_openings(
        &self,
        r1cs: &R1CS<C::ScalarField>,
        U: &CommittedInstance<C>,
        commit: impl Fn(&[C::ScalarField], &C::ScalarField) -> Result<C, Error>,
    ) -> Result<(), Error> {
        if U.x.len() != r1cs.n_public_inputs() {
            return Err(Error::NotExpectedLength(U.x.len(), r1cs.n_public_inputs()));
        }
        if self.W.len() != r1cs.n_witnesses() {
            return Err(Error::NotExpectedLength(self.W.len(), r1cs.n_witnesses()));
        }
        if self.E.len() != r1cs.n_constraints() {
            return Err(Error::NotExpectedLength(self.E.len(), r1cs.n_constraints()));
        }
        if commit(&self.W, &self.rW)? != U.cmW || commit(&self.E, &self.rE)? != U.cmE {
            return Err(Error::CommitmentVerificationFail);
        }
        Ok(())
    }

    pub fn commit<CS: CommitmentScheme<C, HC>, const HC: bool>(
        &self,
        params: &CS::ProverParams,
        x: Vec<C::ScalarField>,
    ) -> Result<CommittedInstance<C>, Error> {
        let mut cmE = C::zero();
        if !is_zero_vec::<C::ScalarField>(&self.E) {
            cmE = CS::commit(params, &self.E, &self.rE)?;
        }
        let cmW = CS::commit(params, &self.W, &self.rW)?;
        Ok(CommittedInstance {
            cmE,
            u: C::ScalarField::one(),
            cmW,
            x,
        })
    }
}

impl<C: Curve> Dummy<&R1CS<CF1<C>>> for Witness<C> {
    fn dummy(r1cs: &R1CS<CF1<C>>) -> Self {
        Self {
            E: vec![C::ScalarField::zero(); r1cs.n_constraints()],
            rE: C::ScalarField::zero(),
            W: vec![C::ScalarField::zero(); r1cs.n_witnesses()],
            rW: C::ScalarField::zero(),
        }
    }
}

impl<C: Curve> WitnessOps<C::ScalarField> for Witness<C> {
    type Var = WitnessVar<C>;

    fn get_openings(&self) -> Vec<(&[C::ScalarField], C::ScalarField)> {
        vec![(&self.W, self.rW), (&self.E, self.rE)]
    }
}

#[derive(Debug, Clone)]
pub struct PreprocessorParam<C1, C2, FC, CS1, CS2, const H: bool = false>
where
    C1: Curve,
    C2: Curve,
    FC: FCircuit<C1::ScalarField>,
    CS1: CommitmentScheme<C1, H>,
    CS2: CommitmentScheme<C2, H>,
{
    pub poseidon_config: PoseidonConfig<C1::ScalarField>,
    pub F: FC,
    // cs params if not provided, will be generated at the preprocess method
    pub cs_pp: Option<CS1::ProverParams>,
    pub cs_vp: Option<CS1::VerifierParams>,
    pub cf_cs_pp: Option<CS2::ProverParams>,
    pub cf_cs_vp: Option<CS2::VerifierParams>,
}

impl<C1, C2, FC, CS1, CS2, const H: bool> PreprocessorParam<C1, C2, FC, CS1, CS2, H>
where
    C1: Curve,
    C2: Curve,
    FC: FCircuit<C1::ScalarField>,
    CS1: CommitmentScheme<C1, H>,
    CS2: CommitmentScheme<C2, H>,
{
    pub fn new(poseidon_config: PoseidonConfig<C1::ScalarField>, F: FC) -> Self {
        Self {
            poseidon_config,
            F,
            cs_pp: None,
            cs_vp: None,
            cf_cs_pp: None,
            cf_cs_vp: None,
        }
    }
}

/// Proving parameters for Nova-based IVC
#[derive(Debug, Clone)]
pub struct ProverParams<C1, C2, CS1, CS2, const H: bool = false>
where
    C1: Curve,
    C2: Curve,
    CS1: CommitmentScheme<C1, H>,
    CS2: CommitmentScheme<C2, H>,
{
    /// Poseidon sponge configuration
    pub poseidon_config: PoseidonConfig<C1::ScalarField>,
    /// Proving parameters of the underlying commitment scheme over C1
    pub cs_pp: CS1::ProverParams,
    /// Proving parameters of the underlying commitment scheme over C2
    pub cf_cs_pp: CS2::ProverParams,
}

impl<C1, C2, CS1, CS2, const H: bool> Valid for ProverParams<C1, C2, CS1, CS2, H>
where
    C1: Curve,
    C2: Curve,
    CS1: CommitmentScheme<C1, H>,
    CS2: CommitmentScheme<C2, H>,
{
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        self.poseidon_config.full_rounds.check()?;
        self.poseidon_config.partial_rounds.check()?;
        self.poseidon_config.alpha.check()?;
        self.poseidon_config.ark.check()?;
        self.poseidon_config.mds.check()?;
        self.poseidon_config.rate.check()?;
        self.poseidon_config.capacity.check()?;
        self.cs_pp.check()?;
        self.cf_cs_pp.check()?;
        Ok(())
    }
}
impl<C1, C2, CS1, CS2, const H: bool> CanonicalSerialize for ProverParams<C1, C2, CS1, CS2, H>
where
    C1: Curve,
    C2: Curve,
    CS1: CommitmentScheme<C1, H>,
    CS2: CommitmentScheme<C2, H>,
{
    fn serialize_with_mode<W: std::io::prelude::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.cs_pp.serialize_with_mode(&mut writer, compress)?;
        self.cf_cs_pp.serialize_with_mode(&mut writer, compress)
    }

    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.cs_pp.serialized_size(compress) + self.cf_cs_pp.serialized_size(compress)
    }
}
impl<C1, C2, CS1, CS2, const H: bool> CanonicalDeserialize for ProverParams<C1, C2, CS1, CS2, H>
where
    C1: Curve,
    C2: Curve,
    CS1: CommitmentScheme<C1, H>,
    CS2: CommitmentScheme<C2, H>,
{
    fn deserialize_with_mode<R: std::io::prelude::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let cs_pp = CS1::ProverParams::deserialize_with_mode(&mut reader, compress, validate)?;
        let cf_cs_pp = CS2::ProverParams::deserialize_with_mode(&mut reader, compress, validate)?;
        Ok(ProverParams {
            poseidon_config: poseidon_canonical_config::<C1::ScalarField>(),
            cs_pp,
            cf_cs_pp,
        })
    }
}

/// Verification parameters for Nova-based IVC
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierParams<C1, C2, CS1, CS2, const H: bool = false>
where
    C1: Curve,
    C2: Curve,
    CS1: CommitmentScheme<C1, H>,
    CS2: CommitmentScheme<C2, H>,
{
    /// Poseidon sponge configuration
    pub poseidon_config: PoseidonConfig<C1::ScalarField>,
    /// R1CS of the Augmented step circuit
    pub r1cs: R1CS<C1::ScalarField>,
    /// R1CS of the CycleFold circuit
    pub cf_r1cs: R1CS<C2::ScalarField>,
    /// Verification parameters of the underlying commitment scheme over C1
    pub cs_vp: CS1::VerifierParams,
    /// Verification parameters of the underlying commitment scheme over C2
    pub cf_cs_vp: CS2::VerifierParams,
}

// impl<C1, C2, CS1, CS2, const H: bool> Valid for VerifierParams<C1, C2, CS1, CS2, H>
// where
//     C1: Curve,
//     C2: Curve,
//     CS1: CommitmentScheme<C1, H>,
//     CS2: CommitmentScheme<C2, H>,
// {
//     fn check(&self) -> Result<(), ark_serialize::SerializationError> {
//         self.cs_vp.check()?;
//         self.cf_cs_vp.check()?;
//         Ok(())
//     }
// }
// impl<C1, C2, CS1, CS2, const H: bool> CanonicalSerialize for VerifierParams<C1, C2, CS1, CS2, H>
// where
//     C1: Curve,
//     C2: Curve,
//     CS1: CommitmentScheme<C1, H>,
//     CS2: CommitmentScheme<C2, H>,
// {
//     fn serialize_with_mode<W: std::io::prelude::Write>(
//         &self,
//         mut writer: W,
//         compress: ark_serialize::Compress,
//     ) -> Result<(), ark_serialize::SerializationError> {
//         self.cs_vp.serialize_with_mode(&mut writer, compress)?;
//         self.cf_cs_vp.serialize_with_mode(&mut writer, compress)
//     }
//
//     fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
//         self.cs_vp.serialized_size(compress) + self.cf_cs_vp.serialized_size(compress)
//     }
// }

impl<C1, C2, CS1, CS2, const H: bool> VerifierParams<C1, C2, CS1, CS2, H>
where
    C1: Curve,
    C2: Curve,
    CS1: CommitmentScheme<C1, H>,
    CS2: CommitmentScheme<C2, H>,
{
    /// returns the hash of the public parameters of Nova
    pub fn pp_hash(&self) -> Result<C1::ScalarField, Error> {
        pp_hash::<C1, C2, CS1, CS2, H>(
            &self.r1cs,
            &self.cf_r1cs,
            &self.cs_vp,
            &self.cf_cs_vp,
            &self.poseidon_config,
        )
    }
}

#[derive(PartialEq, Eq, Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct IVCProof<C1, C2>
where
    C1: Curve,
    C2: Curve,
{
    // current step of the IVC
    pub i: C1::ScalarField,
    /// personas fork (C1): the step-counter randomness. This non-zk proof carries `(i, ρ)`
    /// in the clear and the verifier recomputes `c = Poseidon(D_CTR, i, ρ)`. It is not
    /// zero-knowledge and must never be sent where `i` is meant to stay hidden.
    pub rho: C1::ScalarField,
    // initial state
    pub z_0: Vec<C1::ScalarField>,
    // current state
    pub z_i: Vec<C1::ScalarField>,
    // running instance
    pub W_i: Witness<C1>,
    pub U_i: CommittedInstance<C1>,
    // incoming instance
    pub w_i: Witness<C1>,
    pub u_i: CommittedInstance<C1>,
    // CycleFold instances
    pub cf_W_i: CycleFoldWitness<C2>,
    pub cf_U_i: CycleFoldCommittedInstance<C2>,
}

/// Implements Nova+CycleFold's IVC, described in [Nova](https://eprint.iacr.org/2021/370.pdf) and
/// [CycleFold](https://eprint.iacr.org/2023/1192.pdf), following the FoldingScheme trait
/// The `H` const generic specifies whether the homorphic commitment scheme is blinding
#[derive(Clone, Debug)]
pub struct Nova<C1, C2, FC, CS1, CS2, const H: bool = false>
where
    C1: Curve,
    C2: Curve,
    FC: FCircuit<C1::ScalarField>,
    CS1: CommitmentScheme<C1, H>,
    CS2: CommitmentScheme<C2, H>,
{
    /// R1CS of the Augmented Function circuit
    pub r1cs: R1CS<C1::ScalarField>,
    /// R1CS of the CycleFold circuit
    pub cf_r1cs: R1CS<C2::ScalarField>,
    pub poseidon_config: PoseidonConfig<C1::ScalarField>,
    /// CommitmentScheme::ProverParams over C1
    pub cs_pp: CS1::ProverParams,
    /// CycleFold CommitmentScheme::ProverParams, over C2
    pub cf_cs_pp: CS2::ProverParams,
    /// F circuit, the circuit that is being folded
    pub F: FC,
    /// public params hash
    pub pp_hash: C1::ScalarField,
    pub i: C1::ScalarField,
    /// personas fork (C1): randomness of the committed step counter `c_i = Poseidon(D_CTR, i, ρ)`
    /// that replaces `i` in every instance hash. One `ρ` per run, sampled by
    /// `randomize_initial_accumulators`, 0 for a plain run. Secret: anyone who knows `ρ`
    /// learns `i` from `c` by trying small `i`.
    pub rho: C1::ScalarField,
    /// initial state
    pub z_0: Vec<C1::ScalarField>,
    /// current i-th state
    pub z_i: Vec<C1::ScalarField>,
    /// Nova instances
    pub w_i: Witness<C1>,
    pub u_i: CommittedInstance<C1>,
    pub W_i: Witness<C1>,
    pub U_i: CommittedInstance<C1>,

    /// CycleFold running instance
    pub cf_W_i: CycleFoldWitness<C2>,
    pub cf_U_i: CycleFoldCommittedInstance<C2>,

    /// personas fork (C2): set by [`Nova::randomize_initial_accumulators`] once `(W_i, U_i)`
    /// and `(cf_W_i, cf_U_i)` start from random satisfying pairs instead of `U_⊥`/`cf_U_⊥`.
    /// [`zk::RandomizedIVCProof::new`] refuses to build a proof without it, because a proof
    /// over a `U_⊥`-started accumulator leaks the step count. Private, so it can only be set
    /// by actually randomizing.
    randomized_init: bool,
}

impl<C1, C2, FC, CS1, CS2, const H: bool> FoldingScheme<C1, C2, FC>
    for Nova<C1, C2, FC, CS1, CS2, H>
where
    C1: Curve,
    C2: Curve,
    FC: FCircuit<C1::ScalarField>,
    CS1: CommitmentScheme<C1, H>,
    CS2: CommitmentScheme<C2, H>,
    C1: Curve<BaseField = C2::ScalarField, ScalarField = C2::BaseField>,
{
    type PreprocessorParam = PreprocessorParam<C1, C2, FC, CS1, CS2, H>;
    type ProverParam = ProverParams<C1, C2, CS1, CS2, H>;
    type VerifierParam = VerifierParams<C1, C2, CS1, CS2, H>;
    type RunningInstance = (CommittedInstance<C1>, Witness<C1>);
    type IncomingInstance = (CommittedInstance<C1>, Witness<C1>);
    type MultiCommittedInstanceWithWitness = ();
    type CFInstance = (CycleFoldCommittedInstance<C2>, CycleFoldWitness<C2>);
    type IVCProof = IVCProof<C1, C2>;

    fn pp_deserialize_with_mode<R: std::io::prelude::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
        _fc_params: FC::Params, // FCircuit params
    ) -> Result<Self::ProverParam, Error> {
        Ok(Self::ProverParam::deserialize_with_mode(
            reader, compress, validate,
        )?)
    }
    fn vp_deserialize_with_mode<R: std::io::prelude::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
        fc_params: FC::Params,
    ) -> Result<Self::VerifierParam, Error> {
        // personas fork note: hkailad/sonobe@4d4fa08 switched `VerifierParams` to a *derived*
        // `CanonicalSerialize` (the whole struct, R1CS included), but this method still read
        // only `cs_vp || cf_cs_vp`, so every round trip failed with `InvalidData`. Read the
        // derived encoding, then keep the original intent of this method: the R1CS must be
        // the one the circuit generates, never whatever the bytes say.
        let vp = Self::VerifierParam::deserialize_with_mode(reader, compress, validate)?;

        let poseidon_config = poseidon_canonical_config::<C1::ScalarField>();

        // generate the r1cs & cf_r1cs from the circuit, and require the deserialized ones to
        // match them.

        // main circuit R1CS:
        let f_circuit = FC::new(fc_params)?;
        let cs = ConstraintSystem::<C1::ScalarField>::new_ref();
        let augmented_F_circuit =
            AugmentedFCircuit::<C1, C2, FC>::empty(&poseidon_config, f_circuit.clone());
        augmented_F_circuit.generate_constraints(cs.clone())?;
        cs.finalize();
        let cs = cs.into_inner().ok_or(Error::NoInnerConstraintSystem)?;
        let r1cs = extract_r1cs::<C1::ScalarField>(&cs)?;

        // CycleFold circuit R1CS
        let cs2 = ConstraintSystem::<C1::BaseField>::new_ref();
        let cf_circuit = NovaCycleFoldCircuit::<C1>::empty();
        cf_circuit.generate_constraints(cs2.clone())?;
        cs2.finalize();
        let cs2 = cs2.into_inner().ok_or(Error::NoInnerConstraintSystem)?;
        let cf_r1cs = extract_r1cs::<C1::BaseField>(&cs2)?;

        if vp.r1cs != r1cs || vp.cf_r1cs != cf_r1cs {
            return Err(Error::SerializationError(
                ark_serialize::SerializationError::InvalidData,
            ));
        }

        Ok(Self::VerifierParam {
            poseidon_config,
            r1cs,
            cf_r1cs,
            cs_vp: vp.cs_vp,
            cf_cs_vp: vp.cf_cs_vp,
        })
    }

    fn preprocess(
        mut rng: impl RngCore,
        prep_param: &Self::PreprocessorParam,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), Error> {
        let (r1cs, cf_r1cs) =
            get_r1cs::<C1, C2, FC>(&prep_param.poseidon_config, prep_param.F.clone())?;

        // if cs params exist, use them, if not, generate new ones
        let (cs_pp, cs_vp) = match (&prep_param.cs_pp, &prep_param.cs_vp) {
            (Some(cs_pp), Some(cs_vp)) => (cs_pp.clone(), cs_vp.clone()),
            _ => CS1::setup(
                &mut rng,
                // `CS1` is for committing to Nova's witness vector `w` and
                // error term `e`, where the length of `e` is the number of
                // constraints, so we set `len` to the maximum of `e` and `w`'s
                // lengths.
                max(r1cs.n_constraints(), r1cs.n_witnesses()),
            )?,
        };
        let (cf_cs_pp, cf_cs_vp) = match (&prep_param.cf_cs_pp, &prep_param.cf_cs_vp) {
            (Some(cf_cs_pp), Some(cf_cs_vp)) => (cf_cs_pp.clone(), cf_cs_vp.clone()),
            _ => CS2::setup(
                &mut rng,
                // `CS2` is for committing to CycleFold's witness vector `w` and
                // error term `e`, where the length of `e` is the number of
                // constraints, so we set `len` to the maximum of `e` and `w`'s
                // lengths.
                max(cf_r1cs.n_constraints(), cf_r1cs.n_witnesses()),
            )?,
        };

        let prover_params = ProverParams::<C1, C2, CS1, CS2, H> {
            poseidon_config: prep_param.poseidon_config.clone(),
            cs_pp: cs_pp.clone(),
            cf_cs_pp: cf_cs_pp.clone(),
        };
        let verifier_params = VerifierParams::<C1, C2, CS1, CS2, H> {
            poseidon_config: prep_param.poseidon_config.clone(),
            r1cs,
            cf_r1cs,
            cs_vp,
            cf_cs_vp,
        };

        Ok((prover_params, verifier_params))
    }

    /// Initializes the Nova+CycleFold's IVC for the given parameters and initial state `z_0`.
    fn init(
        params: &(Self::ProverParam, Self::VerifierParam),
        F: FC,
        z_0: Vec<C1::ScalarField>,
    ) -> Result<Self, Error> {
        let (pp, vp) = params;

        // prepare the circuit to obtain its R1CS
        let cs = ConstraintSystem::<C1::ScalarField>::new_ref();
        let cs2 = ConstraintSystem::<C1::BaseField>::new_ref();

        let augmented_F_circuit =
            AugmentedFCircuit::<C1, C2, FC>::empty(&pp.poseidon_config, F.clone());
        let cf_circuit = NovaCycleFoldCircuit::<C1>::empty();

        augmented_F_circuit.generate_constraints(cs.clone())?;
        cs.finalize();
        let cs = cs.into_inner().ok_or(Error::NoInnerConstraintSystem)?;
        let r1cs = extract_r1cs::<C1::ScalarField>(&cs)?;

        cf_circuit.generate_constraints(cs2.clone())?;
        cs2.finalize();
        let cs2 = cs2.into_inner().ok_or(Error::NoInnerConstraintSystem)?;
        let cf_r1cs = extract_r1cs::<C1::BaseField>(&cs2)?;

        // compute the public params hash
        let pp_hash = vp.pp_hash()?;

        // setup the dummy instances
        let (W_dummy, U_dummy) = r1cs.dummy_witness_instance();
        let (w_dummy, u_dummy) = r1cs.dummy_witness_instance();
        let (cf_W_dummy, cf_U_dummy) = cf_r1cs.dummy_witness_instance();

        // W_dummy=W_0 is a 'dummy witness', all zeroes, but with the size corresponding to the
        // R1CS that we're working with.
        Ok(Self {
            r1cs,
            cf_r1cs,
            poseidon_config: pp.poseidon_config.clone(),
            cs_pp: pp.cs_pp.clone(),
            cf_cs_pp: pp.cf_cs_pp.clone(),
            F,
            pp_hash,
            i: C1::ScalarField::zero(),
            rho: C1::ScalarField::zero(),
            z_0: z_0.clone(),
            z_i: z_0,
            w_i: w_dummy,
            u_i: u_dummy,
            W_i: W_dummy,
            U_i: U_dummy,
            // cyclefold running instance
            cf_W_i: cf_W_dummy,
            cf_U_i: cf_U_dummy,
            randomized_init: false,
        })
    }

    /// Implements IVC.P of Nova+CycleFold
    fn prove_step(
        &mut self,
        mut rng: impl RngCore,
        external_inputs: FC::ExternalInputs,
        // Nova does not support multi-instances folding (by design)
        _other_instances: Option<Self::MultiCommittedInstanceWithWitness>,
    ) -> Result<(), Error> {
        // ensure that commitments are blinding if user has specified so.
        //
        // personas fork (B3): incoming witnesses now have `rE = 0` (their `cmE` is the constant
        // 0), so `w_i.rE` is no longer checked. Without a randomized initial accumulator, the
        // running `W_i.rE` stays 0 as well: incoming `rE` and `r_T` are both 0. (C2) With one,
        // the running blinders come from `W_init` and must be nonzero from the first step on.
        if H && self.i >= C1::ScalarField::one() {
            let blinding_commitments = if self.randomized_init {
                vec![self.w_i.rW, self.W_i.rW, self.W_i.rE]
            } else if self.i == C1::ScalarField::one() {
                // blinding values of the running instances are zero at the first iteration
                vec![self.w_i.rW]
            } else {
                vec![self.w_i.rW, self.W_i.rW]
            };
            if blinding_commitments.contains(&C1::ScalarField::zero()) {
                return Err(Error::IncorrectBlinding(
                    H,
                    format!("{:?}", blinding_commitments),
                ));
            }
        }
        // `sponge` is for digest computation.
        let sponge = PoseidonSponge::<C1::ScalarField>::new(&self.poseidon_config);
        // `transcript` is for challenge generation.
        let mut transcript = sponge.clone();

        let augmented_F_circuit: AugmentedFCircuit<C1, C2, FC>;

        // Nova does not support (by design) multi-instances folding
        if _other_instances.is_some() {
            return Err(Error::NoMultiInstances);
        }

        if self.z_i.len() != self.F.state_len() {
            return Err(Error::NotSameLength(
                "z_i.len()".to_string(),
                self.z_i.len(),
                "F.state_len()".to_string(),
                self.F.state_len(),
            ));
        }

        if self.i > C1::ScalarField::from_le_bytes_mod_order(&usize::MAX.to_le_bytes()) {
            return Err(Error::MaxStep);
        }

        let i_usize;

        #[cfg(target_pointer_width = "64")]
        {
            let mut i_bytes: [u8; 8] = [0; 8];
            i_bytes.copy_from_slice(&self.i.into_bigint().to_bytes_le()[..8]);
            i_usize = usize::from_le_bytes(i_bytes);
        }

        #[cfg(target_pointer_width = "32")]
        {
            let mut i_bytes: [u8; 4] = [0; 4];
            i_bytes.copy_from_slice(&self.i.into_bigint().to_bytes_le()[..4]);
            i_usize = usize::from_le_bytes(i_bytes);
        }

        // fold Nova instances
        let (W_i1, U_i1, cmT, r_bits): (Witness<C1>, CommittedInstance<C1>, C1, Vec<bool>) =
            NIFS::<C1, CS1, PoseidonSponge<C1::ScalarField>, H>::prove(
                &self.cs_pp,
                &self.r1cs,
                &mut transcript,
                self.pp_hash,
                &self.W_i,
                &self.U_i,
                &self.w_i,
                &self.u_i,
            )?;

        if self.i == C1::ScalarField::zero() {
            // base case
            augmented_F_circuit = AugmentedFCircuit::<C1, C2, FC> {
                poseidon_config: self.poseidon_config.clone(),
                pp_hash: Some(self.pp_hash),
                i: Some(C1::ScalarField::zero()), // = i=0
                i_usize: Some(0),
                rho: Some(self.rho),
                z_0: Some(self.z_0.clone()), // = z_i
                z_i: Some(self.z_i.clone()),
                external_inputs: Some(external_inputs.clone()),
                u_i_cmW: Some(self.u_i.cmW), // = dummy
                U_i: Some(self.U_i.clone()), // = dummy
                U_i1_cmE: Some(U_i1.cmE),
                U_i1_cmW: Some(U_i1.cmW),
                cmT: Some(cmT),
                F: self.F.clone(),
                cf1_u_i_cmW: None,
                cf2_u_i_cmW: None,
                // personas fork (C2): the base case now outputs H(cf_U_i) of the witnessed
                // CycleFold accumulator (cf_U_init after randomization), so it must be the real
                // one, not the circuit's cf_U_⊥ default. No CycleFold fold happens at i = 0.
                cf_U_i: Some(self.cf_U_i.clone()),
                cf1_cmT: None,
                cf2_cmT: None,
            };

            #[cfg(test)]
            {
                let r_Fr = C1::ScalarField::from_bigint(BigInteger::from_bits_le(&r_bits))
                    .ok_or(Error::OutOfBounds)?;
                let expected =
                    NIFS::<C1, CS1, PoseidonSponge<C1::ScalarField>, H>::fold_committed_instances(
                        r_Fr, &self.U_i, &self.u_i, &cmT,
                    );
                assert_eq!(U_i1, expected);
            }
        } else {
            // CycleFold part:
            let cfW_circuit = NovaCycleFoldCircuit::<C1> {
                r_bits: Some(r_bits.clone()),
                points: Some(vec![self.U_i.clone().cmW, self.u_i.clone().cmW]),
            };
            let cfE_circuit = NovaCycleFoldCircuit::<C1> {
                r_bits: Some(r_bits.clone()),
                points: Some(vec![self.U_i.clone().cmE, cmT]),
            };

            // fold self.cf_U_i + cfW_U -> folded running with cfW
            let (cfW_u_i, cfW_W_i1, cfW_U_i1, cfW_cmT) = self.fold_cyclefold_circuit(
                &mut transcript,
                self.cf_W_i.clone(), // CycleFold running instance witness
                self.cf_U_i.clone(), // CycleFold running instance
                cfW_circuit,
                &mut rng,
            )?;
            // fold [the output from folding self.cf_U_i + cfW_U] + cfE_U = folded_running_with_cfW + cfE
            let (cfE_u_i, cf_W_i1, cf_U_i1, cf_cmT) = self.fold_cyclefold_circuit(
                &mut transcript,
                cfW_W_i1,
                cfW_U_i1.clone(),
                cfE_circuit,
                &mut rng,
            )?;

            augmented_F_circuit = AugmentedFCircuit::<C1, C2, FC> {
                poseidon_config: self.poseidon_config.clone(),
                pp_hash: Some(self.pp_hash),
                i: Some(self.i),
                i_usize: Some(i_usize),
                rho: Some(self.rho),
                z_0: Some(self.z_0.clone()),
                z_i: Some(self.z_i.clone()),
                external_inputs: Some(external_inputs.clone()),
                u_i_cmW: Some(self.u_i.cmW),
                U_i: Some(self.U_i.clone()),
                U_i1_cmE: Some(U_i1.cmE),
                U_i1_cmW: Some(U_i1.cmW),
                cmT: Some(cmT),
                F: self.F.clone(),
                // cyclefold values
                cf1_u_i_cmW: Some(cfW_u_i.cmW),
                cf2_u_i_cmW: Some(cfE_u_i.cmW),
                cf_U_i: Some(self.cf_U_i.clone()),
                cf1_cmT: Some(cfW_cmT),
                cf2_cmT: Some(cf_cmT),
            };

            self.cf_W_i = cf_W_i1;
            self.cf_U_i = cf_U_i1;
        }

        let cs = ConstraintSystem::<C1::ScalarField>::new_ref();

        let z_i1 = augmented_F_circuit
            .compute_next_state(cs.clone())?
            .value()?;

        #[cfg(test)]
        assert!(cs.is_satisfied()?);

        let cs = cs.into_inner().ok_or(Error::NoInnerConstraintSystem)?;
        let (w_i1, x_i1) = extract_w_x::<C1::ScalarField>(&cs);

        // personas fork: every new witness (C1's `rho`, C2's witnessed base-case output) must
        // be allocated unconditionally, so a real step must have exactly the R1CS
        // `AugmentedFCircuit::empty()` produced in `preprocess`/`init`. Otherwise honest proofs
        // fail against the verifier's R1CS. Asserted on every test-build step.
        #[cfg(test)]
        {
            let mut cs_shape = cs.clone();
            cs_shape.finalize();
            assert_eq!(
                extract_r1cs::<C1::ScalarField>(&cs_shape)?,
                self.r1cs,
                "a real step's R1CS differs from AugmentedFCircuit::empty()'s"
            );
        }

        #[cfg(test)]
        if x_i1.len() != 2 {
            return Err(Error::NotExpectedLength(x_i1.len(), 2));
        }

        // set values for next iteration
        self.i += C1::ScalarField::one();
        self.z_i = z_i1;
        self.w_i = Witness::<C1>::new::<H>(w_i1, self.r1cs.n_constraints(), &mut rng);
        self.u_i = self.w_i.commit::<CS1, H>(&self.cs_pp, x_i1)?;
        self.W_i = W_i1;
        self.U_i = U_i1;

        #[cfg(test)]
        {
            self.u_i.check_incoming()?;
            self.r1cs.check_relation(&self.w_i, &self.u_i)?;
            self.r1cs.check_relation(&self.W_i, &self.U_i)?;
            // personas fork (B1/B3): openings must stay consistent after every step, for both
            // the primary pairs and CycleFold's running pair.
            let commit =
                |v: &[C1::ScalarField], r: &C1::ScalarField| CS1::commit(&self.cs_pp, v, r);
            self.w_i
                .check_shape_and_openings(&self.r1cs, &self.u_i, commit)?;
            self.W_i
                .check_shape_and_openings(&self.r1cs, &self.U_i, commit)?;
            self.cf_W_i
                .check_shape_and_openings(&self.cf_r1cs, &self.cf_U_i, |v, r| {
                    CS2::commit(&self.cf_cs_pp, v, r)
                })?;
        }

        Ok(())
    }

    fn state(&self) -> Vec<C1::ScalarField> {
        self.z_i.clone()
    }

    fn ivc_proof(&self) -> Self::IVCProof {
        Self::IVCProof {
            i: self.i,
            rho: self.rho,
            z_0: self.z_0.clone(),
            z_i: self.z_i.clone(),
            W_i: self.W_i.clone(),
            U_i: self.U_i.clone(),
            w_i: self.w_i.clone(),
            u_i: self.u_i.clone(),
            cf_W_i: self.cf_W_i.clone(),
            cf_U_i: self.cf_U_i.clone(),
        }
    }

    fn from_ivc_proof(
        ivc_proof: IVCProof<C1, C2>,
        fcircuit_params: FC::Params,
        params: (Self::ProverParam, Self::VerifierParam),
    ) -> Result<Self, Error> {
        let IVCProof {
            i,
            rho,
            z_0,
            z_i,
            W_i,
            U_i,
            w_i,
            u_i,
            cf_W_i,
            cf_U_i,
        } = ivc_proof;
        let (pp, vp) = params;

        let f_circuit = FC::new(fcircuit_params)?;
        let cs = ConstraintSystem::<C1::ScalarField>::new_ref();
        let cs2 = ConstraintSystem::<C1::BaseField>::new_ref();
        let augmented_F_circuit =
            AugmentedFCircuit::<C1, C2, FC>::empty(&pp.poseidon_config, f_circuit.clone());
        let cf_circuit = NovaCycleFoldCircuit::<C1>::empty();

        augmented_F_circuit.generate_constraints(cs.clone())?;
        cs.finalize();
        let cs = cs.into_inner().ok_or(Error::NoInnerConstraintSystem)?;
        let r1cs = extract_r1cs::<C1::ScalarField>(&cs)?;

        cf_circuit.generate_constraints(cs2.clone())?;
        cs2.finalize();
        let cs2 = cs2.into_inner().ok_or(Error::NoInnerConstraintSystem)?;
        let cf_r1cs = extract_r1cs::<C1::BaseField>(&cs2)?;

        Ok(Self {
            r1cs,
            cf_r1cs,
            poseidon_config: pp.poseidon_config,
            cs_pp: pp.cs_pp,
            cf_cs_pp: pp.cf_cs_pp,
            F: f_circuit,
            pp_hash: vp.pp_hash()?,
            i,
            rho,
            z_0,
            z_i,
            w_i,
            u_i,
            W_i,
            U_i,
            cf_W_i,
            cf_U_i,
            // personas fork (C2): an `IVCProof` does not record whether its accumulators were
            // randomized, so a Nova rebuilt from one cannot produce a `RandomizedIVCProof`.
            randomized_init: false,
        })
    }

    /// Implements IVC.V of Nov.clone()a+CycleFold. Notice that this method does not include the
    /// commitments verification, which is done in the Decider.
    fn verify(vp: Self::VerifierParam, ivc_proof: Self::IVCProof) -> Result<(), Error> {
        let Self::IVCProof {
            i: num_steps,
            rho,
            z_0,
            z_i,
            W_i,
            U_i,
            w_i,
            u_i,
            cf_W_i,
            cf_U_i,
        } = ivc_proof;

        let sponge = PoseidonSponge::<C1::ScalarField>::new(&vp.poseidon_config);

        if num_steps == C1::ScalarField::zero() {
            if z_0 != z_i {
                return Err(Error::IVCVerificationFail);
            }
            return Ok(());
        }

        if u_i.x.len() != 2 || U_i.x.len() != 2 {
            return Err(Error::IVCVerificationFail);
        }

        let pp_hash = vp.pp_hash()?;

        // check that u_i's output points to the running instance
        // u_i.X[0] == H(c, z_0, z_i, U_i), with c = Poseidon(D_CTR, i, ρ) (personas fork, C1)
        let c = committed_step_counter(&vp.poseidon_config, num_steps, rho);
        let expected_u_i_x = U_i.hash(&sponge, pp_hash, c, &z_0, &z_i);
        if expected_u_i_x != u_i.x[0] {
            return Err(Error::IVCVerificationFail);
        }
        // u_i.X[1] == H(cf_U_i)
        let expected_cf_u_i_x = cf_U_i.hash_cyclefold(&sponge, pp_hash);
        if expected_cf_u_i_x != u_i.x[1] {
            return Err(Error::IVCVerificationFail);
        }

        // check R1CS satisfiability, which is equivalent to checking if `u_i`
        // is an incoming instance and if `w_i` and `u_i` satisfy RelaxedR1CS
        u_i.check_incoming()?;
        vp.r1cs.check_relation(&w_i, &u_i)?;
        // check RelaxedR1CS satisfiability
        vp.r1cs.check_relation(&W_i, &U_i)?;

        // check CycleFold RelaxedR1CS satisfiability
        vp.cf_r1cs.check_relation(&cf_W_i, &cf_U_i)?;

        // personas fork (B1, docs/FINDINGS.md O14): the relation checks above are vacuous
        // unless each witness also opens its instance's commitments. Upstream left this to
        // "the Decider", but this method is used as a verifier on its own. Fails closed for a
        // commitment scheme whose verifier parameters cannot recompute a commitment (KZG).
        let cs_commit = |v: &[C1::ScalarField], r: &C1::ScalarField| {
            CS1::commit_with_verifier_params(&vp.cs_vp, v, r)
        };
        let cf_cs_commit = |v: &[C2::ScalarField], r: &C2::ScalarField| {
            CS2::commit_with_verifier_params(&vp.cf_cs_vp, v, r)
        };
        w_i.check_shape_and_openings(&vp.r1cs, &u_i, cs_commit)?;
        W_i.check_shape_and_openings(&vp.r1cs, &U_i, cs_commit)?;
        cf_W_i.check_shape_and_openings(&vp.cf_r1cs, &cf_U_i, cf_cs_commit)?;

        Ok(())
    }
}

impl<C1, C2, FC, CS1, CS2, const H: bool> Nova<C1, C2, FC, CS1, CS2, H>
where
    C1: Curve,
    C2: Curve,
    FC: FCircuit<C1::ScalarField>,
    CS1: CommitmentScheme<C1, H>,
    CS2: CommitmentScheme<C2, H>,
    C1: Curve<BaseField = C2::ScalarField, ScalarField = C2::BaseField>,
{
    /// personas fork (C1): the committed step counter `c = Poseidon(D_CTR, i, ρ)` of the
    /// current state. This, not `i`, is the public input a `RandomizedIVCProof` verifies
    /// against.
    pub fn c(&self) -> C1::ScalarField {
        committed_step_counter(&self.poseidon_config, self.i, self.rho)
    }

    // folds the given cyclefold circuit and its instances
    #[allow(clippy::type_complexity)]
    fn fold_cyclefold_circuit<T: Transcript<C1::ScalarField>>(
        &self,
        transcript: &mut T,
        cf_W_i: CycleFoldWitness<C2>, // witness of the running instance
        cf_U_i: CycleFoldCommittedInstance<C2>, // running instance
        cf_circuit: NovaCycleFoldCircuit<C1>,
        rng: &mut impl RngCore,
    ) -> Result<
        (
            CycleFoldCommittedInstance<C2>, // u_i
            CycleFoldWitness<C2>,           // W_i1
            CycleFoldCommittedInstance<C2>, // U_i1
            C2,                             // cmT
        ),
        Error,
    > {
        fold_cyclefold_circuit::<NovaCycleFoldConfig<C1>, C2, CS2, H>(
            transcript,
            self.cf_r1cs.clone(),
            self.cf_cs_pp.clone(),
            self.pp_hash,
            cf_W_i,
            cf_U_i,
            cf_circuit,
            rng,
        )
    }
}

/// personas fork (C2, docs/FOLD_ITERATION_HIDING.md): iteration hiding needs a blinding
/// (`H = true`) commitment scheme on both curves.
impl<C1, C2, FC, CS1, CS2> Nova<C1, C2, FC, CS1, CS2, true>
where
    C1: Curve,
    C2: Curve,
    FC: FCircuit<C1::ScalarField>,
    CS1: CommitmentScheme<C1, true>,
    CS2: CommitmentScheme<C2, true>,
    C1: Curve<BaseField = C2::ScalarField, ScalarField = C2::BaseField>,
{
    /// Starts both running accumulators from fresh **random satisfying** pairs,
    /// `(W_init, U_init)` over the augmented R1CS and `(cf_W_init, cf_U_init)` over the
    /// CycleFold R1CS (`ArithSampler::sample_witness_instance`, HyperNova construction 5),
    /// instead of `U_⊥` / `cf_U_⊥`. Must be called right after `init`, before the first
    /// `prove_step`.
    ///
    /// Why: starting from `U_⊥ = (0, 0, 0, 0)`, the running instance after `i` steps has
    /// `U_i.u = Σ_j r_j` with 128-bit challenges, so `|U_i.u| < (i−1)·2¹²⁸` reveals `i`.
    /// At `i = 1`, `U_1 = U_⊥` and `cf_U_1 = cf_U_⊥` exactly. Starting from a uniform `u_init`
    /// (and uniform `x`, `W`, blinders) makes `U_i` and `(cf_U_i, cf_W_i)` uniform satisfying
    /// pairs whatever `i` is.
    ///
    /// The base step folds `(U_init, W_init)` with the dummy incoming `u_0`. The cross term is
    /// `T = 0`, so `cmT = Com(0, 0) = 0` and `U_1 = U_init` falls out of the unchanged
    /// `NIFS::prove`. This is why `prove_step` keeps `r_T = 0`; the hiding `r_T` lives only in
    /// `NIFS::prove_hiding`, used by `RandomizedIVCProof::new`.
    pub fn randomize_initial_accumulators(&mut self, mut rng: impl RngCore) -> Result<(), Error> {
        if !self.i.is_zero() {
            return Err(Error::Other(
                "randomize_initial_accumulators must be called at i == 0, before any prove_step"
                    .to_string(),
            ));
        }
        if self.randomized_init {
            return Err(Error::Other(
                "the initial accumulators are already randomized".to_string(),
            ));
        }
        let (W_init, U_init) = self
            .r1cs
            .sample_witness_instance::<CS1>(&self.cs_pp, &mut rng)?;
        let (cf_W_init, cf_U_init) = self
            .cf_r1cs
            .sample_witness_instance::<CS2>(&self.cf_cs_pp, &mut rng)?;
        self.W_i = W_init;
        self.U_i = U_init;
        self.cf_W_i = cf_W_init;
        self.cf_U_i = cf_U_init;
        // (C1) one uniform ρ per run suffices: the intermediate u_j.x = H(c_j, ...) the verifier
        // never sees are folded into U.x, which U_init.x masks.
        self.rho = C1::ScalarField::rand(&mut rng);
        self.randomized_init = true;
        Ok(())
    }

    /// Whether [`Nova::randomize_initial_accumulators`] has run.
    pub fn has_randomized_initial_accumulators(&self) -> bool {
        self.randomized_init
    }
}

/// helper method to get the r1cs from the ConstraintSynthesizer
pub fn get_r1cs_from_cs<F: PrimeField>(
    circuit: impl ConstraintSynthesizer<F>,
) -> Result<R1CS<F>, Error> {
    let cs = ConstraintSystem::<F>::new_ref();
    circuit.generate_constraints(cs.clone())?;
    cs.finalize();
    let cs = cs.into_inner().ok_or(Error::NoInnerConstraintSystem)?;
    let r1cs = extract_r1cs::<F>(&cs)?;
    Ok(r1cs)
}

/// helper method to get the R1CS for both the AugmentedFCircuit and the CycleFold circuit
#[allow(clippy::type_complexity)]
pub fn get_r1cs<C1, C2, FC>(
    poseidon_config: &PoseidonConfig<C1::ScalarField>,
    F_circuit: FC,
) -> Result<(R1CS<C1::ScalarField>, R1CS<C2::ScalarField>), Error>
where
    C1: Curve,
    C2: Curve,
    FC: FCircuit<C1::ScalarField>,
    C1: Curve<BaseField = C2::ScalarField, ScalarField = C2::BaseField>,
{
    let augmented_F_circuit = AugmentedFCircuit::<C1, C2, FC>::empty(poseidon_config, F_circuit);
    let cf_circuit = NovaCycleFoldCircuit::<C1>::empty();
    let r1cs = get_r1cs_from_cs::<C1::ScalarField>(augmented_F_circuit)?;
    let cf_r1cs = get_r1cs_from_cs::<C2::ScalarField>(cf_circuit)?;
    Ok((r1cs, cf_r1cs))
}

#[cfg(test)]
pub mod tests {
    use crate::commitment::kzg::KZG;
    use ark_bn254::{Bn254, Fr, G1Projective as Projective};
    use ark_grumpkin::Projective as Projective2;

    use super::*;
    use crate::commitment::pedersen::Pedersen;
    use crate::frontend::utils::CubicFCircuit;
    use crate::transcript::poseidon::poseidon_canonical_config;

    /// This test tests the Nova+CycleFold IVC, and by consequence it is also testing the
    /// AugmentedFCircuit
    #[test]
    fn test_ivc() -> Result<(), Error> {
        let poseidon_config = poseidon_canonical_config::<Fr>();

        let F_circuit = CubicFCircuit::<Fr>::new(())?;

        // run the test using Pedersen commitments on both sides of the curve cycle
        let _ = test_ivc_opt::<Pedersen<Projective>, Pedersen<Projective2>, false>(
            poseidon_config.clone(),
            F_circuit,
            3,
        )?;

        let _ = test_ivc_opt::<Pedersen<Projective, true>, Pedersen<Projective2, true>, true>(
            poseidon_config.clone(),
            F_circuit,
            3,
        )?;

        // run the test using KZG for the commitments on the main curve, and Pedersen for the
        // commitments on the secondary curve.
        //
        // personas fork (B1): `Nova::verify` now checks commitment openings, and a KZG verifier
        // key cannot recompute a vector commitment, so the verifier must refuse (fail closed)
        // rather than accept unchecked openings. Folding with KZG still runs: every
        // `prove_step` above `verify` executes, with its in-test relation asserts.
        let kzg =
            test_ivc_opt::<KZG<Bn254>, Pedersen<Projective2>, false>(poseidon_config, F_circuit, 3);
        assert!(
            matches!(kzg, Err(Error::NotSupported(_))),
            "{:?}",
            kzg.err()
        );
        Ok(())
    }

    // test_ivc allowing to choose the CommitmentSchemes
    #[allow(clippy::type_complexity)]
    pub(crate) fn test_ivc_opt<
        CS1: CommitmentScheme<Projective, H>,
        CS2: CommitmentScheme<Projective2, H>,
        const H: bool,
    >(
        poseidon_config: PoseidonConfig<Fr>,
        F_circuit: CubicFCircuit<Fr>,
        num_steps: usize,
    ) -> Result<
        (
            Vec<Fr>,
            Nova<Projective, Projective2, CubicFCircuit<Fr>, CS1, CS2, H>,
        ),
        Error,
    > {
        let mut rng = ark_std::test_rng();

        let prep_param =
            PreprocessorParam::<Projective, Projective2, CubicFCircuit<Fr>, CS1, CS2, H> {
                poseidon_config,
                F: F_circuit,
                cs_pp: None,
                cs_vp: None,
                cf_cs_pp: None,
                cf_cs_vp: None,
            };
        let nova_params =
            Nova::<Projective, Projective2, CubicFCircuit<Fr>, CS1, CS2, H>::preprocess(
                &mut rng,
                &prep_param,
            )?;

        let z_0 = vec![Fr::from(3_u32)];
        let mut nova = Nova::<Projective, Projective2, CubicFCircuit<Fr>, CS1, CS2, H>::init(
            &nova_params,
            F_circuit,
            z_0.clone(),
        )?;

        for _ in 0..num_steps {
            nova.prove_step(&mut rng, (), None)?;
        }
        assert_eq!(Fr::from(num_steps as u32), nova.i);

        // serialize the Nova Prover & Verifier params. These params are the trusted setup of the commitment schemes used
        let mut nova_pp_serialized = vec![];
        nova_params
            .0
            .serialize_compressed(&mut nova_pp_serialized)?;
        let mut nova_vp_serialized = vec![];
        nova_params
            .1
            .serialize_compressed(&mut nova_vp_serialized)?;

        // deserialize the Nova params
        let _nova_pp_deserialized =
            ProverParams::<Projective, Projective2, CS1, CS2, H>::deserialize_compressed(
                &mut nova_pp_serialized.as_slice(),
            )?;
        let nova_vp_deserialized = Nova::<
            Projective,
            Projective2,
            CubicFCircuit<Fr>,
            CS1,
            CS2,
            H,
        >::vp_deserialize_with_mode(
            &mut nova_vp_serialized.as_slice(),
            ark_serialize::Compress::Yes,
            ark_serialize::Validate::Yes,
            (), // fcircuit_params
        )?;

        let ivc_proof = nova.ivc_proof();

        // serialize IVCProof
        let mut ivc_proof_serialized = vec![];
        assert!(ivc_proof
            .serialize_compressed(&mut ivc_proof_serialized)
            .is_ok());
        // deserialize IVCProof
        let ivc_proof_deserialized =
            <Nova<Projective, Projective2, CubicFCircuit<Fr>, CS1, CS2, H> as FoldingScheme<
                Projective,
                Projective2,
                CubicFCircuit<Fr>,
            >>::IVCProof::deserialize_compressed(ivc_proof_serialized.as_slice())?;

        // verify the deserialized IVCProof with the deserialized VerifierParams
        Nova::<Projective, Projective2, CubicFCircuit<Fr>, CS1, CS2, H>::verify(
            nova_vp_deserialized, // Nova's verifier params
            ivc_proof_deserialized,
        )?;
        Ok((z_0, nova))
    }
}
