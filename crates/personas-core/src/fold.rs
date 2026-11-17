//! The server-backed folded scan: one Nova step per callback slot, padded to a fixed
//! number of steps.
//!
//! zk-callbacks' generic [`FoldingScan`] folds scan steps but knows nothing of this
//! object's epoch or post count. [`PersonasFold`] runs the same step and then applies the
//! rules every personas scan follows (see `scan_predicate` in [`crate::circuits`]):
//!
//! - a sweep may start only if the object was last brought up to date in an earlier epoch
//!   (`ep < t`), so there is one sweep per epoch;
//! - the step that finishes a sweep sets `ep = t` and resets the post count;
//! - a padding step (`noop`) leaves the object as it was, re-randomized.
//!
//! Every fold has [`FOLD_DEPTH`] steps: the real ones (or one empty-sweep step for a
//! member with no tickets), then padding. Nova's verifier takes the step count as input, so
//! without padding a folded scan would reveal how many callbacks it answers.

use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::Boolean;
use ark_r1cs_std::select::CondSelectGadget;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use folding_schemes::frontend::FCircuit;
use zk_callbacks::generic::bulletin::{PublicCallbackBul, PublicUserBul};
use zk_callbacks::generic::fold::{FoldInput, FoldInputVar, FoldingScan};
use zk_callbacks::generic::scan::{PubScanArgs, PubScanArgsVar, scan_apply_method_zk};
use zk_callbacks::generic::user::User;

use crate::circuits::{K_MAX, MsgUser, NUM_SCANS_PER_FOLD};
use crate::{Args, ArgsVar, Cr, F, H};

/// Steps in every server-backed folded scan: enough slots for `k_max` live tickets.
pub const FOLD_DEPTH: usize = K_MAX.div_ceil(NUM_SCANS_PER_FOLD);

/// One step of a server-backed folded scan, with the personas sweep rules. See the module
/// docs.
#[derive(Clone)]
pub struct PersonasFold<Bul, CBul, const N: usize>
where
    Bul: PublicUserBul<F, MsgUser>,
    CBul: PublicCallbackBul<F, Args, Cr>,
{
    pub inner: FoldingScan<F, MsgUser, Args, ArgsVar, Cr, Bul, CBul, H, N>,
}

impl<Bul, CBul, const N: usize> std::fmt::Debug for PersonasFold<Bul, CBul, N>
where
    Bul: PublicUserBul<F, MsgUser>,
    CBul: PublicCallbackBul<F, Args, Cr>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Personas folding scan")
    }
}

impl<Bul, CBul, const N: usize> FCircuit<F> for PersonasFold<Bul, CBul, N>
where
    Bul: PublicUserBul<F, MsgUser> + Clone,
    CBul: PublicCallbackBul<F, Args, Cr> + Clone + std::fmt::Debug + Default,
    Bul::MembershipPub: std::fmt::Debug,
    CBul::MembershipWitness: Default,
    CBul::NonMembershipWitness: Default,
{
    type Params = (
        PubScanArgs<F, MsgUser, Args, ArgsVar, Cr, CBul, N>,
        Bul::MembershipPub,
    );
    type ExternalInputs = FoldInput<F, MsgUser, Args, ArgsVar, Cr, Bul, CBul, N>;
    type ExternalInputsVar = FoldInputVar<F, MsgUser, Args, ArgsVar, Cr, Bul, CBul, N>;

    fn new(params: Self::Params) -> Result<Self, folding_schemes::Error> {
        Ok(Self {
            inner: FoldingScan::new(params)?,
        })
    }

    fn state_len(&self) -> usize {
        2
    }

    fn generate_step_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<FpVar<F>>,
        external_inputs: Self::ExternalInputsVar,
    ) -> Result<Vec<FpVar<F>>, SynthesisError> {
        let old = external_inputs.user.clone();
        User::commit_in_zk::<H>(old.clone())?.enforce_equal(&z_i[0])?;
        let cur_time = z_i[1].clone();

        let mut p = PubScanArgsVar::new_constant(cs.clone(), self.inner.const_args.clone())?;
        p.cur_time = cur_time.clone();
        let mut scanned = scan_apply_method_zk::<F, MsgUser, Args, ArgsVar, Cr, CBul, H, N>(
            &old,
            p,
            external_inputs.scan_args,
        )?;

        // ONE SWEEP PER EPOCH, as in the Groth16 scan: a sweep may start only if the object
        // is from an earlier epoch. Padding steps change nothing, so they are exempt.
        let starting = old.zk_fields.is_ingest_over.clone();
        let earlier = old
            .data
            .ep
            .is_cmp(&cur_time, core::cmp::Ordering::Less, false)?;
        (external_inputs.noop.clone() | !starting | earlier).enforce_equal(&Boolean::TRUE)?;

        // The step that finishes a sweep brings the object up to this epoch and resets the
        // post count.
        let finished = scanned.zk_fields.is_ingest_over.clone();
        scanned.data.ep = FpVar::conditionally_select(&finished, &cur_time, &old.data.ep)?;
        scanned.data.num_interactions_since_last_scan = FpVar::conditionally_select(
            &finished,
            &FpVar::zero(),
            &old.data.num_interactions_since_last_scan,
        )?;
        scanned.zk_fields.nul = external_inputs.nul.clone();
        scanned.zk_fields.com_rand = external_inputs.com_rand.clone();

        let mut kept = old;
        kept.zk_fields.nul = external_inputs.nul;
        kept.zk_fields.com_rand = external_inputs.com_rand;

        let out = FpVar::conditionally_select(
            &external_inputs.noop,
            &User::commit_in_zk::<H>(kept)?,
            &User::commit_in_zk::<H>(scanned)?,
        )?;
        Ok(vec![out, cur_time])
    }
}

/// How many real steps a fold of `callbacks` live tickets takes: one per `N` tickets, and
/// at least one, so a member with no tickets still finishes an (empty) sweep and brings its
/// object up to the epoch.
pub fn real_fold_steps(callbacks: usize, n: usize) -> usize {
    callbacks.div_ceil(n).max(1)
}
