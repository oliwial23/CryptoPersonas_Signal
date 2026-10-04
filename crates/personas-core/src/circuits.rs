

use ark_bn254::Fr as F;
use ark_bn254::G1Projective as Projective;
use ark_ff::{PrimeField, ToConstraintField, fields::AdditiveGroup};
use ark_grumpkin::{Fq, Projective as Projective2};
use ark_r1cs_std::{
    boolean::Boolean,
    eq::EqGadget,
    fields::{FieldVar, fp::FpVar},
    prelude::{AllocVar, AllocationMode},
    select::CondSelectGadget,
};
use ark_relations::r1cs::{Namespace, Result as ArkResult, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::vec::Vec;
use folding_schemes::folding::nova::zk::RandomizedIVCProof;
use folding_schemes::folding::nova::{ProverParams, VerifierParams};
use folding_schemes::{commitment::pedersen::Pedersen, folding::nova::Nova};
use rand::{CryptoRng, RngCore};
use std::borrow::Borrow;
use zk_callbacks::generic::fold::FoldingScan;
use zk_callbacks::generic::object::{Com, Nul};

use zk_callbacks::{
    crypto::hash::HasherZK,
    generic::{
        bulletin::{PublicCallbackBul, PublicUserBul},
        interaction::{Callback, Interaction},
        object::{Id, Time},
        scan::{self, PrivScanArgs, PrivScanArgsVar, PubScanArgs, PubScanArgsVar},
        user::{ExecutedMethod, User, UserVar},
    },
    impls::{centralized::crypto::FakeSigPubkey, hash::Poseidon},
    scannable_zk_object,
};

use lazy_static::lazy_static;
use blake2::{Blake2s256, Digest};

use crate::{Args, ArgsVar, CStore, Cr, H, OStore, PK, Snark};

pub const NUM_INTS_BEFORE_SCAN: usize = 200;
pub const MAX_PSEUDO: usize = 4;
pub const BAN_FLAG: u64 = 999999999;
pub const BADGE1_FLAG: u64 = 111111111;
pub const BADGE2_FLAG: u64 = 222222222;
pub const BADGE3_FLAG: u64 = 333333333;
/// The default number of callback scans a single proof accounts for — one Nova
/// fold step, or one plain Groth16 scan. The scan and fold circuits are
/// const-generic over this count (`N`); this is only the value everything
/// defaults to, and the concrete server/client pipeline stays pinned to it until
/// the fold-size menu (c2/c3) selects `N` at runtime. Must appear in
/// [`FOLD_SIZES`].
pub const NUM_SCANS_PER_FOLD: usize = 1;

/// The fold sizes the circuits are monomorphized for. [`dispatch_fold_size!`]
/// turns a runtime `n` into one of these const-generic instantiations; any other
/// value is unsupported. Keep this in lockstep with the macro's match arms — the
/// `dispatch_fold_size` test panics if a listed size has no arm.
pub const FOLD_SIZES: &[usize] = &[1, 2, 4, 8, 16];

/// Dispatch a runtime fold size `$n` to the const-generic monomorphization for it.
///
/// The scan and fold circuits are const-generic over `N` (callback scans per
/// proof), so `N` must be known at compile time. This macro matches `$n` against
/// the supported [`FOLD_SIZES`], binds a `const $N` to the matched size, and
/// evaluates `$body` with it in scope; any unsupported size evaluates
/// `$fallback` instead. Every arm — the fallback included — must produce the
/// same type, so use this only where the result has erased `N` (Nova/Groth16
/// params, a verification outcome, encoded bytes), never where the type still
/// mentions `N`.
///
/// ```ignore
/// let material = dispatch_fold_size!(
///     n,
///     N => generate_folding_material::<N>(rng, db)?,
///     return Err(ParamsError::UnsupportedFoldSize(n)),
/// );
/// ```
#[macro_export]
macro_rules! dispatch_fold_size {
    ($n:expr, $N:ident => $body:expr, $fallback:expr $(,)?) => {{
        match $n {
            1 => {
                const $N: usize = 1;
                $body
            }
            2 => {
                const $N: usize = 2;
                $body
            }
            4 => {
                const $N: usize = 4;
                $body
            }
            8 => {
                const $N: usize = 8;
                $body
            }
            16 => {
                const $N: usize = 16;
                $body
            }
            _ => $fallback,
        }
    }};
}


#[scannable_zk_object(F)]
#[derive(Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct MsgUser {
    pub sk: F,
    pub reputation: F,
    pub num_interactions_since_last_scan: F,
    pub pseudo_counter: F,
    pub banned: F,
    pub badge1: F,
    pub badge2: F,
    pub badge3: F,
   
}

pub type NF<const N: usize = NUM_SCANS_PER_FOLD> = Nova<
    Projective,
    Projective2,
    FoldingScan<F, MsgUser, Args, ArgsVar, Cr, OStore, CStore, H, N>,
    Pedersen<Projective, true>,
    Pedersen<Projective2, true>,
    true,
>;

pub type NP = (
    ProverParams<
        Projective,
        Projective2,
        Pedersen<Projective, true>,
        Pedersen<Projective2, true>,
        true,
    >,
    VerifierParams<
        Projective,
        Projective2,
        Pedersen<Projective, true>,
        Pedersen<Projective2, true>,
        true,
    >,
);

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct FoldingProofData {
    pub i: Fq,
    pub z_0: Vec<Fq>,
    pub z_i: Vec<Fq>,
    pub proof: RandomizedIVCProof<Projective, Projective2>,
    pub extra_verif: (Com<Fq>, Nul<Fq>, <Snark as SNARK<Fq>>::Proof),
}

#[derive(Clone, Debug, Default, CanonicalDeserialize, CanonicalSerialize)]
pub struct PseudonymArgs<F: PrimeField> {
    pub context: F,
    pub claimed: F,
}

#[derive(Clone)]
pub struct PseudonymArgsVar<F: PrimeField> {
    pub context: FpVar<F>,
    pub claimed: FpVar<F>,
}
#[derive(Clone, Debug, Default, CanonicalDeserialize, CanonicalSerialize)]
pub struct PseudonymArgsRate<F: PrimeField> {
    pub context: F,
    pub claimed: F,
    pub i: F,
}

#[derive(Clone)]
pub struct PseudonymArgsRateVar<F: PrimeField> {
    pub context: FpVar<F>,
    pub claimed: FpVar<F>,
    pub i: FpVar<F>,
}

#[derive(Clone, Debug, Default, CanonicalDeserialize, CanonicalSerialize)]
pub struct BadgesArgs<F: PrimeField> {
    pub i: F,
    pub claimed: F,
}

#[derive(Clone)]
pub struct BadgesArgsVar<F: PrimeField> {
    pub i: FpVar<F>,
    pub claimed: FpVar<F>,
}

#[derive(Clone, Default)]
pub struct PseudonymArgsPair<F: PrimeField> {
    pub a: PseudonymArgs<F>,
    pub b: PseudonymArgs<F>,
}

#[derive(Clone)]
pub struct PseudonymArgsPairVar<F: PrimeField> {
    pub a: PseudonymArgsVar<F>,
    pub b: PseudonymArgsVar<F>,
}

impl<F: PrimeField> AllocVar<PseudonymArgs<F>, F> for PseudonymArgsVar<F> {
    fn new_variable<T: Borrow<PseudonymArgs<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs(); // ConstraintSystemRef<F>

        let PseudonymArgs { context, claimed } = *f()?.borrow();
        Ok(Self {
            context: FpVar::new_variable(cs.clone(), || Ok(context), mode)?,
            claimed: FpVar::new_variable(cs, || Ok(claimed), mode)?,
        })
    }
}

impl<F: PrimeField> ToConstraintField<F> for PseudonymArgs<F> {
    fn to_field_elements(&self) -> Option<Vec<F>> {
        Some(vec![self.context, self.claimed])
    }
}

pub fn pseudonym_pred<'a, 'b>(
    tu: &'a UserVar<F, MsgUser>,
    _com: &'b FpVar<F>,
    pub_args: PseudonymArgsVar<F>,
    _priv_args: (),
) -> ArkResult<Boolean<F>> {
    let context = pub_args.context;
    let claimed = pub_args.claimed;
    let derived = Poseidon::<2>::hash_in_zk(&[tu.data.sk.clone(), context.clone()])?;
    derived.is_eq(&claimed)
}

impl<F: PrimeField> AllocVar<PseudonymArgsRate<F>, F> for PseudonymArgsRateVar<F> {
    fn new_variable<T: Borrow<PseudonymArgsRate<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs(); // ConstraintSystemRef<F>

        let PseudonymArgsRate {
            context,
            claimed,
            i,
        } = *f()?.borrow();
        Ok(Self {
            context: FpVar::new_variable(cs.clone(), || Ok(context), mode)?,
            claimed: FpVar::new_variable(cs.clone(), || Ok(claimed), mode)?,
            i: FpVar::new_variable(cs, || Ok(i), mode)?,
        })
    }
}

impl<F: PrimeField> ToConstraintField<F> for PseudonymArgsRate<F> {
    fn to_field_elements(&self) -> Option<Vec<F>> {
        Some(vec![self.context, self.claimed, self.i])
    }
}

impl<F: PrimeField> AllocVar<BadgesArgs<F>, F> for BadgesArgsVar<F> {
    fn new_variable<T: Borrow<BadgesArgs<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::alloc::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs(); // ConstraintSystemRef<F>

        let BadgesArgs { i, claimed } = *f()?.borrow();
        Ok(Self {
            i: FpVar::new_variable(cs.clone(), || Ok(i), mode)?,
            claimed: FpVar::new_variable(cs, || Ok(claimed), mode)?,
        })
    }
}

impl<F: PrimeField> ToConstraintField<F> for BadgesArgs<F> {
    fn to_field_elements(&self) -> Option<Vec<F>> {
        Some(vec![self.i, self.claimed])
    }
}

pub fn badge_pred<'a, 'b>(
    tu: &'a UserVar<F, MsgUser>,
    _com: &'b FpVar<F>,
    pub_args: BadgesArgsVar<F>,
    _priv_args: (),
) -> ArkResult<Boolean<F>> {
    let claimed = pub_args.claimed;

    let is_one = pub_args.i.is_eq(&FpVar::Constant(F::from(1)))?;
    let is_two = pub_args.i.is_eq(&FpVar::Constant(F::from(2)))?;

    let badge12 = FpVar::conditionally_select(&is_one, &tu.data.badge1, &tu.data.badge2)?;
    let badge = FpVar::conditionally_select(&is_two, &badge12, &tu.data.badge3)?;

    let x1 = badge.is_eq(&claimed)?;

    Ok(x1)
}

impl<F: PrimeField> AllocVar<PseudonymArgsPair<F>, F> for PseudonymArgsPairVar<F> {
    fn new_variable<T: Borrow<PseudonymArgsPair<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let pair = f()?;
        let pair = pair.borrow();

        let a_var = PseudonymArgsVar {
            context: FpVar::new_variable(cs.clone(), || Ok(pair.a.context), mode)?,
            claimed: FpVar::new_variable(cs.clone(), || Ok(pair.a.claimed), mode)?,
        };

        let b_var = PseudonymArgsVar {
            context: FpVar::new_variable(cs.clone(), || Ok(pair.b.context), mode)?,
            claimed: FpVar::new_variable(cs, || Ok(pair.b.claimed), mode)?,
        };

        Ok(Self { a: a_var, b: b_var })
    }
}

pub fn authorship_pred<'a, 'b>(
    tu: &'a UserVar<F, MsgUser>,
    _com: &'b FpVar<F>,
    pub_args: PseudonymArgsPairVar<F>,
    _priv_args: (),
) -> ArkResult<Boolean<F>> {
    let context = pub_args.a.context;
    let claimed = pub_args.a.claimed;
    let derived = Poseidon::<2>::hash_in_zk(&[tu.data.sk.clone(), context.clone()])?;

    let x1 = derived.is_eq(&claimed)?;

    let context2 = pub_args.b.context;
    let claimed2 = pub_args.b.claimed;
    let derived2 = Poseidon::<2>::hash_in_zk(&[tu.data.sk.clone(), context2.clone()])?;

    let x2 = derived2.is_eq(&claimed2)?;

    Ok(x1 & x2)
}

fn standard_method(tu: &User<F, MsgUser>, _args: F, _priv: ()) -> User<F, MsgUser> {
    let mut u = tu.clone();
    u.data.num_interactions_since_last_scan += F::from(1);
    u
}

fn standard_pseudo_method(
    tu: &User<F, MsgUser>,
    _args: PseudonymArgs<F>,
    _priv: (),
) -> User<F, MsgUser> {
    let mut u = tu.clone();
    u.data.num_interactions_since_last_scan += F::from(1);
    u
}

fn standard_pseudo_rate_method(
    tu: &User<F, MsgUser>,
    _args: PseudonymArgsRate<F>,
    _priv: (),
) -> User<F, MsgUser> {
    let mut u = tu.clone();
    u.data.num_interactions_since_last_scan += F::from(1);
    u
}

fn standard_badge_request_method(
    tu: &User<F, MsgUser>,
    _args: BadgesArgs<F>,
    _priv: (),
) -> User<F, MsgUser> {
    let mut u = tu.clone();
    u.data.num_interactions_since_last_scan += F::from(1);
    u
}

fn standard_predicate<'a>(
    tu_old: &'a UserVar<F, MsgUser>,
    tu_new: &'a UserVar<F, MsgUser>,
    _args: FpVar<F>,
    _priv: (),
) -> ArkResult<Boolean<F>> {
    let x1 = tu_new.data.num_interactions_since_last_scan.is_eq(
        &(tu_old.data.num_interactions_since_last_scan.clone() + FpVar::Constant(F::from(1))),
    )?;
    let x2 = tu_new.data.reputation.is_eq(&tu_old.data.reputation)?;
    let x3 = tu_new
        .data
        .num_interactions_since_last_scan
        .is_neq(&FpVar::Constant(F::from(NUM_INTS_BEFORE_SCAN as u64)))?;

    // Make sure user is not banned
    let x4 = tu_new.data.banned.is_eq(&FpVar::Constant(F::from(0)))?;
    let x5 = tu_new.data.sk.is_eq(&tu_old.data.sk)?;

    let x6 = tu_new.data.badge1.is_eq(&tu_old.data.badge1)?;
    let x7 = tu_new.data.badge2.is_eq(&tu_old.data.badge2)?;
    let x8 = tu_new.data.badge3.is_eq(&tu_old.data.badge3)?;

    Ok(x1 & x2 & x3 & x4 & x5 & x6 & x7 & x8) 
}

fn standard_pseudo_predicate<'a>(
    tu_old: &'a UserVar<F, MsgUser>,
    tu_new: &'a UserVar<F, MsgUser>,
    pub_args: PseudonymArgsVar<F>,
    _priv: (),
) -> ArkResult<Boolean<F>> {
    let x1 = tu_new.data.num_interactions_since_last_scan.is_eq(
        &(tu_old.data.num_interactions_since_last_scan.clone() + FpVar::Constant(F::from(1))),
    )?;
    let x2 = tu_new.data.reputation.is_eq(&tu_old.data.reputation)?;
    let x3 = tu_new
        .data
        .num_interactions_since_last_scan
        .is_neq(&FpVar::Constant(F::from(NUM_INTS_BEFORE_SCAN as u64)))?;

    // Make sure user is not banned
    let x4 = tu_new.data.banned.is_eq(&FpVar::Constant(F::from(0)))?;
    let x5 = tu_new.data.sk.is_eq(&tu_old.data.sk)?;

    let x6 = tu_new.data.badge1.is_eq(&tu_old.data.badge1)?;
    let x7 = tu_new.data.badge2.is_eq(&tu_old.data.badge2)?;
    let x8 = tu_new.data.badge3.is_eq(&tu_old.data.badge3)?;

    // Pseudonym check
    let context = pub_args.context;
    let claimed = pub_args.claimed;
    let derived = Poseidon::<2>::hash_in_zk(&[tu_new.data.sk.clone(), context.clone()])?;
    let x9 = derived.is_eq(&claimed)?;

    Ok(x1 & x2 & x3 & x4 & x5 & x6 & x7 & x8 & x9)
}

fn standard_pseudo_rate_predicate<'a>(
    tu_old: &'a UserVar<F, MsgUser>,
    tu_new: &'a UserVar<F, MsgUser>,
    pub_args: PseudonymArgsRateVar<F>,
    _priv: (),
) -> ArkResult<Boolean<F>> {
    let x1 = tu_new.data.num_interactions_since_last_scan.is_eq(
        &(tu_old.data.num_interactions_since_last_scan.clone() + FpVar::Constant(F::from(1))),
    )?;
    let x2 = tu_new.data.reputation.is_eq(&tu_old.data.reputation)?;
    let x3 = tu_new
        .data
        .num_interactions_since_last_scan
        .is_neq(&FpVar::Constant(F::from(NUM_INTS_BEFORE_SCAN as u64)))?;

    // Make sure user is not banned
    let x4 = tu_new.data.banned.is_eq(&FpVar::Constant(F::from(0)))?;
    let x5 = tu_new.data.sk.is_eq(&tu_old.data.sk)?;

    let x6 = tu_new.data.badge1.is_eq(&tu_old.data.badge1)?;
    let x7 = tu_new.data.badge2.is_eq(&tu_old.data.badge2)?;
    let x8 = tu_new.data.badge3.is_eq(&tu_old.data.badge3)?;

    // Pseudonym check
    let context = pub_args.context;
    let claimed = pub_args.claimed;
    let i = pub_args.i;

    let x9 = i.is_neq(&FpVar::Constant(F::from(MAX_PSEUDO as u64)))?;

    let derived = Poseidon::<2>::hash_in_zk(&[tu_new.data.sk.clone(), context, i])?;
    let x10 = derived.is_eq(&claimed)?;

    Ok(x1 & x2 & x3 & x4 & x5 & x6 & x7 & x8 & x9 & x10)
}

fn standard_badge_request_predicate<'a>(
    tu_old: &'a UserVar<F, MsgUser>,
    tu_new: &'a UserVar<F, MsgUser>,
    pub_args: BadgesArgsVar<F>,
    _priv: (),
) -> ArkResult<Boolean<F>> {
    let x1 = tu_new.data.num_interactions_since_last_scan.is_eq(
        &(tu_old.data.num_interactions_since_last_scan.clone() + FpVar::Constant(F::from(1))),
    )?;
    let x2 = tu_new.data.reputation.is_eq(&tu_old.data.reputation)?;
    let x3 = tu_new
        .data
        .num_interactions_since_last_scan
        .is_neq(&FpVar::Constant(F::from(NUM_INTS_BEFORE_SCAN as u64)))?;

    // Make sure user is not banned
    let x4 = tu_new.data.banned.is_eq(&FpVar::Constant(F::from(0)))?;
    let x5 = tu_new.data.sk.is_eq(&tu_old.data.sk)?;

    let x6 = tu_new.data.badge1.is_eq(&tu_old.data.badge1)?;
    let x7 = tu_new.data.badge2.is_eq(&tu_old.data.badge2)?;
    let x8 = tu_new.data.badge3.is_eq(&tu_old.data.badge3)?;

    let index = pub_args.i;
    let claimed = pub_args.claimed;

    let is_one =  index.is_eq(&FpVar::Constant(F::from(1)))?;
    let is_two = index.is_eq(&FpVar::Constant(F::from(2)))?;
    let is_three = index.is_eq(&FpVar::Constant(F::from(3)))?;

    let is_claimed_faculty = claimed.is_eq(&FpVar::Constant(*FACULTY_F))?;
    let is_claimed_student =  claimed.is_eq(&FpVar::Constant(*STUDENT_F))?;
    let is_claimed_industry =  claimed.is_eq(&FpVar::Constant(*INDUSTRY_F))?;

    let is_claimed_zero = claimed.is_eq(&FpVar::Constant(F::from(0)))?;

    let x9 = &is_claimed_faculty | &is_claimed_student | &is_claimed_industry | &is_claimed_zero;

       
    // badge1 == 0?
    let faculty_not_present =
        tu_new.data.badge1.is_eq(&FpVar::Constant(F::from(0)))?;
    // badge2 == 0?
    let student_not_present =
        tu_new.data.badge2.is_eq(&FpVar::Constant(F::from(0)))?;
    
    // faculty request antecedent
    let faculty_antecedent = is_one.clone() & is_claimed_faculty.clone();
    
    // faculty implication: (!antecedent) OR student_not_present
    let faculty_request_ok =
        !faculty_antecedent | student_not_present.clone();
    
    // student antecedent
    let student_antecedent = is_two.clone() & is_claimed_student.clone();
    
    // student implication: (!antecedent) OR faculty_not_present
    let student_request_ok =
        !student_antecedent | faculty_not_present.clone();
    
    // industry always ok
    let industry_antecedent = is_three.clone() & is_claimed_industry.clone();
    let industry_request_ok = !industry_antecedent | Boolean::constant(true);
    
    // final result
    let result =
            x1 & x2 & x3 & x4 & x5
        & x6 & x7 & x8 & x9
        & faculty_request_ok
        & student_request_ok
        & industry_request_ok; 
    
    Ok(result)
}

pub fn arg_rep(n: i64) -> F {
    F::from(n)
}

// ---------- 1. Hash string to field element ----------
pub fn string_hash_to_f<F: PrimeField>(s: &str) -> F {
    let hash = Blake2s256::digest(s.as_bytes());
    F::from_le_bytes_mod_order(&hash)
}

// ---------- 2. Precompute badge constants ----------
lazy_static! {
    pub static ref FACULTY_F: F = string_hash_to_f::<F>("Faculty");
    pub static ref STUDENT_F: F = string_hash_to_f::<F>("Student");
    pub static ref INDUSTRY_F: F = string_hash_to_f::<F>("Industry");
}

// ---------- 3. Standard callback method ----------
fn standard_callback_method(user: &User<F, MsgUser>, argument: F) -> User<F, MsgUser> {
    let mut u = user.clone();

    if argument == F::from(BAN_FLAG) {
        u.data.banned = F::from(1);
    } else if argument == F::from(BADGE1_FLAG) {
        u.data.badge1 = *FACULTY_F;
    } else if argument == F::from(BADGE2_FLAG) {
        u.data.badge2 = *STUDENT_F;
    } else if argument == F::from(BADGE3_FLAG) {
        u.data.badge3 = *INDUSTRY_F;
    } else {
        u.data.reputation += argument;
    }

    u
}

// ---------- 4. Standard callback predicate ----------
fn standard_callback_predicate(
    user: &UserVar<F, MsgUser>,
    argument: FpVar<F>,
) -> ArkResult<UserVar<F, MsgUser>> {
    let mut u = user.clone();

    // Convert constants to circuit constants
    let faculty_c = FpVar::Constant(*FACULTY_F);
    let student_c = FpVar::Constant(*STUDENT_F);
    let industry_c = FpVar::Constant(*INDUSTRY_F);

    // Check which operation is requested
    let is_ban = argument.is_eq(&FpVar::Constant(F::from(BAN_FLAG)))?;
    let is_badge1 = argument.is_eq(&FpVar::Constant(F::from(BADGE1_FLAG)))?;
    let is_badge2 = argument.is_eq(&FpVar::Constant(F::from(BADGE2_FLAG)))?;
    let is_badge3 = argument.is_eq(&FpVar::Constant(F::from(BADGE3_FLAG)))?;

    let is_rep = !(&is_ban | &is_badge1 | &is_badge2 | &is_badge3);

    // Badge existence checks
    let student_badge_exists = user.data.badge2.is_eq(&student_c)?;
    let faculty_badge_exists = user.data.badge1.is_eq(&faculty_c)?;

    // Only assign badge if the user doesn’t already have the conflicting badge
    let assign_badge1 = &is_badge1 & !&student_badge_exists;
    let assign_badge2 = &is_badge2 & !&faculty_badge_exists;

    // Update reputation
    let new_rep = &user.data.reputation + &argument;
    u.data.reputation =
        FpVar::conditionally_select(&is_rep, &new_rep, &user.data.reputation)?;

    // Update banned flag
    u.data.banned =
        FpVar::conditionally_select(&is_ban, &FpVar::Constant(F::from(1)), &u.data.banned)?;

    // Update badges
    u.data.badge1 = FpVar::conditionally_select(&assign_badge1, &faculty_c, &u.data.badge1)?;
    u.data.badge2 = FpVar::conditionally_select(&assign_badge2, &student_c, &u.data.badge2)?;
    u.data.badge3 = FpVar::conditionally_select(&is_badge3, &industry_c, &u.data.badge3)?;

    Ok(u)
}

fn scan_method<CBul: PublicCallbackBul<F, Args, Cr> + Clone, const N: usize>(
    tu: &User<F, MsgUser>,
    pub_args: PubScan<CBul, N>,
    priv_args: PrivScan<CBul, N>,
) -> User<F, MsgUser> {
    let interaction = scan::get_scan_interaction::<
        F,
        MsgUser,
        Args,
        ArgsVar,
        Cr,
        CBul,
        Poseidon<2>,
        N,
    >();
    let mut out_user = (interaction.meth.0)(tu, pub_args, priv_args);
    out_user.data.num_interactions_since_last_scan = F::ZERO;
    out_user
}

fn scan_predicate<CBul: PublicCallbackBul<F, Args, Cr> + Clone, const N: usize>(
    user_old: &UserVar<F, MsgUser>,
    user_new: &UserVar<F, MsgUser>,
    pub_args: PubScanVar<CBul, N>,
    priv_args: PrivScanVar<CBul, N>,
) -> ArkResult<Boolean<F>> {
    let interaction =
        scan::get_scan_interaction::<F, MsgUser, Args, ArgsVar, Cr, CBul, H, N>();
    let mut user_new_prime = user_new.clone();
    user_new_prime.data.num_interactions_since_last_scan =
        user_old.data.num_interactions_since_last_scan.clone();
    let x = (interaction.meth.1)(user_old, &user_new_prime, pub_args, priv_args);
    x.map(|a| {
        a & user_new
            .data
            .num_interactions_since_last_scan
            .is_eq(&FpVar::zero())
            .unwrap()
    })
}

pub fn get_callbacks() -> Vec<Callback<F, MsgUser, Args, ArgsVar>> {
    let standard_callback = Callback {
        method_id: Id::from(0),
        expirable: false,
        expiration: Time::from(10),
        method: standard_callback_method,
        predicate: standard_callback_predicate,
    };

    vec![standard_callback]
}

pub type StandInt = Interaction<F, MsgUser, F, FpVar<F>, (), (), Args, ArgsVar, 1>;

pub type PseudoStandInt =
    Interaction<F, MsgUser, PseudonymArgs<F>, PseudonymArgsVar<F>, (), (), Args, ArgsVar, 1>;

pub type PseudoRateStandInt = Interaction<
    F,
    MsgUser,
    PseudonymArgsRate<F>,
    PseudonymArgsRateVar<F>,
    (),
    (),
    Args,
    ArgsVar,
    1,
>;

pub type BadgeRequestStandInt =
    Interaction<F, MsgUser, BadgesArgs<F>, BadgesArgsVar<F>, (), (), Args, ArgsVar, 1>;

pub fn get_standard_interaction() -> StandInt {
    Interaction {
        meth: (standard_method, standard_predicate),
        callbacks: get_callbacks().try_into().unwrap(),
    }
}

pub fn get_standard_pseudo_interaction() -> PseudoStandInt {
    Interaction {
        meth: (standard_pseudo_method, standard_pseudo_predicate),
        callbacks: get_callbacks().try_into().unwrap(),
    }
}

pub fn get_standard_pseudo_rate_interaction() -> PseudoRateStandInt {
    Interaction {
        meth: (standard_pseudo_rate_method, standard_pseudo_rate_predicate),
        callbacks: get_callbacks().try_into().unwrap(),
    }
}

pub fn get_badge_request_interaction() -> BadgeRequestStandInt{
    Interaction {
        meth: (standard_badge_request_method, standard_badge_request_predicate),
        callbacks: get_callbacks().try_into().unwrap(),
    }
}

pub fn exec_standint<Bul: PublicUserBul<F, MsgUser>>(
    user: &mut User<F, MsgUser>,
    rng: &mut (impl CryptoRng + RngCore),
    bul: &Bul,
    pk: &PK,
    cur_time: Time<F>,
    pub_args: F,
    priv_args: (),
) -> ArkResult<ExecutedMethod<F, Snark, Args, Cr, 1>> {
    user.exec_method_create_cb::<H, F, FpVar<F>, (), (), Args, ArgsVar, Cr, Snark, Bul, 1>(
        rng,
        get_standard_interaction(),
        [FakeSigPubkey::pk()],
        cur_time,
        bul,
        true,
        pk,
        pub_args,
        priv_args,
    )
}

pub fn exec_pseudo_standint<Bul: PublicUserBul<F, MsgUser>>(
    user: &mut User<F, MsgUser>,
    rng: &mut (impl CryptoRng + RngCore),
    bul: &Bul,
    pk: &PK,
    cur_time: Time<F>,
    pub_args: PseudonymArgs<F>,
    priv_args: (),
) -> ArkResult<ExecutedMethod<F, Snark, Args, Cr, 1>> {
    user.exec_method_create_cb::<H, PseudonymArgs<F>, PseudonymArgsVar<F>, (), (), Args, ArgsVar, Cr, Snark, Bul, 1>(
        rng,
        get_standard_pseudo_interaction(),
        [FakeSigPubkey::pk()],
        cur_time,
        bul,
        true,
        pk,
        pub_args,
        priv_args,
    )
}

pub fn exec_pseudo_rate_standint<Bul: PublicUserBul<F, MsgUser>>(
    user: &mut User<F, MsgUser>,
    rng: &mut (impl CryptoRng + RngCore),
    bul: &Bul,
    pk: &PK,
    cur_time: Time<F>,
    pub_args: PseudonymArgsRate<F>,
    priv_args: (),
) -> ArkResult<ExecutedMethod<F, Snark, Args, Cr, 1>> {
    user.exec_method_create_cb::<H, PseudonymArgsRate<F>, PseudonymArgsRateVar<F>, (), (), Args, ArgsVar, Cr, Snark, Bul, 1>(
        rng,
        get_standard_pseudo_rate_interaction(),
        [FakeSigPubkey::pk()],
        cur_time,
        bul,
        true,
        pk,
        pub_args,
        priv_args,
    )
}

pub fn exec_badge_request_standint<Bul: PublicUserBul<F, MsgUser>>(
    user: &mut User<F, MsgUser>,
    rng: &mut (impl CryptoRng + RngCore),
    bul: &Bul,
    pk: &PK,
    cur_time: Time<F>,
    pub_args: BadgesArgs<F>,
    priv_args: (),
) -> ArkResult<ExecutedMethod<F, Snark, Args, Cr, 1>> {
    user.exec_method_create_cb::<H, BadgesArgs<F>, BadgesArgsVar<F>, (), (), Args, ArgsVar, Cr, Snark, Bul, 1>(
        rng,
        get_badge_request_interaction(),
        [FakeSigPubkey::pk()],
        cur_time,
        bul,
        true,
        pk,
        pub_args,
        priv_args,
    )
}

pub type PubScan<CBul, const N: usize = NUM_SCANS_PER_FOLD> =
    PubScanArgs<F, MsgUser, Args, ArgsVar, Cr, CBul, N>;
pub type PubScanVar<CBul, const N: usize = NUM_SCANS_PER_FOLD> =
    PubScanArgsVar<F, MsgUser, Args, ArgsVar, Cr, CBul, N>;

pub type PrivScan<CBul, const N: usize = NUM_SCANS_PER_FOLD> = PrivScanArgs<F, Args, Cr, CBul, N>;
pub type PrivScanVar<CBul, const N: usize = NUM_SCANS_PER_FOLD> =
    PrivScanArgsVar<F, Args, Cr, CBul, N>;

pub type ScanInt<CBul, const N: usize = NUM_SCANS_PER_FOLD> = Interaction<
    F,
    MsgUser,
    PubScan<CBul, N>,
    PubScanVar<CBul, N>,
    PrivScan<CBul, N>,
    PrivScanVar<CBul, N>,
    Args,
    ArgsVar,
    0,
>;

pub fn get_scan_interaction<CBul: PublicCallbackBul<F, Args, Cr> + Clone, const N: usize>()
-> ScanInt<CBul, N> {
    Interaction {
        meth: (scan_method::<CBul, N>, scan_predicate::<CBul, N>),
        callbacks: [],
    }
}

pub fn exec_scanint<
    Bul: PublicUserBul<F, MsgUser>,
    CBul: PublicCallbackBul<F, Args, Cr> + std::fmt::Debug + Clone,
    const N: usize,
>(
    user: &mut User<F, MsgUser>,
    rng: &mut (impl CryptoRng + RngCore),
    bul: &Bul,
    pk: &PK,
    cbul: &CBul,
    cur_time: Time<F>,
) -> ArkResult<ExecutedMethod<F, Snark, Args, Cr, 0>>
where
    CBul::MembershipPub: std::fmt::Debug,
    CBul::NonMembershipPub: std::fmt::Debug,
{
    let (ps, prs) = user.get_scan_arguments::<_, _, _, _, N>(
        cbul,
        (true, true),
        cur_time,
        get_callbacks(),
    );

    user.interact::<H, _, _, _, _, _, _, Cr, Snark, Bul, 0>(
        rng,
        get_scan_interaction::<CBul, N>(),
        [],
        cur_time,
        bul.get_membership_data(user.commit::<H>()).unwrap(),
        true,
        pk,
        ps,
        prs,
        true,
    )
}

pub fn get_extra_pubdata_for_scan<CBul: PublicCallbackBul<F, Args, Cr> + Clone, const N: usize>(
    cstore: &CBul,
    memb_pub: <CBul as PublicCallbackBul<F, Args, Cr>>::MembershipPub,
    nmemb_pub: <CBul as PublicCallbackBul<F, Args, Cr>>::NonMembershipPub,
    time: Time<F>,
) -> PubScan<CBul, N> {
    PubScan {
        memb_pub: core::array::from_fn(|_| memb_pub.clone()),
        is_memb_data_const: true,
        nmemb_pub: core::array::from_fn(|_| nmemb_pub.clone()),
        is_nmemb_data_const: true,
        cur_time: time,
        bulletin: cstore.clone(),
        cb_methods: get_callbacks(),
    }
}

#[cfg(test)]
mod fold_size_tests {
    use super::*;
    use core::marker::PhantomData;

    /// Hands back its own const-generic fold size, so a test can prove
    /// `dispatch_fold_size!` routes a runtime `n` to the matching monomorphization
    /// rather than to some other arm.
    fn size_of_fold<const N: usize>() -> usize {
        N
    }

    #[test]
    fn default_fold_size_is_on_the_menu() {
        assert!(
            FOLD_SIZES.contains(&NUM_SCANS_PER_FOLD),
            "NUM_SCANS_PER_FOLD must be one of the monomorphized FOLD_SIZES"
        );
    }

    #[test]
    fn dispatch_routes_every_menu_size() {
        // If FOLD_SIZES and the macro's match arms ever drift, a listed size lands
        // in the fallback and this panics — that is the coupling being guarded.
        for &n in FOLD_SIZES {
            let routed = crate::dispatch_fold_size!(
                n,
                N => size_of_fold::<N>(),
                panic!("FOLD_SIZES lists {n}, but dispatch_fold_size! has no arm for it"),
            );
            assert_eq!(routed, n, "dispatch routed {n} to the wrong monomorphization");
        }
    }

    #[test]
    fn dispatch_falls_back_on_unsupported_size() {
        let routed = crate::dispatch_fold_size!(3usize, N => size_of_fold::<N>(), usize::MAX);
        assert_eq!(routed, usize::MAX);
    }

    /// Compile-only: the scan/fold types must instantiate for a non-default `N`,
    /// not merely for `NUM_SCANS_PER_FOLD`. Never called — naming the aliases is
    /// what makes the compiler check that the const generic threads through.
    #[allow(dead_code)]
    fn types_instantiate_for_non_default_n() {
        let _nova: PhantomData<NF<2>> = PhantomData;
        let _pub: PhantomData<PubScan<CStore, 4>> = PhantomData;
        let _pub_var: PhantomData<PubScanVar<CStore, 4>> = PhantomData;
        let _priv: PhantomData<PrivScan<CStore, 8>> = PhantomData;
        let _priv_var: PhantomData<PrivScanVar<CStore, 8>> = PhantomData;
        let _int: PhantomData<ScanInt<CStore, 16>> = PhantomData;
    }

    /// Compile-only: the scan/fold *functions* must have well-formed signatures for
    /// an arbitrary `N`. Referencing the fn items forces that check without paying
    /// for a keygen or a proof. (`exec_scanint` is exercised at its real call site
    /// in the client; it takes an un-nameable `impl CryptoRng` rng, so it can't be
    /// named as a bare fn item here — its only use of `N` is the two calls below.)
    #[allow(dead_code)]
    fn fns_instantiate_for_arbitrary_n<CBul, const N: usize>()
    where
        CBul: PublicCallbackBul<F, Args, Cr> + Clone,
    {
        let _get_int = get_scan_interaction::<CBul, N>;
        let _pubdata = get_extra_pubdata_for_scan::<CBul, N>;
    }
}