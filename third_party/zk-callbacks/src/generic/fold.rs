use ark_relations::ns;
use std::{borrow::Borrow, marker::PhantomData};
use rand::distributions::Standard;
use rand::prelude::Distribution;
use ark_r1cs_std::{alloc::AllocationMode, prelude::Boolean, select::CondSelectGadget};
use rand::{CryptoRng, RngCore};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget};
use ark_relations::r1cs::{Namespace, SynthesisError};
use folding_schemes::frontend::FCircuit;
use ark_relations::r1cs::{Result as ArkResult};
use ark_snark::SNARK;
use crate::{
    crypto::{enc::AECipherSigZK, hash::FieldHash},
    generic::{
        bulletin::{PublicCallbackBul, PublicUserBul},
 interaction::generate_keys_for_statement_in, object::{Com, ComRand, ComRandVar, ComVar, Nul, NulVar},
 scan::{scan_apply_method_zk, PrivScanArgs, PrivScanArgsVar, PubScanArgs, PubScanArgsVar},
 user::{User, UserData, UserVar}
    },
};


// TODO: add a verify for folding? that uses this rerand struct internally
#[derive(Default, Clone)]
pub(crate) struct Rerand<F> {
    pub(crate) com: Com<F>,
    pub(crate) nul: Nul<F>,
}

#[derive(Clone)]
pub(crate) struct RerandVar<F: PrimeField> {
    com: ComVar<F>,
    nul: NulVar<F>,
}

impl<F: PrimeField + Absorb> AllocVar<Rerand<F>, F> for RerandVar<F> {
    fn new_variable<T: Borrow<Rerand<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();

        res.and_then(|rec| {
            let rec = rec.borrow();
            let com =
                <ComVar<F>>::new_variable(ns!(cs, "com"), || Ok(rec.com.clone()), mode)?;
            let nul = <NulVar<F>>::new_variable(
                ns!(cs, "nul"),
                || Ok(rec.nul.clone()),
                mode,
            )?;
            Ok(RerandVar { com , nul })
        })
    }
}


pub(crate) fn rerandomize_predicate<'a, 'b, H: FieldHash<F>, F: PrimeField + Absorb, U: UserData<F>>(u: &'a UserVar<F, U>, _com: &'b ComVar<F>, pub_args: RerandVar<F>, priv_args: ComRandVar<F>) -> ArkResult<Boolean<F>> {
    let b1 = u.zk_fields.nul.is_eq(&pub_args.nul)?;
    let mut new_u = u.clone();
    new_u.zk_fields.com_rand = priv_args;
    let b2 = <User<F, U>>::commit_in_zk::<H>(new_u)?.is_eq(&pub_args.com)?;
    Ok(b1 & b2)
}

// TODO: write docs.
/// TODO.
pub fn gen_fold_proof_snark_key<F: PrimeField + Absorb, H: FieldHash<F>, U: UserData<F> + Default, Snark: SNARK<F>, Bul: PublicUserBul<F, U>>(
    rng: &mut (impl CryptoRng + RngCore),
    memb_data: Option<Bul::MembershipPub>,
) -> (Snark::ProvingKey, Snark::VerifyingKey) where Standard: Distribution<F> {
    generate_keys_for_statement_in::<F, H, U, Rerand<F>, RerandVar<F>, ComRand<F>, ComRandVar<F>, Snark, Bul>(rng, rerandomize_predicate::<H, F, U>, memb_data, Rerand { com: F::default(), nul: F::default() })
}

/// This allows for users to perform a folding scan instead of scanning incremenetally.
///
/// This implements `FCircuit` from PSE's folding-schemes, and so it may be used with any folding
/// scheme supported by FCircuit.
///
/// The parameters passed in include the public arguments for the scan. The private arguments are
/// treated as extra witnesses during the folding process.
/// At each folding step, [`PrivScanArgs`] are deserialized from the folding representation. This
/// struct will always have a callback count of `1`, as we only fold the scan one step at a time.
#[derive(Clone)]
pub struct FoldingScan<
    F: PrimeField + Absorb,
    U: UserData<F>,
    CBArgs: Clone + std::fmt::Debug,
    CBArgsVar: AllocVar<CBArgs, F> + Clone,
    Crypto: AECipherSigZK<F, CBArgs>,
    Bul: PublicUserBul<F, U>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    H: FieldHash<F>,
    const NUMCBS: usize,
> {
    _f: PhantomData<F>,
    _u: PhantomData<U>,
    _c: PhantomData<Crypto>,
    _h: PhantomData<H>,
    _b: PhantomData<Bul>,
    /// The public arguments during the scan.
    pub const_args: PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>,
    /// The public bulletin membership data.
    pub const_memb: Bul::MembershipPub,
}

impl<
    F: PrimeField + Absorb,
    U: UserData<F>,
    CBArgs: Clone + std::fmt::Debug,
    CBArgsVar: AllocVar<CBArgs, F> + Clone,
    Crypto: AECipherSigZK<F, CBArgs>,
    Bul: PublicUserBul<F, U>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    H: FieldHash<F>,
    const NUMCBS: usize,
> std::fmt::Debug for FoldingScan<F, U, CBArgs, CBArgsVar, Crypto, Bul, CBul, H, NUMCBS>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Folding scan")
    }
}

// TODO: write docs
/// An external input to a single folding step. TODO
#[derive(Clone)]
pub struct FoldInput<
    F: PrimeField + Absorb,
    U: UserData<F> + Default,
    CBArgs: Clone + Default,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar> + Default,
    Bul: PublicUserBul<F, U>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> where
    CBul::MembershipWitness: Default,
    CBul::NonMembershipWitness: Default,
{
    /// The user. TODO
    pub user: User<F, U>,
    /// Scan args. TODO
    pub scan_args: PrivScanArgs<F, CBArgs, Crypto, CBul, NUMCBS>,
    /// New nullifier. TODO
    pub nul: Nul<F>,
    /// New commitment randomness. TODO
    pub com_rand: ComRand<F>,
    /// Bulletin membership witness. TODO
    pub memb_witness: Bul::MembershipWitness,
}

impl<
    F: PrimeField + Absorb,
    U: UserData<F> + Default,
    CBArgs: Clone + Default,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar> + Default,
    Bul: PublicUserBul<F, U>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> Default for FoldInput<F, U, CBArgs, CBArgsVar, Crypto, Bul, CBul, NUMCBS>
where
    Bul::MembershipWitness: Default,
    CBul::MembershipWitness: Default,
    CBul::NonMembershipWitness: Default,
{
    fn default() -> Self {
        Self {
            user: <User<F, U>>::default(),
            scan_args: PrivScanArgs::default(),
            nul: Nul::default(),
            com_rand: ComRand::default(),
            memb_witness: Bul::MembershipWitness::default(),
        }
    }
}

impl<
    F: PrimeField + Absorb,
    U: UserData<F> + Default,
    CBArgs: Clone + Default,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar> + Default,
    Bul: PublicUserBul<F, U>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> std::fmt::Debug for FoldInput<F, U, CBArgs, CBArgsVar, Crypto, Bul, CBul, NUMCBS>
where
    CBul::MembershipWitness: Default,
    CBul::NonMembershipWitness: Default,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Folding input")
    }
}

// TODO: write docs
/// An external input to a single folding step in-circuit. TODO
#[derive(Clone)]
pub struct FoldInputVar<
    F: PrimeField + Absorb,
    U: UserData<F> + Default,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar>,
    Bul: PublicUserBul<F, U>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> {
    /// The user. TODO
    pub user: UserVar<F, U>,
    /// Scan args. TODO
    pub scan_args: PrivScanArgsVar<F, CBArgs, Crypto, CBul, NUMCBS>,
    /// New nullifier. TODO
    pub nul: NulVar<F>,
    /// New commitment randomness. TODO
    pub com_rand: ComRandVar<F>,
    /// Bulletin membership witness. TODO
    pub memb_witness: Bul::MembershipWitnessVar,
}

impl<
    F: PrimeField + Absorb,
    U: UserData<F> + Default,
    CBArgs: Clone + Default,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar> + Default,
    Bul: PublicUserBul<F, U>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> std::fmt::Debug for FoldInputVar<F, U, CBArgs, CBArgsVar, Crypto, Bul, CBul, NUMCBS>
where
    CBul::MembershipWitness: Default,
    CBul::NonMembershipWitness: Default,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Folding input var")
    }
}

impl<
    F: PrimeField + Absorb,
    U: UserData<F> + Default,
    CBArgs: Clone + Default,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar> + Default,
    Bul: PublicUserBul<F, U>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> AllocVar<FoldInput<F, U, CBArgs, CBArgsVar, Crypto, Bul, CBul, NUMCBS>, F>
    for FoldInputVar<F, U, CBArgs, CBArgsVar, Crypto, Bul, CBul, NUMCBS>
where
    CBul::MembershipWitness: Default,
    CBul::NonMembershipWitness: Default,
{
    fn new_variable<T: Borrow<FoldInput<F, U, CBArgs, CBArgsVar, Crypto, Bul, CBul, NUMCBS>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();

        res.and_then(|rec| {
            let rec = rec.borrow();
            let user =
                <UserVar<F, U>>::new_variable(ns!(cs, "user"), || Ok(rec.user.clone()), mode)?;
            let scan_args = PrivScanArgsVar::new_variable(
                ns!(cs, "scan_args"),
                || Ok(rec.scan_args.clone()),
                mode,
            )?;

            let nul = <NulVar<F>>::new_variable(ns!(cs, "nul"), || Ok(rec.nul.clone()), mode)?;
            let com_rand = <ComRandVar<F>>::new_variable(
                ns!(cs, "com_rand"),
                || Ok(rec.com_rand.clone()),
                mode,
            )?;
            let memb_witness = <Bul::MembershipWitnessVar>::new_variable(
                ns!(cs, "memb_witness"),
                || Ok(rec.memb_witness.clone()),
                mode,
            )?;

            Ok(Self {
                user,
                scan_args,
                nul,
                com_rand,
                memb_witness,
            })
        })
    }
}

impl<
    F: PrimeField + Absorb,
    U: UserData<F> + Default,
    CBArgs: Clone + std::fmt::Debug + Default,
    CBArgsVar: AllocVar<CBArgs, F> + Clone + std::fmt::Debug,
    Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar> + Default,
    Bul: PublicUserBul<F, U> + Clone,
    CBul: PublicCallbackBul<F, CBArgs, Crypto> + Clone + std::fmt::Debug + Default,
    H: FieldHash<F>,
    const NUMCBS: usize,
> FCircuit<F> for FoldingScan<F, U, CBArgs, CBArgsVar, Crypto, Bul, CBul, H, NUMCBS>
where
    Bul::MembershipPub: std::fmt::Debug,
    CBul::MembershipWitness: Default,
    CBul::NonMembershipWitness: Default,
    U::UserDataVar: CondSelectGadget<F> + EqGadget<F>,
{
    type Params = (
        PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>,
        Bul::MembershipPub,
    );

    type ExternalInputs = FoldInput<F, U, CBArgs, CBArgsVar, Crypto, Bul, CBul, NUMCBS>;

    type ExternalInputsVar = FoldInputVar<F, U, CBArgs, CBArgsVar, Crypto, Bul, CBul, NUMCBS>;

    fn new(init: Self::Params) -> Result<Self, folding_schemes::Error> {
        assert!(init.0.is_memb_data_const == true);
        assert!(init.0.is_nmemb_data_const == true);
        Ok(Self {
            _f: PhantomData,
            _u: PhantomData,
            _c: PhantomData,
            _h: PhantomData,
            _b: PhantomData,
            const_args: init.0,
            const_memb: init.1,
        })
    }

    fn state_len(&self) -> usize {
        2
    }

    fn generate_step_constraints(
        // this method uses self, so that each FCircuit implementation (and different frontends)
        // can hold a state if needed to store data to generate the constraints.
        &self,
        cs: ark_relations::r1cs::ConstraintSystemRef<F>,
        _i: usize,
        z_i: Vec<ark_r1cs_std::fields::fp::FpVar<F>>,
        external_inputs: Self::ExternalInputsVar, // inputs that are not part of the state
    ) -> Result<Vec<ark_r1cs_std::fields::fp::FpVar<F>>, ark_relations::r1cs::SynthesisError> {
        assert!(self.const_args.is_memb_data_const == true);
        assert!(self.const_args.is_nmemb_data_const == true);

        let cu = User::commit_in_zk::<H>(external_inputs.user.clone())?;

        cu.enforce_equal(&z_i[0])?;

        // let outside_commitment = [cu, external_inputs.nonce.clone()].to_vec();
        // let u = H::hash_in_zk(&outside_commitment)?;

        // u.enforce_equal(&z_i[0])?;
        // H::hash_in_zk(&[
        //     external_inputs.hid_old_com.clone(),
        //     external_inputs.nonce.clone(),
        // ])?
        // .enforce_equal(&z_i[1])?;
        // Bul::enforce_membership_of(
        //     external_inputs.hid_old_com.clone(),
        //     external_inputs.memb_witness,
        //     Bul::MembershipPubVar::new_constant(cs.clone(), self.const_memb.clone())?,
        // )?
        // .enforce_equal(&Boolean::TRUE)?;
        let mut p = PubScanArgsVar::new_constant(cs.clone(), self.const_args.clone())?;
        p.cur_time = z_i[1].clone();
        let mut new_user = scan_apply_method_zk::<F, U, CBArgs, CBArgsVar, Crypto, CBul, H, NUMCBS>(
            &external_inputs.user,
            p,
            external_inputs.scan_args,
        )?;
        new_user.zk_fields.nul = external_inputs.nul;
        new_user.zk_fields.com_rand = external_inputs.com_rand;
        Ok(vec![
            User::commit_in_zk::<H>(new_user)?,
            z_i[1].clone(),
        ])
    }
}
