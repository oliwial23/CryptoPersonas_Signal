use crate::crypto::{enc::CPACipher, rr::RRVerifier};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{
    alloc::AllocVar, cmp::CmpGadget, eq::EqGadget, fields::fp::FpVar, prelude::Boolean,
    select::CondSelectGadget, uint::UInt,
};
use ark_relations::{ns, r1cs::Result as ArkResult};
use ark_serialize::CanonicalSerialize;

use crate::{
    crypto::{enc::AECipherSigZK, hash::FieldHash},
    generic::callbacks::add_ticket_to_hc,
    util::ArrayVar,
};

use crate::generic::{
    bulletin::PublicCallbackBul,
    callbacks::{CallbackCom, CallbackComVar, add_ticket_to_hc_zk},
    interaction::Callback,
    object::{Time, TimeVar},
    user::{User, UserData, UserVar},
};

use crate::generic::interaction::Interaction;

/// Public arguments to the scan method.
///
/// These arguments are passed into the scan method. This includes public membership data for the
/// callback tickets (for example, signature public keys or a Merkle root), along with the current time
/// and the list of callbacks.
///
/// # Example
/// ```rust
/// # use ark_bn254::{Bn254 as E, Fr};
/// # use ark_groth16::Groth16;
/// # use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, prelude::Boolean};
/// # use ark_relations::r1cs::{Result as ArkResult, ToConstraintField};
/// # use ark_snark::SNARK;
/// # use rand::thread_rng;
/// # use std::time::SystemTime;
/// # use zk_callbacks::{
/// #     generic::{
/// #         bulletin::{CallbackBul, JoinableBulletin, UserBul},
/// #         interaction::{generate_keys_for_statement_in, Callback, Interaction},
/// #         object::{Id, Time},
/// #         scan::{get_scan_interaction, PubScanArgs},
/// #         service::ServiceProvider,
/// #         user::{User, UserVar},
/// #     },
/// #     impls::{
/// #         centralized::{
/// #             crypto::{FakeSigPrivkey, FakeSigPubkey, NoSigOTP},
/// #             ds::sigstore::{UOVCallbackStore, UOVObjStore, UOVStore},
/// #         },
/// #         hash::Poseidon,
/// #     },
/// #     scannable_zk_object,
/// # };
/// type PubScan = PubScanArgs<Fr, Data, Fr, FpVar<Fr>, NoSigOTP<Fr>, UOVCallbackStore<Fr, Fr>, 1>;
///
/// #[scannable_zk_object(Fr)]
/// #[derive(Default)]
/// pub struct Data {
///     pub token: Fr,
/// }
///
/// fn cb_method<'a>(old_user: &'a User<Fr, Data>, args: Fr) -> User<Fr, Data> {
///     let mut out = old_user.clone();
///     out.data.token = args;
///     out
/// }
///
/// fn cb_enforce<'a>(old_user: &'a UserVar<Fr, Data>, args: FpVar<Fr>) -> ArkResult<UserVar<Fr, Data>> {
///     let mut out = old_user.clone();
///     out.data.token = args;
///     Ok(out)
/// }
///
/// fn main() {
///     let mut rng = thread_rng();
///     let cb = Callback {
///         method_id: Id::from(0),
///         expirable: false,
///         expiration: Time::from(300),
///         method: cb_method,
///         predicate: cb_enforce,
///     };
///
///     let mut store = <UOVStore<Fr, Fr>>::new(&mut rng);
///
///     let cb_methods = vec![cb.clone()];
///
///     let pub_scan_args: PubScan = PubScanArgs {
///         memb_pub: [store.callback_bul.get_pubkey(); 1],
///         is_memb_data_const: true,
///         nmemb_pub: [store.callback_bul.nmemb_bul.get_pubkey(); 1],
///         is_nmemb_data_const: true,
///         cur_time: Fr::from(0),
///         bulletin: store.callback_bul.clone(),
///         cb_methods: cb_methods.clone(),
///     };
/// }
/// ```
#[derive(Clone)]
pub struct PubScanArgs<
    F: PrimeField + Absorb,
    U: UserData<F>,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> {
    /// Public membership data for each callback ticket.
    pub memb_pub: [CBul::MembershipPub; NUMCBS],
    /// If the public membership data is constant.
    pub is_memb_data_const: bool,
    /// Public *non*membership data for each callback ticket.
    pub nmemb_pub: [CBul::NonMembershipPub; NUMCBS],
    /// If the nonmemmbership data is constant.
    pub is_nmemb_data_const: bool,
    /// The current time.
    pub cur_time: Time<F>,

    /// The callback bulletin.
    pub bulletin: CBul,
    /// List of callbacks (used to call the function if the callback ticket was posted).
    pub cb_methods: Vec<Callback<F, U, CBArgs, CBArgsVar>>,
}

impl<
    F: PrimeField + Absorb,
    U: UserData<F>,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto> + Default,
    const NUMCBS: usize,
> Default for PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>
where
    CBul::MembershipPub: Default,
    CBul::NonMembershipPub: Default,
{
    fn default() -> Self {
        Self {
            memb_pub: core::array::from_fn(|_| CBul::MembershipPub::default()),
            nmemb_pub: core::array::from_fn(|_| CBul::NonMembershipPub::default()),
            is_memb_data_const: false,
            is_nmemb_data_const: false,
            cur_time: Time::<F>::zero(),
            bulletin: CBul::default(),
            cb_methods: vec![],
        }
    }
}

impl<
    F: PrimeField + Absorb,
    U: UserData<F>,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> std::fmt::Debug for PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Public Scan Arguments")
    }
}

impl<
    F: PrimeField + Absorb,
    U: UserData<F>,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> ToConstraintField<F> for PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>
where
    CBul::MembershipPub: ToConstraintField<F>,
    CBul::NonMembershipPub: ToConstraintField<F>,
{
    fn to_field_elements(&self) -> Option<Vec<F>> {
        let mut out = vec![];
        if !self.is_memb_data_const {
            for i in 0..NUMCBS {
                out.extend(self.memb_pub[i].to_field_elements()?);
            }
        }
        if !self.is_nmemb_data_const {
            for i in 0..NUMCBS {
                out.extend(self.nmemb_pub[i].to_field_elements()?);
            }
        }

        out.extend(self.cur_time.to_field_elements()?);
        Some(out)
    }
}

/// In-circuit representation of the public scan arguments.
///
/// For more details, see [`PubScanArgs`].
#[derive(Clone)]
pub struct PubScanArgsVar<
    F: PrimeField + Absorb,
    U: UserData<F>,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> {
    /// Public callback ticket membership data in-circuit.
    pub memb_pub: [CBul::MembershipPubVar; NUMCBS],
    /// Public callback ticket nonmembership data in-circuit.
    pub nmemb_pub: [CBul::NonMembershipPubVar; NUMCBS],
    /// Current time in-circuit.
    pub cur_time: TimeVar<F>,

    /// Callback methods. Note that these are not in circuit, as they are called to *construct*
    /// the circuit.
    pub cb_methods: Vec<Callback<F, U, CBArgs, CBArgsVar>>,
}

impl<
    F: PrimeField + Absorb,
    U: UserData<F>,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> std::fmt::Debug for PubScanArgsVar<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Public Scan Arguments in ZK")
    }
}

impl<
    F: PrimeField + Absorb,
    U: UserData<F>,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F> + Clone,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> AllocVar<PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>, F>
    for PubScanArgsVar<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>
{
    fn new_variable<
        T: std::borrow::Borrow<PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>>,
    >(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();
        res.and_then(|rec| {
            let rec = rec.borrow();
            let memb_pub: [CBul::MembershipPubVar; NUMCBS] = match rec.is_memb_data_const {
                false => {
                    ArrayVar::new_variable(ns!(cs, "memb_pub"), || Ok(rec.memb_pub.clone()), mode)?
                        .0
                }
                true => ArrayVar::new_constant(cs.clone(), &rec.memb_pub)?.0,
            };

            let nmemb_pub: [CBul::NonMembershipPubVar; NUMCBS] = match rec.is_nmemb_data_const {
                false => {
                    ArrayVar::new_variable(
                        ns!(cs, "nmemb_pub"),
                        || Ok(rec.nmemb_pub.clone()),
                        mode,
                    )?
                    .0
                }
                true => ArrayVar::new_constant(cs.clone(), &rec.nmemb_pub)?.0,
            };

            let mut cb_methods = vec![];
            for i in &rec.cb_methods {
                cb_methods.push(i.clone());
            }

            let cur_time = TimeVar::new_variable(ns!(cs, "cur_time"), || Ok(rec.cur_time), mode)?;
            Ok(Self {
                memb_pub,
                nmemb_pub,
                cur_time,

                cb_methods,
            })
        })
    }
}

/// Private arguments to the scan method.
///
/// These arguments are passed into the scan method. To prove a proper scan (without revealing the
/// tickets given), one must pass in the tickets as private arguments into the proof.
///
/// # Example
/// ```rust
/// # use zk_callbacks::zk_object;
/// # use zk_callbacks::generic::user::User;
/// # use rand::thread_rng;
/// # use ark_bn254::{Bn254 as E, Fr};
/// # use ark_r1cs_std::eq::EqGadget;
/// # use ark_r1cs_std::cmp::CmpGadget;
/// # use zk_callbacks::generic::interaction::Interaction;
/// # use zk_callbacks::generic::interaction::Callback;
/// # use zk_callbacks::generic::object::Id;
/// # use zk_callbacks::generic::object::Time;
/// # use zk_callbacks::generic::object::TimeVar;
/// # use ark_relations::r1cs::SynthesisError;
/// # use zk_callbacks::generic::user::UserVar;
/// # use ark_r1cs_std::fields::fp::FpVar;
/// # use ark_groth16::Groth16;
/// # use ark_r1cs_std::prelude::Boolean;
/// # use zk_callbacks::generic::bulletin::UserBul;
/// # use zk_callbacks::impls::hash::Poseidon;
/// # use ark_r1cs_std::prelude::UInt8;
/// # use zk_callbacks::impls::dummy::DummyStore;
/// # use zk_callbacks::generic::scan::get_scan_interaction;
/// # use zk_callbacks::generic::scan::PubScanArgs;
/// # use ark_r1cs_std::select::CondSelectGadget;
/// # use zk_callbacks::impls::centralized::crypto::{FakeSigPrivkey, FakeSigPubkey, NoSigOTP};
/// # use zk_callbacks::scannable_zk_object;
/// # use zk_callbacks::generic::scan::PrivScanArgs;
/// # use crate::zk_callbacks::impls::centralized::ds::sigstore::NonmembStore;
/// # use crate::zk_callbacks::generic::bulletin::PublicCallbackBul;
/// # use zk_callbacks::impls::centralized::ds::sigstore::{UOVCallbackStore, UOVStore};
/// # type Groth = Groth16<E>;
/// type PubScan = PubScanArgs<Fr, Data, Fr, FpVar<Fr>, NoSigOTP<Fr>, UOVCallbackStore<Fr, Fr>, 1>;
///
/// #[scannable_zk_object(Fr)]
/// #[derive(Default)]
/// struct Data {
///     pub num_visits: Fr,
///     pub bad_rep: u8,
///     pub last_interacted_time: Time<Fr>,
/// }
///
/// fn method<'a>(old_user: &'a User<Fr, Data>, pub_time: Time<Fr>, _priv: ()) -> User<Fr, Data> {
///     let mut new = old_user.clone();
///     new.data.num_visits += Fr::from(1);
///     new.data.last_interacted_time = pub_time;
///     new
/// }
///
/// fn predicate<'a>(old_user: &'a UserVar<Fr, Data>, new_user: &'a UserVar<Fr, Data>, pub_time: TimeVar<Fr>, _priv: ()) -> Result<Boolean<Fr>, SynthesisError> {
///     let o1 = old_user.data.bad_rep.is_eq(&new_user.data.bad_rep)?;
///     let o2 = old_user.data.bad_rep.is_le(&UInt8::constant(40))?;
///     let o3 = new_user.data.num_visits.is_eq(&(old_user.data.num_visits.clone() + FpVar::Constant(Fr::from(1))))?;
///     let o4 = new_user.data.last_interacted_time.is_eq(&pub_time)?;
///     Ok(o1 & o2 & o3 & o4)
/// }
///
/// fn callback<'a>(old_user: &'a User<Fr, Data>, args: Fr) -> User<Fr, Data> {
///     let mut u2 = old_user.clone();
///     if args == Fr::from(0) {
///         u2.data.bad_rep;
///     } else {
///         u2.data.bad_rep += 10;
///     }
///     u2.clone()
/// }
///
/// fn enforce_callback<'a>(old_user: &'a UserVar<Fr, Data>, args: FpVar<Fr>) -> Result<UserVar<Fr, Data>, SynthesisError> {
///     let mut u = old_user.clone();
///     u.data.bad_rep =
///     UInt8::conditionally_select(
///         &args.is_eq(&FpVar::Constant(Fr::from(0)))?,
///         &u.data.bad_rep,
///         &u.data.bad_rep.wrapping_add(&UInt8::constant(10))
///     )?;
///     Ok(u)
/// }
///
///
/// fn main () {
///
///     let mut rng = thread_rng();
///
///     let cb = Callback {
///         method_id: Id::from(0),
///         expirable: false,
///         expiration: Time::from(10),
///         method: callback,
///         predicate: enforce_callback
///     };
///
///     let cb_methods = vec![cb.clone()];
///
///     let mut store = <UOVStore<Fr, Fr>>::new(&mut rng);
///
///     let int = Interaction {
///         meth: (method, predicate),
///         callbacks: [cb.clone()],
///     };
///
///     let example_pubscan: PubScan = PubScanArgs {
///         memb_pub: [store.callback_bul.get_pubkey()],
///         is_memb_data_const: true,
///         nmemb_pub: [store.callback_bul.nmemb_bul.get_pubkey()],
///         is_nmemb_data_const: true,
///         cur_time: store.callback_bul.nmemb_bul.get_epoch(),
///         bulletin: store.callback_bul.clone(),
///         cb_methods: cb_methods.clone(),
///     };
///
///     let (pk, vk) = int.generate_keys::<Poseidon<2>, Groth, NoSigOTP<Fr>, DummyStore>(&mut rng, Some(()), None, false);
///
///     let (pks, vks) = get_scan_interaction::<_, _, _, _, _, _, Poseidon<2>, 1>().generate_keys::<Poseidon<2>, Groth, NoSigOTP<Fr>, DummyStore>(&mut rng, Some(()), Some(example_pubscan), true);
///
///     let mut u = User::create(Data { bad_rep: 0, num_visits: Fr::from(0), last_interacted_time: Time::from(0) }, &mut rng);
///
///     let exec_meth = u.interact::<Poseidon<2>, Time<Fr>, TimeVar<Fr>, (), (), Fr, FpVar<Fr>, NoSigOTP<Fr>, Groth, DummyStore, 1>(&mut rng, int.clone(), [FakeSigPubkey::pk()], Time::from(20), ((), ()), true, &pk, Time::from(20), (), false).unwrap();
///
///     let cb = u.get_cb::<Fr, NoSigOTP<Fr>>(0);
///     let tik: FakeSigPubkey<Fr> = cb.get_ticket();
///
///     let x = <UOVCallbackStore<Fr, Fr> as PublicCallbackBul<Fr, Fr, NoSigOTP<Fr>>>::verify_in(&store.callback_bul, tik.clone());
///
///     let prs: PrivScanArgs<Fr, Fr, NoSigOTP<Fr>, UOVCallbackStore<Fr, Fr>, 1> = PrivScanArgs {
///         priv_n_tickets: [cb],
///         post_times: [x.map_or(Fr::from(0), |(_, p2)| p2)],
///         enc_args: [x.map_or(Fr::from(0), |(p1, _)| p1)],
///         memb_priv: [store.callback_bul.get_memb_witness(&tik).unwrap_or_default()],
///         nmemb_priv: [store.callback_bul.get_nmemb_witness(&tik).unwrap_or_default()],
///     };
///
/// }
/// ```
pub struct PrivScanArgs<
    F: PrimeField + Absorb,
    CBArgs: Clone,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> {
    /// The private callback tickets handed out.
    pub priv_n_tickets: [CallbackCom<F, CBArgs, Crypto>; NUMCBS],
    /// The encrypted arguments if a callback ticket has been called. If not, this should be
    /// set to a default value.
    pub enc_args: [Crypto::Ct; NUMCBS],
    /// The post time of a callback ticket if it has been called (posted). If not, this should
    /// be set to a default value.
    pub post_times: [Time<F>; NUMCBS],
    /// Private membership data for callback tickets. If the callback ticket is not a member (has not
    /// been called), then this should be set to a default value.
    pub memb_priv: [CBul::MembershipWitness; NUMCBS],
    /// Private nonmembership data for callback tickets. If the callback ticket is a member
    /// (has been called), then this should be set to a default value.
    pub nmemb_priv: [CBul::NonMembershipWitness; NUMCBS],
}

impl<
    F: PrimeField + Absorb,
    CBArgs: Clone,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> Clone for PrivScanArgs<F, CBArgs, Crypto, CBul, NUMCBS>
where
    CBul::MembershipWitness: Clone,
    CBul::NonMembershipWitness: Clone,
{
    fn clone(&self) -> Self {
        Self {
            priv_n_tickets: core::array::from_fn(|i| self.priv_n_tickets[i].clone()),
            enc_args: core::array::from_fn(|i| self.enc_args[i].clone()),
            post_times: core::array::from_fn(|i| self.post_times[i].clone()),
            memb_priv: core::array::from_fn(|i| self.memb_priv[i].clone()),
            nmemb_priv: core::array::from_fn(|i| self.nmemb_priv[i].clone()),
        }
    }
}

impl<
    F: PrimeField + Absorb,
    CBArgs: Clone + Default,
    Crypto: AECipherSigZK<F, CBArgs> + Default,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> Default for PrivScanArgs<F, CBArgs, Crypto, CBul, NUMCBS>
where
    CBul::MembershipWitness: Default,
    CBul::NonMembershipWitness: Default,
{
    fn default() -> Self {
        let pnt: [CallbackCom<F, CBArgs, Crypto>; NUMCBS] =
            core::array::from_fn(|_| CallbackCom::default());
        Self {
            memb_priv: core::array::from_fn(|_| CBul::MembershipWitness::default()),
            nmemb_priv: core::array::from_fn(|_| CBul::NonMembershipWitness::default()),
            enc_args: core::array::from_fn(|_| Crypto::Ct::default()),
            post_times: core::array::from_fn(|_| Time::<F>::default()),
            priv_n_tickets: pnt,
        }
    }
}

impl<
    F: PrimeField + Absorb,
    CBArgs: Clone,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> std::fmt::Debug for PrivScanArgs<F, CBArgs, Crypto, CBul, NUMCBS>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Private Scan Arguments")
    }
}

/// In-circuit representation of the private scan arguments.
///
/// For more details, see [`PrivScanArgs`].
#[derive(Clone)]
pub struct PrivScanArgsVar<
    F: PrimeField + Absorb,
    CBArgs: Clone,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> {
    /// Opened callback ticket commitments in-circuit.
    pub priv_n_tickets: [CallbackComVar<F, CBArgs, Crypto>; NUMCBS],
    /// The encrypted arguments for called callback tickets in-circuit.
    pub enc_args: [<Crypto::EncKey as CPACipher<F>>::CV; NUMCBS],
    /// The post (call) time for called callback tickets in-circuit.
    pub post_times: [TimeVar<F>; NUMCBS],
    /// The private membership data for a callback ticket in-circuit.
    pub memb_priv: [CBul::MembershipWitnessVar; NUMCBS],
    /// The private nonmembership data for a callback ticket in-circuit.
    pub nmemb_priv: [CBul::NonMembershipWitnessVar; NUMCBS],
}

impl<
    F: PrimeField + Absorb,
    CBArgs: Clone,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> std::fmt::Debug for PrivScanArgsVar<F, CBArgs, Crypto, CBul, NUMCBS>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Private Scan Arguments in ZK")
    }
}

impl<
    F: PrimeField + Absorb,
    CBArgs: Clone,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    const NUMCBS: usize,
> AllocVar<PrivScanArgs<F, CBArgs, Crypto, CBul, NUMCBS>, F>
    for PrivScanArgsVar<F, CBArgs, Crypto, CBul, NUMCBS>
{
    fn new_variable<T: std::borrow::Borrow<PrivScanArgs<F, CBArgs, Crypto, CBul, NUMCBS>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();
        res.and_then(|rec| {
            let rec = rec.borrow();

            let priv_n_tickets: ArrayVar<CallbackComVar<F, CBArgs, Crypto>, NUMCBS> =
                ArrayVar::new_variable(
                    ns!(cs, "priv_n_tickets"),
                    || Ok(rec.priv_n_tickets.clone()),
                    mode,
                )?;

            let memb_priv: [CBul::MembershipWitnessVar; NUMCBS] =
                ArrayVar::new_variable(ns!(cs, "memb_priv"), || Ok(rec.memb_priv.clone()), mode)?.0;
            let nmemb_priv: [CBul::NonMembershipWitnessVar; NUMCBS] =
                ArrayVar::new_variable(ns!(cs, "nmemb_priv"), || Ok(rec.nmemb_priv.clone()), mode)?
                    .0;
            let post_times: [TimeVar<F>; NUMCBS] =
                ArrayVar::new_variable(ns!(cs, "post_times"), || Ok(rec.post_times), mode)?.0;

            let enc_args: [<Crypto::EncKey as CPACipher<F>>::CV; NUMCBS] =
                ArrayVar::new_variable(ns!(cs, "enc_args"), || Ok(rec.enc_args.clone()), mode)?.0;

            Ok(Self {
                priv_n_tickets: priv_n_tickets.0,
                enc_args,
                post_times,
                memb_priv,
                nmemb_priv,
            })
        })
    }
}

/// Applies a scan to a user.
///
/// This applies a scan with public arguments (callback bulletin public data, the time of
/// scan) and private arguments (the callback tickets, encrypted arguments, and post times).
///
/// This is structured for use within an interaction.
pub fn scan_method<
    F: PrimeField + Absorb,
    U: UserData<F>,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    H: FieldHash<F>,
    const NUMCBS: usize,
>(
    user: &User<F, U>,
    pub_args: PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>,
    priv_args: PrivScanArgs<F, CBArgs, Crypto, CBul, NUMCBS>,
) -> User<F, U> {
    let mut out_user = user.clone();

    if out_user.zk_fields.is_ingest_over {
        out_user.zk_fields.is_ingest_over = false;
        out_user.zk_fields.old_in_progress_callback_hash = F::zero();
        out_user.zk_fields.new_in_progress_callback_hash = F::zero();
        out_user.scan_index = Some(0);
        out_user.in_progress_cbs = out_user.callbacks.clone();
    }

    let mut marked_for_deletion = vec![];

    for i in priv_args.priv_n_tickets {
        out_user.zk_fields.old_in_progress_callback_hash = add_ticket_to_hc::<F, H, CBArgs, Crypto>(
            out_user.zk_fields.old_in_progress_callback_hash,
            i.cb_entry.clone(),
        );

        match pub_args.bulletin.verify_in(i.cb_entry.tik.clone()) {
            Some((ct, sig, time)) => {
                assert!(
                    <Crypto as AECipherSigZK<F, CBArgs>>::SigPK::verify(
                        &i.cb_entry.tik,
                        ct.clone(),
                        sig
                    ) == true
                );
                if i.cb_entry.expirable && time > i.cb_entry.expiration {
                } else {
                    for x in &pub_args.cb_methods {
                        if x.method_id == i.cb_entry.cb_method_id {
                            let args = i.cb_entry.enc_key.decrypt(ct.clone());
                            out_user = (x.method)(&out_user, args);
                        }
                    }
                }

                let mut cb = Vec::new();
                i.clone().serialize_compressed(&mut cb).unwrap();
                for x in 0..out_user.in_progress_cbs.len() {
                    if out_user.in_progress_cbs[x] == cb {
                        marked_for_deletion.push(x);
                    }
                }
            }
            None => {
                assert!(pub_args.bulletin.verify_not_in(i.clone().cb_entry.tik));
                if i.cb_entry.expirable && pub_args.cur_time > i.cb_entry.expiration {
                    let mut cb = Vec::new();
                    i.clone().serialize_compressed(&mut cb).unwrap();
                    for x in 0..out_user.in_progress_cbs.len() {
                        if out_user.in_progress_cbs[x] == cb {
                            marked_for_deletion.push(x);
                        }
                    }
                } else {
                    out_user.zk_fields.new_in_progress_callback_hash =
                        add_ticket_to_hc::<F, H, CBArgs, Crypto>(
                            out_user.zk_fields.new_in_progress_callback_hash,
                            i.cb_entry,
                        );
                }
            }
        }

        out_user.scan_index = Some(out_user.scan_index.unwrap() + 1);
    }

    let mut new_ipc = vec![];
    for i in 0..out_user.in_progress_cbs.len() {
        if !marked_for_deletion.contains(&i) {
            new_ipc.push(out_user.in_progress_cbs[i].clone());
        }
    }

    out_user.in_progress_cbs = new_ipc;

    if out_user.zk_fields.old_in_progress_callback_hash == out_user.zk_fields.callback_hash {
        out_user.zk_fields.callback_hash = out_user.zk_fields.new_in_progress_callback_hash;
        out_user.zk_fields.new_in_progress_callback_hash = F::ZERO;
        out_user.zk_fields.old_in_progress_callback_hash = out_user.zk_fields.callback_hash;
        out_user.zk_fields.is_ingest_over = true;
        out_user.callbacks = out_user.in_progress_cbs.clone();
        out_user.in_progress_cbs = vec![];
        out_user.scan_index = None;
    }

    out_user
}

pub(crate) fn scan_apply_method_zk<
    F: PrimeField + Absorb,
    U: UserData<F>,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    H: FieldHash<F>,
    const NUMCBS: usize,
>(
    user_old: &UserVar<F, U>,
    pub_args: PubScanArgsVar<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>,
    priv_args: PrivScanArgsVar<F, CBArgs, Crypto, CBul, NUMCBS>,
) -> ArkResult<UserVar<F, U>>
where
    U::UserDataVar: CondSelectGadget<F> + EqGadget<F>,
{
    let mut inprog_user = user_old.clone();

    let updated_old = FpVar::<F>::conditionally_select(
        &user_old.zk_fields.is_ingest_over,
        &FpVar::Constant(F::zero()),
        &user_old.zk_fields.old_in_progress_callback_hash,
    )?;

    let updated_new = FpVar::<F>::conditionally_select(
        &user_old.zk_fields.is_ingest_over,
        &FpVar::Constant(F::zero()),
        &user_old.zk_fields.new_in_progress_callback_hash,
    )?;

    let updated_ingest = Boolean::conditionally_select(
        &user_old.zk_fields.is_ingest_over,
        &Boolean::FALSE,
        &user_old.zk_fields.is_ingest_over,
    )?;

    inprog_user.zk_fields.is_ingest_over = updated_ingest;
    inprog_user.zk_fields.old_in_progress_callback_hash = updated_old;
    inprog_user.zk_fields.new_in_progress_callback_hash = updated_new;

    // check the ids are sequentially assigned and in-order
    let mut r = F::ZERO;
    for j in 0..pub_args.cb_methods.len() {
        assert!(pub_args.cb_methods[j].method_id == r);
        r += F::ONE;
    }

    for i in 0..NUMCBS {
        add_ticket_to_hc_zk::<F, H, CBArgs, Crypto>(
            &mut inprog_user.zk_fields.old_in_progress_callback_hash,
            priv_args.priv_n_tickets[i].cb_entry.clone(),
        )?;

        let memb = CBul::enforce_memb_nmemb(
            (
                priv_args.priv_n_tickets[i].cb_entry.tik.clone(),
                priv_args.enc_args[i].clone(),
                priv_args.post_times[i].clone(),
            ),
            (
                priv_args.memb_priv[i].clone(),
                priv_args.nmemb_priv[i].clone(),
            ),
            (pub_args.memb_pub[i].clone(), pub_args.nmemb_pub[i].clone()),
        )?;

        // part 1: if we are in the membership setting
        //
        // if expired (do nothing)
        // if not expired
        //      1. call every callback on the user to get a list of "potential" users
        //      2. conditionally select the user based off the cb id

        let mut memb_world_user = inprog_user.clone();

        let mut potential = vec![];

        for j in 0..pub_args.cb_methods.len() {
            let dec = Crypto::EncKey::decrypt_in_zk(
                priv_args.priv_n_tickets[i].cb_entry.enc_key.clone(),
                priv_args.enc_args[i].clone(),
            )?;

            potential.push((
                (pub_args.cb_methods[j].predicate)(&memb_world_user, dec)?,
                FpVar::Constant(pub_args.cb_methods[j].method_id),
            ));
        }

        let mut cond_user_select = memb_world_user.clone();

        for k in 0..potential.len() {
            cond_user_select = UserVar::conditionally_select(
                &(priv_args.priv_n_tickets[i]
                    .cb_entry
                    .cb_method_id
                    .is_eq(&potential[k].1)?),
                &potential[k].0,
                &cond_user_select,
            )?;
        }

        let ut1 = <UInt<64, u64, F>>::from_fp(&priv_args.post_times[i])?.0;
        let ut2 = <UInt<64, u64, F>>::from_fp(&priv_args.priv_n_tickets[i].cb_entry.expiration)?.0;

        memb_world_user = UserVar::conditionally_select(
            &(priv_args.priv_n_tickets[i].clone().cb_entry.expirable & ((ut1.is_gt(&ut2))?)),
            &memb_world_user,
            &cond_user_select,
        )?;

        // part 2: nonmembership!
        //
        // a) conditionally select on expiry and update the callback hash
        //
        //
        //

        let mut nmemb_world_user = inprog_user.clone();

        let ut1 = <UInt<64, u64, F>>::from_fp(&pub_args.cur_time)?.0;
        let ut2 = <UInt<64, u64, F>>::from_fp(&priv_args.priv_n_tickets[i].cb_entry.expiration)?.0;

        let mut possibly_nonexpired_hc = nmemb_world_user
            .zk_fields
            .new_in_progress_callback_hash
            .clone();

        add_ticket_to_hc_zk::<F, H, CBArgs, Crypto>(
            &mut possibly_nonexpired_hc,
            priv_args.priv_n_tickets[i].cb_entry.clone(),
        )?;

        nmemb_world_user.zk_fields.new_in_progress_callback_hash =
            FpVar::<F>::conditionally_select(
                &(priv_args.priv_n_tickets[i].clone().cb_entry.expirable & ((ut1.is_gt(&ut2))?)),
                &nmemb_world_user.zk_fields.new_in_progress_callback_hash,
                &possibly_nonexpired_hc,
            )?;

        // together: using memb, select the correct user from part 1 / 2
        let correct_updated_user =
            UserVar::conditionally_select(&memb, &memb_world_user, &nmemb_world_user)?;

        inprog_user = correct_updated_user;
    }

    let updated_cbh = FpVar::<F>::conditionally_select(
        &(inprog_user
            .zk_fields
            .callback_hash
            .is_eq(&inprog_user.zk_fields.old_in_progress_callback_hash)?),
        &inprog_user.zk_fields.new_in_progress_callback_hash,
        &inprog_user.zk_fields.callback_hash,
    )?;

    let updated_new = FpVar::<F>::conditionally_select(
        &(inprog_user
            .zk_fields
            .callback_hash
            .is_eq(&inprog_user.zk_fields.old_in_progress_callback_hash)?),
        &FpVar::Constant(F::zero()),
        &inprog_user.zk_fields.new_in_progress_callback_hash,
    )?;

    let updated_old = FpVar::<F>::conditionally_select(
        &(inprog_user
            .zk_fields
            .callback_hash
            .is_eq(&inprog_user.zk_fields.old_in_progress_callback_hash)?),
        &updated_cbh,
        &inprog_user.zk_fields.old_in_progress_callback_hash,
    )?;

    let updated_ingest = Boolean::conditionally_select(
        &(inprog_user
            .zk_fields
            .callback_hash
            .is_eq(&inprog_user.zk_fields.old_in_progress_callback_hash)?),
        &Boolean::TRUE,
        &inprog_user.zk_fields.is_ingest_over,
    )?;

    inprog_user.zk_fields.callback_hash = updated_cbh;
    inprog_user.zk_fields.new_in_progress_callback_hash = updated_new;
    inprog_user.zk_fields.old_in_progress_callback_hash = updated_old;
    inprog_user.zk_fields.is_ingest_over = updated_ingest;

    Ok(inprog_user)
}

/// Enforces that the `user_new` is a scan of `user_old`.
///
/// This is the predicate associated with [`scan_method`], for use in an interaction.
pub fn scan_predicate<
    F: PrimeField + Absorb,
    U: UserData<F>,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto>,
    H: FieldHash<F>,
    const NUMCBS: usize,
>(
    user_old: &UserVar<F, U>,
    user_new: &UserVar<F, U>,
    pub_args: PubScanArgsVar<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMCBS>,
    priv_args: PrivScanArgsVar<F, CBArgs, Crypto, CBul, NUMCBS>,
) -> ArkResult<Boolean<F>>
where
    U::UserDataVar: CondSelectGadget<F> + EqGadget<F>,
{
    let out_user = scan_apply_method_zk::<F, U, CBArgs, CBArgsVar, Crypto, CBul, H, NUMCBS>(
        user_old, pub_args, priv_args,
    )?;

    let b = out_user.data.is_eq(&user_new.data)?;

    // let b = User::commit_in_zk::<H>(inprog_user)?
    //    .is_eq(&(User::commit_in_zk::<H>(user_new.clone())?))?;

    Ok(b)
}

/// Returns the interaction associated with a scan.
///
/// Note that a scan is simply just a method (to scan some number of tickets) and a predicate (to
/// enforce the correct scan). Therefore, a scan can be encapsulated into an interaction, which
/// contains 0 new callbacks.
///
/// This function returns the interaction associated with [`scan_method`] and [`scan_predicate`].
///
/// # Example
/// ```rust
/// # use zk_callbacks::zk_object;
/// # use zk_callbacks::generic::user::User;
/// # use rand::thread_rng;
/// # use ark_bn254::{Bn254 as E, Fr};
/// # use ark_r1cs_std::eq::EqGadget;
/// # use ark_r1cs_std::cmp::CmpGadget;
/// # use zk_callbacks::generic::interaction::Interaction;
/// # use zk_callbacks::generic::interaction::Callback;
/// # use zk_callbacks::generic::object::Id;
/// # use zk_callbacks::generic::object::Time;
/// # use zk_callbacks::generic::object::TimeVar;
/// # use ark_relations::r1cs::SynthesisError;
/// # use zk_callbacks::generic::user::UserVar;
/// # use ark_r1cs_std::fields::fp::FpVar;
/// # use ark_groth16::Groth16;
/// # use ark_r1cs_std::prelude::Boolean;
/// # use zk_callbacks::generic::bulletin::UserBul;
/// # use zk_callbacks::impls::hash::Poseidon;
/// # use ark_r1cs_std::prelude::UInt8;
/// # use zk_callbacks::impls::dummy::DummyStore;
/// # use zk_callbacks::generic::scan::get_scan_interaction;
/// # use zk_callbacks::generic::scan::PubScanArgs;
/// # use ark_r1cs_std::select::CondSelectGadget;
/// # use zk_callbacks::impls::centralized::crypto::{FakeSigPrivkey, FakeSigPubkey, NoSigOTP};
/// # use zk_callbacks::scannable_zk_object;
/// # type Groth = Groth16<E>;
/// # type PubScan = PubScanArgs<Fr, Data, Fr, FpVar<Fr>, NoSigOTP<Fr>, DummyStore, 1>;
/// #[scannable_zk_object(Fr)]
/// #[derive(Default)]
/// struct Data {
///     pub num_visits: Fr,
///     pub bad_rep: u8,
///     pub last_interacted_time: Time<Fr>,
/// }
///
/// fn method<'a>(old_user: &'a User<Fr, Data>, pub_time: Time<Fr>, _priv: ()) -> User<Fr, Data> {
///     let mut new = old_user.clone();
///     new.data.num_visits += Fr::from(1);
///     new.data.last_interacted_time = pub_time;
///     new
/// }
///
/// fn predicate<'a>(old_user: &'a UserVar<Fr, Data>, new_user: &'a UserVar<Fr, Data>, pub_time: TimeVar<Fr>, _priv: ()) -> Result<Boolean<Fr>, SynthesisError> {
///     let o1 = old_user.data.bad_rep.is_eq(&new_user.data.bad_rep)?;
///     let o2 = old_user.data.bad_rep.is_le(&UInt8::constant(40))?;
///     let o3 = new_user.data.num_visits.is_eq(&(old_user.data.num_visits.clone() + FpVar::Constant(Fr::from(1))))?;
///     let o4 = new_user.data.last_interacted_time.is_eq(&pub_time)?;
///     Ok(o1 & o2 & o3 & o4)
/// }
///
/// fn callback<'a>(old_user: &'a User<Fr, Data>, args: Fr) -> User<Fr, Data> {
///     let mut u2 = old_user.clone();
///     if args == Fr::from(0) {
///         u2.data.bad_rep;
///     } else {
///         u2.data.bad_rep += 10;
///     }
///     u2.clone()
/// }
///
/// fn enforce_callback<'a>(old_user: &'a UserVar<Fr, Data>, args: FpVar<Fr>) -> Result<UserVar<Fr, Data>, SynthesisError> {
///     let mut u = old_user.clone();
///     u.data.bad_rep =
///     UInt8::conditionally_select(
///         &args.is_eq(&FpVar::Constant(Fr::from(0)))?,
///         &u.data.bad_rep,
///         &u.data.bad_rep.wrapping_add(&UInt8::constant(10))
///     )?;
///     Ok(u)
/// }
///
///
/// fn main () {
///     let cb = Callback {
///         method_id: Id::from(0),
///         expirable: false,
///         expiration: Time::from(10),
///         method: callback,
///         predicate: enforce_callback
///     };
///
///     let cb_methods = vec![cb.clone()];
///
///     let int = Interaction {
///         meth: (method, predicate),
///         callbacks: [cb.clone()],
///     };
///
///     let ex: PubScan = PubScanArgs {
///         memb_pub: [(); 1],
///         is_memb_data_const: true,
///         nmemb_pub: [(); 1],
///         is_nmemb_data_const: true,
///         cur_time: Fr::from(0),
///         bulletin: DummyStore,
///         cb_methods: cb_methods.clone(),
///     };
///
///     let mut rng = thread_rng();
///
///     let (pk, vk) = int.generate_keys::<Poseidon<2>, Groth, NoSigOTP<Fr>, DummyStore>(&mut rng, Some(()), None, false);
///
///     let inter = get_scan_interaction::<_, Data, _, _, NoSigOTP<Fr>, DummyStore, Poseidon<2>, 1>();
/// }
/// ```
pub fn get_scan_interaction<
    F: PrimeField + Absorb,
    U: UserData<F>,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F> + Clone,
    Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar>,
    CBul: PublicCallbackBul<F, CBArgs, Crypto> + Clone,
    H: FieldHash<F>,
    const NUMSCANS: usize,
>() -> Interaction<
    F,
    U,
    PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS>,
    PubScanArgsVar<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS>,
    PrivScanArgs<F, CBArgs, Crypto, CBul, NUMSCANS>,
    PrivScanArgsVar<F, CBArgs, Crypto, CBul, NUMSCANS>,
    CBArgs,
    CBArgsVar,
    0,
>
where
    U::UserDataVar: CondSelectGadget<F> + EqGadget<F>,
{
    Interaction {
        meth: (
            scan_method::<F, U, CBArgs, CBArgsVar, Crypto, CBul, H, NUMSCANS>,
            scan_predicate::<F, U, CBArgs, CBArgsVar, Crypto, CBul, H, NUMSCANS>,
        ),
        callbacks: [],
    }
}
