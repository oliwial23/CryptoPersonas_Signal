use crate::{
    crypto::{
        enc::{AECipherSigZK, CPACipher},
        rr::RRVerifier,
    },
    generic::{
        object::{Com, ComVar, Nul},
        user::UserData,
    },
};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{
    eq::EqGadget,
    prelude::{AllocVar, Boolean},
};
use ark_relations::r1cs::SynthesisError;
use ark_snark::SNARK;

use crate::generic::object::{Time, TimeVar};

/// An error indicating something went wrong with a bulletin.
#[derive(Debug, Clone)]
pub enum BulError<E> {
    /// A proof verification failed (returned false).
    VerifyError,
    /// Appending to the bulletin failed.
    AppendError(E),
}

/// Methods which users can perform by viewing a public user bulletin.
///
/// This trait allows for users to verify membership of an object within a bulletin. Additionally, it allows for a user to prove
/// membership with [`PublicUserBul::enforce_membership_of`].
///
/// This could be a network handle to a site containing a list of
/// commitments to users.
///
/// # Example (Static List)
///
/// In this example, the bulletin is a static list of 10 commitments. To prove membership, one
/// loops through the whole list and checks that one of them is equal to the commitment.
/// ```rust
/// # use ark_bls12_381::Fr;
/// # use zk_callbacks::generic::object::{Com, ComVar};
/// # use zk_callbacks::generic::bulletin::PublicUserBul;
/// # use ark_relations::r1cs::{SynthesisError, Namespace};
/// # use ark_r1cs_std::prelude::AllocationMode;
/// # use ark_relations::ns;
/// # use ark_r1cs_std::alloc::AllocVar;
/// # use ark_relations::r1cs::ToConstraintField;
/// # use ark_snark::SNARK;
/// # use zk_callbacks::generic::object::Nul;
/// # use zk_callbacks::scannable_zk_object;
/// # use ark_r1cs_std::prelude::Boolean;
/// # use ark_r1cs_std::eq::EqGadget;
/// #[scannable_zk_object(Fr)]
/// struct Data {
///     pub token: Fr
/// }
///
/// #[derive(Clone, Default)]
/// struct StaticList {
///     pub list: [Com<Fr>; 10],
/// }
///
/// #[derive(Clone)]
/// struct StaticListVar {
///     pub list: [ComVar<Fr>; 10]
/// }
/// # impl AllocVar<StaticList, Fr> for StaticListVar {
/// #    fn new_variable<T: std::borrow::Borrow<StaticList>>(
/// #        cs: impl Into<Namespace<Fr>>,
/// #        f: impl FnOnce() -> Result<T, SynthesisError>,
/// #        mode: AllocationMode
/// #    ) -> Result<Self, SynthesisError> {
/// #        let ns = cs.into();
/// #        let cs = ns.cs();
/// #        let res = f();
/// #        res.and_then(|rec| {
/// #            let rec = rec.borrow();
/// #            let data = Vec::<ComVar<Fr>>::new_variable(ns!(cs, "list"), || Ok(rec.list.clone()), mode)?;
/// #            Ok(Self {
/// #                list: data.try_into().unwrap()
/// #            })
/// #        })
/// #    }
/// # }
/// # impl ToConstraintField<Fr> for StaticList {
/// #   fn to_field_elements(&self) -> Option<Vec<Fr>> {
/// #       Some(self.list.to_vec())
/// #   }
/// # }
///
/// impl PublicUserBul<Fr, Data> for StaticList {
///
///     type MembershipWitness = ();
///
///     type MembershipWitnessVar = ();
///
///     type MembershipPub = StaticList;
///
///     type MembershipPubVar = StaticListVar;
///
///     fn verify_in<PubArgs, Snark: SNARK<Fr>, const NUMCBS: usize>(
///         &self,
///         object: Com<Fr>,
///         _old_nul: Nul<Fr>,
///         _cb_com_list: [Com<Fr>; NUMCBS],
///         _args: PubArgs,
///         _proof: Snark::Proof,
///         _memb_data: Self::MembershipPub,
///         _verif_key: &Snark::VerifyingKey
///     ) -> bool {
///         self.list.contains(&object)
///     }
///
///     fn get_membership_data(&self, o: Com<Fr>) -> Option<(Self, ())> {
///         match self.list.contains(&o) {
///             true => Some((self.clone(), ())),
///             false => None
///         }
///     }
///
///     fn enforce_membership_of(ov: ComVar<Fr>, ewit: (), epub: StaticListVar) -> Result<Boolean<Fr>, SynthesisError> {
///         let mut b = Boolean::FALSE;
///         for i in 0..10 {
///             b = b | ov.is_eq(&epub.list[i])?;
///         }
///         Ok(b)
///     }
/// }
///
/// ```
///
/// # Example (Over the network)
///
/// Here, a user client interacts with a server over the network. To interface with the server, we
/// treat the HTTP client session as a public user bulletin. (In this example, we still have a
/// static list over the network).
///
/// ```rust
/// # use ark_bls12_381::Fr;
/// # use zk_callbacks::generic::object::{Com, ComVar};
/// # use zk_callbacks::generic::bulletin::PublicUserBul;
/// # use ark_relations::r1cs::{SynthesisError, Namespace};
/// # use ark_r1cs_std::prelude::AllocationMode;
/// # use ark_relations::ns;
/// # use ark_r1cs_std::alloc::AllocVar;
/// # use ark_relations::r1cs::ToConstraintField;
/// # use ark_snark::SNARK;
/// # use zk_callbacks::generic::object::Nul;
/// # use zk_callbacks::scannable_zk_object;
/// # use ark_r1cs_std::prelude::Boolean;
/// # use ark_r1cs_std::eq::EqGadget;
/// #[scannable_zk_object(Fr)]
/// struct Data {
///     pub token: Fr
/// }
/// # #[derive(Clone, Default)]
/// # struct Session {
/// # }
/// #
/// # impl Session {
/// #   fn fetch_list_from(&self, url: &str) -> Result<StaticList, &'static str> {
/// #       todo!()
/// #   }
/// # }
/// #
/// # #[derive(Clone, Default)]
/// # struct StaticList {
/// #     pub list: [Com<Fr>; 10],
/// # }
/// #
/// # #[derive(Clone)]
/// # struct StaticListVar {
/// #     pub list: [ComVar<Fr>; 10]
/// # }
/// # impl AllocVar<StaticList, Fr> for StaticListVar {
/// #    fn new_variable<T: std::borrow::Borrow<StaticList>>(
/// #        cs: impl Into<Namespace<Fr>>,
/// #        f: impl FnOnce() -> Result<T, SynthesisError>,
/// #        mode: AllocationMode
/// #    ) -> Result<Self, SynthesisError> {
/// #        let ns = cs.into();
/// #        let cs = ns.cs();
/// #        let res = f();
/// #        res.and_then(|rec| {
/// #            let rec = rec.borrow();
/// #            let data = Vec::<ComVar<Fr>>::new_variable(ns!(cs, "list"), || Ok(rec.list.clone()), mode)?;
/// #            Ok(Self {
/// #                list: data.try_into().unwrap()
/// #            })
/// #        })
/// #    }
/// # }
/// # impl ToConstraintField<Fr> for StaticList {
/// #   fn to_field_elements(&self) -> Option<Vec<Fr>> {
/// #       Some(self.list.to_vec())
/// #   }
/// # }
///
/// impl PublicUserBul<Fr, Data> for Session {
///
///     type MembershipWitness = ();
///
///     type MembershipWitnessVar = ();
///
///     type MembershipPub = StaticList;
///
///     type MembershipPubVar = StaticListVar;
///
///     fn verify_in<PubArgs, Snark: SNARK<Fr>, const NUMCBS: usize>(
///         &self,
///         object: Com<Fr>,
///         _old_nul: Nul<Fr>,
///         _cb_com_list: [Com<Fr>; NUMCBS],
///         _args: PubArgs,
///         _proof: Snark::Proof,
///         _memb_data: Self::MembershipPub,
///         _verif_key: &Snark::VerifyingKey
///     ) -> bool {
///         let list = self.fetch_list_from("http://example.com/pubuserbul").unwrap().list;
///         list.contains(&object)
///     }
///
///     fn get_membership_data(&self, o: Com<Fr>) -> Option<(StaticList, ())> {
///         let sl = self.fetch_list_from("http://example.com/pubuserbul").unwrap();
///         match sl.list.contains(&o) {
///             true => Some((sl, ())),
///             false => None
///         }
///     }
///
///     fn enforce_membership_of(ov: ComVar<Fr>, ewit: (), epub: StaticListVar) -> Result<Boolean<Fr>, SynthesisError> {
///         let mut b = Boolean::FALSE;
///         for i in 0..10 {
///             b = b | ov.is_eq(&epub.list[i])?;
///         }
///         Ok(b)
///     }
/// }
///
/// ```
pub trait PublicUserBul<F: PrimeField + Absorb, U: UserData<F>> {
    /// The witness for object membership. For example, a Merkle path.
    type MembershipWitness: Clone + Default;
    /// The in-circuit representation of the witness.
    type MembershipWitnessVar: AllocVar<Self::MembershipWitness, F> + Clone;
    /// The public data for object membership. For example, the Merkle root.
    type MembershipPub: Clone + Default + ToConstraintField<F>;
    /// The in-circuit representation of the public data.
    type MembershipPubVar: AllocVar<Self::MembershipPub, F> + Clone;

    /// Verify that a user object is in the bulletin.
    ///
    /// This function also contains extra data if the bulletin chooses to store the extra proof
    /// data. Once a user provides a new object to the bulletin, the bulletin may choose to publish
    /// the users proof so any other user / service can verify the proof. Therefore, we must be
    /// able to verify membership of the user *along with their proof*.
    ///
    /// However, for centralized scenarios (where there is a single server), it is often only
    /// necessary to post the object. The example illustrates a centralized setting above.
    #[allow(clippy::too_many_arguments)]
    fn verify_in<PubArgs: ToConstraintField<F>, Snark: SNARK<F>, const NUMCBS: usize>(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        args: PubArgs,
        proof: Snark::Proof,
        memb_data: Self::MembershipPub,
        verif_key: &Snark::VerifyingKey,
    ) -> bool;

    /// Given an object, get the membership data associated to that object.
    ///
    /// If the object is not contained in the bulletin, this function should return `None`.
    ///
    /// For example, for an object this could return a Merkle root and path.
    fn get_membership_data(
        &self,
        object: Com<F>,
    ) -> Option<(Self::MembershipPub, Self::MembershipWitness)>;

    /// Prove membership in-circuit.
    ///
    /// Given a user object and membership witness and public data, return `true` if the user is in
    /// the bulletin, and `false` otherwise.
    fn enforce_membership_of(
        data_var: ComVar<F>,
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError>;
}

/// A user bulletin.
///
/// This represents a user bulletin. While the [`PublicUserBul`] contains functions users can
/// perform by *viewing* the bulletin, this trait encompasses **the bulletin** itself, which
/// includes appending and verifying user objects.
///
/// Note that **this gives the freedom of a backend**. For example, one may implement [`UserBul`]
/// via a SQL database (by implementing [`UserBul::append_value`] as inserting into the database).
/// Alternatively, in the decentralized setting, one may abstract away the consensus layer, and
/// "append" a new value to the Merkle tree by performing some consensus append protocol.
///
/// # Example (Static List)
///
/// In this example, the bulletin is a static list of 10 commitments. To prove membership, one
/// loops through the whole list and checks that one of them is equal to the commitment.
/// ```rust
/// # use ark_bls12_381::Fr;
/// # use zk_callbacks::generic::object::{Com, ComVar};
/// # use zk_callbacks::generic::bulletin::PublicUserBul;
/// # use ark_relations::r1cs::{SynthesisError, Namespace};
/// # use ark_r1cs_std::prelude::AllocationMode;
/// # use ark_relations::ns;
/// # use ark_r1cs_std::alloc::AllocVar;
/// # use ark_relations::r1cs::ToConstraintField;
/// # use ark_snark::SNARK;
/// # use zk_callbacks::generic::object::Nul;
/// # use zk_callbacks::generic::bulletin::UserBul;
/// # use zk_callbacks::scannable_zk_object;
/// # use ark_r1cs_std::prelude::Boolean;
/// # use ark_r1cs_std::eq::EqGadget;
/// #[scannable_zk_object(Fr)]
/// struct Data {
///     pub token: Fr
/// }
///
/// #[derive(Clone, Default)]
/// struct StaticList {
///     pub list: [Com<Fr>; 10],
///     pub nuls: Vec<Nul<Fr>>,
///     pub index: usize,
/// }
///
/// #[derive(Clone)]
/// struct StaticListVar {
///     pub list: [ComVar<Fr>; 10]
/// }
/// # impl AllocVar<StaticList, Fr> for StaticListVar {
/// #    fn new_variable<T: std::borrow::Borrow<StaticList>>(
/// #        cs: impl Into<Namespace<Fr>>,
/// #        f: impl FnOnce() -> Result<T, SynthesisError>,
/// #        mode: AllocationMode
/// #    ) -> Result<Self, SynthesisError> {
/// #        let ns = cs.into();
/// #        let cs = ns.cs();
/// #        let res = f();
/// #        res.and_then(|rec| {
/// #            let rec = rec.borrow();
/// #            let data = Vec::<ComVar<Fr>>::new_variable(ns!(cs, "list"), || Ok(rec.list.clone()), mode)?;
/// #            Ok(Self {
/// #                list: data.try_into().unwrap()
/// #            })
/// #        })
/// #    }
/// # }
/// # impl ToConstraintField<Fr> for StaticList {
/// #   fn to_field_elements(&self) -> Option<Vec<Fr>> {
/// #       Some(self.list.to_vec())
/// #   }
/// # }
/// #
/// # impl PublicUserBul<Fr, Data> for StaticList {
/// #
/// #     type MembershipWitness = ();
/// #
/// #     type MembershipWitnessVar = ();
/// #
/// #     type MembershipPub = StaticList;
/// #
/// #     type MembershipPubVar = StaticListVar;
/// #
/// #     fn verify_in<PubArgs, Snark: SNARK<Fr>, const NUMCBS: usize>(
/// #         &self,
/// #         object: Com<Fr>,
/// #         _old_nul: Nul<Fr>,
/// #         _cb_com_list: [Com<Fr>; NUMCBS],
/// #         _args: PubArgs,
/// #         _proof: Snark::Proof,
/// #         _memb_data: Self::MembershipPub,
/// #         _verif_key: &Snark::VerifyingKey
/// #     ) -> bool {
/// #         self.list.contains(&object)
/// #     }
/// #
/// #     fn get_membership_data(&self, o: Com<Fr>) -> Option<(Self, ())> {
/// #         match self.list.contains(&o) {
/// #             true => Some((self.clone(), ())),
/// #             false => None
/// #         }
/// #     }
/// #
/// #     fn enforce_membership_of(ov: ComVar<Fr>, ewit: (), epub: StaticListVar) -> Result<Boolean<Fr>, SynthesisError> {
/// #         let mut b = Boolean::FALSE;
/// #         for i in 0..10 {
/// #             b = b | ov.is_eq(&epub.list[i])?;
/// #         }
/// #         Ok(b)
/// #     }
/// # }
///
/// impl UserBul<Fr, Data> for StaticList {
///
///      type Error = ();
///
///      fn has_never_received_nul(&self, nul: &Nul<Fr>) -> bool {
///         !self.nuls.contains(nul)
///      }
///
///      fn append_value<PubArgs, Snark: SNARK<Fr>, const NUMCBS: usize>(
///         &mut self,
///         object: Com<Fr>,
///         old_nul: Nul<Fr>,
///         _cb_com_list: [Com<Fr>; NUMCBS],
///         _args: PubArgs,
///         _proof: Snark::Proof,
///         _memb_data: Option<Self::MembershipPub>,
///         _verif_key: &Snark::VerifyingKey,
///      ) -> Result<(), Self::Error> {
///         if self.index >= self.list.len() {
///             return Err(());
///         }
///         self.list[self.index] = object;
///         self.nuls.push(old_nul);
///         self.index += 1;
///         Ok(())
///      }
/// }
///
/// ```
///
/// This static list now keeps track of nullifiers to implement `has_never_received_nul`. The
/// static list has a maximum capacity of 10 new user objects (so `num_users * total_interactions <=
/// 10`). Additionally, an index is used to append a value into this list.
///
/// This builds on the example implementation in [`PublicUserBul`].
pub trait UserBul<F: PrimeField + Absorb, U: UserData<F>>: PublicUserBul<F, U> {
    /// An error type.
    type Error;

    /// Check whether the bulletin has received a nullifier (when appending a value) before. If it has, return false, and
    /// otherwise return true.
    fn has_never_received_nul(&self, nul: &Nul<F>) -> bool;

    /// Append a user object into the bulletin.
    ///
    /// This function should not do any checking. It will append the user object, nullifier, and
    /// optionally any extra data to the user bulletin.
    ///
    /// If the user bulletin is a SQL database, then this could insert an entry into the database.
    ///
    /// The optional extra data allows any user or other service to verify the interaction proof
    /// anytime in the future, which can be used if there are multiple services.
    ///
    /// # Arguments
    ///- `&mut self`: The user bulletin.
    ///- `old_nul`: The old nullifier.
    ///- `cb_com_list`: A list of commitments to callbacks added.
    ///- `args`: The public arguments of the method applied in the interaction.
    ///- `proof`: The proof of correctness given by the interaction.
    ///- `memb_data`: Membership data for the **prior** object. If the membership data **is
    ///constant**, this should be passed in as `None`, as the membership data is already loaded in
    ///the key. Otherwise, this should be the membership data for the prior object (on which the
    ///interaction was applied).
    ///- `verif_key`: The verification key to verify the proof (this should be the key generated
    ///from the interaction, which encodes the predicate circuit).
    #[allow(clippy::too_many_arguments)]
    fn append_value<PubArgs: ToConstraintField<F>, Snark: SNARK<F>, const NUMCBS: usize>(
        &mut self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        args: PubArgs,
        proof: Snark::Proof,
        memb_data: Option<Self::MembershipPub>, // membership for the PREVIOUS object, meant to verify the proof: NOT membership for current object
        verif_key: &Snark::VerifyingKey,
    ) -> Result<(), Self::Error>;

    /// Given a new user object and proof, this verifies the proof that the new user object
    /// respects the interaction.
    ///
    /// This function verifies the proof by the user and checks that the nullifier has never been
    /// previously seen. This proof is verified with respect to the `verif_key` given from the
    /// interaction keys.
    ///
    /// # Arguments
    ///- `&self`: The user bulletin.
    ///- `old_nul`: The old nullifier.
    ///- `args`: The public arguments of the method applied in the interaction.
    ///- `cb_com_list`: A list of commitments to callbacks added.
    ///- `proof`: The proof of correctness given by the interaction.
    ///- `memb_data`: Membership data for the **prior** object. If the membership data **is
    ///constant**, this should be passed in as `None`, as the membership data is already loaded in
    ///the key. Otherwise, this should be the membership data for the prior object (on which the
    ///interaction was applied).
    ///- `verif_key`: The verification key to verify the proof (this should be the key generated
    ///from the interaction, which encodes the predicate circuit).
    #[allow(clippy::too_many_arguments)]
    fn verify_interaction<PubArgs: ToConstraintField<F>, Snark: SNARK<F>, const NUMCBS: usize>(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        args: PubArgs,
        cb_com_list: [Com<F>; NUMCBS],
        proof: Snark::Proof,
        memb_data: Option<Self::MembershipPub>,
        verif_key: &Snark::VerifyingKey,
    ) -> bool {
        if !self.has_never_received_nul(&old_nul) {
            return false;
        }

        let mut pub_inputs = vec![object, old_nul];
        pub_inputs.extend::<Vec<F>>(args.to_field_elements().unwrap());
        pub_inputs.extend::<Vec<F>>(cb_com_list.to_field_elements().unwrap());
        if let Some(a) = memb_data {
            pub_inputs.extend::<Vec<F>>(a.to_field_elements().unwrap());
        }

        let out = Snark::verify(verif_key, &pub_inputs, &proof);

        out.unwrap_or(false)
    }

    /// Verifies a user's interaction and appends the new object to the bulletin.
    ///
    ///# Example
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
    /// # use zk_callbacks::generic::bulletin::UserBul;
    /// # use zk_callbacks::generic::object::Time;
    /// # use zk_callbacks::generic::object::TimeVar;
    /// # use ark_relations::r1cs::SynthesisError;
    /// # use zk_callbacks::generic::user::UserVar;
    /// # use ark_r1cs_std::fields::fp::FpVar;
    /// # use ark_groth16::Groth16;
    /// # use ark_r1cs_std::prelude::Boolean;
    /// # use zk_callbacks::impls::hash::Poseidon;
    /// # use ark_r1cs_std::prelude::UInt8;
    /// # use zk_callbacks::impls::dummy::DummyStore;
    /// # use ark_r1cs_std::select::CondSelectGadget;
    /// # use zk_callbacks::impls::centralized::crypto::{FakeSigPubkey, NoSigOTP};
    /// # type Groth = Groth16<E>;
    /// #[zk_object(Fr)]
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
    ///     let int = Interaction {
    ///         meth: (method, predicate),
    ///         callbacks: [cb.clone()],
    ///     };
    ///
    ///     let mut rng = thread_rng();
    ///
    ///     let (pk, vk) = int.generate_keys::<Poseidon<2>, Groth, NoSigOTP<Fr>, DummyStore>(&mut rng, Some(()), None, false);
    ///
    ///     let mut u = User::create(Data { bad_rep: 0, num_visits: Fr::from(0), last_interacted_time: Time::from(0) }, &mut rng);
    ///
    ///     let exec_meth = u.interact::<Poseidon<2>, Time<Fr>, TimeVar<Fr>, (), (), Fr, FpVar<Fr>, NoSigOTP<Fr>, Groth, DummyStore, 1>(&mut rng, int.clone(), [FakeSigPubkey::pk()], Time::from(20), ((), ()), true, &pk, Time::from(20), (), false).unwrap();
    ///
    ///     let out = <DummyStore as UserBul<Fr, Data>>::verify_interact_and_append::<Time<Fr>, Groth, 1>(
    ///         &mut DummyStore,
    ///         exec_meth.new_object.clone(),
    ///         exec_meth.old_nullifier.clone(),
    ///         Time::from(20),
    ///         exec_meth.cb_com_list.clone(),
    ///         exec_meth.proof.clone(),
    ///         None,
    ///         &vk
    ///     );
    ///
    ///     assert!(out.is_ok())
    /// }
    /// ```
    #[allow(clippy::too_many_arguments)]
    fn verify_interact_and_append<
        PubArgs: ToConstraintField<F> + Clone,
        Snark: SNARK<F>,
        const NUMCBS: usize,
    >(
        &mut self,
        object: Com<F>,
        old_nul: Nul<F>,
        args: PubArgs,
        cb_com_list: [Com<F>; NUMCBS],
        proof: Snark::Proof,
        memb_data: Option<Self::MembershipPub>,
        verif_key: &Snark::VerifyingKey,
    ) -> Result<(), BulError<Self::Error>> {
        let out = self.verify_interaction::<PubArgs, Snark, NUMCBS>(
            object,
            old_nul,
            args.clone(),
            cb_com_list,
            proof.clone(),
            memb_data.clone(),
            verif_key,
        );

        if !out {
            return Err(BulError::VerifyError);
        }

        self.append_value::<PubArgs, Snark, NUMCBS>(
            object,
            old_nul,
            cb_com_list,
            args,
            proof,
            memb_data,
            verif_key,
        )
        .map_err(BulError::AppendError)?;

        Ok(())
    }
}

/// Methods which users can perform by viewing a public callback bulletin.
///
/// This trait allows for users to verify membership an nonmembership of callback tickets (with
/// arguments) within a bulletin. Additionally, it allows for a user to prove membership or
/// nonmembership using [`PublicCallbackBul::enforce_membership_of`] and
/// [`PublicCallbackBul::enforce_nonmembership_of`].
///
/// This could be a network handle to a site containing a list of callback tickets.
///
/// # Example (Static List)
///
/// In this example, the bulletin is a static list of 10 callback tickets. To prove membership (or
/// nonmembership), one
/// loops through the whole list and checks that one of them is equal to the commitment (or none of
/// them are equal).
///
/// ```rust
/// # use ark_bls12_381::Fr;
/// # use zk_callbacks::generic::object::{Com, ComVar};
/// # use zk_callbacks::generic::bulletin::PublicUserBul;
/// # use ark_relations::r1cs::{SynthesisError, Namespace};
/// # use ark_r1cs_std::prelude::AllocationMode;
/// # use ark_relations::ns;
/// # use ark_r1cs_std::alloc::AllocVar;
/// # use ark_relations::r1cs::ToConstraintField;
/// # use ark_snark::SNARK;
/// # use zk_callbacks::generic::object::TimeVar;
/// # use ark_r1cs_std::fields::fp::FpVar;
/// # use zk_callbacks::impls::centralized::crypto::FakeSigPubkeyVar;
/// # use zk_callbacks::generic::object::Nul;
/// # use zk_callbacks::scannable_zk_object;
/// # use zk_callbacks::generic::bulletin::PublicCallbackBul;
/// # use ark_r1cs_std::prelude::Boolean;
/// # use zk_callbacks::generic::object::Time;
/// # use zk_callbacks::impls::centralized::crypto::FakeSigPubkey;
/// # use zk_callbacks::impls::centralized::crypto::NoSigOTP;
/// # use ark_r1cs_std::eq::EqGadget;
/// #[scannable_zk_object(Fr)]
/// struct Data {
///     pub token: Fr
/// }
///
/// #[derive(Clone, Default)]
/// struct StaticList {
///     pub tiks: [FakeSigPubkey<Fr>; 10],
///     pub args: [Fr; 10],
///     pub times: [Time<Fr>; 10],
/// }
///
/// #[derive(Clone)]
/// struct StaticListVar {
///     pub tiks: [FakeSigPubkeyVar<Fr>; 10],
///     pub args: [FpVar<Fr>; 10],
///     pub times: [TimeVar<Fr>; 10],
/// }
/// # impl AllocVar<StaticList, Fr> for StaticListVar {
/// #    fn new_variable<T: std::borrow::Borrow<StaticList>>(
/// #        cs: impl Into<Namespace<Fr>>,
/// #        f: impl FnOnce() -> Result<T, SynthesisError>,
/// #        mode: AllocationMode
/// #    ) -> Result<Self, SynthesisError> {
/// #        let ns = cs.into();
/// #        let cs = ns.cs();
/// #        let res = f();
/// #        res.and_then(|rec| {
/// #            let rec = rec.borrow();
/// #            let tiks = Vec::<FakeSigPubkeyVar<Fr>>::new_variable(ns!(cs, "tiks"), || Ok(rec.tiks.clone()), mode)?;
/// #            let args = Vec::<FpVar<Fr>>::new_variable(ns!(cs, "args"), || Ok(rec.args.clone()), mode)?;
/// #            let times = Vec::<TimeVar<Fr>>::new_variable(ns!(cs, "times"), || Ok(rec.times.clone()), mode)?;
/// #            Ok(Self {
/// #                tiks: tiks.try_into().unwrap_or_else(|_| panic!("oops")),
/// #                args: args.try_into().unwrap_or_else(|_| panic!("oops")),
/// #                times: times.try_into().unwrap_or_else(|_| panic!("oops"))
/// #            })
/// #        })
/// #    }
/// # }
/// # impl ToConstraintField<Fr> for StaticList {
/// #   fn to_field_elements(&self) -> Option<Vec<Fr>> {
/// #       Some(self.tiks.to_vec().into_iter().map(|x| x.to()).collect::<Vec<_>>())
/// #   }
/// # }
///
/// impl PublicCallbackBul<Fr, Fr, NoSigOTP<Fr>> for StaticList {
///
///     type MembershipWitness = ();
///
///     type MembershipWitnessVar = ();
///
///     type MembershipPub = StaticList;
///
///     type MembershipPubVar = StaticListVar;
///
///     type NonMembershipWitness = ();
///     
///     type NonMembershipWitnessVar = ();
///
///     type NonMembershipPub = StaticList;
///
///     type NonMembershipPubVar = StaticListVar;
///
///     fn verify_in(&self, tik: FakeSigPubkey<Fr>) -> Option<(Fr, Time<Fr>)> {
///         let x = self.tiks.contains(&tik);
///         match x {
///             false => None,
///             true => {
///                 let ind = self.tiks.iter().position(|x| *x == tik).unwrap();
///                 Some((self.args[ind], self.times[ind]))
///             }
///         }
///     }
///
///     fn verify_not_in(&self, tik: FakeSigPubkey<Fr>) -> bool {
///         !self.tiks.contains(&tik)
///     }
///
///     fn get_membership_data(&self, _tik: FakeSigPubkey<Fr>) -> (StaticList, (), StaticList, ()) {
///         (self.clone(), (), self.clone(), ())
///     }
///
///     fn enforce_membership_of(tikvar: (FakeSigPubkeyVar<Fr>, FpVar<Fr>, TimeVar<Fr>), ewit: (), epub: StaticListVar) -> Result<Boolean<Fr>, SynthesisError> {
///         let mut b = Boolean::FALSE;
///         for i in 0..10 {
///             b = b | (tikvar.0.0.is_eq(&epub.tiks[i].0)? & tikvar.1.is_eq(&epub.args[i])? & tikvar.2.is_eq(&epub.times[i])?);
///         }
///         Ok(b)
///     }
///
///     fn enforce_nonmembership_of(tikvar: FakeSigPubkeyVar<Fr>, ewit: (), epub: StaticListVar) -> Result<Boolean<Fr>, SynthesisError> {
///         let mut b = Boolean::TRUE;
///         for i in 0..10 {
///             b = b & tikvar.0.is_neq(&epub.tiks[i].0)?;
///         }
///         Ok(b)
///     }
///
/// }
/// ```
/// # Example
/// Additionally, similar to the [`PublicUserBul`], we may also have a network handle get the list
/// from some server.
///
/// ```rust
/// # use ark_bls12_381::Fr;
/// # use zk_callbacks::generic::object::{Com, ComVar};
/// # use zk_callbacks::generic::bulletin::PublicUserBul;
/// # use ark_relations::r1cs::{SynthesisError, Namespace};
/// # use ark_r1cs_std::prelude::AllocationMode;
/// # use ark_relations::ns;
/// # use ark_r1cs_std::alloc::AllocVar;
/// # use ark_relations::r1cs::ToConstraintField;
/// # use ark_snark::SNARK;
/// # use zk_callbacks::generic::object::TimeVar;
/// # use ark_r1cs_std::fields::fp::FpVar;
/// # use zk_callbacks::impls::centralized::crypto::FakeSigPubkeyVar;
/// # use zk_callbacks::generic::object::Nul;
/// # use zk_callbacks::scannable_zk_object;
/// # use zk_callbacks::generic::bulletin::PublicCallbackBul;
/// # use ark_r1cs_std::prelude::Boolean;
/// # use zk_callbacks::generic::object::Time;
/// # use zk_callbacks::impls::centralized::crypto::FakeSigPubkey;
/// # use zk_callbacks::impls::centralized::crypto::NoSigOTP;
/// # use ark_r1cs_std::eq::EqGadget;
/// #[scannable_zk_object(Fr)]
/// struct Data {
///     pub token: Fr
/// }
/// # #[derive(Clone, Default)]
/// # struct Session {
/// # }
/// #
/// # impl Session {
/// #   fn fetch_list_from(&self, url: &str) -> Result<StaticList, &'static str> {
/// #       todo!()
/// #   }
/// # }
/// # #[derive(Clone, Default)]
/// # struct StaticList {
/// #     pub tiks: [FakeSigPubkey<Fr>; 10],
/// #     pub args: [Fr; 10],
/// #     pub times: [Time<Fr>; 10],
/// # }
///
/// # #[derive(Clone)]
/// # struct StaticListVar {
/// #     pub tiks: [FakeSigPubkeyVar<Fr>; 10],
/// #     pub args: [FpVar<Fr>; 10],
/// #     pub times: [TimeVar<Fr>; 10],
/// # }
/// # impl AllocVar<StaticList, Fr> for StaticListVar {
/// #    fn new_variable<T: std::borrow::Borrow<StaticList>>(
/// #        cs: impl Into<Namespace<Fr>>,
/// #        f: impl FnOnce() -> Result<T, SynthesisError>,
/// #        mode: AllocationMode
/// #    ) -> Result<Self, SynthesisError> {
/// #        let ns = cs.into();
/// #        let cs = ns.cs();
/// #        let res = f();
/// #        res.and_then(|rec| {
/// #            let rec = rec.borrow();
/// #            let tiks = Vec::<FakeSigPubkeyVar<Fr>>::new_variable(ns!(cs, "tiks"), || Ok(rec.tiks.clone()), mode)?;
/// #            let args = Vec::<FpVar<Fr>>::new_variable(ns!(cs, "args"), || Ok(rec.args.clone()), mode)?;
/// #            let times = Vec::<TimeVar<Fr>>::new_variable(ns!(cs, "times"), || Ok(rec.times.clone()), mode)?;
/// #            Ok(Self {
/// #                tiks: tiks.try_into().unwrap_or_else(|_| panic!("oops")),
/// #                args: args.try_into().unwrap_or_else(|_| panic!("oops")),
/// #                times: times.try_into().unwrap_or_else(|_| panic!("oops"))
/// #            })
/// #        })
/// #    }
/// # }
/// # impl ToConstraintField<Fr> for StaticList {
/// #   fn to_field_elements(&self) -> Option<Vec<Fr>> {
/// #       Some(self.tiks.to_vec().into_iter().map(|x| x.to()).collect::<Vec<_>>())
/// #   }
/// # }
/// impl PublicCallbackBul<Fr, Fr, NoSigOTP<Fr>> for Session {
///
///     type MembershipWitness = ();
///
///     type MembershipWitnessVar = ();
///
///     type MembershipPub = StaticList;
///
///     type MembershipPubVar = StaticListVar;
///
///     type NonMembershipWitness = ();
///
///     type NonMembershipWitnessVar = ();
///
///     type NonMembershipPub = StaticList;
///
///     type NonMembershipPubVar = StaticListVar;
///
///     fn verify_in(&self, tik: FakeSigPubkey<Fr>) -> Option<(Fr, Time<Fr>)> {
///         let list = self.fetch_list_from("http://example.com/pubcbbul").unwrap();
///         let x = list.tiks.contains(&tik);
///         match x {
///             false => None,
///             true => {
///                 let ind = list.tiks.iter().position(|x| *x == tik).unwrap();
///                 Some((list.args[ind], list.times[ind]))
///             }
///         }
///     }
///
///     fn verify_not_in(&self, tik: FakeSigPubkey<Fr>) -> bool {
///         let list = self.fetch_list_from("http://example.com/pubcbbul").unwrap();
///         !list.tiks.contains(&tik)
///     }
///
///     fn get_membership_data(&self, _tik: FakeSigPubkey<Fr>) -> (StaticList, (), StaticList, ()) {
///         let sl = self.fetch_list_from("http://example.com/pubcbbul").unwrap();
///         (sl.clone(), (), sl.clone(), ())
///     }
///
///     fn enforce_membership_of(tikvar: (FakeSigPubkeyVar<Fr>, FpVar<Fr>, TimeVar<Fr>), ewit: (), epub: StaticListVar) -> Result<Boolean<Fr>, SynthesisError> {
///         let mut b = Boolean::FALSE;
///         for i in 0..10 {
///             b = b | (tikvar.0.0.is_eq(&epub.tiks[i].0)? & tikvar.1.is_eq(&epub.args[i])? & tikvar.2.is_eq(&epub.times[i])?);
///         }
///         Ok(b)
///     }
///
///     fn enforce_nonmembership_of(tikvar: FakeSigPubkeyVar<Fr>, ewit: (), epub: StaticListVar) -> Result<Boolean<Fr>, SynthesisError> {
///         let mut b = Boolean::TRUE;
///         for i in 0..10 {
///             b = b & tikvar.0.is_neq(&epub.tiks[i].0)?;
///         }
///         Ok(b)
///     }
///
/// }
///
/// ```
pub trait PublicCallbackBul<F: PrimeField, CBArgs: Clone, Crypto: AECipherSigZK<F, CBArgs>> {
    /// The witness for callback ticket membership. For example, a Merkle path.
    type MembershipWitness: Clone;
    /// The in-circuit representation of the witness for membership.
    type MembershipWitnessVar: Clone + AllocVar<Self::MembershipWitness, F>;
    /// The witness for callback ticket nonmembership. For example, A Merkle complement tree path,
    /// or a Merkle trie path.
    type NonMembershipWitness: Clone;
    /// The in-circuit representation for callback ticket nonmembership.
    type NonMembershipWitnessVar: Clone + AllocVar<Self::NonMembershipWitness, F>;

    /// The public data for callback ticket membership (for example, the root).
    type MembershipPub: Clone;

    /// The public membership data in-circuit.
    type MembershipPubVar: Clone + AllocVar<Self::MembershipPub, F>;
    /// The public data for callback ticket nonmembership.
    type NonMembershipPub: Clone;
    /// The public nonmembership data in-circuit.
    type NonMembershipPubVar: Clone + AllocVar<Self::NonMembershipPub, F>;

    /// Verify that a callback ticket is in the bulletin.
    ///
    /// If the callback ticket is contained within the bulletin, this function will also return the
    /// ciphertext and time when the ticket was posted (or the callback was called).
    ///
    /// This function returns None if the callback ticket is not in the bulletin.
    fn verify_in(&self, tik: Crypto::SigPK) -> Option<(Crypto::Ct, Crypto::Sig, Time<F>)>;

    /// Checks whether a ticket is not contained in the bulletin (has not been called).
    fn verify_not_in(&self, tik: Crypto::SigPK) -> bool;

    /// Given a ticket, get the membership data associated to that ticket.
    ///
    /// If the ticket is contained in the bulletin, then `Self::NonMembershipPub` and
    /// `Self::NonMembershipWitness` can be anything (could be garbage, or a default value).
    ///
    /// If the ticket is not contained in the bulletin, then `Self::MembershipPub` and
    /// `Self::MembershipWitness` can be anything (could be garbage, or a default value).
    fn get_membership_data(
        &self,
        tik: Crypto::SigPK,
    ) -> (
        Self::MembershipPub,
        Self::MembershipWitness,
        Self::NonMembershipPub,
        Self::NonMembershipWitness,
    );

    /// Prove membership of a (ticket, arguments, time) tuple in the callback bulletin in-circuit.
    ///
    /// Given a ticket and membership witness and public data, return `true` if the ticket data is in
    /// the bulletin, and `false` otherwise.
    fn enforce_membership_of(
        tikvar: (
            Crypto::SigPKV,
            <Crypto::EncKey as CPACipher<F>>::CV,
            TimeVar<F>,
        ),
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError>;

    /// Prove nonmembership of a ticket in the callback bulletin in-circuit.
    ///
    /// Given a ticket and nonmembership witness and public data, return `true` if the ticket is not in
    /// the bulletin, and `false` otherwise.
    fn enforce_nonmembership_of(
        tikvar: Crypto::SigPKV,
        extra_witness: Self::NonMembershipWitnessVar,
        extra_pub: Self::NonMembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError>;

    /// Enforces a ticket is either a member of the bulletin or not. Returns true if the ticket is a
    /// member, and false if not.
    fn enforce_memb_nmemb(
        tikvar: (
            Crypto::SigPKV,
            <Crypto::EncKey as CPACipher<F>>::CV,
            TimeVar<F>,
        ),
        ewitness: (Self::MembershipWitnessVar, Self::NonMembershipWitnessVar),
        epub: (Self::MembershipPubVar, Self::NonMembershipPubVar),
    ) -> Result<Boolean<F>, SynthesisError> {
        let b2 = Self::enforce_nonmembership_of(tikvar.0.clone(), ewitness.1, epub.1)?;
        let b1 = Self::enforce_membership_of(tikvar, ewitness.0, epub.0)?;
        let o = b1.is_neq(&b2)?;
        o.enforce_equal(&Boolean::TRUE)?;
        Ok(b1)
    }
}

/// A callback bulletin.
///
/// This represents a callback bulletin. While the [`PublicCallbackBul`] contains functions users
/// can perform by *viewing* the bulletin, this traits encompasses **the bulletin** itself, which
/// includes appending and verifying new tickets.
///
/// Note that **this gives the freedom of a backend**. For example, one may implement
/// [`CallbackBul`] via an SQL database. Alternatively, in the decentralized setting, one may
/// abstract away the consensus layer and "append" a new value to the Merkle tree by performing
/// some consensus protocol.
///
/// # Example (Static List)
///
/// This example builds on top of the example given in [`PublicCallbackBul`]. The bulletin is a
/// static list of 10 tickets. To prove membership, one loops through the whole list and checks
/// that one of them is equal to the commitment. Alternatively, to prove nonmembership, one loops
/// through the whole list and checks that none of them are equal.
///
/// ```rust
/// # use ark_bls12_381::Fr;
/// # use zk_callbacks::generic::object::{Com, ComVar};
/// # use zk_callbacks::generic::bulletin::PublicUserBul;
/// # use ark_relations::r1cs::{SynthesisError, Namespace};
/// # use ark_r1cs_std::prelude::AllocationMode;
/// # use ark_relations::ns;
/// # use ark_r1cs_std::alloc::AllocVar;
/// # use ark_relations::r1cs::ToConstraintField;
/// # use ark_snark::SNARK;
/// # use zk_callbacks::generic::object::TimeVar;
/// # use ark_r1cs_std::fields::fp::FpVar;
/// # use zk_callbacks::impls::centralized::crypto::FakeSigPubkeyVar;
/// # use zk_callbacks::generic::object::Nul;
/// # use zk_callbacks::scannable_zk_object;
/// # use zk_callbacks::generic::bulletin::PublicCallbackBul;
/// # use ark_r1cs_std::prelude::Boolean;
/// # use zk_callbacks::generic::object::Time;
/// # use zk_callbacks::impls::centralized::crypto::FakeSigPubkey;
/// # use zk_callbacks::impls::centralized::crypto::NoSigOTP;
/// # use zk_callbacks::generic::bulletin::CallbackBul;
/// # use ark_r1cs_std::eq::EqGadget;
/// #[scannable_zk_object(Fr)]
/// struct Data {
///     pub token: Fr
/// }
///
/// #[derive(Clone, Default)]
/// struct StaticList {
///     pub tiks: [FakeSigPubkey<Fr>; 10],
///     pub args: [Fr; 10],
///     pub times: [Time<Fr>; 10],
///     pub index: usize,
/// }
///
/// #[derive(Clone)]
/// struct StaticListVar {
///     pub tiks: [FakeSigPubkeyVar<Fr>; 10],
///     pub args: [FpVar<Fr>; 10],
///     pub times: [TimeVar<Fr>; 10],
/// }
/// # impl AllocVar<StaticList, Fr> for StaticListVar {
/// #    fn new_variable<T: std::borrow::Borrow<StaticList>>(
/// #        cs: impl Into<Namespace<Fr>>,
/// #        f: impl FnOnce() -> Result<T, SynthesisError>,
/// #        mode: AllocationMode
/// #    ) -> Result<Self, SynthesisError> {
/// #        let ns = cs.into();
/// #        let cs = ns.cs();
/// #        let res = f();
/// #        res.and_then(|rec| {
/// #            let rec = rec.borrow();
/// #            let tiks = Vec::<FakeSigPubkeyVar<Fr>>::new_variable(ns!(cs, "tiks"), || Ok(rec.tiks.clone()), mode)?;
/// #            let args = Vec::<FpVar<Fr>>::new_variable(ns!(cs, "args"), || Ok(rec.args.clone()), mode)?;
/// #            let times = Vec::<TimeVar<Fr>>::new_variable(ns!(cs, "times"), || Ok(rec.times.clone()), mode)?;
/// #            Ok(Self {
/// #                tiks: tiks.try_into().unwrap_or_else(|_| panic!("oops")),
/// #                args: args.try_into().unwrap_or_else(|_| panic!("oops")),
/// #                times: times.try_into().unwrap_or_else(|_| panic!("oops"))
/// #            })
/// #        })
/// #    }
/// # }
/// # impl ToConstraintField<Fr> for StaticList {
/// #   fn to_field_elements(&self) -> Option<Vec<Fr>> {
/// #       Some(self.tiks.to_vec().into_iter().map(|x| x.to()).collect::<Vec<_>>())
/// #   }
/// # }
/// #
/// # impl PublicCallbackBul<Fr, Fr, NoSigOTP<Fr>> for StaticList {
/// #     type MembershipWitness = ();
/// #     type MembershipWitnessVar = ();
/// #     type MembershipPub = StaticList;
/// #     type MembershipPubVar = StaticListVar;
/// #     type NonMembershipWitness = ();
/// #
/// #     type NonMembershipWitnessVar = ();
/// #     type NonMembershipPub = StaticList;
/// #     type NonMembershipPubVar = StaticListVar;
/// #     fn verify_in(&self, tik: FakeSigPubkey<Fr>) -> Option<(Fr, Time<Fr>)> {
/// #         let x = self.tiks.contains(&tik);
/// #         match x {
/// #             false => None,
/// #             true => {
/// #                 let ind = self.tiks.iter().position(|x| *x == tik).unwrap();
/// #                 Some((self.args[ind], self.times[ind]))
/// #             }
/// #         }
/// #     }
/// #     fn verify_not_in(&self, tik: FakeSigPubkey<Fr>) -> bool {
/// #         !self.tiks.contains(&tik)
/// #     }
/// #     fn get_membership_data(&self, _tik: FakeSigPubkey<Fr>) -> (StaticList, (), StaticList, ()) {
/// #         (self.clone(), (), self.clone(), ())
/// #     }
/// #     fn enforce_membership_of(tikvar: (FakeSigPubkeyVar<Fr>, FpVar<Fr>, TimeVar<Fr>), ewit: (), epub: StaticListVar) -> Result<Boolean<Fr>, SynthesisError> {
/// #         let mut b = Boolean::FALSE;
/// #         for i in 0..10 {
/// #             b = b | (tikvar.0.0.is_eq(&epub.tiks[i].0)? & tikvar.1.is_eq(&epub.args[i])? & tikvar.2.is_eq(&epub.times[i])?);
/// #         }
/// #         Ok(b)
/// #     }
/// #     fn enforce_nonmembership_of(tikvar: FakeSigPubkeyVar<Fr>, ewit: (), epub: StaticListVar) -> Result<Boolean<Fr>, SynthesisError> {
/// #         let mut b = Boolean::TRUE;
/// #         for i in 0..10 {
/// #             b = b & tikvar.0.is_neq(&epub.tiks[i].0)?;
/// #         }
/// #         Ok(b)
/// #     }
/// # }
///
/// impl CallbackBul<Fr, Fr, NoSigOTP<Fr>> for StaticList {
///     type Error = ();
///
///     fn has_never_received_tik(&self, tik: &FakeSigPubkey<Fr>) -> bool {
///         !self.tiks.contains(&tik)
///     }
///
///     fn append_value(&mut self, tik: FakeSigPubkey<Fr>, args: Fr, sig: (), time: Time<Fr>) -> Result<(), Self::Error> {
///         self.tiks[self.index] = tik;
///         self.args[self.index] = args;
///         self.times[self.index] = time;
///         self.index += 1;
///         Ok(())
///     }
/// }
/// ```
pub trait CallbackBul<F: PrimeField, CBArgs: Clone, Crypto: AECipherSigZK<F, CBArgs>>:
    PublicCallbackBul<F, CBArgs, Crypto>
{
    /// An error type.
    type Error;

    /// Check whether the bulletin has received a ticket before. If it has, return false, and otherwise
    /// return true.
    fn has_never_received_tik(&self, tik: &Crypto::SigPK) -> bool;

    /// Append a new ticket into the bulletin.
    ///
    /// This function should not do any checking. It will append the ticket, arguments, and service
    /// signature to the public callback bulletin.
    ///
    /// If the callback bulletin is an SQL database, then this could insert an entry into the database.
    ///
    /// # Arguments
    ///- `&mut self`: The callback bulletin.
    ///- `tik`: The ticket a service provider wants to call.
    ///- `enc_args`: The encrypted arguments provided by the service provider.
    ///- `signature`: The signature on the encrypted arguments proving authenticity of the service.
    ///- `time`: The time the callback was called.
    fn append_value(
        &mut self,
        tik: Crypto::SigPK,
        enc_args: Crypto::Ct,
        signature: Crypto::Sig,
        time: Time<F>,
    ) -> Result<(), Self::Error>;

    /// Verifies a ticket call.
    ///
    /// Checks if the ticket is new (has not been called before), and additionally checks the signature
    /// with the ticket and arguments.
    fn verify_call(
        &self,
        tik: Crypto::SigPK,
        enc_args: Crypto::Ct,
        signature: Crypto::Sig,
    ) -> bool {
        if !self.has_never_received_tik(&tik) {
            return false;
        }
        tik.verify(enc_args.clone(), signature)
    }

    /// Verify the ticket being appended to the callback bulletin, and then append it.
    fn verify_call_and_append(
        &mut self,
        tik: Crypto::SigPK,
        enc_args: Crypto::Ct,
        signature: Crypto::Sig,
        time: Time<F>,
    ) -> Result<(), BulError<Self::Error>> {
        let out = self.verify_call(tik.clone(), enc_args.clone(), signature.clone());

        if !out {
            return Err(BulError::VerifyError);
        }

        self.append_value(tik, enc_args, signature, time)
            .map_err(BulError::AppendError)?;

        Ok(())
    }
}

/// A bulletin where a user can also join.
///
/// To add a user, some extra data can be provided alongside a new committed user. If the extra
/// data passes some check, then the committed user should be added to the bulletin.
///
/// For example, one can add users to a bulletin given that they can produce a proof of email, and
/// generate the commitment randomness from that email.
///
/// Another example is using a proof of phone number and generating a nonce deterministically.
pub trait JoinableBulletin<F: PrimeField + Absorb, U: UserData<F>>: UserBul<F, U> {
    /// Can be any type.
    ///
    /// For example, some struct containing auxiliary data and a proof.
    type PubData;

    /// Decide and append a new user object to a bulletin based on some public data.
    fn join_bul(&mut self, object: Com<F>, pub_data: Self::PubData) -> Result<(), Self::Error>;
}
