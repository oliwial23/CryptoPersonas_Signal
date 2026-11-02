use crate::{
    crypto::{enc::AECipherSigZK, hash::FieldHash, rr::RRSigner},
    generic::{
        bulletin::{BulError, PublicUserBul},
        callbacks::CallbackCom,
        interaction::Callback,
        object::Time,
        user::{ExecutedMethod, UserData},
    },
};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::alloc::AllocVar;
use ark_snark::SNARK;

/// A called callback.
///
/// This consists of
/// - A ticket (which is a rerandomized public key).
/// - A ciphertext (which are the encrypted arguments passed into the callback).
/// - A signature (signed by the service).
pub type Called<F, A, Crypto> = (
    <Crypto as AECipherSigZK<F, A>>::SigPK,
    <Crypto as AECipherSigZK<F, A>>::Ct,
    <Crypto as AECipherSigZK<F, A>>::Sig,
);

/// Functions which are called by service providers within the callbacks system.
///
/// When users interact with service providers, they provide proofs of method execution and
/// callbacks. The service may then "call" a callback by posting a called callback on a
/// [`CallbackBul`](`super::bulletin::CallbackBul`).
///
/// For example, a user may edit a page on Wikipedia. To do so, the user provides a proof by
/// calling [`interact`](`super::user::User::interact`) on their user and producing a proof. This
/// proof is then handed to the service, along with some interaction data (the page edit, an
/// interaction id, etc.)
///
/// The service provider will then check this interaction and the proof, and store it. The service
/// provider trait provides an
/// [`approve_interaction_and_store`](`ServiceProvider::approve_interaction_and_store`) function to
/// do this.
///
/// Along with this, a service provider may call a callback through
/// [`call`](`ServiceProvider::call`). The output data may then be sent to any callback bulletin to
/// post.
///
/// # Example
///
/// In this example, we have a post id associated to any post on the anonymous forum, as well as a
/// set of callbacks provided to the server when a user makes a post.
///
/// To call a callback, the server may pick which interaction they want to update the user's
/// reputation on, pop that interaction id and cb_ticket, and then run `call` on that callback
/// ticket with some argument.
///
/// ```rust
/// # use ark_bls12_381::Fr;
/// # use zk_callbacks::impls::centralized::crypto::{FakeSigPubkey, NoSigOTP};
/// # use ark_snark::SNARK;
/// # use zk_callbacks::generic::service::ServiceProvider;
/// # use zk_callbacks::generic::user::UserData;
/// # use zk_callbacks::generic::user::ExecutedMethod;
/// # use zk_callbacks::crypto::enc::AECipherSigZK;
/// # use zk_callbacks::generic::callbacks::CallbackCom;
/// # use ark_r1cs_std::fields::fp::FpVar;
/// type CB = CallbackCom<Fr, Fr, NoSigOTP<Fr>>;
/// type SigRand = <NoSigOTP<Fr> as AECipherSigZK<Fr, Fr>>::Rand;
///
/// pub struct AnonForum {
///     pub interaction_ids: Vec<u64>,
///     pub cb_tickets: Vec<Vec<(CB, SigRand)>>,
/// }
///
/// impl ServiceProvider<Fr, Fr, FpVar<Fr>, NoSigOTP<Fr>> for AnonForum {
///     type Error = ();
///     type InteractionData = u64;
///
///     fn has_never_received_tik(&self, tik: FakeSigPubkey<Fr>) -> bool {
///         for j in &self.cb_tickets {
///             for (a, _) in j {
///                 if a.cb_entry.tik == tik {
///                     return false;
///                 }
///             }
///         }
///         true
///     }
///
///     fn store_interaction<U: UserData<Fr>, Snark: SNARK<Fr>, const NUMCBS: usize>(&mut self, interaction: ExecutedMethod<Fr, Snark, Fr, NoSigOTP<Fr>, NUMCBS>, data: u64) -> Result<(), Self::Error> {
///         self.interaction_ids.push(data);
///         self.cb_tickets.push(interaction.cb_tik_list.to_vec());
///         Ok(())
///     }
/// }
/// ```
pub trait ServiceProvider<
    F: PrimeField + Absorb,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs>,
>
{
    /// An error type.
    type Error;

    /// The data associated with an interaction outside of the cryptography. For example, this may
    /// be an interaction id, or an edit made to a page, or a post.
    type InteractionData;

    /// Calls a callback, producing called data which must be provided to the callback bulletin.
    ///
    /// Given a specific ticket (which might be associated to a specific interaction), the service
    /// may then call the ticket with some arguments, to produce a "called" result. This data can
    /// then be appended to the callback bulletin.
    ///
    /// For example, if Reddit needs to moderate a specific post, after viewing the post with a
    /// specific id, if it is bad, they may choose to then call a callback and deduct some karma
    /// from the user which posted.
    fn call(
        &self,
        ticket: CallbackCom<F, CBArgs, Crypto>,
        arguments: CBArgs,
        sk: Crypto::SigSK,
    ) -> Result<Called<F, CBArgs, Crypto>, Self::Error> {
        let (enc, sig) = Crypto::encrypt_and_sign(arguments, ticket.cb_entry.enc_key, sk);
        Ok((ticket.cb_entry.tik, enc, sig))
    }

    /// Check if the service has ever received a specific ticket before, as otherwise a service may
    /// receive overlapping callbacks.
    fn has_never_received_tik(&self, ticket: Crypto::SigPK) -> bool;

    /// Store a specific interaction, which includes the callbacks along with the interaction data,
    /// and optionally the proof as well.
    ///
    /// In the decentralized setting, a service provider may also
    /// store the proof to later cross-verify with the user bulletin.
    fn store_interaction<U: UserData<F>, Snark: SNARK<F>, const NUMCBS: usize>(
        &mut self,
        interaction: ExecutedMethod<F, Snark, CBArgs, Crypto, NUMCBS>,
        data: Self::InteractionData,
    ) -> Result<(), Self::Error>;

    /// Given an interaction, this function checks if the interaction is approved.
    ///
    /// In other words, this function verifies the proof given by the user. Specifically, it
    /// verifies that
    ///- The *new* user is contained within the user bulletin. (Note that this means the new
    ///updated user must be in the bulletin before calling this)
    ///- None of the tickets were previously received.
    ///- The proof is correct.
    ///
    /// # Arguments
    ///
    /// - `&self`: The service provider.
    /// - `interaction_request`: The interaction requested by the user (contains all the data for
    /// the proof).
    /// - `sk`: The secret signature key used by the service provider to call callbacks.
    /// - `args`: The public arguments passed to the interaction method `meth(U, args) -> U'`
    /// - `bul`: The user bulletin in which the user is contained.
    /// - `memb_data`: Public data associated to membership within the bulletin. For example, it
    /// may be a Merkle root, or a signature public key.
    /// - `is_memb_data_const`: Is the public memebership data constant. Determines whether to load
    /// the data as constant or as an input in-circuit.
    /// - `verif_key`: The verification key for the SNARK proof. Generated by calling
    /// [`Interaction::generate_keys`](`super::interaction::Interaction::generate_keys`). Note that
    /// if the membership data is constant, the keys *must* be generated that way.
    fn approve_interaction<
        U: UserData<F>,
        Snark: SNARK<F>,
        PubArgs: Clone + ToConstraintField<F>,
        Bul: PublicUserBul<F, U>,
        H: FieldHash<F>,
        const NUMCBS: usize,
    >(
        &self,
        interaction_request: &ExecutedMethod<F, Snark, CBArgs, Crypto, NUMCBS>,
        sk: Crypto::SigSK,
        args: PubArgs,
        bul: &Bul,
        cb_list: Vec<Callback<F, U, CBArgs, CBArgsVar>>,
        cur_time: Time<F>,
        memb_data: Bul::MembershipPub,
        is_memb_data_const: bool,
        verif_key: &Snark::VerifyingKey,
    ) -> bool {
        let out = bul.verify_in::<PubArgs, Snark, NUMCBS>(
            interaction_request.new_object,
            interaction_request.old_nullifier,
            interaction_request.cb_com_list,
            args.clone(),
            interaction_request.proof.clone(),
            memb_data.clone(),
            verif_key,
        );
        if !out {
            return false;
        }

        for i in 0..NUMCBS {
            let cb = interaction_request.cb_tik_list[i].0.clone();

            if cb.cb_entry.expirable != cb_list[i].expirable {
                return false;
            }

            if cb.cb_entry.expiration != cb_list[i].expiration + cur_time {
                return false;
            }

            if cb.cb_entry.cb_method_id != cb_list[i].method_id {
                return false;
            }

            let cb_com = interaction_request.cb_com_list[i].clone();

            if cb_com != CallbackCom::commit::<H>(&cb) {
                return false;
            }

            let rand = interaction_request.cb_tik_list[i].1.clone();
            let vpk = sk.rerand(rand).sk_to_pk();
            if vpk != cb.cb_entry.tik {
                return false;
            }

            if !self.has_never_received_tik(cb.cb_entry.tik) {
                return false;
            }
        }

        let mut pub_inputs = vec![
            interaction_request.new_object,
            interaction_request.old_nullifier,
        ];
        pub_inputs.extend::<Vec<F>>(args.to_field_elements().unwrap());
        pub_inputs.extend::<Vec<F>>(interaction_request.cb_com_list.to_field_elements().unwrap());
        if !is_memb_data_const {
            pub_inputs.extend(memb_data.to_field_elements().unwrap());
        }
        Snark::verify(verif_key, &pub_inputs, &interaction_request.proof).unwrap_or(false)
    }

    /// Approves an interaction, as well as stores it.
    ///
    /// # Example
    /// ```rust
    /// # use zk_callbacks::zk_object;
    /// # use zk_callbacks::generic::user::User;
    /// # use rand::thread_rng;
    /// # use ark_r1cs_std::eq::EqGadget;
    /// # use zk_callbacks::generic::interaction::Interaction;
    /// # use zk_callbacks::generic::interaction::Callback;
    /// # use zk_callbacks::generic::object::Id;
    /// # use zk_callbacks::generic::object::Time;
    /// # use ark_relations::r1cs::SynthesisError;
    /// # use zk_callbacks::generic::user::UserVar;
    /// # use ark_r1cs_std::fields::fp::FpVar;
    /// # use ark_groth16::Groth16;
    /// # use ark_r1cs_std::prelude::Boolean;
    /// # use zk_callbacks::impls::hash::Poseidon;
    /// # use zk_callbacks::impls::dummy::DummyStore;
    /// # use zk_callbacks::impls::centralized::crypto::{FakeSigPrivkey, FakeSigPubkey, NoSigOTP};
    /// # use ark_bls12_381::{Bls12_381 as E, Fr};
    /// # type Groth = Groth16<E>;
    /// # use ark_snark::SNARK;
    /// # use zk_callbacks::generic::service::ServiceProvider;
    /// # use zk_callbacks::generic::user::UserData;
    /// # use zk_callbacks::generic::user::ExecutedMethod;
    /// # use zk_callbacks::crypto::enc::AECipherSigZK;
    /// # use zk_callbacks::generic::callbacks::CallbackCom;
    /// type CB = CallbackCom<Fr, Fr, NoSigOTP<Fr>>;
    /// type SigRand = <NoSigOTP<Fr> as AECipherSigZK<Fr, Fr>>::Rand;
    ///
    /// pub struct AnonForum {
    ///     pub interaction_ids: Vec<u64>,
    ///     pub cb_tickets: Vec<Vec<(CB, SigRand)>>,
    /// }
    ///
    /// impl ServiceProvider<Fr, Fr, FpVar<Fr>, NoSigOTP<Fr>> for AnonForum {
    ///     type Error = ();
    ///     type InteractionData = u64;
    ///
    ///     fn has_never_received_tik(&self, tik: FakeSigPubkey<Fr>) -> bool {
    ///         for j in &self.cb_tickets {
    ///             for (a, _) in j {
    ///                 if a.cb_entry.tik == tik {
    ///                     return false;
    ///                 }
    ///             }
    ///         }
    ///         true
    ///     }
    ///
    ///     fn store_interaction<U: UserData<Fr>, Snark: SNARK<Fr>, const NUMCBS: usize>(&mut self, interaction: ExecutedMethod<Fr, Snark, Fr, NoSigOTP<Fr>, NUMCBS>, data: u64) -> Result<(), Self::Error> {
    ///         self.interaction_ids.push(data);
    ///         self.cb_tickets.push(interaction.cb_tik_list.to_vec());
    ///         Ok(())
    ///     }
    /// }
    ///
    /// #[zk_object(Fr)]
    /// #[derive(Default)]
    /// struct Data {
    ///     karma: Fr,
    ///     is_banned: bool,
    /// }
    ///#
    ///#  fn method<'a>(old_user: &'a User<Fr, Data>, _pub: (), _priv: ()) -> User<Fr, Data> {
    ///#      old_user.clone()
    ///#  }
    ///#
    ///#  fn predicate<'a>(old_user: &'a UserVar<Fr, Data>, new_user: &'a UserVar<Fr, Data>, _pub: (), _priv: ()) -> Result<Boolean<Fr>, SynthesisError> {
    ///#      let o1 = old_user.data.karma.is_eq(&new_user.data.karma)?;
    ///#      let o2 = old_user.data.is_banned.is_eq(&new_user.data.is_banned)?;
    ///#      Ok(o1 & o2)
    ///#  }
    ///#
    ///#  fn callback<'a>(old_user: &'a User<Fr, Data>, args: Fr) -> User<Fr, Data> {
    ///#      let mut u = old_user.clone();
    ///#      u.data.karma = args;
    ///#      u
    ///#  }
    ///#
    ///#  fn enforce_callback<'a>(old_user: &'a UserVar<Fr, Data>, args: FpVar<Fr>) -> Result<UserVar<Fr, Data>, SynthesisError> {
    ///#      let mut u = old_user.clone();
    ///#      u.data.karma = args;
    ///#      Ok(u)
    ///#  }
    ///#
    ///#
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
    ///     let mut forum = AnonForum {
    ///         interaction_ids: vec![],
    ///         cb_tickets: vec![],
    ///     };
    ///
    ///     let cb_methods = vec![cb];
    ///
    ///     let mut dummy = DummyStore;
    ///
    ///     let mut rng = thread_rng();
    ///
    ///     let (pk, vk) = int.generate_keys::<Poseidon<2>, Groth, NoSigOTP<Fr>, DummyStore>(&mut rng, Some(()), None, false);
    ///
    ///     let mut u = User::create(Data { karma: Fr::from(0), is_banned: false }, &mut rng);
    ///
    ///     let exec_meth = u.exec_method_create_cb::<Poseidon<2>, _, _, _, _, _, _, NoSigOTP<Fr>, Groth, DummyStore, 1>(&mut rng, int.clone(), [FakeSigPubkey::pk()], Time::from(0), &DummyStore, true, &pk, (), ()).unwrap();
    ///
    ///     forum.approve_interaction_and_store::<Data, _, _, _, Poseidon<2>, 1>(exec_meth, FakeSigPrivkey::sk(), (), &dummy, cb_methods, Time::from(0), (), true, &vk, 727).unwrap();
    ///
    /// }
    /// ```
    fn approve_interaction_and_store<
        U: UserData<F>,
        Snark: SNARK<F>,
        PubArgs: Clone + ToConstraintField<F>,
        Bul: PublicUserBul<F, U>,
        H: FieldHash<F>,
        const NUMCBS: usize,
    >(
        &mut self,
        interaction_request: ExecutedMethod<F, Snark, CBArgs, Crypto, NUMCBS>,
        sk: Crypto::SigSK,
        args: PubArgs,
        bul: &Bul,
        cb_list: Vec<Callback<F, U, CBArgs, CBArgsVar>>,
        cur_time: Time<F>,
        memb_data: Bul::MembershipPub,
        is_memb_data_const: bool,
        verif_key: &Snark::VerifyingKey,
        data: Self::InteractionData,
    ) -> Result<(), BulError<Self::Error>> {
        let out = self.approve_interaction::<U, Snark, PubArgs, Bul, H, NUMCBS>(
            &interaction_request,
            sk,
            args,
            bul,
            cb_list,
            cur_time,
            memb_data,
            is_memb_data_const,
            verif_key,
        );

        if !out {
            return Err(BulError::VerifyError);
        }

        self.store_interaction::<U, Snark, NUMCBS>(interaction_request, data)
            .map_err(BulError::AppendError)
    }
}
