#[cfg(any(feature = "folding", doc))]
#[cfg(feature = "folding")]
use crate::generic::fold::{FoldInput, Rerand, RerandVar};
#[cfg(any(feature = "folding", doc))]
#[cfg(feature = "folding")]
use crate::generic::object::{ComRand, ComRandVar};
use crate::{
    crypto::{enc::AECipherSigZK, hash::FieldHash, rr::RRVerifier},
    generic::{
        bulletin::{PublicCallbackBul, PublicUserBul},
        callbacks::{CallbackCom, add_ticket_to_hc, create_cbs_from_interaction},
        interaction::{
            ExecMethodCircuit, Interaction, ProvePredInCircuit, ProvePredicateCircuit,
            SingularPredicate,
        },
        object::{Com, ComVar, Nul, Ser, SerVar, Time, ZKFields, ZKFieldsVar},
        scan::{PrivScanArgs, PrivScanArgsVar, PubScanArgs, PubScanArgsVar, get_scan_interaction},
    },
};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    eq::EqGadget,
    prelude::CondSelectGadget,
};
use ark_relations::{
    ns,
    r1cs::{
        ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, Namespace, SynthesisError,
    },
};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate,
};
use ark_snark::SNARK;
use rand::{CryptoRng, Rng, RngCore, distributions::Standard, prelude::Distribution};
use std::{
    borrow::Borrow,
    io::{Read, Write},
};

use crate::generic::interaction::Callback;

/// A trait that captures data which can be placed inside a user.
///
/// For any system, one needs to have some state associated with the user. Any struct implementing
/// this trait can be used as user state within an anonymous reputation system. The standard
/// example consists of a user with a single bit indicating if such a user is banned.
///
/// # Example (Banned Bit)
///
/// To capture the single bit, we can use a `bool`. Therefore, the struct will look something like
/// this:
///
/// ```rust
/// struct Data {
///     pub ban_status: bool,
/// }
/// ```
/// Now, we may implement AllocVar for this object, converting the `ban_status` to a `Boolean`
/// representation in-circuit. Totally, it will look something like this:
///
/// ```rust
/// # use ark_ff::ToConstraintField;
/// # use ark_ff::PrimeField;
/// # use ark_r1cs_std::prelude::UInt8;
/// # use rand::distributions::Standard;
/// # use rand::prelude::Distribution;
/// # use zk_callbacks::crypto::enc::CPACipher;
/// # use ark_r1cs_std::prelude::AllocationMode;
/// # use ark_relations::r1cs::SynthesisError;
/// # use std::borrow::Borrow;
/// # use ark_relations::r1cs::Namespace;
/// # use ark_r1cs_std::prelude::AllocVar;
/// # use ark_r1cs_std::prelude::Boolean;
/// # use ark_relations::ns;
/// # use ark_r1cs_std::fields::fp::FpVar;
/// # use ark_r1cs_std::convert::ToConstraintFieldGadget;
/// # use ark_r1cs_std::convert::ToBitsGadget;
/// # use rand::{Rng, RngCore, CryptoRng};
/// #[derive(Clone, PartialEq, Eq, Debug)]
/// struct Data {
///     pub ban_status: bool,
/// }
///
/// #[derive(Clone)]
/// struct DataVar<F: PrimeField> {
///     pub ban_status: Boolean<F>
/// }
///
/// impl<F: PrimeField> AllocVar<Data, F> for DataVar<F> {
///   fn new_variable<T: Borrow<Data>>(
///       cs: impl Into<Namespace<F>>,
///       f: impl FnOnce() -> Result<T, SynthesisError>,
///       mode: AllocationMode
/// ) -> Result<Self, SynthesisError> {
///       let ns = cs.into();
///       let cs = ns.cs();
///       let res = f();
///       res.and_then(|rec| {
///           let rec = rec.borrow();
///           let t = Boolean::new_variable(ns!(cs, "ban_status"), || Ok(rec.ban_status), mode)?;
///           Ok(Self { ban_status: t } )
///       })
/// }
/// }
/// ```
///
/// Finally, we can implement `UserData` by serializing the elements using `to_constraint_field`.
///
/// ```rust
/// # use ark_ff::ToConstraintField;
/// # use ark_ff::PrimeField;
/// # use ark_r1cs_std::prelude::UInt8;
/// # use rand::distributions::Standard;
/// # use rand::prelude::Distribution;
/// # use zk_callbacks::crypto::enc::CPACipher;
/// # use ark_r1cs_std::prelude::AllocationMode;
/// # use ark_relations::r1cs::SynthesisError;
/// # use std::borrow::Borrow;
/// # use ark_relations::r1cs::Namespace;
/// # use ark_r1cs_std::prelude::AllocVar;
/// # use ark_r1cs_std::prelude::Boolean;
/// # use ark_relations::ns;
/// # use ark_r1cs_std::fields::fp::FpVar;
/// # use ark_r1cs_std::convert::ToConstraintFieldGadget;
/// # use ark_r1cs_std::convert::ToBitsGadget;
/// # use zk_callbacks::generic::object::{Ser, SerVar};
/// # use ark_crypto_primitives::sponge::Absorb;
/// # use zk_callbacks::generic::user::UserData;
/// # use rand::{Rng, RngCore, CryptoRng};
/// # #[derive(Clone, PartialEq, Eq, Debug)]
/// # struct Data {
/// #     pub ban_status: bool,
/// # }
/// # #[derive(Clone)]
/// # struct DataVar<F: PrimeField> {
/// #     pub ban_status: Boolean<F>
/// # }
/// # impl<F: PrimeField> AllocVar<Data, F> for DataVar<F> {
/// #   fn new_variable<T: Borrow<Data>>(
/// #       cs: impl Into<Namespace<F>>,
/// #       f: impl FnOnce() -> Result<T, SynthesisError>,
/// #       mode: AllocationMode
/// # ) -> Result<Self, SynthesisError> {
/// #       let ns = cs.into();
/// #       let cs = ns.cs();
/// #       let res = f();
/// #       res.and_then(|rec| {
/// #           let rec = rec.borrow();
/// #           let t = Boolean::new_variable(ns!(cs, "ban_status"), || Ok(rec.ban_status), mode)?;
/// #           Ok(Self { ban_status: t } )
/// #       })
/// # }
/// # }
/// impl<F: PrimeField + Absorb> UserData<F> for Data {
///     type UserDataVar = DataVar<F>;
///
///     fn serialize_elements(&self) -> Vec<Ser<F>> {
///         let mut buf = Vec::new();
///         buf.extend_from_slice(&self.ban_status.to_field_elements().unwrap());
///         buf
///     }
///
///     fn serialize_in_zk(user_var: DataVar<F>) -> Result<Vec<SerVar<F>>, SynthesisError> {
///         let mut buf = Vec::new();
///         buf.extend_from_slice(&user_var.ban_status.to_constraint_field()?);
///         Ok(buf)
///     }
/// }
/// ```
/// With this, we may now define a user object. To do this, we use the [`User`] struct, see the
/// documentation for more details on how to use the user.
/// ```rust
/// # use ark_ff::ToConstraintField;
/// # use ark_ff::PrimeField;
/// # use ark_r1cs_std::prelude::UInt8;
/// # use rand::distributions::Standard;
/// # use rand::prelude::Distribution;
/// # use zk_callbacks::crypto::enc::CPACipher;
/// # use ark_r1cs_std::prelude::AllocationMode;
/// # use ark_relations::r1cs::SynthesisError;
/// # use std::borrow::Borrow;
/// # use ark_relations::r1cs::Namespace;
/// # use ark_r1cs_std::prelude::AllocVar;
/// # use ark_r1cs_std::prelude::Boolean;
/// # use ark_relations::ns;
/// # use ark_r1cs_std::fields::fp::FpVar;
/// # use ark_r1cs_std::convert::ToConstraintFieldGadget;
/// # use ark_r1cs_std::convert::ToBitsGadget;
/// # use zk_callbacks::generic::object::{Ser, SerVar};
/// # use ark_crypto_primitives::sponge::Absorb;
/// # use zk_callbacks::generic::user::UserData;
/// # use rand::{Rng, RngCore, CryptoRng};
/// # use rand::thread_rng;
/// # use zk_callbacks::generic::user::User;
/// # #[derive(Clone, PartialEq, Eq, Debug)]
/// # struct Data {
/// #     pub ban_status: bool,
/// # }
/// # #[derive(Clone)]
/// # struct DataVar<F: PrimeField> {
/// #     pub ban_status: Boolean<F>
/// # }
/// # impl<F: PrimeField> AllocVar<Data, F> for DataVar<F> {
/// #   fn new_variable<T: Borrow<Data>>(
/// #       cs: impl Into<Namespace<F>>,
/// #       f: impl FnOnce() -> Result<T, SynthesisError>,
/// #       mode: AllocationMode
/// # ) -> Result<Self, SynthesisError> {
/// #       let ns = cs.into();
/// #       let cs = ns.cs();
/// #       let res = f();
/// #       res.and_then(|rec| {
/// #           let rec = rec.borrow();
/// #           let t = Boolean::new_variable(ns!(cs, "ban_status"), || Ok(rec.ban_status), mode)?;
/// #           Ok(Self { ban_status: t } )
/// #       })
/// # }
/// # }
/// # impl<F: PrimeField + Absorb> UserData<F> for Data {
/// #     type UserDataVar = DataVar<F>;
/// #     fn serialize_elements(&self) -> Vec<Ser<F>> {
/// #         let mut buf = Vec::new();
/// #         buf.extend_from_slice(&self.ban_status.to_field_elements().unwrap());
/// #         buf
/// #     }
/// #     fn serialize_in_zk(user_var: DataVar<F>) -> Result<Vec<SerVar<F>>, SynthesisError> {
/// #         let mut buf = Vec::new();
/// #         buf.extend_from_slice(&user_var.ban_status.to_constraint_field()?);
/// #         Ok(buf)
/// #     }
/// # }
/// # use ark_bn254::{Fr as F};
/// # fn main() {
///     let mut rng = thread_rng();
///     let test_data = Data { ban_status: false };
///     let u: User<F, Data> = User::create(test_data, &mut rng);
/// # }
/// ```
///
/// # Example (Reputation)
///
/// For a more complex example, we may take an example where a user has more complex state; for
/// example, a reputation or karma score. Then a user struct will look like the following:
///
/// ```rust
/// # use ark_bn254::Fr;
/// struct Data {
///     karma: Fr,
///     is_banned: bool,
/// }
/// ```
/// where `F` is a field element from a choice field (bls12 or bn254 scalar fields, for example).
///
/// To make the implementation process easier, we may simply implement `UserData` using the
/// [`zk_object`] macro. This macro allows us to auto implement `UserData` along with defining an
/// in-circuit struct representation for the Data. This way, we can easily do the following:
///
/// ```rust
/// use zk_callbacks::zk_object;
/// use ark_bn254::Fr;
///
/// #[zk_object(Fr)]
/// #[derive(Default)]
/// struct Data {
///     karma: Fr,
///     is_banned: bool,
/// }
/// ```
///
/// As both `F` and `bool` implement UserData already, we may use the macro to implement
/// `UserData`. We may then use this in a similar manner to the previous example in a `User`
/// struct.
pub trait UserData<F: PrimeField + Absorb>: Clone + Eq + std::fmt::Debug {
    /// The in circuit representation of the user data.
    type UserDataVar: AllocVar<Self, F> + Clone;

    /// How to serialize the data of the user into a canonical representation of field elements.
    /// This is necessary so users can be committed to.
    fn serialize_elements(&self) -> Vec<Ser<F>>;

    /// Convert the data of the user into a serialized vector of field elements in-circuit.
    fn serialize_in_zk(user_var: Self::UserDataVar) -> Result<Vec<SerVar<F>>, SynthesisError>;
}

/// Struct representing the whole user object.
///
/// This struct consists of user data (which implements [`UserData`]), along with other data. The
/// user object consists of extra fields contained in `zk_fields`, along with a list of outstanding
/// callbacks (stored in `callbacks`), which are also encoded within the `zk_fields`.
///
/// Note that user implements `AllocVar`, which converts data and the zk_fields into an allocated
/// in-circuit representation, so proofs can be made for the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User<F: PrimeField + Absorb, U: UserData<F>> {
    /// Any data stored within the user. Can be a banned status, reputation, or more.
    pub data: U,

    /// Consists of extra fields used within proofs: commitment randomness, nullifiers, and more.
    /// For all intents and purposes (unless dealing with advanced usage), this may be ignored.
    pub zk_fields: ZKFields<F>,

    /// A list of callbacks, serialized and stored. This may also be ignored (the [`User::get_cb`]
    /// function should be used instead.
    pub(crate) callbacks: Vec<Vec<u8>>,

    pub(crate) scan_index: Option<usize>,

    pub(crate) in_progress_cbs: Vec<Vec<u8>>,
}

impl<F: PrimeField + Absorb, U: UserData<F> + Default> Default for User<F, U> {
    fn default() -> Self {
        Self {
            data: U::default(),
            zk_fields: ZKFields::default(),
            callbacks: vec![],
            scan_index: None,
            in_progress_cbs: vec![],
        }
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>> CanonicalSerialize for User<F, U>
where
    U: CanonicalSerialize,
{
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.data.serialize_with_mode(&mut writer, compress)?;
        self.zk_fields.serialize_with_mode(&mut writer, compress)?;
        self.callbacks.serialize_with_mode(&mut writer, compress)?;
        self.scan_index.serialize_with_mode(&mut writer, compress)?;
        self.in_progress_cbs
            .serialize_with_mode(&mut writer, compress)?;

        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.data.serialized_size(compress)
            + self.zk_fields.serialized_size(compress)
            + self.callbacks.serialized_size(compress)
            + self.scan_index.serialized_size(compress)
            + self.in_progress_cbs.serialized_size(compress)
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>> Valid for User<F, U>
where
    U: Valid,
{
    fn check(&self) -> Result<(), SerializationError> {
        self.data.check()?;
        self.zk_fields.check()?;
        self.callbacks.check()?;
        self.scan_index.check()?;
        self.in_progress_cbs.check()?;
        Ok(())
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>> CanonicalDeserialize for User<F, U>
where
    U: CanonicalDeserialize,
{
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let data = <U>::deserialize_with_mode(&mut reader, compress, validate)?;
        let zk_fields = ZKFields::deserialize_with_mode(&mut reader, compress, validate)?;
        let callbacks = <Vec<Vec<u8>>>::deserialize_with_mode(&mut reader, compress, validate)?;
        let scan_index = <Option<usize>>::deserialize_with_mode(&mut reader, compress, validate)?;
        let in_progress_cbs =
            <Vec<Vec<u8>>>::deserialize_with_mode(&mut reader, compress, validate)?;
        Ok(User {
            data,
            zk_fields,
            callbacks,
            scan_index,
            in_progress_cbs,
        })
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>> std::fmt::Octal for User<F, U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[U: {} callbacks, ingesting: {}]",
            self.callbacks.len(),
            !self.zk_fields.is_ingest_over
        )
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>> std::fmt::Display for User<F, U>
where
    U: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.data,)
    }
}

/// In-circuit representation of the user object.
///
/// Consists of both user data in circuit, along with the extra zero knowledge fields.
#[derive(Clone, Debug)]
pub struct UserVar<F: PrimeField + Absorb, U: UserData<F>> {
    /// User data, in-circuit.
    pub data: U::UserDataVar,
    /// Zero knowledge fields (nullifier, nonce, etc.) in circuit.
    pub zk_fields: ZKFieldsVar<F>,
}

impl<F: PrimeField + Absorb, U: UserData<F>> CondSelectGadget<F> for UserVar<F, U>
where
    U::UserDataVar: CondSelectGadget<F>,
{
    fn conditionally_select(
        cond: &ark_r1cs_std::prelude::Boolean<F>,
        true_value: &Self,
        false_value: &Self,
    ) -> Result<Self, SynthesisError> {
        let d = U::UserDataVar::conditionally_select(cond, &true_value.data, &false_value.data)?;
        let zkf = <ZKFieldsVar<F>>::conditionally_select(
            cond,
            &true_value.zk_fields,
            &false_value.zk_fields,
        )?;
        Ok(Self {
            data: d,
            zk_fields: zkf,
        })
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>> AllocVar<User<F, U>, F> for UserVar<F, U> {
    fn new_variable<T: Borrow<User<F, U>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();

        res.and_then(|rec| {
            let rec = rec.borrow();
            let data =
                U::UserDataVar::new_variable(ns!(cs, "data"), || Ok(rec.data.clone()), mode)?;
            let zk_fields = ZKFieldsVar::new_variable(
                ns!(cs, "zk_fields"),
                || Ok(rec.zk_fields.clone()),
                mode,
            )?;
            Ok(UserVar { data, zk_fields })
        })
    }
}

/// Output data after a method has been executed on a user.
///
/// When a user executes a method, it must prove correctness of execution. To do so, the user
/// publicly reveals the old nullifier and constructs a new object with a random nullifier.
/// Additionally, the user may have to append some callbacks.
///
/// On execution, the user will output data, such that the user may prove that
///* A prior user object existed in the storage structure
///* Some statement is enforced across the old and new objects: p(U, U') = 1
///
/// To verify the proof, some additional data is necessary, which is provided by this struct.
/// Additionally, on method execution the user also maintains a list of callback tickets, this list
/// may be handed to the service provider.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ExecutedMethod<
    F: PrimeField + Absorb,
    Snark: SNARK<F>,
    CBArgs: Clone,
    Crypto: AECipherSigZK<F, CBArgs>,
    const NUMCBS: usize,
> {
    /// A *commitment* to new object after the method update: Com(U') where U' = f(U)
    pub new_object: Com<F>,
    /// The nullifier of the old user, to ensure past users aren't being reused.
    pub old_nullifier: Nul<F>,
    /// A list of callback tickets added to the user from the interaction.
    pub cb_tik_list: [(CallbackCom<F, CBArgs, Crypto>, Crypto::Rand); NUMCBS],
    /// A list of commitments to the tickets added to the user.
    pub cb_com_list: [Com<F>; NUMCBS],
    /// The current time. This should be validated.
    pub cur_time: Time<F>,
    /// Proof of valid user object update.
    pub proof: Snark::Proof,
}

/// Output data after a proof is made on the user object.
///
/// If one wants to make a standard proof for a user object, this struct captures the data
/// necessary to make such a statement. Note that this is **not necessarily anonymous**, as it
/// reveals the current object *commitment*. This struct is the output which is obtained after an
/// arbitrary proof *about* the user is created.
///
/// If you want to make a proof about the user object while remaining anonymous within some set,
/// you must prove membership of your object along with the statement; this can be done with
/// [`User::prove_statement_and_in`]. This struct is meant for just making statements, and is used
/// with [`User::prove_statement`].
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProveResult<F: PrimeField + Absorb, S: SNARK<F>> {
    /// The current user commitment.
    pub object: Com<F>,
    /// The proof of some statement on the user.
    pub proof: S::Proof,
}

impl<F: PrimeField + Absorb, U: UserData<F>> User<F, U>
where
    Standard: Distribution<F>,
{
    /// Create a new user from some user data with zero callbacks.
    ///
    /// # Example
    /// ```rust
    /// # use zk_callbacks::zk_object;
    /// # use zk_callbacks::generic::user::User;
    /// # use rand::thread_rng;
    /// # use ark_bn254::Fr;
    /// #[zk_object(Fr)]
    /// #[derive(Default)]
    /// struct Data {
    ///     karma: Fr,
    ///     is_banned: bool,
    /// }
    ///
    /// fn main () {
    ///     let mut rng = thread_rng();
    ///     let mut u = User::create(Data { karma: Fr::from(0), is_banned: false }, &mut rng);
    /// }
    /// ```
    ///
    /// Here, `u` is a single user object, with all the data associated to it.
    pub fn create(user: U, rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self {
            data: user,
            zk_fields: ZKFields {
                nul: rng.r#gen(),
                com_rand: rng.r#gen(),
                callback_hash: F::zero(),
                new_in_progress_callback_hash: F::zero(),
                old_in_progress_callback_hash: F::zero(),
                is_ingest_over: true,
            },
            callbacks: vec![],
            scan_index: None,
            in_progress_cbs: vec![],
        }
    }

    /// Gets the i-th callback stored within the user. If this callback does not exist, this
    /// function will panic.
    ///
    /// # Example
    /// ```rust
    /// # use zk_callbacks::zk_object;
    /// # use zk_callbacks::generic::user::User;
    /// # use rand::thread_rng;
    /// # use ark_bn254::{Bn254 as E, Fr};
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
    /// # use zk_callbacks::impls::centralized::crypto::{FakeSigPubkey, NoSigOTP};
    /// # type Groth = Groth16<E>;
    ///#  #[zk_object(Fr)]
    ///#  #[derive(Default)]
    ///#  struct Data {
    ///#      karma: Fr,
    ///#      is_banned: bool,
    ///#  }
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
    ///     let mut u = User::create(Data { karma: Fr::from(0), is_banned: false }, &mut rng);
    ///
    ///     // Execute the method, and append a single callback to the user callback list. This
    ///     // callback is a ticket associated to `cb`.
    ///     let _ = u.exec_method_create_cb::<Poseidon<2>, _, _, _, _, _, _, NoSigOTP<Fr>, Groth, DummyStore, 1>(&mut rng, int.clone(), [FakeSigPubkey::pk()], Time::from(0), &DummyStore, true, &pk, (), ()).unwrap();
    ///
    ///     // Get the first callback stored in the user.
    ///     let first_callback = u.get_cb
    ///         ::<Fr, NoSigOTP<Fr>>
    ///     (0);
    ///
    ///     // Ensure the callback is the correct callback method.
    ///     assert_eq!(first_callback.cb_entry.cb_method_id, cb.method_id);
    /// }
    /// ```
    pub fn get_cb<Args: Clone, Crypto: AECipherSigZK<F, Args>>(
        &self,
        index: usize,
    ) -> CallbackCom<F, Args, Crypto> {
        CallbackCom::deserialize_compressed(&*self.callbacks[index]).unwrap()
    }

    /// Get the total number of callbacks stored within the user object.
    ///
    /// These are the outstanding callbacks which have been handed to some service.
    pub fn num_outstanding_callbacks(&self) -> usize {
        self.callbacks.len()
    }

    /// Get the user scanning status.
    pub fn is_scanning(&self) -> bool {
        self.scan_index.is_some()
    }

    /// Gets the scan index. This should not be used unless you know what you are doing.
    pub fn get_scan_index(&self) -> Option<usize> {
        self.scan_index
    }

    /// Force set the scan index. This should not be used unless you know what you are doing.
    pub fn force_set_scan_index(&mut self, data: usize) {
        self.scan_index = Some(data)
    }

    /// Force clear the scan index. This should not be used unless you know what you are doing.
    pub fn force_clear_scan_index(&mut self) {
        self.scan_index = None
    }

    /// Gets the arguments for a scan.
    pub fn get_scan_arguments<
        CBArgs: Clone + std::fmt::Debug + PartialEq + Eq,
        CBArgsVar: AllocVar<CBArgs, F> + Clone,
        Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar> + PartialEq + Eq,
        CBul: PublicCallbackBul<F, CBArgs, Crypto> + Clone,
        const NUMSCANS: usize,
    >(
        &mut self,
        cbul: &CBul,
        is_memb_nmemb_const: (bool, bool),
        cur_time: Time<F>,
        cb_methods: Vec<Callback<F, U, CBArgs, CBArgsVar>>,
    ) -> (
        PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS>,
        PrivScanArgs<F, CBArgs, Crypto, CBul, NUMSCANS>,
    ) {
        let start_ind = match self.scan_index {
            Some(ind) => {
                assert!(NUMSCANS + ind <= self.callbacks.len());
                ind
            }
            None => {
                assert!(NUMSCANS <= self.callbacks.len());
                0
            }
        };

        let mut vec_cbs = vec![];
        let mut vec_memb_pub = vec![];
        let mut vec_nmemb_pub = vec![];
        let mut vec_memb_priv = vec![];
        let mut vec_nmemb_priv = vec![];
        let mut vec_enc = vec![];
        let mut vec_times = vec![];

        for i in 0..NUMSCANS {
            let cb: CallbackCom<F, CBArgs, Crypto> = self.get_cb::<CBArgs, Crypto>(start_ind + i);
            let data = cbul.get_membership_data(cb.get_ticket());
            let if_in = cbul.verify_in(cb.get_ticket());
            let (enc, sig, time) = match if_in {
                Some((e, s, t)) => (e, s, t),
                None => (
                    Crypto::Ct::default(),
                    Crypto::Sig::default(),
                    Time::default(),
                ),
            };

            assert!(
                <Crypto as AECipherSigZK<F, CBArgs>>::SigPK::verify(
                    &cb.get_ticket(),
                    enc.clone(),
                    sig
                ) == true
            );

            vec_enc.push(enc);
            vec_times.push(time);
            vec_cbs.push(cb);
            vec_memb_pub.push(data.0);
            vec_memb_priv.push(data.1);
            vec_nmemb_pub.push(data.2);
            vec_nmemb_priv.push(data.3);
        }

        let ps: PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS> = PubScanArgs {
            memb_pub: vec_memb_pub
                .try_into()
                .unwrap_or_else(|_| panic!("Unexpected failure.")),
            nmemb_pub: vec_nmemb_pub
                .try_into()
                .unwrap_or_else(|_| panic!("Unexpected failure.")),
            bulletin: cbul.clone(),
            is_memb_data_const: is_memb_nmemb_const.0,
            is_nmemb_data_const: is_memb_nmemb_const.1,
            cur_time,
            cb_methods,
        };

        let prs: PrivScanArgs<F, CBArgs, Crypto, CBul, NUMSCANS> = PrivScanArgs {
            priv_n_tickets: vec_cbs.try_into().unwrap(),
            post_times: vec_times.try_into().unwrap(),
            enc_args: vec_enc
                .try_into()
                .unwrap_or_else(|_| panic!("Unexpected failure.")),
            memb_priv: vec_memb_priv
                .try_into()
                .unwrap_or_else(|_| panic!("Unexpected failure.")),
            nmemb_priv: vec_nmemb_priv
                .try_into()
                .unwrap_or_else(|_| panic!("Unexpected failure.")),
        };

        (ps, prs)
    }

    /// Execute a method, add on callbacks, and produce a proof to a server.
    ///
    /// # Note
    ///
    /// Note that for most scenarios, [`exec_method_create_cb`](`User::exec_method_create_cb`) and
    /// [`scan_callbacks`](`User::scan_callbacks`) will be
    /// enough. These are specialized versions of `interact`, which are **safe; they perform additional safeguard checks**. If possible use these
    /// functions.
    ///
    /// # Description
    ///
    /// This is the main function of interest in zk_callbacks, which allows a user to "interact"
    /// with a server. When a user interacts (by making a post, editing a page, etc.), the user
    /// will produce a proof to the service, which the service verifies.
    ///
    /// To do so, the user first executes a method `U -> U'`, and then produces a proof of
    ///* `pred(U, U', args) == 1`
    ///* `U` is in the user bulletin
    ///* The callback tickets [cb, ... cb] have been appended to the user
    ///
    /// A simple example interaction can be the following:
    ///* Method: `new_user.visits_per_day = old_user.visits_per_day + 1`
    ///* Predicate: `new_user.visits_per_day == old_user.visits_per_day + 1
    ///&& new_user.reputation == old_user.reputation
    ///&& new_user.reputation > 50`
    ///* A single callback: `user.reputation += args`
    ///
    ///Every time a user goes to make a post on a website, it first increases its visits per day,
    ///and then produces a proof that it has a proper reputation and has increased the number of
    ///visits. Finally, the user hands a callback ticket to the website to update the reputation.
    ///
    /// This function takes in an [`Interaction`] and produces the [`ExecutedMethod`] output, which
    /// contains the proof, callbacks to give to the service, new updated user commitment to give
    /// to the bulletin, and auxiliary proof data (nullifier, callback commitments).
    ///
    /// # Generics
    ///- `H`: the hash used for commitments. For example, it may be Poseidon or Sha256.
    ///- `PubArgs`: The public arguments provided to the method.
    ///- `PubArgsVar`: In-circuit representation of the public arguments, provided to the
    ///predicate.
    ///- `PrivArgs`: The private arguments provided to the method.
    ///- `PrivArgsVar`: In-circuit representation of the private arguments, provided to the
    ///predicate.
    ///- `CBArgs`: The public arguments provided to the callback function `cb(U, CBArgs) -> U`
    ///- `CBArgsVar`: The in-circuit representation of the public arguments provided to the
    ///callback function, which are enforced by the callback predicate.
    ///- `Crypto`: Authenticated encryption, which provides authenticity and confidentiality for
    ///called callbacks.
    ///- `Snark`: The SNARK used to produce proofs.
    ///- `Bul`: The public user bulletin (can be a network handle to a Merkle tree, or a signature
    ///storage system)
    ///- `NUMCBS`: The number of callbacks being produced and added to the user.
    ///
    ///# Arguments
    ///
    ///- `&mut self`: The user being updated.
    ///- `rng`: Random number generator. Used for generating callback tickets and updating the user
    ///nonce.
    ///- `method`: The interaction. Consists of a method `U -> U'`, a predicate `p(U, U') -> bool`, along with a list of callbacks.
    ///- `rpks`: Rerandomizable public keys; these are the public keys of services. This way, the
    ///user may then verify that the called callback has a valid signature on it (from the correct
    ///service).
    ///- `bul_data`: This is public and private data to prove membership of the user in the user
    ///bulletin. For example, with a Merkle tree, the witness will be a path, while the public data
    ///will be the Merkle root.
    ///- `is_memb_data_const`: Is the public membership data a constant. Determines whether to load
    ///the data as a constant or not.
    ///- `pk`: The snark proving key. Generated by calling [`Interaction::generate_keys`]. Note
    ///that if the membership data is constant, the keys *must* be generated that way as well.
    ///- `pub_args`: The public arguments passed in when calling the method.
    ///- `priv_args`: The private arguments passed in when calling the method.
    ///- `is_scan`: Does this function affect the callbacks? Some extra checks are removed for
    ///scanning methods which affect the callbacks. (Only set to true if necessary).
    ///
    /// Note that **any method** may be executed: This includes methods which involve scanning.
    /// Therefore, this method captures both *the creation of callbacks*, and *the scan / ingestion of
    /// callbacks*.
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
    ///     // User has been updated according to the method
    ///     assert_eq!(u.data.num_visits, Fr::from(1));
    ///     assert_eq!(u.data.last_interacted_time, Time::from(20));
    ///     // User has a single callback corresponding to the callback added
    ///     // The new commitment is the commitment of the user
    ///     assert_eq!(u.commit::<Poseidon<2>>(), exec_meth.new_object);
    /// }
    /// ```
    pub fn interact<
        H: FieldHash<F>,
        PubArgs: Clone + std::fmt::Debug,
        PubArgsVar: AllocVar<PubArgs, F> + Clone,
        PrivArgs: Clone + std::fmt::Debug,
        PrivArgsVar: AllocVar<PrivArgs, F> + Clone,
        CBArgs: Clone + std::fmt::Debug,
        CBArgsVar: AllocVar<CBArgs, F> + Clone,
        Crypto: AECipherSigZK<F, CBArgs>,
        Snark: SNARK<F, Error = SynthesisError>,
        Bul: PublicUserBul<F, U>,
        const NUMCBS: usize,
    >(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        method: Interaction<
            F,
            U,
            PubArgs,
            PubArgsVar,
            PrivArgs,
            PrivArgsVar,
            CBArgs,
            CBArgsVar,
            NUMCBS,
        >,
        rpks: [Crypto::SigPK; NUMCBS],
        cur_time: Time<F>,
        bul_data: (Bul::MembershipPub, Bul::MembershipWitness),
        is_memb_data_const: bool,
        pk: &Snark::ProvingKey,
        pub_args: PubArgs,
        priv_args: PrivArgs,
        is_scan: bool,
    ) -> Result<ExecutedMethod<F, Snark, CBArgs, Crypto, NUMCBS>, SynthesisError> {
        // Steps:
        // a) update user/self [ old user ] --> method(user) [ new user ]
        // b) update user's zk fields properly (new nul, new comrand, proper cblist, etc)
        // c) generate proof of correctness for
        //      - a) the user was properly updated via the predicate
        //      - b) the zk statements (nul == old nul, proper cblist, etc)

        // (A) update the user object
        // Create the new zk_object from the method
        let mut new_user = (method.meth.0)(self, pub_args.clone(), priv_args.clone());

        // (B) update the new users zk fields properly

        new_user.zk_fields.nul = rng.r#gen();
        new_user.zk_fields.com_rand = rng.r#gen();

        let cb_tik_list: [(CallbackCom<F, CBArgs, Crypto>, Crypto::Rand); NUMCBS] =
            create_cbs_from_interaction(rng, method.clone(), rpks, cur_time);

        let issued_callbacks: [CallbackCom<F, CBArgs, Crypto>; NUMCBS] = cb_tik_list
            .iter()
            .map(|(x, _)| x.clone())
            .collect::<Vec<CallbackCom<F, CBArgs, Crypto>>>()
            .try_into()
            .unwrap();

        let issued_cb_coms = cb_tik_list
            .iter()
            .map(|(x, _)| x.commit::<H>())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        for item in issued_callbacks.iter().take(NUMCBS) {
            let mut cb = Vec::new();
            item.clone().serialize_compressed(&mut cb).unwrap();
            new_user.callbacks.push(cb);

            new_user.zk_fields.callback_hash = add_ticket_to_hc::<F, H, CBArgs, Crypto>(
                new_user.zk_fields.callback_hash,
                item.clone().cb_entry,
            );
        }

        if !is_scan {
            new_user.zk_fields.old_in_progress_callback_hash = new_user.zk_fields.callback_hash;
        }

        // (C) Generate proof of correctness
        // Extract the zk fields from the objects to do bookkeeping

        let out_commit = new_user.commit::<H>();

        let out_nul = self.zk_fields.nul;

        let exec_method_circ: ExecMethodCircuit<
            F,
            H,
            U,
            PubArgs,
            PubArgsVar,
            PrivArgs,
            PrivArgsVar,
            CBArgs,
            CBArgsVar,
            Crypto,
            Bul,
            NUMCBS,
        > = ExecMethodCircuit {
            priv_old_user: self.clone(),
            priv_new_user: new_user.clone(),
            priv_issued_callbacks: issued_callbacks,
            priv_bul_membership_witness: bul_data.1,
            priv_args,

            pub_new_com: out_commit,
            pub_old_nul: out_nul,
            pub_issued_callback_coms: issued_cb_coms,
            pub_args,
            pub_bul_membership_data: bul_data.0,
            bul_memb_is_const: is_memb_data_const,

            associated_method: method,
            is_scan,
            _phantom_hash: core::marker::PhantomData,
        };

        let new_cs = ConstraintSystem::<F>::new_ref();
        exec_method_circ
            .clone()
            .generate_constraints(new_cs.clone())?;
        new_cs.is_satisfied()?;

        let proof = Snark::prove(pk, exec_method_circ, rng)?;

        // (D) Update current object
        *self = new_user;

        Ok(ExecutedMethod {
            new_object: out_commit,
            old_nullifier: out_nul,
            cb_tik_list,
            cb_com_list: issued_cb_coms,
            cur_time,
            proof,
        })
    }

    /// Get the execute method circuit for an interaction.
    ///
    /// For advanced use only.
    pub fn circuit_interact<
        H: FieldHash<F>,
        PubArgs: Clone + std::fmt::Debug,
        PubArgsVar: AllocVar<PubArgs, F> + Clone,
        PrivArgs: Clone + std::fmt::Debug,
        PrivArgsVar: AllocVar<PrivArgs, F> + Clone,
        CBArgs: Clone + std::fmt::Debug,
        CBArgsVar: AllocVar<CBArgs, F> + Clone,
        Crypto: AECipherSigZK<F, CBArgs>,
        Bul: PublicUserBul<F, U>,
        const NUMCBS: usize,
    >(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        method: Interaction<
            F,
            U,
            PubArgs,
            PubArgsVar,
            PrivArgs,
            PrivArgsVar,
            CBArgs,
            CBArgsVar,
            NUMCBS,
        >,
        rpks: [Crypto::SigPK; NUMCBS],
        cur_time: Time<F>,
        bul_data: (Bul::MembershipPub, Bul::MembershipWitness),
        is_memb_data_const: bool,
        pub_args: PubArgs,
        priv_args: PrivArgs,
        is_scan: bool,
    ) -> Result<
        ExecMethodCircuit<
            F,
            H,
            U,
            PubArgs,
            PubArgsVar,
            PrivArgs,
            PrivArgsVar,
            CBArgs,
            CBArgsVar,
            Crypto,
            Bul,
            NUMCBS,
        >,
        SynthesisError,
    > {
        // Steps:
        // a) update user/self [ old user ] --> method(user) [ new user ]
        // b) update user's zk fields properly (new nul, new comrand, proper cblist, etc)
        // c) generate proof of correctness for
        //      - a) the user was properly updated via the predicate
        //      - b) the zk statements (nul == old nul, proper cblist, etc)

        // (A) update the user object
        // Create the new zk_object from the method
        let mut new_user = (method.meth.0)(self, pub_args.clone(), priv_args.clone());

        // (B) update the new users zk fields properly

        new_user.zk_fields.nul = rng.r#gen();
        new_user.zk_fields.com_rand = rng.r#gen();

        let cb_tik_list: [(CallbackCom<F, CBArgs, Crypto>, Crypto::Rand); NUMCBS] =
            create_cbs_from_interaction(rng, method.clone(), rpks, cur_time);

        let issued_callbacks: [CallbackCom<F, CBArgs, Crypto>; NUMCBS] = cb_tik_list
            .iter()
            .map(|(x, _)| x.clone())
            .collect::<Vec<CallbackCom<F, CBArgs, Crypto>>>()
            .try_into()
            .unwrap();

        let issued_cb_coms = cb_tik_list
            .iter()
            .map(|(x, _)| x.commit::<H>())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        for item in issued_callbacks.iter().take(NUMCBS) {
            let mut cb = Vec::new();
            item.clone().serialize_compressed(&mut cb).unwrap();
            new_user.callbacks.push(cb);

            new_user.zk_fields.callback_hash = add_ticket_to_hc::<F, H, CBArgs, Crypto>(
                new_user.zk_fields.callback_hash,
                item.clone().cb_entry,
            );
        }

        if !is_scan {
            new_user.zk_fields.old_in_progress_callback_hash = new_user.zk_fields.callback_hash;
        }

        // (C) Generate proof of correctness
        // Extract the zk fields from the objects to do bookkeeping

        let out_commit = new_user.commit::<H>();

        let out_nul = self.zk_fields.nul;

        let exec_method_circ: ExecMethodCircuit<
            F,
            H,
            U,
            PubArgs,
            PubArgsVar,
            PrivArgs,
            PrivArgsVar,
            CBArgs,
            CBArgsVar,
            Crypto,
            Bul,
            NUMCBS,
        > = ExecMethodCircuit {
            priv_old_user: self.clone(),
            priv_new_user: new_user.clone(),
            priv_issued_callbacks: issued_callbacks,
            priv_bul_membership_witness: bul_data.1,
            priv_args,

            pub_new_com: out_commit,
            pub_old_nul: out_nul,
            pub_issued_callback_coms: issued_cb_coms,
            pub_args,
            pub_bul_membership_data: bul_data.0,
            bul_memb_is_const: is_memb_data_const,

            associated_method: method,
            is_scan,
            _phantom_hash: core::marker::PhantomData,
        };

        Ok(exec_method_circ)
    }

    /// Get the constraint system for an interaction.
    ///
    /// Useful for debugging.
    ///
    /// **Note that this does not modify the user, it modifies a cloned user internally.**
    ///
    /// See [`User::interact`] for more documentation.
    pub fn constraint_interact<
        H: FieldHash<F>,
        PubArgs: Clone + std::fmt::Debug,
        PubArgsVar: AllocVar<PubArgs, F> + Clone,
        PrivArgs: Clone + std::fmt::Debug,
        PrivArgsVar: AllocVar<PrivArgs, F> + Clone,
        CBArgs: Clone + std::fmt::Debug,
        CBArgsVar: AllocVar<CBArgs, F> + Clone,
        Crypto: AECipherSigZK<F, CBArgs>,
        Bul: PublicUserBul<F, U>,
        const NUMCBS: usize,
    >(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        method: Interaction<
            F,
            U,
            PubArgs,
            PubArgsVar,
            PrivArgs,
            PrivArgsVar,
            CBArgs,
            CBArgsVar,
            NUMCBS,
        >,
        rpks: [Crypto::SigPK; NUMCBS],
        cur_time: Time<F>,
        bul_data: (Bul::MembershipPub, Bul::MembershipWitness),
        is_memb_data_const: bool,
        pub_args: PubArgs,
        priv_args: PrivArgs,
        is_scan: bool,
    ) -> Result<ConstraintSystemRef<F>, SynthesisError> {
        // Steps:
        // a) update user/self [ old user ] --> method(user) [ new user ]
        // b) update user's zk fields properly (new nul, new comrand, proper cblist, etc)
        // c) generate proof of correctness for
        //      - a) the user was properly updated via the predicate
        //      - b) the zk statements (nul == old nul, proper cblist, etc)

        // (A) update the user object
        // Create the new zk_object from the method
        let mut new_user = (method.meth.0)(self, pub_args.clone(), priv_args.clone());

        // (B) update the new users zk fields properly

        new_user.zk_fields.nul = rng.r#gen();
        new_user.zk_fields.com_rand = rng.r#gen();

        let cb_tik_list: [(CallbackCom<F, CBArgs, Crypto>, Crypto::Rand); NUMCBS] =
            create_cbs_from_interaction(rng, method.clone(), rpks, cur_time);

        let issued_callbacks: [CallbackCom<F, CBArgs, Crypto>; NUMCBS] = cb_tik_list
            .iter()
            .map(|(x, _)| x.clone())
            .collect::<Vec<CallbackCom<F, CBArgs, Crypto>>>()
            .try_into()
            .unwrap();

        let issued_cb_coms = cb_tik_list
            .iter()
            .map(|(x, _)| x.commit::<H>())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        for item in issued_callbacks.iter().take(NUMCBS) {
            let mut cb = Vec::new();
            item.clone().serialize_compressed(&mut cb).unwrap();
            new_user.callbacks.push(cb);

            new_user.zk_fields.callback_hash = add_ticket_to_hc::<F, H, CBArgs, Crypto>(
                new_user.zk_fields.callback_hash,
                item.clone().cb_entry,
            );
        }

        if !is_scan {
            new_user.zk_fields.old_in_progress_callback_hash = new_user.zk_fields.callback_hash;
        }

        // (C) Generate proof of correctness
        // Extract the zk fields from the objects to do bookkeeping

        let out_commit = new_user.commit::<H>();

        let out_nul = self.zk_fields.nul;

        let exec_method_circ: ExecMethodCircuit<
            F,
            H,
            U,
            PubArgs,
            PubArgsVar,
            PrivArgs,
            PrivArgsVar,
            CBArgs,
            CBArgsVar,
            Crypto,
            Bul,
            NUMCBS,
        > = ExecMethodCircuit {
            priv_old_user: self.clone(),
            priv_new_user: new_user.clone(),
            priv_issued_callbacks: issued_callbacks,
            priv_bul_membership_witness: bul_data.1,
            priv_args,

            pub_new_com: out_commit,
            pub_old_nul: out_nul,
            pub_issued_callback_coms: issued_cb_coms,
            pub_args,
            pub_bul_membership_data: bul_data.0,
            bul_memb_is_const: is_memb_data_const,

            associated_method: method,
            is_scan,
            _phantom_hash: core::marker::PhantomData,
        };

        let new_cs = ConstraintSystem::<F>::new_ref();
        exec_method_circ
            .clone()
            .generate_constraints(new_cs.clone())?;

        Ok(new_cs)
    }

    /// A specialization of the [`User::interact`] function.
    ///
    /// Here, a user may execute a method *which does not scan or change any callback-related data*.
    /// Along with this, a user may also append a number of callbacks. See [`User::interact`] for
    /// details and more documentation.
    ///
    /// For example, the prior example in [`User::interact`] may be replaced with
    /// [`User::exec_method_create_cb`], as the method only changes `num_visits` and
    /// `last_interacted_time`, and no zk field values.
    ///
    /// Note that this function just calls interact with `is_scan = false`. Additionally, the
    /// arguments are not the same; a `Bul` is passed in, and membership data is retrieved from the
    /// bulletin.
    ///
    /// # Generics
    ///- `H`: the hash used for commitments. For example, it may be Poseidon or Sha256.
    ///- `PubArgs`: The public arguments provided to the method.
    ///- `PubArgsVar`: In-circuit representation of the public arguments, provided to the
    ///predicate.
    ///- `PrivArgs`: The private arguments provided to the method.
    ///- `PrivArgsVar`: In-circuit representation of the private arguments, provided to the
    ///predicate.
    ///- `CBArgs`: The public arguments provided to the callback function `cb(U, CBArgs) -> U`
    ///- `CBArgsVar`: The in-circuit representation of the public arguments provided to the
    ///callback function, which are enforced by the callback predicate.
    ///- `Crypto`: Authenticated encryption, which provides authenticity and confidentiality for
    ///called callbacks.
    ///- `Snark`: The SNARK used to produce proofs.
    ///- `Bul`: The public user bulletin (can be a network handle to a Merkle tree, or a signature
    ///storage system)
    ///- `NUMCBS`: The number of callbacks being produced and added to the user.
    ///
    ///# Arguments
    ///
    ///- `&mut self`: The user being updated.
    ///- `rng`: Random number generator. Used for generating callback tickets and updating the user
    ///nonce.
    ///- `method`: The interaction. Consists of a method `U -> U'`, a predicate `p(U, U') -> bool`, along with a list of callbacks.
    ///- `rpks`: Rerandomizable public keys; these are the public keys of services. This way, the
    ///user may then verify that the called callback has a valid signature on it (from the correct
    ///service).
    ///- `bul`: This is an interface to the public bulletin. For example, it may be some network
    ///handle to retrieve bulletin data, such as a Merkle tree. See the documentation on
    ///[`PublicUserBul`] for more details.
    ///- `is_memb_data_const`: Is the public membership data a constant. Determines whether to load
    ///the data as a constant or not.
    ///- `pk`: The snark proving key. Generated by calling [`Interaction::generate_keys`]. Note
    ///that if the membership data is constant, the keys *must* be generated that way as well.
    ///- `pub_args`: The public arguments passed in when calling the method.
    ///- `priv_args`: The private arguments passed in when calling the method.
    pub fn exec_method_create_cb<
        H: FieldHash<F>,
        PubArgs: Clone + std::fmt::Debug,
        PubArgsVar: AllocVar<PubArgs, F> + Clone,
        PrivArgs: Clone + std::fmt::Debug,
        PrivArgsVar: AllocVar<PrivArgs, F> + Clone,
        CBArgs: Clone + std::fmt::Debug,
        CBArgsVar: AllocVar<CBArgs, F> + Clone,
        Crypto: AECipherSigZK<F, CBArgs>,
        Snark: SNARK<F, Error = SynthesisError>,
        Bul: PublicUserBul<F, U>,
        const NUMCBS: usize,
    >(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        method: Interaction<
            F,
            U,
            PubArgs,
            PubArgsVar,
            PrivArgs,
            PrivArgsVar,
            CBArgs,
            CBArgsVar,
            NUMCBS,
        >,
        rpks: [Crypto::SigPK; NUMCBS],
        cur_time: Time<F>,
        bul: &Bul,
        is_memb_data_const: bool,
        pk: &Snark::ProvingKey,
        pub_args: PubArgs,
        priv_args: PrivArgs,
    ) -> Result<ExecutedMethod<F, Snark, CBArgs, Crypto, NUMCBS>, SynthesisError> {
        assert!(self.scan_index.is_none());

        let bul_data = bul.get_membership_data(self.commit::<H>()).unwrap();

        self.interact::<H, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar, CBArgs, CBArgsVar, Crypto, Snark, Bul, NUMCBS>(
            rng,
            method,
            rpks,
            cur_time,
            bul_data,
            is_memb_data_const,
            pk,
            pub_args,
            priv_args,
            false,
        )
    }

    /// Get the constraint system for executing a method and creating callbacks.
    ///
    /// Useful for debugging.
    ///
    /// **Note that this does not modify the user, it modifies a cloned user internally.**
    ///
    /// See [`User::exec_method_create_cb`] for more documentation.
    pub fn constraint_exec_method_create_cb<
        H: FieldHash<F>,
        PubArgs: Clone + std::fmt::Debug,
        PubArgsVar: AllocVar<PubArgs, F> + Clone,
        PrivArgs: Clone + std::fmt::Debug,
        PrivArgsVar: AllocVar<PrivArgs, F> + Clone,
        CBArgs: Clone + std::fmt::Debug,
        CBArgsVar: AllocVar<CBArgs, F> + Clone,
        Crypto: AECipherSigZK<F, CBArgs>,
        Bul: PublicUserBul<F, U>,
        const NUMCBS: usize,
    >(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        method: Interaction<
            F,
            U,
            PubArgs,
            PubArgsVar,
            PrivArgs,
            PrivArgsVar,
            CBArgs,
            CBArgsVar,
            NUMCBS,
        >,
        rpks: [Crypto::SigPK; NUMCBS],
        cur_time: Time<F>,
        bul: &Bul,
        is_memb_data_const: bool,
        pub_args: PubArgs,
        priv_args: PrivArgs,
    ) -> Result<ConstraintSystemRef<F>, SynthesisError> {
        assert!(self.scan_index.is_none());

        let bul_data = bul.get_membership_data(self.commit::<H>()).unwrap();

        self.constraint_interact::<H, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar, CBArgs, CBArgsVar, Crypto, Bul, NUMCBS>(
            rng,
            method,
            rpks,
            cur_time,
            bul_data,
            is_memb_data_const,
            pub_args,
            priv_args,
            false,
        )
    }

    /// Get the execute method circuit for an interaction without scan.
    ///
    /// For advanced use only.
    pub fn circuit_exec_method_create_cb<
        H: FieldHash<F>,
        PubArgs: Clone + std::fmt::Debug,
        PubArgsVar: AllocVar<PubArgs, F> + Clone,
        PrivArgs: Clone + std::fmt::Debug,
        PrivArgsVar: AllocVar<PrivArgs, F> + Clone,
        CBArgs: Clone + std::fmt::Debug,
        CBArgsVar: AllocVar<CBArgs, F> + Clone,
        Crypto: AECipherSigZK<F, CBArgs>,
        Bul: PublicUserBul<F, U>,
        const NUMCBS: usize,
    >(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        method: Interaction<
            F,
            U,
            PubArgs,
            PubArgsVar,
            PrivArgs,
            PrivArgsVar,
            CBArgs,
            CBArgsVar,
            NUMCBS,
        >,
        rpks: [Crypto::SigPK; NUMCBS],
        cur_time: Time<F>,
        bul: &Bul,
        is_memb_data_const: bool,
        pub_args: PubArgs,
        priv_args: PrivArgs,
    ) -> Result<
        ExecMethodCircuit<
            F,
            H,
            U,
            PubArgs,
            PubArgsVar,
            PrivArgs,
            PrivArgsVar,
            CBArgs,
            CBArgsVar,
            Crypto,
            Bul,
            NUMCBS,
        >,
        SynthesisError,
    > {
        assert!(self.scan_index.is_none());

        let bul_data = bul.get_membership_data(self.commit::<H>()).unwrap();

        self.circuit_interact::<H, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar, CBArgs, CBArgsVar, Crypto, Bul, NUMCBS>(
            rng,
            method,
            rpks,
            cur_time,
            bul_data,
            is_memb_data_const,
            pub_args,
            priv_args,
            false,
        )
    }

    /// Execute a scan method and produces a proof.
    ///
    /// This function scans `NUMSCANS` callbacks and checks if those callbacks were called or not.
    /// If called, the associated callback function will be applied to the user.
    ///
    /// This function is a wrapper around `interact`, which just performs a specific interaction given
    /// by [`get_scan_interaction`].
    ///
    /// # Warning!
    ///
    /// The scan **will only complete** if the scan is done *incrementally*. For example, if a user
    /// has 3 callbacks, the user may scan `[0]`, and then `[1, 2]`, which will complete the scan.
    ///
    /// However, going over by doing `[0, 1]`, `[2, 0]` will fail (even if it wraps around
    /// properly). Note that also attempting something like `[0, 2]` and then `[1]` will fail;
    /// callbacks have an inherent order from when they were assigned.
    ///
    /// # Note
    ///
    /// This function not only returns the `ExecutedMethod`, but it also returns a
    /// `PublicScanArgs`. This return value corresponds to the public arguments necessary to verify
    /// the proof produced. Specifically, this is the `PubArgs` passed to the interaction call
    /// inside this scan function.
    ///
    /// # Generics
    ///- `H`: the hash used for commitments. For example, it may be Poseidon or Sha256.
    ///- `CBArgs`: The public arguments provided to the callback function `cb(U, CBArgs) -> U`
    ///- `CBArgsVar`: The in-circuit representation of the public arguments provided to the
    ///callback function, which are enforced by the callback predicate.
    ///- `Crypto`: Authenticated encryption, which provides authenticity and confidentiality for
    ///called callbacks.
    ///- `CBul`: The public callback bulletin (can be a network handle to a signature store or
    /// Merkle tree).
    ///- `Snark`: The SNARK used to produce proofs.
    ///- `Bul`: The public user bulletin (can be a network handle to a Merkle tree, or a signature
    ///storage system)
    ///- `NUMSCANS`: The number of callbacks being *scanned*.
    ///
    ///# Arguments
    ///
    ///- `&mut self`: The user being updated.
    ///- `rng`: Random number generator. Used for generating callback tickets and updating the user
    ///nonce.
    ///- `bul`: A handle to the user bulletin; It could be a Merkle tree of commitments, or a
    ///signature store.
    ///- `is_memb_data_const`: Is the public membership data a constant. Determines whether to load
    ///the data as a constant or not.
    ///- `pk`: The snark proving key. Generated by calling [`Interaction::generate_keys`]. Note
    ///that if the membership data is constant, the keys *must* be generated that way as well.
    ///- `cbul`: The public callback bulletin.
    ///- `is_memb_nmemb_data_const`: Is
    ///  1. The public membership data *for a callback* constant?
    ///  2. The public *non*membership data *for a callback* constant?
    ///The first element in the tuple is for membership, while the second element is for
    ///nonmembership.
    ///- `cur_time`: The time at which the scan occurs.
    ///- `cb_methods`: A list of callbacks used to produce the proof.
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
    ///
    /// type PubScan = PubScanArgs<Fr, Data, Fr, FpVar<Fr>, NoSigOTP<Fr>, DummyStore, 1>;
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
    ///     let (pks, vks) = get_scan_interaction::<_, _, _, _, _, _, Poseidon<2>, 1>().generate_keys::<Poseidon<2>, Groth, NoSigOTP<Fr>, DummyStore>(&mut rng, Some(()), Some(ex), true);
    ///
    ///     let mut u = User::create(Data { bad_rep: 0, num_visits: Fr::from(0), last_interacted_time: Time::from(0) }, &mut rng);
    ///
    ///     let exec_meth = u.interact::<Poseidon<2>, Time<Fr>, TimeVar<Fr>, (), (), Fr, FpVar<Fr>, NoSigOTP<Fr>, Groth, DummyStore, 1>(&mut rng, int.clone(), [FakeSigPubkey::pk()], Time::from(20), ((), ()), true, &pk, Time::from(20), (), false).unwrap();
    ///
    ///     let (ps, scan_meth) = u.scan_callbacks::<Poseidon<2>, Fr, FpVar<Fr>, NoSigOTP<Fr>, DummyStore, Groth, DummyStore, 1>(&mut rng, &DummyStore, true, &pks, &DummyStore, (true, true), Time::from(25), cb_methods.clone()).unwrap();
    ///
    ///     <DummyStore as UserBul<Fr, Data>>::verify_interact_and_append::<PubScan, Groth, 0>(&mut DummyStore, scan_meth.new_object.clone(), scan_meth.old_nullifier.clone(), ps.clone(), scan_meth.cb_com_list.clone(), scan_meth.proof.clone(), None, &vks).unwrap();
    /// }
    /// ```
    pub fn scan_callbacks<
        H: FieldHash<F>,
        CBArgs: Clone + std::fmt::Debug + PartialEq + Eq,
        CBArgsVar: AllocVar<CBArgs, F> + Clone,
        Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar> + PartialEq + Eq,
        CBul: PublicCallbackBul<F, CBArgs, Crypto> + Clone,
        Snark: SNARK<F, Error = SynthesisError>,
        Bul: PublicUserBul<F, U>,
        const NUMSCANS: usize,
    >(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        bul: &Bul,
        is_memb_data_const: bool,
        pk: &Snark::ProvingKey,
        cbul: &CBul,
        is_memb_nmemb_const: (bool, bool),
        cur_time: Time<F>,
        cb_methods: Vec<Callback<F, U, CBArgs, CBArgsVar>>,
    ) -> Result<
        (
            PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS>,
            ExecutedMethod<F, Snark, CBArgs, Crypto, 0>,
        ),
        SynthesisError,
    >
    where
        U::UserDataVar: CondSelectGadget<F> + EqGadget<F>,
        CBul::MembershipPub: std::fmt::Debug,
        CBul::NonMembershipPub: std::fmt::Debug,
    {
        let start_ind = match self.scan_index {
            Some(ind) => {
                assert!(NUMSCANS + ind <= self.callbacks.len());
                ind
            }
            None => {
                assert!(NUMSCANS <= self.callbacks.len());
                0
            }
        };

        let bul_data = bul.get_membership_data(self.commit::<H>()).unwrap();

        let mut vec_cbs = vec![];
        let mut vec_memb_pub = vec![];
        let mut vec_nmemb_pub = vec![];
        let mut vec_memb_priv = vec![];
        let mut vec_nmemb_priv = vec![];
        let mut vec_enc = vec![];
        let mut vec_times = vec![];

        for i in 0..NUMSCANS {
            let cb: CallbackCom<F, CBArgs, Crypto> = self.get_cb::<CBArgs, Crypto>(start_ind + i);
            let data = cbul.get_membership_data(cb.get_ticket());
            let if_in = cbul.verify_in(cb.get_ticket());
            let (enc, sig, time) = match if_in {
                Some((e, s, t)) => (e, s, t),
                None => (
                    Crypto::Ct::default(),
                    Crypto::Sig::default(),
                    Time::default(),
                ),
            };

            assert!(
                <Crypto as AECipherSigZK<F, CBArgs>>::SigPK::verify(
                    &cb.get_ticket(),
                    enc.clone(),
                    sig
                ) == true
            );

            vec_enc.push(enc);
            vec_times.push(time);
            vec_cbs.push(cb);
            vec_memb_pub.push(data.0);
            vec_memb_priv.push(data.1);
            vec_nmemb_pub.push(data.2);
            vec_nmemb_priv.push(data.3);
        }

        let ps: PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS> = PubScanArgs {
            memb_pub: vec_memb_pub
                .try_into()
                .unwrap_or_else(|_| panic!("Unexpected failure.")),
            nmemb_pub: vec_nmemb_pub
                .try_into()
                .unwrap_or_else(|_| panic!("Unexpected failure.")),
            bulletin: cbul.clone(),
            is_memb_data_const: is_memb_nmemb_const.0,
            is_nmemb_data_const: is_memb_nmemb_const.1,
            cur_time,
            cb_methods,
        };

        let prs: PrivScanArgs<F, CBArgs, Crypto, CBul, NUMSCANS> = PrivScanArgs {
            priv_n_tickets: vec_cbs.try_into().unwrap(),
            post_times: vec_times.try_into().unwrap(),
            enc_args: vec_enc
                .try_into()
                .unwrap_or_else(|_| panic!("Unexpected failure.")),
            memb_priv: vec_memb_priv
                .try_into()
                .unwrap_or_else(|_| panic!("Unexpected failure.")),
            nmemb_priv: vec_nmemb_priv
                .try_into()
                .unwrap_or_else(|_| panic!("Unexpected failure.")),
        };

        let out = self.interact::<H, PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS>, PubScanArgsVar<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS>, PrivScanArgs<F, CBArgs, Crypto, CBul, NUMSCANS>, PrivScanArgsVar<F, CBArgs, Crypto, CBul, NUMSCANS>, CBArgs, CBArgsVar, Crypto, Snark, Bul, 0>(
            rng,
            get_scan_interaction::<F, U, CBArgs, CBArgsVar, Crypto, CBul, H, NUMSCANS>(),
            [],
            cur_time,
            bul_data,
            is_memb_data_const,
            pk,
            ps.clone(),
            prs,
            true,
        )?;

        Ok((ps, out))
    }

    /// Get the constraint system for scanning callbacks.
    ///
    /// Useful for debugging.
    ///
    /// **Note that this does not modify the user, it modifies a cloned user internally.**
    ///
    /// See [`User::scan_callbacks`] for more documentation.
    pub fn constraint_scan_callbacks<
        H: FieldHash<F>,
        CBArgs: Clone + std::fmt::Debug + PartialEq + Eq,
        CBArgsVar: AllocVar<CBArgs, F> + Clone,
        Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar> + PartialEq + Eq,
        CBul: PublicCallbackBul<F, CBArgs, Crypto> + Clone,
        Bul: PublicUserBul<F, U>,
        const NUMSCANS: usize,
    >(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        bul: &Bul,
        is_memb_data_const: bool,
        cbul: &CBul,
        is_memb_nmemb_const: (bool, bool),
        cur_time: Time<F>,
        cb_methods: Vec<Callback<F, U, CBArgs, CBArgsVar>>,
    ) -> Result<
        (
            PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS>,
            ConstraintSystemRef<F>,
        ),
        SynthesisError,
    >
    where
        U::UserDataVar: CondSelectGadget<F> + EqGadget<F>,
    {
        let start_ind = match self.scan_index {
            Some(ind) => {
                assert!(NUMSCANS + ind <= self.callbacks.len());
                ind
            }
            None => {
                assert!(NUMSCANS <= self.callbacks.len());
                0
            }
        };

        let bul_data = bul.get_membership_data(self.commit::<H>()).unwrap();

        let mut vec_cbs = vec![];
        let mut vec_memb_pub = vec![];
        let mut vec_nmemb_pub = vec![];
        let mut vec_memb_priv = vec![];
        let mut vec_nmemb_priv = vec![];
        let mut vec_enc = vec![];
        let mut vec_times = vec![];

        for i in 0..NUMSCANS {
            let cb: CallbackCom<F, CBArgs, Crypto> = self.get_cb::<CBArgs, Crypto>(start_ind + i);
            let data = cbul.get_membership_data(cb.get_ticket());
            let if_in = cbul.verify_in(cb.get_ticket());
            let (enc, sig, time) = match if_in {
                Some((e, s, t)) => (e, s, t),
                None => (
                    Crypto::Ct::default(),
                    Crypto::Sig::default(),
                    Time::default(),
                ),
            };

            assert!(
                <Crypto as AECipherSigZK<F, CBArgs>>::SigPK::verify(
                    &cb.get_ticket(),
                    enc.clone(),
                    sig
                ) == true
            );

            vec_enc.push(enc);
            vec_times.push(time);
            vec_cbs.push(cb);
            vec_memb_pub.push(data.0);
            vec_memb_priv.push(data.1);
            vec_nmemb_pub.push(data.2);
            vec_nmemb_priv.push(data.3);
        }

        let ps: PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS> = PubScanArgs {
            memb_pub: vec_memb_pub
                .try_into()
                .unwrap_or_else(|_| panic!("Unexpected failure.")),
            nmemb_pub: vec_nmemb_pub
                .try_into()
                .unwrap_or_else(|_| panic!("Unexpected failure.")),
            bulletin: cbul.clone(),
            is_memb_data_const: is_memb_nmemb_const.0,
            is_nmemb_data_const: is_memb_nmemb_const.1,
            cur_time,
            cb_methods,
        };

        let prs: PrivScanArgs<F, CBArgs, Crypto, CBul, NUMSCANS> = PrivScanArgs {
            priv_n_tickets: vec_cbs.try_into().unwrap(),
            post_times: vec_times.try_into().unwrap(),
            enc_args: vec_enc
                .try_into()
                .unwrap_or_else(|_| panic!("Unexpected failure.")),
            memb_priv: vec_memb_priv
                .try_into()
                .unwrap_or_else(|_| panic!("Unexpected failure.")),
            nmemb_priv: vec_nmemb_priv
                .try_into()
                .unwrap_or_else(|_| panic!("Unexpected failure.")),
        };

        let out = self.constraint_interact::<H, PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS>, PubScanArgsVar<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS>, PrivScanArgs<F, CBArgs, Crypto, CBul, NUMSCANS>, PrivScanArgsVar<F, CBArgs, Crypto, CBul, NUMSCANS>, CBArgs, CBArgsVar, Crypto, Bul, 0>(
            rng,
            get_scan_interaction::<F, U, CBArgs, CBArgsVar, Crypto, CBul, H, NUMSCANS>(),
            [],
            cur_time,
            bul_data,
            is_memb_data_const,
            ps.clone(),
            prs,
            true,
        )?;

        Ok((ps, out))
    }

    /// Get the execute method circuit for a scan interaction.
    ///
    /// For advanced use only.
    pub fn circuit_scan_callbacks<
        H: FieldHash<F>,
        CBArgs: Clone + std::fmt::Debug + PartialEq + Eq,
        CBArgsVar: AllocVar<CBArgs, F> + Clone,
        Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar> + PartialEq + Eq,
        CBul: PublicCallbackBul<F, CBArgs, Crypto> + Clone,
        Bul: PublicUserBul<F, U>,
        const NUMSCANS: usize,
    >(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        bul: &Bul,
        is_memb_data_const: bool,
        cbul: &CBul,
        is_memb_nmemb_const: (bool, bool),
        cur_time: Time<F>,
        cb_methods: Vec<Callback<F, U, CBArgs, CBArgsVar>>,
    ) -> Result<
        (
            PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS>,
            ExecMethodCircuit<
                F,
                H,
                U,
                PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS>,
                PubScanArgsVar<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS>,
                PrivScanArgs<F, CBArgs, Crypto, CBul, NUMSCANS>,
                PrivScanArgsVar<F, CBArgs, Crypto, CBul, NUMSCANS>,
                CBArgs,
                CBArgsVar,
                Crypto,
                Bul,
                0,
            >,
        ),
        SynthesisError,
    >
    where
        U::UserDataVar: CondSelectGadget<F> + EqGadget<F>,
    {
        let start_ind = match self.scan_index {
            Some(ind) => {
                assert!(NUMSCANS + ind <= self.callbacks.len());
                ind
            }
            None => {
                assert!(NUMSCANS <= self.callbacks.len());
                0
            }
        };

        let bul_data = bul.get_membership_data(self.commit::<H>()).unwrap();

        let mut vec_cbs = vec![];
        let mut vec_memb_pub = vec![];
        let mut vec_nmemb_pub = vec![];
        let mut vec_memb_priv = vec![];
        let mut vec_nmemb_priv = vec![];
        let mut vec_enc = vec![];
        let mut vec_times = vec![];

        for i in 0..NUMSCANS {
            let cb: CallbackCom<F, CBArgs, Crypto> = self.get_cb::<CBArgs, Crypto>(start_ind + i);
            let data = cbul.get_membership_data(cb.get_ticket());
            let if_in = cbul.verify_in(cb.get_ticket());
            let (enc, sig, time) = match if_in {
                Some((e, s, t)) => (e, s, t),
                None => (
                    Crypto::Ct::default(),
                    Crypto::Sig::default(),
                    Time::default(),
                ),
            };

            assert!(
                <Crypto as AECipherSigZK<F, CBArgs>>::SigPK::verify(
                    &cb.get_ticket(),
                    enc.clone(),
                    sig
                ) == true
            );

            vec_enc.push(enc);
            vec_times.push(time);
            vec_cbs.push(cb);
            vec_memb_pub.push(data.0);
            vec_memb_priv.push(data.1);
            vec_nmemb_pub.push(data.2);
            vec_nmemb_priv.push(data.3);
        }

        let ps: PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS> = PubScanArgs {
            memb_pub: vec_memb_pub
                .try_into()
                .unwrap_or_else(|_| panic!("Unexpected failure.")),
            nmemb_pub: vec_nmemb_pub
                .try_into()
                .unwrap_or_else(|_| panic!("Unexpected failure.")),
            bulletin: cbul.clone(),
            is_memb_data_const: is_memb_nmemb_const.0,
            is_nmemb_data_const: is_memb_nmemb_const.1,
            cur_time,
            cb_methods,
        };

        let prs: PrivScanArgs<F, CBArgs, Crypto, CBul, NUMSCANS> = PrivScanArgs {
            priv_n_tickets: vec_cbs.try_into().unwrap(),
            post_times: vec_times.try_into().unwrap(),
            enc_args: vec_enc
                .try_into()
                .unwrap_or_else(|_| panic!("Unexpected failure.")),
            memb_priv: vec_memb_priv
                .try_into()
                .unwrap_or_else(|_| panic!("Unexpected failure.")),
            nmemb_priv: vec_nmemb_priv
                .try_into()
                .unwrap_or_else(|_| panic!("Unexpected failure.")),
        };

        let out = self.circuit_interact::<H, PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS>, PubScanArgsVar<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS>, PrivScanArgs<F, CBArgs, Crypto, CBul, NUMSCANS>, PrivScanArgsVar<F, CBArgs, Crypto, CBul, NUMSCANS>, CBArgs, CBArgsVar, Crypto, Bul, 0>(
            rng,
            get_scan_interaction::<F, U, CBArgs, CBArgsVar, Crypto, CBul, H, NUMSCANS>(),
            [],
            cur_time,
            bul_data,
            is_memb_data_const,
            ps.clone(),
            prs,
            true,
        )?;

        Ok((ps, out))
    }

    /// Prove a generic statement about the user with respect to a public user commitment.
    ///
    /// This function allows one to prove something about a user object with a public commitment.
    /// Note that this *does not preserve anonymity* if the proof + result is given to a service,
    /// as the user commitment is revealed (not the user, so privacy is not an issue).
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
    /// # use ark_snark::SNARK;
    /// # use ark_ff::ToConstraintField;
    /// # use zk_callbacks::generic::interaction::generate_keys_for_statement;
    /// # use zk_callbacks::impls::centralized::crypto::{NoSigOTP};
    /// # type Groth = Groth16<E>;
    /// #[zk_object(Fr)]
    /// #[derive(Default)]
    /// struct Data {
    ///     pub num_visits: Fr,
    ///     pub bad_rep: u8,
    ///     pub last_interacted_time: Time<Fr>,
    /// }
    ///
    /// fn predicate<'a, 'b>(user: &'a UserVar<Fr, Data>, _com: &'b FpVar<Fr>, _pub_args: (), _priv_args: ()) -> Result<Boolean<Fr>, SynthesisError> {
    ///     user.data.num_visits.is_eq(&FpVar::Constant(Fr::from(1)))
    /// }
    ///
    /// fn main () {
    ///
    ///     let mut rng = thread_rng();
    ///
    ///     let (pk, vk) = generate_keys_for_statement::<Fr, Poseidon<2>, Data, _, _, _, _, Groth>(&mut rng, predicate, None);
    ///
    ///     let mut u = User::create(Data { bad_rep: 0, num_visits: Fr::from(1), last_interacted_time: Time::from(0) }, &mut rng);
    ///
    ///     let result = u.prove_statement::<Poseidon<2>, _, _, _, _, Groth>(&mut rng, predicate, &pk, (), ()).unwrap();
    ///
    ///     assert_eq!(result.object, u.commit::<Poseidon<2>>());
    ///
    ///     let mut pub_inputs = vec![];
    ///
    ///     pub_inputs.extend_from_slice(&result.object.to_field_elements().unwrap());
    ///     pub_inputs.extend_from_slice(&().to_field_elements().unwrap());
    ///
    ///     let out = Groth::verify(&vk, &pub_inputs, &result.proof).unwrap();
    ///
    ///     assert!(out);
    ///
    /// }
    /// ```
    pub fn prove_statement<
        H: FieldHash<F>,
        PubArgs: Clone,
        PubArgsVar: AllocVar<PubArgs, F> + Clone,
        PrivArgs: Clone,
        PrivArgsVar: AllocVar<PrivArgs, F> + Clone,
        Snark: SNARK<F, Error = SynthesisError>,
    >(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        predicate: SingularPredicate<F, UserVar<F, U>, ComVar<F>, PubArgsVar, PrivArgsVar>,
        pk: &Snark::ProvingKey,
        pub_args: PubArgs,
        priv_args: PrivArgs,
    ) -> Result<ProveResult<F, Snark>, SynthesisError> {
        let ppcirc: ProvePredicateCircuit<F, U, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar> =
            ProvePredicateCircuit {
                priv_user: self.clone(),
                pub_com: self.commit::<H>(),
                priv_args,

                pub_args,
                associated_method: predicate,
            };

        let new_cs = ConstraintSystem::<F>::new_ref();
        ppcirc.clone().generate_constraints(new_cs.clone())?;
        new_cs.is_satisfied()?;

        let proof = Snark::prove(pk, ppcirc, rng)?;

        Ok(ProveResult {
            object: self.commit::<H>(),
            proof,
        })
    }

    /// Get the constraint system for proving a statement on a user.
    ///
    /// Useful for debugging.
    ///
    /// See [`User::prove_statement`] for more documentation.
    pub fn constraint_prove_statement<
        H: FieldHash<F>,
        PubArgs: Clone,
        PubArgsVar: AllocVar<PubArgs, F> + Clone,
        PrivArgs: Clone,
        PrivArgsVar: AllocVar<PrivArgs, F> + Clone,
        Snark: SNARK<F, Error = SynthesisError>,
    >(
        &self,
        predicate: SingularPredicate<F, UserVar<F, U>, ComVar<F>, PubArgsVar, PrivArgsVar>,
        pub_args: PubArgs,
        priv_args: PrivArgs,
    ) -> Result<ConstraintSystemRef<F>, SynthesisError> {
        let ppcirc: ProvePredicateCircuit<F, U, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar> =
            ProvePredicateCircuit {
                priv_user: self.clone(),
                pub_com: self.commit::<H>(),
                priv_args,

                pub_args,
                associated_method: predicate,
            };

        let new_cs = ConstraintSystem::<F>::new_ref();
        ppcirc.clone().generate_constraints(new_cs.clone())?;

        Ok(new_cs)
    }

    /// Get the prove predicate circuit for a statement.
    ///
    /// For advanced use only.
    pub fn circuit_prove_statement<
        H: FieldHash<F>,
        PubArgs: Clone,
        PubArgsVar: AllocVar<PubArgs, F> + Clone,
        PrivArgs: Clone,
        PrivArgsVar: AllocVar<PrivArgs, F> + Clone,
        Snark: SNARK<F, Error = SynthesisError>,
    >(
        &self,
        predicate: SingularPredicate<F, UserVar<F, U>, ComVar<F>, PubArgsVar, PrivArgsVar>,
        pub_args: PubArgs,
        priv_args: PrivArgs,
    ) -> Result<
        ProvePredicateCircuit<F, U, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar>,
        SynthesisError,
    > {
        let ppcirc: ProvePredicateCircuit<F, U, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar> =
            ProvePredicateCircuit {
                priv_user: self.clone(),
                pub_com: self.commit::<H>(),
                priv_args,

                pub_args,
                associated_method: predicate,
            };

        Ok(ppcirc)
    }

    /// Prove a statement about the user object, along with membership in some bulletin.
    ///
    /// If a method update is not necessary, one can prove a statement about their user without
    /// updating it. This function also does not reveal the user commitment; the membership in the
    /// bulletin is proven without revealing anything more.
    ///
    /// # Arguments
    ///- `&self`: The user on which a statement is being made.
    ///- `rng`: Random number generator. Used for generating the proof.
    ///- `predicate`: A predicate `p(U, Com(U), args)` one wants to prove.
    ///- `pk`: The SNARK proving key, generated by calling
    ///[`generate_keys_for_statement_in`](`super::interaction::generate_keys_for_statement_in`).
    ///Note that if membership data is constant, the keys *must* be generated that way as well.
    ///- `is_memb_data_const`: Is the public membership data constant. Determines whether to load
    ///the data as a constant or not.
    ///- `pub_args`: The public arguments to the predicate.
    ///- `priv_args`: The private arguments to the predicate.
    ///- `print_constraints`: Whether to print the number of constraints or not.
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
    /// # use zk_callbacks::generic::interaction::generate_keys_for_statement;
    /// # use zk_callbacks::impls::centralized::crypto::{NoSigOTP};
    /// # use zk_callbacks::impls::centralized::ds::sigstore::UOVObjStore;
    /// # use crate::zk_callbacks::generic::bulletin::JoinableBulletin;
    /// # use zk_callbacks::generic::interaction::generate_keys_for_statement_in;
    /// # type Groth = Groth16<E>;
    /// #[zk_object(Fr)]
    /// #[derive(Default)]
    /// struct Data {
    ///     pub num_visits: Fr,
    ///     pub bad_rep: u8,
    ///     pub last_interacted_time: Time<Fr>,
    /// }
    ///
    /// fn predicate<'a, 'b>(user: &'a UserVar<Fr, Data>, _com: &'b FpVar<Fr>, _pub_args: (), _priv_args: ()) -> Result<Boolean<Fr>, SynthesisError> {
    ///     user.data.num_visits.is_eq(&FpVar::Constant(Fr::from(1)))
    /// }
    ///
    /// fn main () {
    ///
    ///     let mut rng = thread_rng();
    ///
    ///     let mut obj_store = UOVObjStore::new(&mut rng);
    ///
    ///     let (pk, vk) = generate_keys_for_statement_in::<Fr, Poseidon<2>, Data, _, _, _, _, Groth, UOVObjStore<Fr>>(&mut rng, predicate, Some(obj_store.get_pubkey()), None);
    ///
    ///     let mut u = User::create(Data { bad_rep: 0, num_visits: Fr::from(1), last_interacted_time: Time::from(0) }, &mut rng);
    ///
    ///     <UOVObjStore<Fr> as JoinableBulletin<Fr, Data>>::join_bul(&mut obj_store, u.commit::<Poseidon<2>>(), ()).unwrap();
    ///
    ///     let result = u.prove_statement_and_in::<Poseidon<2>, _, _, _, _, Groth, UOVObjStore<Fr>>(&mut rng, predicate, &pk, (obj_store.get_signature_of(&u.commit::<Poseidon<2>>()).unwrap(), obj_store.get_pubkey()), true, (), ()).unwrap();
    ///
    /// }
    /// ```
    pub fn prove_statement_and_in<
        H: FieldHash<F>,
        PubArgs: Clone,
        PubArgsVar: AllocVar<PubArgs, F> + Clone,
        PrivArgs: Clone,
        PrivArgsVar: AllocVar<PrivArgs, F> + Clone,
        Snark: SNARK<F, Error = SynthesisError>,
        Bul: PublicUserBul<F, U>,
    >(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        predicate: SingularPredicate<F, UserVar<F, U>, ComVar<F>, PubArgsVar, PrivArgsVar>,
        pk: &Snark::ProvingKey,
        memb_data: (Bul::MembershipWitness, Bul::MembershipPub),
        is_memb_data_const: bool,
        pub_args: PubArgs,
        priv_args: PrivArgs,
    ) -> Result<Snark::Proof, SynthesisError> {
        let ppcirc: ProvePredInCircuit<F, H, U, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar, Bul> =
            ProvePredInCircuit {
                priv_user: self.clone(),
                priv_extra_membership_data: memb_data.0,
                priv_args,
                pub_extra_membership_data: memb_data.1,
                bul_memb_is_const: is_memb_data_const,
                pub_args,
                associated_method: predicate,

                _phantom_hash: core::marker::PhantomData,
            };

        let new_cs = ConstraintSystem::<F>::new_ref();
        ppcirc.clone().generate_constraints(new_cs.clone())?;
        new_cs.is_satisfied()?;

        let proof = Snark::prove(pk, ppcirc, rng)?;

        Ok(proof)
    }

    /// Get the constraint system for proving a statement and membership on a user.
    ///
    /// Useful for debugging.
    ///
    /// See [`User::prove_statement_and_in`] for more documentation.
    pub fn constraint_prove_statement_and_in<
        H: FieldHash<F>,
        PubArgs: Clone,
        PubArgsVar: AllocVar<PubArgs, F> + Clone,
        PrivArgs: Clone,
        PrivArgsVar: AllocVar<PrivArgs, F> + Clone,
        Bul: PublicUserBul<F, U>,
    >(
        &self,
        predicate: SingularPredicate<F, UserVar<F, U>, ComVar<F>, PubArgsVar, PrivArgsVar>,
        memb_data: (Bul::MembershipWitness, Bul::MembershipPub),
        is_memb_data_const: bool,
        pub_args: PubArgs,
        priv_args: PrivArgs,
    ) -> Result<ConstraintSystemRef<F>, SynthesisError> {
        let ppcirc: ProvePredInCircuit<F, H, U, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar, Bul> =
            ProvePredInCircuit {
                priv_user: self.clone(),
                priv_extra_membership_data: memb_data.0,
                priv_args,
                pub_extra_membership_data: memb_data.1,
                bul_memb_is_const: is_memb_data_const,
                pub_args,
                associated_method: predicate,

                _phantom_hash: core::marker::PhantomData,
            };

        let new_cs = ConstraintSystem::<F>::new_ref();
        ppcirc.clone().generate_constraints(new_cs.clone())?;

        Ok(new_cs)
    }

    /// Get the execute method circuit for proving a statement and membership.
    ///
    /// For advanced use only.
    pub fn circuit_prove_statement_and_in<
        H: FieldHash<F>,
        PubArgs: Clone,
        PubArgsVar: AllocVar<PubArgs, F> + Clone,
        PrivArgs: Clone,
        PrivArgsVar: AllocVar<PrivArgs, F> + Clone,
        Bul: PublicUserBul<F, U>,
    >(
        &self,
        predicate: SingularPredicate<F, UserVar<F, U>, ComVar<F>, PubArgsVar, PrivArgsVar>,
        memb_data: (Bul::MembershipWitness, Bul::MembershipPub),
        is_memb_data_const: bool,
        pub_args: PubArgs,
        priv_args: PrivArgs,
    ) -> Result<
        ProvePredInCircuit<F, H, U, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar, Bul>,
        SynthesisError,
    > {
        let ppcirc: ProvePredInCircuit<F, H, U, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar, Bul> =
            ProvePredInCircuit {
                priv_user: self.clone(),
                priv_extra_membership_data: memb_data.0,
                priv_args,
                pub_extra_membership_data: memb_data.1,
                bul_memb_is_const: is_memb_data_const,
                pub_args,
                associated_method: predicate,

                _phantom_hash: core::marker::PhantomData,
            };

        Ok(ppcirc)
    }

    /// TODO.
    #[cfg(feature = "folding")]
    #[cfg(any(feature = "folding", doc))]
    #[doc(cfg(feature = "folding"))]
    pub fn scan_and_create_fold_proof_inputs<
        CBArgs: Clone + std::fmt::Debug + PartialEq + Eq + Default,
        CBArgsVar: AllocVar<CBArgs, F> + Clone,
        Crypto: AECipherSigZK<F, CBArgs, AV = CBArgsVar> + PartialEq + Eq + Default,
        Bul: PublicUserBul<F, U>,
        CBul: PublicCallbackBul<F, CBArgs, Crypto> + Clone,
        H: FieldHash<F>,
        Snark: SNARK<F, Error = SynthesisError>,
        const NUMSCANS: usize,
    >(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),

        bul_data: (Bul::MembershipPub, Bul::MembershipWitness),
        cbul: &CBul,
        is_bul_data_const: bool,
        is_memb_nmemb_const: (bool, bool),
        cur_time: Time<F>,
        cb_methods: Vec<Callback<F, U, CBArgs, CBArgsVar>>,
        pk: &Snark::ProvingKey,
        num_folds: usize,
    ) -> (
        (
            PubScanArgs<F, U, CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS>,
            Bul::MembershipPub,
        ),
        Vec<F>,
        Vec<FoldInput<F, U, CBArgs, CBArgsVar, Crypto, Bul, CBul, NUMSCANS>>,
        (Com<F>, Nul<F>, Snark::Proof),
    )
    where
        U: Default,
        CBul::MembershipPub: Default,
        CBul::NonMembershipPub: Default,
        CBul::MembershipWitness: Default,
        CBul::NonMembershipWitness: Default,
    {
        assert!(is_bul_data_const == true);
        assert!(is_memb_nmemb_const == (true, true));
        assert!(num_folds > 0);
        use crate::generic::{fold::rerandomize_predicate, scan::scan_method};

        let mut v: Vec<FoldInput<F, U, CBArgs, CBArgsVar, Crypto, Bul, CBul, NUMSCANS>> = vec![];

        let mut u: User<F, U> = self.clone();

        u.zk_fields.com_rand = rng.r#gen();

        let commit = u.commit::<H>();

        let old_nul = u.zk_fields.nul.clone();

        let proof = self.prove_statement_and_in::<H, Rerand<F>, RerandVar<F>, ComRand<F>, ComRandVar<F>, Snark, Bul>(rng, rerandomize_predicate::<H, F, U>, pk, (bul_data.1.clone(), bul_data.0.clone()), is_bul_data_const, Rerand { com: commit, nul: u.zk_fields.nul.clone() } , u.zk_fields.com_rand).unwrap();

        let mut ps_ret = PubScanArgs {
            memb_pub: core::array::from_fn(|_| CBul::MembershipPub::default()),
            is_memb_data_const: is_memb_nmemb_const.0,
            nmemb_pub: core::array::from_fn(|_| CBul::NonMembershipPub::default()),
            is_nmemb_data_const: is_memb_nmemb_const.1,
            cur_time,
            bulletin: cbul.clone(),
            cb_methods: cb_methods.clone(),
        };

        for _ in 0..num_folds {
            let (ps, prs) = u.get_scan_arguments::<CBArgs, CBArgsVar, Crypto, CBul, NUMSCANS>(
                cbul,
                is_memb_nmemb_const,
                cur_time,
                cb_methods.clone(),
            );

            ps_ret = ps.clone();

            let mut new_u = scan_method::<F, U, CBArgs, CBArgsVar, Crypto, CBul, H, NUMSCANS>(
                &u,
                ps,
                prs.clone(),
            );

            new_u.zk_fields.nul = rng.r#gen();
            new_u.zk_fields.com_rand = rng.r#gen();

            v.push(FoldInput {
                user: u.clone(),
                scan_args: prs,
                nul: new_u.zk_fields.nul,
                com_rand: new_u.zk_fields.com_rand,
                memb_witness: bul_data.1.clone(),
            });

            u = new_u.clone();
        }

        *self = u;

        (
            (ps_ret, bul_data.0),
            [commit, cur_time].to_vec(),
            v,
            (commit, old_nul, proof),
        )
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>> User<F, U> {
    /// Produce a commitment to the user object.
    ///
    /// Uses the hash `H` to produce a commitment to the user object. Note that the nonce is
    /// already stored within the user.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use zk_callbacks::zk_object;
    /// # use ark_bn254::Fr;
    /// # use rand::thread_rng;
    /// # use zk_callbacks::impls::hash::Poseidon;
    /// # use zk_callbacks::generic::user::User;
    /// #[zk_object(Fr)]
    /// #[derive(Default)]
    /// struct Data {
    ///     stuff: Fr,
    /// }
    ///
    /// fn main () {
    ///     let mut rng = thread_rng();
    ///     let u = User::create(Data { stuff: Fr::from(3) }, &mut rng);
    ///     let com = u.commit::<Poseidon<2>>();
    /// }
    /// ```
    pub fn commit<H: FieldHash<F>>(&self) -> Com<F> {
        let ser_data = self.data.serialize_elements();
        let ser_fields = self.zk_fields.serialize();
        let full_dat = [ser_data.as_slice(), ser_fields.as_slice()].concat();
        H::hash(&full_dat)
    }

    /// Produce a commitment of `user_var` in-circuit.
    pub fn commit_in_zk<H: FieldHash<F>>(
        user_var: UserVar<F, U>,
    ) -> Result<ComVar<F>, SynthesisError> {
        let ser_data = U::serialize_in_zk(user_var.data)?;
        let ser_fields = user_var.zk_fields.serialize()?;
        let full_dat = [ser_data.as_slice(), ser_fields.as_slice()].concat();

        H::hash_in_zk(&full_dat)
    }
}
