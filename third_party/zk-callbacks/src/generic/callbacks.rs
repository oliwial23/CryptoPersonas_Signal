use crate::{
    crypto::{
        enc::{AECipherSigZK, CPACipher},
        hash::FieldHash,
        rr::RRVerifier,
    },
    generic::{
        interaction::Interaction,
        object::{
            CBHash, CBHashVar, Com, ComRand, ComRandVar, ComVar, Id, IdVar, Ser, SerVar, Time,
            TimeVar,
        },
        user::UserData,
    },
};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::{PrimeField, ToConstraintField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    boolean::Boolean,
    convert::ToConstraintFieldGadget,
};
use ark_relations::{
    ns,
    r1cs::{Namespace, SynthesisError},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{CryptoRng, Rng, RngCore, distributions::Standard, prelude::Distribution};
use std::borrow::Borrow;

/// A callback ticket consists of all the data stored within a user associated to a callback.
///
/// This is the object given to a service when providing a callback. This allows the service to
/// force a function call on the user object.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Default)]
pub struct CallbackTicket<F: PrimeField + Absorb, Args: Clone, Crypto: AECipherSigZK<F, Args>> {
    /// The random ticket. This is the base part of the callback ticket -- this is the random value
    /// handed to the service which can then later be published to call the function.
    ///
    /// Note that this is a public key; this way, a service may use the rerandomized public key to
    /// sign arguments, so users are ensured that arguments are authentic.
    pub tik: Crypto::SigPK,
    /// The ID for the callback. This is what determines what function is called. If the function
    /// must remain private as well, then the function ID must be passed in as an argument in zero
    /// knowledge. This determines what function can be called by this ticket.
    pub cb_method_id: Id<F>,
    /// Does this ticket expire.
    pub expirable: bool,
    /// What time does this callback expire.
    pub expiration: Time<F>,
    /// A unique random encryption key to hide the arguments when the server calls the callback.
    pub enc_key: Crypto::EncKey,
}

/// In-circuit representation of a callback ticket.
///
/// See [`CallbackTicket`](`CallbackTicket`) for more information.
#[derive(Clone)]
pub struct CallbackTicketVar<F: PrimeField + Absorb, Args: Clone, Crypto: AECipherSigZK<F, Args>> {
    /// In circuit representation of the ticket.
    pub tik: Crypto::SigPKV,
    /// In circuit representation of the method id.
    pub cb_method_id: IdVar<F>,
    /// In circuit representation of the expirable status of the ticket.
    pub expirable: Boolean<F>,
    /// In circuit representation of the expiration time.
    pub expiration: TimeVar<F>,
    /// In circuit representation of the encryption key.
    pub enc_key: Crypto::EncKeyVar,
}

impl<Args: Clone, Crypto: AECipherSigZK<F, Args>, F: PrimeField + Absorb>
    CallbackTicket<F, Args, Crypto>
{
    /// Serialize a callback into field elements.
    pub fn serialize(&self) -> Vec<Ser<F>> {
        [
            self.tik.to_field_elements().unwrap(),
            self.cb_method_id.to_field_elements().unwrap(),
            self.expirable.to_field_elements().unwrap(),
            self.expiration.to_field_elements().unwrap(),
            self.enc_key.to_field_elements().unwrap(),
        ]
        .concat()
    }
}

impl<Args: Clone, Crypto: AECipherSigZK<F, Args>, F: PrimeField + Absorb>
    CallbackTicketVar<F, Args, Crypto>
{
    /// Serialize a callback into field elements in-circuit.
    pub fn serialize(&self) -> Result<Vec<SerVar<F>>, SynthesisError> {
        Ok([
            self.tik.to_constraint_field()?,
            self.cb_method_id.to_constraint_field()?,
            self.expirable.to_constraint_field()?,
            self.expiration.to_constraint_field()?,
            self.enc_key.to_constraint_field()?,
        ]
        .concat())
    }
}

impl<Args: Clone, Crypto: AECipherSigZK<F, Args>, F: PrimeField + Absorb>
    AllocVar<CallbackTicket<F, Args, Crypto>, F> for CallbackTicketVar<F, Args, Crypto>
{
    fn new_variable<K: Borrow<CallbackTicket<F, Args, Crypto>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<K, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();
        res.and_then(|rec| {
            let rec = rec.borrow();
            let tik = Crypto::SigPKV::new_variable(ns!(cs, "tik"), || Ok(rec.tik.clone()), mode)?;
            let cb_method_id =
                IdVar::new_variable(ns!(cs, "cb_method_id"), || Ok(rec.cb_method_id), mode)?;

            let expirable =
                Boolean::new_variable(ns!(cs, "expirable"), || Ok(rec.expirable), mode)?;

            let expiration =
                TimeVar::new_variable(ns!(cs, "expiration"), || Ok(rec.expiration), mode)?;

            let enc_key = Crypto::EncKeyVar::new_variable(
                ns!(cs, "enc_key"),
                || Ok(rec.enc_key.clone()),
                mode,
            )?;

            Ok(CallbackTicketVar {
                tik,
                cb_method_id,
                expirable,
                expiration,
                enc_key,
            })
        })
    }
}

/// A full callback ticket object, which can be committed to.
///
/// Represents an *opened* callback commitment. Contains the ticket information, as well as
/// commitment randomness.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Default)]
pub struct CallbackCom<F: PrimeField + Absorb, Args: Clone, Crypto: AECipherSigZK<F, Args>> {
    /// The callback ticket.
    pub cb_entry: CallbackTicket<F, Args, Crypto>,
    /// The commitment randomness from the opened commitment.
    pub com_rand: ComRand<F>,
}

impl<F: PrimeField + Absorb, Args: Clone, Crypto: AECipherSigZK<F, Args>>
    CallbackCom<F, Args, Crypto>
{
    /// Get the underlying random ticket from the opened callback commitment.
    pub fn get_ticket(&self) -> Crypto::SigPK {
        self.cb_entry.tik.clone()
    }
}

/// An in-circuit representation of an opened callback commitment.
///
/// See [`CallbackCom`](`CallbackCom`) for more details.
#[derive(Clone)]
pub struct CallbackComVar<F: PrimeField + Absorb, Args: Clone, Crypto: AECipherSigZK<F, Args>> {
    /// The callback ticket in-circuit.
    pub cb_entry: CallbackTicketVar<F, Args, Crypto>,
    /// The commitment randomness in-circuit.
    pub com_rand: ComRandVar<F>,
}

impl<Args: Clone, Crypto: AECipherSigZK<F, Args>, F: PrimeField + Absorb>
    CallbackCom<F, Args, Crypto>
{
    /// Produce a commitment to the callback entry.
    ///
    /// Uses the hash `H` to produce a commitment. Note that the nonce is already stored within the
    /// callback entry.
    pub fn commit<H: FieldHash<F>>(&self) -> Com<F> {
        let ser_fields = self.cb_entry.serialize();
        let com_rand_ser = self.com_rand.to_field_elements().unwrap();
        let full_dat = [ser_fields.as_slice(), com_rand_ser.as_slice()].concat();
        H::hash(&full_dat)
    }

    /// Produce a commitment of `cb_var` in-circuit.
    pub fn commit_in_zk<H: FieldHash<F>>(
        cb_var: CallbackComVar<F, Args, Crypto>,
    ) -> Result<ComVar<F>, SynthesisError> {
        let ser_fields = cb_var.cb_entry.serialize()?;
        let com_rand_ser = cb_var.com_rand.to_constraint_field()?;

        let full_dat = [ser_fields.as_slice(), com_rand_ser.as_slice()].concat();
        H::hash_in_zk(&full_dat)
    }
}

impl<Args: Clone, Crypto: AECipherSigZK<F, Args>, F: PrimeField + Absorb>
    AllocVar<CallbackCom<F, Args, Crypto>, F> for CallbackComVar<F, Args, Crypto>
{
    fn new_variable<K: Borrow<CallbackCom<F, Args, Crypto>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<K, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let res = f();
        res.and_then(|rec| {
            let rec = rec.borrow();
            let cb_entry = CallbackTicketVar::new_variable(
                ns!(cs, "cb_entry"),
                || Ok(rec.cb_entry.clone()),
                mode,
            )?;

            let com_rand =
                ComRandVar::new_variable(ns!(cs, "com_rand"), || Ok(rec.com_rand), mode)?;

            Ok(CallbackComVar { cb_entry, com_rand })
        })
    }
}

type CBList<F, Crypto, Args, const NUMCBS: usize> = [(
    CallbackCom<F, Args, Crypto>,
    <Crypto as AECipherSigZK<F, Args>>::Rand,
); NUMCBS];

pub(crate) fn create_defaults<
    F: PrimeField + Absorb,
    U: UserData<F>,
    PubArgs: Clone,
    PubArgsVar: AllocVar<PubArgs, F>,
    PrivArgs: Clone,
    PrivArgsVar: AllocVar<PrivArgs, F>,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs>,
    const NUMCBS: usize,
>(
    interaction: Interaction<
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
    pub_cur_time: Time<F>,
) -> [CallbackCom<F, CBArgs, Crypto>; NUMCBS] {
    interaction
        .callbacks
        .iter()
        .map(|cb| {
            let ticket_value = Crypto::SigPK::default();
            let enc_key: Crypto::EncKey = Crypto::EncKey::default();
            let com_rand = F::zero();

            let cb_data: CallbackTicket<F, CBArgs, Crypto> = CallbackTicket {
                tik: ticket_value,
                cb_method_id: cb.method_id,
                expirable: cb.expirable,
                expiration: cb.expiration + pub_cur_time,
                enc_key,
            };

            CallbackCom {
                cb_entry: cb_data,
                com_rand,
            }
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap_or_else(|_| panic!("Failed to create defaults."))
}

pub(crate) fn create_cbs_from_interaction<
    F: PrimeField + Absorb,
    U: UserData<F>,
    PubArgs: Clone + std::fmt::Debug,
    PubArgsVar: AllocVar<PubArgs, F>,
    PrivArgs: Clone + std::fmt::Debug,
    PrivArgsVar: AllocVar<PrivArgs, F>,
    CBArgs: Clone + std::fmt::Debug,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs>,
    const NUMCBS: usize,
>(
    rng: &mut (impl CryptoRng + RngCore),
    interaction: Interaction<
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
    rpk_identities: [Crypto::SigPK; NUMCBS],
    cur_time: Time<F>,
) -> CBList<F, Crypto, CBArgs, NUMCBS>
where
    Standard: Distribution<F>,
{
    interaction
        .callbacks
        .iter()
        .enumerate()
        .map(|(i, cb)| {
            let (rand, ticket_value) = rpk_identities[i].rerand(rng);
            let enc_key = Crypto::EncKey::keygen(rng);
            let com_rand = rng.r#gen::<F>();

            let cb_data: CallbackTicket<F, CBArgs, Crypto> = CallbackTicket {
                tik: ticket_value,
                cb_method_id: cb.method_id,
                expirable: cb.expirable,
                expiration: cb.expiration + cur_time,
                enc_key,
            };

            let cb = CallbackCom {
                cb_entry: cb_data,
                com_rand,
            };
            (cb, rand)
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

pub(crate) fn add_ticket_to_hc<
    F: PrimeField + Absorb,
    H: FieldHash<F>,
    Args: Clone,
    Crypto: AECipherSigZK<F, Args>,
>(
    hash_chain: CBHash<F>,
    ticket: CallbackTicket<F, Args, Crypto>,
) -> CBHash<F> {
    let serialized_ticket = ticket.serialize();
    H::hash(&[&[hash_chain], serialized_ticket.as_slice()].concat())
}

pub(crate) fn add_ticket_to_hc_zk<
    F: PrimeField + Absorb,
    H: FieldHash<F>,
    Args: Clone,
    Crypto: AECipherSigZK<F, Args>,
>(
    hash_chain: &mut CBHashVar<F>,
    ticket: CallbackTicketVar<F, Args, Crypto>,
) -> Result<(), SynthesisError> {
    let ser_ticket = ticket.serialize()?;
    let ser_hc = hash_chain.to_constraint_field()?;

    let full_dat = [ser_hc.as_slice(), ser_ticket.as_slice()].concat();

    *hash_chain = H::hash_in_zk(&full_dat)?;

    Ok(())
}
