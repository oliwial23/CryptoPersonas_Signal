use crate::{
    crypto::enc::{AECipherSigZK, CPACipher},
    generic::{
        bulletin::{CallbackBul, JoinableBulletin, PublicCallbackBul, PublicUserBul, UserBul},
        object::{Com, Time, TimeVar},
        service::ServiceProvider,
        user::UserData,
    },
};
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, prelude::Boolean};
use ark_relations::r1cs::SynthesisError;

/// A dummy store. This is a testing object which implements all bulletins.
///
/// All possible user objects are contained within the dummy store, and there are zero callback
/// tickets in the dummy store. Proving membership of a user amounts to no constraints as it is
/// always true, and proving membership / nonmembership of a callback ticket is similarly no
/// constraints (as all callbacks are not in the store).
#[derive(Clone, Default)]
pub struct DummyStore;

impl<F: PrimeField + Absorb, U: UserData<F>> PublicUserBul<F, U> for DummyStore {
    type MembershipPub = ();
    type MembershipWitness = ();

    type MembershipPubVar = ();
    type MembershipWitnessVar = ();

    fn verify_in<Args, Snark: ark_snark::SNARK<F>, const NUMCBS: usize>(
        &self,
        _object: crate::generic::object::Com<F>,
        _old_nul: crate::generic::object::Nul<F>,
        _cb_com_list: [crate::generic::object::Com<F>; NUMCBS],
        _args: Args,
        _proof: Snark::Proof,
        _memb_data: Self::MembershipPub,
        _verif_key: &Snark::VerifyingKey,
    ) -> bool {
        true
    }

    fn get_membership_data(&self, _object: Com<F>) -> Option<((), ())> {
        Some(((), ()))
    }

    fn enforce_membership_of(
        _data_var: crate::generic::object::ComVar<F>,
        _extra_witness: Self::MembershipWitnessVar,
        _extra_pub: Self::MembershipPubVar,
    ) -> Result<Boolean<F>, ark_relations::r1cs::SynthesisError> {
        Ok(Boolean::TRUE)
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>> UserBul<F, U> for DummyStore {
    type Error = ();

    fn has_never_received_nul(&self, _nul: &crate::generic::object::Nul<F>) -> bool {
        true
    }

    fn append_value<Args, Snark: ark_snark::SNARK<F>, const NUMCBS: usize>(
        &mut self,
        _object: crate::generic::object::Com<F>,
        _old_nul: crate::generic::object::Nul<F>,
        _cb_com_list: [crate::generic::object::Com<F>; NUMCBS],
        _args: Args,
        _proof: Snark::Proof,
        _memb_data: Option<Self::MembershipPub>,
        _verif_key: &Snark::VerifyingKey,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>> JoinableBulletin<F, U> for DummyStore {
    type PubData = ();

    fn join_bul(
        &mut self,
        _object: crate::generic::object::Com<F>,
        _pub_data: (),
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl<F: PrimeField + Absorb, Args: Clone, Crypto: AECipherSigZK<F, Args>>
    PublicCallbackBul<F, Args, Crypto> for DummyStore
{
    type MembershipPub = ();
    type MembershipPubVar = ();
    type MembershipWitness = ();
    type MembershipWitnessVar = ();
    type NonMembershipPub = ();
    type NonMembershipPubVar = ();
    type NonMembershipWitness = ();
    type NonMembershipWitnessVar = ();

    fn verify_in(
        &self,
        _tik: <Crypto as AECipherSigZK<F, Args>>::SigPK,
    ) -> Option<(
        <Crypto as AECipherSigZK<F, Args>>::Ct,
        <Crypto as AECipherSigZK<F, Args>>::Sig,
        Time<F>,
    )> {
        None
    }

    fn verify_not_in(&self, _tik: <Crypto as AECipherSigZK<F, Args>>::SigPK) -> bool {
        true
    }

    fn get_membership_data(
        &self,
        _tik: <Crypto as AECipherSigZK<F, Args>>::SigPK,
    ) -> ((), (), (), ()) {
        ((), (), (), ())
    }

    fn enforce_membership_of(
        _tikvar: (
            <Crypto as AECipherSigZK<F, Args>>::SigPKV,
            <Crypto::EncKey as CPACipher<F>>::CV,
            TimeVar<F>,
        ),
        _extra_witness: Self::MembershipWitnessVar,
        _extra_pub: Self::MembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        Ok(Boolean::FALSE)
    }

    fn enforce_nonmembership_of(
        _tikvar: <Crypto as AECipherSigZK<F, Args>>::SigPKV,
        _extra_witness: Self::NonMembershipWitnessVar,
        _extra_pub: Self::NonMembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        Ok(Boolean::TRUE)
    }
}

impl<F: PrimeField + Absorb, Args: Clone, Crypto: AECipherSigZK<F, Args>>
    CallbackBul<F, Args, Crypto> for DummyStore
{
    type Error = ();

    fn has_never_received_tik(&self, _tik: &<Crypto as AECipherSigZK<F, Args>>::SigPK) -> bool {
        true
    }

    fn append_value(
        &mut self,
        _tik: <Crypto as AECipherSigZK<F, Args>>::SigPK,
        _enc_args: <Crypto as AECipherSigZK<F, Args>>::Ct,
        _sig: <Crypto as AECipherSigZK<F, Args>>::Sig,
        _time: Time<F>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl<
    F: PrimeField + Absorb,
    Args: Clone,
    ArgsVar: AllocVar<Args, F>,
    Crypto: AECipherSigZK<F, Args>,
> ServiceProvider<F, Args, ArgsVar, Crypto> for DummyStore
{
    type Error = ();
    type InteractionData = ();

    fn has_never_received_tik(&self, _ticket: Crypto::SigPK) -> bool {
        true
    }

    fn store_interaction<U: UserData<F>, Snark: ark_snark::SNARK<F>, const NUMCBS: usize>(
        &mut self,
        _interaction: crate::generic::user::ExecutedMethod<F, Snark, Args, Crypto, NUMCBS>,
        _data: (),
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}
