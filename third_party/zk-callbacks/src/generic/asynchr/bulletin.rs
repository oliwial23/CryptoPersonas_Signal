use crate::{
    crypto::{
        enc::{AECipherSigZK, CPACipher},
        rr::RRVerifier,
    },
    generic::{
        object::{Com, ComVar, Nul, Time, TimeVar},
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

#[derive(Debug, Clone)]
pub enum BulError<E> {
    VerifyError,
    AppendError(E),
}

pub trait PublicUserBul<F: PrimeField + Absorb, U: UserData<F>> {
    type Error;

    type MembershipWitness: Clone + Default;
    type MembershipWitnessVar: AllocVar<Self::MembershipWitness, F> + Clone;
    type MembershipPub: Clone + Default + ToConstraintField<F>;
    type MembershipPubVar: AllocVar<Self::MembershipPub, F> + Clone;

    #[allow(clippy::too_many_arguments)]
    async fn verify_in<PubArgs, Snark: SNARK<F>, const NUMCBS: usize>(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        args: PubArgs,
        proof: Snark::Proof,
        memb_data: Self::MembershipPub,
        verif_key: &Snark::VerifyingKey,
    ) -> bool;

    fn enforce_membership_of(
        data_var: ComVar<F>,
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError>;
}

pub trait UserBul<F: PrimeField + Absorb, U: UserData<F>>: PublicUserBul<F, U> {
    async fn has_never_recieved_nul(&self, nul: &Nul<F>) -> bool;

    #[allow(clippy::too_many_arguments)]
    async fn append_value<PubArgs, Snark: SNARK<F>, const NUMCBS: usize>(
        &mut self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        args: PubArgs,
        proof: Snark::Proof,
        memb_data: Option<Self::MembershipPub>, // membership for the PREVIOUS object, meant to verify the proof: NOT membership for current object
        verif_key: &Snark::VerifyingKey,
    ) -> Result<(), Self::Error>;

    #[allow(clippy::too_many_arguments)]
    async fn verify_interaction<
        PubArgs: ToConstraintField<F>,
        Snark: SNARK<F>,
        const NUMCBS: usize,
    >(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        args: PubArgs,
        cb_com_list: [Com<F>; NUMCBS],
        proof: Snark::Proof,
        memb_data: Option<Self::MembershipPub>,
        verif_key: &Snark::VerifyingKey,
    ) -> bool {
        if !self.has_never_recieved_nul(&old_nul).await {
            return false;
        }

        let mut pub_inputs = vec![object, old_nul];
        pub_inputs.extend::<Vec<F>>(args.to_field_elements().unwrap());
        pub_inputs.extend::<Vec<F>>(cb_com_list.to_field_elements().unwrap());
        if let Some(a) = memb_data {
            pub_inputs.extend::<Vec<F>>(a.to_field_elements().unwrap());
        }

        Snark::verify(verif_key, &pub_inputs, &proof).unwrap_or(false)
    }

    #[allow(clippy::too_many_arguments)]
    async fn verify_interact_and_append<
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
        let out = self
            .verify_interaction::<PubArgs, Snark, NUMCBS>(
                object,
                old_nul,
                args.clone(),
                cb_com_list,
                proof.clone(),
                memb_data.clone(),
                verif_key,
            )
            .await;

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
        .await
        .map_err(BulError::AppendError)?;

        Ok(())
    }
}

pub trait PublicCallbackBul<F: PrimeField, CBArgs: Clone, Crypto: AECipherSigZK<F, CBArgs>> {
    type Error;

    type MembershipWitness: Clone;
    type MembershipWitnessVar: AllocVar<Self::MembershipWitness, F>;
    type NonMembershipWitness: Clone;
    type NonMembershipWitnessVar: AllocVar<Self::NonMembershipWitness, F>;

    type MembershipPub: Clone;
    type MembershipPubVar: AllocVar<Self::MembershipPub, F>;
    type NonMembershipPub: Clone;
    type NonMembershipPubVar: AllocVar<Self::NonMembershipPub, F>;

    async fn verify_in(&self, tik: Crypto::SigPK) -> Option<(Crypto::Ct, Crypto::Sig, Time<F>)>;

    async fn verify_not_in(&self, tik: Crypto::SigPK) -> bool;

    fn enforce_membership_of(
        tikvar: (
            Crypto::SigPKV,
            <Crypto::EncKey as CPACipher<F>>::CV,
            TimeVar<F>,
        ),
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError>;

    fn enforce_nonmembership_of(
        tikvar: Crypto::SigPKV,
        extra_witness: Self::NonMembershipWitnessVar,
        extra_pub: Self::NonMembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError>;

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

pub trait CallbackBulletin<F: PrimeField, CBArgs: Clone, Crypto: AECipherSigZK<F, CBArgs>>:
    PublicCallbackBul<F, CBArgs, Crypto>
{
    async fn has_never_recieved_tik(&self, tik: &Crypto::SigPK) -> bool;

    async fn append_value(
        &mut self,
        tik: Crypto::SigPK,
        enc_args: Crypto::Ct,
        signature: Crypto::Sig,
        time: Time<F>,
    ) -> Result<(), Self::Error>;

    async fn verify_call(
        &self,
        tik: Crypto::SigPK,
        enc_args: Crypto::Ct,
        signature: Crypto::Sig,
    ) -> bool {
        if !self.has_never_recieved_tik(&tik).await {
            return false;
        }
        tik.verify(enc_args.clone(), signature)
    }

    async fn verify_call_and_append(
        &mut self,
        tik: Crypto::SigPK,
        enc_args: Crypto::Ct,
        signature: Crypto::Sig,
        time: Time<F>,
    ) -> Result<(), BulError<Self::Error>> {
        let out = self
            .verify_call(tik.clone(), enc_args.clone(), signature.clone())
            .await;

        if !out {
            return Err(BulError::VerifyError);
        }

        self.append_value(tik, enc_args, signature, time)
            .await
            .map_err(BulError::AppendError)?;

        Ok(())
    }
}

pub trait JoinableBulletin<F: PrimeField + Absorb, U: UserData<F>>: UserBul<F, U> {
    type PubData;

    async fn join_bul(
        &mut self,
        object: Com<F>,
        pub_data: Self::PubData,
    ) -> Result<(), Self::Error>;
}
