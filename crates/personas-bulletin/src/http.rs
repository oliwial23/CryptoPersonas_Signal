//! The as-a-service bulletin: an HTTP view onto the server's centralized store.
//!
//! `BulNet` implements only the *public* halves of the zk-callbacks bulletin traits
//! ([`PublicUserBul`], [`PublicCallbackBul`]) — the ones a client needs to build a
//! membership witness and prove against it. Appending to the bulletin stays server-side.

use std::str::FromStr;

use ark_r1cs_std::prelude::Boolean;
use ark_relations::r1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use ark_snark::SNARK;
use personas_core::{Args, ArgsVar, CStore, Cr, F, OStore, circuits::MsgUser};
use reqwest::{Url, blocking::Client};
use zk_callbacks::{
    generic::{
        bulletin::{PublicCallbackBul, PublicUserBul},
        object::{Com, ComVar, Nul, Time, TimeVar},
    },
    impls::centralized::crypto::{FakeSigPubkey, FakeSigPubkeyVar, NoSigOTP},
};

/// The object bulletin, as served: `(commitment, old nullifier, callback coms, membership witness)`.
type UserBulletin<W> = Vec<(Com<F>, Nul<F>, Vec<Com<F>>, W)>;

/// The callback bulletin, as served: `(ticket, args, time, membership witness)`.
type CallbackBulletin<W> = Vec<(FakeSigPubkey<F>, Args, Time<F>, W)>;

#[derive(Debug, Clone)]
pub struct BulNet {
    pub client: Client,
    pub api: Url,
}

impl Default for BulNet {
    fn default() -> Self {
        Self {
            client: Client::default(),
            api: Url::from_str("https://example.net").unwrap(),
        }
    }
}

impl BulNet {
    pub fn new(api: Url) -> Self {
        Self {
            client: Client::new(),
            api,
        }
    }

    /// GET `route` and canonical-deserialize the body.
    ///
    /// Panics on any failure: a client that cannot read the bulletin cannot produce a
    /// proof at all, and every caller is inside a zk-callbacks trait method whose
    /// signature has no error channel.
    fn get<T: CanonicalDeserialize>(&self, route: &str, validate: Validate) -> T {
        let url = self
            .api
            .join(route)
            .unwrap_or_else(|e| panic!("bulletin route {route} is not a valid URL: {e}"));

        let bytes = self
            .client
            .get(url)
            .send()
            .unwrap_or_else(|e| panic!("bulletin GET {route} failed: {e}"))
            .bytes()
            .unwrap_or_else(|e| panic!("bulletin GET {route} returned no body: {e}"));

        T::deserialize_with_mode(&*bytes, Compress::No, validate)
            .unwrap_or_else(|e| panic!("bulletin GET {route} returned undecodable data: {e}"))
    }

    pub fn join_bul(&self, object: Com<F>) -> Result<(), String> {
        let url = self.api.join("api/user/join").map_err(|e| e.to_string())?;

        // A join is a record — the member's committed object — so it travels in the same
        // versioned envelope as everything else they will later post.
        let bytes = personas_wire::encode_one(personas_wire::Kind::Join, &object)
            .map_err(|e| e.to_string())?;

        let res = self
            .client
            .post(url)
            .header("Content-Type", "application/octet-stream")
            .body(bytes)
            .send()
            .map_err(|e| e.to_string())?;

        if res.status().is_success() {
            Ok(())
        } else {
            Err(format!("Join failed with status {}", res.status()))
        }
    }

    pub fn post(
        &self,
        endpoint: &str,
        payload: Vec<u8>,
    ) -> Result<reqwest::blocking::Response, reqwest::Error> {
        let url = self.api.join(endpoint).expect("Invalid endpoint");
        self.client.post(url).body(payload).send()
    }
}

impl PublicUserBul<F, MsgUser> for BulNet {
    type MembershipWitness = <OStore as PublicUserBul<F, MsgUser>>::MembershipWitness;

    type MembershipWitnessVar = <OStore as PublicUserBul<F, MsgUser>>::MembershipWitnessVar;

    type MembershipPub = <OStore as PublicUserBul<F, MsgUser>>::MembershipPub;

    type MembershipPubVar = <OStore as PublicUserBul<F, MsgUser>>::MembershipPubVar;

    fn verify_in<PubArgs, Snark: SNARK<F>, const NUMCBS: usize>(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        _args: PubArgs,
        _proof: Snark::Proof,
        _memb_data: Self::MembershipPub,
        _verif_key: &Snark::VerifyingKey,
    ) -> bool {
        let db: UserBulletin<Self::MembershipWitness> =
            self.get("api/user/bulletin", Validate::Yes);

        db.iter()
            .any(|(c, n, l, _)| *c == object && *n == old_nul && *l == cb_com_list)
    }

    fn get_membership_data(
        &self,
        object: Com<F>,
    ) -> Option<(Self::MembershipPub, Self::MembershipWitness)> {
        let key: Self::MembershipPub = self.get("api/user/pubkey", Validate::No);
        let db: UserBulletin<Self::MembershipWitness> =
            self.get("api/user/bulletin", Validate::Yes);

        db.iter()
            .find(|(c, _, _, _)| *c == object)
            .map(|(_, _, _, s)| (key, s.clone()))
    }

    fn enforce_membership_of(
        data_var: ComVar<F>,
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        <OStore as PublicUserBul<F, MsgUser>>::enforce_membership_of(
            data_var,
            extra_witness,
            extra_pub,
        )
    }
}

impl PublicCallbackBul<F, Args, Cr> for BulNet {
    type MembershipWitness = <CStore as PublicCallbackBul<F, F, NoSigOTP<F>>>::MembershipWitness;

    type MembershipWitnessVar = <CStore as PublicCallbackBul<F, Args, Cr>>::MembershipWitnessVar;

    type NonMembershipWitness = <CStore as PublicCallbackBul<F, Args, Cr>>::NonMembershipWitness;

    type NonMembershipWitnessVar =
        <CStore as PublicCallbackBul<F, Args, Cr>>::NonMembershipWitnessVar;

    type MembershipPub = <CStore as PublicCallbackBul<F, Args, Cr>>::MembershipPub;

    type MembershipPubVar = <CStore as PublicCallbackBul<F, Args, Cr>>::MembershipPubVar;

    type NonMembershipPub = <CStore as PublicCallbackBul<F, Args, Cr>>::NonMembershipPub;

    type NonMembershipPubVar = <CStore as PublicCallbackBul<F, Args, Cr>>::NonMembershipPubVar;

    fn verify_in(&self, tik: FakeSigPubkey<F>) -> Option<(Args, (), Time<F>)> {
        let db: CallbackBulletin<Self::MembershipWitness> =
            self.get("api/callbacks/bulletin", Validate::Yes);

        db.iter()
            .find(|(t, _, _, _)| *t == tik)
            .map(|(_, arg, time, _)| (*arg, (), *time))
    }

    fn verify_not_in(&self, tik: FakeSigPubkey<F>) -> bool {
        let db: CallbackBulletin<Self::MembershipWitness> =
            self.get("api/callbacks/bulletin", Validate::Yes);

        !db.iter().any(|(t, _, _, _)| *t == tik)
    }

    fn get_membership_data(
        &self,
        tik: FakeSigPubkey<F>,
    ) -> (
        Self::MembershipPub,
        Self::MembershipWitness,
        Self::NonMembershipPub,
        Self::NonMembershipWitness,
    ) {
        let mkey: Self::MembershipPub = self.get("api/callbacks/membership_pubkey", Validate::Yes);
        let nkey: Self::NonMembershipPub =
            self.get("api/callbacks/nonmembership_pubkey", Validate::Yes);

        let db: CallbackBulletin<Self::MembershipWitness> =
            self.get("api/callbacks/bulletin", Validate::Yes);

        // The ticket was called back: prove membership, and leave the nonmembership
        // witness at its default (the scan circuit selects on one or the other).
        if let Some((_, _, _, s)) = db.iter().find(|(t, _, _, _)| *t == tik) {
            return (mkey, s.clone(), nkey, Self::NonMembershipWitness::default());
        }

        // Otherwise it was never called back: find the range leaf that brackets it.
        let nbul: Vec<Self::NonMembershipWitness> =
            self.get("api/callbacks/nmemb_bulletin", Validate::Yes);

        for r in nbul.iter() {
            if r.is_in_range(tik.to()) {
                return (mkey, Self::MembershipWitness::default(), nkey, r.clone());
            }
        }

        panic!(
            "callback bulletin is inconsistent: ticket is neither called back nor covered \
             by a nonmembership range"
        );
    }

    fn enforce_membership_of(
        tikvar: (FakeSigPubkeyVar<F>, ArgsVar, TimeVar<F>),
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        <CStore as PublicCallbackBul<F, Args, Cr>>::enforce_membership_of(
            tikvar,
            extra_witness,
            extra_pub,
        )
    }

    fn enforce_nonmembership_of(
        tikvar: FakeSigPubkeyVar<F>,
        extra_witness: Self::NonMembershipWitnessVar,
        extra_pub: Self::NonMembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        <CStore as PublicCallbackBul<F, Args, Cr>>::enforce_nonmembership_of(
            tikvar,
            extra_witness,
            extra_pub,
        )
    }
}
