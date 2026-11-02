use crate::{
    crypto::hash::HasherZK,
    generic::{
        bulletin::{CallbackBul, JoinableBulletin, PublicCallbackBul, PublicUserBul, UserBul},
        callbacks::CallbackCom,
        object::{Com, Nul, Time, TimeVar},
        service::ServiceProvider,
        user::{ExecutedMethod, UserData},
    },
    impls::{
        centralized::{
            crypto::{FakeSigPubkey, FakeSigPubkeyVar, NoEnc, NoSigOTP},
            ds::{
                sig::{
                    Signature, bls377_schnorr::Bls377Schnorr, gr_schnorr::GrumpkinSchnorr,
                    jj_schnorr::JubjubSchnorr, uov::BleedingUOV,
                },
                sigrange::SigRangeStore,
            },
        },
        hash::Poseidon,
    },
};
use ark_bls12_377::Fr as Bls377Fr;
use ark_bls12_381::Fr as BlsFr;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::{PrimeField, ToConstraintField};
use ark_grumpkin::Fq as BnFr;
use ark_r1cs_std::{
    alloc::AllocVar, convert::ToConstraintFieldGadget, fields::fp::FpVar, prelude::Boolean,
};
use ark_relations::r1cs::SynthesisError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{
    CryptoRng, Rng, RngCore,
    distributions::{Distribution, Standard},
    thread_rng,
};

/// This is a centralized object storage system, with proofs of membership.
///
/// To add an object, object commitments are signed with a private key associated to the server.
///
/// To prove membership, users will then prove knowledge of a signature that verifies under the
/// public key with their user object commitment.
///
/// Note that this implements [`PublicUserBul`] and [`UserBul`].
#[derive(Clone, Default, Debug)]
pub struct SigObjStore<F: PrimeField + Absorb, S: Signature<F>> {
    privkey: S::Privkey,

    /// The public key to verify object commitments in the bulletin.
    pub pubkey: S::Pubkey,

    /// The object commitments.
    pub coms: Vec<Com<F>>,

    /// The old nullifiers for each object.
    pub old_nuls: Vec<Nul<F>>,

    /// The callback commitments given by the users.
    pub cb_com_lists: Vec<Vec<Com<F>>>,

    /// The signatures on each object.
    pub sigs: Vec<S::Sig>,
}

impl<F: PrimeField + Absorb, S: Signature<F>> SigObjStore<F, S> {
    /// Construct a new SigObjStore.
    ///
    /// Generates a new private key and public key pair.
    pub fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let sk = S::gen_key(rng);
        Self {
            privkey: sk.clone(),
            pubkey: S::get_pubkey(&sk),
            coms: vec![],
            old_nuls: vec![],
            cb_com_lists: vec![],
            sigs: vec![],
        }
    }

    /// Given an already existing database, initialize the store from this database.
    pub fn from(privkey: S::Privkey, db: Vec<(Com<F>, Nul<F>, Vec<Com<F>>, S::Sig)>) -> Self {
        let pubkey = S::get_pubkey(&privkey);
        let coms = db.iter().map(|(c, _, _, _)| c.clone()).collect();
        let old_nuls = db.iter().map(|(_, n, _, _)| n.clone()).collect();
        let cb_com_lists = db.iter().map(|(_, _, l, _)| l.clone()).collect();
        let sigs = db.into_iter().map(|(_, _, _, s)| s).collect();
        Self {
            privkey,
            pubkey,
            coms,
            old_nuls,
            cb_com_lists,
            sigs,
        }
    }

    /// Get the public key.
    pub fn get_pubkey(&self) -> S::Pubkey {
        self.pubkey.clone()
    }

    /// Get the full database.
    pub fn get_db(&self) -> Vec<(Com<F>, Nul<F>, Vec<Com<F>>, S::Sig)> {
        (0..(self.coms.len()))
            .map(|x| {
                (
                    self.coms[x],
                    self.old_nuls[x],
                    self.cb_com_lists[x].clone(),
                    self.sigs[x].clone(),
                )
            })
            .collect()
    }

    /// Rotate keys. Resigns all object commitments with the new key.
    pub fn rotate_key(&mut self, new_key: S::Privkey) -> Result<(), ()> {
        self.pubkey = S::get_pubkey(&new_key);
        self.privkey = new_key;
        let mut rng = thread_rng();
        let mut v = vec![];
        for i in 0..self.coms.len() {
            let out = S::sign(&self.privkey, &mut rng, self.coms[i]);
            match out {
                Some(x) => {
                    v.push(x);
                }
                None => {
                    return Err(());
                }
            }
        }
        self.sigs = v;
        Ok(())
    }

    /// Get the signature of a specific object. Returns None if the object is not contained in the
    /// bulletin.
    pub fn get_signature_of(&self, obj: &Com<F>) -> Option<S::Sig> {
        for (i, c) in self.coms.iter().enumerate() {
            if c == obj {
                return Some(self.sigs[i].clone());
            }
        }
        None
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>, S: Signature<F>> PublicUserBul<F, U>
    for SigObjStore<F, S>
{
    type MembershipWitness = S::Sig;

    type MembershipWitnessVar = S::SigVar;

    type MembershipPub = S::Pubkey;

    type MembershipPubVar = S::PubkeyVar;

    fn verify_in<PubArgs, Snark: ark_snark::SNARK<F>, const NUMCBS: usize>(
        &self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        _args: PubArgs,
        _proof: Snark::Proof,
        _memb_data: Self::MembershipPub,
        _verif_key: &Snark::VerifyingKey,
    ) -> bool {
        for (i, c) in self.coms.iter().enumerate() {
            if c == &object
                && self.old_nuls[i] == old_nul
                && self.cb_com_lists[i] == cb_com_list.to_vec()
            {
                return true;
            }
        }
        false
    }

    fn get_membership_data(&self, object: Com<F>) -> Option<(S::Pubkey, S::Sig)> {
        let sig = self.get_signature_of(&object);
        sig.map(|t| (self.get_pubkey().clone(), t))
    }

    fn enforce_membership_of(
        data_var: crate::generic::object::ComVar<F>,
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        S::verify_zk(extra_pub, extra_witness, data_var)
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>, S: Signature<F>> UserBul<F, U> for SigObjStore<F, S> {
    type Error = ();

    fn has_never_received_nul(&self, nul: &Nul<F>) -> bool {
        for i in &self.old_nuls {
            if i == nul {
                return false;
            }
        }
        true
    }

    fn append_value<PubArgs, Snark: ark_snark::SNARK<F>, const NUMCBS: usize>(
        &mut self,
        object: Com<F>,
        old_nul: Nul<F>,
        cb_com_list: [Com<F>; NUMCBS],
        _args: PubArgs,
        _proof: Snark::Proof,
        _memb_data: Option<Self::MembershipPub>,
        _verif_key: &Snark::VerifyingKey,
    ) -> Result<(), Self::Error> {
        let mut rng = thread_rng();
        let out = S::sign(&self.privkey, &mut rng, object);
        match out {
            Some(x) => {
                self.coms.push(object);
                self.old_nuls.push(old_nul);
                self.cb_com_lists.push(cb_com_list.into());
                self.sigs.push(x);
                Ok(())
            }
            None => Err(()),
        }
    }
}

impl<F: PrimeField + Absorb, U: UserData<F>, S: Signature<F>> JoinableBulletin<F, U>
    for SigObjStore<F, S>
where
    Standard: Distribution<F>,
{
    type PubData = ();

    fn join_bul(
        &mut self,
        object: crate::generic::object::Com<F>,
        _pub_data: (),
    ) -> Result<(), Self::Error> {
        let mut rng = thread_rng();
        let out = S::sign(&self.privkey, &mut rng, object);
        match out {
            Some(x) => {
                self.coms.push(object);
                self.old_nuls.push(rng.r#gen());
                self.cb_com_lists.push(vec![]);
                self.sigs.push(x);
                Ok(())
            }
            None => Err(()),
        }
    }
}

/// This is a centralized nonmembership storage system for tickets.
///
/// Specifically, this trait encompasses nonmembership for plain tickets.
///
///
/// While proofs of membership remain static (a ticket which was once a member will always be a
/// member), this is not true for nonmembership.
///
/// For example, one may have a proof of nonmembership for a ticket at some point in the past, but
/// it could change when the ticket is appended to the bulletin.
///
/// Therefore, this trait also captures the time with the `epoch`. To update all proofs of
/// nonmembership for tickets, one has to call [`NonmembStore::update_epoch`].
///
/// Verifying nonmembership should also account for the epoch. Any nonmembership proof should be
/// unique with respect to the epoch, so any nonmembership witness must encode the information of
/// the epoch.
pub trait NonmembStore<F: PrimeField + Absorb>
where
    Standard: Distribution<F>,
{
    /// A nonmembership witness.
    type NonMembershipWitness: Clone + Default;
    /// A nonmembership witness in-circuit.
    type NonMembershipWitnessVar: Clone + AllocVar<Self::NonMembershipWitness, F>;

    /// Nonmembership public data.
    type NonMembershipPub: Clone + Default;
    /// Nonmembership public data in-circuit.
    type NonMembershipPubVar: Clone + AllocVar<Self::NonMembershipPub, F>;

    /// Construct a new nonmembership store.
    fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self;

    /// Update the epoch.
    ///
    /// This takes in a list of tickets in the bulletin. This should be *all* the tickets in the
    /// bulletin. This will step the epoch and construct new proofs of nonmembership for elements
    /// not in this set.
    fn update_epoch(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        current_store: Vec<FakeSigPubkey<F>>,
    );

    /// Get the current epoch.
    fn get_epoch(&self) -> F;

    /// Get nonmembership data for a specific ticket. If the ticket is a member, this should return
    /// None.
    fn get_nmemb(
        &self,
        tik: &FakeSigPubkey<F>,
    ) -> Option<(Self::NonMembershipPub, Self::NonMembershipWitness)>;

    /// Get the nonmembership public data.
    fn get_nmemb_pub(&self) -> Self::NonMembershipPub;

    /// Return true if the ticket is a non-member, and false if the ticket is a member.
    fn verify_not_in(&self, tik: FakeSigPubkey<F>) -> bool;

    /// Prove nonmembership in-circuit for a ticket. Returns `true` if not a member, and `false` if
    /// a member.
    fn enforce_nonmembership_of(
        tikvar: FakeSigPubkeyVar<F>,
        extra_witness: Self::NonMembershipWitnessVar,
        extra_pub: Self::NonMembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError>;
}

/// A centralized callback storage system with proofs of membership and nonmembership.
///
/// To add a ticket, the ticket is signed by the private key associated to the callback bulletin.
/// Along with this **the ticket is also inserted into a nonmembership store**, which implements
/// [`NonmembStore`].
///
/// To prove membership, users may then prove knowledge of a signature on the callback ticket which verifies under the
/// public key.
///
/// To prove nonmembership, one uses the [`NonmembStore`] circuit.
#[derive(Clone, Default, Debug)]
pub struct CallbackStore<F: PrimeField + Absorb, S: Signature<F>, B: NonmembStore<F>, Args>
where
    Standard: Distribution<F>,
    Args: Clone + ToConstraintField<F>,
{
    privkey: S::Privkey,
    /// The public key for verifying membership of tickets.
    pub pubkey: S::Pubkey,
    /// The called tickets.
    pub memb_called_cbs: Vec<(FakeSigPubkey<F>, Args, Time<F>)>,
    /// The signatures on the called tickets.
    pub memb_cbs_sigs: Vec<S::Sig>,
    /// A nonmembership bulletin for proofs of nonmembership on called tickets.
    pub nmemb_bul: B,
}

impl<F: PrimeField + Absorb, S: Signature<F>, B: NonmembStore<F>, Args> CallbackStore<F, S, B, Args>
where
    Standard: Distribution<F>,
    Args: Clone + ToConstraintField<F>,
{
    /// Construct a new callback store.
    ///
    /// Generates a random public key / private key pair.
    pub fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let sk = S::gen_key(rng);
        Self {
            privkey: sk.clone(),
            pubkey: S::get_pubkey(&sk),
            memb_called_cbs: vec![],
            memb_cbs_sigs: vec![],
            nmemb_bul: B::new(rng),
        }
    }

    /// Given an already existing database and a nonmembership store, initialize the store from
    /// this database.
    pub fn from(
        privkey: S::Privkey,
        db: Vec<(FakeSigPubkey<F>, Args, Time<F>, S::Sig)>,
        nmemb_bul: B,
    ) -> Self {
        let pubkey = S::get_pubkey(&privkey);
        let memb_cbs_sigs = db.iter().map(|(_, _, _, s)| s.clone()).collect();
        let memb_called_cbs = db.into_iter().map(|(t, a, e, _)| (t, a, e)).collect();
        Self {
            privkey,
            pubkey,
            memb_called_cbs,
            memb_cbs_sigs,
            nmemb_bul,
        }
    }

    /// Given an already existing database, initialize the store from this databse.
    ///
    /// This constructs a new nonmembership bulletin, and steps the epoch using the database to
    /// commit all tickets so proofs of nonmembership can be generated. See [`NonmembStore`] for
    /// more information.
    pub fn from_only_memb(
        privkey: S::Privkey,
        db: Vec<(FakeSigPubkey<F>, Args, Time<F>, S::Sig)>,
    ) -> Self {
        let mut rng = thread_rng();

        let mut nmemb_bul = B::new(&mut rng);

        let tiks = db.iter().map(|(t, _, _, _)| t.clone()).collect();

        nmemb_bul.update_epoch(&mut rng, tiks);

        Self::from(privkey, db, nmemb_bul)
    }

    /// Get the public key for membership.
    pub fn get_pubkey(&self) -> S::Pubkey {
        self.pubkey.clone()
    }

    /// Get the database (this is the membership database).
    pub fn get_db(&self) -> Vec<(FakeSigPubkey<F>, Args, Time<F>, S::Sig)> {
        (0..(self.memb_called_cbs.len()))
            .map(|x| {
                (
                    self.memb_called_cbs[x].0.clone(),
                    self.memb_called_cbs[x].1.clone(),
                    self.memb_called_cbs[x].2,
                    self.memb_cbs_sigs[x].clone(),
                )
            })
            .collect()
    }

    /// Rotate the key for membership. All tickets are resigned under the new private key.
    pub fn rotate_key(&mut self, new_key: S::Privkey) -> Result<(), ()> {
        self.pubkey = S::get_pubkey(&new_key);
        self.privkey = new_key;
        let mut rng = thread_rng();
        let mut v = vec![];
        for i in 0..self.memb_called_cbs.len() {
            let mut v2 = vec![];
            v2.push(self.memb_called_cbs[i].0.to());
            v2.extend_from_slice(&self.memb_called_cbs[i].1.to_field_elements().unwrap());
            v2.push(self.memb_called_cbs[i].2);
            let out = S::sign(&self.privkey, &mut rng, <Poseidon<2>>::hash(&v2));

            match out {
                Some(x) => {
                    v.push(x);
                }
                None => {
                    return Err(());
                }
            }
        }

        self.memb_cbs_sigs = v;

        Ok(())
    }

    /// Get a membership witness (a signature) for a specific ticket. If the ticket is not in the
    /// bulletin, this should return None.
    pub fn get_memb_witness(&self, tik: &FakeSigPubkey<F>) -> Option<S::Sig> {
        for (i, (t, _, _)) in (self.memb_called_cbs).iter().enumerate() {
            if t == tik {
                return Some(self.memb_cbs_sigs[i].clone());
            }
        }
        None
    }

    /// Get a nonmembership witness for a ticket. If the ticket is in the bulletin, then this
    /// should return None.
    pub fn get_nmemb_witness(&self, tik: &FakeSigPubkey<F>) -> Option<B::NonMembershipWitness> {
        self.nmemb_bul.get_nmemb(tik).map(|x| x.1)
    }

    /// Get the epoch of the nonmembership bulletin. See [`NonmembStore`] for more details.
    pub fn get_epoch(&self) -> F {
        self.nmemb_bul.get_epoch()
    }

    /// Update the epoch of the nonmembership bulletin with the current tickets in the membership
    /// bulletin.
    ///
    /// This commits any outstanding tickets so proofs of nonmembership can be generated. See
    /// [`NonmembStore`] for more details.
    pub fn update_epoch(&mut self, rng: &mut (impl CryptoRng + RngCore)) {
        self.nmemb_bul.update_epoch(
            rng,
            (self.memb_called_cbs).iter().map(|x| x.0.clone()).collect(),
        );
    }
}

impl<F: PrimeField + Absorb, S: Signature<F>, B: NonmembStore<F>>
    PublicCallbackBul<F, F, NoSigOTP<F>> for CallbackStore<F, S, B, F>
where
    Standard: Distribution<F>,
{
    type MembershipWitness = S::Sig;

    type MembershipWitnessVar = S::SigVar;

    type NonMembershipWitness = B::NonMembershipWitness;

    type NonMembershipWitnessVar = B::NonMembershipWitnessVar;

    type MembershipPub = S::Pubkey;

    type MembershipPubVar = S::PubkeyVar;

    type NonMembershipPub = B::NonMembershipPub;

    type NonMembershipPubVar = B::NonMembershipPubVar;

    fn verify_in(&self, tik: FakeSigPubkey<F>) -> Option<(F, (), Time<F>)> {
        for (t, arg, time) in &self.memb_called_cbs {
            if t == &tik {
                return Some((*arg, (), *time));
            }
        }
        None
    }

    fn verify_not_in(&self, tik: FakeSigPubkey<F>) -> bool {
        self.nmemb_bul.verify_not_in(tik)
    }

    fn get_membership_data(
        &self,
        tik: FakeSigPubkey<F>,
    ) -> (
        S::Pubkey,
        S::Sig,
        B::NonMembershipPub,
        B::NonMembershipWitness,
    ) {
        let d = self.nmemb_bul.get_nmemb(&tik);
        match d {
            Some((p, w)) => (self.get_pubkey(), S::Sig::default(), p, w),
            None => (
                self.get_pubkey(),
                self.get_memb_witness(&tik).unwrap(),
                self.nmemb_bul.get_nmemb_pub(),
                B::NonMembershipWitness::default(),
            ),
        }
    }

    fn enforce_membership_of(
        tikvar: (FakeSigPubkeyVar<F>, FpVar<F>, TimeVar<F>),
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        S::verify_zk(
            extra_pub,
            extra_witness,
            <Poseidon<2>>::hash_in_zk(&[tikvar.0.0, tikvar.1, tikvar.2])?,
        )
    }

    fn enforce_nonmembership_of(
        tikvar: FakeSigPubkeyVar<F>,
        extra_witness: Self::NonMembershipWitnessVar,
        extra_pub: Self::NonMembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        B::enforce_nonmembership_of(tikvar, extra_witness, extra_pub)
    }
}

impl<
    F: PrimeField + Absorb,
    S: Signature<F>,
    B: NonmembStore<F>,
    A: Clone + Default + ToConstraintField<F>,
    AVar: Clone + AllocVar<A, F> + ToConstraintFieldGadget<F>,
> PublicCallbackBul<F, A, NoEnc<F, A, AVar>> for CallbackStore<F, S, B, A>
where
    Standard: Distribution<F>,
{
    type MembershipWitness = S::Sig;

    type MembershipWitnessVar = S::SigVar;

    type NonMembershipWitness = B::NonMembershipWitness;

    type NonMembershipWitnessVar = B::NonMembershipWitnessVar;

    type MembershipPub = S::Pubkey;

    type MembershipPubVar = S::PubkeyVar;

    type NonMembershipPub = B::NonMembershipPub;

    type NonMembershipPubVar = B::NonMembershipPubVar;

    fn verify_in(&self, tik: FakeSigPubkey<F>) -> Option<(A, (), Time<F>)> {
        for (t, arg, time) in &self.memb_called_cbs {
            if t == &tik {
                return Some((arg.clone(), (), *time));
            }
        }
        None
    }

    fn verify_not_in(&self, tik: FakeSigPubkey<F>) -> bool {
        self.nmemb_bul.verify_not_in(tik)
    }

    fn get_membership_data(
        &self,
        tik: FakeSigPubkey<F>,
    ) -> (
        S::Pubkey,
        S::Sig,
        B::NonMembershipPub,
        B::NonMembershipWitness,
    ) {
        let d = self.nmemb_bul.get_nmemb(&tik);
        match d {
            Some((p, w)) => (self.get_pubkey(), S::Sig::default(), p, w),
            None => (
                self.get_pubkey(),
                self.get_memb_witness(&tik).unwrap(),
                self.nmemb_bul.get_nmemb_pub(),
                B::NonMembershipWitness::default(),
            ),
        }
    }

    fn enforce_membership_of(
        tikvar: (FakeSigPubkeyVar<F>, AVar, TimeVar<F>),
        extra_witness: Self::MembershipWitnessVar,
        extra_pub: Self::MembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        let mut v = vec![tikvar.0.0];

        v.extend_from_slice(&tikvar.1.to_constraint_field()?);

        v.push(tikvar.2);

        S::verify_zk(extra_pub, extra_witness, <Poseidon<2>>::hash_in_zk(&v)?)
    }

    fn enforce_nonmembership_of(
        tikvar: FakeSigPubkeyVar<F>,
        extra_witness: Self::NonMembershipWitnessVar,
        extra_pub: Self::NonMembershipPubVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        B::enforce_nonmembership_of(tikvar, extra_witness, extra_pub)
    }
}

impl<F: PrimeField + Absorb, S: Signature<F>, B: NonmembStore<F>> CallbackBul<F, F, NoSigOTP<F>>
    for CallbackStore<F, S, B, F>
where
    Standard: Distribution<F>,
{
    type Error = ();

    fn has_never_received_tik(&self, tik: &FakeSigPubkey<F>) -> bool {
        for (x, _, _) in &self.memb_called_cbs {
            if x == tik {
                return false;
            }
        }
        true
    }

    fn append_value(
        &mut self,
        tik: FakeSigPubkey<F>,
        enc_args: F,
        _signature: (),
        time: Time<F>,
    ) -> Result<(), Self::Error> {
        let mut rng = thread_rng();
        let v2 = vec![tik.to(), enc_args, time];
        let out = S::sign(&self.privkey, &mut rng, <Poseidon<2>>::hash(&v2));

        match out {
            Some(x) => {
                self.memb_called_cbs.push((tik, enc_args, time));
                self.memb_cbs_sigs.push(x);
                Ok(())
            }
            None => Err(()),
        }
    }
}

impl<
    F: PrimeField + Absorb,
    S: Signature<F>,
    B: NonmembStore<F>,
    A: Clone + Default + ToConstraintField<F>,
    AVar: Clone + AllocVar<A, F> + ToConstraintFieldGadget<F>,
> CallbackBul<F, A, NoEnc<F, A, AVar>> for CallbackStore<F, S, B, A>
where
    Standard: Distribution<F>,
{
    type Error = ();

    fn has_never_received_tik(&self, tik: &FakeSigPubkey<F>) -> bool {
        for (x, _, _) in &self.memb_called_cbs {
            if x == tik {
                return false;
            }
        }
        true
    }

    fn append_value(
        &mut self,
        tik: FakeSigPubkey<F>,
        enc_args: A,
        _signature: (),
        time: Time<F>,
    ) -> Result<(), Self::Error> {
        let mut rng = thread_rng();
        let mut v2 = vec![];
        v2.push(tik.to());
        v2.extend_from_slice(&enc_args.to_field_elements().unwrap());
        v2.push(time);
        let out = S::sign(&self.privkey, &mut rng, <Poseidon<2>>::hash(&v2));

        match out {
            Some(x) => {
                self.memb_called_cbs.push((tik, enc_args, time));
                self.memb_cbs_sigs.push(x);
                Ok(())
            }
            None => Err(()),
        }
    }
}

/// A centralized storage system for both objects and tickets.
///
/// This consists of object commitment storage, and callback ticket storage.
///
/// Along with that, the central store stores interactions, and so acts as a centralized service
/// provider *and* both bulletins.
#[derive(Clone)]
pub struct CentralStore<
    F: PrimeField + Absorb,
    S: Signature<F>,
    B: NonmembStore<F>,
    A: Clone + ToConstraintField<F>,
> where
    Standard: Distribution<F>,
{
    /// The object bulletin storing commitments.
    pub obj_bul: SigObjStore<F, S>,

    /// The callback bulletin storing tickets.
    pub callback_bul: CallbackStore<F, S, B, A>,

    /// A list of interactions which have occurred by their interaction id.
    pub interaction_ids: Vec<u64>,
    /// A list of tickets which have not yet been called but handed to the service, each associated
    /// to the interaction id at the same index.
    // pub cb_tickets: Vec<Vec<(CallbackCom<F, F, NoSigOTP<F>>, F)>>,
    pub cb_tickets: Vec<Vec<Vec<u8>>>,
}

impl<F: PrimeField + Absorb, S: Signature<F>, B: NonmembStore<F>>
    ServiceProvider<F, F, FpVar<F>, NoSigOTP<F>> for CentralStore<F, S, B, F>
where
    Standard: Distribution<F>,
{
    type Error = ();
    type InteractionData = u64;

    fn has_never_received_tik(&self, tik: FakeSigPubkey<F>) -> bool {
        for j in &self.cb_tickets {
            for k in j {
                let (a, _) =
                    <(CallbackCom<F, F, NoSigOTP<F>>, F)>::deserialize_compressed(&**k).unwrap();
                if a.cb_entry.tik == tik {
                    return false;
                }
            }
        }
        true
    }

    fn store_interaction<U: UserData<F>, Snark: ark_snark::SNARK<F>, const NUMCBS: usize>(
        &mut self,
        interaction: crate::generic::user::ExecutedMethod<F, Snark, F, NoSigOTP<F>, NUMCBS>,
        data: u64,
    ) -> Result<(), Self::Error> {
        self.interaction_ids.push(data);
        let tiks = interaction.cb_tik_list.to_vec();
        let mut v = vec![];
        for tik in tiks {
            let mut ser = vec![];
            tik.serialize_compressed(&mut ser).map_err(|_| ())?;
            v.push(ser);
        }

        self.cb_tickets.push(v);

        Ok(())
    }
}

impl<F: PrimeField + Absorb, S: Signature<F>, B: NonmembStore<F>> CentralStore<F, S, B, F>
where
    Standard: Distribution<F>,
{
    /// Get a callback ticket (and signature randomness) so the service provider may call the
    /// callback. This gets the ticket from the index in the list. For each interaction, the set of
    /// callbacks is appended to the list.
    ///
    ///- `index` dictates which interaction.
    ///- `which` dictates which callback for that interaction.
    pub fn get_ticket_ind(
        &self,
        index: usize,
        which: usize,
    ) -> (CallbackCom<F, F, NoSigOTP<F>>, F) {
        <(CallbackCom<F, F, NoSigOTP<F>>, F)>::deserialize_compressed(
            &*self.cb_tickets[index][which],
        )
        .unwrap()
    }

    /// Get a callback ticket (and signature randomness) so the service provider may call the
    /// callback. This gets the ticket by the interaction id. Each interaction is associated with
    /// an interaction id, which should be unique. This function is guaranteed to return a proper
    /// and correct ticket if all ids are unique and the id is within this list. If the id
    /// is not in the list, this function panics.
    pub fn get_ticket_id(&self, id: u64, which: usize) -> (CallbackCom<F, F, NoSigOTP<F>>, F) {
        for i in 0..self.interaction_ids.len() {
            if self.interaction_ids[i] == id {
                return self.get_ticket_ind(i, which);
            }
        }
        panic!("No interaction found.");
    }
}

impl<
    F: PrimeField + Absorb,
    S: Signature<F>,
    B: NonmembStore<F>,
    A: Clone + ToConstraintField<F> + Default,
    AVar: AllocVar<A, F> + Clone,
> ServiceProvider<F, A, AVar, NoEnc<F, A, AVar>> for CentralStore<F, S, B, A>
where
    Standard: Distribution<F>,
{
    type Error = ();
    type InteractionData = u64;

    fn has_never_received_tik(&self, tik: FakeSigPubkey<F>) -> bool {
        for j in &self.cb_tickets {
            for k in j {
                let (a, _) =
                    <(CallbackCom<F, A, NoEnc<F, A, AVar>>, F)>::deserialize_compressed(&**k)
                        .unwrap();
                if a.cb_entry.tik == tik {
                    return false;
                }
            }
        }
        true
    }

    fn store_interaction<U: UserData<F>, Snark: ark_snark::SNARK<F>, const NUMCBS: usize>(
        &mut self,
        interaction: ExecutedMethod<F, Snark, A, NoEnc<F, A, AVar>, NUMCBS>,
        data: u64,
    ) -> Result<(), Self::Error> {
        self.interaction_ids.push(data);
        let tiks = interaction.cb_tik_list.to_vec();
        let mut v = vec![];
        for tik in tiks {
            let mut ser = vec![];
            tik.serialize_compressed(&mut ser).map_err(|_| ())?;
            v.push(ser);
        }

        self.cb_tickets.push(v);

        Ok(())
    }
}

impl<
    F: PrimeField + Absorb,
    S: Signature<F>,
    B: NonmembStore<F>,
    A: Clone + ToConstraintField<F> + Default,
> CentralStore<F, S, B, A>
where
    Standard: Distribution<F>,
{
    /// Get a callback ticket (and signature randomness) so the service provider may call the
    /// callback. This gets the ticket from the index in the list. For each interaction, the set of
    /// callbacks is appended to the list.
    ///
    ///- `index` dictates which interaction.
    ///- `which` dictates which callback for that interaction.
    pub fn get_ticket_ind_noenc<AVar: AllocVar<A, F> + Clone>(
        &self,
        index: usize,
        which: usize,
    ) -> (CallbackCom<F, A, NoEnc<F, A, AVar>>, F) {
        <(CallbackCom<F, A, NoEnc<F, A, AVar>>, F)>::deserialize_compressed(
            &*self.cb_tickets[index][which],
        )
        .unwrap()
    }

    /// Get a callback ticket (and signature randomness) so the service provider may call the
    /// callback. This gets the ticket by the interaction id. Each interaction is associated with
    /// an interaction id, which should be unique. This function is guaranteed to return a proper
    /// and correct ticket if all ids are unique and the id is within this list. If the id
    /// is not in the list, this function panics.
    pub fn get_ticket_id_noenc<AVar: AllocVar<A, F> + Clone>(
        &self,
        id: u64,
        which: usize,
    ) -> (CallbackCom<F, A, NoEnc<F, A, AVar>>, F) {
        for i in 0..self.interaction_ids.len() {
            if self.interaction_ids[i] == id {
                return self.get_ticket_ind_noenc(i, which);
            }
        }
        panic!("No interaction found.");
    }
}
impl<F: PrimeField + Absorb, S: Signature<F>, B: NonmembStore<F>, A: Clone + ToConstraintField<F>>
    CentralStore<F, S, B, A>
where
    Standard: Distribution<F>,
{
    /// Construct a new central store.
    pub fn new(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self {
            callback_bul: CallbackStore::new(rng),
            obj_bul: SigObjStore::new(rng),
            interaction_ids: vec![],
            cb_tickets: vec![],
        }
    }
}

/// Type alias for a central store which uses signed ranges for nonmembership.
pub type SigStore<F, S, A> = CentralStore<F, S, SigRangeStore<F, S>, A>;

/// A user object store which uses UOV signatures.
pub type UOVObjStore<F> = SigObjStore<F, BleedingUOV<F>>;

/// A callback storage system which uses UOV signatures.
pub type UOVCallbackStore<F, A> =
    CallbackStore<F, BleedingUOV<F>, SigRangeStore<F, BleedingUOV<F>>, A>;

/// A central storage system which uses UOV signatures.
pub type UOVStore<F, A> = CentralStore<F, BleedingUOV<F>, SigRangeStore<F, BleedingUOV<F>>, A>;

/// A user object store which uses Jubjub BLS Schnorr signatures.
pub type JJSchnorrObjStore = SigObjStore<BlsFr, JubjubSchnorr>;

/// A user object store which uses  BLS377 Schnorr signatures.
pub type BLS377SchnorrObjStore = SigObjStore<Bls377Fr, Bls377Schnorr>;

/// A callback storage system which uses Jubjub BLS Schnorr signatures.
pub type JJSchnorrCallbackStore<A> =
    CallbackStore<BlsFr, JubjubSchnorr, SigRangeStore<BlsFr, JubjubSchnorr>, A>;

/// A central storage system which uses Jubjub BLS Schnorr signatures.
pub type JJSchnorrStore<A> =
    CentralStore<BlsFr, JubjubSchnorr, SigRangeStore<BlsFr, JubjubSchnorr>, A>;

/// A central storage system which uses BLS377 Schnorr signatures.
pub type BLS377SchnorrStore<A> =
    CentralStore<Bls377Fr, Bls377Schnorr, SigRangeStore<Bls377Fr, Bls377Schnorr>, A>;

/// A user object store which uses Grumpkin BN254 Schnorr signatures.
pub type GRSchnorrObjStore = SigObjStore<BnFr, GrumpkinSchnorr>;

/// A callback storage system which uses Grumpkin BN254 Schnorr signatures.
pub type GRSchnorrCallbackStore<A> =
    CallbackStore<BnFr, GrumpkinSchnorr, SigRangeStore<BnFr, GrumpkinSchnorr>, A>;

/// A central storage system which uses Grumpkin BN254 Schnorr signatures.
pub type GRSchnorrStore<A> =
    CentralStore<BnFr, GrumpkinSchnorr, SigRangeStore<BnFr, GrumpkinSchnorr>, A>;
