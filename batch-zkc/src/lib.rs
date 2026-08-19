use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::Field;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField, ToConstraintField};
use ark_grumpkin::Affine as GA;
use ark_grumpkin::Projective as G;
use ark_grumpkin::constraints::GVar;
use ark_grumpkin::{Fq as F, Fr};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::alloc::AllocationMode;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::ns;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_relations::r1cs::ConstraintSystem;
use ark_relations::r1cs::ConstraintSystemRef;
use ark_relations::r1cs::Namespace;
use ark_relations::r1cs::Result as ArkResult;
use ark_relations::r1cs::SynthesisError;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use rand::Rng;
use rand::thread_rng;
use rand::{CryptoRng, RngCore, distributions::Standard, prelude::Distribution};
use std::borrow::Borrow;
use std::marker::PhantomData;
use std::ops::Mul;
use std::ops::{Deref, DerefMut};
use zk_callbacks::crypto::enc::AECipherSigZK;
use zk_callbacks::crypto::hash::FieldHash;
use zk_callbacks::generic::bulletin::PublicUserBul;
use zk_callbacks::generic::callbacks::CallbackCom;
use zk_callbacks::generic::callbacks::CallbackComVar;
use zk_callbacks::generic::callbacks::CallbackTicket;
use zk_callbacks::generic::interaction::Interaction;
use zk_callbacks::generic::object::ComVar;
use zk_callbacks::generic::object::Ser;
use zk_callbacks::generic::object::SerVar;
use zk_callbacks::generic::object::{Com, Nul};
use zk_callbacks::generic::user::ExecutedMethod;
use zk_callbacks::generic::user::UserData;
use zk_callbacks::generic::{object::Time, user::User};

pub struct BatchUser<U: UserData<F>> {
    pub user: User<F, U>,
    pub(crate) outstanding_batched_callbacks: Vec<(Fr, usize)>,
    pub(crate) validated_batched_callbacks: Vec<G>,
    pub(crate) pointer: usize,
    pub(crate) valid_pointer: usize,
}

impl<U: UserData<F>> BatchUser<U> {
    pub fn create(user: User<F, U>) -> Self {
        Self {
            user,
            outstanding_batched_callbacks: vec![],
            validated_batched_callbacks: vec![],
            pointer: 0,
            valid_pointer: 0,
        }
    }

    /// Rebuild a `BatchUser` from previously-exported bookkeeping (see the
    /// `*_batched_callbacks`/`pointer`/`valid_pointer` accessors below), so a caller
    /// can persist ticket-request state across separate process invocations instead
    /// of requesting and redeeming within one call.
    pub fn from_parts(
        user: User<F, U>,
        outstanding_batched_callbacks: Vec<(Fr, usize)>,
        validated_batched_callbacks: Vec<G>,
        pointer: usize,
        valid_pointer: usize,
    ) -> Self {
        Self {
            user,
            outstanding_batched_callbacks,
            validated_batched_callbacks,
            pointer,
            valid_pointer,
        }
    }

    /// Tickets that have been blindly issued (`batch_issue_tickets`) but not yet
    /// validated (`store_validated_tickets`) — each is `(blind factor, index into
    /// `self.user`'s callback list)`.
    pub fn outstanding_batched_callbacks(&self) -> &[(Fr, usize)] {
        &self.outstanding_batched_callbacks
    }

    /// Tickets that have been validated and are ready to redeem
    /// (`use_validated_ticket`) — the deblinded curve points.
    pub fn validated_batched_callbacks(&self) -> &[G] {
        &self.validated_batched_callbacks
    }

    /// How many of `outstanding_batched_callbacks` have already been validated.
    pub fn pointer(&self) -> usize {
        self.pointer
    }

    /// How many of `validated_batched_callbacks` have already been redeemed.
    pub fn valid_pointer(&self) -> usize {
        self.valid_pointer
    }
}

impl<U: UserData<F>> Deref for BatchUser<U> {
    type Target = User<F, U>;

    fn deref(&self) -> &Self::Target {
        &self.user
    }
}

impl<U: UserData<F>> DerefMut for BatchUser<U> {
    fn deref_mut(&mut self) -> &mut User<F, U> {
        &mut self.user
    }
}

impl<U: UserData<F>> BatchUser<U>
where
    Standard: Distribution<F>,
{
    pub fn batch_issue_tickets<
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
        const BATCHSIZE: usize,
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
            BATCHSIZE,
        >,
        rpks: [Crypto::SigPK; BATCHSIZE],
        cur_time: Time<F>,
        bul_data: (Bul::MembershipPub, Bul::MembershipWitness),
        is_memb_data_const: bool,
        pk: &Snark::ProvingKey,
        pkb: &Snark::ProvingKey,
        pub_args: PubArgs,
        priv_args: PrivArgs,
        is_scan: bool,
    ) -> Result<BatchExecutedMethod<Snark, CBArgs, Crypto, BATCHSIZE>, SynthesisError> {
        let old = self.num_outstanding_callbacks();

        let res_exec_method = self.user.interact::<H, PubArgs, PubArgsVar, PrivArgs, PrivArgsVar, CBArgs, CBArgsVar, Crypto, Snark, Bul, BATCHSIZE>(
            rng,
            method,
            rpks,
            cur_time,
            bul_data,
            is_memb_data_const,
            pk,
            pub_args,
            priv_args,
            is_scan,
        )?;

        let mut vec_blinds: Vec<Fr> = vec![];

        let mut blind_tiks: Vec<G> = vec![];

        for i in 0..BATCHSIZE {
            vec_blinds.push(rng.r#gen::<Fr>());
            let hashed = hash_to_curve::<H>(&res_exec_method.cb_tik_list[i].0.cb_entry.serialize());
            blind_tiks.push(hashed * vec_blinds[i]);
        }

        let cb_arr = res_exec_method
            .cb_tik_list
            .iter()
            .map(|(x, _)| x.clone())
            .collect::<Vec<_>>();

        let batch_tik_circuit = BatchTicketCircuit {
            priv_issued_callbacks: cb_arr.try_into().unwrap(),
            priv_blinds: vec_blinds.clone().try_into().unwrap(),
            pub_cb_commitments: res_exec_method.cb_com_list,
            pub_new_com: res_exec_method.new_object,
            pub_blinded_tickets: blind_tiks.clone().try_into().unwrap(),
            _phantom_hash: PhantomData::<H>,
        };

        let new_cs = ConstraintSystem::<F>::new_ref();
        batch_tik_circuit
            .clone()
            .generate_constraints(new_cs.clone())?;
        new_cs.is_satisfied()?;

        let proof = Snark::prove(pkb, batch_tik_circuit, rng)?;

        for i in 0..BATCHSIZE {
            self.outstanding_batched_callbacks
                .push((vec_blinds[i], old + i));
        }

        Ok(BatchExecutedMethod {
            exec_meth: res_exec_method,
            pub_blinded_tickets: blind_tiks.try_into().unwrap(),
            proof,
        })
    }

    pub fn store_validated_tickets<
        H: FieldHash<F>,
        Args: Clone,
        Crypto: AECipherSigZK<F, Args>,
        const BATCHSIZE: usize,
    >(
        &mut self,
        pubkey: G,
        t: ValidatedTickets<BATCHSIZE>,
    ) -> Result<(), &'static str> {
        let blinded = self.outstanding_batched_callbacks[self.pointer..(self.pointer + BATCHSIZE)]
            .iter()
            .map(|(x, i)| {
                hash_to_curve::<H>(&self.get_cb::<Args, Crypto>(*i).cb_entry.serialize()) * x
            })
            .collect::<Vec<_>>();

        let out = verify_dleq_proof::<H, BATCHSIZE>(pubkey, t.clone(), blinded.try_into().unwrap());

        if !out {
            return Err("Proof did not verify.");
        }

        let deblinded = self.outstanding_batched_callbacks
            [self.pointer..(self.pointer + BATCHSIZE)]
            .iter()
            .zip(t.vtickets.iter())
            .map(|(blind, v)| *v * blind.0.inverse().unwrap())
            .collect::<Vec<_>>();

        self.validated_batched_callbacks.extend(deblinded);

        self.pointer += BATCHSIZE;

        Ok(())
    }

    pub fn use_validated_ticket<
        H: FieldHash<F>,
        CBArgs: Clone,
        Crypto: AECipherSigZK<F, CBArgs>,
    >(
        &mut self,
        data: &[F],
    ) -> RedeemExecMethod<CBArgs, Crypto> {
        let ticket = self.validated_batched_callbacks[self.valid_pointer];
        let cb =
            self.get_cb::<CBArgs, Crypto>(self.outstanding_batched_callbacks[self.valid_pointer].1);

        let mut inp_hash = cb.cb_entry.serialize();
        inp_hash.extend([
            ticket.into_affine().x,
            ticket.into_affine().y,
            F::from(ticket.into_affine().infinity),
        ]);

        self.valid_pointer += 1;

        let mac_key = H::hash(&inp_hash);

        let mut v = vec![mac_key];

        v.extend(data);

        let hmac = H::hash(&v);

        RedeemExecMethod {
            data: data.to_vec(),
            callback: cb,
            mac: hmac,
        }
    }
}

pub struct RedeemExecMethod<CBArgs: Clone, Crypto: AECipherSigZK<F, CBArgs>> {
    pub data: Vec<F>,
    pub callback: CallbackCom<F, CBArgs, Crypto>,
    pub mac: F,
}

pub(crate) fn hash_to_curve<H: FieldHash<F>>(value: &[Ser<F>]) -> G {
    let f = H::hash(value);

    let fp = {
        let digest_bits = f.into_bigint().to_bits_le();

        // The truncated bits now represent an integer that's less than r. This cannot fail.
        Fr::from_bigint(<Fr as PrimeField>::BigInt::from_bits_le(&digest_bits)).unwrap()
    };

    G::generator() * fp
}

pub(crate) fn hash_to_curve_zk<H: FieldHash<F>>(value: &[SerVar<F>]) -> GVar {
    let f = H::hash_in_zk(value);

    let f_bits = f
        .iter()
        .flat_map(|b| b.to_bits_le().unwrap())
        .collect::<Vec<_>>();
    GVar::constant(G::generator())
        .scalar_mul_le(f_bits.iter())
        .unwrap()
}

#[derive(Debug, Clone)]
pub struct ExpVar {
    enc: Vec<UInt8<F>>,
}

impl AllocVar<Fr, F> for ExpVar {
    fn new_variable<T: Borrow<Fr>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let mut r = Vec::new();
        let _ = &f()
            .map(|b| *b.borrow())
            .unwrap_or(Fr::ZERO)
            .serialize_compressed(&mut r)
            .unwrap();

        match mode {
            AllocationMode::Constant => Ok(Self {
                enc: UInt8::constant_vec(&r),
            }),
            AllocationMode::Input => Ok(Self {
                enc: UInt8::new_input_vec(cs, &r)?,
            }),
            AllocationMode::Witness => Ok(Self {
                enc: UInt8::new_witness_vec(cs, &r)?,
            }),
        }
    }
}

impl Mul<GVar> for ExpVar {
    type Output = Result<GVar, SynthesisError>;

    fn mul(self, rhs: GVar) -> Self::Output {
        let vector = self
            .enc
            .iter()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect::<Vec<_>>();

        let new_val = rhs.scalar_mul_le(vector.iter())?;

        Ok(new_val)
    }
}

pub struct BatchExecutedMethod<
    Snark: SNARK<F>,
    CBArgs: Clone,
    Crypto: AECipherSigZK<F, CBArgs>,
    const BATCHSIZE: usize,
> {
    pub exec_meth: ExecutedMethod<F, Snark, CBArgs, Crypto, BATCHSIZE>,
    pub pub_blinded_tickets: [G; BATCHSIZE],
    pub proof: Snark::Proof,
}

#[derive(Clone)]
pub struct BatchTicketCircuit<
    H: FieldHash<F>,
    CBArgs: Clone,
    Crypto: AECipherSigZK<F, CBArgs>,
    const BATCHSIZE: usize,
> {
    pub priv_issued_callbacks: [CallbackCom<F, CBArgs, Crypto>; BATCHSIZE],
    pub priv_blinds: [Fr; BATCHSIZE],
    pub pub_cb_commitments: [Com<F>; BATCHSIZE],
    pub pub_new_com: Com<F>,
    pub pub_blinded_tickets: [G; BATCHSIZE],
    pub _phantom_hash: PhantomData<H>,
}

pub fn generate_keys_for_batch_tickets<
    H: FieldHash<F>,
    U: UserData<F> + Default,
    PubArgs: Clone,
    PubArgsVar: AllocVar<PubArgs, F>,
    PrivArgs: Clone,
    PrivArgsVar: AllocVar<PrivArgs, F>,
    CBArgs: Clone,
    CBArgsVar: AllocVar<CBArgs, F>,
    Crypto: AECipherSigZK<F, CBArgs>,
    Snark: SNARK<F>,
    const BATCHSIZE: usize,
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
        BATCHSIZE,
    >,
) -> (Snark::ProvingKey, Snark::VerifyingKey) {
    let cbs = interaction
        .callbacks
        .iter()
        .map(|cb| {
            let ticket_value = Crypto::SigPK::default();
            let enc_key: Crypto::EncKey = Crypto::EncKey::default();
            let com_rand = F::ZERO;

            let cb_data: CallbackTicket<F, CBArgs, Crypto> = CallbackTicket {
                tik: ticket_value,
                cb_method_id: cb.method_id,
                expirable: cb.expirable,
                expiration: cb.expiration + F::ZERO,
                enc_key,
            };

            CallbackCom {
                cb_entry: cb_data,
                com_rand,
            }
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap_or_else(|_| panic!("Failed to create defaults."));
    let out: BatchTicketCircuit<H, CBArgs, Crypto, BATCHSIZE> = BatchTicketCircuit {
        priv_issued_callbacks: cbs,
        priv_blinds: [Fr::ZERO; BATCHSIZE],
        pub_cb_commitments: [F::ZERO; BATCHSIZE],
        pub_new_com: F::ZERO,
        pub_blinded_tickets: vec![G::generator(); BATCHSIZE].try_into().unwrap(),

        _phantom_hash: PhantomData,
    };

    Snark::circuit_specific_setup(out, rng).unwrap()
}

impl<H: FieldHash<F>, CBArgs: Clone, Crypto: AECipherSigZK<F, CBArgs>, const BATCHSIZE: usize>
    ConstraintSynthesizer<F> for BatchTicketCircuit<H, CBArgs, Crypto, BATCHSIZE>
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> ArkResult<()> {
        let priv_issued_callbacks = <[CallbackComVar<F, CBArgs, Crypto>; BATCHSIZE] as AllocVar<
            [CallbackCom<F, CBArgs, Crypto>; BATCHSIZE],
            F,
        >>::new_witness(
            ns!(cs, "priv_issued_callbacks"),
            || Ok(self.priv_issued_callbacks),
        )?;

        let priv_blinds_var = <[ExpVar; BATCHSIZE] as AllocVar<[Fr; BATCHSIZE], F>>::new_witness(
            ns!(cs, "priv_blinds"),
            || Ok(self.priv_blinds),
        )?;

        let mut pub_cb_com_var_vec: Vec<ComVar<F>> = vec![];
        for i in self.pub_cb_commitments {
            pub_cb_com_var_vec.push(<ComVar<F>>::new_input(ns!(cs, "pub_cb_com"), || Ok(i))?);
        }

        let pub_cb_com_var: [ComVar<F>; BATCHSIZE] = pub_cb_com_var_vec.try_into().unwrap();

        let mut pub_tik_var_vec = vec![];

        for i in self.pub_blinded_tickets {
            pub_tik_var_vec.push(GVar::new_input(ns!(cs, "pub_tiks"), || Ok(i))?);
        }

        let pub_tik_var: [GVar; BATCHSIZE] = pub_tik_var_vec.try_into().unwrap();

        // commit to new user and enforce that that is correct

        // (User::commit_in_zk::<H>(new_user_var.clone())?).enforce_equal(&pub_com_var)?;

        for i in 0..BATCHSIZE {
            // next: check that callbacks are well formed wrt the old callback commitments
            (CallbackCom::commit_in_zk::<H>(priv_issued_callbacks[i].clone())?)
                .enforce_equal(&pub_cb_com_var[i])?;

            // check that the privacy pass blinds are correct
            (priv_blinds_var[i].clone()
                * hash_to_curve_zk::<H>(&priv_issued_callbacks[i].cb_entry.serialize()?))?
            .enforce_equal(&pub_tik_var[i])?;
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct ValidatedTickets<const BATCHSIZE: usize> {
    pub vtickets: [G; BATCHSIZE],
    pub proof: (Fr, Fr),
}

pub fn verify_and_validate<
    H: FieldHash<F>,
    U: UserData<F>,
    PubArgs: Clone + ToConstraintField<F>,
    CBArgs: Clone + std::fmt::Debug,
    CBArgsVar: AllocVar<CBArgs, F> + Clone,
    Crypto: AECipherSigZK<F, CBArgs>,
    Snark: SNARK<F>,
    Bul: PublicUserBul<F, U>,
    const BATCHSIZE: usize,
>(
    object: Com<F>,
    old_nul: Nul<F>,
    args: PubArgs,
    cb_com_list: [Com<F>; BATCHSIZE],
    proof: Snark::Proof,
    memb_data: Bul::MembershipPub,
    is_memb_data_const: bool,
    verif_key: &Snark::VerifyingKey,
    bul: &Bul,
    blinded: [G; BATCHSIZE],
    blinded_proof: Snark::Proof,
    blinded_verif_key: &Snark::VerifyingKey,
    private_key: Fr,
) -> Result<ValidatedTickets<BATCHSIZE>, &'static str> {
    let out = bul.verify_in::<PubArgs, Snark, BATCHSIZE>(
        object,
        old_nul,
        cb_com_list,
        args.clone(),
        proof.clone(),
        memb_data.clone(),
        verif_key,
    );

    if !out {
        return Err("Not inside bulletin");
    }

    let mut pub_inputs = vec![object, old_nul];
    pub_inputs.extend::<Vec<F>>(args.to_field_elements().unwrap());
    pub_inputs.extend::<Vec<F>>(cb_com_list.to_field_elements().unwrap());
    if !is_memb_data_const {
        pub_inputs.extend::<Vec<F>>(memb_data.to_field_elements().unwrap());
    }

    let out = Snark::verify(verif_key, &pub_inputs, &proof).unwrap_or(false);

    if !out {
        return Err("Standard proof failed to verify.");
    }

    let mut pub_inputs = vec![];
    for i in cb_com_list {
        pub_inputs.push(i);
    }

    // pub_inputs.extend::<Vec<F>>(cb_com_list.to_field_elements().unwrap());
    for i in blinded {
        pub_inputs.extend_from_slice(&i.into_affine().x.to_field_elements().unwrap());
        pub_inputs.extend_from_slice(&i.into_affine().y.to_field_elements().unwrap());
        pub_inputs.push(F::from(!i.into_affine().infinity));
    }

    let out = Snark::verify(blinded_verif_key, &pub_inputs, &blinded_proof).unwrap_or(false);

    if !out {
        return Err("Blinding proof failed to verify.");
    }

    let pubkey = G::generator() * private_key;

    let validated = blinded.iter().map(|&x| x * private_key).collect::<Vec<_>>();

    let mut v_tot = vec![
        G::generator().into_affine().x,
        G::generator().into_affine().y,
        F::from(G::generator().into_affine().infinity),
        pubkey.into_affine().x,
        pubkey.into_affine().y,
        F::from(G::generator().into_affine().infinity),
    ];

    for (i, j) in blinded.iter().zip(validated.iter()) {
        v_tot.extend([
            i.into_affine().x,
            i.into_affine().y,
            F::from(i.into_affine().infinity),
            j.into_affine().x,
            j.into_affine().y,
            F::from(j.into_affine().infinity),
        ]);
    }

    let w = H::hash(&v_tot);

    let mut prng_outputs = vec![];

    for i in 0..BATCHSIZE {
        let ci = {
            let prng_in = H::hash(&[w, F::from(i as u64)]);
            let digest_bits = prng_in.into_bigint().to_bits_le();

            Fr::from_bigint(<Fr as PrimeField>::BigInt::from_bits_le(&digest_bits)).unwrap()
        };
        prng_outputs.push(ci);
    }

    let m = blinded
        .iter()
        .zip(prng_outputs.iter())
        .fold(GA::identity(), |acc, (p, c)| (acc + (*p * c)).into());

    let z = validated
        .iter()
        .zip(prng_outputs.iter())
        .fold(GA::identity(), |acc, (q, c)| (acc + (*q * c)).into());

    let mut rng = thread_rng();

    let nonce: Fr = rng.r#gen();

    let a = G::generator() * nonce;
    let b = m * nonce;

    let cprime = H::hash(&[
        G::generator().into_affine().x,
        G::generator().into_affine().y,
        F::from(G::generator().into_affine().infinity),
        pubkey.into_affine().x,
        pubkey.into_affine().y,
        F::from(G::generator().into_affine().infinity),
        m.x,
        m.y,
        F::from(m.infinity),
        z.x,
        z.y,
        F::from(z.infinity),
        a.into_affine().x,
        a.into_affine().y,
        F::from(a.into_affine().infinity),
        b.into_affine().x,
        b.into_affine().y,
        F::from(b.into_affine().infinity),
    ]);

    let c = {
        let digest_bits = cprime.into_bigint().to_bits_le();

        Fr::from_bigint(<Fr as PrimeField>::BigInt::from_bits_le(&digest_bits)).unwrap()
    };

    let s = nonce - c * private_key;

    Ok(ValidatedTickets {
        vtickets: validated.try_into().unwrap(),
        proof: (c, s),
    })
}

pub(crate) fn verify_dleq_proof<H: FieldHash<F>, const BATCHSIZE: usize>(
    pubkey: G,
    tickets: ValidatedTickets<BATCHSIZE>,
    blinded: [G; BATCHSIZE],
) -> bool {
    let mut v_tot = vec![
        G::generator().into_affine().x,
        G::generator().into_affine().y,
        F::from(G::generator().into_affine().infinity),
        pubkey.into_affine().x,
        pubkey.into_affine().y,
        F::from(G::generator().into_affine().infinity),
    ];

    for (i, j) in blinded.iter().zip(tickets.vtickets.iter()) {
        v_tot.extend([
            i.into_affine().x,
            i.into_affine().y,
            F::from(i.into_affine().infinity),
            j.into_affine().x,
            j.into_affine().y,
            F::from(j.into_affine().infinity),
        ]);
    }

    let w = H::hash(&v_tot);

    let mut prng_outputs = vec![];

    for i in 0..BATCHSIZE {
        let ci = {
            let prng_in = H::hash(&[w, F::from(i as u64)]);
            let digest_bits = prng_in.into_bigint().to_bits_le();

            Fr::from_bigint(<Fr as PrimeField>::BigInt::from_bits_le(&digest_bits)).unwrap()
        };
        prng_outputs.push(ci);
    }

    let m = blinded
        .iter()
        .zip(prng_outputs.iter())
        .fold(GA::identity(), |acc, (p, c)| (acc + (*p * c)).into());

    let z = tickets
        .vtickets
        .iter()
        .zip(prng_outputs.iter())
        .fold(GA::identity(), |acc, (q, c)| (acc + (*q * c)).into());

    let ap = G::generator() * tickets.proof.1 + pubkey * tickets.proof.0;
    let bp = m * tickets.proof.1 + z * tickets.proof.0;

    let chash = H::hash(&[
        G::generator().into_affine().x,
        G::generator().into_affine().y,
        F::from(G::generator().into_affine().infinity),
        pubkey.into_affine().x,
        pubkey.into_affine().y,
        F::from(G::generator().into_affine().infinity),
        m.x,
        m.y,
        F::from(m.infinity),
        z.x,
        z.y,
        F::from(z.infinity),
        ap.into_affine().x,
        ap.into_affine().y,
        F::from(ap.into_affine().infinity),
        bp.into_affine().x,
        bp.into_affine().y,
        F::from(bp.into_affine().infinity),
    ]);

    let cp = {
        let digest_bits = chash.into_bigint().to_bits_le();

        Fr::from_bigint(<Fr as PrimeField>::BigInt::from_bits_le(&digest_bits)).unwrap()
    };

    return cp == tickets.proof.0;
}

pub fn verify_ticket<H: FieldHash<F>, CBArgs: Clone, Crypto: AECipherSigZK<F, CBArgs>>(
    privkey: Fr,
    data: RedeemExecMethod<CBArgs, Crypto>,
) -> bool {
    let t = hash_to_curve::<H>(&data.callback.cb_entry.serialize());
    let z = t * privkey;

    let mut inp_hash = data.callback.cb_entry.serialize();
    inp_hash.extend([
        z.into_affine().x,
        z.into_affine().y,
        F::from(z.into_affine().infinity),
    ]);

    let mac_key = H::hash(&inp_hash);
    let mut v = vec![mac_key];

    v.extend(data.data);

    let hmac = H::hash(&v);

    hmac == data.mac
}
