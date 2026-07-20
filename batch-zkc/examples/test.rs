use ark_bn254::{Bn254 as E, Fr as F};
use ark_ec::PrimeGroup;
use ark_groth16::Groth16;
use ark_grumpkin::Fr;
use ark_grumpkin::Projective as G;
use ark_r1cs_std::{eq::EqGadget, fields::fp::FpVar, prelude::Boolean};
use ark_relations::r1cs::Result as ArkResult;
use batch_zkc::BatchUser;
use batch_zkc::generate_keys_for_batch_tickets;
use batch_zkc::verify_and_validate;
use batch_zkc::verify_ticket;
use rand::Rng;
use rand::thread_rng;
use std::time::SystemTime;
use zk_callbacks::generic::bulletin::PublicUserBul;
use zk_callbacks::{
    generic::{
        bulletin::{JoinableBulletin, UserBul},
        interaction::{Callback, Interaction},
        object::{Id, Time},
        user::{User, UserVar},
    },
    impls::{
        centralized::{
            crypto::{FakeSigPubkey, NoSigOTP},
            ds::sigstore::{GRSchnorrObjStore, GRSchnorrStore},
        },
        hash::Poseidon,
    },
    scannable_zk_object,
};

const BATCH_SIZE: usize = 5;

#[scannable_zk_object(F)]
#[derive(Default)]
pub struct UserData {
    pub reputation: F,
}

// Argument for the callback (we only have a single callback here, and the argument is a single
// field element.
type CBArg = F;
type CBArgVar = FpVar<F>;

// The wrapper "User" type around our zk-object.
type U = User<F, UserData>;
type UV = UserVar<F, UserData>;

// The crypto we are using for authenticity and argument hiding.
type Cr = NoSigOTP<F>;

// The type for the callback (what data it takes in: a user and an argument, in this case a field
// element).
type CB = Callback<F, UserData, CBArg, CBArgVar>;

// The first type of interaction (doing a method update, which does nothing so far)
type Int1 = Interaction<F, UserData, (), (), (), (), CBArg, CBArgVar, BATCH_SIZE>;

// Two types of interactions: updating the user normally with Int1, or updating the user with a
// scan through IntScan.

// The user is incrementing the token by 1 each time the method is called.
fn int_meth<'a>(tu: &'a U, _pub_args: (), _priv_args: ()) -> U {
    let a = tu.clone();

    // We could update token2 here! If you want :), there's nothing enforcing we need to keep it
    // the same.
    a
}

// Enforce that token1 in [0, 1, 2] (user can pretty much pick token2). Additionally, enforce
// that token1 is identical to (before + 1). This is effectively a rate limit: The user can
// only do an interaction twice before being unable to produce a proof.
//
// Note that there are no enforcements on token2, so it can be whatever the user wants.
fn int_meth_pred<'a>(
    tu_old: &'a UV,
    tu_new: &'a UV,
    _pub_args: (),
    _priv_args: (),
) -> ArkResult<Boolean<F>> {
    let e = tu_old.data.reputation.is_eq(&tu_new.data.reputation);
    e
}

// The callback method here allows the *server* to call a method on the user: Here the argument (F)
// being passed in can be selected by the server, and the user is forced to set their token1 to
// `args`.
fn cb_meth<'a>(tu: &'a U, args: F) -> U {
    let mut out = tu.clone();
    out.data.reputation = tu.data.reputation + args;
    out
}

// The proof that enforces the callback that the server calls.
fn cb_pred<'a>(tu_old: &'a UV, args: FpVar<F>) -> ArkResult<UV> {
    let mut tu_new = tu_old.clone();
    tu_new.data.reputation = tu_new.data.reputation + args;
    Ok(tu_new)
}

fn main() {
    // SERVER SETUP
    let mut rng = thread_rng();

    let privkey: Fr = rng.r#gen();

    let pubkey = G::generator() * privkey;

    let mut store: GRSchnorrStore<F> = GRSchnorrStore::new(&mut rng);

    // create a single callback type
    let cb: CB = Callback {
        method_id: Id::from(0),
        expirable: false,
        expiration: Time::from(300),
        method: cb_meth,
        predicate: cb_pred,
    };

    // let cb_methods = vec![cb.clone()];

    let interaction: Int1 = Interaction {
        meth: (int_meth, int_meth_pred),
        callbacks: core::array::from_fn(|_| cb.clone()),
    };

    let (pk, vk) = interaction // see interaction
        .generate_keys::<Poseidon<2>, Groth16<E>, Cr, GRSchnorrObjStore>(
            &mut rng,
            Some(store.obj_bul.get_pubkey()),
            (),
            false,
        );

    let (pkb, vkb) = generate_keys_for_batch_tickets::<
        Poseidon<2>,
        UserData,
        (),
        (),
        (),
        (),
        F,
        FpVar<F>,
        Cr,
        Groth16<E>,
        BATCH_SIZE,
    >(&mut rng, interaction.clone());
    let u = User::create(
        UserData {
            reputation: F::from(0), // Try changing this to 1 or 2 to see what happens!
        },
        &mut rng,
    );
    // Join in as a user
    let _ = <GRSchnorrObjStore as JoinableBulletin<F, UserData>>::join_bul(
        &mut store.obj_bul,
        u.commit::<Poseidon<2>>(),
        (),
    );

    let mut batch_user = BatchUser::create(u.clone());

    println!("[USER] Interacting (generating batch)...");
    let start = SystemTime::now();

    let exec_meth = batch_user.batch_issue_tickets::<Poseidon<2>, (), (), (), (), F, FpVar<F>, Cr, Groth16<E>, GRSchnorrObjStore, BATCH_SIZE>(
        &mut rng,
        interaction.clone(),
            core::array::from_fn(|_| FakeSigPubkey::pk()),
            Time::from(0),
        <GRSchnorrObjStore as PublicUserBul<F, UserData>>::get_membership_data(&store.obj_bul, u.commit::<Poseidon<2>>()).unwrap(),
            true,
            &pk,
            &pkb,
            (),
            (),
        false,
    ).unwrap();

    println!(
        "\t (time) Interaction (batch generation) time: {:?}",
        start.elapsed().unwrap()
    );
    println!("[USER] Executed interaction! New user: {:o} \n\n", u);

    println!("[BULLETIN] Storing...");

    let out = <GRSchnorrObjStore as UserBul<F, UserData>>::verify_interact_and_append::<
        (),
        Groth16<E>,
        BATCH_SIZE,
    >(
        &mut store.obj_bul,
        exec_meth.exec_meth.new_object.clone(),
        exec_meth.exec_meth.old_nullifier.clone(),
        (),
        exec_meth.exec_meth.cb_com_list.clone(),
        exec_meth.exec_meth.proof.clone(),
        None,
        &vk,
    );

    println!(
        "[BULLETIN] Checked standard proof and stored user... Output: {:?}",
        out
    );

    println!("[SERVER] Verifying batch interaction...");

    let start = SystemTime::now();

    let out = verify_and_validate::<
        Poseidon<2>,
        UserData,
        _,
        _,
        FpVar<F>,
        Cr,
        Groth16<E>,
        _,
        BATCH_SIZE,
    >(
        exec_meth.exec_meth.new_object.clone(),
        exec_meth.exec_meth.old_nullifier.clone(),
        (),
        exec_meth.exec_meth.cb_com_list.clone(),
        exec_meth.exec_meth.proof.clone(),
        store.obj_bul.get_pubkey(),
        true,
        &vk,
        &store.obj_bul,
        exec_meth.pub_blinded_tickets,
        exec_meth.proof,
        &vkb,
        privkey,
    )
    .unwrap();

    println!(
        "\t (time) Verify privacy pass data: {:?}",
        start.elapsed().unwrap()
    );

    println!("[USER] Validating and storing unblinded tickets ...");
    let start = SystemTime::now();

    batch_user
        .store_validated_tickets::<Poseidon<2>, _, Cr, BATCH_SIZE>(pubkey, out)
        .unwrap();

    println!(
        "\t (time) Unblinding and verifying: {:?}",
        start.elapsed().unwrap()
    );

    println!("[USER] Using a ticket ...");
    let start = SystemTime::now();

    let out = batch_user.use_validated_ticket::<Poseidon<2>, _, Cr>(&[F::from(0)]);

    println!(
        "\t (time) Generating MAC and key: {:?}",
        start.elapsed().unwrap()
    );

    println!("[SERVER] Verifying ticket ...");
    let start = SystemTime::now();

    let out = verify_ticket::<Poseidon<2>, F, Cr>(privkey, out);

    println!(
        "\t (time) Checking callback ticket is well formed: {:?}",
        start.elapsed().unwrap()
    );

    println!("{:?}", out);
}
