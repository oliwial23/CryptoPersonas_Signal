//! Privacy Pass: request an anonymous, unlinkable ticket and redeem it later for a
//! callback, without the redemption revealing which request produced it.
//!
//! Wraps `batch-zkc` (a VOPRF-style blind-issuance/redemption scheme built directly
//! against zk-callbacks' own `User`/bulletin types) fixed to this crate's concrete
//! types, at batch size 1 — one anonymized ticket per request, reusing the existing
//! `StandInt` post interaction completely unmodified; a member accumulates several
//! unlinkable tickets over time by asking more than once, not by requesting several
//! in one call. See `docs/FINDINGS.md` O7. (`batch-zkc` also supports issuing several
//! tickets from one interaction at once — `BATCHSIZE > 1` — which would need a new
//! interaction type with more than one callback; deliberately not built here.)
//!
//! Requesting and redeeming can be separate steps, in separate process invocations —
//! see `load_stash`/`save_stash`. `batch-zkc` is a first-party crate in this
//! workspace, not an external dependency, so the accessors and `BatchUser::from_parts`
//! this needs live there directly rather than being worked around from here.
//!
//! `ark_grumpkin::Fq` is a literal re-export of `ark_bn254::Fr` (`pub use ark_bn254::
//! {Fr as Fq, ...}` in `ark-grumpkin`, because Grumpkin is BN254's curve-cycle
//! partner) — so `batch-zkc`'s field and [`F`] are the identical Rust type, not
//! merely numerically equal. The VOPRF issuer keypair itself lives on Grumpkin's
//! *scalar* field/group (`ark_grumpkin::{Fr, Projective}`), which is a distinct,
//! ordinary elliptic curve unrelated to that identity — nothing unusual there.

use ark_ec::PrimeGroup;
use ark_ff::PrimeField;
use ark_grumpkin::{Fr as IssuerScalar, Projective as IssuerGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use rand::{CryptoRng, Rng, RngCore};
use std::fs;
use std::path::Path;

use batch_zkc::{
    BatchExecutedMethod, BatchUser, RedeemExecMethod, ValidatedTickets,
    generate_keys_for_batch_tickets, verify_and_validate, verify_ticket,
};
use zk_callbacks::generic::bulletin::PublicUserBul;
use zk_callbacks::generic::object::{Com, Nul};
use zk_callbacks::impls::centralized::crypto::FakeSigPubkey;

use crate::circuits::{
    MsgUser, TicketInt, get_ticket_interaction,
};
use crate::params::ParamsError;
use crate::{Args, ArgsVar, Cr, F, H, OStore, PK, Snark, VK};

/// Tickets issued per request, set at build time with `PERSONAS_TICKET_BATCH` (default 1).
/// One request is one ticket interaction (`get_ticket_interaction`) leaving this many
/// callbacks, so it counts this many interactions toward the scan cap and must stay
/// below `NUM_INTS_BEFORE_SCAN`.
pub const TICKET_BATCH_SIZE: usize = match option_env!("PERSONAS_TICKET_BATCH") {
    Some(s) => crate::circuits::parse_build_usize(s),
    None => 1,
};
const _: () = assert!(
    TICKET_BATCH_SIZE >= 1 && TICKET_BATCH_SIZE < crate::circuits::NUM_INTS_BEFORE_SCAN,
    "PERSONAS_TICKET_BATCH must be at least 1 and below NUM_INTS_BEFORE_SCAN"
);

/// A member wrapping their own [`User`] with the bookkeeping `batch-zkc` needs to
/// track which locally-held tickets are still blinded vs. already validated.
pub type PrivPassUser = BatchUser<MsgUser>;

/// What a ticket request produces: the underlying post proof plus the blinding
/// proof, submitted together to `/api/privpass/issue`.
pub type TicketRequest = BatchExecutedMethod<Snark, Args, Cr, TICKET_BATCH_SIZE>;
/// The issuer's blind-signed response to a request, unblinded and stored locally.
pub type ValidatedTicketBatch = ValidatedTickets<TICKET_BATCH_SIZE>;
/// A redeemed ticket, submitted to `/api/privpass/redeem`.
pub type TicketRedemption = RedeemExecMethod<Args, Cr>;

const ISSUER_KEY_FILE: &str = "privpass_issuer_key.bin";
const BATCH_KEYS_FILE: &str = "privpass_batch_keys.bin";

/// The server's VOPRF issuer keypair. `privkey` blind-signs ticket requests and
/// checks redemptions; `pubkey` is public — every client needs it to unblind a
/// validated batch (`store_validated_tickets`).
pub struct IssuerKeys {
    pub privkey: IssuerScalar,
    pub pubkey: IssuerGroup,
}

impl IssuerKeys {
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let privkey: IssuerScalar = rng.r#gen();
        let pubkey = IssuerGroup::generator() * privkey;
        Self { privkey, pubkey }
    }
}

/// Deterministic content-address for the batch-ticket Groth16 keys, mirroring
/// [`crate::params::cache_key`] but kept entirely separate — this never touches the
/// existing proving-key cache, so it can't invalidate or be invalidated by it.
fn privpass_cache_dir(cache_root: &Path, obj_pubkey_bytes: &[u8]) -> std::path::PathBuf {
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(b"personas-privpass;v3;hidden-tickets;batchsize=");
    hasher.update(TICKET_BATCH_SIZE.to_le_bytes());
    hasher.update(crate::circuits::scan_cap_tag().as_bytes());
    hasher.update(obj_pubkey_bytes);
    cache_root.join(hex::encode(&hasher.finalize()[..16]))
}

/// Load the issuer keypair from `data_dir`, generating and persisting a fresh one
/// on first run — the same seed-file discipline `load_or_create_store` uses for the
/// bulletin's own keys.
pub fn load_or_create_issuer_keys(
    rng: &mut (impl CryptoRng + RngCore),
    data_dir: &Path,
) -> Result<IssuerKeys, ParamsError> {
    fs::create_dir_all(data_dir)?;
    let path = data_dir.join(ISSUER_KEY_FILE);

    if path.exists() {
        let bytes = fs::read(&path)?;
        let privkey = IssuerScalar::deserialize_with_mode(&*bytes, Compress::No, Validate::Yes)?;
        let pubkey = IssuerGroup::generator() * privkey;
        return Ok(IssuerKeys { privkey, pubkey });
    }

    rotate_issuer_keys(rng, data_dir)
}

/// Replace the issuer keypair in `data_dir` with a fresh one. Every ticket issued under
/// the old key stops redeeming: the server rotates at each epoch boundary and on each
/// ban, so moderation that changes a member's object after issuance (a ban, a revoked
/// badge, lower reputation) cannot be dodged with tickets issued before it.
pub fn rotate_issuer_keys(
    rng: &mut (impl CryptoRng + RngCore),
    data_dir: &Path,
) -> Result<IssuerKeys, ParamsError> {
    fs::create_dir_all(data_dir)?;
    let path = data_dir.join(ISSUER_KEY_FILE);
    let keys = IssuerKeys::generate(rng);
    let mut bytes = Vec::new();
    keys.privkey.serialize_with_mode(&mut bytes, Compress::No)?;
    // Beside the target, then renamed over it: a crash must not leave a truncated key.
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(&tmp, &path)?;
    Ok(keys)
}

/// The Groth16 keys for one ticket request: the ticket interaction itself (`N`
/// callbacks, see [`TICKET_BATCH_SIZE`]) and the blind-issuance circuit over its `N`
/// callbacks.
pub struct TicketKeys {
    pub interaction_pk: PK,
    pub interaction_vk: VK,
    pub batch_pk: PK,
    pub batch_vk: VK,
}

/// Generate (or load, cached by the object bulletin's public key and the batch size)
/// the [`TicketKeys`]. Additive only — the existing `ServerKeys`/`ensure_params` cache
/// is never read or written here.
pub fn ensure_batch_ticket_keys(
    rng: &mut (impl CryptoRng + RngCore),
    obj_pubkey: <OStore as PublicUserBul<F, MsgUser>>::MembershipPub,
    obj_pubkey_bytes: &[u8],
    cache_root: &Path,
) -> Result<TicketKeys, ParamsError> {
    let dir = privpass_cache_dir(cache_root, obj_pubkey_bytes);
    fs::create_dir_all(&dir)?;
    let path = dir.join(BATCH_KEYS_FILE);

    if path.exists() {
        let bytes = fs::read(&path)?;
        let mut reader = &bytes[..];
        return Ok(TicketKeys {
            interaction_pk: PK::deserialize_with_mode(&mut reader, Compress::No, Validate::No)?,
            interaction_vk: VK::deserialize_with_mode(&mut reader, Compress::No, Validate::No)?,
            batch_pk: PK::deserialize_with_mode(&mut reader, Compress::No, Validate::No)?,
            batch_vk: VK::deserialize_with_mode(&mut reader, Compress::No, Validate::No)?,
        });
    }

    let interaction: TicketInt<TICKET_BATCH_SIZE> = get_ticket_interaction();
    let (interaction_pk, interaction_vk) = interaction
        .clone()
        .generate_keys::<H, Snark, Cr, OStore>(rng, Some(obj_pubkey), F::from(0), false);
    let (batch_pk, batch_vk) = generate_keys_for_batch_tickets::<
        H,
        MsgUser,
        F,
        ArgsVar,
        (),
        (),
        Args,
        ArgsVar,
        Cr,
        Snark,
        TICKET_BATCH_SIZE,
    >(rng, interaction);

    let mut bytes = Vec::new();
    interaction_pk.serialize_with_mode(&mut bytes, Compress::No)?;
    interaction_vk.serialize_with_mode(&mut bytes, Compress::No)?;
    batch_pk.serialize_with_mode(&mut bytes, Compress::No)?;
    batch_vk.serialize_with_mode(&mut bytes, Compress::No)?;
    fs::write(&path, &bytes)?;

    Ok(TicketKeys { interaction_pk, interaction_vk, batch_pk, batch_vk })
}

/// The member's side of requesting tickets: prove the ticket interaction (like a post,
/// but leaving [`TICKET_BATCH_SIZE`] callbacks) and, in the same call, blind one ticket
/// per callback for anonymous redemption later.
pub fn request_ticket<Bul: PublicUserBul<F, MsgUser>>(
    user: &mut PrivPassUser,
    rng: &mut (impl CryptoRng + RngCore),
    bul: &Bul,
    interaction_pk: &PK,
    batch_pk: &PK,
) -> Result<TicketRequest, ark_relations::r1cs::SynthesisError> {
    let bul_data = bul.get_membership_data(user.commit::<H>()).unwrap();
    user.batch_issue_tickets::<H, F, ArgsVar, (), (), Args, ArgsVar, Cr, Snark, Bul, TICKET_BATCH_SIZE>(
        rng,
        get_ticket_interaction::<TICKET_BATCH_SIZE>(),
        core::array::from_fn(|_| FakeSigPubkey::pk()),
        zk_callbacks::generic::object::Time::from(0),
        bul_data,
        // is_memb_data_const: the object bulletin's pubkey is baked in as a circuit
        // constant here, matching every other standard-interaction proof in this
        // service (`exec_standint`) — must agree with `issue_tickets`'s verification
        // side or an honest request fails to verify (the exact O10-adjacent mistake
        // already made once this session).
        true,
        interaction_pk,
        batch_pk,
        F::from(0),
        (),
        false,
    )
}

// ---------------------------------------------------------------------------------------
// Client-side ticket stash: persisting `PrivPassUser`'s bookkeeping — which of
// `batch-zkc`'s `BatchUser` fields aren't part of `User` and so aren't already covered
// by `PersonaClient::save_user`/`load_user` — so requesting a ticket and redeeming it
// can be separate CLI invocations instead of one round trip. `Compress::No`, matching
// `load_or_create_issuer_keys`/`ensure_batch_ticket_keys` above: this is an on-disk
// artifact, not wire traffic, so the wire-encoding section below's `Compress::Yes`-style
// convention doesn't apply.
// ---------------------------------------------------------------------------------------

/// Load a stashed [`PrivPassUser`] from `path`, wrapping `user` (already loaded the
/// normal way, e.g. via `PersonaClient::load_user`) — or a fresh, empty stash if no
/// file exists yet (nothing outstanding or validated).
pub fn load_stash(
    path: &Path,
    user: zk_callbacks::generic::user::User<F, MsgUser>,
) -> Result<PrivPassUser, ParamsError> {
    if !path.exists() {
        return Ok(PrivPassUser::create(user));
    }
    let bytes = fs::read(path)?;
    let mut reader = &bytes[..];

    let outstanding_len = read_u64(&mut reader)?;
    let mut outstanding = Vec::with_capacity(outstanding_len as usize);
    for _ in 0..outstanding_len {
        let blind = IssuerScalar::deserialize_with_mode(&mut reader, Compress::No, Validate::Yes)?;
        let index = read_u64(&mut reader)?;
        outstanding.push((blind, index as usize));
    }

    let validated_len = read_u64(&mut reader)?;
    let mut validated = Vec::with_capacity(validated_len as usize);
    for _ in 0..validated_len {
        let point = IssuerGroup::deserialize_with_mode(&mut reader, Compress::No, Validate::Yes)?;
        validated.push(point);
    }

    let pointer = read_u64(&mut reader)? as usize;
    let valid_pointer = read_u64(&mut reader)? as usize;

    Ok(PrivPassUser::from_parts(
        user,
        outstanding,
        validated,
        pointer,
        valid_pointer,
    ))
}

/// Persist `batch_user`'s ticket-request bookkeeping to `path`. Its own `user` field
/// is the caller's responsibility to save separately, the normal way — this only
/// covers the bookkeeping `batch-zkc` adds on top.
pub fn save_stash(path: &Path, batch_user: &PrivPassUser) -> Result<(), ParamsError> {
    let mut bytes = Vec::new();

    let outstanding = batch_user.outstanding_batched_callbacks();
    bytes.extend_from_slice(&(outstanding.len() as u64).to_le_bytes());
    for (blind, index) in outstanding {
        blind.serialize_with_mode(&mut bytes, Compress::No)?;
        bytes.extend_from_slice(&(*index as u64).to_le_bytes());
    }

    let validated = batch_user.validated_batched_callbacks();
    bytes.extend_from_slice(&(validated.len() as u64).to_le_bytes());
    for point in validated {
        point.serialize_with_mode(&mut bytes, Compress::No)?;
    }

    bytes.extend_from_slice(&(batch_user.pointer() as u64).to_le_bytes());
    bytes.extend_from_slice(&(batch_user.valid_pointer() as u64).to_le_bytes());

    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    // Write beside the target and rename over it, matching every other on-disk store
    // in this service — a crash mid-write must not leave a truncated stash behind.
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn read_u64(reader: &mut &[u8]) -> Result<u64, ParamsError> {
    if reader.len() < 8 {
        return Err(ParamsError::Serialization(
            ark_serialize::SerializationError::IoError(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "stash file is shorter than expected — corrupt or truncated",
            )),
        ));
    }
    let (int_bytes, rest) = reader.split_at(8);
    *reader = rest;
    Ok(u64::from_le_bytes(int_bytes.try_into().unwrap()))
}

/// The server's side of a ticket request: check the blinding proof, then blind-sign
/// the requested batch under the issuer key. **Must be called after** the standard
/// interaction has already been appended to the bulletin (`verify_and_store`) — its
/// internal `verify_in` check looks the new object up in the bulletin, so calling
/// this first (before the object is actually registered) rejects an honest request
/// with "Not inside bulletin". Mirrors `batch-zkc`'s own example (`examples/test.rs`),
/// which does `verify_interact_and_append` before `verify_and_validate` too.
#[allow(clippy::too_many_arguments)]
pub fn issue_tickets(
    request: &TicketRequest,
    object: Com<F>,
    old_nul: Nul<F>,
    memb_data: <OStore as PublicUserBul<F, MsgUser>>::MembershipPub,
    interaction_vk: &VK,
    batch_vk: &VK,
    bul: &OStore,
    issuer: &IssuerKeys,
) -> Result<ValidatedTicketBatch, &'static str> {
    verify_and_validate::<H, MsgUser, F, Args, ArgsVar, Cr, Snark, OStore, TICKET_BATCH_SIZE>(
        object,
        old_nul,
        F::from(0),
        request.exec_meth.cb_com_list,
        request.exec_meth.proof.clone(),
        memb_data,
        true,
        interaction_vk,
        bul,
        request.pub_blinded_tickets,
        request.proof.clone(),
        batch_vk,
        // `request_ticket` runs the ticket interaction at time 0; the blinding proof
        // checks each hidden ticket's expiration against this.
        F::from(0),
        issuer.privkey,
    )
}

/// The server's side of a redemption: check the ticket's MAC is well-formed under
/// the issuer key. Stateless — carries no memory of past redemptions, so the
/// caller must separately enforce one-redemption-per-ticket (see
/// `personas-server::state::PrivPassLog`, keyed by [`redemption_key`]).
pub fn verify_redemption(issuer: &IssuerKeys, redemption: &TicketRedemption) -> bool {
    verify_ticket::<H, Args, Cr>(issuer.privkey, clone_redemption(redemption))
}

/// The double-spend key for a redemption: the callback entry it names, canonically
/// serialized. `verify_ticket` derives everything else deterministically from this
/// plus the (fixed) issuer key, so replaying the same redemption always names the
/// same entry — this is what a spent-ticket log keys on.
pub fn redemption_key(redemption: &TicketRedemption) -> Vec<u8> {
    let mut bytes = Vec::new();
    let _ = redemption
        .callback
        .cb_entry
        .clone()
        .serialize_compressed(&mut bytes);
    bytes
}

/// A manual clone of the request's interaction part. Its derive would require `Snark:
/// Clone`, which `Groth16` doesn't implement. The server needs it twice: appended to the
/// bulletin first, then checked again by [`issue_tickets`]'s internal `verify_in`.
pub fn clone_exec_meth(
    e: &batch_zkc::BlindExecutedMethod<Snark, TICKET_BATCH_SIZE>,
) -> batch_zkc::BlindExecutedMethod<Snark, TICKET_BATCH_SIZE> {
    batch_zkc::BlindExecutedMethod {
        new_object: e.new_object,
        old_nullifier: e.old_nullifier,
        cb_com_list: e.cb_com_list,
        cur_time: e.cur_time,
        proof: e.proof.clone(),
    }
}

fn clone_redemption(r: &TicketRedemption) -> TicketRedemption {
    RedeemExecMethod {
        data: r.data.clone(),
        callback: r.callback.clone(),
        mac: r.mac,
    }
}

// ---------------------------------------------------------------------------------------
// Redeeming. A ticket buys one post and nothing else: a ticket says nothing about who
// holds it, so redeeming one for a badge or a reputation change would let any member
// grant themselves either (FINDINGS O7). Badges and reputation go through their own,
// proved routes.
// ---------------------------------------------------------------------------------------

/// A one-time pseudonym for a redeemed ticket, used only for `redeem_pseudo_post`.
///
/// Deliberately **not** derived from the member's own secret key the way a real
/// persona is (`persona::pseudonym`) — that would require re-proving `claimed =
/// H(sk, context)`, defeating the point of using the ticket as authorization instead.
/// Instead it's derived from the ticket itself: unique per ticket (so two redemptions
/// never collide), and — because a ticket only exists once it's been through blind
/// issuance — unlinkable to whichever member requested it or to any of their other
/// posts, including ones under this same mechanism.
pub fn ticket_pseudonym(redemption: &TicketRedemption) -> F {
    F::from_le_bytes_mod_order(&redemption_key(redemption))
}

/// What a post-shaped redemption submits: a redemption plus the message, channel,
/// and (Signal only) an optional message timestamp to reply to. Shared by all four
/// posting flavours (anon/pseudonymous × plain/reply) — which one a request means is
/// decided by which route it's sent to, not by a field here. Bundled because
/// `TicketRedemption` (from `batch-zkc`) has no room for extra fields and isn't ours
/// to extend.
pub struct PostRedemption {
    pub redemption: TicketRedemption,
    pub message: String,
    pub channel: String,
    pub reply_to: Option<u64>,
}

// ---------------------------------------------------------------------------------------
// Wire encoding. None of `batch-zkc`'s own wrapper structs derive `CanonicalSerialize` —
// only the zk-callbacks types they wrap (`ExecutedMethod`, `CallbackCom`) do — so each
// field is serialized in a fixed order and read back in the same order, the same pattern
// `IssuerKeys`/the batch-ticket keys above already use. Not part of `personas_wire`'s `Kind`
// envelope registry: this is closer to a bulk artifact (a proving key, a bulletin dump)
// than a versioned record.
// ---------------------------------------------------------------------------------------

/// [`TICKET_BATCH_SIZE`] curve points, in order (one per ticket).
fn read_tickets(
    reader: &mut &[u8],
) -> Result<[IssuerGroup; TICKET_BATCH_SIZE], ark_serialize::SerializationError> {
    let mut out = [IssuerGroup::default(); TICKET_BATCH_SIZE];
    for t in out.iter_mut() {
        *t = CanonicalDeserialize::deserialize_compressed(&mut *reader)?;
    }
    Ok(out)
}

pub fn encode_ticket_request(
    req: &TicketRequest,
) -> Result<Vec<u8>, ark_serialize::SerializationError> {
    let mut bytes = Vec::new();
    req.exec_meth.serialize_compressed(&mut bytes)?;
    for t in &req.pub_blinded_tickets {
        t.serialize_compressed(&mut bytes)?;
    }
    req.proof.serialize_compressed(&mut bytes)?;
    Ok(bytes)
}

pub fn decode_ticket_request(
    bytes: &[u8],
) -> Result<TicketRequest, ark_serialize::SerializationError> {
    let mut reader = bytes;
    let exec_meth = CanonicalDeserialize::deserialize_compressed(&mut reader)?;
    let tickets = read_tickets(&mut reader)?;
    let proof = CanonicalDeserialize::deserialize_compressed(&mut reader)?;
    Ok(TicketRequest {
        exec_meth,
        pub_blinded_tickets: tickets,
        proof,
        _phantom: std::marker::PhantomData,
    })
}

pub fn encode_validated_tickets(
    tickets: &ValidatedTicketBatch,
) -> Result<Vec<u8>, ark_serialize::SerializationError> {
    let mut bytes = Vec::new();
    for t in &tickets.vtickets {
        t.serialize_compressed(&mut bytes)?;
    }
    tickets.proof.0.serialize_compressed(&mut bytes)?;
    tickets.proof.1.serialize_compressed(&mut bytes)?;
    Ok(bytes)
}

pub fn decode_validated_tickets(
    bytes: &[u8],
) -> Result<ValidatedTicketBatch, ark_serialize::SerializationError> {
    let mut reader = bytes;
    let tickets = read_tickets(&mut reader)?;
    let c: IssuerScalar = CanonicalDeserialize::deserialize_compressed(&mut reader)?;
    let s: IssuerScalar = CanonicalDeserialize::deserialize_compressed(&mut reader)?;
    Ok(ValidatedTickets {
        vtickets: tickets,
        proof: (c, s),
    })
}

pub fn encode_redemption(
    r: &TicketRedemption,
) -> Result<Vec<u8>, ark_serialize::SerializationError> {
    let mut bytes = Vec::new();
    r.data.serialize_compressed(&mut bytes)?;
    r.callback.serialize_compressed(&mut bytes)?;
    r.mac.serialize_compressed(&mut bytes)?;
    Ok(bytes)
}

pub fn decode_redemption(
    bytes: &[u8],
) -> Result<TicketRedemption, ark_serialize::SerializationError> {
    let mut reader = bytes;
    let data = CanonicalDeserialize::deserialize_compressed(&mut reader)?;
    let callback = CanonicalDeserialize::deserialize_compressed(&mut reader)?;
    let mac = CanonicalDeserialize::deserialize_compressed(&mut reader)?;
    Ok(RedeemExecMethod {
        data,
        callback,
        mac,
    })
}

pub fn encode_post_redemption(
    r: &PostRedemption,
) -> Result<Vec<u8>, ark_serialize::SerializationError> {
    let mut bytes = encode_redemption(&r.redemption)?;
    write_string(&mut bytes, &r.message);
    write_string(&mut bytes, &r.channel);
    bytes.push(if r.reply_to.is_some() { 1 } else { 0 });
    if let Some(ts) = r.reply_to {
        bytes.extend_from_slice(&ts.to_le_bytes());
    }
    Ok(bytes)
}

pub fn decode_post_redemption(
    bytes: &[u8],
) -> Result<PostRedemption, ark_serialize::SerializationError> {
    use ark_serialize::SerializationError as SE;
    let mut reader = bytes;
    let data = CanonicalDeserialize::deserialize_compressed(&mut reader)?;
    let callback = CanonicalDeserialize::deserialize_compressed(&mut reader)?;
    let mac = CanonicalDeserialize::deserialize_compressed(&mut reader)?;
    let message = read_string(&mut reader)?;
    let channel = read_string(&mut reader)?;
    if reader.is_empty() {
        return Err(SE::IoError(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "missing reply_to tag",
        )));
    }
    let has_reply = reader[0] == 1;
    reader = &reader[1..];
    let reply_to = if has_reply {
        if reader.len() < 8 {
            return Err(SE::IoError(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "missing reply_to timestamp",
            )));
        }
        Some(u64::from_le_bytes(reader[..8].try_into().unwrap()))
    } else {
        None
    };
    Ok(PostRedemption {
        redemption: RedeemExecMethod {
            data,
            callback,
            mac,
        },
        message,
        channel,
        reply_to,
    })
}

/// A length-prefixed UTF-8 string, since neither `String` nor `batch-zkc`'s own types
/// carry room for one — matches the fixed-order-fields convention every encoder above
/// already uses.
fn write_string(bytes: &mut Vec<u8>, s: &str) {
    bytes.extend_from_slice(&(s.len() as u64).to_le_bytes());
    bytes.extend_from_slice(s.as_bytes());
}

fn read_string(reader: &mut &[u8]) -> Result<String, ark_serialize::SerializationError> {
    use ark_serialize::SerializationError as SE;
    if reader.len() < 8 {
        return Err(SE::IoError(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "missing string length prefix",
        )));
    }
    let (len_bytes, rest) = reader.split_at(8);
    let len = u64::from_le_bytes(len_bytes.try_into().unwrap()) as usize;
    if rest.len() < len {
        return Err(SE::IoError(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "string shorter than its length prefix",
        )));
    }
    let (s_bytes, rest) = rest.split_at(len);
    let s = String::from_utf8(s_bytes.to_vec()).map_err(|_| {
        SE::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not valid UTF-8",
        ))
    })?;
    *reader = rest;
    Ok(s)
}
