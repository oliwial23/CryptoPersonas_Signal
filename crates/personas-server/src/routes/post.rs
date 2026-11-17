//! Posting: verify the proof, append to the bulletin, relay the message, file the callback.
//!
//! Six handlers used to live here — anonymous, pseudonymous and rate-limited, once for
//! Signal and once for Slack — each ~180 lines, differing in which verifying key they used,
//! which public arguments they built, and whether they shelled out to `signal-cli-client` or
//! called slack-morphism. They are one function now; [`Flavour`] is the difference.
//!
//! # The order matters
//!
//! 1. Verify the proof and append to the bulletin.
//! 2. Relay the message — and only now does it have an id.
//! 3. File the callback the poster committed to, under that id.
//!
//! The old code did (1), then wrote a half-row holding the callback and no id, then relayed,
//! then went back and rewrote *the last line of the file* to add the id. If the relay failed,
//! the half-row stayed, and the next member's post adopted it — filing one member's callback
//! against another member's message. Nothing can be filed before the id exists, so nothing is.
//!
//! Note that (1) is not undone if (2) fails. The bulletin has already accepted the
//! interaction, the member has spent it, and the messenger did not deliver. That was true
//! before and is true now; making it atomic means a bulletin that can roll back, which the
//! bulletin cannot.

use ark_ff::PrimeField;
use axum::extract::{Json, State};
use axum::response::Response;
use personas_core::circuits::{BadgesArgs, Claim, ClaimArgs, PseudonymArgs, PseudonymArgsRate, check_claim, describe_claim};
use personas_core::{Args, Cr, F, Snark, VK, persona};
use personas_wire::{Kind, decode};
use serde::Deserialize;
use zk_callbacks::generic::user::ExecutedMethod;

use transport_api::{ConversationId, MessageId, Outgoing};

use crate::bench;
use crate::bulletin::{INTERACTION, epoch, verify_and_store};
use crate::error::{AppError, AppResult, ok};
use crate::state::{Namespace, ServerLock, ServerState, StoredBadge, badge_name, emoji_for};

// ---------------------------------------------------------------------------------------
// Request bodies. The two messengers name their destination differently — a Signal group id,
// a Slack channel — and that is the only difference between these.
// ---------------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SignalPost {
    pub message: String,
    pub group_id: String,
    pub proof: Vec<u8>,
}

#[derive(Deserialize)]
pub struct SignalReply {
    pub group_id: String,
    pub message: String,
    pub timestamp: u64,
    pub proof: Vec<u8>,
}

#[derive(Deserialize)]
pub struct SignalReact {
    pub group_id: String,
    pub emoji: String,
    pub timestamp: u64,
}

#[derive(Deserialize)]
pub struct SlackPost {
    pub channel: String,
    pub message: String,
    pub proof: Vec<u8>,
}

#[derive(Deserialize)]
pub struct SlackReact {
    pub channel: String,
    pub emoji: String,
    pub timestamp: String,
}

#[derive(Deserialize)]
pub struct SlackProofOnly {
    pub channel: String,
    pub proof: Vec<u8>,
}

/// What a post claims about its author.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flavour {
    /// Nothing: an unlinkable post by some unbanned member.
    Anon,
    /// A pseudonym, scoped to a context. Two posts under the same pseudonym are the same
    /// member; posts under different pseudonyms cannot be linked.
    Pseudo,
    /// A pseudonym plus an index, so a member can be held to *k* posts per context.
    PseudoRate,
    /// A pseudonym that also shows a badge, merges a second persona, or proves reputation
    /// at least a threshold: an interaction with a callback, like any post.
    Claim(Claim),
}

impl Flavour {
    fn kind(self) -> Kind {
        match self {
            Self::Anon => Kind::Post,
            Self::Pseudo => Kind::PostPseudo,
            Self::PseudoRate => Kind::PostPseudoRate,
            Self::Claim(_) => Kind::PostClaim,
        }
    }

    fn verifying_key(self, state: &ServerState) -> VK {
        match self {
            Self::Anon => state.keys.standard_verifying_key.clone(),
            Self::Pseudo => state.keys.standard_pseudo_verifying_key.clone(),
            Self::PseudoRate => state.keys.standard_pseudor_verifying_key.clone(),
            Self::Claim(Claim::ShowBadge) => state.keys.show_badge_verifying_key.clone(),
            Self::Claim(Claim::MergePersonas) => state.keys.merge_personas_verifying_key.clone(),
            Self::Claim(Claim::RepAtLeast) => state.keys.rep_at_least_verifying_key.clone(),
        }
    }
}

/// What verification established, for the relay step to use.
struct Verified {
    /// Hex callback commitments, to be filed once the message has an id.
    callbacks: Vec<String>,
    /// The petname the message is posted under, if any.
    persona: Option<String>,
    /// The *thread* context, set only by a rate-limited post.
    ///
    /// Every pseudonymous post proves a context — that is what a pseudonym is scoped to — but
    /// only a rate-limited one proves a context that names a thread the server assigned. A
    /// plain pseudonym's context is minted client-side and belongs to no thread, so it is not
    /// carried here: it would send the message looking for a thread that does not exist.
    context: Option<String>,
    /// What a post with a claim proves about its author, shown above its message.
    claim: Option<String>,
}

/// Verify a ballot: a Persona-post interaction under `poll_context`, whose pseudonym is
/// `claimed`. Appends it to the bulletin like any interaction (protocol version 5: every
/// feature leaves a callback), but files its callback under no message, so nothing can
/// target a ballot.
pub(super) fn verify_vote(
    st: &mut ServerState,
    proof: &[u8],
    poll_context: F,
    claimed: F,
    payload: F,
) -> AppResult<()> {
    let vk = st.keys.standard_pseudo_verifying_key.clone();
    let mut reader = decode(Kind::PostPseudo, proof)?;
    let exec: ExecutedMethod<F, Snark, Args, Cr, 1> = reader.pull()?;
    let inputs = pub_inputs(&mut reader, 2)?;
    if inputs[0] != poll_context {
        return Err(AppError::Rejected("this vote is proved for a different poll".into()));
    }
    if inputs[1] != claimed {
        return Err(AppError::Rejected("this vote proves a different pseudonym".into()));
    }
    let current = epoch(&st.db);
    let (result, start, millis) = bench::time(|| {
        verify_and_store(
            &mut st.db,
            &vk,
            exec,
            PseudonymArgs {
                context: poll_context,
                claimed,
                payload,
            },
            current,
            INTERACTION,
        )
    });
    bench::verified("pseudo_vote", start, millis);
    result.map(|_callbacks| ())
}

/// Verify a post of any flavour, append it to the bulletin.
///
/// Every flavour files its callbacks at the live epoch (FINDINGS O3) — the old
/// disagreement (anonymous/rate-limited posts at `Time::from(0)`, pseudonymous posts at
/// the live epoch) was unobservable only because the sole callback in use is
/// `expirable: false`, but would silently drop tickets the day an expirable one is
/// introduced. See [`verify_and_store`].
fn verify_post(
    st: &mut ServerState,
    flavour: Flavour,
    proof: &[u8],
    label: &str,
    payload: F,
) -> AppResult<Verified> {
    let vk = flavour.verifying_key(st);
    let mut reader = decode(flavour.kind(), proof)?;
    let exec: ExecutedMethod<F, Snark, Args, Cr, 1> = reader.pull()?;
    let current = epoch(&st.db);

    let (result, start, millis) = bench::time(|| match flavour {
        Flavour::Anon => verify_and_store(&mut st.db, &vk, exec, payload, current, INTERACTION)
            .map(|callbacks| Verified {
                callbacks,
                persona: None,
                context: None,
                claim: None,
            }),

        Flavour::Pseudo => {
            let inputs = pub_inputs(&mut reader, 2)?;
            let (context, claimed) = (inputs[0], inputs[1]);

            verify_and_store(
                &mut st.db,
                &vk,
                exec,
                PseudonymArgs {
                    context,
                    claimed,
                    payload,
                },
                current,
                INTERACTION,
            )
            .map(|callbacks| Verified {
                callbacks,
                persona: Some(persona::petname(claimed)),
                // Deliberately not the thread key. A plain pseudonymous post is scoped to a
                // context the *client* invented for that pseudonym; it names no thread, and
                // looking one up would refuse every post that is not a threaded reply.
                context: None,
                claim: None,
            })
        }

        Flavour::PseudoRate => {
            let inputs = pub_inputs(&mut reader, 3)?;
            let (context, claimed, i) = (inputs[0], inputs[1], inputs[2]);

            verify_and_store(
                &mut st.db,
                &vk,
                exec,
                PseudonymArgsRate {
                    context,
                    claimed,
                    i,
                    payload,
                },
                current,
                INTERACTION,
            )
            .map(|callbacks| Verified {
                callbacks,
                persona: Some(persona::petname(claimed)),
                context: Some(field_to_string(context)),
                claim: None,
            })
        }

        Flavour::Claim(claim) => {
            let inputs = pub_inputs(&mut reader, 4)?;
            let (context, claimed, a, b) = (inputs[0], inputs[1], inputs[2], inputs[3]);
            check_claim(claim, context, a, b).map_err(|why| AppError::Rejected(why.into()))?;

            verify_and_store(
                &mut st.db,
                &vk,
                exec,
                ClaimArgs {
                    post: PseudonymArgs {
                        context,
                        claimed,
                        payload,
                    },
                    a,
                    b,
                },
                current,
                INTERACTION,
            )
            .map(|callbacks| Verified {
                callbacks,
                persona: Some(persona::petname(claimed)),
                // A plain persona's context, like `Pseudo`: it names no thread.
                context: None,
                claim: Some(describe_claim(claim, a, b)),
            })
        }
    });

    bench::verified(label, start, millis);
    result
}

/// Relay a message and file the poster's callbacks against the id it comes back with.
///
/// The state lock is *not* held across the send. A messenger round trip is tens of
/// milliseconds at best, and the old code held the write lock — the one every other post
/// needs — for the whole of a subprocess spawn. Releasing it is only safe because callbacks
/// are now filed by message id rather than by "the last line of the file", so two posts may
/// interleave without stealing each other's rows.
async fn relay(
    state: &ServerLock,
    ns: Namespace,
    verified: Verified,
    mut msg: Outgoing,
) -> AppResult<MessageId> {
    msg.persona = verified.persona;

    let transport = state.read().await.channel(ns).transport.clone();
    let sent = transport.send(msg).await?;

    let mut st = state.write().await;
    for cb in verified.callbacks {
        st.channel_mut(ns).records.record(&sent.id, cb)?;
    }

    Ok(sent.id)
}

/// Where a rate-limited post goes: the thread whose context it was proved against.
///
/// A pseudonym is derived from a context, so a proof naming a context it cannot find is a
/// proof about a thread the server does not have. That is a client bug (it did not fetch the
/// contexts) and it is refused rather than posted into the void.
fn thread_for(
    st: &ServerState,
    ns: Namespace,
    verified: &Verified,
) -> AppResult<Option<MessageId>> {
    let Some(context) = &verified.context else {
        return Ok(None);
    };

    let entry = st
        .channel(ns)
        .contexts
        .by_context(context)
        .ok_or_else(|| AppError::NotFound(format!("no thread has context {context}")))?;

    // Signal has no threads, so it stores no ts and the message is posted to the group
    // unthreaded — which is what the as-a-service Signal deployment has always done.
    Ok(entry.ts.clone().map(MessageId))
}

// ---------------------------------------------------------------------------------------
// Signal
// ---------------------------------------------------------------------------------------

pub async fn signal_anon(
    State(state): State<ServerLock>,
    Json(input): Json<SignalPost>,
) -> AppResult<Response> {
    post(
        state,
        Namespace::Signal,
        Flavour::Anon,
        "anon_msg",
        input.group_id,
        input.message,
        input.proof,
        None,
    )
    .await
}

pub async fn signal_pseudo(
    State(state): State<ServerLock>,
    Json(input): Json<SignalPost>,
) -> AppResult<Response> {
    post(
        state,
        Namespace::Signal,
        Flavour::Pseudo,
        "pseudo_msg",
        input.group_id,
        input.message,
        input.proof,
        None,
    )
    .await
}

pub async fn signal_pseudo_rate(
    State(state): State<ServerLock>,
    Json(input): Json<SignalPost>,
) -> AppResult<Response> {
    post(
        state,
        Namespace::Signal,
        Flavour::PseudoRate,
        "rate_pseudo",
        input.group_id,
        input.message,
        input.proof,
        None,
    )
    .await
}

pub async fn signal_reply(
    State(state): State<ServerLock>,
    Json(input): Json<SignalReply>,
) -> AppResult<Response> {
    post(
        state,
        Namespace::Signal,
        Flavour::Anon,
        "anon_msg",
        input.group_id,
        input.message,
        input.proof,
        Some(MessageId::from(input.timestamp)),
    )
    .await
}

pub async fn signal_reply_pseudo(
    State(state): State<ServerLock>,
    Json(input): Json<SignalReply>,
) -> AppResult<Response> {
    post(
        state,
        Namespace::Signal,
        Flavour::Pseudo,
        "pseudo_msg",
        input.group_id,
        input.message,
        input.proof,
        Some(MessageId::from(input.timestamp)),
    )
    .await
}

/// Rate a message. No proof: a rating says nothing about who is rating.
///
/// It is *not* applied to the poster's object here — it is accumulated in the ledger, and
/// applied only when someone invokes the callback the poster committed to (`/api/reputation`).
/// That indirection is the point: the service cannot change a member's reputation without
/// using a token that member handed it in advance.
pub async fn signal_react(
    State(state): State<ServerLock>,
    Json(input): Json<SignalReact>,
) -> AppResult<Response> {
    react(
        state,
        Namespace::Signal,
        input.group_id,
        MessageId::from(input.timestamp),
        &input.emoji,
    )
    .await
}

/// MergePersonas: a post under one persona proving a second persona is the same member,
/// without saying which member.
pub async fn signal_merge_personas(
    State(state): State<ServerLock>,
    Json(input): Json<SignalPost>,
) -> AppResult<Response> {
    let flavour = Flavour::Claim(Claim::MergePersonas);
    post(state, Namespace::Signal, flavour, "author", input.group_id, input.message, input.proof, None).await
}

/// ShowBadge: a post under a persona showing a badge its member holds.
pub async fn signal_show_badge(
    State(state): State<ServerLock>,
    Json(input): Json<SignalPost>,
) -> AppResult<Response> {
    let flavour = Flavour::Claim(Claim::ShowBadge);
    post(state, Namespace::Signal, flavour, "badge", input.group_id, input.message, input.proof, None).await
}

/// RepAtLeast: a post under a persona proving its member's reputation is at least a
/// threshold.
pub async fn signal_rep_at_least(
    State(state): State<ServerLock>,
    Json(input): Json<SignalPost>,
) -> AppResult<Response> {
    let flavour = Flavour::Claim(Claim::RepAtLeast);
    post(state, Namespace::Signal, flavour, "rep_at_least", input.group_id, input.message, input.proof, None).await
}

// ---------------------------------------------------------------------------------------
// Slack
// ---------------------------------------------------------------------------------------

pub async fn slack_anon(
    State(state): State<ServerLock>,
    Json(input): Json<SlackPost>,
) -> AppResult<Response> {
    post(
        state,
        Namespace::Slack,
        Flavour::Anon,
        "anon_msg",
        input.channel,
        input.message,
        input.proof,
        None,
    )
    .await
}

pub async fn slack_pseudo(
    State(state): State<ServerLock>,
    Json(input): Json<SlackPost>,
) -> AppResult<Response> {
    post(
        state,
        Namespace::Slack,
        Flavour::Pseudo,
        "pseudo_msg",
        input.channel,
        input.message,
        input.proof,
        None,
    )
    .await
}

pub async fn slack_pseudo_rate(
    State(state): State<ServerLock>,
    Json(input): Json<SlackPost>,
) -> AppResult<Response> {
    post(
        state,
        Namespace::Slack,
        Flavour::PseudoRate,
        "rate_pseudo",
        input.channel,
        input.message,
        input.proof,
        None,
    )
    .await
}

pub async fn slack_react(
    State(state): State<ServerLock>,
    Json(input): Json<SlackReact>,
) -> AppResult<Response> {
    react(
        state,
        Namespace::Slack,
        input.channel,
        MessageId(input.timestamp),
        &input.emoji,
    )
    .await
}

/// Ask an admin for a badge. The request is a proof — that the member is unbanned, and that
/// they do not already hold a badge that contradicts this one — and it commits to a callback
/// the admin invokes to grant it.
pub async fn slack_request_badge(
    State(state): State<ServerLock>,
    Json(input): Json<SlackProofOnly>,
) -> AppResult<Response> {
    let (callbacks, index) = {
        let mut st = state.write().await;
        let vk = st.keys.badge_request_verifying_key.clone();

        let mut reader = decode(Kind::BadgeRequest, &input.proof)?;
        let exec: ExecutedMethod<F, Snark, Args, Cr, 1> = reader.pull()?;
        let inputs = pub_inputs(&mut reader, 3)?;
        // `pk` is proved to be the requester's member key. Server-backed joins do not yet
        // register a key per account, so it is not checked against the requester here.
        let (index, claimed, pk) = (inputs[0], inputs[1], inputs[2]);

        let current = epoch(&st.db);
        let callbacks = verify_and_store(
            &mut st.db,
            &vk,
            exec,
            BadgesArgs { i: index, claimed, pk },
            current,
            INTERACTION,
        )
        .map_err(|_| {
            AppError::Rejected(
                "Cannot request new badge: proof failed. Check if you are banned or have a \
                 Student or Faculty badge (you cannot have both)."
                    .into(),
            )
        })?;

        (callbacks, field_to_string(index))
    };

    let transport = state.read().await.slack.transport.clone();
    let sent = transport
        .send(Outgoing::new(
            ConversationId(input.channel),
            "A new Badge has been requested... Waiting for Admin Review",
        ))
        .await?;

    let mut st = state.write().await;
    for cb in &callbacks {
        st.slack.records.record(&sent.id, cb.clone())?;
        st.badges.request(StoredBadge {
            i: index.parse().unwrap_or(0),
            claimed: badge_name(&index).to_string(),
            cb: cb.clone(),
            timestamp: sent.id.0.clone(),
        })?;
    }

    Ok(ok())
}

/// ShowBadge on Slack, relayed as a normal message so it has a callback target.
pub async fn slack_show_badge(
    State(state): State<ServerLock>,
    Json(input): Json<SlackPost>,
) -> AppResult<Response> {
    post(
        state,
        Namespace::Slack,
        Flavour::Claim(Claim::ShowBadge),
        "badge",
        input.channel,
        input.message,
        input.proof,
        None,
    )
    .await
}

/// MergePersonas on Slack.
pub async fn slack_merge_personas(
    State(state): State<ServerLock>,
    Json(input): Json<SlackPost>,
) -> AppResult<Response> {
    let flavour = Flavour::Claim(Claim::MergePersonas);
    post(state, Namespace::Slack, flavour, "author", input.channel, input.message, input.proof, None).await
}

/// RepAtLeast on Slack.
pub async fn slack_rep_at_least(
    State(state): State<ServerLock>,
    Json(input): Json<SlackPost>,
) -> AppResult<Response> {
    let flavour = Flavour::Claim(Claim::RepAtLeast);
    post(state, Namespace::Slack, flavour, "rep_at_least", input.channel, input.message, input.proof, None).await
}

/// A post's message with its claim, if it has one, shown above it.
fn with_claim(verified: &Verified, message: String) -> String {
    match &verified.claim {
        Some(claim) => format!("✔ This persona {claim}.\n\n{message}"),
        None => message,
    }
}

// ---------------------------------------------------------------------------------------
// The shared bodies
// ---------------------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn post(
    state: ServerLock,
    ns: Namespace,
    flavour: Flavour,
    label: &str,
    conversation: String,
    message: String,
    proof: Vec<u8>,
    reply_to: Option<MessageId>,
) -> AppResult<Response> {
    let (verified, thread) = {
        let mut st = state.write().await;
        let payload = if matches!(flavour, Flavour::Claim(_)) {
            persona::server_claim_payload(&conversation, &message)
        } else {
            let reply = reply_to.as_ref().map(|m| m.as_str());
            persona::server_post_payload(&conversation, reply, &message)
        };
        let verified = verify_post(&mut st, flavour, &proof, label, payload)?;
        let thread = thread_for(&st, ns, &verified)?;
        (verified, thread)
    };

    let mut msg = Outgoing::new(ConversationId(conversation), with_claim(&verified, message));
    // An explicit reply target (this is a reply) wins over the thread a rate-limited post
    // belongs to; they are never both set.
    msg.reply_to = reply_to.or(thread);

    relay(&state, ns, verified, msg).await?;
    bench::close_latency(label);

    Ok(ok())
}

async fn react(
    state: ServerLock,
    ns: Namespace,
    conversation: String,
    target: MessageId,
    emoji: &str,
) -> AppResult<Response> {
    let emoji = emoji_for(emoji);
    let conversation = ConversationId(conversation);

    let transport = state.read().await.channel(ns).transport.clone();
    transport.react(&conversation, &target, emoji).await?;

    let delta = match crate::state::emoji_name(emoji) {
        "upvote" => 1,
        "downvote" => -1,
        other => {
            // Flags and ban suggestions are not ratings. They are a prompt for a human to
            // open a ban poll, and they change nobody's reputation on their own.
            tracing::info!("{other} reaction on {target} noted, no reputation change");
            0
        }
    };

    if delta != 0 {
        state
            .write()
            .await
            .channel_mut(ns)
            .records
            .rate(&target, delta)?;
    }

    Ok(ok())
}



/// Public inputs, checked for length before anything indexes into them.
///
/// The old code read `pub_inputs[1]` straight off the wire, so a proof carrying a shorter
/// vector than its route expected panicked the handler — a remote crash from a member who
/// simply sent the wrong record to the wrong route.
fn pub_inputs(reader: &mut personas_wire::Reader, expected: usize) -> AppResult<Vec<F>> {
    let inputs: Vec<F> = reader.pull()?;

    if inputs.len() < expected {
        return Err(AppError::BadRequest(format!(
            "this proof needs {expected} public inputs, got {}",
            inputs.len()
        )));
    }

    Ok(inputs)
}

/// A field element as the decimal string the contexts and badge logs are keyed by.
///
/// The same encoding the client writes when it stores a context, and the same one the badge
/// log keys on: `into_bigint().to_string()`, canonical decimal.
pub fn field_to_string(f: F) -> String {
    f.into_bigint().to_string()
}
