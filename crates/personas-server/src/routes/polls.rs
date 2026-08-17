//! Polls and votes — including the ban vote, which is the group's moderation power.
//!
//! A vote is proof-carrying. The voter proves, in zero knowledge, that they are an unbanned
//! member and that they are voting under a pseudonym derived from *this poll's* context. The
//! server learns which pseudonym voted and nothing else; two ballots from the same pseudonym
//! are the same member voting twice, and that is the only linkage anyone can draw.
//!
//! Which is why there are no vote buttons. A messenger button press carries no proof, and it
//! identifies the presser to the server *before* the pseudonymous proof arrives — correlating
//! the two by timing would link the pseudonym to the account. The old server pressed on
//! anyway, by spawning the `slack-client` binary on every click. Polls now display their id
//! and a member votes from their own client, with their own key.

use ark_ff::PrimeField;
use axum::extract::{Json, State};
use axum::response::Response;
use personas_core::{F, persona};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use transport_api::{ConversationId, MessageId, Outgoing, Poll, PollKind};

use crate::bench;
use crate::error::{AppError, AppResult, ok};
use crate::state::{Ballot, PollEntry, ServerLock, SlackPoll, emoji_for, emoji_name};

// ---------------------------------------------------------------------------------------
// Signal polls: a file, so a tally survives a restart.
// ---------------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SignalPoll {
    pub message: String,
    pub group_id: String,
}

#[derive(Deserialize)]
pub struct SignalBanPoll {
    pub message: Option<String>,
    pub group_id: String,
    /// The message the group is being asked to ban someone over.
    pub timestamp: u64,
}

#[derive(Deserialize)]
pub struct SignalVote {
    pub group_id: String,
    pub emoji: String,
    /// The poll being voted in.
    pub timestamp: u64,
    /// The pseudonym the vote is cast under, as a decimal field element.
    pub claimed: String,
    pub proof: Vec<u8>,
}

#[derive(Deserialize)]
pub struct SignalCountVotes {
    pub group_id: String,
    pub timestamp: u64,
}

pub async fn signal_poll(
    State(state): State<ServerLock>,
    Json(input): Json<SignalPoll>,
) -> AppResult<Response> {
    open(state, input.group_id, input.message, None).await
}

pub async fn signal_ban_poll(
    State(state): State<ServerLock>,
    Json(input): Json<SignalBanPoll>,
) -> AppResult<Response> {
    open(
        state,
        input.group_id,
        input.message.unwrap_or_default(),
        Some(MessageId::from(input.timestamp)),
    )
    .await
}

/// Post a poll and open it for voting.
async fn open(
    state: ServerLock,
    conversation: String,
    body: String,
    target: Option<MessageId>,
) -> AppResult<Response> {
    let context = fresh_context();
    let is_ban = target.is_some();

    let poll = Poll {
        // Named for the moment it was created, as the old code did. The id is what a voter
        // passes to their client, so it has to be stable and printable.
        id: format!("vote_{}", now_secs()),
        question: if is_ban {
            "Ban this user?".to_string()
        } else {
            body.clone()
        },
        options: if is_ban {
            vec!["Yes".into(), "No".into()]
        } else {
            vec!["Yes".into(), "No".into()]
        },
        kind: if is_ban {
            PollKind::Ban
        } else {
            PollKind::Standard
        },
        target: target.clone(),
    };

    let transport = state.read().await.signal.transport.clone();

    let mut msg = Outgoing::new(ConversationId(conversation), body);
    msg.poll = Some(poll);
    msg.reply_to = target.clone();

    let sent = transport.send(msg).await?;

    // The poll is keyed by the id of the message announcing it: a Signal vote quotes that
    // message, so that is the handle the voter has.
    let timestamp = sent
        .id
        .as_u64()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("signal gave a non-numeric id")))?;

    state.write().await.polls.open_poll(PollEntry {
        timestamp,
        votes: vec![],
        ban: target
            .as_ref()
            .and_then(|t| t.as_u64())
            .map(|t| t as i64)
            .unwrap_or(0),
        context,
    })?;

    Ok(ok())
}

/// Cast a proof-carrying vote.
pub async fn signal_vote(
    State(state): State<ServerLock>,
    Json(input): Json<SignalVote>,
) -> AppResult<Response> {
    let claimed = parse_field(&input.claimed)?;
    let name = persona::petname(claimed);

    {
        let st = state.read().await;
        let vk = st.keys.pseudonym_pred_verifying_key.clone();
        super::post::verify_predicate(&vk, &input.proof, "pseudo_vote", "Cannot submit vote")?;
    }

    let emoji = emoji_for(&input.emoji);

    let transport = state.read().await.signal.transport.clone();
    let mut msg = Outgoing::new(
        ConversationId(input.group_id),
        format!("VOTE FROM: {name}\n\n{emoji}"),
    );
    msg.reply_to = Some(MessageId::from(input.timestamp));
    transport.send(msg).await?;

    bench::close_latency("pseudo_vote");

    match emoji_name(emoji) {
        "upvote" | "downvote" | "ban" | "not ban" => {
            state.write().await.polls.cast(
                input.timestamp,
                Ballot {
                    poll_pseudonym: name,
                    seed: input.claimed,
                    emoji: emoji.to_string(),
                },
            )?;
        }
        other => tracing::info!("{other} is not a ballot; not counted"),
    }

    Ok(ok())
}

/// Close a poll and announce the tally.
pub async fn signal_count_votes(
    State(state): State<ServerLock>,
    Json(input): Json<SignalCountVotes>,
) -> AppResult<Response> {
    let (yes, no, is_ban) = {
        let st = state.read().await;
        let poll = st
            .polls
            .get(input.timestamp)
            .ok_or_else(|| AppError::NotFound(format!("no poll at {}", input.timestamp)))?;
        let (yes, no) = poll.tally();
        (yes, no, poll.is_ban())
    };

    let body = tally_message(yes, no, is_ban);

    let transport = state.read().await.signal.transport.clone();
    let mut msg = Outgoing::new(ConversationId(input.group_id), body);
    msg.reply_to = Some(MessageId::from(input.timestamp));
    transport.send(msg).await?;

    if is_ban && yes > no {
        // The vote *recommends* a ban. It does not perform one: banning is invoking the
        // callback the offending post committed to, which an admin does through `/api/ban`.
        // Making the tally itself perform the ban is what `AllowedToRevoke` is for, and it
        // needs a bulletin that can hold the tally — see workstream d.
        tracing::warn!(
            "poll {} voted {yes}-{no} to ban; an admin must invoke the callback",
            input.timestamp
        );
    }

    // Only close a poll that somebody voted in. A poll with no votes stays open — which is
    // what the old code did, and it means "count the votes" is also "have we got any yet?".
    if yes + no > 0 {
        state.write().await.polls.close(input.timestamp)?;
    }

    Ok(ok())
}

fn tally_message(yes: usize, no: usize, is_ban: bool) -> String {
    let total = yes + no;
    let percent = |n: usize| {
        if total == 0 {
            0.0
        } else {
            (n as f64 / total as f64) * 100.0
        }
    };

    let mut out = String::from("📊 *The Results are in!*\n\n");

    if is_ban {
        out.push_str("React with ❌ to *Ban* or ✅ to *Keep* this user.\n\n");
        out.push_str(&format!(
            "❌ Ban: {yes} ({:.1}%)\n✅ Keep: {no} ({:.1}%)\n",
            percent(yes),
            percent(no)
        ));
    } else {
        out.push_str("React with 👍 for *Yes*, 👎 for *No*.\n\n");
        out.push_str(&format!(
            "👍 Yes: {yes} ({:.1}%)\n👎 No: {no} ({:.1}%)\n",
            percent(yes),
            percent(no)
        ));
    }

    out.push_str(&format!("\n🧮 Total votes: {total}\n"));

    if total == 0 {
        out.push_str("⚠️ No votes yet.");
    } else if yes > no {
        out.push_str(if is_ban {
            "🔨 Majority voted to *Ban*."
        } else {
            "✅ Majority voted *Yes*."
        });
    } else if no > yes {
        out.push_str(if is_ban {
            "🛡️ Majority voted to *Keep* the user."
        } else {
            "❌ Majority voted *No*."
        });
    } else {
        out.push_str("🤷 It's a tie!");
    }

    out
}

// ---------------------------------------------------------------------------------------
// Slack polls: in memory, and forgotten on restart.
// ---------------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SlackPollRequest {
    pub question: String,
    pub option1: String,
    pub option2: String,
    pub option3: Option<String>,
    pub option4: Option<String>,
    pub channel: String,
}

#[derive(Deserialize)]
pub struct SlackBanPollRequest {
    pub message: Option<String>,
    pub channel: String,
    pub timestamp: String,
}

#[derive(Deserialize)]
pub struct SlackVoteId {
    pub vote_id: String,
}

#[derive(Deserialize)]
pub struct SlackResults {
    pub vote_id: String,
    pub channel: String,
}

#[derive(Deserialize)]
pub struct SlackVoteRequest {
    pub vote_id: String,
    pub channel: String,
    pub vote: String,
    pub claimed: String,
    pub proof: Vec<u8>,
}

#[derive(Serialize)]
pub struct ContextResponse {
    pub context: String,
}

pub async fn slack_poll(
    State(state): State<ServerLock>,
    Json(input): Json<SlackPollRequest>,
) -> AppResult<Response> {
    let mut options = vec![input.option1, input.option2];
    options.extend(input.option3);
    options.extend(input.option4);

    if options.len() < 2 {
        return Err(AppError::BadRequest(
            "A poll requires at least two options.".into(),
        ));
    }

    open_slack(
        state,
        input.channel,
        input.question.clone(),
        input.question,
        options,
        None,
    )
    .await
}

pub async fn slack_ban_poll(
    State(state): State<ServerLock>,
    Json(input): Json<SlackBanPollRequest>,
) -> AppResult<Response> {
    open_slack(
        state,
        input.channel,
        "📊 Ban Poll Initiated".to_string(),
        input.message.unwrap_or_default(),
        vec!["Yes".into(), "No".into()],
        Some(MessageId(input.timestamp)),
    )
    .await
}

async fn open_slack(
    state: ServerLock,
    channel: String,
    question: String,
    body: String,
    options: Vec<String>,
    target: Option<MessageId>,
) -> AppResult<Response> {
    let vote_id = format!("vote_{}", now_secs());
    let context = fresh_context();
    let is_ban = target.is_some();

    let transport = state.read().await.slack.transport.clone();

    let mut msg = Outgoing::new(ConversationId(channel), body);
    msg.poll = Some(Poll {
        id: vote_id.clone(),
        question,
        options: options.clone(),
        kind: if is_ban {
            PollKind::Ban
        } else {
            PollKind::Standard
        },
        target: target.clone(),
    });
    msg.reply_to = target;

    let sent = transport.send(msg).await?;

    let mut st = state.write().await;
    st.votes.votes.insert(
        vote_id,
        SlackPoll {
            timestamp: sent.id.0,
            context,
            voted: HashSet::new(),
            counts: options.into_iter().map(|o| (o, 0u32)).collect(),
            is_ban,
        },
    );
    st.votes.flush()?;

    Ok(ok())
}

/// The context a voter needs in order to derive their pseudonym for this poll.
pub async fn slack_poll_context(
    State(state): State<ServerLock>,
    Json(input): Json<SlackVoteId>,
) -> AppResult<Json<ContextResponse>> {
    let st = state.read().await;
    let poll = st
        .votes
        .votes
        .get(&input.vote_id)
        .ok_or_else(|| AppError::NotFound(format!("Unknown vote_id '{}'", input.vote_id)))?;

    Ok(Json(ContextResponse {
        context: poll.context.clone(),
    }))
}

/// Cast a proof-carrying vote in a Slack poll.
///
/// Synchronous, unlike the original, which spawned the verification onto a background task
/// and answered `{"status":"received"}` before it had checked anything — so a voter whose
/// proof was rejected learned about it from a message in the channel, and the CLI that sent
/// it exited 0. The caller now gets the verdict it asked for.
pub async fn slack_vote(
    State(state): State<ServerLock>,
    Json(input): Json<SlackVoteRequest>,
) -> AppResult<Response> {
    let claimed = parse_field(&input.claimed)?;
    let name = persona::petname(claimed);

    {
        let st = state.read().await;
        let vk = st.keys.pseudonym_pred_verifying_key.clone();
        super::post::verify_predicate(&vk, &input.proof, "pseudo_vote", "Cannot submit vote")?;
    }

    let announcement = {
        let mut st = state.write().await;
        let poll = st
            .votes
            .votes
            .get_mut(&input.vote_id)
            .ok_or_else(|| AppError::NotFound(format!("Poll {} not found", input.vote_id)))?;

        if !poll.counts.contains_key(&input.vote) {
            let options = poll.counts.keys().cloned().collect::<Vec<_>>().join(", ");
            return Err(AppError::BadRequest(format!(
                "Your vote is not one of the valid options: {options}"
            )));
        }

        // One member, one vote — enforced on the *pseudonym*, which is the only handle the
        // server has. It cannot tell who this is, only that it is someone who has not voted.
        if !poll.voted.insert(input.claimed.clone()) {
            return Err(AppError::BadRequest(format!(
                "{name} has already voted in poll {}",
                input.vote_id
            )));
        }

        *poll.counts.entry(input.vote.clone()).or_insert(0) += 1;
        let announcement = format!(
            "🗳️ {name} has voted for *{}*!\nCurrent counts: {:?}",
            input.vote, poll.counts
        );

        st.votes.flush()?;
        announcement
    };

    let transport = state.read().await.slack.transport.clone();
    transport
        .send(Outgoing::new(
            ConversationId(input.channel),
            announcement,
        ))
        .await?;

    Ok(ok())
}

pub async fn slack_poll_results(
    State(state): State<ServerLock>,
    Json(input): Json<SlackResults>,
) -> AppResult<Response> {
    let body = {
        let st = state.read().await;
        match st.votes.votes.get(&input.vote_id) {
            Some(poll) => results_message(&input.vote_id, &poll.counts, poll.is_ban),
            None => "No poll found with that id".to_string(),
        }
    };

    let transport = state.read().await.slack.transport.clone();
    transport
        .send(Outgoing::new(ConversationId(input.channel), body))
        .await?;

    Ok(ok())
}

fn results_message(vote_id: &str, counts: &HashMap<String, u32>, is_ban: bool) -> String {
    let mut out = format!("Results for poll `{vote_id}`:\n");

    let (mut yes, mut no) = (0, 0);
    for (option, count) in counts {
        out.push_str(&format!("• {option}: {count}\n"));

        if is_ban {
            match option.to_lowercase().as_str() {
                "yes" => yes = *count,
                "no" => no = *count,
                _ => {}
            }
        }
    }

    if is_ban && yes > no {
        out.push_str("\n ⚠️ *NOTICE FOR ADMINS*\n");
        out.push_str(
            "The above message has been flagged for abusive or inappropriate content. A \
             majority of voters recommended a ban. Please review and take appropriate action \
             (e.g., ban user with timestamp).\n",
        );
    }

    out
}

// ---------------------------------------------------------------------------------------

/// A poll's context: a fresh field element nobody can predict.
///
/// It scopes the pseudonyms voters derive, which is what makes "one member, one vote"
/// checkable in a poll while leaving votes in *different* polls unlinkable. If two polls
/// shared a context, a member's pseudonym would be the same in both.
fn fresh_context() -> String {
    use ark_std::UniformRand;
    let mut rng = rand::rngs::OsRng;
    F::rand(&mut rng).into_bigint().to_string()
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn parse_field(decimal: &str) -> AppResult<F> {
    let bigint = <F as PrimeField>::BigInt::from_str(decimal)
        .map_err(|_| AppError::BadRequest(format!("{decimal} is not a field element")))?;

    F::from_bigint(bigint)
        .ok_or_else(|| AppError::BadRequest(format!("{decimal} is not in the field")))
}

/// The poll context a Signal voter needs, looked up by the poll's message id.
#[derive(Deserialize)]
pub struct TimestampRequest {
    pub timestamp: i64,
}

pub async fn signal_poll_context(
    State(state): State<ServerLock>,
    Json(input): Json<TimestampRequest>,
) -> AppResult<Json<ContextResponse>> {
    let st = state.read().await;

    let context = st
        .polls
        .context_of(input.timestamp)
        .ok_or_else(|| AppError::NotFound("No context found for that timestamp".into()))?;

    Ok(Json(ContextResponse {
        context: context.to_string(),
    }))
}
