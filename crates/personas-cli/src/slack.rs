//! Dispatch for the Slack route family (`/api/slack/…`).
//!
//! A faithful port of the former `slack-client` binary: same routes, same request bodies, the
//! badge-image handling Slack renders, and a badge sync after the interactions that might have
//! picked one up. Commands the Slack transport does not serve (`reply`, `reply-pseudo`,
//! `single-rep`) return a clear error.

use crate::parse::Command;
use crate::show;

use anyhow::{Context, Result, bail};
use personas_client::{
    PersonaClient,
    badges::badge_name,
    flows::MessageId,
    personas_core::{F, circuits::string_hash_to_f, persona},
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::task::spawn_blocking;
use url::Url;

#[derive(Serialize)]
struct PostRequest {
    channel: String,
    message: String,
    proof: Vec<u8>,
}

#[derive(Serialize)]
struct ThreadRequest {
    channel: String,
    thread: String,
}

#[derive(Serialize)]
struct BadgeRequest {
    channel: String,
    proof: Vec<u8>,
}

#[derive(Serialize)]
struct ClaimBadgeRequest {
    channel: String,
    badge_bytes: Vec<u8>,
    badge_name: String,
    proof: Vec<u8>,
}

#[derive(Serialize)]
struct AuthorshipRequest {
    channel: String,
    proof: Vec<u8>,
}

#[derive(Serialize)]
struct PollRequest {
    question: String,
    option1: String,
    option2: String,
    option3: Option<String>,
    option4: Option<String>,
    channel: String,
}

#[derive(Serialize)]
struct BanPollRequest {
    message: Option<String>,
    channel: String,
    timestamp: String,
}

#[derive(Serialize)]
struct PollResultsRequest {
    vote_id: String,
    channel: String,
}

#[derive(Serialize)]
struct PollContextRequest {
    vote_id: String,
}

#[derive(Serialize)]
struct VoteRequest {
    vote_id: String,
    channel: String,
    vote: String,
    claimed: String,
    proof: Vec<u8>,
}

#[derive(Serialize)]
struct ReactRequest {
    channel: String,
    emoji: String,
    timestamp: String,
}

#[derive(Deserialize)]
struct ContextResponse {
    context: String,
}

pub async fn run(personas: &PersonaClient, http: Client, command: Command) -> Result<()> {
    let url = |route: &str| -> Result<Url> { personas.cfg.url(route) };

    match command {
        // Serverless mode does not use the HTTP client; `main` routes it before this
        // dispatcher runs. This arm only keeps the match exhaustive.
        Command::Messenger(_) => {
            bail!("serverless messenger mode is handled before transport dispatch");
        }

        Command::Join => {
            let pc = personas.clone();
            spawn_blocking(move || pc.join()).await??;
            println!("Joined successfully");
        }

        Command::Post { message, channel } => {
            let pc = personas.clone();
            let proof = spawn_blocking(move || pc.gen_cb_for_msg()).await??;

            let res = http
                .post(url("api/slack/post/anon")?)
                .json(&PostRequest {
                    channel,
                    message,
                    proof,
                })
                .send()
                .await?;
            show(res).await?;
        }

        Command::PostPseudo {
            message,
            channel,
            pseudo_idx,
        } => {
            let (claimed, context) = pseudonym_at(personas, pseudo_idx)?;

            let pc = personas.clone();
            let proof =
                spawn_blocking(move || pc.pseudo_proof_with_msg(claimed, context)).await??;

            let res = http
                .post(url("api/slack/post/pseudo")?)
                .json(&PostRequest {
                    channel,
                    message,
                    proof,
                })
                .send()
                .await?;
            show(res).await?;
        }

        Command::PostPseudoRate {
            message,
            channel,
            thread,
            pseudo_idx,
        } => {
            let context = personas.lookup_context(&thread).with_context(|| {
                format!("no context for thread {thread}; run `get-contexts` first")
            })?;

            let i = F::from(pseudo_idx as u32);
            let claimed = personas.pseudo_rate(&context, &i)?;

            let pc = personas.clone();
            let proof = spawn_blocking(move || pc.rate_pseudo_proof_with_msg(claimed, context, i))
                .await??;

            let res = http
                .post(url("api/slack/post/pseudo/rate")?)
                .json(&PostRequest {
                    channel,
                    message,
                    proof,
                })
                .send()
                .await?;
            show(res).await?;
        }

        Command::GetContexts => {
            let res = http
                .get(url("api/slack/pseudo/get_all_contexts")?)
                .send()
                .await?;

            let status = res.status();
            let body = res.text().await?;
            if !status.is_success() {
                bail!("server error ({status}): {body}");
            }

            personas.save_contexts(&body)?;
            println!(
                "Downloaded all contexts to {}",
                personas.cfg.contexts().display()
            );
        }

        Command::NewThreadCxt { thread, channel } => {
            let channel =
                channel.context("the slack transport needs -g/--channel for a new thread")?;
            let res = http
                .post(url("api/slack/pseudo/new_thread_context")?)
                .json(&ThreadRequest { channel, thread })
                .send()
                .await?;
            show(res).await?;
        }

        Command::RequestBadge { channel, i } => {
            // The badge request claims the badge's own constant (`FACULTY_F` and friends), not a
            // pseudonym — the moderator approves the credential, and only then does the member
            // choose which persona to show it under.
            let claimed: F = string_hash_to_f(badge_name(i));

            let pc = personas.clone();
            let proof = spawn_blocking(move || pc.gen_cb_for_badge_request(i, claimed)).await??;

            let res = http
                .post(url("api/slack/request/badges")?)
                .json(&BadgeRequest { channel, proof })
                .send()
                .await?;
            show(res).await?;
        }

        Command::Badge { i, channel, .. } => {
            let claimed_str = personas
                .claimed_by_badge_index(i)?
                .filter(|c| c != "0")
                .with_context(|| format!("badge {i} has not been granted yet"))?;

            let claimed = persona::field_from_str(&claimed_str)
                .context("badge log holds a malformed claimed value")?;

            let badge_name = format!("badge{i}");
            let badge_bytes = personas.badge_png(i)?;

            let pc = personas.clone();
            let proof = spawn_blocking(move || pc.make_badge_proof(i, claimed)).await??;

            let res = http
                .post(url("api/slack/claim/badges")?)
                .json(&ClaimBadgeRequest {
                    channel,
                    badge_bytes,
                    badge_name,
                    proof,
                })
                .send()
                .await?;
            show(res).await?;
        }

        Command::GenPseudo => {
            personas.gen_pseudo()?;
        }

        Command::PseudoIndex => {
            personas.list_pseudos()?;
        }

        Command::Scan => {
            // A sweep with k outstanding callbacks takes k `scan` proofs, one per
            // callback (FINDINGS O2) — loop the whole sweep here instead of making the
            // caller re-invoke `scan` k times and risk running another command
            // mid-sweep, which panics upstream.
            let total = personas.outstanding_callbacks()?;
            if total == 0 {
                println!("nothing to scan");
            } else {
                let mut i = 0;
                loop {
                    i += 1;
                    println!("scanning ({i}/{total})...");

                    let pc = personas.clone();
                    let proof = spawn_blocking(move || pc.scan()).await??;

                    let res = http
                        .post(url("api/interact/scan")?)
                        .body(proof)
                        .send()
                        .await?;
                    show(res).await?;

                    if !personas.is_scanning()? {
                        break;
                    }
                }
                println!(
                    "scan complete; {} callback(s) now outstanding",
                    personas.outstanding_callbacks()?
                );
                sync_badges(personas);
            }
        }

        Command::ScanFolding => {
            let pc = personas.clone();
            let proof = spawn_blocking(move || pc.fold()).await??;

            let res = http
                .post(url("api/interact/foldscan")?)
                .header("Content-Length", proof.len())
                .body(proof)
                .send()
                .await?;
            show(res).await?;
            sync_badges(personas);
        }

        Command::UpdateEpoch => {
            let res = http.get(url("api/epoch")?).send().await?;
            show(res).await?;
            sync_badges(personas);
        }

        Command::Rep => {
            println!("Recording rep...");

            let pc = personas.clone();
            spawn_blocking(move || pc.process_reputation_updates()).await??;

            println!("Recorded");
        }

        Command::ApproveBadge => {
            println!("Approving badges...");

            let pc = personas.clone();
            spawn_blocking(move || pc.process_badge_updates()).await??;

            println!("Approved all outstanding badge requests!");
        }

        Command::GetRep => {
            println!("Your Reputation Score = {}", personas.reputation()?);
        }

        Command::Ban { t } => {
            println!("Banning...");

            let pc = personas.clone();
            spawn_blocking(move || pc.ban(&MessageId::Slack(t))).await??;

            println!("Banned user");
        }

        Command::Authorship {
            pseudo_idx1,
            pseudo_idx2,
            channel,
        } => {
            let pc = personas.clone();
            let proof = spawn_blocking(move || pc.make_authorship_proof(pseudo_idx1, pseudo_idx2))
                .await??;

            println!("Authorship proof successfully generated");

            let res = http
                .post(url("api/slack/claim/authorship")?)
                .json(&AuthorshipRequest { channel, proof })
                .send()
                .await?;
            show(res).await?;
        }

        Command::Poll {
            question,
            option1,
            option2,
            option3,
            option4,
            channel,
            ..
        } => {
            let question =
                question.context("the slack transport needs -q/--question for a poll")?;
            let option1 = option1.context("the slack transport needs --option1 for a poll")?;
            let option2 = option2.context("the slack transport needs --option2 for a poll")?;
            let res = http
                .post(url("api/slack/poll")?)
                .json(&PollRequest {
                    question,
                    option1,
                    option2,
                    option3,
                    option4,
                    channel,
                })
                .send()
                .await?;
            show(res).await?;
        }

        Command::BanPoll {
            message,
            channel,
            timestamp,
        } => {
            let res = http
                .post(url("api/slack/banpoll")?)
                .json(&BanPollRequest {
                    message,
                    channel,
                    timestamp,
                })
                .send()
                .await?;
            show(res).await?;
        }

        Command::Vote {
            channel,
            vote_id,
            vote,
            ..
        } => {
            let vote_id = vote_id.context("the slack transport votes by --vote-id")?;
            let vote = vote.context("the slack transport votes with --vote (e.g. option1)")?;

            let res = http
                .post(url("api/slack/poll/context")?)
                .json(&PollContextRequest {
                    vote_id: vote_id.clone(),
                })
                .send()
                .await
                .context("failed to reach the poll context endpoint")?;

            let context_resp: ContextResponse = res
                .json()
                .await
                .context("server returned no poll context")?;

            let context = persona::field_from_str(&context_resp.context)
                .context("server returned a malformed poll context")?;
            let claimed = personas.pseudo_for_poll(&context)?;

            let pc = personas.clone();
            let proof = spawn_blocking(move || pc.pseudo_proof_vote(claimed, context)).await??;

            let res = http
                .post(url("api/slack/vote")?)
                .json(&VoteRequest {
                    vote_id,
                    channel,
                    vote,
                    claimed: claimed.to_string(),
                    proof,
                })
                .send()
                .await?;
            show(res).await?;
        }

        Command::CountVotes {
            channel, vote_id, ..
        } => {
            let vote_id = vote_id.context("the slack transport counts by --vote-id")?;
            let res = http
                .post(url("api/slack/poll/results")?)
                .json(&PollResultsRequest { vote_id, channel })
                .send()
                .await?;

            println!("Server responded with poll results: {}", res.text().await?);
        }

        Command::Reaction {
            channel,
            emoji,
            timestamp,
        } => {
            let res = http
                .post(url("api/slack/react")?)
                .json(&ReactRequest {
                    channel,
                    emoji,
                    timestamp,
                })
                .send()
                .await?;
            show(res).await?;
        }

        Command::Reply { .. } | Command::ReplyPseudo { .. } | Command::SingleRep { .. } => {
            bail!(
                "that command is not available on the slack transport; it is a signal capability"
            );
        }
    }

    Ok(())
}

/// The `(claimed, context)` field elements at a 1-based pseudonym-log index, falling back to
/// the first pseudonym.
fn pseudonym_at(personas: &PersonaClient, index: usize) -> Result<(F, F)> {
    let (claimed, context) = personas
        .claimed_context_by_index(index)
        .or_else(|_| personas.claimed_context_by_index(1))?;

    Ok((
        persona::field_from_str(&claimed)
            .context("pseudonym log holds a malformed claimed value")?,
        persona::field_from_str(&context).context("pseudonym log holds a malformed context")?,
    ))
}

/// Pick up any badge the moderator granted since the last scan. Advisory: a badge that fails to
/// sync is not a reason to fail the command that just succeeded.
fn sync_badges(personas: &PersonaClient) {
    match personas.sync_user_badges() {
        Ok(granted) if !granted.is_empty() => {
            for i in granted {
                println!("Badge granted: {} ({i})", badge_name(i));
            }
        }
        Ok(_) => {}
        Err(e) => eprintln!("failed to sync badges: {e}"),
    }
}
