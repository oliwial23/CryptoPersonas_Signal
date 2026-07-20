//! Dispatch for the Signal route family (`/api/…`).
//!
//! A faithful port of the former `client` binary: same routes, same request bodies, same
//! benchmark stamps the `bench/*.py` harness reads. Commands the Signal transport does not
//! serve (`get-rep`, `request-badge`, `approve-badge`) return a clear error.

use crate::parse::Command;
use crate::show;

use anyhow::{Context, Result, bail};
use personas_client::{
    PersonaClient,
    flows::MessageId,
    personas_core::{F, persona, timing},
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use tokio::task::spawn_blocking;
use url::Url;

#[derive(Serialize)]
struct PostRequest {
    message: String,
    group_id: String,
    proof: Vec<u8>,
}

#[derive(Serialize)]
struct ReactRequest {
    group_id: String,
    emoji: String,
    timestamp: u64,
}

#[derive(Serialize)]
struct ReplyRequest {
    group_id: String,
    message: String,
    timestamp: u64,
    proof: Vec<u8>,
}

#[derive(Serialize)]
struct VoteRequest {
    group_id: String,
    emoji: String,
    timestamp: u64,
    claimed: String,
    proof: Vec<u8>,
}

#[derive(Serialize)]
struct PollRequest {
    message: String,
    group_id: String,
}

#[derive(Serialize)]
struct BanPollRequest {
    message: Option<String>,
    group_id: String,
    timestamp: u64,
}

#[derive(Serialize)]
struct CountVotesRequest {
    group_id: String,
    timestamp: u64,
}

#[derive(Serialize)]
struct ProofRequest {
    proof: Vec<u8>,
    group_id: String,
}

#[derive(Serialize)]
struct ContextRequest {
    thread: String,
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

            stamp("anon_msg");
            let res = http
                .post(url("api/jsonrpc")?)
                .json(&PostRequest {
                    message,
                    group_id: channel,
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

            stamp("pseudo_msg");
            let res = http
                .post(url("api/jsonrpc/pseudo")?)
                .json(&PostRequest {
                    message,
                    group_id: channel,
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

            stamp("rate_pseudo");
            let res = http
                .post(url("api/jsonrpc/pseudo/rate")?)
                .json(&PostRequest {
                    message,
                    group_id: channel,
                    proof,
                })
                .send()
                .await?;
            show(res).await?;
        }

        Command::NewThreadCxt { thread, .. } => {
            let res = http
                .post(url("api/pseudo/new_thread_context")?)
                .json(&ContextRequest { thread })
                .send()
                .await?;
            show(res).await?;
        }

        Command::GetContexts => {
            let res = http.get(url("api/pseudo/get_all_contexts")?).send().await?;

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

        Command::GenPseudo => {
            personas.gen_pseudo()?;
        }

        Command::PseudoIndex => {
            personas.list_pseudos()?;
        }

        Command::Scan => {
            println!("Scanning...");

            let pc = personas.clone();
            let proof = spawn_blocking(move || pc.scan()).await??;

            let start = SystemTime::now();
            let res = http
                .post(url("api/interact/scan")?)
                .body(proof)
                .send()
                .await?;
            record("scan", start);

            show(res).await?;
        }

        Command::ScanFolding => {
            let pc = personas.clone();
            let proof = spawn_blocking(move || pc.fold()).await??;
            println!("Proof byte length: {} bytes", proof.len());

            let res = http
                .post(url("api/interact/foldscan")?)
                .header("Content-Length", proof.len())
                .body(proof)
                .send()
                .await?;
            show(res).await?;
        }

        Command::Poll {
            message, channel, ..
        } => {
            let message = message.context("the signal transport needs -m/--message for a poll")?;
            let res = http
                .post(url("api/poll")?)
                .json(&PollRequest {
                    message,
                    group_id: channel,
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
                .post(url("api/banpoll")?)
                .json(&BanPollRequest {
                    message,
                    group_id: channel,
                    timestamp: ts(&timestamp)?,
                })
                .send()
                .await?;
            show(res).await?;
        }

        Command::Vote {
            channel,
            timestamp,
            emoji,
            ..
        } => {
            let timestamp =
                ts(&timestamp.context("the signal transport votes by -t/--timestamp")?)?;
            let emoji = emoji.context("the signal transport votes with -e/--emoji")?;

            // The vote is bound to the poll's context, which only the server knows.
            let res = http
                .post(url("api/context")?)
                .json(&serde_json::json!({ "timestamp": timestamp }))
                .send()
                .await
                .context("failed to reach the context endpoint")?;

            let context_resp: ContextResponse = res
                .json()
                .await
                .context("server returned no poll context")?;

            let context = persona::field_from_str(&context_resp.context)
                .context("server returned a malformed poll context")?;
            let claimed = personas.pseudo_for_poll(&context)?;

            let pc = personas.clone();
            let proof = spawn_blocking(move || pc.pseudo_proof_vote(claimed, context)).await??;

            stamp("pseudo_vote");
            let res = http
                .post(url("api/vote")?)
                .json(&VoteRequest {
                    group_id: channel,
                    emoji,
                    timestamp,
                    claimed: claimed.to_string(),
                    proof,
                })
                .send()
                .await?;
            show(res).await?;
        }

        Command::CountVotes {
            channel, timestamp, ..
        } => {
            let timestamp =
                ts(&timestamp.context("the signal transport counts by -t/--timestamp")?)?;
            let res = http
                .post(url("api/votecount")?)
                .json(&CountVotesRequest {
                    group_id: channel,
                    timestamp,
                })
                .send()
                .await?;
            show(res).await?;
        }

        Command::Ban { t } => {
            println!("Banning...");
            let start = SystemTime::now();

            let pc = personas.clone();
            let id = ts(&t)?;
            spawn_blocking(move || pc.ban(&MessageId::Signal(id))).await??;

            record("ban", start);
            println!("Banned");
        }

        Command::SingleRep { t } => {
            println!("Recording rep...");
            let start = SystemTime::now();

            let pc = personas.clone();
            let id = ts(&t)?;
            spawn_blocking(move || pc.rep(&MessageId::Signal(id))).await??;

            record("rep", start);
            println!("Recorded");
        }

        Command::Rep => {
            println!("Recording rep...");

            let pc = personas.clone();
            spawn_blocking(move || pc.process_reputation_updates()).await??;

            println!("Recorded");
        }

        Command::UpdateEpoch => {
            let res = http.get(url("api/epoch")?).send().await?;
            show(res).await?;
        }

        Command::Reaction {
            channel,
            emoji,
            timestamp,
        } => {
            let res = http
                .post(url("api/react")?)
                .json(&ReactRequest {
                    group_id: channel,
                    emoji,
                    timestamp: ts(&timestamp)?,
                })
                .send()
                .await?;
            show(res).await?;
        }

        Command::Reply {
            channel,
            message,
            timestamp,
        } => {
            let pc = personas.clone();
            let proof = spawn_blocking(move || pc.gen_cb_for_msg()).await??;

            let res = http
                .post(url("api/reply")?)
                .json(&ReplyRequest {
                    group_id: channel,
                    message,
                    timestamp: ts(&timestamp)?,
                    proof,
                })
                .send()
                .await?;
            show(res).await?;
        }

        Command::ReplyPseudo {
            channel,
            message,
            timestamp,
            pseudo_idx,
        } => {
            let (claimed, context) = pseudonym_at(personas, pseudo_idx)?;

            let pc = personas.clone();
            let proof =
                spawn_blocking(move || pc.pseudo_proof_with_msg(claimed, context)).await??;

            let res = http
                .post(url("api/reply/pseudo")?)
                .json(&ReplyRequest {
                    group_id: channel,
                    message,
                    timestamp: ts(&timestamp)?,
                    proof,
                })
                .send()
                .await?;
            show(res).await?;
        }

        Command::Authorship {
            pseudo_idx1,
            pseudo_idx2,
            channel,
        } => {
            let pc = personas.clone();
            let proof = spawn_blocking(move || pc.make_authorship_proof(pseudo_idx1, pseudo_idx2))
                .await??;

            stamp("author");
            let res = http
                .post(url("api/authorship")?)
                .json(&ProofRequest {
                    proof,
                    group_id: channel,
                })
                .send()
                .await?;
            show(res).await?;
        }

        Command::Badge {
            i,
            claimed,
            channel,
        } => {
            let claimed =
                claimed.context("the signal transport claims a badge with -b/--claimed")?;
            let claimed = persona::field_from_str(&claimed)
                .context("badge pseudonym is not a valid field element")?;

            let pc = personas.clone();
            let proof = spawn_blocking(move || pc.make_badge_proof(i, claimed)).await??;

            stamp("badge");
            let res = http
                .post(url("api/badges")?)
                .json(&ProofRequest {
                    proof,
                    group_id: channel,
                })
                .send()
                .await?;
            show(res).await?;
        }

        Command::GetRep | Command::ApproveBadge | Command::RequestBadge { .. } => {
            bail!(
                "that command is not available on the signal transport; it is a slack capability"
            );
        }
    }

    Ok(())
}

/// The `(claimed, context)` field elements at a 1-based pseudonym-log index, falling back to
/// the first pseudonym — a member always has at least one, minted at join.
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

/// Signal message timestamps are milliseconds since the epoch — a `u64`. The flat CLI carries
/// them as strings (Slack's are not numeric); parse here.
fn ts(s: &str) -> Result<u64> {
    s.parse::<u64>()
        .with_context(|| format!("{s:?} is not a signal timestamp (expected a u64)"))
}

/// Stamp the start of a round trip the server will close out. Best-effort: a failed benchmark
/// write must never fail the command.
fn stamp(label: &str) {
    if let Err(e) = timing::save_start_time(label) {
        eprintln!("failed to record start time for {label}: {e}");
    }
}

fn record(label: &str, start: SystemTime) {
    let Ok(elapsed) = start.elapsed() else { return };
    if let Err(e) =
        timing::append_timing_line_with_filename(label, start, elapsed.as_millis(), "features")
    {
        eprintln!("failed to record timing for {label}: {e}");
    }
}
