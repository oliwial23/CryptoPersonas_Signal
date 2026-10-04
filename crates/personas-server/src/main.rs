//! The personas server: it verifies proofs, keeps the bulletin, and relays what verifies.
//!
//! # What it is trusted for, and what it is not
//!
//! It is trusted to *deliver*. It relays a member's post to the group, and in the
//! as-a-service deployment every message the group sees comes from one phantom account, so
//! the server necessarily knows who asked for what to be posted. Removing that is the whole
//! point of the serverless design (workstream d/e), and it is why this is called
//! "as-a-service" rather than "the system".
//!
//! It is *not* trusted for anything cryptographic. It cannot forge a post, because a post is
//! a proof against a bulletin whose contents every client can fetch. It cannot ban a member it
//! has no callback ticket for. It cannot apply a rating twice, or apply one the circuit
//! forbids. What it can do is refuse — and a refusal is visible.

mod bench;
mod bulletin;
mod error;
mod routes;
mod state;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use personas_config::{Config, SignalBackend, SlackBackend};
use personas_core::params::{ensure_params, load_or_create_store};
use personas_core::privpass::{ensure_batch_ticket_keys, load_or_create_issuer_keys};
use tokio::signal;
use tokio::sync::RwLock;
use tracing::{info, info_span, warn};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use transport_api::Transport;
use transport_mock::MockTransport;
use transport_signal_cli::{SignalCliConfig, SignalCliTransport};
use transport_slack::{SlackConfig, SlackTransport};

use crate::state::ServerState;

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider())
        .map_err(|_| anyhow::anyhow!("could not install the rustls crypto provider"))?;

    dotenvy::dotenv().ok();

    let cfg = Config::load().context("could not load configuration")?;
    cfg.validate()?;
    init_tracing(&cfg.log.level);

    let data_dir = cfg.server.data_dir.clone();

    // The store's genesis is rebuilt from a seed on disk, so its public keys — and the SNARK
    // keys generated against them — survive a restart.
    let span = info_span!("store").entered();
    info!("reconstructing the bulletin from {}", data_dir.display());
    let db = load_or_create_store(&data_dir)?;
    span.exit();

    // Minutes on a cold start, seconds from the content-addressed cache.
    let span = info_span!("params").entered();
    info!("loading proving keys");
    let mut rng = rand::thread_rng();
    let artifacts = ensure_params(&mut rng, &db, &data_dir.join("params"))?;
    span.exit();

    // Privacy Pass (FINDINGS O7): entirely additive, its own cache, never touches the keys
    // or cache directory above.
    let span = info_span!("privpass").entered();
    let privpass_issuer = load_or_create_issuer_keys(&mut rng, &data_dir)?;
    let obj_pubkey_bytes = {
        let mut bytes = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(&db.obj_bul.get_pubkey(), &mut bytes)?;
        bytes
    };
    let (privpass_batch_pk, privpass_batch_vk) =
        ensure_batch_ticket_keys(&mut rng, &obj_pubkey_bytes, &data_dir.join("params"))?;
    span.exit();

    let signal = signal_transport(&cfg);
    let slack = slack_transport(&cfg);
    info!(
        "relaying over {} (signal routes) and {} (slack routes)",
        signal.name(),
        slack.name()
    );

    let state = Arc::new(RwLock::new(ServerState::new(
        &data_dir,
        db,
        artifacts.keys,
        artifacts.folding,
        signal,
        slack,
        privpass_issuer,
        privpass_batch_pk,
        privpass_batch_vk,
    )?));

    // Slack's socket-mode listener, and with it the 👍/👎 rating buttons and reaction events.
    // A transport with nothing to listen for says so, and that is not an error.
    spawn_event_listener(state.clone());

    let addr: SocketAddr = cfg.server.bind;

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("could not bind {addr}"))?;
    info!("listening on http://{addr}");

    axum::serve(listener, routes::router(state))
        .with_graceful_shutdown(async {
            let _ = signal::ctrl_c().await;
            // The params cache, the store seed, and the ledger stay on disk: the next start
            // reuses all three.
            info!("shutting down");
        })
        .await?;

    Ok(())
}

/// The messenger the `/api/…` routes relay through.
///
/// Falls back to the mock. That fallback is the difference between a checkout that runs and
/// one that does not: the old server required `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN` and
/// `SIGNAL_BOT_NUMBER` to be set *at startup* or it exited, and then shelled out to a
/// `signal-cli` daemon that also had to be running. With no credentials at all, this now
/// comes up and posts to an in-process chat log. Which side of that fork we take is
/// [`Config::signal_backend`]'s decision; `PERSONAS_TRANSPORT=mock` forces the mock.
fn signal_transport(cfg: &Config) -> Arc<dyn Transport> {
    match cfg.signal_backend() {
        SignalBackend::Mock => {
            info!("the signal routes will relay to the mock transport");
            mock(cfg, "signal")
        }
        SignalBackend::SignalCli { account, daemon } => Arc::new(SignalCliTransport::new(
            SignalCliConfig::new(account, daemon),
        )),
    }
}

/// The messenger the `/api/slack/…` routes relay through.
fn slack_transport(cfg: &Config) -> Arc<dyn Transport> {
    match cfg.slack_backend() {
        SlackBackend::Mock => {
            info!("the slack routes will relay to the mock transport");
            mock(cfg, "slack")
        }
        SlackBackend::Slack {
            bot_token,
            app_token,
        } => match SlackTransport::new(SlackConfig {
            bot_token,
            app_token,
        }) {
            Ok(slack) => Arc::new(slack),
            Err(e) => {
                warn!("could not start the slack transport ({e}); falling back to the mock");
                mock(cfg, "slack")
            }
        },
    }
}

fn mock(cfg: &Config, name: &str) -> Arc<dyn Transport> {
    Arc::new(
        MockTransport::new()
            .with_log(cfg.server.data_dir.join(format!("{name}_chat.jsonl")))
            .with_echo(),
    )
}

/// Rating buttons and emoji reactions, as they arrive.
///
/// A rating is *accumulated* here, not applied: it is added to the ledger against the message
/// it was given to, and it changes nobody's object until someone invokes the callback that
/// message's poster committed to. The server cannot change a member's reputation on its own,
/// and this is where that shows.
fn spawn_event_listener(state: state::ServerLock) {
    tokio::spawn(async move {
        for ns in [state::Namespace::Signal, state::Namespace::Slack] {
            let transport = state.read().await.channel(ns).transport.clone();

            let stream = match transport.subscribe().await {
                Ok(stream) => stream,
                Err(transport_api::TransportError::Unsupported { transport, .. }) => {
                    info!("{transport} has no event stream; not listening for ratings there");
                    continue;
                }
                Err(e) => {
                    warn!("could not listen for events on {}: {e}", transport.name());
                    continue;
                }
            };

            tokio::spawn(events(state.clone(), ns, stream));
        }
    });
}

async fn events(
    state: state::ServerLock,
    ns: state::Namespace,
    mut stream: futures_util::stream::BoxStream<'static, transport_api::Incoming>,
) {
    use futures_util::StreamExt;
    use transport_api::Incoming;

    while let Some(event) = stream.next().await {
        match event {
            // An emoji reaction is neither counted nor announced.
            //
            // This looks like an omission and is not. `/api/react` — the route a client calls
            // to rate a message — already records the rating and then asks the messenger to
            // add the emoji. The messenger duly reports that emoji back to us as a
            // `reaction_added` event. Counting it here as well would apply every rating
            // twice (FINDINGS F2). That leaves an emoji added by hand in the Slack UI inert —
            // it changes no one's reputation — and this used to still send a "marked for an
            // increase/decrease" notice on every `reaction_added` regardless, which lied about
            // the hand-added case (FINDINGS O4). Only a rating that came through the personas
            // layer counts; the rating buttons below are the in-app path that does.
            Incoming::Reaction { .. } => continue,

            // The 👍/👎 buttons under a persona post. These *are* the personas layer's rating
            // path — no messenger reaction is added in response, so there is nothing to
            // double-count.
            Incoming::Feedback {
                conversation,
                target,
                positive,
                voter,
            } => {
                let delta = if positive { 1 } else { -1 };

                if let Err(e) = state
                    .write()
                    .await
                    .channel_mut(ns)
                    .records
                    .rate(&target, delta)
                {
                    warn!("could not record a rating on {target}: {e}");
                    continue;
                }

                // The reputation has not changed yet: the rating sits in the ledger until
                // someone invokes the callback the poster committed to when they posted.
                let ack = if positive {
                    "Message has been marked with positive feedback! 👍"
                } else {
                    "Message has been flagged for negative content. If further action is \
                     warranted, please submit a ban poll for review. 👎"
                };

                let transport = state.read().await.channel(ns).transport.clone();
                let mut msg = transport_api::Outgoing::new(conversation, ack);
                msg.ephemeral_to = Some(voter);

                if let Err(e) = transport.send(msg).await {
                    warn!("could not acknowledge the rating on {target}: {e}");
                }
            }

            // A member's own message is not a rating — serverless is what reads these for
            // content. As-a-service reads only one thing out of it: whether this is a
            // reply into a thread whose topic hasn't been echoed back yet (FINDINGS O9).
            Incoming::Message {
                conversation,
                reply_to,
                ..
            } => {
                let Some(thread_ts) = reply_to else { continue };

                let topic = state
                    .write()
                    .await
                    .channel_mut(ns)
                    .contexts
                    .topic_to_echo(&thread_ts.0);

                let topic = match topic {
                    Ok(Some(topic)) => topic,
                    Ok(None) => continue,
                    Err(e) => {
                        warn!("could not record the thread topic echo: {e}");
                        continue;
                    }
                };

                let transport = state.read().await.channel(ns).transport.clone();
                let mut msg =
                    transport_api::Outgoing::new(conversation, format!("🧵 *Topic:* {topic}"));
                msg.reply_to = Some(thread_ts);

                if let Err(e) = transport.send(msg).await {
                    warn!("could not echo the thread topic: {e}");
                }
            }
        }
    }
}

fn init_tracing(level: &str) {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::new(format!(
            "server={level},personas_core={level},transport_slack={level},\
             transport_signal_cli={level},transport_mock={level}"
        )))
        .init();
}
