//! The `personas` CLI.
//!
//! One flat command set over the two route families the server exposes. Configuration is
//! resolved once (defaults → `deploy/profiles/<name>.toml` → `PERSONAS_*` env → these CLI
//! flags), the transport it names picks which family to talk to, and the matching dispatcher
//! ([`signal`] or [`slack`]) runs the command. Proving is CPU-bound and slow, so each command
//! runs it on a blocking thread.
//!
//! The runtime is built by hand rather than via `#[tokio::main]` so it can be shut down
//! *before* `personas` is dropped: `PersonaClient` holds a `reqwest::blocking::Client`, which
//! owns its own runtime, and dropping that from inside any tokio context — even a blocking
//! thread — panics. Dropping it after the runtime is gone is fine.

mod messenger;
mod parse;
mod signal;
mod slack;

use anyhow::{Context, Result, bail};
use clap::Parser;
use personas_client::{Namespace, PersonaClient};
use personas_config::Config;
use reqwest::Client;
use url::Url;

use crate::parse::{Cli, Command};

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Layer 1–3: defaults, the selected profile, the legacy env vars.
    let mut cfg = if let Some(name) = &cli.profile {
        let path = personas_config::profile_path(name);
        if !path.exists() {
            bail!("profile {name:?} not found at {}", path.display());
        }
        Config::load_from(Some(&path)).map_err(|e| anyhow::anyhow!("{e}"))?
    } else {
        Config::load().map_err(|e| anyhow::anyhow!("{e}"))?
    };
    cfg.validate().map_err(|e| anyhow::anyhow!("{e}"))?;

    // Layer 4: CLI overrides win over everything.
    if let Some(api) = &cli.api {
        cfg.client.api =
            Url::parse(api).with_context(|| format!("--api is not a valid URL: {api}"))?;
    }
    if let Some(dir) = &cli.data_dir {
        cfg.client.data_dir = Some(dir.clone());
    }
    if let Some(t) = cli.transport {
        cfg.client.transport = t.into();
    }

    // Serverless mode runs a local replica and never touches the HTTP client below,
    // so it branches out before any of that is built.
    if let Command::Messenger(cmd) = &cli.command {
        return messenger::run(cmd, &cfg);
    }

    let namespace: Namespace = cfg.client.transport.into();
    let personas = PersonaClient::new(personas_client::ClientConfig::from_config(&cfg, namespace));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("could not start the async runtime")?;

    let result = runtime.block_on(async {
        let http = Client::new();
        match namespace {
            Namespace::Signal => signal::run(&personas, http, cli.command).await,
            Namespace::Slack => slack::run(&personas, http, cli.command).await,
        }
    });

    // Tear the runtime down first; only then is it safe to drop `personas` (and its blocking
    // HTTP client's own runtime), now that no tokio context is on this thread.
    drop(runtime);
    drop(personas);

    result
}

/// The server's response body, printed for the operator. Shared by both dispatchers.
pub(crate) async fn show(res: reqwest::Response) -> Result<()> {
    println!("Server responded: {}", res.text().await?);
    Ok(())
}

/// `invite-gen`: print `count` fresh one-time invite codes (128 random bits each, as hex).
fn invite_gen(count: usize) {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    for _ in 0..count {
        let mut code = [0u8; 16];
        rng.fill_bytes(&mut code);
        println!("{}", code.iter().map(|b| format!("{b:02x}")).collect::<String>());
    }
}

/// `admin-keygen`: write a fresh group admin secret key to `out` (owner-only) and print the
/// public key. Refuses to overwrite an existing file, so a key in use is never lost.
fn admin_keygen(out: &std::path::Path) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let (secret, public) = personas_core::moderation::generate_admin_key();
    if let Some(dir) = out.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .with_context(|| format!("could not create {} (it must not exist yet)", out.display()))?;
    writeln!(file, "{secret}")?;
    println!("wrote the admin secret key to {}", out.display());
    println!("admin public key: {public}");
    println!("server:       PERSONAS_ADMIN_PK={public}");
    println!("admin client: PERSONAS_ADMIN_KEY_FILE={}", out.display());
    Ok(())
}
