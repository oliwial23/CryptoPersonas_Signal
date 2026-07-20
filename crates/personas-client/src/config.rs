//! Where the client keeps its state and which server routes it talks to.
//!
//! This is the whole difference between the former `client` and `slack-client` crates:
//! a state directory and a handful of transport-namespaced routes. Everything else —
//! every circuit, proof, and bulletin interaction — is identical, which is why they
//! collapse into one [`super::PersonaClient`].
//!
//! The scalar values — server URL, state dir — now come from [`personas_config`] (built-in
//! defaults, `deploy/profiles/*.toml`, the legacy `PERSONAS_*` env vars, then CLI overrides).
//! This module keeps only what is client-specific: the namespaced route helpers and the paths
//! under the state dir.

use anyhow::{Context, Result};
use std::path::PathBuf;
use url::Url;

/// Which transport's server routes and state directory to use.
///
/// The server exposes a Signal route set (`/api/...`) and a parallel Slack one
/// (`/api/slack/...`) over the same bulletin and the same circuits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Namespace {
    Signal,
    Slack,
}

impl Namespace {
    /// The state directory each client used before the merge. Kept as the default so
    /// existing `user.bin` files and the `bench/*.py` harness still resolve.
    pub fn default_data_dir(self) -> &'static str {
        match self {
            Namespace::Signal => "client",
            Namespace::Slack => "slack-client",
        }
    }

    /// Lists every outstanding reputation callback the server holds for this transport.
    pub fn all_callbacks_route(self) -> &'static str {
        match self {
            Namespace::Signal => "api/cb/signal/all",
            Namespace::Slack => "api/cb/slack/all",
        }
    }

    /// Consumes a single reputation callback.
    pub fn reputation_route(self) -> &'static str {
        match self {
            Namespace::Signal => "api/reputation",
            Namespace::Slack => "api/slack/reputation",
        }
    }
}

impl From<personas_config::Transport> for Namespace {
    fn from(t: personas_config::Transport) -> Self {
        match t {
            personas_config::Transport::Signal => Namespace::Signal,
            personas_config::Transport::Slack => Namespace::Slack,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub api_base: Url,
    pub data_dir: PathBuf,
    pub namespace: Namespace,
}

impl ClientConfig {
    pub fn new(namespace: Namespace, api_base: Url, data_dir: PathBuf) -> Self {
        Self {
            api_base: with_trailing_slash(api_base),
            data_dir,
            namespace,
        }
    }

    /// Load the layered config (defaults → profile → `PERSONAS_*` env → …) and build a client
    /// for `namespace`. The namespace is passed explicitly because the caller — a CLI reading
    /// `--transport`, or a bench harness pinned to one side — decides which route family it is
    /// talking to; it overrides the config's default transport.
    pub fn from_env(namespace: Namespace) -> Result<Self> {
        let cfg =
            personas_config::Config::load().map_err(|e| anyhow::anyhow!("bad config: {e}"))?;
        cfg.validate().map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(Self::from_config(&cfg, namespace))
    }

    /// Build a client for `namespace` from an already-loaded [`personas_config::Config`]. The
    /// state dir is the explicit `PERSONAS_DATA_DIR`/profile override, or this namespace's
    /// pre-merge default (`client` / `slack-client`).
    pub fn from_config(cfg: &personas_config::Config, namespace: Namespace) -> Self {
        let data_dir = cfg
            .client
            .data_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(namespace.default_data_dir()));
        Self::new(namespace, cfg.client.api.clone(), data_dir)
    }

    /// Resolve a relative route (`"api/epoch"`) against the configured server.
    pub fn url(&self, route: &str) -> Result<Url> {
        self.api_base
            .join(route)
            .with_context(|| format!("route {route} is not a valid URL under {}", self.api_base))
    }

    /// The serialized zk-callbacks `User` object — the client's entire secret state.
    pub fn user_file(&self) -> PathBuf {
        self.data_dir.join("user.bin")
    }

    /// Append-only log of generated pseudonyms; a pseudonym's 1-based line number is
    /// the index the CLI's `--pseudo-idx` refers to.
    pub fn pseudo_log(&self) -> PathBuf {
        self.data_dir.join("pseudo_log.jsonl")
    }

    /// Thread contexts mirrored from the server, keyed by thread id.
    pub fn contexts(&self) -> PathBuf {
        self.data_dir.join("contexts.jsonl")
    }

    /// The three badge slots and the pseudonym each is claimed under.
    pub fn badge_log(&self) -> PathBuf {
        self.data_dir.join("badges.jsonl")
    }

    /// Rendered badge images (`render` feature).
    pub fn badge_dir(&self) -> PathBuf {
        self.data_dir.join("badges")
    }
}

/// `Url::join` resolves relative to the base's *directory*, so a base without a
/// trailing slash silently drops its last path segment: `join("api/x")` against
/// `http://host/personas` yields `http://host/api/x`. Normalizing here makes
/// sub-path deployments work; for the default root base it is a no-op.
fn with_trailing_slash(mut url: Url) -> Url {
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    url
}
