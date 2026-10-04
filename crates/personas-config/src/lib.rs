//! Layered configuration for the personas binaries.
//!
//! One [`Config`] describes a whole deployment: the server's bind address and data dir, the
//! client's server URL and state dir, which messenger backs each route family, the run
//! [`Mode`], and the log level. It is assembled from four layers, later ones winning:
//!
//! 1. built-in [`Config::default`] — the values the old code hardcoded at the read site;
//! 2. a profile file `deploy/profiles/<name>.toml`, selected by `PERSONAS_PROFILE` (or a full
//!    path in `PERSONAS_CONFIG`);
//! 3. the legacy env vars (`PERSONAS_BIND`, `PERSONAS_API`, `PERSONAS_DATA_DIR`,
//!    `PERSONAS_TRANSPORT`, `PERSONAS_SIGNAL_DAEMON`, `SIGNAL_BOT_NUMBER`, `SLACK_BOT_TOKEN`,
//!    `SLACK_APP_TOKEN`, `SLACK_SERVER_LOG`) — kept working verbatim so nothing that set them
//!    before breaks;
//! 4. CLI overrides, which the caller applies to the returned struct (its fields are public).
//!
//! Because every default equals the value it replaced, a binary that loads this with no
//! profile and no env set behaves exactly as it did before a5.

use std::net::SocketAddr;
use std::path::PathBuf;

use figment::{
    Figment,
    providers::{Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};
use url::Url;

/// The default server bind address; the value the old server hardcoded.
pub const DEFAULT_BIND: &str = "127.0.0.1:3000";
/// The default server URL the clients used to hardcode at ~47 call sites.
pub const DEFAULT_API: &str = "http://127.0.0.1:3000";
/// The default server data directory.
pub const DEFAULT_SERVER_DATA_DIR: &str = "server/data";
/// The default `signal-cli` JSON-RPC daemon address.
pub const DEFAULT_SIGNAL_DAEMON: &str = "127.0.0.1:7583";
/// The default log level.
pub const DEFAULT_LOG_LEVEL: &str = "info";

/// Whether the deployment runs as-a-service (the only mode implemented today) or serverless.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// A trusted relay server verifies proofs and posts under a phantom account.
    #[default]
    Service,
    /// No server: every member verifies locally over the chat log. Workstream (d); not yet
    /// implemented, so [`Config::validate`] rejects it.
    Serverless,
}

/// Which route family a client talks to, and therefore which messenger relays its posts. The
/// server exposes both families at once (`/api/…` and `/api/slack/…`), so this only picks a
/// side; it is not a real-vs-mock choice (that is [`TransportConfig::force_mock`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// The `/api/…` routes, relayed over Signal in a real deployment.
    #[default]
    Signal,
    /// The `/api/slack/…` routes, relayed over Slack.
    Slack,
}

impl Transport {
    /// The state directory each client used before the merge. Kept as the default so existing
    /// `user.bin` files and the `bench/*.py` harness still resolve.
    pub fn default_data_dir(self) -> &'static str {
        match self {
            Transport::Signal => "client",
            Transport::Slack => "slack-client",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// The address the server binds. `PERSONAS_BIND`.
    pub bind: SocketAddr,
    /// Where the store seed, params cache, and ledger live. `PERSONAS_DATA_DIR`.
    pub data_dir: PathBuf,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: DEFAULT_BIND.parse().expect("the default bind is valid"),
            data_dir: PathBuf::from(DEFAULT_SERVER_DATA_DIR),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientConfig {
    /// The server the client posts to. `PERSONAS_API`.
    pub api: Url,
    /// The client's state dir. `None` means "use the per-transport default"
    /// (`client`/`slack-client`). `PERSONAS_DATA_DIR`.
    pub data_dir: Option<PathBuf>,
    /// Which route family (and messenger) to target. The a5b `personas` CLI sets this from
    /// `--transport`.
    pub transport: Transport,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            api: Url::parse(DEFAULT_API).expect("the default api url is valid"),
            data_dir: None,
            transport: Transport::default(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SignalTransportConfig {
    /// The bot's Signal number. Absent → the signal routes relay to the mock.
    /// `SIGNAL_BOT_NUMBER`.
    pub bot_number: Option<String>,
    /// The `signal-cli` JSON-RPC daemon address. `PERSONAS_SIGNAL_DAEMON`.
    pub daemon: Option<SocketAddr>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SlackTransportConfig {
    /// The Slack bot token. Absent (with app_token) → the slack routes relay to the mock.
    /// `SLACK_BOT_TOKEN`.
    pub bot_token: Option<String>,
    /// The Slack app-level (socket-mode) token. `SLACK_APP_TOKEN`.
    pub app_token: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TransportConfig {
    /// Force every route family to the in-process mock even when credentials are present, so a
    /// test or demo cannot talk to a real messenger. `PERSONAS_TRANSPORT=mock`.
    pub force_mock: bool,
    pub signal: SignalTransportConfig,
    pub slack: SlackTransportConfig,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    /// The tracing level for the personas crates. `SLACK_SERVER_LOG`.
    pub level: String,
}

/// Which messenger a route family is wired to, resolved from [`TransportConfig`] plus the
/// force-mock override. The server matches on this to build the actual transport.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignalBackend {
    Mock,
    SignalCli { account: String, daemon: SocketAddr },
}

/// See [`SignalBackend`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlackBackend {
    Mock,
    Slack {
        bot_token: String,
        app_token: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub mode: Mode,
    pub log: LogConfig,
    pub server: ServerConfig,
    pub client: ClientConfig,
    pub transport: TransportConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::default(),
            log: LogConfig {
                level: DEFAULT_LOG_LEVEL.to_string(),
            },
            server: ServerConfig::default(),
            client: ClientConfig::default(),
            transport: TransportConfig::default(),
        }
    }
}

/// Errors from assembling a [`Config`].
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("profile {0:?} not found at {1}")]
    ProfileNotFound(String, PathBuf),
    #[error("could not read config: {0}")]
    Figment(#[from] Box<figment::Error>),
    #[error("{0}")]
    Invalid(String),
    #[error("{name} is not valid: {value:?} ({source})")]
    BadEnv {
        name: &'static str,
        value: String,
        #[source]
        source: anyhow::Error,
    },
}

impl Config {
    /// Assemble the config from defaults, an optional profile, and the legacy env vars.
    ///
    /// The profile is chosen by `PERSONAS_CONFIG` (a full path) or `PERSONAS_PROFILE` (a name
    /// resolved to `deploy/profiles/<name>.toml`). A named profile that does not exist is an
    /// error; the absence of any profile selection is not.
    pub fn load() -> Result<Self, ConfigError> {
        let profile = std::env::var("PERSONAS_CONFIG").ok().map(PathBuf::from);
        let profile = match profile {
            Some(p) => Some(p),
            None => match std::env::var("PERSONAS_PROFILE").ok() {
                Some(name) => {
                    let path = profile_path(&name);
                    if !path.exists() {
                        return Err(ConfigError::ProfileNotFound(name, path));
                    }
                    Some(path)
                }
                None => None,
            },
        };
        Self::load_from(profile.as_deref())
    }

    /// [`load`](Self::load) with the profile path already resolved (or `None`). Also the seam
    /// tests use to avoid touching the process environment for the profile.
    pub fn load_from(profile: Option<&std::path::Path>) -> Result<Self, ConfigError> {
        let mut figment = Figment::from(Serialized::defaults(Config::default()));
        if let Some(path) = profile {
            figment = figment.merge(Toml::file(path));
        }
        let mut cfg: Config = figment.extract().map_err(Box::new)?;
        cfg.apply_env_overrides()?;
        Ok(cfg)
    }

    /// Overlay the legacy env vars. Called last, so `PERSONAS_*` wins over a profile — the same
    /// precedence the ad-hoc `env::var(...).unwrap_or(default)` reads had.
    fn apply_env_overrides(&mut self) -> Result<(), ConfigError> {
        if let Some(v) = env_opt("PERSONAS_BIND") {
            self.server.bind = parse_env("PERSONAS_BIND", &v)?;
        }
        if let Some(v) = env_opt("PERSONAS_API") {
            self.client.api = parse_env("PERSONAS_API", &v)?;
        }
        if let Some(v) = env_opt("PERSONAS_DATA_DIR") {
            // One process is either the server or a client, so the legacy single var maps to
            // both slices; each binary reads only the one it owns.
            self.server.data_dir = PathBuf::from(&v);
            self.client.data_dir = Some(PathBuf::from(&v));
        }
        if env_opt("PERSONAS_TRANSPORT").as_deref() == Some("mock") {
            self.transport.force_mock = true;
        }
        if let Some(v) = env_opt("PERSONAS_SIGNAL_DAEMON") {
            self.transport.signal.daemon = Some(parse_env("PERSONAS_SIGNAL_DAEMON", &v)?);
        }
        if let Some(v) = env_opt("SIGNAL_BOT_NUMBER") {
            self.transport.signal.bot_number = Some(v);
        }
        if let Some(v) = env_opt("SLACK_BOT_TOKEN") {
            self.transport.slack.bot_token = Some(v);
        }
        if let Some(v) = env_opt("SLACK_APP_TOKEN") {
            self.transport.slack.app_token = Some(v);
        }
        if let Some(v) = env_opt("SLACK_SERVER_LOG") {
            self.log.level = v;
        }
        Ok(())
    }

    /// Reject configurations the code cannot honor yet. Serverless mode (workstream d) has no
    /// implementation, so it is refused rather than silently downgraded.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.mode == Mode::Serverless {
            return Err(ConfigError::Invalid(
                "mode=serverless is not implemented yet (workstream d); use mode=service".into(),
            ));
        }
        Ok(())
    }

    /// The client's resolved state directory: the explicit override, or the per-transport
    /// default (`client` / `slack-client`).
    pub fn client_data_dir(&self) -> PathBuf {
        self.client
            .data_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(self.client.transport.default_data_dir()))
    }

    /// Which messenger the `/api/…` (signal) routes relay through. Falls back to the mock when
    /// forced, or when no bot number is set — exactly the old startup behavior.
    pub fn signal_backend(&self) -> SignalBackend {
        if self.transport.force_mock {
            return SignalBackend::Mock;
        }
        match &self.transport.signal.bot_number {
            Some(account) => {
                SignalBackend::SignalCli {
                    account: account.clone(),
                    daemon: self.transport.signal.daemon.unwrap_or_else(|| {
                        DEFAULT_SIGNAL_DAEMON.parse().expect("default is valid")
                    }),
                }
            }
            None => SignalBackend::Mock,
        }
    }

    /// Which messenger the `/api/slack/…` routes relay through. Real Slack needs both tokens;
    /// anything short of that is the mock.
    pub fn slack_backend(&self) -> SlackBackend {
        if self.transport.force_mock {
            return SlackBackend::Mock;
        }
        match (
            &self.transport.slack.bot_token,
            &self.transport.slack.app_token,
        ) {
            (Some(bot_token), Some(app_token)) => SlackBackend::Slack {
                bot_token: bot_token.clone(),
                app_token: app_token.clone(),
            },
            _ => SlackBackend::Mock,
        }
    }
}

/// `deploy/profiles/<name>.toml`, relative to the working directory. Public so a CLI resolving
/// a `--profile <name>` override lands on exactly the file [`Config::load`] would.
pub fn profile_path(name: &str) -> PathBuf {
    PathBuf::from("deploy/profiles").join(format!("{name}.toml"))
}

/// A non-empty env var, or `None`. Empty means "unset" so an exported-but-blank var does not
/// wipe a default with an unparseable value.
fn env_opt(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

fn parse_env<T>(name: &'static str, value: &str) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    value.parse().map_err(|e: T::Err| ConfigError::BadEnv {
        name,
        value: value.to_string(),
        source: e.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defaults must equal the values the pre-a5 code hardcoded, or a checkout with no
    /// profile and no env silently changes behavior.
    #[test]
    fn defaults_match_the_old_hardcoded_values() {
        let cfg = Config::default();
        assert_eq!(cfg.mode, Mode::Service);
        assert_eq!(cfg.server.bind.to_string(), "127.0.0.1:3000");
        assert_eq!(cfg.server.data_dir, PathBuf::from("server/data"));
        assert_eq!(cfg.client.api.as_str(), "http://127.0.0.1:3000/");
        assert_eq!(cfg.client.transport, Transport::Signal);
        assert_eq!(cfg.log.level, "info");
        assert!(!cfg.transport.force_mock);
        assert_eq!(cfg.signal_backend(), SignalBackend::Mock);
        assert_eq!(cfg.slack_backend(), SlackBackend::Mock);
    }

    #[test]
    fn client_data_dir_follows_the_transport() {
        let mut cfg = Config::default();
        assert_eq!(cfg.client_data_dir(), PathBuf::from("client"));
        cfg.client.transport = Transport::Slack;
        assert_eq!(cfg.client_data_dir(), PathBuf::from("slack-client"));
        cfg.client.data_dir = Some(PathBuf::from("/tmp/custom"));
        assert_eq!(cfg.client_data_dir(), PathBuf::from("/tmp/custom"));
    }

    #[test]
    fn credentials_select_a_real_backend_unless_forced_mock() {
        let mut cfg = Config::default();
        cfg.transport.signal.bot_number = Some("+15550000000".into());
        match cfg.signal_backend() {
            SignalBackend::SignalCli { account, daemon } => {
                assert_eq!(account, "+15550000000");
                assert_eq!(daemon.to_string(), "127.0.0.1:7583");
            }
            SignalBackend::Mock => panic!("expected the real signal-cli backend"),
        }

        cfg.transport.force_mock = true;
        assert_eq!(cfg.signal_backend(), SignalBackend::Mock);
    }

    #[test]
    fn serverless_mode_is_rejected() {
        let mut cfg = Config::default();
        cfg.mode = Mode::Serverless;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn a_profile_overrides_defaults_and_a_full_config_round_trips() {
        let dir = std::env::temp_dir().join("personas-config-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("prof.toml");
        std::fs::write(
            &path,
            r#"
mode = "service"
[server]
bind = "0.0.0.0:8080"
[client]
api = "http://example.test:9000"
transport = "slack"
[transport]
force_mock = true
"#,
        )
        .unwrap();

        let cfg = Config::load_from(Some(&path)).unwrap();
        assert_eq!(cfg.server.bind.to_string(), "0.0.0.0:8080");
        assert_eq!(cfg.client.api.as_str(), "http://example.test:9000/");
        assert_eq!(cfg.client.transport, Transport::Slack);
        assert!(cfg.transport.force_mock);
        // A field the profile omits keeps its default.
        assert_eq!(cfg.server.data_dir, PathBuf::from("server/data"));
    }
}
