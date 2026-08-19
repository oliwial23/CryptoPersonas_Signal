//! The Cryptographic Personas client: local user state plus every proving flow a
//! member can run against the bulletin.
//!
//! One [`PersonaClient`] serves both transports. The Signal and Slack clients used to
//! be near-identical copies of this code — the only real differences were a state
//! directory and two route prefixes, both of which now live in [`ClientConfig`].
//!
//! - [`state`] — the `User` object on disk, pseudonyms, thread contexts
//! - [`params`] — proving keys, fetched from the server
//! - [`flows`] — the proving flows (post, scan, fold, vote, authorship, badge)
//! - [`badges`] — the three badge slots and their claimed pseudonyms

pub mod badges;
pub mod config;
pub mod flows;
pub mod params;
pub mod privpass;
#[cfg(feature = "render")]
pub mod render;
pub mod state;

pub use config::{ClientConfig, Namespace};
pub use personas_bulletin::BulNet;

// Re-exported so a binary that drives this client does not have to depend on the core
// crate just to name an `F` or derive a petname.
pub use personas_core;

use anyhow::Result;

/// A member's client: their configuration and their view of the bulletin.
///
/// Cheap to clone (the state itself lives on disk, and `BulNet` is a connection pool),
/// so flows can be moved into `spawn_blocking` without ceremony.
#[derive(Clone, Debug)]
pub struct PersonaClient {
    pub cfg: ClientConfig,
    pub bul: BulNet,
}

impl PersonaClient {
    pub fn new(cfg: ClientConfig) -> Self {
        let bul = BulNet::new(cfg.api_base.clone());
        Self { cfg, bul }
    }

    /// Build a client for `namespace` from the environment. See [`ClientConfig::from_env`].
    pub fn from_env(namespace: Namespace) -> Result<Self> {
        Ok(Self::new(ClientConfig::from_env(namespace)?))
    }
}
