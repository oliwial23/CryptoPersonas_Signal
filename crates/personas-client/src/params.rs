//! Proving keys, fetched from the server.
//!
//! The server generates every Groth16 key and the Nova parameters once at startup (see
//! `personas_core::params`) and serves them; clients hold none of this on disk. The keys
//! are large — tens of MB for the folding parameters — so a flow fetches only the key it
//! needs, at the moment it needs it.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use personas_core::moderation::AdminPk;
use personas_core::schedule::{BanRef, RotationEntry, now_unix};
use personas_core::{Args, CStore, Cr, F, PK, circuits::NP};
use zk_callbacks::generic::bulletin::PublicCallbackBul;
use zk_callbacks::generic::object::Time;
use zk_callbacks::impls::centralized::crypto::FakeSigPubkey;

use crate::{PersonaClient, rotation};

/// Parameter bytes already fetched by this process, by URL. They are fixed for a server's
/// lifetime and a key is megabytes: fetching one for every proof goes unnoticed on
/// loopback but dominates over a real network.
static FETCHED: LazyLock<Mutex<HashMap<String, Arc<Vec<u8>>>>> = LazyLock::new(Default::default);
/// Servers whose scan cap has been checked against this build's.
static CAP_CHECKED: LazyLock<Mutex<std::collections::HashSet<String>>> =
    LazyLock::new(Default::default);

/// How long one parameter may take to download. A client's default 30 s covers the whole
/// request, body included, which the larger keys exceed on an ordinary connection.
const FETCH_TIMEOUT: Duration = Duration::from_secs(600);
const FETCH_ATTEMPTS: u32 = 5;

fn cause_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text = format!("{text}: {cause}");
        source = cause.source();
    }
    text
}

impl PersonaClient {
    /// Refuse to prove against a server whose scan cap differs from this build's: the cap
    /// is a circuit constant, so the proofs would not verify and the failure would look
    /// like a bad proof. Checked once per server per process. A server too old to report
    /// its cap is not checked.
    fn check_scan_cap(&self) {
        let Ok(url) = self.cfg.url("api/scan_cap") else { return };
        if !CAP_CHECKED.lock().unwrap().insert(url.to_string()) {
            return;
        }
        let ours = personas_core::circuits::NUM_INTS_BEFORE_SCAN;
        let theirs = self
            .bul
            .client
            .get(url)
            .timeout(FETCH_TIMEOUT)
            .send()
            .ok()
            .filter(|r| r.status().is_success())
            .and_then(|r| r.text().ok())
            .and_then(|t| t.trim().parse::<usize>().ok());
        if let Some(theirs) = theirs
            && theirs != ours
        {
            panic!(
                "this client was built with scan cap {ours}, but the server uses {theirs}; \
                 rebuild the client with PERSONAS_K_MAX={}",
                (theirs - 1) * personas_core::circuits::EPOCH_W
            );
        }
    }

    /// GET `route` (once per process) and canonical-deserialize a parameter.
    ///
    /// Panics on failure: without the key there is no proof to produce, and every caller
    /// is a proving flow that cannot proceed. The message names the route so a missing
    /// server or a stale key set is obvious.
    fn fetch_param<T: CanonicalDeserialize>(&self, route: &str) -> T {
        let url = self
            .cfg
            .url(route)
            .unwrap_or_else(|e| panic!("bad parameter route: {e}"));

        self.check_scan_cap();
        let cached = FETCHED.lock().unwrap().get(url.as_str()).cloned();
        let bytes = cached.unwrap_or_else(|| {
            let bytes = Arc::new(self.download(&url, route));
            FETCHED
                .lock()
                .unwrap()
                .insert(url.to_string(), bytes.clone());
            bytes
        });

        T::deserialize_with_mode(bytes.as_slice(), Compress::No, Validate::No)
            .unwrap_or_else(|e| panic!("server returned an undecodable parameter for {route}: {e}"))
    }

    /// Download a parameter, retrying: a transfer of tens of MB through a load balancer can
    /// be cut off partway. Says why each attempt failed (reqwest's own message for a failed
    /// body is only "error decoding response body").
    fn download(&self, url: &url::Url, route: &str) -> Vec<u8> {
        let mut last = String::new();
        for attempt in 1..=FETCH_ATTEMPTS {
            let started = Instant::now();
            let result = self
                .bul
                .client
                .get(url.clone())
                .timeout(FETCH_TIMEOUT)
                .send()
                .and_then(reqwest::blocking::Response::error_for_status)
                .and_then(reqwest::blocking::Response::bytes);
            match result {
                Ok(bytes) => return bytes.to_vec(),
                Err(e) => {
                    last = cause_chain(&e.without_url());
                    eprintln!(
                        "fetching {route}: attempt {attempt} failed after {:.1}s: {last}",
                        started.elapsed().as_secs_f64()
                    );
                }
            }
        }
        panic!("could not fetch {route} from the server: {last}");
    }

    fn fetch_pk(&self, route: &str) -> PK {
        self.fetch_param(route)
    }

    /// Posting a message: the standard interaction (rate limit, not banned).
    pub fn standard_pk(&self) -> PK {
        self.fetch_pk("api/interaction/standard/proving_key")
    }

    /// Posting under a pseudonym.
    pub fn standard_pseudo_pk(&self) -> PK {
        self.fetch_pk("api/interaction/standard/pseudo/proving_key")
    }

    /// Posting under a rate-limited pseudonym.
    pub fn standard_pseudo_rate_pk(&self) -> PK {
        self.fetch_pk("api/interaction/standard/pseudor/proving_key")
    }

    /// Requesting a badge.
    pub fn badge_request_pk(&self) -> PK {
        self.fetch_pk("api/interaction/badge/request/proving_key")
    }

    /// Scanning a single callback.
    pub fn scan_pk(&self) -> PK {
        self.fetch_pk("api/interaction/scan/proving_key")
    }

    /// Nova prover/verifier parameters for a folded scan.
    pub fn fold_params(&self) -> NP {
        self.fetch_param("api/interaction/fold/proving_key")
    }

    /// The Groth16 key for the per-step circuit folded by Nova.
    pub fn fold_pk(&self) -> PK {
        self.fetch_pk("api/interaction/fold/pre_proving_key")
    }

    /// Proving a pseudonym (`pseudonym_pred`), for votes.
    pub fn pseudonym_pred_pk(&self) -> PK {
        self.fetch_pk("api/user/arbitrary_pred_proving_key")
    }

    /// A post that shows a badge (ShowBadge).
    pub fn show_badge_pk(&self) -> PK {
        self.fetch_pk("api/interaction/claim/show_badge/proving_key")
    }

    /// A post that merges a second persona (MergePersonas).
    pub fn merge_personas_pk(&self) -> PK {
        self.fetch_pk("api/interaction/claim/merge_personas/proving_key")
    }

    /// A post that proves reputation at least a threshold (RepAtLeast).
    pub fn rep_at_least_pk(&self) -> PK {
        self.fetch_pk("api/interaction/claim/rep_at_least/proving_key")
    }

    /// Privacy Pass: blinding a requested ticket (FINDINGS O7).
    pub fn privpass_batch_pk(&self) -> PK {
        self.fetch_pk("api/privpass/batch_proving_key")
    }

    /// Privacy Pass: the ticket interaction (one request, `TICKET_BATCH_SIZE` callbacks).
    pub fn privpass_interaction_pk(&self) -> PK {
        self.fetch_pk("api/privpass/interaction_proving_key")
    }

    /// Privacy Pass: the issuer's VOPRF public key, needed to unblind a validated batch.
    ///
    /// Fetched fresh every time, unlike the proving keys: the server rotates it at each
    /// epoch boundary and on each ban. A key different from the last one this client
    /// accepted is checked against the server's public rotation log first
    /// (`rotation::check_rotations`), and refused if the log does not explain it.
    pub fn privpass_issuer_pubkey(&self) -> anyhow::Result<ark_grumpkin::Projective> {
        use anyhow::Context;

        let route = "api/privpass/pubkey";
        let url = self.cfg.url(route)?;
        let bytes = self.download(&url, route);
        let served = hex::encode(&bytes);

        let path = self.cfg.privpass_issuer_key();
        let accepted = match std::fs::read_to_string(&path) {
            Ok(text) => Some(text.trim().to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e).with_context(|| format!("could not read {}", path.display())),
        };
        if accepted.as_deref() != Some(served.as_str()) {
            let log: Vec<RotationEntry> = self
                .bul
                .client
                .get(self.cfg.url("api/privpass/rotations")?)
                .timeout(FETCH_TIMEOUT)
                .send()
                .and_then(reqwest::blocking::Response::error_for_status)
                .context("failed to fetch the issuer key rotation log")?
                .json()
                .context("server returned a malformed key rotation log")?;
            let schedule = self.epoch_schedule()?;
            let admin_pk = self.admin_pk()?;
            let mut bulletin = None;
            rotation::check_rotations(
                accepted.as_deref(),
                &served,
                &log,
                &schedule,
                admin_pk.as_ref(),
                now_unix(),
                |ban, epoch| {
                    let bulletin = bulletin.get_or_insert_with(|| self.callback_bulletin());
                    Ok(is_ban_in(bulletin, ban, epoch))
                },
            )
            .context("refusing the server's ticket issuer key")?;
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&path, &served)
                .with_context(|| format!("could not write {}", path.display()))?;
        }

        ark_grumpkin::Projective::deserialize_with_mode(bytes.as_slice(), Compress::No, Validate::No)
            .with_context(|| format!("server returned an undecodable parameter for {route}"))
    }

    /// The group admin's public key, which every ban must be signed with.
    ///
    /// `PERSONAS_ADMIN_PK`, if set, is the key, configured out of band, and a server that
    /// publishes a different one is refused. Otherwise the key the server publishes
    /// (`/api/admin_key`) is pinned the first time this client sees one, and a server that
    /// later publishes a different key is refused. `None` if neither names a key.
    pub fn admin_pk(&self) -> anyhow::Result<Option<AdminPk>> {
        use anyhow::{Context, anyhow, bail};

        #[derive(serde::Deserialize)]
        struct AdminKeyResponse {
            admin_pk: Option<String>,
        }
        let served = self
            .bul
            .client
            .get(self.cfg.url("api/admin_key")?)
            .timeout(FETCH_TIMEOUT)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .context("failed to fetch the group admin key")?
            .json::<AdminKeyResponse>()
            .context("server returned a malformed admin key")?
            .admin_pk
            .map(|k| k.trim().to_lowercase());

        let configured = std::env::var("PERSONAS_ADMIN_PK")
            .ok()
            .map(|k| k.trim().to_lowercase())
            .filter(|k| !k.is_empty());
        let path = self.cfg.admin_key();
        let pinned = match std::fs::read_to_string(&path) {
            Ok(text) => Some(text.trim().to_lowercase()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e).with_context(|| format!("could not read {}", path.display())),
        };

        let trusted = configured.or(pinned.clone());
        let key = match (&trusted, &served) {
            (Some(t), Some(s)) if t != s => bail!(
                "the server's group admin key ({s}) is not the one this client trusts ({t}); \
                 refusing it. If the admin key really changed, remove {}",
                path.display()
            ),
            (Some(t), _) => t.clone(),
            (None, Some(s)) => s.clone(),
            (None, None) => return Ok(None),
        };
        if pinned.is_none() {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&path, &key)
                .with_context(|| format!("could not write {}", path.display()))?;
        }
        personas_core::moderation::parse_admin_pk(&key)
            .map(Some)
            .map_err(|e| anyhow!("{e}"))
    }

    /// The public callback bulletin: every callback invoked so far, with its (encrypted)
    /// argument and the epoch it was invoked in.
    fn callback_bulletin(&self) -> CallbackBulletin {
        let route = "api/callbacks/bulletin";
        let url = self
            .cfg
            .url(route)
            .unwrap_or_else(|e| panic!("bad parameter route: {e}"));
        let bytes = self.download(&url, route);
        CallbackBulletin::deserialize_with_mode(bytes.as_slice(), Compress::No, Validate::Yes)
            .unwrap_or_else(|e| panic!("server returned an undecodable parameter for {route}: {e}"))
    }
}

/// The callback bulletin, as served: `(ticket, argument, epoch, membership witness)`.
type CallbackBulletin = Vec<(
    FakeSigPubkey<F>,
    Args,
    Time<F>,
    <CStore as PublicCallbackBul<F, Args, Cr>>::MembershipWitness,
)>;

/// Whether `ban` names a call in `bulletin`: the entry it cites holds the ticket it names
/// and was invoked in `epoch`.
///
/// Not whether the call *was a ban*: the bulletin holds each call's argument encrypted to
/// the ticket's owner (`NoSigOTP`), so only the banned member can read it. What a client
/// can check is that the rotation is tied to a real, public call in that epoch, and (in
/// `check_rotations`) that no call is cited twice — so rotations are bounded by public
/// calls. See `NOTES-items-1-11.md`.
fn is_ban_in(bulletin: &CallbackBulletin, ban: &BanRef, epoch: u64) -> bool {
    let Some((ticket, _, time, _)) = usize::try_from(ban.index)
        .ok()
        .and_then(|i| bulletin.get(i))
    else {
        return false;
    };
    let mut bytes = Vec::new();
    if ticket.serialize_with_mode(&mut bytes, Compress::No).is_err() {
        return false;
    }
    hex::encode(bytes) == ban.ticket && *time == F::from(epoch)
}
