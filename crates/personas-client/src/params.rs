//! Proving keys, fetched from the server.
//!
//! The server generates every Groth16 key and the Nova parameters once at startup (see
//! `personas_core::params`) and serves them; clients hold none of this on disk. The keys
//! are large — tens of MB for the folding parameters — so a flow fetches only the key it
//! needs, at the moment it needs it.

use ark_serialize::{CanonicalDeserialize, Compress, Validate};
use personas_core::{circuits::NP, PK};

use crate::PersonaClient;

impl PersonaClient {
    /// GET `route` and canonical-deserialize a parameter.
    ///
    /// Panics on failure: without the key there is no proof to produce, and every caller
    /// is a proving flow that cannot proceed. The message names the route so a missing
    /// server or a stale key set is obvious.
    fn fetch_param<T: CanonicalDeserialize>(&self, route: &str) -> T {
        let url = self
            .cfg
            .url(route)
            .unwrap_or_else(|e| panic!("bad parameter route: {e}"));

        let bytes = self
            .bul
            .client
            .get(url)
            .send()
            .unwrap_or_else(|e| panic!("failed to fetch {route} from the server: {e}"))
            .bytes()
            .unwrap_or_else(|e| panic!("server returned no body for {route}: {e}"));

        T::deserialize_with_mode(&*bytes, Compress::No, Validate::No)
            .unwrap_or_else(|e| panic!("server returned an undecodable parameter for {route}: {e}"))
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

    /// Proving two pseudonyms share an author (`authorship_pred`).
    pub fn authorship_pred_pk(&self) -> PK {
        self.fetch_pk("api/user/arbitrary_pred_proving_key2")
    }

    /// Proving a badge is held under a pseudonym (`badge_pred`).
    pub fn badge_pred_pk(&self) -> PK {
        self.fetch_pk("api/user/arbitrary_pred_proving_key3")
    }
}
