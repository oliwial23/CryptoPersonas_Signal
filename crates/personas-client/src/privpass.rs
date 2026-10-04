//! Privacy Pass: request one anonymous ticket and redeem it, unlinkably, for a
//! specific action — a badge, or one pseudonymous post. See
//! `personas_core::privpass` and `docs/FINDINGS.md` O7.
//!
//! Deliberately not a free-form argument the caller can pick: each action here is
//! narrow and specific (matching how `ban`/`reputation`/`approve_badge` are separate
//! routes elsewhere in this service), so redeeming a ticket can't be used to
//! self-grant something arbitrary. See `personas_core::privpass`'s module docs for
//! why a badge redemption still skips `badge_pred`'s eligibility proof — an accepted
//! simplification, not an oversight.
//!
//! Requesting and redeeming are separate steps, in separate process invocations if
//! you like: `priv-pass-request` stashes a validated ticket to
//! `privpass_stash.bin` (see `personas_core::privpass::{load_stash, save_stash}`),
//! and each redeem command pulls the next unredeemed ticket back out of that stash.
//! The anonymity property this buys — a redemption cannot be linked to the request
//! that produced it, because it goes through real blind issuance — holds regardless
//! of how much time passes between the two calls.

use anyhow::{anyhow, Context, Result};
use personas_core::privpass::{
    self, decode_validated_tickets, encode_badge_redemption, encode_post_redemption,
    encode_redemption, encode_ticket_request, BadgeRedemption, PostRedemption, PrivPassUser,
};

use crate::PersonaClient;

impl PersonaClient {
    /// Request one anonymous ticket, unblind and verify the server's response, and
    /// stash it on disk ready to redeem — now or in a later invocation.
    pub fn privpass_request(&self) -> Result<()> {
        let mut batch_user = privpass::load_stash(&self.cfg.privpass_stash(), self.load_user()?)
            .map_err(|e| anyhow!("failed to load the ticket stash: {e}"))?;
        self.request_and_validate(&mut batch_user)?;
        privpass::save_stash(&self.cfg.privpass_stash(), &batch_user)
            .map_err(|e| anyhow!("failed to save the ticket stash: {e}"))?;
        Ok(())
    }

    /// How many validated, unredeemed tickets are currently stashed.
    pub fn privpass_stashed_tickets(&self) -> Result<usize> {
        let batch_user = privpass::load_stash(&self.cfg.privpass_stash(), self.load_user()?)
            .map_err(|e| anyhow!("failed to load the ticket stash: {e}"))?;
        Ok(batch_user.validated_batched_callbacks().len() - batch_user.valid_pointer())
    }

    /// Load the stash and check a ticket is actually available, rather than letting
    /// `use_validated_ticket` panic on an out-of-range index.
    fn take_stashed_ticket(&self) -> Result<PrivPassUser> {
        let batch_user = privpass::load_stash(&self.cfg.privpass_stash(), self.load_user()?)
            .map_err(|e| anyhow!("failed to load the ticket stash: {e}"))?;
        if batch_user.valid_pointer() >= batch_user.validated_batched_callbacks().len() {
            return Err(anyhow!(
                "no Privacy Pass ticket available to redeem — run `priv-pass-request` first"
            ));
        }
        Ok(batch_user)
    }

    /// Request one anonymous ticket, unblind and verify the server's response, and
    /// store it on `batch_user` ready to redeem. Shared by both redemption flows
    /// below — everything up to the point of deciding what to redeem for is
    /// identical.
    fn request_and_validate(&self, batch_user: &mut PrivPassUser) -> Result<()> {
        let standard_pk = self.standard_pk();
        let batch_pk = self.privpass_batch_pk();
        let mut rng = rand::rngs::OsRng;

        let request =
            privpass::request_ticket(batch_user, &mut rng, &self.bul, &standard_pk, &batch_pk)
                .map_err(|e| anyhow!("failed to build the ticket request: {e}"))?;

        let body = encode_ticket_request(&request)
            .map_err(|e| anyhow!("failed to encode the ticket request: {e}"))?;
        let resp = self
            .bul
            .client
            .post(self.cfg.url("api/privpass/issue")?)
            .body(body)
            .send()
            .context("failed to submit the ticket request")?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "server rejected the ticket request ({}): {}",
                resp.status(),
                resp.text().unwrap_or_default()
            ));
        }
        let validated = decode_validated_tickets(&resp.bytes()?)
            .map_err(|e| anyhow!("server returned an undecodable ticket: {e}"))?;

        let issuer_pubkey = self.privpass_issuer_pubkey();
        batch_user
            .store_validated_tickets::<personas_core::H, personas_core::Args, personas_core::Cr, { privpass::TICKET_BATCH_SIZE }>(
                issuer_pubkey,
                validated,
            )
            .map_err(|e| anyhow!("the server's blind-issuance proof did not verify: {e}"))?;

        // The user object didn't change (the standard method's own predicate is
        // identity-preserving here), but saving keeps this consistent with every
        // other flow's "always persist after a successful proof" discipline.
        self.save_user(&batch_user.user)?;
        Ok(())
    }

    /// Redeem a previously-requested, stashed ticket for `index`'s badge (`1`
    /// Faculty, `2` Student, `3` Industry) — see the module docs for why this skips
    /// the usual eligibility proof.
    pub fn privpass_redeem_badge(&self, index: u32) -> Result<()> {
        let mut batch_user = self.take_stashed_ticket()?;

        let redemption = batch_user
            .use_validated_ticket::<personas_core::H, personas_core::Args, personas_core::Cr>(&[]);
        let body = encode_badge_redemption(&BadgeRedemption { redemption, index })
            .map_err(|e| anyhow!("failed to encode the badge redemption: {e}"))?;

        let resp = self
            .bul
            .client
            .post(self.cfg.url("api/privpass/redeem/badge")?)
            .body(body)
            .send()
            .context("failed to submit the badge redemption")?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "server rejected the badge redemption ({}): {}",
                resp.status(),
                resp.text().unwrap_or_default()
            ));
        }
        privpass::save_stash(&self.cfg.privpass_stash(), &batch_user)
            .map_err(|e| anyhow!("failed to save the ticket stash: {e}"))?;
        Ok(())
    }

    /// Redeem a previously-requested, stashed ticket to post `message` into
    /// `channel`, under no persona at all.
    pub fn privpass_redeem_post(
        &self,
        message: String,
        channel: String,
        reply_to: Option<u64>,
    ) -> Result<()> {
        self.redeem_post(message, channel, reply_to, false)
    }

    /// Redeem a previously-requested, stashed ticket to post `message` into
    /// `channel` under a fresh, ticket-derived pseudonym — see
    /// `personas_core::privpass::ticket_pseudonym` for why it isn't one of the
    /// member's own personas.
    pub fn privpass_redeem_pseudo_post(
        &self,
        message: String,
        channel: String,
        reply_to: Option<u64>,
    ) -> Result<()> {
        self.redeem_post(message, channel, reply_to, true)
    }

    fn redeem_post(
        &self,
        message: String,
        channel: String,
        reply_to: Option<u64>,
        pseudonymous: bool,
    ) -> Result<()> {
        let mut batch_user = self.take_stashed_ticket()?;

        let redemption = batch_user
            .use_validated_ticket::<personas_core::H, personas_core::Args, personas_core::Cr>(&[]);
        let body = encode_post_redemption(&PostRedemption {
            redemption,
            message,
            channel,
            reply_to,
        })
        .map_err(|e| anyhow!("failed to encode the post redemption: {e}"))?;

        let route = match (self.cfg.namespace, pseudonymous) {
            (crate::config::Namespace::Signal, false) => "api/privpass/redeem/post",
            (crate::config::Namespace::Signal, true) => "api/privpass/redeem/pseudo_post",
            (crate::config::Namespace::Slack, false) => "api/slack/privpass/redeem/post",
            (crate::config::Namespace::Slack, true) => "api/slack/privpass/redeem/pseudo_post",
        };
        let resp = self
            .bul
            .client
            .post(self.cfg.url(route)?)
            .body(body)
            .send()
            .context("failed to submit the post redemption")?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "server rejected the post redemption ({}): {}",
                resp.status(),
                resp.text().unwrap_or_default()
            ));
        }
        privpass::save_stash(&self.cfg.privpass_stash(), &batch_user)
            .map_err(|e| anyhow!("failed to save the ticket stash: {e}"))?;
        Ok(())
    }

    /// Redeem a previously-requested, stashed ticket for a fixed +1 reputation
    /// bump — see the module docs for why this is a fixed amount, not a
    /// caller-chosen one.
    pub fn privpass_redeem_reputation(&self) -> Result<()> {
        let mut batch_user = self.take_stashed_ticket()?;

        let redemption = batch_user
            .use_validated_ticket::<personas_core::H, personas_core::Args, personas_core::Cr>(&[]);
        let body = encode_redemption(&redemption)
            .map_err(|e| anyhow!("failed to encode the reputation redemption: {e}"))?;

        let resp = self
            .bul
            .client
            .post(self.cfg.url("api/privpass/redeem/reputation")?)
            .body(body)
            .send()
            .context("failed to submit the reputation redemption")?;
        if !resp.status().is_success() {
            return Err(anyhow!(
                "server rejected the reputation redemption ({}): {}",
                resp.status(),
                resp.text().unwrap_or_default()
            ));
        }
        privpass::save_stash(&self.cfg.privpass_stash(), &batch_user)
            .map_err(|e| anyhow!("failed to save the ticket stash: {e}"))?;
        Ok(())
    }
}
