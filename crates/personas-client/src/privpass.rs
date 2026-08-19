//! Privacy Pass: request one anonymous ticket and redeem it, unlinkably, for a
//! callback. See `personas_core::privpass` and `docs/FINDINGS.md` O7.
//!
//! `batch_zkc::BatchUser`'s own bookkeeping (which blinded ticket maps to which
//! locally-held callback) is `pub(crate)` to that crate — there is no supported way
//! to serialize it and reload it in a later process the way `PersonaClient` reloads
//! everything else from `user.bin` on every CLI invocation. So unlike every other
//! flow here, request and redemption happen inside one call, not across separate
//! invocations: a ticket is minted and redeemed in the same round trip. The
//! anonymity property this buys — a redemption cannot be linked to the request that
//! produced it, because it goes through real blind issuance — still holds; what's
//! lost is holding several unredeemed tickets in reserve across a gap in time.
//! Lifting that needs a small upstream change to `batch-zkc` (exposing enough of
//! `BatchUser` to serialize), not something achievable from this crate alone.

use anyhow::{anyhow, Context, Result};
use personas_core::privpass::{
    self, decode_validated_tickets, encode_redemption, encode_ticket_request, PrivPassUser,
};

use crate::PersonaClient;

impl PersonaClient {
    /// Request one anonymous ticket, unblind and verify the server's response, then
    /// immediately redeem it against `data` (the argument a later callback-style
    /// invocation would carry). Returns once the server has confirmed the
    /// redemption. See the module docs for why request and redeem aren't separate
    /// CLI-invocable steps yet.
    pub fn privpass_round_trip(&self, data: &[personas_core::F]) -> Result<()> {
        let user = self.load_user()?;
        let mut batch_user = PrivPassUser::create(user);

        let standard_pk = self.standard_pk();
        let batch_pk = self.privpass_batch_pk();
        let mut rng = rand::rngs::OsRng;

        let request = privpass::request_ticket(&mut batch_user, &mut rng, &self.bul, &standard_pk, &batch_pk)
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

        let redemption = batch_user
            .use_validated_ticket::<personas_core::H, personas_core::Args, personas_core::Cr>(data);

        let body = encode_redemption(&redemption)
            .map_err(|e| anyhow!("failed to encode the redemption: {e}"))?;
        let resp = self
            .bul
            .client
            .post(self.cfg.url("api/privpass/redeem")?)
            .body(body)
            .send()
            .context("failed to submit the redemption")?;

        if !resp.status().is_success() {
            return Err(anyhow!(
                "server rejected the redemption ({}): {}",
                resp.status(),
                resp.text().unwrap_or_default()
            ));
        }

        Ok(())
    }
}
