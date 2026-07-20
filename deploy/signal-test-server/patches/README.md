# test-server patches

`boot.sh` applies every `*.patch` here to `$SIGNAL_SERVER_DIR` before building
(idempotently — it skips a patch that is already applied). These are modifications to
**our isolated single-tenant test-server only**; none of them are safe for a real
Signal deployment.

## 0001 — allow the authenticated websocket to upgrade during registration

`WebSocketAccountAuthenticator.authenticate` stock-throws `InvalidCredentialsException`
(→ HTTP 403) when the basic-auth credentials do not resolve to an existing account. That
is fatal during **initial registration**: presage opens an *authenticated*
`/v1/websocket/` with the provisional `(e164, registration-password)` **before** the
account exists (`submit_verification_code` + `POST /v1/registration` ride that socket), so
the lookup is empty and the upgrade is refused.

The patch returns the authenticator's `Optional` directly (empty → **unauthenticated**
upgrade) instead of throwing. The upgrade's `Authorization` header is still forwarded onto
the `POST /v1/registration` request frame (`WebSocketResourceProvider.getCombinedHeaders`
merges upgrade + frame headers; `Authorization` is not in
`EXCLUDED_UPGRADE_REQUEST_HEADERS`), so `RegistrationController` reads the basic-auth and
creates the account. After registration presage reconnects with now-valid credentials and
authenticates normally.

Without this the e2 A1 account-gated send/receive wiring cannot register an account
against the test-server. See `docs/SERVERLESS_SIGNAL_DESIGN.md` §8 and the
`signal-server-selfhost-route` memory.
