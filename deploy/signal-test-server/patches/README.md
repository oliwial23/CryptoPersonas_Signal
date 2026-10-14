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

## 0002 — widen the `asnTable` S3 poller's refresh interval

`test.yml` points `asnTable` at a placeholder bucket (`a-bucket.s3.a-region.amazonaws.com`)
that nothing serves, with `refreshInterval: PT10S`. `S3ObjectMonitor.start()` does one
blocking fetch at boot (the "expected noise" `UnknownHostException`/`S3Exception` documented
in `docs/RUNNING_E2_LOCALLY.md`) and then reschedules itself every `refreshInterval`, forever,
for the life of the process. Widening it to `PT24H` cuts that down to the one boot-time fetch,
which is a legitimate reduction in background noise and pointless real-AWS traffic on its own
merits.

**This does not fix `b2_shared_identity`.** It was written on the theory that `asnTable`'s
recurring `S3Exception` was intermittently corrupting an unrelated live request via a
Jersey/Dropwizard async-logging scoping bug. That theory was wrong — disproved empirically
(the failure persisted 4/4 runs after this patch was applied and the server rebuilt/rebooted)
and then superseded by finding the actual cause: see `docs/FINDINGS.md` **O13**, a
deterministic (not racy) dependency of `PUT /v2/keys` on a *different*, unconfigured S3
client (`PagedSingleUseKEMPreKeyStore`). Left in only because it's a harmless, independently
worth-having noise reduction — not because it addresses O13. The real fix for O13 is 0003.

## 0003 — point `pagedSingleUseKEMPreKeyStore` at a local S3 mock

The actual fix for `docs/FINDINGS.md` **O13**. `KeysController.setKeys` (`PUT /v2/keys`) stores
PQ (Kyber) one-time prekeys via `PagedSingleUseKEMPreKeyStore`, which — unlike every other
datastore in the test harness — is backed by a real `S3AsyncClient` with no local substitute
configured. Every account's `receive_messages()` call kicks off a background prekey refresh
through this path; against real AWS with the test-server's placeholder credentials it always
403s, surfaced as an HTTP 500. Run `../minio.sh up` before booting the server if this patch is
applied (`endpointOverride` points at it and the boot fails fast otherwise — connection refused,
not a silent no-op).

Three changes, all required together:
- `test.yml`: adds `endpointOverride: http://127.0.0.1:9110` (MinIO). Also lowercases the bucket
  name (`preKeyBucket` → `prekey-bucket`) — the original violates S3's bucket-naming rules (no
  uppercase); real AWS would have rejected it too with `InvalidBucketName`, but the placeholder
  credentials always failed auth first, so this was never reached upstream either.
- `WhisperServerService.java`: adds `S3Configuration.builder().pathStyleAccessEnabled(true)` to
  this store's `S3AsyncClient` builder. Without it, the client defaults to virtual-hosted-style
  addressing (`bucket.endpoint`), which doesn't resolve against a plain `127.0.0.1` endpoint. No
  effect when `endpointOverride` is unset (real AWS accepts path-style too), so this is safe
  regardless of whether MinIO is running.
- `minio.sh` (sibling script, same conventions as `tls-proxy.sh`): starts MinIO on
  `127.0.0.1:9110` credentialed with the exact static `accessKey`/`secretAccess` pair
  `test-secrets-bundle.yml` already supplies everywhere, and creates the bucket. It uses
  `bitnamilegacy/minio` with `MINIO_DEFAULT_BUCKETS`: MinIO stopped publishing `minio/minio` and
  `minio/mc` in late 2025, so a machine without a cached copy can no longer pull them. Port 9110,
  not 9100: 9100 is Prometheus node_exporter's port, which UMIACS VMs already occupy.

Verified: 4/4 post-fix `b2_shared_identity` runs show `Uploading pre-keys` completing for both
ACI and PNI identities with no error (previously: HTTP 500, 4/4). `a1_smoke`/
`e2c_key_distribution` still pass — no regression. `b2_shared_identity` itself still fails, for a
different, previously-masked reason — see `docs/FINDINGS.md` **O14**.

## 0004 — Redis cluster without Compose links (Podman)

`RedisClusterExtension` (which `LocalFaultTolerantRedisClusterFactory` uses for `cacheCluster`
and friends) started the three-node cluster with Testcontainers' `ComposeContainer` and
`withExposedService(...)`. That reaches each service through an `alpine/socat` "ambassador"
container wired up with legacy Docker `--link`s, and Podman rejects links outright:

```
Status 400: {"cause":"link is not supported","message":"bad parameter: link is not supported"}
```

so the server dies at config parsing (`Failed to parse configuration at: cacheCluster`). The
patch starts the same three `bitnamilegacy/redis-cluster` nodes as plain `GenericContainer`s on
one `Network` with aliases `redis-0..2` (the image resolves `REDIS_NODES` by those names),
started **together** with `Startables.deepStart` — each node blocks until it can resolve every
name in `REDIS_NODES`, so a sequential start deadlocks on the first — and keeps the
internal-IP → mapped-port `SocketAddressResolver` unchanged. Verified under Docker with
`CardinalityEstimatorTest` (2/2), so it is safe on the laptop too.
