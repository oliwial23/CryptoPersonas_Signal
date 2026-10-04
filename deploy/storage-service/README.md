# Signal storage-service (GroupsV2 backend) for the personas test server

The chat [`signal-test-server`](../signal-test-server) is only the Signal-Server
chat service (accounts, messages, keys, profiles). **GroupsV2** — create/fetch/
modify a group (`/v1/groups`, `/v2/groups`) — lives in a **separate** Signal
application, [`storage-service`][ss], which the test-server profile never starts.
Desktop's `createGroup` targets `host: storageService` → those paths, so without
this it 404s and no group can be created.

The personas demo is fundamentally group messaging (the anonymity property only
matters among a group), so we stand up the real groups backend rather than fake a
client-side group. Everything is local and ephemeral, like the chat test server.

## How it plugs in

- Runs the storage-service on cleartext **:8090** (admin :8091), backed by a local
  **Cloud Bigtable emulator** on a free port — **pure Java/Maven, no gcloud, no
  Docker, no Python**. The emulator is the one bundled in the storage-service's own
  `google-cloud-bigtable-emulator` dependency (the same one its tests use).
- The chat server's TLS proxy ([`tls-proxy.sh`](../signal-test-server/tls-proxy.sh))
  now **path-routes** `/v1/groups*`, `/v2/groups*`, `/v1/storage*` from
  `https://127.0.0.1:8443` to `:8090`, and everything else to the chat server on
  `:8080`. So Desktop's `storageUrl` (already `127.0.0.1:8443`) reaches groups with
  **no client config change**.
- zkgroup: the storage-service verifies group-auth credential presentations with
  `ServerZkAuthOperations(serverSecretParams)`. `boot.sh` injects the **chat
  server's own** `zkConfig-libsignal-0.42.serverSecret` into `config.yml`, so the
  two share one `ServerSecretParams` and credentials the chat server issues verify
  here. Desktop's `serverPublicParams` already derives from the same secret.

## Prerequisites

- **Java 25** active (Temurin 25 — same as the chat server). `java -version` → 25.
  (That's it — the Bigtable emulator is pulled in via Maven; no gcloud/Docker/Python.)
- The **storage-service** repo cloned at `~/Repos/personas2/storage-service`
  (override with `STORAGE_SERVICE_DIR`), and the **Signal-Server** repo cloned
  (for the shared secret; override with `SIGNAL_SERVER_SECRETS`).

## Boot

With the chat test server already up (`signal-test-server`: `boot.sh` +
`minio.sh up` + `tls-proxy.sh up`):

```sh
cd deploy/storage-service

# One command: renders config (injects the shared zkgroup secret), starts the
# Bigtable emulator + creates the 4 tables, then runs the storage-service on :8090.
./boot.sh
```

Then **re-run the TLS proxy once** so its Caddyfile picks up the new storage route:

```sh
cd ../signal-test-server && ./tls-proxy.sh up
```

Ports: storage-service **:8090** (admin :8091); the Bigtable emulator takes a free
port (written to `.local/bigtable-emulator-host`). Stop the emulator with
`./bigtable.sh down`; the service stops on Ctrl-C.

The first run downloads the storage-service's Maven dependency tree (incl. the
bundled emulator) — a one-time large fetch, like the chat server's first boot.

## Verify

```sh
# Group create is a PUT authed by a zkgroup presentation; an unauthenticated GET
# should reach the service (401/400), NOT 404 — that proves routing + service up.
curl -sk -o /dev/null -w '%{http_code}\n' https://127.0.0.1:8443/v2/groups
# 401/403/400 = reaching the storage-service (good).  404 = route/service not up.
```

Then in Desktop: **New group** → add members → create. It should now hit real
`/v2/groups` instead of 404.

## Notes

- **Ephemeral.** The Bigtable emulator holds all group state in memory; it is lost
  on `bigtable.sh down` / reboot, and the tables are recreated on each `up`. Groups
  must be re-created after a restart (matches the chat server's re-register-per-boot
  story).
- **Placeholders.** `authentication.key`, `cdn.*`, and `group.externalServiceSecret`
  in `config.yml.template` are inert for the demo (contact-manifest sync, group
  avatars, and external group credentials are unused). Only `zkConfig.serverSecret`
  and the Bigtable table ids are load-bearing.
- **Expect iteration.** Like the chat server needed a few patches, the first boot may
  surface a config/field gap; the Dropwizard startup log points at the exact field.

[ss]: https://github.com/signalapp/storage-service
