# Private Signal-Server (test-server mode) for developing the modified client

This directory stands up a **private, isolated [Signal-Server][ss]** on your own
machine so we can develop and test the **modified Signal client** (workstream `e2`,
`transport-presage`) against a real Signal HTTP/websocket API **without ever
touching the production Signal network**.

It uses Signal-Server's own upstream **`test-server`** mode: a real server with real
account registration and real sealed-sender messaging, but with phone-number
verification **stubbed** and all datastores spun up as throwaway local containers by
Testcontainers. Nothing here talks to Signal's servers, uses real phone numbers, or
affects any real user.

> **Why this is allowed pre-sign-off.** The e2 gate ("no live Signal until
> cryptographer sign-off") exists to protect the *production* network and to gate the
> crypto *design*. An isolated instance with only our own test accounts is not the
> production network, so it is the intended **staging** venue. The design sign-off
> still governs before any production use.

**Everything is ephemeral.** Datastores run in-memory and the containers are torn
down when the server stops, so **accounts must be re-registered on every boot.**

---

## Pinned versions (keep in lockstep)

| Component | Version | Notes |
|---|---|---|
| Signal-Server | commit `ed90c1c15c1dcd72b7adfec25d92cafc6b61da22` (tag `v20260714.1.0`) | the revision this harness was validated against |
| JDK | Temurin **25** | Signal-Server pins `.java-version = temurin-25` |
| FoundationDB | **7.3.68** | must match Signal-Server `pom.xml <foundationdb.version>` / api-version 730 |
| Container runtime | Colima (validated) or any Docker daemon | plus the **Docker Compose v2 plugin** |
| Images (auto-pulled, arm64+amd64) | `amazon/dynamodb-local:3.3.0`, `redis:7.4-alpine`, `bitnamilegacy/redis-cluster:7.4.3`, `foundationdb/foundationdb:7.3.68`, `testcontainers/ryuk` | |

If you bump the Signal-Server revision, re-check the FDB version and image tags.

---

## Prerequisites

### macOS — Apple Silicon (validated: M4, macOS 26.2) and Intel

Install via [Homebrew][brew]:

```sh
# 1. JDK 25
brew install --cask temurin@25

# 2. Container runtime — Colima (NOT Docker Desktop; see gotchas)
brew install colima docker
colima start --cpu 4 --memory 8 --disk 60      # sized for ~7 containers + the JVM

# 3. Docker Compose v2 plugin (Testcontainers uses `docker compose` for the redis cluster)
brew install docker-compose
mkdir -p ~/.docker/cli-plugins
ln -sfn "$(brew --prefix)/opt/docker-compose/bin/docker-compose" ~/.docker/cli-plugins/docker-compose
docker compose version    # must print v2.x
```

You do **not** install FoundationDB on macOS — `setup-fdb-client.sh` (below) stages
just the client library. See "The FoundationDB trick" for why.

### Linux

- JDK 25 (Temurin or equivalent).
- Docker Engine + the Compose v2 plugin (`docker compose`), daemon running.
- FoundationDB **clients** package 7.3.68 (`.deb`/`.rpm` from the [FDB release][fdbrel]).
  It installs `libfdb_c.so` on the default loader path, so **no override is needed**
  and you can skip `setup-fdb-client.sh` / the `FDB_C_DYLIB` bits.

---

## One-time setup

```sh
# a) Clone Signal-Server at the pinned revision (separate AGPL repo; do NOT vendor it here)
git clone https://github.com/signalapp/Signal-Server.git ~/Repos/Signal-Server
git -C ~/Repos/Signal-Server checkout ed90c1c15c1dcd72b7adfec25d92cafc6b61da22

# b) Stage the FoundationDB client lib (macOS only; Linux installs the .deb/.rpm instead)
./setup-fdb-client.sh        # downloads the arm64/x86_64 pkg, extracts libfdb_c.dylib to ./.local/
```

## Boot

```sh
./boot.sh                    # runs in the foreground and BLOCKS while serving; Ctrl-C to stop
```

- **First boot is slow** — Maven downloads a very large dependency tree (one-time;
  cached in `~/.m2` thereafter). Subsequent boots reach "server started" in ~1–2 min
  plus a one-time image pull.
- Override paths if your layout differs:
  `SIGNAL_SERVER_DIR=… FDB_C_DYLIB=… ./boot.sh`.

The server is up when the log shows `Started application@…{HTTP/1.1, (http/1.1, h2c)}{0.0.0.0:8080}`.

## Verify

In another terminal:

```sh
./verify.sh                  # liveness + full stubbed registration to "verified":true
```

Expected: `pong`, a session `id`, then `"verified":true`.

## Ports

| Port | Purpose |
|---|---|
| `:8080` | main API + `/v1/websocket`. Connector is `HTTP/1.1, (http/1.1, h2c)` — **accepts plain HTTP/1.1**, so a cleartext client works (no TLS proxy needed). |
| `:8081` | Dropwizard admin (`/ping`, `/healthcheck`) |
| `:50051` | gRPC |

## Registration stub (what the client can rely on)

Modern session-based flow, all under `/v1/verification/session`:
1. `POST /v1/verification/session` `{"number":"+1..."}` → session, `requestedInformation:["captcha"]`.
2. `PATCH /v1/verification/session/{id}` `{"captcha":"noop.noop.registration.noop"}` → `allowedToRequestCode:true`.
3. `PUT  /v1/verification/session/{id}/code` `{"code":"<anything>"}` → `"verified":true` (any code accepted).
4. `PUT /v1/registration` (identity keys + prekeys) then `PUT /v2/keys` — this is what the
   real client (presage) drives to actually create an account.

## Driving the modified client (e2 A1)

The modified client (`transport-presage`, built on presage) always speaks TLS + `wss://`
and pins a configured CA, and presage's registration/receive both ride the **websocket**.
Two extra pieces bridge it to this server; `boot.sh` handles the second automatically.

1. **TLS proxy** — terminate TLS in front of the cleartext `:8080` connector:
   ```sh
   ./tls-proxy.sh up        # Caddy container: https://127.0.0.1:8443 -> :8080 (self-signed CA in .local/tls)
   ./tls-proxy.sh status    # / down
   ```
   `SignalServers::Staging` is repointed at `https://127.0.0.1:8443` with this CA baked in
   (`third_party/libsignal-service-rs/src/configuration.rs`, plus the test-server's UD
   trust root + zkgroup serverPublic).

2. **Registration patch** — `patches/0001-*` lets the authenticated `/v1/websocket/`
   **upgrade** during registration (the account does not exist yet, so stock auth 403s).
   Applied idempotently by `boot.sh`. See `patches/README.md`.

Then, with the server + proxy up, the account-gated paths run against this server:
```sh
cargo run -p transport-presage --example a1_smoke       # register 2 accounts, 1:1 send/receive
cargo run -p transport-presage --example a1_transport   # PresageTransport A->B over the Transport trait
```

## Teardown

`Ctrl-C` the `boot.sh` foreground process (Testcontainers reaps its containers via Ryuk).
To stop the whole runtime: `colima stop`. Nothing persists between boots.

---

## Gotchas we hit (so you don't)

- **Do NOT use Docker Desktop on Apple Silicon.** It prompts for Rosetta, and if you
  install then uninstall the cask it leaves a dangling `~/.docker/cli-plugins/docker-compose`
  symlink. Use Colima.
- **`docker compose` must actually work.** `brew install docker` gives only the CLI;
  without the Compose v2 plugin, Testcontainers' redis-cluster step dies with
  `Local Docker Compose exited abnormally with code 125`. Install `docker-compose` and
  symlink it into `~/.docker/cli-plugins/` (see prereqs). Check with `docker compose version`.
- **The FoundationDB macOS installer wants Rosetta — don't run it.** See below.
- **Testcontainers + Colima socket.** `boot.sh` sets `DOCKER_HOST` to the Colima socket
  and `TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock`. If Testcontainers
  still can't find Docker, confirm `docker context show` is `colima` and the socket path.

### The FoundationDB trick

The Signal-Server test harness runs on the **host** JVM (via `./mvnw … exec:java`), and
fdb-java needs the native client library `libfdb_c` on the host — the fdb-java jar bundles
only its JNI glue (`lib/osx/aarch64/libfdb_java.jnilib`), not the C client.

The official macOS FoundationDB `.pkg` is **native arm64** in its payload (dylib, fdbcli,
fdbmonitor all arm64), but its *installer wrapper* runs an x86 pre/post-install script and
so refuses to install without Rosetta. Rather than install Rosetta, `setup-fdb-client.sh`
expands the pkg in userland (`pkgutil --expand-full`) and copies out just
`libfdb_c.dylib` into `./.local/`. `boot.sh` then points fdb-java at it via the JVM property
`-DFDB_LIBRARY_PATH_FDB_C=<path>` (set through `JAVA_TOOL_OPTIONS` so it reaches the forked
server JVM). Result: no sudo, no Rosetta, no system-wide install.

[ss]: https://github.com/signalapp/Signal-Server
[brew]: https://brew.sh
[fdbrel]: https://github.com/apple/foundationdb/releases/tag/7.3.68
