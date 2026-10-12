<!-- Copyright 2026 Signal Messenger, LLC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Deploying the test server on signalserver00 (UMIACS)

Runbook for standing the backend up on the VM instead of a laptop. Written against the
actual state of that box: RHEL-family, **JDK 17** installed (we need 25), **Podman** and
no Docker, **7 GB RAM / 4 cores**, ~30 GB free on `/`, 30 GB NFS home.

Run every command **on the VM** (`ssh signalserver00.umiacs.umd.edu`) unless marked
otherwise. Verify after each step; a failure three steps later is much harder to read.

> **Two independent projects.** This runbook gets the server *running*. It does not make
> it *reachable* — the VM is on `192.168.25.15`, a private address, so laptops cannot
> connect regardless. §9 covers that, and it needs UMIACS, not you. Start §9 in parallel
> on day one.

---

## 0. Known facts about this box

Established by inspection, so you do not need to re-derive them:

| | |
|---|---|
| arch | `x86_64` |
| OS JDK | **17** — too old; the build needs **25** |
| container runtime | **Podman** only, no Docker; no `compose` provider |
| RAM / cores | 7 GB / 4 |
| workspace | `/srv/signalserver00` — local disk, 49 GB free, world-writable |
| home | `/nfshomes/rthomase` — 30 GB NFS. **Do not** put the Maven repo here |
| `/var/tmp` | only 4 GB — avoid |
| reachable from laptop | **only over the UMD VPN** (SSH confirmed). `192.168.25.15` is private |

---

## 1. One-time setup (already done — here for a rebuild)

```sh
mkdir -p /srv/signalserver00/personas && chmod 700 /srv/signalserver00/personas
export WORK=/srv/signalserver00/personas
mkdir -p "$WORK"/{repos,tools,m2}
```

`chmod 700` matters: `/srv/signalserver00` is world-writable like `/tmp`, and the server
will hold the phantom private key.

Then append to `~/.bashrc` so it survives reconnects:

```sh
export WORK=/srv/signalserver00/personas
export JAVA_HOME="$WORK/tools/jdk-25"
export PATH="$JAVA_HOME/bin:$WORK/tools:$PATH"
export MAVEN_OPTS="-Dmaven.repo.local=$WORK/m2"
export SIGNAL_SERVER_DIR="$WORK/repos/Signal-Server"
export STORAGE_SERVICE_DIR="$WORK/repos/storage-service"
export SIGNAL_SERVER_SECRETS="$SIGNAL_SERVER_DIR/service/src/test/resources/config/test-secrets-bundle.yml"
export DOCKER_HOST="unix:///run/user/$(id -u)/podman/podman.sock"
export TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE="/run/user/$(id -u)/podman/podman.sock"
export TESTCONTAINERS_RYUK_DISABLED=true
```

`TESTCONTAINERS_RYUK_DISABLED` is not optional: Ryuk is testcontainers' cleanup sidecar
and does not work under rootless Podman, failing with an error that never mentions Ryuk.

### JDK 25

```sh
cd "$WORK/tools"
curl -L -o jdk25.tar.gz 'https://api.adoptium.net/v3/binary/latest/25/ga/linux/x64/jdk/hotspot/normal/eclipse'
tar xzf jdk25.tar.gz && rm jdk25.tar.gz && mv jdk-25* jdk-25
hash -r && java -version      # must say 25
```

### Podman as a Docker socket, plus Compose

```sh
systemctl --user enable --now podman.socket
loginctl enable-linger "$USER"        # or the socket dies when you log out
curl -s --unix-socket "/run/user/$(id -u)/podman/podman.sock" http://d/_ping   # OK

ln -sf "$(command -v podman)" "$WORK/tools/docker"   # scripts call `docker` by name

mkdir -p ~/.docker/cli-plugins         # the path podman searches first
curl -L -o ~/.docker/cli-plugins/docker-compose \
  https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64
chmod +x ~/.docker/cli-plugins/docker-compose
podman compose version                 # must print a version
```

### The three repositories — PIN THEM

```sh
cd "$WORK/repos"
git clone https://github.com/oliwial23/CryptoPersonas_Signal.git
git clone https://github.com/signalapp/Signal-Server.git
git clone https://github.com/signalapp/storage-service.git

cd "$SIGNAL_SERVER_DIR" && git checkout ed90c1c15
```

**Pinning is required, not tidiness.** Upstream `HEAD` now targets **Java 26**, which is
not released, so a fresh clone fails with `release version 26 not supported`. `ed90c1c15`
(2026-07-01) is the commit the laptop uses and the one our patches were written against.
If `storage-service` also drifts, pin it to whatever the laptop has.

---

## 2. Starting it — four services, in order

Use `nohup` and a log file, not `tmux`. Each service needs its own.

```sh
cd "$WORK/repos/CryptoPersonas_Signal/deploy/signal-test-server"

# 1. chat server  (applies the three patches, then builds)
nohup ./boot.sh > "$WORK/chat.log" 2>&1 &

# 2. MinIO — the prekey store. WITHOUT THIS, REGISTRATION HANGS ~90s AND FAILS
./minio.sh up
podman exec personas-minio ls /data        # must list prekey-bucket

# 3. storage-service — GroupV2. Without it you cannot create the demo group
cd ../storage-service
nohup ./boot.sh > "$WORK/storage.log" 2>&1 &

# 4. TLS proxy on 8443, WITH the hostname in the certificate
cd ../signal-test-server
PERSONAS_TLS_DNS=signalserver00.umiacs.umd.edu ./tls-proxy.sh up
```

On the proxy: use `tls-proxy.sh`, not `plain-proxy.sh`, while reaching the VM directly
over the VPN — the client speaks TLS and there is no public proxy terminating it. The
`PERSONAS_TLS_DNS` variable is required because the minted certificate otherwise covers
only `127.0.0.1`, `localhost` and `host.docker.internal`; connecting by hostname would
fail hostname verification. **The cert is only minted when absent** — to change the names,
`rm -rf .local/tls` first, then re-copy the new `ca.crt` to every client.

Watching progress, any time:

```sh
tail -f "$WORK/chat.log"        # Ctrl-C stops watching, not the server
grep -nE "applied patch|BUILD|ERROR|Caused by|Started" "$WORK/chat.log" | tail -20
```

---

## 3. Verifying — from the VM

```sh
curl -sS http://127.0.0.1:8081/ping                                        # pong
cd "$WORK/repos/CryptoPersonas_Signal/deploy/signal-test-server" && ./verify.sh
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9100/minio/health/live   # 200
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8090/v1/groups           # not 000
curl -k -s -o /dev/null -w '%{http_code}\n' https://127.0.0.1:8443/v1/config       # 404 = routed
curl -k -s -o /dev/null -w '%{http_code}\n' https://127.0.0.1:8443/v1/storage      # not 404
```

`verify.sh` should give pong / 422 / 405 / 400. A `404` on `/v1/storage` means the proxy
is not path-routing to storage-service, and groups will not work.

---

## 4. Stopping everything

```sh
pkill -f 'mvnw|TextSecure' ; pkill -f storage-service
podman ps -q  | xargs -r podman stop
podman ps -aq | xargs -r podman rm
podman ps -a                                  # should be empty
```

Nothing survives a reboot in any case — every service is a foreground process or an
unmanaged container. For a study you would want systemd user units; not worth it yet.

---

## 5. Current status

**Where it stops today:** the chat server build fails starting a Redis cluster through
testcontainers' `ComposeContainer`:

```
ContainerLaunchException: Local Docker Compose exited abnormally with code 1
  whilst running command: compose up -d
```

This is **progress** — the earlier failure was code **125** ("cannot run compose at
all"), fixed by installing the Compose binary. Code **1** means compose runs and fails
for its own reason, which is usually rootless-Podman-specific: image pull permissions,
network creation, or port binding. Read the compose output directly:

```sh
sed -n '200,262p' "$WORK/chat.log"
podman compose version
podman info --format '{{.Host.NetworkBackend}} {{.Host.Security.Rootless}}'
```

**This is why Docker is worth asking for.** Every failure so far has been a Docker
assumption in Signal-Server's test harness: the Java target, then a missing compose
provider, now compose under rootless Podman. Real Docker removes the category rather
than us fixing instances.

## 6. Reachability — the one thing you cannot fix yourself

The server now works locally on the VM and is still unreachable from any laptop.
`192.168.25.15` is RFC 1918; it is not routed from the public internet or from
`nexusmc200`. Ask UMIACS:

> signalserver00 is on 192.168.25.15. I need clients outside UMIACS to reach a service on
> port 8443. Is there a fronting proxy with a public hostname, and is it configured to
> forward to 8443 on this VM? If not, what is the supported way to expose a long-running
> service to off-campus clients?

Until that exists, test from the VM itself with `curl`, or from `nexusmc200` if routing
to `192.168.25.0/24` is opened.

---

## 7. Point the clients at it

**Today, over the VPN** — connect to the UMD VPN first, then on your laptop:

```sh
./scripts/personas-remote-setup.sh --remote-vpn signalserver00.umiacs.umd.edu
pnpm run build:rolldown
./scripts/personas-run.sh alice --reset
```

That sets `serverUrl` / `storageUrl` / `cdn` to `https://signalserver00.umiacs.umd.edu:8443`
and fetches the VM's `ca.crt` over ssh into `certificateAuthority`. It backs up your
laptop config first; `--local` restores it.

`--reset` is required on first switch: accounts on the old local server do not exist on
this one, and a stale `userData` leaves a client that looks logged in holding an account
the server never heard of.

**Later, through a public proxy** (once §6 is answered): `--remote <host>` instead. That
one *removes* `certificateAuthority`, because a public proxy presents a publicly-trusted
certificate and Node's `ca` option **replaces** the trust store rather than adding to it —
so leaving a self-signed CA in place would reject the real certificate.

### Server parameters must match this deployment

`serverPublicParams` and `serverTrustRoots` belong to the server. Both `--remote` modes
carry over whatever the laptop had, which is only correct if both were built from the same
config. From the VM:

```sh
grep -rhoE 'AAp8[A-Za-z0-9+/=]*' "$SIGNAL_SERVER_DIR" | head -1
grep -rn serverTrustRoots "$SIGNAL_SERVER_DIR/service/src/test/resources/config/" | head
```

If they differ from the laptop's, group operations are rejected with errors that point
nowhere near the cause.

## 8. Cautions

**7 GB RAM is tight.** Two JVMs plus FoundationDB, the Bigtable emulator, MinIO and Caddy
on 7 GB with 4 cores will be slower than the laptop and may hit limits under load. Watch
`free -g` during the first full run. If it thrashes, ask for more RAM — this is a VM, so
that is a request rather than a rebuild.

**Nothing here survives a reboot.** Every service runs in a foreground shell or an
unmanaged container. For anything beyond your own testing, these want systemd user units
so they restart on boot. Worth doing before a study, not before a first test.

**And the multi-user blocker is still unsolved.** Four things are shared through
`PERSONAS_ROSTER_DIR` on one machine — the phantom bundle, the barrier anchor, the roster,
and the sender-key send state. The last one is read-modify-written on *every send* with
"serial posting assumed", so two people sending simultaneously from different machines
corrupts the chain. Deploying this server does not fix that; see the discussion in
`PERSONAS_ZK_WORKPLAN.md`.
