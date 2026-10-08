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

## 0. Confirm three unknowns first

```sh
uname -m                                   # x86_64 or aarch64 — picks the JDK build
ls -ld /srv/signalserver00                 # is it ours?
touch /srv/signalserver00/.w && echo WRITABLE && rm /srv/signalserver00/.w
df -h /srv /var/tmp
```

If `/srv/signalserver00` is not writable, use `/var/tmp/personas` and expect it to be
cleaned periodically, or ask for a writable location.

**Do not put the Maven repository in your NFS home.** `~/.m2` on NFS makes the build
painfully slow and the tree is 1–2 GB against a 30 GB quota. §2 redirects it.

---

## 1. Workspace

```sh
export WORK=/srv/signalserver00          # or /var/tmp/personas
mkdir -p "$WORK"/{repos,tools,m2}
cd "$WORK"
```

Put this in `~/.bashrc` so it survives reconnects — you will be back here often:

```sh
cat >> ~/.bashrc <<'EOF'
export WORK=/srv/signalserver00
export JAVA_HOME="$WORK/tools/jdk-25"
export PATH="$JAVA_HOME/bin:$PATH"
export MAVEN_OPTS="-Dmaven.repo.local=$WORK/m2"
export DOCKER_HOST="unix:///run/user/$(id -u)/podman/podman.sock"
export TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE="/run/user/$(id -u)/podman/podman.sock"
export TESTCONTAINERS_RYUK_DISABLED=true
EOF
source ~/.bashrc
```

`TESTCONTAINERS_RYUK_DISABLED` matters: Ryuk is testcontainers' cleanup sidecar and it
does not work under rootless Podman. Leaving it enabled makes containers fail to start
with an error that does not mention Ryuk.

---

## 2. JDK 25

`RUNNING_E2_LOCALLY.md:59` requires JDK 25; the box has 17. No root needed — unpack a
tarball into `$WORK/tools`.

```sh
cd "$WORK/tools"
# pick the URL matching `uname -m` from https://adoptium.net/temurin/releases/?version=25
curl -LO <temurin-25-linux-$(uname -m)-tarball-url>
tar xzf OpenJDK25*.tar.gz
mv jdk-25* jdk-25
java -version        # must say 25
```

**Verify:** `java -version` reports 25 and `echo $JAVA_HOME` points at `$WORK/tools/jdk-25`.

---

## 3. Podman as a Docker-compatible socket

Testcontainers starts FoundationDB and the Bigtable emulator; it speaks the Docker API.

```sh
systemctl --user enable --now podman.socket
systemctl --user status podman.socket --no-pager | head -5
curl -s --unix-socket "/run/user/$(id -u)/podman/podman.sock" http://d/_ping && echo " <- OK"
loginctl enable-linger "$USER"     # keeps the socket alive after you log out
```

`enable-linger` is easy to miss and its absence is confusing: everything works while you
are connected and dies when you disconnect.

**Verify:** `_ping` returns `OK`.

---

## 4. Clone the three repositories

`boot.sh` needs **three** checkouts, not one:

```sh
cd "$WORK/repos"
git clone https://github.com/oliwial23/CryptoPersonas_Signal.git
git clone https://github.com/signalapp/Signal-Server.git
git clone https://github.com/signalapp/storage-service.git
```

Then tell the scripts where they are (add to `~/.bashrc`):

```sh
export SIGNAL_SERVER_DIR="$WORK/repos/Signal-Server"
export STORAGE_SERVICE_DIR="$WORK/repos/storage-service"
export SIGNAL_SERVER_SECRETS="$SIGNAL_SERVER_DIR/service/src/test/resources/config/test-secrets-bundle.yml"
```

If `storage-service` is not public, ask whoever has it — without it there are no GroupV2
endpoints and **you cannot create the demo group**.

---

## 5. Chat server

`boot.sh` applies our patches to the Signal-Server checkout, then builds and runs. First
build downloads a large Maven tree; expect a long wait.

```sh
cd "$WORK/repos/CryptoPersonas_Signal/deploy/signal-test-server"
./boot.sh                                  # keep this shell open
```

In a second shell:

```sh
curl -sS http://127.0.0.1:8081/ping        # expect: pong
./verify.sh                                # expect pong / 422 / 405 / 400
```

The three patches it applies (websocket auth during registration, ASN refresh interval,
and the paged KEM prekey store pointing at local S3) are in `patches/README.md`. On Linux
the macOS FoundationDB workaround is skipped — `libfdb_c.so` is already on the loader
path (`boot.sh:33`), so that is one problem you do not have.

---

## 6. MinIO — do not skip this

The prekey store writes to S3. Without it, `PUT /v2/keys` never answers, registration
dies after ~90 s with `HTTPError -1`, and clients show a device-link QR screen. This
exact failure has already cost days once.

```sh
cd "$WORK/repos/CryptoPersonas_Signal/deploy/signal-test-server"
./minio.sh up
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9100/minio/health/live   # 200
```

`minio.sh` calls `docker`. With `DOCKER_HOST` set to the Podman socket you may still need
a shim: `alias docker=podman`, or `ln -s $(which podman) "$WORK/tools/docker"` with
`$WORK/tools` on `PATH`.

**Also confirm the bucket exists** — the script has reported success while failing to
create it:

```sh
podman exec personas-minio ls /data        # expect: prekey-bucket
```

---

## 7. storage-service (GroupV2)

```sh
cd "$WORK/repos/CryptoPersonas_Signal/deploy/storage-service"
./boot.sh                                  # starts the Bigtable emulator, then :8090
```

```sh
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8090/v1/groups   # 401/403/405, not 000
```

---

## 8. Expose 8443 — use `plain-proxy.sh`, not `tls-proxy.sh`

UMIACS terminates TLS at their fronting proxy, so the VM should serve **plain HTTP** on
8443. That is exactly what Oliwia's `plain-proxy.sh` is for.

```sh
cd "$WORK/repos/CryptoPersonas_Signal/deploy/signal-test-server"
./plain-proxy.sh up
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8443/v1/config    # 404 = routing works
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8443/v1/storage   # not 404 = storage routed
```

**Podman gotcha:** the script's upstreams are `host.docker.internal:8080` and `:8090`,
which Podman does not resolve by default. Either add
`--add-host=host.docker.internal:host-gateway` to its `docker run`, or set the upstreams
explicitly:

```sh
UPSTREAM=127.0.0.1:8080 STORAGE_UPSTREAM=127.0.0.1:8090 ./plain-proxy.sh up
```

(With `127.0.0.1` the proxy container needs host networking — `--network host` — since
loopback inside the container is not the host's.)

---

## 9. Reachability — start this on day one

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

## 10. Point the clients at it

Once there is a reachable hostname, **on your laptop**:

```sh
./scripts/personas-remote-setup.sh --probe <public-host>
./scripts/personas-remote-setup.sh --remote <public-host>
pnpm run build:rolldown
./scripts/personas-run.sh alice --reset
```

`serverPublicParams` and `serverTrustRoots` must match **this** deployment. From the VM:

```sh
grep -rhoE 'AAp8[A-Za-z0-9+/=]*' "$SIGNAL_SERVER_DIR" | head -1
grep -rn serverTrustRoots "$SIGNAL_SERVER_DIR/service/src/test/resources/config/" | head
```

`--remote` also removes `certificateAuthority`, which is required: it is passed to Node as
`ca`, which **replaces** the trust store, so a self-signed test CA rejects UMIACS's real
certificate.

---

## 11. Two cautions

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
