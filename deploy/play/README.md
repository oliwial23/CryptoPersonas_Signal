# Browser-playable demo on signalserver00

Stage 1 of hosting: every group member's Signal-Persona Desktop runs **on the VM**, each
in its own container on a virtual display, and people play through their browser at

    https://signalserver.umiacs.umd.edu/play/

Nobody installs anything. The members run exactly the code an installed client runs, so
this is also the test bed for the downloadable client: nothing is shared between them
through the filesystem except the proving keys. The phantom bundle and chain travel over
Signal (`ts/services/personasPhantom.preload.ts`), and members find each other through
the directory service (`directory.js`).

```
 browser ──https──▶ signalserver.umiacs.umd.edu:443   (UMIACS LB, terminates TLS)
                           │ plain HTTP
                           ▼
                VM :8443  gateway (Caddy)
                 ├─ /play/            landing page          ┐ basic auth
                 ├─ /play/<member>/   member's noVNC :6080   ┘
                 ├─ /personas/directory  → directory.js        (member discovery)
                 ├─ /v1|v2/groups, /v1/storage → storage-service :8090
                 └─ everything else            → chat server     :8080
   members: alice bob carol dave erin  — Electron on Xvfb, sharing only the keys volume,
            each reaching the gateway through a TLS relay on its own 127.0.0.1
```

## Requirements

* The backend from `PERSONAS_SERVER_DEPLOY.md` §2 steps 1–3 running on the VM (chat
  server :8080, MinIO, storage-service :8090). **Skip step 4** — this gateway replaces
  both `tls-proxy.sh` and `plain-proxy.sh`; stop them if running, they hold :8443.
* Docker with the Compose plugin. Rootless Podman can't run this reliably; it's also
  what blocks the backend (§5).
* **RAM.** Backend ≈ 3–4 GB, each member ≈ 1–1.5 GB. The VM's 7 GB fits the backend
  plus about two members. Five members want ~12–16 GB; ask UMIACS.

## Bring-up (on the VM)

```sh
cd "$WORK/repos/CryptoPersonas_Signal/deploy/play"
./set-password.sh                      # shared login for /play; writes .env
docker compose build                   # ~20-40 min first time: Rust ZK addon + Desktop bundle
docker compose up -d gateway alice bob # start small; add carol dave erin if RAM allows
```

Check:

```sh
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8443/v1/config   # 401/404 = routed to chat server
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8443/play/       # 401 = auth on
curl -s -o /dev/null -w '%{http_code}\n' https://signalserver.umiacs.umd.edu/play/   # 401 from outside
docker compose logs -f alice
```

## Proving keys from the server (recommended)

Every member must prove against an identical Groth16 key set. Without a pin, alice
generates one at first boot and the others share it through the `keys` volume. To run the
members the way installed clients run instead — downloading the keys from the gateway and
verifying them against a pinned SHA-256 — generate them once on the server:

```sh
./keys.sh                                   # one-time keygen into the keys volume; writes the pin to .env
docker compose up -d --force-recreate gateway alice bob carol
```

The gateway then serves them at `/personas/keys/merkle_groth16_keys.bin`, and each member
downloads its own copy into `~/.personas-keys` and refuses any file whose hash differs.
Whoever generates the keys could forge proofs, so this puts that trust on the server, in
one known place. `keys.sh` never regenerates existing keys; a new set means a new pin for
every client.

## After a `git pull`

The gateway reads `Caddyfile` only when its container is created, and `git pull` replaces
the file, so a running gateway keeps the old routes. When the pull changed `Caddyfile`:

```sh
docker compose up -d --force-recreate gateway
```

## Playing

Open `https://signalserver.umiacs.umd.edu/play/`, log in, pick a member. The first launch
on fresh volumes generates the ~51 MB proving keys (minutes) and registers the account.
Then follow `Signal-Desktop-Persona-main/PERSONAS_DEMO.md` from "Create the group".

## Keeping it running (systemd)

Nothing restarts by itself after a reboot unless installed as services. Once everything
works by hand, stop it and install user units (no root needed; requires lingering):

```sh
pkill -f 'Ptest-server|StorageService|EmulatorMain'; ../signal-test-server/minio.sh down
docker compose down
source ~/.bashrc && ../systemd/install.sh                 # gateway + directory
# or: PERSONAS_PLAY_MEMBERS="alice bob carol" ../systemd/install.sh
systemctl --user start personas-minio personas-chat personas-storage personas-play
systemctl --user status 'personas-*'
journalctl --user -u personas-chat -f
```

A restart of the chat server wipes every account. Installed clients notice (their
credentials are refused), restart, and register again with the same number and name;
the directory moves their listing to the new account. Groups must be re-created.

## The member directory

`directory.js` lists members whose app checked in during the last hour (apps check in
every five minutes), so closed or uninstalled apps stop appearing. An entry silent for a
day can be claimed by a new install of the same account; one silent for 30 days is
deleted. All three are configurable (`DIRECTORY_*_MS`, see the file).

## Publishing the app

Build on an Apple Silicon Mac — once per architecture, with the pin from `./keys.sh` — then
put both on the download page:

```sh
cd ../../Signal-Desktop-Persona-main
node scripts/personas-package.mjs --keys-sha256 <pin>              # Apple Silicon
node scripts/personas-package.mjs --keys-sha256 <pin> --arch x64   # Intel (engine cross-compiled)
cd ../deploy/play
./publish-dmg.sh ../../Signal-Desktop-Persona-main/release-personas/Signal-Personas-*.dmg
```

Testers get them, with the tester guide, at `https://signalserver.umiacs.umd.edu/download/`
(same password as `/play`). Every build carries its own version (`…+personas.<UTC stamp>`),
shown in the file name and the About window.

## Resetting the members

After a backend restart (the test server forgets accounts and groups, while each member's
data still thinks it is registered), or whenever you want a clean slate, reset the
members **and the directory together**:

```sh
docker compose rm -sf alice bob carol directory
for v in play_alice play_bob play_carol play_directory; do podman volume rm "$v"; done
docker compose up -d directory alice bob carol
```

Why the directory too: each member owns its directory entry through a secret kept in its
own data. A reset member re-registers the same number, and the test server hands it the
same account id, so the directory sees a new install claiming an existing entry and
refuses it (HTTP 403). Its contacts then keep stale profile keys and do not appear.
Installed clients do not hit this: each install picks a fresh number.

`docker compose down -v` wipes everything, including the proving keys (then re-run
`./keys.sh`, which mints a new set and a new pin every client must be rebuilt with).

## How a member reaches the backend (and why not the public URL)

libsignal-net only talks to a self-hosted server in its `localTestServer` mode, which has
no host setting: it always dials `localhost:<port>` and trusts one private root CA. Any
other `serverUrl` makes Desktop select the **production** Signal network. (A personas
instance now refuses to start in that case; see `ts/textsecure/preconnect.preload.ts`.)

So each member runs `tls-relay.js` on its own `127.0.0.1:8443` with a CA minted at first
boot, and the client config points there. The relay forwards plain HTTP to `gateway:8443`
on the compose network, rewriting `Host`. `PERSONAS_UPSTREAM` changes the target;
`PERSONAS_UPSTREAM_TLS=1` dials it over TLS, e.g. `signalserver.umiacs.umd.edu:443` for
a member running somewhere other than the VM. The same relay is what an installable
client (stage 2) would need on each tester's machine.
