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

## Playing

Open `https://signalserver.umiacs.umd.edu/play/`, log in, pick a member. The first launch
on fresh volumes generates the ~51 MB proving keys (minutes) and registers the account.
Then follow `Signal-Desktop-Persona-main/PERSONAS_DEMO.md` from "Create the group".

## After a backend restart

The test server forgets accounts and groups on restart, while each member's userData
still thinks it is registered. Reset the members:

```sh
PERSONAS_RESET=1 docker compose up -d --force-recreate alice bob
docker compose up -d --force-recreate alice bob      # then drop the flag again
```

`docker compose down -v` wipes everything, including the shared phantom bundle and keys.

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
