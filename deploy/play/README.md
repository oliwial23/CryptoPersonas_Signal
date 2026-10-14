# Browser-playable demo on signalserver00

Stage 1 of hosting: every group member's Signal-Persona Desktop runs **on the VM**, each
in its own container on a virtual display, and people play through their browser at

    https://signalserver.umiacs.umd.edu/play/

Nobody installs anything. Because all members run on one host, the shared
`PERSONAS_ROSTER_DIR` design (phantom bundle, barrier anchor, sender-key send state) works
unchanged — it is just a Docker volume. Stage 2 (installable clients on people's own
machines) needs that coordination moved into a server first; see
`PERSONAS_SERVER_DEPLOY.md` §8.

```
 browser ──https──▶ signalserver.umiacs.umd.edu:443   (UMIACS LB, terminates TLS)
                           │ plain HTTP
                           ▼
                VM :8443  gateway (Caddy)
                 ├─ /play/            landing page          ┐ basic auth
                 ├─ /play/<member>/   member's noVNC :6080   ┘
                 ├─ /v1|v2/groups, /v1/storage → storage-service :8090
                 └─ everything else            → chat server     :8080
   members: alice bob carol dave erin  — Electron on Xvfb, sharing roster+keys volumes,
            talking to the backend through the same public URL
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

## Pointing at a different backend

`PERSONAS_SERVER_URL` (in `.env`) defaults to the public endpoint, so members reach the
backend the same way outside clients will. If hairpinning through the load balancer fails
from inside the VM, use a URL the containers can reach directly. If it isn't publicly
trusted, also mount its CA and set `PERSONAS_CA_FILE` (see `entrypoint.sh`).
