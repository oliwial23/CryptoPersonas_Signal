<!-- Copyright 2026 Signal Messenger, LLC -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Running against a remote test server (UMIACS)

End-to-end steps for pointing the Desktop clients at `signalserver00.umiacs.umd.edu`
instead of a backend on the laptop. Companion to `PERSONAS_DEMO.md` (local setup) and
`PERSONAS_ZK_WORKPLAN.md` (outstanding protocol work).

---

## 0. What this fixes, and what it does not

**Read this before doing the work**, so the result is not a surprise.

Moving the backend off the laptop removes four server processes and the Linux VM hosting
the containerised ones. Measured from an actual diagnostics run:

| Moves to the server | Resident on the laptop today |
|---|---|
| chat server JVM | ~632 MB |
| storage-service JVM | ~169 MB |
| MinIO + its Colima VM | ~500 MB – 1 GB |
| Caddy TLS proxy container | (inside the VM above) |
| **total freed** | **~0.8 – 1.8 GB** |

**What stays on the laptop: the Signal Desktop clients, at roughly 1 GB each.** They are
Electron GUI apps; they cannot run on a headless node, and SLURM does not help with
them.

So the arithmetic for three instances:

```
3 clients          ~3.0 GB
freed by remoting  ~0.8-1.8 GB
```

Remoting alone is **not** sufficient if the laptop was already at ~0.3 GB free. It makes
two instances comfortable and three plausible; three reliably also needs local headroom
(see §6).

The other benefit is less obvious and possibly larger: **MinIO, Colima, the proxy and
the port conflicts leave the laptop entirely.** Those produced a 90-second websocket
timeout, a port owned by an unrelated `dart` process, and a Docker-daemon mix-up — more
lost time than the memory ever caused.

---

## 1. No SLURM, no SSH tunnel

The UMIACS Jupyter guide describes running a job on a **SLURM compute node**, which
needs a tunnel because compute nodes are not publicly reachable. This is a different
resource: a **persistent VM** behind a fronting proxy that accepts traffic *from the
public internet* on port 443 and forwards to 8443, with TLS terminated by UMIACS.

So the laptop talks to it like any website. Nothing is submitted to SLURM, and the nexus
submission node is not in the path.

Confirm before changing anything:

```sh
./scripts/personas-remote-setup.sh --probe signalserver00.umiacs.umd.edu
```

That checks the TLS chain, opens a registration session, and tests whether
`/v1/storage` is routed. If TLS handshakes fail, the proxy is internal-only after all —
see §7 for the tunnel variant.

---

## 2. Three things to confirm with whoever deployed the server

Each of these fails far from its cause, so ask first.

**`serverPublicParams` and `serverTrustRoots` must match the deployment.** These are
zkgroup parameters belonging to that server. If it was built from a different checkout
than your local one, carrying your values over gets group operations rejected with
errors that point nowhere useful. On the VM's CryptoPersonas checkout:

```sh
grep -rhoE 'AAp8[A-Za-z0-9+/=]*' . | head -1    # serverPublicParams
grep -rn serverTrustRoots .                     # trust root(s)
```

**Is storage-service running, and does the proxy path-route to it?** Locally
`tls-proxy.sh` routes `/v1/groups*`, `/v2/groups*` and `/v1/storage*` to port 8090 and
everything else to 8080. If the UMIACS proxy sends *everything* to 8443, GroupV2
create/fetch returns 404 and **you cannot create the demo group**. The probe in §1
reports this.

**Is MinIO (or any S3 endpoint) running for the paged KEM prekey store?** The server
patch points `pagedSingleUseKEMPreKeyStore` at an S3 endpoint. Without it,
`PUT /v2/keys` never answers, registration times out after ~90 s with `HTTPError -1`,
and the client falls back to a device-link QR screen. This precise failure has already
consumed days once; it is worth one message to confirm.

---

## 3. Switch the client config

```sh
./scripts/personas-remote-setup.sh --remote signalserver00.umiacs.umd.edu
```

This backs up `config/local-development.json` to
`config/local-development.local-backup.json` (never overwriting an existing backup),
points `serverUrl`, `storageUrl` and all three `cdn` slots at the host, and **removes
`certificateAuthority`**.

That removal is the part most likely to be got wrong by hand. The value is passed to
Node as the `ca` option, which **replaces** the trust store rather than adding to it —
so a self-signed test CA causes every publicly-signed endpoint to be rejected. It is
also why requests to real Signal endpoints have been failing with
`SELF_SIGNED_CERT_IN_CHAIN`. If §1 reports the cert is *not* publicly trusted, put that
CA's PEM in instead; otherwise the key must be absent.

Note the config has no port: the proxy listens on 443.

Switch back any time with `--local`.

---

## 4. What stays local regardless

These are laptop-side coordination files, not server state, and they do not change:

| Thing | Where | Why it stays |
|---|---|---|
| `PERSONAS_KEYS_DIR` | `~/.personas-demo-keys` | the ~51 MB Merkle proving keys; the ZK engine runs **client-side**, the server never sees it |
| `PERSONAS_ROSTER_DIR` | `/tmp/personas-roster` | phantom bundle + barrier anchor, shared between instances on this machine |
| the napi addon | `packages/personas-engine/*.node` | client-side engine |

A consequence worth stating: **the CryptoPersonas protocol does not move to the server
at all.** Only Signal's transport does. Proving still happens in each client's render
process, so the per-client memory cost is unchanged.

---

## 5. Run it

```sh
pnpm run build:rolldown
./scripts/personas-run.sh alice --reset
./scripts/personas-run.sh bob   --reset
```

`--reset` on first switch is mandatory: the accounts on the old local server do not
exist on the new one, and a stale `userData` leaves a client that looks logged in while
holding an account the server never heard of.

`personas-run.sh` now refuses to launch when free RAM is under ~1.2 GB or swap is over
80 %, with an explanation — rather than letting macOS kill the renderer and leaving you
with `Render process is gone / Exit Code: 9`, which has had five unrelated causes on
this project and distinguishes none of them.

---

## 6. Getting three instances to fit

Remoting gets you ~1 GB. For three clients, reclaim more locally. From a real
diagnostics run, in order of return:

* **VS Code** — ~1.3 GB across renderers, plus **~500 MB** for the `ltex` grammar-checker
  extension's JVM. Disabling that one extension is the single best win and costs nothing
  for this work.
* **Browsers** — ~1.5 GB across WebKit content processes.
* **Any VM you are not using** — Colima can be stopped entirely once the backend is
  remote (`colima stop`), which is also the point of this exercise.

Check with `ps -Ao rss,pid,comm -m | head -20`, or `./scripts/personas-diagnose.sh`
which prints a verdict.

---

## 7. If the proxy turns out to be internal-only

Only if §1's TLS handshake fails. Do **not** tunnel to `localhost`: the certificate is
issued for `signalserver00.umiacs.umd.edu` and would fail hostname verification. Map the
name so the cert still matches:

```sh
# /etc/hosts
127.0.0.1  signalserver00.umiacs.umd.edu
```

```sh
sudo ssh -N -L 443:signalserver00.umiacs.umd.edu:443 <user>@nexusmc2.umiacs.umd.edu
```

`sudo` because 443 is privileged. The client config is unchanged — it still names the
real host. **Remove the `/etc/hosts` line when finished**, or the server becomes
unreachable through normal DNS.
