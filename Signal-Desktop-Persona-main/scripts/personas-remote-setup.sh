#!/usr/bin/env bash
# Point the Desktop clients at a REMOTE Signal test server (e.g. the UMIACS VM) instead
# of a backend running on this laptop — or switch back.
#
# Why this exists: the local demo needs four server-side processes (chat server JVM,
# storage-service JVM, MinIO, Caddy proxy) plus a Linux VM to host the container ones.
# On a 36 GB laptop that is roughly 1-2 GB of resident memory before a single Signal
# client starts, and three clients want ~1 GB each. Moving the backend to a server frees
# that, and removes MinIO/Colima/port-conflicts from the laptop entirely — which has
# historically been a bigger source of lost time than the memory itself.
#
# Usage:
#   ./scripts/personas-remote-setup.sh --remote signalserver00.umiacs.umd.edu
#   ./scripts/personas-remote-setup.sh --local      # restore the laptop backend config
#   ./scripts/personas-remote-setup.sh --probe signalserver00.umiacs.umd.edu
#
# What it does NOT do: invent server parameters. `serverPublicParams` and
# `serverTrustRoots` are properties of the DEPLOYED server. If the remote was deployed
# from a different checkout than your local one, carrying your local values over will
# fail in confusing, far-from-the-cause ways (group operations rejected, credentials
# refused). The script carries them forward and tells you to confirm them; it cannot
# check them for you.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
CFG="$REPO/config/local-development.json"
BACKUP="$REPO/config/local-development.local-backup.json"

die() { echo "ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Probe: is the remote actually serving the chat API, and who signed its cert?
#
# These are the same two things verify.sh checks locally, aimed at the remote. Run them
# BEFORE changing config: a config pointed at an unreachable host produces a QR-code
# screen, which is indistinguishable from half a dozen other failures.
# ---------------------------------------------------------------------------
probe() {
  local host="$1"

  # Separate DNS from TCP from TLS. Lumping them together produces a message that
  # could mean four different things and tells you which action to take: none of them.
  echo "### DNS — does this name resolve from here? ###"
  local ips
  ips="$(dscacheutil -q host -a name "$host" 2>/dev/null | awk '/ip_address/ {print $2}')"
  [[ -z "$ips" ]] && ips="$(host "$host" 2>/dev/null | awk '/has address/ {print $4}')"
  if [[ -z "$ips" ]]; then
    echo "  !! $host does not resolve from this machine."
    echo
    echo "     This is the most common cause, and it means the hostname is published"
    echo "     only in UMIACS's internal DNS. The proxy may well be listening; your"
    echo "     laptop simply cannot look up the name. Nothing is misconfigured here."
    echo
    echo "     Two ways forward:"
    echo "       a) ask for the PUBLIC name or IP of the fronting proxy, if there is one;"
    echo "       b) use the SSH tunnel (PERSONAS_REMOTE_SERVER.md section 7), which also"
    echo "          needs an /etc/hosts entry so the TLS certificate still matches."
    echo
    echo "     Check from inside UMIACS to confirm the server itself is fine:"
    echo "       ssh <you>@nexusmc2.umiacs.umd.edu \\"
    echo "         'curl -sS -m8 -o /dev/null -w \"%{http_code}\\n\" https://$host/'"
    return 1
  fi
  echo "  resolves to: $ips"

  # A private (RFC 1918) address is the single most likely answer when a university
  # hands you an internal hostname, and it is NOT a firewall problem: packets to
  # 10/8, 172.16/12 or 192.168/16 are never routed across the public internet, so no
  # amount of opening ports makes the name reachable from a laptop off-campus.
  # Worth saying explicitly, because every other symptom (timeout, no route to host)
  # looks identical to a blocked port.
  for ip in $ips; do
    case "$ip" in
      10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*)
        echo
        echo "  !! $ip is a PRIVATE address (RFC 1918)."
        echo "     It is not routable from the public internet. This hostname is the"
        echo "     server's INTERNAL name, so the public fronting proxy must be a"
        echo "     different address. Nothing you can change locally will reach it."
        echo
        echo "     Ask for ONE of:"
        echo "       * the public hostname / IP of the fronting proxy, or"
        echo "       * a host inside UMIACS that can route to $ip, to tunnel through"
        echo
        echo "     Beware: if your own LAN uses this range, pointing a client at this"
        echo "     name can reach an unrelated device on your network."
        return 1
        ;;
    esac
  done

  echo
  echo "### TCP — is anything listening on 443? ###"
  if ! nc -z -G 6 "$host" 443 2>/dev/null; then
    echo "  !! nothing accepted a TCP connection on $host:443 within 6s."
    echo "     DNS worked, so the name is fine. Either the proxy is not running, or a"
    echo "     firewall is dropping traffic from outside the UMIACS network."
    return 1
  fi
  echo "  port 443 is open"

  echo
  echo "### TLS — who terminates it, and is the cert trusted by this Mac? ###"
  if ! openssl s_client -connect "$host:443" -servername "$host" </dev/null 2>/dev/null \
      | openssl x509 -noout -issuer -subject -dates 2>/dev/null; then
    echo "  !! TCP connected but the TLS handshake failed."
    echo "     Something is listening on 443 that is not speaking TLS — e.g. the"
    echo "     cleartext connector exposed directly, with no terminating proxy."
    return 1
  fi
  echo
  echo "  verify chain against the system trust store:"
  if echo | openssl s_client -connect "$host:443" -servername "$host" -verify_return_error >/dev/null 2>&1; then
    echo "    OK — publicly trusted. Leave certificateAuthority OUT of the config."
  else
    echo "    NOT trusted by default. You will need that CA's PEM in"
    echo "    certificateAuthority, and NOTHING else will work until you do."
  fi

  echo
  echo "### chat API — can we open a registration session? ###"
  local out
  out="$(curl -sS -m 10 -X POST "https://$host/v1/verification/session" \
          -H 'content-type: application/json' \
          -d '{"number":"+12025551598"}' 2>&1)"
  if [[ "$out" == *'"id"'* ]]; then
    echo "  OK — session created:"
    echo "    ${out:0:120}"
  else
    echo "  !! no session. Response was:"
    echo "    ${out:0:300}"
    echo "     The chat server is not answering through the proxy."
    return 1
  fi

  echo
  echo "### storage-service — needed for GroupV2 (creating the demo group) ###"
  local code
  code="$(curl -s -m 10 -o /dev/null -w '%{http_code}' "https://$host/v1/storage")"
  case "$code" in
    405|401|403|422) echo "  OK — something is answering /v1/storage (HTTP $code)" ;;
    404) echo "  !! HTTP 404 — the proxy is NOT path-routing /v1/storage* to the"
         echo "     storage-service. GroupV2 create/fetch will fail and you will not be"
         echo "     able to make a group. Ask for /v1/groups*, /v2/groups* and"
         echo "     /v1/storage* to be routed to the storage-service port." ;;
    *)   echo "  ?? HTTP $code — unexpected; worth asking about" ;;
  esac

  echo
  echo "### NOT probeable from here, but ask your admin ###"
  echo "  * Is MinIO (or an S3 endpoint) running for the paged KEM prekey store?"
  echo "    Without it, PUT /v2/keys hangs ~90s and registration dies with"
  echo "    'HTTPError -1', showing a device-link QR screen. This exact failure has"
  echo "    already cost days once."
  echo "  * Do serverPublicParams / serverTrustRoots match that deployment?"
}

# ---------------------------------------------------------------------------
# Write the remote config, preserving the parameters we cannot derive.
# ---------------------------------------------------------------------------
go_remote() {
  local host="$1"
  [[ -f "$CFG" ]] || die "no $CFG to convert — run personas-demo-setup.sh first"

  # Keep the laptop config recoverable. Never overwrite an existing backup: the first
  # one is the real local config; a second run would otherwise save the REMOTE config
  # over it and lose the thing we are protecting.
  if [[ -f "$BACKUP" ]]; then
    echo "note: keeping existing backup at $(basename "$BACKUP")"
  else
    cp "$CFG" "$BACKUP" && echo "backed up local config -> $(basename "$BACKUP")"
  fi

  python3 - "$CFG" "$host" <<'PY'
import json, sys
cfg_path, host = sys.argv[1], sys.argv[2]
with open(cfg_path) as f:
    cfg = json.load(f)

base = f"https://{host}"
cfg["serverUrl"] = base
cfg["storageUrl"] = base
# All three CDN slots go to the same proxy: the test server stands in for every CDN.
cfg["cdn"] = {"0": base, "2": base, "3": base}

# certificateAuthority is passed to Node as `ca`, which REPLACES the trust store rather
# than adding to it. With a self-signed test CA in place, a publicly-signed endpoint is
# rejected — so for a proxy with a real cert this key must be absent, not merely wrong.
removed_ca = cfg.pop("certificateAuthority", None) is not None

with open(cfg_path, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")

print(f"  serverUrl / storageUrl / cdn -> {base}")
if removed_ca:
    print("  removed certificateAuthority (proxy terminates TLS with its own cert)")
print(f"  carried over serverPublicParams ({len(cfg.get('serverPublicParams',''))} chars)")
print(f"  carried over serverTrustRoots  ({len(cfg.get('serverTrustRoots',[]))} entry/entries)")
PY

  cat <<EOF

CONFIRM THESE TWO WITH WHOEVER DEPLOYED THE SERVER:

  serverPublicParams and serverTrustRoots were carried over from your LOCAL
  server. They are properties of the deployment. If the remote was built from a
  different checkout, group operations will be rejected with errors that point
  nowhere near the cause.

  Have them run, in the CryptoPersonas checkout on the VM:
    grep -rhoE 'AAp8[A-Za-z0-9+/=]*' . | head -1     # serverPublicParams
    grep -rn serverTrustRoots -r .                   # trust root(s)

Next:
  ./scripts/personas-remote-setup.sh --probe $host
  ./scripts/personas-run.sh alice --reset
EOF
}

go_local() {
  [[ -f "$BACKUP" ]] || die "no backup at $BACKUP — nothing to restore"
  cp "$BACKUP" "$CFG" && echo "restored the laptop config from $(basename "$BACKUP")"
  echo "remember to start the local backend again: chat server, storage-service,"
  echo "tls-proxy.sh up, and minio.sh up (all four, or registration will hang)"
}

case "${1:-}" in
  --remote) [[ -n "${2:-}" ]] || die "usage: $0 --remote <host>"; go_remote "$2" ;;
  --local)  go_local ;;
  --probe)  [[ -n "${2:-}" ]] || die "usage: $0 --probe <host>"; probe "$2" ;;
  *) sed -n '3,22p' "$0"; exit 2 ;;
esac
