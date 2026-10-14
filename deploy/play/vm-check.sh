#!/usr/bin/env bash
# Read-only readiness report for signalserver00. Changes nothing; paste the output back.
#
#   ssh signalserver00.umiacs.umd.edu 'bash -s' < deploy/play/vm-check.sh
set -u

section() { printf '\n== %s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

section "host"
uname -srm
grep -E '^(PRETTY_NAME)=' /etc/os-release 2>/dev/null
free -g | sed -n '1,2p'
nproc
df -h / /srv/signalserver00 2>/dev/null | sed 1d

section "privileges"
if sudo -n true 2>/dev/null; then echo "sudo: yes (passwordless)"
elif sudo -l -n >/dev/null 2>&1; then echo "sudo: yes (needs password)"
else echo "sudo: no / needs password (try 'sudo -v' interactively)"; fi
id

section "container runtime"
for b in docker podman; do have $b && echo "$b: $($b --version 2>/dev/null)"; done
have docker && { docker compose version 2>/dev/null || echo "docker compose: missing"; }
have docker && { docker info >/dev/null 2>&1 && echo "docker daemon: reachable" || echo "docker daemon: NOT reachable as $(whoami)"; }
docker ps --format '{{.Names}}\t{{.Status}}' 2>/dev/null || podman ps --format '{{.Names}}\t{{.Status}}' 2>/dev/null

section "listening ports (8080 chat, 8090 storage, 8443 proxy, 9110 minio, 9100 node_exporter)"
(ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null) | grep -E ':(8080|8081|8090|8443|9100|9110)\b' || echo "none of them"

section "backend health"
curl -s -m 3 -o /dev/null -w 'chat :8081/ping      %{http_code}\n' http://127.0.0.1:8081/ping
curl -s -m 3 -o /dev/null -w 'proxy :8443/v1/config %{http_code}\n' http://127.0.0.1:8443/v1/config
curl -s -m 3 -o /dev/null -w 'minio :9110 live      %{http_code}\n' http://127.0.0.1:9110/minio/health/live

section "public endpoint, from the VM (hairpin through the LB)"
curl -s -m 8 -o /dev/null -w 'https://signalserver.umiacs.umd.edu/ %{http_code}\n' https://signalserver.umiacs.umd.edu/

section "workspace"
WORK="${WORK:-/srv/signalserver00/personas}"
ls "$WORK/repos" 2>/dev/null
for r in CryptoPersonas_Signal Signal-Server storage-service; do
  [ -d "$WORK/repos/$r/.git" ] && printf '%-22s %s\n' "$r" "$(git -C "$WORK/repos/$r" log -1 --format='%h %cd' --date=short)"
done
java -version 2>&1 | head -1
