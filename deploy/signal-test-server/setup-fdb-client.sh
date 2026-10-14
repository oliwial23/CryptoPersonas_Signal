#!/usr/bin/env bash
# Stage the FoundationDB C client library (libfdb_c) that the Signal-Server test
# harness needs on the *host* JVM. See README.md for the full story.
#
# The macOS FoundationDB .pkg *installer wrapper* demands Rosetta on Apple Silicon
# even though its payload is native arm64, so we do NOT run the installer — we
# download the pkg, expand it in userland, and copy out just libfdb_c.dylib. The
# boot script then points fdb-java at it with -DFDB_LIBRARY_PATH_FDB_C, so nothing
# is installed system-wide (no sudo, no Rosetta).
#
# On Linux we download the release's standalone libfdb_c.<arch>.so the same way: the
# foundationdb-clients package would put it on the loader path, but installing it needs
# root, which shared VMs (e.g. UMIACS signalserver00) don't give us.
set -euo pipefail

FDB_VERSION="${FDB_VERSION:-7.3.68}"   # must match Signal-Server pom.xml <foundationdb.version>
HERE="$(cd "$(dirname "$0")" && pwd)"
DEST="$HERE/.local"
mkdir -p "$DEST"

os="$(uname -s)"; arch="$(uname -m)"

if [ "$os" = "Linux" ]; then
  OUT="$DEST/libfdb_c.so"
  case "$arch" in
    # Same artifact and checksum Signal-Server's pom.xml pins for its own container image
    # (<foundationdb.client-library-sha256>); update both together with FDB_VERSION.
    x86_64)  sha="8c96a1f7ab561cd38e16e4c269c5e50ae0fd8063854e0d72c89339a7ac1b6873" ;;
    aarch64) sha="" ;;
    *) echo "unsupported Linux arch: $arch" >&2; exit 1 ;;
  esac
  if [ -f "$OUT" ]; then
    echo "libfdb_c.so already staged: $OUT"
    exit 0
  fi
  url="https://github.com/apple/foundationdb/releases/download/${FDB_VERSION}/libfdb_c.${arch}.so"
  echo "downloading $url"
  curl -fL -o "$OUT.tmp" "$url"
  if [ -n "$sha" ]; then
    echo "$sha  $OUT.tmp" | sha256sum -c - || { rm -f "$OUT.tmp"; echo "checksum mismatch" >&2; exit 1; }
  fi
  mv "$OUT.tmp" "$OUT"
  echo "OK -> $OUT"
  exit 0
fi

OUT="$DEST/libfdb_c.dylib"

# Idempotent: reuse an existing correct-arch dylib.
if [ -f "$OUT" ] && file "$OUT" | grep -qi "$arch"; then
  echo "libfdb_c.dylib already staged ($arch): $OUT"
  exit 0
fi

case "$arch" in
  arm64)  pkgarch=arm64 ;;
  x86_64) pkgarch=x86_64 ;;
  *) echo "unsupported macOS arch: $arch" >&2; exit 1 ;;
esac

url="https://github.com/apple/foundationdb/releases/download/${FDB_VERSION}/FoundationDB-${FDB_VERSION}_${pkgarch}.pkg"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

echo "downloading $url"
curl -fL -o "$tmp/fdb.pkg" "$url"
echo "expanding in userland (NOT running the installer — its wrapper wants Rosetta)"
pkgutil --expand-full "$tmp/fdb.pkg" "$tmp/x"
cp "$tmp/x/FoundationDB-clients.pkg/Payload/usr/local/lib/libfdb_c.dylib" "$OUT"

file "$OUT"
echo "OK -> $OUT"
