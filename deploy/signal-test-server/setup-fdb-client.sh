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
# On Linux there is no such quirk: install the foundationdb-clients package the
# normal way (it drops libfdb_c.so on the default loader path) and skip this script.
set -euo pipefail

FDB_VERSION="${FDB_VERSION:-7.3.68}"   # must match Signal-Server pom.xml <foundationdb.version>
HERE="$(cd "$(dirname "$0")" && pwd)"
DEST="$HERE/.local"
OUT="$DEST/libfdb_c.dylib"
mkdir -p "$DEST"

os="$(uname -s)"; arch="$(uname -m)"

if [ "$os" != "Darwin" ]; then
  echo "This helper is macOS-only. On Linux, install the foundationdb-clients ${FDB_VERSION}"
  echo "package (.deb/.rpm from github.com/apple/foundationdb/releases/tag/${FDB_VERSION});"
  echo "it installs libfdb_c.so on the default loader path and no override is needed."
  exit 0
fi

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
