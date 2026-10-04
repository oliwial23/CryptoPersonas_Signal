#!/usr/bin/env bash
# Rebuild the personas-engine napi addon from the CryptoPersonas_Signal Rust
# workspace and copy the platform binary into this package.
#
# Requires the pinned nightly toolchain (rust-toolchain.toml in the Rust workspace)
# and the workspace checked out next to Signal-Desktop. N-API is ABI-stable, so the
# release binary loads under both Node and Electron.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

# The workspace is identified by its MARKER FILE, never by folder name — the name is
# the least reliable thing about it. Previously this script assumed exactly one layout
# (Rust workspace as a sibling of the Signal checkout) and died if that was wrong, even
# when the workspace was sitting one folder over.
is_workspace() { [[ -f "$1/crates/personas-node/Cargo.toml" ]]; }

RUST_DIR=""
if [[ -n "${PERSONAS_RUST_DIR:-}" ]]; then
  # An explicit setting is honoured as-is, so a deliberate override still wins; it is
  # only validated so the failure names the real problem.
  RUST_DIR="$PERSONAS_RUST_DIR"
else
  for candidate in \
    "$REPO/../CryptoPersonas_Signal" \
    "$REPO/../../CryptoPersonas_Signal" \
    "$REPO/../../oliwia_test_repo/CryptoPersonas_Signal" \
    "$HOME/Documents/Anon_Group_Chat/Signal_Integration_Code_2026/oliwia_test_repo/CryptoPersonas_Signal" \
    "$HOME/Repos/personas2/CryptoPersonas_Signal"; do
    if is_workspace "$candidate"; then RUST_DIR="$(cd "$candidate" && pwd)"; break; fi
  done
fi

if [[ -z "$RUST_DIR" ]] || ! is_workspace "$RUST_DIR"; then
  {
    if [[ -n "${PERSONAS_RUST_DIR:-}" ]]; then
      echo "PERSONAS_RUST_DIR is set to:"
      echo "    $PERSONAS_RUST_DIR"
      echo "but there is no crates/personas-node/Cargo.toml under it."
    else
      echo "Could not find the CryptoPersonas_Signal workspace automatically."
    fi
    echo
    echo "Searching under \$HOME for crates/personas-node ..."
    hits="$(find "$HOME/Documents" "$HOME/Repos" "$HOME/Developer" "$HOME/src" \
              -maxdepth 7 -type d -name personas-node \
              -not -path '*/node_modules/*' -not -path '*/target/*' 2>/dev/null |
            while read -r h; do (cd "$h/../.." && pwd); done | sort -u)"
    if [[ -n "$hits" ]]; then
      echo
      echo "FOUND — re-run with one of these:"
      while read -r h; do
        [[ -z "$h" ]] && continue
        echo "    PERSONAS_RUST_DIR=$h pnpm --filter @signalapp/personas-engine build"
      done <<< "$hits"
    else
      echo "    no match found."
      echo
      echo "The Rust workspace does not appear to be on this machine."
    fi
  } >&2
  exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is not on PATH." >&2
  echo "Install the nightly toolchain pinned in $RUST_DIR/rust-toolchain.toml:" >&2
  echo "    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" >&2
  echo "    source \"\$HOME/.cargo/env\"" >&2
  echo "rustup reads rust-toolchain.toml and installs the pinned nightly on first build." >&2
  exit 1
fi

echo "Building personas-node (release) in $RUST_DIR ..."
( cd "$RUST_DIR" && cargo build -p personas-node --release )

# napi-rs cdylib artifact name -> platform .node
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) TARGET="personas-engine.darwin-arm64.node"; LIB="libpersonas_node.dylib" ;;
  Darwin-x86_64) TARGET="personas-engine.darwin-x64.node"; LIB="libpersonas_node.dylib" ;;
  Linux-x86_64) TARGET="personas-engine.linux-x64.node"; LIB="libpersonas_node.so" ;;
  Linux-aarch64) TARGET="personas-engine.linux-arm64.node"; LIB="libpersonas_node.so" ;;
  *) echo "unsupported platform: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

cp "$RUST_DIR/target/release/$LIB" "$HERE/$TARGET"
echo "Copied -> $HERE/$TARGET"
