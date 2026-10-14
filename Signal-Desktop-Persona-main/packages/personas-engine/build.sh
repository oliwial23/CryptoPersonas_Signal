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

# REPLACE THE BINARY VIA A NEW INODE, NEVER BY OVERWRITING IN PLACE.
#
# This used to be a plain `cp` onto the existing path, and on Apple Silicon that is a
# trap. macOS caches code-signing information per INODE: once the kernel has loaded a
# signed Mach-O, it remembers that inode's cdhash. `cp` opens the destination and
# truncates it, keeping the same inode, so the new contents no longer hash to the
# remembered value. The next load is rejected as an invalid code signature and the
# process is SIGKILLed — exit code 9, "zsh: killed", with no error message anywhere,
# because the kill happens in dyld before any of the module's code runs.
#
# The symptoms are maximally misleading: the file is a structurally perfect, correctly
# signed Mach-O (`file` is happy, the LC_CODE_SIGNATURE blob is intact and covers the
# whole file), so every check on the artifact passes. It reads exactly like an
# out-of-memory kill or a bad build, and it cost a long detour down both of those.
#
# Writing to a temporary name and `mv`-ing over the target allocates a fresh inode, so
# there is no stale cache to collide with. The ad-hoc re-sign is belt and braces: it
# guarantees a signature matching these exact bytes even if the toolchain's own signing
# step is skipped or a later step touches the file.
TMP="$HERE/.$TARGET.tmp.$$"
cleanup() { rm -f "$TMP"; }
trap cleanup EXIT

cp "$RUST_DIR/target/release/$LIB" "$TMP"

if [[ "$(uname -s)" == "Darwin" ]] && command -v codesign >/dev/null 2>&1; then
  # `-` is the ad-hoc identity: no certificate needed, which is all arm64 requires for
  # a locally built library.
  codesign --force --sign - "$TMP" 2>/dev/null ||
    echo "warning: ad-hoc codesign failed; if the addon is killed at load, that is why" >&2
fi

# `mv` within the same directory is atomic and gives the destination a new inode.
mv -f "$TMP" "$HERE/$TARGET"
trap - EXIT

echo "Copied -> $HERE/$TARGET"

# Prove it LOADS, here, rather than discovering it in Electron.
#
# A signature problem kills the process instead of raising an error, so the only honest
# check is to actually load the module in a child process and look at how it exited. 137
# is 128+9 (SIGKILL) — the signature case — and is called out separately because its
# cause and its fix are nothing like a normal exception.
if command -v node >/dev/null 2>&1; then
  if node -e "require('$HERE/index.cjs')" 2>/dev/null; then
    echo "Load check  -> OK (the addon loads under Node; Electron uses the same ABI)"
  else
    status=$?
    if [[ "$status" == "137" ]]; then
      echo "Load check  -> KILLED (SIGKILL) by the OS before any code ran." >&2
      echo "  On macOS this almost always means the code signature was rejected." >&2
      echo "  Try: codesign --force --sign - '$HERE/$TARGET'" >&2
    else
      echo "Load check  -> FAILED (exit $status). Run this to see the error:" >&2
      echo "    node -e \"require('$HERE/index.cjs')\"" >&2
    fi
    exit 1
  fi
fi
