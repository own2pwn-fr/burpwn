#!/bin/sh
# burpwn installer — works both piped (`curl … | sh`) and from a checkout.
#
#   curl -fsSL https://raw.githubusercontent.com/own2pwn-fr/burpwn/main/install.sh | sh
#
# Behaviour (first match wins):
#   1. --from-source / BURPWN_FROM_SOURCE=1   → build from source (cargo).
#   2. a local release build (target/release/burpwn next to this script) → install it.
#   3. download the prebuilt binary for this arch from the latest GitHub release.
#   4. fallback: `cargo install --git` if a download isn't available.
#
# Env: PREFIX (default ~/.local → installs to $PREFIX/bin), BURPWN_VERSION (tag, default latest).
# Linux-only: burpwn needs user/network namespaces + nftables + bubblewrap at RUNTIME.
set -eu

REPO="own2pwn-fr/burpwn"
PREFIX="${PREFIX:-$HOME/.local}"
BIN_DIR="$PREFIX/bin"
VERSION="${BURPWN_VERSION:-latest}"
FROM_SOURCE="${BURPWN_FROM_SOURCE:-0}"
[ "${1:-}" = "--from-source" ] && FROM_SOURCE=1
WANT_HOOKS=0
[ "${1:-}" = "--hooks" ] && WANT_HOOKS=1

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

[ "$(uname -s)" = "Linux" ] || die "burpwn is Linux-only (user/network namespaces + nftables + bubblewrap)."

case "$(uname -m)" in
  x86_64|amd64)   TARGET="x86_64-unknown-linux-gnu" ;;
  aarch64|arm64)  TARGET="aarch64-unknown-linux-gnu" ;;
  *)              TARGET="" ;; # unknown arch → force source build
esac

fetch() { # fetch URL OUTFILE
  if have curl; then curl -fsSL "$1" -o "$2"
  elif have wget; then wget -qO "$2" "$1"
  else return 1; fi
}

build_from_source() {
  have cargo || die "cargo not found — install Rust from https://rustup.rs, or use a release arch."
  if [ -f "Cargo.toml" ] && grep -q 'name = "burpwn"' Cargo.toml 2>/dev/null; then
    say "Building from the local checkout…"
    cargo build --release --bin burpwn
    mkdir -p "$BIN_DIR"; install -m 0755 target/release/burpwn "$BIN_DIR/burpwn"
  else
    say "Installing from git via cargo (this compiles burpwn)…"
    cargo install --git "https://github.com/$REPO" --root "$PREFIX" burpwn
  fi
}

download_release() {
  [ -n "$TARGET" ] || return 1
  base="https://github.com/$REPO/releases"
  if [ "$VERSION" = "latest" ]; then url="$base/latest/download/burpwn-$TARGET.tar.gz"
  else url="$base/download/$VERSION/burpwn-$TARGET.tar.gz"; fi
  tmp="$(mktemp -d)"
  say "Downloading prebuilt burpwn ($TARGET, $VERSION)…"
  fetch "$url" "$tmp/b.tar.gz" || { rm -rf "$tmp"; return 1; }
  if fetch "$url.sha256" "$tmp/b.sha256" 2>/dev/null && have sha256sum; then
    ( cd "$tmp" && sed "s| .*| b.tar.gz|" b.sha256 | sha256sum -c - >/dev/null 2>&1 ) \
      || warn "checksum verification skipped/failed"
  fi
  tar -xzf "$tmp/b.tar.gz" -C "$tmp"
  mkdir -p "$BIN_DIR"; install -m 0755 "$tmp/burpwn-$TARGET/burpwn" "$BIN_DIR/burpwn"
  rm -rf "$tmp"
}

# --- choose an install path -------------------------------------------------
if [ "$FROM_SOURCE" = "1" ]; then
  build_from_source
elif [ -x "target/release/burpwn" ]; then
  say "Installing the local release build…"
  mkdir -p "$BIN_DIR"; install -m 0755 target/release/burpwn "$BIN_DIR/burpwn"
elif download_release; then
  :
else
  warn "no prebuilt binary available for this arch/version — falling back to a source build."
  build_from_source
fi

BURPWN="$BIN_DIR/burpwn"
[ -x "$BURPWN" ] || die "installation failed: $BURPWN not found."

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) warn "$BIN_DIR is not on your PATH — add:  export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac

say "Generating the MITM CA…"; "$BURPWN" ca init || true
say "Checking rootless prerequisites…"
if ! "$BURPWN" doctor; then
  echo "  Fedora/RHEL:   sudo dnf install bubblewrap nftables iproute"
  echo "  Debian/Ubuntu: sudo apt install bubblewrap nftables iproute2"
fi
[ "$WANT_HOOKS" = "1" ] && { say "Installing the global shell hook…"; "$BURPWN" init --global || true; }

cat <<EOF

burpwn installed to $BURPWN

  burpwn session new --name engagement-1
  burpwn exec -- curl -s https://target.example/   # sandboxed + captured + decrypted
  burpwn req list                                  # browse captured flows
  burpwn init --agent claude                       # wire the auto-capture hook into your agent
  burpwn mcp                                        # MCP server over stdio

EOF
