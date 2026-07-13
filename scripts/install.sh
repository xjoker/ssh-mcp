#!/usr/bin/env bash
# install.sh — download pre-built ssh-mcp binary (macOS / Linux).
#
# No Go, no git, no build tools required.
#
# SHA256 verification: automatically verifies binary integrity using checksums.sha256
# from the GitHub release. Fails with non-zero exit if checksum mismatch detected.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/xjoker/ssh-mcp/main/scripts/install.sh | bash
#   bash scripts/install.sh                 # from a local checkout
#
# Env vars:
#   PREFIX    install destination (default: $HOME/.local/bin)
#   VERSION   specific release tag to install (default: latest)

set -euo pipefail

REPO="xjoker/ssh-mcp"
PREFIX="${PREFIX:-$HOME/.local/bin}"

log()  { printf '\033[36m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[install]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[install]\033[0m %s\n' "$*" >&2; exit 1; }

# 1. Detect OS.
case "$(uname -s)" in
  Linux)  os="linux"  ;;
  Darwin) os="darwin" ;;
  *)      fail "Unsupported OS: $(uname -s). Download manually from https://github.com/$REPO/releases" ;;
esac

# 2. Detect architecture.
case "$(uname -m)" in
  x86_64|amd64)   arch="amd64" ;;
  aarch64|arm64)  arch="arm64" ;;
  *)               fail "Unsupported architecture: $(uname -m). Download manually from https://github.com/$REPO/releases" ;;
esac

# 3. Resolve release tag.
TAG="${VERSION:-}"
if [ -z "$TAG" ]; then
  log "fetching latest release..."
  # /releases/latest returns only stable (non-prerelease) releases so users
  # are never accidentally handed a -dev build by the installer.
  API="https://api.github.com/repos/$REPO/releases/latest"
  if command -v python3 >/dev/null 2>&1; then
    TAG="$(curl -fsSL "$API" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('tag_name',''))" 2>/dev/null || true)"
  else
    TAG="$(curl -fsSL "$API" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/' || true)"
  fi
  [ -n "$TAG" ] || fail "could not determine latest release. Set VERSION=vX.Y.Z or visit https://github.com/$REPO/releases"
fi

# 4. Build asset URL.
ASSET="ssh-mcp_${os}_${arch}"
URL="https://github.com/$REPO/releases/download/$TAG/$ASSET"

# 5. Ensure PREFIX exists and is writable.
mkdir -p "$PREFIX" 2>/dev/null || fail "cannot create $PREFIX — set PREFIX=... to a writable directory"
[ -w "$PREFIX" ] || fail "$PREFIX is not writable — set PREFIX=... to a writable directory"

# 6. Download binary to the destination directory without touching the
# existing installation. Keeping the temp file on the same filesystem makes
# the final rename atomic.
DEST="$PREFIX/ssh-mcp"
TMP_BIN=""
CHECKSUM_FILE=""
cleanup() {
  [ -z "${TMP_BIN:-}" ] || rm -f "$TMP_BIN"
  [ -z "${CHECKSUM_FILE:-}" ] || rm -f "$CHECKSUM_FILE"
}
trap cleanup EXIT
TMP_BIN="$(mktemp "$PREFIX/.ssh-mcp-install.XXXXXX")" || fail "failed to create temporary binary in $PREFIX"
CHECKSUM_FILE="$(mktemp)" || fail "failed to create temporary file for checksums"

log "downloading $TAG ($os/$arch)..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$URL" -o "$TMP_BIN" || fail "download failed: $URL"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$TMP_BIN" "$URL" || fail "download failed: $URL"
else
  fail "curl or wget is required to download the binary"
fi

# 7. Verify SHA256 checksum.
log "verifying checksum..."
CHECKSUM_URL="https://github.com/$REPO/releases/download/$TAG/checksums.sha256"

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$CHECKSUM_URL" -o "$CHECKSUM_FILE" || fail "failed to download checksums from $CHECKSUM_URL"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$CHECKSUM_FILE" "$CHECKSUM_URL" || fail "failed to download checksums from $CHECKSUM_URL"
else
  fail "curl or wget is required to download checksums"
fi

EXPECTED_SHA=$(grep " $ASSET$" "$CHECKSUM_FILE" | awk '{print $1}') || true
[ -n "$EXPECTED_SHA" ] || fail "checksum not found for $ASSET in checksums.sha256"

# Calculate actual SHA256 using shasum (macOS) or sha256sum (Linux).
if command -v shasum >/dev/null 2>&1; then
  ACTUAL_SHA=$(shasum -a 256 "$TMP_BIN" | awk '{print $1}')
elif command -v sha256sum >/dev/null 2>&1; then
  ACTUAL_SHA=$(sha256sum "$TMP_BIN" | awk '{print $1}')
else
  fail "shasum or sha256sum is required to verify checksums"
fi

if [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
  fail "checksum mismatch for $ASSET
  expected: $EXPECTED_SHA
  actual:   $ACTUAL_SHA
  The binary may have been corrupted or tampered with. Please try again or visit https://github.com/$REPO/releases"
fi

chmod 0700 "$TMP_BIN"
mv -f "$TMP_BIN" "$DEST" || fail "cannot replace $DEST"
TMP_BIN=""

# 8. PATH hint when ~/.local/bin is not on PATH.
case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *) warn "$PREFIX is not in PATH — add this to your shell profile:"
     warn "  export PATH=\"$PREFIX:\$PATH\""
     ;;
esac

log "installed $TAG → $DEST"
log ""
log "next steps:"
log "  $DEST config init"
log "  $DEST config add-server prod --host example.com --user alice --auth agent"
log ""
log "register with your AI client (use the official CLI, not file-editing):"
log "  claude mcp add --transport stdio --scope user ssh-bridge -- $DEST"
log "  codex  mcp add ssh-bridge -- $DEST"
