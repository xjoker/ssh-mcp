#!/usr/bin/env bash
# install.sh — download pre-built mcp-ssh-bridge binary (macOS / Linux).
#
# No Go, no git, no build tools required.
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
  API="https://api.github.com/repos/$REPO/releases"
  if command -v python3 >/dev/null 2>&1; then
    TAG="$(curl -fsSL "$API" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d[0]['tag_name'] if d else '')" 2>/dev/null || true)"
  else
    TAG="$(curl -fsSL "$API" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/' || true)"
  fi
  [ -n "$TAG" ] || fail "could not determine latest release. Set VERSION=vX.Y.Z or visit https://github.com/$REPO/releases"
fi

# 4. Build asset URL.
ASSET="mcp-ssh-bridge_${os}_${arch}"
URL="https://github.com/$REPO/releases/download/$TAG/$ASSET"

# 5. Ensure PREFIX exists and is writable.
mkdir -p "$PREFIX" 2>/dev/null || fail "cannot create $PREFIX — set PREFIX=... to a writable directory"
[ -w "$PREFIX" ] || fail "$PREFIX is not writable — set PREFIX=... to a writable directory"

# 6. Download binary.
DEST="$PREFIX/mcp-ssh-bridge"
log "downloading $TAG ($os/$arch)..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$URL" -o "$DEST" || fail "download failed: $URL"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$DEST" "$URL" || fail "download failed: $URL"
else
  fail "curl or wget is required to download the binary"
fi
chmod 0755 "$DEST"

# 7. PATH hint when ~/.local/bin is not on PATH.
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
