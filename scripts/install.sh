#!/usr/bin/env bash
# install.sh — one-shot installer for mcp-ssh-bridge.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/xjoker/mcp-ssh-bridge/main/scripts/install.sh | bash
#   bash scripts/install.sh                 # from a local checkout
#
# Env vars:
#   PREFIX        install destination (default: /usr/local/bin, falls back to ~/.local/bin)
#   BRANCH        git branch to clone when fetching from network (default: main)
#   REPO_URL      git URL (default: https://github.com/xjoker/mcp-ssh-bridge.git)
#   SKIP_BUILD=1  if the source tree is already built, just install the binary

set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/xjoker/mcp-ssh-bridge.git}"
BRANCH="${BRANCH:-main}"
PREFIX="${PREFIX:-/usr/local/bin}"

log()  { printf '\033[36m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[install]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[install]\033[0m %s\n' "$*" >&2; exit 1; }

# 1. Pick install prefix that's actually writable. Fall back to ~/.local/bin.
if [ ! -d "$PREFIX" ] || [ ! -w "$PREFIX" ]; then
  if [ -w "$(dirname "$PREFIX")" ]; then
    sudo_required=1
  else
    PREFIX="$HOME/.local/bin"
    mkdir -p "$PREFIX"
    sudo_required=0
  fi
else
  sudo_required=0
fi

# 2. Locate (or fetch) the source tree.
if [ -f "go.mod" ] && [ -d "cmd/mcp-ssh-bridge" ]; then
  log "using local source tree: $(pwd)"
  SRC="$(pwd)"
  cleanup_src=0
else
  command -v git >/dev/null 2>&1 || fail "git not found; install git first"
  SRC="$(mktemp -d)"
  log "cloning $REPO_URL@$BRANCH → $SRC"
  git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$SRC" >/dev/null
  cleanup_src=1
fi

# 3. Build (unless caller provides a prebuilt binary).
if [ "${SKIP_BUILD:-0}" != "1" ]; then
  command -v go >/dev/null 2>&1 || fail "go not found; install Go 1.22+ from https://go.dev/dl/"
  log "building..."
  ( cd "$SRC" && go build -trimpath -o bin/mcp-ssh-bridge ./cmd/mcp-ssh-bridge )
fi

BIN="$SRC/bin/mcp-ssh-bridge"
[ -x "$BIN" ] || fail "binary missing: $BIN (set SKIP_BUILD=0 to rebuild)"

# 4. Install.
DEST="$PREFIX/mcp-ssh-bridge"
if [ "$sudo_required" = "1" ]; then
  log "installing → $DEST (sudo)"
  sudo install -m 0755 "$BIN" "$DEST"
else
  log "installing → $DEST"
  install -m 0755 "$BIN" "$DEST"
fi

# 5. Cleanup tempdir if we cloned.
if [ "$cleanup_src" = "1" ]; then
  rm -rf "$SRC"
fi

# 6. PATH hint when ~/.local/bin isn't on PATH yet.
case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *) warn "$PREFIX is not in PATH — add 'export PATH=\"$PREFIX:\$PATH\"' to your shell profile";;
esac

log "done."
log ""
log "next steps:"
log "  $DEST config init"
log "  $DEST config add-server prod --host example.com --user alice --auth agent"
log "  $DEST install claude-desktop    # or claude-code / codex"
