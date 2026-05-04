#!/usr/bin/env bash
# install.sh — user-level installer for mcp-ssh-bridge (macOS / Linux).
#
# Default install location is ~/.local/bin — no sudo required. The MCP
# binary is just a stdio process spawned by your AI client; it does not
# need /usr/local/bin or root.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/xjoker/ssh-mcp/main/scripts/install.sh | bash
#   bash scripts/install.sh                 # from a local checkout
#
# Env vars:
#   PREFIX        install destination (default: $HOME/.local/bin)
#   BRANCH        git branch to clone when fetching from network (default: main)
#   REPO_URL      git URL (default: https://github.com/xjoker/ssh-mcp.git)
#   SKIP_BUILD=1  if the source tree is already built, just install the binary

set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/xjoker/ssh-mcp.git}"
BRANCH="${BRANCH:-main}"
PREFIX="${PREFIX:-$HOME/.local/bin}"

log()  { printf '\033[36m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[install]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[install]\033[0m %s\n' "$*" >&2; exit 1; }

# 1. Ensure PREFIX exists and is writable. We never escalate; if PREFIX is
#    a system path the user picked, we fail loudly so they know to drop
#    sudo or set PREFIX explicitly.
mkdir -p "$PREFIX" 2>/dev/null || fail "cannot create $PREFIX (set PREFIX=... to a writable directory)"
[ -w "$PREFIX" ] || fail "$PREFIX is not writable. Set PREFIX=... or rerun with appropriate permissions."

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

# 4. Install (user-level, no sudo).
DEST="$PREFIX/mcp-ssh-bridge"
log "installing → $DEST"
install -m 0755 "$BIN" "$DEST"

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
log ""
log "register with your AI client (use the official CLI, not file-editing):"
log "  claude mcp add --transport stdio --scope user ssh-bridge -- $DEST"
log "  codex mcp add ssh-bridge -- $DEST"
