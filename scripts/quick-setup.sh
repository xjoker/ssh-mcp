#!/usr/bin/env bash
# quick-setup.sh — interactive wizard that takes a fresh install through to
# a working MCP entry in three or four prompts.
#
# It is non-destructive: every step asks before writing, and ssh_quick_setup
# entries are routed through `mcp-ssh-bridge config add-server` so the
# resulting file passes config validation before anything is renamed into place.
#
# Usage:
#   bash scripts/quick-setup.sh

set -euo pipefail

BIN="${MCP_SSH_BRIDGE_BIN:-mcp-ssh-bridge}"
command -v "$BIN" >/dev/null 2>&1 || {
  if [ -x "./bin/mcp-ssh-bridge" ]; then
    BIN="$(pwd)/bin/mcp-ssh-bridge"
  else
    echo "quick-setup: '$BIN' not on PATH. Run scripts/install.sh first." >&2
    exit 1
  fi
}

ask() {
  # ask <prompt> <default> [VAR_NAME]
  local prompt="$1" default="${2:-}" var="${3:-REPLY}"
  local hint=""
  [ -n "$default" ] && hint=" [$default]"
  printf '%s%s: ' "$prompt" "$hint" >&2
  local input
  IFS= read -r input || true
  if [ -z "$input" ] && [ -n "$default" ]; then
    input="$default"
  fi
  printf -v "$var" '%s' "$input"
}

echo "━━ mcp-ssh-bridge quick-setup ━━"
echo

# 1. Init config if missing.
CFG_PATH=""
if "$BIN" config validate >/dev/null 2>&1; then
  echo "✓ config exists and validates"
else
  echo "→ initializing default config (no servers yet)"
  "$BIN" config init
fi

# 2. Add a server interactively.
ask "Server name (lowercase, [a-z0-9_-])"            "prod"   NAME
ask "Host (IP or DNS)"                                ""       HOST
[ -z "$HOST" ] && { echo "host required, aborting." >&2; exit 1; }
ask "User"                                            "$USER"  USER_IN
ask "Port"                                            "22"     PORT
ask "Auth (agent / key / password)"                   "agent"  AUTH

ADD_ARGS=( --name "$NAME" --host "$HOST" --user "$USER_IN" --port "$PORT" --auth "$AUTH" )

case "$AUTH" in
  agent)
    ;;
  key)
    ask "Private key path" "$HOME/.ssh/id_ed25519" KEYPATH
    ADD_ARGS+=( --key-path "$KEYPATH" )
    ;;
  password)
    echo
    echo "We will store the password in your OS keychain (never in the config file)."
    echo "After this script finishes, you'll be prompted to run one keychain command."
    ;;
  *)
    echo "auth must be agent|key|password" >&2
    exit 1
    ;;
esac

ask "Tags (comma-separated, optional)" "" TAGS
[ -n "$TAGS" ] && ADD_ARGS+=( --tags "$TAGS" )

ask "Description (optional)" "" DESC
[ -n "$DESC" ] && ADD_ARGS+=( --description "$DESC" )

echo
echo "→ writing entry"
"$BIN" config add-server "${ADD_ARGS[@]}"

# 3. Trust the host key (optional).
echo
ask "Trust the host key now? (y/N)" "n" TRUST
if [ "$TRUST" = "y" ] || [ "$TRUST" = "Y" ]; then
  "$BIN" trust "$NAME" || echo "  (trust failed — you can retry later with 'mcp-ssh-bridge trust $NAME')"
fi

# 4. Pick MCP client to install for.
echo
echo "Which MCP client?"
echo "  1) claude-desktop"
echo "  2) claude-code"
echo "  3) codex"
echo "  4) skip"
ask "Choose" "1" CHOICE
case "$CHOICE" in
  1) "$BIN" install claude-desktop ;;
  2) "$BIN" install claude-code ;;
  3) "$BIN" install codex ;;
  *) echo "  (skipped MCP install — run 'mcp-ssh-bridge install <target>' later)" ;;
esac

echo
echo "✓ done."
if [ "$AUTH" = "password" ]; then
  echo
  echo "Reminder: store the password in keychain BEFORE first connection:"
  echo "  $BIN auth set-keychain mcp-ssh-bridge ssh-password:$NAME"
fi
echo
echo "Validate any time with:"
echo "  $BIN config validate"
