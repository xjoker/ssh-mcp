#!/usr/bin/env bash
# MCP stdio smoke test: drives the bridge over JSON-RPC and exercises the
# happy path of multiple tools against the docker-compose SSH containers.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

BIN="$ROOT/bin/mcp-ssh-bridge"
CFG="$ROOT/test/integration/config.toml"

[ -x "$BIN" ] || { echo "build first: go build -o bin/mcp-ssh-bridge ./cmd/mcp-ssh-bridge"; exit 1; }

# Build a sequence of MCP messages. Order:
#   1. initialize
#   2. tools/list (sanity)
#   3. tools/call ssh_exec  on test-pwd
#   4. tools/call ssh_exec  on test-key (with cwd)
#   5. tools/call sftp_list on test-key /
#   6. tools/call session_start on test-pwd
#   7. tools/call session_send  echo $$
#   8. tools/call session_close
#   9. tools/call audit_query
req() {
  local id="$1" method="$2" params="$3"
  printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":${id},\"method\":\"${method}\",\"params\":${params}}"
}

note() {
  printf '\n=== %s ===\n' "$1" >&2
}

run_smoke() {
  req 1 initialize '{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.0"}}'
  req 2 tools/list '{}'
  req 3 tools/call '{"name":"ssh_exec","arguments":{"server":"test-pwd","command":"hostname && id -u && uname -s"}}'
  req 4 tools/call '{"name":"ssh_exec","arguments":{"server":"test-key","command":"pwd && ls","cwd":"/tmp"}}'
  req 5 tools/call '{"name":"sftp_list","arguments":{"server":"test-key","path":"/"}}'
  req 6 tools/call '{"name":"session_start","arguments":{"server":"test-pwd"}}'
}

note "Sending phase 1 (initialize / tools/list / 3 ssh+sftp calls / session_start)"
PHASE1=$(run_smoke)

# Run phase1, capture, extract session id, then issue session_send/close.
RESP=$(MCP_SSH_BRIDGE_CONFIG="$CFG" "$BIN" <<<"$PHASE1" 2>/tmp/msb-smoke.stderr || true)

echo "$RESP" | head -100

# Pull session_id from response 6 (last response of phase1)
SID=$(echo "$RESP" | tail -1 | python3 -c '
import json, sys
data = json.loads(sys.stdin.read())
content = data["result"]["content"][0]["text"]
inner = json.loads(content)
print(inner["data"]["session_id"])
' 2>/dev/null || echo "")

note "Captured session_id=$SID"

if [ -n "$SID" ]; then
  PHASE2=$(
    req 1 initialize '{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.0"}}'
    req 7 tools/call "{\"name\":\"session_send\",\"arguments\":{\"session_id\":\"$SID\",\"command\":\"echo PHASE2_MARKER && pwd\"}}"
    req 8 tools/call "{\"name\":\"session_close\",\"arguments\":{\"session_id\":\"$SID\"}}"
    req 9 tools/call '{"name":"audit_query","arguments":{"limit":5}}'
  )
  note "Sending phase 2 (session_send / session_close / audit_query)"
  echo "$PHASE2" | MCP_SSH_BRIDGE_CONFIG="$CFG" "$BIN" 2>>/tmp/msb-smoke.stderr | tail -10
fi

note "Stderr tail:"
tail -20 /tmp/msb-smoke.stderr 2>/dev/null || true
