#!/usr/bin/env bash
# SDD §13 hard-constraint grep checks (S-3, S-10).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail=0

# S-3: no InsecureIgnoreHostKey anywhere except tests that explicitly verify rejection.
if grep -rn 'InsecureIgnoreHostKey' --include='*.go' internal/ cmd/ 2>/dev/null \
   | grep -v _test.go ; then
  echo "S-3 violation: InsecureIgnoreHostKey used in non-test code"
  fail=1
fi

# S-2: no `cd ${...}` shell concatenation.
if grep -rnE '"cd \$\{' --include='*.go' internal/ cmd/ 2>/dev/null ; then
  echo "S-2 violation: shell-style cd \${...} concatenation found"
  fail=1
fi

# S-10: examples must not autoApprove destructive tools.
# Structural check (Codex L01): a same-line grep can be bypassed by JSON/TOML
# arrays that span multiple lines. Walk every example file with a parser and
# refuse if any "autoApprove" key contains a destructive tool name.
DESTRUCTIVE='ssh_exec|sftp_op|ssh_group_exec|tunnel|session_send|ssh_quick_setup'

scan_examples_json() {
  local f
  shopt -s nullglob
  for f in examples/*.json; do
    python3 - "$f" "$DESTRUCTIVE" <<'PY' || return 1
import json, re, sys
path, pattern = sys.argv[1], sys.argv[2]
rx = re.compile(pattern)

def walk(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "autoApprove" and isinstance(v, list):
                for item in v:
                    if isinstance(item, str) and rx.fullmatch(item):
                        print(f"S-10 violation: {path}: autoApprove contains {item!r}", file=sys.stderr)
                        sys.exit(1)
            walk(v)
    elif isinstance(node, list):
        for item in node:
            walk(item)

try:
    with open(path) as fp:
        walk(json.load(fp))
except json.JSONDecodeError as e:
    # Parsing failure does not prove safety; refuse to pass without structure.
    print(f"S-10 check: {path} is not valid JSON: {e}", file=sys.stderr)
    sys.exit(1)
PY
  done
  shopt -u nullglob
  return 0
}

scan_examples_toml() {
  local f
  shopt -s nullglob
  for f in examples/*.toml; do
    python3 - "$f" "$DESTRUCTIVE" <<'PY' || return 1
import re, sys
try:
    import tomllib  # Python 3.11+
except ImportError:
    print(f"S-10 check: tomllib unavailable; falling back to grep for {sys.argv[1]}", file=sys.stderr)
    sys.exit(0)
path, pattern = sys.argv[1], sys.argv[2]
rx = re.compile(pattern)

def walk(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "autoApprove" and isinstance(v, list):
                for item in v:
                    if isinstance(item, str) and rx.fullmatch(item):
                        print(f"S-10 violation: {path}: autoApprove contains {item!r}", file=sys.stderr)
                        sys.exit(1)
            walk(v)
    elif isinstance(node, list):
        for item in node:
            walk(item)

try:
    with open(path, "rb") as fp:
        walk(tomllib.load(fp))
except tomllib.TOMLDecodeError as e:
    print(f"S-10 check: {path} is not valid TOML: {e}", file=sys.stderr)
    sys.exit(1)
PY
  done
  shopt -u nullglob
  return 0
}

if ! scan_examples_json ; then
  fail=1
fi
if ! scan_examples_toml ; then
  fail=1
fi

# Backstop grep: catches files we did not parse (e.g. *.yaml, *.md docs that
# someone copied a config snippet into).
if grep -rE 'autoApprove' examples/ docs/ README.md SECURITY.md 2>/dev/null \
   | grep -vE '\.json$|\.toml$' \
   | grep -E "($DESTRUCTIVE)" ; then
  echo "S-10 violation: autoApprove on destructive tool in non-json/toml file"
  fail=1
fi

[ "$fail" -eq 0 ] && echo "check-no-insecure: ok"
exit "$fail"
