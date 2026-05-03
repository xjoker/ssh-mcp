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
if grep -rE 'autoApprove' examples/ 2>/dev/null \
   | grep -E '(ssh_exec|sftp_op|ssh_group_exec|tunnel|session_send|ssh_quick_setup)' ; then
  echo "S-10 violation: autoApprove on destructive tool in examples/"
  fail=1
fi

[ "$fail" -eq 0 ] && echo "check-no-insecure: ok"
exit "$fail"
