#!/usr/bin/env bash
# SDD §14.2 module-boundary enforcement.
# Asserts: dependencies in internal/* flow downward only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# allowlist[pkg] = "space-separated allowed internal/* deps"
declare -A allowlist=(
  [envelope]=""
  [safety]=""
  [config]=""
  [auth]="safety config"
  [audit]="safety"
  [ssh]="safety config"
  [sftp]="safety"
  [session]="ssh safety"
  [tunnel]="ssh safety"
  [mcpserver]="envelope config auth safety ssh sftp session tunnel audit tools"
  [tools]="envelope config auth safety ssh sftp session tunnel audit"
)

mod="$(awk '/^module /{print $2}' go.mod)"
prefix="$mod/internal/"

violations=0
for pkg in "${!allowlist[@]}"; do
  dir="internal/$pkg"
  [ -d "$dir" ] || continue
  # collect imports under internal/*
  imports=$(grep -rh -E "^\s*\"$prefix" "$dir" --include='*.go' 2>/dev/null \
    | sed -E "s|.*\"$prefix||;s|\".*||;s|/.*||" | sort -u || true)
  allowed=" ${allowlist[$pkg]} "
  for imp in $imports; do
    if [[ "$imp" == "$pkg" ]]; then continue; fi
    if [[ "$allowed" != *" $imp "* ]]; then
      echo "VIOLATION: internal/$pkg imports internal/$imp (not in allowlist)"
      violations=$((violations+1))
    fi
  done
done

if [ "$violations" -gt 0 ]; then
  echo "check-deps: $violations violation(s)"
  exit 1
fi
echo "check-deps: ok"
