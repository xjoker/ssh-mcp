#!/usr/bin/env bash
# SDD §14.2 module-boundary enforcement.
# Asserts: dependencies in internal/* flow downward only.
#
# Implementation note: this script avoids bash 4+ features (associative
# arrays via `declare -A`) so it runs on macOS' default /bin/bash 3.2.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# allowlist for internal/<pkg>: <pkg>|<allowed deps space-separated>
# Add new packages here when introduced.
allowlist_for() {
  case "$1" in
    envelope)  echo "" ;;
    safety)    echo "" ;;
    config)    echo "" ;;
    knownhosts) echo "safety" ;;
    auth)      echo "safety config" ;;
    audit)     echo "safety" ;;
    proxy)     echo "" ;;
    # v0.0.6: ssh.proxychain imports internal/proxy (dialer abstractions) and
    # internal/auth (resolve direct-mode SSH proxy creds via CredRef).
    ssh)       echo "safety config auth proxy" ;;
    sftp)      echo "safety" ;;
    session)   echo "ssh safety" ;;
    tunnel)    echo "ssh safety" ;;
    updater)   echo "" ;;
    mcpserver) echo "envelope config auth safety ssh sftp session tunnel audit tools" ;;
    tools)     echo "envelope config auth safety ssh sftp session tunnel audit updater" ;;
    *)         echo "__UNKNOWN__" ;;
  esac
}

mod="$(awk '/^module /{print $2}' go.mod)"
prefix="$mod/internal/"

violations=0

# Iterate through internal/ subdirectories explicitly. Skip any package not
# listed in allowlist_for so the policy stays explicit.
for dir in internal/*/ ; do
  pkg="${dir#internal/}"
  pkg="${pkg%/}"
  allowed="$(allowlist_for "$pkg")"
  if [ "$allowed" = "__UNKNOWN__" ]; then
    echo "check-deps: WARNING package internal/$pkg has no allowlist entry; add it to scripts/check-deps.sh"
    violations=$((violations + 1))
    continue
  fi

  # Collect imports of internal/* found in this package.
  imports="$(grep -rh -E "^\s*\"$prefix" "$dir" --include='*.go' 2>/dev/null \
    | sed -E "s|.*\"$prefix||;s|\".*||;s|/.*||" \
    | sort -u || true)"

  # Pad with surrounding spaces so a substring match is exact-token.
  allowed_tokens=" $allowed "
  for imp in $imports; do
    [ "$imp" = "$pkg" ] && continue
    case "$allowed_tokens" in
      *" $imp "*) ;;  # allowed
      *)
        echo "VIOLATION: internal/$pkg imports internal/$imp (not in allowlist)"
        violations=$((violations + 1))
        ;;
    esac
  done
done

if [ "$violations" -gt 0 ]; then
  echo "check-deps: $violations violation(s)"
  exit 1
fi
echo "check-deps: ok"
