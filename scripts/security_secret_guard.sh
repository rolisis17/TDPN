#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v git >/dev/null 2>&1; then
  echo "missing dependency: git"
  exit 2
fi

invite_pattern='inv-[0-9a-f]{12,}'
private_key_pattern='BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY'

fail=0
umask 077
hits_tmp="$(mktemp "${TMPDIR:-/tmp}/security_secret_guard_hits.XXXXXX")"
trap 'rm -f "$hits_tmp" 2>/dev/null || true' EXIT

echo "[security-secret-guard] scanning tracked docs/deploy files for secret patterns"

while IFS= read -r path; do
  [[ -z "$path" ]] && continue

  # Flag live-looking invite keys in tracked docs/deploy content.
  if grep -nE "$invite_pattern" -- "$path" 2>/dev/null | grep -v 'inv-REDACTED' >"$hits_tmp"; then
    while IFS= read -r hit; do
      echo "$path:$hit"
    done <"$hits_tmp"
    fail=1
  fi

  # Flag PEM private key blocks in tracked docs/deploy content.
  if grep -nE "$private_key_pattern" -- "$path" 2>/dev/null >"$hits_tmp"; then
    while IFS= read -r hit; do
      echo "$path:$hit"
    done <"$hits_tmp"
    fail=1
  fi
done < <(git ls-files 'docs/**' 'deploy/**')

# Fail on tracked private key artifacts.
tracked_key_files="$(git ls-files deploy | grep -E '\.key$' | grep -Ev '\.pub$' || true)"
if [[ -n "$tracked_key_files" ]]; then
  echo "[security-secret-guard] tracked private key files detected:"
  printf '%s\n' "$tracked_key_files"
  fail=1
fi

if (( fail != 0 )); then
  echo "[security-secret-guard] FAIL: secret-like material found"
  exit 1
fi

echo "[security-secret-guard] PASS"
