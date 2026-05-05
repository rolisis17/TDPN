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
forbidden_tracked_path_pattern='^(\.codex|User/|bin/|data/|deploy/\.env|deploy/data/|deploy/tls/)'

fail=0
umask 077
hits_tmp="$(mktemp "${TMPDIR:-/tmp}/security_secret_guard_hits.XXXXXX")"
trap 'rm -f "$hits_tmp" 2>/dev/null || true' EXIT

echo "[security-secret-guard] scanning tracked files for secret patterns and forbidden runtime artifacts"

while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  if [[ "$path" =~ $forbidden_tracked_path_pattern ]]; then
    echo "[security-secret-guard] forbidden tracked runtime/local artifact: $path"
    fail=1
  fi
done < <(git ls-files)

if tree_paths="$(git write-tree 2>/dev/null)"; then
  while IFS= read -r path; do
    [[ -z "$path" ]] && continue
    if [[ "$path" =~ $forbidden_tracked_path_pattern ]]; then
      echo "[security-secret-guard] forbidden runtime/local artifact in pending commit tree: $path"
      fail=1
    fi
  done < <(git ls-tree -r --name-only "$tree_paths" 2>/dev/null || true)
fi

while IFS= read -r path; do
  [[ -z "$path" ]] && continue

  # Flag live-looking invite keys in tracked content.
  if grep -nE "$invite_pattern" -- "$path" 2>/dev/null | grep -v 'inv-REDACTED' >"$hits_tmp"; then
    while IFS= read -r hit; do
      echo "$path:$hit"
    done <"$hits_tmp"
    fail=1
  fi

  # Flag PEM private key blocks in tracked content.
  if grep -nE "$private_key_pattern" -- "$path" 2>/dev/null >"$hits_tmp"; then
    while IFS= read -r hit; do
      echo "$path:$hit"
    done <"$hits_tmp"
    fail=1
  fi
done < <(git ls-files)

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
