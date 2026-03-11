#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in git rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

declare -a FAILURES=()

record_failure() {
  local msg="$1"
  FAILURES+=("$msg")
}

print_header() {
  local label="$1"
  echo "[secret-hygiene] $label"
}

check_forbidden_tracked_paths() {
  print_header "checking forbidden tracked runtime artifacts"
  local path
  local forbidden_paths=(
    "deploy/.env.easy.server"
    "deploy/.env.easy.provider"
    "deploy/data/easy_node_identity.conf"
  )
  for path in "${forbidden_paths[@]}"; do
    if git ls-files --error-unmatch "$path" >/dev/null 2>&1; then
      record_failure "forbidden tracked runtime artifact: $path"
    fi
  done

  local deploy_data_path
  while IFS= read -r deploy_data_path; do
    [[ -z "$deploy_data_path" ]] && continue
    record_failure "unexpected tracked deploy/data artifact: $deploy_data_path"
  done < <(git ls-files | rg '^deploy/data/' || true)
}

check_tracked_sensitive_extensions() {
  print_header "checking tracked sensitive key/cert files"
  local file
  while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    record_failure "tracked sensitive file: $file"
  done < <(git ls-files '*.key' '*.pem' '*.p12' '*.pfx' '*.pk8' '*.der' '*.jks' '*.keystore' || true)
}

run_pattern_check() {
  local label="$1"
  local pattern="$2"
  local tmp
  tmp="$(mktemp)"
  if git grep -nI -E -e "$pattern" -- >"$tmp"; then
    print_header "suspicious matches: $label"
    cat "$tmp"
    record_failure "inline secret pattern matched: $label"
  fi
  rm -f "$tmp"
}

check_inline_secret_patterns() {
  print_header "checking high-confidence inline secret patterns"
  run_pattern_check "private key block headers" '-----BEGIN ([A-Z ]+ )?PRIVATE KEY-----'
  run_pattern_check "provider/API token prefixes" '(ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|sk_live_[0-9A-Za-z]{16,}|rk_live_[0-9A-Za-z]{16,})'
  run_pattern_check "JWT-like bearer tokens" 'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
  run_pattern_check "easy-node admin secrets printed in clear text" '(issuer_admin_token|directory_admin_token|entry_puzzle_secret)[[:space:]]*:[[:space:]]*[A-Za-z0-9._-]{16,}'
}

check_forbidden_tracked_paths
check_tracked_sensitive_extensions
check_inline_secret_patterns

if [[ "${#FAILURES[@]}" -gt 0 ]]; then
  print_header "failed"
  printf '%s\n' "${FAILURES[@]}"
  exit 1
fi

print_header "ok"
