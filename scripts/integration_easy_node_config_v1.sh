#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in rg mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CFG="$TMP_DIR/easy_mode_config_v1.conf"
SHOW_LOG="$TMP_DIR/config_show.log"

assert_kv() {
  local file="$1"
  local key="$2"
  local expected="$3"
  local context="$4"
  if ! rg -q -- "^${key}=${expected}\$" "$file"; then
    echo "$context: expected ${key}=${expected}"
    cat "$file"
    exit 1
  fi
}

assert_key_unique() {
  local file="$1"
  local key="$2"
  local context="$3"
  local count
  count="$(rg -c -- "^${key}=" "$file" || true)"
  if [[ "$count" != "1" ]]; then
    echo "$context: expected exactly one ${key}= entry (observed=$count)"
    cat "$file"
    exit 1
  fi
}

assert_server_federation_contract() {
  local file="$1"
  local context="$2"
  assert_kv "$file" "SIMPLE_SERVER_FEDERATION_WAIT" "1" "$context"
  assert_kv "$file" "SIMPLE_SERVER_FEDERATION_READY_TIMEOUT_SEC" "90" "$context"
  assert_kv "$file" "SIMPLE_SERVER_FEDERATION_POLL_SEC" "5" "$context"
  assert_key_unique "$file" "SIMPLE_SERVER_FEDERATION_WAIT" "$context"
  assert_key_unique "$file" "SIMPLE_SERVER_FEDERATION_READY_TIMEOUT_SEC" "$context"
  assert_key_unique "$file" "SIMPLE_SERVER_FEDERATION_POLL_SEC" "$context"
}

assert_auto_update_contract() {
  local file="$1"
  local context="$2"
  assert_kv "$file" "SIMPLE_AUTO_UPDATE" "0" "$context"
  assert_kv "$file" "SIMPLE_AUTO_UPDATE_REMOTE" "origin" "$context"
  assert_kv "$file" "SIMPLE_AUTO_UPDATE_ALLOW_DIRTY" "0" "$context"
  assert_kv "$file" "SIMPLE_AUTO_UPDATE_SHOW_STATUS" "1" "$context"
  assert_key_unique "$file" "SIMPLE_AUTO_UPDATE" "$context"
  assert_key_unique "$file" "SIMPLE_AUTO_UPDATE_REMOTE" "$context"
  assert_key_unique "$file" "SIMPLE_AUTO_UPDATE_ALLOW_DIRTY" "$context"
  assert_key_unique "$file" "SIMPLE_AUTO_UPDATE_SHOW_STATUS" "$context"
  assert_key_unique "$file" "SIMPLE_AUTO_UPDATE_COMMANDS" "$context"
}

assert_profile_defaults() {
  local file="$1"
  local expected_profile="$2"
  local expected_prod_default="$3"
  local context="$4"
  assert_kv "$file" "SIMPLE_CLIENT_PROFILE_DEFAULT" "$expected_profile" "$context"
  assert_kv "$file" "SIMPLE_CLIENT_PROD_PROFILE_DEFAULT" "$expected_prod_default" "$context"
  assert_key_unique "$file" "SIMPLE_CLIENT_PROFILE_DEFAULT" "$context"
  assert_key_unique "$file" "SIMPLE_CLIENT_PROD_PROFILE_DEFAULT" "$context"
}

run_profile_case() {
  local file="$1"
  local input_profile="$2"
  local expected_profile="$3"
  local expected_prod_default="$4"
  local context="$5"
  ./scripts/easy_node.sh config-v1-set-profile --path "$file" --path-profile "$input_profile" >/dev/null
  assert_profile_defaults "$file" "$expected_profile" "$expected_prod_default" "$context"
  assert_server_federation_contract "$file" "$context"
}

echo "[easy-node-config-v1] init writes template defaults and federation contract"
./scripts/easy_node.sh config-v1-init --path "$CFG" --force 1 >/dev/null
if [[ ! -f "$CFG" ]]; then
  echo "config-v1-init did not write config file: $CFG"
  exit 1
fi
assert_kv "$CFG" "EASY_MODE_CONFIG_VERSION" "1" "config-v1-init"
assert_profile_defaults "$CFG" "2hop" "auto" "config-v1-init"
assert_server_federation_contract "$CFG" "config-v1-init"
assert_auto_update_contract "$CFG" "config-v1-init"

echo "[easy-node-config-v1] show prints path and file content"
./scripts/easy_node.sh config-v1-show --path "$CFG" >"$SHOW_LOG"
if ! rg -q -- "^config_v1_path: $CFG\$" "$SHOW_LOG"; then
  echo "config-v1-show missing config_v1_path header"
  cat "$SHOW_LOG"
  exit 1
fi
if ! rg -q -- '^SIMPLE_SERVER_FEDERATION_WAIT=1$' "$SHOW_LOG" || \
   ! rg -q -- '^SIMPLE_SERVER_FEDERATION_READY_TIMEOUT_SEC=90$' "$SHOW_LOG" || \
   ! rg -q -- '^SIMPLE_SERVER_FEDERATION_POLL_SEC=5$' "$SHOW_LOG"; then
  echo "config-v1-show output missing federation default contract keys"
  cat "$SHOW_LOG"
  exit 1
fi
if ! rg -q -- '^SIMPLE_AUTO_UPDATE=0$' "$SHOW_LOG" || \
   ! rg -q -- '^SIMPLE_AUTO_UPDATE_REMOTE=origin$' "$SHOW_LOG" || \
   ! rg -q -- '^SIMPLE_AUTO_UPDATE_ALLOW_DIRTY=0$' "$SHOW_LOG" || \
   ! rg -q -- '^SIMPLE_AUTO_UPDATE_SHOW_STATUS=1$' "$SHOW_LOG"; then
  echo "config-v1-show output missing auto-update contract keys"
  cat "$SHOW_LOG"
  exit 1
fi

echo "[easy-node-config-v1] canonical path-profile mapping defaults"
run_profile_case "$CFG" "1hop" "1hop" "0" "config-v1-set-profile 1hop"
run_profile_case "$CFG" "2hop" "2hop" "auto" "config-v1-set-profile 2hop"
run_profile_case "$CFG" "3hop" "3hop" "auto" "config-v1-set-profile 3hop"
assert_auto_update_contract "$CFG" "config-v1-set-profile canonical mapping"

echo "[easy-node-config-v1] alias path-profile mapping defaults"
run_profile_case "$CFG" "speed-1hop" "1hop" "0" "config-v1-set-profile speed-1hop"
run_profile_case "$CFG" "speed" "2hop" "auto" "config-v1-set-profile speed"
run_profile_case "$CFG" "balanced" "2hop" "auto" "config-v1-set-profile balanced"
run_profile_case "$CFG" "private" "3hop" "auto" "config-v1-set-profile private"
run_profile_case "$CFG" "privacy" "3hop" "auto" "config-v1-set-profile privacy"
assert_auto_update_contract "$CFG" "config-v1-set-profile alias mapping"

echo "[easy-node-config-v1] set-profile auto-creates template and preserves federation defaults"
AUTO_CFG="$TMP_DIR/auto_created_config_v1.conf"
run_profile_case "$AUTO_CFG" "3hop" "3hop" "auto" "config-v1-set-profile auto-create"
assert_kv "$AUTO_CFG" "EASY_MODE_CONFIG_VERSION" "1" "config-v1-set-profile auto-create"
assert_auto_update_contract "$AUTO_CFG" "config-v1-set-profile auto-create"

echo "[easy-node-config-v1] invalid profile input fails with deterministic guidance"
INVALID_LOG="$TMP_DIR/config_v1_invalid.log"
if ./scripts/easy_node.sh config-v1-set-profile --path "$CFG" --path-profile "invalid-profile" >"$INVALID_LOG" 2>&1; then
  echo "config-v1-set-profile accepted invalid profile unexpectedly"
  cat "$INVALID_LOG"
  exit 1
fi
if ! rg -q -- 'config-v1-set-profile requires --path-profile 1hop\|2hop\|3hop' "$INVALID_LOG"; then
  echo "config-v1-set-profile invalid-profile did not emit expected contract guidance"
  cat "$INVALID_LOG"
  exit 1
fi

echo "easy-node config-v1 integration check ok"
