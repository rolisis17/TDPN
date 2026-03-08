#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

MODE_FILE="$ROOT_DIR/deploy/data/easy_node_server_mode.conf"
AUTH_ENV="$ROOT_DIR/deploy/.env.easy.server"
backup_mode=""
backup_env=""

restore() {
  if [[ -n "$backup_mode" && -f "$backup_mode" ]]; then
    cp "$backup_mode" "$MODE_FILE"
    rm -f "$backup_mode"
  else
    rm -f "$MODE_FILE"
  fi
  if [[ -n "$backup_env" && -f "$backup_env" ]]; then
    cp "$backup_env" "$AUTH_ENV"
    rm -f "$backup_env"
  else
    rm -f "$AUTH_ENV"
  fi
}
trap restore EXIT

mkdir -p "$ROOT_DIR/deploy/data"
if [[ -f "$MODE_FILE" ]]; then
  backup_mode="$(mktemp)"
  cp "$MODE_FILE" "$backup_mode"
fi
if [[ -f "$AUTH_ENV" ]]; then
  backup_env="$(mktemp)"
  cp "$AUTH_ENV" "$backup_env"
fi

cat >"$MODE_FILE" <<'EOF_MODE'
EASY_NODE_SERVER_MODE=authority
EOF_MODE

cat >"$AUTH_ENV" <<'EOF_ENV'
ISSUER_ADMIN_REQUIRE_SIGNED=1
ISSUER_ADMIN_ALLOW_TOKEN=0
EOF_ENV

expect_token_block() {
  local label="$1"
  shift
  local out
  out="$("$@" 2>&1 || true)"
  if ! printf '%s\n' "$out" | rg -q "token admin auth is disabled for this authority"; then
    echo "expected token-auth disabled signal for $label"
    echo "$out"
    exit 1
  fi
}

expect_signed_required_on_missing_auth() {
  local label="$1"
  shift
  local out
  out="$("$@" 2>&1 || true)"
  if ! printf '%s\n' "$out" | rg -q "requires signed admin auth"; then
    echo "expected signed-auth-required signal for $label"
    echo "$out"
    exit 1
  fi
}

expect_token_block "invite-generate token path" \
  ./scripts/easy_node.sh invite-generate --issuer-url http://127.0.0.1:1 --admin-token test --count 1

expect_token_block "invite-check token path" \
  ./scripts/easy_node.sh invite-check --issuer-url http://127.0.0.1:1 --admin-token test --key inv-test

expect_token_block "invite-disable token path" \
  ./scripts/easy_node.sh invite-disable --issuer-url http://127.0.0.1:1 --admin-token test --key inv-test

expect_signed_required_on_missing_auth "invite-generate missing auth" \
  ./scripts/easy_node.sh invite-generate --issuer-url http://127.0.0.1:1 --count 1

echo "easy-node invite auth policy integration check ok"
