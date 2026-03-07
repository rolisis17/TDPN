#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

AUTH_ENV="$ROOT_DIR/deploy/.env.easy.server"
MODE_FILE="$ROOT_DIR/deploy/data/easy_node_server_mode.conf"
backup_env=""
backup_mode=""

env_value() {
  local file="$1"
  local key="$2"
  awk -F= -v k="$key" '$1==k{print substr($0,index($0,"=")+1); exit}' "$file"
}

cleanup() {
  if [[ -n "$backup_env" && -f "$backup_env" ]]; then
    cp "$backup_env" "$AUTH_ENV"
    rm -f "$backup_env"
  else
    rm -f "$AUTH_ENV"
  fi
  if [[ -n "$backup_mode" && -f "$backup_mode" ]]; then
    cp "$backup_mode" "$MODE_FILE"
    rm -f "$backup_mode"
  else
    rm -f "$MODE_FILE"
  fi
}
trap cleanup EXIT

mkdir -p "$ROOT_DIR/deploy/data"
if [[ -f "$AUTH_ENV" ]]; then
  backup_env="$(mktemp)"
  cp "$AUTH_ENV" "$backup_env"
fi
if [[ -f "$MODE_FILE" ]]; then
  backup_mode="$(mktemp)"
  cp "$MODE_FILE" "$backup_mode"
fi

tls_dir="$(mktemp -d)"
"$ROOT_DIR/scripts/bootstrap_mtls.sh" --out-dir "$tls_dir/tls" --days 365 >/dev/null

cat >"$AUTH_ENV" <<EOF_ENV
PROD_STRICT_MODE=1
BETA_STRICT_MODE=1
MTLS_ENABLE=1
DIRECTORY_PUBLIC_URL=https://127.0.0.1:8081
ENTRY_URL_PUBLIC=https://127.0.0.1:8083
EXIT_CONTROL_URL_PUBLIC=https://127.0.0.1:8084
EASY_NODE_MTLS_CA_FILE_LOCAL=$tls_dir/tls/ca.crt
EASY_NODE_MTLS_CLIENT_CERT_FILE_LOCAL=$tls_dir/tls/client.crt
EASY_NODE_MTLS_CLIENT_KEY_FILE_LOCAL=$tls_dir/tls/client.key
MTLS_CERT_FILE=$tls_dir/tls/node.crt
MTLS_KEY_FILE=$tls_dir/tls/node.key
ISSUER_ADMIN_REQUIRE_SIGNED=1
ISSUER_ADMIN_ALLOW_TOKEN=0
DIRECTORY_ADMIN_TOKEN=prod-directory-admin-token-1234567890
ENTRY_PUZZLE_SECRET=prod-entry-puzzle-secret-1234567890
EOF_ENV
chmod 600 "$AUTH_ENV" 2>/dev/null || true

cat >"$MODE_FILE" <<'EOF_MODE'
EASY_NODE_SERVER_MODE=authority
EOF_MODE

./scripts/easy_node.sh admin-signing-rotate --restart-issuer 0 --key-history 2 >/tmp/integration_prod_preflight_rotate.log 2>&1
./scripts/easy_node.sh admin-signing-status >/tmp/integration_prod_preflight_status.log 2>&1
./scripts/easy_node.sh prod-preflight --days-min 0 >/tmp/integration_prod_preflight_ok.log 2>&1

first_key_id="$(env_value "$AUTH_ENV" "ISSUER_ADMIN_SIGNING_KEY_ID")"
./scripts/easy_node.sh admin-signing-rotate --restart-issuer 0 --key-history 2 >/tmp/integration_prod_preflight_rotate2.log 2>&1
second_key_id="$(env_value "$AUTH_ENV" "ISSUER_ADMIN_SIGNING_KEY_ID")"
if [[ -z "$first_key_id" || -z "$second_key_id" || "$first_key_id" == "$second_key_id" ]]; then
  echo "expected signer key id to rotate"
  cat /tmp/integration_prod_preflight_rotate.log /tmp/integration_prod_preflight_rotate2.log 2>/dev/null || true
  exit 1
fi
signers_file="$ROOT_DIR/deploy/data/issuer/issuer_admin_signers.txt"
if [[ ! -f "$signers_file" ]]; then
  echo "missing signer file after rotate: $signers_file"
  exit 1
fi
if ! rg -q "^${first_key_id}=" "$signers_file"; then
  echo "expected previous key to remain in signer history"
  cat "$signers_file"
  exit 1
fi
if ! rg -q "^${second_key_id}=" "$signers_file"; then
  echo "expected new key in signer history"
  cat "$signers_file"
  exit 1
fi
line_count="$(awk 'NF > 0 && $0 !~ /^#/ {n++} END {print n + 0}' "$signers_file")"
if [[ "$line_count" != "2" ]]; then
  echo "expected signer history size=2, got $line_count"
  cat "$signers_file"
  exit 1
fi
./scripts/easy_node.sh admin-signing-status >/tmp/integration_prod_preflight_status2.log 2>&1

if ./scripts/easy_node.sh prod-preflight --days-min 0 --check-live 1 --timeout-sec 1 >/tmp/integration_prod_preflight_live_fail.log 2>&1; then
  echo "expected live preflight to fail when endpoints are down"
  cat /tmp/integration_prod_preflight_live_fail.log
  exit 1
fi
if ! rg -q "live endpoint unreachable" /tmp/integration_prod_preflight_live_fail.log; then
  echo "missing expected live endpoint failure signal"
  cat /tmp/integration_prod_preflight_live_fail.log
  exit 1
fi

sed -i -E 's/^MTLS_ENABLE=.*/MTLS_ENABLE=0/' "$AUTH_ENV"
if ./scripts/easy_node.sh prod-preflight --days-min 0 >/tmp/integration_prod_preflight_fail.log 2>&1; then
  echo "expected prod-preflight to fail when MTLS_ENABLE=0"
  cat /tmp/integration_prod_preflight_fail.log
  exit 1
fi
if ! rg -q "MTLS_ENABLE must be 1" /tmp/integration_prod_preflight_fail.log; then
  echo "missing expected MTLS failure signal in prod-preflight output"
  cat /tmp/integration_prod_preflight_fail.log
  exit 1
fi

sed -i -E 's/^MTLS_ENABLE=.*/MTLS_ENABLE=1/' "$AUTH_ENV"
sed -i -E 's/^ENTRY_PUZZLE_SECRET=.*/ENTRY_PUZZLE_SECRET=entry-secret-default/' "$AUTH_ENV"
if ./scripts/easy_node.sh prod-preflight --days-min 0 >/tmp/integration_prod_preflight_secret_fail.log 2>&1; then
  echo "expected prod-preflight to fail with default ENTRY_PUZZLE_SECRET"
  cat /tmp/integration_prod_preflight_secret_fail.log
  exit 1
fi
if ! rg -q "ENTRY_PUZZLE_SECRET must be set, non-default, and len>=16" /tmp/integration_prod_preflight_secret_fail.log; then
  echo "missing expected entry puzzle secret failure signal in prod-preflight output"
  cat /tmp/integration_prod_preflight_secret_fail.log
  exit 1
fi

sed -i -E 's/^ENTRY_PUZZLE_SECRET=.*/ENTRY_PUZZLE_SECRET=prod-entry-puzzle-secret-1234567890/' "$AUTH_ENV"
chmod 644 "$tls_dir/tls/client.key" 2>/dev/null || true
if ./scripts/easy_node.sh prod-preflight --days-min 0 >/tmp/integration_prod_preflight_perm_fail.log 2>&1; then
  echo "expected prod-preflight to fail when private key permissions are too open"
  cat /tmp/integration_prod_preflight_perm_fail.log
  exit 1
fi
if ! rg -q "private file permissions too open" /tmp/integration_prod_preflight_perm_fail.log; then
  echo "missing expected private file permission failure signal in prod-preflight output"
  cat /tmp/integration_prod_preflight_perm_fail.log
  exit 1
fi

echo "prod preflight/admin-signing integration check ok"
