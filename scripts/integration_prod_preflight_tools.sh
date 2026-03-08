#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

AUTH_ENV="$ROOT_DIR/deploy/.env.easy.server"
PROVIDER_ENV="$ROOT_DIR/deploy/.env.easy.provider"
MODE_FILE="$ROOT_DIR/deploy/data/easy_node_server_mode.conf"
backup_env=""
backup_provider=""
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
  if [[ -n "$backup_provider" && -f "$backup_provider" ]]; then
    cp "$backup_provider" "$PROVIDER_ENV"
    rm -f "$backup_provider"
  else
    rm -f "$PROVIDER_ENV"
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
if [[ -f "$PROVIDER_ENV" ]]; then
  backup_provider="$(mktemp)"
  cp "$PROVIDER_ENV" "$backup_provider"
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
DIRECTORY_PUBLIC_URL=https://203.0.113.10:8081
ENTRY_URL_PUBLIC=https://203.0.113.10:8083
EXIT_CONTROL_URL_PUBLIC=https://203.0.113.10:8084
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

echo "ISSUER_ADMIN_TOKEN=legacy-admin-token-1234567890" >>"$AUTH_ENV"
if ./scripts/easy_node.sh prod-preflight --days-min 0 >/tmp/integration_prod_preflight_token_fail.log 2>&1; then
  echo "expected prod-preflight to fail when ISSUER_ADMIN_TOKEN is set while token auth is disabled"
  cat /tmp/integration_prod_preflight_token_fail.log
  exit 1
fi
if ! rg -q "ISSUER_ADMIN_TOKEN must be empty when ISSUER_ADMIN_ALLOW_TOKEN=0" /tmp/integration_prod_preflight_token_fail.log; then
  echo "missing expected issuer admin token disablement failure signal in prod-preflight output"
  cat /tmp/integration_prod_preflight_token_fail.log
  exit 1
fi
sed -i -E 's/^ISSUER_ADMIN_TOKEN=.*/ISSUER_ADMIN_TOKEN=/' "$AUTH_ENV"

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

sed -i -E 's#^DIRECTORY_PUBLIC_URL=.*#DIRECTORY_PUBLIC_URL=https://127.0.0.1:8081#' "$AUTH_ENV"
if ./scripts/easy_node.sh prod-preflight --days-min 0 >/tmp/integration_prod_preflight_public_host_fail.log 2>&1; then
  echo "expected prod-preflight to fail with private/loopback public URL host"
  cat /tmp/integration_prod_preflight_public_host_fail.log
  exit 1
fi
if ! rg -q "public URL host must not be private/loopback in prod profile" /tmp/integration_prod_preflight_public_host_fail.log; then
  echo "missing expected public host private/loopback failure signal in prod-preflight output"
  cat /tmp/integration_prod_preflight_public_host_fail.log
  exit 1
fi
sed -i -E 's#^DIRECTORY_PUBLIC_URL=.*#DIRECTORY_PUBLIC_URL=https://203.0.113.10:8081#' "$AUTH_ENV"

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
if rg -q '^ENTRY_PUZZLE_DIFFICULTY=' "$AUTH_ENV"; then
  sed -i -E 's/^ENTRY_PUZZLE_DIFFICULTY=.*/ENTRY_PUZZLE_DIFFICULTY=0/' "$AUTH_ENV"
else
  echo "ENTRY_PUZZLE_DIFFICULTY=0" >>"$AUTH_ENV"
fi
if ./scripts/easy_node.sh prod-preflight --days-min 0 >/tmp/integration_prod_preflight_puzzle_fail.log 2>&1; then
  echo "expected prod-preflight to fail with ENTRY_PUZZLE_DIFFICULTY=0"
  cat /tmp/integration_prod_preflight_puzzle_fail.log
  exit 1
fi
if ! rg -q "ENTRY_PUZZLE_DIFFICULTY must be >0 in prod profile" /tmp/integration_prod_preflight_puzzle_fail.log; then
  echo "missing expected entry puzzle difficulty failure signal in prod-preflight output"
  cat /tmp/integration_prod_preflight_puzzle_fail.log
  exit 1
fi
sed -i -E 's/^ENTRY_PUZZLE_DIFFICULTY=.*/ENTRY_PUZZLE_DIFFICULTY=1/' "$AUTH_ENV"

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
chmod 600 "$tls_dir/tls/client.key" 2>/dev/null || true

write_provider_env_file() {
  local core_issuer="$1"
  local admin_token="${2:-}"
  local sign_key_id="${3:-}"
  cat >"$PROVIDER_ENV" <<EOF_PROVIDER
PROD_STRICT_MODE=1
BETA_STRICT_MODE=1
MTLS_ENABLE=1
DIRECTORY_PUBLIC_URL=https://203.0.113.20:8081
ENTRY_URL_PUBLIC=https://203.0.113.20:8083
EXIT_CONTROL_URL_PUBLIC=https://203.0.113.20:8084
EASY_NODE_MTLS_CA_FILE_LOCAL=$tls_dir/tls/ca.crt
EASY_NODE_MTLS_CLIENT_CERT_FILE_LOCAL=$tls_dir/tls/client.crt
EASY_NODE_MTLS_CLIENT_KEY_FILE_LOCAL=$tls_dir/tls/client.key
MTLS_CERT_FILE=$tls_dir/tls/node.crt
MTLS_KEY_FILE=$tls_dir/tls/node.key
DIRECTORY_ADMIN_TOKEN=prod-provider-directory-admin-token-1234567890
ENTRY_PUZZLE_SECRET=prod-provider-entry-puzzle-secret-1234567890
CORE_ISSUER_URL=$core_issuer
ISSUER_ADMIN_TOKEN=$admin_token
ISSUER_ADMIN_SIGNING_KEY_ID=$sign_key_id
EOF_PROVIDER
  chmod 600 "$PROVIDER_ENV" 2>/dev/null || true
}

cat >"$MODE_FILE" <<'EOF_MODE_PROVIDER'
EASY_NODE_SERVER_MODE=provider
EOF_MODE_PROVIDER

write_provider_env_file "https://issuer.example:8082"
./scripts/easy_node.sh prod-preflight --days-min 0 >/tmp/integration_prod_preflight_provider_ok.log 2>&1

write_provider_env_file "https://127.0.0.1:8082"
if ./scripts/easy_node.sh prod-preflight --days-min 0 >/tmp/integration_prod_preflight_provider_issuer_private_host_fail.log 2>&1; then
  echo "expected provider prod-preflight to fail with private/loopback CORE_ISSUER_URL host"
  cat /tmp/integration_prod_preflight_provider_issuer_private_host_fail.log
  exit 1
fi
if ! rg -q "provider CORE_ISSUER_URL host must not be private/loopback" /tmp/integration_prod_preflight_provider_issuer_private_host_fail.log; then
  echo "missing expected provider CORE_ISSUER_URL private host failure signal"
  cat /tmp/integration_prod_preflight_provider_issuer_private_host_fail.log
  exit 1
fi

write_provider_env_file "http://issuer.example:8082"
if ./scripts/easy_node.sh prod-preflight --days-min 0 >/tmp/integration_prod_preflight_provider_issuer_scheme_fail.log 2>&1; then
  echo "expected provider prod-preflight to fail with non-HTTPS CORE_ISSUER_URL"
  cat /tmp/integration_prod_preflight_provider_issuer_scheme_fail.log
  exit 1
fi
if ! rg -q "provider CORE_ISSUER_URL must be HTTPS" /tmp/integration_prod_preflight_provider_issuer_scheme_fail.log; then
  echo "missing expected provider CORE_ISSUER_URL HTTPS failure signal"
  cat /tmp/integration_prod_preflight_provider_issuer_scheme_fail.log
  exit 1
fi

write_provider_env_file "https://issuer.example:8082" "legacy-provider-admin-token"
if ./scripts/easy_node.sh prod-preflight --days-min 0 >/tmp/integration_prod_preflight_provider_token_fail.log 2>&1; then
  echo "expected provider prod-preflight to fail when ISSUER_ADMIN_TOKEN is persisted"
  cat /tmp/integration_prod_preflight_provider_token_fail.log
  exit 1
fi
if ! rg -q "provider env must not persist ISSUER_ADMIN_TOKEN" /tmp/integration_prod_preflight_provider_token_fail.log; then
  echo "missing expected provider token persistence failure signal"
  cat /tmp/integration_prod_preflight_provider_token_fail.log
  exit 1
fi

write_provider_env_file "https://issuer.example:8082" "" "provider-signer-id"
if ./scripts/easy_node.sh prod-preflight --days-min 0 >/tmp/integration_prod_preflight_provider_signer_fail.log 2>&1; then
  echo "expected provider prod-preflight to fail when signing material is persisted"
  cat /tmp/integration_prod_preflight_provider_signer_fail.log
  exit 1
fi
if ! rg -q "provider env must not include issuer admin signing material" /tmp/integration_prod_preflight_provider_signer_fail.log; then
  echo "missing expected provider signer material failure signal"
  cat /tmp/integration_prod_preflight_provider_signer_fail.log
  exit 1
fi

echo "prod preflight/admin-signing integration check ok"
