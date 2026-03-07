#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

AUTH_ENV="$ROOT_DIR/deploy/.env.easy.server"
MODE_FILE="$ROOT_DIR/deploy/data/easy_node_server_mode.conf"
backup_env=""
backup_mode=""

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
EOF_ENV

cat >"$MODE_FILE" <<'EOF_MODE'
EASY_NODE_SERVER_MODE=authority
EOF_MODE

./scripts/easy_node.sh admin-signing-rotate --restart-issuer 0 >/tmp/integration_prod_preflight_rotate.log 2>&1
./scripts/easy_node.sh admin-signing-status >/tmp/integration_prod_preflight_status.log 2>&1
./scripts/easy_node.sh prod-preflight --days-min 0 >/tmp/integration_prod_preflight_ok.log 2>&1

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

echo "prod preflight/admin-signing integration check ok"
