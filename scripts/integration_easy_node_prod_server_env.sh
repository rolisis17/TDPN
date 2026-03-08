#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash go jq rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

AUTH_ENV="$ROOT_DIR/deploy/.env.easy.server"
PROVIDER_ENV="$ROOT_DIR/deploy/.env.easy.provider"
MODE_FILE="$ROOT_DIR/deploy/data/easy_node_server_mode.conf"
IDENTITY_FILE="$ROOT_DIR/deploy/data/easy_node_identity.conf"
TLS_DIR="$ROOT_DIR/deploy/tls"
ISSUER_ADMIN_DIR="$ROOT_DIR/deploy/data/issuer"
HOSTS_FILE="$ROOT_DIR/data/easy_mode_hosts.conf"
TMP_DIR="$(mktemp -d)"
TMP_BIN="$TMP_DIR/bin"
mkdir -p "$TMP_BIN"

backup_file() {
  local src="$1"
  local name="$2"
  if [[ -f "$src" ]]; then
    cp "$src" "$TMP_DIR/${name}.bak"
  fi
}

backup_dir() {
  local src="$1"
  local name="$2"
  if [[ -d "$src" ]]; then
    cp -R "$src" "$TMP_DIR/${name}.bakdir"
  fi
}

restore_file() {
  local dst="$1"
  local name="$2"
  if [[ -f "$TMP_DIR/${name}.bak" ]]; then
    cp "$TMP_DIR/${name}.bak" "$dst"
  else
    rm -f "$dst"
  fi
}

restore_dir() {
  local dst="$1"
  local name="$2"
  rm -rf "$dst"
  if [[ -d "$TMP_DIR/${name}.bakdir" ]]; then
    cp -R "$TMP_DIR/${name}.bakdir" "$dst"
  fi
}

cleanup() {
  restore_file "$AUTH_ENV" "auth_env"
  restore_file "$PROVIDER_ENV" "provider_env"
  restore_file "$MODE_FILE" "mode_file"
  restore_file "$IDENTITY_FILE" "identity_file"
  restore_file "$HOSTS_FILE" "hosts_file"
  restore_dir "$TLS_DIR" "tls_dir"
  restore_dir "$ISSUER_ADMIN_DIR" "issuer_admin_dir"
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

backup_file "$AUTH_ENV" "auth_env"
backup_file "$PROVIDER_ENV" "provider_env"
backup_file "$MODE_FILE" "mode_file"
backup_file "$IDENTITY_FILE" "identity_file"
backup_file "$HOSTS_FILE" "hosts_file"
backup_dir "$TLS_DIR" "tls_dir"
backup_dir "$ISSUER_ADMIN_DIR" "issuer_admin_dir"

cat >"$TMP_BIN/docker" <<'EOF_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "compose" && "${2:-}" == "version" ]]; then
  echo "Docker Compose version vtest"
  exit 0
fi
if [[ "${1:-}" == "compose" ]]; then
  exit 0
fi
if [[ "${1:-}" == "--version" ]]; then
  echo "Docker version test"
  exit 0
fi
if [[ "${1:-}" == "info" ]]; then
  exit 0
fi
exit 0
EOF_DOCKER

cat >"$TMP_BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
echo "{}"
EOF_CURL

chmod +x "$TMP_BIN/docker" "$TMP_BIN/curl"

PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
./scripts/easy_node.sh server-up \
  --mode authority \
  --public-host 203.0.113.10 \
  --beta-profile 1 \
  --prod-profile 1 >/tmp/integration_easy_node_prod_server_env.log 2>&1

env_value() {
  local file="$1"
  local key="$2"
  awk -F= -v k="$key" '$1==k{print substr($0,index($0,"=")+1); exit}' "$file"
}

require_eq() {
  local got="$1"
  local want="$2"
  local label="$3"
  if [[ "$got" != "$want" ]]; then
    echo "unexpected $label: got='$got' want='$want'"
    cat /tmp/integration_easy_node_prod_server_env.log
    exit 1
  fi
}

require_nonempty() {
  local got="$1"
  local label="$2"
  if [[ -z "$got" ]]; then
    echo "missing expected $label"
    cat /tmp/integration_easy_node_prod_server_env.log
    exit 1
  fi
}

if [[ ! -f "$AUTH_ENV" ]]; then
  echo "missing authority env file after server-up: $AUTH_ENV"
  cat /tmp/integration_easy_node_prod_server_env.log
  exit 1
fi

require_eq "$(env_value "$AUTH_ENV" "PROD_STRICT_MODE")" "1" "PROD_STRICT_MODE"
require_eq "$(env_value "$AUTH_ENV" "BETA_STRICT_MODE")" "1" "BETA_STRICT_MODE"
require_eq "$(env_value "$AUTH_ENV" "ISSUER_ADMIN_REQUIRE_SIGNED")" "1" "ISSUER_ADMIN_REQUIRE_SIGNED"
require_eq "$(env_value "$AUTH_ENV" "ISSUER_ADMIN_ALLOW_TOKEN")" "0" "ISSUER_ADMIN_ALLOW_TOKEN"
require_eq "$(env_value "$AUTH_ENV" "ISSUER_ADMIN_TOKEN")" "" "ISSUER_ADMIN_TOKEN"
require_nonempty "$(env_value "$AUTH_ENV" "ISSUER_ADMIN_SIGNING_KEY_ID")" "ISSUER_ADMIN_SIGNING_KEY_ID"
require_nonempty "$(env_value "$AUTH_ENV" "ISSUER_ADMIN_SIGNING_PRIVATE_KEY_FILE_LOCAL")" "ISSUER_ADMIN_SIGNING_PRIVATE_KEY_FILE_LOCAL"
require_nonempty "$(env_value "$AUTH_ENV" "ISSUER_ADMIN_SIGNING_KEYS_FILE")" "ISSUER_ADMIN_SIGNING_KEYS_FILE"

PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
./scripts/easy_node.sh server-up \
  --mode provider \
  --public-host 198.51.100.20 \
  --authority-directory https://203.0.113.10:8081 \
  --authority-issuer https://203.0.113.10:8082 \
  --peer-directories https://203.0.113.10:8081 \
  --beta-profile 1 \
  --prod-profile 1 >/tmp/integration_easy_node_prod_server_env_provider.log 2>&1

if [[ ! -f "$PROVIDER_ENV" ]]; then
  echo "missing provider env file after server-up: $PROVIDER_ENV"
  cat /tmp/integration_easy_node_prod_server_env_provider.log
  exit 1
fi

require_eq "$(env_value "$PROVIDER_ENV" "PROD_STRICT_MODE")" "1" "provider PROD_STRICT_MODE"
require_eq "$(env_value "$PROVIDER_ENV" "BETA_STRICT_MODE")" "1" "provider BETA_STRICT_MODE"
require_eq "$(env_value "$PROVIDER_ENV" "CORE_ISSUER_URL")" "https://203.0.113.10:8082" "provider CORE_ISSUER_URL"
require_eq "$(env_value "$PROVIDER_ENV" "ISSUER_ADMIN_TOKEN")" "" "provider ISSUER_ADMIN_TOKEN"
require_eq "$(env_value "$PROVIDER_ENV" "ISSUER_ADMIN_SIGNING_KEY_ID")" "" "provider ISSUER_ADMIN_SIGNING_KEY_ID"
require_eq "$(env_value "$PROVIDER_ENV" "ISSUER_ADMIN_SIGNING_PRIVATE_KEY_FILE_LOCAL")" "" "provider ISSUER_ADMIN_SIGNING_PRIVATE_KEY_FILE_LOCAL"
require_eq "$(env_value "$PROVIDER_ENV" "ISSUER_ADMIN_SIGNING_KEYS_FILE")" "" "provider ISSUER_ADMIN_SIGNING_KEYS_FILE"

echo "easy-node prod authority/provider env integration check ok"
