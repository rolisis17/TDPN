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

cat >"$TMP_BIN/wg" <<'EOF_WG'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "genkey" ]]; then
  echo "test-wg-private-key"
  exit 0
fi
exit 0
EOF_WG

chmod +x "$TMP_BIN/docker" "$TMP_BIN/curl" "$TMP_BIN/wg"

if PATH="$TMP_BIN:$PATH" EASY_NODE_VERIFY_PUBLIC=0 ./scripts/easy_node.sh server-up \
  --mode authority \
  --public-host 203.0.113.10 \
  --prod-profile 1 >/tmp/integration_easy_node_prod_server_env_quorum_fail.log 2>&1; then
  echo "expected prod server-up to fail without peer issuer quorum"
  cat /tmp/integration_easy_node_prod_server_env_quorum_fail.log
  exit 1
fi

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

PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
./scripts/easy_node.sh server-up \
  --mode authority \
  --public-host 203.0.113.10 \
  --beta-profile 1 \
  --prod-profile 0 >/tmp/integration_easy_node_prod_server_env_beta.log 2>&1

if [[ ! -f "$AUTH_ENV" ]]; then
  echo "missing authority env file after beta server-up: $AUTH_ENV"
  cat /tmp/integration_easy_node_prod_server_env_beta.log
  exit 1
fi

require_nonempty "$(env_value "$AUTH_ENV" "DIRECTORY_OPERATOR_ID")" "beta DIRECTORY_OPERATOR_ID"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_OPERATOR_ID")" "$(env_value "$AUTH_ENV" "DIRECTORY_OPERATOR_ID")" "beta authority ENTRY_OPERATOR_ID"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR")" "1" "beta authority ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR"
require_eq "$(env_value "$AUTH_ENV" "DATA_PLANE_MODE")" "opaque" "beta authority DATA_PLANE_MODE"
require_eq "$(env_value "$AUTH_ENV" "WG_BACKEND")" "command" "beta authority WG_BACKEND"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_LIVE_WG_MODE")" "1" "beta authority ENTRY_LIVE_WG_MODE"
require_eq "$(env_value "$AUTH_ENV" "EXIT_LIVE_WG_MODE")" "1" "beta authority EXIT_LIVE_WG_MODE"
require_eq "$(env_value "$AUTH_ENV" "EXIT_WG_KERNEL_PROXY")" "1" "beta authority EXIT_WG_KERNEL_PROXY"
require_nonempty "$(env_value "$AUTH_ENV" "EXIT_WG_PRIVATE_KEY_PATH")" "beta authority EXIT_WG_PRIVATE_KEY_PATH"
require_nonempty "$(env_value "$AUTH_ENV" "EXIT_WG_INTERFACE")" "beta authority EXIT_WG_INTERFACE"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_EXIT_USER")" "0:0" "beta authority ENTRY_EXIT_USER"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_EXIT_PRIVILEGED")" "true" "beta authority ENTRY_EXIT_PRIVILEGED"

PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
./scripts/easy_node.sh server-up \
  --mode provider \
  --public-host 198.51.100.20 \
  --authority-directory http://203.0.113.10:8081 \
  --authority-issuer http://203.0.113.10:8082 \
  --peer-directories http://203.0.113.10:8081 \
  --beta-profile 1 \
  --prod-profile 0 >/tmp/integration_easy_node_prod_server_env_provider_beta.log 2>&1

if [[ ! -f "$PROVIDER_ENV" ]]; then
  echo "missing provider env file after beta provider server-up: $PROVIDER_ENV"
  cat /tmp/integration_easy_node_prod_server_env_provider_beta.log
  exit 1
fi

require_nonempty "$(env_value "$PROVIDER_ENV" "DIRECTORY_OPERATOR_ID")" "beta provider DIRECTORY_OPERATOR_ID"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_OPERATOR_ID")" "$(env_value "$PROVIDER_ENV" "DIRECTORY_OPERATOR_ID")" "beta provider ENTRY_OPERATOR_ID"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR")" "1" "beta provider ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR"
require_eq "$(env_value "$PROVIDER_ENV" "DATA_PLANE_MODE")" "opaque" "beta provider DATA_PLANE_MODE"
require_eq "$(env_value "$PROVIDER_ENV" "WG_BACKEND")" "command" "beta provider WG_BACKEND"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_LIVE_WG_MODE")" "1" "beta provider ENTRY_LIVE_WG_MODE"
require_eq "$(env_value "$PROVIDER_ENV" "EXIT_LIVE_WG_MODE")" "1" "beta provider EXIT_LIVE_WG_MODE"
require_eq "$(env_value "$PROVIDER_ENV" "EXIT_WG_KERNEL_PROXY")" "1" "beta provider EXIT_WG_KERNEL_PROXY"
require_nonempty "$(env_value "$PROVIDER_ENV" "EXIT_WG_PRIVATE_KEY_PATH")" "beta provider EXIT_WG_PRIVATE_KEY_PATH"
require_nonempty "$(env_value "$PROVIDER_ENV" "EXIT_WG_INTERFACE")" "beta provider EXIT_WG_INTERFACE"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_EXIT_USER")" "0:0" "beta provider ENTRY_EXIT_USER"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_EXIT_PRIVILEGED")" "true" "beta provider ENTRY_EXIT_PRIVILEGED"

PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
./scripts/easy_node.sh server-up \
  --mode authority \
  --public-host 203.0.113.10 \
  --peer-directories https://198.51.100.20:8081 \
  --beta-profile 1 \
  --prod-profile 1 >/tmp/integration_easy_node_prod_server_env.log 2>&1

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
require_eq "$(env_value "$AUTH_ENV" "WG_BACKEND")" "command" "WG_BACKEND"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_LIVE_WG_MODE")" "1" "ENTRY_LIVE_WG_MODE"
require_eq "$(env_value "$AUTH_ENV" "EXIT_LIVE_WG_MODE")" "1" "EXIT_LIVE_WG_MODE"
require_eq "$(env_value "$AUTH_ENV" "EXIT_WG_KERNEL_PROXY")" "1" "EXIT_WG_KERNEL_PROXY"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_EXIT_USER")" "0:0" "ENTRY_EXIT_USER"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_EXIT_PRIVILEGED")" "true" "ENTRY_EXIT_PRIVILEGED"
require_nonempty "$(env_value "$AUTH_ENV" "EXIT_WG_PRIVATE_KEY_PATH")" "EXIT_WG_PRIVATE_KEY_PATH"
require_nonempty "$(env_value "$AUTH_ENV" "EXIT_WG_INTERFACE")" "EXIT_WG_INTERFACE"
require_eq "$(env_value "$AUTH_ENV" "ISSUER_URLS")" "https://203.0.113.10:8082,https://198.51.100.20:8082" "ISSUER_URLS"
require_eq "$(env_value "$AUTH_ENV" "DIRECTORY_ISSUER_TRUST_URLS")" "https://203.0.113.10:8082,https://198.51.100.20:8082" "DIRECTORY_ISSUER_TRUST_URLS"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_OPEN_RPS")" "12" "ENTRY_OPEN_RPS"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_BAN_THRESHOLD")" "3" "ENTRY_BAN_THRESHOLD"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_BAN_SEC")" "90" "ENTRY_BAN_SEC"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_MAX_CONCURRENT_OPENS")" "96" "ENTRY_MAX_CONCURRENT_OPENS"
require_eq "$(env_value "$AUTH_ENV" "DIRECTORY_PEER_DISPUTE_MIN_VOTES")" "2" "DIRECTORY_PEER_DISPUTE_MIN_VOTES"
require_eq "$(env_value "$AUTH_ENV" "DIRECTORY_PEER_APPEAL_MIN_VOTES")" "2" "DIRECTORY_PEER_APPEAL_MIN_VOTES"
require_eq "$(env_value "$AUTH_ENV" "DIRECTORY_ADJUDICATION_META_MIN_VOTES")" "2" "DIRECTORY_ADJUDICATION_META_MIN_VOTES"
require_eq "$(env_value "$AUTH_ENV" "DIRECTORY_FINAL_DISPUTE_MIN_VOTES")" "2" "DIRECTORY_FINAL_DISPUTE_MIN_VOTES"
require_eq "$(env_value "$AUTH_ENV" "DIRECTORY_FINAL_APPEAL_MIN_VOTES")" "2" "DIRECTORY_FINAL_APPEAL_MIN_VOTES"
require_eq "$(env_value "$AUTH_ENV" "DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS")" "2" "DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS"
require_eq "$(env_value "$AUTH_ENV" "DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES")" "2" "DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES"
require_eq "$(env_value "$AUTH_ENV" "DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO")" "0.67" "DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO"
require_eq "$(env_value "$AUTH_ENV" "DIRECTORY_DISPUTE_MAX_TTL_SEC")" "259200" "DIRECTORY_DISPUTE_MAX_TTL_SEC"
require_eq "$(env_value "$AUTH_ENV" "DIRECTORY_APPEAL_MAX_TTL_SEC")" "259200" "DIRECTORY_APPEAL_MAX_TTL_SEC"

PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
./scripts/easy_node.sh server-up \
  --mode provider \
  --public-host 198.51.100.20 \
  --authority-directory https://203.0.113.10:8081 \
  --authority-issuer https://203.0.113.10:8082 \
  --peer-directories https://203.0.113.10:8081,https://198.51.100.30:8081 \
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
require_eq "$(env_value "$PROVIDER_ENV" "WG_BACKEND")" "command" "provider WG_BACKEND"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_LIVE_WG_MODE")" "1" "provider ENTRY_LIVE_WG_MODE"
require_eq "$(env_value "$PROVIDER_ENV" "EXIT_LIVE_WG_MODE")" "1" "provider EXIT_LIVE_WG_MODE"
require_eq "$(env_value "$PROVIDER_ENV" "EXIT_WG_KERNEL_PROXY")" "1" "provider EXIT_WG_KERNEL_PROXY"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_EXIT_USER")" "0:0" "provider ENTRY_EXIT_USER"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_EXIT_PRIVILEGED")" "true" "provider ENTRY_EXIT_PRIVILEGED"
require_nonempty "$(env_value "$PROVIDER_ENV" "EXIT_WG_PRIVATE_KEY_PATH")" "provider EXIT_WG_PRIVATE_KEY_PATH"
require_nonempty "$(env_value "$PROVIDER_ENV" "EXIT_WG_INTERFACE")" "provider EXIT_WG_INTERFACE"
require_eq "$(env_value "$PROVIDER_ENV" "ISSUER_URLS")" "https://203.0.113.10:8082,https://198.51.100.30:8082" "provider ISSUER_URLS"
require_eq "$(env_value "$PROVIDER_ENV" "DIRECTORY_ISSUER_TRUST_URLS")" "https://203.0.113.10:8082,https://198.51.100.30:8082" "provider DIRECTORY_ISSUER_TRUST_URLS"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_OPEN_RPS")" "12" "provider ENTRY_OPEN_RPS"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_BAN_THRESHOLD")" "3" "provider ENTRY_BAN_THRESHOLD"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_BAN_SEC")" "90" "provider ENTRY_BAN_SEC"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_MAX_CONCURRENT_OPENS")" "96" "provider ENTRY_MAX_CONCURRENT_OPENS"
require_eq "$(env_value "$PROVIDER_ENV" "DIRECTORY_PEER_DISPUTE_MIN_VOTES")" "2" "provider DIRECTORY_PEER_DISPUTE_MIN_VOTES"
require_eq "$(env_value "$PROVIDER_ENV" "DIRECTORY_PEER_APPEAL_MIN_VOTES")" "2" "provider DIRECTORY_PEER_APPEAL_MIN_VOTES"
require_eq "$(env_value "$PROVIDER_ENV" "DIRECTORY_ADJUDICATION_META_MIN_VOTES")" "2" "provider DIRECTORY_ADJUDICATION_META_MIN_VOTES"
require_eq "$(env_value "$PROVIDER_ENV" "DIRECTORY_FINAL_DISPUTE_MIN_VOTES")" "2" "provider DIRECTORY_FINAL_DISPUTE_MIN_VOTES"
require_eq "$(env_value "$PROVIDER_ENV" "DIRECTORY_FINAL_APPEAL_MIN_VOTES")" "2" "provider DIRECTORY_FINAL_APPEAL_MIN_VOTES"
require_eq "$(env_value "$PROVIDER_ENV" "DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS")" "2" "provider DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS"
require_eq "$(env_value "$PROVIDER_ENV" "DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES")" "2" "provider DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES"
require_eq "$(env_value "$PROVIDER_ENV" "DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO")" "0.67" "provider DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO"
require_eq "$(env_value "$PROVIDER_ENV" "DIRECTORY_DISPUTE_MAX_TTL_SEC")" "259200" "provider DIRECTORY_DISPUTE_MAX_TTL_SEC"
require_eq "$(env_value "$PROVIDER_ENV" "DIRECTORY_APPEAL_MAX_TTL_SEC")" "259200" "provider DIRECTORY_APPEAL_MAX_TTL_SEC"

echo "easy-node prod authority/provider env integration check ok"
