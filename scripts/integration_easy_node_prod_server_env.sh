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
ENTRY_EXIT_DATA_DIR="$ROOT_DIR/deploy/data/entry-exit"
HOSTS_FILE="$ROOT_DIR/data/easy_mode_hosts.conf"
TMP_DIR="$(mktemp -d)"
TMP_BIN="$TMP_DIR/bin"
mkdir -p "$TMP_BIN"

if ! rg -q 'EXIT_WG_PUBKEY: "\$\{EXIT_WG_PUBKEY:-\}"' "$ROOT_DIR/deploy/docker-compose.yml"; then
  echo "docker-compose entry-exit environment must forward EXIT_WG_PUBKEY"
  exit 1
fi
if [[ "$(rg -c 'ENTRY_RELAY_ID: "\$\{ENTRY_RELAY_ID:-entry-local-1\}"' "$ROOT_DIR/deploy/docker-compose.yml")" -lt 2 ]]; then
  echo "docker-compose must forward ENTRY_RELAY_ID to directory and entry-exit services"
  exit 1
fi
if [[ "$(rg -c 'EXIT_RELAY_ID: "\$\{EXIT_RELAY_ID:-exit-local-1\}"' "$ROOT_DIR/deploy/docker-compose.yml")" -lt 2 ]]; then
  echo "docker-compose must forward EXIT_RELAY_ID to directory and entry-exit services"
  exit 1
fi
if ! rg -q 'ENTRY_ROUTE_ASSERTION_PUBLIC_KEY: "\$\{ENTRY_ROUTE_ASSERTION_PUBLIC_KEY:-\}"' "$ROOT_DIR/deploy/docker-compose.yml"; then
  echo "docker-compose directory environment must forward ENTRY_ROUTE_ASSERTION_PUBLIC_KEY"
  exit 1
fi
if ! rg -q 'ENTRY_ROUTE_ASSERTION_PRIVATE_KEY_FILE: "\$\{ENTRY_ROUTE_ASSERTION_PRIVATE_KEY_FILE:-\}"' "$ROOT_DIR/deploy/docker-compose.yml"; then
  echo "docker-compose entry-exit environment must forward ENTRY_ROUTE_ASSERTION_PRIVATE_KEY_FILE"
  exit 1
fi
if ! rg -q 'EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS: "\$\{EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS:-\}"' "$ROOT_DIR/deploy/docker-compose.yml"; then
  echo "docker-compose entry-exit environment must forward EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS"
  exit 1
fi
if ! rg -q 'EXIT_ENTRY_ROUTE_ASSERTION_DIRECTORY_TRUST: "\$\{EXIT_ENTRY_ROUTE_ASSERTION_DIRECTORY_TRUST:-0\}"' "$ROOT_DIR/deploy/docker-compose.yml"; then
  echo "docker-compose entry-exit environment must forward EXIT_ENTRY_ROUTE_ASSERTION_DIRECTORY_TRUST"
  exit 1
fi
if ! rg -q 'DIRECTORY_ISSUER_TRUSTED_KEYS_FILE: "\$\{DIRECTORY_ISSUER_TRUSTED_KEYS_FILE:-/app/data/directory_issuer_trusted_keys.txt\}"' "$ROOT_DIR/deploy/docker-compose.yml"; then
  echo "docker-compose directory environment must forward DIRECTORY_ISSUER_TRUSTED_KEYS_FILE"
  exit 1
fi
if ! rg -q 'DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_SHARED_FILE_MODE: "\$\{DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_SHARED_FILE_MODE:-0\}"' "$ROOT_DIR/deploy/docker-compose.yml"; then
  echo "docker-compose directory environment must forward provider replay shared-file mode"
  exit 1
fi
if ! rg -q 'EXIT_TOKEN_PROOF_REPLAY_STORE_FILE: "\$\{EXIT_TOKEN_PROOF_REPLAY_STORE_FILE:-\}"' "$ROOT_DIR/deploy/docker-compose.yml"; then
  echo "docker-compose entry-exit environment must forward EXIT_TOKEN_PROOF_REPLAY_STORE_FILE"
  exit 1
fi
if ! rg -q 'ISSUER_PAYMENT_REPLAY_STORE_FILE: "\$\{ISSUER_PAYMENT_REPLAY_STORE_FILE:-/app/data/issuer_payment_replay.json\}"' "$ROOT_DIR/deploy/docker-compose.yml"; then
  echo "docker-compose issuer environment must forward ISSUER_PAYMENT_REPLAY_STORE_FILE"
  exit 1
fi
if ! rg -q 'ISSUER_CLIENT_ALLOWLIST_ONLY: "\$\{ISSUER_CLIENT_ALLOWLIST_ONLY:-1\}"' "$ROOT_DIR/deploy/docker-compose.yml"; then
  echo "docker-compose issuer environment must default ISSUER_CLIENT_ALLOWLIST_ONLY to 1"
  exit 1
fi
if ! rg -q 'ISSUER_ALLOW_ANON_CRED: "\$\{ISSUER_ALLOW_ANON_CRED:-0\}"' "$ROOT_DIR/deploy/docker-compose.yml"; then
  echo "docker-compose issuer environment must default ISSUER_ALLOW_ANON_CRED to 0"
  exit 1
fi
if [[ "$(rg -c 'SETTLEMENT_CHAIN_ADAPTER: "\$\{SETTLEMENT_CHAIN_ADAPTER:-\}"' "$ROOT_DIR/deploy/docker-compose.yml")" -lt 2 ]]; then
  echo "docker-compose must forward SETTLEMENT_CHAIN_ADAPTER to issuer and entry-exit services"
  exit 1
fi
if [[ "$(rg -c 'COSMOS_SETTLEMENT_ENDPOINT: "\$\{COSMOS_SETTLEMENT_ENDPOINT:-\}"' "$ROOT_DIR/deploy/docker-compose.yml")" -lt 2 ]]; then
  echo "docker-compose must forward COSMOS_SETTLEMENT_ENDPOINT to issuer and entry-exit services"
  exit 1
fi
if ! rg -q 'EXIT_EGRESS_BACKEND: "\$\{EXIT_EGRESS_BACKEND:-noop\}"' "$ROOT_DIR/deploy/docker-compose.yml"; then
  echo "docker-compose entry-exit environment must forward EXIT_EGRESS_BACKEND"
  exit 1
fi

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
  restore_dir "$ENTRY_EXIT_DATA_DIR" "entry_exit_data_dir"
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
backup_dir "$ENTRY_EXIT_DATA_DIR" "entry_exit_data_dir"

cat >"$TMP_BIN/docker" <<'EOF_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "compose" && "${2:-}" == "version" ]]; then
  echo "Docker Compose version vtest"
  exit 0
fi
if [[ "${1:-}" == "compose" ]]; then
  for polluted in \
    "PROD_STRICT_MODE=0" \
    "BETA_STRICT_MODE=0" \
    "MTLS_ENABLE=0" \
    "SETTLEMENT_CHAIN_ADAPTER=ambient-bad" \
    "COSMOS_SETTLEMENT_ENDPOINT=https://ambient.invalid" \
    "EXIT_EGRESS_BACKEND=noop" \
    "DIRECTORY_ISSUER_TRUSTED_KEYS_FILE=/ambient/bad.txt"; do
    name="${polluted%%=*}"
    value="${polluted#*=}"
    if [[ "${!name-}" == "$value" ]]; then
      echo "compose env leakage: $name=$value" >&2
      exit 1
    fi
  done
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
for arg in "$@"; do
  case "$arg" in
    */v1/pubkeys)
      echo '{"issuer":"issuer-peer","pub_keys":["AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"]}'
      exit 0
      ;;
  esac
done
echo "{}"
EOF_CURL

cat >"$TMP_BIN/wg" <<'EOF_WG'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "genkey" ]]; then
  echo "test-wg-private-key"
  exit 0
fi
if [[ "${1:-}" == "pubkey" ]]; then
  # server-up derives EXIT_WG_PUBKEY via `wg pubkey`
  cat >/dev/null || true
  echo "test-wg-public-key"
  exit 0
fi
exit 0
EOF_WG

chmod +x "$TMP_BIN/docker" "$TMP_BIN/curl" "$TMP_BIN/wg"

PROD_ISSUER_TRUST_FILE="$TMP_DIR/prod_issuer_trusted_keys.txt"
cat >"$PROD_ISSUER_TRUST_FILE" <<'EOF_TRUST'
peer-a AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE
peer-b AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI
EOF_TRUST

if PATH="$TMP_BIN:$PATH" EASY_NODE_VERIFY_PUBLIC=0 \
  EASY_NODE_PROD_ISSUER_TRUSTED_KEYS_FILE="$PROD_ISSUER_TRUST_FILE" \
  COSMOS_SETTLEMENT_ENDPOINT="https://cosmos.example.test" \
  ./scripts/easy_node.sh server-up \
  --mode authority \
  --public-host 203.0.113.10 \
  --prod-profile 1 >/tmp/integration_easy_node_prod_server_env_quorum_fail.log 2>&1; then
  echo "expected prod server-up to fail without peer issuer quorum"
  cat /tmp/integration_easy_node_prod_server_env_quorum_fail.log
  exit 1
fi
if ! grep -q "requires at least 2 issuer URLs" /tmp/integration_easy_node_prod_server_env_quorum_fail.log; then
  echo "expected prod quorum failure to mention strict issuer URL quorum"
  cat /tmp/integration_easy_node_prod_server_env_quorum_fail.log
  exit 1
fi

if PATH="$TMP_BIN:$PATH" EASY_NODE_VERIFY_PUBLIC=0 \
  EASY_NODE_PROD_ISSUER_TRUSTED_KEYS_FILE="$PROD_ISSUER_TRUST_FILE" \
  ./scripts/easy_node.sh server-up \
  --mode authority \
  --public-host 203.0.113.10 \
  --peer-directories https://198.51.100.20:8081 \
  --prod-profile 1 >/tmp/integration_easy_node_prod_server_env_missing_cosmos.log 2>&1; then
  echo "expected prod server-up to fail without COSMOS_SETTLEMENT_ENDPOINT"
  cat /tmp/integration_easy_node_prod_server_env_missing_cosmos.log
  exit 1
fi
if ! grep -q "requires COSMOS_SETTLEMENT_ENDPOINT" /tmp/integration_easy_node_prod_server_env_missing_cosmos.log; then
  echo "expected missing-cosmos failure to mention COSMOS_SETTLEMENT_ENDPOINT"
  cat /tmp/integration_easy_node_prod_server_env_missing_cosmos.log
  exit 1
fi

if PATH="$TMP_BIN:$PATH" EASY_NODE_VERIFY_PUBLIC=0 \
  COSMOS_SETTLEMENT_ENDPOINT="https://cosmos.example.test" \
  ./scripts/easy_node.sh server-up \
  --mode authority \
  --public-host 203.0.113.10 \
  --peer-directories https://198.51.100.20:8081 \
  --prod-profile 1 >/tmp/integration_easy_node_prod_server_env_missing_issuer_trust.log 2>&1; then
  echo "expected prod server-up to fail without issuer trust anchors"
  cat /tmp/integration_easy_node_prod_server_env_missing_issuer_trust.log
  exit 1
fi
if ! grep -q "requires EASY_NODE_PROD_ISSUER_TRUSTED_KEYS_FILE" /tmp/integration_easy_node_prod_server_env_missing_issuer_trust.log; then
  echo "expected missing-issuer-trust failure to mention trust anchor file"
  cat /tmp/integration_easy_node_prod_server_env_missing_issuer_trust.log
  exit 1
fi

INVALID_PROD_ISSUER_TRUST_FILE="$TMP_DIR/prod_issuer_trusted_keys_invalid.txt"
cat >"$INVALID_PROD_ISSUER_TRUST_FILE" <<'EOF_INVALID_TRUST'
peer-a AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE
peer-b not-a-valid-ed25519-key
EOF_INVALID_TRUST

if PATH="$TMP_BIN:$PATH" EASY_NODE_VERIFY_PUBLIC=0 \
  EASY_NODE_PROD_ISSUER_TRUSTED_KEYS_FILE="$INVALID_PROD_ISSUER_TRUST_FILE" \
  EASY_NODE_COSMOS_SETTLEMENT_ENDPOINT="https://cosmos.example.test" \
  ./scripts/easy_node.sh server-up \
  --mode authority \
  --public-host 203.0.113.10 \
  --peer-directories https://198.51.100.20:8081 \
  --prod-profile 1 >/tmp/integration_easy_node_prod_server_env_invalid_issuer_trust.log 2>&1; then
  echo "expected prod server-up to fail on invalid issuer trust anchor key"
  cat /tmp/integration_easy_node_prod_server_env_invalid_issuer_trust.log
  exit 1
fi
if ! grep -q "invalid Ed25519 public key" /tmp/integration_easy_node_prod_server_env_invalid_issuer_trust.log; then
  echo "expected invalid-issuer-trust failure to mention invalid Ed25519 public key"
  cat /tmp/integration_easy_node_prod_server_env_invalid_issuer_trust.log
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

require_log_contains() {
  local log_path="$1"
  local pattern="$2"
  local label="$3"
  if ! rg -q "$pattern" "$log_path"; then
    echo "missing expected $label"
    cat "$log_path"
    exit 1
  fi
}

PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
EASY_NODE_ENTRY_ROUTE_ASSERTION_KEYGEN=openssl \
./scripts/easy_node.sh server-up \
  --mode authority \
  --public-host 203.0.113.10 \
  --peer-directories http://198.51.100.20:8081 \
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
require_nonempty "$(env_value "$AUTH_ENV" "EXIT_WG_PUBKEY")" "beta authority EXIT_WG_PUBKEY"
require_nonempty "$(env_value "$AUTH_ENV" "EXIT_WG_PRIVATE_KEY_PATH")" "beta authority EXIT_WG_PRIVATE_KEY_PATH"
require_nonempty "$(env_value "$AUTH_ENV" "EXIT_WG_INTERFACE")" "beta authority EXIT_WG_INTERFACE"
require_nonempty "$(env_value "$AUTH_ENV" "ENTRY_ROUTE_ASSERTION_PRIVATE_KEY_FILE")" "beta authority ENTRY_ROUTE_ASSERTION_PRIVATE_KEY_FILE"
require_nonempty "$(env_value "$AUTH_ENV" "ENTRY_ROUTE_ASSERTION_PUBLIC_KEY")" "beta authority ENTRY_ROUTE_ASSERTION_PUBLIC_KEY"
require_eq "$(env_value "$AUTH_ENV" "EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS")" "$(env_value "$AUTH_ENV" "ENTRY_ROUTE_ASSERTION_PUBLIC_KEY")" "beta authority EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS"
require_eq "$(env_value "$AUTH_ENV" "EXIT_ENTRY_ROUTE_ASSERTION_DIRECTORY_TRUST")" "1" "beta authority EXIT_ENTRY_ROUTE_ASSERTION_DIRECTORY_TRUST"
require_eq "$(env_value "$AUTH_ENV" "ISSUER_URLS")" "http://issuer:8082,http://198.51.100.20:8082" "beta authority ISSUER_URLS"
require_eq "$(env_value "$AUTH_ENV" "ISSUER_CLIENT_ALLOWLIST_ONLY")" "1" "beta authority ISSUER_CLIENT_ALLOWLIST_ONLY"
require_eq "$(env_value "$AUTH_ENV" "ISSUER_ALLOW_ANON_CRED")" "0" "beta authority ISSUER_ALLOW_ANON_CRED"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_EXIT_USER")" "0:0" "beta authority ENTRY_EXIT_USER"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_EXIT_PRIVILEGED")" "true" "beta authority ENTRY_EXIT_PRIVILEGED"
require_log_contains /tmp/integration_easy_node_prod_server_env_beta.log 'server WG runtime check: ok' "beta authority WG runtime check"

if PATH="$TMP_BIN:$PATH" \
  EASY_NODE_VERIFY_PUBLIC=0 \
  EASY_NODE_ENTRY_ROUTE_ASSERTION_KEYGEN=openssl \
  ./scripts/easy_node.sh server-up \
    --mode authority \
    --public-host 203.0.113.10 \
    --peer-directories http://198.51.100.20:8081 \
    --beta-profile 1 \
    --prod-profile 0 \
    --client-allowlist 0 >/tmp/integration_easy_node_prod_server_env_beta_open_allowlist.log 2>&1; then
  echo "expected beta authority server-up to reject open client allowlist"
  cat /tmp/integration_easy_node_prod_server_env_beta_open_allowlist.log
  exit 1
fi
if ! rg -q 'requires --client-allowlist 1' /tmp/integration_easy_node_prod_server_env_beta_open_allowlist.log; then
  echo "missing expected beta allowlist rejection diagnostic"
  cat /tmp/integration_easy_node_prod_server_env_beta_open_allowlist.log
  exit 1
fi

if PATH="$TMP_BIN:$PATH" \
  EASY_NODE_VERIFY_PUBLIC=0 \
  EASY_NODE_ENTRY_ROUTE_ASSERTION_KEYGEN=openssl \
  ./scripts/easy_node.sh server-up \
    --mode authority \
    --public-host 203.0.113.10 \
    --peer-directories http://198.51.100.20:8081 \
    --beta-profile 1 \
    --prod-profile 0 \
    --allow-anon-cred 1 >/tmp/integration_easy_node_prod_server_env_beta_anon_cred.log 2>&1; then
  echo "expected beta authority server-up to reject anonymous credentials"
  cat /tmp/integration_easy_node_prod_server_env_beta_anon_cred.log
  exit 1
fi
if ! rg -q 'requires --allow-anon-cred 0' /tmp/integration_easy_node_prod_server_env_beta_anon_cred.log; then
  echo "missing expected beta anonymous credential rejection diagnostic"
  cat /tmp/integration_easy_node_prod_server_env_beta_anon_cred.log
  exit 1
fi

PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
EASY_NODE_ENTRY_ROUTE_ASSERTION_KEYGEN=openssl \
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
require_nonempty "$(env_value "$PROVIDER_ENV" "EXIT_WG_PUBKEY")" "beta provider EXIT_WG_PUBKEY"
require_nonempty "$(env_value "$PROVIDER_ENV" "EXIT_WG_PRIVATE_KEY_PATH")" "beta provider EXIT_WG_PRIVATE_KEY_PATH"
require_nonempty "$(env_value "$PROVIDER_ENV" "EXIT_WG_INTERFACE")" "beta provider EXIT_WG_INTERFACE"
require_nonempty "$(env_value "$PROVIDER_ENV" "ENTRY_ROUTE_ASSERTION_PRIVATE_KEY_FILE")" "beta provider ENTRY_ROUTE_ASSERTION_PRIVATE_KEY_FILE"
require_nonempty "$(env_value "$PROVIDER_ENV" "ENTRY_ROUTE_ASSERTION_PUBLIC_KEY")" "beta provider ENTRY_ROUTE_ASSERTION_PUBLIC_KEY"
require_eq "$(env_value "$PROVIDER_ENV" "EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS")" "$(env_value "$PROVIDER_ENV" "ENTRY_ROUTE_ASSERTION_PUBLIC_KEY")" "beta provider EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS"
require_eq "$(env_value "$PROVIDER_ENV" "EXIT_ENTRY_ROUTE_ASSERTION_DIRECTORY_TRUST")" "1" "beta provider EXIT_ENTRY_ROUTE_ASSERTION_DIRECTORY_TRUST"
require_eq "$(env_value "$PROVIDER_ENV" "ISSUER_URLS")" "http://203.0.113.10:8082" "beta provider ISSUER_URLS"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_EXIT_USER")" "0:0" "beta provider ENTRY_EXIT_USER"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_EXIT_PRIVILEGED")" "true" "beta provider ENTRY_EXIT_PRIVILEGED"
require_log_contains /tmp/integration_easy_node_prod_server_env_provider_beta.log 'server WG runtime check: ok' "beta provider WG runtime check"

PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
EASY_NODE_PROD_ISSUER_TRUSTED_KEYS_FILE="$PROD_ISSUER_TRUST_FILE" \
EASY_NODE_COSMOS_SETTLEMENT_ENDPOINT="https://cosmos.example.test" \
PROD_STRICT_MODE=0 \
BETA_STRICT_MODE=0 \
MTLS_ENABLE=0 \
SETTLEMENT_CHAIN_ADAPTER=ambient-bad \
COSMOS_SETTLEMENT_ENDPOINT="https://ambient.invalid" \
EXIT_EGRESS_BACKEND=noop \
DIRECTORY_ISSUER_TRUSTED_KEYS_FILE=/ambient/bad.txt \
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
require_nonempty "$(env_value "$AUTH_ENV" "EXIT_WG_PUBKEY")" "EXIT_WG_PUBKEY"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_EXIT_USER")" "0:0" "ENTRY_EXIT_USER"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_EXIT_PRIVILEGED")" "true" "ENTRY_EXIT_PRIVILEGED"
require_nonempty "$(env_value "$AUTH_ENV" "EXIT_WG_PRIVATE_KEY_PATH")" "EXIT_WG_PRIVATE_KEY_PATH"
require_nonempty "$(env_value "$AUTH_ENV" "EXIT_WG_INTERFACE")" "EXIT_WG_INTERFACE"
require_nonempty "$(env_value "$AUTH_ENV" "ENTRY_ROUTE_ASSERTION_PRIVATE_KEY_FILE")" "ENTRY_ROUTE_ASSERTION_PRIVATE_KEY_FILE"
require_nonempty "$(env_value "$AUTH_ENV" "ENTRY_ROUTE_ASSERTION_PUBLIC_KEY")" "ENTRY_ROUTE_ASSERTION_PUBLIC_KEY"
require_eq "$(env_value "$AUTH_ENV" "EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS")" "$(env_value "$AUTH_ENV" "ENTRY_ROUTE_ASSERTION_PUBLIC_KEY")" "EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS"
require_eq "$(env_value "$AUTH_ENV" "ISSUER_URLS")" "https://203.0.113.10:8082,https://198.51.100.20:8082" "ISSUER_URLS"
require_eq "$(env_value "$AUTH_ENV" "DIRECTORY_ISSUER_TRUST_URLS")" "https://203.0.113.10:8082,https://198.51.100.20:8082" "DIRECTORY_ISSUER_TRUST_URLS"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_OPEN_RPS")" "12" "ENTRY_OPEN_RPS"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_BAN_THRESHOLD")" "3" "ENTRY_BAN_THRESHOLD"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_BAN_SEC")" "90" "ENTRY_BAN_SEC"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_MAX_CONCURRENT_OPENS")" "96" "ENTRY_MAX_CONCURRENT_OPENS"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_DIRECTORY_MIN_SOURCES")" "2" "ENTRY_DIRECTORY_MIN_SOURCES"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_DIRECTORY_MIN_OPERATORS")" "2" "ENTRY_DIRECTORY_MIN_OPERATORS"
require_eq "$(env_value "$AUTH_ENV" "ENTRY_DIRECTORY_MIN_RELAY_VOTES")" "2" "ENTRY_DIRECTORY_MIN_RELAY_VOTES"
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
require_eq "$(env_value "$AUTH_ENV" "DIRECTORY_KEY_ROTATE_SEC")" "2592000" "DIRECTORY_KEY_ROTATE_SEC"
require_eq "$(env_value "$AUTH_ENV" "DIRECTORY_KEY_HISTORY")" "12" "DIRECTORY_KEY_HISTORY"
require_eq "$(env_value "$AUTH_ENV" "DIRECTORY_ISSUER_TRUSTED_KEYS_FILE")" "/app/data/directory_issuer_trusted_keys.txt" "DIRECTORY_ISSUER_TRUSTED_KEYS_FILE"
require_eq "$(env_value "$AUTH_ENV" "DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_SHARED_FILE_MODE")" "1" "DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_SHARED_FILE_MODE"
require_eq "$(env_value "$AUTH_ENV" "DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE")" "/app/data/directory_provider_token_proof_replay.json" "DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE"
require_eq "$(env_value "$AUTH_ENV" "SETTLEMENT_CHAIN_ADAPTER")" "cosmos" "SETTLEMENT_CHAIN_ADAPTER"
require_eq "$(env_value "$AUTH_ENV" "COSMOS_SETTLEMENT_ENDPOINT")" "https://cosmos.example.test" "COSMOS_SETTLEMENT_ENDPOINT"
require_eq "$(env_value "$AUTH_ENV" "COSMOS_SETTLEMENT_SUBMIT_MODE")" "http" "COSMOS_SETTLEMENT_SUBMIT_MODE"
require_eq "$(env_value "$AUTH_ENV" "ISSUER_REQUIRE_PAYMENT_PROOF")" "1" "ISSUER_REQUIRE_PAYMENT_PROOF"
require_eq "$(env_value "$AUTH_ENV" "ISSUER_CLIENT_ALLOWLIST_ONLY")" "1" "ISSUER_CLIENT_ALLOWLIST_ONLY"
require_eq "$(env_value "$AUTH_ENV" "ISSUER_ALLOW_ANON_CRED")" "0" "ISSUER_ALLOW_ANON_CRED"
expected_issuer_replay="/app/data/issuer_$(env_value "$AUTH_ENV" "ISSUER_ID")_payment_replay.json"
require_eq "$(env_value "$AUTH_ENV" "ISSUER_PAYMENT_REPLAY_STORE_FILE")" "$expected_issuer_replay" "ISSUER_PAYMENT_REPLAY_STORE_FILE"
require_eq "$(env_value "$AUTH_ENV" "ISSUER_KEY_ROTATE_SEC")" "2592000" "ISSUER_KEY_ROTATE_SEC"
require_eq "$(env_value "$AUTH_ENV" "ISSUER_KEY_HISTORY")" "12" "ISSUER_KEY_HISTORY"
require_eq "$(env_value "$AUTH_ENV" "EXIT_TOKEN_PROOF_REPLAY_STORE_FILE")" "/app/data/exit_token_proof_replay.json" "EXIT_TOKEN_PROOF_REPLAY_STORE_FILE"
require_eq "$(env_value "$AUTH_ENV" "EXIT_EGRESS_BACKEND")" "command" "EXIT_EGRESS_BACKEND"
require_eq "$(env_value "$AUTH_ENV" "EXIT_ISSUER_MIN_KEY_VOTES")" "2" "EXIT_ISSUER_MIN_KEY_VOTES"
require_log_contains /tmp/integration_easy_node_prod_server_env.log 'server WG runtime check: ok' "prod authority WG runtime check"

PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
EASY_NODE_PROD_ISSUER_TRUSTED_KEYS_FILE="$PROD_ISSUER_TRUST_FILE" \
EASY_NODE_COSMOS_SETTLEMENT_ENDPOINT="https://cosmos.example.test" \
PROD_STRICT_MODE=0 \
BETA_STRICT_MODE=0 \
MTLS_ENABLE=0 \
SETTLEMENT_CHAIN_ADAPTER=ambient-bad \
COSMOS_SETTLEMENT_ENDPOINT="https://ambient.invalid" \
EXIT_EGRESS_BACKEND=noop \
DIRECTORY_ISSUER_TRUSTED_KEYS_FILE=/ambient/bad.txt \
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
require_nonempty "$(env_value "$PROVIDER_ENV" "EXIT_WG_PUBKEY")" "provider EXIT_WG_PUBKEY"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_EXIT_USER")" "0:0" "provider ENTRY_EXIT_USER"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_EXIT_PRIVILEGED")" "true" "provider ENTRY_EXIT_PRIVILEGED"
require_nonempty "$(env_value "$PROVIDER_ENV" "EXIT_WG_PRIVATE_KEY_PATH")" "provider EXIT_WG_PRIVATE_KEY_PATH"
require_nonempty "$(env_value "$PROVIDER_ENV" "EXIT_WG_INTERFACE")" "provider EXIT_WG_INTERFACE"
require_nonempty "$(env_value "$PROVIDER_ENV" "ENTRY_ROUTE_ASSERTION_PRIVATE_KEY_FILE")" "provider ENTRY_ROUTE_ASSERTION_PRIVATE_KEY_FILE"
require_nonempty "$(env_value "$PROVIDER_ENV" "ENTRY_ROUTE_ASSERTION_PUBLIC_KEY")" "provider ENTRY_ROUTE_ASSERTION_PUBLIC_KEY"
require_eq "$(env_value "$PROVIDER_ENV" "EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS")" "$(env_value "$PROVIDER_ENV" "ENTRY_ROUTE_ASSERTION_PUBLIC_KEY")" "provider EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS"
require_eq "$(env_value "$PROVIDER_ENV" "ISSUER_URLS")" "https://203.0.113.10:8082,https://198.51.100.30:8082" "provider ISSUER_URLS"
require_eq "$(env_value "$PROVIDER_ENV" "DIRECTORY_ISSUER_TRUST_URLS")" "https://203.0.113.10:8082,https://198.51.100.30:8082" "provider DIRECTORY_ISSUER_TRUST_URLS"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_OPEN_RPS")" "12" "provider ENTRY_OPEN_RPS"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_BAN_THRESHOLD")" "3" "provider ENTRY_BAN_THRESHOLD"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_BAN_SEC")" "90" "provider ENTRY_BAN_SEC"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_MAX_CONCURRENT_OPENS")" "96" "provider ENTRY_MAX_CONCURRENT_OPENS"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_DIRECTORY_MIN_SOURCES")" "2" "provider ENTRY_DIRECTORY_MIN_SOURCES"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_DIRECTORY_MIN_OPERATORS")" "2" "provider ENTRY_DIRECTORY_MIN_OPERATORS"
require_eq "$(env_value "$PROVIDER_ENV" "ENTRY_DIRECTORY_MIN_RELAY_VOTES")" "2" "provider ENTRY_DIRECTORY_MIN_RELAY_VOTES"
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
require_eq "$(env_value "$PROVIDER_ENV" "DIRECTORY_KEY_ROTATE_SEC")" "2592000" "provider DIRECTORY_KEY_ROTATE_SEC"
require_eq "$(env_value "$PROVIDER_ENV" "DIRECTORY_KEY_HISTORY")" "12" "provider DIRECTORY_KEY_HISTORY"
require_eq "$(env_value "$PROVIDER_ENV" "DIRECTORY_ISSUER_TRUSTED_KEYS_FILE")" "/app/data/directory_issuer_trusted_keys.txt" "provider DIRECTORY_ISSUER_TRUSTED_KEYS_FILE"
require_eq "$(env_value "$PROVIDER_ENV" "DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_SHARED_FILE_MODE")" "1" "provider DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_SHARED_FILE_MODE"
require_eq "$(env_value "$PROVIDER_ENV" "DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE")" "/app/data/directory_provider_token_proof_replay.json" "provider DIRECTORY_PROVIDER_TOKEN_PROOF_REPLAY_STORE_FILE"
require_eq "$(env_value "$PROVIDER_ENV" "SETTLEMENT_CHAIN_ADAPTER")" "cosmos" "provider SETTLEMENT_CHAIN_ADAPTER"
require_eq "$(env_value "$PROVIDER_ENV" "COSMOS_SETTLEMENT_ENDPOINT")" "https://cosmos.example.test" "provider COSMOS_SETTLEMENT_ENDPOINT"
require_eq "$(env_value "$PROVIDER_ENV" "COSMOS_SETTLEMENT_SUBMIT_MODE")" "http" "provider COSMOS_SETTLEMENT_SUBMIT_MODE"
require_eq "$(env_value "$PROVIDER_ENV" "EXIT_TOKEN_PROOF_REPLAY_STORE_FILE")" "/app/data/exit_token_proof_replay.json" "provider EXIT_TOKEN_PROOF_REPLAY_STORE_FILE"
require_eq "$(env_value "$PROVIDER_ENV" "EXIT_EGRESS_BACKEND")" "command" "provider EXIT_EGRESS_BACKEND"
require_eq "$(env_value "$PROVIDER_ENV" "EXIT_ISSUER_MIN_KEY_VOTES")" "2" "provider EXIT_ISSUER_MIN_KEY_VOTES"
require_log_contains /tmp/integration_easy_node_prod_server_env_provider.log 'server WG runtime check: ok' "prod provider WG runtime check"

echo "easy-node prod authority/provider env integration check ok"
