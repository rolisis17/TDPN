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
live_curl_mock_dir=""

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
  if [[ -n "$live_curl_mock_dir" ]]; then
    rm -rf "$live_curl_mock_dir"
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
wg_key_file="$tls_dir/tls/exit_wg.key"
printf 'test-exit-wg-private-key\n' >"$wg_key_file"
chmod 600 "$wg_key_file" 2>/dev/null || true

cat >"$AUTH_ENV" <<EOF_ENV
PROD_STRICT_MODE=1
BETA_STRICT_MODE=1
MTLS_ENABLE=1
DATA_PLANE_MODE=opaque
DIRECTORY_PUBLIC_URL=https://203.0.113.10:8081
ENTRY_URL_PUBLIC=https://203.0.113.10:8083
EXIT_CONTROL_URL_PUBLIC=https://203.0.113.10:8084
EASY_NODE_MTLS_CA_FILE_LOCAL=$tls_dir/tls/ca.crt
EASY_NODE_MTLS_CLIENT_CERT_FILE_LOCAL=$tls_dir/tls/client.crt
EASY_NODE_MTLS_CLIENT_KEY_FILE_LOCAL=$tls_dir/tls/client.key
MTLS_CERT_FILE=$tls_dir/tls/node.crt
MTLS_KEY_FILE=$tls_dir/tls/node.key
ENTRY_LIVE_WG_MODE=1
WG_BACKEND=command
EXIT_WG_INTERFACE=wgeprod00
EXIT_WG_PRIVATE_KEY_PATH=$wg_key_file
EXIT_WG_AUTO_CREATE_INTERFACE=1
EXIT_WG_KERNEL_PROXY=1
EXIT_LIVE_WG_MODE=1
EXIT_OPAQUE_SINK_ADDR=127.0.0.1:51982
EXIT_OPAQUE_SOURCE_ADDR=127.0.0.1:51983
EXIT_ISSUER_MIN_SOURCES=2
EXIT_ISSUER_MIN_OPERATORS=2
EXIT_ISSUER_REQUIRE_ID=1
ISSUER_URLS=https://203.0.113.10:8082,https://198.51.100.11:8082
DIRECTORY_ISSUER_TRUST_URLS=https://203.0.113.10:8082,https://198.51.100.11:8082
ENTRY_EXIT_USER=0:0
ENTRY_EXIT_PRIVILEGED=true
ISSUER_ADMIN_REQUIRE_SIGNED=1
ISSUER_ADMIN_ALLOW_TOKEN=0
DIRECTORY_ADMIN_TOKEN=prod-directory-admin-token-1234567890
ENTRY_PUZZLE_SECRET=prod-entry-puzzle-secret-1234567890
ENTRY_OPEN_RPS=12
ENTRY_BAN_THRESHOLD=3
ENTRY_BAN_SEC=90
ENTRY_MAX_CONCURRENT_OPENS=96
DIRECTORY_PEER_DISPUTE_MIN_VOTES=2
DIRECTORY_PEER_APPEAL_MIN_VOTES=2
DIRECTORY_ADJUDICATION_META_MIN_VOTES=2
DIRECTORY_FINAL_DISPUTE_MIN_VOTES=2
DIRECTORY_FINAL_APPEAL_MIN_VOTES=2
DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS=2
DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES=2
DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO=0.67
DIRECTORY_DISPUTE_MAX_TTL_SEC=259200
DIRECTORY_APPEAL_MAX_TTL_SEC=259200
EOF_ENV
chmod 600 "$AUTH_ENV" 2>/dev/null || true

cat >"$MODE_FILE" <<'EOF_MODE'
EASY_NODE_SERVER_MODE=authority
EOF_MODE

./scripts/easy_node.sh admin-signing-rotate --restart-issuer 0 --key-history 2 >/tmp/integration_prod_preflight_rotate.log 2>&1
./scripts/easy_node.sh admin-signing-status >/tmp/integration_prod_preflight_status.log 2>&1
./scripts/easy_node.sh prod-preflight --days-min 0 >/tmp/integration_prod_preflight_ok.log 2>&1

if rg -q '^EXIT_WG_PUBKEY=' "$AUTH_ENV"; then
  sed -i -E 's/^EXIT_WG_PUBKEY=.*/EXIT_WG_PUBKEY=invalid-wg-pubkey/' "$AUTH_ENV"
else
  echo "EXIT_WG_PUBKEY=invalid-wg-pubkey" >>"$AUTH_ENV"
fi
if ./scripts/easy_node.sh prod-preflight --days-min 0 >/tmp/integration_prod_preflight_wg_pub_fail.log 2>&1; then
  echo "expected prod-preflight to fail when EXIT_WG_PUBKEY is malformed"
  cat /tmp/integration_prod_preflight_wg_pub_fail.log
  exit 1
fi
if ! rg -q "EXIT_WG_PUBKEY invalid; must be a valid WireGuard public key or unset for runtime derivation" /tmp/integration_prod_preflight_wg_pub_fail.log; then
  echo "missing expected EXIT_WG_PUBKEY malformed failure signal in prod-preflight output"
  cat /tmp/integration_prod_preflight_wg_pub_fail.log
  exit 1
fi
sed -i -E 's/^EXIT_WG_PUBKEY=.*/EXIT_WG_PUBKEY=/' "$AUTH_ENV"

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

sed -i -E 's/^ENTRY_OPEN_RPS=.*/ENTRY_OPEN_RPS=50/' "$AUTH_ENV"
if ./scripts/easy_node.sh prod-preflight --days-min 0 >/tmp/integration_prod_preflight_entry_rps_fail.log 2>&1; then
  echo "expected prod-preflight to fail when ENTRY_OPEN_RPS is too high"
  cat /tmp/integration_prod_preflight_entry_rps_fail.log
  exit 1
fi
if ! rg -q "ENTRY_OPEN_RPS must be set in range 1..12 in prod profile" /tmp/integration_prod_preflight_entry_rps_fail.log; then
  echo "missing expected entry open rps failure signal in prod-preflight output"
  cat /tmp/integration_prod_preflight_entry_rps_fail.log
  exit 1
fi
sed -i -E 's/^ENTRY_OPEN_RPS=.*/ENTRY_OPEN_RPS=12/' "$AUTH_ENV"

sed -i -E 's/^DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO=.*/DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO=0.50/' "$AUTH_ENV"
if ./scripts/easy_node.sh prod-preflight --days-min 0 >/tmp/integration_prod_preflight_ratio_fail.log 2>&1; then
  echo "expected prod-preflight to fail with weak DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO"
  cat /tmp/integration_prod_preflight_ratio_fail.log
  exit 1
fi
if ! rg -q "DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO must be >=0.67 in prod profile" /tmp/integration_prod_preflight_ratio_fail.log; then
  echo "missing expected final adjudication ratio failure signal in prod-preflight output"
  cat /tmp/integration_prod_preflight_ratio_fail.log
  exit 1
fi
sed -i -E 's/^DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO=.*/DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO=0.67/' "$AUTH_ENV"

sed -i -E 's/^DIRECTORY_FINAL_DISPUTE_MIN_VOTES=.*/DIRECTORY_FINAL_DISPUTE_MIN_VOTES=1/' "$AUTH_ENV"
if ./scripts/easy_node.sh prod-preflight --days-min 0 >/tmp/integration_prod_preflight_final_dispute_fail.log 2>&1; then
  echo "expected prod-preflight to fail with weak DIRECTORY_FINAL_DISPUTE_MIN_VOTES"
  cat /tmp/integration_prod_preflight_final_dispute_fail.log
  exit 1
fi
if ! rg -q "DIRECTORY_FINAL_DISPUTE_MIN_VOTES must be >=2 in prod profile" /tmp/integration_prod_preflight_final_dispute_fail.log; then
  echo "missing expected final dispute vote floor failure signal in prod-preflight output"
  cat /tmp/integration_prod_preflight_final_dispute_fail.log
  exit 1
fi
sed -i -E 's/^DIRECTORY_FINAL_DISPUTE_MIN_VOTES=.*/DIRECTORY_FINAL_DISPUTE_MIN_VOTES=2/' "$AUTH_ENV"

sed -i -E 's/^DIRECTORY_DISPUTE_MAX_TTL_SEC=.*/DIRECTORY_DISPUTE_MAX_TTL_SEC=604800/' "$AUTH_ENV"
if ./scripts/easy_node.sh prod-preflight --days-min 0 >/tmp/integration_prod_preflight_dispute_ttl_fail.log 2>&1; then
  echo "expected prod-preflight to fail with oversized DIRECTORY_DISPUTE_MAX_TTL_SEC"
  cat /tmp/integration_prod_preflight_dispute_ttl_fail.log
  exit 1
fi
if ! rg -q "DIRECTORY_DISPUTE_MAX_TTL_SEC must be set in range 1..259200 in prod profile" /tmp/integration_prod_preflight_dispute_ttl_fail.log; then
  echo "missing expected dispute ttl cap failure signal in prod-preflight output"
  cat /tmp/integration_prod_preflight_dispute_ttl_fail.log
  exit 1
fi
sed -i -E 's/^DIRECTORY_DISPUTE_MAX_TTL_SEC=.*/DIRECTORY_DISPUTE_MAX_TTL_SEC=259200/' "$AUTH_ENV"

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
  local issuer_urls="${4:-https://issuer.example:8082,https://issuer2.example:8082}"
  cat >"$PROVIDER_ENV" <<EOF_PROVIDER
PROD_STRICT_MODE=1
BETA_STRICT_MODE=1
MTLS_ENABLE=1
DATA_PLANE_MODE=opaque
DIRECTORY_PUBLIC_URL=https://203.0.113.20:8081
ENTRY_URL_PUBLIC=https://203.0.113.20:8083
EXIT_CONTROL_URL_PUBLIC=https://203.0.113.20:8084
EASY_NODE_MTLS_CA_FILE_LOCAL=$tls_dir/tls/ca.crt
EASY_NODE_MTLS_CLIENT_CERT_FILE_LOCAL=$tls_dir/tls/client.crt
EASY_NODE_MTLS_CLIENT_KEY_FILE_LOCAL=$tls_dir/tls/client.key
MTLS_CERT_FILE=$tls_dir/tls/node.crt
MTLS_KEY_FILE=$tls_dir/tls/node.key
ENTRY_LIVE_WG_MODE=1
WG_BACKEND=command
EXIT_WG_INTERFACE=wgeprod01
EXIT_WG_PRIVATE_KEY_PATH=$wg_key_file
EXIT_WG_AUTO_CREATE_INTERFACE=1
EXIT_WG_KERNEL_PROXY=1
EXIT_LIVE_WG_MODE=1
EXIT_OPAQUE_SINK_ADDR=127.0.0.1:51982
EXIT_OPAQUE_SOURCE_ADDR=127.0.0.1:51983
EXIT_ISSUER_MIN_SOURCES=2
EXIT_ISSUER_MIN_OPERATORS=2
EXIT_ISSUER_REQUIRE_ID=1
ISSUER_URLS=$issuer_urls
DIRECTORY_ISSUER_TRUST_URLS=$issuer_urls
ENTRY_EXIT_USER=0:0
ENTRY_EXIT_PRIVILEGED=true
DIRECTORY_ADMIN_TOKEN=prod-provider-directory-admin-token-1234567890
ENTRY_PUZZLE_SECRET=prod-provider-entry-puzzle-secret-1234567890
ENTRY_OPEN_RPS=12
ENTRY_BAN_THRESHOLD=3
ENTRY_BAN_SEC=90
ENTRY_MAX_CONCURRENT_OPENS=96
DIRECTORY_PEER_DISPUTE_MIN_VOTES=2
DIRECTORY_PEER_APPEAL_MIN_VOTES=2
DIRECTORY_ADJUDICATION_META_MIN_VOTES=2
DIRECTORY_FINAL_DISPUTE_MIN_VOTES=2
DIRECTORY_FINAL_APPEAL_MIN_VOTES=2
DIRECTORY_FINAL_ADJUDICATION_MIN_OPERATORS=2
DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES=2
DIRECTORY_FINAL_ADJUDICATION_MIN_RATIO=0.67
DIRECTORY_DISPUTE_MAX_TTL_SEC=259200
DIRECTORY_APPEAL_MAX_TTL_SEC=259200
CORE_ISSUER_URL=$core_issuer
ISSUER_ADMIN_TOKEN=$admin_token
ISSUER_ADMIN_SIGNING_KEY_ID=$sign_key_id
EOF_PROVIDER
  chmod 600 "$PROVIDER_ENV" 2>/dev/null || true
}

live_curl_mock_dir="$(mktemp -d)"
cat >"$live_curl_mock_dir/curl" <<'EOF_CURL_MOCK'
#!/usr/bin/env bash
set -euo pipefail
out_file=""
write_fmt=""
url=""
idx=1
while [[ $idx -le $# ]]; do
  arg="${!idx}"
  case "$arg" in
    -o)
      idx=$((idx + 1))
      out_file="${!idx:-}"
      ;;
    -w)
      idx=$((idx + 1))
      write_fmt="${!idx:-}"
      ;;
    http://*|https://*)
      url="$arg"
      ;;
  esac
  idx=$((idx + 1))
done

policy_mode="${EASY_NODE_CURL_MOCK_POLICY_MODE:-good}"
federation_mode="${EASY_NODE_CURL_MOCK_FEDERATION_MODE:-healthy}"
sync_mode="${EASY_NODE_CURL_MOCK_SYNC_MODE:-fresh}"
code="200"
body='{}'
case "$url" in
  */v1/relays)
    body='{"relays":[]}'
    ;;
  */v1/health)
    body='{"ok":true}'
    ;;
  */v1/pubkeys)
    body='{"issuer":"issuer-main","pub_keys":["pk1"]}'
    ;;
  */v1/admin/governance-status)
    if [[ "$policy_mode" == "weak" ]]; then
      body='{"policy":{"meta_min_votes":1,"final_dispute_min_votes":1,"final_appeal_min_votes":1,"final_adjudication_min_operators":1,"final_adjudication_min_sources":1,"final_adjudication_min_ratio":0.5}}'
    else
      body='{"policy":{"meta_min_votes":2,"final_dispute_min_votes":2,"final_appeal_min_votes":2,"final_adjudication_min_operators":2,"final_adjudication_min_sources":2,"final_adjudication_min_ratio":0.67}}'
    fi
    ;;
  */v1/admin/sync-status)
    if [[ "$sync_mode" == "stale" ]]; then
      body='{"generated_at":1731000001,"peer":{"success":true,"quorum_met":true,"success_sources":1,"source_operators":["op-sync-peer"],"last_run_at":1730999800},"issuer":{"success":true,"quorum_met":true,"success_sources":1,"source_operators":["op-sync-issuer"],"last_run_at":1730999700}}'
    else
      body='{"generated_at":1731000001,"peer":{"success":true,"quorum_met":true,"success_sources":1,"source_operators":["op-sync-peer"],"last_run_at":1731000000},"issuer":{"success":true,"quorum_met":true,"success_sources":1,"source_operators":["op-sync-issuer"],"last_run_at":1731000000}}'
    fi
    ;;
  */v1/admin/peer-status)
    if [[ "$federation_mode" == "degraded" ]]; then
      body='{"peers":[{"url":"https://seed-a.example:8081","configured":true,"discovered":false,"eligible":true,"cooling_down":false,"consecutive_failures":3},{"url":"https://seed-b.example:8081","configured":false,"discovered":true,"eligible":true,"cooling_down":false,"consecutive_failures":0},{"url":"https://seed-c.example:8081","configured":false,"discovered":true,"eligible":false,"cooling_down":true,"consecutive_failures":4,"retry_after_sec":75}]}'
    else
      body='{"peers":[{"url":"https://seed-a.example:8081","configured":true,"discovered":false,"eligible":true,"cooling_down":false,"consecutive_failures":0},{"url":"https://seed-b.example:8081","configured":false,"discovered":true,"eligible":true,"cooling_down":false,"consecutive_failures":0}]}'
    fi
    ;;
  */v1/admin/subject/get*)
    code="401"
    body='unauthorized'
    ;;
esac

if [[ -n "$out_file" ]]; then
  printf '%s' "$body" >"$out_file"
else
  printf '%s' "$body"
fi
if [[ -n "$write_fmt" ]]; then
  printf '%s' "$code"
fi
if [[ "$code" -ge 400 && "$*" == *" -f"* ]]; then
  exit 22
fi
exit 0
EOF_CURL_MOCK
chmod +x "$live_curl_mock_dir/curl"

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

write_provider_env_file "https://issuer.example:8082"
PATH="$live_curl_mock_dir:$PATH" EASY_NODE_CURL_MOCK_POLICY_MODE=good \
  ./scripts/easy_node.sh prod-preflight --days-min 0 --check-live 1 --timeout-sec 1 >/tmp/integration_prod_preflight_provider_live_governance_ok.log 2>&1

if PATH="$live_curl_mock_dir:$PATH" EASY_NODE_CURL_MOCK_POLICY_MODE=weak \
  ./scripts/easy_node.sh prod-preflight --days-min 0 --check-live 1 --timeout-sec 1 >/tmp/integration_prod_preflight_provider_live_governance_fail.log 2>&1; then
  echo "expected provider prod-preflight live governance check to fail with weak policy"
  cat /tmp/integration_prod_preflight_provider_live_governance_fail.log
  exit 1
fi
if ! rg -q "live governance policy too weak: meta_min_votes must be >=2" /tmp/integration_prod_preflight_provider_live_governance_fail.log; then
  echo "missing expected live governance policy floor failure signal"
  cat /tmp/integration_prod_preflight_provider_live_governance_fail.log
  exit 1
fi

if PATH="$live_curl_mock_dir:$PATH" EASY_NODE_CURL_MOCK_POLICY_MODE=good EASY_NODE_CURL_MOCK_FEDERATION_MODE=degraded \
  ./scripts/easy_node.sh prod-preflight --days-min 0 --check-live 1 --timeout-sec 1 --live-require-configured-healthy 1 >/tmp/integration_prod_preflight_provider_live_configured_strict_fail.log 2>&1; then
  echo "expected provider prod-preflight strict configured peer gate to fail with degraded configured peer health"
  cat /tmp/integration_prod_preflight_provider_live_configured_strict_fail.log
  exit 1
fi
if ! rg -q "live configured peer health degraded: all configured peers must be healthy when --live-require-configured-healthy=1" /tmp/integration_prod_preflight_provider_live_configured_strict_fail.log; then
  echo "missing expected strict configured peer health failure signal"
  cat /tmp/integration_prod_preflight_provider_live_configured_strict_fail.log
  exit 1
fi

if PATH="$live_curl_mock_dir:$PATH" EASY_NODE_CURL_MOCK_POLICY_MODE=good EASY_NODE_CURL_MOCK_FEDERATION_MODE=degraded \
  ./scripts/easy_node.sh prod-preflight --days-min 0 --check-live 1 --timeout-sec 1 --live-max-cooling-retry-sec 60 >/tmp/integration_prod_preflight_provider_live_cooling_retry_fail.log 2>&1; then
  echo "expected provider prod-preflight cooling retry threshold gate to fail when retry_after is too high"
  cat /tmp/integration_prod_preflight_provider_live_cooling_retry_fail.log
  exit 1
fi
if ! rg -q "live cooling retry window too high: observed 75s exceeds threshold 60s" /tmp/integration_prod_preflight_provider_live_cooling_retry_fail.log; then
  echo "missing expected cooling retry threshold failure signal"
  cat /tmp/integration_prod_preflight_provider_live_cooling_retry_fail.log
  exit 1
fi

if PATH="$live_curl_mock_dir:$PATH" EASY_NODE_CURL_MOCK_POLICY_MODE=good EASY_NODE_CURL_MOCK_FEDERATION_MODE=healthy EASY_NODE_CURL_MOCK_SYNC_MODE=stale \
  ./scripts/easy_node.sh prod-preflight --days-min 0 --check-live 1 --timeout-sec 1 --live-max-peer-sync-age-sec 120 >/tmp/integration_prod_preflight_provider_live_peer_sync_age_fail.log 2>&1; then
  echo "expected provider prod-preflight peer-sync freshness gate to fail on stale sync age"
  cat /tmp/integration_prod_preflight_provider_live_peer_sync_age_fail.log
  exit 1
fi
if ! rg -q "live peer-sync freshness too old: age=201s threshold=120s" /tmp/integration_prod_preflight_provider_live_peer_sync_age_fail.log; then
  echo "missing expected peer-sync freshness failure signal"
  cat /tmp/integration_prod_preflight_provider_live_peer_sync_age_fail.log
  exit 1
fi

if PATH="$live_curl_mock_dir:$PATH" EASY_NODE_CURL_MOCK_POLICY_MODE=good EASY_NODE_CURL_MOCK_FEDERATION_MODE=healthy EASY_NODE_CURL_MOCK_SYNC_MODE=stale \
  ./scripts/easy_node.sh prod-preflight --days-min 0 --check-live 1 --timeout-sec 1 --live-max-issuer-sync-age-sec 120 >/tmp/integration_prod_preflight_provider_live_issuer_sync_age_fail.log 2>&1; then
  echo "expected provider prod-preflight issuer-sync freshness gate to fail on stale sync age"
  cat /tmp/integration_prod_preflight_provider_live_issuer_sync_age_fail.log
  exit 1
fi
if ! rg -q "live issuer-sync freshness too old: age=301s threshold=120s" /tmp/integration_prod_preflight_provider_live_issuer_sync_age_fail.log; then
  echo "missing expected issuer-sync freshness failure signal"
  cat /tmp/integration_prod_preflight_provider_live_issuer_sync_age_fail.log
  exit 1
fi

if PATH="$live_curl_mock_dir:$PATH" EASY_NODE_CURL_MOCK_POLICY_MODE=good EASY_NODE_CURL_MOCK_FEDERATION_MODE=healthy EASY_NODE_CURL_MOCK_SYNC_MODE=fresh \
  ./scripts/easy_node.sh prod-preflight --days-min 0 --check-live 1 --timeout-sec 1 --live-min-peer-success-sources 2 >/tmp/integration_prod_preflight_provider_live_peer_sources_fail.log 2>&1; then
  echo "expected provider prod-preflight peer success-sources floor to fail when observed sources are below threshold"
  cat /tmp/integration_prod_preflight_provider_live_peer_sources_fail.log
  exit 1
fi
if ! rg -q "live peer-sync success_sources too low: observed 1 required 2" /tmp/integration_prod_preflight_provider_live_peer_sources_fail.log; then
  echo "missing expected peer success-sources floor failure signal"
  cat /tmp/integration_prod_preflight_provider_live_peer_sources_fail.log
  exit 1
fi

if PATH="$live_curl_mock_dir:$PATH" EASY_NODE_CURL_MOCK_POLICY_MODE=good EASY_NODE_CURL_MOCK_FEDERATION_MODE=healthy EASY_NODE_CURL_MOCK_SYNC_MODE=fresh \
  ./scripts/easy_node.sh prod-preflight --days-min 0 --check-live 1 --timeout-sec 1 --live-min-issuer-success-sources 2 >/tmp/integration_prod_preflight_provider_live_issuer_sources_fail.log 2>&1; then
  echo "expected provider prod-preflight issuer success-sources floor to fail when observed sources are below threshold"
  cat /tmp/integration_prod_preflight_provider_live_issuer_sources_fail.log
  exit 1
fi
if ! rg -q "live issuer-sync success_sources too low: observed 1 required 2" /tmp/integration_prod_preflight_provider_live_issuer_sources_fail.log; then
  echo "missing expected issuer success-sources floor failure signal"
  cat /tmp/integration_prod_preflight_provider_live_issuer_sources_fail.log
  exit 1
fi

if PATH="$live_curl_mock_dir:$PATH" EASY_NODE_CURL_MOCK_POLICY_MODE=good EASY_NODE_CURL_MOCK_FEDERATION_MODE=healthy EASY_NODE_CURL_MOCK_SYNC_MODE=fresh \
  ./scripts/easy_node.sh prod-preflight --days-min 0 --check-live 1 --timeout-sec 1 --live-min-peer-source-operators 2 >/tmp/integration_prod_preflight_provider_live_peer_source_operators_fail.log 2>&1; then
  echo "expected provider prod-preflight peer source-operators floor to fail when observed operators are below threshold"
  cat /tmp/integration_prod_preflight_provider_live_peer_source_operators_fail.log
  exit 1
fi
if ! rg -q "live peer-sync source_operators too low: observed 1 required 2" /tmp/integration_prod_preflight_provider_live_peer_source_operators_fail.log; then
  echo "missing expected peer source-operators floor failure signal"
  cat /tmp/integration_prod_preflight_provider_live_peer_source_operators_fail.log
  exit 1
fi

if PATH="$live_curl_mock_dir:$PATH" EASY_NODE_CURL_MOCK_POLICY_MODE=good EASY_NODE_CURL_MOCK_FEDERATION_MODE=healthy EASY_NODE_CURL_MOCK_SYNC_MODE=fresh \
  ./scripts/easy_node.sh prod-preflight --days-min 0 --check-live 1 --timeout-sec 1 --live-min-issuer-source-operators 2 >/tmp/integration_prod_preflight_provider_live_issuer_source_operators_fail.log 2>&1; then
  echo "expected provider prod-preflight issuer source-operators floor to fail when observed operators are below threshold"
  cat /tmp/integration_prod_preflight_provider_live_issuer_source_operators_fail.log
  exit 1
fi
if ! rg -q "live issuer-sync source_operators too low: observed 1 required 2" /tmp/integration_prod_preflight_provider_live_issuer_source_operators_fail.log; then
  echo "missing expected issuer source-operators floor failure signal"
  cat /tmp/integration_prod_preflight_provider_live_issuer_source_operators_fail.log
  exit 1
fi

echo "prod preflight/admin-signing integration check ok"
