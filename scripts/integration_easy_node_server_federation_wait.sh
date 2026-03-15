#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in rg jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

AUTH_ENV="$ROOT_DIR/deploy/.env.easy.server"
PROVIDER_ENV="$ROOT_DIR/deploy/.env.easy.provider"
MODE_FILE="$ROOT_DIR/deploy/data/easy_node_server_mode.conf"

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

restore_file() {
  local dst="$1"
  local name="$2"
  if [[ -f "$TMP_DIR/${name}.bak" ]]; then
    cp "$TMP_DIR/${name}.bak" "$dst"
  else
    rm -f "$dst"
  fi
}

cleanup() {
  restore_file "$AUTH_ENV" "auth_env"
  restore_file "$PROVIDER_ENV" "provider_env"
  restore_file "$MODE_FILE" "mode_file"
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

backup_file "$AUTH_ENV" "auth_env"
backup_file "$PROVIDER_ENV" "provider_env"
backup_file "$MODE_FILE" "mode_file"

mkdir -p "$(dirname "$AUTH_ENV")" "$(dirname "$MODE_FILE")"
cat >"$AUTH_ENV" <<'EOF_ENV'
EASY_NODE_SERVER_MODE=authority
DIRECTORY_PUBLIC_URL=http://203.0.113.10:8081
DIRECTORY_ADMIN_TOKEN=test-admin-token
EOF_ENV
cat >"$MODE_FILE" <<'EOF_MODE'
EASY_NODE_SERVER_MODE=authority
EOF_MODE

cat >"$TMP_BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail

output_file=""
write_fmt=""
url=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o)
      output_file="${2:-}"
      shift 2
      ;;
    -w)
      write_fmt="${2:-}"
      shift 2
      ;;
    http://*|https://*)
      url="$1"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

mode="${EASY_NODE_CURL_MOCK_MODE:-degraded}"
sync_mode="${EASY_NODE_CURL_MOCK_SYNC_MODE:-fresh}"
payload='{}'
code="200"
case "$url" in
  */v1/admin/sync-status)
    if [[ "$sync_mode" == "stale" ]]; then
      payload='{"generated_at":1731000001,"peer":{"success":true,"success_sources":1,"source_operators":["op-sync-peer"],"required_operators":1,"quorum_met":true,"last_run_at":1730999800},"issuer":{"success":true,"success_sources":1,"source_operators":["op-sync-issuer"],"required_operators":1,"quorum_met":true,"last_run_at":1730999700}}'
    else
      payload='{"generated_at":1731000001,"peer":{"success":true,"success_sources":1,"source_operators":["op-sync-peer"],"required_operators":1,"quorum_met":true,"last_run_at":1731000000},"issuer":{"success":true,"success_sources":1,"source_operators":["op-sync-issuer"],"required_operators":1,"quorum_met":true,"last_run_at":1731000000}}'
    fi
    ;;
  */v1/admin/peer-status)
    if [[ "$mode" == "healthy" ]]; then
      payload='{"generated_at":1731000000,"peers":[{"url":"http://seed.local","configured":true,"discovered":false,"eligible":true,"cooling_down":false,"consecutive_failures":0},{"url":"http://peer-alt.local","configured":false,"discovered":true,"eligible":true,"cooling_down":false,"consecutive_failures":0}]}'
    else
      payload='{"generated_at":1731000000,"peers":[{"url":"http://seed.local","configured":true,"discovered":false,"eligible":true,"cooling_down":false,"consecutive_failures":3,"last_error":"connect refused"},{"url":"http://peer-alt.local","configured":false,"discovered":true,"eligible":true,"cooling_down":false,"consecutive_failures":0},{"url":"http://peer-cool.local","configured":false,"discovered":true,"eligible":false,"cooling_down":true,"consecutive_failures":4,"retry_after_sec":75,"last_error":"dial timeout"}]}'
    fi
    ;;
  *)
    payload='{"error":"not found"}'
    code="404"
    ;;
esac

if [[ -n "$output_file" ]]; then
  printf '%s\n' "$payload" >"$output_file"
else
  printf '%s\n' "$payload"
fi
if [[ -n "$write_fmt" ]]; then
  printf '%s' "$code"
fi
exit 0
EOF_CURL
sed -i 's/\r$//' "$TMP_BIN/curl"
chmod +x "$TMP_BIN/curl"

echo "[server-federation-wait] default readiness allows discovered fallback"
READY_LOG="$TMP_DIR/federation_wait_ready.log"
if ! PATH="$TMP_BIN:$PATH" EASY_NODE_CURL_MOCK_MODE=degraded \
  ./scripts/easy_node.sh server-federation-wait \
    --ready-timeout-sec 3 \
    --poll-sec 1 \
    --timeout-sec 3 >"$READY_LOG" 2>&1; then
  echo "expected default server-federation-wait to succeed with discovered fallback"
  cat "$READY_LOG"
  exit 1
fi
if ! rg -q '^server-federation-wait: READY' "$READY_LOG"; then
  echo "expected READY output in default federation wait"
  cat "$READY_LOG"
  exit 1
fi
if ! rg -q 'configured_failing=1' "$READY_LOG"; then
  echo "expected configured_failing marker in READY output"
  cat "$READY_LOG"
  exit 1
fi

echo "[server-federation-wait] strict configured-healthy gate fails closed"
STRICT_LOG="$TMP_DIR/federation_wait_strict.log"
if PATH="$TMP_BIN:$PATH" EASY_NODE_CURL_MOCK_MODE=degraded \
  ./scripts/easy_node.sh server-federation-wait \
    --require-configured-healthy 1 \
    --ready-timeout-sec 2 \
    --poll-sec 1 \
    --timeout-sec 3 >"$STRICT_LOG" 2>&1; then
  echo "expected strict configured-healthy federation wait to fail"
  cat "$STRICT_LOG"
  exit 1
fi
if ! rg -q '^server-federation-wait: TIMEOUT' "$STRICT_LOG"; then
  echo "expected TIMEOUT output for strict configured-healthy gate"
  cat "$STRICT_LOG"
  exit 1
fi
if ! rg -q 'peer_health_ready=0' "$STRICT_LOG"; then
  echo "expected peer_health_ready=0 in strict configured-healthy failure"
  cat "$STRICT_LOG"
  exit 1
fi

echo "[server-federation-wait] cooling retry threshold fail-close"
COOLING_LOG="$TMP_DIR/federation_wait_cooling.log"
if PATH="$TMP_BIN:$PATH" EASY_NODE_CURL_MOCK_MODE=degraded \
  ./scripts/easy_node.sh server-federation-wait \
    --max-cooling-retry-sec 60 \
    --ready-timeout-sec 10 \
    --poll-sec 1 \
    --timeout-sec 3 \
    --show-json 1 >"$COOLING_LOG" 2>&1; then
  echo "expected cooling retry threshold federation wait to fail"
  cat "$COOLING_LOG"
  exit 1
fi
if ! rg -q 'FAIL cooling retry window exceeds threshold' "$COOLING_LOG"; then
  echo "expected cooling threshold failure message"
  cat "$COOLING_LOG"
  exit 1
fi
if ! rg -q '^json:$' "$COOLING_LOG"; then
  echo "expected show-json marker for cooling threshold failure"
  cat "$COOLING_LOG"
  exit 1
fi
if ! rg -q '"retry_after_sec": 75' "$COOLING_LOG"; then
  echo "expected retry_after_sec detail in cooling threshold JSON payload"
  cat "$COOLING_LOG"
  exit 1
fi

echo "[server-federation-wait] peer success-sources floor fails closed"
PEER_SOURCES_LOG="$TMP_DIR/federation_wait_peer_sources.log"
if PATH="$TMP_BIN:$PATH" EASY_NODE_CURL_MOCK_MODE=healthy EASY_NODE_CURL_MOCK_SYNC_MODE=fresh \
  ./scripts/easy_node.sh server-federation-wait \
    --min-peer-success-sources 2 \
    --ready-timeout-sec 2 \
    --poll-sec 1 \
    --timeout-sec 3 >"$PEER_SOURCES_LOG" 2>&1; then
  echo "expected peer success-sources floor to fail when observed sources are below threshold"
  cat "$PEER_SOURCES_LOG"
  exit 1
fi
if ! rg -q 'peer_sync_ready=0' "$PEER_SOURCES_LOG"; then
  echo "expected peer_sync_ready=0 for peer success-sources floor failure"
  cat "$PEER_SOURCES_LOG"
  exit 1
fi
if ! rg -q 'success_sources=1' "$PEER_SOURCES_LOG"; then
  echo "expected peer success_sources marker in peer success-sources failure output"
  cat "$PEER_SOURCES_LOG"
  exit 1
fi

echo "[server-federation-wait] peer source-operators floor fails closed"
PEER_SOURCE_OPS_LOG="$TMP_DIR/federation_wait_peer_source_operators.log"
if PATH="$TMP_BIN:$PATH" EASY_NODE_CURL_MOCK_MODE=healthy EASY_NODE_CURL_MOCK_SYNC_MODE=fresh \
  ./scripts/easy_node.sh server-federation-wait \
    --min-peer-source-operators 2 \
    --ready-timeout-sec 2 \
    --poll-sec 1 \
    --timeout-sec 3 >"$PEER_SOURCE_OPS_LOG" 2>&1; then
  echo "expected peer source-operators floor to fail when observed source operators are below threshold"
  cat "$PEER_SOURCE_OPS_LOG"
  exit 1
fi
if ! rg -q 'peer_sync_ready=0' "$PEER_SOURCE_OPS_LOG"; then
  echo "expected peer_sync_ready=0 for peer source-operators floor failure"
  cat "$PEER_SOURCE_OPS_LOG"
  exit 1
fi
if ! rg -q 'source_operator_count=1' "$PEER_SOURCE_OPS_LOG"; then
  echo "expected peer source_operator_count marker in source-operators failure output"
  cat "$PEER_SOURCE_OPS_LOG"
  exit 1
fi

echo "[server-federation-wait] issuer success-sources floor fails closed"
ISSUER_SOURCES_LOG="$TMP_DIR/federation_wait_issuer_sources.log"
if PATH="$TMP_BIN:$PATH" EASY_NODE_CURL_MOCK_MODE=healthy EASY_NODE_CURL_MOCK_SYNC_MODE=fresh \
  ./scripts/easy_node.sh server-federation-wait \
    --min-issuer-success-sources 2 \
    --ready-timeout-sec 2 \
    --poll-sec 1 \
    --timeout-sec 3 >"$ISSUER_SOURCES_LOG" 2>&1; then
  echo "expected issuer success-sources floor to fail when observed sources are below threshold"
  cat "$ISSUER_SOURCES_LOG"
  exit 1
fi
if ! rg -q 'issuer_sync_ready=0' "$ISSUER_SOURCES_LOG"; then
  echo "expected issuer_sync_ready=0 for issuer success-sources floor failure"
  cat "$ISSUER_SOURCES_LOG"
  exit 1
fi
if ! rg -q 'success_sources=1' "$ISSUER_SOURCES_LOG"; then
  echo "expected issuer success_sources marker in issuer success-sources failure output"
  cat "$ISSUER_SOURCES_LOG"
  exit 1
fi

echo "[server-federation-wait] issuer source-operators floor fails closed"
ISSUER_SOURCE_OPS_LOG="$TMP_DIR/federation_wait_issuer_source_operators.log"
if PATH="$TMP_BIN:$PATH" EASY_NODE_CURL_MOCK_MODE=healthy EASY_NODE_CURL_MOCK_SYNC_MODE=fresh \
  ./scripts/easy_node.sh server-federation-wait \
    --min-issuer-source-operators 2 \
    --ready-timeout-sec 2 \
    --poll-sec 1 \
    --timeout-sec 3 >"$ISSUER_SOURCE_OPS_LOG" 2>&1; then
  echo "expected issuer source-operators floor to fail when observed source operators are below threshold"
  cat "$ISSUER_SOURCE_OPS_LOG"
  exit 1
fi
if ! rg -q 'issuer_sync_ready=0' "$ISSUER_SOURCE_OPS_LOG"; then
  echo "expected issuer_sync_ready=0 for issuer source-operators floor failure"
  cat "$ISSUER_SOURCE_OPS_LOG"
  exit 1
fi
if ! rg -q 'source_operator_count=1' "$ISSUER_SOURCE_OPS_LOG"; then
  echo "expected issuer source_operator_count marker in source-operators failure output"
  cat "$ISSUER_SOURCE_OPS_LOG"
  exit 1
fi

echo "[server-federation-wait] stale peer-sync age threshold fails closed"
STALE_PEER_LOG="$TMP_DIR/federation_wait_stale_peer.log"
if PATH="$TMP_BIN:$PATH" EASY_NODE_CURL_MOCK_MODE=healthy EASY_NODE_CURL_MOCK_SYNC_MODE=stale \
  ./scripts/easy_node.sh server-federation-wait \
    --max-peer-sync-age-sec 60 \
    --ready-timeout-sec 2 \
    --poll-sec 1 \
    --timeout-sec 3 >"$STALE_PEER_LOG" 2>&1; then
  echo "expected stale peer-sync age gate to fail"
  cat "$STALE_PEER_LOG"
  exit 1
fi
if ! rg -q 'peer_sync_ready=0' "$STALE_PEER_LOG"; then
  echo "expected peer_sync_ready=0 for stale peer-sync age gate"
  cat "$STALE_PEER_LOG"
  exit 1
fi
if ! rg -q 'age_sec=201' "$STALE_PEER_LOG"; then
  echo "expected peer sync age marker in stale peer-sync failure output"
  cat "$STALE_PEER_LOG"
  exit 1
fi

echo "[server-federation-wait] stale issuer-sync age threshold fails closed"
STALE_ISSUER_LOG="$TMP_DIR/federation_wait_stale_issuer.log"
if PATH="$TMP_BIN:$PATH" EASY_NODE_CURL_MOCK_MODE=healthy EASY_NODE_CURL_MOCK_SYNC_MODE=stale \
  ./scripts/easy_node.sh server-federation-wait \
    --max-issuer-sync-age-sec 120 \
    --ready-timeout-sec 2 \
    --poll-sec 1 \
    --timeout-sec 3 >"$STALE_ISSUER_LOG" 2>&1; then
  echo "expected stale issuer-sync age gate to fail"
  cat "$STALE_ISSUER_LOG"
  exit 1
fi
if ! rg -q 'issuer_sync_ready=0' "$STALE_ISSUER_LOG"; then
  echo "expected issuer_sync_ready=0 for stale issuer-sync age gate"
  cat "$STALE_ISSUER_LOG"
  exit 1
fi
if ! rg -q 'age_sec=301' "$STALE_ISSUER_LOG"; then
  echo "expected issuer sync age marker in stale issuer-sync failure output"
  cat "$STALE_ISSUER_LOG"
  exit 1
fi

echo "easy-node server federation wait integration check ok"
