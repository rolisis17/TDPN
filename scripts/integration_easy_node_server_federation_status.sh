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

payload='{}'
code="200"
sync_mode="${EASY_NODE_CURL_MOCK_SYNC_MODE:-fresh}"
case "$url" in
  */v1/admin/peer-status)
    payload='{"generated_at":1731000000,"peers":[{"url":"http://seed.local","configured":true,"discovered":false,"eligible":true,"cooling_down":false,"consecutive_failures":0},{"url":"http://peer-down.local","configured":false,"discovered":true,"eligible":false,"cooling_down":true,"consecutive_failures":4,"cooldown_until":1731000099,"retry_after_sec":75,"last_error":"dial timeout"}]}'
    ;;
  */v1/admin/sync-status)
    if [[ "$sync_mode" == "issuer_optional" ]]; then
      payload='{"generated_at":1731000001,"peer":{"success":true,"success_sources":2,"source_operators":["op-peer-a","op-peer-b"],"required_operators":2,"quorum_met":true,"last_run_at":1731000000},"issuer":{"success":true,"success_sources":0,"source_operators":[],"required_operators":1,"quorum_met":false,"last_run_at":1730999999,"error":""}}'
    else
      payload='{"generated_at":1731000001,"peer":{"success":true,"success_sources":2,"source_operators":["op-peer-a","op-peer-b"],"required_operators":2,"quorum_met":true,"last_run_at":1731000000},"issuer":{"success":true,"success_sources":2,"source_operators":["op-issuer-a","op-issuer-b"],"required_operators":2,"quorum_met":true,"last_run_at":1730999999}}'
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

echo "[server-federation-status] human-readable output includes retry window"
HUMAN_LOG="$TMP_DIR/federation_status_human.log"
if ! PATH="$TMP_BIN:$PATH" \
  ./scripts/easy_node.sh server-federation-status \
    --timeout-sec 3 >"$HUMAN_LOG" 2>&1; then
  echo "server-federation-status command failed in human-readable mode"
  cat "$HUMAN_LOG"
  exit 1
fi

if ! rg -q 'peer_summary: .*cooling_retry_max_sec=75' "$HUMAN_LOG"; then
  echo "expected cooling_retry_max_sec in peer summary"
  cat "$HUMAN_LOG"
  exit 1
fi
if ! rg -q 'peer-down\.local.*retry_in_sec=75' "$HUMAN_LOG"; then
  echo "expected retry_in_sec in per-peer output"
  cat "$HUMAN_LOG"
  exit 1
fi
if ! rg -q 'peer_sync: .*last_run_at=1731000000 age_sec=1' "$HUMAN_LOG"; then
  echo "expected peer sync age/last_run output"
  cat "$HUMAN_LOG"
  exit 1
fi
if ! rg -q 'issuer_sync: .*last_run_at=1730999999 age_sec=2' "$HUMAN_LOG"; then
  echo "expected issuer sync age/last_run output"
  cat "$HUMAN_LOG"
  exit 1
fi
if ! rg -q 'peer_sync: .*source_operator_count=2' "$HUMAN_LOG"; then
  echo "expected peer source_operator_count marker in status output"
  cat "$HUMAN_LOG"
  exit 1
fi
if ! rg -q 'issuer_sync: .*source_operator_count=2' "$HUMAN_LOG"; then
  echo "expected issuer source_operator_count marker in status output"
  cat "$HUMAN_LOG"
  exit 1
fi
if ! rg -q '^  peer_sync_source_operators: op-peer-a,op-peer-b$' "$HUMAN_LOG"; then
  echo "expected peer source_operators list in status output"
  cat "$HUMAN_LOG"
  exit 1
fi
if ! rg -q '^  issuer_sync_source_operators: op-issuer-a,op-issuer-b$' "$HUMAN_LOG"; then
  echo "expected issuer source_operators list in status output"
  cat "$HUMAN_LOG"
  exit 1
fi

echo "[server-federation-status] issuer-sync optional baseline stays ready"
OPTIONAL_LOG="$TMP_DIR/federation_status_issuer_optional.log"
if ! PATH="$TMP_BIN:$PATH" EASY_NODE_CURL_MOCK_SYNC_MODE=issuer_optional \
  ./scripts/easy_node.sh server-federation-status \
    --timeout-sec 3 \
    --fail-on-not-ready 1 >"$OPTIONAL_LOG" 2>&1; then
  echo "expected issuer-optional server-federation-status to pass fail-on-not-ready policy"
  cat "$OPTIONAL_LOG"
  exit 1
fi
if ! rg -q 'readiness: federation_ready=1' "$OPTIONAL_LOG"; then
  echo "expected federation_ready=1 in issuer-optional status output"
  cat "$OPTIONAL_LOG"
  exit 1
fi
if rg -q 'issuer_sync_quorum_not_met' "$OPTIONAL_LOG"; then
  echo "did not expect issuer_sync_quorum_not_met when issuer sync is optional"
  cat "$OPTIONAL_LOG"
  exit 1
fi

echo "[server-federation-status] strict one-shot policy pass + summary artifact"
STRICT_OK_LOG="$TMP_DIR/federation_status_strict_ok.log"
STRICT_OK_SUMMARY="$TMP_DIR/federation_status_strict_ok_summary.json"
if ! PATH="$TMP_BIN:$PATH" \
  ./scripts/easy_node.sh server-federation-status \
    --timeout-sec 3 \
    --require-configured-healthy 1 \
    --max-cooling-retry-sec 90 \
    --max-peer-sync-age-sec 5 \
    --max-issuer-sync-age-sec 5 \
    --min-peer-success-sources 2 \
    --min-issuer-success-sources 2 \
    --min-peer-source-operators 2 \
    --min-issuer-source-operators 2 \
    --fail-on-not-ready 1 \
    --summary-json "$STRICT_OK_SUMMARY" \
    --print-summary-json 1 >"$STRICT_OK_LOG" 2>&1; then
  echo "expected strict server-federation-status policy check to pass"
  cat "$STRICT_OK_LOG"
  exit 1
fi
if ! rg -q '^server-federation-status policy check: PASS$' "$STRICT_OK_LOG"; then
  echo "expected policy PASS marker in strict status output"
  cat "$STRICT_OK_LOG"
  exit 1
fi
if ! rg -q '^summary_json:$' "$STRICT_OK_LOG"; then
  echo "expected printed summary JSON marker in strict status output"
  cat "$STRICT_OK_LOG"
  exit 1
fi
if [[ ! -f "$STRICT_OK_SUMMARY" ]]; then
  echo "expected strict status summary artifact file"
  cat "$STRICT_OK_LOG"
  exit 1
fi
if ! jq -e '.readiness.federation_ready == true' "$STRICT_OK_SUMMARY" >/dev/null; then
  echo "strict status summary expected readiness=true"
  cat "$STRICT_OK_SUMMARY"
  exit 1
fi
if ! jq -e '.policy.min_peer_source_operators == 2 and .policy.min_issuer_source_operators == 2 and .policy.fail_on_not_ready == true' "$STRICT_OK_SUMMARY" >/dev/null; then
  echo "strict status summary expected policy metadata"
  cat "$STRICT_OK_SUMMARY"
  exit 1
fi
if ! jq -e '.readiness.failure_reasons == [] and .readiness.failure_count == 0' "$STRICT_OK_SUMMARY" >/dev/null; then
  echo "strict status summary expected empty readiness failure reasons"
  cat "$STRICT_OK_SUMMARY"
  exit 1
fi

echo "[server-federation-status] strict one-shot policy fail-close"
STRICT_FAIL_LOG="$TMP_DIR/federation_status_strict_fail.log"
STRICT_FAIL_SUMMARY="$TMP_DIR/federation_status_strict_fail_summary.json"
if PATH="$TMP_BIN:$PATH" \
  ./scripts/easy_node.sh server-federation-status \
    --timeout-sec 3 \
    --min-peer-source-operators 3 \
    --fail-on-not-ready 1 \
    --summary-json "$STRICT_FAIL_SUMMARY" >"$STRICT_FAIL_LOG" 2>&1; then
  echo "expected strict server-federation-status policy check to fail when peer source operators are below floor"
  cat "$STRICT_FAIL_LOG"
  exit 1
fi
if ! rg -q '^server-federation-status policy check: FAIL$' "$STRICT_FAIL_LOG"; then
  echo "expected policy FAIL marker in strict status failure output"
  cat "$STRICT_FAIL_LOG"
  exit 1
fi
if ! rg -q 'readiness: federation_ready=0' "$STRICT_FAIL_LOG"; then
  echo "expected readiness=failure marker in strict status failure output"
  cat "$STRICT_FAIL_LOG"
  exit 1
fi
if ! rg -q '^  readiness_failure_reasons: peer_source_operators_below_floor$' "$STRICT_FAIL_LOG"; then
  echo "expected readiness_failure_reasons marker in strict status failure output"
  cat "$STRICT_FAIL_LOG"
  exit 1
fi
if [[ ! -f "$STRICT_FAIL_SUMMARY" ]]; then
  echo "expected strict-fail status summary artifact file"
  cat "$STRICT_FAIL_LOG"
  exit 1
fi
if ! jq -e '.readiness.federation_ready == false and .policy.min_peer_source_operators == 3 and .readiness.peer_sync_ready == false' "$STRICT_FAIL_SUMMARY" >/dev/null; then
  echo "strict-fail status summary expected readiness/policy failure metadata"
  cat "$STRICT_FAIL_SUMMARY"
  exit 1
fi
if ! jq -e '.readiness.failure_reasons == ["peer_source_operators_below_floor"] and .readiness.failure_count == 1' "$STRICT_FAIL_SUMMARY" >/dev/null; then
  echo "strict-fail status summary expected explicit readiness failure reasons"
  cat "$STRICT_FAIL_SUMMARY"
  exit 1
fi

echo "[server-federation-status] show-json output preserves retry_after_sec"
JSON_LOG="$TMP_DIR/federation_status_json.log"
if ! PATH="$TMP_BIN:$PATH" \
  ./scripts/easy_node.sh server-federation-status \
    --timeout-sec 3 \
    --show-json 1 >"$JSON_LOG" 2>&1; then
  echo "server-federation-status command failed in show-json mode"
  cat "$JSON_LOG"
  exit 1
fi

if ! rg -q '^json:$' "$JSON_LOG"; then
  echo "expected show-json marker in server-federation-status output"
  cat "$JSON_LOG"
  exit 1
fi
if ! rg -q '"retry_after_sec": 75' "$JSON_LOG"; then
  echo "expected retry_after_sec in server-federation-status JSON payload"
  cat "$JSON_LOG"
  exit 1
fi
if ! jq -e '.peer_status.peers[] | select(.url=="http://peer-down.local") | .retry_after_sec == 75' < <(sed -n '/^json:$/,$p' "$JSON_LOG" | tail -n +2) >/dev/null; then
  echo "show-json payload missing expected peer retry_after_sec value"
  cat "$JSON_LOG"
  exit 1
fi
if ! jq -e '.sync_status.peer.source_operators == ["op-peer-a","op-peer-b"]' < <(sed -n '/^json:$/,$p' "$JSON_LOG" | tail -n +2) >/dev/null; then
  echo "show-json payload missing expected peer source_operators list"
  cat "$JSON_LOG"
  exit 1
fi
if ! jq -e '.sync_status.issuer.source_operators == ["op-issuer-a","op-issuer-b"]' < <(sed -n '/^json:$/,$p' "$JSON_LOG" | tail -n +2) >/dev/null; then
  echo "show-json payload missing expected issuer source_operators list"
  cat "$JSON_LOG"
  exit 1
fi

echo "easy-node server federation status integration check ok"
