#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp jq rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
TMP_BIN="$TMP_DIR/bin"
mkdir -p "$TMP_BIN"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

FAKE_EASY_NODE="$TMP_DIR/fake_easy_node.sh"
EASY_CAPTURE="$TMP_DIR/easy_capture.log"
FAKE_CURL="$TMP_BIN/curl"
FAKE_RELAYS_FILE="$TMP_DIR/relays.json"

cat >"$FAKE_EASY_NODE" <<'EOF_FAKE_EASY_NODE'
#!/usr/bin/env bash
set -euo pipefail
cmd="${1:-}"
printf '%s\n' "$*" >>"${EASY_CAPTURE_FILE:?}"
case "$cmd" in
  server-preflight)
    exit "${FAKE_PREFLIGHT_RC:-0}"
    ;;
  server-up)
    exit "${FAKE_SERVER_UP_RC:-0}"
    ;;
  server-down)
    exit "${FAKE_SERVER_DOWN_RC:-0}"
    ;;
  server-federation-wait)
    shift || true
    summary_json_path=""
    print_summary_json="0"
    disable_summary="${FAKE_FEDERATION_WAIT_SUMMARY_DISABLE:-0}"
    suppress_output="${FAKE_FEDERATION_WAIT_OUTPUT_DISABLE:-0}"
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --summary-json)
          summary_json_path="${2:-}"
          shift 2
          ;;
        --print-summary-json)
          if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
            print_summary_json="${2:-}"
            shift 2
          else
            print_summary_json="1"
            shift
          fi
          ;;
        *)
          shift
          ;;
      esac
    done
    if [[ "$disable_summary" != "1" && -n "$summary_json_path" ]]; then
      mkdir -p "$(dirname "$summary_json_path")"
      cat >"$summary_json_path" <<'EOF_FAKE_WAIT_SUMMARY'
{"status":"ready","state":"ready","timing":{"attempts":2,"elapsed_sec":6,"remaining_sec":9},"readiness":{"federation_ready":true,"peer_sync_ready":true,"issuer_sync_ready":true,"peer_health_ready":true,"cooling_retry_exceeded":false,"failure_reasons":[],"failure_count":0},"observed":{"peer_summary":{"cooling_retry_max_sec":0},"peer_health":{"configured_failing":0,"discovered_eligible":1},"peer_sync":{"age_sec":1,"source_operator_count":2},"issuer_sync":{"age_sec":2,"source_operator_count":3}}}
EOF_FAKE_WAIT_SUMMARY
    fi
    if [[ "$suppress_output" != "1" ]]; then
      printf 'server-federation-wait: READY (fake)\n'
    fi
    if [[ "$print_summary_json" == "1" && -n "$summary_json_path" ]]; then
      printf 'summary_json: %s\n' "$summary_json_path"
      cat "$summary_json_path"
    fi
    exit "${FAKE_FEDERATION_WAIT_RC:-0}"
    ;;
  server-federation-status)
    shift || true
    summary_json_path=""
    disable_summary="${FAKE_FEDERATION_STATUS_SUMMARY_DISABLE:-0}"
    suppress_output="${FAKE_FEDERATION_STATUS_OUTPUT_DISABLE:-0}"
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --summary-json)
          summary_json_path="${2:-}"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    if [[ "$disable_summary" != "1" && -n "$summary_json_path" ]]; then
      mkdir -p "$(dirname "$summary_json_path")"
      cat >"$summary_json_path" <<'EOF_FAKE_FED_SUMMARY'
{"directory_url":"http://127.0.0.1:8081","policy":{"require_configured_healthy":true,"max_cooling_retry_sec":120,"max_peer_sync_age_sec":90,"max_issuer_sync_age_sec":80,"min_peer_success_sources":2,"min_issuer_success_sources":2,"min_peer_source_operators":2,"min_issuer_source_operators":3,"fail_on_not_ready":true},"readiness":{"federation_ready":true,"peer_sync_ready":true,"issuer_sync_ready":true,"peer_health_ready":true,"cooling_retry_exceeded":false,"failure_reasons":[],"failure_count":0},"observed":{"peer_summary":{"total":2,"configured":1,"discovered":1,"eligible":1,"cooling":0,"failing":0,"cooling_retry_max_sec":0},"peer_health":{"configured_healthy":1,"configured_failing":0,"discovered_eligible":1},"peer_sync":{"success":true,"quorum_met":true,"success_sources":2,"source_operator_count":2,"source_operators":["op-peer-a","op-peer-b"],"required_operators":2,"last_run_at":1731000000,"age_sec":1,"age_sec_display":"1","error":""},"issuer_sync":{"success":true,"quorum_met":true,"success_sources":2,"source_operator_count":3,"source_operators":["op-issuer-a","op-issuer-b","op-issuer-c"],"required_operators":2,"last_run_at":1730999999,"age_sec":2,"age_sec_display":"2","error":""}},"peer_status":{"peers":[{"url":"http://seed.local","configured":true,"discovered":false,"eligible":true,"cooling_down":false,"consecutive_failures":0}]},"sync_status":{"peer":{"success":true},"issuer":{"success":true}}}
EOF_FAKE_FED_SUMMARY
    fi
    if [[ "$suppress_output" != "1" ]]; then
      printf '{"ready":true,"peer_sync":{"ready":true},"issuer_sync":{"ready":true}}\n'
    fi
    exit "${FAKE_FEDERATION_STATUS_RC:-0}"
    ;;
  invite-generate)
    printf 'inv-integration-001\n'
    printf 'invite keys generated: 1 (issuer=http://127.0.0.1:8082)\n'
    exit "${FAKE_INVITE_GENERATE_RC:-0}"
    ;;
  runtime-doctor)
    suppress_output="${FAKE_RUNTIME_DOCTOR_OUTPUT_DISABLE:-0}"
    if [[ "$suppress_output" != "1" ]]; then
      printf '{"status":"ok","doctor":"fake"}\n'
    fi
    exit "${FAKE_RUNTIME_DOCTOR_RC:-0}"
    ;;
  incident-snapshot)
    bundle_dir=""
    disable_summary="${FAKE_INCIDENT_SUMMARY_OUTPUT_DISABLE:-0}"
    disable_bundle="${FAKE_INCIDENT_BUNDLE_OUTPUT_DISABLE:-0}"
    disable_manifest="${FAKE_INCIDENT_ATTACHMENT_MANIFEST_DISABLE:-0}"
    inject_skipped="${FAKE_INCIDENT_ATTACHMENT_SKIPPED_INJECT:-0}"
    declare -a attach_artifacts=()
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --bundle-dir)
          bundle_dir="${2:-}"
          shift 2
          ;;
        --attach-artifact)
          attach_artifacts+=("${2:-}")
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    if [[ -n "$bundle_dir" ]]; then
      mkdir -p "$bundle_dir"
      if [[ "$disable_summary" != "1" ]]; then
        printf '{"status":"ok"}\n' >"$bundle_dir/incident_summary.json"
        printf '# fake incident report\n' >"$bundle_dir/incident_report.md"
      fi
      if [[ "$disable_bundle" != "1" ]]; then
        printf 'fake tarball\n' >"${bundle_dir}.tar.gz"
        printf 'fake sha\n' >"${bundle_dir}.tar.gz.sha256"
      fi
      if ((${#attach_artifacts[@]} > 0)); then
        mkdir -p "$bundle_dir/attachments"
        if [[ "$disable_manifest" != "1" ]]; then
          : >"$bundle_dir/attachments/manifest.tsv"
          idx=0
          for artifact in "${attach_artifacts[@]}"; do
            idx=$((idx + 1))
            if [[ -e "$artifact" ]]; then
              printf 'attachments/%02d_artifact\tfile\t%s\n' "$idx" "$artifact" >>"$bundle_dir/attachments/manifest.tsv"
            fi
          done
        fi
      fi
      if [[ "$inject_skipped" == "1" ]]; then
        mkdir -p "$bundle_dir/attachments"
        printf 'missing_artifact\tfile\t/tmp/missing_artifact.log\n' >"$bundle_dir/attachments/skipped.tsv"
      fi
    fi
    exit "${FAKE_INCIDENT_SNAPSHOT_RC:-0}"
    ;;
  *)
    exit 0
    ;;
esac
EOF_FAKE_EASY_NODE
chmod +x "$FAKE_EASY_NODE"

cat >"$FAKE_CURL" <<'EOF_FAKE_CURL'
#!/usr/bin/env bash
set -euo pipefail
url="${@: -1}"
case "$url" in
  */v1/relays)
    cat "${FAKE_RELAYS_FILE:?}"
    ;;
  */v1/pubkeys)
    printf '{"issuer":"issuer-test","pub_keys":["k1"],"key_epoch":1,"min_token_epoch":1}\n'
    ;;
  */v1/health)
    printf '{"ok":true}\n'
    ;;
  *)
    exit 7
    ;;
esac
EOF_FAKE_CURL
chmod +x "$FAKE_CURL"

echo "[prod-operator-lifecycle] onboard success path"
cat >"$FAKE_RELAYS_FILE" <<'EOF_RELAYS_OK'
{"relays":[{"relay_id":"entry-op-test","role":"entry","operator_id":"op-test"},{"relay_id":"exit-op-test","role":"exit","operator_id":"op-test"}]}
EOF_RELAYS_OK

ONBOARD_SUMMARY="$TMP_DIR/onboard_summary.json"
ONBOARD_REPORT="$TMP_DIR/onboard_summary.md"
ONBOARD_FEDERATION_STATUS="$TMP_DIR/onboard_federation_status.json"
ONBOARD_FEDERATION_WAIT_LOG="$TMP_DIR/onboard_federation_wait.log"
ONBOARD_FEDERATION_WAIT_SUMMARY="$TMP_DIR/onboard_federation_wait_summary.json"
ONBOARD_FEDERATION_STATUS_SUMMARY="$TMP_DIR/onboard_federation_status_summary.json"
: >"$EASY_CAPTURE"
EASY_CAPTURE_FILE="$EASY_CAPTURE" \
FAKE_RELAYS_FILE="$FAKE_RELAYS_FILE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
PROD_OPERATOR_LIFECYCLE_CURL_BIN="$FAKE_CURL" \
./scripts/prod_operator_lifecycle_runbook.sh \
  --action onboard \
  --mode provider \
  --public-host 127.0.0.1 \
  --operator-id op-test \
  --authority-directory http://127.0.0.1:8081 \
  --authority-issuer http://127.0.0.1:8082 \
  --peer-directories http://127.0.0.2:8081 \
  --peer-identity-strict 1 \
  --preflight-check 1 \
  --preflight-timeout-sec 8 \
  --health-check 1 \
  --health-timeout-sec 2 \
  --verify-relays 1 \
  --verify-relay-min-count 2 \
  --verify-relay-timeout-sec 2 \
  --federation-check 1 \
  --federation-ready-timeout-sec 15 \
  --federation-poll-sec 3 \
  --federation-timeout-sec 4 \
  --federation-require-configured-healthy 1 \
  --federation-max-cooling-retry-sec 120 \
  --federation-max-peer-sync-age-sec 90 \
  --federation-max-issuer-sync-age-sec 80 \
  --federation-min-peer-success-sources 2 \
  --federation-min-issuer-success-sources 2 \
  --federation-min-peer-source-operators 2 \
  --federation-min-issuer-source-operators 3 \
  --federation-wait-file "$ONBOARD_FEDERATION_WAIT_LOG" \
  --federation-wait-file-required 1 \
  --federation-wait-summary-json "$ONBOARD_FEDERATION_WAIT_SUMMARY" \
  --federation-wait-print-summary-json 0 \
  --federation-wait-summary-required 1 \
  --federation-status-fail-on-not-ready 1 \
  --federation-status-file "$ONBOARD_FEDERATION_STATUS" \
  --federation-status-file-required 1 \
  --federation-status-summary-json "$ONBOARD_FEDERATION_STATUS_SUMMARY" \
  --federation-status-summary-required 1 \
  --directory-url http://127.0.0.1:8081 \
  --report-md "$ONBOARD_REPORT" \
  --summary-json "$ONBOARD_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_prod_operator_lifecycle_runbook_onboard_ok.log 2>&1

if [[ ! -f "$ONBOARD_SUMMARY" ]]; then
  echo "onboard runbook did not produce summary json"
  cat /tmp/integration_prod_operator_lifecycle_runbook_onboard_ok.log
  exit 1
fi
if [[ "$(jq -r '.status' "$ONBOARD_SUMMARY")" != "ok" ]]; then
  echo "onboard runbook summary has unexpected status"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.action' "$ONBOARD_SUMMARY")" != "onboard" ]]; then
  echo "onboard runbook summary has unexpected action"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.relay_policy.observed_count' "$ONBOARD_SUMMARY")" != "2" ]]; then
  echo "onboard runbook did not report expected relay count"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if ! jq -e '.completed_steps | index("server_preflight") != null' "$ONBOARD_SUMMARY" >/dev/null; then
  echo "onboard runbook missing server_preflight completion step"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if ! jq -e '.completed_steps | index("server_up") != null' "$ONBOARD_SUMMARY" >/dev/null; then
  echo "onboard runbook missing server_up completion step"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if ! jq -e '.completed_steps | index("health_check") != null' "$ONBOARD_SUMMARY" >/dev/null; then
  echo "onboard runbook missing health_check completion step"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if ! jq -e '.completed_steps | index("relay_verify") != null' "$ONBOARD_SUMMARY" >/dev/null; then
  echo "onboard runbook missing relay_verify completion step"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if ! jq -e '.completed_steps | index("federation_wait") != null' "$ONBOARD_SUMMARY" >/dev/null; then
  echo "onboard runbook missing federation_wait completion step"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if ! jq -e '.completed_steps | index("federation_status") != null' "$ONBOARD_SUMMARY" >/dev/null; then
  echo "onboard runbook missing federation_status completion step"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.checks.federation_enabled' "$ONBOARD_SUMMARY")" != "true" ]]; then
  echo "onboard runbook summary did not enable federation checks"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.wait_state' "$ONBOARD_SUMMARY")" != "ready" ]]; then
  echo "onboard runbook summary has unexpected federation wait state"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.wait_file' "$ONBOARD_SUMMARY")" != "$ONBOARD_FEDERATION_WAIT_LOG" ]]; then
  echo "onboard runbook summary has unexpected federation wait log artifact path"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.wait_file_required' "$ONBOARD_SUMMARY")" != "true" ]]; then
  echo "onboard runbook summary has unexpected federation wait file required flag"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.wait_file_required_met' "$ONBOARD_SUMMARY")" != "true" ]]; then
  echo "onboard runbook summary has unexpected federation wait file required-met value"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.wait_capture_rc' "$ONBOARD_SUMMARY")" != "0" ]]; then
  echo "onboard runbook summary has unexpected federation wait capture rc"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.wait_summary_state' "$ONBOARD_SUMMARY")" != "captured" ]]; then
  echo "onboard runbook summary has unexpected federation wait summary state"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.wait_summary_required' "$ONBOARD_SUMMARY")" != "true" ]]; then
  echo "onboard runbook summary has unexpected federation wait summary required flag"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.wait_summary_required_met' "$ONBOARD_SUMMARY")" != "true" ]]; then
  echo "onboard runbook summary has unexpected federation wait summary required-met value"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.wait_summary_capture_rc' "$ONBOARD_SUMMARY")" != "0" ]]; then
  echo "onboard runbook summary has unexpected federation wait summary capture rc"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.wait_summary_file' "$ONBOARD_SUMMARY")" != "$ONBOARD_FEDERATION_WAIT_SUMMARY" ]]; then
  echo "onboard runbook summary has unexpected federation wait summary artifact path"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.wait_summary_status' "$ONBOARD_SUMMARY")" != "ready" ]]; then
  echo "onboard runbook summary has unexpected federation wait summary status"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.wait_summary_final_state' "$ONBOARD_SUMMARY")" != "ready" ]]; then
  echo "onboard runbook summary has unexpected federation wait summary final state"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if ! jq -e '.federation.wait_ready_failure_reasons == []' "$ONBOARD_SUMMARY" >/dev/null; then
  echo "onboard runbook summary has unexpected federation wait readiness failure reasons"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.wait_timing.attempts' "$ONBOARD_SUMMARY")" != "2" ]]; then
  echo "onboard runbook summary has unexpected federation wait attempt count"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.wait_observed.peer_source_operator_count' "$ONBOARD_SUMMARY")" != "2" ]]; then
  echo "onboard runbook summary has unexpected federation wait observed peer source-operator count"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.require_configured_healthy' "$ONBOARD_SUMMARY")" != "true" ]]; then
  echo "onboard runbook summary has unexpected federation require_configured_healthy flag"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.max_cooling_retry_sec' "$ONBOARD_SUMMARY")" != "120" ]]; then
  echo "onboard runbook summary has unexpected federation max_cooling_retry_sec"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.max_peer_sync_age_sec' "$ONBOARD_SUMMARY")" != "90" ]]; then
  echo "onboard runbook summary has unexpected federation max_peer_sync_age_sec"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.max_issuer_sync_age_sec' "$ONBOARD_SUMMARY")" != "80" ]]; then
  echo "onboard runbook summary has unexpected federation max_issuer_sync_age_sec"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.min_peer_success_sources' "$ONBOARD_SUMMARY")" != "2" ]]; then
  echo "onboard runbook summary has unexpected federation min_peer_success_sources"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.min_issuer_success_sources' "$ONBOARD_SUMMARY")" != "2" ]]; then
  echo "onboard runbook summary has unexpected federation min_issuer_success_sources"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.min_peer_source_operators' "$ONBOARD_SUMMARY")" != "2" ]]; then
  echo "onboard runbook summary has unexpected federation min_peer_source_operators"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.min_issuer_source_operators' "$ONBOARD_SUMMARY")" != "3" ]]; then
  echo "onboard runbook summary has unexpected federation min_issuer_source_operators"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.status_fail_on_not_ready' "$ONBOARD_SUMMARY")" != "true" ]]; then
  echo "onboard runbook summary has unexpected federation status_fail_on_not_ready"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.peer_count' "$ONBOARD_SUMMARY")" != "1" ]]; then
  echo "onboard runbook summary has unexpected federation peer count"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.status_capture_rc' "$ONBOARD_SUMMARY")" != "0" ]]; then
  echo "onboard runbook summary has unexpected federation status capture rc"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.status_file' "$ONBOARD_SUMMARY")" != "$ONBOARD_FEDERATION_STATUS" ]]; then
  echo "onboard runbook summary has unexpected federation status artifact path"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.status_file_required' "$ONBOARD_SUMMARY")" != "true" ]]; then
  echo "onboard runbook summary has unexpected federation status file required flag"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.status_file_required_met' "$ONBOARD_SUMMARY")" != "true" ]]; then
  echo "onboard runbook summary has unexpected federation status file required-met value"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.status_summary_file' "$ONBOARD_SUMMARY")" != "$ONBOARD_FEDERATION_STATUS_SUMMARY" ]]; then
  echo "onboard runbook summary has unexpected federation status summary artifact path"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.status_summary_state' "$ONBOARD_SUMMARY")" != "captured" ]]; then
  echo "onboard runbook summary has unexpected federation status summary state"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.status_summary_required' "$ONBOARD_SUMMARY")" != "true" ]]; then
  echo "onboard runbook summary has unexpected federation status summary required flag"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.status_summary_required_met' "$ONBOARD_SUMMARY")" != "true" ]]; then
  echo "onboard runbook summary has unexpected federation status summary required-met value"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.status_summary_capture_rc' "$ONBOARD_SUMMARY")" != "0" ]]; then
  echo "onboard runbook summary has unexpected federation status summary capture rc"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.status_ready' "$ONBOARD_SUMMARY")" != "true" ]]; then
  echo "onboard runbook summary has unexpected federation status ready value"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if ! jq -e '.federation.status_ready_failure_reasons == []' "$ONBOARD_SUMMARY" >/dev/null; then
  echo "onboard runbook summary has unexpected federation status readiness failure reasons"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.status_observed.peer_source_operator_count' "$ONBOARD_SUMMARY")" != "2" ]]; then
  echo "onboard runbook summary has unexpected federation status observed peer source-operator count"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.status_observed.issuer_source_operator_count' "$ONBOARD_SUMMARY")" != "3" ]]; then
  echo "onboard runbook summary has unexpected federation status observed issuer source-operator count"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.report_md' "$ONBOARD_SUMMARY")" != "$ONBOARD_REPORT" ]]; then
  echo "onboard runbook summary has unexpected report markdown path"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ ! -f "$ONBOARD_FEDERATION_STATUS" ]]; then
  echo "onboard runbook did not write federation status artifact"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ ! -f "$ONBOARD_FEDERATION_WAIT_LOG" ]]; then
  echo "onboard runbook did not write federation wait log artifact"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ ! -f "$ONBOARD_FEDERATION_WAIT_SUMMARY" ]]; then
  echo "onboard runbook did not write federation wait summary artifact"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ ! -f "$ONBOARD_FEDERATION_STATUS_SUMMARY" ]]; then
  echo "onboard runbook did not write federation status summary artifact"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ ! -f "$ONBOARD_REPORT" ]]; then
  echo "onboard runbook did not write report markdown artifact"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if ! rg -q -- '- status: ok' "$ONBOARD_REPORT"; then
  echo "onboard runbook report markdown missing expected status line"
  cat "$ONBOARD_REPORT"
  exit 1
fi
if ! rg -q -- '"ready":true' "$ONBOARD_FEDERATION_STATUS"; then
  echo "onboard runbook federation status artifact missing expected payload"
  cat "$ONBOARD_FEDERATION_STATUS"
  exit 1
fi
if ! rg -q -- 'server-federation-wait: READY \(fake\)' "$ONBOARD_FEDERATION_WAIT_LOG"; then
  echo "onboard runbook federation wait log artifact missing expected payload"
  cat "$ONBOARD_FEDERATION_WAIT_LOG"
  exit 1
fi
if ! rg -q -- '"status":"ready"' "$ONBOARD_FEDERATION_WAIT_SUMMARY"; then
  echo "onboard runbook federation wait summary artifact missing expected payload"
  cat "$ONBOARD_FEDERATION_WAIT_SUMMARY"
  exit 1
fi
if ! rg -q -- '^server-preflight --mode provider' "$EASY_CAPTURE"; then
  echo "onboard runbook missing server-preflight invocation"
  cat "$EASY_CAPTURE"
  exit 1
fi
if ! rg -q -- '^server-up --mode provider' "$EASY_CAPTURE"; then
  echo "onboard runbook missing server-up invocation"
  cat "$EASY_CAPTURE"
  exit 1
fi
if ! rg -Fq -- "server-federation-wait --directory-url http://127.0.0.1:8081 --ready-timeout-sec 15 --poll-sec 3 --require-configured-healthy 1 --max-cooling-retry-sec 120 --max-peer-sync-age-sec 90 --max-issuer-sync-age-sec 80 --min-peer-success-sources 2 --min-issuer-success-sources 2 --min-peer-source-operators 2 --min-issuer-source-operators 3 --summary-json $ONBOARD_FEDERATION_WAIT_SUMMARY --print-summary-json 0 --timeout-sec 4" "$EASY_CAPTURE"; then
  echo "onboard runbook missing server-federation-wait invocation"
  cat "$EASY_CAPTURE"
  exit 1
fi
if ! rg -Fq -- "server-federation-status --directory-url http://127.0.0.1:8081 --timeout-sec 4 --require-configured-healthy 1 --max-cooling-retry-sec 120 --max-peer-sync-age-sec 90 --max-issuer-sync-age-sec 80 --min-peer-success-sources 2 --min-issuer-success-sources 2 --min-peer-source-operators 2 --min-issuer-source-operators 3 --fail-on-not-ready 1 --summary-json $ONBOARD_FEDERATION_STATUS_SUMMARY --show-json 1" "$EASY_CAPTURE"; then
  echo "onboard runbook missing server-federation-status invocation"
  cat "$EASY_CAPTURE"
  exit 1
fi

echo "[prod-operator-lifecycle] onboard federation wait summary-required fail-close path"
ONBOARD_WAIT_REQUIRED_FAIL_SUMMARY="$TMP_DIR/onboard_wait_required_fail_summary.json"
ONBOARD_WAIT_REQUIRED_FAIL_WAIT_SUMMARY="$TMP_DIR/onboard_wait_required_fail_wait_summary.json"
ONBOARD_WAIT_REQUIRED_FAIL_WAIT_LOG="$TMP_DIR/onboard_wait_required_fail_wait.log"
: >"$EASY_CAPTURE"
set +e
EASY_CAPTURE_FILE="$EASY_CAPTURE" \
FAKE_RELAYS_FILE="$FAKE_RELAYS_FILE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
FAKE_FEDERATION_WAIT_SUMMARY_DISABLE=1 \
PROD_OPERATOR_LIFECYCLE_CURL_BIN="$FAKE_CURL" \
./scripts/prod_operator_lifecycle_runbook.sh \
  --action onboard \
  --mode provider \
  --public-host 127.0.0.1 \
  --operator-id op-test \
  --preflight-check 0 \
  --health-check 0 \
  --verify-relays 0 \
  --federation-check 1 \
  --peer-directories http://127.0.0.2:8081 \
  --federation-wait-file "$ONBOARD_WAIT_REQUIRED_FAIL_WAIT_LOG" \
  --federation-wait-summary-json "$ONBOARD_WAIT_REQUIRED_FAIL_WAIT_SUMMARY" \
  --federation-wait-summary-required 1 \
  --runtime-doctor-on-fail 0 \
  --incident-snapshot-on-fail 0 \
  --rollback-on-fail 0 \
  --directory-url http://127.0.0.1:8081 \
  --summary-json "$ONBOARD_WAIT_REQUIRED_FAIL_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_prod_operator_lifecycle_runbook_wait_required_fail.log 2>&1
onboard_wait_required_fail_rc=$?
set -e
if [[ "$onboard_wait_required_fail_rc" -ne 10 ]]; then
  echo "onboard wait-summary-required fail-close path returned unexpected rc=$onboard_wait_required_fail_rc (expected 10)"
  cat /tmp/integration_prod_operator_lifecycle_runbook_wait_required_fail.log
  exit 1
fi
if [[ "$(jq -r '.status' "$ONBOARD_WAIT_REQUIRED_FAIL_SUMMARY")" != "fail" ]]; then
  echo "onboard wait-summary-required fail-close summary has unexpected status"
  cat "$ONBOARD_WAIT_REQUIRED_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.failure_step' "$ONBOARD_WAIT_REQUIRED_FAIL_SUMMARY")" != "federation_wait_summary" ]]; then
  echo "onboard wait-summary-required fail-close summary has unexpected failure_step"
  cat "$ONBOARD_WAIT_REQUIRED_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.wait_state' "$ONBOARD_WAIT_REQUIRED_FAIL_SUMMARY")" != "failed_summary_required" ]]; then
  echo "onboard wait-summary-required fail-close summary has unexpected wait_state"
  cat "$ONBOARD_WAIT_REQUIRED_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.wait_summary_required' "$ONBOARD_WAIT_REQUIRED_FAIL_SUMMARY")" != "true" ]]; then
  echo "onboard wait-summary-required fail-close summary has unexpected wait_summary_required"
  cat "$ONBOARD_WAIT_REQUIRED_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.wait_summary_required_met' "$ONBOARD_WAIT_REQUIRED_FAIL_SUMMARY")" != "false" ]]; then
  echo "onboard wait-summary-required fail-close summary has unexpected wait_summary_required_met"
  cat "$ONBOARD_WAIT_REQUIRED_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.wait_summary_state' "$ONBOARD_WAIT_REQUIRED_FAIL_SUMMARY")" != "missing_or_invalid" ]]; then
  echo "onboard wait-summary-required fail-close summary has unexpected wait_summary_state"
  cat "$ONBOARD_WAIT_REQUIRED_FAIL_SUMMARY"
  exit 1
fi
if [[ ! -f "$ONBOARD_WAIT_REQUIRED_FAIL_WAIT_LOG" ]]; then
  echo "onboard wait-summary-required fail-close run did not write federation wait log"
  cat "$ONBOARD_WAIT_REQUIRED_FAIL_SUMMARY"
  exit 1
fi
if ! rg -q -- 'server-federation-wait: READY \(fake\)' "$ONBOARD_WAIT_REQUIRED_FAIL_WAIT_LOG"; then
  echo "onboard wait-summary-required fail-close wait log missing expected payload"
  cat "$ONBOARD_WAIT_REQUIRED_FAIL_WAIT_LOG"
  exit 1
fi

echo "[prod-operator-lifecycle] onboard federation wait file-required fail-close path"
ONBOARD_WAIT_FILE_REQUIRED_FAIL_SUMMARY="$TMP_DIR/onboard_wait_file_required_fail_summary.json"
ONBOARD_WAIT_FILE_REQUIRED_FAIL_WAIT_LOG="$TMP_DIR/onboard_wait_file_required_fail_wait.log"
: >"$EASY_CAPTURE"
set +e
EASY_CAPTURE_FILE="$EASY_CAPTURE" \
FAKE_RELAYS_FILE="$FAKE_RELAYS_FILE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
FAKE_FEDERATION_WAIT_OUTPUT_DISABLE=1 \
PROD_OPERATOR_LIFECYCLE_CURL_BIN="$FAKE_CURL" \
./scripts/prod_operator_lifecycle_runbook.sh \
  --action onboard \
  --mode provider \
  --public-host 127.0.0.1 \
  --operator-id op-test \
  --preflight-check 0 \
  --health-check 0 \
  --verify-relays 0 \
  --federation-check 1 \
  --peer-directories http://127.0.0.2:8081 \
  --federation-wait-file "$ONBOARD_WAIT_FILE_REQUIRED_FAIL_WAIT_LOG" \
  --federation-wait-file-required 1 \
  --federation-wait-summary-required 0 \
  --runtime-doctor-on-fail 0 \
  --incident-snapshot-on-fail 0 \
  --rollback-on-fail 0 \
  --directory-url http://127.0.0.1:8081 \
  --summary-json "$ONBOARD_WAIT_FILE_REQUIRED_FAIL_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_prod_operator_lifecycle_runbook_wait_file_required_fail.log 2>&1
onboard_wait_file_required_fail_rc=$?
set -e
if [[ "$onboard_wait_file_required_fail_rc" -ne 12 ]]; then
  echo "onboard wait-file-required fail-close path returned unexpected rc=$onboard_wait_file_required_fail_rc (expected 12)"
  cat /tmp/integration_prod_operator_lifecycle_runbook_wait_file_required_fail.log
  exit 1
fi
if [[ "$(jq -r '.status' "$ONBOARD_WAIT_FILE_REQUIRED_FAIL_SUMMARY")" != "fail" ]]; then
  echo "onboard wait-file-required fail-close summary has unexpected status"
  cat "$ONBOARD_WAIT_FILE_REQUIRED_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.failure_step' "$ONBOARD_WAIT_FILE_REQUIRED_FAIL_SUMMARY")" != "federation_wait_file" ]]; then
  echo "onboard wait-file-required fail-close summary has unexpected failure_step"
  cat "$ONBOARD_WAIT_FILE_REQUIRED_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.wait_state' "$ONBOARD_WAIT_FILE_REQUIRED_FAIL_SUMMARY")" != "failed_wait_file_required" ]]; then
  echo "onboard wait-file-required fail-close summary has unexpected wait_state"
  cat "$ONBOARD_WAIT_FILE_REQUIRED_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.wait_file_required' "$ONBOARD_WAIT_FILE_REQUIRED_FAIL_SUMMARY")" != "true" ]]; then
  echo "onboard wait-file-required fail-close summary has unexpected wait_file_required"
  cat "$ONBOARD_WAIT_FILE_REQUIRED_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.wait_file_required_met' "$ONBOARD_WAIT_FILE_REQUIRED_FAIL_SUMMARY")" != "false" ]]; then
  echo "onboard wait-file-required fail-close summary has unexpected wait_file_required_met"
  cat "$ONBOARD_WAIT_FILE_REQUIRED_FAIL_SUMMARY"
  exit 1
fi
if [[ ! -f "$ONBOARD_WAIT_FILE_REQUIRED_FAIL_WAIT_LOG" ]]; then
  echo "onboard wait-file-required fail-close run did not create wait log file"
  cat "$ONBOARD_WAIT_FILE_REQUIRED_FAIL_SUMMARY"
  exit 1
fi
if [[ -s "$ONBOARD_WAIT_FILE_REQUIRED_FAIL_WAIT_LOG" ]]; then
  echo "onboard wait-file-required fail-close wait log should be empty"
  cat "$ONBOARD_WAIT_FILE_REQUIRED_FAIL_WAIT_LOG"
  exit 1
fi

echo "[prod-operator-lifecycle] onboard federation status file-required fail-close path"
ONBOARD_STATUS_FILE_REQUIRED_FAIL_SUMMARY="$TMP_DIR/onboard_status_file_required_fail_summary.json"
ONBOARD_STATUS_FILE_REQUIRED_FAIL_STATUS_FILE="$TMP_DIR/onboard_status_file_required_fail_status.log"
: >"$EASY_CAPTURE"
set +e
EASY_CAPTURE_FILE="$EASY_CAPTURE" \
FAKE_RELAYS_FILE="$FAKE_RELAYS_FILE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
FAKE_FEDERATION_STATUS_OUTPUT_DISABLE=1 \
PROD_OPERATOR_LIFECYCLE_CURL_BIN="$FAKE_CURL" \
./scripts/prod_operator_lifecycle_runbook.sh \
  --action onboard \
  --mode provider \
  --public-host 127.0.0.1 \
  --operator-id op-test \
  --preflight-check 0 \
  --health-check 0 \
  --verify-relays 0 \
  --federation-check 1 \
  --peer-directories http://127.0.0.2:8081 \
  --federation-wait-summary-required 0 \
  --federation-status-file "$ONBOARD_STATUS_FILE_REQUIRED_FAIL_STATUS_FILE" \
  --federation-status-file-required 1 \
  --federation-status-summary-required 0 \
  --runtime-doctor-on-fail 0 \
  --incident-snapshot-on-fail 0 \
  --rollback-on-fail 0 \
  --directory-url http://127.0.0.1:8081 \
  --summary-json "$ONBOARD_STATUS_FILE_REQUIRED_FAIL_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_prod_operator_lifecycle_runbook_status_file_required_fail.log 2>&1
onboard_status_file_required_fail_rc=$?
set -e
if [[ "$onboard_status_file_required_fail_rc" -ne 13 ]]; then
  echo "onboard status-file-required fail-close path returned unexpected rc=$onboard_status_file_required_fail_rc (expected 13)"
  cat /tmp/integration_prod_operator_lifecycle_runbook_status_file_required_fail.log
  exit 1
fi
if [[ "$(jq -r '.status' "$ONBOARD_STATUS_FILE_REQUIRED_FAIL_SUMMARY")" != "fail" ]]; then
  echo "onboard status-file-required fail-close summary has unexpected status"
  cat "$ONBOARD_STATUS_FILE_REQUIRED_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.failure_step' "$ONBOARD_STATUS_FILE_REQUIRED_FAIL_SUMMARY")" != "federation_status_file" ]]; then
  echo "onboard status-file-required fail-close summary has unexpected failure_step"
  cat "$ONBOARD_STATUS_FILE_REQUIRED_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.status_file_required' "$ONBOARD_STATUS_FILE_REQUIRED_FAIL_SUMMARY")" != "true" ]]; then
  echo "onboard status-file-required fail-close summary has unexpected status_file_required"
  cat "$ONBOARD_STATUS_FILE_REQUIRED_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.status_file_required_met' "$ONBOARD_STATUS_FILE_REQUIRED_FAIL_SUMMARY")" != "false" ]]; then
  echo "onboard status-file-required fail-close summary has unexpected status_file_required_met"
  cat "$ONBOARD_STATUS_FILE_REQUIRED_FAIL_SUMMARY"
  exit 1
fi
if [[ ! -f "$ONBOARD_STATUS_FILE_REQUIRED_FAIL_STATUS_FILE" ]]; then
  echo "onboard status-file-required fail-close run did not create status log file"
  cat "$ONBOARD_STATUS_FILE_REQUIRED_FAIL_SUMMARY"
  exit 1
fi
if [[ -s "$ONBOARD_STATUS_FILE_REQUIRED_FAIL_STATUS_FILE" ]]; then
  echo "onboard status-file-required fail-close status log should be empty"
  cat "$ONBOARD_STATUS_FILE_REQUIRED_FAIL_STATUS_FILE"
  exit 1
fi

echo "[prod-operator-lifecycle] onboard federation status summary-required fail-close path"
ONBOARD_STATUS_REQUIRED_FAIL_SUMMARY="$TMP_DIR/onboard_status_required_fail_summary.json"
ONBOARD_STATUS_REQUIRED_FAIL_STATUS_SUMMARY="$TMP_DIR/onboard_status_required_fail_status_summary.json"
: >"$EASY_CAPTURE"
set +e
EASY_CAPTURE_FILE="$EASY_CAPTURE" \
FAKE_RELAYS_FILE="$FAKE_RELAYS_FILE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
FAKE_FEDERATION_STATUS_SUMMARY_DISABLE=1 \
PROD_OPERATOR_LIFECYCLE_CURL_BIN="$FAKE_CURL" \
./scripts/prod_operator_lifecycle_runbook.sh \
  --action onboard \
  --mode provider \
  --public-host 127.0.0.1 \
  --operator-id op-test \
  --preflight-check 0 \
  --health-check 0 \
  --verify-relays 0 \
  --federation-check 1 \
  --peer-directories http://127.0.0.2:8081 \
  --federation-wait-summary-required 0 \
  --federation-status-summary-json "$ONBOARD_STATUS_REQUIRED_FAIL_STATUS_SUMMARY" \
  --federation-status-summary-required 1 \
  --runtime-doctor-on-fail 0 \
  --incident-snapshot-on-fail 0 \
  --rollback-on-fail 0 \
  --directory-url http://127.0.0.1:8081 \
  --summary-json "$ONBOARD_STATUS_REQUIRED_FAIL_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_prod_operator_lifecycle_runbook_status_required_fail.log 2>&1
onboard_status_required_fail_rc=$?
set -e
if [[ "$onboard_status_required_fail_rc" -ne 11 ]]; then
  echo "onboard status-summary-required fail-close path returned unexpected rc=$onboard_status_required_fail_rc (expected 11)"
  cat /tmp/integration_prod_operator_lifecycle_runbook_status_required_fail.log
  exit 1
fi
if [[ "$(jq -r '.status' "$ONBOARD_STATUS_REQUIRED_FAIL_SUMMARY")" != "fail" ]]; then
  echo "onboard status-summary-required fail-close summary has unexpected status"
  cat "$ONBOARD_STATUS_REQUIRED_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.failure_step' "$ONBOARD_STATUS_REQUIRED_FAIL_SUMMARY")" != "federation_status_summary" ]]; then
  echo "onboard status-summary-required fail-close summary has unexpected failure_step"
  cat "$ONBOARD_STATUS_REQUIRED_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.status_summary_required' "$ONBOARD_STATUS_REQUIRED_FAIL_SUMMARY")" != "true" ]]; then
  echo "onboard status-summary-required fail-close summary has unexpected status_summary_required"
  cat "$ONBOARD_STATUS_REQUIRED_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.status_summary_required_met' "$ONBOARD_STATUS_REQUIRED_FAIL_SUMMARY")" != "false" ]]; then
  echo "onboard status-summary-required fail-close summary has unexpected status_summary_required_met"
  cat "$ONBOARD_STATUS_REQUIRED_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.federation.status_summary_state' "$ONBOARD_STATUS_REQUIRED_FAIL_SUMMARY")" != "missing_or_invalid" ]]; then
  echo "onboard status-summary-required fail-close summary has unexpected status_summary_state"
  cat "$ONBOARD_STATUS_REQUIRED_FAIL_SUMMARY"
  exit 1
fi

echo "[prod-operator-lifecycle] onboard authority invite bootstrap success path"
cat >"$FAKE_RELAYS_FILE" <<'EOF_RELAYS_AUTH_OK'
{"relays":[{"relay_id":"entry-op-auth","role":"entry","operator_id":"op-auth"},{"relay_id":"exit-op-auth","role":"exit","operator_id":"op-auth"}]}
EOF_RELAYS_AUTH_OK
AUTH_ONBOARD_SUMMARY="$TMP_DIR/onboard_authority_summary.json"
AUTH_ONBOARD_INVITE_FILE="$TMP_DIR/onboard_authority_invites.txt"
: >"$EASY_CAPTURE"
EASY_CAPTURE_FILE="$EASY_CAPTURE" \
FAKE_RELAYS_FILE="$FAKE_RELAYS_FILE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
PROD_OPERATOR_LIFECYCLE_CURL_BIN="$FAKE_CURL" \
./scripts/prod_operator_lifecycle_runbook.sh \
  --action onboard \
  --mode authority \
  --public-host 127.0.0.1 \
  --operator-id op-auth \
  --preflight-check 0 \
  --health-check 1 \
  --health-timeout-sec 2 \
  --verify-relays 1 \
  --verify-relay-min-count 2 \
  --verify-relay-timeout-sec 2 \
  --federation-check 0 \
  --onboard-invite 1 \
  --onboard-invite-count 1 \
  --onboard-invite-tier 2 \
  --onboard-invite-wait-sec 3 \
  --onboard-invite-fail-open 0 \
  --onboard-invite-file "$AUTH_ONBOARD_INVITE_FILE" \
  --directory-url http://127.0.0.1:8081 \
  --summary-json "$AUTH_ONBOARD_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_prod_operator_lifecycle_runbook_onboard_authority_invite_ok.log 2>&1

if [[ "$(jq -r '.status' "$AUTH_ONBOARD_SUMMARY")" != "ok" ]]; then
  echo "authority onboard invite summary has unexpected status"
  cat "$AUTH_ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.checks.onboard_invite_enabled' "$AUTH_ONBOARD_SUMMARY")" != "true" ]]; then
  echo "authority onboard invite summary did not enable invite bootstrap"
  cat "$AUTH_ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.invite_bootstrap.state' "$AUTH_ONBOARD_SUMMARY")" != "generated" ]]; then
  echo "authority onboard invite summary has unexpected invite state"
  cat "$AUTH_ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.invite_bootstrap.generated_count' "$AUTH_ONBOARD_SUMMARY")" != "1" ]]; then
  echo "authority onboard invite summary has unexpected generated count"
  cat "$AUTH_ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.invite_bootstrap.file' "$AUTH_ONBOARD_SUMMARY")" != "$AUTH_ONBOARD_INVITE_FILE" ]]; then
  echo "authority onboard invite summary has unexpected invite artifact path"
  cat "$AUTH_ONBOARD_SUMMARY"
  exit 1
fi
if [[ ! -f "$AUTH_ONBOARD_INVITE_FILE" ]]; then
  echo "authority onboard invite file not created"
  cat "$AUTH_ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(head -n 1 "$AUTH_ONBOARD_INVITE_FILE")" != "inv-integration-001" ]]; then
  echo "authority onboard invite file missing expected invite key"
  cat "$AUTH_ONBOARD_INVITE_FILE"
  exit 1
fi
if ! jq -e '.completed_steps | index("onboard_invite") != null' "$AUTH_ONBOARD_SUMMARY" >/dev/null; then
  echo "authority onboard runbook missing onboard_invite completion step"
  cat "$AUTH_ONBOARD_SUMMARY"
  exit 1
fi
if ! rg -q -- '^invite-generate --count 1 --tier 2 --wait-sec 3$' "$EASY_CAPTURE"; then
  echo "authority onboard runbook missing invite-generate invocation"
  cat "$EASY_CAPTURE"
  exit 1
fi

echo "[prod-operator-lifecycle] onboard authority invite bootstrap fail-open path"
AUTH_ONBOARD_FAIL_OPEN_SUMMARY="$TMP_DIR/onboard_authority_fail_open_summary.json"
AUTH_ONBOARD_FAIL_OPEN_INVITE_FILE="$TMP_DIR/onboard_authority_fail_open_invites.log"
: >"$EASY_CAPTURE"
EASY_CAPTURE_FILE="$EASY_CAPTURE" \
FAKE_RELAYS_FILE="$FAKE_RELAYS_FILE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
FAKE_INVITE_GENERATE_RC=13 \
PROD_OPERATOR_LIFECYCLE_CURL_BIN="$FAKE_CURL" \
./scripts/prod_operator_lifecycle_runbook.sh \
  --action onboard \
  --mode authority \
  --public-host 127.0.0.1 \
  --operator-id op-auth \
  --preflight-check 0 \
  --health-check 1 \
  --health-timeout-sec 2 \
  --verify-relays 1 \
  --verify-relay-min-count 2 \
  --verify-relay-timeout-sec 2 \
  --federation-check 0 \
  --onboard-invite 1 \
  --onboard-invite-count 1 \
  --onboard-invite-tier 1 \
  --onboard-invite-wait-sec 0 \
  --onboard-invite-fail-open 1 \
  --onboard-invite-file "$AUTH_ONBOARD_FAIL_OPEN_INVITE_FILE" \
  --directory-url http://127.0.0.1:8081 \
  --summary-json "$AUTH_ONBOARD_FAIL_OPEN_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_prod_operator_lifecycle_runbook_onboard_authority_invite_fail_open.log 2>&1

if [[ "$(jq -r '.status' "$AUTH_ONBOARD_FAIL_OPEN_SUMMARY")" != "ok" ]]; then
  echo "authority onboard invite fail-open summary has unexpected status"
  cat "$AUTH_ONBOARD_FAIL_OPEN_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.invite_bootstrap.state' "$AUTH_ONBOARD_FAIL_OPEN_SUMMARY")" != "failed" ]]; then
  echo "authority onboard invite fail-open summary has unexpected invite state"
  cat "$AUTH_ONBOARD_FAIL_OPEN_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.invite_bootstrap.rc' "$AUTH_ONBOARD_FAIL_OPEN_SUMMARY")" != "13" ]]; then
  echo "authority onboard invite fail-open summary has unexpected invite rc"
  cat "$AUTH_ONBOARD_FAIL_OPEN_SUMMARY"
  exit 1
fi
if ! jq -e '.completed_steps | index("onboard_invite_failed_open") != null' "$AUTH_ONBOARD_FAIL_OPEN_SUMMARY" >/dev/null; then
  echo "authority onboard runbook missing onboard_invite_failed_open completion step"
  cat "$AUTH_ONBOARD_FAIL_OPEN_SUMMARY"
  exit 1
fi
if [[ ! -f "$AUTH_ONBOARD_FAIL_OPEN_INVITE_FILE" ]]; then
  echo "authority onboard invite fail-open diagnostics file not created"
  cat "$AUTH_ONBOARD_FAIL_OPEN_SUMMARY"
  exit 1
fi

echo "[prod-operator-lifecycle] onboard fail path with rollback"
cat >"$FAKE_RELAYS_FILE" <<'EOF_RELAYS_ROLLBACK_ABSENT'
{"relays":[{"relay_id":"entry-other","role":"entry","operator_id":"op-other"},{"relay_id":"exit-other","role":"exit","operator_id":"op-other"}]}
EOF_RELAYS_ROLLBACK_ABSENT
ONBOARD_ROLLBACK_SUMMARY="$TMP_DIR/onboard_fail_with_rollback_summary.json"
ONBOARD_ROLLBACK_INCIDENT_BUNDLE="$TMP_DIR/onboard_fail_with_rollback_incident"
ONBOARD_ROLLBACK_RUNTIME_DOCTOR_FILE="${ONBOARD_ROLLBACK_SUMMARY%.json}.runtime_doctor.log"
ONBOARD_ROLLBACK_REPORT="${ONBOARD_ROLLBACK_SUMMARY%.json}.report.md"
: >"$EASY_CAPTURE"
set +e
EASY_CAPTURE_FILE="$EASY_CAPTURE" \
FAKE_RELAYS_FILE="$FAKE_RELAYS_FILE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
PROD_OPERATOR_LIFECYCLE_CURL_BIN="$FAKE_CURL" \
./scripts/prod_operator_lifecycle_runbook.sh \
  --action onboard \
  --mode provider \
  --public-host 127.0.0.1 \
  --operator-id op-test \
  --preflight-check 0 \
  --health-check 1 \
  --health-timeout-sec 2 \
  --verify-relays 1 \
  --verify-relay-min-count 2 \
  --verify-relay-timeout-sec 1 \
  --federation-check 0 \
  --rollback-on-fail 1 \
  --rollback-verify-absent 1 \
  --rollback-verify-timeout-sec 1 \
  --incident-snapshot-on-fail 1 \
  --incident-bundle-dir "$ONBOARD_ROLLBACK_INCIDENT_BUNDLE" \
  --incident-timeout-sec 7 \
  --incident-include-docker-logs 0 \
  --incident-docker-log-lines 55 \
  --incident-attach-artifact "$ONBOARD_FEDERATION_STATUS" \
  --directory-url http://127.0.0.1:8081 \
  --summary-json "$ONBOARD_ROLLBACK_SUMMARY" >/tmp/integration_prod_operator_lifecycle_runbook_onboard_fail_with_rollback.log 2>&1
onboard_rollback_rc=$?
set -e
if [[ "$onboard_rollback_rc" -ne 4 ]]; then
  echo "onboard fail-with-rollback path returned unexpected rc=$onboard_rollback_rc (expected 4)"
  cat /tmp/integration_prod_operator_lifecycle_runbook_onboard_fail_with_rollback.log
  exit 1
fi
if [[ "$(jq -r '.status' "$ONBOARD_ROLLBACK_SUMMARY")" != "fail" ]]; then
  echo "onboard fail-with-rollback summary has unexpected status"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.failure_step' "$ONBOARD_ROLLBACK_SUMMARY")" != "relay_verify" ]]; then
  echo "onboard fail-with-rollback summary has unexpected failure_step"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.rollback.enabled' "$ONBOARD_ROLLBACK_SUMMARY")" != "true" ]]; then
  echo "onboard fail-with-rollback summary did not report rollback enabled"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.rollback.performed' "$ONBOARD_ROLLBACK_SUMMARY")" != "true" ]]; then
  echo "onboard fail-with-rollback summary did not report rollback performed"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.rollback.state' "$ONBOARD_ROLLBACK_SUMMARY")" != "completed" ]]; then
  echo "onboard fail-with-rollback summary has unexpected rollback state"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.rollback.server_down_rc' "$ONBOARD_ROLLBACK_SUMMARY")" != "0" ]]; then
  echo "onboard fail-with-rollback summary has unexpected rollback server_down_rc"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.rollback.absent_verify_state' "$ONBOARD_ROLLBACK_SUMMARY")" != "ok" ]]; then
  echo "onboard fail-with-rollback summary has unexpected rollback absent_verify_state"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.checks.runtime_doctor_on_fail_enabled' "$ONBOARD_ROLLBACK_SUMMARY")" != "true" ]]; then
  echo "onboard fail-with-rollback summary did not enable runtime doctor on fail"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.runtime_doctor.state' "$ONBOARD_ROLLBACK_SUMMARY")" != "captured" ]]; then
  echo "onboard fail-with-rollback summary has unexpected runtime_doctor.state"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.runtime_doctor.rc' "$ONBOARD_ROLLBACK_SUMMARY")" != "0" ]]; then
  echo "onboard fail-with-rollback summary has unexpected runtime_doctor.rc"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.runtime_doctor.file_required' "$ONBOARD_ROLLBACK_SUMMARY")" != "false" ]]; then
  echo "onboard fail-with-rollback summary has unexpected runtime_doctor.file_required"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.runtime_doctor.file_required_met' "$ONBOARD_ROLLBACK_SUMMARY")" != "true" ]]; then
  echo "onboard fail-with-rollback summary has unexpected runtime_doctor.file_required_met"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.runtime_doctor.file' "$ONBOARD_ROLLBACK_SUMMARY")" != "$ONBOARD_ROLLBACK_RUNTIME_DOCTOR_FILE" ]]; then
  echo "onboard fail-with-rollback summary has unexpected runtime_doctor.file"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ ! -f "$ONBOARD_ROLLBACK_RUNTIME_DOCTOR_FILE" ]]; then
  echo "onboard fail-with-rollback did not write runtime-doctor artifact"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if ! rg -q -- '"doctor":"fake"' "$ONBOARD_ROLLBACK_RUNTIME_DOCTOR_FILE"; then
  echo "onboard fail-with-rollback runtime-doctor artifact missing expected payload"
  cat "$ONBOARD_ROLLBACK_RUNTIME_DOCTOR_FILE"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.state' "$ONBOARD_ROLLBACK_SUMMARY")" != "captured" ]]; then
  echo "onboard fail-with-rollback summary has unexpected incident snapshot state"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.rc' "$ONBOARD_ROLLBACK_SUMMARY")" != "0" ]]; then
  echo "onboard fail-with-rollback summary has unexpected incident snapshot rc"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.bundle_dir' "$ONBOARD_ROLLBACK_SUMMARY")" != "$ONBOARD_ROLLBACK_INCIDENT_BUNDLE" ]]; then
  echo "onboard fail-with-rollback summary has unexpected incident bundle dir"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.summary_json' "$ONBOARD_ROLLBACK_SUMMARY")" != "$ONBOARD_ROLLBACK_INCIDENT_BUNDLE/incident_summary.json" ]]; then
  echo "onboard fail-with-rollback summary has unexpected incident summary path"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.report_md' "$ONBOARD_ROLLBACK_SUMMARY")" != "$ONBOARD_ROLLBACK_INCIDENT_BUNDLE/incident_report.md" ]]; then
  echo "onboard fail-with-rollback summary has unexpected incident report path"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.bundle_tar' "$ONBOARD_ROLLBACK_SUMMARY")" != "${ONBOARD_ROLLBACK_INCIDENT_BUNDLE}.tar.gz" ]]; then
  echo "onboard fail-with-rollback summary has unexpected incident tar path"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.bundle_tar_sha256_file' "$ONBOARD_ROLLBACK_SUMMARY")" != "${ONBOARD_ROLLBACK_INCIDENT_BUNDLE}.tar.gz.sha256" ]]; then
  echo "onboard fail-with-rollback summary has unexpected incident tar sha path"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.artifact_state' "$ONBOARD_ROLLBACK_SUMMARY")" != "complete" ]]; then
  echo "onboard fail-with-rollback summary has unexpected incident artifact_state"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.summary_required' "$ONBOARD_ROLLBACK_SUMMARY")" != "false" ]]; then
  echo "onboard fail-with-rollback summary has unexpected incident summary_required"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.summary_required_met' "$ONBOARD_ROLLBACK_SUMMARY")" != "true" ]]; then
  echo "onboard fail-with-rollback summary has unexpected incident summary_required_met"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.bundle_required' "$ONBOARD_ROLLBACK_SUMMARY")" != "false" ]]; then
  echo "onboard fail-with-rollback summary has unexpected incident bundle_required"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.bundle_required_met' "$ONBOARD_ROLLBACK_SUMMARY")" != "true" ]]; then
  echo "onboard fail-with-rollback summary has unexpected incident bundle_required_met"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.required_artifacts_met' "$ONBOARD_ROLLBACK_SUMMARY")" != "true" ]]; then
  echo "onboard fail-with-rollback summary has unexpected incident required_artifacts_met"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if (( $(jq -r '.incident_snapshot.attach_count' "$ONBOARD_ROLLBACK_SUMMARY") < 2 )); then
  echo "onboard fail-with-rollback summary has unexpected incident attach_count"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if (( $(jq -r '.incident_snapshot.attachment_manifest_count' "$ONBOARD_ROLLBACK_SUMMARY") < 2 )); then
  echo "onboard fail-with-rollback summary has unexpected incident attachment manifest count"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if ! rg -q -- "runtime_doctor\\.log" <<<"$(jq -r '.incident_snapshot.attach_artifacts_csv' "$ONBOARD_ROLLBACK_SUMMARY")"; then
  echo "onboard fail-with-rollback summary attach list missing runtime-doctor artifact"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if [[ ! -f "$ONBOARD_ROLLBACK_REPORT" ]]; then
  echo "onboard fail-with-rollback report markdown artifact missing"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if ! rg -q -- '- status: fail' "$ONBOARD_ROLLBACK_REPORT"; then
  echo "onboard fail-with-rollback report markdown missing fail status line"
  cat "$ONBOARD_ROLLBACK_REPORT"
  exit 1
fi
if [[ ! -f "$ONBOARD_ROLLBACK_INCIDENT_BUNDLE/incident_summary.json" ]]; then
  echo "onboard fail-with-rollback did not create incident bundle summary"
  ls -la "$ONBOARD_ROLLBACK_INCIDENT_BUNDLE" || true
  exit 1
fi
if ! jq -e '.completed_steps | index("rollback_server_down") != null' "$ONBOARD_ROLLBACK_SUMMARY" >/dev/null; then
  echo "onboard fail-with-rollback summary missing rollback_server_down completion step"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if ! jq -e '.completed_steps | index("rollback_relay_absent_verify") != null' "$ONBOARD_ROLLBACK_SUMMARY" >/dev/null; then
  echo "onboard fail-with-rollback summary missing rollback_relay_absent_verify completion step"
  cat "$ONBOARD_ROLLBACK_SUMMARY"
  exit 1
fi
if ! rg -q -- '^server-down$' "$EASY_CAPTURE"; then
  echo "onboard fail-with-rollback path missing rollback server-down invocation"
  cat "$EASY_CAPTURE"
  exit 1
fi
if ! rg -Fq -- "incident-snapshot --mode provider --bundle-dir $ONBOARD_ROLLBACK_INCIDENT_BUNDLE --timeout-sec 7 --include-docker-logs 0 --docker-log-lines 55 --directory-url http://127.0.0.1:8081 --entry-url http://127.0.0.1:8083 --exit-url http://127.0.0.1:8084" "$EASY_CAPTURE"; then
  echo "onboard fail-with-rollback path missing incident-snapshot invocation"
  cat "$EASY_CAPTURE"
  exit 1
fi
if ! rg -Fq -- "--attach-artifact $ONBOARD_ROLLBACK_RUNTIME_DOCTOR_FILE" "$EASY_CAPTURE"; then
  echo "onboard fail-with-rollback path missing runtime-doctor incident attachment"
  cat "$EASY_CAPTURE"
  exit 1
fi

echo "[prod-operator-lifecycle] onboard fail path"
ONBOARD_FAIL_SUMMARY="$TMP_DIR/onboard_fail_summary.json"
ONBOARD_FAIL_RUNTIME_DOCTOR_FILE="${ONBOARD_FAIL_SUMMARY%.json}.runtime_doctor.log"
ONBOARD_FAIL_REPORT="${ONBOARD_FAIL_SUMMARY%.json}.report.md"
: >"$EASY_CAPTURE"
set +e
EASY_CAPTURE_FILE="$EASY_CAPTURE" \
FAKE_RELAYS_FILE="$FAKE_RELAYS_FILE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
FAKE_SERVER_UP_RC=27 \
PROD_OPERATOR_LIFECYCLE_CURL_BIN="$FAKE_CURL" \
./scripts/prod_operator_lifecycle_runbook.sh \
  --action onboard \
  --mode provider \
  --operator-id op-test \
  --preflight-check 0 \
  --health-check 0 \
  --verify-relays 0 \
  --summary-json "$ONBOARD_FAIL_SUMMARY" >/tmp/integration_prod_operator_lifecycle_runbook_onboard_fail.log 2>&1
onboard_fail_rc=$?
set -e
if [[ "$onboard_fail_rc" -ne 27 ]]; then
  echo "onboard fail path returned unexpected rc=$onboard_fail_rc (expected 27)"
  cat /tmp/integration_prod_operator_lifecycle_runbook_onboard_fail.log
  exit 1
fi
if [[ "$(jq -r '.status' "$ONBOARD_FAIL_SUMMARY")" != "fail" ]]; then
  echo "onboard fail path summary has unexpected status"
  cat "$ONBOARD_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.failure_step' "$ONBOARD_FAIL_SUMMARY")" != "server_up" ]]; then
  echo "onboard fail path summary has unexpected failure_step"
  cat "$ONBOARD_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.rollback.state' "$ONBOARD_FAIL_SUMMARY")" != "skipped_server_not_started" ]]; then
  echo "onboard fail path summary has unexpected rollback state"
  cat "$ONBOARD_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.rollback.performed' "$ONBOARD_FAIL_SUMMARY")" != "false" ]]; then
  echo "onboard fail path summary has unexpected rollback performed state"
  cat "$ONBOARD_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.state' "$ONBOARD_FAIL_SUMMARY")" != "captured" ]]; then
  echo "onboard fail path summary has unexpected incident snapshot state"
  cat "$ONBOARD_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.artifact_state' "$ONBOARD_FAIL_SUMMARY")" != "complete" ]]; then
  echo "onboard fail path summary has unexpected incident artifact state"
  cat "$ONBOARD_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.runtime_doctor.state' "$ONBOARD_FAIL_SUMMARY")" != "captured" ]]; then
  echo "onboard fail path summary has unexpected runtime_doctor.state"
  cat "$ONBOARD_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.runtime_doctor.file_required' "$ONBOARD_FAIL_SUMMARY")" != "false" ]]; then
  echo "onboard fail path summary has unexpected runtime_doctor.file_required"
  cat "$ONBOARD_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.runtime_doctor.file_required_met' "$ONBOARD_FAIL_SUMMARY")" != "true" ]]; then
  echo "onboard fail path summary has unexpected runtime_doctor.file_required_met"
  cat "$ONBOARD_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.runtime_doctor.file' "$ONBOARD_FAIL_SUMMARY")" != "$ONBOARD_FAIL_RUNTIME_DOCTOR_FILE" ]]; then
  echo "onboard fail path summary has unexpected runtime_doctor.file"
  cat "$ONBOARD_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.summary_required' "$ONBOARD_FAIL_SUMMARY")" != "false" ]]; then
  echo "onboard fail path summary has unexpected incident summary_required"
  cat "$ONBOARD_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.bundle_required' "$ONBOARD_FAIL_SUMMARY")" != "false" ]]; then
  echo "onboard fail path summary has unexpected incident bundle_required"
  cat "$ONBOARD_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.required_artifacts_met' "$ONBOARD_FAIL_SUMMARY")" != "true" ]]; then
  echo "onboard fail path summary has unexpected incident required_artifacts_met"
  cat "$ONBOARD_FAIL_SUMMARY"
  exit 1
fi
if [[ ! -f "$ONBOARD_FAIL_RUNTIME_DOCTOR_FILE" ]]; then
  echo "onboard fail path runtime-doctor artifact missing"
  cat "$ONBOARD_FAIL_SUMMARY"
  exit 1
fi
if ! rg -q -- '^runtime-doctor --base-port 19280 --client-iface wgcstack0 --exit-iface wgestack0 --vpn-iface wgvpn0 --show-json 1$' "$EASY_CAPTURE"; then
  echo "onboard fail path missing runtime-doctor invocation"
  cat "$EASY_CAPTURE"
  exit 1
fi
if [[ ! -f "$ONBOARD_FAIL_REPORT" ]]; then
  echo "onboard fail path report markdown artifact missing"
  cat "$ONBOARD_FAIL_SUMMARY"
  exit 1
fi
if ! rg -q -- '- failure: server_up \(rc=27\)' "$ONBOARD_FAIL_REPORT"; then
  echo "onboard fail path report markdown missing expected failure line"
  cat "$ONBOARD_FAIL_REPORT"
  exit 1
fi

echo "[prod-operator-lifecycle] runtime-doctor file-required policy"
ONBOARD_RUNTIME_FILE_REQUIRED_SUMMARY="$TMP_DIR/onboard_runtime_file_required_summary.json"
: >"$EASY_CAPTURE"
set +e
EASY_CAPTURE_FILE="$EASY_CAPTURE" \
FAKE_RELAYS_FILE="$FAKE_RELAYS_FILE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
FAKE_SERVER_UP_RC=27 \
FAKE_RUNTIME_DOCTOR_OUTPUT_DISABLE=1 \
PROD_OPERATOR_LIFECYCLE_CURL_BIN="$FAKE_CURL" \
./scripts/prod_operator_lifecycle_runbook.sh \
  --action onboard \
  --mode provider \
  --operator-id op-test \
  --preflight-check 0 \
  --health-check 0 \
  --verify-relays 0 \
  --runtime-doctor-on-fail 1 \
  --runtime-doctor-file-required 1 \
  --incident-snapshot-on-fail 0 \
  --summary-json "$ONBOARD_RUNTIME_FILE_REQUIRED_SUMMARY" >/tmp/integration_prod_operator_lifecycle_runbook_runtime_file_required.log 2>&1
onboard_runtime_required_rc=$?
set -e
if [[ "$onboard_runtime_required_rc" -ne 27 ]]; then
  echo "runtime-doctor file-required policy path returned unexpected rc=$onboard_runtime_required_rc (expected 27)"
  cat /tmp/integration_prod_operator_lifecycle_runbook_runtime_file_required.log
  exit 1
fi
if [[ "$(jq -r '.runtime_doctor.state' "$ONBOARD_RUNTIME_FILE_REQUIRED_SUMMARY")" != "failed_file_required" ]]; then
  echo "runtime-doctor file-required policy summary has unexpected runtime_doctor.state"
  cat "$ONBOARD_RUNTIME_FILE_REQUIRED_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.runtime_doctor.file_required' "$ONBOARD_RUNTIME_FILE_REQUIRED_SUMMARY")" != "true" ]]; then
  echo "runtime-doctor file-required policy summary has unexpected runtime_doctor.file_required"
  cat "$ONBOARD_RUNTIME_FILE_REQUIRED_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.runtime_doctor.file_required_met' "$ONBOARD_RUNTIME_FILE_REQUIRED_SUMMARY")" != "false" ]]; then
  echo "runtime-doctor file-required policy summary has unexpected runtime_doctor.file_required_met"
  cat "$ONBOARD_RUNTIME_FILE_REQUIRED_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.runtime_doctor.rc' "$ONBOARD_RUNTIME_FILE_REQUIRED_SUMMARY")" != "0" ]]; then
  echo "runtime-doctor file-required policy summary has unexpected runtime_doctor.rc"
  cat "$ONBOARD_RUNTIME_FILE_REQUIRED_SUMMARY"
  exit 1
fi
if jq -e '.completed_steps | index("runtime_doctor") != null' "$ONBOARD_RUNTIME_FILE_REQUIRED_SUMMARY" >/dev/null; then
  echo "runtime-doctor file-required policy summary unexpectedly marked runtime_doctor completed"
  cat "$ONBOARD_RUNTIME_FILE_REQUIRED_SUMMARY"
  exit 1
fi

echo "[prod-operator-lifecycle] incident required artifacts policy"
ONBOARD_INCIDENT_REQUIRED_SUMMARY="$TMP_DIR/onboard_incident_required_summary.json"
: >"$EASY_CAPTURE"
set +e
EASY_CAPTURE_FILE="$EASY_CAPTURE" \
FAKE_RELAYS_FILE="$FAKE_RELAYS_FILE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
FAKE_SERVER_UP_RC=27 \
FAKE_INCIDENT_SUMMARY_OUTPUT_DISABLE=1 \
FAKE_INCIDENT_BUNDLE_OUTPUT_DISABLE=1 \
PROD_OPERATOR_LIFECYCLE_CURL_BIN="$FAKE_CURL" \
./scripts/prod_operator_lifecycle_runbook.sh \
  --action onboard \
  --mode provider \
  --operator-id op-test \
  --preflight-check 0 \
  --health-check 0 \
  --verify-relays 0 \
  --runtime-doctor-on-fail 0 \
  --incident-snapshot-on-fail 1 \
  --incident-summary-required 1 \
  --incident-bundle-required 1 \
  --summary-json "$ONBOARD_INCIDENT_REQUIRED_SUMMARY" >/tmp/integration_prod_operator_lifecycle_runbook_incident_required.log 2>&1
onboard_incident_required_rc=$?
set -e
if [[ "$onboard_incident_required_rc" -ne 27 ]]; then
  echo "incident required-artifacts policy path returned unexpected rc=$onboard_incident_required_rc (expected 27)"
  cat /tmp/integration_prod_operator_lifecycle_runbook_incident_required.log
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.state' "$ONBOARD_INCIDENT_REQUIRED_SUMMARY")" != "captured_missing_required_artifacts" ]]; then
  echo "incident required-artifacts policy summary has unexpected incident_snapshot.state"
  cat "$ONBOARD_INCIDENT_REQUIRED_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.summary_required' "$ONBOARD_INCIDENT_REQUIRED_SUMMARY")" != "true" ]]; then
  echo "incident required-artifacts policy summary has unexpected summary_required"
  cat "$ONBOARD_INCIDENT_REQUIRED_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.summary_required_met' "$ONBOARD_INCIDENT_REQUIRED_SUMMARY")" != "false" ]]; then
  echo "incident required-artifacts policy summary has unexpected summary_required_met"
  cat "$ONBOARD_INCIDENT_REQUIRED_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.bundle_required' "$ONBOARD_INCIDENT_REQUIRED_SUMMARY")" != "true" ]]; then
  echo "incident required-artifacts policy summary has unexpected bundle_required"
  cat "$ONBOARD_INCIDENT_REQUIRED_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.bundle_required_met' "$ONBOARD_INCIDENT_REQUIRED_SUMMARY")" != "false" ]]; then
  echo "incident required-artifacts policy summary has unexpected bundle_required_met"
  cat "$ONBOARD_INCIDENT_REQUIRED_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.required_artifacts_met' "$ONBOARD_INCIDENT_REQUIRED_SUMMARY")" != "false" ]]; then
  echo "incident required-artifacts policy summary has unexpected required_artifacts_met"
  cat "$ONBOARD_INCIDENT_REQUIRED_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.artifact_state' "$ONBOARD_INCIDENT_REQUIRED_SUMMARY")" != "missing" ]]; then
  echo "incident required-artifacts policy summary has unexpected artifact_state"
  cat "$ONBOARD_INCIDENT_REQUIRED_SUMMARY"
  exit 1
fi

echo "[prod-operator-lifecycle] incident attachment-manifest required policy"
ONBOARD_INCIDENT_MANIFEST_REQUIRED_SUMMARY="$TMP_DIR/onboard_incident_manifest_required_summary.json"
: >"$EASY_CAPTURE"
set +e
EASY_CAPTURE_FILE="$EASY_CAPTURE" \
FAKE_RELAYS_FILE="$FAKE_RELAYS_FILE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
FAKE_SERVER_UP_RC=27 \
FAKE_INCIDENT_ATTACHMENT_MANIFEST_DISABLE=1 \
PROD_OPERATOR_LIFECYCLE_CURL_BIN="$FAKE_CURL" \
./scripts/prod_operator_lifecycle_runbook.sh \
  --action onboard \
  --mode provider \
  --operator-id op-test \
  --preflight-check 0 \
  --health-check 0 \
  --verify-relays 0 \
  --runtime-doctor-on-fail 1 \
  --incident-snapshot-on-fail 1 \
  --incident-attachment-manifest-required 1 \
  --incident-attachment-no-skips-required 0 \
  --summary-json "$ONBOARD_INCIDENT_MANIFEST_REQUIRED_SUMMARY" >/tmp/integration_prod_operator_lifecycle_runbook_incident_manifest_required.log 2>&1
onboard_incident_manifest_required_rc=$?
set -e
if [[ "$onboard_incident_manifest_required_rc" -ne 27 ]]; then
  echo "incident attachment-manifest-required policy path returned unexpected rc=$onboard_incident_manifest_required_rc (expected 27)"
  cat /tmp/integration_prod_operator_lifecycle_runbook_incident_manifest_required.log
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.state' "$ONBOARD_INCIDENT_MANIFEST_REQUIRED_SUMMARY")" != "captured_missing_attachment_manifest_required" ]]; then
  echo "incident attachment-manifest-required policy summary has unexpected incident_snapshot.state"
  cat "$ONBOARD_INCIDENT_MANIFEST_REQUIRED_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.attachment_manifest_required' "$ONBOARD_INCIDENT_MANIFEST_REQUIRED_SUMMARY")" != "true" ]]; then
  echo "incident attachment-manifest-required policy summary has unexpected attachment_manifest_required"
  cat "$ONBOARD_INCIDENT_MANIFEST_REQUIRED_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.attachment_manifest_required_met' "$ONBOARD_INCIDENT_MANIFEST_REQUIRED_SUMMARY")" != "false" ]]; then
  echo "incident attachment-manifest-required policy summary has unexpected attachment_manifest_required_met"
  cat "$ONBOARD_INCIDENT_MANIFEST_REQUIRED_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.required_attachment_policy_met' "$ONBOARD_INCIDENT_MANIFEST_REQUIRED_SUMMARY")" != "false" ]]; then
  echo "incident attachment-manifest-required policy summary has unexpected required_attachment_policy_met"
  cat "$ONBOARD_INCIDENT_MANIFEST_REQUIRED_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.required_policies_met' "$ONBOARD_INCIDENT_MANIFEST_REQUIRED_SUMMARY")" != "false" ]]; then
  echo "incident attachment-manifest-required policy summary has unexpected required_policies_met"
  cat "$ONBOARD_INCIDENT_MANIFEST_REQUIRED_SUMMARY"
  exit 1
fi
if (( $(jq -r '.incident_snapshot.attach_count' "$ONBOARD_INCIDENT_MANIFEST_REQUIRED_SUMMARY") < 1 )); then
  echo "incident attachment-manifest-required policy summary has unexpected attach_count"
  cat "$ONBOARD_INCIDENT_MANIFEST_REQUIRED_SUMMARY"
  exit 1
fi

echo "[prod-operator-lifecycle] incident no-skipped-attachments policy"
ONBOARD_INCIDENT_NO_SKIPS_REQUIRED_SUMMARY="$TMP_DIR/onboard_incident_no_skips_required_summary.json"
: >"$EASY_CAPTURE"
set +e
EASY_CAPTURE_FILE="$EASY_CAPTURE" \
FAKE_RELAYS_FILE="$FAKE_RELAYS_FILE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
FAKE_SERVER_UP_RC=27 \
FAKE_INCIDENT_ATTACHMENT_SKIPPED_INJECT=1 \
PROD_OPERATOR_LIFECYCLE_CURL_BIN="$FAKE_CURL" \
./scripts/prod_operator_lifecycle_runbook.sh \
  --action onboard \
  --mode provider \
  --operator-id op-test \
  --preflight-check 0 \
  --health-check 0 \
  --verify-relays 0 \
  --runtime-doctor-on-fail 0 \
  --incident-snapshot-on-fail 1 \
  --incident-attachment-manifest-required 0 \
  --incident-attachment-no-skips-required 1 \
  --summary-json "$ONBOARD_INCIDENT_NO_SKIPS_REQUIRED_SUMMARY" >/tmp/integration_prod_operator_lifecycle_runbook_incident_no_skips_required.log 2>&1
onboard_incident_no_skips_required_rc=$?
set -e
if [[ "$onboard_incident_no_skips_required_rc" -ne 27 ]]; then
  echo "incident no-skips-required policy path returned unexpected rc=$onboard_incident_no_skips_required_rc (expected 27)"
  cat /tmp/integration_prod_operator_lifecycle_runbook_incident_no_skips_required.log
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.state' "$ONBOARD_INCIDENT_NO_SKIPS_REQUIRED_SUMMARY")" != "captured_attachment_skips_required" ]]; then
  echo "incident no-skips-required policy summary has unexpected incident_snapshot.state"
  cat "$ONBOARD_INCIDENT_NO_SKIPS_REQUIRED_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.attachment_no_skips_required' "$ONBOARD_INCIDENT_NO_SKIPS_REQUIRED_SUMMARY")" != "true" ]]; then
  echo "incident no-skips-required policy summary has unexpected attachment_no_skips_required"
  cat "$ONBOARD_INCIDENT_NO_SKIPS_REQUIRED_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.attachment_no_skips_required_met' "$ONBOARD_INCIDENT_NO_SKIPS_REQUIRED_SUMMARY")" != "false" ]]; then
  echo "incident no-skips-required policy summary has unexpected attachment_no_skips_required_met"
  cat "$ONBOARD_INCIDENT_NO_SKIPS_REQUIRED_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.required_attachment_policy_met' "$ONBOARD_INCIDENT_NO_SKIPS_REQUIRED_SUMMARY")" != "false" ]]; then
  echo "incident no-skips-required policy summary has unexpected required_attachment_policy_met"
  cat "$ONBOARD_INCIDENT_NO_SKIPS_REQUIRED_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.required_policies_met' "$ONBOARD_INCIDENT_NO_SKIPS_REQUIRED_SUMMARY")" != "false" ]]; then
  echo "incident no-skips-required policy summary has unexpected required_policies_met"
  cat "$ONBOARD_INCIDENT_NO_SKIPS_REQUIRED_SUMMARY"
  exit 1
fi
if (( $(jq -r '.incident_snapshot.attachment_skipped_count' "$ONBOARD_INCIDENT_NO_SKIPS_REQUIRED_SUMMARY") < 1 )); then
  echo "incident no-skips-required policy summary has unexpected attachment_skipped_count"
  cat "$ONBOARD_INCIDENT_NO_SKIPS_REQUIRED_SUMMARY"
  exit 1
fi

echo "[prod-operator-lifecycle] incident attachment min-count policy"
ONBOARD_INCIDENT_ATTACH_MIN_COUNT_SUMMARY="$TMP_DIR/onboard_incident_attach_min_count_summary.json"
INCIDENT_ATTACH_MIN_COUNT_ARTIFACT="$TMP_DIR/incident_attach_min_count_artifact.log"
printf 'attach-min-count evidence\n' >"$INCIDENT_ATTACH_MIN_COUNT_ARTIFACT"
: >"$EASY_CAPTURE"
set +e
EASY_CAPTURE_FILE="$EASY_CAPTURE" \
FAKE_RELAYS_FILE="$FAKE_RELAYS_FILE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
FAKE_SERVER_UP_RC=27 \
PROD_OPERATOR_LIFECYCLE_CURL_BIN="$FAKE_CURL" \
./scripts/prod_operator_lifecycle_runbook.sh \
  --action onboard \
  --mode provider \
  --operator-id op-test \
  --preflight-check 0 \
  --health-check 0 \
  --verify-relays 0 \
  --runtime-doctor-on-fail 0 \
  --incident-snapshot-on-fail 1 \
  --incident-attach-min-count 2 \
  --incident-attachment-manifest-min-count 0 \
  --incident-attach-artifact "$INCIDENT_ATTACH_MIN_COUNT_ARTIFACT" \
  --summary-json "$ONBOARD_INCIDENT_ATTACH_MIN_COUNT_SUMMARY" >/tmp/integration_prod_operator_lifecycle_runbook_incident_attach_min_count.log 2>&1
onboard_incident_attach_min_count_rc=$?
set -e
if [[ "$onboard_incident_attach_min_count_rc" -ne 27 ]]; then
  echo "incident attach-min-count policy path returned unexpected rc=$onboard_incident_attach_min_count_rc (expected 27)"
  cat /tmp/integration_prod_operator_lifecycle_runbook_incident_attach_min_count.log
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.state' "$ONBOARD_INCIDENT_ATTACH_MIN_COUNT_SUMMARY")" != "captured_attachment_min_count_required" ]]; then
  echo "incident attach-min-count policy summary has unexpected incident_snapshot.state"
  cat "$ONBOARD_INCIDENT_ATTACH_MIN_COUNT_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.attach_min_count_required' "$ONBOARD_INCIDENT_ATTACH_MIN_COUNT_SUMMARY")" != "2" ]]; then
  echo "incident attach-min-count policy summary has unexpected attach_min_count_required"
  cat "$ONBOARD_INCIDENT_ATTACH_MIN_COUNT_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.attach_min_count_required_met' "$ONBOARD_INCIDENT_ATTACH_MIN_COUNT_SUMMARY")" != "false" ]]; then
  echo "incident attach-min-count policy summary has unexpected attach_min_count_required_met"
  cat "$ONBOARD_INCIDENT_ATTACH_MIN_COUNT_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.attachment_policy_failure_count' "$ONBOARD_INCIDENT_ATTACH_MIN_COUNT_SUMMARY")" != "1" ]]; then
  echo "incident attach-min-count policy summary has unexpected attachment_policy_failure_count"
  cat "$ONBOARD_INCIDENT_ATTACH_MIN_COUNT_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.required_attachment_policy_met' "$ONBOARD_INCIDENT_ATTACH_MIN_COUNT_SUMMARY")" != "false" ]]; then
  echo "incident attach-min-count policy summary has unexpected required_attachment_policy_met"
  cat "$ONBOARD_INCIDENT_ATTACH_MIN_COUNT_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.required_policies_met' "$ONBOARD_INCIDENT_ATTACH_MIN_COUNT_SUMMARY")" != "false" ]]; then
  echo "incident attach-min-count policy summary has unexpected required_policies_met"
  cat "$ONBOARD_INCIDENT_ATTACH_MIN_COUNT_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.attach_count' "$ONBOARD_INCIDENT_ATTACH_MIN_COUNT_SUMMARY")" != "1" ]]; then
  echo "incident attach-min-count policy summary has unexpected attach_count"
  cat "$ONBOARD_INCIDENT_ATTACH_MIN_COUNT_SUMMARY"
  exit 1
fi

echo "[prod-operator-lifecycle] incident attachment manifest min-count policy"
ONBOARD_INCIDENT_MANIFEST_MIN_COUNT_SUMMARY="$TMP_DIR/onboard_incident_manifest_min_count_summary.json"
INCIDENT_MANIFEST_MIN_COUNT_ARTIFACT="$TMP_DIR/incident_manifest_min_count_artifact.log"
printf 'manifest-min-count evidence\n' >"$INCIDENT_MANIFEST_MIN_COUNT_ARTIFACT"
: >"$EASY_CAPTURE"
set +e
EASY_CAPTURE_FILE="$EASY_CAPTURE" \
FAKE_RELAYS_FILE="$FAKE_RELAYS_FILE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
FAKE_SERVER_UP_RC=27 \
PROD_OPERATOR_LIFECYCLE_CURL_BIN="$FAKE_CURL" \
./scripts/prod_operator_lifecycle_runbook.sh \
  --action onboard \
  --mode provider \
  --operator-id op-test \
  --preflight-check 0 \
  --health-check 0 \
  --verify-relays 0 \
  --runtime-doctor-on-fail 0 \
  --incident-snapshot-on-fail 1 \
  --incident-attach-min-count 0 \
  --incident-attachment-manifest-min-count 2 \
  --incident-attach-artifact "$INCIDENT_MANIFEST_MIN_COUNT_ARTIFACT" \
  --summary-json "$ONBOARD_INCIDENT_MANIFEST_MIN_COUNT_SUMMARY" >/tmp/integration_prod_operator_lifecycle_runbook_incident_manifest_min_count.log 2>&1
onboard_incident_manifest_min_count_rc=$?
set -e
if [[ "$onboard_incident_manifest_min_count_rc" -ne 27 ]]; then
  echo "incident attachment-manifest-min-count policy path returned unexpected rc=$onboard_incident_manifest_min_count_rc (expected 27)"
  cat /tmp/integration_prod_operator_lifecycle_runbook_incident_manifest_min_count.log
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.state' "$ONBOARD_INCIDENT_MANIFEST_MIN_COUNT_SUMMARY")" != "captured_attachment_manifest_min_count_required" ]]; then
  echo "incident attachment-manifest-min-count policy summary has unexpected incident_snapshot.state"
  cat "$ONBOARD_INCIDENT_MANIFEST_MIN_COUNT_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.attachment_manifest_min_count_required' "$ONBOARD_INCIDENT_MANIFEST_MIN_COUNT_SUMMARY")" != "2" ]]; then
  echo "incident attachment-manifest-min-count policy summary has unexpected attachment_manifest_min_count_required"
  cat "$ONBOARD_INCIDENT_MANIFEST_MIN_COUNT_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.attachment_manifest_min_count_required_met' "$ONBOARD_INCIDENT_MANIFEST_MIN_COUNT_SUMMARY")" != "false" ]]; then
  echo "incident attachment-manifest-min-count policy summary has unexpected attachment_manifest_min_count_required_met"
  cat "$ONBOARD_INCIDENT_MANIFEST_MIN_COUNT_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.attachment_policy_failure_count' "$ONBOARD_INCIDENT_MANIFEST_MIN_COUNT_SUMMARY")" != "1" ]]; then
  echo "incident attachment-manifest-min-count policy summary has unexpected attachment_policy_failure_count"
  cat "$ONBOARD_INCIDENT_MANIFEST_MIN_COUNT_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.required_attachment_policy_met' "$ONBOARD_INCIDENT_MANIFEST_MIN_COUNT_SUMMARY")" != "false" ]]; then
  echo "incident attachment-manifest-min-count policy summary has unexpected required_attachment_policy_met"
  cat "$ONBOARD_INCIDENT_MANIFEST_MIN_COUNT_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.required_policies_met' "$ONBOARD_INCIDENT_MANIFEST_MIN_COUNT_SUMMARY")" != "false" ]]; then
  echo "incident attachment-manifest-min-count policy summary has unexpected required_policies_met"
  cat "$ONBOARD_INCIDENT_MANIFEST_MIN_COUNT_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.incident_snapshot.attachment_manifest_count' "$ONBOARD_INCIDENT_MANIFEST_MIN_COUNT_SUMMARY")" != "1" ]]; then
  echo "incident attachment-manifest-min-count policy summary has unexpected attachment_manifest_count"
  cat "$ONBOARD_INCIDENT_MANIFEST_MIN_COUNT_SUMMARY"
  exit 1
fi

echo "[prod-operator-lifecycle] offboard success path"
cat >"$FAKE_RELAYS_FILE" <<'EOF_RELAYS_ABSENT'
{"relays":[{"relay_id":"entry-other","role":"entry","operator_id":"op-other"},{"relay_id":"exit-other","role":"exit","operator_id":"op-other"}]}
EOF_RELAYS_ABSENT
OFFBOARD_SUMMARY="$TMP_DIR/offboard_summary.json"
: >"$EASY_CAPTURE"
EASY_CAPTURE_FILE="$EASY_CAPTURE" \
FAKE_RELAYS_FILE="$FAKE_RELAYS_FILE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
PROD_OPERATOR_LIFECYCLE_CURL_BIN="$FAKE_CURL" \
./scripts/prod_operator_lifecycle_runbook.sh \
  --action offboard \
  --operator-id op-test \
  --verify-absent 1 \
  --verify-relay-timeout-sec 2 \
  --directory-url http://127.0.0.1:8081 \
  --summary-json "$OFFBOARD_SUMMARY" >/tmp/integration_prod_operator_lifecycle_runbook_offboard_ok.log 2>&1

if [[ "$(jq -r '.status' "$OFFBOARD_SUMMARY")" != "ok" ]]; then
  echo "offboard runbook summary has unexpected status"
  cat "$OFFBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.action' "$OFFBOARD_SUMMARY")" != "offboard" ]]; then
  echo "offboard runbook summary has unexpected action"
  cat "$OFFBOARD_SUMMARY"
  exit 1
fi
if ! jq -e '.completed_steps | index("server_down") != null' "$OFFBOARD_SUMMARY" >/dev/null; then
  echo "offboard runbook missing server_down completion step"
  cat "$OFFBOARD_SUMMARY"
  exit 1
fi
if ! jq -e '.completed_steps | index("relay_absent_verify") != null' "$OFFBOARD_SUMMARY" >/dev/null; then
  echo "offboard runbook missing relay_absent_verify completion step"
  cat "$OFFBOARD_SUMMARY"
  exit 1
fi
if ! rg -q -- '^server-down$' "$EASY_CAPTURE"; then
  echo "offboard runbook missing server-down invocation"
  cat "$EASY_CAPTURE"
  exit 1
fi

cat >"$TMP_BIN/docker" <<'EOF_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "compose" && "${2:-}" == "version" ]]; then
  printf 'Docker Compose version vtest\n'
  exit 0
fi
if [[ "${1:-}" == "compose" ]]; then
  exit 0
fi
if [[ "${1:-}" == "--version" ]]; then
  printf 'Docker version test\n'
  exit 0
fi
if [[ "${1:-}" == "info" ]]; then
  exit 0
fi
exit 0
EOF_DOCKER
chmod +x "$TMP_BIN/docker"

FAKE_RUNBOOK="$TMP_DIR/fake_prod_operator_lifecycle_runbook.sh"
DISPATCH_CAPTURE="$TMP_DIR/dispatch_capture.log"
cat >"$FAKE_RUNBOOK" <<'EOF_FAKE_RUNBOOK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${DISPATCH_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_RUNBOOK
chmod +x "$FAKE_RUNBOOK"

echo "[prod-operator-lifecycle] easy_node dispatch"
PATH="$TMP_BIN:$PATH" \
DISPATCH_CAPTURE_FILE="$DISPATCH_CAPTURE" \
PROD_OPERATOR_LIFECYCLE_RUNBOOK_SCRIPT="$FAKE_RUNBOOK" \
./scripts/easy_node.sh prod-operator-lifecycle-runbook \
  --action offboard \
  --verify-absent 0 \
  --federation-check 0 \
  --federation-ready-timeout-sec 11 \
  --federation-poll-sec 2 \
  --federation-timeout-sec 5 \
  --federation-min-peer-source-operators 4 \
  --federation-min-issuer-source-operators 5 \
  --federation-wait-file /tmp/fed_wait_dispatch.log \
  --federation-wait-file-required 1 \
  --federation-wait-summary-json /tmp/fed_wait_summary_dispatch.json \
  --federation-wait-print-summary-json 1 \
  --federation-wait-summary-required 1 \
  --federation-status-fail-on-not-ready 1 \
  --federation-status-file /tmp/fed_status_dispatch.json \
  --federation-status-file-required 1 \
  --federation-status-summary-json /tmp/fed_status_summary_dispatch.json \
  --federation-status-summary-required 1 \
  --onboard-invite 1 \
  --onboard-invite-count 4 \
  --onboard-invite-tier 3 \
  --onboard-invite-wait-sec 9 \
  --onboard-invite-fail-open 0 \
  --onboard-invite-file /tmp/onboard_invites_dispatch.txt \
  --rollback-on-fail 0 \
  --rollback-verify-absent 0 \
  --rollback-verify-timeout-sec 14 \
  --runtime-doctor-on-fail 1 \
  --runtime-doctor-base-port 19333 \
  --runtime-doctor-client-iface wg-client-test \
  --runtime-doctor-exit-iface wg-exit-test \
  --runtime-doctor-vpn-iface wg-vpn-test \
  --runtime-doctor-file /tmp/operator_runtime_doctor_dispatch.log \
  --runtime-doctor-file-required 1 \
  --incident-snapshot-on-fail 0 \
  --incident-bundle-dir /tmp/operator_incident_dispatch \
  --incident-timeout-sec 18 \
  --incident-include-docker-logs 0 \
  --incident-docker-log-lines 42 \
  --incident-summary-required 1 \
  --incident-bundle-required 1 \
  --incident-attachment-manifest-required 1 \
  --incident-attachment-no-skips-required 1 \
  --incident-attach-min-count 6 \
  --incident-attachment-manifest-min-count 7 \
  --incident-attach-artifact /tmp/operator_attach_dispatch.log \
  --report-md /tmp/operator_lifecycle_dispatch.md >/tmp/integration_prod_operator_lifecycle_runbook_dispatch.log 2>&1

if ! rg -q -- '--action offboard' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --action"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--verify-absent 0' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --verify-absent"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--federation-check 0' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --federation-check"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--federation-ready-timeout-sec 11' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --federation-ready-timeout-sec"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--federation-poll-sec 2' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --federation-poll-sec"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--federation-timeout-sec 5' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --federation-timeout-sec"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--federation-min-peer-source-operators 4' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --federation-min-peer-source-operators"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--federation-min-issuer-source-operators 5' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --federation-min-issuer-source-operators"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--federation-wait-file /tmp/fed_wait_dispatch\.log' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --federation-wait-file"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--federation-wait-file-required 1' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --federation-wait-file-required"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--federation-wait-summary-json /tmp/fed_wait_summary_dispatch\.json' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --federation-wait-summary-json"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--federation-wait-print-summary-json 1' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --federation-wait-print-summary-json"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--federation-wait-summary-required 1' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --federation-wait-summary-required"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--federation-status-fail-on-not-ready 1' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --federation-status-fail-on-not-ready"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--federation-status-file /tmp/fed_status_dispatch\.json' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --federation-status-file"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--federation-status-file-required 1' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --federation-status-file-required"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--federation-status-summary-json /tmp/fed_status_summary_dispatch\.json' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --federation-status-summary-json"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--federation-status-summary-required 1' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --federation-status-summary-required"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--onboard-invite 1' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --onboard-invite"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--onboard-invite-count 4' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --onboard-invite-count"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--onboard-invite-tier 3' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --onboard-invite-tier"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--onboard-invite-wait-sec 9' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --onboard-invite-wait-sec"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--onboard-invite-fail-open 0' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --onboard-invite-fail-open"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--onboard-invite-file /tmp/onboard_invites_dispatch\.txt' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --onboard-invite-file"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--rollback-on-fail 0' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --rollback-on-fail"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--rollback-verify-absent 0' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --rollback-verify-absent"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--rollback-verify-timeout-sec 14' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --rollback-verify-timeout-sec"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--runtime-doctor-on-fail 1' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --runtime-doctor-on-fail"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--runtime-doctor-base-port 19333' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --runtime-doctor-base-port"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--runtime-doctor-client-iface wg-client-test' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --runtime-doctor-client-iface"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--runtime-doctor-exit-iface wg-exit-test' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --runtime-doctor-exit-iface"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--runtime-doctor-vpn-iface wg-vpn-test' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --runtime-doctor-vpn-iface"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--runtime-doctor-file /tmp/operator_runtime_doctor_dispatch\.log' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --runtime-doctor-file"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--runtime-doctor-file-required 1' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --runtime-doctor-file-required"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-snapshot-on-fail 0' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --incident-snapshot-on-fail"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-bundle-dir /tmp/operator_incident_dispatch' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --incident-bundle-dir"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-timeout-sec 18' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --incident-timeout-sec"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-include-docker-logs 0' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --incident-include-docker-logs"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-docker-log-lines 42' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --incident-docker-log-lines"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-summary-required 1' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --incident-summary-required"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-bundle-required 1' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --incident-bundle-required"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-attachment-manifest-required 1' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --incident-attachment-manifest-required"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-attachment-no-skips-required 1' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --incident-attachment-no-skips-required"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-attach-min-count 6' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --incident-attach-min-count"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-attachment-manifest-min-count 7' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --incident-attachment-manifest-min-count"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-attach-artifact /tmp/operator_attach_dispatch\.log' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --incident-attach-artifact"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--report-md /tmp/operator_lifecycle_dispatch\.md' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --report-md"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi

echo "prod operator lifecycle runbook integration check ok"
