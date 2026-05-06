#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq rg mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/fake_easy_calls.log"
FAKE_COUNTER_DIR="$TMP_DIR/counters"
FAKE_LOG_DIR="$TMP_DIR/client_logs"
mkdir -p "$FAKE_COUNTER_DIR" "$FAKE_LOG_DIR"

FAKE_EASY="$TMP_DIR/fake_easy_node.sh"
cat >"$FAKE_EASY" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"${FAKE_CAPTURE_FILE:?}"
printf 'env container_directory_urls=%s container_issuer_url=%s container_entry_url=%s container_exit_url=%s client_inner_source=%s disable_synthetic_fallback=%s data_plane_mode=%s client_force_build=%s directory_trusted_keys_file=%s wg_only_mode=%s client_live_wg_mode=%s client_wg_backend=%s client_wg_private_key_path=%s client_wg_interface=%s client_wg_kernel_proxy=%s client_wg_proxy_addr=%s startup_sync_timeout_sec=%s\n' \
  "${EASY_NODE_CLIENT_TEST_CONTAINER_DIRECTORY_URLS:-}" \
  "${EASY_NODE_CLIENT_TEST_CONTAINER_ISSUER_URL:-}" \
  "${EASY_NODE_CLIENT_TEST_CONTAINER_ENTRY_URL:-}" \
  "${EASY_NODE_CLIENT_TEST_CONTAINER_EXIT_URL:-}" \
  "${CLIENT_INNER_SOURCE:-}" \
  "${CLIENT_DISABLE_SYNTHETIC_FALLBACK:-}" \
  "${DATA_PLANE_MODE:-}" \
  "${EASY_NODE_CLIENT_FORCE_BUILD:-}" \
  "${DIRECTORY_TRUSTED_KEYS_FILE:-}" \
  "${WG_ONLY_MODE:-}" \
  "${CLIENT_LIVE_WG_MODE:-}" \
  "${CLIENT_WG_BACKEND:-}" \
  "${CLIENT_WG_PRIVATE_KEY_PATH:-}" \
  "${CLIENT_WG_INTERFACE:-}" \
  "${CLIENT_WG_KERNEL_PROXY:-}" \
  "${CLIENT_WG_PROXY_ADDR:-}" \
  "${CLIENT_STARTUP_SYNC_TIMEOUT_SEC:-}" >>"${FAKE_CAPTURE_FILE:?}"
cmd="${1:-}"
shift || true

case "$cmd" in
  wg-only-stack-up)
    mkdir -p deploy/data/wg_only
    printf '%s\n' fake-directory-key >deploy/data/wg_only/fake_trusted_directory_keys.txt
    printf '%s\n' fake-client-private-key >deploy/data/wg_only/fake_client.key
    chmod 600 deploy/data/wg_only/fake_client.key
    cat >deploy/data/wg_only_stack.state <<EOF_STATE
WG_ONLY_KEY_DIR=$PWD/deploy/data/wg_only
WG_ONLY_CLIENT_WG_PRIVATE_KEY_PATH=$PWD/deploy/data/wg_only/fake_client.key
WG_ONLY_CLIENT_WG_INTERFACE=wgcstack0
WG_ONLY_CLIENT_WG_PROXY_ADDR=127.0.0.1:19383
WG_ONLY_CLIENT_STARTUP_SYNC_TIMEOUT_SEC=8
WG_ONLY_DIRECTORY_TRUST_FILE=$PWD/deploy/data/wg_only/fake_trusted_directory_keys.txt
EOF_STATE
    echo "fake $cmd ok"
    exit 0
    ;;
  wg-only-stack-down)
    rm -f deploy/data/wg_only_stack.state deploy/data/wg_only/fake_trusted_directory_keys.txt deploy/data/wg_only/fake_client.key
    echo "fake $cmd ok"
    exit 0
    ;;
  client-test)
    profile=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --path-profile)
          profile="${2:-}"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done

    if [[ -z "$profile" ]]; then
      echo "fake client-test missing --path-profile"
      exit 2
    fi

    counter_file="${FAKE_COUNTER_DIR:?}/${profile}.count"
    count=0
    if [[ -f "$counter_file" ]]; then
      count="$(cat "$counter_file")"
    fi
    count=$((count + 1))
    printf '%s\n' "$count" >"$counter_file"

    client_log="${FAKE_LOG_DIR:?}/client_${profile}_${count}.log"
    direct_forced="false"
    if [[ "$profile" == "speed-1hop" ]]; then
      direct_forced="true"
    fi
    policy_path_profile="2hop"
    case "$profile" in
      private)
        policy_path_profile="3hop"
        ;;
      speed-1hop)
        policy_path_profile="1hop"
        ;;
    esac

    {
      echo "2026/03/24 12:00:00 client role enabled: path_profile=${policy_path_profile} direct_exit_forced=${direct_forced}"
      if [[ "$profile" == "speed" ]]; then
        echo "2026/03/24 12:00:01 client bootstrap retry failed: transient"
      fi
      if [[ "$profile" == "speed-1hop" ]]; then
        echo "2026/03/24 12:00:02 client direct-exit mode engaged entry=entry-local-1 exit=exit-local-1"
      fi
      middle_segment=""
      if [[ "$profile" == "private" ]]; then
        middle_segment=" middle=micro-relay-1 middle_op=op-middle"
      fi
      echo "2026/03/24 12:00:03 client received wg-session config: key_id=test"
      if [[ "${FAKE_CLIENT_KERNEL_PROXY_READY:-0}" == "1" ]]; then
        echo "2026/03/24 12:00:04 client wg-kernel proxy listening: interface=wgvpn0 addr=127.0.0.1:57970 allowed_ips=0.0.0.0/0 install_route=false session=test"
      else
        echo "2026/03/24 12:00:04 client wireguard runtime ready: interface=wgvpn0 key_id=test"
      fi
      echo "2026/03/24 12:00:05 client selected entry=entry-local-1 (http://entry) entry_op=op-entry${middle_segment} exit=exit-local-1 (http://exit) exit_op=op-exit path_control=http://entry token_exp=1"
      if [[ "$profile" == "private" && "$count" -eq 2 ]]; then
        echo "2026/03/24 12:00:06 token proof invalid: deterministic m4 quality penalty"
      fi
    } >"$client_log"

    echo "client selection summary: selections=1 entry_ops=1 exit_ops=1 cross_pairs=1 same_ops=0 missing_ops=0"

    if [[ "$profile" == "private" && "$count" -eq 2 ]]; then
      echo "client test: failed"
      echo "client test log: $client_log"
      exit 1
    fi

    echo "client test: ok"
    echo "client test log: $client_log"
    exit 0
    ;;
  *)
    echo "unexpected fake easy command: $cmd"
    exit 1
    ;;
esac
EOF_FAKE
chmod +x "$FAKE_EASY"

SUMMARY_JSON="$TMP_DIR/profile_compare_summary.json"
REPORT_MD="$TMP_DIR/profile_compare_report.md"
RUN_LOG="$TMP_DIR/profile_compare_run.log"

echo "[profile-compare-local] script behavior"
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$FAKE_COUNTER_DIR" \
FAKE_LOG_DIR="$FAKE_LOG_DIR" \
PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT="$FAKE_EASY" \
./scripts/profile_compare_local.sh \
  --profiles balanced,speed,private,speed-1hop \
  --rounds 2 \
  --execution-mode local \
  --directory-urls http://dir-a:8081 \
  --issuer-url http://issuer-a:8082 \
  --entry-url http://entry-a:8083 \
  --exit-url http://exit-a:8084 \
  --summary-json "$SUMMARY_JSON" \
  --report-md "$REPORT_MD" \
  --print-summary-json 1 >"$RUN_LOG"

if ! rg -q 'profile-compare-local: status=warn' "$RUN_LOG"; then
  echo "expected warn status in profile compare output"
  cat "$RUN_LOG"
  exit 1
fi
if [[ ! -f "$SUMMARY_JSON" || ! -f "$REPORT_MD" ]]; then
  echo "expected profile compare artifacts missing"
  ls -la "$TMP_DIR"
  exit 1
fi
if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .summary.runs_total == 8
  and .summary.runs_executed == 8
  and .summary.runs_fail == 1
  and .summary.selection_policy.sticky_pair_sec == 300
  and .summary.selection_policy.entry_rotation_sec == 180
  and .summary.selection_policy.entry_rotation_jitter_pct == 15
  and .summary.selection_policy.exit_exploration_pct == 10
  and .summary.selection_policy.path_profile == "2hop"
  and .summary.selection_policy.source == "partial-log-fallback"
  and .summary.selection_policy.observed_from_log == false
  and .summary.selection_policy_source == "partial-log-fallback"
  and .decision.recommended_default_profile == "balanced"
  and .summary.m4_micro_relay_evidence.available == true
  and .summary.m4_micro_relay_evidence.middle_selection_count == 2
  and .summary.m4_micro_relay_evidence.micro_relay_quality.available == true
  and .summary.m4_micro_relay_evidence.micro_relay_quality.middle_selection_count == 2
  and .summary.m4_micro_relay_evidence.micro_relay_quality.sample_runs == 2
  and .summary.m4_micro_relay_evidence.micro_relay_quality.all_executed_runs == 8
  and .summary.m4_micro_relay_evidence.micro_relay_quality.score_denominator_runs == 2
  and .summary.m4_micro_relay_evidence.micro_relay_quality.quality_score == 96
  and .summary.m4_micro_relay_evidence.micro_relay_quality.signals.token_proof_invalid_failures_total == 1
  and .summary.m4_micro_relay_evidence.micro_relay_quality.signals.m4_token_proof_invalid_failures_total == 1
  and .summary.m4_micro_relay_evidence.micro_relay_quality.signals.m4_runs_pass == 1
  and .summary.m4_micro_relay_evidence.micro_relay_quality.signals.m4_runs_fail == 1
  and .summary.m4_micro_relay_evidence.adaptive_demotion_promotion.available == true
  and .summary.m4_micro_relay_evidence.adaptive_demotion_promotion.demotion_signal_count == 1
  and .summary.m4_micro_relay_evidence.adaptive_demotion_promotion.promotion_signal_count == 1
  and .summary.m4_micro_relay_evidence.adaptive_demotion_promotion.demotion_candidate == true
  and .summary.m4_micro_relay_evidence.adaptive_demotion_promotion.promotion_candidate == false
  and (.summary.m4_micro_relay_evidence.adaptive_demotion_promotion.reason | contains("demotion signals are present"))
  and .summary.m4_micro_relay_evidence.trust_tier_port_unlock_wiring.present == false
  and (.summary.m4_micro_relay_evidence.trust_tier_port_unlock_wiring.reason | type == "string")
  and ([.profiles[] | select(.profile == "speed-1hop")][0].direct_exit_forced_runs == 2)
' "$SUMMARY_JSON" >/dev/null; then
  echo "summary json missing expected fields"
  cat "$SUMMARY_JSON"
  exit 1
fi
if rg -q '^wg-only-stack-up' "$CAPTURE"; then
  echo "profile compare should not auto-start local stack when explicit endpoints are provided"
  cat "$CAPTURE"
  exit 1
fi
remote_env_line="$(rg '^env ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$remote_env_line" ]]; then
  echo "missing remote env capture line"
  cat "$CAPTURE"
  exit 1
fi
for expected in 'client_inner_source=udp' 'disable_synthetic_fallback=1' 'data_plane_mode=opaque'; do
  if ! grep -F -- "$expected" <<<"$remote_env_line" >/dev/null; then
    echo "remote endpoint run missing $expected"
    cat "$CAPTURE"
    exit 1
  fi
done
if ! rg -q -- 'client-test .*--path-profile speed-1hop .*--min-entry-operators 0' "$CAPTURE"; then
  echo "speed-1hop profile compare should allow direct-exit selection without an entry operator"
  cat "$CAPTURE"
  exit 1
fi
if rg -q -- 'client-test .*--path-profile speed-1hop .*--min-entry-operators 1' "$CAPTURE"; then
  echo "speed-1hop profile compare should not require entry operators"
  cat "$CAPTURE"
  exit 1
fi

STRICT_FAIL_SUMMARY_JSON="$TMP_DIR/profile_compare_strict_fail_summary.json"
STRICT_FAIL_REPORT_MD="$TMP_DIR/profile_compare_strict_fail_report.md"
STRICT_FAIL_RUN_LOG="$TMP_DIR/profile_compare_strict_fail_run.log"

echo "[profile-compare-local] fail-on-run-fail escalates partial failures"
rm -f "$FAKE_COUNTER_DIR"/*.count
set +e
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$FAKE_COUNTER_DIR" \
FAKE_LOG_DIR="$FAKE_LOG_DIR" \
PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT="$FAKE_EASY" \
./scripts/profile_compare_local.sh \
  --profiles private \
  --rounds 2 \
  --execution-mode local \
  --directory-urls http://dir-strict:8081 \
  --issuer-url http://issuer-strict:8082 \
  --entry-url http://entry-strict:8083 \
  --exit-url http://exit-strict:8084 \
  --fail-on-run-fail 1 \
  --summary-json "$STRICT_FAIL_SUMMARY_JSON" \
  --report-md "$STRICT_FAIL_REPORT_MD" >"$STRICT_FAIL_RUN_LOG" 2>&1
STRICT_FAIL_RC=$?
set -e
if [[ "$STRICT_FAIL_RC" -ne 1 ]]; then
  echo "expected fail-on-run-fail rc=1"
  cat "$STRICT_FAIL_RUN_LOG"
  cat "$STRICT_FAIL_SUMMARY_JSON"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .inputs.fail_on_run_fail == true
  and .summary.runs_pass == 1
  and .summary.runs_fail == 1
  and (.notes | contains("--fail-on-run-fail"))
' "$STRICT_FAIL_SUMMARY_JSON" >/dev/null; then
  echo "fail-on-run-fail summary did not fail closed"
  cat "$STRICT_FAIL_RUN_LOG"
  cat "$STRICT_FAIL_SUMMARY_JSON"
  exit 1
fi

KERNEL_PROXY_SUMMARY_JSON="$TMP_DIR/profile_compare_kernel_proxy_summary.json"
KERNEL_PROXY_REPORT_MD="$TMP_DIR/profile_compare_kernel_proxy_report.md"
KERNEL_PROXY_RUN_LOG="$TMP_DIR/profile_compare_kernel_proxy_run.log"

echo "[profile-compare-local] kernel proxy readiness counts as wg session evidence"
rm -f "$FAKE_COUNTER_DIR"/*.count
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$FAKE_COUNTER_DIR" \
FAKE_LOG_DIR="$FAKE_LOG_DIR" \
FAKE_CLIENT_KERNEL_PROXY_READY=1 \
PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT="$FAKE_EASY" \
./scripts/profile_compare_local.sh \
  --profiles balanced \
  --rounds 1 \
  --execution-mode local \
  --directory-urls http://dir-kernel:8081 \
  --issuer-url http://issuer-kernel:8082 \
  --entry-url http://entry-kernel:8083 \
  --exit-url http://exit-kernel:8084 \
  --summary-json "$KERNEL_PROXY_SUMMARY_JSON" \
  --report-md "$KERNEL_PROXY_REPORT_MD" >"$KERNEL_PROXY_RUN_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .summary.runs_pass == 1
  and .runs[0].wg_session_count == 1
' "$KERNEL_PROXY_SUMMARY_JSON" >/dev/null; then
  echo "kernel proxy readiness did not count as wg session evidence"
  cat "$KERNEL_PROXY_RUN_LOG"
  cat "$KERNEL_PROXY_SUMMARY_JSON"
  exit 1
fi

PRIVATE_DEFAULT_SUMMARY_JSON="$TMP_DIR/profile_compare_private_default_summary.json"
PRIVATE_DEFAULT_REPORT_MD="$TMP_DIR/profile_compare_private_default_report.md"
PRIVATE_DEFAULT_RUN_LOG="$TMP_DIR/profile_compare_private_default_run.log"

echo "[profile-compare-local] private default selection policy fallback"
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$FAKE_COUNTER_DIR" \
FAKE_LOG_DIR="$FAKE_LOG_DIR" \
PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT="$FAKE_EASY" \
./scripts/profile_compare_local.sh \
  --profiles private \
  --rounds 1 \
  --execution-mode local \
  --directory-urls http://dir-private:8081 \
  --issuer-url http://issuer-private:8082 \
  --entry-url http://entry-private:8083 \
  --exit-url http://exit-private:8084 \
  --summary-json "$PRIVATE_DEFAULT_SUMMARY_JSON" \
  --report-md "$PRIVATE_DEFAULT_REPORT_MD" \
  --print-summary-json 0 >"$PRIVATE_DEFAULT_RUN_LOG"

if ! jq -e '
  .status == "pass"
  and .summary.selection_policy.sticky_pair_sec == 420
  and .summary.selection_policy.entry_rotation_sec == 240
  and .summary.selection_policy.entry_rotation_jitter_pct == 10
  and .summary.selection_policy.exit_exploration_pct == 5
  and .summary.selection_policy.path_profile == "3hop"
  and .summary.selection_policy.source == "partial-log-fallback"
  and .summary.selection_policy.observed_from_log == false
  and .summary.selection_policy_source == "partial-log-fallback"
' "$PRIVATE_DEFAULT_SUMMARY_JSON" >/dev/null; then
  echo "private summary json missing expected selection policy defaults"
  cat "$PRIVATE_DEFAULT_SUMMARY_JSON"
  exit 1
fi

SPEED_1HOP_DEFAULT_SUMMARY_JSON="$TMP_DIR/profile_compare_speed_1hop_default_summary.json"
SPEED_1HOP_DEFAULT_REPORT_MD="$TMP_DIR/profile_compare_speed_1hop_default_report.md"
SPEED_1HOP_DEFAULT_RUN_LOG="$TMP_DIR/profile_compare_speed_1hop_default_run.log"

echo "[profile-compare-local] speed-1hop default selection policy fallback"
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$FAKE_COUNTER_DIR" \
FAKE_LOG_DIR="$FAKE_LOG_DIR" \
PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT="$FAKE_EASY" \
./scripts/profile_compare_local.sh \
  --profiles speed-1hop \
  --rounds 1 \
  --execution-mode local \
  --directory-urls http://dir-speed-1hop:8081 \
  --issuer-url http://issuer-speed-1hop:8082 \
  --entry-url http://entry-speed-1hop:8083 \
  --exit-url http://exit-speed-1hop:8084 \
  --summary-json "$SPEED_1HOP_DEFAULT_SUMMARY_JSON" \
  --report-md "$SPEED_1HOP_DEFAULT_REPORT_MD" \
  --print-summary-json 0 >"$SPEED_1HOP_DEFAULT_RUN_LOG"

if ! jq -e '
  .status == "pass"
  and .summary.selection_policy.sticky_pair_sec == 300
  and .summary.selection_policy.entry_rotation_sec == 120
  and .summary.selection_policy.entry_rotation_jitter_pct == 20
  and .summary.selection_policy.exit_exploration_pct == 20
  and .summary.selection_policy.path_profile == "1hop"
  and .summary.selection_policy.source == "partial-log-fallback"
  and .summary.selection_policy.observed_from_log == false
  and .summary.selection_policy_source == "partial-log-fallback"
' "$SPEED_1HOP_DEFAULT_SUMMARY_JSON" >/dev/null; then
  echo "speed-1hop summary json missing expected selection policy defaults"
  cat "$SPEED_1HOP_DEFAULT_SUMMARY_JSON"
  exit 1
fi

M4_UNAVAILABLE_SUMMARY_JSON="$TMP_DIR/profile_compare_m4_unavailable_summary.json"
M4_UNAVAILABLE_REPORT_MD="$TMP_DIR/profile_compare_m4_unavailable_report.md"
M4_UNAVAILABLE_RUN_LOG="$TMP_DIR/profile_compare_m4_unavailable_run.log"

echo "[profile-compare-local] m4 evidence explicit unavailable shape when no runs execute"
set +e
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$FAKE_COUNTER_DIR" \
FAKE_LOG_DIR="$FAKE_LOG_DIR" \
PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT="$FAKE_EASY" \
./scripts/profile_compare_local.sh \
  --profiles speed-1hop \
  --rounds 1 \
  --beta-profile 1 \
  --prod-profile 0 \
  --execution-mode local \
  --directory-urls http://dir-m4-none:8081 \
  --issuer-url http://issuer-m4-none:8082 \
  --entry-url http://entry-m4-none:8083 \
  --exit-url http://exit-m4-none:8084 \
  --summary-json "$M4_UNAVAILABLE_SUMMARY_JSON" \
  --report-md "$M4_UNAVAILABLE_REPORT_MD" \
  --print-summary-json 0 >"$M4_UNAVAILABLE_RUN_LOG"
m4_unavailable_rc=$?
set -e
if [[ "$m4_unavailable_rc" -eq 0 ]]; then
  echo "expected non-zero rc when all runs are skipped"
  cat "$M4_UNAVAILABLE_RUN_LOG"
  exit 1
fi
if ! jq -e '
  .summary.runs_executed == 0
  and .summary.m4_micro_relay_evidence.available == false
  and (.summary.m4_micro_relay_evidence.reason | type == "string")
  and .summary.m4_micro_relay_evidence.micro_relay_quality.available == false
  and .summary.m4_micro_relay_evidence.micro_relay_quality.quality_score == null
  and .summary.m4_micro_relay_evidence.adaptive_demotion_promotion.available == false
  and .summary.m4_micro_relay_evidence.adaptive_demotion_promotion.demotion_candidate == null
  and .summary.m4_micro_relay_evidence.adaptive_demotion_promotion.promotion_candidate == null
  and .summary.m4_micro_relay_evidence.trust_tier_port_unlock_wiring.present == false
  and (.summary.m4_micro_relay_evidence.trust_tier_port_unlock_wiring.reason | type == "string")
' "$M4_UNAVAILABLE_SUMMARY_JSON" >/dev/null; then
  echo "m4 unavailable summary missing explicit unavailable evidence fields"
  cat "$M4_UNAVAILABLE_SUMMARY_JSON"
  exit 1
fi

LOOPBACK_SUMMARY_JSON="$TMP_DIR/profile_compare_loopback_summary.json"
LOOPBACK_REPORT_MD="$TMP_DIR/profile_compare_loopback_report.md"
LOOPBACK_RUN_LOG="$TMP_DIR/profile_compare_loopback_run.log"
: >"$CAPTURE"

echo "[profile-compare-local] loopback endpoints keep transport defaults unchanged"
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$FAKE_COUNTER_DIR" \
FAKE_LOG_DIR="$FAKE_LOG_DIR" \
PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT="$FAKE_EASY" \
./scripts/profile_compare_local.sh \
  --profiles balanced \
  --rounds 1 \
  --execution-mode local \
  --directory-urls http://127.0.0.1:18081 \
  --issuer-url http://127.0.0.1:18082 \
  --entry-url http://127.0.0.1:18083 \
  --exit-url http://127.0.0.1:18084 \
  --summary-json "$LOOPBACK_SUMMARY_JSON" \
  --report-md "$LOOPBACK_REPORT_MD" \
  --print-summary-json 0 >"$LOOPBACK_RUN_LOG"

if ! jq -e '
  .status == "pass"
  and .inputs.explicit_remote_endpoints == false
  and (.summary.transport_mismatch_failures_total | type == "number")
  and (.summary.token_proof_invalid_failures_total | type == "number")
  and (.summary.unknown_exit_failures_total | type == "number")
  and (.summary.directory_trust_failures_total | type == "number")
  and ([.profiles[] | select(.profile == "balanced")][0].avg_transport_mismatch_failures | type == "number")
  and ([.profiles[] | select(.profile == "balanced")][0].avg_token_proof_invalid_failures | type == "number")
  and ([.profiles[] | select(.profile == "balanced")][0].avg_unknown_exit_failures | type == "number")
  and ([.profiles[] | select(.profile == "balanced")][0].avg_directory_trust_failures | type == "number")
  and ([.runs[] | select(.profile == "balanced")][0].transport_mismatch_failures | type == "number")
  and ([.runs[] | select(.profile == "balanced")][0].token_proof_invalid_failures | type == "number")
  and ([.runs[] | select(.profile == "balanced")][0].unknown_exit_failures | type == "number")
  and ([.runs[] | select(.profile == "balanced")][0].directory_trust_failures | type == "number")
' "$LOOPBACK_SUMMARY_JSON" >/dev/null; then
  echo "loopback summary did not preserve explicit_remote_endpoints=false"
  cat "$LOOPBACK_SUMMARY_JSON"
  exit 1
fi
loopback_env_line="$(rg '^env ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$loopback_env_line" ]]; then
  echo "missing loopback env capture line"
  cat "$CAPTURE"
  exit 1
fi
for expected in 'client_inner_source=' 'disable_synthetic_fallback=' 'data_plane_mode='; do
  if ! grep -F -- "$expected" <<<"$loopback_env_line" >/dev/null; then
    echo "loopback run missing $expected"
    cat "$CAPTURE"
    exit 1
  fi
done
if grep -F -- 'client_inner_source=udp' <<<"$loopback_env_line" >/dev/null; then
  echo "loopback run unexpectedly forced udp inner source"
  cat "$CAPTURE"
  exit 1
fi
if grep -F -- 'disable_synthetic_fallback=1' <<<"$loopback_env_line" >/dev/null; then
  echo "loopback run unexpectedly forced synthetic fallback disable"
  cat "$CAPTURE"
  exit 1
fi
if grep -F -- 'data_plane_mode=opaque' <<<"$loopback_env_line" >/dev/null; then
  echo "loopback run unexpectedly forced opaque data plane mode"
  cat "$CAPTURE"
  exit 1
fi

LIVE_LOOPBACK_SUMMARY_JSON="$TMP_DIR/profile_compare_live_loopback_summary.json"
LIVE_LOOPBACK_REPORT_MD="$TMP_DIR/profile_compare_live_loopback_report.md"
LIVE_LOOPBACK_RUN_LOG="$TMP_DIR/profile_compare_live_loopback_run.log"
: >"$CAPTURE"

echo "[profile-compare-local] live evidence forces transport defaults on loopback endpoints"
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$FAKE_COUNTER_DIR" \
FAKE_LOG_DIR="$FAKE_LOG_DIR" \
PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT="$FAKE_EASY" \
./scripts/profile_compare_local.sh \
  --profiles balanced \
  --rounds 1 \
  --execution-mode local \
  --directory-urls http://127.0.0.1:28081 \
  --issuer-url http://127.0.0.1:28082 \
  --entry-url http://127.0.0.1:28083 \
  --exit-url http://127.0.0.1:28084 \
  --min-entry-operators 1 \
  --min-exit-operators 1 \
  --require-cross-operator-pair 1 \
  --live-evidence 1 \
  --summary-json "$LIVE_LOOPBACK_SUMMARY_JSON" \
  --report-md "$LIVE_LOOPBACK_REPORT_MD" \
  --print-summary-json 0 >"$LIVE_LOOPBACK_RUN_LOG"

if ! jq -e '
  .status == "pass"
  and .inputs.live_evidence == true
  and .inputs.live_evidence_udp_inject == true
  and .inputs.min_entry_operators == 1
  and .inputs.min_exit_operators == 1
  and .inputs.require_cross_operator_pair == true
  and .inputs.fail_on_run_fail == true
  and .inputs.explicit_remote_endpoints == false
  and .inputs.transport_auto_defaults.client_inner_source_udp == true
  and .inputs.transport_auto_defaults.disable_synthetic_fallback == true
  and .inputs.transport_auto_defaults.data_plane_mode_opaque == true
  and .summary.selection_policy.source == "partial-log-fallback"
  and .summary.selection_policy.observed_from_log == false
  and .summary.selection_policy_source == "partial-log-fallback"
' "$LIVE_LOOPBACK_SUMMARY_JSON" >/dev/null; then
  echo "live loopback summary did not force strict transport defaults"
  cat "$LIVE_LOOPBACK_SUMMARY_JSON"
  exit 1
fi
live_loopback_env_line="$(rg '^env ' "$CAPTURE" | tail -n 1 || true)"
for expected in 'client_inner_source=udp' 'disable_synthetic_fallback=1' 'data_plane_mode=opaque'; do
  if ! grep -F -- "$expected" <<<"$live_loopback_env_line" >/dev/null; then
    echo "live loopback env missing $expected"
    cat "$CAPTURE"
    exit 1
  fi
done
live_loopback_call_line="$(rg '^client-test ' "$CAPTURE" | tail -n 1 || true)"
for expected in '--min-entry-operators 1' '--min-exit-operators 1' '--require-cross-operator-pair 1'; do
  if ! grep -F -- "$expected" <<<"$live_loopback_call_line" >/dev/null; then
    echo "live loopback client-test args missing $expected"
    cat "$CAPTURE"
    exit 1
  fi
done

LIVE_NO_INJECT_SUMMARY_JSON="$TMP_DIR/profile_compare_live_no_inject_summary.json"
LIVE_NO_INJECT_REPORT_MD="$TMP_DIR/profile_compare_live_no_inject_report.md"
: >"$CAPTURE"

echo "[profile-compare-local] live evidence UDP injector can be disabled"
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$FAKE_COUNTER_DIR" \
FAKE_LOG_DIR="$FAKE_LOG_DIR" \
PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT="$FAKE_EASY" \
./scripts/profile_compare_local.sh \
  --profiles balanced \
  --rounds 1 \
  --execution-mode local \
  --directory-urls http://127.0.0.1:28181 \
  --issuer-url http://127.0.0.1:28182 \
  --entry-url http://127.0.0.1:28183 \
  --exit-url http://127.0.0.1:28184 \
  --live-evidence 1 \
  --live-evidence-udp-inject 0 \
  --summary-json "$LIVE_NO_INJECT_SUMMARY_JSON" \
  --report-md "$LIVE_NO_INJECT_REPORT_MD" \
  --print-summary-json 0 >/tmp/integration_profile_compare_live_no_inject.log

if ! jq -e '
  .status == "pass"
  and .inputs.live_evidence == true
  and .inputs.live_evidence_udp_inject == false
  and .inputs.transport_auto_defaults.client_inner_source_udp == true
' "$LIVE_NO_INJECT_SUMMARY_JSON" >/dev/null; then
  echo "live no-inject summary did not preserve disabled injector metadata"
  cat "$LIVE_NO_INJECT_SUMMARY_JSON"
  exit 1
fi

LIVE_UNSAFE_RUN_LOG="$TMP_DIR/profile_compare_live_unsafe_run.log"
echo "[profile-compare-local] live evidence rejects unsafe transport overrides"
set +e
CLIENT_INNER_SOURCE=synthetic \
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$FAKE_COUNTER_DIR" \
FAKE_LOG_DIR="$FAKE_LOG_DIR" \
PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT="$FAKE_EASY" \
./scripts/profile_compare_local.sh \
  --profiles balanced \
  --rounds 1 \
  --execution-mode local \
  --directory-urls http://127.0.0.1:29081 \
  --issuer-url http://127.0.0.1:29082 \
  --entry-url http://127.0.0.1:29083 \
  --exit-url http://127.0.0.1:29084 \
  --live-evidence 1 >"$LIVE_UNSAFE_RUN_LOG" 2>&1
live_unsafe_rc=$?
set -e
if [[ "$live_unsafe_rc" -eq 0 ]]; then
  echo "live evidence should reject CLIENT_INNER_SOURCE=synthetic"
  cat "$LIVE_UNSAFE_RUN_LOG"
  exit 1
fi
if ! grep -F -- '--live-evidence requires CLIENT_INNER_SOURCE=udp' "$LIVE_UNSAFE_RUN_LOG" >/dev/null; then
  echo "live evidence unsafe override message missing"
  cat "$LIVE_UNSAFE_RUN_LOG"
  exit 1
fi

DOCKER_LOCAL_STACK_SUMMARY_JSON="$TMP_DIR/profile_compare_docker_local_stack_summary.json"
DOCKER_LOCAL_STACK_REPORT_MD="$TMP_DIR/profile_compare_docker_local_stack_report.md"
DOCKER_LOCAL_STACK_RUN_LOG="$TMP_DIR/profile_compare_docker_local_stack_run.log"
: >"$CAPTURE"

echo "[profile-compare-local] docker local-stack mode fails fast"
set +e
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$FAKE_COUNTER_DIR" \
FAKE_LOG_DIR="$FAKE_LOG_DIR" \
PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT="$FAKE_EASY" \
./scripts/profile_compare_local.sh \
  --profiles balanced \
  --rounds 1 \
  --execution-mode docker \
  --start-local-stack 1 \
  --summary-json "$DOCKER_LOCAL_STACK_SUMMARY_JSON" \
  --report-md "$DOCKER_LOCAL_STACK_REPORT_MD" \
  --print-summary-json 0 >"$DOCKER_LOCAL_STACK_RUN_LOG" 2>&1
docker_local_stack_rc=$?
set -e
if [[ "$docker_local_stack_rc" -eq 0 ]]; then
  echo "docker local-stack mode should fail before invoking fake easy helper"
  cat "$DOCKER_LOCAL_STACK_RUN_LOG"
  exit 1
fi
if ! grep -F -- '--start-local-stack=1 requires --execution-mode local' "$DOCKER_LOCAL_STACK_RUN_LOG" >/dev/null; then
  echo "docker local-stack failure message missing"
  cat "$DOCKER_LOCAL_STACK_RUN_LOG"
  exit 1
fi
if [[ -s "$CAPTURE" ]]; then
  echo "docker local-stack fail-fast should not invoke easy helper"
  cat "$CAPTURE"
  exit 1
fi

LOCAL_STACK_TRUST_SUMMARY_JSON="$TMP_DIR/profile_compare_local_stack_trust_summary.json"
LOCAL_STACK_TRUST_REPORT_MD="$TMP_DIR/profile_compare_local_stack_trust_report.md"
LOCAL_STACK_TRUST_RUN_LOG="$TMP_DIR/profile_compare_local_stack_trust_run.log"
: >"$CAPTURE"

echo "[profile-compare-local] local stack forwards pinned directory trust"
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$FAKE_COUNTER_DIR" \
FAKE_LOG_DIR="$FAKE_LOG_DIR" \
PROFILE_COMPARE_LOCAL_EFFECTIVE_UID_OVERRIDE=0 \
PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT="$FAKE_EASY" \
./scripts/profile_compare_local.sh \
  --profiles balanced \
  --rounds 1 \
  --execution-mode local \
  --start-local-stack 1 \
  --summary-json "$LOCAL_STACK_TRUST_SUMMARY_JSON" \
  --report-md "$LOCAL_STACK_TRUST_REPORT_MD" \
  --print-summary-json 0 >"$LOCAL_STACK_TRUST_RUN_LOG"

local_stack_env_line="$(rg '^env .*directory_trusted_keys_file=[^ ]' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$local_stack_env_line" ]]; then
  echo "missing local stack env capture line"
  cat "$CAPTURE"
  exit 1
fi
if ! grep -F -- 'directory_trusted_keys_file=' <<<"$local_stack_env_line" >/dev/null ||
  ! grep -F -- '/deploy/data/wg_only/fake_trusted_directory_keys.txt' <<<"$local_stack_env_line" >/dev/null; then
  echo "local stack run did not forward the generated directory trust file"
  cat "$CAPTURE"
  exit 1
fi
for expected in \
  'client_inner_source=udp' \
  'disable_synthetic_fallback=1' \
  'data_plane_mode=opaque' \
  'wg_only_mode=1' \
  'client_live_wg_mode=1' \
  'client_wg_backend=command' \
  'client_wg_private_key_path=' \
  '/deploy/data/wg_only/fake_client.key' \
  'client_wg_interface=wgcstack0' \
  'client_wg_kernel_proxy=1' \
  'client_wg_proxy_addr=127.0.0.1:19383' \
  'startup_sync_timeout_sec=8'
do
  if ! grep -F -- "$expected" <<<"$local_stack_env_line" >/dev/null; then
    echo "local stack run missing live WireGuard client env: $expected"
    cat "$CAPTURE"
    exit 1
  fi
done

ALLOW_HTTP_SUMMARY_JSON="$TMP_DIR/profile_compare_allow_http_summary.json"
ALLOW_HTTP_REPORT_MD="$TMP_DIR/profile_compare_allow_http_report.md"
ALLOW_HTTP_RUN_LOG="$TMP_DIR/profile_compare_allow_http_run.log"
: >"$CAPTURE"

echo "[profile-compare-local] explicit insecure remote HTTP opt-in forwards to client-test"
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$FAKE_COUNTER_DIR" \
FAKE_LOG_DIR="$FAKE_LOG_DIR" \
PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT="$FAKE_EASY" \
./scripts/profile_compare_local.sh \
  --profiles balanced \
  --rounds 1 \
  --execution-mode local \
  --allow-insecure-remote-http 1 \
  --directory-urls http://dir-allow-http:8081 \
  --issuer-url http://issuer-allow-http:8082 \
  --entry-url http://entry-allow-http:8083 \
  --exit-url http://exit-allow-http:8084 \
  --summary-json "$ALLOW_HTTP_SUMMARY_JSON" \
  --report-md "$ALLOW_HTTP_REPORT_MD" \
  --print-summary-json 0 >"$ALLOW_HTTP_RUN_LOG"

if ! jq -e '.status == "pass" and .inputs.allow_insecure_remote_http == true' "$ALLOW_HTTP_SUMMARY_JSON" >/dev/null; then
  echo "allow-insecure-remote-http summary missing expected input marker"
  cat "$ALLOW_HTTP_SUMMARY_JSON"
  exit 1
fi
if ! grep -F -- '--allow-insecure-remote-http 1' "$CAPTURE" >/dev/null; then
  echo "profile compare did not forward --allow-insecure-remote-http to client-test"
  cat "$CAPTURE"
  exit 1
fi

OVERRIDE_SUMMARY_JSON="$TMP_DIR/profile_compare_override_summary.json"
OVERRIDE_REPORT_MD="$TMP_DIR/profile_compare_override_report.md"
OVERRIDE_RUN_LOG="$TMP_DIR/profile_compare_override_run.log"
: >"$CAPTURE"

echo "[profile-compare-local] explicit user transport env overrides are preserved"
CLIENT_INNER_SOURCE=tcp \
CLIENT_DISABLE_SYNTHETIC_FALLBACK=0 \
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$FAKE_COUNTER_DIR" \
FAKE_LOG_DIR="$FAKE_LOG_DIR" \
PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT="$FAKE_EASY" \
./scripts/profile_compare_local.sh \
  --profiles balanced \
  --rounds 1 \
  --execution-mode local \
  --directory-urls http://dir-b:8081 \
  --issuer-url http://issuer-b:8082 \
  --entry-url http://entry-b:8083 \
  --exit-url http://exit-b:8084 \
  --summary-json "$OVERRIDE_SUMMARY_JSON" \
  --report-md "$OVERRIDE_REPORT_MD" \
  --print-summary-json 0 >"$OVERRIDE_RUN_LOG"

override_env_line="$(rg '^env ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$override_env_line" ]]; then
  echo "missing override env capture line"
  cat "$CAPTURE"
  exit 1
fi
for expected in 'client_inner_source=tcp' 'disable_synthetic_fallback=0' 'data_plane_mode=opaque'; do
  if ! grep -F -- "$expected" <<<"$override_env_line" >/dev/null; then
    echo "override run missing $expected"
    cat "$CAPTURE"
    exit 1
  fi
done

DOCKER_SUMMARY_JSON="$TMP_DIR/profile_compare_docker_summary.json"
DOCKER_REPORT_MD="$TMP_DIR/profile_compare_docker_report.md"
DOCKER_RUN_LOG="$TMP_DIR/profile_compare_docker_run.log"
: >"$CAPTURE"

echo "[profile-compare-local] docker loopback endpoint rewrite"
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$FAKE_COUNTER_DIR" \
FAKE_LOG_DIR="$FAKE_LOG_DIR" \
PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT="$FAKE_EASY" \
./scripts/profile_compare_local.sh \
  --profiles balanced \
  --rounds 1 \
  --execution-mode docker \
  --directory-urls http://127.0.0.1:18081,http://localhost:28081 \
  --issuer-url http://127.0.0.1:18082 \
  --entry-url http://localhost:18083 \
  --exit-url http://127.0.0.1:18084 \
  --summary-json "$DOCKER_SUMMARY_JSON" \
  --report-md "$DOCKER_REPORT_MD" \
  --print-summary-json 0 >"$DOCKER_RUN_LOG"

if ! jq -e '
  .status == "pass"
  and .inputs.execution_mode == "docker"
  and .inputs.docker_host_alias == "host.docker.internal"
' "$DOCKER_SUMMARY_JSON" >/dev/null; then
  echo "docker rewrite run summary missing expected fields"
  cat "$DOCKER_RUN_LOG"
  cat "$DOCKER_SUMMARY_JSON"
  exit 1
fi

docker_env_line="$(rg '^env container_directory_urls=' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$docker_env_line" ]]; then
  echo "missing docker env rewrite capture line"
  cat "$CAPTURE"
  exit 1
fi
for expected in \
  'container_directory_urls=http://host.docker.internal:18081,http://host.docker.internal:28081' \
  'container_issuer_url=http://host.docker.internal:18082' \
  'container_entry_url=http://host.docker.internal:18083' \
  'container_exit_url=http://host.docker.internal:18084' \
  'client_force_build=1'
do
  if ! grep -F -- "$expected" <<<"$docker_env_line" >/dev/null; then
    echo "docker env rewrite capture missing $expected"
    cat "$CAPTURE"
    exit 1
  fi
done

REDACTION_SUMMARY_JSON="$TMP_DIR/profile_compare_redaction_summary.json"
REDACTION_REPORT_MD="$TMP_DIR/profile_compare_redaction_report.md"
REDACTION_RUN_LOG="$TMP_DIR/profile_compare_redaction_run.log"

echo "[profile-compare-local] artifact redaction"
FAKE_CAPTURE_FILE="$CAPTURE" \
FAKE_COUNTER_DIR="$FAKE_COUNTER_DIR" \
FAKE_LOG_DIR="$FAKE_LOG_DIR" \
PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT="$FAKE_EASY" \
./scripts/profile_compare_local.sh \
  --profiles balanced \
  --rounds 1 \
  --execution-mode local \
  --directory-urls 'http://user:pw-secret@dir-a:8081?token=dir-secret,http://user:pw-secret@dir-b:8081?token=dir-secret-b' \
  --bootstrap-directory 'http://user:pw-secret@dir-a:8081?token=bootstrap-secret' \
  --issuer-url 'http://user:pw-secret@issuer-a:8082?token=issuer-secret' \
  --entry-url 'http://user:pw-secret@entry-a:8083?token=entry-secret' \
  --exit-url 'http://user:pw-secret@exit-a:8084?token=exit-secret' \
  --allow-insecure-remote-http 1 \
  --subject 'inv-local-secret-subject' \
  --summary-json "$REDACTION_SUMMARY_JSON" \
  --report-md "$REDACTION_REPORT_MD" \
  --print-summary-json 0 >"$REDACTION_RUN_LOG"

for forbidden in 'pw-secret' 'token=' 'inv-local-secret-subject'; do
  if grep -F -- "$forbidden" "$REDACTION_SUMMARY_JSON" "$REDACTION_REPORT_MD" >/dev/null; then
    echo "profile compare local artifact leaked forbidden value: $forbidden"
    cat "$REDACTION_SUMMARY_JSON"
    cat "$REDACTION_REPORT_MD"
    exit 1
  fi
done
if ! jq -e '
  .inputs.directory_urls == "http://dir-a:8081,http://dir-b:8081"
  and .inputs.bootstrap_directory == "http://dir-a:8081"
  and .inputs.issuer_url == "http://issuer-a:8082"
  and .inputs.entry_url == "http://entry-a:8083"
  and .inputs.exit_url == "http://exit-a:8084"
  and .inputs.subject == "[redacted]"
  and (.runs[0].command | contains("--subject"))
  and (.runs[0].command | contains("redacted"))
  and ((.runs[0].command | contains("pw-secret")) | not)
  and ((.runs[0].command | contains("token=")) | not)
  and ((.command | contains("inv-local-secret-subject")) | not)
' "$REDACTION_SUMMARY_JSON" >/dev/null; then
  echo "profile compare local redaction summary missing expected sanitized fields"
  cat "$REDACTION_SUMMARY_JSON"
  exit 1
fi

FORWARD_CAPTURE="$TMP_DIR/forward_capture.log"
FAKE_FORWARD="$TMP_DIR/fake_profile_compare_forward.sh"
cat >"$FAKE_FORWARD" <<'EOF_FORWARD'
#!/usr/bin/env bash
set -euo pipefail
printf 'profile-compare-local %s\n' "$*" >>"${FORWARD_CAPTURE_FILE:?}"
EOF_FORWARD
chmod +x "$FAKE_FORWARD"

: >"$FORWARD_CAPTURE"

echo "[profile-compare-local] easy_node forwarding"
FORWARD_CAPTURE_FILE="$FORWARD_CAPTURE" \
PROFILE_COMPARE_LOCAL_SCRIPT="$FAKE_FORWARD" \
./scripts/easy_node.sh profile-compare-local \
  --profiles balanced,speed \
  --rounds 2 \
  --fail-on-run-fail 1 \
  --summary-json /tmp/profile_compare_test.json \
  --print-summary-json 1

forward_line="$(rg '^profile-compare-local ' "$FORWARD_CAPTURE" | tail -n 1 || true)"
if [[ -z "$forward_line" ]]; then
  echo "missing easy_node forwarding capture"
  cat "$FORWARD_CAPTURE"
  exit 1
fi
for expected in '--profiles balanced,speed' '--rounds 2' '--fail-on-run-fail 1' '--summary-json /tmp/profile_compare_test.json' '--print-summary-json 1'; do
  if ! grep -F -- "$expected" <<<"$forward_line" >/dev/null; then
    echo "easy_node forwarding missing $expected"
    cat "$FORWARD_CAPTURE"
    exit 1
  fi
done

echo "profile compare local integration check ok"
