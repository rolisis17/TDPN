#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 1
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

WARN_SUMMARY="$TMP_DIR/warn_summary.json"
WARN_LOG="$TMP_DIR/warn.log"
LOCAL_FAIL_SUMMARY="$TMP_DIR/local_fail_summary.json"
LOCAL_FAIL_LOG="$TMP_DIR/local_fail.log"
STEP_FAIL_SUMMARY="$TMP_DIR/step_fail_summary.json"
STEP_FAIL_LOG="$TMP_DIR/step_fail.log"
STEP_TIMEOUT_SUMMARY="$TMP_DIR/step_timeout_summary.json"
STEP_TIMEOUT_LOG="$TMP_DIR/step_timeout.log"
PROFILE_SIGNOFF_SUMMARY="$TMP_DIR/profile_signoff_summary.json"
PROFILE_SIGNOFF_LOG="$TMP_DIR/profile_signoff.log"
PROFILE_SIGNOFF_NON_BLOCKING_SUMMARY="$TMP_DIR/profile_signoff_non_blocking_summary.json"
PROFILE_SIGNOFF_NON_BLOCKING_LOG="$TMP_DIR/profile_signoff_non_blocking.log"
AUTO_REFRESH_SUMMARY="$TMP_DIR/auto_refresh_summary.json"
AUTO_REFRESH_LOG="$TMP_DIR/auto_refresh.log"
AUTO_REFRESH_DOCKER_SUMMARY="$TMP_DIR/auto_refresh_docker_summary.json"
AUTO_REFRESH_DOCKER_LOG="$TMP_DIR/auto_refresh_docker.log"
AUTO_REFRESH_STALE_SIGNOFF_SUMMARY="$TMP_DIR/auto_refresh_stale_signoff_summary.json"
AUTO_REFRESH_STALE_SIGNOFF_LOG="$TMP_DIR/auto_refresh_stale_signoff.log"
AUTO_REFRESH_NON_ROOT_SKIP_SUMMARY="$TMP_DIR/auto_refresh_non_root_skip_summary.json"
AUTO_REFRESH_NON_ROOT_SKIP_LOG="$TMP_DIR/auto_refresh_non_root_skip.log"
DOCKER_REHEARSAL_SUMMARY="$TMP_DIR/docker_rehearsal_summary.json"
DOCKER_REHEARSAL_LOG="$TMP_DIR/docker_rehearsal.log"
DOCKER_REHEARSAL_ARGS_LOG="$TMP_DIR/docker_rehearsal_args.log"
PROFILE_SIGNOFF_ARGS_LOG="$TMP_DIR/profile_signoff_args.log"
MANUAL_REPORT_ARGS_LOG="$TMP_DIR/manual_report_args.log"
CAPTURE="$TMP_DIR/capture.log"

# Keep fake manual-validation report artifacts isolated to the test tmp dir so
# this integration cannot clobber shared operator handoff pointers in .easy-node-logs.
export SINGLE_MACHINE_MANUAL_VALIDATION_REPORT_SUMMARY_JSON="$TMP_DIR/manual_validation_readiness_summary.json"
export SINGLE_MACHINE_MANUAL_VALIDATION_REPORT_MD="$TMP_DIR/manual_validation_readiness_report.md"
export SINGLE_MACHINE_SUMMARY_JSON_LATEST="$TMP_DIR/single_machine_prod_readiness_latest.json"

FAKE_CI="$TMP_DIR/fake_ci_local.sh"
FAKE_BETA="$TMP_DIR/fake_beta_preflight.sh"
FAKE_DEEP_OK="$TMP_DIR/fake_deep_ok.sh"
FAKE_DEEP_FAIL="$TMP_DIR/fake_deep_fail.sh"
FAKE_DEEP_SLEEP="$TMP_DIR/fake_deep_sleep.sh"
FAKE_RUNTIME_FIX_RECORD="$TMP_DIR/fake_runtime_fix_record.sh"
FAKE_THREE_MACHINE_DOCKER_READINESS="$TMP_DIR/fake_three_machine_docker_readiness.sh"
FAKE_PROFILE_SIGNOFF="$TMP_DIR/fake_profile_compare_campaign_signoff.sh"
FAKE_PRE_REAL="$TMP_DIR/fake_pre_real_host_readiness.sh"
FAKE_REAL_WG_PRIVILEGED_MATRIX_RECORD="$TMP_DIR/fake_real_wg_privileged_matrix_record.sh"
FAKE_MANUAL_REPORT="$TMP_DIR/fake_manual_validation_report.sh"
FAKE_SINGLE_MACHINE_FORWARD="$TMP_DIR/fake_single_machine_forward.sh"

cat >"$FAKE_CI" <<'EOF_OK'
#!/usr/bin/env bash
set -euo pipefail
printf 'fake ci_local ok\n'
EOF_OK

cat >"$FAKE_BETA" <<'EOF_OK'
#!/usr/bin/env bash
set -euo pipefail
printf 'fake beta_preflight ok\n'
EOF_OK

cat >"$FAKE_DEEP_OK" <<'EOF_OK'
#!/usr/bin/env bash
set -euo pipefail
printf 'fake deep suite ok\n'
EOF_OK

cat >"$FAKE_DEEP_FAIL" <<'EOF_FAIL'
#!/usr/bin/env bash
set -euo pipefail
printf 'fake deep suite fail\n'
exit 1
EOF_FAIL

cat >"$FAKE_DEEP_SLEEP" <<'EOF_SLEEP'
#!/usr/bin/env bash
set -euo pipefail
sleep "${FAKE_DEEP_SLEEP_SEC:-3}"
printf 'fake deep suite sleep done\n'
EOF_SLEEP

cat >"$FAKE_RUNTIME_FIX_RECORD" <<'EOF_OK'
#!/usr/bin/env bash
set -euo pipefail
printf 'fake runtime fix record ok\n'
EOF_OK

cat >"$FAKE_THREE_MACHINE_DOCKER_READINESS" <<'EOF_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
summary_json=""
if [[ -n "${FAKE_THREE_MACHINE_DOCKER_READINESS_ARGS_LOG:-}" ]]; then
  printf '%s\n' "$*" >>"$FAKE_THREE_MACHINE_DOCKER_READINESS_ARGS_LOG"
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<EOF_JSON
{
  "version": 1,
  "status": "${FAKE_THREE_MACHINE_DOCKER_READINESS_STATUS:-pass}",
  "rc": ${FAKE_THREE_MACHINE_DOCKER_READINESS_RC:-0},
  "notes": "fake docker readiness",
  "endpoints": {
    "directory_a": "${FAKE_THREE_MACHINE_DOCKER_DIRECTORY_A:-http://127.0.0.1:18081}",
    "directory_b": "${FAKE_THREE_MACHINE_DOCKER_DIRECTORY_B:-http://127.0.0.1:28081}",
    "issuer_a": "${FAKE_THREE_MACHINE_DOCKER_ISSUER_A:-http://127.0.0.1:18082}",
    "entry": "${FAKE_THREE_MACHINE_DOCKER_ENTRY:-http://127.0.0.1:18083}",
    "exit": "${FAKE_THREE_MACHINE_DOCKER_EXIT:-http://127.0.0.1:18084}"
  }
}
EOF_JSON
fi
printf 'fake docker 3-machine readiness\n'
exit "${FAKE_THREE_MACHINE_DOCKER_READINESS_EXIT_RC:-0}"
EOF_DOCKER

cat >"$FAKE_PROFILE_SIGNOFF" <<'EOF_OK'
#!/usr/bin/env bash
set -euo pipefail
summary_json=""
if [[ -n "${FAKE_PROFILE_SIGNOFF_ARGS_LOG:-}" ]]; then
  printf '%s\n' "$*" >>"$FAKE_PROFILE_SIGNOFF_ARGS_LOG"
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<'EOF_JSON'
{
  "version": 1,
  "status": "ok",
  "final_rc": 0,
  "decision": {
    "decision": "GO",
    "recommended_profile": "balanced"
  }
}
EOF_JSON
fi
printf 'fake profile compare campaign signoff ok\n'
exit "${FAKE_PROFILE_SIGNOFF_RC:-0}"
EOF_OK

cat >"$FAKE_PRE_REAL" <<'EOF_OK'
#!/usr/bin/env bash
set -euo pipefail
printf 'fake pre real host readiness ok\n'
EOF_OK

cat >"$FAKE_REAL_WG_PRIVILEGED_MATRIX_RECORD" <<'EOF_OK'
#!/usr/bin/env bash
set -euo pipefail
printf 'fake real wg privileged matrix record ok\n'
exit "${FAKE_REAL_WG_PRIVILEGED_MATRIX_RECORD_RC:-0}"
EOF_OK

cat >"$FAKE_MANUAL_REPORT" <<'EOF_REPORT'
#!/usr/bin/env bash
set -euo pipefail
summary_json=""
report_md=""
if [[ -n "${FAKE_MANUAL_REPORT_ARGS_LOG:-}" ]]; then
  printf '%s\n' "$*" >>"$FAKE_MANUAL_REPORT_ARGS_LOG"
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --report-md)
      report_md="${2:-}"
      shift 2
      ;;
    --print-report|--print-summary-json)
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -z "$summary_json" || -z "$report_md" ]]; then
  echo "fake manual report missing required paths"
  exit 2
fi
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"
mode="${FAKE_MANUAL_REPORT_MODE:-pending_multi}"
case "$mode" in
  pending_multi)
    cat >"$summary_json" <<'EOF_JSON'
{
  "summary": {
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "single_machine_ready": true,
    "profile_default_gate": {
      "status": "pending",
      "available": true,
      "valid_json": true,
      "non_root_refresh_blocked": true,
      "next_command": "sudo ./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --refresh-campaign 1 --fail-on-no-go 0 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1"
    },
    "profile_default_ready": false,
    "next_action_check_id": "machine_c_vpn_smoke",
    "next_action_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY"
  },
  "report": {
    "readiness_status": "NOT_READY"
  },
  "checks": [
    {"check_id":"runtime_hygiene","label":"Runtime hygiene doctor","status":"pass","command":"runtime","notes":""},
    {"check_id":"wg_only_stack_selftest","label":"WG-only stack selftest","status":"pass","command":"wg-only","notes":""},
    {"check_id":"machine_c_vpn_smoke","label":"Machine C VPN smoke test","status":"pending","command":"machine-c","notes":""},
    {"check_id":"three_machine_prod_signoff","label":"True 3-machine production signoff","status":"pending","command":"three-machine","notes":""}
  ]
}
EOF_JSON
    ;;
  local_blocker)
    cat >"$summary_json" <<'EOF_JSON'
{
  "summary": {
    "roadmap_stage": "BLOCKED_LOCAL",
    "single_machine_ready": false,
    "profile_default_gate": {
      "status": "pending",
      "available": false,
      "valid_json": false
    },
    "profile_default_ready": false,
    "next_action_check_id": "runtime_hygiene",
    "next_action_command": "sudo ./scripts/easy_node.sh runtime-fix-record --prune-wg-only-dir 1 --print-summary-json 1"
  },
  "report": {
    "readiness_status": "NOT_READY"
  },
  "checks": [
    {"check_id":"runtime_hygiene","label":"Runtime hygiene doctor","status":"warn","command":"runtime","notes":"fix needed"},
    {"check_id":"wg_only_stack_selftest","label":"WG-only stack selftest","status":"pass","command":"wg-only","notes":""},
    {"check_id":"machine_c_vpn_smoke","label":"Machine C VPN smoke test","status":"pending","command":"machine-c","notes":""},
    {"check_id":"three_machine_prod_signoff","label":"True 3-machine production signoff","status":"pending","command":"three-machine","notes":""}
  ]
}
EOF_JSON
    ;;
  all_pass)
    cat >"$summary_json" <<'EOF_JSON'
{
  "summary": {
    "roadmap_stage": "PRODUCTION_SIGNOFF_COMPLETE",
    "single_machine_ready": true,
    "profile_default_gate": {
      "status": "pass",
      "available": true,
      "valid_json": true
    },
    "profile_default_ready": true,
    "next_action_check_id": "",
    "next_action_command": ""
  },
  "report": {
    "readiness_status": "READY"
  },
  "checks": [
    {"check_id":"runtime_hygiene","label":"Runtime hygiene doctor","status":"pass","command":"runtime","notes":""},
    {"check_id":"wg_only_stack_selftest","label":"WG-only stack selftest","status":"pass","command":"wg-only","notes":""},
    {"check_id":"machine_c_vpn_smoke","label":"Machine C VPN smoke test","status":"pass","command":"machine-c","notes":""},
    {"check_id":"three_machine_prod_signoff","label":"True 3-machine production signoff","status":"pass","command":"three-machine","notes":""}
  ]
}
EOF_JSON
    ;;
  *)
    echo "unknown FAKE_MANUAL_REPORT_MODE=$mode"
    exit 2
    ;;
esac
printf '# fake report\n' >"$report_md"
printf '[manual-validation-report] summary_json=%s\n' "$summary_json"
printf '[manual-validation-report] report_md=%s\n' "$report_md"
printf '[manual-validation-report] readiness_status=%s\n' "$(jq -r '.report.readiness_status' "$summary_json")"
EOF_REPORT

cat >"$FAKE_SINGLE_MACHINE_FORWARD" <<EOF_FORWARD
#!/usr/bin/env bash
set -euo pipefail
printf 'single-machine-prod-readiness %s\n' "\$*" >>"$CAPTURE"
EOF_FORWARD

chmod +x \
  "$FAKE_CI" \
  "$FAKE_BETA" \
  "$FAKE_DEEP_OK" \
  "$FAKE_DEEP_FAIL" \
  "$FAKE_DEEP_SLEEP" \
  "$FAKE_RUNTIME_FIX_RECORD" \
  "$FAKE_THREE_MACHINE_DOCKER_READINESS" \
  "$FAKE_PROFILE_SIGNOFF" \
  "$FAKE_PRE_REAL" \
  "$FAKE_REAL_WG_PRIVILEGED_MATRIX_RECORD" \
  "$FAKE_MANUAL_REPORT" \
  "$FAKE_SINGLE_MACHINE_FORWARD"

echo "[single-machine-prod-readiness] warn path"
FAKE_MANUAL_REPORT_MODE=pending_multi \
SINGLE_MACHINE_CI_LOCAL_SCRIPT="$FAKE_CI" \
SINGLE_MACHINE_BETA_PREFLIGHT_SCRIPT="$FAKE_BETA" \
SINGLE_MACHINE_DEEP_TEST_SUITE_SCRIPT="$FAKE_DEEP_OK" \
SINGLE_MACHINE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME_FIX_RECORD" \
SINGLE_MACHINE_THREE_MACHINE_DOCKER_READINESS_SCRIPT="$FAKE_THREE_MACHINE_DOCKER_READINESS" \
SINGLE_MACHINE_PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_PROFILE_SIGNOFF" \
SINGLE_MACHINE_PRE_REAL_HOST_READINESS_SCRIPT="$FAKE_PRE_REAL" \
SINGLE_MACHINE_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL_REPORT" \
./scripts/single_machine_prod_readiness.sh \
  --run-three-machine-docker-readiness 0 \
  --run-profile-compare-campaign-signoff 0 \
  --run-pre-real-host-readiness 0 \
  --run-real-wg-privileged-matrix 0 \
  --summary-json "$WARN_SUMMARY" \
  --print-summary-json 1 >"$WARN_LOG"

if ! rg -q '\[single-machine-prod-readiness\] status=warn rc=0' "$WARN_LOG"; then
  echo "warn path missing status line"
  cat "$WARN_LOG"
  exit 1
fi
if ! rg -q '\[single-machine-prod-readiness\] next_action_check_id=machine_c_vpn_smoke' "$WARN_LOG"; then
  echo "warn path missing next_action_check_id line"
  cat "$WARN_LOG"
  exit 1
fi
if ! rg -q '\[single-machine-prod-readiness\] next_action_command=sudo \./scripts/easy_node\.sh client-vpn-smoke' "$WARN_LOG"; then
  echo "warn path missing next_action_command line"
  cat "$WARN_LOG"
  exit 1
fi
if ! rg -q '\[single-machine-prod-readiness\] profile_default_gate_status=pending' "$WARN_LOG"; then
  echo "warn path missing profile_default_gate_status line"
  cat "$WARN_LOG"
  exit 1
fi
if ! rg -q '\[single-machine-prod-readiness\] profile_default_gate_available=true' "$WARN_LOG"; then
  echo "warn path missing profile_default_gate_available line"
  cat "$WARN_LOG"
  exit 1
fi
if ! rg -q '\[single-machine-prod-readiness\] profile_default_gate_next_command=sudo \./scripts/easy_node\.sh profile-compare-campaign-signoff' "$WARN_LOG"; then
  echo "warn path missing profile_default_gate_next_command line"
  cat "$WARN_LOG"
  exit 1
fi
if ! jq -e '
  .schema.id == "single_machine_prod_readiness_summary"
  and .schema.major == 1
  and .schema.minor == 0
  and
  .status == "warn"
  and .rc == 0
  and .summary.roadmap_stage == "READY_FOR_MACHINE_C_SMOKE"
  and .summary.profile_default_gate.status == "pending"
  and .summary.profile_default_gate.available == true
  and .summary.profile_default_gate.non_root_refresh_blocked == true
  and .summary.profile_default_ready == false
  and .summary.three_machine_docker_readiness.available == false
  and .summary.three_machine_docker_readiness.status == "skip"
  and .summary.three_machine_docker_readiness.ready == true
  and .summary.real_wg_privileged_matrix.status == "skip"
  and .summary.real_wg_privileged_matrix.ready == true
  and .summary.pending_local_checks == []
  and (.summary.pending_multi_machine_checks | length) == 2
  and .inputs.run_real_wg_privileged_matrix == "0"
  and (.steps[] | select(.step_id == "real_wg_privileged_matrix") | .status == "skip")
  and (.steps[] | select(.step_id == "pre_real_host_readiness") | .status == "skip")
' "$WARN_SUMMARY" >/dev/null; then
  echo "warn summary JSON missing expected fields"
  cat "$WARN_SUMMARY"
  exit 1
fi
if ! jq -e --arg latest "$SINGLE_MACHINE_SUMMARY_JSON_LATEST" '.paths.summary_latest_json == $latest' "$WARN_SUMMARY" >/dev/null; then
  echo "warn summary JSON missing summary_latest_json path"
  cat "$WARN_SUMMARY"
  exit 1
fi
if [[ ! -f "$SINGLE_MACHINE_SUMMARY_JSON_LATEST" ]]; then
  echo "single-machine latest summary pointer file was not written"
  ls -l "$TMP_DIR"
  exit 1
fi
if ! jq -e '.status == "warn"' "$SINGLE_MACHINE_SUMMARY_JSON_LATEST" >/dev/null; then
  echo "single-machine latest summary pointer JSON missing expected status"
  cat "$SINGLE_MACHINE_SUMMARY_JSON_LATEST"
  exit 1
fi
if ! jq -e '.schema.id == "single_machine_prod_readiness_summary" and .schema.major == 1 and .schema.minor == 0' "$SINGLE_MACHINE_SUMMARY_JSON_LATEST" >/dev/null; then
  echo "single-machine latest summary pointer JSON missing expected schema metadata"
  cat "$SINGLE_MACHINE_SUMMARY_JSON_LATEST"
  exit 1
fi

echo "[single-machine-prod-readiness] local blocker fail path"
set +e
FAKE_MANUAL_REPORT_MODE=local_blocker \
SINGLE_MACHINE_CI_LOCAL_SCRIPT="$FAKE_CI" \
SINGLE_MACHINE_BETA_PREFLIGHT_SCRIPT="$FAKE_BETA" \
SINGLE_MACHINE_DEEP_TEST_SUITE_SCRIPT="$FAKE_DEEP_OK" \
SINGLE_MACHINE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME_FIX_RECORD" \
SINGLE_MACHINE_THREE_MACHINE_DOCKER_READINESS_SCRIPT="$FAKE_THREE_MACHINE_DOCKER_READINESS" \
SINGLE_MACHINE_PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_PROFILE_SIGNOFF" \
SINGLE_MACHINE_PRE_REAL_HOST_READINESS_SCRIPT="$FAKE_PRE_REAL" \
SINGLE_MACHINE_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL_REPORT" \
./scripts/single_machine_prod_readiness.sh \
  --run-ci-local 0 \
  --run-beta-preflight 0 \
  --run-deep-suite 0 \
  --run-runtime-fix-record 0 \
  --run-three-machine-docker-readiness 0 \
  --run-profile-compare-campaign-signoff 0 \
  --run-pre-real-host-readiness 0 \
  --run-real-wg-privileged-matrix 0 \
  --summary-json "$LOCAL_FAIL_SUMMARY" \
  --print-summary-json 0 >"$LOCAL_FAIL_LOG" 2>&1
rc_local=$?
set -e
if [[ $rc_local -eq 0 ]]; then
  echo "local blocker path should fail"
  cat "$LOCAL_FAIL_LOG"
  cat "$LOCAL_FAIL_SUMMARY"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and (.summary.pending_local_checks | length) == 1
  and .summary.pending_local_checks[0].check_id == "runtime_hygiene"
' "$LOCAL_FAIL_SUMMARY" >/dev/null; then
  echo "local blocker summary JSON missing expected fields"
  cat "$LOCAL_FAIL_SUMMARY"
  exit 1
fi

echo "[single-machine-prod-readiness] step failure path"
set +e
FAKE_MANUAL_REPORT_MODE=all_pass \
SINGLE_MACHINE_CI_LOCAL_SCRIPT="$FAKE_CI" \
SINGLE_MACHINE_BETA_PREFLIGHT_SCRIPT="$FAKE_BETA" \
SINGLE_MACHINE_DEEP_TEST_SUITE_SCRIPT="$FAKE_DEEP_FAIL" \
SINGLE_MACHINE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME_FIX_RECORD" \
SINGLE_MACHINE_THREE_MACHINE_DOCKER_READINESS_SCRIPT="$FAKE_THREE_MACHINE_DOCKER_READINESS" \
SINGLE_MACHINE_PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_PROFILE_SIGNOFF" \
SINGLE_MACHINE_PRE_REAL_HOST_READINESS_SCRIPT="$FAKE_PRE_REAL" \
SINGLE_MACHINE_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL_REPORT" \
./scripts/single_machine_prod_readiness.sh \
  --run-ci-local 0 \
  --run-beta-preflight 0 \
  --run-runtime-fix-record 0 \
  --run-three-machine-docker-readiness 0 \
  --run-profile-compare-campaign-signoff 0 \
  --run-pre-real-host-readiness 0 \
  --run-real-wg-privileged-matrix 0 \
  --summary-json "$STEP_FAIL_SUMMARY" \
  --print-summary-json 0 >"$STEP_FAIL_LOG" 2>&1
rc_step=$?
set -e
if [[ $rc_step -eq 0 ]]; then
  echo "step failure path should fail"
  cat "$STEP_FAIL_LOG"
  cat "$STEP_FAIL_SUMMARY"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and (.steps[] | select(.step_id == "deep_test_suite") | .status == "fail")
' "$STEP_FAIL_SUMMARY" >/dev/null; then
  echo "step failure summary JSON missing deep_test_suite fail"
  cat "$STEP_FAIL_SUMMARY"
  exit 1
fi

if command -v timeout >/dev/null 2>&1; then
  echo "[single-machine-prod-readiness] step timeout path"
  set +e
  FAKE_MANUAL_REPORT_MODE=all_pass \
  FAKE_DEEP_SLEEP_SEC=3 \
  SINGLE_MACHINE_CI_LOCAL_SCRIPT="$FAKE_CI" \
  SINGLE_MACHINE_BETA_PREFLIGHT_SCRIPT="$FAKE_BETA" \
  SINGLE_MACHINE_DEEP_TEST_SUITE_SCRIPT="$FAKE_DEEP_SLEEP" \
  SINGLE_MACHINE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME_FIX_RECORD" \
  SINGLE_MACHINE_THREE_MACHINE_DOCKER_READINESS_SCRIPT="$FAKE_THREE_MACHINE_DOCKER_READINESS" \
  SINGLE_MACHINE_PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_PROFILE_SIGNOFF" \
  SINGLE_MACHINE_PRE_REAL_HOST_READINESS_SCRIPT="$FAKE_PRE_REAL" \
  SINGLE_MACHINE_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL_REPORT" \
  ./scripts/single_machine_prod_readiness.sh \
    --run-ci-local 0 \
    --run-beta-preflight 0 \
    --run-runtime-fix-record 0 \
    --run-three-machine-docker-readiness 0 \
    --run-profile-compare-campaign-signoff 0 \
    --run-pre-real-host-readiness 0 \
    --run-real-wg-privileged-matrix 0 \
    --step-timeout-sec 1 \
    --summary-json "$STEP_TIMEOUT_SUMMARY" \
    --print-summary-json 0 >"$STEP_TIMEOUT_LOG" 2>&1
  rc_step_timeout=$?
  set -e
  if [[ $rc_step_timeout -eq 0 ]]; then
    echo "step timeout path should fail"
    cat "$STEP_TIMEOUT_LOG"
    cat "$STEP_TIMEOUT_SUMMARY"
    exit 1
  fi
  if ! rg -q '\[single-machine-prod-readiness\] step=deep_test_suite status=running timeout_sec=1 ' "$STEP_TIMEOUT_LOG"; then
    echo "step timeout path missing running heartbeat line"
    cat "$STEP_TIMEOUT_LOG"
    exit 1
  fi
  if ! rg -q '\[single-machine-prod-readiness\] step=deep_test_suite status=fail rc=124 timed_out=true' "$STEP_TIMEOUT_LOG"; then
    echo "step timeout path missing timeout completion line"
    cat "$STEP_TIMEOUT_LOG"
    exit 1
  fi
  if ! jq -e '
    .status == "fail"
    and .rc == 1
    and .inputs.step_timeout_sec == 1
    and .summary.timed_out_steps >= 1
    and ((.summary.timed_out_step_details // []) | any(.step_id == "deep_test_suite" and .status == "fail" and .timed_out == true and .rc == 124))
    and (.steps[] | select(.step_id == "deep_test_suite") | .status == "fail" and .timed_out == true and .timeout_sec == 1 and .rc == 124)
  ' "$STEP_TIMEOUT_SUMMARY" >/dev/null; then
    echo "step timeout summary JSON missing expected timeout fields"
    cat "$STEP_TIMEOUT_LOG"
    cat "$STEP_TIMEOUT_SUMMARY"
    exit 1
  fi
fi

echo "[single-machine-prod-readiness] docker rehearsal step"
: >"$DOCKER_REHEARSAL_ARGS_LOG"
FAKE_MANUAL_REPORT_MODE=pending_multi \
SINGLE_MACHINE_CI_LOCAL_SCRIPT="$FAKE_CI" \
SINGLE_MACHINE_BETA_PREFLIGHT_SCRIPT="$FAKE_BETA" \
SINGLE_MACHINE_DEEP_TEST_SUITE_SCRIPT="$FAKE_DEEP_OK" \
SINGLE_MACHINE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME_FIX_RECORD" \
SINGLE_MACHINE_THREE_MACHINE_DOCKER_READINESS_SCRIPT="$FAKE_THREE_MACHINE_DOCKER_READINESS" \
SINGLE_MACHINE_PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_PROFILE_SIGNOFF" \
SINGLE_MACHINE_PRE_REAL_HOST_READINESS_SCRIPT="$FAKE_PRE_REAL" \
SINGLE_MACHINE_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL_REPORT" \
THREE_MACHINE_DOCKER_DOCKER_BIN="bash" \
FAKE_THREE_MACHINE_DOCKER_READINESS_ARGS_LOG="$DOCKER_REHEARSAL_ARGS_LOG" \
FAKE_THREE_MACHINE_DOCKER_READINESS_STATUS="pass" \
FAKE_THREE_MACHINE_DOCKER_READINESS_RC=0 \
FAKE_THREE_MACHINE_DOCKER_READINESS_EXIT_RC=0 \
./scripts/single_machine_prod_readiness.sh \
  --run-ci-local 0 \
  --run-beta-preflight 0 \
  --run-deep-suite 0 \
  --run-runtime-fix-record 0 \
  --run-three-machine-docker-readiness 1 \
  --three-machine-docker-readiness-run-validate 1 \
  --three-machine-docker-readiness-run-soak 1 \
  --three-machine-docker-readiness-soak-rounds 2 \
  --three-machine-docker-readiness-soak-pause-sec 1 \
  --three-machine-docker-readiness-path-profile balanced \
  --three-machine-docker-readiness-keep-stacks 0 \
  --three-machine-docker-readiness-summary-json "$TMP_DIR/docker_rehearsal_script_summary.json" \
  --run-profile-compare-campaign-signoff 0 \
  --run-pre-real-host-readiness 0 \
  --run-real-wg-privileged-matrix 0 \
  --summary-json "$DOCKER_REHEARSAL_SUMMARY" \
  --print-summary-json 0 >"$DOCKER_REHEARSAL_LOG"

if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .inputs.run_three_machine_docker_readiness == "1"
  and .inputs.three_machine_docker_readiness_run_validate == true
  and .inputs.three_machine_docker_readiness_run_soak == true
  and .inputs.three_machine_docker_readiness_soak_rounds == 2
  and .inputs.three_machine_docker_readiness_soak_pause_sec == 1
  and .inputs.three_machine_docker_readiness_path_profile == "balanced"
  and .inputs.three_machine_docker_readiness_keep_stacks == false
  and (.steps[] | select(.step_id == "three_machine_docker_readiness") | .status == "pass")
  and .summary.three_machine_docker_readiness.available == true
  and .summary.three_machine_docker_readiness.status == "pass"
  and .summary.three_machine_docker_readiness.ready == true
' "$DOCKER_REHEARSAL_SUMMARY" >/dev/null; then
  echo "docker rehearsal summary JSON missing expected fields"
  cat "$DOCKER_REHEARSAL_LOG"
  cat "$DOCKER_REHEARSAL_SUMMARY"
  exit 1
fi
if ! rg -q -- '--run-validate 1' "$DOCKER_REHEARSAL_ARGS_LOG"; then
  echo "docker rehearsal args missing --run-validate 1"
  cat "$DOCKER_REHEARSAL_ARGS_LOG"
  exit 1
fi
if ! rg -q -- '--soak-rounds 2' "$DOCKER_REHEARSAL_ARGS_LOG"; then
  echo "docker rehearsal args missing --soak-rounds 2"
  cat "$DOCKER_REHEARSAL_ARGS_LOG"
  exit 1
fi

echo "[single-machine-prod-readiness] profile-compare campaign signoff step"
: >"$MANUAL_REPORT_ARGS_LOG"
FAKE_MANUAL_REPORT_MODE=pending_multi \
SINGLE_MACHINE_CI_LOCAL_SCRIPT="$FAKE_CI" \
SINGLE_MACHINE_BETA_PREFLIGHT_SCRIPT="$FAKE_BETA" \
SINGLE_MACHINE_DEEP_TEST_SUITE_SCRIPT="$FAKE_DEEP_OK" \
SINGLE_MACHINE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME_FIX_RECORD" \
SINGLE_MACHINE_THREE_MACHINE_DOCKER_READINESS_SCRIPT="$FAKE_THREE_MACHINE_DOCKER_READINESS" \
SINGLE_MACHINE_PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_PROFILE_SIGNOFF" \
SINGLE_MACHINE_PRE_REAL_HOST_READINESS_SCRIPT="$FAKE_PRE_REAL" \
SINGLE_MACHINE_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL_REPORT" \
FAKE_MANUAL_REPORT_ARGS_LOG="$MANUAL_REPORT_ARGS_LOG" \
FAKE_PROFILE_SIGNOFF_RC=0 \
./scripts/single_machine_prod_readiness.sh \
  --run-ci-local 0 \
  --run-beta-preflight 0 \
  --run-deep-suite 0 \
  --run-runtime-fix-record 0 \
  --run-three-machine-docker-readiness 0 \
  --run-profile-compare-campaign-signoff 1 \
  --run-pre-real-host-readiness 0 \
  --run-real-wg-privileged-matrix 0 \
  --profile-compare-campaign-signoff-refresh-campaign 0 \
  --profile-compare-campaign-signoff-summary-json "$TMP_DIR/profile_compare_campaign_signoff_summary.json" \
  --summary-json "$PROFILE_SIGNOFF_SUMMARY" \
  --print-summary-json 0 >"$PROFILE_SIGNOFF_LOG"

if ! jq -e '
  .status == "warn"
  and .rc == 0
  and (.steps[] | select(.step_id == "profile_compare_campaign_signoff") | .status == "pass")
  and .summary.profile_compare_campaign_signoff.available == true
  and .summary.profile_compare_campaign_signoff.ready == true
  and .summary.profile_compare_campaign_signoff.decision == "GO"
  and .summary.profile_compare_campaign_signoff.recommended_profile == "balanced"
' "$PROFILE_SIGNOFF_SUMMARY" >/dev/null; then
  echo "profile compare campaign signoff summary JSON missing expected fields"
  cat "$PROFILE_SIGNOFF_LOG"
  cat "$PROFILE_SIGNOFF_SUMMARY"
  exit 1
fi
if ! rg -q -- "--profile-compare-signoff-summary-json $TMP_DIR/profile_compare_campaign_signoff_summary.json" "$MANUAL_REPORT_ARGS_LOG"; then
  echo "manual validation report invocation missing forwarded --profile-compare-signoff-summary-json path"
  cat "$MANUAL_REPORT_ARGS_LOG"
  exit 1
fi

echo "[single-machine-prod-readiness] profile-compare signoff non-blocking failure"
set +e
FAKE_MANUAL_REPORT_MODE=pending_multi \
SINGLE_MACHINE_CI_LOCAL_SCRIPT="$FAKE_CI" \
SINGLE_MACHINE_BETA_PREFLIGHT_SCRIPT="$FAKE_BETA" \
SINGLE_MACHINE_DEEP_TEST_SUITE_SCRIPT="$FAKE_DEEP_OK" \
SINGLE_MACHINE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME_FIX_RECORD" \
SINGLE_MACHINE_THREE_MACHINE_DOCKER_READINESS_SCRIPT="$FAKE_THREE_MACHINE_DOCKER_READINESS" \
SINGLE_MACHINE_PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_PROFILE_SIGNOFF" \
SINGLE_MACHINE_PRE_REAL_HOST_READINESS_SCRIPT="$FAKE_PRE_REAL" \
SINGLE_MACHINE_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL_REPORT" \
FAKE_PROFILE_SIGNOFF_RC=1 \
./scripts/single_machine_prod_readiness.sh \
  --run-ci-local 0 \
  --run-beta-preflight 0 \
  --run-deep-suite 0 \
  --run-runtime-fix-record 0 \
  --run-three-machine-docker-readiness 0 \
  --run-profile-compare-campaign-signoff 1 \
  --run-pre-real-host-readiness 0 \
  --run-real-wg-privileged-matrix 0 \
  --profile-compare-campaign-signoff-refresh-campaign 0 \
  --profile-compare-campaign-signoff-summary-json "$TMP_DIR/profile_compare_campaign_signoff_non_blocking_summary.json" \
  --summary-json "$PROFILE_SIGNOFF_NON_BLOCKING_SUMMARY" \
  --print-summary-json 0 >"$PROFILE_SIGNOFF_NON_BLOCKING_LOG" 2>&1
rc_profile_non_blocking=$?
set -e
if [[ "$rc_profile_non_blocking" -ne 0 ]]; then
  echo "profile-compare signoff failure should remain non-blocking"
  cat "$PROFILE_SIGNOFF_NON_BLOCKING_LOG"
  cat "$PROFILE_SIGNOFF_NON_BLOCKING_SUMMARY"
  exit 1
fi
if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .summary.critical_fail_steps == 0
  and .summary.non_blocking_fail_steps == 1
  and (.summary.non_blocking_failed_steps | length) == 1
  and .summary.non_blocking_failed_steps[0].step_id == "profile_compare_campaign_signoff"
  and (.steps[] | select(.step_id == "profile_compare_campaign_signoff") | .status == "fail")
' "$PROFILE_SIGNOFF_NON_BLOCKING_SUMMARY" >/dev/null; then
  echo "profile-compare signoff non-blocking summary JSON missing expected fields"
  cat "$PROFILE_SIGNOFF_NON_BLOCKING_LOG"
  cat "$PROFILE_SIGNOFF_NON_BLOCKING_SUMMARY"
  exit 1
fi

echo "[single-machine-prod-readiness] auto refresh when campaign summary is missing"
rm -rf "$TMP_DIR/auto_refresh_reports"
: >"$PROFILE_SIGNOFF_ARGS_LOG"
FAKE_MANUAL_REPORT_MODE=pending_multi \
SINGLE_MACHINE_CI_LOCAL_SCRIPT="$FAKE_CI" \
SINGLE_MACHINE_BETA_PREFLIGHT_SCRIPT="$FAKE_BETA" \
SINGLE_MACHINE_DEEP_TEST_SUITE_SCRIPT="$FAKE_DEEP_OK" \
SINGLE_MACHINE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME_FIX_RECORD" \
SINGLE_MACHINE_THREE_MACHINE_DOCKER_READINESS_SCRIPT="$FAKE_THREE_MACHINE_DOCKER_READINESS" \
SINGLE_MACHINE_PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_PROFILE_SIGNOFF" \
SINGLE_MACHINE_PRE_REAL_HOST_READINESS_SCRIPT="$FAKE_PRE_REAL" \
SINGLE_MACHINE_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL_REPORT" \
FAKE_PROFILE_SIGNOFF_RC=0 \
FAKE_PROFILE_SIGNOFF_ARGS_LOG="$PROFILE_SIGNOFF_ARGS_LOG" \
./scripts/single_machine_prod_readiness.sh \
  --run-ci-local 0 \
  --run-beta-preflight 0 \
  --run-deep-suite 0 \
  --run-runtime-fix-record 0 \
  --run-three-machine-docker-readiness 0 \
  --run-profile-compare-campaign-signoff auto \
  --profile-compare-campaign-signoff-refresh-campaign 0 \
  --profile-compare-campaign-signoff-reports-dir "$TMP_DIR/auto_refresh_reports" \
  --run-pre-real-host-readiness 0 \
  --run-real-wg-privileged-matrix 0 \
  --summary-json "$AUTO_REFRESH_SUMMARY" \
  --print-summary-json 0 >"$AUTO_REFRESH_LOG"

if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .inputs.run_profile_compare_campaign_signoff == "auto"
  and .inputs.profile_compare_campaign_signoff_refresh_campaign == false
  and .inputs.profile_compare_campaign_signoff_refresh_effective == true
  and .inputs.profile_compare_campaign_signoff_auto_refreshed == true
  and .inputs.profile_compare_campaign_signoff_auto_refreshed_via_docker == false
  and (.steps[] | select(.step_id == "profile_compare_campaign_signoff") | .status == "pass")
' "$AUTO_REFRESH_SUMMARY" >/dev/null; then
  echo "auto refresh summary JSON missing expected fields"
  cat "$AUTO_REFRESH_LOG"
  cat "$AUTO_REFRESH_SUMMARY"
  exit 1
fi
if ! rg -q -- '--refresh-campaign 1' "$PROFILE_SIGNOFF_ARGS_LOG"; then
  echo "auto refresh path did not force --refresh-campaign 1"
  cat "$PROFILE_SIGNOFF_ARGS_LOG"
  exit 1
fi

echo "[single-machine-prod-readiness] auto refresh via docker rehearsal endpoints"
rm -rf "$TMP_DIR/auto_refresh_docker_reports"
: >"$PROFILE_SIGNOFF_ARGS_LOG"
FAKE_MANUAL_REPORT_MODE=pending_multi \
SINGLE_MACHINE_CI_LOCAL_SCRIPT="$FAKE_CI" \
SINGLE_MACHINE_BETA_PREFLIGHT_SCRIPT="$FAKE_BETA" \
SINGLE_MACHINE_DEEP_TEST_SUITE_SCRIPT="$FAKE_DEEP_OK" \
SINGLE_MACHINE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME_FIX_RECORD" \
SINGLE_MACHINE_THREE_MACHINE_DOCKER_READINESS_SCRIPT="$FAKE_THREE_MACHINE_DOCKER_READINESS" \
SINGLE_MACHINE_PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_PROFILE_SIGNOFF" \
SINGLE_MACHINE_PRE_REAL_HOST_READINESS_SCRIPT="$FAKE_PRE_REAL" \
SINGLE_MACHINE_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL_REPORT" \
THREE_MACHINE_DOCKER_DOCKER_BIN="bash" \
FAKE_THREE_MACHINE_DOCKER_READINESS_STATUS="pass" \
FAKE_THREE_MACHINE_DOCKER_READINESS_RC=0 \
FAKE_THREE_MACHINE_DOCKER_READINESS_EXIT_RC=0 \
FAKE_PROFILE_SIGNOFF_RC=0 \
FAKE_PROFILE_SIGNOFF_ARGS_LOG="$PROFILE_SIGNOFF_ARGS_LOG" \
./scripts/single_machine_prod_readiness.sh \
  --run-ci-local 0 \
  --run-beta-preflight 0 \
  --run-deep-suite 0 \
  --run-runtime-fix-record 0 \
  --run-three-machine-docker-readiness 1 \
  --run-profile-compare-campaign-signoff auto \
  --profile-compare-campaign-signoff-refresh-campaign 0 \
  --profile-compare-campaign-signoff-reports-dir "$TMP_DIR/auto_refresh_docker_reports" \
  --run-pre-real-host-readiness 0 \
  --run-real-wg-privileged-matrix 0 \
  --summary-json "$AUTO_REFRESH_DOCKER_SUMMARY" \
  --print-summary-json 0 >"$AUTO_REFRESH_DOCKER_LOG"

if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .inputs.run_profile_compare_campaign_signoff == "auto"
  and .inputs.profile_compare_campaign_signoff_refresh_campaign == false
  and .inputs.profile_compare_campaign_signoff_refresh_effective == true
  and .inputs.profile_compare_campaign_signoff_auto_refreshed == true
  and .inputs.profile_compare_campaign_signoff_auto_refreshed_via_docker == true
  and .inputs.profile_compare_campaign_signoff_auto_skipped_non_root == false
  and .inputs.profile_compare_campaign_signoff_campaign_refresh_overrides_effective.execution_mode == "docker"
  and .inputs.profile_compare_campaign_signoff_campaign_refresh_overrides_effective.start_local_stack == "0"
  and .inputs.profile_compare_campaign_signoff_campaign_refresh_overrides_effective.directory_urls == "http://127.0.0.1:18081,http://127.0.0.1:28081"
  and .inputs.profile_compare_campaign_signoff_campaign_refresh_overrides_effective.bootstrap_directory == "http://127.0.0.1:18081"
  and .inputs.profile_compare_campaign_signoff_campaign_refresh_overrides_effective.issuer_url == "http://127.0.0.1:18082"
  and .inputs.profile_compare_campaign_signoff_campaign_refresh_overrides_effective.entry_url == "http://127.0.0.1:18083"
  and .inputs.profile_compare_campaign_signoff_campaign_refresh_overrides_effective.exit_url == "http://127.0.0.1:18084"
  and (.steps[] | select(.step_id == "three_machine_docker_readiness") | .status == "pass")
  and (.steps[] | select(.step_id == "profile_compare_campaign_signoff") | .status == "pass")
' "$AUTO_REFRESH_DOCKER_SUMMARY" >/dev/null; then
  echo "auto refresh via docker summary JSON missing expected fields"
  cat "$AUTO_REFRESH_DOCKER_LOG"
  cat "$AUTO_REFRESH_DOCKER_SUMMARY"
  exit 1
fi
for expected in \
  '--refresh-campaign 1' \
  '--campaign-execution-mode docker' \
  '--campaign-directory-urls http://127.0.0.1:18081,http://127.0.0.1:28081' \
  '--campaign-bootstrap-directory http://127.0.0.1:18081' \
  '--campaign-issuer-url http://127.0.0.1:18082' \
  '--campaign-entry-url http://127.0.0.1:18083' \
  '--campaign-exit-url http://127.0.0.1:18084' \
  '--campaign-start-local-stack 0'; do
  if ! rg -q -- "$expected" "$PROFILE_SIGNOFF_ARGS_LOG"; then
    echo "auto refresh via docker path missing $expected"
    cat "$PROFILE_SIGNOFF_ARGS_LOG"
    exit 1
  fi
done

echo "[single-machine-prod-readiness] auto refresh stale signoff summary via docker rehearsal endpoints"
rm -rf "$TMP_DIR/auto_refresh_stale_signoff_reports"
mkdir -p "$TMP_DIR/auto_refresh_stale_signoff_reports"
cat >"$TMP_DIR/auto_refresh_stale_signoff_reports/profile_compare_campaign_signoff_summary.json" <<'EOF_STALE_SIGNOFF'
{
  "version": 1,
  "status": "fail",
  "final_rc": 1,
  "failure_stage": "campaign_check",
  "inputs": {
    "refresh_campaign": false
  },
  "decision": {
    "decision": "NO-GO",
    "recommended_profile": "balanced"
  }
}
EOF_STALE_SIGNOFF
: >"$PROFILE_SIGNOFF_ARGS_LOG"
FAKE_MANUAL_REPORT_MODE=pending_multi \
SINGLE_MACHINE_CI_LOCAL_SCRIPT="$FAKE_CI" \
SINGLE_MACHINE_BETA_PREFLIGHT_SCRIPT="$FAKE_BETA" \
SINGLE_MACHINE_DEEP_TEST_SUITE_SCRIPT="$FAKE_DEEP_OK" \
SINGLE_MACHINE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME_FIX_RECORD" \
SINGLE_MACHINE_THREE_MACHINE_DOCKER_READINESS_SCRIPT="$FAKE_THREE_MACHINE_DOCKER_READINESS" \
SINGLE_MACHINE_PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_PROFILE_SIGNOFF" \
SINGLE_MACHINE_PRE_REAL_HOST_READINESS_SCRIPT="$FAKE_PRE_REAL" \
SINGLE_MACHINE_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL_REPORT" \
THREE_MACHINE_DOCKER_DOCKER_BIN="bash" \
FAKE_THREE_MACHINE_DOCKER_READINESS_STATUS="pass" \
FAKE_THREE_MACHINE_DOCKER_READINESS_RC=0 \
FAKE_THREE_MACHINE_DOCKER_READINESS_EXIT_RC=0 \
FAKE_PROFILE_SIGNOFF_RC=0 \
FAKE_PROFILE_SIGNOFF_ARGS_LOG="$PROFILE_SIGNOFF_ARGS_LOG" \
./scripts/single_machine_prod_readiness.sh \
  --run-ci-local 0 \
  --run-beta-preflight 0 \
  --run-deep-suite 0 \
  --run-runtime-fix-record 0 \
  --run-three-machine-docker-readiness 1 \
  --run-profile-compare-campaign-signoff auto \
  --profile-compare-campaign-signoff-refresh-campaign 0 \
  --profile-compare-campaign-signoff-reports-dir "$TMP_DIR/auto_refresh_stale_signoff_reports" \
  --profile-compare-campaign-signoff-summary-json "$TMP_DIR/auto_refresh_stale_signoff_reports/profile_compare_campaign_signoff_summary.json" \
  --run-pre-real-host-readiness 0 \
  --run-real-wg-privileged-matrix 0 \
  --summary-json "$AUTO_REFRESH_STALE_SIGNOFF_SUMMARY" \
  --print-summary-json 0 >"$AUTO_REFRESH_STALE_SIGNOFF_LOG"

if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .inputs.profile_compare_campaign_signoff_refresh_campaign == false
  and .inputs.profile_compare_campaign_signoff_refresh_effective == true
  and .inputs.profile_compare_campaign_signoff_auto_refreshed == true
  and .inputs.profile_compare_campaign_signoff_auto_refreshed_via_docker == true
  and .inputs.profile_compare_campaign_signoff_auto_refresh_reason == "stale non-refreshed signoff summary (status=fail decision=NO-GO)"
  and .inputs.profile_compare_campaign_signoff_existing_summary.available == true
  and .inputs.profile_compare_campaign_signoff_existing_summary.valid_json == true
  and .inputs.profile_compare_campaign_signoff_existing_summary.status == "fail"
  and .inputs.profile_compare_campaign_signoff_existing_summary.decision == "NO-GO"
  and .inputs.profile_compare_campaign_signoff_existing_summary.refresh_campaign == false
  and .inputs.profile_compare_campaign_signoff_existing_summary.requires_refresh == true
  and (.steps[] | select(.step_id == "profile_compare_campaign_signoff") | .status == "pass")
' "$AUTO_REFRESH_STALE_SIGNOFF_SUMMARY" >/dev/null; then
  echo "auto refresh stale signoff summary JSON missing expected fields"
  cat "$AUTO_REFRESH_STALE_SIGNOFF_LOG"
  cat "$AUTO_REFRESH_STALE_SIGNOFF_SUMMARY"
  exit 1
fi
if ! rg -q -- '--refresh-campaign 1' "$PROFILE_SIGNOFF_ARGS_LOG"; then
  echo "stale signoff auto-refresh path did not force --refresh-campaign 1"
  cat "$PROFILE_SIGNOFF_ARGS_LOG"
  exit 1
fi

echo "[single-machine-prod-readiness] auto refresh non-root skip path (default signoff script)"
rm -rf "$TMP_DIR/auto_refresh_non_root_reports"
FAKE_MANUAL_REPORT_MODE=pending_multi \
SINGLE_MACHINE_CI_LOCAL_SCRIPT="$FAKE_CI" \
SINGLE_MACHINE_BETA_PREFLIGHT_SCRIPT="$FAKE_BETA" \
SINGLE_MACHINE_DEEP_TEST_SUITE_SCRIPT="$FAKE_DEEP_OK" \
SINGLE_MACHINE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME_FIX_RECORD" \
SINGLE_MACHINE_THREE_MACHINE_DOCKER_READINESS_SCRIPT="$FAKE_THREE_MACHINE_DOCKER_READINESS" \
SINGLE_MACHINE_PRE_REAL_HOST_READINESS_SCRIPT="$FAKE_PRE_REAL" \
SINGLE_MACHINE_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL_REPORT" \
./scripts/single_machine_prod_readiness.sh \
  --run-ci-local 0 \
  --run-beta-preflight 0 \
  --run-deep-suite 0 \
  --run-runtime-fix-record 0 \
  --run-three-machine-docker-readiness 0 \
  --run-profile-compare-campaign-signoff auto \
  --profile-compare-campaign-signoff-refresh-campaign 0 \
  --profile-compare-campaign-signoff-reports-dir "$TMP_DIR/auto_refresh_non_root_reports" \
  --run-pre-real-host-readiness 0 \
  --run-real-wg-privileged-matrix 0 \
  --summary-json "$AUTO_REFRESH_NON_ROOT_SKIP_SUMMARY" \
  --print-summary-json 0 >"$AUTO_REFRESH_NON_ROOT_SKIP_LOG"

if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .inputs.run_profile_compare_campaign_signoff == "auto"
  and .inputs.profile_compare_campaign_signoff_refresh_campaign == false
  and .inputs.profile_compare_campaign_signoff_refresh_effective == false
  and .inputs.profile_compare_campaign_signoff_auto_refreshed == false
  and .inputs.profile_compare_campaign_signoff_auto_skipped_non_root == true
  and (.steps[] | select(.step_id == "profile_compare_campaign_signoff") | .status == "skip")
' "$AUTO_REFRESH_NON_ROOT_SKIP_SUMMARY" >/dev/null; then
  echo "auto refresh non-root skip summary JSON missing expected fields"
  cat "$AUTO_REFRESH_NON_ROOT_SKIP_LOG"
  cat "$AUTO_REFRESH_NON_ROOT_SKIP_SUMMARY"
  exit 1
fi

echo "[single-machine-prod-readiness] easy_node forwarding"
: >"$CAPTURE"
SINGLE_MACHINE_PROD_READINESS_SCRIPT="$FAKE_SINGLE_MACHINE_FORWARD" \
./scripts/easy_node.sh single-machine-prod-readiness \
  --run-ci-local 0 \
  --run-real-wg-privileged-matrix 0 \
  --summary-json /tmp/single_machine_prod_readiness_test.json \
  --print-summary-json 1

line_forward="$(rg '^single-machine-prod-readiness ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$line_forward" ]]; then
  echo "easy_node forwarding missing capture"
  cat "$CAPTURE"
  exit 1
fi
for expected in '--run-ci-local 0' '--run-real-wg-privileged-matrix 0' '--summary-json /tmp/single_machine_prod_readiness_test.json' '--print-summary-json 1'; do
  if ! grep -F -- "$expected" <<<"$line_forward" >/dev/null; then
    echo "easy_node forwarding missing $expected"
    cat "$CAPTURE"
    exit 1
  fi
done

echo "[single-machine-prod-readiness] real-WG matrix root requirement"
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  FAKE_MANUAL_REPORT_MODE=pending_multi \
  SINGLE_MACHINE_CI_LOCAL_SCRIPT="$FAKE_CI" \
  SINGLE_MACHINE_BETA_PREFLIGHT_SCRIPT="$FAKE_BETA" \
  SINGLE_MACHINE_DEEP_TEST_SUITE_SCRIPT="$FAKE_DEEP_OK" \
  SINGLE_MACHINE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME_FIX_RECORD" \
  SINGLE_MACHINE_THREE_MACHINE_DOCKER_READINESS_SCRIPT="$FAKE_THREE_MACHINE_DOCKER_READINESS" \
  SINGLE_MACHINE_PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_PROFILE_SIGNOFF" \
  SINGLE_MACHINE_PRE_REAL_HOST_READINESS_SCRIPT="$FAKE_PRE_REAL" \
  SINGLE_MACHINE_REAL_WG_PRIVILEGED_MATRIX_RECORD_SCRIPT="$FAKE_REAL_WG_PRIVILEGED_MATRIX_RECORD" \
  SINGLE_MACHINE_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL_REPORT" \
  FAKE_REAL_WG_PRIVILEGED_MATRIX_RECORD_RC=0 \
  ./scripts/single_machine_prod_readiness.sh \
    --run-ci-local 0 \
    --run-beta-preflight 0 \
    --run-deep-suite 0 \
    --run-runtime-fix-record 0 \
    --run-three-machine-docker-readiness 0 \
    --run-profile-compare-campaign-signoff 0 \
    --run-pre-real-host-readiness 0 \
    --run-real-wg-privileged-matrix 1 \
    --summary-json "$TMP_DIR/real_wg_root_ok_summary.json" \
    --print-summary-json 0 >/tmp/integration_single_machine_prod_readiness_real_wg_root_ok.log 2>&1

  if ! jq -e '
    .inputs.run_real_wg_privileged_matrix == "1"
    and (.steps[] | select(.step_id == "real_wg_privileged_matrix") | .status == "pass")
    and .summary.real_wg_privileged_matrix.status == "pass"
    and .summary.real_wg_privileged_matrix.ready == true
  ' "$TMP_DIR/real_wg_root_ok_summary.json" >/dev/null; then
    echo "real-WG matrix root path summary missing expected fields"
    cat /tmp/integration_single_machine_prod_readiness_real_wg_root_ok.log
    cat "$TMP_DIR/real_wg_root_ok_summary.json"
    exit 1
  fi
else
  set +e
  FAKE_MANUAL_REPORT_MODE=pending_multi \
  SINGLE_MACHINE_CI_LOCAL_SCRIPT="$FAKE_CI" \
  SINGLE_MACHINE_BETA_PREFLIGHT_SCRIPT="$FAKE_BETA" \
  SINGLE_MACHINE_DEEP_TEST_SUITE_SCRIPT="$FAKE_DEEP_OK" \
  SINGLE_MACHINE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME_FIX_RECORD" \
  SINGLE_MACHINE_THREE_MACHINE_DOCKER_READINESS_SCRIPT="$FAKE_THREE_MACHINE_DOCKER_READINESS" \
  SINGLE_MACHINE_PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_PROFILE_SIGNOFF" \
  SINGLE_MACHINE_PRE_REAL_HOST_READINESS_SCRIPT="$FAKE_PRE_REAL" \
  SINGLE_MACHINE_REAL_WG_PRIVILEGED_MATRIX_RECORD_SCRIPT="$FAKE_REAL_WG_PRIVILEGED_MATRIX_RECORD" \
  SINGLE_MACHINE_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL_REPORT" \
  ./scripts/single_machine_prod_readiness.sh \
    --run-ci-local 0 \
    --run-beta-preflight 0 \
    --run-deep-suite 0 \
    --run-runtime-fix-record 0 \
    --run-three-machine-docker-readiness 0 \
    --run-profile-compare-campaign-signoff 0 \
    --run-pre-real-host-readiness 0 \
    --run-real-wg-privileged-matrix 1 \
    --summary-json "$TMP_DIR/real_wg_non_root_fail_summary.json" \
    --print-summary-json 0 >/tmp/integration_single_machine_prod_readiness_real_wg_non_root_fail.log 2>&1
  rc_real_wg_non_root=$?
  set -e
  if [[ "$rc_real_wg_non_root" -eq 0 ]]; then
    echo "non-root real-WG matrix path should fail"
    cat /tmp/integration_single_machine_prod_readiness_real_wg_non_root_fail.log
    exit 1
  fi
  if ! rg -q -- '--run-real-wg-privileged-matrix=1 requires root' /tmp/integration_single_machine_prod_readiness_real_wg_non_root_fail.log; then
    echo "non-root real-WG matrix path missing root-requirement message"
    cat /tmp/integration_single_machine_prod_readiness_real_wg_non_root_fail.log
    exit 1
  fi
fi

echo "single machine prod readiness integration check ok"
