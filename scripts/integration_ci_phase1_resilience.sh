#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq mktemp chmod grep sed wc cat bash; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

GATE_SCRIPT="$ROOT_DIR/scripts/ci_phase1_resilience.sh"
if [[ ! -x "$GATE_SCRIPT" ]]; then
  echo "missing executable script under test: $GATE_SCRIPT"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/stage_calls.tsv"
DRY_RUN_LOG="$TMP_DIR/dry_run.log"
RESUME_LOG="$TMP_DIR/resume.log"
RESUME_FALLBACK_LOG="$TMP_DIR/resume_fallback.log"
TIMEOUT_LOG="$TMP_DIR/timeout.log"
FAIL_LOG="$TMP_DIR/fail.log"
POLICY_NO_GO_FAIL_CLOSED_LOG="$TMP_DIR/policy_no_go_fail_closed.log"
POLICY_NO_GO_ALLOWED_LOG="$TMP_DIR/policy_no_go_allowed.log"
THREE_HOP_ONLY_LOG="$TMP_DIR/three_hop_only.log"

DRY_RUN_REPORTS_DIR="$TMP_DIR/reports_dry_run"
RESUME_REPORTS_DIR="$TMP_DIR/reports_resume"
RESUME_FALLBACK_REPORTS_DIR="$TMP_DIR/reports_resume_fallback"
TIMEOUT_REPORTS_DIR="$TMP_DIR/reports_timeout"
FAIL_REPORTS_DIR="$TMP_DIR/reports_fail"
POLICY_NO_GO_FAIL_CLOSED_REPORTS_DIR="$TMP_DIR/reports_policy_no_go_fail_closed"
POLICY_NO_GO_ALLOWED_REPORTS_DIR="$TMP_DIR/reports_policy_no_go_allowed"
THREE_HOP_ONLY_REPORTS_DIR="$TMP_DIR/reports_three_hop_only"
DRY_RUN_SUMMARY_JSON="$TMP_DIR/summary_dry_run.json"
RESUME_SUMMARY_JSON="$TMP_DIR/summary_resume.json"
RESUME_FALLBACK_SUMMARY_JSON="$TMP_DIR/summary_resume_fallback.json"
TIMEOUT_SUMMARY_JSON="$TMP_DIR/summary_timeout.json"
FAIL_SUMMARY_JSON="$TMP_DIR/summary_fail.json"
POLICY_NO_GO_FAIL_CLOSED_SUMMARY_JSON="$TMP_DIR/summary_policy_no_go_fail_closed.json"
POLICY_NO_GO_ALLOWED_SUMMARY_JSON="$TMP_DIR/summary_policy_no_go_allowed.json"
THREE_HOP_ONLY_SUMMARY_JSON="$TMP_DIR/summary_three_hop_only.json"
TIMEOUT_CHILD_PID_FILE="$TMP_DIR/timeout_child.pid"

STAGE_ENV_NAMES=(
  "CI_PHASE1_RESILIENCE_THREE_MACHINE_DOCKER_PROFILE_MATRIX_SCRIPT"
  "CI_PHASE1_RESILIENCE_PROFILE_COMPARE_DOCKER_MATRIX_SCRIPT"
  "CI_PHASE1_RESILIENCE_THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_SCRIPT"
  "CI_PHASE1_RESILIENCE_VPN_RC_MATRIX_PATH_SCRIPT"
  "CI_PHASE1_RESILIENCE_VPN_RC_RESILIENCE_PATH_SCRIPT"
  "CI_PHASE1_RESILIENCE_SESSION_CHURN_GUARD_SCRIPT"
  "CI_PHASE1_RESILIENCE_THREE_HOP_RUNTIME_INTEGRATION_SCRIPT"
)

STAGE_IDS=(
  "three_machine_docker_profile_matrix"
  "profile_compare_docker_matrix"
  "three_machine_docker_profile_matrix_record"
  "vpn_rc_matrix_path"
  "vpn_rc_resilience_path"
  "session_churn_guard"
  "three_hop_runtime_integration"
)

WRAPPER_STAGE_IDS=(
  "three_machine_docker_profile_matrix"
  "profile_compare_docker_matrix"
  "three_machine_docker_profile_matrix_record"
  "vpn_rc_matrix_path"
  "vpn_rc_resilience_path"
)

DEFAULT_ENABLED_NON_DRY_STAGE_IDS=(
  "three_machine_docker_profile_matrix"
  "profile_compare_docker_matrix"
  "three_machine_docker_profile_matrix_record"
  "vpn_rc_matrix_path"
  "vpn_rc_resilience_path"
  "session_churn_guard"
)

FAKE_STAGE_HELPER="$TMP_DIR/fake_stage_helper.sh"
cat >"$FAKE_STAGE_HELPER" <<'EOF_FAKE_STAGE_HELPER'
#!/usr/bin/env bash
set -euo pipefail

capture="${CI_PHASE1_RESILIENCE_CAPTURE_FILE:?}"
stage_id="${CI_PHASE1_RESILIENCE_STAGE_ID:?}"

{
  printf '%s' "$stage_id"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture"

write_json_file() {
  local path="$1"
  mkdir -p "$(dirname "$path")"
  cat >"$path" <<'EOF_JSON'
{
  "version": 1,
  "status": "pass",
  "rc": 0
}
EOF_JSON
}

write_policy_no_go_summary_file() {
  local path="$1"
  local rc="${2:-1}"
  mkdir -p "$(dirname "$path")"
  cat >"$path" <<EOF_JSON
{
  "version": 1,
  "status": "fail",
  "rc": ${rc},
  "failure": {
    "kind": "policy_no_go"
  },
  "policy_outcome": {
    "decision": "NO-GO",
    "fail_closed_no_go": true
  }
}
EOF_JSON
}

write_markdown_file() {
  local path="$1"
  mkdir -p "$(dirname "$path")"
  printf '# fake stage report\n' >"$path"
}

args=("$@")
summary_json_path=""
for (( i=0; i<${#args[@]}; i++ )); do
  flag="${args[$i]}"
  value="${args[$((i + 1))]:-}"
  case "$flag" in
    --reports-dir)
      if [[ -n "$value" ]]; then
        mkdir -p "$value"
      fi
      ;;
    --summary-json|--matrix-summary-json|--docker-summary-json|--rc-summary-json|--roadmap-summary-json|--signoff-summary-json|--campaign-summary-json|--rehearsal-summary-json|--manual-validation-report-summary-json)
      if [[ -n "$value" ]]; then
        write_json_file "$value"
        if [[ "$flag" == "--summary-json" ]]; then
          summary_json_path="$value"
        fi
      fi
      ;;
    --report-md|--matrix-report-md|--docker-report-md|--roadmap-report-md|--campaign-report-md|--manual-validation-report-md)
      if [[ -n "$value" ]]; then
        write_markdown_file "$value"
      fi
      ;;
  esac
done

if [[ "${CI_PHASE1_RESILIENCE_POLICY_NO_GO_STAGE:-}" == "$stage_id" ]] && [[ -n "$summary_json_path" ]]; then
  write_policy_no_go_summary_file "$summary_json_path" "${CI_PHASE1_RESILIENCE_POLICY_NO_GO_RC:-1}"
fi

if [[ "${CI_PHASE1_RESILIENCE_TIMEOUT_STAGE:-}" == "$stage_id" ]]; then
  sleep "${CI_PHASE1_RESILIENCE_TIMEOUT_CHILD_SLEEP_SEC:-60}" &
  timeout_child_pid=$!
  if [[ -n "${CI_PHASE1_RESILIENCE_TIMEOUT_CHILD_PID_FILE:-}" ]]; then
    printf '%s\n' "$timeout_child_pid" >"${CI_PHASE1_RESILIENCE_TIMEOUT_CHILD_PID_FILE}"
  fi
  sleep "${CI_PHASE1_RESILIENCE_TIMEOUT_SLEEP_SEC:-60}"
fi

if [[ "${CI_PHASE1_RESILIENCE_FAIL_ON_STAGE:-}" == "$stage_id" ]]; then
  exit "${CI_PHASE1_RESILIENCE_FAIL_RC:-1}"
fi

exit 0
EOF_FAKE_STAGE_HELPER
chmod +x "$FAKE_STAGE_HELPER"

for idx in "${!STAGE_ENV_NAMES[@]}"; do
  env_name="${STAGE_ENV_NAMES[$idx]}"
  stage_id="${STAGE_IDS[$idx]}"
  fake_stage="$TMP_DIR/fake_stage_${idx}.sh"
  cat >"$fake_stage" <<EOF_FAKE_STAGE
#!/usr/bin/env bash
set -euo pipefail
CI_PHASE1_RESILIENCE_CAPTURE_FILE="\${CI_PHASE1_RESILIENCE_CAPTURE_FILE:?}" \\
CI_PHASE1_RESILIENCE_STAGE_ID="$stage_id" \\
CI_PHASE1_RESILIENCE_FAIL_ON_STAGE="\${CI_PHASE1_RESILIENCE_FAIL_ON_STAGE:-}" \\
CI_PHASE1_RESILIENCE_FAIL_RC="\${CI_PHASE1_RESILIENCE_FAIL_RC:-1}" \\
CI_PHASE1_RESILIENCE_TIMEOUT_STAGE="\${CI_PHASE1_RESILIENCE_TIMEOUT_STAGE:-}" \\
CI_PHASE1_RESILIENCE_TIMEOUT_SLEEP_SEC="\${CI_PHASE1_RESILIENCE_TIMEOUT_SLEEP_SEC:-60}" \\
CI_PHASE1_RESILIENCE_TIMEOUT_CHILD_SLEEP_SEC="\${CI_PHASE1_RESILIENCE_TIMEOUT_CHILD_SLEEP_SEC:-60}" \\
CI_PHASE1_RESILIENCE_TIMEOUT_CHILD_PID_FILE="\${CI_PHASE1_RESILIENCE_TIMEOUT_CHILD_PID_FILE:-}" \\
CI_PHASE1_RESILIENCE_POLICY_NO_GO_STAGE="\${CI_PHASE1_RESILIENCE_POLICY_NO_GO_STAGE:-}" \\
CI_PHASE1_RESILIENCE_POLICY_NO_GO_RC="\${CI_PHASE1_RESILIENCE_POLICY_NO_GO_RC:-1}" \\
"$FAKE_STAGE_HELPER" "\$@"
EOF_FAKE_STAGE
  chmod +x "$fake_stage"
  export "$env_name=$fake_stage"
done

assert_stage_order() {
  local capture_file="$1"
  shift
  local expected_ids=("$@")
  local idx line actual expected count

  count="$(wc -l <"$capture_file" | tr -d ' ')"
  if [[ "$count" -ne "${#expected_ids[@]}" ]]; then
    echo "unexpected stage invocation count: expected ${#expected_ids[@]}, got $count"
    cat "$capture_file"
    exit 1
  fi

  for idx in "${!expected_ids[@]}"; do
    expected="${expected_ids[$idx]}"
    line="$(sed -n "$((idx + 1))p" "$capture_file" || true)"
    if [[ -z "$line" ]]; then
      echo "missing stage invocation at index $idx"
      cat "$capture_file"
      exit 1
    fi
    actual="${line%%$'\t'*}"
    if [[ "$actual" != "$expected" ]]; then
      echo "stage order mismatch at index $idx: expected $expected, got $actual"
      cat "$capture_file"
      exit 1
    fi
  done
}

find_stage_line() {
  local capture_file="$1"
  local stage_id="$2"
  grep -E "^${stage_id}(\$|	)" "$capture_file" | tail -n 1 || true
}

wait_for_pid_exit() {
  local pid="$1"
  local retries="${2:-50}"
  local attempt
  for (( attempt=0; attempt<retries; attempt++ )); do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

echo "[ci-phase1-resilience] dry-run contract path"
: >"$CAPTURE"
CI_PHASE1_RESILIENCE_CAPTURE_FILE="$CAPTURE" \
bash "$GATE_SCRIPT" \
  --dry-run 1 \
  --reports-dir "$DRY_RUN_REPORTS_DIR" \
  --summary-json "$DRY_RUN_SUMMARY_JSON" \
  --print-summary-json 1 >"$DRY_RUN_LOG" 2>&1

assert_stage_order "$CAPTURE" "${WRAPPER_STAGE_IDS[@]}"

for stage_id in "${WRAPPER_STAGE_IDS[@]}"; do
  stage_line="$(find_stage_line "$CAPTURE" "$stage_id")"
  if [[ -z "$stage_line" ]]; then
    echo "missing stage invocation: $stage_id"
    cat "$CAPTURE"
    cat "$DRY_RUN_LOG"
    exit 1
  fi
  if [[ "$stage_line" != *$'\t--dry-run\t1'* ]]; then
    echo "dry-run forwarding missing for stage: $stage_id"
    echo "$stage_line"
    cat "$CAPTURE"
    cat "$DRY_RUN_LOG"
    exit 1
  fi
  if [[ "$stage_line" != *$'\t--print-summary-json\t0'* ]]; then
    echo "print-summary-json forwarding missing for stage: $stage_id"
    echo "$stage_line"
    cat "$CAPTURE"
    cat "$DRY_RUN_LOG"
    exit 1
  fi
done

for skipped_stage_id in "session_churn_guard" "three_hop_runtime_integration"; do
  if grep -q "^${skipped_stage_id}\$" "$CAPTURE" || grep -q "^${skipped_stage_id}	" "$CAPTURE"; then
    echo "dry-run should not invoke runtime-only stage: ${skipped_stage_id}"
    cat "$CAPTURE"
    cat "$DRY_RUN_LOG"
    exit 1
  fi
done

expected_three_machine_matrix_summary_json="$DRY_RUN_REPORTS_DIR/three_machine_docker_profile_matrix/three_machine_docker_profile_matrix_summary.json"
expected_three_machine_matrix_report_md="$DRY_RUN_REPORTS_DIR/three_machine_docker_profile_matrix/three_machine_docker_profile_matrix_report.md"
expected_vpn_rc_matrix_summary_json="$DRY_RUN_REPORTS_DIR/vpn_rc_matrix_path/vpn_rc_matrix_path_summary.json"

record_line="$(find_stage_line "$CAPTURE" "three_machine_docker_profile_matrix_record")"
if [[ "$record_line" != *$'\t--record-result\t0'* ]]; then
  echo "record stage missing --record-result 0 contract in dry-run path"
  echo "$record_line"
  cat "$CAPTURE"
  cat "$DRY_RUN_LOG"
  exit 1
fi
if [[ "$record_line" != *$'\t--manual-validation-report\t0'* ]]; then
  echo "record stage missing --manual-validation-report 0 contract in dry-run path"
  echo "$record_line"
  cat "$CAPTURE"
  cat "$DRY_RUN_LOG"
  exit 1
fi
record_matrix_summary_needle=$'\t--matrix-summary-json\t'"$expected_three_machine_matrix_summary_json"
if [[ "$record_line" != *"$record_matrix_summary_needle"* ]]; then
  echo "record stage missing upstream matrix summary forwarding contract"
  echo "$record_line"
  cat "$CAPTURE"
  cat "$DRY_RUN_LOG"
  exit 1
fi
if [[ "$record_line" == *$'\t--run-matrix\t0'* ]]; then
  echo "dry-run path should not force record stage matrix dedupe (requires real matrix summary)"
  echo "$record_line"
  cat "$CAPTURE"
  cat "$DRY_RUN_LOG"
  exit 1
fi

vpn_rc_resilience_line="$(find_stage_line "$CAPTURE" "vpn_rc_resilience_path")"
if [[ "$vpn_rc_resilience_line" != *$'\t--run-docker-profile-matrix\t0'* ]]; then
  echo "vpn_rc_resilience_path missing --run-docker-profile-matrix 0 dedupe contract"
  echo "$vpn_rc_resilience_line"
  cat "$CAPTURE"
  cat "$DRY_RUN_LOG"
  exit 1
fi
vpn_rc_resilience_docker_summary_needle=$'\t--docker-summary-json\t'"$expected_three_machine_matrix_summary_json"
if [[ "$vpn_rc_resilience_line" != *"$vpn_rc_resilience_docker_summary_needle"* ]]; then
  echo "vpn_rc_resilience_path missing docker summary forwarding contract"
  echo "$vpn_rc_resilience_line"
  cat "$CAPTURE"
  cat "$DRY_RUN_LOG"
  exit 1
fi
vpn_rc_resilience_docker_report_needle=$'\t--docker-report-md\t'"$expected_three_machine_matrix_report_md"
if [[ "$vpn_rc_resilience_line" != *"$vpn_rc_resilience_docker_report_needle"* ]]; then
  echo "vpn_rc_resilience_path missing docker report forwarding contract"
  echo "$vpn_rc_resilience_line"
  cat "$CAPTURE"
  cat "$DRY_RUN_LOG"
  exit 1
fi
if [[ "$vpn_rc_resilience_line" != *$'\t--run-rc-matrix-path\t0'* ]]; then
  echo "vpn_rc_resilience_path missing --run-rc-matrix-path 0 dedupe contract"
  echo "$vpn_rc_resilience_line"
  cat "$CAPTURE"
  cat "$DRY_RUN_LOG"
  exit 1
fi
vpn_rc_resilience_rc_summary_needle=$'\t--rc-summary-json\t'"$expected_vpn_rc_matrix_summary_json"
if [[ "$vpn_rc_resilience_line" != *"$vpn_rc_resilience_rc_summary_needle"* ]]; then
  echo "vpn_rc_resilience_path missing rc summary forwarding contract"
  echo "$vpn_rc_resilience_line"
  cat "$CAPTURE"
  cat "$DRY_RUN_LOG"
  exit 1
fi

if [[ ! -f "$DRY_RUN_SUMMARY_JSON" ]]; then
  echo "missing dry-run summary json: $DRY_RUN_SUMMARY_JSON"
  cat "$DRY_RUN_LOG"
  exit 1
fi

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .schema.id == "ci_phase1_resilience_summary"
  and .schema.major == 1
  and .schema.minor == 0
  and .automation.track == "non_blockchain"
  and .automation.requires_sudo == false
  and .automation.requires_github == false
  and .automation.automatable_without_sudo_or_github == true
  and .inputs.dry_run == true
  and .steps.three_machine_docker_profile_matrix.status == "pass"
  and .steps.profile_compare_docker_matrix.status == "pass"
  and .steps.three_machine_docker_profile_matrix_record.status == "pass"
  and .steps.vpn_rc_matrix_path.status == "pass"
  and .steps.vpn_rc_resilience_path.status == "pass"
  and .inputs.run_session_churn_guard == true
  and .steps.session_churn_guard.enabled == true
  and .steps.session_churn_guard.status == "skip"
  and .steps.session_churn_guard.rc == 0
  and .inputs.run_3hop_runtime_integration == false
  and .steps.three_hop_runtime_integration.enabled == false
  and .steps.three_hop_runtime_integration.status == "skip"
  and .steps.three_hop_runtime_integration.rc == 0
' "$DRY_RUN_SUMMARY_JSON" >/dev/null; then
  echo "dry-run summary missing expected contract fields"
  cat "$DRY_RUN_SUMMARY_JSON"
  exit 1
fi

if ! grep -q '\[ci-phase1-resilience\] step=session_churn_guard status=skip reason=dry-run-not-supported' "$DRY_RUN_LOG"; then
  echo "dry-run log missing session churn guard skip signal"
  cat "$DRY_RUN_LOG"
  exit 1
fi
if ! grep -q '\[ci-phase1-resilience\] step=three_hop_runtime_integration status=skip reason=disabled' "$DRY_RUN_LOG"; then
  echo "dry-run log missing disabled 3hop runtime signal"
  cat "$DRY_RUN_LOG"
  exit 1
fi
if ! grep -q '\[ci-phase1-resilience\] status=pass rc=0 dry_run=1' "$DRY_RUN_LOG"; then
  echo "dry-run log missing final pass status line"
  cat "$DRY_RUN_LOG"
  exit 1
fi

echo "[ci-phase1-resilience] resume mode reuses passing artifact"
resume_matrix_summary_json="$RESUME_REPORTS_DIR/three_machine_docker_profile_matrix/three_machine_docker_profile_matrix_summary.json"
mkdir -p "$(dirname "$resume_matrix_summary_json")"
cat >"$resume_matrix_summary_json" <<'EOF_RESUME_PASS_SUMMARY'
{
  "version": 1,
  "status": "pass",
  "rc": 0
}
EOF_RESUME_PASS_SUMMARY

: >"$CAPTURE"
CI_PHASE1_RESILIENCE_CAPTURE_FILE="$CAPTURE" \
bash "$GATE_SCRIPT" \
  --resume 1 \
  --reports-dir "$RESUME_REPORTS_DIR" \
  --summary-json "$RESUME_SUMMARY_JSON" \
  --print-summary-json 0 \
  --run-three-machine-docker-profile-matrix 1 \
  --run-profile-compare-docker-matrix 0 \
  --run-three-machine-docker-profile-matrix-record 0 \
  --run-vpn-rc-matrix-path 0 \
  --run-vpn-rc-resilience-path 0 \
  --run-session-churn-guard 0 \
  --run-3hop-runtime-integration 0 >"$RESUME_LOG" 2>&1

if [[ -s "$CAPTURE" ]]; then
  echo "resume mode should skip matrix stage when pass artifact exists"
  cat "$CAPTURE"
  cat "$RESUME_LOG"
  exit 1
fi
if [[ ! -f "$RESUME_SUMMARY_JSON" ]]; then
  echo "missing resume summary json: $RESUME_SUMMARY_JSON"
  cat "$RESUME_LOG"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.resume == true
  and .inputs.run_three_machine_docker_profile_matrix == true
  and .steps.three_machine_docker_profile_matrix.enabled == true
  and .steps.three_machine_docker_profile_matrix.status == "pass"
  and .steps.three_machine_docker_profile_matrix.rc == 0
  and .steps.three_machine_docker_profile_matrix.reused_artifact == true
  and .steps.profile_compare_docker_matrix.enabled == false
  and .steps.vpn_rc_matrix_path.enabled == false
  and .steps.vpn_rc_resilience_path.enabled == false
' "$RESUME_SUMMARY_JSON" >/dev/null; then
  echo "resume summary missing expected artifact-reuse contract fields"
  cat "$RESUME_SUMMARY_JSON"
  exit 1
fi
if ! grep -q '\[ci-phase1-resilience\] step=three_machine_docker_profile_matrix status=pass rc=0 reason=resume-artifact-pass' "$RESUME_LOG"; then
  echo "resume log missing artifact-reuse signal"
  cat "$RESUME_LOG"
  exit 1
fi

echo "[ci-phase1-resilience] resume mode ignores non-pass artifact and reruns stage"
resume_fallback_matrix_summary_json="$RESUME_FALLBACK_REPORTS_DIR/three_machine_docker_profile_matrix/three_machine_docker_profile_matrix_summary.json"
mkdir -p "$(dirname "$resume_fallback_matrix_summary_json")"
cat >"$resume_fallback_matrix_summary_json" <<'EOF_RESUME_FAIL_SUMMARY'
{
  "version": 1,
  "status": "fail",
  "rc": 1
}
EOF_RESUME_FAIL_SUMMARY

: >"$CAPTURE"
CI_PHASE1_RESILIENCE_CAPTURE_FILE="$CAPTURE" \
bash "$GATE_SCRIPT" \
  --resume 1 \
  --reports-dir "$RESUME_FALLBACK_REPORTS_DIR" \
  --summary-json "$RESUME_FALLBACK_SUMMARY_JSON" \
  --print-summary-json 0 \
  --run-three-machine-docker-profile-matrix 1 \
  --run-profile-compare-docker-matrix 0 \
  --run-three-machine-docker-profile-matrix-record 0 \
  --run-vpn-rc-matrix-path 0 \
  --run-vpn-rc-resilience-path 0 \
  --run-session-churn-guard 0 \
  --run-3hop-runtime-integration 0 >"$RESUME_FALLBACK_LOG" 2>&1

assert_stage_order "$CAPTURE" "three_machine_docker_profile_matrix"
if [[ ! -f "$RESUME_FALLBACK_SUMMARY_JSON" ]]; then
  echo "missing resume-fallback summary json: $RESUME_FALLBACK_SUMMARY_JSON"
  cat "$RESUME_FALLBACK_LOG"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.resume == true
  and .steps.three_machine_docker_profile_matrix.enabled == true
  and .steps.three_machine_docker_profile_matrix.status == "pass"
  and .steps.three_machine_docker_profile_matrix.rc == 0
  and .steps.three_machine_docker_profile_matrix.reused_artifact == false
' "$RESUME_FALLBACK_SUMMARY_JSON" >/dev/null; then
  echo "resume fallback summary missing expected rerun contract fields"
  cat "$RESUME_FALLBACK_SUMMARY_JSON"
  exit 1
fi

echo "[ci-phase1-resilience] timeout path fails closed and kills stage tree"
: >"$CAPTURE"
rm -f "$TIMEOUT_CHILD_PID_FILE"
set +e
CI_PHASE1_RESILIENCE_CAPTURE_FILE="$CAPTURE" \
CI_PHASE1_RESILIENCE_TIMEOUT_STAGE="vpn_rc_resilience_path" \
CI_PHASE1_RESILIENCE_TIMEOUT_SLEEP_SEC="30" \
CI_PHASE1_RESILIENCE_TIMEOUT_CHILD_SLEEP_SEC="30" \
CI_PHASE1_RESILIENCE_TIMEOUT_CHILD_PID_FILE="$TIMEOUT_CHILD_PID_FILE" \
bash "$GATE_SCRIPT" \
  --reports-dir "$TIMEOUT_REPORTS_DIR" \
  --summary-json "$TIMEOUT_SUMMARY_JSON" \
  --print-summary-json 0 \
  --run-three-machine-docker-profile-matrix 0 \
  --run-profile-compare-docker-matrix 0 \
  --run-three-machine-docker-profile-matrix-record 0 \
  --run-vpn-rc-matrix-path 0 \
  --run-vpn-rc-resilience-path 1 \
  --run-session-churn-guard 0 \
  --run-3hop-runtime-integration 0 \
  --vpn-rc-resilience-path-timeout-sec 1 >"$TIMEOUT_LOG" 2>&1
timeout_rc=$?
set -e

if [[ "$timeout_rc" -ne 124 ]]; then
  echo "expected timeout rc=124, got rc=$timeout_rc"
  cat "$TIMEOUT_LOG"
  exit 1
fi

assert_stage_order "$CAPTURE" "vpn_rc_resilience_path"

if [[ ! -s "$TIMEOUT_CHILD_PID_FILE" ]]; then
  echo "timeout path did not capture child pid"
  cat "$TIMEOUT_LOG"
  exit 1
fi
timeout_child_pid="$(cat "$TIMEOUT_CHILD_PID_FILE" | tr -d '[:space:]')"
if [[ -z "$timeout_child_pid" || ! "$timeout_child_pid" =~ ^[0-9]+$ ]]; then
  echo "timeout child pid file is invalid: $timeout_child_pid"
  cat "$TIMEOUT_LOG"
  exit 1
fi
if ! wait_for_pid_exit "$timeout_child_pid" 80; then
  echo "timeout child process still alive after timeout kill: pid=$timeout_child_pid"
  cat "$TIMEOUT_LOG"
  exit 1
fi

if [[ ! -f "$TIMEOUT_SUMMARY_JSON" ]]; then
  echo "missing timeout summary json: $TIMEOUT_SUMMARY_JSON"
  cat "$TIMEOUT_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 124
  and .inputs.dry_run == false
  and .inputs.run_vpn_rc_resilience_path == true
  and .inputs.vpn_rc_resilience_path_timeout_sec == 1
  and .steps.vpn_rc_resilience_path.enabled == true
  and .steps.vpn_rc_resilience_path.status == "fail"
  and .steps.vpn_rc_resilience_path.rc == 124
  and .steps.vpn_rc_resilience_path.reason == "timeout"
  and .steps.vpn_rc_resilience_path.timed_out == true
  and .steps.vpn_rc_resilience_path.timeout_sec == 1
' "$TIMEOUT_SUMMARY_JSON" >/dev/null; then
  echo "timeout summary missing expected timeout contract fields"
  cat "$TIMEOUT_SUMMARY_JSON"
  exit 1
fi
if ! grep -q '\[ci-phase1-resilience\] step=vpn_rc_resilience_path status=fail rc=124 reason=timeout timeout_sec=1' "$TIMEOUT_LOG"; then
  echo "timeout log missing timeout reason line"
  cat "$TIMEOUT_LOG"
  exit 1
fi
if ! grep -q '\[ci-phase1-resilience\] status=fail rc=124 dry_run=0' "$TIMEOUT_LOG"; then
  echo "timeout log missing final fail status line"
  cat "$TIMEOUT_LOG"
  exit 1
fi

echo "[ci-phase1-resilience] fail path preserves first failing rc and continues stages"
: >"$CAPTURE"
set +e
CI_PHASE1_RESILIENCE_CAPTURE_FILE="$CAPTURE" \
CI_PHASE1_RESILIENCE_FAIL_ON_STAGE="profile_compare_docker_matrix" \
CI_PHASE1_RESILIENCE_FAIL_RC="27" \
bash "$GATE_SCRIPT" \
  --reports-dir "$FAIL_REPORTS_DIR" \
  --summary-json "$FAIL_SUMMARY_JSON" \
  --print-summary-json 0 >"$FAIL_LOG" 2>&1
fail_rc=$?
set -e

if [[ "$fail_rc" -ne 27 ]]; then
  echo "expected fail rc=27, got rc=$fail_rc"
  cat "$FAIL_LOG"
  exit 1
fi

assert_stage_order "$CAPTURE" "${DEFAULT_ENABLED_NON_DRY_STAGE_IDS[@]}"

if ! grep -q '^three_machine_docker_profile_matrix_record' "$CAPTURE"; then
  echo "record stage did not run after profile compare failure"
  cat "$CAPTURE"
  cat "$FAIL_LOG"
  exit 1
fi
record_line_fail="$(find_stage_line "$CAPTURE" "three_machine_docker_profile_matrix_record")"
if [[ "$record_line_fail" != *$'\t--run-matrix\t0'* ]]; then
  echo "non-dry-run record stage missing --run-matrix 0 dedupe contract"
  echo "$record_line_fail"
  cat "$CAPTURE"
  cat "$FAIL_LOG"
  exit 1
fi
record_matrix_summary_needle_fail=$'\t--matrix-summary-json\t'"$FAIL_REPORTS_DIR/three_machine_docker_profile_matrix/three_machine_docker_profile_matrix_summary.json"
if [[ "$record_line_fail" != *"$record_matrix_summary_needle_fail"* ]]; then
  echo "non-dry-run record stage missing upstream matrix summary forwarding contract"
  echo "$record_line_fail"
  cat "$CAPTURE"
  cat "$FAIL_LOG"
  exit 1
fi
if ! grep -q '^vpn_rc_matrix_path' "$CAPTURE"; then
  echo "vpn_rc_matrix_path stage did not run after profile compare failure"
  cat "$CAPTURE"
  cat "$FAIL_LOG"
  exit 1
fi
if ! grep -q '^vpn_rc_resilience_path' "$CAPTURE"; then
  echo "vpn_rc_resilience_path stage did not run after profile compare failure"
  cat "$CAPTURE"
  cat "$FAIL_LOG"
  exit 1
fi
if ! grep -q '^session_churn_guard' "$CAPTURE"; then
  echo "session_churn_guard stage did not run after profile compare failure"
  cat "$CAPTURE"
  cat "$FAIL_LOG"
  exit 1
fi
if grep -q '^three_hop_runtime_integration' "$CAPTURE"; then
  echo "three_hop_runtime_integration should be disabled by default"
  cat "$CAPTURE"
  cat "$FAIL_LOG"
  exit 1
fi

if [[ ! -f "$FAIL_SUMMARY_JSON" ]]; then
  echo "missing fail summary json: $FAIL_SUMMARY_JSON"
  cat "$FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 27
  and .automation.track == "non_blockchain"
  and .automation.requires_sudo == false
  and .automation.requires_github == false
  and .automation.automatable_without_sudo_or_github == true
  and .inputs.dry_run == false
  and .steps.three_machine_docker_profile_matrix.status == "pass"
  and .steps.profile_compare_docker_matrix.status == "fail"
  and .steps.profile_compare_docker_matrix.rc == 27
  and .steps.three_machine_docker_profile_matrix_record.status == "pass"
  and .steps.vpn_rc_matrix_path.status == "pass"
  and .steps.vpn_rc_resilience_path.status == "pass"
  and .inputs.run_session_churn_guard == true
  and .steps.session_churn_guard.enabled == true
  and .steps.session_churn_guard.status == "pass"
  and .steps.session_churn_guard.rc == 0
  and .inputs.run_3hop_runtime_integration == false
  and .steps.three_hop_runtime_integration.enabled == false
  and .steps.three_hop_runtime_integration.status == "skip"
  and .steps.three_hop_runtime_integration.rc == 0
' "$FAIL_SUMMARY_JSON" >/dev/null; then
  echo "fail summary missing expected contract fields"
  cat "$FAIL_SUMMARY_JSON"
  exit 1
fi

if ! grep -q '\[ci-phase1-resilience\] status=fail rc=27 dry_run=0' "$FAIL_LOG"; then
  echo "fail log missing final fail status line"
  cat "$FAIL_LOG"
  exit 1
fi

echo "[ci-phase1-resilience] policy_no_go default path remains fail-closed"
: >"$CAPTURE"
set +e
CI_PHASE1_RESILIENCE_CAPTURE_FILE="$CAPTURE" \
CI_PHASE1_RESILIENCE_FAIL_ON_STAGE="vpn_rc_matrix_path" \
CI_PHASE1_RESILIENCE_FAIL_RC="31" \
CI_PHASE1_RESILIENCE_POLICY_NO_GO_STAGE="vpn_rc_matrix_path" \
CI_PHASE1_RESILIENCE_POLICY_NO_GO_RC="31" \
bash "$GATE_SCRIPT" \
  --reports-dir "$POLICY_NO_GO_FAIL_CLOSED_REPORTS_DIR" \
  --summary-json "$POLICY_NO_GO_FAIL_CLOSED_SUMMARY_JSON" \
  --print-summary-json 0 \
  --run-three-machine-docker-profile-matrix 0 \
  --run-profile-compare-docker-matrix 0 \
  --run-three-machine-docker-profile-matrix-record 0 \
  --run-vpn-rc-matrix-path 1 \
  --run-vpn-rc-resilience-path 0 \
  --run-session-churn-guard 0 \
  --run-3hop-runtime-integration 0 >"$POLICY_NO_GO_FAIL_CLOSED_LOG" 2>&1
policy_no_go_fail_closed_rc=$?
set -e

if [[ "$policy_no_go_fail_closed_rc" -ne 31 ]]; then
  echo "expected policy_no_go fail-closed rc=31, got rc=$policy_no_go_fail_closed_rc"
  cat "$POLICY_NO_GO_FAIL_CLOSED_LOG"
  exit 1
fi

assert_stage_order "$CAPTURE" "vpn_rc_matrix_path"

if [[ ! -f "$POLICY_NO_GO_FAIL_CLOSED_SUMMARY_JSON" ]]; then
  echo "missing policy_no_go fail-closed summary json: $POLICY_NO_GO_FAIL_CLOSED_SUMMARY_JSON"
  cat "$POLICY_NO_GO_FAIL_CLOSED_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 31
  and .failure.kind == "policy_no_go"
  and .failure.policy_no_go == true
  and .policy_outcome.fail_closed_no_go == true
  and .steps.vpn_rc_matrix_path.status == "fail"
  and .steps.vpn_rc_matrix_path.rc == 31
  and .steps.vpn_rc_matrix_path.failure_semantics.kind == "policy_no_go"
' "$POLICY_NO_GO_FAIL_CLOSED_SUMMARY_JSON" >/dev/null; then
  echo "policy_no_go fail-closed summary missing expected contract fields"
  cat "$POLICY_NO_GO_FAIL_CLOSED_SUMMARY_JSON"
  exit 1
fi

if ! grep -q '\[ci-phase1-resilience\] status=fail rc=31 dry_run=0' "$POLICY_NO_GO_FAIL_CLOSED_LOG"; then
  echo "policy_no_go fail-closed log missing final fail status line"
  cat "$POLICY_NO_GO_FAIL_CLOSED_LOG"
  exit 1
fi

echo "[ci-phase1-resilience] --allow-policy-no-go enables warn+rc0 without hiding policy semantics"
: >"$CAPTURE"
CI_PHASE1_RESILIENCE_CAPTURE_FILE="$CAPTURE" \
CI_PHASE1_RESILIENCE_FAIL_ON_STAGE="vpn_rc_matrix_path" \
CI_PHASE1_RESILIENCE_FAIL_RC="31" \
CI_PHASE1_RESILIENCE_POLICY_NO_GO_STAGE="vpn_rc_matrix_path" \
CI_PHASE1_RESILIENCE_POLICY_NO_GO_RC="31" \
bash "$GATE_SCRIPT" \
  --reports-dir "$POLICY_NO_GO_ALLOWED_REPORTS_DIR" \
  --summary-json "$POLICY_NO_GO_ALLOWED_SUMMARY_JSON" \
  --print-summary-json 0 \
  --allow-policy-no-go 1 \
  --run-three-machine-docker-profile-matrix 0 \
  --run-profile-compare-docker-matrix 0 \
  --run-three-machine-docker-profile-matrix-record 0 \
  --run-vpn-rc-matrix-path 1 \
  --run-vpn-rc-resilience-path 0 \
  --run-session-churn-guard 0 \
  --run-3hop-runtime-integration 0 >"$POLICY_NO_GO_ALLOWED_LOG" 2>&1

assert_stage_order "$CAPTURE" "vpn_rc_matrix_path"

if [[ ! -f "$POLICY_NO_GO_ALLOWED_SUMMARY_JSON" ]]; then
  echo "missing policy_no_go allow summary json: $POLICY_NO_GO_ALLOWED_SUMMARY_JSON"
  cat "$POLICY_NO_GO_ALLOWED_LOG"
  exit 1
fi
if ! jq -e '
  .status == "warn"
  and .rc == 0
  and ((.inputs.allow_policy_no_go // false) == true)
  and .failure.kind == "policy_no_go"
  and .failure.policy_no_go == true
  and .policy_outcome.fail_closed_no_go == false
  and .steps.vpn_rc_matrix_path.status == "fail"
  and .steps.vpn_rc_matrix_path.rc == 31
  and .steps.vpn_rc_matrix_path.failure_semantics.kind == "policy_no_go"
' "$POLICY_NO_GO_ALLOWED_SUMMARY_JSON" >/dev/null; then
  echo "policy_no_go allow summary missing expected warn contract fields"
  cat "$POLICY_NO_GO_ALLOWED_SUMMARY_JSON"
  exit 1
fi

if ! grep -q '\[ci-phase1-resilience\] status=warn rc=0 dry_run=0' "$POLICY_NO_GO_ALLOWED_LOG"; then
  echo "policy_no_go allow log missing final warn status line"
  cat "$POLICY_NO_GO_ALLOWED_LOG"
  exit 1
fi

echo "[ci-phase1-resilience] optional 3hop runtime stage toggle"
: >"$CAPTURE"
CI_PHASE1_RESILIENCE_CAPTURE_FILE="$CAPTURE" \
bash "$GATE_SCRIPT" \
  --reports-dir "$THREE_HOP_ONLY_REPORTS_DIR" \
  --summary-json "$THREE_HOP_ONLY_SUMMARY_JSON" \
  --print-summary-json 0 \
  --run-three-machine-docker-profile-matrix 0 \
  --run-profile-compare-docker-matrix 0 \
  --run-three-machine-docker-profile-matrix-record 0 \
  --run-vpn-rc-matrix-path 0 \
  --run-vpn-rc-resilience-path 0 \
  --run-session-churn-guard 0 \
  --run-3hop-runtime-integration 1 >"$THREE_HOP_ONLY_LOG" 2>&1

assert_stage_order "$CAPTURE" "three_hop_runtime_integration"

if [[ ! -f "$THREE_HOP_ONLY_SUMMARY_JSON" ]]; then
  echo "missing three-hop-only summary json: $THREE_HOP_ONLY_SUMMARY_JSON"
  cat "$THREE_HOP_ONLY_LOG"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.dry_run == false
  and .inputs.run_session_churn_guard == false
  and .inputs.run_3hop_runtime_integration == true
  and .steps.session_churn_guard.enabled == false
  and .steps.session_churn_guard.status == "skip"
  and .steps.three_hop_runtime_integration.enabled == true
  and .steps.three_hop_runtime_integration.status == "pass"
  and .steps.three_hop_runtime_integration.rc == 0
' "$THREE_HOP_ONLY_SUMMARY_JSON" >/dev/null; then
  echo "three-hop-only summary missing expected toggle fields"
  cat "$THREE_HOP_ONLY_SUMMARY_JSON"
  exit 1
fi

echo "ci phase1 resilience integration check ok"
