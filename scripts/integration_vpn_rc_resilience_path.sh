#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq mktemp chmod awk sed grep bash; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

CHAIN_SCRIPT="${VPN_RC_RESILIENCE_PATH_UNDER_TEST_SCRIPT:-$ROOT_DIR/scripts/vpn_rc_resilience_path.sh}"
if [[ ! -f "$CHAIN_SCRIPT" ]]; then
  echo "missing chain script under test: $CHAIN_SCRIPT"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.tsv"
SUCCESS_LOG="$TMP_DIR/success.log"
TIMEOUT_LOG="$TMP_DIR/timeout.log"
FAIL_STAGE1_LOG="$TMP_DIR/fail_stage1.log"
FAIL_STAGE2_LOG="$TMP_DIR/fail_stage2.log"
ALIAS_LOG="$TMP_DIR/alias.log"
ROADMAP_COMPAT_LOG="$TMP_DIR/roadmap_compat.log"
DISABLED_ARTIFACT_LOG="$TMP_DIR/disabled_artifact.log"
SIGNOFF_NO_GO_LOG="$TMP_DIR/signoff_no_go.log"
TIMEOUT_CHILD_PID_FILE="$TMP_DIR/timeout_child.pid"

FORWARD_CAPTURE="$TMP_DIR/forward_capture.tsv"
FORWARD_LOG="$TMP_DIR/forward.log"

REPORTS_DIR="$TMP_DIR/reports"
FINAL_SUMMARY_JSON="$TMP_DIR/final_summary.json"
mkdir -p "$REPORTS_DIR"

mapfile -t STAGE_ENV_VARS < <(awk '
  {
    line = $0
    while (match(line, /VPN_RC_RESILIENCE_PATH_[A-Z0-9_]+_SCRIPT/)) {
      key = substr(line, RSTART, RLENGTH)
      if (!(key in seen)) {
        seen[key] = 1
        print key
      }
      line = substr(line, RSTART + RLENGTH)
    }
  }
' "$CHAIN_SCRIPT")

if [[ "${#STAGE_ENV_VARS[@]}" -eq 0 ]]; then
  echo "no stage override env vars found in chain script: $CHAIN_SCRIPT"
  echo "expected at least one VPN_RC_RESILIENCE_PATH_*_SCRIPT variable"
  exit 1
fi

FAKE_STAGE_TEMPLATE="$TMP_DIR/fake_stage_template.sh"
cat >"$FAKE_STAGE_TEMPLATE" <<'EOF_FAKE_STAGE_TEMPLATE'
#!/usr/bin/env bash
set -euo pipefail

capture_file="${VPN_RC_RESILIENCE_CAPTURE_FILE:?}"
stage_id="${VPN_RC_RESILIENCE_STAGE_ID:?}"

{
  printf '%s' "$stage_id"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"

write_json_file() {
  local path="$1"
  mkdir -p "$(dirname "$path")"
  cat >"$path" <<'EOF_JSON'
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "final_rc": 0,
  "decision": {
    "decision": "GO"
  },
  "summary": {
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "next_action_check_id": "machine_c_vpn_smoke",
    "next_action_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY"
  },
  "vpn_track": {
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "readiness_status": "NOT_READY",
    "next_action": {
      "command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_JSON
}

write_markdown_file() {
  local path="$1"
  mkdir -p "$(dirname "$path")"
  printf '# fake stage report\n' >"$path"
}

is_path_flag() {
  local flag="$1"
  case "$flag" in
    --summary-json|--report-md|--matrix-summary-json|--matrix-report-md|--signoff-summary-json|--roadmap-summary-json|--roadmap-report-md|--campaign-summary-json|--campaign-report-md|--profile-compare-signoff-summary-json|--single-machine-summary-json|--manual-validation-summary-json|--manual-validation-report-md|--rehearsal-summary-json)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

args=("$@")
for (( i=0; i < ${#args[@]}; i++ )); do
  arg="${args[$i]}"
  if [[ "$arg" == "--reports-dir" ]]; then
    value="${args[$((i + 1))]:-}"
    if [[ -n "$value" ]]; then
      mkdir -p "$value"
    fi
    continue
  fi
  if is_path_flag "$arg"; then
    value="${args[$((i + 1))]:-}"
    if [[ -z "$value" ]]; then
      continue
    fi
    case "$arg" in
      *report-md)
        write_markdown_file "$value"
        ;;
      *)
        write_json_file "$value"
        ;;
    esac
  fi
done

if [[ "${VPN_RC_RESILIENCE_TIMEOUT_STAGE:-}" == "$stage_id" ]]; then
  sleep "${VPN_RC_RESILIENCE_TIMEOUT_CHILD_SLEEP_SEC:-60}" &
  timeout_child_pid=$!
  if [[ -n "${VPN_RC_RESILIENCE_TIMEOUT_CHILD_PID_FILE:-}" ]]; then
    printf '%s\n' "$timeout_child_pid" >"${VPN_RC_RESILIENCE_TIMEOUT_CHILD_PID_FILE}"
  fi
  sleep "${VPN_RC_RESILIENCE_TIMEOUT_SLEEP_SEC:-60}"
fi

if [[ "${VPN_RC_RESILIENCE_FAIL_ON_STAGE:-}" == "$stage_id" ]]; then
  exit "${VPN_RC_RESILIENCE_FAIL_RC:-1}"
fi

exit 0
EOF_FAKE_STAGE_TEMPLATE
chmod +x "$FAKE_STAGE_TEMPLATE"

declare -a STAGE_IDS=()
rc_stage_env_var=""
rc_stage_id=""
for idx in "${!STAGE_ENV_VARS[@]}"; do
  env_name="${STAGE_ENV_VARS[$idx]}"
  stage_id="$(printf '%02d_%s' "$((idx + 1))" "$(printf '%s' "$env_name" | tr '[:upper:]' '[:lower:]')")"
  STAGE_IDS+=("$stage_id")
  if [[ "$env_name" == *"RC_MATRIX_PATH_SCRIPT" ]]; then
    rc_stage_env_var="$env_name"
    rc_stage_id="$stage_id"
  fi
  fake_stage="$TMP_DIR/fake_stage_${idx}.sh"
  cat >"$fake_stage" <<EOF_FAKE_STAGE
#!/usr/bin/env bash
set -euo pipefail
VPN_RC_RESILIENCE_CAPTURE_FILE="\${VPN_RC_RESILIENCE_CAPTURE_FILE:?}" \
VPN_RC_RESILIENCE_STAGE_ID="$stage_id" \
VPN_RC_RESILIENCE_FAIL_ON_STAGE="\${VPN_RC_RESILIENCE_FAIL_ON_STAGE:-}" \
VPN_RC_RESILIENCE_FAIL_RC="\${VPN_RC_RESILIENCE_FAIL_RC:-1}" \
VPN_RC_RESILIENCE_TIMEOUT_STAGE="\${VPN_RC_RESILIENCE_TIMEOUT_STAGE:-}" \
VPN_RC_RESILIENCE_TIMEOUT_SLEEP_SEC="\${VPN_RC_RESILIENCE_TIMEOUT_SLEEP_SEC:-60}" \
VPN_RC_RESILIENCE_TIMEOUT_CHILD_SLEEP_SEC="\${VPN_RC_RESILIENCE_TIMEOUT_CHILD_SLEEP_SEC:-60}" \
VPN_RC_RESILIENCE_TIMEOUT_CHILD_PID_FILE="\${VPN_RC_RESILIENCE_TIMEOUT_CHILD_PID_FILE:-}" \
"$FAKE_STAGE_TEMPLATE" "\$@"
EOF_FAKE_STAGE
  chmod +x "$fake_stage"
  export "$env_name=$fake_stage"
done

if [[ -z "$rc_stage_env_var" && "${#STAGE_ENV_VARS[@]}" -gt 1 ]]; then
  rc_stage_env_var="${STAGE_ENV_VARS[1]}"
  rc_stage_id="${STAGE_IDS[1]}"
fi

script_has_flag() {
  local flag="$1"
  grep -F -- "$flag" "$CHAIN_SCRIPT" >/dev/null 2>&1
}

assert_capture_order() {
  local capture_file="$1"
  local expected_count="${#STAGE_IDS[@]}"
  local idx

  for idx in "${!STAGE_IDS[@]}"; do
    local line_number="$((idx + 1))"
    local expected_stage="${STAGE_IDS[$idx]}"
    local line
    line="$(sed -n "${line_number}p" "$capture_file" || true)"
    if [[ -z "$line" ]]; then
      echo "missing stage invocation at position $line_number (expected $expected_stage)"
      cat "$capture_file"
      exit 1
    fi
    local actual_stage="${line%%$'\t'*}"
    if [[ "$actual_stage" != "$expected_stage" ]]; then
      echo "stage order mismatch at position $line_number (expected $expected_stage, got $actual_stage)"
      cat "$capture_file"
      exit 1
    fi
  done

  local line_count
  line_count="$(wc -l <"$capture_file" | tr -d ' ')"
  if [[ "$line_count" -lt "$expected_count" ]]; then
    echo "capture has too few stage invocations (expected at least $expected_count, got $line_count)"
    cat "$capture_file"
    exit 1
  fi
}

assert_contains_token() {
  local haystack_file="$1"
  local token="$2"
  local message="$3"
  if ! grep -F -- "$token" "$haystack_file" >/dev/null 2>&1; then
    echo "$message"
    cat "$haystack_file"
    exit 1
  fi
}

capture_line_for_stage() {
  local capture_file="$1"
  local stage_id="$2"
  grep -E "^${stage_id}([[:space:]]|$)" "$capture_file" | tail -n 1 || true
}

assert_handoff_contract() {
  local summary_file="$1"
  if ! jq -e '
    (.profile_matrix_stable | type) == "boolean"
    and (.peer_loss_recovery_ok | type) == "boolean"
    and (.session_churn_guard_ok | type) == "boolean"
    and (.resilience_handoff | type) == "object"
    and (.resilience_handoff.profile_matrix_stable == .profile_matrix_stable)
    and (.resilience_handoff.peer_loss_recovery_ok == .peer_loss_recovery_ok)
    and (.resilience_handoff.session_churn_guard_ok == .session_churn_guard_ok)
  ' "$summary_file" >/dev/null 2>&1; then
    echo "missing or invalid resilience handoff booleans in summary"
    cat "$summary_file"
    exit 1
  fi
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

declare -a BASE_ARGS=()
if script_has_flag '--reports-dir'; then
  BASE_ARGS+=(--reports-dir "$REPORTS_DIR")
fi
if script_has_flag '--summary-json'; then
  BASE_ARGS+=(--summary-json "$FINAL_SUMMARY_JSON")
fi

declare -a SUCCESS_ARGS=("${BASE_ARGS[@]}")
if script_has_flag '--print-report'; then
  SUCCESS_ARGS+=(--print-report 0)
fi
if script_has_flag '--print-summary-json'; then
  SUCCESS_ARGS+=(--print-summary-json 1)
fi

declare -a QUIET_ARGS=("${BASE_ARGS[@]}")
if script_has_flag '--print-report'; then
  QUIET_ARGS+=(--print-report 0)
fi
if script_has_flag '--print-summary-json'; then
  QUIET_ARGS+=(--print-summary-json 0)
fi

echo "[vpn-rc-resilience-path] success path"
: >"$CAPTURE"
VPN_RC_RESILIENCE_CAPTURE_FILE="$CAPTURE" \
bash "$CHAIN_SCRIPT" "${SUCCESS_ARGS[@]}" >"$SUCCESS_LOG" 2>&1

assert_capture_order "$CAPTURE"

if script_has_flag '--reports-dir'; then
  assert_contains_token "$CAPTURE" "$REPORTS_DIR" "stage forwarding missing reports-dir path"
fi
if script_has_flag '--print-summary-json'; then
  assert_contains_token "$CAPTURE" '--print-summary-json' "stage forwarding missing --print-summary-json"
fi

if [[ ! -f "$FINAL_SUMMARY_JSON" ]]; then
  echo "success path missing final summary json"
  cat "$SUCCESS_LOG"
  exit 1
fi
assert_handoff_contract "$FINAL_SUMMARY_JSON"
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .profile_matrix_stable == true
  and .peer_loss_recovery_ok == true
  and .session_churn_guard_ok == true
' "$FINAL_SUMMARY_JSON" >/dev/null 2>&1; then
  echo "success path summary contract mismatch"
  cat "$FINAL_SUMMARY_JSON"
  exit 1
fi

if [[ -n "$rc_stage_id" ]] \
  && script_has_flag '--run-docker-profile-matrix' \
  && script_has_flag '--run-rc-matrix-path'; then
  echo "[vpn-rc-resilience-path] rc alias forwarding path"
  : >"$CAPTURE"
  declare -a ALIAS_ARGS=("${QUIET_ARGS[@]}")
  ALIAS_ARGS+=(
    --run-docker-profile-matrix 0
    --run-rc-matrix-path 1
    --rc-refresh-manual-validation 1
    --rc-refresh-single-machine-readiness 0
  )
  VPN_RC_RESILIENCE_CAPTURE_FILE="$CAPTURE" \
  bash "$CHAIN_SCRIPT" "${ALIAS_ARGS[@]}" >"$ALIAS_LOG" 2>&1

  rc_alias_line="$(capture_line_for_stage "$CAPTURE" "$rc_stage_id")"
  if [[ -z "$rc_alias_line" ]]; then
    echo "alias path missing rc-stage invocation capture"
    cat "$CAPTURE"
    cat "$ALIAS_LOG"
    exit 1
  fi
  if [[ "$rc_alias_line" != *$'\t--roadmap-refresh-manual-validation\t1'* ]]; then
    echo "alias forwarding missing canonical roadmap manual-validation arg"
    cat "$CAPTURE"
    cat "$ALIAS_LOG"
    exit 1
  fi
  if [[ "$rc_alias_line" != *$'\t--roadmap-refresh-single-machine-readiness\t0'* ]]; then
    echo "alias forwarding missing canonical roadmap single-machine-readiness arg"
    cat "$CAPTURE"
    cat "$ALIAS_LOG"
    exit 1
  fi
  if [[ "$rc_alias_line" == *$'\t--refresh-manual-validation\t'* ]]; then
    echo "alias forwarding leaked non-canonical --refresh-manual-validation arg"
    cat "$CAPTURE"
    cat "$ALIAS_LOG"
    exit 1
  fi
  if [[ "$rc_alias_line" == *$'\t--refresh-single-machine-readiness\t'* ]]; then
    echo "alias forwarding leaked non-canonical --refresh-single-machine-readiness arg"
    cat "$CAPTURE"
    cat "$ALIAS_LOG"
    exit 1
  fi

  echo "[vpn-rc-resilience-path] rc roadmap-prefixed compatibility path"
  : >"$CAPTURE"
  declare -a ROADMAP_COMPAT_ARGS=("${QUIET_ARGS[@]}")
  ROADMAP_COMPAT_ARGS+=(
    --run-docker-profile-matrix 0
    --run-rc-matrix-path 1
    --rc-roadmap-refresh-manual-validation 0
    --rc-roadmap-refresh-single-machine-readiness 1
  )
  VPN_RC_RESILIENCE_CAPTURE_FILE="$CAPTURE" \
  bash "$CHAIN_SCRIPT" "${ROADMAP_COMPAT_ARGS[@]}" >"$ROADMAP_COMPAT_LOG" 2>&1

  rc_roadmap_line="$(capture_line_for_stage "$CAPTURE" "$rc_stage_id")"
  if [[ -z "$rc_roadmap_line" ]]; then
    echo "roadmap-prefixed compatibility path missing rc-stage invocation capture"
    cat "$CAPTURE"
    cat "$ROADMAP_COMPAT_LOG"
    exit 1
  fi
  if [[ "$rc_roadmap_line" != *$'\t--roadmap-refresh-manual-validation\t0'* ]]; then
    echo "roadmap-prefixed compatibility path missing manual-validation arg"
    cat "$CAPTURE"
    cat "$ROADMAP_COMPAT_LOG"
    exit 1
  fi
  if [[ "$rc_roadmap_line" != *$'\t--roadmap-refresh-single-machine-readiness\t1'* ]]; then
    echo "roadmap-prefixed compatibility path missing single-machine-readiness arg"
    cat "$CAPTURE"
    cat "$ROADMAP_COMPAT_LOG"
    exit 1
  fi
else
  echo "[vpn-rc-resilience-path] rc alias forwarding path unavailable; script lacks rc stage or run-* flags"
fi

if script_has_flag '--run-docker-profile-matrix' \
  && script_has_flag '--run-rc-matrix-path' \
  && script_has_flag '--docker-summary-json' \
  && script_has_flag '--rc-summary-json'; then
  echo "[vpn-rc-resilience-path] disabled stages derive from provided artifacts"
  DISABLED_DOCKER_SUMMARY_JSON="$TMP_DIR/disabled_docker_summary.json"
  DISABLED_RC_SUMMARY_JSON="$TMP_DIR/disabled_rc_summary.json"
  cat >"$DISABLED_DOCKER_SUMMARY_JSON" <<'EOF_DISABLED_DOCKER_SUMMARY_JSON'
{
  "version": 1,
  "resilience": {
    "profile_matrix_stable": true,
    "peer_loss_recovery_ok": true
  },
  "inputs": {
    "run_peer_failover": true
  }
}
EOF_DISABLED_DOCKER_SUMMARY_JSON
  cat >"$DISABLED_RC_SUMMARY_JSON" <<'EOF_DISABLED_RC_SUMMARY_JSON'
{
  "version": 1,
  "resilience": {
    "session_churn_guard_ok": true
  }
}
EOF_DISABLED_RC_SUMMARY_JSON

  : >"$CAPTURE"
  declare -a DISABLED_ARTIFACT_ARGS=("${QUIET_ARGS[@]}")
  DISABLED_ARTIFACT_ARGS+=(
    --run-docker-profile-matrix 0
    --run-rc-matrix-path 0
    --docker-summary-json "$DISABLED_DOCKER_SUMMARY_JSON"
    --rc-summary-json "$DISABLED_RC_SUMMARY_JSON"
  )
  VPN_RC_RESILIENCE_CAPTURE_FILE="$CAPTURE" \
  bash "$CHAIN_SCRIPT" "${DISABLED_ARTIFACT_ARGS[@]}" >"$DISABLED_ARTIFACT_LOG" 2>&1

  if [[ -s "$CAPTURE" ]]; then
    echo "disabled artifact path should not invoke docker/rc stages when both are disabled"
    cat "$CAPTURE"
    cat "$DISABLED_ARTIFACT_LOG"
    exit 1
  fi
  if [[ ! -f "$FINAL_SUMMARY_JSON" ]]; then
    echo "disabled artifact path missing final summary json"
    cat "$DISABLED_ARTIFACT_LOG"
    exit 1
  fi
  assert_handoff_contract "$FINAL_SUMMARY_JSON"
  if ! jq -e '
    .status == "pass"
    and .rc == 0
    and .inputs.run_docker_profile_matrix == false
    and .inputs.run_rc_matrix_path == false
    and .profile_matrix_stable == true
    and .peer_loss_recovery_ok == true
    and .session_churn_guard_ok == true
    and .resilience_handoff.derivation.profile_matrix_stable == "docker_summary.resilience.profile_matrix_stable"
    and .resilience_handoff.derivation.peer_loss_recovery_ok == "docker_summary.resilience.peer_loss_recovery_ok"
    and .resilience_handoff.derivation.session_churn_guard_ok == "rc_summary.resilience.session_churn_guard_ok"
    and .steps.three_machine_docker_profile_matrix.status == "skip"
    and .steps.vpn_rc_matrix_path.status == "skip"
  ' "$FINAL_SUMMARY_JSON" >/dev/null 2>&1; then
    echo "disabled artifact path summary contract mismatch"
    cat "$FINAL_SUMMARY_JSON"
    exit 1
  fi
else
  echo "[vpn-rc-resilience-path] disabled artifact derivation path unavailable; script lacks flags"
fi

if script_has_flag '--docker-profile-matrix-timeout-sec'; then
  echo "[vpn-rc-resilience-path] timeout contract path"
  : >"$CAPTURE"
  rm -f "$TIMEOUT_CHILD_PID_FILE"
  declare -a TIMEOUT_ARGS=("${QUIET_ARGS[@]}")
  if script_has_flag '--run-docker-profile-matrix'; then
    TIMEOUT_ARGS+=(--run-docker-profile-matrix 1)
  fi
  if script_has_flag '--run-rc-matrix-path'; then
    TIMEOUT_ARGS+=(--run-rc-matrix-path 0)
  fi
  TIMEOUT_ARGS+=(--docker-profile-matrix-timeout-sec 1)

  set +e
  VPN_RC_RESILIENCE_CAPTURE_FILE="$CAPTURE" \
  VPN_RC_RESILIENCE_TIMEOUT_STAGE="${STAGE_IDS[0]}" \
  VPN_RC_RESILIENCE_TIMEOUT_SLEEP_SEC="30" \
  VPN_RC_RESILIENCE_TIMEOUT_CHILD_SLEEP_SEC="30" \
  VPN_RC_RESILIENCE_TIMEOUT_CHILD_PID_FILE="$TIMEOUT_CHILD_PID_FILE" \
  bash "$CHAIN_SCRIPT" "${TIMEOUT_ARGS[@]}" >"$TIMEOUT_LOG" 2>&1
  timeout_rc=$?
  set -e

  if [[ "$timeout_rc" -ne 124 ]]; then
    echo "expected timeout rc=124, got rc=$timeout_rc"
    cat "$TIMEOUT_LOG"
    exit 1
  fi
  if ! grep -E -q "^${STAGE_IDS[0]}([[:space:]]|$)" "$CAPTURE"; then
    echo "timeout path missing stage invocation for ${STAGE_IDS[0]}"
    cat "$CAPTURE"
    cat "$TIMEOUT_LOG"
    exit 1
  fi
  if [[ "${#STAGE_IDS[@]}" -gt 1 ]] && grep -E -q "^${STAGE_IDS[1]}([[:space:]]|$)" "$CAPTURE"; then
    echo "timeout path should not run stage ${STAGE_IDS[1]} when rc stage disabled"
    cat "$CAPTURE"
    cat "$TIMEOUT_LOG"
    exit 1
  fi
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
  if [[ ! -f "$FINAL_SUMMARY_JSON" ]]; then
    echo "timeout path missing final summary json"
    cat "$TIMEOUT_LOG"
    exit 1
  fi
  assert_handoff_contract "$FINAL_SUMMARY_JSON"
  if ! jq -e '
    .status == "fail"
    and .rc == 124
    and .inputs.docker_profile_matrix_timeout_sec == 1
    and .steps.three_machine_docker_profile_matrix.status == "fail"
    and .steps.three_machine_docker_profile_matrix.rc == 124
    and .steps.three_machine_docker_profile_matrix.reason == "timeout"
    and .steps.three_machine_docker_profile_matrix.timed_out == true
    and .steps.three_machine_docker_profile_matrix.timeout_sec == 1
    and .profile_matrix_stable == false
    and .peer_loss_recovery_ok == false
  ' "$FINAL_SUMMARY_JSON" >/dev/null 2>&1; then
    echo "timeout path summary contract mismatch"
    cat "$FINAL_SUMMARY_JSON"
    exit 1
  fi
  if ! grep -q '\[vpn-rc-resilience-path\] step=three_machine_docker_profile_matrix status=fail rc=124 reason=timeout timeout_sec=1' "$TIMEOUT_LOG"; then
    echo "timeout log missing timeout reason line"
    cat "$TIMEOUT_LOG"
    exit 1
  fi
else
  echo "[vpn-rc-resilience-path] timeout contract path unavailable; script lacks timeout flag"
fi

echo "[vpn-rc-resilience-path] fail path"
: >"$CAPTURE"
set +e
VPN_RC_RESILIENCE_CAPTURE_FILE="$CAPTURE" \
VPN_RC_RESILIENCE_FAIL_ON_STAGE="${STAGE_IDS[0]}" \
VPN_RC_RESILIENCE_FAIL_RC=23 \
bash "$CHAIN_SCRIPT" "${QUIET_ARGS[@]}" >"$FAIL_STAGE1_LOG" 2>&1
fail_stage1_rc=$?
set -e
if [[ "$fail_stage1_rc" -eq 0 ]]; then
  echo "expected non-zero rc when stage ${STAGE_IDS[0]} fails"
  cat "$FAIL_STAGE1_LOG"
  exit 1
fi

continue_after_failure=0
if [[ "${#STAGE_IDS[@]}" -gt 1 ]]; then
  if grep -E -q "^${STAGE_IDS[1]}([[:space:]]|$)" "$CAPTURE"; then
    continue_after_failure=1
  fi
fi
if [[ ! -f "$FINAL_SUMMARY_JSON" ]]; then
  echo "stage-1 failure path missing final summary json"
  cat "$FAIL_STAGE1_LOG"
  exit 1
fi
assert_handoff_contract "$FINAL_SUMMARY_JSON"
expected_session_churn_stage1_fail="false"
if [[ "$continue_after_failure" -eq 1 ]]; then
  expected_session_churn_stage1_fail="true"
fi
if ! jq -e --argjson expected_rc "$fail_stage1_rc" --argjson expected_session "$expected_session_churn_stage1_fail" '
  .status == "fail"
  and .rc == $expected_rc
  and .profile_matrix_stable == false
  and .peer_loss_recovery_ok == false
  and .session_churn_guard_ok == $expected_session
' "$FINAL_SUMMARY_JSON" >/dev/null 2>&1; then
  echo "stage-1 failure summary contract mismatch"
  cat "$FINAL_SUMMARY_JSON"
  exit 1
fi

if [[ "${#STAGE_IDS[@]}" -gt 1 ]]; then
  : >"$CAPTURE"
  set +e
  VPN_RC_RESILIENCE_CAPTURE_FILE="$CAPTURE" \
  VPN_RC_RESILIENCE_FAIL_ON_STAGE="${STAGE_IDS[1]}" \
  VPN_RC_RESILIENCE_FAIL_RC=29 \
  bash "$CHAIN_SCRIPT" "${QUIET_ARGS[@]}" >"$FAIL_STAGE2_LOG" 2>&1
  fail_stage2_rc=$?
  set -e
  if [[ "$fail_stage2_rc" -eq 0 ]]; then
    echo "expected non-zero rc when stage ${STAGE_IDS[1]} fails"
    cat "$FAIL_STAGE2_LOG"
    exit 1
  fi

  if [[ "${#STAGE_IDS[@]}" -gt 2 ]]; then
    stage3_ran=0
    if grep -E -q "^${STAGE_IDS[2]}([[:space:]]|$)" "$CAPTURE"; then
      stage3_ran=1
    fi
    if [[ "$continue_after_failure" -eq 1 && "$stage3_ran" -ne 1 ]]; then
      echo "later-stage contract mismatch: script continues after failure but stage 3 did not run"
      cat "$CAPTURE"
      cat "$FAIL_STAGE2_LOG"
      exit 1
    fi
    if [[ "$continue_after_failure" -eq 0 && "$stage3_ran" -ne 0 ]]; then
      echo "later-stage contract mismatch: script stops after failure but stage 3 ran"
      cat "$CAPTURE"
      cat "$FAIL_STAGE2_LOG"
      exit 1
    fi
  fi

  if [[ ! -f "$FINAL_SUMMARY_JSON" ]]; then
    echo "stage-2 failure path missing final summary json"
    cat "$FAIL_STAGE2_LOG"
    exit 1
  fi
  assert_handoff_contract "$FINAL_SUMMARY_JSON"
  if ! jq -e --argjson expected_rc "$fail_stage2_rc" '
    .status == "fail"
    and .rc == $expected_rc
    and .profile_matrix_stable == true
    and .peer_loss_recovery_ok == true
    and .session_churn_guard_ok == false
  ' "$FINAL_SUMMARY_JSON" >/dev/null 2>&1; then
    echo "stage-2 failure summary contract mismatch"
    cat "$FINAL_SUMMARY_JSON"
    exit 1
  fi
fi

if [[ -n "$rc_stage_env_var" && -n "$rc_stage_id" ]] \
  && script_has_flag '--run-docker-profile-matrix' \
  && script_has_flag '--run-rc-matrix-path' \
  && script_has_flag '--signoff-fail-on-no-go'; then
  echo "[vpn-rc-resilience-path] signoff NO-GO fail-closed with resilience signal path"
  FAKE_RC_NO_GO="$TMP_DIR/fake_rc_no_go.sh"
  cat >"$FAKE_RC_NO_GO" <<EOF_FAKE_RC_NO_GO
#!/usr/bin/env bash
set -euo pipefail

capture_file="\${VPN_RC_RESILIENCE_CAPTURE_FILE:?}"
stage_id="$rc_stage_id"

{
  printf '%s' "\$stage_id"
  for arg in "\$@"; do
    printf '\t%s' "\$arg"
  done
  printf '\n'
} >>"\$capture_file"

summary_json=""
reports_dir=""
args=("\$@")
for (( i=0; i < \${#args[@]}; i++ )); do
  arg="\${args[\$i]}"
  case "\$arg" in
    --summary-json)
      summary_json="\${args[\$((i + 1))]:-}"
      ;;
    --reports-dir)
      reports_dir="\${args[\$((i + 1))]:-}"
      ;;
  esac
done

if [[ -n "\$reports_dir" ]]; then
  mkdir -p "\$reports_dir"
fi
if [[ -n "\$summary_json" ]]; then
  mkdir -p "\$(dirname "\$summary_json")"
  cat >"\$summary_json" <<'EOF_JSON'
{
  "version": 1,
  "status": "fail",
  "rc": 41,
  "steps": {
    "profile_compare_campaign_signoff": {
      "status": "fail",
      "rc": 41,
      "decision": "NO-GO",
      "go": false
    },
    "roadmap_progress_report": {
      "status": "pass",
      "rc": 0,
      "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
      "readiness_status": "NOT_READY"
    },
    "session_churn_guard": {
      "status": "pass",
      "rc": 0
    }
  },
  "resilience": {
    "session_churn_guard_ok": true
  }
}
EOF_JSON
fi

exit 41
EOF_FAKE_RC_NO_GO
  chmod +x "$FAKE_RC_NO_GO"

  : >"$CAPTURE"
  declare -a NO_GO_ARGS=("${QUIET_ARGS[@]}")
  NO_GO_ARGS+=(
    --run-docker-profile-matrix 0
    --run-rc-matrix-path 1
    --signoff-fail-on-no-go 1
  )
  set +e
  env "$rc_stage_env_var=$FAKE_RC_NO_GO" \
    VPN_RC_RESILIENCE_CAPTURE_FILE="$CAPTURE" \
    bash "$CHAIN_SCRIPT" "${NO_GO_ARGS[@]}" >"$SIGNOFF_NO_GO_LOG" 2>&1
  signoff_no_go_rc=$?
  set -e
  if [[ "$signoff_no_go_rc" -ne 41 ]]; then
    echo "expected signoff NO-GO fail-closed rc=41, got rc=$signoff_no_go_rc"
    cat "$SIGNOFF_NO_GO_LOG"
    exit 1
  fi

  rc_no_go_line="$(capture_line_for_stage "$CAPTURE" "$rc_stage_id")"
  if [[ -z "$rc_no_go_line" ]]; then
    echo "signoff NO-GO path missing rc-stage invocation capture"
    cat "$CAPTURE"
    cat "$SIGNOFF_NO_GO_LOG"
    exit 1
  fi
  if [[ "$rc_no_go_line" != *$'\t--signoff-fail-on-no-go\t1'* ]]; then
    echo "signoff NO-GO path missing --signoff-fail-on-no-go 1 forwarding"
    cat "$CAPTURE"
    cat "$SIGNOFF_NO_GO_LOG"
    exit 1
  fi

  if [[ ! -f "$FINAL_SUMMARY_JSON" ]]; then
    echo "signoff NO-GO path missing final summary json"
    cat "$SIGNOFF_NO_GO_LOG"
    exit 1
  fi
  assert_handoff_contract "$FINAL_SUMMARY_JSON"
  if ! jq -e --argjson expected_rc "$signoff_no_go_rc" '
    .status == "fail"
    and .rc == $expected_rc
    and .inputs.run_docker_profile_matrix == false
    and .inputs.run_rc_matrix_path == true
    and .inputs.signoff_fail_on_no_go == true
    and .profile_matrix_stable == false
    and .peer_loss_recovery_ok == false
    and .steps.vpn_rc_matrix_path.status == "fail"
    and .steps.vpn_rc_matrix_path.rc == $expected_rc
    and .steps.vpn_rc_matrix_path.signoff_decision == "NO-GO"
    and .session_churn_guard_ok == true
    and .resilience_handoff.derivation.session_churn_guard_ok == "rc_summary.resilience.session_churn_guard_ok"
  ' "$FINAL_SUMMARY_JSON" >/dev/null 2>&1; then
    echo "signoff NO-GO path summary contract mismatch"
    cat "$FINAL_SUMMARY_JSON"
    exit 1
  fi
else
  echo "[vpn-rc-resilience-path] signoff NO-GO fail-closed path unavailable; script lacks rc stage or required flags"
fi

if [[ -x "$ROOT_DIR/scripts/easy_node.sh" ]] \
  && grep -F -- 'VPN_RC_RESILIENCE_PATH_SCRIPT' "$ROOT_DIR/scripts/easy_node.sh" >/dev/null 2>&1 \
  && "$ROOT_DIR/scripts/easy_node.sh" help | grep -q 'vpn-rc-resilience-path'; then
  echo "[vpn-rc-resilience-path] easy_node forwarding"
  FAKE_FORWARD="$TMP_DIR/fake_forward.sh"
  cat >"$FAKE_FORWARD" <<'EOF_FAKE_FORWARD'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${VPN_RC_FORWARD_CAPTURE_FILE:?}"
{
  printf 'forward'
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
EOF_FAKE_FORWARD
  chmod +x "$FAKE_FORWARD"

  : >"$FORWARD_CAPTURE"
  set +e
  VPN_RC_RESILIENCE_PATH_SCRIPT="$FAKE_FORWARD" \
  VPN_RC_FORWARD_CAPTURE_FILE="$FORWARD_CAPTURE" \
  "$ROOT_DIR/scripts/easy_node.sh" vpn-rc-resilience-path --print-summary-json 0 >"$FORWARD_LOG" 2>&1
  forward_rc=$?
  set -e
  if [[ "$forward_rc" -ne 0 ]]; then
    echo "easy_node forwarding invocation failed"
    cat "$FORWARD_LOG"
    exit 1
  fi

  forward_line="$(tail -n 1 "$FORWARD_CAPTURE" || true)"
  if [[ -z "$forward_line" ]]; then
    echo "missing easy_node forwarding capture"
    cat "$FORWARD_CAPTURE"
    exit 1
  fi
  if [[ "$forward_line" != *$'\t--print-summary-json\t0'* ]]; then
    echo "easy_node forwarding missing --print-summary-json 0"
    cat "$FORWARD_CAPTURE"
    exit 1
  fi
else
  echo "[vpn-rc-resilience-path] easy_node forwarding hook unavailable; chain-focused checks only"
fi

echo "vpn-rc resilience path integration check ok"
