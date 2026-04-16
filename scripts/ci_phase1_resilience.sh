#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/ci_phase1_resilience.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]] \
    [--allow-policy-no-go [0|1]] \
    [--resume [0|1]] \
    [--dry-run [0|1]] \
    [--run-three-machine-docker-profile-matrix [0|1]] \
    [--run-profile-compare-docker-matrix [0|1]] \
    [--run-three-machine-docker-profile-matrix-record [0|1]] \
    [--run-vpn-rc-matrix-path [0|1]] \
    [--run-vpn-rc-resilience-path [0|1]] \
    [--run-session-churn-guard [0|1]] \
    [--run-3hop-runtime-integration [0|1]] \
    [--three-machine-docker-profile-matrix-timeout-sec N] \
    [--profile-compare-docker-matrix-timeout-sec N] \
    [--three-machine-docker-profile-matrix-record-timeout-sec N] \
    [--vpn-rc-matrix-path-timeout-sec N] \
    [--vpn-rc-resilience-path-timeout-sec N] \
    [--session-churn-guard-timeout-sec N] \
    [--3hop-runtime-integration-timeout-sec N]

Purpose:
  Run a focused Phase-1 resilience CI gate around profile-matrix and RC
  resilience wrappers:
    1) three_machine_docker_profile_matrix.sh
    2) profile_compare_docker_matrix.sh
    3) three_machine_docker_profile_matrix_record.sh
    4) vpn_rc_matrix_path.sh
    5) vpn_rc_resilience_path.sh
    6) integration_session_churn_guard.sh
    7) integration_live_wg_full_path_strict.sh (optional)

Dry-run mode:
  --dry-run 1 forwards dry-run to wrapper stages so checks are deterministic
  and contract-oriented (no heavy runtime orchestration). Runtime integration
  stages are marked as skipped in dry-run mode.

Resume mode:
  --resume 1 reuses per-stage pass artifacts from --reports-dir when present,
  skipping already-passing wrapper stages for faster retry/continuation.

Timeouts:
  Timeout values are per-stage, in seconds, and fail-closed when exceeded.
  Timeout expiry returns rc=124 with stage reason=timeout.
USAGE
}

trim() {
  local value="${1:-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

abs_path() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
  elif [[ "$path" == /* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

require_value_or_die() {
  local flag="$1"
  if [[ $# -lt 2 || -z "${2:-}" ]]; then
    echo "$flag requires a value"
    exit 2
  fi
}

non_negative_int_arg_or_die() {
  local name="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be an integer >= 0"
    exit 2
  fi
}

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
}

print_cmd() {
  local arg
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
  printf '\n'
}

kill_process_tree() {
  local root_pid="$1"
  local signal="$2"
  local child_pid=""
  if command -v pgrep >/dev/null 2>&1; then
    while IFS= read -r child_pid; do
      [[ -z "$child_pid" ]] && continue
      kill_process_tree "$child_pid" "$signal"
    done < <(pgrep -P "$root_pid" 2>/dev/null || true)
  fi
  kill "-${signal}" "$root_pid" >/dev/null 2>&1 || true
}

RUN_WITH_TIMEOUT_TIMED_OUT="false"

run_with_timeout() {
  local timeout_sec="$1"
  shift
  local rc=0
  local timeout_marker=""
  local stage_pid=0
  local stage_pgid=""
  local watcher_pid=0

  RUN_WITH_TIMEOUT_TIMED_OUT="false"

  if (( timeout_sec <= 0 )); then
    "$@"
    return $?
  fi

  timeout_marker="$(mktemp)"
  rm -f "$timeout_marker"

  if command -v setsid >/dev/null 2>&1; then
    setsid "$@" &
    stage_pid=$!
    stage_pgid="$stage_pid"
  else
    "$@" &
    stage_pid=$!
  fi

  (
    sleep "$timeout_sec"
    if kill -0 "$stage_pid" >/dev/null 2>&1; then
      : >"$timeout_marker"
      if [[ -n "$stage_pgid" ]]; then
        kill -TERM -- "-${stage_pgid}" >/dev/null 2>&1 || true
      else
        kill_process_tree "$stage_pid" TERM
      fi
      sleep 2
      if kill -0 "$stage_pid" >/dev/null 2>&1; then
        if [[ -n "$stage_pgid" ]]; then
          kill -KILL -- "-${stage_pgid}" >/dev/null 2>&1 || true
        else
          kill_process_tree "$stage_pid" KILL
        fi
      fi
    fi
  ) &
  watcher_pid=$!

  wait "$stage_pid"
  rc=$?

  kill "$watcher_pid" >/dev/null 2>&1 || true
  wait "$watcher_pid" >/dev/null 2>&1 || true

  if [[ -f "$timeout_marker" ]]; then
    RUN_WITH_TIMEOUT_TIMED_OUT="true"
    rc=124
  fi
  rm -f "$timeout_marker"
  return "$rc"
}

RUN_STEP_REASON=""
RUN_STEP_TIMED_OUT="false"

run_step() {
  local label="$1"
  local timeout_sec="$2"
  shift 2
  local rc=0
  local timed_out="false"
  local reason=""
  echo "[ci-phase1-resilience] step=${label} status=running timeout_sec=${timeout_sec}"
  set +e
  run_with_timeout "$timeout_sec" "$@"
  rc=$?
  timed_out="$RUN_WITH_TIMEOUT_TIMED_OUT"
  set -e
  if (( rc == 0 )); then
    echo "[ci-phase1-resilience] step=${label} status=pass rc=0"
    reason=""
  else
    if [[ "$timed_out" == "true" ]]; then
      reason="timeout"
    else
      reason="command-failed"
    fi
    echo "[ci-phase1-resilience] step=${label} status=fail rc=${rc} reason=${reason} timeout_sec=${timeout_sec}"
  fi
  RUN_STEP_REASON="$reason"
  RUN_STEP_TIMED_OUT="$timed_out"
  return "$rc"
}

json_file_valid() {
  local path="$1"
  [[ -f "$path" ]] && jq -e . "$path" >/dev/null 2>&1
}

summary_pass_contract_valid() {
  local path="$1"
  if ! json_file_valid "$path"; then
    return 1
  fi
  jq -e '
    (.status | type) == "string"
    and .status == "pass"
    and (.rc | type) == "number"
    and .rc == 0
  ' "$path" >/dev/null 2>&1
}

normalize_failure_kind() {
  local kind="${1:-}"
  case "$kind" in
    policy_no_go|policy-no-go)
      printf '%s' "policy_no_go"
      ;;
    timeout)
      printf '%s' "timeout"
      ;;
    execution_failure|command_failed|command-failed)
      printf '%s' "execution_failure"
      ;;
    none|"")
      printf '%s' "none"
      ;;
    *)
      printf '%s' "execution_failure"
      ;;
  esac
}

classify_stage_failure_kind() {
  local default_kind="${1:-execution_failure}"
  local stage_summary_json="${2:-}"
  local timed_out="${3:-false}"
  local jq_expr="${4:-}"
  local raw_kind=""
  if [[ "$timed_out" == "true" ]]; then
    printf '%s' "timeout"
    return
  fi
  if [[ -z "$stage_summary_json" || ! -f "$stage_summary_json" ]] || ! jq -e . "$stage_summary_json" >/dev/null 2>&1; then
    printf '%s' "$default_kind"
    return
  fi
  if [[ -n "$jq_expr" ]]; then
    raw_kind="$(jq -r "$jq_expr" "$stage_summary_json" 2>/dev/null || true)"
  fi
  printf '%s' "$(normalize_failure_kind "$raw_kind")"
}

failure_kind_to_reason() {
  local kind="${1:-}"
  case "$kind" in
    policy_no_go)
      printf '%s' "policy-no-go"
      ;;
    timeout)
      printf '%s' "timeout"
      ;;
    *)
      printf '%s' "command-failed"
      ;;
  esac
}

need_cmd jq
need_cmd date
need_cmd mktemp

reports_dir="${CI_PHASE1_RESILIENCE_REPORTS_DIR:-}"
summary_json="${CI_PHASE1_RESILIENCE_SUMMARY_JSON:-}"
print_summary_json="${CI_PHASE1_RESILIENCE_PRINT_SUMMARY_JSON:-1}"
allow_policy_no_go="${CI_PHASE1_RESILIENCE_ALLOW_POLICY_NO_GO:-0}"
resume="${CI_PHASE1_RESILIENCE_RESUME:-0}"
dry_run="${CI_PHASE1_RESILIENCE_DRY_RUN:-0}"

run_three_machine_docker_profile_matrix="${CI_PHASE1_RESILIENCE_RUN_THREE_MACHINE_DOCKER_PROFILE_MATRIX:-1}"
run_profile_compare_docker_matrix="${CI_PHASE1_RESILIENCE_RUN_PROFILE_COMPARE_DOCKER_MATRIX:-1}"
run_three_machine_docker_profile_matrix_record="${CI_PHASE1_RESILIENCE_RUN_THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD:-1}"
run_vpn_rc_matrix_path="${CI_PHASE1_RESILIENCE_RUN_VPN_RC_MATRIX_PATH:-1}"
run_vpn_rc_resilience_path="${CI_PHASE1_RESILIENCE_RUN_VPN_RC_RESILIENCE_PATH:-1}"
run_session_churn_guard="${CI_PHASE1_RESILIENCE_RUN_SESSION_CHURN_GUARD:-1}"
run_3hop_runtime_integration="${CI_PHASE1_RESILIENCE_RUN_3HOP_RUNTIME_INTEGRATION:-0}"

three_machine_docker_profile_matrix_timeout_sec="${CI_PHASE1_RESILIENCE_THREE_MACHINE_DOCKER_PROFILE_MATRIX_TIMEOUT_SEC:-5400}"
profile_compare_docker_matrix_timeout_sec="${CI_PHASE1_RESILIENCE_PROFILE_COMPARE_DOCKER_MATRIX_TIMEOUT_SEC:-5400}"
three_machine_docker_profile_matrix_record_timeout_sec="${CI_PHASE1_RESILIENCE_THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_TIMEOUT_SEC:-5400}"
vpn_rc_matrix_path_timeout_sec="${CI_PHASE1_RESILIENCE_VPN_RC_MATRIX_PATH_TIMEOUT_SEC:-5400}"
vpn_rc_resilience_path_timeout_sec="${CI_PHASE1_RESILIENCE_VPN_RC_RESILIENCE_PATH_TIMEOUT_SEC:-7200}"
session_churn_guard_timeout_sec="${CI_PHASE1_RESILIENCE_SESSION_CHURN_GUARD_TIMEOUT_SEC:-3600}"
three_hop_runtime_integration_timeout_sec="${CI_PHASE1_RESILIENCE_3HOP_RUNTIME_INTEGRATION_TIMEOUT_SEC:-3600}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
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
    --allow-policy-no-go)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        allow_policy_no_go="${2:-}"
        shift 2
      else
        allow_policy_no_go="1"
        shift
      fi
      ;;
    --resume)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        resume="${2:-}"
        shift 2
      else
        resume="1"
        shift
      fi
      ;;
    --dry-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        dry_run="${2:-}"
        shift 2
      else
        dry_run="1"
        shift
      fi
      ;;
    --run-three-machine-docker-profile-matrix)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_three_machine_docker_profile_matrix="${2:-}"
        shift 2
      else
        run_three_machine_docker_profile_matrix="1"
        shift
      fi
      ;;
    --run-profile-compare-docker-matrix)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_profile_compare_docker_matrix="${2:-}"
        shift 2
      else
        run_profile_compare_docker_matrix="1"
        shift
      fi
      ;;
    --run-three-machine-docker-profile-matrix-record)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_three_machine_docker_profile_matrix_record="${2:-}"
        shift 2
      else
        run_three_machine_docker_profile_matrix_record="1"
        shift
      fi
      ;;
    --run-vpn-rc-matrix-path)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_vpn_rc_matrix_path="${2:-}"
        shift 2
      else
        run_vpn_rc_matrix_path="1"
        shift
      fi
      ;;
    --run-vpn-rc-resilience-path)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_vpn_rc_resilience_path="${2:-}"
        shift 2
      else
        run_vpn_rc_resilience_path="1"
        shift
      fi
      ;;
    --run-session-churn-guard)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_session_churn_guard="${2:-}"
        shift 2
      else
        run_session_churn_guard="1"
        shift
      fi
      ;;
    --run-3hop-runtime-integration)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_3hop_runtime_integration="${2:-}"
        shift 2
      else
        run_3hop_runtime_integration="1"
        shift
      fi
      ;;
    --three-machine-docker-profile-matrix-timeout-sec)
      require_value_or_die "$1" "${2:-}"
      three_machine_docker_profile_matrix_timeout_sec="${2:-}"
      shift 2
      ;;
    --profile-compare-docker-matrix-timeout-sec)
      require_value_or_die "$1" "${2:-}"
      profile_compare_docker_matrix_timeout_sec="${2:-}"
      shift 2
      ;;
    --three-machine-docker-profile-matrix-record-timeout-sec)
      require_value_or_die "$1" "${2:-}"
      three_machine_docker_profile_matrix_record_timeout_sec="${2:-}"
      shift 2
      ;;
    --vpn-rc-matrix-path-timeout-sec)
      require_value_or_die "$1" "${2:-}"
      vpn_rc_matrix_path_timeout_sec="${2:-}"
      shift 2
      ;;
    --vpn-rc-resilience-path-timeout-sec)
      require_value_or_die "$1" "${2:-}"
      vpn_rc_resilience_path_timeout_sec="${2:-}"
      shift 2
      ;;
    --session-churn-guard-timeout-sec)
      require_value_or_die "$1" "${2:-}"
      session_churn_guard_timeout_sec="${2:-}"
      shift 2
      ;;
    --3hop-runtime-integration-timeout-sec)
      require_value_or_die "$1" "${2:-}"
      three_hop_runtime_integration_timeout_sec="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--allow-policy-no-go" "$allow_policy_no_go"
bool_arg_or_die "--resume" "$resume"
bool_arg_or_die "--dry-run" "$dry_run"
bool_arg_or_die "--run-three-machine-docker-profile-matrix" "$run_three_machine_docker_profile_matrix"
bool_arg_or_die "--run-profile-compare-docker-matrix" "$run_profile_compare_docker_matrix"
bool_arg_or_die "--run-three-machine-docker-profile-matrix-record" "$run_three_machine_docker_profile_matrix_record"
bool_arg_or_die "--run-vpn-rc-matrix-path" "$run_vpn_rc_matrix_path"
bool_arg_or_die "--run-vpn-rc-resilience-path" "$run_vpn_rc_resilience_path"
bool_arg_or_die "--run-session-churn-guard" "$run_session_churn_guard"
bool_arg_or_die "--run-3hop-runtime-integration" "$run_3hop_runtime_integration"
non_negative_int_arg_or_die "--three-machine-docker-profile-matrix-timeout-sec" "$three_machine_docker_profile_matrix_timeout_sec"
non_negative_int_arg_or_die "--profile-compare-docker-matrix-timeout-sec" "$profile_compare_docker_matrix_timeout_sec"
non_negative_int_arg_or_die "--three-machine-docker-profile-matrix-record-timeout-sec" "$three_machine_docker_profile_matrix_record_timeout_sec"
non_negative_int_arg_or_die "--vpn-rc-matrix-path-timeout-sec" "$vpn_rc_matrix_path_timeout_sec"
non_negative_int_arg_or_die "--vpn-rc-resilience-path-timeout-sec" "$vpn_rc_resilience_path_timeout_sec"
non_negative_int_arg_or_die "--session-churn-guard-timeout-sec" "$session_churn_guard_timeout_sec"
non_negative_int_arg_or_die "--3hop-runtime-integration-timeout-sec" "$three_hop_runtime_integration_timeout_sec"

three_machine_docker_profile_matrix_script="${CI_PHASE1_RESILIENCE_THREE_MACHINE_DOCKER_PROFILE_MATRIX_SCRIPT:-$ROOT_DIR/scripts/three_machine_docker_profile_matrix.sh}"
profile_compare_docker_matrix_script="${CI_PHASE1_RESILIENCE_PROFILE_COMPARE_DOCKER_MATRIX_SCRIPT:-$ROOT_DIR/scripts/profile_compare_docker_matrix.sh}"
three_machine_docker_profile_matrix_record_script="${CI_PHASE1_RESILIENCE_THREE_MACHINE_DOCKER_PROFILE_MATRIX_RECORD_SCRIPT:-$ROOT_DIR/scripts/three_machine_docker_profile_matrix_record.sh}"
vpn_rc_matrix_path_script="${CI_PHASE1_RESILIENCE_VPN_RC_MATRIX_PATH_SCRIPT:-$ROOT_DIR/scripts/vpn_rc_matrix_path.sh}"
vpn_rc_resilience_path_script="${CI_PHASE1_RESILIENCE_VPN_RC_RESILIENCE_PATH_SCRIPT:-$ROOT_DIR/scripts/vpn_rc_resilience_path.sh}"
session_churn_guard_script="${CI_PHASE1_RESILIENCE_SESSION_CHURN_GUARD_SCRIPT:-$ROOT_DIR/scripts/integration_session_churn_guard.sh}"
three_hop_runtime_integration_script="${CI_PHASE1_RESILIENCE_THREE_HOP_RUNTIME_INTEGRATION_SCRIPT:-$ROOT_DIR/scripts/integration_live_wg_full_path_strict.sh}"

if [[ "$run_three_machine_docker_profile_matrix" == "1" && ! -x "$three_machine_docker_profile_matrix_script" ]]; then
  echo "missing executable stage script: $three_machine_docker_profile_matrix_script"
  exit 2
fi
if [[ "$run_profile_compare_docker_matrix" == "1" && ! -x "$profile_compare_docker_matrix_script" ]]; then
  echo "missing executable stage script: $profile_compare_docker_matrix_script"
  exit 2
fi
if [[ "$run_three_machine_docker_profile_matrix_record" == "1" && ! -x "$three_machine_docker_profile_matrix_record_script" ]]; then
  echo "missing executable stage script: $three_machine_docker_profile_matrix_record_script"
  exit 2
fi
if [[ "$run_vpn_rc_matrix_path" == "1" && ! -x "$vpn_rc_matrix_path_script" ]]; then
  echo "missing executable stage script: $vpn_rc_matrix_path_script"
  exit 2
fi
if [[ "$run_vpn_rc_resilience_path" == "1" && ! -x "$vpn_rc_resilience_path_script" ]]; then
  echo "missing executable stage script: $vpn_rc_resilience_path_script"
  exit 2
fi
if [[ "$run_session_churn_guard" == "1" && ! -x "$session_churn_guard_script" ]]; then
  echo "missing executable stage script: $session_churn_guard_script"
  exit 2
fi
if [[ "$run_3hop_runtime_integration" == "1" && ! -x "$three_hop_runtime_integration_script" ]]; then
  echo "missing executable stage script: $three_hop_runtime_integration_script"
  exit 2
fi

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/ci_phase1_resilience_${run_stamp}"
else
  reports_dir="$(abs_path "$reports_dir")"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/ci_phase1_resilience_summary.json"
else
  summary_json="$(abs_path "$summary_json")"
fi

three_machine_matrix_reports_dir="$reports_dir/three_machine_docker_profile_matrix"
profile_compare_matrix_reports_dir="$reports_dir/profile_compare_docker_matrix"
three_machine_matrix_record_reports_dir="$reports_dir/three_machine_docker_profile_matrix_record"
vpn_rc_matrix_reports_dir="$reports_dir/vpn_rc_matrix_path"
vpn_rc_resilience_reports_dir="$reports_dir/vpn_rc_resilience_path"

three_machine_matrix_summary_json="$three_machine_matrix_reports_dir/three_machine_docker_profile_matrix_summary.json"
three_machine_matrix_report_md="$three_machine_matrix_reports_dir/three_machine_docker_profile_matrix_report.md"
profile_compare_matrix_summary_json="$profile_compare_matrix_reports_dir/profile_compare_docker_matrix_summary.json"
profile_compare_matrix_report_md="$profile_compare_matrix_reports_dir/profile_compare_docker_matrix_report.md"
three_machine_matrix_record_summary_json="$three_machine_matrix_record_reports_dir/three_machine_docker_profile_matrix_record_summary.json"
three_machine_matrix_record_matrix_summary_json="$three_machine_matrix_record_reports_dir/three_machine_docker_profile_matrix_record_matrix_summary.json"
vpn_rc_matrix_summary_json="$vpn_rc_matrix_reports_dir/vpn_rc_matrix_path_summary.json"
vpn_rc_resilience_summary_json="$vpn_rc_resilience_reports_dir/vpn_rc_resilience_path_summary.json"

# Reuse upstream matrix artifact when both matrix and record stages are enabled.
if [[ "$run_three_machine_docker_profile_matrix" == "1" ]]; then
  three_machine_matrix_record_matrix_summary_json="$three_machine_matrix_summary_json"
fi

mkdir -p "$reports_dir"
mkdir -p "$three_machine_matrix_reports_dir" "$profile_compare_matrix_reports_dir" "$three_machine_matrix_record_reports_dir"
mkdir -p "$vpn_rc_matrix_reports_dir" "$vpn_rc_resilience_reports_dir"
mkdir -p "$(dirname "$summary_json")"

three_machine_matrix_cmd=(
  "$three_machine_docker_profile_matrix_script"
  --reports-dir "$three_machine_matrix_reports_dir"
  --summary-json "$three_machine_matrix_summary_json"
  --report-md "$three_machine_matrix_report_md"
  --print-summary-json 0
)
profile_compare_matrix_cmd=(
  "$profile_compare_docker_matrix_script"
  --reports-dir "$profile_compare_matrix_reports_dir"
  --summary-json "$profile_compare_matrix_summary_json"
  --report-md "$profile_compare_matrix_report_md"
  --print-summary-json 0
)
three_machine_matrix_record_cmd=(
  "$three_machine_docker_profile_matrix_record_script"
  --summary-json "$three_machine_matrix_record_summary_json"
  --matrix-summary-json "$three_machine_matrix_record_matrix_summary_json"
  --record-result 0
  --manual-validation-report 0
  --print-summary-json 0
)
if [[ "$run_three_machine_docker_profile_matrix" == "1" && "$dry_run" != "1" ]]; then
  three_machine_matrix_record_cmd+=(--run-matrix 0)
fi
vpn_rc_matrix_cmd=(
  "$vpn_rc_matrix_path_script"
  --reports-dir "$vpn_rc_matrix_reports_dir"
  --summary-json "$vpn_rc_matrix_summary_json"
  --print-report 0
  --print-summary-json 0
)
vpn_rc_resilience_cmd=(
  "$vpn_rc_resilience_path_script"
  --reports-dir "$vpn_rc_resilience_reports_dir"
  --summary-json "$vpn_rc_resilience_summary_json"
  --print-report 0
  --print-summary-json 0
)
if [[ "$run_three_machine_docker_profile_matrix" == "1" ]]; then
  vpn_rc_resilience_cmd+=(
    --run-docker-profile-matrix 0
    --docker-summary-json "$three_machine_matrix_summary_json"
    --docker-report-md "$three_machine_matrix_report_md"
  )
fi
if [[ "$run_vpn_rc_matrix_path" == "1" ]]; then
  vpn_rc_resilience_cmd+=(
    --run-rc-matrix-path 0
    --rc-summary-json "$vpn_rc_matrix_summary_json"
  )
fi
session_churn_guard_cmd=(
  "$session_churn_guard_script"
)
three_hop_runtime_integration_cmd=(
  "$three_hop_runtime_integration_script"
)

if [[ "$dry_run" == "1" ]]; then
  three_machine_matrix_cmd+=(--dry-run 1)
  profile_compare_matrix_cmd+=(--dry-run 1)
  three_machine_matrix_record_cmd+=(--dry-run 1)
  vpn_rc_matrix_cmd+=(--dry-run 1)
  vpn_rc_resilience_cmd+=(--dry-run 1)
fi

three_machine_matrix_status="skip"
three_machine_matrix_rc=0
three_machine_matrix_command=""
three_machine_matrix_reason="disabled"
three_machine_matrix_timed_out="false"
three_machine_matrix_reused="false"
three_machine_matrix_timeout_sec="$three_machine_docker_profile_matrix_timeout_sec"
three_machine_matrix_failure_kind="none"

profile_compare_matrix_status="skip"
profile_compare_matrix_rc=0
profile_compare_matrix_command=""
profile_compare_matrix_reason="disabled"
profile_compare_matrix_timed_out="false"
profile_compare_matrix_reused="false"
profile_compare_matrix_timeout_sec="$profile_compare_docker_matrix_timeout_sec"
profile_compare_matrix_failure_kind="none"

three_machine_matrix_record_status="skip"
three_machine_matrix_record_rc=0
three_machine_matrix_record_command=""
three_machine_matrix_record_reason="disabled"
three_machine_matrix_record_timed_out="false"
three_machine_matrix_record_reused="false"
three_machine_matrix_record_timeout_sec="$three_machine_docker_profile_matrix_record_timeout_sec"
three_machine_matrix_record_failure_kind="none"

vpn_rc_matrix_status="skip"
vpn_rc_matrix_rc=0
vpn_rc_matrix_command=""
vpn_rc_matrix_reason="disabled"
vpn_rc_matrix_timed_out="false"
vpn_rc_matrix_reused="false"
vpn_rc_matrix_timeout_sec="$vpn_rc_matrix_path_timeout_sec"
vpn_rc_matrix_failure_kind="none"

vpn_rc_resilience_status="skip"
vpn_rc_resilience_rc=0
vpn_rc_resilience_command=""
vpn_rc_resilience_reason="disabled"
vpn_rc_resilience_timed_out="false"
vpn_rc_resilience_reused="false"
vpn_rc_resilience_timeout_sec="$vpn_rc_resilience_path_timeout_sec"
vpn_rc_resilience_failure_kind="none"

session_churn_guard_status="skip"
session_churn_guard_rc=0
session_churn_guard_command=""
session_churn_guard_reason="disabled"
session_churn_guard_timed_out="false"
session_churn_guard_reused="false"
session_churn_guard_step_timeout_sec="$session_churn_guard_timeout_sec"
session_churn_guard_failure_kind="none"

three_hop_runtime_integration_status="skip"
three_hop_runtime_integration_rc=0
three_hop_runtime_integration_command=""
three_hop_runtime_integration_reason="disabled"
three_hop_runtime_integration_timed_out="false"
three_hop_runtime_integration_reused="false"
three_hop_runtime_integration_step_timeout_sec="$three_hop_runtime_integration_timeout_sec"
three_hop_runtime_integration_failure_kind="none"

final_rc=0

if [[ "$run_three_machine_docker_profile_matrix" == "1" ]]; then
  three_machine_matrix_command="$(print_cmd "${three_machine_matrix_cmd[@]}")"
  if [[ "$resume" == "1" ]] && summary_pass_contract_valid "$three_machine_matrix_summary_json"; then
    echo "[ci-phase1-resilience] step=three_machine_docker_profile_matrix status=pass rc=0 reason=resume-artifact-pass"
    three_machine_matrix_status="pass"
    three_machine_matrix_rc=0
    three_machine_matrix_reason=""
    three_machine_matrix_timed_out="false"
    three_machine_matrix_reused="true"
    three_machine_matrix_failure_kind="none"
  elif run_step "three_machine_docker_profile_matrix" "$three_machine_docker_profile_matrix_timeout_sec" "${three_machine_matrix_cmd[@]}"; then
    three_machine_matrix_status="pass"
    three_machine_matrix_rc=0
    three_machine_matrix_reason=""
    three_machine_matrix_timed_out="$RUN_STEP_TIMED_OUT"
    three_machine_matrix_failure_kind="none"
  else
    step_rc=$?
    three_machine_matrix_status="fail"
    three_machine_matrix_rc=$step_rc
    three_machine_matrix_reason="$RUN_STEP_REASON"
    three_machine_matrix_timed_out="$RUN_STEP_TIMED_OUT"
    three_machine_matrix_failure_kind="$(classify_stage_failure_kind "execution_failure" "" "$three_machine_matrix_timed_out")"
    three_machine_matrix_reason="$(failure_kind_to_reason "$three_machine_matrix_failure_kind")"
    if (( final_rc == 0 )); then
      final_rc=$three_machine_matrix_rc
    fi
  fi
else
  echo "[ci-phase1-resilience] step=three_machine_docker_profile_matrix status=skip reason=disabled"
fi

if [[ "$run_profile_compare_docker_matrix" == "1" ]]; then
  profile_compare_matrix_command="$(print_cmd "${profile_compare_matrix_cmd[@]}")"
  if [[ "$resume" == "1" ]] && summary_pass_contract_valid "$profile_compare_matrix_summary_json"; then
    echo "[ci-phase1-resilience] step=profile_compare_docker_matrix status=pass rc=0 reason=resume-artifact-pass"
    profile_compare_matrix_status="pass"
    profile_compare_matrix_rc=0
    profile_compare_matrix_reason=""
    profile_compare_matrix_timed_out="false"
    profile_compare_matrix_reused="true"
    profile_compare_matrix_failure_kind="none"
  elif run_step "profile_compare_docker_matrix" "$profile_compare_docker_matrix_timeout_sec" "${profile_compare_matrix_cmd[@]}"; then
    profile_compare_matrix_status="pass"
    profile_compare_matrix_rc=0
    profile_compare_matrix_reason=""
    profile_compare_matrix_timed_out="$RUN_STEP_TIMED_OUT"
    profile_compare_matrix_failure_kind="none"
  else
    step_rc=$?
    profile_compare_matrix_status="fail"
    profile_compare_matrix_rc=$step_rc
    profile_compare_matrix_reason="$RUN_STEP_REASON"
    profile_compare_matrix_timed_out="$RUN_STEP_TIMED_OUT"
    profile_compare_matrix_failure_kind="$(classify_stage_failure_kind "execution_failure" "" "$profile_compare_matrix_timed_out")"
    profile_compare_matrix_reason="$(failure_kind_to_reason "$profile_compare_matrix_failure_kind")"
    if (( final_rc == 0 )); then
      final_rc=$profile_compare_matrix_rc
    fi
  fi
else
  echo "[ci-phase1-resilience] step=profile_compare_docker_matrix status=skip reason=disabled"
fi

if [[ "$run_three_machine_docker_profile_matrix_record" == "1" ]]; then
  three_machine_matrix_record_command="$(print_cmd "${three_machine_matrix_record_cmd[@]}")"
  if [[ "$resume" == "1" ]] && summary_pass_contract_valid "$three_machine_matrix_record_summary_json"; then
    echo "[ci-phase1-resilience] step=three_machine_docker_profile_matrix_record status=pass rc=0 reason=resume-artifact-pass"
    three_machine_matrix_record_status="pass"
    three_machine_matrix_record_rc=0
    three_machine_matrix_record_reason=""
    three_machine_matrix_record_timed_out="false"
    three_machine_matrix_record_reused="true"
    three_machine_matrix_record_failure_kind="none"
  elif run_step "three_machine_docker_profile_matrix_record" "$three_machine_docker_profile_matrix_record_timeout_sec" "${three_machine_matrix_record_cmd[@]}"; then
    three_machine_matrix_record_status="pass"
    three_machine_matrix_record_rc=0
    three_machine_matrix_record_reason=""
    three_machine_matrix_record_timed_out="$RUN_STEP_TIMED_OUT"
    three_machine_matrix_record_failure_kind="none"
  else
    step_rc=$?
    three_machine_matrix_record_status="fail"
    three_machine_matrix_record_rc=$step_rc
    three_machine_matrix_record_reason="$RUN_STEP_REASON"
    three_machine_matrix_record_timed_out="$RUN_STEP_TIMED_OUT"
    three_machine_matrix_record_failure_kind="$(classify_stage_failure_kind "execution_failure" "" "$three_machine_matrix_record_timed_out")"
    three_machine_matrix_record_reason="$(failure_kind_to_reason "$three_machine_matrix_record_failure_kind")"
    if (( final_rc == 0 )); then
      final_rc=$three_machine_matrix_record_rc
    fi
  fi
else
  echo "[ci-phase1-resilience] step=three_machine_docker_profile_matrix_record status=skip reason=disabled"
fi

if [[ "$run_vpn_rc_matrix_path" == "1" ]]; then
  vpn_rc_matrix_command="$(print_cmd "${vpn_rc_matrix_cmd[@]}")"
  if [[ "$resume" == "1" ]] && summary_pass_contract_valid "$vpn_rc_matrix_summary_json"; then
    echo "[ci-phase1-resilience] step=vpn_rc_matrix_path status=pass rc=0 reason=resume-artifact-pass"
    vpn_rc_matrix_status="pass"
    vpn_rc_matrix_rc=0
    vpn_rc_matrix_reason=""
    vpn_rc_matrix_timed_out="false"
    vpn_rc_matrix_reused="true"
    vpn_rc_matrix_failure_kind="none"
  elif run_step "vpn_rc_matrix_path" "$vpn_rc_matrix_path_timeout_sec" "${vpn_rc_matrix_cmd[@]}"; then
    vpn_rc_matrix_status="pass"
    vpn_rc_matrix_rc=0
    vpn_rc_matrix_reason=""
    vpn_rc_matrix_timed_out="$RUN_STEP_TIMED_OUT"
    vpn_rc_matrix_failure_kind="none"
  else
    step_rc=$?
    vpn_rc_matrix_status="fail"
    vpn_rc_matrix_rc=$step_rc
    vpn_rc_matrix_reason="$RUN_STEP_REASON"
    vpn_rc_matrix_timed_out="$RUN_STEP_TIMED_OUT"
    vpn_rc_matrix_failure_kind="$(classify_stage_failure_kind \
      "execution_failure" \
      "$vpn_rc_matrix_summary_json" \
      "$vpn_rc_matrix_timed_out" \
      'if (.failure.kind | type) == "string" then .failure.kind
        elif (.steps.profile_compare_campaign_signoff.failure_semantics.kind | type) == "string" then .steps.profile_compare_campaign_signoff.failure_semantics.kind
        elif (.steps.profile_compare_campaign_signoff.decision // .policy_outcome.signoff_decision // "") == "NO-GO" then "policy_no_go"
        else empty end')"
    vpn_rc_matrix_reason="$(failure_kind_to_reason "$vpn_rc_matrix_failure_kind")"
    if (( final_rc == 0 )); then
      final_rc=$vpn_rc_matrix_rc
    fi
  fi
else
  echo "[ci-phase1-resilience] step=vpn_rc_matrix_path status=skip reason=disabled"
fi

if [[ "$run_vpn_rc_resilience_path" == "1" ]]; then
  vpn_rc_resilience_command="$(print_cmd "${vpn_rc_resilience_cmd[@]}")"
  if [[ "$resume" == "1" ]] && summary_pass_contract_valid "$vpn_rc_resilience_summary_json"; then
    echo "[ci-phase1-resilience] step=vpn_rc_resilience_path status=pass rc=0 reason=resume-artifact-pass"
    vpn_rc_resilience_status="pass"
    vpn_rc_resilience_rc=0
    vpn_rc_resilience_reason=""
    vpn_rc_resilience_timed_out="false"
    vpn_rc_resilience_reused="true"
    vpn_rc_resilience_failure_kind="none"
  elif run_step "vpn_rc_resilience_path" "$vpn_rc_resilience_path_timeout_sec" "${vpn_rc_resilience_cmd[@]}"; then
    vpn_rc_resilience_status="pass"
    vpn_rc_resilience_rc=0
    vpn_rc_resilience_reason=""
    vpn_rc_resilience_timed_out="$RUN_STEP_TIMED_OUT"
    vpn_rc_resilience_failure_kind="none"
  else
    step_rc=$?
    vpn_rc_resilience_status="fail"
    vpn_rc_resilience_rc=$step_rc
    vpn_rc_resilience_reason="$RUN_STEP_REASON"
    vpn_rc_resilience_timed_out="$RUN_STEP_TIMED_OUT"
    vpn_rc_resilience_failure_kind="$(classify_stage_failure_kind \
      "execution_failure" \
      "$vpn_rc_resilience_summary_json" \
      "$vpn_rc_resilience_timed_out" \
      'if (.steps.vpn_rc_matrix_path.failure_semantics.kind | type) == "string" then .steps.vpn_rc_matrix_path.failure_semantics.kind
        elif (.steps.vpn_rc_matrix_path.signoff_decision // "") == "NO-GO" then "policy_no_go"
        elif (.resilience_handoff.session_churn_guard_ok | type) == "boolean" and (.resilience_handoff.session_churn_guard_ok == false) and ((.steps.vpn_rc_matrix_path.signoff_decision // "") == "NO-GO") then "policy_no_go"
        else empty end')"
    vpn_rc_resilience_reason="$(failure_kind_to_reason "$vpn_rc_resilience_failure_kind")"
    if (( final_rc == 0 )); then
      final_rc=$vpn_rc_resilience_rc
    fi
  fi
else
  echo "[ci-phase1-resilience] step=vpn_rc_resilience_path status=skip reason=disabled"
fi

if [[ "$run_session_churn_guard" == "1" ]]; then
  session_churn_guard_command="$(print_cmd "${session_churn_guard_cmd[@]}")"
  if [[ "$dry_run" == "1" ]]; then
    echo "[ci-phase1-resilience] step=session_churn_guard status=skip reason=dry-run-not-supported"
    session_churn_guard_status="skip"
    session_churn_guard_rc=0
    session_churn_guard_reason="dry-run-not-supported"
    session_churn_guard_timed_out="false"
    session_churn_guard_failure_kind="none"
  elif run_step "session_churn_guard" "$session_churn_guard_timeout_sec" "${session_churn_guard_cmd[@]}"; then
    session_churn_guard_status="pass"
    session_churn_guard_rc=0
    session_churn_guard_reason=""
    session_churn_guard_timed_out="$RUN_STEP_TIMED_OUT"
    session_churn_guard_failure_kind="none"
  else
    step_rc=$?
    session_churn_guard_status="fail"
    session_churn_guard_rc=$step_rc
    session_churn_guard_reason="$RUN_STEP_REASON"
    session_churn_guard_timed_out="$RUN_STEP_TIMED_OUT"
    session_churn_guard_failure_kind="$(classify_stage_failure_kind "execution_failure" "" "$session_churn_guard_timed_out")"
    session_churn_guard_reason="$(failure_kind_to_reason "$session_churn_guard_failure_kind")"
    if (( final_rc == 0 )); then
      final_rc=$session_churn_guard_rc
    fi
  fi
else
  echo "[ci-phase1-resilience] step=session_churn_guard status=skip reason=disabled"
fi

if [[ "$run_3hop_runtime_integration" == "1" ]]; then
  three_hop_runtime_integration_command="$(print_cmd "${three_hop_runtime_integration_cmd[@]}")"
  if [[ "$dry_run" == "1" ]]; then
    echo "[ci-phase1-resilience] step=three_hop_runtime_integration status=skip reason=dry-run-not-supported"
    three_hop_runtime_integration_status="skip"
    three_hop_runtime_integration_rc=0
    three_hop_runtime_integration_reason="dry-run-not-supported"
    three_hop_runtime_integration_timed_out="false"
    three_hop_runtime_integration_failure_kind="none"
  elif run_step "three_hop_runtime_integration" "$three_hop_runtime_integration_timeout_sec" "${three_hop_runtime_integration_cmd[@]}"; then
    three_hop_runtime_integration_status="pass"
    three_hop_runtime_integration_rc=0
    three_hop_runtime_integration_reason=""
    three_hop_runtime_integration_timed_out="$RUN_STEP_TIMED_OUT"
    three_hop_runtime_integration_failure_kind="none"
  else
    step_rc=$?
    three_hop_runtime_integration_status="fail"
    three_hop_runtime_integration_rc=$step_rc
    three_hop_runtime_integration_reason="$RUN_STEP_REASON"
    three_hop_runtime_integration_timed_out="$RUN_STEP_TIMED_OUT"
    three_hop_runtime_integration_failure_kind="$(classify_stage_failure_kind "execution_failure" "" "$three_hop_runtime_integration_timed_out")"
    three_hop_runtime_integration_reason="$(failure_kind_to_reason "$three_hop_runtime_integration_failure_kind")"
    if (( final_rc == 0 )); then
      final_rc=$three_hop_runtime_integration_rc
    fi
  fi
else
  echo "[ci-phase1-resilience] step=three_hop_runtime_integration status=skip reason=disabled"
fi

final_failure_stage="none"
final_failure_kind="none"
if (( three_machine_matrix_rc != 0 )); then
  final_failure_stage="three_machine_docker_profile_matrix"
  final_failure_kind="$three_machine_matrix_failure_kind"
elif (( profile_compare_matrix_rc != 0 )); then
  final_failure_stage="profile_compare_docker_matrix"
  final_failure_kind="$profile_compare_matrix_failure_kind"
elif (( three_machine_matrix_record_rc != 0 )); then
  final_failure_stage="three_machine_docker_profile_matrix_record"
  final_failure_kind="$three_machine_matrix_record_failure_kind"
elif (( vpn_rc_matrix_rc != 0 )); then
  final_failure_stage="vpn_rc_matrix_path"
  final_failure_kind="$vpn_rc_matrix_failure_kind"
elif (( vpn_rc_resilience_rc != 0 )); then
  final_failure_stage="vpn_rc_resilience_path"
  final_failure_kind="$vpn_rc_resilience_failure_kind"
elif (( session_churn_guard_rc != 0 )); then
  final_failure_stage="session_churn_guard"
  final_failure_kind="$session_churn_guard_failure_kind"
elif (( three_hop_runtime_integration_rc != 0 )); then
  final_failure_stage="three_hop_runtime_integration"
  final_failure_kind="$three_hop_runtime_integration_failure_kind"
fi

final_status="pass"
if (( final_rc != 0 )); then
  final_status="fail"
fi

policy_no_go_allowance_applied="false"
if [[ "$allow_policy_no_go" == "1" && "$final_failure_kind" == "policy_no_go" && "$final_status" == "fail" ]]; then
  policy_no_go_allowance_applied="true"
  final_status="warn"
  final_rc=0
fi

policy_outcome_fail_closed_no_go="false"
if [[ "$final_failure_kind" == "policy_no_go" ]]; then
  policy_outcome_fail_closed_no_go="true"
fi
if [[ "$policy_no_go_allowance_applied" == "true" ]]; then
  policy_outcome_fail_closed_no_go="false"
fi

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg resume "$resume" \
  --arg dry_run "$dry_run" \
  --arg print_summary_json "$print_summary_json" \
  --arg allow_policy_no_go "$allow_policy_no_go" \
  --arg run_three_machine_docker_profile_matrix "$run_three_machine_docker_profile_matrix" \
  --arg run_profile_compare_docker_matrix "$run_profile_compare_docker_matrix" \
  --arg run_three_machine_docker_profile_matrix_record "$run_three_machine_docker_profile_matrix_record" \
  --arg run_vpn_rc_matrix_path "$run_vpn_rc_matrix_path" \
  --arg run_vpn_rc_resilience_path "$run_vpn_rc_resilience_path" \
  --arg run_session_churn_guard "$run_session_churn_guard" \
  --arg run_3hop_runtime_integration "$run_3hop_runtime_integration" \
  --argjson three_machine_docker_profile_matrix_timeout_sec "$three_machine_docker_profile_matrix_timeout_sec" \
  --argjson profile_compare_docker_matrix_timeout_sec "$profile_compare_docker_matrix_timeout_sec" \
  --argjson three_machine_docker_profile_matrix_record_timeout_sec "$three_machine_docker_profile_matrix_record_timeout_sec" \
  --argjson vpn_rc_matrix_path_timeout_sec "$vpn_rc_matrix_path_timeout_sec" \
  --argjson vpn_rc_resilience_path_timeout_sec "$vpn_rc_resilience_path_timeout_sec" \
  --argjson session_churn_guard_timeout_sec "$session_churn_guard_timeout_sec" \
  --argjson three_hop_runtime_integration_timeout_sec "$three_hop_runtime_integration_timeout_sec" \
  --arg three_machine_matrix_status "$three_machine_matrix_status" \
  --argjson three_machine_matrix_rc "$three_machine_matrix_rc" \
  --arg three_machine_matrix_reason "$three_machine_matrix_reason" \
  --arg three_machine_matrix_timed_out "$three_machine_matrix_timed_out" \
  --arg three_machine_matrix_reused "$three_machine_matrix_reused" \
  --arg three_machine_matrix_failure_kind "$three_machine_matrix_failure_kind" \
  --argjson three_machine_matrix_timeout_sec "$three_machine_matrix_timeout_sec" \
  --arg three_machine_matrix_command "$three_machine_matrix_command" \
  --arg three_machine_matrix_summary_json "$three_machine_matrix_summary_json" \
  --arg three_machine_matrix_report_md "$three_machine_matrix_report_md" \
  --arg profile_compare_matrix_status "$profile_compare_matrix_status" \
  --argjson profile_compare_matrix_rc "$profile_compare_matrix_rc" \
  --arg profile_compare_matrix_reason "$profile_compare_matrix_reason" \
  --arg profile_compare_matrix_timed_out "$profile_compare_matrix_timed_out" \
  --arg profile_compare_matrix_reused "$profile_compare_matrix_reused" \
  --arg profile_compare_matrix_failure_kind "$profile_compare_matrix_failure_kind" \
  --argjson profile_compare_matrix_timeout_sec "$profile_compare_matrix_timeout_sec" \
  --arg profile_compare_matrix_command "$profile_compare_matrix_command" \
  --arg profile_compare_matrix_summary_json "$profile_compare_matrix_summary_json" \
  --arg profile_compare_matrix_report_md "$profile_compare_matrix_report_md" \
  --arg three_machine_matrix_record_status "$three_machine_matrix_record_status" \
  --argjson three_machine_matrix_record_rc "$three_machine_matrix_record_rc" \
  --arg three_machine_matrix_record_reason "$three_machine_matrix_record_reason" \
  --arg three_machine_matrix_record_timed_out "$three_machine_matrix_record_timed_out" \
  --arg three_machine_matrix_record_reused "$three_machine_matrix_record_reused" \
  --arg three_machine_matrix_record_failure_kind "$three_machine_matrix_record_failure_kind" \
  --argjson three_machine_matrix_record_timeout_sec "$three_machine_matrix_record_timeout_sec" \
  --arg three_machine_matrix_record_command "$three_machine_matrix_record_command" \
  --arg three_machine_matrix_record_summary_json "$three_machine_matrix_record_summary_json" \
  --arg three_machine_matrix_record_matrix_summary_json "$three_machine_matrix_record_matrix_summary_json" \
  --arg vpn_rc_matrix_status "$vpn_rc_matrix_status" \
  --argjson vpn_rc_matrix_rc "$vpn_rc_matrix_rc" \
  --arg vpn_rc_matrix_reason "$vpn_rc_matrix_reason" \
  --arg vpn_rc_matrix_timed_out "$vpn_rc_matrix_timed_out" \
  --arg vpn_rc_matrix_reused "$vpn_rc_matrix_reused" \
  --arg vpn_rc_matrix_failure_kind "$vpn_rc_matrix_failure_kind" \
  --argjson vpn_rc_matrix_timeout_sec "$vpn_rc_matrix_timeout_sec" \
  --arg vpn_rc_matrix_command "$vpn_rc_matrix_command" \
  --arg vpn_rc_matrix_summary_json "$vpn_rc_matrix_summary_json" \
  --arg vpn_rc_resilience_status "$vpn_rc_resilience_status" \
  --argjson vpn_rc_resilience_rc "$vpn_rc_resilience_rc" \
  --arg vpn_rc_resilience_reason "$vpn_rc_resilience_reason" \
  --arg vpn_rc_resilience_timed_out "$vpn_rc_resilience_timed_out" \
  --arg vpn_rc_resilience_reused "$vpn_rc_resilience_reused" \
  --arg vpn_rc_resilience_failure_kind "$vpn_rc_resilience_failure_kind" \
  --argjson vpn_rc_resilience_timeout_sec "$vpn_rc_resilience_timeout_sec" \
  --arg vpn_rc_resilience_command "$vpn_rc_resilience_command" \
  --arg vpn_rc_resilience_summary_json "$vpn_rc_resilience_summary_json" \
  --arg session_churn_guard_status "$session_churn_guard_status" \
  --argjson session_churn_guard_rc "$session_churn_guard_rc" \
  --arg session_churn_guard_reason "$session_churn_guard_reason" \
  --arg session_churn_guard_timed_out "$session_churn_guard_timed_out" \
  --arg session_churn_guard_reused "$session_churn_guard_reused" \
  --arg session_churn_guard_failure_kind "$session_churn_guard_failure_kind" \
  --argjson session_churn_guard_step_timeout_sec "$session_churn_guard_step_timeout_sec" \
  --arg session_churn_guard_command "$session_churn_guard_command" \
  --arg three_hop_runtime_integration_status "$three_hop_runtime_integration_status" \
  --argjson three_hop_runtime_integration_rc "$three_hop_runtime_integration_rc" \
  --arg three_hop_runtime_integration_reason "$three_hop_runtime_integration_reason" \
  --arg three_hop_runtime_integration_timed_out "$three_hop_runtime_integration_timed_out" \
  --arg three_hop_runtime_integration_reused "$three_hop_runtime_integration_reused" \
  --arg three_hop_runtime_integration_failure_kind "$three_hop_runtime_integration_failure_kind" \
  --argjson three_hop_runtime_integration_step_timeout_sec "$three_hop_runtime_integration_step_timeout_sec" \
  --arg three_hop_runtime_integration_command "$three_hop_runtime_integration_command" \
  --arg final_failure_stage "$final_failure_stage" \
  --arg final_failure_kind "$final_failure_kind" \
  --arg policy_no_go_allowance_applied "$policy_no_go_allowance_applied" \
  --arg policy_outcome_fail_closed_no_go "$policy_outcome_fail_closed_no_go" \
  '{
    version: 1,
    schema: {
      id: "ci_phase1_resilience_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    automation: {
      track: "non_blockchain",
      requires_sudo: false,
      requires_github: false,
      automatable_without_sudo_or_github: true,
      notes: "Docker/runtime prerequisites may still apply for enabled stages."
    },
    inputs: {
      resume: ($resume == "1"),
      dry_run: ($dry_run == "1"),
      print_summary_json: ($print_summary_json == "1"),
      allow_policy_no_go: ($allow_policy_no_go == "1"),
      run_three_machine_docker_profile_matrix: ($run_three_machine_docker_profile_matrix == "1"),
      run_profile_compare_docker_matrix: ($run_profile_compare_docker_matrix == "1"),
      run_three_machine_docker_profile_matrix_record: ($run_three_machine_docker_profile_matrix_record == "1"),
      run_vpn_rc_matrix_path: ($run_vpn_rc_matrix_path == "1"),
      run_vpn_rc_resilience_path: ($run_vpn_rc_resilience_path == "1"),
      run_session_churn_guard: ($run_session_churn_guard == "1"),
      run_3hop_runtime_integration: ($run_3hop_runtime_integration == "1"),
      three_machine_docker_profile_matrix_timeout_sec: $three_machine_docker_profile_matrix_timeout_sec,
      profile_compare_docker_matrix_timeout_sec: $profile_compare_docker_matrix_timeout_sec,
      three_machine_docker_profile_matrix_record_timeout_sec: $three_machine_docker_profile_matrix_record_timeout_sec,
      vpn_rc_matrix_path_timeout_sec: $vpn_rc_matrix_path_timeout_sec,
      vpn_rc_resilience_path_timeout_sec: $vpn_rc_resilience_path_timeout_sec,
      session_churn_guard_timeout_sec: $session_churn_guard_timeout_sec,
      three_hop_runtime_integration_timeout_sec: $three_hop_runtime_integration_timeout_sec
    },
    steps: {
      three_machine_docker_profile_matrix: {
        enabled: ($run_three_machine_docker_profile_matrix == "1"),
        status: $three_machine_matrix_status,
        rc: $three_machine_matrix_rc,
        reason: (if $three_machine_matrix_reason == "" then null else $three_machine_matrix_reason end),
        reused_artifact: ($three_machine_matrix_reused == "true"),
        timed_out: ($three_machine_matrix_timed_out == "true"),
        failure_semantics: {
          kind: $three_machine_matrix_failure_kind,
          policy_no_go: ($three_machine_matrix_failure_kind == "policy_no_go"),
          execution_failure: ($three_machine_matrix_failure_kind == "execution_failure"),
          timeout: ($three_machine_matrix_failure_kind == "timeout")
        },
        timeout_sec: $three_machine_matrix_timeout_sec,
        command: (if $three_machine_matrix_command == "" then null else $three_machine_matrix_command end),
        artifacts: {
          summary_json: $three_machine_matrix_summary_json,
          report_md: $three_machine_matrix_report_md
        }
      },
      profile_compare_docker_matrix: {
        enabled: ($run_profile_compare_docker_matrix == "1"),
        status: $profile_compare_matrix_status,
        rc: $profile_compare_matrix_rc,
        reason: (if $profile_compare_matrix_reason == "" then null else $profile_compare_matrix_reason end),
        reused_artifact: ($profile_compare_matrix_reused == "true"),
        timed_out: ($profile_compare_matrix_timed_out == "true"),
        failure_semantics: {
          kind: $profile_compare_matrix_failure_kind,
          policy_no_go: ($profile_compare_matrix_failure_kind == "policy_no_go"),
          execution_failure: ($profile_compare_matrix_failure_kind == "execution_failure"),
          timeout: ($profile_compare_matrix_failure_kind == "timeout")
        },
        timeout_sec: $profile_compare_matrix_timeout_sec,
        command: (if $profile_compare_matrix_command == "" then null else $profile_compare_matrix_command end),
        artifacts: {
          summary_json: $profile_compare_matrix_summary_json,
          report_md: $profile_compare_matrix_report_md
        }
      },
      three_machine_docker_profile_matrix_record: {
        enabled: ($run_three_machine_docker_profile_matrix_record == "1"),
        status: $three_machine_matrix_record_status,
        rc: $three_machine_matrix_record_rc,
        reason: (if $three_machine_matrix_record_reason == "" then null else $three_machine_matrix_record_reason end),
        reused_artifact: ($three_machine_matrix_record_reused == "true"),
        timed_out: ($three_machine_matrix_record_timed_out == "true"),
        failure_semantics: {
          kind: $three_machine_matrix_record_failure_kind,
          policy_no_go: ($three_machine_matrix_record_failure_kind == "policy_no_go"),
          execution_failure: ($three_machine_matrix_record_failure_kind == "execution_failure"),
          timeout: ($three_machine_matrix_record_failure_kind == "timeout")
        },
        timeout_sec: $three_machine_matrix_record_timeout_sec,
        command: (if $three_machine_matrix_record_command == "" then null else $three_machine_matrix_record_command end),
        artifacts: {
          summary_json: $three_machine_matrix_record_summary_json,
          matrix_summary_json: $three_machine_matrix_record_matrix_summary_json
        }
      },
      vpn_rc_matrix_path: {
        enabled: ($run_vpn_rc_matrix_path == "1"),
        status: $vpn_rc_matrix_status,
        rc: $vpn_rc_matrix_rc,
        reason: (if $vpn_rc_matrix_reason == "" then null else $vpn_rc_matrix_reason end),
        reused_artifact: ($vpn_rc_matrix_reused == "true"),
        timed_out: ($vpn_rc_matrix_timed_out == "true"),
        failure_semantics: {
          kind: $vpn_rc_matrix_failure_kind,
          policy_no_go: ($vpn_rc_matrix_failure_kind == "policy_no_go"),
          execution_failure: ($vpn_rc_matrix_failure_kind == "execution_failure"),
          timeout: ($vpn_rc_matrix_failure_kind == "timeout")
        },
        timeout_sec: $vpn_rc_matrix_timeout_sec,
        command: (if $vpn_rc_matrix_command == "" then null else $vpn_rc_matrix_command end),
        artifacts: {
          summary_json: $vpn_rc_matrix_summary_json
        }
      },
      vpn_rc_resilience_path: {
        enabled: ($run_vpn_rc_resilience_path == "1"),
        status: $vpn_rc_resilience_status,
        rc: $vpn_rc_resilience_rc,
        reason: (if $vpn_rc_resilience_reason == "" then null else $vpn_rc_resilience_reason end),
        reused_artifact: ($vpn_rc_resilience_reused == "true"),
        timed_out: ($vpn_rc_resilience_timed_out == "true"),
        failure_semantics: {
          kind: $vpn_rc_resilience_failure_kind,
          policy_no_go: ($vpn_rc_resilience_failure_kind == "policy_no_go"),
          execution_failure: ($vpn_rc_resilience_failure_kind == "execution_failure"),
          timeout: ($vpn_rc_resilience_failure_kind == "timeout")
        },
        timeout_sec: $vpn_rc_resilience_timeout_sec,
        command: (if $vpn_rc_resilience_command == "" then null else $vpn_rc_resilience_command end),
        artifacts: {
          summary_json: $vpn_rc_resilience_summary_json
        }
      },
      session_churn_guard: {
        enabled: ($run_session_churn_guard == "1"),
        status: $session_churn_guard_status,
        rc: $session_churn_guard_rc,
        reason: (if $session_churn_guard_reason == "" then null else $session_churn_guard_reason end),
        reused_artifact: ($session_churn_guard_reused == "true"),
        timed_out: ($session_churn_guard_timed_out == "true"),
        failure_semantics: {
          kind: $session_churn_guard_failure_kind,
          policy_no_go: ($session_churn_guard_failure_kind == "policy_no_go"),
          execution_failure: ($session_churn_guard_failure_kind == "execution_failure"),
          timeout: ($session_churn_guard_failure_kind == "timeout")
        },
        timeout_sec: $session_churn_guard_step_timeout_sec,
        command: (if $session_churn_guard_command == "" then null else $session_churn_guard_command end),
        artifacts: {}
      },
      three_hop_runtime_integration: {
        enabled: ($run_3hop_runtime_integration == "1"),
        status: $three_hop_runtime_integration_status,
        rc: $three_hop_runtime_integration_rc,
        reason: (if $three_hop_runtime_integration_reason == "" then null else $three_hop_runtime_integration_reason end),
        reused_artifact: ($three_hop_runtime_integration_reused == "true"),
        timed_out: ($three_hop_runtime_integration_timed_out == "true"),
        failure_semantics: {
          kind: $three_hop_runtime_integration_failure_kind,
          policy_no_go: ($three_hop_runtime_integration_failure_kind == "policy_no_go"),
          execution_failure: ($three_hop_runtime_integration_failure_kind == "execution_failure"),
          timeout: ($three_hop_runtime_integration_failure_kind == "timeout")
        },
        timeout_sec: $three_hop_runtime_integration_step_timeout_sec,
        command: (if $three_hop_runtime_integration_command == "" then null else $three_hop_runtime_integration_command end),
        artifacts: {}
      }
    },
    failure: {
      stage: (if $final_failure_stage == "none" then null else $final_failure_stage end),
      kind: $final_failure_kind,
      policy_no_go: ($final_failure_kind == "policy_no_go"),
      execution_failure: ($final_failure_kind == "execution_failure"),
      timeout: ($final_failure_kind == "timeout")
    },
    policy_outcome: {
      fail_closed_no_go: ($policy_outcome_fail_closed_no_go == "true"),
      allow_policy_no_go_enabled: ($allow_policy_no_go == "1"),
      allow_policy_no_go_applied: ($policy_no_go_allowance_applied == "true")
    },
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

echo "[ci-phase1-resilience] status=$final_status rc=$final_rc dry_run=$dry_run"
echo "[ci-phase1-resilience] reports_dir=$reports_dir"
echo "[ci-phase1-resilience] summary_json=$summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
