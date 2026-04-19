#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/vpn_rc_resilience_path.sh \
    [--reports-dir DIR] \
    [--docker-summary-json PATH] \
    [--docker-report-md PATH] \
    [--rc-summary-json PATH] \
    [--summary-json PATH] \
    [--run-docker-profile-matrix [0|1]] \
    [--run-rc-matrix-path [0|1]] \
    [--signoff-fail-on-no-go [0|1]] \
    [--print-report [0|1]] \
    [--print-summary-json [0|1]] \
    [--dry-run [0|1]] \
    [--docker-profile-matrix-timeout-sec N] \
    [--rc-matrix-path-timeout-sec N] \
    [--docker-<arg> ...] \
    [--rc-<arg> ...]

Purpose:
  Run the VPN RC resilience chain in one command:
    1) three_machine_docker_profile_matrix.sh
    2) vpn_rc_matrix_path.sh

Notes:
  - One shared reports directory is used across both stages.
  - Wrapper always emits an aggregate summary JSON (unless dry-run).
  - Stage pass-through args use prefixes:
      --docker-...  -> forwarded to three_machine_docker_profile_matrix.sh
      --rc-...      -> forwarded to vpn_rc_matrix_path.sh
  - Reserved wrapper-owned stage args are not allowed via pass-through:
      docker: reports-dir, summary-json, report-md, print-summary-json, dry-run
      rc: reports-dir, summary-json, signoff-fail-on-no-go, print-report, print-summary-json, dry-run
  - RC compatibility aliases accepted for common typos:
      --rc-refresh-manual-validation -> --rc-roadmap-refresh-manual-validation
      --rc-refresh-single-machine-readiness -> --rc-roadmap-refresh-single-machine-readiness
  - Timeout values are in seconds. Timeout expiry fails closed with rc=124 and
    stage reason=timeout.
USAGE
}

trim() {
  local value="$1"
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

non_negative_int_arg_or_die() {
  local name="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be an integer >= 0"
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

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

json_file_valid() {
  local path="$1"
  [[ -f "$path" ]] && jq -e . "$path" >/dev/null 2>&1
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
  local name="$1"
  local timeout_sec="$2"
  shift 2
  local rc=0
  local timed_out="false"
  local reason=""
  echo "[vpn-rc-resilience-path] step=$name status=running timeout_sec=$timeout_sec"
  set +e
  run_with_timeout "$timeout_sec" "$@"
  rc=$?
  timed_out="$RUN_WITH_TIMEOUT_TIMED_OUT"
  set -e
  if (( rc == 0 )); then
    echo "[vpn-rc-resilience-path] step=$name status=pass rc=0"
    reason=""
  else
    if [[ "$timed_out" == "true" ]]; then
      reason="timeout"
    else
      reason="command-failed"
    fi
    echo "[vpn-rc-resilience-path] step=$name status=fail rc=$rc reason=$reason timeout_sec=$timeout_sec"
  fi
  RUN_STEP_REASON="$reason"
  RUN_STEP_TIMED_OUT="$timed_out"
  return "$rc"
}

reports_dir="${VPN_RC_RESILIENCE_PATH_REPORTS_DIR:-}"
docker_summary_json="${VPN_RC_RESILIENCE_PATH_DOCKER_SUMMARY_JSON:-}"
docker_report_md="${VPN_RC_RESILIENCE_PATH_DOCKER_REPORT_MD:-}"
rc_summary_json="${VPN_RC_RESILIENCE_PATH_RC_SUMMARY_JSON:-}"
summary_json="${VPN_RC_RESILIENCE_PATH_SUMMARY_JSON:-}"
run_docker_profile_matrix="${VPN_RC_RESILIENCE_PATH_RUN_DOCKER_PROFILE_MATRIX:-1}"
run_rc_matrix_path="${VPN_RC_RESILIENCE_PATH_RUN_RC_MATRIX_PATH:-1}"
signoff_fail_on_no_go="${VPN_RC_RESILIENCE_PATH_SIGNOFF_FAIL_ON_NO_GO:-1}"
print_report="${VPN_RC_RESILIENCE_PATH_PRINT_REPORT:-1}"
print_summary_json="${VPN_RC_RESILIENCE_PATH_PRINT_SUMMARY_JSON:-1}"
dry_run="${VPN_RC_RESILIENCE_PATH_DRY_RUN:-0}"
docker_profile_matrix_timeout_sec="${VPN_RC_RESILIENCE_PATH_DOCKER_PROFILE_MATRIX_TIMEOUT_SEC:-5400}"
rc_matrix_path_timeout_sec="${VPN_RC_RESILIENCE_PATH_RC_MATRIX_PATH_TIMEOUT_SEC:-5400}"

declare -a docker_passthrough_args=()
declare -a rc_passthrough_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      require_value_or_die "$1" "${2:-}"
      reports_dir="${2:-}"
      shift 2
      ;;
    --docker-summary-json)
      require_value_or_die "$1" "${2:-}"
      docker_summary_json="${2:-}"
      shift 2
      ;;
    --docker-report-md)
      require_value_or_die "$1" "${2:-}"
      docker_report_md="${2:-}"
      shift 2
      ;;
    --rc-summary-json)
      require_value_or_die "$1" "${2:-}"
      rc_summary_json="${2:-}"
      shift 2
      ;;
    --summary-json)
      require_value_or_die "$1" "${2:-}"
      summary_json="${2:-}"
      shift 2
      ;;
    --run-docker-profile-matrix)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_docker_profile_matrix="${2:-}"
        shift 2
      else
        run_docker_profile_matrix="1"
        shift
      fi
      ;;
    --run-rc-matrix-path)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_rc_matrix_path="${2:-}"
        shift 2
      else
        run_rc_matrix_path="1"
        shift
      fi
      ;;
    --signoff-fail-on-no-go)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_fail_on_no_go="${2:-}"
        shift 2
      else
        signoff_fail_on_no_go="1"
        shift
      fi
      ;;
    --print-report)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_report="${2:-}"
        shift 2
      else
        print_report="1"
        shift
      fi
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
    --dry-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        dry_run="${2:-}"
        shift 2
      else
        dry_run="1"
        shift
      fi
      ;;
    --docker-profile-matrix-timeout-sec)
      require_value_or_die "$1" "${2:-}"
      docker_profile_matrix_timeout_sec="${2:-}"
      shift 2
      ;;
    --rc-matrix-path-timeout-sec)
      require_value_or_die "$1" "${2:-}"
      rc_matrix_path_timeout_sec="${2:-}"
      shift 2
      ;;
    --docker-*)
      forwarded_flag="--${1#--docker-}"
      case "$forwarded_flag" in
        --reports-dir|--summary-json|--report-md|--print-summary-json|--dry-run)
          echo "$1 is reserved by vpn_rc_resilience_path.sh"
          exit 2
          ;;
      esac
      if [[ "$forwarded_flag" == "--" ]]; then
        echo "invalid docker-prefixed arg: $1"
        exit 2
      fi
      if [[ $# -ge 2 && ! "${2:-}" =~ ^-- ]]; then
        docker_passthrough_args+=("$forwarded_flag" "${2:-}")
        shift 2
      else
        docker_passthrough_args+=("$forwarded_flag")
        shift
      fi
      ;;
    --rc-*)
      forwarded_flag="--${1#--rc-}"
      case "$forwarded_flag" in
        --refresh-manual-validation)
          forwarded_flag="--roadmap-refresh-manual-validation"
          ;;
        --refresh-single-machine-readiness)
          forwarded_flag="--roadmap-refresh-single-machine-readiness"
          ;;
      esac
      case "$forwarded_flag" in
        --reports-dir|--summary-json|--signoff-fail-on-no-go|--print-report|--print-summary-json|--dry-run)
          echo "$1 is reserved by vpn_rc_resilience_path.sh"
          exit 2
          ;;
      esac
      if [[ "$forwarded_flag" == "--" ]]; then
        echo "invalid rc-prefixed arg: $1"
        exit 2
      fi
      if [[ $# -ge 2 && ! "${2:-}" =~ ^-- ]]; then
        rc_passthrough_args+=("$forwarded_flag" "${2:-}")
        shift 2
      else
        rc_passthrough_args+=("$forwarded_flag")
        shift
      fi
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown arg: $1"
      usage
      exit 2
      ;;
  esac
done

bool_arg_or_die "--run-docker-profile-matrix" "$run_docker_profile_matrix"
bool_arg_or_die "--run-rc-matrix-path" "$run_rc_matrix_path"
bool_arg_or_die "--signoff-fail-on-no-go" "$signoff_fail_on_no_go"
bool_arg_or_die "--print-report" "$print_report"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--dry-run" "$dry_run"
non_negative_int_arg_or_die "--docker-profile-matrix-timeout-sec" "$docker_profile_matrix_timeout_sec"
non_negative_int_arg_or_die "--rc-matrix-path-timeout-sec" "$rc_matrix_path_timeout_sec"

need_cmd jq
need_cmd date
need_cmd mktemp

docker_profile_matrix_script="${VPN_RC_RESILIENCE_PATH_DOCKER_PROFILE_MATRIX_SCRIPT:-$ROOT_DIR/scripts/three_machine_docker_profile_matrix.sh}"
rc_matrix_path_script="${VPN_RC_RESILIENCE_PATH_RC_MATRIX_PATH_SCRIPT:-$ROOT_DIR/scripts/vpn_rc_matrix_path.sh}"

if [[ ! -x "$docker_profile_matrix_script" ]]; then
  echo "missing executable docker profile matrix script: $docker_profile_matrix_script"
  exit 2
fi
if [[ ! -x "$rc_matrix_path_script" ]]; then
  echo "missing executable rc matrix path script: $rc_matrix_path_script"
  exit 2
fi

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/vpn_rc_resilience_${run_stamp}"
fi
reports_dir="$(abs_path "$reports_dir")"

if [[ -n "$docker_summary_json" ]]; then
  docker_summary_json="$(abs_path "$docker_summary_json")"
else
  docker_summary_json="$reports_dir/three_machine_docker_profile_matrix_summary.json"
fi
if [[ -n "$docker_report_md" ]]; then
  docker_report_md="$(abs_path "$docker_report_md")"
else
  docker_report_md="$reports_dir/three_machine_docker_profile_matrix_report.md"
fi
if [[ -n "$rc_summary_json" ]]; then
  rc_summary_json="$(abs_path "$rc_summary_json")"
else
  rc_summary_json="$reports_dir/vpn_rc_matrix_path_summary.json"
fi
if [[ -n "$summary_json" ]]; then
  summary_json="$(abs_path "$summary_json")"
else
  summary_json="$reports_dir/vpn_rc_resilience_path_summary.json"
fi

mkdir -p "$reports_dir"
mkdir -p "$(dirname "$docker_summary_json")"
mkdir -p "$(dirname "$docker_report_md")"
mkdir -p "$(dirname "$rc_summary_json")"
mkdir -p "$(dirname "$summary_json")"

docker_cmd=(
  "$docker_profile_matrix_script"
  --reports-dir "$reports_dir"
  --summary-json "$docker_summary_json"
  --report-md "$docker_report_md"
  --print-summary-json 0
)
if [[ "${#docker_passthrough_args[@]}" -gt 0 ]]; then
  docker_cmd+=("${docker_passthrough_args[@]}")
fi

rc_cmd=(
  "$rc_matrix_path_script"
  --reports-dir "$reports_dir"
  --summary-json "$rc_summary_json"
  --signoff-fail-on-no-go "$signoff_fail_on_no_go"
  --print-report "$print_report"
  --print-summary-json 0
)
if [[ "${#rc_passthrough_args[@]}" -gt 0 ]]; then
  rc_cmd+=("${rc_passthrough_args[@]}")
fi

if [[ "$dry_run" == "1" ]]; then
  docker_passthrough_print="$(print_cmd "${docker_passthrough_args[@]}")"
  rc_passthrough_print="$(print_cmd "${rc_passthrough_args[@]}")"
  echo "[vpn-rc-resilience-path] dry-run=1"
  echo "[vpn-rc-resilience-path] run_docker_profile_matrix=$run_docker_profile_matrix"
  echo "[vpn-rc-resilience-path] run_rc_matrix_path=$run_rc_matrix_path"
  echo "[vpn-rc-resilience-path] signoff_fail_on_no_go=$signoff_fail_on_no_go"
  echo "[vpn-rc-resilience-path] docker_profile_matrix_timeout_sec=$docker_profile_matrix_timeout_sec"
  echo "[vpn-rc-resilience-path] rc_matrix_path_timeout_sec=$rc_matrix_path_timeout_sec"
  echo "[vpn-rc-resilience-path] reports_dir=$reports_dir"
  echo "[vpn-rc-resilience-path] docker_summary_json=$docker_summary_json"
  echo "[vpn-rc-resilience-path] docker_report_md=$docker_report_md"
  echo "[vpn-rc-resilience-path] rc_summary_json=$rc_summary_json"
  echo "[vpn-rc-resilience-path] summary_json=$summary_json"
  echo "[vpn-rc-resilience-path] docker_passthrough_args=${docker_passthrough_print:-}"
  echo "[vpn-rc-resilience-path] rc_passthrough_args=${rc_passthrough_print:-}"
  printf '[vpn-rc-resilience-path] docker_cmd: '
  print_cmd "${docker_cmd[@]}"
  printf '[vpn-rc-resilience-path] rc_cmd: '
  print_cmd "${rc_cmd[@]}"
  exit 0
fi

docker_rc=0
rc_rc=0
docker_status="skip"
rc_status="skip"
docker_reason="disabled"
rc_reason="disabled"
docker_timed_out="false"
rc_timed_out="false"

if [[ "$run_docker_profile_matrix" == "1" ]]; then
  if run_step "three_machine_docker_profile_matrix" "$docker_profile_matrix_timeout_sec" "${docker_cmd[@]}"; then
    docker_status="pass"
    docker_reason=""
    docker_timed_out="$RUN_STEP_TIMED_OUT"
  else
    docker_rc=$?
    docker_status="fail"
    docker_reason="$RUN_STEP_REASON"
    docker_timed_out="$RUN_STEP_TIMED_OUT"
  fi
else
  echo "[vpn-rc-resilience-path] step=three_machine_docker_profile_matrix status=skip reason=disabled"
fi

if [[ "$run_rc_matrix_path" == "1" ]]; then
  if run_step "vpn_rc_matrix_path" "$rc_matrix_path_timeout_sec" "${rc_cmd[@]}"; then
    rc_status="pass"
    rc_reason=""
    rc_timed_out="$RUN_STEP_TIMED_OUT"
  else
    rc_rc=$?
    rc_status="fail"
    rc_reason="$RUN_STEP_REASON"
    rc_timed_out="$RUN_STEP_TIMED_OUT"
  fi
else
  echo "[vpn-rc-resilience-path] step=vpn_rc_matrix_path status=skip reason=disabled"
fi

final_rc=0
if [[ "$run_docker_profile_matrix" == "1" && "$docker_rc" != "0" ]]; then
  final_rc="$docker_rc"
fi
if [[ "$run_rc_matrix_path" == "1" && "$rc_rc" != "0" && "$final_rc" == "0" ]]; then
  final_rc="$rc_rc"
fi

final_status="pass"
if [[ "$final_rc" != "0" ]]; then
  final_status="fail"
fi

docker_profiles_total=""
docker_profiles_pass=""
docker_profiles_fail=""
if [[ -f "$docker_summary_json" ]] && jq -e . "$docker_summary_json" >/dev/null 2>&1; then
  docker_profiles_total="$(jq -r 'if (.summary.profiles_total? | type) == "number" then (.summary.profiles_total | tostring) else "" end' "$docker_summary_json" 2>/dev/null || true)"
  docker_profiles_pass="$(jq -r 'if (.summary.profiles_pass? | type) == "number" then (.summary.profiles_pass | tostring) else "" end' "$docker_summary_json" 2>/dev/null || true)"
  docker_profiles_fail="$(jq -r 'if (.summary.profiles_fail? | type) == "number" then (.summary.profiles_fail | tostring) else "" end' "$docker_summary_json" 2>/dev/null || true)"
fi

rc_signoff_decision=""
rc_roadmap_stage=""
rc_readiness_status=""
if [[ -f "$rc_summary_json" ]] && jq -e . "$rc_summary_json" >/dev/null 2>&1; then
  rc_signoff_decision="$(jq -r '.steps.profile_compare_campaign_signoff.decision // ""' "$rc_summary_json" 2>/dev/null || true)"
  rc_roadmap_stage="$(jq -r '.steps.roadmap_progress_report.roadmap_stage // ""' "$rc_summary_json" 2>/dev/null || true)"
  rc_readiness_status="$(jq -r '.steps.roadmap_progress_report.readiness_status // ""' "$rc_summary_json" 2>/dev/null || true)"
fi

# Resilience handoff booleans for downstream gates.
# Semantics:
#   - profile_matrix_stable: docker profile matrix stage is stable/passing.
#   - peer_loss_recovery_ok: peer-loss failover checks are passing/covered.
#   - session_churn_guard_ok: RC path stage indicates session churn guard is healthy.
profile_matrix_stable="false"
profile_matrix_stable_source="docker_stage_disabled_or_failed"
peer_loss_recovery_ok="false"
peer_loss_recovery_ok_source="docker_stage_disabled_or_failed"
session_churn_guard_ok="false"
session_churn_guard_ok_source="rc_stage_disabled_or_failed"
docker_stage_pass="false"
docker_allow_artifact_positive="false"
if [[ "$run_docker_profile_matrix" == "0" ]]; then
  docker_allow_artifact_positive="true"
fi

if [[ "$run_docker_profile_matrix" == "1" && "$docker_status" == "pass" && "$docker_rc" == "0" ]]; then
  docker_stage_pass="true"
  docker_allow_artifact_positive="true"
  profile_matrix_stable="true"
  profile_matrix_stable_source="docker_stage_status"
  peer_loss_recovery_ok="true"
  peer_loss_recovery_ok_source="docker_stage_status"
fi

if json_file_valid "$docker_summary_json"; then
  docker_profile_matrix_stable="$(jq -r 'if (.resilience.profile_matrix_stable? | type) == "boolean" then (if .resilience.profile_matrix_stable then "true" else "false" end) else "" end' "$docker_summary_json" 2>/dev/null || true)"
  if [[ -n "$docker_profile_matrix_stable" ]]; then
    if [[ "$docker_allow_artifact_positive" == "true" && "$docker_profile_matrix_stable" == "true" ]]; then
      profile_matrix_stable="true"
    else
      profile_matrix_stable="false"
    fi
    profile_matrix_stable_source="docker_summary.resilience.profile_matrix_stable"
  else
    docker_decision_pass="$(jq -r 'if (.decision.pass? | type) == "boolean" then (if .decision.pass then "true" else "false" end) else "" end' "$docker_summary_json" 2>/dev/null || true)"
    if [[ -n "$docker_decision_pass" ]]; then
      if [[ "$docker_allow_artifact_positive" == "true" && "$docker_decision_pass" == "true" ]]; then
        profile_matrix_stable="true"
      else
        profile_matrix_stable="false"
      fi
      profile_matrix_stable_source="docker_summary.decision.pass"
    else
      docker_profiles_fail_value="$(jq -r 'if (.summary.profiles_fail? | type) == "number" then (.summary.profiles_fail | tostring) else "" end' "$docker_summary_json" 2>/dev/null || true)"
      if [[ -n "$docker_profiles_fail_value" ]]; then
        if [[ "$docker_allow_artifact_positive" == "true" && "$docker_profiles_fail_value" == "0" ]]; then
          profile_matrix_stable="true"
        else
          profile_matrix_stable="false"
        fi
        profile_matrix_stable_source="docker_summary.summary.profiles_fail"
      fi
    fi
  fi

  docker_peer_loss_override="$(jq -r 'if (.resilience.peer_loss_recovery_ok? | type) == "boolean" then (if .resilience.peer_loss_recovery_ok then "true" else "false" end) else "" end' "$docker_summary_json" 2>/dev/null || true)"
  if [[ -n "$docker_peer_loss_override" ]]; then
    if [[ "$docker_allow_artifact_positive" == "true" && "$docker_peer_loss_override" == "true" ]]; then
      peer_loss_recovery_ok="true"
    else
      peer_loss_recovery_ok="false"
    fi
    peer_loss_recovery_ok_source="docker_summary.resilience.peer_loss_recovery_ok"
  else
    docker_run_peer_failover="$(jq -r 'if (.inputs.run_peer_failover? | type) == "boolean" then (if .inputs.run_peer_failover then "true" else "false" end) else "" end' "$docker_summary_json" 2>/dev/null || true)"
    if [[ "$docker_run_peer_failover" == "false" ]]; then
      peer_loss_recovery_ok="false"
      peer_loss_recovery_ok_source="docker_summary.inputs.run_peer_failover"
    else
      peer_failover_pass_count=0
      peer_failover_fail_count=0
      peer_failover_skip_count=0
      mapfile -t profile_summary_paths < <(jq -r '.profiles[]?.artifacts.summary_json // empty' "$docker_summary_json" 2>/dev/null || true)
      for profile_summary_path in "${profile_summary_paths[@]}"; do
        [[ -z "$profile_summary_path" ]] && continue
        resolved_profile_summary_path="$profile_summary_path"
        if [[ "$resolved_profile_summary_path" != /* ]]; then
          resolved_profile_summary_path="$(abs_path "$resolved_profile_summary_path")"
        fi
        if ! json_file_valid "$resolved_profile_summary_path"; then
          continue
        fi
        peer_failover_status="$(jq -r '(.steps // []) | map(select((.step_id // "") == "peer_failover")) | .[0].status // ""' "$resolved_profile_summary_path" 2>/dev/null || true)"
        case "$peer_failover_status" in
          pass)
            peer_failover_pass_count=$((peer_failover_pass_count + 1))
            ;;
          fail)
            peer_failover_fail_count=$((peer_failover_fail_count + 1))
            ;;
          skip)
            peer_failover_skip_count=$((peer_failover_skip_count + 1))
            ;;
        esac
      done
      if [[ "$peer_failover_fail_count" != "0" ]]; then
        peer_loss_recovery_ok="false"
        peer_loss_recovery_ok_source="docker_profile_summaries.peer_failover_status"
      elif [[ "$peer_failover_pass_count" != "0" ]]; then
        if [[ "$docker_allow_artifact_positive" == "true" ]]; then
          peer_loss_recovery_ok="true"
        else
          peer_loss_recovery_ok="false"
        fi
        peer_loss_recovery_ok_source="docker_profile_summaries.peer_failover_status"
      elif [[ "$peer_failover_skip_count" != "0" ]]; then
        peer_loss_recovery_ok="false"
        peer_loss_recovery_ok_source="docker_profile_summaries.peer_failover_skipped"
      elif [[ "$docker_stage_pass" == "true" ]]; then
        peer_loss_recovery_ok="true"
        peer_loss_recovery_ok_source="docker_stage_status_fallback"
      else
        peer_loss_recovery_ok="false"
        peer_loss_recovery_ok_source="docker_stage_status_fallback"
      fi
    fi
  fi
fi

if [[ "$run_rc_matrix_path" == "1" && "$rc_status" == "pass" && "$rc_rc" == "0" ]]; then
  session_churn_guard_ok="true"
  session_churn_guard_ok_source="rc_stage_status"
fi

if json_file_valid "$rc_summary_json"; then
  rc_session_churn_override="$(jq -r 'if (.resilience.session_churn_guard_ok? | type) == "boolean" then (if .resilience.session_churn_guard_ok then "true" else "false" end) else "" end' "$rc_summary_json" 2>/dev/null || true)"
  if [[ -n "$rc_session_churn_override" ]]; then
    if [[ "$rc_session_churn_override" == "true" ]]; then
      session_churn_guard_ok="true"
    else
      session_churn_guard_ok="false"
    fi
    session_churn_guard_ok_source="rc_summary.resilience.session_churn_guard_ok"
  else
    rc_session_churn_step_status="$(jq -r '.steps.session_churn_guard.status // ""' "$rc_summary_json" 2>/dev/null || true)"
    if [[ -n "$rc_session_churn_step_status" ]]; then
      if [[ "$rc_session_churn_step_status" == "pass" ]]; then
        session_churn_guard_ok="true"
      else
        session_churn_guard_ok="false"
      fi
      session_churn_guard_ok_source="rc_summary.steps.session_churn_guard.status"
    fi
  fi
fi

docker_passthrough_json="$(printf '%s\n' "${docker_passthrough_args[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"
rc_passthrough_json="$(printf '%s\n' "${rc_passthrough_args[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg final_status "$final_status" \
  --argjson final_rc "$final_rc" \
  --arg reports_dir "$reports_dir" \
  --arg docker_summary_json "$docker_summary_json" \
  --arg docker_report_md "$docker_report_md" \
  --arg rc_summary_json "$rc_summary_json" \
  --arg summary_json "$summary_json" \
  --arg run_docker_profile_matrix "$run_docker_profile_matrix" \
  --arg run_rc_matrix_path "$run_rc_matrix_path" \
  --arg signoff_fail_on_no_go "$signoff_fail_on_no_go" \
  --arg print_report "$print_report" \
  --arg print_summary_json "$print_summary_json" \
  --arg dry_run "$dry_run" \
  --argjson docker_profile_matrix_timeout_sec "$docker_profile_matrix_timeout_sec" \
  --argjson rc_matrix_path_timeout_sec "$rc_matrix_path_timeout_sec" \
  --arg docker_status "$docker_status" \
  --argjson docker_rc "$docker_rc" \
  --arg docker_reason "$docker_reason" \
  --arg docker_timed_out "$docker_timed_out" \
  --arg docker_profiles_total "$docker_profiles_total" \
  --arg docker_profiles_pass "$docker_profiles_pass" \
  --arg docker_profiles_fail "$docker_profiles_fail" \
  --arg rc_status "$rc_status" \
  --argjson rc_rc "$rc_rc" \
  --arg rc_reason "$rc_reason" \
  --arg rc_timed_out "$rc_timed_out" \
  --arg rc_signoff_decision "$rc_signoff_decision" \
  --arg rc_roadmap_stage "$rc_roadmap_stage" \
  --arg rc_readiness_status "$rc_readiness_status" \
  --argjson profile_matrix_stable "$profile_matrix_stable" \
  --arg profile_matrix_stable_source "$profile_matrix_stable_source" \
  --argjson peer_loss_recovery_ok "$peer_loss_recovery_ok" \
  --arg peer_loss_recovery_ok_source "$peer_loss_recovery_ok_source" \
  --argjson session_churn_guard_ok "$session_churn_guard_ok" \
  --arg session_churn_guard_ok_source "$session_churn_guard_ok_source" \
  --argjson docker_passthrough_args "$docker_passthrough_json" \
  --argjson rc_passthrough_args "$rc_passthrough_json" \
  '{
    version: 1,
    generated_at_utc: $generated_at_utc,
    status: $final_status,
    rc: $final_rc,
    profile_matrix_stable: $profile_matrix_stable,
    peer_loss_recovery_ok: $peer_loss_recovery_ok,
    session_churn_guard_ok: $session_churn_guard_ok,
    resilience_handoff: {
      profile_matrix_stable: $profile_matrix_stable,
      peer_loss_recovery_ok: $peer_loss_recovery_ok,
      session_churn_guard_ok: $session_churn_guard_ok,
      derivation: {
        profile_matrix_stable: $profile_matrix_stable_source,
        peer_loss_recovery_ok: $peer_loss_recovery_ok_source,
        session_churn_guard_ok: $session_churn_guard_ok_source
      }
    },
    inputs: {
      run_docker_profile_matrix: ($run_docker_profile_matrix == "1"),
      run_rc_matrix_path: ($run_rc_matrix_path == "1"),
      signoff_fail_on_no_go: ($signoff_fail_on_no_go == "1"),
      print_report: ($print_report == "1"),
      print_summary_json: ($print_summary_json == "1"),
      dry_run: ($dry_run == "1"),
      docker_profile_matrix_timeout_sec: $docker_profile_matrix_timeout_sec,
      rc_matrix_path_timeout_sec: $rc_matrix_path_timeout_sec,
      docker_passthrough_args: $docker_passthrough_args,
      rc_passthrough_args: $rc_passthrough_args
    },
    steps: {
      three_machine_docker_profile_matrix: {
        enabled: ($run_docker_profile_matrix == "1"),
        status: $docker_status,
        rc: $docker_rc,
        reason: (if $docker_reason == "" then null else $docker_reason end),
        timed_out: ($docker_timed_out == "true"),
        timeout_sec: $docker_profile_matrix_timeout_sec,
        summary: {
          profiles_total: (if $docker_profiles_total == "" then null else ($docker_profiles_total | tonumber) end),
          profiles_pass: (if $docker_profiles_pass == "" then null else ($docker_profiles_pass | tonumber) end),
          profiles_fail: (if $docker_profiles_fail == "" then null else ($docker_profiles_fail | tonumber) end)
        }
      },
      vpn_rc_matrix_path: {
        enabled: ($run_rc_matrix_path == "1"),
        status: $rc_status,
        rc: $rc_rc,
        reason: (if $rc_reason == "" then null else $rc_reason end),
        timed_out: ($rc_timed_out == "true"),
        timeout_sec: $rc_matrix_path_timeout_sec,
        signoff_decision: $rc_signoff_decision,
        roadmap_stage: $rc_roadmap_stage,
        readiness_status: $rc_readiness_status
      }
    },
    artifacts: {
      reports_dir: $reports_dir,
      docker_summary_json: $docker_summary_json,
      docker_report_md: $docker_report_md,
      rc_summary_json: $rc_summary_json,
      summary_json: $summary_json
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

echo "[vpn-rc-resilience-path] status=$final_status rc=$final_rc"
echo "[vpn-rc-resilience-path] reports_dir=$reports_dir"
echo "[vpn-rc-resilience-path] docker_summary_json=$docker_summary_json"
echo "[vpn-rc-resilience-path] docker_report_md=$docker_report_md"
echo "[vpn-rc-resilience-path] rc_summary_json=$rc_summary_json"
echo "[vpn-rc-resilience-path] summary_json=$summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
