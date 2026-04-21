#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/single_machine_prod_readiness.sh \
    [--step-timeout-sec N] \
    [--run-ci-local 0|1] \
    [--run-beta-preflight 0|1] \
    [--run-deep-suite 0|1] \
    [--run-runtime-fix-record 0|1] \
    [--run-three-machine-docker-readiness auto|0|1] \
    [--three-machine-docker-readiness-run-validate 0|1] \
    [--three-machine-docker-readiness-run-soak 0|1] \
    [--three-machine-docker-readiness-run-peer-failover 0|1] \
    [--three-machine-docker-readiness-peer-failover-downtime-sec N] \
    [--three-machine-docker-readiness-peer-failover-timeout-sec N] \
    [--three-machine-docker-readiness-soak-rounds N] \
    [--three-machine-docker-readiness-soak-pause-sec N] \
    [--three-machine-docker-readiness-path-profile speed|balanced|private] \
    [--three-machine-docker-readiness-keep-stacks 0|1] \
    [--three-machine-docker-readiness-summary-json PATH] \
    [--run-profile-compare-campaign-signoff auto|0|1] \
    [--profile-compare-campaign-signoff-refresh-campaign 0|1] \
    [--profile-compare-campaign-signoff-fail-on-no-go 0|1] \
    [--profile-compare-campaign-signoff-require-selection-policy-present 0|1] \
    [--profile-compare-campaign-signoff-require-selection-policy-valid 0|1] \
    [--profile-compare-campaign-signoff-reports-dir PATH] \
    [--profile-compare-campaign-signoff-summary-json PATH] \
    [--profile-compare-campaign-signoff-campaign-execution-mode auto|docker|local] \
    [--profile-compare-campaign-signoff-campaign-directory-urls URL[,URL...]] \
    [--profile-compare-campaign-signoff-campaign-bootstrap-directory URL] \
    [--profile-compare-campaign-signoff-campaign-discovery-wait-sec N] \
    [--profile-compare-campaign-signoff-campaign-issuer-url URL] \
    [--profile-compare-campaign-signoff-campaign-entry-url URL] \
    [--profile-compare-campaign-signoff-campaign-exit-url URL] \
    [--profile-compare-campaign-signoff-campaign-start-local-stack auto|0|1] \
    [--run-pre-real-host-readiness auto|0|1] \
    [--run-real-wg-privileged-matrix auto|0|1] \
    [--beta-preflight-privileged auto|0|1] \
    [--summary-json PATH] \
    [--manual-validation-report-summary-json PATH] \
    [--manual-validation-report-md PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Run all production-grade checks that are feasible on a single machine,
  then report exactly what remains blocked by multi-machine requirements.

Behavior notes:
  - In profile signoff auto mode, if campaign artifacts are missing the script
    forces one refresh pass to bootstrap those artifacts.
  - `--profile-compare-campaign-signoff-refresh-campaign 1` means "attempt
    campaign refresh now"; `0` means "reuse existing artifacts" unless auto
    mode escalates to refresh for stale/missing data.
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

tri_state_or_die() {
  local name="$1"
  local value="$2"
  case "$value" in
    auto|0|1) ;;
    *)
      echo "$name must be one of: auto, 0, 1"
      exit 2
      ;;
  esac
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

validate_manual_validation_report_summary_payload() {
  local payload="$1"
  local schema_id=""
  local schema_major=""

  if [[ -z "$payload" ]]; then
    return 1
  fi
  if ! jq -e . >/dev/null 2>&1 <<<"$payload"; then
    return 1
  fi

  schema_id="$(printf '%s\n' "$payload" | jq -r '.schema.id // ""' 2>/dev/null || true)"
  if [[ -n "$schema_id" && "$schema_id" != "manual_validation_readiness_summary" ]]; then
    return 1
  fi
  schema_major="$(printf '%s\n' "$payload" | jq -r '.schema.major // ""' 2>/dev/null || true)"
  if [[ -n "$schema_major" ]]; then
    if [[ ! "$schema_major" =~ ^[0-9]+$ ]] || (( schema_major > 1 )); then
      return 1
    fi
  fi

  if ! printf '%s\n' "$payload" | jq -e '
      (.summary | type) == "object"
      and (.report.readiness_status | type) == "string"
      and ((.report.readiness_status | length) > 0)
      and ((.checks | type) == "array")
    ' >/dev/null 2>&1; then
    return 1
  fi

  return 0
}

run_ci_local="1"
run_beta_preflight="1"
run_deep_suite="1"
run_runtime_fix_record="1"
step_timeout_sec="${SINGLE_MACHINE_STEP_TIMEOUT_SEC:-5400}"
run_three_machine_docker_readiness="auto"
three_machine_docker_readiness_run_validate="1"
three_machine_docker_readiness_run_soak="1"
three_machine_docker_readiness_run_peer_failover="1"
three_machine_docker_readiness_peer_failover_downtime_sec="8"
three_machine_docker_readiness_peer_failover_timeout_sec="45"
three_machine_docker_readiness_soak_rounds="6"
three_machine_docker_readiness_soak_pause_sec="3"
three_machine_docker_readiness_path_profile="balanced"
three_machine_docker_readiness_keep_stacks="0"
three_machine_docker_readiness_summary_json=""
run_profile_compare_campaign_signoff="auto"
profile_compare_campaign_signoff_refresh_campaign="0"
profile_compare_campaign_signoff_fail_on_no_go="1"
profile_compare_campaign_signoff_require_selection_policy_present="${SINGLE_MACHINE_PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_SELECTION_POLICY_PRESENT:-1}"
profile_compare_campaign_signoff_require_selection_policy_valid="${SINGLE_MACHINE_PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_SELECTION_POLICY_VALID:-1}"
profile_compare_campaign_signoff_reports_dir="$ROOT_DIR/.easy-node-logs"
profile_compare_campaign_signoff_summary_json=""
profile_compare_campaign_signoff_campaign_execution_mode="auto"
profile_compare_campaign_signoff_campaign_directory_urls=""
profile_compare_campaign_signoff_campaign_bootstrap_directory=""
profile_compare_campaign_signoff_campaign_discovery_wait_sec=""
profile_compare_campaign_signoff_campaign_issuer_url=""
profile_compare_campaign_signoff_campaign_entry_url=""
profile_compare_campaign_signoff_campaign_exit_url=""
profile_compare_campaign_signoff_campaign_start_local_stack=""
run_pre_real_host_readiness="auto"
run_real_wg_privileged_matrix="auto"
beta_preflight_privileged="auto"
print_summary_json="0"
summary_json=""
manual_validation_report_summary_json=""
manual_validation_report_md=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-ci-local)
      run_ci_local="${2:-}"
      shift 2
      ;;
    --run-beta-preflight)
      run_beta_preflight="${2:-}"
      shift 2
      ;;
    --run-deep-suite)
      run_deep_suite="${2:-}"
      shift 2
      ;;
    --run-runtime-fix-record)
      run_runtime_fix_record="${2:-}"
      shift 2
      ;;
    --step-timeout-sec)
      step_timeout_sec="${2:-}"
      shift 2
      ;;
    --run-three-machine-docker-readiness)
      run_three_machine_docker_readiness="${2:-}"
      shift 2
      ;;
    --three-machine-docker-readiness-run-validate)
      three_machine_docker_readiness_run_validate="${2:-}"
      shift 2
      ;;
    --three-machine-docker-readiness-run-soak)
      three_machine_docker_readiness_run_soak="${2:-}"
      shift 2
      ;;
    --three-machine-docker-readiness-run-peer-failover)
      three_machine_docker_readiness_run_peer_failover="${2:-}"
      shift 2
      ;;
    --three-machine-docker-readiness-peer-failover-downtime-sec)
      three_machine_docker_readiness_peer_failover_downtime_sec="${2:-}"
      shift 2
      ;;
    --three-machine-docker-readiness-peer-failover-timeout-sec)
      three_machine_docker_readiness_peer_failover_timeout_sec="${2:-}"
      shift 2
      ;;
    --three-machine-docker-readiness-soak-rounds)
      three_machine_docker_readiness_soak_rounds="${2:-}"
      shift 2
      ;;
    --three-machine-docker-readiness-soak-pause-sec)
      three_machine_docker_readiness_soak_pause_sec="${2:-}"
      shift 2
      ;;
    --three-machine-docker-readiness-path-profile)
      three_machine_docker_readiness_path_profile="${2:-}"
      shift 2
      ;;
    --three-machine-docker-readiness-keep-stacks)
      three_machine_docker_readiness_keep_stacks="${2:-}"
      shift 2
      ;;
    --three-machine-docker-readiness-summary-json)
      three_machine_docker_readiness_summary_json="${2:-}"
      shift 2
      ;;
    --run-profile-compare-campaign-signoff)
      run_profile_compare_campaign_signoff="${2:-}"
      shift 2
      ;;
    --profile-compare-campaign-signoff-refresh-campaign)
      profile_compare_campaign_signoff_refresh_campaign="${2:-}"
      shift 2
      ;;
    --profile-compare-campaign-signoff-fail-on-no-go)
      profile_compare_campaign_signoff_fail_on_no_go="${2:-}"
      shift 2
      ;;
    --profile-compare-campaign-signoff-require-selection-policy-present)
      profile_compare_campaign_signoff_require_selection_policy_present="${2:-}"
      shift 2
      ;;
    --profile-compare-campaign-signoff-require-selection-policy-valid)
      profile_compare_campaign_signoff_require_selection_policy_valid="${2:-}"
      shift 2
      ;;
    --profile-compare-campaign-signoff-reports-dir)
      profile_compare_campaign_signoff_reports_dir="${2:-}"
      shift 2
      ;;
    --profile-compare-campaign-signoff-summary-json)
      profile_compare_campaign_signoff_summary_json="${2:-}"
      shift 2
      ;;
    --profile-compare-campaign-signoff-campaign-execution-mode)
      profile_compare_campaign_signoff_campaign_execution_mode="${2:-}"
      shift 2
      ;;
    --profile-compare-campaign-signoff-campaign-directory-urls)
      profile_compare_campaign_signoff_campaign_directory_urls="${2:-}"
      shift 2
      ;;
    --profile-compare-campaign-signoff-campaign-bootstrap-directory)
      profile_compare_campaign_signoff_campaign_bootstrap_directory="${2:-}"
      shift 2
      ;;
    --profile-compare-campaign-signoff-campaign-discovery-wait-sec)
      profile_compare_campaign_signoff_campaign_discovery_wait_sec="${2:-}"
      shift 2
      ;;
    --profile-compare-campaign-signoff-campaign-issuer-url)
      profile_compare_campaign_signoff_campaign_issuer_url="${2:-}"
      shift 2
      ;;
    --profile-compare-campaign-signoff-campaign-entry-url)
      profile_compare_campaign_signoff_campaign_entry_url="${2:-}"
      shift 2
      ;;
    --profile-compare-campaign-signoff-campaign-exit-url)
      profile_compare_campaign_signoff_campaign_exit_url="${2:-}"
      shift 2
      ;;
    --profile-compare-campaign-signoff-campaign-start-local-stack)
      profile_compare_campaign_signoff_campaign_start_local_stack="${2:-}"
      shift 2
      ;;
    --run-pre-real-host-readiness)
      run_pre_real_host_readiness="${2:-}"
      shift 2
      ;;
    --run-real-wg-privileged-matrix)
      run_real_wg_privileged_matrix="${2:-}"
      shift 2
      ;;
    --beta-preflight-privileged)
      beta_preflight_privileged="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --manual-validation-report-summary-json)
      manual_validation_report_summary_json="${2:-}"
      shift 2
      ;;
    --manual-validation-report-md)
      manual_validation_report_md="${2:-}"
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
    -h|--help|help)
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

need_cmd jq
need_cmd date
need_cmd bash

bool_arg_or_die "--run-ci-local" "$run_ci_local"
bool_arg_or_die "--run-beta-preflight" "$run_beta_preflight"
bool_arg_or_die "--run-deep-suite" "$run_deep_suite"
bool_arg_or_die "--run-runtime-fix-record" "$run_runtime_fix_record"
if ! [[ "$step_timeout_sec" =~ ^[0-9]+$ ]]; then
  echo "--step-timeout-sec must be an integer >= 0"
  exit 2
fi
tri_state_or_die "--run-three-machine-docker-readiness" "$run_three_machine_docker_readiness"
bool_arg_or_die "--three-machine-docker-readiness-run-validate" "$three_machine_docker_readiness_run_validate"
bool_arg_or_die "--three-machine-docker-readiness-run-soak" "$three_machine_docker_readiness_run_soak"
bool_arg_or_die "--three-machine-docker-readiness-run-peer-failover" "$three_machine_docker_readiness_run_peer_failover"
bool_arg_or_die "--three-machine-docker-readiness-keep-stacks" "$three_machine_docker_readiness_keep_stacks"
if ! [[ "$three_machine_docker_readiness_soak_rounds" =~ ^[0-9]+$ ]]; then
  echo "--three-machine-docker-readiness-soak-rounds must be an integer"
  exit 2
fi
if ! [[ "$three_machine_docker_readiness_soak_pause_sec" =~ ^[0-9]+$ ]]; then
  echo "--three-machine-docker-readiness-soak-pause-sec must be an integer"
  exit 2
fi
if ! [[ "$three_machine_docker_readiness_peer_failover_downtime_sec" =~ ^[0-9]+$ ]]; then
  echo "--three-machine-docker-readiness-peer-failover-downtime-sec must be an integer"
  exit 2
fi
if ! [[ "$three_machine_docker_readiness_peer_failover_timeout_sec" =~ ^[0-9]+$ ]]; then
  echo "--three-machine-docker-readiness-peer-failover-timeout-sec must be an integer"
  exit 2
fi
case "$three_machine_docker_readiness_path_profile" in
  speed|balanced|private|fast|privacy) ;;
  *)
    echo "--three-machine-docker-readiness-path-profile must be one of: speed, balanced, private (fast/privacy aliases allowed)"
    exit 2
    ;;
esac
tri_state_or_die "--run-profile-compare-campaign-signoff" "$run_profile_compare_campaign_signoff"
bool_arg_or_die "--profile-compare-campaign-signoff-refresh-campaign" "$profile_compare_campaign_signoff_refresh_campaign"
bool_arg_or_die "--profile-compare-campaign-signoff-fail-on-no-go" "$profile_compare_campaign_signoff_fail_on_no_go"
bool_arg_or_die "--profile-compare-campaign-signoff-require-selection-policy-present" "$profile_compare_campaign_signoff_require_selection_policy_present"
bool_arg_or_die "--profile-compare-campaign-signoff-require-selection-policy-valid" "$profile_compare_campaign_signoff_require_selection_policy_valid"
case "$profile_compare_campaign_signoff_campaign_execution_mode" in
  auto|docker|local) ;;
  *)
    echo "--profile-compare-campaign-signoff-campaign-execution-mode must be one of: auto, docker, local"
    exit 2
    ;;
esac
if [[ -n "$profile_compare_campaign_signoff_campaign_discovery_wait_sec" && ! "$profile_compare_campaign_signoff_campaign_discovery_wait_sec" =~ ^[0-9]+$ ]]; then
  echo "--profile-compare-campaign-signoff-campaign-discovery-wait-sec must be an integer"
  exit 2
fi
if [[ -n "$profile_compare_campaign_signoff_campaign_start_local_stack" ]]; then
  tri_state_or_die "--profile-compare-campaign-signoff-campaign-start-local-stack" "$profile_compare_campaign_signoff_campaign_start_local_stack"
fi
tri_state_or_die "--run-pre-real-host-readiness" "$run_pre_real_host_readiness"
tri_state_or_die "--run-real-wg-privileged-matrix" "$run_real_wg_privileged_matrix"
tri_state_or_die "--beta-preflight-privileged" "$beta_preflight_privileged"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

ci_local_script="${SINGLE_MACHINE_CI_LOCAL_SCRIPT:-$ROOT_DIR/scripts/ci_local.sh}"
beta_preflight_script="${SINGLE_MACHINE_BETA_PREFLIGHT_SCRIPT:-$ROOT_DIR/scripts/beta_preflight.sh}"
deep_test_suite_script="${SINGLE_MACHINE_DEEP_TEST_SUITE_SCRIPT:-$ROOT_DIR/scripts/deep_test_suite.sh}"
runtime_fix_record_script="${SINGLE_MACHINE_RUNTIME_FIX_RECORD_SCRIPT:-$ROOT_DIR/scripts/runtime_fix_record.sh}"
three_machine_docker_readiness_script="${SINGLE_MACHINE_THREE_MACHINE_DOCKER_READINESS_SCRIPT:-$ROOT_DIR/scripts/three_machine_docker_readiness.sh}"
profile_compare_campaign_signoff_script="${SINGLE_MACHINE_PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT:-$ROOT_DIR/scripts/profile_compare_campaign_signoff.sh}"
default_profile_compare_campaign_signoff_script="$ROOT_DIR/scripts/profile_compare_campaign_signoff.sh"
pre_real_host_readiness_script="${SINGLE_MACHINE_PRE_REAL_HOST_READINESS_SCRIPT:-$ROOT_DIR/scripts/pre_real_host_readiness.sh}"
real_wg_privileged_matrix_record_script="${SINGLE_MACHINE_REAL_WG_PRIVILEGED_MATRIX_RECORD_SCRIPT:-$ROOT_DIR/scripts/real_wg_privileged_matrix_record.sh}"
manual_validation_report_script="${SINGLE_MACHINE_MANUAL_VALIDATION_REPORT_SCRIPT:-$ROOT_DIR/scripts/manual_validation_report.sh}"

for script_path in \
  "$ci_local_script" \
  "$beta_preflight_script" \
  "$deep_test_suite_script" \
  "$runtime_fix_record_script" \
  "$profile_compare_campaign_signoff_script" \
  "$pre_real_host_readiness_script" \
  "$manual_validation_report_script"; do
  if [[ ! -x "$script_path" ]]; then
    echo "missing executable script: $script_path"
    exit 2
  fi
done

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
log_dir="$ROOT_DIR/.easy-node-logs"
mkdir -p "$log_dir"

summary_json="$(abs_path "${summary_json:-$log_dir/single_machine_prod_readiness_${run_stamp}.json}")"
mkdir -p "$(dirname "$summary_json")"
summary_latest_json="$(abs_path "${SINGLE_MACHINE_SUMMARY_JSON_LATEST:-$log_dir/single_machine_prod_readiness_latest.json}")"
mkdir -p "$(dirname "$summary_latest_json")"

three_machine_docker_readiness_summary_json="$(abs_path "${three_machine_docker_readiness_summary_json:-$log_dir/single_machine_prod_readiness_${run_stamp}_three_machine_docker_readiness.json}")"
mkdir -p "$(dirname "$three_machine_docker_readiness_summary_json")"

profile_compare_campaign_signoff_reports_dir="$(abs_path "${profile_compare_campaign_signoff_reports_dir:-$ROOT_DIR/.easy-node-logs}")"
mkdir -p "$profile_compare_campaign_signoff_reports_dir"
profile_compare_campaign_signoff_summary_json="$(abs_path "${profile_compare_campaign_signoff_summary_json:-$profile_compare_campaign_signoff_reports_dir/profile_compare_campaign_signoff_summary.json}")"
mkdir -p "$(dirname "$profile_compare_campaign_signoff_summary_json")"
profile_compare_campaign_summary_json="$profile_compare_campaign_signoff_reports_dir/profile_compare_campaign_summary.json"

manual_validation_report_summary_json="$(abs_path "${manual_validation_report_summary_json:-${SINGLE_MACHINE_MANUAL_VALIDATION_REPORT_SUMMARY_JSON:-$log_dir/manual_validation_readiness_summary.json}}")"
manual_validation_report_md="$(abs_path "${manual_validation_report_md:-${SINGLE_MACHINE_MANUAL_VALIDATION_REPORT_MD:-$log_dir/manual_validation_readiness_report.md}}")"
mkdir -p "$(dirname "$manual_validation_report_summary_json")" "$(dirname "$manual_validation_report_md")"

steps_file="$(mktemp)"
trap 'rm -f "$steps_file"' EXIT

steps_failed="0"
step_timeout_warning_emitted="0"

run_with_optional_timeout() {
  local timeout_sec="$1"
  shift
  if [[ "$timeout_sec" -gt 0 ]]; then
    if command -v timeout >/dev/null 2>&1; then
      timeout "${timeout_sec}s" "$@"
    else
      if [[ "$step_timeout_warning_emitted" == "0" ]]; then
        echo "[single-machine-prod-readiness] warn=timeout command not found; step timeout guard disabled"
        step_timeout_warning_emitted="1"
      fi
      "$@"
    fi
  else
    "$@"
  fi
}

run_step() {
  local step_id="$1"
  local label="$2"
  local command="$3"
  local note="${4:-}"
  local start_sec end_sec duration_sec rc status timed_out
  local step_log="$log_dir/single_machine_prod_readiness_${run_stamp}_${step_id}.log"

  echo "[single-machine-prod-readiness] step=${step_id} status=running timeout_sec=${step_timeout_sec} log=${step_log}"
  start_sec="$(date +%s)"
  set +e
  run_with_optional_timeout "$step_timeout_sec" bash -lc "cd $(printf '%q' "$ROOT_DIR") && $command" >"$step_log" 2>&1
  rc=$?
  set -e
  timed_out="false"
  if [[ "$rc" -eq 0 ]]; then
    rc=0
    status="pass"
  else
    if [[ "$rc" -eq 124 ]]; then
      timed_out="true"
    fi
    status="fail"
    steps_failed=$((steps_failed + 1))
  fi
  end_sec="$(date +%s)"
  duration_sec=$((end_sec - start_sec))

  jq -n \
    --arg step_id "$step_id" \
    --arg step_label "$label" \
    --arg status "$status" \
    --arg command "$command" \
    --arg note "$note" \
    --arg log "$step_log" \
    --argjson timed_out "$timed_out" \
    --argjson timeout_sec "$step_timeout_sec" \
    --argjson rc "$rc" \
    --argjson duration_sec "$duration_sec" \
    '{
      "step_id": $step_id,
      "label": $step_label,
      "status": $status,
      "command": $command,
      "rc": $rc,
      "timed_out": $timed_out,
      "timeout_sec": $timeout_sec,
      "duration_sec": $duration_sec,
      "note": $note,
      "log": $log
    }' >>"$steps_file"

  echo "[single-machine-prod-readiness] step=${step_id} status=${status} rc=${rc} timed_out=${timed_out} duration_sec=${duration_sec} log=${step_log}"
}

skip_step() {
  local step_id="$1"
  local label="$2"
  local command="$3"
  local note="$4"

  jq -n \
    --arg step_id "$step_id" \
    --arg step_label "$label" \
    --arg command "$command" \
    --arg note "$note" \
    '{
      "step_id": $step_id,
      "label": $step_label,
      "status": "skip",
      "command": $command,
      "rc": 0,
      "timed_out": false,
      "timeout_sec": 0,
      "duration_sec": 0,
      "note": $note,
      "log": ""
    }' >>"$steps_file"

  echo "[single-machine-prod-readiness] step=${step_id} status=skip note=${note}"
}

if [[ "$run_ci_local" == "1" ]]; then
  run_step "ci_local" "Local CI suite" "$(printf '%q' "$ci_local_script")"
else
  skip_step "ci_local" "Local CI suite" "$(printf '%q' "$ci_local_script")" "disabled by flag"
fi

if [[ "$run_beta_preflight" == "1" ]]; then
  beta_cmd="$(printf '%q' "$beta_preflight_script")"
  case "$beta_preflight_privileged" in
    auto)
      if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        beta_cmd="BETA_PREFLIGHT_PRIVILEGED=1 ${beta_cmd}"
      fi
      ;;
    1)
      if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        echo "--beta-preflight-privileged=1 requires root"
        exit 2
      fi
      beta_cmd="BETA_PREFLIGHT_PRIVILEGED=1 ${beta_cmd}"
      ;;
    0)
      ;;
  esac
  run_step "beta_preflight" "Beta preflight suite" "$beta_cmd"
else
  skip_step "beta_preflight" "Beta preflight suite" "$(printf '%q' "$beta_preflight_script")" "disabled by flag"
fi

if [[ "$run_deep_suite" == "1" ]]; then
  run_step "deep_test_suite" "Deep test suite" "$(printf '%q' "$deep_test_suite_script")"
else
  skip_step "deep_test_suite" "Deep test suite" "$(printf '%q' "$deep_test_suite_script")" "disabled by flag"
fi

if [[ "$run_runtime_fix_record" == "1" ]]; then
  run_step "runtime_fix_record" "Runtime hygiene recorded fix" "$(printf '%q' "$runtime_fix_record_script") --prune-wg-only-dir 1 --print-summary-json 1"
else
  skip_step "runtime_fix_record" "Runtime hygiene recorded fix" "$(printf '%q' "$runtime_fix_record_script") --prune-wg-only-dir 1 --print-summary-json 1" "disabled by flag"
fi

three_machine_docker_readiness_cmd="$(printf '%q' "$three_machine_docker_readiness_script") --run-validate $three_machine_docker_readiness_run_validate --run-soak $three_machine_docker_readiness_run_soak --run-peer-failover $three_machine_docker_readiness_run_peer_failover --peer-failover-downtime-sec $three_machine_docker_readiness_peer_failover_downtime_sec --peer-failover-timeout-sec $three_machine_docker_readiness_peer_failover_timeout_sec --soak-rounds $three_machine_docker_readiness_soak_rounds --soak-pause-sec $three_machine_docker_readiness_soak_pause_sec --path-profile $(printf '%q' "$three_machine_docker_readiness_path_profile") --keep-stacks $three_machine_docker_readiness_keep_stacks --summary-json $(printf '%q' "$three_machine_docker_readiness_summary_json") --print-summary-json 0"
three_machine_docker_bin="${THREE_MACHINE_DOCKER_DOCKER_BIN:-docker}"
case "$run_three_machine_docker_readiness" in
  auto)
    if [[ ! -x "$three_machine_docker_readiness_script" ]]; then
      skip_step "three_machine_docker_readiness" "Docker 3-machine rehearsal" "$three_machine_docker_readiness_cmd" "auto mode: script missing"
    elif ! command -v "$three_machine_docker_bin" >/dev/null 2>&1; then
      skip_step "three_machine_docker_readiness" "Docker 3-machine rehearsal" "$three_machine_docker_readiness_cmd" "auto mode: docker command not found"
    elif ! "$three_machine_docker_bin" info >/dev/null 2>&1; then
      skip_step "three_machine_docker_readiness" "Docker 3-machine rehearsal" "$three_machine_docker_readiness_cmd" "auto mode: docker daemon unavailable for current user"
    else
      run_step "three_machine_docker_readiness" "Docker 3-machine rehearsal" "$three_machine_docker_readiness_cmd"
    fi
    ;;
  1)
    if [[ ! -x "$three_machine_docker_readiness_script" ]]; then
      echo "missing executable script: $three_machine_docker_readiness_script"
      exit 2
    fi
    if ! command -v "$three_machine_docker_bin" >/dev/null 2>&1; then
      echo "missing required command: $three_machine_docker_bin"
      exit 2
    fi
    run_step "three_machine_docker_readiness" "Docker 3-machine rehearsal" "$three_machine_docker_readiness_cmd"
    ;;
  0)
    skip_step "three_machine_docker_readiness" "Docker 3-machine rehearsal" "$three_machine_docker_readiness_cmd" "disabled by flag"
    ;;
esac

three_machine_docker_endpoints_available="0"
three_machine_docker_endpoints_reachable="0"
three_machine_docker_directory_a_url=""
three_machine_docker_directory_b_url=""
three_machine_docker_issuer_a_url=""
three_machine_docker_entry_url=""
three_machine_docker_exit_url=""
if [[ -f "$three_machine_docker_readiness_summary_json" ]] && jq -e . "$three_machine_docker_readiness_summary_json" >/dev/null 2>&1; then
  if [[ "$(jq -r '.status // ""' "$three_machine_docker_readiness_summary_json")" == "pass" ]]; then
    three_machine_docker_directory_a_url="$(jq -r '.endpoints.directory_a // ""' "$three_machine_docker_readiness_summary_json")"
    three_machine_docker_directory_b_url="$(jq -r '.endpoints.directory_b // ""' "$three_machine_docker_readiness_summary_json")"
    three_machine_docker_issuer_a_url="$(jq -r '.endpoints.issuer_a // ""' "$three_machine_docker_readiness_summary_json")"
    three_machine_docker_entry_url="$(jq -r '.endpoints.entry // ""' "$three_machine_docker_readiness_summary_json")"
    three_machine_docker_exit_url="$(jq -r '.endpoints.exit // ""' "$three_machine_docker_readiness_summary_json")"
    if [[ -n "$three_machine_docker_directory_a_url" && -n "$three_machine_docker_directory_b_url" && -n "$three_machine_docker_issuer_a_url" && -n "$three_machine_docker_entry_url" && -n "$three_machine_docker_exit_url" ]]; then
      three_machine_docker_endpoints_available="1"
    fi
  fi
fi

# Auto-refresh in docker mode should only assume host endpoints are reusable when
# they are reachable from this host context. For non-default test stubs we treat
# endpoints as reachable to keep integration fakes deterministic.
if [[ "$three_machine_docker_endpoints_available" == "1" ]]; then
  if [[ "$profile_compare_campaign_signoff_script" != "$default_profile_compare_campaign_signoff_script" ]]; then
    three_machine_docker_endpoints_reachable="1"
  elif command -v curl >/dev/null 2>&1; then
    if curl --silent --show-error --fail --max-time 3 "${three_machine_docker_directory_a_url%/}/v1/pubkeys" >/dev/null 2>&1 \
      && curl --silent --show-error --fail --max-time 3 "${three_machine_docker_directory_b_url%/}/v1/pubkeys" >/dev/null 2>&1 \
      && curl --silent --show-error --fail --max-time 3 "${three_machine_docker_issuer_a_url%/}/v1/pubkeys" >/dev/null 2>&1 \
      && curl --silent --show-error --fail --max-time 3 "${three_machine_docker_entry_url%/}/v1/health" >/dev/null 2>&1 \
      && curl --silent --show-error --fail --max-time 3 "${three_machine_docker_exit_url%/}/v1/health" >/dev/null 2>&1; then
      three_machine_docker_endpoints_reachable="1"
    fi
  fi
fi

profile_compare_campaign_signoff_refresh_effective="$profile_compare_campaign_signoff_refresh_campaign"
profile_compare_campaign_signoff_auto_refreshed="0"
profile_compare_campaign_signoff_auto_refreshed_via_docker="0"
profile_compare_campaign_signoff_auto_skipped_non_root="0"
profile_compare_campaign_signoff_auto_refresh_reason=""
profile_compare_campaign_signoff_cmd=""
profile_compare_campaign_signoff_campaign_execution_mode_effective=""
if [[ "$profile_compare_campaign_signoff_campaign_execution_mode" != "auto" ]]; then
  profile_compare_campaign_signoff_campaign_execution_mode_effective="$profile_compare_campaign_signoff_campaign_execution_mode"
fi
profile_compare_campaign_signoff_campaign_directory_urls_effective="$profile_compare_campaign_signoff_campaign_directory_urls"
profile_compare_campaign_signoff_campaign_bootstrap_directory_effective="$profile_compare_campaign_signoff_campaign_bootstrap_directory"
profile_compare_campaign_signoff_campaign_discovery_wait_sec_effective="$profile_compare_campaign_signoff_campaign_discovery_wait_sec"
profile_compare_campaign_signoff_campaign_issuer_url_effective="$profile_compare_campaign_signoff_campaign_issuer_url"
profile_compare_campaign_signoff_campaign_entry_url_effective="$profile_compare_campaign_signoff_campaign_entry_url"
profile_compare_campaign_signoff_campaign_exit_url_effective="$profile_compare_campaign_signoff_campaign_exit_url"
profile_compare_campaign_signoff_campaign_start_local_stack_effective="$profile_compare_campaign_signoff_campaign_start_local_stack"
profile_compare_campaign_signoff_require_selection_policy_present_effective="$profile_compare_campaign_signoff_require_selection_policy_present"
profile_compare_campaign_signoff_require_selection_policy_valid_effective="$profile_compare_campaign_signoff_require_selection_policy_valid"

profile_compare_campaign_summary_available="0"
if [[ -f "$profile_compare_campaign_summary_json" ]] && jq -e . "$profile_compare_campaign_summary_json" >/dev/null 2>&1; then
  profile_compare_campaign_summary_available="1"
fi

profile_compare_campaign_signoff_existing_summary_available="0"
profile_compare_campaign_signoff_existing_summary_valid="0"
profile_compare_campaign_signoff_existing_summary_status=""
profile_compare_campaign_signoff_existing_summary_decision=""
profile_compare_campaign_signoff_existing_summary_refresh_campaign="0"
profile_compare_campaign_signoff_existing_summary_final_rc="0"
profile_compare_campaign_signoff_existing_summary_failure_stage=""
profile_compare_campaign_signoff_existing_summary_requires_refresh="0"
profile_compare_campaign_signoff_existing_summary_refresh_reason=""
if [[ -f "$profile_compare_campaign_signoff_summary_json" ]]; then
  profile_compare_campaign_signoff_existing_summary_available="1"
  if jq -e . "$profile_compare_campaign_signoff_summary_json" >/dev/null 2>&1; then
    profile_compare_campaign_signoff_existing_summary_valid="1"
    profile_compare_campaign_signoff_existing_summary_status="$(jq -r '.status // ""' "$profile_compare_campaign_signoff_summary_json")"
    profile_compare_campaign_signoff_existing_summary_decision="$(jq -r '.decision.decision // ""' "$profile_compare_campaign_signoff_summary_json")"
    profile_compare_campaign_signoff_existing_summary_refresh_campaign="$(jq -r '(.inputs.refresh_campaign // false) | if . then "1" else "0" end' "$profile_compare_campaign_signoff_summary_json")"
    profile_compare_campaign_signoff_existing_summary_final_rc="$(jq -r '.final_rc // 0' "$profile_compare_campaign_signoff_summary_json")"
    if ! [[ "$profile_compare_campaign_signoff_existing_summary_final_rc" =~ ^-?[0-9]+$ ]]; then
      profile_compare_campaign_signoff_existing_summary_final_rc="0"
    fi
    profile_compare_campaign_signoff_existing_summary_failure_stage="$(jq -r '.failure_stage // ""' "$profile_compare_campaign_signoff_summary_json")"
    if [[ "$profile_compare_campaign_signoff_existing_summary_status" == "ok" && "$profile_compare_campaign_signoff_existing_summary_decision" == "GO" ]]; then
      profile_compare_campaign_signoff_existing_summary_requires_refresh="0"
    elif [[ "$profile_compare_campaign_signoff_existing_summary_refresh_campaign" == "1" ]]; then
      profile_compare_campaign_signoff_existing_summary_requires_refresh="0"
    else
      profile_compare_campaign_signoff_existing_summary_requires_refresh="1"
      profile_compare_campaign_signoff_existing_summary_refresh_reason="stale non-refreshed signoff summary (status=${profile_compare_campaign_signoff_existing_summary_status:-unknown} decision=${profile_compare_campaign_signoff_existing_summary_decision:-unknown})"
    fi
  else
    profile_compare_campaign_signoff_existing_summary_requires_refresh="1"
    profile_compare_campaign_signoff_existing_summary_refresh_reason="invalid signoff summary JSON"
  fi
fi

build_profile_compare_campaign_signoff_cmd() {
  local refresh_value="$1"
  local -a cmd=(
    "$profile_compare_campaign_signoff_script"
    --reports-dir "$profile_compare_campaign_signoff_reports_dir"
    --refresh-campaign "$refresh_value"
    --fail-on-no-go "$profile_compare_campaign_signoff_fail_on_no_go"
    --require-selection-policy-present "$profile_compare_campaign_signoff_require_selection_policy_present_effective"
    --require-selection-policy-valid "$profile_compare_campaign_signoff_require_selection_policy_valid_effective"
    --summary-json "$profile_compare_campaign_signoff_summary_json"
    --print-summary-json 0
  )

  if [[ -n "$profile_compare_campaign_signoff_campaign_execution_mode_effective" ]]; then
    cmd+=(--campaign-execution-mode "$profile_compare_campaign_signoff_campaign_execution_mode_effective")
  fi
  if [[ -n "$profile_compare_campaign_signoff_campaign_directory_urls_effective" ]]; then
    cmd+=(--campaign-directory-urls "$profile_compare_campaign_signoff_campaign_directory_urls_effective")
  fi
  if [[ -n "$profile_compare_campaign_signoff_campaign_bootstrap_directory_effective" ]]; then
    cmd+=(--campaign-bootstrap-directory "$profile_compare_campaign_signoff_campaign_bootstrap_directory_effective")
  fi
  if [[ -n "$profile_compare_campaign_signoff_campaign_discovery_wait_sec_effective" ]]; then
    cmd+=(--campaign-discovery-wait-sec "$profile_compare_campaign_signoff_campaign_discovery_wait_sec_effective")
  fi
  if [[ -n "$profile_compare_campaign_signoff_campaign_issuer_url_effective" ]]; then
    cmd+=(--campaign-issuer-url "$profile_compare_campaign_signoff_campaign_issuer_url_effective")
  fi
  if [[ -n "$profile_compare_campaign_signoff_campaign_entry_url_effective" ]]; then
    cmd+=(--campaign-entry-url "$profile_compare_campaign_signoff_campaign_entry_url_effective")
  fi
  if [[ -n "$profile_compare_campaign_signoff_campaign_exit_url_effective" ]]; then
    cmd+=(--campaign-exit-url "$profile_compare_campaign_signoff_campaign_exit_url_effective")
  fi
  if [[ -n "$profile_compare_campaign_signoff_campaign_start_local_stack_effective" ]]; then
    cmd+=(--campaign-start-local-stack "$profile_compare_campaign_signoff_campaign_start_local_stack_effective")
  fi

  printf '%q ' "${cmd[@]}"
  printf '\n'
}

set_profile_compare_auto_refresh_mode() {
  local refresh_reason="$1"
  profile_compare_campaign_signoff_auto_refresh_reason="$refresh_reason"
  if [[ "$three_machine_docker_endpoints_available" == "1" && "$three_machine_docker_endpoints_reachable" == "1" ]]; then
    profile_compare_campaign_signoff_refresh_effective="1"
    profile_compare_campaign_signoff_auto_refreshed="1"
    profile_compare_campaign_signoff_auto_refreshed_via_docker="1"
    if [[ -z "$profile_compare_campaign_signoff_campaign_execution_mode_effective" ]]; then
      profile_compare_campaign_signoff_campaign_execution_mode_effective="docker"
    fi
    if [[ -z "$profile_compare_campaign_signoff_campaign_directory_urls_effective" ]]; then
      profile_compare_campaign_signoff_campaign_directory_urls_effective="${three_machine_docker_directory_a_url},${three_machine_docker_directory_b_url}"
    fi
    if [[ -z "$profile_compare_campaign_signoff_campaign_bootstrap_directory_effective" ]]; then
      profile_compare_campaign_signoff_campaign_bootstrap_directory_effective="$three_machine_docker_directory_a_url"
    fi
    if [[ -z "$profile_compare_campaign_signoff_campaign_issuer_url_effective" ]]; then
      profile_compare_campaign_signoff_campaign_issuer_url_effective="$three_machine_docker_issuer_a_url"
    fi
    if [[ -z "$profile_compare_campaign_signoff_campaign_entry_url_effective" ]]; then
      profile_compare_campaign_signoff_campaign_entry_url_effective="$three_machine_docker_entry_url"
    fi
    if [[ -z "$profile_compare_campaign_signoff_campaign_exit_url_effective" ]]; then
      profile_compare_campaign_signoff_campaign_exit_url_effective="$three_machine_docker_exit_url"
    fi
    if [[ -z "$profile_compare_campaign_signoff_campaign_start_local_stack_effective" ]]; then
      profile_compare_campaign_signoff_campaign_start_local_stack_effective="0"
    fi
  elif [[ "${EUID:-$(id -u)}" -ne 0 && "$profile_compare_campaign_signoff_script" == "$default_profile_compare_campaign_signoff_script" ]]; then
    profile_compare_campaign_signoff_refresh_effective="0"
    profile_compare_campaign_signoff_auto_skipped_non_root="1"
    if [[ "$three_machine_docker_endpoints_available" == "1" && "$three_machine_docker_endpoints_reachable" != "1" ]]; then
      if [[ -n "$profile_compare_campaign_signoff_auto_refresh_reason" ]]; then
        profile_compare_campaign_signoff_auto_refresh_reason="${profile_compare_campaign_signoff_auto_refresh_reason}; docker rehearsal endpoints are no longer reachable (rerun with --three-machine-docker-readiness-keep-stacks 1)"
      else
        profile_compare_campaign_signoff_auto_refresh_reason="docker rehearsal endpoints are no longer reachable (rerun with --three-machine-docker-readiness-keep-stacks 1)"
      fi
    fi
  else
    profile_compare_campaign_signoff_refresh_effective="1"
    profile_compare_campaign_signoff_auto_refreshed="1"
  fi
}

case "$run_profile_compare_campaign_signoff" in
  auto)
    if [[ "$profile_compare_campaign_signoff_refresh_campaign" == "1" ]]; then
      profile_compare_campaign_signoff_refresh_effective="1"
      profile_compare_campaign_signoff_auto_refresh_reason="explicit refresh-campaign=1"
    elif [[ "$profile_compare_campaign_signoff_existing_summary_available" == "1" ]]; then
      if [[ "$profile_compare_campaign_signoff_existing_summary_requires_refresh" == "1" ]]; then
        set_profile_compare_auto_refresh_mode "$profile_compare_campaign_signoff_existing_summary_refresh_reason"
      else
        profile_compare_campaign_signoff_refresh_effective="0"
      fi
    elif [[ "$profile_compare_campaign_summary_available" == "1" ]]; then
      profile_compare_campaign_signoff_refresh_effective="0"
    else
      # Auto mode should keep roadmap momentum by generating missing campaign artifacts.
      # On non-root hosts (default script path), local campaign refresh requires root
      # for stack bootstrap, so skip instead of failing the whole readiness sweep.
      set_profile_compare_auto_refresh_mode "campaign summary missing"
    fi
    profile_compare_campaign_signoff_cmd="$(build_profile_compare_campaign_signoff_cmd "$profile_compare_campaign_signoff_refresh_effective")"
    profile_compare_campaign_signoff_auto_refresh_reason_note=""
    if [[ -n "$profile_compare_campaign_signoff_auto_refresh_reason" ]]; then
      profile_compare_campaign_signoff_auto_refresh_reason_note=" (${profile_compare_campaign_signoff_auto_refresh_reason})"
    fi
    if [[ "$profile_compare_campaign_signoff_auto_skipped_non_root" == "1" ]]; then
      skip_step "profile_compare_campaign_signoff" "Profile compare campaign signoff" "$profile_compare_campaign_signoff_cmd" "auto mode: local campaign refresh requires root; skipped on non-root host${profile_compare_campaign_signoff_auto_refresh_reason_note}"
    elif [[ "$profile_compare_campaign_signoff_auto_refreshed_via_docker" == "1" ]]; then
      run_step "profile_compare_campaign_signoff" "Profile compare campaign signoff" "$profile_compare_campaign_signoff_cmd" "auto mode: using docker rehearsal endpoints for refresh-campaign=1${profile_compare_campaign_signoff_auto_refresh_reason_note}"
    elif [[ "$profile_compare_campaign_signoff_auto_refreshed" == "1" ]]; then
      run_step "profile_compare_campaign_signoff" "Profile compare campaign signoff" "$profile_compare_campaign_signoff_cmd" "auto mode: forcing refresh-campaign=1${profile_compare_campaign_signoff_auto_refresh_reason_note}"
    else
      run_step "profile_compare_campaign_signoff" "Profile compare campaign signoff" "$profile_compare_campaign_signoff_cmd"
    fi
    ;;
  1)
    profile_compare_campaign_signoff_refresh_effective="$profile_compare_campaign_signoff_refresh_campaign"
    profile_compare_campaign_signoff_cmd="$(build_profile_compare_campaign_signoff_cmd "$profile_compare_campaign_signoff_refresh_effective")"
    run_step "profile_compare_campaign_signoff" "Profile compare campaign signoff" "$profile_compare_campaign_signoff_cmd"
    ;;
  0)
    profile_compare_campaign_signoff_refresh_effective="$profile_compare_campaign_signoff_refresh_campaign"
    profile_compare_campaign_signoff_cmd="$(build_profile_compare_campaign_signoff_cmd "$profile_compare_campaign_signoff_refresh_effective")"
    skip_step "profile_compare_campaign_signoff" "Profile compare campaign signoff" "$profile_compare_campaign_signoff_cmd" "disabled by flag"
    ;;
esac

pre_real_cmd="$(printf '%q' "$pre_real_host_readiness_script") --strict-beta 1 --print-summary-json 1"
case "$run_pre_real_host_readiness" in
  auto)
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
      run_step "pre_real_host_readiness" "Pre-real-host readiness" "$pre_real_cmd"
    else
      skip_step "pre_real_host_readiness" "Pre-real-host readiness" "$pre_real_cmd" "requires root (skipped on non-root host)"
    fi
    ;;
  1)
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
      echo "--run-pre-real-host-readiness=1 requires root"
      exit 2
    fi
    run_step "pre_real_host_readiness" "Pre-real-host readiness" "$pre_real_cmd"
    ;;
  0)
    skip_step "pre_real_host_readiness" "Pre-real-host readiness" "$pre_real_cmd" "disabled by flag"
    ;;
esac

real_wg_privileged_matrix_cmd="$(printf '%q' "$real_wg_privileged_matrix_record_script") --print-summary-json 1"
case "$run_real_wg_privileged_matrix" in
  auto)
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
      skip_step "real_wg_privileged_matrix" "Linux root real-WG privileged matrix" "$real_wg_privileged_matrix_cmd" "requires root (skipped on non-root host)"
    elif [[ ! -x "$real_wg_privileged_matrix_record_script" ]]; then
      skip_step "real_wg_privileged_matrix" "Linux root real-WG privileged matrix" "$real_wg_privileged_matrix_cmd" "auto mode: script missing"
    else
      run_step "real_wg_privileged_matrix" "Linux root real-WG privileged matrix" "$real_wg_privileged_matrix_cmd"
    fi
    ;;
  1)
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
      echo "--run-real-wg-privileged-matrix=1 requires root"
      exit 2
    fi
    if [[ ! -x "$real_wg_privileged_matrix_record_script" ]]; then
      echo "missing executable script: $real_wg_privileged_matrix_record_script"
      exit 2
    fi
    run_step "real_wg_privileged_matrix" "Linux root real-WG privileged matrix" "$real_wg_privileged_matrix_cmd"
    ;;
  0)
    skip_step "real_wg_privileged_matrix" "Linux root real-WG privileged matrix" "$real_wg_privileged_matrix_cmd" "disabled by flag"
    ;;
esac

manual_report_cmd="$(printf '%q' "$manual_validation_report_script") --profile-compare-signoff-summary-json $(printf '%q' "$profile_compare_campaign_signoff_summary_json") --summary-json $(printf '%q' "$manual_validation_report_summary_json") --report-md $(printf '%q' "$manual_validation_report_md") --print-report 0 --print-summary-json 0"
run_step "manual_validation_report" "Manual validation readiness report" "$manual_report_cmd"

steps_json="$(jq -s '.' "$steps_file")"
critical_failed_steps_json="$(printf '%s\n' "$steps_json" | jq -c '[.[] | select(.status == "fail" and .step_id != "profile_compare_campaign_signoff" and .step_id != "real_wg_privileged_matrix")]')"
non_blocking_failed_steps_json="$(printf '%s\n' "$steps_json" | jq -c '[.[] | select(.status == "fail" and (.step_id == "profile_compare_campaign_signoff" or .step_id == "real_wg_privileged_matrix"))]')"
timed_out_steps_json="$(printf '%s\n' "$steps_json" | jq -c '[.[] | select((.timed_out // false) == true)]')"
critical_steps_failed_count="$(printf '%s\n' "$critical_failed_steps_json" | jq -r 'length')"
non_blocking_steps_failed_count="$(printf '%s\n' "$non_blocking_failed_steps_json" | jq -r 'length')"
timed_out_steps_count="$(printf '%s\n' "$timed_out_steps_json" | jq -r 'length')"
three_machine_docker_readiness_step_status="$(printf '%s\n' "$steps_json" | jq -r '[.[] | select(.step_id == "three_machine_docker_readiness") | .status][0] // "skip"')"
three_machine_docker_readiness_available="0"
three_machine_docker_readiness_status="$three_machine_docker_readiness_step_status"
three_machine_docker_readiness_final_rc="0"
if [[ "$three_machine_docker_readiness_step_status" != "skip" && -f "$three_machine_docker_readiness_summary_json" ]] && jq -e . "$three_machine_docker_readiness_summary_json" >/dev/null 2>&1; then
  three_machine_docker_readiness_available="1"
  three_machine_docker_readiness_status="$(jq -r '.status // "'"$three_machine_docker_readiness_step_status"'"' "$three_machine_docker_readiness_summary_json")"
  three_machine_docker_readiness_final_rc="$(jq -r '.rc // 0' "$three_machine_docker_readiness_summary_json")"
fi
profile_compare_campaign_signoff_step_status="$(printf '%s\n' "$steps_json" | jq -r '[.[] | select(.step_id == "profile_compare_campaign_signoff") | .status][0] // "skip"')"
real_wg_privileged_matrix_step_status="$(printf '%s\n' "$steps_json" | jq -r '[.[] | select(.step_id == "real_wg_privileged_matrix") | .status][0] // "skip"')"

manual_report_available="0"
manual_report_json='{}'
manual_report_validation_error=""
if [[ -f "$manual_validation_report_summary_json" ]]; then
  if jq -e . "$manual_validation_report_summary_json" >/dev/null 2>&1; then
    manual_report_json_candidate="$(cat "$manual_validation_report_summary_json")"
    if validate_manual_validation_report_summary_payload "$manual_report_json_candidate"; then
      manual_report_available="1"
      manual_report_json="$manual_report_json_candidate"
    else
      manual_report_validation_error="manual validation readiness summary payload is malformed, partial, or schema-incompatible"
    fi
  else
    manual_report_validation_error="manual validation readiness summary JSON is invalid"
  fi
fi

profile_compare_campaign_signoff_available="0"
profile_compare_campaign_signoff_status=""
profile_compare_campaign_signoff_final_rc="0"
profile_compare_campaign_signoff_decision=""
profile_compare_campaign_signoff_recommended_profile=""
profile_compare_campaign_signoff_selection_policy_evidence_available="0"
profile_compare_campaign_signoff_selection_policy_evidence_present="0"
profile_compare_campaign_signoff_selection_policy_evidence_valid="0"
if [[ "$profile_compare_campaign_signoff_step_status" != "skip" && -f "$profile_compare_campaign_signoff_summary_json" ]] && jq -e . "$profile_compare_campaign_signoff_summary_json" >/dev/null 2>&1; then
  profile_compare_campaign_signoff_available="1"
  profile_compare_campaign_signoff_status="$(jq -r '.status // ""' "$profile_compare_campaign_signoff_summary_json")"
  profile_compare_campaign_signoff_final_rc="$(jq -r '.final_rc // 0' "$profile_compare_campaign_signoff_summary_json")"
  profile_compare_campaign_signoff_decision="$(jq -r '.decision.decision // ""' "$profile_compare_campaign_signoff_summary_json")"
  profile_compare_campaign_signoff_recommended_profile="$(jq -r '.decision.recommended_profile // ""' "$profile_compare_campaign_signoff_summary_json")"
  if jq -e '.decision.selection_policy_evidence | type == "object"' "$profile_compare_campaign_signoff_summary_json" >/dev/null 2>&1; then
    profile_compare_campaign_signoff_selection_policy_evidence_available="1"
    profile_compare_campaign_signoff_selection_policy_evidence_present="$(jq -r 'if (.decision.selection_policy_evidence.present // false) then "1" else "0" end' "$profile_compare_campaign_signoff_summary_json")"
    profile_compare_campaign_signoff_selection_policy_evidence_valid="$(jq -r 'if (.decision.selection_policy_evidence.valid // false) then "1" else "0" end' "$profile_compare_campaign_signoff_summary_json")"
  fi
fi

pending_checks_json='[]'
pending_multi_machine_json='[]'
pending_local_json='[]'
roadmap_stage=""
manual_readiness_status=""
single_machine_ready="false"
machine_c_smoke_ready="false"
local_gate_json='{}'
real_host_gate_json='{}'
profile_default_gate_json='{}'
profile_default_ready="false"
profile_default_gate_status=""
profile_default_gate_available="false"
profile_default_gate_decision=""
profile_default_gate_recommended_profile=""
profile_default_gate_next_command=""
next_action_check_id=""
next_action_command=""

if [[ "$manual_report_available" == "1" ]]; then
  pending_checks_json="$(printf '%s\n' "$manual_report_json" | jq -c '[
      ((.checks // []) | if type == "array" then . else [] end)[] |
      select((.status // "pending") != "pass" and (.status // "pending") != "skip") |
      {"check_id": (.check_id // ""), "label": (.label // ""), "status": (.status // "pending"), "command": (.command // ""), "notes": (.notes // "")}
    ]')"
  pending_multi_machine_json="$(printf '%s\n' "$pending_checks_json" | jq -c '[.[] | select(.check_id == "machine_c_vpn_smoke" or .check_id == "three_machine_prod_signoff")]')"
  pending_local_json="$(printf '%s\n' "$pending_checks_json" | jq -c '[.[] | select(.check_id != "machine_c_vpn_smoke" and .check_id != "three_machine_prod_signoff" and .check_id != "three_machine_docker_readiness" and .check_id != "real_wg_privileged_matrix")]')"
  roadmap_stage="$(printf '%s\n' "$manual_report_json" | jq -r '.summary.roadmap_stage // ""')"
  manual_readiness_status="$(printf '%s\n' "$manual_report_json" | jq -r '.report.readiness_status // ""')"
  single_machine_ready="$(printf '%s\n' "$manual_report_json" | jq -r '.summary.single_machine_ready // false')"
  machine_c_smoke_ready="$(printf '%s\n' "$manual_report_json" | jq -r '.summary.pre_machine_c_gate.ready // false')"
  local_gate_json="$(printf '%s\n' "$manual_report_json" | jq -c '.summary.local_gate // {}')"
  real_host_gate_json="$(printf '%s\n' "$manual_report_json" | jq -c '.summary.real_host_gate // {}')"
  profile_default_gate_json="$(printf '%s\n' "$manual_report_json" | jq -c '.summary.profile_default_gate // {}')"
  profile_default_ready="$(printf '%s\n' "$manual_report_json" | jq -r '.summary.profile_default_ready // false')"
  profile_default_gate_status="$(printf '%s\n' "$manual_report_json" | jq -r '.summary.profile_default_gate.status // ""')"
  profile_default_gate_available="$(printf '%s\n' "$manual_report_json" | jq -r '.summary.profile_default_gate.available // false')"
  profile_default_gate_decision="$(printf '%s\n' "$manual_report_json" | jq -r '.summary.profile_default_gate.decision // ""')"
  profile_default_gate_recommended_profile="$(printf '%s\n' "$manual_report_json" | jq -r '.summary.profile_default_gate.recommended_profile // ""')"
  profile_default_gate_next_command="$(printf '%s\n' "$manual_report_json" | jq -r '.summary.profile_default_gate.next_command // ""')"
  next_action_check_id="$(printf '%s\n' "$manual_report_json" | jq -r '.summary.next_action_check_id // ""')"
  next_action_command="$(printf '%s\n' "$manual_report_json" | jq -r '.summary.next_action_command // ""')"
fi

pending_multi_count="$(printf '%s\n' "$pending_multi_machine_json" | jq -r 'length')"
pending_local_count="$(printf '%s\n' "$pending_local_json" | jq -r 'length')"

overall_status="pass"
overall_rc=0
notes="All single-machine checks passed; no remaining blockers."

if ((critical_steps_failed_count > 0)); then
  overall_status="fail"
  overall_rc=1
  if ((timed_out_steps_count > 0)); then
    notes="One or more executed local checks timed out or failed; inspect failed step logs."
  else
    notes="One or more executed local checks failed; inspect failed step logs."
  fi
elif [[ "$manual_report_available" != "1" ]]; then
  overall_status="fail"
  overall_rc=1
  notes="Manual validation readiness summary is unavailable; cannot determine remaining blockers."
elif ((pending_local_count > 0)); then
  overall_status="fail"
  overall_rc=1
  notes="Local blockers remain before machine-C smoke is ready."
elif ((non_blocking_steps_failed_count > 0)); then
  overall_status="warn"
  overall_rc=0
  notes="One or more optional non-blocking gates failed; inspect related summaries and logs."
elif ((pending_multi_count > 0)); then
  overall_status="warn"
  overall_rc=0
  notes="Single-machine gates passed; remaining blockers require external machine(s)."
fi

summary_payload="$({
  jq -n \
    --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg status "$overall_status" \
    --arg notes "$notes" \
    --arg root_dir "$ROOT_DIR" \
    --arg summary_json "$summary_json" \
    --arg summary_latest_json "$summary_latest_json" \
    --arg manual_validation_report_summary_json "$manual_validation_report_summary_json" \
    --arg manual_validation_report_md "$manual_validation_report_md" \
    --arg manual_readiness_status "$manual_readiness_status" \
    --arg manual_report_validation_error "$manual_report_validation_error" \
    --arg roadmap_stage "$roadmap_stage" \
    --arg single_machine_ready "$single_machine_ready" \
    --arg machine_c_smoke_ready "$machine_c_smoke_ready" \
    --arg profile_default_ready "$profile_default_ready" \
    --arg next_action_check_id "$next_action_check_id" \
    --arg next_action_command "$next_action_command" \
    --arg run_ci_local "$run_ci_local" \
    --arg run_beta_preflight "$run_beta_preflight" \
    --arg run_deep_suite "$run_deep_suite" \
    --arg run_runtime_fix_record "$run_runtime_fix_record" \
    --arg step_timeout_sec "$step_timeout_sec" \
    --arg run_three_machine_docker_readiness "$run_three_machine_docker_readiness" \
    --arg three_machine_docker_readiness_run_validate "$three_machine_docker_readiness_run_validate" \
    --arg three_machine_docker_readiness_run_soak "$three_machine_docker_readiness_run_soak" \
    --arg three_machine_docker_readiness_run_peer_failover "$three_machine_docker_readiness_run_peer_failover" \
    --arg three_machine_docker_readiness_peer_failover_downtime_sec "$three_machine_docker_readiness_peer_failover_downtime_sec" \
    --arg three_machine_docker_readiness_peer_failover_timeout_sec "$three_machine_docker_readiness_peer_failover_timeout_sec" \
    --arg three_machine_docker_readiness_soak_rounds "$three_machine_docker_readiness_soak_rounds" \
    --arg three_machine_docker_readiness_soak_pause_sec "$three_machine_docker_readiness_soak_pause_sec" \
    --arg three_machine_docker_readiness_path_profile "$three_machine_docker_readiness_path_profile" \
    --arg three_machine_docker_readiness_keep_stacks "$three_machine_docker_readiness_keep_stacks" \
    --arg three_machine_docker_readiness_summary_json "$three_machine_docker_readiness_summary_json" \
    --arg three_machine_docker_readiness_status "$three_machine_docker_readiness_status" \
    --arg three_machine_docker_readiness_final_rc "$three_machine_docker_readiness_final_rc" \
    --arg run_profile_compare_campaign_signoff "$run_profile_compare_campaign_signoff" \
    --arg profile_compare_campaign_signoff_refresh_campaign "$profile_compare_campaign_signoff_refresh_campaign" \
    --arg profile_compare_campaign_signoff_refresh_effective "$profile_compare_campaign_signoff_refresh_effective" \
    --arg profile_compare_campaign_signoff_auto_refresh_reason "$profile_compare_campaign_signoff_auto_refresh_reason" \
    --arg profile_compare_campaign_signoff_fail_on_no_go "$profile_compare_campaign_signoff_fail_on_no_go" \
    --arg profile_compare_campaign_signoff_require_selection_policy_present "$profile_compare_campaign_signoff_require_selection_policy_present" \
    --arg profile_compare_campaign_signoff_require_selection_policy_valid "$profile_compare_campaign_signoff_require_selection_policy_valid" \
    --arg profile_compare_campaign_signoff_require_selection_policy_present_effective "$profile_compare_campaign_signoff_require_selection_policy_present_effective" \
    --arg profile_compare_campaign_signoff_require_selection_policy_valid_effective "$profile_compare_campaign_signoff_require_selection_policy_valid_effective" \
    --arg profile_compare_campaign_summary_available "$profile_compare_campaign_summary_available" \
    --arg profile_compare_campaign_signoff_existing_summary_available "$profile_compare_campaign_signoff_existing_summary_available" \
    --arg profile_compare_campaign_signoff_existing_summary_valid "$profile_compare_campaign_signoff_existing_summary_valid" \
    --arg profile_compare_campaign_signoff_existing_summary_status "$profile_compare_campaign_signoff_existing_summary_status" \
    --arg profile_compare_campaign_signoff_existing_summary_decision "$profile_compare_campaign_signoff_existing_summary_decision" \
    --arg profile_compare_campaign_signoff_existing_summary_refresh_campaign "$profile_compare_campaign_signoff_existing_summary_refresh_campaign" \
    --arg profile_compare_campaign_signoff_existing_summary_final_rc "$profile_compare_campaign_signoff_existing_summary_final_rc" \
    --arg profile_compare_campaign_signoff_existing_summary_failure_stage "$profile_compare_campaign_signoff_existing_summary_failure_stage" \
    --arg profile_compare_campaign_signoff_existing_summary_requires_refresh "$profile_compare_campaign_signoff_existing_summary_requires_refresh" \
    --arg profile_compare_campaign_signoff_existing_summary_refresh_reason "$profile_compare_campaign_signoff_existing_summary_refresh_reason" \
    --arg profile_compare_campaign_signoff_campaign_execution_mode "$profile_compare_campaign_signoff_campaign_execution_mode" \
    --arg profile_compare_campaign_signoff_campaign_directory_urls "$profile_compare_campaign_signoff_campaign_directory_urls" \
    --arg profile_compare_campaign_signoff_campaign_bootstrap_directory "$profile_compare_campaign_signoff_campaign_bootstrap_directory" \
    --arg profile_compare_campaign_signoff_campaign_discovery_wait_sec "$profile_compare_campaign_signoff_campaign_discovery_wait_sec" \
    --arg profile_compare_campaign_signoff_campaign_issuer_url "$profile_compare_campaign_signoff_campaign_issuer_url" \
    --arg profile_compare_campaign_signoff_campaign_entry_url "$profile_compare_campaign_signoff_campaign_entry_url" \
    --arg profile_compare_campaign_signoff_campaign_exit_url "$profile_compare_campaign_signoff_campaign_exit_url" \
    --arg profile_compare_campaign_signoff_campaign_start_local_stack "$profile_compare_campaign_signoff_campaign_start_local_stack" \
    --arg profile_compare_campaign_signoff_campaign_execution_mode_effective "$profile_compare_campaign_signoff_campaign_execution_mode_effective" \
    --arg profile_compare_campaign_signoff_campaign_directory_urls_effective "$profile_compare_campaign_signoff_campaign_directory_urls_effective" \
    --arg profile_compare_campaign_signoff_campaign_bootstrap_directory_effective "$profile_compare_campaign_signoff_campaign_bootstrap_directory_effective" \
    --arg profile_compare_campaign_signoff_campaign_discovery_wait_sec_effective "$profile_compare_campaign_signoff_campaign_discovery_wait_sec_effective" \
    --arg profile_compare_campaign_signoff_campaign_issuer_url_effective "$profile_compare_campaign_signoff_campaign_issuer_url_effective" \
    --arg profile_compare_campaign_signoff_campaign_entry_url_effective "$profile_compare_campaign_signoff_campaign_entry_url_effective" \
    --arg profile_compare_campaign_signoff_campaign_exit_url_effective "$profile_compare_campaign_signoff_campaign_exit_url_effective" \
    --arg profile_compare_campaign_signoff_campaign_start_local_stack_effective "$profile_compare_campaign_signoff_campaign_start_local_stack_effective" \
    --arg run_pre_real_host_readiness "$run_pre_real_host_readiness" \
    --arg run_real_wg_privileged_matrix "$run_real_wg_privileged_matrix" \
    --arg beta_preflight_privileged "$beta_preflight_privileged" \
    --arg profile_compare_campaign_signoff_reports_dir "$profile_compare_campaign_signoff_reports_dir" \
    --arg profile_compare_campaign_signoff_summary_json "$profile_compare_campaign_signoff_summary_json" \
    --arg profile_compare_campaign_summary_json "$profile_compare_campaign_summary_json" \
    --arg profile_compare_campaign_signoff_status "$profile_compare_campaign_signoff_status" \
    --arg profile_compare_campaign_signoff_final_rc "$profile_compare_campaign_signoff_final_rc" \
    --arg profile_compare_campaign_signoff_decision "$profile_compare_campaign_signoff_decision" \
    --arg profile_compare_campaign_signoff_recommended_profile "$profile_compare_campaign_signoff_recommended_profile" \
    --arg profile_compare_campaign_signoff_selection_policy_evidence_available "$profile_compare_campaign_signoff_selection_policy_evidence_available" \
    --arg profile_compare_campaign_signoff_selection_policy_evidence_present "$profile_compare_campaign_signoff_selection_policy_evidence_present" \
    --arg profile_compare_campaign_signoff_selection_policy_evidence_valid "$profile_compare_campaign_signoff_selection_policy_evidence_valid" \
    --arg real_wg_privileged_matrix_step_status "$real_wg_privileged_matrix_step_status" \
    --argjson rc "$overall_rc" \
    --argjson steps_failed "$steps_failed" \
    --argjson critical_steps_failed_count "$critical_steps_failed_count" \
    --argjson non_blocking_steps_failed_count "$non_blocking_steps_failed_count" \
    --argjson timed_out_steps_count "$timed_out_steps_count" \
    --argjson manual_report_available "$manual_report_available" \
    --argjson three_machine_docker_readiness_available "$three_machine_docker_readiness_available" \
    --argjson profile_compare_campaign_signoff_available "$profile_compare_campaign_signoff_available" \
    --argjson profile_compare_campaign_signoff_auto_refreshed "$profile_compare_campaign_signoff_auto_refreshed" \
    --argjson profile_compare_campaign_signoff_auto_refreshed_via_docker "$profile_compare_campaign_signoff_auto_refreshed_via_docker" \
    --argjson profile_compare_campaign_signoff_auto_skipped_non_root "$profile_compare_campaign_signoff_auto_skipped_non_root" \
    --argjson three_machine_docker_endpoints_available "$three_machine_docker_endpoints_available" \
    --argjson steps "$steps_json" \
    --argjson critical_failed_steps "$critical_failed_steps_json" \
    --argjson non_blocking_failed_steps "$non_blocking_failed_steps_json" \
    --argjson timed_out_steps "$timed_out_steps_json" \
    --argjson pending_checks "$pending_checks_json" \
    --argjson pending_multi_machine "$pending_multi_machine_json" \
    --argjson pending_local "$pending_local_json" \
    --argjson local_gate "$local_gate_json" \
    --argjson real_host_gate "$real_host_gate_json" \
    --argjson profile_default_gate "$profile_default_gate_json" \
    '{
      version: 1,
      schema: {
        id: "single_machine_prod_readiness_summary",
        major: 1,
        minor: 0
      },
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $rc,
      notes: $notes,
      inputs: {
        run_ci_local: ($run_ci_local == "1"),
        run_beta_preflight: ($run_beta_preflight == "1"),
        run_deep_suite: ($run_deep_suite == "1"),
        run_runtime_fix_record: ($run_runtime_fix_record == "1"),
        step_timeout_sec: ($step_timeout_sec | tonumber),
        run_three_machine_docker_readiness: $run_three_machine_docker_readiness,
        three_machine_docker_readiness_run_validate: ($three_machine_docker_readiness_run_validate == "1"),
        three_machine_docker_readiness_run_soak: ($three_machine_docker_readiness_run_soak == "1"),
        three_machine_docker_readiness_run_peer_failover: ($three_machine_docker_readiness_run_peer_failover == "1"),
        three_machine_docker_readiness_peer_failover_downtime_sec: ($three_machine_docker_readiness_peer_failover_downtime_sec | tonumber),
        three_machine_docker_readiness_peer_failover_timeout_sec: ($three_machine_docker_readiness_peer_failover_timeout_sec | tonumber),
        three_machine_docker_readiness_soak_rounds: ($three_machine_docker_readiness_soak_rounds | tonumber),
        three_machine_docker_readiness_soak_pause_sec: ($three_machine_docker_readiness_soak_pause_sec | tonumber),
        three_machine_docker_readiness_path_profile: $three_machine_docker_readiness_path_profile,
        three_machine_docker_readiness_keep_stacks: ($three_machine_docker_readiness_keep_stacks == "1"),
        run_profile_compare_campaign_signoff: $run_profile_compare_campaign_signoff,
        profile_compare_campaign_signoff_refresh_campaign: ($profile_compare_campaign_signoff_refresh_campaign == "1"),
        profile_compare_campaign_signoff_refresh_effective: ($profile_compare_campaign_signoff_refresh_effective == "1"),
        profile_compare_campaign_signoff_auto_refresh_reason: (if $profile_compare_campaign_signoff_auto_refresh_reason == "" then null else $profile_compare_campaign_signoff_auto_refresh_reason end),
        profile_compare_campaign_signoff_auto_refreshed: ($profile_compare_campaign_signoff_auto_refreshed == 1),
        profile_compare_campaign_signoff_auto_refreshed_via_docker: ($profile_compare_campaign_signoff_auto_refreshed_via_docker == 1),
        profile_compare_campaign_signoff_auto_skipped_non_root: ($profile_compare_campaign_signoff_auto_skipped_non_root == 1),
        profile_compare_campaign_signoff_fail_on_no_go: ($profile_compare_campaign_signoff_fail_on_no_go == "1"),
        profile_compare_campaign_signoff_require_selection_policy_present_requested: ($profile_compare_campaign_signoff_require_selection_policy_present == "1"),
        profile_compare_campaign_signoff_require_selection_policy_valid_requested: ($profile_compare_campaign_signoff_require_selection_policy_valid == "1"),
        profile_compare_campaign_signoff_require_selection_policy_present_effective: ($profile_compare_campaign_signoff_require_selection_policy_present_effective == "1"),
        profile_compare_campaign_signoff_require_selection_policy_valid_effective: ($profile_compare_campaign_signoff_require_selection_policy_valid_effective == "1"),
        profile_compare_campaign_summary_available: ($profile_compare_campaign_summary_available == "1"),
        profile_compare_campaign_signoff_existing_summary: {
          available: ($profile_compare_campaign_signoff_existing_summary_available == "1"),
          valid_json: ($profile_compare_campaign_signoff_existing_summary_valid == "1"),
          status: $profile_compare_campaign_signoff_existing_summary_status,
          decision: $profile_compare_campaign_signoff_existing_summary_decision,
          refresh_campaign: ($profile_compare_campaign_signoff_existing_summary_refresh_campaign == "1"),
          final_rc: ($profile_compare_campaign_signoff_existing_summary_final_rc | tonumber),
          failure_stage: $profile_compare_campaign_signoff_existing_summary_failure_stage,
          requires_refresh: ($profile_compare_campaign_signoff_existing_summary_requires_refresh == "1"),
          refresh_reason: (if $profile_compare_campaign_signoff_existing_summary_refresh_reason == "" then null else $profile_compare_campaign_signoff_existing_summary_refresh_reason end)
        },
        profile_compare_campaign_signoff_campaign_refresh_overrides_requested: {
          execution_mode: (if $profile_compare_campaign_signoff_campaign_execution_mode == "auto" then null else $profile_compare_campaign_signoff_campaign_execution_mode end),
          directory_urls: (if $profile_compare_campaign_signoff_campaign_directory_urls == "" then null else $profile_compare_campaign_signoff_campaign_directory_urls end),
          bootstrap_directory: (if $profile_compare_campaign_signoff_campaign_bootstrap_directory == "" then null else $profile_compare_campaign_signoff_campaign_bootstrap_directory end),
          discovery_wait_sec: (if $profile_compare_campaign_signoff_campaign_discovery_wait_sec == "" then null else ($profile_compare_campaign_signoff_campaign_discovery_wait_sec | tonumber) end),
          issuer_url: (if $profile_compare_campaign_signoff_campaign_issuer_url == "" then null else $profile_compare_campaign_signoff_campaign_issuer_url end),
          entry_url: (if $profile_compare_campaign_signoff_campaign_entry_url == "" then null else $profile_compare_campaign_signoff_campaign_entry_url end),
          exit_url: (if $profile_compare_campaign_signoff_campaign_exit_url == "" then null else $profile_compare_campaign_signoff_campaign_exit_url end),
          start_local_stack: (if $profile_compare_campaign_signoff_campaign_start_local_stack == "" then null else $profile_compare_campaign_signoff_campaign_start_local_stack end)
        },
        profile_compare_campaign_signoff_campaign_refresh_overrides_effective: {
          execution_mode: (if $profile_compare_campaign_signoff_campaign_execution_mode_effective == "" then null else $profile_compare_campaign_signoff_campaign_execution_mode_effective end),
          directory_urls: (if $profile_compare_campaign_signoff_campaign_directory_urls_effective == "" then null else $profile_compare_campaign_signoff_campaign_directory_urls_effective end),
          bootstrap_directory: (if $profile_compare_campaign_signoff_campaign_bootstrap_directory_effective == "" then null else $profile_compare_campaign_signoff_campaign_bootstrap_directory_effective end),
          discovery_wait_sec: (if $profile_compare_campaign_signoff_campaign_discovery_wait_sec_effective == "" then null else ($profile_compare_campaign_signoff_campaign_discovery_wait_sec_effective | tonumber) end),
          issuer_url: (if $profile_compare_campaign_signoff_campaign_issuer_url_effective == "" then null else $profile_compare_campaign_signoff_campaign_issuer_url_effective end),
          entry_url: (if $profile_compare_campaign_signoff_campaign_entry_url_effective == "" then null else $profile_compare_campaign_signoff_campaign_entry_url_effective end),
          exit_url: (if $profile_compare_campaign_signoff_campaign_exit_url_effective == "" then null else $profile_compare_campaign_signoff_campaign_exit_url_effective end),
          start_local_stack: (if $profile_compare_campaign_signoff_campaign_start_local_stack_effective == "" then null else $profile_compare_campaign_signoff_campaign_start_local_stack_effective end),
          docker_endpoints_available: ($three_machine_docker_endpoints_available == 1)
        },
        run_pre_real_host_readiness: $run_pre_real_host_readiness,
        run_real_wg_privileged_matrix: $run_real_wg_privileged_matrix,
        beta_preflight_privileged: $beta_preflight_privileged
      },
      paths: {
        root_dir: $root_dir,
        summary_json: $summary_json,
        summary_latest_json: $summary_latest_json,
        three_machine_docker_readiness_summary_json: $three_machine_docker_readiness_summary_json,
        profile_compare_campaign_signoff_reports_dir: $profile_compare_campaign_signoff_reports_dir,
        profile_compare_campaign_summary_json: $profile_compare_campaign_summary_json,
        profile_compare_campaign_signoff_summary_json: $profile_compare_campaign_signoff_summary_json,
        manual_validation_report_summary_json: $manual_validation_report_summary_json,
        manual_validation_report_md: $manual_validation_report_md
      },
      steps: $steps,
      summary: {
        total_steps: ($steps | length),
        pass_steps: ([ $steps[] | select(.status == "pass") ] | length),
        fail_steps: ([ $steps[] | select(.status == "fail") ] | length),
        skip_steps: ([ $steps[] | select(.status == "skip") ] | length),
        critical_fail_steps: $critical_steps_failed_count,
        non_blocking_fail_steps: $non_blocking_steps_failed_count,
        timed_out_steps: $timed_out_steps_count,
        timed_out_step_details: $timed_out_steps,
        critical_failed_steps: $critical_failed_steps,
        non_blocking_failed_steps: $non_blocking_failed_steps,
        manual_report_available: ($manual_report_available == 1),
        manual_report_validation_error: (if $manual_report_validation_error == "" then null else $manual_report_validation_error end),
        manual_readiness_status: $manual_readiness_status,
        roadmap_stage: $roadmap_stage,
        single_machine_ready: ($single_machine_ready == "true"),
        machine_c_smoke_ready: ($machine_c_smoke_ready == "true"),
        next_action_check_id: $next_action_check_id,
        next_action_command: $next_action_command,
        pending_checks: $pending_checks,
        pending_local_checks: $pending_local,
        pending_multi_machine_checks: $pending_multi_machine,
        three_machine_docker_readiness: {
          available: ($three_machine_docker_readiness_available == 1),
          status: $three_machine_docker_readiness_status,
          final_rc: ($three_machine_docker_readiness_final_rc | tonumber),
          ready: (
            if $three_machine_docker_readiness_status == "skip" then
              true
            elif $three_machine_docker_readiness_status == "pass" then
              ($three_machine_docker_readiness_available == 1)
            else
              false
            end
          )
        },
        profile_compare_campaign_signoff: {
          available: ($profile_compare_campaign_signoff_available == 1),
          status: $profile_compare_campaign_signoff_status,
          final_rc: ($profile_compare_campaign_signoff_final_rc | tonumber),
          decision: $profile_compare_campaign_signoff_decision,
          recommended_profile: $profile_compare_campaign_signoff_recommended_profile,
          selection_policy_evidence: {
            available: ($profile_compare_campaign_signoff_selection_policy_evidence_available == "1"),
            present: ($profile_compare_campaign_signoff_selection_policy_evidence_present == "1"),
            valid: ($profile_compare_campaign_signoff_selection_policy_evidence_valid == "1")
          },
          ready: ($profile_compare_campaign_signoff_status == "ok" and $profile_compare_campaign_signoff_decision == "GO")
        },
        real_wg_privileged_matrix: {
          status: $real_wg_privileged_matrix_step_status,
          ready: ($real_wg_privileged_matrix_step_status == "pass" or $real_wg_privileged_matrix_step_status == "skip"),
          non_blocking: true
        },
        profile_default_gate: $profile_default_gate,
        profile_default_ready: ($profile_default_ready == "true"),
        local_gate: $local_gate,
        real_host_gate: $real_host_gate
      }
    }'
} )"

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
printf '%s\n' "$summary_payload" >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"
if [[ "$summary_latest_json" != "$summary_json" ]]; then
  summary_latest_tmp="$(mktemp "${summary_latest_json}.tmp.XXXXXX")"
  printf '%s\n' "$summary_payload" >"$summary_latest_tmp"
  mv -f "$summary_latest_tmp" "$summary_latest_json"
fi

echo "[single-machine-prod-readiness] status=$overall_status rc=$overall_rc"
echo "[single-machine-prod-readiness] summary_json=$summary_json"
echo "[single-machine-prod-readiness] summary_latest_json=$summary_latest_json"
if [[ -n "$roadmap_stage" ]]; then
  echo "[single-machine-prod-readiness] roadmap_stage=$roadmap_stage"
fi
echo "[single-machine-prod-readiness] pending_local_count=$pending_local_count"
echo "[single-machine-prod-readiness] pending_multi_machine_count=$pending_multi_count"
if [[ -n "$manual_report_validation_error" ]]; then
  echo "[single-machine-prod-readiness] manual_validation_report_validation_error=$manual_report_validation_error"
fi
if [[ -n "$next_action_check_id" ]]; then
  echo "[single-machine-prod-readiness] next_action_check_id=$next_action_check_id"
fi
if [[ -n "$next_action_command" ]]; then
  echo "[single-machine-prod-readiness] next_action_command=$next_action_command"
fi
if [[ "$three_machine_docker_readiness_available" == "1" ]]; then
  echo "[single-machine-prod-readiness] three_machine_docker_readiness_status=$three_machine_docker_readiness_status"
fi
if [[ "$profile_compare_campaign_signoff_available" == "1" ]]; then
  echo "[single-machine-prod-readiness] profile_compare_campaign_signoff_status=$profile_compare_campaign_signoff_status decision=${profile_compare_campaign_signoff_decision:-unset}"
fi
if [[ "$real_wg_privileged_matrix_step_status" != "skip" ]]; then
  echo "[single-machine-prod-readiness] real_wg_privileged_matrix_step_status=$real_wg_privileged_matrix_step_status"
fi
if [[ -n "$profile_default_gate_status" ]]; then
  echo "[single-machine-prod-readiness] profile_default_gate_status=$profile_default_gate_status"
fi
echo "[single-machine-prod-readiness] profile_default_gate_available=$profile_default_gate_available"
if [[ -n "$profile_default_gate_decision" ]]; then
  echo "[single-machine-prod-readiness] profile_default_gate_decision=$profile_default_gate_decision"
fi
if [[ -n "$profile_default_gate_recommended_profile" ]]; then
  echo "[single-machine-prod-readiness] profile_default_gate_recommended_profile=$profile_default_gate_recommended_profile"
fi
if [[ -n "$profile_default_gate_next_command" ]]; then
  echo "[single-machine-prod-readiness] profile_default_gate_next_command=$profile_default_gate_next_command"
fi

if [[ "$print_summary_json" == "1" ]]; then
  echo "[single-machine-prod-readiness] summary_json_payload:"
  printf '%s\n' "$summary_payload"
fi

exit "$overall_rc"
