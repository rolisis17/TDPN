#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/vpn_non_blockchain_fastlane.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--runtime-fix-record-summary-json PATH] \
    [--phase1-resilience-handoff-run-summary-json PATH] \
    [--phase2-linux-prod-candidate-handoff-run-summary-json PATH] \
    [--phase3-windows-client-beta-handoff-run-summary-json PATH] \
    [--phase4-windows-full-parity-handoff-run-summary-json PATH] \
    [--vpn-rc-resilience-summary-json PATH] \
    [--roadmap-progress-summary-json PATH] \
    [--roadmap-progress-report-md PATH] \
    [--run-runtime-fix-record [0|1]] \
    [--run-phase1-resilience-handoff-run [0|1]] \
    [--run-phase2-linux-prod-candidate-handoff-run [0|1]] \
    [--run-phase3-windows-client-beta-handoff-run [0|1]] \
    [--run-phase4-windows-full-parity-handoff-run [0|1]] \
    [--run-roadmap-progress-report [0|1]] \
    [--parallel [0|1]] \
    [--allow-policy-no-go [0|1]] \
    [--print-summary-json [0|1]] \
    [--dry-run [0|1]] \
    [--runtime-<arg> ...] \
    [--phase1-<arg> ...] \
    [--phase2-<arg> ...] \
    [--phase3-<arg> ...] \
    [--phase4-<arg> ...] \
    [--roadmap-<arg> ...]

Purpose:
  One-command non-chain fastlane for highest-value VPN/app gates:
    1) runtime_fix_record.sh
    2) phase1_resilience_handoff_run.sh
    3) phase2_linux_prod_candidate_handoff_run.sh
    4) phase3_windows_client_beta_handoff_run.sh
    5) phase4_windows_full_parity_handoff_run.sh
    6) roadmap_progress_report.sh

Notes:
  - This wrapper intentionally excludes settlement-chain and chain modules.
  - Independent non-chain stages (runtime + phase1..4 handoff-run) run in parallel by default.
    Use --parallel 0 (or VPN_NON_BLOCKCHAIN_FASTLANE_PARALLEL=0) for sequential debug mode.
  - roadmap_progress_report runs after phase1..4 summaries are ready.
  - Dry-run is forwarded to phase1/2/3/4 handoff-run stages only.
  - --allow-policy-no-go is forwarded to phase1 unless an explicit
    --phase1-allow-policy-no-go passthrough is provided.
  - Wrapper emits a machine-readable summary JSON for both normal and dry-run.
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

array_has_arg() {
  local needle="$1"
  shift
  local arg
  for arg in "$@"; do
    if [[ "$arg" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

array_has_arg_or_equals_prefix() {
  local needle="$1"
  shift
  local arg
  for arg in "$@"; do
    if [[ "$arg" == "$needle" || "$arg" == "$needle="* ]]; then
      return 0
    fi
  done
  return 1
}

path_within_dir() {
  local path
  local dir
  path="$(abs_path "${1:-}")"
  dir="$(abs_path "${2:-}")"
  path="${path%/}"
  dir="${dir%/}"
  if [[ -z "$path" || -z "$dir" ]]; then
    return 1
  fi
  [[ "$path" == "$dir" || "$path" == "$dir/"* ]]
}

json_file_valid() {
  local path="$1"
  [[ -f "$path" ]] && jq -e . "$path" >/dev/null 2>&1
}

resolve_path_with_base() {
  local candidate
  local base_file
  local base_dir=""
  candidate="$(trim "${1:-}")"
  base_file="$(trim "${2:-}")"
  if [[ -z "$candidate" ]]; then
    printf '%s' ""
    return
  fi
  if [[ "$candidate" == /* ]]; then
    printf '%s' "$candidate"
    return
  fi
  if [[ -n "$base_file" && -e "$base_file" ]]; then
    base_dir="$(cd "$(dirname "$base_file")" && pwd)"
    if [[ -f "$base_dir/$candidate" ]]; then
      printf '%s' "$base_dir/$candidate"
      return
    fi
  fi
  printf '%s' "$ROOT_DIR/$candidate"
}

json_string_field_or_empty() {
  local path="${1:-}"
  local jq_expr="${2:-}"
  local value=""
  if ! json_file_valid "$path"; then
    printf '%s' ""
    return
  fi
  value="$(jq -r "$jq_expr" "$path" 2>/dev/null || true)"
  value="$(trim "$value")"
  if [[ "$value" == "null" ]]; then
    value=""
  fi
  printf '%s' "$value"
}

json_bool_field_or_empty() {
  local path="${1:-}"
  local jq_expr="${2:-}"
  local value=""
  if ! json_file_valid "$path"; then
    printf '%s' ""
    return
  fi
  value="$(jq -r "$jq_expr" "$path" 2>/dev/null || true)"
  value="$(trim "$value")"
  case "$value" in
    true|false)
      printf '%s' "$value"
      ;;
    *)
      printf '%s' ""
      ;;
  esac
}

runtime_fix_record_summary_contract_valid() {
  local path="$1"
  json_file_valid "$path"
}

phase1_summary_contract_valid() {
  local path="$1"
  if ! json_file_valid "$path"; then
    return 1
  fi
  jq -e '
    (.schema | type) == "object"
    and (.schema.id // "") == "phase1_resilience_handoff_run_summary"
    and ((.schema.major // 0) | type) == "number"
    and ((.schema.major // 0) == 1)
    and (.status | type) == "string"
    and (.rc | type) == "number"
  ' "$path" >/dev/null 2>&1
}

phase2_summary_contract_valid() {
  local path="$1"
  if ! json_file_valid "$path"; then
    return 1
  fi
  jq -e '
    (.schema | type) == "object"
    and (.schema.id // "") == "phase2_linux_prod_candidate_handoff_run_summary"
    and ((.schema.major // 0) | type) == "number"
    and ((.schema.major // 0) == 1)
    and (.status | type) == "string"
    and (.rc | type) == "number"
  ' "$path" >/dev/null 2>&1
}

phase3_summary_contract_valid() {
  local path="$1"
  if ! json_file_valid "$path"; then
    return 1
  fi
  jq -e '
    (.schema | type) == "object"
    and (.schema.id // "") == "phase3_windows_client_beta_handoff_run_summary"
    and ((.schema.major // 0) | type) == "number"
    and ((.schema.major // 0) == 1)
    and (.status | type) == "string"
    and (.rc | type) == "number"
  ' "$path" >/dev/null 2>&1
}

phase4_summary_contract_valid() {
  local path="$1"
  if ! json_file_valid "$path"; then
    return 1
  fi
  jq -e '
    (.schema | type) == "object"
    and (.schema.id // "") == "phase4_windows_full_parity_handoff_run_summary"
    and ((.schema.major // 0) | type) == "number"
    and ((.schema.major // 0) == 1)
    and (.status | type) == "string"
    and (.rc | type) == "number"
  ' "$path" >/dev/null 2>&1
}

roadmap_summary_contract_valid() {
  local path="$1"
  if ! json_file_valid "$path"; then
    return 1
  fi
  jq -e '
    type == "object"
    and (.status | type) == "string"
    and (.rc | type) == "number"
    and (
      ((.vpn_track | type) == "object")
      or (((.summary | type) == "object") and ((.report | type) == "object"))
    )
  ' "$path" >/dev/null 2>&1
}

resolve_phase1_handoff_check_summary_path() {
  local phase1_summary_path="${1:-}"
  local candidate=""
  if ! json_file_valid "$phase1_summary_path"; then
    printf '%s' ""
    return
  fi
  candidate="$(json_string_field_or_empty "$phase1_summary_path" '
    if (.artifacts.handoff_summary_json | type) == "string" then .artifacts.handoff_summary_json
    elif (.steps.phase1_resilience_handoff_check.artifacts.summary_json | type) == "string" then .steps.phase1_resilience_handoff_check.artifacts.summary_json
    else "" end
  ')"
  candidate="$(resolve_path_with_base "$candidate" "$phase1_summary_path")"
  if json_file_valid "$candidate"; then
    printf '%s' "$candidate"
  else
    printf '%s' ""
  fi
}

merge_phase1_failure_semantics_from_summary() {
  local source_path="${1:-}"
  local merged_any="0"
  local value=""
  if ! json_file_valid "$source_path"; then
    return
  fi

  if [[ -z "$phase1_failure_kind" ]]; then
    value="$(json_string_field_or_empty "$source_path" '
      if (.failure.kind | type) == "string" then .failure.kind
      elif (.handoff.failure.kind | type) == "string" then .handoff.failure.kind
      else "" end
    ')"
    if [[ -n "$value" ]]; then
      phase1_failure_kind="$value"
      merged_any="1"
    fi
  fi

  if [[ -z "$phase1_policy_outcome_decision" ]]; then
    value="$(json_string_field_or_empty "$source_path" '
      if (.policy_outcome.decision | type) == "string" then .policy_outcome.decision
      elif (.handoff.policy_outcome.decision | type) == "string" then .handoff.policy_outcome.decision
      else "" end
    ')"
    if [[ -n "$value" ]]; then
      phase1_policy_outcome_decision="$value"
      merged_any="1"
    fi
  fi

  if [[ "$phase1_policy_outcome_fail_closed_no_go" == "null" ]]; then
    value="$(json_bool_field_or_empty "$source_path" '
      if (.policy_outcome.fail_closed_no_go | type) == "boolean" then .policy_outcome.fail_closed_no_go
      elif (.handoff.policy_outcome.fail_closed_no_go | type) == "boolean" then .handoff.policy_outcome.fail_closed_no_go
      else empty end
    ')"
    if [[ "$value" == "true" || "$value" == "false" ]]; then
      phase1_policy_outcome_fail_closed_no_go="$value"
      merged_any="1"
    fi
  fi

  if [[ -z "$phase1_profile_matrix_stable_failure_kind" ]]; then
    value="$(json_string_field_or_empty "$source_path" '
      if (.handoff.failure_semantics.profile_matrix_stable.kind | type) == "string" then .handoff.failure_semantics.profile_matrix_stable.kind
      elif (.failure_semantics.profile_matrix_stable.kind | type) == "string" then .failure_semantics.profile_matrix_stable.kind
      else "" end
    ')"
    if [[ -n "$value" ]]; then
      phase1_profile_matrix_stable_failure_kind="$value"
      merged_any="1"
    fi
  fi

  if [[ -z "$phase1_peer_loss_recovery_ok_failure_kind" ]]; then
    value="$(json_string_field_or_empty "$source_path" '
      if (.handoff.failure_semantics.peer_loss_recovery_ok.kind | type) == "string" then .handoff.failure_semantics.peer_loss_recovery_ok.kind
      elif (.failure_semantics.peer_loss_recovery_ok.kind | type) == "string" then .failure_semantics.peer_loss_recovery_ok.kind
      else "" end
    ')"
    if [[ -n "$value" ]]; then
      phase1_peer_loss_recovery_ok_failure_kind="$value"
      merged_any="1"
    fi
  fi

  if [[ -z "$phase1_session_churn_guard_ok_failure_kind" ]]; then
    value="$(json_string_field_or_empty "$source_path" '
      if (.handoff.failure_semantics.session_churn_guard_ok.kind | type) == "string" then .handoff.failure_semantics.session_churn_guard_ok.kind
      elif (.failure_semantics.session_churn_guard_ok.kind | type) == "string" then .failure_semantics.session_churn_guard_ok.kind
      else "" end
    ')"
    if [[ -n "$value" ]]; then
      phase1_session_churn_guard_ok_failure_kind="$value"
      merged_any="1"
    fi
  fi

  if [[ "$merged_any" == "1" && -z "$phase1_failure_semantics_source_summary_json" ]]; then
    phase1_failure_semantics_source_summary_json="$source_path"
  fi
}

extract_phase1_failure_semantics() {
  local handoff_summary_json=""
  phase1_failure_semantics_source_summary_json=""
  phase1_failure_kind=""
  phase1_policy_outcome_decision=""
  phase1_policy_outcome_fail_closed_no_go="null"
  phase1_profile_matrix_stable_failure_kind=""
  phase1_peer_loss_recovery_ok_failure_kind=""
  phase1_session_churn_guard_ok_failure_kind=""

  merge_phase1_failure_semantics_from_summary "$phase1_summary_json"
  handoff_summary_json="$(resolve_phase1_handoff_check_summary_path "$phase1_summary_json")"
  if [[ -n "$handoff_summary_json" ]]; then
    merge_phase1_failure_semantics_from_summary "$handoff_summary_json"
  fi
}

run_stage_capture() {
  local label="$1"
  local log_path="$2"
  shift 2
  local rc=0
  echo "[vpn-non-blockchain-fastlane] stage=$label status=running"
  set +e
  "$@" >"$log_path" 2>&1
  rc=$?
  set -e
  if (( rc == 0 )); then
    echo "[vpn-non-blockchain-fastlane] stage=$label status=pass rc=0"
  else
    echo "[vpn-non-blockchain-fastlane] stage=$label status=fail rc=$rc"
  fi
  return "$rc"
}

update_first_failure_rc() {
  local step_rc="$1"
  if (( step_rc != 0 )) && (( final_rc == 0 )); then
    final_rc="$step_rc"
  fi
}

need_cmd jq
need_cmd date
need_cmd mktemp

reports_dir="${VPN_NON_BLOCKCHAIN_FASTLANE_REPORTS_DIR:-}"
summary_json="${VPN_NON_BLOCKCHAIN_FASTLANE_SUMMARY_JSON:-}"
runtime_summary_json="${VPN_NON_BLOCKCHAIN_FASTLANE_RUNTIME_FIX_RECORD_SUMMARY_JSON:-}"
phase1_summary_json="${VPN_NON_BLOCKCHAIN_FASTLANE_PHASE1_RESILIENCE_HANDOFF_RUN_SUMMARY_JSON:-}"
phase2_summary_json="${VPN_NON_BLOCKCHAIN_FASTLANE_PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SUMMARY_JSON:-}"
phase3_summary_json="${VPN_NON_BLOCKCHAIN_FASTLANE_PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_RUN_SUMMARY_JSON:-}"
phase4_summary_json="${VPN_NON_BLOCKCHAIN_FASTLANE_PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_SUMMARY_JSON:-}"
roadmap_vpn_rc_resilience_summary_json="${VPN_NON_BLOCKCHAIN_FASTLANE_VPN_RC_RESILIENCE_SUMMARY_JSON:-}"
roadmap_summary_json="${VPN_NON_BLOCKCHAIN_FASTLANE_ROADMAP_PROGRESS_SUMMARY_JSON:-}"
roadmap_report_md="${VPN_NON_BLOCKCHAIN_FASTLANE_ROADMAP_PROGRESS_REPORT_MD:-}"

run_runtime_fix_record="${VPN_NON_BLOCKCHAIN_FASTLANE_RUN_RUNTIME_FIX_RECORD:-1}"
run_phase1_resilience_handoff_run="${VPN_NON_BLOCKCHAIN_FASTLANE_RUN_PHASE1_RESILIENCE_HANDOFF_RUN:-1}"
run_phase2_linux_prod_candidate_handoff_run="${VPN_NON_BLOCKCHAIN_FASTLANE_RUN_PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN:-1}"
run_phase3_windows_client_beta_handoff_run="${VPN_NON_BLOCKCHAIN_FASTLANE_RUN_PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_RUN:-1}"
run_phase4_windows_full_parity_handoff_run="${VPN_NON_BLOCKCHAIN_FASTLANE_RUN_PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN:-1}"
run_roadmap_progress_report="${VPN_NON_BLOCKCHAIN_FASTLANE_RUN_ROADMAP_PROGRESS_REPORT:-1}"
parallel="${VPN_NON_BLOCKCHAIN_FASTLANE_PARALLEL:-1}"
allow_policy_no_go="${VPN_NON_BLOCKCHAIN_FASTLANE_ALLOW_POLICY_NO_GO:-0}"
print_summary_json="${VPN_NON_BLOCKCHAIN_FASTLANE_PRINT_SUMMARY_JSON:-1}"
dry_run="${VPN_NON_BLOCKCHAIN_FASTLANE_DRY_RUN:-0}"

declare -a runtime_passthrough_args=()
declare -a phase1_passthrough_args=()
declare -a phase2_passthrough_args=()
declare -a phase3_passthrough_args=()
declare -a phase4_passthrough_args=()
declare -a roadmap_passthrough_args=()

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
    --runtime-fix-record-summary-json)
      runtime_summary_json="${2:-}"
      shift 2
      ;;
    --phase1-resilience-handoff-run-summary-json)
      phase1_summary_json="${2:-}"
      shift 2
      ;;
    --phase2-linux-prod-candidate-handoff-run-summary-json)
      phase2_summary_json="${2:-}"
      shift 2
      ;;
    --phase3-windows-client-beta-handoff-run-summary-json)
      phase3_summary_json="${2:-}"
      shift 2
      ;;
    --phase4-windows-full-parity-handoff-run-summary-json)
      phase4_summary_json="${2:-}"
      shift 2
      ;;
    --vpn-rc-resilience-summary-json)
      roadmap_vpn_rc_resilience_summary_json="${2:-}"
      shift 2
      ;;
    --roadmap-progress-summary-json)
      roadmap_summary_json="${2:-}"
      shift 2
      ;;
    --roadmap-progress-report-md)
      roadmap_report_md="${2:-}"
      shift 2
      ;;
    --run-runtime-fix-record)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_runtime_fix_record="${2:-}"
        shift 2
      else
        run_runtime_fix_record="1"
        shift
      fi
      ;;
    --run-phase1-resilience-handoff-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase1_resilience_handoff_run="${2:-}"
        shift 2
      else
        run_phase1_resilience_handoff_run="1"
        shift
      fi
      ;;
    --run-phase2-linux-prod-candidate-handoff-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase2_linux_prod_candidate_handoff_run="${2:-}"
        shift 2
      else
        run_phase2_linux_prod_candidate_handoff_run="1"
        shift
      fi
      ;;
    --run-phase3-windows-client-beta-handoff-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase3_windows_client_beta_handoff_run="${2:-}"
        shift 2
      else
        run_phase3_windows_client_beta_handoff_run="1"
        shift
      fi
      ;;
    --run-phase4-windows-full-parity-handoff-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase4_windows_full_parity_handoff_run="${2:-}"
        shift 2
      else
        run_phase4_windows_full_parity_handoff_run="1"
        shift
      fi
      ;;
    --run-roadmap-progress-report)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_roadmap_progress_report="${2:-}"
        shift 2
      else
        run_roadmap_progress_report="1"
        shift
      fi
      ;;
    --parallel)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        parallel="${2:-}"
        shift 2
      else
        parallel="1"
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
    --runtime-*)
      forwarded_flag="--${1#--runtime-}"
      if [[ "$forwarded_flag" == "--" ]]; then
        echo "invalid runtime-prefixed arg: $1"
        exit 2
      fi
      if [[ $# -ge 2 && ! "${2:-}" =~ ^-- ]]; then
        runtime_passthrough_args+=("$forwarded_flag" "${2:-}")
        shift 2
      else
        runtime_passthrough_args+=("$forwarded_flag")
        shift
      fi
      ;;
    --phase1-*)
      forwarded_flag="--${1#--phase1-}"
      if [[ "$forwarded_flag" == "--" ]]; then
        echo "invalid phase1-prefixed arg: $1"
        exit 2
      fi
      if [[ $# -ge 2 && ! "${2:-}" =~ ^-- ]]; then
        phase1_passthrough_args+=("$forwarded_flag" "${2:-}")
        shift 2
      else
        phase1_passthrough_args+=("$forwarded_flag")
        shift
      fi
      ;;
    --phase2-*)
      forwarded_flag="--${1#--phase2-}"
      if [[ "$forwarded_flag" == "--" ]]; then
        echo "invalid phase2-prefixed arg: $1"
        exit 2
      fi
      if [[ $# -ge 2 && ! "${2:-}" =~ ^-- ]]; then
        phase2_passthrough_args+=("$forwarded_flag" "${2:-}")
        shift 2
      else
        phase2_passthrough_args+=("$forwarded_flag")
        shift
      fi
      ;;
    --phase3-*)
      forwarded_flag="--${1#--phase3-}"
      if [[ "$forwarded_flag" == "--" ]]; then
        echo "invalid phase3-prefixed arg: $1"
        exit 2
      fi
      if [[ $# -ge 2 && ! "${2:-}" =~ ^-- ]]; then
        phase3_passthrough_args+=("$forwarded_flag" "${2:-}")
        shift 2
      else
        phase3_passthrough_args+=("$forwarded_flag")
        shift
      fi
      ;;
    --phase4-*)
      forwarded_flag="--${1#--phase4-}"
      if [[ "$forwarded_flag" == "--" ]]; then
        echo "invalid phase4-prefixed arg: $1"
        exit 2
      fi
      if [[ $# -ge 2 && ! "${2:-}" =~ ^-- ]]; then
        phase4_passthrough_args+=("$forwarded_flag" "${2:-}")
        shift 2
      else
        phase4_passthrough_args+=("$forwarded_flag")
        shift
      fi
      ;;
    --roadmap-*)
      forwarded_flag="--${1#--roadmap-}"
      if [[ "$forwarded_flag" == "--" ]]; then
        echo "invalid roadmap-prefixed arg: $1"
        exit 2
      fi
      if [[ $# -ge 2 && ! "${2:-}" =~ ^-- ]]; then
        roadmap_passthrough_args+=("$forwarded_flag" "${2:-}")
        shift 2
      else
        roadmap_passthrough_args+=("$forwarded_flag")
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

bool_arg_or_die "--run-runtime-fix-record" "$run_runtime_fix_record"
bool_arg_or_die "--run-phase1-resilience-handoff-run" "$run_phase1_resilience_handoff_run"
bool_arg_or_die "--run-phase2-linux-prod-candidate-handoff-run" "$run_phase2_linux_prod_candidate_handoff_run"
bool_arg_or_die "--run-phase3-windows-client-beta-handoff-run" "$run_phase3_windows_client_beta_handoff_run"
bool_arg_or_die "--run-phase4-windows-full-parity-handoff-run" "$run_phase4_windows_full_parity_handoff_run"
bool_arg_or_die "--run-roadmap-progress-report" "$run_roadmap_progress_report"
bool_arg_or_die "--parallel" "$parallel"
bool_arg_or_die "--allow-policy-no-go" "$allow_policy_no_go"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--dry-run" "$dry_run"

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/vpn_non_blockchain_fastlane_${run_stamp}"
fi
reports_dir="$(abs_path "$reports_dir")"
mkdir -p "$reports_dir"

if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/vpn_non_blockchain_fastlane_summary.json"
fi
if [[ -z "$runtime_summary_json" ]]; then
  runtime_summary_json="$reports_dir/runtime_fix_record_summary.json"
fi
if [[ -z "$phase1_summary_json" ]]; then
  phase1_summary_json="$reports_dir/phase1_resilience_handoff_run_summary.json"
fi
if [[ -z "$phase2_summary_json" ]]; then
  phase2_summary_json="$reports_dir/phase2_linux_prod_candidate_handoff_run_summary.json"
fi
if [[ -z "$phase3_summary_json" ]]; then
  phase3_summary_json="$reports_dir/phase3_windows_client_beta_handoff_run_summary.json"
fi
if [[ -z "$phase4_summary_json" ]]; then
  phase4_summary_json="$reports_dir/phase4_windows_full_parity_handoff_run_summary.json"
fi
if [[ -z "$roadmap_vpn_rc_resilience_summary_json" ]]; then
  roadmap_vpn_rc_resilience_summary_json="$reports_dir/ci_phase1_resilience/vpn_rc_resilience_path/vpn_rc_resilience_path_summary.json"
fi
if [[ -z "$roadmap_summary_json" ]]; then
  roadmap_summary_json="$reports_dir/roadmap_progress_summary.json"
fi
if [[ -z "$roadmap_report_md" ]]; then
  roadmap_report_md="$reports_dir/roadmap_progress_report.md"
fi

summary_json="$(abs_path "$summary_json")"
runtime_summary_json="$(abs_path "$runtime_summary_json")"
phase1_summary_json="$(abs_path "$phase1_summary_json")"
phase2_summary_json="$(abs_path "$phase2_summary_json")"
phase3_summary_json="$(abs_path "$phase3_summary_json")"
phase4_summary_json="$(abs_path "$phase4_summary_json")"
roadmap_vpn_rc_resilience_summary_json="$(abs_path "$roadmap_vpn_rc_resilience_summary_json")"
roadmap_summary_json="$(abs_path "$roadmap_summary_json")"
roadmap_report_md="$(abs_path "$roadmap_report_md")"

mkdir -p "$(dirname "$summary_json")"
mkdir -p "$(dirname "$runtime_summary_json")"
mkdir -p "$(dirname "$phase1_summary_json")"
mkdir -p "$(dirname "$phase2_summary_json")"
mkdir -p "$(dirname "$phase3_summary_json")"
mkdir -p "$(dirname "$phase4_summary_json")"
mkdir -p "$(dirname "$roadmap_vpn_rc_resilience_summary_json")"
mkdir -p "$(dirname "$roadmap_summary_json")"
mkdir -p "$(dirname "$roadmap_report_md")"

runtime_fix_record_script="${VPN_NON_BLOCKCHAIN_FASTLANE_RUNTIME_FIX_RECORD_SCRIPT:-$ROOT_DIR/scripts/runtime_fix_record.sh}"
phase1_script="${VPN_NON_BLOCKCHAIN_FASTLANE_PHASE1_RESILIENCE_HANDOFF_RUN_SCRIPT:-$ROOT_DIR/scripts/phase1_resilience_handoff_run.sh}"
phase2_script="${VPN_NON_BLOCKCHAIN_FASTLANE_PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SCRIPT:-$ROOT_DIR/scripts/phase2_linux_prod_candidate_handoff_run.sh}"
phase3_script="${VPN_NON_BLOCKCHAIN_FASTLANE_PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_RUN_SCRIPT:-$ROOT_DIR/scripts/phase3_windows_client_beta_handoff_run.sh}"
phase4_script="${VPN_NON_BLOCKCHAIN_FASTLANE_PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_SCRIPT:-$ROOT_DIR/scripts/phase4_windows_full_parity_handoff_run.sh}"
roadmap_script="${VPN_NON_BLOCKCHAIN_FASTLANE_ROADMAP_PROGRESS_REPORT_SCRIPT:-$ROOT_DIR/scripts/roadmap_progress_report.sh}"

for script_path in \
  "$runtime_fix_record_script" \
  "$phase1_script" \
  "$phase2_script" \
  "$phase3_script" \
  "$phase4_script" \
  "$roadmap_script"; do
  if [[ ! -x "$script_path" ]]; then
    echo "missing executable stage script: $script_path"
    exit 2
  fi
done

runtime_cmd=(
  "$runtime_fix_record_script"
  --summary-json "$runtime_summary_json"
  --print-summary-json 0
)
if [[ "${#runtime_passthrough_args[@]}" -gt 0 ]]; then
  runtime_cmd+=("${runtime_passthrough_args[@]}")
fi

phase1_cmd=(
  "$phase1_script"
  --reports-dir "$reports_dir"
  --summary-json "$phase1_summary_json"
  --print-summary-json 0
)
if ! array_has_arg "--resume" "${phase1_passthrough_args[@]}"; then
  # Default Phase-1 handoff run to resumable mode so retries on the same
  # reports-dir can continue quickly without rerunning already-pass stages.
  phase1_cmd+=(--resume 1)
fi
if [[ "$dry_run" == "1" ]] && ! array_has_arg "--dry-run" "${phase1_passthrough_args[@]}"; then
  phase1_cmd+=(--dry-run 1)
fi
if [[ "$allow_policy_no_go" == "1" ]] && ! array_has_arg_or_equals_prefix "--allow-policy-no-go" "${phase1_passthrough_args[@]}"; then
  phase1_cmd+=(--allow-policy-no-go 1)
fi
if [[ "${#phase1_passthrough_args[@]}" -gt 0 ]]; then
  phase1_cmd+=("${phase1_passthrough_args[@]}")
fi

phase2_cmd=(
  "$phase2_script"
  --reports-dir "$reports_dir"
  --summary-json "$phase2_summary_json"
  --print-summary-json 0
)
if ! array_has_arg "--resume" "${phase2_passthrough_args[@]}"; then
  phase2_cmd+=(--resume 1)
fi
if [[ "$dry_run" == "1" ]] && ! array_has_arg "--dry-run" "${phase2_passthrough_args[@]}"; then
  phase2_cmd+=(--dry-run 1)
fi
if [[ "${#phase2_passthrough_args[@]}" -gt 0 ]]; then
  phase2_cmd+=("${phase2_passthrough_args[@]}")
fi

phase3_cmd=(
  "$phase3_script"
  --reports-dir "$reports_dir"
  --summary-json "$phase3_summary_json"
  --print-summary-json 0
)
if ! array_has_arg "--resume" "${phase3_passthrough_args[@]}"; then
  phase3_cmd+=(--resume 1)
fi
if [[ "$dry_run" == "1" ]] && ! array_has_arg "--dry-run" "${phase3_passthrough_args[@]}"; then
  phase3_cmd+=(--dry-run 1)
fi
if [[ "${#phase3_passthrough_args[@]}" -gt 0 ]]; then
  phase3_cmd+=("${phase3_passthrough_args[@]}")
fi

phase4_cmd=(
  "$phase4_script"
  --reports-dir "$reports_dir"
  --summary-json "$phase4_summary_json"
  --print-summary-json 0
)
if ! array_has_arg "--resume" "${phase4_passthrough_args[@]}"; then
  phase4_cmd+=(--resume 1)
fi
if [[ "$dry_run" == "1" ]] && ! array_has_arg "--dry-run" "${phase4_passthrough_args[@]}"; then
  phase4_cmd+=(--dry-run 1)
fi
if [[ "${#phase4_passthrough_args[@]}" -gt 0 ]]; then
  phase4_cmd+=("${phase4_passthrough_args[@]}")
fi

resolve_roadmap_resilience_summary_path() {
  local fallback_path="$reports_dir/ci_phase1_resilience/vpn_rc_resilience_path/vpn_rc_resilience_path_summary.json"
  local candidate="$roadmap_vpn_rc_resilience_summary_json"
  local ci_summary_candidate=""
  local nested_candidate=""

  if phase1_summary_contract_valid "$phase1_summary_json"; then
    ci_summary_candidate="$(jq -r '.artifacts.ci_summary_json // .steps.ci_phase1_resilience.artifacts.summary_json // ""' "$phase1_summary_json" 2>/dev/null || true)"
    ci_summary_candidate="$(abs_path "$ci_summary_candidate")"
    if [[ -n "$ci_summary_candidate" ]] && path_within_dir "$ci_summary_candidate" "$reports_dir" && json_file_valid "$ci_summary_candidate"; then
      nested_candidate="$(jq -r '.steps.vpn_rc_resilience_path.artifacts.summary_json // .artifacts.vpn_rc_resilience_summary_json // ""' "$ci_summary_candidate" 2>/dev/null || true)"
      nested_candidate="$(abs_path "$nested_candidate")"
      if [[ -n "$nested_candidate" ]] && path_within_dir "$nested_candidate" "$reports_dir"; then
        candidate="$nested_candidate"
      fi
    fi
  fi

  if [[ -z "$candidate" ]] || ! path_within_dir "$candidate" "$reports_dir"; then
    candidate="$fallback_path"
  fi
  roadmap_vpn_rc_resilience_summary_json="$(abs_path "$candidate")"
}

declare -a roadmap_cmd=()
build_roadmap_cmd() {
  roadmap_cmd=(
    "$roadmap_script"
  )
  if [[ "${#roadmap_passthrough_args[@]}" -gt 0 ]]; then
    roadmap_cmd+=("${roadmap_passthrough_args[@]}")
  fi
  roadmap_cmd+=(
    --refresh-manual-validation 0
    --refresh-single-machine-readiness 0
    --phase1-resilience-handoff-summary-json "$phase1_summary_json"
    --phase2-linux-prod-candidate-summary-json "$phase2_summary_json"
    --phase3-windows-client-beta-summary-json "$phase3_summary_json"
    --phase4-windows-full-parity-summary-json "$phase4_summary_json"
    --vpn-rc-resilience-summary-json "$roadmap_vpn_rc_resilience_summary_json"
    --summary-json "$roadmap_summary_json"
    --report-md "$roadmap_report_md"
    --print-report 0
    --print-summary-json 0
  )
}

final_rc=0

runtime_status="skip"
runtime_rc=0
runtime_command_rc=0
runtime_contract_valid="null"
runtime_contract_error=""
runtime_summary_exists="false"
runtime_log="$reports_dir/runtime_fix_record.log"
runtime_command=""

phase1_status="skip"
phase1_rc=0
phase1_command_rc=0
phase1_contract_valid="null"
phase1_contract_error=""
phase1_summary_exists="false"
phase1_log="$reports_dir/phase1_resilience_handoff_run.log"
phase1_command=""
phase1_failure_semantics_source_summary_json=""
phase1_failure_kind=""
phase1_policy_outcome_decision=""
phase1_policy_outcome_fail_closed_no_go="null"
phase1_profile_matrix_stable_failure_kind=""
phase1_peer_loss_recovery_ok_failure_kind=""
phase1_session_churn_guard_ok_failure_kind=""

phase2_status="skip"
phase2_rc=0
phase2_command_rc=0
phase2_contract_valid="null"
phase2_contract_error=""
phase2_summary_exists="false"
phase2_log="$reports_dir/phase2_linux_prod_candidate_handoff_run.log"
phase2_command=""

phase3_status="skip"
phase3_rc=0
phase3_command_rc=0
phase3_contract_valid="null"
phase3_contract_error=""
phase3_summary_exists="false"
phase3_log="$reports_dir/phase3_windows_client_beta_handoff_run.log"
phase3_command=""

phase4_status="skip"
phase4_rc=0
phase4_command_rc=0
phase4_contract_valid="null"
phase4_contract_error=""
phase4_summary_exists="false"
phase4_log="$reports_dir/phase4_windows_full_parity_handoff_run.log"
phase4_command=""

roadmap_status="skip"
roadmap_rc=0
roadmap_command_rc=0
roadmap_contract_valid="null"
roadmap_contract_error=""
roadmap_summary_exists="false"
roadmap_log="$reports_dir/roadmap_progress_report.log"
roadmap_command=""

runtime_pid=""
phase1_pid=""
phase2_pid=""
phase3_pid=""
phase4_pid=""

execution_mode="sequential"
if [[ "$parallel" == "1" ]]; then
  execution_mode="parallel"
fi

finalize_runtime_stage() {
  runtime_rc="$runtime_command_rc"
  if runtime_fix_record_summary_contract_valid "$runtime_summary_json"; then
    runtime_contract_valid="1"
    runtime_summary_exists="true"
  else
    runtime_contract_valid="0"
    runtime_contract_error="runtime_fix_record summary JSON is missing required fields or uses an incompatible schema"
    runtime_summary_exists="false"
    runtime_status="fail"
    if (( runtime_rc == 0 )); then
      runtime_rc=3
    fi
  fi
  update_first_failure_rc "$runtime_rc"
}

finalize_phase1_stage() {
  phase1_rc="$phase1_command_rc"
  if phase1_summary_contract_valid "$phase1_summary_json"; then
    phase1_contract_valid="1"
    phase1_summary_exists="true"
    extract_phase1_failure_semantics
  else
    phase1_contract_valid="0"
    phase1_contract_error="phase1_resilience_handoff_run summary JSON is missing required fields or uses an incompatible schema"
    phase1_summary_exists="false"
    phase1_status="fail"
    if (( phase1_rc == 0 )); then
      phase1_rc=3
    fi
  fi
  update_first_failure_rc "$phase1_rc"
}

finalize_phase2_stage() {
  phase2_rc="$phase2_command_rc"
  if phase2_summary_contract_valid "$phase2_summary_json"; then
    phase2_contract_valid="1"
    phase2_summary_exists="true"
  else
    phase2_contract_valid="0"
    phase2_contract_error="phase2_linux_prod_candidate_handoff_run summary JSON is missing required fields or uses an incompatible schema"
    phase2_summary_exists="false"
    phase2_status="fail"
    if (( phase2_rc == 0 )); then
      phase2_rc=3
    fi
  fi
  update_first_failure_rc "$phase2_rc"
}

finalize_phase3_stage() {
  phase3_rc="$phase3_command_rc"
  if phase3_summary_contract_valid "$phase3_summary_json"; then
    phase3_contract_valid="1"
    phase3_summary_exists="true"
  else
    phase3_contract_valid="0"
    phase3_contract_error="phase3_windows_client_beta_handoff_run summary JSON is missing required fields or uses an incompatible schema"
    phase3_summary_exists="false"
    phase3_status="fail"
    if (( phase3_rc == 0 )); then
      phase3_rc=3
    fi
  fi
  update_first_failure_rc "$phase3_rc"
}

finalize_phase4_stage() {
  phase4_rc="$phase4_command_rc"
  if phase4_summary_contract_valid "$phase4_summary_json"; then
    phase4_contract_valid="1"
    phase4_summary_exists="true"
  else
    phase4_contract_valid="0"
    phase4_contract_error="phase4_windows_full_parity_handoff_run summary JSON is missing required fields or uses an incompatible schema"
    phase4_summary_exists="false"
    phase4_status="fail"
    if (( phase4_rc == 0 )); then
      phase4_rc=3
    fi
  fi
  update_first_failure_rc "$phase4_rc"
}

if [[ "$parallel" == "1" ]]; then
  if [[ "$run_runtime_fix_record" == "1" ]]; then
    runtime_command="$(print_cmd "${runtime_cmd[@]}")"
    echo "[vpn-non-blockchain-fastlane] stage=runtime_fix_record status=running mode=parallel"
    ("${runtime_cmd[@]}" >"$runtime_log" 2>&1) &
    runtime_pid="$!"
  else
    echo "[vpn-non-blockchain-fastlane] stage=runtime_fix_record status=skip reason=disabled"
  fi

  if [[ "$run_phase1_resilience_handoff_run" == "1" ]]; then
    phase1_command="$(print_cmd "${phase1_cmd[@]}")"
    echo "[vpn-non-blockchain-fastlane] stage=phase1_resilience_handoff_run status=running mode=parallel"
    ("${phase1_cmd[@]}" >"$phase1_log" 2>&1) &
    phase1_pid="$!"
  else
    echo "[vpn-non-blockchain-fastlane] stage=phase1_resilience_handoff_run status=skip reason=disabled"
  fi

  if [[ "$run_phase2_linux_prod_candidate_handoff_run" == "1" ]]; then
    phase2_command="$(print_cmd "${phase2_cmd[@]}")"
    echo "[vpn-non-blockchain-fastlane] stage=phase2_linux_prod_candidate_handoff_run status=running mode=parallel"
    ("${phase2_cmd[@]}" >"$phase2_log" 2>&1) &
    phase2_pid="$!"
  else
    echo "[vpn-non-blockchain-fastlane] stage=phase2_linux_prod_candidate_handoff_run status=skip reason=disabled"
  fi

  if [[ "$run_phase3_windows_client_beta_handoff_run" == "1" ]]; then
    phase3_command="$(print_cmd "${phase3_cmd[@]}")"
    echo "[vpn-non-blockchain-fastlane] stage=phase3_windows_client_beta_handoff_run status=running mode=parallel"
    ("${phase3_cmd[@]}" >"$phase3_log" 2>&1) &
    phase3_pid="$!"
  else
    echo "[vpn-non-blockchain-fastlane] stage=phase3_windows_client_beta_handoff_run status=skip reason=disabled"
  fi

  if [[ "$run_phase4_windows_full_parity_handoff_run" == "1" ]]; then
    phase4_command="$(print_cmd "${phase4_cmd[@]}")"
    echo "[vpn-non-blockchain-fastlane] stage=phase4_windows_full_parity_handoff_run status=running mode=parallel"
    ("${phase4_cmd[@]}" >"$phase4_log" 2>&1) &
    phase4_pid="$!"
  else
    echo "[vpn-non-blockchain-fastlane] stage=phase4_windows_full_parity_handoff_run status=skip reason=disabled"
  fi

  if [[ -n "$runtime_pid" ]]; then
    if wait "$runtime_pid"; then
      runtime_command_rc=0
      runtime_status="pass"
    else
      runtime_command_rc=$?
      runtime_status="fail"
    fi
    echo "[vpn-non-blockchain-fastlane] stage=runtime_fix_record status=$runtime_status rc=$runtime_command_rc mode=parallel"
    finalize_runtime_stage
  fi

  if [[ -n "$phase1_pid" ]]; then
    if wait "$phase1_pid"; then
      phase1_command_rc=0
      phase1_status="pass"
    else
      phase1_command_rc=$?
      phase1_status="fail"
    fi
    echo "[vpn-non-blockchain-fastlane] stage=phase1_resilience_handoff_run status=$phase1_status rc=$phase1_command_rc mode=parallel"
    finalize_phase1_stage
  fi

  if [[ -n "$phase2_pid" ]]; then
    if wait "$phase2_pid"; then
      phase2_command_rc=0
      phase2_status="pass"
    else
      phase2_command_rc=$?
      phase2_status="fail"
    fi
    echo "[vpn-non-blockchain-fastlane] stage=phase2_linux_prod_candidate_handoff_run status=$phase2_status rc=$phase2_command_rc mode=parallel"
    finalize_phase2_stage
  fi

  if [[ -n "$phase3_pid" ]]; then
    if wait "$phase3_pid"; then
      phase3_command_rc=0
      phase3_status="pass"
    else
      phase3_command_rc=$?
      phase3_status="fail"
    fi
    echo "[vpn-non-blockchain-fastlane] stage=phase3_windows_client_beta_handoff_run status=$phase3_status rc=$phase3_command_rc mode=parallel"
    finalize_phase3_stage
  fi

  if [[ -n "$phase4_pid" ]]; then
    if wait "$phase4_pid"; then
      phase4_command_rc=0
      phase4_status="pass"
    else
      phase4_command_rc=$?
      phase4_status="fail"
    fi
    echo "[vpn-non-blockchain-fastlane] stage=phase4_windows_full_parity_handoff_run status=$phase4_status rc=$phase4_command_rc mode=parallel"
    finalize_phase4_stage
  fi
else
  if [[ "$run_runtime_fix_record" == "1" ]]; then
    runtime_command="$(print_cmd "${runtime_cmd[@]}")"
    if run_stage_capture "runtime_fix_record" "$runtime_log" "${runtime_cmd[@]}"; then
      runtime_command_rc=0
      runtime_status="pass"
    else
      runtime_command_rc=$?
      runtime_status="fail"
    fi
    finalize_runtime_stage
  else
    echo "[vpn-non-blockchain-fastlane] stage=runtime_fix_record status=skip reason=disabled"
  fi

  if [[ "$run_phase1_resilience_handoff_run" == "1" ]]; then
    phase1_command="$(print_cmd "${phase1_cmd[@]}")"
    if run_stage_capture "phase1_resilience_handoff_run" "$phase1_log" "${phase1_cmd[@]}"; then
      phase1_command_rc=0
      phase1_status="pass"
    else
      phase1_command_rc=$?
      phase1_status="fail"
    fi
    finalize_phase1_stage
  else
    echo "[vpn-non-blockchain-fastlane] stage=phase1_resilience_handoff_run status=skip reason=disabled"
  fi

  if [[ "$run_phase2_linux_prod_candidate_handoff_run" == "1" ]]; then
    phase2_command="$(print_cmd "${phase2_cmd[@]}")"
    if run_stage_capture "phase2_linux_prod_candidate_handoff_run" "$phase2_log" "${phase2_cmd[@]}"; then
      phase2_command_rc=0
      phase2_status="pass"
    else
      phase2_command_rc=$?
      phase2_status="fail"
    fi
    finalize_phase2_stage
  else
    echo "[vpn-non-blockchain-fastlane] stage=phase2_linux_prod_candidate_handoff_run status=skip reason=disabled"
  fi

  if [[ "$run_phase3_windows_client_beta_handoff_run" == "1" ]]; then
    phase3_command="$(print_cmd "${phase3_cmd[@]}")"
    if run_stage_capture "phase3_windows_client_beta_handoff_run" "$phase3_log" "${phase3_cmd[@]}"; then
      phase3_command_rc=0
      phase3_status="pass"
    else
      phase3_command_rc=$?
      phase3_status="fail"
    fi
    finalize_phase3_stage
  else
    echo "[vpn-non-blockchain-fastlane] stage=phase3_windows_client_beta_handoff_run status=skip reason=disabled"
  fi

  if [[ "$run_phase4_windows_full_parity_handoff_run" == "1" ]]; then
    phase4_command="$(print_cmd "${phase4_cmd[@]}")"
    if run_stage_capture "phase4_windows_full_parity_handoff_run" "$phase4_log" "${phase4_cmd[@]}"; then
      phase4_command_rc=0
      phase4_status="pass"
    else
      phase4_command_rc=$?
      phase4_status="fail"
    fi
    finalize_phase4_stage
  else
    echo "[vpn-non-blockchain-fastlane] stage=phase4_windows_full_parity_handoff_run status=skip reason=disabled"
  fi
fi

if [[ "$run_roadmap_progress_report" == "1" ]]; then
  resolve_roadmap_resilience_summary_path
  build_roadmap_cmd
  roadmap_command="$(print_cmd "${roadmap_cmd[@]}")"
  if run_stage_capture "roadmap_progress_report" "$roadmap_log" "${roadmap_cmd[@]}"; then
    roadmap_command_rc=0
    roadmap_status="pass"
  else
    roadmap_command_rc=$?
    roadmap_status="fail"
  fi
  roadmap_rc="$roadmap_command_rc"
  if roadmap_summary_contract_valid "$roadmap_summary_json"; then
    roadmap_contract_valid="1"
    roadmap_summary_exists="true"
  else
    roadmap_contract_valid="0"
    roadmap_contract_error="roadmap_progress_report summary JSON is missing required fields or uses an incompatible schema"
    roadmap_summary_exists="false"
    roadmap_status="fail"
    if (( roadmap_rc == 0 )); then
      roadmap_rc=3
    fi
  fi
  update_first_failure_rc "$roadmap_rc"
else
  echo "[vpn-non-blockchain-fastlane] stage=roadmap_progress_report status=skip reason=disabled"
fi

runtime_passthrough_json="$(printf '%s\n' "${runtime_passthrough_args[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"
phase1_passthrough_json="$(printf '%s\n' "${phase1_passthrough_args[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"
phase2_passthrough_json="$(printf '%s\n' "${phase2_passthrough_args[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"
phase3_passthrough_json="$(printf '%s\n' "${phase3_passthrough_args[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"
phase4_passthrough_json="$(printf '%s\n' "${phase4_passthrough_args[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"
roadmap_passthrough_json="$(printf '%s\n' "${roadmap_passthrough_args[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"

final_status="pass"
if (( final_rc != 0 )); then
  final_status="fail"
fi

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg runtime_summary_json "$runtime_summary_json" \
  --arg phase1_summary_json "$phase1_summary_json" \
  --arg phase2_summary_json "$phase2_summary_json" \
  --arg phase3_summary_json "$phase3_summary_json" \
  --arg phase4_summary_json "$phase4_summary_json" \
  --arg roadmap_vpn_rc_resilience_summary_json "$roadmap_vpn_rc_resilience_summary_json" \
  --arg roadmap_summary_json "$roadmap_summary_json" \
  --arg roadmap_report_md "$roadmap_report_md" \
  --argjson dry_run "$dry_run" \
  --argjson print_summary_json "$print_summary_json" \
  --argjson run_runtime_fix_record "$run_runtime_fix_record" \
  --argjson run_phase1_resilience_handoff_run "$run_phase1_resilience_handoff_run" \
  --argjson run_phase2_linux_prod_candidate_handoff_run "$run_phase2_linux_prod_candidate_handoff_run" \
  --argjson run_phase3_windows_client_beta_handoff_run "$run_phase3_windows_client_beta_handoff_run" \
  --argjson run_phase4_windows_full_parity_handoff_run "$run_phase4_windows_full_parity_handoff_run" \
  --argjson run_roadmap_progress_report "$run_roadmap_progress_report" \
  --argjson parallel "$parallel" \
  --argjson allow_policy_no_go "$allow_policy_no_go" \
  --arg execution_mode "$execution_mode" \
  --argjson runtime_passthrough_args "$runtime_passthrough_json" \
  --argjson phase1_passthrough_args "$phase1_passthrough_json" \
  --argjson phase2_passthrough_args "$phase2_passthrough_json" \
  --argjson phase3_passthrough_args "$phase3_passthrough_json" \
  --argjson phase4_passthrough_args "$phase4_passthrough_json" \
  --argjson roadmap_passthrough_args "$roadmap_passthrough_json" \
  --arg runtime_status "$runtime_status" \
  --argjson runtime_rc "$runtime_rc" \
  --argjson runtime_command_rc "$runtime_command_rc" \
  --arg runtime_command "$runtime_command" \
  --arg runtime_contract_valid "$runtime_contract_valid" \
  --arg runtime_contract_error "$runtime_contract_error" \
  --arg runtime_summary_exists "$runtime_summary_exists" \
  --arg runtime_log "$runtime_log" \
  --arg phase1_status "$phase1_status" \
  --argjson phase1_rc "$phase1_rc" \
  --argjson phase1_command_rc "$phase1_command_rc" \
  --arg phase1_command "$phase1_command" \
  --arg phase1_contract_valid "$phase1_contract_valid" \
  --arg phase1_contract_error "$phase1_contract_error" \
  --arg phase1_summary_exists "$phase1_summary_exists" \
  --arg phase1_log "$phase1_log" \
  --arg phase1_failure_semantics_source_summary_json "$phase1_failure_semantics_source_summary_json" \
  --arg phase1_failure_kind "$phase1_failure_kind" \
  --arg phase1_policy_outcome_decision "$phase1_policy_outcome_decision" \
  --arg phase1_policy_outcome_fail_closed_no_go "$phase1_policy_outcome_fail_closed_no_go" \
  --arg phase1_profile_matrix_stable_failure_kind "$phase1_profile_matrix_stable_failure_kind" \
  --arg phase1_peer_loss_recovery_ok_failure_kind "$phase1_peer_loss_recovery_ok_failure_kind" \
  --arg phase1_session_churn_guard_ok_failure_kind "$phase1_session_churn_guard_ok_failure_kind" \
  --arg phase2_status "$phase2_status" \
  --argjson phase2_rc "$phase2_rc" \
  --argjson phase2_command_rc "$phase2_command_rc" \
  --arg phase2_command "$phase2_command" \
  --arg phase2_contract_valid "$phase2_contract_valid" \
  --arg phase2_contract_error "$phase2_contract_error" \
  --arg phase2_summary_exists "$phase2_summary_exists" \
  --arg phase2_log "$phase2_log" \
  --arg phase3_status "$phase3_status" \
  --argjson phase3_rc "$phase3_rc" \
  --argjson phase3_command_rc "$phase3_command_rc" \
  --arg phase3_command "$phase3_command" \
  --arg phase3_contract_valid "$phase3_contract_valid" \
  --arg phase3_contract_error "$phase3_contract_error" \
  --arg phase3_summary_exists "$phase3_summary_exists" \
  --arg phase3_log "$phase3_log" \
  --arg phase4_status "$phase4_status" \
  --argjson phase4_rc "$phase4_rc" \
  --argjson phase4_command_rc "$phase4_command_rc" \
  --arg phase4_command "$phase4_command" \
  --arg phase4_contract_valid "$phase4_contract_valid" \
  --arg phase4_contract_error "$phase4_contract_error" \
  --arg phase4_summary_exists "$phase4_summary_exists" \
  --arg phase4_log "$phase4_log" \
  --arg roadmap_status "$roadmap_status" \
  --argjson roadmap_rc "$roadmap_rc" \
  --argjson roadmap_command_rc "$roadmap_command_rc" \
  --arg roadmap_command "$roadmap_command" \
  --arg roadmap_contract_valid "$roadmap_contract_valid" \
  --arg roadmap_contract_error "$roadmap_contract_error" \
  --arg roadmap_summary_exists "$roadmap_summary_exists" \
  --arg roadmap_log "$roadmap_log" \
  '{
    version: 1,
    schema: {
      id: "vpn_non_blockchain_fastlane_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    non_blockchain_only: true,
    execution: {
      mode: $execution_mode,
      parallel_enabled: ($parallel == 1),
      independent_parallel_stages: [
        "runtime_fix_record",
        "phase1_resilience_handoff_run",
        "phase2_linux_prod_candidate_handoff_run",
        "phase3_windows_client_beta_handoff_run",
        "phase4_windows_full_parity_handoff_run"
      ],
      sequential_dependency_stages: ["roadmap_progress_report"]
    },
    inputs: {
      dry_run: ($dry_run == 1),
      print_summary_json: ($print_summary_json == 1),
      parallel: ($parallel == 1),
      run_runtime_fix_record: ($run_runtime_fix_record == 1),
      run_phase1_resilience_handoff_run: ($run_phase1_resilience_handoff_run == 1),
      run_phase2_linux_prod_candidate_handoff_run: ($run_phase2_linux_prod_candidate_handoff_run == 1),
      run_phase3_windows_client_beta_handoff_run: ($run_phase3_windows_client_beta_handoff_run == 1),
      run_phase4_windows_full_parity_handoff_run: ($run_phase4_windows_full_parity_handoff_run == 1),
      run_roadmap_progress_report: ($run_roadmap_progress_report == 1),
      allow_policy_no_go: ($allow_policy_no_go == 1),
      runtime_passthrough_args: $runtime_passthrough_args,
      phase1_passthrough_args: $phase1_passthrough_args,
      phase2_passthrough_args: $phase2_passthrough_args,
      phase3_passthrough_args: $phase3_passthrough_args,
      phase4_passthrough_args: $phase4_passthrough_args,
      roadmap_passthrough_args: $roadmap_passthrough_args
    },
    steps: {
      runtime_fix_record: {
        enabled: ($run_runtime_fix_record == 1),
        status: $runtime_status,
        rc: $runtime_rc,
        command_rc: $runtime_command_rc,
        command: (if $runtime_command == "" then null else $runtime_command end),
        contract_valid: (
          if $runtime_contract_valid == "1" then true
          elif $runtime_contract_valid == "0" then false
          else null
          end
        ),
        contract_error: (if $runtime_contract_error == "" then null else $runtime_contract_error end),
        artifacts: {
          summary_json: $runtime_summary_json,
          summary_exists: ($runtime_summary_exists == "true"),
          log: $runtime_log
        }
      },
      phase1_resilience_handoff_run: {
        enabled: ($run_phase1_resilience_handoff_run == 1),
        status: $phase1_status,
        rc: $phase1_rc,
        command_rc: $phase1_command_rc,
        command: (if $phase1_command == "" then null else $phase1_command end),
        contract_valid: (
          if $phase1_contract_valid == "1" then true
          elif $phase1_contract_valid == "0" then false
          else null
          end
        ),
        contract_error: (if $phase1_contract_error == "" then null else $phase1_contract_error end),
        artifacts: {
          summary_json: $phase1_summary_json,
          summary_exists: ($phase1_summary_exists == "true"),
          log: $phase1_log
        },
        failure_semantics: {
          source_summary_json: (
            if $phase1_failure_semantics_source_summary_json == "" then null
            else $phase1_failure_semantics_source_summary_json
            end
          ),
          failure: {
            kind: (if $phase1_failure_kind == "" then null else $phase1_failure_kind end)
          },
          policy_outcome: {
            decision: (
              if $phase1_policy_outcome_decision == "" then null
              else $phase1_policy_outcome_decision
              end
            ),
            fail_closed_no_go: (
              if $phase1_policy_outcome_fail_closed_no_go == "true" then true
              elif $phase1_policy_outcome_fail_closed_no_go == "false" then false
              else null
              end
            )
          },
          signals: {
            profile_matrix_stable: {
              kind: (
                if $phase1_profile_matrix_stable_failure_kind == "" then null
                else $phase1_profile_matrix_stable_failure_kind
                end
              )
            },
            peer_loss_recovery_ok: {
              kind: (
                if $phase1_peer_loss_recovery_ok_failure_kind == "" then null
                else $phase1_peer_loss_recovery_ok_failure_kind
                end
              )
            },
            session_churn_guard_ok: {
              kind: (
                if $phase1_session_churn_guard_ok_failure_kind == "" then null
                else $phase1_session_churn_guard_ok_failure_kind
                end
              )
            }
          }
        }
      },
      phase2_linux_prod_candidate_handoff_run: {
        enabled: ($run_phase2_linux_prod_candidate_handoff_run == 1),
        status: $phase2_status,
        rc: $phase2_rc,
        command_rc: $phase2_command_rc,
        command: (if $phase2_command == "" then null else $phase2_command end),
        contract_valid: (
          if $phase2_contract_valid == "1" then true
          elif $phase2_contract_valid == "0" then false
          else null
          end
        ),
        contract_error: (if $phase2_contract_error == "" then null else $phase2_contract_error end),
        artifacts: {
          summary_json: $phase2_summary_json,
          summary_exists: ($phase2_summary_exists == "true"),
          log: $phase2_log
        }
      },
      phase3_windows_client_beta_handoff_run: {
        enabled: ($run_phase3_windows_client_beta_handoff_run == 1),
        status: $phase3_status,
        rc: $phase3_rc,
        command_rc: $phase3_command_rc,
        command: (if $phase3_command == "" then null else $phase3_command end),
        contract_valid: (
          if $phase3_contract_valid == "1" then true
          elif $phase3_contract_valid == "0" then false
          else null
          end
        ),
        contract_error: (if $phase3_contract_error == "" then null else $phase3_contract_error end),
        artifacts: {
          summary_json: $phase3_summary_json,
          summary_exists: ($phase3_summary_exists == "true"),
          log: $phase3_log
        }
      },
      phase4_windows_full_parity_handoff_run: {
        enabled: ($run_phase4_windows_full_parity_handoff_run == 1),
        status: $phase4_status,
        rc: $phase4_rc,
        command_rc: $phase4_command_rc,
        command: (if $phase4_command == "" then null else $phase4_command end),
        contract_valid: (
          if $phase4_contract_valid == "1" then true
          elif $phase4_contract_valid == "0" then false
          else null
          end
        ),
        contract_error: (if $phase4_contract_error == "" then null else $phase4_contract_error end),
        artifacts: {
          summary_json: $phase4_summary_json,
          summary_exists: ($phase4_summary_exists == "true"),
          log: $phase4_log
        }
      },
      roadmap_progress_report: {
        enabled: ($run_roadmap_progress_report == 1),
        status: $roadmap_status,
        rc: $roadmap_rc,
        command_rc: $roadmap_command_rc,
        command: (if $roadmap_command == "" then null else $roadmap_command end),
        contract_valid: (
          if $roadmap_contract_valid == "1" then true
          elif $roadmap_contract_valid == "0" then false
          else null
          end
        ),
        contract_error: (if $roadmap_contract_error == "" then null else $roadmap_contract_error end),
        artifacts: {
          summary_json: $roadmap_summary_json,
          summary_exists: ($roadmap_summary_exists == "true"),
          report_md: $roadmap_report_md,
          log: $roadmap_log
        }
      }
    },
    diagnostics: {
      phase1_resilience_handoff: {
        source_summary_json: (
          if $phase1_failure_semantics_source_summary_json == "" then null
          else $phase1_failure_semantics_source_summary_json
          end
        ),
        failure: {
          kind: (if $phase1_failure_kind == "" then null else $phase1_failure_kind end)
        },
        policy_outcome: {
          decision: (
            if $phase1_policy_outcome_decision == "" then null
            else $phase1_policy_outcome_decision
            end
          ),
          fail_closed_no_go: (
            if $phase1_policy_outcome_fail_closed_no_go == "true" then true
            elif $phase1_policy_outcome_fail_closed_no_go == "false" then false
            else null
            end
          )
        },
        failure_semantics: {
          profile_matrix_stable: {
            kind: (
              if $phase1_profile_matrix_stable_failure_kind == "" then null
              else $phase1_profile_matrix_stable_failure_kind
              end
            )
          },
          peer_loss_recovery_ok: {
            kind: (
              if $phase1_peer_loss_recovery_ok_failure_kind == "" then null
              else $phase1_peer_loss_recovery_ok_failure_kind
              end
            )
          },
          session_churn_guard_ok: {
            kind: (
              if $phase1_session_churn_guard_ok_failure_kind == "" then null
              else $phase1_session_churn_guard_ok_failure_kind
              end
            )
          }
        }
      }
    },
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
    runtime_fix_record_summary_json: $runtime_summary_json,
    phase1_resilience_handoff_run_summary_json: $phase1_summary_json,
    phase2_linux_prod_candidate_handoff_run_summary_json: $phase2_summary_json,
    phase3_windows_client_beta_handoff_run_summary_json: $phase3_summary_json,
    phase4_windows_full_parity_handoff_run_summary_json: $phase4_summary_json,
    vpn_rc_resilience_summary_json: $roadmap_vpn_rc_resilience_summary_json,
    roadmap_progress_summary_json: $roadmap_summary_json,
    roadmap_progress_report_md: $roadmap_report_md
  }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

echo "[vpn-non-blockchain-fastlane] status=$final_status rc=$final_rc dry_run=$dry_run parallel=$parallel mode=$execution_mode"
echo "[vpn-non-blockchain-fastlane] reports_dir=$reports_dir"
echo "[vpn-non-blockchain-fastlane] summary_json=$summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
