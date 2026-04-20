#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/ci_phase4_windows_full_parity.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]] \
    [--dry-run [0|1]] \
    [--run-windows-server-packaging [0|1]] \
    [--run-windows-native-bootstrap-guardrails [0|1]] \
    [--run-windows-desktop-shell-guardrails [0|1]] \
    [--run-windows-local-api-session-guardrails [0|1]] \
    [--run-windows-role-runbooks [0|1]] \
    [--run-cross-platform-interop [0|1]] \
    [--run-role-combination-validation [0|1]] \
    [--run-phase4-windows-full-parity-check [0|1]] \
    [--run-phase4-windows-full-parity-run [0|1]] \
    [--run-phase4-windows-full-parity-handoff-check [0|1]] \
    [--run-phase4-windows-full-parity-handoff-run [0|1]]

Purpose:
  Run a focused Phase-4 Windows full-parity CI gate around server/federation/
  multi-machine readiness and full-parity wrappers:
    1) integration_easy_node_server_preflight.sh
    2) integration_windows_desktop_native_bootstrap_guardrails.sh
    3) integration_windows_desktop_shell_guardrails.sh
    4) integration_windows_local_api_session_guardrails.sh
    5) integration_prod_operator_lifecycle_runbook.sh
    6) integration_three_machine_prod_signoff.sh
    7) integration_machine_b_federation_check.sh
    8) integration_phase4_windows_full_parity_check.sh
    9) integration_phase4_windows_full_parity_run.sh
   10) integration_phase4_windows_full_parity_handoff_check.sh
   11) integration_phase4_windows_full_parity_handoff_run.sh

Dry-run mode:
  --dry-run 1 skips stage execution, records deterministic skip accounting,
  and still emits the runner summary JSON.
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

run_step() {
  local label="$1"
  shift
  local rc=0
  echo "[ci-phase4-windows-full-parity] step=${label} status=running"
  set +e
  "$@"
  rc=$?
  set -e
  if (( rc == 0 )); then
    echo "[ci-phase4-windows-full-parity] step=${label} status=pass rc=0"
  else
    echo "[ci-phase4-windows-full-parity] step=${label} status=fail rc=${rc}"
  fi
  return "$rc"
}

need_cmd jq
need_cmd date
need_cmd mktemp

reports_dir="${CI_PHASE4_WINDOWS_FULL_PARITY_REPORTS_DIR:-}"
summary_json="${CI_PHASE4_WINDOWS_FULL_PARITY_SUMMARY_JSON:-}"
print_summary_json="${CI_PHASE4_WINDOWS_FULL_PARITY_PRINT_SUMMARY_JSON:-1}"
dry_run="${CI_PHASE4_WINDOWS_FULL_PARITY_DRY_RUN:-0}"

run_windows_server_packaging="${CI_PHASE4_WINDOWS_FULL_PARITY_RUN_WINDOWS_SERVER_PACKAGING:-1}"
run_windows_native_bootstrap_guardrails="${CI_PHASE4_WINDOWS_FULL_PARITY_RUN_WINDOWS_NATIVE_BOOTSTRAP_GUARDRAILS:-1}"
run_windows_desktop_shell_guardrails="${CI_PHASE4_WINDOWS_FULL_PARITY_RUN_WINDOWS_DESKTOP_SHELL_GUARDRAILS:-1}"
run_windows_local_api_session_guardrails="${CI_PHASE4_WINDOWS_FULL_PARITY_RUN_WINDOWS_LOCAL_API_SESSION_GUARDRAILS:-1}"
run_windows_role_runbooks="${CI_PHASE4_WINDOWS_FULL_PARITY_RUN_WINDOWS_ROLE_RUNBOOKS:-1}"
run_cross_platform_interop="${CI_PHASE4_WINDOWS_FULL_PARITY_RUN_CROSS_PLATFORM_INTEROP:-1}"
run_role_combination_validation="${CI_PHASE4_WINDOWS_FULL_PARITY_RUN_ROLE_COMBINATION_VALIDATION:-1}"
run_phase4_windows_full_parity_check="${CI_PHASE4_WINDOWS_FULL_PARITY_RUN_PHASE4_WINDOWS_FULL_PARITY_CHECK:-1}"
run_phase4_windows_full_parity_run="${CI_PHASE4_WINDOWS_FULL_PARITY_RUN_PHASE4_WINDOWS_FULL_PARITY_RUN:-1}"
run_phase4_windows_full_parity_handoff_check="${CI_PHASE4_WINDOWS_FULL_PARITY_RUN_PHASE4_WINDOWS_FULL_PARITY_HANDOFF_CHECK:-1}"
run_phase4_windows_full_parity_handoff_run="${CI_PHASE4_WINDOWS_FULL_PARITY_RUN_PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN:-1}"

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
    --dry-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        dry_run="${2:-}"
        shift 2
      else
        dry_run="1"
        shift
      fi
      ;;
    --run-windows-server-packaging)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_windows_server_packaging="${2:-}"
        shift 2
      else
        run_windows_server_packaging="1"
        shift
      fi
      ;;
    --run-windows-native-bootstrap-guardrails)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_windows_native_bootstrap_guardrails="${2:-}"
        shift 2
      else
        run_windows_native_bootstrap_guardrails="1"
        shift
      fi
      ;;
    --run-windows-desktop-shell-guardrails)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_windows_desktop_shell_guardrails="${2:-}"
        shift 2
      else
        run_windows_desktop_shell_guardrails="1"
        shift
      fi
      ;;
    --run-windows-local-api-session-guardrails)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_windows_local_api_session_guardrails="${2:-}"
        shift 2
      else
        run_windows_local_api_session_guardrails="1"
        shift
      fi
      ;;
    --run-windows-role-runbooks)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_windows_role_runbooks="${2:-}"
        shift 2
      else
        run_windows_role_runbooks="1"
        shift
      fi
      ;;
    --run-cross-platform-interop)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_cross_platform_interop="${2:-}"
        shift 2
      else
        run_cross_platform_interop="1"
        shift
      fi
      ;;
    --run-role-combination-validation)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_role_combination_validation="${2:-}"
        shift 2
      else
        run_role_combination_validation="1"
        shift
      fi
      ;;
    --run-phase4-windows-full-parity-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase4_windows_full_parity_check="${2:-}"
        shift 2
      else
        run_phase4_windows_full_parity_check="1"
        shift
      fi
      ;;
    --run-phase4-windows-full-parity-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase4_windows_full_parity_run="${2:-}"
        shift 2
      else
        run_phase4_windows_full_parity_run="1"
        shift
      fi
      ;;
    --run-phase4-windows-full-parity-handoff-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase4_windows_full_parity_handoff_check="${2:-}"
        shift 2
      else
        run_phase4_windows_full_parity_handoff_check="1"
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
bool_arg_or_die "--dry-run" "$dry_run"
bool_arg_or_die "--run-windows-server-packaging" "$run_windows_server_packaging"
bool_arg_or_die "--run-windows-native-bootstrap-guardrails" "$run_windows_native_bootstrap_guardrails"
bool_arg_or_die "--run-windows-desktop-shell-guardrails" "$run_windows_desktop_shell_guardrails"
bool_arg_or_die "--run-windows-local-api-session-guardrails" "$run_windows_local_api_session_guardrails"
bool_arg_or_die "--run-windows-role-runbooks" "$run_windows_role_runbooks"
bool_arg_or_die "--run-cross-platform-interop" "$run_cross_platform_interop"
bool_arg_or_die "--run-role-combination-validation" "$run_role_combination_validation"
bool_arg_or_die "--run-phase4-windows-full-parity-check" "$run_phase4_windows_full_parity_check"
bool_arg_or_die "--run-phase4-windows-full-parity-run" "$run_phase4_windows_full_parity_run"
bool_arg_or_die "--run-phase4-windows-full-parity-handoff-check" "$run_phase4_windows_full_parity_handoff_check"
bool_arg_or_die "--run-phase4-windows-full-parity-handoff-run" "$run_phase4_windows_full_parity_handoff_run"

windows_server_packaging_script="${CI_PHASE4_WINDOWS_FULL_PARITY_WINDOWS_SERVER_PACKAGING_SCRIPT:-$ROOT_DIR/scripts/integration_easy_node_server_preflight.sh}"
windows_native_bootstrap_guardrails_script="${CI_PHASE4_WINDOWS_FULL_PARITY_WINDOWS_NATIVE_BOOTSTRAP_GUARDRAILS_SCRIPT:-$ROOT_DIR/scripts/integration_windows_desktop_native_bootstrap_guardrails.sh}"
windows_desktop_shell_guardrails_script="${CI_PHASE4_WINDOWS_FULL_PARITY_WINDOWS_DESKTOP_SHELL_GUARDRAILS_SCRIPT:-$ROOT_DIR/scripts/integration_windows_desktop_shell_guardrails.sh}"
windows_local_api_session_guardrails_script="${CI_PHASE4_WINDOWS_FULL_PARITY_WINDOWS_LOCAL_API_SESSION_GUARDRAILS_SCRIPT:-$ROOT_DIR/scripts/integration_windows_local_api_session_guardrails.sh}"
windows_role_runbooks_script="${CI_PHASE4_WINDOWS_FULL_PARITY_WINDOWS_ROLE_RUNBOOKS_SCRIPT:-$ROOT_DIR/scripts/integration_prod_operator_lifecycle_runbook.sh}"
cross_platform_interop_script="${CI_PHASE4_WINDOWS_FULL_PARITY_CROSS_PLATFORM_INTEROP_SCRIPT:-$ROOT_DIR/scripts/integration_three_machine_prod_signoff.sh}"
role_combination_validation_script="${CI_PHASE4_WINDOWS_FULL_PARITY_ROLE_COMBINATION_VALIDATION_SCRIPT:-$ROOT_DIR/scripts/integration_machine_b_federation_check.sh}"
phase4_windows_full_parity_check_script="${CI_PHASE4_WINDOWS_FULL_PARITY_PHASE4_WINDOWS_FULL_PARITY_CHECK_SCRIPT:-$ROOT_DIR/scripts/integration_phase4_windows_full_parity_check.sh}"
phase4_windows_full_parity_run_script="${CI_PHASE4_WINDOWS_FULL_PARITY_PHASE4_WINDOWS_FULL_PARITY_RUN_SCRIPT:-$ROOT_DIR/scripts/integration_phase4_windows_full_parity_run.sh}"
phase4_windows_full_parity_handoff_check_script="${CI_PHASE4_WINDOWS_FULL_PARITY_PHASE4_WINDOWS_FULL_PARITY_HANDOFF_CHECK_SCRIPT:-$ROOT_DIR/scripts/integration_phase4_windows_full_parity_handoff_check.sh}"
phase4_windows_full_parity_handoff_run_script="${CI_PHASE4_WINDOWS_FULL_PARITY_PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_SCRIPT:-$ROOT_DIR/scripts/integration_phase4_windows_full_parity_handoff_run.sh}"

stage_ids=(
  "windows_server_packaging"
  "windows_native_bootstrap_guardrails"
  "windows_desktop_shell_guardrails"
  "windows_local_api_session_guardrails"
  "windows_role_runbooks"
  "cross_platform_interop"
  "role_combination_validation"
  "phase4_windows_full_parity_check"
  "phase4_windows_full_parity_run"
  "phase4_windows_full_parity_handoff_check"
  "phase4_windows_full_parity_handoff_run"
)

declare -A stage_script=(
  ["windows_server_packaging"]="$windows_server_packaging_script"
  ["windows_native_bootstrap_guardrails"]="$windows_native_bootstrap_guardrails_script"
  ["windows_desktop_shell_guardrails"]="$windows_desktop_shell_guardrails_script"
  ["windows_local_api_session_guardrails"]="$windows_local_api_session_guardrails_script"
  ["windows_role_runbooks"]="$windows_role_runbooks_script"
  ["cross_platform_interop"]="$cross_platform_interop_script"
  ["role_combination_validation"]="$role_combination_validation_script"
  ["phase4_windows_full_parity_check"]="$phase4_windows_full_parity_check_script"
  ["phase4_windows_full_parity_run"]="$phase4_windows_full_parity_run_script"
  ["phase4_windows_full_parity_handoff_check"]="$phase4_windows_full_parity_handoff_check_script"
  ["phase4_windows_full_parity_handoff_run"]="$phase4_windows_full_parity_handoff_run_script"
)

declare -A stage_enabled=(
  ["windows_server_packaging"]="$run_windows_server_packaging"
  ["windows_native_bootstrap_guardrails"]="$run_windows_native_bootstrap_guardrails"
  ["windows_desktop_shell_guardrails"]="$run_windows_desktop_shell_guardrails"
  ["windows_local_api_session_guardrails"]="$run_windows_local_api_session_guardrails"
  ["windows_role_runbooks"]="$run_windows_role_runbooks"
  ["cross_platform_interop"]="$run_cross_platform_interop"
  ["role_combination_validation"]="$run_role_combination_validation"
  ["phase4_windows_full_parity_check"]="$run_phase4_windows_full_parity_check"
  ["phase4_windows_full_parity_run"]="$run_phase4_windows_full_parity_run"
  ["phase4_windows_full_parity_handoff_check"]="$run_phase4_windows_full_parity_handoff_check"
  ["phase4_windows_full_parity_handoff_run"]="$run_phase4_windows_full_parity_handoff_run"
)

for stage_id in "${stage_ids[@]}"; do
  if [[ "${stage_enabled[$stage_id]}" == "1" && ! -x "${stage_script[$stage_id]}" ]]; then
    echo "missing executable stage script: ${stage_script[$stage_id]}"
    exit 2
  fi
done

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/ci_phase4_windows_full_parity_${run_stamp}"
else
  reports_dir="$(abs_path "$reports_dir")"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/ci_phase4_windows_full_parity_summary.json"
else
  summary_json="$(abs_path "$summary_json")"
fi

mkdir -p "$reports_dir"
mkdir -p "$(dirname "$summary_json")"

declare -A stage_status
declare -A stage_rc
declare -A stage_command
declare -A stage_reason

final_rc=0

for stage_id in "${stage_ids[@]}"; do
  script="${stage_script[$stage_id]}"
  enabled="${stage_enabled[$stage_id]}"

  stage_status["$stage_id"]="skip"
  stage_rc["$stage_id"]=0
  stage_command["$stage_id"]=""
  stage_reason["$stage_id"]=""

  if [[ "$enabled" == "1" ]]; then
    stage_command["$stage_id"]="$(print_cmd "$script")"
    if [[ "$dry_run" == "1" ]]; then
      stage_reason["$stage_id"]="dry-run"
      echo "[ci-phase4-windows-full-parity] step=${stage_id} status=skip reason=dry-run"
    elif run_step "$stage_id" "$script"; then
      stage_status["$stage_id"]="pass"
      stage_rc["$stage_id"]=0
    else
      step_rc=$?
      stage_status["$stage_id"]="fail"
      stage_rc["$stage_id"]=$step_rc
      if (( final_rc == 0 )); then
        final_rc=$step_rc
      fi
    fi
  else
    echo "[ci-phase4-windows-full-parity] step=${stage_id} status=skip reason=disabled"
    stage_reason["$stage_id"]="disabled"
  fi
done

final_status="pass"
if (( final_rc != 0 )); then
  final_status="fail"
fi

steps_json='{}'
for stage_id in "${stage_ids[@]}"; do
  stage_entry="$(
    jq -n \
      --arg enabled "${stage_enabled[$stage_id]}" \
      --arg status "${stage_status[$stage_id]}" \
      --argjson rc "${stage_rc[$stage_id]}" \
      --arg command "${stage_command[$stage_id]}" \
      --arg reason "${stage_reason[$stage_id]}" \
      '{
        enabled: ($enabled == "1"),
        status: $status,
        rc: $rc,
        command: (if $command == "" then null else $command end),
        reason: (if $reason == "" then null else $reason end),
        artifacts: {}
      }'
  )"
  steps_json="$(
    jq -n \
      --argjson base "$steps_json" \
      --arg key "$stage_id" \
      --argjson val "$stage_entry" \
      '$base + {($key): $val}'
  )"
done

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg dry_run "$dry_run" \
  --arg print_summary_json "$print_summary_json" \
  --arg run_windows_server_packaging "$run_windows_server_packaging" \
  --arg run_windows_native_bootstrap_guardrails "$run_windows_native_bootstrap_guardrails" \
  --arg run_windows_desktop_shell_guardrails "$run_windows_desktop_shell_guardrails" \
  --arg run_windows_local_api_session_guardrails "$run_windows_local_api_session_guardrails" \
  --arg run_windows_role_runbooks "$run_windows_role_runbooks" \
  --arg run_cross_platform_interop "$run_cross_platform_interop" \
  --arg run_role_combination_validation "$run_role_combination_validation" \
  --arg run_phase4_windows_full_parity_check "$run_phase4_windows_full_parity_check" \
  --arg run_phase4_windows_full_parity_run "$run_phase4_windows_full_parity_run" \
  --arg run_phase4_windows_full_parity_handoff_check "$run_phase4_windows_full_parity_handoff_check" \
  --arg run_phase4_windows_full_parity_handoff_run "$run_phase4_windows_full_parity_handoff_run" \
  --argjson steps "$steps_json" \
  '{
    version: 1,
    schema: {
      id: "ci_phase4_windows_full_parity_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    inputs: {
      dry_run: ($dry_run == "1"),
      print_summary_json: ($print_summary_json == "1"),
      run_windows_server_packaging: ($run_windows_server_packaging == "1"),
      run_windows_native_bootstrap_guardrails: ($run_windows_native_bootstrap_guardrails == "1"),
      run_windows_desktop_shell_guardrails: ($run_windows_desktop_shell_guardrails == "1"),
      run_windows_local_api_session_guardrails: ($run_windows_local_api_session_guardrails == "1"),
      run_windows_role_runbooks: ($run_windows_role_runbooks == "1"),
      run_cross_platform_interop: ($run_cross_platform_interop == "1"),
      run_role_combination_validation: ($run_role_combination_validation == "1"),
      run_phase4_windows_full_parity_check: ($run_phase4_windows_full_parity_check == "1"),
      run_phase4_windows_full_parity_run: ($run_phase4_windows_full_parity_run == "1"),
      run_phase4_windows_full_parity_handoff_check: ($run_phase4_windows_full_parity_handoff_check == "1"),
      run_phase4_windows_full_parity_handoff_run: ($run_phase4_windows_full_parity_handoff_run == "1")
    },
    steps: $steps,
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

echo "[ci-phase4-windows-full-parity] status=$final_status rc=$final_rc dry_run=$dry_run"
echo "[ci-phase4-windows-full-parity] reports_dir=$reports_dir"
echo "[ci-phase4-windows-full-parity] summary_json=$summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
