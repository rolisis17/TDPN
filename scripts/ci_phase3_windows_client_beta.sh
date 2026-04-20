#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/ci_phase3_windows_client_beta.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]] \
    [--dry-run [0|1]] \
    [--run-desktop-scaffold-contract [0|1]] \
    [--run-windows-desktop-native-bootstrap-guardrails [0|1]] \
    [--run-windows-desktop-shell-guardrails [0|1]] \
    [--run-local-control-api-contract [0|1]] \
    [--run-local-api-config-defaults [0|1]] \
    [--run-easy-node-config-v1 [0|1]] \
    [--run-easy-mode-launcher-wiring [0|1]] \
    [--run-easy-mode-launcher-runtime [0|1]] \
    [--run-phase3-windows-client-beta-check [0|1]] \
    [--run-phase3-windows-client-beta-run [0|1]] \
    [--run-phase3-windows-client-beta-handoff-check [0|1]] \
    [--run-phase3-windows-client-beta-handoff-run [0|1]]

Purpose:
  Run a focused Phase-3 Windows client-beta CI gate around desktop/client
  contract checks:
    1) integration_desktop_scaffold_contract.sh
    2) integration_windows_desktop_native_bootstrap_guardrails.sh
    3) integration_windows_desktop_shell_guardrails.sh
    4) integration_local_control_api_contract.sh
    5) integration_local_api_config_defaults.sh
    6) integration_easy_node_config_v1.sh
    7) integration_easy_mode_launcher_wiring.sh
    8) integration_easy_mode_launcher_runtime.sh
    9) integration_phase3_windows_client_beta_check.sh
   10) integration_phase3_windows_client_beta_run.sh
   11) integration_phase3_windows_client_beta_handoff_check.sh
   12) integration_phase3_windows_client_beta_handoff_run.sh

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
  echo "[ci-phase3-windows-client-beta] step=${label} status=running"
  set +e
  "$@"
  rc=$?
  set -e
  if (( rc == 0 )); then
    echo "[ci-phase3-windows-client-beta] step=${label} status=pass rc=0"
  else
    echo "[ci-phase3-windows-client-beta] step=${label} status=fail rc=${rc}"
  fi
  return "$rc"
}

need_cmd jq
need_cmd date
need_cmd mktemp

reports_dir="${CI_PHASE3_WINDOWS_CLIENT_BETA_REPORTS_DIR:-}"
summary_json="${CI_PHASE3_WINDOWS_CLIENT_BETA_SUMMARY_JSON:-}"
print_summary_json="${CI_PHASE3_WINDOWS_CLIENT_BETA_PRINT_SUMMARY_JSON:-1}"
dry_run="${CI_PHASE3_WINDOWS_CLIENT_BETA_DRY_RUN:-0}"

run_desktop_scaffold_contract="${CI_PHASE3_WINDOWS_CLIENT_BETA_RUN_DESKTOP_SCAFFOLD_CONTRACT:-1}"
run_windows_desktop_native_bootstrap_guardrails="${CI_PHASE3_WINDOWS_CLIENT_BETA_RUN_WINDOWS_DESKTOP_NATIVE_BOOTSTRAP_GUARDRAILS:-1}"
run_windows_desktop_shell_guardrails="${CI_PHASE3_WINDOWS_CLIENT_BETA_RUN_WINDOWS_DESKTOP_SHELL_GUARDRAILS:-1}"
run_local_control_api_contract="${CI_PHASE3_WINDOWS_CLIENT_BETA_RUN_LOCAL_CONTROL_API_CONTRACT:-1}"
run_local_api_config_defaults="${CI_PHASE3_WINDOWS_CLIENT_BETA_RUN_LOCAL_API_CONFIG_DEFAULTS:-1}"
run_easy_node_config_v1="${CI_PHASE3_WINDOWS_CLIENT_BETA_RUN_EASY_NODE_CONFIG_V1:-1}"
run_easy_mode_launcher_wiring="${CI_PHASE3_WINDOWS_CLIENT_BETA_RUN_EASY_MODE_LAUNCHER_WIRING:-1}"
run_easy_mode_launcher_runtime="${CI_PHASE3_WINDOWS_CLIENT_BETA_RUN_EASY_MODE_LAUNCHER_RUNTIME:-1}"
run_phase3_windows_client_beta_check="${CI_PHASE3_WINDOWS_CLIENT_BETA_RUN_PHASE3_WINDOWS_CLIENT_BETA_CHECK:-1}"
run_phase3_windows_client_beta_run="${CI_PHASE3_WINDOWS_CLIENT_BETA_RUN_PHASE3_WINDOWS_CLIENT_BETA_RUN:-1}"
run_phase3_windows_client_beta_handoff_check="${CI_PHASE3_WINDOWS_CLIENT_BETA_RUN_PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_CHECK:-1}"
run_phase3_windows_client_beta_handoff_run="${CI_PHASE3_WINDOWS_CLIENT_BETA_RUN_PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_RUN:-1}"

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
    --run-desktop-scaffold-contract)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_desktop_scaffold_contract="${2:-}"
        shift 2
      else
        run_desktop_scaffold_contract="1"
        shift
      fi
      ;;
    --run-windows-desktop-native-bootstrap-guardrails)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_windows_desktop_native_bootstrap_guardrails="${2:-}"
        shift 2
      else
        run_windows_desktop_native_bootstrap_guardrails="1"
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
    --run-local-control-api-contract)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_local_control_api_contract="${2:-}"
        shift 2
      else
        run_local_control_api_contract="1"
        shift
      fi
      ;;
    --run-local-api-config-defaults)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_local_api_config_defaults="${2:-}"
        shift 2
      else
        run_local_api_config_defaults="1"
        shift
      fi
      ;;
    --run-easy-node-config-v1)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_easy_node_config_v1="${2:-}"
        shift 2
      else
        run_easy_node_config_v1="1"
        shift
      fi
      ;;
    --run-easy-mode-launcher-wiring)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_easy_mode_launcher_wiring="${2:-}"
        shift 2
      else
        run_easy_mode_launcher_wiring="1"
        shift
      fi
      ;;
    --run-easy-mode-launcher-runtime)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_easy_mode_launcher_runtime="${2:-}"
        shift 2
      else
        run_easy_mode_launcher_runtime="1"
        shift
      fi
      ;;
    --run-phase3-windows-client-beta-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase3_windows_client_beta_check="${2:-}"
        shift 2
      else
        run_phase3_windows_client_beta_check="1"
        shift
      fi
      ;;
    --run-phase3-windows-client-beta-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase3_windows_client_beta_run="${2:-}"
        shift 2
      else
        run_phase3_windows_client_beta_run="1"
        shift
      fi
      ;;
    --run-phase3-windows-client-beta-handoff-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase3_windows_client_beta_handoff_check="${2:-}"
        shift 2
      else
        run_phase3_windows_client_beta_handoff_check="1"
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
bool_arg_or_die "--run-desktop-scaffold-contract" "$run_desktop_scaffold_contract"
bool_arg_or_die "--run-windows-desktop-native-bootstrap-guardrails" "$run_windows_desktop_native_bootstrap_guardrails"
bool_arg_or_die "--run-windows-desktop-shell-guardrails" "$run_windows_desktop_shell_guardrails"
bool_arg_or_die "--run-local-control-api-contract" "$run_local_control_api_contract"
bool_arg_or_die "--run-local-api-config-defaults" "$run_local_api_config_defaults"
bool_arg_or_die "--run-easy-node-config-v1" "$run_easy_node_config_v1"
bool_arg_or_die "--run-easy-mode-launcher-wiring" "$run_easy_mode_launcher_wiring"
bool_arg_or_die "--run-easy-mode-launcher-runtime" "$run_easy_mode_launcher_runtime"
bool_arg_or_die "--run-phase3-windows-client-beta-check" "$run_phase3_windows_client_beta_check"
bool_arg_or_die "--run-phase3-windows-client-beta-run" "$run_phase3_windows_client_beta_run"
bool_arg_or_die "--run-phase3-windows-client-beta-handoff-check" "$run_phase3_windows_client_beta_handoff_check"
bool_arg_or_die "--run-phase3-windows-client-beta-handoff-run" "$run_phase3_windows_client_beta_handoff_run"

desktop_scaffold_contract_script="${CI_PHASE3_WINDOWS_CLIENT_BETA_DESKTOP_SCAFFOLD_CONTRACT_SCRIPT:-$ROOT_DIR/scripts/integration_desktop_scaffold_contract.sh}"
windows_desktop_native_bootstrap_guardrails_script="${CI_PHASE3_WINDOWS_CLIENT_BETA_WINDOWS_DESKTOP_NATIVE_BOOTSTRAP_GUARDRAILS_SCRIPT:-$ROOT_DIR/scripts/integration_windows_desktop_native_bootstrap_guardrails.sh}"
windows_desktop_shell_guardrails_script="${CI_PHASE3_WINDOWS_CLIENT_BETA_WINDOWS_DESKTOP_SHELL_GUARDRAILS_SCRIPT:-$ROOT_DIR/scripts/integration_windows_desktop_shell_guardrails.sh}"
local_control_api_contract_script="${CI_PHASE3_WINDOWS_CLIENT_BETA_LOCAL_CONTROL_API_CONTRACT_SCRIPT:-$ROOT_DIR/scripts/integration_local_control_api_contract.sh}"
local_api_config_defaults_script="${CI_PHASE3_WINDOWS_CLIENT_BETA_LOCAL_API_CONFIG_DEFAULTS_SCRIPT:-$ROOT_DIR/scripts/integration_local_api_config_defaults.sh}"
easy_node_config_v1_script="${CI_PHASE3_WINDOWS_CLIENT_BETA_EASY_NODE_CONFIG_V1_SCRIPT:-$ROOT_DIR/scripts/integration_easy_node_config_v1.sh}"
easy_mode_launcher_wiring_script="${CI_PHASE3_WINDOWS_CLIENT_BETA_EASY_MODE_LAUNCHER_WIRING_SCRIPT:-$ROOT_DIR/scripts/integration_easy_mode_launcher_wiring.sh}"
easy_mode_launcher_runtime_script="${CI_PHASE3_WINDOWS_CLIENT_BETA_EASY_MODE_LAUNCHER_RUNTIME_SCRIPT:-$ROOT_DIR/scripts/integration_easy_mode_launcher_runtime.sh}"
phase3_windows_client_beta_check_script="${CI_PHASE3_WINDOWS_CLIENT_BETA_PHASE3_WINDOWS_CLIENT_BETA_CHECK_SCRIPT:-$ROOT_DIR/scripts/integration_phase3_windows_client_beta_check.sh}"
phase3_windows_client_beta_run_script="${CI_PHASE3_WINDOWS_CLIENT_BETA_PHASE3_WINDOWS_CLIENT_BETA_RUN_SCRIPT:-$ROOT_DIR/scripts/integration_phase3_windows_client_beta_run.sh}"
phase3_windows_client_beta_handoff_check_script="${CI_PHASE3_WINDOWS_CLIENT_BETA_PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_CHECK_SCRIPT:-$ROOT_DIR/scripts/integration_phase3_windows_client_beta_handoff_check.sh}"
phase3_windows_client_beta_handoff_run_script="${CI_PHASE3_WINDOWS_CLIENT_BETA_PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_RUN_SCRIPT:-$ROOT_DIR/scripts/integration_phase3_windows_client_beta_handoff_run.sh}"

stage_ids=(
  "desktop_scaffold_contract"
  "windows_desktop_native_bootstrap_guardrails"
  "windows_desktop_shell_guardrails"
  "local_control_api_contract"
  "local_api_config_defaults"
  "easy_node_config_v1"
  "easy_mode_launcher_wiring"
  "easy_mode_launcher_runtime"
  "phase3_windows_client_beta_check"
  "phase3_windows_client_beta_run"
  "phase3_windows_client_beta_handoff_check"
  "phase3_windows_client_beta_handoff_run"
)

declare -A stage_script=(
  ["desktop_scaffold_contract"]="$desktop_scaffold_contract_script"
  ["windows_desktop_native_bootstrap_guardrails"]="$windows_desktop_native_bootstrap_guardrails_script"
  ["windows_desktop_shell_guardrails"]="$windows_desktop_shell_guardrails_script"
  ["local_control_api_contract"]="$local_control_api_contract_script"
  ["local_api_config_defaults"]="$local_api_config_defaults_script"
  ["easy_node_config_v1"]="$easy_node_config_v1_script"
  ["easy_mode_launcher_wiring"]="$easy_mode_launcher_wiring_script"
  ["easy_mode_launcher_runtime"]="$easy_mode_launcher_runtime_script"
  ["phase3_windows_client_beta_check"]="$phase3_windows_client_beta_check_script"
  ["phase3_windows_client_beta_run"]="$phase3_windows_client_beta_run_script"
  ["phase3_windows_client_beta_handoff_check"]="$phase3_windows_client_beta_handoff_check_script"
  ["phase3_windows_client_beta_handoff_run"]="$phase3_windows_client_beta_handoff_run_script"
)

declare -A stage_enabled=(
  ["desktop_scaffold_contract"]="$run_desktop_scaffold_contract"
  ["windows_desktop_native_bootstrap_guardrails"]="$run_windows_desktop_native_bootstrap_guardrails"
  ["windows_desktop_shell_guardrails"]="$run_windows_desktop_shell_guardrails"
  ["local_control_api_contract"]="$run_local_control_api_contract"
  ["local_api_config_defaults"]="$run_local_api_config_defaults"
  ["easy_node_config_v1"]="$run_easy_node_config_v1"
  ["easy_mode_launcher_wiring"]="$run_easy_mode_launcher_wiring"
  ["easy_mode_launcher_runtime"]="$run_easy_mode_launcher_runtime"
  ["phase3_windows_client_beta_check"]="$run_phase3_windows_client_beta_check"
  ["phase3_windows_client_beta_run"]="$run_phase3_windows_client_beta_run"
  ["phase3_windows_client_beta_handoff_check"]="$run_phase3_windows_client_beta_handoff_check"
  ["phase3_windows_client_beta_handoff_run"]="$run_phase3_windows_client_beta_handoff_run"
)

for stage_id in "${stage_ids[@]}"; do
  if [[ "${stage_enabled[$stage_id]}" == "1" && ! -x "${stage_script[$stage_id]}" ]]; then
    echo "missing executable stage script: ${stage_script[$stage_id]}"
    exit 2
  fi
done

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/ci_phase3_windows_client_beta_${run_stamp}"
else
  reports_dir="$(abs_path "$reports_dir")"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/ci_phase3_windows_client_beta_summary.json"
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
      echo "[ci-phase3-windows-client-beta] step=${stage_id} status=skip reason=dry-run"
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
    echo "[ci-phase3-windows-client-beta] step=${stage_id} status=skip reason=disabled"
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
  --arg run_desktop_scaffold_contract "$run_desktop_scaffold_contract" \
  --arg run_windows_desktop_native_bootstrap_guardrails "$run_windows_desktop_native_bootstrap_guardrails" \
  --arg run_windows_desktop_shell_guardrails "$run_windows_desktop_shell_guardrails" \
  --arg run_local_control_api_contract "$run_local_control_api_contract" \
  --arg run_local_api_config_defaults "$run_local_api_config_defaults" \
  --arg run_easy_node_config_v1 "$run_easy_node_config_v1" \
  --arg run_easy_mode_launcher_wiring "$run_easy_mode_launcher_wiring" \
  --arg run_easy_mode_launcher_runtime "$run_easy_mode_launcher_runtime" \
  --arg run_phase3_windows_client_beta_check "$run_phase3_windows_client_beta_check" \
  --arg run_phase3_windows_client_beta_run "$run_phase3_windows_client_beta_run" \
  --arg run_phase3_windows_client_beta_handoff_check "$run_phase3_windows_client_beta_handoff_check" \
  --arg run_phase3_windows_client_beta_handoff_run "$run_phase3_windows_client_beta_handoff_run" \
  --argjson steps "$steps_json" \
  '{
    version: 1,
    schema: {
      id: "ci_phase3_windows_client_beta_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    inputs: {
      dry_run: ($dry_run == "1"),
      print_summary_json: ($print_summary_json == "1"),
      run_desktop_scaffold_contract: ($run_desktop_scaffold_contract == "1"),
      run_windows_desktop_native_bootstrap_guardrails: ($run_windows_desktop_native_bootstrap_guardrails == "1"),
      run_windows_desktop_shell_guardrails: ($run_windows_desktop_shell_guardrails == "1"),
      run_local_control_api_contract: ($run_local_control_api_contract == "1"),
      run_local_api_config_defaults: ($run_local_api_config_defaults == "1"),
      run_easy_node_config_v1: ($run_easy_node_config_v1 == "1"),
      run_easy_mode_launcher_wiring: ($run_easy_mode_launcher_wiring == "1"),
      run_easy_mode_launcher_runtime: ($run_easy_mode_launcher_runtime == "1"),
      run_phase3_windows_client_beta_check: ($run_phase3_windows_client_beta_check == "1"),
      run_phase3_windows_client_beta_run: ($run_phase3_windows_client_beta_run == "1"),
      run_phase3_windows_client_beta_handoff_check: ($run_phase3_windows_client_beta_handoff_check == "1"),
      run_phase3_windows_client_beta_handoff_run: ($run_phase3_windows_client_beta_handoff_run == "1")
    },
    steps: $steps,
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

echo "[ci-phase3-windows-client-beta] status=$final_status rc=$final_rc dry_run=$dry_run"
echo "[ci-phase3-windows-client-beta] reports_dir=$reports_dir"
echo "[ci-phase3-windows-client-beta] summary_json=$summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
