#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/ci_phase0.sh [--dry-run [0|1]] [--summary-json PATH] [--print-summary-json [0|1]]

Purpose:
  Run a fast Phase-0 product-surface gate:
    1) easy-mode launcher wiring contract
    2) easy-mode launcher runtime contract
    3) easy-mode simple prompt budget contract
    4) config-v1 contract
    5) local control API contract

Notes:
  - fail-fast by default
  - --dry-run 1 prints commands without executing
  - always emits a machine-readable summary artifact (including dry-run)
  - --print-summary-json 1 prints summary JSON payload to stdout at the end
  - default summary artifact:
      .easy-node-logs/ci_phase0_summary.json
  - each step path can be overridden by env vars:
      CI_PHASE0_LAUNCHER_WIRING_SCRIPT
      CI_PHASE0_LAUNCHER_RUNTIME_SCRIPT
      CI_PHASE0_PROMPT_BUDGET_SCRIPT
      CI_PHASE0_CONFIG_V1_SCRIPT
      CI_PHASE0_LOCAL_CONTROL_API_SCRIPT
      CI_PHASE0_SUMMARY_JSON
USAGE
}

abs_path() {
  local path="${1:-}"
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

print_cmd() {
  local arg
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
  printf '\n'
}

dry_run="${CI_PHASE0_DRY_RUN:-0}"
summary_json="$(abs_path "${CI_PHASE0_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/ci_phase0_summary.json}")"
print_summary_json="${CI_PHASE0_PRINT_SUMMARY_JSON:-0}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      if [[ $# -ge 2 && ! "${2:-}" =~ ^-- ]]; then
        dry_run="${2:-}"
        shift 2
      else
        dry_run="1"
        shift
      fi
      ;;
    --summary-json)
      summary_json="$(abs_path "${2:-}")"
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

bool_arg_or_die "--dry-run" "$dry_run"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

launcher_wiring_script="${CI_PHASE0_LAUNCHER_WIRING_SCRIPT:-$ROOT_DIR/scripts/integration_easy_mode_launcher_wiring.sh}"
launcher_runtime_script="${CI_PHASE0_LAUNCHER_RUNTIME_SCRIPT:-$ROOT_DIR/scripts/integration_easy_mode_launcher_runtime.sh}"
prompt_budget_script="${CI_PHASE0_PROMPT_BUDGET_SCRIPT:-$ROOT_DIR/scripts/integration_easy_mode_simple_prompt_budget.sh}"
config_v1_script="${CI_PHASE0_CONFIG_V1_SCRIPT:-$ROOT_DIR/scripts/integration_easy_node_config_v1.sh}"
local_control_api_script="${CI_PHASE0_LOCAL_CONTROL_API_SCRIPT:-$ROOT_DIR/scripts/integration_local_control_api_contract.sh}"

step_ids=("launcher_wiring" "launcher_runtime" "prompt_budget" "config_v1" "local_control_api")
step_labels=(
  "easy-mode launcher wiring integration"
  "easy-mode launcher runtime integration"
  "easy-mode simple prompt budget integration"
  "easy-node config-v1 defaults contract integration"
  "local control API contract integration"
)
step_scripts=(
  "$launcher_wiring_script"
  "$launcher_runtime_script"
  "$prompt_budget_script"
  "$config_v1_script"
  "$local_control_api_script"
)
step_statuses=("pending" "pending" "pending" "pending" "pending")
step_rcs=("null" "null" "null" "null" "null")

set_step_result() {
  local idx="$1"
  local status="$2"
  local rc="${3:-null}"
  step_statuses[$idx]="$status"
  step_rcs[$idx]="$rc"
}

write_summary() {
  local script_rc="${1:-1}"
  local status="fail"
  local generated_at_utc=""
  local steps_json='{}'
  local i=0
  local step_count=0
  local pass_steps=0
  local fail_steps=0
  local dry_run_steps=0
  local skipped_steps=0
  local pending_steps=0
  local contract_ok="false"
  local all_required_steps_ok="false"
  local summary_tmp=""
  local rc_value=""

  if [[ "$dry_run" == "1" ]]; then
    status="dry-run"
  elif [[ "$script_rc" -eq 0 ]]; then
    status="pass"
  fi

  for (( i=0; i<${#step_ids[@]}; i++ )); do
    if [[ "${step_statuses[$i]}" == "pending" && "$status" == "fail" ]]; then
      step_statuses[$i]="skipped"
      step_rcs[$i]="null"
    fi
  done

  for (( i=0; i<${#step_ids[@]}; i++ )); do
    step_count=$((step_count + 1))
    case "${step_statuses[$i]}" in
      pass)
        pass_steps=$((pass_steps + 1))
        ;;
      fail)
        fail_steps=$((fail_steps + 1))
        ;;
      dry-run)
        dry_run_steps=$((dry_run_steps + 1))
        ;;
      skipped)
        skipped_steps=$((skipped_steps + 1))
        ;;
      *)
        pending_steps=$((pending_steps + 1))
        ;;
    esac
  done

  if [[ "$status" == "pass" ]]; then
    contract_ok="true"
  fi
  if [[ "$pass_steps" -eq "$step_count" ]]; then
    all_required_steps_ok="true"
  fi

  for (( i=0; i<${#step_ids[@]}; i++ )); do
    rc_value="${step_rcs[$i]}"
    steps_json="$(jq -cn \
      --argjson base "$steps_json" \
      --arg id "${step_ids[$i]}" \
      --arg label "${step_labels[$i]}" \
      --arg script "${step_scripts[$i]}" \
      --arg step_status "${step_statuses[$i]}" \
      --arg step_rc "$rc_value" \
      '
        $base + {
          ($id): {
            label: $label,
            script: $script,
            status: $step_status,
            rc: (if $step_rc == "null" then null else ($step_rc | tonumber) end)
          }
        }
      ')"
  done

  generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  mkdir -p "$(dirname "$summary_json")"
  summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
  jq -n \
    --arg generated_at_utc "$generated_at_utc" \
    --arg status "$status" \
    --argjson rc "$script_rc" \
    --argjson dry_run "$( [[ "$dry_run" == "1" ]] && printf 'true' || printf 'false' )" \
    --argjson steps "$steps_json" \
    --argjson total_steps "$step_count" \
    --argjson pass_steps "$pass_steps" \
    --argjson fail_steps "$fail_steps" \
    --argjson dry_run_steps "$dry_run_steps" \
    --argjson skipped_steps "$skipped_steps" \
    --argjson pending_steps "$pending_steps" \
    --argjson contract_ok "$contract_ok" \
    --argjson all_required_steps_ok "$all_required_steps_ok" \
    --arg summary_json_path "$summary_json" \
    '
      {
        version: 1,
        schema: {
          id: "ci_phase0_summary",
          major: 1,
          minor: 0
        },
        generated_at_utc: $generated_at_utc,
        status: $status,
        rc: $rc,
        dry_run: $dry_run,
        steps: $steps,
        summary: {
          total_steps: $total_steps,
          pass_steps: $pass_steps,
          fail_steps: $fail_steps,
          dry_run_steps: $dry_run_steps,
          skipped_steps: $skipped_steps,
          pending_steps: $pending_steps,
          contract_ok: $contract_ok,
          all_required_steps_ok: $all_required_steps_ok
        },
        artifacts: {
          summary_json: $summary_json_path
        }
      }
    ' >"$summary_tmp"
  mv -f "$summary_tmp" "$summary_json"
}

on_exit() {
  local rc=$?
  write_summary "$rc" || true
  if [[ "$print_summary_json" == "1" && -f "$summary_json" ]]; then
    cat "$summary_json" || true
  fi
}
trap on_exit EXIT

run_step() {
  local idx="$1"
  local label="${step_labels[$idx]}"
  local script="${step_scripts[$idx]}"
  local rc=0
  if [[ ! -x "$script" ]]; then
    set_step_result "$idx" "fail" "2"
    echo "missing executable step script for ${label}: $script"
    return 2
  fi
  if [[ "$dry_run" == "1" ]]; then
    set_step_result "$idx" "dry-run" "0"
    printf '[ci-phase0] dry-run step: %s -> ' "$label"
    print_cmd "$script"
    return 0
  fi
  echo "[ci-phase0] ${label}"
  set +e
  "$script"
  rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    set_step_result "$idx" "pass" "0"
  else
    set_step_result "$idx" "fail" "$rc"
  fi
  return "$rc"
}

if [[ "$dry_run" == "1" ]]; then
  echo "[ci-phase0] dry-run=1"
fi

run_step 0
run_step 1
run_step 2
run_step 3
run_step 4

if [[ "$dry_run" == "1" ]]; then
  echo "[ci-phase0] dry-run complete"
else
  echo "[ci-phase0] ok"
fi
echo "[ci-phase0] summary_json=$summary_json"
