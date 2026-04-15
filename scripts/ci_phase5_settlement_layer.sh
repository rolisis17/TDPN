#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/ci_phase5_settlement_layer.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]] \
    [--dry-run [0|1]] \
    [--run-settlement-failsoft [0|1]] \
    [--run-settlement-acceptance [0|1]] \
    [--run-settlement-bridge-smoke [0|1]] \
    [--run-settlement-state-persistence [0|1]] \
    [--run-settlement-adapter-roundtrip [0|1]] \
    [--run-settlement-adapter-signed-tx-roundtrip [0|1]] \
    [--run-settlement-shadow-env [0|1]] \
    [--run-phase5-settlement-layer-check [0|1]] \
    [--run-phase5-settlement-layer-run [0|1]] \
    [--run-phase5-settlement-layer-handoff-check [0|1]] \
    [--run-phase5-settlement-layer-handoff-run [0|1]]

Purpose:
  Run a focused Phase-5 settlement layer CI gate around Cosmos settlement
  integration readiness:
    1) integration_cosmos_settlement_failsoft.sh
    2) integration_cosmos_settlement_acceptance_paths.sh
    3) integration_cosmos_tdpnd_settlement_bridge_smoke.sh
    4) integration_cosmos_tdpnd_state_dir_persistence.sh
    5) integration_cosmos_adapter_tdpnd_bridge_roundtrip.sh
    6) integration_cosmos_adapter_tdpnd_signed_tx_roundtrip.sh
    7) integration_cosmos_settlement_shadow_env.sh
    8) integration_phase5_settlement_layer_check.sh
    9) integration_phase5_settlement_layer_run.sh
    10) integration_phase5_settlement_layer_handoff_check.sh
    11) integration_phase5_settlement_layer_handoff_run.sh

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
  echo "[ci-phase5-settlement-layer] step=${label} status=running"
  set +e
  "$@"
  rc=$?
  set -e
  if (( rc == 0 )); then
    echo "[ci-phase5-settlement-layer] step=${label} status=pass rc=0"
  else
    echo "[ci-phase5-settlement-layer] step=${label} status=fail rc=${rc}"
  fi
  return "$rc"
}

need_cmd jq
need_cmd date
need_cmd mktemp

reports_dir="${CI_PHASE5_SETTLEMENT_LAYER_REPORTS_DIR:-}"
summary_json="${CI_PHASE5_SETTLEMENT_LAYER_SUMMARY_JSON:-}"
print_summary_json="${CI_PHASE5_SETTLEMENT_LAYER_PRINT_SUMMARY_JSON:-1}"
dry_run="${CI_PHASE5_SETTLEMENT_LAYER_DRY_RUN:-0}"

run_settlement_failsoft="${CI_PHASE5_SETTLEMENT_LAYER_RUN_SETTLEMENT_FAILSOFT:-${CI_PHASE5_SETTLEMENT_LAYER_RUN_WINDOWS_SERVER_PACKAGING:-1}}"
run_settlement_acceptance="${CI_PHASE5_SETTLEMENT_LAYER_RUN_SETTLEMENT_ACCEPTANCE:-${CI_PHASE5_SETTLEMENT_LAYER_RUN_WINDOWS_ROLE_RUNBOOKS:-1}}"
run_settlement_bridge_smoke="${CI_PHASE5_SETTLEMENT_LAYER_RUN_SETTLEMENT_BRIDGE_SMOKE:-${CI_PHASE5_SETTLEMENT_LAYER_RUN_CROSS_PLATFORM_INTEROP:-1}}"
run_settlement_state_persistence="${CI_PHASE5_SETTLEMENT_LAYER_RUN_SETTLEMENT_STATE_PERSISTENCE:-${CI_PHASE5_SETTLEMENT_LAYER_RUN_ROLE_COMBINATION_VALIDATION:-1}}"
run_settlement_adapter_roundtrip="${CI_PHASE5_SETTLEMENT_LAYER_RUN_SETTLEMENT_ADAPTER_ROUNDTRIP:-1}"
run_settlement_adapter_signed_tx_roundtrip="${CI_PHASE5_SETTLEMENT_LAYER_RUN_SETTLEMENT_ADAPTER_SIGNED_TX_ROUNDTRIP:-1}"
run_settlement_shadow_env="${CI_PHASE5_SETTLEMENT_LAYER_RUN_SETTLEMENT_SHADOW_ENV:-1}"
run_phase5_settlement_layer_check="${CI_PHASE5_SETTLEMENT_LAYER_RUN_PHASE5_SETTLEMENT_LAYER_CHECK:-1}"
run_phase5_settlement_layer_run="${CI_PHASE5_SETTLEMENT_LAYER_RUN_PHASE5_SETTLEMENT_LAYER_RUN:-1}"
run_phase5_settlement_layer_handoff_check="${CI_PHASE5_SETTLEMENT_LAYER_RUN_PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK:-1}"
run_phase5_settlement_layer_handoff_run="${CI_PHASE5_SETTLEMENT_LAYER_RUN_PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN:-1}"

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
    --run-settlement-failsoft)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_settlement_failsoft="${2:-}"
        shift 2
      else
        run_settlement_failsoft="1"
        shift
      fi
      ;;
    --run-settlement-acceptance)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_settlement_acceptance="${2:-}"
        shift 2
      else
        run_settlement_acceptance="1"
        shift
      fi
      ;;
    --run-settlement-bridge-smoke)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_settlement_bridge_smoke="${2:-}"
        shift 2
      else
        run_settlement_bridge_smoke="1"
        shift
      fi
      ;;
    --run-settlement-state-persistence)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_settlement_state_persistence="${2:-}"
        shift 2
      else
        run_settlement_state_persistence="1"
        shift
      fi
      ;;
    --run-settlement-adapter-roundtrip)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_settlement_adapter_roundtrip="${2:-}"
        shift 2
      else
        run_settlement_adapter_roundtrip="1"
        shift
      fi
      ;;
    --run-settlement-adapter-signed-tx-roundtrip)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_settlement_adapter_signed_tx_roundtrip="${2:-}"
        shift 2
      else
        run_settlement_adapter_signed_tx_roundtrip="1"
        shift
      fi
      ;;
    --run-settlement-shadow-env)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_settlement_shadow_env="${2:-}"
        shift 2
      else
        run_settlement_shadow_env="1"
        shift
      fi
      ;;
    --run-phase5-settlement-layer-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase5_settlement_layer_check="${2:-}"
        shift 2
      else
        run_phase5_settlement_layer_check="1"
        shift
      fi
      ;;
    --run-phase5-settlement-layer-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase5_settlement_layer_run="${2:-}"
        shift 2
      else
        run_phase5_settlement_layer_run="1"
        shift
      fi
      ;;
    --run-phase5-settlement-layer-handoff-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase5_settlement_layer_handoff_check="${2:-}"
        shift 2
      else
        run_phase5_settlement_layer_handoff_check="1"
        shift
      fi
      ;;
    --run-phase5-settlement-layer-handoff-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase5_settlement_layer_handoff_run="${2:-}"
        shift 2
      else
        run_phase5_settlement_layer_handoff_run="1"
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
bool_arg_or_die "--run-settlement-failsoft" "$run_settlement_failsoft"
bool_arg_or_die "--run-settlement-acceptance" "$run_settlement_acceptance"
bool_arg_or_die "--run-settlement-bridge-smoke" "$run_settlement_bridge_smoke"
bool_arg_or_die "--run-settlement-state-persistence" "$run_settlement_state_persistence"
bool_arg_or_die "--run-settlement-adapter-roundtrip" "$run_settlement_adapter_roundtrip"
bool_arg_or_die "--run-settlement-adapter-signed-tx-roundtrip" "$run_settlement_adapter_signed_tx_roundtrip"
bool_arg_or_die "--run-settlement-shadow-env" "$run_settlement_shadow_env"
bool_arg_or_die "--run-phase5-settlement-layer-check" "$run_phase5_settlement_layer_check"
bool_arg_or_die "--run-phase5-settlement-layer-run" "$run_phase5_settlement_layer_run"
bool_arg_or_die "--run-phase5-settlement-layer-handoff-check" "$run_phase5_settlement_layer_handoff_check"
bool_arg_or_die "--run-phase5-settlement-layer-handoff-run" "$run_phase5_settlement_layer_handoff_run"

settlement_failsoft_script="${CI_PHASE5_SETTLEMENT_LAYER_SETTLEMENT_FAILSOFT_SCRIPT:-${CI_PHASE5_SETTLEMENT_LAYER_WINDOWS_SERVER_PACKAGING_SCRIPT:-$ROOT_DIR/scripts/integration_cosmos_settlement_failsoft.sh}}"
settlement_acceptance_script="${CI_PHASE5_SETTLEMENT_LAYER_SETTLEMENT_ACCEPTANCE_SCRIPT:-${CI_PHASE5_SETTLEMENT_LAYER_WINDOWS_ROLE_RUNBOOKS_SCRIPT:-$ROOT_DIR/scripts/integration_cosmos_settlement_acceptance_paths.sh}}"
settlement_bridge_smoke_script="${CI_PHASE5_SETTLEMENT_LAYER_SETTLEMENT_BRIDGE_SMOKE_SCRIPT:-${CI_PHASE5_SETTLEMENT_LAYER_CROSS_PLATFORM_INTEROP_SCRIPT:-$ROOT_DIR/scripts/integration_cosmos_tdpnd_settlement_bridge_smoke.sh}}"
settlement_state_persistence_script="${CI_PHASE5_SETTLEMENT_LAYER_SETTLEMENT_STATE_PERSISTENCE_SCRIPT:-${CI_PHASE5_SETTLEMENT_LAYER_ROLE_COMBINATION_VALIDATION_SCRIPT:-$ROOT_DIR/scripts/integration_cosmos_tdpnd_state_dir_persistence.sh}}"
settlement_adapter_roundtrip_script="${CI_PHASE5_SETTLEMENT_LAYER_SETTLEMENT_ADAPTER_ROUNDTRIP_SCRIPT:-$ROOT_DIR/scripts/integration_cosmos_adapter_tdpnd_bridge_roundtrip.sh}"
settlement_adapter_signed_tx_roundtrip_script="${CI_PHASE5_SETTLEMENT_LAYER_SETTLEMENT_ADAPTER_SIGNED_TX_ROUNDTRIP_SCRIPT:-$ROOT_DIR/scripts/integration_cosmos_adapter_tdpnd_signed_tx_roundtrip.sh}"
settlement_shadow_env_script="${CI_PHASE5_SETTLEMENT_LAYER_SETTLEMENT_SHADOW_ENV_SCRIPT:-$ROOT_DIR/scripts/integration_cosmos_settlement_shadow_env.sh}"
phase5_settlement_layer_check_script="${CI_PHASE5_SETTLEMENT_LAYER_PHASE5_SETTLEMENT_LAYER_CHECK_SCRIPT:-$ROOT_DIR/scripts/integration_phase5_settlement_layer_check.sh}"
phase5_settlement_layer_run_script="${CI_PHASE5_SETTLEMENT_LAYER_PHASE5_SETTLEMENT_LAYER_RUN_SCRIPT:-$ROOT_DIR/scripts/integration_phase5_settlement_layer_run.sh}"
phase5_settlement_layer_handoff_check_script="${CI_PHASE5_SETTLEMENT_LAYER_PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_SCRIPT:-$ROOT_DIR/scripts/integration_phase5_settlement_layer_handoff_check.sh}"
phase5_settlement_layer_handoff_run_script="${CI_PHASE5_SETTLEMENT_LAYER_PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_SCRIPT:-$ROOT_DIR/scripts/integration_phase5_settlement_layer_handoff_run.sh}"

stage_ids=(
  "settlement_failsoft"
  "settlement_acceptance"
  "settlement_bridge_smoke"
  "settlement_state_persistence"
  "settlement_adapter_roundtrip"
  "settlement_adapter_signed_tx_roundtrip"
  "settlement_shadow_env"
  "phase5_settlement_layer_check"
  "phase5_settlement_layer_run"
  "phase5_settlement_layer_handoff_check"
  "phase5_settlement_layer_handoff_run"
)

declare -A stage_script=(
  ["settlement_failsoft"]="$settlement_failsoft_script"
  ["settlement_acceptance"]="$settlement_acceptance_script"
  ["settlement_bridge_smoke"]="$settlement_bridge_smoke_script"
  ["settlement_state_persistence"]="$settlement_state_persistence_script"
  ["settlement_adapter_roundtrip"]="$settlement_adapter_roundtrip_script"
  ["settlement_adapter_signed_tx_roundtrip"]="$settlement_adapter_signed_tx_roundtrip_script"
  ["settlement_shadow_env"]="$settlement_shadow_env_script"
  ["phase5_settlement_layer_check"]="$phase5_settlement_layer_check_script"
  ["phase5_settlement_layer_run"]="$phase5_settlement_layer_run_script"
  ["phase5_settlement_layer_handoff_check"]="$phase5_settlement_layer_handoff_check_script"
  ["phase5_settlement_layer_handoff_run"]="$phase5_settlement_layer_handoff_run_script"
)

declare -A stage_enabled=(
  ["settlement_failsoft"]="$run_settlement_failsoft"
  ["settlement_acceptance"]="$run_settlement_acceptance"
  ["settlement_bridge_smoke"]="$run_settlement_bridge_smoke"
  ["settlement_state_persistence"]="$run_settlement_state_persistence"
  ["settlement_adapter_roundtrip"]="$run_settlement_adapter_roundtrip"
  ["settlement_adapter_signed_tx_roundtrip"]="$run_settlement_adapter_signed_tx_roundtrip"
  ["settlement_shadow_env"]="$run_settlement_shadow_env"
  ["phase5_settlement_layer_check"]="$run_phase5_settlement_layer_check"
  ["phase5_settlement_layer_run"]="$run_phase5_settlement_layer_run"
  ["phase5_settlement_layer_handoff_check"]="$run_phase5_settlement_layer_handoff_check"
  ["phase5_settlement_layer_handoff_run"]="$run_phase5_settlement_layer_handoff_run"
)

for stage_id in "${stage_ids[@]}"; do
  if [[ "${stage_enabled[$stage_id]}" == "1" && ! -x "${stage_script[$stage_id]}" ]]; then
    echo "missing executable stage script: ${stage_script[$stage_id]}"
    exit 2
  fi
done

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/ci_phase5_settlement_layer_${run_stamp}"
else
  reports_dir="$(abs_path "$reports_dir")"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/ci_phase5_settlement_layer_summary.json"
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
      echo "[ci-phase5-settlement-layer] step=${stage_id} status=skip reason=dry-run"
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
    echo "[ci-phase5-settlement-layer] step=${stage_id} status=skip reason=disabled"
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
  --arg run_settlement_failsoft "$run_settlement_failsoft" \
  --arg run_settlement_acceptance "$run_settlement_acceptance" \
  --arg run_settlement_bridge_smoke "$run_settlement_bridge_smoke" \
  --arg run_settlement_state_persistence "$run_settlement_state_persistence" \
  --arg run_settlement_adapter_roundtrip "$run_settlement_adapter_roundtrip" \
  --arg run_settlement_adapter_signed_tx_roundtrip "$run_settlement_adapter_signed_tx_roundtrip" \
  --arg run_settlement_shadow_env "$run_settlement_shadow_env" \
  --arg run_phase5_settlement_layer_check "$run_phase5_settlement_layer_check" \
  --arg run_phase5_settlement_layer_run "$run_phase5_settlement_layer_run" \
  --arg run_phase5_settlement_layer_handoff_check "$run_phase5_settlement_layer_handoff_check" \
  --arg run_phase5_settlement_layer_handoff_run "$run_phase5_settlement_layer_handoff_run" \
  --argjson steps "$steps_json" \
  '{
    version: 1,
    schema: {
      id: "ci_phase5_settlement_layer_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    inputs: {
      dry_run: ($dry_run == "1"),
      print_summary_json: ($print_summary_json == "1"),
      run_settlement_failsoft: ($run_settlement_failsoft == "1"),
      run_settlement_acceptance: ($run_settlement_acceptance == "1"),
      run_settlement_bridge_smoke: ($run_settlement_bridge_smoke == "1"),
      run_settlement_state_persistence: ($run_settlement_state_persistence == "1"),
      run_settlement_adapter_roundtrip: ($run_settlement_adapter_roundtrip == "1"),
      run_settlement_adapter_signed_tx_roundtrip: ($run_settlement_adapter_signed_tx_roundtrip == "1"),
      run_settlement_shadow_env: ($run_settlement_shadow_env == "1"),
      run_phase5_settlement_layer_check: ($run_phase5_settlement_layer_check == "1"),
      run_phase5_settlement_layer_run: ($run_phase5_settlement_layer_run == "1"),
      run_phase5_settlement_layer_handoff_check: ($run_phase5_settlement_layer_handoff_check == "1"),
      run_phase5_settlement_layer_handoff_run: ($run_phase5_settlement_layer_handoff_run == "1")
    },
    steps: $steps,
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

echo "[ci-phase5-settlement-layer] status=$final_status rc=$final_rc dry_run=$dry_run"
echo "[ci-phase5-settlement-layer] reports_dir=$reports_dir"
echo "[ci-phase5-settlement-layer] summary_json=$summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
