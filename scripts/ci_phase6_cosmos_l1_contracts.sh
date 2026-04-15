#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/ci_phase6_cosmos_l1_contracts.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]] \
    [--dry-run [0|1]] \
    [--run-ci-phase6-cosmos-l1-build-testnet [0|1]] \
    [--run-phase6-cosmos-l1-build-testnet-check [0|1]] \
    [--run-phase6-cosmos-l1-build-testnet-run [0|1]] \
    [--run-phase6-cosmos-l1-build-testnet-handoff-check [0|1]] \
    [--run-phase6-cosmos-l1-build-testnet-handoff-run [0|1]] \
    [--run-phase6-cosmos-l1-build-testnet-suite [0|1]]

Purpose:
  Run the Phase-6 Cosmos L1 contracts CI gate in deterministic order:
    1) integration_ci_phase6_cosmos_l1_build_testnet.sh
    2) integration_phase6_cosmos_l1_build_testnet_check.sh
    3) integration_phase6_cosmos_l1_build_testnet_run.sh
    4) integration_phase6_cosmos_l1_build_testnet_handoff_check.sh
    5) integration_phase6_cosmos_l1_build_testnet_handoff_run.sh
    6) integration_phase6_cosmos_l1_build_testnet_suite.sh

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
  echo "[ci-phase6-cosmos-l1-contracts] step=${label} status=running"
  set +e
  "$@"
  rc=$?
  set -e
  if (( rc == 0 )); then
    echo "[ci-phase6-cosmos-l1-contracts] step=${label} status=pass rc=0"
  else
    echo "[ci-phase6-cosmos-l1-contracts] step=${label} status=fail rc=${rc}"
  fi
  return "$rc"
}

need_cmd jq
need_cmd date
need_cmd mktemp

reports_dir="${CI_PHASE6_COSMOS_L1_CONTRACTS_REPORTS_DIR:-}"
summary_json="${CI_PHASE6_COSMOS_L1_CONTRACTS_SUMMARY_JSON:-}"
print_summary_json="${CI_PHASE6_COSMOS_L1_CONTRACTS_PRINT_SUMMARY_JSON:-1}"
dry_run="${CI_PHASE6_COSMOS_L1_CONTRACTS_DRY_RUN:-0}"

run_ci_phase6_cosmos_l1_build_testnet="${CI_PHASE6_COSMOS_L1_CONTRACTS_RUN_CI_PHASE6_COSMOS_L1_BUILD_TESTNET:-1}"
run_phase6_cosmos_l1_build_testnet_check="${CI_PHASE6_COSMOS_L1_CONTRACTS_RUN_PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK:-1}"
run_phase6_cosmos_l1_build_testnet_run="${CI_PHASE6_COSMOS_L1_CONTRACTS_RUN_PHASE6_COSMOS_L1_BUILD_TESTNET_RUN:-1}"
run_phase6_cosmos_l1_build_testnet_handoff_check="${CI_PHASE6_COSMOS_L1_CONTRACTS_RUN_PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK:-1}"
run_phase6_cosmos_l1_build_testnet_handoff_run="${CI_PHASE6_COSMOS_L1_CONTRACTS_RUN_PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_RUN:-1}"
run_phase6_cosmos_l1_build_testnet_suite="${CI_PHASE6_COSMOS_L1_CONTRACTS_RUN_PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE:-1}"

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
    --run-ci-phase6-cosmos-l1-build-testnet)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_ci_phase6_cosmos_l1_build_testnet="${2:-}"
        shift 2
      else
        run_ci_phase6_cosmos_l1_build_testnet="1"
        shift
      fi
      ;;
    --run-phase6-cosmos-l1-build-testnet-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase6_cosmos_l1_build_testnet_check="${2:-}"
        shift 2
      else
        run_phase6_cosmos_l1_build_testnet_check="1"
        shift
      fi
      ;;
    --run-phase6-cosmos-l1-build-testnet-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase6_cosmos_l1_build_testnet_run="${2:-}"
        shift 2
      else
        run_phase6_cosmos_l1_build_testnet_run="1"
        shift
      fi
      ;;
    --run-phase6-cosmos-l1-build-testnet-handoff-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase6_cosmos_l1_build_testnet_handoff_check="${2:-}"
        shift 2
      else
        run_phase6_cosmos_l1_build_testnet_handoff_check="1"
        shift
      fi
      ;;
    --run-phase6-cosmos-l1-build-testnet-handoff-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase6_cosmos_l1_build_testnet_handoff_run="${2:-}"
        shift 2
      else
        run_phase6_cosmos_l1_build_testnet_handoff_run="1"
        shift
      fi
      ;;
    --run-phase6-cosmos-l1-build-testnet-suite)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_phase6_cosmos_l1_build_testnet_suite="${2:-}"
        shift 2
      else
        run_phase6_cosmos_l1_build_testnet_suite="1"
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
bool_arg_or_die "--run-ci-phase6-cosmos-l1-build-testnet" "$run_ci_phase6_cosmos_l1_build_testnet"
bool_arg_or_die "--run-phase6-cosmos-l1-build-testnet-check" "$run_phase6_cosmos_l1_build_testnet_check"
bool_arg_or_die "--run-phase6-cosmos-l1-build-testnet-run" "$run_phase6_cosmos_l1_build_testnet_run"
bool_arg_or_die "--run-phase6-cosmos-l1-build-testnet-handoff-check" "$run_phase6_cosmos_l1_build_testnet_handoff_check"
bool_arg_or_die "--run-phase6-cosmos-l1-build-testnet-handoff-run" "$run_phase6_cosmos_l1_build_testnet_handoff_run"
bool_arg_or_die "--run-phase6-cosmos-l1-build-testnet-suite" "$run_phase6_cosmos_l1_build_testnet_suite"

ci_phase6_cosmos_l1_build_testnet_script="${CI_PHASE6_COSMOS_L1_CONTRACTS_CI_PHASE6_COSMOS_L1_BUILD_TESTNET_SCRIPT:-$ROOT_DIR/scripts/integration_ci_phase6_cosmos_l1_build_testnet.sh}"
phase6_cosmos_l1_build_testnet_check_script="${CI_PHASE6_COSMOS_L1_CONTRACTS_PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_SCRIPT:-$ROOT_DIR/scripts/integration_phase6_cosmos_l1_build_testnet_check.sh}"
phase6_cosmos_l1_build_testnet_run_script="${CI_PHASE6_COSMOS_L1_CONTRACTS_PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_SCRIPT:-$ROOT_DIR/scripts/integration_phase6_cosmos_l1_build_testnet_run.sh}"
phase6_cosmos_l1_build_testnet_handoff_check_script="${CI_PHASE6_COSMOS_L1_CONTRACTS_PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_SCRIPT:-$ROOT_DIR/scripts/integration_phase6_cosmos_l1_build_testnet_handoff_check.sh}"
phase6_cosmos_l1_build_testnet_handoff_run_script="${CI_PHASE6_COSMOS_L1_CONTRACTS_PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_RUN_SCRIPT:-$ROOT_DIR/scripts/integration_phase6_cosmos_l1_build_testnet_handoff_run.sh}"
phase6_cosmos_l1_build_testnet_suite_script="${CI_PHASE6_COSMOS_L1_CONTRACTS_PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_SCRIPT:-$ROOT_DIR/scripts/integration_phase6_cosmos_l1_build_testnet_suite.sh}"

stage_ids=(
  "ci_phase6_cosmos_l1_build_testnet"
  "phase6_cosmos_l1_build_testnet_check"
  "phase6_cosmos_l1_build_testnet_run"
  "phase6_cosmos_l1_build_testnet_handoff_check"
  "phase6_cosmos_l1_build_testnet_handoff_run"
  "phase6_cosmos_l1_build_testnet_suite"
)

declare -A stage_script=(
  ["ci_phase6_cosmos_l1_build_testnet"]="$ci_phase6_cosmos_l1_build_testnet_script"
  ["phase6_cosmos_l1_build_testnet_check"]="$phase6_cosmos_l1_build_testnet_check_script"
  ["phase6_cosmos_l1_build_testnet_run"]="$phase6_cosmos_l1_build_testnet_run_script"
  ["phase6_cosmos_l1_build_testnet_handoff_check"]="$phase6_cosmos_l1_build_testnet_handoff_check_script"
  ["phase6_cosmos_l1_build_testnet_handoff_run"]="$phase6_cosmos_l1_build_testnet_handoff_run_script"
  ["phase6_cosmos_l1_build_testnet_suite"]="$phase6_cosmos_l1_build_testnet_suite_script"
)

declare -A stage_enabled=(
  ["ci_phase6_cosmos_l1_build_testnet"]="$run_ci_phase6_cosmos_l1_build_testnet"
  ["phase6_cosmos_l1_build_testnet_check"]="$run_phase6_cosmos_l1_build_testnet_check"
  ["phase6_cosmos_l1_build_testnet_run"]="$run_phase6_cosmos_l1_build_testnet_run"
  ["phase6_cosmos_l1_build_testnet_handoff_check"]="$run_phase6_cosmos_l1_build_testnet_handoff_check"
  ["phase6_cosmos_l1_build_testnet_handoff_run"]="$run_phase6_cosmos_l1_build_testnet_handoff_run"
  ["phase6_cosmos_l1_build_testnet_suite"]="$run_phase6_cosmos_l1_build_testnet_suite"
)

for stage_id in "${stage_ids[@]}"; do
  if [[ "${stage_enabled[$stage_id]}" == "1" && ! -x "${stage_script[$stage_id]}" ]]; then
    echo "missing executable stage script: ${stage_script[$stage_id]}"
    exit 2
  fi
done

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/ci_phase6_cosmos_l1_contracts_${run_stamp}"
else
  reports_dir="$(abs_path "$reports_dir")"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/ci_phase6_cosmos_l1_contracts_summary.json"
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
      echo "[ci-phase6-cosmos-l1-contracts] step=${stage_id} status=skip reason=dry-run"
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
    echo "[ci-phase6-cosmos-l1-contracts] step=${stage_id} status=skip reason=disabled"
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
  --arg run_ci_phase6_cosmos_l1_build_testnet "$run_ci_phase6_cosmos_l1_build_testnet" \
  --arg run_phase6_cosmos_l1_build_testnet_check "$run_phase6_cosmos_l1_build_testnet_check" \
  --arg run_phase6_cosmos_l1_build_testnet_run "$run_phase6_cosmos_l1_build_testnet_run" \
  --arg run_phase6_cosmos_l1_build_testnet_handoff_check "$run_phase6_cosmos_l1_build_testnet_handoff_check" \
  --arg run_phase6_cosmos_l1_build_testnet_handoff_run "$run_phase6_cosmos_l1_build_testnet_handoff_run" \
  --arg run_phase6_cosmos_l1_build_testnet_suite "$run_phase6_cosmos_l1_build_testnet_suite" \
  --argjson steps "$steps_json" \
  '{
    version: 1,
    schema: {
      id: "ci_phase6_cosmos_l1_contracts_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    inputs: {
      dry_run: ($dry_run == "1"),
      print_summary_json: ($print_summary_json == "1"),
      run_ci_phase6_cosmos_l1_build_testnet: ($run_ci_phase6_cosmos_l1_build_testnet == "1"),
      run_phase6_cosmos_l1_build_testnet_check: ($run_phase6_cosmos_l1_build_testnet_check == "1"),
      run_phase6_cosmos_l1_build_testnet_run: ($run_phase6_cosmos_l1_build_testnet_run == "1"),
      run_phase6_cosmos_l1_build_testnet_handoff_check: ($run_phase6_cosmos_l1_build_testnet_handoff_check == "1"),
      run_phase6_cosmos_l1_build_testnet_handoff_run: ($run_phase6_cosmos_l1_build_testnet_handoff_run == "1"),
      run_phase6_cosmos_l1_build_testnet_suite: ($run_phase6_cosmos_l1_build_testnet_suite == "1")
    },
    steps: $steps,
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"

echo "[ci-phase6-cosmos-l1-contracts] status=$final_status rc=$final_rc dry_run=$dry_run"
echo "[ci-phase6-cosmos-l1-contracts] reports_dir=$reports_dir"
echo "[ci-phase6-cosmos-l1-contracts] summary_json=$summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
