#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/blockchain_fastlane.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]] \
    [--dry-run [0|1]] \
    [--run-ci-phase5-settlement-layer [0|1]] \
    [--run-ci-phase6-cosmos-l1-build-testnet [0|1]] \
    [--run-ci-phase6-cosmos-l1-contracts [0|1]] \
    [--run-ci-phase7-mainnet-cutover [0|1]] \
    [--run-blockchain-mainnet-activation-metrics [0|1]] \
    [--blockchain-mainnet-activation-metrics-json PATH] \
    [--blockchain-mainnet-activation-metrics-summary-json PATH] \
    [--run-blockchain-mainnet-activation-gate [0|1]]

Purpose:
  Run blockchain CI gates in deterministic order:
    1) scripts/ci_phase5_settlement_layer.sh
    2) scripts/ci_phase6_cosmos_l1_build_testnet.sh
    3) scripts/ci_phase6_cosmos_l1_contracts.sh
    4) scripts/ci_phase7_mainnet_cutover.sh
    5) scripts/blockchain_mainnet_activation_metrics.sh
    6) scripts/blockchain_mainnet_activation_gate.sh

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
  echo "[blockchain-fastlane] step=${label} status=running"
  set +e
  "$@"
  rc=$?
  set -e
  if (( rc == 0 )); then
    echo "[blockchain-fastlane] step=${label} status=pass rc=0"
  else
    echo "[blockchain-fastlane] step=${label} status=fail rc=${rc}"
  fi
  return "$rc"
}

need_cmd jq
need_cmd date
need_cmd mktemp

reports_dir="${BLOCKCHAIN_FASTLANE_REPORTS_DIR:-}"
summary_json="${BLOCKCHAIN_FASTLANE_SUMMARY_JSON:-}"
canonical_summary_json="${BLOCKCHAIN_FASTLANE_CANONICAL_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/blockchain_fastlane_summary.json}"
print_summary_json="${BLOCKCHAIN_FASTLANE_PRINT_SUMMARY_JSON:-1}"
dry_run="${BLOCKCHAIN_FASTLANE_DRY_RUN:-0}"

run_ci_phase5_settlement_layer="${BLOCKCHAIN_FASTLANE_RUN_CI_PHASE5_SETTLEMENT_LAYER:-1}"
run_ci_phase6_cosmos_l1_build_testnet="${BLOCKCHAIN_FASTLANE_RUN_CI_PHASE6_COSMOS_L1_BUILD_TESTNET:-1}"
run_ci_phase6_cosmos_l1_contracts="${BLOCKCHAIN_FASTLANE_RUN_CI_PHASE6_COSMOS_L1_CONTRACTS:-1}"
run_ci_phase7_mainnet_cutover="${BLOCKCHAIN_FASTLANE_RUN_CI_PHASE7_MAINNET_CUTOVER:-1}"
run_blockchain_mainnet_activation_metrics="${BLOCKCHAIN_FASTLANE_RUN_BLOCKCHAIN_MAINNET_ACTIVATION_METRICS:-0}"
blockchain_mainnet_activation_metrics_json="${BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_JSON:-}"
blockchain_mainnet_activation_metrics_summary_json="${BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_SUMMARY_JSON:-}"
run_blockchain_mainnet_activation_gate="${BLOCKCHAIN_FASTLANE_RUN_BLOCKCHAIN_MAINNET_ACTIVATION_GATE:-1}"

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
    --run-ci-phase5-settlement-layer)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_ci_phase5_settlement_layer="${2:-}"
        shift 2
      else
        run_ci_phase5_settlement_layer="1"
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
    --run-ci-phase6-cosmos-l1-contracts)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_ci_phase6_cosmos_l1_contracts="${2:-}"
        shift 2
      else
        run_ci_phase6_cosmos_l1_contracts="1"
        shift
      fi
      ;;
    --run-ci-phase7-mainnet-cutover)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_ci_phase7_mainnet_cutover="${2:-}"
        shift 2
      else
        run_ci_phase7_mainnet_cutover="1"
        shift
      fi
      ;;
    --run-blockchain-mainnet-activation-metrics)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_blockchain_mainnet_activation_metrics="${2:-}"
        shift 2
      else
        run_blockchain_mainnet_activation_metrics="1"
        shift
      fi
      ;;
    --blockchain-mainnet-activation-metrics-json)
      blockchain_mainnet_activation_metrics_json="${2:-}"
      shift 2
      ;;
    --blockchain-mainnet-activation-metrics-summary-json)
      blockchain_mainnet_activation_metrics_summary_json="${2:-}"
      shift 2
      ;;
    --run-blockchain-mainnet-activation-gate)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_blockchain_mainnet_activation_gate="${2:-}"
        shift 2
      else
        run_blockchain_mainnet_activation_gate="1"
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
bool_arg_or_die "--run-ci-phase5-settlement-layer" "$run_ci_phase5_settlement_layer"
bool_arg_or_die "--run-ci-phase6-cosmos-l1-build-testnet" "$run_ci_phase6_cosmos_l1_build_testnet"
bool_arg_or_die "--run-ci-phase6-cosmos-l1-contracts" "$run_ci_phase6_cosmos_l1_contracts"
bool_arg_or_die "--run-ci-phase7-mainnet-cutover" "$run_ci_phase7_mainnet_cutover"
bool_arg_or_die "--run-blockchain-mainnet-activation-metrics" "$run_blockchain_mainnet_activation_metrics"
bool_arg_or_die "--run-blockchain-mainnet-activation-gate" "$run_blockchain_mainnet_activation_gate"

ci_phase5_settlement_layer_script="${BLOCKCHAIN_FASTLANE_CI_PHASE5_SETTLEMENT_LAYER_SCRIPT:-$ROOT_DIR/scripts/ci_phase5_settlement_layer.sh}"
ci_phase6_cosmos_l1_build_testnet_script="${BLOCKCHAIN_FASTLANE_CI_PHASE6_COSMOS_L1_BUILD_TESTNET_SCRIPT:-$ROOT_DIR/scripts/ci_phase6_cosmos_l1_build_testnet.sh}"
ci_phase6_cosmos_l1_contracts_script="${BLOCKCHAIN_FASTLANE_CI_PHASE6_COSMOS_L1_CONTRACTS_SCRIPT:-$ROOT_DIR/scripts/ci_phase6_cosmos_l1_contracts.sh}"
ci_phase7_mainnet_cutover_script="${BLOCKCHAIN_FASTLANE_CI_PHASE7_MAINNET_CUTOVER_SCRIPT:-$ROOT_DIR/scripts/ci_phase7_mainnet_cutover.sh}"
blockchain_mainnet_activation_metrics_script="${BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics.sh}"
blockchain_mainnet_activation_gate_script="${BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_GATE_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_gate.sh}"

stage_ids=(
  "ci_phase5_settlement_layer"
  "ci_phase6_cosmos_l1_build_testnet"
  "ci_phase6_cosmos_l1_contracts"
  "ci_phase7_mainnet_cutover"
  "blockchain_mainnet_activation_metrics"
  "blockchain_mainnet_activation_gate"
)

declare -A stage_script=(
  ["ci_phase5_settlement_layer"]="$ci_phase5_settlement_layer_script"
  ["ci_phase6_cosmos_l1_build_testnet"]="$ci_phase6_cosmos_l1_build_testnet_script"
  ["ci_phase6_cosmos_l1_contracts"]="$ci_phase6_cosmos_l1_contracts_script"
  ["ci_phase7_mainnet_cutover"]="$ci_phase7_mainnet_cutover_script"
  ["blockchain_mainnet_activation_metrics"]="$blockchain_mainnet_activation_metrics_script"
  ["blockchain_mainnet_activation_gate"]="$blockchain_mainnet_activation_gate_script"
)

declare -A stage_enabled=(
  ["ci_phase5_settlement_layer"]="$run_ci_phase5_settlement_layer"
  ["ci_phase6_cosmos_l1_build_testnet"]="$run_ci_phase6_cosmos_l1_build_testnet"
  ["ci_phase6_cosmos_l1_contracts"]="$run_ci_phase6_cosmos_l1_contracts"
  ["ci_phase7_mainnet_cutover"]="$run_ci_phase7_mainnet_cutover"
  ["blockchain_mainnet_activation_metrics"]="$run_blockchain_mainnet_activation_metrics"
  ["blockchain_mainnet_activation_gate"]="$run_blockchain_mainnet_activation_gate"
)

for stage_id in "${stage_ids[@]}"; do
  if [[ "${stage_enabled[$stage_id]}" == "1" && ! -x "${stage_script[$stage_id]}" ]]; then
    echo "missing executable stage script: ${stage_script[$stage_id]}"
    exit 2
  fi
done

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/blockchain_fastlane_${run_stamp}"
else
  reports_dir="$(abs_path "$reports_dir")"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/blockchain_fastlane_summary.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
if [[ -z "$blockchain_mainnet_activation_metrics_json" && "$run_blockchain_mainnet_activation_metrics" == "1" ]]; then
  blockchain_mainnet_activation_metrics_json="$reports_dir/blockchain_mainnet_activation_metrics.json"
fi
if [[ -n "$blockchain_mainnet_activation_metrics_json" ]]; then
  blockchain_mainnet_activation_metrics_json="$(abs_path "$blockchain_mainnet_activation_metrics_json")"
fi
if [[ -z "$blockchain_mainnet_activation_metrics_summary_json" && "$run_blockchain_mainnet_activation_metrics" == "1" ]]; then
  blockchain_mainnet_activation_metrics_summary_json="$reports_dir/blockchain_mainnet_activation_metrics_summary.json"
fi
if [[ -n "$blockchain_mainnet_activation_metrics_summary_json" ]]; then
  blockchain_mainnet_activation_metrics_summary_json="$(abs_path "$blockchain_mainnet_activation_metrics_summary_json")"
fi
canonical_summary_json="$(abs_path "$canonical_summary_json")"

mkdir -p "$reports_dir"
mkdir -p "$(dirname "$summary_json")"
mkdir -p "$(dirname "$canonical_summary_json")"
if [[ -n "$blockchain_mainnet_activation_metrics_json" ]]; then
  mkdir -p "$(dirname "$blockchain_mainnet_activation_metrics_json")"
fi
if [[ -n "$blockchain_mainnet_activation_metrics_summary_json" ]]; then
  mkdir -p "$(dirname "$blockchain_mainnet_activation_metrics_summary_json")"
fi

declare -A stage_status
declare -A stage_rc
declare -A stage_command
declare -A stage_reason

final_rc=0

for stage_id in "${stage_ids[@]}"; do
  script="${stage_script[$stage_id]}"
  enabled="${stage_enabled[$stage_id]}"
  stage_args=("$script")

  stage_status["$stage_id"]="skip"
  stage_rc["$stage_id"]=0
  stage_command["$stage_id"]=""
  stage_reason["$stage_id"]=""

  case "$stage_id" in
    "blockchain_mainnet_activation_metrics")
      if [[ -n "$blockchain_mainnet_activation_metrics_json" ]]; then
        stage_args+=(--metrics-json "$blockchain_mainnet_activation_metrics_json")
      fi
      if [[ -n "$blockchain_mainnet_activation_metrics_summary_json" ]]; then
        stage_args+=(--summary-json "$blockchain_mainnet_activation_metrics_summary_json")
      fi
      stage_args+=(--print-summary-json 0)
      ;;
    "blockchain_mainnet_activation_gate")
      if [[ -n "$blockchain_mainnet_activation_metrics_json" ]]; then
        stage_args+=(--metrics-json "$blockchain_mainnet_activation_metrics_json")
      fi
      ;;
  esac

  if [[ "$enabled" == "1" ]]; then
    stage_command["$stage_id"]="$(print_cmd "${stage_args[@]}")"
    if [[ "$dry_run" == "1" ]]; then
      stage_reason["$stage_id"]="dry-run"
      echo "[blockchain-fastlane] step=${stage_id} status=skip reason=dry-run"
    elif run_step "$stage_id" "${stage_args[@]}"; then
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
    echo "[blockchain-fastlane] step=${stage_id} status=skip reason=disabled"
    stage_reason["$stage_id"]="disabled"
  fi
done

final_status="pass"
if (( final_rc != 0 )); then
  final_status="fail"
fi

steps_json='{}'
for stage_id in "${stage_ids[@]}"; do
  stage_artifacts_json='{}'
  case "$stage_id" in
    "blockchain_mainnet_activation_metrics")
      stage_artifacts_json="$(
        jq -n \
          --arg metrics_json "$blockchain_mainnet_activation_metrics_json" \
          --arg summary_json "$blockchain_mainnet_activation_metrics_summary_json" \
          '{
            metrics_json: (if $metrics_json == "" then null else $metrics_json end),
            summary_json: (if $summary_json == "" then null else $summary_json end)
          }'
      )"
      ;;
    "blockchain_mainnet_activation_gate")
      stage_artifacts_json="$(
        jq -n \
          --arg metrics_json "$blockchain_mainnet_activation_metrics_json" \
          '{
            metrics_json: (if $metrics_json == "" then null else $metrics_json end)
          }'
      )"
      ;;
  esac

  stage_entry="$(
    jq -n \
      --arg enabled "${stage_enabled[$stage_id]}" \
      --arg status "${stage_status[$stage_id]}" \
      --argjson rc "${stage_rc[$stage_id]}" \
      --arg command "${stage_command[$stage_id]}" \
      --arg reason "${stage_reason[$stage_id]}" \
      --argjson artifacts "$stage_artifacts_json" \
      '{
        enabled: ($enabled == "1"),
        status: $status,
        rc: $rc,
        command: (if $command == "" then null else $command end),
        reason: (if $reason == "" then null else $reason end),
        artifacts: $artifacts
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
  --arg canonical_summary_json "$canonical_summary_json" \
  --arg dry_run "$dry_run" \
  --arg print_summary_json "$print_summary_json" \
  --arg run_ci_phase5_settlement_layer "$run_ci_phase5_settlement_layer" \
  --arg run_ci_phase6_cosmos_l1_build_testnet "$run_ci_phase6_cosmos_l1_build_testnet" \
  --arg run_ci_phase6_cosmos_l1_contracts "$run_ci_phase6_cosmos_l1_contracts" \
  --arg run_ci_phase7_mainnet_cutover "$run_ci_phase7_mainnet_cutover" \
  --arg run_blockchain_mainnet_activation_metrics "$run_blockchain_mainnet_activation_metrics" \
  --arg blockchain_mainnet_activation_metrics_json "$blockchain_mainnet_activation_metrics_json" \
  --arg blockchain_mainnet_activation_metrics_summary_json "$blockchain_mainnet_activation_metrics_summary_json" \
  --arg run_blockchain_mainnet_activation_gate "$run_blockchain_mainnet_activation_gate" \
  --argjson steps "$steps_json" \
  '{
    version: 1,
    schema: {
      id: "blockchain_fastlane_summary",
      major: 1,
      minor: 1
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    inputs: {
      dry_run: ($dry_run == "1"),
      print_summary_json: ($print_summary_json == "1"),
      run_ci_phase5_settlement_layer: ($run_ci_phase5_settlement_layer == "1"),
      run_ci_phase6_cosmos_l1_build_testnet: ($run_ci_phase6_cosmos_l1_build_testnet == "1"),
      run_ci_phase6_cosmos_l1_contracts: ($run_ci_phase6_cosmos_l1_contracts == "1"),
      run_ci_phase7_mainnet_cutover: ($run_ci_phase7_mainnet_cutover == "1"),
      run_blockchain_mainnet_activation_metrics: ($run_blockchain_mainnet_activation_metrics == "1"),
      blockchain_mainnet_activation_metrics_json: (if $blockchain_mainnet_activation_metrics_json == "" then null else $blockchain_mainnet_activation_metrics_json end),
      blockchain_mainnet_activation_metrics_summary_json: (if $blockchain_mainnet_activation_metrics_summary_json == "" then null else $blockchain_mainnet_activation_metrics_summary_json end),
      run_blockchain_mainnet_activation_gate: ($run_blockchain_mainnet_activation_gate == "1")
    },
    steps: $steps,
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      canonical_summary_json: $canonical_summary_json,
      blockchain_mainnet_activation_metrics_json: (if $blockchain_mainnet_activation_metrics_json == "" then null else $blockchain_mainnet_activation_metrics_json end),
      blockchain_mainnet_activation_metrics_summary_json: (if $blockchain_mainnet_activation_metrics_summary_json == "" then null else $blockchain_mainnet_activation_metrics_summary_json end)
    }
  }' >"$summary_tmp"
mv -f "$summary_tmp" "$summary_json"
if [[ "$summary_json" != "$canonical_summary_json" ]]; then
  cp -f "$summary_json" "$canonical_summary_json"
fi

echo "[blockchain-fastlane] status=$final_status rc=$final_rc dry_run=$dry_run"
echo "[blockchain-fastlane] reports_dir=$reports_dir"
echo "[blockchain-fastlane] summary_json=$summary_json"
echo "[blockchain-fastlane] canonical_summary_json=$canonical_summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
