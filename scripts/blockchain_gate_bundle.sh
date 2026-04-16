#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/blockchain_gate_bundle.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--canonical-summary-json PATH] \
    [--print-summary-json [0|1]] \
    [--metrics-json PATH] \
    [--metrics-summary-json PATH] \
    [--blockchain-mainnet-activation-metrics-input-json PATH] \
    [--blockchain-mainnet-activation-metrics-input-summary-json PATH] \
    [--blockchain-mainnet-activation-metrics-input-canonical-json PATH] \
    [--activation-summary-json PATH] \
    [--bootstrap-summary-json PATH] \
    [--source-json PATH] \
    [--measurement-window-weeks N] \
    [--vpn-connect-session-success-slo-pct N] \
    [--vpn-recovery-mttr-p95-minutes N] \
    [--paying-users-3mo-min N] \
    [--paid-sessions-per-day-30d-avg N] \
    [--validator-candidate-depth N] \
    [--validator-independent-operators N] \
    [--validator-max-operator-seat-share-pct N] \
    [--validator-max-asn-provider-seat-share-pct N] \
    [--validator-region-count N] \
    [--validator-country-count N] \
    [--manual-sanctions-reversed-pct-90d N] \
    [--abuse-report-to-decision-p95-hours N] \
    [--subsidy-runway-months N] \
    [--contribution-margin-3mo N]

Purpose:
  Deterministically run blockchain metrics + both gates and always emit bundle
  summaries even when gate decisions are NO-GO.

Execution order:
  1) scripts/blockchain_mainnet_activation_metrics.sh
  2) scripts/blockchain_mainnet_activation_gate.sh --fail-close 0
  3) scripts/blockchain_bootstrap_graduation_gate.sh --fail-close 0

Notes:
  - Metrics flags and repeatable --source-json are forwarded to step (1).
  - Optional --blockchain-mainnet-activation-metrics-input-json is normalized
    via scripts/blockchain_mainnet_activation_metrics_input.sh and injected as
    a deterministic --source-json artifact before step (1).
  - Helper discoverability: start from scripts/blockchain_mainnet_activation_metrics_input_template.sh
    (easy-node: ./scripts/easy_node.sh blockchain-mainnet-activation-metrics-input-template),
    then run scripts/blockchain_mainnet_activation_gate_cycle.sh for one-command
    normalization + gate cycle (easy-node: ./scripts/easy_node.sh blockchain-mainnet-activation-gate-cycle).
  - Bundle exits 0 for logical NO-GO decisions; non-zero only for usage/runtime
    failures in the bundle run (for example a stage command exiting non-zero).
USAGE
}

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
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

path_arg_or_die() {
  local name="$1"
  local value="$2"
  value="$(trim "$value")"
  if [[ -z "$value" ]]; then
    echo "$name requires a value"
    exit 2
  fi
  case "$value" in
    -*)
      echo "$name requires a path value, got flag-like token: $value"
      exit 2
      ;;
  esac
}

value_arg_or_die() {
  local name="$1"
  local value="$2"
  value="$(trim "$value")"
  if [[ -z "$value" ]]; then
    echo "$name requires a value"
    exit 2
  fi
  case "$value" in
    --*)
      echo "$name requires a value, got flag-like token: $value"
      exit 2
      ;;
  esac
}

array_to_json() {
  local -n arr_ref=$1
  if ((${#arr_ref[@]} == 0)); then
    printf '%s' "[]"
    return
  fi
  printf '%s\n' "${arr_ref[@]}" | jq -R 'select(length > 0)' | jq -s .
}

append_unique_abs_path() {
  local -n arr_ref=$1
  local candidate_abs
  local existing=""
  candidate_abs="$(abs_path "${2:-}")"
  if [[ -z "$candidate_abs" ]]; then
    return
  fi
  for existing in "${arr_ref[@]}"; do
    if [[ "$existing" == "$candidate_abs" ]]; then
      return
    fi
  done
  arr_ref+=("$candidate_abs")
}

append_csv_abs_paths_unique() {
  local csv="${1:-}"
  local target_arr_name="$2"
  local old_ifs="$IFS"
  local part=""
  local parts=()
  IFS=','
  read -r -a parts <<<"$csv"
  IFS="$old_ifs"
  for part in "${parts[@]}"; do
    append_unique_abs_path "$target_arr_name" "$part"
  done
}

print_cmd() {
  local arg
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
  printf '\n'
}

json_array_or_empty() {
  local path="$1"
  local expr="$2"
  if [[ -z "$path" || ! -f "$path" ]]; then
    printf '%s' '[]'
    return
  fi
  jq -c "$expr" "$path" 2>/dev/null || printf '%s' '[]'
}

json_text_or_empty() {
  local path="$1"
  local expr="$2"
  if [[ -z "$path" || ! -f "$path" ]]; then
    printf '%s' ""
    return
  fi
  jq -r "$expr // empty" "$path" 2>/dev/null || true
}

json_bool_or_null() {
  local path="$1"
  local expr="$2"
  if [[ -z "$path" || ! -f "$path" ]]; then
    printf '%s' 'null'
    return
  fi
  local value
  value="$(jq -r "$expr" "$path" 2>/dev/null || true)"
  case "$value" in
    true|false)
      printf '%s' "$value"
      ;;
    *)
      printf '%s' 'null'
      ;;
  esac
}

run_step() {
  local step_id="$1"
  shift
  local rc=0
  local started_at=""
  local completed_at=""

  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  step_started_at["$step_id"]="$started_at"
  step_command["$step_id"]="$(print_cmd "$@" | sed 's/[[:space:]]*$//')"

  echo "[blockchain-gate-bundle] step=${step_id} status=running"
  set +e
  "$@"
  rc=$?
  set -e

  completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  step_completed_at["$step_id"]="$completed_at"
  step_rc["$step_id"]="$rc"

  if (( rc == 0 )); then
    step_status["$step_id"]="pass"
    echo "[blockchain-gate-bundle] step=${step_id} status=pass rc=0"
  else
    step_status["$step_id"]="fail"
    echo "[blockchain-gate-bundle] step=${step_id} status=fail rc=${rc}"
  fi
}

need_cmd jq
need_cmd date
need_cmd cp
need_cmd mktemp

reports_dir="${BLOCKCHAIN_GATE_BUNDLE_REPORTS_DIR:-}"
summary_json="${BLOCKCHAIN_GATE_BUNDLE_SUMMARY_JSON:-}"
canonical_summary_json="${BLOCKCHAIN_GATE_BUNDLE_CANONICAL_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/blockchain_gate_bundle_summary.json}"
print_summary_json="${BLOCKCHAIN_GATE_BUNDLE_PRINT_SUMMARY_JSON:-1}"
metrics_json="${BLOCKCHAIN_GATE_BUNDLE_METRICS_JSON:-}"
metrics_summary_json="${BLOCKCHAIN_GATE_BUNDLE_METRICS_SUMMARY_JSON:-}"
blockchain_mainnet_activation_metrics_input_json="${BLOCKCHAIN_GATE_BUNDLE_BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_INPUT_JSON:-}"
blockchain_mainnet_activation_metrics_input_summary_json="${BLOCKCHAIN_GATE_BUNDLE_BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_INPUT_SUMMARY_JSON:-}"
blockchain_mainnet_activation_metrics_input_canonical_json="${BLOCKCHAIN_GATE_BUNDLE_BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_INPUT_CANONICAL_JSON:-}"
activation_summary_json="${BLOCKCHAIN_GATE_BUNDLE_ACTIVATION_SUMMARY_JSON:-}"
bootstrap_summary_json="${BLOCKCHAIN_GATE_BUNDLE_BOOTSTRAP_SUMMARY_JSON:-}"
source_jsons_env_csv="${BLOCKCHAIN_GATE_BUNDLE_SOURCE_JSONS:-}"

metrics_script="${BLOCKCHAIN_GATE_BUNDLE_METRICS_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics.sh}"
metrics_input_script="${BLOCKCHAIN_GATE_BUNDLE_BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_INPUT_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics_input.sh}"
activation_gate_script="${BLOCKCHAIN_GATE_BUNDLE_ACTIVATION_GATE_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_gate.sh}"
bootstrap_gate_script="${BLOCKCHAIN_GATE_BUNDLE_BOOTSTRAP_GATE_SCRIPT:-$ROOT_DIR/scripts/blockchain_bootstrap_graduation_gate.sh}"

declare -a source_jsons=()
declare -a metrics_passthrough_args=()

if [[ -n "$(trim "$source_jsons_env_csv")" ]]; then
  append_csv_abs_paths_unique "$source_jsons_env_csv" source_jsons
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      path_arg_or_die "--reports-dir" "${2:-}"
      reports_dir="${2:-}"
      shift 2
      ;;
    --summary-json)
      path_arg_or_die "--summary-json" "${2:-}"
      summary_json="${2:-}"
      shift 2
      ;;
    --canonical-summary-json)
      path_arg_or_die "--canonical-summary-json" "${2:-}"
      canonical_summary_json="${2:-}"
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
    --metrics-json)
      path_arg_or_die "--metrics-json" "${2:-}"
      metrics_json="${2:-}"
      shift 2
      ;;
    --metrics-summary-json)
      path_arg_or_die "--metrics-summary-json" "${2:-}"
      metrics_summary_json="${2:-}"
      shift 2
      ;;
    --blockchain-mainnet-activation-metrics-input-json)
      path_arg_or_die "--blockchain-mainnet-activation-metrics-input-json" "${2:-}"
      blockchain_mainnet_activation_metrics_input_json="${2:-}"
      shift 2
      ;;
    --blockchain-mainnet-activation-metrics-input-summary-json)
      path_arg_or_die "--blockchain-mainnet-activation-metrics-input-summary-json" "${2:-}"
      blockchain_mainnet_activation_metrics_input_summary_json="${2:-}"
      shift 2
      ;;
    --blockchain-mainnet-activation-metrics-input-canonical-json)
      path_arg_or_die "--blockchain-mainnet-activation-metrics-input-canonical-json" "${2:-}"
      blockchain_mainnet_activation_metrics_input_canonical_json="${2:-}"
      shift 2
      ;;
    --activation-summary-json)
      path_arg_or_die "--activation-summary-json" "${2:-}"
      activation_summary_json="${2:-}"
      shift 2
      ;;
    --bootstrap-summary-json)
      path_arg_or_die "--bootstrap-summary-json" "${2:-}"
      bootstrap_summary_json="${2:-}"
      shift 2
      ;;
    --source-json)
      path_arg_or_die "--source-json" "${2:-}"
      append_unique_abs_path source_jsons "${2:-}"
      shift 2
      ;;
    --measurement-window-weeks|--vpn-connect-session-success-slo-pct|--vpn-recovery-mttr-p95-minutes|--paying-users-3mo-min|--paid-sessions-per-day-30d-avg|--validator-candidate-depth|--validator-independent-operators|--validator-max-operator-seat-share-pct|--validator-max-asn-provider-seat-share-pct|--validator-region-count|--validator-country-count|--manual-sanctions-reversed-pct-90d|--abuse-report-to-decision-p95-hours|--subsidy-runway-months|--contribution-margin-3mo)
      value_arg_or_die "$1" "${2:-}"
      metrics_passthrough_args+=("$1" "${2:-}")
      shift 2
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

bool_arg_or_die "--print-summary-json" "$print_summary_json"
if [[ -n "$(trim "$blockchain_mainnet_activation_metrics_input_json")" && ! -x "$metrics_input_script" ]]; then
  echo "missing executable stage script: $metrics_input_script"
  exit 2
fi

if [[ -z "$(trim "$reports_dir")" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/blockchain_gate_bundle_$(date -u +%Y%m%d_%H%M%S)"
fi
if [[ -n "$(trim "$reports_dir")" ]]; then
  path_arg_or_die "--reports-dir" "$reports_dir"
fi
reports_dir="$(abs_path "$reports_dir")"
mkdir -p "$reports_dir"

if [[ -z "$(trim "$summary_json")" ]]; then
  summary_json="$reports_dir/blockchain_gate_bundle_summary.json"
fi
if [[ -z "$(trim "$metrics_json")" ]]; then
  metrics_json="$reports_dir/blockchain_mainnet_activation_metrics.json"
fi
if [[ -z "$(trim "$metrics_summary_json")" ]]; then
  metrics_summary_json="$reports_dir/blockchain_mainnet_activation_metrics_summary.json"
fi
if [[ -n "$(trim "$blockchain_mainnet_activation_metrics_input_json")" ]]; then
  path_arg_or_die "--blockchain-mainnet-activation-metrics-input-json" "$blockchain_mainnet_activation_metrics_input_json"
  blockchain_mainnet_activation_metrics_input_json="$(abs_path "$blockchain_mainnet_activation_metrics_input_json")"
fi
if [[ -z "$(trim "$blockchain_mainnet_activation_metrics_input_summary_json")" && -n "$blockchain_mainnet_activation_metrics_input_json" ]]; then
  blockchain_mainnet_activation_metrics_input_summary_json="$reports_dir/blockchain_mainnet_activation_metrics_input_summary.json"
fi
if [[ -n "$(trim "$blockchain_mainnet_activation_metrics_input_summary_json")" ]]; then
  path_arg_or_die "--blockchain-mainnet-activation-metrics-input-summary-json" "$blockchain_mainnet_activation_metrics_input_summary_json"
  blockchain_mainnet_activation_metrics_input_summary_json="$(abs_path "$blockchain_mainnet_activation_metrics_input_summary_json")"
fi
if [[ -z "$(trim "$blockchain_mainnet_activation_metrics_input_canonical_json")" && -n "$blockchain_mainnet_activation_metrics_input_json" ]]; then
  blockchain_mainnet_activation_metrics_input_canonical_json="$reports_dir/blockchain_mainnet_activation_metrics_input.json"
fi
if [[ -n "$(trim "$blockchain_mainnet_activation_metrics_input_canonical_json")" ]]; then
  path_arg_or_die "--blockchain-mainnet-activation-metrics-input-canonical-json" "$blockchain_mainnet_activation_metrics_input_canonical_json"
  blockchain_mainnet_activation_metrics_input_canonical_json="$(abs_path "$blockchain_mainnet_activation_metrics_input_canonical_json")"
fi
if [[ -z "$(trim "$activation_summary_json")" ]]; then
  activation_summary_json="$reports_dir/blockchain_mainnet_activation_gate_summary.json"
fi
if [[ -z "$(trim "$bootstrap_summary_json")" ]]; then
  bootstrap_summary_json="$reports_dir/blockchain_bootstrap_governance_graduation_gate_summary.json"
fi

for path_var in summary_json canonical_summary_json metrics_json metrics_summary_json activation_summary_json bootstrap_summary_json; do
  path_arg_or_die "--${path_var//_/-}" "${!path_var}"
  printf -v "$path_var" '%s' "$(abs_path "${!path_var}")"
  mkdir -p "$(dirname "${!path_var}")"
done
if [[ -n "$blockchain_mainnet_activation_metrics_input_summary_json" ]]; then
  mkdir -p "$(dirname "$blockchain_mainnet_activation_metrics_input_summary_json")"
fi
if [[ -n "$blockchain_mainnet_activation_metrics_input_canonical_json" ]]; then
  mkdir -p "$(dirname "$blockchain_mainnet_activation_metrics_input_canonical_json")"
fi

step_ids=(
  "metrics"
  "mainnet_activation_gate"
  "bootstrap_graduation_gate"
)

declare -A step_status=()
declare -A step_rc=()
declare -A step_command=()
declare -A step_started_at=()
declare -A step_completed_at=()

for step_id in "${step_ids[@]}"; do
  step_status["$step_id"]="pending"
  step_rc["$step_id"]="0"
  step_command["$step_id"]=""
  step_started_at["$step_id"]=""
  step_completed_at["$step_id"]=""
done

run_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
run_started_epoch="$(date -u +%s)"

if [[ -n "$blockchain_mainnet_activation_metrics_input_json" ]]; then
  metrics_input_cmd=(
    "$metrics_input_script"
    --input-json "$blockchain_mainnet_activation_metrics_input_json"
    --summary-json "$blockchain_mainnet_activation_metrics_input_summary_json"
    --canonical-summary-json "$blockchain_mainnet_activation_metrics_input_canonical_json"
    --print-summary-json 0
  )
  echo "[blockchain-gate-bundle] step=metrics_input status=running"
  if "${metrics_input_cmd[@]}"; then
    echo "[blockchain-gate-bundle] step=metrics_input status=pass rc=0"
  else
    metrics_input_rc=$?
    echo "[blockchain-gate-bundle] step=metrics_input status=fail rc=${metrics_input_rc}"
    exit "$metrics_input_rc"
  fi
  append_unique_abs_path source_jsons "$blockchain_mainnet_activation_metrics_input_canonical_json"
fi

metrics_cmd=(
  bash "$metrics_script"
  --summary-json "$metrics_summary_json"
  --canonical-summary-json "$metrics_json"
  --print-summary-json 0
)

for src in "${source_jsons[@]}"; do
  metrics_cmd+=(--source-json "$src")
done

if ((${#metrics_passthrough_args[@]} > 0)); then
  metrics_cmd+=("${metrics_passthrough_args[@]}")
fi

activation_cmd=(
  bash "$activation_gate_script"
  --metrics-json "$metrics_json"
  --summary-json "$activation_summary_json"
  --fail-close 0
  --print-summary-json 0
)

bootstrap_cmd=(
  bash "$bootstrap_gate_script"
  --metrics-json "$metrics_json"
  --summary-json "$bootstrap_summary_json"
  --fail-close 0
  --print-summary-json 0
)

run_step "metrics" "${metrics_cmd[@]}"
run_step "mainnet_activation_gate" "${activation_cmd[@]}"
run_step "bootstrap_graduation_gate" "${bootstrap_cmd[@]}"

run_completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
run_completed_epoch="$(date -u +%s)"
run_duration_sec="$((run_completed_epoch - run_started_epoch))"
if (( run_duration_sec < 0 )); then
  run_duration_sec=0
fi

first_runtime_failure_step=""
first_runtime_failure_rc=0
for step_id in "${step_ids[@]}"; do
  if [[ "${step_status[$step_id]}" == "fail" ]]; then
    first_runtime_failure_step="$step_id"
    first_runtime_failure_rc="${step_rc[$step_id]}"
    break
  fi
done

bundle_status="pass"
bundle_rc=0
if [[ -n "$first_runtime_failure_step" ]]; then
  bundle_status="runtime-fail"
  bundle_rc="$first_runtime_failure_rc"
fi

metrics_missing_required_json="[]"
if [[ -f "$metrics_summary_json" ]]; then
  metrics_missing_required_json="$(json_array_or_empty "$metrics_summary_json" '(.required_missing_metrics // []) | if type == "array" then unique else [] end')"
fi

metrics_ready_for_gate_json="$(json_bool_or_null "$metrics_summary_json" '.ready_for_gate')"
activation_decision="$(json_text_or_empty "$activation_summary_json" '.decision')"
bootstrap_decision="$(json_text_or_empty "$bootstrap_summary_json" '.decision')"

bundle_decision="UNKNOWN"
if [[ "$activation_decision" == "GO" && "$bootstrap_decision" == "GO" ]]; then
  bundle_decision="GO"
elif [[ "$activation_decision" == "NO-GO" || "$bootstrap_decision" == "NO-GO" ]]; then
  bundle_decision="NO-GO"
fi

source_jsons_json="$(array_to_json source_jsons)"
metrics_passthrough_args_json="$(array_to_json metrics_passthrough_args)"

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
cleanup() {
  rm -f "$summary_tmp"
}
trap cleanup EXIT

jq -n \
  --arg generated_at "$run_completed_at" \
  --arg started_at "$run_started_at" \
  --arg completed_at "$run_completed_at" \
  --arg status "$bundle_status" \
  --arg decision "$bundle_decision" \
  --argjson rc "$bundle_rc" \
  --arg root_dir "$ROOT_DIR" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg canonical_summary_json "$canonical_summary_json" \
  --arg blockchain_mainnet_activation_metrics_input_json "$blockchain_mainnet_activation_metrics_input_json" \
  --arg blockchain_mainnet_activation_metrics_input_summary_json "$blockchain_mainnet_activation_metrics_input_summary_json" \
  --arg blockchain_mainnet_activation_metrics_input_canonical_json "$blockchain_mainnet_activation_metrics_input_canonical_json" \
  --arg metrics_json "$metrics_json" \
  --arg metrics_summary_json "$metrics_summary_json" \
  --arg activation_summary_json "$activation_summary_json" \
  --arg bootstrap_summary_json "$bootstrap_summary_json" \
  --argjson print_summary_json "$( [[ "$print_summary_json" == "1" ]] && echo true || echo false )" \
  --argjson duration_sec "$run_duration_sec" \
  --arg first_runtime_failure_step "$first_runtime_failure_step" \
  --argjson first_runtime_failure_rc "$first_runtime_failure_rc" \
  --argjson source_jsons "$source_jsons_json" \
  --argjson metrics_passthrough_args "$metrics_passthrough_args_json" \
  --argjson missing_required_metrics "$metrics_missing_required_json" \
  --argjson metrics_ready_for_gate "$metrics_ready_for_gate_json" \
  --arg activation_decision "$activation_decision" \
  --arg bootstrap_decision "$bootstrap_decision" \
  --arg metrics_status "${step_status[metrics]}" \
  --argjson metrics_rc "${step_rc[metrics]}" \
  --arg metrics_command "${step_command[metrics]}" \
  --arg metrics_started_at "${step_started_at[metrics]}" \
  --arg metrics_completed_at "${step_completed_at[metrics]}" \
  --arg activation_status "${step_status[mainnet_activation_gate]}" \
  --argjson activation_rc "${step_rc[mainnet_activation_gate]}" \
  --arg activation_command "${step_command[mainnet_activation_gate]}" \
  --arg activation_started_at "${step_started_at[mainnet_activation_gate]}" \
  --arg activation_completed_at "${step_completed_at[mainnet_activation_gate]}" \
  --arg bootstrap_status "${step_status[bootstrap_graduation_gate]}" \
  --argjson bootstrap_rc "${step_rc[bootstrap_graduation_gate]}" \
  --arg bootstrap_command "${step_command[bootstrap_graduation_gate]}" \
  --arg bootstrap_started_at "${step_started_at[bootstrap_graduation_gate]}" \
  --arg bootstrap_completed_at "${step_completed_at[bootstrap_graduation_gate]}" \
  '
  {
    schema: {
      id: "blockchain_gate_bundle_summary",
      version: "1.0.0"
    },
    generated_at: $generated_at,
    started_at: $started_at,
    completed_at: $completed_at,
    duration_sec: $duration_sec,
    status: $status,
    decision: $decision,
    rc: $rc,
    first_runtime_failure: {
      step: (if $first_runtime_failure_step == "" then null else $first_runtime_failure_step end),
      rc: (if $first_runtime_failure_step == "" then null else $first_runtime_failure_rc end)
    },
    inputs: {
      print_summary_json: $print_summary_json,
      blockchain_mainnet_activation_metrics_input_json: (if $blockchain_mainnet_activation_metrics_input_json == "" then null else $blockchain_mainnet_activation_metrics_input_json end),
      blockchain_mainnet_activation_metrics_input_summary_json: (if $blockchain_mainnet_activation_metrics_input_summary_json == "" then null else $blockchain_mainnet_activation_metrics_input_summary_json end),
      blockchain_mainnet_activation_metrics_input_canonical_json: (if $blockchain_mainnet_activation_metrics_input_canonical_json == "" then null else $blockchain_mainnet_activation_metrics_input_canonical_json end),
      source_jsons: $source_jsons,
      metrics_passthrough_args: $metrics_passthrough_args
    },
    steps: {
      metrics: {
        status: $metrics_status,
        rc: $metrics_rc,
        command: $metrics_command,
        started_at: (if $metrics_started_at == "" then null else $metrics_started_at end),
        completed_at: (if $metrics_completed_at == "" then null else $metrics_completed_at end),
        artifacts: {
          metrics_input_json: (if $blockchain_mainnet_activation_metrics_input_json == "" then null else $blockchain_mainnet_activation_metrics_input_json end),
          metrics_input_summary_json: (if $blockchain_mainnet_activation_metrics_input_summary_json == "" then null else $blockchain_mainnet_activation_metrics_input_summary_json end),
          metrics_input_canonical_json: (if $blockchain_mainnet_activation_metrics_input_canonical_json == "" then null else $blockchain_mainnet_activation_metrics_input_canonical_json end),
          summary_json: $metrics_summary_json,
          metrics_json: $metrics_json,
          source_jsons: $source_jsons
        },
        missing_required_metrics: $missing_required_metrics,
        ready_for_gate: $metrics_ready_for_gate
      },
      mainnet_activation_gate: {
        status: $activation_status,
        rc: $activation_rc,
        command: $activation_command,
        started_at: (if $activation_started_at == "" then null else $activation_started_at end),
        completed_at: (if $activation_completed_at == "" then null else $activation_completed_at end),
        artifacts: {
          summary_json: $activation_summary_json,
          metrics_json: $metrics_json
        },
        decision: (if $activation_decision == "" then null else $activation_decision end)
      },
      bootstrap_graduation_gate: {
        status: $bootstrap_status,
        rc: $bootstrap_rc,
        command: $bootstrap_command,
        started_at: (if $bootstrap_started_at == "" then null else $bootstrap_started_at end),
        completed_at: (if $bootstrap_completed_at == "" then null else $bootstrap_completed_at end),
        artifacts: {
          summary_json: $bootstrap_summary_json,
          metrics_json: $metrics_json
        },
        decision: (if $bootstrap_decision == "" then null else $bootstrap_decision end)
      }
    },
    missing_required_metrics: $missing_required_metrics,
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      canonical_summary_json: $canonical_summary_json,
      blockchain_mainnet_activation_metrics_input_json: (if $blockchain_mainnet_activation_metrics_input_json == "" then null else $blockchain_mainnet_activation_metrics_input_json end),
      blockchain_mainnet_activation_metrics_input_summary_json: (if $blockchain_mainnet_activation_metrics_input_summary_json == "" then null else $blockchain_mainnet_activation_metrics_input_summary_json end),
      blockchain_mainnet_activation_metrics_input_canonical_json: (if $blockchain_mainnet_activation_metrics_input_canonical_json == "" then null else $blockchain_mainnet_activation_metrics_input_canonical_json end),
      metrics_json: $metrics_json,
      metrics_summary_json: $metrics_summary_json,
      activation_summary_json: $activation_summary_json,
      bootstrap_summary_json: $bootstrap_summary_json
    }
  }
  ' >"$summary_tmp"

mv -f "$summary_tmp" "$summary_json"

if [[ "$canonical_summary_json" == "$summary_json" ]]; then
  :
else
  cp -f "$summary_json" "$canonical_summary_json"
fi

echo "[blockchain-gate-bundle] status=$bundle_status decision=$bundle_decision rc=$bundle_rc"
echo "[blockchain-gate-bundle] summary_json=$summary_json canonical_summary_json=$canonical_summary_json"
echo "[blockchain-gate-bundle] missing_required_metrics=$(jq -r '.missing_required_metrics | if length == 0 then "none" else join(",") end' "$summary_json")"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$bundle_rc"
