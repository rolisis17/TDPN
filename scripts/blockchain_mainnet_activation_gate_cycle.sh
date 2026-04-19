#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/blockchain_mainnet_activation_gate_cycle.sh \
    [--input-json PATH] \
    [--seed-example-input [0|1]] \
    [--emit-missing-checklist [0|1]] \
    [--missing-checklist-json PATH] \
    [--missing-checklist-md PATH] \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--canonical-summary-json PATH] \
    [--refresh-roadmap [0|1]] \
    [--print-summary-json [0|1]] \
    [--print-output-json [0|1]]

Purpose:
  Run one deterministic blockchain activation-gate cycle:
    1) metrics input normalization
    2) gate bundle evaluation
    3) optional roadmap refresh

Execution:
  0) scripts/blockchain_mainnet_activation_metrics_input_template.sh (optional seed mode)
  1) scripts/blockchain_mainnet_activation_metrics_input.sh
  2) scripts/blockchain_gate_bundle.sh
  3) scripts/blockchain_mainnet_activation_metrics_missing_checklist.sh (optional; default enabled)
  4) scripts/roadmap_progress_report.sh (optional; default enabled)

Notes:
  - When --seed-example-input=1 and --input-json is omitted, the cycle seeds
    a deterministic example metrics input under reports dir and uses it for
    metrics normalization.
  - Logical NO-GO decisions remain fail-soft (cycle exits 0) when stage
    commands succeed.
  - Non-zero exit is reserved for usage/runtime failures in cycle stages.
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

is_nonempty_iso_utc() {
  local value
  value="$(trim "${1:-}")"
  [[ -n "$value" && "$value" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]
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

print_cmd() {
  local arg
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
  printf '\n'
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

json_array_or_empty() {
  local path="$1"
  local expr="$2"
  if [[ -z "$path" || ! -f "$path" ]]; then
    printf '%s' "[]"
    return
  fi
  jq -c "$expr" "$path" 2>/dev/null || printf '%s' "[]"
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

  echo "[blockchain-mainnet-activation-gate-cycle] step=${step_id} status=running"
  set +e
  "$@"
  rc=$?
  set -e

  completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  step_completed_at["$step_id"]="$completed_at"
  step_rc["$step_id"]="$rc"

  if (( rc == 0 )); then
    step_status["$step_id"]="pass"
    echo "[blockchain-mainnet-activation-gate-cycle] step=${step_id} status=pass rc=0"
  else
    step_status["$step_id"]="fail"
    echo "[blockchain-mainnet-activation-gate-cycle] step=${step_id} status=fail rc=${rc}"
  fi
}

need_cmd jq
need_cmd date
need_cmd cp
need_cmd mktemp

input_json="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_INPUT_JSON:-}"
reports_dir="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs/blockchain_mainnet_activation_gate_cycle}"
summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_SUMMARY_JSON:-}"
canonical_summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_CANONICAL_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/blockchain_mainnet_activation_gate_cycle_summary.json}"
refresh_roadmap="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_REFRESH_ROADMAP:-1}"
print_summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_PRINT_SUMMARY_JSON:-1}"
seed_example_input="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_SEED_EXAMPLE_INPUT:-0}"
emit_missing_checklist="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_EMIT_MISSING_CHECKLIST:-1}"
missing_checklist_json="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_MISSING_CHECKLIST_JSON:-}"
missing_checklist_md="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_MISSING_CHECKLIST_MD:-}"

metrics_input_script="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_METRICS_INPUT_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics_input.sh}"
metrics_input_template_script="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_METRICS_INPUT_TEMPLATE_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics_input_template.sh}"
gate_bundle_script="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_GATE_BUNDLE_SCRIPT:-$ROOT_DIR/scripts/blockchain_gate_bundle.sh}"
metrics_missing_checklist_script="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_METRICS_MISSING_CHECKLIST_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics_missing_checklist.sh}"
roadmap_progress_report_script="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_ROADMAP_PROGRESS_REPORT_SCRIPT:-$ROOT_DIR/scripts/roadmap_progress_report.sh}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --input-json)
      path_arg_or_die "--input-json" "${2:-}"
      input_json="${2:-}"
      shift 2
      ;;
    --seed-example-input)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        seed_example_input="${2:-}"
        shift 2
      else
        seed_example_input="1"
        shift
      fi
      ;;
    --emit-missing-checklist)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        emit_missing_checklist="${2:-}"
        shift 2
      else
        emit_missing_checklist="1"
        shift
      fi
      ;;
    --missing-checklist-json)
      path_arg_or_die "--missing-checklist-json" "${2:-}"
      missing_checklist_json="${2:-}"
      shift 2
      ;;
    --missing-checklist-md)
      path_arg_or_die "--missing-checklist-md" "${2:-}"
      missing_checklist_md="${2:-}"
      shift 2
      ;;
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
    --refresh-roadmap)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        refresh_roadmap="${2:-}"
        shift 2
      else
        refresh_roadmap="1"
        shift
      fi
      ;;
    --print-summary-json|--print-output-json)
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

if [[ -z "$(trim "$input_json")" && "$seed_example_input" != "1" ]]; then
  echo "--input-json is required unless --seed-example-input=1"
  usage
  exit 2
fi

bool_arg_or_die "--refresh-roadmap" "$refresh_roadmap"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--seed-example-input" "$seed_example_input"
bool_arg_or_die "--emit-missing-checklist" "$emit_missing_checklist"

if [[ -n "$(trim "$input_json")" ]]; then
  path_arg_or_die "--input-json" "$input_json"
fi
path_arg_or_die "--reports-dir" "$reports_dir"
path_arg_or_die "--canonical-summary-json" "$canonical_summary_json"

if [[ ! -x "$metrics_input_script" ]]; then
  echo "missing executable stage script: $metrics_input_script"
  exit 2
fi
if [[ "$seed_example_input" == "1" && -z "$(trim "$input_json")" && ! -x "$metrics_input_template_script" ]]; then
  echo "missing executable stage script: $metrics_input_template_script"
  exit 2
fi
if [[ ! -x "$gate_bundle_script" ]]; then
  echo "missing executable stage script: $gate_bundle_script"
  exit 2
fi
if [[ "$emit_missing_checklist" == "1" && ! -x "$metrics_missing_checklist_script" ]]; then
  echo "missing executable stage script: $metrics_missing_checklist_script"
  exit 2
fi
if [[ "$refresh_roadmap" == "1" && ! -x "$roadmap_progress_report_script" ]]; then
  echo "missing executable stage script: $roadmap_progress_report_script"
  exit 2
fi

if [[ -n "$(trim "$input_json")" ]]; then
  input_json="$(abs_path "$input_json")"
fi
reports_dir="$(abs_path "$reports_dir")"
canonical_summary_json="$(abs_path "$canonical_summary_json")"

mkdir -p "$reports_dir"
mkdir -p "$(dirname "$canonical_summary_json")"

if [[ -z "$(trim "$summary_json")" ]]; then
  summary_json="$reports_dir/blockchain_mainnet_activation_gate_cycle_summary.json"
fi
summary_json="$(abs_path "$summary_json")"
mkdir -p "$(dirname "$summary_json")"

metrics_input_summary_json="$reports_dir/blockchain_mainnet_activation_metrics_input_summary.json"
metrics_input_canonical_json="$reports_dir/blockchain_mainnet_activation_metrics_input.json"
seeded_input_json="$reports_dir/blockchain_mainnet_activation_metrics_input.seed.json"
metrics_input_template_summary_json="$seeded_input_json"
metrics_input_template_canonical_json="$reports_dir/blockchain_mainnet_activation_metrics_input.seed.canonical.json"
bundle_summary_json="$reports_dir/blockchain_gate_bundle_summary.json"
bundle_canonical_summary_json="$reports_dir/blockchain_gate_bundle_canonical_summary.json"
bundle_metrics_json="$reports_dir/blockchain_mainnet_activation_metrics.json"
bundle_metrics_summary_json="$reports_dir/blockchain_mainnet_activation_metrics_summary.json"
bundle_activation_summary_json="$reports_dir/blockchain_mainnet_activation_gate_summary.json"
bundle_bootstrap_summary_json="$reports_dir/blockchain_bootstrap_governance_graduation_gate_summary.json"
if [[ -z "$(trim "$missing_checklist_json")" ]]; then
  missing_checklist_json="$reports_dir/blockchain_mainnet_activation_metrics_missing_checklist.json"
fi
if [[ -z "$(trim "$missing_checklist_md")" ]]; then
  missing_checklist_md="$reports_dir/blockchain_mainnet_activation_metrics_missing_checklist.md"
fi
if [[ -n "$(trim "$missing_checklist_json")" ]]; then
  path_arg_or_die "--missing-checklist-json" "$missing_checklist_json"
  missing_checklist_json="$(abs_path "$missing_checklist_json")"
fi
if [[ -n "$(trim "$missing_checklist_md")" ]]; then
  path_arg_or_die "--missing-checklist-md" "$missing_checklist_md"
  missing_checklist_md="$(abs_path "$missing_checklist_md")"
fi
roadmap_summary_json="$reports_dir/roadmap_progress_summary.json"
roadmap_report_md="$reports_dir/roadmap_progress_report.md"

step_ids=("metrics_input_template" "metrics_input" "gate_bundle" "missing_metrics_checklist" "roadmap_refresh")

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

seeded_input_active="0"
if [[ "$seed_example_input" == "1" && -z "$(trim "$input_json")" ]]; then
  seeded_input_active="1"
else
  step_status["metrics_input_template"]="skipped"
fi

if [[ "$refresh_roadmap" == "0" ]]; then
  step_status["roadmap_refresh"]="skipped"
fi
if [[ "$emit_missing_checklist" == "0" ]]; then
  step_status["missing_metrics_checklist"]="skipped"
fi

run_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
run_started_epoch="$(date -u +%s)"
activation_summary_generated_at=""
bootstrap_summary_generated_at=""
gate_summary_generated_at_validation_status="skipped"
gate_summary_generated_at_validation_rc=41

if [[ "$seeded_input_active" == "1" ]]; then
  metrics_input_template_cmd=(
    bash "$metrics_input_template_script"
    --output-json "$metrics_input_template_summary_json"
    --canonical-output-json "$metrics_input_template_canonical_json"
    --include-example-values 1
    --print-output-json 0
  )
  run_step "metrics_input_template" "${metrics_input_template_cmd[@]}"
  if [[ "${step_status[metrics_input_template]}" == "pass" ]]; then
    input_json="$seeded_input_json"
  fi
fi

metrics_input_cmd=(
  bash "$metrics_input_script"
  --input-json "$input_json"
  --summary-json "$metrics_input_summary_json"
  --canonical-summary-json "$metrics_input_canonical_json"
  --print-summary-json 0
)
if [[ "$seeded_input_active" == "0" || "${step_status[metrics_input_template]}" == "pass" ]]; then
  run_step "metrics_input" "${metrics_input_cmd[@]}"
else
  step_status["metrics_input"]="skipped"
fi

gate_bundle_cmd=(
  bash "$gate_bundle_script"
  --reports-dir "$reports_dir"
  --summary-json "$bundle_summary_json"
  --canonical-summary-json "$bundle_canonical_summary_json"
  --metrics-json "$bundle_metrics_json"
  --metrics-summary-json "$bundle_metrics_summary_json"
  --blockchain-mainnet-activation-metrics-input-json "$input_json"
  --blockchain-mainnet-activation-metrics-input-summary-json "$metrics_input_summary_json"
  --blockchain-mainnet-activation-metrics-input-canonical-json "$metrics_input_canonical_json"
  --activation-summary-json "$bundle_activation_summary_json"
  --bootstrap-summary-json "$bundle_bootstrap_summary_json"
  --print-summary-json 0
)

if [[ "${step_status[metrics_input]}" == "pass" ]]; then
  run_step "gate_bundle" "${gate_bundle_cmd[@]}"
else
  step_status["gate_bundle"]="skipped"
fi

if [[ "${step_status[gate_bundle]}" == "pass" ]]; then
  gate_summary_generated_at_validation_status="pass"
  activation_summary_generated_at="$(trim "$(json_text_or_empty "$bundle_activation_summary_json" '.generated_at')")"
  bootstrap_summary_generated_at="$(trim "$(json_text_or_empty "$bundle_bootstrap_summary_json" '.generated_at')")"

  if ! is_nonempty_iso_utc "$activation_summary_generated_at"; then
    gate_summary_generated_at_validation_status="fail"
    echo "[blockchain-mainnet-activation-gate-cycle] step=gate_bundle status=fail reason=activation_summary_generated_at_invalid summary_json=$bundle_activation_summary_json value=${activation_summary_generated_at:-empty}"
  fi
  if ! is_nonempty_iso_utc "$bootstrap_summary_generated_at"; then
    gate_summary_generated_at_validation_status="fail"
    echo "[blockchain-mainnet-activation-gate-cycle] step=gate_bundle status=fail reason=bootstrap_summary_generated_at_invalid summary_json=$bundle_bootstrap_summary_json value=${bootstrap_summary_generated_at:-empty}"
  fi

  if [[ "$gate_summary_generated_at_validation_status" == "fail" ]]; then
    step_status["gate_bundle"]="fail"
    step_rc["gate_bundle"]="$gate_summary_generated_at_validation_rc"
    echo "[blockchain-mainnet-activation-gate-cycle] step=gate_bundle status=fail rc=$gate_summary_generated_at_validation_rc reason=gate_summary_generated_at_contract"
  fi
fi

if [[ "$emit_missing_checklist" == "1" ]]; then
  missing_metrics_checklist_cmd=(
    bash "$metrics_missing_checklist_script"
    --metrics-summary-json "$bundle_metrics_summary_json"
    --output-json "$missing_checklist_json"
    --output-md "$missing_checklist_md"
    --print-output-json 0
  )

  if [[ "${step_status[gate_bundle]}" == "pass" ]]; then
    run_step "missing_metrics_checklist" "${missing_metrics_checklist_cmd[@]}"
  else
    step_status["missing_metrics_checklist"]="skipped"
  fi
fi

if [[ "$refresh_roadmap" == "1" ]]; then
  roadmap_cmd=(
    bash "$roadmap_progress_report_script"
    --refresh-manual-validation 0
    --refresh-single-machine-readiness 0
    --summary-json "$roadmap_summary_json"
    --report-md "$roadmap_report_md"
    --blockchain-mainnet-activation-gate-summary-json "$bundle_activation_summary_json"
    --blockchain-bootstrap-governance-graduation-gate-summary-json "$bundle_bootstrap_summary_json"
    --print-report 0
    --print-summary-json 0
  )

  if [[ "${step_status[gate_bundle]}" == "pass" ]]; then
    run_step "roadmap_refresh" "${roadmap_cmd[@]}"
  else
    step_status["roadmap_refresh"]="skipped"
  fi
fi

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

cycle_status="pass"
cycle_rc=0
if [[ -n "$first_runtime_failure_step" ]]; then
  cycle_status="runtime-fail"
  cycle_rc="$first_runtime_failure_rc"
fi

bundle_status="$(json_text_or_empty "$bundle_summary_json" '.status')"
bundle_decision="$(json_text_or_empty "$bundle_summary_json" '.decision')"
bundle_rc_json_raw="$(json_text_or_empty "$bundle_summary_json" '.rc')"
bundle_missing_required_metrics_json="$(json_array_or_empty "$bundle_summary_json" '(.missing_required_metrics // []) | if type == "array" then . else [] end')"
missing_metrics_checklist_observed_json=""
if [[ "$emit_missing_checklist" == "1" && "${step_status[missing_metrics_checklist]}" != "skipped" ]]; then
  missing_metrics_checklist_observed_json="$missing_checklist_json"
fi
missing_metrics_checklist_status="$(json_text_or_empty "$missing_metrics_checklist_observed_json" '.status')"
missing_metrics_checklist_missing_count_raw="$(json_text_or_empty "$missing_metrics_checklist_observed_json" '.missing_count')"
missing_metrics_checklist_missing_keys_json="$(json_array_or_empty "$missing_metrics_checklist_observed_json" 'if (.missing_keys? | type) == "array" then .missing_keys elif (.checklist? | type) == "array" then [.checklist[]? | .key?] else [] end | map(select(type == "string" and length > 0))')"

if [[ ! "$bundle_rc_json_raw" =~ ^-?[0-9]+$ ]]; then
  bundle_rc_json_raw="null"
fi
if [[ ! "$missing_metrics_checklist_missing_count_raw" =~ ^-?[0-9]+$ ]]; then
  missing_metrics_checklist_missing_count_raw="$(jq -n --argjson missing_keys "$missing_metrics_checklist_missing_keys_json" '$missing_keys | length')"
fi

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
cleanup() {
  rm -f "$summary_tmp"
}
trap cleanup EXIT

jq -n \
  --arg generated_at "$run_completed_at" \
  --arg started_at "$run_started_at" \
  --arg completed_at "$run_completed_at" \
  --arg status "$cycle_status" \
  --arg decision "$bundle_decision" \
  --argjson rc "$cycle_rc" \
  --arg input_json "$input_json" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg canonical_summary_json "$canonical_summary_json" \
  --arg metrics_input_summary_json "$metrics_input_summary_json" \
  --arg metrics_input_canonical_json "$metrics_input_canonical_json" \
  --arg bundle_summary_json "$bundle_summary_json" \
  --arg bundle_canonical_summary_json "$bundle_canonical_summary_json" \
  --arg bundle_metrics_json "$bundle_metrics_json" \
  --arg bundle_metrics_summary_json "$bundle_metrics_summary_json" \
  --arg bundle_activation_summary_json "$bundle_activation_summary_json" \
  --arg bundle_bootstrap_summary_json "$bundle_bootstrap_summary_json" \
  --arg roadmap_summary_json "$roadmap_summary_json" \
  --arg roadmap_report_md "$roadmap_report_md" \
  --arg metrics_input_template_summary_json "$metrics_input_template_summary_json" \
  --arg metrics_input_template_canonical_json "$metrics_input_template_canonical_json" \
  --arg seeded_input_json "$seeded_input_json" \
  --arg missing_checklist_json "$missing_checklist_json" \
  --arg missing_checklist_md "$missing_checklist_md" \
  --argjson refresh_roadmap "$( [[ "$refresh_roadmap" == "1" ]] && echo true || echo false )" \
  --argjson print_summary_json "$( [[ "$print_summary_json" == "1" ]] && echo true || echo false )" \
  --argjson seed_example_input "$( [[ "$seed_example_input" == "1" ]] && echo true || echo false )" \
  --argjson seeded_input_active "$( [[ "$seeded_input_active" == "1" ]] && echo true || echo false )" \
  --argjson emit_missing_checklist "$( [[ "$emit_missing_checklist" == "1" ]] && echo true || echo false )" \
  --argjson duration_sec "$run_duration_sec" \
  --arg first_runtime_failure_step "$first_runtime_failure_step" \
  --argjson first_runtime_failure_rc "$first_runtime_failure_rc" \
  --arg bundle_status "$bundle_status" \
  --arg bundle_decision "$bundle_decision" \
  --argjson bundle_rc "$bundle_rc_json_raw" \
  --argjson bundle_missing_required_metrics "$bundle_missing_required_metrics_json" \
  --arg missing_metrics_checklist_status "$missing_metrics_checklist_status" \
  --argjson missing_metrics_checklist_missing_count "$missing_metrics_checklist_missing_count_raw" \
  --argjson missing_metrics_checklist_missing_keys "$missing_metrics_checklist_missing_keys_json" \
  --arg activation_summary_generated_at "$activation_summary_generated_at" \
  --arg bootstrap_summary_generated_at "$bootstrap_summary_generated_at" \
  --arg gate_summary_generated_at_validation_status "$gate_summary_generated_at_validation_status" \
  --arg metrics_input_template_status "${step_status[metrics_input_template]}" \
  --argjson metrics_input_template_rc "${step_rc[metrics_input_template]}" \
  --arg metrics_input_template_command "${step_command[metrics_input_template]}" \
  --arg metrics_input_template_started_at "${step_started_at[metrics_input_template]}" \
  --arg metrics_input_template_completed_at "${step_completed_at[metrics_input_template]}" \
  --arg metrics_input_status "${step_status[metrics_input]}" \
  --argjson metrics_input_rc "${step_rc[metrics_input]}" \
  --arg metrics_input_command "${step_command[metrics_input]}" \
  --arg metrics_input_started_at "${step_started_at[metrics_input]}" \
  --arg metrics_input_completed_at "${step_completed_at[metrics_input]}" \
  --arg gate_bundle_status "${step_status[gate_bundle]}" \
  --argjson gate_bundle_rc "${step_rc[gate_bundle]}" \
  --arg gate_bundle_command "${step_command[gate_bundle]}" \
  --arg gate_bundle_started_at "${step_started_at[gate_bundle]}" \
  --arg gate_bundle_completed_at "${step_completed_at[gate_bundle]}" \
  --arg missing_metrics_checklist_step_status "${step_status[missing_metrics_checklist]}" \
  --argjson missing_metrics_checklist_step_rc "${step_rc[missing_metrics_checklist]}" \
  --arg missing_metrics_checklist_step_command "${step_command[missing_metrics_checklist]}" \
  --arg missing_metrics_checklist_step_started_at "${step_started_at[missing_metrics_checklist]}" \
  --arg missing_metrics_checklist_step_completed_at "${step_completed_at[missing_metrics_checklist]}" \
  --arg roadmap_refresh_status "${step_status[roadmap_refresh]}" \
  --argjson roadmap_refresh_rc "${step_rc[roadmap_refresh]}" \
  --arg roadmap_refresh_command "${step_command[roadmap_refresh]}" \
  --arg roadmap_refresh_started_at "${step_started_at[roadmap_refresh]}" \
  --arg roadmap_refresh_completed_at "${step_completed_at[roadmap_refresh]}" \
  '
  {
    schema: {
      id: "blockchain_mainnet_activation_gate_cycle_summary",
      version: "1.0.0"
    },
    generated_at: $generated_at,
    started_at: $started_at,
    completed_at: $completed_at,
    duration_sec: $duration_sec,
    status: $status,
    decision: (if $gate_summary_generated_at_validation_status == "fail" or $bundle_decision == "" then "UNKNOWN" else $bundle_decision end),
    rc: $rc,
    first_runtime_failure: {
      step: (if $first_runtime_failure_step == "" then null else $first_runtime_failure_step end),
      rc: (if $first_runtime_failure_step == "" then null else $first_runtime_failure_rc end)
    },
    inputs: {
      input_json: $input_json,
      seed_example_input: $seed_example_input,
      emit_missing_checklist: $emit_missing_checklist,
      refresh_roadmap: $refresh_roadmap,
      print_summary_json: $print_summary_json
    },
    steps: {
      metrics_input_template: {
        enabled: $seeded_input_active,
        status: $metrics_input_template_status,
        rc: $metrics_input_template_rc,
        command: $metrics_input_template_command,
        started_at: (if $metrics_input_template_started_at == "" then null else $metrics_input_template_started_at end),
        completed_at: (if $metrics_input_template_completed_at == "" then null else $metrics_input_template_completed_at end),
        artifacts: {
          summary_json: (if $seeded_input_active then $metrics_input_template_summary_json else null end),
          canonical_summary_json: (if $seeded_input_active then $metrics_input_template_canonical_json else null end),
          seeded_input_json: (if $seeded_input_active then $seeded_input_json else null end)
        }
      },
      metrics_input: {
        status: $metrics_input_status,
        rc: $metrics_input_rc,
        command: $metrics_input_command,
        started_at: (if $metrics_input_started_at == "" then null else $metrics_input_started_at end),
        completed_at: (if $metrics_input_completed_at == "" then null else $metrics_input_completed_at end),
        artifacts: {
          summary_json: $metrics_input_summary_json,
          canonical_summary_json: $metrics_input_canonical_json
        }
      },
      gate_bundle: {
        status: $gate_bundle_status,
        rc: $gate_bundle_rc,
        command: $gate_bundle_command,
        started_at: (if $gate_bundle_started_at == "" then null else $gate_bundle_started_at end),
        completed_at: (if $gate_bundle_completed_at == "" then null else $gate_bundle_completed_at end),
        decision: (if $gate_summary_generated_at_validation_status == "fail" or $bundle_decision == "" then null else $bundle_decision end),
        bundle_status: (if $bundle_status == "" then null else $bundle_status end),
        bundle_rc: $bundle_rc,
        missing_required_metrics: $bundle_missing_required_metrics,
        activation_summary_generated_at: (if $activation_summary_generated_at == "" then null else $activation_summary_generated_at end),
        bootstrap_summary_generated_at: (if $bootstrap_summary_generated_at == "" then null else $bootstrap_summary_generated_at end),
        gate_summary_generated_at_contract: {
          status: $gate_summary_generated_at_validation_status,
          requires_nonempty_iso_utc: true
        },
        artifacts: {
          summary_json: $bundle_summary_json,
          canonical_summary_json: $bundle_canonical_summary_json,
          metrics_json: $bundle_metrics_json,
          metrics_summary_json: $bundle_metrics_summary_json,
          activation_summary_json: $bundle_activation_summary_json,
          bootstrap_summary_json: $bundle_bootstrap_summary_json
        }
      },
      missing_metrics_checklist: {
        enabled: $emit_missing_checklist,
        status: $missing_metrics_checklist_step_status,
        rc: $missing_metrics_checklist_step_rc,
        command: $missing_metrics_checklist_step_command,
        started_at: (if $missing_metrics_checklist_step_started_at == "" then null else $missing_metrics_checklist_step_started_at end),
        completed_at: (if $missing_metrics_checklist_step_completed_at == "" then null else $missing_metrics_checklist_step_completed_at end),
        checklist_status: (if $missing_metrics_checklist_status == "" then null else $missing_metrics_checklist_status end),
        missing_count: (if $emit_missing_checklist then $missing_metrics_checklist_missing_count else null end),
        missing_keys: (if $emit_missing_checklist then $missing_metrics_checklist_missing_keys else [] end),
        artifacts: {
          checklist_json: (if $emit_missing_checklist then $missing_checklist_json else null end),
          checklist_md: (if $emit_missing_checklist then $missing_checklist_md else null end)
        }
      },
      roadmap_refresh: {
        enabled: $refresh_roadmap,
        status: $roadmap_refresh_status,
        rc: $roadmap_refresh_rc,
        command: $roadmap_refresh_command,
        started_at: (if $roadmap_refresh_started_at == "" then null else $roadmap_refresh_started_at end),
        completed_at: (if $roadmap_refresh_completed_at == "" then null else $roadmap_refresh_completed_at end),
        artifacts: {
          summary_json: (if $refresh_roadmap then $roadmap_summary_json else null end),
          report_md: (if $refresh_roadmap then $roadmap_report_md else null end)
        }
      }
    },
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      canonical_summary_json: $canonical_summary_json,
      seeded_input_json: (if $seeded_input_active then $seeded_input_json else null end),
      metrics_input_template_summary_json: (if $seeded_input_active then $metrics_input_template_summary_json else null end),
      metrics_input_template_canonical_json: (if $seeded_input_active then $metrics_input_template_canonical_json else null end),
      metrics_input_summary_json: $metrics_input_summary_json,
      metrics_input_canonical_json: $metrics_input_canonical_json,
      bundle_summary_json: $bundle_summary_json,
      bundle_canonical_summary_json: $bundle_canonical_summary_json,
      bundle_metrics_json: $bundle_metrics_json,
      bundle_metrics_summary_json: $bundle_metrics_summary_json,
      bundle_activation_summary_json: $bundle_activation_summary_json,
      bundle_bootstrap_summary_json: $bundle_bootstrap_summary_json,
      missing_metrics_checklist_json: (if $emit_missing_checklist then $missing_checklist_json else null end),
      missing_metrics_checklist_md: (if $emit_missing_checklist then $missing_checklist_md else null end),
      roadmap_summary_json: (if $refresh_roadmap then $roadmap_summary_json else null end),
      roadmap_report_md: (if $refresh_roadmap then $roadmap_report_md else null end)
    }
  }
  ' >"$summary_tmp"

mv -f "$summary_tmp" "$summary_json"

if [[ "$canonical_summary_json" == "$summary_json" ]]; then
  :
else
  cp -f "$summary_json" "$canonical_summary_json"
fi

echo "[blockchain-mainnet-activation-gate-cycle] status=$cycle_status decision=${bundle_decision:-UNKNOWN} rc=$cycle_rc"
echo "[blockchain-mainnet-activation-gate-cycle] summary_json=$summary_json canonical_summary_json=$canonical_summary_json"
echo "[blockchain-mainnet-activation-gate-cycle] bundle_summary_json=$bundle_summary_json missing_required_metrics=$(jq -r '.steps.gate_bundle.missing_required_metrics | if length == 0 then "none" else join(",") end' "$summary_json")"
echo "[blockchain-mainnet-activation-gate-cycle] missing_metrics_checklist_status=$(jq -r '.steps.missing_metrics_checklist.checklist_status // "none"' "$summary_json") missing_count=$(jq -r '.steps.missing_metrics_checklist.missing_count // 0' "$summary_json") missing_keys=$(jq -r '.steps.missing_metrics_checklist.missing_keys | if length == 0 then "none" else join(",") end' "$summary_json")"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$cycle_rc"
