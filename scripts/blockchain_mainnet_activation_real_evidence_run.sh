#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/blockchain_mainnet_activation_real_evidence_run.sh \
    --input-json PATH \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--canonical-summary-json PATH] \
    [--template-output-json PATH] \
    [--template-canonical-output-json PATH] \
    [--missing-checklist-json PATH] \
    [--missing-checklist-md PATH] \
    [--gate-cycle-reports-dir DIR] \
    [--gate-cycle-summary-json PATH] \
    [--gate-cycle-canonical-summary-json PATH] \
    [--operator-pack-reports-dir DIR] \
    [--operator-pack-summary-json PATH] \
    [--operator-pack-canonical-summary-json PATH] \
    [--refresh-roadmap [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Run one deterministic, operator-friendly blockchain activation evidence flow
  for real (non-seeded) input JSON files:
    1) scripts/blockchain_mainnet_activation_metrics_input_template.sh
    2) scripts/blockchain_mainnet_activation_gate_cycle.sh (seed disabled)
    3) scripts/blockchain_mainnet_activation_metrics_missing_checklist.sh
    4) scripts/blockchain_mainnet_activation_operator_pack.sh

Notes:
  - This helper intentionally requires --input-json and always forwards
    --seed-example-input 0 to gate-cycle.
  - Gate thresholds remain unchanged because this helper only orchestrates
    existing scripts and paths.
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

  echo "[blockchain-mainnet-activation-real-evidence] step=${step_id} status=running"
  set +e
  "$@"
  rc=$?
  set -e

  completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  step_completed_at["$step_id"]="$completed_at"
  step_rc["$step_id"]="$rc"

  if (( rc == 0 )); then
    step_status["$step_id"]="pass"
    echo "[blockchain-mainnet-activation-real-evidence] step=${step_id} status=pass rc=0"
  else
    step_status["$step_id"]="fail"
    echo "[blockchain-mainnet-activation-real-evidence] step=${step_id} status=fail rc=${rc}"
  fi
}

need_cmd jq
need_cmd date
need_cmd cp
need_cmd mktemp

input_json="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_INPUT_JSON:-}"
reports_dir="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs/blockchain_mainnet_activation_real_evidence}"
summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_SUMMARY_JSON:-}"
canonical_summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_CANONICAL_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/blockchain_mainnet_activation_real_evidence_summary.json}"
print_summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_PRINT_SUMMARY_JSON:-1}"
refresh_roadmap="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_REFRESH_ROADMAP:-1}"

template_output_json="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_TEMPLATE_OUTPUT_JSON:-}"
template_canonical_output_json="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_TEMPLATE_CANONICAL_OUTPUT_JSON:-}"
missing_checklist_json="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_MISSING_CHECKLIST_JSON:-}"
missing_checklist_md="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_MISSING_CHECKLIST_MD:-}"

gate_cycle_reports_dir="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_GATE_CYCLE_REPORTS_DIR:-}"
gate_cycle_summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_GATE_CYCLE_SUMMARY_JSON:-}"
gate_cycle_canonical_summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_GATE_CYCLE_CANONICAL_SUMMARY_JSON:-}"

operator_pack_reports_dir="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_OPERATOR_PACK_REPORTS_DIR:-}"
operator_pack_summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_OPERATOR_PACK_SUMMARY_JSON:-}"
operator_pack_canonical_summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_OPERATOR_PACK_CANONICAL_SUMMARY_JSON:-}"

template_script="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_TEMPLATE_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics_input_template.sh}"
gate_cycle_script="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_GATE_CYCLE_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_gate_cycle.sh}"
missing_checklist_script="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_MISSING_CHECKLIST_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics_missing_checklist.sh}"
operator_pack_script="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_OPERATOR_PACK_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_operator_pack.sh}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --input-json)
      path_arg_or_die "--input-json" "${2:-}"
      input_json="${2:-}"
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
    --template-output-json)
      path_arg_or_die "--template-output-json" "${2:-}"
      template_output_json="${2:-}"
      shift 2
      ;;
    --template-canonical-output-json)
      path_arg_or_die "--template-canonical-output-json" "${2:-}"
      template_canonical_output_json="${2:-}"
      shift 2
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
    --gate-cycle-reports-dir)
      path_arg_or_die "--gate-cycle-reports-dir" "${2:-}"
      gate_cycle_reports_dir="${2:-}"
      shift 2
      ;;
    --gate-cycle-summary-json)
      path_arg_or_die "--gate-cycle-summary-json" "${2:-}"
      gate_cycle_summary_json="${2:-}"
      shift 2
      ;;
    --gate-cycle-canonical-summary-json)
      path_arg_or_die "--gate-cycle-canonical-summary-json" "${2:-}"
      gate_cycle_canonical_summary_json="${2:-}"
      shift 2
      ;;
    --operator-pack-reports-dir)
      path_arg_or_die "--operator-pack-reports-dir" "${2:-}"
      operator_pack_reports_dir="${2:-}"
      shift 2
      ;;
    --operator-pack-summary-json)
      path_arg_or_die "--operator-pack-summary-json" "${2:-}"
      operator_pack_summary_json="${2:-}"
      shift 2
      ;;
    --operator-pack-canonical-summary-json)
      path_arg_or_die "--operator-pack-canonical-summary-json" "${2:-}"
      operator_pack_canonical_summary_json="${2:-}"
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

if [[ -z "$(trim "$input_json")" ]]; then
  echo "--input-json is required"
  usage
  exit 2
fi

path_arg_or_die "--input-json" "$input_json"
path_arg_or_die "--reports-dir" "$reports_dir"
path_arg_or_die "--canonical-summary-json" "$canonical_summary_json"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--refresh-roadmap" "$refresh_roadmap"

if [[ -n "$(trim "$summary_json")" ]]; then
  path_arg_or_die "--summary-json" "$summary_json"
fi
if [[ -n "$(trim "$template_output_json")" ]]; then
  path_arg_or_die "--template-output-json" "$template_output_json"
fi
if [[ -n "$(trim "$template_canonical_output_json")" ]]; then
  path_arg_or_die "--template-canonical-output-json" "$template_canonical_output_json"
fi
if [[ -n "$(trim "$missing_checklist_json")" ]]; then
  path_arg_or_die "--missing-checklist-json" "$missing_checklist_json"
fi
if [[ -n "$(trim "$missing_checklist_md")" ]]; then
  path_arg_or_die "--missing-checklist-md" "$missing_checklist_md"
fi
if [[ -n "$(trim "$gate_cycle_reports_dir")" ]]; then
  path_arg_or_die "--gate-cycle-reports-dir" "$gate_cycle_reports_dir"
fi
if [[ -n "$(trim "$gate_cycle_summary_json")" ]]; then
  path_arg_or_die "--gate-cycle-summary-json" "$gate_cycle_summary_json"
fi
if [[ -n "$(trim "$gate_cycle_canonical_summary_json")" ]]; then
  path_arg_or_die "--gate-cycle-canonical-summary-json" "$gate_cycle_canonical_summary_json"
fi
if [[ -n "$(trim "$operator_pack_reports_dir")" ]]; then
  path_arg_or_die "--operator-pack-reports-dir" "$operator_pack_reports_dir"
fi
if [[ -n "$(trim "$operator_pack_summary_json")" ]]; then
  path_arg_or_die "--operator-pack-summary-json" "$operator_pack_summary_json"
fi
if [[ -n "$(trim "$operator_pack_canonical_summary_json")" ]]; then
  path_arg_or_die "--operator-pack-canonical-summary-json" "$operator_pack_canonical_summary_json"
fi

if [[ ! -x "$template_script" ]]; then
  echo "missing executable stage script: $template_script"
  exit 2
fi
if [[ ! -x "$gate_cycle_script" ]]; then
  echo "missing executable stage script: $gate_cycle_script"
  exit 2
fi
if [[ ! -x "$missing_checklist_script" ]]; then
  echo "missing executable stage script: $missing_checklist_script"
  exit 2
fi
if [[ ! -x "$operator_pack_script" ]]; then
  echo "missing executable stage script: $operator_pack_script"
  exit 2
fi

input_json="$(abs_path "$input_json")"
reports_dir="$(abs_path "$reports_dir")"
canonical_summary_json="$(abs_path "$canonical_summary_json")"

if [[ -z "$(trim "$summary_json")" ]]; then
  summary_json="$reports_dir/blockchain_mainnet_activation_real_evidence_summary.json"
fi
summary_json="$(abs_path "$summary_json")"

if [[ -z "$(trim "$gate_cycle_reports_dir")" ]]; then
  gate_cycle_reports_dir="$reports_dir/gate_cycle"
fi
gate_cycle_reports_dir="$(abs_path "$gate_cycle_reports_dir")"

if [[ -z "$(trim "$operator_pack_reports_dir")" ]]; then
  operator_pack_reports_dir="$reports_dir/operator_pack"
fi
operator_pack_reports_dir="$(abs_path "$operator_pack_reports_dir")"

if [[ -z "$(trim "$gate_cycle_summary_json")" ]]; then
  gate_cycle_summary_json="$gate_cycle_reports_dir/blockchain_mainnet_activation_gate_cycle_summary.json"
fi
gate_cycle_summary_json="$(abs_path "$gate_cycle_summary_json")"

if [[ -z "$(trim "$gate_cycle_canonical_summary_json")" ]]; then
  gate_cycle_canonical_summary_json="$gate_cycle_reports_dir/blockchain_mainnet_activation_gate_cycle_summary.canonical.json"
fi
gate_cycle_canonical_summary_json="$(abs_path "$gate_cycle_canonical_summary_json")"

if [[ -z "$(trim "$operator_pack_summary_json")" ]]; then
  operator_pack_summary_json="$operator_pack_reports_dir/blockchain_mainnet_activation_operator_pack_summary.json"
fi
operator_pack_summary_json="$(abs_path "$operator_pack_summary_json")"

if [[ -z "$(trim "$operator_pack_canonical_summary_json")" ]]; then
  operator_pack_canonical_summary_json="$operator_pack_reports_dir/blockchain_mainnet_activation_operator_pack_summary.canonical.json"
fi
operator_pack_canonical_summary_json="$(abs_path "$operator_pack_canonical_summary_json")"

if [[ -z "$(trim "$template_output_json")" ]]; then
  template_output_json="$reports_dir/blockchain_mainnet_activation_metrics_input_template.json"
fi
template_output_json="$(abs_path "$template_output_json")"

if [[ -z "$(trim "$template_canonical_output_json")" ]]; then
  template_canonical_output_json="$reports_dir/blockchain_mainnet_activation_metrics_input_template.canonical.json"
fi
template_canonical_output_json="$(abs_path "$template_canonical_output_json")"

if [[ -z "$(trim "$missing_checklist_json")" ]]; then
  missing_checklist_json="$reports_dir/blockchain_mainnet_activation_metrics_missing_checklist.json"
fi
missing_checklist_json="$(abs_path "$missing_checklist_json")"

if [[ -z "$(trim "$missing_checklist_md")" ]]; then
  missing_checklist_md="$reports_dir/blockchain_mainnet_activation_metrics_missing_checklist.md"
fi
missing_checklist_md="$(abs_path "$missing_checklist_md")"

mkdir -p "$reports_dir"
mkdir -p "$gate_cycle_reports_dir"
mkdir -p "$operator_pack_reports_dir"
mkdir -p "$(dirname "$summary_json")"
mkdir -p "$(dirname "$canonical_summary_json")"
mkdir -p "$(dirname "$template_output_json")"
mkdir -p "$(dirname "$template_canonical_output_json")"
mkdir -p "$(dirname "$missing_checklist_json")"
mkdir -p "$(dirname "$missing_checklist_md")"
mkdir -p "$(dirname "$gate_cycle_summary_json")"
mkdir -p "$(dirname "$gate_cycle_canonical_summary_json")"
mkdir -p "$(dirname "$operator_pack_summary_json")"
mkdir -p "$(dirname "$operator_pack_canonical_summary_json")"

gate_cycle_metrics_summary_json="$gate_cycle_reports_dir/blockchain_mainnet_activation_metrics_summary.json"

step_ids=("metrics_input_template" "gate_cycle" "missing_metrics_checklist" "operator_pack")

declare -A step_status=()
declare -A step_rc=()
declare -A step_command=()
declare -A step_started_at=()
declare -A step_completed_at=()
declare -A step_note=()

for step_id in "${step_ids[@]}"; do
  step_status["$step_id"]="pending"
  step_rc["$step_id"]="0"
  step_command["$step_id"]=""
  step_started_at["$step_id"]=""
  step_completed_at["$step_id"]=""
  step_note["$step_id"]=""
done

run_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
run_started_epoch="$(date -u +%s)"

template_cmd=(
  bash "$template_script"
  --output-json "$template_output_json"
  --canonical-output-json "$template_canonical_output_json"
  --include-example-values 0
  --print-output-json 0
)
run_step "metrics_input_template" "${template_cmd[@]}"

if [[ "${step_status[metrics_input_template]}" == "pass" ]]; then
  gate_cycle_cmd=(
    bash "$gate_cycle_script"
    --input-json "$input_json"
    --seed-example-input 0
    --emit-missing-checklist 0
    --reports-dir "$gate_cycle_reports_dir"
    --summary-json "$gate_cycle_summary_json"
    --canonical-summary-json "$gate_cycle_canonical_summary_json"
    --refresh-roadmap "$refresh_roadmap"
    --print-summary-json 0
  )
  run_step "gate_cycle" "${gate_cycle_cmd[@]}"
else
  step_status["gate_cycle"]="skipped"
  step_note["gate_cycle"]="template-step-failed"
fi

if [[ "${step_status[gate_cycle]}" == "pass" ]]; then
  missing_checklist_cmd=(
    bash "$missing_checklist_script"
    --metrics-summary-json "$gate_cycle_metrics_summary_json"
    --output-json "$missing_checklist_json"
    --output-md "$missing_checklist_md"
    --print-output-json 0
  )
  run_step "missing_metrics_checklist" "${missing_checklist_cmd[@]}"

  operator_pack_cmd=(
    bash "$operator_pack_script"
    --reports-dir "$operator_pack_reports_dir"
    --summary-json "$operator_pack_summary_json"
    --canonical-summary-json "$operator_pack_canonical_summary_json"
    --metrics-summary-json "$gate_cycle_metrics_summary_json"
    --template-output-json "$template_output_json"
    --template-canonical-output-json "$template_canonical_output_json"
    --template-include-example-values 0
    --checklist-output-json "$missing_checklist_json"
    --checklist-output-md "$missing_checklist_md"
    --print-summary-json 0
  )
  run_step "operator_pack" "${operator_pack_cmd[@]}"
else
  step_status["missing_metrics_checklist"]="skipped"
  step_note["missing_metrics_checklist"]="gate-cycle-step-failed"
  step_status["operator_pack"]="skipped"
  step_note["operator_pack"]="gate-cycle-step-failed"
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

helper_status="pass"
helper_rc=0
if [[ -n "$first_runtime_failure_step" ]]; then
  helper_status="runtime-fail"
  helper_rc="$first_runtime_failure_rc"
fi

gate_cycle_decision="$(json_text_or_empty "$gate_cycle_summary_json" '.decision')"
gate_cycle_missing_required_metrics_json="$(
  json_array_or_empty "$gate_cycle_summary_json" '(.steps.gate_bundle.missing_required_metrics // []) | if type == "array" then . else [] end'
)"

missing_checklist_status="$(json_text_or_empty "$missing_checklist_json" '.status')"
missing_checklist_missing_keys_json="$(
  json_array_or_empty "$missing_checklist_json" '
    if (.missing_metric_keys | type) == "array" then .missing_metric_keys
    elif (.missing_keys | type) == "array" then .missing_keys
    elif (.checklist | type) == "array" then [.checklist[]? | .key?]
    else [] end
    | map(select(type == "string" and length > 0))
  '
)"
missing_checklist_missing_count_raw="$(json_text_or_empty "$missing_checklist_json" '.counts.missing // .missing_count')"
if [[ ! "$missing_checklist_missing_count_raw" =~ ^-?[0-9]+$ ]]; then
  missing_checklist_missing_count_raw="$(jq -n --argjson missing_keys "$missing_checklist_missing_keys_json" '$missing_keys | length')"
fi

operator_pack_status_observed="$(json_text_or_empty "$operator_pack_summary_json" '.status')"
operator_pack_rc_observed="$(json_text_or_empty "$operator_pack_summary_json" '.rc')"
if [[ ! "$operator_pack_rc_observed" =~ ^-?[0-9]+$ ]]; then
  operator_pack_rc_observed="null"
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
  --arg status "$helper_status" \
  --argjson rc "$helper_rc" \
  --arg input_json "$input_json" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg canonical_summary_json "$canonical_summary_json" \
  --arg gate_cycle_reports_dir "$gate_cycle_reports_dir" \
  --arg gate_cycle_summary_json "$gate_cycle_summary_json" \
  --arg gate_cycle_canonical_summary_json "$gate_cycle_canonical_summary_json" \
  --arg gate_cycle_metrics_summary_json "$gate_cycle_metrics_summary_json" \
  --arg operator_pack_reports_dir "$operator_pack_reports_dir" \
  --arg operator_pack_summary_json "$operator_pack_summary_json" \
  --arg operator_pack_canonical_summary_json "$operator_pack_canonical_summary_json" \
  --arg template_output_json "$template_output_json" \
  --arg template_canonical_output_json "$template_canonical_output_json" \
  --arg missing_checklist_json "$missing_checklist_json" \
  --arg missing_checklist_md "$missing_checklist_md" \
  --argjson print_summary_json "$( [[ "$print_summary_json" == "1" ]] && echo true || echo false )" \
  --argjson refresh_roadmap "$( [[ "$refresh_roadmap" == "1" ]] && echo true || echo false )" \
  --argjson duration_sec "$run_duration_sec" \
  --arg first_runtime_failure_step "$first_runtime_failure_step" \
  --argjson first_runtime_failure_rc "$first_runtime_failure_rc" \
  --arg gate_cycle_decision "$gate_cycle_decision" \
  --argjson gate_cycle_missing_required_metrics "$gate_cycle_missing_required_metrics_json" \
  --arg missing_checklist_status "$missing_checklist_status" \
  --argjson missing_checklist_missing_count "$missing_checklist_missing_count_raw" \
  --argjson missing_checklist_missing_keys "$missing_checklist_missing_keys_json" \
  --arg operator_pack_status_observed "$operator_pack_status_observed" \
  --argjson operator_pack_rc_observed "$operator_pack_rc_observed" \
  --arg template_status "${step_status[metrics_input_template]}" \
  --argjson template_rc "${step_rc[metrics_input_template]}" \
  --arg template_command "${step_command[metrics_input_template]}" \
  --arg template_started_at "${step_started_at[metrics_input_template]}" \
  --arg template_completed_at "${step_completed_at[metrics_input_template]}" \
  --arg template_note "${step_note[metrics_input_template]}" \
  --arg gate_cycle_status "${step_status[gate_cycle]}" \
  --argjson gate_cycle_rc "${step_rc[gate_cycle]}" \
  --arg gate_cycle_command "${step_command[gate_cycle]}" \
  --arg gate_cycle_started_at "${step_started_at[gate_cycle]}" \
  --arg gate_cycle_completed_at "${step_completed_at[gate_cycle]}" \
  --arg gate_cycle_note "${step_note[gate_cycle]}" \
  --arg missing_checklist_step_status "${step_status[missing_metrics_checklist]}" \
  --argjson missing_checklist_step_rc "${step_rc[missing_metrics_checklist]}" \
  --arg missing_checklist_step_command "${step_command[missing_metrics_checklist]}" \
  --arg missing_checklist_step_started_at "${step_started_at[missing_metrics_checklist]}" \
  --arg missing_checklist_step_completed_at "${step_completed_at[missing_metrics_checklist]}" \
  --arg missing_checklist_step_note "${step_note[missing_metrics_checklist]}" \
  --arg operator_pack_step_status "${step_status[operator_pack]}" \
  --argjson operator_pack_step_rc "${step_rc[operator_pack]}" \
  --arg operator_pack_step_command "${step_command[operator_pack]}" \
  --arg operator_pack_step_started_at "${step_started_at[operator_pack]}" \
  --arg operator_pack_step_completed_at "${step_completed_at[operator_pack]}" \
  --arg operator_pack_step_note "${step_note[operator_pack]}" \
  --arg template_script "$template_script" \
  --arg gate_cycle_script "$gate_cycle_script" \
  --arg missing_checklist_script "$missing_checklist_script" \
  --arg operator_pack_script "$operator_pack_script" \
  '
  {
    schema: {
      id: "blockchain_mainnet_activation_real_evidence_summary",
      version: "1.0.0"
    },
    generated_at: $generated_at,
    started_at: $started_at,
    completed_at: $completed_at,
    duration_sec: $duration_sec,
    status: $status,
    rc: $rc,
    first_runtime_failure: {
      step: (if $first_runtime_failure_step == "" then null else $first_runtime_failure_step end),
      rc: (if $first_runtime_failure_step == "" then null else $first_runtime_failure_rc end)
    },
    inputs: {
      input_json: $input_json,
      reports_dir: $reports_dir,
      refresh_roadmap: $refresh_roadmap,
      print_summary_json: $print_summary_json
    },
    steps: {
      metrics_input_template: {
        status: $template_status,
        rc: $template_rc,
        command: (if $template_command == "" then null else $template_command end),
        started_at: (if $template_started_at == "" then null else $template_started_at end),
        completed_at: (if $template_completed_at == "" then null else $template_completed_at end),
        note: (if $template_note == "" then null else $template_note end),
        artifacts: {
          output_json: $template_output_json,
          canonical_output_json: $template_canonical_output_json
        }
      },
      gate_cycle: {
        status: $gate_cycle_status,
        rc: $gate_cycle_rc,
        command: (if $gate_cycle_command == "" then null else $gate_cycle_command end),
        started_at: (if $gate_cycle_started_at == "" then null else $gate_cycle_started_at end),
        completed_at: (if $gate_cycle_completed_at == "" then null else $gate_cycle_completed_at end),
        note: (if $gate_cycle_note == "" then null else $gate_cycle_note end),
        decision: (if $gate_cycle_decision == "" then null else $gate_cycle_decision end),
        missing_required_metrics: $gate_cycle_missing_required_metrics,
        artifacts: {
          reports_dir: $gate_cycle_reports_dir,
          summary_json: $gate_cycle_summary_json,
          canonical_summary_json: $gate_cycle_canonical_summary_json,
          metrics_summary_json: $gate_cycle_metrics_summary_json
        }
      },
      missing_metrics_checklist: {
        status: $missing_checklist_step_status,
        rc: $missing_checklist_step_rc,
        command: (if $missing_checklist_step_command == "" then null else $missing_checklist_step_command end),
        started_at: (if $missing_checklist_step_started_at == "" then null else $missing_checklist_step_started_at end),
        completed_at: (if $missing_checklist_step_completed_at == "" then null else $missing_checklist_step_completed_at end),
        note: (if $missing_checklist_step_note == "" then null else $missing_checklist_step_note end),
        checklist_status: (if $missing_checklist_status == "" then null else $missing_checklist_status end),
        missing_count: $missing_checklist_missing_count,
        missing_keys: $missing_checklist_missing_keys,
        artifacts: {
          checklist_json: $missing_checklist_json,
          checklist_md: $missing_checklist_md
        }
      },
      operator_pack: {
        status: $operator_pack_step_status,
        rc: $operator_pack_step_rc,
        command: (if $operator_pack_step_command == "" then null else $operator_pack_step_command end),
        started_at: (if $operator_pack_step_started_at == "" then null else $operator_pack_step_started_at end),
        completed_at: (if $operator_pack_step_completed_at == "" then null else $operator_pack_step_completed_at end),
        note: (if $operator_pack_step_note == "" then null else $operator_pack_step_note end),
        observed_status: (if $operator_pack_status_observed == "" then null else $operator_pack_status_observed end),
        observed_rc: $operator_pack_rc_observed,
        artifacts: {
          reports_dir: $operator_pack_reports_dir,
          summary_json: $operator_pack_summary_json,
          canonical_summary_json: $operator_pack_canonical_summary_json
        }
      }
    },
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      canonical_summary_json: $canonical_summary_json,
      template_output_json: $template_output_json,
      template_canonical_output_json: $template_canonical_output_json,
      gate_cycle_reports_dir: $gate_cycle_reports_dir,
      gate_cycle_summary_json: $gate_cycle_summary_json,
      gate_cycle_canonical_summary_json: $gate_cycle_canonical_summary_json,
      gate_cycle_metrics_summary_json: $gate_cycle_metrics_summary_json,
      missing_checklist_json: $missing_checklist_json,
      missing_checklist_md: $missing_checklist_md,
      operator_pack_reports_dir: $operator_pack_reports_dir,
      operator_pack_summary_json: $operator_pack_summary_json,
      operator_pack_canonical_summary_json: $operator_pack_canonical_summary_json
    },
    scripts: {
      metrics_input_template: $template_script,
      gate_cycle: $gate_cycle_script,
      missing_metrics_checklist: $missing_checklist_script,
      operator_pack: $operator_pack_script
    }
  }
  ' >"$summary_tmp"

mv -f "$summary_tmp" "$summary_json"
if [[ "$canonical_summary_json" != "$summary_json" ]]; then
  cp -f "$summary_json" "$canonical_summary_json"
fi

echo "[blockchain-mainnet-activation-real-evidence] status=$helper_status rc=$helper_rc"
echo "[blockchain-mainnet-activation-real-evidence] summary_json=$summary_json canonical_summary_json=$canonical_summary_json"
echo "[blockchain-mainnet-activation-real-evidence] gate_cycle_decision=${gate_cycle_decision:-UNKNOWN} missing_required_metrics=$(jq -r '.steps.gate_cycle.missing_required_metrics | if length == 0 then "none" else join(",") end' "$summary_json")"
echo "[blockchain-mainnet-activation-real-evidence] checklist_status=$(jq -r '.steps.missing_metrics_checklist.checklist_status // "none"' "$summary_json") missing_count=$(jq -r '.steps.missing_metrics_checklist.missing_count // 0' "$summary_json")"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$helper_rc"
