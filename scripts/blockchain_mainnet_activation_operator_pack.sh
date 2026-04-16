#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/blockchain_mainnet_activation_operator_pack.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--canonical-summary-json PATH] \
    [--print-summary-json [0|1]] \
    [--metrics-summary-json PATH] \
    [--template-output-json PATH] \
    [--template-canonical-output-json PATH] \
    [--template-include-example-values [0|1]] \
    [--missing-input-template-output-json PATH] \
    [--missing-input-template-canonical-output-json PATH] \
    [--missing-input-template-include-example-values [0|1]] \
    [--checklist-output-json PATH] \
    [--checklist-output-md PATH]

Purpose:
  Generate operator-ready blockchain mainnet activation artifacts in one run:
    1) metrics input template artifact
    2) optional missing-only metrics input template when metrics summary is available
    3) optional missing-metrics checklist when metrics summary is available

Execution:
  1) scripts/blockchain_mainnet_activation_metrics_input_template.sh
  2) scripts/blockchain_mainnet_activation_metrics_missing_input_template.sh (optional)
  3) scripts/blockchain_mainnet_activation_metrics_missing_checklist.sh (optional)

Notes:
  - Missing input template + checklist stages run only when
    --metrics-summary-json is provided and the file exists at execution time.
  - Missing metrics summary is fail-soft: optional stages are skipped and pack
    still exits 0 when no runtime stage failure occurs.
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

run_step() {
  local step_id="$1"
  shift

  local rc=0
  local started_at=""
  local completed_at=""

  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  step_started_at["$step_id"]="$started_at"
  step_command["$step_id"]="$(print_cmd "$@" | sed 's/[[:space:]]*$//')"

  echo "[blockchain-mainnet-activation-operator-pack] step=${step_id} status=running"
  set +e
  "$@"
  rc=$?
  set -e

  completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  step_completed_at["$step_id"]="$completed_at"
  step_rc["$step_id"]="$rc"

  if (( rc == 0 )); then
    step_status["$step_id"]="pass"
    echo "[blockchain-mainnet-activation-operator-pack] step=${step_id} status=pass rc=0"
  else
    step_status["$step_id"]="fail"
    echo "[blockchain-mainnet-activation-operator-pack] step=${step_id} status=fail rc=${rc}"
  fi
}

need_cmd jq
need_cmd date
need_cmd cp
need_cmd mktemp

reports_dir="${BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs/blockchain_mainnet_activation_operator_pack}"
summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_SUMMARY_JSON:-}"
canonical_summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_CANONICAL_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/blockchain_mainnet_activation_operator_pack_summary.json}"
print_summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_PRINT_SUMMARY_JSON:-1}"

metrics_summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_METRICS_SUMMARY_JSON:-}"

template_output_json="${BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_TEMPLATE_OUTPUT_JSON:-}"
template_canonical_output_json="${BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_TEMPLATE_CANONICAL_OUTPUT_JSON:-}"
template_include_example_values="${BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_TEMPLATE_INCLUDE_EXAMPLE_VALUES:-0}"
missing_input_template_output_json="${BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_MISSING_INPUT_TEMPLATE_OUTPUT_JSON:-}"
missing_input_template_canonical_output_json="${BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_MISSING_INPUT_TEMPLATE_CANONICAL_OUTPUT_JSON:-}"
missing_input_template_include_example_values="${BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_MISSING_INPUT_TEMPLATE_INCLUDE_EXAMPLE_VALUES:-0}"

checklist_output_json="${BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_CHECKLIST_OUTPUT_JSON:-}"
checklist_output_md="${BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_CHECKLIST_OUTPUT_MD:-}"

template_script="${BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_TEMPLATE_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics_input_template.sh}"
missing_input_template_script="${BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_MISSING_INPUT_TEMPLATE_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics_missing_input_template.sh}"
checklist_script="${BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_CHECKLIST_SCRIPT:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics_missing_checklist.sh}"

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
    --metrics-summary-json)
      path_arg_or_die "--metrics-summary-json" "${2:-}"
      metrics_summary_json="${2:-}"
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
    --template-include-example-values)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        template_include_example_values="${2:-}"
        shift 2
      else
        template_include_example_values="1"
        shift
      fi
      ;;
    --missing-input-template-output-json)
      path_arg_or_die "--missing-input-template-output-json" "${2:-}"
      missing_input_template_output_json="${2:-}"
      shift 2
      ;;
    --missing-input-template-canonical-output-json)
      path_arg_or_die "--missing-input-template-canonical-output-json" "${2:-}"
      missing_input_template_canonical_output_json="${2:-}"
      shift 2
      ;;
    --missing-input-template-include-example-values)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        missing_input_template_include_example_values="${2:-}"
        shift 2
      else
        missing_input_template_include_example_values="1"
        shift
      fi
      ;;
    --checklist-output-json)
      path_arg_or_die "--checklist-output-json" "${2:-}"
      checklist_output_json="${2:-}"
      shift 2
      ;;
    --checklist-output-md)
      path_arg_or_die "--checklist-output-md" "${2:-}"
      checklist_output_md="${2:-}"
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
bool_arg_or_die "--template-include-example-values" "$template_include_example_values"
bool_arg_or_die "--missing-input-template-include-example-values" "$missing_input_template_include_example_values"
path_arg_or_die "--reports-dir" "$reports_dir"
path_arg_or_die "--canonical-summary-json" "$canonical_summary_json"

if [[ -n "$(trim "$metrics_summary_json")" ]]; then
  path_arg_or_die "--metrics-summary-json" "$metrics_summary_json"
fi
if [[ -n "$(trim "$template_output_json")" ]]; then
  path_arg_or_die "--template-output-json" "$template_output_json"
fi
if [[ -n "$(trim "$template_canonical_output_json")" ]]; then
  path_arg_or_die "--template-canonical-output-json" "$template_canonical_output_json"
fi
if [[ -n "$(trim "$missing_input_template_output_json")" ]]; then
  path_arg_or_die "--missing-input-template-output-json" "$missing_input_template_output_json"
fi
if [[ -n "$(trim "$missing_input_template_canonical_output_json")" ]]; then
  path_arg_or_die "--missing-input-template-canonical-output-json" "$missing_input_template_canonical_output_json"
fi
if [[ -n "$(trim "$checklist_output_json")" ]]; then
  path_arg_or_die "--checklist-output-json" "$checklist_output_json"
fi
if [[ -n "$(trim "$checklist_output_md")" ]]; then
  path_arg_or_die "--checklist-output-md" "$checklist_output_md"
fi

if [[ ! -f "$template_script" ]]; then
  echo "missing stage script: $template_script"
  exit 2
fi
if [[ ! -f "$missing_input_template_script" ]]; then
  echo "missing stage script: $missing_input_template_script"
  exit 2
fi
if [[ ! -f "$checklist_script" ]]; then
  echo "missing stage script: $checklist_script"
  exit 2
fi

reports_dir="$(abs_path "$reports_dir")"
canonical_summary_json="$(abs_path "$canonical_summary_json")"

if [[ -z "$(trim "$summary_json")" ]]; then
  summary_json="$reports_dir/blockchain_mainnet_activation_operator_pack_summary.json"
fi
summary_json="$(abs_path "$summary_json")"

if [[ -z "$(trim "$template_output_json")" ]]; then
  template_output_json="$reports_dir/blockchain_mainnet_activation_metrics_input_template.json"
fi
template_output_json="$(abs_path "$template_output_json")"

if [[ -z "$(trim "$template_canonical_output_json")" ]]; then
  template_canonical_output_json="$reports_dir/blockchain_mainnet_activation_metrics_input_template.canonical.json"
fi
template_canonical_output_json="$(abs_path "$template_canonical_output_json")"

if [[ -z "$(trim "$missing_input_template_output_json")" ]]; then
  missing_input_template_output_json="$reports_dir/blockchain_mainnet_activation_metrics_missing_input_template.json"
fi
missing_input_template_output_json="$(abs_path "$missing_input_template_output_json")"

if [[ -z "$(trim "$missing_input_template_canonical_output_json")" ]]; then
  missing_input_template_canonical_output_json="$reports_dir/blockchain_mainnet_activation_metrics_missing_input_template.canonical.json"
fi
missing_input_template_canonical_output_json="$(abs_path "$missing_input_template_canonical_output_json")"

if [[ -z "$(trim "$checklist_output_json")" ]]; then
  checklist_output_json="$reports_dir/blockchain_mainnet_activation_metrics_missing_checklist.json"
fi
checklist_output_json="$(abs_path "$checklist_output_json")"

if [[ -z "$(trim "$checklist_output_md")" ]]; then
  checklist_output_md="$reports_dir/blockchain_mainnet_activation_metrics_missing_checklist.md"
fi
checklist_output_md="$(abs_path "$checklist_output_md")"

if [[ -n "$(trim "$metrics_summary_json")" ]]; then
  metrics_summary_json="$(abs_path "$metrics_summary_json")"
fi

mkdir -p "$reports_dir"
mkdir -p "$(dirname "$summary_json")"
mkdir -p "$(dirname "$canonical_summary_json")"
mkdir -p "$(dirname "$template_output_json")"
mkdir -p "$(dirname "$template_canonical_output_json")"
mkdir -p "$(dirname "$missing_input_template_output_json")"
mkdir -p "$(dirname "$missing_input_template_canonical_output_json")"
mkdir -p "$(dirname "$checklist_output_json")"
mkdir -p "$(dirname "$checklist_output_md")"

step_ids=("metrics_input_template" "metrics_missing_input_template" "metrics_missing_checklist")

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

metrics_summary_provided="0"
metrics_summary_exists="0"
missing_input_template_enabled="0"
missing_input_template_skipped_reason=""
checklist_enabled="0"
checklist_skipped_reason=""

if [[ -n "$(trim "$metrics_summary_json")" ]]; then
  metrics_summary_provided="1"
fi
if [[ "$metrics_summary_provided" == "1" && -f "$metrics_summary_json" ]]; then
  metrics_summary_exists="1"
fi
if [[ "$metrics_summary_provided" == "1" && "$metrics_summary_exists" == "1" ]]; then
  missing_input_template_enabled="1"
  checklist_enabled="1"
fi

if [[ "$missing_input_template_enabled" == "0" ]]; then
  step_status["metrics_missing_input_template"]="skipped"
  if [[ "$metrics_summary_provided" == "0" ]]; then
    missing_input_template_skipped_reason="metrics-summary-json-not-provided"
  else
    missing_input_template_skipped_reason="metrics-summary-json-missing-file"
  fi
  step_note["metrics_missing_input_template"]="$missing_input_template_skipped_reason"
fi

if [[ "$checklist_enabled" == "0" ]]; then
  step_status["metrics_missing_checklist"]="skipped"
  if [[ "$metrics_summary_provided" == "0" ]]; then
    checklist_skipped_reason="metrics-summary-json-not-provided"
  else
    checklist_skipped_reason="metrics-summary-json-missing-file"
  fi
  step_note["metrics_missing_checklist"]="$checklist_skipped_reason"
fi

run_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
run_started_epoch="$(date -u +%s)"

template_cmd=(
  bash "$template_script"
  --output-json "$template_output_json"
  --canonical-output-json "$template_canonical_output_json"
  --include-example-values "$template_include_example_values"
  --print-output-json 0
)
run_step "metrics_input_template" "${template_cmd[@]}"

if [[ "${step_status[metrics_input_template]}" == "pass" && "$missing_input_template_enabled" == "1" ]]; then
  missing_input_template_cmd=(
    bash "$missing_input_template_script"
    --metrics-summary-json "$metrics_summary_json"
    --output-json "$missing_input_template_output_json"
    --canonical-output-json "$missing_input_template_canonical_output_json"
    --include-example-values "$missing_input_template_include_example_values"
    --print-output-json 0
  )
  run_step "metrics_missing_input_template" "${missing_input_template_cmd[@]}"
elif [[ "${step_status[metrics_input_template]}" != "pass" ]]; then
  step_status["metrics_missing_input_template"]="skipped"
  missing_input_template_skipped_reason="template-step-failed"
  step_note["metrics_missing_input_template"]="$missing_input_template_skipped_reason"
fi

if [[ "${step_status[metrics_input_template]}" == "pass" && "${step_status[metrics_missing_input_template]}" == "pass" && "$checklist_enabled" == "1" ]]; then
  checklist_cmd=(
    bash "$checklist_script"
    --metrics-summary-json "$metrics_summary_json"
    --output-json "$checklist_output_json"
    --output-md "$checklist_output_md"
    --print-output-json 0
  )
  run_step "metrics_missing_checklist" "${checklist_cmd[@]}"
elif [[ "${step_status[metrics_input_template]}" != "pass" ]]; then
  step_status["metrics_missing_checklist"]="skipped"
  checklist_skipped_reason="template-step-failed"
  step_note["metrics_missing_checklist"]="$checklist_skipped_reason"
elif [[ "$checklist_enabled" == "1" && "${step_status[metrics_missing_input_template]}" != "pass" ]]; then
  step_status["metrics_missing_checklist"]="skipped"
  checklist_skipped_reason="missing-input-template-step-failed"
  step_note["metrics_missing_checklist"]="$checklist_skipped_reason"
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

pack_status="pass"
pack_rc=0
if [[ -n "$first_runtime_failure_step" ]]; then
  pack_status="runtime-fail"
  pack_rc="$first_runtime_failure_rc"
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
  --arg status "$pack_status" \
  --argjson rc "$pack_rc" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg canonical_summary_json "$canonical_summary_json" \
  --arg metrics_summary_json "$metrics_summary_json" \
  --arg template_output_json "$template_output_json" \
  --arg template_canonical_output_json "$template_canonical_output_json" \
  --arg missing_input_template_output_json "$missing_input_template_output_json" \
  --arg missing_input_template_canonical_output_json "$missing_input_template_canonical_output_json" \
  --arg checklist_output_json "$checklist_output_json" \
  --arg checklist_output_md "$checklist_output_md" \
  --arg template_script "$template_script" \
  --arg missing_input_template_script "$missing_input_template_script" \
  --arg checklist_script "$checklist_script" \
  --argjson print_summary_json "$( [[ "$print_summary_json" == "1" ]] && echo true || echo false )" \
  --argjson template_include_example_values "$( [[ "$template_include_example_values" == "1" ]] && echo true || echo false )" \
  --argjson missing_input_template_include_example_values "$( [[ "$missing_input_template_include_example_values" == "1" ]] && echo true || echo false )" \
  --argjson metrics_summary_provided "$( [[ "$metrics_summary_provided" == "1" ]] && echo true || echo false )" \
  --argjson metrics_summary_exists "$( [[ "$metrics_summary_exists" == "1" ]] && echo true || echo false )" \
  --argjson missing_input_template_enabled "$( [[ "$missing_input_template_enabled" == "1" ]] && echo true || echo false )" \
  --arg missing_input_template_skipped_reason "$missing_input_template_skipped_reason" \
  --argjson checklist_enabled "$( [[ "$checklist_enabled" == "1" ]] && echo true || echo false )" \
  --arg checklist_skipped_reason "$checklist_skipped_reason" \
  --argjson duration_sec "$run_duration_sec" \
  --arg first_runtime_failure_step "$first_runtime_failure_step" \
  --argjson first_runtime_failure_rc "$first_runtime_failure_rc" \
  --arg template_status "${step_status[metrics_input_template]}" \
  --argjson template_rc "${step_rc[metrics_input_template]}" \
  --arg template_command "${step_command[metrics_input_template]}" \
  --arg template_started_at "${step_started_at[metrics_input_template]}" \
  --arg template_completed_at "${step_completed_at[metrics_input_template]}" \
  --arg template_note "${step_note[metrics_input_template]}" \
  --arg missing_input_template_status "${step_status[metrics_missing_input_template]}" \
  --argjson missing_input_template_rc "${step_rc[metrics_missing_input_template]}" \
  --arg missing_input_template_command "${step_command[metrics_missing_input_template]}" \
  --arg missing_input_template_started_at "${step_started_at[metrics_missing_input_template]}" \
  --arg missing_input_template_completed_at "${step_completed_at[metrics_missing_input_template]}" \
  --arg missing_input_template_note "${step_note[metrics_missing_input_template]}" \
  --arg checklist_status "${step_status[metrics_missing_checklist]}" \
  --argjson checklist_rc "${step_rc[metrics_missing_checklist]}" \
  --arg checklist_command "${step_command[metrics_missing_checklist]}" \
  --arg checklist_started_at "${step_started_at[metrics_missing_checklist]}" \
  --arg checklist_completed_at "${step_completed_at[metrics_missing_checklist]}" \
  --arg checklist_note "${step_note[metrics_missing_checklist]}" \
  '
  {
    schema: {
      id: "blockchain_mainnet_activation_operator_pack_summary",
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
      print_summary_json: $print_summary_json,
      template_include_example_values: $template_include_example_values,
      missing_input_template_include_example_values: $missing_input_template_include_example_values,
      metrics_summary_json: (if $metrics_summary_json == "" then null else $metrics_summary_json end),
      metrics_summary_provided: $metrics_summary_provided,
      metrics_summary_exists: $metrics_summary_exists,
      missing_input_template_output_json: $missing_input_template_output_json,
      missing_input_template_canonical_output_json: $missing_input_template_canonical_output_json
    },
    steps: {
      metrics_input_template: {
        status: $template_status,
        rc: $template_rc,
        command: $template_command,
        started_at: (if $template_started_at == "" then null else $template_started_at end),
        completed_at: (if $template_completed_at == "" then null else $template_completed_at end),
        note: (if $template_note == "" then null else $template_note end),
        artifacts: {
          output_json: $template_output_json,
          canonical_output_json: $template_canonical_output_json
        }
      },
      metrics_missing_input_template: {
        enabled: $missing_input_template_enabled,
        status: $missing_input_template_status,
        rc: $missing_input_template_rc,
        command: (if $missing_input_template_command == "" then null else $missing_input_template_command end),
        started_at: (if $missing_input_template_started_at == "" then null else $missing_input_template_started_at end),
        completed_at: (if $missing_input_template_completed_at == "" then null else $missing_input_template_completed_at end),
        note: (if $missing_input_template_note == "" then null else $missing_input_template_note end),
        skipped_reason: (if $missing_input_template_skipped_reason == "" then null else $missing_input_template_skipped_reason end),
        input: {
          metrics_summary_json: (if $metrics_summary_json == "" then null else $metrics_summary_json end),
          metrics_summary_provided: $metrics_summary_provided,
          metrics_summary_exists: $metrics_summary_exists
        },
        artifacts: {
          output_json: (if $missing_input_template_enabled then $missing_input_template_output_json else null end),
          canonical_output_json: (if $missing_input_template_enabled then $missing_input_template_canonical_output_json else null end)
        }
      },
      metrics_missing_checklist: {
        enabled: $checklist_enabled,
        status: $checklist_status,
        rc: $checklist_rc,
        command: (if $checklist_command == "" then null else $checklist_command end),
        started_at: (if $checklist_started_at == "" then null else $checklist_started_at end),
        completed_at: (if $checklist_completed_at == "" then null else $checklist_completed_at end),
        note: (if $checklist_note == "" then null else $checklist_note end),
        skipped_reason: (if $checklist_skipped_reason == "" then null else $checklist_skipped_reason end),
        input: {
          metrics_summary_json: (if $metrics_summary_json == "" then null else $metrics_summary_json end),
          metrics_summary_provided: $metrics_summary_provided,
          metrics_summary_exists: $metrics_summary_exists
        },
        artifacts: {
          output_json: (if $checklist_enabled then $checklist_output_json else null end),
          output_md: (if $checklist_enabled then $checklist_output_md else null end)
        }
      }
    },
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      canonical_summary_json: $canonical_summary_json,
      metrics_summary_json: (if $metrics_summary_json == "" then null else $metrics_summary_json end),
      template_output_json: $template_output_json,
      template_canonical_output_json: $template_canonical_output_json,
      missing_input_template_output_json: (if $missing_input_template_enabled then $missing_input_template_output_json else null end),
      missing_input_template_canonical_output_json: (if $missing_input_template_enabled then $missing_input_template_canonical_output_json else null end),
      checklist_output_json: (if $checklist_enabled then $checklist_output_json else null end),
      checklist_output_md: (if $checklist_enabled then $checklist_output_md else null end)
    },
    scripts: {
      metrics_input_template: $template_script,
      metrics_missing_input_template: $missing_input_template_script,
      metrics_missing_checklist: $checklist_script
    }
  }
  ' >"$summary_tmp"

mv -f "$summary_tmp" "$summary_json"

if [[ "$canonical_summary_json" == "$summary_json" ]]; then
  :
else
  cp -f "$summary_json" "$canonical_summary_json"
fi

echo "[blockchain-mainnet-activation-operator-pack] status=$pack_status rc=$pack_rc"
echo "[blockchain-mainnet-activation-operator-pack] summary_json=$summary_json canonical_summary_json=$canonical_summary_json"
echo "[blockchain-mainnet-activation-operator-pack] checklist_enabled=$checklist_enabled skipped_reason=${checklist_skipped_reason:-none}"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$pack_rc"
