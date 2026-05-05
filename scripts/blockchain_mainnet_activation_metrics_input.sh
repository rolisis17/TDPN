#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/blockchain_mainnet_activation_metrics_input.sh \
    --input-json PATH \
    [--summary-json PATH] \
    [--canonical-summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Normalize one operator-provided blockchain metrics evidence JSON into the
  canonical metric keys consumed by
  scripts/blockchain_mainnet_activation_metrics.sh.

Canonical metric keys:
  measurement_window_weeks
  vpn_connect_session_success_slo_pct
  vpn_recovery_mttr_p95_minutes
  paying_users_3mo_min
  paid_sessions_per_day_30d_avg
  validator_candidate_depth
  validator_independent_operators
  validator_max_operator_seat_share_pct
  validator_max_asn_provider_seat_share_pct
  validator_region_count
  validator_country_count
  manual_sanctions_reversed_pct_90d
  abuse_report_to_decision_p95_hours
  subsidy_runway_months
  contribution_margin_3mo

Notes:
  - Accepts canonical keys at top-level and/or nested/grouped JSON shapes.
  - Top-level canonical values take precedence over nested values.
  - Fail-soft on partial/missing data: exits 0 with status complete|partial|missing.
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

numeric_text_or_empty() {
  local raw
  raw="$(trim "${1:-}")"
  if [[ "$raw" =~ ^-?[0-9]+([.][0-9]+)?([eE][+-]?[0-9]+)?$ ]]; then
    printf '%s' "$raw"
  else
    printf '%s' ""
  fi
}

array_to_json() {
  local -n arr_ref=$1
  if ((${#arr_ref[@]} == 0)); then
    printf '%s' "[]"
    return
  fi
  printf '%s\n' "${arr_ref[@]}" | jq -R . | jq -s .
}

extract_top_level_numeric() {
  local input_json="$1"
  local key="$2"
  local raw=""
  raw="$(jq -r --arg key "$key" '
    if (.[$key] | type) == "number" then .[$key] else empty end
  ' "$input_json" 2>/dev/null || true)"
  numeric_text_or_empty "$raw"
}

extract_nested_numeric() {
  local input_json="$1"
  local key="$2"
  local raw=""
  raw="$(jq -r --arg key "$key" '
    limit(1; .. | objects | .[$key]? | select(type == "number"))
  ' "$input_json" 2>/dev/null || true)"
  numeric_text_or_empty "$raw"
}

metric_has_non_numeric_value() {
  local input_json="$1"
  local key="$2"
  local raw=""
  raw="$(jq -r --arg key "$key" '
    if ([.. | objects | select(has($key)) | .[$key] | select(type != "number" and type != "null")] | length) > 0
    then "1"
    else "0"
    end
  ' "$input_json" 2>/dev/null || true)"
  if [[ "$raw" == "1" ]]; then
    return 0
  fi
  return 1
}

need_cmd jq
need_cmd cp
need_cmd mktemp

input_json="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_INPUT_INPUT_JSON:-}"
summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_INPUT_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/blockchain_mainnet_activation_metrics_input_summary.json}"
canonical_summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_INPUT_CANONICAL_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/blockchain_mainnet_activation_metrics_input.json}"
print_summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_INPUT_PRINT_SUMMARY_JSON:-0}"

summary_json_source="env_or_default"
canonical_summary_json_source="env_or_default"
input_json_source="env"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --input-json)
      path_arg_or_die "--input-json" "${2:-}"
      input_json="${2:-}"
      input_json_source="arg"
      shift 2
      ;;
    --summary-json)
      path_arg_or_die "--summary-json" "${2:-}"
      summary_json="${2:-}"
      summary_json_source="arg"
      shift 2
      ;;
    --canonical-summary-json)
      path_arg_or_die "--canonical-summary-json" "${2:-}"
      canonical_summary_json="${2:-}"
      canonical_summary_json_source="arg"
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

bool_arg_or_die "--print-summary-json" "$print_summary_json"

if [[ -z "$(trim "$input_json")" ]]; then
  echo "--input-json is required"
  usage
  exit 2
fi

path_arg_or_die "--input-json" "$input_json"
path_arg_or_die "--summary-json" "$summary_json"
path_arg_or_die "--canonical-summary-json" "$canonical_summary_json"

input_json="$(abs_path "$input_json")"
summary_json="$(abs_path "$summary_json")"
canonical_summary_json="$(abs_path "$canonical_summary_json")"

mkdir -p "$(dirname "$summary_json")"
mkdir -p "$(dirname "$canonical_summary_json")"

metric_keys=(
  measurement_window_weeks
  vpn_connect_session_success_slo_pct
  vpn_recovery_mttr_p95_minutes
  paying_users_3mo_min
  paid_sessions_per_day_30d_avg
  validator_candidate_depth
  validator_independent_operators
  validator_max_operator_seat_share_pct
  validator_max_asn_provider_seat_share_pct
  validator_region_count
  validator_country_count
  manual_sanctions_reversed_pct_90d
  abuse_report_to_decision_p95_hours
  subsidy_runway_months
  contribution_margin_3mo
)

reliability_metric_keys=(
  vpn_connect_session_success_slo_pct
  vpn_recovery_mttr_p95_minutes
)

demand_metric_keys=(
  paying_users_3mo_min
  paid_sessions_per_day_30d_avg
)

validator_decentralization_metric_keys=(
  validator_candidate_depth
  validator_independent_operators
  validator_max_operator_seat_share_pct
  validator_max_asn_provider_seat_share_pct
  validator_region_count
  validator_country_count
)

governance_metric_keys=(
  manual_sanctions_reversed_pct_90d
  abuse_report_to_decision_p95_hours
)

economics_metric_keys=(
  subsidy_runway_months
  contribution_margin_3mo
)

general_metric_keys=(
  measurement_window_weeks
)

declare -A metric_value_json=()
declare -A metric_source=()

for key in "${metric_keys[@]}"; do
  metric_value_json["$key"]="null"
  metric_source["$key"]="missing"
done

input_state="available"
input_reason=""
input_valid="1"

if [[ ! -f "$input_json" ]]; then
  input_state="missing"
  input_reason="input JSON file not found: $input_json"
  input_valid="0"
elif ! jq -e . "$input_json" >/dev/null 2>&1; then
  input_state="invalid"
  input_reason="input JSON is not valid JSON: $input_json"
  input_valid="0"
fi

declare -a provided_metric_keys=()
declare -a missing_metric_keys=()
declare -a invalid_metric_keys=()

provided_count=0
missing_count=0
invalid_count=0

if [[ "$input_valid" == "1" ]]; then
  for key in "${metric_keys[@]}"; do
    top_level_numeric="$(extract_top_level_numeric "$input_json" "$key")"
    if [[ -n "$top_level_numeric" ]]; then
      metric_value_json["$key"]="$top_level_numeric"
      metric_source["$key"]="input_json_top_level"
      provided_metric_keys+=("$key")
      provided_count=$((provided_count + 1))
      continue
    fi

    nested_numeric="$(extract_nested_numeric "$input_json" "$key")"
    if [[ -n "$nested_numeric" ]]; then
      metric_value_json["$key"]="$nested_numeric"
      metric_source["$key"]="input_json_nested"
      provided_metric_keys+=("$key")
      provided_count=$((provided_count + 1))
      continue
    fi

    if metric_has_non_numeric_value "$input_json" "$key"; then
      metric_value_json["$key"]="null"
      metric_source["$key"]="input_json_invalid"
      missing_metric_keys+=("$key")
      invalid_metric_keys+=("$key")
      missing_count=$((missing_count + 1))
      invalid_count=$((invalid_count + 1))
      continue
    fi

    metric_value_json["$key"]="null"
    metric_source["$key"]="missing"
    missing_metric_keys+=("$key")
    missing_count=$((missing_count + 1))
  done
else
  for key in "${metric_keys[@]}"; do
    metric_value_json["$key"]="null"
    metric_source["$key"]="missing"
    missing_metric_keys+=("$key")
    missing_count=$((missing_count + 1))
  done
fi

status="partial"
if (( provided_count == 0 && invalid_count == 0 )); then
  status="missing"
elif (( missing_count == 0 && invalid_count == 0 )); then
  status="complete"
fi

ready_for_metrics_script="0"
if [[ "$status" == "complete" ]]; then
  ready_for_metrics_script="1"
fi

metric_keys_json="$(array_to_json metric_keys)"
provided_metric_keys_json="$(array_to_json provided_metric_keys)"
missing_metric_keys_json="$(array_to_json missing_metric_keys)"
invalid_metric_keys_json="$(array_to_json invalid_metric_keys)"
reliability_metric_keys_json="$(array_to_json reliability_metric_keys)"
demand_metric_keys_json="$(array_to_json demand_metric_keys)"
validator_decentralization_metric_keys_json="$(array_to_json validator_decentralization_metric_keys)"
governance_metric_keys_json="$(array_to_json governance_metric_keys)"
economics_metric_keys_json="$(array_to_json economics_metric_keys)"
general_metric_keys_json="$(array_to_json general_metric_keys)"

metrics_values_json='{}'
sources_metrics_json='{}'
for key in "${metric_keys[@]}"; do
  metrics_values_json="$(jq -c \
    --arg key "$key" \
    --argjson value "${metric_value_json[$key]}" \
    '. + {($key): $value}' <<<"$metrics_values_json")"
  sources_metrics_json="$(jq -c \
    --arg key "$key" \
    --arg value "${metric_source[$key]}" \
    '. + {($key): $value}' <<<"$sources_metrics_json")"
done

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
canonical_tmp="$(mktemp "${canonical_summary_json}.tmp.XXXXXX")"
cleanup() {
  rm -f "$summary_tmp" "$canonical_tmp"
}
trap cleanup EXIT

jq -n \
  --arg schema_id "blockchain_mainnet_activation_metrics_input_summary" \
  --arg status "$status" \
  --argjson rc 0 \
  --argjson ready_for_metrics_script "$ready_for_metrics_script" \
  --arg input_json "$input_json" \
  --arg input_json_source "$input_json_source" \
  --arg input_state "$input_state" \
  --arg input_reason "$input_reason" \
  --argjson input_valid "$input_valid" \
  --arg summary_json "$summary_json" \
  --arg canonical_summary_json "$canonical_summary_json" \
  --arg summary_json_source "$summary_json_source" \
  --arg canonical_summary_json_source "$canonical_summary_json_source" \
  --argjson required_metric_keys "$metric_keys_json" \
  --argjson provided_metric_keys "$provided_metric_keys_json" \
  --argjson missing_metric_keys "$missing_metric_keys_json" \
  --argjson invalid_metric_keys "$invalid_metric_keys_json" \
  --argjson required_metric_count "${#metric_keys[@]}" \
  --argjson provided_count "$provided_count" \
  --argjson missing_count "$missing_count" \
  --argjson invalid_count "$invalid_count" \
  --argjson reliability_metric_keys "$reliability_metric_keys_json" \
  --argjson demand_metric_keys "$demand_metric_keys_json" \
  --argjson validator_decentralization_metric_keys "$validator_decentralization_metric_keys_json" \
  --argjson governance_metric_keys "$governance_metric_keys_json" \
  --argjson economics_metric_keys "$economics_metric_keys_json" \
  --argjson general_metric_keys "$general_metric_keys_json" \
  --argjson metrics_values "$metrics_values_json" \
  --argjson sources_metrics "$sources_metrics_json" \
  '{
    version: 1,
    schema: {id: $schema_id, major: 1, minor: 0},
    status: $status,
    rc: $rc,
    ready_for_metrics_script: ($ready_for_metrics_script == 1),
    input: {
      input_json: $input_json,
      input_json_source: $input_json_source,
      state: $input_state,
      valid: ($input_valid == 1),
      reason: $input_reason
    },
    counts: {
      required: $required_metric_count,
      provided: $provided_count,
      missing: $missing_count,
      invalid: $invalid_count
    },
    required_metric_keys: $required_metric_keys,
    provided_metric_keys: $provided_metric_keys,
    missing_metric_keys: $missing_metric_keys,
    invalid_metric_keys: $invalid_metric_keys,
    groups: {
      reliability: $reliability_metric_keys,
      demand: $demand_metric_keys,
      validator_decentralization: $validator_decentralization_metric_keys,
      governance: $governance_metric_keys,
      economics: $economics_metric_keys,
      general: $general_metric_keys
    },
    sources: {
      summary_json: $summary_json_source,
      canonical_summary_json: $canonical_summary_json_source,
      metrics: $sources_metrics
    },
    metrics: $metrics_values,
    artifacts: {
      input_json: $input_json,
      summary_json: $summary_json,
      canonical_summary_json: $canonical_summary_json
    }
  } + $metrics_values' >"$summary_tmp"

mv -f "$summary_tmp" "$summary_json"

if [[ "$canonical_summary_json" == "$summary_json" ]]; then
  :
else
  cp -f "$summary_json" "$canonical_tmp"
  mv -f "$canonical_tmp" "$canonical_summary_json"
fi

echo "[blockchain-mainnet-activation-metrics-input] status=$status ready_for_metrics_script=$ready_for_metrics_script required_provided=$provided_count required_missing=$missing_count required_invalid=$invalid_count input_state=$input_state"
echo "[blockchain-mainnet-activation-metrics-input] missing_metric_keys=$(jq -r '.missing_metric_keys | if length == 0 then "none" else join(",") end' "$summary_json")"
echo "[blockchain-mainnet-activation-metrics-input] invalid_metric_keys=$(jq -r '.invalid_metric_keys | if length == 0 then "none" else join(",") end' "$summary_json")"
echo "[blockchain-mainnet-activation-metrics-input] summary_json=$summary_json canonical_summary_json=$canonical_summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit 0
