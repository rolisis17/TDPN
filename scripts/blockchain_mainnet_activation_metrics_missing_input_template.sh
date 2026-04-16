#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/blockchain_mainnet_activation_metrics_missing_input_template.sh \
    --metrics-summary-json PATH \
    [--output-json PATH] \
    [--canonical-output-json PATH] \
    [--print-output-json [0|1]] \
    [--include-example-values [0|1]]

Purpose:
  Emit a deterministic missing-only metrics input template derived from
  blockchain activation metrics summaries.

Notes:
  - Accepts summaries produced by:
      scripts/blockchain_mainnet_activation_metrics.sh
      scripts/blockchain_gate_bundle.sh
  - Fail-soft for missing/invalid input summaries: exits 0 and emits a
    template with all required metric keys marked missing.
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

need_cmd jq
need_cmd cp
need_cmd mktemp

metrics_summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_MISSING_INPUT_TEMPLATE_METRICS_SUMMARY_JSON:-}"
output_json="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_MISSING_INPUT_TEMPLATE_OUTPUT_JSON:-$ROOT_DIR/.easy-node-logs/blockchain_mainnet_activation_metrics_missing_input_template.json}"
canonical_output_json="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_MISSING_INPUT_TEMPLATE_CANONICAL_OUTPUT_JSON:-}"
print_output_json="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_MISSING_INPUT_TEMPLATE_PRINT_OUTPUT_JSON:-0}"
include_example_values="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_MISSING_INPUT_TEMPLATE_INCLUDE_EXAMPLE_VALUES:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --metrics-summary-json)
      path_arg_or_die "--metrics-summary-json" "${2:-}"
      metrics_summary_json="${2:-}"
      shift 2
      ;;
    --output-json)
      path_arg_or_die "--output-json" "${2:-}"
      output_json="${2:-}"
      shift 2
      ;;
    --canonical-output-json)
      path_arg_or_die "--canonical-output-json" "${2:-}"
      canonical_output_json="${2:-}"
      shift 2
      ;;
    --print-output-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_output_json="${2:-}"
        shift 2
      else
        print_output_json="1"
        shift
      fi
      ;;
    --include-example-values)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        include_example_values="${2:-}"
        shift 2
      else
        include_example_values="1"
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

if [[ -z "$(trim "$canonical_output_json")" ]]; then
  canonical_output_json="$output_json"
fi

if [[ -z "$(trim "$metrics_summary_json")" ]]; then
  echo "--metrics-summary-json is required"
  usage
  exit 2
fi

path_arg_or_die "--metrics-summary-json" "$metrics_summary_json"
path_arg_or_die "--output-json" "$output_json"
path_arg_or_die "--canonical-output-json" "$canonical_output_json"
bool_arg_or_die "--print-output-json" "$print_output_json"
bool_arg_or_die "--include-example-values" "$include_example_values"

metrics_summary_json="$(abs_path "$metrics_summary_json")"
output_json="$(abs_path "$output_json")"
canonical_output_json="$(abs_path "$canonical_output_json")"

mkdir -p "$(dirname "$output_json")"
mkdir -p "$(dirname "$canonical_output_json")"

required_metric_keys=(
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

declare -A required_metric_known=()
for key in "${required_metric_keys[@]}"; do
  required_metric_known["$key"]="1"
done

input_state="available"
input_valid_json="true"
source_schema_id=""
reported_missing_keys_json="[]"

if [[ ! -f "$metrics_summary_json" ]]; then
  input_state="missing"
  input_valid_json="false"
elif ! jq -e . "$metrics_summary_json" >/dev/null 2>&1; then
  input_state="invalid"
  input_valid_json="false"
else
  source_schema_id="$(jq -r '.schema.id // ""' "$metrics_summary_json" 2>/dev/null || true)"
  reported_missing_keys_json="$(
    jq -c '
      def normalized_array(v):
        (v | if type == "array" then . else [] end | map(select(type == "string" and length > 0)) | unique);
      (
        if (.required_missing_metrics | type) == "array" then .required_missing_metrics
        elif (.missing_required_metrics | type) == "array" then .missing_required_metrics
        elif (.steps.metrics.required_missing_metrics | type) == "array" then .steps.metrics.required_missing_metrics
        elif (.steps.metrics.missing_required_metrics | type) == "array" then .steps.metrics.missing_required_metrics
        else [] end
      ) as $reported
      | (normalized_array($reported)) as $normalized_reported
      | if ($normalized_reported | length) > 0 then
          $normalized_reported
        elif (((.counts.missing // 0) | tonumber? // 0) > 0 and (.required_metric_keys | type) == "array") then
          ([.required_metric_keys[] | select(type == "string") as $k | select((.metrics[$k] // .[$k]) == null)] | unique)
        else
          []
        end
    ' "$metrics_summary_json" 2>/dev/null || echo '[]'
  )"
fi

declare -A missing_lookup=()
if [[ "$input_state" == "available" ]]; then
  while IFS= read -r key; do
    key="$(trim "$key")"
    if [[ -z "$key" ]]; then
      continue
    fi
    if [[ "${required_metric_known[$key]:-0}" == "1" ]]; then
      missing_lookup["$key"]="1"
    fi
  done < <(jq -r '.[]?' <<<"$reported_missing_keys_json" 2>/dev/null || true)
else
  for key in "${required_metric_keys[@]}"; do
    missing_lookup["$key"]="1"
  done
fi

ordered_missing_keys=()
for key in "${required_metric_keys[@]}"; do
  if [[ "${missing_lookup[$key]:-0}" == "1" ]]; then
    ordered_missing_keys+=("$key")
  fi
done

if ((${#ordered_missing_keys[@]} == 0)); then
  missing_keys_json='[]'
else
  missing_keys_json="$(printf '%s\n' "${ordered_missing_keys[@]}" | jq -R . | jq -s .)"
fi

missing_count="${#ordered_missing_keys[@]}"
status="missing"
if [[ "$missing_count" == "0" ]]; then
  status="complete"
fi

summary_tmp="$(mktemp "${output_json}.tmp.XXXXXX")"
cleanup() {
  rm -f "$summary_tmp"
}
trap cleanup EXIT

jq -n \
  --arg metrics_summary_json "$metrics_summary_json" \
  --arg output_json "$output_json" \
  --arg canonical_output_json "$canonical_output_json" \
  --arg source_schema_id "$source_schema_id" \
  --arg input_state "$input_state" \
  --argjson input_valid "$input_valid_json" \
  --arg status "$status" \
  --argjson rc 0 \
  --argjson include_example_values "$include_example_values" \
  --argjson missing_count "$missing_count" \
  --argjson missing_keys "$missing_keys_json" \
  '
  def intersection($keys; $allowed):
    [$keys[] as $k | select(($allowed | index($k)) != null) | $k];
  def values_map:
    {
      measurement_window_weeks: 13,
      vpn_connect_session_success_slo_pct: 99.82,
      vpn_recovery_mttr_p95_minutes: 19,
      paying_users_3mo_min: 1650,
      paid_sessions_per_day_30d_avg: 15500,
      validator_candidate_depth: 38,
      validator_independent_operators: 14,
      validator_max_operator_seat_share_pct: 18.5,
      validator_max_asn_provider_seat_share_pct: 22.0,
      validator_region_count: 5,
      validator_country_count: 9,
      manual_sanctions_reversed_pct_90d: 4.2,
      abuse_report_to_decision_p95_hours: 11,
      subsidy_runway_months: 16,
      contribution_margin_3mo: 0.9
    };
  def template_from(keys):
    reduce keys[] as $k ({}; . + {($k): (if $include_example_values == 1 then (values_map[$k] // null) else null end)});
  (intersection($missing_keys; ["measurement_window_weeks"])) as $general_keys
  | (intersection($missing_keys; ["vpn_connect_session_success_slo_pct", "vpn_recovery_mttr_p95_minutes"])) as $reliability_keys
  | (intersection($missing_keys; ["paying_users_3mo_min", "paid_sessions_per_day_30d_avg"])) as $demand_keys
  | (intersection($missing_keys; ["validator_candidate_depth", "validator_independent_operators", "validator_max_operator_seat_share_pct", "validator_max_asn_provider_seat_share_pct", "validator_region_count", "validator_country_count"])) as $validator_keys
  | (intersection($missing_keys; ["manual_sanctions_reversed_pct_90d", "abuse_report_to_decision_p95_hours"])) as $governance_keys
  | (intersection($missing_keys; ["subsidy_runway_months", "contribution_margin_3mo"])) as $economics_keys
  | {
      version: 1,
      schema: {id: "blockchain_mainnet_activation_metrics_missing_input_template", major: 1, minor: 0},
      status: $status,
      rc: $rc,
      include_example_values: ($include_example_values == 1),
      input: {
        metrics_summary_json: $metrics_summary_json,
        state: $input_state,
        valid: ($input_valid == true),
        source_schema_id: (if $source_schema_id == "" then null else $source_schema_id end)
      },
      missing_count: $missing_count,
      missing_keys: $missing_keys,
      template: template_from($missing_keys),
      general: template_from($general_keys),
      reliability: template_from($reliability_keys),
      demand: template_from($demand_keys),
      validator: template_from($validator_keys),
      governance: template_from($governance_keys),
      economics: template_from($economics_keys),
      artifacts: {
        output_json: $output_json,
        canonical_output_json: $canonical_output_json
      }
    }
  ' >"$summary_tmp"

cp "$summary_tmp" "$output_json"
if [[ "$canonical_output_json" != "$output_json" ]]; then
  cp "$summary_tmp" "$canonical_output_json"
fi

echo "[blockchain-mainnet-activation-metrics-missing-input-template] status=$status missing_count=$missing_count include_example_values=$include_example_values metrics_summary_json=$metrics_summary_json output_json=$output_json canonical_output_json=$canonical_output_json"

if [[ "$print_output_json" == "1" ]]; then
  cat "$output_json"
fi

exit 0
