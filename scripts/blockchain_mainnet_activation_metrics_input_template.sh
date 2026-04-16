#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/blockchain_mainnet_activation_metrics_input_template.sh \
    [--output-json PATH] \
    [--canonical-output-json PATH] \
    [--print-output-json [0|1]] \
    [--include-example-values [0|1]]

Purpose:
  Emit a deterministic JSON template for blockchain activation/bootstrap gate
  metrics input. The template includes grouped metric sections plus canonical
  top-level keys expected by gate tooling.

Notes:
  - Default output path:
      .easy-node-logs/blockchain_mainnet_activation_metrics_input_template.json
  - By default canonical output path mirrors output path.
  - include-example-values=0 uses null placeholders.
  - include-example-values=1 uses plausible example numbers.
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

default_output_json="$ROOT_DIR/.easy-node-logs/blockchain_mainnet_activation_metrics_input_template.json"

output_json="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_INPUT_TEMPLATE_OUTPUT_JSON:-$default_output_json}"
canonical_output_json="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_INPUT_TEMPLATE_CANONICAL_OUTPUT_JSON:-$output_json}"
print_output_json="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_INPUT_TEMPLATE_PRINT_OUTPUT_JSON:-0}"
include_example_values="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_INPUT_TEMPLATE_INCLUDE_EXAMPLE_VALUES:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
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

path_arg_or_die "--output-json" "$output_json"
path_arg_or_die "--canonical-output-json" "$canonical_output_json"
bool_arg_or_die "--print-output-json" "$print_output_json"
bool_arg_or_die "--include-example-values" "$include_example_values"

output_json="$(abs_path "$output_json")"
canonical_output_json="$(abs_path "$canonical_output_json")"

mkdir -p "$(dirname "$output_json")"
mkdir -p "$(dirname "$canonical_output_json")"

measurement_window_weeks="null"
vpn_connect_session_success_slo_pct="null"
vpn_recovery_mttr_p95_minutes="null"
paying_users_3mo_min="null"
paid_sessions_per_day_30d_avg="null"
validator_candidate_depth="null"
validator_independent_operators="null"
validator_max_operator_seat_share_pct="null"
validator_max_asn_provider_seat_share_pct="null"
validator_region_count="null"
validator_country_count="null"
manual_sanctions_reversed_pct_90d="null"
abuse_report_to_decision_p95_hours="null"
subsidy_runway_months="null"
contribution_margin_3mo="null"

if [[ "$include_example_values" == "1" ]]; then
  measurement_window_weeks="13"
  vpn_connect_session_success_slo_pct="99.82"
  vpn_recovery_mttr_p95_minutes="19"
  paying_users_3mo_min="1650"
  paid_sessions_per_day_30d_avg="15500"
  validator_candidate_depth="38"
  validator_independent_operators="14"
  validator_max_operator_seat_share_pct="18.5"
  validator_max_asn_provider_seat_share_pct="22.0"
  validator_region_count="5"
  validator_country_count="9"
  manual_sanctions_reversed_pct_90d="4.2"
  abuse_report_to_decision_p95_hours="11"
  subsidy_runway_months="16"
  contribution_margin_3mo="0.9"
fi

tmp_json="$(mktemp)"
trap 'rm -f "$tmp_json"' EXIT

jq -n \
  --argjson include_example_values "$include_example_values" \
  --arg output_json "$output_json" \
  --arg canonical_output_json "$canonical_output_json" \
  --argjson measurement_window_weeks "$measurement_window_weeks" \
  --argjson vpn_connect_session_success_slo_pct "$vpn_connect_session_success_slo_pct" \
  --argjson vpn_recovery_mttr_p95_minutes "$vpn_recovery_mttr_p95_minutes" \
  --argjson paying_users_3mo_min "$paying_users_3mo_min" \
  --argjson paid_sessions_per_day_30d_avg "$paid_sessions_per_day_30d_avg" \
  --argjson validator_candidate_depth "$validator_candidate_depth" \
  --argjson validator_independent_operators "$validator_independent_operators" \
  --argjson validator_max_operator_seat_share_pct "$validator_max_operator_seat_share_pct" \
  --argjson validator_max_asn_provider_seat_share_pct "$validator_max_asn_provider_seat_share_pct" \
  --argjson validator_region_count "$validator_region_count" \
  --argjson validator_country_count "$validator_country_count" \
  --argjson manual_sanctions_reversed_pct_90d "$manual_sanctions_reversed_pct_90d" \
  --argjson abuse_report_to_decision_p95_hours "$abuse_report_to_decision_p95_hours" \
  --argjson subsidy_runway_months "$subsidy_runway_months" \
  --argjson contribution_margin_3mo "$contribution_margin_3mo" \
  '{
    version: 1,
    schema: {id: "blockchain_mainnet_activation_metrics_input_template", major: 1, minor: 0},
    status: "ok",
    include_example_values: ($include_example_values == 1),
    general: {
      measurement_window_weeks: $measurement_window_weeks
    },
    reliability: {
      vpn_connect_session_success_slo_pct: $vpn_connect_session_success_slo_pct,
      vpn_recovery_mttr_p95_minutes: $vpn_recovery_mttr_p95_minutes
    },
    demand: {
      paying_users_3mo_min: $paying_users_3mo_min,
      paid_sessions_per_day_30d_avg: $paid_sessions_per_day_30d_avg
    },
    validator: {
      validator_candidate_depth: $validator_candidate_depth,
      validator_independent_operators: $validator_independent_operators,
      validator_max_operator_seat_share_pct: $validator_max_operator_seat_share_pct,
      validator_max_asn_provider_seat_share_pct: $validator_max_asn_provider_seat_share_pct,
      validator_region_count: $validator_region_count,
      validator_country_count: $validator_country_count
    },
    governance: {
      manual_sanctions_reversed_pct_90d: $manual_sanctions_reversed_pct_90d,
      abuse_report_to_decision_p95_hours: $abuse_report_to_decision_p95_hours
    },
    economics: {
      subsidy_runway_months: $subsidy_runway_months,
      contribution_margin_3mo: $contribution_margin_3mo
    },
    measurement_window_weeks: $measurement_window_weeks,
    vpn_connect_session_success_slo_pct: $vpn_connect_session_success_slo_pct,
    vpn_recovery_mttr_p95_minutes: $vpn_recovery_mttr_p95_minutes,
    paying_users_3mo_min: $paying_users_3mo_min,
    paid_sessions_per_day_30d_avg: $paid_sessions_per_day_30d_avg,
    validator_candidate_depth: $validator_candidate_depth,
    validator_independent_operators: $validator_independent_operators,
    validator_max_operator_seat_share_pct: $validator_max_operator_seat_share_pct,
    validator_max_asn_provider_seat_share_pct: $validator_max_asn_provider_seat_share_pct,
    validator_region_count: $validator_region_count,
    validator_country_count: $validator_country_count,
    manual_sanctions_reversed_pct_90d: $manual_sanctions_reversed_pct_90d,
    abuse_report_to_decision_p95_hours: $abuse_report_to_decision_p95_hours,
    subsidy_runway_months: $subsidy_runway_months,
    contribution_margin_3mo: $contribution_margin_3mo,
    artifacts: {
      output_json: $output_json,
      canonical_output_json: $canonical_output_json
    }
  }' >"$tmp_json"

cp "$tmp_json" "$output_json"
if [[ "$canonical_output_json" != "$output_json" ]]; then
  cp "$tmp_json" "$canonical_output_json"
fi

echo "[blockchain-mainnet-activation-metrics-input-template] status=ok include_example_values=$include_example_values output_json=$output_json canonical_output_json=$canonical_output_json"

if [[ "$print_output_json" == "1" ]]; then
  cat "$output_json"
fi

exit 0
