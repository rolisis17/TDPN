#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/blockchain_mainnet_activation_metrics_missing_checklist.sh \
    --metrics-summary-json PATH \
    [--output-json PATH] \
    [--output-md PATH] \
    [--print-output-json [0|1]]

Purpose:
  Emit a deterministic checklist of still-missing required mainnet activation
  metrics from canonical metrics summary artifacts.

Notes:
  - Accepts summaries produced by:
      scripts/blockchain_mainnet_activation_metrics.sh
      scripts/blockchain_gate_bundle.sh
  - Fail-soft by default: exits 0 and emits checklist status/outputs even when
    the input summary is missing/invalid.
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

metric_spec_fields() {
  local key="$1"
  case "$key" in
    measurement_window_weeks) printf '%s' "Readiness window|>=|12|weeks|Confirm the rolling observation window covers at least 12 full weeks." ;;
    vpn_connect_session_success_slo_pct) printf '%s' "VPN reliability|>=|99.5|percent|Use production telemetry to report rolling connect/session success SLO." ;;
    vpn_recovery_mttr_p95_minutes) printf '%s' "VPN reliability|<=|30|minutes|Report P95 recovery MTTR from incident/repair telemetry." ;;
    paying_users_3mo_min) printf '%s' "Demand|>=|1000|clients|Use a 3-month active paying-user floor from billing records." ;;
    paid_sessions_per_day_30d_avg) printf '%s' "Demand|>=|10000|sessions/day|Use rolling 30-day daily paid-session average from settlement counters." ;;
    validator_candidate_depth) printf '%s' "Validator supply|>=|30|servers|Count launch-ready validator candidates after policy screening." ;;
    validator_independent_operators) printf '%s' "Validator decentralization|>=|12|operators|Count independent validator operators in the active candidate set." ;;
    validator_max_operator_seat_share_pct) printf '%s' "Validator decentralization|<=|20|percent|Compute max operator seat concentration across active candidates." ;;
    validator_max_asn_provider_seat_share_pct) printf '%s' "Validator decentralization|<=|25|percent|Compute max ASN/provider concentration across active candidates." ;;
    validator_region_count) printf '%s' "Validator decentralization|>=|4|regions|Count unique regions represented in active validator candidates." ;;
    validator_country_count) printf '%s' "Validator decentralization|>=|8|countries|Count unique countries represented in active validator candidates." ;;
    manual_sanctions_reversed_pct_90d) printf '%s' "Governance quality|<|5|percent|Track 90-day reversal rate for manual sanctions decisions." ;;
    abuse_report_to_decision_p95_hours) printf '%s' "Governance quality|<=|24|hours|Report P95 time from abuse report intake to final decision." ;;
    subsidy_runway_months) printf '%s' "Economics|>=|12|months|Model subsidy runway at current burn with conservative assumptions." ;;
    contribution_margin_3mo) printf '%s' "Economics|>|0|margin|Use rolling 3-month contribution margin net of direct delivery costs." ;;
    *)
      printf '%s' "Unmapped|?|unknown|unknown|Metric key is not mapped; verify gate policy metadata manually."
      ;;
  esac
}

need_cmd jq
need_cmd cp

metrics_summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_MISSING_CHECKLIST_METRICS_SUMMARY_JSON:-}"
output_json="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_MISSING_CHECKLIST_OUTPUT_JSON:-$ROOT_DIR/.easy-node-logs/blockchain_mainnet_activation_metrics_missing_checklist.json}"
output_md="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_MISSING_CHECKLIST_OUTPUT_MD:-}"
print_output_json="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_MISSING_CHECKLIST_PRINT_OUTPUT_JSON:-0}"

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
    --output-md)
      path_arg_or_die "--output-md" "${2:-}"
      output_md="${2:-}"
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

if [[ -z "$(trim "$metrics_summary_json")" ]]; then
  echo "--metrics-summary-json is required"
  usage
  exit 2
fi

path_arg_or_die "--metrics-summary-json" "$metrics_summary_json"
path_arg_or_die "--output-json" "$output_json"
if [[ -n "$(trim "$output_md")" ]]; then
  path_arg_or_die "--output-md" "$output_md"
fi
bool_arg_or_die "--print-output-json" "$print_output_json"

metrics_summary_json="$(abs_path "$metrics_summary_json")"
output_json="$(abs_path "$output_json")"
if [[ -n "$(trim "$output_md")" ]]; then
  output_md="$(abs_path "$output_md")"
fi

mkdir -p "$(dirname "$output_json")"
if [[ -n "$output_md" ]]; then
  mkdir -p "$(dirname "$output_md")"
fi

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
declare -A missing_lookup=()
for key in "${required_metric_keys[@]}"; do
  required_metric_known["$key"]="1"
done

input_state="available"
input_valid_json="true"
source_schema_id=""
missing_keys_json="[]"

if [[ ! -f "$metrics_summary_json" ]]; then
  input_state="missing"
  input_valid_json="false"
elif ! jq -e . "$metrics_summary_json" >/dev/null 2>&1; then
  input_state="invalid"
  input_valid_json="false"
else
  source_schema_id="$(jq -r '.schema.id // ""' "$metrics_summary_json" 2>/dev/null || true)"
  missing_keys_json="$(
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

if [[ "$input_state" != "available" ]]; then
  missing_keys_json="$(printf '%s\n' "${required_metric_keys[@]}" | jq -R . | jq -s .)"
fi

while IFS= read -r key; do
  key="$(trim "$key")"
  if [[ -z "$key" ]]; then
    continue
  fi
  missing_lookup["$key"]="1"
done < <(jq -r '.[]?' <<<"$missing_keys_json" 2>/dev/null || true)

checklist_json='[]'
checklist_key_order_json='[]'
known_entry_count=0
unknown_entry_count=0

for key in "${required_metric_keys[@]}"; do
  if [[ "${missing_lookup[$key]:-0}" != "1" ]]; then
    continue
  fi
  spec="$(metric_spec_fields "$key")"
  IFS='|' read -r category comparator threshold unit hint <<<"$spec"
  entry_json="$(jq -n \
    --arg key "$key" \
    --arg category "$category" \
    --arg comparator "$comparator" \
    --arg threshold "$threshold" \
    --arg unit "$unit" \
    --arg hint "$hint" \
    '{
      key: $key,
      category: $category,
      comparator: $comparator,
      threshold: $threshold,
      unit: $unit,
      hint: $hint
    }')"
  checklist_json="$(jq -c --argjson entry "$entry_json" '. + [$entry]' <<<"$checklist_json")"
  checklist_key_order_json="$(jq -c --arg key "$key" '. + [$key]' <<<"$checklist_key_order_json")"
  known_entry_count=$((known_entry_count + 1))
done

declare -a unknown_missing_keys=()
for key in "${!missing_lookup[@]}"; do
  if [[ "${required_metric_known[$key]:-0}" == "1" ]]; then
    continue
  fi
  unknown_missing_keys+=("$key")
done
if ((${#unknown_missing_keys[@]} > 0)); then
  IFS=$'\n' unknown_missing_keys=($(printf '%s\n' "${unknown_missing_keys[@]}" | LC_ALL=C sort))
  unset IFS
fi

for key in "${unknown_missing_keys[@]}"; do
  spec="$(metric_spec_fields "$key")"
  IFS='|' read -r category comparator threshold unit hint <<<"$spec"
  entry_json="$(jq -n \
    --arg key "$key" \
    --arg category "$category" \
    --arg comparator "$comparator" \
    --arg threshold "$threshold" \
    --arg unit "$unit" \
    --arg hint "$hint" \
    '{
      key: $key,
      category: $category,
      comparator: $comparator,
      threshold: $threshold,
      unit: $unit,
      hint: $hint
    }')"
  checklist_json="$(jq -c --argjson entry "$entry_json" '. + [$entry]' <<<"$checklist_json")"
  checklist_key_order_json="$(jq -c --arg key "$key" '. + [$key]' <<<"$checklist_key_order_json")"
  unknown_entry_count=$((unknown_entry_count + 1))
done

missing_count="$(jq -r 'length' <<<"$checklist_json")"
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
  --arg schema_id "blockchain_mainnet_activation_metrics_missing_checklist" \
  --arg status "$status" \
  --argjson rc 0 \
  --arg metrics_summary_json "$metrics_summary_json" \
  --arg input_state "$input_state" \
  --argjson input_valid "$input_valid_json" \
  --arg source_schema_id "$source_schema_id" \
  --argjson required_expected "${#required_metric_keys[@]}" \
  --argjson missing_count "$missing_count" \
  --argjson known_entry_count "$known_entry_count" \
  --argjson unknown_entry_count "$unknown_entry_count" \
  --argjson checklist "$checklist_json" \
  --argjson missing_metric_keys "$checklist_key_order_json" \
  --arg output_json "$output_json" \
  --arg output_md "$output_md" \
  '{
    version: 1,
    schema: {id: $schema_id, major: 1, minor: 0},
    status: $status,
    rc: $rc,
    input: {
      metrics_summary_json: $metrics_summary_json,
      state: $input_state,
      valid: ($input_valid == true),
      source_schema_id: (if $source_schema_id == "" then null else $source_schema_id end)
    },
    counts: {
      required_expected: $required_expected,
      missing: $missing_count,
      checklist_entries: $missing_count,
      known_entries: $known_entry_count,
      unknown_entries: $unknown_entry_count
    },
    missing_metric_keys: $missing_metric_keys,
    checklist: $checklist,
    artifacts: {
      output_json: $output_json,
      output_md: (if $output_md == "" then null else $output_md end)
    }
  }' >"$summary_tmp"

mv -f "$summary_tmp" "$output_json"

if [[ -n "$output_md" ]]; then
  {
    echo "# Blockchain Mainnet Activation Missing Metrics Checklist"
    echo
    echo "- status: $(jq -r '.status' "$output_json")"
    echo "- missing_count: $(jq -r '.counts.missing' "$output_json")"
    echo "- metrics_summary_json: $(jq -r '.input.metrics_summary_json' "$output_json")"
    echo
    if [[ "$status" == "complete" ]]; then
      echo "No missing required metrics detected."
    else
      echo "| key | category | comparator | threshold | unit | hint |"
      echo "| --- | --- | --- | --- | --- | --- |"
      jq -r '.checklist[] | "| \(.key) | \(.category) | \(.comparator) | \(.threshold) | \(.unit) | \(.hint) |"' "$output_json"
    fi
  } >"$output_md"
fi

echo "[blockchain-mainnet-activation-metrics-missing-checklist] status=$status missing_count=$missing_count metrics_summary_json=$metrics_summary_json output_json=$output_json output_md=${output_md:-none}"

if [[ "$print_output_json" == "1" ]]; then
  cat "$output_json"
fi

exit 0
