#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/blockchain_mainnet_activation_metrics_prefill.sh \
    [--reports-dir PATH] \
    [--metrics-summary-json PATH] \
    [--output-json PATH] \
    [--canonical-output-json PATH] \
    [--source-json PATH] \
    [--print-output-json [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Prefill blockchain mainnet activation metrics from existing JSON artifacts in
  a deterministic, fail-soft way. Explicit --source-json inputs are checked
  first, then the default blockchain artifact set under reports-dir.

Default source artifacts under reports-dir:
  - blockchain_gate_bundle_summary.json
  - phase5_settlement_layer_summary_report.json
  - phase6_cosmos_l1_summary_report.json
  - phase7_mainnet_cutover_summary_report.json
  - manual_after_dryfix_roadmap_summary.json
  - blockchain_mainnet_activation_metrics_summary.json
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

resolve_path_with_base() {
  local candidate
  local base_file
  local base_dir=""
  candidate="$(trim "${1:-}")"
  base_file="$(trim "${2:-}")"
  if [[ -z "$candidate" ]]; then
    printf '%s' ""
    return
  fi
  if [[ "$candidate" == /* ]]; then
    printf '%s' "$candidate"
    return
  fi
  if [[ -n "$base_file" ]]; then
    base_dir="$(cd "$(dirname "$base_file")" && pwd)"
    if [[ -f "$base_dir/$candidate" ]]; then
      printf '%s' "$base_dir/$candidate"
      return
    fi
  fi
  printf '%s' "$(abs_path "$candidate")"
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

add_unique_source() {
  local -n paths_ref=$1
  local -n labels_ref=$2
  local label="$3"
  local path
  path="$(abs_path "${4:-}")"
  local existing
  for existing in "${paths_ref[@]}"; do
    if [[ "$existing" == "$path" ]]; then
      return 0
    fi
  done
  paths_ref+=("$path")
  labels_ref+=("$label")
}

extract_numeric_from_source_json() {
  local source_json="$1"
  local key="$2"
  local raw=""

  raw="$(jq -r --arg key "$key" '
    if (.[$key] | type) == "number" then .[$key] else empty end
  ' "$source_json" 2>/dev/null || true)"
  if [[ -n "$raw" ]]; then
    numeric_text_or_empty "$raw"
    return 0
  fi

  raw="$(jq -r --arg key "$key" '
    limit(1; .. | objects | .[$key]? | select(type == "number"))
  ' "$source_json" 2>/dev/null || true)"
  numeric_text_or_empty "$raw"
}

need_cmd jq
need_cmd cp
need_cmd mktemp

reports_dir="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_PREFILL_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"
metrics_summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_PREFILL_METRICS_SUMMARY_JSON:-}"
output_json="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_PREFILL_OUTPUT_JSON:-$reports_dir/blockchain_mainnet_activation_metrics_prefill.json}"
canonical_output_json="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_PREFILL_CANONICAL_OUTPUT_JSON:-$output_json}"
print_output_json="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_PREFILL_PRINT_OUTPUT_JSON:-0}"

declare -a source_jsons_cli=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      path_arg_or_die "--reports-dir" "${2:-}"
      reports_dir="${2:-}"
      shift 2
      ;;
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
    --source-json)
      path_arg_or_die "--source-json" "${2:-}"
      source_jsons_cli+=("${2:-}")
      shift 2
      ;;
    --print-output-json|--print-summary-json)
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

bool_arg_or_die "--print-{output|summary}-json" "$print_output_json"

path_arg_or_die "--reports-dir" "$reports_dir"
path_arg_or_die "--output-json" "$output_json"
path_arg_or_die "--canonical-output-json" "$canonical_output_json"
if [[ -n "$(trim "$metrics_summary_json")" ]]; then
  path_arg_or_die "--metrics-summary-json" "$metrics_summary_json"
fi

reports_dir="$(abs_path "$reports_dir")"
if [[ -n "$(trim "$metrics_summary_json")" ]]; then
  metrics_summary_json="$(abs_path "$metrics_summary_json")"
fi
output_json="$(abs_path "$output_json")"
canonical_output_json="$(abs_path "$canonical_output_json")"

mkdir -p "$reports_dir"
mkdir -p "$(dirname "$output_json")"
mkdir -p "$(dirname "$canonical_output_json")"

default_source_labels=(
  blockchain_gate_bundle_summary
  phase5_settlement_layer_summary_report
  phase6_cosmos_l1_summary_report
  phase7_mainnet_cutover_summary_report
  manual_after_dryfix_roadmap_summary
  blockchain_mainnet_activation_metrics_summary
)

default_source_paths=(
  "$reports_dir/blockchain_gate_bundle_summary.json"
  "$reports_dir/phase5_settlement_layer_summary_report.json"
  "$reports_dir/phase6_cosmos_l1_summary_report.json"
  "$reports_dir/phase7_mainnet_cutover_summary_report.json"
  "$reports_dir/manual_after_dryfix_roadmap_summary.json"
  "$reports_dir/blockchain_mainnet_activation_metrics_summary.json"
)

declare -a source_paths=()
declare -a source_labels=()

if [[ -n "$(trim "$metrics_summary_json")" ]]; then
  add_unique_source source_paths source_labels "metrics_summary_json" "$metrics_summary_json"
fi

for idx in "${!source_jsons_cli[@]}"; do
  add_unique_source source_paths source_labels "explicit_source_json_$((idx + 1))" "${source_jsons_cli[$idx]}"
done

for idx in "${!default_source_paths[@]}"; do
  add_unique_source source_paths source_labels "${default_source_labels[$idx]}" "${default_source_paths[$idx]}"
done

# Expand source candidates by following one-hop JSON artifact references
# discovered inside each initially configured source file. This lets summary
# wrappers contribute referenced metrics artifacts without exploding into deep
# recursive crawls across all referenced JSON files.
initial_source_count=${#source_paths[@]}
for ((processed_source_index=0; processed_source_index<initial_source_count; processed_source_index++)); do
  source_path="${source_paths[$processed_source_index]}"
  source_label="${source_labels[$processed_source_index]}"
  if [[ -f "$source_path" ]] && jq -e . "$source_path" >/dev/null 2>&1; then
    ref_index=0
    while IFS= read -r source_ref_path; do
      source_ref_path="$(trim "$source_ref_path")"
      if [[ -z "$source_ref_path" ]]; then
        continue
      fi
      resolved_ref_path="$(resolve_path_with_base "$source_ref_path" "$source_path")"
      if [[ -z "$resolved_ref_path" || ! -f "$resolved_ref_path" ]]; then
        continue
      fi
      if ! jq -e . "$resolved_ref_path" >/dev/null 2>&1; then
        continue
      fi
      ref_index=$((ref_index + 1))
      add_unique_source source_paths source_labels "${source_label}_ref_json_$ref_index" "$resolved_ref_path"
    done < <(
      jq -r '
        [.. | strings | select(test("\\.json$"))]
        | unique[]
      ' "$source_path" 2>/dev/null || true
    )
  fi
done

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

declare -A metric_value_json=()
declare -A metric_source=()
for key in "${metric_keys[@]}"; do
  metric_value_json["$key"]="null"
  metric_source["$key"]="missing"
done

source_candidates_json="[]"
declare -a usable_sources=()

for idx in "${!source_paths[@]}"; do
  source_path="${source_paths[$idx]}"
  source_label="${source_labels[$idx]}"
  exists="0"
  valid_json="0"
  usable="0"
  status="missing"

  if [[ -f "$source_path" ]]; then
    exists="1"
    if jq -e . "$source_path" >/dev/null 2>&1; then
      valid_json="1"
      usable="1"
      status="usable"
      usable_sources+=("$source_path")
    else
      status="invalid_json"
    fi
  fi

  candidate_json="$(
    jq -n \
      --arg label "$source_label" \
      --arg path "$source_path" \
      --argjson exists "$exists" \
      --argjson valid_json "$valid_json" \
      --argjson usable "$usable" \
      --arg status "$status" \
      '{
        label: $label,
        path: $path,
        exists: ($exists == 1),
        valid_json: ($valid_json == 1),
        usable: ($usable == 1),
        status: $status
      }'
  )"
  source_candidates_json="$(jq -c --argjson candidate "$candidate_json" '. + [$candidate]' <<<"$source_candidates_json")"

  if [[ "$usable" != "1" ]]; then
    continue
  fi

  for key in "${metric_keys[@]}"; do
    if [[ "${metric_value_json[$key]}" != "null" ]]; then
      continue
    fi
    numeric_value="$(extract_numeric_from_source_json "$source_path" "$key")"
    if [[ -n "$numeric_value" ]]; then
      metric_value_json["$key"]="$numeric_value"
      metric_source["$key"]="$source_path"
    fi
  done
done

provided_metric_keys=()
missing_metric_keys=()
provided_count=0
missing_count=0
for key in "${metric_keys[@]}"; do
  if [[ "${metric_value_json[$key]}" != "null" ]]; then
    provided_metric_keys+=("$key")
    provided_count=$((provided_count + 1))
  else
    missing_metric_keys+=("$key")
    missing_count=$((missing_count + 1))
  fi
done

status="partial"
if (( provided_count == 0 )); then
  status="missing"
elif (( missing_count == 0 )); then
  status="complete"
fi

metrics_json="{}"
metric_sources_json="[]"
for key in "${metric_keys[@]}"; do
  metrics_json="$(jq -c --arg key "$key" --argjson value "${metric_value_json[$key]}" '. + {($key): $value}' <<<"$metrics_json")"
  source_entry_json="$(
    jq -n \
      --arg metric_key "$key" \
      --arg source "${metric_source[$key]}" \
      '{metric_key: $metric_key, source: $source}'
  )"
  metric_sources_json="$(jq -c --argjson entry "$source_entry_json" '. + [$entry]' <<<"$metric_sources_json")"
done

metric_keys_json="$(array_to_json metric_keys)"
provided_metric_keys_json="$(array_to_json provided_metric_keys)"
missing_metric_keys_json="$(array_to_json missing_metric_keys)"
usable_sources_json="$(array_to_json usable_sources)"

tmp_output_json="$(mktemp "${output_json}.tmp.XXXXXX")"
tmp_canonical_output_json="$(mktemp "${canonical_output_json}.tmp.XXXXXX")"
cleanup() {
  rm -f "$tmp_output_json" "$tmp_canonical_output_json"
}
trap cleanup EXIT

jq -n \
  --arg schema_id "blockchain_mainnet_activation_metrics_prefill" \
  --arg id "blockchain_mainnet_activation_metrics_prefill" \
  --arg status "$status" \
  --arg reports_dir "$reports_dir" \
  --arg output_json "$output_json" \
  --arg canonical_output_json "$canonical_output_json" \
  --argjson source_candidates "$source_candidates_json" \
  --argjson usable_sources "$usable_sources_json" \
  --argjson metric_keys "$metric_keys_json" \
  --argjson provided_count "$provided_count" \
  --argjson missing_count "$missing_count" \
  --argjson metrics "$metrics_json" \
  --argjson metric_sources "$metric_sources_json" \
  --argjson provided_metric_keys "$provided_metric_keys_json" \
  --argjson missing_metric_keys "$missing_metric_keys_json" \
  '({
    version: 1,
    id: $id,
    schema: {id: $schema_id, major: 1, minor: 0},
    status: $status,
    reports_dir: $reports_dir,
    source_candidates: $source_candidates,
    usable_sources: $usable_sources,
    coverage: {
      required: ($metric_keys | length),
      provided: $provided_count,
      missing: $missing_count
    },
    provided_metric_keys: $provided_metric_keys,
    missing_metric_keys: $missing_metric_keys,
    metrics: $metrics,
    metric_sources: $metric_sources,
    artifacts: {
      output_json: $output_json,
      canonical_output_json: $canonical_output_json
    }
  } + $metrics)' >"$tmp_output_json"

cp -f "$tmp_output_json" "$output_json"
if [[ "$canonical_output_json" != "$output_json" ]]; then
  cp -f "$tmp_output_json" "$tmp_canonical_output_json"
  mv -f "$tmp_canonical_output_json" "$canonical_output_json"
fi

echo "[blockchain-mainnet-activation-metrics-prefill] status=$status provided=$provided_count missing=$missing_count source_candidates=$(jq -r '.source_candidates | length' "$output_json") usable_sources=$(jq -r '.usable_sources | length' "$output_json")"
echo "[blockchain-mainnet-activation-metrics-prefill] output_json=$output_json canonical_output_json=$canonical_output_json"

if [[ "$print_output_json" == "1" ]]; then
  cat "$output_json"
fi

exit 0
