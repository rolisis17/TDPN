#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/blockchain_mainnet_activation_metrics.sh \
    [--summary-json PATH] \
    [--canonical-summary-json PATH] \
    [--source-json PATH] \
    [--print-summary-json [0|1]] \
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
  Produce deterministic blockchain mainnet activation metrics JSON that is
  directly consumable by scripts/blockchain_mainnet_activation_gate.sh.

Notes:
  - Required gate metrics default to null when omitted.
  - Missing/partial inputs are fail-soft: script exits 0 and reports coverage.
  - `--source-json PATH` is repeatable and accepts source artifacts for
    auto-population of missing metrics.
  - Source artifact fallback env:
      BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_SOURCE_JSONS=path1.json,path2.json
  - Each metric can also be set via environment variable:
      BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_<UPPER_SNAKE_CASE_METRIC_NAME>
    Example:
      BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_PAYING_USERS_3MO_MIN=1200
  - Output paths can be provided by:
      --summary-json / BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_SUMMARY_JSON
      --canonical-summary-json / BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_CANONICAL_SUMMARY_JSON
  - --metrics-json and --canonical-metrics-json are accepted aliases for
    summary/canonical-summary paths.
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

assign_metric_value() {
  local key="$1"
  local raw_value="$2"
  local source="$3"
  raw_value="$(trim "$raw_value")"
  if [[ -z "$raw_value" ]]; then
    metric_raw["$key"]=""
    metric_source["$key"]="${source}_empty"
    return
  fi
  metric_raw["$key"]="$raw_value"
  metric_source["$key"]="$source"
}

metric_locked_by_user() {
  local source="${1:-}"
  if [[ "$source" == env* || "$source" == cli* ]]; then
    return 0
  fi
  return 1
}

extract_metric_from_source_json() {
  local source_json="$1"
  local key="$2"
  local raw=""
  local numeric=""

  if [[ -z "$source_json" || ! -f "$source_json" ]]; then
    printf '%s' ""
    return
  fi

  raw="$(jq -r --arg key "$key" '
    limit(1;
      (
        (.[$key] | select(type == "number")),
        (.. | objects | .[$key]? | select(type == "number"))
      )
    )
  ' "$source_json" 2>/dev/null || true)"
  numeric="$(numeric_text_or_empty "$raw")"
  printf '%s' "$numeric"
}

need_cmd jq
need_cmd cp

summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_SUMMARY_JSON:-}"
canonical_summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_CANONICAL_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/blockchain_mainnet_activation_metrics.json}"
print_summary_json="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_PRINT_SUMMARY_JSON:-0}"
source_jsons_env_csv="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_SOURCE_JSONS:-}"
summary_json_source="env"
canonical_summary_json_source="env"

declare -a source_jsons_cli=()
declare -a source_jsons_env=()
declare -a source_jsons=()
declare -a usable_source_jsons=()

if [[ -z "$(trim "$summary_json")" ]]; then
  summary_json="$ROOT_DIR/.easy-node-logs/blockchain_mainnet_activation_metrics_summary.json"
  summary_json_source="default"
fi
if [[ -z "$(trim "$canonical_summary_json")" ]]; then
  canonical_summary_json="$ROOT_DIR/.easy-node-logs/blockchain_mainnet_activation_metrics.json"
  canonical_summary_json_source="default"
fi
if [[ -n "$(trim "$summary_json")" ]]; then
  path_arg_or_die "--summary-json" "$summary_json"
fi
if [[ -n "$(trim "$canonical_summary_json")" ]]; then
  path_arg_or_die "--canonical-summary-json" "$canonical_summary_json"
fi

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

required_metric_keys=(
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

optional_metric_keys=(
  measurement_window_weeks
)

declare -A known_metric=()
declare -A metric_raw=()
declare -A metric_source=()
declare -A metric_json=()

for key in "${metric_keys[@]}"; do
  known_metric["$key"]="1"
  metric_raw["$key"]=""
  metric_source["$key"]="default_null"
  metric_json["$key"]="null"
done

for key in "${metric_keys[@]}"; do
  env_name="BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_${key^^}"
  env_value="${!env_name:-}"
  if [[ -n "$(trim "$env_value")" ]]; then
    assign_metric_value "$key" "$env_value" "env"
  fi
done

if [[ -n "$(trim "$source_jsons_env_csv")" ]]; then
  IFS=',' read -r -a source_jsons_env_raw <<<"$source_jsons_env_csv"
  for source_json in "${source_jsons_env_raw[@]}"; do
    source_json="$(trim "$source_json")"
    if [[ -n "$source_json" ]]; then
      source_jsons_env+=("$source_json")
    fi
  done
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json|--metrics-json)
      path_arg_or_die "$1" "${2:-}"
      summary_json="${2:-}"
      summary_json_source="arg"
      shift 2
      ;;
    --canonical-summary-json|--canonical-metrics-json)
      path_arg_or_die "$1" "${2:-}"
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
    --source-json)
      path_arg_or_die "$1" "${2:-}"
      source_jsons_cli+=("${2:-}")
      shift 2
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    --*)
      metric_key="${1#--}"
      metric_key="${metric_key//-/_}"
      if [[ "${known_metric[$metric_key]:-0}" == "1" ]]; then
        assign_metric_value "$metric_key" "${2:-}" "cli"
        shift 2
      else
        echo "unknown argument: $1"
        usage
        exit 2
      fi
      ;;
    *)
      echo "unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

bool_arg_or_die "--print-summary-json" "$print_summary_json"

if ((${#source_jsons_cli[@]} > 0)); then
  source_jsons=("${source_jsons_cli[@]}")
else
  source_jsons=("${source_jsons_env[@]}")
fi

if ((${#source_jsons[@]} > 0)); then
  declare -a source_jsons_abs=()
  for source_json in "${source_jsons[@]}"; do
    source_json="$(trim "$source_json")"
    if [[ -n "$source_json" ]]; then
      path_arg_or_die "--source-json" "$source_json"
      source_jsons_abs+=("$(abs_path "$source_json")")
    fi
  done
  source_jsons=("${source_jsons_abs[@]}")
fi

summary_json="$(abs_path "$summary_json")"
canonical_summary_json="$(abs_path "$canonical_summary_json")"
mkdir -p "$(dirname "$summary_json")"
mkdir -p "$(dirname "$canonical_summary_json")"

for source_json in "${source_jsons[@]}"; do
  if [[ ! -f "$source_json" ]]; then
    continue
  fi
  if ! jq -e . "$source_json" >/dev/null 2>&1; then
    continue
  fi
  usable_source_jsons+=("$source_json")
  for key in "${metric_keys[@]}"; do
    if metric_locked_by_user "${metric_source[$key]}"; then
      continue
    fi
    if [[ -n "$(trim "${metric_raw[$key]}")" ]]; then
      continue
    fi
    extracted_value="$(extract_metric_from_source_json "$source_json" "$key")"
    if [[ -z "$extracted_value" ]]; then
      continue
    fi
    metric_raw["$key"]="$extracted_value"
    metric_source["$key"]="source_json"
  done
done

declare -a required_missing_metrics=()
declare -a required_provided_metrics=()
declare -a invalid_metrics=()

required_provided_count=0
required_missing_count=0
required_invalid_count=0

for key in "${required_metric_keys[@]}"; do
  raw_value="${metric_raw[$key]}"
  if [[ -z "$raw_value" ]]; then
    metric_json["$key"]="null"
    required_missing_metrics+=("$key")
    required_missing_count=$((required_missing_count + 1))
    continue
  fi

  numeric_value="$(numeric_text_or_empty "$raw_value")"
  if [[ -z "$numeric_value" ]]; then
    metric_json["$key"]="null"
    metric_source["$key"]="${metric_source[$key]}_invalid"
    required_missing_metrics+=("$key")
    invalid_metrics+=("$key")
    required_missing_count=$((required_missing_count + 1))
    required_invalid_count=$((required_invalid_count + 1))
    continue
  fi

  metric_json["$key"]="$numeric_value"
  required_provided_metrics+=("$key")
  required_provided_count=$((required_provided_count + 1))
done

for key in "${optional_metric_keys[@]}"; do
  raw_value="${metric_raw[$key]}"
  if [[ -z "$raw_value" ]]; then
    metric_json["$key"]="null"
    continue
  fi

  numeric_value="$(numeric_text_or_empty "$raw_value")"
  if [[ -z "$numeric_value" ]]; then
    metric_json["$key"]="null"
    metric_source["$key"]="${metric_source[$key]}_invalid"
    invalid_metrics+=("$key")
    continue
  fi

  metric_json["$key"]="$numeric_value"
done

status="partial"
if (( required_provided_count == 0 && required_invalid_count == 0 )); then
  status="missing"
elif (( required_missing_count == 0 && required_invalid_count == 0 )); then
  status="complete"
fi

ready_for_gate="0"
if [[ "$status" == "complete" ]]; then
  ready_for_gate="1"
fi

required_metric_keys_json="$(array_to_json required_metric_keys)"
optional_metric_keys_json="$(array_to_json optional_metric_keys)"
required_missing_metrics_json="$(array_to_json required_missing_metrics)"
required_provided_metrics_json="$(array_to_json required_provided_metrics)"
invalid_metrics_json="$(array_to_json invalid_metrics)"
source_jsons_json="$(array_to_json source_jsons)"
usable_source_jsons_json="$(array_to_json usable_source_jsons)"

metrics_values_json='{}'
sources_metrics_json='{}'
for key in "${metric_keys[@]}"; do
  metrics_values_json="$(jq -c \
    --arg key "$key" \
    --argjson value "${metric_json[$key]}" \
    '. + {($key): $value}' <<<"$metrics_values_json")"
  sources_metrics_json="$(jq -c \
    --arg key "$key" \
    --arg source "${metric_source[$key]}" \
    '. + {($key): $source}' <<<"$sources_metrics_json")"
done

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
canonical_tmp="$(mktemp "${canonical_summary_json}.tmp.XXXXXX")"
cleanup() {
  rm -f "$summary_tmp" "$canonical_tmp"
}
trap cleanup EXIT

jq -n \
  --arg schema_id "blockchain_mainnet_activation_metrics_summary" \
  --arg status "$status" \
  --argjson rc 0 \
  --argjson ready_for_gate "$ready_for_gate" \
  --argjson required_metric_count "${#required_metric_keys[@]}" \
  --argjson required_provided_count "$required_provided_count" \
  --argjson required_missing_count "$required_missing_count" \
  --argjson required_invalid_count "$required_invalid_count" \
  --argjson required_metric_keys "$required_metric_keys_json" \
  --argjson optional_metric_keys "$optional_metric_keys_json" \
  --argjson required_missing_metrics "$required_missing_metrics_json" \
  --argjson required_provided_metrics "$required_provided_metrics_json" \
  --argjson invalid_metrics "$invalid_metrics_json" \
  --arg summary_json "$summary_json" \
  --arg canonical_summary_json "$canonical_summary_json" \
  --arg summary_json_source "$summary_json_source" \
  --arg canonical_summary_json_source "$canonical_summary_json_source" \
  --argjson source_jsons "$source_jsons_json" \
  --argjson usable_source_jsons "$usable_source_jsons_json" \
  --argjson sources_metrics "$sources_metrics_json" \
  --argjson metrics_values "$metrics_values_json" \
  '{
    version: 1,
    schema: {id: $schema_id, major: 1, minor: 0},
    status: $status,
    rc: $rc,
    ready_for_gate: ($ready_for_gate == 1),
    counts: {
      required: $required_metric_count,
      provided: $required_provided_count,
      missing: $required_missing_count,
      invalid: $required_invalid_count
    },
    required_metric_keys: $required_metric_keys,
    optional_metric_keys: $optional_metric_keys,
    required_missing_metrics: $required_missing_metrics,
    required_provided_metrics: $required_provided_metrics,
    invalid_metrics: $invalid_metrics,
    sources: {
      summary_json: $summary_json_source,
      canonical_summary_json: $canonical_summary_json_source,
      source_jsons: $source_jsons,
      usable_source_jsons: $usable_source_jsons,
      metrics: $sources_metrics
    },
    metrics: $metrics_values,
    artifacts: {
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

echo "[blockchain-mainnet-activation-metrics] status=$status ready_for_gate=$ready_for_gate required_provided=$required_provided_count required_missing=$required_missing_count required_invalid=$required_invalid_count summary_json=$summary_json canonical_summary_json=$canonical_summary_json"
echo "[blockchain-mainnet-activation-metrics] required_missing_metrics=$(jq -r '.required_missing_metrics | if length == 0 then "none" else join(",") end' "$summary_json")"
echo "[blockchain-mainnet-activation-metrics] invalid_metrics=$(jq -r '.invalid_metrics | if length == 0 then "none" else join(",") end' "$summary_json")"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit 0
