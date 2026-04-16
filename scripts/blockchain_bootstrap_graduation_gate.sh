#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/blockchain_bootstrap_graduation_gate.sh \
    [--metrics-json PATH] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]] \
    [--fail-close [0|1]]

Purpose:
  Evaluate bootstrap governance graduation readiness from objective metrics in
  docs/blockchain-bootstrap-validator-plan.md and emit one GO/NO-GO summary JSON.

Notes:
  - The metrics input path can be provided by:
    - --metrics-json PATH
    - BLOCKCHAIN_BOOTSTRAP_GRADUATION_GATE_METRICS_JSON
  - The summary path can be provided by:
    - --summary-json PATH
    - BLOCKCHAIN_BOOTSTRAP_GRADUATION_GATE_SUMMARY_JSON
  - Use --fail-close=1 to return non-zero on NO-GO or missing/invalid input.
  - Exit codes:
      0: help or evaluation completed and fail-close did not trigger
      1: fail-close triggered
      2: usage/argument error
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

array_to_json() {
  local -n arr_ref=$1
  if ((${#arr_ref[@]} == 0)); then
    printf '%s' "[]"
    return
  fi
  printf '%s\n' "${arr_ref[@]}" | jq -R 'select(length > 0)' | jq -s 'unique'
}

json_valid01() {
  local path="$1"
  if [[ -n "$path" && -f "$path" ]] && jq -e . "$path" >/dev/null 2>&1; then
    echo "1"
  else
    echo "0"
  fi
}

json_object01() {
  local path="$1"
  if [[ -n "$path" && -f "$path" ]] && jq -e 'type == "object"' "$path" >/dev/null 2>&1; then
    echo "1"
  else
    echo "0"
  fi
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

json_number_or_empty() {
  local path="$1"
  local expr="$2"
  local raw=""
  raw="$(json_text_or_empty "$path" "$expr")"
  if [[ "$raw" =~ ^-?[0-9]+([.][0-9]+)?$ ]]; then
    printf '%s' "$raw"
  else
    printf '%s' ""
  fi
}

numeric_compare_ok() {
  local actual="$1"
  local comparator="$2"
  local threshold="$3"
  jq -e -n \
    --argjson actual "$actual" \
    --argjson threshold "$threshold" \
    --arg comparator "$comparator" \
    '
    if $comparator == ">=" then $actual >= $threshold
    elif $comparator == "<=" then $actual <= $threshold
    elif $comparator == ">" then $actual > $threshold
    elif $comparator == "<" then $actual < $threshold
    elif $comparator == "==" then $actual == $threshold
    else false end
    ' >/dev/null 2>&1
}

make_gate_json() {
  local id="$1"
  local title="$2"
  local category="$3"
  local metric="$4"
  local comparison="$5"
  local unit="$6"
  local status="$7"
  local reason="$8"
  local actual_json="$9"
  local threshold_json="${10}"
  jq -n \
    --arg id "$id" \
    --arg title "$title" \
    --arg category "$category" \
    --arg metric "$metric" \
    --arg comparison "$comparison" \
    --arg unit "$unit" \
    --arg status "$status" \
    --arg reason "$reason" \
    --argjson actual "$actual_json" \
    --argjson threshold "$threshold_json" \
    '{
      id: $id,
      title: $title,
      category: $category,
      required: true,
      metric: $metric,
      comparison: $comparison,
      unit: $unit,
      actual: $actual,
      threshold: $threshold,
      status: $status,
      reason: $reason
    }'
}

evaluate_single_gate() {
  local metric_json_path="$1"
  local gate_id="$2"
  local title="$3"
  local category="$4"
  local field_name="$5"
  local comparison="$6"
  local threshold="$7"
  local unit="$8"

  local actual_raw=""
  local actual_json="null"
  local status="fail"
  local reason=""

  actual_raw="$(json_number_or_empty "$metric_json_path" ".$field_name")"
  if [[ -z "$actual_raw" ]]; then
    reason="missing or invalid metric: $field_name"
  elif numeric_compare_ok "$actual_raw" "$comparison" "$threshold"; then
    status="pass"
    reason=""
    actual_json="$actual_raw"
  else
    reason="$field_name=$actual_raw does not satisfy $comparison $threshold"
    actual_json="$actual_raw"
  fi

  make_gate_json \
    "$gate_id" \
    "$title" \
    "$category" \
    "$field_name" \
    "$comparison" \
    "$unit" \
    "$status" \
    "$reason" \
    "$actual_json" \
    "$threshold"
}

metrics_json="${BLOCKCHAIN_BOOTSTRAP_GRADUATION_GATE_METRICS_JSON:-}"
summary_json="${BLOCKCHAIN_BOOTSTRAP_GRADUATION_GATE_SUMMARY_JSON:-}"
print_summary_json="${BLOCKCHAIN_BOOTSTRAP_GRADUATION_GATE_PRINT_SUMMARY_JSON:-0}"
fail_close="${BLOCKCHAIN_BOOTSTRAP_GRADUATION_GATE_FAIL_CLOSE:-0}"

metrics_source="missing"
if [[ -n "$(trim "$metrics_json")" ]]; then
  metrics_source="env"
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --metrics-json)
      path_arg_or_die "--metrics-json" "${2:-}"
      metrics_json="${2:-}"
      metrics_source="arg"
      shift 2
      ;;
    --summary-json)
      path_arg_or_die "--summary-json" "${2:-}"
      summary_json="${2:-}"
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
    --fail-close)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        fail_close="${2:-}"
        shift 2
      else
        fail_close="1"
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

need_cmd jq
need_cmd mktemp
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--fail-close" "$fail_close"

if [[ -n "$(trim "$metrics_json")" ]]; then
  path_arg_or_die "--metrics-json" "$metrics_json"
fi
metrics_json="$(abs_path "$metrics_json")"

if [[ -z "$(trim "$summary_json")" ]]; then
  summary_json="$ROOT_DIR/.easy-node-logs/blockchain_bootstrap_graduation_gate_summary.json"
fi
if [[ -n "$(trim "$summary_json")" ]]; then
  path_arg_or_die "--summary-json" "$summary_json"
fi
summary_json="$(abs_path "$summary_json")"
mkdir -p "$(dirname "$summary_json")"

summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
cleanup() {
  rm -f "$summary_tmp"
}
trap cleanup EXIT

declare -a gate_json_entries=()
declare -a failed_gate_ids=()
declare -a failed_reasons=()
declare -a source_paths=()

input_state="available"
input_reason=""
input_valid="1"
if [[ -z "$(trim "$metrics_json")" ]]; then
  input_state="missing"
  input_reason="missing required metrics JSON path"
  input_valid="0"
elif [[ ! -f "$metrics_json" ]]; then
  input_state="missing"
  input_reason="metrics JSON file not found: $metrics_json"
  input_valid="0"
elif [[ "$(json_valid01 "$metrics_json")" != "1" ]]; then
  input_state="invalid"
  input_reason="metrics JSON is not valid JSON: $metrics_json"
  input_valid="0"
elif [[ "$(json_object01 "$metrics_json")" != "1" ]]; then
  input_state="invalid"
  input_reason="metrics JSON root must be an object: $metrics_json"
  input_valid="0"
fi

if [[ -n "$(trim "$metrics_json")" ]]; then
  source_paths+=("$metrics_json")
fi
source_paths_json="$(array_to_json source_paths)"

decision="NO-GO"
status="no-go"
go_bool="0"
no_go_bool="1"
summary_rc="1"
exit_code="0"
required_gate_count=9
measurement_window_weeks="null"

if [[ "$input_valid" != "1" ]]; then
  failed_gate_ids+=("metrics_input")
  failed_reasons+=("$input_reason")
  failed_gate_ids_json="$(array_to_json failed_gate_ids)"
  failed_reasons_json="$(array_to_json failed_reasons)"
  if [[ "$fail_close" == "1" ]]; then
    exit_code="1"
  fi

  jq -n \
    --arg schema_id "blockchain_bootstrap_graduation_gate_summary" \
    --arg decision "$decision" \
    --arg status "$status" \
    --argjson go_bool "$go_bool" \
    --argjson no_go_bool "$no_go_bool" \
    --argjson rc "$summary_rc" \
    --argjson exit_code "$exit_code" \
    --argjson fail_close "$fail_close" \
    --arg metrics_json "$metrics_json" \
    --arg metrics_source "$metrics_source" \
    --arg input_state "$input_state" \
    --arg input_reason "$input_reason" \
    --argjson input_valid "$input_valid" \
    --argjson measurement_window_weeks "$measurement_window_weeks" \
    --argjson counts "$(jq -n --argjson required "$required_gate_count" '{required: $required, evaluated: 0, pass: 0, fail: 0}')" \
    --argjson failed_gate_ids "$failed_gate_ids_json" \
    --argjson failed_reasons "$failed_reasons_json" \
    --argjson reasons "$failed_reasons_json" \
    --argjson source_paths "$source_paths_json" \
    --argjson gates '[]' \
    --arg summary_json "$summary_json" \
    --arg metrics_json "$metrics_json" \
    '{
      version: 1,
      schema: {id: $schema_id, major: 1, minor: 0},
      decision: $decision,
      status: $status,
      go: ($go_bool == 1),
      no_go: ($no_go_bool == 1),
      rc: $rc,
      exit_code: $exit_code,
      fail_close: $fail_close,
      input: {
        metrics_json: $metrics_json,
        metrics_source: $metrics_source,
        state: $input_state,
        valid: ($input_valid == 1),
        reason: $input_reason
      },
      measurement_window_weeks: $measurement_window_weeks,
      counts: $counts,
      failed_gate_ids: $failed_gate_ids,
      failed_reasons: $failed_reasons,
      reasons: $reasons,
      source_paths: $source_paths,
      gates: $gates,
      artifacts: {
        summary_json: $summary_json,
        metrics_json: $metrics_json
      }
    }' >"$summary_tmp"
else
  measurement_window_weeks="$(json_number_or_empty "$metrics_json" '.measurement_window_weeks')"
  if [[ -z "$measurement_window_weeks" ]]; then
    measurement_window_weeks="null"
  fi

  gate_json_entries+=("$(evaluate_single_gate "$metrics_json" "measurement_window_weeks" "Readiness window - Measurement coverage" "Readiness window" "measurement_window_weeks" ">=" "12" "weeks")")
  gate_json_entries+=("$(evaluate_single_gate "$metrics_json" "validator_candidate_depth" "Validator supply - Candidate depth" "Validator supply" "validator_candidate_depth" ">=" "30" "servers")")

  validator_independent_operators="$(json_number_or_empty "$metrics_json" '.validator_independent_operators')"
  validator_max_operator_seat_share_pct="$(json_number_or_empty "$metrics_json" '.validator_max_operator_seat_share_pct')"
  validator_operator_status="fail"
  validator_operator_reason=""
  validator_operator_actual_json="null"
  validator_operator_threshold_json='{"independent_operators":12,"max_operator_seat_share_pct":20}'
  if [[ -z "$validator_independent_operators" || -z "$validator_max_operator_seat_share_pct" ]]; then
    validator_operator_reason="missing or invalid metric: validator_independent_operators or validator_max_operator_seat_share_pct"
  elif [[ "$validator_independent_operators" =~ ^-?[0-9]+$ && "$validator_max_operator_seat_share_pct" =~ ^-?[0-9]+([.][0-9]+)?$ ]] && \
    numeric_compare_ok "$validator_independent_operators" ">=" "12" && \
    numeric_compare_ok "$validator_max_operator_seat_share_pct" "<=" "20"; then
    validator_operator_status="pass"
    validator_operator_reason=""
    validator_operator_actual_json="$(jq -n \
      --argjson independent_operators "$validator_independent_operators" \
      --argjson max_operator_seat_share_pct "$validator_max_operator_seat_share_pct" \
      '{independent_operators: $independent_operators, max_operator_seat_share_pct: $max_operator_seat_share_pct}')"
  else
    validator_operator_reason="independent_operators=$validator_independent_operators must be >= 12 and max_operator_seat_share_pct=$validator_max_operator_seat_share_pct must be <= 20"
    validator_operator_actual_json="$(jq -n \
      --argjson independent_operators "${validator_independent_operators:-null}" \
      --argjson max_operator_seat_share_pct "${validator_max_operator_seat_share_pct:-null}" \
      '{independent_operators: $independent_operators, max_operator_seat_share_pct: $max_operator_seat_share_pct}')"
  fi
  gate_json_entries+=("$(make_gate_json "validator_operator_concentration" "Validator decentralization - Operator concentration" "Validator decentralization" "validator_independent_operators, validator_max_operator_seat_share_pct" ">=" "operators / percent" "$validator_operator_status" "$validator_operator_reason" "$validator_operator_actual_json" "$validator_operator_threshold_json")")

  gate_json_entries+=("$(evaluate_single_gate "$metrics_json" "validator_infra_concentration" "Validator decentralization - Infra concentration" "Validator decentralization" "validator_max_asn_provider_seat_share_pct" "<=" "25" "percent")")

  validator_region_count="$(json_number_or_empty "$metrics_json" '.validator_region_count')"
  validator_country_count="$(json_number_or_empty "$metrics_json" '.validator_country_count')"
  validator_geo_status="fail"
  validator_geo_reason=""
  validator_geo_actual_json="null"
  validator_geo_threshold_json='{"validator_region_count":4,"validator_country_count":8}'
  if [[ -z "$validator_region_count" || -z "$validator_country_count" ]]; then
    validator_geo_reason="missing or invalid metric: validator_region_count or validator_country_count"
  elif numeric_compare_ok "$validator_region_count" ">=" "4" && numeric_compare_ok "$validator_country_count" ">=" "8"; then
    validator_geo_status="pass"
    validator_geo_reason=""
    validator_geo_actual_json="$(jq -n \
      --argjson validator_region_count "$validator_region_count" \
      --argjson validator_country_count "$validator_country_count" \
      '{validator_region_count: $validator_region_count, validator_country_count: $validator_country_count}')"
  else
    validator_geo_reason="validator_region_count=$validator_region_count must be >= 4 and validator_country_count=$validator_country_count must be >= 8"
    validator_geo_actual_json="$(jq -n \
      --argjson validator_region_count "${validator_region_count:-null}" \
      --argjson validator_country_count "${validator_country_count:-null}" \
      '{validator_region_count: $validator_region_count, validator_country_count: $validator_country_count}')"
  fi
  gate_json_entries+=("$(make_gate_json "validator_geography_diversity" "Validator decentralization - Geography diversity" "Validator decentralization" "validator_region_count, validator_country_count" ">=" "regions / countries" "$validator_geo_status" "$validator_geo_reason" "$validator_geo_actual_json" "$validator_geo_threshold_json")")

  gate_json_entries+=("$(evaluate_single_gate "$metrics_json" "manual_sanctions_reversal_rate" "Governance quality - Manual action quality" "Governance quality" "manual_sanctions_reversed_pct_90d" "<" "5" "percent")")
  gate_json_entries+=("$(evaluate_single_gate "$metrics_json" "abuse_response_speed" "Governance quality - Abuse response speed" "Governance quality" "abuse_report_to_decision_p95_hours" "<=" "24" "hours")")
  gate_json_entries+=("$(evaluate_single_gate "$metrics_json" "vpn_connect_session_success_slo" "VPN reliability - Connect/session success SLO" "VPN reliability" "vpn_connect_session_success_slo_pct" ">=" "99.5" "percent")")
  gate_json_entries+=("$(evaluate_single_gate "$metrics_json" "vpn_recovery_mttr_p95" "VPN reliability - Recovery SLO" "VPN reliability" "vpn_recovery_mttr_p95_minutes" "<=" "30" "minutes")")

  gates_json="$(printf '%s\n' "${gate_json_entries[@]}" | jq -s .)"
  pass_count="$(jq '[.[] | select(.status == "pass")] | length' <<<"$gates_json")"
  fail_count="$(jq '[.[] | select(.status != "pass")] | length' <<<"$gates_json")"
  summary_rc="1"
  if [[ "$fail_count" == "0" ]]; then
    decision="GO"
    status="go"
    go_bool="1"
    no_go_bool="0"
    summary_rc="0"
    exit_code="0"
  elif [[ "$fail_close" == "1" ]]; then
    exit_code="1"
  fi

  counts_json="$(jq -n \
    --argjson required "$required_gate_count" \
    --argjson evaluated "$(jq 'length' <<<"$gates_json")" \
    --argjson pass "$pass_count" \
    --argjson fail "$fail_count" \
    '{required: $required, evaluated: $evaluated, pass: $pass, fail: $fail}')"

  failed_gate_ids_json="$(jq -c '[.[] | select(.status != "pass") | .id]' <<<"$gates_json")"
  failed_reasons_json="$(jq -c '[.[] | select(.status != "pass") | .reason]' <<<"$gates_json")"

  jq -n \
    --arg schema_id "blockchain_bootstrap_graduation_gate_summary" \
    --arg decision "$decision" \
    --arg status "$status" \
    --argjson go_bool "$go_bool" \
    --argjson no_go_bool "$no_go_bool" \
    --argjson rc "$summary_rc" \
    --argjson exit_code "$exit_code" \
    --argjson fail_close "$fail_close" \
    --arg metrics_json "$metrics_json" \
    --arg metrics_source "$metrics_source" \
    --arg input_state "$input_state" \
    --argjson input_valid 1 \
    --argjson measurement_window_weeks "$measurement_window_weeks" \
    --argjson counts "$counts_json" \
    --argjson failed_gate_ids "$failed_gate_ids_json" \
    --argjson failed_reasons "$failed_reasons_json" \
    --argjson reasons "$failed_reasons_json" \
    --argjson source_paths "$source_paths_json" \
    --argjson gates "$gates_json" \
    --arg summary_json "$summary_json" \
    --arg metrics_json "$metrics_json" \
    '{
      version: 1,
      schema: {id: $schema_id, major: 1, minor: 0},
      decision: $decision,
      status: $status,
      go: ($go_bool == 1),
      no_go: ($no_go_bool == 1),
      rc: $rc,
      exit_code: $exit_code,
      fail_close: $fail_close,
      input: {
        metrics_json: $metrics_json,
        metrics_source: $metrics_source,
        state: $input_state,
        valid: ($input_valid == 1),
        reason: ""
      },
      measurement_window_weeks: $measurement_window_weeks,
      counts: $counts,
      failed_gate_ids: $failed_gate_ids,
      failed_reasons: $failed_reasons,
      reasons: $reasons,
      source_paths: $source_paths,
      gates: $gates,
      artifacts: {
        summary_json: $summary_json,
        metrics_json: $metrics_json
      }
    }' >"$summary_tmp"
fi

mv -f "$summary_tmp" "$summary_json"

echo "[blockchain-bootstrap-graduation-gate] decision=$decision status=$status rc=$summary_rc exit_code=$exit_code fail_close=$fail_close metrics_json=$metrics_json summary_json=$summary_json"
echo "[blockchain-bootstrap-graduation-gate] failed_gate_ids=$(jq -r '.failed_gate_ids | if length == 0 then "none" else join(",") end' "$summary_json")"
echo "[blockchain-bootstrap-graduation-gate] failed_reasons=$(jq -r '.failed_reasons | if length == 0 then "none" else join(" | ") end' "$summary_json")"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$exit_code"
