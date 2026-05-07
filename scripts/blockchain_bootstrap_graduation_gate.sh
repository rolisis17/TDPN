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
    [--mode enforce|report-only] \
    [--enforce-launch] \
    [--report-only] \
    [--fail-close [0|1]] \
    [--require-real-evidence [0|1]] \
    [--evidence-max-age-sec SECONDS]

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
  - Default mode is enforce: real production evidence is required and NO-GO/
    missing/invalid input returns non-zero. Use --report-only for diagnostic
    summaries over raw metrics.
  - Enforce mode rejects ad hoc metric JSON and requires a metrics-summary
    schema with production source-json provenance for every bootstrap
    graduation metric. Each usable source JSON must carry an allowlisted
    production evidence.source_kind. The freshness window defaults to
    1209600 seconds (14 days).
  - Exit codes:
      0: help, GO in enforce mode, or report-only evaluation completed
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

nonnegative_int_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be a non-negative integer"
    exit 2
  fi
}

mode_arg_or_die() {
  local value="$1"
  if [[ "$value" != "enforce" && "$value" != "report-only" ]]; then
    echo "--mode must be enforce or report-only"
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

metric_value_is_valid() {
  local metric="$1"
  local value="$2"
  if [[ -z "$value" ]]; then
    return 1
  fi
  case "$metric" in
    measurement_window_weeks|validator_candidate_depth|validator_independent_operators|validator_region_count|validator_country_count)
      jq -n -e --argjson value "$value" '
        ($value | type) == "number"
        and (($value % 1) == 0)
        and ($value >= 0)
      ' >/dev/null 2>&1
      ;;
    validator_max_operator_seat_share_pct|validator_max_asn_provider_seat_share_pct|manual_sanctions_reversed_pct_90d|vpn_connect_session_success_slo_pct)
      jq -n -e --argjson value "$value" '
        ($value | type) == "number"
        and ($value >= 0)
        and ($value <= 100)
      ' >/dev/null 2>&1
      ;;
    abuse_report_to_decision_p95_hours|vpn_recovery_mttr_p95_minutes)
      jq -n -e --argjson value "$value" '
        ($value | type) == "number"
        and ($value >= 0)
      ' >/dev/null 2>&1
      ;;
    *)
      jq -n -e --argjson value "$value" '($value | type) == "number"' >/dev/null 2>&1
      ;;
  esac
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

extract_metric_from_source_json() {
  local source_json="$1"
  local key="$2"
  local raw=""

  if [[ -z "$source_json" || ! -f "$source_json" ]]; then
    printf '%s' ""
    return
  fi

  raw="$(jq -r --arg key "$key" '
    def emit($value):
      if $value == null then empty else $value end;
    def grouped:
      if $key == "measurement_window_weeks" then
        emit(.pipeline.window[$key]),
        emit(.window[$key]),
        emit(.general[$key])
      elif ($key == "vpn_connect_session_success_slo_pct" or $key == "vpn_recovery_mttr_p95_minutes") then
        emit(.pipeline.vpn.slo[$key]),
        emit(.vpn.slo[$key]),
        emit(.reliability[$key])
      elif ($key | startswith("validator_")) then
        emit(.validator[$key]),
        emit(.validator.supply[$key]),
        emit(.validator.concentration[$key]),
        emit(.validator.geo[$key]),
        emit(.validator_decentralization[$key])
      elif ($key == "manual_sanctions_reversed_pct_90d" or $key == "abuse_report_to_decision_p95_hours") then
        emit(.governance[$key])
      else
        empty
      end;
    limit(1;
      emit(.[$key]),
      emit(.metrics[$key]),
      grouped
    )
    | if type == "string" then . else tostring end
  ' "$source_json" 2>/dev/null || true)"
  printf '%s' "$(trim "$raw")"
}

validate_real_evidence_contract() {
  local metrics_path="$1"
  if [[ -z "$metrics_path" || ! -f "$metrics_path" ]]; then
    printf '%s' "metrics JSON is missing and real production evidence is required"
    return 0
  fi
  if [[ -L "$metrics_path" ]]; then
    printf '%s' "metrics JSON path must not be a symlink when real production evidence is required: $metrics_path"
    return 0
  fi
  if ! jq -e '
    def required_metrics: [
      "measurement_window_weeks",
      "validator_candidate_depth",
      "validator_independent_operators",
      "validator_max_operator_seat_share_pct",
      "validator_max_asn_provider_seat_share_pct",
      "validator_region_count",
      "validator_country_count",
      "manual_sanctions_reversed_pct_90d",
      "abuse_report_to_decision_p95_hours",
      "vpn_connect_session_success_slo_pct",
      "vpn_recovery_mttr_p95_minutes"
    ];
    . as $root
    | (($root.schema.id == "blockchain_mainnet_activation_metrics_summary") or ($root.schema.id == "blockchain_bootstrap_graduation_metrics_summary"))
    and ($root.status == "complete")
    and (($root.ready_for_gate == true) or ($root.ready_for_gate == 1))
    and ((($root.sources.usable_source_jsons // []) | type) == "array")
    and ((($root.sources.usable_source_jsons // []) | length) > 0)
    and (all(required_metrics[]; ($root.sources.metrics[.] == "source_json")))
    and (all(required_metrics[];
      . as $metric |
      (($root.sources.metric_bindings[$metric] // null) | type) == "object"
      and (($root.sources.metric_bindings[$metric].source_json // "") | type == "string")
      and (($root.sources.metric_bindings[$metric].source_json // "") | length > 0)
      and (($root.sources.usable_source_jsons // []) | index($root.sources.metric_bindings[$metric].source_json) != null)
      and (($root.sources.metric_bindings[$metric].source_sha256 // "") | test("^[a-f0-9]{64}$"))
      and ($root.sources.metric_bindings[$metric].value == $root[$metric])
    ))
  ' "$metrics_path" >/dev/null 2>&1; then
    printf '%s' "metrics JSON lacks required real-evidence provenance: expected metrics summary with complete source-json evidence bindings for every bootstrap graduation metric"
    return 0
  fi

  local source_json=""
  local -a source_jsons=()
  mapfile -t source_jsons < <(jq -r '(.sources.usable_source_jsons // [])[] | select(type == "string" and length > 0)' "$metrics_path" 2>/dev/null || true)
  if ((${#source_jsons[@]} == 0)); then
    printf '%s' "metrics JSON lacks usable production evidence source paths"
    return 0
  fi

  for source_json in "${source_jsons[@]}"; do
    source_json="$(abs_path "$source_json")"
    if [[ ! -f "$source_json" ]]; then
      printf '%s' "production evidence source JSON not found: $source_json"
      return 0
    fi
    if [[ -L "$source_json" ]]; then
      printf '%s' "production evidence source JSON must not be a symlink: $source_json"
      return 0
    fi
    if ! jq -e '
      def nonempty_string: type == "string" and length > 0;
      def iso_utc: nonempty_string and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$");
      def production_mode:
        ((.evidence.mode // .evidence.evidence_mode // .metadata.evidence_mode // "") == "production");
      def allowed_source_kind:
        ((.evidence.source_kind // .evidence.source_system // .source_kind // .metadata.source_kind // "") as $kind
        | [
            "prod-observability-export",
            "prod-billing-export",
            "prod-validator-registry-export",
            "prod-support-ops-export",
            "prod-governance-export",
            "prod-settlement-export"
          ] | index($kind) != null);
      production_mode
      and ((.evidence.generated_at // .generated_at // .generated_at_utc) | iso_utc)
      and ((.evidence.source_kind // .evidence.source_system // .source_kind // .metadata.source_kind) | nonempty_string)
      and allowed_source_kind
    ' "$source_json" >/dev/null 2>&1; then
      printf '%s' "source JSON lacks production evidence contract: $source_json"
      return 0
    fi

    local freshness_json=""
    freshness_json="$(
      jq -c \
        --argjson now_epoch "$(date -u +%s)" \
        --argjson max_age_sec "$evidence_max_age_sec" \
        '
        def generated_at:
          .evidence.generated_at // .generated_at // .generated_at_utc // "";
        (generated_at) as $generated_at
        | (try ($generated_at | fromdateiso8601) catch null) as $generated_epoch
        | if $generated_epoch == null then
            {ok: false, reason: "invalid", generated_at: $generated_at, age_sec: null}
          elif $generated_epoch > $now_epoch then
            {ok: false, reason: "future", generated_at: $generated_at, age_sec: ($now_epoch - $generated_epoch)}
          elif (($now_epoch - $generated_epoch) > $max_age_sec) then
            {ok: false, reason: "stale", generated_at: $generated_at, age_sec: ($now_epoch - $generated_epoch)}
          else
            {ok: true, reason: "fresh", generated_at: $generated_at, age_sec: ($now_epoch - $generated_epoch)}
          end
        ' "$source_json" 2>/dev/null || printf '%s' '{"ok":false,"reason":"invalid","generated_at":"","age_sec":null}'
    )"
    if [[ "$(jq -r '.ok' <<<"$freshness_json")" != "true" ]]; then
      local freshness_reason=""
      local freshness_generated_at=""
      local freshness_age_sec=""
      freshness_reason="$(jq -r '.reason // "invalid"' <<<"$freshness_json")"
      freshness_generated_at="$(jq -r '.generated_at // ""' <<<"$freshness_json")"
      freshness_age_sec="$(jq -r '.age_sec // "null"' <<<"$freshness_json")"
      if [[ "$freshness_reason" == "future" ]]; then
        printf '%s' "source JSON production evidence generated_at is in the future: $source_json generated_at=$freshness_generated_at"
      elif [[ "$freshness_reason" == "stale" ]]; then
        printf '%s' "source JSON production evidence is stale: $source_json generated_at=$freshness_generated_at age_sec=$freshness_age_sec max_age_sec=$evidence_max_age_sec"
      else
        printf '%s' "source JSON production evidence generated_at is invalid: $source_json generated_at=$freshness_generated_at"
      fi
      return 0
    fi
  done

  local metric_name=""
  local binding_source_json=""
  local binding_source_sha256=""
  local binding_value=""
  local root_value=""
  local actual_source_sha256=""
  local source_value=""
  while IFS=$'\t' read -r metric_name binding_source_json binding_source_sha256 binding_value root_value; do
    [[ -n "$metric_name" ]] || continue
    binding_source_json="$(abs_path "$binding_source_json")"
    if [[ ! -f "$binding_source_json" ]]; then
      printf '%s' "metric evidence binding source JSON not found: metric=$metric_name source=$binding_source_json"
      return 0
    fi
    if [[ -L "$binding_source_json" ]]; then
      printf '%s' "metric evidence binding source JSON must not be a symlink: metric=$metric_name source=$binding_source_json"
      return 0
    fi
    actual_source_sha256="$(sha256sum "$binding_source_json" | awk '{print $1}')"
    if [[ "$actual_source_sha256" != "$binding_source_sha256" ]]; then
      printf '%s' "metric evidence binding sha256 mismatch: metric=$metric_name source=$binding_source_json"
      return 0
    fi
    source_value="$(extract_metric_from_source_json "$binding_source_json" "$metric_name")"
    if [[ -z "$source_value" ]]; then
      printf '%s' "metric evidence binding source value missing: metric=$metric_name source=$binding_source_json"
      return 0
    fi
    if ! metric_value_is_valid "$metric_name" "$source_value"; then
      printf '%s' "metric evidence binding source value invalid: metric=$metric_name source=$binding_source_json value=$source_value"
      return 0
    fi
    if ! jq -n -e \
      --argjson source_value "$source_value" \
      --argjson binding_value "$binding_value" \
      --argjson root_value "$root_value" \
      '$source_value == $binding_value and $source_value == $root_value' >/dev/null 2>&1; then
      printf '%s' "metric evidence binding source value mismatch: metric=$metric_name source=$binding_source_json source_value=$source_value binding_value=$binding_value root_value=$root_value"
      return 0
    fi
  done < <(jq -r '
    def required_metrics: [
      "measurement_window_weeks",
      "validator_candidate_depth",
      "validator_independent_operators",
      "validator_max_operator_seat_share_pct",
      "validator_max_asn_provider_seat_share_pct",
      "validator_region_count",
      "validator_country_count",
      "manual_sanctions_reversed_pct_90d",
      "abuse_report_to_decision_p95_hours",
      "vpn_connect_session_success_slo_pct",
      "vpn_recovery_mttr_p95_minutes"
    ];
    . as $root
    | required_metrics[] as $metric
    | [$metric, ($root.sources.metric_bindings[$metric].source_json // ""), ($root.sources.metric_bindings[$metric].source_sha256 // ""), ($root.sources.metric_bindings[$metric].value // null), ($root[$metric] // null)]
    | @tsv
  ' "$metrics_path")

  printf '%s' ""
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
  elif ! metric_value_is_valid "$field_name" "$actual_raw"; then
    reason="missing or invalid metric: $field_name"
    actual_json="$actual_raw"
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
gate_mode="${BLOCKCHAIN_BOOTSTRAP_GRADUATION_GATE_MODE:-enforce}"
fail_close="${BLOCKCHAIN_BOOTSTRAP_GRADUATION_GATE_FAIL_CLOSE:-}"
require_real_evidence="${BLOCKCHAIN_BOOTSTRAP_GRADUATION_GATE_REQUIRE_REAL_EVIDENCE:-}"
evidence_max_age_sec="${BLOCKCHAIN_BOOTSTRAP_GRADUATION_GATE_EVIDENCE_MAX_AGE_SEC:-1209600}"
max_enforce_evidence_age_sec=1209600

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
	    --mode)
	      if [[ $# -lt 2 ]]; then
	        echo "--mode requires a value"
	        exit 2
	      fi
	      mode_arg_or_die "${2:-}"
	      gate_mode="${2:-}"
	      shift 2
	      ;;
	    --enforce-launch)
	      gate_mode="enforce"
	      shift
	      ;;
	    --report-only)
	      gate_mode="report-only"
	      shift
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
	    --require-real-evidence)
	      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
	        require_real_evidence="${2:-}"
	        shift 2
	      else
	        require_real_evidence="1"
	        shift
	      fi
	      ;;
	    --evidence-max-age-sec)
	      if [[ $# -lt 2 ]]; then
	        echo "--evidence-max-age-sec requires a value"
	        exit 2
	      fi
	      nonnegative_int_arg_or_die "--evidence-max-age-sec" "${2:-}"
	      evidence_max_age_sec="${2:-}"
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

need_cmd jq
need_cmd mktemp
need_cmd awk
need_cmd sha256sum
bool_arg_or_die "--print-summary-json" "$print_summary_json"
mode_arg_or_die "$gate_mode"
if [[ -z "$fail_close" ]]; then
  if [[ "$gate_mode" == "enforce" ]]; then
    fail_close="1"
  else
    fail_close="0"
  fi
fi
if [[ -z "$require_real_evidence" ]]; then
  if [[ "$gate_mode" == "enforce" ]]; then
    require_real_evidence="1"
  else
    require_real_evidence="0"
  fi
fi
bool_arg_or_die "--fail-close" "$fail_close"
bool_arg_or_die "--require-real-evidence" "$require_real_evidence"
nonnegative_int_arg_or_die "--evidence-max-age-sec" "$evidence_max_age_sec"
if [[ "$gate_mode" == "enforce" ]] && (( evidence_max_age_sec > max_enforce_evidence_age_sec )); then
  echo "--evidence-max-age-sec cannot exceed $max_enforce_evidence_age_sec in enforce mode; use --report-only for wider forensic windows"
  exit 2
fi
if [[ "$gate_mode" == "enforce" && ( "$fail_close" != "1" || "$require_real_evidence" != "1" ) ]]; then
  echo "enforce mode requires --fail-close 1 and --require-real-evidence 1; use --report-only for fail-soft diagnostics"
  exit 2
fi

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
generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

declare -a gate_json_entries=()
declare -a failed_gate_ids=()
declare -a failed_reasons=()
declare -a source_paths=()

input_state="available"
input_reason=""
input_valid="1"
input_failure_gate_id="metrics_input"
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

if [[ "$input_valid" == "1" && "$require_real_evidence" == "1" ]]; then
  evidence_reason="$(validate_real_evidence_contract "$metrics_json")"
  if [[ -n "$evidence_reason" ]]; then
    input_state="invalid"
    input_reason="$evidence_reason"
    input_valid="0"
    input_failure_gate_id="metrics_evidence"
  fi
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
  failed_gate_ids+=("$input_failure_gate_id")
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
	    --argjson require_real_evidence "$require_real_evidence" \
	    --argjson evidence_max_age_sec "$evidence_max_age_sec" \
	    --arg mode "$gate_mode" \
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
    --arg generated_at "$generated_at" \
    '{
      version: 1,
      schema: {id: $schema_id, major: 1, minor: 0},
      generated_at: $generated_at,
      decision: $decision,
	      status: $status,
	      go: ($go_bool == 1),
	      no_go: ($no_go_bool == 1),
	      rc: $rc,
	      exit_code: $exit_code,
	      mode: $mode,
	      fail_close: $fail_close,
	      require_real_evidence: $require_real_evidence,
	      evidence_max_age_sec: $evidence_max_age_sec,
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
  elif ! metric_value_is_valid "validator_independent_operators" "$validator_independent_operators" || \
    ! metric_value_is_valid "validator_max_operator_seat_share_pct" "$validator_max_operator_seat_share_pct"; then
    validator_operator_reason="missing or invalid metric: validator_independent_operators or validator_max_operator_seat_share_pct"
    validator_operator_actual_json="$(jq -n \
      --argjson independent_operators "${validator_independent_operators:-null}" \
      --argjson max_operator_seat_share_pct "${validator_max_operator_seat_share_pct:-null}" \
      '{independent_operators: $independent_operators, max_operator_seat_share_pct: $max_operator_seat_share_pct}')"
  elif numeric_compare_ok "$validator_independent_operators" ">=" "12" && \
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
  elif ! metric_value_is_valid "validator_region_count" "$validator_region_count" || \
    ! metric_value_is_valid "validator_country_count" "$validator_country_count"; then
    validator_geo_reason="missing or invalid metric: validator_region_count or validator_country_count"
    validator_geo_actual_json="$(jq -n \
      --argjson validator_region_count "${validator_region_count:-null}" \
      --argjson validator_country_count "${validator_country_count:-null}" \
      '{validator_region_count: $validator_region_count, validator_country_count: $validator_country_count}')"
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
	    --argjson require_real_evidence "$require_real_evidence" \
	    --argjson evidence_max_age_sec "$evidence_max_age_sec" \
	    --arg mode "$gate_mode" \
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
    --arg generated_at "$generated_at" \
    '{
      version: 1,
      schema: {id: $schema_id, major: 1, minor: 0},
      generated_at: $generated_at,
      decision: $decision,
      status: $status,
      go: ($go_bool == 1),
	      no_go: ($no_go_bool == 1),
	      rc: $rc,
	      exit_code: $exit_code,
	      mode: $mode,
	      fail_close: $fail_close,
	      require_real_evidence: $require_real_evidence,
	      evidence_max_age_sec: $evidence_max_age_sec,
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
