#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SLO_SUMMARY_SCRIPT="${PROD_GATE_SLO_SUMMARY_SCRIPT:-$ROOT_DIR/scripts/prod_gate_slo_summary.sh}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_gate_slo_trend.sh \
    [--run-report-json PATH]... \
    [--run-report-list FILE] \
    [--reports-dir DIR] \
    [--max-reports N] \
    [--since-hours N] \
    [--require-full-sequence [0|1]] \
    [--require-wg-validate-ok [0|1]] \
    [--require-wg-soak-ok [0|1]] \
    [--max-wg-soak-failed-rounds N] \
    [--require-preflight-ok [0|1]] \
    [--require-bundle-ok [0|1]] \
    [--require-integrity-ok [0|1]] \
    [--require-signoff-ok [0|1]] \
    [--require-incident-snapshot-on-fail [0|1]] \
    [--require-incident-snapshot-artifacts [0|1]] \
    [--require-wg-validate-udp-source [0|1]] \
    [--require-wg-validate-strict-distinct [0|1]] \
    [--require-wg-soak-diversity-pass [0|1]] \
    [--min-wg-soak-selection-lines N] \
    [--min-wg-soak-entry-operators N] \
    [--min-wg-soak-exit-operators N] \
    [--min-wg-soak-cross-operator-pairs N] \
    [--fail-on-any-no-go [0|1]] \
    [--min-go-rate-pct N] \
    [--show-details [0|1]] \
    [--show-top-reasons N] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Evaluate GO/NO-GO SLO trend across multiple prod-bundle run reports.

Notes:
  - If no report input is supplied, defaults to scanning ./.easy-node-logs.
  - Decision per report is delegated to prod_gate_slo_summary.sh with same policy flags.
  - Use --fail-on-any-no-go=1 and/or --min-go-rate-pct for fail-closed trend gates.
  - Use --summary-json to emit machine-readable aggregate output.
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

is_non_negative_decimal() {
  local v="$1"
  [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

float_lt() {
  local left="$1"
  local right="$2"
  awk -v l="$left" -v r="$right" 'BEGIN { exit (l < r) ? 0 : 1 }'
}

file_mtime_epoch() {
  local file="$1"
  if stat -c %Y "$file" >/dev/null 2>&1; then
    stat -c %Y "$file"
    return
  fi
  if stat -f %m "$file" >/dev/null 2>&1; then
    stat -f %m "$file"
    return
  fi
  echo "0"
}

require_full_sequence="${PROD_GATE_SLO_REQUIRE_FULL_SEQUENCE:-1}"
require_wg_validate_ok="${PROD_GATE_SLO_REQUIRE_WG_VALIDATE_OK:-1}"
require_wg_soak_ok="${PROD_GATE_SLO_REQUIRE_WG_SOAK_OK:-1}"
max_wg_soak_failed_rounds="${PROD_GATE_SLO_MAX_WG_SOAK_FAILED_ROUNDS:-0}"
require_preflight_ok="${PROD_GATE_SLO_REQUIRE_PREFLIGHT_OK:-0}"
require_bundle_ok="${PROD_GATE_SLO_REQUIRE_BUNDLE_OK:-0}"
require_integrity_ok="${PROD_GATE_SLO_REQUIRE_INTEGRITY_OK:-0}"
require_signoff_ok="${PROD_GATE_SLO_REQUIRE_SIGNOFF_OK:-0}"
require_incident_snapshot_on_fail="${PROD_GATE_SLO_REQUIRE_INCIDENT_SNAPSHOT_ON_FAIL:-0}"
require_incident_snapshot_artifacts="${PROD_GATE_SLO_REQUIRE_INCIDENT_SNAPSHOT_ARTIFACTS:-0}"
require_wg_validate_udp_source="${PROD_GATE_SLO_REQUIRE_WG_VALIDATE_UDP_SOURCE:-0}"
require_wg_validate_strict_distinct="${PROD_GATE_SLO_REQUIRE_WG_VALIDATE_STRICT_DISTINCT:-0}"
require_wg_soak_diversity_pass="${PROD_GATE_SLO_REQUIRE_WG_SOAK_DIVERSITY_PASS:-0}"
min_wg_soak_selection_lines="${PROD_GATE_SLO_MIN_WG_SOAK_SELECTION_LINES:-0}"
min_wg_soak_entry_operators="${PROD_GATE_SLO_MIN_WG_SOAK_ENTRY_OPERATORS:-0}"
min_wg_soak_exit_operators="${PROD_GATE_SLO_MIN_WG_SOAK_EXIT_OPERATORS:-0}"
min_wg_soak_cross_operator_pairs="${PROD_GATE_SLO_MIN_WG_SOAK_CROSS_OPERATOR_PAIRS:-0}"
fail_on_any_no_go="${PROD_GATE_SLO_TREND_FAIL_ON_ANY_NO_GO:-0}"
min_go_rate_pct="${PROD_GATE_SLO_TREND_MIN_GO_RATE_PCT:-0}"
max_reports="${PROD_GATE_SLO_TREND_MAX_REPORTS:-25}"
since_hours="${PROD_GATE_SLO_TREND_SINCE_HOURS:-0}"
show_details="${PROD_GATE_SLO_TREND_SHOW_DETAILS:-1}"
show_top_reasons="${PROD_GATE_SLO_TREND_SHOW_TOP_REASONS:-5}"
summary_json=""
print_summary_json="${PROD_GATE_SLO_TREND_PRINT_SUMMARY_JSON:-0}"

run_report_list=""
reports_dir=""
declare -a run_report_jsons=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-report-json)
      run_report_jsons+=("${2:-}")
      shift 2
      ;;
    --run-report-list)
      run_report_list="${2:-}"
      shift 2
      ;;
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --max-reports)
      max_reports="${2:-}"
      shift 2
      ;;
    --since-hours)
      since_hours="${2:-}"
      shift 2
      ;;
    --require-full-sequence)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_full_sequence="${2:-}"
        shift 2
      else
        require_full_sequence="1"
        shift
      fi
      ;;
    --require-wg-validate-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_wg_validate_ok="${2:-}"
        shift 2
      else
        require_wg_validate_ok="1"
        shift
      fi
      ;;
    --require-wg-soak-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_wg_soak_ok="${2:-}"
        shift 2
      else
        require_wg_soak_ok="1"
        shift
      fi
      ;;
    --max-wg-soak-failed-rounds)
      max_wg_soak_failed_rounds="${2:-}"
      shift 2
      ;;
    --require-preflight-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_preflight_ok="${2:-}"
        shift 2
      else
        require_preflight_ok="1"
        shift
      fi
      ;;
    --require-bundle-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_bundle_ok="${2:-}"
        shift 2
      else
        require_bundle_ok="1"
        shift
      fi
      ;;
    --require-integrity-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_integrity_ok="${2:-}"
        shift 2
      else
        require_integrity_ok="1"
        shift
      fi
      ;;
    --require-signoff-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_signoff_ok="${2:-}"
        shift 2
      else
        require_signoff_ok="1"
        shift
      fi
      ;;
    --require-incident-snapshot-on-fail)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_incident_snapshot_on_fail="${2:-}"
        shift 2
      else
        require_incident_snapshot_on_fail="1"
        shift
      fi
      ;;
    --require-incident-snapshot-artifacts)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_incident_snapshot_artifacts="${2:-}"
        shift 2
      else
        require_incident_snapshot_artifacts="1"
        shift
      fi
      ;;
    --require-wg-validate-udp-source)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_wg_validate_udp_source="${2:-}"
        shift 2
      else
        require_wg_validate_udp_source="1"
        shift
      fi
      ;;
    --require-wg-validate-strict-distinct)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_wg_validate_strict_distinct="${2:-}"
        shift 2
      else
        require_wg_validate_strict_distinct="1"
        shift
      fi
      ;;
    --require-wg-soak-diversity-pass)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_wg_soak_diversity_pass="${2:-}"
        shift 2
      else
        require_wg_soak_diversity_pass="1"
        shift
      fi
      ;;
    --min-wg-soak-selection-lines)
      min_wg_soak_selection_lines="${2:-}"
      shift 2
      ;;
    --min-wg-soak-entry-operators)
      min_wg_soak_entry_operators="${2:-}"
      shift 2
      ;;
    --min-wg-soak-exit-operators)
      min_wg_soak_exit_operators="${2:-}"
      shift 2
      ;;
    --min-wg-soak-cross-operator-pairs)
      min_wg_soak_cross_operator_pairs="${2:-}"
      shift 2
      ;;
    --fail-on-any-no-go)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        fail_on_any_no_go="${2:-}"
        shift 2
      else
        fail_on_any_no_go="1"
        shift
      fi
      ;;
    --min-go-rate-pct)
      min_go_rate_pct="${2:-}"
      shift 2
      ;;
    --show-details)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        show_details="${2:-}"
        shift 2
      else
        show_details="1"
        shift
      fi
      ;;
    --show-top-reasons)
      show_top_reasons="${2:-}"
      shift 2
      ;;
    --summary-json)
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

for cmd in bash jq awk sort sed grep find mktemp date; do
  need_cmd "$cmd"
done

if [[ ! -x "$SLO_SUMMARY_SCRIPT" ]]; then
  echo "missing executable slo summary script: $SLO_SUMMARY_SCRIPT"
  exit 2
fi

bool_arg_or_die "--require-full-sequence" "$require_full_sequence"
bool_arg_or_die "--require-wg-validate-ok" "$require_wg_validate_ok"
bool_arg_or_die "--require-wg-soak-ok" "$require_wg_soak_ok"
bool_arg_or_die "--require-preflight-ok" "$require_preflight_ok"
bool_arg_or_die "--require-bundle-ok" "$require_bundle_ok"
bool_arg_or_die "--require-integrity-ok" "$require_integrity_ok"
bool_arg_or_die "--require-signoff-ok" "$require_signoff_ok"
bool_arg_or_die "--require-incident-snapshot-on-fail" "$require_incident_snapshot_on_fail"
bool_arg_or_die "--require-incident-snapshot-artifacts" "$require_incident_snapshot_artifacts"
bool_arg_or_die "--require-wg-validate-udp-source" "$require_wg_validate_udp_source"
bool_arg_or_die "--require-wg-validate-strict-distinct" "$require_wg_validate_strict_distinct"
bool_arg_or_die "--require-wg-soak-diversity-pass" "$require_wg_soak_diversity_pass"
bool_arg_or_die "--fail-on-any-no-go" "$fail_on_any_no_go"
bool_arg_or_die "--show-details" "$show_details"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

if [[ ! "$max_reports" =~ ^[0-9]+$ ]] || ((max_reports < 1)); then
  echo "--max-reports must be an integer >= 1"
  exit 2
fi
if [[ ! "$since_hours" =~ ^[0-9]+$ ]]; then
  echo "--since-hours must be an integer >= 0"
  exit 2
fi
if [[ ! "$max_wg_soak_failed_rounds" =~ ^[0-9]+$ ]]; then
  echo "--max-wg-soak-failed-rounds must be an integer >= 0"
  exit 2
fi
if [[ ! "$min_wg_soak_selection_lines" =~ ^[0-9]+$ ]]; then
  echo "--min-wg-soak-selection-lines must be an integer >= 0"
  exit 2
fi
if [[ ! "$min_wg_soak_entry_operators" =~ ^[0-9]+$ ]]; then
  echo "--min-wg-soak-entry-operators must be an integer >= 0"
  exit 2
fi
if [[ ! "$min_wg_soak_exit_operators" =~ ^[0-9]+$ ]]; then
  echo "--min-wg-soak-exit-operators must be an integer >= 0"
  exit 2
fi
if [[ ! "$min_wg_soak_cross_operator_pairs" =~ ^[0-9]+$ ]]; then
  echo "--min-wg-soak-cross-operator-pairs must be an integer >= 0"
  exit 2
fi
if [[ ! "$show_top_reasons" =~ ^[0-9]+$ ]]; then
  echo "--show-top-reasons must be an integer >= 0"
  exit 2
fi
if ! is_non_negative_decimal "$min_go_rate_pct"; then
  echo "--min-go-rate-pct must be a number between 0 and 100"
  exit 2
fi
if float_lt "100" "$min_go_rate_pct"; then
  echo "--min-go-rate-pct must be <= 100"
  exit 2
fi

run_report_list="$(trim "$run_report_list")"
reports_dir="$(trim "$reports_dir")"
summary_json="$(trim "$summary_json")"
if [[ -n "$summary_json" && "$summary_json" != /* ]]; then
  summary_json="$ROOT_DIR/$summary_json"
fi
if [[ -z "$reports_dir" && ${#run_report_jsons[@]} -eq 0 && -z "$run_report_list" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs"
fi

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

candidates_file="$tmp_dir/candidates.txt"
touch "$candidates_file"

for raw in "${run_report_jsons[@]}"; do
  raw="$(trim "$raw")"
  [[ -z "$raw" ]] && continue
  printf '%s\n' "$raw" >>"$candidates_file"
done

if [[ -n "$run_report_list" ]]; then
  if [[ ! -f "$run_report_list" ]]; then
    echo "run report list file not found: $run_report_list"
    exit 1
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="$(trim "$line")"
    [[ -z "$line" ]] && continue
    [[ "${line:0:1}" == "#" ]] && continue
    printf '%s\n' "$line" >>"$candidates_file"
  done <"$run_report_list"
fi

if [[ -n "$reports_dir" ]]; then
  if [[ ! -d "$reports_dir" ]]; then
    echo "reports directory not found: $reports_dir"
    exit 1
  fi
  find "$reports_dir" -type f -name 'prod_bundle_run_report.json' -print >>"$candidates_file"
fi

ranked_file="$tmp_dir/ranked_reports.txt"
touch "$ranked_file"
declare -A seen_paths=()
now_epoch="$(date +%s 2>/dev/null || echo 0)"
cutoff_epoch=0
if ((since_hours > 0 && now_epoch > 0)); then
  cutoff_epoch=$((now_epoch - since_hours * 3600))
fi

while IFS= read -r candidate || [[ -n "$candidate" ]]; do
  candidate="$(trim "$candidate")"
  [[ -z "$candidate" ]] && continue
  local_path="$candidate"
  if [[ "$local_path" != /* ]]; then
    local_path="$ROOT_DIR/$local_path"
  fi
  if [[ ! -f "$local_path" ]]; then
    echo "[prod-gate-slo-trend] warning: skipping missing run report: $local_path"
    continue
  fi
  if ! jq -e . "$local_path" >/dev/null 2>&1; then
    echo "[prod-gate-slo-trend] warning: skipping invalid JSON run report: $local_path"
    continue
  fi
  if [[ -n "${seen_paths[$local_path]:-}" ]]; then
    continue
  fi
  seen_paths["$local_path"]=1
  mtime="$(file_mtime_epoch "$local_path")"
  if ((cutoff_epoch > 0 && mtime < cutoff_epoch)); then
    continue
  fi
  printf '%s\t%s\n' "$mtime" "$local_path" >>"$ranked_file"
done <"$candidates_file"

if [[ ! -s "$ranked_file" ]]; then
  echo "no valid run reports found"
  exit 1
fi

selected_file="$tmp_dir/selected_reports.txt"
sort -rn "$ranked_file" | head -n "$max_reports" >"$selected_file"

total_reports=0
go_reports=0
no_go_reports=0
eval_errors=0

declare -A reason_counts=()
details_file="$tmp_dir/details.txt"
touch "$details_file"

while IFS=$'\t' read -r _mtime report_path || [[ -n "${report_path:-}" ]]; do
  [[ -z "${report_path:-}" ]] && continue
  total_reports=$((total_reports + 1))

  generated_at="$(jq -r '.generated_at_utc // ""' "$report_path" 2>/dev/null || true)"
  if [[ -z "$generated_at" ]]; then
    generated_at="unknown"
  fi

  out_file="$tmp_dir/slo_${total_reports}.log"
  set +e
  "$SLO_SUMMARY_SCRIPT" \
    --run-report-json "$report_path" \
    --require-full-sequence "$require_full_sequence" \
    --require-wg-validate-ok "$require_wg_validate_ok" \
    --require-wg-soak-ok "$require_wg_soak_ok" \
    --max-wg-soak-failed-rounds "$max_wg_soak_failed_rounds" \
    --require-preflight-ok "$require_preflight_ok" \
    --require-bundle-ok "$require_bundle_ok" \
    --require-integrity-ok "$require_integrity_ok" \
    --require-signoff-ok "$require_signoff_ok" \
    --require-incident-snapshot-on-fail "$require_incident_snapshot_on_fail" \
    --require-incident-snapshot-artifacts "$require_incident_snapshot_artifacts" \
    --require-wg-validate-udp-source "$require_wg_validate_udp_source" \
    --require-wg-validate-strict-distinct "$require_wg_validate_strict_distinct" \
    --require-wg-soak-diversity-pass "$require_wg_soak_diversity_pass" \
    --min-wg-soak-selection-lines "$min_wg_soak_selection_lines" \
    --min-wg-soak-entry-operators "$min_wg_soak_entry_operators" \
    --min-wg-soak-exit-operators "$min_wg_soak_exit_operators" \
    --min-wg-soak-cross-operator-pairs "$min_wg_soak_cross_operator_pairs" \
    --fail-on-no-go 0 \
    --show-json 0 >"$out_file" 2>&1
  rc=$?
  set -e

  decision="$(sed -nE 's/^\[prod-gate-slo\] decision=([A-Z-]+)$/\1/p' "$out_file" | tail -n1)"
  if [[ "$decision" != "GO" && "$decision" != "NO-GO" ]]; then
    decision="NO-GO"
    eval_errors=$((eval_errors + 1))
    reason_counts["slo summary execution failed (rc=$rc)"]=$(( ${reason_counts["slo summary execution failed (rc=$rc)"]:-0} + 1 ))
  fi

  first_reason=""
  if [[ "$decision" == "GO" ]]; then
    go_reports=$((go_reports + 1))
  else
    no_go_reports=$((no_go_reports + 1))
    while IFS= read -r reason || [[ -n "$reason" ]]; do
      reason="$(trim "${reason#- }")"
      [[ -z "$reason" ]] && continue
      if [[ -z "$first_reason" ]]; then
        first_reason="$reason"
      fi
      reason_counts["$reason"]=$(( ${reason_counts["$reason"]:-0} + 1 ))
    done < <(sed -nE 's/^  - (.*)$/\1/p' "$out_file")
    if [[ -z "$first_reason" ]]; then
      first_reason="unspecified no-go reason"
      reason_counts["$first_reason"]=$(( ${reason_counts["$first_reason"]:-0} + 1 ))
    fi
  fi

  printf '%s\t%s\t%s\t%s\n' "$generated_at" "$decision" "$report_path" "$first_reason" >>"$details_file"
done <"$selected_file"

go_rate_pct="$(awk -v g="$go_reports" -v t="$total_reports" 'BEGIN { if (t == 0) { printf "0.00" } else { printf "%.2f", (g * 100.0) / t } }')"

echo "[prod-gate-slo-trend] reports_total=$total_reports go=$go_reports no_go=$no_go_reports go_rate_pct=$go_rate_pct"
echo "[prod-gate-slo-trend] filters max_reports=$max_reports since_hours=$since_hours"
echo "[prod-gate-slo-trend] policy require_full_sequence=$require_full_sequence require_wg_validate_ok=$require_wg_validate_ok require_wg_soak_ok=$require_wg_soak_ok max_wg_soak_failed_rounds=$max_wg_soak_failed_rounds require_preflight_ok=$require_preflight_ok require_bundle_ok=$require_bundle_ok require_integrity_ok=$require_integrity_ok require_signoff_ok=$require_signoff_ok require_wg_validate_udp_source=$require_wg_validate_udp_source require_wg_validate_strict_distinct=$require_wg_validate_strict_distinct require_wg_soak_diversity_pass=$require_wg_soak_diversity_pass min_wg_soak_selection_lines=$min_wg_soak_selection_lines min_wg_soak_entry_operators=$min_wg_soak_entry_operators min_wg_soak_exit_operators=$min_wg_soak_exit_operators min_wg_soak_cross_operator_pairs=$min_wg_soak_cross_operator_pairs"
if ((eval_errors > 0)); then
  echo "[prod-gate-slo-trend] evaluation_errors=$eval_errors"
fi

if [[ "$show_details" == "1" ]]; then
  idx=0
  while IFS=$'\t' read -r generated_at decision report_path first_reason || [[ -n "${report_path:-}" ]]; do
    [[ -z "${report_path:-}" ]] && continue
    idx=$((idx + 1))
    echo "[prod-gate-slo-trend] run[$idx] decision=$decision generated_at=$generated_at path=$report_path"
    if [[ "$decision" == "NO-GO" ]]; then
      echo "[prod-gate-slo-trend] run[$idx] no_go_reason=$first_reason"
    fi
  done <"$details_file"
fi

reasons_ranked="$tmp_dir/reasons_ranked.txt"
: >"$reasons_ranked"
if ((no_go_reports > 0)); then
  for reason in "${!reason_counts[@]}"; do
    printf '%s\t%s\n' "${reason_counts[$reason]}" "$reason" >>"$reasons_ranked"
  done
fi

if ((no_go_reports > 0 && show_top_reasons > 0)); then
  echo "[prod-gate-slo-trend] top_no_go_reasons:"
  rank=0
  while IFS=$'\t' read -r count reason || [[ -n "${reason:-}" ]]; do
    [[ -z "${reason:-}" ]] && continue
    rank=$((rank + 1))
    echo "  $rank) count=$count reason=$reason"
    if ((rank >= show_top_reasons)); then
      break
    fi
  done < <(sort -rn "$reasons_ranked")
fi

decision="GO"
if [[ "$fail_on_any_no_go" == "1" && "$no_go_reports" -gt 0 ]]; then
  decision="NO-GO"
fi
if float_lt "$go_rate_pct" "$min_go_rate_pct"; then
  decision="NO-GO"
fi

echo "[prod-gate-slo-trend] trend_decision=$decision fail_on_any_no_go=$fail_on_any_no_go min_go_rate_pct=$min_go_rate_pct"

details_json="$(jq -Rn '[inputs | split("\t") | {generated_at_utc: .[0], decision: .[1], report_path: .[2], first_no_go_reason: .[3]}]' <"$details_file")"
if [[ -s "$reasons_ranked" ]]; then
  top_reasons_json="$(
    sort -rn "$reasons_ranked" | jq -Rn --argjson limit "$show_top_reasons" '[inputs | split("\t") | {count: (.[0] | tonumber), reason: .[1]}] | .[:$limit]'
  )"
else
  top_reasons_json='[]'
fi

summary_payload="$(
  jq -n \
    --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg decision "$decision" \
    --argjson reports_total "$total_reports" \
    --argjson go "$go_reports" \
    --argjson no_go "$no_go_reports" \
    --argjson go_rate_pct "$go_rate_pct" \
    --argjson eval_errors "$eval_errors" \
    --argjson max_reports "$max_reports" \
    --argjson since_hours "$since_hours" \
    --argjson min_go_rate_pct "$min_go_rate_pct" \
    --argjson require_full_sequence "$require_full_sequence" \
    --argjson require_wg_validate_ok "$require_wg_validate_ok" \
    --argjson require_wg_soak_ok "$require_wg_soak_ok" \
    --argjson max_wg_soak_failed_rounds "$max_wg_soak_failed_rounds" \
    --argjson require_preflight_ok "$require_preflight_ok" \
    --argjson require_bundle_ok "$require_bundle_ok" \
    --argjson require_integrity_ok "$require_integrity_ok" \
    --argjson require_signoff_ok "$require_signoff_ok" \
    --argjson require_wg_validate_udp_source "$require_wg_validate_udp_source" \
    --argjson require_wg_validate_strict_distinct "$require_wg_validate_strict_distinct" \
    --argjson require_wg_soak_diversity_pass "$require_wg_soak_diversity_pass" \
    --argjson min_wg_soak_selection_lines "$min_wg_soak_selection_lines" \
    --argjson min_wg_soak_entry_operators "$min_wg_soak_entry_operators" \
    --argjson min_wg_soak_exit_operators "$min_wg_soak_exit_operators" \
    --argjson min_wg_soak_cross_operator_pairs "$min_wg_soak_cross_operator_pairs" \
    --argjson fail_on_any_no_go "$fail_on_any_no_go" \
    --argjson show_top_reasons "$show_top_reasons" \
    --argjson top_no_go_reasons "$top_reasons_json" \
    --argjson runs "$details_json" \
    '{
      version: 1,
      generated_at_utc: $generated_at_utc,
      decision: $decision,
      reports_total: $reports_total,
      go: $go,
      no_go: $no_go,
      go_rate_pct: $go_rate_pct,
      evaluation_errors: $eval_errors,
      filters: {
        max_reports: $max_reports,
        since_hours: $since_hours
      },
      policy: {
        require_full_sequence: $require_full_sequence,
        require_wg_validate_ok: $require_wg_validate_ok,
        require_wg_soak_ok: $require_wg_soak_ok,
        max_wg_soak_failed_rounds: $max_wg_soak_failed_rounds,
        require_preflight_ok: $require_preflight_ok,
        require_bundle_ok: $require_bundle_ok,
        require_integrity_ok: $require_integrity_ok,
        require_signoff_ok: $require_signoff_ok,
        require_wg_validate_udp_source: $require_wg_validate_udp_source,
        require_wg_validate_strict_distinct: $require_wg_validate_strict_distinct,
        require_wg_soak_diversity_pass: $require_wg_soak_diversity_pass,
        min_wg_soak_selection_lines: $min_wg_soak_selection_lines,
        min_wg_soak_entry_operators: $min_wg_soak_entry_operators,
        min_wg_soak_exit_operators: $min_wg_soak_exit_operators,
        min_wg_soak_cross_operator_pairs: $min_wg_soak_cross_operator_pairs,
        fail_on_any_no_go: $fail_on_any_no_go,
        min_go_rate_pct: $min_go_rate_pct
      },
      top_no_go_reasons_limit: $show_top_reasons,
      top_no_go_reasons: $top_no_go_reasons,
      runs: $runs
    }'
)"

if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  printf '%s\n' "$summary_payload" >"$summary_json"
  echo "[prod-gate-slo-trend] summary_json=$summary_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  echo "[prod-gate-slo-trend] summary_json_payload:"
  printf '%s\n' "$summary_payload"
fi

if [[ "$decision" == "NO-GO" ]]; then
  exit 1
fi
exit 0
