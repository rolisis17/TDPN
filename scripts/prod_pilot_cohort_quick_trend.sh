#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

QUICK_CHECK_SCRIPT="${PROD_PILOT_COHORT_QUICK_CHECK_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_quick_check.sh}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_pilot_cohort_quick_trend.sh \
    [--run-report-json PATH]... \
    [--run-report-list FILE] \
    [--reports-dir DIR] \
    [--max-reports N] \
    [--since-hours N] \
    [--require-status-ok [0|1]] \
    [--require-runbook-ok [0|1]] \
    [--require-signoff-attempted [0|1]] \
    [--require-signoff-ok [0|1]] \
    [--require-cohort-signoff-policy [0|1]] \
    [--require-summary-json [0|1]] \
    [--require-summary-status-ok [0|1]] \
    [--require-incident-snapshot-on-fail [0|1]] \
    [--require-incident-snapshot-artifacts [0|1]] \
    [--incident-snapshot-min-attachment-count N] \
    [--incident-snapshot-max-skipped-count N|-1] \
    [--max-duration-sec N] \
    [--fail-on-any-no-go [0|1]] \
    [--min-go-rate-pct N] \
    [--show-details [0|1]] \
    [--show-top-reasons N] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Evaluate GO/NO-GO trend across quick-mode sustained-pilot run reports.

Notes:
  - If no report input is supplied, defaults to scanning ./.easy-node-logs.
  - Per-report decision is delegated to prod_pilot_cohort_quick_check.sh using
    the same quick policy flags.
  - Use --fail-on-any-no-go=1 and/or --min-go-rate-pct for fail-close trend gates.
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

abs_path() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    echo ""
    return
  fi
  if [[ "$path" == /* ]]; then
    echo "$path"
  else
    echo "$ROOT_DIR/$path"
  fi
}

json_string_file() {
  local file="$1"
  local expr="$2"
  if [[ -z "$file" || ! -f "$file" ]]; then
    echo ""
    return
  fi
  jq -er "$expr // empty" "$file" 2>/dev/null || true
}

json_bool_flag_file() {
  local file="$1"
  local expr="$2"
  if [[ -z "$file" || ! -f "$file" ]]; then
    echo "0"
    return
  fi
  if jq -er "$expr == true" "$file" >/dev/null 2>&1; then
    echo "1"
  else
    echo "0"
  fi
}

path_exists01() {
  local path
  path="$(trim "${1:-}")"
  if [[ -n "$path" && -e "$path" ]]; then
    echo "1"
  else
    echo "0"
  fi
}

json_valid01() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" || ! -f "$path" ]]; then
    echo "0"
    return
  fi
  if jq -e . "$path" >/dev/null 2>&1; then
    echo "1"
  else
    echo "0"
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

is_non_negative_decimal() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]]
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

require_status_ok="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_STATUS_OK:-1}"
require_runbook_ok="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_RUNBOOK_OK:-1}"
require_signoff_attempted="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_SIGNOFF_ATTEMPTED:-1}"
require_signoff_ok="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_SIGNOFF_OK:-1}"
require_cohort_signoff_policy="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_COHORT_SIGNOFF_POLICY:-0}"
require_summary_json="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_SUMMARY_JSON:-1}"
require_summary_status_ok="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_SUMMARY_STATUS_OK:-1}"
require_incident_snapshot_on_fail="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_INCIDENT_SNAPSHOT_ON_FAIL:-1}"
require_incident_snapshot_artifacts="${PROD_PILOT_COHORT_QUICK_CHECK_REQUIRE_INCIDENT_SNAPSHOT_ARTIFACTS:-1}"
incident_snapshot_min_attachment_count="${PROD_PILOT_COHORT_QUICK_CHECK_INCIDENT_SNAPSHOT_MIN_ATTACHMENT_COUNT:-0}"
incident_snapshot_max_skipped_count="${PROD_PILOT_COHORT_QUICK_CHECK_INCIDENT_SNAPSHOT_MAX_SKIPPED_COUNT:--1}"
max_duration_sec="${PROD_PILOT_COHORT_QUICK_CHECK_MAX_DURATION_SEC:-0}"

fail_on_any_no_go="${PROD_PILOT_COHORT_QUICK_TREND_FAIL_ON_ANY_NO_GO:-0}"
min_go_rate_pct="${PROD_PILOT_COHORT_QUICK_TREND_MIN_GO_RATE_PCT:-0}"
max_reports="${PROD_PILOT_COHORT_QUICK_TREND_MAX_REPORTS:-25}"
since_hours="${PROD_PILOT_COHORT_QUICK_TREND_SINCE_HOURS:-0}"
show_details="${PROD_PILOT_COHORT_QUICK_TREND_SHOW_DETAILS:-1}"
show_top_reasons="${PROD_PILOT_COHORT_QUICK_TREND_SHOW_TOP_REASONS:-5}"
summary_json=""
print_summary_json="${PROD_PILOT_COHORT_QUICK_TREND_PRINT_SUMMARY_JSON:-0}"

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
    --require-status-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_status_ok="${2:-}"
        shift 2
      else
        require_status_ok="1"
        shift
      fi
      ;;
    --require-runbook-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_runbook_ok="${2:-}"
        shift 2
      else
        require_runbook_ok="1"
        shift
      fi
      ;;
    --require-signoff-attempted)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_signoff_attempted="${2:-}"
        shift 2
      else
        require_signoff_attempted="1"
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
    --require-cohort-signoff-policy)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_cohort_signoff_policy="${2:-}"
        shift 2
      else
        require_cohort_signoff_policy="1"
        shift
      fi
      ;;
    --require-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_summary_json="${2:-}"
        shift 2
      else
        require_summary_json="1"
        shift
      fi
      ;;
    --require-summary-status-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_summary_status_ok="${2:-}"
        shift 2
      else
        require_summary_status_ok="1"
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
    --incident-snapshot-min-attachment-count)
      incident_snapshot_min_attachment_count="${2:-}"
      shift 2
      ;;
    --incident-snapshot-max-skipped-count)
      incident_snapshot_max_skipped_count="${2:-}"
      shift 2
      ;;
    --max-duration-sec)
      max_duration_sec="${2:-}"
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

if [[ ! -x "$QUICK_CHECK_SCRIPT" ]]; then
  echo "missing executable quick-check script: $QUICK_CHECK_SCRIPT"
  exit 2
fi

bool_arg_or_die "--require-status-ok" "$require_status_ok"
bool_arg_or_die "--require-runbook-ok" "$require_runbook_ok"
bool_arg_or_die "--require-signoff-attempted" "$require_signoff_attempted"
bool_arg_or_die "--require-signoff-ok" "$require_signoff_ok"
bool_arg_or_die "--require-cohort-signoff-policy" "$require_cohort_signoff_policy"
bool_arg_or_die "--require-summary-json" "$require_summary_json"
bool_arg_or_die "--require-summary-status-ok" "$require_summary_status_ok"
bool_arg_or_die "--require-incident-snapshot-on-fail" "$require_incident_snapshot_on_fail"
bool_arg_or_die "--require-incident-snapshot-artifacts" "$require_incident_snapshot_artifacts"
bool_arg_or_die "--fail-on-any-no-go" "$fail_on_any_no_go"
bool_arg_or_die "--show-details" "$show_details"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

if [[ ! "$max_duration_sec" =~ ^[0-9]+$ ]]; then
  echo "--max-duration-sec must be an integer >= 0"
  exit 2
fi
if [[ ! "$incident_snapshot_min_attachment_count" =~ ^[0-9]+$ ]]; then
  echo "--incident-snapshot-min-attachment-count must be an integer >= 0"
  exit 2
fi
if [[ ! "$incident_snapshot_max_skipped_count" =~ ^-?[0-9]+$ ]] || ((incident_snapshot_max_skipped_count < -1)); then
  echo "--incident-snapshot-max-skipped-count must be an integer >= -1"
  exit 2
fi
if [[ ! "$max_reports" =~ ^[0-9]+$ ]] || ((max_reports < 1)); then
  echo "--max-reports must be an integer >= 1"
  exit 2
fi
if [[ ! "$since_hours" =~ ^[0-9]+$ ]]; then
  echo "--since-hours must be an integer >= 0"
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
  find "$reports_dir" -type f -name 'prod_pilot_cohort_quick_report.json' -print >>"$candidates_file"
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
    echo "[prod-pilot-cohort-quick-trend] warning: skipping missing run report: $local_path"
    continue
  fi
  if ! jq -e . "$local_path" >/dev/null 2>&1; then
    echo "[prod-pilot-cohort-quick-trend] warning: skipping invalid JSON run report: $local_path"
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
  echo "no valid quick run reports found"
  exit 1
fi

selected_file="$tmp_dir/selected_reports.txt"
sort -rn "$ranked_file" | head -n "$max_reports" >"$selected_file"

total_reports=0
go_reports=0
no_go_reports=0
eval_errors=0

incident_source_quick_run_report=""
incident_source_quick_run_report_exists=0
incident_source_summary_json=""
incident_source_summary_exists=0
incident_source_summary_valid_json=0
incident_latest_run_report=""
incident_enabled=0
incident_status=""
incident_bundle_dir=""
incident_bundle_dir_exists=0
incident_bundle_tar=""
incident_bundle_tar_exists=0
incident_summary_json=""
incident_summary_exists=0
incident_summary_valid_json=0
incident_report_md=""
incident_report_exists=0
incident_attachment_manifest=""
incident_attachment_manifest_exists=0
incident_attachment_skipped=""
incident_attachment_skipped_exists=0
incident_attachment_count=0

declare -A reason_counts=()
details_file="$tmp_dir/details.txt"
touch "$details_file"

while IFS=$'\t' read -r _mtime report_path || [[ -n "${report_path:-}" ]]; do
  [[ -z "${report_path:-}" ]] && continue
  total_reports=$((total_reports + 1))

  generated_at="$(jq -r '.finished_at // .started_at // .generated_at_utc // ""' "$report_path" 2>/dev/null || true)"
  if [[ -z "$generated_at" ]]; then
    generated_at="unknown"
  fi

  quick_summary_json="$(abs_path "$(json_string_file "$report_path" '.artifacts.summary_json')")"
  quick_summary_exists="$(path_exists01 "$quick_summary_json")"
  quick_summary_valid_json="$(json_valid01 "$quick_summary_json")"
  if [[ -z "$incident_latest_run_report" && "$quick_summary_valid_json" == "1" ]]; then
    candidate_incident_run_report="$(abs_path "$(json_string_file "$quick_summary_json" '.incident_snapshot.latest_failed_run_report.path')")"
    candidate_incident_enabled="$(json_bool_flag_file "$quick_summary_json" '.incident_snapshot.latest_failed_run_report.enabled')"
    candidate_incident_status="$(json_string_file "$quick_summary_json" '.incident_snapshot.latest_failed_run_report.status')"
    candidate_incident_bundle_dir="$(abs_path "$(json_string_file "$quick_summary_json" '.incident_snapshot.latest_failed_run_report.bundle_dir.path')")"
    candidate_incident_bundle_tar="$(abs_path "$(json_string_file "$quick_summary_json" '.incident_snapshot.latest_failed_run_report.bundle_tar.path')")"
    candidate_incident_summary_json="$(abs_path "$(json_string_file "$quick_summary_json" '.incident_snapshot.latest_failed_run_report.summary_json.path')")"
    candidate_incident_report_md="$(abs_path "$(json_string_file "$quick_summary_json" '.incident_snapshot.latest_failed_run_report.report_md.path')")"
    candidate_incident_attachment_manifest="$(abs_path "$(json_string_file "$quick_summary_json" '.incident_snapshot.latest_failed_run_report.attachment_manifest.path')")"
    candidate_incident_attachment_skipped="$(abs_path "$(json_string_file "$quick_summary_json" '.incident_snapshot.latest_failed_run_report.attachment_skipped.path')")"
    candidate_incident_attachment_count="$(json_string_file "$quick_summary_json" '.incident_snapshot.latest_failed_run_report.attachment_count')"
    if [[ -z "$candidate_incident_attachment_count" ]]; then
      candidate_incident_attachment_count="0"
    fi
    if [[ -n "$candidate_incident_run_report" || -n "$candidate_incident_summary_json" || -n "$candidate_incident_report_md" || -n "$candidate_incident_attachment_manifest" || -n "$candidate_incident_attachment_skipped" ]]; then
      incident_source_quick_run_report="$report_path"
      incident_source_quick_run_report_exists="$(path_exists01 "$incident_source_quick_run_report")"
      incident_source_summary_json="$quick_summary_json"
      incident_source_summary_exists="$quick_summary_exists"
      incident_source_summary_valid_json="$quick_summary_valid_json"
      incident_latest_run_report="$candidate_incident_run_report"
      incident_enabled="$candidate_incident_enabled"
      incident_status="$candidate_incident_status"
      incident_bundle_dir="$candidate_incident_bundle_dir"
      incident_bundle_dir_exists="$(path_exists01 "$incident_bundle_dir")"
      incident_bundle_tar="$candidate_incident_bundle_tar"
      incident_bundle_tar_exists="$(path_exists01 "$incident_bundle_tar")"
      incident_summary_json="$candidate_incident_summary_json"
      incident_summary_exists="$(path_exists01 "$incident_summary_json")"
      incident_summary_valid_json="$(json_valid01 "$incident_summary_json")"
      incident_report_md="$candidate_incident_report_md"
      incident_report_exists="$(path_exists01 "$incident_report_md")"
      incident_attachment_manifest="$candidate_incident_attachment_manifest"
      incident_attachment_manifest_exists="$(path_exists01 "$incident_attachment_manifest")"
      incident_attachment_skipped="$candidate_incident_attachment_skipped"
      incident_attachment_skipped_exists="$(path_exists01 "$incident_attachment_skipped")"
      incident_attachment_count="$candidate_incident_attachment_count"
    fi
  fi

  out_file="$tmp_dir/quick_check_${total_reports}.log"
  set +e
  "$QUICK_CHECK_SCRIPT" \
    --run-report-json "$report_path" \
    --require-status-ok "$require_status_ok" \
    --require-runbook-ok "$require_runbook_ok" \
    --require-signoff-attempted "$require_signoff_attempted" \
    --require-signoff-ok "$require_signoff_ok" \
    --require-cohort-signoff-policy "$require_cohort_signoff_policy" \
    --require-summary-json "$require_summary_json" \
    --require-summary-status-ok "$require_summary_status_ok" \
    --require-incident-snapshot-on-fail "$require_incident_snapshot_on_fail" \
    --require-incident-snapshot-artifacts "$require_incident_snapshot_artifacts" \
    --incident-snapshot-min-attachment-count "$incident_snapshot_min_attachment_count" \
    --incident-snapshot-max-skipped-count "$incident_snapshot_max_skipped_count" \
    --max-duration-sec "$max_duration_sec" \
    --show-json 0 >"$out_file" 2>&1
  rc=$?
  set -e

  decision="$(sed -nE 's/^\[prod-pilot-cohort-quick-check\] decision=([A-Z-]+).*/\1/p' "$out_file" | tail -n1)"
  if [[ "$decision" != "GO" && "$decision" != "NO-GO" ]]; then
    if [[ "$rc" -eq 0 ]]; then
      decision="GO"
    else
      decision="NO-GO"
    fi
    eval_errors=$((eval_errors + 1))
    reason_counts["quick-check decision parse failed (rc=$rc)"]=$(( ${reason_counts["quick-check decision parse failed (rc=$rc)"]:-0} + 1 ))
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

echo "[prod-pilot-cohort-quick-trend] reports_total=$total_reports go=$go_reports no_go=$no_go_reports go_rate_pct=$go_rate_pct"
echo "[prod-pilot-cohort-quick-trend] filters max_reports=$max_reports since_hours=$since_hours"
echo "[prod-pilot-cohort-quick-trend] policy require_status_ok=$require_status_ok require_runbook_ok=$require_runbook_ok require_signoff_attempted=$require_signoff_attempted require_signoff_ok=$require_signoff_ok require_cohort_signoff_policy=$require_cohort_signoff_policy require_summary_json=$require_summary_json require_summary_status_ok=$require_summary_status_ok max_duration_sec=$max_duration_sec incident_snapshot_min_attachment_count=$incident_snapshot_min_attachment_count incident_snapshot_max_skipped_count=$incident_snapshot_max_skipped_count"
if ((eval_errors > 0)); then
  echo "[prod-pilot-cohort-quick-trend] evaluation_errors=$eval_errors"
fi

if [[ "$show_details" == "1" ]]; then
  idx=0
  while IFS=$'\t' read -r generated_at decision report_path first_reason || [[ -n "${report_path:-}" ]]; do
    [[ -z "${report_path:-}" ]] && continue
    idx=$((idx + 1))
    echo "[prod-pilot-cohort-quick-trend] run[$idx] decision=$decision generated_at=$generated_at path=$report_path"
    if [[ "$decision" == "NO-GO" ]]; then
      echo "[prod-pilot-cohort-quick-trend] run[$idx] no_go_reason=$first_reason"
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
  echo "[prod-pilot-cohort-quick-trend] top_no_go_reasons:"
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

if [[ -n "$incident_latest_run_report" || -n "$incident_summary_json" || -n "$incident_report_md" || -n "$incident_attachment_manifest" || -n "$incident_attachment_skipped" ]]; then
  echo "[prod-pilot-cohort-quick-trend] incident_handoff source_quick_run_report=${incident_source_quick_run_report:-unset} source_run_report=${incident_latest_run_report:-unset} summary_json=${incident_summary_json:-unset} report_md=${incident_report_md:-unset} attachment_manifest=${incident_attachment_manifest:-unset} attachment_skipped=${incident_attachment_skipped:-unset} attachment_count=${incident_attachment_count}"
fi

decision="GO"
if [[ "$fail_on_any_no_go" == "1" && "$no_go_reports" -gt 0 ]]; then
  decision="NO-GO"
fi
if float_lt "$go_rate_pct" "$min_go_rate_pct"; then
  decision="NO-GO"
fi

echo "[prod-pilot-cohort-quick-trend] trend_decision=$decision fail_on_any_no_go=$fail_on_any_no_go min_go_rate_pct=$min_go_rate_pct"

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
    --argjson require_status_ok "$require_status_ok" \
    --argjson require_runbook_ok "$require_runbook_ok" \
    --argjson require_signoff_attempted "$require_signoff_attempted" \
    --argjson require_signoff_ok "$require_signoff_ok" \
    --argjson require_cohort_signoff_policy "$require_cohort_signoff_policy" \
    --argjson require_summary_json "$require_summary_json" \
    --argjson require_summary_status_ok "$require_summary_status_ok" \
    --argjson max_duration_sec "$max_duration_sec" \
    --argjson incident_snapshot_min_attachment_count "$incident_snapshot_min_attachment_count" \
    --argjson incident_snapshot_max_skipped_count "$incident_snapshot_max_skipped_count" \
    --argjson fail_on_any_no_go "$fail_on_any_no_go" \
    --argjson min_go_rate_pct "$min_go_rate_pct" \
    --argjson show_top_reasons "$show_top_reasons" \
    --argjson top_no_go_reasons "$top_reasons_json" \
    --argjson runs "$details_json" \
    --arg incident_source_quick_run_report "$incident_source_quick_run_report" \
    --arg incident_source_summary_json "$incident_source_summary_json" \
    --arg incident_latest_run_report "$incident_latest_run_report" \
    --arg incident_status "$incident_status" \
    --arg incident_bundle_dir "$incident_bundle_dir" \
    --arg incident_bundle_tar "$incident_bundle_tar" \
    --arg incident_summary_json "$incident_summary_json" \
    --arg incident_report_md "$incident_report_md" \
    --arg incident_attachment_manifest "$incident_attachment_manifest" \
    --arg incident_attachment_skipped "$incident_attachment_skipped" \
    --argjson incident_source_quick_run_report_exists "$incident_source_quick_run_report_exists" \
    --argjson incident_source_summary_exists "$incident_source_summary_exists" \
    --argjson incident_source_summary_valid_json "$incident_source_summary_valid_json" \
    --argjson incident_enabled "$incident_enabled" \
    --argjson incident_bundle_dir_exists "$incident_bundle_dir_exists" \
    --argjson incident_bundle_tar_exists "$incident_bundle_tar_exists" \
    --argjson incident_summary_exists "$incident_summary_exists" \
    --argjson incident_summary_valid_json "$incident_summary_valid_json" \
    --argjson incident_report_exists "$incident_report_exists" \
    --argjson incident_attachment_manifest_exists "$incident_attachment_manifest_exists" \
    --argjson incident_attachment_skipped_exists "$incident_attachment_skipped_exists" \
    --argjson incident_attachment_count "$incident_attachment_count" \
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
        require_status_ok: $require_status_ok,
        require_runbook_ok: $require_runbook_ok,
        require_signoff_attempted: $require_signoff_attempted,
        require_signoff_ok: $require_signoff_ok,
        require_cohort_signoff_policy: $require_cohort_signoff_policy,
        require_summary_json: $require_summary_json,
        require_summary_status_ok: $require_summary_status_ok,
        max_duration_sec: $max_duration_sec,
        incident_snapshot_min_attachment_count: $incident_snapshot_min_attachment_count,
        incident_snapshot_max_skipped_count: $incident_snapshot_max_skipped_count,
        fail_on_any_no_go: $fail_on_any_no_go,
        min_go_rate_pct: $min_go_rate_pct
      },
      incident_snapshot: {
        latest_failed_run_report: {
          source_quick_run_report: {path: ($incident_source_quick_run_report // ""), exists: $incident_source_quick_run_report_exists},
          source_summary_json: {path: ($incident_source_summary_json // ""), exists: $incident_source_summary_exists, valid_json: $incident_source_summary_valid_json},
          path: ($incident_latest_run_report // ""),
          enabled: $incident_enabled,
          status: ($incident_status // ""),
          bundle_dir: {path: ($incident_bundle_dir // ""), exists: $incident_bundle_dir_exists},
          bundle_tar: {path: ($incident_bundle_tar // ""), exists: $incident_bundle_tar_exists},
          summary_json: {path: ($incident_summary_json // ""), exists: $incident_summary_exists, valid_json: $incident_summary_valid_json},
          report_md: {path: ($incident_report_md // ""), exists: $incident_report_exists},
          attachment_manifest: {path: ($incident_attachment_manifest // ""), exists: $incident_attachment_manifest_exists},
          attachment_skipped: {path: ($incident_attachment_skipped // ""), exists: $incident_attachment_skipped_exists},
          attachment_count: $incident_attachment_count
        }
      },
      top_no_go_reasons_limit: $show_top_reasons,
      top_no_go_reasons: $top_no_go_reasons,
      runs: $runs
    }'
)"

if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  printf '%s\n' "$summary_payload" >"$summary_json"
  echo "[prod-pilot-cohort-quick-trend] summary_json=$summary_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  echo "[prod-pilot-cohort-quick-trend] summary_json_payload:"
  printf '%s\n' "$summary_payload"
fi

if [[ "$decision" == "NO-GO" ]]; then
  exit 1
fi
exit 0
