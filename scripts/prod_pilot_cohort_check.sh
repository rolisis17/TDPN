#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_pilot_cohort_check.sh \
    [--summary-json PATH] \
    [--reports-dir PATH] \
    [--require-status-ok [0|1]] \
    [--require-all-rounds-ok [0|1]] \
    [--max-round-failures N] \
    [--require-trend-go [0|1]] \
    [--min-go-rate-pct N] \
    [--max-alert-severity OK|WARN|CRITICAL] \
    [--require-bundle-created [0|1]] \
    [--require-bundle-manifest [0|1]] \
    [--require-incident-snapshot-on-fail [0|1]] \
    [--require-incident-snapshot-artifacts [0|1]] \
    [--show-json [0|1]]

Purpose:
  Verify sustained pilot cohort summary artifacts and enforce fail-closed signoff policy.

Notes:
  - Provide one of:
    - --summary-json (recommended; from prod-pilot-cohort-runbook)
    - --reports-dir (auto-resolves <reports_dir>/prod_pilot_cohort_summary.json)
  - Default policy is strict: status must be ok, rounds_failed must be 0, trend decision
    must be GO, GO rate must be >= 95, alert severity must be <= WARN, and bundle
    artifacts must be present.
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

severity_rank() {
  local severity
  severity="$(printf '%s' "${1:-}" | tr '[:lower:]' '[:upper:]')"
  case "$severity" in
    OK) echo "0" ;;
    WARN) echo "1" ;;
    CRITICAL) echo "2" ;;
    *) echo "-1" ;;
  esac
}

json_bool() {
  if [[ "${1:-0}" == "1" ]]; then
    echo "true"
  else
    echo "false"
  fi
}

json_string() {
  local file="$1"
  local expr="$2"
  jq -r "$expr // \"\"" "$file" 2>/dev/null || true
}

json_int() {
  local file="$1"
  local expr="$2"
  local value
  value="$(jq -r "$expr // 0" "$file" 2>/dev/null || true)"
  if [[ -z "$value" || ! "$value" =~ ^-?[0-9]+$ ]]; then
    echo "0"
    return
  fi
  echo "$value"
}

json_bool_flag() {
  local file="$1"
  local expr="$2"
  local value
  value="$(jq -r "$expr // false | if . then \"1\" else \"0\" end" "$file" 2>/dev/null || true)"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "0"
    return
  fi
  echo "$value"
}

json_string_array() {
  local file="$1"
  local expr="$2"
  jq -r "$expr // [] | .[]? // empty" "$file" 2>/dev/null || true
}

for cmd in bash jq awk date; do
  need_cmd "$cmd"
done

summary_json=""
reports_dir=""
require_status_ok="${PROD_PILOT_COHORT_CHECK_REQUIRE_STATUS_OK:-1}"
require_all_rounds_ok="${PROD_PILOT_COHORT_CHECK_REQUIRE_ALL_ROUNDS_OK:-1}"
max_round_failures="${PROD_PILOT_COHORT_CHECK_MAX_ROUND_FAILURES:-0}"
require_trend_go="${PROD_PILOT_COHORT_CHECK_REQUIRE_TREND_GO:-1}"
min_go_rate_pct="${PROD_PILOT_COHORT_CHECK_MIN_GO_RATE_PCT:-95}"
max_alert_severity="${PROD_PILOT_COHORT_CHECK_MAX_ALERT_SEVERITY:-WARN}"
require_bundle_created="${PROD_PILOT_COHORT_CHECK_REQUIRE_BUNDLE_CREATED:-1}"
require_bundle_manifest="${PROD_PILOT_COHORT_CHECK_REQUIRE_BUNDLE_MANIFEST:-1}"
require_incident_snapshot_on_fail="${PROD_PILOT_COHORT_CHECK_REQUIRE_INCIDENT_SNAPSHOT_ON_FAIL:-1}"
require_incident_snapshot_artifacts="${PROD_PILOT_COHORT_CHECK_REQUIRE_INCIDENT_SNAPSHOT_ARTIFACTS:-1}"
show_json="${PROD_PILOT_COHORT_CHECK_SHOW_JSON:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --reports-dir)
      reports_dir="${2:-}"
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
    --require-all-rounds-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_all_rounds_ok="${2:-}"
        shift 2
      else
        require_all_rounds_ok="1"
        shift
      fi
      ;;
    --max-round-failures)
      max_round_failures="${2:-}"
      shift 2
      ;;
    --require-trend-go)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_trend_go="${2:-}"
        shift 2
      else
        require_trend_go="1"
        shift
      fi
      ;;
    --min-go-rate-pct)
      min_go_rate_pct="${2:-}"
      shift 2
      ;;
    --max-alert-severity)
      max_alert_severity="${2:-}"
      shift 2
      ;;
    --require-bundle-created)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_bundle_created="${2:-}"
        shift 2
      else
        require_bundle_created="1"
        shift
      fi
      ;;
    --require-bundle-manifest)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_bundle_manifest="${2:-}"
        shift 2
      else
        require_bundle_manifest="1"
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
    --show-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        show_json="${2:-}"
        shift 2
      else
        show_json="1"
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

bool_arg_or_die "--require-status-ok" "$require_status_ok"
bool_arg_or_die "--require-all-rounds-ok" "$require_all_rounds_ok"
bool_arg_or_die "--require-trend-go" "$require_trend_go"
bool_arg_or_die "--require-bundle-created" "$require_bundle_created"
bool_arg_or_die "--require-bundle-manifest" "$require_bundle_manifest"
bool_arg_or_die "--require-incident-snapshot-on-fail" "$require_incident_snapshot_on_fail"
bool_arg_or_die "--require-incident-snapshot-artifacts" "$require_incident_snapshot_artifacts"
bool_arg_or_die "--show-json" "$show_json"

if [[ ! "$max_round_failures" =~ ^[0-9]+$ ]]; then
  echo "--max-round-failures must be an integer >= 0"
  exit 2
fi
if ! is_non_negative_decimal "$min_go_rate_pct"; then
  echo "--min-go-rate-pct must be a non-negative number"
  exit 2
fi
if float_lt "100" "$min_go_rate_pct"; then
  echo "--min-go-rate-pct must be <= 100"
  exit 2
fi

max_alert_severity="$(printf '%s' "$max_alert_severity" | tr '[:lower:]' '[:upper:]')"
max_alert_rank="$(severity_rank "$max_alert_severity")"
if [[ "$max_alert_rank" -lt 0 ]]; then
  echo "--max-alert-severity must be OK, WARN, or CRITICAL"
  exit 2
fi

summary_json="$(abs_path "$summary_json")"
reports_dir="$(abs_path "$reports_dir")"
if [[ -z "$summary_json" && -n "$reports_dir" ]]; then
  summary_json="$reports_dir/prod_pilot_cohort_summary.json"
fi
if [[ -z "$summary_json" ]]; then
  echo "missing required input: set --summary-json or --reports-dir"
  exit 2
fi
if [[ ! -f "$summary_json" ]]; then
  echo "cohort summary JSON file not found: $summary_json"
  exit 1
fi
if ! jq -e . "$summary_json" >/dev/null 2>&1; then
  echo "cohort summary JSON is not valid JSON: $summary_json"
  exit 1
fi

status="$(json_string "$summary_json" '.status')"
failure_step="$(json_string "$summary_json" '.failure_step')"
final_rc="$(json_int "$summary_json" '.final_rc')"

rounds_requested="$(json_int "$summary_json" '.rounds.requested')"
rounds_attempted="$(json_int "$summary_json" '.rounds.attempted')"
rounds_passed="$(json_int "$summary_json" '.rounds.passed')"
rounds_failed="$(json_int "$summary_json" '.rounds.failed')"

trend_rc="$(json_int "$summary_json" '.trend.rc')"
trend_go_rate_pct="$(json_string "$summary_json" '.trend.go_rate_pct')"
trend_summary_json="$(json_string "$summary_json" '.artifacts.trend_summary_json')"
if [[ -n "$trend_summary_json" && "$trend_summary_json" != /* ]]; then
  trend_summary_json="$ROOT_DIR/$trend_summary_json"
fi
trend_decision=""
if [[ -n "$trend_summary_json" && -f "$trend_summary_json" ]]; then
  trend_decision="$(jq -r '.decision // ""' "$trend_summary_json" 2>/dev/null || true)"
fi
trend_decision="$(printf '%s' "$trend_decision" | tr '[:lower:]' '[:upper:]')"

alert_rc="$(json_int "$summary_json" '.alert.rc')"
alert_severity="$(json_string "$summary_json" '.alert.severity')"
alert_severity="$(printf '%s' "$alert_severity" | tr '[:lower:]' '[:upper:]')"
alert_rank="$(severity_rank "$alert_severity")"
alert_policy_violation="$(json_bool_flag "$summary_json" '.alert.policy_violation')"

bundle_created="$(json_bool_flag "$summary_json" '.bundle.created')"
bundle_rc="$(json_int "$summary_json" '.bundle.rc')"
bundle_manifest_created="$(json_bool_flag "$summary_json" '.bundle.manifest_created')"
bundle_manifest_json="$(json_string "$summary_json" '.artifacts.bundle_manifest_json')"
if [[ -n "$bundle_manifest_json" && "$bundle_manifest_json" != /* ]]; then
  bundle_manifest_json="$ROOT_DIR/$bundle_manifest_json"
fi

declare -a errors=()

incident_failed_reports_checked=0
incident_failed_reports_ok=0
incident_failed_reports_policy_errors=0
if [[ "$rounds_failed" -gt 0 && ( "$require_incident_snapshot_on_fail" == "1" || "$require_incident_snapshot_artifacts" == "1" ) ]]; then
  mapfile -t run_report_paths < <(json_string_array "$summary_json" '.run_reports')
  if [[ "${#run_report_paths[@]}" -eq 0 ]]; then
    errors+=("incident snapshot policy requires run_reports[] in cohort summary when rounds_failed>0")
  fi

  failed_report_paths_found=0
  for rr in "${run_report_paths[@]:-}"; do
    rr="$(trim "$rr")"
    [[ -z "$rr" ]] && continue
    if [[ "$rr" != /* ]]; then
      rr="$ROOT_DIR/$rr"
    fi
    if [[ ! -f "$rr" ]]; then
      errors+=("run report file listed in cohort summary not found: $rr")
      incident_failed_reports_policy_errors=$((incident_failed_reports_policy_errors + 1))
      continue
    fi
    if ! jq -e . "$rr" >/dev/null 2>&1; then
      errors+=("run report listed in cohort summary is not valid JSON: $rr")
      incident_failed_reports_policy_errors=$((incident_failed_reports_policy_errors + 1))
      continue
    fi

    rr_status="$(json_string "$rr" '.status')"
    rr_final_rc="$(json_int "$rr" '.final_rc')"
    rr_failed=0
    if [[ "$rr_status" != "ok" || "$rr_final_rc" -ne 0 ]]; then
      rr_failed=1
    fi
    if [[ "$rr_failed" != "1" ]]; then
      continue
    fi

    failed_report_paths_found=$((failed_report_paths_found + 1))
    incident_failed_reports_checked=$((incident_failed_reports_checked + 1))

    rr_snapshot_enabled="$(json_bool_flag "$rr" '.incident_snapshot.enabled')"
    rr_snapshot_status="$(json_string "$rr" '.incident_snapshot.status')"
    rr_snapshot_bundle_dir="$(json_string "$rr" '.incident_snapshot.bundle_dir')"
    rr_snapshot_bundle_tar="$(json_string "$rr" '.incident_snapshot.bundle_tar')"
    if [[ -n "$rr_snapshot_bundle_dir" && "$rr_snapshot_bundle_dir" != /* ]]; then
      rr_snapshot_bundle_dir="$ROOT_DIR/$rr_snapshot_bundle_dir"
    fi
    if [[ -n "$rr_snapshot_bundle_tar" && "$rr_snapshot_bundle_tar" != /* ]]; then
      rr_snapshot_bundle_tar="$ROOT_DIR/$rr_snapshot_bundle_tar"
    fi

    rr_has_policy_error=0
    if [[ "$require_incident_snapshot_on_fail" == "1" ]]; then
      if [[ "$rr_snapshot_enabled" != "1" ]]; then
        errors+=("failed round run report missing incident snapshot enablement: $rr")
        rr_has_policy_error=1
      fi
      if [[ "$rr_snapshot_status" != "ok" ]]; then
        errors+=("failed round incident snapshot status is not ok: $rr (status=${rr_snapshot_status:-unset})")
        rr_has_policy_error=1
      fi
    fi

    if [[ "$require_incident_snapshot_artifacts" == "1" ]]; then
      if [[ -z "$rr_snapshot_bundle_dir" || ! -d "$rr_snapshot_bundle_dir" ]]; then
        errors+=("failed round incident snapshot bundle_dir missing/not-found: $rr (bundle_dir=${rr_snapshot_bundle_dir:-unset})")
        rr_has_policy_error=1
      fi
      if [[ -z "$rr_snapshot_bundle_tar" || ! -f "$rr_snapshot_bundle_tar" ]]; then
        errors+=("failed round incident snapshot bundle_tar missing/not-found: $rr (bundle_tar=${rr_snapshot_bundle_tar:-unset})")
        rr_has_policy_error=1
      fi
    fi

    if [[ "$rr_has_policy_error" == "1" ]]; then
      incident_failed_reports_policy_errors=$((incident_failed_reports_policy_errors + 1))
    else
      incident_failed_reports_ok=$((incident_failed_reports_ok + 1))
    fi
  done

  if [[ "$failed_report_paths_found" -eq 0 ]]; then
    errors+=("incident snapshot policy could not find failed run reports while rounds_failed=$rounds_failed")
  fi
fi

if [[ "$require_status_ok" == "1" && "$status" != "ok" ]]; then
  errors+=("cohort status is not ok (status=${status:-unset}, failure_step=${failure_step:-none}, final_rc=$final_rc)")
fi

if [[ "$require_all_rounds_ok" == "1" && "$rounds_failed" -gt 0 ]]; then
  errors+=("round policy violation: rounds_failed=$rounds_failed (require_all_rounds_ok=1)")
fi

if [[ "$rounds_failed" -gt "$max_round_failures" ]]; then
  errors+=("round failure budget exceeded: rounds_failed=$rounds_failed > max_round_failures=$max_round_failures")
fi

if [[ -z "$trend_go_rate_pct" || ! "$trend_go_rate_pct" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  errors+=("trend.go_rate_pct missing or invalid in cohort summary")
elif float_lt "$trend_go_rate_pct" "$min_go_rate_pct"; then
  errors+=("trend go-rate below threshold: go_rate_pct=$trend_go_rate_pct min_go_rate_pct=$min_go_rate_pct")
fi

if [[ "$require_trend_go" == "1" ]]; then
  if [[ -z "$trend_summary_json" ]]; then
    errors+=("trend summary path missing in cohort artifacts")
  elif [[ ! -f "$trend_summary_json" ]]; then
    errors+=("trend summary file not found: $trend_summary_json")
  elif [[ "$trend_decision" != "GO" ]]; then
    errors+=("trend decision is not GO (decision=${trend_decision:-unset})")
  fi
  if [[ "$trend_rc" -ne 0 ]]; then
    errors+=("trend rc is non-zero (trend_rc=$trend_rc)")
  fi
fi

if [[ "$alert_rc" -ne 0 ]]; then
  errors+=("alert rc is non-zero (alert_rc=$alert_rc)")
fi
if [[ "$alert_rank" -lt 0 ]]; then
  errors+=("alert severity missing or invalid (severity=${alert_severity:-unset})")
elif [[ "$alert_rank" -gt "$max_alert_rank" ]]; then
  errors+=("alert severity exceeds policy: severity=$alert_severity max_allowed=$max_alert_severity")
fi
if [[ "$alert_policy_violation" == "1" ]]; then
  errors+=("cohort summary reports alert policy violation")
fi

if [[ "$require_bundle_created" == "1" && "$bundle_created" != "1" ]]; then
  errors+=("bundle.created is false while bundle is required (bundle_rc=$bundle_rc)")
fi

if [[ "$require_bundle_manifest" == "1" ]]; then
  if [[ "$bundle_manifest_created" != "1" ]]; then
    errors+=("bundle.manifest_created is false while manifest is required")
  fi
  if [[ -z "$bundle_manifest_json" ]]; then
    errors+=("bundle manifest path missing in artifacts")
  elif [[ ! -f "$bundle_manifest_json" ]]; then
    errors+=("bundle manifest file not found: $bundle_manifest_json")
  fi
fi

decision="GO"
if [[ "${#errors[@]}" -gt 0 ]]; then
  decision="NO-GO"
fi

timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
errors_json="$(printf '%s\n' "${errors[@]}" | jq -R . | jq -s .)"
summary_payload="$(
  jq -nc \
    --arg timestamp "$timestamp" \
    --arg decision "$decision" \
    --arg status "$status" \
    --arg failure_step "$failure_step" \
    --argjson final_rc "$final_rc" \
    --argjson rounds_requested "$rounds_requested" \
    --argjson rounds_attempted "$rounds_attempted" \
    --argjson rounds_passed "$rounds_passed" \
    --argjson rounds_failed "$rounds_failed" \
    --argjson trend_rc "$trend_rc" \
    --arg trend_go_rate_pct "$trend_go_rate_pct" \
    --arg trend_decision "$trend_decision" \
    --argjson alert_rc "$alert_rc" \
    --arg alert_severity "$alert_severity" \
    --argjson alert_rank "$alert_rank" \
    --argjson max_alert_rank "$max_alert_rank" \
    --arg max_alert_severity "$max_alert_severity" \
    --argjson bundle_created "$(json_bool "$bundle_created")" \
    --argjson bundle_manifest_created "$(json_bool "$bundle_manifest_created")" \
    --arg bundle_manifest_json "$bundle_manifest_json" \
    --arg summary_json "$summary_json" \
    --arg trend_summary_json "$trend_summary_json" \
    --argjson require_status_ok "$(json_bool "$require_status_ok")" \
    --argjson require_all_rounds_ok "$(json_bool "$require_all_rounds_ok")" \
    --argjson max_round_failures "$max_round_failures" \
    --argjson require_trend_go "$(json_bool "$require_trend_go")" \
    --argjson min_go_rate_pct "$min_go_rate_pct" \
    --argjson require_bundle_created "$(json_bool "$require_bundle_created")" \
    --argjson require_bundle_manifest "$(json_bool "$require_bundle_manifest")" \
    --argjson require_incident_snapshot_on_fail "$(json_bool "$require_incident_snapshot_on_fail")" \
    --argjson require_incident_snapshot_artifacts "$(json_bool "$require_incident_snapshot_artifacts")" \
    --argjson incident_failed_reports_checked "$incident_failed_reports_checked" \
    --argjson incident_failed_reports_ok "$incident_failed_reports_ok" \
    --argjson incident_failed_reports_policy_errors "$incident_failed_reports_policy_errors" \
    --argjson errors "$errors_json" \
    '{
      generated_at_utc:$timestamp,
      decision:$decision,
      summary_json:$summary_json,
      status:$status,
      failure_step:$failure_step,
      final_rc:$final_rc,
      rounds:{
        requested:$rounds_requested,
        attempted:$rounds_attempted,
        passed:$rounds_passed,
        failed:$rounds_failed
      },
      trend:{
        rc:$trend_rc,
        go_rate_pct:$trend_go_rate_pct,
        decision:($trend_decision // ""),
        trend_summary_json:($trend_summary_json // "")
      },
      alert:{
        rc:$alert_rc,
        severity:($alert_severity // ""),
        severity_rank:$alert_rank,
        max_allowed_severity:$max_alert_severity,
        max_allowed_severity_rank:$max_alert_rank
      },
      bundle:{
        created:$bundle_created,
        manifest_created:$bundle_manifest_created,
        manifest_json:($bundle_manifest_json // "")
      },
      incident_snapshot:{
        failed_reports_checked:$incident_failed_reports_checked,
        failed_reports_ok:$incident_failed_reports_ok,
        failed_reports_policy_errors:$incident_failed_reports_policy_errors
      },
      policy:{
        require_status_ok:$require_status_ok,
        require_all_rounds_ok:$require_all_rounds_ok,
        max_round_failures:$max_round_failures,
        require_trend_go:$require_trend_go,
        min_go_rate_pct:$min_go_rate_pct,
        max_alert_severity:$max_alert_severity,
        require_bundle_created:$require_bundle_created,
        require_bundle_manifest:$require_bundle_manifest,
        require_incident_snapshot_on_fail:$require_incident_snapshot_on_fail,
        require_incident_snapshot_artifacts:$require_incident_snapshot_artifacts
      },
      errors:$errors
    }'
)"

echo "[prod-pilot-cohort-check] decision=$decision status=${status:-unset} rounds_failed=$rounds_failed go_rate_pct=${trend_go_rate_pct:-unset} alert=${alert_severity:-unset} errors=${#errors[@]}"
if [[ "$show_json" == "1" ]]; then
  echo "[prod-pilot-cohort-check] summary_json_payload:"
  printf '%s\n' "$summary_payload"
fi

if [[ "$decision" == "NO-GO" ]]; then
  idx=0
  while [[ "$idx" -lt "${#errors[@]}" ]]; do
    echo "[prod-pilot-cohort-check] error[$((idx + 1))]: ${errors[$idx]}"
    idx=$((idx + 1))
  done
  exit 1
fi

exit 0
