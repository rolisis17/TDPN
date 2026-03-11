#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BUNDLE_VERIFY_SCRIPT="${PROD_PILOT_COHORT_BUNDLE_VERIFY_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_bundle_verify.sh}"
COHORT_CHECK_SCRIPT="${PROD_PILOT_COHORT_CHECK_SCRIPT:-$ROOT_DIR/scripts/prod_pilot_cohort_check.sh}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_pilot_cohort_signoff.sh \
    [--summary-json PATH] \
    [--reports-dir PATH] \
    [--bundle-tar PATH] \
    [--bundle-sha256-file PATH] \
    [--bundle-manifest-json PATH] \
    [--check-tar-sha256 [0|1]] \
    [--check-manifest [0|1]] \
    [--show-integrity-details [0|1]] \
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
  Run cohort bundle integrity verification and cohort policy checks in one fail-closed command.
  Recommended input is --summary-json from prod-pilot-cohort-runbook.
USAGE
}

summary_json=""
reports_dir=""
bundle_tar=""
bundle_sha256_file=""
bundle_manifest_json=""
check_tar_sha256="${PROD_PILOT_COHORT_SIGNOFF_CHECK_TAR_SHA256:-1}"
check_manifest="${PROD_PILOT_COHORT_SIGNOFF_CHECK_MANIFEST:-1}"
show_integrity_details="${PROD_PILOT_COHORT_SIGNOFF_SHOW_INTEGRITY_DETAILS:-0}"

require_status_ok="${PROD_PILOT_COHORT_SIGNOFF_REQUIRE_STATUS_OK:-1}"
require_all_rounds_ok="${PROD_PILOT_COHORT_SIGNOFF_REQUIRE_ALL_ROUNDS_OK:-1}"
max_round_failures="${PROD_PILOT_COHORT_SIGNOFF_MAX_ROUND_FAILURES:-0}"
require_trend_go="${PROD_PILOT_COHORT_SIGNOFF_REQUIRE_TREND_GO:-1}"
min_go_rate_pct="${PROD_PILOT_COHORT_SIGNOFF_MIN_GO_RATE_PCT:-95}"
max_alert_severity="${PROD_PILOT_COHORT_SIGNOFF_MAX_ALERT_SEVERITY:-WARN}"
require_bundle_created="${PROD_PILOT_COHORT_SIGNOFF_REQUIRE_BUNDLE_CREATED:-1}"
require_bundle_manifest="${PROD_PILOT_COHORT_SIGNOFF_REQUIRE_BUNDLE_MANIFEST:-1}"
require_incident_snapshot_on_fail="${PROD_PILOT_COHORT_SIGNOFF_REQUIRE_INCIDENT_SNAPSHOT_ON_FAIL:-1}"
require_incident_snapshot_artifacts="${PROD_PILOT_COHORT_SIGNOFF_REQUIRE_INCIDENT_SNAPSHOT_ARTIFACTS:-1}"
show_json="${PROD_PILOT_COHORT_SIGNOFF_SHOW_JSON:-0}"

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
    --bundle-tar)
      bundle_tar="${2:-}"
      shift 2
      ;;
    --bundle-sha256-file)
      bundle_sha256_file="${2:-}"
      shift 2
      ;;
    --bundle-manifest-json)
      bundle_manifest_json="${2:-}"
      shift 2
      ;;
    --check-tar-sha256)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        check_tar_sha256="${2:-}"
        shift 2
      else
        check_tar_sha256="1"
        shift
      fi
      ;;
    --check-manifest)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        check_manifest="${2:-}"
        shift 2
      else
        check_manifest="1"
        shift
      fi
      ;;
    --show-integrity-details)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        show_integrity_details="${2:-}"
        shift 2
      else
        show_integrity_details="1"
        shift
      fi
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

if [[ ! -x "$BUNDLE_VERIFY_SCRIPT" ]]; then
  echo "missing executable bundle verify script: $BUNDLE_VERIFY_SCRIPT"
  exit 2
fi
if [[ ! -x "$COHORT_CHECK_SCRIPT" ]]; then
  echo "missing executable cohort check script: $COHORT_CHECK_SCRIPT"
  exit 2
fi

declare -a verify_args=(
  --check-tar-sha256 "$check_tar_sha256"
  --check-manifest "$check_manifest"
  --show-details "$show_integrity_details"
)
if [[ -n "$summary_json" ]]; then
  verify_args+=(--summary-json "$summary_json")
fi
if [[ -n "$reports_dir" ]]; then
  verify_args+=(--reports-dir "$reports_dir")
fi
if [[ -n "$bundle_tar" ]]; then
  verify_args+=(--bundle-tar "$bundle_tar")
fi
if [[ -n "$bundle_sha256_file" ]]; then
  verify_args+=(--bundle-sha256-file "$bundle_sha256_file")
fi
if [[ -n "$bundle_manifest_json" ]]; then
  verify_args+=(--bundle-manifest-json "$bundle_manifest_json")
fi

declare -a check_args=(
  --require-status-ok "$require_status_ok"
  --require-all-rounds-ok "$require_all_rounds_ok"
  --max-round-failures "$max_round_failures"
  --require-trend-go "$require_trend_go"
  --min-go-rate-pct "$min_go_rate_pct"
  --max-alert-severity "$max_alert_severity"
  --require-bundle-created "$require_bundle_created"
  --require-bundle-manifest "$require_bundle_manifest"
  --require-incident-snapshot-on-fail "$require_incident_snapshot_on_fail"
  --require-incident-snapshot-artifacts "$require_incident_snapshot_artifacts"
  --show-json "$show_json"
)
if [[ -n "$summary_json" ]]; then
  check_args+=(--summary-json "$summary_json")
fi
if [[ -n "$reports_dir" ]]; then
  check_args+=(--reports-dir "$reports_dir")
fi

echo "prod-pilot-cohort-signoff: verifying cohort bundle integrity"
"$BUNDLE_VERIFY_SCRIPT" "${verify_args[@]}"
echo "prod-pilot-cohort-signoff: checking cohort signoff policy"
"$COHORT_CHECK_SCRIPT" "${check_args[@]}"
