#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_gate_check.sh \
    [--bundle-dir PATH] \
    [--run-report-json PATH] \
    [--gate-summary-json PATH] \
    [--require-full-sequence [0|1]] \
    [--require-wg-validate-ok [0|1]] \
    [--require-wg-soak-ok [0|1]] \
    [--require-preflight-ok [0|1]] \
    [--require-bundle-ok [0|1]] \
    [--require-integrity-ok [0|1]] \
    [--require-signoff-ok [0|1]] \
    [--require-incident-snapshot-on-fail [0|1]] \
    [--require-incident-snapshot-artifacts [0|1]] \
    [--max-wg-soak-failed-rounds N] \
    [--show-json [0|1]]

Purpose:
  Verify production gate result artifacts and fail fast on non-signoff conditions.
  This is intended for machine-C closed-beta/prod signoff automation.

Notes:
  - Provide one of:
    - --run-report-json (recommended; from three-machine-prod-bundle)
    - --bundle-dir (contains prod_gate_summary.json)
    - --gate-summary-json
  - Default policy is strict: full sequence required, WG validate must be ok, WG soak must be ok, and WG soak failed rounds must be 0.
  - Run-report stage checks and incident-snapshot checks are optional and default-off for backwards compatibility.
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

bundle_dir=""
run_report_json=""
gate_summary_json=""
require_full_sequence="${PROD_GATE_CHECK_REQUIRE_FULL_SEQUENCE:-1}"
require_wg_validate_ok="${PROD_GATE_CHECK_REQUIRE_WG_VALIDATE_OK:-1}"
require_wg_soak_ok="${PROD_GATE_CHECK_REQUIRE_WG_SOAK_OK:-1}"
require_preflight_ok="${PROD_GATE_CHECK_REQUIRE_PREFLIGHT_OK:-0}"
require_bundle_ok="${PROD_GATE_CHECK_REQUIRE_BUNDLE_OK:-0}"
require_integrity_ok="${PROD_GATE_CHECK_REQUIRE_INTEGRITY_OK:-0}"
require_signoff_ok="${PROD_GATE_CHECK_REQUIRE_SIGNOFF_OK:-0}"
require_incident_snapshot_on_fail="${PROD_GATE_CHECK_REQUIRE_INCIDENT_SNAPSHOT_ON_FAIL:-0}"
require_incident_snapshot_artifacts="${PROD_GATE_CHECK_REQUIRE_INCIDENT_SNAPSHOT_ARTIFACTS:-0}"
max_wg_soak_failed_rounds="${PROD_GATE_CHECK_MAX_WG_SOAK_FAILED_ROUNDS:-0}"
show_json="${PROD_GATE_CHECK_SHOW_JSON:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle-dir)
      bundle_dir="${2:-}"
      shift 2
      ;;
    --run-report-json)
      run_report_json="${2:-}"
      shift 2
      ;;
    --gate-summary-json)
      gate_summary_json="${2:-}"
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
    --max-wg-soak-failed-rounds)
      max_wg_soak_failed_rounds="${2:-}"
      shift 2
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

need_cmd jq

bool_arg_or_die "--require-full-sequence" "$require_full_sequence"
bool_arg_or_die "--require-wg-validate-ok" "$require_wg_validate_ok"
bool_arg_or_die "--require-wg-soak-ok" "$require_wg_soak_ok"
bool_arg_or_die "--require-preflight-ok" "$require_preflight_ok"
bool_arg_or_die "--require-bundle-ok" "$require_bundle_ok"
bool_arg_or_die "--require-integrity-ok" "$require_integrity_ok"
bool_arg_or_die "--require-signoff-ok" "$require_signoff_ok"
bool_arg_or_die "--require-incident-snapshot-on-fail" "$require_incident_snapshot_on_fail"
bool_arg_or_die "--require-incident-snapshot-artifacts" "$require_incident_snapshot_artifacts"
bool_arg_or_die "--show-json" "$show_json"
if [[ ! "$max_wg_soak_failed_rounds" =~ ^[0-9]+$ ]]; then
  echo "--max-wg-soak-failed-rounds must be an integer >= 0"
  exit 2
fi

bundle_dir="$(trim "$bundle_dir")"
run_report_json="$(trim "$run_report_json")"
gate_summary_json="$(trim "$gate_summary_json")"
if [[ -z "$run_report_json" && -n "$bundle_dir" ]]; then
  candidate_run_report="${bundle_dir%/}/prod_bundle_run_report.json"
  if [[ -f "$candidate_run_report" ]]; then
    run_report_json="$candidate_run_report"
  fi
fi
if [[ -n "$run_report_json" ]]; then
  if [[ ! -f "$run_report_json" ]]; then
    echo "run report JSON file not found: $run_report_json"
    exit 1
  fi
  if ! jq -e . "$run_report_json" >/dev/null 2>&1; then
    echo "run report JSON is not valid JSON: $run_report_json"
    exit 1
  fi
  if [[ -z "$bundle_dir" ]]; then
    bundle_dir="$(jq -r '.bundle_dir // ""' "$run_report_json" 2>/dev/null || true)"
    bundle_dir="$(trim "$bundle_dir")"
  fi
  if [[ -z "$gate_summary_json" ]]; then
    gate_summary_json="$(jq -r '.gate_summary_json // ""' "$run_report_json" 2>/dev/null || true)"
    gate_summary_json="$(trim "$gate_summary_json")"
  fi
fi
if [[ -z "$gate_summary_json" && -n "$bundle_dir" ]]; then
  gate_summary_json="${bundle_dir%/}/prod_gate_summary.json"
fi
if [[ -z "$gate_summary_json" ]]; then
  echo "missing required input: set --run-report-json, --gate-summary-json, or --bundle-dir"
  exit 2
fi
if [[ ! -f "$gate_summary_json" ]]; then
  echo "gate summary file not found: $gate_summary_json"
  exit 1
fi
if ! jq -e . "$gate_summary_json" >/dev/null 2>&1; then
  echo "gate summary is not valid JSON: $gate_summary_json"
  exit 1
fi

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

gate_status="$(json_string "$gate_summary_json" '.status')"
failed_step="$(json_string "$gate_summary_json" '.failed_step')"
failed_rc="$(json_int "$gate_summary_json" '.failed_rc')"
step_control_validate="$(json_string "$gate_summary_json" '.steps.control_validate')"
step_control_soak="$(json_string "$gate_summary_json" '.steps.control_soak')"
step_prod_wg_validate="$(json_string "$gate_summary_json" '.steps.prod_wg_validate')"
step_prod_wg_soak="$(json_string "$gate_summary_json" '.steps.prod_wg_soak')"

wg_validate_summary_json="$(json_string "$gate_summary_json" '.wg_validate_summary_json')"
wg_validate_status="$(json_string "$gate_summary_json" '.wg_validate_status')"
wg_validate_failed_step="$(json_string "$gate_summary_json" '.wg_validate_failed_step')"

wg_soak_summary_json="$(json_string "$gate_summary_json" '.wg_soak_summary_json')"
wg_soak_status="$(json_string "$gate_summary_json" '.wg_soak_status')"
wg_soak_rounds_failed="$(json_int "$gate_summary_json" '.wg_soak_rounds_failed')"
wg_soak_top_failure_class="$(json_string "$gate_summary_json" '.wg_soak_top_failure_class')"
wg_soak_top_failure_count="$(json_int "$gate_summary_json" '.wg_soak_top_failure_count')"

run_report_status=""
run_report_final_rc=0
run_report_preflight_status=""
run_report_bundle_status=""
run_report_integrity_status=""
run_report_signoff_enabled=""
run_report_signoff_rc=0
run_report_incident_enabled_on_fail=""
run_report_incident_status=""
run_report_incident_rc=0
run_report_incident_bundle_dir=""
run_report_incident_bundle_tar=""
if [[ -n "$run_report_json" ]]; then
  run_report_status="$(json_string "$run_report_json" '.status')"
  run_report_final_rc="$(json_int "$run_report_json" '.final_rc')"
  run_report_preflight_status="$(json_string "$run_report_json" '.preflight.status')"
  run_report_bundle_status="$(json_string "$run_report_json" '.bundle.status')"
  run_report_integrity_status="$(json_string "$run_report_json" '.integrity_verify.status')"
  run_report_signoff_enabled="$(json_string "$run_report_json" '.signoff.enabled')"
  run_report_signoff_rc="$(json_int "$run_report_json" '.signoff.rc')"
  run_report_incident_enabled_on_fail="$(json_string "$run_report_json" '.incident_snapshot.enabled_on_fail')"
  run_report_incident_status="$(json_string "$run_report_json" '.incident_snapshot.status')"
  run_report_incident_rc="$(json_int "$run_report_json" '.incident_snapshot.rc')"
  run_report_incident_bundle_dir="$(json_string "$run_report_json" '.incident_snapshot.bundle_dir')"
  run_report_incident_bundle_tar="$(json_string "$run_report_json" '.incident_snapshot.bundle_tar')"
fi

declare -a errors=()

if [[ "$gate_status" != "ok" ]]; then
  errors+=("gate status is not ok (status=${gate_status:-unset}, failed_step=${failed_step:-none}, failed_rc=$failed_rc)")
fi

if [[ "$require_full_sequence" == "1" ]]; then
  if [[ "$step_control_validate" != "ok" ]]; then
    errors+=("control_validate step is not ok (value=${step_control_validate:-unset})")
  fi
  if [[ "$step_control_soak" != "ok" ]]; then
    errors+=("control_soak step is not ok (value=${step_control_soak:-unset})")
  fi
  if [[ "$step_prod_wg_validate" != "ok" ]]; then
    errors+=("prod_wg_validate step is not ok (value=${step_prod_wg_validate:-unset})")
  fi
  if [[ "$step_prod_wg_soak" != "ok" ]]; then
    errors+=("prod_wg_soak step is not ok (value=${step_prod_wg_soak:-unset})")
  fi
fi

if [[ "$require_wg_validate_ok" == "1" ]]; then
  if [[ -z "$wg_validate_summary_json" ]]; then
    errors+=("wg_validate_summary_json path missing in gate summary")
  elif [[ ! -f "$wg_validate_summary_json" ]]; then
    errors+=("wg_validate_summary_json file not found: $wg_validate_summary_json")
  fi
  if [[ "$wg_validate_status" != "ok" ]]; then
    errors+=("wg_validate_status is not ok (status=${wg_validate_status:-unset}, failed_step=${wg_validate_failed_step:-none})")
  fi
fi

if [[ "$require_wg_soak_ok" == "1" ]]; then
  if [[ -z "$wg_soak_summary_json" ]]; then
    errors+=("wg_soak_summary_json path missing in gate summary")
  elif [[ ! -f "$wg_soak_summary_json" ]]; then
    errors+=("wg_soak_summary_json file not found: $wg_soak_summary_json")
  fi
  if [[ "$wg_soak_status" != "ok" ]]; then
    errors+=("wg_soak_status is not ok (status=${wg_soak_status:-unset}, top_failure_class=${wg_soak_top_failure_class:-none}, top_failure_count=$wg_soak_top_failure_count)")
  fi
fi

if (( wg_soak_rounds_failed > max_wg_soak_failed_rounds )); then
  errors+=("wg_soak_rounds_failed exceeds limit (${wg_soak_rounds_failed} > ${max_wg_soak_failed_rounds})")
fi

if [[ -n "$run_report_json" ]]; then
  if [[ "$run_report_status" == "ok" && "$run_report_final_rc" != "0" ]]; then
    errors+=("run report status/final_rc mismatch (status=ok but final_rc=$run_report_final_rc)")
  fi
  if [[ "$run_report_status" == "fail" && "$run_report_final_rc" == "0" ]]; then
    errors+=("run report status/final_rc mismatch (status=fail but final_rc=0)")
  fi
fi

if [[ "$require_preflight_ok" == "1" ]]; then
  if [[ -z "$run_report_json" ]]; then
    errors+=("require-preflight-ok requested but run report JSON was not provided")
  elif [[ "$run_report_preflight_status" != "ok" ]]; then
    errors+=("run report preflight status is not ok (value=${run_report_preflight_status:-unset})")
  fi
fi

if [[ "$require_bundle_ok" == "1" ]]; then
  if [[ -z "$run_report_json" ]]; then
    errors+=("require-bundle-ok requested but run report JSON was not provided")
  elif [[ "$run_report_bundle_status" != "ok" ]]; then
    errors+=("run report bundle status is not ok (value=${run_report_bundle_status:-unset})")
  fi
fi

if [[ "$require_integrity_ok" == "1" ]]; then
  if [[ -z "$run_report_json" ]]; then
    errors+=("require-integrity-ok requested but run report JSON was not provided")
  elif [[ "$run_report_integrity_status" != "ok" ]]; then
    errors+=("run report integrity status is not ok (value=${run_report_integrity_status:-unset})")
  fi
fi

if [[ "$require_signoff_ok" == "1" ]]; then
  if [[ -z "$run_report_json" ]]; then
    errors+=("require-signoff-ok requested but run report JSON was not provided")
  else
    if [[ "$run_report_signoff_enabled" != "true" ]]; then
      errors+=("run report signoff stage is not enabled (enabled=${run_report_signoff_enabled:-unset})")
    fi
    if [[ "$run_report_signoff_rc" != "0" ]]; then
      errors+=("run report signoff rc is not 0 (rc=$run_report_signoff_rc)")
    fi
  fi
fi

if [[ "$require_incident_snapshot_on_fail" == "1" ]]; then
  if [[ -z "$run_report_json" ]]; then
    errors+=("require-incident-snapshot-on-fail requested but run report JSON was not provided")
  else
    if [[ "$run_report_status" == "fail" || "$run_report_final_rc" != "0" ]]; then
      if [[ "$run_report_incident_enabled_on_fail" != "true" ]]; then
        errors+=("run report incident snapshot is not enabled on fail (enabled_on_fail=${run_report_incident_enabled_on_fail:-unset})")
      fi
      if [[ "$run_report_incident_status" != "ok" ]]; then
        errors+=("run report incident snapshot status is not ok (status=${run_report_incident_status:-unset}, rc=$run_report_incident_rc)")
      fi
    fi
  fi
fi

if [[ "$require_incident_snapshot_artifacts" == "1" ]]; then
  if [[ -z "$run_report_json" ]]; then
    errors+=("require-incident-snapshot-artifacts requested but run report JSON was not provided")
  else
    if [[ "$run_report_incident_status" == "ok" ]]; then
      if [[ -z "$run_report_incident_bundle_dir" ]]; then
        errors+=("run report incident snapshot bundle_dir missing")
      elif [[ ! -d "$run_report_incident_bundle_dir" ]]; then
        errors+=("run report incident snapshot bundle_dir not found: $run_report_incident_bundle_dir")
      fi
      if [[ -z "$run_report_incident_bundle_tar" ]]; then
        errors+=("run report incident snapshot bundle_tar missing")
      elif [[ ! -f "$run_report_incident_bundle_tar" ]]; then
        errors+=("run report incident snapshot bundle_tar not found: $run_report_incident_bundle_tar")
      fi
    elif [[ "$run_report_status" == "fail" || "$run_report_final_rc" != "0" ]]; then
      errors+=("run report incident snapshot artifacts requested but snapshot status is not ok (status=${run_report_incident_status:-unset})")
    fi
  fi
fi

if [[ -n "$run_report_json" ]]; then
  echo "[prod-gate-check] run_report_json=$run_report_json"
fi
echo "[prod-gate-check] gate_summary_json=$gate_summary_json"
echo "[prod-gate-check] status=${gate_status:-unset} failed_step=${failed_step:-none} failed_rc=$failed_rc"
echo "[prod-gate-check] steps control_validate=${step_control_validate:-unset} control_soak=${step_control_soak:-unset} prod_wg_validate=${step_prod_wg_validate:-unset} prod_wg_soak=${step_prod_wg_soak:-unset}"
echo "[prod-gate-check] wg_validate status=${wg_validate_status:-unset} failed_step=${wg_validate_failed_step:-none} summary=${wg_validate_summary_json:-unset}"
echo "[prod-gate-check] wg_soak status=${wg_soak_status:-unset} rounds_failed=${wg_soak_rounds_failed} top_failure_class=${wg_soak_top_failure_class:-none} top_failure_count=${wg_soak_top_failure_count} summary=${wg_soak_summary_json:-unset}"
if [[ -n "$run_report_json" ]]; then
  echo "[prod-gate-check] run_report status=${run_report_status:-unset} final_rc=${run_report_final_rc} preflight=${run_report_preflight_status:-unset} bundle=${run_report_bundle_status:-unset} integrity=${run_report_integrity_status:-unset} signoff_enabled=${run_report_signoff_enabled:-unset} signoff_rc=${run_report_signoff_rc} incident_enabled_on_fail=${run_report_incident_enabled_on_fail:-unset} incident_status=${run_report_incident_status:-unset} incident_rc=${run_report_incident_rc}"
fi

if ((${#errors[@]} > 0)); then
  echo "[prod-gate-check] failed with ${#errors[@]} issue(s):"
  for err in "${errors[@]}"; do
    echo "  - $err"
  done
  if [[ "$show_json" == "1" ]]; then
    echo "[prod-gate-check] gate summary payload:"
    cat "$gate_summary_json"
  fi
  exit 1
fi

echo "[prod-gate-check] ok"
if [[ "$show_json" == "1" ]]; then
  echo "[prod-gate-check] gate summary payload:"
  cat "$gate_summary_json"
fi
