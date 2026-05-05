#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase2_linux_prod_candidate_check.sh \
    [--ci-phase2-summary-json PATH] \
    [--require-release-integrity-ok [0|1]] \
    [--require-release-policy-ok [0|1]] \
    [--require-operator-lifecycle-ok [0|1]] \
    [--require-pilot-signoff-ok [0|1]] \
    [--summary-json PATH] \
    [--show-json [0|1]]

Purpose:
  Fail-closed checker for the Phase-2 Linux production-candidate handoff.
  Evaluates required readiness booleans derived from the CI Phase-2 summary:
    - release_integrity_ok
    - release_policy_ok
    - operator_lifecycle_ok
    - pilot_signoff_ok

Notes:
  - Provide the CI summary with --ci-phase2-summary-json.
  - The checker treats unresolved or false readiness signals as failures.
  - Use --show-json 1 to print the emitted summary JSON after it is written.
USAGE
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

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
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

json_file_valid_01() {
  local path="${1:-}"
  if [[ -f "$path" ]] && jq -e . "$path" >/dev/null 2>&1; then
    printf '%s' "1"
  else
    printf '%s' "0"
  fi
}

json_text_or_empty() {
  local path="${1:-}"
  local expr="${2:-}"
  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '%s' ""
    return
  fi
  jq -r "$expr // empty" "$path" 2>/dev/null || true
}

normalize_boolish_or_empty() {
  local value
  value="$(trim "${1:-}")"
  value="$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    true|1|pass|ok|passed|success|succeeded)
      printf '%s' "true"
      ;;
    false|0|fail|error|failed|blocked|skip|skipped|warn|warning)
      printf '%s' "false"
      ;;
    *)
      printf '%s' ""
      ;;
  esac
}

stage_status_from_raw() {
  local raw="${1:-}"
  local normalized
  normalized="$(normalize_boolish_or_empty "$raw")"
  case "$normalized" in
    true)
      printf '%s' "pass"
      ;;
    false)
      printf '%s' "fail"
      ;;
    *)
      if [[ -z "$(trim "$raw")" ]]; then
        printf '%s' "missing"
      else
        printf '%s' "fail"
      fi
      ;;
  esac
}

resolve_signal_raw_or_empty() {
  local path="${1:-}"
  local signal="${2:-}"

  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    printf '%s' ""
    return
  fi

  case "$signal" in
    release_integrity_ok)
      json_text_or_empty "$path" 'if (.release_integrity_ok? != null) then .release_integrity_ok
        elif (.summary.release_integrity_ok? != null) then .summary.release_integrity_ok
        elif (.signals.release_integrity_ok? != null) then .signals.release_integrity_ok
        elif (.stages.release_integrity.ok? != null) then .stages.release_integrity.ok
        elif (.stages.release_integrity.pass? != null) then .stages.release_integrity.pass
        elif (.stages.release_integrity.status? != null) then .stages.release_integrity.status
        elif (.steps.release_integrity.ok? != null) then .steps.release_integrity.ok
        elif (.steps.release_integrity.status? != null) then .steps.release_integrity.status
        elif (.release_integrity.status? != null) then .release_integrity.status
        else empty end'
      ;;
    release_policy_ok)
      json_text_or_empty "$path" 'if (.release_policy_ok? != null) then .release_policy_ok
        elif (.summary.release_policy_ok? != null) then .summary.release_policy_ok
        elif (.signals.release_policy_ok? != null) then .signals.release_policy_ok
        elif (.stages.release_policy.ok? != null) then .stages.release_policy.ok
        elif (.stages.release_policy.pass? != null) then .stages.release_policy.pass
        elif (.stages.release_policy.status? != null) then .stages.release_policy.status
        elif (.stages.release_policy_gate.ok? != null) then .stages.release_policy_gate.ok
        elif (.stages.release_policy_gate.pass? != null) then .stages.release_policy_gate.pass
        elif (.stages.release_policy_gate.status? != null) then .stages.release_policy_gate.status
        elif (.steps.release_policy.status? != null) then .steps.release_policy.status
        elif (.steps.release_policy_gate.status? != null) then .steps.release_policy_gate.status
        elif (.release_policy.status? != null) then .release_policy.status
        else empty end'
      ;;
    operator_lifecycle_ok)
      json_text_or_empty "$path" 'if (.operator_lifecycle_ok? != null) then .operator_lifecycle_ok
        elif (.summary.operator_lifecycle_ok? != null) then .summary.operator_lifecycle_ok
        elif (.signals.operator_lifecycle_ok? != null) then .signals.operator_lifecycle_ok
        elif (.stages.operator_lifecycle.ok? != null) then .stages.operator_lifecycle.ok
        elif (.stages.operator_lifecycle.pass? != null) then .stages.operator_lifecycle.pass
        elif (.stages.operator_lifecycle.status? != null) then .stages.operator_lifecycle.status
        elif (.stages.prod_operator_lifecycle_runbook.ok? != null) then .stages.prod_operator_lifecycle_runbook.ok
        elif (.stages.prod_operator_lifecycle_runbook.pass? != null) then .stages.prod_operator_lifecycle_runbook.pass
        elif (.stages.prod_operator_lifecycle_runbook.status? != null) then .stages.prod_operator_lifecycle_runbook.status
        elif (.stages.prod_operator_lifecycle.ok? != null) then .stages.prod_operator_lifecycle.ok
        elif (.stages.prod_operator_lifecycle.pass? != null) then .stages.prod_operator_lifecycle.pass
        elif (.stages.prod_operator_lifecycle.status? != null) then .stages.prod_operator_lifecycle.status
        elif (.steps.operator_lifecycle.status? != null) then .steps.operator_lifecycle.status
        elif (.steps.prod_operator_lifecycle_runbook.status? != null) then .steps.prod_operator_lifecycle_runbook.status
        elif (.steps.prod_operator_lifecycle.status? != null) then .steps.prod_operator_lifecycle.status
        elif (.release.operator_lifecycle.status? != null) then .release.operator_lifecycle.status
        else empty end'
      ;;
    pilot_signoff_ok)
      json_text_or_empty "$path" 'if (.pilot_signoff_ok? != null) then .pilot_signoff_ok
        elif (.summary.pilot_signoff_ok? != null) then .summary.pilot_signoff_ok
        elif (.signals.pilot_signoff_ok? != null) then .signals.pilot_signoff_ok
        elif (.stages.pilot_signoff.ok? != null) then .stages.pilot_signoff.ok
        elif (.stages.pilot_signoff.pass? != null) then .stages.pilot_signoff.pass
        elif (.stages.pilot_signoff.status? != null) then .stages.pilot_signoff.status
        elif (.stages.prod_pilot_cohort_signoff.ok? != null) then .stages.prod_pilot_cohort_signoff.ok
        elif (.stages.prod_pilot_cohort_signoff.pass? != null) then .stages.prod_pilot_cohort_signoff.pass
        elif (.stages.prod_pilot_cohort_signoff.status? != null) then .stages.prod_pilot_cohort_signoff.status
        elif (.stages.prod_pilot_cohort_quick_signoff.ok? != null) then .stages.prod_pilot_cohort_quick_signoff.ok
        elif (.stages.prod_pilot_cohort_quick_signoff.pass? != null) then .stages.prod_pilot_cohort_quick_signoff.pass
        elif (.stages.prod_pilot_cohort_quick_signoff.status? != null) then .stages.prod_pilot_cohort_quick_signoff.status
        elif (.stages.prod_pilot_signoff.ok? != null) then .stages.prod_pilot_signoff.ok
        elif (.stages.prod_pilot_signoff.pass? != null) then .stages.prod_pilot_signoff.pass
        elif (.stages.prod_pilot_signoff.status? != null) then .stages.prod_pilot_signoff.status
        elif (.steps.pilot_signoff.status? != null) then .steps.pilot_signoff.status
        elif (.steps.prod_pilot_cohort_signoff.status? != null) then .steps.prod_pilot_cohort_signoff.status
        elif (.steps.prod_pilot_cohort_quick_signoff.status? != null) then .steps.prod_pilot_cohort_quick_signoff.status
        elif (.steps.prod_pilot_signoff.status? != null) then .steps.prod_pilot_signoff.status
        elif (.release.pilot_signoff.status? != null) then .release.pilot_signoff.status
        else empty end'
      ;;
    *)
      printf '%s' ""
      ;;
  esac
}

emit_summary_json() {
  local summary_json="$1"
  local generated_at_utc="$2"
  local status="$3"
  local rc="$4"
  local ci_phase2_summary_json="$5"
  local ci_phase2_summary_usable="$6"
  local show_json="$7"
  local require_release_integrity_ok="$8"
  local require_release_policy_ok="$9"
  local require_operator_lifecycle_ok="${10}"
  local require_pilot_signoff_ok="${11}"
  local release_integrity_status="${12}"
  local release_policy_status="${13}"
  local operator_lifecycle_status="${14}"
  local pilot_signoff_status="${15}"
  local release_integrity_ok="${16}"
  local release_policy_ok="${17}"
  local operator_lifecycle_ok="${18}"
  local pilot_signoff_ok="${19}"
  local release_integrity_resolved="${20}"
  local release_policy_resolved="${21}"
  local operator_lifecycle_resolved="${22}"
  local pilot_signoff_resolved="${23}"
  local reasons_json="${24}"
  local reason_details_json="${25}"
  local warnings_json="${26}"
  local warning_details_json="${27}"

  local summary_tmp
  summary_tmp="$(mktemp)"
  jq -n \
    --arg generated_at_utc "$generated_at_utc" \
    --arg status "$status" \
    --argjson rc "$rc" \
    --arg summary_json "$summary_json" \
    --arg ci_phase2_summary_json "$ci_phase2_summary_json" \
    --argjson ci_phase2_summary_usable "$ci_phase2_summary_usable" \
    --arg show_json "$show_json" \
    --argjson require_release_integrity_ok "$require_release_integrity_ok" \
    --argjson require_release_policy_ok "$require_release_policy_ok" \
    --argjson require_operator_lifecycle_ok "$require_operator_lifecycle_ok" \
    --argjson require_pilot_signoff_ok "$require_pilot_signoff_ok" \
    --arg release_integrity_status "$release_integrity_status" \
    --arg release_policy_status "$release_policy_status" \
    --arg operator_lifecycle_status "$operator_lifecycle_status" \
    --arg pilot_signoff_status "$pilot_signoff_status" \
    --argjson release_integrity_ok "$release_integrity_ok" \
    --argjson release_policy_ok "$release_policy_ok" \
    --argjson operator_lifecycle_ok "$operator_lifecycle_ok" \
    --argjson pilot_signoff_ok "$pilot_signoff_ok" \
    --argjson release_integrity_resolved "$release_integrity_resolved" \
    --argjson release_policy_resolved "$release_policy_resolved" \
    --argjson operator_lifecycle_resolved "$operator_lifecycle_resolved" \
    --argjson pilot_signoff_resolved "$pilot_signoff_resolved" \
    --argjson reasons "$reasons_json" \
    --argjson reason_details "$reason_details_json" \
    --argjson warnings "$warnings_json" \
    --argjson warning_details "$warning_details_json" \
    '{
      version: 1,
      schema: {
        id: "phase2_linux_prod_candidate_check_summary",
        major: 1,
        minor: 0
      },
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $rc,
      fail_closed: true,
      metadata: {
        contract: "phase2-linux-production-candidate",
        script: "phase2_linux_prod_candidate_check.sh"
      },
      inputs: {
        ci_phase2_summary_json: $ci_phase2_summary_json,
        summary_json: $summary_json,
        show_json: ($show_json == "1"),
        usable: {
          ci_phase2_summary_json: ($ci_phase2_summary_usable == 1)
        }
      },
      policy: {
        require_release_integrity_ok: ($require_release_integrity_ok == 1),
        require_release_policy_ok: ($require_release_policy_ok == 1),
        require_operator_lifecycle_ok: ($require_operator_lifecycle_ok == 1),
        require_pilot_signoff_ok: ($require_pilot_signoff_ok == 1)
      },
      stages: {
        release_integrity: {
          enabled: ($require_release_integrity_ok == 1),
          status: $release_integrity_status,
          resolved: ($release_integrity_resolved == 1),
          ok: ($release_integrity_ok == true)
        },
        release_policy: {
          enabled: ($require_release_policy_ok == 1),
          status: $release_policy_status,
          resolved: ($release_policy_resolved == 1),
          ok: ($release_policy_ok == true)
        },
        operator_lifecycle: {
          enabled: ($require_operator_lifecycle_ok == 1),
          status: $operator_lifecycle_status,
          resolved: ($operator_lifecycle_resolved == 1),
          ok: ($operator_lifecycle_ok == true)
        },
        pilot_signoff: {
          enabled: ($require_pilot_signoff_ok == 1),
          status: $pilot_signoff_status,
          resolved: ($pilot_signoff_resolved == 1),
          ok: ($pilot_signoff_ok == true)
        }
      },
      signals: {
        release_integrity_ok: ($release_integrity_ok == true),
        release_policy_ok: ($release_policy_ok == true),
        operator_lifecycle_ok: ($operator_lifecycle_ok == true),
        pilot_signoff_ok: ($pilot_signoff_ok == true)
      },
      decision: {
        pass: ($status == "pass"),
        reasons: $reasons,
        reason_details: $reason_details,
        reason_codes: ($reason_details | map(.code) | unique),
        warnings: $warnings,
        warning_details: $warning_details,
        warning_codes: ($warning_details | map(.code) | unique)
      }
    }' >"$summary_tmp"
  mv -f "$summary_tmp" "$summary_json"
}

need_cmd jq
need_cmd date
need_cmd mktemp

ci_phase2_summary_json="${PHASE2_LINUX_PROD_CANDIDATE_CHECK_CI_PHASE2_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase2_linux_prod_candidate_ci_summary.json}"
summary_json="${PHASE2_LINUX_PROD_CANDIDATE_CHECK_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase2_linux_prod_candidate_check_summary.json}"
show_json="${PHASE2_LINUX_PROD_CANDIDATE_CHECK_SHOW_JSON:-0}"
require_release_integrity_ok="${PHASE2_LINUX_PROD_CANDIDATE_CHECK_REQUIRE_RELEASE_INTEGRITY_OK:-1}"
require_release_policy_ok="${PHASE2_LINUX_PROD_CANDIDATE_CHECK_REQUIRE_RELEASE_POLICY_OK:-1}"
require_operator_lifecycle_ok="${PHASE2_LINUX_PROD_CANDIDATE_CHECK_REQUIRE_OPERATOR_LIFECYCLE_OK:-1}"
require_pilot_signoff_ok="${PHASE2_LINUX_PROD_CANDIDATE_CHECK_REQUIRE_PILOT_SIGNOFF_OK:-1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ci-phase2-summary-json)
      ci_phase2_summary_json="${2:-}"
      shift 2
      ;;
    --require-release-integrity-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_release_integrity_ok="${2:-}"
        shift 2
      else
        require_release_integrity_ok="1"
        shift
      fi
      ;;
    --require-release-policy-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_release_policy_ok="${2:-}"
        shift 2
      else
        require_release_policy_ok="1"
        shift
      fi
      ;;
    --require-operator-lifecycle-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_operator_lifecycle_ok="${2:-}"
        shift 2
      else
        require_operator_lifecycle_ok="1"
        shift
      fi
      ;;
    --require-pilot-signoff-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_pilot_signoff_ok="${2:-}"
        shift 2
      else
        require_pilot_signoff_ok="1"
        shift
      fi
      ;;
    --summary-json)
      summary_json="${2:-}"
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
    -h|--help)
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

bool_arg_or_die "--require-release-integrity-ok" "$require_release_integrity_ok"
bool_arg_or_die "--require-release-policy-ok" "$require_release_policy_ok"
bool_arg_or_die "--require-operator-lifecycle-ok" "$require_operator_lifecycle_ok"
bool_arg_or_die "--require-pilot-signoff-ok" "$require_pilot_signoff_ok"
bool_arg_or_die "--show-json" "$show_json"

ci_phase2_summary_json="$(abs_path "$ci_phase2_summary_json")"
summary_json="$(abs_path "$summary_json")"

mkdir -p "$(dirname "$summary_json")"

generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ci_phase2_summary_usable="$(json_file_valid_01 "$ci_phase2_summary_json")"

declare -a reasons=()
reasons_details_json='[]'
warnings_details_json='[]'

append_reason_detail() {
  local code="$1"
  local signal="$2"
  local message="$3"
  local required="$4"
  local observed_status="$5"
  local resolved="$6"
  local observed_value="$7"
  reasons_details_json="$(
    jq -cn \
      --argjson arr "$reasons_details_json" \
      --arg code "$code" \
      --arg signal "$signal" \
      --arg message "$message" \
      --argjson required "$required" \
      --arg observed_status "$observed_status" \
      --argjson resolved "$resolved" \
      --arg observed_value "$observed_value" \
      '$arr + [{
        code: $code,
        signal: $signal,
        message: $message,
        required: $required,
        observed_status: $observed_status,
        resolved: $resolved,
        observed_value: (if $observed_value == "" then null else $observed_value end)
      }]'
  )"
}

append_warning_detail() {
  local code="$1"
  local signal="$2"
  local message="$3"
  local observed_status="$4"
  local resolved="$5"
  local observed_value="$6"
  warnings_details_json="$(
    jq -cn \
      --argjson arr "$warnings_details_json" \
      --arg code "$code" \
      --arg signal "$signal" \
      --arg message "$message" \
      --arg observed_status "$observed_status" \
      --argjson resolved "$resolved" \
      --arg observed_value "$observed_value" \
      '$arr + [{
        code: $code,
        signal: $signal,
        message: $message,
        observed_status: $observed_status,
        resolved: $resolved,
        observed_value: (if $observed_value == "" then null else $observed_value end)
      }]'
  )"
}

release_integrity_raw=""
release_policy_raw=""
operator_lifecycle_raw=""
pilot_signoff_raw=""

if [[ "$ci_phase2_summary_usable" == "1" ]]; then
  release_integrity_raw="$(resolve_signal_raw_or_empty "$ci_phase2_summary_json" "release_integrity_ok")"
  release_policy_raw="$(resolve_signal_raw_or_empty "$ci_phase2_summary_json" "release_policy_ok")"
  operator_lifecycle_raw="$(resolve_signal_raw_or_empty "$ci_phase2_summary_json" "operator_lifecycle_ok")"
  pilot_signoff_raw="$(resolve_signal_raw_or_empty "$ci_phase2_summary_json" "pilot_signoff_ok")"
else
  reasons+=("ci phase2 summary file not found or invalid JSON: $ci_phase2_summary_json")
  append_reason_detail \
    "ci_summary_unusable" \
    "ci_phase2_summary_json" \
    "ci phase2 summary file not found or invalid JSON: $ci_phase2_summary_json" \
    true \
    "missing" \
    false \
    ""
fi

release_integrity_ok="$(normalize_boolish_or_empty "$release_integrity_raw")"
release_policy_ok="$(normalize_boolish_or_empty "$release_policy_raw")"
operator_lifecycle_ok="$(normalize_boolish_or_empty "$operator_lifecycle_raw")"
pilot_signoff_ok="$(normalize_boolish_or_empty "$pilot_signoff_raw")"

if [[ -z "$release_integrity_ok" ]]; then
  release_integrity_ok="false"
fi
if [[ -z "$release_policy_ok" ]]; then
  release_policy_ok="false"
fi
if [[ -z "$operator_lifecycle_ok" ]]; then
  operator_lifecycle_ok="false"
fi
if [[ -z "$pilot_signoff_ok" ]]; then
  pilot_signoff_ok="false"
fi

release_integrity_resolved="0"
release_policy_resolved="0"
operator_lifecycle_resolved="0"
pilot_signoff_resolved="0"

release_integrity_status="$(stage_status_from_raw "$release_integrity_raw")"
release_policy_status="$(stage_status_from_raw "$release_policy_raw")"
operator_lifecycle_status="$(stage_status_from_raw "$operator_lifecycle_raw")"
pilot_signoff_status="$(stage_status_from_raw "$pilot_signoff_raw")"

if [[ -n "$(trim "$release_integrity_raw")" ]]; then
  release_integrity_resolved="1"
elif [[ "$ci_phase2_summary_usable" == "1" ]]; then
  reasons+=("release_integrity_ok could not be resolved from ci phase2 summary")
  append_reason_detail \
    "signal_unresolved" \
    "release_integrity_ok" \
    "release_integrity_ok could not be resolved from ci phase2 summary" \
    true \
    "$release_integrity_status" \
    false \
    "$release_integrity_raw"
fi
if [[ -n "$(trim "$release_policy_raw")" ]]; then
  release_policy_resolved="1"
elif [[ "$ci_phase2_summary_usable" == "1" ]]; then
  reasons+=("release_policy_ok could not be resolved from ci phase2 summary")
  append_reason_detail \
    "signal_unresolved" \
    "release_policy_ok" \
    "release_policy_ok could not be resolved from ci phase2 summary" \
    true \
    "$release_policy_status" \
    false \
    "$release_policy_raw"
fi
if [[ -n "$(trim "$operator_lifecycle_raw")" ]]; then
  operator_lifecycle_resolved="1"
elif [[ "$ci_phase2_summary_usable" == "1" ]]; then
  reasons+=("operator_lifecycle_ok could not be resolved from ci phase2 summary")
  append_reason_detail \
    "signal_unresolved" \
    "operator_lifecycle_ok" \
    "operator_lifecycle_ok could not be resolved from ci phase2 summary" \
    true \
    "$operator_lifecycle_status" \
    false \
    "$operator_lifecycle_raw"
fi
if [[ -n "$(trim "$pilot_signoff_raw")" ]]; then
  pilot_signoff_resolved="1"
elif [[ "$ci_phase2_summary_usable" == "1" ]]; then
  reasons+=("pilot_signoff_ok could not be resolved from ci phase2 summary")
  append_reason_detail \
    "signal_unresolved" \
    "pilot_signoff_ok" \
    "pilot_signoff_ok could not be resolved from ci phase2 summary" \
    true \
    "$pilot_signoff_status" \
    false \
    "$pilot_signoff_raw"
fi

if [[ "$require_release_integrity_ok" == "1" && "$release_integrity_ok" != "true" ]]; then
  reasons+=("release_integrity_ok is false")
  append_reason_detail \
    "required_signal_false" \
    "release_integrity_ok" \
    "release_integrity_ok is false" \
    true \
    "$release_integrity_status" \
    "$( [[ "$release_integrity_resolved" == "1" ]] && echo true || echo false )" \
    "$release_integrity_raw"
fi
if [[ "$require_release_policy_ok" == "1" && "$release_policy_ok" != "true" ]]; then
  reasons+=("release_policy_ok is false")
  append_reason_detail \
    "required_signal_false" \
    "release_policy_ok" \
    "release_policy_ok is false" \
    true \
    "$release_policy_status" \
    "$( [[ "$release_policy_resolved" == "1" ]] && echo true || echo false )" \
    "$release_policy_raw"
fi
if [[ "$require_operator_lifecycle_ok" == "1" && "$operator_lifecycle_ok" != "true" ]]; then
  reasons+=("operator_lifecycle_ok is false")
  append_reason_detail \
    "required_signal_false" \
    "operator_lifecycle_ok" \
    "operator_lifecycle_ok is false" \
    true \
    "$operator_lifecycle_status" \
    "$( [[ "$operator_lifecycle_resolved" == "1" ]] && echo true || echo false )" \
    "$operator_lifecycle_raw"
fi
if [[ "$require_pilot_signoff_ok" == "1" && "$pilot_signoff_ok" != "true" ]]; then
  reasons+=("pilot_signoff_ok is false")
  append_reason_detail \
    "required_signal_false" \
    "pilot_signoff_ok" \
    "pilot_signoff_ok is false" \
    true \
    "$pilot_signoff_status" \
    "$( [[ "$pilot_signoff_resolved" == "1" ]] && echo true || echo false )" \
    "$pilot_signoff_raw"
fi

if [[ "$require_release_integrity_ok" == "0" && "$release_integrity_ok" != "true" ]]; then
  append_warning_detail \
    "optional_signal_not_ready" \
    "release_integrity_ok" \
    "release_integrity_ok is not ready but requirement is disabled" \
    "$release_integrity_status" \
    "$( [[ "$release_integrity_resolved" == "1" ]] && echo true || echo false )" \
    "$release_integrity_raw"
fi
if [[ "$require_release_policy_ok" == "0" && "$release_policy_ok" != "true" ]]; then
  append_warning_detail \
    "optional_signal_not_ready" \
    "release_policy_ok" \
    "release_policy_ok is not ready but requirement is disabled" \
    "$release_policy_status" \
    "$( [[ "$release_policy_resolved" == "1" ]] && echo true || echo false )" \
    "$release_policy_raw"
fi
if [[ "$require_operator_lifecycle_ok" == "0" && "$operator_lifecycle_ok" != "true" ]]; then
  append_warning_detail \
    "optional_signal_not_ready" \
    "operator_lifecycle_ok" \
    "operator_lifecycle_ok is not ready but requirement is disabled" \
    "$operator_lifecycle_status" \
    "$( [[ "$operator_lifecycle_resolved" == "1" ]] && echo true || echo false )" \
    "$operator_lifecycle_raw"
fi
if [[ "$require_pilot_signoff_ok" == "0" && "$pilot_signoff_ok" != "true" ]]; then
  append_warning_detail \
    "optional_signal_not_ready" \
    "pilot_signoff_ok" \
    "pilot_signoff_ok is not ready but requirement is disabled" \
    "$pilot_signoff_status" \
    "$( [[ "$pilot_signoff_resolved" == "1" ]] && echo true || echo false )" \
    "$pilot_signoff_raw"
fi

status="pass"
rc=0
if ((${#reasons[@]} > 0)); then
  status="fail"
  rc=1
fi

if ((${#reasons[@]} > 0)); then
  reasons_json="$(printf '%s\n' "${reasons[@]}" | jq -R . | jq -s .)"
else
  reasons_json='[]'
fi
warnings_json="$(
  jq -cn --argjson details "$warnings_details_json" '[ $details[] | .message ]'
)"

emit_summary_json \
  "$summary_json" \
  "$generated_at_utc" \
  "$status" \
  "$rc" \
  "$ci_phase2_summary_json" \
  "$ci_phase2_summary_usable" \
  "$show_json" \
  "$require_release_integrity_ok" \
  "$require_release_policy_ok" \
  "$require_operator_lifecycle_ok" \
  "$require_pilot_signoff_ok" \
  "$release_integrity_status" \
  "$release_policy_status" \
  "$operator_lifecycle_status" \
  "$pilot_signoff_status" \
  "$release_integrity_ok" \
  "$release_policy_ok" \
  "$operator_lifecycle_ok" \
  "$pilot_signoff_ok" \
  "$release_integrity_resolved" \
  "$release_policy_resolved" \
  "$operator_lifecycle_resolved" \
  "$pilot_signoff_resolved" \
  "$reasons_json" \
  "$reasons_details_json" \
  "$warnings_json" \
  "$warnings_details_json"

if [[ "$show_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$status" == "pass" ]]; then
  exit 0
fi
exit 1
