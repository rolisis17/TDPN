#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase2_linux_prod_candidate_handoff_check.sh \
    [--phase2-signoff-summary-json PATH] \
    [--roadmap-summary-json PATH] \
    [--require-signoff-pipeline-ok [0|1]] \
    [--require-release-integrity-ok [0|1]] \
    [--require-release-policy-ok [0|1]] \
    [--require-operator-lifecycle-ok [0|1]] \
    [--require-pilot-signoff-ok [0|1]] \
    [--summary-json PATH] \
    [--show-json [0|1]]

Purpose:
  Fail-closed checker for the Phase-2 Linux production-candidate handoff.
  Evaluates the signoff pipeline and the handoff readiness booleans.

Notes:
  - The checker prefers readiness booleans from the roadmap summary at:
      .vpn_track.phase2_linux_prod_candidate_handoff.*
  - If needed, it falls back to the nested check summary referenced by the
    signoff/run artifacts.
  - signoff_pipeline_ok is true only when the signoff summary contract is
    valid, the run stage passed, and the roadmap stage was pass or warn with a
    valid contract.
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

resolve_path_with_base() {
  local candidate="${1:-}"
  local base_file="${2:-}"
  local base_dir=""
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
  printf '%s' "$ROOT_DIR/$candidate"
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

json_bool_or_empty() {
  local path="${1:-}"
  local expr="${2:-}"
  local value=""
  value="$(json_text_or_empty "$path" "$expr")"
  case "$value" in
    true|false)
      printf '%s' "$value"
      ;;
    *)
      printf '%s' ""
      ;;
  esac
}

print_cmd() {
  local arg
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
  printf '\n'
}

array_has_arg() {
  local needle="$1"
  shift
  local arg
  for arg in "$@"; do
    if [[ "$arg" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

resolve_signoff_pipeline() {
  local signoff_summary_json="$1"
  local signoff_summary_usable="$2"
  local status="missing"
  local value="null"
  local resolved="0"
  local source="unresolved"

  if [[ "$signoff_summary_usable" != "1" ]]; then
    printf '%s|%s|%s|%s\n' "$value" "$status" "$source" "$resolved"
    return
  fi

  local contract_valid="0"
  local run_status=""
  local run_contract_valid="0"
  local roadmap_status=""
  local roadmap_contract_valid="0"

  if jq -e '
    type == "object"
    and (.version // 0) == 1
    and (.schema | type) == "object"
    and (.schema.id // "") == "phase2_linux_prod_candidate_signoff_summary"
    and ((.status | type) == "string")
    and ((.rc | type) == "number")
    and ((.steps.phase2_linux_prod_candidate_run.status | type) == "string")
    and ((.steps.phase2_linux_prod_candidate_run.rc | type) == "number")
    and ((.steps.phase2_linux_prod_candidate_run.command_rc | type) == "number")
    and ((.steps.phase2_linux_prod_candidate_run.contract_valid | type) == "boolean")
    and ((.steps.roadmap_progress_report.status | type) == "string")
    and ((.steps.roadmap_progress_report.rc | type) == "number")
    and ((.steps.roadmap_progress_report.command_rc | type) == "number")
    and ((.steps.roadmap_progress_report.contract_valid | type) == "boolean")
  ' "$signoff_summary_json" >/dev/null 2>&1; then
    contract_valid="1"
  fi

  run_status="$(json_text_or_empty "$signoff_summary_json" '.steps.phase2_linux_prod_candidate_run.status')"
  roadmap_status="$(json_text_or_empty "$signoff_summary_json" '.steps.roadmap_progress_report.status')"
  if [[ "$(json_bool_or_empty "$signoff_summary_json" '.steps.phase2_linux_prod_candidate_run.contract_valid')" == "true" ]]; then
    run_contract_valid="1"
  fi
  if [[ "$(json_bool_or_empty "$signoff_summary_json" '.steps.roadmap_progress_report.contract_valid')" == "true" ]]; then
    roadmap_contract_valid="1"
  fi

  if [[ "$contract_valid" != "1" ]]; then
    status="invalid"
    value="false"
    resolved="1"
    source="phase2_signoff_summary.contract"
  elif [[ "$run_status" != "pass" || "$run_contract_valid" != "1" ]]; then
    status="fail"
    value="false"
    resolved="1"
    source="phase2_signoff_summary.steps.phase2_linux_prod_candidate_run"
  elif [[ "$roadmap_status" != "pass" && "$roadmap_status" != "warn" ]] || [[ "$roadmap_contract_valid" != "1" ]]; then
    status="fail"
    value="false"
    resolved="1"
    source="phase2_signoff_summary.steps.roadmap_progress_report"
  else
    status="pass"
    value="true"
    resolved="1"
    source="phase2_signoff_summary"
  fi

  printf '%s|%s|%s|%s\n' "$value" "$status" "$source" "$resolved"
}

resolve_handoff_bool() {
  local signal="$1"
  local roadmap_summary_json="$2"
  local roadmap_summary_usable="$3"
  local signoff_summary_json="$4"
  local signoff_summary_usable="$5"

  local value="null"
  local status="missing"
  local source="unresolved"
  local resolved="0"

  if [[ "$roadmap_summary_usable" == "1" ]]; then
    value="$(json_bool_or_empty "$roadmap_summary_json" "if (.vpn_track.phase2_linux_prod_candidate_handoff.$signal | type) == \"boolean\" then .vpn_track.phase2_linux_prod_candidate_handoff.$signal elif (.phase2_linux_prod_candidate_handoff.$signal | type) == \"boolean\" then .phase2_linux_prod_candidate_handoff.$signal else empty end")"
    if [[ -n "$value" ]]; then
      status="$( [[ "$value" == "true" ]] && printf '%s' "pass" || printf '%s' "fail" )"
      source="roadmap_progress_summary.vpn_track.phase2_linux_prod_candidate_handoff.$signal"
      resolved="1"
      printf '%s|%s|%s|%s\n' "$value" "$status" "$source" "$resolved"
      return
    fi
  fi

  if [[ "$signoff_summary_usable" == "1" ]]; then
    local run_summary_json=""
    local check_summary_json=""
    run_summary_json="$(json_text_or_empty "$signoff_summary_json" '.steps.phase2_linux_prod_candidate_run.artifacts.summary_json // .artifacts.run_summary_json')"
    if [[ -n "$run_summary_json" ]]; then
      run_summary_json="$(resolve_path_with_base "$run_summary_json" "$signoff_summary_json")"
      if [[ "$(json_file_valid_01 "$run_summary_json")" == "1" ]]; then
        check_summary_json="$(json_text_or_empty "$run_summary_json" '.steps.phase2_linux_prod_candidate_check.artifacts.summary_json // .artifacts.check_summary_json')"
        if [[ -n "$check_summary_json" ]]; then
          check_summary_json="$(resolve_path_with_base "$check_summary_json" "$run_summary_json")"
          if [[ "$(json_file_valid_01 "$check_summary_json")" == "1" ]]; then
            value="$(json_bool_or_empty "$check_summary_json" "if (.signals.$signal | type) == \"boolean\" then .signals.$signal elif (.handoff.$signal | type) == \"boolean\" then .handoff.$signal elif (.phase2_linux_prod_candidate_handoff.$signal | type) == \"boolean\" then .phase2_linux_prod_candidate_handoff.$signal elif (.vpn_track.phase2_linux_prod_candidate_handoff.$signal | type) == \"boolean\" then .vpn_track.phase2_linux_prod_candidate_handoff.$signal else empty end")"
            if [[ -n "$value" ]]; then
              status="$( [[ "$value" == "true" ]] && printf '%s' "pass" || printf '%s' "fail" )"
              source="phase2_linux_prod_candidate_check_summary.$signal"
              resolved="1"
              printf '%s|%s|%s|%s\n' "$value" "$status" "$source" "$resolved"
              return
            fi
          fi
        fi
      fi
    fi
  fi

  if [[ -z "$value" ]]; then
    value="null"
  fi
  printf '%s|%s|%s|%s\n' "$value" "$status" "$source" "$resolved"
}

emit_summary_json() {
  local summary_json="$1"
  local generated_at_utc="$2"
  local status="$3"
  local rc="$4"
  local phase2_signoff_summary_json="$5"
  local roadmap_summary_json="$6"
  local signoff_summary_usable="$7"
  local roadmap_summary_usable="$8"
  local show_json="$9"
  local require_signoff_pipeline_ok="${10}"
  local require_release_integrity_ok="${11}"
  local require_release_policy_ok="${12}"
  local require_operator_lifecycle_ok="${13}"
  local require_pilot_signoff_ok="${14}"
  local signoff_pipeline_status="${15}"
  local signoff_pipeline_ok="${16}"
  local signoff_pipeline_resolved="${17}"
  local signoff_pipeline_source="${18}"
  local signoff_pipeline_contract_valid="${19}"
  local release_integrity_status="${20}"
  local release_policy_status="${21}"
  local operator_lifecycle_status="${22}"
  local pilot_signoff_status="${23}"
  local release_integrity_ok="${24}"
  local release_policy_ok="${25}"
  local operator_lifecycle_ok="${26}"
  local pilot_signoff_ok="${27}"
  local release_integrity_resolved="${28}"
  local release_policy_resolved="${29}"
  local operator_lifecycle_resolved="${30}"
  local pilot_signoff_resolved="${31}"
  local release_integrity_source="${32}"
  local release_policy_source="${33}"
  local operator_lifecycle_source="${34}"
  local pilot_signoff_source="${35}"
  local reasons_json="${36}"
  local reason_details_json="${37}"
  local warnings_json="${38}"
  local warning_details_json="${39}"

  local summary_tmp
  summary_tmp="$(mktemp)"
  jq -n \
    --arg generated_at_utc "$generated_at_utc" \
    --arg status "$status" \
    --argjson rc "$rc" \
    --arg summary_json "$summary_json" \
    --arg phase2_signoff_summary_json "$phase2_signoff_summary_json" \
    --arg roadmap_summary_json "$roadmap_summary_json" \
    --argjson signoff_summary_usable "$signoff_summary_usable" \
    --argjson roadmap_summary_usable "$roadmap_summary_usable" \
    --arg show_json "$show_json" \
    --argjson require_signoff_pipeline_ok "$require_signoff_pipeline_ok" \
    --argjson require_release_integrity_ok "$require_release_integrity_ok" \
    --argjson require_release_policy_ok "$require_release_policy_ok" \
    --argjson require_operator_lifecycle_ok "$require_operator_lifecycle_ok" \
    --argjson require_pilot_signoff_ok "$require_pilot_signoff_ok" \
    --arg signoff_pipeline_status "$signoff_pipeline_status" \
    --argjson signoff_pipeline_ok "$signoff_pipeline_ok" \
    --argjson signoff_pipeline_resolved "$signoff_pipeline_resolved" \
    --arg signoff_pipeline_source "$signoff_pipeline_source" \
    --argjson signoff_pipeline_contract_valid "$signoff_pipeline_contract_valid" \
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
    --arg release_integrity_source "$release_integrity_source" \
    --arg release_policy_source "$release_policy_source" \
    --arg operator_lifecycle_source "$operator_lifecycle_source" \
    --arg pilot_signoff_source "$pilot_signoff_source" \
    --argjson reasons "$reasons_json" \
    --argjson reason_details "$reason_details_json" \
    --argjson warnings "$warnings_json" \
    --argjson warning_details "$warning_details_json" \
    '{
      version: 1,
      schema: {
        id: "phase2_linux_prod_candidate_handoff_check_summary",
        major: 1,
        minor: 0
      },
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $rc,
      fail_closed: true,
      metadata: {
        contract: "phase2-linux-production-candidate",
        script: "phase2_linux_prod_candidate_handoff_check.sh"
      },
      inputs: {
        phase2_signoff_summary_json: (if $phase2_signoff_summary_json == "" then null else $phase2_signoff_summary_json end),
        roadmap_summary_json: (if $roadmap_summary_json == "" then null else $roadmap_summary_json end),
        show_json: ($show_json == "1"),
        requirements: {
          signoff_pipeline_ok: ($require_signoff_pipeline_ok == 1),
          release_integrity_ok: ($require_release_integrity_ok == 1),
          release_policy_ok: ($require_release_policy_ok == 1),
          operator_lifecycle_ok: ($require_operator_lifecycle_ok == 1),
          pilot_signoff_ok: ($require_pilot_signoff_ok == 1)
        },
        usable: {
          phase2_signoff_summary_json: ($signoff_summary_usable == 1),
          roadmap_summary_json: ($roadmap_summary_usable == 1)
        }
      },
      handoff: {
        signoff_pipeline_ok: $signoff_pipeline_ok,
        signoff_pipeline_status: $signoff_pipeline_status,
        signoff_pipeline_resolved: ($signoff_pipeline_resolved == 1),
        signoff_pipeline_contract_valid: ($signoff_pipeline_contract_valid == 1),
        release_integrity_ok: $release_integrity_ok,
        release_integrity_status: $release_integrity_status,
        release_integrity_resolved: ($release_integrity_resolved == 1),
        release_policy_ok: $release_policy_ok,
        release_policy_status: $release_policy_status,
        release_policy_resolved: ($release_policy_resolved == 1),
        operator_lifecycle_ok: $operator_lifecycle_ok,
        operator_lifecycle_status: $operator_lifecycle_status,
        operator_lifecycle_resolved: ($operator_lifecycle_resolved == 1),
        pilot_signoff_ok: $pilot_signoff_ok,
        pilot_signoff_status: $pilot_signoff_status,
        pilot_signoff_resolved: ($pilot_signoff_resolved == 1),
        sources: {
          signoff_pipeline_ok: $signoff_pipeline_source,
          release_integrity_ok: $release_integrity_source,
          release_policy_ok: $release_policy_source,
          operator_lifecycle_ok: $operator_lifecycle_source,
          pilot_signoff_ok: $pilot_signoff_source
        }
      },
      decision: {
        pass: ($status == "pass"),
        reasons: $reasons,
        reason_details: $reason_details,
        reason_codes: ($reason_details | map(.code) | unique),
        warnings: $warnings,
        warning_details: $warning_details,
        warning_codes: ($warning_details | map(.code) | unique)
      },
      artifacts: {
        summary_json: $summary_json
      }
    }' >"$summary_tmp"
  mv -f "$summary_tmp" "$summary_json"
}

need_cmd jq
need_cmd date
need_cmd mktemp

phase2_signoff_summary_json="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_CHECK_PHASE2_SIGNOFF_SUMMARY_JSON:-}"
roadmap_summary_json="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_CHECK_ROADMAP_SUMMARY_JSON:-}"
summary_json="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_CHECK_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase2_linux_prod_candidate_handoff_check_summary.json}"
show_json="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_CHECK_SHOW_JSON:-0}"
require_signoff_pipeline_ok="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_CHECK_REQUIRE_SIGNOFF_PIPELINE_OK:-1}"
require_release_integrity_ok="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_CHECK_REQUIRE_RELEASE_INTEGRITY_OK:-1}"
require_release_policy_ok="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_CHECK_REQUIRE_RELEASE_POLICY_OK:-1}"
require_operator_lifecycle_ok="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_CHECK_REQUIRE_OPERATOR_LIFECYCLE_OK:-1}"
require_pilot_signoff_ok="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_CHECK_REQUIRE_PILOT_SIGNOFF_OK:-1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --phase2-signoff-summary-json)
      phase2_signoff_summary_json="${2:-}"
      shift 2
      ;;
    --roadmap-summary-json)
      roadmap_summary_json="${2:-}"
      shift 2
      ;;
    --require-signoff-pipeline-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_signoff_pipeline_ok="${2:-}"
        shift 2
      else
        require_signoff_pipeline_ok="1"
        shift
      fi
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

bool_arg_or_die "--require-signoff-pipeline-ok" "$require_signoff_pipeline_ok"
bool_arg_or_die "--require-release-integrity-ok" "$require_release_integrity_ok"
bool_arg_or_die "--require-release-policy-ok" "$require_release_policy_ok"
bool_arg_or_die "--require-operator-lifecycle-ok" "$require_operator_lifecycle_ok"
bool_arg_or_die "--require-pilot-signoff-ok" "$require_pilot_signoff_ok"
bool_arg_or_die "--show-json" "$show_json"

phase2_signoff_summary_json="$(abs_path "$phase2_signoff_summary_json")"
roadmap_summary_json="$(abs_path "$roadmap_summary_json")"
summary_json="$(abs_path "$summary_json")"

mkdir -p "$(dirname "$summary_json")"

generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

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
  local source="$8"
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
      --arg source "$source" \
      '$arr + [{
        code: $code,
        signal: $signal,
        message: $message,
        required: $required,
        observed_status: $observed_status,
        resolved: $resolved,
        observed_value: (if $observed_value == "" or $observed_value == "null" then null else $observed_value end),
        source: $source
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
  local source="$7"
  warnings_details_json="$(
    jq -cn \
      --argjson arr "$warnings_details_json" \
      --arg code "$code" \
      --arg signal "$signal" \
      --arg message "$message" \
      --arg observed_status "$observed_status" \
      --argjson resolved "$resolved" \
      --arg observed_value "$observed_value" \
      --arg source "$source" \
      '$arr + [{
        code: $code,
        signal: $signal,
        message: $message,
        observed_status: $observed_status,
        resolved: $resolved,
        observed_value: (if $observed_value == "" or $observed_value == "null" then null else $observed_value end),
        source: $source
      }]'
  )"
}

phase2_signoff_summary_usable="0"
roadmap_summary_usable="0"
signoff_summary_contract_valid="0"
signoff_pipeline_value="null"
signoff_pipeline_status="missing"
signoff_pipeline_resolved="0"
signoff_pipeline_source="unresolved"

if [[ -n "$phase2_signoff_summary_json" ]]; then
  if [[ "$(json_file_valid_01 "$phase2_signoff_summary_json")" == "1" ]]; then
    phase2_signoff_summary_usable="1"
  else
    reasons+=("phase2 signoff summary file not found or invalid JSON: $phase2_signoff_summary_json")
    append_reason_detail \
      "signoff_summary_unusable" \
      "signoff_pipeline_ok" \
      "phase2 signoff summary file not found or invalid JSON: $phase2_signoff_summary_json" \
      true \
      "missing" \
      false \
      "" \
      "phase2_signoff_summary_json"
  fi
fi

if [[ -n "$roadmap_summary_json" ]]; then
  if [[ "$(json_file_valid_01 "$roadmap_summary_json")" == "1" ]]; then
    roadmap_summary_usable="1"
  else
    reasons+=("roadmap summary file not found or invalid JSON: $roadmap_summary_json")
    append_reason_detail \
      "roadmap_summary_unusable" \
      "roadmap_summary_json" \
      "roadmap summary file not found or invalid JSON: $roadmap_summary_json" \
      true \
      "missing" \
      false \
      "" \
      "roadmap_summary_json"
  fi
fi

if [[ "$phase2_signoff_summary_usable" == "1" ]]; then
  signoff_pipeline_pair="$(resolve_signoff_pipeline "$phase2_signoff_summary_json" "$phase2_signoff_summary_usable")"
  signoff_pipeline_value="${signoff_pipeline_pair%%|*}"
  signoff_pipeline_pair="${signoff_pipeline_pair#*|}"
  signoff_pipeline_status="${signoff_pipeline_pair%%|*}"
  signoff_pipeline_pair="${signoff_pipeline_pair#*|}"
  signoff_pipeline_source="${signoff_pipeline_pair%%|*}"
  signoff_pipeline_resolved="${signoff_pipeline_pair##*|}"
  if jq -e '
    type == "object"
    and (.version // 0) == 1
    and (.schema | type) == "object"
    and (.schema.id // "") == "phase2_linux_prod_candidate_signoff_summary"
    and ((.status | type) == "string")
    and ((.rc | type) == "number")
    and ((.steps.phase2_linux_prod_candidate_run.status | type) == "string")
    and ((.steps.phase2_linux_prod_candidate_run.rc | type) == "number")
    and ((.steps.phase2_linux_prod_candidate_run.command_rc | type) == "number")
    and ((.steps.phase2_linux_prod_candidate_run.contract_valid | type) == "boolean")
    and ((.steps.roadmap_progress_report.status | type) == "string")
    and ((.steps.roadmap_progress_report.rc | type) == "number")
    and ((.steps.roadmap_progress_report.command_rc | type) == "number")
    and ((.steps.roadmap_progress_report.contract_valid | type) == "boolean")
  ' "$phase2_signoff_summary_json" >/dev/null 2>&1; then
    signoff_summary_contract_valid="1"
  else
    signoff_summary_contract_valid="0"
  fi
  if [[ "$signoff_pipeline_status" == "invalid" ]]; then
    reasons+=("phase2 signoff summary contract is invalid")
    append_reason_detail \
      "signoff_summary_contract_invalid" \
      "signoff_pipeline_ok" \
      "phase2 signoff summary contract is invalid" \
      true \
      "$signoff_pipeline_status" \
      true \
      "$signoff_pipeline_value" \
      "$signoff_pipeline_source"
  elif [[ "$signoff_pipeline_status" == "fail" ]]; then
    reasons+=("signoff pipeline is not ready")
    append_reason_detail \
      "signoff_pipeline_not_ready" \
      "signoff_pipeline_ok" \
      "signoff pipeline is not ready" \
      true \
      "$signoff_pipeline_status" \
      true \
      "$signoff_pipeline_value" \
      "$signoff_pipeline_source"
  fi
else
  reasons+=("phase2 signoff summary is unavailable")
  append_reason_detail \
    "signoff_summary_unavailable" \
    "signoff_pipeline_ok" \
    "phase2 signoff summary is unavailable" \
    true \
    "$signoff_pipeline_status" \
    false \
    "$signoff_pipeline_value" \
    "$signoff_pipeline_source"
fi

release_integrity_pair="$(resolve_handoff_bool "release_integrity_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase2_signoff_summary_json" "$phase2_signoff_summary_usable")"
release_policy_pair="$(resolve_handoff_bool "release_policy_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase2_signoff_summary_json" "$phase2_signoff_summary_usable")"
operator_lifecycle_pair="$(resolve_handoff_bool "operator_lifecycle_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase2_signoff_summary_json" "$phase2_signoff_summary_usable")"
pilot_signoff_pair="$(resolve_handoff_bool "pilot_signoff_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase2_signoff_summary_json" "$phase2_signoff_summary_usable")"

release_integrity_ok="${release_integrity_pair%%|*}"
release_integrity_pair="${release_integrity_pair#*|}"
release_integrity_status="${release_integrity_pair%%|*}"
release_integrity_pair="${release_integrity_pair#*|}"
release_integrity_source="${release_integrity_pair%%|*}"
release_integrity_resolved="${release_integrity_pair##*|}"

release_policy_ok="${release_policy_pair%%|*}"
release_policy_pair="${release_policy_pair#*|}"
release_policy_status="${release_policy_pair%%|*}"
release_policy_pair="${release_policy_pair#*|}"
release_policy_source="${release_policy_pair%%|*}"
release_policy_resolved="${release_policy_pair##*|}"

operator_lifecycle_ok="${operator_lifecycle_pair%%|*}"
operator_lifecycle_pair="${operator_lifecycle_pair#*|}"
operator_lifecycle_status="${operator_lifecycle_pair%%|*}"
operator_lifecycle_pair="${operator_lifecycle_pair#*|}"
operator_lifecycle_source="${operator_lifecycle_pair%%|*}"
operator_lifecycle_resolved="${operator_lifecycle_pair##*|}"

pilot_signoff_ok="${pilot_signoff_pair%%|*}"
pilot_signoff_pair="${pilot_signoff_pair#*|}"
pilot_signoff_status="${pilot_signoff_pair%%|*}"
pilot_signoff_pair="${pilot_signoff_pair#*|}"
pilot_signoff_source="${pilot_signoff_pair%%|*}"
pilot_signoff_resolved="${pilot_signoff_pair##*|}"

if [[ "$require_signoff_pipeline_ok" == "1" && "$signoff_pipeline_value" != "true" ]]; then
  if [[ "$signoff_pipeline_status" == "missing" ]]; then
    reasons+=("signoff_pipeline_ok unresolved from provided artifacts")
    append_reason_detail \
      "signal_unresolved" \
      "signoff_pipeline_ok" \
      "signoff_pipeline_ok unresolved from provided artifacts" \
      true \
      "$signoff_pipeline_status" \
      false \
      "$signoff_pipeline_value" \
      "$signoff_pipeline_source"
  else
    reasons+=("signoff_pipeline_ok is false")
    append_reason_detail \
      "required_signal_false" \
      "signoff_pipeline_ok" \
      "signoff_pipeline_ok is false" \
      true \
      "$signoff_pipeline_status" \
      "$( [[ "$signoff_pipeline_resolved" == "1" ]] && echo true || echo false )" \
      "$signoff_pipeline_value" \
      "$signoff_pipeline_source"
  fi
fi
if [[ "$require_release_integrity_ok" == "1" && "$release_integrity_ok" != "true" ]]; then
  if [[ "$release_integrity_status" == "missing" ]]; then
    reasons+=("release_integrity_ok unresolved from provided artifacts")
    append_reason_detail \
      "signal_unresolved" \
      "release_integrity_ok" \
      "release_integrity_ok unresolved from provided artifacts" \
      true \
      "$release_integrity_status" \
      false \
      "$release_integrity_ok" \
      "$release_integrity_source"
  else
    reasons+=("release_integrity_ok is false")
    append_reason_detail \
      "required_signal_false" \
      "release_integrity_ok" \
      "release_integrity_ok is false" \
      true \
      "$release_integrity_status" \
      "$( [[ "$release_integrity_resolved" == "1" ]] && echo true || echo false )" \
      "$release_integrity_ok" \
      "$release_integrity_source"
  fi
fi
if [[ "$require_release_policy_ok" == "1" && "$release_policy_ok" != "true" ]]; then
  if [[ "$release_policy_status" == "missing" ]]; then
    reasons+=("release_policy_ok unresolved from provided artifacts")
    append_reason_detail \
      "signal_unresolved" \
      "release_policy_ok" \
      "release_policy_ok unresolved from provided artifacts" \
      true \
      "$release_policy_status" \
      false \
      "$release_policy_ok" \
      "$release_policy_source"
  else
    reasons+=("release_policy_ok is false")
    append_reason_detail \
      "required_signal_false" \
      "release_policy_ok" \
      "release_policy_ok is false" \
      true \
      "$release_policy_status" \
      "$( [[ "$release_policy_resolved" == "1" ]] && echo true || echo false )" \
      "$release_policy_ok" \
      "$release_policy_source"
  fi
fi
if [[ "$require_operator_lifecycle_ok" == "1" && "$operator_lifecycle_ok" != "true" ]]; then
  if [[ "$operator_lifecycle_status" == "missing" ]]; then
    reasons+=("operator_lifecycle_ok unresolved from provided artifacts")
    append_reason_detail \
      "signal_unresolved" \
      "operator_lifecycle_ok" \
      "operator_lifecycle_ok unresolved from provided artifacts" \
      true \
      "$operator_lifecycle_status" \
      false \
      "$operator_lifecycle_ok" \
      "$operator_lifecycle_source"
  else
    reasons+=("operator_lifecycle_ok is false")
    append_reason_detail \
      "required_signal_false" \
      "operator_lifecycle_ok" \
      "operator_lifecycle_ok is false" \
      true \
      "$operator_lifecycle_status" \
      "$( [[ "$operator_lifecycle_resolved" == "1" ]] && echo true || echo false )" \
      "$operator_lifecycle_ok" \
      "$operator_lifecycle_source"
  fi
fi
if [[ "$require_pilot_signoff_ok" == "1" && "$pilot_signoff_ok" != "true" ]]; then
  if [[ "$pilot_signoff_status" == "missing" ]]; then
    reasons+=("pilot_signoff_ok unresolved from provided artifacts")
    append_reason_detail \
      "signal_unresolved" \
      "pilot_signoff_ok" \
      "pilot_signoff_ok unresolved from provided artifacts" \
      true \
      "$pilot_signoff_status" \
      false \
      "$pilot_signoff_ok" \
      "$pilot_signoff_source"
  else
    reasons+=("pilot_signoff_ok is false")
    append_reason_detail \
      "required_signal_false" \
      "pilot_signoff_ok" \
      "pilot_signoff_ok is false" \
      true \
      "$pilot_signoff_status" \
      "$( [[ "$pilot_signoff_resolved" == "1" ]] && echo true || echo false )" \
      "$pilot_signoff_ok" \
      "$pilot_signoff_source"
  fi
fi

if [[ "$require_signoff_pipeline_ok" == "0" && "$signoff_pipeline_value" != "true" ]]; then
  append_warning_detail \
    "optional_signal_not_ready" \
    "signoff_pipeline_ok" \
    "signoff_pipeline_ok is not ready but requirement is disabled" \
    "$signoff_pipeline_status" \
    "$( [[ "$signoff_pipeline_resolved" == "1" ]] && echo true || echo false )" \
    "$signoff_pipeline_value" \
    "$signoff_pipeline_source"
fi
if [[ "$require_release_integrity_ok" == "0" && "$release_integrity_ok" != "true" ]]; then
  append_warning_detail \
    "optional_signal_not_ready" \
    "release_integrity_ok" \
    "release_integrity_ok is not ready but requirement is disabled" \
    "$release_integrity_status" \
    "$( [[ "$release_integrity_resolved" == "1" ]] && echo true || echo false )" \
    "$release_integrity_ok" \
    "$release_integrity_source"
fi
if [[ "$require_release_policy_ok" == "0" && "$release_policy_ok" != "true" ]]; then
  append_warning_detail \
    "optional_signal_not_ready" \
    "release_policy_ok" \
    "release_policy_ok is not ready but requirement is disabled" \
    "$release_policy_status" \
    "$( [[ "$release_policy_resolved" == "1" ]] && echo true || echo false )" \
    "$release_policy_ok" \
    "$release_policy_source"
fi
if [[ "$require_operator_lifecycle_ok" == "0" && "$operator_lifecycle_ok" != "true" ]]; then
  append_warning_detail \
    "optional_signal_not_ready" \
    "operator_lifecycle_ok" \
    "operator_lifecycle_ok is not ready but requirement is disabled" \
    "$operator_lifecycle_status" \
    "$( [[ "$operator_lifecycle_resolved" == "1" ]] && echo true || echo false )" \
    "$operator_lifecycle_ok" \
    "$operator_lifecycle_source"
fi
if [[ "$require_pilot_signoff_ok" == "0" && "$pilot_signoff_ok" != "true" ]]; then
  append_warning_detail \
    "optional_signal_not_ready" \
    "pilot_signoff_ok" \
    "pilot_signoff_ok is not ready but requirement is disabled" \
    "$pilot_signoff_status" \
    "$( [[ "$pilot_signoff_resolved" == "1" ]] && echo true || echo false )" \
    "$pilot_signoff_ok" \
    "$pilot_signoff_source"
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
  "$phase2_signoff_summary_json" \
  "$roadmap_summary_json" \
  "$phase2_signoff_summary_usable" \
  "$roadmap_summary_usable" \
  "$show_json" \
  "$require_signoff_pipeline_ok" \
  "$require_release_integrity_ok" \
  "$require_release_policy_ok" \
  "$require_operator_lifecycle_ok" \
  "$require_pilot_signoff_ok" \
  "$signoff_pipeline_status" \
  "$signoff_pipeline_value" \
  "$signoff_pipeline_resolved" \
  "$signoff_pipeline_source" \
  "$signoff_summary_contract_valid" \
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
  "$release_integrity_source" \
  "$release_policy_source" \
  "$operator_lifecycle_source" \
  "$pilot_signoff_source" \
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
