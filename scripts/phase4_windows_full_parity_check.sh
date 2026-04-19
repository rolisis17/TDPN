#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase4_windows_full_parity_check.sh \
    [--ci-phase4-summary-json PATH] \
    [--require-windows-server-packaging-ok [0|1]] \
    [--require-windows-role-runbooks-ok [0|1]] \
    [--require-cross-platform-interop-ok [0|1]] \
    [--require-role-combination-validation-ok [0|1]] \
    [--summary-json PATH] \
    [--show-json [0|1]]

Purpose:
  Fail-closed checker for the Phase-4 Windows full-parity readiness contract.
  Evaluates required readiness booleans derived from the CI Phase-4 summary:
    - windows_server_packaging_ok
    - windows_role_runbooks_ok
    - cross_platform_interop_ok
    - role_combination_validation_ok

Notes:
  - Provide the CI summary with --ci-phase4-summary-json.
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
    windows_server_packaging_ok)
      json_text_or_empty "$path" 'if (.windows_server_packaging_ok? != null) then .windows_server_packaging_ok
        elif (.summary.windows_server_packaging_ok? != null) then .summary.windows_server_packaging_ok
        elif (.signals.windows_server_packaging_ok? != null) then .signals.windows_server_packaging_ok
        elif (.stages.windows_server_packaging.status? != null) then .stages.windows_server_packaging.status
        elif (.steps.windows_server_packaging.status? != null) then .steps.windows_server_packaging.status
        else empty end'
      ;;
    windows_role_runbooks_ok)
      json_text_or_empty "$path" 'if (.windows_role_runbooks_ok? != null) then .windows_role_runbooks_ok
        elif (.summary.windows_role_runbooks_ok? != null) then .summary.windows_role_runbooks_ok
        elif (.signals.windows_role_runbooks_ok? != null) then .signals.windows_role_runbooks_ok
        elif (.stages.windows_role_runbooks.status? != null) then .stages.windows_role_runbooks.status
        elif (.steps.windows_role_runbooks.status? != null) then .steps.windows_role_runbooks.status
        else empty end'
      ;;
    cross_platform_interop_ok)
      json_text_or_empty "$path" 'if (.cross_platform_interop_ok? != null) then .cross_platform_interop_ok
        elif (.summary.cross_platform_interop_ok? != null) then .summary.cross_platform_interop_ok
        elif (.signals.cross_platform_interop_ok? != null) then .signals.cross_platform_interop_ok
        elif (.stages.cross_platform_interop.status? != null) then .stages.cross_platform_interop.status
        elif (.steps.cross_platform_interop.status? != null) then .steps.cross_platform_interop.status
        else empty end'
      ;;
    role_combination_validation_ok)
      json_text_or_empty "$path" 'if (.role_combination_validation_ok? != null) then .role_combination_validation_ok
        elif (.summary.role_combination_validation_ok? != null) then .summary.role_combination_validation_ok
        elif (.signals.role_combination_validation_ok? != null) then .signals.role_combination_validation_ok
        elif (.stages.role_combination_validation.status? != null) then .stages.role_combination_validation.status
        elif (.steps.role_combination_validation.status? != null) then .steps.role_combination_validation.status
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
  local ci_phase4_summary_json="$5"
  local ci_phase4_summary_usable="$6"
  local show_json="$7"
  local require_windows_server_packaging_ok="$8"
  local require_windows_role_runbooks_ok="$9"
  local require_cross_platform_interop_ok="${10}"
  local require_role_combination_validation_ok="${11}"
  local windows_server_packaging_status="${12}"
  local windows_role_runbooks_status="${13}"
  local cross_platform_interop_status="${14}"
  local role_combination_validation_status="${15}"
  local windows_server_packaging_ok="${16}"
  local windows_role_runbooks_ok="${17}"
  local cross_platform_interop_ok="${18}"
  local role_combination_validation_ok="${19}"
  local windows_server_packaging_resolved="${20}"
  local windows_role_runbooks_resolved="${21}"
  local cross_platform_interop_resolved="${22}"
  local role_combination_validation_resolved="${23}"
  local reasons_json="${24}"

  local summary_tmp
  summary_tmp="$(mktemp)"
  jq -n \
    --arg generated_at_utc "$generated_at_utc" \
    --arg status "$status" \
    --argjson rc "$rc" \
    --arg summary_json "$summary_json" \
    --arg ci_phase4_summary_json "$ci_phase4_summary_json" \
    --argjson ci_phase4_summary_usable "$ci_phase4_summary_usable" \
    --arg show_json "$show_json" \
    --argjson require_windows_server_packaging_ok "$require_windows_server_packaging_ok" \
    --argjson require_windows_role_runbooks_ok "$require_windows_role_runbooks_ok" \
    --argjson require_cross_platform_interop_ok "$require_cross_platform_interop_ok" \
    --argjson require_role_combination_validation_ok "$require_role_combination_validation_ok" \
    --arg windows_server_packaging_status "$windows_server_packaging_status" \
    --arg windows_role_runbooks_status "$windows_role_runbooks_status" \
    --arg cross_platform_interop_status "$cross_platform_interop_status" \
    --arg role_combination_validation_status "$role_combination_validation_status" \
    --argjson windows_server_packaging_ok "$windows_server_packaging_ok" \
    --argjson windows_role_runbooks_ok "$windows_role_runbooks_ok" \
    --argjson cross_platform_interop_ok "$cross_platform_interop_ok" \
    --argjson role_combination_validation_ok "$role_combination_validation_ok" \
    --argjson windows_server_packaging_resolved "$windows_server_packaging_resolved" \
    --argjson windows_role_runbooks_resolved "$windows_role_runbooks_resolved" \
    --argjson cross_platform_interop_resolved "$cross_platform_interop_resolved" \
    --argjson role_combination_validation_resolved "$role_combination_validation_resolved" \
    --argjson reasons "$reasons_json" \
    '{
      version: 1,
      schema: {
        id: "phase4_windows_full_parity_check_summary",
        major: 1,
        minor: 0
      },
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $rc,
      metadata: {
        contract: "phase4-windows-full-parity",
        script: "phase4_windows_full_parity_check.sh"
      },
      inputs: {
        ci_phase4_summary_json: $ci_phase4_summary_json,
        summary_json: $summary_json,
        show_json: ($show_json == "1"),
        usable: {
          ci_phase4_summary_json: ($ci_phase4_summary_usable == 1)
        }
      },
      policy: {
        require_windows_server_packaging_ok: ($require_windows_server_packaging_ok == 1),
        require_windows_role_runbooks_ok: ($require_windows_role_runbooks_ok == 1),
        require_cross_platform_interop_ok: ($require_cross_platform_interop_ok == 1),
        require_role_combination_validation_ok: ($require_role_combination_validation_ok == 1)
      },
      stages: {
        windows_server_packaging: {
          enabled: ($require_windows_server_packaging_ok == 1),
          status: $windows_server_packaging_status,
          resolved: ($windows_server_packaging_resolved == 1),
          ok: ($windows_server_packaging_ok == true)
        },
        windows_role_runbooks: {
          enabled: ($require_windows_role_runbooks_ok == 1),
          status: $windows_role_runbooks_status,
          resolved: ($windows_role_runbooks_resolved == 1),
          ok: ($windows_role_runbooks_ok == true)
        },
        cross_platform_interop: {
          enabled: ($require_cross_platform_interop_ok == 1),
          status: $cross_platform_interop_status,
          resolved: ($cross_platform_interop_resolved == 1),
          ok: ($cross_platform_interop_ok == true)
        },
        role_combination_validation: {
          enabled: ($require_role_combination_validation_ok == 1),
          status: $role_combination_validation_status,
          resolved: ($role_combination_validation_resolved == 1),
          ok: ($role_combination_validation_ok == true)
        }
      },
      signals: {
        windows_server_packaging_ok: ($windows_server_packaging_ok == true),
        windows_role_runbooks_ok: ($windows_role_runbooks_ok == true),
        cross_platform_interop_ok: ($cross_platform_interop_ok == true),
        role_combination_validation_ok: ($role_combination_validation_ok == true)
      },
      decision: {
        pass: ($status == "pass"),
        reasons: $reasons,
        reason_codes: [
          (if ($ci_phase4_summary_usable != 1) then "ci_phase4_summary_unusable" else empty end),
          (if ($require_windows_server_packaging_ok == 1 and $windows_server_packaging_resolved != 1) then "windows_server_packaging_ok_unresolved"
           elif ($require_windows_server_packaging_ok == 1 and $windows_server_packaging_resolved == 1 and $windows_server_packaging_ok != true) then "windows_server_packaging_ok_false"
           else empty end),
          (if ($require_windows_role_runbooks_ok == 1 and $windows_role_runbooks_resolved != 1) then "windows_role_runbooks_ok_unresolved"
           elif ($require_windows_role_runbooks_ok == 1 and $windows_role_runbooks_resolved == 1 and $windows_role_runbooks_ok != true) then "windows_role_runbooks_ok_false"
           else empty end),
          (if ($require_cross_platform_interop_ok == 1 and $cross_platform_interop_resolved != 1) then "cross_platform_interop_ok_unresolved"
           elif ($require_cross_platform_interop_ok == 1 and $cross_platform_interop_resolved == 1 and $cross_platform_interop_ok != true) then "cross_platform_interop_ok_false"
           else empty end),
          (if ($require_role_combination_validation_ok == 1 and $role_combination_validation_resolved != 1) then "role_combination_validation_ok_unresolved"
           elif ($require_role_combination_validation_ok == 1 and $role_combination_validation_resolved == 1 and $role_combination_validation_ok != true) then "role_combination_validation_ok_false"
           else empty end)
        ],
        reason_details: [
          (if ($ci_phase4_summary_usable != 1) then {
            code: "ci_phase4_summary_unusable",
            signal: null,
            kind: "unresolved",
            source: "inputs.ci_phase4_summary_json",
            required: true,
            resolved: false,
            observed: null,
            stage_status: "missing"
          } else empty end),
          (if ($require_windows_server_packaging_ok == 1 and $windows_server_packaging_resolved != 1) then {
            code: "windows_server_packaging_ok_unresolved",
            signal: "windows_server_packaging_ok",
            kind: "unresolved",
            source: "signals.windows_server_packaging_ok",
            required: true,
            resolved: false,
            observed: ($windows_server_packaging_ok == true),
            stage_status: $windows_server_packaging_status
          } elif ($require_windows_server_packaging_ok == 1 and $windows_server_packaging_resolved == 1 and $windows_server_packaging_ok != true) then {
            code: "windows_server_packaging_ok_false",
            signal: "windows_server_packaging_ok",
            kind: "false",
            source: "signals.windows_server_packaging_ok",
            required: true,
            resolved: true,
            observed: false,
            stage_status: $windows_server_packaging_status
          } else empty end),
          (if ($require_windows_role_runbooks_ok == 1 and $windows_role_runbooks_resolved != 1) then {
            code: "windows_role_runbooks_ok_unresolved",
            signal: "windows_role_runbooks_ok",
            kind: "unresolved",
            source: "signals.windows_role_runbooks_ok",
            required: true,
            resolved: false,
            observed: ($windows_role_runbooks_ok == true),
            stage_status: $windows_role_runbooks_status
          } elif ($require_windows_role_runbooks_ok == 1 and $windows_role_runbooks_resolved == 1 and $windows_role_runbooks_ok != true) then {
            code: "windows_role_runbooks_ok_false",
            signal: "windows_role_runbooks_ok",
            kind: "false",
            source: "signals.windows_role_runbooks_ok",
            required: true,
            resolved: true,
            observed: false,
            stage_status: $windows_role_runbooks_status
          } else empty end),
          (if ($require_cross_platform_interop_ok == 1 and $cross_platform_interop_resolved != 1) then {
            code: "cross_platform_interop_ok_unresolved",
            signal: "cross_platform_interop_ok",
            kind: "unresolved",
            source: "signals.cross_platform_interop_ok",
            required: true,
            resolved: false,
            observed: ($cross_platform_interop_ok == true),
            stage_status: $cross_platform_interop_status
          } elif ($require_cross_platform_interop_ok == 1 and $cross_platform_interop_resolved == 1 and $cross_platform_interop_ok != true) then {
            code: "cross_platform_interop_ok_false",
            signal: "cross_platform_interop_ok",
            kind: "false",
            source: "signals.cross_platform_interop_ok",
            required: true,
            resolved: true,
            observed: false,
            stage_status: $cross_platform_interop_status
          } else empty end),
          (if ($require_role_combination_validation_ok == 1 and $role_combination_validation_resolved != 1) then {
            code: "role_combination_validation_ok_unresolved",
            signal: "role_combination_validation_ok",
            kind: "unresolved",
            source: "signals.role_combination_validation_ok",
            required: true,
            resolved: false,
            observed: ($role_combination_validation_ok == true),
            stage_status: $role_combination_validation_status
          } elif ($require_role_combination_validation_ok == 1 and $role_combination_validation_resolved == 1 and $role_combination_validation_ok != true) then {
            code: "role_combination_validation_ok_false",
            signal: "role_combination_validation_ok",
            kind: "false",
            source: "signals.role_combination_validation_ok",
            required: true,
            resolved: true,
            observed: false,
            stage_status: $role_combination_validation_status
          } else empty end)
        ],
        failure_kind: (if $status == "pass" then "none" else "policy_no_go" end)
      },
      failure: {
        kind: (if $status == "pass" then "none" else "policy_no_go" end),
        policy_no_go: ($status != "pass"),
        execution_failure: false
      },
      signal_semantics: {
        windows_server_packaging_ok: {
          required: ($require_windows_server_packaging_ok == 1),
          resolved: ($windows_server_packaging_resolved == 1),
          observed: ($windows_server_packaging_ok == true),
          stage_status: $windows_server_packaging_status,
          failure_kind: (
            if ($require_windows_server_packaging_ok != 1) then "not_required"
            elif ($windows_server_packaging_resolved != 1) then "unresolved"
            elif ($windows_server_packaging_ok == true) then "ok"
            else "false"
            end
          )
        },
        windows_role_runbooks_ok: {
          required: ($require_windows_role_runbooks_ok == 1),
          resolved: ($windows_role_runbooks_resolved == 1),
          observed: ($windows_role_runbooks_ok == true),
          stage_status: $windows_role_runbooks_status,
          failure_kind: (
            if ($require_windows_role_runbooks_ok != 1) then "not_required"
            elif ($windows_role_runbooks_resolved != 1) then "unresolved"
            elif ($windows_role_runbooks_ok == true) then "ok"
            else "false"
            end
          )
        },
        cross_platform_interop_ok: {
          required: ($require_cross_platform_interop_ok == 1),
          resolved: ($cross_platform_interop_resolved == 1),
          observed: ($cross_platform_interop_ok == true),
          stage_status: $cross_platform_interop_status,
          failure_kind: (
            if ($require_cross_platform_interop_ok != 1) then "not_required"
            elif ($cross_platform_interop_resolved != 1) then "unresolved"
            elif ($cross_platform_interop_ok == true) then "ok"
            else "false"
            end
          )
        },
        role_combination_validation_ok: {
          required: ($require_role_combination_validation_ok == 1),
          resolved: ($role_combination_validation_resolved == 1),
          observed: ($role_combination_validation_ok == true),
          stage_status: $role_combination_validation_status,
          failure_kind: (
            if ($require_role_combination_validation_ok != 1) then "not_required"
            elif ($role_combination_validation_resolved != 1) then "unresolved"
            elif ($role_combination_validation_ok == true) then "ok"
            else "false"
            end
          )
        }
      }
    }' >"$summary_tmp"
  mv -f "$summary_tmp" "$summary_json"
}

need_cmd jq
need_cmd date
need_cmd mktemp

ci_phase4_summary_json="${PHASE4_WINDOWS_FULL_PARITY_CHECK_CI_PHASE4_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase4_windows_full_parity_ci_summary.json}"
summary_json="${PHASE4_WINDOWS_FULL_PARITY_CHECK_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase4_windows_full_parity_check_summary.json}"
show_json="${PHASE4_WINDOWS_FULL_PARITY_CHECK_SHOW_JSON:-0}"
require_windows_server_packaging_ok="${PHASE4_WINDOWS_FULL_PARITY_CHECK_REQUIRE_WINDOWS_SERVER_PACKAGING_OK:-1}"
require_windows_role_runbooks_ok="${PHASE4_WINDOWS_FULL_PARITY_CHECK_REQUIRE_WINDOWS_ROLE_RUNBOOKS_OK:-1}"
require_cross_platform_interop_ok="${PHASE4_WINDOWS_FULL_PARITY_CHECK_REQUIRE_CROSS_PLATFORM_INTEROP_OK:-1}"
require_role_combination_validation_ok="${PHASE4_WINDOWS_FULL_PARITY_CHECK_REQUIRE_ROLE_COMBINATION_VALIDATION_OK:-1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ci-phase4-summary-json)
      ci_phase4_summary_json="${2:-}"
      shift 2
      ;;
    --require-windows-server-packaging-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_windows_server_packaging_ok="${2:-}"
        shift 2
      else
        require_windows_server_packaging_ok="1"
        shift
      fi
      ;;
    --require-windows-role-runbooks-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_windows_role_runbooks_ok="${2:-}"
        shift 2
      else
        require_windows_role_runbooks_ok="1"
        shift
      fi
      ;;
    --require-cross-platform-interop-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_cross_platform_interop_ok="${2:-}"
        shift 2
      else
        require_cross_platform_interop_ok="1"
        shift
      fi
      ;;
    --require-role-combination-validation-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_role_combination_validation_ok="${2:-}"
        shift 2
      else
        require_role_combination_validation_ok="1"
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

bool_arg_or_die "--require-windows-server-packaging-ok" "$require_windows_server_packaging_ok"
bool_arg_or_die "--require-windows-role-runbooks-ok" "$require_windows_role_runbooks_ok"
bool_arg_or_die "--require-cross-platform-interop-ok" "$require_cross_platform_interop_ok"
bool_arg_or_die "--require-role-combination-validation-ok" "$require_role_combination_validation_ok"
bool_arg_or_die "--show-json" "$show_json"

ci_phase4_summary_json="$(abs_path "$ci_phase4_summary_json")"
summary_json="$(abs_path "$summary_json")"

mkdir -p "$(dirname "$summary_json")"

generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ci_phase4_summary_usable="$(json_file_valid_01 "$ci_phase4_summary_json")"

declare -a reasons=()

windows_server_packaging_raw=""
windows_role_runbooks_raw=""
cross_platform_interop_raw=""
role_combination_validation_raw=""

if [[ "$ci_phase4_summary_usable" == "1" ]]; then
  windows_server_packaging_raw="$(resolve_signal_raw_or_empty "$ci_phase4_summary_json" "windows_server_packaging_ok")"
  windows_role_runbooks_raw="$(resolve_signal_raw_or_empty "$ci_phase4_summary_json" "windows_role_runbooks_ok")"
  cross_platform_interop_raw="$(resolve_signal_raw_or_empty "$ci_phase4_summary_json" "cross_platform_interop_ok")"
  role_combination_validation_raw="$(resolve_signal_raw_or_empty "$ci_phase4_summary_json" "role_combination_validation_ok")"
else
  reasons+=("ci phase4 summary file not found or invalid JSON: $ci_phase4_summary_json")
fi

windows_server_packaging_ok="$(normalize_boolish_or_empty "$windows_server_packaging_raw")"
windows_role_runbooks_ok="$(normalize_boolish_or_empty "$windows_role_runbooks_raw")"
cross_platform_interop_ok="$(normalize_boolish_or_empty "$cross_platform_interop_raw")"
role_combination_validation_ok="$(normalize_boolish_or_empty "$role_combination_validation_raw")"

if [[ -z "$windows_server_packaging_ok" ]]; then
  windows_server_packaging_ok="false"
fi
if [[ -z "$windows_role_runbooks_ok" ]]; then
  windows_role_runbooks_ok="false"
fi
if [[ -z "$cross_platform_interop_ok" ]]; then
  cross_platform_interop_ok="false"
fi
if [[ -z "$role_combination_validation_ok" ]]; then
  role_combination_validation_ok="false"
fi

windows_server_packaging_resolved="0"
windows_role_runbooks_resolved="0"
cross_platform_interop_resolved="0"
role_combination_validation_resolved="0"

windows_server_packaging_status="$(stage_status_from_raw "$windows_server_packaging_raw")"
windows_role_runbooks_status="$(stage_status_from_raw "$windows_role_runbooks_raw")"
cross_platform_interop_status="$(stage_status_from_raw "$cross_platform_interop_raw")"
role_combination_validation_status="$(stage_status_from_raw "$role_combination_validation_raw")"

if [[ -n "$(trim "$windows_server_packaging_raw")" ]]; then
  windows_server_packaging_resolved="1"
elif [[ "$ci_phase4_summary_usable" == "1" ]]; then
  reasons+=("windows_server_packaging_ok could not be resolved from ci phase4 summary")
fi
if [[ -n "$(trim "$windows_role_runbooks_raw")" ]]; then
  windows_role_runbooks_resolved="1"
elif [[ "$ci_phase4_summary_usable" == "1" ]]; then
  reasons+=("windows_role_runbooks_ok could not be resolved from ci phase4 summary")
fi
if [[ -n "$(trim "$cross_platform_interop_raw")" ]]; then
  cross_platform_interop_resolved="1"
elif [[ "$ci_phase4_summary_usable" == "1" ]]; then
  reasons+=("cross_platform_interop_ok could not be resolved from ci phase4 summary")
fi
if [[ -n "$(trim "$role_combination_validation_raw")" ]]; then
  role_combination_validation_resolved="1"
elif [[ "$ci_phase4_summary_usable" == "1" ]]; then
  reasons+=("role_combination_validation_ok could not be resolved from ci phase4 summary")
fi

if [[ "$require_windows_server_packaging_ok" == "1" && "$windows_server_packaging_resolved" == "1" && "$windows_server_packaging_ok" != "true" ]]; then
  reasons+=("windows_server_packaging_ok is false")
fi
if [[ "$require_windows_role_runbooks_ok" == "1" && "$windows_role_runbooks_resolved" == "1" && "$windows_role_runbooks_ok" != "true" ]]; then
  reasons+=("windows_role_runbooks_ok is false")
fi
if [[ "$require_cross_platform_interop_ok" == "1" && "$cross_platform_interop_resolved" == "1" && "$cross_platform_interop_ok" != "true" ]]; then
  reasons+=("cross_platform_interop_ok is false")
fi
if [[ "$require_role_combination_validation_ok" == "1" && "$role_combination_validation_resolved" == "1" && "$role_combination_validation_ok" != "true" ]]; then
  reasons+=("role_combination_validation_ok is false")
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

emit_summary_json \
  "$summary_json" \
  "$generated_at_utc" \
  "$status" \
  "$rc" \
  "$ci_phase4_summary_json" \
  "$ci_phase4_summary_usable" \
  "$show_json" \
  "$require_windows_server_packaging_ok" \
  "$require_windows_role_runbooks_ok" \
  "$require_cross_platform_interop_ok" \
  "$require_role_combination_validation_ok" \
  "$windows_server_packaging_status" \
  "$windows_role_runbooks_status" \
  "$cross_platform_interop_status" \
  "$role_combination_validation_status" \
  "$windows_server_packaging_ok" \
  "$windows_role_runbooks_ok" \
  "$cross_platform_interop_ok" \
  "$role_combination_validation_ok" \
  "$windows_server_packaging_resolved" \
  "$windows_role_runbooks_resolved" \
  "$cross_platform_interop_resolved" \
  "$role_combination_validation_resolved" \
  "$reasons_json"

if [[ "$show_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$status" == "pass" ]]; then
  exit 0
fi
exit 1
