#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase4_windows_full_parity_handoff_check.sh \
    [--phase4-run-summary-json PATH] \
    [--roadmap-summary-json PATH] \
    [--require-run-pipeline-ok [0|1]] \
    [--require-windows-server-packaging-ok [0|1]] \
    [--require-windows-native-bootstrap-guardrails-ok [0|1]] \
    [--require-windows-role-runbooks-ok [0|1]] \
    [--require-cross-platform-interop-ok [0|1]] \
    [--require-role-combination-validation-ok [0|1]] \
    [--summary-json PATH] \
    [--show-json [0|1]]

Purpose:
  Fail-closed checker for the Phase-4 Windows full-parity handoff.
  Evaluates the run pipeline and handoff readiness booleans.

Notes:
  - The checker prefers readiness booleans from the roadmap summary at:
      .vpn_track.phase4_windows_full_parity_handoff.*
  - If needed, it falls back to the nested check summary referenced by the
    run artifacts.
  - run_pipeline_ok is true only when the run summary contract is valid and
    both run steps pass with valid contracts.
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

resolve_run_pipeline() {
  local run_summary_json="$1"
  local run_summary_usable="$2"
  local value="null"
  local status="missing"
  local source="unresolved"
  local resolved="0"
  local contract_valid="0"

  if [[ "$run_summary_usable" != "1" ]]; then
    printf '%s|%s|%s|%s|%s\n' "$value" "$status" "$source" "$resolved" "$contract_valid"
    return
  fi

  if jq -e '
    type == "object"
    and (.version // 0) == 1
    and (.schema | type) == "object"
    and (.schema.id // "") == "phase4_windows_full_parity_run_summary"
    and ((.status | type) == "string")
    and ((.rc | type) == "number")
    and ((.steps.ci_phase4_windows_full_parity.status | type) == "string")
    and ((.steps.ci_phase4_windows_full_parity.rc | type) == "number")
    and ((.steps.ci_phase4_windows_full_parity.command_rc | type) == "number")
    and ((.steps.ci_phase4_windows_full_parity.contract_valid | type) == "boolean")
    and ((.steps.phase4_windows_full_parity_check.status | type) == "string")
    and ((.steps.phase4_windows_full_parity_check.rc | type) == "number")
    and ((.steps.phase4_windows_full_parity_check.command_rc | type) == "number")
    and ((.steps.phase4_windows_full_parity_check.contract_valid | type) == "boolean")
  ' "$run_summary_json" >/dev/null 2>&1; then
    contract_valid="1"
  fi

  local ci_status=""
  local ci_contract_valid="0"
  local check_status=""
  local check_contract_valid="0"
  ci_status="$(json_text_or_empty "$run_summary_json" '.steps.ci_phase4_windows_full_parity.status')"
  check_status="$(json_text_or_empty "$run_summary_json" '.steps.phase4_windows_full_parity_check.status')"
  if [[ "$(json_bool_or_empty "$run_summary_json" '.steps.ci_phase4_windows_full_parity.contract_valid')" == "true" ]]; then
    ci_contract_valid="1"
  fi
  if [[ "$(json_bool_or_empty "$run_summary_json" '.steps.phase4_windows_full_parity_check.contract_valid')" == "true" ]]; then
    check_contract_valid="1"
  fi

  if [[ "$contract_valid" != "1" ]]; then
    value="false"
    status="invalid"
    source="phase4_run_summary.contract"
    resolved="1"
  elif [[ "$ci_status" != "pass" || "$ci_contract_valid" != "1" ]]; then
    value="false"
    status="fail"
    source="phase4_run_summary.steps.ci_phase4_windows_full_parity"
    resolved="1"
  elif [[ "$check_status" != "pass" || "$check_contract_valid" != "1" ]]; then
    value="false"
    status="fail"
    source="phase4_run_summary.steps.phase4_windows_full_parity_check"
    resolved="1"
  else
    value="true"
    status="pass"
    source="phase4_run_summary"
    resolved="1"
  fi

  printf '%s|%s|%s|%s|%s\n' "$value" "$status" "$source" "$resolved" "$contract_valid"
}

resolve_handoff_bool() {
  local signal="$1"
  local roadmap_summary_json="$2"
  local roadmap_summary_usable="$3"
  local run_summary_json="$4"
  local run_summary_usable="$5"

  local value="null"
  local status="missing"
  local source="unresolved"
  local resolved="0"

  if [[ "$roadmap_summary_usable" == "1" ]]; then
    if [[ "$signal" == "windows_native_bootstrap_guardrails_ok" ]]; then
      value="$(json_bool_or_empty "$roadmap_summary_json" 'if (.vpn_track.phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok | type) == "boolean" then .vpn_track.phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok elif (.vpn_track.phase4_windows_full_parity_handoff.windows_server_packaging_ok | type) == "boolean" then .vpn_track.phase4_windows_full_parity_handoff.windows_server_packaging_ok elif (.phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok | type) == "boolean" then .phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok elif (.phase4_windows_full_parity_handoff.windows_server_packaging_ok | type) == "boolean" then .phase4_windows_full_parity_handoff.windows_server_packaging_ok else empty end')"
    else
      value="$(json_bool_or_empty "$roadmap_summary_json" "if (.vpn_track.phase4_windows_full_parity_handoff.$signal | type) == \"boolean\" then .vpn_track.phase4_windows_full_parity_handoff.$signal elif (.phase4_windows_full_parity_handoff.$signal | type) == \"boolean\" then .phase4_windows_full_parity_handoff.$signal else empty end")"
    fi
    if [[ -n "$value" ]]; then
      status="$( [[ "$value" == "true" ]] && printf '%s' "pass" || printf '%s' "fail" )"
      if [[ "$signal" == "windows_native_bootstrap_guardrails_ok" ]]; then
        source="roadmap_progress_summary.vpn_track.phase4_windows_full_parity_handoff.windows_server_packaging_ok"
      else
        source="roadmap_progress_summary.vpn_track.phase4_windows_full_parity_handoff.$signal"
      fi
      resolved="1"
      printf '%s|%s|%s|%s\n' "$value" "$status" "$source" "$resolved"
      return
    fi
  fi

  if [[ "$run_summary_usable" == "1" ]]; then
    local check_summary_json=""
    check_summary_json="$(json_text_or_empty "$run_summary_json" '.steps.phase4_windows_full_parity_check.artifacts.summary_json // .artifacts.check_summary_json')"
    if [[ -n "$check_summary_json" ]]; then
      check_summary_json="$(resolve_path_with_base "$check_summary_json" "$run_summary_json")"
      if [[ "$(json_file_valid_01 "$check_summary_json")" == "1" ]]; then
        if [[ "$signal" == "windows_native_bootstrap_guardrails_ok" ]]; then
          value="$(json_bool_or_empty "$check_summary_json" 'if (.signals.windows_native_bootstrap_guardrails_ok | type) == "boolean" then .signals.windows_native_bootstrap_guardrails_ok elif (.signals.windows_server_packaging_ok | type) == "boolean" then .signals.windows_server_packaging_ok elif (.handoff.windows_native_bootstrap_guardrails_ok | type) == "boolean" then .handoff.windows_native_bootstrap_guardrails_ok elif (.handoff.windows_server_packaging_ok | type) == "boolean" then .handoff.windows_server_packaging_ok elif (.phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok | type) == "boolean" then .phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok elif (.phase4_windows_full_parity_handoff.windows_server_packaging_ok | type) == "boolean" then .phase4_windows_full_parity_handoff.windows_server_packaging_ok elif (.vpn_track.phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok | type) == "boolean" then .vpn_track.phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok elif (.vpn_track.phase4_windows_full_parity_handoff.windows_server_packaging_ok | type) == "boolean" then .vpn_track.phase4_windows_full_parity_handoff.windows_server_packaging_ok else empty end')"
        else
          value="$(json_bool_or_empty "$check_summary_json" "if (.signals.$signal | type) == \"boolean\" then .signals.$signal elif (.handoff.$signal | type) == \"boolean\" then .handoff.$signal elif (.phase4_windows_full_parity_handoff.$signal | type) == \"boolean\" then .phase4_windows_full_parity_handoff.$signal elif (.vpn_track.phase4_windows_full_parity_handoff.$signal | type) == \"boolean\" then .vpn_track.phase4_windows_full_parity_handoff.$signal else empty end")"
        fi
        if [[ -n "$value" ]]; then
          status="$( [[ "$value" == "true" ]] && printf '%s' "pass" || printf '%s' "fail" )"
          if [[ "$signal" == "windows_native_bootstrap_guardrails_ok" ]]; then
            source="phase4_windows_full_parity_check_summary.windows_server_packaging_ok"
          else
            source="phase4_windows_full_parity_check_summary.$signal"
          fi
          resolved="1"
          printf '%s|%s|%s|%s\n' "$value" "$status" "$source" "$resolved"
          return
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
  local phase4_run_summary_json="$5"
  local roadmap_summary_json="$6"
  local run_summary_usable="$7"
  local roadmap_summary_usable="$8"
  local show_json="$9"
  local require_run_pipeline_ok="${10}"
  local require_windows_server_packaging_ok="${11}"
  local require_windows_native_bootstrap_guardrails_ok="${12}"
  local require_windows_role_runbooks_ok="${13}"
  local require_cross_platform_interop_ok="${14}"
  local require_role_combination_validation_ok="${15}"
  local run_pipeline_status="${16}"
  local run_pipeline_ok="${17}"
  local run_pipeline_resolved="${18}"
  local run_pipeline_source="${19}"
  local run_pipeline_contract_valid="${20}"
  local windows_server_packaging_status="${21}"
  local windows_native_bootstrap_guardrails_status="${22}"
  local windows_role_runbooks_status="${23}"
  local cross_platform_interop_status="${24}"
  local role_combination_validation_status="${25}"
  local windows_server_packaging_ok="${26}"
  local windows_native_bootstrap_guardrails_ok="${27}"
  local windows_role_runbooks_ok="${28}"
  local cross_platform_interop_ok="${29}"
  local role_combination_validation_ok="${30}"
  local windows_server_packaging_resolved="${31}"
  local windows_native_bootstrap_guardrails_resolved="${32}"
  local windows_role_runbooks_resolved="${33}"
  local cross_platform_interop_resolved="${34}"
  local role_combination_validation_resolved="${35}"
  local windows_server_packaging_source="${36}"
  local windows_native_bootstrap_guardrails_source="${37}"
  local windows_role_runbooks_source="${38}"
  local cross_platform_interop_source="${39}"
  local role_combination_validation_source="${40}"
  local reasons_json="${41}"

  local summary_tmp
  summary_tmp="$(mktemp)"
  jq -n \
    --arg generated_at_utc "$generated_at_utc" \
    --arg status "$status" \
    --argjson rc "$rc" \
    --arg summary_json "$summary_json" \
    --arg phase4_run_summary_json "$phase4_run_summary_json" \
    --arg roadmap_summary_json "$roadmap_summary_json" \
    --argjson run_summary_usable "$run_summary_usable" \
    --argjson roadmap_summary_usable "$roadmap_summary_usable" \
    --arg show_json "$show_json" \
    --argjson require_run_pipeline_ok "$require_run_pipeline_ok" \
    --argjson require_windows_server_packaging_ok "$require_windows_server_packaging_ok" \
    --argjson require_windows_native_bootstrap_guardrails_ok "$require_windows_native_bootstrap_guardrails_ok" \
    --argjson require_windows_role_runbooks_ok "$require_windows_role_runbooks_ok" \
    --argjson require_cross_platform_interop_ok "$require_cross_platform_interop_ok" \
    --argjson require_role_combination_validation_ok "$require_role_combination_validation_ok" \
    --arg run_pipeline_status "$run_pipeline_status" \
    --argjson run_pipeline_ok "$run_pipeline_ok" \
    --argjson run_pipeline_resolved "$run_pipeline_resolved" \
    --arg run_pipeline_source "$run_pipeline_source" \
    --argjson run_pipeline_contract_valid "$run_pipeline_contract_valid" \
    --arg windows_server_packaging_status "$windows_server_packaging_status" \
    --arg windows_native_bootstrap_guardrails_status "$windows_native_bootstrap_guardrails_status" \
    --arg windows_role_runbooks_status "$windows_role_runbooks_status" \
    --arg cross_platform_interop_status "$cross_platform_interop_status" \
    --arg role_combination_validation_status "$role_combination_validation_status" \
    --argjson windows_server_packaging_ok "$windows_server_packaging_ok" \
    --argjson windows_native_bootstrap_guardrails_ok "$windows_native_bootstrap_guardrails_ok" \
    --argjson windows_role_runbooks_ok "$windows_role_runbooks_ok" \
    --argjson cross_platform_interop_ok "$cross_platform_interop_ok" \
    --argjson role_combination_validation_ok "$role_combination_validation_ok" \
    --argjson windows_server_packaging_resolved "$windows_server_packaging_resolved" \
    --argjson windows_native_bootstrap_guardrails_resolved "$windows_native_bootstrap_guardrails_resolved" \
    --argjson windows_role_runbooks_resolved "$windows_role_runbooks_resolved" \
    --argjson cross_platform_interop_resolved "$cross_platform_interop_resolved" \
    --argjson role_combination_validation_resolved "$role_combination_validation_resolved" \
    --arg windows_server_packaging_source "$windows_server_packaging_source" \
    --arg windows_native_bootstrap_guardrails_source "$windows_native_bootstrap_guardrails_source" \
    --arg windows_role_runbooks_source "$windows_role_runbooks_source" \
    --arg cross_platform_interop_source "$cross_platform_interop_source" \
    --arg role_combination_validation_source "$role_combination_validation_source" \
    --argjson reasons "$reasons_json" \
    '
      def actionable_gate($id; $signal; $enabled; $ok; $resolved; $status):
        {
          id: $id,
          signal: $signal,
          required: $enabled,
          ok: $ok,
          resolved: $resolved,
          status: $status,
          failure_kind: (
            if ($enabled | not) then "not_required"
            elif $ok == true then "ok"
            elif $resolved == false then "unresolved"
            else "false"
            end
          ),
          reason: (
            if ($enabled | not) then "not_required"
            elif $ok == true then "pass"
            elif $resolved == false then "required_signal_unresolved"
            else "required_signal_false"
            end
          )
        };
      {
      version: 1,
      schema: {
        id: "phase4_windows_full_parity_handoff_check_summary",
        major: 1,
        minor: 0
      },
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $rc,
      fail_closed: true,
      metadata: {
        contract: "phase4-windows-full-parity",
        script: "phase4_windows_full_parity_handoff_check.sh"
      },
      inputs: {
        phase4_run_summary_json: (if $phase4_run_summary_json == "" then null else $phase4_run_summary_json end),
        roadmap_summary_json: (if $roadmap_summary_json == "" then null else $roadmap_summary_json end),
        show_json: ($show_json == "1"),
        requirements: {
          run_pipeline_ok: ($require_run_pipeline_ok == 1),
          windows_server_packaging_ok: ($require_windows_server_packaging_ok == 1),
          windows_native_bootstrap_guardrails_ok: ($require_windows_native_bootstrap_guardrails_ok == 1),
          windows_role_runbooks_ok: ($require_windows_role_runbooks_ok == 1),
          cross_platform_interop_ok: ($require_cross_platform_interop_ok == 1),
          role_combination_validation_ok: ($require_role_combination_validation_ok == 1)
        },
        usable: {
          phase4_run_summary_json: ($run_summary_usable == 1),
          roadmap_summary_json: ($roadmap_summary_usable == 1)
        }
      },
      handoff: {
        run_pipeline_ok: $run_pipeline_ok,
        run_pipeline_status: $run_pipeline_status,
        run_pipeline_resolved: ($run_pipeline_resolved == 1),
        run_pipeline_contract_valid: ($run_pipeline_contract_valid == 1),
        windows_server_packaging_ok: $windows_server_packaging_ok,
        windows_server_packaging_status: $windows_server_packaging_status,
        windows_server_packaging_resolved: ($windows_server_packaging_resolved == 1),
        windows_native_bootstrap_guardrails_ok: $windows_native_bootstrap_guardrails_ok,
        windows_native_bootstrap_guardrails_status: $windows_native_bootstrap_guardrails_status,
        windows_native_bootstrap_guardrails_resolved: ($windows_native_bootstrap_guardrails_resolved == 1),
        windows_role_runbooks_ok: $windows_role_runbooks_ok,
        windows_role_runbooks_status: $windows_role_runbooks_status,
        windows_role_runbooks_resolved: ($windows_role_runbooks_resolved == 1),
        cross_platform_interop_ok: $cross_platform_interop_ok,
        cross_platform_interop_status: $cross_platform_interop_status,
        cross_platform_interop_resolved: ($cross_platform_interop_resolved == 1),
        role_combination_validation_ok: $role_combination_validation_ok,
        role_combination_validation_status: $role_combination_validation_status,
        role_combination_validation_resolved: ($role_combination_validation_resolved == 1),
        sources: {
          run_pipeline_ok: $run_pipeline_source,
          windows_server_packaging_ok: $windows_server_packaging_source,
          windows_native_bootstrap_guardrails_ok: $windows_native_bootstrap_guardrails_source,
          windows_role_runbooks_ok: $windows_role_runbooks_source,
          cross_platform_interop_ok: $cross_platform_interop_source,
          role_combination_validation_ok: $role_combination_validation_source
        }
      },
      decision: {
        pass: ($status == "pass"),
        reasons: $reasons,
        reason_codes: [
          (if ($phase4_run_summary_json != "" and $run_summary_usable != 1) then "phase4_run_summary_unusable" else empty end),
          (if ($roadmap_summary_json != "" and $roadmap_summary_usable != 1) then "roadmap_summary_unusable" else empty end),
          (if ($require_run_pipeline_ok == 1 and $run_pipeline_resolved != 1) then "run_pipeline_ok_unresolved"
           elif ($require_run_pipeline_ok == 1 and $run_pipeline_status == "invalid") then "run_pipeline_contract_invalid"
           elif ($require_run_pipeline_ok == 1 and $run_pipeline_ok != true) then "run_pipeline_ok_false"
           else empty end),
          (if ($require_windows_server_packaging_ok == 1 and $windows_server_packaging_resolved != 1) then "windows_server_packaging_ok_unresolved"
           elif ($require_windows_server_packaging_ok == 1 and $windows_server_packaging_ok != true) then "windows_server_packaging_ok_false"
           else empty end),
          (if ($require_windows_native_bootstrap_guardrails_ok == 1 and $windows_native_bootstrap_guardrails_resolved != 1) then "windows_native_bootstrap_guardrails_ok_unresolved"
           elif ($require_windows_native_bootstrap_guardrails_ok == 1 and $windows_native_bootstrap_guardrails_ok != true) then "windows_native_bootstrap_guardrails_ok_false"
           else empty end),
          (if ($require_windows_role_runbooks_ok == 1 and $windows_role_runbooks_resolved != 1) then "windows_role_runbooks_ok_unresolved"
           elif ($require_windows_role_runbooks_ok == 1 and $windows_role_runbooks_ok != true) then "windows_role_runbooks_ok_false"
           else empty end),
          (if ($require_cross_platform_interop_ok == 1 and $cross_platform_interop_resolved != 1) then "cross_platform_interop_ok_unresolved"
           elif ($require_cross_platform_interop_ok == 1 and $cross_platform_interop_ok != true) then "cross_platform_interop_ok_false"
           else empty end),
          (if ($require_role_combination_validation_ok == 1 and $role_combination_validation_resolved != 1) then "role_combination_validation_ok_unresolved"
           elif ($require_role_combination_validation_ok == 1 and $role_combination_validation_ok != true) then "role_combination_validation_ok_false"
           else empty end)
        ],
        reason_details: [
          (if ($phase4_run_summary_json != "" and $run_summary_usable != 1) then {
            code: "phase4_run_summary_unusable",
            signal: "run_pipeline_ok",
            kind: "unresolved",
            source: "inputs.phase4_run_summary_json",
            required: true,
            resolved: false,
            observed: null,
            stage_status: "missing"
          } else empty end),
          (if ($roadmap_summary_json != "" and $roadmap_summary_usable != 1) then {
            code: "roadmap_summary_unusable",
            signal: null,
            kind: "unresolved",
            source: "inputs.roadmap_summary_json",
            required: false,
            resolved: false,
            observed: null,
            stage_status: "missing"
          } else empty end),
          (if ($require_run_pipeline_ok == 1 and $run_pipeline_resolved != 1) then {
            code: "run_pipeline_ok_unresolved",
            signal: "run_pipeline_ok",
            kind: "unresolved",
            source: $run_pipeline_source,
            required: true,
            resolved: false,
            observed: $run_pipeline_ok,
            stage_status: $run_pipeline_status
          } elif ($require_run_pipeline_ok == 1 and $run_pipeline_status == "invalid") then {
            code: "run_pipeline_contract_invalid",
            signal: "run_pipeline_ok",
            kind: "invalid_contract",
            source: $run_pipeline_source,
            required: true,
            resolved: true,
            observed: false,
            stage_status: $run_pipeline_status
          } elif ($require_run_pipeline_ok == 1 and $run_pipeline_ok != true) then {
            code: "run_pipeline_ok_false",
            signal: "run_pipeline_ok",
            kind: "false",
            source: $run_pipeline_source,
            required: true,
            resolved: ($run_pipeline_resolved == 1),
            observed: false,
            stage_status: $run_pipeline_status
          } else empty end),
          (if ($require_windows_server_packaging_ok == 1 and $windows_server_packaging_resolved != 1) then {
            code: "windows_server_packaging_ok_unresolved",
            signal: "windows_server_packaging_ok",
            kind: "unresolved",
            source: $windows_server_packaging_source,
            required: true,
            resolved: false,
            observed: $windows_server_packaging_ok,
            stage_status: $windows_server_packaging_status
          } elif ($require_windows_server_packaging_ok == 1 and $windows_server_packaging_ok != true) then {
            code: "windows_server_packaging_ok_false",
            signal: "windows_server_packaging_ok",
            kind: "false",
            source: $windows_server_packaging_source,
            required: true,
            resolved: true,
            observed: false,
            stage_status: $windows_server_packaging_status
          } else empty end),
          (if ($require_windows_native_bootstrap_guardrails_ok == 1 and $windows_native_bootstrap_guardrails_resolved != 1) then {
            code: "windows_native_bootstrap_guardrails_ok_unresolved",
            signal: "windows_native_bootstrap_guardrails_ok",
            kind: "unresolved",
            source: $windows_native_bootstrap_guardrails_source,
            required: true,
            resolved: false,
            observed: $windows_native_bootstrap_guardrails_ok,
            stage_status: $windows_native_bootstrap_guardrails_status
          } elif ($require_windows_native_bootstrap_guardrails_ok == 1 and $windows_native_bootstrap_guardrails_ok != true) then {
            code: "windows_native_bootstrap_guardrails_ok_false",
            signal: "windows_native_bootstrap_guardrails_ok",
            kind: "false",
            source: $windows_native_bootstrap_guardrails_source,
            required: true,
            resolved: true,
            observed: false,
            stage_status: $windows_native_bootstrap_guardrails_status
          } else empty end),
          (if ($require_windows_role_runbooks_ok == 1 and $windows_role_runbooks_resolved != 1) then {
            code: "windows_role_runbooks_ok_unresolved",
            signal: "windows_role_runbooks_ok",
            kind: "unresolved",
            source: $windows_role_runbooks_source,
            required: true,
            resolved: false,
            observed: $windows_role_runbooks_ok,
            stage_status: $windows_role_runbooks_status
          } elif ($require_windows_role_runbooks_ok == 1 and $windows_role_runbooks_ok != true) then {
            code: "windows_role_runbooks_ok_false",
            signal: "windows_role_runbooks_ok",
            kind: "false",
            source: $windows_role_runbooks_source,
            required: true,
            resolved: true,
            observed: false,
            stage_status: $windows_role_runbooks_status
          } else empty end),
          (if ($require_cross_platform_interop_ok == 1 and $cross_platform_interop_resolved != 1) then {
            code: "cross_platform_interop_ok_unresolved",
            signal: "cross_platform_interop_ok",
            kind: "unresolved",
            source: $cross_platform_interop_source,
            required: true,
            resolved: false,
            observed: $cross_platform_interop_ok,
            stage_status: $cross_platform_interop_status
          } elif ($require_cross_platform_interop_ok == 1 and $cross_platform_interop_ok != true) then {
            code: "cross_platform_interop_ok_false",
            signal: "cross_platform_interop_ok",
            kind: "false",
            source: $cross_platform_interop_source,
            required: true,
            resolved: true,
            observed: false,
            stage_status: $cross_platform_interop_status
          } else empty end),
          (if ($require_role_combination_validation_ok == 1 and $role_combination_validation_resolved != 1) then {
            code: "role_combination_validation_ok_unresolved",
            signal: "role_combination_validation_ok",
            kind: "unresolved",
            source: $role_combination_validation_source,
            required: true,
            resolved: false,
            observed: $role_combination_validation_ok,
            stage_status: $role_combination_validation_status
          } elif ($require_role_combination_validation_ok == 1 and $role_combination_validation_ok != true) then {
            code: "role_combination_validation_ok_false",
            signal: "role_combination_validation_ok",
            kind: "false",
            source: $role_combination_validation_source,
            required: true,
            resolved: true,
            observed: false,
            stage_status: $role_combination_validation_status
          } else empty end)
        ],
        actionable: (
          [
            actionable_gate("phase4_windows_full_parity_run_pipeline_gate"; "run_pipeline_ok"; ($require_run_pipeline_ok == 1); ($run_pipeline_ok == true); ($run_pipeline_resolved == 1); $run_pipeline_status),
            actionable_gate("phase4_windows_full_parity_windows_server_packaging_gate"; "windows_server_packaging_ok"; ($require_windows_server_packaging_ok == 1); ($windows_server_packaging_ok == true); ($windows_server_packaging_resolved == 1); $windows_server_packaging_status),
            actionable_gate("phase4_windows_full_parity_windows_native_bootstrap_guardrails_gate"; "windows_native_bootstrap_guardrails_ok"; ($require_windows_native_bootstrap_guardrails_ok == 1); ($windows_native_bootstrap_guardrails_ok == true); ($windows_native_bootstrap_guardrails_resolved == 1); $windows_native_bootstrap_guardrails_status),
            actionable_gate("phase4_windows_full_parity_windows_role_runbooks_gate"; "windows_role_runbooks_ok"; ($require_windows_role_runbooks_ok == 1); ($windows_role_runbooks_ok == true); ($windows_role_runbooks_resolved == 1); $windows_role_runbooks_status),
            actionable_gate("phase4_windows_full_parity_cross_platform_interop_gate"; "cross_platform_interop_ok"; ($require_cross_platform_interop_ok == 1); ($cross_platform_interop_ok == true); ($cross_platform_interop_resolved == 1); $cross_platform_interop_status),
            actionable_gate("phase4_windows_full_parity_role_combination_validation_gate"; "role_combination_validation_ok"; ($require_role_combination_validation_ok == 1); ($role_combination_validation_ok == true); ($role_combination_validation_resolved == 1); $role_combination_validation_status)
          ] as $all_gates
          | ($all_gates | map(select(.required == true and .ok != true))) as $failed_required
          | {
              count: ($failed_required | length),
              recommended_gate_id: ($failed_required[0].id // null),
              gates: $failed_required
            }
        ),
        failure_kind: (if $status == "pass" then "none" else "policy_no_go" end),
        warnings: []
      },
      failure: {
        kind: (if $status == "pass" then "none" else "policy_no_go" end),
        policy_no_go: ($status != "pass"),
        execution_failure: false
      },
      handoff_semantics: {
        run_pipeline_ok: {
          required: ($require_run_pipeline_ok == 1),
          resolved: ($run_pipeline_resolved == 1),
          observed: $run_pipeline_ok,
          status: $run_pipeline_status,
          source: $run_pipeline_source,
          contract_valid: ($run_pipeline_contract_valid == 1),
          failure_kind: (
            if ($require_run_pipeline_ok != 1) then "not_required"
            elif ($run_pipeline_resolved != 1) then "unresolved"
            elif ($run_pipeline_status == "invalid") then "invalid_contract"
            elif ($run_pipeline_ok == true) then "ok"
            else "false"
            end
          )
        },
        windows_server_packaging_ok: {
          required: ($require_windows_server_packaging_ok == 1),
          resolved: ($windows_server_packaging_resolved == 1),
          observed: $windows_server_packaging_ok,
          status: $windows_server_packaging_status,
          source: $windows_server_packaging_source,
          failure_kind: (
            if ($require_windows_server_packaging_ok != 1) then "not_required"
            elif ($windows_server_packaging_resolved != 1) then "unresolved"
            elif ($windows_server_packaging_ok == true) then "ok"
            else "false"
            end
          )
        },
        windows_native_bootstrap_guardrails_ok: {
          required: ($require_windows_native_bootstrap_guardrails_ok == 1),
          resolved: ($windows_native_bootstrap_guardrails_resolved == 1),
          observed: $windows_native_bootstrap_guardrails_ok,
          status: $windows_native_bootstrap_guardrails_status,
          source: $windows_native_bootstrap_guardrails_source,
          failure_kind: (
            if ($require_windows_native_bootstrap_guardrails_ok != 1) then "not_required"
            elif ($windows_native_bootstrap_guardrails_resolved != 1) then "unresolved"
            elif ($windows_native_bootstrap_guardrails_ok == true) then "ok"
            else "false"
            end
          )
        },
        windows_role_runbooks_ok: {
          required: ($require_windows_role_runbooks_ok == 1),
          resolved: ($windows_role_runbooks_resolved == 1),
          observed: $windows_role_runbooks_ok,
          status: $windows_role_runbooks_status,
          source: $windows_role_runbooks_source,
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
          observed: $cross_platform_interop_ok,
          status: $cross_platform_interop_status,
          source: $cross_platform_interop_source,
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
          observed: $role_combination_validation_ok,
          status: $role_combination_validation_status,
          source: $role_combination_validation_source,
          failure_kind: (
            if ($require_role_combination_validation_ok != 1) then "not_required"
            elif ($role_combination_validation_resolved != 1) then "unresolved"
            elif ($role_combination_validation_ok == true) then "ok"
            else "false"
            end
          )
        }
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

phase4_run_summary_json="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_CHECK_PHASE4_RUN_SUMMARY_JSON:-}"
roadmap_summary_json="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_CHECK_ROADMAP_SUMMARY_JSON:-}"
summary_json="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_CHECK_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase4_windows_full_parity_handoff_check_summary.json}"
show_json="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_CHECK_SHOW_JSON:-0}"
require_run_pipeline_ok="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_CHECK_REQUIRE_RUN_PIPELINE_OK:-1}"
require_windows_server_packaging_ok="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_CHECK_REQUIRE_WINDOWS_SERVER_PACKAGING_OK:-1}"
require_windows_native_bootstrap_guardrails_ok="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_CHECK_REQUIRE_WINDOWS_NATIVE_BOOTSTRAP_GUARDRAILS_OK:-1}"
require_windows_role_runbooks_ok="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_CHECK_REQUIRE_WINDOWS_ROLE_RUNBOOKS_OK:-1}"
require_cross_platform_interop_ok="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_CHECK_REQUIRE_CROSS_PLATFORM_INTEROP_OK:-1}"
require_role_combination_validation_ok="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_CHECK_REQUIRE_ROLE_COMBINATION_VALIDATION_OK:-1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --phase4-run-summary-json)
      phase4_run_summary_json="${2:-}"
      shift 2
      ;;
    --roadmap-summary-json)
      roadmap_summary_json="${2:-}"
      shift 2
      ;;
    --require-run-pipeline-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_run_pipeline_ok="${2:-}"
        shift 2
      else
        require_run_pipeline_ok="1"
        shift
      fi
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
    --require-windows-native-bootstrap-guardrails-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_windows_native_bootstrap_guardrails_ok="${2:-}"
        shift 2
      else
        require_windows_native_bootstrap_guardrails_ok="1"
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

bool_arg_or_die "--require-run-pipeline-ok" "$require_run_pipeline_ok"
bool_arg_or_die "--require-windows-server-packaging-ok" "$require_windows_server_packaging_ok"
bool_arg_or_die "--require-windows-native-bootstrap-guardrails-ok" "$require_windows_native_bootstrap_guardrails_ok"
bool_arg_or_die "--require-windows-role-runbooks-ok" "$require_windows_role_runbooks_ok"
bool_arg_or_die "--require-cross-platform-interop-ok" "$require_cross_platform_interop_ok"
bool_arg_or_die "--require-role-combination-validation-ok" "$require_role_combination_validation_ok"
bool_arg_or_die "--show-json" "$show_json"

phase4_run_summary_json="$(abs_path "$phase4_run_summary_json")"
roadmap_summary_json="$(abs_path "$roadmap_summary_json")"
summary_json="$(abs_path "$summary_json")"

mkdir -p "$(dirname "$summary_json")"

generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

declare -a reasons=()

phase4_run_summary_usable="0"
roadmap_summary_usable="0"
run_pipeline_contract_valid="0"
run_pipeline_value="null"
run_pipeline_status="missing"
run_pipeline_resolved="0"
run_pipeline_source="unresolved"

if [[ -n "$phase4_run_summary_json" ]]; then
  if [[ "$(json_file_valid_01 "$phase4_run_summary_json")" == "1" ]]; then
    phase4_run_summary_usable="1"
  else
    reasons+=("phase4 run summary file not found or invalid JSON: $phase4_run_summary_json")
  fi
fi

if [[ -n "$roadmap_summary_json" ]]; then
  if [[ "$(json_file_valid_01 "$roadmap_summary_json")" == "1" ]]; then
    roadmap_summary_usable="1"
  else
    reasons+=("roadmap summary file not found or invalid JSON: $roadmap_summary_json")
  fi
fi

if [[ "$phase4_run_summary_usable" == "1" ]]; then
  run_pipeline_pair="$(resolve_run_pipeline "$phase4_run_summary_json" "$phase4_run_summary_usable")"
  run_pipeline_value="${run_pipeline_pair%%|*}"
  run_pipeline_pair="${run_pipeline_pair#*|}"
  run_pipeline_status="${run_pipeline_pair%%|*}"
  run_pipeline_pair="${run_pipeline_pair#*|}"
  run_pipeline_source="${run_pipeline_pair%%|*}"
  run_pipeline_pair="${run_pipeline_pair#*|}"
  run_pipeline_resolved="${run_pipeline_pair%%|*}"
  run_pipeline_contract_valid="${run_pipeline_pair##*|}"
  if [[ "$run_pipeline_status" == "invalid" ]]; then
    reasons+=("phase4 run summary contract is invalid")
  elif [[ "$run_pipeline_status" == "fail" ]]; then
    reasons+=("run pipeline is not ready")
  fi
else
  reasons+=("phase4 run summary is unavailable")
fi

windows_server_packaging_pair="$(resolve_handoff_bool "windows_server_packaging_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase4_run_summary_json" "$phase4_run_summary_usable")"
windows_native_bootstrap_guardrails_pair="$(resolve_handoff_bool "windows_native_bootstrap_guardrails_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase4_run_summary_json" "$phase4_run_summary_usable")"
windows_role_runbooks_pair="$(resolve_handoff_bool "windows_role_runbooks_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase4_run_summary_json" "$phase4_run_summary_usable")"
cross_platform_interop_pair="$(resolve_handoff_bool "cross_platform_interop_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase4_run_summary_json" "$phase4_run_summary_usable")"
role_combination_validation_pair="$(resolve_handoff_bool "role_combination_validation_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase4_run_summary_json" "$phase4_run_summary_usable")"

windows_server_packaging_ok="${windows_server_packaging_pair%%|*}"
windows_server_packaging_pair="${windows_server_packaging_pair#*|}"
windows_server_packaging_status="${windows_server_packaging_pair%%|*}"
windows_server_packaging_pair="${windows_server_packaging_pair#*|}"
windows_server_packaging_source="${windows_server_packaging_pair%%|*}"
windows_server_packaging_resolved="${windows_server_packaging_pair##*|}"

windows_native_bootstrap_guardrails_ok="${windows_native_bootstrap_guardrails_pair%%|*}"
windows_native_bootstrap_guardrails_pair="${windows_native_bootstrap_guardrails_pair#*|}"
windows_native_bootstrap_guardrails_status="${windows_native_bootstrap_guardrails_pair%%|*}"
windows_native_bootstrap_guardrails_pair="${windows_native_bootstrap_guardrails_pair#*|}"
windows_native_bootstrap_guardrails_source="${windows_native_bootstrap_guardrails_pair%%|*}"
windows_native_bootstrap_guardrails_resolved="${windows_native_bootstrap_guardrails_pair##*|}"

windows_role_runbooks_ok="${windows_role_runbooks_pair%%|*}"
windows_role_runbooks_pair="${windows_role_runbooks_pair#*|}"
windows_role_runbooks_status="${windows_role_runbooks_pair%%|*}"
windows_role_runbooks_pair="${windows_role_runbooks_pair#*|}"
windows_role_runbooks_source="${windows_role_runbooks_pair%%|*}"
windows_role_runbooks_resolved="${windows_role_runbooks_pair##*|}"

cross_platform_interop_ok="${cross_platform_interop_pair%%|*}"
cross_platform_interop_pair="${cross_platform_interop_pair#*|}"
cross_platform_interop_status="${cross_platform_interop_pair%%|*}"
cross_platform_interop_pair="${cross_platform_interop_pair#*|}"
cross_platform_interop_source="${cross_platform_interop_pair%%|*}"
cross_platform_interop_resolved="${cross_platform_interop_pair##*|}"

role_combination_validation_ok="${role_combination_validation_pair%%|*}"
role_combination_validation_pair="${role_combination_validation_pair#*|}"
role_combination_validation_status="${role_combination_validation_pair%%|*}"
role_combination_validation_pair="${role_combination_validation_pair#*|}"
role_combination_validation_source="${role_combination_validation_pair%%|*}"
role_combination_validation_resolved="${role_combination_validation_pair##*|}"

if [[ "$require_run_pipeline_ok" == "1" && "$run_pipeline_value" != "true" ]]; then
  if [[ "$run_pipeline_status" == "missing" ]]; then
    reasons+=("run_pipeline_ok unresolved from provided artifacts")
  else
    reasons+=("run_pipeline_ok is false")
  fi
fi
if [[ "$require_windows_server_packaging_ok" == "1" && "$windows_server_packaging_ok" != "true" ]]; then
  if [[ "$windows_server_packaging_status" == "missing" ]]; then
    reasons+=("windows_server_packaging_ok unresolved from provided artifacts")
  else
    reasons+=("windows_server_packaging_ok is false")
  fi
fi
if [[ "$require_windows_native_bootstrap_guardrails_ok" == "1" && "$windows_native_bootstrap_guardrails_ok" != "true" ]]; then
  if [[ "$windows_native_bootstrap_guardrails_status" == "missing" ]]; then
    reasons+=("windows_native_bootstrap_guardrails_ok unresolved from provided artifacts")
  else
    reasons+=("windows_native_bootstrap_guardrails_ok is false")
  fi
fi
if [[ "$require_windows_role_runbooks_ok" == "1" && "$windows_role_runbooks_ok" != "true" ]]; then
  if [[ "$windows_role_runbooks_status" == "missing" ]]; then
    reasons+=("windows_role_runbooks_ok unresolved from provided artifacts")
  else
    reasons+=("windows_role_runbooks_ok is false")
  fi
fi
if [[ "$require_cross_platform_interop_ok" == "1" && "$cross_platform_interop_ok" != "true" ]]; then
  if [[ "$cross_platform_interop_status" == "missing" ]]; then
    reasons+=("cross_platform_interop_ok unresolved from provided artifacts")
  else
    reasons+=("cross_platform_interop_ok is false")
  fi
fi
if [[ "$require_role_combination_validation_ok" == "1" && "$role_combination_validation_ok" != "true" ]]; then
  if [[ "$role_combination_validation_status" == "missing" ]]; then
    reasons+=("role_combination_validation_ok unresolved from provided artifacts")
  else
    reasons+=("role_combination_validation_ok is false")
  fi
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
  "$phase4_run_summary_json" \
  "$roadmap_summary_json" \
  "$phase4_run_summary_usable" \
  "$roadmap_summary_usable" \
  "$show_json" \
  "$require_run_pipeline_ok" \
  "$require_windows_server_packaging_ok" \
  "$require_windows_native_bootstrap_guardrails_ok" \
  "$require_windows_role_runbooks_ok" \
  "$require_cross_platform_interop_ok" \
  "$require_role_combination_validation_ok" \
  "$run_pipeline_status" \
  "$run_pipeline_value" \
  "$run_pipeline_resolved" \
  "$run_pipeline_source" \
  "$run_pipeline_contract_valid" \
  "$windows_server_packaging_status" \
  "$windows_native_bootstrap_guardrails_status" \
  "$windows_role_runbooks_status" \
  "$cross_platform_interop_status" \
  "$role_combination_validation_status" \
  "$windows_server_packaging_ok" \
  "$windows_native_bootstrap_guardrails_ok" \
  "$windows_role_runbooks_ok" \
  "$cross_platform_interop_ok" \
  "$role_combination_validation_ok" \
  "$windows_server_packaging_resolved" \
  "$windows_native_bootstrap_guardrails_resolved" \
  "$windows_role_runbooks_resolved" \
  "$cross_platform_interop_resolved" \
  "$role_combination_validation_resolved" \
  "$windows_server_packaging_source" \
  "$windows_native_bootstrap_guardrails_source" \
  "$windows_role_runbooks_source" \
  "$cross_platform_interop_source" \
  "$role_combination_validation_source" \
  "$reasons_json"

if [[ "$show_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$status" == "pass" ]]; then
  exit 0
fi
exit 1
