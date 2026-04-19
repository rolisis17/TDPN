#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase3_windows_client_beta_handoff_check.sh \
    [--phase3-run-summary-json PATH] \
    [--roadmap-summary-json PATH] \
    [--require-run-pipeline-ok [0|1]] \
    [--require-desktop-scaffold-ok [0|1]] \
    [--require-local-control-api-ok [0|1]] \
    [--require-local-api-config-defaults-ok [0|1]] \
    [--require-easy-node-config-v1-ok [0|1]] \
    [--require-launcher-wiring-ok [0|1]] \
    [--require-launcher-runtime-ok [0|1]] \
    [--require-windows-native-bootstrap-guardrails-ok [0|1]] \
    [--summary-json PATH] \
    [--show-json [0|1]]

Purpose:
  Fail-closed checker for the Phase-3 Windows client-beta handoff.
  Evaluates the run pipeline and handoff readiness booleans.

Notes:
  - The checker prefers readiness booleans from the roadmap summary at:
      .vpn_track.phase3_windows_client_beta_handoff.*
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
    and (.schema.id // "") == "phase3_windows_client_beta_run_summary"
    and ((.status | type) == "string")
    and ((.rc | type) == "number")
    and ((.steps.ci_phase3_windows_client_beta.status | type) == "string")
    and ((.steps.ci_phase3_windows_client_beta.rc | type) == "number")
    and ((.steps.ci_phase3_windows_client_beta.command_rc | type) == "number")
    and ((.steps.ci_phase3_windows_client_beta.contract_valid | type) == "boolean")
    and ((.steps.phase3_windows_client_beta_check.status | type) == "string")
    and ((.steps.phase3_windows_client_beta_check.rc | type) == "number")
    and ((.steps.phase3_windows_client_beta_check.command_rc | type) == "number")
    and ((.steps.phase3_windows_client_beta_check.contract_valid | type) == "boolean")
  ' "$run_summary_json" >/dev/null 2>&1; then
    contract_valid="1"
  fi

  local ci_status=""
  local ci_contract_valid="0"
  local check_status=""
  local check_contract_valid="0"
  ci_status="$(json_text_or_empty "$run_summary_json" '.steps.ci_phase3_windows_client_beta.status')"
  check_status="$(json_text_or_empty "$run_summary_json" '.steps.phase3_windows_client_beta_check.status')"
  if [[ "$(json_bool_or_empty "$run_summary_json" '.steps.ci_phase3_windows_client_beta.contract_valid')" == "true" ]]; then
    ci_contract_valid="1"
  fi
  if [[ "$(json_bool_or_empty "$run_summary_json" '.steps.phase3_windows_client_beta_check.contract_valid')" == "true" ]]; then
    check_contract_valid="1"
  fi

  if [[ "$contract_valid" != "1" ]]; then
    value="false"
    status="invalid"
    source="phase3_run_summary.contract"
    resolved="1"
  elif [[ "$ci_status" != "pass" || "$ci_contract_valid" != "1" ]]; then
    value="false"
    status="fail"
    source="phase3_run_summary.steps.ci_phase3_windows_client_beta"
    resolved="1"
  elif [[ "$check_status" != "pass" || "$check_contract_valid" != "1" ]]; then
    value="false"
    status="fail"
    source="phase3_run_summary.steps.phase3_windows_client_beta_check"
    resolved="1"
  else
    value="true"
    status="pass"
    source="phase3_run_summary"
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
    value="$(json_bool_or_empty "$roadmap_summary_json" "if (.vpn_track.phase3_windows_client_beta_handoff.$signal | type) == \"boolean\" then .vpn_track.phase3_windows_client_beta_handoff.$signal elif (.phase3_windows_client_beta_handoff.$signal | type) == \"boolean\" then .phase3_windows_client_beta_handoff.$signal else empty end")"
    if [[ -n "$value" ]]; then
      status="$( [[ "$value" == "true" ]] && printf '%s' "pass" || printf '%s' "fail" )"
      source="roadmap_progress_summary.vpn_track.phase3_windows_client_beta_handoff.$signal"
      resolved="1"
      printf '%s|%s|%s|%s\n' "$value" "$status" "$source" "$resolved"
      return
    fi
  fi

  if [[ "$run_summary_usable" == "1" ]]; then
    local check_summary_json=""
    check_summary_json="$(json_text_or_empty "$run_summary_json" '.steps.phase3_windows_client_beta_check.artifacts.summary_json // .artifacts.check_summary_json')"
    if [[ -n "$check_summary_json" ]]; then
      check_summary_json="$(resolve_path_with_base "$check_summary_json" "$run_summary_json")"
      if [[ "$(json_file_valid_01 "$check_summary_json")" == "1" ]]; then
        value="$(json_bool_or_empty "$check_summary_json" "if (.signals.$signal | type) == \"boolean\" then .signals.$signal elif (.handoff.$signal | type) == \"boolean\" then .handoff.$signal elif (.phase3_windows_client_beta_handoff.$signal | type) == \"boolean\" then .phase3_windows_client_beta_handoff.$signal elif (.vpn_track.phase3_windows_client_beta_handoff.$signal | type) == \"boolean\" then .vpn_track.phase3_windows_client_beta_handoff.$signal else empty end")"
        if [[ -n "$value" ]]; then
          status="$( [[ "$value" == "true" ]] && printf '%s' "pass" || printf '%s' "fail" )"
          source="phase3_windows_client_beta_check_summary.$signal"
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
  local phase3_run_summary_json="$5"
  local roadmap_summary_json="$6"
  local run_summary_usable="$7"
  local roadmap_summary_usable="$8"
  local show_json="$9"
  local require_run_pipeline_ok="${10}"
  local require_desktop_scaffold_ok="${11}"
  local require_local_control_api_ok="${12}"
  local require_local_api_config_defaults_ok="${13}"
  local require_easy_node_config_v1_ok="${14}"
  local require_launcher_wiring_ok="${15}"
  local require_launcher_runtime_ok="${16}"
  local require_windows_native_bootstrap_guardrails_ok="${17}"
  local run_pipeline_status="${18}"
  local run_pipeline_ok="${19}"
  local run_pipeline_resolved="${20}"
  local run_pipeline_source="${21}"
  local run_pipeline_contract_valid="${22}"
  local desktop_scaffold_status="${23}"
  local local_control_api_status="${24}"
  local local_api_config_defaults_status="${25}"
  local easy_node_config_v1_status="${26}"
  local launcher_wiring_status="${27}"
  local launcher_runtime_status="${28}"
  local windows_native_bootstrap_guardrails_status="${29}"
  local desktop_scaffold_ok="${30}"
  local local_control_api_ok="${31}"
  local local_api_config_defaults_ok="${32}"
  local easy_node_config_v1_ok="${33}"
  local launcher_wiring_ok="${34}"
  local launcher_runtime_ok="${35}"
  local windows_native_bootstrap_guardrails_ok="${36}"
  local desktop_scaffold_resolved="${37}"
  local local_control_api_resolved="${38}"
  local local_api_config_defaults_resolved="${39}"
  local easy_node_config_v1_resolved="${40}"
  local launcher_wiring_resolved="${41}"
  local launcher_runtime_resolved="${42}"
  local windows_native_bootstrap_guardrails_resolved="${43}"
  local desktop_scaffold_source="${44}"
  local local_control_api_source="${45}"
  local local_api_config_defaults_source="${46}"
  local easy_node_config_v1_source="${47}"
  local launcher_wiring_source="${48}"
  local launcher_runtime_source="${49}"
  local windows_native_bootstrap_guardrails_source="${50}"
  local final_failure_kind="${51}"
  local policy_outcome_decision="${52}"
  local reasons_json="${53}"

  local summary_tmp
  summary_tmp="$(mktemp)"
  jq -n \
    --arg generated_at_utc "$generated_at_utc" \
    --arg status "$status" \
    --argjson rc "$rc" \
    --arg summary_json "$summary_json" \
    --arg phase3_run_summary_json "$phase3_run_summary_json" \
    --arg roadmap_summary_json "$roadmap_summary_json" \
    --argjson run_summary_usable "$run_summary_usable" \
    --argjson roadmap_summary_usable "$roadmap_summary_usable" \
    --arg show_json "$show_json" \
    --argjson require_run_pipeline_ok "$require_run_pipeline_ok" \
    --argjson require_desktop_scaffold_ok "$require_desktop_scaffold_ok" \
    --argjson require_local_control_api_ok "$require_local_control_api_ok" \
    --argjson require_local_api_config_defaults_ok "$require_local_api_config_defaults_ok" \
    --argjson require_easy_node_config_v1_ok "$require_easy_node_config_v1_ok" \
    --argjson require_launcher_wiring_ok "$require_launcher_wiring_ok" \
    --argjson require_launcher_runtime_ok "$require_launcher_runtime_ok" \
    --argjson require_windows_native_bootstrap_guardrails_ok "$require_windows_native_bootstrap_guardrails_ok" \
    --arg run_pipeline_status "$run_pipeline_status" \
    --argjson run_pipeline_ok "$run_pipeline_ok" \
    --argjson run_pipeline_resolved "$run_pipeline_resolved" \
    --arg run_pipeline_source "$run_pipeline_source" \
    --argjson run_pipeline_contract_valid "$run_pipeline_contract_valid" \
    --arg desktop_scaffold_status "$desktop_scaffold_status" \
    --arg local_control_api_status "$local_control_api_status" \
    --arg local_api_config_defaults_status "$local_api_config_defaults_status" \
    --arg easy_node_config_v1_status "$easy_node_config_v1_status" \
    --arg launcher_wiring_status "$launcher_wiring_status" \
    --arg launcher_runtime_status "$launcher_runtime_status" \
    --arg windows_native_bootstrap_guardrails_status "$windows_native_bootstrap_guardrails_status" \
    --argjson desktop_scaffold_ok "$desktop_scaffold_ok" \
    --argjson local_control_api_ok "$local_control_api_ok" \
    --argjson local_api_config_defaults_ok "$local_api_config_defaults_ok" \
    --argjson easy_node_config_v1_ok "$easy_node_config_v1_ok" \
    --argjson launcher_wiring_ok "$launcher_wiring_ok" \
    --argjson launcher_runtime_ok "$launcher_runtime_ok" \
    --argjson windows_native_bootstrap_guardrails_ok "$windows_native_bootstrap_guardrails_ok" \
    --argjson desktop_scaffold_resolved "$desktop_scaffold_resolved" \
    --argjson local_control_api_resolved "$local_control_api_resolved" \
    --argjson local_api_config_defaults_resolved "$local_api_config_defaults_resolved" \
    --argjson easy_node_config_v1_resolved "$easy_node_config_v1_resolved" \
    --argjson launcher_wiring_resolved "$launcher_wiring_resolved" \
    --argjson launcher_runtime_resolved "$launcher_runtime_resolved" \
    --argjson windows_native_bootstrap_guardrails_resolved "$windows_native_bootstrap_guardrails_resolved" \
    --arg desktop_scaffold_source "$desktop_scaffold_source" \
    --arg local_control_api_source "$local_control_api_source" \
    --arg local_api_config_defaults_source "$local_api_config_defaults_source" \
    --arg easy_node_config_v1_source "$easy_node_config_v1_source" \
    --arg launcher_wiring_source "$launcher_wiring_source" \
    --arg launcher_runtime_source "$launcher_runtime_source" \
    --arg windows_native_bootstrap_guardrails_source "$windows_native_bootstrap_guardrails_source" \
    --arg final_failure_kind "$final_failure_kind" \
    --arg policy_outcome_decision "$policy_outcome_decision" \
    --argjson reasons "$reasons_json" \
    '
      def failure_kind($enabled; $ok; $resolved; $status):
        if ($enabled | not) then "none"
        elif $ok == true then "none"
        elif ($status == "missing" or $status == "invalid") then "execution_failure"
        elif $resolved == true then "policy_no_go"
        else "execution_failure"
        end;
      def actionable_gate($id; $signal; $enabled; $ok; $resolved; $status):
        {
          id: $id,
          signal: $signal,
          required: $enabled,
          ok: $ok,
          resolved: $resolved,
          status: $status,
          failure_kind: failure_kind($enabled; $ok; $resolved; $status),
          reason: (
            if ($enabled | not) then "not_required"
            elif $ok == true then "pass"
            elif $resolved == true then "required_signal_false"
            else "required_signal_unresolved"
            end
          )
        };
      {
      version: 1,
      schema: {
        id: "phase3_windows_client_beta_handoff_check_summary",
        major: 1,
        minor: 0
      },
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $rc,
      fail_closed: true,
      metadata: {
        contract: "phase3-windows-client-beta",
        script: "phase3_windows_client_beta_handoff_check.sh"
      },
      inputs: {
        phase3_run_summary_json: (if $phase3_run_summary_json == "" then null else $phase3_run_summary_json end),
        roadmap_summary_json: (if $roadmap_summary_json == "" then null else $roadmap_summary_json end),
        show_json: ($show_json == "1"),
        requirements: {
          run_pipeline_ok: ($require_run_pipeline_ok == 1),
          desktop_scaffold_ok: ($require_desktop_scaffold_ok == 1),
          local_control_api_ok: ($require_local_control_api_ok == 1),
          local_api_config_defaults_ok: ($require_local_api_config_defaults_ok == 1),
          easy_node_config_v1_ok: ($require_easy_node_config_v1_ok == 1),
          launcher_wiring_ok: ($require_launcher_wiring_ok == 1),
          launcher_runtime_ok: ($require_launcher_runtime_ok == 1),
          windows_native_bootstrap_guardrails_ok: ($require_windows_native_bootstrap_guardrails_ok == 1)
        },
        usable: {
          phase3_run_summary_json: ($run_summary_usable == 1),
          roadmap_summary_json: ($roadmap_summary_usable == 1)
        }
      },
      handoff: {
        run_pipeline_ok: $run_pipeline_ok,
        run_pipeline_status: $run_pipeline_status,
        run_pipeline_resolved: ($run_pipeline_resolved == 1),
        run_pipeline_contract_valid: ($run_pipeline_contract_valid == 1),
        desktop_scaffold_ok: $desktop_scaffold_ok,
        desktop_scaffold_status: $desktop_scaffold_status,
        desktop_scaffold_resolved: ($desktop_scaffold_resolved == 1),
        local_control_api_ok: $local_control_api_ok,
        local_control_api_status: $local_control_api_status,
        local_control_api_resolved: ($local_control_api_resolved == 1),
        local_api_config_defaults_ok: $local_api_config_defaults_ok,
        local_api_config_defaults_status: $local_api_config_defaults_status,
        local_api_config_defaults_resolved: ($local_api_config_defaults_resolved == 1),
        easy_node_config_v1_ok: $easy_node_config_v1_ok,
        easy_node_config_v1_status: $easy_node_config_v1_status,
        easy_node_config_v1_resolved: ($easy_node_config_v1_resolved == 1),
        launcher_wiring_ok: $launcher_wiring_ok,
        launcher_wiring_status: $launcher_wiring_status,
        launcher_wiring_resolved: ($launcher_wiring_resolved == 1),
        launcher_runtime_ok: $launcher_runtime_ok,
        launcher_runtime_status: $launcher_runtime_status,
        launcher_runtime_resolved: ($launcher_runtime_resolved == 1),
        windows_native_bootstrap_guardrails_ok: $windows_native_bootstrap_guardrails_ok,
        windows_native_bootstrap_guardrails_status: $windows_native_bootstrap_guardrails_status,
        windows_native_bootstrap_guardrails_resolved: ($windows_native_bootstrap_guardrails_resolved == 1),
        sources: {
          run_pipeline_ok: $run_pipeline_source,
          desktop_scaffold_ok: $desktop_scaffold_source,
          local_control_api_ok: $local_control_api_source,
          local_api_config_defaults_ok: $local_api_config_defaults_source,
          easy_node_config_v1_ok: $easy_node_config_v1_source,
          launcher_wiring_ok: $launcher_wiring_source,
          launcher_runtime_ok: $launcher_runtime_source,
          windows_native_bootstrap_guardrails_ok: $windows_native_bootstrap_guardrails_source
        },
        failure_semantics: {
          run_pipeline_ok: {
            kind: (if ($require_run_pipeline_ok == 1) and ($run_pipeline_ok != true) then "execution_failure" else "none" end),
            policy_no_go: false,
            execution_failure: (($require_run_pipeline_ok == 1) and ($run_pipeline_ok != true))
          },
          desktop_scaffold_ok: {
            kind: failure_kind(($require_desktop_scaffold_ok == 1); $desktop_scaffold_ok; ($desktop_scaffold_resolved == 1); $desktop_scaffold_status),
            policy_no_go: (failure_kind(($require_desktop_scaffold_ok == 1); $desktop_scaffold_ok; ($desktop_scaffold_resolved == 1); $desktop_scaffold_status) == "policy_no_go"),
            execution_failure: (failure_kind(($require_desktop_scaffold_ok == 1); $desktop_scaffold_ok; ($desktop_scaffold_resolved == 1); $desktop_scaffold_status) == "execution_failure")
          },
          local_control_api_ok: {
            kind: failure_kind(($require_local_control_api_ok == 1); $local_control_api_ok; ($local_control_api_resolved == 1); $local_control_api_status),
            policy_no_go: (failure_kind(($require_local_control_api_ok == 1); $local_control_api_ok; ($local_control_api_resolved == 1); $local_control_api_status) == "policy_no_go"),
            execution_failure: (failure_kind(($require_local_control_api_ok == 1); $local_control_api_ok; ($local_control_api_resolved == 1); $local_control_api_status) == "execution_failure")
          },
          local_api_config_defaults_ok: {
            kind: failure_kind(($require_local_api_config_defaults_ok == 1); $local_api_config_defaults_ok; ($local_api_config_defaults_resolved == 1); $local_api_config_defaults_status),
            policy_no_go: (failure_kind(($require_local_api_config_defaults_ok == 1); $local_api_config_defaults_ok; ($local_api_config_defaults_resolved == 1); $local_api_config_defaults_status) == "policy_no_go"),
            execution_failure: (failure_kind(($require_local_api_config_defaults_ok == 1); $local_api_config_defaults_ok; ($local_api_config_defaults_resolved == 1); $local_api_config_defaults_status) == "execution_failure")
          },
          easy_node_config_v1_ok: {
            kind: failure_kind(($require_easy_node_config_v1_ok == 1); $easy_node_config_v1_ok; ($easy_node_config_v1_resolved == 1); $easy_node_config_v1_status),
            policy_no_go: (failure_kind(($require_easy_node_config_v1_ok == 1); $easy_node_config_v1_ok; ($easy_node_config_v1_resolved == 1); $easy_node_config_v1_status) == "policy_no_go"),
            execution_failure: (failure_kind(($require_easy_node_config_v1_ok == 1); $easy_node_config_v1_ok; ($easy_node_config_v1_resolved == 1); $easy_node_config_v1_status) == "execution_failure")
          },
          launcher_wiring_ok: {
            kind: failure_kind(($require_launcher_wiring_ok == 1); $launcher_wiring_ok; ($launcher_wiring_resolved == 1); $launcher_wiring_status),
            policy_no_go: (failure_kind(($require_launcher_wiring_ok == 1); $launcher_wiring_ok; ($launcher_wiring_resolved == 1); $launcher_wiring_status) == "policy_no_go"),
            execution_failure: (failure_kind(($require_launcher_wiring_ok == 1); $launcher_wiring_ok; ($launcher_wiring_resolved == 1); $launcher_wiring_status) == "execution_failure")
          },
          launcher_runtime_ok: {
            kind: failure_kind(($require_launcher_runtime_ok == 1); $launcher_runtime_ok; ($launcher_runtime_resolved == 1); $launcher_runtime_status),
            policy_no_go: (failure_kind(($require_launcher_runtime_ok == 1); $launcher_runtime_ok; ($launcher_runtime_resolved == 1); $launcher_runtime_status) == "policy_no_go"),
            execution_failure: (failure_kind(($require_launcher_runtime_ok == 1); $launcher_runtime_ok; ($launcher_runtime_resolved == 1); $launcher_runtime_status) == "execution_failure")
          },
          windows_native_bootstrap_guardrails_ok: {
            kind: failure_kind(($require_windows_native_bootstrap_guardrails_ok == 1); $windows_native_bootstrap_guardrails_ok; ($windows_native_bootstrap_guardrails_resolved == 1); $windows_native_bootstrap_guardrails_status),
            policy_no_go: (failure_kind(($require_windows_native_bootstrap_guardrails_ok == 1); $windows_native_bootstrap_guardrails_ok; ($windows_native_bootstrap_guardrails_resolved == 1); $windows_native_bootstrap_guardrails_status) == "policy_no_go"),
            execution_failure: (failure_kind(($require_windows_native_bootstrap_guardrails_ok == 1); $windows_native_bootstrap_guardrails_ok; ($windows_native_bootstrap_guardrails_resolved == 1); $windows_native_bootstrap_guardrails_status) == "execution_failure")
          }
        }
      },
      failure: {
        kind: $final_failure_kind,
        policy_no_go: ($final_failure_kind == "policy_no_go"),
        execution_failure: ($final_failure_kind == "execution_failure"),
        timeout: false
      },
      policy_outcome: {
        decision: $policy_outcome_decision,
        fail_closed_no_go: ($final_failure_kind == "policy_no_go")
      },
      decision: {
        pass: ($status == "pass"),
        reasons: $reasons,
        warnings: [],
        actionable: (
          [
            actionable_gate("phase3_windows_client_beta_run_pipeline_gate"; "run_pipeline_ok"; ($require_run_pipeline_ok == 1); $run_pipeline_ok; ($run_pipeline_resolved == 1); $run_pipeline_status),
            actionable_gate("phase3_windows_client_beta_desktop_scaffold_gate"; "desktop_scaffold_ok"; ($require_desktop_scaffold_ok == 1); $desktop_scaffold_ok; ($desktop_scaffold_resolved == 1); $desktop_scaffold_status),
            actionable_gate("phase3_windows_client_beta_local_control_api_gate"; "local_control_api_ok"; ($require_local_control_api_ok == 1); $local_control_api_ok; ($local_control_api_resolved == 1); $local_control_api_status),
            actionable_gate("phase3_windows_client_beta_local_api_config_defaults_gate"; "local_api_config_defaults_ok"; ($require_local_api_config_defaults_ok == 1); $local_api_config_defaults_ok; ($local_api_config_defaults_resolved == 1); $local_api_config_defaults_status),
            actionable_gate("phase3_windows_client_beta_easy_node_config_v1_gate"; "easy_node_config_v1_ok"; ($require_easy_node_config_v1_ok == 1); $easy_node_config_v1_ok; ($easy_node_config_v1_resolved == 1); $easy_node_config_v1_status),
            actionable_gate("phase3_windows_client_beta_launcher_wiring_gate"; "launcher_wiring_ok"; ($require_launcher_wiring_ok == 1); $launcher_wiring_ok; ($launcher_wiring_resolved == 1); $launcher_wiring_status),
            actionable_gate("phase3_windows_client_beta_launcher_runtime_gate"; "launcher_runtime_ok"; ($require_launcher_runtime_ok == 1); $launcher_runtime_ok; ($launcher_runtime_resolved == 1); $launcher_runtime_status),
            actionable_gate("phase3_windows_client_beta_windows_native_bootstrap_guardrails_gate"; "windows_native_bootstrap_guardrails_ok"; ($require_windows_native_bootstrap_guardrails_ok == 1); $windows_native_bootstrap_guardrails_ok; ($windows_native_bootstrap_guardrails_resolved == 1); $windows_native_bootstrap_guardrails_status)
          ] as $all_gates
          | ($all_gates | map(select(.required == true and .ok != true))) as $failed_required
          | {
              count: ($failed_required | length),
              recommended_gate_id: ($failed_required[0].id // null),
              gates: $failed_required
            }
        )
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

phase3_run_summary_json="${PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_CHECK_PHASE3_RUN_SUMMARY_JSON:-}"
roadmap_summary_json="${PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_CHECK_ROADMAP_SUMMARY_JSON:-}"
summary_json="${PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_CHECK_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase3_windows_client_beta_handoff_check_summary.json}"
show_json="${PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_CHECK_SHOW_JSON:-0}"
require_run_pipeline_ok="${PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_CHECK_REQUIRE_RUN_PIPELINE_OK:-1}"
require_desktop_scaffold_ok="${PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_CHECK_REQUIRE_DESKTOP_SCAFFOLD_OK:-1}"
require_local_control_api_ok="${PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_CHECK_REQUIRE_LOCAL_CONTROL_API_OK:-1}"
require_local_api_config_defaults_ok="${PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_CHECK_REQUIRE_LOCAL_API_CONFIG_DEFAULTS_OK:-1}"
require_easy_node_config_v1_ok="${PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_CHECK_REQUIRE_EASY_NODE_CONFIG_V1_OK:-1}"
require_launcher_wiring_ok="${PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_CHECK_REQUIRE_LAUNCHER_WIRING_OK:-1}"
require_launcher_runtime_ok="${PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_CHECK_REQUIRE_LAUNCHER_RUNTIME_OK:-1}"
require_windows_native_bootstrap_guardrails_ok="${PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_CHECK_REQUIRE_WINDOWS_NATIVE_BOOTSTRAP_GUARDRAILS_OK:-1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --phase3-run-summary-json)
      phase3_run_summary_json="${2:-}"
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
    --require-desktop-scaffold-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_desktop_scaffold_ok="${2:-}"
        shift 2
      else
        require_desktop_scaffold_ok="1"
        shift
      fi
      ;;
    --require-local-control-api-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_local_control_api_ok="${2:-}"
        shift 2
      else
        require_local_control_api_ok="1"
        shift
      fi
      ;;
    --require-local-api-config-defaults-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_local_api_config_defaults_ok="${2:-}"
        shift 2
      else
        require_local_api_config_defaults_ok="1"
        shift
      fi
      ;;
    --require-easy-node-config-v1-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_easy_node_config_v1_ok="${2:-}"
        shift 2
      else
        require_easy_node_config_v1_ok="1"
        shift
      fi
      ;;
    --require-launcher-wiring-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_launcher_wiring_ok="${2:-}"
        shift 2
      else
        require_launcher_wiring_ok="1"
        shift
      fi
      ;;
    --require-launcher-runtime-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_launcher_runtime_ok="${2:-}"
        shift 2
      else
        require_launcher_runtime_ok="1"
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
bool_arg_or_die "--require-desktop-scaffold-ok" "$require_desktop_scaffold_ok"
bool_arg_or_die "--require-local-control-api-ok" "$require_local_control_api_ok"
bool_arg_or_die "--require-local-api-config-defaults-ok" "$require_local_api_config_defaults_ok"
bool_arg_or_die "--require-easy-node-config-v1-ok" "$require_easy_node_config_v1_ok"
bool_arg_or_die "--require-launcher-wiring-ok" "$require_launcher_wiring_ok"
bool_arg_or_die "--require-launcher-runtime-ok" "$require_launcher_runtime_ok"
bool_arg_or_die "--require-windows-native-bootstrap-guardrails-ok" "$require_windows_native_bootstrap_guardrails_ok"
bool_arg_or_die "--show-json" "$show_json"

phase3_run_summary_json="$(abs_path "$phase3_run_summary_json")"
roadmap_summary_json="$(abs_path "$roadmap_summary_json")"
summary_json="$(abs_path "$summary_json")"

mkdir -p "$(dirname "$summary_json")"

generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

declare -a reasons=()

phase3_run_summary_usable="0"
roadmap_summary_usable="0"
run_pipeline_contract_valid="0"
run_pipeline_value="null"
run_pipeline_status="missing"
run_pipeline_resolved="0"
run_pipeline_source="unresolved"

if [[ -n "$phase3_run_summary_json" ]]; then
  if [[ "$(json_file_valid_01 "$phase3_run_summary_json")" == "1" ]]; then
    phase3_run_summary_usable="1"
  else
    reasons+=("phase3 run summary file not found or invalid JSON: $phase3_run_summary_json")
  fi
fi

if [[ -n "$roadmap_summary_json" ]]; then
  if [[ "$(json_file_valid_01 "$roadmap_summary_json")" == "1" ]]; then
    roadmap_summary_usable="1"
  else
    reasons+=("roadmap summary file not found or invalid JSON: $roadmap_summary_json")
  fi
fi

if [[ "$phase3_run_summary_usable" == "1" ]]; then
  run_pipeline_pair="$(resolve_run_pipeline "$phase3_run_summary_json" "$phase3_run_summary_usable")"
  run_pipeline_value="${run_pipeline_pair%%|*}"
  run_pipeline_pair="${run_pipeline_pair#*|}"
  run_pipeline_status="${run_pipeline_pair%%|*}"
  run_pipeline_pair="${run_pipeline_pair#*|}"
  run_pipeline_source="${run_pipeline_pair%%|*}"
  run_pipeline_pair="${run_pipeline_pair#*|}"
  run_pipeline_resolved="${run_pipeline_pair%%|*}"
  run_pipeline_contract_valid="${run_pipeline_pair##*|}"
  if [[ "$run_pipeline_status" == "invalid" ]]; then
    reasons+=("phase3 run summary contract is invalid")
  elif [[ "$run_pipeline_status" == "fail" ]]; then
    reasons+=("run pipeline is not ready")
  fi
else
  reasons+=("phase3 run summary is unavailable")
fi

desktop_scaffold_pair="$(resolve_handoff_bool "desktop_scaffold_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase3_run_summary_json" "$phase3_run_summary_usable")"
local_control_api_pair="$(resolve_handoff_bool "local_control_api_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase3_run_summary_json" "$phase3_run_summary_usable")"
local_api_config_defaults_pair="$(resolve_handoff_bool "local_api_config_defaults_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase3_run_summary_json" "$phase3_run_summary_usable")"
easy_node_config_v1_pair="$(resolve_handoff_bool "easy_node_config_v1_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase3_run_summary_json" "$phase3_run_summary_usable")"
launcher_wiring_pair="$(resolve_handoff_bool "launcher_wiring_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase3_run_summary_json" "$phase3_run_summary_usable")"
launcher_runtime_pair="$(resolve_handoff_bool "launcher_runtime_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase3_run_summary_json" "$phase3_run_summary_usable")"
windows_native_bootstrap_guardrails_pair="$(resolve_handoff_bool "windows_native_bootstrap_guardrails_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase3_run_summary_json" "$phase3_run_summary_usable")"

desktop_scaffold_ok="${desktop_scaffold_pair%%|*}"
desktop_scaffold_pair="${desktop_scaffold_pair#*|}"
desktop_scaffold_status="${desktop_scaffold_pair%%|*}"
desktop_scaffold_pair="${desktop_scaffold_pair#*|}"
desktop_scaffold_source="${desktop_scaffold_pair%%|*}"
desktop_scaffold_resolved="${desktop_scaffold_pair##*|}"

local_control_api_ok="${local_control_api_pair%%|*}"
local_control_api_pair="${local_control_api_pair#*|}"
local_control_api_status="${local_control_api_pair%%|*}"
local_control_api_pair="${local_control_api_pair#*|}"
local_control_api_source="${local_control_api_pair%%|*}"
local_control_api_resolved="${local_control_api_pair##*|}"

local_api_config_defaults_ok="${local_api_config_defaults_pair%%|*}"
local_api_config_defaults_pair="${local_api_config_defaults_pair#*|}"
local_api_config_defaults_status="${local_api_config_defaults_pair%%|*}"
local_api_config_defaults_pair="${local_api_config_defaults_pair#*|}"
local_api_config_defaults_source="${local_api_config_defaults_pair%%|*}"
local_api_config_defaults_resolved="${local_api_config_defaults_pair##*|}"

easy_node_config_v1_ok="${easy_node_config_v1_pair%%|*}"
easy_node_config_v1_pair="${easy_node_config_v1_pair#*|}"
easy_node_config_v1_status="${easy_node_config_v1_pair%%|*}"
easy_node_config_v1_pair="${easy_node_config_v1_pair#*|}"
easy_node_config_v1_source="${easy_node_config_v1_pair%%|*}"
easy_node_config_v1_resolved="${easy_node_config_v1_pair##*|}"

launcher_wiring_ok="${launcher_wiring_pair%%|*}"
launcher_wiring_pair="${launcher_wiring_pair#*|}"
launcher_wiring_status="${launcher_wiring_pair%%|*}"
launcher_wiring_pair="${launcher_wiring_pair#*|}"
launcher_wiring_source="${launcher_wiring_pair%%|*}"
launcher_wiring_resolved="${launcher_wiring_pair##*|}"

launcher_runtime_ok="${launcher_runtime_pair%%|*}"
launcher_runtime_pair="${launcher_runtime_pair#*|}"
launcher_runtime_status="${launcher_runtime_pair%%|*}"
launcher_runtime_pair="${launcher_runtime_pair#*|}"
launcher_runtime_source="${launcher_runtime_pair%%|*}"
launcher_runtime_resolved="${launcher_runtime_pair##*|}"

windows_native_bootstrap_guardrails_ok="${windows_native_bootstrap_guardrails_pair%%|*}"
windows_native_bootstrap_guardrails_pair="${windows_native_bootstrap_guardrails_pair#*|}"
windows_native_bootstrap_guardrails_status="${windows_native_bootstrap_guardrails_pair%%|*}"
windows_native_bootstrap_guardrails_pair="${windows_native_bootstrap_guardrails_pair#*|}"
windows_native_bootstrap_guardrails_source="${windows_native_bootstrap_guardrails_pair%%|*}"
windows_native_bootstrap_guardrails_resolved="${windows_native_bootstrap_guardrails_pair##*|}"

if [[ "$require_run_pipeline_ok" == "1" && "$run_pipeline_value" != "true" ]]; then
  if [[ "$run_pipeline_status" == "missing" ]]; then
    reasons+=("run_pipeline_ok unresolved from provided artifacts")
  else
    reasons+=("run_pipeline_ok is false")
  fi
fi
if [[ "$require_desktop_scaffold_ok" == "1" && "$desktop_scaffold_ok" != "true" ]]; then
  if [[ "$desktop_scaffold_status" == "missing" ]]; then
    reasons+=("desktop_scaffold_ok unresolved from provided artifacts")
  else
    reasons+=("desktop_scaffold_ok is false")
  fi
fi
if [[ "$require_local_control_api_ok" == "1" && "$local_control_api_ok" != "true" ]]; then
  if [[ "$local_control_api_status" == "missing" ]]; then
    reasons+=("local_control_api_ok unresolved from provided artifacts")
  else
    reasons+=("local_control_api_ok is false")
  fi
fi
if [[ "$require_local_api_config_defaults_ok" == "1" && "$local_api_config_defaults_ok" != "true" ]]; then
  if [[ "$local_api_config_defaults_status" == "missing" ]]; then
    reasons+=("local_api_config_defaults_ok unresolved from provided artifacts")
  else
    reasons+=("local_api_config_defaults_ok is false")
  fi
fi
if [[ "$require_easy_node_config_v1_ok" == "1" && "$easy_node_config_v1_ok" != "true" ]]; then
  if [[ "$easy_node_config_v1_status" == "missing" ]]; then
    reasons+=("easy_node_config_v1_ok unresolved from provided artifacts")
  else
    reasons+=("easy_node_config_v1_ok is false")
  fi
fi
if [[ "$require_launcher_wiring_ok" == "1" && "$launcher_wiring_ok" != "true" ]]; then
  if [[ "$launcher_wiring_status" == "missing" ]]; then
    reasons+=("launcher_wiring_ok unresolved from provided artifacts")
  else
    reasons+=("launcher_wiring_ok is false")
  fi
fi
if [[ "$require_launcher_runtime_ok" == "1" && "$launcher_runtime_ok" != "true" ]]; then
  if [[ "$launcher_runtime_status" == "missing" ]]; then
    reasons+=("launcher_runtime_ok unresolved from provided artifacts")
  else
    reasons+=("launcher_runtime_ok is false")
  fi
fi
if [[ "$require_windows_native_bootstrap_guardrails_ok" == "1" && "$windows_native_bootstrap_guardrails_ok" != "true" ]]; then
  if [[ "$windows_native_bootstrap_guardrails_status" == "missing" ]]; then
    reasons+=("windows_native_bootstrap_guardrails_ok unresolved from provided artifacts")
  else
    reasons+=("windows_native_bootstrap_guardrails_ok is false")
  fi
fi

status="pass"
rc=0
if ((${#reasons[@]} > 0)); then
  status="fail"
  rc=1
fi

final_failure_kind="none"
policy_outcome_decision="GO"
if [[ "$status" == "fail" ]]; then
  final_failure_kind="policy_no_go"
  policy_outcome_decision="NO-GO"

  if [[ "$require_run_pipeline_ok" == "1" && "$run_pipeline_value" != "true" ]]; then
    final_failure_kind="execution_failure"
    policy_outcome_decision="ERROR"
  fi
  if [[ "$require_desktop_scaffold_ok" == "1" && "$desktop_scaffold_ok" != "true" && "$desktop_scaffold_resolved" != "1" ]]; then
    final_failure_kind="execution_failure"
    policy_outcome_decision="ERROR"
  fi
  if [[ "$require_local_control_api_ok" == "1" && "$local_control_api_ok" != "true" && "$local_control_api_resolved" != "1" ]]; then
    final_failure_kind="execution_failure"
    policy_outcome_decision="ERROR"
  fi
  if [[ "$require_local_api_config_defaults_ok" == "1" && "$local_api_config_defaults_ok" != "true" && "$local_api_config_defaults_resolved" != "1" ]]; then
    final_failure_kind="execution_failure"
    policy_outcome_decision="ERROR"
  fi
  if [[ "$require_easy_node_config_v1_ok" == "1" && "$easy_node_config_v1_ok" != "true" && "$easy_node_config_v1_resolved" != "1" ]]; then
    final_failure_kind="execution_failure"
    policy_outcome_decision="ERROR"
  fi
  if [[ "$require_launcher_wiring_ok" == "1" && "$launcher_wiring_ok" != "true" && "$launcher_wiring_resolved" != "1" ]]; then
    final_failure_kind="execution_failure"
    policy_outcome_decision="ERROR"
  fi
  if [[ "$require_launcher_runtime_ok" == "1" && "$launcher_runtime_ok" != "true" && "$launcher_runtime_resolved" != "1" ]]; then
    final_failure_kind="execution_failure"
    policy_outcome_decision="ERROR"
  fi
  if [[ "$require_windows_native_bootstrap_guardrails_ok" == "1" && "$windows_native_bootstrap_guardrails_ok" != "true" && "$windows_native_bootstrap_guardrails_resolved" != "1" ]]; then
    final_failure_kind="execution_failure"
    policy_outcome_decision="ERROR"
  fi
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
  "$phase3_run_summary_json" \
  "$roadmap_summary_json" \
  "$phase3_run_summary_usable" \
  "$roadmap_summary_usable" \
  "$show_json" \
  "$require_run_pipeline_ok" \
  "$require_desktop_scaffold_ok" \
  "$require_local_control_api_ok" \
  "$require_local_api_config_defaults_ok" \
  "$require_easy_node_config_v1_ok" \
  "$require_launcher_wiring_ok" \
  "$require_launcher_runtime_ok" \
  "$require_windows_native_bootstrap_guardrails_ok" \
  "$run_pipeline_status" \
  "$run_pipeline_value" \
  "$run_pipeline_resolved" \
  "$run_pipeline_source" \
  "$run_pipeline_contract_valid" \
  "$desktop_scaffold_status" \
  "$local_control_api_status" \
  "$local_api_config_defaults_status" \
  "$easy_node_config_v1_status" \
  "$launcher_wiring_status" \
  "$launcher_runtime_status" \
  "$windows_native_bootstrap_guardrails_status" \
  "$desktop_scaffold_ok" \
  "$local_control_api_ok" \
  "$local_api_config_defaults_ok" \
  "$easy_node_config_v1_ok" \
  "$launcher_wiring_ok" \
  "$launcher_runtime_ok" \
  "$windows_native_bootstrap_guardrails_ok" \
  "$desktop_scaffold_resolved" \
  "$local_control_api_resolved" \
  "$local_api_config_defaults_resolved" \
  "$easy_node_config_v1_resolved" \
  "$launcher_wiring_resolved" \
  "$launcher_runtime_resolved" \
  "$windows_native_bootstrap_guardrails_resolved" \
  "$desktop_scaffold_source" \
  "$local_control_api_source" \
  "$local_api_config_defaults_source" \
  "$easy_node_config_v1_source" \
  "$launcher_wiring_source" \
  "$launcher_runtime_source" \
  "$windows_native_bootstrap_guardrails_source" \
  "$final_failure_kind" \
  "$policy_outcome_decision" \
  "$reasons_json"

if [[ "$show_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$status" == "pass" ]]; then
  exit 0
fi
exit 1
