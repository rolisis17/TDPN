#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase3_windows_client_beta_check.sh \
    [--ci-phase3-summary-json PATH] \
    [--require-desktop-scaffold-ok [0|1]] \
    [--require-local-control-api-ok [0|1]] \
    [--require-local-api-config-defaults-ok [0|1]] \
    [--require-easy-node-config-v1-ok [0|1]] \
    [--require-launcher-wiring-ok [0|1]] \
    [--require-windows-native-bootstrap-guardrails-ok [0|1]] \
    [--require-launcher-runtime-ok [0|1]] \
    [--summary-json PATH] \
    [--show-json [0|1]]

Purpose:
  Fail-closed checker for the Phase-3 Windows client beta readiness contract.
  Evaluates required readiness booleans derived from the CI Phase-3 summary:
    - desktop_scaffold_ok
    - local_control_api_ok
    - local_api_config_defaults_ok
    - easy_node_config_v1_ok
    - launcher_wiring_ok
    - windows_native_bootstrap_guardrails_ok
    - launcher_runtime_ok
  Emits canonical roadmap aliases (derived, fail-closed):
    - windows_parity_ok
    - desktop_contract_ok
    - installer_update_ok
    - telemetry_stability_ok

Notes:
  - Provide the CI summary with --ci-phase3-summary-json.
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
    desktop_scaffold_ok)
      json_text_or_empty "$path" 'if (.desktop_scaffold_ok? != null) then .desktop_scaffold_ok
        elif (.summary.desktop_scaffold_ok? != null) then .summary.desktop_scaffold_ok
        elif (.signals.desktop_scaffold_ok? != null) then .signals.desktop_scaffold_ok
        elif (.stages.desktop_scaffold.status? != null) then .stages.desktop_scaffold.status
        elif (.stages.desktop_scaffold_contract.status? != null) then .stages.desktop_scaffold_contract.status
        elif (.steps.desktop_scaffold.status? != null) then .steps.desktop_scaffold.status
        elif (.steps.desktop_scaffold_contract.status? != null) then .steps.desktop_scaffold_contract.status
        else empty end'
      ;;
    local_control_api_ok)
      json_text_or_empty "$path" 'if (.local_control_api_ok? != null) then .local_control_api_ok
        elif (.summary.local_control_api_ok? != null) then .summary.local_control_api_ok
        elif (.signals.local_control_api_ok? != null) then .signals.local_control_api_ok
        elif (.stages.local_control_api.status? != null) then .stages.local_control_api.status
        elif (.stages.local_control_api_contract.status? != null) then .stages.local_control_api_contract.status
        elif (.steps.local_control_api.status? != null) then .steps.local_control_api.status
        elif (.steps.local_control_api_contract.status? != null) then .steps.local_control_api_contract.status
        else empty end'
      ;;
    local_api_config_defaults_ok)
      json_text_or_empty "$path" 'if (.local_api_config_defaults_ok? != null) then .local_api_config_defaults_ok
        elif (.summary.local_api_config_defaults_ok? != null) then .summary.local_api_config_defaults_ok
        elif (.signals.local_api_config_defaults_ok? != null) then .signals.local_api_config_defaults_ok
        elif (.stages.local_api_config_defaults.status? != null) then .stages.local_api_config_defaults.status
        elif (.steps.local_api_config_defaults.status? != null) then .steps.local_api_config_defaults.status
        else empty end'
      ;;
    easy_node_config_v1_ok)
      json_text_or_empty "$path" 'if (.easy_node_config_v1_ok? != null) then .easy_node_config_v1_ok
        elif (.summary.easy_node_config_v1_ok? != null) then .summary.easy_node_config_v1_ok
        elif (.signals.easy_node_config_v1_ok? != null) then .signals.easy_node_config_v1_ok
        elif (.stages.easy_node_config_v1.status? != null) then .stages.easy_node_config_v1.status
        elif (.steps.easy_node_config_v1.status? != null) then .steps.easy_node_config_v1.status
        else empty end'
      ;;
    launcher_wiring_ok)
      json_text_or_empty "$path" 'if (.launcher_wiring_ok? != null) then .launcher_wiring_ok
        elif (.summary.launcher_wiring_ok? != null) then .summary.launcher_wiring_ok
        elif (.signals.launcher_wiring_ok? != null) then .signals.launcher_wiring_ok
        elif (.stages.easy_mode_launcher_wiring.status? != null) then .stages.easy_mode_launcher_wiring.status
        elif (.steps.easy_mode_launcher_wiring.status? != null) then .steps.easy_mode_launcher_wiring.status
        else empty end'
      ;;
    windows_native_bootstrap_guardrails_ok)
      json_text_or_empty "$path" 'if (.windows_native_bootstrap_guardrails_ok? != null) then .windows_native_bootstrap_guardrails_ok
        elif (.summary.windows_native_bootstrap_guardrails_ok? != null) then .summary.windows_native_bootstrap_guardrails_ok
        elif (.signals.windows_native_bootstrap_guardrails_ok? != null) then .signals.windows_native_bootstrap_guardrails_ok
        elif (.stages.windows_desktop_native_bootstrap_guardrails.status? != null) then .stages.windows_desktop_native_bootstrap_guardrails.status
        elif (.steps.windows_desktop_native_bootstrap_guardrails.status? != null) then .steps.windows_desktop_native_bootstrap_guardrails.status
        else empty end'
      ;;
    launcher_runtime_ok)
      json_text_or_empty "$path" 'if (.launcher_runtime_ok? != null) then .launcher_runtime_ok
        elif (.summary.launcher_runtime_ok? != null) then .summary.launcher_runtime_ok
        elif (.signals.launcher_runtime_ok? != null) then .signals.launcher_runtime_ok
        elif (.stages.easy_mode_launcher_runtime.status? != null) then .stages.easy_mode_launcher_runtime.status
        elif (.steps.easy_mode_launcher_runtime.status? != null) then .steps.easy_mode_launcher_runtime.status
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
  local ci_phase3_summary_json="$5"
  local ci_phase3_summary_usable="$6"
  local show_json="$7"
  local require_desktop_scaffold_ok="$8"
  local require_local_control_api_ok="$9"
  local require_local_api_config_defaults_ok="${10}"
  local require_easy_node_config_v1_ok="${11}"
  local require_launcher_wiring_ok="${12}"
  local require_launcher_runtime_ok="${13}"
  local desktop_scaffold_status="${14}"
  local local_control_api_status="${15}"
  local local_api_config_defaults_status="${16}"
  local easy_node_config_v1_status="${17}"
  local launcher_wiring_status="${18}"
  local launcher_runtime_status="${19}"
  local desktop_scaffold_ok="${20}"
  local local_control_api_ok="${21}"
  local local_api_config_defaults_ok="${22}"
  local easy_node_config_v1_ok="${23}"
  local launcher_wiring_ok="${24}"
  local launcher_runtime_ok="${25}"
  local desktop_scaffold_resolved="${26}"
  local local_control_api_resolved="${27}"
  local local_api_config_defaults_resolved="${28}"
  local easy_node_config_v1_resolved="${29}"
  local launcher_wiring_resolved="${30}"
  local launcher_runtime_resolved="${31}"
  local windows_parity_ok="${32}"
  local desktop_contract_ok="${33}"
  local installer_update_ok="${34}"
  local telemetry_stability_ok="${35}"
  local final_failure_kind="${36}"
  local policy_outcome_decision="${37}"
  local reasons_json="${38}"
  local require_windows_native_bootstrap_guardrails_ok="${39}"
  local windows_native_bootstrap_guardrails_status="${40}"
  local windows_native_bootstrap_guardrails_ok="${41}"
  local windows_native_bootstrap_guardrails_resolved="${42}"

  local summary_tmp
  summary_tmp="$(mktemp)"
  jq -n \
    --arg generated_at_utc "$generated_at_utc" \
    --arg status "$status" \
    --argjson rc "$rc" \
    --arg summary_json "$summary_json" \
    --arg ci_phase3_summary_json "$ci_phase3_summary_json" \
    --argjson ci_phase3_summary_usable "$ci_phase3_summary_usable" \
    --arg show_json "$show_json" \
    --argjson require_desktop_scaffold_ok "$require_desktop_scaffold_ok" \
    --argjson require_local_control_api_ok "$require_local_control_api_ok" \
    --argjson require_local_api_config_defaults_ok "$require_local_api_config_defaults_ok" \
    --argjson require_easy_node_config_v1_ok "$require_easy_node_config_v1_ok" \
    --argjson require_launcher_wiring_ok "$require_launcher_wiring_ok" \
    --argjson require_launcher_runtime_ok "$require_launcher_runtime_ok" \
    --argjson require_windows_native_bootstrap_guardrails_ok "$require_windows_native_bootstrap_guardrails_ok" \
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
    --argjson windows_parity_ok "$windows_parity_ok" \
    --argjson desktop_contract_ok "$desktop_contract_ok" \
    --argjson installer_update_ok "$installer_update_ok" \
    --argjson telemetry_stability_ok "$telemetry_stability_ok" \
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
        id: "phase3_windows_client_beta_check_summary",
        major: 1,
        minor: 0
      },
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $rc,
      metadata: {
        contract: "phase3-windows-client-beta",
        script: "phase3_windows_client_beta_check.sh"
      },
      inputs: {
        ci_phase3_summary_json: $ci_phase3_summary_json,
        summary_json: $summary_json,
        show_json: ($show_json == "1"),
        usable: {
          ci_phase3_summary_json: ($ci_phase3_summary_usable == 1)
        }
      },
      policy: {
        require_desktop_scaffold_ok: ($require_desktop_scaffold_ok == 1),
        require_local_control_api_ok: ($require_local_control_api_ok == 1),
        require_local_api_config_defaults_ok: ($require_local_api_config_defaults_ok == 1),
        require_easy_node_config_v1_ok: ($require_easy_node_config_v1_ok == 1),
        require_launcher_wiring_ok: ($require_launcher_wiring_ok == 1),
        require_launcher_runtime_ok: ($require_launcher_runtime_ok == 1),
        require_windows_native_bootstrap_guardrails_ok: ($require_windows_native_bootstrap_guardrails_ok == 1)
      },
      stages: {
        desktop_scaffold: {
          enabled: ($require_desktop_scaffold_ok == 1),
          status: $desktop_scaffold_status,
          resolved: ($desktop_scaffold_resolved == 1),
          ok: ($desktop_scaffold_ok == true)
        },
        local_control_api: {
          enabled: ($require_local_control_api_ok == 1),
          status: $local_control_api_status,
          resolved: ($local_control_api_resolved == 1),
          ok: ($local_control_api_ok == true)
        },
        local_api_config_defaults: {
          enabled: ($require_local_api_config_defaults_ok == 1),
          status: $local_api_config_defaults_status,
          resolved: ($local_api_config_defaults_resolved == 1),
          ok: ($local_api_config_defaults_ok == true)
        },
        easy_node_config_v1: {
          enabled: ($require_easy_node_config_v1_ok == 1),
          status: $easy_node_config_v1_status,
          resolved: ($easy_node_config_v1_resolved == 1),
          ok: ($easy_node_config_v1_ok == true)
        },
        launcher_wiring: {
          enabled: ($require_launcher_wiring_ok == 1),
          status: $launcher_wiring_status,
          resolved: ($launcher_wiring_resolved == 1),
          ok: ($launcher_wiring_ok == true)
        },
        launcher_runtime: {
          enabled: ($require_launcher_runtime_ok == 1),
          status: $launcher_runtime_status,
          resolved: ($launcher_runtime_resolved == 1),
          ok: ($launcher_runtime_ok == true)
        },
        windows_desktop_native_bootstrap_guardrails: {
          enabled: ($require_windows_native_bootstrap_guardrails_ok == 1),
          status: $windows_native_bootstrap_guardrails_status,
          resolved: ($windows_native_bootstrap_guardrails_resolved == 1),
          ok: ($windows_native_bootstrap_guardrails_ok == true)
        }
      },
      signals: {
        desktop_scaffold_ok: ($desktop_scaffold_ok == true),
        local_control_api_ok: ($local_control_api_ok == true),
        local_api_config_defaults_ok: ($local_api_config_defaults_ok == true),
        easy_node_config_v1_ok: ($easy_node_config_v1_ok == true),
        launcher_wiring_ok: ($launcher_wiring_ok == true),
        launcher_runtime_ok: ($launcher_runtime_ok == true),
        windows_native_bootstrap_guardrails_ok: ($windows_native_bootstrap_guardrails_ok == true),
        windows_parity_ok: ($windows_parity_ok == true),
        desktop_contract_ok: ($desktop_contract_ok == true),
        installer_update_ok: ($installer_update_ok == true),
        telemetry_stability_ok: ($telemetry_stability_ok == true)
      },
      windows_parity_ok: ($windows_parity_ok == true),
      desktop_contract_ok: ($desktop_contract_ok == true),
      installer_update_ok: ($installer_update_ok == true),
      telemetry_stability_ok: ($telemetry_stability_ok == true),
      handoff: {
        windows_parity_ok: ($windows_parity_ok == true),
        desktop_contract_ok: ($desktop_contract_ok == true),
        installer_update_ok: ($installer_update_ok == true),
        telemetry_stability_ok: ($telemetry_stability_ok == true),
        failure_semantics: {
          desktop_scaffold_ok: {
            kind: failure_kind(($require_desktop_scaffold_ok == 1); ($desktop_scaffold_ok == true); ($desktop_scaffold_resolved == 1); $desktop_scaffold_status),
            policy_no_go: (failure_kind(($require_desktop_scaffold_ok == 1); ($desktop_scaffold_ok == true); ($desktop_scaffold_resolved == 1); $desktop_scaffold_status) == "policy_no_go"),
            execution_failure: (failure_kind(($require_desktop_scaffold_ok == 1); ($desktop_scaffold_ok == true); ($desktop_scaffold_resolved == 1); $desktop_scaffold_status) == "execution_failure")
          },
          local_control_api_ok: {
            kind: failure_kind(($require_local_control_api_ok == 1); ($local_control_api_ok == true); ($local_control_api_resolved == 1); $local_control_api_status),
            policy_no_go: (failure_kind(($require_local_control_api_ok == 1); ($local_control_api_ok == true); ($local_control_api_resolved == 1); $local_control_api_status) == "policy_no_go"),
            execution_failure: (failure_kind(($require_local_control_api_ok == 1); ($local_control_api_ok == true); ($local_control_api_resolved == 1); $local_control_api_status) == "execution_failure")
          },
          local_api_config_defaults_ok: {
            kind: failure_kind(($require_local_api_config_defaults_ok == 1); ($local_api_config_defaults_ok == true); ($local_api_config_defaults_resolved == 1); $local_api_config_defaults_status),
            policy_no_go: (failure_kind(($require_local_api_config_defaults_ok == 1); ($local_api_config_defaults_ok == true); ($local_api_config_defaults_resolved == 1); $local_api_config_defaults_status) == "policy_no_go"),
            execution_failure: (failure_kind(($require_local_api_config_defaults_ok == 1); ($local_api_config_defaults_ok == true); ($local_api_config_defaults_resolved == 1); $local_api_config_defaults_status) == "execution_failure")
          },
          easy_node_config_v1_ok: {
            kind: failure_kind(($require_easy_node_config_v1_ok == 1); ($easy_node_config_v1_ok == true); ($easy_node_config_v1_resolved == 1); $easy_node_config_v1_status),
            policy_no_go: (failure_kind(($require_easy_node_config_v1_ok == 1); ($easy_node_config_v1_ok == true); ($easy_node_config_v1_resolved == 1); $easy_node_config_v1_status) == "policy_no_go"),
            execution_failure: (failure_kind(($require_easy_node_config_v1_ok == 1); ($easy_node_config_v1_ok == true); ($easy_node_config_v1_resolved == 1); $easy_node_config_v1_status) == "execution_failure")
          },
          launcher_wiring_ok: {
            kind: failure_kind(($require_launcher_wiring_ok == 1); ($launcher_wiring_ok == true); ($launcher_wiring_resolved == 1); $launcher_wiring_status),
            policy_no_go: (failure_kind(($require_launcher_wiring_ok == 1); ($launcher_wiring_ok == true); ($launcher_wiring_resolved == 1); $launcher_wiring_status) == "policy_no_go"),
            execution_failure: (failure_kind(($require_launcher_wiring_ok == 1); ($launcher_wiring_ok == true); ($launcher_wiring_resolved == 1); $launcher_wiring_status) == "execution_failure")
          },
          launcher_runtime_ok: {
            kind: failure_kind(($require_launcher_runtime_ok == 1); ($launcher_runtime_ok == true); ($launcher_runtime_resolved == 1); $launcher_runtime_status),
            policy_no_go: (failure_kind(($require_launcher_runtime_ok == 1); ($launcher_runtime_ok == true); ($launcher_runtime_resolved == 1); $launcher_runtime_status) == "policy_no_go"),
            execution_failure: (failure_kind(($require_launcher_runtime_ok == 1); ($launcher_runtime_ok == true); ($launcher_runtime_resolved == 1); $launcher_runtime_status) == "execution_failure")
          },
          windows_native_bootstrap_guardrails_ok: {
            kind: failure_kind(($require_windows_native_bootstrap_guardrails_ok == 1); ($windows_native_bootstrap_guardrails_ok == true); ($windows_native_bootstrap_guardrails_resolved == 1); $windows_native_bootstrap_guardrails_status),
            policy_no_go: (failure_kind(($require_windows_native_bootstrap_guardrails_ok == 1); ($windows_native_bootstrap_guardrails_ok == true); ($windows_native_bootstrap_guardrails_resolved == 1); $windows_native_bootstrap_guardrails_status) == "policy_no_go"),
            execution_failure: (failure_kind(($require_windows_native_bootstrap_guardrails_ok == 1); ($windows_native_bootstrap_guardrails_ok == true); ($windows_native_bootstrap_guardrails_resolved == 1); $windows_native_bootstrap_guardrails_status) == "execution_failure")
          }
        }
      },
      phase3_windows_client_beta_handoff: {
        windows_parity_ok: ($windows_parity_ok == true),
        desktop_contract_ok: ($desktop_contract_ok == true),
        installer_update_ok: ($installer_update_ok == true),
        telemetry_stability_ok: ($telemetry_stability_ok == true)
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
        actionable: (
          [
            actionable_gate("phase3_windows_client_beta_desktop_scaffold_gate"; "desktop_scaffold_ok"; ($require_desktop_scaffold_ok == 1); ($desktop_scaffold_ok == true); ($desktop_scaffold_resolved == 1); $desktop_scaffold_status),
            actionable_gate("phase3_windows_client_beta_local_control_api_gate"; "local_control_api_ok"; ($require_local_control_api_ok == 1); ($local_control_api_ok == true); ($local_control_api_resolved == 1); $local_control_api_status),
            actionable_gate("phase3_windows_client_beta_local_api_config_defaults_gate"; "local_api_config_defaults_ok"; ($require_local_api_config_defaults_ok == 1); ($local_api_config_defaults_ok == true); ($local_api_config_defaults_resolved == 1); $local_api_config_defaults_status),
            actionable_gate("phase3_windows_client_beta_easy_node_config_v1_gate"; "easy_node_config_v1_ok"; ($require_easy_node_config_v1_ok == 1); ($easy_node_config_v1_ok == true); ($easy_node_config_v1_resolved == 1); $easy_node_config_v1_status),
            actionable_gate("phase3_windows_client_beta_launcher_wiring_gate"; "launcher_wiring_ok"; ($require_launcher_wiring_ok == 1); ($launcher_wiring_ok == true); ($launcher_wiring_resolved == 1); $launcher_wiring_status),
            actionable_gate("phase3_windows_client_beta_launcher_runtime_gate"; "launcher_runtime_ok"; ($require_launcher_runtime_ok == 1); ($launcher_runtime_ok == true); ($launcher_runtime_resolved == 1); $launcher_runtime_status),
            actionable_gate("phase3_windows_client_beta_windows_native_bootstrap_guardrails_gate"; "windows_native_bootstrap_guardrails_ok"; ($require_windows_native_bootstrap_guardrails_ok == 1); ($windows_native_bootstrap_guardrails_ok == true); ($windows_native_bootstrap_guardrails_resolved == 1); $windows_native_bootstrap_guardrails_status)
          ] as $all_gates
          | ($all_gates | map(select(.required == true and .ok == false))) as $failed_required
          | {
              count: ($failed_required | length),
              recommended_gate_id: ($failed_required[0].id // null),
              gates: $failed_required
            }
        )
      }
    }' >"$summary_tmp"
  mv -f "$summary_tmp" "$summary_json"
}

need_cmd jq
need_cmd date
need_cmd mktemp

ci_phase3_summary_json="${PHASE3_WINDOWS_CLIENT_BETA_CHECK_CI_PHASE3_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase3_windows_client_beta_ci_summary.json}"
summary_json="${PHASE3_WINDOWS_CLIENT_BETA_CHECK_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase3_windows_client_beta_check_summary.json}"
show_json="${PHASE3_WINDOWS_CLIENT_BETA_CHECK_SHOW_JSON:-0}"
require_desktop_scaffold_ok="${PHASE3_WINDOWS_CLIENT_BETA_CHECK_REQUIRE_DESKTOP_SCAFFOLD_OK:-1}"
require_local_control_api_ok="${PHASE3_WINDOWS_CLIENT_BETA_CHECK_REQUIRE_LOCAL_CONTROL_API_OK:-1}"
require_local_api_config_defaults_ok="${PHASE3_WINDOWS_CLIENT_BETA_CHECK_REQUIRE_LOCAL_API_CONFIG_DEFAULTS_OK:-1}"
require_easy_node_config_v1_ok="${PHASE3_WINDOWS_CLIENT_BETA_CHECK_REQUIRE_EASY_NODE_CONFIG_V1_OK:-1}"
require_launcher_wiring_ok="${PHASE3_WINDOWS_CLIENT_BETA_CHECK_REQUIRE_LAUNCHER_WIRING_OK:-1}"
require_windows_native_bootstrap_guardrails_ok="${PHASE3_WINDOWS_CLIENT_BETA_CHECK_REQUIRE_WINDOWS_NATIVE_BOOTSTRAP_GUARDRAILS_OK:-1}"
require_launcher_runtime_ok="${PHASE3_WINDOWS_CLIENT_BETA_CHECK_REQUIRE_LAUNCHER_RUNTIME_OK:-1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ci-phase3-summary-json)
      ci_phase3_summary_json="${2:-}"
      shift 2
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
    --require-windows-native-bootstrap-guardrails-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_windows_native_bootstrap_guardrails_ok="${2:-}"
        shift 2
      else
        require_windows_native_bootstrap_guardrails_ok="1"
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

bool_arg_or_die "--require-desktop-scaffold-ok" "$require_desktop_scaffold_ok"
bool_arg_or_die "--require-local-control-api-ok" "$require_local_control_api_ok"
bool_arg_or_die "--require-local-api-config-defaults-ok" "$require_local_api_config_defaults_ok"
bool_arg_or_die "--require-easy-node-config-v1-ok" "$require_easy_node_config_v1_ok"
bool_arg_or_die "--require-launcher-wiring-ok" "$require_launcher_wiring_ok"
bool_arg_or_die "--require-windows-native-bootstrap-guardrails-ok" "$require_windows_native_bootstrap_guardrails_ok"
bool_arg_or_die "--require-launcher-runtime-ok" "$require_launcher_runtime_ok"
bool_arg_or_die "--show-json" "$show_json"

ci_phase3_summary_json="$(abs_path "$ci_phase3_summary_json")"
summary_json="$(abs_path "$summary_json")"

mkdir -p "$(dirname "$summary_json")"

generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ci_phase3_summary_usable="$(json_file_valid_01 "$ci_phase3_summary_json")"

declare -a reasons=()

desktop_scaffold_raw=""
local_control_api_raw=""
local_api_config_defaults_raw=""
easy_node_config_v1_raw=""
launcher_wiring_raw=""
windows_native_bootstrap_guardrails_raw=""
launcher_runtime_raw=""

if [[ "$ci_phase3_summary_usable" == "1" ]]; then
  desktop_scaffold_raw="$(resolve_signal_raw_or_empty "$ci_phase3_summary_json" "desktop_scaffold_ok")"
  local_control_api_raw="$(resolve_signal_raw_or_empty "$ci_phase3_summary_json" "local_control_api_ok")"
  local_api_config_defaults_raw="$(resolve_signal_raw_or_empty "$ci_phase3_summary_json" "local_api_config_defaults_ok")"
  easy_node_config_v1_raw="$(resolve_signal_raw_or_empty "$ci_phase3_summary_json" "easy_node_config_v1_ok")"
  launcher_wiring_raw="$(resolve_signal_raw_or_empty "$ci_phase3_summary_json" "launcher_wiring_ok")"
  windows_native_bootstrap_guardrails_raw="$(resolve_signal_raw_or_empty "$ci_phase3_summary_json" "windows_native_bootstrap_guardrails_ok")"
  launcher_runtime_raw="$(resolve_signal_raw_or_empty "$ci_phase3_summary_json" "launcher_runtime_ok")"
else
  reasons+=("ci phase3 summary file not found or invalid JSON: $ci_phase3_summary_json")
fi

desktop_scaffold_ok="$(normalize_boolish_or_empty "$desktop_scaffold_raw")"
local_control_api_ok="$(normalize_boolish_or_empty "$local_control_api_raw")"
local_api_config_defaults_ok="$(normalize_boolish_or_empty "$local_api_config_defaults_raw")"
easy_node_config_v1_ok="$(normalize_boolish_or_empty "$easy_node_config_v1_raw")"
launcher_wiring_ok="$(normalize_boolish_or_empty "$launcher_wiring_raw")"
windows_native_bootstrap_guardrails_ok="$(normalize_boolish_or_empty "$windows_native_bootstrap_guardrails_raw")"
launcher_runtime_ok="$(normalize_boolish_or_empty "$launcher_runtime_raw")"

if [[ -z "$desktop_scaffold_ok" ]]; then
  desktop_scaffold_ok="false"
fi
if [[ -z "$local_control_api_ok" ]]; then
  local_control_api_ok="false"
fi
if [[ -z "$local_api_config_defaults_ok" ]]; then
  local_api_config_defaults_ok="false"
fi
if [[ -z "$easy_node_config_v1_ok" ]]; then
  easy_node_config_v1_ok="false"
fi
if [[ -z "$launcher_wiring_ok" ]]; then
  launcher_wiring_ok="false"
fi
if [[ -z "$windows_native_bootstrap_guardrails_ok" ]]; then
  windows_native_bootstrap_guardrails_ok="false"
fi
if [[ -z "$launcher_runtime_ok" ]]; then
  launcher_runtime_ok="false"
fi

# Canonical Phase-3 handoff aliases for roadmap ingestion.
# Deterministic mapping from existing readiness signals (fail-closed):
# - windows_parity_ok       = desktop_scaffold_ok && local_control_api_ok && launcher_wiring_ok && windows_native_bootstrap_guardrails_ok && launcher_runtime_ok
# - desktop_contract_ok     = desktop_scaffold_ok && local_control_api_ok && windows_native_bootstrap_guardrails_ok
# - installer_update_ok     = easy_node_config_v1_ok && launcher_wiring_ok && windows_native_bootstrap_guardrails_ok
# - telemetry_stability_ok  = local_api_config_defaults_ok && launcher_runtime_ok
windows_parity_ok="false"
desktop_contract_ok="false"
installer_update_ok="false"
telemetry_stability_ok="false"
if [[ "$desktop_scaffold_ok" == "true" && "$local_control_api_ok" == "true" && "$launcher_wiring_ok" == "true" && "$windows_native_bootstrap_guardrails_ok" == "true" && "$launcher_runtime_ok" == "true" ]]; then
  windows_parity_ok="true"
fi
if [[ "$desktop_scaffold_ok" == "true" && "$local_control_api_ok" == "true" && "$windows_native_bootstrap_guardrails_ok" == "true" ]]; then
  desktop_contract_ok="true"
fi
if [[ "$easy_node_config_v1_ok" == "true" && "$launcher_wiring_ok" == "true" && "$windows_native_bootstrap_guardrails_ok" == "true" ]]; then
  installer_update_ok="true"
fi
if [[ "$local_api_config_defaults_ok" == "true" && "$launcher_runtime_ok" == "true" ]]; then
  telemetry_stability_ok="true"
fi

desktop_scaffold_resolved="0"
local_control_api_resolved="0"
local_api_config_defaults_resolved="0"
easy_node_config_v1_resolved="0"
launcher_wiring_resolved="0"
windows_native_bootstrap_guardrails_resolved="0"
launcher_runtime_resolved="0"

desktop_scaffold_status="$(stage_status_from_raw "$desktop_scaffold_raw")"
local_control_api_status="$(stage_status_from_raw "$local_control_api_raw")"
local_api_config_defaults_status="$(stage_status_from_raw "$local_api_config_defaults_raw")"
easy_node_config_v1_status="$(stage_status_from_raw "$easy_node_config_v1_raw")"
launcher_wiring_status="$(stage_status_from_raw "$launcher_wiring_raw")"
windows_native_bootstrap_guardrails_status="$(stage_status_from_raw "$windows_native_bootstrap_guardrails_raw")"
launcher_runtime_status="$(stage_status_from_raw "$launcher_runtime_raw")"

if [[ -n "$(trim "$desktop_scaffold_raw")" ]]; then
  desktop_scaffold_resolved="1"
elif [[ "$ci_phase3_summary_usable" == "1" ]]; then
  reasons+=("desktop_scaffold_ok could not be resolved from ci phase3 summary")
fi
if [[ -n "$(trim "$local_control_api_raw")" ]]; then
  local_control_api_resolved="1"
elif [[ "$ci_phase3_summary_usable" == "1" ]]; then
  reasons+=("local_control_api_ok could not be resolved from ci phase3 summary")
fi
if [[ -n "$(trim "$local_api_config_defaults_raw")" ]]; then
  local_api_config_defaults_resolved="1"
elif [[ "$ci_phase3_summary_usable" == "1" ]]; then
  reasons+=("local_api_config_defaults_ok could not be resolved from ci phase3 summary")
fi
if [[ -n "$(trim "$easy_node_config_v1_raw")" ]]; then
  easy_node_config_v1_resolved="1"
elif [[ "$ci_phase3_summary_usable" == "1" ]]; then
  reasons+=("easy_node_config_v1_ok could not be resolved from ci phase3 summary")
fi
if [[ -n "$(trim "$launcher_wiring_raw")" ]]; then
  launcher_wiring_resolved="1"
elif [[ "$ci_phase3_summary_usable" == "1" ]]; then
  reasons+=("launcher_wiring_ok could not be resolved from ci phase3 summary")
fi
if [[ -n "$(trim "$windows_native_bootstrap_guardrails_raw")" ]]; then
  windows_native_bootstrap_guardrails_resolved="1"
elif [[ "$ci_phase3_summary_usable" == "1" ]]; then
  reasons+=("windows_native_bootstrap_guardrails_ok could not be resolved from ci phase3 summary")
fi
if [[ -n "$(trim "$launcher_runtime_raw")" ]]; then
  launcher_runtime_resolved="1"
elif [[ "$ci_phase3_summary_usable" == "1" ]]; then
  reasons+=("launcher_runtime_ok could not be resolved from ci phase3 summary")
fi

if [[ "$require_desktop_scaffold_ok" == "1" && "$desktop_scaffold_ok" != "true" ]]; then
  reasons+=("desktop_scaffold_ok is false")
fi
if [[ "$require_local_control_api_ok" == "1" && "$local_control_api_ok" != "true" ]]; then
  reasons+=("local_control_api_ok is false")
fi
if [[ "$require_local_api_config_defaults_ok" == "1" && "$local_api_config_defaults_ok" != "true" ]]; then
  reasons+=("local_api_config_defaults_ok is false")
fi
if [[ "$require_easy_node_config_v1_ok" == "1" && "$easy_node_config_v1_ok" != "true" ]]; then
  reasons+=("easy_node_config_v1_ok is false")
fi
if [[ "$require_launcher_wiring_ok" == "1" && "$launcher_wiring_ok" != "true" ]]; then
  reasons+=("launcher_wiring_ok is false")
fi
if [[ "$require_windows_native_bootstrap_guardrails_ok" == "1" && "$windows_native_bootstrap_guardrails_ok" != "true" ]]; then
  reasons+=("windows_native_bootstrap_guardrails_ok is false")
fi
if [[ "$require_launcher_runtime_ok" == "1" && "$launcher_runtime_ok" != "true" ]]; then
  reasons+=("launcher_runtime_ok is false")
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
  if [[ "$ci_phase3_summary_usable" != "1" ]]; then
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
  if [[ "$require_windows_native_bootstrap_guardrails_ok" == "1" && "$windows_native_bootstrap_guardrails_ok" != "true" && "$windows_native_bootstrap_guardrails_resolved" != "1" ]]; then
    final_failure_kind="execution_failure"
    policy_outcome_decision="ERROR"
  fi
  if [[ "$require_launcher_runtime_ok" == "1" && "$launcher_runtime_ok" != "true" && "$launcher_runtime_resolved" != "1" ]]; then
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
  "$ci_phase3_summary_json" \
  "$ci_phase3_summary_usable" \
  "$show_json" \
  "$require_desktop_scaffold_ok" \
  "$require_local_control_api_ok" \
  "$require_local_api_config_defaults_ok" \
  "$require_easy_node_config_v1_ok" \
  "$require_launcher_wiring_ok" \
  "$require_launcher_runtime_ok" \
  "$desktop_scaffold_status" \
  "$local_control_api_status" \
  "$local_api_config_defaults_status" \
  "$easy_node_config_v1_status" \
  "$launcher_wiring_status" \
  "$launcher_runtime_status" \
  "$desktop_scaffold_ok" \
  "$local_control_api_ok" \
  "$local_api_config_defaults_ok" \
  "$easy_node_config_v1_ok" \
  "$launcher_wiring_ok" \
  "$launcher_runtime_ok" \
  "$desktop_scaffold_resolved" \
  "$local_control_api_resolved" \
  "$local_api_config_defaults_resolved" \
  "$easy_node_config_v1_resolved" \
  "$launcher_wiring_resolved" \
  "$launcher_runtime_resolved" \
  "$windows_parity_ok" \
  "$desktop_contract_ok" \
  "$installer_update_ok" \
  "$telemetry_stability_ok" \
  "$final_failure_kind" \
  "$policy_outcome_decision" \
  "$reasons_json" \
  "$require_windows_native_bootstrap_guardrails_ok" \
  "$windows_native_bootstrap_guardrails_status" \
  "$windows_native_bootstrap_guardrails_ok" \
  "$windows_native_bootstrap_guardrails_resolved"

if [[ "$show_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$status" == "pass" ]]; then
  exit 0
fi
exit 1
