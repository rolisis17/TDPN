#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase5_settlement_layer_handoff_check.sh \
    [--phase5-run-summary-json PATH] \
    [--roadmap-summary-json PATH] \
    [--require-run-pipeline-ok [0|1]] \
    [--require-settlement-failsoft-ok [0|1]] \
    [--require-settlement-acceptance-ok [0|1]] \
    [--require-settlement-bridge-smoke-ok [0|1]] \
    [--require-settlement-state-persistence-ok [0|1]] \
    [--require-settlement-dual-asset-parity-ok [0|1]] \
    [--require-issuer-sponsor-api-live-smoke-ok [0|1]] \
    [--require-issuer-admin-blockchain-handlers-coverage-ok [0|1]] \
    [--summary-json PATH] \
    [--show-json [0|1]]

Purpose:
  Fail-closed checker for the Phase-5 settlement layer handoff.
  Evaluates the run pipeline and handoff readiness booleans.

Notes:
  - The checker prefers readiness booleans from the roadmap summary at:
      .vpn_track.phase5_settlement_layer_handoff.*
  - If needed, it falls back to the nested check summary referenced by the
    run artifacts.
  - run_pipeline_ok is true only when the run summary contract is valid and
    both run steps pass with valid contracts.
  - Legacy compatibility: --phase4-run-summary-json is accepted as an alias
    for --phase5-run-summary-json.
  - Legacy requirement aliases are accepted:
      --require-windows-server-packaging-ok -> --require-settlement-failsoft-ok
      --require-windows-role-runbooks-ok -> --require-settlement-acceptance-ok
      --require-cross-platform-interop-ok -> --require-settlement-bridge-smoke-ok
      --require-role-combination-validation-ok -> --require-settlement-state-persistence-ok
      --require-settlement-dual-asset-ok -> --require-settlement-dual-asset-parity-ok
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
  jq -r "($expr) | if . == null then empty else . end" "$path" 2>/dev/null || true
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
    and (.schema.id // "") == "phase5_settlement_layer_run_summary"
    and ((.status | type) == "string")
    and ((.rc | type) == "number")
    and ((.steps.ci_phase5_settlement_layer.status | type) == "string")
    and ((.steps.ci_phase5_settlement_layer.rc | type) == "number")
    and ((.steps.ci_phase5_settlement_layer.command_rc | type) == "number")
    and ((.steps.ci_phase5_settlement_layer.contract_valid | type) == "boolean")
    and ((.steps.phase5_settlement_layer_check.status | type) == "string")
    and ((.steps.phase5_settlement_layer_check.rc | type) == "number")
    and ((.steps.phase5_settlement_layer_check.command_rc | type) == "number")
    and ((.steps.phase5_settlement_layer_check.contract_valid | type) == "boolean")
  ' "$run_summary_json" >/dev/null 2>&1; then
    contract_valid="1"
  fi

  local ci_status=""
  local ci_contract_valid="0"
  local check_status=""
  local check_contract_valid="0"
  ci_status="$(json_text_or_empty "$run_summary_json" '.steps.ci_phase5_settlement_layer.status')"
  check_status="$(json_text_or_empty "$run_summary_json" '.steps.phase5_settlement_layer_check.status')"
  if [[ "$(json_bool_or_empty "$run_summary_json" '.steps.ci_phase5_settlement_layer.contract_valid')" == "true" ]]; then
    ci_contract_valid="1"
  fi
  if [[ "$(json_bool_or_empty "$run_summary_json" '.steps.phase5_settlement_layer_check.contract_valid')" == "true" ]]; then
    check_contract_valid="1"
  fi

  if [[ "$contract_valid" != "1" ]]; then
    value="false"
    status="invalid"
    source="phase5_run_summary.contract"
    resolved="1"
  elif [[ "$ci_status" != "pass" || "$ci_contract_valid" != "1" ]]; then
    value="false"
    status="fail"
    source="phase5_run_summary.steps.ci_phase5_settlement_layer"
    resolved="1"
  elif [[ "$check_status" != "pass" || "$check_contract_valid" != "1" ]]; then
    value="false"
    status="fail"
    source="phase5_run_summary.steps.phase5_settlement_layer_check"
    resolved="1"
  else
    value="true"
    status="pass"
    source="phase5_run_summary"
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
    value="$(json_bool_or_empty "$roadmap_summary_json" "if (.vpn_track.phase5_settlement_layer_handoff.$signal | type) == \"boolean\" then .vpn_track.phase5_settlement_layer_handoff.$signal elif (.phase5_settlement_layer_handoff.$signal | type) == \"boolean\" then .phase5_settlement_layer_handoff.$signal else empty end")"
    if [[ -n "$value" ]]; then
      status="$( [[ "$value" == "true" ]] && printf '%s' "pass" || printf '%s' "fail" )"
      source="roadmap_progress_summary.vpn_track.phase5_settlement_layer_handoff.$signal"
      resolved="1"
      printf '%s|%s|%s|%s\n' "$value" "$status" "$source" "$resolved"
      return
    fi
  fi

  if [[ "$run_summary_usable" == "1" ]]; then
    local check_summary_json=""
    check_summary_json="$(json_text_or_empty "$run_summary_json" '.steps.phase5_settlement_layer_check.artifacts.summary_json // .artifacts.check_summary_json')"
    if [[ -n "$check_summary_json" ]]; then
      check_summary_json="$(resolve_path_with_base "$check_summary_json" "$run_summary_json")"
      if [[ "$(json_file_valid_01 "$check_summary_json")" == "1" ]]; then
        value="$(json_bool_or_empty "$check_summary_json" "if (.signals.$signal | type) == \"boolean\" then .signals.$signal elif (.handoff.$signal | type) == \"boolean\" then .handoff.$signal elif (.phase5_settlement_layer_handoff.$signal | type) == \"boolean\" then .phase5_settlement_layer_handoff.$signal elif (.vpn_track.phase5_settlement_layer_handoff.$signal | type) == \"boolean\" then .vpn_track.phase5_settlement_layer_handoff.$signal else empty end")"
        if [[ -n "$value" ]]; then
          status="$( [[ "$value" == "true" ]] && printf '%s' "pass" || printf '%s' "fail" )"
          source="phase5_settlement_layer_check_summary.$signal"
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
  local phase5_run_summary_json="$5"
  local roadmap_summary_json="$6"
  local run_summary_usable="$7"
  local roadmap_summary_usable="$8"
  local show_json="$9"
  local require_run_pipeline_ok="${10}"
  local require_settlement_failsoft_ok="${11}"
  local require_settlement_acceptance_ok="${12}"
  local require_settlement_bridge_smoke_ok="${13}"
  local require_settlement_state_persistence_ok="${14}"
  local run_pipeline_status="${15}"
  local run_pipeline_ok="${16}"
  local run_pipeline_resolved="${17}"
  local run_pipeline_source="${18}"
  local run_pipeline_contract_valid="${19}"
  local settlement_failsoft_status="${20}"
  local settlement_acceptance_status="${21}"
  local settlement_bridge_smoke_status="${22}"
  local settlement_state_persistence_status="${23}"
  local settlement_failsoft_ok="${24}"
  local settlement_acceptance_ok="${25}"
  local settlement_bridge_smoke_ok="${26}"
  local settlement_state_persistence_ok="${27}"
  local settlement_failsoft_resolved="${28}"
  local settlement_acceptance_resolved="${29}"
  local settlement_bridge_smoke_resolved="${30}"
  local settlement_state_persistence_resolved="${31}"
  local settlement_failsoft_source="${32}"
  local settlement_acceptance_source="${33}"
  local settlement_bridge_smoke_source="${34}"
  local settlement_state_persistence_source="${35}"
  local reasons_json="${36}"
  local require_issuer_sponsor_api_live_smoke_ok="${37}"
  local issuer_sponsor_api_live_smoke_status="${38}"
  local issuer_sponsor_api_live_smoke_ok="${39}"
  local issuer_sponsor_api_live_smoke_resolved="${40}"
  local issuer_sponsor_api_live_smoke_source="${41}"
  local require_settlement_dual_asset_parity_ok="${42}"
  local settlement_dual_asset_parity_status="${43}"
  local settlement_dual_asset_parity_ok="${44}"
  local settlement_dual_asset_parity_resolved="${45}"
  local settlement_dual_asset_parity_source="${46}"
  local require_issuer_admin_blockchain_handlers_coverage_ok="${47}"
  local issuer_admin_blockchain_handlers_coverage_status="${48}"
  local issuer_admin_blockchain_handlers_coverage_ok="${49}"
  local issuer_admin_blockchain_handlers_coverage_resolved="${50}"
  local issuer_admin_blockchain_handlers_coverage_source="${51}"

  local summary_tmp
  summary_tmp="$(mktemp)"
  jq -n \
    --arg generated_at_utc "$generated_at_utc" \
    --arg status "$status" \
    --argjson rc "$rc" \
    --arg summary_json "$summary_json" \
    --arg canonical_summary_json "$canonical_summary_json" \
    --arg phase5_run_summary_json "$phase5_run_summary_json" \
    --arg roadmap_summary_json "$roadmap_summary_json" \
    --argjson run_summary_usable "$run_summary_usable" \
    --argjson roadmap_summary_usable "$roadmap_summary_usable" \
    --arg show_json "$show_json" \
    --argjson require_run_pipeline_ok "$require_run_pipeline_ok" \
    --argjson require_settlement_failsoft_ok "$require_settlement_failsoft_ok" \
    --argjson require_settlement_acceptance_ok "$require_settlement_acceptance_ok" \
    --argjson require_settlement_bridge_smoke_ok "$require_settlement_bridge_smoke_ok" \
    --argjson require_settlement_state_persistence_ok "$require_settlement_state_persistence_ok" \
    --argjson require_settlement_dual_asset_parity_ok "$require_settlement_dual_asset_parity_ok" \
    --argjson require_issuer_sponsor_api_live_smoke_ok "$require_issuer_sponsor_api_live_smoke_ok" \
    --argjson require_issuer_admin_blockchain_handlers_coverage_ok "$require_issuer_admin_blockchain_handlers_coverage_ok" \
    --arg run_pipeline_status "$run_pipeline_status" \
    --argjson run_pipeline_ok "$run_pipeline_ok" \
    --argjson run_pipeline_resolved "$run_pipeline_resolved" \
    --arg run_pipeline_source "$run_pipeline_source" \
    --argjson run_pipeline_contract_valid "$run_pipeline_contract_valid" \
    --arg settlement_failsoft_status "$settlement_failsoft_status" \
    --arg settlement_acceptance_status "$settlement_acceptance_status" \
    --arg settlement_bridge_smoke_status "$settlement_bridge_smoke_status" \
    --arg settlement_state_persistence_status "$settlement_state_persistence_status" \
    --argjson settlement_failsoft_ok "$settlement_failsoft_ok" \
    --argjson settlement_acceptance_ok "$settlement_acceptance_ok" \
    --argjson settlement_bridge_smoke_ok "$settlement_bridge_smoke_ok" \
    --argjson settlement_state_persistence_ok "$settlement_state_persistence_ok" \
    --argjson settlement_failsoft_resolved "$settlement_failsoft_resolved" \
    --argjson settlement_acceptance_resolved "$settlement_acceptance_resolved" \
    --argjson settlement_bridge_smoke_resolved "$settlement_bridge_smoke_resolved" \
    --argjson settlement_state_persistence_resolved "$settlement_state_persistence_resolved" \
    --arg settlement_failsoft_source "$settlement_failsoft_source" \
    --arg settlement_acceptance_source "$settlement_acceptance_source" \
    --arg settlement_bridge_smoke_source "$settlement_bridge_smoke_source" \
    --arg settlement_state_persistence_source "$settlement_state_persistence_source" \
    --arg settlement_dual_asset_parity_status "$settlement_dual_asset_parity_status" \
    --argjson settlement_dual_asset_parity_ok "$settlement_dual_asset_parity_ok" \
    --argjson settlement_dual_asset_parity_resolved "$settlement_dual_asset_parity_resolved" \
    --arg settlement_dual_asset_parity_source "$settlement_dual_asset_parity_source" \
    --arg issuer_sponsor_api_live_smoke_status "$issuer_sponsor_api_live_smoke_status" \
    --argjson issuer_sponsor_api_live_smoke_ok "$issuer_sponsor_api_live_smoke_ok" \
    --argjson issuer_sponsor_api_live_smoke_resolved "$issuer_sponsor_api_live_smoke_resolved" \
    --arg issuer_sponsor_api_live_smoke_source "$issuer_sponsor_api_live_smoke_source" \
    --arg issuer_admin_blockchain_handlers_coverage_status "$issuer_admin_blockchain_handlers_coverage_status" \
    --argjson issuer_admin_blockchain_handlers_coverage_ok "$issuer_admin_blockchain_handlers_coverage_ok" \
    --argjson issuer_admin_blockchain_handlers_coverage_resolved "$issuer_admin_blockchain_handlers_coverage_resolved" \
    --arg issuer_admin_blockchain_handlers_coverage_source "$issuer_admin_blockchain_handlers_coverage_source" \
    --argjson reasons "$reasons_json" \
    '{
      version: 1,
      schema: {
        id: "phase5_settlement_layer_handoff_check_summary",
        major: 1,
        minor: 0
      },
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $rc,
      fail_closed: true,
      metadata: {
        contract: "phase5-settlement-layer",
        script: "phase5_settlement_layer_handoff_check.sh"
      },
      inputs: {
        phase5_run_summary_json: (if $phase5_run_summary_json == "" then null else $phase5_run_summary_json end),
        phase4_run_summary_json: (if $phase5_run_summary_json == "" then null else $phase5_run_summary_json end),
        roadmap_summary_json: (if $roadmap_summary_json == "" then null else $roadmap_summary_json end),
        show_json: ($show_json == "1"),
        requirements: {
          run_pipeline_ok: ($require_run_pipeline_ok == 1),
          settlement_failsoft_ok: ($require_settlement_failsoft_ok == 1),
          settlement_acceptance_ok: ($require_settlement_acceptance_ok == 1),
          settlement_bridge_smoke_ok: ($require_settlement_bridge_smoke_ok == 1),
          settlement_state_persistence_ok: ($require_settlement_state_persistence_ok == 1),
          settlement_dual_asset_parity_ok: ($require_settlement_dual_asset_parity_ok == 1),
          issuer_sponsor_api_live_smoke_ok: ($require_issuer_sponsor_api_live_smoke_ok == 1),
          issuer_admin_blockchain_handlers_coverage_ok: ($require_issuer_admin_blockchain_handlers_coverage_ok == 1)
        },
        usable: {
          phase5_run_summary_json: ($run_summary_usable == 1),
          phase4_run_summary_json: ($run_summary_usable == 1),
          roadmap_summary_json: ($roadmap_summary_usable == 1)
        }
      },
      handoff: {
        run_pipeline_ok: $run_pipeline_ok,
        run_pipeline_status: $run_pipeline_status,
        run_pipeline_resolved: ($run_pipeline_resolved == 1),
        run_pipeline_contract_valid: ($run_pipeline_contract_valid == 1),
        settlement_failsoft_ok: $settlement_failsoft_ok,
        settlement_failsoft_status: $settlement_failsoft_status,
        settlement_failsoft_resolved: ($settlement_failsoft_resolved == 1),
        settlement_acceptance_ok: $settlement_acceptance_ok,
        settlement_acceptance_status: $settlement_acceptance_status,
        settlement_acceptance_resolved: ($settlement_acceptance_resolved == 1),
        settlement_bridge_smoke_ok: $settlement_bridge_smoke_ok,
        settlement_bridge_smoke_status: $settlement_bridge_smoke_status,
        settlement_bridge_smoke_resolved: ($settlement_bridge_smoke_resolved == 1),
        settlement_state_persistence_ok: $settlement_state_persistence_ok,
        settlement_state_persistence_status: $settlement_state_persistence_status,
        settlement_state_persistence_resolved: ($settlement_state_persistence_resolved == 1),
        settlement_dual_asset_parity_ok: $settlement_dual_asset_parity_ok,
        settlement_dual_asset_parity_status: $settlement_dual_asset_parity_status,
        settlement_dual_asset_parity_resolved: ($settlement_dual_asset_parity_resolved == 1),
        issuer_sponsor_api_live_smoke_ok: $issuer_sponsor_api_live_smoke_ok,
        issuer_sponsor_api_live_smoke_status: $issuer_sponsor_api_live_smoke_status,
        issuer_sponsor_api_live_smoke_resolved: ($issuer_sponsor_api_live_smoke_resolved == 1),
        issuer_admin_blockchain_handlers_coverage_ok: $issuer_admin_blockchain_handlers_coverage_ok,
        issuer_admin_blockchain_handlers_coverage_status: $issuer_admin_blockchain_handlers_coverage_status,
        issuer_admin_blockchain_handlers_coverage_resolved: ($issuer_admin_blockchain_handlers_coverage_resolved == 1),
        sources: {
          run_pipeline_ok: $run_pipeline_source,
          settlement_failsoft_ok: $settlement_failsoft_source,
          settlement_acceptance_ok: $settlement_acceptance_source,
          settlement_bridge_smoke_ok: $settlement_bridge_smoke_source,
          settlement_state_persistence_ok: $settlement_state_persistence_source,
          settlement_dual_asset_parity_ok: $settlement_dual_asset_parity_source,
          issuer_sponsor_api_live_smoke_ok: $issuer_sponsor_api_live_smoke_source,
          issuer_admin_blockchain_handlers_coverage_ok: $issuer_admin_blockchain_handlers_coverage_source
        }
      },
      decision: {
        pass: ($status == "pass"),
        reasons: $reasons,
        warnings: []
      },
      artifacts: {
        summary_json: $summary_json,
        canonical_summary_json: $canonical_summary_json
      }
    }' >"$summary_tmp"
  mv -f "$summary_tmp" "$summary_json"
  if [[ "$summary_json" != "$canonical_summary_json" ]]; then
    cp -f "$summary_json" "$canonical_summary_json"
  fi
}

need_cmd jq
need_cmd date
need_cmd mktemp

phase5_run_summary_json="${PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_PHASE5_RUN_SUMMARY_JSON:-${PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_PHASE4_RUN_SUMMARY_JSON:-}}"
roadmap_summary_json="${PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_ROADMAP_SUMMARY_JSON:-}"
summary_json="${PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase5_settlement_layer_handoff_check_summary.json}"
canonical_summary_json="${PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_CANONICAL_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase5_settlement_layer_handoff_check_summary.json}"
show_json="${PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_SHOW_JSON:-0}"
require_run_pipeline_ok="${PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_REQUIRE_RUN_PIPELINE_OK:-1}"
require_settlement_failsoft_ok="${PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_REQUIRE_SETTLEMENT_FAILSOFT_OK:-${PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_REQUIRE_WINDOWS_SERVER_PACKAGING_OK:-1}}"
require_settlement_acceptance_ok="${PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_REQUIRE_SETTLEMENT_ACCEPTANCE_OK:-${PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_REQUIRE_WINDOWS_ROLE_RUNBOOKS_OK:-1}}"
require_settlement_bridge_smoke_ok="${PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_REQUIRE_SETTLEMENT_BRIDGE_SMOKE_OK:-${PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_REQUIRE_CROSS_PLATFORM_INTEROP_OK:-1}}"
require_settlement_state_persistence_ok="${PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_REQUIRE_SETTLEMENT_STATE_PERSISTENCE_OK:-${PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_REQUIRE_ROLE_COMBINATION_VALIDATION_OK:-1}}"
require_settlement_dual_asset_parity_ok="${PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_REQUIRE_SETTLEMENT_DUAL_ASSET_PARITY_OK:-${PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_REQUIRE_SETTLEMENT_DUAL_ASSET_OK:-1}}"
require_issuer_sponsor_api_live_smoke_ok="${PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_REQUIRE_ISSUER_SPONSOR_API_LIVE_SMOKE_OK:-1}"
require_issuer_admin_blockchain_handlers_coverage_ok="${PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_REQUIRE_ISSUER_ADMIN_BLOCKCHAIN_HANDLERS_COVERAGE_OK:-1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --phase5-run-summary-json)
      phase5_run_summary_json="${2:-}"
      shift 2
      ;;
    --phase4-run-summary-json)
      phase5_run_summary_json="${2:-}"
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
    --require-settlement-failsoft-ok|--require-windows-server-packaging-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_settlement_failsoft_ok="${2:-}"
        shift 2
      else
        require_settlement_failsoft_ok="1"
        shift
      fi
      ;;
    --require-settlement-acceptance-ok|--require-windows-role-runbooks-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_settlement_acceptance_ok="${2:-}"
        shift 2
      else
        require_settlement_acceptance_ok="1"
        shift
      fi
      ;;
    --require-settlement-bridge-smoke-ok|--require-cross-platform-interop-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_settlement_bridge_smoke_ok="${2:-}"
        shift 2
      else
        require_settlement_bridge_smoke_ok="1"
        shift
      fi
      ;;
    --require-settlement-state-persistence-ok|--require-role-combination-validation-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_settlement_state_persistence_ok="${2:-}"
        shift 2
      else
        require_settlement_state_persistence_ok="1"
        shift
      fi
      ;;
    --require-settlement-dual-asset-parity-ok|--require-settlement-dual-asset-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_settlement_dual_asset_parity_ok="${2:-}"
        shift 2
      else
        require_settlement_dual_asset_parity_ok="1"
        shift
      fi
      ;;
    --require-issuer-sponsor-api-live-smoke-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_issuer_sponsor_api_live_smoke_ok="${2:-}"
        shift 2
      else
        require_issuer_sponsor_api_live_smoke_ok="1"
        shift
      fi
      ;;
    --require-issuer-admin-blockchain-handlers-coverage-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_issuer_admin_blockchain_handlers_coverage_ok="${2:-}"
        shift 2
      else
        require_issuer_admin_blockchain_handlers_coverage_ok="1"
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
bool_arg_or_die "--require-settlement-failsoft-ok" "$require_settlement_failsoft_ok"
bool_arg_or_die "--require-settlement-acceptance-ok" "$require_settlement_acceptance_ok"
bool_arg_or_die "--require-settlement-bridge-smoke-ok" "$require_settlement_bridge_smoke_ok"
bool_arg_or_die "--require-settlement-state-persistence-ok" "$require_settlement_state_persistence_ok"
bool_arg_or_die "--require-settlement-dual-asset-parity-ok" "$require_settlement_dual_asset_parity_ok"
bool_arg_or_die "--require-issuer-sponsor-api-live-smoke-ok" "$require_issuer_sponsor_api_live_smoke_ok"
bool_arg_or_die "--require-issuer-admin-blockchain-handlers-coverage-ok" "$require_issuer_admin_blockchain_handlers_coverage_ok"
bool_arg_or_die "--show-json" "$show_json"

phase5_run_summary_json="$(abs_path "$phase5_run_summary_json")"
roadmap_summary_json="$(abs_path "$roadmap_summary_json")"
summary_json="$(abs_path "$summary_json")"
canonical_summary_json="$(abs_path "$canonical_summary_json")"

mkdir -p "$(dirname "$summary_json")"
mkdir -p "$(dirname "$canonical_summary_json")"

generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

declare -a reasons=()

phase5_run_summary_usable="0"
roadmap_summary_usable="0"
run_pipeline_contract_valid="0"
run_pipeline_value="null"
run_pipeline_status="missing"
run_pipeline_resolved="0"
run_pipeline_source="unresolved"

if [[ -n "$phase5_run_summary_json" ]]; then
  if [[ "$(json_file_valid_01 "$phase5_run_summary_json")" == "1" ]]; then
    phase5_run_summary_usable="1"
  else
    reasons+=("phase5 run summary file not found or invalid JSON: $phase5_run_summary_json")
  fi
fi

if [[ -n "$roadmap_summary_json" ]]; then
  if [[ "$(json_file_valid_01 "$roadmap_summary_json")" == "1" ]]; then
    roadmap_summary_usable="1"
  else
    reasons+=("roadmap summary file not found or invalid JSON: $roadmap_summary_json")
  fi
fi

if [[ "$phase5_run_summary_usable" == "1" ]]; then
  run_pipeline_pair="$(resolve_run_pipeline "$phase5_run_summary_json" "$phase5_run_summary_usable")"
  run_pipeline_value="${run_pipeline_pair%%|*}"
  run_pipeline_pair="${run_pipeline_pair#*|}"
  run_pipeline_status="${run_pipeline_pair%%|*}"
  run_pipeline_pair="${run_pipeline_pair#*|}"
  run_pipeline_source="${run_pipeline_pair%%|*}"
  run_pipeline_pair="${run_pipeline_pair#*|}"
  run_pipeline_resolved="${run_pipeline_pair%%|*}"
  run_pipeline_contract_valid="${run_pipeline_pair##*|}"
  if [[ "$run_pipeline_status" == "invalid" ]]; then
    reasons+=("phase5 run summary contract is invalid")
  elif [[ "$run_pipeline_status" == "fail" ]]; then
    reasons+=("run pipeline is not ready")
  fi
else
  reasons+=("phase5 run summary is unavailable")
fi

settlement_failsoft_pair="$(resolve_handoff_bool "settlement_failsoft_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase5_run_summary_json" "$phase5_run_summary_usable")"
settlement_acceptance_pair="$(resolve_handoff_bool "settlement_acceptance_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase5_run_summary_json" "$phase5_run_summary_usable")"
settlement_bridge_smoke_pair="$(resolve_handoff_bool "settlement_bridge_smoke_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase5_run_summary_json" "$phase5_run_summary_usable")"
settlement_state_persistence_pair="$(resolve_handoff_bool "settlement_state_persistence_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase5_run_summary_json" "$phase5_run_summary_usable")"
settlement_dual_asset_parity_pair="$(resolve_handoff_bool "settlement_dual_asset_parity_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase5_run_summary_json" "$phase5_run_summary_usable")"
issuer_sponsor_api_live_smoke_pair="$(resolve_handoff_bool "issuer_sponsor_api_live_smoke_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase5_run_summary_json" "$phase5_run_summary_usable")"
issuer_admin_blockchain_handlers_coverage_pair="$(resolve_handoff_bool "issuer_admin_blockchain_handlers_coverage_ok" "$roadmap_summary_json" "$roadmap_summary_usable" "$phase5_run_summary_json" "$phase5_run_summary_usable")"

settlement_failsoft_ok="${settlement_failsoft_pair%%|*}"
settlement_failsoft_pair="${settlement_failsoft_pair#*|}"
settlement_failsoft_status="${settlement_failsoft_pair%%|*}"
settlement_failsoft_pair="${settlement_failsoft_pair#*|}"
settlement_failsoft_source="${settlement_failsoft_pair%%|*}"
settlement_failsoft_resolved="${settlement_failsoft_pair##*|}"

settlement_acceptance_ok="${settlement_acceptance_pair%%|*}"
settlement_acceptance_pair="${settlement_acceptance_pair#*|}"
settlement_acceptance_status="${settlement_acceptance_pair%%|*}"
settlement_acceptance_pair="${settlement_acceptance_pair#*|}"
settlement_acceptance_source="${settlement_acceptance_pair%%|*}"
settlement_acceptance_resolved="${settlement_acceptance_pair##*|}"

settlement_bridge_smoke_ok="${settlement_bridge_smoke_pair%%|*}"
settlement_bridge_smoke_pair="${settlement_bridge_smoke_pair#*|}"
settlement_bridge_smoke_status="${settlement_bridge_smoke_pair%%|*}"
settlement_bridge_smoke_pair="${settlement_bridge_smoke_pair#*|}"
settlement_bridge_smoke_source="${settlement_bridge_smoke_pair%%|*}"
settlement_bridge_smoke_resolved="${settlement_bridge_smoke_pair##*|}"

settlement_state_persistence_ok="${settlement_state_persistence_pair%%|*}"
settlement_state_persistence_pair="${settlement_state_persistence_pair#*|}"
settlement_state_persistence_status="${settlement_state_persistence_pair%%|*}"
settlement_state_persistence_pair="${settlement_state_persistence_pair#*|}"
settlement_state_persistence_source="${settlement_state_persistence_pair%%|*}"
settlement_state_persistence_resolved="${settlement_state_persistence_pair##*|}"

settlement_dual_asset_parity_ok="${settlement_dual_asset_parity_pair%%|*}"
settlement_dual_asset_parity_pair="${settlement_dual_asset_parity_pair#*|}"
settlement_dual_asset_parity_status="${settlement_dual_asset_parity_pair%%|*}"
settlement_dual_asset_parity_pair="${settlement_dual_asset_parity_pair#*|}"
settlement_dual_asset_parity_source="${settlement_dual_asset_parity_pair%%|*}"
settlement_dual_asset_parity_resolved="${settlement_dual_asset_parity_pair##*|}"

issuer_sponsor_api_live_smoke_ok="${issuer_sponsor_api_live_smoke_pair%%|*}"
issuer_sponsor_api_live_smoke_pair="${issuer_sponsor_api_live_smoke_pair#*|}"
issuer_sponsor_api_live_smoke_status="${issuer_sponsor_api_live_smoke_pair%%|*}"
issuer_sponsor_api_live_smoke_pair="${issuer_sponsor_api_live_smoke_pair#*|}"
issuer_sponsor_api_live_smoke_source="${issuer_sponsor_api_live_smoke_pair%%|*}"
issuer_sponsor_api_live_smoke_resolved="${issuer_sponsor_api_live_smoke_pair##*|}"

issuer_admin_blockchain_handlers_coverage_ok="${issuer_admin_blockchain_handlers_coverage_pair%%|*}"
issuer_admin_blockchain_handlers_coverage_pair="${issuer_admin_blockchain_handlers_coverage_pair#*|}"
issuer_admin_blockchain_handlers_coverage_status="${issuer_admin_blockchain_handlers_coverage_pair%%|*}"
issuer_admin_blockchain_handlers_coverage_pair="${issuer_admin_blockchain_handlers_coverage_pair#*|}"
issuer_admin_blockchain_handlers_coverage_source="${issuer_admin_blockchain_handlers_coverage_pair%%|*}"
issuer_admin_blockchain_handlers_coverage_resolved="${issuer_admin_blockchain_handlers_coverage_pair##*|}"

if [[ "$require_run_pipeline_ok" == "1" && "$run_pipeline_value" != "true" ]]; then
  if [[ "$run_pipeline_status" == "missing" ]]; then
    reasons+=("run_pipeline_ok unresolved from provided artifacts")
  else
    reasons+=("run_pipeline_ok is false")
  fi
fi
if [[ "$require_settlement_failsoft_ok" == "1" && "$settlement_failsoft_ok" != "true" ]]; then
  if [[ "$settlement_failsoft_status" == "missing" ]]; then
    reasons+=("settlement_failsoft_ok unresolved from provided artifacts")
  else
    reasons+=("settlement_failsoft_ok is false")
  fi
fi
if [[ "$require_settlement_acceptance_ok" == "1" && "$settlement_acceptance_ok" != "true" ]]; then
  if [[ "$settlement_acceptance_status" == "missing" ]]; then
    reasons+=("settlement_acceptance_ok unresolved from provided artifacts")
  else
    reasons+=("settlement_acceptance_ok is false")
  fi
fi
if [[ "$require_settlement_bridge_smoke_ok" == "1" && "$settlement_bridge_smoke_ok" != "true" ]]; then
  if [[ "$settlement_bridge_smoke_status" == "missing" ]]; then
    reasons+=("settlement_bridge_smoke_ok unresolved from provided artifacts")
  else
    reasons+=("settlement_bridge_smoke_ok is false")
  fi
fi
if [[ "$require_settlement_state_persistence_ok" == "1" && "$settlement_state_persistence_ok" != "true" ]]; then
  if [[ "$settlement_state_persistence_status" == "missing" ]]; then
    reasons+=("settlement_state_persistence_ok unresolved from provided artifacts")
  else
    reasons+=("settlement_state_persistence_ok is false")
  fi
fi
if [[ "$require_settlement_dual_asset_parity_ok" == "1" && "$settlement_dual_asset_parity_ok" != "true" ]]; then
  if [[ "$settlement_dual_asset_parity_status" == "missing" ]]; then
    reasons+=("settlement_dual_asset_parity_ok unresolved from provided artifacts")
  else
    reasons+=("settlement_dual_asset_parity_ok is false")
  fi
fi
if [[ "$require_issuer_sponsor_api_live_smoke_ok" == "1" && "$issuer_sponsor_api_live_smoke_ok" != "true" ]]; then
  if [[ "$issuer_sponsor_api_live_smoke_status" == "missing" ]]; then
    reasons+=("issuer_sponsor_api_live_smoke_ok unresolved from provided artifacts")
  else
    reasons+=("issuer_sponsor_api_live_smoke_ok is false")
  fi
fi
if [[ "$require_issuer_admin_blockchain_handlers_coverage_ok" == "1" && "$issuer_admin_blockchain_handlers_coverage_ok" != "true" ]]; then
  if [[ "$issuer_admin_blockchain_handlers_coverage_status" == "missing" ]]; then
    reasons+=("issuer_admin_blockchain_handlers_coverage_ok unresolved from provided artifacts")
  else
    reasons+=("issuer_admin_blockchain_handlers_coverage_ok is false")
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
  "$phase5_run_summary_json" \
  "$roadmap_summary_json" \
  "$phase5_run_summary_usable" \
  "$roadmap_summary_usable" \
  "$show_json" \
  "$require_run_pipeline_ok" \
  "$require_settlement_failsoft_ok" \
  "$require_settlement_acceptance_ok" \
  "$require_settlement_bridge_smoke_ok" \
  "$require_settlement_state_persistence_ok" \
  "$run_pipeline_status" \
  "$run_pipeline_value" \
  "$run_pipeline_resolved" \
  "$run_pipeline_source" \
  "$run_pipeline_contract_valid" \
  "$settlement_failsoft_status" \
  "$settlement_acceptance_status" \
  "$settlement_bridge_smoke_status" \
  "$settlement_state_persistence_status" \
  "$settlement_failsoft_ok" \
  "$settlement_acceptance_ok" \
  "$settlement_bridge_smoke_ok" \
  "$settlement_state_persistence_ok" \
  "$settlement_failsoft_resolved" \
  "$settlement_acceptance_resolved" \
  "$settlement_bridge_smoke_resolved" \
  "$settlement_state_persistence_resolved" \
  "$settlement_failsoft_source" \
  "$settlement_acceptance_source" \
  "$settlement_bridge_smoke_source" \
  "$settlement_state_persistence_source" \
  "$reasons_json" \
  "$require_issuer_sponsor_api_live_smoke_ok" \
  "$issuer_sponsor_api_live_smoke_status" \
  "$issuer_sponsor_api_live_smoke_ok" \
  "$issuer_sponsor_api_live_smoke_resolved" \
  "$issuer_sponsor_api_live_smoke_source" \
  "$require_settlement_dual_asset_parity_ok" \
  "$settlement_dual_asset_parity_status" \
  "$settlement_dual_asset_parity_ok" \
  "$settlement_dual_asset_parity_resolved" \
  "$settlement_dual_asset_parity_source" \
  "$require_issuer_admin_blockchain_handlers_coverage_ok" \
  "$issuer_admin_blockchain_handlers_coverage_status" \
  "$issuer_admin_blockchain_handlers_coverage_ok" \
  "$issuer_admin_blockchain_handlers_coverage_resolved" \
  "$issuer_admin_blockchain_handlers_coverage_source"

if [[ "$show_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$status" == "pass" ]]; then
  exit 0
fi
exit 1
