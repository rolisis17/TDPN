#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/phase5_settlement_layer_check.sh \
    [--ci-phase5-summary-json PATH] \
    [--require-settlement-failsoft-ok [0|1]] \
    [--require-settlement-acceptance-ok [0|1]] \
    [--require-settlement-bridge-smoke-ok [0|1]] \
    [--require-settlement-adapter-roundtrip-ok [0|1]] \
    [--require-settlement-adapter-signed-tx-roundtrip-ok [0|1]] \
    [--require-settlement-shadow-env-ok [0|1]] \
    [--require-settlement-shadow-status-surface-ok [0|1]] \
    [--require-settlement-state-persistence-ok [0|1]] \
    [--require-settlement-dual-asset-parity-ok [0|1]] \
    [--require-issuer-sponsor-api-live-smoke-ok [0|1]] \
    [--require-issuer-sponsor-vpn-session-live-smoke-ok [0|1]] \
    [--require-issuer-settlement-status-live-smoke-ok [0|1]] \
    [--require-exit-settlement-status-live-smoke-ok [0|1]] \
    [--require-issuer-admin-blockchain-handlers-coverage-ok [0|1]] \
    [--require-windows-server-packaging-ok [0|1]] \
    [--require-windows-role-runbooks-ok [0|1]] \
    [--require-cross-platform-interop-ok [0|1]] \
    [--require-role-combination-validation-ok [0|1]] \
    [--summary-json PATH] \
    [--show-json [0|1]]

Purpose:
  Fail-closed checker for the Phase-5 settlement layer readiness contract.
  Evaluates required readiness booleans derived from the CI Phase-5 summary:
    - settlement_failsoft_ok
    - settlement_acceptance_ok
    - settlement_bridge_smoke_ok
    - settlement_adapter_roundtrip_ok
    - settlement_adapter_signed_tx_roundtrip_ok
    - settlement_shadow_env_ok
    - settlement_shadow_status_surface_ok
    - settlement_state_persistence_ok
    - settlement_dual_asset_parity_ok
    - issuer_sponsor_api_live_smoke_ok
    - issuer_sponsor_vpn_session_live_smoke_ok
    - issuer_settlement_status_live_smoke_ok
    - exit_settlement_status_live_smoke_ok
    - issuer_admin_blockchain_handlers_coverage_ok

Notes:
  - Provide the CI summary with --ci-phase5-summary-json (canonical).
  - Legacy alias --ci-phase4-summary-json is accepted for compatibility.
  - Canonical requirement flags are --require-settlement-*-ok.
  - Legacy requirement flags --require-windows-*/--require-cross-platform-*/--require-role-combination-* are accepted as aliases.
  - Canonical env vars are PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_SETTLEMENT_*_OK (including *_ADAPTER_SIGNED_TX_ROUNDTRIP_OK, *_SHADOW_ENV_OK, and *_SHADOW_STATUS_SURFACE_OK) plus PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_ISSUER_SPONSOR_API_LIVE_SMOKE_OK, PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_ISSUER_SPONSOR_VPN_SESSION_LIVE_SMOKE_OK, PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_ISSUER_SETTLEMENT_STATUS_LIVE_SMOKE_OK, PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_EXIT_SETTLEMENT_STATUS_LIVE_SMOKE_OK, and PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_ISSUER_ADMIN_BLOCKCHAIN_HANDLERS_COVERAGE_OK, with PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_WINDOWS_*/PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_CROSS_PLATFORM_INTEROP_OK/PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_ROLE_COMBINATION_VALIDATION_OK fallback.
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
  jq -r "($expr) | if . == null then empty else . end" "$path" 2>/dev/null || true
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
    settlement_failsoft_ok)
      json_text_or_empty "$path" 'if (.settlement_failsoft_ok? != null) then .settlement_failsoft_ok
        elif (.summary.settlement_failsoft_ok? != null) then .summary.settlement_failsoft_ok
        elif (.signals.settlement_failsoft_ok? != null) then .signals.settlement_failsoft_ok
        elif (.stages.settlement_failsoft.status? != null) then .stages.settlement_failsoft.status
        elif (.steps.settlement_failsoft.status? != null) then .steps.settlement_failsoft.status
        else empty end'
      ;;
    settlement_acceptance_ok)
      json_text_or_empty "$path" 'if (.settlement_acceptance_ok? != null) then .settlement_acceptance_ok
        elif (.summary.settlement_acceptance_ok? != null) then .summary.settlement_acceptance_ok
        elif (.signals.settlement_acceptance_ok? != null) then .signals.settlement_acceptance_ok
        elif (.stages.settlement_acceptance.status? != null) then .stages.settlement_acceptance.status
        elif (.steps.settlement_acceptance.status? != null) then .steps.settlement_acceptance.status
        else empty end'
      ;;
    settlement_bridge_smoke_ok)
      json_text_or_empty "$path" 'if (.settlement_bridge_smoke_ok? != null) then .settlement_bridge_smoke_ok
        elif (.summary.settlement_bridge_smoke_ok? != null) then .summary.settlement_bridge_smoke_ok
        elif (.signals.settlement_bridge_smoke_ok? != null) then .signals.settlement_bridge_smoke_ok
        elif (.stages.settlement_bridge_smoke.status? != null) then .stages.settlement_bridge_smoke.status
        elif (.steps.settlement_bridge_smoke.status? != null) then .steps.settlement_bridge_smoke.status
        else empty end'
      ;;
    settlement_adapter_roundtrip_ok)
      json_text_or_empty "$path" 'if (.settlement_adapter_roundtrip_ok? != null) then .settlement_adapter_roundtrip_ok
        elif (.settlement_adapter_roundtrip_status? != null) then .settlement_adapter_roundtrip_status
        elif (.summary.settlement_adapter_roundtrip_ok? != null) then .summary.settlement_adapter_roundtrip_ok
        elif (.summary.settlement_adapter_roundtrip_status? != null) then .summary.settlement_adapter_roundtrip_status
        elif (.signals.settlement_adapter_roundtrip_ok? != null) then .signals.settlement_adapter_roundtrip_ok
        elif (.signals.settlement_adapter_roundtrip? != null) then .signals.settlement_adapter_roundtrip
        elif (.signals.settlement_adapter_roundtrip_status? != null) then .signals.settlement_adapter_roundtrip_status
        elif (.stages.settlement_adapter_roundtrip.ok? != null) then .stages.settlement_adapter_roundtrip.ok
        elif (.stages.settlement_adapter_roundtrip.status? != null) then .stages.settlement_adapter_roundtrip.status
        elif (.steps.settlement_adapter_roundtrip.status? != null) then .steps.settlement_adapter_roundtrip.status
        elif (.settlement_bridge_smoke_ok? != null) then .settlement_bridge_smoke_ok
        elif (.summary.settlement_bridge_smoke_ok? != null) then .summary.settlement_bridge_smoke_ok
        elif (.signals.settlement_bridge_smoke_ok? != null) then .signals.settlement_bridge_smoke_ok
        elif (.stages.settlement_bridge_smoke.status? != null) then .stages.settlement_bridge_smoke.status
        elif (.steps.settlement_bridge_smoke.status? != null) then .steps.settlement_bridge_smoke.status
        else empty end'
      ;;
    settlement_adapter_signed_tx_roundtrip_ok)
      json_text_or_empty "$path" 'if (.settlement_adapter_signed_tx_roundtrip_ok? != null) then .settlement_adapter_signed_tx_roundtrip_ok
        elif (.settlement_adapter_signed_tx_roundtrip_status? != null) then .settlement_adapter_signed_tx_roundtrip_status
        elif (.summary.settlement_adapter_signed_tx_roundtrip_ok? != null) then .summary.settlement_adapter_signed_tx_roundtrip_ok
        elif (.summary.settlement_adapter_signed_tx_roundtrip_status? != null) then .summary.settlement_adapter_signed_tx_roundtrip_status
        elif (.signals.settlement_adapter_signed_tx_roundtrip_ok? != null) then .signals.settlement_adapter_signed_tx_roundtrip_ok
        elif (.signals.settlement_adapter_signed_tx_roundtrip? != null) then .signals.settlement_adapter_signed_tx_roundtrip
        elif (.signals.settlement_adapter_signed_tx_roundtrip_status? != null) then .signals.settlement_adapter_signed_tx_roundtrip_status
        elif (.stages.settlement_adapter_signed_tx_roundtrip.ok? != null) then .stages.settlement_adapter_signed_tx_roundtrip.ok
        elif (.stages.settlement_adapter_signed_tx_roundtrip.status? != null) then .stages.settlement_adapter_signed_tx_roundtrip.status
        elif (.steps.settlement_adapter_signed_tx_roundtrip.status? != null) then .steps.settlement_adapter_signed_tx_roundtrip.status
        else empty end'
      ;;
    settlement_shadow_env_ok)
      json_text_or_empty "$path" 'if (.settlement_shadow_env_ok? != null) then .settlement_shadow_env_ok
        elif (.settlement_shadow_env_status? != null) then .settlement_shadow_env_status
        elif (.summary.settlement_shadow_env_ok? != null) then .summary.settlement_shadow_env_ok
        elif (.summary.settlement_shadow_env_status? != null) then .summary.settlement_shadow_env_status
        elif (.signals.settlement_shadow_env_ok? != null) then .signals.settlement_shadow_env_ok
        elif (.signals.settlement_shadow_env? != null) then .signals.settlement_shadow_env
        elif (.signals.settlement_shadow_env_status? != null) then .signals.settlement_shadow_env_status
        elif (.stages.settlement_shadow_env.ok? != null) then .stages.settlement_shadow_env.ok
        elif (.stages.settlement_shadow_env.status? != null) then .stages.settlement_shadow_env.status
        elif (.steps.settlement_shadow_env.status? != null) then .steps.settlement_shadow_env.status
        else empty end'
      ;;
    settlement_shadow_status_surface_ok)
      json_text_or_empty "$path" 'if (.settlement_shadow_status_surface_ok? != null) then .settlement_shadow_status_surface_ok
        elif (.settlement_shadow_status_surface_status? != null) then .settlement_shadow_status_surface_status
        elif (.summary.settlement_shadow_status_surface_ok? != null) then .summary.settlement_shadow_status_surface_ok
        elif (.summary.settlement_shadow_status_surface_status? != null) then .summary.settlement_shadow_status_surface_status
        elif (.signals.settlement_shadow_status_surface_ok? != null) then .signals.settlement_shadow_status_surface_ok
        elif (.signals.settlement_shadow_status_surface? != null) then .signals.settlement_shadow_status_surface
        elif (.signals.settlement_shadow_status_surface_status? != null) then .signals.settlement_shadow_status_surface_status
        elif (.stages.settlement_shadow_status_surface.ok? != null) then .stages.settlement_shadow_status_surface.ok
        elif (.stages.settlement_shadow_status_surface.status? != null) then .stages.settlement_shadow_status_surface.status
        elif (.steps.settlement_shadow_status_surface.status? != null) then .steps.settlement_shadow_status_surface.status
        else empty end'
      ;;
    settlement_state_persistence_ok)
      json_text_or_empty "$path" 'if (.settlement_state_persistence_ok? != null) then .settlement_state_persistence_ok
        elif (.summary.settlement_state_persistence_ok? != null) then .summary.settlement_state_persistence_ok
        elif (.signals.settlement_state_persistence_ok? != null) then .signals.settlement_state_persistence_ok
        elif (.stages.settlement_state_persistence.status? != null) then .stages.settlement_state_persistence.status
        elif (.steps.settlement_state_persistence.status? != null) then .steps.settlement_state_persistence.status
        else empty end'
      ;;
    settlement_dual_asset_parity_ok)
      json_text_or_empty "$path" 'if (.settlement_dual_asset_parity_ok? != null) then .settlement_dual_asset_parity_ok
        elif (.summary.settlement_dual_asset_parity_ok? != null) then .summary.settlement_dual_asset_parity_ok
        elif (.signals.settlement_dual_asset_parity_ok? != null) then .signals.settlement_dual_asset_parity_ok
        elif (.stages.settlement_dual_asset_parity.status? != null) then .stages.settlement_dual_asset_parity.status
        elif (.steps.settlement_dual_asset_parity.status? != null) then .steps.settlement_dual_asset_parity.status
        else empty end'
      ;;
    issuer_sponsor_api_live_smoke_ok)
      json_text_or_empty "$path" 'if (.issuer_sponsor_api_live_smoke_ok? != null) then .issuer_sponsor_api_live_smoke_ok
        elif (.summary.issuer_sponsor_api_live_smoke_ok? != null) then .summary.issuer_sponsor_api_live_smoke_ok
        elif (.signals.issuer_sponsor_api_live_smoke_ok? != null) then .signals.issuer_sponsor_api_live_smoke_ok
        elif (.stages.issuer_sponsor_api_live_smoke.status? != null) then .stages.issuer_sponsor_api_live_smoke.status
        elif (.steps.issuer_sponsor_api_live_smoke.status? != null) then .steps.issuer_sponsor_api_live_smoke.status
        else empty end'
      ;;
    issuer_sponsor_vpn_session_live_smoke_ok)
      json_text_or_empty "$path" 'if (.issuer_sponsor_vpn_session_live_smoke_ok? != null) then .issuer_sponsor_vpn_session_live_smoke_ok
        elif (.summary.issuer_sponsor_vpn_session_live_smoke_ok? != null) then .summary.issuer_sponsor_vpn_session_live_smoke_ok
        elif (.signals.issuer_sponsor_vpn_session_live_smoke_ok? != null) then .signals.issuer_sponsor_vpn_session_live_smoke_ok
        elif (.stages.issuer_sponsor_vpn_session_live_smoke.status? != null) then .stages.issuer_sponsor_vpn_session_live_smoke.status
        elif (.steps.issuer_sponsor_vpn_session_live_smoke.status? != null) then .steps.issuer_sponsor_vpn_session_live_smoke.status
        else empty end'
      ;;
    issuer_settlement_status_live_smoke_ok)
      json_text_or_empty "$path" 'if (.issuer_settlement_status_live_smoke_ok? != null) then .issuer_settlement_status_live_smoke_ok
        elif (.summary.issuer_settlement_status_live_smoke_ok? != null) then .summary.issuer_settlement_status_live_smoke_ok
        elif (.signals.issuer_settlement_status_live_smoke_ok? != null) then .signals.issuer_settlement_status_live_smoke_ok
        elif (.stages.issuer_settlement_status_live_smoke.status? != null) then .stages.issuer_settlement_status_live_smoke.status
        elif (.steps.issuer_settlement_status_live_smoke.status? != null) then .steps.issuer_settlement_status_live_smoke.status
        else empty end'
      ;;
    exit_settlement_status_live_smoke_ok)
      json_text_or_empty "$path" 'if (.exit_settlement_status_live_smoke_ok? != null) then .exit_settlement_status_live_smoke_ok
        elif (.summary.exit_settlement_status_live_smoke_ok? != null) then .summary.exit_settlement_status_live_smoke_ok
        elif (.signals.exit_settlement_status_live_smoke_ok? != null) then .signals.exit_settlement_status_live_smoke_ok
        elif (.stages.exit_settlement_status_live_smoke.status? != null) then .stages.exit_settlement_status_live_smoke.status
        elif (.steps.exit_settlement_status_live_smoke.status? != null) then .steps.exit_settlement_status_live_smoke.status
        else empty end'
      ;;
    issuer_admin_blockchain_handlers_coverage_ok)
      json_text_or_empty "$path" 'if (.issuer_admin_blockchain_handlers_coverage_ok? != null) then .issuer_admin_blockchain_handlers_coverage_ok
        elif (.summary.issuer_admin_blockchain_handlers_coverage_ok? != null) then .summary.issuer_admin_blockchain_handlers_coverage_ok
        elif (.signals.issuer_admin_blockchain_handlers_coverage_ok? != null) then .signals.issuer_admin_blockchain_handlers_coverage_ok
        elif (.stages.issuer_admin_blockchain_handlers_coverage.status? != null) then .stages.issuer_admin_blockchain_handlers_coverage.status
        elif (.steps.issuer_admin_blockchain_handlers_coverage.status? != null) then .steps.issuer_admin_blockchain_handlers_coverage.status
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
  local ci_phase5_summary_json="$5"
  local ci_phase5_summary_usable="$6"
  local show_json="$7"
  local require_settlement_failsoft_ok="$8"
  local require_settlement_acceptance_ok="$9"
  local require_settlement_bridge_smoke_ok="${10}"
  local require_settlement_adapter_roundtrip_ok="${11}"
  local require_settlement_state_persistence_ok="${12}"
  local settlement_failsoft_status="${13}"
  local settlement_acceptance_status="${14}"
  local settlement_bridge_smoke_status="${15}"
  local settlement_adapter_roundtrip_status="${16}"
  local settlement_state_persistence_status="${17}"
  local settlement_failsoft_ok="${18}"
  local settlement_acceptance_ok="${19}"
  local settlement_bridge_smoke_ok="${20}"
  local settlement_adapter_roundtrip_ok="${21}"
  local settlement_state_persistence_ok="${22}"
  local settlement_failsoft_resolved="${23}"
  local settlement_acceptance_resolved="${24}"
  local settlement_bridge_smoke_resolved="${25}"
  local settlement_adapter_roundtrip_resolved="${26}"
  local settlement_state_persistence_resolved="${27}"
  local reasons_json="${28}"
  local require_issuer_sponsor_api_live_smoke_ok="${29}"
  local issuer_sponsor_api_live_smoke_status="${30}"
  local issuer_sponsor_api_live_smoke_ok="${31}"
  local issuer_sponsor_api_live_smoke_resolved="${32}"
  local require_issuer_settlement_status_live_smoke_ok="${33}"
  local issuer_settlement_status_live_smoke_status="${34}"
  local issuer_settlement_status_live_smoke_ok="${35}"
  local issuer_settlement_status_live_smoke_resolved="${36}"
  local require_exit_settlement_status_live_smoke_ok="${37}"
  local exit_settlement_status_live_smoke_status="${38}"
  local exit_settlement_status_live_smoke_ok="${39}"
  local exit_settlement_status_live_smoke_resolved="${40}"
  local require_settlement_dual_asset_parity_ok="${41}"
  local settlement_dual_asset_parity_status="${42}"
  local settlement_dual_asset_parity_ok="${43}"
  local settlement_dual_asset_parity_resolved="${44}"
  local require_issuer_admin_blockchain_handlers_coverage_ok="${45}"
  local issuer_admin_blockchain_handlers_coverage_status="${46}"
  local issuer_admin_blockchain_handlers_coverage_ok="${47}"
  local issuer_admin_blockchain_handlers_coverage_resolved="${48}"
  local require_settlement_adapter_signed_tx_roundtrip_ok="${49}"
  local settlement_adapter_signed_tx_roundtrip_status="${50}"
  local settlement_adapter_signed_tx_roundtrip_ok="${51}"
  local settlement_adapter_signed_tx_roundtrip_resolved="${52}"
  local require_settlement_shadow_env_ok="${53}"
  local settlement_shadow_env_status="${54}"
  local settlement_shadow_env_ok="${55}"
  local settlement_shadow_env_resolved="${56}"
  local require_settlement_shadow_status_surface_ok="${57}"
  local settlement_shadow_status_surface_status="${58}"
  local settlement_shadow_status_surface_ok="${59}"
  local settlement_shadow_status_surface_resolved="${60}"
  local require_issuer_sponsor_vpn_session_live_smoke_ok="${61}"
  local issuer_sponsor_vpn_session_live_smoke_status="${62}"
  local issuer_sponsor_vpn_session_live_smoke_ok="${63}"
  local issuer_sponsor_vpn_session_live_smoke_resolved="${64}"

  local summary_tmp
  summary_tmp="$(mktemp)"
  jq -n \
    --arg generated_at_utc "$generated_at_utc" \
    --arg status "$status" \
    --argjson rc "$rc" \
    --arg summary_json "$summary_json" \
    --arg canonical_summary_json "$canonical_summary_json" \
    --arg ci_phase5_summary_json "$ci_phase5_summary_json" \
    --argjson ci_phase5_summary_usable "$ci_phase5_summary_usable" \
    --arg show_json "$show_json" \
    --argjson require_settlement_failsoft_ok "$require_settlement_failsoft_ok" \
    --argjson require_settlement_acceptance_ok "$require_settlement_acceptance_ok" \
    --argjson require_settlement_bridge_smoke_ok "$require_settlement_bridge_smoke_ok" \
    --argjson require_settlement_adapter_roundtrip_ok "$require_settlement_adapter_roundtrip_ok" \
    --argjson require_settlement_state_persistence_ok "$require_settlement_state_persistence_ok" \
    --argjson require_settlement_dual_asset_parity_ok "$require_settlement_dual_asset_parity_ok" \
    --argjson require_settlement_adapter_signed_tx_roundtrip_ok "$require_settlement_adapter_signed_tx_roundtrip_ok" \
    --argjson require_settlement_shadow_env_ok "$require_settlement_shadow_env_ok" \
    --argjson require_settlement_shadow_status_surface_ok "$require_settlement_shadow_status_surface_ok" \
    --argjson require_issuer_sponsor_api_live_smoke_ok "$require_issuer_sponsor_api_live_smoke_ok" \
    --argjson require_issuer_sponsor_vpn_session_live_smoke_ok "$require_issuer_sponsor_vpn_session_live_smoke_ok" \
    --argjson require_issuer_settlement_status_live_smoke_ok "$require_issuer_settlement_status_live_smoke_ok" \
    --argjson require_exit_settlement_status_live_smoke_ok "$require_exit_settlement_status_live_smoke_ok" \
    --argjson require_issuer_admin_blockchain_handlers_coverage_ok "$require_issuer_admin_blockchain_handlers_coverage_ok" \
    --arg settlement_failsoft_status "$settlement_failsoft_status" \
    --arg settlement_acceptance_status "$settlement_acceptance_status" \
    --arg settlement_bridge_smoke_status "$settlement_bridge_smoke_status" \
    --arg settlement_adapter_roundtrip_status "$settlement_adapter_roundtrip_status" \
    --arg settlement_adapter_signed_tx_roundtrip_status "$settlement_adapter_signed_tx_roundtrip_status" \
    --arg settlement_shadow_env_status "$settlement_shadow_env_status" \
    --arg settlement_shadow_status_surface_status "$settlement_shadow_status_surface_status" \
    --arg settlement_state_persistence_status "$settlement_state_persistence_status" \
    --arg settlement_dual_asset_parity_status "$settlement_dual_asset_parity_status" \
    --arg issuer_sponsor_api_live_smoke_status "$issuer_sponsor_api_live_smoke_status" \
    --arg issuer_sponsor_vpn_session_live_smoke_status "$issuer_sponsor_vpn_session_live_smoke_status" \
    --arg issuer_settlement_status_live_smoke_status "$issuer_settlement_status_live_smoke_status" \
    --arg exit_settlement_status_live_smoke_status "$exit_settlement_status_live_smoke_status" \
    --arg issuer_admin_blockchain_handlers_coverage_status "$issuer_admin_blockchain_handlers_coverage_status" \
    --argjson settlement_failsoft_ok "$settlement_failsoft_ok" \
    --argjson settlement_acceptance_ok "$settlement_acceptance_ok" \
    --argjson settlement_bridge_smoke_ok "$settlement_bridge_smoke_ok" \
    --argjson settlement_adapter_roundtrip_ok "$settlement_adapter_roundtrip_ok" \
    --argjson settlement_adapter_signed_tx_roundtrip_ok "$settlement_adapter_signed_tx_roundtrip_ok" \
    --argjson settlement_shadow_env_ok "$settlement_shadow_env_ok" \
    --argjson settlement_shadow_status_surface_ok "$settlement_shadow_status_surface_ok" \
    --argjson settlement_state_persistence_ok "$settlement_state_persistence_ok" \
    --argjson settlement_dual_asset_parity_ok "$settlement_dual_asset_parity_ok" \
    --argjson issuer_sponsor_api_live_smoke_ok "$issuer_sponsor_api_live_smoke_ok" \
    --argjson issuer_sponsor_vpn_session_live_smoke_ok "$issuer_sponsor_vpn_session_live_smoke_ok" \
    --argjson issuer_settlement_status_live_smoke_ok "$issuer_settlement_status_live_smoke_ok" \
    --argjson exit_settlement_status_live_smoke_ok "$exit_settlement_status_live_smoke_ok" \
    --argjson issuer_admin_blockchain_handlers_coverage_ok "$issuer_admin_blockchain_handlers_coverage_ok" \
    --argjson settlement_failsoft_resolved "$settlement_failsoft_resolved" \
    --argjson settlement_acceptance_resolved "$settlement_acceptance_resolved" \
    --argjson settlement_bridge_smoke_resolved "$settlement_bridge_smoke_resolved" \
    --argjson settlement_adapter_roundtrip_resolved "$settlement_adapter_roundtrip_resolved" \
    --argjson settlement_adapter_signed_tx_roundtrip_resolved "$settlement_adapter_signed_tx_roundtrip_resolved" \
    --argjson settlement_shadow_env_resolved "$settlement_shadow_env_resolved" \
    --argjson settlement_shadow_status_surface_resolved "$settlement_shadow_status_surface_resolved" \
    --argjson settlement_state_persistence_resolved "$settlement_state_persistence_resolved" \
    --argjson settlement_dual_asset_parity_resolved "$settlement_dual_asset_parity_resolved" \
    --argjson issuer_sponsor_api_live_smoke_resolved "$issuer_sponsor_api_live_smoke_resolved" \
    --argjson issuer_sponsor_vpn_session_live_smoke_resolved "$issuer_sponsor_vpn_session_live_smoke_resolved" \
    --argjson issuer_settlement_status_live_smoke_resolved "$issuer_settlement_status_live_smoke_resolved" \
    --argjson exit_settlement_status_live_smoke_resolved "$exit_settlement_status_live_smoke_resolved" \
    --argjson issuer_admin_blockchain_handlers_coverage_resolved "$issuer_admin_blockchain_handlers_coverage_resolved" \
    --argjson reasons "$reasons_json" \
    '{
      version: 1,
      schema: {
        id: "phase5_settlement_layer_check_summary",
        major: 1,
        minor: 0
      },
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $rc,
      metadata: {
        contract: "phase5-settlement-layer",
        script: "phase5_settlement_layer_check.sh"
      },
      inputs: {
        ci_phase5_summary_json: $ci_phase5_summary_json,
        summary_json: $summary_json,
        show_json: ($show_json == "1"),
        require_settlement_adapter_signed_tx_roundtrip_ok: ($require_settlement_adapter_signed_tx_roundtrip_ok == 1),
        require_settlement_shadow_env_ok: ($require_settlement_shadow_env_ok == 1),
        require_settlement_shadow_status_surface_ok: ($require_settlement_shadow_status_surface_ok == 1),
        usable: {
          ci_phase5_summary_json: ($ci_phase5_summary_usable == 1)
        }
      },
      policy: {
        require_settlement_failsoft_ok: ($require_settlement_failsoft_ok == 1),
        require_settlement_acceptance_ok: ($require_settlement_acceptance_ok == 1),
        require_settlement_bridge_smoke_ok: ($require_settlement_bridge_smoke_ok == 1),
        require_settlement_adapter_roundtrip_ok: ($require_settlement_adapter_roundtrip_ok == 1),
        require_settlement_adapter_signed_tx_roundtrip_ok: ($require_settlement_adapter_signed_tx_roundtrip_ok == 1),
        require_settlement_shadow_env_ok: ($require_settlement_shadow_env_ok == 1),
        require_settlement_shadow_status_surface_ok: ($require_settlement_shadow_status_surface_ok == 1),
        require_settlement_state_persistence_ok: ($require_settlement_state_persistence_ok == 1),
        require_settlement_dual_asset_parity_ok: ($require_settlement_dual_asset_parity_ok == 1),
        require_issuer_sponsor_api_live_smoke_ok: ($require_issuer_sponsor_api_live_smoke_ok == 1),
        require_issuer_sponsor_vpn_session_live_smoke_ok: ($require_issuer_sponsor_vpn_session_live_smoke_ok == 1),
        require_issuer_settlement_status_live_smoke_ok: ($require_issuer_settlement_status_live_smoke_ok == 1),
        require_exit_settlement_status_live_smoke_ok: ($require_exit_settlement_status_live_smoke_ok == 1),
        require_issuer_admin_blockchain_handlers_coverage_ok: ($require_issuer_admin_blockchain_handlers_coverage_ok == 1)
      },
      stages: {
        settlement_failsoft: {
          enabled: ($require_settlement_failsoft_ok == 1),
          status: $settlement_failsoft_status,
          resolved: ($settlement_failsoft_resolved == 1),
          ok: ($settlement_failsoft_ok == true)
        },
        settlement_acceptance: {
          enabled: ($require_settlement_acceptance_ok == 1),
          status: $settlement_acceptance_status,
          resolved: ($settlement_acceptance_resolved == 1),
          ok: ($settlement_acceptance_ok == true)
        },
        settlement_bridge_smoke: {
          enabled: ($require_settlement_bridge_smoke_ok == 1),
          status: $settlement_bridge_smoke_status,
          resolved: ($settlement_bridge_smoke_resolved == 1),
          ok: ($settlement_bridge_smoke_ok == true)
        },
        settlement_adapter_roundtrip: {
          enabled: ($require_settlement_adapter_roundtrip_ok == 1),
          status: $settlement_adapter_roundtrip_status,
          resolved: ($settlement_adapter_roundtrip_resolved == 1),
          ok: ($settlement_adapter_roundtrip_ok == true)
        },
        settlement_adapter_signed_tx_roundtrip: {
          enabled: ($require_settlement_adapter_signed_tx_roundtrip_ok == 1),
          status: $settlement_adapter_signed_tx_roundtrip_status,
          resolved: ($settlement_adapter_signed_tx_roundtrip_resolved == 1),
          ok: ($settlement_adapter_signed_tx_roundtrip_ok == true)
        },
        settlement_shadow_env: {
          enabled: ($require_settlement_shadow_env_ok == 1),
          status: $settlement_shadow_env_status,
          resolved: ($settlement_shadow_env_resolved == 1),
          ok: ($settlement_shadow_env_ok == true)
        },
        settlement_shadow_status_surface: {
          enabled: ($require_settlement_shadow_status_surface_ok == 1),
          status: $settlement_shadow_status_surface_status,
          resolved: ($settlement_shadow_status_surface_resolved == 1),
          ok: ($settlement_shadow_status_surface_ok == true)
        },
        settlement_state_persistence: {
          enabled: ($require_settlement_state_persistence_ok == 1),
          status: $settlement_state_persistence_status,
          resolved: ($settlement_state_persistence_resolved == 1),
          ok: ($settlement_state_persistence_ok == true)
        },
        settlement_dual_asset_parity: {
          enabled: ($require_settlement_dual_asset_parity_ok == 1),
          status: $settlement_dual_asset_parity_status,
          resolved: ($settlement_dual_asset_parity_resolved == 1),
          ok: ($settlement_dual_asset_parity_ok == true)
        },
        issuer_sponsor_api_live_smoke: {
          enabled: ($require_issuer_sponsor_api_live_smoke_ok == 1),
          status: $issuer_sponsor_api_live_smoke_status,
          resolved: ($issuer_sponsor_api_live_smoke_resolved == 1),
          ok: ($issuer_sponsor_api_live_smoke_ok == true)
        },
        issuer_sponsor_vpn_session_live_smoke: {
          enabled: ($require_issuer_sponsor_vpn_session_live_smoke_ok == 1),
          status: $issuer_sponsor_vpn_session_live_smoke_status,
          resolved: ($issuer_sponsor_vpn_session_live_smoke_resolved == 1),
          ok: ($issuer_sponsor_vpn_session_live_smoke_ok == true)
        },
        issuer_settlement_status_live_smoke: {
          enabled: ($require_issuer_settlement_status_live_smoke_ok == 1),
          status: $issuer_settlement_status_live_smoke_status,
          resolved: ($issuer_settlement_status_live_smoke_resolved == 1),
          ok: ($issuer_settlement_status_live_smoke_ok == true)
        },
        exit_settlement_status_live_smoke: {
          enabled: ($require_exit_settlement_status_live_smoke_ok == 1),
          status: $exit_settlement_status_live_smoke_status,
          resolved: ($exit_settlement_status_live_smoke_resolved == 1),
          ok: ($exit_settlement_status_live_smoke_ok == true)
        },
        issuer_admin_blockchain_handlers_coverage: {
          enabled: ($require_issuer_admin_blockchain_handlers_coverage_ok == 1),
          status: $issuer_admin_blockchain_handlers_coverage_status,
          resolved: ($issuer_admin_blockchain_handlers_coverage_resolved == 1),
          ok: ($issuer_admin_blockchain_handlers_coverage_ok == true)
        }
      },
      signals: {
        settlement_failsoft_ok: ($settlement_failsoft_ok == true),
        settlement_acceptance_ok: ($settlement_acceptance_ok == true),
        settlement_bridge_smoke_ok: ($settlement_bridge_smoke_ok == true),
        settlement_adapter_roundtrip_ok: ($settlement_adapter_roundtrip_ok == true),
        settlement_adapter_roundtrip_status: $settlement_adapter_roundtrip_status,
        settlement_adapter_roundtrip_resolved: ($settlement_adapter_roundtrip_resolved == 1),
        settlement_adapter_signed_tx_roundtrip_ok: ($settlement_adapter_signed_tx_roundtrip_ok == true),
        settlement_adapter_signed_tx_roundtrip_status: $settlement_adapter_signed_tx_roundtrip_status,
        settlement_adapter_signed_tx_roundtrip_resolved: ($settlement_adapter_signed_tx_roundtrip_resolved == 1),
        settlement_shadow_env_ok: ($settlement_shadow_env_ok == true),
        settlement_shadow_env_status: $settlement_shadow_env_status,
        settlement_shadow_env_resolved: ($settlement_shadow_env_resolved == 1),
        settlement_shadow_status_surface_ok: ($settlement_shadow_status_surface_ok == true),
        settlement_shadow_status_surface_status: $settlement_shadow_status_surface_status,
        settlement_shadow_status_surface_resolved: ($settlement_shadow_status_surface_resolved == 1),
        settlement_state_persistence_ok: ($settlement_state_persistence_ok == true),
        settlement_dual_asset_parity_ok: ($settlement_dual_asset_parity_ok == true),
        issuer_sponsor_api_live_smoke_ok: ($issuer_sponsor_api_live_smoke_ok == true),
        issuer_sponsor_vpn_session_live_smoke_ok: ($issuer_sponsor_vpn_session_live_smoke_ok == true),
        issuer_sponsor_vpn_session_live_smoke_status: $issuer_sponsor_vpn_session_live_smoke_status,
        issuer_sponsor_vpn_session_live_smoke_resolved: ($issuer_sponsor_vpn_session_live_smoke_resolved == 1),
        issuer_settlement_status_live_smoke_ok: ($issuer_settlement_status_live_smoke_ok == true),
        issuer_settlement_status_live_smoke_status: $issuer_settlement_status_live_smoke_status,
        issuer_settlement_status_live_smoke_resolved: ($issuer_settlement_status_live_smoke_resolved == 1),
        exit_settlement_status_live_smoke_ok: ($exit_settlement_status_live_smoke_ok == true),
        exit_settlement_status_live_smoke_status: $exit_settlement_status_live_smoke_status,
        exit_settlement_status_live_smoke_resolved: ($exit_settlement_status_live_smoke_resolved == 1),
        issuer_admin_blockchain_handlers_coverage_ok: ($issuer_admin_blockchain_handlers_coverage_ok == true),
        issuer_admin_blockchain_handlers_coverage_status: $issuer_admin_blockchain_handlers_coverage_status,
        issuer_admin_blockchain_handlers_coverage: {
          status: $issuer_admin_blockchain_handlers_coverage_status,
          ok: ($issuer_admin_blockchain_handlers_coverage_ok == true),
          source: "ci_phase5_summary",
          source_path: $ci_phase5_summary_json,
          source_fallback: false
        }
      },
      decision: {
        pass: ($status == "pass"),
        reasons: $reasons
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

ci_phase5_summary_json="${PHASE5_SETTLEMENT_LAYER_CHECK_CI_PHASE5_SUMMARY_JSON:-${PHASE5_SETTLEMENT_LAYER_CHECK_CI_PHASE4_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase5_settlement_layer_ci_summary.json}}"
summary_json="${PHASE5_SETTLEMENT_LAYER_CHECK_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase5_settlement_layer_check_summary.json}"
canonical_summary_json="${PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/phase5_settlement_layer_check_summary.json}"
show_json="${PHASE5_SETTLEMENT_LAYER_CHECK_SHOW_JSON:-0}"
require_settlement_failsoft_ok="${PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_SETTLEMENT_FAILSOFT_OK:-${PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_WINDOWS_SERVER_PACKAGING_OK:-1}}"
require_settlement_acceptance_ok="${PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_SETTLEMENT_ACCEPTANCE_OK:-${PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_WINDOWS_ROLE_RUNBOOKS_OK:-1}}"
require_settlement_bridge_smoke_ok="${PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_SETTLEMENT_BRIDGE_SMOKE_OK:-${PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_CROSS_PLATFORM_INTEROP_OK:-1}}"
require_settlement_adapter_roundtrip_ok="${PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_SETTLEMENT_ADAPTER_ROUNDTRIP_OK:-$require_settlement_bridge_smoke_ok}"
require_settlement_adapter_signed_tx_roundtrip_ok="${PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_SETTLEMENT_ADAPTER_SIGNED_TX_ROUNDTRIP_OK:-1}"
require_settlement_shadow_env_ok="${PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_SETTLEMENT_SHADOW_ENV_OK:-1}"
require_settlement_shadow_status_surface_ok="${PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_SETTLEMENT_SHADOW_STATUS_SURFACE_OK:-1}"
require_settlement_state_persistence_ok="${PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_SETTLEMENT_STATE_PERSISTENCE_OK:-${PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_ROLE_COMBINATION_VALIDATION_OK:-1}}"
require_settlement_dual_asset_parity_ok="${PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_SETTLEMENT_DUAL_ASSET_PARITY_OK:-${PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_SETTLEMENT_DUAL_ASSET_OK:-1}}"
require_issuer_sponsor_api_live_smoke_ok="${PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_ISSUER_SPONSOR_API_LIVE_SMOKE_OK:-1}"
require_issuer_sponsor_vpn_session_live_smoke_ok="${PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_ISSUER_SPONSOR_VPN_SESSION_LIVE_SMOKE_OK:-1}"
require_issuer_settlement_status_live_smoke_ok="${PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_ISSUER_SETTLEMENT_STATUS_LIVE_SMOKE_OK:-1}"
require_exit_settlement_status_live_smoke_ok="${PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_EXIT_SETTLEMENT_STATUS_LIVE_SMOKE_OK:-1}"
require_issuer_admin_blockchain_handlers_coverage_ok="${PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_ISSUER_ADMIN_BLOCKCHAIN_HANDLERS_COVERAGE_OK:-1}"
adapter_requirement_explicit=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ci-phase5-summary-json)
      ci_phase5_summary_json="${2:-}"
      shift 2
      ;;
    --ci-phase4-summary-json)
      ci_phase5_summary_json="${2:-}"
      shift 2
      ;;
    --require-settlement-failsoft-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_settlement_failsoft_ok="${2:-}"
        shift 2
      else
        require_settlement_failsoft_ok="1"
        shift
      fi
      ;;
    --require-settlement-acceptance-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_settlement_acceptance_ok="${2:-}"
        shift 2
      else
        require_settlement_acceptance_ok="1"
        shift
      fi
      ;;
    --require-settlement-bridge-smoke-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_settlement_bridge_smoke_ok="${2:-}"
        if [[ "$adapter_requirement_explicit" != "1" ]]; then
          require_settlement_adapter_roundtrip_ok="$require_settlement_bridge_smoke_ok"
        fi
        shift 2
      else
        require_settlement_bridge_smoke_ok="1"
        if [[ "$adapter_requirement_explicit" != "1" ]]; then
          require_settlement_adapter_roundtrip_ok="$require_settlement_bridge_smoke_ok"
        fi
        shift
      fi
      ;;
    --require-settlement-adapter-roundtrip-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_settlement_adapter_roundtrip_ok="${2:-}"
        shift 2
      else
        require_settlement_adapter_roundtrip_ok="1"
        shift
      fi
      adapter_requirement_explicit=1
      ;;
    --require-settlement-adapter-signed-tx-roundtrip-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_settlement_adapter_signed_tx_roundtrip_ok="${2:-}"
        shift 2
      else
        require_settlement_adapter_signed_tx_roundtrip_ok="1"
        shift
      fi
      ;;
    --require-settlement-shadow-env-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_settlement_shadow_env_ok="${2:-}"
        shift 2
      else
        require_settlement_shadow_env_ok="1"
        shift
      fi
      ;;
    --require-settlement-shadow-status-surface-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_settlement_shadow_status_surface_ok="${2:-}"
        shift 2
      else
        require_settlement_shadow_status_surface_ok="1"
        shift
      fi
      ;;
    --require-settlement-state-persistence-ok)
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
    --require-issuer-sponsor-vpn-session-live-smoke-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_issuer_sponsor_vpn_session_live_smoke_ok="${2:-}"
        shift 2
      else
        require_issuer_sponsor_vpn_session_live_smoke_ok="1"
        shift
      fi
      ;;
    --require-issuer-settlement-status-live-smoke-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_issuer_settlement_status_live_smoke_ok="${2:-}"
        shift 2
      else
        require_issuer_settlement_status_live_smoke_ok="1"
        shift
      fi
      ;;
    --require-exit-settlement-status-live-smoke-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_exit_settlement_status_live_smoke_ok="${2:-}"
        shift 2
      else
        require_exit_settlement_status_live_smoke_ok="1"
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
    --require-windows-server-packaging-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_settlement_failsoft_ok="${2:-}"
        shift 2
      else
        require_settlement_failsoft_ok="1"
        shift
      fi
      ;;
    --require-windows-role-runbooks-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_settlement_acceptance_ok="${2:-}"
        shift 2
      else
        require_settlement_acceptance_ok="1"
        shift
      fi
      ;;
    --require-cross-platform-interop-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_settlement_bridge_smoke_ok="${2:-}"
        if [[ "$adapter_requirement_explicit" != "1" ]]; then
          require_settlement_adapter_roundtrip_ok="$require_settlement_bridge_smoke_ok"
        fi
        shift 2
      else
        require_settlement_bridge_smoke_ok="1"
        if [[ "$adapter_requirement_explicit" != "1" ]]; then
          require_settlement_adapter_roundtrip_ok="$require_settlement_bridge_smoke_ok"
        fi
        shift
      fi
      ;;
    --require-role-combination-validation-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_settlement_state_persistence_ok="${2:-}"
        shift 2
      else
        require_settlement_state_persistence_ok="1"
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

bool_arg_or_die "--require-settlement-failsoft-ok" "$require_settlement_failsoft_ok"
bool_arg_or_die "--require-settlement-acceptance-ok" "$require_settlement_acceptance_ok"
bool_arg_or_die "--require-settlement-bridge-smoke-ok" "$require_settlement_bridge_smoke_ok"
bool_arg_or_die "--require-settlement-adapter-roundtrip-ok" "$require_settlement_adapter_roundtrip_ok"
bool_arg_or_die "--require-settlement-adapter-signed-tx-roundtrip-ok" "$require_settlement_adapter_signed_tx_roundtrip_ok"
bool_arg_or_die "--require-settlement-shadow-env-ok" "$require_settlement_shadow_env_ok"
bool_arg_or_die "--require-settlement-shadow-status-surface-ok" "$require_settlement_shadow_status_surface_ok"
bool_arg_or_die "--require-settlement-state-persistence-ok" "$require_settlement_state_persistence_ok"
bool_arg_or_die "--require-settlement-dual-asset-parity-ok" "$require_settlement_dual_asset_parity_ok"
bool_arg_or_die "--require-issuer-sponsor-api-live-smoke-ok" "$require_issuer_sponsor_api_live_smoke_ok"
bool_arg_or_die "--require-issuer-sponsor-vpn-session-live-smoke-ok" "$require_issuer_sponsor_vpn_session_live_smoke_ok"
bool_arg_or_die "--require-issuer-settlement-status-live-smoke-ok" "$require_issuer_settlement_status_live_smoke_ok"
bool_arg_or_die "--require-exit-settlement-status-live-smoke-ok" "$require_exit_settlement_status_live_smoke_ok"
bool_arg_or_die "--require-issuer-admin-blockchain-handlers-coverage-ok" "$require_issuer_admin_blockchain_handlers_coverage_ok"
bool_arg_or_die "--show-json" "$show_json"

ci_phase5_summary_json="$(abs_path "$ci_phase5_summary_json")"
summary_json="$(abs_path "$summary_json")"
canonical_summary_json="$(abs_path "$canonical_summary_json")"

mkdir -p "$(dirname "$summary_json")"
mkdir -p "$(dirname "$canonical_summary_json")"

generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ci_phase5_summary_usable="$(json_file_valid_01 "$ci_phase5_summary_json")"

declare -a reasons=()

settlement_failsoft_raw=""
settlement_acceptance_raw=""
settlement_bridge_smoke_raw=""
settlement_adapter_roundtrip_raw=""
settlement_adapter_signed_tx_roundtrip_raw=""
settlement_shadow_env_raw=""
settlement_shadow_status_surface_raw=""
settlement_state_persistence_raw=""
settlement_dual_asset_parity_raw=""
issuer_sponsor_api_live_smoke_raw=""
issuer_sponsor_vpn_session_live_smoke_raw=""
issuer_settlement_status_live_smoke_raw=""
exit_settlement_status_live_smoke_raw=""
issuer_admin_blockchain_handlers_coverage_raw=""

if [[ "$ci_phase5_summary_usable" == "1" ]]; then
  settlement_failsoft_raw="$(resolve_signal_raw_or_empty "$ci_phase5_summary_json" "settlement_failsoft_ok")"
  settlement_acceptance_raw="$(resolve_signal_raw_or_empty "$ci_phase5_summary_json" "settlement_acceptance_ok")"
  settlement_bridge_smoke_raw="$(resolve_signal_raw_or_empty "$ci_phase5_summary_json" "settlement_bridge_smoke_ok")"
  settlement_adapter_roundtrip_raw="$(resolve_signal_raw_or_empty "$ci_phase5_summary_json" "settlement_adapter_roundtrip_ok")"
  settlement_adapter_signed_tx_roundtrip_raw="$(resolve_signal_raw_or_empty "$ci_phase5_summary_json" "settlement_adapter_signed_tx_roundtrip_ok")"
  settlement_shadow_env_raw="$(resolve_signal_raw_or_empty "$ci_phase5_summary_json" "settlement_shadow_env_ok")"
  settlement_shadow_status_surface_raw="$(resolve_signal_raw_or_empty "$ci_phase5_summary_json" "settlement_shadow_status_surface_ok")"
  settlement_state_persistence_raw="$(resolve_signal_raw_or_empty "$ci_phase5_summary_json" "settlement_state_persistence_ok")"
  settlement_dual_asset_parity_raw="$(resolve_signal_raw_or_empty "$ci_phase5_summary_json" "settlement_dual_asset_parity_ok")"
  issuer_sponsor_api_live_smoke_raw="$(resolve_signal_raw_or_empty "$ci_phase5_summary_json" "issuer_sponsor_api_live_smoke_ok")"
  issuer_sponsor_vpn_session_live_smoke_raw="$(resolve_signal_raw_or_empty "$ci_phase5_summary_json" "issuer_sponsor_vpn_session_live_smoke_ok")"
  issuer_settlement_status_live_smoke_raw="$(resolve_signal_raw_or_empty "$ci_phase5_summary_json" "issuer_settlement_status_live_smoke_ok")"
  exit_settlement_status_live_smoke_raw="$(resolve_signal_raw_or_empty "$ci_phase5_summary_json" "exit_settlement_status_live_smoke_ok")"
  issuer_admin_blockchain_handlers_coverage_raw="$(resolve_signal_raw_or_empty "$ci_phase5_summary_json" "issuer_admin_blockchain_handlers_coverage_ok")"
else
  reasons+=("ci phase5 summary file not found or invalid JSON: $ci_phase5_summary_json")
fi

settlement_failsoft_ok="$(normalize_boolish_or_empty "$settlement_failsoft_raw")"
settlement_acceptance_ok="$(normalize_boolish_or_empty "$settlement_acceptance_raw")"
settlement_bridge_smoke_ok="$(normalize_boolish_or_empty "$settlement_bridge_smoke_raw")"
settlement_adapter_roundtrip_ok="$(normalize_boolish_or_empty "$settlement_adapter_roundtrip_raw")"
settlement_adapter_signed_tx_roundtrip_ok="$(normalize_boolish_or_empty "$settlement_adapter_signed_tx_roundtrip_raw")"
settlement_shadow_env_ok="$(normalize_boolish_or_empty "$settlement_shadow_env_raw")"
settlement_shadow_status_surface_ok="$(normalize_boolish_or_empty "$settlement_shadow_status_surface_raw")"
settlement_state_persistence_ok="$(normalize_boolish_or_empty "$settlement_state_persistence_raw")"
settlement_dual_asset_parity_ok="$(normalize_boolish_or_empty "$settlement_dual_asset_parity_raw")"
issuer_sponsor_api_live_smoke_ok="$(normalize_boolish_or_empty "$issuer_sponsor_api_live_smoke_raw")"
issuer_sponsor_vpn_session_live_smoke_ok="$(normalize_boolish_or_empty "$issuer_sponsor_vpn_session_live_smoke_raw")"
issuer_settlement_status_live_smoke_ok="$(normalize_boolish_or_empty "$issuer_settlement_status_live_smoke_raw")"
exit_settlement_status_live_smoke_ok="$(normalize_boolish_or_empty "$exit_settlement_status_live_smoke_raw")"
issuer_admin_blockchain_handlers_coverage_ok="$(normalize_boolish_or_empty "$issuer_admin_blockchain_handlers_coverage_raw")"

if [[ -z "$settlement_failsoft_ok" ]]; then
  settlement_failsoft_ok="false"
fi
if [[ -z "$settlement_acceptance_ok" ]]; then
  settlement_acceptance_ok="false"
fi
if [[ -z "$settlement_bridge_smoke_ok" ]]; then
  settlement_bridge_smoke_ok="false"
fi
if [[ -z "$settlement_adapter_roundtrip_ok" ]]; then
  settlement_adapter_roundtrip_ok="false"
fi
if [[ -z "$settlement_adapter_signed_tx_roundtrip_ok" ]]; then
  settlement_adapter_signed_tx_roundtrip_ok="false"
fi
if [[ -z "$settlement_shadow_env_ok" ]]; then
  settlement_shadow_env_ok="false"
fi
if [[ -z "$settlement_shadow_status_surface_ok" ]]; then
  settlement_shadow_status_surface_ok="false"
fi
if [[ -z "$settlement_state_persistence_ok" ]]; then
  settlement_state_persistence_ok="false"
fi
if [[ -z "$settlement_dual_asset_parity_ok" ]]; then
  settlement_dual_asset_parity_ok="false"
fi
if [[ -z "$issuer_sponsor_api_live_smoke_ok" ]]; then
  issuer_sponsor_api_live_smoke_ok="false"
fi
if [[ -z "$issuer_sponsor_vpn_session_live_smoke_ok" ]]; then
  issuer_sponsor_vpn_session_live_smoke_ok="false"
fi
if [[ -z "$issuer_settlement_status_live_smoke_ok" ]]; then
  issuer_settlement_status_live_smoke_ok="false"
fi
if [[ -z "$exit_settlement_status_live_smoke_ok" ]]; then
  exit_settlement_status_live_smoke_ok="false"
fi
if [[ -z "$issuer_admin_blockchain_handlers_coverage_ok" ]]; then
  issuer_admin_blockchain_handlers_coverage_ok="false"
fi

settlement_failsoft_resolved="0"
settlement_acceptance_resolved="0"
settlement_bridge_smoke_resolved="0"
settlement_adapter_roundtrip_resolved="0"
settlement_adapter_signed_tx_roundtrip_resolved="0"
settlement_shadow_env_resolved="0"
settlement_shadow_status_surface_resolved="0"
settlement_state_persistence_resolved="0"
settlement_dual_asset_parity_resolved="0"
issuer_sponsor_api_live_smoke_resolved="0"
issuer_sponsor_vpn_session_live_smoke_resolved="0"
issuer_settlement_status_live_smoke_resolved="0"
exit_settlement_status_live_smoke_resolved="0"
issuer_admin_blockchain_handlers_coverage_resolved="0"

settlement_failsoft_status="$(stage_status_from_raw "$settlement_failsoft_raw")"
settlement_acceptance_status="$(stage_status_from_raw "$settlement_acceptance_raw")"
settlement_bridge_smoke_status="$(stage_status_from_raw "$settlement_bridge_smoke_raw")"
settlement_adapter_roundtrip_status="$(stage_status_from_raw "$settlement_adapter_roundtrip_raw")"
settlement_adapter_signed_tx_roundtrip_status="$(stage_status_from_raw "$settlement_adapter_signed_tx_roundtrip_raw")"
settlement_shadow_env_status="$(stage_status_from_raw "$settlement_shadow_env_raw")"
settlement_shadow_status_surface_status="$(stage_status_from_raw "$settlement_shadow_status_surface_raw")"
settlement_state_persistence_status="$(stage_status_from_raw "$settlement_state_persistence_raw")"
settlement_dual_asset_parity_status="$(stage_status_from_raw "$settlement_dual_asset_parity_raw")"
issuer_sponsor_api_live_smoke_status="$(stage_status_from_raw "$issuer_sponsor_api_live_smoke_raw")"
issuer_sponsor_vpn_session_live_smoke_status="$(stage_status_from_raw "$issuer_sponsor_vpn_session_live_smoke_raw")"
issuer_settlement_status_live_smoke_status="$(stage_status_from_raw "$issuer_settlement_status_live_smoke_raw")"
exit_settlement_status_live_smoke_status="$(stage_status_from_raw "$exit_settlement_status_live_smoke_raw")"
issuer_admin_blockchain_handlers_coverage_status="$(stage_status_from_raw "$issuer_admin_blockchain_handlers_coverage_raw")"

if [[ -n "$(trim "$settlement_failsoft_raw")" ]]; then
  settlement_failsoft_resolved="1"
elif [[ "$ci_phase5_summary_usable" == "1" ]]; then
  reasons+=("settlement_failsoft_ok could not be resolved from ci phase5 summary")
fi
if [[ -n "$(trim "$settlement_acceptance_raw")" ]]; then
  settlement_acceptance_resolved="1"
elif [[ "$ci_phase5_summary_usable" == "1" ]]; then
  reasons+=("settlement_acceptance_ok could not be resolved from ci phase5 summary")
fi
if [[ -n "$(trim "$settlement_bridge_smoke_raw")" ]]; then
  settlement_bridge_smoke_resolved="1"
elif [[ "$ci_phase5_summary_usable" == "1" ]]; then
  reasons+=("settlement_bridge_smoke_ok could not be resolved from ci phase5 summary")
fi
if [[ -n "$(trim "$settlement_adapter_roundtrip_raw")" ]]; then
  settlement_adapter_roundtrip_resolved="1"
elif [[ "$ci_phase5_summary_usable" == "1" ]]; then
  reasons+=("settlement_adapter_roundtrip_ok could not be resolved from ci phase5 summary")
fi
if [[ -n "$(trim "$settlement_adapter_signed_tx_roundtrip_raw")" ]]; then
  settlement_adapter_signed_tx_roundtrip_resolved="1"
elif [[ "$ci_phase5_summary_usable" == "1" ]]; then
  reasons+=("settlement_adapter_signed_tx_roundtrip_ok could not be resolved from ci phase5 summary")
fi
if [[ -n "$(trim "$settlement_shadow_env_raw")" ]]; then
  settlement_shadow_env_resolved="1"
elif [[ "$ci_phase5_summary_usable" == "1" ]]; then
  reasons+=("settlement_shadow_env_ok could not be resolved from ci phase5 summary")
fi
if [[ -n "$(trim "$settlement_shadow_status_surface_raw")" ]]; then
  settlement_shadow_status_surface_resolved="1"
elif [[ "$ci_phase5_summary_usable" == "1" ]]; then
  reasons+=("settlement_shadow_status_surface_ok could not be resolved from ci phase5 summary")
fi
if [[ -n "$(trim "$settlement_state_persistence_raw")" ]]; then
  settlement_state_persistence_resolved="1"
elif [[ "$ci_phase5_summary_usable" == "1" ]]; then
  reasons+=("settlement_state_persistence_ok could not be resolved from ci phase5 summary")
fi
if [[ -n "$(trim "$settlement_dual_asset_parity_raw")" ]]; then
  settlement_dual_asset_parity_resolved="1"
elif [[ "$ci_phase5_summary_usable" == "1" ]]; then
  reasons+=("settlement_dual_asset_parity_ok could not be resolved from ci phase5 summary")
fi
if [[ -n "$(trim "$issuer_sponsor_api_live_smoke_raw")" ]]; then
  issuer_sponsor_api_live_smoke_resolved="1"
elif [[ "$ci_phase5_summary_usable" == "1" ]]; then
  reasons+=("issuer_sponsor_api_live_smoke_ok could not be resolved from ci phase5 summary")
fi
if [[ -n "$(trim "$issuer_sponsor_vpn_session_live_smoke_raw")" ]]; then
  issuer_sponsor_vpn_session_live_smoke_resolved="1"
elif [[ "$ci_phase5_summary_usable" == "1" ]]; then
  reasons+=("issuer_sponsor_vpn_session_live_smoke_ok could not be resolved from ci phase5 summary")
fi
if [[ -n "$(trim "$issuer_settlement_status_live_smoke_raw")" ]]; then
  issuer_settlement_status_live_smoke_resolved="1"
elif [[ "$ci_phase5_summary_usable" == "1" ]]; then
  reasons+=("issuer_settlement_status_live_smoke_ok could not be resolved from ci phase5 summary")
fi
if [[ -n "$(trim "$exit_settlement_status_live_smoke_raw")" ]]; then
  exit_settlement_status_live_smoke_resolved="1"
elif [[ "$ci_phase5_summary_usable" == "1" ]]; then
  reasons+=("exit_settlement_status_live_smoke_ok could not be resolved from ci phase5 summary")
fi
if [[ -n "$(trim "$issuer_admin_blockchain_handlers_coverage_raw")" ]]; then
  issuer_admin_blockchain_handlers_coverage_resolved="1"
elif [[ "$ci_phase5_summary_usable" == "1" ]]; then
  reasons+=("issuer_admin_blockchain_handlers_coverage_ok could not be resolved from ci phase5 summary")
fi

if [[ "$require_settlement_failsoft_ok" == "1" && "$settlement_failsoft_ok" != "true" ]]; then
  reasons+=("settlement_failsoft_ok is false")
fi
if [[ "$require_settlement_acceptance_ok" == "1" && "$settlement_acceptance_ok" != "true" ]]; then
  reasons+=("settlement_acceptance_ok is false")
fi
if [[ "$require_settlement_bridge_smoke_ok" == "1" && "$settlement_bridge_smoke_ok" != "true" ]]; then
  reasons+=("settlement_bridge_smoke_ok is false")
fi
if [[ "$require_settlement_adapter_roundtrip_ok" == "1" && "$settlement_adapter_roundtrip_ok" != "true" ]]; then
  reasons+=("settlement_adapter_roundtrip_ok is false")
fi
if [[ "$require_settlement_adapter_signed_tx_roundtrip_ok" == "1" && "$settlement_adapter_signed_tx_roundtrip_ok" != "true" ]]; then
  reasons+=("settlement_adapter_signed_tx_roundtrip_ok is false")
fi
if [[ "$require_settlement_shadow_env_ok" == "1" && "$settlement_shadow_env_ok" != "true" ]]; then
  reasons+=("settlement_shadow_env_ok is false")
fi
if [[ "$require_settlement_shadow_status_surface_ok" == "1" && "$settlement_shadow_status_surface_ok" != "true" ]]; then
  reasons+=("settlement_shadow_status_surface_ok is false")
fi
if [[ "$require_settlement_state_persistence_ok" == "1" && "$settlement_state_persistence_ok" != "true" ]]; then
  reasons+=("settlement_state_persistence_ok is false")
fi
if [[ "$require_settlement_dual_asset_parity_ok" == "1" && "$settlement_dual_asset_parity_ok" != "true" ]]; then
  reasons+=("settlement_dual_asset_parity_ok is false")
fi
if [[ "$require_issuer_sponsor_api_live_smoke_ok" == "1" && "$issuer_sponsor_api_live_smoke_ok" != "true" ]]; then
  reasons+=("issuer_sponsor_api_live_smoke_ok is false")
fi
if [[ "$require_issuer_sponsor_vpn_session_live_smoke_ok" == "1" && "$issuer_sponsor_vpn_session_live_smoke_ok" != "true" ]]; then
  reasons+=("issuer_sponsor_vpn_session_live_smoke_ok is false")
fi
if [[ "$require_issuer_settlement_status_live_smoke_ok" == "1" && "$issuer_settlement_status_live_smoke_ok" != "true" ]]; then
  reasons+=("issuer_settlement_status_live_smoke_ok is false")
fi
if [[ "$require_exit_settlement_status_live_smoke_ok" == "1" && "$exit_settlement_status_live_smoke_ok" != "true" ]]; then
  reasons+=("exit_settlement_status_live_smoke_ok is false")
fi
if [[ "$require_issuer_admin_blockchain_handlers_coverage_ok" == "1" && "$issuer_admin_blockchain_handlers_coverage_ok" != "true" ]]; then
  reasons+=("issuer_admin_blockchain_handlers_coverage_ok is false")
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
  "$ci_phase5_summary_json" \
  "$ci_phase5_summary_usable" \
  "$show_json" \
  "$require_settlement_failsoft_ok" \
  "$require_settlement_acceptance_ok" \
  "$require_settlement_bridge_smoke_ok" \
  "$require_settlement_adapter_roundtrip_ok" \
  "$require_settlement_state_persistence_ok" \
  "$settlement_failsoft_status" \
  "$settlement_acceptance_status" \
  "$settlement_bridge_smoke_status" \
  "$settlement_adapter_roundtrip_status" \
  "$settlement_state_persistence_status" \
  "$settlement_failsoft_ok" \
  "$settlement_acceptance_ok" \
  "$settlement_bridge_smoke_ok" \
  "$settlement_adapter_roundtrip_ok" \
  "$settlement_state_persistence_ok" \
  "$settlement_failsoft_resolved" \
  "$settlement_acceptance_resolved" \
  "$settlement_bridge_smoke_resolved" \
  "$settlement_adapter_roundtrip_resolved" \
  "$settlement_state_persistence_resolved" \
  "$reasons_json" \
  "$require_issuer_sponsor_api_live_smoke_ok" \
  "$issuer_sponsor_api_live_smoke_status" \
  "$issuer_sponsor_api_live_smoke_ok" \
  "$issuer_sponsor_api_live_smoke_resolved" \
  "$require_issuer_settlement_status_live_smoke_ok" \
  "$issuer_settlement_status_live_smoke_status" \
  "$issuer_settlement_status_live_smoke_ok" \
  "$issuer_settlement_status_live_smoke_resolved" \
  "$require_exit_settlement_status_live_smoke_ok" \
  "$exit_settlement_status_live_smoke_status" \
  "$exit_settlement_status_live_smoke_ok" \
  "$exit_settlement_status_live_smoke_resolved" \
  "$require_settlement_dual_asset_parity_ok" \
  "$settlement_dual_asset_parity_status" \
  "$settlement_dual_asset_parity_ok" \
  "$settlement_dual_asset_parity_resolved" \
  "$require_issuer_admin_blockchain_handlers_coverage_ok" \
  "$issuer_admin_blockchain_handlers_coverage_status" \
  "$issuer_admin_blockchain_handlers_coverage_ok" \
  "$issuer_admin_blockchain_handlers_coverage_resolved" \
  "$require_settlement_adapter_signed_tx_roundtrip_ok" \
  "$settlement_adapter_signed_tx_roundtrip_status" \
  "$settlement_adapter_signed_tx_roundtrip_ok" \
  "$settlement_adapter_signed_tx_roundtrip_resolved" \
  "$require_settlement_shadow_env_ok" \
  "$settlement_shadow_env_status" \
  "$settlement_shadow_env_ok" \
  "$settlement_shadow_env_resolved" \
  "$require_settlement_shadow_status_surface_ok" \
  "$settlement_shadow_status_surface_status" \
  "$settlement_shadow_status_surface_ok" \
  "$settlement_shadow_status_surface_resolved" \
  "$require_issuer_sponsor_vpn_session_live_smoke_ok" \
  "$issuer_sponsor_vpn_session_live_smoke_status" \
  "$issuer_sponsor_vpn_session_live_smoke_ok" \
  "$issuer_sponsor_vpn_session_live_smoke_resolved"

if [[ "$show_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$status" == "pass" ]]; then
  exit 0
fi
exit 1
