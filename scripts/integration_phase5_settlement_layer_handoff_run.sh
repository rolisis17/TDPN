#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod grep cat cmp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

RUNNER="${PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase5_settlement_layer_handoff_run.sh}"
if [[ ! -x "$RUNNER" ]]; then
  echo "missing executable script under test: $RUNNER"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.tsv"
PASS_STDOUT="$TMP_DIR/pass.stdout"
DRY_STDOUT="$TMP_DIR/dry.stdout"
ENV_DRY_STDOUT="$TMP_DIR/env_dry.stdout"
FAIL_STDOUT="$TMP_DIR/fail.stdout"
RUN_CONTRACT_FAIL_STDOUT="$TMP_DIR/run_contract_fail.stdout"
HANDOFF_CONTRACT_FAIL_STDOUT="$TMP_DIR/handoff_contract_fail.stdout"
PASS_CANONICAL_SUMMARY="$TMP_DIR/pass_wrapper_canonical.json"
DRY_CANONICAL_SUMMARY="$TMP_DIR/dry_wrapper_canonical.json"
ENV_DRY_CANONICAL_SUMMARY="$TMP_DIR/env_dry_wrapper_canonical.json"
FAIL_CANONICAL_SUMMARY="$TMP_DIR/fail_wrapper_canonical.json"
RUN_CONTRACT_FAIL_CANONICAL_SUMMARY="$TMP_DIR/run_contract_fail_canonical.json"
HANDOFF_CONTRACT_FAIL_CANONICAL_SUMMARY="$TMP_DIR/handoff_contract_fail_canonical.json"

FAKE_RUN="$TMP_DIR/fake_phase5_settlement_layer_run.sh"
cat >"$FAKE_RUN" <<'EOF_FAKE_RUN'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE5_HANDOFF_RUN_CAPTURE_FILE:-${PHASE4_HANDOFF_RUN_CAPTURE_FILE:-}}"
if [[ -z "$capture" ]]; then
  echo "missing capture file env: PHASE5_HANDOFF_RUN_CAPTURE_FILE"
  exit 2
fi
printf 'run\t%s\n' "$*" >>"$capture"

reports_dir=""
summary_json=""
dry_run="0"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --dry-run)
      dry_run="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

status="pass"
rc=0
if [[ "${FAKE_RUN_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc="${FAKE_RUN_FAIL_RC:-31}"
fi

check_summary="${FAKE_RUN_CHECK_SUMMARY:-${reports_dir}/phase5_settlement_layer_check_summary.json}"
roadmap_summary="${FAKE_RUN_ROADMAP_SUMMARY:-${reports_dir}/roadmap_progress_summary.json}"
mkdir -p "$(dirname "$check_summary")" "$(dirname "$roadmap_summary")"

cat >"$check_summary" <<'EOF_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "signals": {
    "settlement_failsoft_ok": true,
    "settlement_acceptance_ok": true,
    "settlement_bridge_smoke_ok": true,
    "settlement_state_persistence_ok": true,
    "settlement_dual_asset_parity_ok": true,
    "issuer_sponsor_api_live_smoke_ok": true
  }
}
EOF_CHECK

cat >"$roadmap_summary" <<'EOF_ROADMAP'
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "vpn_track": {
    "phase5_settlement_layer_handoff": {
      "settlement_failsoft_ok": true,
      "settlement_acceptance_ok": true,
      "settlement_bridge_smoke_ok": true,
      "settlement_state_persistence_ok": true,
      "settlement_dual_asset_parity_ok": true,
      "issuer_sponsor_api_live_smoke_ok": true
    }
  }
}
EOF_ROADMAP

if [[ -n "$summary_json" && "${FAKE_RUN_OMIT_SUMMARY:-0}" != "1" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<EOF_SUMMARY
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc,
  "steps": {
    "ci_phase5_settlement_layer": {
      "status": "$status",
      "rc": $rc,
      "command_rc": $rc,
      "contract_valid": true
    },
    "phase5_settlement_layer_check": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "$check_summary",
        "roadmap_summary_json": "$roadmap_summary"
      }
    }
  },
  "artifacts": {
    "check_summary_json": "$check_summary",
    "roadmap_summary_json": "$roadmap_summary"
  }
}
EOF_SUMMARY
fi

if [[ "${FAKE_RUN_FAIL:-0}" == "1" ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_RUN
chmod +x "$FAKE_RUN"

FAKE_HANDOFF="$TMP_DIR/fake_phase5_settlement_layer_handoff_check.sh"
cat >"$FAKE_HANDOFF" <<'EOF_FAKE_HANDOFF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--help" ]]; then
  help_mode="${FAKE_HANDOFF_HELP_MODE:-canonical}"
  if [[ "$help_mode" == "legacy" ]]; then
    cat <<'EOF_HELP_LEGACY'
Usage:
  fake_phase5_settlement_layer_handoff_check.sh [flags]

Flags:
  --require-run-pipeline-ok [0|1]
  --require-windows-server-packaging-ok [0|1]
  --require-windows-role-runbooks-ok [0|1]
  --require-cross-platform-interop-ok [0|1]
  --require-role-combination-validation-ok [0|1]
  --require-settlement-dual-asset-ok [0|1]
EOF_HELP_LEGACY
  else
    cat <<'EOF_HELP'
Usage:
  fake_phase5_settlement_layer_handoff_check.sh [flags]

Flags:
  --require-run-pipeline-ok [0|1]
  --require-settlement-failsoft-ok [0|1]
  --require-settlement-acceptance-ok [0|1]
  --require-settlement-bridge-smoke-ok [0|1]
  --require-settlement-state-persistence-ok [0|1]
  --require-settlement-dual-asset-parity-ok [0|1]
  --require-settlement-adapter-signed-tx-roundtrip-ok [0|1]
  --require-settlement-shadow-env-ok [0|1]
  --require-settlement-shadow-status-surface-ok [0|1]
  --require-issuer-sponsor-api-live-smoke-ok [0|1]
  --require-issuer-sponsor-vpn-session-live-smoke-ok [0|1]
  --require-issuer-settlement-status-live-smoke-ok [0|1]
  --require-exit-settlement-status-live-smoke-ok [0|1]
  --require-issuer-admin-blockchain-handlers-coverage-ok [0|1]
EOF_HELP
  fi
  exit 0
fi

capture="${PHASE5_HANDOFF_RUN_CAPTURE_FILE:-${PHASE4_HANDOFF_RUN_CAPTURE_FILE:-}}"
if [[ -z "$capture" ]]; then
  echo "missing capture file env: PHASE5_HANDOFF_RUN_CAPTURE_FILE"
  exit 2
fi
printf 'handoff\t%s\n' "$*" >>"$capture"

summary_json=""
require_issuer_sponsor_api_live_smoke_ok="1"
require_settlement_dual_asset_parity_ok="1"
require_settlement_adapter_signed_tx_roundtrip_ok="1"
require_settlement_shadow_env_ok="1"
require_settlement_shadow_status_surface_ok="1"
require_issuer_settlement_status_live_smoke_ok="0"
require_exit_settlement_status_live_smoke_ok="0"
require_issuer_sponsor_vpn_session_live_smoke_ok="1"
require_issuer_admin_blockchain_handlers_coverage_ok="1"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
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
    --require-settlement-dual-asset-parity-ok|--require-settlement-dual-asset-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_settlement_dual_asset_parity_ok="${2:-}"
        shift 2
      else
        require_settlement_dual_asset_parity_ok="1"
        shift
      fi
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
    *)
      shift
      ;;
  esac
done

status="pass"
rc=0
if [[ "${FAKE_HANDOFF_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc="${FAKE_HANDOFF_FAIL_RC:-19}"
fi

sponsor_mode="${FAKE_HANDOFF_SPONSOR_SIGNAL_MODE:-pass}"
sponsor_ok_json="true"
sponsor_status="pass"
sponsor_resolved_json="true"
sponsor_source="phase5_settlement_layer_handoff_check.signals.issuer_sponsor_api_live_smoke_ok"
case "$sponsor_mode" in
  unresolved)
    sponsor_ok_json="null"
    sponsor_status="missing"
    sponsor_resolved_json="false"
    sponsor_source="unresolved"
    ;;
  fail)
    sponsor_ok_json="false"
    sponsor_status="fail"
    sponsor_resolved_json="true"
    ;;
  *)
    sponsor_ok_json="true"
    sponsor_status="pass"
    sponsor_resolved_json="true"
    ;;
esac

sponsor_vpn_session_mode="${FAKE_HANDOFF_ISSUER_SPONSOR_VPN_SESSION_LIVE_SMOKE_SIGNAL_MODE:-pass}"
sponsor_vpn_session_ok_json="true"
sponsor_vpn_session_status="pass"
sponsor_vpn_session_resolved_json="true"
sponsor_vpn_session_source="phase5_settlement_layer_handoff_check.signals.issuer_sponsor_vpn_session_live_smoke_ok"
case "$sponsor_vpn_session_mode" in
  unresolved)
    sponsor_vpn_session_ok_json="null"
    sponsor_vpn_session_status="missing"
    sponsor_vpn_session_resolved_json="false"
    sponsor_vpn_session_source="unresolved"
    ;;
  fail)
    sponsor_vpn_session_ok_json="false"
    sponsor_vpn_session_status="fail"
    sponsor_vpn_session_resolved_json="true"
    ;;
  *)
    sponsor_vpn_session_ok_json="true"
    sponsor_vpn_session_status="pass"
    sponsor_vpn_session_resolved_json="true"
    ;;
esac

issuer_settlement_status_mode="${FAKE_HANDOFF_ISSUER_SETTLEMENT_STATUS_SIGNAL_MODE:-pass}"
issuer_settlement_status_ok_json="true"
issuer_settlement_status_status="pass"
issuer_settlement_status_resolved_json="true"
issuer_settlement_status_source="phase5_settlement_layer_handoff_check.signals.issuer_settlement_status_live_smoke_ok"
case "$issuer_settlement_status_mode" in
  unresolved)
    issuer_settlement_status_ok_json="null"
    issuer_settlement_status_status="missing"
    issuer_settlement_status_resolved_json="false"
    issuer_settlement_status_source="unresolved"
    ;;
  fail)
    issuer_settlement_status_ok_json="false"
    issuer_settlement_status_status="fail"
    issuer_settlement_status_resolved_json="true"
    ;;
  *)
    issuer_settlement_status_ok_json="true"
    issuer_settlement_status_status="pass"
    issuer_settlement_status_resolved_json="true"
    ;;
esac

exit_settlement_status_mode="${FAKE_HANDOFF_EXIT_SETTLEMENT_STATUS_SIGNAL_MODE:-pass}"
exit_settlement_status_ok_json="true"
exit_settlement_status_status="pass"
exit_settlement_status_resolved_json="true"
exit_settlement_status_source="phase5_settlement_layer_handoff_check.signals.exit_settlement_status_live_smoke_ok"
case "$exit_settlement_status_mode" in
  unresolved)
    exit_settlement_status_ok_json="null"
    exit_settlement_status_status="missing"
    exit_settlement_status_resolved_json="false"
    exit_settlement_status_source="unresolved"
    ;;
  fail)
    exit_settlement_status_ok_json="false"
    exit_settlement_status_status="fail"
    exit_settlement_status_resolved_json="true"
    ;;
  *)
    exit_settlement_status_ok_json="true"
    exit_settlement_status_status="pass"
    exit_settlement_status_resolved_json="true"
    ;;
esac

dual_asset_mode="${FAKE_HANDOFF_DUAL_ASSET_SIGNAL_MODE:-pass}"
dual_asset_ok_json="true"
dual_asset_status="pass"
dual_asset_resolved_json="true"
dual_asset_source="phase5_settlement_layer_handoff_check.signals.settlement_dual_asset_parity_ok"
case "$dual_asset_mode" in
  unresolved)
    dual_asset_ok_json="null"
    dual_asset_status="missing"
    dual_asset_resolved_json="false"
    dual_asset_source="unresolved"
    ;;
  fail)
    dual_asset_ok_json="false"
    dual_asset_status="fail"
    dual_asset_resolved_json="true"
    ;;
  *)
    dual_asset_ok_json="true"
    dual_asset_status="pass"
    dual_asset_resolved_json="true"
    ;;
esac

adapter_signed_tx_mode="${FAKE_HANDOFF_SETTLEMENT_ADAPTER_SIGNED_TX_ROUNDTRIP_SIGNAL_MODE:-pass}"
adapter_signed_tx_ok_json="true"
adapter_signed_tx_status="pass"
adapter_signed_tx_resolved_json="true"
adapter_signed_tx_source="phase5_settlement_layer_handoff_check.signals.settlement_adapter_signed_tx_roundtrip_ok"
case "$adapter_signed_tx_mode" in
  unresolved)
    adapter_signed_tx_ok_json="null"
    adapter_signed_tx_status="missing"
    adapter_signed_tx_resolved_json="false"
    adapter_signed_tx_source="unresolved"
    ;;
  fail)
    adapter_signed_tx_ok_json="false"
    adapter_signed_tx_status="fail"
    adapter_signed_tx_resolved_json="true"
    ;;
  *)
    adapter_signed_tx_ok_json="true"
    adapter_signed_tx_status="pass"
    adapter_signed_tx_resolved_json="true"
    ;;
esac

shadow_env_mode="${FAKE_HANDOFF_SETTLEMENT_SHADOW_ENV_SIGNAL_MODE:-pass}"
shadow_env_ok_json="true"
shadow_env_status="pass"
shadow_env_resolved_json="true"
shadow_env_source="phase5_settlement_layer_handoff_check.signals.settlement_shadow_env_ok"
case "$shadow_env_mode" in
  unresolved)
    shadow_env_ok_json="null"
    shadow_env_status="missing"
    shadow_env_resolved_json="false"
    shadow_env_source="unresolved"
    ;;
  fail)
    shadow_env_ok_json="false"
    shadow_env_status="fail"
    shadow_env_resolved_json="true"
    ;;
  *)
    shadow_env_ok_json="true"
    shadow_env_status="pass"
    shadow_env_resolved_json="true"
    ;;
esac

shadow_status_surface_mode="${FAKE_HANDOFF_SETTLEMENT_SHADOW_STATUS_SURFACE_SIGNAL_MODE:-pass}"
shadow_status_surface_ok_json="true"
shadow_status_surface_status="pass"
shadow_status_surface_resolved_json="true"
shadow_status_surface_source="phase5_settlement_layer_handoff_check.signals.settlement_shadow_status_surface_ok"
case "$shadow_status_surface_mode" in
  unresolved)
    shadow_status_surface_ok_json="null"
    shadow_status_surface_status="missing"
    shadow_status_surface_resolved_json="false"
    shadow_status_surface_source="unresolved"
    ;;
  fail)
    shadow_status_surface_ok_json="false"
    shadow_status_surface_status="fail"
    shadow_status_surface_resolved_json="true"
    ;;
  *)
    shadow_status_surface_ok_json="true"
    shadow_status_surface_status="pass"
    shadow_status_surface_resolved_json="true"
    ;;
esac

issuer_admin_mode="${FAKE_HANDOFF_ISSUER_ADMIN_BLOCKCHAIN_HANDLERS_COVERAGE_SIGNAL_MODE:-pass}"
issuer_admin_ok_json="true"
issuer_admin_status="pass"
issuer_admin_resolved_json="true"
issuer_admin_source="phase5_settlement_layer_handoff_check.signals.issuer_admin_blockchain_handlers_coverage_ok"
case "$issuer_admin_mode" in
  unresolved)
    issuer_admin_ok_json="null"
    issuer_admin_status="missing"
    issuer_admin_resolved_json="false"
    issuer_admin_source="unresolved"
    ;;
  fail)
    issuer_admin_ok_json="false"
    issuer_admin_status="fail"
    issuer_admin_resolved_json="true"
    ;;
  *)
    issuer_admin_ok_json="true"
    issuer_admin_status="pass"
    issuer_admin_resolved_json="true"
    ;;
esac

if [[ -n "$summary_json" && "${FAKE_HANDOFF_OMIT_SUMMARY:-0}" != "1" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<EOF_SUMMARY
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc,
  "fail_closed": true,
  "inputs": {
    "requirements": {
      "settlement_dual_asset_parity_ok": $( [[ "$require_settlement_dual_asset_parity_ok" == "1" ]] && printf '%s' "true" || printf '%s' "false" ),
      "settlement_adapter_signed_tx_roundtrip_ok": $( [[ "$require_settlement_adapter_signed_tx_roundtrip_ok" == "1" ]] && printf '%s' "true" || printf '%s' "false" ),
      "settlement_shadow_env_ok": $( [[ "$require_settlement_shadow_env_ok" == "1" ]] && printf '%s' "true" || printf '%s' "false" ),
      "settlement_shadow_status_surface_ok": $( [[ "$require_settlement_shadow_status_surface_ok" == "1" ]] && printf '%s' "true" || printf '%s' "false" ),
      "issuer_sponsor_api_live_smoke_ok": $( [[ "$require_issuer_sponsor_api_live_smoke_ok" == "1" ]] && printf '%s' "true" || printf '%s' "false" ),
      "issuer_sponsor_vpn_session_live_smoke_ok": $( [[ "$require_issuer_sponsor_vpn_session_live_smoke_ok" == "1" ]] && printf '%s' "true" || printf '%s' "false" ),
      "issuer_settlement_status_live_smoke_ok": $( [[ "$require_issuer_settlement_status_live_smoke_ok" == "1" ]] && printf '%s' "true" || printf '%s' "false" ),
      "exit_settlement_status_live_smoke_ok": $( [[ "$require_exit_settlement_status_live_smoke_ok" == "1" ]] && printf '%s' "true" || printf '%s' "false" ),
      "issuer_admin_blockchain_handlers_coverage_ok": $( [[ "$require_issuer_admin_blockchain_handlers_coverage_ok" == "1" ]] && printf '%s' "true" || printf '%s' "false" )
    }
  },
  "handoff": {
    "run_pipeline_ok": true,
    "settlement_failsoft_ok": true,
    "settlement_acceptance_ok": true,
    "settlement_bridge_smoke_ok": true,
    "settlement_state_persistence_ok": true,
    "settlement_dual_asset_parity_ok": $dual_asset_ok_json,
    "settlement_dual_asset_parity_status": "$dual_asset_status",
    "settlement_dual_asset_parity_resolved": $dual_asset_resolved_json,
    "settlement_adapter_signed_tx_roundtrip_ok": $adapter_signed_tx_ok_json,
    "settlement_adapter_signed_tx_roundtrip_status": "$adapter_signed_tx_status",
    "settlement_adapter_signed_tx_roundtrip_resolved": $adapter_signed_tx_resolved_json,
    "settlement_shadow_env_ok": $shadow_env_ok_json,
    "settlement_shadow_env_status": "$shadow_env_status",
    "settlement_shadow_env_resolved": $shadow_env_resolved_json,
    "settlement_shadow_status_surface_ok": $shadow_status_surface_ok_json,
    "settlement_shadow_status_surface_status": "$shadow_status_surface_status",
    "settlement_shadow_status_surface_resolved": $shadow_status_surface_resolved_json,
    "issuer_sponsor_api_live_smoke_ok": $sponsor_ok_json,
    "issuer_sponsor_api_live_smoke_status": "$sponsor_status",
    "issuer_sponsor_api_live_smoke_resolved": $sponsor_resolved_json,
    "issuer_sponsor_vpn_session_live_smoke_ok": $sponsor_vpn_session_ok_json,
    "issuer_sponsor_vpn_session_live_smoke_status": "$sponsor_vpn_session_status",
    "issuer_sponsor_vpn_session_live_smoke_resolved": $sponsor_vpn_session_resolved_json,
    "issuer_settlement_status_live_smoke_ok": $issuer_settlement_status_ok_json,
    "issuer_settlement_status_live_smoke_status": "$issuer_settlement_status_status",
    "issuer_settlement_status_live_smoke_resolved": $issuer_settlement_status_resolved_json,
    "exit_settlement_status_live_smoke_ok": $exit_settlement_status_ok_json,
    "exit_settlement_status_live_smoke_status": "$exit_settlement_status_status",
    "exit_settlement_status_live_smoke_resolved": $exit_settlement_status_resolved_json,
    "issuer_admin_blockchain_handlers_coverage_ok": $issuer_admin_ok_json,
    "issuer_admin_blockchain_handlers_coverage_status": "$issuer_admin_status",
    "issuer_admin_blockchain_handlers_coverage_resolved": $issuer_admin_resolved_json,
    "sources": {
      "settlement_dual_asset_parity_ok": "$dual_asset_source",
      "settlement_adapter_signed_tx_roundtrip_ok": "$adapter_signed_tx_source",
      "settlement_shadow_env_ok": "$shadow_env_source",
      "settlement_shadow_status_surface_ok": "$shadow_status_surface_source",
      "issuer_sponsor_api_live_smoke_ok": "$sponsor_source",
      "issuer_sponsor_vpn_session_live_smoke_ok": "$sponsor_vpn_session_source",
      "issuer_settlement_status_live_smoke_ok": "$issuer_settlement_status_source",
      "exit_settlement_status_live_smoke_ok": "$exit_settlement_status_source",
      "issuer_admin_blockchain_handlers_coverage_ok": "$issuer_admin_source"
    }
  },
  "decision": {
    "pass": true,
    "reasons": [],
    "warnings": []
  }
}
EOF_SUMMARY
fi

if [[ "${FAKE_HANDOFF_FAIL:-0}" == "1" ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_HANDOFF
chmod +x "$FAKE_HANDOFF"

echo "[phase5-settlement-layer-handoff-run] pass path"
: >"$CAPTURE"
PASS_WRAPPER_SUMMARY="$TMP_DIR/pass_wrapper.json"
PHASE5_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_CANONICAL_SUMMARY_JSON="$PASS_CANONICAL_SUMMARY" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_pass" \
  --run-summary-json "$TMP_DIR/pass_run_summary.json" \
  --handoff-summary-json "$TMP_DIR/pass_handoff_summary.json" \
  --summary-json "$PASS_WRAPPER_SUMMARY" \
  --print-summary-json 0 \
  --run-gamma 7 \
  --handoff-require-run-pipeline-ok 1 >"$PASS_STDOUT" 2>&1

run_line="$(grep '^run	' "$CAPTURE" | tail -n 1 || true)"
handoff_line="$(grep '^handoff	' "$CAPTURE" | tail -n 1 || true)"
if [[ "$run_line" != *"--reports-dir $TMP_DIR/reports_pass"* || "$run_line" != *"--summary-json $TMP_DIR/pass_run_summary.json"* ]]; then
  echo "run forwarding mismatch"
  echo "$run_line"
  exit 1
fi
if [[ "$run_line" != *"--gamma 7"* ]]; then
  echo "run passthrough mismatch"
  echo "$run_line"
  exit 1
fi
if [[ "$handoff_line" != *"--phase5-run-summary-json $TMP_DIR/pass_run_summary.json"* || "$handoff_line" != *"--roadmap-summary-json $TMP_DIR/reports_pass/roadmap_progress_summary.json"* ]]; then
  echo "handoff forwarding mismatch"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" != *"--require-run-pipeline-ok 1"* || "$handoff_line" != *"--show-json 0"* || "$handoff_line" != *"--require-issuer-admin-blockchain-handlers-coverage-ok 1"* ]]; then
  echo "handoff default forwarding mismatch"
  echo "$handoff_line"
  exit 1
fi
if [[ ! -f "$PASS_CANONICAL_SUMMARY" ]]; then
  echo "missing pass-path canonical summary file: $PASS_CANONICAL_SUMMARY"
  exit 1
fi
if ! cmp -s "$PASS_WRAPPER_SUMMARY" "$PASS_CANONICAL_SUMMARY"; then
  echo "pass-path canonical summary content mismatch"
  cat "$PASS_WRAPPER_SUMMARY"
  cat "$PASS_CANONICAL_SUMMARY"
  exit 1
fi
if ! grep -Fq -- "[phase5-settlement-layer-handoff-run] canonical_summary_json=$PASS_CANONICAL_SUMMARY" "$PASS_STDOUT"; then
  echo "pass-path log missing canonical summary line"
  cat "$PASS_STDOUT"
  exit 1
fi

if ! jq -e --arg run_summary "$TMP_DIR/pass_run_summary.json" --arg handoff_summary "$TMP_DIR/pass_handoff_summary.json" --arg canonical "$PASS_CANONICAL_SUMMARY" '
  .version == 1
  and .schema.id == "phase5_settlement_layer_handoff_run_summary"
  and .status == "pass"
  and .rc == 0
  and .artifacts.canonical_summary_json == $canonical
  and .inputs.dry_run == false
  and .steps.phase5_settlement_layer_run.status == "pass"
  and .steps.phase5_settlement_layer_run.rc == 0
  and .steps.phase5_settlement_layer_run.command_rc == 0
  and .steps.phase5_settlement_layer_run.contract_valid == true
  and .steps.phase5_settlement_layer_run.artifacts.summary_json == $run_summary
  and .steps.phase5_settlement_layer_handoff_check.status == "pass"
  and .steps.phase5_settlement_layer_handoff_check.rc == 0
  and .steps.phase5_settlement_layer_handoff_check.command_rc == 0
  and .steps.phase5_settlement_layer_handoff_check.contract_valid == true
  and .steps.phase5_settlement_layer_handoff_check.artifacts.summary_json == $handoff_summary
  and .handoff.settlement_dual_asset_parity_ok == true
  and .handoff.settlement_dual_asset_parity_status == "pass"
  and .handoff.settlement_dual_asset_parity_required == true
  and .handoff.settlement_dual_asset_parity_resolved == true
  and .handoff.sources.settlement_dual_asset_parity_ok == "phase5_settlement_layer_handoff_check.signals.settlement_dual_asset_parity_ok"
  and .handoff.settlement_adapter_signed_tx_roundtrip_ok == true
  and .handoff.settlement_adapter_signed_tx_roundtrip_status == "pass"
  and .handoff.settlement_adapter_signed_tx_roundtrip_required == true
  and .handoff.settlement_adapter_signed_tx_roundtrip_resolved == true
  and .handoff.sources.settlement_adapter_signed_tx_roundtrip_ok == "phase5_settlement_layer_handoff_check.signals.settlement_adapter_signed_tx_roundtrip_ok"
  and .handoff.settlement_shadow_env_ok == true
  and .handoff.settlement_shadow_env_status == "pass"
  and .handoff.settlement_shadow_env_required == true
  and .handoff.settlement_shadow_env_resolved == true
  and .handoff.sources.settlement_shadow_env_ok == "phase5_settlement_layer_handoff_check.signals.settlement_shadow_env_ok"
  and .handoff.settlement_shadow_status_surface_ok == true
  and .handoff.settlement_shadow_status_surface_status == "pass"
  and .handoff.settlement_shadow_status_surface_required == true
  and .handoff.settlement_shadow_status_surface_resolved == true
  and .handoff.sources.settlement_shadow_status_surface_ok == "phase5_settlement_layer_handoff_check.signals.settlement_shadow_status_surface_ok"
  and .handoff.issuer_sponsor_api_live_smoke_ok == true
  and .handoff.issuer_sponsor_api_live_smoke_status == "pass"
  and .handoff.issuer_sponsor_api_live_smoke_required == true
  and .handoff.issuer_sponsor_api_live_smoke_resolved == true
  and .handoff.sources.issuer_sponsor_api_live_smoke_ok == "phase5_settlement_layer_handoff_check.signals.issuer_sponsor_api_live_smoke_ok"
  and .handoff.issuer_sponsor_vpn_session_live_smoke_ok == true
  and .handoff.issuer_sponsor_vpn_session_live_smoke_status == "pass"
  and .handoff.issuer_sponsor_vpn_session_live_smoke_required == true
  and .handoff.issuer_sponsor_vpn_session_live_smoke_resolved == true
  and .handoff.sources.issuer_sponsor_vpn_session_live_smoke_ok == "phase5_settlement_layer_handoff_check.signals.issuer_sponsor_vpn_session_live_smoke_ok"
  and .handoff.issuer_settlement_status_live_smoke_ok == true
  and .handoff.issuer_settlement_status_live_smoke_status == "pass"
  and .handoff.issuer_settlement_status_live_smoke_required == false
  and .handoff.issuer_settlement_status_live_smoke_resolved == true
  and .handoff.sources.issuer_settlement_status_live_smoke_ok == "phase5_settlement_layer_handoff_check.signals.issuer_settlement_status_live_smoke_ok"
  and .handoff.exit_settlement_status_live_smoke_ok == true
  and .handoff.exit_settlement_status_live_smoke_status == "pass"
  and .handoff.exit_settlement_status_live_smoke_required == false
  and .handoff.exit_settlement_status_live_smoke_resolved == true
  and .handoff.sources.exit_settlement_status_live_smoke_ok == "phase5_settlement_layer_handoff_check.signals.exit_settlement_status_live_smoke_ok"
  and .handoff.issuer_admin_blockchain_handlers_coverage_ok == true
  and .handoff.issuer_admin_blockchain_handlers_coverage_status == "pass"
  and .handoff.issuer_admin_blockchain_handlers_coverage_required == true
  and .handoff.issuer_admin_blockchain_handlers_coverage_resolved == true
  and .handoff.sources.issuer_admin_blockchain_handlers_coverage_ok == "phase5_settlement_layer_handoff_check.signals.issuer_admin_blockchain_handlers_coverage_ok"
' "$PASS_WRAPPER_SUMMARY" >/dev/null; then
  echo "pass-path combined summary mismatch"
  cat "$PASS_WRAPPER_SUMMARY"
  exit 1
fi

echo "[phase5-settlement-layer-handoff-run] dry-run forwarding and relax behavior"
: >"$CAPTURE"
DRY_WRAPPER_SUMMARY="$TMP_DIR/dry_wrapper.json"
PHASE5_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_CANONICAL_SUMMARY_JSON="$DRY_CANONICAL_SUMMARY" \
FAKE_HANDOFF_SPONSOR_SIGNAL_MODE=unresolved \
FAKE_HANDOFF_ISSUER_SETTLEMENT_STATUS_SIGNAL_MODE=unresolved \
FAKE_HANDOFF_EXIT_SETTLEMENT_STATUS_SIGNAL_MODE=unresolved \
FAKE_HANDOFF_DUAL_ASSET_SIGNAL_MODE=unresolved \
FAKE_HANDOFF_SETTLEMENT_ADAPTER_SIGNED_TX_ROUNDTRIP_SIGNAL_MODE=unresolved \
FAKE_HANDOFF_SETTLEMENT_SHADOW_ENV_SIGNAL_MODE=unresolved \
FAKE_HANDOFF_SETTLEMENT_SHADOW_STATUS_SURFACE_SIGNAL_MODE=unresolved \
FAKE_HANDOFF_ISSUER_SPONSOR_VPN_SESSION_LIVE_SMOKE_SIGNAL_MODE=unresolved \
FAKE_HANDOFF_ISSUER_ADMIN_BLOCKCHAIN_HANDLERS_COVERAGE_SIGNAL_MODE=unresolved \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_dry" \
  --run-summary-json "$TMP_DIR/dry_run_summary.json" \
  --handoff-summary-json "$TMP_DIR/dry_handoff_summary.json" \
  --summary-json "$DRY_WRAPPER_SUMMARY" \
  --dry-run 1 \
  --print-summary-json 0 \
  --run-theta 9 \
  --handoff-require-windows-role-runbooks-ok 1 >"$DRY_STDOUT" 2>&1

run_line="$(grep '^run	' "$CAPTURE" | tail -n 1 || true)"
handoff_line="$(grep '^handoff	' "$CAPTURE" | tail -n 1 || true)"
if [[ "$run_line" != *"--dry-run 1"* || "$run_line" != *"--theta 9"* ]]; then
  echo "dry-run run forwarding mismatch"
  echo "$run_line"
  exit 1
fi
if [[ "$handoff_line" != *"--require-run-pipeline-ok 0"* || "$handoff_line" != *"--require-settlement-failsoft-ok 0"* || "$handoff_line" != *"--require-windows-role-runbooks-ok 1"* || "$handoff_line" != *"--require-settlement-bridge-smoke-ok 0"* || "$handoff_line" != *"--require-settlement-state-persistence-ok 0"* || "$handoff_line" != *"--require-settlement-adapter-signed-tx-roundtrip-ok 0"* || "$handoff_line" != *"--require-settlement-shadow-env-ok 0"* || "$handoff_line" != *"--require-settlement-shadow-status-surface-ok 0"* || "$handoff_line" != *"--require-issuer-sponsor-api-live-smoke-ok 0"* || "$handoff_line" != *"--require-issuer-sponsor-vpn-session-live-smoke-ok 0"* || "$handoff_line" != *"--require-issuer-settlement-status-live-smoke-ok 0"* || "$handoff_line" != *"--require-exit-settlement-status-live-smoke-ok 0"* || "$handoff_line" != *"--require-issuer-admin-blockchain-handlers-coverage-ok 0"* ]]; then
  echo "dry-run handoff relax/override mismatch"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" != *"--require-settlement-dual-asset-parity-ok 0"* ]]; then
  echo "dry-run handoff dual-asset relax mismatch"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" == *"--dry-run 1"* ]]; then
  echo "dry-run should not leak to handoff checker"
  echo "$handoff_line"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.dry_run == true
  and .steps.phase5_settlement_layer_run.contract_valid == true
  and .steps.phase5_settlement_layer_handoff_check.contract_valid == true
  and .handoff.settlement_dual_asset_parity_ok == null
  and .handoff.settlement_dual_asset_parity_status == "missing"
  and .handoff.settlement_dual_asset_parity_required == false
  and .handoff.settlement_dual_asset_parity_resolved == false
  and .handoff.sources.settlement_dual_asset_parity_ok == "unresolved"
  and .handoff.settlement_adapter_signed_tx_roundtrip_ok == null
  and .handoff.settlement_adapter_signed_tx_roundtrip_status == "missing"
  and .handoff.settlement_adapter_signed_tx_roundtrip_required == false
  and .handoff.settlement_adapter_signed_tx_roundtrip_resolved == false
  and .handoff.sources.settlement_adapter_signed_tx_roundtrip_ok == "unresolved"
  and .handoff.settlement_shadow_env_ok == null
  and .handoff.settlement_shadow_env_status == "missing"
  and .handoff.settlement_shadow_env_required == false
  and .handoff.settlement_shadow_env_resolved == false
  and .handoff.sources.settlement_shadow_env_ok == "unresolved"
  and .handoff.settlement_shadow_status_surface_ok == null
  and .handoff.settlement_shadow_status_surface_status == "missing"
  and .handoff.settlement_shadow_status_surface_required == false
  and .handoff.settlement_shadow_status_surface_resolved == false
  and .handoff.sources.settlement_shadow_status_surface_ok == "unresolved"
  and .handoff.issuer_sponsor_api_live_smoke_ok == null
  and .handoff.issuer_sponsor_api_live_smoke_status == "missing"
  and .handoff.issuer_sponsor_api_live_smoke_required == false
  and .handoff.issuer_sponsor_api_live_smoke_resolved == false
  and .handoff.sources.issuer_sponsor_api_live_smoke_ok == "unresolved"
  and .handoff.issuer_sponsor_vpn_session_live_smoke_ok == null
  and .handoff.issuer_sponsor_vpn_session_live_smoke_status == "missing"
  and .handoff.issuer_sponsor_vpn_session_live_smoke_required == false
  and .handoff.issuer_sponsor_vpn_session_live_smoke_resolved == false
  and .handoff.sources.issuer_sponsor_vpn_session_live_smoke_ok == "unresolved"
  and .handoff.issuer_settlement_status_live_smoke_ok == null
  and .handoff.issuer_settlement_status_live_smoke_status == "missing"
  and .handoff.issuer_settlement_status_live_smoke_required == false
  and .handoff.issuer_settlement_status_live_smoke_resolved == false
  and .handoff.sources.issuer_settlement_status_live_smoke_ok == "unresolved"
  and .handoff.exit_settlement_status_live_smoke_ok == null
  and .handoff.exit_settlement_status_live_smoke_status == "missing"
  and .handoff.exit_settlement_status_live_smoke_required == false
  and .handoff.exit_settlement_status_live_smoke_resolved == false
  and .handoff.sources.exit_settlement_status_live_smoke_ok == "unresolved"
  and .handoff.issuer_admin_blockchain_handlers_coverage_ok == null
  and .handoff.issuer_admin_blockchain_handlers_coverage_status == "missing"
  and .handoff.issuer_admin_blockchain_handlers_coverage_required == false
  and .handoff.issuer_admin_blockchain_handlers_coverage_resolved == false
  and .handoff.sources.issuer_admin_blockchain_handlers_coverage_ok == "unresolved"
' "$DRY_WRAPPER_SUMMARY" >/dev/null; then
  echo "dry-run wrapper summary mismatch"
  cat "$DRY_WRAPPER_SUMMARY"
  exit 1
fi

echo "[phase5-settlement-layer-handoff-run] env dry-run + legacy requirement compatibility"
: >"$CAPTURE"
ENV_DRY_WRAPPER_SUMMARY="$TMP_DIR/env_dry_wrapper.json"
PHASE5_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_DRY_RUN=1 \
PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_CANONICAL_SUMMARY_JSON="$ENV_DRY_CANONICAL_SUMMARY" \
FAKE_HANDOFF_HELP_MODE=legacy \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_env_dry" \
  --run-summary-json "$TMP_DIR/env_dry_run_summary.json" \
  --handoff-summary-json "$TMP_DIR/env_dry_handoff_summary.json" \
  --summary-json "$ENV_DRY_WRAPPER_SUMMARY" \
  --print-summary-json 0 \
  --handoff-require-settlement-bridge-smoke-ok 1 \
  --handoff-require-windows-role-runbooks-ok 1 >"$ENV_DRY_STDOUT" 2>&1

run_line="$(grep '^run	' "$CAPTURE" | tail -n 1 || true)"
handoff_line="$(grep '^handoff	' "$CAPTURE" | tail -n 1 || true)"
if [[ "$run_line" != *"--dry-run 1"* ]]; then
  echo "env dry-run should forward --dry-run 1 to run stage"
  echo "$run_line"
  exit 1
fi
if [[ "$handoff_line" != *"--require-run-pipeline-ok 0"* || "$handoff_line" != *"--require-windows-server-packaging-ok 0"* || "$handoff_line" != *"--require-windows-role-runbooks-ok 1"* || "$handoff_line" != *"--require-cross-platform-interop-ok 1"* || "$handoff_line" != *"--require-role-combination-validation-ok 0"* ]]; then
  echo "env dry-run legacy handoff requirement forwarding mismatch"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" == *"--require-settlement-failsoft-ok"* || "$handoff_line" == *"--require-settlement-acceptance-ok"* || "$handoff_line" == *"--require-settlement-bridge-smoke-ok"* || "$handoff_line" == *"--require-settlement-state-persistence-ok"* || "$handoff_line" == *"--require-settlement-adapter-signed-tx-roundtrip-ok"* || "$handoff_line" == *"--require-settlement-shadow-env-ok"* || "$handoff_line" == *"--require-settlement-shadow-status-surface-ok"* ]]; then
  echo "canonical handoff requirement flags leaked for legacy checker help mode"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" == *"--require-issuer-sponsor-api-live-smoke-ok"* ]]; then
  echo "sponsor live-smoke requirement should not be auto-injected for legacy checker help mode"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" == *"--require-issuer-sponsor-vpn-session-live-smoke-ok"* ]]; then
  echo "sponsor vpn-session live-smoke requirement should not be auto-injected for legacy checker help mode"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" == *"--require-issuer-settlement-status-live-smoke-ok"* ]]; then
  echo "issuer settlement-status requirement should not be auto-injected for legacy checker help mode"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" == *"--require-exit-settlement-status-live-smoke-ok"* ]]; then
  echo "exit settlement-status requirement should not be auto-injected for legacy checker help mode"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" == *"--require-issuer-admin-blockchain-handlers-coverage-ok"* ]]; then
  echo "issuer-admin handlers requirement should not be auto-injected for legacy checker help mode"
  echo "$handoff_line"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.dry_run == true
  and .steps.phase5_settlement_layer_run.contract_valid == true
  and .steps.phase5_settlement_layer_handoff_check.contract_valid == true
' "$ENV_DRY_WRAPPER_SUMMARY" >/dev/null; then
  echo "env dry-run wrapper summary mismatch"
  cat "$ENV_DRY_WRAPPER_SUMMARY"
  exit 1
fi

echo "[phase5-settlement-layer-handoff-run] legacy passthrough compatibility"
: >"$CAPTURE"
LEGACY_WRAPPER_SUMMARY="$TMP_DIR/legacy_wrapper.json"
PHASE5_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_CANONICAL_SUMMARY_JSON="$FAIL_CANONICAL_SUMMARY" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_legacy" \
  --run-summary-json "$TMP_DIR/legacy_run_summary.json" \
  --handoff-summary-json "$TMP_DIR/legacy_handoff_summary.json" \
  --summary-json "$LEGACY_WRAPPER_SUMMARY" \
  --dry-run 1 \
  --print-summary-json 0 \
  --handoff-require-cross-platform-interop-ok 1 > /dev/null 2>&1

handoff_line="$(grep '^handoff	' "$CAPTURE" | tail -n 1 || true)"
if [[ "$handoff_line" != *"--require-cross-platform-interop-ok 1"* ]]; then
  echo "legacy handoff passthrough mismatch"
  echo "$handoff_line"
  exit 1
fi

echo "[phase5-settlement-layer-handoff-run] run failure still runs handoff check"
: >"$CAPTURE"
FAIL_WRAPPER_SUMMARY="$TMP_DIR/fail_wrapper.json"
set +e
PHASE5_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_CANONICAL_SUMMARY_JSON="$FAIL_CANONICAL_SUMMARY" \
FAKE_RUN_FAIL=1 \
FAKE_RUN_FAIL_RC=27 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_fail" \
  --run-summary-json "$TMP_DIR/fail_run_summary.json" \
  --handoff-summary-json "$TMP_DIR/fail_handoff_summary.json" \
  --summary-json "$FAIL_WRAPPER_SUMMARY" \
  --print-summary-json 0 >"$FAIL_STDOUT" 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 27 ]]; then
  echo "expected wrapper rc=27, got rc=$fail_rc"
  cat "$FAIL_STDOUT"
  exit 1
fi
run_line="$(grep '^run	' "$CAPTURE" | tail -n 1 || true)"
handoff_line="$(grep '^handoff	' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$run_line" || -z "$handoff_line" ]]; then
  echo "expected both stages to run in run-failure path"
  cat "$CAPTURE"
  cat "$FAIL_STDOUT"
  exit 1
fi
if [[ ! -f "$FAIL_CANONICAL_SUMMARY" ]]; then
  echo "missing fail-path canonical summary file: $FAIL_CANONICAL_SUMMARY"
  exit 1
fi
if ! cmp -s "$FAIL_WRAPPER_SUMMARY" "$FAIL_CANONICAL_SUMMARY"; then
  echo "fail-path canonical summary content mismatch"
  cat "$FAIL_WRAPPER_SUMMARY"
  cat "$FAIL_CANONICAL_SUMMARY"
  exit 1
fi
if ! grep -Fq -- "[phase5-settlement-layer-handoff-run] canonical_summary_json=$FAIL_CANONICAL_SUMMARY" "$FAIL_STDOUT"; then
  echo "fail-path log missing canonical summary line"
  cat "$FAIL_STDOUT"
  exit 1
fi
if ! jq -e --arg canonical "$FAIL_CANONICAL_SUMMARY" '
  .status == "fail"
  and .rc == 27
  and .artifacts.canonical_summary_json == $canonical
  and .steps.phase5_settlement_layer_run.status == "fail"
  and .steps.phase5_settlement_layer_run.rc == 27
  and .steps.phase5_settlement_layer_run.command_rc == 27
  and .steps.phase5_settlement_layer_run.contract_valid == true
  and .steps.phase5_settlement_layer_handoff_check.status == "pass"
  and .steps.phase5_settlement_layer_handoff_check.rc == 0
  and .steps.phase5_settlement_layer_handoff_check.command_rc == 0
  and .steps.phase5_settlement_layer_handoff_check.contract_valid == true
' "$FAIL_WRAPPER_SUMMARY" >/dev/null; then
  echo "run-failure summary mismatch"
  cat "$FAIL_WRAPPER_SUMMARY"
  exit 1
fi

echo "[phase5-settlement-layer-handoff-run] run contract fail-close"
: >"$CAPTURE"
RUN_CONTRACT_FAIL_SUMMARY="$TMP_DIR/run_contract_fail.json"
set +e
PHASE5_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_CANONICAL_SUMMARY_JSON="$RUN_CONTRACT_FAIL_CANONICAL_SUMMARY" \
FAKE_RUN_OMIT_SUMMARY=1 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_run_contract_fail" \
  --run-summary-json "$TMP_DIR/run_contract_fail_summary.json" \
  --handoff-summary-json "$TMP_DIR/run_contract_fail_handoff.json" \
  --summary-json "$RUN_CONTRACT_FAIL_SUMMARY" \
  --print-summary-json 0 >"$RUN_CONTRACT_FAIL_STDOUT" 2>&1
run_contract_fail_rc=$?
set -e
if [[ "$run_contract_fail_rc" -ne 3 ]]; then
  echo "expected wrapper rc=3 for run contract failure, got rc=$run_contract_fail_rc"
  cat "$RUN_CONTRACT_FAIL_STDOUT"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 3
  and .steps.phase5_settlement_layer_run.status == "fail"
  and .steps.phase5_settlement_layer_run.contract_valid == false
  and .steps.phase5_settlement_layer_run.rc == 3
  and .steps.phase5_settlement_layer_handoff_check.status == "pass"
' "$RUN_CONTRACT_FAIL_SUMMARY" >/dev/null; then
  echo "run contract-fail summary mismatch"
  cat "$RUN_CONTRACT_FAIL_SUMMARY"
  exit 1
fi

echo "[phase5-settlement-layer-handoff-run] handoff contract fail-close"
: >"$CAPTURE"
HANDOFF_CONTRACT_FAIL_SUMMARY="$TMP_DIR/handoff_contract_fail.json"
set +e
PHASE5_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_CANONICAL_SUMMARY_JSON="$HANDOFF_CONTRACT_FAIL_CANONICAL_SUMMARY" \
FAKE_HANDOFF_OMIT_SUMMARY=1 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_handoff_contract_fail" \
  --run-summary-json "$TMP_DIR/handoff_contract_fail_run.json" \
  --handoff-summary-json "$TMP_DIR/handoff_contract_fail_summary.json" \
  --summary-json "$HANDOFF_CONTRACT_FAIL_SUMMARY" \
  --print-summary-json 0 >"$HANDOFF_CONTRACT_FAIL_STDOUT" 2>&1
handoff_contract_fail_rc=$?
set -e
if [[ "$handoff_contract_fail_rc" -ne 3 ]]; then
  echo "expected wrapper rc=3 for handoff contract failure, got rc=$handoff_contract_fail_rc"
  cat "$HANDOFF_CONTRACT_FAIL_STDOUT"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 3
  and .steps.phase5_settlement_layer_run.status == "pass"
  and .steps.phase5_settlement_layer_run.contract_valid == true
  and .steps.phase5_settlement_layer_handoff_check.status == "fail"
  and .steps.phase5_settlement_layer_handoff_check.contract_valid == false
  and .steps.phase5_settlement_layer_handoff_check.rc == 3
' "$HANDOFF_CONTRACT_FAIL_SUMMARY" >/dev/null; then
  echo "handoff contract-fail summary mismatch"
  cat "$HANDOFF_CONTRACT_FAIL_SUMMARY"
  exit 1
fi

echo "phase5 settlement layer handoff run integration ok"
