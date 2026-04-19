#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod cp touch; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

REPORT_SCRIPT_SOURCE="$ROOT_DIR/scripts/roadmap_progress_report.sh"
if [[ ! -f "$REPORT_SCRIPT_SOURCE" ]]; then
  echo "missing report script: $REPORT_SCRIPT_SOURCE"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

WORKSPACE="$TMP_DIR/workspace"
mkdir -p "$WORKSPACE/scripts" "$WORKSPACE/.easy-node-logs"
cp "$REPORT_SCRIPT_SOURCE" "$WORKSPACE/scripts/roadmap_progress_report.sh"
chmod +x "$WORKSPACE/scripts/roadmap_progress_report.sh"

MANUAL_SUMMARY_JSON="$TMP_DIR/manual_validation_summary.json"
MANUAL_REPORT_MD="$TMP_DIR/manual_validation_report.md"
cat >"$MANUAL_SUMMARY_JSON" <<'EOF_MANUAL'
{
  "version": 1,
  "summary": {
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "single_machine_ready": true
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_MANUAL
printf '# manual validation report\n' >"$MANUAL_REPORT_MD"

PHASE5_HANDOFF_SUMMARY_JSON="$TMP_DIR/phase5_settlement_layer_handoff_check_summary.json"
PHASE5_CHECK_SUMMARY_JSON="$TMP_DIR/phase5_settlement_layer_check_summary.json"
PHASE5_RUN_SUMMARY_JSON="$TMP_DIR/phase5_settlement_layer_run_summary.json"
PHASE5_CHECK_CI_CHAIN_SUMMARY_JSON="$TMP_DIR/phase5_settlement_layer_check_summary_ci_chain.json"
PHASE5_CI_SUMMARY_JSON="$WORKSPACE/.easy-node-logs/ci_phase5_settlement_layer_summary.json"
PHASE5_RUN_CI_CHAIN_SUMMARY_JSON="$TMP_DIR/phase5_settlement_layer_run_summary_ci_chain.json"
PHASE5_NEWER_CHECK_SUMMARY_JSON="$TMP_DIR/phase5_settlement_layer_check_summary_newer.json"
PHASE5_INCOMPLETE_CHECK_SUMMARY_JSON="$TMP_DIR/phase5_settlement_layer_check_summary_incomplete_newer.json"
PHASE5_INVALID_SUMMARY_JSON="$TMP_DIR/phase5_settlement_layer_invalid_summary.json"

cat >"$PHASE5_HANDOFF_SUMMARY_JSON" <<'EOF_PHASE5_HANDOFF'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "signals": {
    "settlement_failsoft_ok": true,
    "settlement_acceptance_ok": true,
    "settlement_bridge_smoke_ok": false,
    "settlement_state_persistence_ok": true,
    "settlement_adapter_roundtrip_status": "pass",
    "settlement_adapter_roundtrip_ok": true,
    "settlement_adapter_signed_tx_roundtrip_status": "pass",
    "settlement_adapter_signed_tx_roundtrip_ok": true,
    "settlement_shadow_env_status": "pass",
    "settlement_shadow_env_ok": true,
    "settlement_shadow_status_surface_status": "pass",
    "settlement_shadow_status_surface_ok": true
  }
}
EOF_PHASE5_HANDOFF

cat >"$PHASE5_CHECK_SUMMARY_JSON" <<'EOF_PHASE5_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "warn",
  "rc": 7,
  "signals": {
    "settlement_failsoft_ok": false,
    "settlement_acceptance_ok": true,
    "settlement_bridge_smoke_ok": true,
    "settlement_state_persistence_ok": false,
    "settlement_adapter_roundtrip_status": "pass",
    "settlement_adapter_roundtrip_ok": true,
    "settlement_adapter_signed_tx_roundtrip_status": "warn",
    "settlement_adapter_signed_tx_roundtrip_ok": false,
    "settlement_shadow_env_status": "pass",
    "settlement_shadow_env_ok": true,
    "settlement_shadow_status_surface_status": "fail",
    "settlement_shadow_status_surface_ok": false
  }
}
EOF_PHASE5_CHECK

cat >"$PHASE5_RUN_SUMMARY_JSON" <<EOF_PHASE5_RUN
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "artifacts": {
    "check_summary_json": "$PHASE5_CHECK_SUMMARY_JSON"
  },
  "steps": {
    "phase5_settlement_layer_check": {
      "artifacts": {
        "summary_json": "$PHASE5_CHECK_SUMMARY_JSON"
      }
    }
  }
}
EOF_PHASE5_RUN

cat >"$PHASE5_CHECK_CI_CHAIN_SUMMARY_JSON" <<'EOF_PHASE5_CHECK_CI_CHAIN'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "warn",
  "rc": 6,
  "signals": {
    "settlement_failsoft_ok": true,
    "settlement_acceptance_ok": true,
    "settlement_bridge_smoke_ok": true,
    "settlement_state_persistence_ok": true
  }
}
EOF_PHASE5_CHECK_CI_CHAIN

cat >"$PHASE5_CI_SUMMARY_JSON" <<'EOF_PHASE5_CI'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "settlement_adapter_roundtrip": {
      "status": "pass"
    },
    "issuer_sponsor_api_live_smoke": {
      "status": "pass"
    },
    "issuer_sponsor_vpn_session_live_smoke": {
      "status": "pass"
    }
  }
}
EOF_PHASE5_CI

cat >"$PHASE5_RUN_CI_CHAIN_SUMMARY_JSON" <<EOF_PHASE5_RUN_CI_CHAIN
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "artifacts": {
    "check_summary_json": "$PHASE5_CHECK_CI_CHAIN_SUMMARY_JSON",
    "ci_summary_json": "$PHASE5_CI_SUMMARY_JSON"
  },
  "steps": {
    "phase5_settlement_layer_check": {
      "artifacts": {
        "summary_json": "$PHASE5_CHECK_CI_CHAIN_SUMMARY_JSON"
      }
    },
    "ci_phase5_settlement_layer": {
      "artifacts": {
        "summary_json": "$PHASE5_CI_SUMMARY_JSON"
      }
    }
  }
}
EOF_PHASE5_RUN_CI_CHAIN

cat >"$PHASE5_NEWER_CHECK_SUMMARY_JSON" <<'EOF_PHASE5_CHECK_NEWER'
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
    "settlement_acceptance_ok": false,
    "settlement_bridge_smoke_ok": false,
    "settlement_state_persistence_ok": true,
    "settlement_adapter_roundtrip_status": "pass",
    "settlement_adapter_roundtrip_ok": true,
    "settlement_adapter_signed_tx_roundtrip_status": "pass",
    "settlement_adapter_signed_tx_roundtrip_ok": true,
    "settlement_shadow_env_status": "warn",
    "settlement_shadow_env_ok": false,
    "settlement_shadow_status_surface_status": "pass",
    "settlement_shadow_status_surface_ok": true
  }
}
EOF_PHASE5_CHECK_NEWER

cat >"$PHASE5_INCOMPLETE_CHECK_SUMMARY_JSON" <<'EOF_PHASE5_CHECK_INCOMPLETE'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "warn",
  "rc": 9,
  "signals": {
    "settlement_failsoft_ok": null,
    "settlement_acceptance_ok": null,
    "settlement_bridge_smoke_ok": null,
    "settlement_state_persistence_ok": null,
    "settlement_adapter_roundtrip_status": null,
    "settlement_adapter_roundtrip_ok": null,
    "settlement_adapter_signed_tx_roundtrip_status": null,
    "settlement_adapter_signed_tx_roundtrip_ok": null,
    "settlement_shadow_env_status": null,
    "settlement_shadow_env_ok": null,
    "settlement_shadow_status_surface_status": null,
    "settlement_shadow_status_surface_ok": null
  },
  "stages": {
    "settlement_failsoft": {
      "status": "unknown"
    },
    "settlement_acceptance": {
      "status": "unknown"
    },
    "settlement_bridge_smoke": {
      "status": "unknown"
    },
    "settlement_state_persistence": {
      "status": "unknown"
    },
    "settlement_adapter_roundtrip": {
      "status": "unknown"
    },
    "settlement_adapter_signed_tx_roundtrip": {
      "status": "unknown"
    },
    "settlement_shadow_env": {
      "status": "unknown"
    },
    "settlement_shadow_status_surface": {
      "status": "unknown"
    }
  }
}
EOF_PHASE5_CHECK_INCOMPLETE

cat >"$PHASE5_INVALID_SUMMARY_JSON" <<'EOF_PHASE5_INVALID'
{"version":1
EOF_PHASE5_INVALID

run_report() {
  local summary_json="$1"
  local report_md="$2"
  shift 2
  bash "$WORKSPACE/scripts/roadmap_progress_report.sh" \
    --refresh-manual-validation 0 \
    --refresh-single-machine-readiness 0 \
    --manual-validation-summary-json "$MANUAL_SUMMARY_JSON" \
    --manual-validation-report-md "$MANUAL_REPORT_MD" \
    --summary-json "$summary_json" \
    --report-md "$report_md" \
    --print-report 0 \
    --print-summary-json 0 \
    "$@"
}

assert_phase5_block() {
  local summary_json="$1"
  local input_json="$2"
  local source_json="$3"
  local source_kind="$4"
  local status="$5"
  local rc="$6"
  local settlement_failsoft_ok="$7"
  local settlement_acceptance_ok="$8"
  local settlement_bridge_smoke_ok="$9"
  local settlement_state_persistence_ok="${10}"
  local settlement_adapter_roundtrip_status="${11}"
  local settlement_adapter_roundtrip_ok="${12}"
  local settlement_adapter_signed_tx_roundtrip_status="${13}"
  local settlement_adapter_signed_tx_roundtrip_ok="${14}"
  local settlement_shadow_env_status="${15}"
  local settlement_shadow_env_ok="${16}"
  local settlement_shadow_status_surface_status="${17}"
  local settlement_shadow_status_surface_ok="${18}"
  jq -e \
    --arg input_json "$input_json" \
    --arg source_json "$source_json" \
    --arg source_kind "$source_kind" \
    --arg status "$status" \
    --argjson rc "$rc" \
    --argjson settlement_failsoft_ok "$settlement_failsoft_ok" \
    --argjson settlement_acceptance_ok "$settlement_acceptance_ok" \
    --argjson settlement_bridge_smoke_ok "$settlement_bridge_smoke_ok" \
    --argjson settlement_state_persistence_ok "$settlement_state_persistence_ok" \
    --arg settlement_adapter_roundtrip_status "$settlement_adapter_roundtrip_status" \
    --argjson settlement_adapter_roundtrip_ok "$settlement_adapter_roundtrip_ok" \
    --arg settlement_adapter_signed_tx_roundtrip_status "$settlement_adapter_signed_tx_roundtrip_status" \
    --argjson settlement_adapter_signed_tx_roundtrip_ok "$settlement_adapter_signed_tx_roundtrip_ok" \
    --arg settlement_shadow_env_status "$settlement_shadow_env_status" \
    --argjson settlement_shadow_env_ok "$settlement_shadow_env_ok" \
    --arg settlement_shadow_status_surface_status "$settlement_shadow_status_surface_status" \
    --argjson settlement_shadow_status_surface_ok "$settlement_shadow_status_surface_ok" \
    '
      .vpn_track.phase5_settlement_layer_handoff.available == true
      and .vpn_track.phase5_settlement_layer_handoff.input_summary_json == $input_json
      and .vpn_track.phase5_settlement_layer_handoff.source_summary_json == $source_json
      and .vpn_track.phase5_settlement_layer_handoff.source_summary_kind == $source_kind
      and .vpn_track.phase5_settlement_layer_handoff.status == $status
      and .vpn_track.phase5_settlement_layer_handoff.rc == $rc
      and .vpn_track.phase5_settlement_layer_handoff.settlement_failsoft_ok == $settlement_failsoft_ok
      and .vpn_track.phase5_settlement_layer_handoff.settlement_acceptance_ok == $settlement_acceptance_ok
      and .vpn_track.phase5_settlement_layer_handoff.settlement_bridge_smoke_ok == $settlement_bridge_smoke_ok
      and .vpn_track.phase5_settlement_layer_handoff.settlement_state_persistence_ok == $settlement_state_persistence_ok
      and (
        if $settlement_adapter_roundtrip_status == "null" then
          .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_roundtrip_status == null
        else
          .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_roundtrip_status == $settlement_adapter_roundtrip_status
        end
      )
      and .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_roundtrip_ok == $settlement_adapter_roundtrip_ok
      and (
        if $settlement_adapter_signed_tx_roundtrip_status == "null" then
          .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_status == null
        else
          .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_status == $settlement_adapter_signed_tx_roundtrip_status
        end
      )
      and .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_ok == $settlement_adapter_signed_tx_roundtrip_ok
      and (
        if $settlement_shadow_env_status == "null" then
          .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_status == null
        else
          .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_status == $settlement_shadow_env_status
        end
      )
      and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_ok == $settlement_shadow_env_ok
      and (
        if $settlement_shadow_status_surface_status == "null" then
          .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_status == null
        else
          .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_status == $settlement_shadow_status_surface_status
        end
      )
      and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_ok == $settlement_shadow_status_surface_ok
      and .artifacts.phase5_settlement_layer_summary_json == $source_json
    ' "$summary_json" >/dev/null
}

assert_phase5_missing_block() {
  local summary_json="$1"
  jq -e '
    .vpn_track.phase5_settlement_layer_handoff.available == false
    and .vpn_track.phase5_settlement_layer_handoff.input_summary_json == null
    and .vpn_track.phase5_settlement_layer_handoff.source_summary_json == null
    and .vpn_track.phase5_settlement_layer_handoff.source_summary_kind == null
    and .vpn_track.phase5_settlement_layer_handoff.status == "missing"
    and .vpn_track.phase5_settlement_layer_handoff.rc == null
    and .vpn_track.phase5_settlement_layer_handoff.settlement_failsoft_ok == null
    and .vpn_track.phase5_settlement_layer_handoff.settlement_acceptance_ok == null
    and .vpn_track.phase5_settlement_layer_handoff.settlement_bridge_smoke_ok == null
    and .vpn_track.phase5_settlement_layer_handoff.settlement_state_persistence_ok == null
    and .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_roundtrip_status == null
    and .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_roundtrip_ok == null
    and .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_status == null
    and .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_ok == null
    and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_status == null
    and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_ok == null
    and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_status == null
    and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_ok == null
    and .artifacts.phase5_settlement_layer_summary_json == null
  ' "$summary_json" >/dev/null
}

assert_phase5_invalid_block() {
  local summary_json="$1"
  local input_json="$2"
  jq -e \
    --arg input_json "$input_json" \
    '
      .vpn_track.phase5_settlement_layer_handoff.available == false
      and .vpn_track.phase5_settlement_layer_handoff.input_summary_json == $input_json
      and .vpn_track.phase5_settlement_layer_handoff.source_summary_json == null
      and .vpn_track.phase5_settlement_layer_handoff.source_summary_kind == null
      and .vpn_track.phase5_settlement_layer_handoff.status == "invalid"
      and .vpn_track.phase5_settlement_layer_handoff.rc == null
      and .vpn_track.phase5_settlement_layer_handoff.settlement_failsoft_ok == null
      and .vpn_track.phase5_settlement_layer_handoff.settlement_acceptance_ok == null
      and .vpn_track.phase5_settlement_layer_handoff.settlement_bridge_smoke_ok == null
      and .vpn_track.phase5_settlement_layer_handoff.settlement_state_persistence_ok == null
      and .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_roundtrip_status == null
      and .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_roundtrip_ok == null
      and .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_status == null
      and .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_ok == null
      and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_status == null
      and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_ok == null
      and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_status == null
      and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_ok == null
      and .artifacts.phase5_settlement_layer_summary_json == null
    ' "$summary_json" >/dev/null
}

assert_phase5_sponsor_live_smoke_block() {
  local summary_json="$1"
  local issuer_sponsor_api_live_smoke_status="$2"
  local issuer_sponsor_api_live_smoke_ok="$3"
  local issuer_sponsor_vpn_session_live_smoke_status="$4"
  local issuer_sponsor_vpn_session_live_smoke_ok="$5"
  jq -e \
    --arg issuer_sponsor_api_live_smoke_status "$issuer_sponsor_api_live_smoke_status" \
    --argjson issuer_sponsor_api_live_smoke_ok "$issuer_sponsor_api_live_smoke_ok" \
    --arg issuer_sponsor_vpn_session_live_smoke_status "$issuer_sponsor_vpn_session_live_smoke_status" \
    --argjson issuer_sponsor_vpn_session_live_smoke_ok "$issuer_sponsor_vpn_session_live_smoke_ok" \
    '
      (
        if $issuer_sponsor_api_live_smoke_status == "null" then
          .vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_status == null
        else
          .vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_status == $issuer_sponsor_api_live_smoke_status
        end
      )
      and .vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_ok == $issuer_sponsor_api_live_smoke_ok
      and (
        if $issuer_sponsor_vpn_session_live_smoke_status == "null" then
          .vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_vpn_session_live_smoke_status == null
        else
          .vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_vpn_session_live_smoke_status == $issuer_sponsor_vpn_session_live_smoke_status
        end
      )
      and .vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_vpn_session_live_smoke_ok == $issuer_sponsor_vpn_session_live_smoke_ok
    ' "$summary_json" >/dev/null
}

echo "[roadmap-progress-phase5-handoff] direct handoff summary path"
DIRECT_SUMMARY_JSON="$TMP_DIR/roadmap_progress_phase5_direct.json"
DIRECT_REPORT_MD="$TMP_DIR/roadmap_progress_phase5_direct.md"
run_report "$DIRECT_SUMMARY_JSON" "$DIRECT_REPORT_MD" \
  --phase5-settlement-layer-summary-json "$PHASE5_HANDOFF_SUMMARY_JSON"
assert_phase5_block "$DIRECT_SUMMARY_JSON" "$PHASE5_HANDOFF_SUMMARY_JSON" "$PHASE5_HANDOFF_SUMMARY_JSON" "handoff" "pass" "0" "true" "true" "false" "true" "pass" "true" "pass" "true" "pass" "true" "pass" "true"

echo "[roadmap-progress-phase5-handoff] nested run->check summary path"
NESTED_SUMMARY_JSON="$TMP_DIR/roadmap_progress_phase5_nested.json"
NESTED_REPORT_MD="$TMP_DIR/roadmap_progress_phase5_nested.md"
run_report "$NESTED_SUMMARY_JSON" "$NESTED_REPORT_MD" \
  --phase5-settlement-layer-summary-json "$PHASE5_RUN_SUMMARY_JSON"
assert_phase5_block "$NESTED_SUMMARY_JSON" "$PHASE5_RUN_SUMMARY_JSON" "$PHASE5_CHECK_SUMMARY_JSON" "check" "warn" "7" "false" "true" "true" "false" "pass" "true" "warn" "false" "pass" "true" "fail" "false"

echo "[roadmap-progress-phase5-handoff] nested run->ci summary path surfaces roundtrip when missing in check summary"
NESTED_CI_SUMMARY_JSON="$TMP_DIR/roadmap_progress_phase5_nested_ci.json"
NESTED_CI_REPORT_MD="$TMP_DIR/roadmap_progress_phase5_nested_ci.md"
run_report "$NESTED_CI_SUMMARY_JSON" "$NESTED_CI_REPORT_MD" \
  --phase5-settlement-layer-summary-json "$PHASE5_RUN_CI_CHAIN_SUMMARY_JSON"
assert_phase5_block "$NESTED_CI_SUMMARY_JSON" "$PHASE5_RUN_CI_CHAIN_SUMMARY_JSON" "$PHASE5_CHECK_CI_CHAIN_SUMMARY_JSON" "check" "warn" "6" "true" "true" "true" "true" "pass" "true" "null" "null" "null" "null" "null" "null"
assert_phase5_sponsor_live_smoke_block "$NESTED_CI_SUMMARY_JSON" "pass" "true" "pass" "true"

echo "[roadmap-progress-phase5-handoff] .easy-node-logs fallback path"
PHASE5_OLD_DIR="$WORKSPACE/.easy-node-logs/zzz_old_valid"
PHASE5_NEW_DIR="$WORKSPACE/.easy-node-logs/aaa_new_valid"
PHASE5_INVALID_DIR="$WORKSPACE/.easy-node-logs/yyy_invalid_newest"
mkdir -p "$PHASE5_OLD_DIR" "$PHASE5_NEW_DIR" "$PHASE5_INVALID_DIR"
PHASE5_FALLBACK_OLD_JSON="$PHASE5_OLD_DIR/phase5_settlement_layer_check_summary.json"
FALLBACK_SOURCE_JSON="$PHASE5_NEW_DIR/phase5_settlement_layer_check_summary.json"
PHASE5_INVALID_FALLBACK_JSON="$PHASE5_INVALID_DIR/phase5_settlement_layer_handoff_check_summary.json"
cp "$PHASE5_CHECK_SUMMARY_JSON" "$PHASE5_FALLBACK_OLD_JSON"
cp "$PHASE5_NEWER_CHECK_SUMMARY_JSON" "$FALLBACK_SOURCE_JSON"
cp "$PHASE5_INVALID_SUMMARY_JSON" "$PHASE5_INVALID_FALLBACK_JSON"
touch -t 202601010101 "$PHASE5_FALLBACK_OLD_JSON"
touch -t 202601020202 "$FALLBACK_SOURCE_JSON"
touch -t 202601030303 "$PHASE5_INVALID_FALLBACK_JSON"
FALLBACK_SUMMARY_JSON="$TMP_DIR/roadmap_progress_phase5_fallback.json"
FALLBACK_REPORT_MD="$TMP_DIR/roadmap_progress_phase5_fallback.md"
run_report "$FALLBACK_SUMMARY_JSON" "$FALLBACK_REPORT_MD"
assert_phase5_block "$FALLBACK_SUMMARY_JSON" "$FALLBACK_SOURCE_JSON" "$FALLBACK_SOURCE_JSON" "check" "pass" "0" "true" "false" "false" "true" "pass" "true" "pass" "true" "warn" "false" "pass" "true"

echo "[roadmap-progress-phase5-handoff] .easy-node-logs fallback prefers complete summary over newer incomplete summary"
rm -f "$PHASE5_FALLBACK_OLD_JSON" "$FALLBACK_SOURCE_JSON" "$PHASE5_INVALID_FALLBACK_JSON"
PHASE5_COMPLETE_FALLBACK_DIR="$WORKSPACE/.easy-node-logs/bbb_complete_older"
PHASE5_INCOMPLETE_FALLBACK_DIR="$WORKSPACE/.easy-node-logs/ccc_incomplete_newer"
mkdir -p "$PHASE5_COMPLETE_FALLBACK_DIR" "$PHASE5_INCOMPLETE_FALLBACK_DIR"
PHASE5_COMPLETE_FALLBACK_JSON="$PHASE5_COMPLETE_FALLBACK_DIR/phase5_settlement_layer_handoff_check_summary.json"
PHASE5_INCOMPLETE_FALLBACK_JSON="$PHASE5_INCOMPLETE_FALLBACK_DIR/phase5_settlement_layer_check_summary.json"
cp "$PHASE5_HANDOFF_SUMMARY_JSON" "$PHASE5_COMPLETE_FALLBACK_JSON"
cp "$PHASE5_INCOMPLETE_CHECK_SUMMARY_JSON" "$PHASE5_INCOMPLETE_FALLBACK_JSON"
PHASE5_COMPLETE_FALLBACK_NORMALIZED="$TMP_DIR/phase5_complete_fallback_normalized.json"
jq '
  .status = "pass"
  | .rc = 0
  | .signals.settlement_bridge_smoke_ok = true
' "$PHASE5_COMPLETE_FALLBACK_JSON" >"$PHASE5_COMPLETE_FALLBACK_NORMALIZED"
mv -f "$PHASE5_COMPLETE_FALLBACK_NORMALIZED" "$PHASE5_COMPLETE_FALLBACK_JSON"
touch -t 202601040101 "$PHASE5_COMPLETE_FALLBACK_JSON"
touch -t 202601040202 "$PHASE5_INCOMPLETE_FALLBACK_JSON"
FALLBACK_COMPLETE_PREFERRED_SUMMARY_JSON="$TMP_DIR/roadmap_progress_phase5_fallback_complete_preferred.json"
FALLBACK_COMPLETE_PREFERRED_REPORT_MD="$TMP_DIR/roadmap_progress_phase5_fallback_complete_preferred.md"
run_report "$FALLBACK_COMPLETE_PREFERRED_SUMMARY_JSON" "$FALLBACK_COMPLETE_PREFERRED_REPORT_MD"
assert_phase5_block "$FALLBACK_COMPLETE_PREFERRED_SUMMARY_JSON" "$PHASE5_COMPLETE_FALLBACK_JSON" "$PHASE5_COMPLETE_FALLBACK_JSON" "handoff" "pass" "0" "true" "true" "true" "true" "pass" "true" "pass" "true" "pass" "true" "pass" "true"

echo "[roadmap-progress-phase5-handoff] missing-input fail-soft path"
rm -f "$PHASE5_COMPLETE_FALLBACK_JSON" "$PHASE5_INCOMPLETE_FALLBACK_JSON"
MISSING_SUMMARY_JSON="$TMP_DIR/roadmap_progress_phase5_missing.json"
MISSING_REPORT_MD="$TMP_DIR/roadmap_progress_phase5_missing.md"
run_report "$MISSING_SUMMARY_JSON" "$MISSING_REPORT_MD"
assert_phase5_missing_block "$MISSING_SUMMARY_JSON"

echo "[roadmap-progress-phase5-handoff] unusable explicit summary path"
INVALID_SUMMARY_JSON="$TMP_DIR/roadmap_progress_phase5_invalid.json"
INVALID_REPORT_MD="$TMP_DIR/roadmap_progress_phase5_invalid.md"
run_report "$INVALID_SUMMARY_JSON" "$INVALID_REPORT_MD" \
  --phase5-settlement-layer-summary-json "$PHASE5_INVALID_SUMMARY_JSON"
assert_phase5_invalid_block "$INVALID_SUMMARY_JSON" "$PHASE5_INVALID_SUMMARY_JSON"

echo "roadmap progress phase5 handoff integration ok"
