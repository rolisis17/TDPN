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

PHASE3_HANDOFF_SUMMARY_JSON="$TMP_DIR/phase3_windows_client_beta_handoff_check_summary.json"
PHASE3_HANDOFF_DERIVED_SUMMARY_JSON="$TMP_DIR/phase3_windows_client_beta_handoff_check_summary_derived.json"
PHASE3_CHECK_SUMMARY_JSON="$TMP_DIR/phase3_windows_client_beta_check_summary.json"
PHASE3_RUN_SUMMARY_JSON="$TMP_DIR/phase3_windows_client_beta_run_summary.json"
PHASE3_NEWER_CHECK_SUMMARY_JSON="$TMP_DIR/phase3_windows_client_beta_check_summary_newer.json"
PHASE3_DRY_RUN_CHECK_SUMMARY_JSON="$TMP_DIR/phase3_windows_client_beta_check_summary_dry_run_newer.json"
PHASE3_INVALID_SUMMARY_JSON="$TMP_DIR/phase3_windows_client_beta_invalid_summary.json"

cat >"$PHASE3_HANDOFF_SUMMARY_JSON" <<'EOF_PHASE3_HANDOFF'
{
  "version": 1,
  "schema": {
    "id": "phase3_windows_client_beta_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "signals": {
    "windows_parity_ok": true,
    "desktop_contract_ok": true,
    "installer_update_ok": false,
    "telemetry_stability_ok": true
  }
}
EOF_PHASE3_HANDOFF

cat >"$PHASE3_HANDOFF_DERIVED_SUMMARY_JSON" <<'EOF_PHASE3_HANDOFF_DERIVED'
{
  "version": 1,
  "schema": {
    "id": "phase3_windows_client_beta_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "handoff": {
    "desktop_scaffold_ok": true,
    "local_control_api_ok": true,
    "local_api_config_defaults_ok": true,
    "easy_node_config_v1_ok": false,
    "launcher_wiring_ok": true,
    "launcher_runtime_ok": true
  }
}
EOF_PHASE3_HANDOFF_DERIVED

cat >"$PHASE3_CHECK_SUMMARY_JSON" <<'EOF_PHASE3_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase3_windows_client_beta_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "warn",
  "rc": 7,
  "signals": {
    "windows_parity_ok": false,
    "desktop_contract_ok": true,
    "installer_update_ok": true,
    "telemetry_stability_ok": false
  }
}
EOF_PHASE3_CHECK

cat >"$PHASE3_RUN_SUMMARY_JSON" <<EOF_PHASE3_RUN
{
  "version": 1,
  "schema": {
    "id": "phase3_windows_client_beta_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "artifacts": {
    "check_summary_json": "$PHASE3_CHECK_SUMMARY_JSON"
  },
  "steps": {
    "phase3_windows_client_beta_check": {
      "artifacts": {
        "summary_json": "$PHASE3_CHECK_SUMMARY_JSON"
      }
    }
  }
}
EOF_PHASE3_RUN

cat >"$PHASE3_NEWER_CHECK_SUMMARY_JSON" <<'EOF_PHASE3_CHECK_NEWER'
{
  "version": 1,
  "schema": {
    "id": "phase3_windows_client_beta_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "signals": {
    "windows_parity_ok": true,
    "desktop_contract_ok": false,
    "installer_update_ok": false,
    "telemetry_stability_ok": true
  }
}
EOF_PHASE3_CHECK_NEWER

cat >"$PHASE3_DRY_RUN_CHECK_SUMMARY_JSON" <<'EOF_PHASE3_CHECK_DRY_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase3_windows_client_beta_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "inputs": {
    "dry_run": true
  },
  "signals": {
    "windows_parity_ok": true,
    "desktop_contract_ok": false,
    "installer_update_ok": false,
    "telemetry_stability_ok": true
  }
}
EOF_PHASE3_CHECK_DRY_RUN

cat >"$PHASE3_INVALID_SUMMARY_JSON" <<'EOF_PHASE3_INVALID'
{"version":1
EOF_PHASE3_INVALID

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

assert_phase3_block() {
  local summary_json="$1"
  local input_json="$2"
  local source_json="$3"
  local source_kind="$4"
  local status="$5"
  local rc="$6"
  local windows_parity_ok="$7"
  local desktop_contract_ok="$8"
  local installer_update_ok="$9"
  local telemetry_stability_ok="${10}"
  jq -e \
    --arg input_json "$input_json" \
    --arg source_json "$source_json" \
    --arg source_kind "$source_kind" \
    --arg status "$status" \
    --argjson rc "$rc" \
    --argjson windows_parity_ok "$windows_parity_ok" \
    --argjson desktop_contract_ok "$desktop_contract_ok" \
    --argjson installer_update_ok "$installer_update_ok" \
    --argjson telemetry_stability_ok "$telemetry_stability_ok" \
    '
      .vpn_track.phase3_windows_client_beta_handoff.available == true
      and .vpn_track.phase3_windows_client_beta_handoff.input_summary_json == $input_json
      and .vpn_track.phase3_windows_client_beta_handoff.source_summary_json == $source_json
      and .vpn_track.phase3_windows_client_beta_handoff.source_summary_kind == $source_kind
      and .vpn_track.phase3_windows_client_beta_handoff.status == $status
      and .vpn_track.phase3_windows_client_beta_handoff.rc == $rc
      and .vpn_track.phase3_windows_client_beta_handoff.windows_parity_ok == $windows_parity_ok
      and .vpn_track.phase3_windows_client_beta_handoff.desktop_contract_ok == $desktop_contract_ok
      and .vpn_track.phase3_windows_client_beta_handoff.installer_update_ok == $installer_update_ok
      and .vpn_track.phase3_windows_client_beta_handoff.telemetry_stability_ok == $telemetry_stability_ok
      and .artifacts.phase3_windows_client_beta_summary_json == $source_json
    ' "$summary_json" >/dev/null
}

assert_phase3_missing_block() {
  local summary_json="$1"
  jq -e '
    .vpn_track.phase3_windows_client_beta_handoff.available == false
    and .vpn_track.phase3_windows_client_beta_handoff.input_summary_json == null
    and .vpn_track.phase3_windows_client_beta_handoff.source_summary_json == null
    and .vpn_track.phase3_windows_client_beta_handoff.source_summary_kind == null
    and .vpn_track.phase3_windows_client_beta_handoff.status == "missing"
    and .vpn_track.phase3_windows_client_beta_handoff.rc == null
    and .vpn_track.phase3_windows_client_beta_handoff.windows_parity_ok == null
    and .vpn_track.phase3_windows_client_beta_handoff.desktop_contract_ok == null
    and .vpn_track.phase3_windows_client_beta_handoff.installer_update_ok == null
    and .vpn_track.phase3_windows_client_beta_handoff.telemetry_stability_ok == null
    and .artifacts.phase3_windows_client_beta_summary_json == null
  ' "$summary_json" >/dev/null
}

assert_phase3_invalid_block() {
  local summary_json="$1"
  local input_json="$2"
  jq -e \
    --arg input_json "$input_json" \
    '
      .vpn_track.phase3_windows_client_beta_handoff.available == false
      and .vpn_track.phase3_windows_client_beta_handoff.input_summary_json == $input_json
      and .vpn_track.phase3_windows_client_beta_handoff.source_summary_json == null
      and .vpn_track.phase3_windows_client_beta_handoff.source_summary_kind == null
      and .vpn_track.phase3_windows_client_beta_handoff.status == "invalid"
      and .vpn_track.phase3_windows_client_beta_handoff.rc == null
      and .vpn_track.phase3_windows_client_beta_handoff.windows_parity_ok == null
      and .vpn_track.phase3_windows_client_beta_handoff.desktop_contract_ok == null
      and .vpn_track.phase3_windows_client_beta_handoff.installer_update_ok == null
      and .vpn_track.phase3_windows_client_beta_handoff.telemetry_stability_ok == null
      and .artifacts.phase3_windows_client_beta_summary_json == null
    ' "$summary_json" >/dev/null
}

echo "[roadmap-progress-phase3-handoff] direct handoff summary path"
DIRECT_SUMMARY_JSON="$TMP_DIR/roadmap_progress_phase3_direct.json"
DIRECT_REPORT_MD="$TMP_DIR/roadmap_progress_phase3_direct.md"
run_report "$DIRECT_SUMMARY_JSON" "$DIRECT_REPORT_MD" \
  --phase3-windows-client-beta-summary-json "$PHASE3_HANDOFF_SUMMARY_JSON"
assert_phase3_block "$DIRECT_SUMMARY_JSON" "$PHASE3_HANDOFF_SUMMARY_JSON" "$PHASE3_HANDOFF_SUMMARY_JSON" "handoff" "pass" "0" "true" "true" "false" "true"

echo "[roadmap-progress-phase3-handoff] handoff summary derives aliases from readiness booleans"
DERIVED_SUMMARY_JSON="$TMP_DIR/roadmap_progress_phase3_derived_aliases.json"
DERIVED_REPORT_MD="$TMP_DIR/roadmap_progress_phase3_derived_aliases.md"
run_report "$DERIVED_SUMMARY_JSON" "$DERIVED_REPORT_MD" \
  --phase3-windows-client-beta-summary-json "$PHASE3_HANDOFF_DERIVED_SUMMARY_JSON"
assert_phase3_block "$DERIVED_SUMMARY_JSON" "$PHASE3_HANDOFF_DERIVED_SUMMARY_JSON" "$PHASE3_HANDOFF_DERIVED_SUMMARY_JSON" "handoff" "pass" "0" "true" "true" "false" "true"

echo "[roadmap-progress-phase3-handoff] nested run->check summary path"
NESTED_SUMMARY_JSON="$TMP_DIR/roadmap_progress_phase3_nested.json"
NESTED_REPORT_MD="$TMP_DIR/roadmap_progress_phase3_nested.md"
run_report "$NESTED_SUMMARY_JSON" "$NESTED_REPORT_MD" \
  --phase3-windows-client-beta-summary-json "$PHASE3_RUN_SUMMARY_JSON"
assert_phase3_block "$NESTED_SUMMARY_JSON" "$PHASE3_RUN_SUMMARY_JSON" "$PHASE3_CHECK_SUMMARY_JSON" "check" "warn" "7" "false" "true" "true" "false"

echo "[roadmap-progress-phase3-handoff] .easy-node-logs fallback path"
PHASE3_OLD_DIR="$WORKSPACE/.easy-node-logs/zzz_old_valid"
PHASE3_NEW_DIR="$WORKSPACE/.easy-node-logs/aaa_new_valid"
PHASE3_INVALID_DIR="$WORKSPACE/.easy-node-logs/yyy_invalid_newest"
mkdir -p "$PHASE3_OLD_DIR" "$PHASE3_NEW_DIR" "$PHASE3_INVALID_DIR"
PHASE3_FALLBACK_OLD_JSON="$PHASE3_OLD_DIR/phase3_windows_client_beta_check_summary.json"
FALLBACK_SOURCE_JSON="$PHASE3_NEW_DIR/phase3_windows_client_beta_check_summary.json"
PHASE3_INVALID_FALLBACK_JSON="$PHASE3_INVALID_DIR/phase3_windows_client_beta_handoff_run_summary.json"
cp "$PHASE3_CHECK_SUMMARY_JSON" "$PHASE3_FALLBACK_OLD_JSON"
cp "$PHASE3_NEWER_CHECK_SUMMARY_JSON" "$FALLBACK_SOURCE_JSON"
cp "$PHASE3_INVALID_SUMMARY_JSON" "$PHASE3_INVALID_FALLBACK_JSON"
touch -t 202601010101 "$PHASE3_FALLBACK_OLD_JSON"
touch -t 202601020202 "$FALLBACK_SOURCE_JSON"
touch -t 202601030303 "$PHASE3_INVALID_FALLBACK_JSON"
FALLBACK_SUMMARY_JSON="$TMP_DIR/roadmap_progress_phase3_fallback.json"
FALLBACK_REPORT_MD="$TMP_DIR/roadmap_progress_phase3_fallback.md"
run_report "$FALLBACK_SUMMARY_JSON" "$FALLBACK_REPORT_MD"
assert_phase3_block "$FALLBACK_SUMMARY_JSON" "$FALLBACK_SOURCE_JSON" "$FALLBACK_SOURCE_JSON" "check" "pass" "0" "true" "false" "false" "true"

echo "[roadmap-progress-phase3-handoff] .easy-node-logs fallback prefers complete older source over newer incomplete candidate"
PHASE3_COMPLETE_OLD_DIR="$WORKSPACE/.easy-node-logs/zzz_complete_old"
PHASE3_INCOMPLETE_NEW_DIR="$WORKSPACE/.easy-node-logs/aaa_incomplete_newer"
mkdir -p "$PHASE3_COMPLETE_OLD_DIR" "$PHASE3_INCOMPLETE_NEW_DIR"
PHASE3_COMPLETE_OLD_JSON="$PHASE3_COMPLETE_OLD_DIR/phase3_windows_client_beta_check_summary.json"
PHASE3_INCOMPLETE_NEW_JSON="$PHASE3_INCOMPLETE_NEW_DIR/phase3_windows_client_beta_run_summary.json"
cp "$PHASE3_CHECK_SUMMARY_JSON" "$PHASE3_COMPLETE_OLD_JSON"
cat >"$PHASE3_INCOMPLETE_NEW_JSON" <<EOF_PHASE3_INCOMPLETE_NEW
{
  "version": 1,
  "schema": {
    "id": "phase3_windows_client_beta_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "signals": {
    "windows_parity_ok": null,
    "desktop_contract_ok": null,
    "installer_update_ok": null,
    "telemetry_stability_ok": null
  },
  "artifacts": {
    "check_summary_json": "$PHASE3_COMPLETE_OLD_JSON"
  }
}
EOF_PHASE3_INCOMPLETE_NEW
touch -t 202601040404 "$PHASE3_COMPLETE_OLD_JSON"
touch -t 202601050505 "$PHASE3_INCOMPLETE_NEW_JSON"
COMPLETENESS_SUMMARY_JSON="$TMP_DIR/roadmap_progress_phase3_fallback_complete_preferred.json"
COMPLETENESS_REPORT_MD="$TMP_DIR/roadmap_progress_phase3_fallback_complete_preferred.md"
run_report "$COMPLETENESS_SUMMARY_JSON" "$COMPLETENESS_REPORT_MD"
assert_phase3_block "$COMPLETENESS_SUMMARY_JSON" "$PHASE3_COMPLETE_OLD_JSON" "$PHASE3_COMPLETE_OLD_JSON" "check" "warn" "7" "false" "true" "true" "false"

echo "[roadmap-progress-phase3-handoff] .easy-node-logs fallback prefers non-dry source over newer dry-run candidate"
PHASE3_NON_DRY_FALLBACK_DIR="$WORKSPACE/.easy-node-logs/ddd_non_dry_older"
PHASE3_DRY_RUN_FALLBACK_DIR="$WORKSPACE/.easy-node-logs/eee_dry_run_newer"
mkdir -p "$PHASE3_NON_DRY_FALLBACK_DIR" "$PHASE3_DRY_RUN_FALLBACK_DIR"
PHASE3_NON_DRY_FALLBACK_JSON="$PHASE3_NON_DRY_FALLBACK_DIR/phase3_windows_client_beta_check_summary.json"
PHASE3_DRY_RUN_FALLBACK_JSON="$PHASE3_DRY_RUN_FALLBACK_DIR/phase3_windows_client_beta_check_summary.json"
cp "$PHASE3_CHECK_SUMMARY_JSON" "$PHASE3_NON_DRY_FALLBACK_JSON"
cp "$PHASE3_DRY_RUN_CHECK_SUMMARY_JSON" "$PHASE3_DRY_RUN_FALLBACK_JSON"
touch -t 202601060606 "$PHASE3_NON_DRY_FALLBACK_JSON"
touch -t 202601060707 "$PHASE3_DRY_RUN_FALLBACK_JSON"
DRY_RUN_PREFERENCE_SUMMARY_JSON="$TMP_DIR/roadmap_progress_phase3_fallback_non_dry_preferred.json"
DRY_RUN_PREFERENCE_REPORT_MD="$TMP_DIR/roadmap_progress_phase3_fallback_non_dry_preferred.md"
run_report "$DRY_RUN_PREFERENCE_SUMMARY_JSON" "$DRY_RUN_PREFERENCE_REPORT_MD"
assert_phase3_block "$DRY_RUN_PREFERENCE_SUMMARY_JSON" "$PHASE3_NON_DRY_FALLBACK_JSON" "$PHASE3_NON_DRY_FALLBACK_JSON" "check" "warn" "7" "false" "true" "true" "false"

echo "[roadmap-progress-phase3-handoff] missing-input fail-soft path"
rm -f "$PHASE3_FALLBACK_OLD_JSON" "$FALLBACK_SOURCE_JSON" "$PHASE3_INVALID_FALLBACK_JSON" "$PHASE3_COMPLETE_OLD_JSON" "$PHASE3_INCOMPLETE_NEW_JSON" "$PHASE3_NON_DRY_FALLBACK_JSON" "$PHASE3_DRY_RUN_FALLBACK_JSON"
MISSING_SUMMARY_JSON="$TMP_DIR/roadmap_progress_phase3_missing.json"
MISSING_REPORT_MD="$TMP_DIR/roadmap_progress_phase3_missing.md"
run_report "$MISSING_SUMMARY_JSON" "$MISSING_REPORT_MD"
assert_phase3_missing_block "$MISSING_SUMMARY_JSON"

echo "[roadmap-progress-phase3-handoff] unusable explicit summary path"
INVALID_SUMMARY_JSON="$TMP_DIR/roadmap_progress_phase3_invalid.json"
INVALID_REPORT_MD="$TMP_DIR/roadmap_progress_phase3_invalid.md"
run_report "$INVALID_SUMMARY_JSON" "$INVALID_REPORT_MD" \
  --phase3-windows-client-beta-summary-json "$PHASE3_INVALID_SUMMARY_JSON"
assert_phase3_invalid_block "$INVALID_SUMMARY_JSON" "$PHASE3_INVALID_SUMMARY_JSON"

echo "roadmap progress phase3 handoff integration ok"
