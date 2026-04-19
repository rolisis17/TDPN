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

PHASE4_HANDOFF_SUMMARY_JSON="$TMP_DIR/phase4_windows_full_parity_handoff_check_summary.json"
PHASE4_CHECK_SUMMARY_JSON="$TMP_DIR/phase4_windows_full_parity_check_summary.json"
PHASE4_RUN_SUMMARY_JSON="$TMP_DIR/phase4_windows_full_parity_run_summary.json"
PHASE4_NEWER_CHECK_SUMMARY_JSON="$TMP_DIR/phase4_windows_full_parity_check_summary_newer.json"
PHASE4_DRY_RUN_CHECK_SUMMARY_JSON="$TMP_DIR/phase4_windows_full_parity_check_summary_dry_run_newer.json"
PHASE4_STAGE_SUMMARY_JSON="$TMP_DIR/phase4_windows_full_parity_stage_summary.json"
PHASE4_INVALID_SUMMARY_JSON="$TMP_DIR/phase4_windows_full_parity_invalid_summary.json"

cat >"$PHASE4_HANDOFF_SUMMARY_JSON" <<'EOF_PHASE4_HANDOFF'
{
  "version": 1,
  "schema": {
    "id": "phase4_windows_full_parity_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "signals": {
    "windows_server_packaging_ok": true,
    "windows_role_runbooks_ok": true,
    "cross_platform_interop_ok": false,
    "role_combination_validation_ok": true,
    "windows_native_bootstrap_guardrails_ok": true
  }
}
EOF_PHASE4_HANDOFF

cat >"$PHASE4_CHECK_SUMMARY_JSON" <<'EOF_PHASE4_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase4_windows_full_parity_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "warn",
  "rc": 7,
  "signals": {
    "windows_server_packaging_ok": false,
    "windows_role_runbooks_ok": true,
    "cross_platform_interop_ok": true,
    "role_combination_validation_ok": false
  }
}
EOF_PHASE4_CHECK

cat >"$PHASE4_RUN_SUMMARY_JSON" <<EOF_PHASE4_RUN
{
  "version": 1,
  "schema": {
    "id": "phase4_windows_full_parity_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "artifacts": {
    "check_summary_json": "$PHASE4_CHECK_SUMMARY_JSON"
  },
  "steps": {
    "phase4_windows_full_parity_check": {
      "artifacts": {
        "summary_json": "$PHASE4_CHECK_SUMMARY_JSON"
      }
    }
  }
}
EOF_PHASE4_RUN

cat >"$PHASE4_NEWER_CHECK_SUMMARY_JSON" <<'EOF_PHASE4_CHECK_NEWER'
{
  "version": 1,
  "schema": {
    "id": "phase4_windows_full_parity_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "signals": {
    "windows_server_packaging_ok": true,
    "windows_role_runbooks_ok": false,
    "cross_platform_interop_ok": false,
    "role_combination_validation_ok": true,
    "windows_native_bootstrap_guardrails_ok": true
  }
}
EOF_PHASE4_CHECK_NEWER

cat >"$PHASE4_DRY_RUN_CHECK_SUMMARY_JSON" <<'EOF_PHASE4_CHECK_DRY_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase4_windows_full_parity_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "inputs": {
    "dry_run": true
  },
  "signals": {
    "windows_server_packaging_ok": true,
    "windows_role_runbooks_ok": false,
    "cross_platform_interop_ok": false,
    "role_combination_validation_ok": true
  }
}
EOF_PHASE4_CHECK_DRY_RUN

cat >"$PHASE4_STAGE_SUMMARY_JSON" <<'EOF_PHASE4_STAGE'
{
  "version": 1,
  "schema": {
    "id": "phase4_windows_full_parity_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "stages": {
    "windows_native_bootstrap_guardrails": {
      "ok": true
    }
  }
}
EOF_PHASE4_STAGE

cat >"$PHASE4_INVALID_SUMMARY_JSON" <<'EOF_PHASE4_INVALID'
{"version":1
EOF_PHASE4_INVALID

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

assert_phase4_block() {
  local summary_json="$1"
  local input_json="$2"
  local source_json="$3"
  local source_kind="$4"
  local status="$5"
  local rc="$6"
  local windows_server_packaging_ok="$7"
  local windows_role_runbooks_ok="$8"
  local cross_platform_interop_ok="$9"
  local role_combination_validation_ok="${10}"
  local windows_native_bootstrap_guardrails_ok="${11}"
  local windows_native_bootstrap_guardrails_ok_source="${12}"
  jq -e \
    --arg input_json "$input_json" \
    --arg source_json "$source_json" \
    --arg source_kind "$source_kind" \
    --arg status "$status" \
    --argjson rc "$rc" \
    --argjson windows_server_packaging_ok "$windows_server_packaging_ok" \
    --argjson windows_role_runbooks_ok "$windows_role_runbooks_ok" \
    --argjson cross_platform_interop_ok "$cross_platform_interop_ok" \
    --argjson role_combination_validation_ok "$role_combination_validation_ok" \
    --argjson windows_native_bootstrap_guardrails_ok "$windows_native_bootstrap_guardrails_ok" \
    --arg windows_native_bootstrap_guardrails_ok_source "$windows_native_bootstrap_guardrails_ok_source" \
    '
      .vpn_track.phase4_windows_full_parity_handoff.available == true
      and .vpn_track.phase4_windows_full_parity_handoff.input_summary_json == $input_json
      and .vpn_track.phase4_windows_full_parity_handoff.source_summary_json == $source_json
      and .vpn_track.phase4_windows_full_parity_handoff.source_summary_kind == $source_kind
      and .vpn_track.phase4_windows_full_parity_handoff.status == $status
      and .vpn_track.phase4_windows_full_parity_handoff.rc == $rc
      and .vpn_track.phase4_windows_full_parity_handoff.windows_server_packaging_ok == $windows_server_packaging_ok
      and .vpn_track.phase4_windows_full_parity_handoff.windows_role_runbooks_ok == $windows_role_runbooks_ok
      and .vpn_track.phase4_windows_full_parity_handoff.cross_platform_interop_ok == $cross_platform_interop_ok
      and .vpn_track.phase4_windows_full_parity_handoff.role_combination_validation_ok == $role_combination_validation_ok
      and .vpn_track.phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok == $windows_native_bootstrap_guardrails_ok
      and .vpn_track.phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok_source == (if $windows_native_bootstrap_guardrails_ok_source == "null" then null else $windows_native_bootstrap_guardrails_ok_source end)
      and .artifacts.phase4_windows_full_parity_summary_json == $source_json
    ' "$summary_json" >/dev/null
}

assert_phase4_missing_block() {
  local summary_json="$1"
  jq -e '
    .vpn_track.phase4_windows_full_parity_handoff.available == false
    and .vpn_track.phase4_windows_full_parity_handoff.input_summary_json == null
    and .vpn_track.phase4_windows_full_parity_handoff.source_summary_json == null
    and .vpn_track.phase4_windows_full_parity_handoff.source_summary_kind == null
    and .vpn_track.phase4_windows_full_parity_handoff.status == "missing"
    and .vpn_track.phase4_windows_full_parity_handoff.rc == null
    and .vpn_track.phase4_windows_full_parity_handoff.windows_server_packaging_ok == null
    and .vpn_track.phase4_windows_full_parity_handoff.windows_role_runbooks_ok == null
    and .vpn_track.phase4_windows_full_parity_handoff.cross_platform_interop_ok == null
    and .vpn_track.phase4_windows_full_parity_handoff.role_combination_validation_ok == null
    and .vpn_track.phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok == null
    and .vpn_track.phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok_source == null
    and .artifacts.phase4_windows_full_parity_summary_json == null
  ' "$summary_json" >/dev/null
}

assert_phase4_invalid_block() {
  local summary_json="$1"
  local input_json="$2"
  jq -e \
    --arg input_json "$input_json" \
    '
      .vpn_track.phase4_windows_full_parity_handoff.available == false
      and .vpn_track.phase4_windows_full_parity_handoff.input_summary_json == $input_json
      and .vpn_track.phase4_windows_full_parity_handoff.source_summary_json == null
      and .vpn_track.phase4_windows_full_parity_handoff.source_summary_kind == null
      and .vpn_track.phase4_windows_full_parity_handoff.status == "invalid"
      and .vpn_track.phase4_windows_full_parity_handoff.rc == null
      and .vpn_track.phase4_windows_full_parity_handoff.windows_server_packaging_ok == null
      and .vpn_track.phase4_windows_full_parity_handoff.windows_role_runbooks_ok == null
      and .vpn_track.phase4_windows_full_parity_handoff.cross_platform_interop_ok == null
      and .vpn_track.phase4_windows_full_parity_handoff.role_combination_validation_ok == null
      and .vpn_track.phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok == null
      and .vpn_track.phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok_source == null
      and .artifacts.phase4_windows_full_parity_summary_json == null
    ' "$summary_json" >/dev/null
}

echo "[roadmap-progress-phase4-handoff] direct handoff summary path"
DIRECT_SUMMARY_JSON="$TMP_DIR/roadmap_progress_phase4_direct.json"
DIRECT_REPORT_MD="$TMP_DIR/roadmap_progress_phase4_direct.md"
run_report "$DIRECT_SUMMARY_JSON" "$DIRECT_REPORT_MD" \
  --phase4-windows-full-parity-summary-json "$PHASE4_HANDOFF_SUMMARY_JSON"
assert_phase4_block "$DIRECT_SUMMARY_JSON" "$PHASE4_HANDOFF_SUMMARY_JSON" "$PHASE4_HANDOFF_SUMMARY_JSON" "handoff" "pass" "0" "true" "true" "false" "true" "true" "signals.windows_native_bootstrap_guardrails_ok"

echo "[roadmap-progress-phase4-handoff] nested run->check summary path"
NESTED_SUMMARY_JSON="$TMP_DIR/roadmap_progress_phase4_nested.json"
NESTED_REPORT_MD="$TMP_DIR/roadmap_progress_phase4_nested.md"
run_report "$NESTED_SUMMARY_JSON" "$NESTED_REPORT_MD" \
  --phase4-windows-full-parity-summary-json "$PHASE4_RUN_SUMMARY_JSON"
assert_phase4_block "$NESTED_SUMMARY_JSON" "$PHASE4_RUN_SUMMARY_JSON" "$PHASE4_CHECK_SUMMARY_JSON" "check" "warn" "7" "false" "true" "true" "false" "null" "null"

echo "[roadmap-progress-phase4-handoff] .easy-node-logs fallback path"
PHASE4_OLD_DIR="$WORKSPACE/.easy-node-logs/zzz_old_valid"
PHASE4_NEW_DIR="$WORKSPACE/.easy-node-logs/aaa_new_valid"
PHASE4_INVALID_DIR="$WORKSPACE/.easy-node-logs/yyy_invalid_newest"
mkdir -p "$PHASE4_OLD_DIR" "$PHASE4_NEW_DIR" "$PHASE4_INVALID_DIR"
PHASE4_FALLBACK_OLD_JSON="$PHASE4_OLD_DIR/phase4_windows_full_parity_check_summary.json"
FALLBACK_SOURCE_JSON="$PHASE4_NEW_DIR/phase4_windows_full_parity_check_summary.json"
PHASE4_INVALID_FALLBACK_JSON="$PHASE4_INVALID_DIR/phase4_windows_full_parity_handoff_summary.json"
cp "$PHASE4_CHECK_SUMMARY_JSON" "$PHASE4_FALLBACK_OLD_JSON"
cp "$PHASE4_NEWER_CHECK_SUMMARY_JSON" "$FALLBACK_SOURCE_JSON"
cp "$PHASE4_INVALID_SUMMARY_JSON" "$PHASE4_INVALID_FALLBACK_JSON"
touch -t 202601010101 "$PHASE4_FALLBACK_OLD_JSON"
touch -t 202601020202 "$FALLBACK_SOURCE_JSON"
touch -t 202601030303 "$PHASE4_INVALID_FALLBACK_JSON"
FALLBACK_SUMMARY_JSON="$TMP_DIR/roadmap_progress_phase4_fallback.json"
FALLBACK_REPORT_MD="$TMP_DIR/roadmap_progress_phase4_fallback.md"
run_report "$FALLBACK_SUMMARY_JSON" "$FALLBACK_REPORT_MD"
assert_phase4_block "$FALLBACK_SUMMARY_JSON" "$FALLBACK_SOURCE_JSON" "$FALLBACK_SOURCE_JSON" "check" "pass" "0" "true" "false" "false" "true" "true" "signals.windows_native_bootstrap_guardrails_ok"

echo "[roadmap-progress-phase4-handoff] .easy-node-logs fallback prefers complete older source over newer incomplete candidate"
PHASE4_COMPLETE_OLD_DIR="$WORKSPACE/.easy-node-logs/zzz_complete_old"
PHASE4_INCOMPLETE_NEW_DIR="$WORKSPACE/.easy-node-logs/aaa_incomplete_newer"
mkdir -p "$PHASE4_COMPLETE_OLD_DIR" "$PHASE4_INCOMPLETE_NEW_DIR"
PHASE4_COMPLETE_OLD_JSON="$PHASE4_COMPLETE_OLD_DIR/phase4_windows_full_parity_check_summary.json"
PHASE4_INCOMPLETE_NEW_JSON="$PHASE4_INCOMPLETE_NEW_DIR/phase4_windows_full_parity_run_summary.json"
cp "$PHASE4_CHECK_SUMMARY_JSON" "$PHASE4_COMPLETE_OLD_JSON"
cat >"$PHASE4_INCOMPLETE_NEW_JSON" <<EOF_PHASE4_INCOMPLETE_NEW
{
  "version": 1,
  "schema": {
    "id": "phase4_windows_full_parity_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "signals": {
    "windows_server_packaging_ok": null,
    "windows_role_runbooks_ok": null,
    "cross_platform_interop_ok": null,
    "role_combination_validation_ok": null
  },
  "artifacts": {
    "check_summary_json": "$PHASE4_COMPLETE_OLD_JSON"
  }
}
EOF_PHASE4_INCOMPLETE_NEW
touch -t 202601040404 "$PHASE4_COMPLETE_OLD_JSON"
touch -t 202601050505 "$PHASE4_INCOMPLETE_NEW_JSON"
COMPLETENESS_SUMMARY_JSON="$TMP_DIR/roadmap_progress_phase4_fallback_complete_preferred.json"
COMPLETENESS_REPORT_MD="$TMP_DIR/roadmap_progress_phase4_fallback_complete_preferred.md"
run_report "$COMPLETENESS_SUMMARY_JSON" "$COMPLETENESS_REPORT_MD"
assert_phase4_block "$COMPLETENESS_SUMMARY_JSON" "$PHASE4_COMPLETE_OLD_JSON" "$PHASE4_COMPLETE_OLD_JSON" "check" "warn" "7" "false" "true" "true" "false" "null" "null"

echo "[roadmap-progress-phase4-handoff] stage-based guardrail fallback path"
PHASE4_STAGE_REPORT_JSON="$TMP_DIR/roadmap_progress_phase4_stage.json"
PHASE4_STAGE_REPORT_MD="$TMP_DIR/roadmap_progress_phase4_stage.md"
run_report "$PHASE4_STAGE_REPORT_JSON" "$PHASE4_STAGE_REPORT_MD" \
  --phase4-windows-full-parity-summary-json "$PHASE4_STAGE_SUMMARY_JSON"
assert_phase4_block "$PHASE4_STAGE_REPORT_JSON" "$PHASE4_STAGE_SUMMARY_JSON" "$PHASE4_STAGE_SUMMARY_JSON" "handoff" "pass" "0" "null" "null" "null" "null" "true" "stages.windows_native_bootstrap_guardrails.ok"

echo "[roadmap-progress-phase4-handoff] .easy-node-logs fallback prefers non-dry source over newer dry-run candidate"
PHASE4_NON_DRY_FALLBACK_DIR="$WORKSPACE/.easy-node-logs/ddd_non_dry_older"
PHASE4_DRY_RUN_FALLBACK_DIR="$WORKSPACE/.easy-node-logs/eee_dry_run_newer"
mkdir -p "$PHASE4_NON_DRY_FALLBACK_DIR" "$PHASE4_DRY_RUN_FALLBACK_DIR"
PHASE4_NON_DRY_FALLBACK_JSON="$PHASE4_NON_DRY_FALLBACK_DIR/phase4_windows_full_parity_check_summary.json"
PHASE4_DRY_RUN_FALLBACK_JSON="$PHASE4_DRY_RUN_FALLBACK_DIR/phase4_windows_full_parity_check_summary.json"
cp "$PHASE4_CHECK_SUMMARY_JSON" "$PHASE4_NON_DRY_FALLBACK_JSON"
cp "$PHASE4_DRY_RUN_CHECK_SUMMARY_JSON" "$PHASE4_DRY_RUN_FALLBACK_JSON"
touch -t 202601060606 "$PHASE4_NON_DRY_FALLBACK_JSON"
touch -t 202601060707 "$PHASE4_DRY_RUN_FALLBACK_JSON"
DRY_RUN_PREFERENCE_SUMMARY_JSON="$TMP_DIR/roadmap_progress_phase4_fallback_non_dry_preferred.json"
DRY_RUN_PREFERENCE_REPORT_MD="$TMP_DIR/roadmap_progress_phase4_fallback_non_dry_preferred.md"
run_report "$DRY_RUN_PREFERENCE_SUMMARY_JSON" "$DRY_RUN_PREFERENCE_REPORT_MD"
assert_phase4_block "$DRY_RUN_PREFERENCE_SUMMARY_JSON" "$PHASE4_NON_DRY_FALLBACK_JSON" "$PHASE4_NON_DRY_FALLBACK_JSON" "check" "warn" "7" "false" "true" "true" "false" "null" "null"

echo "[roadmap-progress-phase4-handoff] missing-input fail-soft path"
rm -f "$PHASE4_FALLBACK_OLD_JSON" "$FALLBACK_SOURCE_JSON" "$PHASE4_INVALID_FALLBACK_JSON" "$PHASE4_COMPLETE_OLD_JSON" "$PHASE4_INCOMPLETE_NEW_JSON" "$PHASE4_NON_DRY_FALLBACK_JSON" "$PHASE4_DRY_RUN_FALLBACK_JSON"
MISSING_SUMMARY_JSON="$TMP_DIR/roadmap_progress_phase4_missing.json"
MISSING_REPORT_MD="$TMP_DIR/roadmap_progress_phase4_missing.md"
run_report "$MISSING_SUMMARY_JSON" "$MISSING_REPORT_MD"
assert_phase4_missing_block "$MISSING_SUMMARY_JSON"

echo "[roadmap-progress-phase4-handoff] unusable explicit summary path"
INVALID_SUMMARY_JSON="$TMP_DIR/roadmap_progress_phase4_invalid.json"
INVALID_REPORT_MD="$TMP_DIR/roadmap_progress_phase4_invalid.md"
run_report "$INVALID_SUMMARY_JSON" "$INVALID_REPORT_MD" \
  --phase4-windows-full-parity-summary-json "$PHASE4_INVALID_SUMMARY_JSON"
assert_phase4_invalid_block "$INVALID_SUMMARY_JSON" "$PHASE4_INVALID_SUMMARY_JSON"

echo "roadmap progress phase4 handoff integration ok"
