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

SCRIPT_UNDER_TEST="${PHASE5_SETTLEMENT_LAYER_SUMMARY_REPORT_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase5_settlement_layer_summary_report.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS_CI="$TMP_DIR/ci_pass.json"
PASS_CHECK="$TMP_DIR/check_pass.json"
PASS_RUN="$TMP_DIR/run_pass.json"
PASS_HANDOFF_CHECK="$TMP_DIR/handoff_check_pass.json"
PASS_HANDOFF_RUN="$TMP_DIR/handoff_run_pass.json"
PASS_REPORT_JSON="$TMP_DIR/report_pass.json"
PASS_CANONICAL_REPORT_JSON="$TMP_DIR/report_pass_canonical.json"
PASS_LOG="$TMP_DIR/pass.log"
PASS_SAME_PATH_REPORT_JSON="$TMP_DIR/report_pass_same_path.json"
PASS_SAME_PATH_LOG="$TMP_DIR/pass_same_path.log"

FAIL_CI="$TMP_DIR/ci_fail_case.json"
FAIL_CHECK="$TMP_DIR/check_fail_case.json"
FAIL_RUN="$TMP_DIR/run_fail_case.json"
FAIL_HANDOFF_CHECK="$TMP_DIR/handoff_check_fail_case.json"
FAIL_HANDOFF_RUN="$TMP_DIR/handoff_run_fail_case.json"
FAIL_REPORT_JSON="$TMP_DIR/report_fail.json"
FAIL_LOG="$TMP_DIR/fail.log"

MISSING_REPORT_JSON="$TMP_DIR/report_missing.json"
MISSING_LOG="$TMP_DIR/missing.log"
MISSING_PATH="$TMP_DIR/does_not_exist.json"

FALLBACK_REPORTS_DIR="$TMP_DIR/fallback_reports"
FALLBACK_REPORT_JSON="$TMP_DIR/report_fallback.json"
FALLBACK_LOG="$TMP_DIR/fallback.log"

FALLBACK_CI_OLD_DIR="$FALLBACK_REPORTS_DIR/ci_phase5_settlement_layer_20260416_165959"
FALLBACK_CI_NEW_DIR="$FALLBACK_REPORTS_DIR/ci_phase5_settlement_layer_20260416_170000"
FALLBACK_HANDOFF_RUN_OLD_DIR="$FALLBACK_REPORTS_DIR/phase5_settlement_layer_handoff_run_20260416_170500"
FALLBACK_HANDOFF_RUN_NEW_DIR="$FALLBACK_REPORTS_DIR/phase5_settlement_layer_handoff_run_20260416_170700"
FALLBACK_HANDOFF_CHECK_FROM_HANDOFF_RUN="$FALLBACK_HANDOFF_RUN_NEW_DIR/phase5_settlement_layer_handoff_check_fallback.json"

EMBEDDED_TS_REPORTS_DIR="$TMP_DIR/embedded_timestamp_reports"
EMBEDDED_TS_REPORT_JSON="$TMP_DIR/report_embedded_timestamp.json"
EMBEDDED_TS_LOG="$TMP_DIR/embedded_timestamp.log"
EMBEDDED_TS_CI_HIGH_TS_OLDER_DIR="$EMBEDDED_TS_REPORTS_DIR/ci_phase5_settlement_layer_20260416_170000"
EMBEDDED_TS_CI_LOW_TS_NEWER_DIR="$EMBEDDED_TS_REPORTS_DIR/ci_phase5_settlement_layer_20260416_170100"
EMBEDDED_TS_CI_INVALID_TS_NEWEST_DIR="$EMBEDDED_TS_REPORTS_DIR/ci_phase5_settlement_layer_20260416_170200"
EMBEDDED_TS_CI_CONFLICT_TS_NEWEST_DIR="$EMBEDDED_TS_REPORTS_DIR/ci_phase5_settlement_layer_20260416_170300"
EMBEDDED_TS_CHECK="$EMBEDDED_TS_REPORTS_DIR/phase5_settlement_layer_check_summary.json"
EMBEDDED_TS_RUN="$EMBEDDED_TS_REPORTS_DIR/phase5_settlement_layer_run_summary.json"
EMBEDDED_TS_HANDOFF_CHECK="$EMBEDDED_TS_REPORTS_DIR/phase5_settlement_layer_handoff_check_summary.json"
EMBEDDED_TS_HANDOFF_RUN="$EMBEDDED_TS_REPORTS_DIR/phase5_settlement_layer_handoff_run_summary.json"

# Isolation default: prevent fail/missing/fallback paths from clobbering
# canonical summary artifacts under repository .easy-node-logs.
DEFAULT_CANONICAL_REPORT_JSON="$TMP_DIR/default_canonical_report.json"
export PHASE5_SETTLEMENT_LAYER_SUMMARY_REPORT_CANONICAL_SUMMARY_JSON="$DEFAULT_CANONICAL_REPORT_JSON"

assert_default_canonical_report() {
  local summary_json="$1"
  local log_file="$2"
  local label="$3"

  if [[ ! -f "$DEFAULT_CANONICAL_REPORT_JSON" ]]; then
    echo "$label: missing default canonical report: $DEFAULT_CANONICAL_REPORT_JSON"
    cat "$log_file"
    exit 1
  fi
  if ! jq -e --arg expected_canonical "$DEFAULT_CANONICAL_REPORT_JSON" '.artifacts.canonical_summary_json == $expected_canonical' "$summary_json" >/dev/null; then
    echo "$label: summary report did not use isolated default canonical path"
    cat "$summary_json"
    cat "$log_file"
    exit 1
  fi
  if ! cmp -s "$summary_json" "$DEFAULT_CANONICAL_REPORT_JSON"; then
    echo "$label: default canonical report diverges from run summary report"
    cat "$summary_json"
    cat "$DEFAULT_CANONICAL_REPORT_JSON"
    cat "$log_file"
    exit 1
  fi
}

cat >"$PASS_CI" <<'EOF_PASS_CI'
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
    "settlement_dual_asset_parity": {
      "status": "fail"
    },
    "settlement_adapter_signed_tx_roundtrip": {
      "status": "fail"
    },
    "settlement_shadow_env": {
      "status": "fail"
    },
    "settlement_shadow_status_surface": {
      "status": "fail"
    },
    "issuer_sponsor_api_live_smoke": {
      "status": "fail"
    },
    "issuer_sponsor_vpn_session_live_smoke": {
      "status": "fail"
    },
    "issuer_settlement_status_live_smoke": {
      "status": "fail"
    },
    "issuer_admin_blockchain_handlers_coverage": {
      "status": "fail"
    }
  }
}
EOF_PASS_CI

cat >"$PASS_CHECK" <<'EOF_PASS_CHECK'
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
    "settlement_dual_asset_parity_ok": false,
    "issuer_sponsor_api_live_smoke_ok": false,
    "issuer_sponsor_vpn_session_live_smoke_ok": false,
    "issuer_admin_blockchain_handlers_coverage_ok": false
  }
}
EOF_PASS_CHECK

cat >"$PASS_RUN" <<'EOF_PASS_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_PASS_RUN

cat >"$PASS_HANDOFF_CHECK" <<'EOF_PASS_HANDOFF_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "handoff": {
    "settlement_dual_asset_parity_ok": true,
    "settlement_adapter_signed_tx_roundtrip_status": "pass",
    "settlement_adapter_signed_tx_roundtrip_ok": true,
    "settlement_shadow_env_status": "pass",
    "settlement_shadow_env_ok": true,
    "settlement_shadow_status_surface_status": "pass",
    "settlement_shadow_status_surface_ok": true,
    "issuer_sponsor_api_live_smoke_ok": true,
    "issuer_sponsor_vpn_session_live_smoke_ok": true,
    "issuer_settlement_status_live_smoke_ok": true,
    "issuer_admin_blockchain_handlers_coverage_ok": true
  }
}
EOF_PASS_HANDOFF_CHECK

cat >"$PASS_HANDOFF_RUN" <<'EOF_PASS_HANDOFF_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_PASS_HANDOFF_RUN

echo "[phase5-settlement-summary-report] pass path"
PHASE5_SETTLEMENT_LAYER_SUMMARY_REPORT_CANONICAL_SUMMARY_JSON="$PASS_CANONICAL_REPORT_JSON" "$SCRIPT_UNDER_TEST" \
  --ci-summary-json "$PASS_CI" \
  --check-summary-json "$PASS_CHECK" \
  --run-summary-json "$PASS_RUN" \
  --handoff-check-summary-json "$PASS_HANDOFF_CHECK" \
  --handoff-run-summary-json "$PASS_HANDOFF_RUN" \
  --summary-json "$PASS_REPORT_JSON" \
  --print-summary-json 0 >"$PASS_LOG" 2>&1

if ! jq -e \
  --arg expected_canonical_summary_json "$PASS_CANONICAL_REPORT_JSON" \
  --arg expected_signal_path "$PASS_HANDOFF_CHECK" \
  '
  .version == 1
  and .schema.id == "phase5_settlement_layer_summary_report"
  and .status == "pass"
  and .rc == 0
  and .counts.configured == 5
  and .counts.pass == 5
  and .counts.fail == 0
  and .counts.missing == 0
  and .counts.invalid == 0
  and .summaries.ci_phase5_settlement_layer_summary.status == "pass"
  and .summaries.phase5_settlement_layer_check_summary.status == "pass"
  and .summaries.phase5_settlement_layer_run_summary.status == "pass"
  and .summaries.phase5_settlement_layer_handoff_check_summary.status == "pass"
  and .summaries.phase5_settlement_layer_handoff_run_summary.status == "pass"
  and .summaries.ci_phase5_settlement_layer_summary.schema_id == "ci_phase5_settlement_layer_summary"
  and .summaries.phase5_settlement_layer_check_summary.schema_id == "phase5_settlement_layer_check_summary"
  and .summaries.phase5_settlement_layer_run_summary.schema_id == "phase5_settlement_layer_run_summary"
  and .summaries.phase5_settlement_layer_handoff_check_summary.schema_id == "phase5_settlement_layer_handoff_check_summary"
  and .summaries.phase5_settlement_layer_handoff_run_summary.schema_id == "phase5_settlement_layer_handoff_run_summary"
  and .signals.issuer_sponsor_api_live_smoke.status == "pass"
  and .signals.issuer_sponsor_api_live_smoke.ok == true
  and .signals.issuer_sponsor_api_live_smoke.resolved == true
  and .signals.issuer_sponsor_api_live_smoke.source == "phase5_settlement_layer_handoff_check_summary"
  and .signals.issuer_sponsor_api_live_smoke.source_field == "handoff.issuer_sponsor_api_live_smoke_ok"
  and .signals.issuer_sponsor_api_live_smoke.source_path == $expected_signal_path
  and .signals.issuer_sponsor_api_live_smoke.fallback == false
  and .signals.issuer_sponsor_api_live_smoke.source_priority_index == 1
  and (.signals.issuer_sponsor_api_live_smoke.source_priority | length) == 5
  and .signals.issuer_sponsor_vpn_session_live_smoke.status == "pass"
  and .signals.issuer_sponsor_vpn_session_live_smoke.ok == true
  and .signals.issuer_sponsor_vpn_session_live_smoke.resolved == true
  and .signals.issuer_sponsor_vpn_session_live_smoke.source == "phase5_settlement_layer_handoff_check_summary"
  and .signals.issuer_sponsor_vpn_session_live_smoke.source_field == "handoff.issuer_sponsor_vpn_session_live_smoke_ok"
  and .signals.issuer_sponsor_vpn_session_live_smoke.source_path == $expected_signal_path
  and .signals.issuer_sponsor_vpn_session_live_smoke.fallback == false
  and .signals.issuer_sponsor_vpn_session_live_smoke.source_priority_index == 1
  and (.signals.issuer_sponsor_vpn_session_live_smoke.source_priority | length) == 5
  and .signals.issuer_settlement_status_live_smoke.status == "pass"
  and .signals.issuer_settlement_status_live_smoke.ok == true
  and .signals.issuer_settlement_status_live_smoke.resolved == true
  and .signals.issuer_settlement_status_live_smoke.source == "phase5_settlement_layer_handoff_check_summary"
  and .signals.issuer_settlement_status_live_smoke.source_field == "handoff.issuer_settlement_status_live_smoke_ok"
  and .signals.issuer_settlement_status_live_smoke.source_path == $expected_signal_path
  and .signals.issuer_settlement_status_live_smoke.fallback == false
  and .signals.issuer_settlement_status_live_smoke.source_priority_index == 1
  and (.signals.issuer_settlement_status_live_smoke.source_priority | length) == 6
  and .signals.settlement_dual_asset_parity.status == "pass"
  and .signals.settlement_dual_asset_parity.ok == true
  and .signals.settlement_dual_asset_parity.resolved == true
  and .signals.settlement_dual_asset_parity.source == "phase5_settlement_layer_handoff_check_summary"
  and .signals.settlement_dual_asset_parity.source_field == "handoff.settlement_dual_asset_parity_ok"
  and .signals.settlement_dual_asset_parity.source_path == $expected_signal_path
  and .signals.settlement_dual_asset_parity.fallback == false
  and .signals.settlement_dual_asset_parity.source_priority_index == 1
  and (.signals.settlement_dual_asset_parity.source_priority | length) == 5
  and .signals.settlement_adapter_signed_tx_roundtrip.status == "pass"
  and .signals.settlement_adapter_signed_tx_roundtrip.ok == true
  and .signals.settlement_adapter_signed_tx_roundtrip.resolved == true
  and .signals.settlement_adapter_signed_tx_roundtrip.source == "phase5_settlement_layer_handoff_check_summary"
  and .signals.settlement_adapter_signed_tx_roundtrip.source_field == "handoff.settlement_adapter_signed_tx_roundtrip_ok"
  and .signals.settlement_adapter_signed_tx_roundtrip.source_path == $expected_signal_path
  and .signals.settlement_adapter_signed_tx_roundtrip.fallback == false
  and .signals.settlement_adapter_signed_tx_roundtrip.source_priority_index == 1
  and (.signals.settlement_adapter_signed_tx_roundtrip.source_priority | length) == 6
  and .signals.settlement_shadow_env.status == "pass"
  and .signals.settlement_shadow_env.ok == true
  and .signals.settlement_shadow_env.resolved == true
  and .signals.settlement_shadow_env.source == "phase5_settlement_layer_handoff_check_summary"
  and .signals.settlement_shadow_env.source_field == "handoff.settlement_shadow_env_ok"
  and .signals.settlement_shadow_env.source_path == $expected_signal_path
  and .signals.settlement_shadow_env.fallback == false
  and .signals.settlement_shadow_env.source_priority_index == 1
  and (.signals.settlement_shadow_env.source_priority | length) == 6
  and .signals.settlement_shadow_status_surface.status == "pass"
  and .signals.settlement_shadow_status_surface.ok == true
  and .signals.settlement_shadow_status_surface.resolved == true
  and .signals.settlement_shadow_status_surface.source == "phase5_settlement_layer_handoff_check_summary"
  and .signals.settlement_shadow_status_surface.source_field == "handoff.settlement_shadow_status_surface_ok"
  and .signals.settlement_shadow_status_surface.source_path == $expected_signal_path
  and .signals.settlement_shadow_status_surface.fallback == false
  and .signals.settlement_shadow_status_surface.source_priority_index == 1
  and (.signals.settlement_shadow_status_surface.source_priority | length) == 6
  and (
    if (.signals | has("issuer_admin_blockchain_handlers_coverage")) then
      .signals.issuer_admin_blockchain_handlers_coverage.status == "pass"
      and .signals.issuer_admin_blockchain_handlers_coverage.ok == true
      and .signals.issuer_admin_blockchain_handlers_coverage.resolved == true
      and .signals.issuer_admin_blockchain_handlers_coverage.source == "phase5_settlement_layer_handoff_check_summary"
      and .signals.issuer_admin_blockchain_handlers_coverage.source_field == "handoff.issuer_admin_blockchain_handlers_coverage_ok"
      and .signals.issuer_admin_blockchain_handlers_coverage.source_path == $expected_signal_path
      and .signals.issuer_admin_blockchain_handlers_coverage.fallback == false
      and .signals.issuer_admin_blockchain_handlers_coverage.source_priority_index == 1
      and (.signals.issuer_admin_blockchain_handlers_coverage.source_priority | length) == 5
    else true end
  )
  and .artifacts.canonical_summary_json == $expected_canonical_summary_json
' "$PASS_REPORT_JSON" >/dev/null; then
  echo "phase5 summary report pass-path contract mismatch"
  cat "$PASS_REPORT_JSON"
  cat "$PASS_LOG"
  exit 1
fi

if ! grep -Fq "[phase5-summary] issuer_sponsor_vpn_session_live_smoke: status=pass ok=true source=phase5_settlement_layer_handoff_check_summary fallback=0 path=$PASS_HANDOFF_CHECK" "$PASS_LOG"; then
  echo "expected issuer_sponsor_vpn_session_live_smoke log line in pass-path output"
  cat "$PASS_LOG"
  exit 1
fi

if [[ ! -f "$PASS_CANONICAL_REPORT_JSON" ]]; then
  echo "expected canonical summary artifact to exist: $PASS_CANONICAL_REPORT_JSON"
  cat "$PASS_LOG"
  exit 1
fi

if ! cmp -s "$PASS_REPORT_JSON" "$PASS_CANONICAL_REPORT_JSON"; then
  echo "expected canonical summary artifact parity with run summary"
  cat "$PASS_REPORT_JSON"
  cat "$PASS_CANONICAL_REPORT_JSON"
  cat "$PASS_LOG"
  exit 1
fi

echo "[phase5-settlement-summary-report] pass path (canonical equals summary path)"
PHASE5_SETTLEMENT_LAYER_SUMMARY_REPORT_CANONICAL_SUMMARY_JSON="$PASS_SAME_PATH_REPORT_JSON" "$SCRIPT_UNDER_TEST" \
  --ci-summary-json "$PASS_CI" \
  --check-summary-json "$PASS_CHECK" \
  --run-summary-json "$PASS_RUN" \
  --handoff-check-summary-json "$PASS_HANDOFF_CHECK" \
  --handoff-run-summary-json "$PASS_HANDOFF_RUN" \
  --summary-json "$PASS_SAME_PATH_REPORT_JSON" \
  --print-summary-json 0 >"$PASS_SAME_PATH_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .artifacts.summary_json == .artifacts.canonical_summary_json
' "$PASS_SAME_PATH_REPORT_JSON" >/dev/null; then
  echo "phase5 summary report same-path canonical contract mismatch"
  cat "$PASS_SAME_PATH_REPORT_JSON"
  cat "$PASS_SAME_PATH_LOG"
  exit 1
fi

if ! grep -Fq "[phase5-summary] canonical_summary_json=$PASS_SAME_PATH_REPORT_JSON" "$PASS_SAME_PATH_LOG"; then
  echo "expected canonical summary log output for same-path canonical summary"
  cat "$PASS_SAME_PATH_LOG"
  exit 1
fi

cat >"$FAIL_CI" <<'EOF_FAIL_CI'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FAIL_CI

cat >"$FAIL_CHECK" <<'EOF_FAIL_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FAIL_CHECK

cat >"$FAIL_RUN" <<'EOF_FAIL_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FAIL_RUN

cat >"$FAIL_HANDOFF_CHECK" <<'EOF_FAIL_HANDOFF_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FAIL_HANDOFF_CHECK

cat >"$FAIL_HANDOFF_RUN" <<'EOF_FAIL_HANDOFF_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "rc": 41
}
EOF_FAIL_HANDOFF_RUN

echo "[phase5-settlement-summary-report] fail path"
set +e
"$SCRIPT_UNDER_TEST" \
  --ci-summary-json "$FAIL_CI" \
  --check-summary-json "$FAIL_CHECK" \
  --run-summary-json "$FAIL_RUN" \
  --handoff-check-summary-json "$FAIL_HANDOFF_CHECK" \
  --handoff-run-summary-json "$FAIL_HANDOFF_RUN" \
  --summary-json "$FAIL_REPORT_JSON" \
  --print-summary-json 0 >"$FAIL_LOG" 2>&1
fail_rc=$?
set -e

if [[ "$fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for fail path, got rc=$fail_rc"
  cat "$FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .counts.configured == 5
  and .counts.fail == 1
  and .summaries.phase5_settlement_layer_handoff_run_summary.status == "fail"
  and ((.decision.reasons // []) | any(test("phase5_settlement_layer_handoff_run status is fail")))
' "$FAIL_REPORT_JSON" >/dev/null; then
  echo "phase5 summary report fail-path contract mismatch"
  cat "$FAIL_REPORT_JSON"
  cat "$FAIL_LOG"
  exit 1
fi
assert_default_canonical_report "$FAIL_REPORT_JSON" "$FAIL_LOG" "fail path"

echo "[phase5-settlement-summary-report] missing-input path"
set +e
"$SCRIPT_UNDER_TEST" \
  --ci-summary-json "$MISSING_PATH" \
  --summary-json "$MISSING_REPORT_JSON" \
  --print-summary-json 0 >"$MISSING_LOG" 2>&1
missing_rc=$?
set -e

if [[ "$missing_rc" -ne 1 ]]; then
  echo "expected rc=1 for missing-input path, got rc=$missing_rc"
  cat "$MISSING_LOG"
  exit 1
fi
if ! jq -e '
  .status == "missing"
  and .rc == 1
  and .counts.configured == 1
  and .counts.pass == 0
  and .counts.fail == 0
  and .counts.missing == 1
  and .counts.invalid == 0
  and .summaries.ci_phase5_settlement_layer_summary.status == "missing"
  and .summaries.phase5_settlement_layer_check_summary.status == "skipped"
  and .summaries.phase5_settlement_layer_run_summary.status == "skipped"
  and .summaries.phase5_settlement_layer_handoff_check_summary.status == "skipped"
  and .summaries.phase5_settlement_layer_handoff_run_summary.status == "skipped"
  and .signals.issuer_sponsor_api_live_smoke.status == "missing"
  and .signals.issuer_sponsor_api_live_smoke.ok == null
  and .signals.issuer_sponsor_api_live_smoke.resolved == false
  and .signals.issuer_sponsor_api_live_smoke.source == "unresolved"
  and .signals.issuer_sponsor_api_live_smoke.source_field == null
  and .signals.issuer_sponsor_api_live_smoke.source_path == null
  and .signals.issuer_sponsor_api_live_smoke.fallback == false
  and .signals.issuer_sponsor_api_live_smoke.source_priority_index == null
  and .signals.issuer_sponsor_vpn_session_live_smoke.status == "missing"
  and .signals.issuer_sponsor_vpn_session_live_smoke.ok == null
  and .signals.issuer_sponsor_vpn_session_live_smoke.resolved == false
  and .signals.issuer_sponsor_vpn_session_live_smoke.source == "unresolved"
  and .signals.issuer_sponsor_vpn_session_live_smoke.source_field == null
  and .signals.issuer_sponsor_vpn_session_live_smoke.source_path == null
  and .signals.issuer_sponsor_vpn_session_live_smoke.fallback == false
  and .signals.issuer_sponsor_vpn_session_live_smoke.source_priority_index == null
  and .signals.issuer_settlement_status_live_smoke.status == "missing"
  and .signals.issuer_settlement_status_live_smoke.ok == null
  and .signals.issuer_settlement_status_live_smoke.resolved == false
  and .signals.issuer_settlement_status_live_smoke.source == "unresolved"
  and .signals.issuer_settlement_status_live_smoke.source_field == null
  and .signals.issuer_settlement_status_live_smoke.source_path == null
  and .signals.issuer_settlement_status_live_smoke.fallback == false
  and .signals.issuer_settlement_status_live_smoke.source_priority_index == null
  and .signals.settlement_dual_asset_parity.status == "missing"
  and .signals.settlement_dual_asset_parity.ok == null
  and .signals.settlement_dual_asset_parity.resolved == false
  and .signals.settlement_dual_asset_parity.source == "unresolved"
  and .signals.settlement_dual_asset_parity.source_field == null
  and .signals.settlement_dual_asset_parity.source_path == null
  and .signals.settlement_dual_asset_parity.fallback == false
  and .signals.settlement_dual_asset_parity.source_priority_index == null
  and .signals.settlement_adapter_signed_tx_roundtrip.status == "missing"
  and .signals.settlement_adapter_signed_tx_roundtrip.ok == null
  and .signals.settlement_adapter_signed_tx_roundtrip.resolved == false
  and .signals.settlement_adapter_signed_tx_roundtrip.source == "unresolved"
  and .signals.settlement_adapter_signed_tx_roundtrip.source_field == null
  and .signals.settlement_adapter_signed_tx_roundtrip.source_path == null
  and .signals.settlement_adapter_signed_tx_roundtrip.fallback == false
  and .signals.settlement_adapter_signed_tx_roundtrip.source_priority_index == null
  and .signals.settlement_shadow_env.status == "missing"
  and .signals.settlement_shadow_env.ok == null
  and .signals.settlement_shadow_env.resolved == false
  and .signals.settlement_shadow_env.source == "unresolved"
  and .signals.settlement_shadow_env.source_field == null
  and .signals.settlement_shadow_env.source_path == null
  and .signals.settlement_shadow_env.fallback == false
  and .signals.settlement_shadow_env.source_priority_index == null
  and .signals.settlement_shadow_status_surface.status == "missing"
  and .signals.settlement_shadow_status_surface.ok == null
  and .signals.settlement_shadow_status_surface.resolved == false
  and .signals.settlement_shadow_status_surface.source == "unresolved"
  and .signals.settlement_shadow_status_surface.source_field == null
  and .signals.settlement_shadow_status_surface.source_path == null
  and .signals.settlement_shadow_status_surface.fallback == false
  and .signals.settlement_shadow_status_surface.source_priority_index == null
  and (
    if (.signals | has("issuer_admin_blockchain_handlers_coverage")) then
      .signals.issuer_admin_blockchain_handlers_coverage.status == "missing"
      and .signals.issuer_admin_blockchain_handlers_coverage.ok == null
      and .signals.issuer_admin_blockchain_handlers_coverage.resolved == false
      and .signals.issuer_admin_blockchain_handlers_coverage.source == "unresolved"
      and .signals.issuer_admin_blockchain_handlers_coverage.source_field == null
      and .signals.issuer_admin_blockchain_handlers_coverage.source_path == null
      and .signals.issuer_admin_blockchain_handlers_coverage.fallback == false
      and .signals.issuer_admin_blockchain_handlers_coverage.source_priority_index == null
    else true end
  )
' "$MISSING_REPORT_JSON" >/dev/null; then
  echo "phase5 summary report missing-input contract mismatch"
  cat "$MISSING_REPORT_JSON"
  cat "$MISSING_LOG"
  exit 1
fi
assert_default_canonical_report "$MISSING_REPORT_JSON" "$MISSING_LOG" "missing-input path"

mkdir -p "$FALLBACK_REPORTS_DIR"
mkdir -p "$FALLBACK_CI_OLD_DIR" "$FALLBACK_CI_NEW_DIR" "$FALLBACK_HANDOFF_RUN_OLD_DIR" "$FALLBACK_HANDOFF_RUN_NEW_DIR"

cat >"$FALLBACK_CI_OLD_DIR/ci_phase5_settlement_layer_summary.json" <<'EOF_FALLBACK_CI_OLD'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FALLBACK_CI_OLD

cat >"$FALLBACK_CI_NEW_DIR/ci_phase5_settlement_layer_summary.json" <<'EOF_FALLBACK_CI_NEW'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FALLBACK_CI_NEW

cat >"$FALLBACK_HANDOFF_RUN_OLD_DIR/phase5_settlement_layer_handoff_run_summary.json" <<'EOF_FALLBACK_HANDOFF_RUN_OLD'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FALLBACK_HANDOFF_RUN_OLD

cat >"$FALLBACK_HANDOFF_RUN_NEW_DIR/phase5_settlement_layer_handoff_run_summary.json" <<'EOF_FALLBACK_HANDOFF_RUN_NEW'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "phase5_settlement_layer_handoff_check": {
      "artifacts": {
        "summary_json": "phase5_settlement_layer_handoff_check_fallback.json"
      }
    }
  }
}
EOF_FALLBACK_HANDOFF_RUN_NEW

cat >"$FALLBACK_HANDOFF_CHECK_FROM_HANDOFF_RUN" <<'EOF_FALLBACK_HANDOFF_CHECK_FROM_HANDOFF_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "handoff": {
    "settlement_dual_asset_parity_ok": true,
    "settlement_adapter_signed_tx_roundtrip_status": "pass",
    "settlement_adapter_signed_tx_roundtrip_ok": true,
    "settlement_shadow_env_status": "pass",
    "settlement_shadow_env_ok": true,
    "settlement_shadow_status_surface_status": "pass",
    "settlement_shadow_status_surface_ok": true,
    "issuer_sponsor_api_live_smoke_ok": true,
    "issuer_sponsor_vpn_session_live_smoke_ok": true,
    "issuer_settlement_status_live_smoke_ok": true,
    "issuer_admin_blockchain_handlers_coverage_ok": true
  }
}
EOF_FALLBACK_HANDOFF_CHECK_FROM_HANDOFF_RUN

cat >"$FALLBACK_REPORTS_DIR/phase5_settlement_layer_check_summary.json" <<'EOF_FALLBACK_CHECK'
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
    "settlement_dual_asset_parity_ok": false,
    "issuer_sponsor_api_live_smoke_ok": false,
    "issuer_sponsor_vpn_session_live_smoke_ok": false,
    "issuer_admin_blockchain_handlers_coverage_ok": false
  }
}
EOF_FALLBACK_CHECK

cat >"$FALLBACK_REPORTS_DIR/phase5_settlement_layer_run_summary.json" <<'EOF_FALLBACK_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FALLBACK_RUN

cat >"$FALLBACK_REPORTS_DIR/phase5_settlement_layer_handoff_check_summary.json" <<'EOF_FALLBACK_HANDOFF_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FALLBACK_HANDOFF_CHECK

echo "[phase5-settlement-summary-report] fallback discovery path"
"$SCRIPT_UNDER_TEST" \
  --reports-dir "$FALLBACK_REPORTS_DIR" \
  --summary-json "$FALLBACK_REPORT_JSON" \
  --print-summary-json 0 >"$FALLBACK_LOG" 2>&1

if ! jq -e \
  --arg expected_ci_path "$FALLBACK_CI_NEW_DIR/ci_phase5_settlement_layer_summary.json" \
  --arg expected_handoff_run_path "$FALLBACK_HANDOFF_RUN_NEW_DIR/phase5_settlement_layer_handoff_run_summary.json" \
  --arg expected_check_path "$FALLBACK_REPORTS_DIR/phase5_settlement_layer_check_summary.json" \
  --arg expected_run_path "$FALLBACK_REPORTS_DIR/phase5_settlement_layer_run_summary.json" \
  --arg expected_handoff_check_path "$FALLBACK_REPORTS_DIR/phase5_settlement_layer_handoff_check_summary.json" \
  --arg expected_signal_path "$FALLBACK_HANDOFF_CHECK_FROM_HANDOFF_RUN" \
  '
  .status == "pass"
  and .rc == 0
  and .counts.configured == 5
  and .counts.pass == 5
  and .counts.fail == 0
  and .counts.missing == 0
  and .counts.invalid == 0
  and .summaries.ci_phase5_settlement_layer_summary.status == "pass"
  and .summaries.phase5_settlement_layer_handoff_run_summary.status == "pass"
  and .summaries.ci_phase5_settlement_layer_summary.path == $expected_ci_path
  and .summaries.phase5_settlement_layer_handoff_run_summary.path == $expected_handoff_run_path
  and .summaries.phase5_settlement_layer_check_summary.path == $expected_check_path
  and .summaries.phase5_settlement_layer_run_summary.path == $expected_run_path
  and .summaries.phase5_settlement_layer_handoff_check_summary.path == $expected_handoff_check_path
  and .signals.issuer_sponsor_api_live_smoke.status == "pass"
  and .signals.issuer_sponsor_api_live_smoke.ok == true
  and .signals.issuer_sponsor_api_live_smoke.resolved == true
  and .signals.issuer_sponsor_api_live_smoke.source == "phase5_settlement_layer_handoff_run_summary.artifacts.handoff_summary_json"
  and .signals.issuer_sponsor_api_live_smoke.source_field == "handoff.issuer_sponsor_api_live_smoke_ok"
  and .signals.issuer_sponsor_api_live_smoke.source_path == $expected_signal_path
  and .signals.issuer_sponsor_api_live_smoke.fallback == true
  and .signals.issuer_sponsor_api_live_smoke.source_priority_index == 2
  and .signals.issuer_sponsor_vpn_session_live_smoke.status == "pass"
  and .signals.issuer_sponsor_vpn_session_live_smoke.ok == true
  and .signals.issuer_sponsor_vpn_session_live_smoke.resolved == true
  and .signals.issuer_sponsor_vpn_session_live_smoke.source == "phase5_settlement_layer_handoff_run_summary.artifacts.handoff_summary_json"
  and .signals.issuer_sponsor_vpn_session_live_smoke.source_field == "handoff.issuer_sponsor_vpn_session_live_smoke_ok"
  and .signals.issuer_sponsor_vpn_session_live_smoke.source_path == $expected_signal_path
  and .signals.issuer_sponsor_vpn_session_live_smoke.fallback == true
  and .signals.issuer_sponsor_vpn_session_live_smoke.source_priority_index == 2
  and .signals.issuer_settlement_status_live_smoke.status == "pass"
  and .signals.issuer_settlement_status_live_smoke.ok == true
  and .signals.issuer_settlement_status_live_smoke.resolved == true
  and .signals.issuer_settlement_status_live_smoke.source == "phase5_settlement_layer_handoff_run_summary.artifacts.handoff_summary_json"
  and .signals.issuer_settlement_status_live_smoke.source_field == "handoff.issuer_settlement_status_live_smoke_ok"
  and .signals.issuer_settlement_status_live_smoke.source_path == $expected_signal_path
  and .signals.issuer_settlement_status_live_smoke.fallback == true
  and .signals.issuer_settlement_status_live_smoke.source_priority_index == 2
  and .signals.settlement_dual_asset_parity.status == "pass"
  and .signals.settlement_dual_asset_parity.ok == true
  and .signals.settlement_dual_asset_parity.resolved == true
  and .signals.settlement_dual_asset_parity.source == "phase5_settlement_layer_handoff_run_summary.artifacts.handoff_summary_json"
  and .signals.settlement_dual_asset_parity.source_field == "handoff.settlement_dual_asset_parity_ok"
  and .signals.settlement_dual_asset_parity.source_path == $expected_signal_path
  and .signals.settlement_dual_asset_parity.fallback == true
  and .signals.settlement_dual_asset_parity.source_priority_index == 2
  and .signals.settlement_adapter_signed_tx_roundtrip.status == "pass"
  and .signals.settlement_adapter_signed_tx_roundtrip.ok == true
  and .signals.settlement_adapter_signed_tx_roundtrip.resolved == true
  and .signals.settlement_adapter_signed_tx_roundtrip.source == "phase5_settlement_layer_handoff_run_summary.artifacts.handoff_summary_json"
  and .signals.settlement_adapter_signed_tx_roundtrip.source_field == "handoff.settlement_adapter_signed_tx_roundtrip_ok"
  and .signals.settlement_adapter_signed_tx_roundtrip.source_path == $expected_signal_path
  and .signals.settlement_adapter_signed_tx_roundtrip.fallback == true
  and .signals.settlement_adapter_signed_tx_roundtrip.source_priority_index == 2
  and .signals.settlement_shadow_env.status == "pass"
  and .signals.settlement_shadow_env.ok == true
  and .signals.settlement_shadow_env.resolved == true
  and .signals.settlement_shadow_env.source == "phase5_settlement_layer_handoff_run_summary.artifacts.handoff_summary_json"
  and .signals.settlement_shadow_env.source_field == "handoff.settlement_shadow_env_ok"
  and .signals.settlement_shadow_env.source_path == $expected_signal_path
  and .signals.settlement_shadow_env.fallback == true
  and .signals.settlement_shadow_env.source_priority_index == 2
  and .signals.settlement_shadow_status_surface.status == "pass"
  and .signals.settlement_shadow_status_surface.ok == true
  and .signals.settlement_shadow_status_surface.resolved == true
  and .signals.settlement_shadow_status_surface.source == "phase5_settlement_layer_handoff_run_summary.artifacts.handoff_summary_json"
  and .signals.settlement_shadow_status_surface.source_field == "handoff.settlement_shadow_status_surface_ok"
  and .signals.settlement_shadow_status_surface.source_path == $expected_signal_path
  and .signals.settlement_shadow_status_surface.fallback == true
  and .signals.settlement_shadow_status_surface.source_priority_index == 2
  and (
    if (.signals | has("issuer_admin_blockchain_handlers_coverage")) then
      .signals.issuer_admin_blockchain_handlers_coverage.status == "pass"
      and .signals.issuer_admin_blockchain_handlers_coverage.ok == true
      and .signals.issuer_admin_blockchain_handlers_coverage.resolved == true
      and .signals.issuer_admin_blockchain_handlers_coverage.source == "phase5_settlement_layer_handoff_run_summary.artifacts.handoff_summary_json"
      and .signals.issuer_admin_blockchain_handlers_coverage.source_field == "handoff.issuer_admin_blockchain_handlers_coverage_ok"
      and .signals.issuer_admin_blockchain_handlers_coverage.source_path == $expected_signal_path
      and .signals.issuer_admin_blockchain_handlers_coverage.fallback == true
      and .signals.issuer_admin_blockchain_handlers_coverage.source_priority_index == 2
    else true end
  )
' "$FALLBACK_REPORT_JSON" >/dev/null; then
  echo "phase5 summary report fallback-discovery contract mismatch"
  cat "$FALLBACK_REPORT_JSON"
  cat "$FALLBACK_LOG"
  exit 1
fi
assert_default_canonical_report "$FALLBACK_REPORT_JSON" "$FALLBACK_LOG" "fallback discovery path"

mkdir -p "$EMBEDDED_TS_REPORTS_DIR"
mkdir -p "$EMBEDDED_TS_CI_HIGH_TS_OLDER_DIR" "$EMBEDDED_TS_CI_LOW_TS_NEWER_DIR" "$EMBEDDED_TS_CI_INVALID_TS_NEWEST_DIR" "$EMBEDDED_TS_CI_CONFLICT_TS_NEWEST_DIR"

cat >"$EMBEDDED_TS_CI_HIGH_TS_OLDER_DIR/ci_phase5_settlement_layer_summary.json" <<'EOF_EMBEDDED_TS_CI_HIGH_TS'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "generated_at_utc": "2026-04-16T17:30:00Z",
  "status": "pass",
  "rc": 0
}
EOF_EMBEDDED_TS_CI_HIGH_TS

cat >"$EMBEDDED_TS_CI_LOW_TS_NEWER_DIR/ci_phase5_settlement_layer_summary.json" <<'EOF_EMBEDDED_TS_CI_LOW_TS'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "generated_at_utc": "2026-04-16T17:05:00Z",
  "status": "pass",
  "rc": 0
}
EOF_EMBEDDED_TS_CI_LOW_TS

cat >"$EMBEDDED_TS_CI_INVALID_TS_NEWEST_DIR/ci_phase5_settlement_layer_summary.json" <<'EOF_EMBEDDED_TS_CI_INVALID_TS'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "generated_at_utc": "definitely-not-a-utc-timestamp",
  "status": "pass",
  "rc": 0
}
EOF_EMBEDDED_TS_CI_INVALID_TS

cat >"$EMBEDDED_TS_CI_CONFLICT_TS_NEWEST_DIR/ci_phase5_settlement_layer_summary.json" <<'EOF_EMBEDDED_TS_CI_CONFLICT_TS'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "generated_at_utc": "2026-04-16T17:40:00Z",
  "summary_generated_at_utc": "2026-04-16T17:10:00Z",
  "status": "pass",
  "rc": 0
}
EOF_EMBEDDED_TS_CI_CONFLICT_TS

cat >"$EMBEDDED_TS_CHECK" <<'EOF_EMBEDDED_TS_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_EMBEDDED_TS_CHECK

cat >"$EMBEDDED_TS_RUN" <<'EOF_EMBEDDED_TS_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_EMBEDDED_TS_RUN

cat >"$EMBEDDED_TS_HANDOFF_CHECK" <<'EOF_EMBEDDED_TS_HANDOFF_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_EMBEDDED_TS_HANDOFF_CHECK

cat >"$EMBEDDED_TS_HANDOFF_RUN" <<'EOF_EMBEDDED_TS_HANDOFF_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_EMBEDDED_TS_HANDOFF_RUN

echo "[phase5-settlement-summary-report] embedded timestamp precedence with invalid fail-closed path"
"$SCRIPT_UNDER_TEST" \
  --reports-dir "$EMBEDDED_TS_REPORTS_DIR" \
  --summary-json "$EMBEDDED_TS_REPORT_JSON" \
  --print-summary-json 0 >"$EMBEDDED_TS_LOG" 2>&1

if ! jq -e \
  --arg expected_ci_path "$EMBEDDED_TS_CI_HIGH_TS_OLDER_DIR/ci_phase5_settlement_layer_summary.json" \
  --arg rejected_low_ts_path "$EMBEDDED_TS_CI_LOW_TS_NEWER_DIR/ci_phase5_settlement_layer_summary.json" \
  --arg rejected_invalid_ts_path "$EMBEDDED_TS_CI_INVALID_TS_NEWEST_DIR/ci_phase5_settlement_layer_summary.json" \
  --arg rejected_conflict_ts_path "$EMBEDDED_TS_CI_CONFLICT_TS_NEWEST_DIR/ci_phase5_settlement_layer_summary.json" \
  --arg expected_check_path "$EMBEDDED_TS_CHECK" \
  --arg expected_run_path "$EMBEDDED_TS_RUN" \
  --arg expected_handoff_check_path "$EMBEDDED_TS_HANDOFF_CHECK" \
  --arg expected_handoff_run_path "$EMBEDDED_TS_HANDOFF_RUN" \
  '
  .status == "pass"
  and .rc == 0
  and .counts.configured == 5
  and .counts.pass == 5
  and .counts.fail == 0
  and .counts.missing == 0
  and .counts.invalid == 0
  and .summaries.ci_phase5_settlement_layer_summary.path == $expected_ci_path
  and .summaries.ci_phase5_settlement_layer_summary.path != $rejected_low_ts_path
  and .summaries.ci_phase5_settlement_layer_summary.path != $rejected_invalid_ts_path
  and .summaries.ci_phase5_settlement_layer_summary.path != $rejected_conflict_ts_path
  and .summaries.phase5_settlement_layer_check_summary.path == $expected_check_path
  and .summaries.phase5_settlement_layer_run_summary.path == $expected_run_path
  and .summaries.phase5_settlement_layer_handoff_check_summary.path == $expected_handoff_check_path
  and .summaries.phase5_settlement_layer_handoff_run_summary.path == $expected_handoff_run_path
' "$EMBEDDED_TS_REPORT_JSON" >/dev/null; then
  echo "phase5 summary report embedded timestamp precedence/invalid fail-closed mismatch"
  cat "$EMBEDDED_TS_REPORT_JSON"
  cat "$EMBEDDED_TS_LOG"
  exit 1
fi
assert_default_canonical_report "$EMBEDDED_TS_REPORT_JSON" "$EMBEDDED_TS_LOG" "embedded timestamp precedence path"

echo "phase5 settlement layer summary report integration ok"
