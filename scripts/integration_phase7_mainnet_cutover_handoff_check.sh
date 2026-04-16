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

SCRIPT_UNDER_TEST="${PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase7_mainnet_cutover_handoff_check.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS_RUN="$TMP_DIR/run_pass.json"
PASS_CHECK="$TMP_DIR/check_pass.json"
PASS_REPORT="$TMP_DIR/report_pass.json"
PASS_OUTPUT="$TMP_DIR/output_pass.json"
PASS_CANONICAL="$TMP_DIR/output_pass_canonical.json"
PASS_LOG="$TMP_DIR/pass.log"

FAIL_RUN="$TMP_DIR/run_fail_auth.json"
FAIL_OUTPUT="$TMP_DIR/output_fail.json"
FAIL_CANONICAL="$TMP_DIR/output_fail_canonical.json"
FAIL_LOG="$TMP_DIR/fail.log"

RELAXED_OUTPUT="$TMP_DIR/output_relaxed.json"
RELAXED_CANONICAL="$TMP_DIR/output_relaxed_canonical.json"
RELAXED_LOG="$TMP_DIR/relaxed.log"

MISSING_REPORT_PATH="$TMP_DIR/missing_report.json"
MISSING_REPORT_OUTPUT="$TMP_DIR/output_missing_report.json"
MISSING_REPORT_LOG="$TMP_DIR/missing_report.log"

MISSING_REPORT_RELAXED_OUTPUT="$TMP_DIR/output_missing_report_relaxed.json"
MISSING_REPORT_RELAXED_CANONICAL="$TMP_DIR/output_missing_report_relaxed_canonical.json"
MISSING_REPORT_RELAXED_LOG="$TMP_DIR/missing_report_relaxed.log"

cat >"$PASS_RUN" <<'EOF_PASS_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "phase7_mainnet_cutover_check": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "signal_snapshot": {
        "module_tx_surface_ok": true,
        "tdpnd_grpc_runtime_smoke_ok": true,
        "tdpnd_grpc_live_smoke_ok": true,
        "tdpnd_grpc_auth_live_smoke_ok": true,
        "dual_write_parity_ok": true,
        "rollback_path_ready": true,
        "operator_approval_ok": true
      }
    }
  }
}
EOF_PASS_RUN

cat >"$PASS_CHECK" <<'EOF_PASS_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "signals": {
    "module_tx_surface_ok": true,
    "tdpnd_grpc_runtime_smoke_ok": true,
    "tdpnd_grpc_live_smoke_ok": true,
    "tdpnd_grpc_auth_live_smoke_ok": true,
    "dual_write_parity_ok": true,
    "rollback_path_ready": true,
    "operator_approval_ok": true
  }
}
EOF_PASS_CHECK

cat >"$PASS_REPORT" <<'EOF_PASS_REPORT'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_summary_report",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "summaries": {
    "check": {
      "status": "pass"
    },
    "run": {
      "status": "pass"
    }
  }
}
EOF_PASS_REPORT

cat >"$FAIL_RUN" <<'EOF_FAIL_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "phase7_mainnet_cutover_check": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "signal_snapshot": {
        "module_tx_surface_ok": true,
        "tdpnd_grpc_runtime_smoke_ok": true,
        "tdpnd_grpc_live_smoke_ok": true,
        "tdpnd_grpc_auth_live_smoke_ok": false,
        "dual_write_parity_ok": true,
        "rollback_path_ready": true,
        "operator_approval_ok": true
      }
    }
  }
}
EOF_FAIL_RUN

echo "[phase7-mainnet-cutover-handoff-check] pass path"
PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_CANONICAL_SUMMARY_JSON="$PASS_CANONICAL" \
bash "$SCRIPT_UNDER_TEST" \
  --phase7-run-summary-json "$PASS_RUN" \
  --phase7-check-summary-json "$PASS_CHECK" \
  --phase7-summary-report-json "$PASS_REPORT" \
  --summary-json "$PASS_OUTPUT" \
  --show-json 0 >"$PASS_LOG" 2>&1

if [[ ! -f "$PASS_CANONICAL" ]]; then
  echo "missing canonical summary on pass path: $PASS_CANONICAL"
  cat "$PASS_LOG"
  exit 1
fi
if ! jq -e '
  .version == 1
  and .schema.id == "phase7_mainnet_cutover_handoff_check_summary"
  and .status == "pass"
  and .rc == 0
  and .fail_closed == true
  and .handoff.run_pipeline_ok == true
  and .handoff.summary_report_ok == true
  and .handoff.module_tx_surface_ok == true
  and .handoff.tdpnd_grpc_auth_live_smoke_ok == true
  and .handoff.dual_write_parity_ok == true
  and .handoff.rollback_path_ready == true
  and .handoff.operator_approval_ok == true
  and .inputs.provided.phase7_check_summary_json == true
  and .inputs.usable.phase7_check_summary_json == true
  and .artifacts.canonical_summary_json == $expected_canonical
' --arg expected_canonical "$PASS_CANONICAL" "$PASS_OUTPUT" >/dev/null; then
  echo "pass-path summary mismatch"
  cat "$PASS_OUTPUT"
  cat "$PASS_LOG"
  exit 1
fi
if ! cmp -s "$PASS_OUTPUT" "$PASS_CANONICAL"; then
  echo "pass-path canonical summary diverges from run summary"
  cat "$PASS_OUTPUT"
  cat "$PASS_CANONICAL"
  exit 1
fi

echo "[phase7-mainnet-cutover-handoff-check] fail-closed signal path"
set +e
PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_CANONICAL_SUMMARY_JSON="$FAIL_CANONICAL" \
bash "$SCRIPT_UNDER_TEST" \
  --phase7-run-summary-json "$FAIL_RUN" \
  --phase7-summary-report-json "$PASS_REPORT" \
  --summary-json "$FAIL_OUTPUT" \
  --show-json 0 >"$FAIL_LOG" 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for fail-closed signal path, got rc=$fail_rc"
  cat "$FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .handoff.tdpnd_grpc_auth_live_smoke_ok == false
  and .handoff.tdpnd_grpc_auth_live_smoke_status == "fail"
  and ((.decision.reasons // []) | any(test("tdpnd_grpc_auth_live_smoke_ok is false")))
' "$FAIL_OUTPUT" >/dev/null; then
  echo "fail-path summary mismatch"
  cat "$FAIL_OUTPUT"
  cat "$FAIL_LOG"
  exit 1
fi
if [[ ! -f "$FAIL_CANONICAL" ]]; then
  echo "missing canonical summary on fail path: $FAIL_CANONICAL"
  cat "$FAIL_LOG"
  exit 1
fi
if ! cmp -s "$FAIL_OUTPUT" "$FAIL_CANONICAL"; then
  echo "fail-path canonical summary diverges from run summary"
  cat "$FAIL_OUTPUT"
  cat "$FAIL_CANONICAL"
  exit 1
fi

echo "[phase7-mainnet-cutover-handoff-check] relaxed requirement toggle path"
PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_CANONICAL_SUMMARY_JSON="$RELAXED_CANONICAL" \
bash "$SCRIPT_UNDER_TEST" \
  --phase7-run-summary-json "$FAIL_RUN" \
  --phase7-summary-report-json "$PASS_REPORT" \
  --summary-json "$RELAXED_OUTPUT" \
  --require-tdpnd-grpc-auth-live-smoke-ok 0 \
  --show-json 0 >"$RELAXED_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.requirements.tdpnd_grpc_auth_live_smoke_ok == false
  and .handoff.tdpnd_grpc_auth_live_smoke_ok == false
  and .handoff.tdpnd_grpc_auth_live_smoke_status == "fail"
' "$RELAXED_OUTPUT" >/dev/null; then
  echo "relaxed-path summary mismatch"
  cat "$RELAXED_OUTPUT"
  cat "$RELAXED_LOG"
  exit 1
fi
if [[ ! -f "$RELAXED_CANONICAL" ]]; then
  echo "missing canonical summary on relaxed path: $RELAXED_CANONICAL"
  cat "$RELAXED_LOG"
  exit 1
fi
if ! cmp -s "$RELAXED_OUTPUT" "$RELAXED_CANONICAL"; then
  echo "relaxed-path canonical summary diverges from run summary"
  cat "$RELAXED_OUTPUT"
  cat "$RELAXED_CANONICAL"
  exit 1
fi

echo "[phase7-mainnet-cutover-handoff-check] missing summary-report path"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --phase7-run-summary-json "$PASS_RUN" \
  --phase7-summary-report-json "$MISSING_REPORT_PATH" \
  --summary-json "$MISSING_REPORT_OUTPUT" \
  --show-json 0 >"$MISSING_REPORT_LOG" 2>&1
missing_report_rc=$?
set -e
if [[ "$missing_report_rc" -ne 1 ]]; then
  echo "expected rc=1 for missing summary-report path, got rc=$missing_report_rc"
  cat "$MISSING_REPORT_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .handoff.summary_report_status == "missing"
  and ((.decision.reasons // []) | any(test("summary_report_ok unresolved")))
' "$MISSING_REPORT_OUTPUT" >/dev/null; then
  echo "missing-report summary mismatch"
  cat "$MISSING_REPORT_OUTPUT"
  cat "$MISSING_REPORT_LOG"
  exit 1
fi

echo "[phase7-mainnet-cutover-handoff-check] missing summary-report relaxed requirement path"
PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_CANONICAL_SUMMARY_JSON="$MISSING_REPORT_RELAXED_CANONICAL" \
bash "$SCRIPT_UNDER_TEST" \
  --phase7-run-summary-json "$PASS_RUN" \
  --phase7-summary-report-json "$MISSING_REPORT_PATH" \
  --summary-json "$MISSING_REPORT_RELAXED_OUTPUT" \
  --require-summary-report-ok 0 \
  --show-json 0 >"$MISSING_REPORT_RELAXED_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.requirements.summary_report_ok == false
  and .handoff.summary_report_status == "missing"
' "$MISSING_REPORT_RELAXED_OUTPUT" >/dev/null; then
  echo "missing-report-relaxed summary mismatch"
  cat "$MISSING_REPORT_RELAXED_OUTPUT"
  cat "$MISSING_REPORT_RELAXED_LOG"
  exit 1
fi
if [[ ! -f "$MISSING_REPORT_RELAXED_CANONICAL" ]]; then
  echo "missing canonical summary on missing-report-relaxed path: $MISSING_REPORT_RELAXED_CANONICAL"
  cat "$MISSING_REPORT_RELAXED_LOG"
  exit 1
fi
if ! cmp -s "$MISSING_REPORT_RELAXED_OUTPUT" "$MISSING_REPORT_RELAXED_CANONICAL"; then
  echo "missing-report-relaxed canonical summary diverges from run summary"
  cat "$MISSING_REPORT_RELAXED_OUTPUT"
  cat "$MISSING_REPORT_RELAXED_CANONICAL"
  exit 1
fi

echo "phase7 mainnet cutover handoff check integration ok"
