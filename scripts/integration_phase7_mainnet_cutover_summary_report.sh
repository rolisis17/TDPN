#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod grep cat cmp touch; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase7_mainnet_cutover_summary_report.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS_CHECK="$TMP_DIR/check_pass.json"
PASS_RUN="$TMP_DIR/run_pass.json"
PASS_HANDOFF_CHECK="$TMP_DIR/handoff_check_pass.json"
PASS_HANDOFF_RUN="$TMP_DIR/handoff_run_pass.json"
PASS_REPORT_JSON="$TMP_DIR/report_pass.json"
PASS_CANONICAL_REPORT_JSON="$TMP_DIR/report_pass_canonical.json"
PASS_LOG="$TMP_DIR/pass.log"
PASS_SAME_PATH_REPORT_JSON="$TMP_DIR/report_pass_same_path.json"
PASS_SAME_PATH_LOG="$TMP_DIR/pass_same_path.log"

ALIAS_CHECK="$TMP_DIR/check_alias.json"
ALIAS_RUN="$TMP_DIR/run_alias.json"
ALIAS_HANDOFF_CHECK="$TMP_DIR/handoff_check_alias.json"
ALIAS_HANDOFF_RUN="$TMP_DIR/handoff_run_alias.json"
ALIAS_REPORT_JSON="$TMP_DIR/report_alias.json"
ALIAS_CANONICAL_REPORT_JSON="$TMP_DIR/report_alias_canonical.json"
ALIAS_LOG="$TMP_DIR/alias.log"

FAIL_CHECK="$TMP_DIR/check_fail_case.json"
FAIL_RUN="$TMP_DIR/run_fail_case.json"
FAIL_HANDOFF_CHECK="$TMP_DIR/handoff_check_fail_case.json"
FAIL_HANDOFF_RUN="$TMP_DIR/handoff_run_fail_case.json"
FAIL_REPORT_JSON="$TMP_DIR/report_fail.json"
FAIL_CANONICAL_REPORT_JSON="$TMP_DIR/report_fail_canonical.json"
FAIL_LOG="$TMP_DIR/fail.log"

MISSING_REPORT_JSON="$TMP_DIR/report_missing.json"
MISSING_CANONICAL_REPORT_JSON="$TMP_DIR/report_missing_canonical.json"
MISSING_LOG="$TMP_DIR/missing.log"
MISSING_PATH="$TMP_DIR/does_not_exist.json"

FALLBACK_REPORTS_DIR="$TMP_DIR/fallback_reports"
FALLBACK_REPORT_JSON="$TMP_DIR/report_fallback.json"
FALLBACK_CANONICAL_REPORT_JSON="$TMP_DIR/report_fallback_canonical.json"
FALLBACK_LOG="$TMP_DIR/fallback.log"

FALLBACK_CHECK_OLD_DIR="$FALLBACK_REPORTS_DIR/phase7_mainnet_cutover_check_20260415_165959"
FALLBACK_CHECK_NEW_DIR="$FALLBACK_REPORTS_DIR/phase7_mainnet_cutover_check_20260415_170000"
FALLBACK_RUN_OLD_DIR="$FALLBACK_REPORTS_DIR/phase7_mainnet_cutover_run_20260415_170100"
FALLBACK_RUN_NEW_DIR="$FALLBACK_REPORTS_DIR/phase7_mainnet_cutover_run_20260415_170300"
FALLBACK_HANDOFF_CHECK_OLD_DIR="$FALLBACK_REPORTS_DIR/phase7_mainnet_cutover_handoff_check_20260415_170400"
FALLBACK_HANDOFF_CHECK_NEW_DIR="$FALLBACK_REPORTS_DIR/phase7_mainnet_cutover_handoff_check_20260415_170500"
FALLBACK_HANDOFF_RUN_OLD_DIR="$FALLBACK_REPORTS_DIR/phase7_mainnet_cutover_handoff_run_20260415_170600"
FALLBACK_HANDOFF_RUN_NEW_DIR="$FALLBACK_REPORTS_DIR/phase7_mainnet_cutover_handoff_run_20260415_170700"

EMBEDDED_INVALID_REPORTS_DIR="$TMP_DIR/embedded_invalid_reports"
EMBEDDED_INVALID_REPORT_JSON="$TMP_DIR/report_embedded_invalid.json"
EMBEDDED_INVALID_CANONICAL_REPORT_JSON="$TMP_DIR/report_embedded_invalid_canonical.json"
EMBEDDED_INVALID_LOG="$TMP_DIR/embedded_invalid.log"
EMBEDDED_INVALID_CHECK_OLDER_DIR="$EMBEDDED_INVALID_REPORTS_DIR/phase7_mainnet_cutover_check_20260415_175900"
EMBEDDED_INVALID_CHECK_INVALID_NEWER_DIR="$EMBEDDED_INVALID_REPORTS_DIR/phase7_mainnet_cutover_check_20260415_180000"
EMBEDDED_INVALID_RUN_DEFAULT="$EMBEDDED_INVALID_REPORTS_DIR/phase7_mainnet_cutover_run_summary.json"
EMBEDDED_INVALID_HANDOFF_CHECK_DEFAULT="$EMBEDDED_INVALID_REPORTS_DIR/phase7_mainnet_cutover_handoff_check_summary.json"
EMBEDDED_INVALID_HANDOFF_RUN_DEFAULT="$EMBEDDED_INVALID_REPORTS_DIR/phase7_mainnet_cutover_handoff_run_summary.json"

EMBEDDED_VALID_REPORTS_DIR="$TMP_DIR/embedded_valid_reports"
EMBEDDED_VALID_REPORT_JSON="$TMP_DIR/report_embedded_valid.json"
EMBEDDED_VALID_CANONICAL_REPORT_JSON="$TMP_DIR/report_embedded_valid_canonical.json"
EMBEDDED_VALID_LOG="$TMP_DIR/embedded_valid.log"
EMBEDDED_VALID_CHECK_NEWER_MTIME_OLDER_TS_DIR="$EMBEDDED_VALID_REPORTS_DIR/phase7_mainnet_cutover_check_20260415_180100"
EMBEDDED_VALID_CHECK_OLDER_MTIME_NEWER_TS_DIR="$EMBEDDED_VALID_REPORTS_DIR/phase7_mainnet_cutover_check_20260415_180200"
EMBEDDED_VALID_RUN_DEFAULT="$EMBEDDED_VALID_REPORTS_DIR/phase7_mainnet_cutover_run_summary.json"
EMBEDDED_VALID_HANDOFF_CHECK_DEFAULT="$EMBEDDED_VALID_REPORTS_DIR/phase7_mainnet_cutover_handoff_check_summary.json"
EMBEDDED_VALID_HANDOFF_RUN_DEFAULT="$EMBEDDED_VALID_REPORTS_DIR/phase7_mainnet_cutover_handoff_run_summary.json"

assert_canonical_path_hygiene() {
  local summary_json="${1:?summary json required}"
  local expected_canonical="${2:?expected canonical path required}"
  local label="${3:?label required}"

  if [[ "$expected_canonical" != "$TMP_DIR/"* ]]; then
    echo "$label canonical path is not under TMP_DIR: $expected_canonical"
    cat "$summary_json"
    exit 1
  fi
  if [[ "$expected_canonical" == *".easy-node-logs"* ]]; then
    echo "$label canonical path unexpectedly points to .easy-node-logs: $expected_canonical"
    cat "$summary_json"
    exit 1
  fi
  if ! jq -e \
    --arg expected "$expected_canonical" \
    --arg tmp_prefix "$TMP_DIR/" \
    '
    .artifacts.canonical_summary_json == $expected
    and (.artifacts.canonical_summary_json | startswith($tmp_prefix))
    and ((.artifacts.canonical_summary_json | contains(".easy-node-logs")) | not)
  ' "$summary_json" >/dev/null; then
    echo "$label canonical summary artifact path hygiene check failed"
    cat "$summary_json"
    exit 1
  fi
}

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
    "module_tx_surface": true,
    "tdpnd_grpc_live_smoke": true,
    "tdpnd_grpc_auth_live_smoke": true,
    "tdpnd_comet_runtime_smoke_ok": true,
    "mainnet_activation_gate_go": true,
    "bootstrap_governance_graduation_gate_go": true,
    "cosmos_module_coverage_floor_ok": true,
    "cosmos_keeper_coverage_floor_ok": true,
    "cosmos_app_coverage_floor_ok": true,
    "rollback_path_ready": true,
    "operator_approval_ok": true
  }
}
EOF_PASS_CHECK

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
      "signal_snapshot": {
        "module_tx_surface_ok": true,
        "tdpnd_grpc_live_smoke_ok": true,
        "tdpnd_grpc_auth_live_smoke_ok": true,
        "tdpnd_comet_runtime_smoke_ok": true,
        "mainnet_activation_gate_go": true,
        "bootstrap_governance_graduation_gate_go": true,
        "dual_write_parity_ok": true,
        "cosmos_module_coverage_floor_ok": true,
        "cosmos_keeper_coverage_floor_ok": true,
        "cosmos_app_coverage_floor_ok": true,
        "rollback_path_ready": true,
        "operator_approval_ok": true
      }
    }
  }
}
EOF_PASS_RUN

cat >"$PASS_HANDOFF_CHECK" <<'EOF_PASS_HANDOFF_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "handoff": {
    "module_tx_surface_ok": true,
    "tdpnd_grpc_live_smoke_ok": true,
    "tdpnd_grpc_auth_live_smoke_ok": true,
    "tdpnd_comet_runtime_smoke_ok": true,
    "mainnet_activation_gate_go": true,
    "bootstrap_governance_graduation_gate_go": true,
    "dual_write_parity_ok": true,
    "cosmos_module_coverage_floor_ok": true,
    "cosmos_keeper_coverage_floor_ok": true,
    "cosmos_app_coverage_floor_ok": true,
    "rollback_path_ready": true,
    "operator_approval_ok": true
  }
}
EOF_PASS_HANDOFF_CHECK

cat >"$PASS_HANDOFF_RUN" <<'EOF_PASS_HANDOFF_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "handoff": {
    "module_tx_surface_ok": true,
    "tdpnd_grpc_live_smoke_ok": true,
    "tdpnd_grpc_auth_live_smoke_ok": true,
    "tdpnd_comet_runtime_smoke_ok": true,
    "mainnet_activation_gate_go": true,
    "bootstrap_governance_graduation_gate_go": true,
    "dual_write_parity_ok": true,
    "cosmos_module_coverage_floor_ok": true,
    "cosmos_keeper_coverage_floor_ok": true,
    "cosmos_app_coverage_floor_ok": true,
    "rollback_path_ready": true,
    "operator_approval_ok": true
  }
}
EOF_PASS_HANDOFF_RUN

echo "[phase7-mainnet-cutover-summary-report] pass path"
if ! jq -e '
  .signals.module_tx_surface == true
  and .signals.tdpnd_grpc_live_smoke == true
  and .signals.tdpnd_grpc_auth_live_smoke == true
  and .signals.mainnet_activation_gate_go == true
  and .signals.bootstrap_governance_graduation_gate_go == true
  and .signals.cosmos_module_coverage_floor_ok == true
  and .signals.cosmos_keeper_coverage_floor_ok == true
  and .signals.cosmos_app_coverage_floor_ok == true
  and .signals.rollback_path_ready == true
  and .signals.operator_approval_ok == true
' "$PASS_CHECK" >/dev/null; then
  echo "pass check fixture missing required phase7 signal assertions"
  cat "$PASS_CHECK"
  exit 1
fi
if ! jq -e '
  .steps.phase7_mainnet_cutover_check.signal_snapshot.module_tx_surface_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_grpc_live_smoke_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.mainnet_activation_gate_go == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.bootstrap_governance_graduation_gate_go == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.dual_write_parity_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.cosmos_module_coverage_floor_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.cosmos_keeper_coverage_floor_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.cosmos_app_coverage_floor_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.rollback_path_ready == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.operator_approval_ok == true
' "$PASS_RUN" >/dev/null; then
  echo "pass run fixture missing required phase7 signal snapshot assertions"
  cat "$PASS_RUN"
  exit 1
fi
if ! jq -e '.handoff.module_tx_surface_ok == true and .handoff.tdpnd_grpc_live_smoke_ok == true and .handoff.tdpnd_grpc_auth_live_smoke_ok == true and .handoff.mainnet_activation_gate_go == true and .handoff.bootstrap_governance_graduation_gate_go == true and .handoff.cosmos_module_coverage_floor_ok == true and .handoff.cosmos_keeper_coverage_floor_ok == true and .handoff.cosmos_app_coverage_floor_ok == true' "$PASS_HANDOFF_CHECK" >/dev/null; then
  echo "pass handoff-check fixture missing required mainnet activation gate signal assertion"
  cat "$PASS_HANDOFF_CHECK"
  exit 1
fi
if ! jq -e '.handoff.module_tx_surface_ok == true and .handoff.tdpnd_grpc_live_smoke_ok == true and .handoff.tdpnd_grpc_auth_live_smoke_ok == true and .handoff.mainnet_activation_gate_go == true and .handoff.bootstrap_governance_graduation_gate_go == true and .handoff.cosmos_module_coverage_floor_ok == true and .handoff.cosmos_keeper_coverage_floor_ok == true and .handoff.cosmos_app_coverage_floor_ok == true' "$PASS_HANDOFF_RUN" >/dev/null; then
  echo "pass handoff-run fixture missing required mainnet activation gate signal assertion"
  cat "$PASS_HANDOFF_RUN"
  exit 1
fi
PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_CANONICAL_SUMMARY_JSON="$PASS_CANONICAL_REPORT_JSON" \
bash "$SCRIPT_UNDER_TEST" \
  --check-summary-json "$PASS_CHECK" \
  --run-summary-json "$PASS_RUN" \
  --handoff-check-summary-json "$PASS_HANDOFF_CHECK" \
  --handoff-run-summary-json "$PASS_HANDOFF_RUN" \
  --summary-json "$PASS_REPORT_JSON" \
  --print-report 1 \
  --show-json 0 >"$PASS_LOG" 2>&1

if ! jq -e \
  --arg expected_summary "$PASS_REPORT_JSON" \
  --arg expected_canonical "$PASS_CANONICAL_REPORT_JSON" \
  '
  .version == 1
  and .schema.id == "phase7_mainnet_cutover_summary_report"
  and .status == "pass"
  and .rc == 0
  and .counts.configured == 4
  and .counts.pass == 4
  and .counts.fail == 0
  and .counts.missing == 0
  and .counts.invalid == 0
  and .signals.cosmos_module_coverage_floor_ok == true
  and .signals.cosmos_keeper_coverage_floor_ok == true
  and .signals.cosmos_app_coverage_floor_ok == true
  and .signals.dual_write_parity_ok == true
  and .signals.mainnet_activation_gate_go_ok == true
  and .signals.bootstrap_governance_graduation_gate_go_ok == true
  and .signals.module_tx_surface_ok == true
  and .signals.tdpnd_grpc_live_smoke_ok == true
  and .signals.tdpnd_grpc_auth_live_smoke_ok == true
  and .signals.tdpnd_comet_runtime_smoke_ok == true
  and .summaries.check.status == "pass"
  and .summaries.check.source_kind == "explicit"
  and .summaries.check.signal_snapshot.module_tx_surface == true
  and .summaries.check.signal_snapshot.tdpnd_grpc_live_smoke == true
  and .summaries.check.signal_snapshot.tdpnd_grpc_auth_live_smoke == true
  and .summaries.check.signal_snapshot.tdpnd_comet_runtime_smoke_ok == true
  and .summaries.check.signal_snapshot.mainnet_activation_gate_go == true
  and .summaries.check.signal_snapshot.bootstrap_governance_graduation_gate_go == true
  and .summaries.check.signal_snapshot.cosmos_module_coverage_floor_ok == true
  and .summaries.check.signal_snapshot.cosmos_keeper_coverage_floor_ok == true
  and .summaries.check.signal_snapshot.cosmos_app_coverage_floor_ok == true
  and .summaries.run.status == "pass"
  and .summaries.run.source_kind == "explicit"
  and .summaries.run.signal_snapshot.module_tx_surface_ok == true
  and .summaries.run.signal_snapshot.tdpnd_grpc_live_smoke_ok == true
  and .summaries.run.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok == true
  and .summaries.run.signal_snapshot.tdpnd_comet_runtime_smoke_ok == true
  and .summaries.run.signal_snapshot.mainnet_activation_gate_go == true
  and .summaries.run.signal_snapshot.bootstrap_governance_graduation_gate_go == true
  and .summaries.run.signal_snapshot.cosmos_module_coverage_floor_ok == true
  and .summaries.run.signal_snapshot.cosmos_keeper_coverage_floor_ok == true
  and .summaries.run.signal_snapshot.cosmos_app_coverage_floor_ok == true
  and .summaries.handoff_check.status == "pass"
  and .summaries.handoff_check.source_kind == "explicit"
  and .summaries.handoff_check.signal_snapshot.module_tx_surface_ok == true
  and .summaries.handoff_check.signal_snapshot.tdpnd_grpc_live_smoke_ok == true
  and .summaries.handoff_check.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok == true
  and .summaries.handoff_check.signal_snapshot.tdpnd_comet_runtime_smoke_ok == true
  and .summaries.handoff_check.signal_snapshot.mainnet_activation_gate_go == true
  and .summaries.handoff_check.signal_snapshot.bootstrap_governance_graduation_gate_go == true
  and .summaries.handoff_check.signal_snapshot.cosmos_module_coverage_floor_ok == true
  and .summaries.handoff_check.signal_snapshot.cosmos_keeper_coverage_floor_ok == true
  and .summaries.handoff_check.signal_snapshot.cosmos_app_coverage_floor_ok == true
  and .summaries.handoff_run.status == "pass"
  and .summaries.handoff_run.source_kind == "explicit"
  and .summaries.handoff_run.signal_snapshot.module_tx_surface_ok == true
  and .summaries.handoff_run.signal_snapshot.tdpnd_grpc_live_smoke_ok == true
  and .summaries.handoff_run.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok == true
  and .summaries.handoff_run.signal_snapshot.tdpnd_comet_runtime_smoke_ok == true
  and .summaries.handoff_run.signal_snapshot.mainnet_activation_gate_go == true
  and .summaries.handoff_run.signal_snapshot.bootstrap_governance_graduation_gate_go == true
  and .summaries.handoff_run.signal_snapshot.cosmos_module_coverage_floor_ok == true
  and .summaries.handoff_run.signal_snapshot.cosmos_keeper_coverage_floor_ok == true
  and .summaries.handoff_run.signal_snapshot.cosmos_app_coverage_floor_ok == true
  and .artifacts.summary_json == $expected_summary
  and .artifacts.canonical_summary_json == $expected_canonical
' "$PASS_REPORT_JSON" >/dev/null; then
  echo "phase7 summary report pass-path contract mismatch"
  cat "$PASS_REPORT_JSON"
  cat "$PASS_LOG"
  exit 1
fi

if [[ ! -f "$PASS_CANONICAL_REPORT_JSON" ]]; then
  echo "missing pass canonical summary report: $PASS_CANONICAL_REPORT_JSON"
  cat "$PASS_LOG"
  exit 1
fi
if ! cmp -s "$PASS_REPORT_JSON" "$PASS_CANONICAL_REPORT_JSON"; then
  echo "pass summary and canonical summary mismatch"
  cat "$PASS_REPORT_JSON"
  cat "$PASS_CANONICAL_REPORT_JSON"
  exit 1
fi
assert_canonical_path_hygiene "$PASS_REPORT_JSON" "$PASS_CANONICAL_REPORT_JSON" "pass-path"
if ! grep -Fq -- "[phase7-summary] canonical_summary_json=$PASS_CANONICAL_REPORT_JSON" "$PASS_LOG"; then
  echo "pass log missing canonical summary line"
  cat "$PASS_LOG"
  exit 1
fi
if ! grep -Fq -- "[phase7-summary] handoff_check: status=pass" "$PASS_LOG"; then
  echo "pass log missing handoff_check line"
  cat "$PASS_LOG"
  exit 1
fi
if ! grep -Fq -- "[phase7-summary] handoff_run: status=pass" "$PASS_LOG"; then
  echo "pass log missing handoff_run line"
  cat "$PASS_LOG"
  exit 1
fi

echo "[phase7-mainnet-cutover-summary-report] canonical-same-path pass path"
PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_CANONICAL_SUMMARY_JSON="$PASS_SAME_PATH_REPORT_JSON" \
bash "$SCRIPT_UNDER_TEST" \
  --check-summary-json "$PASS_CHECK" \
  --run-summary-json "$PASS_RUN" \
  --handoff-check-summary-json "$PASS_HANDOFF_CHECK" \
  --handoff-run-summary-json "$PASS_HANDOFF_RUN" \
  --summary-json "$PASS_SAME_PATH_REPORT_JSON" \
  --print-report 1 \
  --show-json 0 >"$PASS_SAME_PATH_LOG" 2>&1

if ! jq -e \
  --arg expected_same_path "$PASS_SAME_PATH_REPORT_JSON" \
  '
  .status == "pass"
  and .rc == 0
  and .artifacts.summary_json == $expected_same_path
  and .artifacts.canonical_summary_json == $expected_same_path
  and .artifacts.summary_json == .artifacts.canonical_summary_json
  and .signals.cosmos_module_coverage_floor_ok == true
  and .signals.cosmos_keeper_coverage_floor_ok == true
  and .signals.cosmos_app_coverage_floor_ok == true
  and .signals.dual_write_parity_ok == true
  and .signals.mainnet_activation_gate_go_ok == true
  and .signals.bootstrap_governance_graduation_gate_go_ok == true
  and .signals.module_tx_surface_ok == true
  and .signals.tdpnd_grpc_live_smoke_ok == true
  and .signals.tdpnd_grpc_auth_live_smoke_ok == true
  and .summaries.check.signal_snapshot.module_tx_surface == true
  and .summaries.check.signal_snapshot.tdpnd_grpc_live_smoke == true
  and .summaries.check.signal_snapshot.tdpnd_grpc_auth_live_smoke == true
  and .summaries.check.signal_snapshot.mainnet_activation_gate_go == true
  and .summaries.check.signal_snapshot.bootstrap_governance_graduation_gate_go == true
  and .summaries.run.signal_snapshot.module_tx_surface_ok == true
  and .summaries.run.signal_snapshot.tdpnd_grpc_live_smoke_ok == true
  and .summaries.run.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok == true
  and .summaries.run.signal_snapshot.mainnet_activation_gate_go == true
  and .summaries.run.signal_snapshot.bootstrap_governance_graduation_gate_go == true
  and .summaries.handoff_check.signal_snapshot.module_tx_surface_ok == true
  and .summaries.handoff_check.signal_snapshot.tdpnd_grpc_live_smoke_ok == true
  and .summaries.handoff_check.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok == true
  and .summaries.handoff_check.signal_snapshot.mainnet_activation_gate_go == true
  and .summaries.handoff_check.signal_snapshot.bootstrap_governance_graduation_gate_go == true
  and .summaries.handoff_run.signal_snapshot.module_tx_surface_ok == true
  and .summaries.handoff_run.signal_snapshot.tdpnd_grpc_live_smoke_ok == true
  and .summaries.handoff_run.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok == true
  and .summaries.handoff_run.signal_snapshot.mainnet_activation_gate_go == true
  and .summaries.handoff_run.signal_snapshot.bootstrap_governance_graduation_gate_go == true
  and .summaries.handoff_check.status == "pass"
  and .summaries.handoff_run.status == "pass"
' "$PASS_SAME_PATH_REPORT_JSON" >/dev/null; then
  echo "phase7 summary report canonical-same-path contract mismatch"
  cat "$PASS_SAME_PATH_REPORT_JSON"
  cat "$PASS_SAME_PATH_LOG"
  exit 1
fi
if ! grep -Fq -- "[phase7-summary] canonical_summary_json=$PASS_SAME_PATH_REPORT_JSON" "$PASS_SAME_PATH_LOG"; then
  echo "canonical-same-path log missing canonical summary line"
  cat "$PASS_SAME_PATH_LOG"
  exit 1
fi
assert_canonical_path_hygiene "$PASS_SAME_PATH_REPORT_JSON" "$PASS_SAME_PATH_REPORT_JSON" "canonical-same-path"

cat >"$ALIAS_CHECK" <<'EOF_ALIAS_CHECK'
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
    "module_tx_surface": true,
    "tdpnd_grpc_live_smoke": true,
    "tdpnd_grpc_auth_live_smoke": true
  }
}
EOF_ALIAS_CHECK

cat >"$ALIAS_RUN" <<'EOF_ALIAS_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "cosmos_module_coverage_floor": true,
  "cosmos_keeper_coverage_floor_ok": true,
  "mainnet_activation_gate_go": true,
  "tdpnd_comet_runtime_smoke": true
}
EOF_ALIAS_RUN

cat >"$ALIAS_HANDOFF_CHECK" <<'EOF_ALIAS_HANDOFF_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "handoff": {
    "cosmos_app_coverage_floor": true,
    "bootstrap_governance_graduation_gate_go_ok": true,
    "dual_write_parity": true
  }
}
EOF_ALIAS_HANDOFF_CHECK

cat >"$ALIAS_HANDOFF_RUN" <<'EOF_ALIAS_HANDOFF_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_ALIAS_HANDOFF_RUN

echo "[phase7-mainnet-cutover-summary-report] alias-resolution path"
PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_CANONICAL_SUMMARY_JSON="$ALIAS_CANONICAL_REPORT_JSON" \
bash "$SCRIPT_UNDER_TEST" \
  --check-summary-json "$ALIAS_CHECK" \
  --run-summary-json "$ALIAS_RUN" \
  --handoff-check-summary-json "$ALIAS_HANDOFF_CHECK" \
  --handoff-run-summary-json "$ALIAS_HANDOFF_RUN" \
  --summary-json "$ALIAS_REPORT_JSON" \
  --print-report 0 \
  --show-json 0 >"$ALIAS_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .signals.module_tx_surface_ok == true
  and .signals.tdpnd_grpc_live_smoke_ok == true
  and .signals.tdpnd_grpc_auth_live_smoke_ok == true
  and .signals.tdpnd_comet_runtime_smoke_ok == true
  and .signals.cosmos_module_coverage_floor_ok == true
  and .signals.cosmos_keeper_coverage_floor_ok == true
  and .signals.cosmos_app_coverage_floor_ok == true
  and .signals.mainnet_activation_gate_go_ok == true
  and .signals.bootstrap_governance_graduation_gate_go_ok == true
  and .signals.dual_write_parity_ok == true
  and .summaries.run.signal_snapshot.cosmos_module_coverage_floor == true
  and .summaries.run.signal_snapshot.cosmos_keeper_coverage_floor_ok == true
  and .summaries.run.signal_snapshot.mainnet_activation_gate_go == true
  and .summaries.run.signal_snapshot.tdpnd_comet_runtime_smoke == true
  and .summaries.handoff_check.signal_snapshot.cosmos_app_coverage_floor == true
  and .summaries.handoff_check.signal_snapshot.bootstrap_governance_graduation_gate_go_ok == true
  and .summaries.handoff_check.signal_snapshot.dual_write_parity == true
' "$ALIAS_REPORT_JSON" >/dev/null; then
  echo "phase7 summary report alias-resolution contract mismatch"
  cat "$ALIAS_REPORT_JSON"
  cat "$ALIAS_LOG"
  exit 1
fi
if [[ ! -f "$ALIAS_CANONICAL_REPORT_JSON" ]]; then
  echo "missing alias canonical summary report: $ALIAS_CANONICAL_REPORT_JSON"
  cat "$ALIAS_LOG"
  exit 1
fi
if ! cmp -s "$ALIAS_REPORT_JSON" "$ALIAS_CANONICAL_REPORT_JSON"; then
  echo "alias summary and canonical summary mismatch"
  cat "$ALIAS_REPORT_JSON"
  cat "$ALIAS_CANONICAL_REPORT_JSON"
  exit 1
fi
assert_canonical_path_hygiene "$ALIAS_REPORT_JSON" "$ALIAS_CANONICAL_REPORT_JSON" "alias-resolution"

cat >"$FAIL_CHECK" <<'EOF_FAIL_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_check_summary",
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
    "id": "phase7_mainnet_cutover_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "rc": 29
}
EOF_FAIL_RUN

cat >"$FAIL_HANDOFF_CHECK" <<'EOF_FAIL_HANDOFF_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_handoff_check_summary",
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
    "id": "phase7_mainnet_cutover_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "rc": 31
}
EOF_FAIL_HANDOFF_RUN

echo "[phase7-mainnet-cutover-summary-report] fail path"
set +e
PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_CANONICAL_SUMMARY_JSON="$FAIL_CANONICAL_REPORT_JSON" \
bash "$SCRIPT_UNDER_TEST" \
  --check-summary-json "$FAIL_CHECK" \
  --run-summary-json "$FAIL_RUN" \
  --handoff-check-summary-json "$FAIL_HANDOFF_CHECK" \
  --handoff-run-summary-json "$FAIL_HANDOFF_RUN" \
  --summary-json "$FAIL_REPORT_JSON" \
  --print-report 0 \
  --show-json 0 >"$FAIL_LOG" 2>&1
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
  and .counts.configured == 4
  and .counts.pass == 2
  and .counts.fail == 2
  and .counts.missing == 0
  and .counts.invalid == 0
  and .summaries.run.status == "fail"
  and .summaries.handoff_run.status == "fail"
  and ((.decision.reasons // []) | any(test("handoff_run status is fail")))
  and ((.decision.reasons // []) | any(test("run status is fail")))
' "$FAIL_REPORT_JSON" >/dev/null; then
  echo "phase7 summary report fail-path contract mismatch"
  cat "$FAIL_REPORT_JSON"
  cat "$FAIL_LOG"
  exit 1
fi
if [[ ! -f "$FAIL_CANONICAL_REPORT_JSON" ]]; then
  echo "missing fail canonical summary report: $FAIL_CANONICAL_REPORT_JSON"
  cat "$FAIL_LOG"
  exit 1
fi
if ! cmp -s "$FAIL_REPORT_JSON" "$FAIL_CANONICAL_REPORT_JSON"; then
  echo "fail summary and canonical summary mismatch"
  cat "$FAIL_REPORT_JSON"
  cat "$FAIL_CANONICAL_REPORT_JSON"
  exit 1
fi
assert_canonical_path_hygiene "$FAIL_REPORT_JSON" "$FAIL_CANONICAL_REPORT_JSON" "fail-path"

echo "[phase7-mainnet-cutover-summary-report] missing-input path"
set +e
PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_CANONICAL_SUMMARY_JSON="$MISSING_CANONICAL_REPORT_JSON" \
bash "$SCRIPT_UNDER_TEST" \
  --check-summary-json "$MISSING_PATH" \
  --handoff-check-summary-json "$MISSING_PATH" \
  --summary-json "$MISSING_REPORT_JSON" \
  --print-report 0 \
  --show-json 0 >"$MISSING_LOG" 2>&1
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
  and .counts.configured == 2
  and .counts.pass == 0
  and .counts.fail == 0
  and .counts.missing == 2
  and .counts.invalid == 0
  and .summaries.check.status == "missing"
  and .summaries.check.source_kind == "explicit"
  and .summaries.handoff_check.status == "missing"
  and .summaries.handoff_check.source_kind == "explicit"
  and .summaries.run.status == "skipped"
  and .summaries.handoff_run.status == "skipped"
  and .signals.bootstrap_governance_graduation_gate_go_ok == null
' "$MISSING_REPORT_JSON" >/dev/null; then
  echo "phase7 summary report missing-input contract mismatch"
  cat "$MISSING_REPORT_JSON"
  cat "$MISSING_LOG"
  exit 1
fi
if [[ ! -f "$MISSING_CANONICAL_REPORT_JSON" ]]; then
  echo "missing missing-input canonical summary report: $MISSING_CANONICAL_REPORT_JSON"
  cat "$MISSING_LOG"
  exit 1
fi
if ! cmp -s "$MISSING_REPORT_JSON" "$MISSING_CANONICAL_REPORT_JSON"; then
  echo "missing-input summary and canonical summary mismatch"
  cat "$MISSING_REPORT_JSON"
  cat "$MISSING_CANONICAL_REPORT_JSON"
  exit 1
fi
assert_canonical_path_hygiene "$MISSING_REPORT_JSON" "$MISSING_CANONICAL_REPORT_JSON" "missing-input"

mkdir -p "$FALLBACK_REPORTS_DIR"
mkdir -p "$FALLBACK_CHECK_OLD_DIR" "$FALLBACK_CHECK_NEW_DIR" "$FALLBACK_RUN_OLD_DIR" "$FALLBACK_RUN_NEW_DIR" "$FALLBACK_HANDOFF_CHECK_OLD_DIR" "$FALLBACK_HANDOFF_CHECK_NEW_DIR" "$FALLBACK_HANDOFF_RUN_OLD_DIR" "$FALLBACK_HANDOFF_RUN_NEW_DIR"

cat >"$FALLBACK_CHECK_OLD_DIR/phase7_mainnet_cutover_check_summary.json" <<'EOF_FALLBACK_CHECK_OLD'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FALLBACK_CHECK_OLD

cat >"$FALLBACK_CHECK_NEW_DIR/phase7_mainnet_cutover_check_summary.json" <<'EOF_FALLBACK_CHECK_NEW'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FALLBACK_CHECK_NEW

cat >"$FALLBACK_RUN_OLD_DIR/phase7_mainnet_cutover_run_summary.json" <<'EOF_FALLBACK_RUN_OLD'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FALLBACK_RUN_OLD

cat >"$FALLBACK_RUN_NEW_DIR/phase7_mainnet_cutover_run_summary.json" <<'EOF_FALLBACK_RUN_NEW'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FALLBACK_RUN_NEW

cat >"$FALLBACK_HANDOFF_CHECK_OLD_DIR/phase7_mainnet_cutover_handoff_check_summary.json" <<'EOF_FALLBACK_HANDOFF_CHECK_OLD'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FALLBACK_HANDOFF_CHECK_OLD

cat >"$FALLBACK_HANDOFF_CHECK_NEW_DIR/phase7_mainnet_cutover_handoff_check_summary.json" <<'EOF_FALLBACK_HANDOFF_CHECK_NEW'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FALLBACK_HANDOFF_CHECK_NEW

cat >"$FALLBACK_HANDOFF_RUN_OLD_DIR/phase7_mainnet_cutover_handoff_run_summary.json" <<'EOF_FALLBACK_HANDOFF_RUN_OLD'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FALLBACK_HANDOFF_RUN_OLD

cat >"$FALLBACK_HANDOFF_RUN_NEW_DIR/phase7_mainnet_cutover_handoff_run_summary.json" <<'EOF_FALLBACK_HANDOFF_RUN_NEW'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FALLBACK_HANDOFF_RUN_NEW

echo "[phase7-mainnet-cutover-summary-report] fallback-discovery path"
PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_CANONICAL_SUMMARY_JSON="$FALLBACK_CANONICAL_REPORT_JSON" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$FALLBACK_REPORTS_DIR" \
  --summary-json "$FALLBACK_REPORT_JSON" \
  --print-report 0 \
  --show-json 0 >"$FALLBACK_LOG" 2>&1

if ! jq -e \
  --arg expected_check_path "$FALLBACK_CHECK_NEW_DIR/phase7_mainnet_cutover_check_summary.json" \
  --arg expected_run_path "$FALLBACK_RUN_NEW_DIR/phase7_mainnet_cutover_run_summary.json" \
  --arg expected_handoff_check_path "$FALLBACK_HANDOFF_CHECK_NEW_DIR/phase7_mainnet_cutover_handoff_check_summary.json" \
  --arg expected_handoff_run_path "$FALLBACK_HANDOFF_RUN_NEW_DIR/phase7_mainnet_cutover_handoff_run_summary.json" \
  '
  .status == "pass"
  and .rc == 0
  and .counts.configured == 4
  and .counts.pass == 4
  and .counts.fail == 0
  and .counts.missing == 0
  and .counts.invalid == 0
  and .summaries.check.status == "pass"
  and .summaries.check.source_path == $expected_check_path
  and .summaries.check.source_kind == "discovered_timestamp_dir"
  and .summaries.run.status == "pass"
  and .summaries.run.source_path == $expected_run_path
  and .summaries.run.source_kind == "discovered_timestamp_dir"
  and .summaries.handoff_check.status == "pass"
  and .summaries.handoff_check.source_path == $expected_handoff_check_path
  and .summaries.handoff_check.source_kind == "discovered_timestamp_dir"
  and .summaries.handoff_run.status == "pass"
  and .summaries.handoff_run.source_path == $expected_handoff_run_path
  and .summaries.handoff_run.source_kind == "discovered_timestamp_dir"
  and .signals.bootstrap_governance_graduation_gate_go_ok == null
' "$FALLBACK_REPORT_JSON" >/dev/null; then
  echo "phase7 summary report fallback-discovery contract mismatch"
  cat "$FALLBACK_REPORT_JSON"
  cat "$FALLBACK_LOG"
  exit 1
fi
if [[ ! -f "$FALLBACK_CANONICAL_REPORT_JSON" ]]; then
  echo "missing fallback canonical summary report: $FALLBACK_CANONICAL_REPORT_JSON"
  cat "$FALLBACK_LOG"
  exit 1
fi
if ! cmp -s "$FALLBACK_REPORT_JSON" "$FALLBACK_CANONICAL_REPORT_JSON"; then
  echo "fallback summary and canonical summary mismatch"
  cat "$FALLBACK_REPORT_JSON"
  cat "$FALLBACK_CANONICAL_REPORT_JSON"
  exit 1
fi
assert_canonical_path_hygiene "$FALLBACK_REPORT_JSON" "$FALLBACK_CANONICAL_REPORT_JSON" "fallback-discovery"

mkdir -p "$EMBEDDED_INVALID_REPORTS_DIR" "$EMBEDDED_INVALID_CHECK_OLDER_DIR" "$EMBEDDED_INVALID_CHECK_INVALID_NEWER_DIR"

cat >"$EMBEDDED_INVALID_CHECK_OLDER_DIR/phase7_mainnet_cutover_check_summary.json" <<'EOF_EMBEDDED_INVALID_CHECK_OLDER'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_EMBEDDED_INVALID_CHECK_OLDER

cat >"$EMBEDDED_INVALID_CHECK_INVALID_NEWER_DIR/phase7_mainnet_cutover_check_summary.json" <<'EOF_EMBEDDED_INVALID_CHECK_INVALID_NEWER'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_check_summary",
    "major": 1,
    "minor": 0
  },
  "summary_generated_at": "not-a-real-timestamp",
  "status": "pass",
  "rc": 0
}
EOF_EMBEDDED_INVALID_CHECK_INVALID_NEWER

cat >"$EMBEDDED_INVALID_RUN_DEFAULT" <<'EOF_EMBEDDED_INVALID_RUN_DEFAULT'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_EMBEDDED_INVALID_RUN_DEFAULT

cat >"$EMBEDDED_INVALID_HANDOFF_CHECK_DEFAULT" <<'EOF_EMBEDDED_INVALID_HANDOFF_CHECK_DEFAULT'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_EMBEDDED_INVALID_HANDOFF_CHECK_DEFAULT

cat >"$EMBEDDED_INVALID_HANDOFF_RUN_DEFAULT" <<'EOF_EMBEDDED_INVALID_HANDOFF_RUN_DEFAULT'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_EMBEDDED_INVALID_HANDOFF_RUN_DEFAULT

touch -t 202604151201.00 "$EMBEDDED_INVALID_CHECK_OLDER_DIR/phase7_mainnet_cutover_check_summary.json"
touch -t 202604151259.00 "$EMBEDDED_INVALID_CHECK_INVALID_NEWER_DIR/phase7_mainnet_cutover_check_summary.json"

echo "[phase7-mainnet-cutover-summary-report] invalid-embedded-fail-closed path"
PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_CANONICAL_SUMMARY_JSON="$EMBEDDED_INVALID_CANONICAL_REPORT_JSON" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$EMBEDDED_INVALID_REPORTS_DIR" \
  --summary-json "$EMBEDDED_INVALID_REPORT_JSON" \
  --print-report 0 \
  --show-json 0 >"$EMBEDDED_INVALID_LOG" 2>&1

if ! jq -e \
  --arg expected_check_path "$EMBEDDED_INVALID_CHECK_OLDER_DIR/phase7_mainnet_cutover_check_summary.json" \
  --arg rejected_check_path "$EMBEDDED_INVALID_CHECK_INVALID_NEWER_DIR/phase7_mainnet_cutover_check_summary.json" \
  '
  .status == "pass"
  and .rc == 0
  and .counts.configured == 4
  and .counts.pass == 4
  and .counts.fail == 0
  and .counts.missing == 0
  and .counts.invalid == 0
  and .summaries.check.status == "pass"
  and .summaries.check.source_kind == "discovered_timestamp_dir"
  and .summaries.check.source_path == $expected_check_path
  and .summaries.check.source_path != $rejected_check_path
  and .summaries.run.source_kind == "default"
  and .summaries.handoff_check.source_kind == "default"
  and .summaries.handoff_run.source_kind == "default"
' "$EMBEDDED_INVALID_REPORT_JSON" >/dev/null; then
  echo "phase7 summary report invalid-embedded-fail-closed contract mismatch"
  cat "$EMBEDDED_INVALID_REPORT_JSON"
  cat "$EMBEDDED_INVALID_LOG"
  exit 1
fi
if [[ ! -f "$EMBEDDED_INVALID_CANONICAL_REPORT_JSON" ]]; then
  echo "missing invalid-embedded canonical summary report: $EMBEDDED_INVALID_CANONICAL_REPORT_JSON"
  cat "$EMBEDDED_INVALID_LOG"
  exit 1
fi
if ! cmp -s "$EMBEDDED_INVALID_REPORT_JSON" "$EMBEDDED_INVALID_CANONICAL_REPORT_JSON"; then
  echo "invalid-embedded summary and canonical summary mismatch"
  cat "$EMBEDDED_INVALID_REPORT_JSON"
  cat "$EMBEDDED_INVALID_CANONICAL_REPORT_JSON"
  exit 1
fi
assert_canonical_path_hygiene "$EMBEDDED_INVALID_REPORT_JSON" "$EMBEDDED_INVALID_CANONICAL_REPORT_JSON" "invalid-embedded-fail-closed"

mkdir -p "$EMBEDDED_VALID_REPORTS_DIR" "$EMBEDDED_VALID_CHECK_NEWER_MTIME_OLDER_TS_DIR" "$EMBEDDED_VALID_CHECK_OLDER_MTIME_NEWER_TS_DIR"

cat >"$EMBEDDED_VALID_CHECK_NEWER_MTIME_OLDER_TS_DIR/phase7_mainnet_cutover_check_summary.json" <<'EOF_EMBEDDED_VALID_CHECK_NEWER_MTIME_OLDER_TS'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_check_summary",
    "major": 1,
    "minor": 0
  },
  "generated_at_utc": "2026-04-15T12:00:00Z",
  "status": "pass",
  "rc": 0
}
EOF_EMBEDDED_VALID_CHECK_NEWER_MTIME_OLDER_TS

cat >"$EMBEDDED_VALID_CHECK_OLDER_MTIME_NEWER_TS_DIR/phase7_mainnet_cutover_check_summary.json" <<'EOF_EMBEDDED_VALID_CHECK_OLDER_MTIME_NEWER_TS'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_check_summary",
    "major": 1,
    "minor": 0
  },
  "summary_generated_at_utc": "2026-04-15T12:30:00Z",
  "status": "pass",
  "rc": 0
}
EOF_EMBEDDED_VALID_CHECK_OLDER_MTIME_NEWER_TS

cat >"$EMBEDDED_VALID_RUN_DEFAULT" <<'EOF_EMBEDDED_VALID_RUN_DEFAULT'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_EMBEDDED_VALID_RUN_DEFAULT

cat >"$EMBEDDED_VALID_HANDOFF_CHECK_DEFAULT" <<'EOF_EMBEDDED_VALID_HANDOFF_CHECK_DEFAULT'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_EMBEDDED_VALID_HANDOFF_CHECK_DEFAULT

cat >"$EMBEDDED_VALID_HANDOFF_RUN_DEFAULT" <<'EOF_EMBEDDED_VALID_HANDOFF_RUN_DEFAULT'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_EMBEDDED_VALID_HANDOFF_RUN_DEFAULT

touch -t 202604151300.00 "$EMBEDDED_VALID_CHECK_NEWER_MTIME_OLDER_TS_DIR/phase7_mainnet_cutover_check_summary.json"
touch -t 202604151200.00 "$EMBEDDED_VALID_CHECK_OLDER_MTIME_NEWER_TS_DIR/phase7_mainnet_cutover_check_summary.json"

echo "[phase7-mainnet-cutover-summary-report] valid-embedded-precedence path"
PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_CANONICAL_SUMMARY_JSON="$EMBEDDED_VALID_CANONICAL_REPORT_JSON" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$EMBEDDED_VALID_REPORTS_DIR" \
  --summary-json "$EMBEDDED_VALID_REPORT_JSON" \
  --print-report 0 \
  --show-json 0 >"$EMBEDDED_VALID_LOG" 2>&1

if ! jq -e \
  --arg expected_check_path "$EMBEDDED_VALID_CHECK_OLDER_MTIME_NEWER_TS_DIR/phase7_mainnet_cutover_check_summary.json" \
  --arg rejected_check_path "$EMBEDDED_VALID_CHECK_NEWER_MTIME_OLDER_TS_DIR/phase7_mainnet_cutover_check_summary.json" \
  '
  .status == "pass"
  and .rc == 0
  and .counts.configured == 4
  and .counts.pass == 4
  and .counts.fail == 0
  and .counts.missing == 0
  and .counts.invalid == 0
  and .summaries.check.status == "pass"
  and .summaries.check.source_kind == "discovered_timestamp_dir"
  and .summaries.check.source_path == $expected_check_path
  and .summaries.check.source_path != $rejected_check_path
  and .summaries.run.source_kind == "default"
  and .summaries.handoff_check.source_kind == "default"
  and .summaries.handoff_run.source_kind == "default"
' "$EMBEDDED_VALID_REPORT_JSON" >/dev/null; then
  echo "phase7 summary report valid-embedded-precedence contract mismatch"
  cat "$EMBEDDED_VALID_REPORT_JSON"
  cat "$EMBEDDED_VALID_LOG"
  exit 1
fi
if [[ ! -f "$EMBEDDED_VALID_CANONICAL_REPORT_JSON" ]]; then
  echo "missing valid-embedded canonical summary report: $EMBEDDED_VALID_CANONICAL_REPORT_JSON"
  cat "$EMBEDDED_VALID_LOG"
  exit 1
fi
if ! cmp -s "$EMBEDDED_VALID_REPORT_JSON" "$EMBEDDED_VALID_CANONICAL_REPORT_JSON"; then
  echo "valid-embedded summary and canonical summary mismatch"
  cat "$EMBEDDED_VALID_REPORT_JSON"
  cat "$EMBEDDED_VALID_CANONICAL_REPORT_JSON"
  exit 1
fi
assert_canonical_path_hygiene "$EMBEDDED_VALID_REPORT_JSON" "$EMBEDDED_VALID_CANONICAL_REPORT_JSON" "valid-embedded-precedence"

echo "phase7 mainnet cutover summary report integration ok"
