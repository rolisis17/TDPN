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

SCRIPT_UNDER_TEST="${PHASE6_COSMOS_L1_SUMMARY_REPORT_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase6_cosmos_l1_summary_report.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS_CI="$TMP_DIR/ci_pass.json"
PASS_CONTRACTS="$TMP_DIR/contracts_pass.json"
PASS_SUITE="$TMP_DIR/suite_pass.json"
PASS_REPORT_JSON="$TMP_DIR/report_pass.json"
PASS_CANONICAL_REPORT_JSON="$TMP_DIR/report_pass_canonical.json"
PASS_LOG="$TMP_DIR/pass.log"
PASS_SAME_PATH_REPORT_JSON="$TMP_DIR/report_pass_same_path.json"
PASS_SAME_PATH_LOG="$TMP_DIR/pass_same_path.log"
PASS_SIGNAL_CHECK="$TMP_DIR/check_signal_pass.json"
PASS_SIGNAL_RUN="$TMP_DIR/run_signal_pass.json"
PASS_SIGNAL_HANDOFF_CHECK="$TMP_DIR/handoff_check_signal_pass.json"
PASS_SIGNAL_HANDOFF_RUN="$TMP_DIR/handoff_run_signal_pass.json"
PASS_SIGNAL_REPORT_JSON="$TMP_DIR/report_signal_pass.json"
PASS_SIGNAL_CANONICAL_REPORT_JSON="$TMP_DIR/report_signal_pass_canonical.json"
PASS_SIGNAL_LOG="$TMP_DIR/signal_pass.log"

FAIL_CI="$TMP_DIR/ci_fail_case.json"
FAIL_CONTRACTS="$TMP_DIR/contracts_fail_case.json"
FAIL_SUITE="$TMP_DIR/suite_fail_case.json"
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

FALLBACK_CI_OLD_DIR="$FALLBACK_REPORTS_DIR/ci_phase6_cosmos_l1_build_testnet_20260415_165959"
FALLBACK_CI_NEW_DIR="$FALLBACK_REPORTS_DIR/ci_phase6_cosmos_l1_build_testnet_20260415_170000"
FALLBACK_CONTRACTS_OLD_DIR="$FALLBACK_REPORTS_DIR/ci_phase6_cosmos_l1_contracts_20260415_170500"
FALLBACK_CONTRACTS_NEW_DIR="$FALLBACK_REPORTS_DIR/ci_phase6_cosmos_l1_contracts_20260415_170700"
FALLBACK_SUITE_OLD_DIR="$FALLBACK_REPORTS_DIR/phase6_cosmos_l1_build_testnet_suite_20260415_170100"
FALLBACK_SUITE_NEW_DIR="$FALLBACK_REPORTS_DIR/phase6_cosmos_l1_build_testnet_suite_20260415_170300"

cat >"$PASS_CI" <<'EOF_PASS_CI'
{
  "version": 1,
  "schema": {
    "id": "ci_phase6_cosmos_l1_build_testnet_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_PASS_CI

cat >"$PASS_CONTRACTS" <<'EOF_PASS_CONTRACTS'
{
  "version": 1,
  "schema": {
    "id": "ci_phase6_cosmos_l1_contracts_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_PASS_CONTRACTS

cat >"$PASS_SUITE" <<'EOF_PASS_SUITE'
{
  "version": 1,
  "schema": {
    "id": "phase6_cosmos_l1_build_testnet_suite_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_PASS_SUITE

echo "[phase6-cosmos-l1-summary-report] pass path"
PHASE6_COSMOS_L1_SUMMARY_REPORT_CANONICAL_SUMMARY_JSON="$PASS_CANONICAL_REPORT_JSON" \
"$SCRIPT_UNDER_TEST" \
  --ci-summary-json "$PASS_CI" \
  --contracts-summary-json "$PASS_CONTRACTS" \
  --suite-summary-json "$PASS_SUITE" \
  --summary-json "$PASS_REPORT_JSON" \
  --print-report 1 \
  --show-json 0 >"$PASS_LOG" 2>&1

if ! jq -e \
  --arg expected_summary "$PASS_REPORT_JSON" \
  --arg expected_canonical "$PASS_CANONICAL_REPORT_JSON" \
  '
  .version == 1
  and .schema.id == "phase6_cosmos_l1_summary_report"
  and .status == "pass"
  and .rc == 0
  and .counts.configured == 3
  and .counts.pass == 3
  and .counts.fail == 0
  and .counts.missing == 0
  and .counts.invalid == 0
  and .summaries.build_testnet_ci.status == "pass"
  and .summaries.contracts_ci.status == "pass"
  and .summaries.build_testnet_suite.status == "pass"
  and .signals.tdpnd_comet_runtime_smoke.ok == null
  and .signals.tdpnd_comet_runtime_smoke.status == "missing"
  and .signals.tdpnd_comet_runtime_smoke.resolved == false
  and .signals.tdpnd_comet_runtime_smoke.source == "unresolved"
  and .artifacts.summary_json == $expected_summary
  and .artifacts.canonical_summary_json == $expected_canonical
' "$PASS_REPORT_JSON" >/dev/null; then
  echo "phase6 summary report pass-path contract mismatch"
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
if ! grep -Fq -- "[phase6-summary] canonical_summary_json=$PASS_CANONICAL_REPORT_JSON" "$PASS_LOG"; then
  echo "pass log missing canonical summary line"
  cat "$PASS_LOG"
  exit 1
fi

echo "[phase6-cosmos-l1-summary-report] canonical-same-path pass path"
PHASE6_COSMOS_L1_SUMMARY_REPORT_CANONICAL_SUMMARY_JSON="$PASS_SAME_PATH_REPORT_JSON" \
"$SCRIPT_UNDER_TEST" \
  --ci-summary-json "$PASS_CI" \
  --contracts-summary-json "$PASS_CONTRACTS" \
  --suite-summary-json "$PASS_SUITE" \
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
  and .signals.tdpnd_comet_runtime_smoke.ok == null
' "$PASS_SAME_PATH_REPORT_JSON" >/dev/null; then
  echo "phase6 summary report canonical-same-path contract mismatch"
  cat "$PASS_SAME_PATH_REPORT_JSON"
  cat "$PASS_SAME_PATH_LOG"
  exit 1
fi
if ! grep -Fq -- "[phase6-summary] canonical_summary_json=$PASS_SAME_PATH_REPORT_JSON" "$PASS_SAME_PATH_LOG"; then
  echo "canonical-same-path log missing canonical summary line"
  cat "$PASS_SAME_PATH_LOG"
  exit 1
fi

cat >"$PASS_SIGNAL_CHECK" <<'EOF_PASS_SIGNAL_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase6_cosmos_l1_build_testnet_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "signals": {
    "chain_scaffold_ok": true,
    "proto_surface_ok": true,
    "proto_codegen_surface_ok": true,
    "query_surface_ok": true,
    "module_tx_surface_ok": true,
    "grpc_app_roundtrip_ok": true,
    "tdpnd_grpc_runtime_smoke_ok": true,
    "tdpnd_grpc_live_smoke_ok": true,
    "tdpnd_grpc_auth_live_smoke_ok": true
  }
}
EOF_PASS_SIGNAL_CHECK

cat >"$PASS_SIGNAL_RUN" <<'EOF_PASS_SIGNAL_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase6_cosmos_l1_build_testnet_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "ci_phase6_cosmos_l1_build_testnet": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true
    },
    "phase6_cosmos_l1_build_testnet_check": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "signal_snapshot": {
        "tdpnd_comet_runtime_smoke_ok": true
      }
    }
  }
}
EOF_PASS_SIGNAL_RUN

cat >"$PASS_SIGNAL_HANDOFF_CHECK" <<'EOF_PASS_SIGNAL_HANDOFF_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase6_cosmos_l1_build_testnet_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "fail_closed": true,
  "handoff": {
    "run_pipeline_ok": true,
    "chain_scaffold_ok": true,
    "proto_surface_ok": true,
    "proto_codegen_surface_ok": true,
    "query_surface_ok": true,
    "module_tx_surface_ok": true,
    "grpc_app_roundtrip_ok": true,
    "tdpnd_grpc_runtime_smoke_ok": true,
    "tdpnd_grpc_live_smoke_ok": true,
    "tdpnd_grpc_auth_live_smoke_ok": true
  },
  "decision": {
    "pass": true,
    "reasons": [],
    "warnings": []
  }
}
EOF_PASS_SIGNAL_HANDOFF_CHECK

cat >"$PASS_SIGNAL_HANDOFF_RUN" <<'EOF_PASS_SIGNAL_HANDOFF_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase6_cosmos_l1_build_testnet_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "handoff": {
    "run_pipeline_ok": true,
    "chain_scaffold_ok": true,
    "proto_surface_ok": true,
    "proto_codegen_surface_ok": true,
    "query_surface_ok": true,
    "module_tx_surface_ok": true,
    "grpc_app_roundtrip_ok": true,
    "tdpnd_grpc_runtime_smoke_ok": true,
    "tdpnd_grpc_live_smoke_ok": true,
    "tdpnd_grpc_auth_live_smoke_ok": true
  },
  "decision": {
    "pass": true,
    "reasons": [],
    "warnings": []
  }
}
EOF_PASS_SIGNAL_HANDOFF_RUN

echo "[phase6-cosmos-l1-summary-report] optional signal path"
PHASE6_COSMOS_L1_SUMMARY_REPORT_CANONICAL_SUMMARY_JSON="$PASS_SIGNAL_CANONICAL_REPORT_JSON" \
"$SCRIPT_UNDER_TEST" \
  --ci-summary-json "$PASS_CI" \
  --contracts-summary-json "$PASS_CONTRACTS" \
  --suite-summary-json "$PASS_SUITE" \
  --check-summary-json "$PASS_SIGNAL_CHECK" \
  --run-summary-json "$PASS_SIGNAL_RUN" \
  --handoff-check-summary-json "$PASS_SIGNAL_HANDOFF_CHECK" \
  --handoff-run-summary-json "$PASS_SIGNAL_HANDOFF_RUN" \
  --summary-json "$PASS_SIGNAL_REPORT_JSON" \
  --print-report 1 \
  --show-json 0 >"$PASS_SIGNAL_LOG" 2>&1

if ! jq -e \
  --arg expected_summary "$PASS_SIGNAL_REPORT_JSON" \
  --arg expected_canonical "$PASS_SIGNAL_CANONICAL_REPORT_JSON" \
  --arg expected_run_path "$PASS_SIGNAL_RUN" \
  '
  .version == 1
  and .schema.id == "phase6_cosmos_l1_summary_report"
  and .status == "pass"
  and .rc == 0
  and .counts.configured == 7
  and .counts.pass == 7
  and .counts.fail == 0
  and .counts.missing == 0
  and .counts.invalid == 0
  and .summaries.build_testnet_check.status == "pass"
  and .summaries.build_testnet_run.status == "pass"
  and .summaries.build_testnet_handoff_check.status == "pass"
  and .summaries.build_testnet_handoff_run.status == "pass"
  and .signals.tdpnd_comet_runtime_smoke.ok == true
  and .signals.tdpnd_comet_runtime_smoke.status == "pass"
  and .signals.tdpnd_comet_runtime_smoke.resolved == true
  and .signals.tdpnd_comet_runtime_smoke.source == "build_testnet_run"
  and .signals.tdpnd_comet_runtime_smoke.source_field == "steps.phase6_cosmos_l1_build_testnet_check.signal_snapshot.tdpnd_comet_runtime_smoke_ok"
  and .signals.tdpnd_comet_runtime_smoke.source_path == $expected_run_path
  and .signals.tdpnd_comet_runtime_smoke.source_priority_index == 4
  and .artifacts.summary_json == $expected_summary
  and .artifacts.canonical_summary_json == $expected_canonical
' "$PASS_SIGNAL_REPORT_JSON" >/dev/null; then
  echo "phase6 summary report optional-signal contract mismatch"
  cat "$PASS_SIGNAL_REPORT_JSON"
  cat "$PASS_SIGNAL_LOG"
  exit 1
fi
if [[ ! -f "$PASS_SIGNAL_CANONICAL_REPORT_JSON" ]]; then
  echo "missing optional-signal canonical summary report: $PASS_SIGNAL_CANONICAL_REPORT_JSON"
  cat "$PASS_SIGNAL_LOG"
  exit 1
fi
if ! cmp -s "$PASS_SIGNAL_REPORT_JSON" "$PASS_SIGNAL_CANONICAL_REPORT_JSON"; then
  echo "optional-signal summary and canonical summary mismatch"
  cat "$PASS_SIGNAL_REPORT_JSON"
  cat "$PASS_SIGNAL_CANONICAL_REPORT_JSON"
  exit 1
fi
if ! grep -Fq -- "[phase6-summary] canonical_summary_json=$PASS_SIGNAL_CANONICAL_REPORT_JSON" "$PASS_SIGNAL_LOG"; then
  echo "optional-signal log missing canonical summary line"
  cat "$PASS_SIGNAL_LOG"
  exit 1
fi

cat >"$FAIL_CI" <<'EOF_FAIL_CI'
{
  "version": 1,
  "schema": {
    "id": "ci_phase6_cosmos_l1_build_testnet_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FAIL_CI

cat >"$FAIL_CONTRACTS" <<'EOF_FAIL_CONTRACTS'
{
  "version": 1,
  "schema": {
    "id": "ci_phase6_cosmos_l1_contracts_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FAIL_CONTRACTS

cat >"$FAIL_SUITE" <<'EOF_FAIL_SUITE'
{
  "version": 1,
  "schema": {
    "id": "phase6_cosmos_l1_build_testnet_suite_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "rc": 41
}
EOF_FAIL_SUITE

echo "[phase6-cosmos-l1-summary-report] fail path"
set +e
PHASE6_COSMOS_L1_SUMMARY_REPORT_CANONICAL_SUMMARY_JSON="$FAIL_CANONICAL_REPORT_JSON" \
"$SCRIPT_UNDER_TEST" \
  --ci-summary-json "$FAIL_CI" \
  --contracts-summary-json "$FAIL_CONTRACTS" \
  --suite-summary-json "$FAIL_SUITE" \
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
  and .counts.fail == 1
  and .summaries.build_testnet_suite.status == "fail"
  and ((.decision.reasons // []) | any(test("build_testnet_suite status is fail")))
' "$FAIL_REPORT_JSON" >/dev/null; then
  echo "phase6 summary report fail-path contract mismatch"
  cat "$FAIL_REPORT_JSON"
  cat "$FAIL_LOG"
  exit 1
fi

echo "[phase6-cosmos-l1-summary-report] missing-input path"
set +e
PHASE6_COSMOS_L1_SUMMARY_REPORT_CANONICAL_SUMMARY_JSON="$MISSING_CANONICAL_REPORT_JSON" \
"$SCRIPT_UNDER_TEST" \
  --ci-summary-json "$MISSING_PATH" \
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
  and .counts.configured == 1
  and .counts.pass == 0
  and .counts.fail == 0
  and .counts.missing == 1
  and .summaries.build_testnet_ci.status == "missing"
  and .summaries.contracts_ci.status == "skipped"
  and .summaries.build_testnet_suite.status == "skipped"
' "$MISSING_REPORT_JSON" >/dev/null; then
  echo "phase6 summary report missing-input contract mismatch"
  cat "$MISSING_REPORT_JSON"
  cat "$MISSING_LOG"
  exit 1
fi

mkdir -p "$FALLBACK_REPORTS_DIR"
mkdir -p "$FALLBACK_CI_OLD_DIR" "$FALLBACK_CI_NEW_DIR" "$FALLBACK_CONTRACTS_OLD_DIR" "$FALLBACK_CONTRACTS_NEW_DIR" "$FALLBACK_SUITE_OLD_DIR" "$FALLBACK_SUITE_NEW_DIR"

cat >"$FALLBACK_CI_OLD_DIR/ci_phase6_cosmos_l1_build_testnet_summary.json" <<'EOF_FALLBACK_CI_OLD'
{
  "version": 1,
  "schema": {
    "id": "ci_phase6_cosmos_l1_build_testnet_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FALLBACK_CI_OLD

cat >"$FALLBACK_CI_NEW_DIR/ci_phase6_cosmos_l1_build_testnet_summary.json" <<'EOF_FALLBACK_CI_NEW'
{
  "version": 1,
  "schema": {
    "id": "ci_phase6_cosmos_l1_build_testnet_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FALLBACK_CI_NEW

cat >"$FALLBACK_CONTRACTS_OLD_DIR/ci_phase6_cosmos_l1_contracts_summary.json" <<'EOF_FALLBACK_CONTRACTS_OLD'
{
  "version": 1,
  "schema": {
    "id": "ci_phase6_cosmos_l1_contracts_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FALLBACK_CONTRACTS_OLD

cat >"$FALLBACK_CONTRACTS_NEW_DIR/ci_phase6_cosmos_l1_contracts_summary.json" <<'EOF_FALLBACK_CONTRACTS_NEW'
{
  "version": 1,
  "schema": {
    "id": "ci_phase6_cosmos_l1_contracts_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FALLBACK_CONTRACTS_NEW

cat >"$FALLBACK_SUITE_OLD_DIR/phase6_cosmos_l1_build_testnet_suite_summary.json" <<'EOF_FALLBACK_SUITE_OLD'
{
  "version": 1,
  "schema": {
    "id": "phase6_cosmos_l1_build_testnet_suite_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FALLBACK_SUITE_OLD

cat >"$FALLBACK_SUITE_NEW_DIR/phase6_cosmos_l1_build_testnet_suite_summary.json" <<'EOF_FALLBACK_SUITE_NEW'
{
  "version": 1,
  "schema": {
    "id": "phase6_cosmos_l1_build_testnet_suite_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_FALLBACK_SUITE_NEW

echo "[phase6-cosmos-l1-summary-report] fallback discovery path"
PHASE6_COSMOS_L1_SUMMARY_REPORT_CANONICAL_SUMMARY_JSON="$FALLBACK_CANONICAL_REPORT_JSON" \
"$SCRIPT_UNDER_TEST" \
  --reports-dir "$FALLBACK_REPORTS_DIR" \
  --summary-json "$FALLBACK_REPORT_JSON" \
  --print-report 0 \
  --show-json 0 >"$FALLBACK_LOG" 2>&1

if ! jq -e \
  --arg expected_ci_path "$FALLBACK_CI_NEW_DIR/ci_phase6_cosmos_l1_build_testnet_summary.json" \
  --arg expected_contracts_path "$FALLBACK_CONTRACTS_NEW_DIR/ci_phase6_cosmos_l1_contracts_summary.json" \
  --arg expected_suite_path "$FALLBACK_SUITE_NEW_DIR/phase6_cosmos_l1_build_testnet_suite_summary.json" \
  '
  .status == "pass"
  and .rc == 0
  and .counts.configured == 3
  and .counts.pass == 3
  and .counts.fail == 0
  and .counts.missing == 0
  and .counts.invalid == 0
  and .summaries.build_testnet_ci.status == "pass"
  and .summaries.contracts_ci.status == "pass"
  and .summaries.build_testnet_suite.status == "pass"
  and .summaries.build_testnet_ci.path == $expected_ci_path
  and .summaries.contracts_ci.path == $expected_contracts_path
  and .summaries.build_testnet_suite.path == $expected_suite_path
' "$FALLBACK_REPORT_JSON" >/dev/null; then
  echo "phase6 summary report fallback-discovery contract mismatch"
  cat "$FALLBACK_REPORT_JSON"
  cat "$FALLBACK_LOG"
  exit 1
fi

echo "phase6 cosmos l1 summary report integration ok"
