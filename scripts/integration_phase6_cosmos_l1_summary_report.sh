#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod grep cat; do
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
PASS_LOG="$TMP_DIR/pass.log"

FAIL_CI="$TMP_DIR/ci_fail_case.json"
FAIL_CONTRACTS="$TMP_DIR/contracts_fail_case.json"
FAIL_SUITE="$TMP_DIR/suite_fail_case.json"
FAIL_REPORT_JSON="$TMP_DIR/report_fail.json"
FAIL_LOG="$TMP_DIR/fail.log"

MISSING_REPORT_JSON="$TMP_DIR/report_missing.json"
MISSING_LOG="$TMP_DIR/missing.log"
MISSING_PATH="$TMP_DIR/does_not_exist.json"

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
"$SCRIPT_UNDER_TEST" \
  --ci-summary-json "$PASS_CI" \
  --contracts-summary-json "$PASS_CONTRACTS" \
  --suite-summary-json "$PASS_SUITE" \
  --summary-json "$PASS_REPORT_JSON" \
  --print-report 0 \
  --show-json 0 >"$PASS_LOG" 2>&1

if ! jq -e '
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
' "$PASS_REPORT_JSON" >/dev/null; then
  echo "phase6 summary report pass-path contract mismatch"
  cat "$PASS_REPORT_JSON"
  cat "$PASS_LOG"
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

echo "phase6 cosmos l1 summary report integration ok"
