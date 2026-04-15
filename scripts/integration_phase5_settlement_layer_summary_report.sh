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

cat >"$PASS_CI" <<'EOF_PASS_CI'
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
  "rc": 0
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
  "rc": 0
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

if ! jq -e --arg expected_canonical_summary_json "$PASS_CANONICAL_REPORT_JSON" '
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
  and .artifacts.canonical_summary_json == $expected_canonical_summary_json
' "$PASS_REPORT_JSON" >/dev/null; then
  echo "phase5 summary report pass-path contract mismatch"
  cat "$PASS_REPORT_JSON"
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
' "$MISSING_REPORT_JSON" >/dev/null; then
  echo "phase5 summary report missing-input contract mismatch"
  cat "$MISSING_REPORT_JSON"
  cat "$MISSING_LOG"
  exit 1
fi

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
  "rc": 0
}
EOF_FALLBACK_HANDOFF_RUN_NEW

cat >"$FALLBACK_REPORTS_DIR/phase5_settlement_layer_check_summary.json" <<'EOF_FALLBACK_CHECK'
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
' "$FALLBACK_REPORT_JSON" >/dev/null; then
  echo "phase5 summary report fallback-discovery contract mismatch"
  cat "$FALLBACK_REPORT_JSON"
  cat "$FALLBACK_LOG"
  exit 1
fi

echo "phase5 settlement layer summary report integration ok"
