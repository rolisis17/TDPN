#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp date; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PROFILE_DEFAULT_GATE_STABILITY_EVIDENCE_PACK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/profile_default_gate_stability_evidence_pack.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

assert_jq() {
  local file="$1"
  local query="$2"
  if ! jq -e "$query" "$file" >/dev/null; then
    echo "assertion failed: $query"
    echo "file: $file"
    cat "$file"
    exit 1
  fi
}

write_valid_run_summary() {
  local path="$1"
  local generated_at="$2"
  jq -n \
    --arg generated_at_utc "$generated_at" \
    '{
      version: 1,
      schema: { id: "profile_default_gate_stability_summary" },
      generated_at_utc: $generated_at_utc,
      status: "pass",
      rc: 0,
      stability_ok: true,
      runs_requested: 3,
      runs_completed: 3
    }' >"$path"
}

write_valid_check_summary() {
  local path="$1"
  local generated_at="$2"
  local decision="${3:-GO}"
  jq -n \
    --arg generated_at_utc "$generated_at" \
    --arg decision "$decision" \
    '{
      version: 1,
      schema: { id: "profile_default_gate_stability_check_summary" },
      generated_at_utc: $generated_at_utc,
      decision: $decision,
      status: "ok",
      rc: 0,
      errors: []
    }' >"$path"
}

write_valid_cycle_summary() {
  local path="$1"
  local generated_at="$2"
  local decision="${3:-GO}"
  jq -n \
    --arg generated_at_utc "$generated_at" \
    --arg decision "$decision" \
    '{
      version: 1,
      schema: { id: "profile_default_gate_stability_cycle_summary" },
      generated_at_utc: $generated_at_utc,
      decision: $decision,
      status: "pass",
      rc: 0
    }' >"$path"
}

NOW_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

PASS_DIR="$TMP_DIR/pass"
mkdir -p "$PASS_DIR"
PASS_RUN="$PASS_DIR/profile_default_gate_stability_summary.json"
PASS_CHECK="$PASS_DIR/profile_default_gate_stability_check_summary.json"
PASS_CYCLE="$PASS_DIR/profile_default_gate_stability_cycle_summary.json"
PASS_SUMMARY="$PASS_DIR/evidence_pack_summary.json"
PASS_REPORT="$PASS_DIR/evidence_pack_report.md"

write_valid_run_summary "$PASS_RUN" "$NOW_UTC"
write_valid_check_summary "$PASS_CHECK" "$NOW_UTC" "GO"
write_valid_cycle_summary "$PASS_CYCLE" "$NOW_UTC" "GO"

bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$PASS_DIR" \
  --summary-json "$PASS_SUMMARY" \
  --report-md "$PASS_REPORT" \
  --max-age-sec 3600 \
  --print-summary-json 0

assert_jq "$PASS_SUMMARY" '.schema.id == "profile_default_gate_stability_evidence_pack_summary"'
assert_jq "$PASS_SUMMARY" '.status == "ok"'
assert_jq "$PASS_SUMMARY" '.decision == "GO"'
assert_jq "$PASS_SUMMARY" '(.generated_at_utc | type) == "string" and (.generated_at_utc | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))'
assert_jq "$PASS_SUMMARY" '.evidence.run.usable == true and .evidence.check.usable == true and .evidence.cycle.usable == true'
if [[ ! -f "$PASS_REPORT" ]]; then
  echo "expected report markdown missing: $PASS_REPORT"
  exit 1
fi

NOGO_DIR="$TMP_DIR/nogo"
mkdir -p "$NOGO_DIR"
NOGO_RUN="$NOGO_DIR/profile_default_gate_stability_summary.json"
NOGO_CHECK="$NOGO_DIR/profile_default_gate_stability_check_summary.json"
NOGO_CYCLE="$NOGO_DIR/profile_default_gate_stability_cycle_summary.json"
NOGO_SOFT_SUMMARY="$NOGO_DIR/evidence_pack_soft_nogo_summary.json"
NOGO_HARD_SUMMARY="$NOGO_DIR/evidence_pack_hard_nogo_summary.json"
NOGO_REPORT="$NOGO_DIR/evidence_pack_report.md"

write_valid_run_summary "$NOGO_RUN" "$NOW_UTC"
write_valid_check_summary "$NOGO_CHECK" "$NOW_UTC" "NO-GO"
write_valid_cycle_summary "$NOGO_CYCLE" "$NOW_UTC" "NO-GO"

bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$NOGO_DIR" \
  --summary-json "$NOGO_SOFT_SUMMARY" \
  --report-md "$NOGO_REPORT" \
  --fail-on-no-go 0 \
  --max-age-sec 3600 \
  --print-summary-json 0

assert_jq "$NOGO_SOFT_SUMMARY" '.schema.id == "profile_default_gate_stability_evidence_pack_summary"'
assert_jq "$NOGO_SOFT_SUMMARY" '.decision == "NO-GO"'
assert_jq "$NOGO_SOFT_SUMMARY" '.status == "warn"'
assert_jq "$NOGO_SOFT_SUMMARY" '.rc == 0'
assert_jq "$NOGO_SOFT_SUMMARY" '.evidence.cycle.usable == true'

set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$NOGO_DIR" \
  --summary-json "$NOGO_HARD_SUMMARY" \
  --report-md "$NOGO_REPORT" \
  --fail-on-no-go 1 \
  --max-age-sec 3600 \
  --print-summary-json 0
NOGO_HARD_RC=$?
set -e

if [[ "$NOGO_HARD_RC" -eq 0 ]]; then
  echo "expected non-zero exit code for usable NO-GO with fail-on-no-go=1"
  exit 1
fi
assert_jq "$NOGO_HARD_SUMMARY" '.decision == "NO-GO"'
assert_jq "$NOGO_HARD_SUMMARY" '.status == "fail"'
assert_jq "$NOGO_HARD_SUMMARY" '.rc != 0'
assert_jq "$NOGO_HARD_SUMMARY" '.evidence.cycle.usable == true'

MISMATCH_DIR="$TMP_DIR/mismatch"
mkdir -p "$MISMATCH_DIR"
MISMATCH_RUN="$MISMATCH_DIR/profile_default_gate_stability_summary.json"
MISMATCH_CHECK="$MISMATCH_DIR/profile_default_gate_stability_check_summary.json"
MISMATCH_CYCLE="$MISMATCH_DIR/profile_default_gate_stability_cycle_summary.json"
MISMATCH_SUMMARY="$MISMATCH_DIR/evidence_pack_summary.json"
MISMATCH_REPORT="$MISMATCH_DIR/evidence_pack_report.md"

write_valid_run_summary "$MISMATCH_RUN" "$NOW_UTC"
write_valid_check_summary "$MISMATCH_CHECK" "$NOW_UTC" "NO-GO"
write_valid_cycle_summary "$MISMATCH_CYCLE" "$NOW_UTC" "GO"

set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$MISMATCH_DIR" \
  --summary-json "$MISMATCH_SUMMARY" \
  --report-md "$MISMATCH_REPORT" \
  --fail-on-no-go 1 \
  --max-age-sec 3600 \
  --print-summary-json 0
MISMATCH_RC=$?
set -e

if [[ "$MISMATCH_RC" -eq 0 ]]; then
  echo "expected non-zero exit code for cycle/check decision mismatch"
  exit 1
fi
assert_jq "$MISMATCH_SUMMARY" '.status == "fail"'
assert_jq "$MISMATCH_SUMMARY" '.decision == "NO-GO"'
assert_jq "$MISMATCH_SUMMARY" '.rc != 0'
assert_jq "$MISMATCH_SUMMARY" '(.reasons | map(test("^decision mismatch between cycle and check summaries")) | any)'

MISSING_DIR="$TMP_DIR/missing"
mkdir -p "$MISSING_DIR"
MISSING_RUN="$MISSING_DIR/profile_default_gate_stability_summary.json"
MISSING_CHECK="$MISSING_DIR/profile_default_gate_stability_check_summary.json"
MISSING_SUMMARY="$MISSING_DIR/evidence_pack_summary.json"
MISSING_REPORT="$MISSING_DIR/evidence_pack_report.md"

write_valid_run_summary "$MISSING_RUN" "$NOW_UTC"
write_valid_check_summary "$MISSING_CHECK" "$NOW_UTC" "GO"

set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$MISSING_DIR" \
  --summary-json "$MISSING_SUMMARY" \
  --report-md "$MISSING_REPORT" \
  --max-age-sec 3600 \
  --print-summary-json 0
MISSING_RC=$?
set -e

if [[ "$MISSING_RC" -eq 0 ]]; then
  echo "expected non-zero exit code for missing evidence case"
  exit 1
fi
assert_jq "$MISSING_SUMMARY" '.status == "fail"'
assert_jq "$MISSING_SUMMARY" '.decision == "NO-GO"'
assert_jq "$MISSING_SUMMARY" '.reasons | map(test("^cycle: missing required evidence file:")) | any'
assert_jq "$MISSING_SUMMARY" '(.operator_next_action_command | type) == "string" and (.operator_next_action_command | length) > 0'

INVALID_DIR="$TMP_DIR/invalid_freshness"
mkdir -p "$INVALID_DIR"
INVALID_RUN="$INVALID_DIR/profile_default_gate_stability_summary.json"
INVALID_CHECK="$INVALID_DIR/profile_default_gate_stability_check_summary.json"
INVALID_CYCLE="$INVALID_DIR/profile_default_gate_stability_cycle_summary.json"
INVALID_SUMMARY="$INVALID_DIR/evidence_pack_summary.json"
INVALID_REPORT="$INVALID_DIR/evidence_pack_report.md"

write_valid_run_summary "$INVALID_RUN" "$NOW_UTC"
write_valid_check_summary "$INVALID_CHECK" "$NOW_UTC" "GO"
write_valid_cycle_summary "$INVALID_CYCLE" "not-iso-utc" "GO"

set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$INVALID_DIR" \
  --summary-json "$INVALID_SUMMARY" \
  --report-md "$INVALID_REPORT" \
  --max-age-sec 3600 \
  --print-summary-json 0
INVALID_RC=$?
set -e

if [[ "$INVALID_RC" -eq 0 ]]; then
  echo "expected non-zero exit code for invalid freshness case"
  exit 1
fi
assert_jq "$INVALID_SUMMARY" '.status == "fail"'
assert_jq "$INVALID_SUMMARY" '.decision == "NO-GO"'
assert_jq "$INVALID_SUMMARY" '.evidence.cycle.freshness.known == false'
assert_jq "$INVALID_SUMMARY" '.reasons | map(test("^cycle: generated_at_utc invalid ISO-8601 UTC timestamp$")) | any'

echo "integration_profile_default_gate_stability_evidence_pack: PASS"
