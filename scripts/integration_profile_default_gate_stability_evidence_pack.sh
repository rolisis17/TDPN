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

assert_no_empty_emitted_strings() {
  local file="$1"
  assert_jq "$file" '[
    (.reasons[]?),
    (.evidence.run.errors[]?),
    (.evidence.check.errors[]?),
    (.evidence.cycle.errors[]?)
  ] | all((type == "string") and (length > 0))'
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
assert_jq "$PASS_SUMMARY" '(.operator_next_action_command | contains("profile-default-gate-stability-cycle")) and (.operator_next_action_command | contains("--campaign-subject INVITE_KEY"))'
assert_no_empty_emitted_strings "$PASS_SUMMARY"
if [[ ! -f "$PASS_REPORT" ]]; then
  echo "expected report markdown missing: $PASS_REPORT"
  exit 1
fi

PATH_NORM_DIR="$TMP_DIR/path_normalized"
mkdir -p "$PATH_NORM_DIR"
PATH_NORM_RUN="$PATH_NORM_DIR/profile_default_gate_stability_summary.json"
PATH_NORM_CHECK="$PATH_NORM_DIR/profile_default_gate_stability_check_summary.json"
PATH_NORM_CYCLE="$PATH_NORM_DIR/profile_default_gate_stability_cycle_summary.json"
PATH_NORM_SUMMARY="$PATH_NORM_DIR/evidence_pack_summary.json"
PATH_NORM_REPORT="$PATH_NORM_DIR/evidence_pack_report.md"

write_valid_run_summary "$PATH_NORM_RUN" "$NOW_UTC"
write_valid_check_summary "$PATH_NORM_CHECK" "$NOW_UTC" "GO"
write_valid_cycle_summary "$PATH_NORM_CYCLE" "$NOW_UTC" "GO"

PATH_NORM_RUN_NOISY="$(printf ' \r%s\r ' "$PATH_NORM_RUN")"
PATH_NORM_CHECK_NOISY="$(printf '\n%s\r\t' "$PATH_NORM_CHECK")"
PATH_NORM_CYCLE_NOISY="$(printf '\t%s \r\n' "$PATH_NORM_CYCLE")"

bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$PATH_NORM_DIR" \
  --run-summary-json "$PATH_NORM_RUN_NOISY" \
  --check-summary-json "$PATH_NORM_CHECK_NOISY" \
  --cycle-summary-json "$PATH_NORM_CYCLE_NOISY" \
  --summary-json "$PATH_NORM_SUMMARY" \
  --report-md "$PATH_NORM_REPORT" \
  --max-age-sec 3600 \
  --print-summary-json 0

assert_jq "$PATH_NORM_SUMMARY" '.status == "ok" and .decision == "GO" and .rc == 0'
assert_jq "$PATH_NORM_SUMMARY" '.artifacts.run_summary_json == .evidence.run.path'
assert_jq "$PATH_NORM_SUMMARY" '.artifacts.check_summary_json == .evidence.check.path'
assert_jq "$PATH_NORM_SUMMARY" '.artifacts.cycle_summary_json == .evidence.cycle.path'
assert_jq "$PATH_NORM_SUMMARY" '[.artifacts.run_summary_json, .artifacts.check_summary_json, .artifacts.cycle_summary_json, .evidence.run.path, .evidence.check.path, .evidence.cycle.path] | all((type == "string") and (test("[\\r\\n]") | not) and (test("^\\s|\\s$") | not))'
assert_no_empty_emitted_strings "$PATH_NORM_SUMMARY"

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
assert_no_empty_emitted_strings "$NOGO_SOFT_SUMMARY"

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
assert_no_empty_emitted_strings "$NOGO_HARD_SUMMARY"

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
assert_no_empty_emitted_strings "$MISMATCH_SUMMARY"

STATUS_FAIL_GO_DIR="$TMP_DIR/status_fail_go"
mkdir -p "$STATUS_FAIL_GO_DIR"
STATUS_FAIL_GO_RUN="$STATUS_FAIL_GO_DIR/profile_default_gate_stability_summary.json"
STATUS_FAIL_GO_CHECK="$STATUS_FAIL_GO_DIR/profile_default_gate_stability_check_summary.json"
STATUS_FAIL_GO_CYCLE="$STATUS_FAIL_GO_DIR/profile_default_gate_stability_cycle_summary.json"
STATUS_FAIL_GO_SUMMARY="$STATUS_FAIL_GO_DIR/evidence_pack_summary.json"
STATUS_FAIL_GO_REPORT="$STATUS_FAIL_GO_DIR/evidence_pack_report.md"

write_valid_run_summary "$STATUS_FAIL_GO_RUN" "$NOW_UTC"
write_valid_check_summary "$STATUS_FAIL_GO_CHECK" "$NOW_UTC" "GO"
jq -n \
  --arg generated_at_utc "$NOW_UTC" \
  '{
    version: 1,
    schema: { id: "profile_default_gate_stability_cycle_summary" },
    generated_at_utc: $generated_at_utc,
    decision: "GO",
    status: "fail",
    rc: 0
  }' >"$STATUS_FAIL_GO_CYCLE"

set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$STATUS_FAIL_GO_DIR" \
  --summary-json "$STATUS_FAIL_GO_SUMMARY" \
  --report-md "$STATUS_FAIL_GO_REPORT" \
  --fail-on-no-go 1 \
  --max-age-sec 3600 \
  --print-summary-json 0
STATUS_FAIL_GO_RC=$?
set -e

if [[ "$STATUS_FAIL_GO_RC" -eq 0 ]]; then
  echo "expected non-zero exit code when cycle status=fail despite GO tuple"
  exit 1
fi
assert_jq "$STATUS_FAIL_GO_SUMMARY" '.status == "fail" and .decision == "NO-GO" and .rc != 0'
assert_jq "$STATUS_FAIL_GO_SUMMARY" '.evidence.cycle.status.value == "fail" and .evidence.cycle.status.valid == true and .evidence.cycle.status.pass_like == false'
assert_jq "$STATUS_FAIL_GO_SUMMARY" '.evidence.cycle.rc.value == 0 and .evidence.cycle.rc.valid == true and .evidence.cycle.rc.zero == true'
assert_jq "$STATUS_FAIL_GO_SUMMARY" '(.reasons | map(test("^cycle: status is fail \\(expected pass/ok\\)$")) | any)'
assert_jq "$STATUS_FAIL_GO_SUMMARY" '(.operator_next_action_command | contains("profile-default-gate-stability-cycle")) and (.operator_next_action_command | contains("--campaign-subject INVITE_KEY"))'
assert_no_empty_emitted_strings "$STATUS_FAIL_GO_SUMMARY"

RC_NONZERO_GO_DIR="$TMP_DIR/rc_nonzero_go"
mkdir -p "$RC_NONZERO_GO_DIR"
RC_NONZERO_GO_RUN="$RC_NONZERO_GO_DIR/profile_default_gate_stability_summary.json"
RC_NONZERO_GO_CHECK="$RC_NONZERO_GO_DIR/profile_default_gate_stability_check_summary.json"
RC_NONZERO_GO_CYCLE="$RC_NONZERO_GO_DIR/profile_default_gate_stability_cycle_summary.json"
RC_NONZERO_GO_SUMMARY="$RC_NONZERO_GO_DIR/evidence_pack_summary.json"
RC_NONZERO_GO_REPORT="$RC_NONZERO_GO_DIR/evidence_pack_report.md"

write_valid_run_summary "$RC_NONZERO_GO_RUN" "$NOW_UTC"
write_valid_check_summary "$RC_NONZERO_GO_CHECK" "$NOW_UTC" "GO"
jq -n \
  --arg generated_at_utc "$NOW_UTC" \
  '{
    version: 1,
    schema: { id: "profile_default_gate_stability_cycle_summary" },
    generated_at_utc: $generated_at_utc,
    decision: "GO",
    status: "pass",
    rc: 7
  }' >"$RC_NONZERO_GO_CYCLE"

set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$RC_NONZERO_GO_DIR" \
  --summary-json "$RC_NONZERO_GO_SUMMARY" \
  --report-md "$RC_NONZERO_GO_REPORT" \
  --fail-on-no-go 1 \
  --max-age-sec 3600 \
  --print-summary-json 0
RC_NONZERO_GO_RC=$?
set -e

if [[ "$RC_NONZERO_GO_RC" -eq 0 ]]; then
  echo "expected non-zero exit code when cycle rc!=0 despite GO tuple"
  exit 1
fi
assert_jq "$RC_NONZERO_GO_SUMMARY" '.status == "fail" and .decision == "NO-GO" and .rc != 0'
assert_jq "$RC_NONZERO_GO_SUMMARY" '.evidence.cycle.status.value == "pass" and .evidence.cycle.status.valid == true and .evidence.cycle.status.pass_like == true'
assert_jq "$RC_NONZERO_GO_SUMMARY" '.evidence.cycle.rc.value == 7 and .evidence.cycle.rc.valid == true and .evidence.cycle.rc.zero == false'
assert_jq "$RC_NONZERO_GO_SUMMARY" '(.reasons | map(test("^cycle: rc is 7 \\(expected 0\\)$")) | any)'
assert_jq "$RC_NONZERO_GO_SUMMARY" '(.operator_next_action_command | contains("profile-default-gate-stability-cycle")) and (.operator_next_action_command | contains("--campaign-subject INVITE_KEY"))'
assert_no_empty_emitted_strings "$RC_NONZERO_GO_SUMMARY"

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
assert_jq "$MISSING_SUMMARY" '(.operator_next_action_command | contains("profile-default-gate-stability-cycle")) and (.operator_next_action_command | contains("--campaign-subject INVITE_KEY"))'
assert_no_empty_emitted_strings "$MISSING_SUMMARY"

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
assert_no_empty_emitted_strings "$INVALID_SUMMARY"

echo "integration_profile_default_gate_stability_evidence_pack: PASS"
