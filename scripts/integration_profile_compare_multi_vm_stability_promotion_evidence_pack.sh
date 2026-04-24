#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Keep evidence-pack selection hermetic from ambient environment.
unset PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_EVIDENCE_PACK_REPORTS_DIR || true
unset PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_EVIDENCE_PACK_PROMOTION_CYCLE_SUMMARY_JSON || true
unset PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_EVIDENCE_PACK_FAIL_ON_NO_GO || true
unset PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_EVIDENCE_PACK_MAX_AGE_SEC || true
unset PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_EVIDENCE_PACK_SUMMARY_JSON || true
unset PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_EVIDENCE_PACK_REPORT_MD || true
unset PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_EVIDENCE_PACK_PRINT_SUMMARY_JSON || true
unset REPORTS_DIR || true

for cmd in bash jq mktemp date cat grep sleep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_EVIDENCE_PACK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/profile_compare_multi_vm_stability_promotion_evidence_pack.sh}"
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

assert_no_blank_reason_error_entries() {
  local file="$1"
  assert_jq "$file" '
    ([.reasons[]?, .evidence.promotion_cycle.errors[]?]
      | map(select((type == "string") and ((gsub("^\\s+|\\s+$"; "") | length) == 0)))
      | length) == 0
  '
}

write_valid_promotion_cycle_summary() {
  local path="$1"
  local generated_at="$2"
  local decision="${3:-GO}"
  local status="${4:-pass}"
  local rc="${5:-0}"
  jq -n \
    --arg generated_at_utc "$generated_at" \
    --arg decision "$decision" \
    --arg status "$status" \
    --argjson rc "$rc" \
    '{
      version: 1,
      schema: { id: "profile_compare_multi_vm_stability_promotion_cycle_summary" },
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $rc,
      decision: $decision,
      next_operator_action: "Promotion may proceed.",
      promotion: {
        summary_exists: true,
        summary_valid_json: true,
        summary_fresh: true,
        decision: $decision,
        status: $status,
        rc: $rc,
        next_operator_action: "Promotion may proceed."
      },
      outcome: {
        next_operator_action: "Promotion may proceed."
      }
    }' >"$path"
}

NOW_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

PASS_DIR="$TMP_DIR/pass"
mkdir -p "$PASS_DIR"
PASS_SUMMARY_SRC="$PASS_DIR/profile_compare_multi_vm_stability_promotion_cycle_summary.json"
PASS_SUMMARY="$PASS_DIR/profile_compare_multi_vm_stability_promotion_evidence_pack_summary.json"
PASS_REPORT="$PASS_DIR/profile_compare_multi_vm_stability_promotion_evidence_pack_report.md"

write_valid_promotion_cycle_summary "$PASS_SUMMARY_SRC" "$NOW_UTC" "GO" "pass"

bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$PASS_DIR" \
  --promotion-cycle-summary-json "$PASS_SUMMARY_SRC" \
  --summary-json "$PASS_SUMMARY" \
  --report-md "$PASS_REPORT" \
  --max-age-sec 3600 \
  --print-summary-json 0

assert_jq "$PASS_SUMMARY" '.schema.id == "profile_compare_multi_vm_stability_promotion_evidence_pack_summary"'
assert_jq "$PASS_SUMMARY" '.status == "ok"'
assert_jq "$PASS_SUMMARY" '.rc == 0'
assert_jq "$PASS_SUMMARY" '.decision == "GO"'
assert_jq "$PASS_SUMMARY" '.evidence.promotion_cycle.usable == true'
assert_jq "$PASS_SUMMARY" '.failure_reason_code == null'
assert_jq "$PASS_SUMMARY" '(.reason_details | length) == 0'
assert_jq "$PASS_SUMMARY" '(.next_operator_action | type) == "string" and (.next_operator_action | length) > 0'
assert_jq "$PASS_SUMMARY" '(.inputs.rerun_guidance.refresh_promotion_cycle_command | type) == "string" and (.inputs.rerun_guidance.refresh_promotion_cycle_command | length) > 0'
assert_jq "$PASS_SUMMARY" '(.inputs.rerun_guidance.rebuild_evidence_pack_command | type) == "string" and (.inputs.rerun_guidance.rebuild_evidence_pack_command | length) > 0'
assert_no_blank_reason_error_entries "$PASS_SUMMARY"
if [[ ! -f "$PASS_REPORT" ]]; then
  echo "expected report markdown missing: $PASS_REPORT"
  exit 1
fi
if ! grep -F -- '# Profile Compare Multi-VM Stability Promotion Evidence Pack' "$PASS_REPORT" >/dev/null 2>&1; then
  echo "pass path report markdown header missing"
  cat "$PASS_REPORT"
  exit 1
fi

GO_WARN_DIR="$TMP_DIR/go_warn"
mkdir -p "$GO_WARN_DIR"
GO_WARN_SUMMARY_SRC="$GO_WARN_DIR/profile_compare_multi_vm_stability_promotion_cycle_summary.json"
GO_WARN_SUMMARY="$GO_WARN_DIR/profile_compare_multi_vm_stability_promotion_evidence_pack_summary.json"
GO_WARN_REPORT="$GO_WARN_DIR/profile_compare_multi_vm_stability_promotion_evidence_pack_report.md"

write_valid_promotion_cycle_summary "$GO_WARN_SUMMARY_SRC" "$NOW_UTC" "GO" "warn" 0

set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$GO_WARN_DIR" \
  --promotion-cycle-summary-json "$GO_WARN_SUMMARY_SRC" \
  --summary-json "$GO_WARN_SUMMARY" \
  --report-md "$GO_WARN_REPORT" \
  --fail-on-no-go 0 \
  --max-age-sec 3600 \
  --print-summary-json 0
GO_WARN_RC=$?
set -e

if [[ "$GO_WARN_RC" -eq 0 ]]; then
  echo "expected non-zero exit code for GO source with warn status"
  exit 1
fi
assert_jq "$GO_WARN_SUMMARY" '.status == "fail" and .rc != 0 and .decision == "NO-GO"'
assert_jq "$GO_WARN_SUMMARY" '.failure_reason_code == "promotion_cycle_go_requires_pass_status"'
assert_jq "$GO_WARN_SUMMARY" '.evidence.promotion_cycle.usable == false'
assert_jq "$GO_WARN_SUMMARY" '.evidence.promotion_cycle.decision.normalized == "GO"'
assert_jq "$GO_WARN_SUMMARY" '.evidence.promotion_cycle.decision.status_rc_contract_valid == false'
assert_jq "$GO_WARN_SUMMARY" '.evidence.promotion_cycle.status.normalized == "warn"'
assert_jq "$GO_WARN_SUMMARY" '.evidence.promotion_cycle.rc.value == 0'
assert_jq "$GO_WARN_SUMMARY" '.reasons | map(test("^promotion_cycle: GO decision requires pass/ok status")) | any'
assert_jq "$GO_WARN_SUMMARY" '((.reason_details | map(.code) | index("promotion_cycle_go_requires_pass_status")) != null)'
if ! jq -e --arg artifact "$GO_WARN_SUMMARY_SRC" '.next_operator_action | contains($artifact)' "$GO_WARN_SUMMARY" >/dev/null; then
  echo "GO warn fail-closed summary missing concrete artifact path in next_operator_action"
  cat "$GO_WARN_SUMMARY"
  exit 1
fi
assert_no_blank_reason_error_entries "$GO_WARN_SUMMARY"

GO_RC_NONZERO_DIR="$TMP_DIR/go_rc_nonzero"
mkdir -p "$GO_RC_NONZERO_DIR"
GO_RC_NONZERO_SUMMARY_SRC="$GO_RC_NONZERO_DIR/profile_compare_multi_vm_stability_promotion_cycle_summary.json"
GO_RC_NONZERO_SUMMARY="$GO_RC_NONZERO_DIR/profile_compare_multi_vm_stability_promotion_evidence_pack_summary.json"
GO_RC_NONZERO_REPORT="$GO_RC_NONZERO_DIR/profile_compare_multi_vm_stability_promotion_evidence_pack_report.md"

write_valid_promotion_cycle_summary "$GO_RC_NONZERO_SUMMARY_SRC" "$NOW_UTC" "GO" "pass" 5

set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$GO_RC_NONZERO_DIR" \
  --promotion-cycle-summary-json "$GO_RC_NONZERO_SUMMARY_SRC" \
  --summary-json "$GO_RC_NONZERO_SUMMARY" \
  --report-md "$GO_RC_NONZERO_REPORT" \
  --fail-on-no-go 0 \
  --max-age-sec 3600 \
  --print-summary-json 0
GO_RC_NONZERO_RC=$?
set -e

if [[ "$GO_RC_NONZERO_RC" -eq 0 ]]; then
  echo "expected non-zero exit code for GO source with non-zero rc"
  exit 1
fi
assert_jq "$GO_RC_NONZERO_SUMMARY" '.status == "fail" and .rc != 0 and .decision == "NO-GO"'
assert_jq "$GO_RC_NONZERO_SUMMARY" '.failure_reason_code == "promotion_cycle_go_requires_rc_zero"'
assert_jq "$GO_RC_NONZERO_SUMMARY" '.evidence.promotion_cycle.usable == false'
assert_jq "$GO_RC_NONZERO_SUMMARY" '.evidence.promotion_cycle.decision.normalized == "GO"'
assert_jq "$GO_RC_NONZERO_SUMMARY" '.evidence.promotion_cycle.decision.status_rc_contract_valid == false'
assert_jq "$GO_RC_NONZERO_SUMMARY" '.evidence.promotion_cycle.status.normalized == "pass"'
assert_jq "$GO_RC_NONZERO_SUMMARY" '.evidence.promotion_cycle.rc.value == 5'
assert_jq "$GO_RC_NONZERO_SUMMARY" '.reasons | map(test("^promotion_cycle: GO decision requires rc=0")) | any'
assert_jq "$GO_RC_NONZERO_SUMMARY" '((.reason_details | map(.code) | index("promotion_cycle_go_requires_rc_zero")) != null)'
if ! jq -e --arg artifact "$GO_RC_NONZERO_SUMMARY_SRC" '.next_operator_action | contains($artifact)' "$GO_RC_NONZERO_SUMMARY" >/dev/null; then
  echo "GO non-zero rc fail-closed summary missing concrete artifact path in next_operator_action"
  cat "$GO_RC_NONZERO_SUMMARY"
  exit 1
fi
assert_no_blank_reason_error_entries "$GO_RC_NONZERO_SUMMARY"

NOGO_DIR="$TMP_DIR/nogo"
mkdir -p "$NOGO_DIR"
NOGO_SUMMARY_SRC="$NOGO_DIR/profile_compare_multi_vm_stability_promotion_cycle_summary.json"
NOGO_SOFT_SUMMARY="$NOGO_DIR/profile_compare_multi_vm_stability_promotion_evidence_pack_soft_summary.json"
NOGO_HARD_SUMMARY="$NOGO_DIR/profile_compare_multi_vm_stability_promotion_evidence_pack_hard_summary.json"

write_valid_promotion_cycle_summary "$NOGO_SUMMARY_SRC" "$NOW_UTC" "NO-GO" "warn" 0

bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$NOGO_DIR" \
  --promotion-cycle-summary-json "$NOGO_SUMMARY_SRC" \
  --summary-json "$NOGO_SOFT_SUMMARY" \
  --report-md "$NOGO_DIR/profile_compare_multi_vm_stability_promotion_evidence_pack_soft_report.md" \
  --fail-on-no-go 0 \
  --max-age-sec 3600 \
  --print-summary-json 0

assert_jq "$NOGO_SOFT_SUMMARY" '.decision == "NO-GO"'
assert_jq "$NOGO_SOFT_SUMMARY" '.status == "warn"'
assert_jq "$NOGO_SOFT_SUMMARY" '.rc == 0'
assert_jq "$NOGO_SOFT_SUMMARY" '.failure_reason_code == null'
assert_jq "$NOGO_SOFT_SUMMARY" '.inputs.fail_on_no_go == false'
assert_no_blank_reason_error_entries "$NOGO_SOFT_SUMMARY"

set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$NOGO_DIR" \
  --promotion-cycle-summary-json "$NOGO_SUMMARY_SRC" \
  --summary-json "$NOGO_HARD_SUMMARY" \
  --report-md "$NOGO_DIR/profile_compare_multi_vm_stability_promotion_evidence_pack_hard_report.md" \
  --fail-on-no-go 1 \
  --max-age-sec 3600 \
  --print-summary-json 0
NOGO_HARD_RC=$?
set -e

if [[ "$NOGO_HARD_RC" -eq 0 ]]; then
  echo "expected non-zero exit code for usable NO-GO with --fail-on-no-go 1"
  exit 1
fi
assert_jq "$NOGO_HARD_SUMMARY" '.decision == "NO-GO"'
assert_jq "$NOGO_HARD_SUMMARY" '.status == "fail"'
assert_jq "$NOGO_HARD_SUMMARY" '.rc != 0'
assert_jq "$NOGO_HARD_SUMMARY" '.failure_reason_code == "promotion_cycle_decision_no_go"'
assert_jq "$NOGO_HARD_SUMMARY" '.inputs.fail_on_no_go == true'
assert_no_blank_reason_error_entries "$NOGO_HARD_SUMMARY"

DISCOVER_DIR="$TMP_DIR/discover"
mkdir -p "$DISCOVER_DIR/profile_compare_multi_vm_stability_promotion_cycle_20260101_000000"
DISCOVER_ROOT_SRC="$DISCOVER_DIR/profile_compare_multi_vm_stability_promotion_cycle_summary.json"
DISCOVER_ARCHIVE_SRC="$DISCOVER_DIR/profile_compare_multi_vm_stability_promotion_cycle_20260101_000000/profile_compare_multi_vm_stability_promotion_cycle_summary.json"
DISCOVER_SUMMARY="$DISCOVER_DIR/profile_compare_multi_vm_stability_promotion_evidence_pack_summary.json"
DISCOVER_REPORT="$DISCOVER_DIR/profile_compare_multi_vm_stability_promotion_evidence_pack_report.md"

write_valid_promotion_cycle_summary "$DISCOVER_ROOT_SRC" "2000-01-01T00:00:00Z" "NO-GO" "fail"
sleep 1
write_valid_promotion_cycle_summary "$DISCOVER_ARCHIVE_SRC" "$NOW_UTC" "GO" "pass"

set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$DISCOVER_DIR" \
  --summary-json "$DISCOVER_SUMMARY" \
  --report-md "$DISCOVER_REPORT" \
  --max-age-sec 3600 \
  --print-summary-json 0
DISCOVER_RC=$?
set -e

if [[ "$DISCOVER_RC" -ne 0 ]]; then
  echo "expected auto-discovery fresh-selection path rc=0, got rc=$DISCOVER_RC"
  cat "$DISCOVER_SUMMARY"
  exit 1
fi
if ! jq -e --arg selected_path "$DISCOVER_ARCHIVE_SRC" '
  .status == "ok"
  and .rc == 0
  and .decision == "GO"
  and .evidence.promotion_cycle.path == $selected_path
  and .evidence.promotion_cycle.freshness.fresh == true
  and .evidence.promotion_cycle.decision.normalized == "GO"
' "$DISCOVER_SUMMARY" >/dev/null; then
  echo "auto-discovery fresh-selection summary mismatch"
  cat "$DISCOVER_SUMMARY"
  exit 1
fi
assert_no_blank_reason_error_entries "$DISCOVER_SUMMARY"

DISCOVER_FALLBACK_DIR="$TMP_DIR/discover_fallback_order"
mkdir -p "$DISCOVER_FALLBACK_DIR/profile_compare_multi_vm_stability_promotion_cycle_20260101_000000"
DISCOVER_FALLBACK_ROOT_SRC="$DISCOVER_FALLBACK_DIR/profile_compare_multi_vm_stability_promotion_cycle_summary.json"
DISCOVER_FALLBACK_ARCHIVE_SRC="$DISCOVER_FALLBACK_DIR/profile_compare_multi_vm_stability_promotion_cycle_20260101_000000/profile_compare_multi_vm_stability_promotion_cycle_summary.json"
DISCOVER_FALLBACK_SUMMARY="$DISCOVER_FALLBACK_DIR/profile_compare_multi_vm_stability_promotion_evidence_pack_summary.json"
DISCOVER_FALLBACK_REPORT="$DISCOVER_FALLBACK_DIR/profile_compare_multi_vm_stability_promotion_evidence_pack_report.md"

write_valid_promotion_cycle_summary "$DISCOVER_FALLBACK_ARCHIVE_SRC" "$NOW_UTC" "GO" "pass" 0
sleep 1
write_valid_promotion_cycle_summary "$DISCOVER_FALLBACK_ROOT_SRC" "2000-01-01T00:00:00Z" "GO" "pass" 0

set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$DISCOVER_FALLBACK_DIR" \
  --summary-json "$DISCOVER_FALLBACK_SUMMARY" \
  --report-md "$DISCOVER_FALLBACK_REPORT" \
  --max-age-sec 3600 \
  --print-summary-json 0
DISCOVER_FALLBACK_RC=$?
set -e

if [[ "$DISCOVER_FALLBACK_RC" -ne 0 ]]; then
  echo "expected fallback-order path rc=0, got rc=$DISCOVER_FALLBACK_RC"
  cat "$DISCOVER_FALLBACK_SUMMARY"
  exit 1
fi
if ! jq -e --arg selected_path "$DISCOVER_FALLBACK_ARCHIVE_SRC" '
  .status == "ok"
  and .rc == 0
  and .decision == "GO"
  and .evidence.promotion_cycle.path == $selected_path
  and .inputs.promotion_cycle_summary_selection.fallback_used == true
  and .inputs.promotion_cycle_summary_selection.source == "fallback_candidate"
  and .evidence.selection.fallback_used == true
  and .evidence.selection.source == "fallback_candidate"
' "$DISCOVER_FALLBACK_SUMMARY" >/dev/null; then
  echo "fallback-order summary mismatch"
  cat "$DISCOVER_FALLBACK_SUMMARY"
  exit 1
fi
assert_no_blank_reason_error_entries "$DISCOVER_FALLBACK_SUMMARY"

FAIL_DIR="$TMP_DIR/fail"
mkdir -p "$FAIL_DIR"
FAIL_SUMMARY_SRC="$FAIL_DIR/profile_compare_multi_vm_stability_promotion_cycle_summary.json"
FAIL_SUMMARY="$FAIL_DIR/profile_compare_multi_vm_stability_promotion_evidence_pack_summary.json"
FAIL_REPORT="$FAIL_DIR/profile_compare_multi_vm_stability_promotion_evidence_pack_report.md"

write_valid_promotion_cycle_summary "$FAIL_SUMMARY_SRC" "2000-01-01T00:00:00Z" "GO" "pass"

set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$FAIL_DIR" \
  --promotion-cycle-summary-json "$FAIL_SUMMARY_SRC" \
  --summary-json "$FAIL_SUMMARY" \
  --report-md "$FAIL_REPORT" \
  --max-age-sec 3600 \
  --print-summary-json 0
FAIL_RC=$?
set -e

if [[ "$FAIL_RC" -eq 0 ]]; then
  echo "expected non-zero exit code for fail-closed freshness case"
  exit 1
fi
assert_jq "$FAIL_SUMMARY" '.status == "fail"'
assert_jq "$FAIL_SUMMARY" '.rc != 0'
assert_jq "$FAIL_SUMMARY" '.decision == "NO-GO"'
assert_jq "$FAIL_SUMMARY" '.failure_reason_code == "promotion_cycle_evidence_stale"'
assert_jq "$FAIL_SUMMARY" '.evidence.promotion_cycle.freshness.fresh == false'
assert_jq "$FAIL_SUMMARY" '.reasons | map(test("^promotion_cycle: stale evidence \\(age_sec=")) | any'
assert_jq "$FAIL_SUMMARY" '((.reason_details | map(.code) | index("promotion_cycle_evidence_stale")) != null)'
assert_jq "$FAIL_SUMMARY" '(.operator_next_action_command | type) == "string" and (.operator_next_action_command | length) > 0'
assert_jq "$FAIL_SUMMARY" '(.operator_next_action_command | contains("profile_compare_multi_vm_stability_promotion_cycle.sh"))'
assert_jq "$FAIL_SUMMARY" '(.next_operator_action | contains("Rebuild evidence pack with"))'
assert_jq "$FAIL_SUMMARY" '(.operator_next_action_commands.refresh_promotion_cycle_command | contains("profile_compare_multi_vm_stability_promotion_cycle.sh"))'
assert_jq "$FAIL_SUMMARY" '(.operator_next_action_commands.rebuild_evidence_pack_command | contains("profile_compare_multi_vm_stability_promotion_evidence_pack.sh"))'
assert_no_blank_reason_error_entries "$FAIL_SUMMARY"
if [[ ! -f "$FAIL_REPORT" ]]; then
  echo "expected fail-closed report markdown missing: $FAIL_REPORT"
  exit 1
fi
if ! grep -F -- "Refresh promotion-cycle summary artifact $FAIL_SUMMARY_SRC" "$FAIL_REPORT" >/dev/null 2>&1; then
  echo "fail-closed report missing refresh guidance"
  cat "$FAIL_REPORT"
  exit 1
fi

MISSING_DIR="$TMP_DIR/missing"
mkdir -p "$MISSING_DIR"
MISSING_SUMMARY_SRC="$MISSING_DIR/missing_profile_compare_multi_vm_stability_promotion_cycle_summary.json"
MISSING_SUMMARY="$MISSING_DIR/profile_compare_multi_vm_stability_promotion_evidence_pack_summary.json"
MISSING_REPORT="$MISSING_DIR/profile_compare_multi_vm_stability_promotion_evidence_pack_report.md"

set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$MISSING_DIR" \
  --promotion-cycle-summary-json "$MISSING_SUMMARY_SRC" \
  --summary-json "$MISSING_SUMMARY" \
  --report-md "$MISSING_REPORT" \
  --max-age-sec 3600 \
  --print-summary-json 0
MISSING_RC=$?
set -e

if [[ "$MISSING_RC" -eq 0 ]]; then
  echo "expected non-zero exit code for missing explicit promotion-cycle summary"
  exit 1
fi
assert_jq "$MISSING_SUMMARY" '.status == "fail" and .decision == "NO-GO" and .rc != 0'
assert_jq "$MISSING_SUMMARY" '.failure_reason_code == "promotion_cycle_artifact_missing"'
assert_jq "$MISSING_SUMMARY" '.reasons | map(test("^promotion_cycle: missing required evidence file:")) | any'
if ! jq -e --arg missing_src "$MISSING_SUMMARY_SRC" '.next_operator_action | contains("Refresh promotion-cycle summary artifact " + $missing_src)' "$MISSING_SUMMARY" >/dev/null; then
  echo "missing-summary next_operator_action mismatch"
  cat "$MISSING_SUMMARY"
  exit 1
fi
assert_jq "$MISSING_SUMMARY" '(.operator_next_action_command | contains("profile_compare_multi_vm_stability_promotion_cycle.sh"))'
if ! jq -e --arg missing_src "$MISSING_SUMMARY_SRC" '.operator_next_action_commands.rebuild_evidence_pack_command | contains("--promotion-cycle-summary-json " + $missing_src)' "$MISSING_SUMMARY" >/dev/null; then
  echo "missing-summary rebuild command guidance mismatch"
  cat "$MISSING_SUMMARY"
  exit 1
fi
assert_no_blank_reason_error_entries "$MISSING_SUMMARY"

echo "integration_profile_compare_multi_vm_stability_promotion_evidence_pack: PASS"
