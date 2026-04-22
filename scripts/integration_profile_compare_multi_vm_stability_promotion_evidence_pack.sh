#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp date cat grep; do
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

write_valid_promotion_cycle_summary() {
  local path="$1"
  local generated_at="$2"
  local decision="${3:-GO}"
  local status="${4:-pass}"
  jq -n \
    --arg generated_at_utc "$generated_at" \
    --arg decision "$decision" \
    --arg status "$status" \
    '{
      version: 1,
      schema: { id: "profile_compare_multi_vm_stability_promotion_cycle_summary" },
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: 0,
      decision: $decision,
      next_operator_action: "Promotion may proceed.",
      promotion: {
        summary_exists: true,
        summary_valid_json: true,
        summary_fresh: true,
        decision: $decision,
        status: $status,
        rc: 0,
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
assert_jq "$PASS_SUMMARY" '(.next_operator_action | type) == "string" and (.next_operator_action | length) > 0'
if [[ ! -f "$PASS_REPORT" ]]; then
  echo "expected report markdown missing: $PASS_REPORT"
  exit 1
fi
if ! grep -F -- '# Profile Compare Multi-VM Stability Promotion Evidence Pack' "$PASS_REPORT" >/dev/null 2>&1; then
  echo "pass path report markdown header missing"
  cat "$PASS_REPORT"
  exit 1
fi

NOGO_DIR="$TMP_DIR/nogo"
mkdir -p "$NOGO_DIR"
NOGO_SUMMARY_SRC="$NOGO_DIR/profile_compare_multi_vm_stability_promotion_cycle_summary.json"
NOGO_SOFT_SUMMARY="$NOGO_DIR/profile_compare_multi_vm_stability_promotion_evidence_pack_soft_summary.json"
NOGO_HARD_SUMMARY="$NOGO_DIR/profile_compare_multi_vm_stability_promotion_evidence_pack_hard_summary.json"

write_valid_promotion_cycle_summary "$NOGO_SUMMARY_SRC" "$NOW_UTC" "NO-GO" "fail"

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
assert_jq "$NOGO_SOFT_SUMMARY" '.inputs.fail_on_no_go == false'

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
assert_jq "$NOGO_HARD_SUMMARY" '.inputs.fail_on_no_go == true'

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
assert_jq "$FAIL_SUMMARY" '.evidence.promotion_cycle.freshness.fresh == false'
assert_jq "$FAIL_SUMMARY" '.reasons | map(test("^promotion_cycle: stale evidence \\(age_sec=")) | any'
assert_jq "$FAIL_SUMMARY" '(.operator_next_action_command | type) == "string" and (.operator_next_action_command | length) > 0'
if [[ ! -f "$FAIL_REPORT" ]]; then
  echo "expected fail-closed report markdown missing: $FAIL_REPORT"
  exit 1
fi
if ! grep -F -- 'Refresh profile_compare_multi_vm_stability_promotion_cycle_summary.json' "$FAIL_REPORT" >/dev/null 2>&1; then
  echo "fail-closed report missing refresh guidance"
  cat "$FAIL_REPORT"
  exit 1
fi

echo "integration_profile_compare_multi_vm_stability_promotion_evidence_pack: PASS"
