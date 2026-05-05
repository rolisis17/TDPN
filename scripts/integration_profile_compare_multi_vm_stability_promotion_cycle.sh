#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp cat chmod grep wc; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/profile_compare_multi_vm_stability_promotion_cycle.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE_FILE="$TMP_DIR/promotion_cycle_capture.log"
COUNTER_FILE="$TMP_DIR/fake_cycle_counter.txt"

FAKE_CYCLE_SCRIPT="$TMP_DIR/fake_profile_compare_multi_vm_stability_cycle.sh"
cat >"$FAKE_CYCLE_SCRIPT" <<'EOF_FAKE_CYCLE'
#!/usr/bin/env bash
set -euo pipefail

capture_file="${FAKE_PROFILE_COMPARE_PROMOTION_CAPTURE_FILE:-}"
counter_file="${FAKE_PROFILE_COMPARE_PROMOTION_COUNTER_FILE:-}"
scenarios_csv="${FAKE_PROFILE_COMPARE_PROMOTION_CYCLE_SCENARIOS:-pass}"

summary_json=""
reports_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --summary-json=*)
      summary_json="${1#*=}"
      shift
      ;;
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --reports-dir=*)
      reports_dir="${1#*=}"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" ]]; then
  echo "fake cycle missing --summary-json" >&2
  exit 2
fi

cycle_index=1
if [[ -n "$counter_file" ]]; then
  mkdir -p "$(dirname "$counter_file")"
  if [[ -f "$counter_file" ]]; then
    last_idx="$(cat "$counter_file" 2>/dev/null || printf '%s' "0")"
    if [[ "$last_idx" =~ ^[0-9]+$ ]]; then
      cycle_index=$((last_idx + 1))
    fi
  fi
  printf '%s\n' "$cycle_index" >"$counter_file"
fi

IFS=',' read -r -a scenarios <<<"$scenarios_csv"
scenario="${scenarios[0]}"
if (( cycle_index <= ${#scenarios[@]} )); then
  scenario="${scenarios[$((cycle_index - 1))]}"
elif ((${#scenarios[@]} > 0)); then
  scenario="${scenarios[$((${#scenarios[@]} - 1))]}"
fi
scenario="$(printf '%s' "$scenario" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
if [[ -z "$scenario" ]]; then
  scenario="pass"
fi

if [[ -n "$capture_file" ]]; then
  printf 'cycle\tindex=%s\tscenario=%s\treports_dir=%s\tsummary_json=%s\n' \
    "$cycle_index" "$scenario" "$reports_dir" "$summary_json" >>"$capture_file"
fi

if [[ "$scenario" == "missing_summary" ]]; then
  exit 23
fi

mkdir -p "$(dirname "$summary_json")"

if [[ "$scenario" == "invalid_json" ]]; then
  printf '%s\n' '{ invalid json' >"$summary_json"
  exit 0
fi

status="pass"
decision="GO"
rc=0
failure_reason=""
if [[ "$scenario" == "warn" ]]; then
  status="warn"
elif [[ "$scenario" == "fail" ]]; then
  status="fail"
  decision="NO-GO"
  rc=1
  failure_reason="simulated_cycle_failure"
fi

jq -n \
  --arg status "$status" \
  --arg decision "$decision" \
  --arg failure_reason "$failure_reason" \
  --argjson rc "$rc" \
  '{
    version: 1,
    schema: {
      id: "profile_compare_multi_vm_stability_cycle_summary"
    },
    status: $status,
    rc: $rc,
    decision: $decision,
    failure_reason: (
      if $failure_reason == "" then null
      else $failure_reason
      end
    )
  }' >"$summary_json"

if [[ "$rc" -ne 0 ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_CYCLE
chmod +x "$FAKE_CYCLE_SCRIPT"

FAKE_PROMOTION_SCRIPT="$TMP_DIR/fake_profile_compare_multi_vm_stability_promotion_check.sh"
cat >"$FAKE_PROMOTION_SCRIPT" <<'EOF_FAKE_PROMOTION'
#!/usr/bin/env bash
set -euo pipefail

capture_file="${FAKE_PROFILE_COMPARE_PROMOTION_CAPTURE_FILE:-}"
scenario="${FAKE_PROFILE_COMPARE_PROMOTION_CHECK_SCENARIO:-go}"
summary_json=""
cycle_summary_list=""
fail_on_no_go="1"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --summary-json=*)
      summary_json="${1#*=}"
      shift
      ;;
    --cycle-summary-list)
      cycle_summary_list="${2:-}"
      shift 2
      ;;
    --cycle-summary-list=*)
      cycle_summary_list="${1#*=}"
      shift
      ;;
    --fail-on-no-go)
      fail_on_no_go="${2:-}"
      shift 2
      ;;
    --fail-on-no-go=*)
      fail_on_no_go="${1#*=}"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" ]]; then
  echo "fake promotion check missing --summary-json" >&2
  exit 2
fi
if [[ -z "$cycle_summary_list" || ! -f "$cycle_summary_list" ]]; then
  echo "fake promotion check missing --cycle-summary-list" >&2
  exit 2
fi

if [[ -n "$capture_file" ]]; then
  printf 'promotion\tscenario=%s\tfail_on_no_go=%s\tcycle_summary_list=%s\tsummary_json=%s\n' \
    "$scenario" "$fail_on_no_go" "$cycle_summary_list" "$summary_json" >>"$capture_file"
  while IFS= read -r line || [[ -n "$line" ]]; do
    printf 'list\t%s\n' "$line" >>"$capture_file"
  done <"$cycle_summary_list"
fi

mkdir -p "$(dirname "$summary_json")"
scenario="$(printf '%s' "$scenario" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"

if [[ "$scenario" == "fail_no_write" ]]; then
  exit 37
fi

if [[ "$scenario" == "success_no_write" ]]; then
  exit 0
fi

if [[ "$scenario" == "missing_decision" ]]; then
  jq -n '{
    version: 1,
    schema: { id: "profile_compare_multi_vm_stability_promotion_check_summary" },
    status: "ok",
    rc: 0,
    notes: "simulated contract with missing decision",
    violations: [],
    errors: []
  }' >"$summary_json"
  exit 0
fi

if [[ "$scenario" == "no_go" ]]; then
  promotion_rc=0
  no_go_enforced=false
  outcome_action="hold_promotion_warn_only"
  if [[ "$fail_on_no_go" == "1" ]]; then
    promotion_rc=1
    no_go_enforced=true
    outcome_action="hold_promotion_blocked"
  fi
  jq -n \
    --argjson promotion_rc "$promotion_rc" \
    --argjson no_go_enforced "$no_go_enforced" \
    --arg outcome_action "$outcome_action" \
    '{
      version: 1,
      schema: { id: "profile_compare_multi_vm_stability_promotion_check_summary" },
      decision: "NO-GO",
      status: "fail",
      rc: $promotion_rc,
      notes: "simulated NO-GO",
      operator_next_action: "Hold promotion. investigate NO-GO signal.",
      enforcement: {
        fail_on_no_go: true,
        no_go_detected: true,
        no_go_enforced: $no_go_enforced
      },
      outcome: {
        should_promote: false,
        action: $outcome_action
      },
      violations: [
        {
          code: "simulated_no_go",
          field: "observed.cycles_status_fail",
          severity: "error",
          message: "simulated NO-GO for integration coverage"
        }
      ],
      errors: []
    }' >"$summary_json"
  if [[ "$promotion_rc" -ne 0 ]]; then
    exit "$promotion_rc"
  fi
  exit 0
fi

jq -n '{
  version: 1,
  schema: { id: "profile_compare_multi_vm_stability_promotion_check_summary" },
  decision: "GO",
  status: "ok",
  rc: 0,
  notes: "simulated GO",
  operator_next_action: "Promotion may proceed.",
  enforcement: {
    fail_on_no_go: true,
    no_go_detected: false,
    no_go_enforced: false
  },
  outcome: {
    should_promote: true,
    action: "promote_allowed"
  },
  violations: [],
  errors: []
}' >"$summary_json"
exit 0
EOF_FAKE_PROMOTION
chmod +x "$FAKE_PROMOTION_SCRIPT"

echo "[profile-compare-multi-vm-stability-promotion-cycle] strict happy path"
HAPPY_SUMMARY="$TMP_DIR/promotion_cycle_happy_summary.json"
HAPPY_CAPTURE="$TMP_DIR/promotion_cycle_happy_capture.log"
HAPPY_COUNTER="$TMP_DIR/promotion_cycle_happy_counter.txt"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_STAGE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_STAGE_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
FAKE_PROFILE_COMPARE_PROMOTION_CAPTURE_FILE="$HAPPY_CAPTURE" \
FAKE_PROFILE_COMPARE_PROMOTION_COUNTER_FILE="$HAPPY_COUNTER" \
FAKE_PROFILE_COMPARE_PROMOTION_CYCLE_SCENARIOS="pass,pass,pass" \
FAKE_PROFILE_COMPARE_PROMOTION_CHECK_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/reports_happy" \
  --cycles 3 \
  --sleep-between-sec 0 \
  --cycle-arg "--sentinel-flag" \
  --summary-json "$HAPPY_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_promotion_cycle_happy.log 2>&1
happy_rc=$?
set -e

if [[ "$happy_rc" -ne 0 ]]; then
  echo "expected strict happy path rc=0, got rc=$happy_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_promotion_cycle_happy.log
  exit 1
fi
if ! jq -e '
  .schema.id == "profile_compare_multi_vm_stability_promotion_cycle_summary"
  and .status == "pass"
  and .rc == 0
  and .decision == "GO"
  and .failure_stage == null
  and .failure_reason_code == null
  and .cycle_counts.requested == 3
  and .cycle_counts.completed == 3
  and .cycle_counts.pass == 3
  and .cycle_counts.warn == 0
  and .cycle_counts.fail == 0
  and (.cycles | length) == 3
  and .promotion.contract_ok == true
  and .promotion.decision == "GO"
  and .promotion.status == "pass"
  and .promotion.rc == 0
  and .operator_next_action_command != null
  and .enforcement.no_go_enforced == false
  and .outcome.should_promote == true
  and .outcome.action == "promote_allowed"
' "$HAPPY_SUMMARY" >/dev/null 2>&1; then
  echo "strict happy-path summary mismatch"
  cat "$HAPPY_SUMMARY"
  exit 1
fi

HAPPY_LIST="$(jq -r '.artifacts.cycle_summary_list' "$HAPPY_SUMMARY")"
if [[ ! -f "$HAPPY_LIST" ]]; then
  echo "expected cycle-summary list artifact not found: $HAPPY_LIST"
  exit 1
fi
if [[ "$(wc -l <"$HAPPY_LIST")" -ne 3 ]]; then
  echo "expected deterministic cycle-summary list with 3 lines"
  cat "$HAPPY_LIST"
  exit 1
fi
if ! grep -q 'cycle_001/profile_compare_multi_vm_stability_cycle_summary.json' "$HAPPY_LIST"; then
  echo "expected cycle_001 summary in deterministic list"
  cat "$HAPPY_LIST"
  exit 1
fi
if ! grep -q 'cycle_002/profile_compare_multi_vm_stability_cycle_summary.json' "$HAPPY_LIST"; then
  echo "expected cycle_002 summary in deterministic list"
  cat "$HAPPY_LIST"
  exit 1
fi
if ! grep -q 'cycle_003/profile_compare_multi_vm_stability_cycle_summary.json' "$HAPPY_LIST"; then
  echo "expected cycle_003 summary in deterministic list"
  cat "$HAPPY_LIST"
  exit 1
fi
if [[ "$(grep -c '^cycle' "$HAPPY_CAPTURE")" -lt 3 ]]; then
  echo "expected at least 3 fake cycle invocations"
  cat "$HAPPY_CAPTURE"
  exit 1
fi
if ! grep -q '^promotion' "$HAPPY_CAPTURE"; then
  echo "expected fake promotion invocation"
  cat "$HAPPY_CAPTURE"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-promotion-cycle] NO-GO soft path when fail-on-no-go=0"
SOFT_SUMMARY="$TMP_DIR/promotion_cycle_soft_summary.json"
SOFT_CAPTURE="$TMP_DIR/promotion_cycle_soft_capture.log"
SOFT_COUNTER="$TMP_DIR/promotion_cycle_soft_counter.txt"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_STAGE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_STAGE_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
FAKE_PROFILE_COMPARE_PROMOTION_CAPTURE_FILE="$SOFT_CAPTURE" \
FAKE_PROFILE_COMPARE_PROMOTION_COUNTER_FILE="$SOFT_COUNTER" \
FAKE_PROFILE_COMPARE_PROMOTION_CYCLE_SCENARIOS="pass,pass,pass" \
FAKE_PROFILE_COMPARE_PROMOTION_CHECK_SCENARIO="no_go" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/reports_soft" \
  --cycles 3 \
  --sleep-between-sec 0 \
  --fail-on-no-go 0 \
  --summary-json "$SOFT_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_promotion_cycle_soft.log 2>&1
soft_rc=$?
set -e

if [[ "$soft_rc" -ne 0 ]]; then
  echo "expected NO-GO soft path rc=0, got rc=$soft_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_promotion_cycle_soft.log
  exit 1
fi
if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .decision == "NO-GO"
  and .failure_stage == null
  and .failure_reason_code == "simulated_no_go"
  and .promotion.contract_ok == true
  and .promotion.decision == "NO-GO"
  and .promotion.status == "fail"
  and .enforcement.no_go_enforced == false
  and .outcome.should_promote == false
  and .outcome.action == "hold_promotion_warn_only"
' "$SOFT_SUMMARY" >/dev/null 2>&1; then
  echo "NO-GO soft summary mismatch"
  cat "$SOFT_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-promotion-cycle] cycle artifact failure is fail-closed"
HARD_FAIL_SUMMARY="$TMP_DIR/promotion_cycle_hard_fail_summary.json"
HARD_FAIL_CAPTURE="$TMP_DIR/promotion_cycle_hard_fail_capture.log"
HARD_FAIL_COUNTER="$TMP_DIR/promotion_cycle_hard_fail_counter.txt"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_STAGE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_STAGE_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
FAKE_PROFILE_COMPARE_PROMOTION_CAPTURE_FILE="$HARD_FAIL_CAPTURE" \
FAKE_PROFILE_COMPARE_PROMOTION_COUNTER_FILE="$HARD_FAIL_COUNTER" \
FAKE_PROFILE_COMPARE_PROMOTION_CYCLE_SCENARIOS="pass,missing_summary" \
FAKE_PROFILE_COMPARE_PROMOTION_CHECK_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/reports_hard_fail" \
  --cycles 2 \
  --sleep-between-sec 0 \
  --fail-on-no-go 0 \
  --summary-json "$HARD_FAIL_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_promotion_cycle_hard_fail.log 2>&1
hard_fail_rc=$?
set -e

if [[ "$hard_fail_rc" -eq 0 ]]; then
  echo "expected fail-closed artifact contract path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_promotion_cycle_hard_fail.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc != 0
  and .decision == "NO-GO"
  and .failure_stage == "cycles"
  and .failure_reason == "one or more cycle runs failed to execute or produce fresh valid summary artifacts"
  and .failure_reason_code == "cycles_collection_incomplete"
  and .cycle_counts.command_failures >= 1
  and .stages.promotion_check.attempted == true
  and .promotion.contract_ok == true
  and .promotion.decision == "GO"
  and .outcome.should_promote == false
' "$HARD_FAIL_SUMMARY" >/dev/null 2>&1; then
  echo "fail-closed artifact summary mismatch"
  cat "$HARD_FAIL_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-promotion-cycle] missing promotion decision fails closed"
MISSING_DECISION_SUMMARY="$TMP_DIR/promotion_cycle_missing_decision_summary.json"
MISSING_DECISION_CAPTURE="$TMP_DIR/promotion_cycle_missing_decision_capture.log"
MISSING_DECISION_COUNTER="$TMP_DIR/promotion_cycle_missing_decision_counter.txt"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_STAGE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_STAGE_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
FAKE_PROFILE_COMPARE_PROMOTION_CAPTURE_FILE="$MISSING_DECISION_CAPTURE" \
FAKE_PROFILE_COMPARE_PROMOTION_COUNTER_FILE="$MISSING_DECISION_COUNTER" \
FAKE_PROFILE_COMPARE_PROMOTION_CYCLE_SCENARIOS="pass" \
FAKE_PROFILE_COMPARE_PROMOTION_CHECK_SCENARIO="missing_decision" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/reports_missing_decision" \
  --cycles 1 \
  --sleep-between-sec 0 \
  --summary-json "$MISSING_DECISION_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_promotion_cycle_missing_decision.log 2>&1
missing_decision_rc=$?
set -e

if [[ "$missing_decision_rc" -eq 0 ]]; then
  echo "expected missing-promotion-decision path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_promotion_cycle_missing_decision.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc != 0
  and .decision == "NO-GO"
  and .failure_stage == "promotion_check"
  and .failure_reason == "promotion check summary is missing a usable decision"
  and .failure_reason_code == "promotion_decision_unusable"
  and .promotion.contract_ok == false
  and .promotion.decision == "NO-GO"
  and .promotion.observed_decision == null
  and .outcome.should_promote == false
' "$MISSING_DECISION_SUMMARY" >/dev/null 2>&1; then
  echo "missing-decision fail-closed summary mismatch"
  cat "$MISSING_DECISION_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-promotion-cycle] promotion-check success without summary fails closed"
MISSING_PROMOTION_SUMMARY="$TMP_DIR/promotion_cycle_missing_promotion_summary.json"
MISSING_PROMOTION_CAPTURE="$TMP_DIR/promotion_cycle_missing_promotion_capture.log"
MISSING_PROMOTION_COUNTER="$TMP_DIR/promotion_cycle_missing_promotion_counter.txt"
MISSING_PROMOTION_STAGE_SUMMARY="$TMP_DIR/missing_promotion_stage_summary.json"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_STAGE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_STAGE_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
FAKE_PROFILE_COMPARE_PROMOTION_CAPTURE_FILE="$MISSING_PROMOTION_CAPTURE" \
FAKE_PROFILE_COMPARE_PROMOTION_COUNTER_FILE="$MISSING_PROMOTION_COUNTER" \
FAKE_PROFILE_COMPARE_PROMOTION_CYCLE_SCENARIOS="pass" \
FAKE_PROFILE_COMPARE_PROMOTION_CHECK_SCENARIO="success_no_write" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/reports_missing_promotion_summary" \
  --cycles 1 \
  --sleep-between-sec 0 \
  --promotion-summary-json "$MISSING_PROMOTION_STAGE_SUMMARY" \
  --summary-json "$MISSING_PROMOTION_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_promotion_cycle_missing_promotion_summary.log 2>&1
missing_promotion_rc=$?
set -e

if [[ "$missing_promotion_rc" -eq 0 ]]; then
  echo "expected promotion summary missing path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_promotion_cycle_missing_promotion_summary.log
  exit 1
fi
if ! jq -e --arg missing_stage_summary "$MISSING_PROMOTION_STAGE_SUMMARY" '
  .status == "fail"
  and .rc != 0
  and .decision == "NO-GO"
  and .failure_stage == "promotion_check"
  and .failure_reason_code == "promotion_check_summary_missing_or_invalid"
  and .stages.promotion_check.attempted == true
  and .stages.promotion_check.rc == 0
  and .promotion.summary_exists == false
  and .promotion.summary_valid_json == false
  and .promotion.contract_ok == false
  and ((.next_operator_action // "") | contains($missing_stage_summary))
  and .outcome.should_promote == false
' "$MISSING_PROMOTION_SUMMARY" >/dev/null 2>&1; then
  echo "missing promotion-summary fail-closed mismatch"
  cat "$MISSING_PROMOTION_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-promotion-cycle] stale preseeded promotion summary with success/no-write fails closed as stale"
STALE_NO_WRITE_SUMMARY="$TMP_DIR/promotion_cycle_stale_no_write_summary.json"
STALE_NO_WRITE_CAPTURE="$TMP_DIR/promotion_cycle_stale_no_write_capture.log"
STALE_NO_WRITE_COUNTER="$TMP_DIR/promotion_cycle_stale_no_write_counter.txt"
STALE_NO_WRITE_PROMOTION_SUMMARY="$TMP_DIR/stale_no_write_promotion_summary.json"
cat >"$STALE_NO_WRITE_PROMOTION_SUMMARY" <<'EOF_STALE_NO_WRITE_PROMOTION_SUMMARY'
{
  "version": 1,
  "schema": { "id": "profile_compare_multi_vm_stability_promotion_check_summary" },
  "decision": "GO",
  "status": "ok",
  "rc": 0,
  "notes": "stale preseeded go for no-write stale coverage",
  "enforcement": {
    "fail_on_no_go": true,
    "no_go_detected": false,
    "no_go_enforced": false
  },
  "outcome": {
    "should_promote": true,
    "action": "promote_allowed"
  },
  "violations": [],
  "errors": []
}
EOF_STALE_NO_WRITE_PROMOTION_SUMMARY
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_STAGE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_STAGE_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
FAKE_PROFILE_COMPARE_PROMOTION_CAPTURE_FILE="$STALE_NO_WRITE_CAPTURE" \
FAKE_PROFILE_COMPARE_PROMOTION_COUNTER_FILE="$STALE_NO_WRITE_COUNTER" \
FAKE_PROFILE_COMPARE_PROMOTION_CYCLE_SCENARIOS="pass" \
FAKE_PROFILE_COMPARE_PROMOTION_CHECK_SCENARIO="success_no_write" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/reports_stale_no_write" \
  --cycles 1 \
  --sleep-between-sec 0 \
  --promotion-summary-json "$STALE_NO_WRITE_PROMOTION_SUMMARY" \
  --summary-json "$STALE_NO_WRITE_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_promotion_cycle_stale_no_write.log 2>&1
stale_no_write_rc=$?
set -e

if [[ "$stale_no_write_rc" -eq 0 ]]; then
  echo "expected stale no-write promotion summary path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_promotion_cycle_stale_no_write.log
  exit 1
fi
if ! jq -e --arg stale_summary "$STALE_NO_WRITE_PROMOTION_SUMMARY" '
  .status == "fail"
  and .rc != 0
  and .decision == "NO-GO"
  and .failure_stage == "promotion_check"
  and .failure_reason_code == "promotion_check_summary_stale"
  and .stages.promotion_check.attempted == true
  and .stages.promotion_check.rc == 0
  and .promotion.summary_exists == true
  and .promotion.summary_valid_json == true
  and .promotion.summary_fresh == false
  and .promotion.observed_decision == "GO"
  and .promotion.observed_status == "pass"
  and ((.next_operator_action // "") | contains($stale_summary))
  and .outcome.should_promote == false
' "$STALE_NO_WRITE_SUMMARY" >/dev/null 2>&1; then
  echo "stale no-write fail-closed summary mismatch"
  cat "$STALE_NO_WRITE_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-promotion-cycle] stale preseeded GO + failing promotion command fails closed"
STALE_FAIL_SUMMARY="$TMP_DIR/promotion_cycle_stale_fail_summary.json"
STALE_FAIL_CAPTURE="$TMP_DIR/promotion_cycle_stale_fail_capture.log"
STALE_FAIL_COUNTER="$TMP_DIR/promotion_cycle_stale_fail_counter.txt"
STALE_PROMOTION_SUMMARY="$TMP_DIR/stale_preseeded_promotion_summary.json"
cat >"$STALE_PROMOTION_SUMMARY" <<'EOF_STALE_PROMOTION_SUMMARY'
{
  "version": 1,
  "schema": { "id": "profile_compare_multi_vm_stability_promotion_check_summary" },
  "decision": "GO",
  "status": "ok",
  "rc": 0,
  "notes": "stale preseeded go",
  "enforcement": {
    "fail_on_no_go": true,
    "no_go_detected": false,
    "no_go_enforced": false
  },
  "outcome": {
    "should_promote": true,
    "action": "promote_allowed"
  },
  "violations": [],
  "errors": []
}
EOF_STALE_PROMOTION_SUMMARY
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_STAGE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_STAGE_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
FAKE_PROFILE_COMPARE_PROMOTION_CAPTURE_FILE="$STALE_FAIL_CAPTURE" \
FAKE_PROFILE_COMPARE_PROMOTION_COUNTER_FILE="$STALE_FAIL_COUNTER" \
FAKE_PROFILE_COMPARE_PROMOTION_CYCLE_SCENARIOS="pass" \
FAKE_PROFILE_COMPARE_PROMOTION_CHECK_SCENARIO="fail_no_write" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/reports_stale_fail" \
  --cycles 1 \
  --sleep-between-sec 0 \
  --promotion-summary-json "$STALE_PROMOTION_SUMMARY" \
  --summary-json "$STALE_FAIL_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_promotion_cycle_stale_fail.log 2>&1
stale_fail_rc=$?
set -e

if [[ "$stale_fail_rc" -eq 0 ]]; then
  echo "expected stale-preseeded promotion failure path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_promotion_cycle_stale_fail.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc != 0
  and .decision == "NO-GO"
  and .failure_stage == "promotion_check"
  and ((.failure_reason // "") | test("promotion check command failed"))
  and .failure_reason_code == "promotion_check_command_failed"
  and .promotion.contract_ok == false
  and .promotion.decision == "NO-GO"
  and .promotion.status == "fail"
  and .promotion.observed_decision == "GO"
  and .promotion.observed_status == "pass"
  and .outcome.should_promote == false
  and .outcome.action == "hold_promotion_blocked"
' "$STALE_FAIL_SUMMARY" >/dev/null 2>&1; then
  echo "stale-preseeded promotion fail-closed summary mismatch"
  cat "$STALE_FAIL_SUMMARY"
  exit 1
fi

echo "profile compare multi-vm stability promotion cycle integration ok"
