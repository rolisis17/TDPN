#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp grep chmod cat; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PROFILE_COMPARE_MULTI_VM_STABILITY_CYCLE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/profile_compare_multi_vm_stability_cycle.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE_FILE="$TMP_DIR/cycle_capture.log"

FAKE_RUN_SCRIPT="$TMP_DIR/fake_profile_compare_multi_vm_stability_run.sh"
cat >"$FAKE_RUN_SCRIPT" <<'EOF_FAKE_RUN'
#!/usr/bin/env bash
set -euo pipefail

scenario="${FAKE_MULTI_VM_STABILITY_RUN_SCENARIO:-pass}"
capture_file="${FAKE_MULTI_VM_STABILITY_CAPTURE_FILE:-}"
summary_json=""
runs=""
sleep_between_sec=""
allow_partial=""
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
    --runs)
      runs="${2:-}"
      shift 2
      ;;
    --runs=*)
      runs="${1#*=}"
      shift
      ;;
    --sleep-between-sec)
      sleep_between_sec="${2:-}"
      shift 2
      ;;
    --sleep-between-sec=*)
      sleep_between_sec="${1#*=}"
      shift
      ;;
    --allow-partial)
      allow_partial="${2:-}"
      shift 2
      ;;
    --allow-partial=*)
      allow_partial="${1#*=}"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -n "$capture_file" ]]; then
  printf 'run\tscenario=%s\truns=%s\tsleep_between_sec=%s\tallow_partial=%s\treports_dir=%s\tsummary_json=%s\n' \
    "$scenario" "$runs" "$sleep_between_sec" "$allow_partial" "$reports_dir" "$summary_json" >>"$capture_file"
fi

if [[ "$scenario" == "fail" ]]; then
  echo "simulated run failure" >&2
  exit 17
fi

if [[ "$scenario" == "pass_no_write" ]]; then
  exit 0
fi

if [[ -z "$summary_json" ]]; then
  echo "fake run missing --summary-json" >&2
  exit 2
fi

mkdir -p "$(dirname "$summary_json")"
jq -n '{
  version: 1,
  schema: { id: "profile_compare_multi_vm_stability_run_summary" },
  status: "pass",
  counts: {
    requested: 3,
    completed: 3,
    pass: 3,
    warn: 0,
    fail: 0,
    timeout: 0
  },
  histograms: {
    recommended_profile_counts: { balanced: 3 },
    decision_counts: { GO: 3 }
  },
  modal: {
    decision: "GO",
    recommended_profile: "balanced",
    support_rate_pct: 100
  },
  runs: [
    { completed: true, decision: "GO", recommended_profile: "balanced", support_rate_pct: 100 },
    { completed: true, decision: "GO", recommended_profile: "balanced", support_rate_pct: 100 },
    { completed: true, decision: "GO", recommended_profile: "balanced", support_rate_pct: 100 }
  ]
}' >"$summary_json"
exit 0
EOF_FAKE_RUN
chmod +x "$FAKE_RUN_SCRIPT"

FAKE_CHECK_SCRIPT="$TMP_DIR/fake_profile_compare_multi_vm_stability_check.sh"
cat >"$FAKE_CHECK_SCRIPT" <<'EOF_FAKE_CHECK'
#!/usr/bin/env bash
set -euo pipefail

scenario="${FAKE_MULTI_VM_STABILITY_CHECK_SCENARIO:-go}"
capture_file="${FAKE_MULTI_VM_STABILITY_CAPTURE_FILE:-}"
summary_json=""
stability_summary_json=""
fail_on_no_go="1"
require_status_pass=""
require_decision_consensus=""

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
    --stability-summary-json)
      stability_summary_json="${2:-}"
      shift 2
      ;;
    --stability-summary-json=*)
      stability_summary_json="${1#*=}"
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
    --require-status-pass)
      require_status_pass="${2:-}"
      shift 2
      ;;
    --require-status-pass=*)
      require_status_pass="${1#*=}"
      shift
      ;;
    --require-decision-consensus)
      require_decision_consensus="${2:-}"
      shift 2
      ;;
    --require-decision-consensus=*)
      require_decision_consensus="${1#*=}"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -n "$capture_file" ]]; then
  printf 'check\tscenario=%s\tfail_on_no_go=%s\trequire_status_pass=%s\trequire_decision_consensus=%s\tstability_summary_json=%s\tsummary_json=%s\n' \
    "$scenario" "$fail_on_no_go" "$require_status_pass" "$require_decision_consensus" "$stability_summary_json" "$summary_json" >>"$capture_file"
fi

if [[ "$scenario" == "fail" ]]; then
  echo "simulated check failure" >&2
  exit 31
fi

if [[ -z "$summary_json" ]]; then
  echo "fake check missing --summary-json" >&2
  exit 2
fi

if [[ "$scenario" == "reuse" ]]; then
  if [[ ! -f "$summary_json" ]]; then
    echo "reuse scenario expects pre-existing summary file" >&2
    exit 2
  fi
  exit 0
fi

mkdir -p "$(dirname "$summary_json")"

if [[ "$scenario" == "go" ]]; then
  jq -n '{
    version: 1,
    schema: { id: "profile_compare_multi_vm_stability_check_summary" },
    decision: "GO",
    status: "ok",
    rc: 0,
    observed: {
      modal_recommended_profile: "balanced",
      modal_support_rate_pct: 100
    },
    errors: []
  }' >"$summary_json"
  exit 0
fi

check_rc=0
if [[ "$fail_on_no_go" == "1" ]]; then
  check_rc=1
fi
jq -n \
  --argjson rc "$check_rc" \
  '{
    version: 1,
    schema: { id: "profile_compare_multi_vm_stability_check_summary" },
    decision: "NO-GO",
    status: "fail",
    rc: $rc,
    observed: {
      modal_recommended_profile: "balanced",
      modal_support_rate_pct: 55
    },
    errors: ["simulated stability check no-go"]
  }' >"$summary_json"
exit "$check_rc"
EOF_FAKE_CHECK
chmod +x "$FAKE_CHECK_SCRIPT"

echo "[profile-compare-multi-vm-stability-cycle] happy path"
HAPPY_SUMMARY="$TMP_DIR/cycle_happy_summary.json"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_SCRIPT="$FAKE_RUN_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_MULTI_VM_STABILITY_CAPTURE_FILE="$CAPTURE_FILE" \
FAKE_MULTI_VM_STABILITY_RUN_SCENARIO="pass" \
FAKE_MULTI_VM_STABILITY_CHECK_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/happy_reports" \
  --runs 3 \
  --sleep-between-sec 0 \
  --allow-partial 1 \
  --require-status-pass 1 \
  --require-decision-consensus 1 \
  --summary-json "$HAPPY_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_cycle_happy.log 2>&1
happy_rc=$?
set -e

if [[ "$happy_rc" -ne 0 ]]; then
  echo "expected happy path rc=0, got rc=$happy_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_cycle_happy.log
  exit 1
fi
if ! jq -e '
  .schema.id == "profile_compare_multi_vm_stability_cycle_summary"
  and .status == "pass"
  and .rc == 0
  and .decision == "GO"
  and .failure_stage == null
  and .stages.run.attempted == true
  and .stages.run.status == "pass"
  and .stages.check.attempted == true
  and .stages.check.status == "pass"
   and .run.summary_fresh == true
   and .check.summary_fresh == true
  and .check.decision == "GO"
  and .inputs.check.policy.require_status_pass == true
  and .inputs.check.policy.require_decision_consensus == true
' "$HAPPY_SUMMARY" >/dev/null 2>&1; then
  echo "happy-path cycle summary mismatch"
  cat "$HAPPY_SUMMARY"
  exit 1
fi

if ! grep -q $'^run\t.*\truns=3\tsleep_between_sec=0\tallow_partial=1\t' "$CAPTURE_FILE"; then
  echo "expected run-stage forwarding capture not found"
  cat "$CAPTURE_FILE"
  exit 1
fi
if ! grep -q $'^check\t.*\trequire_status_pass=1\trequire_decision_consensus=1\t' "$CAPTURE_FILE"; then
  echo "expected check-stage forwarding capture not found"
  cat "$CAPTURE_FILE"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-cycle] NO-GO soft path"
SOFT_SUMMARY="$TMP_DIR/cycle_soft_summary.json"
SOFT_CAPTURE="$TMP_DIR/cycle_soft_capture.log"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_SCRIPT="$FAKE_RUN_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_MULTI_VM_STABILITY_CAPTURE_FILE="$SOFT_CAPTURE" \
FAKE_MULTI_VM_STABILITY_RUN_SCENARIO="pass" \
FAKE_MULTI_VM_STABILITY_CHECK_SCENARIO="no_go" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/soft_reports" \
  --fail-on-no-go 0 \
  --summary-json "$SOFT_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_cycle_soft.log 2>&1
soft_rc=$?
set -e

if [[ "$soft_rc" -ne 0 ]]; then
  echo "expected NO-GO soft path rc=0, got rc=$soft_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_cycle_soft.log
  exit 1
fi
if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .decision == "NO-GO"
  and .failure_stage == null
  and .stages.check.attempted == true
  and .stages.check.status == "fail"
  and .stages.check.rc == 0
  and .check.decision == "NO-GO"
' "$SOFT_SUMMARY" >/dev/null 2>&1; then
  echo "NO-GO soft cycle summary mismatch"
  cat "$SOFT_SUMMARY"
  exit 1
fi
if ! grep -q $'^check\t.*\tfail_on_no_go=0\t' "$SOFT_CAPTURE"; then
  echo "expected check fail_on_no_go=0 capture not found"
  cat "$SOFT_CAPTURE"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-cycle] run failure skips check"
RUN_FAIL_SUMMARY="$TMP_DIR/cycle_run_fail_summary.json"
RUN_FAIL_CAPTURE="$TMP_DIR/cycle_run_fail_capture.log"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_SCRIPT="$FAKE_RUN_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_MULTI_VM_STABILITY_CAPTURE_FILE="$RUN_FAIL_CAPTURE" \
FAKE_MULTI_VM_STABILITY_RUN_SCENARIO="fail" \
FAKE_MULTI_VM_STABILITY_CHECK_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/run_fail_reports" \
  --summary-json "$RUN_FAIL_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_cycle_run_fail.log 2>&1
run_fail_rc=$?
set -e

if [[ "$run_fail_rc" -eq 0 ]]; then
  echo "expected run-failure path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_cycle_run_fail.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .decision == "NO-GO"
  and .failure_stage == "run"
  and ((.failure_reason // "") | test("run"))
  and .stages.run.status == "fail"
  and .stages.check.attempted == false
  and .stages.check.status == "skip"
' "$RUN_FAIL_SUMMARY" >/dev/null 2>&1; then
  echo "run-failure cycle summary mismatch"
  cat "$RUN_FAIL_SUMMARY"
  exit 1
fi
if grep -q '^check' "$RUN_FAIL_CAPTURE"; then
  echo "check stage should not run when run stage fails"
  cat "$RUN_FAIL_CAPTURE"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-cycle] stale run summary fails closed"
STALE_RUN_INPUT="$TMP_DIR/stale_run_input_summary.json"
cat >"$STALE_RUN_INPUT" <<'EOF_STALE_RUN_INPUT'
{
  "version": 1,
  "schema": { "id": "profile_compare_multi_vm_stability_run_summary" },
  "status": "pass",
  "counts": { "requested": 3, "completed": 3, "pass": 3, "warn": 0, "fail": 0, "timeout": 0 },
  "histograms": { "recommended_profile_counts": { "balanced": 3 }, "decision_counts": { "GO": 3 } },
  "modal": { "decision": "GO", "recommended_profile": "balanced", "support_rate_pct": 100 },
  "runs": []
}
EOF_STALE_RUN_INPUT
RUN_STALE_SUMMARY="$TMP_DIR/cycle_run_stale_summary.json"
RUN_STALE_CAPTURE="$TMP_DIR/cycle_run_stale_capture.log"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_SCRIPT="$FAKE_RUN_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_MULTI_VM_STABILITY_CAPTURE_FILE="$RUN_STALE_CAPTURE" \
FAKE_MULTI_VM_STABILITY_RUN_SCENARIO="pass_no_write" \
FAKE_MULTI_VM_STABILITY_CHECK_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/run_stale_reports" \
  --run-summary-json "$STALE_RUN_INPUT" \
  --summary-json "$RUN_STALE_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_cycle_run_stale.log 2>&1
run_stale_rc=$?
set -e

if [[ "$run_stale_rc" -eq 0 ]]; then
  echo "expected stale-run path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_cycle_run_stale.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .decision == "NO-GO"
  and .failure_stage == "run"
  and ((.failure_reason // "") | test("stale"))
  and .run.summary_fresh == false
  and .stages.check.attempted == false
' "$RUN_STALE_SUMMARY" >/dev/null 2>&1; then
  echo "stale-run cycle summary mismatch"
  cat "$RUN_STALE_SUMMARY"
  exit 1
fi
if grep -q '^check' "$RUN_STALE_CAPTURE"; then
  echo "check stage should not run when run summary is stale"
  cat "$RUN_STALE_CAPTURE"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-cycle] stale check summary fails closed"
STALE_CHECK_INPUT="$TMP_DIR/stale_check_input_summary.json"
cat >"$STALE_CHECK_INPUT" <<'EOF_STALE_CHECK_INPUT'
{
  "version": 1,
  "schema": { "id": "profile_compare_multi_vm_stability_check_summary" },
  "decision": "GO",
  "status": "ok",
  "rc": 0,
  "observed": {
    "modal_recommended_profile": "balanced",
    "modal_support_rate_pct": 100
  },
  "errors": []
}
EOF_STALE_CHECK_INPUT
CHECK_STALE_SUMMARY="$TMP_DIR/cycle_check_stale_summary.json"
CHECK_STALE_CAPTURE="$TMP_DIR/cycle_check_stale_capture.log"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_SCRIPT="$FAKE_RUN_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_MULTI_VM_STABILITY_CAPTURE_FILE="$CHECK_STALE_CAPTURE" \
FAKE_MULTI_VM_STABILITY_RUN_SCENARIO="pass" \
FAKE_MULTI_VM_STABILITY_CHECK_SCENARIO="reuse" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/check_stale_reports" \
  --check-summary-json "$STALE_CHECK_INPUT" \
  --summary-json "$CHECK_STALE_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_cycle_check_stale.log 2>&1
check_stale_rc=$?
set -e

if [[ "$check_stale_rc" -eq 0 ]]; then
  echo "expected stale-check path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_cycle_check_stale.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .decision == "NO-GO"
  and .failure_stage == "check"
  and ((.failure_reason // "") | test("stale"))
  and .check.summary_fresh == false
  and .stages.check.attempted == true
' "$CHECK_STALE_SUMMARY" >/dev/null 2>&1; then
  echo "stale-check cycle summary mismatch"
  cat "$CHECK_STALE_SUMMARY"
  exit 1
fi

echo "profile compare multi-vm stability cycle integration ok"
