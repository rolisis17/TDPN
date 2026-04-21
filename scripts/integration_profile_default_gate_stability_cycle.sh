#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp rg chmod; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PROFILE_DEFAULT_GATE_STABILITY_CYCLE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/profile_default_gate_stability_cycle.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

FAKE_CAPTURE_FILE="$TMP_DIR/fake_capture.log"

FAKE_RUN_SCRIPT="$TMP_DIR/fake_stability_run.sh"
cat >"$FAKE_RUN_SCRIPT" <<'EOF_FAKE_RUN'
#!/usr/bin/env bash
set -euo pipefail

scenario="${FAKE_CYCLE_RUN_SCENARIO:-pass}"
capture_file="${FAKE_CYCLE_CAPTURE_FILE:-}"
summary_json=""
reports_dir=""
runs=""
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
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" ]]; then
  echo "fake run missing --summary-json" >&2
  exit 2
fi

if [[ -n "$capture_file" ]]; then
  printf 'run\tscenario=%s\truns=%s\treports_dir=%s\tsummary_json=%s\n' \
    "$scenario" "$runs" "$reports_dir" "$summary_json" >>"$capture_file"
fi

if [[ "$scenario" == "fail" ]]; then
  echo "simulated run-stage failure" >&2
  exit 17
fi

mkdir -p "$(dirname "$summary_json")"
jq -n '{
  version: 1,
  schema: { id: "profile_default_gate_stability_summary" },
  status: "pass",
  rc: 0,
  runs_requested: 3,
  runs_completed: 3,
  runs_fail: 0,
  stability_ok: true,
  selection_policy_present_all: true,
  consistent_selection_policy: true,
  recommended_profile_counts: { "balanced": 3 },
  artifacts: { summary_json: "placeholder" }
}' >"$summary_json"
exit 0
EOF_FAKE_RUN
chmod +x "$FAKE_RUN_SCRIPT"

FAKE_CHECK_SCRIPT="$TMP_DIR/fake_stability_check.sh"
cat >"$FAKE_CHECK_SCRIPT" <<'EOF_FAKE_CHECK'
#!/usr/bin/env bash
set -euo pipefail

scenario="${FAKE_CYCLE_CHECK_SCENARIO:-go}"
capture_file="${FAKE_CYCLE_CAPTURE_FILE:-}"
summary_json=""
stability_summary_json=""
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
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" ]]; then
  echo "fake check missing --summary-json" >&2
  exit 2
fi
if [[ -z "$stability_summary_json" ]]; then
  echo "fake check missing --stability-summary-json" >&2
  exit 2
fi

if [[ -n "$capture_file" ]]; then
  printf 'check\tscenario=%s\tfail_on_no_go=%s\tstability_summary_json=%s\tsummary_json=%s\n' \
    "$scenario" "$fail_on_no_go" "$stability_summary_json" "$summary_json" >>"$capture_file"
fi

mkdir -p "$(dirname "$summary_json")"

if [[ "$scenario" == "go" ]]; then
  jq -n '{
    version: 1,
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

jq -n '{
  version: 1,
  decision: "NO-GO",
  status: "fail",
  rc: 1,
  observed: {
    modal_recommended_profile: "balanced",
    modal_support_rate_pct: 33.33
  },
  errors: ["modal support rate below threshold"]
}' >"$summary_json"

if [[ "$fail_on_no_go" == "0" ]]; then
  exit 0
fi
exit 1
EOF_FAKE_CHECK
chmod +x "$FAKE_CHECK_SCRIPT"

echo "[profile-default-gate-stability-cycle] happy path"
HAPPY_SUMMARY="$TMP_DIR/cycle_happy_summary.json"
set +e
PROFILE_DEFAULT_GATE_STABILITY_RUN_SCRIPT="$FAKE_RUN_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_CYCLE_CAPTURE_FILE="$FAKE_CAPTURE_FILE" \
FAKE_CYCLE_RUN_SCENARIO="pass" \
FAKE_CYCLE_CHECK_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "a.test" \
  --host-b "b.test" \
  --campaign-subject "inv-happy" \
  --runs 3 \
  --campaign-timeout-sec 1200 \
  --sleep-between-sec 0 \
  --reports-dir "$TMP_DIR/happy_reports" \
  --summary-json "$HAPPY_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_cycle_happy.log 2>&1
happy_rc=$?
set -e

if [[ "$happy_rc" -ne 0 ]]; then
  echo "expected happy path rc=0, got rc=$happy_rc"
  cat /tmp/integration_profile_default_gate_stability_cycle_happy.log
  exit 1
fi
if ! jq -e '
  .schema.id == "profile_default_gate_stability_cycle_summary"
  and .status == "pass"
  and .rc == 0
  and .decision == "GO"
  and .failure_stage == null
  and .stages.run.status == "pass"
  and .stages.check.attempted == true
  and .stages.check.status == "pass"
  and .check.decision == "GO"
  and .check.modal_recommended_profile == "balanced"
  and .artifacts.run_summary_json == .stages.run.summary_json
  and .artifacts.check_summary_json == .stages.check.summary_json
' "$HAPPY_SUMMARY" >/dev/null 2>&1; then
  echo "happy-path cycle summary mismatch"
  cat "$HAPPY_SUMMARY"
  exit 1
fi
if ! rg -q '^run' "$FAKE_CAPTURE_FILE"; then
  echo "expected fake run script invocation not captured"
  cat "$FAKE_CAPTURE_FILE"
  exit 1
fi
if ! rg -q '^check' "$FAKE_CAPTURE_FILE"; then
  echo "expected fake check script invocation not captured"
  cat "$FAKE_CAPTURE_FILE"
  exit 1
fi

echo "[profile-default-gate-stability-cycle] run-stage failure path"
RUN_FAIL_SUMMARY="$TMP_DIR/cycle_run_fail_summary.json"
RUN_FAIL_CAPTURE="$TMP_DIR/capture_run_fail.log"
set +e
PROFILE_DEFAULT_GATE_STABILITY_RUN_SCRIPT="$FAKE_RUN_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_CYCLE_CAPTURE_FILE="$RUN_FAIL_CAPTURE" \
FAKE_CYCLE_RUN_SCENARIO="fail" \
FAKE_CYCLE_CHECK_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "a.test" \
  --host-b "b.test" \
  --campaign-subject "inv-run-fail" \
  --reports-dir "$TMP_DIR/run_fail_reports" \
  --summary-json "$RUN_FAIL_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_cycle_run_fail.log 2>&1
run_fail_rc=$?
set -e

if [[ "$run_fail_rc" -eq 0 ]]; then
  echo "expected run-stage failure rc!=0"
  cat /tmp/integration_profile_default_gate_stability_cycle_run_fail.log
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
  echo "run-stage failure cycle summary mismatch"
  cat "$RUN_FAIL_SUMMARY"
  exit 1
fi
if rg -q '^check' "$RUN_FAIL_CAPTURE"; then
  echo "check stage should not run when run stage fails"
  cat "$RUN_FAIL_CAPTURE"
  exit 1
fi

echo "[profile-default-gate-stability-cycle] check-stage NO-GO fail-on-no-go behavior"
CHECK_FAIL_CLOSED_SUMMARY="$TMP_DIR/cycle_check_no_go_fail_closed_summary.json"
set +e
PROFILE_DEFAULT_GATE_STABILITY_RUN_SCRIPT="$FAKE_RUN_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_CYCLE_CAPTURE_FILE="$TMP_DIR/capture_check_fail_closed.log" \
FAKE_CYCLE_RUN_SCENARIO="pass" \
FAKE_CYCLE_CHECK_SCENARIO="no_go" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "a.test" \
  --host-b "b.test" \
  --campaign-subject "inv-check-fail-closed" \
  --reports-dir "$TMP_DIR/check_fail_closed_reports" \
  --summary-json "$CHECK_FAIL_CLOSED_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_cycle_check_fail_closed.log 2>&1
check_fail_closed_rc=$?
set -e

if [[ "$check_fail_closed_rc" -eq 0 ]]; then
  echo "expected check-stage fail-closed rc!=0"
  cat /tmp/integration_profile_default_gate_stability_cycle_check_fail_closed.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .decision == "NO-GO"
  and .failure_stage == "check"
  and .stages.check.attempted == true
  and .stages.check.status == "fail"
  and .check.decision == "NO-GO"
  and ((.check.errors // []) | length) >= 1
' "$CHECK_FAIL_CLOSED_SUMMARY" >/dev/null 2>&1; then
  echo "check-stage NO-GO fail-closed summary mismatch"
  cat "$CHECK_FAIL_CLOSED_SUMMARY"
  exit 1
fi

CHECK_FAIL_OPEN_SUMMARY="$TMP_DIR/cycle_check_no_go_fail_open_summary.json"
set +e
PROFILE_DEFAULT_GATE_STABILITY_RUN_SCRIPT="$FAKE_RUN_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_CYCLE_CAPTURE_FILE="$TMP_DIR/capture_check_fail_open.log" \
FAKE_CYCLE_RUN_SCENARIO="pass" \
FAKE_CYCLE_CHECK_SCENARIO="no_go" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "a.test" \
  --host-b "b.test" \
  --campaign-subject "inv-check-fail-open" \
  --reports-dir "$TMP_DIR/check_fail_open_reports" \
  --fail-on-no-go 0 \
  --summary-json "$CHECK_FAIL_OPEN_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_cycle_check_fail_open.log 2>&1
check_fail_open_rc=$?
set -e

if [[ "$check_fail_open_rc" -ne 0 ]]; then
  echo "expected check-stage NO-GO fail-open rc=0"
  cat /tmp/integration_profile_default_gate_stability_cycle_check_fail_open.log
  exit 1
fi
if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .decision == "NO-GO"
  and .failure_stage == null
  and .stages.check.attempted == true
  and .stages.check.status == "pass"
  and .check.decision == "NO-GO"
' "$CHECK_FAIL_OPEN_SUMMARY" >/dev/null 2>&1; then
  echo "check-stage NO-GO fail-open summary mismatch"
  cat "$CHECK_FAIL_OPEN_SUMMARY"
  exit 1
fi

echo "profile default gate stability cycle integration ok"
