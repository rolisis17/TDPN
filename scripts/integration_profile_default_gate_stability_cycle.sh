#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp grep chmod; do
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
host_a=""
host_b=""
campaign_subject=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host-a)
      host_a="${2:-}"
      shift 2
      ;;
    --host-a=*)
      host_a="${1#*=}"
      shift
      ;;
    --host-b)
      host_b="${2:-}"
      shift 2
      ;;
    --host-b=*)
      host_b="${1#*=}"
      shift
      ;;
    --campaign-subject)
      campaign_subject="${2:-}"
      shift 2
      ;;
    --campaign-subject=*)
      campaign_subject="${1#*=}"
      shift
      ;;
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
  printf 'run\tscenario=%s\thost_a=%s\thost_b=%s\tcampaign_subject=%s\truns=%s\treports_dir=%s\tsummary_json=%s\n' \
    "$scenario" "$host_a" "$host_b" "$campaign_subject" "$runs" "$reports_dir" "$summary_json" >>"$capture_file"
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
require_decision_consensus=""
require_modal_decision=""
require_modal_decision_support_rate_pct=""
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
    --require-decision-consensus)
      require_decision_consensus="${2:-}"
      shift 2
      ;;
    --require-decision-consensus=*)
      require_decision_consensus="${1#*=}"
      shift
      ;;
    --require-modal-decision)
      require_modal_decision="${2:-}"
      shift 2
      ;;
    --require-modal-decision=*)
      require_modal_decision="${1#*=}"
      shift
      ;;
    --require-modal-decision-support-rate-pct)
      require_modal_decision_support_rate_pct="${2:-}"
      shift 2
      ;;
    --require-modal-decision-support-rate-pct=*)
      require_modal_decision_support_rate_pct="${1#*=}"
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
  printf 'check\tscenario=%s\tfail_on_no_go=%s\trequire_decision_consensus=%s\trequire_modal_decision=%s\trequire_modal_decision_support_rate_pct=%s\tstability_summary_json=%s\tsummary_json=%s\n' \
    "$scenario" "$fail_on_no_go" "$require_decision_consensus" "$require_modal_decision" "$require_modal_decision_support_rate_pct" "$stability_summary_json" "$summary_json" >>"$capture_file"
fi

mkdir -p "$(dirname "$summary_json")"

if [[ "$scenario" == "go" ]]; then
  jq -n '{
    version: 1,
    schema: { id: "profile_default_gate_stability_check_summary" },
    decision: "GO",
    status: "ok",
    rc: 0,
    enforcement: {
      fail_on_no_go: true,
      no_go_detected: false,
      no_go_enforced: false
    },
    outcome: {
      should_promote: true,
      action: "promote_allowed"
    },
    observed: {
      modal_recommended_profile: "balanced",
      modal_support_rate_pct: 100
    },
    errors: []
  }' >"$summary_json"
  exit 0
fi

if [[ "$scenario" == "invalid" ]]; then
  jq -n '{
    version: 1,
    status: "fail",
    rc: 0,
    errors: ["invalid check summary shape"]
  }' >"$summary_json"
  exit 0
fi

if [[ "$scenario" == "missing_decision" ]]; then
  jq -n '{
    version: 1,
    schema: { id: "profile_default_gate_stability_check_summary" },
    status: "fail",
    rc: 0,
    observed: {
      modal_recommended_profile: "balanced",
      modal_support_rate_pct: 33.33
    },
    errors: ["decision missing from check summary"]
  }' >"$summary_json"
  exit 0
fi

jq -n '{
  version: 1,
  schema: { id: "profile_default_gate_stability_check_summary" },
  decision: "NO-GO",
  status: "fail",
  rc: 1,
  enforcement: {
    fail_on_no_go: true,
    no_go_detected: true,
    no_go_enforced: true
  },
  outcome: {
    should_promote: false,
    action: "hold_promotion_blocked"
  },
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
  --subject "inv-happy" \
  --runs 3 \
  --campaign-timeout-sec 1200 \
  --sleep-between-sec 0 \
  --require-decision-consensus 1 \
  --require-modal-decision GO \
  --require-modal-decision-support-rate-pct 70 \
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
  and .check.summary_schema_valid == true
  and .check.has_usable_decision == true
  and .check.modal_recommended_profile == "balanced"
  and .inputs.check.policy.require_decision_consensus == true
  and .inputs.check.policy.require_modal_decision == "GO"
  and .inputs.check.policy.require_modal_decision_support_rate_pct == 70
  and .enforcement.no_go_enforced == false
  and .outcome.should_promote == true
  and .outcome.action == "promote_allowed"
  and .artifacts.run_summary_json == .stages.run.summary_json
  and .artifacts.check_summary_json == .stages.check.summary_json
' "$HAPPY_SUMMARY" >/dev/null 2>&1; then
  echo "happy-path cycle summary mismatch"
  cat "$HAPPY_SUMMARY"
  exit 1
fi
if ! grep -q '^run' "$FAKE_CAPTURE_FILE"; then
  echo "expected fake run script invocation not captured"
  cat "$FAKE_CAPTURE_FILE"
  exit 1
fi
if ! grep -q '^check' "$FAKE_CAPTURE_FILE"; then
  echo "expected fake check script invocation not captured"
  cat "$FAKE_CAPTURE_FILE"
  exit 1
fi
if ! grep -q $'check\t.*\trequire_decision_consensus=1\trequire_modal_decision=GO\trequire_modal_decision_support_rate_pct=70\t' "$FAKE_CAPTURE_FILE"; then
  echo "expected check-stage policy forwarding not captured"
  cat "$FAKE_CAPTURE_FILE"
  exit 1
fi

echo "[profile-default-gate-stability-cycle] default require-modal-decision policy aligns with check"
DEFAULT_POLICY_SUMMARY="$TMP_DIR/cycle_default_policy_summary.json"
DEFAULT_POLICY_CAPTURE="$TMP_DIR/capture_default_policy.log"
set +e
PROFILE_DEFAULT_GATE_STABILITY_RUN_SCRIPT="$FAKE_RUN_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_CYCLE_CAPTURE_FILE="$DEFAULT_POLICY_CAPTURE" \
FAKE_CYCLE_RUN_SCENARIO="pass" \
FAKE_CYCLE_CHECK_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "a.test" \
  --host-b "b.test" \
  --campaign-subject "inv-default-policy" \
  --reports-dir "$TMP_DIR/default_policy_reports" \
  --summary-json "$DEFAULT_POLICY_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_cycle_default_policy.log 2>&1
default_policy_rc=$?
set -e

if [[ "$default_policy_rc" -ne 0 ]]; then
  echo "expected default policy path rc=0, got rc=$default_policy_rc"
  cat /tmp/integration_profile_default_gate_stability_cycle_default_policy.log
  exit 1
fi
if ! grep -q $'check\t.*\trequire_modal_decision=GO\t' "$DEFAULT_POLICY_CAPTURE"; then
  echo "expected default check modal-decision policy forwarding to GO"
  cat "$DEFAULT_POLICY_CAPTURE"
  exit 1
fi
if ! jq -e '
  .inputs.check.policy.require_modal_decision == "GO"
  and .check.summary_schema_valid == true
  and .check.has_usable_decision == true
' "$DEFAULT_POLICY_SUMMARY" >/dev/null 2>&1; then
  echo "expected default policy summary fields missing"
  cat "$DEFAULT_POLICY_SUMMARY"
  exit 1
fi

echo "[profile-default-gate-stability-cycle] HOST_A/HOST_B/INVITE_KEY placeholders resolve from env when provided"
PLACEHOLDER_RESOLVED_SUMMARY="$TMP_DIR/cycle_placeholder_resolved_summary.json"
PLACEHOLDER_RESOLVED_CAPTURE="$TMP_DIR/capture_placeholder_resolved.log"
set +e
A_HOST="198.51.100.10" \
B_HOST="198.51.100.20" \
PROFILE_DEFAULT_GATE_STABILITY_CAMPAIGN_SUBJECT="inv-placeholder-env" \
PROFILE_DEFAULT_GATE_STABILITY_RUN_SCRIPT="$FAKE_RUN_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_CYCLE_CAPTURE_FILE="$PLACEHOLDER_RESOLVED_CAPTURE" \
FAKE_CYCLE_RUN_SCENARIO="pass" \
FAKE_CYCLE_CHECK_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "HOST_A" \
  --host-b "HOST_B" \
  --campaign-subject "INVITE_KEY" \
  --reports-dir "$TMP_DIR/placeholder_resolved_reports" \
  --summary-json "$PLACEHOLDER_RESOLVED_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_cycle_placeholder_resolved.log 2>&1
placeholder_resolved_rc=$?
set -e

if [[ "$placeholder_resolved_rc" -ne 0 ]]; then
  echo "expected placeholder env-resolution path rc=0, got rc=$placeholder_resolved_rc"
  cat /tmp/integration_profile_default_gate_stability_cycle_placeholder_resolved.log
  exit 1
fi
if ! grep -q $'run\t.*\thost_a=198.51.100.10\thost_b=198.51.100.20\tcampaign_subject=inv-placeholder-env\t' "$PLACEHOLDER_RESOLVED_CAPTURE"; then
  echo "expected run-stage placeholder substitutions were not forwarded"
  cat "$PLACEHOLDER_RESOLVED_CAPTURE"
  exit 1
fi
if ! jq -e '
  .inputs.host_a == "198.51.100.10"
  and .inputs.host_b == "198.51.100.20"
  and .inputs.campaign_subject == "inv-placeholder-env"
' "$PLACEHOLDER_RESOLVED_SUMMARY" >/dev/null 2>&1; then
  echo "placeholder env-resolution summary mismatch"
  cat "$PLACEHOLDER_RESOLVED_SUMMARY"
  exit 1
fi

echo "[profile-default-gate-stability-cycle] unresolved host placeholders fail closed before stages run"
HOST_PLACEHOLDER_FAIL_CAPTURE="$TMP_DIR/capture_host_placeholder_fail.log"
set +e
A_HOST="" \
B_HOST="" \
PROFILE_DEFAULT_GATE_STABILITY_CAMPAIGN_SUBJECT="" \
PROFILE_DEFAULT_GATE_STABILITY_RUN_SCRIPT="$FAKE_RUN_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_CYCLE_CAPTURE_FILE="$HOST_PLACEHOLDER_FAIL_CAPTURE" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "HOST_A" \
  --host-b "HOST_B" \
  --campaign-subject "INVITE_KEY" \
  --reports-dir "$TMP_DIR/host_placeholder_fail_reports" \
  --summary-json "$TMP_DIR/cycle_host_placeholder_fail_summary.json" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_cycle_host_placeholder_fail.log 2>&1
host_placeholder_fail_rc=$?
set -e

if [[ "$host_placeholder_fail_rc" -ne 2 ]]; then
  echo "expected unresolved host placeholder path to return rc=2, got rc=$host_placeholder_fail_rc"
  cat /tmp/integration_profile_default_gate_stability_cycle_host_placeholder_fail.log
  exit 1
fi
if ! grep -q -- "--host-a uses placeholder token 'HOST_A'" /tmp/integration_profile_default_gate_stability_cycle_host_placeholder_fail.log; then
  echo "expected unresolved host placeholder error message not found"
  cat /tmp/integration_profile_default_gate_stability_cycle_host_placeholder_fail.log
  exit 1
fi
if [[ -s "$HOST_PLACEHOLDER_FAIL_CAPTURE" ]]; then
  echo "run/check stages should not execute when host placeholders are unresolved"
  cat "$HOST_PLACEHOLDER_FAIL_CAPTURE"
  exit 1
fi

echo "[profile-default-gate-stability-cycle] unresolved INVITE_KEY subject placeholder fails closed"
set +e
A_HOST="" \
B_HOST="" \
PROFILE_DEFAULT_GATE_STABILITY_CAMPAIGN_SUBJECT="" \
INVITE_KEY="" \
PROFILE_DEFAULT_GATE_STABILITY_RUN_SCRIPT="$FAKE_RUN_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_CYCLE_CAPTURE_FILE="$TMP_DIR/capture_subject_placeholder_fail.log" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "a.test" \
  --host-b "b.test" \
  --campaign-subject "INVITE_KEY" \
  --reports-dir "$TMP_DIR/subject_placeholder_fail_reports" \
  --summary-json "$TMP_DIR/cycle_subject_placeholder_fail_summary.json" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_cycle_subject_placeholder_fail.log 2>&1
subject_placeholder_fail_rc=$?
set -e

if [[ "$subject_placeholder_fail_rc" -ne 2 ]]; then
  echo "expected unresolved subject placeholder path to return rc=2, got rc=$subject_placeholder_fail_rc"
  cat /tmp/integration_profile_default_gate_stability_cycle_subject_placeholder_fail.log
  exit 1
fi
if ! grep -q -- "--campaign-subject/--subject uses placeholder token 'INVITE_KEY'" /tmp/integration_profile_default_gate_stability_cycle_subject_placeholder_fail.log; then
  echo "expected unresolved subject placeholder error message not found"
  cat /tmp/integration_profile_default_gate_stability_cycle_subject_placeholder_fail.log
  exit 1
fi

echo "[profile-default-gate-stability-cycle] conflicting --campaign-subject/--subject is rejected"
set +e
PROFILE_DEFAULT_GATE_STABILITY_RUN_SCRIPT="$FAKE_RUN_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_CYCLE_CAPTURE_FILE="$TMP_DIR/capture_conflict.log" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "a.test" \
  --host-b "b.test" \
  --campaign-subject "inv-one" \
  --subject "inv-two" \
  --reports-dir "$TMP_DIR/conflict_reports" \
  --summary-json "$TMP_DIR/cycle_conflict_summary.json" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_cycle_conflict.log 2>&1
conflict_rc=$?
set -e

if [[ "$conflict_rc" -ne 2 ]]; then
  echo "expected conflicting subject values to return rc=2, got rc=$conflict_rc"
  cat /tmp/integration_profile_default_gate_stability_cycle_conflict.log
  exit 1
fi
if ! grep -q 'conflicting subject values' /tmp/integration_profile_default_gate_stability_cycle_conflict.log; then
  echo "expected conflicting subject error message not found"
  cat /tmp/integration_profile_default_gate_stability_cycle_conflict.log
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
if grep -q '^check' "$RUN_FAIL_CAPTURE"; then
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
  and .stages.check.status == "fail"
  and .stages.check.rc == 0
  and .check.decision == "NO-GO"
' "$CHECK_FAIL_OPEN_SUMMARY" >/dev/null 2>&1; then
  echo "check-stage NO-GO fail-open summary mismatch"
  cat "$CHECK_FAIL_OPEN_SUMMARY"
  exit 1
fi

echo "[profile-default-gate-stability-cycle] malformed check summary fails closed even with fail-on-no-go=0"
CHECK_INVALID_SUMMARY="$TMP_DIR/cycle_check_invalid_summary.json"
set +e
PROFILE_DEFAULT_GATE_STABILITY_RUN_SCRIPT="$FAKE_RUN_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_CYCLE_CAPTURE_FILE="$TMP_DIR/capture_check_invalid.log" \
FAKE_CYCLE_RUN_SCENARIO="pass" \
FAKE_CYCLE_CHECK_SCENARIO="invalid" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "a.test" \
  --host-b "b.test" \
  --campaign-subject "inv-check-invalid" \
  --reports-dir "$TMP_DIR/check_invalid_reports" \
  --fail-on-no-go 0 \
  --summary-json "$CHECK_INVALID_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_cycle_check_invalid.log 2>&1
check_invalid_rc=$?
set -e

if [[ "$check_invalid_rc" -eq 0 ]]; then
  echo "expected malformed check summary to fail closed with rc!=0"
  cat /tmp/integration_profile_default_gate_stability_cycle_check_invalid.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc != 0
  and .decision == "NO-GO"
  and .failure_stage == "check"
  and ((.failure_reason // "") | test("schema.id mismatch"))
  and .stages.check.status == "fail"
  and .stages.check.rc == 0
  and .check.summary_valid_json == true
  and .check.summary_schema_valid == false
  and .check.decision == null
' "$CHECK_INVALID_SUMMARY" >/dev/null 2>&1; then
  echo "malformed check summary fail-closed mismatch"
  cat "$CHECK_INVALID_SUMMARY"
  exit 1
fi

echo "[profile-default-gate-stability-cycle] check summary without usable decision fails closed"
CHECK_MISSING_DECISION_SUMMARY="$TMP_DIR/cycle_check_missing_decision_summary.json"
set +e
PROFILE_DEFAULT_GATE_STABILITY_RUN_SCRIPT="$FAKE_RUN_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_CYCLE_CAPTURE_FILE="$TMP_DIR/capture_check_missing_decision.log" \
FAKE_CYCLE_RUN_SCENARIO="pass" \
FAKE_CYCLE_CHECK_SCENARIO="missing_decision" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "a.test" \
  --host-b "b.test" \
  --campaign-subject "inv-check-missing-decision" \
  --reports-dir "$TMP_DIR/check_missing_decision_reports" \
  --summary-json "$CHECK_MISSING_DECISION_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_cycle_check_missing_decision.log 2>&1
check_missing_decision_rc=$?
set -e

if [[ "$check_missing_decision_rc" -eq 0 ]]; then
  echo "expected missing-decision summary to fail closed with rc!=0"
  cat /tmp/integration_profile_default_gate_stability_cycle_check_missing_decision.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc != 0
  and .decision == "NO-GO"
  and .failure_stage == "check"
  and ((.failure_reason // "") | test("missing a usable decision"))
  and .stages.check.status == "fail"
  and .stages.check.rc == 0
  and .check.summary_valid_json == true
  and .check.summary_schema_valid == true
  and .check.has_usable_decision == false
  and .check.decision == null
' "$CHECK_MISSING_DECISION_SUMMARY" >/dev/null 2>&1; then
  echo "missing-decision fail-closed summary mismatch"
  cat "$CHECK_MISSING_DECISION_SUMMARY"
  exit 1
fi

echo "profile default gate stability cycle integration ok"
