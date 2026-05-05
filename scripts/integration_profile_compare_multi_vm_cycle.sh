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

SCRIPT_UNDER_TEST="${PROFILE_COMPARE_MULTI_VM_CYCLE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/profile_compare_multi_vm_cycle.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

FAKE_CAPTURE_FILE="$TMP_DIR/fake_capture.log"

FAKE_SWEEP_SCRIPT="$TMP_DIR/fake_profile_compare_multi_vm_sweep.sh"
cat >"$FAKE_SWEEP_SCRIPT" <<'EOF_FAKE_SWEEP'
#!/usr/bin/env bash
set -euo pipefail

scenario="${FAKE_CYCLE_SWEEP_SCENARIO:-pass}"
capture_file="${FAKE_CYCLE_CAPTURE_FILE:-}"
summary_json=""
canonical_summary_json=""
report_md=""
vm_command_count=0
vm_command_file_count=0
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
    --canonical-summary-json)
      canonical_summary_json="${2:-}"
      shift 2
      ;;
    --canonical-summary-json=*)
      canonical_summary_json="${1#*=}"
      shift
      ;;
    --report-md)
      report_md="${2:-}"
      shift 2
      ;;
    --report-md=*)
      report_md="${1#*=}"
      shift
      ;;
    --vm-command)
      vm_command_count=$((vm_command_count + 1))
      shift 2
      ;;
    --vm-command=*)
      vm_command_count=$((vm_command_count + 1))
      shift
      ;;
    --vm-command-file)
      vm_command_file_count=$((vm_command_file_count + 1))
      shift 2
      ;;
    --vm-command-file=*)
      vm_command_file_count=$((vm_command_file_count + 1))
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" ]]; then
  echo "fake sweep missing --summary-json" >&2
  exit 2
fi

if [[ -n "$capture_file" ]]; then
  printf 'sweep\tscenario=%s\tvm_command_count=%s\tvm_command_file_count=%s\tsummary_json=%s\tcanonical_summary_json=%s\treport_md=%s\n' \
    "$scenario" "$vm_command_count" "$vm_command_file_count" "$summary_json" "$canonical_summary_json" "$report_md" >>"$capture_file"
fi

if [[ "$scenario" == "fail" ]]; then
  echo "simulated sweep failure" >&2
  exit 23
fi

input_summary_a="${FAKE_CYCLE_SWEEP_INPUT_SUMMARY_A:-$(dirname "$summary_json")/vm_a_campaign_summary.json}"
input_summary_b="${FAKE_CYCLE_SWEEP_INPUT_SUMMARY_B:-$(dirname "$summary_json")/vm_b_campaign_summary.json}"

mkdir -p "$(dirname "$summary_json")" "$(dirname "$input_summary_a")" "$(dirname "$input_summary_b")"
jq -n '{version: 1, status: "pass"}' >"$input_summary_a"
jq -n '{version: 1, status: "pass"}' >"$input_summary_b"

if [[ -n "$canonical_summary_json" ]]; then
  mkdir -p "$(dirname "$canonical_summary_json")"
fi
if [[ -n "$report_md" ]]; then
  mkdir -p "$(dirname "$report_md")"
  printf '# fake sweep report\n' >"$report_md"
fi

jq -n \
  --arg summary_json "$summary_json" \
  --arg canonical_summary_json "$canonical_summary_json" \
  --arg report_md "$report_md" \
  --arg input_summary_a "$input_summary_a" \
  --arg input_summary_b "$input_summary_b" \
  --arg scenario "$scenario" \
  '{
    version: 1,
    schema: { id: "profile_compare_multi_vm_sweep_summary" },
    status: "pass",
    rc: 0,
    reducer_handoff: {
      ready: ($scenario != "not_ready"),
      not_ready_reason: (if $scenario == "not_ready" then "insufficient reducer-ready VM outputs" else null end),
      input_vm_count: 2,
      input_summary_jsons: (if $scenario == "ready_missing_inputs" then [] else [$input_summary_a, $input_summary_b] end),
      input_report_mds: [],
      input_logs: []
    },
    artifacts: {
      summary_json: $summary_json,
      canonical_summary_json: $canonical_summary_json,
      report_md: $report_md
    }
  }' >"$summary_json"

if [[ -n "$canonical_summary_json" ]]; then
  cp "$summary_json" "$canonical_summary_json"
fi

exit 0
EOF_FAKE_SWEEP
chmod +x "$FAKE_SWEEP_SCRIPT"

FAKE_REDUCER_SCRIPT="$TMP_DIR/fake_profile_compare_multi_vm_reducer.sh"
cat >"$FAKE_REDUCER_SCRIPT" <<'EOF_FAKE_REDUCER'
#!/usr/bin/env bash
set -euo pipefail

scenario="${FAKE_CYCLE_REDUCER_SCENARIO:-go}"
capture_file="${FAKE_CYCLE_CAPTURE_FILE:-}"
summary_json=""
report_md=""
fail_on_no_go="0"
min_support_rate_pct=""
campaign_summary_json_count=0
campaign_summary_list=""
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
    --report-md)
      report_md="${2:-}"
      shift 2
      ;;
    --report-md=*)
      report_md="${1#*=}"
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
    --min-support-rate-pct)
      min_support_rate_pct="${2:-}"
      shift 2
      ;;
    --min-support-rate-pct=*)
      min_support_rate_pct="${1#*=}"
      shift
      ;;
    --campaign-summary-json)
      campaign_summary_json_count=$((campaign_summary_json_count + 1))
      shift 2
      ;;
    --campaign-summary-json=*)
      campaign_summary_json_count=$((campaign_summary_json_count + 1))
      shift
      ;;
    --campaign-summary-list)
      campaign_summary_list="${2:-}"
      shift 2
      ;;
    --campaign-summary-list=*)
      campaign_summary_list="${1#*=}"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" ]]; then
  echo "fake reducer missing --summary-json" >&2
  exit 2
fi
if [[ -z "$report_md" ]]; then
  echo "fake reducer missing --report-md" >&2
  exit 2
fi

if [[ -n "$capture_file" ]]; then
  printf 'reducer\tscenario=%s\tfail_on_no_go=%s\tmin_support_rate_pct=%s\tcampaign_summary_json_count=%s\tcampaign_summary_list=%s\tsummary_json=%s\treport_md=%s\n' \
    "$scenario" "$fail_on_no_go" "$min_support_rate_pct" "$campaign_summary_json_count" "$campaign_summary_list" "$summary_json" "$report_md" >>"$capture_file"
fi

if [[ "$scenario" == "fail" ]]; then
  echo "simulated reducer failure" >&2
  exit 29
fi

mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"
printf '# fake reducer report\n' >"$report_md"

if [[ "$scenario" == "no_go" ]]; then
  reducer_rc=0
  if [[ "$fail_on_no_go" == "1" ]]; then
    reducer_rc=1
  fi
  jq -n \
    --argjson rc "$reducer_rc" \
    '{
      version: 1,
      status: "fail",
      rc: $rc,
      decision: {
        decision: "NO-GO",
        recommended_profile: "balanced",
        support_rate_pct: 40,
        trend_source: "policy_reliability_latency"
      },
      summary: {
        vm_summaries_total: 2,
        vm_summaries_valid: 2,
        vm_summaries_invalid: 0,
        status_counts: { pass: 0, warn: 1, fail: 1, other: 0 },
        decision_counts: { GO: 0, "NO-GO": 2 },
        recommended_profile_counts: { balanced: 2 },
        average_input_support_rate_pct: 40
      },
      promotion_gate: {
        decision: "NO-GO",
        status: "fail",
        promotion_ready: false,
        missing_evidence_reasons: [
          { id: "vm_decisions_not_all_go", message: "simulated reducer no-go" }
        ],
        missing_evidence_reason_ids: ["vm_decisions_not_all_go"]
      },
      vm_summaries: [
        { input_summary_json: "vm_a.json", status: "fail", valid: true },
        { input_summary_json: "vm_b.json", status: "warn", valid: true }
      ],
      errors: ["simulated reducer no-go"]
    }' >"$summary_json"
  exit "$reducer_rc"
fi

jq -n '{
  version: 1,
  status: "ok",
  rc: 0,
  decision: {
    decision: "GO",
    recommended_profile: "balanced",
    support_rate_pct: 88.8,
    trend_source: "policy_reliability_latency"
  },
  summary: {
    vm_summaries_total: 2,
    vm_summaries_valid: 2,
    vm_summaries_invalid: 0,
    status_counts: { pass: 2, warn: 0, fail: 0, other: 0 },
    decision_counts: { GO: 2, "NO-GO": 0 },
    recommended_profile_counts: { balanced: 2 },
    average_input_support_rate_pct: 88.8
  },
  promotion_gate: {
    decision: "GO",
    status: "pass",
    promotion_ready: true,
    missing_evidence_reasons: [],
    missing_evidence_reason_ids: []
  },
  vm_summaries: [
    { input_summary_json: "vm_a.json", status: "pass", valid: true },
    { input_summary_json: "vm_b.json", status: "pass", valid: true }
  ],
  errors: []
}' >"$summary_json"
exit 0
EOF_FAKE_REDUCER
chmod +x "$FAKE_REDUCER_SCRIPT"

FAKE_CHECK_SCRIPT="$TMP_DIR/fake_profile_compare_campaign_check.sh"
cat >"$FAKE_CHECK_SCRIPT" <<'EOF_FAKE_CHECK'
#!/usr/bin/env bash
set -euo pipefail

scenario="${FAKE_CYCLE_CHECK_SCENARIO:-go}"
capture_file="${FAKE_CYCLE_CAPTURE_FILE:-}"
summary_json=""
campaign_summary_json=""
trend_summary_json=""
fail_on_no_go="1"
require_status_pass=""
require_recommendation_support_rate_pct=""
require_selection_policy_valid=""
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
    --campaign-summary-json)
      campaign_summary_json="${2:-}"
      shift 2
      ;;
    --campaign-summary-json=*)
      campaign_summary_json="${1#*=}"
      shift
      ;;
    --trend-summary-json)
      trend_summary_json="${2:-}"
      shift 2
      ;;
    --trend-summary-json=*)
      trend_summary_json="${1#*=}"
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
    --require-recommendation-support-rate-pct)
      require_recommendation_support_rate_pct="${2:-}"
      shift 2
      ;;
    --require-recommendation-support-rate-pct=*)
      require_recommendation_support_rate_pct="${1#*=}"
      shift
      ;;
    --require-selection-policy-valid)
      require_selection_policy_valid="${2:-}"
      shift 2
      ;;
    --require-selection-policy-valid=*)
      require_selection_policy_valid="${1#*=}"
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
if [[ -z "$campaign_summary_json" ]]; then
  echo "fake check missing --campaign-summary-json" >&2
  exit 2
fi
if [[ -z "$trend_summary_json" ]]; then
  echo "fake check missing --trend-summary-json" >&2
  exit 2
fi

if [[ -n "$capture_file" ]]; then
  printf 'check\tscenario=%s\tfail_on_no_go=%s\trequire_status_pass=%s\trequire_recommendation_support_rate_pct=%s\trequire_selection_policy_valid=%s\tcampaign_summary_json=%s\ttrend_summary_json=%s\tsummary_json=%s\n' \
    "$scenario" "$fail_on_no_go" "$require_status_pass" "$require_recommendation_support_rate_pct" "$require_selection_policy_valid" "$campaign_summary_json" "$trend_summary_json" "$summary_json" >>"$capture_file"
fi

mkdir -p "$(dirname "$summary_json")"

if [[ "$scenario" == "go" ]]; then
  jq -n '{
    version: 1,
    decision: "GO",
    status: "ok",
    rc: 0,
    observed: {
      recommended_profile: "balanced",
      recommendation_support_rate_pct: 88.8,
      trend_source: "policy_reliability_latency"
    },
    errors: []
  }' >"$summary_json"
  exit 0
fi

if [[ "$scenario" == "fail" ]]; then
  echo "simulated check failure" >&2
  exit 31
fi

check_rc=0
if [[ "$fail_on_no_go" == "1" ]]; then
  check_rc=1
fi
jq -n \
  --argjson rc "$check_rc" \
  '{
    version: 1,
    decision: "NO-GO",
    status: "fail",
    rc: $rc,
    observed: {
      recommended_profile: "balanced",
      recommendation_support_rate_pct: 40,
      trend_source: "policy_reliability_latency"
    },
    decision_diagnostics: {
      m4_policy: {
        unmet_requirements: ["runtime_actuation_status_not_pass"],
        gate_evaluation: {
          runtime_actuation_status_pass: {
            status: "fail"
          }
        }
      }
    },
    errors: ["simulated check no-go"]
  }' >"$summary_json"
exit "$check_rc"
EOF_FAKE_CHECK
chmod +x "$FAKE_CHECK_SCRIPT"

VM_COMMAND_FILE="$TMP_DIR/vm_commands.txt"
cat >"$VM_COMMAND_FILE" <<'EOF_VM_COMMANDS'
vm_file::echo "fake vm"
EOF_VM_COMMANDS

echo "[profile-compare-multi-vm-cycle] happy path"
HAPPY_SUMMARY="$TMP_DIR/cycle_happy_summary.json"
set +e
PROFILE_COMPARE_MULTI_VM_SWEEP_SCRIPT="$FAKE_SWEEP_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_REDUCER_SCRIPT="$FAKE_REDUCER_SCRIPT" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_CYCLE_CAPTURE_FILE="$FAKE_CAPTURE_FILE" \
FAKE_CYCLE_SWEEP_SCENARIO="pass" \
FAKE_CYCLE_REDUCER_SCENARIO="go" \
FAKE_CYCLE_CHECK_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/happy_reports" \
  --vm-command "vm_arg::echo vm" \
  --vm-command-file "$VM_COMMAND_FILE" \
  --reducer-summary-json "$TMP_DIR/happy_reducer_summary.json" \
  --reducer-report-md "$TMP_DIR/happy_reducer_report.md" \
  --reducer-min-support-rate-pct 66 \
  --check-summary-json "$TMP_DIR/happy_check_summary.json" \
  --require-status-pass 1 \
  --require-recommendation-support-rate-pct 75 \
  --require-selection-policy-valid 1 \
  --summary-json "$HAPPY_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_cycle_happy.log 2>&1
happy_rc=$?
set -e

if [[ "$happy_rc" -ne 0 ]]; then
  echo "expected happy path rc=0, got rc=$happy_rc"
  cat /tmp/integration_profile_compare_multi_vm_cycle_happy.log
  exit 1
fi
if ! jq -e '
  .schema.id == "profile_compare_multi_vm_cycle_summary"
  and .status == "pass"
  and .rc == 0
  and .decision == "GO"
  and .promotion_gate.decision == "GO"
  and .promotion_gate.status == "pass"
  and .promotion_gate.promotion_ready == true
  and (.promotion_gate.missing_evidence_reasons | length) == 0
  and .failure_stage == null
  and .stages.sweep.attempted == true
  and .stages.sweep.status == "pass"
  and .stages.reducer.attempted == true
  and .stages.reducer.status == "pass"
  and .stages.check.attempted == true
  and .stages.check.status == "pass"
  and .check.decision == "GO"
  and .inputs.check.policy.require_status_pass == true
  and .inputs.check.policy.require_recommendation_support_rate_pct == 75
  and .inputs.check.policy.require_selection_policy_valid == true
  and .inputs.reducer.min_support_rate_pct == 66
  and .inputs.sweep.allow_unready_handoff == false
  and .artifacts.sweep_summary_json == .stages.sweep.summary_json
  and .artifacts.reducer_summary_json == .stages.reducer.summary_json
  and .artifacts.check_summary_json == .stages.check.summary_json
' "$HAPPY_SUMMARY" >/dev/null 2>&1; then
  echo "happy-path cycle summary mismatch"
  cat "$HAPPY_SUMMARY"
  exit 1
fi
if ! grep -q $'^sweep\t.*\tvm_command_count=1\tvm_command_file_count=1\t' "$FAKE_CAPTURE_FILE"; then
  echo "expected sweep vm-command forwarding capture not found"
  cat "$FAKE_CAPTURE_FILE"
  exit 1
fi
if ! grep -q $'^reducer\t.*\tcampaign_summary_json_count=2\t' "$FAKE_CAPTURE_FILE"; then
  echo "expected reducer input-summary forwarding capture not found"
  cat "$FAKE_CAPTURE_FILE"
  exit 1
fi
if ! grep -q $'^reducer\t.*\tmin_support_rate_pct=66.00\t' "$FAKE_CAPTURE_FILE"; then
  echo "expected reducer min-support-rate threshold forwarding capture not found"
  cat "$FAKE_CAPTURE_FILE"
  exit 1
fi
if ! grep -q $'^check\t.*\trequire_status_pass=1\trequire_recommendation_support_rate_pct=75\trequire_selection_policy_valid=1\t' "$FAKE_CAPTURE_FILE"; then
  echo "expected check policy forwarding capture not found"
  cat "$FAKE_CAPTURE_FILE"
  exit 1
fi

echo "[profile-compare-multi-vm-cycle] command redaction covers header/query/url credentials"
REDACTION_SUMMARY="$TMP_DIR/cycle_redaction_summary.json"
set +e
PROFILE_COMPARE_MULTI_VM_SWEEP_SCRIPT="$FAKE_SWEEP_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_REDUCER_SCRIPT="$FAKE_REDUCER_SCRIPT" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_CYCLE_CAPTURE_FILE="$TMP_DIR/capture_redaction.log" \
FAKE_CYCLE_SWEEP_SCENARIO="pass" \
FAKE_CYCLE_REDUCER_SCENARIO="go" \
FAKE_CYCLE_CHECK_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/redaction_reports" \
  --vm-command "vm_secret::curl -H 'Authorization: Bearer topsecretbearer' -H 'X-API-Key: topsecretkey' 'https://demo-user:demo-pass@example.test/ping?token=tok123&api_key=api123'" \
  --summary-json "$REDACTION_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_cycle_redaction.log 2>&1
redaction_rc=$?
set -e

if [[ "$redaction_rc" -ne 0 ]]; then
  echo "expected redaction path rc=0, got rc=$redaction_rc"
  cat /tmp/integration_profile_compare_multi_vm_cycle_redaction.log
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and (.stages.sweep.command | test("\\[redacted\\]"))
  and ((.stages.sweep.command | test("topsecretbearer|topsecretkey|tok123|api123|demo-pass")) | not)
' "$REDACTION_SUMMARY" >/dev/null 2>&1; then
  echo "redaction summary mismatch"
  cat "$REDACTION_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-cycle] check NO-GO with fail-on-no-go=0 returns warn/rc0"
NO_GO_SOFT_SUMMARY="$TMP_DIR/cycle_no_go_soft_summary.json"
set +e
PROFILE_COMPARE_MULTI_VM_SWEEP_SCRIPT="$FAKE_SWEEP_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_REDUCER_SCRIPT="$FAKE_REDUCER_SCRIPT" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_CYCLE_CAPTURE_FILE="$TMP_DIR/capture_no_go_soft.log" \
FAKE_CYCLE_SWEEP_SCENARIO="pass" \
FAKE_CYCLE_REDUCER_SCENARIO="go" \
FAKE_CYCLE_CHECK_SCENARIO="no_go" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/no_go_soft_reports" \
  --vm-command "vm_arg::echo vm" \
  --vm-command-file "$VM_COMMAND_FILE" \
  --fail-on-no-go 0 \
  --summary-json "$NO_GO_SOFT_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_cycle_no_go_soft.log 2>&1
no_go_soft_rc=$?
set -e

if [[ "$no_go_soft_rc" -ne 0 ]]; then
  echo "expected NO-GO soft path rc=0, got rc=$no_go_soft_rc"
  cat /tmp/integration_profile_compare_multi_vm_cycle_no_go_soft.log
  exit 1
fi
if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .decision == "NO-GO"
  and .promotion_gate.decision == "NO-GO"
  and .promotion_gate.status == "fail"
  and .promotion_gate.promotion_ready == false
  and .promotion_gate.check.status == "fail"
  and ((.promotion_gate.missing_evidence_reason_ids // []) | index("runtime_actuation_status_not_pass"))
  and .failure_stage == null
  and .stages.check.attempted == true
  and .stages.check.status == "fail"
  and .stages.check.rc == 0
  and .check.decision == "NO-GO"
' "$NO_GO_SOFT_SUMMARY" >/dev/null 2>&1; then
  echo "NO-GO soft summary mismatch"
  cat "$NO_GO_SOFT_SUMMARY"
  exit 1
fi
if ! grep -q $'^check\t.*\tfail_on_no_go=0\t' "$TMP_DIR/capture_no_go_soft.log"; then
  echo "expected check fail_on_no_go=0 capture not found"
  cat "$TMP_DIR/capture_no_go_soft.log"
  exit 1
fi

echo "[profile-compare-multi-vm-cycle] sweep reducer-handoff not-ready fails closed by default"
HANDOFF_NOT_READY_SUMMARY="$TMP_DIR/cycle_handoff_not_ready_summary.json"
HANDOFF_NOT_READY_CAPTURE="$TMP_DIR/capture_handoff_not_ready.log"
set +e
PROFILE_COMPARE_MULTI_VM_SWEEP_SCRIPT="$FAKE_SWEEP_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_REDUCER_SCRIPT="$FAKE_REDUCER_SCRIPT" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_CYCLE_CAPTURE_FILE="$HANDOFF_NOT_READY_CAPTURE" \
FAKE_CYCLE_SWEEP_SCENARIO="not_ready" \
FAKE_CYCLE_REDUCER_SCENARIO="go" \
FAKE_CYCLE_CHECK_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/handoff_not_ready_reports" \
  --vm-command "vm_arg::echo vm" \
  --vm-command-file "$VM_COMMAND_FILE" \
  --summary-json "$HANDOFF_NOT_READY_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_cycle_handoff_not_ready.log 2>&1
handoff_not_ready_rc=$?
set -e

if [[ "$handoff_not_ready_rc" -eq 0 ]]; then
  echo "expected non-zero rc when sweep reducer handoff is not ready"
  cat /tmp/integration_profile_compare_multi_vm_cycle_handoff_not_ready.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .decision == "NO-GO"
  and .failure_stage == "sweep"
  and ((.failure_reason // "") | test("handoff"))
  and .sweep.reducer_handoff_ready == false
  and .stages.reducer.attempted == false
  and .stages.check.attempted == false
' "$HANDOFF_NOT_READY_SUMMARY" >/dev/null 2>&1; then
  echo "handoff-not-ready cycle summary mismatch"
  cat "$HANDOFF_NOT_READY_SUMMARY"
  exit 1
fi
if grep -q '^reducer' "$HANDOFF_NOT_READY_CAPTURE"; then
  echo "reducer should not run when sweep handoff is not ready and override is disabled"
  cat "$HANDOFF_NOT_READY_CAPTURE"
  exit 1
fi
if grep -q '^check' "$HANDOFF_NOT_READY_CAPTURE"; then
  echo "check should not run when sweep handoff is not ready and override is disabled"
  cat "$HANDOFF_NOT_READY_CAPTURE"
  exit 1
fi

echo "[profile-compare-multi-vm-cycle] sweep handoff ready-but-missing-inputs fails closed"
HANDOFF_INCONSISTENT_SUMMARY="$TMP_DIR/cycle_handoff_inconsistent_summary.json"
HANDOFF_INCONSISTENT_CAPTURE="$TMP_DIR/capture_handoff_inconsistent.log"
set +e
PROFILE_COMPARE_MULTI_VM_SWEEP_SCRIPT="$FAKE_SWEEP_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_REDUCER_SCRIPT="$FAKE_REDUCER_SCRIPT" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_CYCLE_CAPTURE_FILE="$HANDOFF_INCONSISTENT_CAPTURE" \
FAKE_CYCLE_SWEEP_SCENARIO="ready_missing_inputs" \
FAKE_CYCLE_REDUCER_SCENARIO="go" \
FAKE_CYCLE_CHECK_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/handoff_inconsistent_reports" \
  --vm-command "vm_arg::echo vm" \
  --vm-command-file "$VM_COMMAND_FILE" \
  --summary-json "$HANDOFF_INCONSISTENT_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_cycle_handoff_inconsistent.log 2>&1
handoff_inconsistent_rc=$?
set -e

if [[ "$handoff_inconsistent_rc" -eq 0 ]]; then
  echo "expected non-zero rc when sweep handoff is ready but input summaries are missing"
  cat /tmp/integration_profile_compare_multi_vm_cycle_handoff_inconsistent.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .decision == "NO-GO"
  and .failure_stage == "sweep"
  and ((.failure_reason // "") | test("inconsistent"))
  and .sweep.reducer_handoff_ready == true
  and .sweep.reducer_input_vm_count == 2
  and (.sweep.reducer_input_summary_jsons | length) == 0
  and .stages.reducer.attempted == false
  and .stages.check.attempted == false
' "$HANDOFF_INCONSISTENT_SUMMARY" >/dev/null 2>&1; then
  echo "handoff-inconsistent cycle summary mismatch"
  cat "$HANDOFF_INCONSISTENT_SUMMARY"
  exit 1
fi
if grep -q '^reducer' "$HANDOFF_INCONSISTENT_CAPTURE"; then
  echo "reducer should not run when sweep handoff inputs are inconsistent"
  cat "$HANDOFF_INCONSISTENT_CAPTURE"
  exit 1
fi
if grep -q '^check' "$HANDOFF_INCONSISTENT_CAPTURE"; then
  echo "check should not run when sweep handoff inputs are inconsistent"
  cat "$HANDOFF_INCONSISTENT_CAPTURE"
  exit 1
fi

echo "[profile-compare-multi-vm-cycle] sweep reducer-handoff override allows reducer/check"
HANDOFF_OVERRIDE_SUMMARY="$TMP_DIR/cycle_handoff_override_summary.json"
HANDOFF_OVERRIDE_CAPTURE="$TMP_DIR/capture_handoff_override.log"
set +e
PROFILE_COMPARE_MULTI_VM_SWEEP_SCRIPT="$FAKE_SWEEP_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_REDUCER_SCRIPT="$FAKE_REDUCER_SCRIPT" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_CYCLE_CAPTURE_FILE="$HANDOFF_OVERRIDE_CAPTURE" \
FAKE_CYCLE_SWEEP_SCENARIO="not_ready" \
FAKE_CYCLE_REDUCER_SCENARIO="go" \
FAKE_CYCLE_CHECK_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/handoff_override_reports" \
  --vm-command "vm_arg::echo vm" \
  --vm-command-file "$VM_COMMAND_FILE" \
  --sweep-allow-unready-handoff 1 \
  --summary-json "$HANDOFF_OVERRIDE_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_cycle_handoff_override.log 2>&1
handoff_override_rc=$?
set -e

if [[ "$handoff_override_rc" -ne 0 ]]; then
  echo "expected rc=0 when sweep handoff override is enabled"
  cat /tmp/integration_profile_compare_multi_vm_cycle_handoff_override.log
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .decision == "GO"
  and .inputs.sweep.allow_unready_handoff == true
  and .sweep.reducer_handoff_ready == false
  and .stages.reducer.attempted == true
  and .stages.check.attempted == true
' "$HANDOFF_OVERRIDE_SUMMARY" >/dev/null 2>&1; then
  echo "handoff-override cycle summary mismatch"
  cat "$HANDOFF_OVERRIDE_SUMMARY"
  exit 1
fi
if ! grep -q '^reducer' "$HANDOFF_OVERRIDE_CAPTURE"; then
  echo "reducer should run when sweep handoff override is enabled"
  cat "$HANDOFF_OVERRIDE_CAPTURE"
  exit 1
fi
if ! grep -q '^check' "$HANDOFF_OVERRIDE_CAPTURE"; then
  echo "check should run when sweep handoff override is enabled"
  cat "$HANDOFF_OVERRIDE_CAPTURE"
  exit 1
fi

echo "[profile-compare-multi-vm-cycle] sweep failure skips reducer/check and sets failure_stage"
SWEEP_FAIL_SUMMARY="$TMP_DIR/cycle_sweep_fail_summary.json"
SWEEP_FAIL_CAPTURE="$TMP_DIR/capture_sweep_fail.log"
set +e
PROFILE_COMPARE_MULTI_VM_SWEEP_SCRIPT="$FAKE_SWEEP_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_REDUCER_SCRIPT="$FAKE_REDUCER_SCRIPT" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK_SCRIPT" \
FAKE_CYCLE_CAPTURE_FILE="$SWEEP_FAIL_CAPTURE" \
FAKE_CYCLE_SWEEP_SCENARIO="fail" \
FAKE_CYCLE_REDUCER_SCENARIO="go" \
FAKE_CYCLE_CHECK_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/sweep_fail_reports" \
  --vm-command "vm_arg::echo vm" \
  --vm-command-file "$VM_COMMAND_FILE" \
  --summary-json "$SWEEP_FAIL_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_cycle_sweep_fail.log 2>&1
sweep_fail_rc=$?
set -e

if [[ "$sweep_fail_rc" -eq 0 ]]; then
  echo "expected sweep failure rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_cycle_sweep_fail.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .decision == "NO-GO"
  and .failure_stage == "sweep"
  and ((.failure_reason // "") | test("sweep"))
  and .stages.sweep.status == "fail"
  and .stages.reducer.attempted == false
  and .stages.reducer.status == "skip"
  and .stages.check.attempted == false
  and .stages.check.status == "skip"
' "$SWEEP_FAIL_SUMMARY" >/dev/null 2>&1; then
  echo "sweep-failure cycle summary mismatch"
  cat "$SWEEP_FAIL_SUMMARY"
  exit 1
fi
if grep -q '^reducer' "$SWEEP_FAIL_CAPTURE"; then
  echo "reducer should not run when sweep fails"
  cat "$SWEEP_FAIL_CAPTURE"
  exit 1
fi
if grep -q '^check' "$SWEEP_FAIL_CAPTURE"; then
  echo "check should not run when sweep fails"
  cat "$SWEEP_FAIL_CAPTURE"
  exit 1
fi

echo "profile compare multi-vm cycle integration ok"
