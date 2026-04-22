#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp grep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/profile_default_gate_stability_check.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

make_summary() {
  local path="$1"
  local status="$2"
  local runs_requested="$3"
  local runs_completed="$4"
  local runs_fail="$5"
  local stability_ok="$6"
  local selection_policy_present_all="$7"
  local consistent_selection_policy="$8"
  local recommended_profile_counts_json="$9"
  local decision_counts_json="{\"GO\":${runs_completed}}"
  local decision_consensus_json="true"
  local _args=("$@")
  if ((${#_args[@]} >= 10)); then
    decision_counts_json="${_args[9]}"
  fi
  if ((${#_args[@]} >= 11)); then
    decision_consensus_json="${_args[10]}"
  fi

  jq -n \
    --arg status "$status" \
    --argjson runs_requested "$runs_requested" \
    --argjson runs_completed "$runs_completed" \
    --argjson runs_fail "$runs_fail" \
    --argjson stability_ok "$stability_ok" \
    --argjson selection_policy_present_all "$selection_policy_present_all" \
    --argjson consistent_selection_policy "$consistent_selection_policy" \
    --argjson recommended_profile_counts "$recommended_profile_counts_json" \
    --argjson decision_counts "$decision_counts_json" \
    --argjson decision_consensus "$decision_consensus_json" \
    '{
      version: 1,
      schema: { id: "profile_default_gate_stability_summary" },
      generated_at_utc: "2026-04-21T00:00:00Z",
      status: $status,
      rc: 0,
      runs_requested: $runs_requested,
      runs_completed: $runs_completed,
      runs_fail: $runs_fail,
      stability_ok: $stability_ok,
      selection_policy_present_all: $selection_policy_present_all,
      consistent_selection_policy: $consistent_selection_policy,
      recommended_profile_counts: $recommended_profile_counts,
      decision_counts: $decision_counts,
      decision_consensus: $decision_consensus,
      artifacts: { summary_json: "dummy" }
    }' >"$path"
}

echo "[profile-default-gate-stability-check] baseline pass"
BASELINE_SUMMARY="$TMP_DIR/stability_summary_baseline.json"
make_summary "$BASELINE_SUMMARY" "pass" 3 3 0 true true true '{"balanced":2,"2hop":1}'

BASELINE_OUT="$TMP_DIR/stability_check_baseline.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --stability-summary-json "$BASELINE_SUMMARY" \
  --summary-json "$BASELINE_OUT" \
  --print-summary-json 1 >/tmp/integration_profile_default_gate_stability_check_baseline.log 2>&1
baseline_rc=$?
set -e

if [[ "$baseline_rc" -ne 0 ]]; then
  echo "expected baseline rc=0, got rc=$baseline_rc"
  cat /tmp/integration_profile_default_gate_stability_check_baseline.log
  exit 1
fi
if ! grep -q '\[profile-default-gate-stability-check\] decision=GO status=ok rc=0' /tmp/integration_profile_default_gate_stability_check_baseline.log; then
  echo "expected GO baseline output not found"
  cat /tmp/integration_profile_default_gate_stability_check_baseline.log
  exit 1
fi
if ! jq -e '
  .schema.id == "profile_default_gate_stability_check_summary"
  and .decision == "GO"
  and .status == "ok"
  and .rc == 0
  and (.errors | length) == 0
  and .enforcement.no_go_enforced == false
  and .outcome.should_promote == true
  and .outcome.action == "promote_allowed"
  and .observed.runs_requested == 3
  and .observed.runs_completed == 3
  and .observed.runs_fail == 0
  and .observed.modal_recommended_profile == "balanced"
  and (.observed.modal_support_rate_pct >= 99.9)
  and .observed.modal_decision == "GO"
  and .observed.decision_consensus == true
  and .observed.decision_counts.GO == 3
' "$BASELINE_OUT" >/dev/null 2>&1; then
  echo "baseline summary missing expected fields"
  cat "$BASELINE_OUT"
  exit 1
fi

echo "[profile-default-gate-stability-check] require-decision-consensus pass path"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --stability-summary-json "$BASELINE_SUMMARY" \
  --require-decision-consensus 1 \
  --summary-json "$TMP_DIR/stability_check_decision_consensus_pass.json" >/tmp/integration_profile_default_gate_stability_check_decision_consensus_pass.log 2>&1
decision_consensus_pass_rc=$?
set -e

if [[ "$decision_consensus_pass_rc" -ne 0 ]]; then
  echo "expected decision-consensus pass path rc=0"
  cat /tmp/integration_profile_default_gate_stability_check_decision_consensus_pass.log
  exit 1
fi

echo "[profile-default-gate-stability-check] fail when decision consensus is required and mixed"
MIXED_DECISION_SUMMARY="$TMP_DIR/stability_summary_mixed_decision.json"
make_summary "$MIXED_DECISION_SUMMARY" "pass" 3 3 0 true true true '{"balanced":3}' '{"GO":2,"NO-GO":1}' false

set +e
bash "$SCRIPT_UNDER_TEST" \
  --stability-summary-json "$MIXED_DECISION_SUMMARY" \
  --require-decision-consensus 1 \
  --summary-json "$TMP_DIR/stability_check_decision_consensus_fail.json" >/tmp/integration_profile_default_gate_stability_check_decision_consensus_fail.log 2>&1
decision_consensus_fail_rc=$?
set -e

if [[ "$decision_consensus_fail_rc" -eq 0 ]]; then
  echo "expected non-zero rc for mixed decision consensus requirement"
  cat /tmp/integration_profile_default_gate_stability_check_decision_consensus_fail.log
  exit 1
fi
if ! grep -q 'decision_consensus must be true' /tmp/integration_profile_default_gate_stability_check_decision_consensus_fail.log; then
  echo "expected decision-consensus failure reason missing"
  cat /tmp/integration_profile_default_gate_stability_check_decision_consensus_fail.log
  exit 1
fi

echo "[profile-default-gate-stability-check] fail when modal decision requirement mismatches"
NO_GO_MODAL_SUMMARY="$TMP_DIR/stability_summary_no_go_modal.json"
make_summary "$NO_GO_MODAL_SUMMARY" "pass" 3 3 0 true true true '{"balanced":3}' '{"NO-GO":3}' true

set +e
bash "$SCRIPT_UNDER_TEST" \
  --stability-summary-json "$NO_GO_MODAL_SUMMARY" \
  --require-modal-decision GO \
  --summary-json "$TMP_DIR/stability_check_modal_decision_mismatch.json" >/tmp/integration_profile_default_gate_stability_check_modal_decision_mismatch.log 2>&1
modal_decision_mismatch_rc=$?
set -e

if [[ "$modal_decision_mismatch_rc" -eq 0 ]]; then
  echo "expected non-zero rc for modal decision mismatch"
  cat /tmp/integration_profile_default_gate_stability_check_modal_decision_mismatch.log
  exit 1
fi
if ! grep -q 'modal decision mismatch' /tmp/integration_profile_default_gate_stability_check_modal_decision_mismatch.log; then
  echo "expected modal decision mismatch failure reason missing"
  cat /tmp/integration_profile_default_gate_stability_check_modal_decision_mismatch.log
  exit 1
fi

echo "[profile-default-gate-stability-check] fail when modal decision support rate is below threshold"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --stability-summary-json "$MIXED_DECISION_SUMMARY" \
  --require-modal-decision GO \
  --require-modal-decision-support-rate-pct 80 \
  --summary-json "$TMP_DIR/stability_check_modal_decision_support_fail.json" >/tmp/integration_profile_default_gate_stability_check_modal_decision_support_fail.log 2>&1
modal_decision_support_fail_rc=$?
set -e

if [[ "$modal_decision_support_fail_rc" -eq 0 ]]; then
  echo "expected non-zero rc for low modal decision support rate"
  cat /tmp/integration_profile_default_gate_stability_check_modal_decision_support_fail.log
  exit 1
fi
if ! grep -q 'modal decision support rate below threshold' /tmp/integration_profile_default_gate_stability_check_modal_decision_support_fail.log; then
  echo "expected modal decision support-rate failure reason missing"
  cat /tmp/integration_profile_default_gate_stability_check_modal_decision_support_fail.log
  exit 1
fi

echo "[profile-default-gate-stability-check] fail when modal support rate is below threshold"
LOW_SUPPORT_SUMMARY="$TMP_DIR/stability_summary_low_support.json"
make_summary "$LOW_SUPPORT_SUMMARY" "pass" 3 3 0 true true true '{"balanced":1,"speed":1,"private":1}'

set +e
bash "$SCRIPT_UNDER_TEST" \
  --stability-summary-json "$LOW_SUPPORT_SUMMARY" \
  --summary-json "$TMP_DIR/stability_check_low_support.json" >/tmp/integration_profile_default_gate_stability_check_low_support.log 2>&1
low_support_rc=$?
set -e

if [[ "$low_support_rc" -eq 0 ]]; then
  echo "expected non-zero rc for low modal support rate"
  cat /tmp/integration_profile_default_gate_stability_check_low_support.log
  exit 1
fi
if ! grep -q 'modal support rate below threshold' /tmp/integration_profile_default_gate_stability_check_low_support.log; then
  echo "expected modal support failure reason missing"
  cat /tmp/integration_profile_default_gate_stability_check_low_support.log
  exit 1
fi

echo "[profile-default-gate-stability-check] fail when recommended profile is not allowed"
NOT_ALLOWED_SUMMARY="$TMP_DIR/stability_summary_not_allowed.json"
make_summary "$NOT_ALLOWED_SUMMARY" "pass" 3 3 0 true true true '{"speed-1hop":3}'

set +e
bash "$SCRIPT_UNDER_TEST" \
  --stability-summary-json "$NOT_ALLOWED_SUMMARY" \
  --summary-json "$TMP_DIR/stability_check_not_allowed.json" >/tmp/integration_profile_default_gate_stability_check_not_allowed.log 2>&1
not_allowed_rc=$?
set -e

if [[ "$not_allowed_rc" -eq 0 ]]; then
  echo "expected non-zero rc for disallowed recommended profile"
  cat /tmp/integration_profile_default_gate_stability_check_not_allowed.log
  exit 1
fi
if ! grep -q 'recommended profile is not in allowed set' /tmp/integration_profile_default_gate_stability_check_not_allowed.log; then
  echo "expected disallowed-profile failure reason missing"
  cat /tmp/integration_profile_default_gate_stability_check_not_allowed.log
  exit 1
fi

echo "[profile-default-gate-stability-check] fail when required recommended profile mismatches"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --stability-summary-json "$BASELINE_SUMMARY" \
  --require-recommended-profile private \
  --summary-json "$TMP_DIR/stability_check_required_mismatch.json" >/tmp/integration_profile_default_gate_stability_check_required_mismatch.log 2>&1
required_mismatch_rc=$?
set -e

if [[ "$required_mismatch_rc" -eq 0 ]]; then
  echo "expected non-zero rc for required-profile mismatch"
  cat /tmp/integration_profile_default_gate_stability_check_required_mismatch.log
  exit 1
fi
if ! grep -q 'recommended profile mismatch' /tmp/integration_profile_default_gate_stability_check_required_mismatch.log; then
  echo "expected required-profile mismatch failure reason missing"
  cat /tmp/integration_profile_default_gate_stability_check_required_mismatch.log
  exit 1
fi

echo "[profile-default-gate-stability-check] fail when selection policy flags are invalid"
INVALID_FLAGS_SUMMARY="$TMP_DIR/stability_summary_invalid_flags.json"
make_summary "$INVALID_FLAGS_SUMMARY" "pass" 3 3 0 false false false '{"balanced":3}'

set +e
bash "$SCRIPT_UNDER_TEST" \
  --stability-summary-json "$INVALID_FLAGS_SUMMARY" \
  --summary-json "$TMP_DIR/stability_check_invalid_flags.json" >/tmp/integration_profile_default_gate_stability_check_invalid_flags.log 2>&1
invalid_flags_rc=$?
set -e

if [[ "$invalid_flags_rc" -eq 0 ]]; then
  echo "expected non-zero rc when selection policy flags are invalid"
  cat /tmp/integration_profile_default_gate_stability_check_invalid_flags.log
  exit 1
fi
if ! grep -q 'selection_policy_present_all must be true' /tmp/integration_profile_default_gate_stability_check_invalid_flags.log; then
  echo "expected selection_policy_present_all failure reason missing"
  cat /tmp/integration_profile_default_gate_stability_check_invalid_flags.log
  exit 1
fi
if ! grep -q 'consistent_selection_policy must be true' /tmp/integration_profile_default_gate_stability_check_invalid_flags.log; then
  echo "expected consistent_selection_policy failure reason missing"
  cat /tmp/integration_profile_default_gate_stability_check_invalid_flags.log
  exit 1
fi

echo "[profile-default-gate-stability-check] missing value for numeric threshold returns rc=2"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --stability-summary-json "$BASELINE_SUMMARY" \
  --require-min-runs-completed >/tmp/integration_profile_default_gate_stability_check_missing_value.log 2>&1
missing_value_rc=$?
set -e

if [[ "$missing_value_rc" -ne 2 ]]; then
  echo "expected rc=2 when --require-min-runs-completed is missing a value"
  cat /tmp/integration_profile_default_gate_stability_check_missing_value.log
  exit 1
fi
if ! grep -q -- '--require-min-runs-completed requires a value' /tmp/integration_profile_default_gate_stability_check_missing_value.log; then
  echo "expected missing-value error message not found"
  cat /tmp/integration_profile_default_gate_stability_check_missing_value.log
  exit 1
fi

echo "[profile-default-gate-stability-check] invalid --require-modal-decision returns rc=2"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --stability-summary-json "$BASELINE_SUMMARY" \
  --require-modal-decision maybe \
  --summary-json "$TMP_DIR/stability_check_invalid_modal_decision.json" >/tmp/integration_profile_default_gate_stability_check_invalid_modal_decision.log 2>&1
invalid_modal_decision_rc=$?
set -e

if [[ "$invalid_modal_decision_rc" -ne 2 ]]; then
  echo "expected rc=2 for invalid --require-modal-decision value"
  cat /tmp/integration_profile_default_gate_stability_check_invalid_modal_decision.log
  exit 1
fi
if ! grep -q -- '--require-modal-decision must be GO or NO-GO' /tmp/integration_profile_default_gate_stability_check_invalid_modal_decision.log; then
  echo "expected invalid-modal-decision error message not found"
  cat /tmp/integration_profile_default_gate_stability_check_invalid_modal_decision.log
  exit 1
fi

echo "[profile-default-gate-stability-check] runs_requested fallback to inputs.runs_requested"
FALLBACK_SUMMARY="$TMP_DIR/stability_summary_fallback_runs_requested.json"
jq -n '{
  version: 1,
  schema: { id: "profile_default_gate_stability_summary" },
  generated_at_utc: "2026-04-21T00:00:00Z",
  status: "pass",
  rc: 0,
  inputs: { runs_requested: 4 },
  runs_completed: 4,
  runs_fail: 0,
  stability_ok: true,
  selection_policy_present_all: true,
  consistent_selection_policy: true,
  decision_counts: { "GO": 4 },
  modal_decision: "GO",
  modal_decision_support_rate_pct: 100,
  recommended_profile_counts: { "balanced": 4 }
}' >"$FALLBACK_SUMMARY"

FALLBACK_OUT="$TMP_DIR/stability_check_fallback_runs_requested.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --stability-summary-json "$FALLBACK_SUMMARY" \
  --require-min-runs-requested 4 \
  --summary-json "$FALLBACK_OUT" >/tmp/integration_profile_default_gate_stability_check_fallback.log 2>&1
fallback_rc=$?
set -e

if [[ "$fallback_rc" -ne 0 ]]; then
  echo "expected fallback runs_requested path to pass"
  cat /tmp/integration_profile_default_gate_stability_check_fallback.log
  exit 1
fi
if ! jq -e '.decision == "GO" and .observed.runs_requested == 4' "$FALLBACK_OUT" >/dev/null 2>&1; then
  echo "expected observed.runs_requested fallback value missing"
  cat "$FALLBACK_OUT"
  exit 1
fi

echo "[profile-default-gate-stability-check] fail-on-no-go=0 keeps rc=0 with NO-GO decision"
FAIL_OPEN_OUT="$TMP_DIR/stability_check_fail_on_no_go_0.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --stability-summary-json "$LOW_SUPPORT_SUMMARY" \
  --fail-on-no-go=0 \
  --summary-json "$FAIL_OPEN_OUT" >/tmp/integration_profile_default_gate_stability_check_fail_open.log 2>&1
fail_open_rc=$?
set -e

if [[ "$fail_open_rc" -ne 0 ]]; then
  echo "expected rc=0 when --fail-on-no-go 0 is set"
  cat /tmp/integration_profile_default_gate_stability_check_fail_open.log
  exit 1
fi
if ! jq -e '.decision == "NO-GO" and .status == "fail" and .rc == 0' "$FAIL_OPEN_OUT" >/dev/null 2>&1; then
  echo "expected NO-GO decision with rc=0 for fail-on-no-go=0"
  cat "$FAIL_OPEN_OUT"
  exit 1
fi
if ! jq -e '
  .enforcement.no_go_enforced == false
  and .outcome.should_promote == false
  and .outcome.action == "hold_promotion_warn_only"
' "$FAIL_OPEN_OUT" >/dev/null 2>&1; then
  echo "expected machine-readable enforcement/outcome fields for fail-open NO-GO path"
  cat "$FAIL_OPEN_OUT"
  exit 1
fi

echo "profile default gate stability check integration ok"
