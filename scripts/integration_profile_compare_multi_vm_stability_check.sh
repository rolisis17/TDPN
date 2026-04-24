#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp cat grep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PROFILE_COMPARE_MULTI_VM_STABILITY_CHECK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/profile_compare_multi_vm_stability_check.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS_SUMMARY="$TMP_DIR/stability_pass_summary.json"
cat >"$PASS_SUMMARY" <<'EOF_PASS_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "profile_compare_multi_vm_stability_summary"
  },
  "status": "pass",
  "runs_requested": 3,
  "runs_completed": 3,
  "runs_fail": 0,
  "decision_consensus": true,
  "recommended_profile_counts": {
    "balanced": 3
  },
  "modal_recommended_profile": "balanced",
  "modal_support_rate_pct": 100,
  "decision_counts": {
    "GO": 3
  },
  "modal_decision": "GO",
  "modal_decision_support_rate_pct": 100
}
EOF_PASS_SUMMARY

FAIL_SUMMARY="$TMP_DIR/stability_fail_summary.json"
cat >"$FAIL_SUMMARY" <<'EOF_FAIL_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "profile_compare_multi_vm_stability_summary"
  },
  "status": "pass",
  "runs_requested": 3,
  "runs_completed": 3,
  "runs_fail": 1,
  "decision_consensus": false,
  "recommended_profile_counts": {
    "private": 2,
    "speed": 1
  },
  "modal_recommended_profile": "private",
  "modal_support_rate_pct": 66.67,
  "decision_counts": {
    "NO-GO": 2,
    "GO": 1
  },
  "modal_decision": "NO-GO",
  "modal_decision_support_rate_pct": 66.67
}
EOF_FAIL_SUMMARY

RUN_STYLE_SUMMARY="$TMP_DIR/stability_run_style_summary.json"
cat >"$RUN_STYLE_SUMMARY" <<'EOF_RUN_STYLE_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "profile_compare_multi_vm_stability_run_summary"
  },
  "status": "pass",
  "counts": {
    "requested": 3,
    "completed": 3,
    "pass": 3,
    "warn": 0,
    "fail": 0,
    "timeout": 0
  },
  "histograms": {
    "recommended_profile_counts": {
      "balanced": 3
    },
    "decision_counts": {
      "GO": 3
    }
  },
  "modal": {
    "decision": "GO",
    "recommended_profile": "balanced",
    "support_rate_pct": 100
  },
  "runs": [
    { "completed": true, "decision": "GO", "recommended_profile": "balanced", "support_rate_pct": 100 },
    { "completed": true, "decision": "GO", "recommended_profile": "balanced", "support_rate_pct": 100 },
    { "completed": true, "decision": "GO", "recommended_profile": "balanced", "support_rate_pct": 100 }
  ]
}
EOF_RUN_STYLE_SUMMARY

TIE_SUMMARY="$TMP_DIR/stability_tie_summary.json"
cat >"$TIE_SUMMARY" <<'EOF_TIE_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "profile_compare_multi_vm_stability_summary"
  },
  "status": "pass",
  "runs_requested": 2,
  "runs_completed": 2,
  "runs_fail": 0,
  "decision_consensus": false,
  "recommended_profile_counts": {
    "balanced": 1,
    "private": 1
  },
  "modal_recommended_profile": "balanced",
  "modal_support_rate_pct": 50,
  "decision_counts": {
    "GO": 1,
    "NO-GO": 1
  },
  "modal_decision": "GO",
  "modal_decision_support_rate_pct": 50
}
EOF_TIE_SUMMARY

SPLIT_GO_SUMMARY="$TMP_DIR/stability_split_go_summary.json"
cat >"$SPLIT_GO_SUMMARY" <<'EOF_SPLIT_GO_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "profile_compare_multi_vm_stability_summary"
  },
  "status": "pass",
  "runs_requested": 3,
  "runs_completed": 3,
  "runs_fail": 0,
  "decision_consensus": false,
  "recommended_profile_counts": {
    "balanced": 3
  },
  "modal_recommended_profile": "balanced",
  "modal_support_rate_pct": 100,
  "decision_counts": {
    "GO": 2,
    "NO-GO": 1
  },
  "modal_decision": "GO",
  "modal_decision_support_rate_pct": 66.67
}
EOF_SPLIT_GO_SUMMARY

FRACTIONAL_RUNS_SUMMARY="$TMP_DIR/stability_fractional_runs_summary.json"
cat >"$FRACTIONAL_RUNS_SUMMARY" <<'EOF_FRACTIONAL_RUNS_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "profile_compare_multi_vm_stability_summary"
  },
  "status": "pass",
  "runs_requested": 3.5,
  "runs_completed": 3,
  "runs_fail": 0,
  "decision_consensus": true,
  "recommended_profile_counts": {
    "balanced": 3
  },
  "modal_recommended_profile": "balanced",
  "modal_support_rate_pct": 100,
  "decision_counts": {
    "GO": 3
  },
  "modal_decision": "GO",
  "modal_decision_support_rate_pct": 100
}
EOF_FRACTIONAL_RUNS_SUMMARY

CONSENSUS_MISMATCH_SUMMARY="$TMP_DIR/stability_consensus_mismatch_summary.json"
cat >"$CONSENSUS_MISMATCH_SUMMARY" <<'EOF_CONSENSUS_MISMATCH_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "profile_compare_multi_vm_stability_summary"
  },
  "status": "pass",
  "runs_requested": 3,
  "runs_completed": 3,
  "runs_fail": 0,
  "decision_consensus": true,
  "recommended_profile_counts": {
    "balanced": 3
  },
  "modal_recommended_profile": "balanced",
  "modal_support_rate_pct": 100,
  "decision_counts": {
    "GO": 2,
    "NO-GO": 1
  },
  "modal_decision": "GO",
  "modal_decision_support_rate_pct": 66.67
}
EOF_CONSENSUS_MISMATCH_SUMMARY

echo "[profile-compare-multi-vm-stability-check] strict happy path"
STRICT_SUMMARY="$TMP_DIR/check_strict_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --stability-summary-json "$PASS_SUMMARY" \
  --require-status-pass 1 \
  --require-min-runs-requested 3 \
  --require-min-runs-completed 3 \
  --require-max-runs-fail 0 \
  --require-decision-consensus 1 \
  --require-modal-decision GO \
  --require-modal-decision-support-rate-pct 90 \
  --require-recommended-profile balanced \
  --allow-recommended-profiles balanced,speed \
  --require-modal-support-rate-pct 90 \
  --fail-on-no-go 1 \
  --summary-json "$STRICT_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_check_strict.log 2>&1
strict_rc=$?
set -e

if [[ "$strict_rc" -ne 0 ]]; then
  echo "expected strict path rc=0, got rc=$strict_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_check_strict.log
  exit 1
fi
if ! jq -e '
  .schema.id == "profile_compare_multi_vm_stability_check_summary"
  and .decision == "GO"
  and .status == "ok"
  and .rc == 0
  and (.violations | length) == 0
  and .failure_reason_code == null
  and .inputs.policy.require_decision_consensus == true
  and .observed.modal_decision == "GO"
  and .observed.modal_recommended_profile == "balanced"
' "$STRICT_SUMMARY" >/dev/null 2>&1; then
  echo "strict summary JSON mismatch"
  cat "$STRICT_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-check] run-summary schema compatibility path"
RUN_STYLE_CHECK_SUMMARY="$TMP_DIR/check_run_style_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --stability-summary-json "$RUN_STYLE_SUMMARY" \
  --require-status-pass 1 \
  --require-min-runs-requested 3 \
  --require-min-runs-completed 3 \
  --require-max-runs-fail 0 \
  --require-decision-consensus 1 \
  --require-modal-decision GO \
  --require-modal-decision-support-rate-pct 90 \
  --require-recommended-profile balanced \
  --allow-recommended-profiles balanced,speed \
  --require-modal-support-rate-pct 90 \
  --fail-on-no-go 1 \
  --summary-json "$RUN_STYLE_CHECK_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_check_run_style.log 2>&1
run_style_rc=$?
set -e

if [[ "$run_style_rc" -ne 0 ]]; then
  echo "expected run-style schema path rc=0, got rc=$run_style_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_check_run_style.log
  exit 1
fi
if ! jq -e '
  .decision == "GO"
  and .status == "ok"
  and .rc == 0
  and .inputs.stability_summary_json == "'"$RUN_STYLE_SUMMARY"'"
  and .observed.runs_requested == 3
  and .observed.runs_completed == 3
  and .observed.runs_fail == 0
' "$RUN_STYLE_CHECK_SUMMARY" >/dev/null 2>&1; then
  echo "run-style compatibility summary mismatch"
  cat "$RUN_STYLE_CHECK_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-check] NO-GO soft path with fail-on-no-go=0"
SOFT_SUMMARY="$TMP_DIR/check_soft_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --stability-summary-json "$FAIL_SUMMARY" \
  --require-status-pass 1 \
  --require-min-runs-requested 3 \
  --require-min-runs-completed 3 \
  --require-max-runs-fail 0 \
  --require-decision-consensus 1 \
  --require-modal-decision GO \
  --require-modal-decision-support-rate-pct 80 \
  --require-recommended-profile balanced \
  --allow-recommended-profiles balanced,speed \
  --require-modal-support-rate-pct 80 \
  --fail-on-no-go 0 \
  --summary-json "$SOFT_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_check_soft.log 2>&1
soft_rc=$?
set -e

if [[ "$soft_rc" -ne 0 ]]; then
  echo "expected soft NO-GO path rc=0, got rc=$soft_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_check_soft.log
  exit 1
fi
if ! jq -e '
  .decision == "NO-GO"
  and .status == "fail"
  and .rc == 0
  and (.violations | length) > 0
  and ((.failure_reason_code // "") | length) > 0
  and ((.operator_next_action // "") | length) > 0
  and ((.operator_next_action_command // "") | test("profile_compare_multi_vm_stability_check\\.sh"))
  and (.errors | length) > 0
' "$SOFT_SUMMARY" >/dev/null 2>&1; then
  echo "soft summary JSON mismatch"
  cat "$SOFT_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-check] consensus optional policy"
OPTIONAL_SUMMARY="$TMP_DIR/check_optional_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --stability-summary-json "$FAIL_SUMMARY" \
  --require-status-pass 1 \
  --require-min-runs-requested 3 \
  --require-min-runs-completed 3 \
  --require-max-runs-fail 2 \
  --require-decision-consensus 0 \
  --require-modal-decision NO-GO \
  --require-modal-decision-support-rate-pct 60 \
  --require-recommended-profile private \
  --allow-recommended-profiles private,speed \
  --require-modal-support-rate-pct 60 \
  --fail-on-no-go 1 \
  --summary-json "$OPTIONAL_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_check_optional.log 2>&1
optional_rc=$?
set -e

if [[ "$optional_rc" -ne 0 ]]; then
  echo "expected optional-consensus path rc=0, got rc=$optional_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_check_optional.log
  exit 1
fi
if ! jq -e '
  .decision == "GO"
  and .status == "ok"
  and .rc == 0
  and .inputs.policy.require_decision_consensus == false
  and .observed.modal_decision == "NO-GO"
  and .observed.modal_recommended_profile == "private"
' "$OPTIONAL_SUMMARY" >/dev/null 2>&1; then
  echo "optional-consensus summary JSON mismatch"
  cat "$OPTIONAL_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-check] modal decision tie-break prefers NO-GO"
TIE_CHECK_SUMMARY="$TMP_DIR/check_tie_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --stability-summary-json "$TIE_SUMMARY" \
  --require-status-pass 1 \
  --require-min-runs-requested 2 \
  --require-min-runs-completed 2 \
  --require-max-runs-fail 0 \
  --require-decision-consensus 0 \
  --require-modal-decision NO-GO \
  --require-modal-decision-support-rate-pct 50 \
  --allow-recommended-profiles balanced,private \
  --require-modal-support-rate-pct 50 \
  --fail-on-no-go 1 \
  --summary-json "$TIE_CHECK_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_check_tie.log 2>&1
tie_rc=$?
set -e

if [[ "$tie_rc" -ne 0 ]]; then
  echo "expected tie-break path rc=0, got rc=$tie_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_check_tie.log
  exit 1
fi
if ! jq -e '
  .decision == "GO"
  and .status == "ok"
  and .rc == 0
  and .observed.modal_decision == "NO-GO"
  and .observed.modal_decision_count == 1
  and .observed.modal_decision_support_rate_pct == 50
' "$TIE_CHECK_SUMMARY" >/dev/null 2>&1; then
  echo "tie-break summary JSON mismatch"
  cat "$TIE_CHECK_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-check] tightened default split safety"
DEFAULT_SPLIT_SUMMARY="$TMP_DIR/check_default_split_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --stability-summary-json "$SPLIT_GO_SUMMARY" \
  --fail-on-no-go 0 \
  --summary-json "$DEFAULT_SPLIT_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_check_default_split.log 2>&1
default_split_rc=$?
set -e

if [[ "$default_split_rc" -ne 0 ]]; then
  echo "expected default split safety soft path rc=0, got rc=$default_split_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_check_default_split.log
  exit 1
fi
if ! jq -e '
  .decision == "NO-GO"
  and .status == "fail"
  and .rc == 0
  and .inputs.policy.require_decision_consensus == true
  and .inputs.policy.require_modal_decision_support_rate_pct == 67
  and ((.errors | map(test("decision_consensus|modal decision support rate")) | any) == true)
' "$DEFAULT_SPLIT_SUMMARY" >/dev/null 2>&1; then
  echo "default split safety summary JSON mismatch"
  cat "$DEFAULT_SPLIT_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-check] fractional runs fail closed"
FRACTIONAL_RUNS_CHECK_SUMMARY="$TMP_DIR/check_fractional_runs_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --stability-summary-json "$FRACTIONAL_RUNS_SUMMARY" \
  --fail-on-no-go 0 \
  --summary-json "$FRACTIONAL_RUNS_CHECK_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_check_fractional_runs.log 2>&1
fractional_runs_rc=$?
set -e

if [[ "$fractional_runs_rc" -ne 0 ]]; then
  echo "expected fractional-runs soft path rc=0, got rc=$fractional_runs_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_check_fractional_runs.log
  exit 1
fi
if ! jq -e '
  .decision == "NO-GO"
  and .status == "fail"
  and .rc == 0
  and ((.errors | map(test("runs_requested is missing or invalid")) | any) == true)
' "$FRACTIONAL_RUNS_CHECK_SUMMARY" >/dev/null 2>&1; then
  echo "fractional-runs fail-closed summary mismatch"
  cat "$FRACTIONAL_RUNS_CHECK_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-check] reported/computed consensus mismatch fails closed"
CONSENSUS_MISMATCH_CHECK_SUMMARY="$TMP_DIR/check_consensus_mismatch_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --stability-summary-json "$CONSENSUS_MISMATCH_SUMMARY" \
  --require-decision-consensus 0 \
  --require-modal-decision GO \
  --require-modal-decision-support-rate-pct 60 \
  --require-recommended-profile balanced \
  --allow-recommended-profiles balanced,speed,private \
  --require-modal-support-rate-pct 60 \
  --fail-on-no-go 0 \
  --summary-json "$CONSENSUS_MISMATCH_CHECK_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_check_consensus_mismatch.log 2>&1
consensus_mismatch_rc=$?
set -e

if [[ "$consensus_mismatch_rc" -ne 0 ]]; then
  echo "expected consensus-mismatch soft path rc=0, got rc=$consensus_mismatch_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_check_consensus_mismatch.log
  exit 1
fi
if ! jq -e '
  .decision == "NO-GO"
  and .status == "fail"
  and .rc == 0
  and .observed.decision_consensus_reported == true
  and .observed.decision_consensus_computed == false
  and ((.errors | map(test("decision_consensus mismatch between reported and computed")) | any) == true)
' "$CONSENSUS_MISMATCH_CHECK_SUMMARY" >/dev/null 2>&1; then
  echo "consensus-mismatch fail-closed summary mismatch"
  cat "$CONSENSUS_MISMATCH_CHECK_SUMMARY"
  exit 1
fi

echo "profile compare multi-vm stability check integration ok"
