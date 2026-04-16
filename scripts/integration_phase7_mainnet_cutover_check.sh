#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod grep cat cmp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PHASE7_MAINNET_CUTOVER_CHECK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase7_mainnet_cutover_check.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS_HANDOFF="$TMP_DIR/phase6_handoff_pass.json"
PASS_CONTRACTS="$TMP_DIR/phase6_contracts_pass.json"
PASS_OUTPUT="$TMP_DIR/pass_output.json"
PASS_LOG="$TMP_DIR/pass.log"
PASS_CANONICAL="$TMP_DIR/pass_canonical_summary.json"

FAIL_HANDOFF="$TMP_DIR/phase6_handoff_module_tx_fail.json"
FAIL_OUTPUT="$TMP_DIR/fail_output.json"
FAIL_LOG="$TMP_DIR/fail.log"
FAIL_CANONICAL="$TMP_DIR/fail_canonical_summary.json"

RELAXED_OUTPUT="$TMP_DIR/relaxed_output.json"
RELAXED_LOG="$TMP_DIR/relaxed.log"
RELAXED_CANONICAL="$TMP_DIR/relaxed_canonical_summary.json"

DUAL_STAGE_CONTRACTS="$TMP_DIR/phase6_contracts_stage_only.json"
DUAL_OUTPUT="$TMP_DIR/dual_stage_output.json"
DUAL_LOG="$TMP_DIR/dual_stage.log"
DUAL_CANONICAL="$TMP_DIR/dual_stage_canonical_summary.json"

OP_DEFAULT_OUTPUT="$TMP_DIR/operator_default_output.json"
OP_DEFAULT_LOG="$TMP_DIR/operator_default.log"
OP_DEFAULT_CANONICAL="$TMP_DIR/operator_default_canonical_summary.json"

OP_REQUIRED_MISSING_OUTPUT="$TMP_DIR/operator_required_missing_output.json"
OP_REQUIRED_MISSING_LOG="$TMP_DIR/operator_required_missing.log"
OP_REQUIRED_MISSING_CANONICAL="$TMP_DIR/operator_required_missing_canonical_summary.json"

OP_REQUIRED_FALSE_OUTPUT="$TMP_DIR/operator_required_false_output.json"
OP_REQUIRED_FALSE_LOG="$TMP_DIR/operator_required_false.log"
OP_REQUIRED_FALSE_CANONICAL="$TMP_DIR/operator_required_false_canonical_summary.json"

ACTIVATION_GATE_GO_SUMMARY="$TMP_DIR/mainnet_activation_gate_go.json"
ACTIVATION_GATE_STATUS_FAIL_SUMMARY="$TMP_DIR/mainnet_activation_gate_status_fail.json"
ACTIVATION_GATE_DECISION_NO_GO_SUMMARY="$TMP_DIR/mainnet_activation_gate_decision_no_go.json"

ACTIVATION_REQUIRED_GO_OUTPUT="$TMP_DIR/activation_required_go_output.json"
ACTIVATION_REQUIRED_GO_LOG="$TMP_DIR/activation_required_go.log"
ACTIVATION_REQUIRED_GO_CANONICAL="$TMP_DIR/activation_required_go_canonical_summary.json"

ACTIVATION_REQUIRED_STATUS_FAIL_OUTPUT="$TMP_DIR/activation_required_status_fail_output.json"
ACTIVATION_REQUIRED_STATUS_FAIL_LOG="$TMP_DIR/activation_required_status_fail.log"
ACTIVATION_REQUIRED_STATUS_FAIL_CANONICAL="$TMP_DIR/activation_required_status_fail_canonical_summary.json"

ACTIVATION_REQUIRED_MISSING_OUTPUT="$TMP_DIR/activation_required_missing_output.json"
ACTIVATION_REQUIRED_MISSING_LOG="$TMP_DIR/activation_required_missing.log"
ACTIVATION_REQUIRED_MISSING_CANONICAL="$TMP_DIR/activation_required_missing_canonical_summary.json"

ACTIVATION_REQUIRED_FALSE_OUTPUT="$TMP_DIR/activation_required_false_output.json"
ACTIVATION_REQUIRED_FALSE_LOG="$TMP_DIR/activation_required_false.log"
ACTIVATION_REQUIRED_FALSE_CANONICAL="$TMP_DIR/activation_required_false_canonical_summary.json"

cat >"$PASS_HANDOFF" <<'EOF_PASS_HANDOFF'
{
  "version": 1,
  "schema": {
    "id": "phase6_cosmos_l1_build_testnet_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "handoff": {
    "run_pipeline_ok": true,
    "module_tx_surface_ok": true,
    "tdpnd_grpc_runtime_smoke_ok": true,
    "tdpnd_grpc_live_smoke_ok": true,
    "tdpnd_grpc_auth_live_smoke_ok": true,
    "tdpnd_comet_runtime_smoke_ok": true
  }
}
EOF_PASS_HANDOFF

cat >"$PASS_CONTRACTS" <<'EOF_PASS_CONTRACTS'
{
  "version": 1,
  "schema": {
    "id": "ci_phase6_cosmos_l1_contracts_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "signals": {
    "dual_write_parity_ok": true
  }
}
EOF_PASS_CONTRACTS

cat >"$FAIL_HANDOFF" <<'EOF_FAIL_HANDOFF'
{
  "version": 1,
  "schema": {
    "id": "phase6_cosmos_l1_build_testnet_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "handoff": {
    "run_pipeline_ok": true,
    "module_tx_surface_ok": false,
    "tdpnd_grpc_runtime_smoke_ok": true,
    "tdpnd_grpc_live_smoke_ok": true,
    "tdpnd_grpc_auth_live_smoke_ok": true,
    "tdpnd_comet_runtime_smoke_ok": false
  }
}
EOF_FAIL_HANDOFF

cat >"$DUAL_STAGE_CONTRACTS" <<'EOF_DUAL_STAGE_CONTRACTS'
{
  "version": 1,
  "schema": {
    "id": "ci_phase6_cosmos_l1_contracts_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "phase6_cosmos_dual_write_parity": {
      "status": "pass"
    }
  }
}
EOF_DUAL_STAGE_CONTRACTS

cat >"$ACTIVATION_GATE_GO_SUMMARY" <<'EOF_ACTIVATION_GATE_GO_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "blockchain_mainnet_activation_gate_summary",
    "major": 1,
    "minor": 0
  },
  "decision": "GO",
  "status": "go",
  "go": true
}
EOF_ACTIVATION_GATE_GO_SUMMARY

cat >"$ACTIVATION_GATE_STATUS_FAIL_SUMMARY" <<'EOF_ACTIVATION_GATE_STATUS_FAIL_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "blockchain_mainnet_activation_gate_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail"
}
EOF_ACTIVATION_GATE_STATUS_FAIL_SUMMARY

cat >"$ACTIVATION_GATE_DECISION_NO_GO_SUMMARY" <<'EOF_ACTIVATION_GATE_DECISION_NO_GO_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "blockchain_mainnet_activation_gate_summary",
    "major": 1,
    "minor": 0
  },
  "decision": "NO-GO"
}
EOF_ACTIVATION_GATE_DECISION_NO_GO_SUMMARY

echo "[phase7-mainnet-cutover-check] pass path"
PHASE7_MAINNET_CUTOVER_CHECK_CANONICAL_SUMMARY_JSON="$PASS_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --phase6-handoff-summary-json "$PASS_HANDOFF" \
  --phase6-contracts-summary-json "$PASS_CONTRACTS" \
  --rollback-path-ready 1 \
  --operator-approval-ok 1 \
  --summary-json "$PASS_OUTPUT" \
  --show-json 0 >"$PASS_LOG" 2>&1

if [[ ! -f "$PASS_CANONICAL" ]]; then
  echo "missing canonical summary on pass path: $PASS_CANONICAL"
  cat "$PASS_LOG"
  exit 1
fi
if ! jq -e '
  .version == 1
  and .schema.id == "phase7_mainnet_cutover_check_summary"
  and .status == "pass"
  and .rc == 0
  and .fail_closed == true
  and .artifacts.canonical_summary_json == $expected_canonical
  and .inputs.usable.phase6_handoff_summary_json == true
  and .inputs.usable.phase6_contracts_summary_json == true
  and .policy.require_run_pipeline_ok == true
  and .policy.require_module_tx_surface_ok == true
  and .policy.require_tdpnd_grpc_runtime_smoke_ok == true
  and .policy.require_tdpnd_grpc_live_smoke_ok == true
  and .policy.require_tdpnd_grpc_auth_live_smoke_ok == true
  and .policy.require_tdpnd_comet_runtime_smoke_ok == false
  and .policy.require_dual_write_parity_ok == true
  and .policy.require_mainnet_activation_gate_go == false
  and .policy.require_rollback_path_ready == true
  and .policy.require_operator_approval_ok == false
  and .signals.run_pipeline_ok == true
  and .signals.module_tx_surface_ok == true
  and .signals.tdpnd_grpc_runtime_smoke_ok == true
  and .signals.tdpnd_grpc_live_smoke_ok == true
  and .signals.tdpnd_grpc_auth_live_smoke_ok == true
  and .signals.tdpnd_comet_runtime_smoke_ok == true
  and .signals.dual_write_parity_ok == true
  and .signals.mainnet_activation_gate_go == null
  and .stages.mainnet_activation_gate.status == "missing"
  and .signals.rollback_path_ready == true
  and .signals.operator_approval_ok == true
' --arg expected_canonical "$PASS_CANONICAL" "$PASS_OUTPUT" >/dev/null; then
  echo "pass-path summary mismatch"
  cat "$PASS_OUTPUT"
  cat "$PASS_LOG"
  exit 1
fi
if ! cmp -s "$PASS_OUTPUT" "$PASS_CANONICAL"; then
  echo "pass-path canonical summary diverges from run summary"
  cat "$PASS_OUTPUT"
  cat "$PASS_CANONICAL"
  exit 1
fi

echo "[phase7-mainnet-cutover-check] fail-closed module tx path"
set +e
PHASE7_MAINNET_CUTOVER_CHECK_CANONICAL_SUMMARY_JSON="$FAIL_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --phase6-handoff-summary-json "$FAIL_HANDOFF" \
  --phase6-contracts-summary-json "$PASS_CONTRACTS" \
  --rollback-path-ready 1 \
  --summary-json "$FAIL_OUTPUT" \
  --show-json 0 >"$FAIL_LOG" 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for fail-closed module tx path, got rc=$fail_rc"
  cat "$FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .signals.module_tx_surface_ok == false
  and .signals.tdpnd_comet_runtime_smoke_ok == false
  and .stages.module_tx_surface.status == "fail"
  and ((.decision.reasons // []) | any(test("module_tx_surface_ok is false")))
' "$FAIL_OUTPUT" >/dev/null; then
  echo "fail-path summary mismatch"
  cat "$FAIL_OUTPUT"
  cat "$FAIL_LOG"
  exit 1
fi

echo "[phase7-mainnet-cutover-check] relaxed module tx requirement"
PHASE7_MAINNET_CUTOVER_CHECK_CANONICAL_SUMMARY_JSON="$RELAXED_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --phase6-handoff-summary-json "$FAIL_HANDOFF" \
  --phase6-contracts-summary-json "$PASS_CONTRACTS" \
  --rollback-path-ready 1 \
  --require-module-tx-surface-ok 0 \
  --summary-json "$RELAXED_OUTPUT" \
  --show-json 0 >"$RELAXED_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_module_tx_surface_ok == false
  and .signals.module_tx_surface_ok == false
  and .stages.module_tx_surface.status == "fail"
' "$RELAXED_OUTPUT" >/dev/null; then
  echo "relaxed-path summary mismatch"
  cat "$RELAXED_OUTPUT"
  cat "$RELAXED_LOG"
  exit 1
fi

echo "[phase7-mainnet-cutover-check] dual-write parity fallback from stage status"
PHASE7_MAINNET_CUTOVER_CHECK_CANONICAL_SUMMARY_JSON="$DUAL_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --phase6-handoff-summary-json "$PASS_HANDOFF" \
  --phase6-contracts-summary-json "$DUAL_STAGE_CONTRACTS" \
  --rollback-path-ready 1 \
  --summary-json "$DUAL_OUTPUT" \
  --show-json 0 >"$DUAL_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .signals.dual_write_parity_ok == true
  and .stages.dual_write_parity.status == "pass"
' "$DUAL_OUTPUT" >/dev/null; then
  echo "dual-write fallback summary mismatch"
  cat "$DUAL_OUTPUT"
  cat "$DUAL_LOG"
  exit 1
fi

echo "[phase7-mainnet-cutover-check] mainnet activation gate GO when required"
PHASE7_MAINNET_CUTOVER_CHECK_CANONICAL_SUMMARY_JSON="$ACTIVATION_REQUIRED_GO_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --phase6-handoff-summary-json "$PASS_HANDOFF" \
  --phase6-contracts-summary-json "$PASS_CONTRACTS" \
  --mainnet-activation-gate-summary-json "$ACTIVATION_GATE_GO_SUMMARY" \
  --require-mainnet-activation-gate-go 1 \
  --rollback-path-ready 1 \
  --summary-json "$ACTIVATION_REQUIRED_GO_OUTPUT" \
  --show-json 0 >"$ACTIVATION_REQUIRED_GO_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_mainnet_activation_gate_go == true
  and .inputs.usable.mainnet_activation_gate_summary_json == true
  and .signals.mainnet_activation_gate_go == true
  and .stages.mainnet_activation_gate.status == "pass"
  and .stages.mainnet_activation_gate.ok == true
' "$ACTIVATION_REQUIRED_GO_OUTPUT" >/dev/null; then
  echo "activation-required-go summary mismatch"
  cat "$ACTIVATION_REQUIRED_GO_OUTPUT"
  cat "$ACTIVATION_REQUIRED_GO_LOG"
  exit 1
fi

echo "[phase7-mainnet-cutover-check] mainnet activation gate fail status when required"
set +e
PHASE7_MAINNET_CUTOVER_CHECK_CANONICAL_SUMMARY_JSON="$ACTIVATION_REQUIRED_STATUS_FAIL_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --phase6-handoff-summary-json "$PASS_HANDOFF" \
  --phase6-contracts-summary-json "$PASS_CONTRACTS" \
  --mainnet-activation-gate-summary-json "$ACTIVATION_GATE_STATUS_FAIL_SUMMARY" \
  --require-mainnet-activation-gate-go 1 \
  --rollback-path-ready 1 \
  --summary-json "$ACTIVATION_REQUIRED_STATUS_FAIL_OUTPUT" \
  --show-json 0 >"$ACTIVATION_REQUIRED_STATUS_FAIL_LOG" 2>&1
activation_fail_status_rc=$?
set -e
if [[ "$activation_fail_status_rc" -ne 1 ]]; then
  echo "expected rc=1 when activation gate required signal resolves false from status=fail, got rc=$activation_fail_status_rc"
  cat "$ACTIVATION_REQUIRED_STATUS_FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .policy.require_mainnet_activation_gate_go == true
  and .signals.mainnet_activation_gate_go == false
  and .stages.mainnet_activation_gate.status == "fail"
  and ((.decision.reasons // []) | any(test("mainnet_activation_gate_go is false")))
' "$ACTIVATION_REQUIRED_STATUS_FAIL_OUTPUT" >/dev/null; then
  echo "activation-required-status-fail summary mismatch"
  cat "$ACTIVATION_REQUIRED_STATUS_FAIL_OUTPUT"
  cat "$ACTIVATION_REQUIRED_STATUS_FAIL_LOG"
  exit 1
fi

echo "[phase7-mainnet-cutover-check] mainnet activation gate required but missing"
set +e
PHASE7_MAINNET_CUTOVER_CHECK_CANONICAL_SUMMARY_JSON="$ACTIVATION_REQUIRED_MISSING_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --phase6-handoff-summary-json "$PASS_HANDOFF" \
  --phase6-contracts-summary-json "$PASS_CONTRACTS" \
  --require-mainnet-activation-gate-go 1 \
  --rollback-path-ready 1 \
  --summary-json "$ACTIVATION_REQUIRED_MISSING_OUTPUT" \
  --show-json 0 >"$ACTIVATION_REQUIRED_MISSING_LOG" 2>&1
activation_missing_rc=$?
set -e
if [[ "$activation_missing_rc" -ne 1 ]]; then
  echo "expected rc=1 when activation gate signal is required but missing, got rc=$activation_missing_rc"
  cat "$ACTIVATION_REQUIRED_MISSING_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .policy.require_mainnet_activation_gate_go == true
  and .signals.mainnet_activation_gate_go == null
  and .stages.mainnet_activation_gate.status == "missing"
  and ((.decision.reasons // []) | any(test("mainnet_activation_gate_go unresolved")))
' "$ACTIVATION_REQUIRED_MISSING_OUTPUT" >/dev/null; then
  echo "activation-required-missing summary mismatch"
  cat "$ACTIVATION_REQUIRED_MISSING_OUTPUT"
  cat "$ACTIVATION_REQUIRED_MISSING_LOG"
  exit 1
fi

echo "[phase7-mainnet-cutover-check] mainnet activation gate required and NO-GO decision"
set +e
PHASE7_MAINNET_CUTOVER_CHECK_CANONICAL_SUMMARY_JSON="$ACTIVATION_REQUIRED_FALSE_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --phase6-handoff-summary-json "$PASS_HANDOFF" \
  --phase6-contracts-summary-json "$PASS_CONTRACTS" \
  --mainnet-activation-gate-summary-json "$ACTIVATION_GATE_DECISION_NO_GO_SUMMARY" \
  --require-mainnet-activation-gate-go 1 \
  --rollback-path-ready 1 \
  --summary-json "$ACTIVATION_REQUIRED_FALSE_OUTPUT" \
  --show-json 0 >"$ACTIVATION_REQUIRED_FALSE_LOG" 2>&1
activation_false_rc=$?
set -e
if [[ "$activation_false_rc" -ne 1 ]]; then
  echo "expected rc=1 when activation gate required signal resolves false from decision=NO-GO, got rc=$activation_false_rc"
  cat "$ACTIVATION_REQUIRED_FALSE_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .policy.require_mainnet_activation_gate_go == true
  and .signals.mainnet_activation_gate_go == false
  and .stages.mainnet_activation_gate.status == "fail"
  and ((.decision.reasons // []) | any(test("mainnet_activation_gate_go is false")))
' "$ACTIVATION_REQUIRED_FALSE_OUTPUT" >/dev/null; then
  echo "activation-required-false summary mismatch"
  cat "$ACTIVATION_REQUIRED_FALSE_OUTPUT"
  cat "$ACTIVATION_REQUIRED_FALSE_LOG"
  exit 1
fi

echo "[phase7-mainnet-cutover-check] operator approval default and required-toggle behavior"
PHASE7_MAINNET_CUTOVER_CHECK_CANONICAL_SUMMARY_JSON="$OP_DEFAULT_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --phase6-handoff-summary-json "$PASS_HANDOFF" \
  --phase6-contracts-summary-json "$PASS_CONTRACTS" \
  --rollback-path-ready 1 \
  --summary-json "$OP_DEFAULT_OUTPUT" \
  --show-json 0 >"$OP_DEFAULT_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_operator_approval_ok == false
  and .signals.operator_approval_ok == null
  and .stages.operator_approval.status == "missing"
' "$OP_DEFAULT_OUTPUT" >/dev/null; then
  echo "operator-default summary mismatch"
  cat "$OP_DEFAULT_OUTPUT"
  cat "$OP_DEFAULT_LOG"
  exit 1
fi

set +e
PHASE7_MAINNET_CUTOVER_CHECK_CANONICAL_SUMMARY_JSON="$OP_REQUIRED_MISSING_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --phase6-handoff-summary-json "$PASS_HANDOFF" \
  --phase6-contracts-summary-json "$PASS_CONTRACTS" \
  --rollback-path-ready 1 \
  --require-operator-approval-ok 1 \
  --summary-json "$OP_REQUIRED_MISSING_OUTPUT" \
  --show-json 0 >"$OP_REQUIRED_MISSING_LOG" 2>&1
operator_missing_rc=$?
set -e
if [[ "$operator_missing_rc" -ne 1 ]]; then
  echo "expected rc=1 when operator approval is required but missing, got rc=$operator_missing_rc"
  cat "$OP_REQUIRED_MISSING_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .policy.require_operator_approval_ok == true
  and .signals.operator_approval_ok == null
  and .stages.operator_approval.status == "missing"
  and ((.decision.reasons // []) | any(test("operator_approval_ok unresolved")))
' "$OP_REQUIRED_MISSING_OUTPUT" >/dev/null; then
  echo "operator-required-missing summary mismatch"
  cat "$OP_REQUIRED_MISSING_OUTPUT"
  cat "$OP_REQUIRED_MISSING_LOG"
  exit 1
fi

set +e
PHASE7_MAINNET_CUTOVER_CHECK_CANONICAL_SUMMARY_JSON="$OP_REQUIRED_FALSE_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --phase6-handoff-summary-json "$PASS_HANDOFF" \
  --phase6-contracts-summary-json "$PASS_CONTRACTS" \
  --rollback-path-ready 1 \
  --operator-approval-ok 0 \
  --require-operator-approval-ok 1 \
  --summary-json "$OP_REQUIRED_FALSE_OUTPUT" \
  --show-json 0 >"$OP_REQUIRED_FALSE_LOG" 2>&1
operator_false_rc=$?
set -e
if [[ "$operator_false_rc" -ne 1 ]]; then
  echo "expected rc=1 when operator approval is required but false, got rc=$operator_false_rc"
  cat "$OP_REQUIRED_FALSE_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .signals.operator_approval_ok == false
  and .stages.operator_approval.status == "fail"
  and ((.decision.reasons // []) | any(test("operator_approval_ok is false")))
' "$OP_REQUIRED_FALSE_OUTPUT" >/dev/null; then
  echo "operator-required-false summary mismatch"
  cat "$OP_REQUIRED_FALSE_OUTPUT"
  cat "$OP_REQUIRED_FALSE_LOG"
  exit 1
fi

echo "phase7 mainnet cutover check integration ok"
