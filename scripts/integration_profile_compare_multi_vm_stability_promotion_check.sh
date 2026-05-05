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

SCRIPT_UNDER_TEST="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/profile_compare_multi_vm_stability_promotion_check.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS_CYCLE_A="$TMP_DIR/cycle_pass_a.json"
PASS_CYCLE_B="$TMP_DIR/cycle_pass_b.json"
PASS_CYCLE_C="$TMP_DIR/cycle_pass_c.json"
NO_GO_CYCLE="$TMP_DIR/cycle_no_go.json"
POLICY_MISMATCH_CYCLE="$TMP_DIR/cycle_policy_mismatch.json"
SCHEMA_INVALID_CYCLE="$TMP_DIR/cycle_schema_invalid.json"
INVALID_CONTRACT_CYCLE="$TMP_DIR/cycle_invalid_contract.json"

cat >"$PASS_CYCLE_A" <<'EOF_PASS_CYCLE_A'
{
  "version": 1,
  "schema": { "id": "profile_compare_multi_vm_stability_cycle_summary" },
  "status": "pass",
  "rc": 0,
  "decision": "GO",
  "inputs": { "check": { "policy": { "require_modal_decision": "GO" } } },
  "check": { "decision": "GO" }
}
EOF_PASS_CYCLE_A

cat >"$PASS_CYCLE_B" <<'EOF_PASS_CYCLE_B'
{
  "version": 1,
  "schema": { "id": "profile_compare_multi_vm_stability_cycle_summary" },
  "status": "pass",
  "rc": 0,
  "decision": "GO",
  "inputs": { "check": { "policy": { "require_modal_decision": "GO" } } },
  "check": { "decision": "GO" }
}
EOF_PASS_CYCLE_B

cat >"$PASS_CYCLE_C" <<'EOF_PASS_CYCLE_C'
{
  "version": 1,
  "schema": { "id": "profile_compare_multi_vm_stability_cycle_summary" },
  "status": "pass",
  "rc": 0,
  "decision": "GO",
  "inputs": { "check": { "policy": { "require_modal_decision": "GO" } } },
  "check": { "decision": "GO" }
}
EOF_PASS_CYCLE_C

cat >"$NO_GO_CYCLE" <<'EOF_NO_GO_CYCLE'
{
  "version": 1,
  "schema": { "id": "profile_compare_multi_vm_stability_cycle_summary" },
  "status": "fail",
  "rc": 1,
  "decision": "NO-GO",
  "inputs": { "check": { "policy": { "require_modal_decision": "GO" } } },
  "check": { "decision": "NO-GO" }
}
EOF_NO_GO_CYCLE

cat >"$POLICY_MISMATCH_CYCLE" <<'EOF_POLICY_MISMATCH_CYCLE'
{
  "version": 1,
  "schema": { "id": "profile_compare_multi_vm_stability_cycle_summary" },
  "status": "pass",
  "rc": 0,
  "decision": "GO",
  "inputs": { "check": { "policy": { "require_modal_decision": "NO-GO" } } },
  "check": { "decision": "GO" }
}
EOF_POLICY_MISMATCH_CYCLE

cat >"$SCHEMA_INVALID_CYCLE" <<'EOF_SCHEMA_INVALID_CYCLE'
{
  "version": 1,
  "schema": { "id": "profile_compare_multi_vm_cycle_summary" },
  "status": "pass",
  "rc": 0,
  "decision": "GO",
  "inputs": { "check": { "policy": { "require_modal_decision": "GO" } } },
  "check": { "decision": "GO" }
}
EOF_SCHEMA_INVALID_CYCLE

cat >"$INVALID_CONTRACT_CYCLE" <<'EOF_INVALID_CONTRACT_CYCLE'
{
  "version": 1,
  "schema": { "id": "profile_compare_multi_vm_stability_cycle_summary" },
  "status": "pass",
  "rc": 5,
  "decision": "GO",
  "inputs": { "check": { "policy": { "require_modal_decision": "GO" } } },
  "check": { "decision": "GO" }
}
EOF_INVALID_CONTRACT_CYCLE

echo "[profile-compare-multi-vm-stability-promotion-check] strict happy path"
STRICT_SUMMARY="$TMP_DIR/promotion_check_strict_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --cycle-summary-json "$PASS_CYCLE_A" \
  --cycle-summary-json "$PASS_CYCLE_B" \
  --cycle-summary-json "$PASS_CYCLE_C" \
  --require-min-cycles 3 \
  --require-min-pass-cycles 3 \
  --require-max-fail-cycles 0 \
  --require-max-warn-cycles 0 \
  --require-min-pass-rate-pct 100 \
  --require-min-go-decision-rate-pct 100 \
  --require-cycle-schema-valid 1 \
  --require-check-modal-decision GO \
  --fail-on-no-go 1 \
  --summary-json "$STRICT_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_promotion_check_strict.log 2>&1
strict_rc=$?
set -e

if [[ "$strict_rc" -ne 0 ]]; then
  echo "expected strict happy path rc=0, got rc=$strict_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_promotion_check_strict.log
  exit 1
fi
if ! jq -e '
  .schema.id == "profile_compare_multi_vm_stability_promotion_check_summary"
  and .decision == "GO"
  and .status == "ok"
  and .rc == 0
  and .failure_reason_code == null
  and .operator_next_action_command != null
  and .observed.cycles_total == 3
  and .observed.cycles_promotion_pass == 3
  and (.violations | length) == 0
  and .outcome.should_promote == true
  and .outcome.action == "promote_allowed"
' "$STRICT_SUMMARY" >/dev/null 2>&1; then
  echo "strict happy-path summary mismatch"
  cat "$STRICT_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-promotion-check] invalid cycle contract is fail-closed even with permissive thresholds"
CONTRACT_SUMMARY="$TMP_DIR/promotion_check_invalid_contract_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --cycle-summary-json "$INVALID_CONTRACT_CYCLE" \
  --require-min-cycles 1 \
  --require-min-pass-cycles 0 \
  --require-max-fail-cycles 0 \
  --require-max-warn-cycles 0 \
  --require-min-pass-rate-pct 0 \
  --require-min-go-decision-rate-pct 0 \
  --require-cycle-schema-valid 1 \
  --require-check-modal-decision GO \
  --fail-on-no-go 1 \
  --summary-json "$CONTRACT_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_promotion_check_contract.log 2>&1
contract_rc=$?
set -e

if [[ "$contract_rc" -eq 0 ]]; then
  echo "expected invalid-contract path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_promotion_check_contract.log
  exit 1
fi
if ! jq -e '
  .decision == "NO-GO"
  and .status == "fail"
  and .rc != 0
  and .failure_reason_code == "cycle_contract_invalid"
  and .observed.cycle_contract_invalid_cycles == 1
  and ((.violations | map(.code) | index("cycle_contract_invalid")) != null)
  and (.cycles[0].reasons | map(.code) | index("cycle_contract_invalid")) != null
  and ((.cycles[0].reasons | map(.message) | join(" ")) | test("decision=GO"))
  and ((.cycles[0].reasons | map(.message) | join(" ")) | test("rc=5"))
' "$CONTRACT_SUMMARY" >/dev/null 2>&1; then
  echo "invalid-contract summary mismatch"
  cat "$CONTRACT_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-promotion-check] NO-GO soft path when fail-on-no-go=0"
SOFT_SUMMARY="$TMP_DIR/promotion_check_soft_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --cycle-summary-json "$PASS_CYCLE_A" \
  --cycle-summary-json "$PASS_CYCLE_B" \
  --cycle-summary-json "$NO_GO_CYCLE" \
  --require-min-cycles 3 \
  --require-min-pass-cycles 3 \
  --require-max-fail-cycles 0 \
  --require-max-warn-cycles 0 \
  --require-min-pass-rate-pct 100 \
  --require-min-go-decision-rate-pct 100 \
  --require-cycle-schema-valid 1 \
  --require-check-modal-decision GO \
  --fail-on-no-go 0 \
  --summary-json "$SOFT_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_promotion_check_soft.log 2>&1
soft_rc=$?
set -e

if [[ "$soft_rc" -ne 0 ]]; then
  echo "expected soft NO-GO path rc=0, got rc=$soft_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_promotion_check_soft.log
  exit 1
fi
if ! jq -e '
  .decision == "NO-GO"
  and .status == "fail"
  and .rc == 0
  and (
    .failure_reason_code == "max_fail_cycles_exceeded"
    or .failure_reason_code == "min_pass_cycles_not_met"
    or .failure_reason_code == "pass_rate_below_threshold"
    or .failure_reason_code == "go_decision_rate_below_threshold"
  )
  and .enforcement.no_go_enforced == false
  and .outcome.action == "hold_promotion_warn_only"
  and ((.violations | map(.code) | index("min_pass_cycles_not_met")) != null)
  and ((.violations | map(.code) | index("max_fail_cycles_exceeded")) != null)
  and ((.violations | map(.code) | index("pass_rate_below_threshold")) != null)
  and ((.violations | map(.code) | index("go_decision_rate_below_threshold")) != null)
' "$SOFT_SUMMARY" >/dev/null 2>&1; then
  echo "soft NO-GO summary mismatch"
  cat "$SOFT_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-promotion-check] policy mismatch is enforced"
MISMATCH_SUMMARY="$TMP_DIR/promotion_check_policy_mismatch_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --cycle-summary-json "$POLICY_MISMATCH_CYCLE" \
  --require-min-cycles 1 \
  --require-min-pass-cycles 1 \
  --require-max-fail-cycles 0 \
  --require-max-warn-cycles 0 \
  --require-min-pass-rate-pct 100 \
  --require-min-go-decision-rate-pct 100 \
  --require-cycle-schema-valid 1 \
  --require-check-policy-modal-decision GO \
  --fail-on-no-go 1 \
  --summary-json "$MISMATCH_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_promotion_check_policy_mismatch.log 2>&1
mismatch_rc=$?
set -e

if [[ "$mismatch_rc" -eq 0 ]]; then
  echo "expected policy mismatch path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_promotion_check_policy_mismatch.log
  exit 1
fi
if ! jq -e '
  .decision == "NO-GO"
  and .status == "fail"
  and .rc != 0
  and (
    .failure_reason_code == "check_policy_modal_decision_mismatch"
    or .failure_reason_code == "min_pass_cycles_not_met"
    or .failure_reason_code == "pass_rate_below_threshold"
  )
  and .enforcement.no_go_enforced == true
  and .outcome.action == "hold_promotion_blocked"
  and ((.violations | map(.code) | index("check_policy_modal_decision_mismatch")) != null)
  and ((.violations | map(.code) | index("min_pass_cycles_not_met")) != null)
  and ((.violations | map(.code) | index("pass_rate_below_threshold")) != null)
  and ((.operator_next_action // "") | test("Hold promotion"))
' "$MISMATCH_SUMMARY" >/dev/null 2>&1; then
  echo "policy mismatch summary mismatch"
  cat "$MISMATCH_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-promotion-check] default policy mismatch is fail-closed"
DEFAULT_MISMATCH_SUMMARY="$TMP_DIR/promotion_check_default_policy_mismatch_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --cycle-summary-json "$POLICY_MISMATCH_CYCLE" \
  --require-min-cycles 1 \
  --require-min-pass-cycles 1 \
  --require-max-fail-cycles 0 \
  --require-max-warn-cycles 0 \
  --require-min-pass-rate-pct 100 \
  --require-min-go-decision-rate-pct 100 \
  --require-cycle-schema-valid 1 \
  --fail-on-no-go 1 \
  --summary-json "$DEFAULT_MISMATCH_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_promotion_check_default_policy_mismatch.log 2>&1
default_mismatch_rc=$?
set -e

if [[ "$default_mismatch_rc" -eq 0 ]]; then
  echo "expected default policy mismatch path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_promotion_check_default_policy_mismatch.log
  exit 1
fi
if ! jq -e '
  .decision == "NO-GO"
  and .status == "fail"
  and .rc != 0
  and (
    .failure_reason_code == "check_policy_modal_decision_mismatch"
    or .failure_reason_code == "min_pass_cycles_not_met"
    or .failure_reason_code == "pass_rate_below_threshold"
  )
  and .inputs.policy.require_check_policy_modal_decision == "GO"
  and ((.violations | map(.code) | index("check_policy_modal_decision_mismatch")) != null)
  and ((.violations | map(.code) | index("min_pass_cycles_not_met")) != null)
  and ((.violations | map(.code) | index("pass_rate_below_threshold")) != null)
' "$DEFAULT_MISMATCH_SUMMARY" >/dev/null 2>&1; then
  echo "default policy mismatch summary mismatch"
  cat "$DEFAULT_MISMATCH_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-promotion-check] cycle schema validation is enforced"
SCHEMA_SUMMARY="$TMP_DIR/promotion_check_schema_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --cycle-summary-json "$SCHEMA_INVALID_CYCLE" \
  --require-min-cycles 1 \
  --require-min-pass-cycles 1 \
  --require-max-fail-cycles 0 \
  --require-max-warn-cycles 0 \
  --require-min-pass-rate-pct 100 \
  --require-min-go-decision-rate-pct 100 \
  --require-cycle-schema-valid 1 \
  --fail-on-no-go 1 \
  --summary-json "$SCHEMA_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_promotion_check_schema.log 2>&1
schema_rc=$?
set -e

if [[ "$schema_rc" -eq 0 ]]; then
  echo "expected cycle-schema validation path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_promotion_check_schema.log
  exit 1
fi
if ! jq -e '
  .decision == "NO-GO"
  and .status == "fail"
  and .rc != 0
  and (
    .failure_reason_code == "cycle_schema_invalid"
    or .failure_reason_code == "min_pass_cycles_not_met"
    or .failure_reason_code == "max_fail_cycles_exceeded"
    or .failure_reason_code == "pass_rate_below_threshold"
  )
  and .observed.cycle_schema_invalid_cycles == 1
  and ((.violations | map(.code) | index("cycle_schema_invalid")) != null)
  and ((.violations | map(.code) | index("min_pass_cycles_not_met")) != null)
  and ((.violations | map(.code) | index("max_fail_cycles_exceeded")) != null)
  and ((.violations | map(.code) | index("pass_rate_below_threshold")) != null)
' "$SCHEMA_SUMMARY" >/dev/null 2>&1; then
  echo "cycle-schema summary mismatch"
  cat "$SCHEMA_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-promotion-check] missing cycle-summary list produces deterministic NO-GO contract"
MISSING_LIST_SUMMARY="$TMP_DIR/promotion_check_missing_list_summary.json"
MISSING_LIST_REPORTS="$TMP_DIR/missing_list_reports"
mkdir -p "$MISSING_LIST_REPORTS"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --cycle-summary-list "$TMP_DIR/does_not_exist.list" \
  --reports-dir "$MISSING_LIST_REPORTS" \
  --require-min-cycles 1 \
  --require-min-pass-cycles 1 \
  --require-max-fail-cycles 0 \
  --require-max-warn-cycles 0 \
  --require-min-pass-rate-pct 100 \
  --require-min-go-decision-rate-pct 100 \
  --require-cycle-schema-valid 1 \
  --fail-on-no-go 1 \
  --summary-json "$MISSING_LIST_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_promotion_check_missing_list.log 2>&1
missing_list_rc=$?
set -e

if [[ "$missing_list_rc" -eq 0 ]]; then
  echo "expected missing-list path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_promotion_check_missing_list.log
  exit 1
fi
if ! jq -e '
  .decision == "NO-GO"
  and .status == "fail"
  and .rc != 0
  and .inputs.cycle_summary_list_missing == true
  and .observed.cycle_summary_list_missing == true
  and .failure_reason_code == "cycle_summary_list_missing"
  and ((.violations | map(.code) | index("cycle_summary_list_missing")) != null)
' "$MISSING_LIST_SUMMARY" >/dev/null 2>&1; then
  echo "missing-list summary mismatch"
  cat "$MISSING_LIST_SUMMARY"
  exit 1
fi

echo "profile compare multi-vm stability promotion check integration ok"
