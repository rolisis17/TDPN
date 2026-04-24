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

SCRIPT_UNDER_TEST="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CHECK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/profile_default_gate_stability_promotion_check.sh}"
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
INVALID_SCHEMA_CYCLE="$TMP_DIR/cycle_invalid_schema.json"

cat >"$PASS_CYCLE_A" <<'EOF_PASS_CYCLE_A'
{
  "version": 1,
  "schema": { "id": "profile_default_gate_stability_cycle_summary" },
  "status": "pass",
  "rc": 0,
  "decision": "GO",
  "inputs": { "check": { "policy": { "require_modal_decision": "GO" } } },
  "check": { "summary_schema_valid": true, "has_usable_decision": true, "decision": "GO" },
  "outcome": { "should_promote": true }
}
EOF_PASS_CYCLE_A

cat >"$PASS_CYCLE_B" <<'EOF_PASS_CYCLE_B'
{
  "version": 1,
  "schema": { "id": "profile_default_gate_stability_cycle_summary" },
  "status": "pass",
  "rc": 0,
  "decision": "GO",
  "inputs": { "check": { "policy": { "require_modal_decision": "GO" } } },
  "check": { "summary_schema_valid": true, "has_usable_decision": true, "decision": "GO" },
  "outcome": { "should_promote": true }
}
EOF_PASS_CYCLE_B

cat >"$PASS_CYCLE_C" <<'EOF_PASS_CYCLE_C'
{
  "version": 1,
  "schema": { "id": "profile_default_gate_stability_cycle_summary" },
  "status": "pass",
  "rc": 0,
  "decision": "GO",
  "inputs": { "check": { "policy": { "require_modal_decision": "GO" } } },
  "check": { "summary_schema_valid": true, "has_usable_decision": true, "decision": "GO" },
  "outcome": { "should_promote": true }
}
EOF_PASS_CYCLE_C

cat >"$NO_GO_CYCLE" <<'EOF_NO_GO_CYCLE'
{
  "version": 1,
  "schema": { "id": "profile_default_gate_stability_cycle_summary" },
  "status": "fail",
  "rc": 1,
  "decision": "NO-GO",
  "inputs": { "check": { "policy": { "require_modal_decision": "GO" } } },
  "check": { "summary_schema_valid": true, "has_usable_decision": true, "decision": "NO-GO" },
  "outcome": { "should_promote": false }
}
EOF_NO_GO_CYCLE

cat >"$POLICY_MISMATCH_CYCLE" <<'EOF_POLICY_MISMATCH_CYCLE'
{
  "version": 1,
  "schema": { "id": "profile_default_gate_stability_cycle_summary" },
  "status": "pass",
  "rc": 0,
  "decision": "GO",
  "inputs": { "check": { "policy": { "require_modal_decision": "NO-GO" } } },
  "check": { "summary_schema_valid": true, "has_usable_decision": true, "decision": "GO" },
  "outcome": { "should_promote": true }
}
EOF_POLICY_MISMATCH_CYCLE

cat >"$INVALID_SCHEMA_CYCLE" <<'EOF_INVALID_SCHEMA_CYCLE'
{
  "version": 1,
  "schema": { "id": "unexpected_cycle_schema" },
  "status": "pass",
  "rc": 0,
  "decision": "GO",
  "inputs": { "check": { "policy": { "require_modal_decision": "GO" } } },
  "check": { "summary_schema_valid": true, "has_usable_decision": true, "decision": "GO" },
  "outcome": { "should_promote": true }
}
EOF_INVALID_SCHEMA_CYCLE

echo "[profile-default-gate-stability-promotion-check] strict happy path"
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
  --require-check-schema-valid 1 \
  --require-check-usable-decision 1 \
  --require-check-policy-modal-decision GO \
  --fail-on-no-go 1 \
  --summary-json "$STRICT_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_promotion_check_strict.log 2>&1
strict_rc=$?
set -e

if [[ "$strict_rc" -ne 0 ]]; then
  echo "expected strict happy path rc=0, got rc=$strict_rc"
  cat /tmp/integration_profile_default_gate_stability_promotion_check_strict.log
  exit 1
fi
if ! jq -e '
  .schema.id == "profile_default_gate_stability_promotion_check_summary"
  and .decision == "GO"
  and .status == "ok"
  and .rc == 0
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

echo "[profile-default-gate-stability-promotion-check] invalid cycle schema is fail-closed"
INVALID_SCHEMA_SUMMARY="$TMP_DIR/promotion_check_invalid_schema_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --cycle-summary-json "$PASS_CYCLE_A" \
  --cycle-summary-json "$INVALID_SCHEMA_CYCLE" \
  --require-min-cycles 2 \
  --require-min-pass-cycles 1 \
  --require-max-fail-cycles 10 \
  --require-max-warn-cycles 10 \
  --require-min-pass-rate-pct 0 \
  --require-min-go-decision-rate-pct 0 \
  --require-check-schema-valid 0 \
  --require-check-usable-decision 0 \
  --require-check-policy-modal-decision GO \
  --fail-on-no-go 1 \
  --summary-json "$INVALID_SCHEMA_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_promotion_check_invalid_schema.log 2>&1
invalid_schema_rc=$?
set -e

if [[ "$invalid_schema_rc" -eq 0 ]]; then
  echo "expected invalid schema path rc!=0"
  cat /tmp/integration_profile_default_gate_stability_promotion_check_invalid_schema.log
  exit 1
fi
if ! jq -e '
  .decision == "NO-GO"
  and .status == "fail"
  and .rc != 0
  and .enforcement.no_go_enforced == true
  and ((.violations | map(.code) | index("cycle_schema_invalid")) != null)
' "$INVALID_SCHEMA_SUMMARY" >/dev/null 2>&1; then
  echo "invalid schema summary mismatch"
  cat "$INVALID_SCHEMA_SUMMARY"
  exit 1
fi

echo "[profile-default-gate-stability-promotion-check] NO-GO soft path when fail-on-no-go=0"
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
  --require-check-schema-valid 1 \
  --require-check-usable-decision 1 \
  --require-check-policy-modal-decision GO \
  --fail-on-no-go 0 \
  --summary-json "$SOFT_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_promotion_check_soft.log 2>&1
soft_rc=$?
set -e

if [[ "$soft_rc" -ne 0 ]]; then
  echo "expected soft NO-GO path rc=0, got rc=$soft_rc"
  cat /tmp/integration_profile_default_gate_stability_promotion_check_soft.log
  exit 1
fi
if ! jq -e '
  .decision == "NO-GO"
  and .status == "fail"
  and .rc == 0
  and .enforcement.no_go_enforced == false
  and .outcome.action == "hold_promotion_warn_only"
  and ((.violations | map(.code) | index("max_fail_cycles_exceeded")) != null)
' "$SOFT_SUMMARY" >/dev/null 2>&1; then
  echo "soft NO-GO summary mismatch"
  cat "$SOFT_SUMMARY"
  exit 1
fi

echo "[profile-default-gate-stability-promotion-check] policy mismatch is enforced"
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
  --require-check-schema-valid 1 \
  --require-check-usable-decision 1 \
  --require-check-policy-modal-decision GO \
  --fail-on-no-go 1 \
  --summary-json "$MISMATCH_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_promotion_check_policy_mismatch.log 2>&1
mismatch_rc=$?
set -e

if [[ "$mismatch_rc" -eq 0 ]]; then
  echo "expected policy mismatch path rc!=0"
  cat /tmp/integration_profile_default_gate_stability_promotion_check_policy_mismatch.log
  exit 1
fi
if ! jq -e '
  .decision == "NO-GO"
  and .status == "fail"
  and .rc != 0
  and .enforcement.no_go_enforced == true
  and .outcome.action == "hold_promotion_blocked"
  and ((.violations | map(.code) | index("check_policy_modal_decision_mismatch")) != null)
' "$MISMATCH_SUMMARY" >/dev/null 2>&1; then
  echo "policy mismatch summary mismatch"
  cat "$MISMATCH_SUMMARY"
  exit 1
fi

echo "profile default gate stability promotion check integration ok"
