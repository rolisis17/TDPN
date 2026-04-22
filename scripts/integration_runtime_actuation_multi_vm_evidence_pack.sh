#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp grep cat; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${RUNTIME_ACTUATION_MULTI_VM_EVIDENCE_PACK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/runtime_actuation_multi_vm_evidence_pack.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

EASY_NODE_SCRIPT_UNDER_TEST="${EASY_NODE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/easy_node.sh}"
if [[ ! -x "$EASY_NODE_SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable easy_node script under test: $EASY_NODE_SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

HELP_OUT="$TMP_DIR/help.txt"

echo "[runtime-actuation-multi-vm-evidence-pack] easy_node help contract"
bash "$EASY_NODE_SCRIPT_UNDER_TEST" help >"$HELP_OUT"
if ! grep -F -- './scripts/easy_node.sh runtime-actuation-multi-vm-evidence-pack [runtime_actuation_multi_vm_evidence_pack args...]' "$HELP_OUT" >/dev/null 2>&1; then
  echo "easy_node help missing runtime-actuation-multi-vm-evidence-pack command contract"
  cat "$HELP_OUT"
  exit 1
fi

PASS_REPORTS="$TMP_DIR/pass_reports"
PASS_RUNTIME_SUMMARY="$PASS_REPORTS/runtime_actuation_promotion_cycle_latest_summary.json"
PASS_MULTI_VM_SUMMARY="$PASS_REPORTS/profile_compare_multi_vm_stability_promotion_cycle_summary.json"
PASS_SUMMARY="$TMP_DIR/pass_evidence_pack_summary.json"
PASS_REPORT="$TMP_DIR/pass_evidence_pack_report.md"

mkdir -p "$PASS_REPORTS"

cat >"$PASS_RUNTIME_SUMMARY" <<'EOF_PASS_RUNTIME'
{
  "version": 1,
  "schema": {
    "id": "runtime_actuation_promotion_cycle_summary"
  },
  "status": "pass",
  "rc": 0,
  "decision": "GO",
  "stages": {
    "promotion_check": {
      "summary_exists": true,
      "summary_valid_json": true,
      "summary_fresh": true,
      "has_usable_decision": true
    }
  },
  "promotion_check": {
    "decision": "GO",
    "status": "pass",
    "rc": 0,
    "next_operator_action": "No action required"
  }
}
EOF_PASS_RUNTIME

cat >"$PASS_MULTI_VM_SUMMARY" <<'EOF_PASS_MULTI_VM'
{
  "version": 1,
  "schema": {
    "id": "profile_compare_multi_vm_stability_promotion_cycle_summary"
  },
  "status": "pass",
  "rc": 0,
  "decision": "GO",
  "promotion": {
    "summary_exists": true,
    "summary_valid_json": true,
    "summary_fresh": true,
    "decision": "GO",
    "status": "pass",
    "rc": 0,
    "next_operator_action": "Promotion may proceed."
  },
  "next_operator_action": "Promotion may proceed."
}
EOF_PASS_MULTI_VM

echo "[runtime-actuation-multi-vm-evidence-pack] pass path via easy_node wrapper"
set +e
RUNTIME_ACTUATION_MULTI_VM_EVIDENCE_PACK_SCRIPT="$SCRIPT_UNDER_TEST" \
bash "$EASY_NODE_SCRIPT_UNDER_TEST" runtime-actuation-multi-vm-evidence-pack \
  --reports-dir "$PASS_REPORTS" \
  --summary-json "$PASS_SUMMARY" \
  --report-md "$PASS_REPORT" \
  --print-summary-json 0 \
  --print-report 0 >/tmp/integration_runtime_actuation_multi_vm_evidence_pack_pass.log 2>&1
pass_rc=$?
set -e

if [[ "$pass_rc" -ne 0 ]]; then
  echo "expected pass path rc=0, got rc=$pass_rc"
  cat /tmp/integration_runtime_actuation_multi_vm_evidence_pack_pass.log
  exit 1
fi
if [[ ! -f "$PASS_SUMMARY" || ! -f "$PASS_REPORT" ]]; then
  echo "pass path missing output artifacts"
  ls -la "$TMP_DIR"
  exit 1
fi
if ! jq -e '
  .schema.id == "runtime_actuation_multi_vm_evidence_pack_summary"
  and .status == "pass"
  and .rc == 0
  and .decision == "GO"
  and .fail_closed == false
  and .outcome.should_promote == true
  and .outcome.action == "promote_allowed"
  and .gates.runtime_actuation_promotion_cycle.usable == true
  and .gates.multi_vm_stability_promotion_cycle.usable == true
  and .normalized.runtime_actuation_decision == "GO"
  and .normalized.multi_vm_decision == "GO"
  and .normalized.combined_decision == "GO"
' "$PASS_SUMMARY" >/dev/null 2>&1; then
  echo "pass path summary mismatch"
  cat "$PASS_SUMMARY"
  exit 1
fi
if ! grep -F -- '# Runtime Actuation + Multi-VM Promotion Evidence Pack' "$PASS_REPORT" >/dev/null 2>&1; then
  echo "pass path report markdown header missing"
  cat "$PASS_REPORT"
  exit 1
fi

NOGO_REPORTS="$TMP_DIR/nogo_reports"
NOGO_RUNTIME_SUMMARY="$NOGO_REPORTS/runtime_actuation_promotion_cycle_latest_summary.json"
NOGO_MULTI_VM_SUMMARY="$NOGO_REPORTS/profile_compare_multi_vm_stability_promotion_cycle_summary.json"
NOGO_SOFT_SUMMARY="$TMP_DIR/nogo_soft_evidence_pack_summary.json"
NOGO_HARD_SUMMARY="$TMP_DIR/nogo_hard_evidence_pack_summary.json"

mkdir -p "$NOGO_REPORTS"

cat >"$NOGO_RUNTIME_SUMMARY" <<'EOF_NOGO_RUNTIME'
{
  "version": 1,
  "schema": {
    "id": "runtime_actuation_promotion_cycle_summary"
  },
  "status": "pass",
  "rc": 0,
  "decision": "NO-GO",
  "stages": {
    "promotion_check": {
      "summary_exists": true,
      "summary_valid_json": true,
      "summary_fresh": true,
      "has_usable_decision": true
    }
  },
  "promotion_check": {
    "decision": "NO-GO",
    "status": "pass",
    "rc": 0,
    "next_operator_action": "Hold promotion."
  }
}
EOF_NOGO_RUNTIME

cat >"$NOGO_MULTI_VM_SUMMARY" <<'EOF_NOGO_MULTI_VM'
{
  "version": 1,
  "schema": {
    "id": "profile_compare_multi_vm_stability_promotion_cycle_summary"
  },
  "status": "pass",
  "rc": 0,
  "decision": "NO-GO",
  "promotion": {
    "summary_exists": true,
    "summary_valid_json": true,
    "summary_fresh": true,
    "decision": "NO-GO",
    "status": "pass",
    "rc": 0,
    "next_operator_action": "Hold promotion."
  },
  "next_operator_action": "Hold promotion."
}
EOF_NOGO_MULTI_VM

echo "[runtime-actuation-multi-vm-evidence-pack] usable NO-GO soft path"
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$NOGO_REPORTS" \
  --summary-json "$NOGO_SOFT_SUMMARY" \
  --report-md "$TMP_DIR/nogo_soft_report.md" \
  --fail-on-no-go 0 \
  --print-summary-json 0 \
  --print-report 0

if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .decision == "NO-GO"
  and .fail_closed == false
  and .outcome.action == "hold_promotion_warn_only"
' "$NOGO_SOFT_SUMMARY" >/dev/null 2>&1; then
  echo "usable NO-GO soft path summary mismatch"
  cat "$NOGO_SOFT_SUMMARY"
  exit 1
fi

echo "[runtime-actuation-multi-vm-evidence-pack] usable NO-GO hard path"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$NOGO_REPORTS" \
  --summary-json "$NOGO_HARD_SUMMARY" \
  --report-md "$TMP_DIR/nogo_hard_report.md" \
  --fail-on-no-go 1 \
  --print-summary-json 0 \
  --print-report 0 >/tmp/integration_runtime_actuation_multi_vm_evidence_pack_nogo_hard.log 2>&1
nogo_hard_rc=$?
set -e

if [[ "$nogo_hard_rc" -eq 0 ]]; then
  echo "expected usable NO-GO hard path rc!=0"
  cat /tmp/integration_runtime_actuation_multi_vm_evidence_pack_nogo_hard.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc != 0
  and .decision == "NO-GO"
  and .fail_closed == true
  and ((.reasons | index("usable_no_go_detected")) != null)
  and .outcome.action == "hold_evidence_pack_blocked"
' "$NOGO_HARD_SUMMARY" >/dev/null 2>&1; then
  echo "usable NO-GO hard path summary mismatch"
  cat "$NOGO_HARD_SUMMARY"
  exit 1
fi

FAIL_REPORTS="$TMP_DIR/fail_reports"
FAIL_RUNTIME_SUMMARY="$FAIL_REPORTS/runtime_actuation_promotion_cycle_latest_summary.json"
FAIL_MULTI_VM_SUMMARY="$FAIL_REPORTS/profile_compare_multi_vm_stability_promotion_cycle_summary.json"
FAIL_SUMMARY="$TMP_DIR/fail_evidence_pack_summary.json"
FAIL_REPORT="$TMP_DIR/fail_evidence_pack_report.md"

mkdir -p "$FAIL_REPORTS"

cat >"$FAIL_RUNTIME_SUMMARY" <<'EOF_FAIL_RUNTIME'
{
  "version": 1,
  "schema": {
    "id": "runtime_actuation_promotion_cycle_summary"
  },
  "status": "pass",
  "rc": 0,
  "decision": "GO",
  "stages": {
    "promotion_check": {
      "summary_exists": true,
      "summary_valid_json": true,
      "has_usable_decision": true
    }
  },
  "promotion_check": {
    "decision": "GO",
    "status": "pass",
    "rc": 0
  }
}
EOF_FAIL_RUNTIME

cat >"$FAIL_MULTI_VM_SUMMARY" <<'EOF_FAIL_MULTI_VM'
{
  "version": 1,
  "schema": {
    "id": "profile_compare_multi_vm_stability_promotion_cycle_summary"
  },
  "status": "pass",
  "rc": 0,
  "decision": "GO",
  "promotion": {
    "summary_exists": true,
    "summary_valid_json": true,
    "summary_fresh": true,
    "decision": "GO",
    "status": "pass",
    "rc": 0
  },
  "next_operator_action": "Promotion may proceed."
}
EOF_FAIL_MULTI_VM

echo "[runtime-actuation-multi-vm-evidence-pack] fail-closed path (unknown freshness)"
set +e
RUNTIME_ACTUATION_MULTI_VM_EVIDENCE_PACK_SCRIPT="$SCRIPT_UNDER_TEST" \
bash "$EASY_NODE_SCRIPT_UNDER_TEST" runtime-actuation-multi-vm-evidence-pack \
  --reports-dir "$FAIL_REPORTS" \
  --summary-json "$FAIL_SUMMARY" \
  --report-md "$FAIL_REPORT" \
  --print-summary-json 0 \
  --print-report 0 >/tmp/integration_runtime_actuation_multi_vm_evidence_pack_fail_closed.log 2>&1
fail_rc=$?
set -e

if [[ "$fail_rc" -eq 0 ]]; then
  echo "expected fail-closed path rc!=0"
  cat /tmp/integration_runtime_actuation_multi_vm_evidence_pack_fail_closed.log
  exit 1
fi
if [[ ! -f "$FAIL_SUMMARY" || ! -f "$FAIL_REPORT" ]]; then
  echo "fail-closed path missing output artifacts"
  ls -la "$TMP_DIR"
  exit 1
fi
if ! jq -e '
  .schema.id == "runtime_actuation_multi_vm_evidence_pack_summary"
  and .status == "fail"
  and .rc != 0
  and .decision == "NO-GO"
  and .fail_closed == true
  and .outcome.should_promote == false
  and .outcome.action == "hold_evidence_pack_blocked"
  and .gates.runtime_actuation_promotion_cycle.usable == false
  and .gates.multi_vm_stability_promotion_cycle.usable == true
  and ((.reasons | index("runtime_actuation_promotion_cycle:freshness_unknown")) != null)
' "$FAIL_SUMMARY" >/dev/null 2>&1; then
  echo "fail-closed path summary mismatch"
  cat "$FAIL_SUMMARY"
  exit 1
fi
if ! grep -F -- 'Fail closed: true' "$FAIL_REPORT" >/dev/null 2>&1; then
  echo "fail-closed report missing fail-closed marker"
  cat "$FAIL_REPORT"
  exit 1
fi

echo "runtime actuation multi-vm evidence pack integration ok"
