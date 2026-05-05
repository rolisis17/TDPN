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
  and .needs_attention == false
  and .no_go_reason_category == "none"
  and .next_command == null
  and .next_command_reason == null
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
  and .needs_attention == true
  and .no_go_reason_category == "usable_no_go"
  and (.next_command != null and (.next_command | contains("roadmap-live-evidence-cycle-batch-run")))
  and (.next_command_reason != null and (.next_command_reason | test("NO-GO"; "i")))
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
  and .needs_attention == true
  and .no_go_reason_category == "usable_no_go"
  and (.next_command != null and (.next_command | contains("roadmap-live-evidence-cycle-batch-run")))
  and (.next_command_reason != null and (.next_command_reason | test("resolve blockers"; "i")))
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
  and .needs_attention == true
  and .no_go_reason_category == "stale_or_unknown_freshness"
  and (.next_command != null and (.next_command | contains("runtime-actuation-promotion-cycle")))
  and (.next_command_reason != null and (.next_command_reason | test("stale|freshness"; "i")))
  and ((.next_command_reason | test("REPLACE_WITH_INVITE_SUBJECT|<SET-REAL-INVITE-KEY>|\\[redacted\\]|\\[REDACTED\\]")) | not)
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

MISSING_REPORTS="$TMP_DIR/missing_reports"
MISSING_RUNTIME_SUMMARY="$MISSING_REPORTS/runtime_actuation_promotion_cycle_latest_summary.json"
MISSING_SUMMARY="$TMP_DIR/missing_evidence_pack_summary.json"

mkdir -p "$MISSING_REPORTS"

cat >"$MISSING_RUNTIME_SUMMARY" <<'EOF_MISSING_RUNTIME'
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
      "summary_fresh": true
    }
  }
}
EOF_MISSING_RUNTIME

echo "[runtime-actuation-multi-vm-evidence-pack] fail-closed path (missing multi-vm summary)"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$MISSING_REPORTS" \
  --summary-json "$MISSING_SUMMARY" \
  --report-md "$TMP_DIR/missing_report.md" \
  --print-summary-json 0 \
  --print-report 0 >/tmp/integration_runtime_actuation_multi_vm_evidence_pack_missing.log 2>&1
missing_rc=$?
set -e

if [[ "$missing_rc" -eq 0 ]]; then
  echo "expected missing summary path rc!=0"
  cat /tmp/integration_runtime_actuation_multi_vm_evidence_pack_missing.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .fail_closed == true
  and .no_go_reason_category == "missing_or_invalid_source_summary"
  and ((.no_go_reason_codes | index("multi_vm_stability_promotion_cycle:summary_missing")) != null)
  and (.next_command != null and (.next_command | contains("profile-compare-multi-vm-stability-promotion-cycle")))
  and (.next_command_reason != null and (.next_command_reason | test("source summaries are missing or invalid"; "i")))
' "$MISSING_SUMMARY" >/dev/null 2>&1; then
  echo "missing summary fail-closed path summary mismatch"
  cat "$MISSING_SUMMARY"
  exit 1
fi

SANITIZE_REPORTS="$TMP_DIR/sanitize_reports"
SANITIZE_RUNTIME_SUMMARY="$SANITIZE_REPORTS/runtime_actuation_promotion_cycle_latest_summary.json"
SANITIZE_MULTI_VM_SUMMARY="$SANITIZE_REPORTS/profile_compare_multi_vm_stability_promotion_cycle_summary.json"
SANITIZE_SUMMARY="$TMP_DIR/sanitize_evidence_pack_summary.json"

mkdir -p "$SANITIZE_REPORTS"

cat >"$SANITIZE_RUNTIME_SUMMARY" <<'EOF_SANITIZE_RUNTIME'
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
      "summary_fresh": true
    }
  },
  "promotion_check": {
    "decision": "NO-GO",
    "status": "pass",
    "rc": 0,
    "next_operator_action": "Use REPLACE_WITH_INVITE_SUBJECT and [redacted] to rerun."
  },
  "failure_reason": "CAMPAIGN_SUBJECT unresolved."
}
EOF_SANITIZE_RUNTIME

cat >"$SANITIZE_MULTI_VM_SUMMARY" <<'EOF_SANITIZE_MULTI_VM'
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
  }
}
EOF_SANITIZE_MULTI_VM

echo "[runtime-actuation-multi-vm-evidence-pack] sanitized no-go guidance path"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$SANITIZE_REPORTS" \
  --summary-json "$SANITIZE_SUMMARY" \
  --report-md "$TMP_DIR/sanitize_report.md" \
  --fail-on-no-go 1 \
  --print-summary-json 0 \
  --print-report 0 >/tmp/integration_runtime_actuation_multi_vm_evidence_pack_sanitize.log 2>&1
sanitize_rc=$?
set -e

if [[ "$sanitize_rc" -eq 0 ]]; then
  echo "expected sanitized no-go path rc!=0"
  cat /tmp/integration_runtime_actuation_multi_vm_evidence_pack_sanitize.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .fail_closed == true
  and .no_go_reason_category == "usable_no_go"
  and (.next_command != null and (.next_command | contains("runtime-actuation-promotion-cycle")))
  and (.next_command_reason != null and (.next_command_reason | test("resolve blockers|NO-GO"; "i")))
  and ((.next_command_reason | test("REPLACE_WITH_INVITE_SUBJECT|<SET-REAL-INVITE-KEY>|\\[redacted\\]|\\[REDACTED\\]|CAMPAIGN_SUBJECT|INVITE_KEY")) | not)
  and ((.next_operator_action | test("REPLACE_WITH_INVITE_SUBJECT|\\[redacted\\]|CAMPAIGN_SUBJECT|INVITE_KEY")) | not)
' "$SANITIZE_SUMMARY" >/dev/null 2>&1; then
  echo "sanitized no-go guidance summary mismatch"
  cat "$SANITIZE_SUMMARY"
  exit 1
fi

echo "runtime actuation multi-vm evidence pack integration ok"
