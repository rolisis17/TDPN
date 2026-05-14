#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp grep cat mkdir sed; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${GPM_GAP_SCAN_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/gpm_gap_scan.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

assert_file_contains() {
  local file_path="$1"
  local expected="$2"
  local message="$3"
  if ! grep -F -- "$expected" "$file_path" >/dev/null 2>&1; then
    echo "$message"
    cat "$file_path"
    exit 1
  fi
}

assert_file_matches_regex() {
  local file_path="$1"
  local regex="$2"
  local message="$3"
  if ! grep -E -- "$regex" "$file_path" >/dev/null 2>&1; then
    echo "$message"
    cat "$file_path"
    exit 1
  fi
}

echo "[gpm-gap-scan] help contract"
HELP_OUTPUT_FILE="$TMP_DIR/help.txt"
bash "$SCRIPT_UNDER_TEST" --help >"$HELP_OUTPUT_FILE"
for token in \
  "--status-doc PATH" \
  "--roadmap-summary-json PATH" \
  "--summary-json PATH" \
  "--reports-dir DIR" \
  "--print-summary-json [0|1]"; do
  assert_file_contains "$HELP_OUTPUT_FILE" "$token" "help output missing token: $token"
done

echo "[gpm-gap-scan] primary parse + markdown/json outputs"
PRIMARY_STATUS_DOC="$TMP_DIR/primary_status.md"
PRIMARY_REPORTS_DIR="$TMP_DIR/primary_reports"
PRIMARY_SUMMARY_JSON="$TMP_DIR/primary_summary.json"
PRIMARY_STDOUT="$TMP_DIR/primary_stdout.md"

cat >"$PRIMARY_STATUS_DOC" <<'EOF_PRIMARY_STATUS'
# GPM Status Fixture

## Completed
- Done item for context.

## In-Progress
- In progress one.
- In progress two
  with continuation context.

## Missing / Next
Next wave, in order:
- Missing one.
- Missing two.
EOF_PRIMARY_STATUS

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$PRIMARY_STATUS_DOC" \
  --reports-dir "$PRIMARY_REPORTS_DIR" \
  --summary-json "$PRIMARY_SUMMARY_JSON" \
  --print-summary-json 0 >"$PRIMARY_STDOUT"

assert_file_contains "$PRIMARY_STDOUT" "# GPM Roadmap Gap Scan" "markdown output missing title"
assert_file_contains "$PRIMARY_STDOUT" "## In-Progress (2)" "markdown output missing in-progress count heading"
assert_file_contains "$PRIMARY_STDOUT" "1. In progress one." "markdown output missing first in-progress item"
assert_file_contains "$PRIMARY_STDOUT" "2. In progress two with continuation context." "markdown output missing wrapped in-progress item normalization"
assert_file_contains "$PRIMARY_STDOUT" "## Missing / Next (2)" "markdown output missing missing/next count heading"
assert_file_contains "$PRIMARY_STDOUT" "1. Missing one." "markdown output missing first missing/next item"
assert_file_contains "$PRIMARY_STDOUT" "2. Missing two." "markdown output missing second missing/next item"

assert_file_contains "$PRIMARY_SUMMARY_JSON" '"schema": {' "summary JSON missing schema object"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"id": "gpm_gap_scan_summary"' "summary JSON missing schema id"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"counts": {' "summary JSON missing counts object"
assert_file_matches_regex "$PRIMARY_SUMMARY_JSON" '"in_progress"[[:space:]]*:[[:space:]]*2' "summary JSON in_progress count mismatch"
assert_file_matches_regex "$PRIMARY_SUMMARY_JSON" '"missing_next"[[:space:]]*:[[:space:]]*2' "summary JSON missing_next count mismatch"
assert_file_matches_regex "$PRIMARY_SUMMARY_JSON" '"total"[[:space:]]*:[[:space:]]*4' "summary JSON total count mismatch"
assert_file_matches_regex "$PRIMARY_SUMMARY_JSON" '"top_local_only"[[:space:]]*:[[:space:]]*4' "summary JSON top_local_only count mismatch"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"items": [' "summary JSON missing items key"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"id": "in_progress_01"' "summary JSON missing in_progress item id"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"id": "missing_next_02"' "summary JSON missing missing_next item id"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"section": "in_progress"' "summary JSON missing in_progress section key"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"section": "missing_next"' "summary JSON missing missing_next section key"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"text": "In progress two with continuation context."' "summary JSON missing normalized wrapped text"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"severity": "p2"' "summary JSON missing expected in-progress severity classification"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"severity": "p1"' "summary JSON missing expected missing/next severity classification"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"recommended_action": "' "summary JSON missing recommended_action field"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"closure_mode": "local_only"' "summary JSON missing local_only closure_mode"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"blocked_by": []' "summary JSON missing empty blocked_by array"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"requires_real_hosts": false' "summary JSON missing requires_real_hosts false"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"suggested_tests": []' "summary JSON missing empty suggested_tests array"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"suggested_files": ["docs/gpm-productization-status.md"]' "summary JSON missing default suggested_files array"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"top_actionable_item_ids": [' "summary JSON missing top_actionable_item_ids field"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"top_local_only_item_ids": [' "summary JSON missing top_local_only_item_ids field"
if ! grep -A16 '"top_local_only_item_ids": \[' "$PRIMARY_SUMMARY_JSON" | grep -F '"missing_next_01"' >/dev/null 2>&1; then
  echo "primary local-only top tasks should include first missing/next item"
  cat "$PRIMARY_SUMMARY_JSON"
  exit 1
fi
if ! grep -A16 '"top_local_only_item_ids": \[' "$PRIMARY_SUMMARY_JSON" | grep -F '"in_progress_02"' >/dev/null 2>&1; then
  echo "primary local-only top tasks should include second in-progress item"
  cat "$PRIMARY_SUMMARY_JSON"
  exit 1
fi

if command -v cygpath >/dev/null 2>&1; then
  echo "[gpm-gap-scan] Windows absolute status-doc paths are preserved"
  WINDOWS_ABS_STATUS_DOC="$(cygpath -m "$PRIMARY_STATUS_DOC")"
  WINDOWS_ABS_SUMMARY_JSON="$TMP_DIR/windows_abs_summary.json"
  bash "$SCRIPT_UNDER_TEST" \
    --status-doc "$WINDOWS_ABS_STATUS_DOC" \
    --summary-json "$WINDOWS_ABS_SUMMARY_JSON" \
    --print-summary-json 0 >/dev/null

  assert_file_contains "$WINDOWS_ABS_SUMMARY_JSON" "\"status_doc\": \"$WINDOWS_ABS_STATUS_DOC\"" "Windows absolute status-doc path was incorrectly re-rooted"
else
  echo "[gpm-gap-scan] Windows absolute path check skipped; cygpath unavailable"
fi

echo "[gpm-gap-scan] optional roadmap summary contributes machine-readable blockers"
ROADMAP_STATUS_DOC="$TMP_DIR/roadmap_status.md"
ROADMAP_SUMMARY_INPUT="$TMP_DIR/roadmap_input_summary.json"
ROADMAP_SUMMARY_JSON="$TMP_DIR/roadmap_scan_summary.json"
ROADMAP_STDOUT="$TMP_DIR/roadmap_stdout.md"

cat >"$ROADMAP_STATUS_DOC" <<'EOF_ROADMAP_STATUS'
# Roadmap-Aware Fixture

## In-Progress
- Roadmap-aware in-progress item.

## Missing / Next
- Roadmap-aware missing item.
EOF_ROADMAP_STATUS

cat >"$ROADMAP_SUMMARY_INPUT" <<'EOF_ROADMAP_SUMMARY'
{
  "vpn_track": {
    "profile_default_gate": {
      "unresolved_placeholders": true,
      "unresolved_placeholder_keys": ["invite_key"]
    },
    "profile_compare_multi_vm_stability": {
      "vm_command_source_ready": false,
      "next_command_actionable": false
    },
    "runtime_actuation_promotion": {
      "status": "fail",
      "decision": "NO-GO"
    },
    "profile_default_gate_evidence_pack": {
      "status": "stale",
      "needs_attention": true
    },
    "runtime_actuation_promotion_evidence_pack": {
      "status": "fail",
      "needs_attention": true
    },
    "profile_compare_multi_vm_stability_promotion_evidence_pack": {
      "status": "missing",
      "needs_attention": true
    }
  }
}
EOF_ROADMAP_SUMMARY

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$ROADMAP_STATUS_DOC" \
  --roadmap-summary-json "$ROADMAP_SUMMARY_INPUT" \
  --summary-json "$ROADMAP_SUMMARY_JSON" \
  --print-summary-json 0 >"$ROADMAP_STDOUT"

assert_file_contains "$ROADMAP_SUMMARY_JSON" '"roadmap_summary_json": "' "roadmap-aware summary missing roadmap summary input path"
assert_file_matches_regex "$ROADMAP_SUMMARY_JSON" '"missing_next"[[:space:]]*:[[:space:]]*8' "roadmap-aware missing_next count mismatch"
assert_file_matches_regex "$ROADMAP_SUMMARY_JSON" '"total"[[:space:]]*:[[:space:]]*9' "roadmap-aware total count mismatch"
assert_file_matches_regex "$ROADMAP_SUMMARY_JSON" '"top_local_only"[[:space:]]*:[[:space:]]*2' "roadmap-aware top_local_only count mismatch"
assert_file_contains "$ROADMAP_SUMMARY_JSON" 'Roadmap Access Recovery handoff state is missing; provide a roadmap summary with access_recovery_track before pilot handoff.' "roadmap-aware summary missing access recovery track blocker"
assert_file_contains "$ROADMAP_SUMMARY_JSON" 'Roadmap profile-default gate next action has unresolved placeholders (invite_key)' "roadmap-aware summary missing profile placeholder blocker"
assert_file_contains "$ROADMAP_SUMMARY_JSON" 'Roadmap multi-VM stability command source is not actionable' "roadmap-aware summary missing multi-vm blocker"
assert_file_contains "$ROADMAP_SUMMARY_JSON" 'Roadmap runtime-actuation promotion is not green' "roadmap-aware summary missing runtime promotion blocker"
assert_file_contains "$ROADMAP_SUMMARY_JSON" 'Roadmap evidence pack profile_default_gate_evidence_pack needs attention' "roadmap-aware summary missing profile evidence-pack blocker"
assert_file_contains "$ROADMAP_SUMMARY_JSON" '"closure_mode": "real_host_required"' "roadmap-aware summary missing real_host_required closure mode"
assert_file_contains "$ROADMAP_SUMMARY_JSON" '"closure_mode": "network_required"' "roadmap-aware summary missing network_required closure mode"
assert_file_contains "$ROADMAP_SUMMARY_JSON" '"blocked_by": ["unresolved_placeholders", "real_hosts", "network"]' "roadmap-aware summary missing placeholder/real-host/network blocker metadata"
assert_file_contains "$ROADMAP_SUMMARY_JSON" '"blocked_by": ["vm_command_source"]' "roadmap-aware summary missing vm command blocker metadata"
assert_file_contains "$ROADMAP_SUMMARY_JSON" '"blocked_by": ["promotion_thresholds", "evidence_pack_artifacts"]' "roadmap-aware summary missing promotion/evidence blocker metadata"
assert_file_contains "$ROADMAP_SUMMARY_JSON" '"requires_real_hosts": true' "roadmap-aware summary missing requires_real_hosts true"
assert_file_contains "$ROADMAP_SUMMARY_JSON" '"suggested_tests": ["scripts/integration_client_vpn_path_profile_wiring.sh"]' "roadmap-aware summary missing profile suggested test"
assert_file_contains "$ROADMAP_SUMMARY_JSON" '"suggested_tests": ["scripts/integration_3machine_prod_wg_validate.sh"]' "roadmap-aware summary missing multi-vm suggested test"
assert_file_contains "$ROADMAP_STDOUT" "## Missing / Next (8)" "roadmap-aware markdown missing expanded missing/next count"
if grep -A16 '"top_local_only_item_ids": \[' "$ROADMAP_SUMMARY_JSON" | grep -F '"missing_next_03"' >/dev/null 2>&1; then
  echo "roadmap real-host blocker should not appear in top_local_only_item_ids"
  cat "$ROADMAP_SUMMARY_JSON"
  exit 1
fi

echo "[gpm-gap-scan] access recovery roadmap handoff state is surfaced"
ACCESS_RECOVERY_STATUS_DOC="$TMP_DIR/access_recovery_status.md"
ACCESS_RECOVERY_ROADMAP_INPUT="$TMP_DIR/access_recovery_roadmap.json"
ACCESS_RECOVERY_SUMMARY_JSON="$TMP_DIR/access_recovery_summary.json"
ACCESS_RECOVERY_STDOUT="$TMP_DIR/access_recovery_stdout.md"

cat >"$ACCESS_RECOVERY_STATUS_DOC" <<'EOF_ACCESS_RECOVERY_STATUS'
# Access Recovery Fixture

## In-Progress
- Access Recovery local rehearsal is wired.

## Missing / Next
- Keep the pilot handoff state visible.
EOF_ACCESS_RECOVERY_STATUS

cat >"$ACCESS_RECOVERY_ROADMAP_INPUT" <<'EOF_ACCESS_RECOVERY_ROADMAP'
{
  "access_recovery_pilot_handoff_ready": false,
  "access_recovery_track": {
    "status": "installed-host-evidence-required",
    "pilot_handoff_ready": false,
    "needs_attention": true,
    "trusted_verifier_receipt_valid": false,
    "trusted_pilot_receipt_ready": false,
    "verifier_pilot_handoff_ready": false,
    "preferred_operator_next_action": {
      "id": "trusted_verifier_receipt",
      "command": "./scripts/easy_node.sh access-recovery-real-helper-evidence-run --trust-store TRUST_STORE",
      "reason": "Write the trusted verifier receipt before pilot handoff",
      "placeholder_unresolved": true,
      "placeholder_keys": ["TRUST_STORE"],
      "safe_to_execute_as_is": false
    },
    "recommended_next_action": {
      "id": "fallback_recommended",
      "command": "should-not-be-used"
    }
  }
}
EOF_ACCESS_RECOVERY_ROADMAP

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$ACCESS_RECOVERY_STATUS_DOC" \
  --roadmap-summary-json "$ACCESS_RECOVERY_ROADMAP_INPUT" \
  --summary-json "$ACCESS_RECOVERY_SUMMARY_JSON" \
  --print-summary-json 0 >"$ACCESS_RECOVERY_STDOUT"

assert_file_matches_regex "$ACCESS_RECOVERY_SUMMARY_JSON" '"missing_next"[[:space:]]*:[[:space:]]*6' "access recovery roadmap should add handoff blocker plus fail-closed vpn blockers"
assert_file_matches_regex "$ACCESS_RECOVERY_SUMMARY_JSON" '"total"[[:space:]]*:[[:space:]]*7' "access recovery roadmap total count mismatch"
assert_file_contains "$ACCESS_RECOVERY_SUMMARY_JSON" '"roadmap_status": {' "access recovery summary missing roadmap_status object"
assert_file_contains "$ACCESS_RECOVERY_SUMMARY_JSON" '"access_recovery": {' "access recovery summary missing access_recovery status object"
assert_file_contains "$ACCESS_RECOVERY_SUMMARY_JSON" '"status": "installed-host-evidence-required"' "access recovery status not extracted"
assert_file_contains "$ACCESS_RECOVERY_SUMMARY_JSON" '"access_recovery_pilot_handoff_ready": false' "access recovery root handoff readiness not extracted"
assert_file_contains "$ACCESS_RECOVERY_SUMMARY_JSON" '"trusted_verifier_receipt_valid": false' "access recovery trusted verifier receipt validity not extracted"
assert_file_contains "$ACCESS_RECOVERY_SUMMARY_JSON" '"trusted_pilot_receipt_ready": false' "access recovery trusted pilot receipt readiness not extracted"
assert_file_contains "$ACCESS_RECOVERY_SUMMARY_JSON" '"verifier_pilot_handoff_ready": false' "access recovery verifier handoff readiness not extracted"
assert_file_contains "$ACCESS_RECOVERY_SUMMARY_JSON" '"source": "preferred_operator_next_action"' "access recovery preferred operator action not selected"
assert_file_contains "$ACCESS_RECOVERY_SUMMARY_JSON" '"command": "./scripts/easy_node.sh access-recovery-real-helper-evidence-run --trust-store TRUST_STORE"' "access recovery preferred command not extracted"
assert_file_contains "$ACCESS_RECOVERY_SUMMARY_JSON" '"placeholder_keys": ["TRUST_STORE"]' "access recovery placeholder keys not extracted"
assert_file_contains "$ACCESS_RECOVERY_SUMMARY_JSON" 'Roadmap Access Recovery handoff state is not ready (status=installed-host-evidence-required, access_recovery_pilot_handoff_ready=false' "access recovery handoff blocker text missing"
assert_file_contains "$ACCESS_RECOVERY_SUMMARY_JSON" 'Operator next action (preferred_operator_next_action/trusted_verifier_receipt): ./scripts/easy_node.sh access-recovery-real-helper-evidence-run --trust-store TRUST_STORE' "access recovery operator next action missing from blocker text"
assert_file_contains "$ACCESS_RECOVERY_SUMMARY_JSON" '"recommended_action": "Complete Access Recovery real-helper evidence and trusted verifier receipt, then refresh roadmap handoff state."' "access recovery recommended action classification missing"
assert_file_contains "$ACCESS_RECOVERY_SUMMARY_JSON" '"blocked_by": ["unresolved_placeholders", "access_recovery_handoff", "real_helper_evidence", "trusted_verifier_receipt"]' "access recovery blocker metadata missing"
assert_file_contains "$ACCESS_RECOVERY_SUMMARY_JSON" '"suggested_tests": ["scripts/access_recovery_real_helper_evidence_run.sh", "scripts/access_bridge_pilot_evidence_bundle_verify.sh"]' "access recovery suggested tests missing"
assert_file_contains "$ACCESS_RECOVERY_SUMMARY_JSON" '"suggested_files": ["docs/gpm-productization-status.md", "docs/global-privacy-mesh-track.md", "docs/product-roadmap.md", "docs/access-recovery-toolkit-track.md", "docs/access-recovery-operator-runbook.md", "scripts/access_recovery_real_helper_evidence_run.sh", "scripts/access_bridge_pilot_evidence_bundle_verify.sh", "scripts/roadmap_progress_report.sh"]' "access recovery suggested files missing"
assert_file_contains "$ACCESS_RECOVERY_STDOUT" "## Missing / Next (6)" "access recovery markdown missing expanded missing/next count"

echo "[gpm-gap-scan] access recovery operator command is redacted in artifacts"
ACCESS_RECOVERY_REDACTION_INPUT="$TMP_DIR/access_recovery_redaction_roadmap.json"
ACCESS_RECOVERY_REDACTION_SUMMARY_JSON="$TMP_DIR/access_recovery_redaction_summary.json"
ACCESS_RECOVERY_REDACTION_STDOUT="$TMP_DIR/access_recovery_redaction_stdout.md"

cat >"$ACCESS_RECOVERY_REDACTION_INPUT" <<'EOF_ACCESS_RECOVERY_REDACTION'
{
  "access_recovery_pilot_handoff_ready": false,
  "access_recovery_track": {
    "status": "installed-host-evidence-required",
    "pilot_handoff_ready": false,
    "needs_attention": true,
    "trusted_verifier_receipt_valid": false,
    "trusted_pilot_receipt_ready": false,
    "verifier_pilot_handoff_ready": false,
    "preferred_operator_next_action": {
      "id": "sensitive_command_preview",
      "command": "./scripts/easy_node.sh access-recovery-real-helper-evidence-run --subject inv-secret-leak --admin-token super-admin-token --bootstrap-directory http://user:pass@helper.example/path?token=supersecret",
      "reason": "Retry with AUTH_TOKEN=reason-secret and --invite-key inv-reason-leak",
      "placeholder_unresolved": false,
      "safe_to_execute_as_is": true
    }
  }
}
EOF_ACCESS_RECOVERY_REDACTION

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$ACCESS_RECOVERY_STATUS_DOC" \
  --roadmap-summary-json "$ACCESS_RECOVERY_REDACTION_INPUT" \
  --summary-json "$ACCESS_RECOVERY_REDACTION_SUMMARY_JSON" \
  --print-summary-json 0 >"$ACCESS_RECOVERY_REDACTION_STDOUT"

assert_file_contains "$ACCESS_RECOVERY_REDACTION_SUMMARY_JSON" '"command_redacted": true' "access recovery redaction summary missing command_redacted marker"
assert_file_contains "$ACCESS_RECOVERY_REDACTION_SUMMARY_JSON" '--subject [redacted] --admin-token [redacted]' "access recovery command did not redact secret flags"
assert_file_contains "$ACCESS_RECOVERY_REDACTION_SUMMARY_JSON" 'http://[redacted]@helper.example/path?token=[redacted]' "access recovery command did not redact URL credentials/query token"
assert_file_contains "$ACCESS_RECOVERY_REDACTION_SUMMARY_JSON" 'AUTH_TOKEN=[redacted] and --invite-key [redacted]' "access recovery reason did not redact secret env/flag values"
for leaked in inv-secret-leak super-admin-token user:pass supersecret reason-secret inv-reason-leak; do
  if grep -F -- "$leaked" "$ACCESS_RECOVERY_REDACTION_SUMMARY_JSON" "$ACCESS_RECOVERY_REDACTION_STDOUT" >/dev/null 2>&1; then
    echo "access recovery redaction leaked sensitive token: $leaked"
    cat "$ACCESS_RECOVERY_REDACTION_SUMMARY_JSON"
    cat "$ACCESS_RECOVERY_REDACTION_STDOUT"
    exit 1
  fi
done

echo "[gpm-gap-scan] access recovery ready roadmap state does not add a blocker"
ACCESS_RECOVERY_READY_INPUT="$TMP_DIR/access_recovery_ready_roadmap.json"
ACCESS_RECOVERY_READY_SUMMARY_JSON="$TMP_DIR/access_recovery_ready_summary.json"

cat >"$ACCESS_RECOVERY_READY_INPUT" <<'EOF_ACCESS_RECOVERY_READY'
{
  "access_recovery_pilot_handoff_ready": true,
  "access_recovery_track": {
    "status": "pilot-handoff-ready",
    "pilot_handoff_ready": true,
    "needs_attention": false,
    "trusted_verifier_receipt_valid": true,
    "trusted_pilot_receipt_ready": true,
    "verifier_pilot_handoff_ready": true,
    "recommended_next_action": {
      "id": "archive_receipt",
      "command": "archive trusted verifier receipt"
    }
  }
}
EOF_ACCESS_RECOVERY_READY

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$ACCESS_RECOVERY_STATUS_DOC" \
  --roadmap-summary-json "$ACCESS_RECOVERY_READY_INPUT" \
  --summary-json "$ACCESS_RECOVERY_READY_SUMMARY_JSON" \
  --print-summary-json 0 >/dev/null

assert_file_matches_regex "$ACCESS_RECOVERY_READY_SUMMARY_JSON" '"missing_next"[[:space:]]*:[[:space:]]*5' "ready access recovery roadmap should not add a handoff blocker"
assert_file_contains "$ACCESS_RECOVERY_READY_SUMMARY_JSON" '"status": "pilot-handoff-ready"' "ready access recovery status not extracted"
assert_file_contains "$ACCESS_RECOVERY_READY_SUMMARY_JSON" '"access_recovery_pilot_handoff_ready": true' "ready access recovery handoff readiness not extracted"
assert_file_contains "$ACCESS_RECOVERY_READY_SUMMARY_JSON" '"source": "recommended_next_action"' "ready access recovery recommended action source not extracted"
if grep -F "Roadmap Access Recovery handoff state is not ready" "$ACCESS_RECOVERY_READY_SUMMARY_JSON" >/dev/null 2>&1; then
  echo "ready access recovery roadmap should not add not-ready blocker"
  cat "$ACCESS_RECOVERY_READY_SUMMARY_JSON"
  exit 1
fi

echo "[gpm-gap-scan] access recovery missing attention boolean fails closed"
ACCESS_RECOVERY_UNKNOWN_ATTENTION_INPUT="$TMP_DIR/access_recovery_unknown_attention_roadmap.json"
ACCESS_RECOVERY_UNKNOWN_ATTENTION_SUMMARY_JSON="$TMP_DIR/access_recovery_unknown_attention_summary.json"

cat >"$ACCESS_RECOVERY_UNKNOWN_ATTENTION_INPUT" <<'EOF_ACCESS_RECOVERY_UNKNOWN_ATTENTION'
{
  "access_recovery_pilot_handoff_ready": true,
  "access_recovery_track": {
    "status": "pilot-handoff-ready",
    "pilot_handoff_ready": true,
    "trusted_verifier_receipt_valid": true,
    "trusted_pilot_receipt_ready": true,
    "verifier_pilot_handoff_ready": true
  }
}
EOF_ACCESS_RECOVERY_UNKNOWN_ATTENTION

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$ACCESS_RECOVERY_STATUS_DOC" \
  --roadmap-summary-json "$ACCESS_RECOVERY_UNKNOWN_ATTENTION_INPUT" \
  --summary-json "$ACCESS_RECOVERY_UNKNOWN_ATTENTION_SUMMARY_JSON" \
  --print-summary-json 0 >/dev/null

assert_file_matches_regex "$ACCESS_RECOVERY_UNKNOWN_ATTENTION_SUMMARY_JSON" '"missing_next"[[:space:]]*:[[:space:]]*6' "missing access recovery needs_attention should add a handoff blocker"
assert_file_contains "$ACCESS_RECOVERY_UNKNOWN_ATTENTION_SUMMARY_JSON" 'Roadmap Access Recovery handoff state is not ready (status=pilot-handoff-ready, access_recovery_pilot_handoff_ready=true' "missing access recovery needs_attention blocker text missing"
assert_file_contains "$ACCESS_RECOVERY_UNKNOWN_ATTENTION_SUMMARY_JSON" 'verifier authority and synced roadmap status are both required before handoff is complete' "missing access recovery needs_attention blocker should preserve authority wording"

echo "[gpm-gap-scan] missing roadmap fields fail closed"
MISSING_FIELDS_STATUS_DOC="$TMP_DIR/missing_fields_status.md"
MISSING_FIELDS_INPUT="$TMP_DIR/missing_fields_roadmap.json"
MISSING_FIELDS_SUMMARY_JSON="$TMP_DIR/missing_fields_summary.json"

cat >"$MISSING_FIELDS_STATUS_DOC" <<'EOF_MISSING_FIELDS_STATUS'
# Missing Roadmap Fields Fixture

## In-Progress
- Schema transition check.

## Missing / Next
- Keep roadmap evidence packs fresh.
EOF_MISSING_FIELDS_STATUS

cat >"$MISSING_FIELDS_INPUT" <<'EOF_MISSING_FIELDS_SUMMARY'
{
  "vpn_track": {
    "profile_default_gate": {
      "unresolved_placeholders": false
    },
    "runtime_actuation_promotion": {
      "status": "pass",
      "decision": "GO"
    }
  }
}
EOF_MISSING_FIELDS_SUMMARY

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$MISSING_FIELDS_STATUS_DOC" \
  --roadmap-summary-json "$MISSING_FIELDS_INPUT" \
  --summary-json "$MISSING_FIELDS_SUMMARY_JSON" \
  --print-summary-json 0 >/dev/null

assert_file_matches_regex "$MISSING_FIELDS_SUMMARY_JSON" '"missing_next"[[:space:]]*:[[:space:]]*6' "missing roadmap fields should add five fail-closed blockers"
assert_file_contains "$MISSING_FIELDS_SUMMARY_JSON" 'Roadmap Access Recovery handoff state is missing; provide a roadmap summary with access_recovery_track before pilot handoff.' "missing roadmap fields summary missing access recovery track blocker"
assert_file_contains "$MISSING_FIELDS_SUMMARY_JSON" 'Roadmap multi-VM stability command source is not actionable (vm_command_source_ready=unknown, next_command_actionable=unknown)' "missing roadmap fields summary missing multi-vm unknown blocker"
assert_file_contains "$MISSING_FIELDS_SUMMARY_JSON" 'Roadmap evidence pack profile_default_gate_evidence_pack needs attention (status=missing)' "missing roadmap fields summary missing profile evidence-pack blocker"
assert_file_contains "$MISSING_FIELDS_SUMMARY_JSON" 'Roadmap evidence pack runtime_actuation_promotion_evidence_pack needs attention (status=missing)' "missing roadmap fields summary missing runtime evidence-pack blocker"
assert_file_contains "$MISSING_FIELDS_SUMMARY_JSON" 'Roadmap evidence pack profile_compare_multi_vm_stability_promotion_evidence_pack needs attention (status=missing)' "missing roadmap fields summary missing multi-vm evidence-pack blocker"

echo "[gpm-gap-scan] generic profile-default evidence text is not treated as a placeholder"
PROFILE_DEFAULT_STATUS_DOC="$TMP_DIR/profile_default_status.md"
PROFILE_DEFAULT_SUMMARY_JSON="$TMP_DIR/profile_default_summary.json"
PROFILE_DEFAULT_STDOUT="$TMP_DIR/profile_default_stdout.md"

cat >"$PROFILE_DEFAULT_STATUS_DOC" <<'EOF_PROFILE_DEFAULT_STATUS'
# Profile Default Evidence Fixture

## In-Progress
- Profile-default evidence gathering is in place, but repeated campaign evidence still needs capture and publish.

## Missing / Next
- M2: run and archive real-host stability cycles for strict selection-policy defaults, then publish evidence-pack artifacts from those archived outputs.
EOF_PROFILE_DEFAULT_STATUS

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$PROFILE_DEFAULT_STATUS_DOC" \
  --summary-json "$PROFILE_DEFAULT_SUMMARY_JSON" \
  --print-summary-json 0 >"$PROFILE_DEFAULT_STDOUT"

assert_file_contains "$PROFILE_DEFAULT_SUMMARY_JSON" '"recommended_action": "Generate and publish deterministic evidence-pack artifacts with fail-closed checks."' "profile-default fixture should not imply missing A_HOST/B_HOST placeholders"
assert_file_contains "$PROFILE_DEFAULT_SUMMARY_JSON" "\"suggested_tests\": [\"scripts/integration_client_vpn_path_profile_wiring.sh\", \"scripts/integration_roadmap_progress_report.sh\"]" "profile-default fixture missing profile/evidence suggested tests"
if grep -F "Populate A_HOST/B_HOST and campaign subject" "$PROFILE_DEFAULT_SUMMARY_JSON" >/dev/null 2>&1; then
  echo "generic profile-default evidence text should not use placeholder remediation action"
  cat "$PROFILE_DEFAULT_SUMMARY_JSON"
  exit 1
fi

echo "[gpm-gap-scan] live-condition validation artifacts require real-host evidence"
LIVE_CONDITIONS_STATUS_DOC="$TMP_DIR/live_conditions_status.md"
LIVE_CONDITIONS_SUMMARY_JSON="$TMP_DIR/live_conditions_summary.json"
LIVE_CONDITIONS_STDOUT="$TMP_DIR/live_conditions_stdout.md"

cat >"$LIVE_CONDITIONS_STATUS_DOC" <<'EOF_LIVE_CONDITIONS_STATUS'
# Live Conditions Fixture

## In-Progress
- Legacy runtime-admission wave M1 dedicated contribution-role runtime admission is implemented locally.

## Missing / Next
- Remaining work: real scheduler/path-selection promotion evidence and end-to-end validation artifacts under live conditions.
EOF_LIVE_CONDITIONS_STATUS

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$LIVE_CONDITIONS_STATUS_DOC" \
  --summary-json "$LIVE_CONDITIONS_SUMMARY_JSON" \
  --print-summary-json 0 >"$LIVE_CONDITIONS_STDOUT"

assert_file_contains "$LIVE_CONDITIONS_SUMMARY_JSON" '"closure_mode": "real_host_required"' "live conditions fixture summary missing real_host_required closure mode"
assert_file_contains "$LIVE_CONDITIONS_SUMMARY_JSON" '"blocked_by": ["real_hosts", "evidence_pack_artifacts"]' "live conditions fixture summary missing real-host/evidence blockers"
assert_file_contains "$LIVE_CONDITIONS_SUMMARY_JSON" '"requires_real_hosts": true' "live conditions fixture summary missing requires_real_hosts true"
assert_file_contains "$LIVE_CONDITIONS_SUMMARY_JSON" "\"suggested_tests\": [\"scripts/integration_client_3hop_runtime.sh\", \"scripts/integration_live_wg_full_path_strict.sh\"]" "live conditions fixture summary missing runtime suggested tests"
assert_file_contains "$LIVE_CONDITIONS_SUMMARY_JSON" '"suggested_files": ["docs/gpm-productization-status.md", "docs/global-privacy-mesh-track.md", "docs/product-roadmap.md", "scripts/integration_3machine_prod_wg_validate.sh"]' "live conditions fixture summary missing real-host suggested files"

echo "[gpm-gap-scan] admin settlement/slashing blockers are classified"
ADMIN_STATUS_DOC="$TMP_DIR/admin_status.md"
ADMIN_SUMMARY_JSON="$TMP_DIR/admin_summary.json"
ADMIN_STDOUT="$TMP_DIR/admin_stdout.md"

cat >"$ADMIN_STATUS_DOC" <<'EOF_ADMIN_STATUS'
# Admin Settlement Fixture

## In-Progress
- Admin Console settlement review remains local-only until live chain proof is archived.
- Local reservation id/session/subject binding exists, but this subject wording is not a profile-default campaign placeholder.

## Missing / Next
- Productization: finish end-to-end Admin Console validation against live chain settlement, slashing holds, dispute/finalization review, and weekly payout release evidence.
EOF_ADMIN_STATUS

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$ADMIN_STATUS_DOC" \
  --summary-json "$ADMIN_SUMMARY_JSON" \
  --print-summary-json 0 >"$ADMIN_STDOUT"

assert_file_contains "$ADMIN_SUMMARY_JSON" '"recommended_action": "Run Admin Console settlement/slashing validation, then archive live-chain payout evidence."' "admin fixture summary missing admin settlement action"
assert_file_contains "$ADMIN_SUMMARY_JSON" '"closure_mode": "network_required"' "admin fixture summary missing network_required closure mode"
assert_file_contains "$ADMIN_SUMMARY_JSON" '"blocked_by": ["admin_settlement_validation", "live_chain"]' "admin fixture summary missing admin/live-chain blockers"
assert_file_contains "$ADMIN_SUMMARY_JSON" "\"suggested_tests\": [\"scripts/gpm_admin_settlement_live_evidence.sh --start-local-tdpnd 1 --print-summary-json 1\", \"scripts/integration_gpm_admin_settlement_contract.sh\", \"go test ./services/localapi -run GPMAdminRewardFinalize -count=1\", \"go test ./pkg/settlement -run 'IssueReward|SubmitSlashEvidence' -count=1\"]" "admin fixture summary missing settlement suggested tests"
assert_file_contains "$ADMIN_SUMMARY_JSON" '"suggested_files": ["docs/gpm-productization-status.md", "docs/local-control-api.md", "scripts/gpm_admin_settlement_live_evidence.sh", "scripts/integration_gpm_admin_settlement_contract.sh", "services/localapi/gpm_api.go", "pkg/settlement/memory.go"]' "admin fixture summary missing admin suggested files"

echo "[gpm-gap-scan] wallet auth hardening blockers stay separate from admin settlement"
AUTH_STATUS_DOC="$TMP_DIR/auth_status.md"
AUTH_SUMMARY_JSON="$TMP_DIR/auth_summary.json"
AUTH_STDOUT="$TMP_DIR/auth_stdout.md"

cat >"$AUTH_STATUS_DOC" <<'EOF_AUTH_STATUS'
# Auth Fixture

## In-Progress
- Local wallet binding for GPM auth now works for secp256k1 wallet proofs.

## Missing / Next
- Auth hardening: capture end-to-end Keplr and Leap wallet-extension evidence against the local secp256k1 binding path, including alias pubkey types and mismatched-wallet rejection. Admin Console access remains command-backed even after local binding.
EOF_AUTH_STATUS

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$AUTH_STATUS_DOC" \
  --summary-json "$AUTH_SUMMARY_JSON" \
  --print-summary-json 0 >"$AUTH_STDOUT"

assert_file_contains "$AUTH_SUMMARY_JSON" '"recommended_action": "Archive Keplr/Leap wallet-extension auth evidence for secp256k1 binding and mismatched-wallet rejection."' "auth fixture summary missing wallet evidence action"
assert_file_contains "$AUTH_SUMMARY_JSON" '"blocked_by": ["wallet_extension_evidence"]' "auth fixture summary should not route to admin settlement blockers"
assert_file_contains "$AUTH_SUMMARY_JSON" "\"suggested_tests\": [\"scripts/gpm_wallet_auth_evidence.sh --print-summary-json 1\", \"go test ./services/localapi -run 'GPM.*Auth|Wallet|Keplr|Leap|Secp' -count=1\"]" "auth fixture summary missing wallet auth suggested tests"
assert_file_contains "$AUTH_SUMMARY_JSON" '"suggested_files": ["docs/gpm-productization-status.md", "docs/local-control-api.md", "scripts/gpm_wallet_auth_evidence.sh", "services/localapi/gpm_api.go", "services/localapi/gpm_api_test.go"]' "auth fixture summary missing wallet auth suggested files"

echo "[gpm-gap-scan] reservation write blockers are classified"
RESERVATION_STATUS_DOC="$TMP_DIR/reservation_status.md"
RESERVATION_SUMMARY_JSON="$TMP_DIR/reservation_summary.json"
RESERVATION_STDOUT="$TMP_DIR/reservation_stdout.md"

cat >"$RESERVATION_STATUS_DOC" <<'EOF_RESERVATION_STATUS'
# Reservation Write Fixture

## In-Progress
- Chain settlement reservation-write bridge support exists, but the local GPM API subject_id reservation binding and API-to-chain evidence are still missing for ReserveFunds intents.

## Missing / Next
- Productization: add authenticated local GPM ReserveFunds reservation API and archive live API-to-chain reservation-write evidence.
EOF_RESERVATION_STATUS

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$RESERVATION_STATUS_DOC" \
  --summary-json "$RESERVATION_SUMMARY_JSON" \
  --print-summary-json 0 >"$RESERVATION_STDOUT"

assert_file_contains "$RESERVATION_SUMMARY_JSON" '"recommended_action": "Wire the local GPM ReserveFunds API path, then archive API-to-chain reservation evidence."' "reservation fixture summary missing reservation action"
assert_file_contains "$RESERVATION_SUMMARY_JSON" '"blocked_by": ["admin_settlement_validation", "local_api_reservation_evidence", "live_chain"]' "reservation fixture summary missing precise reservation blockers"
assert_file_contains "$RESERVATION_SUMMARY_JSON" "\"suggested_tests\": [\"scripts/gpm_admin_settlement_live_evidence.sh --start-local-tdpnd 1 --print-summary-json 1\", \"scripts/integration_gpm_admin_settlement_contract.sh\", \"go test ./services/localapi -run GPMAdminRewardFinalize -count=1\", \"go test ./pkg/settlement -run 'IssueReward|SubmitSlashEvidence' -count=1\", \"go test ./services/localapi -run 'ReserveFunds|SettlementReservation|GPM.*Reservation' -count=1\", \"go test ./pkg/settlement -run 'ReserveFunds|CosmosAdapter' -count=1\", \"go test ./blockchain/tdpn-chain/cmd/tdpnd -run 'Settlement.*Reservation|BillingReservation' -count=1\"]" "reservation fixture summary missing reservation suggested tests"
assert_file_contains "$RESERVATION_SUMMARY_JSON" '"suggested_files": ["docs/gpm-productization-status.md", "docs/local-control-api.md", "scripts/gpm_admin_settlement_live_evidence.sh", "scripts/integration_gpm_admin_settlement_contract.sh", "services/localapi/gpm_api.go", "pkg/settlement/memory.go", "services/localapi/service.go", "pkg/settlement/types.go", "pkg/settlement/cosmos_adapter.go", "blockchain/tdpn-chain/cmd/tdpnd/settlement_bridge.go", "blockchain/tdpn-chain/cmd/tdpnd/settlement_bridge_test.go"]' "reservation fixture summary missing reservation suggested files"

echo "[gpm-gap-scan] wired reservation blockers are classified as evidence work"
RESERVATION_WIRED_STATUS_DOC="$TMP_DIR/reservation_wired_status.md"
RESERVATION_WIRED_SUMMARY_JSON="$TMP_DIR/reservation_wired_summary.json"
RESERVATION_WIRED_STDOUT="$TMP_DIR/reservation_wired_stdout.md"

cat >"$RESERVATION_WIRED_STATUS_DOC" <<'EOF_RESERVATION_WIRED_STATUS'
# Wired Reservation Evidence Fixture

## In-Progress
- GPM addendum implementation has wallet-bound local GPM API reservation binding wired, but live API-to-chain ReserveFunds reservation evidence and live-chain settlement round-trip evidence remain blockers.

## Missing / Next
- Productization: finish API-to-chain reservation evidence for the wallet-bound ReserveFunds path and rerun live bridge reservation/settlement smoke.
EOF_RESERVATION_WIRED_STATUS

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$RESERVATION_WIRED_STATUS_DOC" \
  --summary-json "$RESERVATION_WIRED_SUMMARY_JSON" \
  --print-summary-json 0 >"$RESERVATION_WIRED_STDOUT"

assert_file_contains "$RESERVATION_WIRED_SUMMARY_JSON" '"recommended_action": "Archive API-to-chain ReserveFunds reservation evidence, then rerun live bridge reservation/settlement smoke."' "wired reservation fixture summary missing evidence archival action"
assert_file_contains "$RESERVATION_WIRED_SUMMARY_JSON" '"blocked_by": ["admin_settlement_validation", "local_api_reservation_evidence", "live_chain"]' "wired reservation fixture summary missing evidence/live-chain blockers"

echo "[gpm-gap-scan] reserve-and-connect productization wording maps to reservation evidence"
RESERVE_CONNECT_STATUS_DOC="$TMP_DIR/reserve_connect_status.md"
RESERVE_CONNECT_SUMMARY_JSON="$TMP_DIR/reserve_connect_summary.json"
RESERVE_CONNECT_STDOUT="$TMP_DIR/reserve_connect_stdout.md"

cat >"$RESERVE_CONNECT_STATUS_DOC" <<'EOF_RESERVE_CONNECT_STATUS'
# Reserve-And-Connect Evidence Fixture

## In-Progress
- Local reserve-and-connect now binds reservation id/session/subject through client -> entry -> exit path-open proofs.

## Missing / Next
- Productization: finish API-to-chain evidence for the wallet/session-bound reserve-and-connect path and archive live chain settlement evidence.
EOF_RESERVE_CONNECT_STATUS

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$RESERVE_CONNECT_STATUS_DOC" \
  --summary-json "$RESERVE_CONNECT_SUMMARY_JSON" \
  --print-summary-json 0 >"$RESERVE_CONNECT_STDOUT"

assert_file_contains "$RESERVE_CONNECT_SUMMARY_JSON" '"recommended_action": "Archive API-to-chain ReserveFunds reservation evidence, then rerun live bridge reservation/settlement smoke."' "reserve-and-connect fixture summary missing reservation evidence action"
assert_file_contains "$RESERVE_CONNECT_SUMMARY_JSON" '"blocked_by": ["admin_settlement_validation", "local_api_reservation_evidence", "live_chain"]' "reserve-and-connect fixture summary missing reservation/live-chain blockers"
assert_file_contains "$RESERVE_CONNECT_SUMMARY_JSON" "\"suggested_tests\": [\"scripts/gpm_admin_settlement_live_evidence.sh --start-local-tdpnd 1 --print-summary-json 1\", \"scripts/integration_gpm_admin_settlement_contract.sh\", \"go test ./services/localapi -run GPMAdminRewardFinalize -count=1\", \"go test ./pkg/settlement -run 'IssueReward|SubmitSlashEvidence' -count=1\", \"go test ./services/localapi -run 'ReserveFunds|SettlementReservation|GPM.*Reservation' -count=1\", \"go test ./pkg/settlement -run 'ReserveFunds|CosmosAdapter' -count=1\", \"go test ./blockchain/tdpn-chain/cmd/tdpnd -run 'Settlement.*Reservation|BillingReservation' -count=1\"]" "reserve-and-connect fixture summary missing reservation suggested tests"
assert_file_contains "$RESERVE_CONNECT_SUMMARY_JSON" '"suggested_files": ["docs/gpm-productization-status.md", "docs/local-control-api.md", "scripts/gpm_admin_settlement_live_evidence.sh", "scripts/integration_gpm_admin_settlement_contract.sh", "services/localapi/gpm_api.go", "pkg/settlement/memory.go", "services/localapi/service.go", "pkg/settlement/types.go", "pkg/settlement/cosmos_adapter.go", "blockchain/tdpn-chain/cmd/tdpnd/settlement_bridge.go", "blockchain/tdpn-chain/cmd/tdpnd/settlement_bridge_test.go"]' "reserve-and-connect fixture summary missing reservation suggested files"

echo "[gpm-gap-scan] route fallback blockers are classified"
ROUTE_STATUS_DOC="$TMP_DIR/route_status.md"
ROUTE_SUMMARY_JSON="$TMP_DIR/route_summary.json"
ROUTE_STDOUT="$TMP_DIR/route_stdout.md"

cat >"$ROUTE_STATUS_DOC" <<'EOF_ROUTE_STATUS'
# Route Hardening Fixture

## In-Progress
- Route hardening: keep direct-exit fallback as an explicit 1hop/support-mode behavior only.

## Missing / Next
- Core env paths still permit CLIENT_ALLOW_DIRECT_EXIT_FALLBACK=1 on a nominal 2hop client when strict/middle/distinct policies are off, so a follow-up code gate should reject that ambiguous combination by default.
EOF_ROUTE_STATUS

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$ROUTE_STATUS_DOC" \
  --summary-json "$ROUTE_SUMMARY_JSON" \
  --print-summary-json 0 >"$ROUTE_STDOUT"

assert_file_contains "$ROUTE_SUMMARY_JSON" '"recommended_action": "Close the direct-exit fallback ambiguity with a fail-closed runtime gate and profile contract regression."' "route fixture summary missing direct-exit action"
assert_file_contains "$ROUTE_SUMMARY_JSON" '"blocked_by": ["route_policy"]' "route fixture summary missing route policy blocker"
assert_file_contains "$ROUTE_SUMMARY_JSON" "\"suggested_tests\": [\"go test ./internal/app -run 'DirectExitFallback|ValidateRuntimeConfig' -count=1\", \"scripts/integration_client_vpn_path_profile_wiring.sh\"]" "route fixture summary missing route suggested tests"
assert_file_contains "$ROUTE_SUMMARY_JSON" '"suggested_files": ["docs/gpm-productization-status.md", "internal/app/client.go", "internal/app/client_mode_test.go", "scripts/integration_client_vpn_path_profile_wiring.sh"]' "route fixture summary missing route suggested files"

echo "[gpm-gap-scan] middle-hop anti-downgrade blockers are classified"
MIDDLE_STATUS_DOC="$TMP_DIR/middle_status.md"
MIDDLE_SUMMARY_JSON="$TMP_DIR/middle_summary.json"
MIDDLE_STDOUT="$TMP_DIR/middle_stdout.md"

cat >"$MIDDLE_STATUS_DOC" <<'EOF_MIDDLE_STATUS'
# Middle Hop Fixture

## In-Progress
- M3 route-policy and 3-hop validation are partially wired, but exit-side path/profile/middle anti-downgrade binding still needs focused local closure.

## Missing / Next
- M3: bind exit admission to entry-signed path/profile/middle assertions so strict 3-hop clients cannot be downgraded by direct exit path-open calls.
EOF_MIDDLE_STATUS

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$MIDDLE_STATUS_DOC" \
  --summary-json "$MIDDLE_SUMMARY_JSON" \
  --print-summary-json 0 >"$MIDDLE_STDOUT"

assert_file_contains "$MIDDLE_SUMMARY_JSON" '"recommended_action": "Close M3 exit-side anti-downgrade binding with path/profile/middle assertions and focused route tests."' "middle fixture summary missing anti-downgrade action"
assert_file_contains "$MIDDLE_SUMMARY_JSON" '"blocked_by": ["route_policy"]' "middle fixture summary missing route policy blocker"
assert_file_contains "$MIDDLE_SUMMARY_JSON" "\"suggested_tests\": [\"go test ./internal/app ./services/entry -run 'PathOpen|3Hop|Middle|Profile|Downgrade' -count=1\", \"scripts/integration_client_3hop_runtime.sh\"]" "middle fixture summary missing anti-downgrade suggested tests"
assert_file_contains "$MIDDLE_SUMMARY_JSON" '"suggested_files": ["docs/gpm-productization-status.md", "internal/app/client.go", "internal/app/selection_test.go", "services/entry/service.go", "services/entry/path_open_test.go", "scripts/integration_client_3hop_runtime.sh"]' "middle fixture summary missing anti-downgrade suggested files"

echo "[gpm-gap-scan] middle-role deployment/evidence blockers are classified"
MIDDLE_SERVICE_STATUS_DOC="$TMP_DIR/middle_service_status.md"
MIDDLE_SERVICE_SUMMARY_JSON="$TMP_DIR/middle_service_summary.json"
MIDDLE_SERVICE_STDOUT="$TMP_DIR/middle_service_stdout.md"

cat >"$MIDDLE_SERVICE_STATUS_DOC" <<'EOF_MIDDLE_SERVICE_STATUS'
# Middle Role Deployment Evidence Fixture

## In-Progress
- M3 local 3-hop runtime has a middle role available via go run ./cmd/node --middle with static entry/exit peer allowlisting, but real-host evidence and published signoff artifacts are still missing.

## Missing / Next
- M3: run real-host 3-hop validation with the local middle role, publish the evidence pack, and formalize deployment admission policy.
EOF_MIDDLE_SERVICE_STATUS

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$MIDDLE_SERVICE_STATUS_DOC" \
  --summary-json "$MIDDLE_SERVICE_SUMMARY_JSON" \
  --print-summary-json 0 >"$MIDDLE_SERVICE_STDOUT"

assert_file_contains "$MIDDLE_SERVICE_SUMMARY_JSON" '"recommended_action": "Validate the local production middle role contract, then publish real-host middle-hop evidence and deployment admission policy."' "middle role fixture summary missing production middle action"
assert_file_contains "$MIDDLE_SERVICE_SUMMARY_JSON" '"blocked_by": ["real_hosts", "production_admission_policy", "evidence_pack_artifacts"]' "middle role fixture summary missing real-host/evidence/admission blockers"
assert_file_contains "$MIDDLE_SERVICE_SUMMARY_JSON" "\"suggested_tests\": [\"go test ./services/middle ./services/entry ./services/exit -run 'Middle|Relay|Ready|Stats|PathOpen|ServiceContract' -count=1\", \"scripts/integration_middle_service_contract.sh\", \"scripts/integration_client_3hop_runtime.sh\", \"scripts/integration_roadmap_progress_report.sh\"]" "middle role fixture summary missing middle role suggested tests"
assert_file_contains "$MIDDLE_SERVICE_SUMMARY_JSON" '"suggested_files": ["docs/gpm-productization-status.md", "docs/global-privacy-mesh-track.md", "docs/product-roadmap.md", "scripts/integration_3machine_prod_wg_validate.sh", "services/middle/service.go", "services/middle/service_test.go", "services/entry/service.go", "services/exit/service.go", "internal/app/client.go", "scripts/integration_middle_service_contract.sh", "scripts/integration_client_3hop_runtime.sh", "scripts/roadmap_progress_report.sh"]' "middle role fixture summary missing middle role suggested files"

echo "[gpm-gap-scan] objective proof verification blockers are classified"
PROOF_STATUS_DOC="$TMP_DIR/proof_status.md"
PROOF_SUMMARY_JSON="$TMP_DIR/proof_summary.json"
PROOF_STDOUT="$TMP_DIR/proof_stdout.md"

cat >"$PROOF_STATUS_DOC" <<'EOF_PROOF_STATUS'
# Proof Trust Fixture

## In-Progress
- Reward proof trust is bounded to objective proof reference shapes, but proof verification remains unverified without a proof registry.

## Missing / Next
- Settlement: promote reward proof and slashing objective proof references from shape checks to proof registry verification before payout signoff.
EOF_PROOF_STATUS

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$PROOF_STATUS_DOC" \
  --summary-json "$PROOF_SUMMARY_JSON" \
  --print-summary-json 0 >"$PROOF_STDOUT"

assert_file_contains "$PROOF_SUMMARY_JSON" '"recommended_action": "Promote reward/slashing proof references from shape checks to objective proof registry verification before payout signoff."' "proof fixture summary missing proof-verification action"
assert_file_contains "$PROOF_SUMMARY_JSON" '"blocked_by": ["admin_settlement_validation", "objective_proof_verification", "live_chain"]' "proof fixture summary missing proof/live-chain blockers"
assert_file_contains "$PROOF_SUMMARY_JSON" "\"suggested_tests\": [\"scripts/gpm_admin_settlement_live_evidence.sh --start-local-tdpnd 1 --print-summary-json 1\", \"scripts/integration_gpm_admin_settlement_contract.sh\", \"go test ./services/localapi -run GPMAdminRewardFinalize -count=1\", \"go test ./pkg/settlement -run 'IssueReward|SubmitSlashEvidence' -count=1\", \"go test ./pkg/settlement -run 'IssueReward|Proof|Objective|FinalizeWeekly' -count=1\", \"go test ./services/localapi -run 'GPMAdminRewardFinalize|RewardProof' -count=1\", \"go test ./blockchain/tdpn-chain/cmd/tdpnd -run 'Reward|Proof|Settlement' -count=1\"]" "proof fixture summary missing proof suggested tests"
assert_file_contains "$PROOF_SUMMARY_JSON" '"suggested_files": ["docs/gpm-productization-status.md", "docs/local-control-api.md", "scripts/gpm_admin_settlement_live_evidence.sh", "scripts/integration_gpm_admin_settlement_contract.sh", "services/localapi/gpm_api.go", "pkg/settlement/memory.go", "pkg/settlement/reward_proof_trust.md", "blockchain/tdpn-chain/cmd/tdpnd/settlement_bridge.go"]' "proof fixture summary missing proof suggested files"

echo "[gpm-gap-scan] settlement confirmation blockers are classified"
CONFIRM_STATUS_DOC="$TMP_DIR/confirm_status.md"
CONFIRM_SUMMARY_JSON="$TMP_DIR/confirm_summary.json"
CONFIRM_STDOUT="$TMP_DIR/confirm_stdout.md"

cat >"$CONFIRM_STATUS_DOC" <<'EOF_CONFIRM_STATUS'
# Settlement Confirmation Fixture

## In-Progress
- Settlement Reconcile can promote submitted records from chain record existence, but pending chain state should not be treated as confirmed.

## Missing / Next
- Settlement: require finalized chain confirmation status before Reconcile promotes submitted payout, reservation, or slashing records.
EOF_CONFIRM_STATUS

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$CONFIRM_STATUS_DOC" \
  --summary-json "$CONFIRM_SUMMARY_JSON" \
  --print-summary-json 0 >"$CONFIRM_STDOUT"

assert_file_contains "$CONFIRM_SUMMARY_JSON" '"recommended_action": "Require finalized chain status during settlement reconciliation; do not promote submitted records from existence alone."' "confirmation fixture summary missing confirmation action"
assert_file_contains "$CONFIRM_SUMMARY_JSON" '"blocked_by": ["admin_settlement_validation", "chain_confirmation_status"]' "confirmation fixture summary missing confirmation blocker"
assert_file_contains "$CONFIRM_SUMMARY_JSON" "\"suggested_tests\": [\"scripts/gpm_admin_settlement_live_evidence.sh --start-local-tdpnd 1 --print-summary-json 1\", \"scripts/integration_gpm_admin_settlement_contract.sh\", \"go test ./services/localapi -run GPMAdminRewardFinalize -count=1\", \"go test ./pkg/settlement -run 'IssueReward|SubmitSlashEvidence' -count=1\", \"go test ./pkg/settlement -run 'Reconcile|Confirmation|Pending|Submitted' -count=1\", \"go test ./services/localapi -run 'Reconcile|RewardFinalize' -count=1\"]" "confirmation fixture summary missing confirmation suggested tests"
assert_file_contains "$CONFIRM_SUMMARY_JSON" '"suggested_files": ["docs/gpm-productization-status.md", "docs/local-control-api.md", "scripts/gpm_admin_settlement_live_evidence.sh", "scripts/integration_gpm_admin_settlement_contract.sh", "services/localapi/gpm_api.go", "pkg/settlement/memory.go", "pkg/settlement/types.go", "pkg/settlement/cosmos_adapter.go"]' "confirmation fixture summary missing confirmation suggested files"

echo "[gpm-gap-scan] durable replay guard blockers are classified"
REPLAY_STATUS_DOC="$TMP_DIR/replay_status.md"
REPLAY_SUMMARY_JSON="$TMP_DIR/replay_summary.json"
REPLAY_STDOUT="$TMP_DIR/replay_stdout.md"

cat >"$REPLAY_STATUS_DOC" <<'EOF_REPLAY_STATUS'
# Replay Guard Fixture

## In-Progress
- Strict replay guard validation exists, but production multi-instance replay storage is not durable across restart.

## Missing / Next
- VPN: require durable replay guard storage for strict production exit deployments and reject in-memory-only replay cache in multi-instance mode.
EOF_REPLAY_STATUS

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$REPLAY_STATUS_DOC" \
  --summary-json "$REPLAY_SUMMARY_JSON" \
  --print-summary-json 0 >"$REPLAY_STDOUT"

assert_file_contains "$REPLAY_SUMMARY_JSON" '"recommended_action": "Require durable shared replay storage for strict production exit deployments and add restart/multi-instance regressions."' "replay fixture summary missing replay action"
assert_file_contains "$REPLAY_SUMMARY_JSON" '"blocked_by": ["durable_replay_storage"]' "replay fixture summary missing durable replay blocker"
assert_file_contains "$REPLAY_SUMMARY_JSON" "\"suggested_tests\": [\"go test ./services/exit -run 'Replay|Guard|Durable|Strict' -count=1\", \"scripts/integration_live_wg_full_path_strict.sh\"]" "replay fixture summary missing durable replay suggested tests"
assert_file_contains "$REPLAY_SUMMARY_JSON" '"suggested_files": ["docs/gpm-productization-status.md", "services/exit/service.go", "services/exit/service_test.go"]' "replay fixture summary missing durable replay suggested files"

echo "[gpm-gap-scan] helper naming extraction remains deterministic"
HELPER_STATUS_DOC="$TMP_DIR/helper_status.md"
HELPER_REPORTS_DIR="$TMP_DIR/helper_reports"
HELPER_SUMMARY_JSON="$TMP_DIR/helper_summary.json"
HELPER_STDOUT="$TMP_DIR/helper_stdout.md"

cat >"$HELPER_STATUS_DOC" <<'EOF_HELPER_STATUS'
# Helper Naming Fixture

## In-Progress
- Batch helper accelerators include `roadmap_live_evidence_actionable_run`, `roadmap_evidence_pack_actionable_run`, `roadmap_live_and_pack_actionable_run`, `roadmap-live-evidence-cycle-batch-run`, and `roadmap-validation-debt-actionable-run`.

## Missing / Next
- Real-host evidence capture/publish remains the blocker for M2/M4/M5 closure.
EOF_HELPER_STATUS

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$HELPER_STATUS_DOC" \
  --reports-dir "$HELPER_REPORTS_DIR" \
  --summary-json "$HELPER_SUMMARY_JSON" \
  --print-summary-json 0 >"$HELPER_STDOUT"

assert_file_contains "$HELPER_STDOUT" "## In-Progress (1)" "helper fixture markdown missing in-progress count"
assert_file_contains "$HELPER_STDOUT" "## Missing / Next (1)" "helper fixture markdown missing missing/next count"
assert_file_contains "$HELPER_STDOUT" "1. Batch helper accelerators include \`roadmap_live_evidence_actionable_run\`, \`roadmap_evidence_pack_actionable_run\`, \`roadmap_live_and_pack_actionable_run\`, \`roadmap-live-evidence-cycle-batch-run\`, and \`roadmap-validation-debt-actionable-run\`." "helper fixture markdown missing helper text"
assert_file_contains "$HELPER_STDOUT" "1. Real-host evidence capture/publish remains the blocker for M2/M4/M5 closure." "helper fixture markdown missing blocker text"
assert_file_contains "$HELPER_SUMMARY_JSON" '"text": "Batch helper accelerators include `roadmap_live_evidence_actionable_run`, `roadmap_evidence_pack_actionable_run`, `roadmap_live_and_pack_actionable_run`, `roadmap-live-evidence-cycle-batch-run`, and `roadmap-validation-debt-actionable-run`."' "helper fixture summary missing helper text"
assert_file_contains "$HELPER_SUMMARY_JSON" '"text": "Real-host evidence capture/publish remains the blocker for M2/M4/M5 closure."' "helper fixture summary missing blocker text"
assert_file_contains "$HELPER_SUMMARY_JSON" '"blocked_by": ["real_hosts", "evidence_pack_artifacts"]' "helper fixture summary missing real-host/evidence blocker metadata"
assert_file_contains "$HELPER_SUMMARY_JSON" '"requires_real_hosts": true' "helper fixture summary missing real-host requirement metadata"
assert_file_contains "$HELPER_SUMMARY_JSON" '"suggested_files": ["docs/gpm-productization-status.md", "scripts/integration_3machine_prod_wg_validate.sh", "scripts/roadmap_progress_report.sh"]' "helper fixture summary missing real-host suggested files"

echo "[gpm-gap-scan] informational tooling notes are not promoted as blockers"
NOTE_STATUS_DOC="$TMP_DIR/note_status.md"
NOTE_SUMMARY_JSON="$TMP_DIR/note_summary.json"
NOTE_STDOUT="$TMP_DIR/note_stdout.md"

cat >"$NOTE_STATUS_DOC" <<'EOF_NOTE_STATUS'
# Tooling Note Fixture

## In-Progress
- Concrete in-progress blocker is missing live chain evidence.

## Missing / Next
- Tooling note: roadmap output now surfaces batch launchers to reduce manual invocation. These are accelerators only; they do not replace required real-host evidence capture/publish.
- Real-host evidence capture/publish remains the blocker for M2/M4/M5 closure.
EOF_NOTE_STATUS

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$NOTE_STATUS_DOC" \
  --summary-json "$NOTE_SUMMARY_JSON" \
  --print-summary-json 0 >"$NOTE_STDOUT"

assert_file_contains "$NOTE_SUMMARY_JSON" '"text": "Tooling note: roadmap output now surfaces batch launchers to reduce manual invocation. These are accelerators only; they do not replace required real-host evidence capture/publish."' "note fixture summary missing tooling note text"
assert_file_contains "$NOTE_SUMMARY_JSON" '"actionable": false' "note fixture summary should mark tooling note non-actionable"
assert_file_contains "$NOTE_SUMMARY_JSON" '"recommended_action": "No direct closure action; use this note as operator guidance for related roadmap blockers."' "note fixture summary missing informational action"
assert_file_contains "$NOTE_SUMMARY_JSON" '"blocked_by": []' "note fixture summary should not assign blockers to tooling note"
assert_file_contains "$NOTE_SUMMARY_JSON" '"requires_real_hosts": false' "note fixture summary should not require real hosts for tooling note"
if grep -A24 '"id": "missing_next_01"' "$NOTE_SUMMARY_JSON" | grep -F '"top_actionable_item_ids"' >/dev/null 2>&1; then
  echo "note fixture layout unexpectedly collapsed before item assertions"
  cat "$NOTE_SUMMARY_JSON"
  exit 1
fi
if grep -A80 '"top_actionable_item_ids": \[' "$NOTE_SUMMARY_JSON" | grep -F '"missing_next_01"' >/dev/null 2>&1; then
  echo "tooling note should not appear in top_actionable_item_ids"
  cat "$NOTE_SUMMARY_JSON"
  exit 1
fi
if ! grep -A80 '"top_actionable_item_ids": \[' "$NOTE_SUMMARY_JSON" | grep -F '"missing_next_02"' >/dev/null 2>&1; then
  echo "real blocker should remain in top_actionable_item_ids"
  cat "$NOTE_SUMMARY_JSON"
  exit 1
fi

GENERIC_NOTE_STATUS_DOC="$TMP_DIR/generic_note_status.md"
GENERIC_NOTE_SUMMARY_JSON="$TMP_DIR/generic_note_summary.json"
GENERIC_NOTE_STDOUT="$TMP_DIR/generic_note_stdout.md"

cat >"$GENERIC_NOTE_STATUS_DOC" <<'EOF_GENERIC_NOTE_STATUS'
# Generic Note Blocker Fixture

## In-Progress
- Note: live chain evidence is missing and remains a blocker for payout finality.

## Missing / Next
- Note: live chain evidence is missing and remains a blocker for payout finality.
EOF_GENERIC_NOTE_STATUS

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$GENERIC_NOTE_STATUS_DOC" \
  --summary-json "$GENERIC_NOTE_SUMMARY_JSON" \
  --print-summary-json 0 >"$GENERIC_NOTE_STDOUT"

assert_file_contains "$GENERIC_NOTE_SUMMARY_JSON" '"text": "Note: live chain evidence is missing and remains a blocker for payout finality."' "generic note fixture summary missing blocker note text"
assert_file_contains "$GENERIC_NOTE_SUMMARY_JSON" '"actionable": true' "generic note with blocker language should remain actionable"
if ! grep -A80 '"top_actionable_item_ids": \[' "$GENERIC_NOTE_SUMMARY_JSON" | grep -F '"missing_next_01"' >/dev/null 2>&1; then
  echo "generic blocker note should appear in top_actionable_item_ids"
  cat "$GENERIC_NOTE_SUMMARY_JSON"
  exit 1
fi

echo "[gpm-gap-scan] heading normalization + default summary path"
VARIANT_STATUS_DOC="$TMP_DIR/variant_status.md"
VARIANT_REPORTS_DIR="$TMP_DIR/variant_reports"
VARIANT_STDOUT="$TMP_DIR/variant_stdout.md"
VARIANT_SUMMARY_JSON="$VARIANT_REPORTS_DIR/gpm_gap_scan_summary.json"

cat >"$VARIANT_STATUS_DOC" <<'EOF_VARIANT_STATUS'
# GPM Status Variant Fixture

## In Progress
- Variant in-progress item.

## Missing/Next
- Variant missing-next item.
EOF_VARIANT_STATUS

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$VARIANT_STATUS_DOC" \
  --reports-dir "$VARIANT_REPORTS_DIR" \
  --print-summary-json 0 >"$VARIANT_STDOUT"

if [[ ! -s "$VARIANT_SUMMARY_JSON" ]]; then
  echo "expected default summary json at reports-dir path: $VARIANT_SUMMARY_JSON"
  ls -la "$VARIANT_REPORTS_DIR"
  exit 1
fi
assert_file_contains "$VARIANT_STDOUT" "## In-Progress (1)" "variant markdown missing in-progress count"
assert_file_contains "$VARIANT_STDOUT" "## Missing / Next (1)" "variant markdown missing missing/next count"
assert_file_matches_regex "$VARIANT_SUMMARY_JSON" '"in_progress"[[:space:]]*:[[:space:]]*1' "variant summary in_progress count mismatch"
assert_file_matches_regex "$VARIANT_SUMMARY_JSON" '"missing_next"[[:space:]]*:[[:space:]]*1' "variant summary missing_next count mismatch"
assert_file_matches_regex "$VARIANT_SUMMARY_JSON" '"total"[[:space:]]*:[[:space:]]*2' "variant summary total count mismatch"

echo "[gpm-gap-scan] robust heading parsing + blank-line continuations"
ROBUST_STATUS_DOC="$TMP_DIR/robust_status.md"
ROBUST_REPORTS_DIR="$TMP_DIR/robust_reports"
ROBUST_SUMMARY_JSON="$TMP_DIR/robust_summary.json"
ROBUST_STDOUT="$TMP_DIR/robust_stdout.md"

cat >"$ROBUST_STATUS_DOC" <<'EOF_ROBUST_STATUS'
# Robust GPM Status Fixture

##In-Progress##
- Robust in-progress first.
- Robust in-progress second

  continuation line should stay with same item.

  ## Missing / Next: ##
- Robust missing-next first.
- Robust missing-next second

  continuation line should stay with same item.
EOF_ROBUST_STATUS

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$ROBUST_STATUS_DOC" \
  --reports-dir "$ROBUST_REPORTS_DIR" \
  --summary-json "$ROBUST_SUMMARY_JSON" \
  --print-summary-json 0 >"$ROBUST_STDOUT"

assert_file_contains "$ROBUST_STDOUT" "## In-Progress (2)" "robust markdown missing in-progress count"
assert_file_contains "$ROBUST_STDOUT" "## Missing / Next (2)" "robust markdown missing missing/next count"
assert_file_contains "$ROBUST_STDOUT" "2. Robust in-progress second continuation line should stay with same item." "robust markdown missing blank-line continuation merge for in-progress"
assert_file_contains "$ROBUST_STDOUT" "2. Robust missing-next second continuation line should stay with same item." "robust markdown missing blank-line continuation merge for missing-next"
assert_file_contains "$ROBUST_SUMMARY_JSON" '"text": "Robust in-progress second continuation line should stay with same item."' "robust summary missing normalized in-progress continuation text"
assert_file_contains "$ROBUST_SUMMARY_JSON" '"text": "Robust missing-next second continuation line should stay with same item."' "robust summary missing normalized missing-next continuation text"
assert_file_matches_regex "$ROBUST_SUMMARY_JSON" '"in_progress"[[:space:]]*:[[:space:]]*2' "robust summary in_progress count mismatch"
assert_file_matches_regex "$ROBUST_SUMMARY_JSON" '"missing_next"[[:space:]]*:[[:space:]]*2' "robust summary missing_next count mismatch"

echo "[gpm-gap-scan] CRLF + BOM parsing"
CRLF_STATUS_DOC="$TMP_DIR/crlf_status.md"
CRLF_SUMMARY_JSON="$TMP_DIR/crlf_summary.json"
CRLF_STDOUT="$TMP_DIR/crlf_stdout.md"
printf '\xEF\xBB\xBF## In-Progress\r\n- CRLF in-progress item.\r\n\r\n## Missing / Next\r\n- CRLF missing-next item.\r\n' >"$CRLF_STATUS_DOC"

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$CRLF_STATUS_DOC" \
  --summary-json "$CRLF_SUMMARY_JSON" \
  --print-summary-json 0 >"$CRLF_STDOUT"

assert_file_contains "$CRLF_STDOUT" "## In-Progress (1)" "crlf markdown missing in-progress count"
assert_file_contains "$CRLF_STDOUT" "## Missing / Next (1)" "crlf markdown missing missing/next count"
assert_file_contains "$CRLF_STDOUT" "1. CRLF in-progress item." "crlf markdown missing in-progress item"
assert_file_contains "$CRLF_STDOUT" "1. CRLF missing-next item." "crlf markdown missing missing-next item"
assert_file_matches_regex "$CRLF_SUMMARY_JSON" '"in_progress"[[:space:]]*:[[:space:]]*1' "crlf summary in_progress count mismatch"
assert_file_matches_regex "$CRLF_SUMMARY_JSON" '"missing_next"[[:space:]]*:[[:space:]]*1' "crlf summary missing_next count mismatch"
assert_file_matches_regex "$CRLF_SUMMARY_JSON" '"total"[[:space:]]*:[[:space:]]*2' "crlf summary total count mismatch"

echo "[gpm-gap-scan] fail-closed when status doc is missing"
MISSING_DOC_SUMMARY_JSON="$TMP_DIR/missing_doc_summary.json"
MISSING_DOC_STDOUT="$TMP_DIR/missing_doc_stdout.log"
MISSING_DOC_STDERR="$TMP_DIR/missing_doc_stderr.log"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$TMP_DIR/does_not_exist.md" \
  --summary-json "$MISSING_DOC_SUMMARY_JSON" \
  --print-summary-json 0 >"$MISSING_DOC_STDOUT" 2>"$MISSING_DOC_STDERR"
missing_doc_rc=$?
set -e
if [[ "$missing_doc_rc" -eq 0 ]]; then
  echo "expected missing status doc to fail closed"
  cat "$MISSING_DOC_STDOUT"
  cat "$MISSING_DOC_STDERR"
  exit 1
fi
assert_file_contains "$MISSING_DOC_STDERR" "status doc missing:" "missing-doc failure stderr mismatch"
if [[ -e "$MISSING_DOC_SUMMARY_JSON" ]]; then
  echo "summary json should not be created for missing status doc path"
  cat "$MISSING_DOC_SUMMARY_JSON"
  exit 1
fi

echo "[gpm-gap-scan] fail-closed when required headings are malformed"
MALFORMED_STATUS_DOC="$TMP_DIR/malformed_status.md"
MALFORMED_SUMMARY_JSON="$TMP_DIR/malformed_summary.json"
MALFORMED_STDOUT="$TMP_DIR/malformed_stdout.log"
MALFORMED_STDERR="$TMP_DIR/malformed_stderr.log"

cat >"$MALFORMED_STATUS_DOC" <<'EOF_MALFORMED_STATUS'
# Malformed GPM Status Fixture

## In-Progress
- Item present under in-progress.
EOF_MALFORMED_STATUS

set +e
bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$MALFORMED_STATUS_DOC" \
  --summary-json "$MALFORMED_SUMMARY_JSON" \
  --print-summary-json 0 >"$MALFORMED_STDOUT" 2>"$MALFORMED_STDERR"
malformed_rc=$?
set -e
if [[ "$malformed_rc" -eq 0 ]]; then
  echo "expected malformed status doc to fail closed when heading is missing"
  cat "$MALFORMED_STDOUT"
  cat "$MALFORMED_STDERR"
  exit 1
fi
assert_file_contains "$MALFORMED_STDERR" "required heading not found: Missing / Next" "malformed heading failure stderr mismatch"
if [[ -e "$MALFORMED_SUMMARY_JSON" ]]; then
  echo "summary json should not be created for malformed heading input"
  cat "$MALFORMED_SUMMARY_JSON"
  exit 1
fi

echo "[gpm-gap-scan] --print-summary-json emits JSON to stdout"
PRINT_STATUS_DOC="$TMP_DIR/print_status.md"
PRINT_SUMMARY_JSON="$TMP_DIR/print_summary.json"
PRINT_STDOUT="$TMP_DIR/print_stdout.log"

cat >"$PRINT_STATUS_DOC" <<'EOF_PRINT_STATUS'
# Print JSON Fixture

## In-Progress
- Print-mode in-progress.

## Missing / Next
- Print-mode missing-next.
EOF_PRINT_STATUS

bash "$SCRIPT_UNDER_TEST" \
  --status-doc "$PRINT_STATUS_DOC" \
  --summary-json "$PRINT_SUMMARY_JSON" \
  --print-summary-json 1 >"$PRINT_STDOUT"

assert_file_contains "$PRINT_STDOUT" "## In-Progress (1)" "print-summary-json run missing markdown summary"
assert_file_contains "$PRINT_STDOUT" '"schema": {' "print-summary-json run missing JSON payload in stdout"
assert_file_contains "$PRINT_STDOUT" '"id": "gpm_gap_scan_summary"' "print-summary-json run missing schema id in stdout JSON"

echo "gpm gap scan integration ok"
