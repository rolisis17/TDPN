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
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"items": [' "summary JSON missing items key"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"id": "in_progress_01"' "summary JSON missing in_progress item id"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"id": "missing_next_02"' "summary JSON missing missing_next item id"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"section": "in_progress"' "summary JSON missing in_progress section key"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"section": "missing_next"' "summary JSON missing missing_next section key"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"text": "In progress two with continuation context."' "summary JSON missing normalized wrapped text"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"severity": "p2"' "summary JSON missing expected in-progress severity classification"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"severity": "p1"' "summary JSON missing expected missing/next severity classification"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"recommended_action": "' "summary JSON missing recommended_action field"
assert_file_contains "$PRIMARY_SUMMARY_JSON" '"top_actionable_item_ids": [' "summary JSON missing top_actionable_item_ids field"

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
assert_file_matches_regex "$ROADMAP_SUMMARY_JSON" '"missing_next"[[:space:]]*:[[:space:]]*7' "roadmap-aware missing_next count mismatch"
assert_file_matches_regex "$ROADMAP_SUMMARY_JSON" '"total"[[:space:]]*:[[:space:]]*8' "roadmap-aware total count mismatch"
assert_file_contains "$ROADMAP_SUMMARY_JSON" 'Roadmap profile-default gate next action has unresolved placeholders (invite_key)' "roadmap-aware summary missing profile placeholder blocker"
assert_file_contains "$ROADMAP_SUMMARY_JSON" 'Roadmap multi-VM stability command source is not actionable' "roadmap-aware summary missing multi-vm blocker"
assert_file_contains "$ROADMAP_SUMMARY_JSON" 'Roadmap runtime-actuation promotion is not green' "roadmap-aware summary missing runtime promotion blocker"
assert_file_contains "$ROADMAP_SUMMARY_JSON" 'Roadmap evidence pack profile_default_gate_evidence_pack needs attention' "roadmap-aware summary missing profile evidence-pack blocker"
assert_file_contains "$ROADMAP_STDOUT" "## Missing / Next (7)" "roadmap-aware markdown missing expanded missing/next count"

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
