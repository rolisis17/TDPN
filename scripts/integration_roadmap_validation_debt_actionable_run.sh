#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod mkdir cat grep wc; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

mkdir -p "$ROOT_DIR/.easy-node-logs"
TMP_DIR="$(mktemp -d "$ROOT_DIR/.easy-node-logs/integration_roadmap_validation_debt_actionable_run_XXXXXX")"
ACTION_TMP_DIR="$(mktemp -d "$ROOT_DIR/scripts/.integration_roadmap_validation_debt_actionable_run.XXXXXX")"
trap 'rm -rf "$TMP_DIR" "$ACTION_TMP_DIR"' EXIT

SCRIPT_UNDER_TEST="${ROADMAP_VALIDATION_DEBT_ACTIONABLE_RUN_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/roadmap_validation_debt_actionable_run.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

EXEC_LOG="$TMP_DIR/executed_checks.log"
PASS_CLIENT="$ACTION_TMP_DIR/pass_client_3hop_runtime.sh"
PASS_ROADMAP="$ACTION_TMP_DIR/pass_roadmap_progress_report.sh"
PASS_MICRO="$ACTION_TMP_DIR/pass_micro_relay_operator_floor.sh"
PASS_M3_PACK="$ACTION_TMP_DIR/pass_m3_three_machine_real_host_validation_pack.sh"
FAIL_ROADMAP="$ACTION_TMP_DIR/fail_roadmap_progress_report.sh"

cat >"$PASS_CLIENT" <<EOF_PASS_CLIENT
#!/usr/bin/env bash
set -euo pipefail
echo "m1_client_3hop_runtime" >>"$EXEC_LOG"
echo "pass client 3hop runtime"
EOF_PASS_CLIENT
chmod +x "$PASS_CLIENT"

cat >"$PASS_ROADMAP" <<EOF_PASS_ROADMAP
#!/usr/bin/env bash
set -euo pipefail
echo "m1_roadmap_progress_report_contract" >>"$EXEC_LOG"
echo "pass roadmap progress report"
EOF_PASS_ROADMAP
chmod +x "$PASS_ROADMAP"

cat >"$PASS_MICRO" <<EOF_PASS_MICRO
#!/usr/bin/env bash
set -euo pipefail
echo "m3_micro_relay_operator_floor" >>"$EXEC_LOG"
echo "pass micro relay operator floor"
EOF_PASS_MICRO
chmod +x "$PASS_MICRO"

cat >"$PASS_M3_PACK" <<EOF_PASS_M3_PACK
#!/usr/bin/env bash
set -euo pipefail
echo "m3_three_machine_real_host_validation_pack" >>"$EXEC_LOG"
echo "pass m3 three-machine real-host validation pack"
EOF_PASS_M3_PACK
chmod +x "$PASS_M3_PACK"

cat >"$FAIL_ROADMAP" <<EOF_FAIL_ROADMAP
#!/usr/bin/env bash
set -euo pipefail
echo "m1_roadmap_progress_report_contract" >>"$EXEC_LOG"
echo "fail roadmap progress report"
exit 17
EOF_FAIL_ROADMAP
chmod +x "$FAIL_ROADMAP"

echo "[roadmap-validation-debt-actionable-run] help contract"
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--reports-dir DIR" >/dev/null; then
  echo "help output missing --reports-dir DIR"
  exit 1
fi
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--summary-json PATH" >/dev/null; then
  echo "help output missing --summary-json PATH"
  exit 1
fi
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--parallel [0|1]" >/dev/null; then
  echo "help output missing --parallel [0|1]"
  exit 1
fi
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--max-actions N" >/dev/null; then
  echo "help output missing --max-actions N"
  exit 1
fi
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--include-id ID" >/dev/null; then
  echo "help output missing --include-id ID"
  exit 1
fi
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--exclude-id ID" >/dev/null; then
  echo "help output missing --exclude-id ID"
  exit 1
fi
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--print-summary-json [0|1]" >/dev/null; then
  echo "help output missing --print-summary-json [0|1]"
  exit 1
fi

echo "[roadmap-validation-debt-actionable-run] success path"
SUMMARY_SUCCESS="$TMP_DIR/summary_success.json"
REPORTS_SUCCESS="$TMP_DIR/reports_success"
: >"$EXEC_LOG"
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_CLIENT_3HOP_RUNTIME_SCRIPT="$PASS_CLIENT" \
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_ROADMAP_PROGRESS_REPORT_SCRIPT="$PASS_ROADMAP" \
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_MICRO_RELAY_OPERATOR_FLOOR_SCRIPT="$PASS_MICRO" \
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_THREE_MACHINE_REAL_HOST_VALIDATION_PACK_SCRIPT="$PASS_M3_PACK" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$REPORTS_SUCCESS" \
  --summary-json "$SUMMARY_SUCCESS" \
  --print-summary-json 0

if ! jq -e '
  .version == 1
  and .schema.id == "roadmap_validation_debt_actionable_run_summary"
  and .status == "pass"
  and .rc == 0
  and .selection_error_rc == null
  and .selection_error == null
  and .stages.selection.status == "pass"
  and .stages.execution.status == "pass"
  and ([.checks_catalog[].id] == ["m1_client_3hop_runtime","m1_roadmap_progress_report_contract","m3_micro_relay_operator_floor","m3_three_machine_real_host_validation_pack"])
  and .inputs.parallel == false
  and .inputs.max_actions == 0
  and .checks_selected_count == 4
  and .checks_selected_ids == ["m1_client_3hop_runtime","m1_roadmap_progress_report_contract","m3_micro_relay_operator_floor","m3_three_machine_real_host_validation_pack"]
  and .selection_accounting.default_count == 4
  and .selection_accounting.include_ids_requested_count == 0
  and .selection_accounting.include_ids_unique_count == 0
  and .selection_accounting.exclude_ids_requested_count == 0
  and .selection_accounting.exclude_ids_unique_count == 0
  and .selection_accounting.include_filter_applied == false
  and .selection_accounting.exclude_filter_applied == false
  and .selection_accounting.after_include_count == 4
  and .selection_accounting.after_exclude_count == 4
  and .selection_accounting.after_max_actions_count == 4
  and .selection_accounting.before_dedupe_count == 4
  and .selection_accounting.deduped_duplicate_count == 0
  and .selection_accounting.after_dedupe_count == 4
  and .selection_accounting.unknown_include_ids == []
  and .selection_accounting.unknown_exclude_ids == []
  and .selection_accounting.conflicting_duplicate_check_ids == []
  and .summary.checks_executed == 4
  and .summary.pass == 4
  and .summary.fail == 0
  and ((.checks // []) | length == 4)
  and ([.checks[].id] == ["m1_client_3hop_runtime","m1_roadmap_progress_report_contract","m3_micro_relay_operator_floor","m3_three_machine_real_host_validation_pack"])
  and ((.checks // []) | all(.status == "pass"))
  and ((.checks // []) | all(.rc == 0))
' "$SUMMARY_SUCCESS" >/dev/null; then
  echo "success-path summary mismatch"
  cat "$SUMMARY_SUCCESS"
  exit 1
fi

if [[ "$(wc -l <"$EXEC_LOG" | tr -d '[:space:]')" != "4" ]]; then
  echo "expected four executed checks in success path"
  cat "$EXEC_LOG"
  exit 1
fi
mapfile -t success_exec_order <"$EXEC_LOG"
if [[ "${success_exec_order[0]:-}" != "m1_client_3hop_runtime" || "${success_exec_order[1]:-}" != "m1_roadmap_progress_report_contract" || "${success_exec_order[2]:-}" != "m3_micro_relay_operator_floor" || "${success_exec_order[3]:-}" != "m3_three_machine_real_host_validation_pack" ]]; then
  echo "unexpected success-path execution order"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-validation-debt-actionable-run] no-selected-checks fail-closed path"
SUMMARY_NO_SELECTION="$TMP_DIR/summary_no_selection.json"
REPORTS_NO_SELECTION="$TMP_DIR/reports_no_selection"
: >"$EXEC_LOG"
set +e
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_CLIENT_3HOP_RUNTIME_SCRIPT="$PASS_CLIENT" \
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_ROADMAP_PROGRESS_REPORT_SCRIPT="$PASS_ROADMAP" \
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_MICRO_RELAY_OPERATOR_FLOOR_SCRIPT="$PASS_MICRO" \
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_THREE_MACHINE_REAL_HOST_VALIDATION_PACK_SCRIPT="$PASS_M3_PACK" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$REPORTS_NO_SELECTION" \
  --summary-json "$SUMMARY_NO_SELECTION" \
  --include-id m1_client_3hop_runtime \
  --exclude-id m1_client_3hop_runtime \
  --print-summary-json 0
no_selection_rc=$?
set -e

if [[ "$no_selection_rc" != "1" ]]; then
  echo "expected no-selection fail-closed rc=1, got rc=$no_selection_rc"
  cat "$SUMMARY_NO_SELECTION"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .selection_error_rc == 1
  and .selection_error == "no_checks_selected"
  and .stages.selection.status == "fail"
  and .stages.selection.reason == "no_checks_selected"
  and .stages.execution.status == "skip_due_to_selection_error"
  and .checks_selected_count == 0
  and .checks_selected_ids == []
  and .summary.checks_executed == 0
  and .summary.pass == 0
  and .summary.fail == 0
  and ((.checks // []) | length == 0)
' "$SUMMARY_NO_SELECTION" >/dev/null; then
  echo "no-selection fail-closed summary mismatch"
  cat "$SUMMARY_NO_SELECTION"
  exit 1
fi

if [[ "$(wc -l <"$EXEC_LOG" | tr -d '[:space:]')" != "0" ]]; then
  echo "expected zero executed checks in no-selection path"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-validation-debt-actionable-run] unknown-id fail-closed path"
SUMMARY_UNKNOWN_IDS="$TMP_DIR/summary_unknown_ids.json"
REPORTS_UNKNOWN_IDS="$TMP_DIR/reports_unknown_ids"
: >"$EXEC_LOG"
set +e
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_CLIENT_3HOP_RUNTIME_SCRIPT="$PASS_CLIENT" \
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_ROADMAP_PROGRESS_REPORT_SCRIPT="$PASS_ROADMAP" \
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_MICRO_RELAY_OPERATOR_FLOOR_SCRIPT="$PASS_MICRO" \
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_THREE_MACHINE_REAL_HOST_VALIDATION_PACK_SCRIPT="$PASS_M3_PACK" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$REPORTS_UNKNOWN_IDS" \
  --summary-json "$SUMMARY_UNKNOWN_IDS" \
  --include-id unknown_check_id \
  --exclude-id another_unknown_check \
  --print-summary-json 0
unknown_ids_rc=$?
set -e

if [[ "$unknown_ids_rc" != "3" ]]; then
  echo "expected unknown-id fail-closed rc=3, got rc=$unknown_ids_rc"
  cat "$SUMMARY_UNKNOWN_IDS"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 3
  and .selection_error_rc == 3
  and .selection_error == "unknown_check_ids"
  and .stages.selection.status == "fail"
  and .stages.selection.reason == "unknown_check_ids"
  and .stages.execution.status == "skip_due_to_selection_error"
  and .selection_accounting.unknown_include_ids == ["unknown_check_id"]
  and .selection_accounting.unknown_exclude_ids == ["another_unknown_check"]
  and .summary.checks_executed == 0
  and ((.checks // []) | length == 0)
' "$SUMMARY_UNKNOWN_IDS" >/dev/null; then
  echo "unknown-id fail-closed summary mismatch"
  cat "$SUMMARY_UNKNOWN_IDS"
  exit 1
fi

if [[ "$(wc -l <"$EXEC_LOG" | tr -d '[:space:]')" != "0" ]]; then
  echo "expected zero executed checks in unknown-id path"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-validation-debt-actionable-run] filtered path (include/exclude/max-actions)"
SUMMARY_FILTERED="$TMP_DIR/summary_filtered.json"
REPORTS_FILTERED="$TMP_DIR/reports_filtered"
: >"$EXEC_LOG"
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_CLIENT_3HOP_RUNTIME_SCRIPT="$PASS_CLIENT" \
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_ROADMAP_PROGRESS_REPORT_SCRIPT="$PASS_ROADMAP" \
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_MICRO_RELAY_OPERATOR_FLOOR_SCRIPT="$PASS_MICRO" \
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_THREE_MACHINE_REAL_HOST_VALIDATION_PACK_SCRIPT="$PASS_M3_PACK" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$REPORTS_FILTERED" \
  --summary-json "$SUMMARY_FILTERED" \
  --include-id m1_client_3hop_runtime \
  --include-id m3_micro_relay_operator_floor \
  --include-id m3_three_machine_real_host_validation_pack \
  --exclude-id m1_client_3hop_runtime \
  --max-actions 1 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .selection_error == null
  and .inputs.include_ids == ["m1_client_3hop_runtime","m3_micro_relay_operator_floor","m3_three_machine_real_host_validation_pack"]
  and .inputs.exclude_ids == ["m1_client_3hop_runtime"]
  and .inputs.max_actions == 1
  and .checks_selected_count == 1
  and .checks_selected_ids == ["m3_micro_relay_operator_floor"]
  and .selection_accounting.include_filter_applied == true
  and .selection_accounting.exclude_filter_applied == true
  and .selection_accounting.after_include_count == 3
  and .selection_accounting.after_exclude_count == 2
  and .selection_accounting.after_max_actions_count == 1
  and .summary.checks_executed == 1
  and .summary.pass == 1
  and .summary.fail == 0
  and ((.checks // []) | length == 1)
  and .checks[0].id == "m3_micro_relay_operator_floor"
  and .checks[0].status == "pass"
  and .checks[0].rc == 0
' "$SUMMARY_FILTERED" >/dev/null; then
  echo "filtered-path summary mismatch"
  cat "$SUMMARY_FILTERED"
  exit 1
fi

if [[ "$(wc -l <"$EXEC_LOG" | tr -d '[:space:]')" != "1" ]]; then
  echo "expected one executed check in filtered path"
  cat "$EXEC_LOG"
  exit 1
fi
if ! grep -Fx "m3_micro_relay_operator_floor" "$EXEC_LOG" >/dev/null; then
  echo "filtered path executed unexpected check"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-validation-debt-actionable-run] fail path (parallel mode)"
SUMMARY_FAIL="$TMP_DIR/summary_fail.json"
REPORTS_FAIL="$TMP_DIR/reports_fail"
: >"$EXEC_LOG"
set +e
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_CLIENT_3HOP_RUNTIME_SCRIPT="$PASS_CLIENT" \
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_ROADMAP_PROGRESS_REPORT_SCRIPT="$FAIL_ROADMAP" \
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_MICRO_RELAY_OPERATOR_FLOOR_SCRIPT="$PASS_MICRO" \
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CHECK_THREE_MACHINE_REAL_HOST_VALIDATION_PACK_SCRIPT="$PASS_M3_PACK" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$REPORTS_FAIL" \
  --summary-json "$SUMMARY_FAIL" \
  --parallel 1 \
  --print-summary-json 0
fail_rc=$?
set -e

if [[ "$fail_rc" != "17" ]]; then
  echo "expected fail path rc=17, got rc=$fail_rc"
  cat "$SUMMARY_FAIL"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 17
  and .selection_error == null
  and .inputs.parallel == true
  and .checks_selected_count == 4
  and .checks_selected_ids == ["m1_client_3hop_runtime","m1_roadmap_progress_report_contract","m3_micro_relay_operator_floor","m3_three_machine_real_host_validation_pack"]
  and .summary.checks_executed == 4
  and .summary.pass == 3
  and .summary.fail == 1
  and ((.checks // []) | length == 4)
  and .checks[0].id == "m1_client_3hop_runtime"
  and .checks[0].status == "pass"
  and .checks[1].id == "m1_roadmap_progress_report_contract"
  and .checks[1].status == "fail"
  and .checks[1].rc == 17
  and .checks[2].id == "m3_micro_relay_operator_floor"
  and .checks[2].status == "pass"
  and .checks[3].id == "m3_three_machine_real_host_validation_pack"
  and .checks[3].status == "pass"
' "$SUMMARY_FAIL" >/dev/null; then
  echo "fail-path summary mismatch"
  cat "$SUMMARY_FAIL"
  exit 1
fi

if [[ "$(wc -l <"$EXEC_LOG" | tr -d '[:space:]')" != "4" ]]; then
  echo "expected four executed checks in fail path"
  cat "$EXEC_LOG"
  exit 1
fi
if [[ "$(grep -c '^m1_client_3hop_runtime$' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "missing/duplicate client runtime execution marker in fail path"
  cat "$EXEC_LOG"
  exit 1
fi
if [[ "$(grep -c '^m1_roadmap_progress_report_contract$' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "missing/duplicate roadmap contract execution marker in fail path"
  cat "$EXEC_LOG"
  exit 1
fi
if [[ "$(grep -c '^m3_micro_relay_operator_floor$' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "missing/duplicate micro-relay execution marker in fail path"
  cat "$EXEC_LOG"
  exit 1
fi
if [[ "$(grep -c '^m3_three_machine_real_host_validation_pack$' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "missing/duplicate m3 validation-pack execution marker in fail path"
  cat "$EXEC_LOG"
  exit 1
fi

echo "roadmap validation debt actionable run integration check ok"
