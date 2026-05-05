#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod cat grep tr timeout mkdir; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${GPM_LOGIC_CHECK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/gpm_logic_check.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi
if [[ ! -r "$SCRIPT_UNDER_TEST" ]]; then
  echo "script under test is not readable: $SCRIPT_UNDER_TEST"
  exit 2
fi

mkdir -p "$ROOT_DIR/.easy-node-logs"
TMP_DIR="$(mktemp -d "$ROOT_DIR/.easy-node-logs/integration_gpm_logic_check_XXXXXX")"
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

assert_jq_true() {
  local file_path="$1"
  local jq_filter="$2"
  local message="$3"
  if ! jq -e "$jq_filter" "$file_path" >/dev/null 2>&1; then
    echo "$message"
    cat "$file_path"
    exit 1
  fi
}

PASS_A="$TMP_DIR/pass_a.sh"
PASS_B="$TMP_DIR/pass_b.sh"
PASS_C="$TMP_DIR/pass_c.sh"
FAIL_5="$TMP_DIR/fail_5.sh"
FAIL_7="$TMP_DIR/fail_7.sh"
HANG_30="$TMP_DIR/hang_30.sh"
EMPTY_CHECK="$TMP_DIR/empty_check.sh"

cat >"$PASS_A" <<'EOF_PASS_A'
#!/usr/bin/env bash
set -euo pipefail
echo "pass check a"
EOF_PASS_A
chmod +x "$PASS_A"

cat >"$PASS_B" <<'EOF_PASS_B'
#!/usr/bin/env bash
set -euo pipefail
echo "pass check b"
EOF_PASS_B
chmod +x "$PASS_B"

cat >"$PASS_C" <<'EOF_PASS_C'
#!/usr/bin/env bash
set -euo pipefail
echo "pass check c"
EOF_PASS_C
chmod +x "$PASS_C"

cat >"$FAIL_5" <<'EOF_FAIL_5'
#!/usr/bin/env bash
set -euo pipefail
echo "fail check 5"
exit 5
EOF_FAIL_5
chmod +x "$FAIL_5"

cat >"$FAIL_7" <<'EOF_FAIL_7'
#!/usr/bin/env bash
set -euo pipefail
echo "fail check 7"
exit 7
EOF_FAIL_7
chmod +x "$FAIL_7"

cat >"$HANG_30" <<'EOF_HANG_30'
#!/usr/bin/env bash
set -euo pipefail
echo "hang check start"
sleep 30
echo "hang check end"
EOF_HANG_30
chmod +x "$HANG_30"

mapfile -t DEFAULT_EXCLUDES < <(
  bash "$SCRIPT_UNDER_TEST" --print-default-checks 1 \
    | tr -d '\r' \
    | grep -E -v '^[[:space:]]*$'
)
if [[ "${#DEFAULT_EXCLUDES[@]}" -eq 0 ]]; then
  echo "expected --print-default-checks to return at least one default check"
  exit 1
fi
declare -a REQUIRED_DEFAULT_CHECKS=(
  "scripts/integration_roadmap_next_actions_run.sh"
  "scripts/integration_roadmap_non_blockchain_actionable_run.sh"
  "scripts/integration_roadmap_progress_report.sh"
  "scripts/integration_vpn_non_blockchain_fastlane.sh"
  "scripts/integration_roadmap_blockchain_actionable_run.sh"
  "scripts/integration_blockchain_fastlane.sh"
  "scripts/integration_roadmap_evidence_pack_actionable_run.sh"
  "scripts/integration_roadmap_live_evidence_actionable_run.sh"
  "scripts/integration_roadmap_live_evidence_cycle_batch_run.sh"
  "scripts/integration_roadmap_live_evidence_archive_run.sh"
  "scripts/integration_easy_node_roadmap_live_evidence_archive_run.sh"
  "scripts/integration_roadmap_live_and_pack_actionable_run.sh"
  "scripts/integration_three_machine_real_host_validation_pack.sh"
  "scripts/integration_easy_node_three_machine_real_host_validation_pack.sh"
  "scripts/integration_roadmap_validation_debt_actionable_run.sh"
)
if [[ "${#DEFAULT_EXCLUDES[@]}" -ne "${#REQUIRED_DEFAULT_CHECKS[@]}" ]]; then
  echo "default check count mismatch from --print-default-checks output: expected=${#REQUIRED_DEFAULT_CHECKS[@]} actual=${#DEFAULT_EXCLUDES[@]}"
  printf 'default checks were:\n'
  printf '  %s\n' "${DEFAULT_EXCLUDES[@]}"
  exit 1
fi
for idx in "${!REQUIRED_DEFAULT_CHECKS[@]}"; do
  expected_default="${REQUIRED_DEFAULT_CHECKS[$idx]}"
  actual_default="${DEFAULT_EXCLUDES[$idx]}"
  if [[ "$actual_default" != "$expected_default" ]]; then
    echo "default check order mismatch at index $idx: expected=$expected_default actual=$actual_default"
    printf 'default checks were:\n'
    printf '  %s\n' "${DEFAULT_EXCLUDES[@]}"
    exit 1
  fi
done
DEFAULT_EXCLUDES_JSON="$(jq -n '$ARGS.positional' --args "${DEFAULT_EXCLUDES[@]}")"

echo "[gpm-logic-check] all-pass summary aggregation"
PASS_REPORTS="$TMP_DIR/reports_pass"
PASS_SUMMARY="$TMP_DIR/summary_pass.json"
PASS_STDOUT="$TMP_DIR/pass_stdout.log"
pass_cmd=(
  bash "$SCRIPT_UNDER_TEST"
  --reports-dir "$PASS_REPORTS"
  --summary-json "$PASS_SUMMARY"
  --print-summary-json 0
  --include-check "$PASS_A"
  --include-check "$PASS_B"
)
for exclude_script in "${DEFAULT_EXCLUDES[@]}"; do
  pass_cmd+=(--exclude-check "$exclude_script")
done

set +e
"${pass_cmd[@]}" >"$PASS_STDOUT" 2>&1
pass_rc=$?
set -e
if [[ "$pass_rc" -ne 0 ]]; then
  echo "expected all-pass run to exit 0, got rc=$pass_rc"
  cat "$PASS_STDOUT"
  exit 1
fi

assert_jq_true "$PASS_SUMMARY" '
  .status == "pass"
  and .rc == 0
  and .selection_error == null
  and .invariant_error == null
  and .checks_selected == 2
  and .checks_executed == 2
  and .checks_skipped == 0
  and .checks_skipped == (.checks_selected - .checks_executed)
  and .checks_selected >= .checks_executed
  and .checks_passed == 2
  and .checks_failed == 0
  and (.checks_passed + .checks_failed == .checks_executed)
  and (.checks_executed <= .checks_selected)
  and ((.checks // []) | length == 2)
  and ((.selected_checks // []) | length == 2)
  and ((.selected_checks | unique | length) == (.selected_checks | length))
  and (((.checks | map(.path) | unique) | length) == ((.checks | map(.path)) | length))
  and ([.checks[].name] == ["pass_a.sh", "pass_b.sh"])
  and (all(.checks[]; has("status") and has("rc") and has("duration_sec") and has("log_path")))
  and (all(.checks[]; ((.status == "pass" and .rc == 0) or (.status == "fail" and .rc != 0))))
  and (all(.checks[]; (.duration_sec | type) == "number" and .duration_sec >= 0))
' "all-pass summary fields mismatch"
if ! jq -e --argjson expected_defaults "$DEFAULT_EXCLUDES_JSON" '
  .inputs.default_checks_rel == $expected_defaults
  and (.inputs.default_checks_present == .default_checks_present)
' "$PASS_SUMMARY" >/dev/null 2>&1; then
  echo "default checks source/order/content mismatch between list source and summary inputs"
  cat "$PASS_SUMMARY"
  exit 1
fi

mapfile -t pass_logs < <(jq -r '.checks[].log_path' "$PASS_SUMMARY" | tr -d '\r')
if [[ "${#pass_logs[@]}" -ne 2 ]]; then
  echo "expected 2 pass logs, got ${#pass_logs[@]}"
  cat "$PASS_SUMMARY"
  exit 1
fi
if [[ ! -f "${pass_logs[0]}" || ! -f "${pass_logs[1]}" ]]; then
  echo "missing pass log artifact"
  cat "$PASS_SUMMARY"
  exit 1
fi
assert_file_contains "${pass_logs[0]}" "pass check a" "first pass log missing expected output"
assert_file_contains "${pass_logs[1]}" "pass check b" "second pass log missing expected output"

echo "[gpm-logic-check] fail aggregation without fail-fast"
FAIL_REPORTS="$TMP_DIR/reports_fail"
FAIL_SUMMARY="$TMP_DIR/summary_fail.json"
FAIL_STDOUT="$TMP_DIR/fail_stdout.log"
fail_cmd=(
  bash "$SCRIPT_UNDER_TEST"
  --reports-dir "$FAIL_REPORTS"
  --summary-json "$FAIL_SUMMARY"
  --print-summary-json 0
  --fail-fast 0
  --include-check "$PASS_A"
  --include-check "$FAIL_7"
  --include-check "$PASS_C"
)
for exclude_script in "${DEFAULT_EXCLUDES[@]}"; do
  fail_cmd+=(--exclude-check "$exclude_script")
done

set +e
"${fail_cmd[@]}" >"$FAIL_STDOUT" 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 7 ]]; then
  echo "expected fail aggregation run to exit 7, got rc=$fail_rc"
  cat "$FAIL_STDOUT"
  exit 1
fi

assert_jq_true "$FAIL_SUMMARY" '
  .status == "fail"
  and .rc == 7
  and .selection_error == null
  and .invariant_error == null
  and .inputs.fail_fast == false
  and .checks_selected == 3
  and .checks_executed == 3
  and .checks_skipped == 0
  and .checks_skipped == (.checks_selected - .checks_executed)
  and .checks_selected >= .checks_executed
  and .checks_passed == 2
  and .checks_failed == 1
  and (.checks_passed + .checks_failed == .checks_executed)
  and (.checks_executed <= .checks_selected)
  and ((.checks // []) | length == 3)
  and ((.selected_checks | unique | length) == (.selected_checks | length))
  and (((.checks | map(.path) | unique) | length) == ((.checks | map(.path)) | length))
  and .checks[0].status == "pass"
  and .checks[0].rc == 0
  and .checks[1].status == "fail"
  and .checks[1].rc == 7
  and ([.checks[] | select(.status == "fail") | .rc][0] == .rc)
  and .checks[2].status == "pass"
  and .checks[2].rc == 0
  and (all(.checks[]; has("status") and has("rc") and has("duration_sec") and has("log_path")))
  and (all(.checks[]; ((.status == "pass" and .rc == 0) or (.status == "fail" and .rc != 0))))
  and (all(.checks[]; (.duration_sec | type) == "number" and .duration_sec >= 0))
' "fail aggregation summary fields mismatch"

fail_log="$(jq -r '.checks[1].log_path' "$FAIL_SUMMARY" | tr -d '\r')"
if [[ ! -f "$fail_log" ]]; then
  echo "missing fail log artifact: $fail_log"
  cat "$FAIL_SUMMARY"
  exit 1
fi
assert_file_contains "$fail_log" "fail check 7" "fail log missing expected output"

echo "[gpm-logic-check] fail-fast short-circuit"
FAST_REPORTS="$TMP_DIR/reports_fail_fast"
FAST_SUMMARY="$TMP_DIR/summary_fail_fast.json"
FAST_STDOUT="$TMP_DIR/fail_fast_stdout.log"
fast_cmd=(
  bash "$SCRIPT_UNDER_TEST"
  --reports-dir "$FAST_REPORTS"
  --summary-json "$FAST_SUMMARY"
  --print-summary-json 0
  --fail-fast 1
  --include-check "$FAIL_5"
  --include-check "$PASS_A"
)
for exclude_script in "${DEFAULT_EXCLUDES[@]}"; do
  fast_cmd+=(--exclude-check "$exclude_script")
done

set +e
"${fast_cmd[@]}" >"$FAST_STDOUT" 2>&1
fast_rc=$?
set -e
if [[ "$fast_rc" -ne 5 ]]; then
  echo "expected fail-fast run to exit 5, got rc=$fast_rc"
  cat "$FAST_STDOUT"
  exit 1
fi

assert_jq_true "$FAST_SUMMARY" '
  .status == "fail"
  and .rc == 5
  and .selection_error == null
  and .invariant_error == null
  and .inputs.fail_fast == true
  and .checks_selected == 2
  and .checks_executed == 1
  and .checks_skipped == 1
  and .checks_skipped == (.checks_selected - .checks_executed)
  and .checks_selected >= .checks_executed
  and .checks_passed == 0
  and .checks_failed == 1
  and (.checks_passed + .checks_failed == .checks_executed)
  and (.checks_executed <= .checks_selected)
  and ((.checks // []) | length == 1)
  and ((.selected_checks | unique | length) == (.selected_checks | length))
  and (((.checks | map(.path) | unique) | length) == ((.checks | map(.path)) | length))
  and .checks[0].status == "fail"
  and .checks[0].rc == 5
  and ([.checks[] | select(.status == "fail") | .rc][0] == .rc)
  and (all(.checks[]; has("status") and has("rc") and has("duration_sec") and has("log_path")))
  and (all(.checks[]; ((.status == "pass" and .rc == 0) or (.status == "fail" and .rc != 0))))
  and (all(.checks[]; (.duration_sec | type) == "number" and .duration_sec >= 0))
' "fail-fast summary fields mismatch"

fast_log="$(jq -r '.checks[0].log_path' "$FAST_SUMMARY" | tr -d '\r')"
if [[ ! -f "$fast_log" ]]; then
  echo "missing fail-fast log artifact: $fast_log"
  cat "$FAST_SUMMARY"
  exit 1
fi
assert_file_contains "$fast_log" "fail check 5" "fail-fast log missing expected output"

echo "[gpm-logic-check] timeout guard with heartbeat progress"
TIMEOUT_REPORTS="$TMP_DIR/reports_timeout"
TIMEOUT_SUMMARY="$TMP_DIR/summary_timeout.json"
TIMEOUT_STDOUT="$TMP_DIR/timeout_stdout.log"
timeout_cmd=(
  bash "$SCRIPT_UNDER_TEST"
  --reports-dir "$TIMEOUT_REPORTS"
  --summary-json "$TIMEOUT_SUMMARY"
  --print-summary-json 0
  --fail-fast 1
  --check-timeout-sec 2
  --progress-interval-sec 1
  --include-check "$HANG_30"
  --include-check "$PASS_A"
)
for exclude_script in "${DEFAULT_EXCLUDES[@]}"; do
  timeout_cmd+=(--exclude-check "$exclude_script")
done

set +e
"${timeout_cmd[@]}" >"$TIMEOUT_STDOUT" 2>&1
timeout_rc=$?
set -e
if [[ "$timeout_rc" -ne 124 && "$timeout_rc" -ne 137 ]]; then
  echo "expected timeout-guard run to exit 124 or 137, got rc=$timeout_rc"
  cat "$TIMEOUT_STDOUT"
  exit 1
fi

assert_jq_true "$TIMEOUT_SUMMARY" '
  .status == "fail"
  and (.rc == 124 or .rc == 137)
  and .selection_error == null
  and .invariant_error == null
  and .inputs.fail_fast == true
  and .inputs.check_timeout_sec == 2
  and .inputs.progress_interval_sec == 1
  and .checks_selected == 2
  and .checks_executed == 1
  and .checks_skipped == 1
  and .checks_skipped == (.checks_selected - .checks_executed)
  and .checks_selected >= .checks_executed
  and .checks_passed == 0
  and .checks_failed == 1
  and (.checks_passed + .checks_failed == .checks_executed)
  and (.checks_executed <= .checks_selected)
  and ((.checks // []) | length == 1)
  and ((.selected_checks | unique | length) == (.selected_checks | length))
  and (((.checks | map(.path) | unique) | length) == ((.checks | map(.path)) | length))
  and .checks[0].status == "fail"
  and (.checks[0].rc == 124 or .checks[0].rc == 137)
  and (.checks[0].rc == .rc)
  and .checks[0].timed_out == true
  and ([.checks[] | select(.status == "fail") | .rc][0] == .rc)
  and (all(.checks[]; has("status") and has("rc") and has("timed_out") and has("duration_sec") and has("log_path")))
  and (all(.checks[]; ((.status == "pass" and .rc == 0) or (.status == "fail" and .rc != 0))))
  and (all(.checks[]; (.duration_sec | type) == "number" and .duration_sec >= 0))
' "timeout guard summary fields mismatch"

assert_file_contains "$TIMEOUT_STDOUT" "status=running elapsed_sec=" "timeout run did not emit heartbeat progress output"
assert_file_contains "$TIMEOUT_STDOUT" "failure=timeout" "timeout run did not emit timeout failure classification"

timeout_log="$(jq -r '.checks[0].log_path' "$TIMEOUT_SUMMARY" | tr -d '\r')"
if [[ ! -f "$timeout_log" ]]; then
  echo "missing timeout log artifact: $timeout_log"
  cat "$TIMEOUT_SUMMARY"
  exit 1
fi
assert_file_contains "$timeout_log" "hang check start" "timeout log missing expected pre-timeout output"

echo "[gpm-logic-check] include/exclude filters with path normalization"
FILTER_REPORTS="$TMP_DIR/filters/../reports_filter"
FILTER_SUMMARY_ARG="$TMP_DIR/filters/../summary_filter.json"
FILTER_SUMMARY="$TMP_DIR/summary_filter.json"
FILTER_STDOUT="$TMP_DIR/filter_stdout.log"
filter_cmd=(
  bash "$SCRIPT_UNDER_TEST"
  --reports-dir "$FILTER_REPORTS"
  --summary-json "$FILTER_SUMMARY_ARG"
  --print-summary-json 0
  --include-check "$TMP_DIR/./pass_a.sh"
  --include-check "$TMP_DIR/subdir/../pass_b.sh"
  --include-check "$PASS_C"
  --exclude-check "pass_b.sh"
  --exclude-check "$TMP_DIR/./pass_c.sh"
)
for exclude_script in "${DEFAULT_EXCLUDES[@]}"; do
  filter_cmd+=(--exclude-check "$exclude_script")
done

set +e
"${filter_cmd[@]}" >"$FILTER_STDOUT" 2>&1
filter_rc=$?
set -e
if [[ "$filter_rc" -ne 0 ]]; then
  echo "expected filtered run to exit 0, got rc=$filter_rc"
  cat "$FILTER_STDOUT"
  exit 1
fi

assert_jq_true "$FILTER_SUMMARY" '
  .status == "pass"
  and .rc == 0
  and .selection_error == null
  and .invariant_error == null
  and .checks_selected == 1
  and .checks_executed == 1
  and .checks_skipped == 0
  and .checks_skipped == (.checks_selected - .checks_executed)
  and .checks_selected >= .checks_executed
  and .checks_passed == 1
  and .checks_failed == 0
  and ([.checks[].name] == ["pass_a.sh"])
  and ((.selected_checks // []) | length == 1)
  and (.selected_checks[0] | endswith("/pass_a.sh"))
  and ((.inputs.exclude_checks_basename // []) | index("pass_b.sh") != null)
' "filter/exclude summary fields mismatch"

filter_log="$(jq -r '.checks[0].log_path' "$FILTER_SUMMARY" | tr -d '\r')"
if [[ ! -f "$filter_log" ]]; then
  echo "missing filtered log artifact: $filter_log"
  cat "$FILTER_SUMMARY"
  exit 1
fi
assert_file_contains "$filter_log" "pass check a" "filtered log missing expected output"

echo "[gpm-logic-check] fail-closed when filters exclude all checks"
EMPTY_REPORTS="$TMP_DIR/reports_empty"
EMPTY_SUMMARY="$TMP_DIR/summary_empty.json"
EMPTY_STDOUT="$TMP_DIR/empty_stdout.log"
empty_cmd=(
  bash "$SCRIPT_UNDER_TEST"
  --reports-dir "$EMPTY_REPORTS"
  --summary-json "$EMPTY_SUMMARY"
  --print-summary-json 0
  --include-check "$PASS_A"
  --exclude-check "pass_a.sh"
)
for exclude_script in "${DEFAULT_EXCLUDES[@]}"; do
  empty_cmd+=(--exclude-check "$exclude_script")
done

set +e
"${empty_cmd[@]}" >"$EMPTY_STDOUT" 2>&1
empty_rc=$?
set -e
if [[ "$empty_rc" -ne 1 ]]; then
  echo "expected empty-selection run to exit 1, got rc=$empty_rc"
  cat "$EMPTY_STDOUT"
  exit 1
fi

assert_jq_true "$EMPTY_SUMMARY" '
  .status == "fail"
  and .rc == 1
  and .selection_error == "no_checks_selected"
  and .invariant_error == null
  and .checks_selected == 0
  and .checks_executed == 0
  and .checks_skipped == 0
  and .checks_skipped == (.checks_selected - .checks_executed)
  and .checks_selected >= .checks_executed
  and .checks_passed == 0
  and .checks_failed == 0
  and ((.checks // []) | length == 0)
' "empty-selection fail-closed summary fields mismatch"

echo "[gpm-logic-check] fail-closed when selected check script is empty"
: >"$EMPTY_CHECK"
chmod +x "$EMPTY_CHECK"
INVALID_SELECTED_REPORTS="$TMP_DIR/reports_invalid_selected"
INVALID_SELECTED_SUMMARY="$TMP_DIR/summary_invalid_selected.json"
INVALID_SELECTED_STDOUT="$TMP_DIR/invalid_selected_stdout.log"
invalid_selected_cmd=(
  bash "$SCRIPT_UNDER_TEST"
  --reports-dir "$INVALID_SELECTED_REPORTS"
  --summary-json "$INVALID_SELECTED_SUMMARY"
  --print-summary-json 0
  --include-check "$PASS_A"
  --include-check "$EMPTY_CHECK"
)
for exclude_script in "${DEFAULT_EXCLUDES[@]}"; do
  invalid_selected_cmd+=(--exclude-check "$exclude_script")
done

set +e
"${invalid_selected_cmd[@]}" >"$INVALID_SELECTED_STDOUT" 2>&1
invalid_selected_rc=$?
set -e
if [[ "$invalid_selected_rc" -ne 1 ]]; then
  echo "expected invalid-selected-checks run to exit 1, got rc=$invalid_selected_rc"
  cat "$INVALID_SELECTED_STDOUT"
  exit 1
fi
assert_file_contains "$INVALID_SELECTED_STDOUT" "invalid selected checks" "invalid-selected-checks run did not emit fail-closed message"

assert_jq_true "$INVALID_SELECTED_SUMMARY" '
  .status == "fail"
  and .rc == 1
  and .selection_error == "invalid_selected_checks"
  and .invariant_error == null
  and ((.invalid_selected_checks // []) | length == 1)
  and ((.inputs.invalid_selected_checks // []) | length == 1)
  and (.invalid_selected_checks[0] | contains("empty_check.sh (empty)"))
  and (.inputs.invalid_selected_checks[0] | contains("empty_check.sh (empty)"))
  and .checks_selected == 2
  and .checks_executed == 0
  and .checks_skipped == 2
  and .checks_skipped == (.checks_selected - .checks_executed)
  and .checks_passed == 0
  and .checks_failed == 0
  and ((.checks // []) | length == 0)
' "invalid-selected-checks fail-closed summary fields mismatch"

echo "[gpm-logic-check] fail-closed when declared default checks are missing"
MISSING_DEFAULT_ROOT="$TMP_DIR/missing_default_root"
MISSING_DEFAULT_SCRIPT="$MISSING_DEFAULT_ROOT/scripts/gpm_logic_check.sh"
MISSING_DEFAULT_REPORTS="$TMP_DIR/reports_missing_default_checks"
MISSING_DEFAULT_SUMMARY="$TMP_DIR/summary_missing_default_checks.json"
MISSING_DEFAULT_STDOUT="$TMP_DIR/missing_default_checks_stdout.log"
mkdir -p "$MISSING_DEFAULT_ROOT/scripts"
cat "$SCRIPT_UNDER_TEST" >"$MISSING_DEFAULT_SCRIPT"
chmod +x "$MISSING_DEFAULT_SCRIPT"

set +e
bash "$MISSING_DEFAULT_SCRIPT" \
  --reports-dir "$MISSING_DEFAULT_REPORTS" \
  --summary-json "$MISSING_DEFAULT_SUMMARY" \
  --print-summary-json 0 \
  --include-check "$PASS_A" >"$MISSING_DEFAULT_STDOUT" 2>&1
missing_default_rc=$?
set -e
if [[ "$missing_default_rc" -ne 1 ]]; then
  echo "expected missing-default-checks run to exit 1, got rc=$missing_default_rc"
  cat "$MISSING_DEFAULT_STDOUT"
  exit 1
fi
assert_file_contains "$MISSING_DEFAULT_STDOUT" "missing declared default checks" "missing-default-checks run did not emit fail-closed message"

assert_jq_true "$MISSING_DEFAULT_SUMMARY" '
  .status == "fail"
  and .rc == 1
  and .selection_error == "missing_default_checks"
  and .invariant_error == null
  and .inputs.allow_missing_defaults == false
  and ((.missing_default_checks // []) | length > 0)
  and ((.inputs.missing_default_checks // []) | length > 0)
  and .checks_selected == 1
  and .checks_executed == 0
  and .checks_skipped == 1
  and .checks_skipped == (.checks_selected - .checks_executed)
  and .checks_passed == 0
  and .checks_failed == 0
  and ((.checks // []) | length == 0)
' "missing-default-checks fail-closed summary fields mismatch"

echo "[gpm-logic-check] allow-missing-defaults opt-out permits execution"
ALLOW_MISSING_DEFAULTS_REPORTS="$TMP_DIR/reports_allow_missing_defaults"
ALLOW_MISSING_DEFAULTS_SUMMARY="$TMP_DIR/summary_allow_missing_defaults.json"
ALLOW_MISSING_DEFAULTS_STDOUT="$TMP_DIR/allow_missing_defaults_stdout.log"

set +e
bash "$MISSING_DEFAULT_SCRIPT" \
  --reports-dir "$ALLOW_MISSING_DEFAULTS_REPORTS" \
  --summary-json "$ALLOW_MISSING_DEFAULTS_SUMMARY" \
  --print-summary-json 0 \
  --allow-missing-defaults 1 \
  --include-check "$PASS_A" >"$ALLOW_MISSING_DEFAULTS_STDOUT" 2>&1
allow_missing_defaults_rc=$?
set -e
if [[ "$allow_missing_defaults_rc" -ne 0 ]]; then
  echo "expected allow-missing-defaults run to exit 0, got rc=$allow_missing_defaults_rc"
  cat "$ALLOW_MISSING_DEFAULTS_STDOUT"
  exit 1
fi

assert_jq_true "$ALLOW_MISSING_DEFAULTS_SUMMARY" '
  .status == "pass"
  and .rc == 0
  and .selection_error == null
  and .invariant_error == null
  and .inputs.allow_missing_defaults == true
  and ((.missing_default_checks // []) | length > 0)
  and ((.inputs.missing_default_checks // []) | length > 0)
  and .checks_selected == 1
  and .checks_executed == 1
  and .checks_skipped == 0
  and .checks_skipped == (.checks_selected - .checks_executed)
  and .checks_passed == 1
  and .checks_failed == 0
  and ((.checks // []) | length == 1)
' "allow-missing-defaults summary fields mismatch"

allow_missing_defaults_log="$(jq -r '.checks[0].log_path' "$ALLOW_MISSING_DEFAULTS_SUMMARY" | tr -d '\r')"
if [[ ! -f "$allow_missing_defaults_log" ]]; then
  echo "missing allow-missing-defaults log artifact: $allow_missing_defaults_log"
  cat "$ALLOW_MISSING_DEFAULTS_SUMMARY"
  exit 1
fi
assert_file_contains "$allow_missing_defaults_log" "pass check a" "allow-missing-defaults log missing expected output"

echo "[gpm-logic-check] missing include-check script returns usage error"
MISSING_REPORTS="$TMP_DIR/reports_missing"
MISSING_SUMMARY="$TMP_DIR/summary_missing.json"
MISSING_STDOUT="$TMP_DIR/missing_stdout.log"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$MISSING_REPORTS" \
  --summary-json "$MISSING_SUMMARY" \
  --print-summary-json 0 \
  --include-check "$TMP_DIR/does_not_exist.sh" >"$MISSING_STDOUT" 2>&1
missing_rc=$?
set -e
if [[ "$missing_rc" -ne 2 ]]; then
  echo "expected missing include-check run to exit 2, got rc=$missing_rc"
  cat "$MISSING_STDOUT"
  exit 1
fi
assert_file_contains "$MISSING_STDOUT" "--include-check script not found:" "missing include-check error output mismatch"
if [[ -f "$MISSING_SUMMARY" ]]; then
  echo "unexpected summary artifact for missing include-check run"
  cat "$MISSING_SUMMARY"
  exit 1
fi

echo "gpm logic check integration ok"
