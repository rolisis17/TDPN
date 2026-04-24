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

SCRIPT_UNDER_TEST="${GPM_BLOCKCHAIN_LOGIC_CHECK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/gpm_blockchain_logic_check.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi
if [[ ! -r "$SCRIPT_UNDER_TEST" ]]; then
  echo "script under test is not readable: $SCRIPT_UNDER_TEST"
  exit 2
fi

mkdir -p "$ROOT_DIR/.easy-node-logs"
TMP_DIR="$(mktemp -d "$ROOT_DIR/.easy-node-logs/integration_gpm_blockchain_logic_check_XXXXXX")"
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

mapfile -t DEFAULT_CHECK_LINES < <(
  bash "$SCRIPT_UNDER_TEST" --print-default-checks 1 \
    | tr -d '\r' \
    | grep -E -v '^[[:space:]]*$'
)
if [[ "${#DEFAULT_CHECK_LINES[@]}" -eq 0 ]]; then
  echo "expected --print-default-checks to return at least one default check"
  exit 1
fi

declare -a DEFAULT_CHECK_IDS=()
for default_line in "${DEFAULT_CHECK_LINES[@]}"; do
  check_id="${default_line%%$'\t'*}"
  if [[ -z "$check_id" ]]; then
    echo "default check line missing check id"
    printf 'line=%s\n' "$default_line"
    exit 1
  fi
  DEFAULT_CHECK_IDS+=("$check_id")
done

declare -a REQUIRED_DEFAULT_IDS=(
  "internal_app_tests"
  "settlement_tests"
  "integration_blockchain_cosmos_only_guardrail"
)
for required_default in "${REQUIRED_DEFAULT_IDS[@]}"; do
  if ! printf '%s\n' "${DEFAULT_CHECK_IDS[@]}" | grep -Fx -- "$required_default" >/dev/null 2>&1; then
    echo "required default check is missing from --print-default-checks output: $required_default"
    printf 'default check ids were:\n'
    printf '  %s\n' "${DEFAULT_CHECK_IDS[@]}"
    exit 1
  fi
done

DEFAULT_CHECK_IDS_JSON="$(jq -n '$ARGS.positional' --args "${DEFAULT_CHECK_IDS[@]}")"

declare -a DEFAULT_EXCLUDE_ARGS=()
for default_id in "${DEFAULT_CHECK_IDS[@]}"; do
  DEFAULT_EXCLUDE_ARGS+=(--exclude-check "$default_id")
done

echo "[gpm-blockchain-logic-check] all-pass summary aggregation"
PASS_REPORTS="$TMP_DIR/reports_pass"
PASS_SUMMARY="$TMP_DIR/summary_pass.json"
PASS_STDOUT="$TMP_DIR/pass_stdout.log"
pass_cmd=(
  bash "$SCRIPT_UNDER_TEST"
  --reports-dir "$PASS_REPORTS"
  --summary-json "$PASS_SUMMARY"
  --print-summary-json 0
  --include-command "pass_a=bash $PASS_A"
  --include-command "pass_b=bash $PASS_B"
)
pass_cmd+=("${DEFAULT_EXCLUDE_ARGS[@]}")

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
  .schema.id == "gpm_blockchain_logic_check_summary"
  and .status == "pass"
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
  and ((.selected_checks | map(.id) | unique | length) == (.selected_checks | length))
  and (((.checks | map(.id) | unique) | length) == ((.checks | map(.id)) | length))
  and ([.checks[].id] == ["pass_a", "pass_b"])
  and (all(.checks[]; has("id") and has("source") and has("command") and has("status") and has("rc") and has("duration_sec") and has("log_path") and has("timed_out")))
  and (all(.checks[]; ((.status == "pass" and .rc == 0) or (.status == "fail" and .rc != 0))))
  and (all(.checks[]; (.duration_sec | type) == "number" and .duration_sec >= 0))
' "all-pass summary fields mismatch"

if ! jq -e --argjson expected_default_ids "$DEFAULT_CHECK_IDS_JSON" '
  (.inputs.default_checks | map(.id)) == $expected_default_ids
' "$PASS_SUMMARY" >/dev/null 2>&1; then
  echo "default check ids mismatch between --print-default-checks and summary inputs"
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

echo "[gpm-blockchain-logic-check] fail aggregation without fail-fast"
FAIL_REPORTS="$TMP_DIR/reports_fail"
FAIL_SUMMARY="$TMP_DIR/summary_fail.json"
FAIL_STDOUT="$TMP_DIR/fail_stdout.log"
fail_cmd=(
  bash "$SCRIPT_UNDER_TEST"
  --reports-dir "$FAIL_REPORTS"
  --summary-json "$FAIL_SUMMARY"
  --print-summary-json 0
  --fail-fast 0
  --include-command "pass_a=bash $PASS_A"
  --include-command "fail_7=bash $FAIL_7"
  --include-command "pass_c=bash $PASS_C"
)
fail_cmd+=("${DEFAULT_EXCLUDE_ARGS[@]}")

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
  and ((.selected_checks | map(.id) | unique | length) == (.selected_checks | length))
  and (((.checks | map(.id) | unique) | length) == ((.checks | map(.id)) | length))
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

echo "[gpm-blockchain-logic-check] fail-fast short-circuit"
FAST_REPORTS="$TMP_DIR/reports_fail_fast"
FAST_SUMMARY="$TMP_DIR/summary_fail_fast.json"
FAST_STDOUT="$TMP_DIR/fail_fast_stdout.log"
fast_cmd=(
  bash "$SCRIPT_UNDER_TEST"
  --reports-dir "$FAST_REPORTS"
  --summary-json "$FAST_SUMMARY"
  --print-summary-json 0
  --fail-fast 1
  --include-command "fail_5=bash $FAIL_5"
  --include-command "pass_a=bash $PASS_A"
)
fast_cmd+=("${DEFAULT_EXCLUDE_ARGS[@]}")

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
  and ((.selected_checks | map(.id) | unique | length) == (.selected_checks | length))
  and (((.checks | map(.id) | unique) | length) == ((.checks | map(.id)) | length))
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

echo "[gpm-blockchain-logic-check] timeout guard with heartbeat progress"
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
  --include-command "hang_30=bash $HANG_30"
  --include-command "pass_a=bash $PASS_A"
)
timeout_cmd+=("${DEFAULT_EXCLUDE_ARGS[@]}")

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
  and ((.selected_checks | map(.id) | unique | length) == (.selected_checks | length))
  and (((.checks | map(.id) | unique) | length) == ((.checks | map(.id)) | length))
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

echo "[gpm-blockchain-logic-check] fail-closed when filters exclude all checks"
EMPTY_REPORTS="$TMP_DIR/reports_empty"
EMPTY_SUMMARY="$TMP_DIR/summary_empty.json"
EMPTY_STDOUT="$TMP_DIR/empty_stdout.log"
empty_cmd=(
  bash "$SCRIPT_UNDER_TEST"
  --reports-dir "$EMPTY_REPORTS"
  --summary-json "$EMPTY_SUMMARY"
  --print-summary-json 0
  --include-command "pass_a=bash $PASS_A"
  --exclude-check "pass_a"
)
empty_cmd+=("${DEFAULT_EXCLUDE_ARGS[@]}")

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

echo "[gpm-blockchain-logic-check] malformed include-command returns usage error"
MALFORMED_REPORTS="$TMP_DIR/reports_malformed"
MALFORMED_SUMMARY="$TMP_DIR/summary_malformed.json"
MALFORMED_STDOUT="$TMP_DIR/malformed_stdout.log"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$MALFORMED_REPORTS" \
  --summary-json "$MALFORMED_SUMMARY" \
  --print-summary-json 0 \
  --include-command "missing_separator" >"$MALFORMED_STDOUT" 2>&1
malformed_rc=$?
set -e
if [[ "$malformed_rc" -ne 2 ]]; then
  echo "expected malformed include-command run to exit 2, got rc=$malformed_rc"
  cat "$MALFORMED_STDOUT"
  exit 1
fi
assert_file_contains "$MALFORMED_STDOUT" "--include-command must use <check_id>=<shell_command> format" "malformed include-command error output mismatch"
if [[ -f "$MALFORMED_SUMMARY" ]]; then
  echo "unexpected summary artifact for malformed include-command run"
  cat "$MALFORMED_SUMMARY"
  exit 1
fi

echo "gpm blockchain logic check integration ok"
