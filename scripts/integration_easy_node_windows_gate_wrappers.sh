#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp chmod wc sed cat env grep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${EASY_NODE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/easy_node.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.tsv"
PHASE3_CHECK_FAKE="$TMP_DIR/fake_phase3_windows_client_beta_check.sh"
PHASE3_RUN_FAKE="$TMP_DIR/fake_phase3_windows_client_beta_run.sh"
PHASE4_CHECK_FAKE="$TMP_DIR/fake_phase4_windows_full_parity_check.sh"
PHASE4_RUN_FAKE="$TMP_DIR/fake_phase4_windows_full_parity_run.sh"
PHASE4_HANDOFF_CHECK_FAKE="$TMP_DIR/fake_phase4_windows_full_parity_handoff_check.sh"

create_fake_wrapper_script() {
  local target_script="$1"
  local marker="$2"
  cat >"$target_script" <<EOF_FAKE_WRAPPER
#!/usr/bin/env bash
set -euo pipefail
capture_file="\${EASY_NODE_WINDOWS_GATE_CAPTURE_FILE:?}"
{
  printf '%s' "$marker"
  for arg in "\$@"; do
    printf '\t%s' "\$arg"
  done
  printf '\n'
} >>"\$capture_file"
EOF_FAKE_WRAPPER
  chmod +x "$target_script"
}

assert_text_present() {
  local script_path="$1"
  local expected_text="$2"

  if command -v rg >/dev/null 2>&1; then
    if rg -Fq "$expected_text" "$script_path"; then
      return 0
    fi
  fi

  if grep -Fq "$expected_text" "$script_path"; then
    return 0
  fi

  echo "missing expected text in easy_node wrapper script: $expected_text"
  exit 1
}

assert_single_invocation() {
  local capture_file="$1"
  local command_name="$2"
  local count

  count="$(wc -l <"$capture_file")"
  count="${count//[[:space:]]/}"
  if [[ "$count" != "1" ]]; then
    echo "expected exactly one forwarded invocation for $command_name, got $count"
    cat "$capture_file"
    exit 1
  fi
}

assert_forwarded_args() {
  local capture_file="$1"
  local expected_marker="$2"
  local expected_reports_dir="$3"
  local expected_summary_json="$4"
  local expected_custom_flag="$5"
  local expected_custom_value="$6"
  local line
  local marker
  local -a fields=()

  line="$(sed -n '1p' "$capture_file" || true)"
  if [[ -z "$line" ]]; then
    echo "missing forwarded invocation payload"
    exit 1
  fi

  IFS=$'\t' read -r -a fields <<<"$line"
  marker="${fields[0]:-}"
  if [[ "$marker" != "$expected_marker" ]]; then
    echo "forwarded marker mismatch: expected $expected_marker"
    echo "$line"
    exit 1
  fi

  if [[ "${#fields[@]}" -ne 9 ]]; then
    echo "unexpected forwarded arg count: expected 9 got ${#fields[@]}"
    echo "$line"
    exit 1
  fi

  if [[ "${fields[1]:-}" != "--reports-dir" || "${fields[2]:-}" != "$expected_reports_dir" ]]; then
    echo "forwarded --reports-dir mismatch"
    echo "$line"
    exit 1
  fi
  if [[ "${fields[3]:-}" != "--summary-json" || "${fields[4]:-}" != "$expected_summary_json" ]]; then
    echo "forwarded --summary-json mismatch"
    echo "$line"
    exit 1
  fi
  if [[ "${fields[5]:-}" != "--print-summary-json" || "${fields[6]:-}" != "0" ]]; then
    echo "forwarded --print-summary-json mismatch"
    echo "$line"
    exit 1
  fi
  if [[ "${fields[7]:-}" != "$expected_custom_flag" || "${fields[8]:-}" != "$expected_custom_value" ]]; then
    echo "forwarded custom passthrough arg mismatch"
    echo "$line"
    exit 1
  fi
}

run_and_assert_wrapper() {
  local command_name="$1"
  local expected_marker="$2"
  local reports_dir="$3"
  local summary_json="$4"
  local custom_flag="$5"
  local custom_value="$6"

  : >"$CAPTURE"

  env EASY_NODE_WINDOWS_GATE_CAPTURE_FILE="$CAPTURE" \
    PHASE3_WINDOWS_CLIENT_BETA_CHECK_SCRIPT="$PHASE3_CHECK_FAKE" \
    PHASE3_WINDOWS_CLIENT_BETA_RUN_SCRIPT="$PHASE3_RUN_FAKE" \
    PHASE4_WINDOWS_FULL_PARITY_CHECK_SCRIPT="$PHASE4_CHECK_FAKE" \
    PHASE4_WINDOWS_FULL_PARITY_RUN_SCRIPT="$PHASE4_RUN_FAKE" \
    PHASE4_WINDOWS_FULL_PARITY_HANDOFF_CHECK_SCRIPT="$PHASE4_HANDOFF_CHECK_FAKE" \
    bash "$SCRIPT_UNDER_TEST" \
      "$command_name" \
      --reports-dir "$reports_dir" \
      --summary-json "$summary_json" \
      --print-summary-json 0 \
      "$custom_flag" "$custom_value" >/dev/null 2>&1

  assert_single_invocation "$CAPTURE" "$command_name"
  assert_forwarded_args \
    "$CAPTURE" \
    "$expected_marker" \
    "$reports_dir" \
    "$summary_json" \
    "$custom_flag" \
    "$custom_value"
}

assert_text_present "$SCRIPT_UNDER_TEST" "phase3-windows-client-beta-check"
assert_text_present "$SCRIPT_UNDER_TEST" "phase3-windows-client-beta-run"
assert_text_present "$SCRIPT_UNDER_TEST" "phase4-windows-full-parity-check"
assert_text_present "$SCRIPT_UNDER_TEST" "phase4-windows-full-parity-run"
assert_text_present "$SCRIPT_UNDER_TEST" "phase4-windows-full-parity-handoff-check"
assert_text_present "$SCRIPT_UNDER_TEST" "PHASE3_WINDOWS_CLIENT_BETA_CHECK_SCRIPT"
assert_text_present "$SCRIPT_UNDER_TEST" "PHASE3_WINDOWS_CLIENT_BETA_RUN_SCRIPT"
assert_text_present "$SCRIPT_UNDER_TEST" "PHASE4_WINDOWS_FULL_PARITY_CHECK_SCRIPT"
assert_text_present "$SCRIPT_UNDER_TEST" "PHASE4_WINDOWS_FULL_PARITY_RUN_SCRIPT"
assert_text_present "$SCRIPT_UNDER_TEST" "PHASE4_WINDOWS_FULL_PARITY_HANDOFF_CHECK_SCRIPT"

create_fake_wrapper_script "$PHASE3_CHECK_FAKE" "phase3_check"
create_fake_wrapper_script "$PHASE3_RUN_FAKE" "phase3_run"
create_fake_wrapper_script "$PHASE4_CHECK_FAKE" "phase4_check"
create_fake_wrapper_script "$PHASE4_RUN_FAKE" "phase4_run"
create_fake_wrapper_script "$PHASE4_HANDOFF_CHECK_FAKE" "phase4_handoff_check"

run_and_assert_wrapper \
  "phase3-windows-client-beta-check" \
  "phase3_check" \
  "$TMP_DIR/reports phase3" \
  "$TMP_DIR/summary phase3.json" \
  "--sample-arg" \
  "sample value phase3"

run_and_assert_wrapper \
  "phase3-windows-client-beta-run" \
  "phase3_run" \
  "$TMP_DIR/reports phase3 run" \
  "$TMP_DIR/summary phase3 run.json" \
  "--sample-arg" \
  "sample value phase3 run"

run_and_assert_wrapper \
  "phase4-windows-full-parity-check" \
  "phase4_check" \
  "$TMP_DIR/reports phase4 check" \
  "$TMP_DIR/summary phase4 check.json" \
  "--sample-arg" \
  "sample value phase4 check"

run_and_assert_wrapper \
  "phase4-windows-full-parity-run" \
  "phase4_run" \
  "$TMP_DIR/reports phase4 run" \
  "$TMP_DIR/summary phase4 run.json" \
  "--sample-arg" \
  "sample value phase4 run"

run_and_assert_wrapper \
  "phase4-windows-full-parity-handoff-check" \
  "phase4_handoff_check" \
  "$TMP_DIR/reports phase4" \
  "$TMP_DIR/summary phase4.json" \
  "--sample-arg" \
  "sample value phase4"

echo "easy-node windows gate wrapper integration ok"
