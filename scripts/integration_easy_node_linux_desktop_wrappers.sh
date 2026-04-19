#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp chmod wc sed cat env grep tail; do
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
HELP_OUT="$TMP_DIR/help.txt"
STDOUT_OUT="$TMP_DIR/stdout.txt"
STDERR_OUT="$TMP_DIR/stderr.txt"

DOCTOR_FAKE="$TMP_DIR/fake_desktop_linux_doctor.sh"
NATIVE_BOOTSTRAP_FAKE="$TMP_DIR/fake_desktop_linux_native_bootstrap.sh"
ONE_CLICK_FAKE="$TMP_DIR/fake_desktop_linux_one_click.sh"
PACKAGED_RUN_FAKE="$TMP_DIR/fake_desktop_linux_packaged_run.sh"

create_fake_wrapper_script() {
  local target_script="$1"
  local marker="$2"
  local rc_env_var="$3"

  cat >"$target_script" <<EOF_FAKE_WRAPPER
#!/usr/bin/env bash
set -euo pipefail
capture_file="\${EASY_NODE_LINUX_DESKTOP_WRAPPERS_CAPTURE_FILE:?}"
{
  printf '%s' "$marker"
  for arg in "\$@"; do
    printf '\t%s' "\$arg"
  done
  printf '\n'
} >>"\$capture_file"
exit "\${$rc_env_var:-0}"
EOF_FAKE_WRAPPER
  chmod +x "$target_script"
}

assert_help_contains() {
  local expected_line="$1"
  if ! grep -F -- "$expected_line" "$HELP_OUT" >/dev/null 2>&1; then
    echo "easy_node help missing linux desktop wrapper command contract"
    echo "missing: $expected_line"
    cat "$HELP_OUT"
    exit 1
  fi
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

assert_forwarded_exact() {
  local capture_file="$1"
  local expected_marker="$2"
  shift 2
  local -a expected_args=("$@")
  local -a fields=()
  local line
  local expected_field_count
  local marker
  local i

  line="$(sed -n '1p' "$capture_file" || true)"
  if [[ -z "$line" ]]; then
    echo "missing forwarded invocation payload"
    exit 1
  fi

  IFS=$'\t' read -r -a fields <<<"$line"
  marker="${fields[0]:-}"
  if [[ "$marker" != "$expected_marker" ]]; then
    echo "forwarded marker mismatch: expected $expected_marker got $marker"
    echo "$line"
    exit 1
  fi

  expected_field_count=$((1 + ${#expected_args[@]}))
  if [[ "${#fields[@]}" -ne "$expected_field_count" ]]; then
    echo "unexpected forwarded arg count: expected $expected_field_count got ${#fields[@]}"
    echo "$line"
    exit 1
  fi

  i=0
  while [[ "$i" -lt "${#expected_args[@]}" ]]; do
    if [[ "${fields[$((i + 1))]:-}" != "${expected_args[$i]}" ]]; then
      echo "forwarded arg mismatch at position $i: expected '${expected_args[$i]}' got '${fields[$((i + 1))]:-}'"
      echo "$line"
      exit 1
    fi
    i=$((i + 1))
  done
}

run_and_assert_wrapper() {
  local command_name="$1"
  local expected_marker="$2"
  shift 2
  local -a forwarded_args=("$@")

  : >"$CAPTURE"

  env \
    EASY_NODE_LINUX_DESKTOP_WRAPPERS_CAPTURE_FILE="$CAPTURE" \
    DESKTOP_LINUX_DOCTOR_SCRIPT="$DOCTOR_FAKE" \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT="$NATIVE_BOOTSTRAP_FAKE" \
    DESKTOP_LINUX_ONE_CLICK_SCRIPT="$ONE_CLICK_FAKE" \
    DESKTOP_LINUX_PACKAGED_RUN_SCRIPT="$PACKAGED_RUN_FAKE" \
    bash "$SCRIPT_UNDER_TEST" "$command_name" "${forwarded_args[@]}" >"$STDOUT_OUT" 2>"$STDERR_OUT"

  assert_single_invocation "$CAPTURE" "$command_name"
  assert_forwarded_exact "$CAPTURE" "$expected_marker" "${forwarded_args[@]}"
}

create_fake_wrapper_script "$DOCTOR_FAKE" "desktop_linux_doctor" "FAKE_LINUX_DOCTOR_RC"
create_fake_wrapper_script "$NATIVE_BOOTSTRAP_FAKE" "desktop_linux_native_bootstrap" "FAKE_LINUX_NATIVE_BOOTSTRAP_RC"
create_fake_wrapper_script "$ONE_CLICK_FAKE" "desktop_linux_one_click" "FAKE_LINUX_ONE_CLICK_RC"
create_fake_wrapper_script "$PACKAGED_RUN_FAKE" "desktop_linux_packaged_run" "FAKE_LINUX_PACKAGED_RUN_RC"

echo "[easy-node-linux-desktop-wrappers] help contract"
bash "$SCRIPT_UNDER_TEST" help >"$HELP_OUT"
assert_help_contains "./scripts/easy_node.sh desktop-linux-doctor [desktop_doctor args...]"
assert_help_contains "./scripts/easy_node.sh desktop-linux-native-bootstrap [desktop_native_bootstrap args...]"
assert_help_contains "./scripts/easy_node.sh desktop-linux-one-click [desktop_one_click args...]"
assert_help_contains "./scripts/easy_node.sh desktop-linux-packaged-run [desktop_packaged_run args...]"

echo "[easy-node-linux-desktop-wrappers] forwarding contract"
run_and_assert_wrapper \
  "desktop-linux-doctor" \
  "desktop_linux_doctor" \
  "--reports-dir" "$TMP_DIR/reports doctor with spaces" \
  "--summary-json" "$TMP_DIR/summary doctor with spaces.json" \
  "--sample-flag" "doctor value with spaces"

run_and_assert_wrapper \
  "desktop-linux-native-bootstrap" \
  "desktop_linux_native_bootstrap" \
  "--reports-dir" "$TMP_DIR/reports native bootstrap with spaces" \
  "--summary-json" "$TMP_DIR/summary native bootstrap with spaces.json" \
  "--sample-flag" "native bootstrap value with spaces"

run_and_assert_wrapper \
  "desktop-linux-one-click" \
  "desktop_linux_one_click" \
  "--reports-dir" "$TMP_DIR/reports one click with spaces" \
  "--summary-json" "$TMP_DIR/summary one click with spaces.json" \
  "--sample-flag" "one click value with spaces"

run_and_assert_wrapper \
  "desktop-linux-packaged-run" \
  "desktop_linux_packaged_run" \
  "--reports-dir" "$TMP_DIR/reports packaged run with spaces" \
  "--summary-json" "$TMP_DIR/summary packaged run with spaces.json" \
  "--sample-flag" "packaged run value with spaces"

echo "[easy-node-linux-desktop-wrappers] exit semantics contract"
set +e
env \
  EASY_NODE_LINUX_DESKTOP_WRAPPERS_CAPTURE_FILE="$CAPTURE" \
  DESKTOP_LINUX_DOCTOR_SCRIPT="$DOCTOR_FAKE" \
  DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT="$NATIVE_BOOTSTRAP_FAKE" \
  DESKTOP_LINUX_ONE_CLICK_SCRIPT="$ONE_CLICK_FAKE" \
  DESKTOP_LINUX_PACKAGED_RUN_SCRIPT="$PACKAGED_RUN_FAKE" \
  FAKE_LINUX_PACKAGED_RUN_RC=9 \
  bash "$SCRIPT_UNDER_TEST" desktop-linux-packaged-run --sample-flag "rc passthrough" >"$STDOUT_OUT" 2>"$STDERR_OUT"
rc=$?
set -e
if [[ "$rc" -ne 9 ]]; then
  echo "expected easy_node wrapper to return fake script exit code 9, got $rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi

echo "easy-node linux desktop wrappers integration check ok"
