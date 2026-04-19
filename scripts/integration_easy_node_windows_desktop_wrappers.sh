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
RUNTIME_CAPTURE="$TMP_DIR/runtime_capture.tsv"
HELP_OUT="$TMP_DIR/help.txt"
STDOUT_OUT="$TMP_DIR/stdout.txt"
STDERR_OUT="$TMP_DIR/stderr.txt"
RUNTIME_DIR="$TMP_DIR/runtime"

DOCTOR_FAKE="$TMP_DIR/fake_desktop_windows_doctor.sh"
NATIVE_BOOTSTRAP_FAKE="$TMP_DIR/fake_desktop_windows_native_bootstrap.sh"
NATIVE_BOOTSTRAP_GUARDRAILS_FAKE="$TMP_DIR/fake_desktop_windows_native_bootstrap_guardrails.sh"
ONE_CLICK_FAKE="$TMP_DIR/fake_desktop_windows_one_click.sh"
PACKAGED_RUN_FAKE="$TMP_DIR/fake_desktop_windows_packaged_run.sh"
RELEASE_BUNDLE_FAKE="$TMP_DIR/fake_desktop_windows_release_bundle.sh"
LOCAL_API_SESSION_FAKE="$TMP_DIR/fake_desktop_windows_local_api_session.sh"
DOCTOR_PS1="$TMP_DIR/fake_desktop_windows_doctor.ps1"

create_fake_wrapper_script() {
  local target_script="$1"
  local marker="$2"
  local rc_env_var="$3"

  cat >"$target_script" <<EOF_FAKE_WRAPPER
#!/usr/bin/env bash
set -euo pipefail
capture_file="\${EASY_NODE_WINDOWS_DESKTOP_WRAPPERS_CAPTURE_FILE:?}"
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

create_fake_runtime_script() {
  local target_script="$1"
  local marker="$2"

  cat >"$target_script" <<EOF_FAKE_RUNTIME
#!/usr/bin/env bash
set -euo pipefail
capture_file="\${EASY_NODE_WINDOWS_DESKTOP_RUNTIME_CAPTURE_FILE:?}"
{
  printf '%s' "$marker"
  for arg in "\$@"; do
    printf '\t%s' "\$arg"
  done
  printf '\n'
} >>"\$capture_file"
exit "\${FAKE_WINDOWS_RUNTIME_RC:-0}"
EOF_FAKE_RUNTIME
  chmod +x "$target_script"
}

assert_help_contains() {
  local expected_line="$1"
  if ! grep -F -- "$expected_line" "$HELP_OUT" >/dev/null 2>&1; then
    echo "easy_node help missing windows desktop wrapper command contract"
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

assert_runtime_ps1_invocation() {
  local capture_file="$1"
  local expected_script="$2"
  shift 2
  local -a passthrough_args=("$@")
  local -a fields=()
  local line
  local expected_field_count
  local i

  line="$(sed -n '1p' "$capture_file" || true)"
  if [[ -z "$line" ]]; then
    echo "missing runtime invocation payload"
    exit 1
  fi

  IFS=$'\t' read -r -a fields <<<"$line"
  if [[ "${fields[0]:-}" != "powershell.exe" && "${fields[0]:-}" != "pwsh" && "${fields[0]:-}" != "powershell" ]]; then
    echo "runtime mismatch: expected powershell-family runtime got '${fields[0]:-}'"
    echo "$line"
    exit 1
  fi

  if [[ "${fields[1]:-}" != "-NoLogo" ]]; then
    echo "missing -NoLogo runtime flag"
    echo "$line"
    exit 1
  fi
  if [[ "${fields[2]:-}" != "-NoProfile" ]]; then
    echo "missing -NoProfile runtime flag"
    echo "$line"
    exit 1
  fi
  if [[ "${fields[3]:-}" != "-ExecutionPolicy" || "${fields[4]:-}" != "Bypass" ]]; then
    echo "missing -ExecutionPolicy Bypass runtime flags"
    echo "$line"
    exit 1
  fi
  if [[ "${fields[5]:-}" != "-File" || "${fields[6]:-}" != "$expected_script" ]]; then
    echo "missing -File runtime script payload"
    echo "$line"
    exit 1
  fi

  expected_field_count=$((7 + ${#passthrough_args[@]}))
  if [[ "${#fields[@]}" -ne "$expected_field_count" ]]; then
    echo "unexpected runtime arg count: expected $expected_field_count got ${#fields[@]}"
    echo "$line"
    exit 1
  fi

  i=0
  while [[ "$i" -lt "${#passthrough_args[@]}" ]]; do
    if [[ "${fields[$((7 + i))]:-}" != "${passthrough_args[$i]}" ]]; then
      echo "runtime passthrough mismatch at position $i: expected '${passthrough_args[$i]}' got '${fields[$((7 + i))]:-}'"
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
    EASY_NODE_WINDOWS_DESKTOP_WRAPPERS_CAPTURE_FILE="$CAPTURE" \
    DESKTOP_WINDOWS_DOCTOR_SCRIPT="$DOCTOR_FAKE" \
    DESKTOP_WINDOWS_NATIVE_BOOTSTRAP_SCRIPT="$NATIVE_BOOTSTRAP_FAKE" \
    DESKTOP_WINDOWS_NATIVE_BOOTSTRAP_GUARDRAILS_SCRIPT="$NATIVE_BOOTSTRAP_GUARDRAILS_FAKE" \
    DESKTOP_WINDOWS_ONE_CLICK_SCRIPT="$ONE_CLICK_FAKE" \
    DESKTOP_WINDOWS_PACKAGED_RUN_SCRIPT="$PACKAGED_RUN_FAKE" \
    DESKTOP_WINDOWS_RELEASE_BUNDLE_SCRIPT="$RELEASE_BUNDLE_FAKE" \
    DESKTOP_WINDOWS_LOCAL_API_SESSION_SCRIPT="$LOCAL_API_SESSION_FAKE" \
    bash "$SCRIPT_UNDER_TEST" "$command_name" "${forwarded_args[@]}" >"$STDOUT_OUT" 2>"$STDERR_OUT"

  assert_single_invocation "$CAPTURE" "$command_name"
  assert_forwarded_exact "$CAPTURE" "$expected_marker" "${forwarded_args[@]}"
}

create_fake_wrapper_script "$DOCTOR_FAKE" "desktop_windows_doctor" "FAKE_WINDOWS_DOCTOR_RC"
create_fake_wrapper_script "$NATIVE_BOOTSTRAP_FAKE" "desktop_windows_native_bootstrap" "FAKE_WINDOWS_NATIVE_BOOTSTRAP_RC"
create_fake_wrapper_script "$NATIVE_BOOTSTRAP_GUARDRAILS_FAKE" "desktop_windows_native_bootstrap_guardrails" "FAKE_WINDOWS_NATIVE_BOOTSTRAP_GUARDRAILS_RC"
create_fake_wrapper_script "$ONE_CLICK_FAKE" "desktop_windows_one_click" "FAKE_WINDOWS_ONE_CLICK_RC"
create_fake_wrapper_script "$PACKAGED_RUN_FAKE" "desktop_windows_packaged_run" "FAKE_WINDOWS_PACKAGED_RUN_RC"
create_fake_wrapper_script "$RELEASE_BUNDLE_FAKE" "desktop_windows_release_bundle" "FAKE_WINDOWS_RELEASE_BUNDLE_RC"
create_fake_wrapper_script "$LOCAL_API_SESSION_FAKE" "desktop_windows_local_api_session" "FAKE_WINDOWS_LOCAL_API_SESSION_RC"
cat >"$DOCTOR_PS1" <<'EOF_FAKE_PS1'
# fake powershell payload; runtime contract only
EOF_FAKE_PS1

echo "[easy-node-windows-desktop-wrappers] help contract"
bash "$SCRIPT_UNDER_TEST" help >"$HELP_OUT"
assert_help_contains "./scripts/easy_node.sh desktop-windows-doctor [desktop_doctor args...]"
assert_help_contains "./scripts/easy_node.sh desktop-windows-native-bootstrap [desktop_native_bootstrap args...]"
assert_help_contains "./scripts/easy_node.sh desktop-windows-native-bootstrap-guardrails [desktop_native_bootstrap_guardrails args...]"
assert_help_contains "./scripts/easy_node.sh desktop-windows-one-click [desktop_one_click args...]"
assert_help_contains "./scripts/easy_node.sh desktop-windows-packaged-run [desktop_packaged_run args...]"
assert_help_contains "./scripts/easy_node.sh desktop-windows-release-bundle [desktop_release_bundle args...]"
assert_help_contains "./scripts/easy_node.sh desktop-windows-local-api-session [local_api_session args...]"

echo "[easy-node-windows-desktop-wrappers] forwarding contract"
run_and_assert_wrapper \
  "desktop-windows-doctor" \
  "desktop_windows_doctor" \
  "--mode" "check" \
  "--sample-flag" "doctor value with spaces"

run_and_assert_wrapper \
  "desktop-windows-native-bootstrap" \
  "desktop_windows_native_bootstrap" \
  "--mode" "bootstrap" \
  "--sample-flag" "native bootstrap value with spaces"

run_and_assert_wrapper \
  "desktop-windows-native-bootstrap-guardrails" \
  "desktop_windows_native_bootstrap_guardrails" \
  "--sample-flag" "native bootstrap guardrails value with spaces"

run_and_assert_wrapper \
  "desktop-windows-one-click" \
  "desktop_windows_one_click" \
  "--install-missing" \
  "--sample-flag" "one click value with spaces"

run_and_assert_wrapper \
  "desktop-windows-packaged-run" \
  "desktop_windows_packaged_run" \
  "--dry-run" \
  "--sample-flag" "packaged run value with spaces"

run_and_assert_wrapper \
  "desktop-windows-release-bundle" \
  "desktop_windows_release_bundle" \
  "--bundle-dir" "$TMP_DIR/release bundle with spaces" \
  "--sample-flag" "release bundle value with spaces"

run_and_assert_wrapper \
  "desktop-windows-local-api-session" \
  "desktop_windows_local_api_session" \
  "--dry-run" \
  "--sample-flag" "local api session value with spaces"

echo "[easy-node-windows-desktop-wrappers] exit semantics contract"
set +e
env \
  EASY_NODE_WINDOWS_DESKTOP_WRAPPERS_CAPTURE_FILE="$CAPTURE" \
  DESKTOP_WINDOWS_DOCTOR_SCRIPT="$DOCTOR_FAKE" \
  DESKTOP_WINDOWS_NATIVE_BOOTSTRAP_SCRIPT="$NATIVE_BOOTSTRAP_FAKE" \
  DESKTOP_WINDOWS_NATIVE_BOOTSTRAP_GUARDRAILS_SCRIPT="$NATIVE_BOOTSTRAP_GUARDRAILS_FAKE" \
  DESKTOP_WINDOWS_ONE_CLICK_SCRIPT="$ONE_CLICK_FAKE" \
  DESKTOP_WINDOWS_PACKAGED_RUN_SCRIPT="$PACKAGED_RUN_FAKE" \
  DESKTOP_WINDOWS_RELEASE_BUNDLE_SCRIPT="$RELEASE_BUNDLE_FAKE" \
  DESKTOP_WINDOWS_LOCAL_API_SESSION_SCRIPT="$LOCAL_API_SESSION_FAKE" \
  FAKE_WINDOWS_PACKAGED_RUN_RC=13 \
  bash "$SCRIPT_UNDER_TEST" desktop-windows-packaged-run --sample-flag "rc passthrough" >"$STDOUT_OUT" 2>"$STDERR_OUT"
rc=$?
set -e
if [[ "$rc" -ne 13 ]]; then
  echo "expected easy_node wrapper to return fake script exit code 13, got $rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi

echo "[easy-node-windows-desktop-wrappers] ps1 runtime contract"
mkdir -p "$RUNTIME_DIR"
create_fake_runtime_script "$RUNTIME_DIR/powershell.exe" "powershell.exe"
create_fake_runtime_script "$RUNTIME_DIR/pwsh" "pwsh"
create_fake_runtime_script "$RUNTIME_DIR/powershell" "powershell"
: >"$RUNTIME_CAPTURE"

PATH="$RUNTIME_DIR:$PATH"

env \
  EASY_NODE_WINDOWS_DESKTOP_RUNTIME_CAPTURE_FILE="$RUNTIME_CAPTURE" \
  PATH="$PATH" \
  DESKTOP_WINDOWS_DOCTOR_SCRIPT="$DOCTOR_PS1" \
  bash "$SCRIPT_UNDER_TEST" \
    desktop-windows-doctor \
    --sample-flag "runtime value with spaces" >"$STDOUT_OUT" 2>"$STDERR_OUT"

assert_single_invocation "$RUNTIME_CAPTURE" "desktop-windows-doctor runtime"
assert_runtime_ps1_invocation \
  "$RUNTIME_CAPTURE" \
  "$DOCTOR_PS1" \
  "--sample-flag" "runtime value with spaces"

echo "easy-node windows desktop wrappers integration check ok"
