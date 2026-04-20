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
GO_CAPTURE="$TMP_DIR/go_capture.tsv"
HELP_OUT="$TMP_DIR/help.txt"
STDOUT_OUT="$TMP_DIR/stdout.txt"
STDERR_OUT="$TMP_DIR/stderr.txt"
RUNTIME_DIR="$TMP_DIR/runtime"
RUNTIME_CAPTURE="$TMP_DIR/runtime_capture.tsv"

DOCTOR_LINUX_FAKE="$TMP_DIR/fake_desktop_linux_doctor.sh"
NATIVE_BOOTSTRAP_LINUX_FAKE="$TMP_DIR/fake_desktop_linux_native_bootstrap.sh"
ONE_CLICK_LINUX_FAKE="$TMP_DIR/fake_desktop_linux_one_click.sh"
PACKAGED_RUN_LINUX_FAKE="$TMP_DIR/fake_desktop_linux_packaged_run.sh"
RELEASE_BUNDLE_LINUX_FAKE="$TMP_DIR/fake_desktop_linux_release_bundle.sh"
LOCAL_API_LINUX_FAKE="$TMP_DIR/fake_desktop_linux_local_api_session.sh"

DOCTOR_WINDOWS_FAKE="$TMP_DIR/fake_desktop_windows_doctor.ps1"
NATIVE_BOOTSTRAP_WINDOWS_FAKE="$TMP_DIR/fake_desktop_windows_native_bootstrap.ps1"
ONE_CLICK_WINDOWS_FAKE="$TMP_DIR/fake_desktop_windows_one_click.ps1"
PACKAGED_RUN_WINDOWS_FAKE="$TMP_DIR/fake_desktop_windows_packaged_run.ps1"
RELEASE_BUNDLE_WINDOWS_FAKE="$TMP_DIR/fake_desktop_windows_release_bundle.ps1"
LOCAL_API_WINDOWS_FAKE="$TMP_DIR/fake_desktop_windows_local_api_session.ps1"

create_fake_posix_wrapper_script() {
  local target_script="$1"
  local marker="$2"
  local rc_env_var="$3"

  cat >"$target_script" <<EOF_FAKE_WRAPPER
#!/usr/bin/env bash
set -euo pipefail
capture_file="\${EASY_NODE_DESKTOP_WRAPPERS_CAPTURE_FILE:?}"
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

create_fake_ps1_placeholder() {
  local target_script="$1"
  cat >"$target_script" <<'EOF_FAKE_PS1'
# fake powershell payload; runtime contract only
EOF_FAKE_PS1
}

create_fake_runtime_script() {
  local target_script="$1"
  local marker="$2"

  cat >"$target_script" <<EOF_FAKE_RUNTIME
#!/usr/bin/env bash
set -euo pipefail
capture_file="\${EASY_NODE_DESKTOP_WRAPPERS_RUNTIME_CAPTURE_FILE:?}"
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

create_fake_go_script() {
  local target_script="$1"

  cat >"$target_script" <<'EOF_FAKE_GO'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${EASY_NODE_DESKTOP_WRAPPERS_GO_CAPTURE_FILE:?}"
{
  printf 'go'
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
exit "${FAKE_LINUX_LOCAL_API_GO_RC:-0}"
EOF_FAKE_GO
  chmod +x "$target_script"
}

assert_help_contains() {
  local expected_line="$1"
  if ! grep -F -- "$expected_line" "$HELP_OUT" >/dev/null 2>&1; then
    echo "easy_node help missing generic desktop wrapper command contract"
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

assert_runtime_invocation() {
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

assert_go_invocation() {
  local capture_file="$1"
  shift
  local -a expected_args=("$@")
  local -a fields=()
  local line
  local expected_field_count
  local i

  line="$(sed -n '1p' "$capture_file" || true)"
  if [[ -z "$line" ]]; then
    echo "missing go invocation payload"
    exit 1
  fi

  IFS=$'\t' read -r -a fields <<<"$line"
  if [[ "${fields[0]:-}" != "go" ]]; then
    echo "go mismatch: expected fake go executable got '${fields[0]:-}'"
    echo "$line"
    exit 1
  fi

  expected_field_count=$((1 + ${#expected_args[@]}))
  if [[ "${#fields[@]}" -ne "$expected_field_count" ]]; then
    echo "unexpected go arg count: expected $expected_field_count got ${#fields[@]}"
    echo "$line"
    exit 1
  fi

  i=0
  while [[ "$i" -lt "${#expected_args[@]}" ]]; do
    if [[ "${fields[$((i + 1))]:-}" != "${expected_args[$i]}" ]]; then
      echo "go arg mismatch at position $i: expected '${expected_args[$i]}' got '${fields[$((i + 1))]:-}'"
      echo "$line"
      exit 1
    fi
    i=$((i + 1))
  done
}

run_linux_command() {
  local command_name="$1"
  local expected_marker="$2"
  shift 2
  local -a forwarded_args=("$@")

  : >"$CAPTURE"

  env \
    EASY_NODE_DESKTOP_WRAPPERS_CAPTURE_FILE="$CAPTURE" \
    DESKTOP_LINUX_DOCTOR_SCRIPT="$DOCTOR_LINUX_FAKE" \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT="$NATIVE_BOOTSTRAP_LINUX_FAKE" \
    DESKTOP_LINUX_ONE_CLICK_SCRIPT="$ONE_CLICK_LINUX_FAKE" \
    DESKTOP_LINUX_PACKAGED_RUN_SCRIPT="$PACKAGED_RUN_LINUX_FAKE" \
    DESKTOP_LINUX_RELEASE_BUNDLE_SCRIPT="$RELEASE_BUNDLE_LINUX_FAKE" \
    DESKTOP_WINDOWS_DOCTOR_SCRIPT="$DOCTOR_WINDOWS_FAKE" \
    DESKTOP_WINDOWS_NATIVE_BOOTSTRAP_SCRIPT="$NATIVE_BOOTSTRAP_WINDOWS_FAKE" \
    DESKTOP_WINDOWS_ONE_CLICK_SCRIPT="$ONE_CLICK_WINDOWS_FAKE" \
    DESKTOP_WINDOWS_PACKAGED_RUN_SCRIPT="$PACKAGED_RUN_WINDOWS_FAKE" \
    DESKTOP_WINDOWS_RELEASE_BUNDLE_SCRIPT="$RELEASE_BUNDLE_WINDOWS_FAKE" \
    DESKTOP_WINDOWS_LOCAL_API_SESSION_SCRIPT="$LOCAL_API_WINDOWS_FAKE" \
    bash "$SCRIPT_UNDER_TEST" "$command_name" --platform linux "${forwarded_args[@]}" >"$STDOUT_OUT" 2>"$STDERR_OUT"

  assert_single_invocation "$CAPTURE" "$command_name"
  assert_forwarded_exact "$CAPTURE" "$expected_marker" "${forwarded_args[@]}"
}

run_windows_command() {
  local command_name="$1"
  local expected_marker="$2"
  shift 2
  local -a forwarded_args=("$@")

  : >"$RUNTIME_CAPTURE"

  mkdir -p "$RUNTIME_DIR"
  create_fake_runtime_script "$RUNTIME_DIR/powershell.exe" "powershell.exe"
  create_fake_runtime_script "$RUNTIME_DIR/pwsh" "pwsh"
  create_fake_runtime_script "$RUNTIME_DIR/powershell" "powershell"

  env \
    EASY_NODE_DESKTOP_WRAPPERS_RUNTIME_CAPTURE_FILE="$RUNTIME_CAPTURE" \
    DESKTOP_LINUX_DOCTOR_SCRIPT="$DOCTOR_LINUX_FAKE" \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT="$NATIVE_BOOTSTRAP_LINUX_FAKE" \
    DESKTOP_LINUX_ONE_CLICK_SCRIPT="$ONE_CLICK_LINUX_FAKE" \
    DESKTOP_LINUX_PACKAGED_RUN_SCRIPT="$PACKAGED_RUN_LINUX_FAKE" \
    DESKTOP_LINUX_RELEASE_BUNDLE_SCRIPT="$RELEASE_BUNDLE_LINUX_FAKE" \
    DESKTOP_WINDOWS_DOCTOR_SCRIPT="$DOCTOR_WINDOWS_FAKE" \
    DESKTOP_WINDOWS_NATIVE_BOOTSTRAP_SCRIPT="$NATIVE_BOOTSTRAP_WINDOWS_FAKE" \
    DESKTOP_WINDOWS_ONE_CLICK_SCRIPT="$ONE_CLICK_WINDOWS_FAKE" \
    DESKTOP_WINDOWS_PACKAGED_RUN_SCRIPT="$PACKAGED_RUN_WINDOWS_FAKE" \
    DESKTOP_WINDOWS_RELEASE_BUNDLE_SCRIPT="$RELEASE_BUNDLE_WINDOWS_FAKE" \
    DESKTOP_WINDOWS_LOCAL_API_SESSION_SCRIPT="$LOCAL_API_WINDOWS_FAKE" \
    PATH="$RUNTIME_DIR:$PATH" \
    bash "$SCRIPT_UNDER_TEST" "$command_name" --platform windows "${forwarded_args[@]}" >"$STDOUT_OUT" 2>"$STDERR_OUT"

  assert_single_invocation "$RUNTIME_CAPTURE" "$command_name"
  assert_runtime_invocation "$RUNTIME_CAPTURE" "$expected_marker" "${forwarded_args[@]}"
}

create_fake_posix_wrapper_script "$DOCTOR_LINUX_FAKE" "desktop_linux_doctor" "FAKE_LINUX_DOCTOR_RC"
create_fake_posix_wrapper_script "$NATIVE_BOOTSTRAP_LINUX_FAKE" "desktop_linux_native_bootstrap" "FAKE_LINUX_NATIVE_BOOTSTRAP_RC"
create_fake_posix_wrapper_script "$ONE_CLICK_LINUX_FAKE" "desktop_linux_one_click" "FAKE_LINUX_ONE_CLICK_RC"
create_fake_posix_wrapper_script "$PACKAGED_RUN_LINUX_FAKE" "desktop_linux_packaged_run" "FAKE_LINUX_PACKAGED_RUN_RC"
create_fake_posix_wrapper_script "$RELEASE_BUNDLE_LINUX_FAKE" "desktop_linux_release_bundle" "FAKE_LINUX_RELEASE_BUNDLE_RC"
create_fake_posix_wrapper_script "$LOCAL_API_LINUX_FAKE" "desktop_linux_local_api_session" "FAKE_LINUX_LOCAL_API_SESSION_RC"
create_fake_ps1_placeholder "$DOCTOR_WINDOWS_FAKE"
create_fake_ps1_placeholder "$NATIVE_BOOTSTRAP_WINDOWS_FAKE"
create_fake_ps1_placeholder "$ONE_CLICK_WINDOWS_FAKE"
create_fake_ps1_placeholder "$PACKAGED_RUN_WINDOWS_FAKE"
create_fake_ps1_placeholder "$RELEASE_BUNDLE_WINDOWS_FAKE"
create_fake_ps1_placeholder "$LOCAL_API_WINDOWS_FAKE"
create_fake_go_script "$TMP_DIR/go"

echo "[easy-node-desktop-wrappers] help contract"
bash "$SCRIPT_UNDER_TEST" help >"$HELP_OUT"
assert_help_contains "./scripts/easy_node.sh desktop-doctor [--platform auto|linux|windows] [desktop_doctor args...]"
assert_help_contains "./scripts/easy_node.sh desktop-native-bootstrap [--platform auto|linux|windows] [desktop_native_bootstrap args...]"
assert_help_contains "./scripts/easy_node.sh desktop-one-click [--platform auto|linux|windows] [desktop_one_click args...]"
assert_help_contains "./scripts/easy_node.sh desktop-packaged-run [--platform auto|linux|windows] [desktop_packaged_run args...]"
assert_help_contains "./scripts/easy_node.sh desktop-release-bundle [--platform auto|linux|windows] [desktop_release_bundle args...]"
assert_help_contains "./scripts/easy_node.sh desktop-local-api-session [--platform auto|linux|windows] [local_api_session args...]"

echo "[easy-node-desktop-wrappers] explicit linux routing"
run_linux_command \
  "desktop-doctor" \
  "desktop_linux_doctor" \
  "--reports-dir" "$TMP_DIR/reports doctor with spaces" \
  "--summary-json" "$TMP_DIR/summary doctor with spaces.json" \
  "--sample-flag" "doctor value with spaces"

run_linux_command \
  "desktop-native-bootstrap" \
  "desktop_linux_native_bootstrap" \
  "--mode" "bootstrap" \
  "--sample-flag" "native bootstrap value with spaces"

run_linux_command \
  "desktop-one-click" \
  "desktop_linux_one_click" \
  "--no-install-missing" \
  "--sample-flag" "one click value with spaces"

run_linux_command \
  "desktop-packaged-run" \
  "desktop_linux_packaged_run" \
  "--no-install-missing" \
  "--dry-run" \
  "--sample-flag" "packaged run value with spaces"

run_linux_command \
  "desktop-release-bundle" \
  "desktop_linux_release_bundle" \
  "--bundle-dir" "$TMP_DIR/release bundle with spaces" \
  "--sample-flag" "release bundle value with spaces"

echo "[easy-node-desktop-wrappers] explicit windows routing"
run_windows_command \
  "desktop-doctor" \
  "$DOCTOR_WINDOWS_FAKE" \
  "--sample-flag" "doctor value with spaces"

run_windows_command \
  "desktop-native-bootstrap" \
  "$NATIVE_BOOTSTRAP_WINDOWS_FAKE" \
  "--sample-flag" "native bootstrap value with spaces"

run_windows_command \
  "desktop-one-click" \
  "$ONE_CLICK_WINDOWS_FAKE" \
  "-InstallMissing:\$false" \
  "--sample-flag" "one click value with spaces"

run_windows_command \
  "desktop-packaged-run" \
  "$PACKAGED_RUN_WINDOWS_FAKE" \
  "-InstallMissing:\$false" \
  "--sample-flag" "packaged run value with spaces"

run_windows_command \
  "desktop-release-bundle" \
  "$RELEASE_BUNDLE_WINDOWS_FAKE" \
  "--bundle-dir" "$TMP_DIR/release bundle with spaces" \
  "--sample-flag" "release bundle value with spaces"

echo "[easy-node-desktop-wrappers] auto mode via EASY_NODE_DESKTOP_PLATFORM"
: >"$CAPTURE"
env \
  EASY_NODE_DESKTOP_PLATFORM=linux \
  EASY_NODE_DESKTOP_WRAPPERS_CAPTURE_FILE="$CAPTURE" \
  DESKTOP_LINUX_DOCTOR_SCRIPT="$DOCTOR_LINUX_FAKE" \
  bash "$SCRIPT_UNDER_TEST" desktop-doctor --sample-flag "auto linux value" >"$STDOUT_OUT" 2>"$STDERR_OUT"
assert_single_invocation "$CAPTURE" "desktop-doctor auto linux"
assert_forwarded_exact "$CAPTURE" "desktop_linux_doctor" "--sample-flag" "auto linux value"

: >"$RUNTIME_CAPTURE"
mkdir -p "$RUNTIME_DIR"
create_fake_runtime_script "$RUNTIME_DIR/powershell.exe" "powershell.exe"
create_fake_runtime_script "$RUNTIME_DIR/pwsh" "pwsh"
create_fake_runtime_script "$RUNTIME_DIR/powershell" "powershell"
env \
  EASY_NODE_DESKTOP_PLATFORM=windows \
  EASY_NODE_DESKTOP_WRAPPERS_RUNTIME_CAPTURE_FILE="$RUNTIME_CAPTURE" \
  DESKTOP_WINDOWS_DOCTOR_SCRIPT="$DOCTOR_WINDOWS_FAKE" \
  PATH="$RUNTIME_DIR:$PATH" \
  bash "$SCRIPT_UNDER_TEST" desktop-doctor --sample-flag "auto windows value" >"$STDOUT_OUT" 2>"$STDERR_OUT"
assert_single_invocation "$RUNTIME_CAPTURE" "desktop-doctor auto windows"
assert_runtime_invocation "$RUNTIME_CAPTURE" "$DOCTOR_WINDOWS_FAKE" "--sample-flag" "auto windows value"

echo "[easy-node-desktop-wrappers] local-api session routing"
: >"$GO_CAPTURE"
env \
  EASY_NODE_DESKTOP_WRAPPERS_GO_CAPTURE_FILE="$GO_CAPTURE" \
  PATH="$TMP_DIR:$PATH" \
  bash "$SCRIPT_UNDER_TEST" \
    desktop-local-api-session \
    --platform linux \
    --api-addr 127.0.0.1:9999 \
    --script-path "$LOCAL_API_LINUX_FAKE" \
    --config "$TMP_DIR/node.conf" \
    --dry-run 0 \
    --command-timeout-sec 10 >"$STDOUT_OUT" 2>"$STDERR_OUT"
assert_go_invocation "$GO_CAPTURE" run ./cmd/node --config "$TMP_DIR/node.conf" --local-api
if ! grep -F -- "script_path: $LOCAL_API_LINUX_FAKE" "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "local-api-session linux output missing resolved script path"
  cat "$STDOUT_OUT"
  exit 1
fi

set +e
: >"$GO_CAPTURE"
env \
  EASY_NODE_DESKTOP_WRAPPERS_GO_CAPTURE_FILE="$GO_CAPTURE" \
  PATH="$TMP_DIR:$PATH" \
  FAKE_LINUX_LOCAL_API_GO_RC=19 \
  bash "$SCRIPT_UNDER_TEST" \
    desktop-local-api-session \
    --platform linux \
    --api-addr 127.0.0.1:9999 \
    --script-path "$LOCAL_API_LINUX_FAKE" \
    --config "$TMP_DIR/node.conf" >"$STDOUT_OUT" 2>"$STDERR_OUT"
rc=$?
set -e
if [[ "$rc" -ne 19 ]]; then
  echo "expected local-api-session linux path to return fake go exit code 19, got $rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi

: >"$RUNTIME_CAPTURE"
mkdir -p "$RUNTIME_DIR"
create_fake_runtime_script "$RUNTIME_DIR/powershell.exe" "powershell.exe"
create_fake_runtime_script "$RUNTIME_DIR/pwsh" "pwsh"
create_fake_runtime_script "$RUNTIME_DIR/powershell" "powershell"
env \
  EASY_NODE_DESKTOP_WRAPPERS_RUNTIME_CAPTURE_FILE="$RUNTIME_CAPTURE" \
  DESKTOP_WINDOWS_LOCAL_API_SESSION_SCRIPT="$LOCAL_API_WINDOWS_FAKE" \
  PATH="$RUNTIME_DIR:$PATH" \
  bash "$SCRIPT_UNDER_TEST" \
    desktop-local-api-session \
    --platform windows \
    --sample-flag "local api session value with spaces" >"$STDOUT_OUT" 2>"$STDERR_OUT"
assert_runtime_invocation \
  "$RUNTIME_CAPTURE" \
  "$LOCAL_API_WINDOWS_FAKE" \
  "--sample-flag" "local api session value with spaces"

echo "[easy-node-desktop-wrappers] exit semantics contract"
set +e
env \
  EASY_NODE_DESKTOP_WRAPPERS_CAPTURE_FILE="$CAPTURE" \
  DESKTOP_LINUX_PACKAGED_RUN_SCRIPT="$PACKAGED_RUN_LINUX_FAKE" \
  FAKE_LINUX_PACKAGED_RUN_RC=13 \
  bash "$SCRIPT_UNDER_TEST" desktop-packaged-run --platform linux --sample-flag "rc passthrough" >"$STDOUT_OUT" 2>"$STDERR_OUT"
rc=$?
set -e
if [[ "$rc" -ne 13 ]]; then
  echo "expected easy_node wrapper to return fake script exit code 13, got $rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi

set +e
env \
  EASY_NODE_DESKTOP_WRAPPERS_RUNTIME_CAPTURE_FILE="$RUNTIME_CAPTURE" \
  DESKTOP_WINDOWS_PACKAGED_RUN_SCRIPT="$PACKAGED_RUN_WINDOWS_FAKE" \
  PATH="$RUNTIME_DIR:$PATH" \
  FAKE_WINDOWS_RUNTIME_RC=17 \
  bash "$SCRIPT_UNDER_TEST" desktop-packaged-run --platform windows --sample-flag "rc passthrough" >"$STDOUT_OUT" 2>"$STDERR_OUT"
rc=$?
set -e
if [[ "$rc" -ne 17 ]]; then
  echo "expected easy_node wrapper to return fake runtime exit code 17, got $rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi

set +e
env \
  bash "$SCRIPT_UNDER_TEST" desktop-doctor --platform nebula >"$STDOUT_OUT" 2>"$STDERR_OUT"
rc=$?
set -e
if [[ "$rc" -ne 2 ]]; then
  echo "expected invalid platform to exit 2, got $rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi
if ! grep -F -- "invalid --platform value: nebula; expected auto, linux, or windows" "$STDERR_OUT" >/dev/null 2>&1; then
  echo "missing helpful invalid platform message"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi

echo "easy-node desktop wrappers integration check ok"
