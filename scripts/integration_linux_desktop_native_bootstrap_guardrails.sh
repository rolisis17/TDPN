#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SCRIPT_UNDER_TEST="${DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/linux/desktop_native_bootstrap.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "linux desktop native bootstrap guardrails failed: missing script: $SCRIPT_UNDER_TEST"
  exit 1
fi

TMP_DIR="$(mktemp -d)"
PACKAGED_DEFAULT_CREATED="0"
SYSTEM_BASH="$(command -v bash)"
SYSTEM_DIRNAME="$(command -v dirname)"
SYSTEM_BASENAME="$(command -v basename)"
cleanup() {
  if [[ "$PACKAGED_DEFAULT_CREATED" == "1" ]]; then
    rm -f "${FAKE_PACKAGED_DEFAULT:-}"
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

make_exec_wrapper() {
  local target_path="$1"
  local target_command="$2"
  cat >"$target_path" <<EOF
#!/bin/sh
exec "$target_command" "\$@"
EOF
  chmod +x "$target_path"
}

make_exit_zero_wrapper() {
  local target_path="$1"
  cat >"$target_path" <<'EOF'
#!/bin/sh
exit 0
EOF
  chmod +x "$target_path"
}

make_pkg_config_stub() {
  local target_path="$1"
  cat >"$target_path" <<'EOF'
#!/bin/sh
if [ "$1" = "--exists" ]; then
  case "$2" in
    gtk+-3.0|webkit2gtk-4.1|webkit2gtk-4.0|libsoup-3.0|javascriptcoregtk-4.1|javascriptcoregtk-4.0)
      exit 0
      ;;
  esac
fi
exit 1
EOF
  chmod +x "$target_path"
}

make_pkg_config_fail_stub() {
  local target_path="$1"
  cat >"$target_path" <<'EOF'
#!/bin/sh
exit 1
EOF
  chmod +x "$target_path"
}

assert_script_marker() {
  local marker="$1"
  if grep -Fq -- "$marker" "$SCRIPT_UNDER_TEST"; then
    return 0
  fi
  echo "linux desktop native bootstrap guardrails failed: missing marker in script: $marker"
  exit 1
}

run_expect_pass() {
  local name="$1"
  shift
  local log_path="$TMP_DIR/${name}.log"
  if "$@" >"$log_path" 2>&1; then
    return 0
  fi
  echo "linux desktop native bootstrap guardrails failed: expected pass for $name"
  cat "$log_path"
  exit 1
}

run_expect_fail_regex() {
  local name="$1"
  local expected_pattern="$2"
  shift 2
  local log_path="$TMP_DIR/${name}.log"
  if "$@" >"$log_path" 2>&1; then
    echo "linux desktop native bootstrap guardrails failed: expected failure for $name"
    cat "$log_path"
    exit 1
  fi
  if ! grep -Eiq -- "$expected_pattern" "$log_path"; then
    echo "linux desktop native bootstrap guardrails failed: missing expected failure text for $name"
    echo "expected regex: $expected_pattern"
    cat "$log_path"
    exit 1
  fi
}

echo "[linux-desktop-native-bootstrap-guardrails] summary markers present"
assert_script_marker "--summary-json"
assert_script_marker "--print-summary-json"
assert_script_marker "recommended_commands"
assert_script_marker "emit_summary_payload"
assert_script_marker "write_summary_json_file"
assert_script_marker "GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE"
assert_script_marker "GPM_DESKTOP_PACKAGED_EXE"
assert_script_marker "TDPN_DESKTOP_PACKAGED_EXE"
assert_script_marker "assert_native_desktop_prerequisites_for_dev"
assert_script_marker "assert_runtime_toolchain_prerequisites_for_dev"
assert_script_marker "assert_go_runtime_prerequisite_for_api"
assert_script_marker "runtime_tool_label"
assert_script_marker "runtime_tool_install_hint"
assert_script_marker "build_linux_desktop_first_run_distro_hints"
assert_script_marker "missing native Linux desktop prerequisites required for Tauri dev mode"
assert_script_marker "pkg-config"
assert_script_marker "libgtk-3-dev"
assert_script_marker "libwebkit2gtk-4.1-dev"
assert_script_marker "libsoup-3.0-dev"
assert_script_marker "libjavascriptcoregtk-4.1-dev"
assert_script_marker "Debian/Ubuntu:"
assert_script_marker "Fedora/RHEL:"
assert_script_marker "Arch:"
assert_script_marker "openSUSE:"

echo "[linux-desktop-native-bootstrap-guardrails] check --dry-run passes"
run_expect_pass \
  "check_dry_run_pass" \
  bash "$SCRIPT_UNDER_TEST" \
    --mode check \
    --dry-run

echo "[linux-desktop-native-bootstrap-guardrails] bootstrap --dry-run passes"
run_expect_pass \
  "bootstrap_dry_run_pass" \
  bash "$SCRIPT_UNDER_TEST" \
    --mode bootstrap \
    --dry-run

echo "[linux-desktop-native-bootstrap-guardrails] run-full --dry-run passes"
run_expect_pass \
  "run_full_dry_run_pass" \
  bash "$SCRIPT_UNDER_TEST" \
    --mode run-full \
    --desktop-launch-strategy auto \
    --dry-run

FAKE_RUNTIME_BIN_DIR="$TMP_DIR/fake-runtime-bin"
mkdir -p "$FAKE_RUNTIME_BIN_DIR"
make_exec_wrapper "$FAKE_RUNTIME_BIN_DIR/bash" "$SYSTEM_BASH"
make_exec_wrapper "$FAKE_RUNTIME_BIN_DIR/dirname" "$SYSTEM_DIRNAME"
make_exec_wrapper "$FAKE_RUNTIME_BIN_DIR/basename" "$SYSTEM_BASENAME"

echo "[linux-desktop-native-bootstrap-guardrails] run-desktop dev fails fast when runtime toolchain is missing"
run_expect_fail_regex \
  "run_desktop_dev_missing_runtime_fail" \
  "missing Linux runtime prerequisites for desktop dev launch|Node\\.js command 'node' is missing|npm command 'npm' is missing|Debian/Ubuntu: .*apt-get install -y .*nodejs" \
  env \
    PATH="$FAKE_RUNTIME_BIN_DIR" \
    bash "$SCRIPT_UNDER_TEST" \
      --mode run-desktop \
      --desktop-launch-strategy dev

FAKE_DEV_BIN_DIR="$TMP_DIR/fake-dev-bin"
mkdir -p "$FAKE_DEV_BIN_DIR"
make_exec_wrapper "$FAKE_DEV_BIN_DIR/bash" "$SYSTEM_BASH"
make_exec_wrapper "$FAKE_DEV_BIN_DIR/dirname" "$SYSTEM_DIRNAME"
make_exec_wrapper "$FAKE_DEV_BIN_DIR/basename" "$SYSTEM_BASENAME"
make_exit_zero_wrapper "$FAKE_DEV_BIN_DIR/node"
make_exit_zero_wrapper "$FAKE_DEV_BIN_DIR/npm"
make_exit_zero_wrapper "$FAKE_DEV_BIN_DIR/rustc"
make_exit_zero_wrapper "$FAKE_DEV_BIN_DIR/cargo"
make_pkg_config_fail_stub "$FAKE_DEV_BIN_DIR/pkg-config"

echo "[linux-desktop-native-bootstrap-guardrails] run-desktop dev fails on missing native prerequisites after runtime toolchain passes"
run_expect_fail_regex \
  "run_desktop_dev_missing_native_fail" \
  "missing native Linux desktop prerequisites required for Tauri dev mode|desktop_doctor\\.sh --mode fix --install-missing|libsoup-3\\.0-dev" \
  env \
    PATH="$FAKE_DEV_BIN_DIR" \
    bash "$SCRIPT_UNDER_TEST" \
      --mode run-desktop \
      --desktop-launch-strategy dev

FAKE_FULL_BIN_DIR="$TMP_DIR/fake-full-bin"
mkdir -p "$FAKE_FULL_BIN_DIR"
make_exec_wrapper "$FAKE_FULL_BIN_DIR/bash" "$SYSTEM_BASH"
make_exec_wrapper "$FAKE_FULL_BIN_DIR/dirname" "$SYSTEM_DIRNAME"
make_exec_wrapper "$FAKE_FULL_BIN_DIR/basename" "$SYSTEM_BASENAME"
make_exit_zero_wrapper "$FAKE_FULL_BIN_DIR/node"
make_exit_zero_wrapper "$FAKE_FULL_BIN_DIR/npm"
make_exit_zero_wrapper "$FAKE_FULL_BIN_DIR/rustc"
make_exit_zero_wrapper "$FAKE_FULL_BIN_DIR/cargo"
make_pkg_config_stub "$FAKE_FULL_BIN_DIR/pkg-config"

echo "[linux-desktop-native-bootstrap-guardrails] run-full dev fails with explicit Go remediation when API startup prerequisites are missing"
run_expect_fail_regex \
  "run_full_missing_go_fail" \
  "missing Go runtime prerequisite for local API startup|Go toolchain command 'go' is missing|Debian/Ubuntu: .*apt-get install -y golang-go" \
  env \
    PATH="$FAKE_FULL_BIN_DIR" \
    bash "$SCRIPT_UNDER_TEST" \
      --mode run-full \
      --desktop-launch-strategy dev \
      --api-addr 127.0.0.1:8095

echo "[linux-desktop-native-bootstrap-guardrails] invalid mode fails"
run_expect_fail_regex \
  "invalid_mode_fail" \
  "invalid --mode|unsupported mode|unknown mode|mode" \
  bash "$SCRIPT_UNDER_TEST" \
    --mode invalid-mode \
    --dry-run

echo "[linux-desktop-native-bootstrap-guardrails] --print-summary-json with invalid value fails"
run_expect_fail_regex \
  "invalid_print_summary_json_fail" \
  "print-summary-json|expected 0\\|1|invalid" \
  bash "$SCRIPT_UNDER_TEST" \
    --mode check \
    --dry-run \
    --print-summary-json 2

assert_summary_json_field_equals() {
  local summary_path="$1"
  local key="$2"
  local expected_value="$3"
  local escaped_expected
  escaped_expected="$(printf '%s' "$expected_value" | sed -e 's/[.[\*^$()+?{|]/\\&/g')"
  if grep -Eiq "\"$key\"[[:space:]]*:[[:space:]]*\"$escaped_expected\"" "$summary_path"; then
    return 0
  fi
  echo "linux desktop native bootstrap guardrails failed: summary file missing expected $key=$expected_value"
  cat "$summary_path"
  exit 1
}

FAKE_EXECUTABLE_ENV_GLOBAL="$TMP_DIR/global-private-mesh-desktop"
printf '%s\n' "placeholder executable for GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE guardrails" >"$FAKE_EXECUTABLE_ENV_GLOBAL"
chmod +x "$FAKE_EXECUTABLE_ENV_GLOBAL"

FAKE_EXECUTABLE_ENV_GPM="$TMP_DIR/gpm-desktop"
printf '%s\n' "placeholder executable for GPM_DESKTOP_PACKAGED_EXE guardrails" >"$FAKE_EXECUTABLE_ENV_GPM"
chmod +x "$FAKE_EXECUTABLE_ENV_GPM"

FAKE_EXECUTABLE_ENV_TDPN="$TMP_DIR/tdpn-desktop"
printf '%s\n' "placeholder executable for TDPN_DESKTOP_PACKAGED_EXE guardrails" >"$FAKE_EXECUTABLE_ENV_TDPN"
chmod +x "$FAKE_EXECUTABLE_ENV_TDPN"

FAKE_EXECUTABLE_OVERRIDE="$TMP_DIR/explicit-override-desktop"
printf '%s\n' "placeholder executable for explicit override guardrails" >"$FAKE_EXECUTABLE_OVERRIDE"
chmod +x "$FAKE_EXECUTABLE_OVERRIDE"

PACKAGED_RELEASE_DIR="$ROOT_DIR/apps/desktop/src-tauri/target/release"
FAKE_PACKAGED_DEFAULT="$PACKAGED_RELEASE_DIR/gpm-desktop"
if [[ ! -f "$FAKE_PACKAGED_DEFAULT" ]]; then
  mkdir -p "$PACKAGED_RELEASE_DIR"
  printf '%s\n' "placeholder executable for packaged-default guardrails" >"$FAKE_PACKAGED_DEFAULT"
  chmod +x "$FAKE_PACKAGED_DEFAULT"
  PACKAGED_DEFAULT_CREATED="1"
fi

SUMMARY_ENV_PRIORITY_PATH="$TMP_DIR/run_desktop_env_priority_summary.json"
SUMMARY_GLOBAL_ONLY_PATH="$TMP_DIR/run_desktop_env_global_summary.json"
SUMMARY_TDPN_ONLY_PATH="$TMP_DIR/run_desktop_env_tdpn_summary.json"
SUMMARY_OVERRIDE_PATH="$TMP_DIR/run_desktop_override_summary.json"
SUMMARY_PACKAGED_DEFAULT_PATH="$TMP_DIR/run_desktop_packaged_default_summary.json"

echo "[linux-desktop-native-bootstrap-guardrails] env override priority prefers GPM_DESKTOP_PACKAGED_EXE under --dry-run"
run_expect_pass \
  "run_desktop_env_priority_dry_run_pass" \
  env \
    GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE="$FAKE_EXECUTABLE_ENV_GLOBAL" \
    GPM_DESKTOP_PACKAGED_EXE="$FAKE_EXECUTABLE_ENV_GPM" \
    TDPN_DESKTOP_PACKAGED_EXE="$FAKE_EXECUTABLE_ENV_TDPN" \
    bash "$SCRIPT_UNDER_TEST" \
      --mode run-desktop \
      --desktop-launch-strategy packaged \
      --dry-run \
      --summary-json "$SUMMARY_ENV_PRIORITY_PATH"
assert_summary_json_field_equals "$SUMMARY_ENV_PRIORITY_PATH" "resolved_desktop_launch_strategy" "packaged"
assert_summary_json_field_equals "$SUMMARY_ENV_PRIORITY_PATH" "resolved_desktop_executable_path" "$FAKE_EXECUTABLE_ENV_GPM"
assert_summary_json_field_equals "$SUMMARY_ENV_PRIORITY_PATH" "resolved_desktop_executable_source" "env-override:GPM_DESKTOP_PACKAGED_EXE"

echo "[linux-desktop-native-bootstrap-guardrails] env override fallback uses GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE when GPM_DESKTOP_PACKAGED_EXE is unset"
run_expect_pass \
  "run_desktop_env_global_dry_run_pass" \
  env \
    GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE="$FAKE_EXECUTABLE_ENV_GLOBAL" \
    TDPN_DESKTOP_PACKAGED_EXE="$FAKE_EXECUTABLE_ENV_TDPN" \
    bash "$SCRIPT_UNDER_TEST" \
      --mode run-desktop \
      --desktop-launch-strategy packaged \
      --dry-run \
      --summary-json "$SUMMARY_GLOBAL_ONLY_PATH"
assert_summary_json_field_equals "$SUMMARY_GLOBAL_ONLY_PATH" "resolved_desktop_launch_strategy" "packaged"
assert_summary_json_field_equals "$SUMMARY_GLOBAL_ONLY_PATH" "resolved_desktop_executable_path" "$FAKE_EXECUTABLE_ENV_GLOBAL"
assert_summary_json_field_equals "$SUMMARY_GLOBAL_ONLY_PATH" "resolved_desktop_executable_source" "env-override:GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE"

echo "[linux-desktop-native-bootstrap-guardrails] env override fallback uses TDPN_DESKTOP_PACKAGED_EXE under --dry-run"
run_expect_pass \
  "run_desktop_env_tdpn_dry_run_pass" \
  env \
    TDPN_DESKTOP_PACKAGED_EXE="$FAKE_EXECUTABLE_ENV_TDPN" \
    bash "$SCRIPT_UNDER_TEST" \
      --mode run-desktop \
      --desktop-launch-strategy packaged \
      --dry-run \
      --summary-json "$SUMMARY_TDPN_ONLY_PATH"
assert_summary_json_field_equals "$SUMMARY_TDPN_ONLY_PATH" "resolved_desktop_launch_strategy" "packaged"
assert_summary_json_field_equals "$SUMMARY_TDPN_ONLY_PATH" "resolved_desktop_executable_path" "$FAKE_EXECUTABLE_ENV_TDPN"
assert_summary_json_field_equals "$SUMMARY_TDPN_ONLY_PATH" "resolved_desktop_executable_source" "env-override:TDPN_DESKTOP_PACKAGED_EXE"

echo "[linux-desktop-native-bootstrap-guardrails] explicit override path beats env overrides under --dry-run"
run_expect_pass \
  "run_desktop_override_beats_env_dry_run_pass" \
  env \
    GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE="$FAKE_EXECUTABLE_ENV_GLOBAL" \
    GPM_DESKTOP_PACKAGED_EXE="$FAKE_EXECUTABLE_ENV_GPM" \
    TDPN_DESKTOP_PACKAGED_EXE="$FAKE_EXECUTABLE_ENV_TDPN" \
    bash "$SCRIPT_UNDER_TEST" \
      --mode run-desktop \
      --desktop-launch-strategy packaged \
      --desktop-executable-override-path "$FAKE_EXECUTABLE_OVERRIDE" \
      --dry-run \
      --summary-json "$SUMMARY_OVERRIDE_PATH"
assert_summary_json_field_equals "$SUMMARY_OVERRIDE_PATH" "resolved_desktop_launch_strategy" "packaged"
assert_summary_json_field_equals "$SUMMARY_OVERRIDE_PATH" "resolved_desktop_executable_path" "$FAKE_EXECUTABLE_OVERRIDE"
assert_summary_json_field_equals "$SUMMARY_OVERRIDE_PATH" "resolved_desktop_executable_source" "override-path"

echo "[linux-desktop-native-bootstrap-guardrails] packaged-default source is reported under --dry-run"
run_expect_pass \
  "run_desktop_packaged_default_dry_run_pass" \
  bash "$SCRIPT_UNDER_TEST" \
    --mode run-desktop \
    --desktop-launch-strategy packaged \
    --dry-run \
    --summary-json "$SUMMARY_PACKAGED_DEFAULT_PATH"
assert_summary_json_field_equals "$SUMMARY_PACKAGED_DEFAULT_PATH" "resolved_desktop_launch_strategy" "packaged"
assert_summary_json_field_equals "$SUMMARY_PACKAGED_DEFAULT_PATH" "resolved_desktop_executable_path" "$FAKE_PACKAGED_DEFAULT"
assert_summary_json_field_equals "$SUMMARY_PACKAGED_DEFAULT_PATH" "resolved_desktop_executable_source" "packaged-default"

echo "[linux-desktop-native-bootstrap-guardrails] check --dry-run --print-summary-json emits summary payload"
SUMMARY_PRINT_LOG="$TMP_DIR/check_dry_run_print_summary.log"
if ! bash "$SCRIPT_UNDER_TEST" --mode check --dry-run --print-summary-json 1 >"$SUMMARY_PRINT_LOG" 2>&1; then
  echo "linux desktop native bootstrap guardrails failed: check dry-run summary print command failed"
  cat "$SUMMARY_PRINT_LOG"
  exit 1
fi
if ! grep -Eiq '"mode"[[:space:]]*:[[:space:]]*"check"' "$SUMMARY_PRINT_LOG"; then
  echo "linux desktop native bootstrap guardrails failed: summary print missing mode=check"
  cat "$SUMMARY_PRINT_LOG"
  exit 1
fi
if ! grep -Eiq '"status"[[:space:]]*:[[:space:]]*"ok"' "$SUMMARY_PRINT_LOG"; then
  echo "linux desktop native bootstrap guardrails failed: summary print missing status=ok"
  cat "$SUMMARY_PRINT_LOG"
  exit 1
fi
if ! grep -Eiq '"recommended_commands"[[:space:]]*:' "$SUMMARY_PRINT_LOG"; then
  echo "linux desktop native bootstrap guardrails failed: summary print missing recommended_commands"
  cat "$SUMMARY_PRINT_LOG"
  exit 1
fi
if ! grep -Eiq 'recommended remediation commands' "$SUMMARY_PRINT_LOG"; then
  echo "linux desktop native bootstrap guardrails failed: summary print missing remediation guidance log"
  cat "$SUMMARY_PRINT_LOG"
  exit 1
fi

echo "[linux-desktop-native-bootstrap-guardrails] check --dry-run writes summary json payload"
SUMMARY_JSON_PATH="$TMP_DIR/check_dry_run_summary.json"
SUMMARY_FILE_LOG="$TMP_DIR/check_dry_run_summary_file.log"
if ! bash "$SCRIPT_UNDER_TEST" --mode check --dry-run --summary-json "$SUMMARY_JSON_PATH" >"$SUMMARY_FILE_LOG" 2>&1; then
  echo "linux desktop native bootstrap guardrails failed: check dry-run summary file command failed"
  cat "$SUMMARY_FILE_LOG"
  exit 1
fi
if [[ ! -f "$SUMMARY_JSON_PATH" ]]; then
  echo "linux desktop native bootstrap guardrails failed: summary json file not written: $SUMMARY_JSON_PATH"
  cat "$SUMMARY_FILE_LOG"
  exit 1
fi
if ! grep -Eiq '"recommended_commands"[[:space:]]*:' "$SUMMARY_JSON_PATH"; then
  echo "linux desktop native bootstrap guardrails failed: summary file missing recommended_commands"
  cat "$SUMMARY_JSON_PATH"
  exit 1
fi
if ! grep -Eiq '"mode"[[:space:]]*:[[:space:]]*"check"' "$SUMMARY_JSON_PATH"; then
  echo "linux desktop native bootstrap guardrails failed: summary file missing mode=check"
  cat "$SUMMARY_JSON_PATH"
  exit 1
fi

echo "linux desktop native bootstrap guardrails integration check ok"
