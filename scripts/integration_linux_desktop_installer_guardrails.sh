#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq grep mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${DESKTOP_LINUX_INSTALLER_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/linux/desktop_installer.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "linux desktop installer guardrails failed: missing script: $SCRIPT_UNDER_TEST"
  exit 1
fi
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "linux desktop installer guardrails failed: script is not executable: $SCRIPT_UNDER_TEST"
  exit 1
fi

TMP_DIR="$(mktemp -d)"
SYSTEM_BASH="$(command -v bash)"
SYSTEM_DIRNAME="$(command -v dirname)"
SYSTEM_BASENAME="$(command -v basename)"
SYSTEM_CAT="$(command -v cat)"
SYSTEM_DATE="$(command -v date)"
SYSTEM_MKDIR="$(command -v mkdir)"
cleanup() {
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

run_expect_pass() {
  local name="$1"
  shift
  local log_path="$TMP_DIR/${name}.log"
  if "$@" >"$log_path" 2>&1; then
    return 0
  fi
  echo "linux desktop installer guardrails failed: expected pass for $name"
  cat "$log_path"
  exit 1
}

run_expect_fail_regex() {
  local name="$1"
  local expected_pattern="$2"
  shift 2
  local log_path="$TMP_DIR/${name}.log"
  if "$@" >"$log_path" 2>&1; then
    echo "linux desktop installer guardrails failed: expected failure for $name"
    cat "$log_path"
    exit 1
  fi
  if ! grep -Eiq -- "$expected_pattern" "$log_path"; then
    echo "linux desktop installer guardrails failed: missing expected failure text for $name"
    echo "expected regex: $expected_pattern"
    cat "$log_path"
    exit 1
  fi
}

assert_file_contains_fixed() {
  local file_path="$1"
  local expected_text="$2"
  local context_label="$3"
  if ! grep -F -- "$expected_text" "$file_path" >/dev/null 2>&1; then
    echo "linux desktop installer guardrails failed: missing expected marker for $context_label"
    echo "expected text: $expected_text"
    cat "$file_path"
    exit 1
  fi
}

assert_json_predicate() {
  local file_path="$1"
  local predicate="$2"
  local context_label="$3"
  if ! jq -e "$predicate" "$file_path" >/dev/null 2>&1; then
    echo "linux desktop installer guardrails failed: summary json assertion failed for $context_label"
    echo "predicate: $predicate"
    cat "$file_path"
    exit 1
  fi
}

echo "[linux-desktop-installer-guardrails] option markers are present"
for marker in \
  "--installer-path" \
  "--installer-type" \
  "--build-if-missing" \
  "--dry-run" \
  "--launch-after-install" \
  "--installed-executable" \
  "--summary-json" \
  "--print-summary-json"
do
  if ! grep -Fq -- "$marker" "$SCRIPT_UNDER_TEST"; then
    echo "linux desktop installer guardrails failed: missing required option marker in script: $marker"
    exit 1
  fi
done

echo "[linux-desktop-installer-guardrails] first-run remediation markers are present"
for marker in \
  "command_available()" \
  "availability_label()" \
  "build_package_manager_remediation_hints()" \
  "build_installer_first_run_hints()" \
  "log_installer_package_manager_availability()" \
  "preflight package-manager availability:" \
  "no supported DEB installer command found" \
  "no supported RPM installer command found" \
  "non-root DEB install requires sudo" \
  "non-root RPM install requires sudo" \
  "Debian/Ubuntu:" \
  "Fedora/RHEL:" \
  "Arch:" \
  "openSUSE:"
do
  if ! grep -Fq -- "$marker" "$SCRIPT_UNDER_TEST"; then
    echo "linux desktop installer guardrails failed: missing required first-run marker in script: $marker"
    exit 1
  fi
done

echo "[linux-desktop-installer-guardrails] deb/rpm command-path markers are present"
for marker in \
  "apt install -y" \
  "apt-get install -y" \
  "dpkg -i" \
  "dnf install -y" \
  "yum install -y" \
  "zypper --non-interactive install" \
  "rpm -i" \
  "gpm-desktop" \
  "global-private-mesh-desktop" \
  "non-root DEB install requires sudo" \
  "non-root RPM install requires sudo"
do
  if ! grep -Fq -- "$marker" "$SCRIPT_UNDER_TEST"; then
    echo "linux desktop installer guardrails failed: missing required command-path marker in script: $marker"
    exit 1
  fi
done

echo "[linux-desktop-installer-guardrails] --help passes and includes usage line"
run_expect_pass \
  "help_pass" \
  "$SCRIPT_UNDER_TEST" \
    --help
assert_file_contains_fixed "$TMP_DIR/help_pass.log" "Usage:" "help usage header"
assert_file_contains_fixed "$TMP_DIR/help_pass.log" "./scripts/linux/desktop_installer.sh [options]" "help usage command line"

FAKE_APPIMAGE_PATH="$TMP_DIR/fake-desktop.AppImage"
printf '%s\n' "fake appimage artifact for dry-run integration checks" >"$FAKE_APPIMAGE_PATH"

PASS_SUMMARY_JSON="$TMP_DIR/dry_run_explicit_appimage_summary.json"
echo "[linux-desktop-installer-guardrails] explicit .AppImage dry-run passes and writes expected summary fields"
run_expect_pass \
  "dry_run_explicit_appimage_pass" \
  "$SCRIPT_UNDER_TEST" \
    --installer-path "$FAKE_APPIMAGE_PATH" \
    --installer-type appimage \
    --dry-run \
    --launch-after-install 1 \
    --installed-executable "$FAKE_APPIMAGE_PATH" \
    --summary-json "$PASS_SUMMARY_JSON" \
    --print-summary-json 0
if [[ ! -f "$PASS_SUMMARY_JSON" ]]; then
  echo "linux desktop installer guardrails failed: missing summary json for explicit appimage dry-run"
  exit 1
fi
assert_json_predicate "$PASS_SUMMARY_JSON" '.status == "ok"' "dry-run status"
assert_json_predicate "$PASS_SUMMARY_JSON" '.platform == "linux"' "dry-run platform"
assert_json_predicate "$PASS_SUMMARY_JSON" '.installer_type == "appimage"' "dry-run installer_type"
assert_json_predicate "$PASS_SUMMARY_JSON" '.installer_source == "explicit"' "dry-run installer_source"
assert_json_predicate "$PASS_SUMMARY_JSON" '.dry_run == true' "dry-run flag"
assert_json_predicate "$PASS_SUMMARY_JSON" '.launch_after_install == true' "dry-run launch_after_install flag"
assert_json_predicate "$PASS_SUMMARY_JSON" '.installed_executable | type == "string" and length > 0' "dry-run installed_executable marker"
assert_json_predicate "$PASS_SUMMARY_JSON" '.launch_attempted == true' "dry-run launch_attempted flag"
assert_json_predicate "$PASS_SUMMARY_JSON" '.launch_status == "would_run"' "dry-run launch_status marker"
assert_json_predicate "$PASS_SUMMARY_JSON" '.launch_command | type == "string" and length > 0' "dry-run launch_command marker"
assert_json_predicate "$PASS_SUMMARY_JSON" '.launch_command_source == "appimage_artifact"' "dry-run launch_command_source marker"
assert_file_contains_fixed "$TMP_DIR/dry_run_explicit_appimage_pass.log" "dry-run would run launch command:" "dry-run launch marker"
assert_file_contains_fixed "$TMP_DIR/dry_run_explicit_appimage_pass.log" "preflight package-manager availability:" "dry-run package-manager preflight marker"

MISSING_APPIMAGE_PATH="$TMP_DIR/missing-desktop.AppImage"
MISSING_SUMMARY_JSON="$TMP_DIR/missing_explicit_installer_summary.json"
echo "[linux-desktop-installer-guardrails] explicit missing installer path fails with resolve failure stage"
run_expect_fail_regex \
  "explicit_missing_installer_fail" \
  "installer path does not exist" \
  "$SCRIPT_UNDER_TEST" \
    --installer-path "$MISSING_APPIMAGE_PATH" \
    --installer-type appimage \
    --dry-run \
    --summary-json "$MISSING_SUMMARY_JSON" \
    --print-summary-json 0
if [[ ! -f "$MISSING_SUMMARY_JSON" ]]; then
  echo "linux desktop installer guardrails failed: missing summary json for missing explicit installer path scenario"
  exit 1
fi
assert_json_predicate "$MISSING_SUMMARY_JSON" '.status == "fail"' "missing-path status"
assert_json_predicate "$MISSING_SUMMARY_JSON" '.failure_stage == "resolve"' "missing-path failure_stage"

INVALID_TYPE_SUMMARY_JSON="$TMP_DIR/invalid_type_summary.json"
echo "[linux-desktop-installer-guardrails] invalid installer type fails with clear error"
run_expect_fail_regex \
  "invalid_installer_type_fail" \
  "invalid --installer-type" \
  "$SCRIPT_UNDER_TEST" \
    --installer-type invalid-type \
    --dry-run \
    --summary-json "$INVALID_TYPE_SUMMARY_JSON" \
    --print-summary-json 0

FAKE_DEB_PATH="$TMP_DIR/fake-desktop.deb"
printf '%s\n' "fake deb artifact for package-manager guardrails" >"$FAKE_DEB_PATH"
FAKE_PKGLESS_BIN_DIR="$TMP_DIR/fake-pkgless-bin"
mkdir -p "$FAKE_PKGLESS_BIN_DIR"
make_exec_wrapper "$FAKE_PKGLESS_BIN_DIR/bash" "$SYSTEM_BASH"
make_exec_wrapper "$FAKE_PKGLESS_BIN_DIR/dirname" "$SYSTEM_DIRNAME"
make_exec_wrapper "$FAKE_PKGLESS_BIN_DIR/basename" "$SYSTEM_BASENAME"
make_exec_wrapper "$FAKE_PKGLESS_BIN_DIR/cat" "$SYSTEM_CAT"
make_exec_wrapper "$FAKE_PKGLESS_BIN_DIR/date" "$SYSTEM_DATE"
make_exec_wrapper "$FAKE_PKGLESS_BIN_DIR/mkdir" "$SYSTEM_MKDIR"

MISSING_MANAGER_SUMMARY_JSON="$TMP_DIR/missing_manager_summary.json"
echo "[linux-desktop-installer-guardrails] explicit deb install fails with first-run package-manager guidance when installer commands are absent"
run_expect_fail_regex \
  "missing_deb_installer_command_fail" \
  "no supported DEB installer command found|run ./scripts/linux/desktop_doctor.sh --mode fix --install-missing|Debian/Ubuntu: .*apt-get install -y apt dpkg|Fedora/RHEL: .*dnf install -y dnf rpm|Arch: .*pacman -Syu --needed pacman" \
  env \
    PATH="$FAKE_PKGLESS_BIN_DIR" \
    bash "$SCRIPT_UNDER_TEST" \
      --installer-path "$FAKE_DEB_PATH" \
      --installer-type deb \
      --dry-run \
      --summary-json "$MISSING_MANAGER_SUMMARY_JSON" \
      --print-summary-json 0

PRINT_SUMMARY_JSON="$TMP_DIR/print_summary_enabled_summary.json"
echo "[linux-desktop-installer-guardrails] print-summary-json payload marker appears when enabled"
run_expect_pass \
  "print_summary_json_marker_pass" \
  "$SCRIPT_UNDER_TEST" \
    --installer-path "$FAKE_APPIMAGE_PATH" \
    --installer-type appimage \
    --dry-run \
    --summary-json "$PRINT_SUMMARY_JSON" \
    --print-summary-json 1
assert_file_contains_fixed "$TMP_DIR/print_summary_json_marker_pass.log" "[desktop-installer-linux] summary_json_payload:" "print-summary-json payload marker"

echo "linux desktop installer guardrails integration check ok"
