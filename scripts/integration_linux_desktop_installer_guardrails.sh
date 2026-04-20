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
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

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
  "--summary-json" \
  "--print-summary-json"
do
  if ! grep -Fq -- "$marker" "$SCRIPT_UNDER_TEST"; then
    echo "linux desktop installer guardrails failed: missing required option marker in script: $marker"
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
