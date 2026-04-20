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

SCRIPT_UNDER_TEST="${DESKTOP_LINUX_DOCTOR_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/linux/desktop_doctor.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "linux desktop doctor guardrails failed: missing script: $SCRIPT_UNDER_TEST"
  exit 1
fi
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "linux desktop doctor guardrails failed: script is not executable: $SCRIPT_UNDER_TEST"
  exit 1
fi

echo "[linux-desktop-doctor-guardrails] recommended-command markers are present"
if ! grep -qF 'build_recommended_commands()' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing build_recommended_commands marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'select_package_manager()' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing select_package_manager marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'build_selected_remediation_packages()' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing build_selected_remediation_packages marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'RECOMMENDED_COMMANDS=()' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing RECOMMENDED_COMMANDS marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'REMEDIATION_PACKAGES=()' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing REMEDIATION_PACKAGES marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'recommended_commands_json=' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing recommended_commands_json marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF '"recommended_commands": $recommended_commands_json' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing recommended_commands summary field marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'recommended remediation commands:' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing recommended remediation output marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF './scripts/linux/desktop_doctor.sh --mode fix --install-missing' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing doctor fix remediation command marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF './scripts/linux/desktop_one_click.sh' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing one-click remediation command marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'collect_native_dependency_report()' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing native dependency report marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF '"package_manager_selected": "$(json_escape "$package_manager_selected")"' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing package_manager_selected summary marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF '"remediation_packages": $remediation_packages_json' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing remediation_packages summary marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'missing_native_dependencies' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing missing_native_dependencies summary marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'native_dependency_report' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing native_dependency_report summary marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'pkg-config' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing pkg-config native prerequisite marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'libgtk-3-dev' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing GTK3 native apt hint marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'libwebkit2gtk-4.1-dev' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing WebKit2GTK native apt hint marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'libsoup-3.0-dev' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing libsoup3 native apt hint marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'libjavascriptcoregtk-4.1-dev' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing javascriptcoregtk native apt hint marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'fix mode: selected package manager:' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing package-manager selection runtime marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'dnf install -y ${REMEDIATION_PACKAGES[*]}' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing dnf remediation command marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'pacman -Sy --needed ${REMEDIATION_PACKAGES[*]}' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing pacman remediation command marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'zypper install -y ${REMEDIATION_PACKAGES[*]}' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing zypper remediation command marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'dry-run: no package-manager commands executed (preview only)' "$SCRIPT_UNDER_TEST"; then
  echo "linux desktop doctor guardrails failed: missing dry-run safe no-execution marker in $SCRIPT_UNDER_TEST"
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
  echo "linux desktop doctor guardrails failed: expected pass for $name"
  cat "$log_path"
  exit 1
}

run_expect_fail_regex() {
  local name="$1"
  local expected_pattern="$2"
  shift 2
  local log_path="$TMP_DIR/${name}.log"
  if "$@" >"$log_path" 2>&1; then
    echo "linux desktop doctor guardrails failed: expected failure for $name"
    cat "$log_path"
    exit 1
  fi
  if ! grep -Eiq -- "$expected_pattern" "$log_path"; then
    echo "linux desktop doctor guardrails failed: missing expected failure text for $name"
    echo "expected regex: $expected_pattern"
    cat "$log_path"
    exit 1
  fi
}

echo "[linux-desktop-doctor-guardrails] check dry-run passes"
run_expect_pass \
  "check_dry_run_pass" \
  "$SCRIPT_UNDER_TEST" \
    --mode check \
    --dry-run
if ! grep -Fq 'recommended remediation commands:' "$TMP_DIR/check_dry_run_pass.log"; then
  echo "linux desktop doctor guardrails failed: missing recommended remediation runtime output in check dry-run log"
  cat "$TMP_DIR/check_dry_run_pass.log"
  exit 1
fi
if ! grep -Fq './scripts/linux/desktop_doctor.sh --mode fix --install-missing' "$TMP_DIR/check_dry_run_pass.log"; then
  echo "linux desktop doctor guardrails failed: missing doctor fix command in check dry-run log"
  cat "$TMP_DIR/check_dry_run_pass.log"
  exit 1
fi
if ! grep -Fq './scripts/linux/desktop_one_click.sh' "$TMP_DIR/check_dry_run_pass.log"; then
  echo "linux desktop doctor guardrails failed: missing one-click command in check dry-run log"
  cat "$TMP_DIR/check_dry_run_pass.log"
  exit 1
fi

echo "[linux-desktop-doctor-guardrails] fix dry-run passes"
run_expect_pass \
  "fix_dry_run_pass" \
  "$SCRIPT_UNDER_TEST" \
    --mode fix \
    --install-missing \
    --dry-run
if ! grep -Fq 'fix mode: selected package manager:' "$TMP_DIR/fix_dry_run_pass.log"; then
  echo "linux desktop doctor guardrails failed: missing package-manager selection output in fix dry-run log"
  cat "$TMP_DIR/fix_dry_run_pass.log"
  exit 1
fi
if ! grep -Eq 'dry-run: .*apt-get update|dry-run: .*apt-get install -y|dry-run: .*dnf install -y|dry-run: .*pacman -Sy --needed|dry-run: .*zypper install -y|fix mode: no remediation needed for|automatic remediation skipped' "$TMP_DIR/fix_dry_run_pass.log"; then
  echo "linux desktop doctor guardrails failed: fix dry-run log missing package-manager command preview or explicit no-remediation reason"
  cat "$TMP_DIR/fix_dry_run_pass.log"
  exit 1
fi

echo "[linux-desktop-doctor-guardrails] print-summary-json includes recommended_commands"
run_expect_pass \
  "print_summary_json_pass" \
  "$SCRIPT_UNDER_TEST" \
    --mode check \
    --dry-run \
    --print-summary-json 1

if ! grep -Fq '"recommended_commands"' "$TMP_DIR/print_summary_json_pass.log"; then
  echo "linux desktop doctor guardrails failed: missing recommended_commands in print-summary-json output"
  cat "$TMP_DIR/print_summary_json_pass.log"
  exit 1
fi
if ! grep -Fq '"missing_native_dependencies"' "$TMP_DIR/print_summary_json_pass.log"; then
  echo "linux desktop doctor guardrails failed: missing missing_native_dependencies in print-summary-json output"
  cat "$TMP_DIR/print_summary_json_pass.log"
  exit 1
fi
if ! grep -Fq '"native_dependency_report"' "$TMP_DIR/print_summary_json_pass.log"; then
  echo "linux desktop doctor guardrails failed: missing native_dependency_report in print-summary-json output"
  cat "$TMP_DIR/print_summary_json_pass.log"
  exit 1
fi

SUMMARY_JSON="$TMP_DIR/desktop_doctor_summary.json"
echo "[linux-desktop-doctor-guardrails] summary json is written when requested"
run_expect_pass \
  "summary_json_pass" \
  "$SCRIPT_UNDER_TEST" \
    --mode check \
    --dry-run \
    --summary-json "$SUMMARY_JSON" \
    --print-summary-json 0

if [[ ! -f "$SUMMARY_JSON" ]]; then
  echo "linux desktop doctor guardrails failed: summary json was not written: $SUMMARY_JSON"
  cat "$TMP_DIR/summary_json_pass.log"
  exit 1
fi
if ! jq -e 'type == "object"' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "linux desktop doctor guardrails failed: summary json is not a JSON object"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.recommended_commands | type == "array" and length >= 2' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "linux desktop doctor guardrails failed: summary json missing recommended_commands guidance array"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.recommended_commands | map(test("desktop_doctor\\.sh --mode fix --install-missing")) | any' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "linux desktop doctor guardrails failed: summary json missing desktop_doctor fix remediation command"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.recommended_commands | map(test("desktop_one_click\\.sh")) | any' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "linux desktop doctor guardrails failed: summary json missing desktop_one_click remediation command"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.missing_native_dependencies | type == "array"' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "linux desktop doctor guardrails failed: summary json missing missing_native_dependencies array"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.native_dependency_report | type == "object"' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "linux desktop doctor guardrails failed: summary json missing native_dependency_report object"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.package_manager_selected | type == "string"' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "linux desktop doctor guardrails failed: summary json missing package_manager_selected string"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.remediation_packages | type == "array"' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "linux desktop doctor guardrails failed: summary json missing remediation_packages array"
  cat "$SUMMARY_JSON"
  exit 1
fi

echo "[linux-desktop-doctor-guardrails] invalid mode fails with expected message"
run_expect_fail_regex \
  "invalid_mode_fail" \
  "unsupported mode|invalid mode" \
  "$SCRIPT_UNDER_TEST" \
    --mode invalid-mode \
    --dry-run

echo "linux desktop doctor guardrails integration check ok"
