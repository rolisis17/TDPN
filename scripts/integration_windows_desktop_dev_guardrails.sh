#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in grep mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${DESKTOP_WINDOWS_DEV_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/windows/desktop_dev.ps1}"
DESKTOP_ROOT="$ROOT_DIR/apps/desktop"
WINDOWS_ICON_HELPER="$DESKTOP_ROOT/scripts/ensure-windows-icon.mjs"
WINDOWS_ICON_SOURCE="$DESKTOP_ROOT/src-tauri/icons/icon.svg"
WINDOWS_ICON_OUTPUT="$DESKTOP_ROOT/src-tauri/icons/icon.ico"
DESKTOP_PACKAGE_JSON="$DESKTOP_ROOT/package.json"

if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "windows desktop dev guardrails failed: missing script: $SCRIPT_UNDER_TEST"
  exit 1
fi

if command -v powershell >/dev/null 2>&1; then
  POWERSHELL_BIN="powershell"
elif command -v pwsh >/dev/null 2>&1; then
  POWERSHELL_BIN="pwsh"
elif command -v powershell.exe >/dev/null 2>&1; then
  POWERSHELL_BIN="powershell.exe"
else
  echo "windows desktop dev guardrails failed: missing powershell/pwsh/powershell.exe"
  exit 2
fi

if command -v node >/dev/null 2>&1; then
  NODE_BIN="node"
elif command -v node.exe >/dev/null 2>&1; then
  NODE_BIN="node.exe"
else
  echo "windows desktop dev guardrails failed: missing node/node.exe"
  exit 2
fi

POWERSHELL_USES_WINDOWS_PATHS="0"
if [[ "$POWERSHELL_BIN" == *.exe ]]; then
  POWERSHELL_USES_WINDOWS_PATHS="1"
else
  POWERSHELL_IS_WINDOWS_OUTPUT="$("$POWERSHELL_BIN" -NoProfile -Command "if ((\$env:OS -eq 'Windows_NT') -or (\$IsWindows -eq \$true)) { '1' } else { '0' }" 2>/dev/null || true)"
  POWERSHELL_IS_WINDOWS_OUTPUT="${POWERSHELL_IS_WINDOWS_OUTPUT//$'\r'/}"
  POWERSHELL_IS_WINDOWS_OUTPUT="${POWERSHELL_IS_WINDOWS_OUTPUT//$'\n'/}"
  if [[ "$POWERSHELL_IS_WINDOWS_OUTPUT" == "1" ]]; then
    POWERSHELL_USES_WINDOWS_PATHS="1"
  fi
fi

to_powershell_path() {
  local path="$1"
  if [[ "$POWERSHELL_USES_WINDOWS_PATHS" == "1" ]]; then
    if command -v wslpath >/dev/null 2>&1; then
      wslpath -w "$path"
      return
    fi
    if command -v cygpath >/dev/null 2>&1; then
      cygpath -w "$path"
      return
    fi
  fi
  printf '%s' "$path"
}

ps_single_quote() {
  local value="$1"
  value="${value//\'/\'\'}"
  printf "'%s'" "$value"
}

NODE_BIN_PS="$(to_powershell_path "$NODE_BIN")"
WINDOWS_ICON_HELPER_PS="$(to_powershell_path "$WINDOWS_ICON_HELPER")"
WINDOWS_ICON_SOURCE_PS="$(to_powershell_path "$WINDOWS_ICON_SOURCE")"
WINDOWS_ICON_OUTPUT_PS="$(to_powershell_path "$WINDOWS_ICON_OUTPUT")"

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

SCRIPT_UNDER_TEST_PS="$(to_powershell_path "$SCRIPT_UNDER_TEST")"
SCRIPT_UNDER_TEST_PS_Q="$(ps_single_quote "$SCRIPT_UNDER_TEST_PS")"

run_expect_pass_regex() {
  local name="$1"
  local expected_pattern="$2"
  shift 2
  local log_path="$TMP_DIR/${name}.log"
  if ! "$@" >"$log_path" 2>&1; then
    echo "windows desktop dev guardrails failed: expected pass for $name"
    cat "$log_path"
    exit 1
  fi
  if ! grep -Eiq -- "$expected_pattern" "$log_path"; then
    echo "windows desktop dev guardrails failed: missing expected output for $name"
    echo "expected regex: $expected_pattern"
    cat "$log_path"
    exit 1
  fi
}

run_expect_fail_regex() {
  local name="$1"
  local expected_pattern="$2"
  shift 2
  local log_path="$TMP_DIR/${name}.log"
  if "$@" >"$log_path" 2>&1; then
    echo "windows desktop dev guardrails failed: expected failure for $name"
    cat "$log_path"
    exit 1
  fi
  if ! grep -Eiq -- "$expected_pattern" "$log_path"; then
    echo "windows desktop dev guardrails failed: missing expected failure output for $name"
    echo "expected regex: $expected_pattern"
    cat "$log_path"
    exit 1
  fi
}

INSTALL_ON_REGEX='rerun (with|in this shell with) process-scope bypass: .*desktop_native_bootstrap\.ps1.*-DesktopLaunchStrategy '\''dev'\'' -InstallMissing -DryRun -ApiAddr'
INSTALL_OFF_REGEX='rerun (with|in this shell with) process-scope bypass: .*desktop_native_bootstrap\.ps1.*-DesktopLaunchStrategy '\''dev'\'' -DryRun -ApiAddr'
CONFLICT_REGEX='conflicting install intent: specify only one of -InstallMissing or -NoInstallMissing'
PACKAGE_PRETAURI_REGEX='"pretauri"[[:space:]]*:[[:space:]]*"npm run generate:windows-icon"'
ICON_HELPER_DRY_RUN_REGEX='desktop icon prebuild: would generate .*icon\.ico .*icon\.svg|manual command -> cd apps/desktop && npm run generate:windows-icon'
ICON_HELPER_GENERATED_REGEX='desktop icon prebuild: generated .*icon\.ico from .*icon\.svg'

if [[ ! -f "$WINDOWS_ICON_SOURCE" ]]; then
  echo "windows desktop dev guardrails failed: missing icon source asset: $WINDOWS_ICON_SOURCE"
  exit 1
fi

if [[ ! -f "$WINDOWS_ICON_OUTPUT" ]]; then
  echo "windows desktop dev guardrails failed: missing generated icon artifact: $WINDOWS_ICON_OUTPUT"
  exit 1
fi

if [[ ! -f "$WINDOWS_ICON_HELPER" ]]; then
  echo "windows desktop dev guardrails failed: missing icon helper: $WINDOWS_ICON_HELPER"
  exit 1
fi

if [[ ! -f "$DESKTOP_PACKAGE_JSON" ]]; then
  echo "windows desktop dev guardrails failed: missing package.json: $DESKTOP_PACKAGE_JSON"
  exit 1
fi

if ! grep -Eq -- "$PACKAGE_PRETAURI_REGEX" "$DESKTOP_PACKAGE_JSON"; then
  echo "windows desktop dev guardrails failed: package.json is missing the Windows icon prebuild hook"
  exit 1
fi

TMP_ICON_DIR="$TMP_DIR/windows-icon-test"
mkdir -p "$TMP_ICON_DIR"

echo "[windows-desktop-dev-guardrails] icon helper dry-run shows the remediation command"
run_expect_pass_regex \
  "windows_icon_helper_dry_run" \
  "$ICON_HELPER_DRY_RUN_REGEX" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; \$env:GPM_DESKTOP_ICON_SOURCE_PATH='$(printf "%s" "$WINDOWS_ICON_SOURCE_PS")'; \$env:GPM_DESKTOP_ICON_OUTPUT_PATH='$(printf "%s" "$(to_powershell_path "$TMP_ICON_DIR/icon.ico")")'; \$env:GPM_DESKTOP_ICON_PREBUILD_DRY_RUN='1'; & '$(printf "%s" "$NODE_BIN_PS")' '$(printf "%s" "$WINDOWS_ICON_HELPER_PS")'"

echo "[windows-desktop-dev-guardrails] icon helper generates a valid temp icon"
run_expect_pass_regex \
  "windows_icon_helper_generate" \
  "$ICON_HELPER_GENERATED_REGEX" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; \$env:GPM_DESKTOP_ICON_SOURCE_PATH='$(printf "%s" "$WINDOWS_ICON_SOURCE_PS")'; \$env:GPM_DESKTOP_ICON_OUTPUT_PATH='$(printf "%s" "$(to_powershell_path "$TMP_ICON_DIR/icon.ico")")'; & '$(printf "%s" "$NODE_BIN_PS")' '$(printf "%s" "$WINDOWS_ICON_HELPER_PS")'"

if [[ ! -f "$TMP_ICON_DIR/icon.ico" ]]; then
  echo "windows desktop dev guardrails failed: icon helper did not produce $TMP_ICON_DIR/icon.ico"
  exit 1
fi

echo "[windows-desktop-dev-guardrails] default dry-run uses install intent enabled path"
run_expect_pass_regex \
  "default_install_on_dry_run" \
  "$INSTALL_ON_REGEX" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; \$env:GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING=''; \$env:TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING=''; & $SCRIPT_UNDER_TEST_PS_Q -DryRun -EnablePolicyBypass:\$false"

echo "[windows-desktop-dev-guardrails] gpm env disable flips install intent off"
run_expect_pass_regex \
  "gpm_env_disable_install_off_dry_run" \
  "$INSTALL_OFF_REGEX" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; \$env:GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING='0'; \$env:TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING=''; & $SCRIPT_UNDER_TEST_PS_Q -DryRun -EnablePolicyBypass:\$false"

echo "[windows-desktop-dev-guardrails] gpm env enable keeps install intent on"
run_expect_pass_regex \
  "gpm_env_enable_install_on_dry_run" \
  "$INSTALL_ON_REGEX" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; \$env:GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING='1'; \$env:TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING=''; & $SCRIPT_UNDER_TEST_PS_Q -DryRun -EnablePolicyBypass:\$false"

echo "[windows-desktop-dev-guardrails] tdpn alias disable works when gpm env unset"
run_expect_pass_regex \
  "tdpn_env_disable_install_off_dry_run" \
  "$INSTALL_OFF_REGEX" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; \$env:GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING=''; \$env:TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING='0'; & $SCRIPT_UNDER_TEST_PS_Q -DryRun -EnablePolicyBypass:\$false"

echo "[windows-desktop-dev-guardrails] explicit -NoInstallMissing overrides env enable"
run_expect_pass_regex \
  "explicit_no_install_beats_env_enable_dry_run" \
  "$INSTALL_OFF_REGEX" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; \$env:GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING='1'; \$env:TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING=''; & $SCRIPT_UNDER_TEST_PS_Q -DryRun -EnablePolicyBypass:\$false -NoInstallMissing"

echo "[windows-desktop-dev-guardrails] explicit -InstallMissing:\$false overrides env enable"
run_expect_pass_regex \
  "explicit_install_false_beats_env_enable_dry_run" \
  "$INSTALL_OFF_REGEX" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; \$env:GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING='1'; \$env:TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING=''; & $SCRIPT_UNDER_TEST_PS_Q -DryRun -EnablePolicyBypass:\$false -InstallMissing:\$false"

echo "[windows-desktop-dev-guardrails] explicit -InstallMissing overrides env disable"
run_expect_pass_regex \
  "explicit_install_true_beats_env_disable_dry_run" \
  "$INSTALL_ON_REGEX" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; \$env:GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING='0'; \$env:TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING=''; & $SCRIPT_UNDER_TEST_PS_Q -DryRun -EnablePolicyBypass:\$false -InstallMissing"

echo "[windows-desktop-dev-guardrails] conflicting explicit intent flags fail with exact message"
run_expect_fail_regex \
  "conflicting_install_intent_fails" \
  "$CONFLICT_REGEX" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; & $SCRIPT_UNDER_TEST_PS_Q -DryRun -InstallMissing -NoInstallMissing"

echo "windows desktop dev guardrails integration check ok"
