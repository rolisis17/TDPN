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
