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

SCRIPT_UNDER_TEST="${SETUP_WINDOWS_NATIVE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/windows/setup_windows_native.ps1}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "windows setup-windows-native guardrails failed: missing script: $SCRIPT_UNDER_TEST"
  exit 1
fi

assert_marker_present() {
  local marker="$1"
  local file_path="$2"
  if ! grep -Fq -- "$marker" "$file_path"; then
    echo "windows setup-windows-native guardrails failed: missing marker '$marker' in $file_path"
    exit 1
  fi
}

assert_marker_present "function Assert-WindowsNativeNonWsl" "$SCRIPT_UNDER_TEST"
assert_marker_present "execution_model=windows-native-non-wsl" "$SCRIPT_UNDER_TEST"
assert_marker_present "wsl_required=false" "$SCRIPT_UNDER_TEST"
assert_marker_present "is Windows-native and must run outside WSL." "$SCRIPT_UNDER_TEST"
assert_marker_present "scripts\\windows\\wsl2_easy.cmd bootstrap" "$SCRIPT_UNDER_TEST"

if command -v powershell >/dev/null 2>&1; then
  POWERSHELL_BIN="powershell"
elif command -v pwsh >/dev/null 2>&1; then
  POWERSHELL_BIN="pwsh"
elif command -v powershell.exe >/dev/null 2>&1; then
  POWERSHELL_BIN="powershell.exe"
else
  echo "windows setup-windows-native guardrails failed: missing powershell/pwsh/powershell.exe"
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

run_expect_fail_regex() {
  local name="$1"
  local expected_pattern="$2"
  shift 2
  local log_path="$TMP_DIR/${name}.log"
  if "$@" >"$log_path" 2>&1; then
    echo "windows setup-windows-native guardrails failed: expected failure for $name"
    cat "$log_path"
    exit 1
  fi
  if ! grep -Eiq -- "$expected_pattern" "$log_path"; then
    echo "windows setup-windows-native guardrails failed: missing expected failure output for $name"
    echo "expected regex: $expected_pattern"
    cat "$log_path"
    exit 1
  fi
}

echo "[windows-setup-windows-native-guardrails] WSL sessions fail fast with actionable non-WSL guidance"
run_expect_fail_regex \
  "wsl_session_fail_fast" \
  "Windows-native and must run outside WSL|non-WSL|wsl2_easy\\.cmd bootstrap" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; \$env:WSL_DISTRO_NAME='Ubuntu-guardrail'; & $SCRIPT_UNDER_TEST_PS_Q -Workflow both -DryRun"

echo "windows setup-windows-native guardrails integration check ok"
