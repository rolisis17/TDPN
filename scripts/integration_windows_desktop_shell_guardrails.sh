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

DESKTOP_SHELL_PS1="${DESKTOP_WINDOWS_SHELL_PS1_UNDER_TEST:-$ROOT_DIR/scripts/windows/desktop_shell.ps1}"
DESKTOP_SHELL_CMD="${DESKTOP_WINDOWS_SHELL_CMD_UNDER_TEST:-$ROOT_DIR/scripts/windows/desktop_shell.cmd}"

if [[ ! -f "$DESKTOP_SHELL_PS1" ]]; then
  echo "windows desktop shell guardrails failed: missing script: $DESKTOP_SHELL_PS1"
  exit 1
fi
if [[ ! -f "$DESKTOP_SHELL_CMD" ]]; then
  echo "windows desktop shell guardrails failed: missing script: $DESKTOP_SHELL_CMD"
  exit 1
fi

assert_marker_present() {
  local marker="$1"
  local file_path="$2"
  if ! grep -Fq -- "$marker" "$file_path"; then
    echo "windows desktop shell guardrails failed: missing marker '$marker' in $file_path"
    exit 1
  fi
}

if command -v powershell >/dev/null 2>&1; then
  POWERSHELL_BIN="powershell"
elif command -v pwsh >/dev/null 2>&1; then
  POWERSHELL_BIN="pwsh"
elif command -v powershell.exe >/dev/null 2>&1; then
  POWERSHELL_BIN="powershell.exe"
else
  echo "windows desktop shell guardrails failed: missing powershell/pwsh/powershell.exe"
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

DESKTOP_SHELL_PS1_PS="$(to_powershell_path "$DESKTOP_SHELL_PS1")"
DESKTOP_SHELL_CMD_PS="$(to_powershell_path "$DESKTOP_SHELL_CMD")"

run_expect_pass_regex() {
  local name="$1"
  local expected_pattern="$2"
  shift 2
  local log_path="$TMP_DIR/${name}.log"
  if ! "$@" >"$log_path" 2>&1; then
    echo "windows desktop shell guardrails failed: expected pass for $name"
    cat "$log_path"
    exit 1
  fi
  if ! grep -Eiq -- "$expected_pattern" "$log_path"; then
    echo "windows desktop shell guardrails failed: missing expected output for $name"
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
    echo "windows desktop shell guardrails failed: expected failure for $name"
    cat "$log_path"
    exit 1
  fi
  if ! grep -Eiq -- "$expected_pattern" "$log_path"; then
    echo "windows desktop shell guardrails failed: missing expected failure text for $name"
    echo "expected regex: $expected_pattern"
    cat "$log_path"
    exit 1
  fi
}

echo "[windows-desktop-shell-guardrails] marker checks: npm/npx normalization"
assert_marker_present "function Normalize-NodeToolName" "$DESKTOP_SHELL_PS1"
assert_marker_present "return \"npm.cmd\"" "$DESKTOP_SHELL_PS1"
assert_marker_present "return \"npx.cmd\"" "$DESKTOP_SHELL_PS1"
assert_marker_present "^(?i)npm(?:\\.(?:cmd|ps1))?$" "$DESKTOP_SHELL_PS1"
assert_marker_present "^(?i)npx(?:\\.(?:cmd|ps1))?$" "$DESKTOP_SHELL_PS1"

echo "[windows-desktop-shell-guardrails] marker checks: PATH refresh + tool dirs"
assert_marker_present "function Refresh-SessionPath" "$DESKTOP_SHELL_PS1"
assert_marker_present "[Environment]::GetEnvironmentVariable(\"Path\", \"Machine\")" "$DESKTOP_SHELL_PS1"
assert_marker_present "[Environment]::GetEnvironmentVariable(\"Path\", \"User\")" "$DESKTOP_SHELL_PS1"
assert_marker_present "function Get-CommonToolDirectories" "$DESKTOP_SHELL_PS1"
assert_marker_present "Go\\bin" "$DESKTOP_SHELL_PS1"
assert_marker_present "nodejs" "$DESKTOP_SHELL_PS1"
assert_marker_present ".cargo\\bin" "$DESKTOP_SHELL_PS1"
assert_marker_present "Git\\cmd" "$DESKTOP_SHELL_PS1"
assert_marker_present 'Add-SessionPathSegments -Segments $commonToolDirs' "$DESKTOP_SHELL_PS1"

echo "[windows-desktop-shell-guardrails] marker checks: cmd wrapper policy + metachar guard"
assert_marker_present "powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command" "$DESKTOP_SHELL_CMD"
assert_marker_present "-match '[&|<>^%%!]'" "$DESKTOP_SHELL_CMD"
assert_marker_present "Unsupported cmd metacharacters in arguments." "$DESKTOP_SHELL_CMD"
assert_marker_present "powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File \"%PS1%\" %*" "$DESKTOP_SHELL_CMD"

echo "[windows-desktop-shell-guardrails] runtime check: help output (ps1)"
run_expect_pass_regex \
  "ps1_help" \
  'Windows-safe desktop shell wrapper|Usage:' \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$DESKTOP_SHELL_PS1_PS"

echo "[windows-desktop-shell-guardrails] runtime check: dry-run command rendering"
run_expect_pass_regex \
  "dry_run_command_rendering" \
  '\[desktop-shell\] dry-run: .*cmd.*'\''/c'\''.*'\''ver'\''' \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$DESKTOP_SHELL_PS1_PS" \
    -DryRun cmd /c ver

echo "[windows-desktop-shell-guardrails] runtime check: dry-run npm install resolves npm.cmd"
NPM_SHIM_DIR="$TMP_DIR/node-shims"
NPM_SHIM_DIR_PS="$(to_powershell_path "$NPM_SHIM_DIR")"
NPM_SHIM_DIR_PS_Q="$(ps_single_quote "$NPM_SHIM_DIR_PS")"
DESKTOP_SHELL_PS1_PS_Q="$(ps_single_quote "$DESKTOP_SHELL_PS1_PS")"
run_expect_pass_regex \
  "dry_run_npm_install" \
  '\[desktop-shell\] dry-run: .*npm\.cmd.*'\''install'\''' \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; \$shimDir = $NPM_SHIM_DIR_PS_Q; New-Item -ItemType Directory -Path \$shimDir -Force | Out-Null; Set-Content -LiteralPath (Join-Path \$shimDir 'npm.cmd') -Value '@echo off' -Encoding Ascii -NoNewline; Set-Content -LiteralPath (Join-Path \$shimDir 'npx.cmd') -Value '@echo off' -Encoding Ascii -NoNewline; \$userPathOriginal = [Environment]::GetEnvironmentVariable('Path','User'); if (\$null -eq \$userPathOriginal) { \$userPathOriginal = '' }; \$userPathNew = if ([string]::IsNullOrWhiteSpace(\$userPathOriginal)) { \$shimDir } else { \"\$shimDir;\$userPathOriginal\" }; [Environment]::SetEnvironmentVariable('Path', \$userPathNew, 'User'); try { & $DESKTOP_SHELL_PS1_PS_Q -DryRun npm install } finally { [Environment]::SetEnvironmentVariable('Path', \$userPathOriginal, 'User') }"

echo "[windows-desktop-shell-guardrails] runtime check: cmd wrapper help pass-through"
run_expect_pass_regex \
  "cmd_wrapper_help" \
  'Windows-safe desktop shell wrapper|Usage:' \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "& $(ps_single_quote "$DESKTOP_SHELL_CMD_PS")"

echo "windows desktop shell guardrails integration check ok"
