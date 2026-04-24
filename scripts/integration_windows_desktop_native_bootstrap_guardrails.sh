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

SCRIPT_UNDER_TEST="${DESKTOP_WINDOWS_NATIVE_BOOTSTRAP_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/windows/desktop_native_bootstrap.ps1}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "windows desktop native bootstrap guardrails failed: missing script: $SCRIPT_UNDER_TEST"
  exit 1
fi

assert_marker_present() {
  local marker="$1"
  local file_path="$2"
  if ! grep -Fq -- "$marker" "$file_path"; then
    echo "windows desktop native bootstrap guardrails failed: missing marker '$marker' in $file_path"
    exit 1
  fi
}

assert_any_marker_present() {
  local file_path="$1"
  shift
  local marker
  for marker in "$@"; do
    if grep -Fq -- "$marker" "$file_path"; then
      return 0
    fi
  done
  echo "windows desktop native bootstrap guardrails failed: missing expected marker variants in $file_path"
  echo "expected one of: $*"
  exit 1
}

assert_marker_present "recommended_commands" "$SCRIPT_UNDER_TEST"
assert_marker_present "Get-RecommendedCommands" "$SCRIPT_UNDER_TEST"
assert_marker_present "recommended commands (copy/paste):" "$SCRIPT_UNDER_TEST"
assert_marker_present 'running packaged desktop (wait):' "$SCRIPT_UNDER_TEST"
assert_marker_present 'Start-Process -FilePath $DesktopExecutablePath -PassThru -Wait' "$SCRIPT_UNDER_TEST"
assert_marker_present "packaged desktop process exited with code" "$SCRIPT_UNDER_TEST"
assert_any_marker_present "$SCRIPT_UNDER_TEST" \
  "packaged desktop exited cleanly (exit_code=0)" \
  "packaged desktop exited cleanly (exit_code=0, pid={0}, duration_s={1})"
assert_marker_present "Get-PackagedDesktopHandoffMetadata" "$SCRIPT_UNDER_TEST"
assert_marker_present "packaged launch likely handed off to existing instance" "$SCRIPT_UNDER_TEST"
assert_marker_present "packaged handoff detected after clean desktop exit; skipping default local api cleanup" "$SCRIPT_UNDER_TEST"
assert_marker_present "packaged_handoff_detected" "$SCRIPT_UNDER_TEST"
assert_marker_present "api_cleanup_action" "$SCRIPT_UNDER_TEST"
assert_marker_present "-ExpectedProcess \$apiProc" "$SCRIPT_UNDER_TEST"
assert_marker_present "dry_run_no_api_started" "$SCRIPT_UNDER_TEST"
assert_marker_present "stopped_after_failed_startup" "$SCRIPT_UNDER_TEST"
assert_marker_present "stopped_after_run_full_failure" "$SCRIPT_UNDER_TEST"
assert_marker_present "kept_running_keep_api_running" "$SCRIPT_UNDER_TEST"
assert_marker_present "kept_running_packaged_handoff" "$SCRIPT_UNDER_TEST"
assert_marker_present "stopped_after_desktop_exit_default_cleanup" "$SCRIPT_UNDER_TEST"
assert_marker_present "desktop_one_click.ps1" "$SCRIPT_UNDER_TEST"
assert_marker_present "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force" "$SCRIPT_UNDER_TEST"
assert_marker_present "winget install --id" "$SCRIPT_UNDER_TEST"
assert_marker_present "GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE" "$SCRIPT_UNDER_TEST"
assert_marker_present "GPM_DESKTOP_PACKAGED_EXE" "$SCRIPT_UNDER_TEST"
assert_marker_present "TDPN_DESKTOP_PACKAGED_EXE" "$SCRIPT_UNDER_TEST"
assert_marker_present "Microsoft.VisualStudio.2022.BuildTools" "$SCRIPT_UNDER_TEST"
assert_marker_present "Microsoft.WindowsSDK.10.0" "$SCRIPT_UNDER_TEST"
assert_marker_present "jqlang.jq" "$SCRIPT_UNDER_TEST"
assert_marker_present "jq: " "$SCRIPT_UNDER_TEST"
if grep -qF '"Microsoft.WindowsSDK.10.0" { return "" }' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop native bootstrap guardrails failed: Windows SDK must not be hard-skipped from winget remediation"
  exit 1
fi
assert_marker_present "winget install --id Microsoft.WindowsSDK.10.0 --exact" "$SCRIPT_UNDER_TEST"
assert_marker_present "Microsoft.EdgeWebView2Runtime" "$SCRIPT_UNDER_TEST"
assert_marker_present "developer.microsoft.com/windows/downloads/windows-sdk/" "$SCRIPT_UNDER_TEST"
assert_marker_present "developer.microsoft.com/microsoft-edge/webview2/" "$SCRIPT_UNDER_TEST"
assert_marker_present "Ensure-DesktopIconAsset" "$SCRIPT_UNDER_TEST"
assert_marker_present "icon.ico" "$SCRIPT_UNDER_TEST"
assert_marker_present "dry-run desktop source icon remediation: would create placeholder source icon at" "$SCRIPT_UNDER_TEST"
assert_marker_present "desktop source icon remediation: created placeholder source icon at" "$SCRIPT_UNDER_TEST"
assert_marker_present "Resolve-ToolPath \"npm.cmd\"" "$SCRIPT_UNDER_TEST"
assert_marker_present "npm resolver fallback: ignoring npm.ps1 shim" "$SCRIPT_UNDER_TEST"
assert_marker_present "npm.ps1 shim detected but npm.cmd was not found" "$SCRIPT_UNDER_TEST"
assert_marker_present "npm.cmd install" "$SCRIPT_UNDER_TEST"
assert_marker_present "npm.cmd run tauri -- dev" "$SCRIPT_UNDER_TEST"
assert_marker_present "execution policy risk detected: effective_policy=" "$SCRIPT_UNDER_TEST"
assert_marker_present "rerun in this shell with process-scope bypass:" "$SCRIPT_UNDER_TEST"
assert_marker_present "Get-ProcessBypassRerunCommand" "$SCRIPT_UNDER_TEST"
assert_marker_present "next_command" "$SCRIPT_UNDER_TEST"
assert_marker_present "next command:" "$SCRIPT_UNDER_TEST"
assert_marker_present "function Assert-WindowsNativeNonWsl" "$SCRIPT_UNDER_TEST"
assert_marker_present "execution_model=windows-native-non-wsl" "$SCRIPT_UNDER_TEST"
assert_marker_present "wsl_required=false" "$SCRIPT_UNDER_TEST"
assert_marker_present "is Windows-native and must run outside WSL." "$SCRIPT_UNDER_TEST"
assert_marker_present "scripts\\windows\\wsl2_easy.cmd bootstrap" "$SCRIPT_UNDER_TEST"
assert_marker_present "wsl_detected" "$SCRIPT_UNDER_TEST"
assert_marker_present "go version" "$SCRIPT_UNDER_TEST"
assert_marker_present "node -v" "$SCRIPT_UNDER_TEST"
assert_marker_present "npm.cmd -v" "$SCRIPT_UNDER_TEST"
assert_marker_present "rustc -V" "$SCRIPT_UNDER_TEST"
assert_marker_present "cargo -V" "$SCRIPT_UNDER_TEST"

if command -v powershell >/dev/null 2>&1; then
  POWERSHELL_BIN="powershell"
elif command -v pwsh >/dev/null 2>&1; then
  POWERSHELL_BIN="pwsh"
elif command -v powershell.exe >/dev/null 2>&1; then
  POWERSHELL_BIN="powershell.exe"
else
  echo "windows desktop native bootstrap guardrails failed: missing powershell/pwsh/powershell.exe"
  exit 2
fi
POWERSHELL_BIN_PATH="$(command -v "$POWERSHELL_BIN" 2>/dev/null || true)"
if [[ -z "$POWERSHELL_BIN_PATH" ]]; then
  POWERSHELL_BIN_PATH="$POWERSHELL_BIN"
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

prepend_tool_path_for_powershell() {
  local tool_path="$1"
  local existing_path="${2:-$PATH}"
  local separator=":"
  if [[ "$POWERSHELL_USES_WINDOWS_PATHS" == "1" ]]; then
    separator=";"
  fi
  if [[ -z "$existing_path" ]]; then
    printf '%s' "$tool_path"
  else
    printf '%s%s%s' "$tool_path" "$separator" "$existing_path"
  fi
}

ps_single_quote() {
  local value="$1"
  value="${value//\'/\'\'}"
  printf "'%s'" "$value"
}

detect_summary_flag() {
  local script_path="$1"
  if grep -qiE '\$SummaryJson([^A-Za-z0-9_]|$)' "$script_path"; then
    printf '%s' "-SummaryJson"
    return
  fi
  if grep -qiE '\$SummaryJsonPath([^A-Za-z0-9_]|$)' "$script_path"; then
    printf '%s' "-SummaryJsonPath"
    return
  fi
  if grep -qiE '\$SummaryPath([^A-Za-z0-9_]|$)' "$script_path"; then
    printf '%s' "-SummaryPath"
    return
  fi
  if grep -qiE '\$SummaryFile([^A-Za-z0-9_]|$)' "$script_path"; then
    printf '%s' "-SummaryFile"
    return
  fi
  printf '%s' ""
}

detect_print_summary_flag() {
  local script_path="$1"
  if grep -qiE '\$PrintSummaryJson([^A-Za-z0-9_]|$)' "$script_path"; then
    printf '%s' "-PrintSummaryJson"
    return
  fi
  if grep -qiE '\$PrintJson([^A-Za-z0-9_]|$)' "$script_path"; then
    printf '%s' "-PrintJson"
    return
  fi
  printf '%s' ""
}

TMP_DIR="$(mktemp -d)"
SOURCE_ICON_PATH="$ROOT_DIR/apps/desktop/src-tauri/icons/icon.svg"
SOURCE_ICON_BACKUP_PATH="$TMP_DIR/source-icon.svg.backup"
SOURCE_ICON_WAS_PRESENT="0"

cleanup() {
  if [[ "$SOURCE_ICON_WAS_PRESENT" == "1" && -f "$SOURCE_ICON_BACKUP_PATH" ]]; then
    mkdir -p "$(dirname "$SOURCE_ICON_PATH")"
    mv -f "$SOURCE_ICON_BACKUP_PATH" "$SOURCE_ICON_PATH"
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

SCRIPT_UNDER_TEST_PS="$(to_powershell_path "$SCRIPT_UNDER_TEST")"

run_expect_pass() {
  local name="$1"
  shift
  local log_path="$TMP_DIR/${name}.log"
  if "$@" >"$log_path" 2>&1; then
    return 0
  fi
  echo "windows desktop native bootstrap guardrails failed: expected pass for $name"
  cat "$log_path"
  exit 1
}

run_expect_fail_regex() {
  local name="$1"
  local expected_pattern="$2"
  shift 2
  local log_path="$TMP_DIR/${name}.log"
  if "$@" >"$log_path" 2>&1; then
    echo "windows desktop native bootstrap guardrails failed: expected failure for $name"
    cat "$log_path"
    exit 1
  fi
  if ! grep -Eiq -- "$expected_pattern" "$log_path"; then
    echo "windows desktop native bootstrap guardrails failed: missing expected failure text for $name"
    echo "expected regex: $expected_pattern"
    cat "$log_path"
    exit 1
  fi
}

run_expect_pass_or_fail_regex() {
  local name="$1"
  local expected_pattern="$2"
  shift 2
  local log_path="$TMP_DIR/${name}.log"
  if "$@" >"$log_path" 2>&1; then
    return 0
  fi
  if grep -Eiq -- "$expected_pattern" "$log_path"; then
    return 0
  fi
  echo "windows desktop native bootstrap guardrails failed: unexpected failure for $name"
  echo "expected regex when non-zero: $expected_pattern"
  cat "$log_path"
  exit 1
}

prepare_missing_source_icon_fixture() {
  if [[ -f "$SOURCE_ICON_PATH" ]]; then
    cp -f "$SOURCE_ICON_PATH" "$SOURCE_ICON_BACKUP_PATH"
    SOURCE_ICON_WAS_PRESENT="1"
    rm -f "$SOURCE_ICON_PATH"
    return 0
  fi

  SOURCE_ICON_WAS_PRESENT="0"
  rm -f "$SOURCE_ICON_BACKUP_PATH"
  return 0
}

restore_source_icon_fixture() {
  if [[ "$SOURCE_ICON_WAS_PRESENT" == "1" && -f "$SOURCE_ICON_BACKUP_PATH" ]]; then
    mkdir -p "$(dirname "$SOURCE_ICON_PATH")"
    mv -f "$SOURCE_ICON_BACKUP_PATH" "$SOURCE_ICON_PATH"
  fi
  SOURCE_ICON_WAS_PRESENT="0"
}

assert_json_file_is_object() {
  local json_path="$1"
  local context_label="$2"
  local json_path_ps
  json_path_ps="$(to_powershell_path "$json_path")"
  local log_path="$TMP_DIR/assert_${context_label}.log"
  if "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command "\$ErrorActionPreference='Stop'; \$json = Get-Content -Raw -LiteralPath $(ps_single_quote "$json_path_ps"); if ([string]::IsNullOrWhiteSpace(\$json)) { throw 'empty json payload' }; \$trimmed = \$json.TrimStart(); \$trimmed = \$trimmed -replace '^\uFEFF',''; \$trimmed = \$trimmed.TrimStart(); if (-not \$trimmed.StartsWith('{')) { throw 'json payload is not an object' }; \$null = \$trimmed | ConvertFrom-Json" >"$log_path" 2>&1; then
    return 0
  fi
  echo "windows desktop native bootstrap guardrails failed: JSON validation failed for $context_label"
  cat "$log_path"
  exit 1
}

assert_summary_keep_api_running() {
  local json_path="$1"
  local context_label="$2"
  local expected_value="$3"
  local json_path_ps
  json_path_ps="$(to_powershell_path "$json_path")"
  local log_path="$TMP_DIR/assert_keep_api_running_${context_label}.log"
  if "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command "\$ErrorActionPreference='Stop'; \$summary = Get-Content -Raw -LiteralPath $(ps_single_quote "$json_path_ps") | ConvertFrom-Json; if (\$null -eq \$summary) { throw 'summary JSON parse failed' }; if (-not (\$summary.PSObject.Properties.Name -contains 'keep_api_running')) { throw 'keep_api_running field missing' }; \$actual = [bool]\$summary.keep_api_running; \$expected = [System.Convert]::ToBoolean($(ps_single_quote "$expected_value")); if (\$actual -ne \$expected) { throw ('keep_api_running mismatch: expected={0} actual={1}' -f \$expected, \$actual) }" >"$log_path" 2>&1; then
    return 0
  fi
  echo "windows desktop native bootstrap guardrails failed: keep_api_running assertion failed for $context_label"
  cat "$log_path"
  exit 1
}

assert_summary_run_full_cleanup_fields() {
  local json_path="$1"
  local context_label="$2"
  local expected_cleanup_action="$3"
  local expected_handoff_detected="$4"
  local json_path_ps
  json_path_ps="$(to_powershell_path "$json_path")"
  local log_path="$TMP_DIR/assert_run_full_cleanup_${context_label}.log"
  if "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command "\$ErrorActionPreference='Stop'; \$summary = Get-Content -Raw -LiteralPath $(ps_single_quote "$json_path_ps") | ConvertFrom-Json; if (\$null -eq \$summary) { throw 'summary JSON parse failed' }; if (-not (\$summary.PSObject.Properties.Name -contains 'api_cleanup_action')) { throw 'api_cleanup_action field missing' }; if (-not (\$summary.PSObject.Properties.Name -contains 'packaged_handoff_detected')) { throw 'packaged_handoff_detected field missing' }; \$actualCleanup = [string]\$summary.api_cleanup_action; if ([string]::IsNullOrWhiteSpace(\$actualCleanup)) { throw 'api_cleanup_action is empty' }; if (\$actualCleanup -ne $(ps_single_quote "$expected_cleanup_action")) { throw ('api_cleanup_action mismatch: expected={0} actual={1}' -f $(ps_single_quote "$expected_cleanup_action"), \$actualCleanup) }; if (-not (\$summary.packaged_handoff_detected -is [bool])) { throw 'packaged_handoff_detected is not boolean' }; \$actualHandoff = [bool]\$summary.packaged_handoff_detected; \$expectedHandoff = [System.Convert]::ToBoolean($(ps_single_quote "$expected_handoff_detected")); if (\$actualHandoff -ne \$expectedHandoff) { throw ('packaged_handoff_detected mismatch: expected={0} actual={1}' -f \$expectedHandoff, \$actualHandoff) }" >"$log_path" 2>&1; then
    return 0
  fi
  echo "windows desktop native bootstrap guardrails failed: run-full cleanup field assertion failed for $context_label"
  cat "$log_path"
  exit 1
}

assert_summary_run_full_recommended_keep_api_running() {
  local json_path="$1"
  local context_label="$2"
  local expected_value="$3"
  local json_path_ps
  json_path_ps="$(to_powershell_path "$json_path")"
  local log_path="$TMP_DIR/assert_run_full_recommended_keep_${context_label}.log"
  if "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command "\$ErrorActionPreference='Stop'; \$summary = Get-Content -Raw -LiteralPath $(ps_single_quote "$json_path_ps") | ConvertFrom-Json; if (\$null -eq \$summary) { throw 'summary JSON parse failed' }; \$recommended = @(); if (\$summary.PSObject.Properties.Name -contains 'recommended_commands' -and \$null -ne \$summary.recommended_commands) { \$recommended = @(\$summary.recommended_commands) }; \$runFullCommands = @(\$recommended | Where-Object { \$_.ToString() -like '*desktop_native_bootstrap.ps1*' -and \$_.ToString() -like '*-Mode run-full*' }); if (\$runFullCommands.Count -lt 1) { throw 'missing run-full desktop_native_bootstrap recommended commands' }; \$expected = [System.Convert]::ToBoolean($(ps_single_quote "$expected_value")); \$runFullWithKeep = @(\$runFullCommands | Where-Object { \$_.ToString() -like '*-KeepApiRunning*' }); if (\$expected) { if (\$runFullWithKeep.Count -lt \$runFullCommands.Count) { throw 'expected all run-full bootstrap recommended commands to include -KeepApiRunning' } } else { if (\$runFullWithKeep.Count -gt 0) { throw 'unexpected -KeepApiRunning in run-full bootstrap recommended commands' } }; \$nextCommand = [string]\$summary.next_command; if (-not [string]::IsNullOrWhiteSpace(\$nextCommand) -and \$nextCommand -like '*desktop_native_bootstrap.ps1*' -and \$nextCommand -like '*-Mode run-full*') { if (\$expected -and \$nextCommand -notlike '*-KeepApiRunning*') { throw 'next_command missing -KeepApiRunning for run-full keep intent' }; if (-not \$expected -and \$nextCommand -like '*-KeepApiRunning*') { throw 'next_command unexpectedly includes -KeepApiRunning without keep intent' } }" >"$log_path" 2>&1; then
    return 0
  fi
  echo "windows desktop native bootstrap guardrails failed: run-full recommended keep-api assertion failed for $context_label"
  cat "$log_path"
  exit 1
}

assert_summary_recommended_commands() {
  local json_path="$1"
  local context_label="$2"
  local json_path_ps
  json_path_ps="$(to_powershell_path "$json_path")"
  local log_path="$TMP_DIR/assert_recommended_${context_label}.log"
  if "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command "\$ErrorActionPreference='Stop'; \$summary = Get-Content -Raw -LiteralPath $(ps_single_quote "$json_path_ps") | ConvertFrom-Json; if (\$null -eq \$summary) { throw 'summary JSON parse failed' }; if (-not (\$summary.PSObject.Properties.Name -contains 'recommended_commands')) { throw 'recommended_commands field missing' }; if (\$null -eq \$summary.recommended_commands) { throw 'recommended_commands is null' }; \$recommended = @(\$summary.recommended_commands); if (\$recommended.Count -lt 3) { throw 'recommended_commands is unexpectedly short' }; if (-not (\$summary.PSObject.Properties.Name -contains 'next_command')) { throw 'next_command field missing' }; \$nextCommand = [string]\$summary.next_command; if ([string]::IsNullOrWhiteSpace(\$nextCommand)) { throw 'next_command is empty' }; if (-not (\$nextCommand -like '*desktop_native_bootstrap.ps1*')) { throw 'next_command does not reference desktop_native_bootstrap.ps1' }; if (-not (\$recommended | Where-Object { \$_.ToString() -like '*Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force*' })) { throw 'missing execution-policy recommendation' }; if (-not (\$recommended | Where-Object { \$_.ToString() -like '*desktop_native_bootstrap.ps1*' })) { throw 'missing bootstrap rerun recommendation' }; if (-not (\$recommended | Where-Object { \$_.ToString() -like '*-InstallMissing*' })) { throw 'missing -InstallMissing recommendation' }; if (-not (\$recommended | Where-Object { \$_.ToString() -like '*desktop_one_click.ps1*' })) { throw 'missing desktop_one_click recommendation' }; if (-not (\$recommended | Where-Object { \$_.ToString() -like '*go version*' })) { throw 'missing go version recommendation' }; if (-not (\$recommended | Where-Object { \$_.ToString() -like '*node -v*' })) { throw 'missing node -v recommendation' }; if (-not (\$recommended | Where-Object { \$_.ToString() -like '*npm.cmd -v*' })) { throw 'missing npm.cmd -v recommendation' }; if (-not (\$recommended | Where-Object { \$_.ToString() -like '*rustc -V*' })) { throw 'missing rustc -V recommendation' }; if (-not (\$recommended | Where-Object { \$_.ToString() -like '*cargo -V*' })) { throw 'missing cargo -V recommendation' }; \$missing = @(); if (\$summary.PSObject.Properties.Name -contains 'missing_package_ids' -and \$null -ne \$summary.missing_package_ids) { \$missing = @(\$summary.missing_package_ids) }; if (\$missing.Count -gt 0) { if (-not (\$recommended | Where-Object { \$_.ToString() -like '*winget install --id*' })) { throw 'missing winget remediation recommendation when packages are missing' } }; if (\$missing -contains 'Microsoft.WindowsSDK.10.0') { if (-not (\$recommended | Where-Object { \$_.ToString() -like '*winget install --id Microsoft.WindowsSDK.10.0 --exact*' })) { throw 'missing Windows SDK winget remediation recommendation when Windows SDK is missing' }; if (-not (\$recommended | Where-Object { \$_.ToString() -like '*windows-sdk*' })) { throw 'missing Windows SDK fallback guidance link when Windows SDK is missing' } }; if (\$missing -contains 'jqlang.jq') { if (-not (\$recommended | Where-Object { \$_.ToString() -like '*winget install --id jqlang.jq --exact*' })) { throw 'missing jq winget remediation recommendation when jq is missing' } }" >"$log_path" 2>&1; then
    return 0
  fi
  echo "windows desktop native bootstrap guardrails failed: recommended_commands assertion failed for $context_label"
  cat "$log_path"
  exit 1
}

assert_summary_execution_policy_bypass_command() {
  local json_path="$1"
  local context_label="$2"
  local expected_mode="$3"
  local expected_summary_json_path="$4"
  local expected_print_summary_json="$5"
  local json_path_ps
  local expected_summary_json_path_ps
  json_path_ps="$(to_powershell_path "$json_path")"
  expected_summary_json_path_ps="$(to_powershell_path "$expected_summary_json_path")"
  local log_path="$TMP_DIR/assert_execution_policy_command_${context_label}.log"
  if "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command "\$ErrorActionPreference='Stop'; \$summary = Get-Content -Raw -LiteralPath $(ps_single_quote "$json_path_ps") | ConvertFrom-Json; if (\$null -eq \$summary) { throw 'summary JSON parse failed' }; if (-not (\$summary.PSObject.Properties.Name -contains 'execution_policy_bypass_command')) { throw 'execution_policy_bypass_command field missing' }; \$cmd = [string]\$summary.execution_policy_bypass_command; if ([string]::IsNullOrWhiteSpace(\$cmd)) { throw 'execution_policy_bypass_command is empty' }; if (\$cmd -notlike '*desktop_native_bootstrap.ps1*') { throw 'execution_policy_bypass_command does not reference desktop_native_bootstrap.ps1' }; if (\$cmd -notlike ('*-Mode*' + $(ps_single_quote "$expected_mode") + '*')) { throw ('execution_policy_bypass_command missing expected mode: {0}' -f $(ps_single_quote "$expected_mode")) }; if (\$cmd -notlike '*-SummaryJson*') { throw 'execution_policy_bypass_command missing -SummaryJson argument' }; \$expectedSummaryPathRaw = [string]$(ps_single_quote "$expected_summary_json_path_ps"); \$expectedSummaryPathResolved = ''; try { \$expectedSummaryPathResolved = [string](Resolve-Path -LiteralPath $(ps_single_quote "$expected_summary_json_path_ps")).Path } catch { \$expectedSummaryPathResolved = '' }; \$expectedSummaryLeaf = [System.IO.Path]::GetFileName(\$expectedSummaryPathRaw); \$summaryPathMatched = \$false; if (-not [string]::IsNullOrWhiteSpace(\$expectedSummaryPathRaw) -and \$cmd -like ('*' + \$expectedSummaryPathRaw + '*')) { \$summaryPathMatched = \$true }; if (-not \$summaryPathMatched -and -not [string]::IsNullOrWhiteSpace(\$expectedSummaryPathResolved) -and \$cmd -like ('*' + \$expectedSummaryPathResolved + '*')) { \$summaryPathMatched = \$true }; if (-not \$summaryPathMatched -and -not [string]::IsNullOrWhiteSpace(\$expectedSummaryLeaf) -and \$cmd -like ('*' + \$expectedSummaryLeaf + '*')) { \$summaryPathMatched = \$true }; if (-not \$summaryPathMatched) { throw ('execution_policy_bypass_command missing expected summary path: raw={0} resolved={1}' -f \$expectedSummaryPathRaw, \$expectedSummaryPathResolved) }; if (\$cmd -notlike ('*-PrintSummaryJson*' + $(ps_single_quote "$expected_print_summary_json") + '*')) { throw ('execution_policy_bypass_command missing expected -PrintSummaryJson value: {0}' -f $(ps_single_quote "$expected_print_summary_json")) }" >"$log_path" 2>&1; then
    return 0
  fi
  echo "windows desktop native bootstrap guardrails failed: execution_policy_bypass_command assertion failed for $context_label"
  cat "$log_path"
  exit 1
}

summary_has_missing_package() {
  local json_path="$1"
  local package_id="$2"
  local json_path_ps
  json_path_ps="$(to_powershell_path "$json_path")"
  if "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command "\$ErrorActionPreference='Stop'; \$summary = Get-Content -Raw -LiteralPath $(ps_single_quote "$json_path_ps") | ConvertFrom-Json; \$missing = @(); if (\$summary.PSObject.Properties.Name -contains 'missing_package_ids' -and \$null -ne \$summary.missing_package_ids) { \$missing = @(\$summary.missing_package_ids) }; if (\$missing -contains $(ps_single_quote "$package_id")) { exit 0 } else { exit 1 }" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

assert_summary_jq_missing_remediation() {
  local json_path="$1"
  local context_label="$2"
  local json_path_ps
  json_path_ps="$(to_powershell_path "$json_path")"
  local log_path="$TMP_DIR/assert_jq_missing_${context_label}.log"
  if "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command "\$ErrorActionPreference='Stop'; \$summary = Get-Content -Raw -LiteralPath $(ps_single_quote "$json_path_ps") | ConvertFrom-Json; if (\$null -eq \$summary) { throw 'summary JSON parse failed' }; \$missing = @(); if (\$summary.PSObject.Properties.Name -contains 'missing_package_ids' -and \$null -ne \$summary.missing_package_ids) { \$missing = @(\$summary.missing_package_ids) }; if (-not (\$missing -contains 'jqlang.jq')) { throw 'expected jqlang.jq in missing_package_ids for jq-missing scenario' }; \$recommended = @(); if (\$summary.PSObject.Properties.Name -contains 'recommended_commands' -and \$null -ne \$summary.recommended_commands) { \$recommended = @(\$summary.recommended_commands) }; if (-not (\$recommended | Where-Object { \$_.ToString() -like '*winget install --id jqlang.jq --exact*' })) { throw 'missing jq winget remediation recommendation when jq is missing' }" >"$log_path" 2>&1; then
    return 0
  fi
  echo "windows desktop native bootstrap guardrails failed: jq remediation assertion failed for $context_label"
  cat "$log_path"
  exit 1
}

assert_summary_missing_package_absent() {
  local json_path="$1"
  local context_label="$2"
  local package_id="$3"
  local json_path_ps
  json_path_ps="$(to_powershell_path "$json_path")"
  local log_path="$TMP_DIR/assert_missing_absent_${context_label}.log"
  if "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command "\$ErrorActionPreference='Stop'; \$summary = Get-Content -Raw -LiteralPath $(ps_single_quote "$json_path_ps") | ConvertFrom-Json; if (\$null -eq \$summary) { throw 'summary JSON parse failed' }; \$missing = @(); if (\$summary.PSObject.Properties.Name -contains 'missing_package_ids' -and \$null -ne \$summary.missing_package_ids) { \$missing = @(\$summary.missing_package_ids) }; if (\$missing -contains $(ps_single_quote "$package_id")) { throw ('unexpected package id in missing_package_ids: {0}' -f $(ps_single_quote "$package_id")) }" >"$log_path" 2>&1; then
    return 0
  fi
  echo "windows desktop native bootstrap guardrails failed: missing-package absence assertion failed for $context_label"
  cat "$log_path"
  exit 1
}

assert_summary_desktop_prerequisites() {
  local json_path="$1"
  local context_label="$2"
  local strategy_kind="${3:-packaged}"
  local json_path_ps
  json_path_ps="$(to_powershell_path "$json_path")"
  local log_path="$TMP_DIR/assert_desktop_prerequisites_${context_label}.log"
  if "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command "\$ErrorActionPreference='Stop'; \$summary = Get-Content -Raw -LiteralPath $(ps_single_quote "$json_path_ps") | ConvertFrom-Json; if (\$null -eq \$summary) { throw 'summary JSON parse failed' }; if (-not (\$summary.PSObject.Properties.Name -contains 'desktop_prerequisites')) { throw 'desktop_prerequisites field missing' }; \$desktop = \$summary.desktop_prerequisites; if (\$null -eq \$desktop) { throw 'desktop_prerequisites is null' }; \$keys = @('msvc_build_tools_x64','windows_sdk','webview2_runtime'); \$idMap = @{ msvc_build_tools_x64='Microsoft.VisualStudio.2022.BuildTools'; windows_sdk='Microsoft.WindowsSDK.10.0'; webview2_runtime='Microsoft.EdgeWebView2Runtime' }; foreach (\$key in \$keys) { if (-not (\$desktop.PSObject.Properties.Name -contains \$key)) { throw ('desktop prerequisite entry missing: {0}' -f \$key) }; \$entry = \$desktop.\$key; if (\$null -eq \$entry) { throw ('desktop prerequisite entry is null: {0}' -f \$key) }; if (-not (\$entry.PSObject.Properties.Name -contains 'installed')) { throw ('desktop prerequisite installed field missing: {0}' -f \$key) }; if (-not (\$entry.installed -is [bool])) { throw ('desktop prerequisite installed field is not boolean: {0}' -f \$key) } }; \$missing = @(); if (\$summary.PSObject.Properties.Name -contains 'missing_package_ids' -and \$null -ne \$summary.missing_package_ids) { \$missing = @(\$summary.missing_package_ids) }; if ($(ps_single_quote "$strategy_kind") -eq 'packaged') { foreach (\$id in \$idMap.Values) { if (\$missing -contains \$id) { throw ('packaged strategy should not require desktop build prerequisite id: {0}' -f \$id) } } } else { foreach (\$key in \$keys) { \$entry = \$desktop.\$key; \$id = \$idMap[\$key]; if (-not [bool]\$entry.installed -and -not (\$missing -contains \$id)) { throw ('missing_package_ids does not include desktop prerequisite id when prerequisite is missing: {0}' -f \$id) } } }" >"$log_path" 2>&1; then
    return 0
  fi
  echo "windows desktop native bootstrap guardrails failed: desktop_prerequisites assertion failed for $context_label"
  cat "$log_path"
  exit 1
}

assert_summary_desktop_resolution() {
  local json_path="$1"
  local context_label="$2"
  local expected_path="$3"
  local expected_source="$4"
  local expected_strategy="${5:-packaged}"
  local json_path_ps
  local expected_path_ps
  json_path_ps="$(to_powershell_path "$json_path")"
  expected_path_ps="$(to_powershell_path "$expected_path")"
  local log_path="$TMP_DIR/assert_desktop_resolution_${context_label}.log"
  if "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command "\$ErrorActionPreference='Stop'; \$summary = Get-Content -Raw -LiteralPath $(ps_single_quote "$json_path_ps") | ConvertFrom-Json; if (\$null -eq \$summary) { throw 'summary JSON parse failed' }; if (-not (\$summary.PSObject.Properties.Name -contains 'desktop_launch_strategy')) { throw 'desktop_launch_strategy field missing' }; if (-not (\$summary.PSObject.Properties.Name -contains 'desktop_launch_source')) { throw 'desktop_launch_source field missing' }; if (-not (\$summary.PSObject.Properties.Name -contains 'desktop_executable_path')) { throw 'desktop_executable_path field missing' }; \$actualStrategy = [string]\$summary.desktop_launch_strategy; \$actualSource = [string]\$summary.desktop_launch_source; \$actualPath = [string]\$summary.desktop_executable_path; if (\$actualStrategy -ne $(ps_single_quote "$expected_strategy")) { throw ('desktop_launch_strategy mismatch: expected={0} actual={1}' -f $(ps_single_quote "$expected_strategy"), \$actualStrategy) }; if ([string]::IsNullOrWhiteSpace(\$actualPath)) { throw 'desktop_executable_path is empty' }; \$expectedPath = (Resolve-Path -LiteralPath $(ps_single_quote "$expected_path_ps")).Path; if (-not [string]::Equals(\$actualPath, \$expectedPath, [System.StringComparison]::OrdinalIgnoreCase)) { throw ('desktop_executable_path mismatch: expected={0} actual={1}' -f \$expectedPath, \$actualPath) }; if (\$actualSource -ne $(ps_single_quote "$expected_source")) { throw ('desktop_launch_source mismatch: expected={0} actual={1}' -f $(ps_single_quote "$expected_source"), \$actualSource) }" >"$log_path" 2>&1; then
    return 0
  fi
  echo "windows desktop native bootstrap guardrails failed: desktop resolution assertion failed for $context_label"
  cat "$log_path"
  exit 1
}

FAKE_TOOL_DIR="$TMP_DIR/fake-tools"
FAKE_TOOL_DIR_NO_JQ="$TMP_DIR/fake-tools-no-jq"
mkdir -p "$FAKE_TOOL_DIR" "$FAKE_TOOL_DIR_NO_JQ"

FAKE_GO="$FAKE_TOOL_DIR/go"
cat >"$FAKE_GO" <<'EOF_FAKE_GO'
#!/usr/bin/env bash
exit 0
EOF_FAKE_GO
chmod +x "$FAKE_GO"

FAKE_GIT_BASH="$FAKE_TOOL_DIR/bash.exe"
cat >"$FAKE_GIT_BASH" <<'EOF_FAKE_GIT_BASH'
#!/usr/bin/env bash
exit 0
EOF_FAKE_GIT_BASH
chmod +x "$FAKE_GIT_BASH"

FAKE_JQ="$FAKE_TOOL_DIR/jq"
cat >"$FAKE_JQ" <<'EOF_FAKE_JQ'
#!/usr/bin/env bash
exit 0
EOF_FAKE_JQ
chmod +x "$FAKE_JQ"

FAKE_JQ_CMD="$FAKE_TOOL_DIR/jq.cmd"
cat >"$FAKE_JQ_CMD" <<'EOF_FAKE_JQ_CMD'
@echo off
exit /b 0
EOF_FAKE_JQ_CMD

FAKE_GO_NO_JQ="$FAKE_TOOL_DIR_NO_JQ/go"
cat >"$FAKE_GO_NO_JQ" <<'EOF_FAKE_GO_NO_JQ'
#!/usr/bin/env bash
exit 0
EOF_FAKE_GO_NO_JQ
chmod +x "$FAKE_GO_NO_JQ"

FAKE_GIT_BASH_NO_JQ="$FAKE_TOOL_DIR_NO_JQ/bash.exe"
cat >"$FAKE_GIT_BASH_NO_JQ" <<'EOF_FAKE_GIT_BASH_NO_JQ'
#!/usr/bin/env bash
exit 0
EOF_FAKE_GIT_BASH_NO_JQ
chmod +x "$FAKE_GIT_BASH_NO_JQ"

FAKE_GIT_BASH_PS="$(to_powershell_path "$FAKE_GIT_BASH")"
FAKE_GIT_BASH_NO_JQ_PS="$(to_powershell_path "$FAKE_GIT_BASH_NO_JQ")"

FAKE_DESKTOP_EXE="$TMP_DIR/fake-desktop.exe"
printf '%s\n' "placeholder desktop executable used by dry-run integration guardrails" >"$FAKE_DESKTOP_EXE"
FAKE_DESKTOP_EXE_PS="$(to_powershell_path "$FAKE_DESKTOP_EXE")"

FAKE_DESKTOP_EXE_ENV_GLOBAL="$TMP_DIR/fake-desktop-env-global.exe"
printf '%s\n' "placeholder desktop executable for GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE guardrails" >"$FAKE_DESKTOP_EXE_ENV_GLOBAL"
FAKE_DESKTOP_EXE_ENV_GLOBAL_PS="$(to_powershell_path "$FAKE_DESKTOP_EXE_ENV_GLOBAL")"

FAKE_DESKTOP_EXE_ENV_GPM="$TMP_DIR/fake-desktop-env-gpm.exe"
printf '%s\n' "placeholder desktop executable for GPM_DESKTOP_PACKAGED_EXE guardrails" >"$FAKE_DESKTOP_EXE_ENV_GPM"
FAKE_DESKTOP_EXE_ENV_GPM_PS="$(to_powershell_path "$FAKE_DESKTOP_EXE_ENV_GPM")"

FAKE_DESKTOP_EXE_ENV_TDPN="$TMP_DIR/fake-desktop-env-tdpn.exe"
printf '%s\n' "placeholder desktop executable for TDPN_DESKTOP_PACKAGED_EXE guardrails" >"$FAKE_DESKTOP_EXE_ENV_TDPN"
FAKE_DESKTOP_EXE_ENV_TDPN_PS="$(to_powershell_path "$FAKE_DESKTOP_EXE_ENV_TDPN")"

run_ps_with_fake_prereqs() {
  env \
    PATH="$(prepend_tool_path_for_powershell "$FAKE_TOOL_DIR")" \
    LOCAL_CONTROL_API_GIT_BASH_PATH="$FAKE_GIT_BASH_PS" \
    "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" -SkipPathRefresh "$@"
}

run_ps_with_fake_prereqs_no_jq() {
  env \
    PATH="$(prepend_tool_path_for_powershell "$FAKE_TOOL_DIR_NO_JQ" "")" \
    LOCAL_CONTROL_API_GIT_BASH_PATH="$FAKE_GIT_BASH_NO_JQ_PS" \
    DESKTOP_NATIVE_BOOTSTRAP_DISABLE_TOOL_FALLBACK_LOOKUPS=1 \
    DESKTOP_NATIVE_BOOTSTRAP_DISABLE_COMMON_TOOL_PATH_AUGMENT=1 \
    "$POWERSHELL_BIN_PATH" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" -SkipPathRefresh "$@"
}

echo "[windows-desktop-native-bootstrap-guardrails] check --dry-run passes"
run_expect_pass \
  "check_dry_run_pass" \
  run_ps_with_fake_prereqs \
    -Mode check \
    -DesktopLaunchStrategy packaged \
    -DesktopExecutableOverridePath "$FAKE_DESKTOP_EXE_PS" \
    -DryRun

echo "[windows-desktop-native-bootstrap-guardrails] bootstrap --dry-run enforces jq prerequisite when jq is missing"
run_expect_pass_or_fail_regex \
  "bootstrap_dry_run_missing_jq_fail" \
  "jqlang\\.jq|required dependencies missing|missing prerequisites" \
  run_ps_with_fake_prereqs_no_jq \
    -Mode bootstrap \
    -DesktopLaunchStrategy packaged \
    -DesktopExecutableOverridePath "$FAKE_DESKTOP_EXE_PS" \
    -DryRun

echo "[windows-desktop-native-bootstrap-guardrails] run-full --dry-run enforces jq prerequisite when jq is missing"
run_expect_pass_or_fail_regex \
  "run_full_dry_run_missing_jq_fail" \
  "jqlang\\.jq|required dependencies missing|missing prerequisites" \
  run_ps_with_fake_prereqs_no_jq \
    -Mode run-full \
    -DesktopLaunchStrategy packaged \
    -DesktopExecutableOverridePath "$FAKE_DESKTOP_EXE_PS" \
    -DryRun

echo "[windows-desktop-native-bootstrap-guardrails] invalid mode fails with expected message"
run_expect_fail_regex \
  "invalid_mode_fail" \
  "unsupported mode|invalid mode|cannot validate argument.*mode|parameter.*mode" \
  env \
    PATH="$(prepend_tool_path_for_powershell "$FAKE_TOOL_DIR")" \
    LOCAL_CONTROL_API_GIT_BASH_PATH="$FAKE_GIT_BASH_PS" \
    "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" \
      -Mode invalid-mode \
      -DryRun

echo "[windows-desktop-native-bootstrap-guardrails] WSL sessions fail fast with actionable non-WSL guidance"
run_expect_fail_regex \
  "wsl_session_fail_fast" \
  "Windows-native and must run outside WSL|non-WSL|wsl2_easy\\.cmd bootstrap" \
  env \
    PATH="$(prepend_tool_path_for_powershell "$FAKE_TOOL_DIR")" \
    LOCAL_CONTROL_API_GIT_BASH_PATH="$FAKE_GIT_BASH_PS" \
    "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
      "\$ErrorActionPreference='Stop'; \$env:WSL_DISTRO_NAME='Ubuntu-guardrail'; & $(ps_single_quote "$SCRIPT_UNDER_TEST_PS") -SkipPathRefresh -Mode check -DesktopLaunchStrategy packaged -DesktopExecutableOverridePath $(ps_single_quote "$FAKE_DESKTOP_EXE_PS") -DryRun"

SUMMARY_FLAG="$(detect_summary_flag "$SCRIPT_UNDER_TEST")"
if [[ -z "$SUMMARY_FLAG" ]]; then
  echo "windows desktop native bootstrap guardrails failed: unable to detect summary-json parameter marker in $SCRIPT_UNDER_TEST"
  exit 1
fi

SUMMARY_JSON="$TMP_DIR/desktop_native_bootstrap_summary.json"
SUMMARY_JSON_PS="$(to_powershell_path "$SUMMARY_JSON")"

ENV_PRIORITY_SUMMARY_JSON="$TMP_DIR/desktop_native_bootstrap_env_priority_summary.json"
ENV_PRIORITY_SUMMARY_JSON_PS="$(to_powershell_path "$ENV_PRIORITY_SUMMARY_JSON")"

ENV_GLOBAL_SUMMARY_JSON="$TMP_DIR/desktop_native_bootstrap_env_global_summary.json"
ENV_GLOBAL_SUMMARY_JSON_PS="$(to_powershell_path "$ENV_GLOBAL_SUMMARY_JSON")"

ENV_TDPN_SUMMARY_JSON="$TMP_DIR/desktop_native_bootstrap_env_tdpn_summary.json"
ENV_TDPN_SUMMARY_JSON_PS="$(to_powershell_path "$ENV_TDPN_SUMMARY_JSON")"

EXPLICIT_BEATS_ENV_SUMMARY_JSON="$TMP_DIR/desktop_native_bootstrap_explicit_beats_env_summary.json"
EXPLICIT_BEATS_ENV_SUMMARY_JSON_PS="$(to_powershell_path "$EXPLICIT_BEATS_ENV_SUMMARY_JSON")"

DEV_STRATEGY_SUMMARY_JSON="$TMP_DIR/desktop_native_bootstrap_dev_strategy_summary.json"
DEV_STRATEGY_SUMMARY_JSON_PS="$(to_powershell_path "$DEV_STRATEGY_SUMMARY_JSON")"

RUN_DESKTOP_PACKAGED_NO_JQ_SUMMARY_JSON="$TMP_DIR/desktop_native_bootstrap_run_desktop_packaged_no_jq_summary.json"
RUN_DESKTOP_PACKAGED_NO_JQ_SUMMARY_JSON_PS="$(to_powershell_path "$RUN_DESKTOP_PACKAGED_NO_JQ_SUMMARY_JSON")"

RUN_DESKTOP_DEV_MISSING_SOURCE_ICON_SUMMARY_JSON="$TMP_DIR/desktop_native_bootstrap_run_desktop_dev_missing_source_icon_summary.json"
RUN_DESKTOP_DEV_MISSING_SOURCE_ICON_SUMMARY_JSON_PS="$(to_powershell_path "$RUN_DESKTOP_DEV_MISSING_SOURCE_ICON_SUMMARY_JSON")"

JQ_MISSING_SUMMARY_JSON="$TMP_DIR/desktop_native_bootstrap_jq_missing_summary.json"
JQ_MISSING_SUMMARY_JSON_PS="$(to_powershell_path "$JQ_MISSING_SUMMARY_JSON")"

RUN_FULL_DEFAULT_SUMMARY_JSON="$TMP_DIR/desktop_native_bootstrap_run_full_default_summary.json"
RUN_FULL_DEFAULT_SUMMARY_JSON_PS="$(to_powershell_path "$RUN_FULL_DEFAULT_SUMMARY_JSON")"
RUN_FULL_KEEP_SUMMARY_JSON="$TMP_DIR/desktop_native_bootstrap_run_full_keep_summary.json"
RUN_FULL_KEEP_SUMMARY_JSON_PS="$(to_powershell_path "$RUN_FULL_KEEP_SUMMARY_JSON")"

echo "[windows-desktop-native-bootstrap-guardrails] env override priority uses GPM_DESKTOP_PACKAGED_EXE under --dry-run"
run_expect_pass \
  "env_priority_dry_run_pass" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; \$env:GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE=$(ps_single_quote "$FAKE_DESKTOP_EXE_ENV_GLOBAL_PS"); \$env:GPM_DESKTOP_PACKAGED_EXE=$(ps_single_quote "$FAKE_DESKTOP_EXE_ENV_GPM_PS"); \$env:TDPN_DESKTOP_PACKAGED_EXE=$(ps_single_quote "$FAKE_DESKTOP_EXE_ENV_TDPN_PS"); & $(ps_single_quote "$SCRIPT_UNDER_TEST_PS") -Mode check -DesktopLaunchStrategy packaged -DryRun $SUMMARY_FLAG $(ps_single_quote "$ENV_PRIORITY_SUMMARY_JSON_PS")"
assert_json_file_is_object "$ENV_PRIORITY_SUMMARY_JSON" "env_priority_summary"
assert_summary_desktop_resolution "$ENV_PRIORITY_SUMMARY_JSON" "env_priority_summary" "$FAKE_DESKTOP_EXE_ENV_GPM" "env:GPM_DESKTOP_PACKAGED_EXE"
assert_summary_desktop_prerequisites "$ENV_PRIORITY_SUMMARY_JSON" "env_priority_summary" "packaged"

echo "[windows-desktop-native-bootstrap-guardrails] env override fallback uses GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE when GPM_DESKTOP_PACKAGED_EXE is unset"
run_expect_pass \
  "env_global_dry_run_pass" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; \$env:GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE=$(ps_single_quote "$FAKE_DESKTOP_EXE_ENV_GLOBAL_PS"); \$env:GPM_DESKTOP_PACKAGED_EXE=''; \$env:TDPN_DESKTOP_PACKAGED_EXE=$(ps_single_quote "$FAKE_DESKTOP_EXE_ENV_TDPN_PS"); & $(ps_single_quote "$SCRIPT_UNDER_TEST_PS") -Mode check -DesktopLaunchStrategy packaged -DryRun $SUMMARY_FLAG $(ps_single_quote "$ENV_GLOBAL_SUMMARY_JSON_PS")"
assert_json_file_is_object "$ENV_GLOBAL_SUMMARY_JSON" "env_global_summary"
assert_summary_desktop_resolution "$ENV_GLOBAL_SUMMARY_JSON" "env_global_summary" "$FAKE_DESKTOP_EXE_ENV_GLOBAL" "env:GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE"
assert_summary_desktop_prerequisites "$ENV_GLOBAL_SUMMARY_JSON" "env_global_summary" "packaged"

echo "[windows-desktop-native-bootstrap-guardrails] env override fallback uses TDPN_DESKTOP_PACKAGED_EXE under --dry-run"
run_expect_pass \
  "env_tdpn_dry_run_pass" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; \$env:GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE=''; \$env:GPM_DESKTOP_PACKAGED_EXE=''; \$env:TDPN_DESKTOP_PACKAGED_EXE=$(ps_single_quote "$FAKE_DESKTOP_EXE_ENV_TDPN_PS"); & $(ps_single_quote "$SCRIPT_UNDER_TEST_PS") -Mode check -DesktopLaunchStrategy packaged -DryRun $SUMMARY_FLAG $(ps_single_quote "$ENV_TDPN_SUMMARY_JSON_PS")"
assert_json_file_is_object "$ENV_TDPN_SUMMARY_JSON" "env_tdpn_summary"
assert_summary_desktop_resolution "$ENV_TDPN_SUMMARY_JSON" "env_tdpn_summary" "$FAKE_DESKTOP_EXE_ENV_TDPN" "env:TDPN_DESKTOP_PACKAGED_EXE"
assert_summary_desktop_prerequisites "$ENV_TDPN_SUMMARY_JSON" "env_tdpn_summary" "packaged"

echo "[windows-desktop-native-bootstrap-guardrails] explicit override path beats env overrides under --dry-run"
run_expect_pass \
  "explicit_override_beats_env_dry_run_pass" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; \$env:GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE=$(ps_single_quote "$FAKE_DESKTOP_EXE_ENV_GLOBAL_PS"); \$env:GPM_DESKTOP_PACKAGED_EXE=$(ps_single_quote "$FAKE_DESKTOP_EXE_ENV_GPM_PS"); \$env:TDPN_DESKTOP_PACKAGED_EXE=$(ps_single_quote "$FAKE_DESKTOP_EXE_ENV_TDPN_PS"); & $(ps_single_quote "$SCRIPT_UNDER_TEST_PS") -Mode check -DesktopLaunchStrategy packaged -DesktopExecutableOverridePath $(ps_single_quote "$FAKE_DESKTOP_EXE_PS") -DryRun $SUMMARY_FLAG $(ps_single_quote "$EXPLICIT_BEATS_ENV_SUMMARY_JSON_PS")"
assert_json_file_is_object "$EXPLICIT_BEATS_ENV_SUMMARY_JSON" "explicit_beats_env_summary"
assert_summary_desktop_resolution "$EXPLICIT_BEATS_ENV_SUMMARY_JSON" "explicit_beats_env_summary" "$FAKE_DESKTOP_EXE" "override"
assert_summary_desktop_prerequisites "$EXPLICIT_BEATS_ENV_SUMMARY_JSON" "explicit_beats_env_summary" "packaged"

echo "[windows-desktop-native-bootstrap-guardrails] run-desktop dev --dry-run handles missing source icon with scaffold guidance"
prepare_missing_source_icon_fixture
run_expect_pass \
  "run_desktop_dev_missing_source_icon_dry_run_pass" \
  run_ps_with_fake_prereqs \
    -Mode run-desktop \
    -DesktopLaunchStrategy dev \
    -DryRun \
    "$SUMMARY_FLAG" "$RUN_DESKTOP_DEV_MISSING_SOURCE_ICON_SUMMARY_JSON_PS"
restore_source_icon_fixture
assert_marker_present "dry-run desktop source icon remediation: would create placeholder source icon at" "$TMP_DIR/run_desktop_dev_missing_source_icon_dry_run_pass.log"
assert_json_file_is_object "$RUN_DESKTOP_DEV_MISSING_SOURCE_ICON_SUMMARY_JSON" "run_desktop_dev_missing_source_icon_summary"

echo "[windows-desktop-native-bootstrap-guardrails] dev strategy check summary carries desktop prerequisite diagnostics"
run_expect_pass \
  "dev_strategy_summary_pass" \
  run_ps_with_fake_prereqs \
    -Mode check \
    -DesktopLaunchStrategy dev \
    -DryRun \
    "$SUMMARY_FLAG" "$DEV_STRATEGY_SUMMARY_JSON_PS"
assert_json_file_is_object "$DEV_STRATEGY_SUMMARY_JSON" "dev_strategy_summary"
assert_summary_desktop_prerequisites "$DEV_STRATEGY_SUMMARY_JSON" "dev_strategy_summary" "dev"

echo "[windows-desktop-native-bootstrap-guardrails] run-desktop packaged --dry-run does not require jq"
run_expect_pass \
  "run_desktop_packaged_no_jq_dry_run_pass" \
  run_ps_with_fake_prereqs_no_jq \
    -Mode run-desktop \
    -DesktopLaunchStrategy packaged \
    -DesktopExecutableOverridePath "$FAKE_DESKTOP_EXE_PS" \
    -DryRun \
    "$SUMMARY_FLAG" "$RUN_DESKTOP_PACKAGED_NO_JQ_SUMMARY_JSON_PS"
assert_json_file_is_object "$RUN_DESKTOP_PACKAGED_NO_JQ_SUMMARY_JSON" "run_desktop_packaged_no_jq_summary"
assert_summary_missing_package_absent "$RUN_DESKTOP_PACKAGED_NO_JQ_SUMMARY_JSON" "run_desktop_packaged_no_jq_summary" "jqlang.jq"

echo "[windows-desktop-native-bootstrap-guardrails] check --dry-run with jq missing recommends jqlang.jq remediation"
run_expect_pass \
  "check_missing_jq_dry_run_pass" \
  run_ps_with_fake_prereqs_no_jq \
    -Mode check \
    -DesktopLaunchStrategy packaged \
    -DesktopExecutableOverridePath "$FAKE_DESKTOP_EXE_PS" \
    -DryRun \
    "$SUMMARY_FLAG" "$JQ_MISSING_SUMMARY_JSON_PS"
assert_json_file_is_object "$JQ_MISSING_SUMMARY_JSON" "jq_missing_summary"
assert_summary_recommended_commands "$JQ_MISSING_SUMMARY_JSON" "jq_missing_summary"
if summary_has_missing_package "$JQ_MISSING_SUMMARY_JSON" "jqlang.jq"; then
  assert_summary_jq_missing_remediation "$JQ_MISSING_SUMMARY_JSON" "jq_missing_summary"
else
  assert_summary_missing_package_absent "$JQ_MISSING_SUMMARY_JSON" "jq_missing_summary" "jqlang.jq"
fi

echo "[windows-desktop-native-bootstrap-guardrails] run-full --dry-run default keeps keep_api_running=false in summary/log output"
run_expect_pass \
  "run_full_dry_run_default_cleanup_summary" \
  run_ps_with_fake_prereqs \
    -Mode run-full \
    -DesktopLaunchStrategy packaged \
    -DesktopExecutableOverridePath "$FAKE_DESKTOP_EXE_PS" \
    -DryRun \
    "$SUMMARY_FLAG" "$RUN_FULL_DEFAULT_SUMMARY_JSON_PS"
assert_json_file_is_object "$RUN_FULL_DEFAULT_SUMMARY_JSON" "run_full_default_summary"
assert_summary_keep_api_running "$RUN_FULL_DEFAULT_SUMMARY_JSON" "run_full_default_summary" "false"
assert_summary_run_full_cleanup_fields "$RUN_FULL_DEFAULT_SUMMARY_JSON" "run_full_default_summary" "dry_run_no_api_started" "false"
assert_summary_run_full_recommended_keep_api_running "$RUN_FULL_DEFAULT_SUMMARY_JSON" "run_full_default_summary" "false"
assert_marker_present "keep_api_running=false" "$TMP_DIR/run_full_dry_run_default_cleanup_summary.log"

echo "[windows-desktop-native-bootstrap-guardrails] run-full --dry-run with -KeepApiRunning sets keep_api_running=true in summary/log output"
run_expect_pass \
  "run_full_dry_run_keep_api_running_summary" \
  run_ps_with_fake_prereqs \
    -Mode run-full \
    -DesktopLaunchStrategy packaged \
    -DesktopExecutableOverridePath "$FAKE_DESKTOP_EXE_PS" \
    -KeepApiRunning \
    -DryRun \
    "$SUMMARY_FLAG" "$RUN_FULL_KEEP_SUMMARY_JSON_PS"
assert_json_file_is_object "$RUN_FULL_KEEP_SUMMARY_JSON" "run_full_keep_summary"
assert_summary_keep_api_running "$RUN_FULL_KEEP_SUMMARY_JSON" "run_full_keep_summary" "true"
assert_summary_run_full_cleanup_fields "$RUN_FULL_KEEP_SUMMARY_JSON" "run_full_keep_summary" "dry_run_no_api_started" "false"
assert_summary_run_full_recommended_keep_api_running "$RUN_FULL_KEEP_SUMMARY_JSON" "run_full_keep_summary" "true"
assert_marker_present "keep_api_running=true" "$TMP_DIR/run_full_dry_run_keep_api_running_summary.log"

echo "[windows-desktop-native-bootstrap-guardrails] summary json is written when requested"
run_expect_pass \
  "summary_json_pass" \
  run_ps_with_fake_prereqs \
    -Mode check \
    -DesktopLaunchStrategy packaged \
    -DesktopExecutableOverridePath "$FAKE_DESKTOP_EXE_PS" \
    -DryRun \
    "$SUMMARY_FLAG" "$SUMMARY_JSON_PS"

if [[ ! -f "$SUMMARY_JSON" ]]; then
  echo "windows desktop native bootstrap guardrails failed: summary json was not written: $SUMMARY_JSON"
  cat "$TMP_DIR/summary_json_pass.log"
  exit 1
fi
assert_json_file_is_object "$SUMMARY_JSON" "summary_json_file"
assert_summary_recommended_commands "$SUMMARY_JSON" "summary_json_file"
assert_summary_desktop_prerequisites "$SUMMARY_JSON" "summary_json_file" "packaged"
assert_summary_execution_policy_bypass_command "$SUMMARY_JSON" "summary_json_file" "check" "$SUMMARY_JSON" "0"

PRINT_SUMMARY_FLAG="$(detect_print_summary_flag "$SCRIPT_UNDER_TEST")"
if [[ -z "$PRINT_SUMMARY_FLAG" ]]; then
  echo "windows desktop native bootstrap guardrails failed: unable to detect print-summary-json parameter marker in $SCRIPT_UNDER_TEST"
  exit 1
fi

PRINTED_SUMMARY_JSON="$TMP_DIR/desktop_native_bootstrap_printed_summary.json"
PRINTED_SUMMARY_JSON_PS="$(to_powershell_path "$PRINTED_SUMMARY_JSON")"

echo "[windows-desktop-native-bootstrap-guardrails] printed summary json is valid with print-summary-json flag"
run_expect_pass \
  "print_summary_json_pass" \
  env \
    PATH="$(prepend_tool_path_for_powershell "$FAKE_TOOL_DIR")" \
    LOCAL_CONTROL_API_GIT_BASH_PATH="$FAKE_GIT_BASH_PS" \
    "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
      "\$ErrorActionPreference='Stop'; \$out = & $(ps_single_quote "$SCRIPT_UNDER_TEST_PS") -Mode check -DesktopLaunchStrategy packaged -DesktopExecutableOverridePath $(ps_single_quote "$FAKE_DESKTOP_EXE_PS") -DryRun $PRINT_SUMMARY_FLAG 1; if (\$null -eq \$out) { throw 'no summary JSON was emitted' }; \$out | Set-Content -LiteralPath $(ps_single_quote "$PRINTED_SUMMARY_JSON_PS") -Encoding UTF8"

if [[ ! -f "$PRINTED_SUMMARY_JSON" ]]; then
  echo "windows desktop native bootstrap guardrails failed: printed summary json capture missing: $PRINTED_SUMMARY_JSON"
  cat "$TMP_DIR/print_summary_json_pass.log"
  exit 1
fi
assert_json_file_is_object "$PRINTED_SUMMARY_JSON" "printed_summary_json"
assert_summary_recommended_commands "$PRINTED_SUMMARY_JSON" "printed_summary_json"
assert_summary_desktop_prerequisites "$PRINTED_SUMMARY_JSON" "printed_summary_json" "packaged"

echo "windows desktop native bootstrap guardrails integration check ok"
