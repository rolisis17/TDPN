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

SCRIPT_UNDER_TEST="${DESKTOP_DOCTOR_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/windows/desktop_doctor.ps1}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "windows desktop doctor guardrails failed: missing script: $SCRIPT_UNDER_TEST"
  exit 1
fi

if command -v powershell >/dev/null 2>&1; then
  POWERSHELL_BIN="powershell"
elif command -v pwsh >/dev/null 2>&1; then
  POWERSHELL_BIN="pwsh"
elif command -v powershell.exe >/dev/null 2>&1; then
  POWERSHELL_BIN="powershell.exe"
else
  echo "windows desktop doctor guardrails failed: missing powershell/pwsh/powershell.exe"
  exit 2
fi

POWERSHELL_USES_WINDOWS_PATHS="0"
if [[ "$POWERSHELL_BIN" == *.exe ]]; then
  POWERSHELL_USES_WINDOWS_PATHS="1"
fi

to_powershell_path() {
  local path="$1"
  if [[ "$POWERSHELL_USES_WINDOWS_PATHS" == "1" ]] && command -v wslpath >/dev/null 2>&1; then
    wslpath -w "$path"
    return
  fi
  printf '%s' "$path"
}

detect_summary_flag() {
  local script_path="$1"
  if grep -qiE '\$SummaryJsonPath([^A-Za-z0-9_]|$)' "$script_path"; then
    printf '%s' "-SummaryJsonPath"
    return
  fi
  if grep -qiE '\$SummaryJson([^A-Za-z0-9_]|$)' "$script_path"; then
    printf '%s' "-SummaryJson"
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

TMP_DIR="$(mktemp -d)"
cleanup() {
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
  echo "windows desktop doctor guardrails failed: expected pass for $name"
  cat "$log_path"
  exit 1
}

run_expect_fail_regex() {
  local name="$1"
  local expected_pattern="$2"
  shift 2
  local log_path="$TMP_DIR/${name}.log"
  if "$@" >"$log_path" 2>&1; then
    echo "windows desktop doctor guardrails failed: expected failure for $name"
    cat "$log_path"
    exit 1
  fi
  if ! grep -Eiq -- "$expected_pattern" "$log_path"; then
    echo "windows desktop doctor guardrails failed: missing expected failure text for $name"
    echo "expected regex: $expected_pattern"
    cat "$log_path"
    exit 1
  fi
}

echo "[windows-desktop-doctor-guardrails] mode + dry-run markers are present"
if ! grep -qE '\[ValidateSet\("check",[[:space:]]*"fix"\)\]' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing check/fix ValidateSet marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qE '\[switch\]\$DryRun' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing DryRun switch marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qE 'if[[:space:]]*\([[:space:]]*\$DryRun[[:space:]]*\)' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing DryRun branch marker in $SCRIPT_UNDER_TEST"
  exit 1
fi

SUMMARY_FLAG="$(detect_summary_flag "$SCRIPT_UNDER_TEST")"
if [[ -z "$SUMMARY_FLAG" ]]; then
  echo "windows desktop doctor guardrails failed: unable to detect summary-json parameter marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'Write-SummaryJsonFile' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing summary writer marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qE 'PrintSummaryJson' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing PrintSummaryJson marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qE 'recommended_commands[[:space:]]*=' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing recommended_commands summary assignment marker in $SCRIPT_UNDER_TEST"
  exit 1
fi

echo "[windows-desktop-doctor-guardrails] remediation command markers are present"
if ! grep -qF 'function Get-RecommendedCommands' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing remediation command helper marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'recommended_commands' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing recommended_commands summary field marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'recommended commands (copy/paste)' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing copy/paste remediation output marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing policy bypass remediation command marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'winget install --id' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing winget remediation command marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'jqlang.jq' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing jq winget package marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'jq:' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing jq tool report output marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'npm.cmd install' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing npm install remediation command marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'scripts\windows\desktop_shell.cmd npm install' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing desktop_shell npm install remediation command marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'scripts\windows\desktop_shell.cmd npm run tauri -- dev' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing desktop_shell tauri dev remediation command marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'npm.cmd run tauri -- dev' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing tauri dev remediation command marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'scripts\windows\desktop_node.cmd npm run generate:windows-icon' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing windows icon generation remediation command marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'desktop_one_click.ps1' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing one-click rerun remediation marker in $SCRIPT_UNDER_TEST"
  exit 1
fi

echo "[windows-desktop-doctor-guardrails] desktop prerequisite markers are present"
if ! grep -qF 'Microsoft.VisualStudio.2022.BuildTools' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing Visual C++ Build Tools package marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'Microsoft.WindowsSDK.10.0' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing Windows SDK package marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if grep -qF '"Microsoft.WindowsSDK.10.0" { return "" }' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: Windows SDK must not be hard-skipped from winget remediation"
  exit 1
fi
if ! grep -qF 'winget install --id Microsoft.WindowsSDK.10.0 --exact' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing Windows SDK winget remediation command marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'Microsoft.EdgeWebView2Runtime' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing WebView2 runtime package marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'developer.microsoft.com/windows/downloads/windows-sdk/' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing Windows SDK official remediation hint marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'developer.microsoft.com/microsoft-edge/webview2/' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing WebView2 official remediation hint marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'desktop asset report:' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing desktop asset report marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'desktop_assets' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing desktop_assets summary marker in $SCRIPT_UNDER_TEST"
  exit 1
fi
if ! grep -qF 'desktop_asset_issue_ids' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop doctor guardrails failed: missing desktop_asset_issue_ids summary marker in $SCRIPT_UNDER_TEST"
  exit 1
fi

echo "[windows-desktop-doctor-guardrails] check dry-run passes"
run_expect_pass \
  "check_dry_run_pass" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" \
    -Mode check \
    -DryRun

echo "[windows-desktop-doctor-guardrails] fix dry-run passes"
run_expect_pass \
  "fix_dry_run_pass" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" \
    -Mode fix \
    -DryRun

SUMMARY_JSON="$TMP_DIR/desktop_doctor_summary.json"
SUMMARY_JSON_PS="$(to_powershell_path "$SUMMARY_JSON")"

echo "[windows-desktop-doctor-guardrails] summary json is written when requested"
run_expect_pass \
  "summary_json_pass" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" \
    -Mode check \
    -DryRun \
    "$SUMMARY_FLAG" "$SUMMARY_JSON_PS"

if [[ ! -f "$SUMMARY_JSON" ]]; then
  echo "windows desktop doctor guardrails failed: summary json was not written: $SUMMARY_JSON"
  cat "$TMP_DIR/summary_json_pass.log"
  exit 1
fi
if ! jq -e 'type == "object"' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "windows desktop doctor guardrails failed: summary json is not a JSON object"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.tool_report | type == "object" and has("jq")' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "windows desktop doctor guardrails failed: summary json missing tool_report.jq field"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.recommended_commands | type == "array" and length >= 2' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "windows desktop doctor guardrails failed: summary json missing recommended_commands guidance array"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.recommended_commands | any(type == "string" and contains("npm.cmd install"))' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "windows desktop doctor guardrails failed: summary json missing npm install remediation command"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.recommended_commands | any(type == "string" and contains("desktop_shell.cmd") and contains("npm install"))' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "windows desktop doctor guardrails failed: summary json missing desktop_shell npm install remediation command"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.recommended_commands | any(type == "string" and contains("desktop_shell.cmd") and contains("npm run tauri -- dev"))' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "windows desktop doctor guardrails failed: summary json missing desktop_shell tauri dev remediation command"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.recommended_commands | any(type == "string" and contains("npm.cmd run tauri -- dev"))' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "windows desktop doctor guardrails failed: summary json missing tauri dev remediation command"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.recommended_commands | any(type == "string" and contains("generate:windows-icon"))' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "windows desktop doctor guardrails failed: summary json missing windows icon generation remediation command"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e 'if ((.tool_report.jq // "") | tostring | length) == 0 then (.missing_package_ids | index("jqlang.jq") != null) else true end' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "windows desktop doctor guardrails failed: missing package ids do not include jqlang.jq when jq tool is missing"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e 'if .desktop_prerequisites.windows_sdk.installed == false then (.recommended_commands | any(type == "string" and contains("Microsoft.WindowsSDK.10.0"))) else true end' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "windows desktop doctor guardrails failed: summary json missing Windows SDK remediation command when Windows SDK is missing"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e 'if .desktop_prerequisites.windows_sdk.installed == false then (.recommended_commands | any(type == "string" and contains("windows-sdk"))) else true end' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "windows desktop doctor guardrails failed: summary json missing Windows SDK fallback guidance link when Windows SDK is missing"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.desktop_prerequisites | type == "object" and has("msvc_build_tools_x64") and has("windows_sdk") and has("webview2_runtime")' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "windows desktop doctor guardrails failed: summary json missing desktop_prerequisites object with expected keys"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.desktop_assets | type == "object" and has("source_icon") and has("generated_icon") and has("tauri_bundle_icon")' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "windows desktop doctor guardrails failed: summary json missing desktop_assets object with expected keys"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.desktop_asset_issue_ids | type == "array"' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "windows desktop doctor guardrails failed: summary json missing desktop_asset_issue_ids array"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.desktop_prerequisites.msvc_build_tools_x64.installed | type == "boolean"' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "windows desktop doctor guardrails failed: summary json missing msvc_build_tools_x64 installed boolean"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.desktop_prerequisites.windows_sdk.installed | type == "boolean"' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "windows desktop doctor guardrails failed: summary json missing windows_sdk installed boolean"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.desktop_prerequisites.webview2_runtime.installed | type == "boolean"' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "windows desktop doctor guardrails failed: summary json missing webview2_runtime installed boolean"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e 'if .desktop_prerequisites.msvc_build_tools_x64.installed == false then (.missing_package_ids | index("Microsoft.VisualStudio.2022.BuildTools") != null) else true end' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "windows desktop doctor guardrails failed: missing package ids do not include Visual C++ Build Tools when prerequisite is missing"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e 'if .desktop_prerequisites.windows_sdk.installed == false then (.missing_package_ids | index("Microsoft.WindowsSDK.10.0") != null) else true end' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "windows desktop doctor guardrails failed: missing package ids do not include Windows SDK when prerequisite is missing"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e 'if .desktop_prerequisites.webview2_runtime.installed == false then (.missing_package_ids | index("Microsoft.EdgeWebView2Runtime") != null) else true end' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "windows desktop doctor guardrails failed: missing package ids do not include WebView2 runtime when prerequisite is missing"
  cat "$SUMMARY_JSON"
  exit 1
fi

echo "[windows-desktop-doctor-guardrails] invalid mode fails with expected message"
run_expect_fail_regex \
  "invalid_mode_fail" \
  "unsupported mode|invalid mode|cannot validate argument.*mode|parameter.*mode" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" \
    -Mode invalid-mode \
    -DryRun

echo "windows desktop doctor guardrails integration check ok"
