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

FAKE_TOOL_DIR="$TMP_DIR/fake-tools"
mkdir -p "$FAKE_TOOL_DIR"

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

FAKE_GIT_BASH_PS="$(to_powershell_path "$FAKE_GIT_BASH")"

FAKE_DESKTOP_EXE="$TMP_DIR/fake-desktop.exe"
printf '%s\n' "placeholder desktop executable used by dry-run integration guardrails" >"$FAKE_DESKTOP_EXE"
FAKE_DESKTOP_EXE_PS="$(to_powershell_path "$FAKE_DESKTOP_EXE")"

run_ps_with_fake_prereqs() {
  env \
    PATH="$FAKE_TOOL_DIR:$PATH" \
    LOCAL_CONTROL_API_GIT_BASH_PATH="$FAKE_GIT_BASH_PS" \
    "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" "$@"
}

echo "[windows-desktop-native-bootstrap-guardrails] check --dry-run passes"
run_expect_pass \
  "check_dry_run_pass" \
  run_ps_with_fake_prereqs \
    -Mode check \
    -DesktopLaunchStrategy packaged \
    -DesktopExecutableOverridePath "$FAKE_DESKTOP_EXE_PS" \
    -DryRun

echo "[windows-desktop-native-bootstrap-guardrails] bootstrap --dry-run passes"
run_expect_pass \
  "bootstrap_dry_run_pass" \
  run_ps_with_fake_prereqs \
    -Mode bootstrap \
    -DesktopLaunchStrategy packaged \
    -DesktopExecutableOverridePath "$FAKE_DESKTOP_EXE_PS" \
    -DryRun

echo "[windows-desktop-native-bootstrap-guardrails] run-full --dry-run passes"
run_expect_pass \
  "run_full_dry_run_pass" \
  run_ps_with_fake_prereqs \
    -Mode run-full \
    -DesktopLaunchStrategy packaged \
    -DesktopExecutableOverridePath "$FAKE_DESKTOP_EXE_PS" \
    -DryRun

echo "[windows-desktop-native-bootstrap-guardrails] invalid mode fails with expected message"
run_expect_fail_regex \
  "invalid_mode_fail" \
  "unsupported mode|invalid mode|cannot validate argument.*mode|parameter.*mode" \
  env \
    PATH="$FAKE_TOOL_DIR:$PATH" \
    LOCAL_CONTROL_API_GIT_BASH_PATH="$FAKE_GIT_BASH_PS" \
    "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" \
      -Mode invalid-mode \
      -DryRun

SUMMARY_FLAG="$(detect_summary_flag "$SCRIPT_UNDER_TEST")"
if [[ -z "$SUMMARY_FLAG" ]]; then
  echo "windows desktop native bootstrap guardrails failed: unable to detect summary-json parameter marker in $SCRIPT_UNDER_TEST"
  exit 1
fi

SUMMARY_JSON="$TMP_DIR/desktop_native_bootstrap_summary.json"
SUMMARY_JSON_PS="$(to_powershell_path "$SUMMARY_JSON")"

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
    PATH="$FAKE_TOOL_DIR:$PATH" \
    LOCAL_CONTROL_API_GIT_BASH_PATH="$FAKE_GIT_BASH_PS" \
    "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
      "\$ErrorActionPreference='Stop'; \$out = & $(ps_single_quote "$SCRIPT_UNDER_TEST_PS") -Mode check -DesktopLaunchStrategy packaged -DesktopExecutableOverridePath $(ps_single_quote "$FAKE_DESKTOP_EXE_PS") -DryRun $PRINT_SUMMARY_FLAG 1; if (\$null -eq \$out) { throw 'no summary JSON was emitted' }; \$out | Set-Content -LiteralPath $(ps_single_quote "$PRINTED_SUMMARY_JSON_PS") -Encoding UTF8"

if [[ ! -f "$PRINTED_SUMMARY_JSON" ]]; then
  echo "windows desktop native bootstrap guardrails failed: printed summary json capture missing: $PRINTED_SUMMARY_JSON"
  cat "$TMP_DIR/print_summary_json_pass.log"
  exit 1
fi
assert_json_file_is_object "$PRINTED_SUMMARY_JSON" "printed_summary_json"

echo "windows desktop native bootstrap guardrails integration check ok"
