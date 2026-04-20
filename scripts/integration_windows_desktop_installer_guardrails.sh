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

SCRIPT_UNDER_TEST="${DESKTOP_WINDOWS_INSTALLER_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/windows/desktop_installer.ps1}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "windows desktop installer guardrails failed: missing script: $SCRIPT_UNDER_TEST"
  exit 1
fi

if command -v powershell >/dev/null 2>&1; then
  POWERSHELL_BIN="powershell"
elif command -v pwsh >/dev/null 2>&1; then
  POWERSHELL_BIN="pwsh"
elif command -v powershell.exe >/dev/null 2>&1; then
  POWERSHELL_BIN="powershell.exe"
else
  echo "windows desktop installer guardrails failed: missing powershell/pwsh/powershell.exe"
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
  echo "windows desktop installer guardrails failed: expected pass for $name"
  cat "$log_path"
  exit 1
}

run_expect_fail_regex() {
  local name="$1"
  local expected_pattern="$2"
  shift 2
  local log_path="$TMP_DIR/${name}.log"
  if "$@" >"$log_path" 2>&1; then
    echo "windows desktop installer guardrails failed: expected failure for $name"
    cat "$log_path"
    exit 1
  fi
  if ! grep -Eiq -- "$expected_pattern" "$log_path"; then
    echo "windows desktop installer guardrails failed: missing expected failure output for $name"
    echo "expected regex: $expected_pattern"
    cat "$log_path"
    exit 1
  fi
}

assert_json_expr() {
  local summary_json="$1"
  local jq_expr="$2"
  local label="$3"
  if ! jq -e "$jq_expr" "$summary_json" >/dev/null 2>&1; then
    echo "windows desktop installer guardrails failed: $label"
    cat "$summary_json"
    exit 1
  fi
}

echo "[windows-desktop-installer-guardrails] parameter and marker contract"
for marker in \
  '\$InstallerPath' \
  '\$InstallerType' \
  '\$BuildIfMissing' \
  '\$Silent' \
  '\$DryRun' \
  '\$SummaryJson' \
  '\$PrintSummaryJson'
do
  if ! grep -qE -- "$marker" "$SCRIPT_UNDER_TEST"; then
    echo "windows desktop installer guardrails failed: missing marker '$marker' in $SCRIPT_UNDER_TEST"
    exit 1
  fi
done

EXE_INSTALLER="$TMP_DIR/fake_installer.exe"
MSI_INSTALLER="$TMP_DIR/fake_installer.msi"
printf 'fake exe payload\n' >"$EXE_INSTALLER"
printf 'fake msi payload\n' >"$MSI_INSTALLER"

EXE_INSTALLER_PS="$(to_powershell_path "$EXE_INSTALLER")"
MSI_INSTALLER_PS="$(to_powershell_path "$MSI_INSTALLER")"

echo "[windows-desktop-installer-guardrails] explicit .exe dry-run emits expected summary"
EXE_SUMMARY_JSON="$TMP_DIR/exe_summary.json"
EXE_SUMMARY_JSON_PS="$(to_powershell_path "$EXE_SUMMARY_JSON")"
run_expect_pass \
  "explicit_exe_dry_run" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" \
    -InstallerPath "$EXE_INSTALLER_PS" \
    -DryRun \
    -SummaryJson "$EXE_SUMMARY_JSON_PS" \
    -PrintSummaryJson 0

if [[ ! -f "$EXE_SUMMARY_JSON" ]]; then
  echo "windows desktop installer guardrails failed: missing summary json for explicit exe dry-run: $EXE_SUMMARY_JSON"
  cat "$TMP_DIR/explicit_exe_dry_run.log"
  exit 1
fi
assert_json_expr "$EXE_SUMMARY_JSON" '.status == "ok"' "explicit exe summary must have status=ok"
assert_json_expr "$EXE_SUMMARY_JSON" '.platform == "windows"' "explicit exe summary must have platform=windows"
assert_json_expr "$EXE_SUMMARY_JSON" '.installer_type == "nsis"' "explicit exe summary must infer installer_type=nsis"
assert_json_expr "$EXE_SUMMARY_JSON" '.installer_source == "explicit"' "explicit exe summary must have installer_source=explicit"
assert_json_expr "$EXE_SUMMARY_JSON" '.dry_run == true' "explicit exe summary must set dry_run=true"

echo "[windows-desktop-installer-guardrails] explicit .msi dry-run emits expected summary"
MSI_SUMMARY_JSON="$TMP_DIR/msi_summary.json"
MSI_SUMMARY_JSON_PS="$(to_powershell_path "$MSI_SUMMARY_JSON")"
run_expect_pass \
  "explicit_msi_dry_run" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" \
    -InstallerPath "$MSI_INSTALLER_PS" \
    -DryRun \
    -SummaryJson "$MSI_SUMMARY_JSON_PS" \
    -PrintSummaryJson 0

if [[ ! -f "$MSI_SUMMARY_JSON" ]]; then
  echo "windows desktop installer guardrails failed: missing summary json for explicit msi dry-run: $MSI_SUMMARY_JSON"
  cat "$TMP_DIR/explicit_msi_dry_run.log"
  exit 1
fi
assert_json_expr "$MSI_SUMMARY_JSON" '.status == "ok"' "explicit msi summary must have status=ok"
assert_json_expr "$MSI_SUMMARY_JSON" '.installer_type == "msi"' "explicit msi summary must infer installer_type=msi"
assert_json_expr "$MSI_SUMMARY_JSON" '.installer_source == "explicit"' "explicit msi summary must have installer_source=explicit"
assert_json_expr "$MSI_SUMMARY_JSON" '.dry_run == true' "explicit msi summary must set dry_run=true"

echo "[windows-desktop-installer-guardrails] explicit missing installer path fails with summary status=fail"
MISSING_INSTALLER="$TMP_DIR/does_not_exist.exe"
MISSING_INSTALLER_PS="$(to_powershell_path "$MISSING_INSTALLER")"
MISSING_SUMMARY_JSON="$TMP_DIR/missing_summary.json"
MISSING_SUMMARY_JSON_PS="$(to_powershell_path "$MISSING_SUMMARY_JSON")"
run_expect_fail_regex \
  "explicit_missing_path_fail" \
  "explicit installer path does not exist" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" \
    -InstallerPath "$MISSING_INSTALLER_PS" \
    -DryRun \
    -SummaryJson "$MISSING_SUMMARY_JSON_PS" \
    -PrintSummaryJson 0

if [[ ! -f "$MISSING_SUMMARY_JSON" ]]; then
  echo "windows desktop installer guardrails failed: missing summary json for explicit missing-path failure"
  cat "$TMP_DIR/explicit_missing_path_fail.log"
  exit 1
fi
assert_json_expr "$MISSING_SUMMARY_JSON" '.status == "fail"' "missing installer summary must have status=fail"
assert_json_expr "$MISSING_SUMMARY_JSON" '.failure_stage == "installer_validate"' "missing installer summary must have failure_stage=installer_validate"

echo "[windows-desktop-installer-guardrails] print-summary marker appears when enabled"
PRINT_SUMMARY_JSON="$TMP_DIR/print_summary.json"
PRINT_SUMMARY_JSON_PS="$(to_powershell_path "$PRINT_SUMMARY_JSON")"
run_expect_pass \
  "print_summary_enabled" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" \
    -InstallerPath "$EXE_INSTALLER_PS" \
    -DryRun \
    -SummaryJson "$PRINT_SUMMARY_JSON_PS" \
    -PrintSummaryJson 1

if ! grep -Fq 'summary_json_payload:' "$TMP_DIR/print_summary_enabled.log"; then
  echo "windows desktop installer guardrails failed: missing summary_json_payload marker when -PrintSummaryJson 1 is used"
  cat "$TMP_DIR/print_summary_enabled.log"
  exit 1
fi
if ! grep -Eq '"status":[[:space:]]*"ok"' "$TMP_DIR/print_summary_enabled.log"; then
  echo "windows desktop installer guardrails failed: expected summary payload content missing when -PrintSummaryJson 1 is used"
  cat "$TMP_DIR/print_summary_enabled.log"
  exit 1
fi

echo "[windows-desktop-installer-guardrails] build-if-missing invocation contract markers"
if ! grep -qE 'desktop_release_bundle\.ps1' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop installer guardrails failed: missing desktop_release_bundle.ps1 invocation marker"
  exit 1
fi
if ! grep -qE 'if[[:space:]]*\([[:space:]]*\$null[[:space:]]*-eq[[:space:]]*\$found[[:space:]]*-and[[:space:]]*\$BuildIfMissing[[:space:]]*\)' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop installer guardrails failed: missing BuildIfMissing conditional marker"
  exit 1
fi
if ! grep -qE '"-ExecutionPolicy"[[:space:]]*,[[:space:]]*"Bypass"' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop installer guardrails failed: missing powershell -ExecutionPolicy Bypass build invocation marker"
  exit 1
fi
if ! grep -qE '"-File"[[:space:]]*,[[:space:]]*\$releaseBundleScript' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop installer guardrails failed: missing powershell -File \$releaseBundleScript build invocation marker"
  exit 1
fi
if ! grep -qE '&[[:space:]]+powershell[[:space:]]+@buildArgs' "$SCRIPT_UNDER_TEST"; then
  echo "windows desktop installer guardrails failed: missing powershell build invocation execution marker"
  exit 1
fi

echo "windows desktop installer guardrails integration check ok"
