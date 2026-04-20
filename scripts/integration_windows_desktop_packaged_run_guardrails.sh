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

SCRIPT_UNDER_TEST="${DESKTOP_PACKAGED_RUN_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/windows/desktop_packaged_run.ps1}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "windows desktop packaged-run guardrails failed: missing script: $SCRIPT_UNDER_TEST"
  exit 1
fi

if command -v powershell >/dev/null 2>&1; then
  POWERSHELL_BIN="powershell"
elif command -v pwsh >/dev/null 2>&1; then
  POWERSHELL_BIN="pwsh"
elif command -v powershell.exe >/dev/null 2>&1; then
  POWERSHELL_BIN="powershell.exe"
else
  echo "windows desktop packaged-run guardrails failed: missing powershell/pwsh/powershell.exe"
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
  echo "windows desktop packaged-run guardrails failed: expected pass for $name"
  cat "$log_path"
  exit 1
}

run_expect_pass_regex() {
  local name="$1"
  local expected_pattern="$2"
  shift 2
  local log_path="$TMP_DIR/${name}.log"
  if ! "$@" >"$log_path" 2>&1; then
    echo "windows desktop packaged-run guardrails failed: expected pass for $name"
    cat "$log_path"
    exit 1
  fi
  if ! grep -Eiq -- "$expected_pattern" "$log_path"; then
    echo "windows desktop packaged-run guardrails failed: missing expected success text for $name"
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
    echo "windows desktop packaged-run guardrails failed: expected failure for $name"
    cat "$log_path"
    exit 1
  fi
  if ! grep -Eiq -- "$expected_pattern" "$log_path"; then
    echo "windows desktop packaged-run guardrails failed: missing expected failure text for $name"
    echo "expected regex: $expected_pattern"
    cat "$log_path"
    exit 1
  fi
}

FAKE_EXECUTABLE_PATH="$TMP_DIR/fake-desktop.exe"
printf '%s\n' "placeholder desktop executable used by dry-run integration guardrails" >"$FAKE_EXECUTABLE_PATH"
FAKE_EXECUTABLE_PATH_PS="$(to_powershell_path "$FAKE_EXECUTABLE_PATH")"

MISSING_EXECUTABLE_PATH="$TMP_DIR/missing-desktop.exe"
MISSING_EXECUTABLE_PATH_PS="$(to_powershell_path "$MISSING_EXECUTABLE_PATH")"

echo "[windows-desktop-packaged-run-guardrails] dry-run passes with existing executable override path"
run_expect_pass \
  "dry_run_packaged_pass" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" \
    -DryRun \
    -DesktopExecutablePath "$FAKE_EXECUTABLE_PATH_PS"

GPM_DESKTOP_PACKAGED_EXE_WAS_SET="0"
GPM_DESKTOP_PACKAGED_EXE_ORIGINAL=""
if [[ "${GPM_DESKTOP_PACKAGED_EXE+x}" == x ]]; then
  GPM_DESKTOP_PACKAGED_EXE_WAS_SET="1"
  GPM_DESKTOP_PACKAGED_EXE_ORIGINAL="$GPM_DESKTOP_PACKAGED_EXE"
fi

GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE_WAS_SET="0"
GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE_ORIGINAL=""
if [[ "${GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE+x}" == x ]]; then
  GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE_WAS_SET="1"
  GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE_ORIGINAL="$GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE"
fi

TDPN_DESKTOP_PACKAGED_EXE_WAS_SET="0"
TDPN_DESKTOP_PACKAGED_EXE_ORIGINAL=""
if [[ "${TDPN_DESKTOP_PACKAGED_EXE+x}" == x ]]; then
  TDPN_DESKTOP_PACKAGED_EXE_WAS_SET="1"
  TDPN_DESKTOP_PACKAGED_EXE_ORIGINAL="$TDPN_DESKTOP_PACKAGED_EXE"
fi

echo "[windows-desktop-packaged-run-guardrails] dry-run passes with Global Private Mesh env override and no explicit override path"
run_expect_pass \
  "dry_run_packaged_env_override_global_private_mesh_pass" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; \$env:GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE='$FAKE_EXECUTABLE_PATH_PS'; \$env:GPM_DESKTOP_PACKAGED_EXE=''; \$env:TDPN_DESKTOP_PACKAGED_EXE=''; & '$SCRIPT_UNDER_TEST_PS' -DryRun"

echo "[windows-desktop-packaged-run-guardrails] dry-run passes with env override and no explicit override path"
run_expect_pass \
  "dry_run_packaged_env_override_pass" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; \$env:GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE=''; \$env:GPM_DESKTOP_PACKAGED_EXE='$FAKE_EXECUTABLE_PATH_PS'; \$env:TDPN_DESKTOP_PACKAGED_EXE=''; & '$SCRIPT_UNDER_TEST_PS' -DryRun"

echo "[windows-desktop-packaged-run-guardrails] dry-run passes with TDPN env override and no explicit override path"
run_expect_pass \
  "dry_run_packaged_env_override_tdpn_pass" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; \$env:GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE=''; \$env:GPM_DESKTOP_PACKAGED_EXE=''; \$env:TDPN_DESKTOP_PACKAGED_EXE='$FAKE_EXECUTABLE_PATH_PS'; & '$SCRIPT_UNDER_TEST_PS' -DryRun"

echo "[windows-desktop-packaged-run-guardrails] dry-run auto-discovery passes with mocked Global Private Mesh LocalAppData candidate"
run_expect_pass_regex \
  "dry_run_packaged_autodiscovery_global_private_mesh_pass" \
  "packaged executable auto-discovered \\(install\\): .*Global Private Mesh Desktop\\.exe|packaged executable auto-discovered \\(install\\): .*global-private-mesh-desktop\\.exe" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; \$tmpRoot = Join-Path \$env:TEMP ('desktop-packaged-run-guardrails-' + [Guid]::NewGuid().ToString('N')); \$fakeLocalAppData = Join-Path \$tmpRoot 'localappdata'; \$fakeExecutable = Join-Path \$fakeLocalAppData 'Programs\\Global Private Mesh Desktop\\Global Private Mesh Desktop.exe'; New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName(\$fakeExecutable)) -Force | Out-Null; Set-Content -LiteralPath \$fakeExecutable -Value 'placeholder packaged executable for auto-discovery guardrails' -Encoding UTF8; \$env:GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE=''; \$env:GPM_DESKTOP_PACKAGED_EXE=''; \$env:TDPN_DESKTOP_PACKAGED_EXE=''; \$env:LOCALAPPDATA=\$fakeLocalAppData; try { & '$SCRIPT_UNDER_TEST_PS' -DryRun } finally { Remove-Item -LiteralPath \$tmpRoot -Recurse -Force -ErrorAction SilentlyContinue }"

if [[ "$GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE_WAS_SET" == "1" ]]; then
  if [[ "${GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE-}" != "$GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE_ORIGINAL" ]]; then
    echo "windows desktop packaged-run guardrails failed: leaked GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE changes into caller environment"
    exit 1
  fi
elif [[ "${GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE+x}" == x ]]; then
  echo "windows desktop packaged-run guardrails failed: leaked GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE into caller environment"
  exit 1
fi

if [[ "$GPM_DESKTOP_PACKAGED_EXE_WAS_SET" == "1" ]]; then
  if [[ "${GPM_DESKTOP_PACKAGED_EXE-}" != "$GPM_DESKTOP_PACKAGED_EXE_ORIGINAL" ]]; then
    echo "windows desktop packaged-run guardrails failed: leaked GPM_DESKTOP_PACKAGED_EXE changes into caller environment"
    exit 1
  fi
elif [[ "${GPM_DESKTOP_PACKAGED_EXE+x}" == x ]]; then
  echo "windows desktop packaged-run guardrails failed: leaked GPM_DESKTOP_PACKAGED_EXE into caller environment"
  exit 1
fi

if [[ "$TDPN_DESKTOP_PACKAGED_EXE_WAS_SET" == "1" ]]; then
  if [[ "${TDPN_DESKTOP_PACKAGED_EXE-}" != "$TDPN_DESKTOP_PACKAGED_EXE_ORIGINAL" ]]; then
    echo "windows desktop packaged-run guardrails failed: leaked TDPN_DESKTOP_PACKAGED_EXE changes into caller environment"
    exit 1
  fi
elif [[ "${TDPN_DESKTOP_PACKAGED_EXE+x}" == x ]]; then
  echo "windows desktop packaged-run guardrails failed: leaked TDPN_DESKTOP_PACKAGED_EXE into caller environment"
  exit 1
fi

echo "[windows-desktop-packaged-run-guardrails] missing executable override path fails with expected message"
run_expect_fail_regex \
  "missing_override_fail" \
  "desktop executable override was not found|desktop executable override.*not found|desktop executable.*override.*not found" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" \
    -DryRun \
    -DesktopExecutablePath "$MISSING_EXECUTABLE_PATH_PS"

echo "windows desktop packaged-run guardrails integration check ok"
