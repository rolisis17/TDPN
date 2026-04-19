#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SCRIPT_UNDER_TEST="${DESKTOP_RELEASE_BUNDLE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/windows/desktop_release_bundle.ps1}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "desktop release bundle guardrails failed: missing script: $SCRIPT_UNDER_TEST"
  exit 1
fi

assert_marker_present() {
  local marker="$1"
  local file_path="$2"
  if ! grep -Fq -- "$marker" "$file_path"; then
    echo "desktop release bundle guardrails failed: missing marker '$marker' in $file_path"
    exit 1
  fi
}

assert_marker_present "function Ensure-TauriIconScaffold" "$SCRIPT_UNDER_TEST"
assert_marker_present "src-tauri\\icons\\icon.ico" "$SCRIPT_UNDER_TEST"
assert_marker_present "[System.IO.File]::WriteAllBytes" "$SCRIPT_UNDER_TEST"
assert_marker_present 'Ensure-TauriIconScaffold -DesktopDir $desktopDir' "$SCRIPT_UNDER_TEST"

if command -v powershell >/dev/null 2>&1; then
  POWERSHELL_BIN="powershell"
elif command -v pwsh >/dev/null 2>&1; then
  POWERSHELL_BIN="pwsh"
elif command -v powershell.exe >/dev/null 2>&1; then
  POWERSHELL_BIN="powershell.exe"
else
  echo "desktop release bundle guardrails failed: missing powershell/pwsh/powershell.exe"
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
  echo "desktop release bundle guardrails failed: expected pass for $name"
  cat "$log_path"
  exit 1
}

run_expect_fail() {
  local name="$1"
  local expected_pattern="$2"
  shift 2
  local log_path="$TMP_DIR/${name}.log"
  if "$@" >"$log_path" 2>&1; then
    echo "desktop release bundle guardrails failed: expected failure for $name"
    cat "$log_path"
    exit 1
  fi
  if ! grep -F -- "$expected_pattern" "$log_path" >/dev/null 2>&1; then
    echo "desktop release bundle guardrails failed: missing expected failure text for $name"
    echo "expected pattern: $expected_pattern"
    cat "$log_path"
    exit 1
  fi
}

assert_log_contains() {
  local name="$1"
  local expected_pattern="$2"
  local log_path="$TMP_DIR/${name}.log"
  if ! grep -F -- "$expected_pattern" "$log_path" >/dev/null 2>&1; then
    echo "desktop release bundle guardrails failed: missing expected log text for $name"
    echo "expected pattern: $expected_pattern"
    cat "$log_path"
    exit 1
  fi
}

echo "[desktop-release-bundle-guardrails] https update feed passes"
run_expect_pass \
  "https_feed_pass" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" \
    -Channel beta \
    -UpdateFeedUrl "https://updates.example.invalid/gpm/beta.json" \
    -SkipBuild

echo "[desktop-release-bundle-guardrails] localhost http update feed passes"
run_expect_pass \
  "localhost_http_feed_pass" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" \
    -Channel beta \
    -UpdateFeedUrl "http://localhost:18080/gpm/beta.json" \
    -SkipBuild

echo "[desktop-release-bundle-guardrails] non-local http update feed fails"
run_expect_fail \
  "remote_http_feed_fail" \
  "non-local update feeds must use https" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" \
    -Channel beta \
    -UpdateFeedUrl "http://example.com/gpm/beta.json" \
    -SkipBuild

echo "[desktop-release-bundle-guardrails] unsupported update feed scheme fails"
run_expect_fail \
  "unsupported_scheme_fail" \
  "allowed schemes: http, https" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" \
    -Channel beta \
    -UpdateFeedUrl "ftp://updates.example.invalid/gpm/beta.json" \
    -SkipBuild

POWERSHELL_CONSTRAINED_PATH_PREFLIGHT="\$ErrorActionPreference='Stop'; \$env:PATH=''; foreach (\$tool in 'node','npm.cmd','rustc','cargo') { if (Get-Command \$tool -CommandType Application -ErrorAction SilentlyContinue) { throw \"constrained PATH unexpectedly resolved '\$tool'\" } };"

echo "[desktop-release-bundle-guardrails] constrained PATH keeps -SkipBuild update-feed guardrails active"
run_expect_fail \
  "constrained_path_unsupported_scheme_fail" \
  "allowed schemes: http, https" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "$POWERSHELL_CONSTRAINED_PATH_PREFLIGHT & '$SCRIPT_UNDER_TEST_PS' -Channel beta -UpdateFeedUrl 'ftp://updates.example.invalid/gpm/beta.json' -SkipBuild"

run_expect_pass \
  "constrained_path_https_skipbuild_pass" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "$POWERSHELL_CONSTRAINED_PATH_PREFLIGHT & '$SCRIPT_UNDER_TEST_PS' -Channel beta -UpdateFeedUrl 'https://updates.example.invalid/gpm/beta.json' -SkipBuild"
assert_log_contains \
  "constrained_path_https_skipbuild_pass" \
  "[desktop-release-bundle] mode=scaffold-non-production"
assert_log_contains \
  "constrained_path_https_skipbuild_pass" \
  "[desktop-release-bundle] build skipped by -SkipBuild"

echo "[desktop-release-bundle-guardrails] signing password without cert path fails"
run_expect_fail \
  "password_without_cert_fail" \
  "-SigningCertPassword is not supported in this scaffold." \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" \
    -Channel beta \
    -SigningCertPassword "placeholder" \
    -SkipBuild

MISSING_CERT_PATH="$TMP_DIR/nonexistent-signing.pfx"
MISSING_CERT_PATH_PS="$(to_powershell_path "$MISSING_CERT_PATH")"

echo "[desktop-release-bundle-guardrails] missing signing cert path fails"
run_expect_fail \
  "missing_cert_path_fail" \
  "signing certificate file was not found" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" \
    -Channel beta \
    -SigningCertPath "$MISSING_CERT_PATH_PS" \
    -SkipBuild

DUMMY_CERT_PATH="$TMP_DIR/dummy-signing.pfx"
printf '%s\n' "dummy" >"$DUMMY_CERT_PATH"
DUMMY_CERT_PATH_PS="$(to_powershell_path "$DUMMY_CERT_PATH")"

echo "[desktop-release-bundle-guardrails] existing signing cert placeholder path passes"
run_expect_pass \
  "existing_cert_path_pass" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" \
    -Channel beta \
    -SigningCertPath "$DUMMY_CERT_PATH_PS" \
    -SkipBuild

echo "[desktop-release-bundle-guardrails] signing cert password with cert path fails"
run_expect_fail \
  "password_with_cert_fail" \
  "-SigningCertPassword is not supported in this scaffold." \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" \
    -Channel beta \
    -SigningCertPath "$DUMMY_CERT_PATH_PS" \
    -SigningCertPassword "placeholder" \
    -SkipBuild

echo "[desktop-release-bundle-guardrails] scoped environment restore is preserved in-process"
run_expect_pass \
  "scoped_env_restore_pass" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; \$env:TDPN_DESKTOP_UPDATE_CHANNEL='orig-tdpn-channel'; \$env:GPM_DESKTOP_UPDATE_CHANNEL='orig-gpm-channel'; \$env:TDPN_DESKTOP_UPDATE_FEED_CONFIGURED='orig-tdpn-feed-configured'; \$env:GPM_DESKTOP_UPDATE_FEED_CONFIGURED='orig-gpm-feed-configured'; & '$SCRIPT_UNDER_TEST_PS' -Channel canary -UpdateFeedUrl 'https://updates.example.invalid/gpm/canary.json' -SkipBuild; if (\$env:TDPN_DESKTOP_UPDATE_CHANNEL -ne 'orig-tdpn-channel') { throw 'env restore failed for TDPN_DESKTOP_UPDATE_CHANNEL' }; if (\$env:GPM_DESKTOP_UPDATE_CHANNEL -ne 'orig-gpm-channel') { throw 'env restore failed for GPM_DESKTOP_UPDATE_CHANNEL' }; if (\$env:TDPN_DESKTOP_UPDATE_FEED_CONFIGURED -ne 'orig-tdpn-feed-configured') { throw 'env restore failed for TDPN_DESKTOP_UPDATE_FEED_CONFIGURED' }; if (\$env:GPM_DESKTOP_UPDATE_FEED_CONFIGURED -ne 'orig-gpm-feed-configured') { throw 'env restore failed for GPM_DESKTOP_UPDATE_FEED_CONFIGURED' }"

echo "desktop release bundle guardrails integration check ok"
