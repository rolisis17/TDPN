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

SUMMARY_JSON_PATH="$TMP_DIR/desktop_release_bundle_windows_summary.json"
SUMMARY_JSON_PATH_PS="$(to_powershell_path "$SUMMARY_JSON_PATH")"

echo "[desktop-release-bundle-guardrails] skip-build summary json contract"
run_expect_pass \
  "skip_build_summary_json_pass" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" \
    -Channel beta \
    -UpdateFeedUrl "https://updates.example.invalid/gpm/beta.json" \
    -SummaryJson "$SUMMARY_JSON_PATH_PS" \
    -PrintSummaryJson 1 \
    -SkipBuild
assert_log_contains \
  "skip_build_summary_json_pass" \
  "[desktop-release-bundle] summary_json="
assert_log_contains \
  "skip_build_summary_json_pass" \
  "[desktop-release-bundle] summary_json_payload:"
if [[ ! -f "$SUMMARY_JSON_PATH" ]]; then
  echo "desktop release bundle guardrails failed: summary json not created: $SUMMARY_JSON_PATH"
  exit 1
fi
run_expect_pass \
  "skip_build_summary_json_validate" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; \$summary = Get-Content -Raw -LiteralPath '$SUMMARY_JSON_PATH_PS' | ConvertFrom-Json; if (\$summary.version -ne 1) { throw 'version mismatch' }; if (\$summary.status -ne 'ok') { throw 'status mismatch' }; if (\$summary.platform -ne 'windows') { throw 'platform mismatch' }; if (-not \$summary.skip_build) { throw 'skip_build mismatch' }; if (\$summary.channel -ne 'beta') { throw 'channel mismatch' }"

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
  "-SigningCertPassword requires -SigningCertPath." \
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

echo "[desktop-release-bundle-guardrails] signing cert password with cert path passes"
run_expect_pass \
  "password_with_cert_pass" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_UNDER_TEST_PS" \
    -Channel beta \
    -SigningCertPath "$DUMMY_CERT_PATH_PS" \
    -SigningCertPassword "placeholder" \
    -SkipBuild

echo "[desktop-release-bundle-guardrails] scoped environment restore is preserved in-process"
run_expect_pass \
  "scoped_env_restore_pass" \
  "$POWERSHELL_BIN" -NoProfile -ExecutionPolicy Bypass -Command \
    "\$ErrorActionPreference='Stop'; \$env:TDPN_DESKTOP_UPDATE_CHANNEL='orig-tdpn-channel'; \$env:GPM_DESKTOP_UPDATE_CHANNEL='orig-gpm-channel'; \$env:TDPN_DESKTOP_UPDATE_FEED_URL='https://updates.example.invalid/orig-tdpn.json'; \$env:GPM_DESKTOP_UPDATE_FEED_URL='https://updates.example.invalid/orig-gpm.json'; \$env:TDPN_DESKTOP_SIGNING_IDENTITY='orig-tdpn-signing-identity'; \$env:GPM_DESKTOP_SIGNING_IDENTITY='orig-gpm-signing-identity'; \$env:TDPN_DESKTOP_SIGNING_CERT_PATH='orig-tdpn-cert-path'; \$env:GPM_DESKTOP_SIGNING_CERT_PATH='orig-gpm-cert-path'; \$env:TDPN_DESKTOP_SIGNING_CERT_PASSWORD='orig-tdpn-cert-password'; \$env:GPM_DESKTOP_SIGNING_CERT_PASSWORD='orig-gpm-cert-password'; & '$SCRIPT_UNDER_TEST_PS' -Channel canary -UpdateFeedUrl 'https://updates.example.invalid/gpm/canary.json' -SigningIdentity 'scaffold-signing-identity' -SigningCertPath '$DUMMY_CERT_PATH_PS' -SigningCertPassword 'placeholder' -SkipBuild; if (\$env:TDPN_DESKTOP_UPDATE_CHANNEL -ne 'orig-tdpn-channel') { throw 'env restore failed for TDPN_DESKTOP_UPDATE_CHANNEL' }; if (\$env:GPM_DESKTOP_UPDATE_CHANNEL -ne 'orig-gpm-channel') { throw 'env restore failed for GPM_DESKTOP_UPDATE_CHANNEL' }; if (\$env:TDPN_DESKTOP_UPDATE_FEED_URL -ne 'https://updates.example.invalid/orig-tdpn.json') { throw 'env restore failed for TDPN_DESKTOP_UPDATE_FEED_URL' }; if (\$env:GPM_DESKTOP_UPDATE_FEED_URL -ne 'https://updates.example.invalid/orig-gpm.json') { throw 'env restore failed for GPM_DESKTOP_UPDATE_FEED_URL' }; if (\$env:TDPN_DESKTOP_SIGNING_IDENTITY -ne 'orig-tdpn-signing-identity') { throw 'env restore failed for TDPN_DESKTOP_SIGNING_IDENTITY' }; if (\$env:GPM_DESKTOP_SIGNING_IDENTITY -ne 'orig-gpm-signing-identity') { throw 'env restore failed for GPM_DESKTOP_SIGNING_IDENTITY' }; if (\$env:TDPN_DESKTOP_SIGNING_CERT_PATH -ne 'orig-tdpn-cert-path') { throw 'env restore failed for TDPN_DESKTOP_SIGNING_CERT_PATH' }; if (\$env:GPM_DESKTOP_SIGNING_CERT_PATH -ne 'orig-gpm-cert-path') { throw 'env restore failed for GPM_DESKTOP_SIGNING_CERT_PATH' }; if (\$env:TDPN_DESKTOP_SIGNING_CERT_PASSWORD -ne 'orig-tdpn-cert-password') { throw 'env restore failed for TDPN_DESKTOP_SIGNING_CERT_PASSWORD' }; if (\$env:GPM_DESKTOP_SIGNING_CERT_PASSWORD -ne 'orig-gpm-cert-password') { throw 'env restore failed for GPM_DESKTOP_SIGNING_CERT_PASSWORD' }"

echo "desktop release bundle guardrails integration check ok"
