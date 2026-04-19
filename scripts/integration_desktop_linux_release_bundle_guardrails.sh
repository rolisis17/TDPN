#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SCRIPT_UNDER_TEST="${DESKTOP_LINUX_RELEASE_BUNDLE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/linux/desktop_release_bundle.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "desktop linux release bundle guardrails failed: missing script: $SCRIPT_UNDER_TEST"
  exit 1
fi
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "desktop linux release bundle guardrails failed: script is not executable: $SCRIPT_UNDER_TEST"
  exit 1
fi

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

CONSTRAINED_PATH_DIR="$TMP_DIR/constrained-path-bin"
mkdir -p "$CONSTRAINED_PATH_DIR"

link_test_tool() {
  local tool_name="$1"
  local tool_path
  tool_path="$(command -v "$tool_name" || true)"
  if [[ -z "$tool_path" ]]; then
    echo "desktop linux release bundle guardrails failed: missing required test tool: $tool_name"
    exit 1
  fi
  ln -sf "$tool_path" "$CONSTRAINED_PATH_DIR/$tool_name"
}

for tool_name in bash grep dirname tr; do
  link_test_tool "$tool_name"
done

run_expect_pass() {
  local name="$1"
  shift
  local log_path="$TMP_DIR/${name}.log"
  if "$@" >"$log_path" 2>&1; then
    return 0
  fi
  echo "desktop linux release bundle guardrails failed: expected pass for $name"
  cat "$log_path"
  exit 1
}

run_expect_fail() {
  local name="$1"
  local expected_pattern="$2"
  shift 2
  local log_path="$TMP_DIR/${name}.log"
  if "$@" >"$log_path" 2>&1; then
    echo "desktop linux release bundle guardrails failed: expected failure for $name"
    cat "$log_path"
    exit 1
  fi
  if ! grep -F -- "$expected_pattern" "$log_path" >/dev/null 2>&1; then
    echo "desktop linux release bundle guardrails failed: missing expected failure text for $name"
    echo "expected pattern: $expected_pattern"
    cat "$log_path"
    exit 1
  fi
}

run_static_marker_check() {
  local name="$1"
  local pattern="$2"
  if grep -F -- "$pattern" "$SCRIPT_UNDER_TEST" >/dev/null 2>&1; then
    return 0
  fi
  echo "desktop linux release bundle guardrails failed: missing static marker for $name"
  echo "expected pattern: $pattern"
  exit 1
}

echo "[desktop-linux-release-bundle-guardrails] static marker: icon scaffold helper exists"
run_static_marker_check \
  "icon scaffold helper function" \
  "ensure_tauri_icon_scaffold()"

echo "[desktop-linux-release-bundle-guardrails] static marker: icon scaffold path constant exists"
run_static_marker_check \
  "icon scaffold path" \
  "src-tauri/icons/icon.ico"

echo "[desktop-linux-release-bundle-guardrails] static marker: icon scaffold helper writes placeholder"
run_static_marker_check \
  "icon scaffold placeholder write" \
  "printf '\\x00\\x00\\x01\\x00\\x01\\x00"

echo "[desktop-linux-release-bundle-guardrails] static marker: icon scaffold helper is wired in"
ICON_HELPER_REFERENCE_COUNT="$(grep -F -c -- "ensure_tauri_icon_scaffold" "$SCRIPT_UNDER_TEST" || true)"
if [[ "$ICON_HELPER_REFERENCE_COUNT" -lt 2 ]]; then
  echo "desktop linux release bundle guardrails failed: expected icon scaffold helper definition and invocation"
  exit 1
fi

echo "[desktop-linux-release-bundle-guardrails] static marker: --install-missing flag is parsed"
run_static_marker_check \
  "install-missing argument parsing" \
  "--install-missing)"

echo "[desktop-linux-release-bundle-guardrails] static marker: doctor remediation command marker exists"
run_static_marker_check \
  "doctor remediation command" \
  "./scripts/linux/desktop_doctor.sh --mode fix --install-missing"

echo "[desktop-linux-release-bundle-guardrails] static marker: missing tool collection is re-checked"
MISSING_TOOL_COLLECTION_REFERENCE_COUNT="$(grep -F -c -- "collect_missing_build_tools" "$SCRIPT_UNDER_TEST" || true)"
if [[ "$MISSING_TOOL_COLLECTION_REFERENCE_COUNT" -lt 3 ]]; then
  echo "desktop linux release bundle guardrails failed: expected missing tool collection definition plus pre/post remediation checks"
  exit 1
fi

echo "[desktop-linux-release-bundle-guardrails] https update feed passes"
run_expect_pass \
  "https_feed_pass" \
  "$SCRIPT_UNDER_TEST" \
    --channel beta \
    --update-feed-url "https://updates.example.invalid/gpm/beta.json" \
    --skip-build

echo "[desktop-linux-release-bundle-guardrails] localhost http update feed passes"
run_expect_pass \
  "localhost_http_feed_pass" \
  "$SCRIPT_UNDER_TEST" \
    --channel beta \
    --update-feed-url "http://localhost:18080/gpm/beta.json" \
    --skip-build

echo "[desktop-linux-release-bundle-guardrails] non-local http update feed fails"
run_expect_fail \
  "remote_http_feed_fail" \
  "non-local update feeds must use https" \
  "$SCRIPT_UNDER_TEST" \
    --channel beta \
    --update-feed-url "http://example.com/gpm/beta.json" \
    --skip-build

echo "[desktop-linux-release-bundle-guardrails] unsupported update feed scheme fails"
run_expect_fail \
  "unsupported_scheme_fail" \
  "allowed schemes: http, https" \
  "$SCRIPT_UNDER_TEST" \
    --channel beta \
    --update-feed-url "ftp://updates.example.invalid/gpm/beta.json" \
    --skip-build

echo "[desktop-linux-release-bundle-guardrails] signing password without cert path fails"
run_expect_fail \
  "password_without_cert_fail" \
  "-SigningCertPassword requires -SigningCertPath." \
  "$SCRIPT_UNDER_TEST" \
    --channel beta \
    --signing-cert-password "placeholder" \
    --skip-build

MISSING_CERT_PATH="$TMP_DIR/nonexistent-signing.pfx"
echo "[desktop-linux-release-bundle-guardrails] missing signing cert path fails"
run_expect_fail \
  "missing_cert_path_fail" \
  "signing certificate file was not found" \
  "$SCRIPT_UNDER_TEST" \
    --channel beta \
    --signing-cert-path "$MISSING_CERT_PATH" \
    --skip-build

DUMMY_CERT_PATH="$TMP_DIR/dummy-signing.pfx"
printf '%s\n' "dummy" >"$DUMMY_CERT_PATH"
DUMMY_CERT_PATH_Q="$(printf '%q' "$DUMMY_CERT_PATH")"

echo "[desktop-linux-release-bundle-guardrails] existing signing cert placeholder path passes"
run_expect_pass \
  "existing_cert_path_pass" \
  "$SCRIPT_UNDER_TEST" \
    --channel beta \
    --signing-cert-path "$DUMMY_CERT_PATH" \
    --signing-cert-password "placeholder" \
    --skip-build

SCRIPT_UNDER_TEST_Q="$(printf '%q' "$SCRIPT_UNDER_TEST")"
TMP_DIR_Q="$(printf '%q' "$TMP_DIR")"
CONSTRAINED_PATH_DIR_Q="$(printf '%q' "$CONSTRAINED_PATH_DIR")"

echo "[desktop-linux-release-bundle-guardrails] skip-build passes with constrained PATH and still validates scaffold inputs"
run_expect_pass \
  "skip_build_constrained_path_pass" \
  bash -lc "set -euo pipefail; constrained_path=$CONSTRAINED_PATH_DIR_Q; fail_log=$TMP_DIR_Q/skip_build_constrained_validation_fail.log; pass_log=$TMP_DIR_Q/skip_build_constrained_validation_pass.log; PATH=\"\$constrained_path\"; if command -v node >/dev/null 2>&1 || command -v npm >/dev/null 2>&1 || command -v rustc >/dev/null 2>&1 || command -v cargo >/dev/null 2>&1; then echo 'expected constrained PATH to omit node/npm/rustc/cargo' >&2; exit 1; fi; if $SCRIPT_UNDER_TEST_Q --channel beta --update-feed-url 'ftp://updates.example.invalid/gpm/beta.json' --skip-build >\"\$fail_log\" 2>&1; then echo 'expected invalid update feed URL to fail under --skip-build' >&2; exit 1; fi; grep -F -- 'allowed schemes: http, https' \"\$fail_log\" >/dev/null; $SCRIPT_UNDER_TEST_Q --channel beta --update-feed-url 'https://updates.example.invalid/gpm/beta.json' --skip-build >\"\$pass_log\" 2>&1; grep -F -- '[desktop-release-bundle] mode=scaffold-non-production' \"\$pass_log\" >/dev/null; grep -F -- '[desktop-release-bundle] build skipped by --skip-build' \"\$pass_log\" >/dev/null"

echo "[desktop-linux-release-bundle-guardrails] --install-missing still preserves skip-build behavior"
run_expect_pass \
  "install_missing_skip_build_pass" \
  "$SCRIPT_UNDER_TEST" \
    --channel beta \
    --install-missing \
    --skip-build

echo "[desktop-linux-release-bundle-guardrails] scoped environment restore is preserved in-process"
run_expect_pass \
  "scoped_env_restore_pass" \
  bash -lc "set -euo pipefail; export TDPN_DESKTOP_UPDATE_CHANNEL='orig-tdpn-channel'; export GPM_DESKTOP_UPDATE_CHANNEL='orig-gpm-channel'; export TDPN_DESKTOP_UPDATE_FEED_URL='https://updates.example.invalid/orig-tdpn.json'; export GPM_DESKTOP_UPDATE_FEED_URL='https://updates.example.invalid/orig-gpm.json'; export TDPN_DESKTOP_SIGNING_IDENTITY='orig-tdpn-signing-identity'; export GPM_DESKTOP_SIGNING_IDENTITY='orig-gpm-signing-identity'; export TDPN_DESKTOP_SIGNING_CERT_PATH='orig-tdpn-cert-path'; export GPM_DESKTOP_SIGNING_CERT_PATH='orig-gpm-cert-path'; export TDPN_DESKTOP_SIGNING_CERT_PASSWORD='orig-tdpn-cert-password'; export GPM_DESKTOP_SIGNING_CERT_PASSWORD='orig-gpm-cert-password'; $SCRIPT_UNDER_TEST_Q --channel canary --update-feed-url 'https://updates.example.invalid/gpm/canary.json' --signing-identity 'scaffold-signing-identity' --signing-cert-path $DUMMY_CERT_PATH_Q --signing-cert-password 'placeholder' --skip-build >/dev/null; [[ \"\${TDPN_DESKTOP_UPDATE_CHANNEL}\" == 'orig-tdpn-channel' ]]; [[ \"\${GPM_DESKTOP_UPDATE_CHANNEL}\" == 'orig-gpm-channel' ]]; [[ \"\${TDPN_DESKTOP_UPDATE_FEED_URL}\" == 'https://updates.example.invalid/orig-tdpn.json' ]]; [[ \"\${GPM_DESKTOP_UPDATE_FEED_URL}\" == 'https://updates.example.invalid/orig-gpm.json' ]]; [[ \"\${TDPN_DESKTOP_SIGNING_IDENTITY}\" == 'orig-tdpn-signing-identity' ]]; [[ \"\${GPM_DESKTOP_SIGNING_IDENTITY}\" == 'orig-gpm-signing-identity' ]]; [[ \"\${TDPN_DESKTOP_SIGNING_CERT_PATH}\" == 'orig-tdpn-cert-path' ]]; [[ \"\${GPM_DESKTOP_SIGNING_CERT_PATH}\" == 'orig-gpm-cert-path' ]]; [[ \"\${TDPN_DESKTOP_SIGNING_CERT_PASSWORD}\" == 'orig-tdpn-cert-password' ]]; [[ \"\${GPM_DESKTOP_SIGNING_CERT_PASSWORD}\" == 'orig-gpm-cert-password' ]]"

echo "desktop linux release bundle guardrails integration check ok"
