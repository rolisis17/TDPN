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

echo "[desktop-linux-release-bundle-guardrails] https update feed passes"
run_expect_pass \
  "https_feed_pass" \
  "$SCRIPT_UNDER_TEST" \
    --channel beta \
    --update-feed-url "https://updates.example.invalid/tdpn/beta.json" \
    --skip-build

echo "[desktop-linux-release-bundle-guardrails] localhost http update feed passes"
run_expect_pass \
  "localhost_http_feed_pass" \
  "$SCRIPT_UNDER_TEST" \
    --channel beta \
    --update-feed-url "http://localhost:18080/tdpn/beta.json" \
    --skip-build

echo "[desktop-linux-release-bundle-guardrails] non-local http update feed fails"
run_expect_fail \
  "remote_http_feed_fail" \
  "non-local update feeds must use https" \
  "$SCRIPT_UNDER_TEST" \
    --channel beta \
    --update-feed-url "http://example.com/tdpn/beta.json" \
    --skip-build

echo "[desktop-linux-release-bundle-guardrails] unsupported update feed scheme fails"
run_expect_fail \
  "unsupported_scheme_fail" \
  "allowed schemes: http, https" \
  "$SCRIPT_UNDER_TEST" \
    --channel beta \
    --update-feed-url "ftp://updates.example.invalid/tdpn/beta.json" \
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

echo "[desktop-linux-release-bundle-guardrails] existing signing cert placeholder path passes"
run_expect_pass \
  "existing_cert_path_pass" \
  "$SCRIPT_UNDER_TEST" \
    --channel beta \
    --signing-cert-path "$DUMMY_CERT_PATH" \
    --signing-cert-password "placeholder" \
    --skip-build

SCRIPT_UNDER_TEST_Q="$(printf '%q' "$SCRIPT_UNDER_TEST")"

echo "[desktop-linux-release-bundle-guardrails] scoped environment restore is preserved in-process"
run_expect_pass \
  "scoped_env_restore_pass" \
  bash -lc "set -euo pipefail; export TDPN_DESKTOP_UPDATE_CHANNEL='orig-channel'; $SCRIPT_UNDER_TEST_Q --channel canary --skip-build >/dev/null; [[ \"\${TDPN_DESKTOP_UPDATE_CHANNEL}\" == 'orig-channel' ]]"

echo "desktop linux release bundle guardrails integration check ok"
