#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SCRIPT_UNDER_TEST="${DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/linux/desktop_native_bootstrap.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "linux desktop native bootstrap guardrails failed: missing script: $SCRIPT_UNDER_TEST"
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
  echo "linux desktop native bootstrap guardrails failed: expected pass for $name"
  cat "$log_path"
  exit 1
}

run_expect_fail_regex() {
  local name="$1"
  local expected_pattern="$2"
  shift 2
  local log_path="$TMP_DIR/${name}.log"
  if "$@" >"$log_path" 2>&1; then
    echo "linux desktop native bootstrap guardrails failed: expected failure for $name"
    cat "$log_path"
    exit 1
  fi
  if ! grep -Eiq -- "$expected_pattern" "$log_path"; then
    echo "linux desktop native bootstrap guardrails failed: missing expected failure text for $name"
    echo "expected regex: $expected_pattern"
    cat "$log_path"
    exit 1
  fi
}

echo "[linux-desktop-native-bootstrap-guardrails] check --dry-run passes"
run_expect_pass \
  "check_dry_run_pass" \
  bash "$SCRIPT_UNDER_TEST" \
    --mode check \
    --dry-run

echo "[linux-desktop-native-bootstrap-guardrails] bootstrap --dry-run passes"
run_expect_pass \
  "bootstrap_dry_run_pass" \
  bash "$SCRIPT_UNDER_TEST" \
    --mode bootstrap \
    --dry-run

echo "[linux-desktop-native-bootstrap-guardrails] run-full --dry-run passes"
run_expect_pass \
  "run_full_dry_run_pass" \
  bash "$SCRIPT_UNDER_TEST" \
    --mode run-full \
    --desktop-launch-strategy auto \
    --dry-run

echo "[linux-desktop-native-bootstrap-guardrails] invalid mode fails"
run_expect_fail_regex \
  "invalid_mode_fail" \
  "invalid --mode|unsupported mode|unknown mode|mode" \
  bash "$SCRIPT_UNDER_TEST" \
    --mode invalid-mode \
    --dry-run

echo "linux desktop native bootstrap guardrails integration check ok"
