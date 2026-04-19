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

SCRIPT_UNDER_TEST="${DESKTOP_LINUX_DOCTOR_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/linux/desktop_doctor.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "linux desktop doctor guardrails failed: missing script: $SCRIPT_UNDER_TEST"
  exit 1
fi
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "linux desktop doctor guardrails failed: script is not executable: $SCRIPT_UNDER_TEST"
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
  echo "linux desktop doctor guardrails failed: expected pass for $name"
  cat "$log_path"
  exit 1
}

run_expect_fail_regex() {
  local name="$1"
  local expected_pattern="$2"
  shift 2
  local log_path="$TMP_DIR/${name}.log"
  if "$@" >"$log_path" 2>&1; then
    echo "linux desktop doctor guardrails failed: expected failure for $name"
    cat "$log_path"
    exit 1
  fi
  if ! grep -Eiq -- "$expected_pattern" "$log_path"; then
    echo "linux desktop doctor guardrails failed: missing expected failure text for $name"
    echo "expected regex: $expected_pattern"
    cat "$log_path"
    exit 1
  fi
}

echo "[linux-desktop-doctor-guardrails] check dry-run passes"
run_expect_pass \
  "check_dry_run_pass" \
  "$SCRIPT_UNDER_TEST" \
    --mode check \
    --dry-run

echo "[linux-desktop-doctor-guardrails] fix dry-run passes"
run_expect_pass \
  "fix_dry_run_pass" \
  "$SCRIPT_UNDER_TEST" \
    --mode fix \
    --install-missing \
    --dry-run

SUMMARY_JSON="$TMP_DIR/desktop_doctor_summary.json"
echo "[linux-desktop-doctor-guardrails] summary json is written when requested"
run_expect_pass \
  "summary_json_pass" \
  "$SCRIPT_UNDER_TEST" \
    --mode check \
    --dry-run \
    --summary-json "$SUMMARY_JSON" \
    --print-summary-json 0

if [[ ! -f "$SUMMARY_JSON" ]]; then
  echo "linux desktop doctor guardrails failed: summary json was not written: $SUMMARY_JSON"
  cat "$TMP_DIR/summary_json_pass.log"
  exit 1
fi
if ! jq -e 'type == "object"' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "linux desktop doctor guardrails failed: summary json is not a JSON object"
  cat "$SUMMARY_JSON"
  exit 1
fi

echo "[linux-desktop-doctor-guardrails] invalid mode fails with expected message"
run_expect_fail_regex \
  "invalid_mode_fail" \
  "unsupported mode|invalid mode" \
  "$SCRIPT_UNDER_TEST" \
    --mode invalid-mode \
    --dry-run

echo "linux desktop doctor guardrails integration check ok"
