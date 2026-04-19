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

assert_script_marker() {
  local marker="$1"
  if grep -Fq -- "$marker" "$SCRIPT_UNDER_TEST"; then
    return 0
  fi
  echo "linux desktop native bootstrap guardrails failed: missing marker in script: $marker"
  exit 1
}

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

echo "[linux-desktop-native-bootstrap-guardrails] summary markers present"
assert_script_marker "--summary-json"
assert_script_marker "--print-summary-json"
assert_script_marker "recommended_commands"
assert_script_marker "emit_summary_payload"
assert_script_marker "write_summary_json_file"

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

echo "[linux-desktop-native-bootstrap-guardrails] --print-summary-json with invalid value fails"
run_expect_fail_regex \
  "invalid_print_summary_json_fail" \
  "print-summary-json|expected 0\\|1|invalid" \
  bash "$SCRIPT_UNDER_TEST" \
    --mode check \
    --dry-run \
    --print-summary-json 2

echo "[linux-desktop-native-bootstrap-guardrails] check --dry-run --print-summary-json emits summary payload"
SUMMARY_PRINT_LOG="$TMP_DIR/check_dry_run_print_summary.log"
if ! bash "$SCRIPT_UNDER_TEST" --mode check --dry-run --print-summary-json 1 >"$SUMMARY_PRINT_LOG" 2>&1; then
  echo "linux desktop native bootstrap guardrails failed: check dry-run summary print command failed"
  cat "$SUMMARY_PRINT_LOG"
  exit 1
fi
if ! grep -Eiq '"mode"[[:space:]]*:[[:space:]]*"check"' "$SUMMARY_PRINT_LOG"; then
  echo "linux desktop native bootstrap guardrails failed: summary print missing mode=check"
  cat "$SUMMARY_PRINT_LOG"
  exit 1
fi
if ! grep -Eiq '"status"[[:space:]]*:[[:space:]]*"ok"' "$SUMMARY_PRINT_LOG"; then
  echo "linux desktop native bootstrap guardrails failed: summary print missing status=ok"
  cat "$SUMMARY_PRINT_LOG"
  exit 1
fi
if ! grep -Eiq '"recommended_commands"[[:space:]]*:' "$SUMMARY_PRINT_LOG"; then
  echo "linux desktop native bootstrap guardrails failed: summary print missing recommended_commands"
  cat "$SUMMARY_PRINT_LOG"
  exit 1
fi
if ! grep -Eiq 'recommended remediation commands' "$SUMMARY_PRINT_LOG"; then
  echo "linux desktop native bootstrap guardrails failed: summary print missing remediation guidance log"
  cat "$SUMMARY_PRINT_LOG"
  exit 1
fi

echo "[linux-desktop-native-bootstrap-guardrails] check --dry-run writes summary json payload"
SUMMARY_JSON_PATH="$TMP_DIR/check_dry_run_summary.json"
SUMMARY_FILE_LOG="$TMP_DIR/check_dry_run_summary_file.log"
if ! bash "$SCRIPT_UNDER_TEST" --mode check --dry-run --summary-json "$SUMMARY_JSON_PATH" >"$SUMMARY_FILE_LOG" 2>&1; then
  echo "linux desktop native bootstrap guardrails failed: check dry-run summary file command failed"
  cat "$SUMMARY_FILE_LOG"
  exit 1
fi
if [[ ! -f "$SUMMARY_JSON_PATH" ]]; then
  echo "linux desktop native bootstrap guardrails failed: summary json file not written: $SUMMARY_JSON_PATH"
  cat "$SUMMARY_FILE_LOG"
  exit 1
fi
if ! grep -Eiq '"recommended_commands"[[:space:]]*:' "$SUMMARY_JSON_PATH"; then
  echo "linux desktop native bootstrap guardrails failed: summary file missing recommended_commands"
  cat "$SUMMARY_JSON_PATH"
  exit 1
fi
if ! grep -Eiq '"mode"[[:space:]]*:[[:space:]]*"check"' "$SUMMARY_JSON_PATH"; then
  echo "linux desktop native bootstrap guardrails failed: summary file missing mode=check"
  cat "$SUMMARY_JSON_PATH"
  exit 1
fi

echo "linux desktop native bootstrap guardrails integration check ok"
