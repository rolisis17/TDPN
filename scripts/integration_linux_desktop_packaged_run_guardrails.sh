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

SCRIPT_UNDER_TEST="${DESKTOP_LINUX_PACKAGED_RUN_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/linux/desktop_packaged_run.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "linux desktop packaged-run guardrails failed: missing script: $SCRIPT_UNDER_TEST"
  exit 1
fi
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "linux desktop packaged-run guardrails failed: script is not executable: $SCRIPT_UNDER_TEST"
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
  echo "linux desktop packaged-run guardrails failed: expected pass for $name"
  cat "$log_path"
  exit 1
}

run_expect_fail_regex() {
  local name="$1"
  local expected_pattern="$2"
  shift 2
  local log_path="$TMP_DIR/${name}.log"
  if "$@" >"$log_path" 2>&1; then
    echo "linux desktop packaged-run guardrails failed: expected failure for $name"
    cat "$log_path"
    exit 1
  fi
  if ! grep -Eiq -- "$expected_pattern" "$log_path"; then
    echo "linux desktop packaged-run guardrails failed: missing expected failure text for $name"
    echo "expected regex: $expected_pattern"
    cat "$log_path"
    exit 1
  fi
}

FAKE_DOCTOR_SCRIPT="$TMP_DIR/fake_desktop_doctor.sh"
cat >"$FAKE_DOCTOR_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${DOCTOR_MARKER_PATH:-}" ]]; then
  printf '%s\n' "doctor-called" >"$DOCTOR_MARKER_PATH"
fi
exit 0
EOF
chmod +x "$FAKE_DOCTOR_SCRIPT"

FAKE_BOOTSTRAP_SCRIPT="$TMP_DIR/fake_desktop_native_bootstrap.sh"
cat >"$FAKE_BOOTSTRAP_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${BOOTSTRAP_ARGS_MARKER_PATH:-}" ]]; then
  printf '%s\n' "$*" >"$BOOTSTRAP_ARGS_MARKER_PATH"
fi
exit 0
EOF
chmod +x "$FAKE_BOOTSTRAP_SCRIPT"

FAKE_EXECUTABLE_PATH="$TMP_DIR/fake-desktop"
printf '%s\n' "placeholder desktop executable used by dry-run integration guardrails" >"$FAKE_EXECUTABLE_PATH"

MISSING_EXECUTABLE_PATH="$TMP_DIR/missing-desktop"
DOCTOR_MARKER_PATH="$TMP_DIR/doctor.marker"
BOOTSTRAP_ARGS_MARKER_PATH="$TMP_DIR/bootstrap.args"
BOOTSTRAP_MISSING_PATH="$TMP_DIR/missing_desktop_native_bootstrap.sh"

echo "[linux-desktop-packaged-run-guardrails] dry-run passes with existing executable override path"
run_expect_pass \
  "dry_run_packaged_pass" \
  env \
    DESKTOP_LINUX_DOCTOR_SCRIPT_UNDER_TEST="$FAKE_DOCTOR_SCRIPT" \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT_UNDER_TEST="$FAKE_BOOTSTRAP_SCRIPT" \
    DOCTOR_MARKER_PATH="$DOCTOR_MARKER_PATH" \
    BOOTSTRAP_ARGS_MARKER_PATH="$BOOTSTRAP_ARGS_MARKER_PATH" \
    "$SCRIPT_UNDER_TEST" \
      --dry-run \
      --desktop-executable-path "$FAKE_EXECUTABLE_PATH"

if [[ ! -f "$DOCTOR_MARKER_PATH" ]]; then
  echo "linux desktop packaged-run guardrails failed: doctor marker missing after dry-run pass"
  exit 1
fi
if [[ ! -f "$BOOTSTRAP_ARGS_MARKER_PATH" ]]; then
  echo "linux desktop packaged-run guardrails failed: bootstrap args marker missing after dry-run pass"
  exit 1
fi
if ! grep -F -- '--mode run-full' "$BOOTSTRAP_ARGS_MARKER_PATH" >/dev/null 2>&1; then
  echo "linux desktop packaged-run guardrails failed: bootstrap invocation did not include --mode run-full"
  cat "$BOOTSTRAP_ARGS_MARKER_PATH"
  exit 1
fi
if ! grep -F -- '--desktop-launch-strategy packaged' "$BOOTSTRAP_ARGS_MARKER_PATH" >/dev/null 2>&1; then
  echo "linux desktop packaged-run guardrails failed: bootstrap invocation did not include packaged launch strategy"
  cat "$BOOTSTRAP_ARGS_MARKER_PATH"
  exit 1
fi

rm -f "$DOCTOR_MARKER_PATH"
rm -f "$BOOTSTRAP_ARGS_MARKER_PATH"

echo "[linux-desktop-packaged-run-guardrails] dry-run fails when override path does not exist"
run_expect_fail_regex \
  "dry_run_missing_override_fail" \
  "desktop executable override was not found|desktop executable override.*not found|desktop executable.*override.*not found" \
  env \
    DESKTOP_LINUX_DOCTOR_SCRIPT_UNDER_TEST="$FAKE_DOCTOR_SCRIPT" \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT_UNDER_TEST="$BOOTSTRAP_MISSING_PATH" \
    DOCTOR_MARKER_PATH="$DOCTOR_MARKER_PATH" \
    "$SCRIPT_UNDER_TEST" \
      --dry-run \
      --desktop-executable-path "$MISSING_EXECUTABLE_PATH"

if [[ ! -f "$DOCTOR_MARKER_PATH" ]]; then
  echo "linux desktop packaged-run guardrails failed: doctor marker missing after expected-fail case"
  exit 1
fi

echo "linux desktop packaged-run guardrails integration check ok"
