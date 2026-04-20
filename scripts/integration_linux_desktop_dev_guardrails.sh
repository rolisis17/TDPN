#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in grep mktemp chmod; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${DESKTOP_LINUX_DEV_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/linux/desktop_dev.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "linux desktop dev guardrails failed: missing script: $SCRIPT_UNDER_TEST"
  exit 1
fi
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "linux desktop dev guardrails failed: script is not executable: $SCRIPT_UNDER_TEST"
  exit 1
fi

TMP_DIR="$(mktemp -d)"
FAKE_BOOTSTRAP_SCRIPT="$TMP_DIR/fake_desktop_native_bootstrap.sh"
CAPTURE_ARGS_PATH="$TMP_DIR/bootstrap.args"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cat >"$FAKE_BOOTSTRAP_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
capture_path="${DESKTOP_DEV_GUARDRAILS_CAPTURE_PATH:?missing capture path}"
: >"$capture_path"
for arg in "$@"; do
  printf '%s\n' "$arg" >>"$capture_path"
done
EOF
chmod +x "$FAKE_BOOTSTRAP_SCRIPT"

assert_script_marker() {
  local marker="$1"
  if grep -Fq -- "$marker" "$SCRIPT_UNDER_TEST"; then
    return 0
  fi
  echo "linux desktop dev guardrails failed: missing marker in script: $marker"
  exit 1
}

assert_file_contains_fixed() {
  local file_path="$1"
  local expected_text="$2"
  local context_label="$3"
  if ! grep -Fxq -- "$expected_text" "$file_path"; then
    echo "linux desktop dev guardrails failed: missing expected marker for $context_label"
    echo "expected text: $expected_text"
    cat "$file_path"
    exit 1
  fi
}

assert_file_not_contains_fixed() {
  local file_path="$1"
  local unexpected_text="$2"
  local context_label="$3"
  if grep -Fxq -- "$unexpected_text" "$file_path"; then
    echo "linux desktop dev guardrails failed: unexpected marker for $context_label"
    echo "unexpected text: $unexpected_text"
    cat "$file_path"
    exit 1
  fi
}

reset_capture_state() {
  rm -f "$CAPTURE_ARGS_PATH"
}

assert_core_forwarding_markers() {
  local case_name="$1"
  local log_path="$TMP_DIR/${case_name}.log"
  if [[ ! -f "$CAPTURE_ARGS_PATH" ]]; then
    echo "linux desktop dev guardrails failed: missing bootstrap args capture for $case_name"
    cat "$log_path"
    exit 1
  fi

  assert_file_contains_fixed "$CAPTURE_ARGS_PATH" "--mode" "$case_name mode flag"
  assert_file_contains_fixed "$CAPTURE_ARGS_PATH" "run-desktop" "$case_name mode value"
  assert_file_contains_fixed "$CAPTURE_ARGS_PATH" "--desktop-launch-strategy" "$case_name launch strategy flag"
  assert_file_contains_fixed "$CAPTURE_ARGS_PATH" "dev" "$case_name launch strategy value"
  assert_file_contains_fixed "$CAPTURE_ARGS_PATH" "--dry-run" "$case_name dry-run forwarding"
}

assert_install_missing_forwarded() {
  local case_name="$1"
  assert_file_contains_fixed "$CAPTURE_ARGS_PATH" "--install-missing" "$case_name install forwarding"
}

assert_install_missing_not_forwarded() {
  local case_name="$1"
  assert_file_not_contains_fixed "$CAPTURE_ARGS_PATH" "--install-missing" "$case_name install forwarding"
}

run_expect_pass() {
  local case_name="$1"
  shift
  local log_path="$TMP_DIR/${case_name}.log"
  reset_capture_state
  if "$@" >"$log_path" 2>&1; then
    assert_core_forwarding_markers "$case_name"
    return 0
  fi
  echo "linux desktop dev guardrails failed: expected pass for $case_name"
  cat "$log_path"
  exit 1
}

run_expect_fail_regex() {
  local case_name="$1"
  local expected_pattern="$2"
  shift 2
  local log_path="$TMP_DIR/${case_name}.log"
  reset_capture_state
  if "$@" >"$log_path" 2>&1; then
    echo "linux desktop dev guardrails failed: expected failure for $case_name"
    cat "$log_path"
    exit 1
  fi
  if ! grep -Eiq -- "$expected_pattern" "$log_path"; then
    echo "linux desktop dev guardrails failed: missing expected failure text for $case_name"
    echo "expected regex: $expected_pattern"
    cat "$log_path"
    exit 1
  fi
}

echo "[linux-desktop-dev-guardrails] precedence markers present"
assert_script_marker "GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING"
assert_script_marker "TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING"
assert_script_marker "--install-missing"
assert_script_marker "--no-install-missing"
assert_script_marker "--mode run-desktop"
assert_script_marker "--desktop-launch-strategy dev"

echo "[linux-desktop-dev-guardrails] default dry-run forwards install intent"
run_expect_pass \
  "default_install_intent_enabled_dry_run" \
  env \
    -u GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING \
    -u TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT="$FAKE_BOOTSTRAP_SCRIPT" \
    DESKTOP_DEV_GUARDRAILS_CAPTURE_PATH="$CAPTURE_ARGS_PATH" \
    "$SCRIPT_UNDER_TEST" \
      --dry-run
assert_install_missing_forwarded "default_install_intent_enabled_dry_run"

echo "[linux-desktop-dev-guardrails] gpm env disable flips install intent off"
run_expect_pass \
  "gpm_env_disable_install_intent_off_dry_run" \
  env \
    GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING=0 \
    TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING=1 \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT="$FAKE_BOOTSTRAP_SCRIPT" \
    DESKTOP_DEV_GUARDRAILS_CAPTURE_PATH="$CAPTURE_ARGS_PATH" \
    "$SCRIPT_UNDER_TEST" \
      --dry-run
assert_install_missing_not_forwarded "gpm_env_disable_install_intent_off_dry_run"

echo "[linux-desktop-dev-guardrails] gpm env enable keeps install intent on"
run_expect_pass \
  "gpm_env_enable_install_intent_on_dry_run" \
  env \
    GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING=1 \
    TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING=0 \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT="$FAKE_BOOTSTRAP_SCRIPT" \
    DESKTOP_DEV_GUARDRAILS_CAPTURE_PATH="$CAPTURE_ARGS_PATH" \
    "$SCRIPT_UNDER_TEST" \
      --dry-run
assert_install_missing_forwarded "gpm_env_enable_install_intent_on_dry_run"

echo "[linux-desktop-dev-guardrails] tdpn alias disable works when gpm env is unset"
run_expect_pass \
  "tdpn_alias_disable_when_gpm_unset_dry_run" \
  env \
    -u GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING \
    TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING=0 \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT="$FAKE_BOOTSTRAP_SCRIPT" \
    DESKTOP_DEV_GUARDRAILS_CAPTURE_PATH="$CAPTURE_ARGS_PATH" \
    "$SCRIPT_UNDER_TEST" \
      --dry-run
assert_install_missing_not_forwarded "tdpn_alias_disable_when_gpm_unset_dry_run"

echo "[linux-desktop-dev-guardrails] explicit --no-install-missing overrides env enable"
run_expect_pass \
  "explicit_no_install_missing_beats_env_enable_dry_run" \
  env \
    GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING=1 \
    TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING=1 \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT="$FAKE_BOOTSTRAP_SCRIPT" \
    DESKTOP_DEV_GUARDRAILS_CAPTURE_PATH="$CAPTURE_ARGS_PATH" \
    "$SCRIPT_UNDER_TEST" \
      --dry-run \
      --no-install-missing
assert_install_missing_not_forwarded "explicit_no_install_missing_beats_env_enable_dry_run"

echo "[linux-desktop-dev-guardrails] explicit --install-missing overrides env disable"
run_expect_pass \
  "explicit_install_missing_beats_env_disable_dry_run" \
  env \
    GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING=0 \
    TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING=0 \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT="$FAKE_BOOTSTRAP_SCRIPT" \
    DESKTOP_DEV_GUARDRAILS_CAPTURE_PATH="$CAPTURE_ARGS_PATH" \
    "$SCRIPT_UNDER_TEST" \
      --dry-run \
      --install-missing
assert_install_missing_forwarded "explicit_install_missing_beats_env_disable_dry_run"

echo "[linux-desktop-dev-guardrails] conflicting explicit flags fail close"
run_expect_fail_regex \
  "conflicting_install_intent_flags_fail" \
  "conflicting install intent: specify only one of --install-missing or --no-install-missing" \
  env \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT="$FAKE_BOOTSTRAP_SCRIPT" \
    DESKTOP_DEV_GUARDRAILS_CAPTURE_PATH="$CAPTURE_ARGS_PATH" \
    "$SCRIPT_UNDER_TEST" \
      --dry-run \
      --install-missing \
      --no-install-missing

echo "linux desktop dev guardrails integration check ok"
