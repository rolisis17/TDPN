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

assert_file_contains_fixed() {
  local file_path="$1"
  local expected_text="$2"
  local context_label="$3"
  if ! grep -F -- "$expected_text" "$file_path" >/dev/null 2>&1; then
    echo "linux desktop packaged-run guardrails failed: missing expected marker for $context_label"
    echo "expected text: $expected_text"
    cat "$file_path"
    exit 1
  fi
}

assert_file_not_contains_fixed() {
  local file_path="$1"
  local unexpected_text="$2"
  local context_label="$3"
  if grep -F -- "$unexpected_text" "$file_path" >/dev/null 2>&1; then
    echo "linux desktop packaged-run guardrails failed: unexpected marker for $context_label"
    echo "unexpected text: $unexpected_text"
    cat "$file_path"
    exit 1
  fi
}

assert_file_exists() {
  local file_path="$1"
  local context_label="$2"
  if [[ ! -f "$file_path" ]]; then
    echo "linux desktop packaged-run guardrails failed: expected file missing for $context_label"
    echo "missing path: $file_path"
    exit 1
  fi
}

assert_file_contains_regex() {
  local file_path="$1"
  local expected_pattern="$2"
  local context_label="$3"
  if ! grep -E -- "$expected_pattern" "$file_path" >/dev/null 2>&1; then
    echo "linux desktop packaged-run guardrails failed: missing expected regex for $context_label"
    echo "expected regex: $expected_pattern"
    cat "$file_path"
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
if [[ -n "${DOCTOR_ARGS_MARKER_PATH:-}" ]]; then
  printf '%s\n' "$*" >"$DOCTOR_ARGS_MARKER_PATH"
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
FAKE_REBRAND_EXECUTABLE_PATH="$TMP_DIR/global-private-mesh-desktop"
printf '%s\n' "placeholder rebrand desktop executable used by dry-run integration guardrails" >"$FAKE_REBRAND_EXECUTABLE_PATH"
FAKE_ADMIN_EXECUTABLE_PATH="$TMP_DIR/gpm-admin-console"
printf '%s\n' "placeholder admin console executable used by dry-run integration guardrails" >"$FAKE_ADMIN_EXECUTABLE_PATH"

MISSING_EXECUTABLE_PATH="$TMP_DIR/missing-desktop"
DOCTOR_MARKER_PATH="$TMP_DIR/doctor.marker"
DOCTOR_ARGS_MARKER_PATH="$TMP_DIR/doctor.args"
BOOTSTRAP_ARGS_MARKER_PATH="$TMP_DIR/bootstrap.args"
BOOTSTRAP_MISSING_PATH="$TMP_DIR/missing_desktop_native_bootstrap.sh"
SUMMARY_JSON_PATH="$TMP_DIR/desktop_packaged_run_summary.json"

reset_markers() {
  rm -f "$DOCTOR_MARKER_PATH"
  rm -f "$DOCTOR_ARGS_MARKER_PATH"
  rm -f "$BOOTSTRAP_ARGS_MARKER_PATH"
}

assert_runtime_markers_present() {
  local case_name="$1"
  if [[ ! -f "$DOCTOR_MARKER_PATH" ]]; then
    echo "linux desktop packaged-run guardrails failed: doctor marker missing after $case_name"
    exit 1
  fi
  if [[ ! -f "$DOCTOR_ARGS_MARKER_PATH" ]]; then
    echo "linux desktop packaged-run guardrails failed: doctor args marker missing after $case_name"
    exit 1
  fi
  if [[ ! -f "$BOOTSTRAP_ARGS_MARKER_PATH" ]]; then
    echo "linux desktop packaged-run guardrails failed: bootstrap args marker missing after $case_name"
    exit 1
  fi
}

echo "[linux-desktop-packaged-run-guardrails] dry-run passes with existing executable override path"
run_expect_pass \
  "dry_run_packaged_pass" \
  env \
    DESKTOP_LINUX_DOCTOR_SCRIPT_UNDER_TEST="$FAKE_DOCTOR_SCRIPT" \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT_UNDER_TEST="$FAKE_BOOTSTRAP_SCRIPT" \
    GPM_DESKTOP_PACKAGED_RUN_INSTALL_MISSING= \
    TDPN_DESKTOP_PACKAGED_RUN_INSTALL_MISSING= \
    DOCTOR_MARKER_PATH="$DOCTOR_MARKER_PATH" \
    DOCTOR_ARGS_MARKER_PATH="$DOCTOR_ARGS_MARKER_PATH" \
    BOOTSTRAP_ARGS_MARKER_PATH="$BOOTSTRAP_ARGS_MARKER_PATH" \
    "$SCRIPT_UNDER_TEST" \
      --dry-run \
      --desktop-executable-path "$FAKE_EXECUTABLE_PATH" \
      --summary-json "$SUMMARY_JSON_PATH" \
      --print-summary-json 1

assert_runtime_markers_present "dry-run pass"
assert_file_exists "$SUMMARY_JSON_PATH" "dry-run pass summary json"
assert_file_contains_fixed "$TMP_DIR/dry_run_packaged_pass.log" '[desktop-packaged-run] summary_json='"$SUMMARY_JSON_PATH" "dry-run pass summary marker"
assert_file_contains_fixed "$TMP_DIR/dry_run_packaged_pass.log" '[desktop-packaged-run] summary_json_payload:' "dry-run pass summary payload marker"
assert_file_contains_regex "$SUMMARY_JSON_PATH" '"version":[[:space:]]*1' "summary version"
assert_file_contains_regex "$SUMMARY_JSON_PATH" '"status":[[:space:]]*"pass"' "summary status"
assert_file_contains_regex "$SUMMARY_JSON_PATH" '"rc":[[:space:]]*0' "summary rc"
assert_file_contains_regex "$SUMMARY_JSON_PATH" '"platform":[[:space:]]*"linux"' "summary platform"
assert_file_contains_regex "$SUMMARY_JSON_PATH" '"mode":[[:space:]]*"desktop_packaged_run_scaffold"' "summary mode"
assert_file_contains_regex "$SUMMARY_JSON_PATH" '"dry_run":[[:space:]]*true' "summary dry_run"
assert_file_contains_regex "$SUMMARY_JSON_PATH" '"install_missing_intent":[[:space:]]*false' "summary install intent"
assert_file_contains_regex "$SUMMARY_JSON_PATH" '"api_addr":[[:space:]]*"127\.0\.0\.1:8095"' "summary api_addr"
assert_file_contains_regex "$SUMMARY_JSON_PATH" '"resolved_desktop_executable_path":[[:space:]]*".+"' "summary resolved path"
assert_file_contains_regex "$SUMMARY_JSON_PATH" '"resolved_desktop_executable_source":[[:space:]]*"override"' "summary resolved source"
assert_file_contains_regex "$SUMMARY_JSON_PATH" '"failure_stage":[[:space:]]*""' "summary failure stage empty on pass"
assert_file_contains_regex "$SUMMARY_JSON_PATH" '"doctor":[[:space:]]*\{' "summary doctor object present"
assert_file_contains_regex "$SUMMARY_JSON_PATH" '"doctor"' "summary doctor key"
assert_file_contains_regex "$SUMMARY_JSON_PATH" '"bootstrap":[[:space:]]*\{' "summary bootstrap object present"
assert_file_contains_regex "$SUMMARY_JSON_PATH" '"bootstrap"' "summary bootstrap key"
assert_file_contains_regex "$SUMMARY_JSON_PATH" '"status":[[:space:]]*"pass"' "summary includes pass statuses"
assert_file_contains_regex "$SUMMARY_JSON_PATH" '"doctor_summary_json_forwarded":[[:space:]]*""' "summary doctor summary forward path default empty"
assert_file_contains_fixed "$BOOTSTRAP_ARGS_MARKER_PATH" '--mode run-full' "default bootstrap mode"
assert_file_contains_fixed "$BOOTSTRAP_ARGS_MARKER_PATH" '--desktop-launch-strategy packaged' "default packaged launch strategy"
assert_file_contains_fixed "$DOCTOR_ARGS_MARKER_PATH" '--mode check' "default doctor mode=check"
assert_file_not_contains_fixed "$DOCTOR_ARGS_MARKER_PATH" '--install-missing' "default doctor install forwarding"
assert_file_not_contains_fixed "$BOOTSTRAP_ARGS_MARKER_PATH" '--install-missing' "default bootstrap install forwarding"

reset_markers

echo "[linux-desktop-packaged-run-guardrails] GPM packaged-run env disable forces doctor check mode and removes install forwarding"
run_expect_pass \
  "dry_run_install_intent_gpm_disable_check" \
  env \
    DESKTOP_LINUX_DOCTOR_SCRIPT_UNDER_TEST="$FAKE_DOCTOR_SCRIPT" \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT_UNDER_TEST="$FAKE_BOOTSTRAP_SCRIPT" \
    GPM_DESKTOP_PACKAGED_RUN_INSTALL_MISSING=0 \
    TDPN_DESKTOP_PACKAGED_RUN_INSTALL_MISSING=1 \
    DOCTOR_MARKER_PATH="$DOCTOR_MARKER_PATH" \
    DOCTOR_ARGS_MARKER_PATH="$DOCTOR_ARGS_MARKER_PATH" \
    BOOTSTRAP_ARGS_MARKER_PATH="$BOOTSTRAP_ARGS_MARKER_PATH" \
    "$SCRIPT_UNDER_TEST" \
      --dry-run \
      --desktop-executable-path "$FAKE_EXECUTABLE_PATH"

assert_runtime_markers_present "GPM env disable check"
assert_file_contains_fixed "$DOCTOR_ARGS_MARKER_PATH" '--mode check' "GPM packaged-run env disable doctor mode=check"
assert_file_not_contains_fixed "$DOCTOR_ARGS_MARKER_PATH" '--install-missing' "GPM packaged-run env disable doctor install forwarding"
assert_file_not_contains_fixed "$BOOTSTRAP_ARGS_MARKER_PATH" '--install-missing' "GPM packaged-run env disable bootstrap install forwarding"

reset_markers

echo "[linux-desktop-packaged-run-guardrails] GPM packaged-run env enable keeps doctor fix mode and install forwarding"
run_expect_pass \
  "dry_run_install_intent_gpm_enable_fix" \
  env \
    DESKTOP_LINUX_DOCTOR_SCRIPT_UNDER_TEST="$FAKE_DOCTOR_SCRIPT" \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT_UNDER_TEST="$FAKE_BOOTSTRAP_SCRIPT" \
    GPM_DESKTOP_PACKAGED_RUN_INSTALL_MISSING=1 \
    TDPN_DESKTOP_PACKAGED_RUN_INSTALL_MISSING=0 \
    DOCTOR_MARKER_PATH="$DOCTOR_MARKER_PATH" \
    DOCTOR_ARGS_MARKER_PATH="$DOCTOR_ARGS_MARKER_PATH" \
    BOOTSTRAP_ARGS_MARKER_PATH="$BOOTSTRAP_ARGS_MARKER_PATH" \
    "$SCRIPT_UNDER_TEST" \
      --dry-run \
      --desktop-executable-path "$FAKE_EXECUTABLE_PATH"

assert_runtime_markers_present "GPM env enable fix"
assert_file_contains_fixed "$DOCTOR_ARGS_MARKER_PATH" '--mode fix' "GPM packaged-run env enable doctor mode=fix"
assert_file_contains_fixed "$DOCTOR_ARGS_MARKER_PATH" '--install-missing' "GPM packaged-run env enable doctor install forwarding"
assert_file_contains_fixed "$BOOTSTRAP_ARGS_MARKER_PATH" '--install-missing' "GPM packaged-run env enable bootstrap install forwarding"

reset_markers

echo "[linux-desktop-packaged-run-guardrails] TDPN packaged-run legacy alias disable applies when GPM env is unset"
run_expect_pass \
  "dry_run_install_intent_tdpn_disable_check" \
  env \
    DESKTOP_LINUX_DOCTOR_SCRIPT_UNDER_TEST="$FAKE_DOCTOR_SCRIPT" \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT_UNDER_TEST="$FAKE_BOOTSTRAP_SCRIPT" \
    GPM_DESKTOP_PACKAGED_RUN_INSTALL_MISSING= \
    TDPN_DESKTOP_PACKAGED_RUN_INSTALL_MISSING=0 \
    DOCTOR_MARKER_PATH="$DOCTOR_MARKER_PATH" \
    DOCTOR_ARGS_MARKER_PATH="$DOCTOR_ARGS_MARKER_PATH" \
    BOOTSTRAP_ARGS_MARKER_PATH="$BOOTSTRAP_ARGS_MARKER_PATH" \
    "$SCRIPT_UNDER_TEST" \
      --dry-run \
      --desktop-executable-path "$FAKE_EXECUTABLE_PATH"

assert_runtime_markers_present "TDPN legacy disable check"
assert_file_contains_fixed "$DOCTOR_ARGS_MARKER_PATH" '--mode check' "TDPN packaged-run legacy disable doctor mode=check"
assert_file_not_contains_fixed "$DOCTOR_ARGS_MARKER_PATH" '--install-missing' "TDPN packaged-run legacy disable doctor install forwarding"
assert_file_not_contains_fixed "$BOOTSTRAP_ARGS_MARKER_PATH" '--install-missing' "TDPN packaged-run legacy disable bootstrap install forwarding"

reset_markers

echo "[linux-desktop-packaged-run-guardrails] explicit --no-install-missing overrides env enable"
run_expect_pass \
  "dry_run_install_intent_explicit_no_install_beats_env_enable" \
  env \
    DESKTOP_LINUX_DOCTOR_SCRIPT_UNDER_TEST="$FAKE_DOCTOR_SCRIPT" \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT_UNDER_TEST="$FAKE_BOOTSTRAP_SCRIPT" \
    GPM_DESKTOP_PACKAGED_RUN_INSTALL_MISSING=1 \
    TDPN_DESKTOP_PACKAGED_RUN_INSTALL_MISSING=1 \
    DOCTOR_MARKER_PATH="$DOCTOR_MARKER_PATH" \
    DOCTOR_ARGS_MARKER_PATH="$DOCTOR_ARGS_MARKER_PATH" \
    BOOTSTRAP_ARGS_MARKER_PATH="$BOOTSTRAP_ARGS_MARKER_PATH" \
    "$SCRIPT_UNDER_TEST" \
      --dry-run \
      --desktop-executable-path "$FAKE_EXECUTABLE_PATH" \
      --no-install-missing

assert_runtime_markers_present "explicit --no-install-missing precedence"
assert_file_contains_fixed "$DOCTOR_ARGS_MARKER_PATH" '--mode check' "explicit --no-install-missing doctor mode=check"
assert_file_not_contains_fixed "$DOCTOR_ARGS_MARKER_PATH" '--install-missing' "explicit --no-install-missing doctor install forwarding"
assert_file_not_contains_fixed "$BOOTSTRAP_ARGS_MARKER_PATH" '--install-missing' "explicit --no-install-missing bootstrap install forwarding"

reset_markers

echo "[linux-desktop-packaged-run-guardrails] explicit --install-missing overrides env disable"
run_expect_pass \
  "dry_run_install_intent_explicit_install_beats_env_disable" \
  env \
    DESKTOP_LINUX_DOCTOR_SCRIPT_UNDER_TEST="$FAKE_DOCTOR_SCRIPT" \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT_UNDER_TEST="$FAKE_BOOTSTRAP_SCRIPT" \
    GPM_DESKTOP_PACKAGED_RUN_INSTALL_MISSING=0 \
    TDPN_DESKTOP_PACKAGED_RUN_INSTALL_MISSING=0 \
    DOCTOR_MARKER_PATH="$DOCTOR_MARKER_PATH" \
    DOCTOR_ARGS_MARKER_PATH="$DOCTOR_ARGS_MARKER_PATH" \
    BOOTSTRAP_ARGS_MARKER_PATH="$BOOTSTRAP_ARGS_MARKER_PATH" \
    "$SCRIPT_UNDER_TEST" \
      --dry-run \
      --desktop-executable-path "$FAKE_EXECUTABLE_PATH" \
      --install-missing

assert_runtime_markers_present "explicit --install-missing precedence"
assert_file_contains_fixed "$DOCTOR_ARGS_MARKER_PATH" '--mode fix' "explicit --install-missing doctor mode=fix"
assert_file_contains_fixed "$DOCTOR_ARGS_MARKER_PATH" '--install-missing' "explicit --install-missing doctor install forwarding"
assert_file_contains_fixed "$BOOTSTRAP_ARGS_MARKER_PATH" '--install-missing' "explicit --install-missing bootstrap install forwarding"

reset_markers

echo "[linux-desktop-packaged-run-guardrails] invalid GPM install remediation env fails closed before TDPN alias"
run_expect_fail_regex \
  "invalid_gpm_install_env_fail" \
  "invalid boolean value for GPM_DESKTOP_PACKAGED_RUN_INSTALL_MISSING|install remediation fallback" \
  env \
    DESKTOP_LINUX_DOCTOR_SCRIPT_UNDER_TEST="$FAKE_DOCTOR_SCRIPT" \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT_UNDER_TEST="$FAKE_BOOTSTRAP_SCRIPT" \
    GPM_DESKTOP_PACKAGED_RUN_INSTALL_MISSING=maybe \
    TDPN_DESKTOP_PACKAGED_RUN_INSTALL_MISSING=1 \
    DOCTOR_MARKER_PATH="$DOCTOR_MARKER_PATH" \
    DOCTOR_ARGS_MARKER_PATH="$DOCTOR_ARGS_MARKER_PATH" \
    BOOTSTRAP_ARGS_MARKER_PATH="$BOOTSTRAP_ARGS_MARKER_PATH" \
    "$SCRIPT_UNDER_TEST" \
      --dry-run \
      --desktop-executable-path "$FAKE_EXECUTABLE_PATH"

if [[ -f "$DOCTOR_MARKER_PATH" || -f "$DOCTOR_ARGS_MARKER_PATH" || -f "$BOOTSTRAP_ARGS_MARKER_PATH" ]]; then
  echo "linux desktop packaged-run guardrails failed: invalid install env rejection must happen before doctor/bootstrap"
  ls -la "$TMP_DIR"
  exit 1
fi

reset_markers

echo "[linux-desktop-packaged-run-guardrails] dry-run passes with rebrand env override path"
run_expect_pass \
  "dry_run_rebrand_env_override_pass" \
  env \
    DESKTOP_LINUX_DOCTOR_SCRIPT_UNDER_TEST="$FAKE_DOCTOR_SCRIPT" \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT_UNDER_TEST="$FAKE_BOOTSTRAP_SCRIPT" \
    GLOBAL_PRIVATE_MESH_DESKTOP_PACKAGED_EXE="$FAKE_REBRAND_EXECUTABLE_PATH" \
    DOCTOR_MARKER_PATH="$DOCTOR_MARKER_PATH" \
    DOCTOR_ARGS_MARKER_PATH="$DOCTOR_ARGS_MARKER_PATH" \
    BOOTSTRAP_ARGS_MARKER_PATH="$BOOTSTRAP_ARGS_MARKER_PATH" \
    "$SCRIPT_UNDER_TEST" \
      --dry-run

if [[ ! -f "$BOOTSTRAP_ARGS_MARKER_PATH" ]]; then
  echo "linux desktop packaged-run guardrails failed: bootstrap args marker missing after rebrand env override pass"
  exit 1
fi
if ! grep -F -- "--desktop-executable-override-path $FAKE_REBRAND_EXECUTABLE_PATH" "$BOOTSTRAP_ARGS_MARKER_PATH" >/dev/null 2>&1; then
  echo "linux desktop packaged-run guardrails failed: bootstrap invocation did not include rebrand override path"
  cat "$BOOTSTRAP_ARGS_MARKER_PATH"
  exit 1
fi

reset_markers

echo "[linux-desktop-packaged-run-guardrails] public packaged mode refuses daemon admin route env before doctor/bootstrap"
run_expect_fail_regex \
  "public_admin_routes_env_fail" \
  "public packaged mode refuses daemon admin routes|GPM Admin Console" \
  env \
    DESKTOP_LINUX_DOCTOR_SCRIPT_UNDER_TEST="$FAKE_DOCTOR_SCRIPT" \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT_UNDER_TEST="$FAKE_BOOTSTRAP_SCRIPT" \
    GPM_LOCAL_API_ADMIN_ROUTES=1 \
    TDPN_LOCAL_API_ADMIN_ROUTES=0 \
    DOCTOR_MARKER_PATH="$DOCTOR_MARKER_PATH" \
    DOCTOR_ARGS_MARKER_PATH="$DOCTOR_ARGS_MARKER_PATH" \
    BOOTSTRAP_ARGS_MARKER_PATH="$BOOTSTRAP_ARGS_MARKER_PATH" \
    "$SCRIPT_UNDER_TEST" \
      --dry-run \
      --desktop-executable-path "$FAKE_EXECUTABLE_PATH"

if [[ -f "$DOCTOR_MARKER_PATH" || -f "$DOCTOR_ARGS_MARKER_PATH" || -f "$BOOTSTRAP_ARGS_MARKER_PATH" ]]; then
  echo "linux desktop packaged-run guardrails failed: admin-route rejection must happen before doctor/bootstrap"
  ls -la "$TMP_DIR"
  exit 1
fi

reset_markers

echo "[linux-desktop-packaged-run-guardrails] public packaged mode refuses admin console env before doctor/bootstrap"
run_expect_fail_regex \
  "public_admin_console_env_fail" \
  "public packaged mode refuses admin console mode|GPM Admin Console" \
  env \
    DESKTOP_LINUX_DOCTOR_SCRIPT_UNDER_TEST="$FAKE_DOCTOR_SCRIPT" \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT_UNDER_TEST="$FAKE_BOOTSTRAP_SCRIPT" \
    GPM_DESKTOP_ADMIN_CONSOLE=1 \
    DOCTOR_MARKER_PATH="$DOCTOR_MARKER_PATH" \
    DOCTOR_ARGS_MARKER_PATH="$DOCTOR_ARGS_MARKER_PATH" \
    BOOTSTRAP_ARGS_MARKER_PATH="$BOOTSTRAP_ARGS_MARKER_PATH" \
    "$SCRIPT_UNDER_TEST" \
      --dry-run \
      --desktop-executable-path "$FAKE_EXECUTABLE_PATH"

if [[ -f "$DOCTOR_MARKER_PATH" || -f "$DOCTOR_ARGS_MARKER_PATH" || -f "$BOOTSTRAP_ARGS_MARKER_PATH" ]]; then
  echo "linux desktop packaged-run guardrails failed: admin-console env rejection must happen before doctor/bootstrap"
  ls -la "$TMP_DIR"
  exit 1
fi

reset_markers

echo "[linux-desktop-packaged-run-guardrails] public packaged mode refuses admin console executable override"
run_expect_fail_regex \
  "public_admin_console_executable_fail" \
  "public packaged mode refuses admin console executable|admin_console_executable_guard" \
  env \
    DESKTOP_LINUX_DOCTOR_SCRIPT_UNDER_TEST="$FAKE_DOCTOR_SCRIPT" \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT_UNDER_TEST="$FAKE_BOOTSTRAP_SCRIPT" \
    DOCTOR_MARKER_PATH="$DOCTOR_MARKER_PATH" \
    DOCTOR_ARGS_MARKER_PATH="$DOCTOR_ARGS_MARKER_PATH" \
    BOOTSTRAP_ARGS_MARKER_PATH="$BOOTSTRAP_ARGS_MARKER_PATH" \
    "$SCRIPT_UNDER_TEST" \
      --dry-run \
      --desktop-executable-path "$FAKE_ADMIN_EXECUTABLE_PATH"

if [[ -f "$DOCTOR_MARKER_PATH" || -f "$DOCTOR_ARGS_MARKER_PATH" || -f "$BOOTSTRAP_ARGS_MARKER_PATH" ]]; then
  echo "linux desktop packaged-run guardrails failed: admin executable rejection must happen before doctor/bootstrap"
  ls -la "$TMP_DIR"
  exit 1
fi

reset_markers

echo "[linux-desktop-packaged-run-guardrails] dry-run fails when override path does not exist"
run_expect_fail_regex \
  "dry_run_missing_override_fail" \
  "desktop executable override was not found|desktop executable override.*not found|desktop executable.*override.*not found" \
  env \
    DESKTOP_LINUX_DOCTOR_SCRIPT_UNDER_TEST="$FAKE_DOCTOR_SCRIPT" \
    DESKTOP_LINUX_NATIVE_BOOTSTRAP_SCRIPT_UNDER_TEST="$BOOTSTRAP_MISSING_PATH" \
    DOCTOR_MARKER_PATH="$DOCTOR_MARKER_PATH" \
    DOCTOR_ARGS_MARKER_PATH="$DOCTOR_ARGS_MARKER_PATH" \
    "$SCRIPT_UNDER_TEST" \
      --dry-run \
      --desktop-executable-path "$MISSING_EXECUTABLE_PATH"

if [[ ! -f "$DOCTOR_MARKER_PATH" ]]; then
  echo "linux desktop packaged-run guardrails failed: doctor marker missing after expected-fail case"
  exit 1
fi

echo "linux desktop packaged-run guardrails integration check ok"
