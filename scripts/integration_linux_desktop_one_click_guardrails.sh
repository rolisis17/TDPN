#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in grep mktemp cp chmod; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${DESKTOP_LINUX_ONE_CLICK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/linux/desktop_one_click.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "linux desktop one-click guardrails failed: missing script: $SCRIPT_UNDER_TEST"
  exit 1
fi

TMP_DIR="$(mktemp -d)"
FAKE_REPO_DIR="$TMP_DIR/fake_repo"
FAKE_SCRIPTS_DIR="$FAKE_REPO_DIR/scripts/linux"
FAKE_ONE_CLICK_SCRIPT="$FAKE_SCRIPTS_DIR/desktop_one_click.sh"
FAKE_BOOTSTRAP_SCRIPT="$FAKE_SCRIPTS_DIR/desktop_native_bootstrap.sh"
CAPTURE_DIR="$TMP_DIR/bootstrap_capture"
COUNTER_FILE="$TMP_DIR/bootstrap_invocation_count.txt"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

mkdir -p "$FAKE_SCRIPTS_DIR" "$CAPTURE_DIR"
cp "$SCRIPT_UNDER_TEST" "$FAKE_ONE_CLICK_SCRIPT"
chmod +x "$FAKE_ONE_CLICK_SCRIPT"

cat >"$FAKE_BOOTSTRAP_SCRIPT" <<'FAKE_BOOTSTRAP'
#!/usr/bin/env bash
set -euo pipefail

capture_dir="${DESKTOP_ONE_CLICK_GUARDRAILS_CAPTURE_DIR:?missing capture dir}"
counter_file="${DESKTOP_ONE_CLICK_GUARDRAILS_COUNTER_FILE:?missing counter file}"

invocation_number="1"
if [[ -f "$counter_file" ]]; then
  previous="$(cat "$counter_file")"
  if [[ "$previous" =~ ^[0-9]+$ ]]; then
    invocation_number="$((previous + 1))"
  fi
fi

printf '%s\n' "$invocation_number" >"$counter_file"

invocation_file="$capture_dir/invocation_${invocation_number}.args"
: >"$invocation_file"
for arg in "$@"; do
  printf '%s\n' "$arg" >>"$invocation_file"
done
FAKE_BOOTSTRAP
chmod +x "$FAKE_BOOTSTRAP_SCRIPT"

assert_script_marker() {
  local marker="$1"
  if grep -Fq -- "$marker" "$SCRIPT_UNDER_TEST"; then
    return 0
  fi
  echo "linux desktop one-click guardrails failed: missing marker in script: $marker"
  exit 1
}

reset_capture_state() {
  rm -f "$COUNTER_FILE"
  rm -f "$CAPTURE_DIR"/invocation_*.args
}

assert_invocation_count_two() {
  local case_name="$1"
  local log_path="$TMP_DIR/${case_name}.log"
  if [[ ! -f "$COUNTER_FILE" ]]; then
    echo "linux desktop one-click guardrails failed: missing invocation counter for $case_name"
    cat "$log_path"
    exit 1
  fi
  local count
  count="$(cat "$COUNTER_FILE")"
  if [[ "$count" != "2" ]]; then
    echo "linux desktop one-click guardrails failed: expected two bootstrap invocations for $case_name, found $count"
    cat "$log_path"
    exit 1
  fi
  if [[ ! -f "$CAPTURE_DIR/invocation_1.args" ]] || [[ ! -f "$CAPTURE_DIR/invocation_2.args" ]]; then
    echo "linux desktop one-click guardrails failed: missing captured invocation args for $case_name"
    cat "$log_path"
    exit 1
  fi
}

assert_mode_flow_markers() {
  local case_name="$1"
  local log_path="$TMP_DIR/${case_name}.log"
  if ! grep -Fxq -- "--mode" "$CAPTURE_DIR/invocation_1.args" || ! grep -Fxq -- "bootstrap" "$CAPTURE_DIR/invocation_1.args"; then
    echo "linux desktop one-click guardrails failed: expected bootstrap-mode forwarding markers for $case_name"
    cat "$log_path"
    exit 1
  fi
  if ! grep -Fxq -- "--mode" "$CAPTURE_DIR/invocation_2.args" || ! grep -Fxq -- "run-full" "$CAPTURE_DIR/invocation_2.args"; then
    echo "linux desktop one-click guardrails failed: expected run-full-mode forwarding markers for $case_name"
    cat "$log_path"
    exit 1
  fi
}

assert_install_missing_forwarded() {
  local case_name="$1"
  local log_path="$TMP_DIR/${case_name}.log"
  local invocation_file
  for invocation_file in "$CAPTURE_DIR"/invocation_1.args "$CAPTURE_DIR"/invocation_2.args; do
    if ! grep -Fxq -- "--install-missing" "$invocation_file"; then
      echo "linux desktop one-click guardrails failed: expected --install-missing forwarding for $case_name"
      cat "$log_path"
      exit 1
    fi
  done
}

assert_install_missing_not_forwarded() {
  local case_name="$1"
  local log_path="$TMP_DIR/${case_name}.log"
  local invocation_file
  for invocation_file in "$CAPTURE_DIR"/invocation_1.args "$CAPTURE_DIR"/invocation_2.args; do
    if grep -Fxq -- "--install-missing" "$invocation_file"; then
      echo "linux desktop one-click guardrails failed: unexpected --install-missing forwarding for $case_name"
      cat "$log_path"
      exit 1
    fi
  done
}

run_expect_pass() {
  local case_name="$1"
  shift
  local log_path="$TMP_DIR/${case_name}.log"
  reset_capture_state
  if "$@" >"$log_path" 2>&1; then
    assert_invocation_count_two "$case_name"
    assert_mode_flow_markers "$case_name"
    return 0
  fi
  echo "linux desktop one-click guardrails failed: expected pass for $case_name"
  cat "$log_path"
  exit 1
}

echo "[linux-desktop-one-click-guardrails] one-click precedence markers present"
assert_script_marker "GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING"
assert_script_marker "TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING"
assert_script_marker "--install-missing"
assert_script_marker "--no-install-missing"

echo "[linux-desktop-one-click-guardrails] default dry-run forwards remediation intent"
run_expect_pass \
  "default_dry_run_forwards_install_missing" \
  env \
    -u GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING \
    -u TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING \
    DESKTOP_ONE_CLICK_GUARDRAILS_CAPTURE_DIR="$CAPTURE_DIR" \
    DESKTOP_ONE_CLICK_GUARDRAILS_COUNTER_FILE="$COUNTER_FILE" \
    bash "$FAKE_ONE_CLICK_SCRIPT" \
      --dry-run
assert_install_missing_forwarded "default_dry_run_forwards_install_missing"

echo "[linux-desktop-one-click-guardrails] GPM env disable prefers check/no-install path"
run_expect_pass \
  "gpm_env_disable_no_install_missing" \
  env \
    -u TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING \
    GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING="0" \
    DESKTOP_ONE_CLICK_GUARDRAILS_CAPTURE_DIR="$CAPTURE_DIR" \
    DESKTOP_ONE_CLICK_GUARDRAILS_COUNTER_FILE="$COUNTER_FILE" \
    bash "$FAKE_ONE_CLICK_SCRIPT" \
      --dry-run
assert_install_missing_not_forwarded "gpm_env_disable_no_install_missing"

echo "[linux-desktop-one-click-guardrails] GPM env enable forwards install-missing"
run_expect_pass \
  "gpm_env_enable_forwards_install_missing" \
  env \
    -u TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING \
    GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING="1" \
    DESKTOP_ONE_CLICK_GUARDRAILS_CAPTURE_DIR="$CAPTURE_DIR" \
    DESKTOP_ONE_CLICK_GUARDRAILS_COUNTER_FILE="$COUNTER_FILE" \
    bash "$FAKE_ONE_CLICK_SCRIPT" \
      --dry-run
assert_install_missing_forwarded "gpm_env_enable_forwards_install_missing"

echo "[linux-desktop-one-click-guardrails] TDPN env alias works when GPM env is unset"
run_expect_pass \
  "tdpn_env_disable_when_gpm_unset" \
  env \
    -u GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING \
    TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING="0" \
    DESKTOP_ONE_CLICK_GUARDRAILS_CAPTURE_DIR="$CAPTURE_DIR" \
    DESKTOP_ONE_CLICK_GUARDRAILS_COUNTER_FILE="$COUNTER_FILE" \
    bash "$FAKE_ONE_CLICK_SCRIPT" \
      --dry-run
assert_install_missing_not_forwarded "tdpn_env_disable_when_gpm_unset"

echo "[linux-desktop-one-click-guardrails] explicit --no-install-missing overrides env enable"
run_expect_pass \
  "explicit_no_install_missing_beats_env_enable" \
  env \
    GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING="1" \
    TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING="1" \
    DESKTOP_ONE_CLICK_GUARDRAILS_CAPTURE_DIR="$CAPTURE_DIR" \
    DESKTOP_ONE_CLICK_GUARDRAILS_COUNTER_FILE="$COUNTER_FILE" \
    bash "$FAKE_ONE_CLICK_SCRIPT" \
      --dry-run \
      --no-install-missing
assert_install_missing_not_forwarded "explicit_no_install_missing_beats_env_enable"

echo "[linux-desktop-one-click-guardrails] explicit --install-missing overrides env disable"
run_expect_pass \
  "explicit_install_missing_beats_env_disable" \
  env \
    GPM_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING="0" \
    TDPN_DESKTOP_ONE_CLICK_AUTO_INSTALL_MISSING="0" \
    DESKTOP_ONE_CLICK_GUARDRAILS_CAPTURE_DIR="$CAPTURE_DIR" \
    DESKTOP_ONE_CLICK_GUARDRAILS_COUNTER_FILE="$COUNTER_FILE" \
    bash "$FAKE_ONE_CLICK_SCRIPT" \
      --dry-run \
      --install-missing
assert_install_missing_forwarded "explicit_install_missing_beats_env_disable"

echo "linux desktop one-click guardrails integration check ok"
