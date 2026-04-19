#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq mktemp chmod grep sed cat bash; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TARGET_SCRIPT="$ROOT_DIR/scripts/ci_phase0.sh"
if [[ ! -x "$TARGET_SCRIPT" ]]; then
  echo "missing executable script under test: $TARGET_SCRIPT"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.log"
DRY_LOG="$TMP_DIR/dry.log"
SUCCESS_LOG="$TMP_DIR/success.log"
FAIL_LOG="$TMP_DIR/fail.log"
INVALID_BOOL_LOG="$TMP_DIR/invalid_bool.log"
PRINT_ON_LOG="$TMP_DIR/print_on.log"
PRINT_OFF_LOG="$TMP_DIR/print_off.log"
DRY_SUMMARY="$TMP_DIR/summary_dry_run.json"
SUCCESS_SUMMARY="$TMP_DIR/summary_success.json"
FAIL_SUMMARY="$TMP_DIR/summary_fail.json"
PRINT_ON_SUMMARY="$TMP_DIR/summary_print_on.json"
PRINT_OFF_SUMMARY="$TMP_DIR/summary_print_off.json"

make_fake_step() {
  local path="$1"
  local step_id="$2"
  cat >"$path" <<EOF_FAKE
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$step_id" >>"\${CI_PHASE0_CAPTURE_FILE:?}"
if [[ "\${CI_PHASE0_FAIL_STEP:-}" == "$step_id" ]]; then
  exit "\${CI_PHASE0_FAIL_RC:-19}"
fi
exit 0
EOF_FAKE
  chmod +x "$path"
}

FAKE_LAUNCHER_WIRING="$TMP_DIR/fake_launcher_wiring.sh"
FAKE_LAUNCHER_RUNTIME="$TMP_DIR/fake_launcher_runtime.sh"
FAKE_PROMPT_BUDGET="$TMP_DIR/fake_prompt_budget.sh"
FAKE_CONFIG_V1="$TMP_DIR/fake_config_v1.sh"
FAKE_LOCAL_CONTROL="$TMP_DIR/fake_local_control_api.sh"

make_fake_step "$FAKE_LAUNCHER_WIRING" "launcher_wiring"
make_fake_step "$FAKE_LAUNCHER_RUNTIME" "launcher_runtime"
make_fake_step "$FAKE_PROMPT_BUDGET" "prompt_budget"
make_fake_step "$FAKE_CONFIG_V1" "config_v1"
make_fake_step "$FAKE_LOCAL_CONTROL" "local_control_api"

run_under_test() {
  CI_PHASE0_CAPTURE_FILE="$CAPTURE" \
  CI_PHASE0_LAUNCHER_WIRING_SCRIPT="$FAKE_LAUNCHER_WIRING" \
  CI_PHASE0_LAUNCHER_RUNTIME_SCRIPT="$FAKE_LAUNCHER_RUNTIME" \
  CI_PHASE0_PROMPT_BUDGET_SCRIPT="$FAKE_PROMPT_BUDGET" \
  CI_PHASE0_CONFIG_V1_SCRIPT="$FAKE_CONFIG_V1" \
  CI_PHASE0_LOCAL_CONTROL_API_SCRIPT="$FAKE_LOCAL_CONTROL" \
  "$TARGET_SCRIPT" "$@"
}

script_has_flag() {
  local flag="$1"
  "$TARGET_SCRIPT" --help 2>&1 | grep -F -- "$flag" >/dev/null
}

echo "[ci-phase0] dry-run contract"
: >"$CAPTURE"
run_under_test --dry-run 1 --summary-json "$DRY_SUMMARY" >"$DRY_LOG" 2>&1

if [[ -s "$CAPTURE" ]]; then
  echo "dry-run should not execute any phase-0 steps"
  cat "$CAPTURE"
  cat "$DRY_LOG"
  exit 1
fi
if ! grep -F -- '[ci-phase0] dry-run=1' "$DRY_LOG" >/dev/null; then
  echo "dry-run output missing dry-run banner"
  cat "$DRY_LOG"
  exit 1
fi
if ! grep -F -- '[ci-phase0] dry-run complete' "$DRY_LOG" >/dev/null; then
  echo "dry-run output missing completion banner"
  cat "$DRY_LOG"
  exit 1
fi
for expected in "$FAKE_LAUNCHER_WIRING" "$FAKE_LAUNCHER_RUNTIME" "$FAKE_PROMPT_BUDGET" "$FAKE_CONFIG_V1" "$FAKE_LOCAL_CONTROL"; do
  if ! grep -F -- "$expected" "$DRY_LOG" >/dev/null; then
    echo "dry-run output missing command path: $expected"
    cat "$DRY_LOG"
    exit 1
  fi
done
if ! jq -e '
  .schema.id == "ci_phase0_summary"
  and .schema.major == 1
  and .status == "dry-run"
  and .rc == 0
  and .dry_run == true
  and .summary.total_steps == 5
  and .summary.dry_run_steps == 5
  and .summary.contract_ok == false
  and .steps.launcher_wiring.status == "dry-run"
  and .steps.local_control_api.status == "dry-run"
  and .artifacts.summary_json == "'"$DRY_SUMMARY"'"
' "$DRY_SUMMARY" >/dev/null; then
  echo "dry-run summary missing expected fields"
  cat "$DRY_SUMMARY"
  exit 1
fi

echo "[ci-phase0] success flow order"
: >"$CAPTURE"
run_under_test --summary-json "$SUCCESS_SUMMARY" >"$SUCCESS_LOG" 2>&1

if ! grep -F -- '[ci-phase0] ok' "$SUCCESS_LOG" >/dev/null; then
  echo "success output missing [ci-phase0] ok marker"
  cat "$SUCCESS_LOG"
  exit 1
fi

actual_order="$(cat "$CAPTURE")"
expected_order="$(cat <<'EOF_ORDER'
launcher_wiring
launcher_runtime
prompt_budget
config_v1
local_control_api
EOF_ORDER
)"
if [[ "$actual_order" != "$expected_order" ]]; then
  echo "phase-0 step order mismatch"
  echo "--- expected ---"
  printf '%s\n' "$expected_order"
  echo "--- actual ---"
  printf '%s\n' "$actual_order"
  cat "$SUCCESS_LOG"
  exit 1
fi
if ! jq -e '
  .schema.id == "ci_phase0_summary"
  and .status == "pass"
  and .rc == 0
  and .dry_run == false
  and .summary.total_steps == 5
  and .summary.pass_steps == 5
  and .summary.fail_steps == 0
  and .summary.contract_ok == true
  and .summary.all_required_steps_ok == true
  and .steps.prompt_budget.status == "pass"
  and .steps.local_control_api.status == "pass"
  and .artifacts.summary_json == "'"$SUCCESS_SUMMARY"'"
' "$SUCCESS_SUMMARY" >/dev/null; then
  echo "success summary missing expected fields"
  cat "$SUCCESS_SUMMARY"
  exit 1
fi

echo "[ci-phase0] fail-fast behavior"
: >"$CAPTURE"
set +e
CI_PHASE0_FAIL_STEP="prompt_budget" \
CI_PHASE0_FAIL_RC=37 \
run_under_test --summary-json "$FAIL_SUMMARY" >"$FAIL_LOG" 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 37 ]]; then
  echo "expected fail-fast rc=37, got rc=${fail_rc}"
  cat "$FAIL_LOG"
  exit 1
fi
if grep -F -- 'config_v1' "$CAPTURE" >/dev/null || grep -F -- 'local_control_api' "$CAPTURE" >/dev/null; then
  echo "fail-fast contract broken: downstream steps executed after prompt_budget failure"
  cat "$CAPTURE"
  cat "$FAIL_LOG"
  exit 1
fi
if grep -F -- '[ci-phase0] ok' "$FAIL_LOG" >/dev/null; then
  echo "fail-fast contract broken: success marker printed on failure"
  cat "$FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .schema.id == "ci_phase0_summary"
  and .status == "fail"
  and .rc == 37
  and .dry_run == false
  and .summary.pass_steps == 2
  and .summary.fail_steps == 1
  and .summary.skipped_steps == 2
  and .summary.contract_ok == false
  and .steps.prompt_budget.status == "fail"
  and .steps.prompt_budget.rc == 37
  and .steps.config_v1.status == "skipped"
  and .steps.local_control_api.status == "skipped"
  and .artifacts.summary_json == "'"$FAIL_SUMMARY"'"
' "$FAIL_SUMMARY" >/dev/null; then
  echo "fail summary missing expected fields"
  cat "$FAIL_SUMMARY"
  exit 1
fi

if script_has_flag '--print-summary-json'; then
  echo "[ci-phase0] print-summary-json contract"
  : >"$CAPTURE"
  run_under_test --dry-run 1 --summary-json "$PRINT_ON_SUMMARY" --print-summary-json 1 >"$PRINT_ON_LOG" 2>&1

  if [[ -s "$CAPTURE" ]]; then
    echo "print-summary-json dry-run should not execute any phase-0 steps (print=1)"
    cat "$CAPTURE"
    cat "$PRINT_ON_LOG"
    exit 1
  fi
  if ! grep -F -- '"ci_phase0_summary"' "$PRINT_ON_LOG" >/dev/null; then
    echo "print-summary-json=1 should emit summary JSON payload"
    cat "$PRINT_ON_LOG"
    exit 1
  fi
  if ! jq -e '
    .schema.id == "ci_phase0_summary"
    and .status == "dry-run"
    and .dry_run == true
    and .artifacts.summary_json == "'"$PRINT_ON_SUMMARY"'"
  ' "$PRINT_ON_SUMMARY" >/dev/null; then
    echo "print-summary-json=1 should still write summary artifact"
    cat "$PRINT_ON_SUMMARY"
    exit 1
  fi

  : >"$CAPTURE"
  run_under_test --dry-run 1 --summary-json "$PRINT_OFF_SUMMARY" --print-summary-json 0 >"$PRINT_OFF_LOG" 2>&1

  if [[ -s "$CAPTURE" ]]; then
    echo "print-summary-json dry-run should not execute any phase-0 steps (print=0)"
    cat "$CAPTURE"
    cat "$PRINT_OFF_LOG"
    exit 1
  fi
  if grep -F -- '"ci_phase0_summary"' "$PRINT_OFF_LOG" >/dev/null; then
    echo "print-summary-json=0 should suppress summary JSON payload"
    cat "$PRINT_OFF_LOG"
    exit 1
  fi
  if ! jq -e '
    .schema.id == "ci_phase0_summary"
    and .status == "dry-run"
    and .dry_run == true
    and .artifacts.summary_json == "'"$PRINT_OFF_SUMMARY"'"
  ' "$PRINT_OFF_SUMMARY" >/dev/null; then
    echo "print-summary-json=0 should still write summary artifact"
    cat "$PRINT_OFF_SUMMARY"
    exit 1
  fi
else
  echo "[ci-phase0] print-summary-json contract skipped (flag unavailable in ci_phase0.sh)"
fi

echo "[ci-phase0] invalid bool arg guardrail"
set +e
run_under_test --dry-run 2 >"$INVALID_BOOL_LOG" 2>&1
invalid_rc=$?
set -e
if [[ "$invalid_rc" -eq 0 ]]; then
  echo "expected non-zero rc for invalid --dry-run bool"
  cat "$INVALID_BOOL_LOG"
  exit 1
fi
if ! grep -F -- '--dry-run must be 0 or 1' "$INVALID_BOOL_LOG" >/dev/null; then
  echo "invalid bool output missing guardrail message"
  cat "$INVALID_BOOL_LOG"
  exit 1
fi

echo "ci phase0 integration check ok"
