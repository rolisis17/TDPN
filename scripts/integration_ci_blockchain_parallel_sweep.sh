#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp jq grep sed awk sort tr cat chmod cmp wc; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="$ROOT_DIR/scripts/ci_blockchain_parallel_sweep.sh"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

assert_script_contains_literal() {
  local needle="$1"
  if ! grep -Fq "$needle" "$SCRIPT_UNDER_TEST"; then
    echo "script contract missing literal: $needle"
    exit 1
  fi
}

assert_phase_lane_contract_literals() {
  local required_literals=(
    "bash scripts/check_roadmap_consistency.sh"
    "bash scripts/integration_roadmap_consistency.sh"
    "bash scripts/integration_roadmap_progress_report.sh"
    "bash scripts/integration_roadmap_blockchain_actionable_run.sh"
    "bash scripts/integration_easy_node_roadmap_blockchain_actionable_run.sh"
    "bash scripts/integration_blockchain_bootstrap_graduation_gate.sh"
    "bash scripts/integration_blockchain_mainnet_activation_metrics_input_template.sh"
    "bash scripts/integration_blockchain_mainnet_activation_metrics_missing_input_template.sh"
    "bash scripts/integration_blockchain_mainnet_activation_metrics_missing_checklist.sh"
    "bash scripts/integration_blockchain_mainnet_activation_operator_pack.sh"
    "bash scripts/integration_blockchain_mainnet_activation_metrics_input.sh"
    "bash scripts/integration_blockchain_mainnet_activation_metrics.sh"
    "bash scripts/integration_blockchain_mainnet_activation_gate.sh"
    "bash scripts/integration_blockchain_gate_bundle.sh"
    "bash scripts/integration_blockchain_mainnet_activation_gate_cycle.sh"
    "bash scripts/integration_blockchain_fastlane.sh"
    "bash scripts/integration_easy_node_blockchain_fastlane_cohort_quick_check_shim.sh"
    "bash scripts/integration_easy_node_blockchain_gate_wrappers.sh"
    "bash scripts/integration_easy_node_blockchain_summary_reports.sh"
    "bash scripts/integration_ci_phase5_settlement_layer.sh"
    "bash scripts/integration_phase5_settlement_layer_check.sh"
    "bash scripts/integration_phase5_settlement_layer_run.sh"
    "bash scripts/integration_phase5_settlement_layer_handoff_check.sh"
    "bash scripts/integration_phase5_settlement_layer_handoff_run.sh"
    "bash scripts/integration_phase5_settlement_layer_summary_report.sh"
    "bash scripts/integration_ci_phase6_cosmos_l1_build_testnet.sh"
    "bash scripts/integration_ci_phase6_cosmos_l1_contracts.sh"
    "bash scripts/integration_slash_violation_type_contract_consistency.sh"
    "bash scripts/integration_phase6_cosmos_l1_build_testnet_check.sh"
    "bash scripts/integration_phase6_cosmos_l1_build_testnet_run.sh"
    "bash scripts/integration_phase6_cosmos_l1_build_testnet_handoff_check.sh"
    "bash scripts/integration_phase6_cosmos_l1_build_testnet_handoff_run.sh"
    "bash scripts/integration_phase6_cosmos_l1_build_testnet_suite.sh"
    "bash scripts/integration_phase6_cosmos_l1_contracts_live_smoke.sh"
    "bash scripts/integration_phase6_cosmos_l1_summary_report.sh"
    "bash scripts/integration_ci_phase7_mainnet_cutover.sh"
    "bash scripts/integration_phase7_mainnet_cutover_check.sh"
    "bash scripts/integration_phase7_mainnet_cutover_run.sh"
    "bash scripts/integration_phase7_mainnet_cutover_handoff_check.sh"
    "bash scripts/integration_phase7_mainnet_cutover_handoff_run.sh"
    "bash scripts/integration_phase7_mainnet_cutover_summary_report.sh"
    "bash scripts/integration_phase7_mainnet_cutover_live_smoke.sh"
  )

  local literal
  local previous_line=0
  local current_line
  for literal in "${required_literals[@]}"; do
    assert_script_contains_literal "$literal"
    current_line="$(grep -nF "$literal" "$SCRIPT_UNDER_TEST" | head -n1 | cut -d: -f1)"
    if [[ -z "$current_line" || "$current_line" -le "$previous_line" ]]; then
      echo "script contract stage order mismatch around: $literal"
      exit 1
    fi
    previous_line="$current_line"
  done
}

echo "[ci-blockchain-parallel-sweep] static phase lane literal contract"
assert_phase_lane_contract_literals

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/lane_calls.tsv"

SUCCESS_REPORTS_DIR="$TMP_DIR/reports_success"
SUCCESS_SUMMARY_JSON="$TMP_DIR/summary_success.json"
SUCCESS_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_success.json"
SUCCESS_LOG="$TMP_DIR/success.log"

DRY_RUN_REPORTS_DIR="$TMP_DIR/reports_dry_run"
DRY_RUN_SUMMARY_JSON="$TMP_DIR/summary_dry_run.json"
DRY_RUN_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_dry_run.json"
DRY_RUN_LOG="$TMP_DIR/dry_run.log"

TOGGLE_REPORTS_DIR="$TMP_DIR/reports_toggle"
TOGGLE_SUMMARY_JSON="$TMP_DIR/summary_toggle.json"
TOGGLE_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_toggle.json"
TOGGLE_LOG="$TMP_DIR/toggle.log"

FAIL_REPORTS_DIR="$TMP_DIR/reports_fail"
FAIL_SUMMARY_JSON="$TMP_DIR/summary_fail.json"
FAIL_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_fail.json"
FAIL_LOG="$TMP_DIR/fail.log"

FAKE_LANE_HELPER="$TMP_DIR/fake_lane_helper.sh"
cat >"$FAKE_LANE_HELPER" <<'EOF_FAKE_HELPER'
#!/usr/bin/env bash
set -euo pipefail

capture="${CI_BLOCKCHAIN_PARALLEL_SWEEP_CAPTURE_FILE:?}"
lane_id="${CI_BLOCKCHAIN_PARALLEL_SWEEP_LANE_ID:?}"
fail_matrix="${CI_BLOCKCHAIN_PARALLEL_SWEEP_FAIL_MATRIX:-}"

printf '%s\n' "$lane_id" >>"$capture"

if [[ -n "$fail_matrix" ]]; then
  old_ifs="$IFS"
  IFS=',;'
  read -r -a specs <<<"$fail_matrix"
  IFS="$old_ifs"
  for spec in "${specs[@]}"; do
    case "$spec" in
      "$lane_id"=*)
        rc="${spec#*=}"
        if [[ "$rc" =~ ^-?[0-9]+$ ]]; then
          exit "$rc"
        fi
        exit 1
        ;;
    esac
  done
fi

exit 0
EOF_FAKE_HELPER
chmod +x "$FAKE_LANE_HELPER"

FAKE_COSMOS="$TMP_DIR/fake_lane_cosmos.sh"
cat >"$FAKE_COSMOS" <<'EOF_FAKE_COSMOS'
#!/usr/bin/env bash
set -euo pipefail
CI_BLOCKCHAIN_PARALLEL_SWEEP_CAPTURE_FILE="${CI_BLOCKCHAIN_PARALLEL_SWEEP_CAPTURE_FILE:?}" \
CI_BLOCKCHAIN_PARALLEL_SWEEP_LANE_ID="cosmos_low_level" \
CI_BLOCKCHAIN_PARALLEL_SWEEP_FAIL_MATRIX="${CI_BLOCKCHAIN_PARALLEL_SWEEP_FAIL_MATRIX:-}" \
"${CI_BLOCKCHAIN_PARALLEL_SWEEP_FAKE_HELPER:?}"
EOF_FAKE_COSMOS
chmod +x "$FAKE_COSMOS"

FAKE_PHASE="$TMP_DIR/fake_lane_phase.sh"
cat >"$FAKE_PHASE" <<'EOF_FAKE_PHASE'
#!/usr/bin/env bash
set -euo pipefail
CI_BLOCKCHAIN_PARALLEL_SWEEP_CAPTURE_FILE="${CI_BLOCKCHAIN_PARALLEL_SWEEP_CAPTURE_FILE:?}" \
CI_BLOCKCHAIN_PARALLEL_SWEEP_LANE_ID="phase_wrappers" \
CI_BLOCKCHAIN_PARALLEL_SWEEP_FAIL_MATRIX="${CI_BLOCKCHAIN_PARALLEL_SWEEP_FAIL_MATRIX:-}" \
"${CI_BLOCKCHAIN_PARALLEL_SWEEP_FAKE_HELPER:?}"
EOF_FAKE_PHASE
chmod +x "$FAKE_PHASE"

FAKE_GO="$TMP_DIR/fake_lane_go.sh"
cat >"$FAKE_GO" <<'EOF_FAKE_GO'
#!/usr/bin/env bash
set -euo pipefail
CI_BLOCKCHAIN_PARALLEL_SWEEP_CAPTURE_FILE="${CI_BLOCKCHAIN_PARALLEL_SWEEP_CAPTURE_FILE:?}" \
CI_BLOCKCHAIN_PARALLEL_SWEEP_LANE_ID="go_tests" \
CI_BLOCKCHAIN_PARALLEL_SWEEP_FAIL_MATRIX="${CI_BLOCKCHAIN_PARALLEL_SWEEP_FAIL_MATRIX:-}" \
"${CI_BLOCKCHAIN_PARALLEL_SWEEP_FAKE_HELPER:?}"
EOF_FAKE_GO
chmod +x "$FAKE_GO"

assert_capture_lanes_exact() {
  local capture_file="$1"
  shift
  local expected
  expected="$(printf '%s\n' "$@" | sed '/^$/d' | sort)"
  local actual=""
  if [[ -f "$capture_file" ]]; then
    actual="$(sort "$capture_file")"
  fi
  if [[ "$actual" != "$expected" ]]; then
    echo "capture lanes mismatch"
    echo "expected:"
    printf '%s\n' "$expected"
    echo "actual:"
    printf '%s\n' "$actual"
    exit 1
  fi
}

run_sweep() {
  CI_BLOCKCHAIN_PARALLEL_SWEEP_FAKE_HELPER="$FAKE_LANE_HELPER" \
  CI_BLOCKCHAIN_PARALLEL_SWEEP_CAPTURE_FILE="$CAPTURE" \
  CI_BLOCKCHAIN_PARALLEL_SWEEP_LANE_COSMOS_CMD="$FAKE_COSMOS" \
  CI_BLOCKCHAIN_PARALLEL_SWEEP_LANE_PHASE_CMD="$FAKE_PHASE" \
  CI_BLOCKCHAIN_PARALLEL_SWEEP_LANE_GO_CMD="$FAKE_GO" \
  "$SCRIPT_UNDER_TEST" "$@"
}

echo "[ci-blockchain-parallel-sweep] success path"
: >"$CAPTURE"
if ! run_sweep \
  --reports-dir "$SUCCESS_REPORTS_DIR" \
  --summary-json "$SUCCESS_SUMMARY_JSON" \
  --print-summary-json 0 >"$SUCCESS_LOG" 2>&1; then
  echo "expected success path to pass"
  cat "$SUCCESS_LOG"
  exit 1
fi
if [[ ! -f "$SUCCESS_SUMMARY_JSON" ]]; then
  echo "missing success summary JSON"
  exit 1
fi
if [[ ! -f "$ROOT_DIR/.easy-node-logs/ci_blockchain_parallel_sweep_summary.json" ]]; then
  echo "missing canonical success summary JSON under .easy-node-logs"
  exit 1
fi
cp "$ROOT_DIR/.easy-node-logs/ci_blockchain_parallel_sweep_summary.json" "$SUCCESS_CANONICAL_SUMMARY_JSON"
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .dry_run == false
  and .totals.enabled == 3
  and .totals.pass == 3
  and .totals.fail == 0
  and .totals.skipped == 0
  and .first_failure.lane_id == null
  and .lanes.cosmos_low_level.status == "pass"
  and .lanes.phase_wrappers.status == "pass"
  and .lanes.go_tests.status == "pass"
' "$SUCCESS_SUMMARY_JSON" >/dev/null; then
  echo "success summary JSON missing expected fields"
  cat "$SUCCESS_SUMMARY_JSON"
  exit 1
fi
assert_capture_lanes_exact "$CAPTURE" "cosmos_low_level" "phase_wrappers" "go_tests"
if ! cmp -s "$SUCCESS_SUMMARY_JSON" "$SUCCESS_CANONICAL_SUMMARY_JSON"; then
  echo "expected success canonical summary to mirror summary-json output"
  exit 1
fi

echo "[ci-blockchain-parallel-sweep] dry-run skip path"
: >"$CAPTURE"
if ! run_sweep \
  --reports-dir "$DRY_RUN_REPORTS_DIR" \
  --summary-json "$DRY_RUN_SUMMARY_JSON" \
  --dry-run 1 \
  --print-summary-json 0 >"$DRY_RUN_LOG" 2>&1; then
  echo "expected dry-run path to pass"
  cat "$DRY_RUN_LOG"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .dry_run == true
  and .totals.enabled == 3
  and .totals.pass == 0
  and .totals.fail == 0
  and .totals.skipped == 3
  and .lanes.cosmos_low_level.status == "skipped"
  and .lanes.phase_wrappers.status == "skipped"
  and .lanes.go_tests.status == "skipped"
' "$DRY_RUN_SUMMARY_JSON" >/dev/null; then
  echo "dry-run summary JSON missing expected skip fields"
  cat "$DRY_RUN_SUMMARY_JSON"
  exit 1
fi
if [[ -s "$CAPTURE" ]]; then
  echo "dry-run unexpectedly invoked lanes"
  cat "$CAPTURE"
  exit 1
fi

echo "[ci-blockchain-parallel-sweep] toggle path"
: >"$CAPTURE"
if ! run_sweep \
  --reports-dir "$TOGGLE_REPORTS_DIR" \
  --summary-json "$TOGGLE_SUMMARY_JSON" \
  --run-lane-go-tests 0 \
  --print-summary-json 0 >"$TOGGLE_LOG" 2>&1; then
  echo "expected toggle path to pass"
  cat "$TOGGLE_LOG"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .totals.enabled == 2
  and .totals.pass == 2
  and .totals.fail == 0
  and .totals.skipped == 1
  and .lanes.cosmos_low_level.enabled == true
  and .lanes.phase_wrappers.enabled == true
  and .lanes.go_tests.enabled == false
  and .lanes.go_tests.status == "skipped"
' "$TOGGLE_SUMMARY_JSON" >/dev/null; then
  echo "toggle summary JSON missing expected fields"
  cat "$TOGGLE_SUMMARY_JSON"
  exit 1
fi
assert_capture_lanes_exact "$CAPTURE" "cosmos_low_level" "phase_wrappers"

echo "[ci-blockchain-parallel-sweep] first-failure rc propagation"
: >"$CAPTURE"
if CI_BLOCKCHAIN_PARALLEL_SWEEP_FAIL_MATRIX="phase_wrappers=7" \
  run_sweep \
    --reports-dir "$FAIL_REPORTS_DIR" \
    --summary-json "$FAIL_SUMMARY_JSON" \
    --print-summary-json 0 >"$FAIL_LOG" 2>&1; then
  echo "expected failure path to return non-zero"
  cat "$FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 7
  and .first_failure.lane_id == "phase_wrappers"
  and .first_failure.rc == 7
  and .lanes.phase_wrappers.status == "fail"
  and .lanes.phase_wrappers.rc == 7
' "$FAIL_SUMMARY_JSON" >/dev/null; then
  echo "failure summary JSON missing expected failure fields"
  cat "$FAIL_SUMMARY_JSON"
  exit 1
fi
assert_capture_lanes_exact "$CAPTURE" "cosmos_low_level" "phase_wrappers" "go_tests"

cp "$ROOT_DIR/.easy-node-logs/ci_blockchain_parallel_sweep_summary.json" "$FAIL_CANONICAL_SUMMARY_JSON"
if ! cmp -s "$FAIL_SUMMARY_JSON" "$FAIL_CANONICAL_SUMMARY_JSON"; then
  echo "expected failure canonical summary to mirror summary-json output"
  exit 1
fi

echo "ci blockchain parallel sweep integration check ok"
