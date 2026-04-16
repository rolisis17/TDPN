#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp chmod wc sed cat env rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${EASY_NODE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/easy_node.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.tsv"

create_fake_wrapper_script() {
  local target_script="$1"
  local marker="$2"

  cat >"$target_script" <<EOF_FAKE_WRAPPER
#!/usr/bin/env bash
set -euo pipefail
capture_file="\${EASY_NODE_BLOCKCHAIN_GATE_CAPTURE_FILE:?}"
{
  printf '%s' "$marker"
  for arg in "\$@"; do
    printf '\t%s' "\$arg"
  done
  printf '\n'
} >>"\$capture_file"
EOF_FAKE_WRAPPER
  chmod +x "$target_script"
}

assert_single_invocation() {
  local capture_file="$1"
  local command_name="$2"
  local count

  count="$(wc -l <"$capture_file")"
  count="${count//[[:space:]]/}"
  if [[ "$count" != "1" ]]; then
    echo "expected exactly one forwarded invocation for $command_name, got $count"
    cat "$capture_file"
    exit 1
  fi
}

assert_command_text_present() {
  local script_path="$1"
  local command_name="$2"

  if ! rg -Fq "$command_name" "$script_path" && ! grep -Fq "$command_name" "$script_path"; then
    echo "missing command text in easy_node wrapper script: $command_name"
    exit 1
  fi
}

assert_forwarded_args() {
  local capture_file="$1"
  local expected_marker="$2"
  local expected_reports_dir="$3"
  local expected_summary_json="$4"
  local expected_custom_flag="$5"
  local expected_custom_value="$6"
  local expect_seed_example_input="${7:-0}"
  local line
  local marker expected_columns
  local -a fields=()
  local idx=1

  line="$(sed -n '1p' "$capture_file" || true)"
  if [[ -z "$line" ]]; then
    echo "missing forwarded invocation payload"
    cat "$capture_file"
    exit 1
  fi

  IFS=$'\t' read -r -a fields <<<"$line"
  marker="${fields[0]:-}"

  if [[ "$marker" != "$expected_marker" ]]; then
    echo "forwarded marker mismatch: expected $expected_marker"
    echo "$line"
    exit 1
  fi

  expected_columns=9
  if [[ "$expect_seed_example_input" == "1" ]]; then
    expected_columns=11
  fi
  if [[ "${#fields[@]}" -ne "$expected_columns" ]]; then
    echo "unexpected forwarded arg count: expected $expected_columns got ${#fields[@]}"
    echo "$line"
    exit 1
  fi

  if [[ "$expect_seed_example_input" == "1" ]]; then
    if [[ "${fields[$idx]:-}" != "--seed-example-input" || "${fields[$((idx + 1))]:-}" != "1" ]]; then
      echo "missing seeded-cycle forwarded args"
      echo "$line"
      exit 1
    fi
    idx=$((idx + 2))
  fi

  if [[ "${fields[$idx]:-}" != "--reports-dir" || "${fields[$((idx + 1))]:-}" != "$expected_reports_dir" ]]; then
    echo "forwarded --reports-dir mismatch"
    echo "$line"
    exit 1
  fi
  idx=$((idx + 2))

  if [[ "${fields[$idx]:-}" != "--summary-json" || "${fields[$((idx + 1))]:-}" != "$expected_summary_json" ]]; then
    echo "forwarded --summary-json mismatch"
    echo "$line"
    exit 1
  fi
  idx=$((idx + 2))

  if [[ "${fields[$idx]:-}" != "--print-summary-json" || "${fields[$((idx + 1))]:-}" != "0" ]]; then
    echo "forwarded --print-summary-json mismatch"
    echo "$line"
    exit 1
  fi
  idx=$((idx + 2))

  if [[ "${fields[$idx]:-}" != "$expected_custom_flag" || "${fields[$((idx + 1))]:-}" != "$expected_custom_value" ]]; then
    echo "forwarded custom passthrough arg mismatch"
    echo "$line"
    exit 1
  fi
}

COMMANDS=(
  "blockchain-fastlane"
  "blockchain-gate-bundle"
  "ci-blockchain-parallel-sweep"
  "blockchain-mainnet-activation-metrics-input"
  "blockchain-mainnet-activation-metrics-missing-checklist"
  "blockchain-mainnet-activation-metrics-missing-input-template"
  "blockchain-mainnet-activation-metrics-input-template"
  "blockchain-mainnet-activation-metrics"
  "blockchain-mainnet-activation-gate"
  "blockchain-mainnet-activation-gate-cycle"
  "blockchain-mainnet-activation-gate-cycle-seeded"
  "blockchain-mainnet-activation-operator-pack"
  "blockchain-bootstrap-governance-graduation-gate"
  "ci-phase5-settlement-layer"
  "phase5-settlement-layer-check"
  "phase5-settlement-layer-run"
  "phase5-settlement-layer-handoff-check"
  "phase5-settlement-layer-handoff-run"
  "issuer-sponsor-api-live-smoke"
  "issuer-settlement-status-live-smoke"
  "ci-phase6-cosmos-l1-build-testnet"
  "ci-phase6-cosmos-l1-contracts"
  "phase6-cosmos-l1-build-testnet-check"
  "phase6-cosmos-l1-build-testnet-run"
  "phase6-cosmos-l1-build-testnet-handoff-check"
  "phase6-cosmos-l1-build-testnet-handoff-run"
  "phase6-cosmos-l1-build-testnet-suite"
  "ci-phase7-mainnet-cutover"
  "phase7-mainnet-cutover-check"
  "phase7-mainnet-cutover-run"
  "phase7-mainnet-cutover-handoff-check"
  "phase7-mainnet-cutover-handoff-run"
)

ENV_OVERRIDES=(
  "BLOCKCHAIN_FASTLANE_SCRIPT"
  "BLOCKCHAIN_GATE_BUNDLE_SCRIPT"
  "CI_BLOCKCHAIN_PARALLEL_SWEEP_SCRIPT"
  "BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_INPUT_SCRIPT"
  "BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_MISSING_CHECKLIST_SCRIPT"
  "BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_MISSING_INPUT_TEMPLATE_SCRIPT"
  "BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_INPUT_TEMPLATE_SCRIPT"
  "BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_SCRIPT"
  "BLOCKCHAIN_MAINNET_ACTIVATION_GATE_SCRIPT"
  "BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_SCRIPT"
  "BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_SCRIPT"
  "BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_SCRIPT"
  "BLOCKCHAIN_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SCRIPT"
  "CI_PHASE5_SETTLEMENT_LAYER_SCRIPT"
  "PHASE5_SETTLEMENT_LAYER_CHECK_SCRIPT"
  "PHASE5_SETTLEMENT_LAYER_RUN_SCRIPT"
  "PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_SCRIPT"
  "PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_SCRIPT"
  "ISSUER_SPONSOR_API_LIVE_SMOKE_SCRIPT"
  "ISSUER_SETTLEMENT_STATUS_LIVE_SMOKE_SCRIPT"
  "CI_PHASE6_COSMOS_L1_BUILD_TESTNET_SCRIPT"
  "CI_PHASE6_COSMOS_L1_CONTRACTS_SCRIPT"
  "PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_SCRIPT"
  "PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_SCRIPT"
  "PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_SCRIPT"
  "PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_RUN_SCRIPT"
  "PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_SCRIPT"
  "CI_PHASE7_MAINNET_CUTOVER_SCRIPT"
  "PHASE7_MAINNET_CUTOVER_CHECK_SCRIPT"
  "PHASE7_MAINNET_CUTOVER_RUN_SCRIPT"
  "PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_SCRIPT"
  "PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_SCRIPT"
)

for idx in "${!COMMANDS[@]}"; do
  command_name="${COMMANDS[$idx]}"
  env_name="${ENV_OVERRIDES[$idx]}"
  marker="blockchain_gate_wrapper_${idx}"
  fake_script="$TMP_DIR/${marker}.sh"
  reports_dir="$TMP_DIR/reports ${idx}"
  summary_json="$TMP_DIR/summary ${idx}.json"
  custom_flag="--sample-arg"
  custom_value="sample-value-${idx} ${command_name}"
  expect_seed_example_input=0
  if [[ "$command_name" == "blockchain-mainnet-activation-gate-cycle-seeded" ]]; then
    expect_seed_example_input=1
  fi

  assert_command_text_present "$SCRIPT_UNDER_TEST" "$command_name"
  create_fake_wrapper_script "$fake_script" "$marker"
  : >"$CAPTURE"

  env EASY_NODE_BLOCKCHAIN_GATE_CAPTURE_FILE="$CAPTURE" \
    "$env_name=$fake_script" \
    bash "$SCRIPT_UNDER_TEST" \
    "$command_name" \
    --reports-dir "$reports_dir" \
    --summary-json "$summary_json" \
    --print-summary-json 0 \
    "$custom_flag" "$custom_value" >/dev/null 2>&1

  assert_single_invocation "$CAPTURE" "$command_name"
  assert_forwarded_args \
    "$CAPTURE" \
    "$marker" \
    "$reports_dir" \
    "$summary_json" \
    "$custom_flag" \
    "$custom_value" \
    "$expect_seed_example_input"
done

echo "easy-node blockchain gate wrapper integration ok"
