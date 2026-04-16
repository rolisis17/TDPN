#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp jq grep sed wc cat chmod cmp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

GATE_SCRIPT="$ROOT_DIR/scripts/blockchain_fastlane.sh"
if [[ ! -x "$GATE_SCRIPT" ]]; then
  echo "missing executable script under test: $GATE_SCRIPT"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/stage_calls.tsv"
SUCCESS_LOG="$TMP_DIR/success.log"
SOURCE_ENV_LOG="$TMP_DIR/source_env.log"
SOURCE_CLI_LOG="$TMP_DIR/source_cli.log"
SAME_PATH_LOG="$TMP_DIR/same_path.log"
DRY_RUN_LOG="$TMP_DIR/dry_run.log"
TOGGLE_LOG="$TMP_DIR/toggle.log"
PHASE7_INVALID_LOG="$TMP_DIR/phase7_invalid.log"
GATE_FAIL_LOG="$TMP_DIR/gate_fail.log"
FAIL_LOG="$TMP_DIR/fail.log"

SUCCESS_REPORTS_DIR="$TMP_DIR/reports_success"
SOURCE_ENV_REPORTS_DIR="$TMP_DIR/reports_source_env"
SOURCE_CLI_REPORTS_DIR="$TMP_DIR/reports_source_cli"
SAME_PATH_REPORTS_DIR="$TMP_DIR/reports_same_path"
DRY_RUN_REPORTS_DIR="$TMP_DIR/reports_dry_run"
TOGGLE_REPORTS_DIR="$TMP_DIR/reports_toggle"
PHASE7_INVALID_REPORTS_DIR="$TMP_DIR/reports_phase7_invalid"
GATE_FAIL_REPORTS_DIR="$TMP_DIR/reports_gate_fail"
FAIL_REPORTS_DIR="$TMP_DIR/reports_fail"

SUCCESS_SUMMARY_JSON="$TMP_DIR/summary_success.json"
SOURCE_ENV_SUMMARY_JSON="$TMP_DIR/summary_source_env.json"
SOURCE_CLI_SUMMARY_JSON="$TMP_DIR/summary_source_cli.json"
SAME_PATH_SUMMARY_JSON="$TMP_DIR/summary_same_path.json"
DRY_RUN_SUMMARY_JSON="$TMP_DIR/summary_dry_run.json"
TOGGLE_SUMMARY_JSON="$TMP_DIR/summary_toggle.json"
PHASE7_INVALID_SUMMARY_JSON="$TMP_DIR/summary_phase7_invalid.json"
GATE_FAIL_SUMMARY_JSON="$TMP_DIR/summary_gate_fail.json"
FAIL_SUMMARY_JSON="$TMP_DIR/summary_fail.json"
SUCCESS_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_success.json"
SOURCE_ENV_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_source_env.json"
SOURCE_CLI_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_source_cli.json"
DRY_RUN_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_dry_run.json"
TOGGLE_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_toggle.json"
PHASE7_INVALID_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_phase7_invalid.json"
GATE_FAIL_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_gate_fail.json"
FAIL_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_fail.json"
SUCCESS_METRICS_JSON="$SUCCESS_REPORTS_DIR/blockchain_mainnet_activation_metrics.json"
SUCCESS_GATE_SUMMARY_JSON="$SUCCESS_REPORTS_DIR/blockchain_mainnet_activation_gate_summary.json"
SAME_PATH_GATE_SUMMARY_JSON="$SAME_PATH_REPORTS_DIR/blockchain_mainnet_activation_gate_summary.json"
DEFAULT_SOURCE_JSON_PHASE5="$ROOT_DIR/.easy-node-logs/phase5_settlement_layer_handoff_check_summary.json"
ENV_SOURCE_JSON_A="$TMP_DIR/env_source_a.json"
ENV_SOURCE_JSON_B="$TMP_DIR/env_source_b.json"
CLI_SOURCE_JSON_A="$TMP_DIR/cli_source_a.json"
CLI_SOURCE_JSON_B="$TMP_DIR/cli_source_b.json"
PHASE7_SOURCE_JSON="$TMP_DIR/phase7_summary_source.json"
PHASE7_MISSING_JSON="$TMP_DIR/phase7_summary_missing.json"
PHASE7_INVALID_JSON="$TMP_DIR/phase7_summary_invalid.json"

STAGE_ENV_NAMES=(
  "BLOCKCHAIN_FASTLANE_CI_PHASE5_SETTLEMENT_LAYER_SCRIPT"
  "BLOCKCHAIN_FASTLANE_CI_PHASE6_COSMOS_L1_BUILD_TESTNET_SCRIPT"
  "BLOCKCHAIN_FASTLANE_CI_PHASE6_COSMOS_L1_CONTRACTS_SCRIPT"
  "BLOCKCHAIN_FASTLANE_CI_PHASE7_MAINNET_CUTOVER_SCRIPT"
  "BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_SCRIPT"
  "BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_GATE_SCRIPT"
)

STAGE_IDS=(
  "ci_phase5_settlement_layer"
  "ci_phase6_cosmos_l1_build_testnet"
  "ci_phase6_cosmos_l1_contracts"
  "ci_phase7_mainnet_cutover"
  "blockchain_mainnet_activation_metrics"
  "blockchain_mainnet_activation_gate"
)

STAGE_IDS_NO_METRICS=(
  "ci_phase5_settlement_layer"
  "ci_phase6_cosmos_l1_build_testnet"
  "ci_phase6_cosmos_l1_contracts"
  "ci_phase7_mainnet_cutover"
  "blockchain_mainnet_activation_gate"
)

TOGGLE_STAGE_IDS=(
  "ci_phase6_cosmos_l1_build_testnet"
  "ci_phase7_mainnet_cutover"
  "blockchain_mainnet_activation_metrics"
)

FAKE_STAGE_HELPER="$TMP_DIR/fake_stage_helper.sh"
cat >"$FAKE_STAGE_HELPER" <<'EOF_FAKE_STAGE_HELPER'
#!/usr/bin/env bash
set -euo pipefail

capture="${BLOCKCHAIN_FASTLANE_CAPTURE_FILE:?}"
stage_id="${BLOCKCHAIN_FASTLANE_STAGE_ID:?}"

{
  printf '%s' "$stage_id"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture"

fail_matrix="${BLOCKCHAIN_FASTLANE_FAIL_MATRIX:-}"
if [[ -n "$fail_matrix" ]]; then
  old_ifs="$IFS"
  IFS=',;'
  read -r -a fail_specs <<<"$fail_matrix"
  IFS="$old_ifs"
  for spec in "${fail_specs[@]}"; do
    case "$spec" in
      "$stage_id"=*)
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
EOF_FAKE_STAGE_HELPER
chmod +x "$FAKE_STAGE_HELPER"

for idx in "${!STAGE_ENV_NAMES[@]}"; do
  env_name="${STAGE_ENV_NAMES[$idx]}"
  stage_id="${STAGE_IDS[$idx]}"
  fake_stage="$TMP_DIR/fake_stage_${idx}.sh"
  cat >"$fake_stage" <<EOF_FAKE_STAGE
#!/usr/bin/env bash
set -euo pipefail
BLOCKCHAIN_FASTLANE_CAPTURE_FILE="\${BLOCKCHAIN_FASTLANE_CAPTURE_FILE:?}" \
BLOCKCHAIN_FASTLANE_STAGE_ID="$stage_id" \
BLOCKCHAIN_FASTLANE_FAIL_MATRIX="\${BLOCKCHAIN_FASTLANE_FAIL_MATRIX:-}" \
"$FAKE_STAGE_HELPER" "\$@"
EOF_FAKE_STAGE
  chmod +x "$fake_stage"
  export "$env_name=$fake_stage"
done

assert_stage_order() {
  local capture_file="$1"
  shift
  local expected_ids=("$@")
  local count idx line actual expected

  count="$(wc -l <"$capture_file" | tr -d ' ')"
  if [[ "$count" -ne "${#expected_ids[@]}" ]]; then
    echo "unexpected stage invocation count: expected ${#expected_ids[@]}, got $count"
    cat "$capture_file"
    exit 1
  fi

  for idx in "${!expected_ids[@]}"; do
    expected="${expected_ids[$idx]}"
    line="$(sed -n "$((idx + 1))p" "$capture_file" || true)"
    if [[ -z "$line" ]]; then
      echo "missing stage invocation at index $idx"
      cat "$capture_file"
      exit 1
    fi
    actual="${line%%$'\t'*}"
    if [[ "$actual" != "$expected" ]]; then
      echo "stage order mismatch at index $idx: expected $expected, got $actual"
      cat "$capture_file"
      exit 1
    fi
  done
}

assert_stage_invocation_contains() {
  local capture_file="$1"
  local stage_id="$2"
  shift 2
  local line needle

  line="$(awk -F $'\t' -v stage="$stage_id" '$1 == stage { print; exit }' "$capture_file")"
  if [[ -z "$line" ]]; then
    echo "missing stage invocation for $stage_id"
    cat "$capture_file"
    exit 1
  fi

  for needle in "$@"; do
    if [[ "$line" != *$'\t'"$needle"* ]]; then
      echo "stage invocation for $stage_id missing expected token: $needle"
      cat "$capture_file"
      exit 1
    fi
  done
}

assert_stage_invocation_not_contains() {
  local capture_file="$1"
  local stage_id="$2"
  shift 2
  local line needle

  line="$(awk -F $'\t' -v stage="$stage_id" '$1 == stage { print; exit }' "$capture_file")"
  if [[ -z "$line" ]]; then
    echo "missing stage invocation for $stage_id"
    cat "$capture_file"
    exit 1
  fi

  for needle in "$@"; do
    if [[ "$line" == *$'\t'"$needle"* ]]; then
      echo "stage invocation for $stage_id unexpectedly contains token: $needle"
      cat "$capture_file"
      exit 1
    fi
  done
}

assert_stage_invocation_token_count() {
  local capture_file="$1"
  local stage_id="$2"
  local token="$3"
  local expected_count="$4"
  local line actual_count

  line="$(awk -F $'\t' -v stage="$stage_id" '$1 == stage { print; exit }' "$capture_file")"
  if [[ -z "$line" ]]; then
    echo "missing stage invocation for $stage_id"
    cat "$capture_file"
    exit 1
  fi

  actual_count="$(awk -F $'\t' -v stage="$stage_id" -v token="$token" '
    $1 == stage {
      count = 0
      for (i = 2; i <= NF; i++) {
        if ($i == token) count++
      }
      print count
      exit
    }
  ' "$capture_file")"

  if [[ "$actual_count" != "$expected_count" ]]; then
    echo "stage invocation token count mismatch for $stage_id token=$token expected=$expected_count got=$actual_count"
    cat "$capture_file"
    exit 1
  fi
}

assert_capture_empty() {
  local capture_file="$1"
  if [[ -s "$capture_file" ]]; then
    echo "expected dry-run to skip all stage invocations"
    cat "$capture_file"
    exit 1
  fi
}

assert_canonical_summary_artifact() {
  local summary_json="$1"
  local canonical_json="$2"
  local log_file="$3"

  if [[ ! -f "$canonical_json" ]]; then
    echo "missing canonical summary json: $canonical_json"
    cat "$log_file"
    exit 1
  fi

  if ! jq -e --arg canonical "$canonical_json" '.artifacts.canonical_summary_json == $canonical' "$summary_json" >/dev/null; then
    echo "summary json missing canonical_summary_json artifact path"
    cat "$summary_json"
    exit 1
  fi

  if ! cmp -s "$summary_json" "$canonical_json"; then
    echo "canonical summary json does not match summary json"
    cat "$summary_json"
    cat "$canonical_json"
    exit 1
  fi

  if ! grep -Fq -- "[blockchain-fastlane] canonical_summary_json=$canonical_json" "$log_file"; then
    echo "log missing canonical summary path output"
    cat "$log_file"
    exit 1
  fi
}

cat >"$PHASE7_SOURCE_JSON" <<'EOF_PHASE7_SOURCE_JSON'
{
  "status": "pass",
  "signals": {
    "module_tx_surface_ok": true,
    "tdpnd_grpc_live_smoke_ok": true,
    "tdpnd_grpc_auth_live_smoke": false,
    "tdpnd_comet_runtime_smoke_ok": true,
    "cosmos_module_coverage_floor_ok": true,
    "cosmos_keeper_coverage_floor_ok": false,
    "cosmos_app_coverage_floor_ok": true,
    "dual_write_parity": false,
    "mainnet_activation_gate_go_ok": true
  }
}
EOF_PHASE7_SOURCE_JSON
cat >"$PHASE7_INVALID_JSON" <<'EOF_PHASE7_INVALID_JSON'
{
  "status":
EOF_PHASE7_INVALID_JSON

echo "[blockchain-fastlane] success ordering path"
: >"$CAPTURE"
BLOCKCHAIN_FASTLANE_CAPTURE_FILE="$CAPTURE" \
BLOCKCHAIN_FASTLANE_CANONICAL_SUMMARY_JSON="$SUCCESS_CANONICAL_SUMMARY_JSON" \
"$GATE_SCRIPT" \
  --reports-dir "$SUCCESS_REPORTS_DIR" \
  --summary-json "$SUCCESS_SUMMARY_JSON" \
  --run-blockchain-mainnet-activation-metrics 1 \
  --phase7-mainnet-cutover-summary-report-json "$PHASE7_SOURCE_JSON" \
  --print-summary-json 0 >"$SUCCESS_LOG" 2>&1

assert_stage_order "$CAPTURE" "${STAGE_IDS[@]}"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_gate" "--metrics-json" "$SUCCESS_METRICS_JSON"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_gate" "--summary-json" "$SUCCESS_GATE_SUMMARY_JSON"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_metrics" "--source-json" "$DEFAULT_SOURCE_JSON_PHASE5"

if [[ ! -f "$SUCCESS_SUMMARY_JSON" ]]; then
  echo "missing success summary json: $SUCCESS_SUMMARY_JSON"
  cat "$SUCCESS_LOG"
  exit 1
fi
if ! jq -e --arg gate_summary "$SUCCESS_GATE_SUMMARY_JSON" --arg default_source "$DEFAULT_SOURCE_JSON_PHASE5" --arg phase7_summary "$PHASE7_SOURCE_JSON" '
  .status == "pass"
  and .rc == 0
  and .schema.id == "blockchain_fastlane_summary"
  and .schema.major == 1
  and .schema.minor == 1
  and .inputs.dry_run == false
  and .inputs.run_ci_phase5_settlement_layer == true
  and .inputs.run_ci_phase6_cosmos_l1_build_testnet == true
  and .inputs.run_ci_phase6_cosmos_l1_contracts == true
  and .inputs.run_ci_phase7_mainnet_cutover == true
  and .inputs.run_blockchain_mainnet_activation_metrics == true
  and ((.inputs.blockchain_mainnet_activation_metrics_source_jsons | type) == "array")
  and ((.inputs.blockchain_mainnet_activation_metrics_source_jsons | length) > 0)
  and ((.inputs.blockchain_mainnet_activation_metrics_source_jsons | index($default_source)) != null)
  and .inputs.run_blockchain_mainnet_activation_gate == true
  and (.steps | to_entries | all(.value.enabled == true and .value.status == "pass" and .value.rc == 0 and .value.command != null))
  and .steps.blockchain_mainnet_activation_metrics.enabled == true
  and .steps.blockchain_mainnet_activation_metrics.status == "pass"
  and .steps.blockchain_mainnet_activation_metrics.rc == 0
  and .steps.blockchain_mainnet_activation_metrics.artifacts.source_jsons == .inputs.blockchain_mainnet_activation_metrics_source_jsons
  and .steps.blockchain_mainnet_activation_gate.enabled == true
  and .steps.blockchain_mainnet_activation_gate.status == "pass"
  and .steps.blockchain_mainnet_activation_gate.rc == 0
  and .artifacts.blockchain_mainnet_activation_metrics_source_jsons == .inputs.blockchain_mainnet_activation_metrics_source_jsons
  and .inputs.blockchain_mainnet_activation_gate_summary_json == $gate_summary
  and .artifacts.blockchain_mainnet_activation_gate_summary_json == $gate_summary
  and .steps.blockchain_mainnet_activation_gate.artifacts.summary_json == $gate_summary
  and .steps.blockchain_mainnet_activation_gate.artifacts.metrics_json == .artifacts.blockchain_mainnet_activation_metrics_json
  and .artifacts.blockchain_mainnet_activation_metrics_json != null
  and .inputs.phase7_mainnet_cutover_summary_report_json == $phase7_summary
  and .artifacts.phase7_mainnet_cutover_summary_report_json == $phase7_summary
  and .phase7_mainnet_cutover_summary_report.input_summary_json == $phase7_summary
  and .phase7_mainnet_cutover_summary_report.available == true
  and .phase7_mainnet_cutover_summary_report.status == "pass"
  and .phase7_mainnet_cutover_summary_report.signals.module_tx_surface_ok == true
  and .phase7_mainnet_cutover_summary_report.signals.tdpnd_grpc_live_smoke_ok == true
  and .phase7_mainnet_cutover_summary_report.signals.tdpnd_grpc_auth_live_smoke_ok == false
  and .phase7_mainnet_cutover_summary_report.signals.tdpnd_comet_runtime_smoke_ok == true
  and .phase7_mainnet_cutover_summary_report.signals.cosmos_module_coverage_floor_ok == true
  and .phase7_mainnet_cutover_summary_report.signals.cosmos_keeper_coverage_floor_ok == false
  and .phase7_mainnet_cutover_summary_report.signals.cosmos_app_coverage_floor_ok == true
  and .phase7_mainnet_cutover_summary_report.signals.dual_write_parity_ok == false
  and .phase7_mainnet_cutover_summary_report.signals.mainnet_activation_gate_go_ok == true
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.input_summary_json == $phase7_summary
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.available == true
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.status == "pass"
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.signals.tdpnd_grpc_auth_live_smoke_ok == false
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.signals.dual_write_parity_ok == false
' "$SUCCESS_SUMMARY_JSON" >/dev/null; then
  echo "success summary missing expected contract fields"
  cat "$SUCCESS_SUMMARY_JSON"
  exit 1
fi
if ! grep -Fq -- '[blockchain-fastlane] status=pass rc=0 dry_run=0' "$SUCCESS_LOG"; then
  echo "success log missing final pass status line"
  cat "$SUCCESS_LOG"
  exit 1
fi
assert_canonical_summary_artifact "$SUCCESS_SUMMARY_JSON" "$SUCCESS_CANONICAL_SUMMARY_JSON" "$SUCCESS_LOG"

cat >"$ENV_SOURCE_JSON_A" <<'EOF_ENV_SOURCE_JSON_A'
{"paying_users_3mo_min": 1001}
EOF_ENV_SOURCE_JSON_A
cat >"$ENV_SOURCE_JSON_B" <<'EOF_ENV_SOURCE_JSON_B'
{"subsidy_runway_months": 12}
EOF_ENV_SOURCE_JSON_B
cat >"$CLI_SOURCE_JSON_A" <<'EOF_CLI_SOURCE_JSON_A'
{"validator_candidate_depth": 30}
EOF_CLI_SOURCE_JSON_A
cat >"$CLI_SOURCE_JSON_B" <<'EOF_CLI_SOURCE_JSON_B'
{"validator_country_count": 8}
EOF_CLI_SOURCE_JSON_B

echo "[blockchain-fastlane] metrics source-json env-only ingestion"
: >"$CAPTURE"
BLOCKCHAIN_FASTLANE_CAPTURE_FILE="$CAPTURE" \
BLOCKCHAIN_FASTLANE_CANONICAL_SUMMARY_JSON="$SOURCE_ENV_CANONICAL_SUMMARY_JSON" \
BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_SOURCE_JSONS="$ENV_SOURCE_JSON_A,$ENV_SOURCE_JSON_B,$ENV_SOURCE_JSON_A" \
"$GATE_SCRIPT" \
  --reports-dir "$SOURCE_ENV_REPORTS_DIR" \
  --summary-json "$SOURCE_ENV_SUMMARY_JSON" \
  --run-blockchain-mainnet-activation-metrics 1 \
  --print-summary-json 0 >"$SOURCE_ENV_LOG" 2>&1

assert_stage_order "$CAPTURE" "${STAGE_IDS[@]}"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_metrics" "--source-json" "$ENV_SOURCE_JSON_A" "--source-json" "$ENV_SOURCE_JSON_B"
assert_stage_invocation_token_count "$CAPTURE" "blockchain_mainnet_activation_metrics" "--source-json" 2
assert_stage_invocation_not_contains "$CAPTURE" "blockchain_mainnet_activation_metrics" "$DEFAULT_SOURCE_JSON_PHASE5"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_gate" "--fail-close" "1"
assert_stage_invocation_token_count "$CAPTURE" "blockchain_mainnet_activation_gate" "--fail-close" 1

if [[ ! -f "$SOURCE_ENV_SUMMARY_JSON" ]]; then
  echo "missing source-env summary json: $SOURCE_ENV_SUMMARY_JSON"
  cat "$SOURCE_ENV_LOG"
  exit 1
fi
if ! jq -e --arg a "$ENV_SOURCE_JSON_A" --arg b "$ENV_SOURCE_JSON_B" --arg d "$DEFAULT_SOURCE_JSON_PHASE5" '
  .status == "pass"
  and .rc == 0
  and .inputs.blockchain_mainnet_activation_metrics_source_jsons == [$a, $b]
  and .artifacts.blockchain_mainnet_activation_metrics_source_jsons == [$a, $b]
  and .steps.blockchain_mainnet_activation_metrics.artifacts.source_jsons == [$a, $b]
  and ((.inputs.blockchain_mainnet_activation_metrics_source_jsons | index($d)) == null)
' "$SOURCE_ENV_SUMMARY_JSON" >/dev/null; then
  echo "source-env summary missing expected source-json ingestion contract"
  cat "$SOURCE_ENV_SUMMARY_JSON"
  exit 1
fi
assert_canonical_summary_artifact "$SOURCE_ENV_SUMMARY_JSON" "$SOURCE_ENV_CANONICAL_SUMMARY_JSON" "$SOURCE_ENV_LOG"

echo "[blockchain-fastlane] metrics source-json repeated cli forwarding"
: >"$CAPTURE"
BLOCKCHAIN_FASTLANE_CAPTURE_FILE="$CAPTURE" \
BLOCKCHAIN_FASTLANE_CANONICAL_SUMMARY_JSON="$SOURCE_CLI_CANONICAL_SUMMARY_JSON" \
BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_SOURCE_JSONS="" \
"$GATE_SCRIPT" \
  --reports-dir "$SOURCE_CLI_REPORTS_DIR" \
  --summary-json "$SOURCE_CLI_SUMMARY_JSON" \
  --run-blockchain-mainnet-activation-metrics 1 \
  --blockchain-mainnet-activation-metrics-source-json "$CLI_SOURCE_JSON_B" \
  --blockchain-mainnet-activation-metrics-source-json "$CLI_SOURCE_JSON_A" \
  --blockchain-mainnet-activation-metrics-source-json "$CLI_SOURCE_JSON_B" \
  --print-summary-json 0 >"$SOURCE_CLI_LOG" 2>&1

assert_stage_order "$CAPTURE" "${STAGE_IDS[@]}"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_metrics" "--source-json" "$CLI_SOURCE_JSON_B" "--source-json" "$CLI_SOURCE_JSON_A"
assert_stage_invocation_token_count "$CAPTURE" "blockchain_mainnet_activation_metrics" "--source-json" 2
assert_stage_invocation_not_contains "$CAPTURE" "blockchain_mainnet_activation_metrics" "$DEFAULT_SOURCE_JSON_PHASE5"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_gate" "--fail-close" "1"
assert_stage_invocation_token_count "$CAPTURE" "blockchain_mainnet_activation_gate" "--fail-close" 1

if [[ ! -f "$SOURCE_CLI_SUMMARY_JSON" ]]; then
  echo "missing source-cli summary json: $SOURCE_CLI_SUMMARY_JSON"
  cat "$SOURCE_CLI_LOG"
  exit 1
fi
if ! jq -e --arg a "$CLI_SOURCE_JSON_A" --arg b "$CLI_SOURCE_JSON_B" --arg d "$DEFAULT_SOURCE_JSON_PHASE5" '
  .status == "pass"
  and .rc == 0
  and .inputs.blockchain_mainnet_activation_metrics_source_jsons == [$b, $a]
  and .artifacts.blockchain_mainnet_activation_metrics_source_jsons == [$b, $a]
  and .steps.blockchain_mainnet_activation_metrics.artifacts.source_jsons == [$b, $a]
  and ((.inputs.blockchain_mainnet_activation_metrics_source_jsons | index($d)) == null)
' "$SOURCE_CLI_SUMMARY_JSON" >/dev/null; then
  echo "source-cli summary missing expected repeated forwarding + dedupe contract"
  cat "$SOURCE_CLI_SUMMARY_JSON"
  exit 1
fi
assert_canonical_summary_artifact "$SOURCE_CLI_SUMMARY_JSON" "$SOURCE_CLI_CANONICAL_SUMMARY_JSON" "$SOURCE_CLI_LOG"

echo "[blockchain-fastlane] canonical summary same-path"
: >"$CAPTURE"
BLOCKCHAIN_FASTLANE_CAPTURE_FILE="$CAPTURE" \
BLOCKCHAIN_FASTLANE_CANONICAL_SUMMARY_JSON="$SAME_PATH_SUMMARY_JSON" \
"$GATE_SCRIPT" \
  --reports-dir "$SAME_PATH_REPORTS_DIR" \
  --summary-json "$SAME_PATH_SUMMARY_JSON" \
  --phase7-mainnet-cutover-summary-report-json "$PHASE7_MISSING_JSON" \
  --print-summary-json 0 >"$SAME_PATH_LOG" 2>&1

assert_stage_order "$CAPTURE" "${STAGE_IDS_NO_METRICS[@]}"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_gate" "--summary-json" "$SAME_PATH_GATE_SUMMARY_JSON"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_gate" "--fail-close" "1"
assert_stage_invocation_token_count "$CAPTURE" "blockchain_mainnet_activation_gate" "--fail-close" 1

if [[ ! -f "$SAME_PATH_SUMMARY_JSON" ]]; then
  echo "missing same-path summary json: $SAME_PATH_SUMMARY_JSON"
  cat "$SAME_PATH_LOG"
  exit 1
fi
if ! jq -e --arg gate_summary "$SAME_PATH_GATE_SUMMARY_JSON" --arg phase7_missing "$PHASE7_MISSING_JSON" '
  .status == "pass"
  and .rc == 0
  and .inputs.run_blockchain_mainnet_activation_metrics == false
  and .steps.blockchain_mainnet_activation_metrics.enabled == false
  and .steps.blockchain_mainnet_activation_metrics.status == "skip"
  and .steps.blockchain_mainnet_activation_metrics.reason == "disabled"
  and .inputs.blockchain_mainnet_activation_gate_summary_json == $gate_summary
  and .artifacts.blockchain_mainnet_activation_gate_summary_json == $gate_summary
  and .steps.blockchain_mainnet_activation_gate.artifacts.summary_json == $gate_summary
  and .artifacts.summary_json == .artifacts.canonical_summary_json
  and .inputs.phase7_mainnet_cutover_summary_report_json == $phase7_missing
  and .artifacts.phase7_mainnet_cutover_summary_report_json == $phase7_missing
  and .phase7_mainnet_cutover_summary_report.input_summary_json == $phase7_missing
  and .phase7_mainnet_cutover_summary_report.available == false
  and .phase7_mainnet_cutover_summary_report.status == "missing"
  and .phase7_mainnet_cutover_summary_report.signals.module_tx_surface_ok == null
  and .phase7_mainnet_cutover_summary_report.signals.tdpnd_grpc_live_smoke_ok == null
  and .phase7_mainnet_cutover_summary_report.signals.tdpnd_grpc_auth_live_smoke_ok == null
  and .phase7_mainnet_cutover_summary_report.signals.tdpnd_comet_runtime_smoke_ok == null
  and .phase7_mainnet_cutover_summary_report.signals.cosmos_module_coverage_floor_ok == null
  and .phase7_mainnet_cutover_summary_report.signals.cosmos_keeper_coverage_floor_ok == null
  and .phase7_mainnet_cutover_summary_report.signals.cosmos_app_coverage_floor_ok == null
  and .phase7_mainnet_cutover_summary_report.signals.dual_write_parity_ok == null
  and .phase7_mainnet_cutover_summary_report.signals.mainnet_activation_gate_go_ok == null
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.input_summary_json == $phase7_missing
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.available == false
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.status == "missing"
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.signals.mainnet_activation_gate_go_ok == null
' "$SAME_PATH_SUMMARY_JSON" >/dev/null; then
  echo "same-path summary missing pass status or canonical artifact equality"
  cat "$SAME_PATH_SUMMARY_JSON"
  exit 1
fi
if ! grep -Fq -- '[blockchain-fastlane] status=pass rc=0 dry_run=0' "$SAME_PATH_LOG"; then
  echo "same-path log missing final pass status line"
  cat "$SAME_PATH_LOG"
  exit 1
fi
assert_canonical_summary_artifact "$SAME_PATH_SUMMARY_JSON" "$SAME_PATH_SUMMARY_JSON" "$SAME_PATH_LOG"

echo "[blockchain-fastlane] phase7 summary invalid artifact fail-soft"
: >"$CAPTURE"
BLOCKCHAIN_FASTLANE_CAPTURE_FILE="$CAPTURE" \
BLOCKCHAIN_FASTLANE_CANONICAL_SUMMARY_JSON="$PHASE7_INVALID_CANONICAL_SUMMARY_JSON" \
"$GATE_SCRIPT" \
  --reports-dir "$PHASE7_INVALID_REPORTS_DIR" \
  --summary-json "$PHASE7_INVALID_SUMMARY_JSON" \
  --phase7-mainnet-cutover-summary-report-json "$PHASE7_INVALID_JSON" \
  --print-summary-json 0 >"$PHASE7_INVALID_LOG" 2>&1

assert_stage_order "$CAPTURE" "${STAGE_IDS_NO_METRICS[@]}"

if [[ ! -f "$PHASE7_INVALID_SUMMARY_JSON" ]]; then
  echo "missing phase7-invalid summary json: $PHASE7_INVALID_SUMMARY_JSON"
  cat "$PHASE7_INVALID_LOG"
  exit 1
fi
if ! jq -e --arg phase7_invalid "$PHASE7_INVALID_JSON" '
  .status == "pass"
  and .rc == 0
  and .inputs.phase7_mainnet_cutover_summary_report_json == $phase7_invalid
  and .artifacts.phase7_mainnet_cutover_summary_report_json == $phase7_invalid
  and .phase7_mainnet_cutover_summary_report.input_summary_json == $phase7_invalid
  and .phase7_mainnet_cutover_summary_report.available == false
  and .phase7_mainnet_cutover_summary_report.status == "invalid"
  and .phase7_mainnet_cutover_summary_report.signals.module_tx_surface_ok == null
  and .phase7_mainnet_cutover_summary_report.signals.tdpnd_grpc_live_smoke_ok == null
  and .phase7_mainnet_cutover_summary_report.signals.tdpnd_grpc_auth_live_smoke_ok == null
  and .phase7_mainnet_cutover_summary_report.signals.tdpnd_comet_runtime_smoke_ok == null
  and .phase7_mainnet_cutover_summary_report.signals.cosmos_module_coverage_floor_ok == null
  and .phase7_mainnet_cutover_summary_report.signals.cosmos_keeper_coverage_floor_ok == null
  and .phase7_mainnet_cutover_summary_report.signals.cosmos_app_coverage_floor_ok == null
  and .phase7_mainnet_cutover_summary_report.signals.dual_write_parity_ok == null
  and .phase7_mainnet_cutover_summary_report.signals.mainnet_activation_gate_go_ok == null
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.status == "invalid"
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.available == false
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.signals.mainnet_activation_gate_go_ok == null
' "$PHASE7_INVALID_SUMMARY_JSON" >/dev/null; then
  echo "phase7-invalid summary missing expected fail-soft accounting"
  cat "$PHASE7_INVALID_SUMMARY_JSON"
  exit 1
fi
if ! grep -Fq -- '[blockchain-fastlane] status=pass rc=0 dry_run=0' "$PHASE7_INVALID_LOG"; then
  echo "phase7-invalid log missing final pass status line"
  cat "$PHASE7_INVALID_LOG"
  exit 1
fi
assert_canonical_summary_artifact "$PHASE7_INVALID_SUMMARY_JSON" "$PHASE7_INVALID_CANONICAL_SUMMARY_JSON" "$PHASE7_INVALID_LOG"

echo "[blockchain-fastlane] dry-run skip accounting"
: >"$CAPTURE"
BLOCKCHAIN_FASTLANE_CAPTURE_FILE="$CAPTURE" \
BLOCKCHAIN_FASTLANE_CANONICAL_SUMMARY_JSON="$DRY_RUN_CANONICAL_SUMMARY_JSON" \
"$GATE_SCRIPT" \
  --dry-run 1 \
  --run-blockchain-mainnet-activation-metrics 1 \
  --reports-dir "$DRY_RUN_REPORTS_DIR" \
  --summary-json "$DRY_RUN_SUMMARY_JSON" \
  --print-summary-json 0 >"$DRY_RUN_LOG" 2>&1

assert_capture_empty "$CAPTURE"

if [[ ! -f "$DRY_RUN_SUMMARY_JSON" ]]; then
  echo "missing dry-run summary json: $DRY_RUN_SUMMARY_JSON"
  cat "$DRY_RUN_LOG"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.dry_run == true
  and .inputs.run_blockchain_mainnet_activation_metrics == true
  and (.steps | to_entries | all(.value.enabled == true and .value.status == "skip" and .value.rc == 0 and .value.reason == "dry-run"))
  and .steps.blockchain_mainnet_activation_metrics.enabled == true
  and .steps.blockchain_mainnet_activation_metrics.status == "skip"
  and .steps.blockchain_mainnet_activation_metrics.reason == "dry-run"
  and .steps.blockchain_mainnet_activation_gate.enabled == true
  and .steps.blockchain_mainnet_activation_gate.status == "skip"
  and .steps.blockchain_mainnet_activation_gate.reason == "dry-run"
' "$DRY_RUN_SUMMARY_JSON" >/dev/null; then
  echo "dry-run summary missing expected skip accounting"
  cat "$DRY_RUN_SUMMARY_JSON"
  exit 1
fi
if ! grep -Fq -- '[blockchain-fastlane] status=pass rc=0 dry_run=1' "$DRY_RUN_LOG"; then
  echo "dry-run log missing final pass status line"
  cat "$DRY_RUN_LOG"
  exit 1
fi
if ! grep -Fq -- 'step=ci_phase5_settlement_layer status=skip reason=dry-run' "$DRY_RUN_LOG"; then
  echo "dry-run log missing phase5 skip signal"
  cat "$DRY_RUN_LOG"
  exit 1
fi
assert_canonical_summary_artifact "$DRY_RUN_SUMMARY_JSON" "$DRY_RUN_CANONICAL_SUMMARY_JSON" "$DRY_RUN_LOG"

echo "[blockchain-fastlane] toggle behavior"
: >"$CAPTURE"
BLOCKCHAIN_FASTLANE_CAPTURE_FILE="$CAPTURE" \
BLOCKCHAIN_FASTLANE_CANONICAL_SUMMARY_JSON="$TOGGLE_CANONICAL_SUMMARY_JSON" \
"$GATE_SCRIPT" \
  --reports-dir "$TOGGLE_REPORTS_DIR" \
  --summary-json "$TOGGLE_SUMMARY_JSON" \
  --print-summary-json 0 \
  --run-blockchain-mainnet-activation-metrics 1 \
  --run-ci-phase5-settlement-layer 0 \
  --run-ci-phase6-cosmos-l1-contracts 0 \
  --run-blockchain-mainnet-activation-gate 0 >"$TOGGLE_LOG" 2>&1

assert_stage_order "$CAPTURE" "${TOGGLE_STAGE_IDS[@]}"

if [[ ! -f "$TOGGLE_SUMMARY_JSON" ]]; then
  echo "missing toggle summary json: $TOGGLE_SUMMARY_JSON"
  cat "$TOGGLE_LOG"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.run_ci_phase5_settlement_layer == false
  and .steps.ci_phase5_settlement_layer.enabled == false
  and .steps.ci_phase5_settlement_layer.status == "skip"
  and .steps.ci_phase5_settlement_layer.reason == "disabled"
  and .inputs.run_ci_phase6_cosmos_l1_build_testnet == true
  and .steps.ci_phase6_cosmos_l1_build_testnet.enabled == true
  and .steps.ci_phase6_cosmos_l1_build_testnet.status == "pass"
  and .inputs.run_ci_phase6_cosmos_l1_contracts == false
  and .steps.ci_phase6_cosmos_l1_contracts.enabled == false
  and .steps.ci_phase6_cosmos_l1_contracts.status == "skip"
  and .steps.ci_phase6_cosmos_l1_contracts.reason == "disabled"
  and .inputs.run_ci_phase7_mainnet_cutover == true
  and .steps.ci_phase7_mainnet_cutover.enabled == true
  and .steps.ci_phase7_mainnet_cutover.status == "pass"
  and .inputs.run_blockchain_mainnet_activation_metrics == true
  and .steps.blockchain_mainnet_activation_metrics.enabled == true
  and .steps.blockchain_mainnet_activation_metrics.status == "pass"
  and .inputs.run_blockchain_mainnet_activation_gate == false
  and .steps.blockchain_mainnet_activation_gate.enabled == false
  and .steps.blockchain_mainnet_activation_gate.status == "skip"
  and .steps.blockchain_mainnet_activation_gate.reason == "disabled"
' "$TOGGLE_SUMMARY_JSON" >/dev/null; then
  echo "toggle summary missing expected disabled/enabled fields"
  cat "$TOGGLE_SUMMARY_JSON"
  exit 1
fi
assert_canonical_summary_artifact "$TOGGLE_SUMMARY_JSON" "$TOGGLE_CANONICAL_SUMMARY_JSON" "$TOGGLE_LOG"

# activation gate failure semantics: a failing gate should be reflected in the wrapper rc.
echo "[blockchain-fastlane] activation gate failure propagation"
: >"$CAPTURE"
set +e
BLOCKCHAIN_FASTLANE_CAPTURE_FILE="$CAPTURE" \
BLOCKCHAIN_FASTLANE_FAIL_MATRIX="blockchain_mainnet_activation_gate=61" \
BLOCKCHAIN_FASTLANE_CANONICAL_SUMMARY_JSON="$GATE_FAIL_CANONICAL_SUMMARY_JSON" \
"$GATE_SCRIPT" \
  --run-blockchain-mainnet-activation-metrics 1 \
  --reports-dir "$GATE_FAIL_REPORTS_DIR" \
  --summary-json "$GATE_FAIL_SUMMARY_JSON" \
  --print-summary-json 0 >"$GATE_FAIL_LOG" 2>&1
gate_fail_rc=$?
set -e

if [[ "$gate_fail_rc" -ne 61 ]]; then
  echo "expected activation gate fail rc=61, got rc=$gate_fail_rc"
  cat "$GATE_FAIL_LOG"
  exit 1
fi

assert_stage_order "$CAPTURE" "${STAGE_IDS[@]}"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_gate" "--fail-close" "1"
assert_stage_invocation_token_count "$CAPTURE" "blockchain_mainnet_activation_gate" "--fail-close" 1

if [[ ! -f "$GATE_FAIL_SUMMARY_JSON" ]]; then
  echo "missing gate-fail summary json: $GATE_FAIL_SUMMARY_JSON"
  cat "$GATE_FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 61
  and .inputs.run_blockchain_mainnet_activation_gate == true
  and .steps.blockchain_mainnet_activation_gate.status == "fail"
  and .steps.blockchain_mainnet_activation_gate.rc == 61
  and .steps.ci_phase5_settlement_layer.status == "pass"
  and .steps.ci_phase6_cosmos_l1_build_testnet.status == "pass"
  and .steps.ci_phase6_cosmos_l1_contracts.status == "pass"
  and .steps.ci_phase7_mainnet_cutover.status == "pass"
  and .steps.blockchain_mainnet_activation_metrics.status == "pass"
' "$GATE_FAIL_SUMMARY_JSON" >/dev/null; then
  echo "gate-fail summary missing expected activation-gate accounting"
  cat "$GATE_FAIL_SUMMARY_JSON"
  exit 1
fi
if ! grep -Fq -- '[blockchain-fastlane] status=fail rc=61 dry_run=0' "$GATE_FAIL_LOG"; then
  echo "gate-fail log missing final fail status line"
  cat "$GATE_FAIL_LOG"
  exit 1
fi
assert_canonical_summary_artifact "$GATE_FAIL_SUMMARY_JSON" "$GATE_FAIL_CANONICAL_SUMMARY_JSON" "$GATE_FAIL_LOG"

# failure propagation semantics: first failing stage rc becomes wrapper exit rc.
echo "[blockchain-fastlane] first-failure rc propagation"
: >"$CAPTURE"
set +e
BLOCKCHAIN_FASTLANE_CAPTURE_FILE="$CAPTURE" \
BLOCKCHAIN_FASTLANE_FAIL_MATRIX="ci_phase5_settlement_layer=19,ci_phase6_cosmos_l1_build_testnet=23,ci_phase6_cosmos_l1_contracts=41,ci_phase7_mainnet_cutover=53,blockchain_mainnet_activation_metrics=57,blockchain_mainnet_activation_gate=59" \
BLOCKCHAIN_FASTLANE_CANONICAL_SUMMARY_JSON="$FAIL_CANONICAL_SUMMARY_JSON" \
"$GATE_SCRIPT" \
  --run-blockchain-mainnet-activation-metrics 1 \
  --reports-dir "$FAIL_REPORTS_DIR" \
  --summary-json "$FAIL_SUMMARY_JSON" \
  --print-summary-json 0 >"$FAIL_LOG" 2>&1
fail_rc=$?
set -e

if [[ "$fail_rc" -ne 19 ]]; then
  echo "expected fail rc=19, got rc=$fail_rc"
  cat "$FAIL_LOG"
  exit 1
fi

assert_stage_order "$CAPTURE" "${STAGE_IDS[@]}"

if [[ ! -f "$FAIL_SUMMARY_JSON" ]]; then
  echo "missing fail summary json: $FAIL_SUMMARY_JSON"
  cat "$FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 19
  and .inputs.dry_run == false
  and .steps.ci_phase5_settlement_layer.status == "fail"
  and .steps.ci_phase5_settlement_layer.rc == 19
  and .steps.ci_phase6_cosmos_l1_build_testnet.status == "fail"
  and .steps.ci_phase6_cosmos_l1_build_testnet.rc == 23
  and .steps.ci_phase6_cosmos_l1_contracts.status == "fail"
  and .steps.ci_phase6_cosmos_l1_contracts.rc == 41
  and .steps.ci_phase7_mainnet_cutover.status == "fail"
  and .steps.ci_phase7_mainnet_cutover.rc == 53
  and .steps.blockchain_mainnet_activation_metrics.status == "fail"
  and .steps.blockchain_mainnet_activation_metrics.rc == 57
  and .steps.blockchain_mainnet_activation_gate.status == "fail"
  and .steps.blockchain_mainnet_activation_gate.rc == 59
' "$FAIL_SUMMARY_JSON" >/dev/null; then
  echo "fail summary missing expected first-failure accounting"
  cat "$FAIL_SUMMARY_JSON"
  exit 1
fi
if ! grep -Fq -- '[blockchain-fastlane] status=fail rc=19 dry_run=0' "$FAIL_LOG"; then
  echo "fail log missing final fail status line"
  cat "$FAIL_LOG"
  exit 1
fi
assert_canonical_summary_artifact "$FAIL_SUMMARY_JSON" "$FAIL_CANONICAL_SUMMARY_JSON" "$FAIL_LOG"

echo "blockchain fastlane integration check ok"
