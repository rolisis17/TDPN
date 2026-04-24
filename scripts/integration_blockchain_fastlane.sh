#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp jq grep sed wc cat chmod cmp date; do
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
ROOT_PHASE7_SUMMARY_REPORT_JSON="$ROOT_DIR/.easy-node-logs/phase7_mainnet_cutover_summary_report.json"
ROOT_PHASE7_SUMMARY_REPORT_BACKUP="$TMP_DIR/root_phase7_mainnet_cutover_summary_report.backup.json"
ROOT_PHASE7_SUMMARY_REPORT_PRESENT="0"

cleanup_root_phase7_summary_report() {
  if [[ "$ROOT_PHASE7_SUMMARY_REPORT_PRESENT" == "1" ]]; then
    cp "$ROOT_PHASE7_SUMMARY_REPORT_BACKUP" "$ROOT_PHASE7_SUMMARY_REPORT_JSON"
  else
    rm -f "$ROOT_PHASE7_SUMMARY_REPORT_JSON"
  fi
}

trap 'cleanup_root_phase7_summary_report; rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/stage_calls.tsv"
SUCCESS_LOG="$TMP_DIR/success.log"
SOURCE_ENV_LOG="$TMP_DIR/source_env.log"
SOURCE_CLI_LOG="$TMP_DIR/source_cli.log"
METRICS_INPUT_LOG="$TMP_DIR/metrics_input.log"
METRICS_INPUT_GATE_FALLBACK_LOG="$TMP_DIR/metrics_input_gate_fallback.log"
SAME_PATH_LOG="$TMP_DIR/same_path.log"
DRY_RUN_LOG="$TMP_DIR/dry_run.log"
TOGGLE_LOG="$TMP_DIR/toggle.log"
BOOTSTRAP_GATE_LOG="$TMP_DIR/bootstrap_gate.log"
PHASE7_ENV_LOG="$TMP_DIR/phase7_env.log"
PHASE7_INVALID_LOG="$TMP_DIR/phase7_invalid.log"
EXPLICIT_GATE_NO_METRICS_LOG="$TMP_DIR/explicit_gate_no_metrics.log"
ENV_GATE_NO_METRICS_LOG="$TMP_DIR/env_gate_no_metrics.log"
GATE_FAIL_LOG="$TMP_DIR/gate_fail.log"
FAIL_LOG="$TMP_DIR/fail.log"

SUCCESS_REPORTS_DIR="$TMP_DIR/reports_success"
SOURCE_ENV_REPORTS_DIR="$TMP_DIR/reports_source_env"
SOURCE_CLI_REPORTS_DIR="$TMP_DIR/reports_source_cli"
METRICS_INPUT_REPORTS_DIR="$TMP_DIR/reports_metrics_input"
METRICS_INPUT_GATE_FALLBACK_REPORTS_DIR="$TMP_DIR/reports_metrics_input_gate_fallback"
SAME_PATH_REPORTS_DIR="$TMP_DIR/reports_same_path"
DRY_RUN_REPORTS_DIR="$TMP_DIR/reports_dry_run"
TOGGLE_REPORTS_DIR="$TMP_DIR/reports_toggle"
BOOTSTRAP_GATE_REPORTS_DIR="$TMP_DIR/reports_bootstrap_gate"
PHASE7_ENV_REPORTS_DIR="$TMP_DIR/reports_phase7_env"
PHASE7_INVALID_REPORTS_DIR="$TMP_DIR/reports_phase7_invalid"
EXPLICIT_GATE_NO_METRICS_REPORTS_DIR="$TMP_DIR/reports_explicit_gate_no_metrics"
ENV_GATE_NO_METRICS_REPORTS_DIR="$TMP_DIR/reports_env_gate_no_metrics"
GATE_FAIL_REPORTS_DIR="$TMP_DIR/reports_gate_fail"
FAIL_REPORTS_DIR="$TMP_DIR/reports_fail"

SUCCESS_SUMMARY_JSON="$TMP_DIR/summary_success.json"
SOURCE_ENV_SUMMARY_JSON="$TMP_DIR/summary_source_env.json"
SOURCE_CLI_SUMMARY_JSON="$TMP_DIR/summary_source_cli.json"
METRICS_INPUT_SUMMARY_JSON="$TMP_DIR/summary_metrics_input.json"
METRICS_INPUT_GATE_FALLBACK_SUMMARY_JSON="$TMP_DIR/summary_metrics_input_gate_fallback.json"
SAME_PATH_SUMMARY_JSON="$TMP_DIR/summary_same_path.json"
DRY_RUN_SUMMARY_JSON="$TMP_DIR/summary_dry_run.json"
TOGGLE_SUMMARY_JSON="$TMP_DIR/summary_toggle.json"
BOOTSTRAP_GATE_SUMMARY_JSON="$TMP_DIR/summary_bootstrap_gate.json"
PHASE7_ENV_SUMMARY_JSON="$TMP_DIR/summary_phase7_env.json"
PHASE7_INVALID_SUMMARY_JSON="$TMP_DIR/summary_phase7_invalid.json"
EXPLICIT_GATE_NO_METRICS_SUMMARY_JSON="$TMP_DIR/summary_explicit_gate_no_metrics.json"
ENV_GATE_NO_METRICS_SUMMARY_JSON="$TMP_DIR/summary_env_gate_no_metrics.json"
GATE_FAIL_SUMMARY_JSON="$TMP_DIR/summary_gate_fail.json"
FAIL_SUMMARY_JSON="$TMP_DIR/summary_fail.json"
SUCCESS_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_success.json"
SOURCE_ENV_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_source_env.json"
SOURCE_CLI_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_source_cli.json"
METRICS_INPUT_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_metrics_input.json"
METRICS_INPUT_GATE_FALLBACK_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_metrics_input_gate_fallback.json"
DRY_RUN_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_dry_run.json"
TOGGLE_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_toggle.json"
BOOTSTRAP_GATE_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_bootstrap_gate.json"
PHASE7_ENV_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_phase7_env.json"
PHASE7_INVALID_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_phase7_invalid.json"
EXPLICIT_GATE_NO_METRICS_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_explicit_gate_no_metrics.json"
ENV_GATE_NO_METRICS_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_env_gate_no_metrics.json"
GATE_FAIL_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_gate_fail.json"
FAIL_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_fail.json"
SUCCESS_METRICS_JSON="$SUCCESS_REPORTS_DIR/blockchain_mainnet_activation_metrics.json"
SUCCESS_METRICS_SUMMARY_JSON="$SUCCESS_REPORTS_DIR/blockchain_mainnet_activation_metrics_summary.json"
SUCCESS_OPERATOR_PACK_REPORTS_DIR="$SUCCESS_REPORTS_DIR/blockchain_mainnet_activation_operator_pack"
SUCCESS_OPERATOR_PACK_SUMMARY_JSON="$TMP_DIR/success_operator_pack_summary.json"
SUCCESS_OPERATOR_PACK_CANONICAL_SUMMARY_JSON="$SUCCESS_REPORTS_DIR/blockchain_mainnet_activation_operator_pack_summary.json"
SUCCESS_GATE_SUMMARY_JSON="$SUCCESS_REPORTS_DIR/blockchain_mainnet_activation_gate_summary.json"
SUCCESS_BOOTSTRAP_GRADUATION_GATE_SUMMARY_JSON="$SUCCESS_REPORTS_DIR/blockchain_bootstrap_governance_graduation_gate_summary.json"
BOOTSTRAP_GATE_METRICS_JSON="$BOOTSTRAP_GATE_REPORTS_DIR/blockchain_mainnet_activation_metrics.json"
BOOTSTRAP_GATE_METRICS_SUMMARY_JSON="$BOOTSTRAP_GATE_REPORTS_DIR/blockchain_mainnet_activation_metrics_summary.json"
BOOTSTRAP_GATE_SUMMARY_PATH="$BOOTSTRAP_GATE_REPORTS_DIR/blockchain_bootstrap_governance_graduation_gate_summary.json"
BOOTSTRAP_GATE_ACTIVATION_SUMMARY_PATH="$BOOTSTRAP_GATE_REPORTS_DIR/blockchain_mainnet_activation_gate_summary.json"
TOGGLE_OPERATOR_PACK_REPORTS_DIR="$TOGGLE_REPORTS_DIR/blockchain_mainnet_activation_operator_pack"
TOGGLE_OPERATOR_PACK_SUMMARY_JSON="$TOGGLE_REPORTS_DIR/blockchain_mainnet_activation_operator_pack_summary.json"
TOGGLE_BOOTSTRAP_GATE_SUMMARY_PATH="$TOGGLE_REPORTS_DIR/blockchain_bootstrap_governance_graduation_gate_summary.json"
SAME_PATH_GATE_SUMMARY_JSON="$SAME_PATH_REPORTS_DIR/blockchain_mainnet_activation_gate_summary.json"
DEFAULT_SOURCE_JSON_PHASE5="$ROOT_DIR/.easy-node-logs/phase5_settlement_layer_handoff_check_summary.json"
ENV_SOURCE_JSON_A="$TMP_DIR/env_source_a.json"
ENV_SOURCE_JSON_B="$TMP_DIR/env_source_b.json"
CLI_SOURCE_JSON_A="$TMP_DIR/cli_source_a.json"
CLI_SOURCE_JSON_B="$TMP_DIR/cli_source_b.json"
METRICS_INPUT_JSON="$TMP_DIR/metrics_input.json"
METRICS_INPUT_NORMALIZED_SUMMARY_JSON="$METRICS_INPUT_REPORTS_DIR/blockchain_mainnet_activation_metrics_input_summary.json"
METRICS_INPUT_NORMALIZED_CANONICAL_JSON="$METRICS_INPUT_REPORTS_DIR/blockchain_mainnet_activation_metrics_input.json"
METRICS_INPUT_GATE_FALLBACK_NORMALIZED_SUMMARY_JSON="$METRICS_INPUT_GATE_FALLBACK_REPORTS_DIR/blockchain_mainnet_activation_metrics_input_summary.json"
METRICS_INPUT_GATE_FALLBACK_NORMALIZED_CANONICAL_JSON="$METRICS_INPUT_GATE_FALLBACK_REPORTS_DIR/blockchain_mainnet_activation_metrics_input.json"
METRICS_INPUT_GATE_FALLBACK_GATE_SUMMARY_JSON="$METRICS_INPUT_GATE_FALLBACK_REPORTS_DIR/blockchain_mainnet_activation_gate_summary.json"
EXPLICIT_GATE_NO_METRICS_GATE_SUMMARY_JSON="$EXPLICIT_GATE_NO_METRICS_REPORTS_DIR/blockchain_mainnet_activation_gate_summary.json"
PHASE7_SOURCE_JSON="$TMP_DIR/phase7_summary_source.json"
PHASE7_MISSING_JSON="$TMP_DIR/phase7_summary_missing.json"
PHASE7_INVALID_JSON="$TMP_DIR/phase7_summary_invalid.json"
PHASE7_ENV_OVERRIDE_JSON="$TMP_DIR/phase7_summary_env_override.json"
DEFAULT_PHASE7_REPORTS_DIR="$TMP_DIR/reports_phase7_default"
DEFAULT_PHASE7_REPORT_JSON="$DEFAULT_PHASE7_REPORTS_DIR/phase7_mainnet_cutover_summary_report.json"
DEFAULT_PHASE7_SUMMARY_JSON="$TMP_DIR/summary_phase7_default.json"

STAGE_ENV_NAMES=(
  "BLOCKCHAIN_FASTLANE_CI_PHASE5_SETTLEMENT_LAYER_SCRIPT"
  "BLOCKCHAIN_FASTLANE_CI_PHASE6_COSMOS_L1_BUILD_TESTNET_SCRIPT"
  "BLOCKCHAIN_FASTLANE_CI_PHASE6_COSMOS_L1_CONTRACTS_SCRIPT"
  "BLOCKCHAIN_FASTLANE_INTEGRATION_SLASH_VIOLATION_TYPE_CONTRACT_CONSISTENCY_SCRIPT"
  "BLOCKCHAIN_FASTLANE_INTEGRATION_COSMOS_RECORD_NORMALIZATION_CONTRACT_CONSISTENCY_SCRIPT"
  "BLOCKCHAIN_FASTLANE_INTEGRATION_BLOCKCHAIN_COSMOS_ONLY_GUARDRAIL_SCRIPT"
  "BLOCKCHAIN_FASTLANE_CI_PHASE7_MAINNET_CUTOVER_SCRIPT"
  "BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_SCRIPT"
  "BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_SCRIPT"
  "BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_GATE_SCRIPT"
  "BLOCKCHAIN_FASTLANE_BLOCKCHAIN_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SCRIPT"
)

STAGE_IDS_ALL=(
  "ci_phase5_settlement_layer"
  "ci_phase6_cosmos_l1_build_testnet"
  "ci_phase6_cosmos_l1_contracts"
  "integration_slash_violation_type_contract_consistency"
  "integration_cosmos_record_normalization_contract_consistency"
  "integration_blockchain_cosmos_only_guardrail"
  "ci_phase7_mainnet_cutover"
  "blockchain_mainnet_activation_metrics"
  "blockchain_mainnet_activation_operator_pack"
  "blockchain_mainnet_activation_gate"
  "blockchain_bootstrap_governance_graduation_gate"
)

STAGE_IDS=(
  "ci_phase5_settlement_layer"
  "ci_phase6_cosmos_l1_build_testnet"
  "ci_phase6_cosmos_l1_contracts"
  "integration_slash_violation_type_contract_consistency"
  "integration_cosmos_record_normalization_contract_consistency"
  "integration_blockchain_cosmos_only_guardrail"
  "ci_phase7_mainnet_cutover"
  "blockchain_mainnet_activation_metrics"
  "blockchain_mainnet_activation_gate"
)

STAGE_IDS_WITH_OPERATOR_PACK=(
  "ci_phase5_settlement_layer"
  "ci_phase6_cosmos_l1_build_testnet"
  "ci_phase6_cosmos_l1_contracts"
  "integration_slash_violation_type_contract_consistency"
  "integration_cosmos_record_normalization_contract_consistency"
  "integration_blockchain_cosmos_only_guardrail"
  "ci_phase7_mainnet_cutover"
  "blockchain_mainnet_activation_metrics"
  "blockchain_mainnet_activation_operator_pack"
  "blockchain_mainnet_activation_gate"
)

STAGE_IDS_NO_METRICS=(
  "ci_phase5_settlement_layer"
  "ci_phase6_cosmos_l1_build_testnet"
  "ci_phase6_cosmos_l1_contracts"
  "integration_slash_violation_type_contract_consistency"
  "integration_cosmos_record_normalization_contract_consistency"
  "integration_blockchain_cosmos_only_guardrail"
  "ci_phase7_mainnet_cutover"
)

STAGE_IDS_NO_METRICS_WITH_OPERATOR_PACK=(
  "ci_phase5_settlement_layer"
  "ci_phase6_cosmos_l1_build_testnet"
  "ci_phase6_cosmos_l1_contracts"
  "integration_slash_violation_type_contract_consistency"
  "integration_cosmos_record_normalization_contract_consistency"
  "integration_blockchain_cosmos_only_guardrail"
  "ci_phase7_mainnet_cutover"
  "blockchain_mainnet_activation_operator_pack"
)

STAGE_IDS_NO_METRICS_WITH_GATE=(
  "ci_phase5_settlement_layer"
  "ci_phase6_cosmos_l1_build_testnet"
  "ci_phase6_cosmos_l1_contracts"
  "integration_slash_violation_type_contract_consistency"
  "integration_cosmos_record_normalization_contract_consistency"
  "integration_blockchain_cosmos_only_guardrail"
  "ci_phase7_mainnet_cutover"
  "blockchain_mainnet_activation_gate"
)

TOGGLE_STAGE_IDS=(
  "ci_phase6_cosmos_l1_build_testnet"
  "integration_slash_violation_type_contract_consistency"
  "integration_cosmos_record_normalization_contract_consistency"
  "integration_blockchain_cosmos_only_guardrail"
  "ci_phase7_mainnet_cutover"
  "blockchain_mainnet_activation_metrics"
  "blockchain_mainnet_activation_operator_pack"
  "blockchain_bootstrap_governance_graduation_gate"
)

STAGE_IDS_WITH_BOOTSTRAP=(
  "ci_phase5_settlement_layer"
  "ci_phase6_cosmos_l1_build_testnet"
  "ci_phase6_cosmos_l1_contracts"
  "integration_slash_violation_type_contract_consistency"
  "integration_cosmos_record_normalization_contract_consistency"
  "integration_blockchain_cosmos_only_guardrail"
  "ci_phase7_mainnet_cutover"
  "blockchain_mainnet_activation_metrics"
  "blockchain_mainnet_activation_gate"
  "blockchain_bootstrap_governance_graduation_gate"
)

FAKE_STAGE_HELPER="$TMP_DIR/fake_stage_helper.sh"
cat >"$FAKE_STAGE_HELPER" <<'EOF_FAKE_STAGE_HELPER'
#!/usr/bin/env bash
set -euo pipefail

capture="${BLOCKCHAIN_FASTLANE_CAPTURE_FILE:?}"
stage_id="${BLOCKCHAIN_FASTLANE_STAGE_ID:?}"
summary_json=""
all_args=("$@")

{
  printf '%s' "$stage_id"
  for arg in "${all_args[@]}"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture"

idx=0
while [[ "$idx" -lt "${#all_args[@]}" ]]; do
  arg="${all_args[$idx]}"
  if [[ "$arg" == "--summary-json" ]]; then
    next_idx=$((idx + 1))
    if [[ "$next_idx" -lt "${#all_args[@]}" ]]; then
      summary_json="${all_args[$next_idx]}"
    fi
    idx=$((idx + 2))
    continue
  fi
  idx=$((idx + 1))
done

if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  jq -n \
    --arg stage_id "$stage_id" \
    --arg generated_at "$generated_at" \
    '{
      schema: {
        id: ("fake_" + $stage_id + "_summary"),
        major: 1,
        minor: 0
      },
      generated_at: $generated_at,
      status: "pass",
      rc: 0
    }' >"$summary_json"
fi

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

if [[ -f "$ROOT_PHASE7_SUMMARY_REPORT_JSON" ]]; then
  cp "$ROOT_PHASE7_SUMMARY_REPORT_JSON" "$ROOT_PHASE7_SUMMARY_REPORT_BACKUP"
  ROOT_PHASE7_SUMMARY_REPORT_PRESENT="1"
fi

for idx in "${!STAGE_ENV_NAMES[@]}"; do
  env_name="${STAGE_ENV_NAMES[$idx]}"
  stage_id="${STAGE_IDS_ALL[$idx]}"
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

assert_generated_at_iso_utc() {
  local summary_json="$1"
  local label="$2"

  if [[ ! -f "$summary_json" ]]; then
    echo "missing ${label} summary artifact: $summary_json"
    exit 1
  fi

  if ! jq -e '
    (.generated_at | type) == "string"
    and (.generated_at | length) > 0
    and (.generated_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
  ' "$summary_json" >/dev/null; then
    echo "${label} summary artifact missing ISO UTC generated_at"
    cat "$summary_json"
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
    "mainnet_activation_gate_go_ok": true,
    "bootstrap_governance_graduation_gate_go_ok": true
  }
}
EOF_PHASE7_SOURCE_JSON
cat >"$PHASE7_INVALID_JSON" <<'EOF_PHASE7_INVALID_JSON'
{
  "status":
EOF_PHASE7_INVALID_JSON

mkdir -p "$DEFAULT_PHASE7_REPORTS_DIR" "$(dirname "$ROOT_PHASE7_SUMMARY_REPORT_JSON")"
cat >"$DEFAULT_PHASE7_SUMMARY_JSON" <<'EOF_DEFAULT_PHASE7_SUMMARY'
{
  "status": "pass",
  "signals": {
    "module_tx_surface_ok": true,
    "tdpnd_grpc_live_smoke_ok": true,
    "tdpnd_grpc_auth_live_smoke_ok": false,
    "tdpnd_comet_runtime_smoke_ok": true,
    "cosmos_module_coverage_floor_ok": true,
    "cosmos_keeper_coverage_floor_ok": true,
    "cosmos_app_coverage_floor_ok": true,
    "dual_write_parity_ok": false,
    "mainnet_activation_gate_go_ok": true,
    "bootstrap_governance_graduation_gate_go_ok": true
  }
}
EOF_DEFAULT_PHASE7_SUMMARY

cat >"$DEFAULT_PHASE7_REPORT_JSON" <<'EOF_DEFAULT_PHASE7_REPORT'
{
  "status": "pass",
  "signals": {
    "module_tx_surface_ok": true,
    "tdpnd_grpc_live_smoke_ok": true,
    "tdpnd_grpc_auth_live_smoke_ok": false,
    "tdpnd_comet_runtime_smoke_ok": true,
    "cosmos_module_coverage_floor_ok": true,
    "cosmos_keeper_coverage_floor_ok": true,
    "cosmos_app_coverage_floor_ok": true,
    "dual_write_parity_ok": false,
    "mainnet_activation_gate_go_ok": true,
    "bootstrap_governance_graduation_gate_go_ok": true
  }
}
EOF_DEFAULT_PHASE7_REPORT

cat >"$ROOT_PHASE7_SUMMARY_REPORT_JSON" <<'EOF_ROOT_PHASE7_SUMMARY'
{
  "status": "pass",
  "signals": {
    "module_tx_surface_ok": false,
    "tdpnd_grpc_live_smoke_ok": false,
    "tdpnd_grpc_auth_live_smoke_ok": true,
    "tdpnd_comet_runtime_smoke_ok": false,
    "cosmos_module_coverage_floor_ok": false,
    "cosmos_keeper_coverage_floor_ok": false,
    "cosmos_app_coverage_floor_ok": false,
    "dual_write_parity_ok": true,
    "mainnet_activation_gate_go_ok": false,
    "bootstrap_governance_graduation_gate_go_ok": false
  }
}
EOF_ROOT_PHASE7_SUMMARY

echo "[blockchain-fastlane] success ordering path"
: >"$CAPTURE"
BLOCKCHAIN_FASTLANE_CAPTURE_FILE="$CAPTURE" \
BLOCKCHAIN_FASTLANE_CANONICAL_SUMMARY_JSON="$SUCCESS_CANONICAL_SUMMARY_JSON" \
BLOCKCHAIN_FASTLANE_PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_JSON="$PHASE7_ENV_OVERRIDE_JSON" \
"$GATE_SCRIPT" \
  --reports-dir "$SUCCESS_REPORTS_DIR" \
  --summary-json "$SUCCESS_SUMMARY_JSON" \
  --run-blockchain-mainnet-activation-metrics 1 \
  --run-blockchain-mainnet-activation-operator-pack 1 \
  --blockchain-mainnet-activation-operator-pack-summary-json "$SUCCESS_OPERATOR_PACK_SUMMARY_JSON" \
  --phase7-mainnet-cutover-summary-report-json "$PHASE7_SOURCE_JSON" \
  --print-summary-json 0 >"$SUCCESS_LOG" 2>&1

assert_stage_order "$CAPTURE" "${STAGE_IDS_WITH_OPERATOR_PACK[@]}"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_gate" "--metrics-json" "$SUCCESS_METRICS_JSON"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_gate" "--summary-json" "$SUCCESS_GATE_SUMMARY_JSON"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_metrics" "--summary-json" "$SUCCESS_METRICS_SUMMARY_JSON"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_metrics" "--canonical-metrics-json" "$SUCCESS_METRICS_JSON"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_metrics" "--source-json" "$DEFAULT_SOURCE_JSON_PHASE5"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_operator_pack" "--reports-dir" "$SUCCESS_OPERATOR_PACK_REPORTS_DIR"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_operator_pack" "--summary-json" "$SUCCESS_OPERATOR_PACK_SUMMARY_JSON"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_operator_pack" "--canonical-summary-json" "$SUCCESS_OPERATOR_PACK_CANONICAL_SUMMARY_JSON"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_operator_pack" "--metrics-summary-json" "$SUCCESS_METRICS_SUMMARY_JSON"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_operator_pack" "--print-summary-json" "0"

if [[ ! -f "$SUCCESS_SUMMARY_JSON" ]]; then
  echo "missing success summary json: $SUCCESS_SUMMARY_JSON"
  cat "$SUCCESS_LOG"
  exit 1
fi
if ! jq -e --arg gate_summary "$SUCCESS_GATE_SUMMARY_JSON" --arg operator_pack_summary "$SUCCESS_OPERATOR_PACK_SUMMARY_JSON" --arg operator_pack_canonical_summary "$SUCCESS_OPERATOR_PACK_CANONICAL_SUMMARY_JSON" --arg operator_pack_reports_dir "$SUCCESS_OPERATOR_PACK_REPORTS_DIR" --arg default_source "$DEFAULT_SOURCE_JSON_PHASE5" --arg phase7_summary "$PHASE7_SOURCE_JSON" --arg phase7_env_override "$PHASE7_ENV_OVERRIDE_JSON" '
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
  and .inputs.run_blockchain_mainnet_activation_operator_pack == true
  and ((.inputs.blockchain_mainnet_activation_metrics_source_jsons | type) == "array")
  and ((.inputs.blockchain_mainnet_activation_metrics_source_jsons | length) > 0)
  and ((.inputs.blockchain_mainnet_activation_metrics_source_jsons | index($default_source)) != null)
  and .inputs.blockchain_mainnet_activation_operator_pack_summary_json == $operator_pack_summary
  and .inputs.blockchain_mainnet_activation_operator_pack_canonical_summary_json == $operator_pack_canonical_summary
  and .inputs.run_blockchain_mainnet_activation_gate == true
  and .inputs.run_blockchain_bootstrap_governance_graduation_gate == false
  and (.steps | to_entries | all(
      if .value.enabled
      then (.value.status == "pass" and .value.rc == 0 and .value.command != null)
      else (.value.status == "skip" and .value.reason == "disabled")
      end
    ))
  and .steps.blockchain_mainnet_activation_metrics.enabled == true
  and .steps.blockchain_mainnet_activation_metrics.status == "pass"
  and .steps.blockchain_mainnet_activation_metrics.rc == 0
  and .steps.blockchain_mainnet_activation_metrics.artifacts.source_jsons == .inputs.blockchain_mainnet_activation_metrics_source_jsons
  and .steps.blockchain_mainnet_activation_operator_pack.enabled == true
  and .steps.blockchain_mainnet_activation_operator_pack.status == "pass"
  and .steps.blockchain_mainnet_activation_operator_pack.rc == 0
  and .steps.blockchain_mainnet_activation_operator_pack.artifacts.reports_dir == $operator_pack_reports_dir
  and .steps.blockchain_mainnet_activation_operator_pack.artifacts.summary_json == $operator_pack_summary
  and .steps.blockchain_mainnet_activation_operator_pack.artifacts.canonical_summary_json == $operator_pack_canonical_summary
  and .steps.blockchain_mainnet_activation_operator_pack.artifacts.metrics_summary_json == .artifacts.blockchain_mainnet_activation_metrics_summary_json
  and .steps.blockchain_mainnet_activation_gate.enabled == true
  and .steps.blockchain_mainnet_activation_gate.status == "pass"
  and .steps.blockchain_mainnet_activation_gate.rc == 0
  and .steps.blockchain_bootstrap_governance_graduation_gate.enabled == false
  and .steps.blockchain_bootstrap_governance_graduation_gate.status == "skip"
  and .steps.blockchain_bootstrap_governance_graduation_gate.reason == "disabled"
  and .artifacts.blockchain_mainnet_activation_metrics_source_jsons == .inputs.blockchain_mainnet_activation_metrics_source_jsons
  and .artifacts.blockchain_mainnet_activation_operator_pack_summary_json == $operator_pack_summary
  and .artifacts.blockchain_mainnet_activation_operator_pack_canonical_summary_json == $operator_pack_canonical_summary
  and .inputs.blockchain_mainnet_activation_gate_summary_json == $gate_summary
  and .artifacts.blockchain_mainnet_activation_gate_summary_json == $gate_summary
  and .steps.blockchain_mainnet_activation_gate.artifacts.summary_json == $gate_summary
  and .steps.blockchain_mainnet_activation_gate.artifacts.metrics_json == .artifacts.blockchain_mainnet_activation_metrics_json
  and .artifacts.blockchain_mainnet_activation_metrics_json != null
  and .inputs.phase7_mainnet_cutover_summary_report_json == $phase7_summary
  and .inputs.phase7_mainnet_cutover_summary_report_json != $phase7_env_override
  and .artifacts.phase7_mainnet_cutover_summary_report_json == $phase7_summary
  and .artifacts.phase7_mainnet_cutover_summary_report_json != $phase7_env_override
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
  and .phase7_mainnet_cutover_summary_report.signals.bootstrap_governance_graduation_gate_go_ok == true
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.input_summary_json == $phase7_summary
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.available == true
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.status == "pass"
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.signals.tdpnd_grpc_auth_live_smoke_ok == false
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.signals.dual_write_parity_ok == false
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.signals.bootstrap_governance_graduation_gate_go_ok == true
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
assert_generated_at_iso_utc "$SUCCESS_GATE_SUMMARY_JSON" "mainnet activation gate"
assert_canonical_summary_artifact "$SUCCESS_SUMMARY_JSON" "$SUCCESS_CANONICAL_SUMMARY_JSON" "$SUCCESS_LOG"

echo "[blockchain-fastlane] bootstrap governance graduation gate ordering path"
: >"$CAPTURE"
BLOCKCHAIN_FASTLANE_CAPTURE_FILE="$CAPTURE" \
BLOCKCHAIN_FASTLANE_CANONICAL_SUMMARY_JSON="$BOOTSTRAP_GATE_CANONICAL_SUMMARY_JSON" \
"$GATE_SCRIPT" \
  --reports-dir "$BOOTSTRAP_GATE_REPORTS_DIR" \
  --summary-json "$BOOTSTRAP_GATE_SUMMARY_JSON" \
  --run-blockchain-mainnet-activation-metrics 1 \
  --run-blockchain-bootstrap-governance-graduation-gate 1 \
  --print-summary-json 0 >"$BOOTSTRAP_GATE_LOG" 2>&1

assert_stage_order "$CAPTURE" "${STAGE_IDS_WITH_BOOTSTRAP[@]}"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_metrics" "--summary-json" "$BOOTSTRAP_GATE_METRICS_SUMMARY_JSON"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_metrics" "--canonical-metrics-json" "$BOOTSTRAP_GATE_METRICS_JSON"
assert_stage_invocation_contains "$CAPTURE" "blockchain_bootstrap_governance_graduation_gate" "--metrics-json" "$BOOTSTRAP_GATE_METRICS_JSON"
assert_stage_invocation_contains "$CAPTURE" "blockchain_bootstrap_governance_graduation_gate" "--summary-json" "$BOOTSTRAP_GATE_SUMMARY_PATH"
assert_stage_invocation_contains "$CAPTURE" "blockchain_bootstrap_governance_graduation_gate" "--fail-close" "1"
assert_stage_invocation_token_count "$CAPTURE" "blockchain_bootstrap_governance_graduation_gate" "--fail-close" 1

if [[ ! -f "$BOOTSTRAP_GATE_SUMMARY_JSON" ]]; then
  echo "missing bootstrap-gate summary json: $BOOTSTRAP_GATE_SUMMARY_JSON"
  cat "$BOOTSTRAP_GATE_LOG"
  exit 1
fi
if ! jq -e --arg bootstrap_gate_summary "$BOOTSTRAP_GATE_SUMMARY_PATH" --arg metrics_json "$BOOTSTRAP_GATE_METRICS_JSON" '
  .status == "pass"
  and .rc == 0
  and .inputs.run_blockchain_mainnet_activation_metrics == true
  and .inputs.run_blockchain_bootstrap_governance_graduation_gate == true
  and .inputs.blockchain_bootstrap_governance_graduation_gate_summary_json == $bootstrap_gate_summary
  and .artifacts.blockchain_bootstrap_governance_graduation_gate_summary_json == $bootstrap_gate_summary
  and .steps.blockchain_bootstrap_governance_graduation_gate.enabled == true
  and .steps.blockchain_bootstrap_governance_graduation_gate.status == "pass"
  and .steps.blockchain_bootstrap_governance_graduation_gate.rc == 0
  and .steps.blockchain_bootstrap_governance_graduation_gate.artifacts.summary_json == $bootstrap_gate_summary
  and .steps.blockchain_bootstrap_governance_graduation_gate.artifacts.metrics_json == $metrics_json
' "$BOOTSTRAP_GATE_SUMMARY_JSON" >/dev/null; then
  echo "bootstrap-gate summary missing expected stage wiring fields"
  cat "$BOOTSTRAP_GATE_SUMMARY_JSON"
  exit 1
fi
assert_generated_at_iso_utc "$BOOTSTRAP_GATE_ACTIVATION_SUMMARY_PATH" "mainnet activation gate"
assert_generated_at_iso_utc "$BOOTSTRAP_GATE_SUMMARY_PATH" "bootstrap governance graduation gate"
assert_canonical_summary_artifact "$BOOTSTRAP_GATE_SUMMARY_JSON" "$BOOTSTRAP_GATE_CANONICAL_SUMMARY_JSON" "$BOOTSTRAP_GATE_LOG"

echo "[blockchain-fastlane] phase7 summary env input ingestion"
: >"$CAPTURE"
BLOCKCHAIN_FASTLANE_CAPTURE_FILE="$CAPTURE" \
BLOCKCHAIN_FASTLANE_CANONICAL_SUMMARY_JSON="$PHASE7_ENV_CANONICAL_SUMMARY_JSON" \
BLOCKCHAIN_FASTLANE_PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_JSON="$PHASE7_SOURCE_JSON" \
"$GATE_SCRIPT" \
  --reports-dir "$PHASE7_ENV_REPORTS_DIR" \
  --summary-json "$PHASE7_ENV_SUMMARY_JSON" \
  --run-blockchain-mainnet-activation-operator-pack 1 \
  --print-summary-json 0 >"$PHASE7_ENV_LOG" 2>&1 || phase7_env_rc=$?
phase7_env_rc="${phase7_env_rc:-0}"
if [[ "$phase7_env_rc" -ne 66 ]]; then
  echo "phase7-env run should fail-closed with rc=66 when activation metrics prereq is missing (got rc=$phase7_env_rc)"
  cat "$PHASE7_ENV_LOG"
  exit 1
fi

assert_stage_order "$CAPTURE" "${STAGE_IDS_NO_METRICS_WITH_OPERATOR_PACK[@]}"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_operator_pack" "--reports-dir" "$PHASE7_ENV_REPORTS_DIR/blockchain_mainnet_activation_operator_pack"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_operator_pack" "--summary-json" "$PHASE7_ENV_REPORTS_DIR/blockchain_mainnet_activation_operator_pack_summary.json"
assert_stage_invocation_not_contains "$CAPTURE" "blockchain_mainnet_activation_operator_pack" "--metrics-summary-json"
assert_stage_invocation_not_contains "$CAPTURE" "blockchain_mainnet_activation_operator_pack" "--canonical-summary-json"

if [[ ! -f "$PHASE7_ENV_SUMMARY_JSON" ]]; then
  echo "missing phase7-env summary json: $PHASE7_ENV_SUMMARY_JSON"
  cat "$PHASE7_ENV_LOG"
  exit 1
fi
if ! jq -e --arg phase7_summary "$PHASE7_SOURCE_JSON" '
  .status == "fail"
  and .rc == 66
  and .inputs.phase7_mainnet_cutover_summary_report_json == $phase7_summary
  and .artifacts.phase7_mainnet_cutover_summary_report_json == $phase7_summary
  and .phase7_mainnet_cutover_summary_report.input_summary_json == $phase7_summary
  and .phase7_mainnet_cutover_summary_report.available == true
  and .phase7_mainnet_cutover_summary_report.status == "pass"
  and .inputs.run_blockchain_mainnet_activation_operator_pack == true
  and .steps.blockchain_mainnet_activation_operator_pack.enabled == true
  and .steps.blockchain_mainnet_activation_operator_pack.status == "pass"
  and .steps.blockchain_mainnet_activation_operator_pack.rc == 0
  and .steps.blockchain_mainnet_activation_operator_pack.artifacts.metrics_summary_json == null
  and .inputs.run_blockchain_mainnet_activation_gate == true
  and .steps.blockchain_mainnet_activation_gate.enabled == true
  and .steps.blockchain_mainnet_activation_gate.status == "fail"
  and .steps.blockchain_mainnet_activation_gate.rc == 66
  and .steps.blockchain_mainnet_activation_gate.reason == "missing_metrics_prereq"
  and .steps.blockchain_mainnet_activation_gate.artifacts.metrics_json == null
  and .phase7_mainnet_cutover_summary_report.signals.tdpnd_grpc_auth_live_smoke_ok == false
  and .phase7_mainnet_cutover_summary_report.signals.dual_write_parity_ok == false
  and .phase7_mainnet_cutover_summary_report.signals.bootstrap_governance_graduation_gate_go_ok == true
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.input_summary_json == $phase7_summary
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.available == true
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.status == "pass"
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.signals.mainnet_activation_gate_go_ok == true
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.signals.bootstrap_governance_graduation_gate_go_ok == true
' "$PHASE7_ENV_SUMMARY_JSON" >/dev/null; then
  echo "phase7-env summary missing expected env ingestion contract"
  cat "$PHASE7_ENV_SUMMARY_JSON"
  exit 1
fi
assert_canonical_summary_artifact "$PHASE7_ENV_SUMMARY_JSON" "$PHASE7_ENV_CANONICAL_SUMMARY_JSON" "$PHASE7_ENV_LOG"

echo "[blockchain-fastlane] phase7 summary default current-run path preference"
: >"$CAPTURE"
BLOCKCHAIN_FASTLANE_CAPTURE_FILE="$CAPTURE" \
BLOCKCHAIN_FASTLANE_CANONICAL_SUMMARY_JSON="$DEFAULT_PHASE7_REPORTS_DIR/canonical_summary.json" \
"$GATE_SCRIPT" \
  --reports-dir "$DEFAULT_PHASE7_REPORTS_DIR" \
  --summary-json "$DEFAULT_PHASE7_SUMMARY_JSON" \
  --print-summary-json 0 >"$TMP_DIR/phase7_default.log" 2>&1 || default_phase7_rc=$?
default_phase7_rc="${default_phase7_rc:-0}"
if [[ "$default_phase7_rc" -ne 66 ]]; then
  echo "phase7 default-path run should fail-closed with rc=66 when activation metrics prereq is missing (got rc=$default_phase7_rc)"
  cat "$TMP_DIR/phase7_default.log"
  exit 1
fi

assert_stage_order "$CAPTURE" "${STAGE_IDS_NO_METRICS[@]}"
if ! jq -e --arg expected_input "$DEFAULT_PHASE7_REPORT_JSON" '
  .status == "fail"
  and .rc == 66
  and .inputs.phase7_mainnet_cutover_summary_report_json == $expected_input
  and .artifacts.phase7_mainnet_cutover_summary_report_json == $expected_input
  and .phase7_mainnet_cutover_summary_report.input_summary_json == $expected_input
  and .phase7_mainnet_cutover_summary_report.available == true
  and .phase7_mainnet_cutover_summary_report.status == "pass"
  and .phase7_mainnet_cutover_summary_report.signals.module_tx_surface_ok == true
  and .phase7_mainnet_cutover_summary_report.signals.tdpnd_grpc_live_smoke_ok == true
  and .phase7_mainnet_cutover_summary_report.signals.tdpnd_grpc_auth_live_smoke_ok == false
  and .phase7_mainnet_cutover_summary_report.signals.tdpnd_comet_runtime_smoke_ok == true
  and .phase7_mainnet_cutover_summary_report.signals.cosmos_module_coverage_floor_ok == true
  and .phase7_mainnet_cutover_summary_report.signals.cosmos_keeper_coverage_floor_ok == true
  and .phase7_mainnet_cutover_summary_report.signals.cosmos_app_coverage_floor_ok == true
  and .phase7_mainnet_cutover_summary_report.signals.dual_write_parity_ok == false
  and .phase7_mainnet_cutover_summary_report.signals.mainnet_activation_gate_go_ok == true
  and .phase7_mainnet_cutover_summary_report.signals.bootstrap_governance_graduation_gate_go_ok == true
  and .inputs.run_blockchain_mainnet_activation_gate == true
  and .steps.blockchain_mainnet_activation_gate.enabled == true
  and .steps.blockchain_mainnet_activation_gate.status == "fail"
  and .steps.blockchain_mainnet_activation_gate.rc == 66
  and .steps.blockchain_mainnet_activation_gate.reason == "missing_metrics_prereq"
  and .steps.blockchain_mainnet_activation_gate.artifacts.metrics_json == null
' "$DEFAULT_PHASE7_SUMMARY_JSON" >/dev/null; then
  echo "phase7 default-path summary should prefer the current reports_dir artifact"
  cat "$DEFAULT_PHASE7_SUMMARY_JSON"
  cat "$ROOT_PHASE7_SUMMARY_REPORT_JSON"
  cat "$TMP_DIR/phase7_default.log"
  exit 1
fi
assert_canonical_summary_artifact "$DEFAULT_PHASE7_SUMMARY_JSON" "$DEFAULT_PHASE7_REPORTS_DIR/canonical_summary.json" "$TMP_DIR/phase7_default.log"

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
cat >"$METRICS_INPUT_JSON" <<'EOF_METRICS_INPUT_JSON'
{
  "measurement_window_weeks": 12,
  "reliability": {
    "vpn_connect_session_success_slo_pct": 99.97,
    "vpn_recovery_mttr_p95_minutes": 11
  },
  "demand": {
    "paying_users_3mo_min": 1600,
    "paid_sessions_per_day_30d_avg": 9200
  }
}
EOF_METRICS_INPUT_JSON

echo "[blockchain-fastlane] metrics input normalizer wiring"
: >"$CAPTURE"
BLOCKCHAIN_FASTLANE_CAPTURE_FILE="$CAPTURE" \
BLOCKCHAIN_FASTLANE_CANONICAL_SUMMARY_JSON="$METRICS_INPUT_CANONICAL_SUMMARY_JSON" \
"$GATE_SCRIPT" \
  --reports-dir "$METRICS_INPUT_REPORTS_DIR" \
  --summary-json "$METRICS_INPUT_SUMMARY_JSON" \
  --run-blockchain-mainnet-activation-metrics 1 \
  --blockchain-mainnet-activation-metrics-input-json "$METRICS_INPUT_JSON" \
  --print-summary-json 0 >"$METRICS_INPUT_LOG" 2>&1

assert_stage_order "$CAPTURE" "${STAGE_IDS[@]}"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_metrics" "--source-json" "$METRICS_INPUT_NORMALIZED_CANONICAL_JSON" "--source-json" "$DEFAULT_SOURCE_JSON_PHASE5"
assert_stage_invocation_token_count "$CAPTURE" "blockchain_mainnet_activation_metrics" "--source-json" 5

if [[ ! -f "$METRICS_INPUT_SUMMARY_JSON" ]]; then
  echo "missing metrics-input summary json: $METRICS_INPUT_SUMMARY_JSON"
  cat "$METRICS_INPUT_LOG"
  exit 1
fi
if [[ ! -f "$METRICS_INPUT_NORMALIZED_SUMMARY_JSON" || ! -f "$METRICS_INPUT_NORMALIZED_CANONICAL_JSON" ]]; then
  echo "missing metrics-input normalized artifacts"
  ls -la "$METRICS_INPUT_REPORTS_DIR"
  cat "$METRICS_INPUT_LOG"
  exit 1
fi
if ! jq -e --arg input_json "$METRICS_INPUT_JSON" --arg normalized_summary "$METRICS_INPUT_NORMALIZED_SUMMARY_JSON" --arg normalized_canonical "$METRICS_INPUT_NORMALIZED_CANONICAL_JSON" --arg default_source "$DEFAULT_SOURCE_JSON_PHASE5" '
  .status == "pass"
  and .rc == 0
  and .inputs.blockchain_mainnet_activation_metrics_input_json == $input_json
  and .inputs.blockchain_mainnet_activation_metrics_input_summary_json == $normalized_summary
  and .inputs.blockchain_mainnet_activation_metrics_input_canonical_json == $normalized_canonical
  and .artifacts.blockchain_mainnet_activation_metrics_input_json == $input_json
  and .artifacts.blockchain_mainnet_activation_metrics_input_summary_json == $normalized_summary
  and .artifacts.blockchain_mainnet_activation_metrics_input_canonical_json == $normalized_canonical
  and ((.inputs.blockchain_mainnet_activation_metrics_source_jsons | index($normalized_canonical)) != null)
  and ((.inputs.blockchain_mainnet_activation_metrics_source_jsons | index($default_source)) != null)
  and .steps.blockchain_mainnet_activation_metrics.artifacts.metrics_input_json == $input_json
  and .steps.blockchain_mainnet_activation_metrics.artifacts.metrics_input_summary_json == $normalized_summary
  and .steps.blockchain_mainnet_activation_metrics.artifacts.metrics_input_canonical_json == $normalized_canonical
  and ((.steps.blockchain_mainnet_activation_metrics.artifacts.source_jsons | index($normalized_canonical)) != null)
' "$METRICS_INPUT_SUMMARY_JSON" >/dev/null; then
  echo "metrics-input summary missing expected normalizer wiring contract"
  cat "$METRICS_INPUT_SUMMARY_JSON"
  exit 1
fi
assert_canonical_summary_artifact "$METRICS_INPUT_SUMMARY_JSON" "$METRICS_INPUT_CANONICAL_SUMMARY_JSON" "$METRICS_INPUT_LOG"

echo "[blockchain-fastlane] activation gate metrics-input canonical fallback"
: >"$CAPTURE"
BLOCKCHAIN_FASTLANE_CAPTURE_FILE="$CAPTURE" \
BLOCKCHAIN_FASTLANE_CANONICAL_SUMMARY_JSON="$METRICS_INPUT_GATE_FALLBACK_CANONICAL_SUMMARY_JSON" \
"$GATE_SCRIPT" \
  --reports-dir "$METRICS_INPUT_GATE_FALLBACK_REPORTS_DIR" \
  --summary-json "$METRICS_INPUT_GATE_FALLBACK_SUMMARY_JSON" \
  --blockchain-mainnet-activation-metrics-input-json "$METRICS_INPUT_JSON" \
  --print-summary-json 0 >"$METRICS_INPUT_GATE_FALLBACK_LOG" 2>&1

assert_stage_order "$CAPTURE" "${STAGE_IDS_NO_METRICS_WITH_GATE[@]}"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_gate" "--metrics-json" "$METRICS_INPUT_GATE_FALLBACK_NORMALIZED_CANONICAL_JSON"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_gate" "--summary-json" "$METRICS_INPUT_GATE_FALLBACK_GATE_SUMMARY_JSON"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_gate" "--fail-close" "1"
assert_stage_invocation_token_count "$CAPTURE" "blockchain_mainnet_activation_gate" "--fail-close" 1

if [[ ! -f "$METRICS_INPUT_GATE_FALLBACK_SUMMARY_JSON" ]]; then
  echo "missing metrics-input gate-fallback summary json: $METRICS_INPUT_GATE_FALLBACK_SUMMARY_JSON"
  cat "$METRICS_INPUT_GATE_FALLBACK_LOG"
  exit 1
fi
if [[ ! -f "$METRICS_INPUT_GATE_FALLBACK_NORMALIZED_SUMMARY_JSON" || ! -f "$METRICS_INPUT_GATE_FALLBACK_NORMALIZED_CANONICAL_JSON" ]]; then
  echo "missing metrics-input gate-fallback normalized artifacts"
  ls -la "$METRICS_INPUT_GATE_FALLBACK_REPORTS_DIR"
  cat "$METRICS_INPUT_GATE_FALLBACK_LOG"
  exit 1
fi
if ! jq -e --arg input_json "$METRICS_INPUT_JSON" --arg normalized_summary "$METRICS_INPUT_GATE_FALLBACK_NORMALIZED_SUMMARY_JSON" --arg normalized_canonical "$METRICS_INPUT_GATE_FALLBACK_NORMALIZED_CANONICAL_JSON" --arg gate_summary "$METRICS_INPUT_GATE_FALLBACK_GATE_SUMMARY_JSON" '
  .status == "pass"
  and .rc == 0
  and .inputs.run_blockchain_mainnet_activation_metrics == false
  and .inputs.blockchain_mainnet_activation_metrics_input_json == $input_json
  and .inputs.blockchain_mainnet_activation_metrics_input_summary_json == $normalized_summary
  and .inputs.blockchain_mainnet_activation_metrics_input_canonical_json == $normalized_canonical
  and .inputs.blockchain_mainnet_activation_gate_metrics_json == $normalized_canonical
  and .inputs.blockchain_mainnet_activation_gate_metrics_source == "metrics_input_canonical_json"
  and .artifacts.blockchain_mainnet_activation_metrics_json == null
  and .artifacts.blockchain_mainnet_activation_gate_metrics_json == $normalized_canonical
  and .artifacts.blockchain_mainnet_activation_gate_metrics_source == "metrics_input_canonical_json"
  and .steps.blockchain_mainnet_activation_metrics.enabled == false
  and .steps.blockchain_mainnet_activation_metrics.status == "skip"
  and .steps.blockchain_mainnet_activation_metrics.reason == "disabled"
  and .steps.blockchain_mainnet_activation_gate.artifacts.summary_json == $gate_summary
  and .steps.blockchain_mainnet_activation_gate.artifacts.metrics_json == $normalized_canonical
  and .steps.blockchain_mainnet_activation_gate.artifacts.metrics_source == "metrics_input_canonical_json"
' "$METRICS_INPUT_GATE_FALLBACK_SUMMARY_JSON" >/dev/null; then
  echo "metrics-input gate-fallback summary missing expected canonical metrics wiring contract"
  cat "$METRICS_INPUT_GATE_FALLBACK_SUMMARY_JSON"
  exit 1
fi
assert_generated_at_iso_utc "$METRICS_INPUT_GATE_FALLBACK_GATE_SUMMARY_JSON" "mainnet activation gate"
assert_canonical_summary_artifact "$METRICS_INPUT_GATE_FALLBACK_SUMMARY_JSON" "$METRICS_INPUT_GATE_FALLBACK_CANONICAL_SUMMARY_JSON" "$METRICS_INPUT_GATE_FALLBACK_LOG"

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
  --print-summary-json 0 >"$SAME_PATH_LOG" 2>&1 || same_path_rc=$?
same_path_rc="${same_path_rc:-0}"
if [[ "$same_path_rc" -ne 66 ]]; then
  echo "same-path run should fail-closed with rc=66 when activation metrics prereq is missing (got rc=$same_path_rc)"
  cat "$SAME_PATH_LOG"
  exit 1
fi

assert_stage_order "$CAPTURE" "${STAGE_IDS_NO_METRICS[@]}"

if [[ ! -f "$SAME_PATH_SUMMARY_JSON" ]]; then
  echo "missing same-path summary json: $SAME_PATH_SUMMARY_JSON"
  cat "$SAME_PATH_LOG"
  exit 1
fi
if ! jq -e --arg gate_summary "$SAME_PATH_GATE_SUMMARY_JSON" --arg phase7_missing "$PHASE7_MISSING_JSON" '
  .status == "fail"
  and .rc == 66
  and .inputs.run_blockchain_mainnet_activation_metrics == false
  and .steps.blockchain_mainnet_activation_metrics.enabled == false
  and .steps.blockchain_mainnet_activation_metrics.status == "skip"
  and .steps.blockchain_mainnet_activation_metrics.reason == "disabled"
  and .steps.blockchain_mainnet_activation_gate.enabled == true
  and .steps.blockchain_mainnet_activation_gate.status == "fail"
  and .steps.blockchain_mainnet_activation_gate.rc == 66
  and .steps.blockchain_mainnet_activation_gate.reason == "missing_metrics_prereq"
  and .inputs.blockchain_mainnet_activation_gate_summary_json == $gate_summary
  and .artifacts.blockchain_mainnet_activation_gate_summary_json == $gate_summary
  and .steps.blockchain_mainnet_activation_gate.artifacts.summary_json == $gate_summary
  and .steps.blockchain_mainnet_activation_gate.artifacts.metrics_json == null
  and .steps.blockchain_mainnet_activation_gate.artifacts.metrics_source == null
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
  and .phase7_mainnet_cutover_summary_report.signals.bootstrap_governance_graduation_gate_go_ok == null
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.input_summary_json == $phase7_missing
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.available == false
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.status == "missing"
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.signals.mainnet_activation_gate_go_ok == null
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.signals.bootstrap_governance_graduation_gate_go_ok == null
' "$SAME_PATH_SUMMARY_JSON" >/dev/null; then
  echo "same-path summary missing fail-closed status or canonical artifact equality"
  cat "$SAME_PATH_SUMMARY_JSON"
  exit 1
fi
if ! grep -Fq -- '[blockchain-fastlane] status=fail rc=66 dry_run=0' "$SAME_PATH_LOG"; then
  echo "same-path log missing final fail status line"
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
  --print-summary-json 0 >"$PHASE7_INVALID_LOG" 2>&1 || phase7_invalid_rc=$?
phase7_invalid_rc="${phase7_invalid_rc:-0}"
if [[ "$phase7_invalid_rc" -ne 66 ]]; then
  echo "phase7-invalid run should fail-closed with rc=66 when activation metrics prereq is missing (got rc=$phase7_invalid_rc)"
  cat "$PHASE7_INVALID_LOG"
  exit 1
fi

assert_stage_order "$CAPTURE" "${STAGE_IDS_NO_METRICS[@]}"

if [[ ! -f "$PHASE7_INVALID_SUMMARY_JSON" ]]; then
  echo "missing phase7-invalid summary json: $PHASE7_INVALID_SUMMARY_JSON"
  cat "$PHASE7_INVALID_LOG"
  exit 1
fi
if ! jq -e --arg phase7_invalid "$PHASE7_INVALID_JSON" '
  .status == "fail"
  and .rc == 66
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
  and .phase7_mainnet_cutover_summary_report.signals.bootstrap_governance_graduation_gate_go_ok == null
  and .inputs.run_blockchain_mainnet_activation_gate == true
  and .steps.blockchain_mainnet_activation_gate.enabled == true
  and .steps.blockchain_mainnet_activation_gate.status == "fail"
  and .steps.blockchain_mainnet_activation_gate.rc == 66
  and .steps.blockchain_mainnet_activation_gate.reason == "missing_metrics_prereq"
  and .steps.blockchain_mainnet_activation_gate.artifacts.metrics_json == null
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.status == "invalid"
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.available == false
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.signals.mainnet_activation_gate_go_ok == null
  and .steps.ci_phase7_mainnet_cutover.artifacts.phase7_mainnet_cutover_summary_report.signals.bootstrap_governance_graduation_gate_go_ok == null
' "$PHASE7_INVALID_SUMMARY_JSON" >/dev/null; then
  echo "phase7-invalid summary missing expected fail-closed accounting"
  cat "$PHASE7_INVALID_SUMMARY_JSON"
  exit 1
fi
if ! grep -Fq -- '[blockchain-fastlane] status=fail rc=66 dry_run=0' "$PHASE7_INVALID_LOG"; then
  echo "phase7-invalid log missing final fail status line"
  cat "$PHASE7_INVALID_LOG"
  exit 1
fi
assert_canonical_summary_artifact "$PHASE7_INVALID_SUMMARY_JSON" "$PHASE7_INVALID_CANONICAL_SUMMARY_JSON" "$PHASE7_INVALID_LOG"

echo "[blockchain-fastlane] explicit activation-gate request without metrics prereq"
: >"$CAPTURE"
BLOCKCHAIN_FASTLANE_CAPTURE_FILE="$CAPTURE" \
BLOCKCHAIN_FASTLANE_CANONICAL_SUMMARY_JSON="$EXPLICIT_GATE_NO_METRICS_CANONICAL_SUMMARY_JSON" \
"$GATE_SCRIPT" \
  --reports-dir "$EXPLICIT_GATE_NO_METRICS_REPORTS_DIR" \
  --summary-json "$EXPLICIT_GATE_NO_METRICS_SUMMARY_JSON" \
  --run-blockchain-mainnet-activation-gate 1 \
  --print-summary-json 0 >"$EXPLICIT_GATE_NO_METRICS_LOG" 2>&1

assert_stage_order "$CAPTURE" "${STAGE_IDS_NO_METRICS_WITH_GATE[@]}"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_gate" "--summary-json" "$EXPLICIT_GATE_NO_METRICS_GATE_SUMMARY_JSON"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_gate" "--fail-close" "1"
assert_stage_invocation_not_contains "$CAPTURE" "blockchain_mainnet_activation_gate" "--metrics-json"
assert_stage_invocation_token_count "$CAPTURE" "blockchain_mainnet_activation_gate" "--fail-close" 1

if [[ ! -f "$EXPLICIT_GATE_NO_METRICS_SUMMARY_JSON" ]]; then
  echo "missing explicit-gate-no-metrics summary json: $EXPLICIT_GATE_NO_METRICS_SUMMARY_JSON"
  cat "$EXPLICIT_GATE_NO_METRICS_LOG"
  exit 1
fi
if ! jq -e --arg gate_summary "$EXPLICIT_GATE_NO_METRICS_GATE_SUMMARY_JSON" '
  .status == "pass"
  and .rc == 0
  and .inputs.run_blockchain_mainnet_activation_gate == true
  and .steps.blockchain_mainnet_activation_gate.enabled == true
  and .steps.blockchain_mainnet_activation_gate.status == "pass"
  and .steps.blockchain_mainnet_activation_gate.reason == null
  and .steps.blockchain_mainnet_activation_gate.artifacts.summary_json == $gate_summary
  and .steps.blockchain_mainnet_activation_gate.artifacts.metrics_json == null
  and .steps.blockchain_mainnet_activation_gate.artifacts.metrics_source == null
' "$EXPLICIT_GATE_NO_METRICS_SUMMARY_JSON" >/dev/null; then
  echo "explicit-gate-no-metrics summary missing expected explicit-request run contract"
  cat "$EXPLICIT_GATE_NO_METRICS_SUMMARY_JSON"
  exit 1
fi
assert_generated_at_iso_utc "$EXPLICIT_GATE_NO_METRICS_GATE_SUMMARY_JSON" "mainnet activation gate"
assert_canonical_summary_artifact "$EXPLICIT_GATE_NO_METRICS_SUMMARY_JSON" "$EXPLICIT_GATE_NO_METRICS_CANONICAL_SUMMARY_JSON" "$EXPLICIT_GATE_NO_METRICS_LOG"

echo "[blockchain-fastlane] env activation-gate flag without metrics prereq remains fail-closed"
: >"$CAPTURE"
set +e
BLOCKCHAIN_FASTLANE_CAPTURE_FILE="$CAPTURE" \
BLOCKCHAIN_FASTLANE_CANONICAL_SUMMARY_JSON="$ENV_GATE_NO_METRICS_CANONICAL_SUMMARY_JSON" \
BLOCKCHAIN_FASTLANE_RUN_BLOCKCHAIN_MAINNET_ACTIVATION_GATE=1 \
"$GATE_SCRIPT" \
  --reports-dir "$ENV_GATE_NO_METRICS_REPORTS_DIR" \
  --summary-json "$ENV_GATE_NO_METRICS_SUMMARY_JSON" \
  --print-summary-json 0 >"$ENV_GATE_NO_METRICS_LOG" 2>&1
env_gate_no_metrics_rc=$?
set -e
if [[ "$env_gate_no_metrics_rc" -ne 66 ]]; then
  echo "env activation-gate flag should fail-closed with rc=66 when metrics prereq is missing (got rc=$env_gate_no_metrics_rc)"
  cat "$ENV_GATE_NO_METRICS_LOG"
  exit 1
fi

assert_stage_order "$CAPTURE" "${STAGE_IDS_NO_METRICS[@]}"

if [[ ! -f "$ENV_GATE_NO_METRICS_SUMMARY_JSON" ]]; then
  echo "missing env-gate-no-metrics summary json: $ENV_GATE_NO_METRICS_SUMMARY_JSON"
  cat "$ENV_GATE_NO_METRICS_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 66
  and .inputs.run_blockchain_mainnet_activation_gate == true
  and .steps.blockchain_mainnet_activation_gate.enabled == true
  and .steps.blockchain_mainnet_activation_gate.status == "fail"
  and .steps.blockchain_mainnet_activation_gate.rc == 66
  and .steps.blockchain_mainnet_activation_gate.reason == "missing_metrics_prereq"
  and .steps.blockchain_mainnet_activation_gate.artifacts.metrics_json == null
  and .steps.blockchain_mainnet_activation_gate.artifacts.metrics_source == null
' "$ENV_GATE_NO_METRICS_SUMMARY_JSON" >/dev/null; then
  echo "env-gate-no-metrics summary missing expected fail-closed env-override contract"
  cat "$ENV_GATE_NO_METRICS_SUMMARY_JSON"
  exit 1
fi
if ! grep -Fq -- '[blockchain-fastlane] status=fail rc=66 dry_run=0' "$ENV_GATE_NO_METRICS_LOG"; then
  echo "env-gate-no-metrics log missing final fail status line"
  cat "$ENV_GATE_NO_METRICS_LOG"
  exit 1
fi
assert_canonical_summary_artifact "$ENV_GATE_NO_METRICS_SUMMARY_JSON" "$ENV_GATE_NO_METRICS_CANONICAL_SUMMARY_JSON" "$ENV_GATE_NO_METRICS_LOG"

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
  and .inputs.run_blockchain_bootstrap_governance_graduation_gate == false
  and (.steps | to_entries | all(
      if .value.enabled
      then (.value.status == "skip" and .value.rc == 0 and .value.reason == "dry-run")
      else (.value.status == "skip" and .value.rc == 0 and .value.reason == "disabled")
      end
    ))
  and .steps.blockchain_mainnet_activation_metrics.enabled == true
  and .steps.blockchain_mainnet_activation_metrics.status == "skip"
  and .steps.blockchain_mainnet_activation_metrics.reason == "dry-run"
  and .steps.blockchain_mainnet_activation_gate.enabled == true
  and .steps.blockchain_mainnet_activation_gate.status == "skip"
  and .steps.blockchain_mainnet_activation_gate.reason == "dry-run"
  and .steps.blockchain_bootstrap_governance_graduation_gate.enabled == false
  and .steps.blockchain_bootstrap_governance_graduation_gate.status == "skip"
  and .steps.blockchain_bootstrap_governance_graduation_gate.reason == "disabled"
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
  --run-blockchain-mainnet-activation-operator-pack 1 \
  --run-blockchain-bootstrap-governance-graduation-gate 1 \
  --run-ci-phase5-settlement-layer 0 \
  --run-ci-phase6-cosmos-l1-contracts 0 \
  --run-blockchain-mainnet-activation-gate 0 >"$TOGGLE_LOG" 2>&1

assert_stage_order "$CAPTURE" "${TOGGLE_STAGE_IDS[@]}"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_operator_pack" "--reports-dir" "$TOGGLE_OPERATOR_PACK_REPORTS_DIR"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_operator_pack" "--summary-json" "$TOGGLE_OPERATOR_PACK_SUMMARY_JSON"
assert_stage_invocation_contains "$CAPTURE" "blockchain_mainnet_activation_operator_pack" "--metrics-summary-json" "$TOGGLE_REPORTS_DIR/blockchain_mainnet_activation_metrics_summary.json"
assert_stage_invocation_not_contains "$CAPTURE" "blockchain_mainnet_activation_operator_pack" "--canonical-summary-json"
assert_stage_invocation_contains "$CAPTURE" "blockchain_bootstrap_governance_graduation_gate" "--fail-close" "1"
assert_stage_invocation_token_count "$CAPTURE" "blockchain_bootstrap_governance_graduation_gate" "--fail-close" 1

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
  and .inputs.run_blockchain_mainnet_activation_operator_pack == true
  and .steps.blockchain_mainnet_activation_operator_pack.enabled == true
  and .steps.blockchain_mainnet_activation_operator_pack.status == "pass"
  and .steps.blockchain_mainnet_activation_operator_pack.rc == 0
  and .inputs.run_blockchain_mainnet_activation_gate == false
  and .steps.blockchain_mainnet_activation_gate.enabled == false
  and .steps.blockchain_mainnet_activation_gate.status == "skip"
  and .steps.blockchain_mainnet_activation_gate.reason == "disabled"
  and .inputs.run_blockchain_bootstrap_governance_graduation_gate == true
  and .steps.blockchain_bootstrap_governance_graduation_gate.enabled == true
  and .steps.blockchain_bootstrap_governance_graduation_gate.status == "pass"
  and .steps.blockchain_bootstrap_governance_graduation_gate.rc == 0
' "$TOGGLE_SUMMARY_JSON" >/dev/null; then
  echo "toggle summary missing expected disabled/enabled fields"
  cat "$TOGGLE_SUMMARY_JSON"
  exit 1
fi
assert_generated_at_iso_utc "$TOGGLE_BOOTSTRAP_GATE_SUMMARY_PATH" "bootstrap governance graduation gate"
assert_canonical_summary_artifact "$TOGGLE_SUMMARY_JSON" "$TOGGLE_CANONICAL_SUMMARY_JSON" "$TOGGLE_LOG"

echo "[blockchain-fastlane] operator-pack executable validation"
set +e
BLOCKCHAIN_FASTLANE_CAPTURE_FILE="$CAPTURE" \
BLOCKCHAIN_FASTLANE_BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_SCRIPT="$TMP_DIR/missing_blockchain_mainnet_activation_operator_pack.sh" \
BLOCKCHAIN_FASTLANE_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_missing_operator_script.json" \
"$GATE_SCRIPT" \
  --reports-dir "$TMP_DIR/reports_missing_operator_script" \
  --summary-json "$TMP_DIR/summary_missing_operator_script.json" \
  --run-blockchain-mainnet-activation-operator-pack 1 \
  --print-summary-json 0 >"$TMP_DIR/missing_operator_script.log" 2>&1
missing_operator_script_rc=$?
set -e
if [[ "$missing_operator_script_rc" -ne 2 ]]; then
  echo "expected missing operator-pack script validation to exit 2"
  cat "$TMP_DIR/missing_operator_script.log"
  exit 1
fi
if ! grep -Fq -- "missing executable stage script: $TMP_DIR/missing_blockchain_mainnet_activation_operator_pack.sh" "$TMP_DIR/missing_operator_script.log"; then
  echo "expected missing operator-pack script validation message"
  cat "$TMP_DIR/missing_operator_script.log"
  exit 1
fi

echo "[blockchain-fastlane] reject flag-like metrics-json path"
set +e
BLOCKCHAIN_FASTLANE_CAPTURE_FILE="$CAPTURE" \
BLOCKCHAIN_FASTLANE_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_summary_bad_path.json" \
"$GATE_SCRIPT" \
  --reports-dir "$TMP_DIR/reports_bad_path" \
  --summary-json "$TMP_DIR/bad_path_summary.json" \
  --blockchain-mainnet-activation-metrics-json --summary-json \
  --print-summary-json 0 >"$TMP_DIR/bad_path.log" 2>&1
bad_path_rc=$?
set -e
if [[ "$bad_path_rc" -eq 0 ]]; then
  echo "expected flag-like metrics-json path to fail parsing"
  cat "$TMP_DIR/bad_path.log"
  exit 1
fi
if [[ "$bad_path_rc" -ne 2 ]]; then
  echo "expected flag-like metrics-json path to exit 2"
  cat "$TMP_DIR/bad_path.log"
  exit 1
fi
if ! grep -Fq 'flag-like token: --summary-json' "$TMP_DIR/bad_path.log"; then
  echo "expected flag-like token rejection message"
  cat "$TMP_DIR/bad_path.log"
  exit 1
fi

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
BLOCKCHAIN_FASTLANE_FAIL_MATRIX="ci_phase5_settlement_layer=19,ci_phase6_cosmos_l1_build_testnet=23,ci_phase6_cosmos_l1_contracts=41,integration_slash_violation_type_contract_consistency=47,integration_cosmos_record_normalization_contract_consistency=49,integration_blockchain_cosmos_only_guardrail=51,ci_phase7_mainnet_cutover=53,blockchain_mainnet_activation_metrics=57,blockchain_mainnet_activation_operator_pack=58,blockchain_mainnet_activation_gate=59" \
BLOCKCHAIN_FASTLANE_CANONICAL_SUMMARY_JSON="$FAIL_CANONICAL_SUMMARY_JSON" \
"$GATE_SCRIPT" \
  --run-blockchain-mainnet-activation-metrics 1 \
  --run-blockchain-mainnet-activation-operator-pack 1 \
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

assert_stage_order "$CAPTURE" "${STAGE_IDS_WITH_OPERATOR_PACK[@]}"

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
  and .steps.integration_slash_violation_type_contract_consistency.status == "fail"
  and .steps.integration_slash_violation_type_contract_consistency.rc == 47
  and .steps.integration_cosmos_record_normalization_contract_consistency.status == "fail"
  and .steps.integration_cosmos_record_normalization_contract_consistency.rc == 49
  and .steps.integration_blockchain_cosmos_only_guardrail.status == "fail"
  and .steps.integration_blockchain_cosmos_only_guardrail.rc == 51
  and .steps.ci_phase7_mainnet_cutover.status == "fail"
  and .steps.ci_phase7_mainnet_cutover.rc == 53
  and .steps.blockchain_mainnet_activation_metrics.status == "fail"
  and .steps.blockchain_mainnet_activation_metrics.rc == 57
  and .steps.blockchain_mainnet_activation_operator_pack.status == "fail"
  and .steps.blockchain_mainnet_activation_operator_pack.rc == 58
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
