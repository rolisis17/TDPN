#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp cat cmp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_PREFILL_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics_prefill.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

METRICS_INPUT_SCRIPT_UNDER_TEST="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_INPUT_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics_input.sh}"
if [[ ! -x "$METRICS_INPUT_SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable metrics-input script under test: $METRICS_INPUT_SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

REPORTS_DIR="$TMP_DIR/reports"
SOURCE_DIR="$TMP_DIR/sources"
mkdir -p "$REPORTS_DIR" "$SOURCE_DIR"

SUCCESS_SOURCE_A="$SOURCE_DIR/source_a.json"
SUCCESS_SOURCE_B="$SOURCE_DIR/source_b.json"
PARTIAL_SOURCE="$SOURCE_DIR/partial_source.json"
MISSING_SOURCE="$SOURCE_DIR/missing_source.json"
REFERENCE_SOURCE="$SOURCE_DIR/reference_source.json"

cat >"$SUCCESS_SOURCE_A" <<'EOF_A'
{
  "measurement_window_weeks": 13,
  "vpn_connect_session_success_slo_pct": 99.82,
  "paying_users_3mo_min": 1650,
  "validator_candidate_depth": 38,
  "manual_sanctions_reversed_pct_90d": 4.2,
  "nested": {
    "vpn_recovery_mttr_p95_minutes": 19,
    "paid_sessions_per_day_30d_avg": 15500
  }
}
EOF_A

cat >"$SUCCESS_SOURCE_B" <<'EOF_B'
{
  "phase5": {
    "validator_independent_operators": 14,
    "validator_max_operator_seat_share_pct": 18.5
  },
  "phase6": {
    "validator_max_asn_provider_seat_share_pct": 22.0,
    "validator_region_count": 5,
    "validator_country_count": 9
  },
  "roadmap": {
    "abuse_report_to_decision_p95_hours": 11,
    "subsidy_runway_months": 16,
    "contribution_margin_3mo": 0.9
  }
}
EOF_B

cat >"$PARTIAL_SOURCE" <<'EOF_P'
{
  "measurement_window_weeks": 13,
  "vpn_connect_session_success_slo_pct": 99.82,
  "paying_users_3mo_min": 1650,
  "nested": {
    "vpn_recovery_mttr_p95_minutes": 19,
    "paid_sessions_per_day_30d_avg": 15500
  }
}
EOF_P

cat >"$REFERENCE_SOURCE" <<EOF_REF
{
  "artifacts": {
    "metrics_json": "$SUCCESS_SOURCE_A"
  }
}
EOF_REF

expected_keys='["measurement_window_weeks","vpn_connect_session_success_slo_pct","vpn_recovery_mttr_p95_minutes","paying_users_3mo_min","paid_sessions_per_day_30d_avg","validator_candidate_depth","validator_independent_operators","validator_max_operator_seat_share_pct","validator_max_asn_provider_seat_share_pct","validator_region_count","validator_country_count","manual_sanctions_reversed_pct_90d","abuse_report_to_decision_p95_hours","subsidy_runway_months","contribution_margin_3mo"]'

SUCCESS_OUTPUT_JSON="$TMP_DIR/success.json"
SUCCESS_CANONICAL_JSON="$TMP_DIR/success.canonical.json"
SUCCESS_LOG="$TMP_DIR/success.log"
ALIAS_OUTPUT_JSON="$TMP_DIR/alias.json"
ALIAS_LOG="$TMP_DIR/alias.log"
PARTIAL_OUTPUT_JSON="$TMP_DIR/partial.json"
PARTIAL_CANONICAL_JSON="$TMP_DIR/partial.canonical.json"
PARTIAL_LOG="$TMP_DIR/partial.log"
MISSING_OUTPUT_JSON="$TMP_DIR/missing.json"
MISSING_CANONICAL_JSON="$TMP_DIR/missing.canonical.json"
MISSING_LOG="$TMP_DIR/missing.log"
METRICS_SUMMARY_OUTPUT_JSON="$TMP_DIR/metrics_summary.json"
METRICS_SUMMARY_CANONICAL_JSON="$TMP_DIR/metrics_summary.canonical.json"
METRICS_SUMMARY_LOG="$TMP_DIR/metrics_summary.log"
BRIDGE_INPUT_SUMMARY_JSON="$TMP_DIR/bridge_input_summary.json"
BRIDGE_INPUT_CANONICAL_JSON="$TMP_DIR/bridge_input.canonical.json"
BRIDGE_INPUT_LOG="$TMP_DIR/bridge_input.log"
REFERENCE_OUTPUT_JSON="$TMP_DIR/reference.json"
REFERENCE_CANONICAL_JSON="$TMP_DIR/reference.canonical.json"
REFERENCE_LOG="$TMP_DIR/reference.log"

bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$REPORTS_DIR" \
  --source-json "$SUCCESS_SOURCE_A" \
  --source-json "$SUCCESS_SOURCE_B" \
  --output-json "$SUCCESS_OUTPUT_JSON" \
  --canonical-output-json "$SUCCESS_CANONICAL_JSON" \
  --print-output-json 0 >"$SUCCESS_LOG" 2>&1

jq -e \
  --arg source_a "$SUCCESS_SOURCE_A" \
  --arg source_b "$SUCCESS_SOURCE_B" \
  --arg reports_dir "$REPORTS_DIR" \
  --argjson expected_keys "$expected_keys" \
  '
  .version == 1
  and .id == "blockchain_mainnet_activation_metrics_prefill"
  and .schema.id == "blockchain_mainnet_activation_metrics_prefill"
  and .status == "complete"
  and .reports_dir == $reports_dir
  and .coverage.required == 15
  and .coverage.provided == 15
  and .coverage.missing == 0
  and (.source_candidates | length) == 8
  and (.usable_sources | length) == 2
  and .usable_sources == [$source_a, $source_b]
  and (.source_candidates[0].label == "explicit_source_json_1")
  and (.source_candidates[1].label == "explicit_source_json_2")
  and (.source_candidates[2].label == "blockchain_gate_bundle_summary")
  and ((.metrics | keys_unsorted) == $expected_keys)
  and all(.metrics[]; . == null or type == "number")
  and .metrics.measurement_window_weeks == 13
  and .metrics.vpn_connect_session_success_slo_pct == 99.82
  and .metrics.vpn_recovery_mttr_p95_minutes == 19
  and .metrics.paid_sessions_per_day_30d_avg == 15500
  and .metrics.validator_country_count == 9
  and .metrics.contribution_margin_3mo == 0.9
  and .measurement_window_weeks == 13
  and .vpn_recovery_mttr_p95_minutes == 19
  and .validator_country_count == 9
  and .contribution_margin_3mo == 0.9
  ' "$SUCCESS_OUTPUT_JSON" >/dev/null

cmp -s "$SUCCESS_OUTPUT_JSON" "$SUCCESS_CANONICAL_JSON"

bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$REPORTS_DIR" \
  --source-json "$SUCCESS_SOURCE_A" \
  --source-json "$SUCCESS_SOURCE_B" \
  --output-json "$ALIAS_OUTPUT_JSON" \
  --print-summary-json 0 >"$ALIAS_LOG" 2>&1

jq -e '
  .status == "complete"
  and .coverage.required == 15
  and .coverage.provided == 15
  and .coverage.missing == 0
' "$ALIAS_OUTPUT_JSON" >/dev/null

bash "$METRICS_INPUT_SCRIPT_UNDER_TEST" \
  --input-json "$SUCCESS_OUTPUT_JSON" \
  --summary-json "$BRIDGE_INPUT_SUMMARY_JSON" \
  --canonical-summary-json "$BRIDGE_INPUT_CANONICAL_JSON" \
  --print-summary-json 0 >"$BRIDGE_INPUT_LOG" 2>&1

jq -e '
  .status == "complete"
  and .ready_for_metrics_script == true
  and .counts.required == 15
  and .counts.provided == 15
  and .counts.missing == 0
  and .counts.invalid == 0
' "$BRIDGE_INPUT_SUMMARY_JSON" >/dev/null

cmp -s "$BRIDGE_INPUT_SUMMARY_JSON" "$BRIDGE_INPUT_CANONICAL_JSON"

bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$REPORTS_DIR" \
  --metrics-summary-json "$PARTIAL_SOURCE" \
  --output-json "$METRICS_SUMMARY_OUTPUT_JSON" \
  --canonical-output-json "$METRICS_SUMMARY_CANONICAL_JSON" \
  --print-output-json 0 >"$METRICS_SUMMARY_LOG" 2>&1

jq -e \
  --arg partial_source "$PARTIAL_SOURCE" \
  '
  .status == "partial"
  and .coverage.required == 15
  and .coverage.provided == 5
  and .coverage.missing == 10
  and .source_candidates[0].label == "metrics_summary_json"
  and .source_candidates[0].path == $partial_source
  and .source_candidates[0].usable == true
  and ((.usable_sources | index($partial_source)) != null)
' "$METRICS_SUMMARY_OUTPUT_JSON" >/dev/null

cmp -s "$METRICS_SUMMARY_OUTPUT_JSON" "$METRICS_SUMMARY_CANONICAL_JSON"

bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$REPORTS_DIR" \
  --source-json "$REFERENCE_SOURCE" \
  --output-json "$REFERENCE_OUTPUT_JSON" \
  --canonical-output-json "$REFERENCE_CANONICAL_JSON" \
  --print-output-json 0 >"$REFERENCE_LOG" 2>&1

jq -e \
  --arg reference_source "$REFERENCE_SOURCE" \
  --arg success_source_a "$SUCCESS_SOURCE_A" \
  '
  .status == "partial"
  and .metrics.measurement_window_weeks == 13
  and .metrics.vpn_connect_session_success_slo_pct == 99.82
  and ((.usable_sources | index($reference_source)) != null)
  and ((.usable_sources | index($success_source_a)) != null)
  and ((.source_candidates | map(.path) | index($success_source_a)) != null)
' "$REFERENCE_OUTPUT_JSON" >/dev/null

cmp -s "$REFERENCE_OUTPUT_JSON" "$REFERENCE_CANONICAL_JSON"

bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$REPORTS_DIR" \
  --source-json "$PARTIAL_SOURCE" \
  --output-json "$PARTIAL_OUTPUT_JSON" \
  --canonical-output-json "$PARTIAL_CANONICAL_JSON" \
  --print-output-json 0 >"$PARTIAL_LOG" 2>&1

jq -e '
  .status == "partial"
  and .coverage.required == 15
  and .coverage.provided == 5
  and .coverage.missing == 10
  and (.usable_sources | length) == 1
  and .metrics.measurement_window_weeks == 13
  and .metrics.vpn_connect_session_success_slo_pct == 99.82
  and .metrics.validator_country_count == null
  and .metrics.contribution_margin_3mo == null
  and ((.missing_metric_keys | index("validator_country_count")) != null)
' "$PARTIAL_OUTPUT_JSON" >/dev/null

cmp -s "$PARTIAL_OUTPUT_JSON" "$PARTIAL_CANONICAL_JSON"

bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$REPORTS_DIR" \
  --source-json "$MISSING_SOURCE" \
  --output-json "$MISSING_OUTPUT_JSON" \
  --canonical-output-json "$MISSING_CANONICAL_JSON" \
  --print-output-json 0 >"$MISSING_LOG" 2>&1

jq -e '
  .status == "missing"
  and .coverage.required == 15
  and .coverage.provided == 0
  and .coverage.missing == 15
  and (.usable_sources | length) == 0
  and (.source_candidates | length) == 7
  and all(.metrics[]; . == null)
' "$MISSING_OUTPUT_JSON" >/dev/null

cmp -s "$MISSING_OUTPUT_JSON" "$MISSING_CANONICAL_JSON"

echo "blockchain mainnet activation metrics prefill integration ok"
