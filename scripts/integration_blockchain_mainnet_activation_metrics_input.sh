#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp grep cat cmp wc tr; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_INPUT_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics_input.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

METRICS_SCRIPT_UNDER_TEST="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics.sh}"
if [[ ! -x "$METRICS_SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable metrics script under test: $METRICS_SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

HELP_LOG="$TMP_DIR/help.log"

INPUT_COMPLETE_JSON="$TMP_DIR/input_complete.json"
COMPLETE_SUMMARY="$TMP_DIR/complete_summary.json"
COMPLETE_CANONICAL="$TMP_DIR/complete_canonical.json"
COMPLETE_LOG="$TMP_DIR/complete.log"

INPUT_PARTIAL_JSON="$TMP_DIR/input_partial.json"
PARTIAL_SUMMARY="$TMP_DIR/partial_summary.json"
PARTIAL_CANONICAL="$TMP_DIR/partial_canonical.json"
PARTIAL_LOG="$TMP_DIR/partial.log"

MISSING_INPUT_JSON="$TMP_DIR/does_not_exist.json"
MISSING_SUMMARY="$TMP_DIR/missing_summary.json"
MISSING_CANONICAL="$TMP_DIR/missing_canonical.json"
MISSING_LOG="$TMP_DIR/missing.log"

PIPELINE_METRICS_SUMMARY="$TMP_DIR/pipeline_metrics_summary.json"
PIPELINE_METRICS_CANONICAL="$TMP_DIR/pipeline_metrics_canonical.json"
PIPELINE_LOG="$TMP_DIR/pipeline.log"

echo "[blockchain-mainnet-activation-metrics-input] help surface"
"$SCRIPT_UNDER_TEST" --help >"$HELP_LOG" 2>&1
if ! grep -Fq "Usage:" "$HELP_LOG"; then
  echo "help output missing Usage header"
  cat "$HELP_LOG"
  exit 1
fi
if ! grep -Fq "Normalize one operator-provided blockchain metrics evidence JSON" "$HELP_LOG"; then
  echo "help output missing purpose text"
  cat "$HELP_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics-input] complete normalization path"
cat >"$INPUT_COMPLETE_JSON" <<'EOF_INPUT_COMPLETE'
{
  "measurement_window_weeks": 13,
  "reliability": {
    "vpn_connect_session_success_slo_pct": 99.82,
    "vpn_recovery_mttr_p95_minutes": 19
  },
  "demand": {
    "paying_users_3mo_min": 1400,
    "paid_sessions_per_day_30d_avg": 15500
  },
  "paying_users_3mo_min": 1650,
  "validator": {
    "validator_candidate_depth": 38,
    "validator_independent_operators": 14,
    "validator_max_operator_seat_share_pct": 18.5,
    "validator_max_asn_provider_seat_share_pct": 22.0,
    "validator_region_count": 5,
    "validator_country_count": 9
  },
  "governance": {
    "manual_sanctions_reversed_pct_90d": 4.2,
    "abuse_report_to_decision_p95_hours": 11
  },
  "economics": {
    "subsidy_runway_months": 16,
    "contribution_margin_3mo": 0.9
  }
}
EOF_INPUT_COMPLETE

set +e
"$SCRIPT_UNDER_TEST" \
  --input-json "$INPUT_COMPLETE_JSON" \
  --summary-json "$COMPLETE_SUMMARY" \
  --canonical-summary-json "$COMPLETE_CANONICAL" \
  --print-summary-json 1 >"$COMPLETE_LOG" 2>&1
complete_rc=$?
set -e
if [[ "$complete_rc" -ne 0 ]]; then
  echo "expected complete normalization path to exit 0"
  cat "$COMPLETE_LOG"
  exit 1
fi

if ! jq -e \
  --arg expected_input "$INPUT_COMPLETE_JSON" \
  --arg expected_summary "$COMPLETE_SUMMARY" \
  --arg expected_canonical "$COMPLETE_CANONICAL" \
  '
  .version == 1
  and .schema.id == "blockchain_mainnet_activation_metrics_input_summary"
  and .status == "complete"
  and .rc == 0
  and .ready_for_metrics_script == true
  and .counts.required == 15
  and .counts.provided == 15
  and .counts.missing == 0
  and .counts.invalid == 0
  and .input.input_json == $expected_input
  and .input.state == "available"
  and .input.valid == true
  and .measurement_window_weeks == 13
  and .vpn_connect_session_success_slo_pct == 99.82
  and .vpn_recovery_mttr_p95_minutes == 19
  and .paying_users_3mo_min == 1650
  and .paid_sessions_per_day_30d_avg == 15500
  and .validator_candidate_depth == 38
  and .validator_independent_operators == 14
  and .validator_max_operator_seat_share_pct == 18.5
  and .validator_max_asn_provider_seat_share_pct == 22
  and .validator_region_count == 5
  and .validator_country_count == 9
  and .manual_sanctions_reversed_pct_90d == 4.2
  and .abuse_report_to_decision_p95_hours == 11
  and .subsidy_runway_months == 16
  and .contribution_margin_3mo == 0.9
  and .sources.metrics.paying_users_3mo_min == "input_json_top_level"
  and .sources.metrics.vpn_connect_session_success_slo_pct == "input_json_nested"
  and .artifacts.summary_json == $expected_summary
  and .artifacts.canonical_summary_json == $expected_canonical
  ' "$COMPLETE_SUMMARY" >/dev/null; then
  echo "complete normalization contract mismatch"
  cat "$COMPLETE_SUMMARY"
  cat "$COMPLETE_LOG"
  exit 1
fi

if [[ ! -f "$COMPLETE_CANONICAL" ]]; then
  echo "complete canonical output missing"
  cat "$COMPLETE_LOG"
  exit 1
fi
if ! cmp -s "$COMPLETE_SUMMARY" "$COMPLETE_CANONICAL"; then
  echo "complete summary/canonical mismatch"
  cat "$COMPLETE_SUMMARY"
  cat "$COMPLETE_CANONICAL"
  exit 1
fi
if ! grep -Fq '[blockchain-mainnet-activation-metrics-input] status=complete' "$COMPLETE_LOG"; then
  echo "complete log missing status line"
  cat "$COMPLETE_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics-input] partial normalization path"
cat >"$INPUT_PARTIAL_JSON" <<'EOF_INPUT_PARTIAL'
{
  "reliability": {
    "vpn_connect_session_success_slo_pct": 99.6,
    "vpn_recovery_mttr_p95_minutes": "unknown"
  },
  "demand": {
    "paying_users_3mo_min": 1200
  }
}
EOF_INPUT_PARTIAL

set +e
"$SCRIPT_UNDER_TEST" \
  --input-json "$INPUT_PARTIAL_JSON" \
  --summary-json "$PARTIAL_SUMMARY" \
  --canonical-summary-json "$PARTIAL_CANONICAL" \
  --print-summary-json 0 >"$PARTIAL_LOG" 2>&1
partial_rc=$?
set -e
if [[ "$partial_rc" -ne 0 ]]; then
  echo "expected partial normalization path to remain fail-soft (exit 0)"
  cat "$PARTIAL_LOG"
  exit 1
fi

if ! jq -e \
  --arg expected_summary "$PARTIAL_SUMMARY" \
  --arg expected_canonical "$PARTIAL_CANONICAL" \
  '
  .status == "partial"
  and .rc == 0
  and .ready_for_metrics_script == false
  and .counts.required == 15
  and .counts.provided == 2
  and .counts.missing == 13
  and .counts.invalid == 1
  and .vpn_connect_session_success_slo_pct == 99.6
  and .vpn_recovery_mttr_p95_minutes == null
  and .paying_users_3mo_min == 1200
  and ((.missing_metric_keys // []) | index("vpn_recovery_mttr_p95_minutes")) != null
  and ((.invalid_metric_keys // []) | index("vpn_recovery_mttr_p95_minutes")) != null
  and .sources.metrics.vpn_recovery_mttr_p95_minutes == "input_json_invalid"
  and .artifacts.summary_json == $expected_summary
  and .artifacts.canonical_summary_json == $expected_canonical
  ' "$PARTIAL_SUMMARY" >/dev/null; then
  echo "partial normalization contract mismatch"
  cat "$PARTIAL_SUMMARY"
  cat "$PARTIAL_LOG"
  exit 1
fi

if [[ ! -f "$PARTIAL_CANONICAL" ]]; then
  echo "partial canonical output missing"
  cat "$PARTIAL_LOG"
  exit 1
fi
if ! cmp -s "$PARTIAL_SUMMARY" "$PARTIAL_CANONICAL"; then
  echo "partial summary/canonical mismatch"
  cat "$PARTIAL_SUMMARY"
  cat "$PARTIAL_CANONICAL"
  exit 1
fi
if ! grep -Fq '[blockchain-mainnet-activation-metrics-input] invalid_metric_keys=' "$PARTIAL_LOG"; then
  echo "partial log missing invalid_metric_keys line"
  cat "$PARTIAL_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics-input] missing input file fail-soft path"
set +e
"$SCRIPT_UNDER_TEST" \
  --input-json "$MISSING_INPUT_JSON" \
  --summary-json "$MISSING_SUMMARY" \
  --canonical-summary-json "$MISSING_CANONICAL" \
  --print-summary-json 0 >"$MISSING_LOG" 2>&1
missing_rc=$?
set -e
if [[ "$missing_rc" -ne 0 ]]; then
  echo "expected missing-input path to remain fail-soft (exit 0)"
  cat "$MISSING_LOG"
  exit 1
fi

if ! jq -e \
  --arg expected_input "$MISSING_INPUT_JSON" \
  '
  .status == "missing"
  and .rc == 0
  and .ready_for_metrics_script == false
  and .input.input_json == $expected_input
  and .input.state == "missing"
  and .input.valid == false
  and .counts.required == 15
  and .counts.provided == 0
  and .counts.missing == 15
  and .counts.invalid == 0
  and (.missing_metric_keys | length) == 15
  ' "$MISSING_SUMMARY" >/dev/null; then
  echo "missing-input fail-soft contract mismatch"
  cat "$MISSING_SUMMARY"
  cat "$MISSING_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics-input] compatibility with metrics script source-json path"
set +e
"$METRICS_SCRIPT_UNDER_TEST" \
  --source-json "$COMPLETE_CANONICAL" \
  --summary-json "$PIPELINE_METRICS_SUMMARY" \
  --canonical-summary-json "$PIPELINE_METRICS_CANONICAL" \
  --print-summary-json 0 >"$PIPELINE_LOG" 2>&1
pipeline_rc=$?
set -e
if [[ "$pipeline_rc" -ne 0 ]]; then
  echo "expected pipeline compatibility path to exit 0"
  cat "$PIPELINE_LOG"
  exit 1
fi

if ! jq -e '
  .status == "complete"
  and .rc == 0
  and .ready_for_gate == true
  and .measurement_window_weeks == 13
  and .vpn_connect_session_success_slo_pct == 99.82
  and .paying_users_3mo_min == 1650
  and .validator_candidate_depth == 38
  and .subsidy_runway_months == 16
  and .contribution_margin_3mo == 0.9
' "$PIPELINE_METRICS_SUMMARY" >/dev/null; then
  echo "pipeline compatibility contract mismatch"
  cat "$PIPELINE_METRICS_SUMMARY"
  cat "$PIPELINE_LOG"
  exit 1
fi

echo "blockchain mainnet activation metrics input integration ok"
