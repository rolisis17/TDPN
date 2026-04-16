#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp grep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/blockchain_mainnet_activation_gate.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

GO_METRICS="$TMP_DIR/metrics_go.json"
NO_GO_METRICS="$TMP_DIR/metrics_no_go.json"
WINDOW_SHORT_METRICS="$TMP_DIR/metrics_window_short.json"
WINDOW_INVALID_METRICS="$TMP_DIR/metrics_window_invalid.json"
INVALID_METRICS="$TMP_DIR/metrics_invalid.json"
MISSING_METRICS="$TMP_DIR/does_not_exist.json"

GO_SUMMARY="$TMP_DIR/summary_go.json"
NO_GO_SUMMARY="$TMP_DIR/summary_no_go.json"
WINDOW_SHORT_SUMMARY="$TMP_DIR/summary_window_short.json"
WINDOW_INVALID_SUMMARY="$TMP_DIR/summary_window_invalid.json"
MISSING_SUMMARY="$TMP_DIR/summary_missing.json"
INVALID_SUMMARY="$TMP_DIR/summary_invalid.json"
FAIL_CLOSE_SUMMARY="$TMP_DIR/summary_fail_close.json"

GO_LOG="$TMP_DIR/go.log"
NO_GO_LOG="$TMP_DIR/no_go.log"
WINDOW_SHORT_LOG="$TMP_DIR/window_short.log"
WINDOW_INVALID_LOG="$TMP_DIR/window_invalid.log"
MISSING_LOG="$TMP_DIR/missing.log"
INVALID_LOG="$TMP_DIR/invalid.log"
FAIL_CLOSE_LOG="$TMP_DIR/fail_close.log"

cat >"$GO_METRICS" <<'EOF_GO'
{
  "measurement_window_weeks": 12,
  "vpn_connect_session_success_slo_pct": 99.8,
  "vpn_recovery_mttr_p95_minutes": 18,
  "paying_users_3mo_min": 1250,
  "paid_sessions_per_day_30d_avg": 15000,
  "validator_candidate_depth": 40,
  "validator_independent_operators": 14,
  "validator_max_operator_seat_share_pct": 18,
  "validator_max_asn_provider_seat_share_pct": 22,
  "validator_region_count": 4,
  "validator_country_count": 8,
  "manual_sanctions_reversed_pct_90d": 4.5,
  "abuse_report_to_decision_p95_hours": 12,
  "subsidy_runway_months": 14,
  "contribution_margin_3mo": 1.25
}
EOF_GO

cat >"$NO_GO_METRICS" <<'EOF_NO_GO'
{
  "measurement_window_weeks": 12,
  "vpn_connect_session_success_slo_pct": 99.7,
  "vpn_recovery_mttr_p95_minutes": 34,
  "paying_users_3mo_min": 980,
  "paid_sessions_per_day_30d_avg": 9000,
  "validator_candidate_depth": 24,
  "validator_independent_operators": 11,
  "validator_max_operator_seat_share_pct": 21,
  "validator_max_asn_provider_seat_share_pct": 29,
  "validator_region_count": 3,
  "validator_country_count": 7,
  "manual_sanctions_reversed_pct_90d": 6.2,
  "abuse_report_to_decision_p95_hours": 30,
  "subsidy_runway_months": 9,
  "contribution_margin_3mo": -0.75
}
EOF_NO_GO

cat >"$WINDOW_SHORT_METRICS" <<'EOF_WINDOW_SHORT'
{
  "measurement_window_weeks": 11,
  "vpn_connect_session_success_slo_pct": 99.8,
  "vpn_recovery_mttr_p95_minutes": 18,
  "paying_users_3mo_min": 1250,
  "paid_sessions_per_day_30d_avg": 15000,
  "validator_candidate_depth": 40,
  "validator_independent_operators": 14,
  "validator_max_operator_seat_share_pct": 18,
  "validator_max_asn_provider_seat_share_pct": 22,
  "validator_region_count": 4,
  "validator_country_count": 8,
  "manual_sanctions_reversed_pct_90d": 4.5,
  "abuse_report_to_decision_p95_hours": 12,
  "subsidy_runway_months": 14,
  "contribution_margin_3mo": 1.25
}
EOF_WINDOW_SHORT

cat >"$WINDOW_INVALID_METRICS" <<'EOF_WINDOW_INVALID'
{
  "measurement_window_weeks": "invalid",
  "vpn_connect_session_success_slo_pct": 99.8,
  "vpn_recovery_mttr_p95_minutes": 18,
  "paying_users_3mo_min": 1250,
  "paid_sessions_per_day_30d_avg": 15000,
  "validator_candidate_depth": 40,
  "validator_independent_operators": 14,
  "validator_max_operator_seat_share_pct": 18,
  "validator_max_asn_provider_seat_share_pct": 22,
  "validator_region_count": 4,
  "validator_country_count": 8,
  "manual_sanctions_reversed_pct_90d": 4.5,
  "abuse_report_to_decision_p95_hours": 12,
  "subsidy_runway_months": 14,
  "contribution_margin_3mo": 1.25
}
EOF_WINDOW_INVALID

cat >"$INVALID_METRICS" <<'EOF_INVALID'
{
  "measurement_window_weeks": 12,
  "vpn_connect_session_success_slo_pct": 99.8,
EOF_INVALID

echo "[blockchain-mainnet-activation-gate] GO path"
BLOCKCHAIN_MAINNET_ACTIVATION_GATE_METRICS_JSON="$GO_METRICS" \
  "$SCRIPT_UNDER_TEST" \
  --summary-json "$GO_SUMMARY" \
  --print-summary-json 1 >"$GO_LOG" 2>&1

jq -e --arg metrics_path "$GO_METRICS" '
  .decision == "GO"
  and .status == "go"
  and .rc == 0
  and .exit_code == 0
  and .counts.required == 13
  and .counts.evaluated == 13
  and .counts.pass == 13
  and .counts.fail == 0
  and (.failed_gate_ids | length) == 0
  and (.failed_reasons | length) == 0
  and (.gates | length) == 13
  and .input.state == "available"
  and .input.valid == true
  and (.reasons | length) == 0
  and (.source_paths | length) == 1
  and .source_paths[0] == $metrics_path
  and .artifacts.metrics_json == $metrics_path
' "$GO_SUMMARY" >/dev/null
if ! grep -Fq '"decision": "GO"' "$GO_LOG"; then
  echo "expected GO summary JSON in stdout log"
  cat "$GO_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-gate] NO-GO path"
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$NO_GO_METRICS" \
  --summary-json "$NO_GO_SUMMARY" \
  --print-summary-json 0 >"$NO_GO_LOG" 2>&1

jq -e --arg metrics_path "$NO_GO_METRICS" '
  .decision == "NO-GO"
  and .status == "no-go"
  and .rc == 1
  and .exit_code == 0
  and .counts.required == 13
  and .counts.evaluated == 13
  and .counts.pass < 13
  and .counts.fail > 0
  and (.failed_gate_ids | length) > 0
  and (.failed_reasons | length) > 0
  and (.failed_gate_ids | index("vpn_recovery_mttr_p95")) != null
  and (.failed_gate_ids | index("validator_operator_concentration")) != null
  and (.failed_gate_ids | index("unit_economics")) != null
  and (.reasons | length) > 0
  and ((.reasons | index("vpn_recovery_mttr_p95_minutes=34 does not satisfy <= 30")) != null)
  and (.source_paths | length) == 1
  and .source_paths[0] == $metrics_path
  and .artifacts.metrics_json == $metrics_path
' "$NO_GO_SUMMARY" >/dev/null
if ! grep -Fq '[blockchain-mainnet-activation-gate] decision=NO-GO' "$NO_GO_LOG"; then
  echo "expected NO-GO decision log line"
  cat "$NO_GO_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-gate] NO-GO measurement window too short"
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$WINDOW_SHORT_METRICS" \
  --summary-json "$WINDOW_SHORT_SUMMARY" \
  --print-summary-json 0 >"$WINDOW_SHORT_LOG" 2>&1

jq -e --arg metrics_path "$WINDOW_SHORT_METRICS" '
  .decision == "NO-GO"
  and .status == "no-go"
  and .rc == 1
  and .exit_code == 0
  and .counts.required == 13
  and .counts.evaluated == 13
  and .counts.pass == 12
  and .counts.fail == 1
  and .failed_gate_ids == ["measurement_window_weeks"]
  and (.failed_reasons | length) == 1
  and ((.failed_reasons | index("measurement_window_weeks=11 does not satisfy >= 12")) != null)
  and ((.reasons | index("measurement_window_weeks=11 does not satisfy >= 12")) != null)
  and (.source_paths | length) == 1
  and .source_paths[0] == $metrics_path
  and .artifacts.metrics_json == $metrics_path
' "$WINDOW_SHORT_SUMMARY" >/dev/null
if ! grep -Fq '[blockchain-mainnet-activation-gate] decision=NO-GO' "$WINDOW_SHORT_LOG"; then
  echo "expected measurement-window short NO-GO decision log line"
  cat "$WINDOW_SHORT_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-gate] NO-GO measurement window missing-or-invalid"
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$WINDOW_INVALID_METRICS" \
  --summary-json "$WINDOW_INVALID_SUMMARY" \
  --print-summary-json 0 >"$WINDOW_INVALID_LOG" 2>&1

jq -e --arg metrics_path "$WINDOW_INVALID_METRICS" '
  .decision == "NO-GO"
  and .status == "no-go"
  and .rc == 1
  and .exit_code == 0
  and .counts.required == 13
  and .counts.evaluated == 13
  and .counts.pass == 12
  and .counts.fail == 1
  and .failed_gate_ids == ["measurement_window_weeks"]
  and (.failed_reasons | length) == 1
  and ((.failed_reasons | index("missing or invalid metric: measurement_window_weeks")) != null)
  and ((.reasons | index("missing or invalid metric: measurement_window_weeks")) != null)
  and (.source_paths | length) == 1
  and .source_paths[0] == $metrics_path
  and .artifacts.metrics_json == $metrics_path
' "$WINDOW_INVALID_SUMMARY" >/dev/null
if ! grep -Fq '[blockchain-mainnet-activation-gate] decision=NO-GO' "$WINDOW_INVALID_LOG"; then
  echo "expected measurement-window invalid NO-GO decision log line"
  cat "$WINDOW_INVALID_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-gate] missing input path"
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$MISSING_METRICS" \
  --summary-json "$MISSING_SUMMARY" \
  --print-summary-json 0 >"$MISSING_LOG" 2>&1
missing_rc=$?
set -e
if [[ "$missing_rc" -ne 0 ]]; then
  echo "expected missing-input path to stay non-failing without fail-close"
  cat "$MISSING_LOG"
  exit 1
fi
jq -e --arg metrics_path "$MISSING_METRICS" '
  .decision == "NO-GO"
  and .status == "no-go"
  and .rc == 1
  and .exit_code == 0
  and .input.state == "missing"
  and .input.valid == false
  and .failed_gate_ids == ["metrics_input"]
  and (.failed_reasons | length) == 1
  and (.reasons | length) > 0
  and ((.reasons | index("metrics JSON file not found: " + $metrics_path)) != null)
  and (.source_paths | length) == 1
  and .source_paths[0] == $metrics_path
  and .artifacts.metrics_json == $metrics_path
' "$MISSING_SUMMARY" >/dev/null

echo "[blockchain-mainnet-activation-gate] invalid input with fail-close"
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$INVALID_METRICS" \
  --summary-json "$INVALID_SUMMARY" \
  --fail-close 1 \
  --print-summary-json 0 >"$INVALID_LOG" 2>&1
invalid_rc=$?
set -e
if [[ "$invalid_rc" -eq 0 ]]; then
  echo "expected invalid-input path to fail closed"
  cat "$INVALID_LOG"
  exit 1
fi
jq -e --arg metrics_path "$INVALID_METRICS" '
  .decision == "NO-GO"
  and .status == "no-go"
  and .rc == 1
  and .exit_code == 1
  and .input.state == "invalid"
  and .input.valid == false
  and .failed_gate_ids == ["metrics_input"]
  and (.reasons | length) > 0
  and ((.reasons | index("metrics JSON is not valid JSON: " + $metrics_path)) != null)
  and (.source_paths | length) == 1
  and .source_paths[0] == $metrics_path
  and .artifacts.metrics_json == $metrics_path
' "$INVALID_SUMMARY" >/dev/null

echo "[blockchain-mainnet-activation-gate] NO-GO with fail-close"
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$NO_GO_METRICS" \
  --summary-json "$FAIL_CLOSE_SUMMARY" \
  --fail-close 1 \
  --print-summary-json 0 >"$FAIL_CLOSE_LOG" 2>&1
fail_close_rc=$?
set -e
if [[ "$fail_close_rc" -eq 0 ]]; then
  echo "expected NO-GO path to fail closed when requested"
  cat "$FAIL_CLOSE_LOG"
  exit 1
fi
jq -e '
  .decision == "NO-GO"
  and .status == "no-go"
  and .rc == 1
  and .exit_code == 1
  and .counts.fail > 0
' "$FAIL_CLOSE_SUMMARY" >/dev/null
if ! grep -Fq '[blockchain-mainnet-activation-gate] decision=NO-GO' "$FAIL_CLOSE_LOG"; then
  echo "expected fail-close NO-GO log line"
  cat "$FAIL_CLOSE_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-gate] reject flag-like metrics path"
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json --summary-json "$TMP_DIR/bad_metrics_path_summary.json" \
  --print-summary-json 0 >"$TMP_DIR/bad_metrics_path.log" 2>&1
bad_metrics_path_rc=$?
set -e
if [[ "$bad_metrics_path_rc" -eq 0 ]]; then
  echo "expected flag-like metrics path to fail parsing"
  cat "$TMP_DIR/bad_metrics_path.log"
  exit 1
fi
if [[ "$bad_metrics_path_rc" -ne 2 ]]; then
  echo "expected flag-like metrics path to exit 2"
  cat "$TMP_DIR/bad_metrics_path.log"
  exit 1
fi
if ! grep -Fq 'flag-like token: --summary-json' "$TMP_DIR/bad_metrics_path.log"; then
  echo "expected flag-like token rejection message"
  cat "$TMP_DIR/bad_metrics_path.log"
  exit 1
fi

echo "[blockchain-mainnet-activation-gate] ok"
