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

SCRIPT_UNDER_TEST="${BLOCKCHAIN_BOOTSTRAP_GRADUATION_GATE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/blockchain_bootstrap_graduation_gate.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

GO_METRICS="$TMP_DIR/metrics_go.json"
NO_GO_METRICS="$TMP_DIR/metrics_no_go.json"
INVALID_METRICS="$TMP_DIR/metrics_invalid.json"
MISSING_METRICS="$TMP_DIR/does_not_exist.json"

GO_SUMMARY="$TMP_DIR/summary_go.json"
NO_GO_SUMMARY="$TMP_DIR/summary_no_go.json"
MISSING_SUMMARY="$TMP_DIR/summary_missing.json"
INVALID_SUMMARY="$TMP_DIR/summary_invalid.json"
FAIL_CLOSE_SUMMARY="$TMP_DIR/summary_fail_close.json"

GO_LOG="$TMP_DIR/go.log"
NO_GO_LOG="$TMP_DIR/no_go.log"
MISSING_LOG="$TMP_DIR/missing.log"
INVALID_LOG="$TMP_DIR/invalid.log"
FAIL_CLOSE_LOG="$TMP_DIR/fail_close.log"

cat >"$GO_METRICS" <<'EOF_GO'
{
  "measurement_window_weeks": 12,
  "validator_candidate_depth": 38,
  "validator_independent_operators": 13,
  "validator_max_operator_seat_share_pct": 19,
  "validator_max_asn_provider_seat_share_pct": 21,
  "validator_region_count": 4,
  "validator_country_count": 9,
  "manual_sanctions_reversed_pct_90d": 3.5,
  "abuse_report_to_decision_p95_hours": 11,
  "vpn_connect_session_success_slo_pct": 99.8,
  "vpn_recovery_mttr_p95_minutes": 24
}
EOF_GO

cat >"$NO_GO_METRICS" <<'EOF_NO_GO'
{
  "measurement_window_weeks": 12,
  "validator_candidate_depth": 20,
  "validator_independent_operators": 10,
  "validator_max_operator_seat_share_pct": 24,
  "validator_max_asn_provider_seat_share_pct": 31,
  "validator_region_count": 3,
  "validator_country_count": 6,
  "manual_sanctions_reversed_pct_90d": 8.1,
  "abuse_report_to_decision_p95_hours": 39,
  "vpn_connect_session_success_slo_pct": 98.2,
  "vpn_recovery_mttr_p95_minutes": 63
}
EOF_NO_GO

cat >"$INVALID_METRICS" <<'EOF_INVALID'
{
  "measurement_window_weeks": 12,
  "validator_candidate_depth": 38,
EOF_INVALID

echo "[blockchain-bootstrap-graduation-gate] GO path"
BLOCKCHAIN_BOOTSTRAP_GRADUATION_GATE_METRICS_JSON="$GO_METRICS" \
  "$SCRIPT_UNDER_TEST" \
  --summary-json "$GO_SUMMARY" \
  --print-summary-json 1 >"$GO_LOG" 2>&1

jq -e --arg metrics_path "$GO_METRICS" '
  .decision == "GO"
  and .status == "go"
  and .go == true
  and .no_go == false
  and .rc == 0
  and .exit_code == 0
  and .counts.required == 9
  and .counts.evaluated == 9
  and .counts.pass == 9
  and .counts.fail == 0
  and (.failed_gate_ids | length) == 0
  and (.failed_reasons | length) == 0
  and (.reasons | length) == 0
  and (.gates | length) == 9
  and .input.state == "available"
  and .input.valid == true
  and (.source_paths | length) == 1
  and .source_paths[0] == $metrics_path
  and .artifacts.metrics_json == $metrics_path
' "$GO_SUMMARY" >/dev/null
if ! grep -Fq '"decision": "GO"' "$GO_LOG"; then
  echo "expected GO summary JSON in stdout log"
  cat "$GO_LOG"
  exit 1
fi

echo "[blockchain-bootstrap-graduation-gate] NO-GO path"
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$NO_GO_METRICS" \
  --summary-json "$NO_GO_SUMMARY" \
  --print-summary-json 0 >"$NO_GO_LOG" 2>&1

jq -e --arg metrics_path "$NO_GO_METRICS" '
  .decision == "NO-GO"
  and .status == "no-go"
  and .go == false
  and .no_go == true
  and .rc == 1
  and .exit_code == 0
  and .counts.required == 9
  and .counts.evaluated == 9
  and .counts.pass < 9
  and .counts.fail > 0
  and (.failed_gate_ids | length) > 0
  and (.failed_reasons | length) > 0
  and ((.failed_gate_ids | index("validator_candidate_depth")) != null)
  and ((.failed_gate_ids | index("validator_operator_concentration")) != null)
  and ((.failed_gate_ids | index("manual_sanctions_reversal_rate")) != null)
  and ((.failed_gate_ids | index("vpn_recovery_mttr_p95")) != null)
  and ((.reasons | index("validator_candidate_depth=20 does not satisfy >= 30")) != null)
  and (.source_paths | length) == 1
  and .source_paths[0] == $metrics_path
  and .artifacts.metrics_json == $metrics_path
' "$NO_GO_SUMMARY" >/dev/null
if ! grep -Fq '[blockchain-bootstrap-graduation-gate] decision=NO-GO' "$NO_GO_LOG"; then
  echo "expected NO-GO decision log line"
  cat "$NO_GO_LOG"
  exit 1
fi

echo "[blockchain-bootstrap-graduation-gate] missing input path"
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
  and .go == false
  and .no_go == true
  and .rc == 1
  and .exit_code == 0
  and .input.state == "missing"
  and .input.valid == false
  and .failed_gate_ids == ["metrics_input"]
  and (.reasons | length) > 0
  and ((.reasons | index("metrics JSON file not found: " + $metrics_path)) != null)
  and (.source_paths | length) == 1
  and .source_paths[0] == $metrics_path
  and .artifacts.metrics_json == $metrics_path
' "$MISSING_SUMMARY" >/dev/null

echo "[blockchain-bootstrap-graduation-gate] invalid input with fail-close"
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
  and .go == false
  and .no_go == true
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

echo "[blockchain-bootstrap-graduation-gate] NO-GO with fail-close"
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
  and .go == false
  and .no_go == true
  and .rc == 1
  and .exit_code == 1
  and .counts.fail > 0
' "$FAIL_CLOSE_SUMMARY" >/dev/null
if ! grep -Fq '[blockchain-bootstrap-graduation-gate] decision=NO-GO' "$FAIL_CLOSE_LOG"; then
  echo "expected fail-close NO-GO log line"
  cat "$FAIL_CLOSE_LOG"
  exit 1
fi

echo "[blockchain-bootstrap-graduation-gate] reject flag-like metrics path"
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

echo "blockchain bootstrap graduation gate integration check ok"
