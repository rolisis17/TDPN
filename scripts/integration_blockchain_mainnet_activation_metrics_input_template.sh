#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp grep cat cmp cp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_INPUT_TEMPLATE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics_input_template.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
DEFAULT_OUTPUT="$ROOT_DIR/.easy-node-logs/blockchain_mainnet_activation_metrics_input_template.json"
DEFAULT_BACKUP="$TMP_DIR/default_output_backup.json"
DEFAULT_HAD_FILE="0"

cleanup() {
  if [[ "$DEFAULT_HAD_FILE" == "1" ]]; then
    cp "$DEFAULT_BACKUP" "$DEFAULT_OUTPUT"
  else
    rm -f "$DEFAULT_OUTPUT"
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

if [[ -f "$DEFAULT_OUTPUT" ]]; then
  cp "$DEFAULT_OUTPUT" "$DEFAULT_BACKUP"
  DEFAULT_HAD_FILE="1"
fi

HELP_LOG="$TMP_DIR/help.log"
DEFAULT_LOG="$TMP_DIR/default.log"
DEFAULT_RUN_SNAPSHOT="$TMP_DIR/default_snapshot.json"
ALIAS_LOG="$TMP_DIR/alias.log"
EXPLICIT_LOG="$TMP_DIR/explicit.log"
SAME_PATH_LOG="$TMP_DIR/same_path.log"
EXAMPLES_LOG="$TMP_DIR/examples.log"

EXPLICIT_OUTPUT="$TMP_DIR/template_output.json"
EXPLICIT_CANONICAL="$TMP_DIR/template_canonical.json"
ALIAS_OUTPUT="$TMP_DIR/template_alias_output.json"
SAME_PATH_OUTPUT="$TMP_DIR/template_same_path.json"
EXAMPLES_OUTPUT="$TMP_DIR/template_examples_output.json"
EXAMPLES_CANONICAL="$TMP_DIR/template_examples_canonical.json"

echo "[blockchain-mainnet-activation-metrics-input-template] help surface"
bash "$SCRIPT_UNDER_TEST" --help >"$HELP_LOG" 2>&1
if ! grep -Fq "Usage:" "$HELP_LOG"; then
  echo "help output missing Usage header"
  cat "$HELP_LOG"
  exit 1
fi
if ! grep -Fq -- "--output-json" "$HELP_LOG"; then
  echo "help output missing --output-json"
  cat "$HELP_LOG"
  exit 1
fi
if ! grep -Fq -- "--canonical-output-json" "$HELP_LOG"; then
  echo "help output missing --canonical-output-json"
  cat "$HELP_LOG"
  exit 1
fi
if ! grep -Fq -- "--include-example-values" "$HELP_LOG"; then
  echo "help output missing --include-example-values"
  cat "$HELP_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics-input-template] default path contract"
set +e
bash "$SCRIPT_UNDER_TEST" --print-output-json 0 >"$DEFAULT_LOG" 2>&1
default_rc=$?
set -e
if [[ "$default_rc" -ne 0 ]]; then
  echo "default path run must exit 0"
  cat "$DEFAULT_LOG"
  exit 1
fi
if [[ ! -f "$DEFAULT_OUTPUT" ]]; then
  echo "default output file missing: $DEFAULT_OUTPUT"
  cat "$DEFAULT_LOG"
  exit 1
fi
if ! jq -e \
  --arg expected "$DEFAULT_OUTPUT" \
  '
  .version == 1
  and .schema.id == "blockchain_mainnet_activation_metrics_input_template"
  and .status == "ok"
  and .include_example_values == false
  and .general.measurement_window_weeks == null
  and .reliability.vpn_connect_session_success_slo_pct == null
  and .reliability.vpn_recovery_mttr_p95_minutes == null
  and .demand.paying_users_3mo_min == null
  and .demand.paid_sessions_per_day_30d_avg == null
  and .validator.validator_candidate_depth == null
  and .validator.validator_independent_operators == null
  and .validator.validator_max_operator_seat_share_pct == null
  and .validator.validator_max_asn_provider_seat_share_pct == null
  and .validator.validator_region_count == null
  and .validator.validator_country_count == null
  and .governance.manual_sanctions_reversed_pct_90d == null
  and .governance.abuse_report_to_decision_p95_hours == null
  and .economics.subsidy_runway_months == null
  and .economics.contribution_margin_3mo == null
  and .measurement_window_weeks == null
  and .vpn_connect_session_success_slo_pct == null
  and .vpn_recovery_mttr_p95_minutes == null
  and .paying_users_3mo_min == null
  and .paid_sessions_per_day_30d_avg == null
  and .validator_candidate_depth == null
  and .validator_independent_operators == null
  and .validator_max_operator_seat_share_pct == null
  and .validator_max_asn_provider_seat_share_pct == null
  and .validator_region_count == null
  and .validator_country_count == null
  and .manual_sanctions_reversed_pct_90d == null
  and .abuse_report_to_decision_p95_hours == null
  and .subsidy_runway_months == null
  and .contribution_margin_3mo == null
  and .artifacts.output_json == $expected
  and .artifacts.canonical_output_json == $expected
  ' "$DEFAULT_OUTPUT" >/dev/null; then
  echo "default output contract mismatch"
  cat "$DEFAULT_OUTPUT"
  cat "$DEFAULT_LOG"
  exit 1
fi

cp "$DEFAULT_OUTPUT" "$DEFAULT_RUN_SNAPSHOT"
bash "$SCRIPT_UNDER_TEST" --print-output-json 0 >/dev/null 2>&1
if ! cmp -s "$DEFAULT_RUN_SNAPSHOT" "$DEFAULT_OUTPUT"; then
  echo "default output is not deterministic across runs"
  cat "$DEFAULT_RUN_SNAPSHOT"
  cat "$DEFAULT_OUTPUT"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics-input-template] --print-summary-json alias compatibility"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --output-json "$ALIAS_OUTPUT" \
  --print-summary-json 0 >"$ALIAS_LOG" 2>&1
alias_rc=$?
set -e
if [[ "$alias_rc" -ne 0 ]]; then
  echo "print-summary-json alias run must exit 0"
  cat "$ALIAS_LOG"
  exit 1
fi
if [[ ! -f "$ALIAS_OUTPUT" ]]; then
  echo "alias output file missing: $ALIAS_OUTPUT"
  cat "$ALIAS_LOG"
  exit 1
fi
if ! jq -e '.status == "ok" and .include_example_values == false' "$ALIAS_OUTPUT" >/dev/null; then
  echo "alias output contract mismatch"
  cat "$ALIAS_OUTPUT"
  cat "$ALIAS_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics-input-template] explicit output and canonical paths"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --output-json "$EXPLICIT_OUTPUT" \
  --canonical-output-json "$EXPLICIT_CANONICAL" \
  --print-output-json 0 >"$EXPLICIT_LOG" 2>&1
explicit_rc=$?
set -e
if [[ "$explicit_rc" -ne 0 ]]; then
  echo "explicit path run must exit 0"
  cat "$EXPLICIT_LOG"
  exit 1
fi
if [[ ! -f "$EXPLICIT_OUTPUT" || ! -f "$EXPLICIT_CANONICAL" ]]; then
  echo "explicit path output/canonical artifact missing"
  cat "$EXPLICIT_LOG"
  exit 1
fi
if ! cmp -s "$EXPLICIT_OUTPUT" "$EXPLICIT_CANONICAL"; then
  echo "explicit output and canonical files should match"
  cat "$EXPLICIT_OUTPUT"
  cat "$EXPLICIT_CANONICAL"
  exit 1
fi
if ! jq -e \
  --arg expected_output "$EXPLICIT_OUTPUT" \
  --arg expected_canonical "$EXPLICIT_CANONICAL" \
  '
  .include_example_values == false
  and .measurement_window_weeks == null
  and .vpn_connect_session_success_slo_pct == null
  and .contribution_margin_3mo == null
  and .artifacts.output_json == $expected_output
  and .artifacts.canonical_output_json == $expected_canonical
  ' "$EXPLICIT_OUTPUT" >/dev/null; then
  echo "explicit path artifact metadata mismatch"
  cat "$EXPLICIT_OUTPUT"
  cat "$EXPLICIT_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics-input-template] canonical same-path support"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --output-json "$SAME_PATH_OUTPUT" \
  --canonical-output-json "$SAME_PATH_OUTPUT" \
  --print-output-json 0 >"$SAME_PATH_LOG" 2>&1
same_path_rc=$?
set -e
if [[ "$same_path_rc" -ne 0 ]]; then
  echo "same output/canonical path run must exit 0"
  cat "$SAME_PATH_LOG"
  exit 1
fi
if [[ ! -f "$SAME_PATH_OUTPUT" ]]; then
  echo "same-path output artifact missing"
  cat "$SAME_PATH_LOG"
  exit 1
fi
if ! jq -e \
  --arg expected "$SAME_PATH_OUTPUT" \
  '.artifacts.output_json == $expected and .artifacts.canonical_output_json == $expected' \
  "$SAME_PATH_OUTPUT" >/dev/null; then
  echo "same-path artifacts metadata mismatch"
  cat "$SAME_PATH_OUTPUT"
  cat "$SAME_PATH_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics-input-template] example-values toggle"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --output-json "$EXAMPLES_OUTPUT" \
  --canonical-output-json "$EXAMPLES_CANONICAL" \
  --include-example-values 1 \
  --print-output-json 1 >"$EXAMPLES_LOG" 2>&1
examples_rc=$?
set -e
if [[ "$examples_rc" -ne 0 ]]; then
  echo "example-values run must exit 0"
  cat "$EXAMPLES_LOG"
  exit 1
fi
if [[ ! -f "$EXAMPLES_OUTPUT" || ! -f "$EXAMPLES_CANONICAL" ]]; then
  echo "example-values output/canonical artifacts missing"
  cat "$EXAMPLES_LOG"
  exit 1
fi
if ! grep -Fq '"include_example_values": true' "$EXAMPLES_LOG"; then
  echo "print-output-json did not emit template JSON with include_example_values=true"
  cat "$EXAMPLES_LOG"
  exit 1
fi
if ! jq -e '
  .include_example_values == true
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
  and .general.measurement_window_weeks == 13
  and .reliability.vpn_connect_session_success_slo_pct == 99.82
  and .reliability.vpn_recovery_mttr_p95_minutes == 19
  and .demand.paying_users_3mo_min == 1650
  and .demand.paid_sessions_per_day_30d_avg == 15500
  and .validator.validator_candidate_depth == 38
  and .validator.validator_independent_operators == 14
  and .validator.validator_max_operator_seat_share_pct == 18.5
  and .validator.validator_max_asn_provider_seat_share_pct == 22
  and .validator.validator_region_count == 5
  and .validator.validator_country_count == 9
  and .governance.manual_sanctions_reversed_pct_90d == 4.2
  and .governance.abuse_report_to_decision_p95_hours == 11
  and .economics.subsidy_runway_months == 16
  and .economics.contribution_margin_3mo == 0.9
  and ([.measurement_window_weeks, .vpn_connect_session_success_slo_pct, .vpn_recovery_mttr_p95_minutes, .paying_users_3mo_min, .paid_sessions_per_day_30d_avg, .validator_candidate_depth, .validator_independent_operators, .validator_max_operator_seat_share_pct, .validator_max_asn_provider_seat_share_pct, .validator_region_count, .validator_country_count, .manual_sanctions_reversed_pct_90d, .abuse_report_to_decision_p95_hours, .subsidy_runway_months, .contribution_margin_3mo] | all(. != null))
' "$EXAMPLES_OUTPUT" >/dev/null; then
  echo "example-values contract mismatch"
  cat "$EXAMPLES_OUTPUT"
  cat "$EXAMPLES_LOG"
  exit 1
fi

echo "blockchain mainnet activation metrics input template integration ok"
