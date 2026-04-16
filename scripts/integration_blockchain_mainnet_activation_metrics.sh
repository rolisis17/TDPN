#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp grep cat cmp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

HELP_LOG="$TMP_DIR/help.log"

COMPLETE_SUMMARY="$TMP_DIR/metrics_complete_summary.json"
COMPLETE_CANONICAL="$TMP_DIR/metrics_complete_canonical.json"
COMPLETE_LOG="$TMP_DIR/complete.log"

PARTIAL_SUMMARY="$TMP_DIR/metrics_partial_summary.json"
PARTIAL_CANONICAL="$TMP_DIR/metrics_partial_canonical.json"
PARTIAL_LOG="$TMP_DIR/partial.log"

SOURCE_JSON="$TMP_DIR/metrics_source.json"
SOURCE_SUMMARY="$TMP_DIR/metrics_source_summary.json"
SOURCE_CANONICAL="$TMP_DIR/metrics_source_canonical.json"
SOURCE_LOG="$TMP_DIR/source.log"

echo "[blockchain-mainnet-activation-metrics] help surface"
"$SCRIPT_UNDER_TEST" --help >"$HELP_LOG" 2>&1
if ! grep -Fq "Usage:" "$HELP_LOG"; then
  echo "help output missing Usage header"
  cat "$HELP_LOG"
  exit 1
fi
if ! grep -Fq "Produce deterministic blockchain mainnet activation metrics JSON" "$HELP_LOG"; then
  echo "help output missing purpose text"
  cat "$HELP_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics] complete metrics path"
"$SCRIPT_UNDER_TEST" \
  --measurement-window-weeks 12 \
  --vpn-connect-session-success-slo-pct 99.8 \
  --vpn-recovery-mttr-p95-minutes 18 \
  --paying-users-3mo-min 1250 \
  --paid-sessions-per-day-30d-avg 15000 \
  --validator-candidate-depth 40 \
  --validator-independent-operators 14 \
  --validator-max-operator-seat-share-pct 18 \
  --validator-max-asn-provider-seat-share-pct 22 \
  --validator-region-count 4 \
  --validator-country-count 8 \
  --manual-sanctions-reversed-pct-90d 4.5 \
  --abuse-report-to-decision-p95-hours 12 \
  --subsidy-runway-months 14 \
  --contribution-margin-3mo 1.25 \
  --summary-json "$COMPLETE_SUMMARY" \
  --canonical-summary-json "$COMPLETE_CANONICAL" \
  --print-summary-json 1 >"$COMPLETE_LOG" 2>&1

if ! jq -e \
  --arg expected_summary "$COMPLETE_SUMMARY" \
  --arg expected_canonical "$COMPLETE_CANONICAL" \
  '
  .version == 1
  and .schema.id == "blockchain_mainnet_activation_metrics_summary"
  and .status == "complete"
  and .rc == 0
  and .ready_for_gate == true
  and .counts.required == 14
  and .counts.provided == 14
  and .counts.missing == 0
  and .counts.invalid == 0
  and (.required_missing_metrics | length) == 0
  and (.invalid_metrics | length) == 0
  and .measurement_window_weeks == 12
  and .vpn_connect_session_success_slo_pct == 99.8
  and .vpn_recovery_mttr_p95_minutes == 18
  and .paying_users_3mo_min == 1250
  and .paid_sessions_per_day_30d_avg == 15000
  and .validator_candidate_depth == 40
  and .validator_independent_operators == 14
  and .validator_max_operator_seat_share_pct == 18
  and .validator_max_asn_provider_seat_share_pct == 22
  and .validator_region_count == 4
  and .validator_country_count == 8
  and .manual_sanctions_reversed_pct_90d == 4.5
  and .abuse_report_to_decision_p95_hours == 12
  and .subsidy_runway_months == 14
  and .contribution_margin_3mo == 1.25
  and .sources.metrics.paying_users_3mo_min == "cli"
  and .metrics.validator_region_count == 4
  and .artifacts.summary_json == $expected_summary
  and .artifacts.canonical_summary_json == $expected_canonical
' "$COMPLETE_SUMMARY" >/dev/null; then
  echo "complete metrics contract mismatch"
  cat "$COMPLETE_SUMMARY"
  cat "$COMPLETE_LOG"
  exit 1
fi

if [[ ! -f "$COMPLETE_CANONICAL" ]]; then
  echo "complete canonical metrics output missing"
  cat "$COMPLETE_LOG"
  exit 1
fi
if ! cmp -s "$COMPLETE_SUMMARY" "$COMPLETE_CANONICAL"; then
  echo "complete summary/canonical mismatch"
  cat "$COMPLETE_SUMMARY"
  cat "$COMPLETE_CANONICAL"
  exit 1
fi
if ! grep -Fq '"schema": {' "$COMPLETE_LOG"; then
  echo "complete log missing printed JSON payload"
  cat "$COMPLETE_LOG"
  exit 1
fi
if ! grep -Fq '[blockchain-mainnet-activation-metrics] status=complete' "$COMPLETE_LOG"; then
  echo "complete log missing status line"
  cat "$COMPLETE_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics] partial/missing fail-soft path"
set +e
BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_PAYING_USERS_3MO_MIN=1200 \
  "$SCRIPT_UNDER_TEST" \
    --vpn-connect-session-success-slo-pct not_a_number \
    --summary-json "$PARTIAL_SUMMARY" \
    --canonical-summary-json "$PARTIAL_CANONICAL" \
    --print-summary-json 0 >"$PARTIAL_LOG" 2>&1
partial_rc=$?
set -e

if [[ "$partial_rc" -ne 0 ]]; then
  echo "expected partial/missing path to remain fail-soft (exit 0)"
  cat "$PARTIAL_LOG"
  exit 1
fi

if ! jq -e \
  --arg expected_summary "$PARTIAL_SUMMARY" \
  --arg expected_canonical "$PARTIAL_CANONICAL" \
  '
  .status == "partial"
  and .rc == 0
  and .ready_for_gate == false
  and .counts.required == 14
  and .counts.provided == 1
  and .counts.missing == 13
  and .counts.invalid == 1
  and ((.required_missing_metrics // []) | index("vpn_connect_session_success_slo_pct")) != null
  and ((.required_missing_metrics // []) | index("validator_candidate_depth")) != null
  and ((.required_provided_metrics // []) | index("paying_users_3mo_min")) != null
  and ((.invalid_metrics // []) | index("vpn_connect_session_success_slo_pct")) != null
  and .paying_users_3mo_min == 1200
  and .vpn_connect_session_success_slo_pct == null
  and .sources.metrics.paying_users_3mo_min == "env"
  and .sources.metrics.vpn_connect_session_success_slo_pct == "cli_invalid"
  and .artifacts.summary_json == $expected_summary
  and .artifacts.canonical_summary_json == $expected_canonical
' "$PARTIAL_SUMMARY" >/dev/null; then
  echo "partial/missing metrics contract mismatch"
  cat "$PARTIAL_SUMMARY"
  cat "$PARTIAL_LOG"
  exit 1
fi

if [[ ! -f "$PARTIAL_CANONICAL" ]]; then
  echo "partial canonical metrics output missing"
  cat "$PARTIAL_LOG"
  exit 1
fi
if ! cmp -s "$PARTIAL_SUMMARY" "$PARTIAL_CANONICAL"; then
  echo "partial summary/canonical mismatch"
  cat "$PARTIAL_SUMMARY"
  cat "$PARTIAL_CANONICAL"
  exit 1
fi
if ! grep -Fq '[blockchain-mainnet-activation-metrics] required_missing_metrics=' "$PARTIAL_LOG"; then
  echo "partial log missing required_missing_metrics line"
  cat "$PARTIAL_LOG"
  exit 1
fi
if ! grep -Fq '[blockchain-mainnet-activation-metrics] invalid_metrics=' "$PARTIAL_LOG"; then
  echo "partial log missing invalid_metrics line"
  cat "$PARTIAL_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics] source-json autopopulation and precedence path"
cat >"$SOURCE_JSON" <<'EOF_SOURCE'
{
  "pipeline": {
    "window": {
      "measurement_window_weeks": 12
    },
    "vpn": {
      "slo": {
        "vpn_connect_session_success_slo_pct": 99.71,
        "vpn_recovery_mttr_p95_minutes": 23
      }
    }
  },
  "demand": {
    "paying_users_3mo_min": 1410,
    "paid_sessions_per_day_30d_avg": 13200
  },
  "validator": {
    "supply": {
      "validator_candidate_depth": 37,
      "validator_independent_operators": 13
    },
    "concentration": {
      "validator_max_operator_seat_share_pct": 19,
      "validator_max_asn_provider_seat_share_pct": 25
    },
    "geo": {
      "validator_region_count": 5,
      "validator_country_count": 9
    }
  },
  "governance": {
    "manual_sanctions_reversed_pct_90d": 3.9,
    "abuse_report_to_decision_p95_hours": 10
  },
  "economics": {
    "subsidy_runway_months": 16,
    "contribution_margin_3mo": 0.75
  }
}
EOF_SOURCE

set +e
BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_VALIDATOR_REGION_COUNT=7 \
  "$SCRIPT_UNDER_TEST" \
    --source-json "$SOURCE_JSON" \
    --paying-users-3mo-min 1777 \
    --summary-json "$SOURCE_SUMMARY" \
    --canonical-summary-json "$SOURCE_CANONICAL" \
    --print-summary-json 0 >"$SOURCE_LOG" 2>&1
source_rc=$?
set -e

if [[ "$source_rc" -ne 0 ]]; then
  echo "expected source-json path to remain fail-soft (exit 0)"
  cat "$SOURCE_LOG"
  exit 1
fi

if ! jq -e \
  --arg expected_source "$SOURCE_JSON" \
  --arg expected_summary "$SOURCE_SUMMARY" \
  --arg expected_canonical "$SOURCE_CANONICAL" \
  '
  .status == "complete"
  and .rc == 0
  and .ready_for_gate == true
  and .counts.required == 14
  and .counts.provided == 14
  and .counts.missing == 0
  and .counts.invalid == 0
  and .measurement_window_weeks == 12
  and .vpn_connect_session_success_slo_pct == 99.71
  and .vpn_recovery_mttr_p95_minutes == 23
  and .paying_users_3mo_min == 1777
  and .validator_region_count == 7
  and .validator_country_count == 9
  and .sources.metrics.vpn_connect_session_success_slo_pct == "source_json"
  and .sources.metrics.paying_users_3mo_min == "cli"
  and .sources.metrics.validator_region_count == "env"
  and ((.sources.source_jsons // []) | index($expected_source)) != null
  and ((.sources.usable_source_jsons // []) | index($expected_source)) != null
  and .artifacts.summary_json == $expected_summary
  and .artifacts.canonical_summary_json == $expected_canonical
  and .metrics.paying_users_3mo_min == 1777
  and .metrics.validator_region_count == 7
' "$SOURCE_SUMMARY" >/dev/null; then
  echo "source-json metrics contract mismatch"
  cat "$SOURCE_SUMMARY"
  cat "$SOURCE_LOG"
  exit 1
fi

if [[ ! -f "$SOURCE_CANONICAL" ]]; then
  echo "source-json canonical metrics output missing"
  cat "$SOURCE_LOG"
  exit 1
fi
if ! cmp -s "$SOURCE_SUMMARY" "$SOURCE_CANONICAL"; then
  echo "source-json summary/canonical mismatch"
  cat "$SOURCE_SUMMARY"
  cat "$SOURCE_CANONICAL"
  exit 1
fi
if ! grep -Fq '[blockchain-mainnet-activation-metrics] status=complete' "$SOURCE_LOG"; then
  echo "source-json log missing status line"
  cat "$SOURCE_LOG"
  exit 1
fi

echo "blockchain mainnet activation metrics integration ok"
