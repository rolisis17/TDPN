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
METRICS_SCRIPT_UNDER_TEST="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics.sh}"
if [[ ! -x "$METRICS_SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable metrics script under test: $METRICS_SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

GO_METRICS="$TMP_DIR/metrics_go.json"
PRODUCTION_EVIDENCE_SOURCE="$TMP_DIR/metrics_go_production_evidence.json"
NO_GO_METRICS="$TMP_DIR/metrics_no_go.json"
WINDOW_SHORT_METRICS="$TMP_DIR/metrics_window_short.json"
WINDOW_INVALID_METRICS="$TMP_DIR/metrics_window_invalid.json"
SEMANTIC_INVALID_METRICS="$TMP_DIR/metrics_semantic_invalid.json"
INVALID_METRICS="$TMP_DIR/metrics_invalid.json"
ARRAY_METRICS="$TMP_DIR/metrics_array.json"
MISSING_METRICS="$TMP_DIR/does_not_exist.json"

GO_SUMMARY="$TMP_DIR/summary_go.json"
REAL_EVIDENCE_METRICS_SUMMARY="$TMP_DIR/metrics_real_evidence_summary.json"
REAL_EVIDENCE_METRICS_CANONICAL="$TMP_DIR/metrics_real_evidence_canonical.json"
REAL_EVIDENCE_SUMMARY="$TMP_DIR/summary_real_evidence_go.json"
TAMPERED_EVIDENCE_SOURCE="$TMP_DIR/metrics_tampered_source.json"
TAMPERED_EVIDENCE_METRICS_SUMMARY="$TMP_DIR/metrics_tampered_evidence_summary.json"
TAMPERED_EVIDENCE_METRICS_CANONICAL="$TMP_DIR/metrics_tampered_evidence_canonical.json"
TAMPERED_EVIDENCE_METRICS_MUTATED="$TMP_DIR/metrics_tampered_evidence_mutated.json"
TAMPERED_EVIDENCE_SUMMARY="$TMP_DIR/summary_tampered_evidence_rejected.json"
SHA_MISMATCH_EVIDENCE_SOURCE="$TMP_DIR/metrics_sha_mismatch_source.json"
SHA_MISMATCH_EVIDENCE_METRICS_SUMMARY="$TMP_DIR/metrics_sha_mismatch_evidence_summary.json"
SHA_MISMATCH_EVIDENCE_METRICS_CANONICAL="$TMP_DIR/metrics_sha_mismatch_evidence_canonical.json"
SHA_MISMATCH_EVIDENCE_SUMMARY="$TMP_DIR/summary_sha_mismatch_evidence_rejected.json"
SYMLINK_EVIDENCE_SOURCE="$TMP_DIR/metrics_symlink_source.json"
SYMLINK_EVIDENCE_METRICS_SUMMARY="$TMP_DIR/metrics_symlink_evidence_summary.json"
SYMLINK_EVIDENCE_METRICS_CANONICAL="$TMP_DIR/metrics_symlink_evidence_canonical.json"
SYMLINK_EVIDENCE_SUMMARY="$TMP_DIR/summary_symlink_evidence_rejected.json"
STALE_EVIDENCE_SOURCE="$TMP_DIR/metrics_stale_production_evidence.json"
STALE_EVIDENCE_METRICS_SUMMARY="$TMP_DIR/metrics_stale_evidence_summary.json"
STALE_EVIDENCE_METRICS_CANONICAL="$TMP_DIR/metrics_stale_evidence_canonical.json"
STALE_EVIDENCE_SUMMARY="$TMP_DIR/summary_stale_evidence_rejected.json"
FUTURE_EVIDENCE_SOURCE="$TMP_DIR/metrics_future_production_evidence.json"
FUTURE_EVIDENCE_METRICS_SUMMARY="$TMP_DIR/metrics_future_evidence_summary.json"
FUTURE_EVIDENCE_METRICS_CANONICAL="$TMP_DIR/metrics_future_evidence_canonical.json"
FUTURE_EVIDENCE_SUMMARY="$TMP_DIR/summary_future_evidence_rejected.json"
FAKE_EVIDENCE_SUMMARY="$TMP_DIR/summary_fake_evidence_rejected.json"
FAKE_SOURCE_METRICS_SUMMARY="$TMP_DIR/metrics_fake_source_summary.json"
FAKE_SOURCE_METRICS_CANONICAL="$TMP_DIR/metrics_fake_source_canonical.json"
FAKE_SOURCE_EVIDENCE_SUMMARY="$TMP_DIR/summary_fake_source_evidence_rejected.json"
NO_GO_SUMMARY="$TMP_DIR/summary_no_go.json"
WINDOW_SHORT_SUMMARY="$TMP_DIR/summary_window_short.json"
WINDOW_INVALID_SUMMARY="$TMP_DIR/summary_window_invalid.json"
SEMANTIC_INVALID_SUMMARY="$TMP_DIR/summary_semantic_invalid.json"
MISSING_SUMMARY="$TMP_DIR/summary_missing.json"
INVALID_SUMMARY="$TMP_DIR/summary_invalid.json"
FAIL_CLOSE_SUMMARY="$TMP_DIR/summary_fail_close.json"

GO_LOG="$TMP_DIR/go.log"
REAL_EVIDENCE_LOG="$TMP_DIR/real_evidence.log"
TAMPERED_EVIDENCE_LOG="$TMP_DIR/tampered_evidence.log"
SHA_MISMATCH_EVIDENCE_LOG="$TMP_DIR/sha_mismatch_evidence.log"
SYMLINK_EVIDENCE_LOG="$TMP_DIR/symlink_evidence.log"
STALE_EVIDENCE_LOG="$TMP_DIR/stale_evidence.log"
FUTURE_EVIDENCE_LOG="$TMP_DIR/future_evidence.log"
FAKE_EVIDENCE_LOG="$TMP_DIR/fake_evidence.log"
FAKE_SOURCE_EVIDENCE_LOG="$TMP_DIR/fake_source_evidence.log"
NO_GO_LOG="$TMP_DIR/no_go.log"
WINDOW_SHORT_LOG="$TMP_DIR/window_short.log"
WINDOW_INVALID_LOG="$TMP_DIR/window_invalid.log"
SEMANTIC_INVALID_LOG="$TMP_DIR/semantic_invalid.log"
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

jq '. + {
  evidence: {
    mode: "production",
    generated_at: "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    source_kind: "prod-observability-export"
  }
}' "$GO_METRICS" >"$PRODUCTION_EVIDENCE_SOURCE"

jq '. + {
  evidence: {
    mode: "production",
    generated_at: "2020-01-01T00:00:00Z",
    source_kind: "prod-observability-export"
  }
}' "$GO_METRICS" >"$STALE_EVIDENCE_SOURCE"

jq '. + {
  evidence: {
    mode: "production",
    generated_at: "2099-01-01T00:00:00Z",
    source_kind: "prod-observability-export"
  }
}' "$GO_METRICS" >"$FUTURE_EVIDENCE_SOURCE"

jq '.paying_users_3mo_min = 1 | . + {
  evidence: {
    mode: "production",
    generated_at: "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    source_kind: "prod-observability-export"
  }
	}' "$GO_METRICS" >"$TAMPERED_EVIDENCE_SOURCE"

jq '. + {
  evidence: {
    mode: "production",
    generated_at: "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    source_kind: "prod-observability-export"
  }
}' "$GO_METRICS" >"$SHA_MISMATCH_EVIDENCE_SOURCE"

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

cat >"$SEMANTIC_INVALID_METRICS" <<'EOF_SEMANTIC_INVALID'
{
  "measurement_window_weeks": 12.5,
  "vpn_connect_session_success_slo_pct": 120,
  "vpn_recovery_mttr_p95_minutes": -1,
  "paying_users_3mo_min": 1250,
  "paid_sessions_per_day_30d_avg": 15000,
  "validator_candidate_depth": 40,
  "validator_independent_operators": 14.5,
  "validator_max_operator_seat_share_pct": -1,
  "validator_max_asn_provider_seat_share_pct": 22,
  "validator_region_count": 4,
  "validator_country_count": 8,
  "manual_sanctions_reversed_pct_90d": 4.5,
  "abuse_report_to_decision_p95_hours": 12,
  "subsidy_runway_months": 14,
  "contribution_margin_3mo": 1.25
}
EOF_SEMANTIC_INVALID

cat >"$INVALID_METRICS" <<'EOF_INVALID'
{
  "measurement_window_weeks": 12,
  "vpn_connect_session_success_slo_pct": 99.8,
EOF_INVALID

printf '%s\n' '[]' >"$ARRAY_METRICS"

echo "[blockchain-mainnet-activation-gate] GO path"
BLOCKCHAIN_MAINNET_ACTIVATION_GATE_METRICS_JSON="$GO_METRICS" \
  "$SCRIPT_UNDER_TEST" \
  --summary-json "$GO_SUMMARY" \
  --report-only \
  --print-summary-json 1 >"$GO_LOG" 2>&1

jq -e --arg metrics_path "$GO_METRICS" '
  (.generated_at | type) == "string"
  and (.generated_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
  and (.decision == "GO")
  and (.status == "go")
  and (.rc == 0)
  and (.exit_code == 0)
  and (.mode == "report-only")
  and (.fail_close == 0)
  and (.require_real_evidence == 0)
  and (.counts.required == 13)
  and (.counts.evaluated == 13)
  and (.counts.pass == 13)
  and (.counts.fail == 0)
  and ((.failed_gate_ids | length) == 0)
  and ((.failed_reasons | length) == 0)
  and ((.gates | length) == 13)
  and (.input.state == "available")
  and (.input.valid == true)
  and ((.reasons | length) == 0)
  and ((.source_paths | length) == 1)
  and (.source_paths[0] == $metrics_path)
  and (.artifacts.metrics_json == $metrics_path)
' "$GO_SUMMARY" >/dev/null
if ! grep -Fq '"decision": "GO"' "$GO_LOG"; then
  echo "expected GO summary JSON in stdout log"
  cat "$GO_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-gate] real-evidence mode accepts metrics summary provenance"
"$METRICS_SCRIPT_UNDER_TEST" \
  --source-json "$PRODUCTION_EVIDENCE_SOURCE" \
  --summary-json "$REAL_EVIDENCE_METRICS_SUMMARY" \
  --canonical-summary-json "$REAL_EVIDENCE_METRICS_CANONICAL" \
  --print-summary-json 0 >"$TMP_DIR/real_evidence_metrics.log" 2>&1
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$REAL_EVIDENCE_METRICS_CANONICAL" \
  --summary-json "$REAL_EVIDENCE_SUMMARY" \
  --enforce-launch \
  --print-summary-json 0 >"$REAL_EVIDENCE_LOG" 2>&1
jq -e --arg metrics_path "$REAL_EVIDENCE_METRICS_CANONICAL" '
  (.decision == "GO")
  and (.status == "go")
  and (.rc == 0)
  and (.exit_code == 0)
  and (.mode == "enforce")
  and (.fail_close == 1)
  and (.require_real_evidence == 1)
  and (.input.state == "available")
  and (.input.valid == true)
  and (.artifacts.metrics_json == $metrics_path)
' "$REAL_EVIDENCE_SUMMARY" >/dev/null

echo "[blockchain-mainnet-activation-gate] real-evidence mode rejects tampered metrics summary values"
"$METRICS_SCRIPT_UNDER_TEST" \
  --source-json "$TAMPERED_EVIDENCE_SOURCE" \
  --summary-json "$TAMPERED_EVIDENCE_METRICS_SUMMARY" \
  --canonical-summary-json "$TAMPERED_EVIDENCE_METRICS_CANONICAL" \
  --print-summary-json 0 >"$TMP_DIR/tampered_evidence_metrics.log" 2>&1
jq '.paying_users_3mo_min = 1250 | .metrics.paying_users_3mo_min = 1250 | .sources.metric_bindings.paying_users_3mo_min.value = 1250' \
  "$TAMPERED_EVIDENCE_METRICS_CANONICAL" >"$TAMPERED_EVIDENCE_METRICS_MUTATED"
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$TAMPERED_EVIDENCE_METRICS_MUTATED" \
  --summary-json "$TAMPERED_EVIDENCE_SUMMARY" \
  --enforce-launch \
  --print-summary-json 0 >"$TAMPERED_EVIDENCE_LOG" 2>&1
tampered_evidence_rc=$?
set -e
if [[ "$tampered_evidence_rc" -eq 0 ]]; then
  echo "expected tampered metrics summary to fail in real-evidence mode"
  cat "$TAMPERED_EVIDENCE_LOG"
  exit 1
fi
jq -e --arg metrics_path "$TAMPERED_EVIDENCE_METRICS_MUTATED" '
  (.decision == "NO-GO")
  and (.status == "no-go")
  and (.rc == 1)
  and (.exit_code == 1)
  and (.require_real_evidence == 1)
  and (.input.state == "invalid")
  and (.input.valid == false)
  and (.failed_gate_ids == ["metrics_evidence"])
  and ((.reasons | length) == 1)
  and (.reasons[0] | contains("source value mismatch"))
  and (.artifacts.metrics_json == $metrics_path)
' "$TAMPERED_EVIDENCE_SUMMARY" >/dev/null

echo "[blockchain-mainnet-activation-gate] real-evidence mode rejects source SHA mismatch"
"$METRICS_SCRIPT_UNDER_TEST" \
  --source-json "$SHA_MISMATCH_EVIDENCE_SOURCE" \
  --summary-json "$SHA_MISMATCH_EVIDENCE_METRICS_SUMMARY" \
  --canonical-summary-json "$SHA_MISMATCH_EVIDENCE_METRICS_CANONICAL" \
  --print-summary-json 0 >"$TMP_DIR/sha_mismatch_evidence_metrics.log" 2>&1
printf '\n' >>"$SHA_MISMATCH_EVIDENCE_SOURCE"
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$SHA_MISMATCH_EVIDENCE_METRICS_CANONICAL" \
  --summary-json "$SHA_MISMATCH_EVIDENCE_SUMMARY" \
  --enforce-launch \
  --print-summary-json 0 >"$SHA_MISMATCH_EVIDENCE_LOG" 2>&1
sha_mismatch_evidence_rc=$?
set -e
if [[ "$sha_mismatch_evidence_rc" -eq 0 ]]; then
  echo "expected source SHA mismatch to fail in real-evidence mode"
  cat "$SHA_MISMATCH_EVIDENCE_LOG"
  exit 1
fi
jq -e --arg metrics_path "$SHA_MISMATCH_EVIDENCE_METRICS_CANONICAL" '
  (.decision == "NO-GO")
  and (.status == "no-go")
  and (.rc == 1)
  and (.exit_code == 1)
  and (.failed_gate_ids == ["metrics_evidence"])
  and ((.reasons | length) == 1)
  and (.reasons[0] | contains("metric evidence binding sha256 mismatch"))
  and (.artifacts.metrics_json == $metrics_path)
' "$SHA_MISMATCH_EVIDENCE_SUMMARY" >/dev/null

echo "[blockchain-mainnet-activation-gate] real-evidence mode rejects symlink source-json"
ln -s "$PRODUCTION_EVIDENCE_SOURCE" "$SYMLINK_EVIDENCE_SOURCE"
"$METRICS_SCRIPT_UNDER_TEST" \
  --source-json "$SYMLINK_EVIDENCE_SOURCE" \
  --summary-json "$SYMLINK_EVIDENCE_METRICS_SUMMARY" \
  --canonical-summary-json "$SYMLINK_EVIDENCE_METRICS_CANONICAL" \
  --print-summary-json 0 >"$TMP_DIR/symlink_evidence_metrics.log" 2>&1
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$SYMLINK_EVIDENCE_METRICS_CANONICAL" \
  --summary-json "$SYMLINK_EVIDENCE_SUMMARY" \
  --enforce-launch \
  --print-summary-json 0 >"$SYMLINK_EVIDENCE_LOG" 2>&1
symlink_evidence_rc=$?
set -e
if [[ "$symlink_evidence_rc" -eq 0 ]]; then
  echo "expected symlink source-json to fail in real-evidence mode"
  cat "$SYMLINK_EVIDENCE_LOG"
  exit 1
fi
jq -e --arg metrics_path "$SYMLINK_EVIDENCE_METRICS_CANONICAL" '
  (.decision == "NO-GO")
  and (.status == "no-go")
  and (.rc == 1)
  and (.exit_code == 1)
  and (.failed_gate_ids == ["metrics_evidence"])
  and ((.reasons | length) == 1)
  and (.reasons[0] | contains("must not be a symlink"))
  and (.artifacts.metrics_json == $metrics_path)
' "$SYMLINK_EVIDENCE_SUMMARY" >/dev/null

echo "[blockchain-mainnet-activation-gate] real-evidence mode rejects stale production source-json"
"$METRICS_SCRIPT_UNDER_TEST" \
  --source-json "$STALE_EVIDENCE_SOURCE" \
  --summary-json "$STALE_EVIDENCE_METRICS_SUMMARY" \
  --canonical-summary-json "$STALE_EVIDENCE_METRICS_CANONICAL" \
  --print-summary-json 0 >"$TMP_DIR/stale_evidence_metrics.log" 2>&1
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$STALE_EVIDENCE_METRICS_CANONICAL" \
  --summary-json "$STALE_EVIDENCE_SUMMARY" \
  --enforce-launch \
  --print-summary-json 0 >"$STALE_EVIDENCE_LOG" 2>&1
stale_evidence_rc=$?
set -e
if [[ "$stale_evidence_rc" -eq 0 ]]; then
  echo "expected stale production evidence to fail in real-evidence mode"
  cat "$STALE_EVIDENCE_LOG"
  exit 1
fi
jq -e --arg metrics_path "$STALE_EVIDENCE_METRICS_CANONICAL" '
  (.decision == "NO-GO")
  and (.status == "no-go")
  and (.rc == 1)
  and (.exit_code == 1)
  and (.mode == "enforce")
  and (.evidence_max_age_sec == 1209600)
  and (.input.state == "invalid")
  and (.input.valid == false)
  and (.failed_gate_ids == ["metrics_evidence"])
  and ((.reasons | length) == 1)
  and (.reasons[0] | contains("production evidence is stale"))
  and (.reasons[0] | contains("generated_at=2020-01-01T00:00:00Z"))
  and (.artifacts.metrics_json == $metrics_path)
' "$STALE_EVIDENCE_SUMMARY" >/dev/null

echo "[blockchain-mainnet-activation-gate] real-evidence mode rejects unsafe freshness override"
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$STALE_EVIDENCE_METRICS_CANONICAL" \
  --summary-json "$TMP_DIR/summary_unsafe_freshness_override.json" \
  --enforce-launch \
  --evidence-max-age-sec 999999999 \
  --print-summary-json 0 >"$TMP_DIR/unsafe_freshness_override.log" 2>&1
unsafe_freshness_rc=$?
set -e
if [[ "$unsafe_freshness_rc" -ne 2 ]]; then
  echo "expected unsafe freshness override to fail as usage error"
  cat "$TMP_DIR/unsafe_freshness_override.log"
  exit 1
fi
if ! grep -Fq -- 'cannot exceed 1209600 in enforce mode' "$TMP_DIR/unsafe_freshness_override.log"; then
  echo "expected unsafe freshness override rejection message"
  cat "$TMP_DIR/unsafe_freshness_override.log"
  exit 1
fi

echo "[blockchain-mainnet-activation-gate] real-evidence mode rejects future production source-json"
"$METRICS_SCRIPT_UNDER_TEST" \
  --source-json "$FUTURE_EVIDENCE_SOURCE" \
  --summary-json "$FUTURE_EVIDENCE_METRICS_SUMMARY" \
  --canonical-summary-json "$FUTURE_EVIDENCE_METRICS_CANONICAL" \
  --print-summary-json 0 >"$TMP_DIR/future_evidence_metrics.log" 2>&1
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$FUTURE_EVIDENCE_METRICS_CANONICAL" \
  --summary-json "$FUTURE_EVIDENCE_SUMMARY" \
  --enforce-launch \
  --print-summary-json 0 >"$FUTURE_EVIDENCE_LOG" 2>&1
future_evidence_rc=$?
set -e
if [[ "$future_evidence_rc" -eq 0 ]]; then
  echo "expected future production evidence to fail in real-evidence mode"
  cat "$FUTURE_EVIDENCE_LOG"
  exit 1
fi
jq -e --arg metrics_path "$FUTURE_EVIDENCE_METRICS_CANONICAL" '
  (.decision == "NO-GO")
  and (.status == "no-go")
  and (.rc == 1)
  and (.exit_code == 1)
  and (.mode == "enforce")
  and (.evidence_max_age_sec == 1209600)
  and (.input.state == "invalid")
  and (.input.valid == false)
  and (.failed_gate_ids == ["metrics_evidence"])
  and ((.reasons | length) == 1)
  and (.reasons[0] | contains("generated_at is in the future"))
  and (.reasons[0] | contains("generated_at=2099-01-01T00:00:00Z"))
  and (.artifacts.metrics_json == $metrics_path)
' "$FUTURE_EVIDENCE_SUMMARY" >/dev/null

echo "[blockchain-mainnet-activation-gate] real-evidence mode rejects non-production source-json metrics"
"$METRICS_SCRIPT_UNDER_TEST" \
  --source-json "$GO_METRICS" \
  --summary-json "$FAKE_SOURCE_METRICS_SUMMARY" \
  --canonical-summary-json "$FAKE_SOURCE_METRICS_CANONICAL" \
  --print-summary-json 0 >"$TMP_DIR/fake_source_metrics.log" 2>&1
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$FAKE_SOURCE_METRICS_CANONICAL" \
  --summary-json "$FAKE_SOURCE_EVIDENCE_SUMMARY" \
  --enforce-launch \
  --print-summary-json 0 >"$FAKE_SOURCE_EVIDENCE_LOG" 2>&1
fake_source_evidence_rc=$?
set -e
if [[ "$fake_source_evidence_rc" -eq 0 ]]; then
  echo "expected source-json metrics without production evidence contract to fail in real-evidence mode"
  cat "$FAKE_SOURCE_EVIDENCE_LOG"
  exit 1
fi
jq -e --arg metrics_path "$FAKE_SOURCE_METRICS_CANONICAL" '
  (.decision == "NO-GO")
  and (.status == "no-go")
  and (.rc == 1)
  and (.exit_code == 1)
  and (.require_real_evidence == 1)
  and (.input.state == "invalid")
  and (.input.valid == false)
  and (.failed_gate_ids == ["metrics_evidence"])
  and ((.reasons | length) == 1)
  and (.reasons[0] | contains("source JSON lacks production evidence contract"))
  and (.artifacts.metrics_json == $metrics_path)
' "$FAKE_SOURCE_EVIDENCE_SUMMARY" >/dev/null

echo "[blockchain-mainnet-activation-gate] real-evidence mode rejects fixture source-kind self-attestation"
FIXTURE_KIND_SOURCE="$TMP_DIR/metrics_fixture_kind_source.json"
FIXTURE_KIND_METRICS_SUMMARY="$TMP_DIR/metrics_fixture_kind_summary.json"
FIXTURE_KIND_METRICS_CANONICAL="$TMP_DIR/metrics_fixture_kind_canonical.json"
FIXTURE_KIND_SUMMARY="$TMP_DIR/summary_fixture_kind_rejected.json"
FIXTURE_KIND_LOG="$TMP_DIR/fixture_kind.log"
jq '. + {
  evidence: {
    mode: "production",
    generated_at: "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    source_kind: "integration_mainnet_activation_fixture"
  }
}' "$GO_METRICS" >"$FIXTURE_KIND_SOURCE"
"$METRICS_SCRIPT_UNDER_TEST" \
  --source-json "$FIXTURE_KIND_SOURCE" \
  --summary-json "$FIXTURE_KIND_METRICS_SUMMARY" \
  --canonical-summary-json "$FIXTURE_KIND_METRICS_CANONICAL" \
  --print-summary-json 0 >"$TMP_DIR/fixture_kind_metrics.log" 2>&1
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$FIXTURE_KIND_METRICS_CANONICAL" \
  --summary-json "$FIXTURE_KIND_SUMMARY" \
  --enforce-launch \
  --print-summary-json 0 >"$FIXTURE_KIND_LOG" 2>&1
fixture_kind_rc=$?
set -e
if [[ "$fixture_kind_rc" -eq 0 ]]; then
  echo "expected fixture source-kind to fail in real-evidence mode"
  cat "$FIXTURE_KIND_LOG"
  exit 1
fi
jq -e '
  (.failed_gate_ids == ["metrics_evidence"])
  and ((.reasons[0] // "") | contains("source JSON lacks production evidence contract"))
' "$FIXTURE_KIND_SUMMARY" >/dev/null

echo "[blockchain-mainnet-activation-gate] real-evidence mode rejects boolean-only production evidence"
BOOLEAN_ONLY_SOURCE="$TMP_DIR/metrics_boolean_only_source.json"
BOOLEAN_ONLY_METRICS_SUMMARY="$TMP_DIR/metrics_boolean_only_summary.json"
BOOLEAN_ONLY_METRICS_CANONICAL="$TMP_DIR/metrics_boolean_only_canonical.json"
BOOLEAN_ONLY_SUMMARY="$TMP_DIR/summary_boolean_only_rejected.json"
BOOLEAN_ONLY_LOG="$TMP_DIR/boolean_only.log"
jq '. + {
  evidence: {
    production: true,
    generated_at: "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    source_kind: "prod-observability-export"
  },
  production_evidence: true
}' "$GO_METRICS" >"$BOOLEAN_ONLY_SOURCE"
"$METRICS_SCRIPT_UNDER_TEST" \
  --source-json "$BOOLEAN_ONLY_SOURCE" \
  --summary-json "$BOOLEAN_ONLY_METRICS_SUMMARY" \
  --canonical-summary-json "$BOOLEAN_ONLY_METRICS_CANONICAL" \
  --print-summary-json 0 >"$TMP_DIR/boolean_only_metrics.log" 2>&1
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$BOOLEAN_ONLY_METRICS_CANONICAL" \
  --summary-json "$BOOLEAN_ONLY_SUMMARY" \
  --enforce-launch \
  --print-summary-json 0 >"$BOOLEAN_ONLY_LOG" 2>&1
boolean_only_rc=$?
set -e
if [[ "$boolean_only_rc" -eq 0 ]]; then
  echo "expected boolean-only production evidence to fail in real-evidence mode"
  cat "$BOOLEAN_ONLY_LOG"
  exit 1
fi
jq -e '
  (.failed_gate_ids == ["metrics_evidence"])
  and ((.reasons[0] // "") | contains("source JSON lacks production evidence contract"))
' "$BOOLEAN_ONLY_SUMMARY" >/dev/null

echo "[blockchain-mainnet-activation-gate] real-evidence mode rejects raw local metrics"
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$GO_METRICS" \
  --summary-json "$FAKE_EVIDENCE_SUMMARY" \
  --enforce-launch \
  --print-summary-json 0 >"$FAKE_EVIDENCE_LOG" 2>&1
fake_evidence_rc=$?
set -e
if [[ "$fake_evidence_rc" -eq 0 ]]; then
  echo "expected raw local metrics to fail in real-evidence mode"
  cat "$FAKE_EVIDENCE_LOG"
  exit 1
fi
jq -e --arg metrics_path "$GO_METRICS" '
  (.decision == "NO-GO")
  and (.status == "no-go")
  and (.rc == 1)
  and (.exit_code == 1)
  and (.require_real_evidence == 1)
  and (.input.state == "invalid")
  and (.input.valid == false)
  and (.failed_gate_ids == ["metrics_evidence"])
  and ((.reasons | length) == 1)
  and (.reasons[0] | contains("real-evidence provenance"))
  and (.artifacts.metrics_json == $metrics_path)
' "$FAKE_EVIDENCE_SUMMARY" >/dev/null

echo "[blockchain-mainnet-activation-gate] NO-GO path"
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$NO_GO_METRICS" \
  --summary-json "$NO_GO_SUMMARY" \
  --report-only \
  --print-summary-json 0 >"$NO_GO_LOG" 2>&1

jq -e --arg metrics_path "$NO_GO_METRICS" '
  (.generated_at | type) == "string"
  and (.generated_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
  and (.decision == "NO-GO")
  and (.status == "no-go")
  and (.rc == 1)
  and (.exit_code == 0)
  and (.mode == "report-only")
  and (.counts.required == 13)
  and (.counts.evaluated == 13)
  and (.counts.pass < 13)
  and (.counts.fail > 0)
  and ((.failed_gate_ids | length) > 0)
  and ((.failed_reasons | length) > 0)
  and ((.failed_gate_ids | index("vpn_recovery_mttr_p95")) != null)
  and ((.failed_gate_ids | index("validator_operator_concentration")) != null)
  and ((.failed_gate_ids | index("unit_economics")) != null)
  and ((.reasons | length) > 0)
  and ((.reasons | index("vpn_recovery_mttr_p95_minutes=34 does not satisfy <= 30")) != null)
  and ((.source_paths | length) == 1)
  and (.source_paths[0] == $metrics_path)
  and (.artifacts.metrics_json == $metrics_path)
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
  --report-only \
  --print-summary-json 0 >"$WINDOW_SHORT_LOG" 2>&1

jq -e --arg metrics_path "$WINDOW_SHORT_METRICS" '
  (.generated_at | type) == "string"
  and (.generated_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
  and (.decision == "NO-GO")
  and (.status == "no-go")
  and (.rc == 1)
  and (.exit_code == 0)
  and (.counts.required == 13)
  and (.counts.evaluated == 13)
  and (.counts.pass == 12)
  and (.counts.fail == 1)
  and (.failed_gate_ids == ["measurement_window_weeks"])
  and ((.failed_reasons | length) == 1)
  and ((.failed_reasons | index("measurement_window_weeks=11 does not satisfy >= 12")) != null)
  and ((.reasons | index("measurement_window_weeks=11 does not satisfy >= 12")) != null)
  and ((.source_paths | length) == 1)
  and (.source_paths[0] == $metrics_path)
  and (.artifacts.metrics_json == $metrics_path)
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
  --report-only \
  --print-summary-json 0 >"$WINDOW_INVALID_LOG" 2>&1

jq -e --arg metrics_path "$WINDOW_INVALID_METRICS" '
  (.generated_at | type) == "string"
  and (.generated_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
  and (.decision == "NO-GO")
  and (.status == "no-go")
  and (.rc == 1)
  and (.exit_code == 0)
  and (.counts.required == 13)
  and (.counts.evaluated == 13)
  and (.counts.pass == 12)
  and (.counts.fail == 1)
  and (.failed_gate_ids == ["measurement_window_weeks"])
  and ((.failed_reasons | length) == 1)
  and ((.failed_reasons | index("missing or invalid metric: measurement_window_weeks")) != null)
  and ((.reasons | index("missing or invalid metric: measurement_window_weeks")) != null)
  and ((.source_paths | length) == 1)
  and (.source_paths[0] == $metrics_path)
  and (.artifacts.metrics_json == $metrics_path)
' "$WINDOW_INVALID_SUMMARY" >/dev/null
if ! grep -Fq '[blockchain-mainnet-activation-gate] decision=NO-GO' "$WINDOW_INVALID_LOG"; then
  echo "expected measurement-window invalid NO-GO decision log line"
  cat "$WINDOW_INVALID_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-gate] semantic invalid metric values are rejected"
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$SEMANTIC_INVALID_METRICS" \
  --summary-json "$SEMANTIC_INVALID_SUMMARY" \
  --report-only \
  --print-summary-json 0 >"$SEMANTIC_INVALID_LOG" 2>&1

jq -e --arg metrics_path "$SEMANTIC_INVALID_METRICS" '
  (.generated_at | type) == "string"
  and (.decision == "NO-GO")
  and (.status == "no-go")
  and (.rc == 1)
  and (.exit_code == 0)
  and (.counts.required == 13)
  and (.counts.evaluated == 13)
  and (.counts.fail >= 4)
  and ((.failed_gate_ids | index("measurement_window_weeks")) != null)
  and ((.failed_gate_ids | index("vpn_connect_session_success_slo")) != null)
  and ((.failed_gate_ids | index("vpn_recovery_mttr_p95")) != null)
  and ((.failed_gate_ids | index("validator_operator_concentration")) != null)
  and ((.failed_reasons | index("missing or invalid metric: measurement_window_weeks")) != null)
  and ((.failed_reasons | index("missing or invalid metric: vpn_connect_session_success_slo_pct")) != null)
  and ((.failed_reasons | index("missing or invalid metric: vpn_recovery_mttr_p95_minutes")) != null)
  and ((.failed_reasons | index("missing or invalid metric: validator_independent_operators or validator_max_operator_seat_share_pct")) != null)
  and (.artifacts.metrics_json == $metrics_path)
' "$SEMANTIC_INVALID_SUMMARY" >/dev/null

echo "[blockchain-mainnet-activation-gate] missing input path"
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$MISSING_METRICS" \
  --summary-json "$MISSING_SUMMARY" \
  --report-only \
  --print-summary-json 0 >"$MISSING_LOG" 2>&1
missing_rc=$?
set -e
if [[ "$missing_rc" -ne 0 ]]; then
  echo "expected missing-input path to stay non-failing without fail-close"
  cat "$MISSING_LOG"
  exit 1
fi
jq -e --arg metrics_path "$MISSING_METRICS" '
  (.generated_at | type) == "string"
  and (.generated_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
  and (.decision == "NO-GO")
  and (.status == "no-go")
  and (.rc == 1)
  and (.exit_code == 0)
  and (.input.state == "missing")
  and (.input.valid == false)
  and (.failed_gate_ids == ["metrics_input"])
  and ((.failed_reasons | length) == 1)
  and ((.reasons | length) > 0)
  and ((.reasons | index("metrics JSON file not found: " + $metrics_path)) != null)
  and ((.source_paths | length) == 1)
  and (.source_paths[0] == $metrics_path)
  and (.artifacts.metrics_json == $metrics_path)
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
  (.generated_at | type) == "string"
  and (.generated_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
  and (.decision == "NO-GO")
  and (.status == "no-go")
  and (.rc == 1)
  and (.exit_code == 1)
  and (.input.state == "invalid")
  and (.input.valid == false)
  and (.failed_gate_ids == ["metrics_input"])
  and ((.reasons | length) > 0)
  and ((.reasons | index("metrics JSON is not valid JSON: " + $metrics_path)) != null)
  and ((.source_paths | length) == 1)
  and (.source_paths[0] == $metrics_path)
  and (.artifacts.metrics_json == $metrics_path)
' "$INVALID_SUMMARY" >/dev/null

echo "[blockchain-mainnet-activation-gate] JSON root must be an object"
ARRAY_SUMMARY="$TMP_DIR/summary_array_root.json"
ARRAY_LOG="$TMP_DIR/array_root.log"
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$ARRAY_METRICS" \
  --summary-json "$ARRAY_SUMMARY" \
  --report-only \
  --print-summary-json 0 >"$ARRAY_LOG" 2>&1
jq -e --arg metrics_path "$ARRAY_METRICS" '
  (.decision == "NO-GO")
  and (.status == "no-go")
  and (.input.state == "invalid")
  and (.input.valid == false)
  and (.failed_gate_ids == ["metrics_input"])
  and ((.reasons | index("metrics JSON root must be an object: " + $metrics_path)) != null)
  and (.artifacts.metrics_json == $metrics_path)
' "$ARRAY_SUMMARY" >/dev/null

echo "[blockchain-mainnet-activation-gate] NO-GO with fail-close"
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$NO_GO_METRICS" \
  --summary-json "$FAIL_CLOSE_SUMMARY" \
  --report-only \
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
  (.generated_at | type) == "string"
  and (.generated_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
  and (.decision == "NO-GO")
  and (.status == "no-go")
  and (.rc == 1)
  and (.exit_code == 1)
  and (.mode == "report-only")
  and (.counts.fail > 0)
' "$FAIL_CLOSE_SUMMARY" >/dev/null
if ! grep -Fq '[blockchain-mainnet-activation-gate] decision=NO-GO' "$FAIL_CLOSE_LOG"; then
  echo "expected fail-close NO-GO log line"
  cat "$FAIL_CLOSE_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-gate] enforce mode rejects fail-open overrides"
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$GO_METRICS" \
  --summary-json "$TMP_DIR/fail_open_override_summary.json" \
  --fail-close 0 \
  --print-summary-json 0 >"$TMP_DIR/fail_open_override.log" 2>&1
fail_open_override_rc=$?
set -e
if [[ "$fail_open_override_rc" -ne 2 ]]; then
  echo "expected fail-open override in enforce mode to exit 2"
  cat "$TMP_DIR/fail_open_override.log"
  exit 1
fi
if ! grep -Fq 'use --report-only for fail-soft diagnostics' "$TMP_DIR/fail_open_override.log"; then
  echo "expected enforce-mode fail-open override guidance"
  cat "$TMP_DIR/fail_open_override.log"
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
