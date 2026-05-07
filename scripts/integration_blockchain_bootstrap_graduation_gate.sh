#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp grep awk sha256sum; do
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

write_bootstrap_evidence_source() {
  local path="$1"
  local mode="$2"
  local generated_at="$3"
  local source_kind="${4:-prod-observability-export}"
  jq -n \
    --arg mode "$mode" \
    --arg generated_at "$generated_at" \
    --arg source_kind "$source_kind" \
    '{
      evidence: {
        mode: $mode,
        generated_at: $generated_at,
        source_kind: $source_kind
      },
      measurement_window_weeks: 12,
      validator_candidate_depth: 38,
      validator_independent_operators: 13,
      validator_max_operator_seat_share_pct: 19,
      validator_max_asn_provider_seat_share_pct: 21,
      validator_region_count: 4,
      validator_country_count: 9,
      manual_sanctions_reversed_pct_90d: 3.5,
      abuse_report_to_decision_p95_hours: 11,
      vpn_connect_session_success_slo_pct: 99.8,
      vpn_recovery_mttr_p95_minutes: 24
    }' >"$path"
}

write_bootstrap_metrics_summary() {
  local source_path="$1"
  local summary_path="$2"
  local source_sha=""
  source_sha="$(sha256sum "$source_path" | awk '{print $1}')"
  jq \
    --arg source_path "$source_path" \
    --arg source_sha "$source_sha" \
    '
    def required_metrics: [
      "measurement_window_weeks",
      "validator_candidate_depth",
      "validator_independent_operators",
      "validator_max_operator_seat_share_pct",
      "validator_max_asn_provider_seat_share_pct",
      "validator_region_count",
      "validator_country_count",
      "manual_sanctions_reversed_pct_90d",
      "abuse_report_to_decision_p95_hours",
      "vpn_connect_session_success_slo_pct",
      "vpn_recovery_mttr_p95_minutes"
    ];
    . as $source
    | (required_metrics | reduce .[] as $metric ({}; .[$metric] = $source[$metric])) as $metric_values
    | $metric_values + {
        version: 1,
        schema: {id: "blockchain_mainnet_activation_metrics_summary", major: 1, minor: 0},
        status: "complete",
        ready_for_gate: true,
        sources: {
          usable_source_jsons: [$source_path],
          metrics: (required_metrics | reduce .[] as $metric ({}; .[$metric] = "source_json")),
          metric_bindings: (required_metrics | reduce .[] as $metric ({}; .[$metric] = {
            source_json: $source_path,
            source_sha256: $source_sha,
            value: $source[$metric]
          }))
        }
      }
    ' "$source_path" >"$summary_path"
}

echo "[blockchain-bootstrap-graduation-gate] GO path"
BLOCKCHAIN_BOOTSTRAP_GRADUATION_GATE_METRICS_JSON="$GO_METRICS" \
  "$SCRIPT_UNDER_TEST" \
  --summary-json "$GO_SUMMARY" \
  --report-only \
  --print-summary-json 1 >"$GO_LOG" 2>&1

jq -e --arg metrics_path "$GO_METRICS" '
  ((.generated_at // "") | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
  and
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
  --report-only \
  --print-summary-json 0 >"$NO_GO_LOG" 2>&1

jq -e --arg metrics_path "$NO_GO_METRICS" '
  ((.generated_at // "") | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
  and
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
  ((.generated_at // "") | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
  and
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
  ((.generated_at // "") | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
  and
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
  ((.generated_at // "") | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
  and
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

echo "[blockchain-bootstrap-graduation-gate] enforce rejects raw metrics"
RAW_ENFORCE_SUMMARY="$TMP_DIR/summary_raw_enforce.json"
RAW_ENFORCE_LOG="$TMP_DIR/raw_enforce.log"
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$GO_METRICS" \
  --summary-json "$RAW_ENFORCE_SUMMARY" \
  --enforce-launch \
  --print-summary-json 0 >"$RAW_ENFORCE_LOG" 2>&1
raw_enforce_rc=$?
set -e
if [[ "$raw_enforce_rc" -eq 0 ]]; then
  echo "expected raw metrics to fail in enforce mode"
  cat "$RAW_ENFORCE_LOG"
  exit 1
fi
jq -e '
  .mode == "enforce"
  and .require_real_evidence == 1
  and .decision == "NO-GO"
  and .failed_gate_ids == ["metrics_evidence"]
  and ((.reasons[0] // "") | contains("real-evidence provenance"))
' "$RAW_ENFORCE_SUMMARY" >/dev/null

echo "[blockchain-bootstrap-graduation-gate] enforce accepts production evidence summary"
REAL_SOURCE="$TMP_DIR/bootstrap_evidence_prod.json"
REAL_METRICS_SUMMARY="$TMP_DIR/bootstrap_metrics_summary_prod.json"
REAL_GATE_SUMMARY="$TMP_DIR/bootstrap_gate_summary_prod.json"
REAL_GATE_LOG="$TMP_DIR/bootstrap_gate_prod.log"
write_bootstrap_evidence_source "$REAL_SOURCE" "production" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
write_bootstrap_metrics_summary "$REAL_SOURCE" "$REAL_METRICS_SUMMARY"
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$REAL_METRICS_SUMMARY" \
  --summary-json "$REAL_GATE_SUMMARY" \
  --enforce-launch \
  --print-summary-json 0 >"$REAL_GATE_LOG" 2>&1
jq -e --arg metrics_path "$REAL_METRICS_SUMMARY" '
  .mode == "enforce"
  and .require_real_evidence == 1
  and .decision == "GO"
  and .status == "go"
  and .go == true
  and .counts.pass == 9
  and .source_paths[0] == $metrics_path
	' "$REAL_GATE_SUMMARY" >/dev/null

echo "[blockchain-bootstrap-graduation-gate] enforce rejects fixture source-kind self-attestation"
FIXTURE_KIND_SOURCE="$TMP_DIR/bootstrap_evidence_fixture_kind.json"
FIXTURE_KIND_METRICS_SUMMARY="$TMP_DIR/bootstrap_metrics_summary_fixture_kind.json"
FIXTURE_KIND_GATE_SUMMARY="$TMP_DIR/bootstrap_gate_fixture_kind.json"
FIXTURE_KIND_GATE_LOG="$TMP_DIR/bootstrap_gate_fixture_kind.log"
write_bootstrap_evidence_source "$FIXTURE_KIND_SOURCE" "production" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "integration_bootstrap_graduation_fixture"
write_bootstrap_metrics_summary "$FIXTURE_KIND_SOURCE" "$FIXTURE_KIND_METRICS_SUMMARY"
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$FIXTURE_KIND_METRICS_SUMMARY" \
  --summary-json "$FIXTURE_KIND_GATE_SUMMARY" \
  --enforce-launch \
  --print-summary-json 0 >"$FIXTURE_KIND_GATE_LOG" 2>&1
fixture_kind_gate_rc=$?
set -e
if [[ "$fixture_kind_gate_rc" -eq 0 ]]; then
  echo "expected fixture source-kind to fail in enforce mode"
  cat "$FIXTURE_KIND_GATE_LOG"
  exit 1
fi
jq -e '
  .failed_gate_ids == ["metrics_evidence"]
  and ((.reasons[0] // "") | contains("source JSON lacks production evidence contract"))
' "$FIXTURE_KIND_GATE_SUMMARY" >/dev/null

echo "[blockchain-bootstrap-graduation-gate] enforce rejects symlink source-json"
SYMLINK_REAL_SOURCE="$TMP_DIR/bootstrap_evidence_symlink_target.json"
SYMLINK_SOURCE="$TMP_DIR/bootstrap_evidence_symlink.json"
SYMLINK_METRICS_SUMMARY="$TMP_DIR/bootstrap_metrics_summary_symlink.json"
SYMLINK_GATE_SUMMARY="$TMP_DIR/bootstrap_gate_symlink.json"
SYMLINK_GATE_LOG="$TMP_DIR/bootstrap_gate_symlink.log"
write_bootstrap_evidence_source "$SYMLINK_REAL_SOURCE" "production" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ln -s "$SYMLINK_REAL_SOURCE" "$SYMLINK_SOURCE"
write_bootstrap_metrics_summary "$SYMLINK_SOURCE" "$SYMLINK_METRICS_SUMMARY"
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$SYMLINK_METRICS_SUMMARY" \
  --summary-json "$SYMLINK_GATE_SUMMARY" \
  --enforce-launch \
  --print-summary-json 0 >"$SYMLINK_GATE_LOG" 2>&1
symlink_gate_rc=$?
set -e
if [[ "$symlink_gate_rc" -eq 0 ]]; then
  echo "expected symlink source-json to fail in enforce mode"
  cat "$SYMLINK_GATE_LOG"
  exit 1
fi
jq -e '
  .failed_gate_ids == ["metrics_evidence"]
  and ((.reasons[0] // "") | contains("must not be a symlink"))
' "$SYMLINK_GATE_SUMMARY" >/dev/null

echo "[blockchain-bootstrap-graduation-gate] enforce rejects stale production evidence"
STALE_SOURCE="$TMP_DIR/bootstrap_evidence_stale.json"
STALE_METRICS_SUMMARY="$TMP_DIR/bootstrap_metrics_summary_stale.json"
STALE_GATE_SUMMARY="$TMP_DIR/bootstrap_gate_summary_stale.json"
STALE_GATE_LOG="$TMP_DIR/bootstrap_gate_stale.log"
write_bootstrap_evidence_source "$STALE_SOURCE" "production" "2020-01-01T00:00:00Z"
write_bootstrap_metrics_summary "$STALE_SOURCE" "$STALE_METRICS_SUMMARY"
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$STALE_METRICS_SUMMARY" \
  --summary-json "$STALE_GATE_SUMMARY" \
  --enforce-launch \
  --print-summary-json 0 >"$STALE_GATE_LOG" 2>&1
stale_gate_rc=$?
set -e
if [[ "$stale_gate_rc" -eq 0 ]]; then
  echo "expected stale production evidence to fail in enforce mode"
  cat "$STALE_GATE_LOG"
  exit 1
fi
jq -e '
  .failed_gate_ids == ["metrics_evidence"]
  and ((.reasons[0] // "") | contains("production evidence is stale"))
' "$STALE_GATE_SUMMARY" >/dev/null

echo "[blockchain-bootstrap-graduation-gate] enforce rejects unsafe evidence freshness override"
UNSAFE_MAX_AGE_SUMMARY="$TMP_DIR/bootstrap_gate_unsafe_max_age.json"
UNSAFE_MAX_AGE_LOG="$TMP_DIR/bootstrap_gate_unsafe_max_age.log"
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$STALE_METRICS_SUMMARY" \
  --summary-json "$UNSAFE_MAX_AGE_SUMMARY" \
  --enforce-launch \
  --evidence-max-age-sec 999999999 \
  --print-summary-json 0 >"$UNSAFE_MAX_AGE_LOG" 2>&1
unsafe_max_age_rc=$?
set -e
if [[ "$unsafe_max_age_rc" -ne 2 ]]; then
  echo "expected unsafe evidence freshness override to fail as usage error"
  cat "$UNSAFE_MAX_AGE_LOG"
  exit 1
fi
if ! grep -Fq -- 'cannot exceed 1209600 in enforce mode' "$UNSAFE_MAX_AGE_LOG"; then
  echo "expected unsafe evidence freshness override rejection message"
  cat "$UNSAFE_MAX_AGE_LOG"
  exit 1
fi

echo "[blockchain-bootstrap-graduation-gate] enforce rejects future production evidence"
FUTURE_SOURCE="$TMP_DIR/bootstrap_evidence_future.json"
FUTURE_METRICS_SUMMARY="$TMP_DIR/bootstrap_metrics_summary_future.json"
FUTURE_GATE_SUMMARY="$TMP_DIR/bootstrap_gate_summary_future.json"
FUTURE_GATE_LOG="$TMP_DIR/bootstrap_gate_future.log"
write_bootstrap_evidence_source "$FUTURE_SOURCE" "production" "2999-01-01T00:00:00Z"
write_bootstrap_metrics_summary "$FUTURE_SOURCE" "$FUTURE_METRICS_SUMMARY"
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$FUTURE_METRICS_SUMMARY" \
  --summary-json "$FUTURE_GATE_SUMMARY" \
  --enforce-launch \
  --print-summary-json 0 >"$FUTURE_GATE_LOG" 2>&1
future_gate_rc=$?
set -e
if [[ "$future_gate_rc" -eq 0 ]]; then
  echo "expected future production evidence to fail in enforce mode"
  cat "$FUTURE_GATE_LOG"
  exit 1
fi
jq -e '
  .failed_gate_ids == ["metrics_evidence"]
  and ((.reasons[0] // "") | contains("generated_at is in the future"))
' "$FUTURE_GATE_SUMMARY" >/dev/null

echo "[blockchain-bootstrap-graduation-gate] enforce rejects non-production evidence"
LAB_SOURCE="$TMP_DIR/bootstrap_evidence_lab.json"
LAB_METRICS_SUMMARY="$TMP_DIR/bootstrap_metrics_summary_lab.json"
LAB_GATE_SUMMARY="$TMP_DIR/bootstrap_gate_summary_lab.json"
LAB_GATE_LOG="$TMP_DIR/bootstrap_gate_lab.log"
write_bootstrap_evidence_source "$LAB_SOURCE" "lab" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
write_bootstrap_metrics_summary "$LAB_SOURCE" "$LAB_METRICS_SUMMARY"
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$LAB_METRICS_SUMMARY" \
  --summary-json "$LAB_GATE_SUMMARY" \
  --enforce-launch \
  --print-summary-json 0 >"$LAB_GATE_LOG" 2>&1
lab_gate_rc=$?
set -e
if [[ "$lab_gate_rc" -eq 0 ]]; then
  echo "expected non-production evidence to fail in enforce mode"
  cat "$LAB_GATE_LOG"
  exit 1
fi
jq -e '
  .failed_gate_ids == ["metrics_evidence"]
  and ((.reasons[0] // "") | contains("source JSON lacks production evidence contract"))
' "$LAB_GATE_SUMMARY" >/dev/null

echo "[blockchain-bootstrap-graduation-gate] enforce rejects source SHA mismatch"
SHA_SOURCE="$TMP_DIR/bootstrap_evidence_sha.json"
SHA_METRICS_SUMMARY="$TMP_DIR/bootstrap_metrics_summary_sha.json"
SHA_GATE_SUMMARY="$TMP_DIR/bootstrap_gate_summary_sha.json"
SHA_GATE_LOG="$TMP_DIR/bootstrap_gate_sha.log"
write_bootstrap_evidence_source "$SHA_SOURCE" "production" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
write_bootstrap_metrics_summary "$SHA_SOURCE" "$SHA_METRICS_SUMMARY"
printf '\n' >>"$SHA_SOURCE"
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$SHA_METRICS_SUMMARY" \
  --summary-json "$SHA_GATE_SUMMARY" \
  --enforce-launch \
  --print-summary-json 0 >"$SHA_GATE_LOG" 2>&1
sha_gate_rc=$?
set -e
if [[ "$sha_gate_rc" -eq 0 ]]; then
  echo "expected source SHA mismatch to fail in enforce mode"
  cat "$SHA_GATE_LOG"
  exit 1
fi
jq -e '
  .failed_gate_ids == ["metrics_evidence"]
  and ((.reasons[0] // "") | contains("metric evidence binding sha256 mismatch"))
' "$SHA_GATE_SUMMARY" >/dev/null

echo "[blockchain-bootstrap-graduation-gate] enforce rejects source value mismatch"
VALUE_MISMATCH_SOURCE="$TMP_DIR/bootstrap_evidence_value_mismatch.json"
VALUE_MISMATCH_METRICS_SUMMARY="$TMP_DIR/bootstrap_metrics_summary_value_mismatch.json"
VALUE_MISMATCH_GATE_SUMMARY="$TMP_DIR/bootstrap_gate_value_mismatch.json"
VALUE_MISMATCH_GATE_LOG="$TMP_DIR/bootstrap_gate_value_mismatch.log"
write_bootstrap_evidence_source "$VALUE_MISMATCH_SOURCE" "production" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq '.validator_candidate_depth = 1' "$VALUE_MISMATCH_SOURCE" >"$TMP_DIR/bootstrap_evidence_value_mismatch.tmp.json"
mv "$TMP_DIR/bootstrap_evidence_value_mismatch.tmp.json" "$VALUE_MISMATCH_SOURCE"
write_bootstrap_metrics_summary "$VALUE_MISMATCH_SOURCE" "$VALUE_MISMATCH_METRICS_SUMMARY"
jq '.validator_candidate_depth = 38 | .sources.metric_bindings.validator_candidate_depth.value = 38' \
  "$VALUE_MISMATCH_METRICS_SUMMARY" >"$TMP_DIR/bootstrap_metrics_summary_value_mismatch_mutated.json"
mv "$TMP_DIR/bootstrap_metrics_summary_value_mismatch_mutated.json" "$VALUE_MISMATCH_METRICS_SUMMARY"
set +e
"$SCRIPT_UNDER_TEST" \
  --metrics-json "$VALUE_MISMATCH_METRICS_SUMMARY" \
  --summary-json "$VALUE_MISMATCH_GATE_SUMMARY" \
  --enforce-launch \
  --print-summary-json 0 >"$VALUE_MISMATCH_GATE_LOG" 2>&1
value_mismatch_gate_rc=$?
set -e
if [[ "$value_mismatch_gate_rc" -eq 0 ]]; then
  echo "expected source value mismatch to fail in enforce mode"
  cat "$VALUE_MISMATCH_GATE_LOG"
  exit 1
fi
jq -e '
  .failed_gate_ids == ["metrics_evidence"]
  and ((.reasons[0] // "") | contains("source value mismatch"))
' "$VALUE_MISMATCH_GATE_SUMMARY" >/dev/null

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
