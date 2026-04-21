#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp grep cat; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PROFILE_COMPARE_MULTI_VM_REDUCER_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/profile_compare_multi_vm_reducer.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

make_signoff_summary() {
  local path="$1"
  local status="$2"
  local decision="$3"
  local recommended_profile="$4"
  local support_rate_pct="$5"
  local trend_source="$6"
  jq -n \
    --arg status "$status" \
    --arg decision "$decision" \
    --arg recommended_profile "$recommended_profile" \
    --arg support_rate_pct "$support_rate_pct" \
    --arg trend_source "$trend_source" \
    '{
      version: 1,
      status: $status,
      final_rc: 0,
      decision: {
        decision: $decision,
        recommended_profile: $recommended_profile,
        support_rate_pct: ($support_rate_pct | tonumber),
        trend_source: $trend_source
      }
    }' >"$path"
}

make_campaign_check_summary() {
  local path="$1"
  local status="$2"
  local decision="$3"
  local recommended_profile="$4"
  local support_rate_pct="$5"
  local trend_source="$6"
  local runs_total="$7"
  local runs_pass="$8"
  local runs_warn="$9"
  local runs_fail="${10}"
  jq -n \
    --arg status "$status" \
    --arg decision "$decision" \
    --arg recommended_profile "$recommended_profile" \
    --arg support_rate_pct "$support_rate_pct" \
    --arg trend_source "$trend_source" \
    --argjson runs_total "$runs_total" \
    --argjson runs_pass "$runs_pass" \
    --argjson runs_warn "$runs_warn" \
    --argjson runs_fail "$runs_fail" \
    '{
      version: 1,
      status: $status,
      decision: $decision,
      observed: {
        recommended_profile: $recommended_profile,
        recommendation_support_rate_pct: ($support_rate_pct | tonumber),
        trend_source: $trend_source,
        runs_total: $runs_total,
        runs_pass: $runs_pass,
        runs_warn: $runs_warn,
        runs_fail: $runs_fail
      }
    }' >"$path"
}

make_trend_summary() {
  local path="$1"
  local support_rate_pct="$2"
  local trend_source="$3"
  jq -n \
    --arg support_rate_pct "$support_rate_pct" \
    --arg trend_source "$trend_source" \
    '{
      version: 1,
      decision: {
        recommendation_support_rate_pct: ($support_rate_pct | tonumber),
        source: $trend_source
      }
    }' >"$path"
}

make_campaign_summary() {
  local path="$1"
  local status="$2"
  local rc="$3"
  local recommended_profile="$4"
  local decision_source="$5"
  local trend_summary_json="$6"
  local runs_total="$7"
  local runs_pass="$8"
  local runs_warn="$9"
  local runs_fail="${10}"
  jq -n \
    --arg status "$status" \
    --argjson rc "$rc" \
    --arg recommended_profile "$recommended_profile" \
    --arg decision_source "$decision_source" \
    --arg trend_summary_json "$trend_summary_json" \
    --argjson runs_total "$runs_total" \
    --argjson runs_pass "$runs_pass" \
    --argjson runs_warn "$runs_warn" \
    --argjson runs_fail "$runs_fail" \
    '{
      version: 1,
      status: $status,
      rc: $rc,
      summary: {
        runs_total: $runs_total,
        runs_pass: $runs_pass,
        runs_warn: $runs_warn,
        runs_fail: $runs_fail
      },
      decision: {
        recommended_default_profile: $recommended_profile,
        source: $decision_source
      },
      trend: {
        summary_json: $trend_summary_json
      }
    }' >"$path"
}

SIGNOFF_A="$TMP_DIR/vm_a_signoff_summary.json"
CHECK_B="$TMP_DIR/vm_b_campaign_check_summary.json"
TREND_C="$TMP_DIR/vm_c_trend_summary.json"
CAMPAIGN_C="$TMP_DIR/vm_c_campaign_summary.json"

make_signoff_summary "$SIGNOFF_A" "ok" "GO" "balanced" "80.00" "policy_reliability_latency"
make_campaign_check_summary "$CHECK_B" "ok" "GO" "balanced" "72.50" "vote_fallback" 5 5 0 0
make_trend_summary "$TREND_C" "90.00" "policy_reliability_latency"
make_campaign_summary "$CAMPAIGN_C" "pass" 0 "balanced" "policy_reliability_latency" "$TREND_C" 5 5 0 0

echo "[profile-compare-multi-vm-reducer] baseline pass with mixed schema inputs"
BASELINE_SUMMARY="$TMP_DIR/reducer_baseline_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --campaign-summary-json "$SIGNOFF_A" \
  --campaign-summary-json "$CHECK_B" \
  --campaign-summary-json "$CAMPAIGN_C" \
  --summary-json "$BASELINE_SUMMARY" \
  --print-summary-json 1 >/tmp/integration_profile_compare_multi_vm_reducer_baseline.log 2>&1
baseline_rc=$?
set -e

if [[ "$baseline_rc" -ne 0 ]]; then
  echo "expected baseline rc=0, got rc=$baseline_rc"
  cat /tmp/integration_profile_compare_multi_vm_reducer_baseline.log
  exit 1
fi
if ! grep -q '\[profile-compare-multi-vm-reducer\] decision=GO status=ok rc=0' /tmp/integration_profile_compare_multi_vm_reducer_baseline.log; then
  echo "expected baseline status line not found"
  cat /tmp/integration_profile_compare_multi_vm_reducer_baseline.log
  exit 1
fi
if ! jq -e '
  .decision.decision == "GO"
  and .status == "ok"
  and .rc == 0
  and .decision.recommended_profile == "balanced"
  and (.decision.support_rate_pct >= 99.9)
  and .decision.trend_source == "policy_reliability_latency"
  and .summary.vm_summaries_total == 3
  and .summary.vm_summaries_valid == 3
  and .summary.vm_summaries_invalid == 0
  and .summary.status_counts.pass == 3
  and .summary.decision_counts.GO == 3
  and .summary.decision_counts["NO-GO"] == 0
  and .summary.recommended_profile_counts.balanced == 3
  and (.errors | length) == 0
' "$BASELINE_SUMMARY" >/dev/null 2>&1; then
  echo "baseline reducer summary missing expected fields"
  cat "$BASELINE_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-reducer] campaign-summary-list with de-dup works"
LIST_FILE="$TMP_DIR/reducer_inputs.list"
cat >"$LIST_FILE" <<EOF_LIST
# reducer list
$SIGNOFF_A
$CHECK_B
$CHECK_B

$CAMPAIGN_C
EOF_LIST
LIST_SUMMARY="$TMP_DIR/reducer_list_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --campaign-summary-list "$LIST_FILE" \
  --summary-json "$LIST_SUMMARY" >/tmp/integration_profile_compare_multi_vm_reducer_list.log 2>&1
list_rc=$?
set -e

if [[ "$list_rc" -ne 0 ]]; then
  echo "expected list path rc=0, got rc=$list_rc"
  cat /tmp/integration_profile_compare_multi_vm_reducer_list.log
  exit 1
fi
if ! jq -e '.summary.vm_summaries_total == 3 and .summary.vm_summaries_valid == 3' "$LIST_SUMMARY" >/dev/null 2>&1; then
  echo "expected deduplicated vm summary count from list input"
  cat "$LIST_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-reducer] mixed GO/NO-GO fails closed by default"
CHECK_D="$TMP_DIR/vm_d_campaign_check_summary.json"
make_campaign_check_summary "$CHECK_D" "fail" "NO-GO" "private" "40.00" "vote_fallback" 5 2 1 2
MIXED_FAIL_SUMMARY="$TMP_DIR/reducer_mixed_fail_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --campaign-summary-json "$SIGNOFF_A" \
  --campaign-summary-json "$CHECK_B" \
  --campaign-summary-json "$CHECK_D" \
  --summary-json "$MIXED_FAIL_SUMMARY" >/tmp/integration_profile_compare_multi_vm_reducer_mixed_fail.log 2>&1
mixed_fail_rc=$?
set -e

if [[ "$mixed_fail_rc" -eq 0 ]]; then
  echo "expected non-zero rc for mixed GO/NO-GO input"
  cat /tmp/integration_profile_compare_multi_vm_reducer_mixed_fail.log
  exit 1
fi
if ! jq -e '
  .decision.decision == "NO-GO"
  and .status == "fail"
  and .summary.decision_counts["NO-GO"] == 1
  and .summary.status_counts.fail == 1
  and ((.errors // []) | map(test("not all per-VM decisions are GO")) | any)
' "$MIXED_FAIL_SUMMARY" >/dev/null 2>&1; then
  echo "expected mixed GO/NO-GO failure markers missing"
  cat "$MIXED_FAIL_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-reducer] --fail-on-no-go 0 keeps NO-GO decision but exits 0"
MIXED_SOFT_SUMMARY="$TMP_DIR/reducer_mixed_soft_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --campaign-summary-json "$SIGNOFF_A" \
  --campaign-summary-json "$CHECK_B" \
  --campaign-summary-json "$CHECK_D" \
  --fail-on-no-go 0 \
  --summary-json "$MIXED_SOFT_SUMMARY" >/tmp/integration_profile_compare_multi_vm_reducer_mixed_soft.log 2>&1
mixed_soft_rc=$?
set -e

if [[ "$mixed_soft_rc" -ne 0 ]]; then
  echo "expected rc=0 when --fail-on-no-go 0 is set"
  cat /tmp/integration_profile_compare_multi_vm_reducer_mixed_soft.log
  exit 1
fi
if ! jq -e '.decision.decision == "NO-GO" and .rc == 0' "$MIXED_SOFT_SUMMARY" >/dev/null 2>&1; then
  echo "expected soft-fail summary to keep NO-GO decision with rc=0"
  cat "$MIXED_SOFT_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-reducer] invalid JSON input fails closed"
BAD_JSON="$TMP_DIR/invalid_summary.json"
cat >"$BAD_JSON" <<'EOF_BAD_JSON'
{ not-valid-json
EOF_BAD_JSON
INVALID_SUMMARY="$TMP_DIR/reducer_invalid_json_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --campaign-summary-json "$SIGNOFF_A" \
  --campaign-summary-json "$BAD_JSON" \
  --summary-json "$INVALID_SUMMARY" >/tmp/integration_profile_compare_multi_vm_reducer_invalid_json.log 2>&1
invalid_rc=$?
set -e

if [[ "$invalid_rc" -eq 0 ]]; then
  echo "expected non-zero rc for invalid JSON input"
  cat /tmp/integration_profile_compare_multi_vm_reducer_invalid_json.log
  exit 1
fi
if ! jq -e '
  .decision.decision == "NO-GO"
  and .summary.vm_summaries_invalid >= 1
  and ((.errors // []) | map(test("not valid JSON")) | any)
' "$INVALID_SUMMARY" >/dev/null 2>&1; then
  echo "expected invalid-JSON failure markers missing"
  cat "$INVALID_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-reducer] missing summary file fails closed"
MISSING_SUMMARY="$TMP_DIR/reducer_missing_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --campaign-summary-json "$SIGNOFF_A" \
  --campaign-summary-json "$TMP_DIR/does_not_exist.json" \
  --summary-json "$MISSING_SUMMARY" >/tmp/integration_profile_compare_multi_vm_reducer_missing_file.log 2>&1
missing_file_rc=$?
set -e

if [[ "$missing_file_rc" -eq 0 ]]; then
  echo "expected non-zero rc for missing summary file input"
  cat /tmp/integration_profile_compare_multi_vm_reducer_missing_file.log
  exit 1
fi
if ! jq -e '
  .decision.decision == "NO-GO"
  and .summary.vm_summaries_invalid >= 1
  and ((.errors // []) | map(test("summary file not found")) | any)
' "$MISSING_SUMMARY" >/dev/null 2>&1; then
  echo "expected missing-file failure markers missing"
  cat "$MISSING_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-reducer] missing campaign trend support rate fails closed"
TREND_BAD="$TMP_DIR/vm_e_bad_trend_summary.json"
jq -n '{version: 1, decision: {source: "policy_reliability_latency"}}' >"$TREND_BAD"
CAMPAIGN_BAD="$TMP_DIR/vm_e_bad_campaign_summary.json"
make_campaign_summary "$CAMPAIGN_BAD" "pass" 0 "balanced" "policy_reliability_latency" "$TREND_BAD" 4 4 0 0
BAD_CAMPAIGN_SUMMARY="$TMP_DIR/reducer_bad_campaign_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --campaign-summary-json "$CAMPAIGN_BAD" \
  --summary-json "$BAD_CAMPAIGN_SUMMARY" >/tmp/integration_profile_compare_multi_vm_reducer_bad_campaign.log 2>&1
bad_campaign_rc=$?
set -e

if [[ "$bad_campaign_rc" -eq 0 ]]; then
  echo "expected non-zero rc for campaign summary missing trend support-rate evidence"
  cat /tmp/integration_profile_compare_multi_vm_reducer_bad_campaign.log
  exit 1
fi
if ! jq -e '
  .decision.decision == "NO-GO"
  and ((.errors // []) | map(test("support_rate_pct is missing/invalid")) | any)
' "$BAD_CAMPAIGN_SUMMARY" >/dev/null 2>&1; then
  echo "expected missing trend support-rate failure markers missing"
  cat "$BAD_CAMPAIGN_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-reducer] all checks passed"
