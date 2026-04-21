#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq mktemp rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

TREND_JSON="$TMP_DIR/profile_compare_trend_summary.json"
cat >"$TREND_JSON" <<'EOF_TREND'
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "notes": "trend pass",
  "summary": {
    "reports_total": 5,
    "pass_reports": 5,
    "warn_reports": 0,
    "fail_reports": 0
  },
  "decision": {
    "recommended_default_profile": "balanced",
    "source": "policy_reliability_latency",
    "rationale": "balanced is reliable",
    "recommendation_support_rate_pct": 80.0
  },
  "profiles": []
}
EOF_TREND

COMPARE_SUMMARY_POLICY_JSON="$TMP_DIR/profile_compare_local_summary_policy.json"
cat >"$COMPARE_SUMMARY_POLICY_JSON" <<'EOF_COMPARE_POLICY'
{
  "version": 1,
  "status": "pass",
  "summary": {
    "selection_policy": {
      "sticky_pair_sec": 0,
      "entry_rotation_sec": 0,
      "entry_rotation_jitter_pct": 0,
      "exit_exploration_pct": 10,
      "path_profile": "2hop"
    }
  }
}
EOF_COMPARE_POLICY

COMPARE_SUMMARY_POLICY_INVALID_JSON="$TMP_DIR/profile_compare_local_summary_policy_invalid.json"
cat >"$COMPARE_SUMMARY_POLICY_INVALID_JSON" <<'EOF_COMPARE_POLICY_INVALID'
{
  "version": 1,
  "status": "pass",
  "summary": {
    "selection_policy": {
      "sticky_pair_sec": 0,
      "entry_rotation_sec": 0,
      "entry_rotation_jitter_pct": 0,
      "exit_exploration_pct": "10",
      "path_profile": 2
    }
  }
}
EOF_COMPARE_POLICY_INVALID

CAMPAIGN_JSON="$TMP_DIR/profile_compare_campaign_summary.json"
cat >"$CAMPAIGN_JSON" <<EOF_CAMPAIGN
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "notes": "campaign pass",
  "summary": {
    "runs_total": 5,
    "runs_pass": 5,
    "runs_warn": 0,
    "runs_fail": 0,
    "runs_with_summary": 5
  },
  "decision": {
    "recommended_default_profile": "balanced",
    "source": "policy_reliability_latency",
    "rationale": "balanced remains best"
  },
  "trend": {
    "status": "pass",
    "rc": 0,
    "notes": "trend pass",
    "summary_json": "$TREND_JSON"
  },
  "selected_summaries": [
    "$COMPARE_SUMMARY_POLICY_JSON"
  ],
  "runs": []
}
EOF_CAMPAIGN

echo "[profile-compare-campaign-check] baseline pass"
BASELINE_SUMMARY="$TMP_DIR/campaign_check_baseline.json"
./scripts/profile_compare_campaign_check.sh \
  --campaign-summary-json "$CAMPAIGN_JSON" \
  --summary-json "$BASELINE_SUMMARY" \
  --print-summary-json 1 >/tmp/integration_profile_compare_campaign_check_baseline.log 2>&1

if ! rg -q '\[profile-compare-campaign-check\] decision=GO status=ok rc=0' /tmp/integration_profile_compare_campaign_check_baseline.log; then
  echo "expected GO baseline output not found"
  cat /tmp/integration_profile_compare_campaign_check_baseline.log
  exit 1
fi
if ! jq -e '.decision == "GO" and .status == "ok" and .rc == 0 and (.errors | length) == 0 and .observed.recommended_profile == "balanced" and .observed.selection_policy_evidence.present == true and .observed.selection_policy_evidence.valid == true and .observed.selection_policy_evidence.selected_summaries_total == 1 and .observed.selection_policy_evidence.selected_summaries_with_policy_valid == 1 and .inputs.policy.require_micro_relay_quality_evidence == false and .inputs.policy.require_micro_relay_quality_status_pass == false and .inputs.policy.require_micro_relay_demotion_policy == false and .inputs.policy.require_micro_relay_promotion_policy == false and .inputs.policy.require_trust_tier_port_unlock_policy == false' "$BASELINE_SUMMARY" >/dev/null 2>&1; then
  echo "baseline summary missing expected fields"
  cat "$BASELINE_SUMMARY"
  exit 1
fi

echo "[profile-compare-campaign-check] support rate fail-close"
set +e
./scripts/profile_compare_campaign_check.sh \
  --campaign-summary-json "$CAMPAIGN_JSON" \
  --require-recommendation-support-rate-pct 95 \
  --summary-json "$TMP_DIR/campaign_check_support_fail.json" >/tmp/integration_profile_compare_campaign_check_support_fail.log 2>&1
support_fail_rc=$?
set -e
if [[ "$support_fail_rc" -eq 0 ]]; then
  echo "expected non-zero rc for support-rate threshold failure"
  cat /tmp/integration_profile_compare_campaign_check_support_fail.log
  exit 1
fi
if ! rg -q 'recommendation support rate below threshold' /tmp/integration_profile_compare_campaign_check_support_fail.log; then
  echo "expected support-rate failure reason missing"
  cat /tmp/integration_profile_compare_campaign_check_support_fail.log
  exit 1
fi

echo "[profile-compare-campaign-check] selection policy evidence fail-close: present"
CAMPAIGN_NO_POLICY_JSON="$TMP_DIR/profile_compare_campaign_summary_no_policy.json"
cat >"$CAMPAIGN_NO_POLICY_JSON" <<EOF_CAMPAIGN_NO_POLICY
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "notes": "campaign pass",
  "summary": {
    "runs_total": 5,
    "runs_pass": 5,
    "runs_warn": 0,
    "runs_fail": 0,
    "runs_with_summary": 5
  },
  "decision": {
    "recommended_default_profile": "balanced",
    "source": "policy_reliability_latency",
    "rationale": "balanced remains best"
  },
  "trend": {
    "status": "pass",
    "rc": 0,
    "notes": "trend pass",
    "summary_json": "$TREND_JSON"
  },
  "selected_summaries": [],
  "runs": []
}
EOF_CAMPAIGN_NO_POLICY

set +e
./scripts/profile_compare_campaign_check.sh \
  --campaign-summary-json "$CAMPAIGN_NO_POLICY_JSON" \
  --require-selection-policy-present 1 \
  --summary-json "$TMP_DIR/campaign_check_selection_policy_present_fail.json" >/tmp/integration_profile_compare_campaign_check_selection_policy_present_fail.log 2>&1
selection_policy_present_fail_rc=$?
set -e
if [[ "$selection_policy_present_fail_rc" -eq 0 ]]; then
  echo "expected non-zero rc when selection policy evidence presence is required"
  cat /tmp/integration_profile_compare_campaign_check_selection_policy_present_fail.log
  exit 1
fi
if ! rg -q 'selection policy evidence is required but not present' /tmp/integration_profile_compare_campaign_check_selection_policy_present_fail.log; then
  echo "expected selection-policy present failure reason missing"
  cat /tmp/integration_profile_compare_campaign_check_selection_policy_present_fail.log
  exit 1
fi

echo "[profile-compare-campaign-check] selection policy evidence fail-close: valid"
CAMPAIGN_INVALID_POLICY_JSON="$TMP_DIR/profile_compare_campaign_summary_invalid_policy.json"
cat >"$CAMPAIGN_INVALID_POLICY_JSON" <<EOF_CAMPAIGN_INVALID_POLICY
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "notes": "campaign pass",
  "summary": {
    "runs_total": 5,
    "runs_pass": 5,
    "runs_warn": 0,
    "runs_fail": 0,
    "runs_with_summary": 5
  },
  "decision": {
    "recommended_default_profile": "balanced",
    "source": "policy_reliability_latency",
    "rationale": "balanced remains best"
  },
  "trend": {
    "status": "pass",
    "rc": 0,
    "notes": "trend pass",
    "summary_json": "$TREND_JSON"
  },
  "selected_summaries": [
    "$COMPARE_SUMMARY_POLICY_INVALID_JSON"
  ],
  "runs": []
}
EOF_CAMPAIGN_INVALID_POLICY

set +e
./scripts/profile_compare_campaign_check.sh \
  --campaign-summary-json "$CAMPAIGN_INVALID_POLICY_JSON" \
  --require-selection-policy-valid 1 \
  --summary-json "$TMP_DIR/campaign_check_selection_policy_valid_fail.json" >/tmp/integration_profile_compare_campaign_check_selection_policy_valid_fail.log 2>&1
selection_policy_valid_fail_rc=$?
set -e
if [[ "$selection_policy_valid_fail_rc" -eq 0 ]]; then
  echo "expected non-zero rc when selection policy evidence validity is required"
  cat /tmp/integration_profile_compare_campaign_check_selection_policy_valid_fail.log
  exit 1
fi
if ! rg -q 'selection policy evidence is required to be valid' /tmp/integration_profile_compare_campaign_check_selection_policy_valid_fail.log; then
  echo "expected selection-policy valid failure reason missing"
  cat /tmp/integration_profile_compare_campaign_check_selection_policy_valid_fail.log
  exit 1
fi

echo "[profile-compare-campaign-check] m4 policy fail-close: missing evidence"
set +e
./scripts/profile_compare_campaign_check.sh \
  --campaign-summary-json "$CAMPAIGN_JSON" \
  --require-micro-relay-quality-evidence 1 \
  --summary-json "$TMP_DIR/campaign_check_m4_quality_missing_fail.json" >/tmp/integration_profile_compare_campaign_check_m4_quality_missing_fail.log 2>&1
m4_quality_missing_fail_rc=$?
set -e
if [[ "$m4_quality_missing_fail_rc" -eq 0 ]]; then
  echo "expected non-zero rc when micro-relay quality evidence is required"
  cat /tmp/integration_profile_compare_campaign_check_m4_quality_missing_fail.log
  exit 1
fi
if ! rg -q 'micro-relay quality evidence is required but not present' /tmp/integration_profile_compare_campaign_check_m4_quality_missing_fail.log; then
  echo "expected micro-relay quality evidence failure reason missing"
  cat /tmp/integration_profile_compare_campaign_check_m4_quality_missing_fail.log
  exit 1
fi

CAMPAIGN_M4_PASS_JSON="$TMP_DIR/profile_compare_campaign_summary_m4_pass.json"
cat >"$CAMPAIGN_M4_PASS_JSON" <<EOF_CAMPAIGN_M4_PASS
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "notes": "campaign pass",
  "summary": {
    "runs_total": 5,
    "runs_pass": 5,
    "runs_warn": 0,
    "runs_fail": 0,
    "runs_with_summary": 5,
    "m4_micro_relay_evidence": {
      "available": true,
      "micro_relay_quality": {
        "available": true,
        "quality_band": "good",
        "quality_score": 91
      },
      "adaptive_demotion_promotion": {
        "available": true,
        "demotion_candidate": false,
        "promotion_candidate": true
      },
      "trust_tier_port_unlock_wiring": {
        "present": true,
        "evidence_hits": 2
      }
    }
  },
  "decision": {
    "recommended_default_profile": "balanced",
    "source": "policy_reliability_latency",
    "rationale": "balanced remains best"
  },
  "trend": {
    "status": "pass",
    "rc": 0,
    "notes": "trend pass",
    "summary_json": "$TREND_JSON"
  },
  "selected_summaries": [],
  "runs": []
}
EOF_CAMPAIGN_M4_PASS

echo "[profile-compare-campaign-check] m4 policy pass"
M4_PASS_SUMMARY="$TMP_DIR/campaign_check_m4_pass.json"
./scripts/profile_compare_campaign_check.sh \
  --campaign-summary-json "$CAMPAIGN_M4_PASS_JSON" \
  --require-micro-relay-quality-evidence 1 \
  --require-micro-relay-quality-status-pass 1 \
  --require-micro-relay-demotion-policy 1 \
  --require-micro-relay-promotion-policy 1 \
  --require-trust-tier-port-unlock-policy 1 \
  --summary-json "$M4_PASS_SUMMARY" \
  --print-summary-json 1 >/tmp/integration_profile_compare_campaign_check_m4_pass.log 2>&1
if ! rg -q '\[profile-compare-campaign-check\] decision=GO status=ok rc=0' /tmp/integration_profile_compare_campaign_check_m4_pass.log; then
  echo "expected GO output for m4 pass policy run not found"
  cat /tmp/integration_profile_compare_campaign_check_m4_pass.log
  exit 1
fi
if ! jq -e '.decision == "GO" and .status == "ok" and .rc == 0 and .inputs.policy.require_micro_relay_quality_evidence == true and .inputs.policy.require_micro_relay_quality_status_pass == true and .inputs.policy.require_micro_relay_demotion_policy == true and .inputs.policy.require_micro_relay_promotion_policy == true and .inputs.policy.require_trust_tier_port_unlock_policy == true and .observed.micro_relay_policy_evidence.quality_evidence_present == true and .observed.micro_relay_policy_evidence.quality_status_pass == true and .observed.micro_relay_policy_evidence.demotion_policy_present == true and .observed.micro_relay_policy_evidence.promotion_policy_present == true and .observed.micro_relay_policy_evidence.trust_tier_port_unlock_policy_present == true and (.decision_diagnostics.m4_policy.unmet_requirements | length) == 0' "$M4_PASS_SUMMARY" >/dev/null 2>&1; then
  echo "m4 pass summary missing expected fields"
  cat "$M4_PASS_SUMMARY"
  exit 1
fi

CAMPAIGN_M4_WARN_JSON="$TMP_DIR/profile_compare_campaign_summary_m4_warn.json"
cat >"$CAMPAIGN_M4_WARN_JSON" <<EOF_CAMPAIGN_M4_WARN
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "notes": "campaign pass",
  "summary": {
    "runs_total": 5,
    "runs_pass": 5,
    "runs_warn": 0,
    "runs_fail": 0,
    "runs_with_summary": 5,
    "m4_micro_relay_evidence": {
      "available": true,
      "micro_relay_quality": {
        "available": true,
        "quality_band": "poor",
        "quality_score": 32
      }
    }
  },
  "decision": {
    "recommended_default_profile": "balanced",
    "source": "policy_reliability_latency",
    "rationale": "balanced remains best"
  },
  "trend": {
    "status": "pass",
    "rc": 0,
    "notes": "trend pass",
    "summary_json": "$TREND_JSON"
  },
  "selected_summaries": [],
  "runs": []
}
EOF_CAMPAIGN_M4_WARN

echo "[profile-compare-campaign-check] m4 policy warn/non-blocking"
M4_WARN_SUMMARY="$TMP_DIR/campaign_check_m4_warn.json"
./scripts/profile_compare_campaign_check.sh \
  --campaign-summary-json "$CAMPAIGN_M4_WARN_JSON" \
  --require-micro-relay-quality-status-pass 1 \
  --fail-on-no-go 0 \
  --summary-json "$M4_WARN_SUMMARY" >/tmp/integration_profile_compare_campaign_check_m4_warn.log 2>&1
if ! rg -q '\[profile-compare-campaign-check\] decision=NO-GO status=fail rc=0' /tmp/integration_profile_compare_campaign_check_m4_warn.log; then
  echo "expected NO-GO non-blocking output for m4 warn run not found"
  cat /tmp/integration_profile_compare_campaign_check_m4_warn.log
  exit 1
fi
if ! jq -e '.decision == "NO-GO" and .status == "fail" and .rc == 0 and (.decision_diagnostics.m4_policy.unmet_requirements | index("micro_relay_quality_status_not_pass")) != null and (.errors[] | contains("micro-relay quality status must be pass"))' "$M4_WARN_SUMMARY" >/dev/null 2>&1; then
  echo "m4 warn summary missing expected fields"
  cat "$M4_WARN_SUMMARY"
  exit 1
fi

echo "[profile-compare-campaign-check] experimental default fail-close"
CAMPAIGN_EXP_JSON="$TMP_DIR/profile_compare_campaign_summary_exp.json"
cat >"$CAMPAIGN_EXP_JSON" <<EOF_CAMPAIGN_EXP
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "notes": "campaign pass",
  "summary": {
    "runs_total": 5,
    "runs_pass": 5,
    "runs_warn": 0,
    "runs_fail": 0,
    "runs_with_summary": 5
  },
  "decision": {
    "recommended_default_profile": "speed-1hop",
    "source": "vote_fallback",
    "rationale": "test invalid recommendation"
  },
  "trend": {
    "status": "pass",
    "rc": 0,
    "notes": "trend pass",
    "summary_json": "$TREND_JSON"
  },
  "selected_summaries": [
    "$COMPARE_SUMMARY_POLICY_JSON"
  ],
  "runs": []
}
EOF_CAMPAIGN_EXP

set +e
./scripts/profile_compare_campaign_check.sh \
  --campaign-summary-json "$CAMPAIGN_EXP_JSON" \
  --summary-json "$TMP_DIR/campaign_check_experimental_fail.json" >/tmp/integration_profile_compare_campaign_check_experimental_fail.log 2>&1
experimental_fail_rc=$?
set -e
if [[ "$experimental_fail_rc" -eq 0 ]]; then
  echo "expected non-zero rc for experimental-default failure"
  cat /tmp/integration_profile_compare_campaign_check_experimental_fail.log
  exit 1
fi
if ! rg -q 'speed-1hop is experimental and cannot be a default' /tmp/integration_profile_compare_campaign_check_experimental_fail.log; then
  echo "expected experimental-default failure reason missing"
  cat /tmp/integration_profile_compare_campaign_check_experimental_fail.log
  exit 1
fi

FORWARD_CAPTURE="$TMP_DIR/forward_capture.log"
FAKE_FORWARD="$TMP_DIR/fake_profile_compare_campaign_check_forward.sh"
cat >"$FAKE_FORWARD" <<'EOF_FORWARD'
#!/usr/bin/env bash
set -euo pipefail
printf 'profile-compare-campaign-check %s\n' "$*" >>"${FORWARD_CAPTURE_FILE:?}"
EOF_FORWARD
chmod +x "$FAKE_FORWARD"

: >"$FORWARD_CAPTURE"

echo "[profile-compare-campaign-check] easy_node forwarding"
FORWARD_CAPTURE_FILE="$FORWARD_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_FORWARD" \
./scripts/easy_node.sh profile-compare-campaign-check \
  --campaign-summary-json /tmp/campaign.json \
  --require-min-runs-total 7 \
  --require-selection-policy-present 1 \
  --require-selection-policy-valid 1 \
  --require-micro-relay-quality-evidence 1 \
  --require-micro-relay-quality-status-pass 1 \
  --require-micro-relay-demotion-policy 1 \
  --require-micro-relay-promotion-policy 1 \
  --require-trust-tier-port-unlock-policy 1 \
  --fail-on-no-go 0 \
  --print-summary-json 1

forward_line="$(rg '^profile-compare-campaign-check ' "$FORWARD_CAPTURE" | tail -n 1 || true)"
if [[ -z "$forward_line" ]]; then
  echo "missing easy_node forwarding capture"
  cat "$FORWARD_CAPTURE"
  exit 1
fi
for expected in '--campaign-summary-json /tmp/campaign.json' '--require-min-runs-total 7' '--require-selection-policy-present 1' '--require-selection-policy-valid 1' '--require-micro-relay-quality-evidence 1' '--require-micro-relay-quality-status-pass 1' '--require-micro-relay-demotion-policy 1' '--require-micro-relay-promotion-policy 1' '--require-trust-tier-port-unlock-policy 1' '--fail-on-no-go 0' '--print-summary-json 1'; do
  if ! grep -F -- "$expected" <<<"$forward_line" >/dev/null; then
    echo "easy_node forwarding missing $expected"
    cat "$FORWARD_CAPTURE"
    exit 1
  fi
done

echo "profile compare campaign check integration check ok"
