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
if ! jq -e '.decision == "GO" and .status == "ok" and .rc == 0 and (.errors | length) == 0 and .observed.recommended_profile == "balanced" and .observed.selection_policy_evidence.present == true and .observed.selection_policy_evidence.valid == true and .observed.selection_policy_evidence.selected_summaries_total == 1 and .observed.selection_policy_evidence.selected_summaries_with_policy_valid == 1 and .inputs.policy.require_micro_relay_quality_evidence == false and .inputs.policy.require_micro_relay_quality_status_pass == false and .inputs.policy.require_micro_relay_demotion_policy == false and .inputs.policy.require_micro_relay_promotion_policy == false and .inputs.policy.require_trust_tier_port_unlock_policy == false and .decision_diagnostics.m4_policy.gate_summary.required_total == 0 and .decision_diagnostics.m4_policy.gate_summary.required_failed == 0 and (.decision_diagnostics.m4_policy.gate_summary.failed_gate_ids | length) == 0 and .decision_diagnostics.m4_policy.gate_evaluation.micro_relay_quality_evidence.status == "not-required"' "$BASELINE_SUMMARY" >/dev/null 2>&1; then
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
        "quality_score": 91,
        "quality_score_avg": 91,
        "signals": {
          "transport_mismatch_failures_total": 0,
          "token_proof_invalid_failures_total": 0,
          "unknown_exit_failures_total": 0,
          "directory_trust_failures_total": 0
        }
      },
      "adaptive_demotion_promotion": {
        "available": true,
        "demotion_signal_count": 0,
        "promotion_signal_count": 4,
        "demotion_signal_count_total": 0,
        "promotion_signal_count_total": 4,
        "demotion_candidate": false,
        "promotion_candidate": true
      },
      "trust_tier_port_unlock_wiring": {
        "present": true,
        "evidence_hits": 2,
        "evidence_hits_total": 2
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
if ! jq -e '.decision == "GO" and .status == "ok" and .rc == 0 and .inputs.policy.require_micro_relay_quality_evidence == true and .inputs.policy.require_micro_relay_quality_status_pass == true and .inputs.policy.require_micro_relay_demotion_policy == true and .inputs.policy.require_micro_relay_promotion_policy == true and .inputs.policy.require_trust_tier_port_unlock_policy == true and .observed.micro_relay_policy_evidence.quality_evidence_present == true and .observed.micro_relay_policy_evidence.quality_status_pass == true and .observed.micro_relay_policy_evidence.demotion_policy_present == true and .observed.micro_relay_policy_evidence.promotion_policy_present == true and .observed.micro_relay_policy_evidence.trust_tier_port_unlock_policy_present == true and (.decision_diagnostics.m4_policy.unmet_requirements | length) == 0 and .decision_diagnostics.m4_policy.gate_summary.required_total == 5 and .decision_diagnostics.m4_policy.gate_summary.required_passed == 5 and .decision_diagnostics.m4_policy.gate_summary.required_failed == 0 and (.decision_diagnostics.m4_policy.gate_summary.failed_gate_ids | length) == 0 and .decision_diagnostics.m4_policy.gate_evaluation.micro_relay_quality_evidence.status == "pass" and .decision_diagnostics.m4_policy.gate_evaluation.micro_relay_quality_evidence.observed_any == true and .decision_diagnostics.m4_policy.gate_evaluation.micro_relay_quality_evidence.selected_summaries_total == 0 and .decision_diagnostics.m4_policy.gate_evaluation.micro_relay_demotion_policy.status == "pass" and .decision_diagnostics.m4_policy.gate_evaluation.micro_relay_demotion_policy.observed_any == true and .decision_diagnostics.m4_policy.gate_evaluation.micro_relay_demotion_policy.selected_summaries_total == 0 and .decision_diagnostics.m4_policy.gate_evaluation.trust_tier_port_unlock_policy.status == "pass" and .decision_diagnostics.m4_policy.gate_evaluation.trust_tier_port_unlock_policy.observed_any == true and .decision_diagnostics.m4_policy.gate_evaluation.trust_tier_port_unlock_policy.selected_summaries_total == 0' "$M4_PASS_SUMMARY" >/dev/null 2>&1; then
  echo "m4 pass summary missing expected fields"
  cat "$M4_PASS_SUMMARY"
  exit 1
fi
if ! jq -e '
  def num_or_null($value): ($value == null) or (($value | type) == "number");
  def bool_or_null($value): ($value == null) or (($value | type) == "boolean");
  def str_or_null($value): ($value == null) or (($value | type) == "string");
  .observed.micro_relay_policy_evidence.campaign_summary_details as $campaign
  | .decision_diagnostics.m4_policy.observed_details.campaign_summary as $diag_campaign
  | .observed.micro_relay_policy_evidence.selected_summaries_aggregate as $agg_observed
  | .decision_diagnostics.m4_policy.observed_details.selected_summaries_aggregate as $agg_diag
  | ($campaign == $diag_campaign)
    and ($agg_observed == $agg_diag)
    and (($campaign | type) == "object")
    and (($campaign.quality | type) == "object")
    and (($campaign.adaptive | type) == "object")
    and (($campaign.trust_tier | type) == "object")
    and num_or_null($campaign.quality.score)
    and num_or_null($campaign.quality.score_avg)
    and str_or_null($campaign.quality.band)
    and num_or_null($campaign.adaptive.demotion_signal_count)
    and num_or_null($campaign.adaptive.promotion_signal_count)
    and bool_or_null($campaign.adaptive.demotion_candidate)
    and bool_or_null($campaign.adaptive.promotion_candidate)
    and num_or_null($campaign.trust_tier.evidence_hits)
    and bool_or_null($campaign.trust_tier.present_flag)
    and (($campaign.quality.reason // "") != "summary_parse_error")
    and (($campaign.quality.reason // "") != "m4_evidence_missing")
    and (($campaign.adaptive.reason // "") != "summary_parse_error")
    and (($campaign.adaptive.reason // "") != "m4_evidence_missing")
    and (($campaign.trust_tier.reason // "") != "summary_parse_error")
    and (($campaign.trust_tier.reason // "") != "m4_evidence_missing")
    and (($campaign.quality.score | type) == "number")
    and (($campaign.quality.score_avg | type) == "number")
    and (($campaign.quality.band | type) == "string")
    and (($campaign.quality.band | ascii_downcase) == "good")
    and (($campaign.adaptive.demotion_signal_count | type) == "number")
    and (($campaign.adaptive.promotion_signal_count | type) == "number")
    and ($campaign.adaptive.demotion_candidate == false)
    and ($campaign.adaptive.promotion_candidate == true)
    and (($campaign.trust_tier.evidence_hits | type) == "number")
    and ($campaign.trust_tier.evidence_hits >= 0)
    and ($campaign.trust_tier.policy_present == true)
    and (($agg_observed.summaries_count | type) == "number")
    and num_or_null($agg_observed.quality.score_avg)
    and (($agg_observed.adaptive.demotion_signal_count_total | type) == "number")
    and (($agg_observed.adaptive.promotion_signal_count_total | type) == "number")
    and (($agg_observed.trust_tier.evidence_hits_total | type) == "number")
' "$M4_PASS_SUMMARY" >/dev/null 2>&1; then
  echo "m4 pass summary missing rich observed diagnostics fields"
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
        "quality_score": 32,
        "quality_score_avg": 32,
        "signals": {
          "transport_mismatch_failures_total": 2,
          "token_proof_invalid_failures_total": 3,
          "unknown_exit_failures_total": 0,
          "directory_trust_failures_total": 0
        }
      },
      "adaptive_demotion_promotion": {
        "available": false,
        "demotion_signal_count": null,
        "promotion_signal_count": null,
        "demotion_candidate": null,
        "promotion_candidate": null
      },
      "trust_tier_port_unlock_wiring": {
        "present": false,
        "evidence_hits": 0,
        "evidence_hits_total": 0
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
if ! jq -e '.decision == "NO-GO" and .status == "fail" and .rc == 0 and (.decision_diagnostics.m4_policy.unmet_requirements | index("micro_relay_quality_status_not_pass")) != null and (.errors[] | contains("micro-relay quality status must be pass")) and .decision_diagnostics.m4_policy.gate_summary.required_total == 1 and .decision_diagnostics.m4_policy.gate_summary.required_passed == 0 and .decision_diagnostics.m4_policy.gate_summary.required_failed == 1 and .decision_diagnostics.m4_policy.gate_summary.failed_gate_ids == ["micro_relay_quality_status_pass"] and .decision_diagnostics.m4_policy.gate_evaluation.micro_relay_quality_status_pass.status == "fail" and .decision_diagnostics.m4_policy.gate_evaluation.micro_relay_quality_status_pass.observed_any == false and .decision_diagnostics.m4_policy.gate_evaluation.micro_relay_quality_status_pass.selected_summaries_total == 0 and (.decision_diagnostics.m4_policy.gate_evaluation.micro_relay_quality_status_pass.actionable_reason | type) == "string"' "$M4_WARN_SUMMARY" >/dev/null 2>&1; then
  echo "m4 warn summary missing expected fields"
  cat "$M4_WARN_SUMMARY"
  exit 1
fi
if ! jq -e '
  def num_or_null($value): ($value == null) or (($value | type) == "number");
  def bool_or_null($value): ($value == null) or (($value | type) == "boolean");
  def str_or_null($value): ($value == null) or (($value | type) == "string");
  .observed.micro_relay_policy_evidence.campaign_summary_details as $campaign
  | .decision_diagnostics.m4_policy.observed_details.campaign_summary as $diag_campaign
  | .observed.micro_relay_policy_evidence.selected_summaries_aggregate as $agg_observed
  | .decision_diagnostics.m4_policy.observed_details.selected_summaries_aggregate as $agg_diag
  | ($campaign == $diag_campaign)
    and ($agg_observed == $agg_diag)
    and (($campaign | type) == "object")
    and (($campaign.quality | type) == "object")
    and (($campaign.adaptive | type) == "object")
    and (($campaign.trust_tier | type) == "object")
    and num_or_null($campaign.quality.score)
    and num_or_null($campaign.quality.score_avg)
    and str_or_null($campaign.quality.band)
    and num_or_null($campaign.adaptive.demotion_signal_count)
    and num_or_null($campaign.adaptive.promotion_signal_count)
    and bool_or_null($campaign.adaptive.demotion_candidate)
    and bool_or_null($campaign.adaptive.promotion_candidate)
    and num_or_null($campaign.trust_tier.evidence_hits)
    and bool_or_null($campaign.trust_tier.present_flag)
    and (($campaign.quality.reason // "") != "summary_parse_error")
    and (($campaign.quality.reason // "") != "m4_evidence_missing")
    and (($campaign.adaptive.reason // "") != "summary_parse_error")
    and (($campaign.adaptive.reason // "") != "m4_evidence_missing")
    and (($campaign.trust_tier.reason // "") != "summary_parse_error")
    and (($campaign.trust_tier.reason // "") != "m4_evidence_missing")
    and (($campaign.quality.score | type) == "number")
    and (($campaign.quality.score_avg | type) == "number")
    and (($campaign.quality.band | type) == "string")
    and (($campaign.quality.band | ascii_downcase) == "poor")
    and num_or_null($campaign.adaptive.demotion_signal_count)
    and num_or_null($campaign.adaptive.promotion_signal_count)
    and bool_or_null($campaign.adaptive.demotion_candidate)
    and bool_or_null($campaign.adaptive.promotion_candidate)
    and num_or_null($campaign.trust_tier.evidence_hits)
    and bool_or_null($campaign.trust_tier.present_flag)
    and (($agg_observed.summaries_count | type) == "number")
    and num_or_null($agg_observed.quality.score_avg)
    and (($agg_observed.adaptive.demotion_signal_count_total | type) == "number")
    and (($agg_observed.adaptive.promotion_signal_count_total | type) == "number")
    and (($agg_observed.trust_tier.evidence_hits_total | type) == "number")
' "$M4_WARN_SUMMARY" >/dev/null 2>&1; then
  echo "m4 warn summary missing rich observed diagnostics fields"
  cat "$M4_WARN_SUMMARY"
  exit 1
fi

echo "[profile-compare-campaign-check] m4 malformed object fail-close"
CAMPAIGN_M4_MALFORMED_JSON="$TMP_DIR/profile_compare_campaign_summary_m4_malformed.json"
cat >"$CAMPAIGN_M4_MALFORMED_JSON" <<EOF_CAMPAIGN_M4_MALFORMED
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
      "micro_relay_quality": {},
      "adaptive_demotion_promotion": {
        "available": true
      },
      "trust_tier_port_unlock_wiring": {
        "available": true
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
EOF_CAMPAIGN_M4_MALFORMED

M4_MALFORMED_SUMMARY="$TMP_DIR/campaign_check_m4_malformed_fail.json"
./scripts/profile_compare_campaign_check.sh \
  --campaign-summary-json "$CAMPAIGN_M4_MALFORMED_JSON" \
  --require-micro-relay-quality-evidence 1 \
  --require-micro-relay-demotion-policy 1 \
  --require-micro-relay-promotion-policy 1 \
  --require-trust-tier-port-unlock-policy 1 \
  --fail-on-no-go 0 \
  --summary-json "$M4_MALFORMED_SUMMARY" >/tmp/integration_profile_compare_campaign_check_m4_malformed.log 2>&1
if ! rg -q '\[profile-compare-campaign-check\] decision=NO-GO status=fail rc=0' /tmp/integration_profile_compare_campaign_check_m4_malformed.log; then
  echo "expected NO-GO output for malformed m4 evidence run not found"
  cat /tmp/integration_profile_compare_campaign_check_m4_malformed.log
  exit 1
fi
if ! jq -e '.decision == "NO-GO" and .status == "fail" and .rc == 0 and .decision_diagnostics.m4_policy.gate_evaluation.micro_relay_quality_evidence.observed == false and .decision_diagnostics.m4_policy.gate_evaluation.micro_relay_demotion_policy.observed == false and .decision_diagnostics.m4_policy.gate_evaluation.micro_relay_promotion_policy.observed == false and .decision_diagnostics.m4_policy.gate_evaluation.trust_tier_port_unlock_policy.observed == false and (.decision_diagnostics.m4_policy.unmet_requirements | index("missing_micro_relay_quality_evidence")) != null and (.decision_diagnostics.m4_policy.unmet_requirements | index("missing_micro_relay_demotion_policy")) != null and (.decision_diagnostics.m4_policy.unmet_requirements | index("missing_micro_relay_promotion_policy")) != null and (.decision_diagnostics.m4_policy.unmet_requirements | index("missing_trust_tier_port_unlock_policy")) != null' "$M4_MALFORMED_SUMMARY" >/dev/null 2>&1; then
  echo "m4 malformed summary did not fail-close as expected"
  cat "$M4_MALFORMED_SUMMARY"
  exit 1
fi

echo "[profile-compare-campaign-check] m4 selected-summary strict coverage fail-close"
SELECTED_M4_DEMOTION_PRESENT_JSON="$TMP_DIR/profile_compare_selected_m4_demotion_present.json"
cat >"$SELECTED_M4_DEMOTION_PRESENT_JSON" <<'EOF_SELECTED_M4_DEMOTION_PRESENT'
{
  "summary": {
    "m4_micro_relay_evidence": {
      "adaptive_demotion_promotion": {
        "demotion_candidate": true,
        "promotion_candidate": false
      }
    }
  }
}
EOF_SELECTED_M4_DEMOTION_PRESENT

SELECTED_M4_DEMOTION_MISSING_JSON="$TMP_DIR/profile_compare_selected_m4_demotion_missing.json"
cat >"$SELECTED_M4_DEMOTION_MISSING_JSON" <<'EOF_SELECTED_M4_DEMOTION_MISSING'
{
  "summary": {
    "m4_micro_relay_evidence": {
      "micro_relay_quality": {
        "quality_score": 90,
        "quality_band": "good"
      }
    }
  }
}
EOF_SELECTED_M4_DEMOTION_MISSING

CAMPAIGN_M4_PARTIAL_SELECTED_JSON="$TMP_DIR/profile_compare_campaign_summary_m4_partial_selected.json"
cat >"$CAMPAIGN_M4_PARTIAL_SELECTED_JSON" <<EOF_CAMPAIGN_M4_PARTIAL_SELECTED
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
    "$SELECTED_M4_DEMOTION_PRESENT_JSON",
    "$SELECTED_M4_DEMOTION_MISSING_JSON"
  ],
  "runs": []
}
EOF_CAMPAIGN_M4_PARTIAL_SELECTED

M4_PARTIAL_SELECTED_SUMMARY="$TMP_DIR/campaign_check_m4_partial_selected_fail.json"
./scripts/profile_compare_campaign_check.sh \
  --campaign-summary-json "$CAMPAIGN_M4_PARTIAL_SELECTED_JSON" \
  --require-micro-relay-demotion-policy 1 \
  --fail-on-no-go 0 \
  --summary-json "$M4_PARTIAL_SELECTED_SUMMARY" >/tmp/integration_profile_compare_campaign_check_m4_partial_selected.log 2>&1
if ! rg -q '\[profile-compare-campaign-check\] decision=NO-GO status=fail rc=0' /tmp/integration_profile_compare_campaign_check_m4_partial_selected.log; then
  echo "expected NO-GO output for partial selected-summary m4 run not found"
  cat /tmp/integration_profile_compare_campaign_check_m4_partial_selected.log
  exit 1
fi
if ! jq -e '.decision == "NO-GO" and .status == "fail" and .rc == 0 and .decision_diagnostics.m4_policy.gate_evaluation.micro_relay_demotion_policy.status == "fail" and .decision_diagnostics.m4_policy.gate_evaluation.micro_relay_demotion_policy.observed == false and .decision_diagnostics.m4_policy.gate_evaluation.micro_relay_demotion_policy.observed_any == true and .decision_diagnostics.m4_policy.gate_evaluation.micro_relay_demotion_policy.selected_summaries_total == 2 and .decision_diagnostics.m4_policy.gate_evaluation.micro_relay_demotion_policy.selected_summaries_with_signal == 1 and (.decision_diagnostics.m4_policy.unmet_requirements | index("missing_micro_relay_demotion_policy")) != null' "$M4_PARTIAL_SELECTED_SUMMARY" >/dev/null 2>&1; then
  echo "m4 partial selected-summary coverage did not fail-close as expected"
  cat "$M4_PARTIAL_SELECTED_SUMMARY"
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
