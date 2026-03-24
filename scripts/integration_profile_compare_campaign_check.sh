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
if ! jq -e '.decision == "GO" and .status == "ok" and .rc == 0 and (.errors | length) == 0 and .observed.recommended_profile == "balanced"' "$BASELINE_SUMMARY" >/dev/null 2>&1; then
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
  --fail-on-no-go 0 \
  --print-summary-json 1

forward_line="$(rg '^profile-compare-campaign-check ' "$FORWARD_CAPTURE" | tail -n 1 || true)"
if [[ -z "$forward_line" ]]; then
  echo "missing easy_node forwarding capture"
  cat "$FORWARD_CAPTURE"
  exit 1
fi
for expected in '--campaign-summary-json /tmp/campaign.json' '--require-min-runs-total 7' '--fail-on-no-go 0' '--print-summary-json 1'; do
  if ! grep -F -- "$expected" <<<"$forward_line" >/dev/null; then
    echo "easy_node forwarding missing $expected"
    cat "$FORWARD_CAPTURE"
    exit 1
  fi
done

echo "profile compare campaign check integration check ok"
