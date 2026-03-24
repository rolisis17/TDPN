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

LOCAL_CAPTURE="$TMP_DIR/fake_local_calls.log"
TREND_CAPTURE="$TMP_DIR/fake_trend_calls.log"
LOCAL_COUNTER="$TMP_DIR/local_counter.txt"

FAKE_LOCAL="$TMP_DIR/fake_profile_compare_local.sh"
cat >"$FAKE_LOCAL" <<'EOF_LOCAL'
#!/usr/bin/env bash
set -euo pipefail

summary_json=""
report_md=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --report-md)
      report_md="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" || -z "$report_md" ]]; then
  echo "fake local missing summary/report paths"
  exit 2
fi

count=0
if [[ -f "${FAKE_LOCAL_COUNTER_FILE:?}" ]]; then
  count="$(cat "${FAKE_LOCAL_COUNTER_FILE:?}")"
fi
count=$((count + 1))
printf '%s\n' "$count" >"${FAKE_LOCAL_COUNTER_FILE:?}"

printf 'run=%s summary=%s report=%s\n' "$count" "$summary_json" "$report_md" >>"${FAKE_LOCAL_CAPTURE_FILE:?}"

status="pass"
rc=0
notes="fake local pass"
if [[ "${FAKE_LOCAL_FAIL_AT:-0}" =~ ^[0-9]+$ ]] && ((FAKE_LOCAL_FAIL_AT > 0)) && ((count == FAKE_LOCAL_FAIL_AT)); then
  status="fail"
  rc=1
  notes="fake local forced failure"
fi

recommended="balanced"
if ((count % 2 == 0)); then
  recommended="speed"
fi

cat >"$summary_json" <<EOF_SUMMARY
{
  "version": 1,
  "status": "$status",
  "rc": $rc,
  "notes": "$notes",
  "summary": {
    "runs_executed": 4,
    "runs_fail": $rc
  },
  "decision": {
    "recommended_default_profile": "$recommended"
  },
  "profiles": [
    {"profile": "balanced", "runs_executed": 4, "runs_pass": 4, "runs_fail": 0, "avg_duration_sec": 10.2},
    {"profile": "speed", "runs_executed": 4, "runs_pass": 4, "runs_fail": 0, "avg_duration_sec": 9.6},
    {"profile": "private", "runs_executed": 4, "runs_pass": 4, "runs_fail": 0, "avg_duration_sec": 12.8},
    {"profile": "speed-1hop", "runs_executed": 4, "runs_pass": 4, "runs_fail": 0, "avg_duration_sec": 7.1}
  ]
}
EOF_SUMMARY

cat >"$report_md" <<EOF_REPORT
# Fake Local Report $count
EOF_REPORT

if [[ "$rc" -ne 0 ]]; then
  exit "$rc"
fi
exit 0
EOF_LOCAL
chmod +x "$FAKE_LOCAL"

FAKE_TREND="$TMP_DIR/fake_profile_compare_trend.sh"
cat >"$FAKE_TREND" <<'EOF_TREND'
#!/usr/bin/env bash
set -euo pipefail

summary_json=""
report_md=""
declare -a summaries=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --compare-summary-json)
      summaries+=("${2:-}")
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --report-md)
      report_md="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" || -z "$report_md" ]]; then
  echo "fake trend missing summary/report paths"
  exit 2
fi

printf 'summaries=%s summary_json=%s report_md=%s\n' "${#summaries[@]}" "$summary_json" "$report_md" >>"${FAKE_TREND_CAPTURE_FILE:?}"

recommended="balanced"
speed_votes=0
balanced_votes=0
for summary_path in "${summaries[@]}"; do
  if [[ -f "$summary_path" ]]; then
    vote="$(jq -r '.decision.recommended_default_profile // ""' "$summary_path" 2>/dev/null || true)"
    if [[ "$vote" == "speed" ]]; then
      speed_votes=$((speed_votes + 1))
    elif [[ "$vote" == "balanced" ]]; then
      balanced_votes=$((balanced_votes + 1))
    fi
  fi
done
if ((speed_votes > balanced_votes)); then
  recommended="speed"
fi

status="pass"
rc=0
notes="fake trend pass"
if [[ "${FAKE_TREND_FORCE_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc=1
  notes="fake trend forced failure"
fi

cat >"$summary_json" <<EOF_SUMMARY
{
  "version": 1,
  "status": "$status",
  "rc": $rc,
  "notes": "$notes",
  "summary": {
    "reports_total": ${#summaries[@]},
    "pass_reports": ${#summaries[@]},
    "warn_reports": 0,
    "fail_reports": 0
  },
  "decision": {
    "recommended_default_profile": "$recommended",
    "source": "fake_trend",
    "rationale": "fake trend rationale"
  },
  "profiles": []
}
EOF_SUMMARY

cat >"$report_md" <<EOF_REPORT
# Fake Trend Report
EOF_REPORT

if [[ "$rc" -ne 0 ]]; then
  exit "$rc"
fi
exit 0
EOF_TREND
chmod +x "$FAKE_TREND"

echo "[profile-compare-campaign] success path"
SUCCESS_JSON="$TMP_DIR/campaign_success.json"
SUCCESS_REPORT="$TMP_DIR/campaign_success.md"
PROFILE_COMPARE_CAMPAIGN_LOCAL_SCRIPT="$FAKE_LOCAL" \
PROFILE_COMPARE_CAMPAIGN_TREND_SCRIPT="$FAKE_TREND" \
FAKE_LOCAL_CAPTURE_FILE="$LOCAL_CAPTURE" \
FAKE_LOCAL_COUNTER_FILE="$LOCAL_COUNTER" \
FAKE_LOCAL_FAIL_AT=0 \
FAKE_TREND_CAPTURE_FILE="$TREND_CAPTURE" \
FAKE_TREND_FORCE_FAIL=0 \
./scripts/profile_compare_campaign.sh \
  --campaign-runs 3 \
  --campaign-pause-sec 0 \
  --summary-json "$SUCCESS_JSON" \
  --report-md "$SUCCESS_REPORT" \
  --print-summary-json 1 >/tmp/integration_profile_compare_campaign_success.log 2>&1

if ! rg -q 'profile-compare-campaign: status=pass' /tmp/integration_profile_compare_campaign_success.log; then
  echo "expected campaign success status output"
  cat /tmp/integration_profile_compare_campaign_success.log
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .summary.runs_total == 3
  and .summary.runs_fail == 0
  and (.selected_summaries | length) == 3
  and .trend.status == "pass"
' "$SUCCESS_JSON" >/dev/null 2>&1; then
  echo "campaign success summary missing expected fields"
  cat "$SUCCESS_JSON"
  exit 1
fi

echo "[profile-compare-campaign] warn path from local run failure"
: >"$LOCAL_CAPTURE"
: >"$TREND_CAPTURE"
printf '0\n' >"$LOCAL_COUNTER"
WARN_JSON="$TMP_DIR/campaign_warn.json"
PROFILE_COMPARE_CAMPAIGN_LOCAL_SCRIPT="$FAKE_LOCAL" \
PROFILE_COMPARE_CAMPAIGN_TREND_SCRIPT="$FAKE_TREND" \
FAKE_LOCAL_CAPTURE_FILE="$LOCAL_CAPTURE" \
FAKE_LOCAL_COUNTER_FILE="$LOCAL_COUNTER" \
FAKE_LOCAL_FAIL_AT=2 \
FAKE_TREND_CAPTURE_FILE="$TREND_CAPTURE" \
FAKE_TREND_FORCE_FAIL=0 \
./scripts/profile_compare_campaign.sh \
  --campaign-runs 3 \
  --summary-json "$WARN_JSON" >/tmp/integration_profile_compare_campaign_warn.log 2>&1

if ! rg -q 'profile-compare-campaign: status=warn' /tmp/integration_profile_compare_campaign_warn.log; then
  echo "expected campaign warn status output"
  cat /tmp/integration_profile_compare_campaign_warn.log
  exit 1
fi
if ! jq -e '.status == "warn" and .rc == 0 and .summary.runs_fail == 1 and .trend.status == "pass"' "$WARN_JSON" >/dev/null 2>&1; then
  echo "campaign warn summary missing expected fields"
  cat "$WARN_JSON"
  exit 1
fi

echo "[profile-compare-campaign] fail path from trend failure"
: >"$LOCAL_CAPTURE"
: >"$TREND_CAPTURE"
printf '0\n' >"$LOCAL_COUNTER"
set +e
PROFILE_COMPARE_CAMPAIGN_LOCAL_SCRIPT="$FAKE_LOCAL" \
PROFILE_COMPARE_CAMPAIGN_TREND_SCRIPT="$FAKE_TREND" \
FAKE_LOCAL_CAPTURE_FILE="$LOCAL_CAPTURE" \
FAKE_LOCAL_COUNTER_FILE="$LOCAL_COUNTER" \
FAKE_LOCAL_FAIL_AT=0 \
FAKE_TREND_CAPTURE_FILE="$TREND_CAPTURE" \
FAKE_TREND_FORCE_FAIL=1 \
./scripts/profile_compare_campaign.sh \
  --campaign-runs 2 \
  --summary-json "$TMP_DIR/campaign_fail.json" >/tmp/integration_profile_compare_campaign_fail.log 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -eq 0 ]]; then
  echo "expected non-zero rc when trend fails"
  cat /tmp/integration_profile_compare_campaign_fail.log
  exit 1
fi
if ! rg -q 'profile-compare-campaign: status=fail' /tmp/integration_profile_compare_campaign_fail.log; then
  echo "expected campaign fail status output"
  cat /tmp/integration_profile_compare_campaign_fail.log
  exit 1
fi

FORWARD_CAPTURE="$TMP_DIR/forward_capture.log"
FAKE_FORWARD="$TMP_DIR/fake_profile_compare_campaign_forward.sh"
cat >"$FAKE_FORWARD" <<'EOF_FORWARD'
#!/usr/bin/env bash
set -euo pipefail
printf 'profile-compare-campaign %s\n' "$*" >>"${FORWARD_CAPTURE_FILE:?}"
EOF_FORWARD
chmod +x "$FAKE_FORWARD"

: >"$FORWARD_CAPTURE"

echo "[profile-compare-campaign] easy_node forwarding"
FORWARD_CAPTURE_FILE="$FORWARD_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_FORWARD" \
./scripts/easy_node.sh profile-compare-campaign \
  --campaign-runs 4 \
  --reports-dir /tmp/profile_compare_campaign_reports \
  --print-summary-json 1

forward_line="$(rg '^profile-compare-campaign ' "$FORWARD_CAPTURE" | tail -n 1 || true)"
if [[ -z "$forward_line" ]]; then
  echo "missing easy_node forwarding capture"
  cat "$FORWARD_CAPTURE"
  exit 1
fi
for expected in '--campaign-runs 4' '--reports-dir /tmp/profile_compare_campaign_reports' '--print-summary-json 1'; do
  if ! grep -F -- "$expected" <<<"$forward_line" >/dev/null; then
    echo "easy_node forwarding missing $expected"
    cat "$FORWARD_CAPTURE"
    exit 1
  fi
done

echo "profile compare campaign integration check ok"
