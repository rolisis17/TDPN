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

SIGNOFF_CAPTURE="$TMP_DIR/signoff_capture.log"
FORWARD_CAPTURE="$TMP_DIR/forward_capture.log"

FAKE_CAMPAIGN="$TMP_DIR/fake_profile_compare_campaign.sh"
cat >"$FAKE_CAMPAIGN" <<'EOF_FAKE_CAMPAIGN'
#!/usr/bin/env bash
set -euo pipefail
printf 'campaign %s\n' "$*" >>"${SIGNOFF_CAPTURE_FILE:?}"
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
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<'EOF_SUMMARY'
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "summary": {
    "runs_total": 5,
    "runs_pass": 5,
    "runs_warn": 0,
    "runs_fail": 0,
    "runs_with_summary": 5
  },
  "decision": {
    "recommended_default_profile": "balanced",
    "source": "policy_reliability_latency"
  },
  "trend": {
    "status": "pass",
    "rc": 0,
    "summary_json": ""
  }
}
EOF_SUMMARY
fi
if [[ -n "$report_md" ]]; then
  mkdir -p "$(dirname "$report_md")"
  printf '# fake campaign report\n' >"$report_md"
fi
exit "${FAKE_CAMPAIGN_RC:-0}"
EOF_FAKE_CAMPAIGN
chmod +x "$FAKE_CAMPAIGN"

FAKE_CHECK="$TMP_DIR/fake_profile_compare_campaign_check.sh"
cat >"$FAKE_CHECK" <<'EOF_FAKE_CHECK'
#!/usr/bin/env bash
set -euo pipefail
printf 'check %s\n' "$*" >>"${SIGNOFF_CAPTURE_FILE:?}"
summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$summary_json" ]]; then
  if [[ "${FAKE_CHECK_SKIP_SUMMARY_WRITE:-0}" != "1" ]]; then
    mkdir -p "$(dirname "$summary_json")"
    decision="${FAKE_CHECK_DECISION:-GO}"
    support="${FAKE_CHECK_SUPPORT_PCT:-80}"
    cat >"$summary_json" <<EOF_SUMMARY
{
  "decision": "$decision",
  "status": "ok",
  "rc": 0,
  "errors": [],
  "observed": {
    "recommended_profile": "balanced",
    "support_rate_pct": $support,
    "trend_source": "policy_reliability_latency"
  }
}
EOF_SUMMARY
  fi
fi
if [[ -n "${FAKE_CHECK_FAILURE_LINE:-}" ]]; then
  echo "$FAKE_CHECK_FAILURE_LINE" >&2
fi
exit "${FAKE_CHECK_RC:-0}"
EOF_FAKE_CHECK
chmod +x "$FAKE_CHECK"

echo "[profile-compare-campaign-signoff] success path"
: >"$SIGNOFF_CAPTURE"
SUCCESS_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_success.json"
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=0 \
FAKE_CHECK_DECISION=GO \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_success" \
  --refresh-campaign 1 \
  --fail-on-no-go 1 \
  --require-min-runs-total 5 \
  --campaign-execution-mode docker \
  --campaign-directory-urls "http://127.0.0.1:18081,http://127.0.0.1:28081" \
  --campaign-bootstrap-directory "http://127.0.0.1:18081" \
  --campaign-discovery-wait-sec 7 \
  --campaign-issuer-url "http://127.0.0.1:18082" \
  --campaign-entry-url "http://127.0.0.1:18083" \
  --campaign-exit-url "http://127.0.0.1:18084" \
  --campaign-start-local-stack 0 \
  --summary-json "$SUCCESS_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_campaign_signoff_success.log 2>&1

if ! rg -q '\[profile-compare-campaign-signoff\] status=ok final_rc=0 decision=GO' /tmp/integration_profile_compare_campaign_signoff_success.log; then
  echo "expected success status line not found"
  cat /tmp/integration_profile_compare_campaign_signoff_success.log
  exit 1
fi
if ! jq -e '.status == "ok" and .final_rc == 0 and .decision.decision == "GO" and .stages.campaign.status == "pass" and .stages.campaign_check.status == "pass" and .stages.campaign.attempted == true and .stages.campaign_check.attempted == true and .inputs.campaign_refresh_overrides.execution_mode == "docker" and .inputs.campaign_refresh_overrides.directory_urls == "http://127.0.0.1:18081,http://127.0.0.1:28081" and .inputs.campaign_refresh_overrides.bootstrap_directory == "http://127.0.0.1:18081" and .inputs.campaign_refresh_overrides.discovery_wait_sec == 7 and .inputs.campaign_refresh_overrides.issuer_url == "http://127.0.0.1:18082" and .inputs.campaign_refresh_overrides.entry_url == "http://127.0.0.1:18083" and .inputs.campaign_refresh_overrides.exit_url == "http://127.0.0.1:18084" and .inputs.campaign_refresh_overrides.start_local_stack == "0"' "$SUCCESS_SUMMARY" >/dev/null 2>&1; then
  echo "success summary JSON missing expected fields"
  cat "$SUCCESS_SUMMARY"
  exit 1
fi
first_stage="$(sed -n '1p' "$SIGNOFF_CAPTURE" || true)"
second_stage="$(sed -n '2p' "$SIGNOFF_CAPTURE" || true)"
if [[ "$first_stage" != campaign* ]]; then
  echo "expected campaign stage to run first"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if [[ "$second_stage" != check* ]]; then
  echo "expected campaign-check stage to run second"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-min-runs-total 5' "$SIGNOFF_CAPTURE"; then
  echo "expected check forwarding flag missing"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
for expected in \
  '--execution-mode docker' \
  '--directory-urls http://127.0.0.1:18081,http://127.0.0.1:28081' \
  '--bootstrap-directory http://127.0.0.1:18081' \
  '--discovery-wait-sec 7' \
  '--issuer-url http://127.0.0.1:18082' \
  '--entry-url http://127.0.0.1:18083' \
  '--exit-url http://127.0.0.1:18084' \
  '--start-local-stack 0'; do
  if ! rg -q -- "$expected" "$SIGNOFF_CAPTURE"; then
    echo "expected campaign forwarding flag missing: $expected"
    cat "$SIGNOFF_CAPTURE"
    exit 1
  fi
done

echo "[profile-compare-campaign-signoff] campaign failure fail-close"
: >"$SIGNOFF_CAPTURE"
CAMPAIGN_FAIL_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_campaign_fail.json"
set +e
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_RC=23 \
FAKE_CHECK_RC=0 \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_campaign_fail" \
  --refresh-campaign 1 \
  --summary-json "$CAMPAIGN_FAIL_SUMMARY" >/tmp/integration_profile_compare_campaign_signoff_campaign_fail.log 2>&1
rc_campaign_fail=$?
set -e
if [[ "$rc_campaign_fail" -ne 23 ]]; then
  echo "expected rc=23 when campaign stage fails"
  cat /tmp/integration_profile_compare_campaign_signoff_campaign_fail.log
  exit 1
fi
if [[ "$(wc -l < "$SIGNOFF_CAPTURE")" -ne 1 ]]; then
  echo "campaign-fail path should not run check stage"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! jq -e '.status == "fail" and .final_rc == 23 and .failure_stage == "campaign" and .stages.campaign.status == "fail" and .stages.campaign_check.attempted == false' "$CAMPAIGN_FAIL_SUMMARY" >/dev/null 2>&1; then
  echo "campaign-fail summary JSON missing expected fields"
  cat "$CAMPAIGN_FAIL_SUMMARY"
  exit 1
fi

echo "[profile-compare-campaign-signoff] check failure fail-close"
: >"$SIGNOFF_CAPTURE"
CHECK_FAIL_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_check_fail.json"
set +e
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=19 \
FAKE_CHECK_DECISION=NO-GO \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_check_fail" \
  --refresh-campaign 1 \
  --summary-json "$CHECK_FAIL_SUMMARY" >/tmp/integration_profile_compare_campaign_signoff_check_fail.log 2>&1
rc_check_fail=$?
set -e
if [[ "$rc_check_fail" -ne 19 ]]; then
  echo "expected rc=19 when campaign-check stage fails"
  cat /tmp/integration_profile_compare_campaign_signoff_check_fail.log
  exit 1
fi
if ! jq -e '.status == "fail" and .final_rc == 19 and .failure_stage == "campaign_check" and .decision.decision == "NO-GO" and .stages.campaign.status == "pass" and .stages.campaign_check.status == "fail"' "$CHECK_FAIL_SUMMARY" >/dev/null 2>&1; then
  echo "check-fail summary JSON missing expected fields"
  cat "$CHECK_FAIL_SUMMARY"
  exit 1
fi

echo "[profile-compare-campaign-signoff] check failure missing campaign artifact yields deterministic NO-GO context"
: >"$SIGNOFF_CAPTURE"
CHECK_FAIL_MISSING_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_check_fail_missing_campaign_summary.json"
set +e
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=1 \
FAKE_CHECK_SKIP_SUMMARY_WRITE=1 \
FAKE_CHECK_FAILURE_LINE='profile-compare-campaign-check failed: campaign summary JSON not found' \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_check_fail_missing_campaign_summary" \
  --refresh-campaign 1 \
  --summary-json "$CHECK_FAIL_MISSING_SUMMARY" >/tmp/integration_profile_compare_campaign_signoff_check_fail_missing_campaign_summary.log 2>&1
rc_check_fail_missing_summary=$?
set -e
if [[ "$rc_check_fail_missing_summary" -ne 1 ]]; then
  echo "expected rc=1 when campaign-check fails without summary (missing campaign artifact)"
  cat /tmp/integration_profile_compare_campaign_signoff_check_fail_missing_campaign_summary.log
  exit 1
fi
if ! jq -e '.status == "fail" and .final_rc == 1 and .failure_stage == "campaign_check" and .decision.decision == "NO-GO" and .decision.context == "synthetic_campaign_check_failure" and .decision.from_campaign_check_summary == false and .decision.reason == "campaign summary JSON missing" and .stages.campaign.status == "pass" and .stages.campaign_check.status == "fail"' "$CHECK_FAIL_MISSING_SUMMARY" >/dev/null 2>&1; then
  echo "missing-campaign-artifact check-fail summary JSON missing deterministic NO-GO context"
  cat "$CHECK_FAIL_MISSING_SUMMARY"
  exit 1
fi

echo "[profile-compare-campaign-signoff] check failure invalid campaign artifact yields deterministic NO-GO context"
: >"$SIGNOFF_CAPTURE"
CHECK_FAIL_INVALID_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_check_fail_invalid_campaign_summary.json"
set +e
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=1 \
FAKE_CHECK_SKIP_SUMMARY_WRITE=1 \
FAKE_CHECK_FAILURE_LINE='profile-compare-campaign-check failed: invalid campaign summary JSON schema (/tmp/fake.json)' \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_check_fail_invalid_campaign_summary" \
  --refresh-campaign 1 \
  --summary-json "$CHECK_FAIL_INVALID_SUMMARY" >/tmp/integration_profile_compare_campaign_signoff_check_fail_invalid_campaign_summary.log 2>&1
rc_check_fail_invalid_summary=$?
set -e
if [[ "$rc_check_fail_invalid_summary" -ne 1 ]]; then
  echo "expected rc=1 when campaign-check fails without summary (invalid campaign artifact)"
  cat /tmp/integration_profile_compare_campaign_signoff_check_fail_invalid_campaign_summary.log
  exit 1
fi
if ! jq -e '.status == "fail" and .final_rc == 1 and .failure_stage == "campaign_check" and .decision.decision == "NO-GO" and .decision.context == "synthetic_campaign_check_failure" and .decision.from_campaign_check_summary == false and .decision.reason == "campaign summary JSON invalid schema" and .stages.campaign.status == "pass" and .stages.campaign_check.status == "fail"' "$CHECK_FAIL_INVALID_SUMMARY" >/dev/null 2>&1; then
  echo "invalid-campaign-artifact check-fail summary JSON missing deterministic NO-GO context"
  cat "$CHECK_FAIL_INVALID_SUMMARY"
  exit 1
fi

FAKE_FORWARD="$TMP_DIR/fake_profile_compare_campaign_signoff_forward.sh"
cat >"$FAKE_FORWARD" <<'EOF_FORWARD'
#!/usr/bin/env bash
set -euo pipefail
printf 'profile-compare-campaign-signoff %s\n' "$*" >>"${FORWARD_CAPTURE_FILE:?}"
EOF_FORWARD
chmod +x "$FAKE_FORWARD"

: >"$FORWARD_CAPTURE"

echo "[profile-compare-campaign-signoff] easy_node forwarding"
FORWARD_CAPTURE_FILE="$FORWARD_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_FORWARD" \
./scripts/easy_node.sh profile-compare-campaign-signoff \
  --reports-dir /tmp/reports \
  --refresh-campaign 0 \
  --require-min-runs-total 7 \
  --summary-json /tmp/signoff.json \
  --print-summary-json 1

forward_line="$(rg '^profile-compare-campaign-signoff ' "$FORWARD_CAPTURE" | tail -n 1 || true)"
if [[ -z "$forward_line" ]]; then
  echo "missing easy_node forwarding capture"
  cat "$FORWARD_CAPTURE"
  exit 1
fi
for expected in '--reports-dir /tmp/reports' '--refresh-campaign 0' '--require-min-runs-total 7' '--summary-json /tmp/signoff.json' '--print-summary-json 1'; do
  if ! grep -F -- "$expected" <<<"$forward_line" >/dev/null; then
    echo "easy_node forwarding missing $expected"
    cat "$FORWARD_CAPTURE"
    exit 1
  fi
done

echo "profile compare campaign signoff integration check ok"
