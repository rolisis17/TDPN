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

TEST_LOG_DIR="$TMP_DIR/easy-node-logs"
TEST_STATE_DIR="$TMP_DIR/manual-validation-state"
mkdir -p "$TEST_LOG_DIR" "$TEST_STATE_DIR"
export EASY_NODE_LOG_DIR="$TEST_LOG_DIR"
export EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$TEST_STATE_DIR"

SIGNOFF_CAPTURE="$TMP_DIR/signoff_capture.log"
FORWARD_CAPTURE="$TMP_DIR/forward_capture.log"

FAKE_CAMPAIGN="$TMP_DIR/fake_profile_compare_campaign.sh"
cat >"$FAKE_CAMPAIGN" <<'EOF_FAKE_CAMPAIGN'
#!/usr/bin/env bash
set -euo pipefail
printf 'campaign %s\n' "$*" >>"${SIGNOFF_CAPTURE_FILE:?}"
if [[ "${FAKE_CAMPAIGN_FAIL_UNLESS_DOCKER:-0}" == "1" && " $* " != *" --execution-mode docker "* ]]; then
  echo "${FAKE_CAMPAIGN_FAIL_MESSAGE:---start-local-stack=1 requires root (run with sudo)}" >&2
  exit "${FAKE_CAMPAIGN_FAIL_UNLESS_DOCKER_RC:-31}"
fi
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
  --campaign-subject "inv-signoff-test" \
  --campaign-start-local-stack 0 \
  --summary-json "$SUCCESS_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_campaign_signoff_success.log 2>&1

if ! rg -q '\[profile-compare-campaign-signoff\] status=ok final_rc=0 decision=GO' /tmp/integration_profile_compare_campaign_signoff_success.log; then
  echo "expected success status line not found"
  cat /tmp/integration_profile_compare_campaign_signoff_success.log
  exit 1
fi
if ! jq -e '.status == "ok" and .final_rc == 0 and .decision.decision == "GO" and .stages.campaign.status == "pass" and .stages.campaign_check.status == "pass" and .stages.campaign.attempted == true and .stages.campaign_check.attempted == true and .inputs.campaign_refresh_overrides.execution_mode == "docker" and .inputs.campaign_refresh_overrides.directory_urls == "http://127.0.0.1:18081,http://127.0.0.1:28081" and .inputs.campaign_refresh_overrides.bootstrap_directory == "http://127.0.0.1:18081" and .inputs.campaign_refresh_overrides.discovery_wait_sec == 7 and .inputs.campaign_refresh_overrides.issuer_url == "http://127.0.0.1:18082" and .inputs.campaign_refresh_overrides.entry_url == "http://127.0.0.1:18083" and .inputs.campaign_refresh_overrides.exit_url == "http://127.0.0.1:18084" and .inputs.campaign_refresh_overrides.subject_configured == true and .inputs.campaign_refresh_overrides.anon_cred_configured == false and .inputs.campaign_refresh_overrides.start_local_stack == "0" and .inputs.campaign_refresh_overrides_effective.subject_configured == true and .inputs.campaign_refresh_overrides_effective.anon_cred_configured == false' "$SUCCESS_SUMMARY" >/dev/null 2>&1; then
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
  '--subject inv-signoff-test' \
  '--start-local-stack 0'; do
  if ! rg -q -- "$expected" "$SIGNOFF_CAPTURE"; then
    echo "expected campaign forwarding flag missing: $expected"
    cat "$SIGNOFF_CAPTURE"
    exit 1
  fi
done

echo "[profile-compare-campaign-signoff] campaign-subject/campaign-anon-cred mutual exclusion"
set +e
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_mutual_exclusion" \
  --refresh-campaign 1 \
  --campaign-subject inv-a \
  --campaign-anon-cred cred-b \
  --summary-json "$TMP_DIR/profile_compare_campaign_signoff_mutual_exclusion.json" >/tmp/integration_profile_compare_campaign_signoff_mutual_exclusion.log 2>&1
rc_mutual_exclusion=$?
set -e
if [[ "$rc_mutual_exclusion" -ne 2 ]]; then
  echo "expected rc=2 when both --campaign-subject and --campaign-anon-cred are set"
  cat /tmp/integration_profile_compare_campaign_signoff_mutual_exclusion.log
  exit 1
fi
if ! rg -q 'use either --campaign-subject or --campaign-anon-cred, not both' /tmp/integration_profile_compare_campaign_signoff_mutual_exclusion.log; then
  echo "expected mutual exclusion error message missing"
  cat /tmp/integration_profile_compare_campaign_signoff_mutual_exclusion.log
  exit 1
fi

echo "[profile-compare-campaign-signoff] reuse existing campaign summary without refresh"
: >"$SIGNOFF_CAPTURE"
REUSE_REPORTS_DIR="$TMP_DIR/reports_reuse"
REUSE_TREND_JSON="$REUSE_REPORTS_DIR/profile_compare_trend_summary.json"
REUSE_CAMPAIGN_JSON="$REUSE_REPORTS_DIR/profile_compare_campaign_summary.json"
REUSE_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_reuse_summary.json"
mkdir -p "$REUSE_REPORTS_DIR"
cat >"$REUSE_TREND_JSON" <<EOF_REUSE_TREND
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "notes": "trend pass",
  "summary": {
    "reports_total": 3,
    "pass_reports": 3,
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
EOF_REUSE_TREND
cat >"$REUSE_CAMPAIGN_JSON" <<EOF_REUSE_CAMPAIGN
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "notes": "campaign pass",
  "summary": {
    "runs_total": 3,
    "runs_pass": 3,
    "runs_warn": 0,
    "runs_fail": 0,
    "runs_with_summary": 3
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
    "summary_json": "$REUSE_TREND_JSON"
  },
  "runs": []
}
EOF_REUSE_CAMPAIGN

SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_RC=99 \
FAKE_CHECK_RC=0 \
FAKE_CHECK_DECISION=GO \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$REUSE_REPORTS_DIR" \
  --refresh-campaign 0 \
  --summary-json "$REUSE_SUMMARY" >/tmp/integration_profile_compare_campaign_signoff_reuse.log 2>&1

if ! rg -q '\[profile-compare-campaign-signoff\] status=ok final_rc=0 decision=GO' /tmp/integration_profile_compare_campaign_signoff_reuse.log; then
  echo "expected reuse status line not found"
  cat /tmp/integration_profile_compare_campaign_signoff_reuse.log
  exit 1
fi
if [[ "$(wc -l < "$SIGNOFF_CAPTURE")" -ne 1 ]]; then
  echo "reuse path should only run the campaign-check stage"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! jq -e '.status == "ok" and .final_rc == 0 and .inputs.refresh_campaign == false and .inputs.refresh_campaign_effective == false and .inputs.campaign_summary_reused == true and .stages.campaign.status == "skip" and .stages.campaign.attempted == false and .stages.campaign_check.status == "pass" and .stages.campaign_check.attempted == true' "$REUSE_SUMMARY" >/dev/null 2>&1; then
  echo "reuse summary JSON missing expected fields"
  cat "$REUSE_SUMMARY"
  exit 1
fi

echo "[profile-compare-campaign-signoff] refresh-campaign 1 runs campaign even when summary already exists"
: >"$SIGNOFF_CAPTURE"
REUSE_FORCE_REFRESH_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_reuse_force_refresh_summary.json"
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=0 \
FAKE_CHECK_DECISION=GO \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$REUSE_REPORTS_DIR" \
  --refresh-campaign 1 \
  --summary-json "$REUSE_FORCE_REFRESH_SUMMARY" >/tmp/integration_profile_compare_campaign_signoff_reuse_force_refresh.log 2>&1

if ! rg -q '\[profile-compare-campaign-signoff\] status=ok final_rc=0 decision=GO' /tmp/integration_profile_compare_campaign_signoff_reuse_force_refresh.log; then
  echo "expected forced-refresh status line not found"
  cat /tmp/integration_profile_compare_campaign_signoff_reuse_force_refresh.log
  exit 1
fi
if [[ "$(wc -l < "$SIGNOFF_CAPTURE")" -ne 2 ]]; then
  echo "forced-refresh path should run campaign and campaign-check stages"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! jq -e '.status == "ok" and .final_rc == 0 and .inputs.refresh_campaign == true and .inputs.refresh_campaign_effective == true and .inputs.campaign_summary_reused == false and .stages.campaign.status == "pass" and .stages.campaign.attempted == true and .stages.campaign_check.status == "pass" and .stages.campaign_check.attempted == true' "$REUSE_FORCE_REFRESH_SUMMARY" >/dev/null 2>&1; then
  echo "forced-refresh summary JSON missing expected fields"
  cat "$REUSE_FORCE_REFRESH_SUMMARY"
  exit 1
fi

echo "[profile-compare-campaign-signoff] refresh uses docker inputs when remote endpoints are provided"
: >"$SIGNOFF_CAPTURE"
REMOTE_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_remote_summary.json"
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=0 \
FAKE_CHECK_DECISION=GO \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_remote" \
  --refresh-campaign 1 \
  --campaign-directory-urls "http://127.0.0.1:18081,http://127.0.0.1:28081" \
  --campaign-bootstrap-directory "http://127.0.0.1:18081" \
  --campaign-discovery-wait-sec 7 \
  --campaign-issuer-url "http://127.0.0.1:18082" \
  --campaign-entry-url "http://127.0.0.1:18083" \
  --campaign-exit-url "http://127.0.0.1:18084" \
  --summary-json "$REMOTE_SUMMARY" >/tmp/integration_profile_compare_campaign_signoff_remote.log 2>&1

if ! rg -q '\[profile-compare-campaign-signoff\] status=ok final_rc=0 decision=GO' /tmp/integration_profile_compare_campaign_signoff_remote.log; then
  echo "expected remote refresh status line not found"
  cat /tmp/integration_profile_compare_campaign_signoff_remote.log
  exit 1
fi
remote_forward_line="$(sed -n '1p' "$SIGNOFF_CAPTURE" || true)"
for expected in \
  '--execution-mode docker' \
  '--start-local-stack 0' \
  '--directory-urls http://127.0.0.1:18081,http://127.0.0.1:28081' \
  '--bootstrap-directory http://127.0.0.1:18081' \
  '--discovery-wait-sec 7' \
  '--issuer-url http://127.0.0.1:18082' \
  '--entry-url http://127.0.0.1:18083' \
  '--exit-url http://127.0.0.1:18084'; do
  if ! grep -F -- "$expected" <<<"$remote_forward_line" >/dev/null; then
    echo "remote refresh path missing $expected"
    cat "$SIGNOFF_CAPTURE"
    exit 1
  fi
done
if ! jq -e '.status == "ok" and .final_rc == 0 and .inputs.refresh_campaign == true and .inputs.refresh_campaign_effective == true and .inputs.campaign_refresh_overrides_effective.execution_mode == "docker" and .inputs.campaign_refresh_overrides_effective.start_local_stack == "0"' "$REMOTE_SUMMARY" >/dev/null 2>&1; then
  echo "remote refresh summary JSON missing expected fields"
  cat "$REMOTE_SUMMARY"
  exit 1
fi

echo "[profile-compare-campaign-signoff] automatic docker fallback when local refresh is root-blocked"
: >"$SIGNOFF_CAPTURE"
AUTO_FALLBACK_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_auto_fallback.json"
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_FAIL_UNLESS_DOCKER=1 \
FAKE_CAMPAIGN_FAIL_MESSAGE='--start-local-stack=1 requires root (run with sudo)' \
FAKE_CHECK_RC=0 \
FAKE_CHECK_DECISION=GO \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_auto_fallback" \
  --refresh-campaign 1 \
  --summary-json "$AUTO_FALLBACK_SUMMARY" >/tmp/integration_profile_compare_campaign_signoff_auto_fallback.log 2>&1

if ! rg -q '\[profile-compare-campaign-signoff\] campaign auto-fallback: mode=local->docker reason=local stack requires root' /tmp/integration_profile_compare_campaign_signoff_auto_fallback.log; then
  echo "expected auto-fallback trace line not found"
  cat /tmp/integration_profile_compare_campaign_signoff_auto_fallback.log
  exit 1
fi
if ! jq -e '.status == "ok" and .final_rc == 0 and .inputs.refresh_campaign == true and .inputs.campaign_refresh_overrides.execution_mode == null and .inputs.campaign_refresh_overrides_effective.execution_mode == "docker" and .inputs.campaign_refresh_overrides_effective.start_local_stack == "0" and .inputs.campaign_refresh_fallback.eligible == true and .inputs.campaign_refresh_fallback.attempted == true and .inputs.campaign_refresh_fallback.triggered == true and .inputs.campaign_refresh_fallback.reason == "local stack requires root" and .inputs.campaign_refresh_fallback.initial_mode == "local" and .inputs.campaign_refresh_fallback.effective_mode == "docker" and .stages.campaign.status == "pass" and .stages.campaign.initial_command != null and .stages.campaign.fallback_command != null and .stages.campaign.initial_log != null and .stages.campaign.fallback_log != null and .stages.campaign_check.status == "pass"' "$AUTO_FALLBACK_SUMMARY" >/dev/null 2>&1; then
  echo "auto-fallback summary JSON missing expected fields"
  cat "$AUTO_FALLBACK_SUMMARY"
  exit 1
fi
first_campaign_line="$(sed -n '1p' "$SIGNOFF_CAPTURE" || true)"
second_campaign_line="$(sed -n '2p' "$SIGNOFF_CAPTURE" || true)"
third_line="$(sed -n '3p' "$SIGNOFF_CAPTURE" || true)"
if [[ "$first_campaign_line" != campaign* || "$second_campaign_line" != campaign* || "$third_line" != check* ]]; then
  echo "auto-fallback path should run campaign, campaign fallback, then check"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if grep -F -- '--execution-mode docker' <<<"$first_campaign_line" >/dev/null; then
  echo "first auto-fallback attempt should preserve implicit local execution mode"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
for expected in '--execution-mode docker' '--start-local-stack 0'; do
  if ! grep -F -- "$expected" <<<"$second_campaign_line" >/dev/null; then
    echo "fallback campaign attempt missing $expected"
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
  --campaign-subject inv-forward-test \
  --require-min-runs-total 7 \
  --summary-json /tmp/signoff.json \
  --print-summary-json 1

forward_line="$(rg '^profile-compare-campaign-signoff ' "$FORWARD_CAPTURE" | tail -n 1 || true)"
if [[ -z "$forward_line" ]]; then
  echo "missing easy_node forwarding capture"
  cat "$FORWARD_CAPTURE"
  exit 1
fi
for expected in '--reports-dir /tmp/reports' '--refresh-campaign 0' '--campaign-subject inv-forward-test' '--require-min-runs-total 7' '--summary-json /tmp/signoff.json' '--print-summary-json 1'; do
  if ! grep -F -- "$expected" <<<"$forward_line" >/dev/null; then
    echo "easy_node forwarding missing $expected"
    cat "$FORWARD_CAPTURE"
    exit 1
  fi
done

echo "profile compare campaign signoff integration check ok"
