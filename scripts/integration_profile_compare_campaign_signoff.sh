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
if [[ "${FAKE_CAMPAIGN_SLEEP_SEC:-0}" =~ ^[0-9]+$ ]] && [[ "${FAKE_CAMPAIGN_SLEEP_SEC:-0}" -gt 0 ]]; then
  sleep "${FAKE_CAMPAIGN_SLEEP_SEC}"
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
if ! rg -q 'campaign refresh started attempt=initial' /tmp/integration_profile_compare_campaign_signoff_success.log; then
  echo "expected campaign refresh start line not found"
  cat /tmp/integration_profile_compare_campaign_signoff_success.log
  exit 1
fi
if ! rg -q 'campaign refresh completed attempt=initial' /tmp/integration_profile_compare_campaign_signoff_success.log; then
  echo "expected campaign refresh completion line not found"
  cat /tmp/integration_profile_compare_campaign_signoff_success.log
  exit 1
fi
if ! jq -e '.status == "ok" and .final_rc == 0 and .decision.decision == "GO" and .stages.campaign.status == "pass" and .stages.campaign_check.status == "pass" and .stages.campaign.attempted == true and .stages.campaign_check.attempted == true and .stages.campaign.timed_out == false and .stages.campaign.timeout_sec == 0 and .inputs.campaign_refresh_runtime.timeout_sec == 0 and .inputs.campaign_refresh_runtime.heartbeat_interval_sec >= 1 and .inputs.campaign_refresh_overrides.execution_mode == "docker" and .inputs.campaign_refresh_overrides.directory_urls == "http://127.0.0.1:18081,http://127.0.0.1:28081" and .inputs.campaign_refresh_overrides.bootstrap_directory == "http://127.0.0.1:18081" and .inputs.campaign_refresh_overrides.discovery_wait_sec == 7 and .inputs.campaign_refresh_overrides.issuer_url == "http://127.0.0.1:18082" and .inputs.campaign_refresh_overrides.entry_url == "http://127.0.0.1:18083" and .inputs.campaign_refresh_overrides.exit_url == "http://127.0.0.1:18084" and .inputs.campaign_refresh_overrides.subject_configured == true and .inputs.campaign_refresh_overrides.anon_cred_configured == false and .inputs.campaign_refresh_overrides.start_local_stack == "0" and .inputs.campaign_refresh_overrides_effective.subject_configured == true and .inputs.campaign_refresh_overrides_effective.anon_cred_configured == false' "$SUCCESS_SUMMARY" >/dev/null 2>&1; then
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

echo "[profile-compare-campaign-signoff] alias forwarding works"
: >"$SIGNOFF_CAPTURE"
ALIAS_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_alias_summary.json"
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=0 \
FAKE_CHECK_DECISION=GO \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_alias" \
  --refresh-campaign 1 \
  --campaign-execution-mode docker \
  --subject "inv-alias-test" \
  --summary-json "$ALIAS_SUMMARY" >/tmp/integration_profile_compare_campaign_signoff_alias.log 2>&1

if ! rg -q '\[profile-compare-campaign-signoff\] status=ok final_rc=0 decision=GO' /tmp/integration_profile_compare_campaign_signoff_alias.log; then
  echo "expected alias forwarding status line not found"
  cat /tmp/integration_profile_compare_campaign_signoff_alias.log
  exit 1
fi
if ! rg -q -- '--subject inv-alias-test' "$SIGNOFF_CAPTURE"; then
  echo "expected alias subject forwarding flag missing"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! jq -e '.status == "ok" and .final_rc == 0 and .inputs.campaign_refresh_overrides.subject_source == "explicit" and .inputs.campaign_refresh_overrides.subject_configured == true and .inputs.campaign_refresh_overrides.anon_cred_configured == false and .inputs.campaign_refresh_overrides_effective.subject_configured == true and .inputs.campaign_refresh_overrides_effective.anon_cred_configured == false' "$ALIAS_SUMMARY" >/dev/null 2>&1; then
  echo "alias forwarding summary JSON missing expected fields"
  cat "$ALIAS_SUMMARY"
  exit 1
fi

echo "[profile-compare-campaign-signoff] --subject= alias forwarding works"
: >"$SIGNOFF_CAPTURE"
ALIAS_EQUALS_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_alias_equals_summary.json"
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=0 \
FAKE_CHECK_DECISION=GO \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_alias_equals" \
  --refresh-campaign 1 \
  --campaign-execution-mode docker \
  --subject="inv-alias-equals-test" \
  --summary-json "$ALIAS_EQUALS_SUMMARY" >/tmp/integration_profile_compare_campaign_signoff_alias_equals.log 2>&1

if ! rg -q '\[profile-compare-campaign-signoff\] status=ok final_rc=0 decision=GO' /tmp/integration_profile_compare_campaign_signoff_alias_equals.log; then
  echo "expected --subject= alias forwarding status line not found"
  cat /tmp/integration_profile_compare_campaign_signoff_alias_equals.log
  exit 1
fi
if ! rg -q -- '--subject inv-alias-equals-test' "$SIGNOFF_CAPTURE"; then
  echo "expected --subject= alias subject forwarding flag missing"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! jq -e '.status == "ok" and .final_rc == 0 and .inputs.campaign_refresh_overrides.subject_source == "explicit" and .inputs.campaign_refresh_overrides.subject_configured == true and .inputs.campaign_refresh_overrides.anon_cred_configured == false and .inputs.campaign_refresh_overrides_effective.subject_configured == true and .inputs.campaign_refresh_overrides_effective.anon_cred_configured == false' "$ALIAS_EQUALS_SUMMARY" >/dev/null 2>&1; then
  echo "--subject= alias forwarding summary JSON missing expected fields"
  cat "$ALIAS_EQUALS_SUMMARY"
  exit 1
fi

echo "[profile-compare-campaign-signoff] --key alias forwarding works"
: >"$SIGNOFF_CAPTURE"
KEY_ALIAS_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_key_alias_summary.json"
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=0 \
FAKE_CHECK_DECISION=GO \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_key_alias" \
  --refresh-campaign 1 \
  --campaign-execution-mode docker \
  --key "inv-key-alias-test" \
  --summary-json "$KEY_ALIAS_SUMMARY" >/tmp/integration_profile_compare_campaign_signoff_key_alias.log 2>&1

if ! rg -q '\[profile-compare-campaign-signoff\] status=ok final_rc=0 decision=GO' /tmp/integration_profile_compare_campaign_signoff_key_alias.log; then
  echo "expected --key alias forwarding status line not found"
  cat /tmp/integration_profile_compare_campaign_signoff_key_alias.log
  exit 1
fi
if ! rg -q -- '--subject inv-key-alias-test' "$SIGNOFF_CAPTURE"; then
  echo "expected --key alias to normalize to --subject forwarding flag"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if rg -q -- '--key ' "$SIGNOFF_CAPTURE" || rg -q -- '--invite-key ' "$SIGNOFF_CAPTURE"; then
  echo "unexpected raw key alias forwarding flag found in campaign command"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! jq -e '.status == "ok" and .final_rc == 0 and .inputs.campaign_refresh_overrides.subject_source == "explicit" and .inputs.campaign_refresh_overrides.subject_configured == true and .inputs.campaign_refresh_overrides_effective.subject_configured == true' "$KEY_ALIAS_SUMMARY" >/dev/null 2>&1; then
  echo "--key alias forwarding summary JSON missing expected fields"
  cat "$KEY_ALIAS_SUMMARY"
  exit 1
fi

echo "[profile-compare-campaign-signoff] --invite-key alias forwarding works"
: >"$SIGNOFF_CAPTURE"
INVITE_KEY_ALIAS_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_invite_key_alias_summary.json"
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=0 \
FAKE_CHECK_DECISION=GO \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_invite_key_alias" \
  --refresh-campaign 1 \
  --campaign-execution-mode docker \
  --invite-key "inv-invite-key-alias-test" \
  --summary-json "$INVITE_KEY_ALIAS_SUMMARY" >/tmp/integration_profile_compare_campaign_signoff_invite_key_alias.log 2>&1

if ! rg -q '\[profile-compare-campaign-signoff\] status=ok final_rc=0 decision=GO' /tmp/integration_profile_compare_campaign_signoff_invite_key_alias.log; then
  echo "expected --invite-key alias forwarding status line not found"
  cat /tmp/integration_profile_compare_campaign_signoff_invite_key_alias.log
  exit 1
fi
if ! rg -q -- '--subject inv-invite-key-alias-test' "$SIGNOFF_CAPTURE"; then
  echo "expected --invite-key alias to normalize to --subject forwarding flag"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if rg -q -- '--key ' "$SIGNOFF_CAPTURE" || rg -q -- '--invite-key ' "$SIGNOFF_CAPTURE"; then
  echo "unexpected raw invite-key alias forwarding flag found in campaign command"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! jq -e '.status == "ok" and .final_rc == 0 and .inputs.campaign_refresh_overrides.subject_source == "explicit" and .inputs.campaign_refresh_overrides.subject_configured == true and .inputs.campaign_refresh_overrides_effective.subject_configured == true' "$INVITE_KEY_ALIAS_SUMMARY" >/dev/null 2>&1; then
  echo "--invite-key alias forwarding summary JSON missing expected fields"
  cat "$INVITE_KEY_ALIAS_SUMMARY"
  exit 1
fi

echo "[profile-compare-campaign-signoff] anon-cred alias forwarding works"
: >"$SIGNOFF_CAPTURE"
ANON_CRED_ALIAS_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_anon_cred_alias_summary.json"
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=0 \
FAKE_CHECK_DECISION=GO \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_anon_cred_alias" \
  --refresh-campaign 1 \
  --campaign-execution-mode docker \
  --anon-cred "anon-cred-alias-test" \
  --summary-json "$ANON_CRED_ALIAS_SUMMARY" >/tmp/integration_profile_compare_campaign_signoff_anon_cred_alias.log 2>&1

if ! rg -q '\[profile-compare-campaign-signoff\] status=ok final_rc=0 decision=GO' /tmp/integration_profile_compare_campaign_signoff_anon_cred_alias.log; then
  echo "expected anon-cred alias forwarding status line not found"
  cat /tmp/integration_profile_compare_campaign_signoff_anon_cred_alias.log
  exit 1
fi
if ! rg -q -- '--anon-cred anon-cred-alias-test' "$SIGNOFF_CAPTURE"; then
  echo "expected alias anon-cred forwarding flag missing"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if rg -q -- '--subject ' "$SIGNOFF_CAPTURE"; then
  echo "unexpected subject forwarding when anon-cred alias is supplied"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! jq -e '.status == "ok" and .final_rc == 0 and .inputs.campaign_refresh_overrides.subject_source == null and .inputs.campaign_refresh_overrides.subject_configured == false and .inputs.campaign_refresh_overrides.anon_cred_configured == true and .inputs.campaign_refresh_overrides_effective.subject_configured == false and .inputs.campaign_refresh_overrides_effective.anon_cred_configured == true' "$ANON_CRED_ALIAS_SUMMARY" >/dev/null 2>&1; then
  echo "anon-cred alias summary JSON missing expected fields"
  cat "$ANON_CRED_ALIAS_SUMMARY"
  exit 1
fi

echo "[profile-compare-campaign-signoff] --anon-cred= alias forwarding works"
: >"$SIGNOFF_CAPTURE"
ANON_CRED_ALIAS_EQUALS_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_anon_cred_alias_equals_summary.json"
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=0 \
FAKE_CHECK_DECISION=GO \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_anon_cred_alias_equals" \
  --refresh-campaign 1 \
  --campaign-execution-mode docker \
  --anon-cred="anon-cred-alias-equals-test" \
  --summary-json "$ANON_CRED_ALIAS_EQUALS_SUMMARY" >/tmp/integration_profile_compare_campaign_signoff_anon_cred_alias_equals.log 2>&1

if ! rg -q '\[profile-compare-campaign-signoff\] status=ok final_rc=0 decision=GO' /tmp/integration_profile_compare_campaign_signoff_anon_cred_alias_equals.log; then
  echo "expected --anon-cred= alias forwarding status line not found"
  cat /tmp/integration_profile_compare_campaign_signoff_anon_cred_alias_equals.log
  exit 1
fi
if ! rg -q -- '--anon-cred anon-cred-alias-equals-test' "$SIGNOFF_CAPTURE"; then
  echo "expected --anon-cred= alias forwarding flag missing"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if rg -q -- '--subject ' "$SIGNOFF_CAPTURE"; then
  echo "unexpected subject forwarding when --anon-cred= alias is supplied"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! jq -e '.status == "ok" and .final_rc == 0 and .inputs.campaign_refresh_overrides.subject_source == null and .inputs.campaign_refresh_overrides.subject_configured == false and .inputs.campaign_refresh_overrides.anon_cred_configured == true and .inputs.campaign_refresh_overrides_effective.subject_configured == false and .inputs.campaign_refresh_overrides_effective.anon_cred_configured == true' "$ANON_CRED_ALIAS_EQUALS_SUMMARY" >/dev/null 2>&1; then
  echo "--anon-cred= alias summary JSON missing expected fields"
  cat "$ANON_CRED_ALIAS_EQUALS_SUMMARY"
  exit 1
fi

echo "[profile-compare-campaign-signoff] env CAMPAIGN_SUBJECT fallback takes precedence"
: >"$SIGNOFF_CAPTURE"
ENV_CAMPAIGN_SUBJECT_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_env_campaign_subject_summary.json"
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=0 \
FAKE_CHECK_DECISION=GO \
CAMPAIGN_SUBJECT="inv-campaign-env" \
INVITE_KEY="inv-invite-env" \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_env_campaign_subject" \
  --refresh-campaign 1 \
  --campaign-execution-mode docker \
  --summary-json "$ENV_CAMPAIGN_SUBJECT_SUMMARY" >/tmp/integration_profile_compare_campaign_signoff_env_campaign_subject.log 2>&1

if ! rg -q '\[profile-compare-campaign-signoff\] status=ok final_rc=0 decision=GO' /tmp/integration_profile_compare_campaign_signoff_env_campaign_subject.log; then
  echo "expected env campaign-subject fallback status line not found"
  cat /tmp/integration_profile_compare_campaign_signoff_env_campaign_subject.log
  exit 1
fi
if ! rg -q -- '--subject inv-campaign-env' "$SIGNOFF_CAPTURE"; then
  echo "expected CAMPAIGN_SUBJECT fallback forwarding flag missing"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if rg -q -- '--subject inv-invite-env' "$SIGNOFF_CAPTURE"; then
  echo "expected INVITE_KEY to be ignored when CAMPAIGN_SUBJECT is set"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! jq -e '.inputs.campaign_refresh_overrides.subject_source == "env:CAMPAIGN_SUBJECT" and .inputs.campaign_refresh_overrides.subject_configured == true and .inputs.campaign_refresh_overrides_effective.subject_configured == true' "$ENV_CAMPAIGN_SUBJECT_SUMMARY" >/dev/null 2>&1; then
  echo "expected CAMPAIGN_SUBJECT subject_source summary fields missing"
  cat "$ENV_CAMPAIGN_SUBJECT_SUMMARY"
  exit 1
fi

echo "[profile-compare-campaign-signoff] env INVITE_KEY fallback applies when CAMPAIGN_SUBJECT absent"
: >"$SIGNOFF_CAPTURE"
ENV_INVITE_KEY_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_env_invite_key_summary.json"
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=0 \
FAKE_CHECK_DECISION=GO \
INVITE_KEY="inv-invite-env-only" \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_env_invite_key" \
  --refresh-campaign 1 \
  --campaign-execution-mode docker \
  --summary-json "$ENV_INVITE_KEY_SUMMARY" >/tmp/integration_profile_compare_campaign_signoff_env_invite_key.log 2>&1

if ! rg -q '\[profile-compare-campaign-signoff\] status=ok final_rc=0 decision=GO' /tmp/integration_profile_compare_campaign_signoff_env_invite_key.log; then
  echo "expected INVITE_KEY fallback status line not found"
  cat /tmp/integration_profile_compare_campaign_signoff_env_invite_key.log
  exit 1
fi
if ! rg -q -- '--subject inv-invite-env-only' "$SIGNOFF_CAPTURE"; then
  echo "expected INVITE_KEY fallback forwarding flag missing"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! jq -e '.inputs.campaign_refresh_overrides.subject_source == "env:INVITE_KEY" and .inputs.campaign_refresh_overrides.subject_configured == true and .inputs.campaign_refresh_overrides_effective.subject_configured == true' "$ENV_INVITE_KEY_SUMMARY" >/dev/null 2>&1; then
  echo "expected INVITE_KEY subject_source summary fields missing"
  cat "$ENV_INVITE_KEY_SUMMARY"
  exit 1
fi

echo "[profile-compare-campaign-signoff] explicit subject overrides env fallback"
: >"$SIGNOFF_CAPTURE"
EXPLICIT_SUBJECT_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_explicit_subject_summary.json"
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=0 \
FAKE_CHECK_DECISION=GO \
CAMPAIGN_SUBJECT="inv-campaign-env-ignored" \
INVITE_KEY="inv-invite-env-ignored" \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_explicit_subject_overrides_env" \
  --refresh-campaign 1 \
  --campaign-execution-mode docker \
  --subject "inv-cli-explicit" \
  --summary-json "$EXPLICIT_SUBJECT_SUMMARY" >/tmp/integration_profile_compare_campaign_signoff_explicit_subject.log 2>&1

if ! rg -q '\[profile-compare-campaign-signoff\] status=ok final_rc=0 decision=GO' /tmp/integration_profile_compare_campaign_signoff_explicit_subject.log; then
  echo "expected explicit subject override status line not found"
  cat /tmp/integration_profile_compare_campaign_signoff_explicit_subject.log
  exit 1
fi
if ! rg -q -- '--subject inv-cli-explicit' "$SIGNOFF_CAPTURE"; then
  echo "expected explicit subject forwarding flag missing"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if rg -q -- 'inv-campaign-env-ignored\|inv-invite-env-ignored' "$SIGNOFF_CAPTURE"; then
  echo "unexpected env fallback value used when explicit subject provided"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! jq -e '.inputs.campaign_refresh_overrides.subject_source == "explicit" and .inputs.campaign_refresh_overrides.subject_configured == true and .inputs.campaign_refresh_overrides_effective.subject_configured == true' "$EXPLICIT_SUBJECT_SUMMARY" >/dev/null 2>&1; then
  echo "expected explicit subject_source summary fields missing"
  cat "$EXPLICIT_SUBJECT_SUMMARY"
  exit 1
fi

echo "[profile-compare-campaign-signoff] placeholder subject fails fast before campaign/check stages"
: >"$SIGNOFF_CAPTURE"
PLACEHOLDER_SUBJECT_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_placeholder_subject_summary.json"
set +e
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=0 \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_placeholder_subject" \
  --refresh-campaign 1 \
  --subject INVITE_KEY \
  --summary-json "$PLACEHOLDER_SUBJECT_SUMMARY" >/tmp/integration_profile_compare_campaign_signoff_placeholder_subject.log 2>&1
rc_placeholder_subject=$?
set -e
if [[ "$rc_placeholder_subject" -ne 2 ]]; then
  echo "expected rc=2 for placeholder subject precondition"
  cat /tmp/integration_profile_compare_campaign_signoff_placeholder_subject.log
  exit 1
fi
for expected in \
  'failure_kind=missing_invite_subject_precondition reason=placeholder_subject' \
  'campaign subject appears to be placeholder text (INVITE_KEY)'; do
  if ! grep -F -- "$expected" /tmp/integration_profile_compare_campaign_signoff_placeholder_subject.log >/dev/null; then
    echo "expected placeholder-subject precondition output missing: $expected"
    cat /tmp/integration_profile_compare_campaign_signoff_placeholder_subject.log
    exit 1
  fi
done
if [[ -s "$SIGNOFF_CAPTURE" ]]; then
  echo "placeholder-subject path should not run campaign/check scripts"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi

echo "[profile-compare-campaign-signoff] conflicting alias and campaign-prefixed values fail clearly"
set +e
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_conflict_subject" \
  --refresh-campaign 1 \
  --subject inv-alias-a \
  --campaign-subject inv-alias-b \
  --summary-json "$TMP_DIR/profile_compare_campaign_signoff_conflict_subject.json" >/tmp/integration_profile_compare_campaign_signoff_conflict_subject.log 2>&1
rc_conflict_subject=$?
set -e
if [[ "$rc_conflict_subject" -ne 2 ]]; then
  echo "expected rc=2 when --subject conflicts with --campaign-subject"
  cat /tmp/integration_profile_compare_campaign_signoff_conflict_subject.log
  exit 1
fi
if ! rg -q 'conflicting subject values: --subject and --campaign-subject must match when both are provided' /tmp/integration_profile_compare_campaign_signoff_conflict_subject.log; then
  echo "expected subject conflict error message missing"
  cat /tmp/integration_profile_compare_campaign_signoff_conflict_subject.log
  exit 1
fi

echo "[profile-compare-campaign-signoff] conflicting --subject= and --campaign-subject fail clearly"
set +e
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_conflict_subject_equals" \
  --refresh-campaign 1 \
  --subject=inv-alias-equals-a \
  --campaign-subject inv-alias-equals-b \
  --summary-json "$TMP_DIR/profile_compare_campaign_signoff_conflict_subject_equals.json" >/tmp/integration_profile_compare_campaign_signoff_conflict_subject_equals.log 2>&1
rc_conflict_subject_equals=$?
set -e
if [[ "$rc_conflict_subject_equals" -ne 2 ]]; then
  echo "expected rc=2 when --subject= conflicts with --campaign-subject"
  cat /tmp/integration_profile_compare_campaign_signoff_conflict_subject_equals.log
  exit 1
fi
if ! rg -q 'conflicting subject values: --subject and --campaign-subject must match when both are provided' /tmp/integration_profile_compare_campaign_signoff_conflict_subject_equals.log; then
  echo "expected --subject= conflict error message missing"
  cat /tmp/integration_profile_compare_campaign_signoff_conflict_subject_equals.log
  exit 1
fi

echo "[profile-compare-campaign-signoff] conflicting --key and --campaign-subject fail clearly"
set +e
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_conflict_key_campaign_subject" \
  --refresh-campaign 1 \
  --key inv-key-a \
  --campaign-subject inv-key-b \
  --summary-json "$TMP_DIR/profile_compare_campaign_signoff_conflict_key_campaign_subject.json" >/tmp/integration_profile_compare_campaign_signoff_conflict_key_campaign_subject.log 2>&1
rc_conflict_key_campaign_subject=$?
set -e
if [[ "$rc_conflict_key_campaign_subject" -ne 2 ]]; then
  echo "expected rc=2 when --key conflicts with --campaign-subject"
  cat /tmp/integration_profile_compare_campaign_signoff_conflict_key_campaign_subject.log
  exit 1
fi
if ! rg -q 'conflicting subject values: --key and --campaign-subject must match when both are provided' /tmp/integration_profile_compare_campaign_signoff_conflict_key_campaign_subject.log; then
  echo "expected --key conflict error message missing"
  cat /tmp/integration_profile_compare_campaign_signoff_conflict_key_campaign_subject.log
  exit 1
fi

echo "[profile-compare-campaign-signoff] conflicting --invite-key and --subject fail clearly"
set +e
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_conflict_invite_key_subject" \
  --refresh-campaign 1 \
  --invite-key inv-invite-a \
  --subject inv-subject-b \
  --summary-json "$TMP_DIR/profile_compare_campaign_signoff_conflict_invite_key_subject.json" >/tmp/integration_profile_compare_campaign_signoff_conflict_invite_key_subject.log 2>&1
rc_conflict_invite_key_subject=$?
set -e
if [[ "$rc_conflict_invite_key_subject" -ne 2 ]]; then
  echo "expected rc=2 when --invite-key conflicts with --subject"
  cat /tmp/integration_profile_compare_campaign_signoff_conflict_invite_key_subject.log
  exit 1
fi
if ! rg -q 'conflicting subject values: --invite-key and --subject must match when both are provided' /tmp/integration_profile_compare_campaign_signoff_conflict_invite_key_subject.log; then
  echo "expected --invite-key/--subject conflict error message missing"
  cat /tmp/integration_profile_compare_campaign_signoff_conflict_invite_key_subject.log
  exit 1
fi

set +e
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_conflict_anon" \
  --refresh-campaign 1 \
  --anon-cred anon-a \
  --campaign-anon-cred anon-b \
  --summary-json "$TMP_DIR/profile_compare_campaign_signoff_conflict_anon.json" >/tmp/integration_profile_compare_campaign_signoff_conflict_anon.log 2>&1
rc_conflict_anon=$?
set -e
if [[ "$rc_conflict_anon" -ne 2 ]]; then
  echo "expected rc=2 when --anon-cred conflicts with --campaign-anon-cred"
  cat /tmp/integration_profile_compare_campaign_signoff_conflict_anon.log
  exit 1
fi
if ! rg -q 'conflicting anon credential values: --anon-cred and --campaign-anon-cred must match when both are provided' /tmp/integration_profile_compare_campaign_signoff_conflict_anon.log; then
  echo "expected anon-cred conflict error message missing"
  cat /tmp/integration_profile_compare_campaign_signoff_conflict_anon.log
  exit 1
fi

echo "[profile-compare-campaign-signoff] conflicting --anon-cred= and --campaign-anon-cred fail clearly"
set +e
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_conflict_anon_equals" \
  --refresh-campaign 1 \
  --anon-cred=anon-equals-a \
  --campaign-anon-cred anon-equals-b \
  --summary-json "$TMP_DIR/profile_compare_campaign_signoff_conflict_anon_equals.json" >/tmp/integration_profile_compare_campaign_signoff_conflict_anon_equals.log 2>&1
rc_conflict_anon_equals=$?
set -e
if [[ "$rc_conflict_anon_equals" -ne 2 ]]; then
  echo "expected rc=2 when --anon-cred= conflicts with --campaign-anon-cred"
  cat /tmp/integration_profile_compare_campaign_signoff_conflict_anon_equals.log
  exit 1
fi
if ! rg -q 'conflicting anon credential values: --anon-cred and --campaign-anon-cred must match when both are provided' /tmp/integration_profile_compare_campaign_signoff_conflict_anon_equals.log; then
  echo "expected --anon-cred= conflict error message missing"
  cat /tmp/integration_profile_compare_campaign_signoff_conflict_anon_equals.log
  exit 1
fi

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

echo "[profile-compare-campaign-signoff] legacy --subject preserves subject/anon-cred mutual exclusion"
set +e
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_mutual_exclusion_subject_alias" \
  --refresh-campaign 1 \
  --subject inv-a \
  --campaign-anon-cred cred-b \
  --summary-json "$TMP_DIR/profile_compare_campaign_signoff_mutual_exclusion_subject_alias.json" >/tmp/integration_profile_compare_campaign_signoff_mutual_exclusion_subject_alias.log 2>&1
rc_mutual_exclusion_subject_alias=$?
set -e
if [[ "$rc_mutual_exclusion_subject_alias" -ne 2 ]]; then
  echo "expected rc=2 when --subject and --campaign-anon-cred are both set"
  cat /tmp/integration_profile_compare_campaign_signoff_mutual_exclusion_subject_alias.log
  exit 1
fi
if ! rg -q 'use either --campaign-subject or --campaign-anon-cred, not both' /tmp/integration_profile_compare_campaign_signoff_mutual_exclusion_subject_alias.log; then
  echo "expected subject alias mutual exclusion error message missing"
  cat /tmp/integration_profile_compare_campaign_signoff_mutual_exclusion_subject_alias.log
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

echo "[profile-compare-campaign-signoff] remote endpoint preflight fail-closes campaign stage"
: >"$SIGNOFF_CAPTURE"
PREFLIGHT_FAIL_REPORTS_DIR="$TMP_DIR/reports_preflight_fail"
PREFLIGHT_FAIL_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_preflight_fail.json"
mkdir -p "$PREFLIGHT_FAIL_REPORTS_DIR"
cat >"$PREFLIGHT_FAIL_REPORTS_DIR/profile_compare_campaign_check_summary.json" <<'JSON'
{
  "decision": "GO",
  "observed": {
    "recommended_profile": "balanced",
    "support_rate_pct": 94,
    "trend_source": "stale_prior_run"
  }
}
JSON
PREFLIGHT_FAKE_BIN="$TMP_DIR/preflight_fake_bin"
mkdir -p "$PREFLIGHT_FAKE_BIN"
cat >"$PREFLIGHT_FAKE_BIN/curl" <<'EOF_FAKE_CURL'
#!/usr/bin/env bash
set -euo pipefail
echo "curl: (7) failed to connect to endpoint" >&2
exit 7
EOF_FAKE_CURL
chmod +x "$PREFLIGHT_FAKE_BIN/curl"
set +e
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
PATH="$PREFLIGHT_FAKE_BIN:$PATH" \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=0 \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$PREFLIGHT_FAIL_REPORTS_DIR" \
  --refresh-campaign 1 \
  --campaign-execution-mode docker \
  --campaign-endpoint-preflight-timeout-sec 1 \
  --campaign-directory-urls "http://198.51.100.42:18081,http://198.51.100.43:28081" \
  --campaign-bootstrap-directory "http://198.51.100.42:18081" \
  --campaign-issuer-url "http://198.51.100.42:18082" \
  --campaign-entry-url "http://198.51.100.42:18083" \
  --campaign-exit-url "http://198.51.100.42:18084" \
  --summary-json "$PREFLIGHT_FAIL_SUMMARY" >/tmp/integration_profile_compare_campaign_signoff_preflight_fail.log 2>&1
rc_preflight_fail=$?
set -e
if [[ "$rc_preflight_fail" -eq 0 ]]; then
  echo "expected non-zero rc when remote endpoint preflight fails"
  cat /tmp/integration_profile_compare_campaign_signoff_preflight_fail.log
  exit 1
fi
if ! rg -q 'campaign endpoint preflight failed reason=' /tmp/integration_profile_compare_campaign_signoff_preflight_fail.log; then
  echo "expected endpoint preflight failure trace line not found"
  cat /tmp/integration_profile_compare_campaign_signoff_preflight_fail.log
  exit 1
fi
if [[ "$(wc -l < "$SIGNOFF_CAPTURE")" -ne 0 ]]; then
  echo "preflight-fail path should not run campaign/check scripts"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! jq -e '.status == "fail" and .failure_stage == "campaign" and .decision.decision == "NO-GO" and .decision.context == "synthetic_campaign_failure" and .decision.from_campaign_check_summary == false and .decision.diagnostics.source_schema == "synthetic_stage_failure" and .decision.diagnostics.likely_primary_failure == "endpoint_unreachable" and .decision.diagnostics.aggregated_diagnostics.endpoint_unreachable_failures >= 1 and .decision.next_operator_action == "Verify directory/issuer/entry/exit endpoints are reachable, then rerun signoff" and .inputs.campaign_endpoint_preflight.enabled == true and .inputs.campaign_endpoint_preflight.attempted == true and .inputs.campaign_endpoint_preflight.status == "fail" and .inputs.campaign_endpoint_preflight.timeout_sec == 1 and .inputs.campaign_endpoint_preflight.remote_http_endpoints >= 1 and .inputs.campaign_endpoint_preflight.failed_endpoints_count >= 1 and .stages.campaign.preflight.status == "fail" and .stages.campaign_check.attempted == false' "$PREFLIGHT_FAIL_SUMMARY" >/dev/null 2>&1; then
  echo "preflight-fail summary JSON missing expected fields"
  cat "$PREFLIGHT_FAIL_SUMMARY"
  exit 1
fi

echo "[profile-compare-campaign-signoff] endpoint preflight can be disabled"
: >"$SIGNOFF_CAPTURE"
PREFLIGHT_DISABLED_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_preflight_disabled.json"
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=0 \
FAKE_CHECK_DECISION=GO \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$TMP_DIR/reports_preflight_disabled" \
  --refresh-campaign 1 \
  --campaign-execution-mode docker \
  --campaign-endpoint-preflight-timeout-sec 0 \
  --campaign-directory-urls "http://198.51.100.42:18081,http://198.51.100.43:28081" \
  --campaign-bootstrap-directory "http://198.51.100.42:18081" \
  --campaign-issuer-url "http://198.51.100.42:18082" \
  --campaign-entry-url "http://198.51.100.42:18083" \
  --campaign-exit-url "http://198.51.100.42:18084" \
  --summary-json "$PREFLIGHT_DISABLED_SUMMARY" >/tmp/integration_profile_compare_campaign_signoff_preflight_disabled.log 2>&1
if ! rg -q '\[profile-compare-campaign-signoff\] status=ok final_rc=0 decision=GO' /tmp/integration_profile_compare_campaign_signoff_preflight_disabled.log; then
  echo "expected preflight-disabled success status line not found"
  cat /tmp/integration_profile_compare_campaign_signoff_preflight_disabled.log
  exit 1
fi
if [[ "$(wc -l < "$SIGNOFF_CAPTURE")" -ne 2 ]]; then
  echo "preflight-disabled path should run campaign and check stages"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! jq -e '.status == "ok" and .final_rc == 0 and .inputs.campaign_endpoint_preflight.enabled == false and .inputs.campaign_endpoint_preflight.attempted == false and .inputs.campaign_endpoint_preflight.status == "skip" and .inputs.campaign_endpoint_preflight.timeout_sec == 0 and .inputs.campaign_endpoint_preflight.skipped_reason == "endpoint preflight disabled" and .stages.campaign.preflight.status == "skip" and .stages.campaign.preflight.skipped_reason == "endpoint preflight disabled" and .stages.campaign.status == "pass" and .stages.campaign_check.status == "pass"' "$PREFLIGHT_DISABLED_SUMMARY" >/dev/null 2>&1; then
  echo "preflight-disabled summary JSON missing expected fields"
  cat "$PREFLIGHT_DISABLED_SUMMARY"
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

echo "[profile-compare-campaign-signoff] campaign timeout fail-close with heartbeat diagnostics"
: >"$SIGNOFF_CAPTURE"
CAMPAIGN_TIMEOUT_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_campaign_timeout.json"
CAMPAIGN_TIMEOUT_REPORTS_DIR="$TMP_DIR/reports_campaign_timeout"
mkdir -p "$CAMPAIGN_TIMEOUT_REPORTS_DIR"
cat >"$CAMPAIGN_TIMEOUT_REPORTS_DIR/profile_compare_campaign_check_summary.json" <<'JSON'
{
  "decision": "GO",
  "observed": {
    "recommended_profile": "balanced",
    "support_rate_pct": 91,
    "trend_source": "stale_prior_run"
  }
}
JSON
set +e
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
PROFILE_COMPARE_CAMPAIGN_SIGNOFF_HEARTBEAT_INTERVAL_SEC=1 \
FAKE_CAMPAIGN_SLEEP_SEC=4 \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=0 \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$CAMPAIGN_TIMEOUT_REPORTS_DIR" \
  --refresh-campaign 1 \
  --campaign-timeout-sec 2 \
  --summary-json "$CAMPAIGN_TIMEOUT_SUMMARY" >/tmp/integration_profile_compare_campaign_signoff_campaign_timeout.log 2>&1
rc_campaign_timeout=$?
set -e
if [[ "$rc_campaign_timeout" -ne 124 ]]; then
  echo "expected rc=124 when campaign refresh times out"
  cat /tmp/integration_profile_compare_campaign_signoff_campaign_timeout.log
  exit 1
fi
for expected in \
  'campaign refresh started attempt=initial' \
  'campaign refresh heartbeat attempt=initial' \
  'campaign refresh timeout attempt=initial' \
  'campaign_failure_reason=campaign refresh timed out after 2s'; do
  if ! rg -q -- "$expected" /tmp/integration_profile_compare_campaign_signoff_campaign_timeout.log; then
    echo "expected timeout diagnostic output missing: $expected"
    cat /tmp/integration_profile_compare_campaign_signoff_campaign_timeout.log
    exit 1
  fi
done
if [[ "$(wc -l < "$SIGNOFF_CAPTURE")" -ne 1 ]]; then
  echo "campaign-timeout path should not run check stage"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! jq -e '.status == "fail" and .final_rc == 124 and .failure_stage == "campaign" and .decision.decision == "NO-GO" and .decision.context == "synthetic_campaign_failure" and .decision.from_campaign_check_summary == false and (.decision.reason | type == "string") and (.decision.reason | contains("timed out")) and .decision.diagnostics.source_schema == "synthetic_stage_failure" and .decision.diagnostics.likely_primary_failure == "campaign_timeout" and .inputs.campaign_refresh_runtime.timeout_sec == 2 and .inputs.campaign_refresh_runtime.heartbeat_interval_sec == 1 and .stages.campaign.status == "fail" and .stages.campaign.timed_out == true and .stages.campaign.timeout_sec == 2 and .stages.campaign.duration_sec >= 2 and .stages.campaign.heartbeat_count >= 1 and (.stages.campaign.failure_reason | type == "string") and (.stages.campaign.failure_reason | contains("timed out")) and .stages.campaign_check.attempted == false' "$CAMPAIGN_TIMEOUT_SUMMARY" >/dev/null 2>&1; then
  echo "campaign-timeout summary JSON missing expected fields"
  cat "$CAMPAIGN_TIMEOUT_SUMMARY"
  exit 1
fi

echo "[profile-compare-campaign-signoff] campaign failure fail-close"
: >"$SIGNOFF_CAPTURE"
CAMPAIGN_FAIL_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_campaign_fail.json"
CAMPAIGN_FAIL_REPORTS_DIR="$TMP_DIR/reports_campaign_fail"
mkdir -p "$CAMPAIGN_FAIL_REPORTS_DIR"
cat >"$CAMPAIGN_FAIL_REPORTS_DIR/profile_compare_campaign_check_summary.json" <<'JSON'
{
  "decision": "GO",
  "observed": {
    "recommended_profile": "balanced",
    "support_rate_pct": 88,
    "trend_source": "stale_prior_run"
  }
}
JSON
set +e
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_RC=23 \
FAKE_CHECK_RC=0 \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$CAMPAIGN_FAIL_REPORTS_DIR" \
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
if ! jq -e '.status == "fail" and .final_rc == 23 and .failure_stage == "campaign" and .decision.decision == "NO-GO" and .decision.context == "synthetic_campaign_failure" and .decision.from_campaign_check_summary == false and (.decision.reason | type == "string") and (.decision.reason | contains("campaign refresh command failed rc=23")) and .decision.diagnostics.source_schema == "synthetic_stage_failure" and .decision.diagnostics.likely_primary_failure == "campaign_failure" and .stages.campaign.status == "fail" and .stages.campaign_check.attempted == false' "$CAMPAIGN_FAIL_SUMMARY" >/dev/null 2>&1; then
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

echo "[profile-compare-campaign-signoff] concurrent default lock fails fast"
: >"$SIGNOFF_CAPTURE"
LOCK_REPORTS_DIR="$TMP_DIR/reports_lock_default"
LOCK_FIRST_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_lock_first.json"
LOCK_SECOND_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_lock_second.json"
LOCK_FIRST_LOG="/tmp/integration_profile_compare_campaign_signoff_lock_first.log"
LOCK_SECOND_LOG="/tmp/integration_profile_compare_campaign_signoff_lock_second.log"

SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_SLEEP_SEC=6 \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=0 \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$LOCK_REPORTS_DIR" \
  --refresh-campaign 1 \
  --campaign-summary-json "$TMP_DIR/lock_default_first_campaign_summary.json" \
  --campaign-report-md "$TMP_DIR/lock_default_first_campaign_report.md" \
  --campaign-check-summary-json "$TMP_DIR/lock_default_first_campaign_check_summary.json" \
  --summary-json "$LOCK_FIRST_SUMMARY" >"$LOCK_FIRST_LOG" 2>&1 &
lock_first_pid=$!

lock_wait_ok=0
for _ in $(seq 1 50); do
  if [[ -d "$LOCK_REPORTS_DIR/.profile_compare_campaign_signoff.lock" ]]; then
    lock_wait_ok=1
    break
  fi
  sleep 0.1
done
if [[ "$lock_wait_ok" -ne 1 ]]; then
  echo "timed out waiting for default lock directory"
  cat "$LOCK_FIRST_LOG"
  kill "$lock_first_pid" >/dev/null 2>&1 || true
  wait "$lock_first_pid" >/dev/null 2>&1 || true
  exit 1
fi

set +e
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=0 \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$LOCK_REPORTS_DIR" \
  --refresh-campaign 1 \
  --campaign-summary-json "$TMP_DIR/lock_default_second_campaign_summary.json" \
  --campaign-report-md "$TMP_DIR/lock_default_second_campaign_report.md" \
  --campaign-check-summary-json "$TMP_DIR/lock_default_second_campaign_check_summary.json" \
  --summary-json "$LOCK_SECOND_SUMMARY" >"$LOCK_SECOND_LOG" 2>&1
rc_lock_default_second=$?
set -e
if [[ "$rc_lock_default_second" -ne 3 ]]; then
  echo "expected rc=3 when second concurrent signoff is blocked by lock"
  cat "$LOCK_SECOND_LOG"
  kill "$lock_first_pid" >/dev/null 2>&1 || true
  wait "$lock_first_pid" >/dev/null 2>&1 || true
  exit 1
fi
for expected in \
  'another signoff run is already active for this reports-dir' \
  'reports_dir:' \
  'lock_dir:' \
  'active_pid:' \
  'active_start_time_utc:' \
  'active_cmd:' \
  '--allow-concurrent 1'; do
  if ! rg -q -- "$expected" "$LOCK_SECOND_LOG"; then
    echo "expected concurrent lock error detail missing: $expected"
    cat "$LOCK_SECOND_LOG"
    kill "$lock_first_pid" >/dev/null 2>&1 || true
    wait "$lock_first_pid" >/dev/null 2>&1 || true
    exit 1
  fi
done

wait "$lock_first_pid"
if ! jq -e '.status == "ok" and .final_rc == 0 and .inputs.signoff_lock.enabled == true and .inputs.signoff_lock.override_enabled == false and .inputs.signoff_lock.allow_concurrent == false' "$LOCK_FIRST_SUMMARY" >/dev/null 2>&1; then
  echo "expected first locked run summary to report lock enabled"
  cat "$LOCK_FIRST_SUMMARY"
  exit 1
fi
if [[ -d "$LOCK_REPORTS_DIR/.profile_compare_campaign_signoff.lock" ]]; then
  echo "lock directory should be cleaned up after first run exits"
  exit 1
fi
if [[ -f "$LOCK_SECOND_SUMMARY" ]]; then
  echo "second lock-blocked run should not produce signoff summary"
  cat "$LOCK_SECOND_SUMMARY"
  exit 1
fi

echo "[profile-compare-campaign-signoff] override allows concurrent run"
: >"$SIGNOFF_CAPTURE"
LOCK_OVERRIDE_REPORTS_DIR="$TMP_DIR/reports_lock_override"
LOCK_OVERRIDE_FIRST_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_lock_override_first.json"
LOCK_OVERRIDE_SECOND_SUMMARY="$TMP_DIR/profile_compare_campaign_signoff_lock_override_second.json"
LOCK_OVERRIDE_FIRST_LOG="/tmp/integration_profile_compare_campaign_signoff_lock_override_first.log"
LOCK_OVERRIDE_SECOND_LOG="/tmp/integration_profile_compare_campaign_signoff_lock_override_second.log"

SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_SLEEP_SEC=6 \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=0 \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$LOCK_OVERRIDE_REPORTS_DIR" \
  --refresh-campaign 1 \
  --campaign-summary-json "$TMP_DIR/lock_override_first_campaign_summary.json" \
  --campaign-report-md "$TMP_DIR/lock_override_first_campaign_report.md" \
  --campaign-check-summary-json "$TMP_DIR/lock_override_first_campaign_check_summary.json" \
  --summary-json "$LOCK_OVERRIDE_FIRST_SUMMARY" >"$LOCK_OVERRIDE_FIRST_LOG" 2>&1 &
lock_override_first_pid=$!

lock_override_wait_ok=0
for _ in $(seq 1 50); do
  if [[ -d "$LOCK_OVERRIDE_REPORTS_DIR/.profile_compare_campaign_signoff.lock" ]]; then
    lock_override_wait_ok=1
    break
  fi
  sleep 0.1
done
if [[ "$lock_override_wait_ok" -ne 1 ]]; then
  echo "timed out waiting for lock directory before override run"
  cat "$LOCK_OVERRIDE_FIRST_LOG"
  kill "$lock_override_first_pid" >/dev/null 2>&1 || true
  wait "$lock_override_first_pid" >/dev/null 2>&1 || true
  exit 1
fi

SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CAMPAIGN_RC=0 \
FAKE_CHECK_RC=0 \
./scripts/profile_compare_campaign_signoff.sh \
  --reports-dir "$LOCK_OVERRIDE_REPORTS_DIR" \
  --refresh-campaign 1 \
  --allow-concurrent 1 \
  --campaign-summary-json "$TMP_DIR/lock_override_second_campaign_summary.json" \
  --campaign-report-md "$TMP_DIR/lock_override_second_campaign_report.md" \
  --campaign-check-summary-json "$TMP_DIR/lock_override_second_campaign_check_summary.json" \
  --summary-json "$LOCK_OVERRIDE_SECOND_SUMMARY" >"$LOCK_OVERRIDE_SECOND_LOG" 2>&1

wait "$lock_override_first_pid"
if ! jq -e '.status == "ok" and .final_rc == 0 and .inputs.signoff_lock.enabled == true and .inputs.signoff_lock.override_enabled == false and .inputs.signoff_lock.allow_concurrent == false' "$LOCK_OVERRIDE_FIRST_SUMMARY" >/dev/null 2>&1; then
  echo "expected override first run summary to report lock enabled"
  cat "$LOCK_OVERRIDE_FIRST_SUMMARY"
  exit 1
fi
if ! jq -e '.status == "ok" and .final_rc == 0 and .inputs.signoff_lock.enabled == false and .inputs.signoff_lock.override_enabled == true and .inputs.signoff_lock.allow_concurrent == true' "$LOCK_OVERRIDE_SECOND_SUMMARY" >/dev/null 2>&1; then
  echo "expected override second run summary to report lock override"
  cat "$LOCK_OVERRIDE_SECOND_SUMMARY"
  exit 1
fi
if [[ -d "$LOCK_OVERRIDE_REPORTS_DIR/.profile_compare_campaign_signoff.lock" ]]; then
  echo "lock directory should be cleaned up after override scenario completes"
  exit 1
fi

echo "[profile-compare-campaign-signoff] decision diagnostics + operator action mapping"
DIAG_REPORTS_DIR="$TMP_DIR/reports_diag_actions"
mkdir -p "$DIAG_REPORTS_DIR"
DIAG_CAMPAIGN_JSON="$DIAG_REPORTS_DIR/profile_compare_campaign_summary.json"
DIAG_REPORT_MD="$DIAG_REPORTS_DIR/profile_compare_campaign_report.md"
printf '# diag report\n' >"$DIAG_REPORT_MD"

assert_diag_case() {
  local case_name="$1"
  local expected_source_schema="$2"
  local expected_primary_failure="$3"
  local expected_action="$4"
  local expected_transport_mismatch="${5:-0}"
  local expected_token_invalid="${6:-0}"
  local expected_unknown_exit="${7:-0}"
  local expected_directory_trust="${8:-0}"
  local expected_root_required="${9:-0}"
  local expected_endpoint_unreachable="${10:-0}"
  local expected_operator_hint="${11:-}"
  local summary_out="$TMP_DIR/profile_compare_campaign_signoff_diag_${case_name}.json"
  local check_out="$DIAG_REPORTS_DIR/profile_compare_campaign_check_summary_${case_name}.json"

  SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
  PROFILE_COMPARE_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
  PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
  FAKE_CHECK_RC=0 \
  FAKE_CHECK_DECISION=GO \
  ./scripts/profile_compare_campaign_signoff.sh \
    --reports-dir "$DIAG_REPORTS_DIR" \
    --refresh-campaign 0 \
    --campaign-summary-json "$DIAG_CAMPAIGN_JSON" \
    --campaign-report-md "$DIAG_REPORT_MD" \
    --campaign-check-summary-json "$check_out" \
    --summary-json "$summary_out" >/tmp/integration_profile_compare_campaign_signoff_diag_${case_name}.log 2>&1

  if ! jq -e \
    --arg expected_source_schema "$expected_source_schema" \
    --arg expected_primary_failure "$expected_primary_failure" \
    --arg expected_action "$expected_action" \
    --arg expected_operator_hint "$expected_operator_hint" \
    --argjson expected_transport_mismatch "$expected_transport_mismatch" \
    --argjson expected_token_invalid "$expected_token_invalid" \
    --argjson expected_unknown_exit "$expected_unknown_exit" \
    --argjson expected_directory_trust "$expected_directory_trust" \
    --argjson expected_root_required "$expected_root_required" \
    --argjson expected_endpoint_unreachable "$expected_endpoint_unreachable" \
    '
    .status == "ok"
    and .final_rc == 0
    and .decision.decision == "GO"
    and .decision.next_operator_action == $expected_action
    and .decision.diagnostics.source_schema == $expected_source_schema
    and .decision.diagnostics.likely_primary_failure == $expected_primary_failure
    and (.decision.diagnostics.operator_hint // "") == $expected_operator_hint
    and .decision.diagnostics.aggregated_diagnostics.transport_mismatch_failures == $expected_transport_mismatch
    and .decision.diagnostics.aggregated_diagnostics.token_proof_invalid_failures == $expected_token_invalid
    and .decision.diagnostics.aggregated_diagnostics.unknown_exit_failures == $expected_unknown_exit
    and .decision.diagnostics.aggregated_diagnostics.directory_trust_failures == $expected_directory_trust
    and .decision.diagnostics.aggregated_diagnostics.root_required_failures == $expected_root_required
    and .decision.diagnostics.aggregated_diagnostics.endpoint_unreachable_failures == $expected_endpoint_unreachable
    and (if $expected_source_schema == "legacy" then .decision.diagnostics.legacy != null else true end)
    ' \
    "$summary_out" >/dev/null 2>&1; then
    echo "diagnostics mapping assertion failed for case=$case_name"
    cat "$summary_out"
    exit 1
  fi
}

cat >"$DIAG_CAMPAIGN_JSON" <<'EOF_DIAG_TOKEN'
{
  "version": 1,
  "status": "pass",
  "summary": {"runs_total": 3},
  "decision": {"recommended_default_profile": "balanced"},
  "trend": {"status": "pass"},
  "diagnostics": {"failure_kinds": ["token_proof_invalid"]}
}
EOF_DIAG_TOKEN
assert_diag_case "legacy_token" "legacy" "token_proof_invalid" "Use a fresh invite key from active issuer and rerun signoff"

cat >"$DIAG_CAMPAIGN_JSON" <<'EOF_DIAG_UNKNOWN'
{
  "version": 1,
  "status": "pass",
  "summary": {"runs_total": 3},
  "decision": {"recommended_default_profile": "balanced"},
  "trend": {"status": "pass"},
  "diagnostics": {"failure_kinds": ["unknown_exit"]}
}
EOF_DIAG_UNKNOWN
assert_diag_case "legacy_unknown" "legacy" "unknown_exit" "Use a fresh invite key from active issuer and rerun signoff"

cat >"$DIAG_CAMPAIGN_JSON" <<'EOF_DIAG_SUMMARY_TRUST'
{
  "version": 1,
  "status": "pass",
  "summary": {
    "runs_total": 3,
    "diagnostics": {"failure_kinds": ["directory_trust"]}
  },
  "decision": {"recommended_default_profile": "balanced"},
  "trend": {"status": "pass"}
}
EOF_DIAG_SUMMARY_TRUST
assert_diag_case "legacy_summary_trust" "legacy" "directory_trust" "Run trust/runtime reset path then rerun"

cat >"$DIAG_CAMPAIGN_JSON" <<'EOF_DIAG_LEGACY_ROOT_COUNT'
{
  "version": 1,
  "status": "pass",
  "summary": {"runs_total": 3},
  "decision": {"recommended_default_profile": "balanced"},
  "trend": {"status": "pass"},
  "diagnostics": {
    "root_required_failures": 3,
    "endpoint_unreachable_failures": 0
  }
}
EOF_DIAG_LEGACY_ROOT_COUNT
assert_diag_case "legacy_root_counter" "legacy" "root_required" "Run signoff with sudo (root) or force docker campaign refresh mode, then rerun" 0 0 0 0 3 0

cat >"$DIAG_CAMPAIGN_JSON" <<'EOF_DIAG_LEGACY_SUMMARY_ENDPOINT_COUNT'
{
  "version": 1,
  "status": "pass",
  "summary": {
    "runs_total": 3,
    "diagnostics": {
      "root_required_failures": 0,
      "endpoint_unreachable_failures": 2
    }
  },
  "decision": {"recommended_default_profile": "balanced"},
  "trend": {"status": "pass"}
}
EOF_DIAG_LEGACY_SUMMARY_ENDPOINT_COUNT
assert_diag_case "legacy_summary_endpoint_counter" "legacy" "endpoint_unreachable" "Verify directory/issuer/entry/exit endpoints are reachable, then rerun signoff" 0 0 0 0 0 2

cat >"$DIAG_CAMPAIGN_JSON" <<'EOF_DIAG_CURRENT_TRANSPORT'
{
  "version": 1,
  "status": "pass",
  "summary": {"runs_total": 3},
  "decision": {"recommended_default_profile": "balanced"},
  "trend": {"status": "pass"},
  "aggregated_diagnostics": {
    "transport_mismatch_failures": 2,
    "token_proof_invalid_failures": 0,
    "unknown_exit_failures": 0,
    "directory_trust_failures": 0
  }
}
EOF_DIAG_CURRENT_TRANSPORT
assert_diag_case "current_transport" "current" "transport_mismatch" "Rerun with remote docker campaign and opaque/udp transport defaults" 2 0 0 0

cat >"$DIAG_CAMPAIGN_JSON" <<'EOF_DIAG_CURRENT_ROOT'
{
  "version": 1,
  "status": "pass",
  "summary": {"runs_total": 3},
  "decision": {"recommended_default_profile": "balanced"},
  "trend": {"status": "pass"},
  "aggregated_diagnostics": {
    "transport_mismatch_failures": 0,
    "token_proof_invalid_failures": 0,
    "unknown_exit_failures": 0,
    "directory_trust_failures": 0,
    "root_required_failures": 5,
    "endpoint_unreachable_failures": 0
  },
  "operator_hint": "requires root privileges to run local stack"
}
EOF_DIAG_CURRENT_ROOT
assert_diag_case "current_root_required" "current" "root_required" "Run signoff with sudo (root) or force docker campaign refresh mode, then rerun" 0 0 0 0 5 0 "requires root privileges to run local stack"

cat >"$DIAG_CAMPAIGN_JSON" <<'EOF_DIAG_CURRENT_ENDPOINT'
{
  "version": 1,
  "status": "pass",
  "summary": {"runs_total": 3},
  "decision": {"recommended_default_profile": "balanced"},
  "trend": {"status": "pass"},
  "aggregated_diagnostics": {
    "transport_mismatch_failures": 0,
    "token_proof_invalid_failures": 0,
    "unknown_exit_failures": 0,
    "directory_trust_failures": 0,
    "root_required_failures": 0,
    "endpoint_unreachable_failures": 4
  },
  "operator_hint": "directory endpoint did not respond"
}
EOF_DIAG_CURRENT_ENDPOINT
assert_diag_case "current_endpoint_unreachable" "current" "endpoint_unreachable" "Verify directory/issuer/entry/exit endpoints are reachable, then rerun signoff" 0 0 0 0 0 4 "directory endpoint did not respond"

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

echo "[profile-compare-campaign-signoff] easy_node forwarding aliases"
FORWARD_CAPTURE_FILE="$FORWARD_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_FORWARD" \
./scripts/easy_node.sh profile-compare-campaign-signoff \
  --reports-dir /tmp/reports-alias \
  --refresh-campaign 1 \
  --subject inv-forward-alias \
  --anon-cred anon-forward-alias \
  --summary-json /tmp/signoff-alias.json \
  --print-summary-json 1

alias_forward_line="$(rg '^profile-compare-campaign-signoff ' "$FORWARD_CAPTURE" | tail -n 1 || true)"
if [[ -z "$alias_forward_line" ]]; then
  echo "missing easy_node alias forwarding capture"
  cat "$FORWARD_CAPTURE"
  exit 1
fi
for expected in '--reports-dir /tmp/reports-alias' '--refresh-campaign 1' '--campaign-subject inv-forward-alias' '--campaign-anon-cred anon-forward-alias' '--summary-json /tmp/signoff-alias.json' '--print-summary-json 1'; do
  if ! grep -F -- "$expected" <<<"$alias_forward_line" >/dev/null; then
    echo "easy_node alias forwarding missing $expected"
    cat "$FORWARD_CAPTURE"
    exit 1
  fi
done
if grep -F -- '--subject inv-forward-alias' <<<"$alias_forward_line" >/dev/null || grep -F -- '--anon-cred anon-forward-alias' <<<"$alias_forward_line" >/dev/null; then
  echo "easy_node alias forwarding should normalize subject/anon-cred to campaign-prefixed flags"
  cat "$FORWARD_CAPTURE"
  exit 1
fi

echo "[profile-compare-campaign-signoff] easy_node alias/campaign-subject conflict fails clearly"
set +e
FORWARD_CAPTURE_FILE="$FORWARD_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_FORWARD" \
./scripts/easy_node.sh profile-compare-campaign-signoff \
  --reports-dir /tmp/reports-conflict-subject \
  --refresh-campaign 1 \
  --subject inv-alias-a \
  --campaign-subject inv-campaign-b \
  --summary-json /tmp/signoff-conflict-subject.json \
  --print-summary-json 1 >/tmp/integration_profile_compare_campaign_signoff_easy_node_conflict_subject.log 2>&1
easy_node_conflict_subject_rc=$?
set -e
if [[ "$easy_node_conflict_subject_rc" -ne 2 ]]; then
  echo "expected rc=2 when easy_node --subject conflicts with --campaign-subject"
  cat /tmp/integration_profile_compare_campaign_signoff_easy_node_conflict_subject.log
  exit 1
fi
if ! rg -q 'conflicting subject values: --subject and --campaign-subject must match when both are provided' /tmp/integration_profile_compare_campaign_signoff_easy_node_conflict_subject.log; then
  echo "expected easy_node subject conflict message missing"
  cat /tmp/integration_profile_compare_campaign_signoff_easy_node_conflict_subject.log
  exit 1
fi

echo "[profile-compare-campaign-signoff] easy_node alias/campaign-anon-cred conflict fails clearly"
set +e
FORWARD_CAPTURE_FILE="$FORWARD_CAPTURE" \
PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_FORWARD" \
./scripts/easy_node.sh profile-compare-campaign-signoff \
  --reports-dir /tmp/reports-conflict-anon \
  --refresh-campaign 1 \
  --anon-cred anon-a \
  --campaign-anon-cred anon-b \
  --summary-json /tmp/signoff-conflict-anon.json \
  --print-summary-json 1 >/tmp/integration_profile_compare_campaign_signoff_easy_node_conflict_anon.log 2>&1
easy_node_conflict_anon_rc=$?
set -e
if [[ "$easy_node_conflict_anon_rc" -ne 2 ]]; then
  echo "expected rc=2 when easy_node --anon-cred conflicts with --campaign-anon-cred"
  cat /tmp/integration_profile_compare_campaign_signoff_easy_node_conflict_anon.log
  exit 1
fi
if ! rg -q 'conflicting anon credential values: --anon-cred and --campaign-anon-cred must match when both are provided' /tmp/integration_profile_compare_campaign_signoff_easy_node_conflict_anon.log; then
  echo "expected easy_node anon conflict message missing"
  cat /tmp/integration_profile_compare_campaign_signoff_easy_node_conflict_anon.log
  exit 1
fi

echo "profile compare campaign signoff integration check ok"
