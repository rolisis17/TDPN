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
echo "[profile-compare-local] profile=balanced round=1 status=pass rc=0 duration_sec=5"
echo "[profile-compare-local] profile=speed round=2 status=pass rc=0 duration_sec=6"
hard_fail_mode="${FAKE_LOCAL_HARD_FAIL_MODE:-none}"
case "$hard_fail_mode" in
  root_required)
    echo "client test requires root (run with sudo)"
    echo "permission denied"
    ;;
  endpoint_unreachable)
    echo 'dial tcp 100.113.245.61:8081: connect: connection refused'
    echo "could not resolve host: issuer.invalid"
    ;;
esac

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

diag_mode="${FAKE_LOCAL_DIAG_MODE:-staggered}"
transport_mismatch_failures=0
token_proof_invalid_failures=0
unknown_exit_failures=0
directory_trust_failures=0
selection_policy_sticky_pair_sec=300
selection_policy_entry_rotation_sec=45
selection_policy_entry_rotation_jitter_pct=9
selection_policy_exit_exploration_pct=18
selection_policy_path_profile="2hop"
case "$diag_mode" in
  staggered)
    case "$count" in
      1) transport_mismatch_failures=1 ;;
      2) token_proof_invalid_failures=2 ;;
      3) unknown_exit_failures=3 ;;
      4) directory_trust_failures=4 ;;
    esac
    ;;
  directory_only)
    directory_trust_failures=7
    ;;
  none)
    ;;
esac

cat >"$summary_json" <<EOF_SUMMARY
{
  "version": 1,
  "status": "$status",
  "rc": $rc,
  "notes": "$notes",
  "summary": {
    "runs_executed": 4,
    "runs_fail": $rc,
    "selection_policy": {
      "sticky_pair_sec": $selection_policy_sticky_pair_sec,
      "entry_rotation_sec": $selection_policy_entry_rotation_sec,
      "entry_rotation_jitter_pct": $selection_policy_entry_rotation_jitter_pct,
      "exit_exploration_pct": $selection_policy_exit_exploration_pct,
      "path_profile": "$selection_policy_path_profile"
    }
  },
  "decision": {
    "recommended_default_profile": "$recommended"
  },
EOF_SUMMARY

if [[ "$diag_mode" != "missing" ]]; then
cat >>"$summary_json" <<EOF_SUMMARY
  "diagnostics": {
    "transport_mismatch_failures": $transport_mismatch_failures,
    "token_proof_invalid_failures": $token_proof_invalid_failures,
    "unknown_exit_failures": $unknown_exit_failures,
    "directory_trust_failures": $directory_trust_failures
  },
EOF_SUMMARY
fi

cat >>"$summary_json" <<EOF_SUMMARY
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

if [[ "${FAKE_TREND_INCLUDE_SELECTION_POLICY:-1}" == "1" ]]; then
  trend_summary_tmp="${summary_json}.selection_policy.tmp"
  jq '
    .summary.selection_policy = {
      sticky_pair_sec: 410,
      entry_rotation_sec: 60,
      entry_rotation_jitter_pct: 11,
      exit_exploration_pct: 24,
      path_profile: "3hop"
    }
  ' "$summary_json" >"$trend_summary_tmp"
  mv "$trend_summary_tmp" "$summary_json"
fi

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
FAKE_TREND_INCLUDE_SELECTION_POLICY=1 \
./scripts/profile_compare_campaign.sh \
  --campaign-runs 3 \
  --directory-urls http://dir-a:8081 \
  --issuer-url http://issuer-a:8082 \
  --entry-url http://entry-a:8083 \
  --exit-url http://exit-a:8084 \
  --campaign-pause-sec 0 \
  --summary-json "$SUCCESS_JSON" \
  --report-md "$SUCCESS_REPORT" \
  --print-summary-json 1 >/tmp/integration_profile_compare_campaign_success.log 2>&1

if ! rg -q 'profile-compare-campaign: status=pass' /tmp/integration_profile_compare_campaign_success.log; then
  echo "expected campaign success status output"
  cat /tmp/integration_profile_compare_campaign_success.log
  exit 1
fi
for marker in \
  '[profile-compare-campaign] stage=campaign-start' \
  '[profile-compare-campaign] stage=compare-start run_index=1 run_total=3 run_id=01' \
  '[profile-compare-campaign] stage=compare-end run_index=1 run_total=3 run_id=01' \
  '[profile-compare-campaign] stage=compare-progress run_index=1 run_total=3 run_id=01 marker="[profile-compare-local] profile=speed round=2 status=pass rc=0 duration_sec=6"' \
  '[profile-compare-campaign] stage=trend-start reports=3' \
  '[profile-compare-campaign] stage=trend-end rc=0' \
  '[profile-compare-campaign] stage=campaign-end status=pass rc=0'; do
  if ! rg -Fq -- "$marker" /tmp/integration_profile_compare_campaign_success.log; then
    echo "expected progress marker missing from stdout: $marker"
    cat /tmp/integration_profile_compare_campaign_success.log
    exit 1
  fi
done
SUCCESS_SUMMARY_LOG="$(jq -r '.artifacts.summary_log' "$SUCCESS_JSON")"
if [[ -z "$SUCCESS_SUMMARY_LOG" || ! -f "$SUCCESS_SUMMARY_LOG" ]]; then
  echo "expected summary log artifact path in campaign summary"
  cat "$SUCCESS_JSON"
  exit 1
fi
for marker in \
  '[profile-compare-campaign] stage=campaign-start' \
  '[profile-compare-campaign] stage=compare-progress run_index=1 run_total=3 run_id=01 marker="[profile-compare-local] profile=speed round=2 status=pass rc=0 duration_sec=6"' \
  '[profile-compare-campaign] stage=trend-end rc=0' \
  '[profile-compare-campaign] stage=campaign-end status=pass rc=0'; do
  if ! rg -Fq -- "$marker" "$SUCCESS_SUMMARY_LOG"; then
    echo "expected progress marker missing from summary log artifact: $marker"
    cat "$SUCCESS_SUMMARY_LOG"
    exit 1
  fi
done
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .summary.runs_total == 3
  and .summary.runs_fail == 0
  and (.summary.selection_policy.sticky_pair_sec | type == "number")
  and (.summary.selection_policy.entry_rotation_sec | type == "number")
  and (.summary.selection_policy.entry_rotation_jitter_pct | type == "number")
  and (.summary.selection_policy.exit_exploration_pct | type == "number")
  and (.summary.selection_policy.path_profile | type == "string")
  and .summary.selection_policy.sticky_pair_sec == 410
  and .summary.selection_policy.entry_rotation_sec == 60
  and .summary.selection_policy.entry_rotation_jitter_pct == 11
  and .summary.selection_policy.exit_exploration_pct == 24
  and .summary.selection_policy.path_profile == "3hop"
  and (.selected_summaries | length) == 3
  and .trend.status == "pass"
  and .inputs.compare.explicit_remote_endpoints == true
  and .inputs.compare.transport_auto_defaults.client_inner_source_udp == true
  and .inputs.compare.transport_auto_defaults.disable_synthetic_fallback == true
  and .inputs.compare.transport_auto_defaults.data_plane_mode_opaque == true
  and .aggregated_diagnostics.transport_mismatch_failures == 1
  and .aggregated_diagnostics.token_proof_invalid_failures == 2
  and .aggregated_diagnostics.unknown_exit_failures == 3
  and .aggregated_diagnostics.directory_trust_failures == 0
  and .aggregated_diagnostics.root_required_failures == 0
  and .aggregated_diagnostics.endpoint_unreachable_failures == 0
  and .likely_primary_failure == "token_proof_invalid"
  and (.operator_hint | contains("invite/issuer alignment"))
' "$SUCCESS_JSON" >/dev/null 2>&1; then
  echo "campaign success summary missing expected fields"
  cat "$SUCCESS_JSON"
  exit 1
fi

echo "[profile-compare-campaign] selection policy fallback from local summaries"
: >"$LOCAL_CAPTURE"
: >"$TREND_CAPTURE"
printf '0\n' >"$LOCAL_COUNTER"
SELECTION_POLICY_FALLBACK_JSON="$TMP_DIR/campaign_selection_policy_fallback.json"
PROFILE_COMPARE_CAMPAIGN_LOCAL_SCRIPT="$FAKE_LOCAL" \
PROFILE_COMPARE_CAMPAIGN_TREND_SCRIPT="$FAKE_TREND" \
FAKE_LOCAL_CAPTURE_FILE="$LOCAL_CAPTURE" \
FAKE_LOCAL_COUNTER_FILE="$LOCAL_COUNTER" \
FAKE_LOCAL_FAIL_AT=0 \
FAKE_TREND_CAPTURE_FILE="$TREND_CAPTURE" \
FAKE_TREND_FORCE_FAIL=0 \
FAKE_TREND_INCLUDE_SELECTION_POLICY=0 \
./scripts/profile_compare_campaign.sh \
  --campaign-runs 1 \
  --summary-json "$SELECTION_POLICY_FALLBACK_JSON" >/tmp/integration_profile_compare_campaign_selection_policy_fallback.log 2>&1

if ! jq -e '
  .status == "pass"
  and .summary.selection_policy.sticky_pair_sec == 300
  and .summary.selection_policy.entry_rotation_sec == 45
  and .summary.selection_policy.entry_rotation_jitter_pct == 9
  and .summary.selection_policy.exit_exploration_pct == 18
  and .summary.selection_policy.path_profile == "2hop"
' "$SELECTION_POLICY_FALLBACK_JSON" >/dev/null 2>&1; then
  echo "campaign selection policy fallback summary missing expected local values"
  cat "$SELECTION_POLICY_FALLBACK_JSON"
  exit 1
fi

echo "[profile-compare-campaign] diagnostics precedence and operator hint (directory_trust)"
: >"$LOCAL_CAPTURE"
: >"$TREND_CAPTURE"
printf '0\n' >"$LOCAL_COUNTER"
DIRECTORY_DIAG_JSON="$TMP_DIR/campaign_directory_diag.json"
PROFILE_COMPARE_CAMPAIGN_LOCAL_SCRIPT="$FAKE_LOCAL" \
PROFILE_COMPARE_CAMPAIGN_TREND_SCRIPT="$FAKE_TREND" \
FAKE_LOCAL_CAPTURE_FILE="$LOCAL_CAPTURE" \
FAKE_LOCAL_COUNTER_FILE="$LOCAL_COUNTER" \
FAKE_LOCAL_FAIL_AT=0 \
FAKE_LOCAL_DIAG_MODE=directory_only \
FAKE_TREND_CAPTURE_FILE="$TREND_CAPTURE" \
FAKE_TREND_FORCE_FAIL=0 \
FAKE_TREND_INCLUDE_SELECTION_POLICY=1 \
./scripts/profile_compare_campaign.sh \
  --campaign-runs 1 \
  --summary-json "$DIRECTORY_DIAG_JSON" >/tmp/integration_profile_compare_campaign_directory_diag.log 2>&1

if ! jq -e '
  .aggregated_diagnostics.transport_mismatch_failures == 0
  and .aggregated_diagnostics.token_proof_invalid_failures == 0
  and .aggregated_diagnostics.unknown_exit_failures == 0
  and .aggregated_diagnostics.directory_trust_failures == 7
  and .aggregated_diagnostics.root_required_failures == 0
  and .aggregated_diagnostics.endpoint_unreachable_failures == 0
  and .likely_primary_failure == "directory_trust"
  and (.operator_hint | contains("trust reset"))
' "$DIRECTORY_DIAG_JSON" >/dev/null 2>&1; then
  echo "campaign diagnostics summary missing expected directory_trust values"
  cat "$DIRECTORY_DIAG_JSON"
  exit 1
fi

echo "[profile-compare-campaign] log fallback diagnostics (root_required)"
: >"$LOCAL_CAPTURE"
: >"$TREND_CAPTURE"
printf '0\n' >"$LOCAL_COUNTER"
ROOT_FALLBACK_JSON="$TMP_DIR/campaign_root_fallback_diag.json"
PROFILE_COMPARE_CAMPAIGN_LOCAL_SCRIPT="$FAKE_LOCAL" \
PROFILE_COMPARE_CAMPAIGN_TREND_SCRIPT="$FAKE_TREND" \
FAKE_LOCAL_CAPTURE_FILE="$LOCAL_CAPTURE" \
FAKE_LOCAL_COUNTER_FILE="$LOCAL_COUNTER" \
FAKE_LOCAL_FAIL_AT=0 \
FAKE_LOCAL_DIAG_MODE=missing \
FAKE_LOCAL_HARD_FAIL_MODE=root_required \
FAKE_TREND_CAPTURE_FILE="$TREND_CAPTURE" \
FAKE_TREND_FORCE_FAIL=0 \
FAKE_TREND_INCLUDE_SELECTION_POLICY=1 \
./scripts/profile_compare_campaign.sh \
  --campaign-runs 1 \
  --summary-json "$ROOT_FALLBACK_JSON" >/tmp/integration_profile_compare_campaign_root_fallback.log 2>&1

if ! jq -e '
  .aggregated_diagnostics.transport_mismatch_failures == 0
  and .aggregated_diagnostics.token_proof_invalid_failures == 0
  and .aggregated_diagnostics.unknown_exit_failures == 0
  and .aggregated_diagnostics.directory_trust_failures == 0
  and .aggregated_diagnostics.root_required_failures > 0
  and .aggregated_diagnostics.endpoint_unreachable_failures == 0
  and .likely_primary_failure == "root_required"
  and (.operator_hint | contains("sudo/root"))
' "$ROOT_FALLBACK_JSON" >/dev/null 2>&1; then
  echo "campaign fallback diagnostics missing expected root_required values"
  cat "$ROOT_FALLBACK_JSON"
  exit 1
fi

echo "[profile-compare-campaign] log fallback diagnostics (endpoint_unreachable)"
: >"$LOCAL_CAPTURE"
: >"$TREND_CAPTURE"
printf '0\n' >"$LOCAL_COUNTER"
ENDPOINT_FALLBACK_JSON="$TMP_DIR/campaign_endpoint_fallback_diag.json"
PROFILE_COMPARE_CAMPAIGN_LOCAL_SCRIPT="$FAKE_LOCAL" \
PROFILE_COMPARE_CAMPAIGN_TREND_SCRIPT="$FAKE_TREND" \
FAKE_LOCAL_CAPTURE_FILE="$LOCAL_CAPTURE" \
FAKE_LOCAL_COUNTER_FILE="$LOCAL_COUNTER" \
FAKE_LOCAL_FAIL_AT=0 \
FAKE_LOCAL_DIAG_MODE=missing \
FAKE_LOCAL_HARD_FAIL_MODE=endpoint_unreachable \
FAKE_TREND_CAPTURE_FILE="$TREND_CAPTURE" \
FAKE_TREND_FORCE_FAIL=0 \
FAKE_TREND_INCLUDE_SELECTION_POLICY=1 \
./scripts/profile_compare_campaign.sh \
  --campaign-runs 1 \
  --summary-json "$ENDPOINT_FALLBACK_JSON" >/tmp/integration_profile_compare_campaign_endpoint_fallback.log 2>&1

if ! jq -e '
  .aggregated_diagnostics.transport_mismatch_failures == 0
  and .aggregated_diagnostics.token_proof_invalid_failures == 0
  and .aggregated_diagnostics.unknown_exit_failures == 0
  and .aggregated_diagnostics.directory_trust_failures == 0
  and .aggregated_diagnostics.root_required_failures == 0
  and .aggregated_diagnostics.endpoint_unreachable_failures > 0
  and .likely_primary_failure == "endpoint_unreachable"
  and (.operator_hint | contains("reachability and DNS"))
' "$ENDPOINT_FALLBACK_JSON" >/dev/null 2>&1; then
  echo "campaign fallback diagnostics missing expected endpoint_unreachable values"
  cat "$ENDPOINT_FALLBACK_JSON"
  exit 1
fi

echo "[profile-compare-campaign] loopback metadata keeps auto transport defaults off"
: >"$LOCAL_CAPTURE"
: >"$TREND_CAPTURE"
printf '0\n' >"$LOCAL_COUNTER"
LOOPBACK_JSON="$TMP_DIR/campaign_loopback.json"
PROFILE_COMPARE_CAMPAIGN_LOCAL_SCRIPT="$FAKE_LOCAL" \
PROFILE_COMPARE_CAMPAIGN_TREND_SCRIPT="$FAKE_TREND" \
FAKE_LOCAL_CAPTURE_FILE="$LOCAL_CAPTURE" \
FAKE_LOCAL_COUNTER_FILE="$LOCAL_COUNTER" \
FAKE_LOCAL_FAIL_AT=0 \
FAKE_TREND_CAPTURE_FILE="$TREND_CAPTURE" \
FAKE_TREND_FORCE_FAIL=0 \
FAKE_TREND_INCLUDE_SELECTION_POLICY=1 \
./scripts/profile_compare_campaign.sh \
  --campaign-runs 1 \
  --directory-urls http://127.0.0.1:8081 \
  --issuer-url http://127.0.0.1:8082 \
  --entry-url http://127.0.0.1:8083 \
  --exit-url http://127.0.0.1:8084 \
  --summary-json "$LOOPBACK_JSON" >/tmp/integration_profile_compare_campaign_loopback.log 2>&1

if ! jq -e '
  .status == "pass"
  and .inputs.compare.explicit_remote_endpoints == false
  and .inputs.compare.transport_auto_defaults.client_inner_source_udp == false
  and .inputs.compare.transport_auto_defaults.disable_synthetic_fallback == false
  and .inputs.compare.transport_auto_defaults.data_plane_mode_opaque == false
' "$LOOPBACK_JSON" >/dev/null 2>&1; then
  echo "campaign loopback metadata missing expected transport defaults"
  cat "$LOOPBACK_JSON"
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
FAKE_TREND_INCLUDE_SELECTION_POLICY=1 \
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
FAKE_TREND_INCLUDE_SELECTION_POLICY=1 \
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

echo "[profile-compare-campaign] lock fail-fast with owner metadata"
LOCK_REPORTS_DIR="$TMP_DIR/campaign_lock_reports"
LOCK_SUMMARY="$LOCK_REPORTS_DIR/campaign_lock_summary.json"
LOCK_DIR="$LOCK_REPORTS_DIR/.profile_compare_campaign.lock"
mkdir -p "$LOCK_REPORTS_DIR" "$LOCK_DIR"
cat >"$LOCK_DIR/owner" <<EOF_LOCK
pid=$$
start_utc=2026-04-16T00:00:00Z
scope=reports_dir
command=fake-lock-owner
EOF_LOCK

set +e
PROFILE_COMPARE_CAMPAIGN_LOCAL_SCRIPT="$FAKE_LOCAL" \
PROFILE_COMPARE_CAMPAIGN_TREND_SCRIPT="$FAKE_TREND" \
FAKE_LOCAL_CAPTURE_FILE="$LOCAL_CAPTURE" \
FAKE_LOCAL_COUNTER_FILE="$LOCAL_COUNTER" \
FAKE_LOCAL_FAIL_AT=0 \
FAKE_TREND_CAPTURE_FILE="$TREND_CAPTURE" \
FAKE_TREND_FORCE_FAIL=0 \
FAKE_TREND_INCLUDE_SELECTION_POLICY=1 \
./scripts/profile_compare_campaign.sh \
  --campaign-runs 1 \
  --reports-dir "$LOCK_REPORTS_DIR" \
  --summary-json "$LOCK_SUMMARY" >/tmp/integration_profile_compare_campaign_lock_fail.log 2>&1
lock_fail_rc=$?
set -e
if [[ "$lock_fail_rc" -eq 0 ]]; then
  echo "expected lock fail-fast rc when active owner lock exists"
  cat /tmp/integration_profile_compare_campaign_lock_fail.log
  exit 1
fi
if ! rg -q 'another campaign run is active' /tmp/integration_profile_compare_campaign_lock_fail.log; then
  echo "expected lock fail-fast message"
  cat /tmp/integration_profile_compare_campaign_lock_fail.log
  exit 1
fi
if ! rg -q "owner_pid: $$" /tmp/integration_profile_compare_campaign_lock_fail.log; then
  echo "expected lock owner pid in fail-fast message"
  cat /tmp/integration_profile_compare_campaign_lock_fail.log
  exit 1
fi
if ! rg -q 'owner_start_utc: 2026-04-16T00:00:00Z' /tmp/integration_profile_compare_campaign_lock_fail.log; then
  echo "expected lock owner start time in fail-fast message"
  cat /tmp/integration_profile_compare_campaign_lock_fail.log
  exit 1
fi

echo "[profile-compare-campaign] lock override flag allows concurrent execution"
PROFILE_COMPARE_CAMPAIGN_LOCAL_SCRIPT="$FAKE_LOCAL" \
PROFILE_COMPARE_CAMPAIGN_TREND_SCRIPT="$FAKE_TREND" \
FAKE_LOCAL_CAPTURE_FILE="$LOCAL_CAPTURE" \
FAKE_LOCAL_COUNTER_FILE="$LOCAL_COUNTER" \
FAKE_LOCAL_FAIL_AT=0 \
FAKE_TREND_CAPTURE_FILE="$TREND_CAPTURE" \
FAKE_TREND_FORCE_FAIL=0 \
FAKE_TREND_INCLUDE_SELECTION_POLICY=1 \
./scripts/profile_compare_campaign.sh \
  --campaign-runs 1 \
  --reports-dir "$LOCK_REPORTS_DIR" \
  --summary-json "$LOCK_SUMMARY" \
  --allow-concurrent 1 >/tmp/integration_profile_compare_campaign_lock_override_flag.log 2>&1

if ! rg -q 'profile-compare-campaign: status=pass' /tmp/integration_profile_compare_campaign_lock_override_flag.log; then
  echo "expected pass status with --allow-concurrent override"
  cat /tmp/integration_profile_compare_campaign_lock_override_flag.log
  exit 1
fi

echo "[profile-compare-campaign] lock override env allows concurrent execution"
LOCK_REPORTS_ENV="$TMP_DIR/campaign_lock_reports_env"
LOCK_SUMMARY_ENV="$LOCK_REPORTS_ENV/campaign_lock_summary_env.json"
LOCK_DIR_ENV="$LOCK_REPORTS_ENV/.profile_compare_campaign.lock"
mkdir -p "$LOCK_REPORTS_ENV" "$LOCK_DIR_ENV"
cat >"$LOCK_DIR_ENV/owner" <<EOF_LOCK_ENV
pid=$$
start_utc=2026-04-16T00:00:01Z
scope=reports_dir
command=fake-lock-owner-env
EOF_LOCK_ENV

PROFILE_COMPARE_CAMPAIGN_ALLOW_CONCURRENT=1 \
PROFILE_COMPARE_CAMPAIGN_LOCAL_SCRIPT="$FAKE_LOCAL" \
PROFILE_COMPARE_CAMPAIGN_TREND_SCRIPT="$FAKE_TREND" \
FAKE_LOCAL_CAPTURE_FILE="$LOCAL_CAPTURE" \
FAKE_LOCAL_COUNTER_FILE="$LOCAL_COUNTER" \
FAKE_LOCAL_FAIL_AT=0 \
FAKE_TREND_CAPTURE_FILE="$TREND_CAPTURE" \
FAKE_TREND_FORCE_FAIL=0 \
FAKE_TREND_INCLUDE_SELECTION_POLICY=1 \
./scripts/profile_compare_campaign.sh \
  --campaign-runs 1 \
  --reports-dir "$LOCK_REPORTS_ENV" \
  --summary-json "$LOCK_SUMMARY_ENV" >/tmp/integration_profile_compare_campaign_lock_override_env.log 2>&1

if ! rg -q 'profile-compare-campaign: status=pass' /tmp/integration_profile_compare_campaign_lock_override_env.log; then
  echo "expected pass status with PROFILE_COMPARE_CAMPAIGN_ALLOW_CONCURRENT=1"
  cat /tmp/integration_profile_compare_campaign_lock_override_env.log
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
