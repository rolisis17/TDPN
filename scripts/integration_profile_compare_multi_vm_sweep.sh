#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp cat chmod grep sed timeout; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="$ROOT_DIR/scripts/profile_compare_multi_vm_sweep.sh"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

FAKE_VM_CAMPAIGN="$TMP_DIR/fake_vm_campaign.sh"
cat >"$FAKE_VM_CAMPAIGN" <<'EOF_FAKE_VM_CAMPAIGN'
#!/usr/bin/env bash
set -euo pipefail

summary_json=""
report_md=""
decision="${FAKE_VM_DECISION:-GO}"
recommended_profile="${FAKE_VM_RECOMMENDED_PROFILE:-balanced}"
support_rate_pct="${FAKE_VM_SUPPORT_RATE_PCT:-75.5}"
sleep_sec="${FAKE_VM_SLEEP_SEC:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --summary-json=*)
      summary_json="${1#*=}"
      shift
      ;;
    --report-md)
      report_md="${2:-}"
      shift 2
      ;;
    --report-md=*)
      report_md="${1#*=}"
      shift
      ;;
    --decision)
      decision="${2:-}"
      shift 2
      ;;
    --decision=*)
      decision="${1#*=}"
      shift
      ;;
    --recommended-profile)
      recommended_profile="${2:-}"
      shift 2
      ;;
    --recommended-profile=*)
      recommended_profile="${1#*=}"
      shift
      ;;
    --support-rate-pct)
      support_rate_pct="${2:-}"
      shift 2
      ;;
    --support-rate-pct=*)
      support_rate_pct="${1#*=}"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [[ "${FAKE_VM_SHOULD_FAIL:-0}" == "1" ]]; then
  echo "synthetic vm failure"
  exit "${FAKE_VM_FAIL_RC:-31}"
fi

if [[ "$sleep_sec" =~ ^[0-9]+$ ]] && (( sleep_sec > 0 )); then
  sleep "$sleep_sec"
fi

if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  jq -n \
    --arg decision "$decision" \
    --arg recommended_profile "$recommended_profile" \
    --argjson support_rate_pct "$support_rate_pct" \
    '{
      status: "ok",
      final_rc: 0,
      decision: {
        decision: $decision,
        recommended_profile: $recommended_profile,
        support_rate_pct: $support_rate_pct
      }
    }' >"$summary_json"
fi

if [[ -n "$report_md" ]]; then
  mkdir -p "$(dirname "$report_md")"
  printf '# fake vm report\n' >"$report_md"
fi

exit 0
EOF_FAKE_VM_CAMPAIGN
chmod +x "$FAKE_VM_CAMPAIGN"

echo "[profile-compare-multi-vm-sweep] success path with command file + redaction"
SUCCESS_REPORTS_DIR="$TMP_DIR/reports_success"
SUCCESS_SUMMARY="$TMP_DIR/success_summary.json"
SUCCESS_CANONICAL="$TMP_DIR/success_canonical_summary.json"
SUCCESS_REPORT_MD="$TMP_DIR/success_report.md"
SUCCESS_LOG="$TMP_DIR/success.log"
SUCCESS_COMMAND_FILE="$TMP_DIR/vm_commands_success.txt"

cat >"$SUCCESS_COMMAND_FILE" <<EOF_SUCCESS_COMMANDS
# vm specs
vm_a::FAKE_VM_SHOULD_FAIL=0 "$FAKE_VM_CAMPAIGN" --summary-json "$TMP_DIR/vm_a_summary.json" --report-md "$TMP_DIR/vm_a_report.md" --decision GO --recommended-profile balanced --support-rate-pct 80 --campaign-subject "super secret subject"
FAKE_VM_SHOULD_FAIL=0 "$FAKE_VM_CAMPAIGN" --summary-json "$TMP_DIR/vm_b_summary.json" --report-md "$TMP_DIR/vm_b_report.md" --decision NO-GO --recommended-profile private --support-rate-pct 62 --anon-cred "super secret cred"
EOF_SUCCESS_COMMANDS

set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$SUCCESS_REPORTS_DIR" \
  --summary-json "$SUCCESS_SUMMARY" \
  --canonical-summary-json "$SUCCESS_CANONICAL" \
  --report-md "$SUCCESS_REPORT_MD" \
  --command-timeout-sec 120 \
  --vm-command-file "$SUCCESS_COMMAND_FILE" \
  --print-summary-json 0 >"$SUCCESS_LOG" 2>&1
success_rc=$?
set -e

if [[ "$success_rc" -ne 0 ]]; then
  echo "expected success path rc=0, got rc=$success_rc"
  cat "$SUCCESS_LOG"
  exit 1
fi
if [[ ! -f "$SUCCESS_SUMMARY" || ! -f "$SUCCESS_CANONICAL" || ! -f "$SUCCESS_REPORT_MD" ]]; then
  echo "expected success artifacts to exist"
  ls -la "$TMP_DIR"
  exit 1
fi
if ! jq -e '
  .schema.id == "profile_compare_multi_vm_sweep_summary"
  and .status == "pass"
  and .rc == 0
  and .counts.vm_total == 2
  and .counts.vm_pass == 2
  and .counts.vm_fail == 0
  and .counts.vm_timeout == 0
  and .reducer_handoff.ready == true
  and .reducer_handoff.input_vm_count == 2
  and .reducer_handoff.decision_counts.GO == 1
  and .reducer_handoff.decision_counts["NO-GO"] == 1
  and (.reducer_handoff.input_summary_jsons | length) == 2
  and (.vms | length) == 2
' "$SUCCESS_SUMMARY" >/dev/null 2>&1; then
  echo "success summary missing expected fields"
  cat "$SUCCESS_SUMMARY"
  exit 1
fi
if grep -q 'super secret subject' "$SUCCESS_LOG" || grep -q 'super secret cred' "$SUCCESS_LOG"; then
  echo "expected credential-like values to be redacted in sweep logs"
  cat "$SUCCESS_LOG"
  exit 1
fi
if ! grep -q '\[redacted\]' "$SUCCESS_LOG"; then
  echo "expected redaction marker not found in sweep logs"
  cat "$SUCCESS_LOG"
  exit 1
fi

echo "[profile-compare-multi-vm-sweep] quoted summary/report paths with spaces are handled"
QUOTED_REPORTS_DIR="$TMP_DIR/reports_quoted"
QUOTED_SUMMARY="$TMP_DIR/quoted_summary.json"
QUOTED_LOG="$TMP_DIR/quoted.log"
QUOTED_SUMMARY_PATH="$TMP_DIR/vm dir with spaces/vm summary.json"
QUOTED_REPORT_PATH="$TMP_DIR/vm dir with spaces/vm report.md"

set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$QUOTED_REPORTS_DIR" \
  --summary-json "$QUOTED_SUMMARY" \
  --command-timeout-sec 120 \
  --vm-command "vm_quoted::FAKE_VM_SHOULD_FAIL=0 \"$FAKE_VM_CAMPAIGN\" --summary-json \"$QUOTED_SUMMARY_PATH\" --report-md \"$QUOTED_REPORT_PATH\" --decision GO --recommended-profile balanced --support-rate-pct 77" \
  --print-summary-json 0 >"$QUOTED_LOG" 2>&1
quoted_rc=$?
set -e

if [[ "$quoted_rc" -ne 0 ]]; then
  echo "expected quoted-path sweep rc=0, got rc=$quoted_rc"
  cat "$QUOTED_LOG"
  exit 1
fi
if ! jq -e --arg summary "$QUOTED_SUMMARY_PATH" --arg report "$QUOTED_REPORT_PATH" '
  .status == "pass"
  and .rc == 0
  and .counts.vm_total == 1
  and .counts.vm_pass == 1
  and (.vms[0].artifacts.summary_json == $summary)
  and (.vms[0].artifacts.report_md == $report)
  and (.vms[0].artifacts.summary_exists == true)
  and (.vms[0].artifacts.report_exists == true)
' "$QUOTED_SUMMARY" >/dev/null 2>&1; then
  echo "quoted-path sweep summary missing expected artifacts"
  cat "$QUOTED_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-sweep] stale pre-existing artifacts fail closed"
STALE_SUMMARY="$TMP_DIR/stale_summary.json"
STALE_LOG="$TMP_DIR/stale.log"
STALE_CAMPAIGN_SUMMARY_PATH="$TMP_DIR/stale artifacts/stale campaign summary.json"
STALE_CAMPAIGN_REPORT_PATH="$TMP_DIR/stale artifacts/stale campaign report.md"
mkdir -p "$(dirname "$STALE_CAMPAIGN_SUMMARY_PATH")"
printf '{"status":"ok","decision":{"decision":"GO","recommended_profile":"balanced","support_rate_pct":99}}' >"$STALE_CAMPAIGN_SUMMARY_PATH"
printf '# stale report\n' >"$STALE_CAMPAIGN_REPORT_PATH"

set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/reports_stale" \
  --summary-json "$STALE_SUMMARY" \
  --command-timeout-sec 120 \
  --vm-command "vm_stale::bash -lc \"exit 0\" --summary-json \"$STALE_CAMPAIGN_SUMMARY_PATH\" --report-md \"$STALE_CAMPAIGN_REPORT_PATH\"" \
  --print-summary-json 0 >"$STALE_LOG" 2>&1
stale_rc=$?
set -e

if [[ "$stale_rc" -ne 1 ]]; then
  echo "expected stale-artifact path rc=1, got rc=$stale_rc"
  cat "$STALE_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .counts.vm_fail == 1
  and .vms[0].failure_reason == "summary_json_not_fresh"
  and .vms[0].artifacts.summary_exists == true
  and .vms[0].artifacts.summary_fresh == false
' "$STALE_SUMMARY" >/dev/null 2>&1; then
  echo "stale-artifact summary missing expected fail-closed fields"
  cat "$STALE_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-sweep] malformed vm spec fails closed"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/reports_malformed_spec" \
  --summary-json "$TMP_DIR/malformed_spec_summary.json" \
  --vm-command "vm_only::" \
  --print-summary-json 0 >"$TMP_DIR/malformed_spec.log" 2>&1
malformed_spec_rc=$?
set -e
if [[ "$malformed_spec_rc" -ne 2 ]]; then
  echo "expected malformed vm spec rc=2, got rc=$malformed_spec_rc"
  cat "$TMP_DIR/malformed_spec.log"
  exit 1
fi
if ! grep -q 'malformed vm spec' "$TMP_DIR/malformed_spec.log"; then
  echo "expected malformed vm spec message not found"
  cat "$TMP_DIR/malformed_spec.log"
  exit 1
fi

echo "[profile-compare-multi-vm-sweep] malformed shell command fails closed"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/reports_malformed_cmd" \
  --summary-json "$TMP_DIR/malformed_cmd_summary.json" \
  --vm-command "vm_bad::echo 'unterminated" \
  --print-summary-json 0 >"$TMP_DIR/malformed_cmd.log" 2>&1
malformed_cmd_rc=$?
set -e
if [[ "$malformed_cmd_rc" -ne 2 ]]; then
  echo "expected malformed shell command rc=2, got rc=$malformed_cmd_rc"
  cat "$TMP_DIR/malformed_cmd.log"
  exit 1
fi
if ! grep -q 'malformed shell command' "$TMP_DIR/malformed_cmd.log"; then
  echo "expected malformed command message not found"
  cat "$TMP_DIR/malformed_cmd.log"
  exit 1
fi

echo "[profile-compare-multi-vm-sweep] timeout + partial mode"
PARTIAL_REPORTS_DIR="$TMP_DIR/reports_partial"
PARTIAL_SUMMARY="$TMP_DIR/partial_summary.json"
PARTIAL_CANONICAL="$TMP_DIR/partial_canonical_summary.json"
PARTIAL_REPORT_MD="$TMP_DIR/partial_report.md"
PARTIAL_LOG="$TMP_DIR/partial.log"

set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$PARTIAL_REPORTS_DIR" \
  --summary-json "$PARTIAL_SUMMARY" \
  --canonical-summary-json "$PARTIAL_CANONICAL" \
  --report-md "$PARTIAL_REPORT_MD" \
  --command-timeout-sec 1 \
  --allow-partial 1 \
  --reducer-min-successful-vms 1 \
  --vm-command "vm_timeout::FAKE_VM_SLEEP_SEC=3 \"$FAKE_VM_CAMPAIGN\" --summary-json \"$TMP_DIR/vm_timeout_summary.json\" --report-md \"$TMP_DIR/vm_timeout_report.md\"" \
  --vm-command "vm_ok::FAKE_VM_SHOULD_FAIL=0 \"$FAKE_VM_CAMPAIGN\" --summary-json \"$TMP_DIR/vm_ok_summary.json\" --report-md \"$TMP_DIR/vm_ok_report.md\" --decision GO --recommended-profile balanced --support-rate-pct 74" \
  --print-summary-json 0 >"$PARTIAL_LOG" 2>&1
partial_rc=$?
set -e

if [[ "$partial_rc" -ne 0 ]]; then
  echo "expected partial mode rc=0, got rc=$partial_rc"
  cat "$PARTIAL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .counts.vm_total == 2
  and .counts.vm_timeout == 1
  and .counts.vm_pass == 1
  and .reducer_handoff.ready == true
  and .reducer_handoff.input_vm_count == 1
' "$PARTIAL_SUMMARY" >/dev/null 2>&1; then
  echo "partial summary missing expected timeout/partial fields"
  cat "$PARTIAL_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-sweep] fail-closed default mode"
FAIL_CLOSED_SUMMARY="$TMP_DIR/fail_closed_summary.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/reports_fail_closed" \
  --summary-json "$FAIL_CLOSED_SUMMARY" \
  --vm-command "vm_good::FAKE_VM_SHOULD_FAIL=0 \"$FAKE_VM_CAMPAIGN\" --summary-json \"$TMP_DIR/vm_good_summary.json\" --report-md \"$TMP_DIR/vm_good_report.md\"" \
  --vm-command "vm_bad::FAKE_VM_SHOULD_FAIL=1 \"$FAKE_VM_CAMPAIGN\" --summary-json \"$TMP_DIR/vm_bad_summary.json\" --report-md \"$TMP_DIR/vm_bad_report.md\"" \
  --print-summary-json 0 >"$TMP_DIR/fail_closed.log" 2>&1
fail_closed_rc=$?
set -e
if [[ "$fail_closed_rc" -ne 1 ]]; then
  echo "expected fail-closed rc=1, got rc=$fail_closed_rc"
  cat "$TMP_DIR/fail_closed.log"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .counts.vm_fail == 1
' "$FAIL_CLOSED_SUMMARY" >/dev/null 2>&1; then
  echo "fail-closed summary missing expected fields"
  cat "$FAIL_CLOSED_SUMMARY"
  exit 1
fi

echo "integration_profile_compare_multi_vm_sweep: PASS"
