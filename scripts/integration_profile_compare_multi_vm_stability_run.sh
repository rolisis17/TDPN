#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp cat grep timeout wc sed; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/profile_compare_multi_vm_stability_run.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

FAKE_CYCLE="$TMP_DIR/fake_cycle.sh"
cat >"$FAKE_CYCLE" <<'EOF_FAKE_CYCLE'
#!/usr/bin/env bash
set -euo pipefail

counter_file="${FAKE_CYCLE_COUNTER_FILE:?}"
scenario="${FAKE_CYCLE_SCENARIO:-stable}"
capture_file="${FAKE_CYCLE_CAPTURE_FILE:-}"
sleep_sec="${FAKE_CYCLE_SLEEP_SEC:-0}"

summary_json=""
reports_dir=""
sweep_timeout=""
vm_cmd_count=0
vm_cmd_file_count=0

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
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --reports-dir=*)
      reports_dir="${1#*=}"
      shift
      ;;
    --sweep-command-timeout-sec)
      sweep_timeout="${2:-}"
      shift 2
      ;;
    --sweep-command-timeout-sec=*)
      sweep_timeout="${1#*=}"
      shift
      ;;
    --vm-command)
      vm_cmd_count=$((vm_cmd_count + 1))
      shift 2
      ;;
    --vm-command=*)
      vm_cmd_count=$((vm_cmd_count + 1))
      shift
      ;;
    --vm-command-file)
      vm_cmd_file_count=$((vm_cmd_file_count + 1))
      shift 2
      ;;
    --vm-command-file=*)
      vm_cmd_file_count=$((vm_cmd_file_count + 1))
      shift
      ;;
    --show-json|--print-summary-json|--fail-on-no-go)
      if [[ $# -ge 2 && "$2" != --* ]]; then
        shift 2
      else
        shift
      fi
      ;;
    *)
      if [[ "$1" == --*=* ]]; then
        shift
      elif [[ $# -ge 2 && "$2" != --* ]]; then
        shift 2
      else
        shift
      fi
      ;;
  esac
done

if [[ -z "$summary_json" ]]; then
  echo "fake_cycle requires --summary-json" >&2
  exit 2
fi
if [[ -z "$reports_dir" ]]; then
  reports_dir="$(dirname "$summary_json")"
fi

run_index=0
if [[ -f "$counter_file" ]]; then
  run_index="$(cat "$counter_file" 2>/dev/null || echo "0")"
fi
if ! [[ "$run_index" =~ ^[0-9]+$ ]]; then
  run_index="0"
fi
run_index=$((run_index + 1))
printf '%s' "$run_index" >"$counter_file"

if [[ "$sleep_sec" =~ ^[0-9]+$ ]] && (( sleep_sec > 0 )); then
  sleep "$sleep_sec"
fi

status="pass"
decision="GO"
profile="balanced"
support="82"
rc=0

case "$scenario" in
  stable)
    status="pass"
    decision="GO"
    profile="balanced"
    support="82"
    rc=0
    ;;
  partial)
    if (( run_index == 1 )); then
      status="pass"
      decision="GO"
      profile="balanced"
      support="82"
      rc=0
    elif (( run_index == 2 )); then
      status="fail"
      decision="NO-GO"
      profile="private"
      support="44"
      rc=1
    else
      status="warn"
      decision="GO"
      profile="balanced"
      support="71"
      rc=0
    fi
    ;;
  fail_closed)
    if (( run_index == 1 )); then
      status="fail"
      decision="NO-GO"
      profile="private"
      support="35"
      rc=1
    else
      status="pass"
      decision="GO"
      profile="balanced"
      support="80"
      rc=0
    fi
    ;;
  split_decision)
    if (( run_index == 1 )); then
      status="pass"
      decision="GO"
      profile="balanced"
      support="80"
      rc=0
    else
      status="pass"
      decision="NO-GO"
      profile="private"
      support="20"
      rc=0
    fi
    ;;
  *)
    echo "unsupported fake scenario: $scenario" >&2
    exit 2
    ;;
esac

mkdir -p "$(dirname "$summary_json")" "$reports_dir"
report_md="$reports_dir/fake_cycle_report_run_${run_index}.md"
printf '# fake cycle report run %s\n' "$run_index" >"$report_md"

jq -n \
  --arg status "$status" \
  --arg decision "$decision" \
  --arg profile "$profile" \
  --argjson support "$support" \
  --arg summary_json "$summary_json" \
  --arg report_md "$report_md" \
  --argjson rc "$rc" \
  '{
    version: 1,
    schema: { id: "profile_compare_multi_vm_cycle_summary" },
    status: $status,
    rc: $rc,
    decision: $decision,
    reducer: {
      status: $status,
      decision: $decision,
      recommended_profile: $profile,
      support_rate_pct: $support
    },
    check: {
      status: (if $decision == "GO" then "ok" else "fail" end),
      decision: $decision,
      recommended_profile: $profile,
      recommendation_support_rate_pct: $support
    },
    artifacts: {
      summary_json: $summary_json,
      report_md: $report_md
    }
  }' >"$summary_json"

if [[ -n "$capture_file" ]]; then
  printf 'run=%s scenario=%s vm_cmd=%s vm_cmd_file=%s sweep_timeout=%s reports_dir=%s summary_json=%s\n' \
    "$run_index" "$scenario" "$vm_cmd_count" "$vm_cmd_file_count" "${sweep_timeout:-}" "$reports_dir" "$summary_json" >>"$capture_file"
fi

exit "$rc"
EOF_FAKE_CYCLE
chmod +x "$FAKE_CYCLE"

echo "[profile-compare-multi-vm-stability-run] happy path"
HAPPY_REPORTS_DIR="$TMP_DIR/reports_happy"
HAPPY_SUMMARY="$TMP_DIR/happy_summary.json"
HAPPY_CANONICAL="$TMP_DIR/happy_canonical_summary.json"
HAPPY_REPORT_MD="$TMP_DIR/happy_report.md"
HAPPY_COUNTER="$TMP_DIR/happy_counter.txt"
HAPPY_CAPTURE="$TMP_DIR/happy_capture.log"
VM_COMMAND_FILE="$TMP_DIR/vm_commands.txt"
printf 'vm_b::echo vm-b\n' >"$VM_COMMAND_FILE"

set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CYCLE_SCRIPT="$FAKE_CYCLE" \
FAKE_CYCLE_COUNTER_FILE="$HAPPY_COUNTER" \
FAKE_CYCLE_SCENARIO="stable" \
FAKE_CYCLE_CAPTURE_FILE="$HAPPY_CAPTURE" \
bash "$SCRIPT_UNDER_TEST" \
  --runs 3 \
  --sleep-between-sec 0 \
  --reports-dir "$HAPPY_REPORTS_DIR" \
  --summary-json "$HAPPY_SUMMARY" \
  --canonical-summary-json "$HAPPY_CANONICAL" \
  --report-md "$HAPPY_REPORT_MD" \
  --cycle-timeout-sec 30 \
  --sweep-command-timeout-sec 55 \
  --vm-command "vm_a::echo vm-a" \
  --vm-command-file "$VM_COMMAND_FILE" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_run_happy.log 2>&1
happy_rc=$?
set -e

if [[ "$happy_rc" -ne 0 ]]; then
  echo "expected happy path rc=0, got rc=$happy_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_happy.log
  exit 1
fi
if [[ ! -f "$HAPPY_SUMMARY" || ! -f "$HAPPY_CANONICAL" || ! -f "$HAPPY_REPORT_MD" ]]; then
  echo "expected happy artifacts to exist"
  ls -la "$TMP_DIR"
  exit 1
fi
if ! jq -e '
  .schema.id == "profile_compare_multi_vm_stability_run_summary"
  and .status == "pass"
  and .rc == 0
  and .counts.requested == 3
  and .counts.completed == 3
  and .counts.pass == 3
  and .counts.warn == 0
  and .counts.fail == 0
  and .modal.decision == "GO"
  and .modal.recommended_profile == "balanced"
  and .modal.support_rate_pct == 82
  and (.runs | length) == 3
  and (.artifacts.run_dirs | length) == 3
' "$HAPPY_SUMMARY" >/dev/null 2>&1; then
  echo "happy summary missing expected fields"
  cat "$HAPPY_SUMMARY"
  exit 1
fi
if [[ "$(wc -l <"$HAPPY_CAPTURE" | tr -d ' ')" != "3" ]]; then
  echo "expected fake cycle to run 3 times"
  cat "$HAPPY_CAPTURE"
  exit 1
fi
if ! grep -q 'vm_cmd=1 vm_cmd_file=1 sweep_timeout=55' "$HAPPY_CAPTURE"; then
  echo "expected vm-command/vm-command-file + sweep timeout pass-through missing"
  cat "$HAPPY_CAPTURE"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-run] partial mode thresholds met"
PARTIAL_SUMMARY="$TMP_DIR/partial_summary.json"
PARTIAL_COUNTER="$TMP_DIR/partial_counter.txt"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CYCLE_SCRIPT="$FAKE_CYCLE" \
FAKE_CYCLE_COUNTER_FILE="$PARTIAL_COUNTER" \
FAKE_CYCLE_SCENARIO="partial" \
bash "$SCRIPT_UNDER_TEST" \
  --runs 3 \
  --sleep-between-sec 0 \
  --allow-partial 1 \
  --min-completed-runs 2 \
  --min-pass-runs 1 \
  --reports-dir "$TMP_DIR/reports_partial" \
  --summary-json "$PARTIAL_SUMMARY" \
  --vm-command "vm_a::echo vm-a" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_run_partial.log 2>&1
partial_rc=$?
set -e

if [[ "$partial_rc" -ne 0 ]]; then
  echo "expected partial mode rc=0, got rc=$partial_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_partial.log
  exit 1
fi
if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .counts.requested == 3
  and .counts.completed == 3
  and .counts.pass == 1
  and .counts.warn == 1
  and .counts.fail == 1
  and .modal.decision == "GO"
  and .modal.recommended_profile == "balanced"
' "$PARTIAL_SUMMARY" >/dev/null 2>&1; then
  echo "partial summary missing expected fields"
  cat "$PARTIAL_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-run] split decision fail-closed safety"
SPLIT_SUMMARY="$TMP_DIR/split_summary.json"
SPLIT_COUNTER="$TMP_DIR/split_counter.txt"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CYCLE_SCRIPT="$FAKE_CYCLE" \
FAKE_CYCLE_COUNTER_FILE="$SPLIT_COUNTER" \
FAKE_CYCLE_SCENARIO="split_decision" \
bash "$SCRIPT_UNDER_TEST" \
  --runs 2 \
  --sleep-between-sec 0 \
  --reports-dir "$TMP_DIR/reports_split" \
  --summary-json "$SPLIT_SUMMARY" \
  --vm-command "vm_a::echo vm-a" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_run_split.log 2>&1
split_rc=$?
set -e

if [[ "$split_rc" -eq 0 ]]; then
  echo "expected split-decision run rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_split.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .decision == "NO-GO"
  and .decision_consensus == false
  and .decision_split_detected == true
  and .modal.decision == "NO-GO"
  and .modal.decision_tie_break == "prefer_no_go"
  and .histograms.decision_counts == {"GO":1,"NO-GO":1}
' "$SPLIT_SUMMARY" >/dev/null 2>&1; then
  echo "split summary missing fail-closed tie-break fields"
  cat "$SPLIT_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-run] fail-closed default"
FAIL_SUMMARY="$TMP_DIR/fail_summary.json"
FAIL_COUNTER="$TMP_DIR/fail_counter.txt"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CYCLE_SCRIPT="$FAKE_CYCLE" \
FAKE_CYCLE_COUNTER_FILE="$FAIL_COUNTER" \
FAKE_CYCLE_SCENARIO="fail_closed" \
bash "$SCRIPT_UNDER_TEST" \
  --runs 2 \
  --sleep-between-sec 0 \
  --reports-dir "$TMP_DIR/reports_fail" \
  --summary-json "$FAIL_SUMMARY" \
  --vm-command "vm_a::echo vm-a" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_run_fail.log 2>&1
fail_rc=$?
set -e

if [[ "$fail_rc" -eq 0 ]]; then
  echo "expected fail-closed rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_fail.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .counts.fail >= 1
' "$FAIL_SUMMARY" >/dev/null 2>&1; then
  echo "fail-closed summary missing expected fields"
  cat "$FAIL_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-run] per-run timeout path"
TIMEOUT_SUMMARY="$TMP_DIR/timeout_summary.json"
TIMEOUT_COUNTER="$TMP_DIR/timeout_counter.txt"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CYCLE_SCRIPT="$FAKE_CYCLE" \
FAKE_CYCLE_COUNTER_FILE="$TIMEOUT_COUNTER" \
FAKE_CYCLE_SCENARIO="stable" \
FAKE_CYCLE_SLEEP_SEC=2 \
bash "$SCRIPT_UNDER_TEST" \
  --runs 1 \
  --sleep-between-sec 0 \
  --cycle-timeout-sec 1 \
  --reports-dir "$TMP_DIR/reports_timeout" \
  --summary-json "$TIMEOUT_SUMMARY" \
  --vm-command "vm_a::echo vm-a" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_run_timeout.log 2>&1
timeout_rc=$?
set -e

if [[ "$timeout_rc" -eq 0 ]]; then
  echo "expected timeout run rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_timeout.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .counts.timeout == 1
  and .counts.fail == 1
  and .runs[0].timed_out == true
  and .runs[0].failure_reason == "cycle_timeout"
' "$TIMEOUT_SUMMARY" >/dev/null 2>&1; then
  echo "timeout summary missing expected fields"
  cat "$TIMEOUT_SUMMARY"
  exit 1
fi

echo "integration_profile_compare_multi_vm_stability_run: PASS"
