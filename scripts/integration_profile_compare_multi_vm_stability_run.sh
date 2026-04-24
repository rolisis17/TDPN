#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Keep fallback discovery checks hermetic from ambient environment.
unset PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CYCLE_SCRIPT || true
unset PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_RUNS || true
unset PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_SLEEP_BETWEEN_SEC || true
unset PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_ALLOW_PARTIAL || true
unset PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_MIN_COMPLETED_RUNS || true
unset PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_MIN_PASS_RUNS || true
unset PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_REPORTS_DIR || true
unset PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_SUMMARY_JSON || true
unset PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CANONICAL_SUMMARY_JSON || true
unset PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_REPORT_MD || true
unset PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CYCLE_TIMEOUT_SEC || true
unset PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_SWEEP_COMMAND_TIMEOUT_SEC || true
unset PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_SHOW_JSON || true
unset PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_PRINT_SUMMARY_JSON || true
unset PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_VM_COMMAND_FILE || true
unset PROFILE_COMPARE_MULTI_VM_STABILITY_VM_COMMAND_FILE || true
unset PROFILE_COMPARE_MULTI_VM_VM_COMMAND_FILE || true

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
schema_id="profile_compare_multi_vm_cycle_summary"

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
  warn_rc_nonzero)
    status="warn"
    decision="GO"
    profile="balanced"
    support="74"
    rc=23
    ;;
  schema_mismatch)
    status="pass"
    decision="GO"
    profile="balanced"
    support="82"
    rc=0
    schema_id="runtime_actuation_multi_vm_cycle_summary"
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
  --arg schema_id "$schema_id" \
  --arg summary_json "$summary_json" \
  --arg report_md "$report_md" \
  --argjson rc "$rc" \
  '{
    version: 1,
    schema: { id: $schema_id },
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

echo "[profile-compare-multi-vm-stability-run] duplicate --vm-command-file paths are collapsed before cycle handoff"
DUPLICATE_FILE_REPORTS_DIR="$TMP_DIR/reports_duplicate_file"
DUPLICATE_FILE_SUMMARY="$TMP_DIR/duplicate_file_summary.json"
DUPLICATE_FILE_COUNTER="$TMP_DIR/duplicate_file_counter.txt"
DUPLICATE_FILE_CAPTURE="$TMP_DIR/duplicate_file_capture.log"
DUPLICATE_FILE_PATH="$TMP_DIR/vm_commands_duplicate_file.txt"
printf 'vm_dup_path::echo vm-dup-path\n' >"$DUPLICATE_FILE_PATH"

set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CYCLE_SCRIPT="$FAKE_CYCLE" \
FAKE_CYCLE_COUNTER_FILE="$DUPLICATE_FILE_COUNTER" \
FAKE_CYCLE_SCENARIO="stable" \
FAKE_CYCLE_CAPTURE_FILE="$DUPLICATE_FILE_CAPTURE" \
bash "$SCRIPT_UNDER_TEST" \
  --runs 1 \
  --sleep-between-sec 0 \
  --reports-dir "$DUPLICATE_FILE_REPORTS_DIR" \
  --summary-json "$DUPLICATE_FILE_SUMMARY" \
  --vm-command-file "$DUPLICATE_FILE_PATH" \
  --vm-command-file "$DUPLICATE_FILE_PATH" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_run_duplicate_file.log 2>&1
duplicate_file_rc=$?
set -e

if [[ "$duplicate_file_rc" -ne 0 ]]; then
  echo "expected duplicate vm-command-file path to remain runnable, got rc=$duplicate_file_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_duplicate_file.log
  exit 1
fi
if ! grep -q 'vm_cmd=0 vm_cmd_file=1' "$DUPLICATE_FILE_CAPTURE"; then
  echo "expected duplicate vm-command-file path to be collapsed before cycle"
  cat "$DUPLICATE_FILE_CAPTURE"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.vm_command_count == 0
  and .inputs.vm_command_file_count == 1
  and .inputs.vm_command_fallback_used == false
  and (.inputs.vm_command_preflight_diagnostics | type) == "array"
  and (.inputs.vm_command_preflight_diagnostics | map(test("duplicate_path_skipped")) | any)
' "$DUPLICATE_FILE_SUMMARY" >/dev/null 2>&1; then
  echo "duplicate vm-command-file summary missing dedupe metadata"
  cat "$DUPLICATE_FILE_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-run] fallback command-file discovery from reports-dir artifact"
FALLBACK_REPORTS_DIR="$TMP_DIR/reports_fallback"
FALLBACK_SUMMARY="$TMP_DIR/fallback_summary.json"
FALLBACK_COUNTER="$TMP_DIR/fallback_counter.txt"
FALLBACK_CAPTURE="$TMP_DIR/fallback_capture.log"
mkdir -p "$FALLBACK_REPORTS_DIR"
printf 'vm_fb::echo vm-fallback\n' >"$FALLBACK_REPORTS_DIR/profile_compare_multi_vm_stability_vm_commands.txt"

set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CYCLE_SCRIPT="$FAKE_CYCLE" \
FAKE_CYCLE_COUNTER_FILE="$FALLBACK_COUNTER" \
FAKE_CYCLE_SCENARIO="stable" \
FAKE_CYCLE_CAPTURE_FILE="$FALLBACK_CAPTURE" \
bash "$SCRIPT_UNDER_TEST" \
  --runs 1 \
  --sleep-between-sec 0 \
  --reports-dir "$FALLBACK_REPORTS_DIR" \
  --summary-json "$FALLBACK_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_run_fallback.log 2>&1
fallback_rc=$?
set -e

if [[ "$fallback_rc" -ne 0 ]]; then
  echo "expected fallback-discovery path rc=0, got rc=$fallback_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_fallback.log
  exit 1
fi
if ! grep -q 'vm_cmd=0 vm_cmd_file=1' "$FALLBACK_CAPTURE"; then
  echo "expected fallback command-file forwarding to cycle"
  cat "$FALLBACK_CAPTURE"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.vm_command_count == 0
  and .inputs.vm_command_file_count == 1
  and .inputs.vm_command_fallback_used == true
  and .inputs.vm_command_fallback_source == "reports-dir-canonical"
  and ((.inputs.vm_command_fallback_file // "") | test("profile_compare_multi_vm_stability_vm_commands\\.txt$"))
  and (.inputs.vm_command_fallback_diagnostics | type) == "array"
  and (.inputs.vm_command_fallback_diagnostics | map(test("source=reports-dir-canonical")) | any)
  and (.inputs.vm_command_preflight_diagnostics | type) == "array"
  and (.inputs.vm_command_preflight_diagnostics | map(test("result=ready")) | any)
' "$FALLBACK_SUMMARY" >/dev/null 2>&1; then
  echo "fallback summary missing expected metadata"
  cat "$FALLBACK_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-run] invalid env fallback does not block reports-dir fallback"
ENV_INVALID_FALLBACK_REPORTS_DIR="$TMP_DIR/reports_env_invalid_fallback"
ENV_INVALID_FALLBACK_SUMMARY="$TMP_DIR/env_invalid_fallback_summary.json"
ENV_INVALID_FALLBACK_COUNTER="$TMP_DIR/env_invalid_fallback_counter.txt"
ENV_INVALID_FALLBACK_CAPTURE="$TMP_DIR/env_invalid_fallback_capture.log"
mkdir -p "$ENV_INVALID_FALLBACK_REPORTS_DIR"
printf 'vm_env_fb::echo vm-env-fallback\n' >"$ENV_INVALID_FALLBACK_REPORTS_DIR/profile_compare_multi_vm_stability_vm_commands.txt"

set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_VM_COMMAND_FILE="$TMP_DIR/does_not_exist_vm_commands.txt" \
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CYCLE_SCRIPT="$FAKE_CYCLE" \
FAKE_CYCLE_COUNTER_FILE="$ENV_INVALID_FALLBACK_COUNTER" \
FAKE_CYCLE_SCENARIO="stable" \
FAKE_CYCLE_CAPTURE_FILE="$ENV_INVALID_FALLBACK_CAPTURE" \
bash "$SCRIPT_UNDER_TEST" \
  --runs 1 \
  --sleep-between-sec 0 \
  --reports-dir "$ENV_INVALID_FALLBACK_REPORTS_DIR" \
  --summary-json "$ENV_INVALID_FALLBACK_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_run_env_invalid_fallback.log 2>&1
env_invalid_fallback_rc=$?
set -e

if [[ "$env_invalid_fallback_rc" -ne 0 ]]; then
  echo "expected env-invalid fallback path rc=0, got rc=$env_invalid_fallback_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_env_invalid_fallback.log
  exit 1
fi
if ! grep -q 'vm_cmd=0 vm_cmd_file=1' "$ENV_INVALID_FALLBACK_CAPTURE"; then
  echo "expected env-invalid fallback to still forward reports-dir vm-command-file"
  cat "$ENV_INVALID_FALLBACK_CAPTURE"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.vm_command_fallback_used == true
  and .inputs.vm_command_fallback_source == "reports-dir-canonical"
  and ((.inputs.vm_command_fallback_file // "") | test("profile_compare_multi_vm_stability_vm_commands\\.txt$"))
' "$ENV_INVALID_FALLBACK_SUMMARY" >/dev/null 2>&1; then
  echo "env-invalid fallback summary missing expected diagnostics/source"
  cat "$ENV_INVALID_FALLBACK_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-run] reports-dir canonical fallback takes precedence over env fallback"
REPORTS_CANONICAL_PRECEDENCE_REPORTS_DIR="$TMP_DIR/reports_canonical_precedence"
REPORTS_CANONICAL_PRECEDENCE_SUMMARY="$TMP_DIR/reports_canonical_precedence_summary.json"
REPORTS_CANONICAL_PRECEDENCE_COUNTER="$TMP_DIR/reports_canonical_precedence_counter.txt"
REPORTS_CANONICAL_PRECEDENCE_CAPTURE="$TMP_DIR/reports_canonical_precedence_capture.log"
REPORTS_CANONICAL_PRECEDENCE_ENV_FILE="$TMP_DIR/vm_commands_env_precedence.txt"
mkdir -p "$REPORTS_CANONICAL_PRECEDENCE_REPORTS_DIR"
printf 'vm_reports_canonical::echo vm-reports-canonical\n' >"$REPORTS_CANONICAL_PRECEDENCE_REPORTS_DIR/profile_compare_multi_vm_stability_vm_commands.txt"
printf 'vm_env_precedence::echo vm-env-precedence\n' >"$REPORTS_CANONICAL_PRECEDENCE_ENV_FILE"

set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_VM_COMMAND_FILE="$REPORTS_CANONICAL_PRECEDENCE_ENV_FILE" \
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CYCLE_SCRIPT="$FAKE_CYCLE" \
FAKE_CYCLE_COUNTER_FILE="$REPORTS_CANONICAL_PRECEDENCE_COUNTER" \
FAKE_CYCLE_SCENARIO="stable" \
FAKE_CYCLE_CAPTURE_FILE="$REPORTS_CANONICAL_PRECEDENCE_CAPTURE" \
bash "$SCRIPT_UNDER_TEST" \
  --runs 1 \
  --sleep-between-sec 0 \
  --reports-dir "$REPORTS_CANONICAL_PRECEDENCE_REPORTS_DIR" \
  --summary-json "$REPORTS_CANONICAL_PRECEDENCE_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_run_reports_canonical_precedence.log 2>&1
reports_canonical_precedence_rc=$?
set -e

if [[ "$reports_canonical_precedence_rc" -ne 0 ]]; then
  echo "expected reports-canonical precedence path rc=0, got rc=$reports_canonical_precedence_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_reports_canonical_precedence.log
  exit 1
fi
if ! grep -q 'vm_cmd=0 vm_cmd_file=1' "$REPORTS_CANONICAL_PRECEDENCE_CAPTURE"; then
  echo "expected reports-canonical precedence to forward one vm-command-file"
  cat "$REPORTS_CANONICAL_PRECEDENCE_CAPTURE"
  exit 1
fi
if ! jq -e --arg canonical "$REPORTS_CANONICAL_PRECEDENCE_REPORTS_DIR/profile_compare_multi_vm_stability_vm_commands.txt" '
  .status == "pass"
  and .rc == 0
  and .inputs.vm_command_fallback_used == true
  and .inputs.vm_command_fallback_source == "reports-dir-canonical"
  and .inputs.vm_command_fallback_file == $canonical
' "$REPORTS_CANONICAL_PRECEDENCE_SUMMARY" >/dev/null 2>&1; then
  echo "reports-canonical precedence summary missing expected fallback metadata"
  cat "$REPORTS_CANONICAL_PRECEDENCE_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-run] canonical env fallback precedence over alias envs"
ENV_PRIORITY_REPORTS_DIR="$TMP_DIR/reports_env_priority"
ENV_PRIORITY_SUMMARY="$TMP_DIR/env_priority_summary.json"
ENV_PRIORITY_COUNTER="$TMP_DIR/env_priority_counter.txt"
ENV_PRIORITY_CAPTURE="$TMP_DIR/env_priority_capture.log"
ENV_PRIORITY_CANONICAL_FILE="$TMP_DIR/vm_commands_env_canonical.txt"
ENV_PRIORITY_ALIAS_FILE="$TMP_DIR/vm_commands_env_alias.txt"
printf 'vm_env_canonical::echo vm-env-canonical\n' >"$ENV_PRIORITY_CANONICAL_FILE"
printf 'vm_env_alias::echo vm-env-alias\n' >"$ENV_PRIORITY_ALIAS_FILE"

set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_VM_COMMAND_FILE="$ENV_PRIORITY_CANONICAL_FILE" \
PROFILE_COMPARE_MULTI_VM_STABILITY_VM_COMMAND_FILE="$ENV_PRIORITY_ALIAS_FILE" \
PROFILE_COMPARE_MULTI_VM_VM_COMMAND_FILE="$TMP_DIR/vm_commands_env_legacy_unused.txt" \
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CYCLE_SCRIPT="$FAKE_CYCLE" \
FAKE_CYCLE_COUNTER_FILE="$ENV_PRIORITY_COUNTER" \
FAKE_CYCLE_SCENARIO="stable" \
FAKE_CYCLE_CAPTURE_FILE="$ENV_PRIORITY_CAPTURE" \
bash "$SCRIPT_UNDER_TEST" \
  --runs 1 \
  --sleep-between-sec 0 \
  --reports-dir "$ENV_PRIORITY_REPORTS_DIR" \
  --summary-json "$ENV_PRIORITY_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_run_env_priority.log 2>&1
env_priority_rc=$?
set -e

if [[ "$env_priority_rc" -ne 0 ]]; then
  echo "expected env-priority fallback path rc=0, got rc=$env_priority_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_env_priority.log
  exit 1
fi
if ! grep -q 'vm_cmd=0 vm_cmd_file=1' "$ENV_PRIORITY_CAPTURE"; then
  echo "expected canonical env fallback to forward one vm-command-file"
  cat "$ENV_PRIORITY_CAPTURE"
  exit 1
fi
if ! jq -e --arg canonical "$ENV_PRIORITY_CANONICAL_FILE" '
  .status == "pass"
  and .rc == 0
  and .inputs.vm_command_fallback_used == true
  and .inputs.vm_command_fallback_source == "env:PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_VM_COMMAND_FILE"
  and .inputs.vm_command_fallback_file == $canonical
' "$ENV_PRIORITY_SUMMARY" >/dev/null 2>&1; then
  echo "env-priority fallback summary missing canonical ordering metadata"
  cat "$ENV_PRIORITY_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-run] fallback missing remains fail-closed with operator diagnostics"
MISSING_FALLBACK_REPORTS_DIR="$TMP_DIR/reports_missing_fallback"
MISSING_FALLBACK_SUMMARY="$TMP_DIR/missing_fallback_summary.json"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CYCLE_SCRIPT="$FAKE_CYCLE" \
FAKE_CYCLE_COUNTER_FILE="$TMP_DIR/missing_fallback_counter.txt" \
FAKE_CYCLE_SCENARIO="stable" \
bash "$SCRIPT_UNDER_TEST" \
  --runs 1 \
  --sleep-between-sec 0 \
  --reports-dir "$MISSING_FALLBACK_REPORTS_DIR" \
  --summary-json "$MISSING_FALLBACK_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_run_missing_fallback.log 2>&1
missing_fallback_rc=$?
set -e

if [[ "$missing_fallback_rc" -eq 0 ]]; then
  echo "expected missing-fallback path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_missing_fallback.log
  exit 1
fi
if ! grep -q 'at least one --vm-command or --vm-command-file is required' /tmp/integration_profile_compare_multi_vm_stability_run_missing_fallback.log; then
  echo "expected missing-fallback hard error message"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_missing_fallback.log
  exit 1
fi
if ! grep -q 'operator_next_action:' /tmp/integration_profile_compare_multi_vm_stability_run_missing_fallback.log; then
  echo "expected operator_next_action diagnostics on missing fallback"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_missing_fallback.log
  exit 1
fi
if ! grep -q 'operator_next_action: ./scripts/profile_compare_multi_vm_stability_run.sh' /tmp/integration_profile_compare_multi_vm_stability_run_missing_fallback.log; then
  echo "expected exact rerun command in missing-fallback diagnostics"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_missing_fallback.log
  exit 1
fi
if ! grep -q -- '--vm-command VM_ID::COMMAND' /tmp/integration_profile_compare_multi_vm_stability_run_missing_fallback.log; then
  echo "expected --vm-command rerun guidance in missing-fallback diagnostics"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_missing_fallback.log
  exit 1
fi
if ! grep -q -- '--vm-command-file REPLACE_WITH_VM_COMMAND_FILE' /tmp/integration_profile_compare_multi_vm_stability_run_missing_fallback.log; then
  echo "expected --vm-command-file rerun guidance in missing-fallback diagnostics"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_missing_fallback.log
  exit 1
fi
if ! grep -q 'preflight_diag:' /tmp/integration_profile_compare_multi_vm_stability_run_missing_fallback.log; then
  echo "expected structured preflight_diag entries on missing fallback"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_missing_fallback.log
  exit 1
fi
if ! grep -q 'profile_compare_multi_vm_stability_vm_commands.txt' /tmp/integration_profile_compare_multi_vm_stability_run_missing_fallback.log; then
  echo "expected recognized reports-dir artifact path diagnostics"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_missing_fallback.log
  exit 1
fi

echo "[profile-compare-multi-vm-stability-run] malformed fallback vm-command-file fails closed during preflight"
INVALID_FALLBACK_REPORTS_DIR="$TMP_DIR/reports_invalid_fallback"
INVALID_FALLBACK_SUMMARY="$TMP_DIR/invalid_fallback_summary.json"
INVALID_FALLBACK_CAPTURE="$TMP_DIR/invalid_fallback_capture.log"
mkdir -p "$INVALID_FALLBACK_REPORTS_DIR"
printf 'vm_invalid_without_delimiter\n' >"$INVALID_FALLBACK_REPORTS_DIR/profile_compare_multi_vm_stability_vm_commands.txt"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CYCLE_SCRIPT="$FAKE_CYCLE" \
FAKE_CYCLE_COUNTER_FILE="$TMP_DIR/invalid_fallback_counter.txt" \
FAKE_CYCLE_SCENARIO="stable" \
FAKE_CYCLE_CAPTURE_FILE="$INVALID_FALLBACK_CAPTURE" \
bash "$SCRIPT_UNDER_TEST" \
  --runs 1 \
  --sleep-between-sec 0 \
  --reports-dir "$INVALID_FALLBACK_REPORTS_DIR" \
  --summary-json "$INVALID_FALLBACK_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_run_invalid_fallback.log 2>&1
invalid_fallback_rc=$?
set -e

if [[ "$invalid_fallback_rc" -eq 0 ]]; then
  echo "expected invalid-fallback preflight path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_invalid_fallback.log
  exit 1
fi
if ! grep -q 'no usable VM command fallback was discovered (fail-closed).' /tmp/integration_profile_compare_multi_vm_stability_run_invalid_fallback.log; then
  echo "expected invalid fallback hard fail-closed message"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_invalid_fallback.log
  exit 1
fi
if ! grep -q 'preflight_diag: source=reports-dir-canonical path=' /tmp/integration_profile_compare_multi_vm_stability_run_invalid_fallback.log; then
  echo "expected fallback diagnostics for invalid canonical vm-command file"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_invalid_fallback.log
  exit 1
fi
if ! grep -q 'reason=invalid_vm_command_spec_line_1_missing_delimiter' /tmp/integration_profile_compare_multi_vm_stability_run_invalid_fallback.log; then
  echo "expected invalid vm-command-file reason in diagnostics"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_invalid_fallback.log
  exit 1
fi
if [[ -f "$INVALID_FALLBACK_CAPTURE" ]] && [[ -s "$INVALID_FALLBACK_CAPTURE" ]]; then
  echo "invalid fallback should fail before fake cycle invocation"
  cat "$INVALID_FALLBACK_CAPTURE"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-run] explicit malformed --vm-command-file fails closed during preflight"
EXPLICIT_INVALID_REPORTS_DIR="$TMP_DIR/reports_explicit_invalid_vm_file"
EXPLICIT_INVALID_SUMMARY="$TMP_DIR/explicit_invalid_vm_file_summary.json"
EXPLICIT_INVALID_VM_FILE="$TMP_DIR/vm_commands_explicit_invalid.txt"
EXPLICIT_INVALID_CAPTURE="$TMP_DIR/explicit_invalid_vm_file_capture.log"
printf 'vm_explicit_invalid_without_delimiter\n' >"$EXPLICIT_INVALID_VM_FILE"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CYCLE_SCRIPT="$FAKE_CYCLE" \
FAKE_CYCLE_COUNTER_FILE="$TMP_DIR/explicit_invalid_vm_file_counter.txt" \
FAKE_CYCLE_SCENARIO="stable" \
FAKE_CYCLE_CAPTURE_FILE="$EXPLICIT_INVALID_CAPTURE" \
bash "$SCRIPT_UNDER_TEST" \
  --runs 1 \
  --sleep-between-sec 0 \
  --reports-dir "$EXPLICIT_INVALID_REPORTS_DIR" \
  --summary-json "$EXPLICIT_INVALID_SUMMARY" \
  --vm-command-file "$EXPLICIT_INVALID_VM_FILE" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_run_explicit_invalid_vm_file.log 2>&1
explicit_invalid_vm_file_rc=$?
set -e

if [[ "$explicit_invalid_vm_file_rc" -eq 0 ]]; then
  echo "expected explicit invalid vm-command-file preflight path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_explicit_invalid_vm_file.log
  exit 1
fi
if ! grep -q 'vm command file preflight failed: invalid_vm_command_spec_line_1_missing_delimiter' /tmp/integration_profile_compare_multi_vm_stability_run_explicit_invalid_vm_file.log; then
  echo "expected explicit invalid vm-command-file preflight failure reason"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_explicit_invalid_vm_file.log
  exit 1
fi
if ! grep -q 'operator_next_action: ./scripts/profile_compare_multi_vm_stability_run.sh' /tmp/integration_profile_compare_multi_vm_stability_run_explicit_invalid_vm_file.log; then
  echo "expected exact rerun command in explicit invalid vm-command-file diagnostics"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_explicit_invalid_vm_file.log
  exit 1
fi
if ! grep -q -- "--vm-command-file $EXPLICIT_INVALID_VM_FILE" /tmp/integration_profile_compare_multi_vm_stability_run_explicit_invalid_vm_file.log; then
  echo "expected explicit vm-command-file path in rerun guidance"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_explicit_invalid_vm_file.log
  exit 1
fi
if ! grep -q 'preflight_diag: source=vm-command-file path=' /tmp/integration_profile_compare_multi_vm_stability_run_explicit_invalid_vm_file.log; then
  echo "expected explicit vm-command-file preflight diagnostics"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_explicit_invalid_vm_file.log
  exit 1
fi
if ! grep -q 'reason=invalid_vm_command_spec_line_1_missing_delimiter' /tmp/integration_profile_compare_multi_vm_stability_run_explicit_invalid_vm_file.log; then
  echo "expected explicit vm-command-file invalid reason in diagnostics"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_explicit_invalid_vm_file.log
  exit 1
fi
if [[ -f "$EXPLICIT_INVALID_CAPTURE" ]] && [[ -s "$EXPLICIT_INVALID_CAPTURE" ]]; then
  echo "explicit invalid vm-command-file should fail before fake cycle invocation"
  cat "$EXPLICIT_INVALID_CAPTURE"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-run] conflicting duplicate VM_ID in fallback vm-command-file fails closed during preflight"
DUPLICATE_CONFLICT_FALLBACK_REPORTS_DIR="$TMP_DIR/reports_duplicate_conflict_fallback"
DUPLICATE_CONFLICT_FALLBACK_SUMMARY="$TMP_DIR/duplicate_conflict_fallback_summary.json"
DUPLICATE_CONFLICT_FALLBACK_CAPTURE="$TMP_DIR/duplicate_conflict_fallback_capture.log"
mkdir -p "$DUPLICATE_CONFLICT_FALLBACK_REPORTS_DIR"
cat >"$DUPLICATE_CONFLICT_FALLBACK_REPORTS_DIR/profile_compare_multi_vm_stability_vm_commands.txt" <<'EOF_DUPLICATE_CONFLICT_FALLBACK'
vm_dup::echo vm-first
vm_dup::echo vm-second
EOF_DUPLICATE_CONFLICT_FALLBACK
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CYCLE_SCRIPT="$FAKE_CYCLE" \
FAKE_CYCLE_COUNTER_FILE="$TMP_DIR/duplicate_conflict_fallback_counter.txt" \
FAKE_CYCLE_SCENARIO="stable" \
FAKE_CYCLE_CAPTURE_FILE="$DUPLICATE_CONFLICT_FALLBACK_CAPTURE" \
bash "$SCRIPT_UNDER_TEST" \
  --runs 1 \
  --sleep-between-sec 0 \
  --reports-dir "$DUPLICATE_CONFLICT_FALLBACK_REPORTS_DIR" \
  --summary-json "$DUPLICATE_CONFLICT_FALLBACK_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_run_duplicate_conflict_fallback.log 2>&1
duplicate_conflict_fallback_rc=$?
set -e

if [[ "$duplicate_conflict_fallback_rc" -eq 0 ]]; then
  echo "expected duplicate-conflict fallback preflight path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_duplicate_conflict_fallback.log
  exit 1
fi
if ! grep -q 'reason=invalid_vm_command_spec_line_2_duplicate_vm_id_conflict' /tmp/integration_profile_compare_multi_vm_stability_run_duplicate_conflict_fallback.log; then
  echo "expected duplicate VM_ID conflict reason in fallback diagnostics"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_duplicate_conflict_fallback.log
  exit 1
fi
if [[ -f "$DUPLICATE_CONFLICT_FALLBACK_CAPTURE" ]] && [[ -s "$DUPLICATE_CONFLICT_FALLBACK_CAPTURE" ]]; then
  echo "duplicate-conflict fallback should fail before fake cycle invocation"
  cat "$DUPLICATE_CONFLICT_FALLBACK_CAPTURE"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-run] explicit conflicting duplicate VM_ID vm-command-file fails closed during preflight"
EXPLICIT_DUPLICATE_CONFLICT_REPORTS_DIR="$TMP_DIR/reports_explicit_duplicate_conflict_vm_file"
EXPLICIT_DUPLICATE_CONFLICT_SUMMARY="$TMP_DIR/explicit_duplicate_conflict_vm_file_summary.json"
EXPLICIT_DUPLICATE_CONFLICT_VM_FILE="$TMP_DIR/vm_commands_explicit_duplicate_conflict.txt"
EXPLICIT_DUPLICATE_CONFLICT_CAPTURE="$TMP_DIR/explicit_duplicate_conflict_vm_file_capture.log"
cat >"$EXPLICIT_DUPLICATE_CONFLICT_VM_FILE" <<'EOF_EXPLICIT_DUPLICATE_CONFLICT'
vm_explicit_dup::echo vm-explicit-first
vm_explicit_dup::echo vm-explicit-second
EOF_EXPLICIT_DUPLICATE_CONFLICT
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CYCLE_SCRIPT="$FAKE_CYCLE" \
FAKE_CYCLE_COUNTER_FILE="$TMP_DIR/explicit_duplicate_conflict_vm_file_counter.txt" \
FAKE_CYCLE_SCENARIO="stable" \
FAKE_CYCLE_CAPTURE_FILE="$EXPLICIT_DUPLICATE_CONFLICT_CAPTURE" \
bash "$SCRIPT_UNDER_TEST" \
  --runs 1 \
  --sleep-between-sec 0 \
  --reports-dir "$EXPLICIT_DUPLICATE_CONFLICT_REPORTS_DIR" \
  --summary-json "$EXPLICIT_DUPLICATE_CONFLICT_SUMMARY" \
  --vm-command-file "$EXPLICIT_DUPLICATE_CONFLICT_VM_FILE" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_run_explicit_duplicate_conflict_vm_file.log 2>&1
explicit_duplicate_conflict_vm_file_rc=$?
set -e

if [[ "$explicit_duplicate_conflict_vm_file_rc" -eq 0 ]]; then
  echo "expected explicit duplicate-conflict vm-command-file preflight path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_explicit_duplicate_conflict_vm_file.log
  exit 1
fi
if ! grep -q 'vm command file preflight failed: invalid_vm_command_spec_line_2_duplicate_vm_id_conflict' /tmp/integration_profile_compare_multi_vm_stability_run_explicit_duplicate_conflict_vm_file.log; then
  echo "expected explicit duplicate-conflict vm-command-file preflight failure reason"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_explicit_duplicate_conflict_vm_file.log
  exit 1
fi
if ! grep -q 'operator_next_action: ./scripts/profile_compare_multi_vm_stability_run.sh' /tmp/integration_profile_compare_multi_vm_stability_run_explicit_duplicate_conflict_vm_file.log; then
  echo "expected exact rerun command in explicit duplicate-conflict vm-command-file diagnostics"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_explicit_duplicate_conflict_vm_file.log
  exit 1
fi
if ! grep -q -- "--vm-command-file $EXPLICIT_DUPLICATE_CONFLICT_VM_FILE" /tmp/integration_profile_compare_multi_vm_stability_run_explicit_duplicate_conflict_vm_file.log; then
  echo "expected explicit duplicate-conflict vm-command-file path in rerun guidance"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_explicit_duplicate_conflict_vm_file.log
  exit 1
fi
if ! grep -q 'reason=invalid_vm_command_spec_line_2_duplicate_vm_id_conflict' /tmp/integration_profile_compare_multi_vm_stability_run_explicit_duplicate_conflict_vm_file.log; then
  echo "expected explicit duplicate-conflict vm-command-file diagnostics reason"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_explicit_duplicate_conflict_vm_file.log
  exit 1
fi
if [[ -f "$EXPLICIT_DUPLICATE_CONFLICT_CAPTURE" ]] && [[ -s "$EXPLICIT_DUPLICATE_CONFLICT_CAPTURE" ]]; then
  echo "explicit duplicate-conflict vm-command-file should fail before fake cycle invocation"
  cat "$EXPLICIT_DUPLICATE_CONFLICT_CAPTURE"
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

echo "[profile-compare-multi-vm-stability-run] nonzero cycle rc remains fail-closed even with warn summary status"
WARN_RC_NONZERO_SUMMARY="$TMP_DIR/warn_rc_nonzero_summary.json"
WARN_RC_NONZERO_COUNTER="$TMP_DIR/warn_rc_nonzero_counter.txt"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CYCLE_SCRIPT="$FAKE_CYCLE" \
FAKE_CYCLE_COUNTER_FILE="$WARN_RC_NONZERO_COUNTER" \
FAKE_CYCLE_SCENARIO="warn_rc_nonzero" \
bash "$SCRIPT_UNDER_TEST" \
  --runs 1 \
  --sleep-between-sec 0 \
  --allow-partial 1 \
  --min-completed-runs 1 \
  --min-pass-runs 1 \
  --reports-dir "$TMP_DIR/reports_warn_rc_nonzero" \
  --summary-json "$WARN_RC_NONZERO_SUMMARY" \
  --vm-command "vm_a::echo vm-a" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_run_warn_rc_nonzero.log 2>&1
warn_rc_nonzero_rc=$?
set -e

if [[ "$warn_rc_nonzero_rc" -eq 0 ]]; then
  echo "expected warn-rc-nonzero path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_warn_rc_nonzero.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .counts.fail == 1
  and .runs[0].status == "fail"
  and .runs[0].failure_reason == "cycle_rc_nonzero"
' "$WARN_RC_NONZERO_SUMMARY" >/dev/null 2>&1; then
  echo "warn-rc-nonzero summary missing fail-closed contract fields"
  cat "$WARN_RC_NONZERO_SUMMARY"
  exit 1
fi

echo "[profile-compare-multi-vm-stability-run] schema mismatch remains fail-closed"
SCHEMA_MISMATCH_SUMMARY="$TMP_DIR/schema_mismatch_summary.json"
SCHEMA_MISMATCH_COUNTER="$TMP_DIR/schema_mismatch_counter.txt"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_CYCLE_SCRIPT="$FAKE_CYCLE" \
FAKE_CYCLE_COUNTER_FILE="$SCHEMA_MISMATCH_COUNTER" \
FAKE_CYCLE_SCENARIO="schema_mismatch" \
bash "$SCRIPT_UNDER_TEST" \
  --runs 1 \
  --sleep-between-sec 0 \
  --reports-dir "$TMP_DIR/reports_schema_mismatch" \
  --summary-json "$SCHEMA_MISMATCH_SUMMARY" \
  --vm-command "vm_a::echo vm-a" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_run_schema_mismatch.log 2>&1
schema_mismatch_rc=$?
set -e

if [[ "$schema_mismatch_rc" -eq 0 ]]; then
  echo "expected schema-mismatch path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_run_schema_mismatch.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .counts.fail == 1
  and .runs[0].status == "fail"
  and .runs[0].failure_reason == "cycle_summary_schema_mismatch"
  and .runs[0].artifacts.cycle_summary_schema_valid == false
  and .runs[0].artifacts.cycle_summary_schema_id == "runtime_actuation_multi_vm_cycle_summary"
' "$SCHEMA_MISMATCH_SUMMARY" >/dev/null 2>&1; then
  echo "schema-mismatch summary missing fail-closed schema diagnostics"
  cat "$SCHEMA_MISMATCH_SUMMARY"
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
