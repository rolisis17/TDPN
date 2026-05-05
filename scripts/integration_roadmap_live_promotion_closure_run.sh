#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod cat grep awk; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/roadmap_live_promotion_closure_run.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

mkdir -p "$ROOT_DIR/.easy-node-logs"
TMP_DIR="$(mktemp -d "$ROOT_DIR/.easy-node-logs/integration_roadmap_live_promotion_closure_run_XXXXXX")"
STUB_DIR="$(mktemp -d "$ROOT_DIR/scripts/.integration_roadmap_live_promotion_closure_run.XXXXXX")"
trap 'rm -rf "$TMP_DIR" "$STUB_DIR"' EXIT

CAPTURE_LOG="$TMP_DIR/helper_capture.tsv"
VM_COMMAND_FILE_REAL="$TMP_DIR/profile_compare_multi_vm_stability_vm_commands.txt"

assert_token() {
  local haystack="$1"
  local needle="$2"
  local message="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "$message"
    echo "line: $haystack"
    exit 1
  fi
}

cat >"$VM_COMMAND_FILE_REAL" <<'EOF_VM_COMMANDS'
vm-a::echo vm-a
vm-b::echo vm-b
EOF_VM_COMMANDS

FAKE_M2_SCRIPT="$STUB_DIR/fake_m2_profile_default_gate_stability_live_archive_and_pack.sh"
cat >"$FAKE_M2_SCRIPT" <<'EOF_FAKE_M2'
#!/usr/bin/env bash
set -euo pipefail

capture_file="${FAKE_CAPTURE_FILE:?}"
behavior="${FAKE_M2_BEHAVIOR:-pass}"
summary_json=""
reports_dir=""
host_a=""
host_b=""
campaign_subject=""
print_summary_json="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --host-a)
      host_a="${2:-}"
      shift 2
      ;;
    --host-b)
      host_b="${2:-}"
      shift 2
      ;;
    --campaign-subject|--subject)
      campaign_subject="${2:-}"
      shift 2
      ;;
    --print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_summary_json="${2:-}"
        shift 2
      else
        print_summary_json="1"
        shift
      fi
      ;;
    *)
      shift
      ;;
  esac
done

printf 'm2\t%s\t%s\t%s\t%s\t%s\n' "$host_a" "$host_b" "$campaign_subject" "$reports_dir" "$summary_json" >>"$capture_file"

if [[ -n "$reports_dir" ]]; then
  mkdir -p "$reports_dir"
fi
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
fi

case "$behavior" in
  pass)
    jq -n \
      --arg status "pass" \
      --argjson rc 0 \
      --arg schema_id "profile_default_gate_stability_live_archive_and_pack_summary" \
      '{status: $status, rc: $rc, schema: {id: $schema_id}}' >"$summary_json"
    exit_code=0
    ;;
  fail)
    rc="${FAKE_M2_RC:-17}"
    jq -n \
      --arg status "fail" \
      --argjson rc "$rc" \
      --arg schema_id "profile_default_gate_stability_live_archive_and_pack_summary" \
      '{status: $status, rc: $rc, schema: {id: $schema_id}}' >"$summary_json"
    exit_code="$rc"
    ;;
  invalid)
    printf '{ invalid-json\n' >"$summary_json"
    exit_code=0
    ;;
  no_summary)
    rm -f "$summary_json"
    exit_code=0
    ;;
  *)
    echo "unknown FAKE_M2_BEHAVIOR=$behavior" >&2
    exit 2
    ;;
esac

if [[ "$print_summary_json" == "1" && -f "$summary_json" ]]; then
  cat "$summary_json"
fi
exit "$exit_code"
EOF_FAKE_M2
chmod +x "$FAKE_M2_SCRIPT"

FAKE_M4_SCRIPT="$STUB_DIR/fake_m4_runtime_actuation_promotion_live_archive_and_pack.sh"
cat >"$FAKE_M4_SCRIPT" <<'EOF_FAKE_M4'
#!/usr/bin/env bash
set -euo pipefail

capture_file="${FAKE_CAPTURE_FILE:?}"
behavior="${FAKE_M4_BEHAVIOR:-pass}"
summary_json=""
reports_dir=""
print_summary_json="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_summary_json="${2:-}"
        shift 2
      else
        print_summary_json="1"
        shift
      fi
      ;;
    *)
      shift
      ;;
  esac
done

printf 'm4\t\t\t\t%s\t%s\n' "$reports_dir" "$summary_json" >>"$capture_file"

if [[ -n "$reports_dir" ]]; then
  mkdir -p "$reports_dir"
fi
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
fi

case "$behavior" in
  pass)
    jq -n \
      --arg status "pass" \
      --argjson rc 0 \
      --arg schema_id "runtime_actuation_promotion_live_archive_and_pack_summary" \
      '{status: $status, rc: $rc, schema: {id: $schema_id}}' >"$summary_json"
    exit_code=0
    ;;
  pass_exit_nonzero)
    rc="${FAKE_M4_RC:-23}"
    jq -n \
      --arg status "pass" \
      --argjson rc 0 \
      --arg schema_id "runtime_actuation_promotion_live_archive_and_pack_summary" \
      '{status: $status, rc: $rc, schema: {id: $schema_id}}' >"$summary_json"
    exit_code="$rc"
    ;;
  summary_fail_exit_zero)
    rc="${FAKE_M4_RC:-23}"
    jq -n \
      --arg status "fail" \
      --argjson rc "$rc" \
      --arg schema_id "runtime_actuation_promotion_live_archive_and_pack_summary" \
      '{status: $status, rc: $rc, schema: {id: $schema_id}}' >"$summary_json"
    exit_code=0
    ;;
  fail)
    rc="${FAKE_M4_RC:-23}"
    jq -n \
      --arg status "fail" \
      --argjson rc "$rc" \
      --arg schema_id "runtime_actuation_promotion_live_archive_and_pack_summary" \
      '{status: $status, rc: $rc, schema: {id: $schema_id}}' >"$summary_json"
    exit_code="$rc"
    ;;
  invalid)
    printf '{ invalid-json\n' >"$summary_json"
    exit_code=0
    ;;
  no_summary)
    rm -f "$summary_json"
    exit_code=0
    ;;
  *)
    echo "unknown FAKE_M4_BEHAVIOR=$behavior" >&2
    exit 2
    ;;
esac

if [[ "$print_summary_json" == "1" && -f "$summary_json" ]]; then
  cat "$summary_json"
fi
exit "$exit_code"
EOF_FAKE_M4
chmod +x "$FAKE_M4_SCRIPT"

FAKE_M5_SCRIPT="$STUB_DIR/fake_m5_profile_compare_multi_vm_stability_promotion_live_archive_and_pack.sh"
cat >"$FAKE_M5_SCRIPT" <<'EOF_FAKE_M5'
#!/usr/bin/env bash
set -euo pipefail

capture_file="${FAKE_CAPTURE_FILE:?}"
behavior="${FAKE_M5_BEHAVIOR:-pass}"
summary_json=""
reports_dir=""
print_summary_json="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_summary_json="${2:-}"
        shift 2
      else
        print_summary_json="1"
        shift
      fi
      ;;
    *)
      shift
      ;;
  esac
done

printf 'm5\t\t\t\t%s\t%s\n' "$reports_dir" "$summary_json" >>"$capture_file"

if [[ -n "$reports_dir" ]]; then
  mkdir -p "$reports_dir"
fi
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
fi

case "$behavior" in
  pass)
    jq -n \
      --arg status "pass" \
      --argjson rc 0 \
      --arg schema_id "profile_compare_multi_vm_stability_promotion_live_archive_and_pack_summary" \
      '{status: $status, rc: $rc, schema: {id: $schema_id}}' >"$summary_json"
    exit_code=0
    ;;
  fail)
    rc="${FAKE_M5_RC:-31}"
    jq -n \
      --arg status "fail" \
      --argjson rc "$rc" \
      --arg schema_id "profile_compare_multi_vm_stability_promotion_live_archive_and_pack_summary" \
      '{status: $status, rc: $rc, schema: {id: $schema_id}}' >"$summary_json"
    exit_code="$rc"
    ;;
  invalid)
    printf '{ invalid-json\n' >"$summary_json"
    exit_code=0
    ;;
  no_summary)
    rm -f "$summary_json"
    exit_code=0
    ;;
  *)
    echo "unknown FAKE_M5_BEHAVIOR=$behavior" >&2
    exit 2
    ;;
esac

if [[ "$print_summary_json" == "1" && -f "$summary_json" ]]; then
  cat "$summary_json"
fi
exit "$exit_code"
EOF_FAKE_M5
chmod +x "$FAKE_M5_SCRIPT"

echo "[roadmap-live-promotion-closure-run] help contract"
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--reports-dir DIR" >/dev/null; then
  echo "help output missing --reports-dir DIR"
  exit 1
fi
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--summary-json PATH" >/dev/null; then
  echo "help output missing --summary-json PATH"
  exit 1
fi
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--host-a HOST" >/dev/null; then
  echo "help output missing --host-a HOST"
  exit 1
fi
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--host-b HOST" >/dev/null; then
  echo "help output missing --host-b HOST"
  exit 1
fi
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--campaign-subject ID" >/dev/null; then
  echo "help output missing --campaign-subject ID"
  exit 1
fi
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--vm-command-file PATH" >/dev/null; then
  echo "help output missing --vm-command-file PATH"
  exit 1
fi
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--print-summary-json [0|1]" >/dev/null; then
  echo "help output missing --print-summary-json [0|1]"
  exit 1
fi

echo "[roadmap-live-promotion-closure-run] runtime-input preflight missing is fail-closed"
SUMMARY_RUNTIME_MISSING="$TMP_DIR/summary_runtime_missing.json"
: >"$CAPTURE_LOG"
set +e
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M2_SCRIPT="$FAKE_M2_SCRIPT" \
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M4_SCRIPT="$FAKE_M4_SCRIPT" \
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M5_SCRIPT="$FAKE_M5_SCRIPT" \
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M5_VM_COMMAND_FILE="$VM_COMMAND_FILE_REAL" \
FAKE_CAPTURE_FILE="$CAPTURE_LOG" \
FAKE_M2_BEHAVIOR=pass \
FAKE_M4_BEHAVIOR=pass \
FAKE_M5_BEHAVIOR=pass \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/reports_runtime_missing" \
  --summary-json "$SUMMARY_RUNTIME_MISSING" \
  --print-summary-json 0
runtime_missing_rc=$?
set -e

if [[ "$runtime_missing_rc" != "2" ]]; then
  echo "expected runtime-missing fail-closed rc=2, got rc=$runtime_missing_rc"
  cat "$SUMMARY_RUNTIME_MISSING"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 2
  and .failure_substep == "preflight:runtime_inputs_unresolved_or_placeholder"
  and .summary.preflight_ok == false
  and .summary.helper_preflight_ok == true
  and .summary.runtime_input_preflight_ok == false
  and .summary.total_tracks == 3
  and .summary.executed_tracks == 0
  and .summary.pass_tracks == 0
  and .summary.fail_tracks == 2
  and .summary.skipped_tracks == 1
  and .summary.unresolved_runtime_input_track_count == 2
  and .summary.unresolved_runtime_input_count == 4
  and .preflight.runtime_inputs_ok == false
  and (.preflight.runtime_input_failures | length == 2)
  and ([.tracks[].status] == ["fail","fail","skipped"])
  and ([.tracks[].runtime_preflight.ok] == [false,false,true])
' "$SUMMARY_RUNTIME_MISSING" >/dev/null; then
  echo "runtime-missing fail-closed summary mismatch"
  cat "$SUMMARY_RUNTIME_MISSING"
  exit 1
fi

if [[ -s "$CAPTURE_LOG" ]]; then
  echo "helper scripts should not run when runtime-input preflight fails"
  cat "$CAPTURE_LOG"
  exit 1
fi

echo "[roadmap-live-promotion-closure-run] runtime-input placeholder detection is fail-closed"
SUMMARY_RUNTIME_PLACEHOLDER="$TMP_DIR/summary_runtime_placeholder.json"
: >"$CAPTURE_LOG"
set +e
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M2_SCRIPT="$FAKE_M2_SCRIPT" \
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M4_SCRIPT="$FAKE_M4_SCRIPT" \
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M5_SCRIPT="$FAKE_M5_SCRIPT" \
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M5_VM_COMMAND_FILE="$VM_COMMAND_FILE_REAL" \
FAKE_CAPTURE_FILE="$CAPTURE_LOG" \
FAKE_M2_BEHAVIOR=pass \
FAKE_M4_BEHAVIOR=pass \
FAKE_M5_BEHAVIOR=pass \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/reports_runtime_placeholder" \
  --summary-json "$SUMMARY_RUNTIME_PLACEHOLDER" \
  --host-a HOST_A \
  --host-b REPLACE_WITH_HOST_B \
  --campaign-subject INVITE_KEY \
  --vm-command-file REPLACE_WITH_VM_COMMAND_FILE \
  --print-summary-json 0
runtime_placeholder_rc=$?
set -e

if [[ "$runtime_placeholder_rc" != "2" ]]; then
  echo "expected runtime-placeholder fail-closed rc=2, got rc=$runtime_placeholder_rc"
  cat "$SUMMARY_RUNTIME_PLACEHOLDER"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 2
  and .failure_substep == "preflight:runtime_inputs_unresolved_or_placeholder"
  and .summary.runtime_input_preflight_ok == false
  and .tracks[0].runtime_preflight.required_runtime_inputs[0].state == "placeholder_unresolved"
  and .tracks[0].runtime_preflight.required_runtime_inputs[1].state == "placeholder_unresolved"
  and .tracks[0].runtime_preflight.required_runtime_inputs[2].state == "placeholder_unresolved"
  and .tracks[1].runtime_preflight.required_runtime_inputs[0].state == "placeholder_unresolved"
  and .tracks[2].runtime_preflight.required_runtime_inputs[0].state == "placeholder_unresolved"
' "$SUMMARY_RUNTIME_PLACEHOLDER" >/dev/null; then
  echo "runtime-placeholder fail-closed summary mismatch"
  cat "$SUMMARY_RUNTIME_PLACEHOLDER"
  exit 1
fi

if [[ -s "$CAPTURE_LOG" ]]; then
  echo "helper scripts should not run when runtime-input placeholders are unresolved"
  cat "$CAPTURE_LOG"
  exit 1
fi

echo "[roadmap-live-promotion-closure-run] success path"
SUMMARY_SUCCESS="$TMP_DIR/summary_success.json"
: >"$CAPTURE_LOG"
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M2_SCRIPT="$FAKE_M2_SCRIPT" \
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M4_SCRIPT="$FAKE_M4_SCRIPT" \
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M5_SCRIPT="$FAKE_M5_SCRIPT" \
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M5_VM_COMMAND_FILE="$VM_COMMAND_FILE_REAL" \
FAKE_CAPTURE_FILE="$CAPTURE_LOG" \
FAKE_M2_BEHAVIOR=pass \
FAKE_M4_BEHAVIOR=pass \
FAKE_M5_BEHAVIOR=pass \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/reports_success" \
  --summary-json "$SUMMARY_SUCCESS" \
  --host-a 198.51.100.10 \
  --host-b 198.51.100.11 \
  --campaign-subject inv-real-001 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .summary.total_tracks == 3
  and .summary.executed_tracks == 3
  and .summary.pass_tracks == 3
  and .summary.fail_tracks == 0
  and .summary.skipped_tracks == 0
  and .summary.preflight_ok == true
  and .summary.first_failure_track_id == null
  and .inputs.host_a_provided == true
  and .inputs.host_b_provided == true
  and .inputs.campaign_subject_provided == true
  and (.tracks | length == 3)
  and ([.tracks[].track_id] == [
    "m2_profile_default_gate_stability_live_archive_and_pack",
    "m4_runtime_actuation_promotion_live_archive_and_pack",
    "m5_profile_compare_multi_vm_stability_promotion_live_archive_and_pack"
  ])
  and ([.tracks[].status] == ["pass","pass","pass"])
  and ([.tracks[].contract.schema_valid] == [true,true,true])
  and ([.tracks[].contract.valid] == [true,true,true])
' "$SUMMARY_SUCCESS" >/dev/null; then
  echo "success summary mismatch"
  cat "$SUMMARY_SUCCESS"
  exit 1
fi

if [[ "$(grep -c '.' "$CAPTURE_LOG" || true)" != "3" ]]; then
  echo "expected 3 helper invocations in success path"
  cat "$CAPTURE_LOG"
  exit 1
fi

first_track="$(awk -F'\t' 'NR==1 {print $1}' "$CAPTURE_LOG")"
second_track="$(awk -F'\t' 'NR==2 {print $1}' "$CAPTURE_LOG")"
third_track="$(awk -F'\t' 'NR==3 {print $1}' "$CAPTURE_LOG")"
if [[ "$first_track" != "m2" || "$second_track" != "m4" || "$third_track" != "m5" ]]; then
  echo "expected deterministic m2->m4->m5 invocation order"
  cat "$CAPTURE_LOG"
  exit 1
fi

m2_line="$(awk -F'\t' '$1=="m2" {print; exit}' "$CAPTURE_LOG")"
if [[ -z "$m2_line" ]]; then
  echo "missing m2 capture line in success path"
  exit 1
fi
assert_token "$m2_line" $'\t198.51.100.10\t198.51.100.11\tinv-real-001\t' "missing host/campaign forwarding to m2 helper"

echo "[roadmap-live-promotion-closure-run] failing m4 still records all track outcomes"
SUMMARY_FAIL_ONE="$TMP_DIR/summary_fail_one.json"
: >"$CAPTURE_LOG"
set +e
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M2_SCRIPT="$FAKE_M2_SCRIPT" \
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M4_SCRIPT="$FAKE_M4_SCRIPT" \
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M5_SCRIPT="$FAKE_M5_SCRIPT" \
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M5_VM_COMMAND_FILE="$VM_COMMAND_FILE_REAL" \
FAKE_CAPTURE_FILE="$CAPTURE_LOG" \
FAKE_M2_BEHAVIOR=pass \
FAKE_M4_BEHAVIOR=fail \
FAKE_M4_RC=23 \
FAKE_M5_BEHAVIOR=pass \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/reports_fail_one" \
  --summary-json "$SUMMARY_FAIL_ONE" \
  --host-a 198.51.100.12 \
  --host-b 198.51.100.13 \
  --campaign-subject inv-real-002 \
  --print-summary-json 0
fail_one_rc=$?
set -e

if [[ "$fail_one_rc" != "23" ]]; then
  echo "expected failing-m4 rc=23, got rc=$fail_one_rc"
  cat "$SUMMARY_FAIL_ONE"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 23
  and .failure_substep == "track:m4_runtime_actuation_promotion_live_archive_and_pack"
  and .summary.total_tracks == 3
  and .summary.executed_tracks == 3
  and .summary.pass_tracks == 2
  and .summary.fail_tracks == 1
  and .summary.skipped_tracks == 0
  and .summary.first_failure_track_id == "m4_runtime_actuation_promotion_live_archive_and_pack"
  and ([.tracks[].status] == ["pass","fail","pass"])
  and .tracks[1].contract.schema_valid == true
  and .tracks[1].rc == 23
  and .tracks[2].status == "pass"
' "$SUMMARY_FAIL_ONE" >/dev/null; then
  echo "failing-m4 summary mismatch"
  cat "$SUMMARY_FAIL_ONE"
  exit 1
fi

if [[ "$(grep -c '.' "$CAPTURE_LOG" || true)" != "3" ]]; then
  echo "expected 3 helper invocations when m4 fails"
  cat "$CAPTURE_LOG"
  exit 1
fi

third_track_after_fail="$(awk -F'\t' 'NR==3 {print $1}' "$CAPTURE_LOG")"
if [[ "$third_track_after_fail" != "m5" ]]; then
  echo "expected m5 to run after failing m4 for consolidated per-track output"
  cat "$CAPTURE_LOG"
  exit 1
fi

echo "[roadmap-live-promotion-closure-run] non-zero helper rc is fail-closed even with pass summary"
SUMMARY_NONZERO_PASS="$TMP_DIR/summary_nonzero_pass.json"
: >"$CAPTURE_LOG"
set +e
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M2_SCRIPT="$FAKE_M2_SCRIPT" \
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M4_SCRIPT="$FAKE_M4_SCRIPT" \
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M5_SCRIPT="$FAKE_M5_SCRIPT" \
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M5_VM_COMMAND_FILE="$VM_COMMAND_FILE_REAL" \
FAKE_CAPTURE_FILE="$CAPTURE_LOG" \
FAKE_M2_BEHAVIOR=pass \
FAKE_M4_BEHAVIOR=pass_exit_nonzero \
FAKE_M4_RC=29 \
FAKE_M5_BEHAVIOR=pass \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/reports_nonzero_pass" \
  --summary-json "$SUMMARY_NONZERO_PASS" \
  --host-a 198.51.100.20 \
  --host-b 198.51.100.21 \
  --campaign-subject inv-real-003 \
  --print-summary-json 0
nonzero_pass_rc=$?
set -e

if [[ "$nonzero_pass_rc" != "29" ]]; then
  echo "expected nonzero-pass fail-closed rc=29, got rc=$nonzero_pass_rc"
  cat "$SUMMARY_NONZERO_PASS"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 29
  and .failure_substep == "track:m4_runtime_actuation_promotion_live_archive_and_pack"
  and .tracks[1].status == "fail"
  and .tracks[1].rc == 29
  and .tracks[1].contract.valid == false
  and .tracks[1].contract.failure_reason == "helper process exited non-zero (run_rc=29)"
  and .tracks[1].contract.run_rc == 29
  and .tracks[1].contract.observed_status == "pass"
  and .tracks[1].contract.observed_rc == 0
' "$SUMMARY_NONZERO_PASS" >/dev/null; then
  echo "nonzero-pass fail-closed summary mismatch"
  cat "$SUMMARY_NONZERO_PASS"
  exit 1
fi

echo "[roadmap-live-promotion-closure-run] run_rc mismatch is fail-closed"
SUMMARY_MISMATCH="$TMP_DIR/summary_mismatch.json"
: >"$CAPTURE_LOG"
set +e
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M2_SCRIPT="$FAKE_M2_SCRIPT" \
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M4_SCRIPT="$FAKE_M4_SCRIPT" \
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M5_SCRIPT="$FAKE_M5_SCRIPT" \
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M5_VM_COMMAND_FILE="$VM_COMMAND_FILE_REAL" \
FAKE_CAPTURE_FILE="$CAPTURE_LOG" \
FAKE_M2_BEHAVIOR=pass \
FAKE_M4_BEHAVIOR=summary_fail_exit_zero \
FAKE_M4_RC=41 \
FAKE_M5_BEHAVIOR=pass \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/reports_mismatch" \
  --summary-json "$SUMMARY_MISMATCH" \
  --host-a 198.51.100.30 \
  --host-b 198.51.100.31 \
  --campaign-subject inv-real-004 \
  --print-summary-json 0
mismatch_rc=$?
set -e

if [[ "$mismatch_rc" != "125" ]]; then
  echo "expected run_rc mismatch fail-closed rc=125, got rc=$mismatch_rc"
  cat "$SUMMARY_MISMATCH"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 125
  and .failure_substep == "track:m4_runtime_actuation_promotion_live_archive_and_pack"
  and .tracks[1].status == "fail"
  and .tracks[1].rc == 125
  and .tracks[1].contract.valid == false
  and .tracks[1].contract.failure_reason == "summary rc mismatch: observed_rc=41 run_rc=0"
  and .tracks[1].contract.run_rc == 0
  and .tracks[1].contract.observed_status == "fail"
  and .tracks[1].contract.observed_rc == 41
' "$SUMMARY_MISMATCH" >/dev/null; then
  echo "run_rc mismatch summary mismatch"
  cat "$SUMMARY_MISMATCH"
  exit 1
fi

echo "[roadmap-live-promotion-closure-run] missing helper is fail-closed before execution"
SUMMARY_MISSING_HELPER="$TMP_DIR/summary_missing_helper.json"
MISSING_M4_SCRIPT="$STUB_DIR/missing_m4_helper.sh"
: >"$CAPTURE_LOG"
set +e
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M2_SCRIPT="$FAKE_M2_SCRIPT" \
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M4_SCRIPT="$MISSING_M4_SCRIPT" \
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M5_SCRIPT="$FAKE_M5_SCRIPT" \
ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M5_VM_COMMAND_FILE="$VM_COMMAND_FILE_REAL" \
FAKE_CAPTURE_FILE="$CAPTURE_LOG" \
FAKE_M2_BEHAVIOR=pass \
FAKE_M5_BEHAVIOR=pass \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/reports_missing_helper" \
  --summary-json "$SUMMARY_MISSING_HELPER" \
  --host-a 198.51.100.40 \
  --host-b 198.51.100.41 \
  --campaign-subject inv-real-005 \
  --print-summary-json 0
missing_helper_rc=$?
set -e

if [[ "$missing_helper_rc" != "2" ]]; then
  echo "expected missing-helper fail-closed rc=2, got rc=$missing_helper_rc"
  cat "$SUMMARY_MISSING_HELPER"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 2
  and .failure_substep == "preflight:helpers_missing_or_unreadable"
  and .summary.preflight_ok == false
  and .summary.total_tracks == 3
  and .summary.executed_tracks == 0
  and .summary.pass_tracks == 0
  and .summary.fail_tracks == 1
  and .summary.skipped_tracks == 2
  and .summary.missing_or_unreadable_helper_count == 1
  and ([.tracks[].status] == ["skipped","fail","skipped"])
  and .tracks[1].helper.available == false
  and .tracks[1].helper.readable == false
' "$SUMMARY_MISSING_HELPER" >/dev/null; then
  echo "missing-helper fail-closed summary mismatch"
  cat "$SUMMARY_MISSING_HELPER"
  exit 1
fi

if [[ -s "$CAPTURE_LOG" ]]; then
  echo "helper scripts should not run when preflight helper checks fail"
  cat "$CAPTURE_LOG"
  exit 1
fi

echo "roadmap live promotion closure run integration check ok"
