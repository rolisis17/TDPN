#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod rg cat; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

WRAPPER="$ROOT_DIR/scripts/phase2_linux_prod_candidate_signoff.sh"
if [[ ! -f "$WRAPPER" ]]; then
  echo "missing wrapper script: $WRAPPER"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.log"
PASS_STDOUT="$TMP_DIR/pass.stdout"
DRY_STDOUT="$TMP_DIR/dry.stdout"
DRY_OVERRIDE_STDOUT="$TMP_DIR/dry_override.stdout"
FAIL_STDOUT="$TMP_DIR/fail.stdout"
ROADMAP_FAIL_STDOUT="$TMP_DIR/roadmap_fail.stdout"

FAKE_RUN="$TMP_DIR/fake_phase2_linux_prod_candidate_run.sh"
cat >"$FAKE_RUN" <<'EOF_FAKE_RUN'
#!/usr/bin/env bash
set -euo pipefail

capture="${FAKE_SIGNOFF_CAPTURE_FILE:?}"
printf 'run\t%s\n' "$*" >>"$capture"

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

status="pass"
rc=0
if [[ "${FAKE_RUN_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc="${FAKE_RUN_FAIL_RC:-31}"
fi

if [[ -n "$summary_json" && "${FAKE_RUN_OMIT_SUMMARY:-0}" != "1" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<EOF_RUN_SUMMARY
{
  "version": 1,
  "schema": {
    "id": "phase2_linux_prod_candidate_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc
}
EOF_RUN_SUMMARY
fi

if [[ "${FAKE_RUN_FAIL:-0}" == "1" ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_RUN
chmod +x "$FAKE_RUN"

FAKE_ROADMAP="$TMP_DIR/fake_roadmap_progress_report.sh"
cat >"$FAKE_ROADMAP" <<'EOF_FAKE_ROADMAP'
#!/usr/bin/env bash
set -euo pipefail

capture="${FAKE_SIGNOFF_CAPTURE_FILE:?}"
printf 'roadmap\t%s\n' "$*" >>"$capture"

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

status="pass"
rc=0
if [[ "${FAKE_ROADMAP_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc="${FAKE_ROADMAP_FAIL_RC:-23}"
elif [[ "${FAKE_ROADMAP_WARN:-0}" == "1" ]]; then
  status="warn"
  rc=0
fi

if [[ -n "$summary_json" && "${FAKE_ROADMAP_INVALID_SUMMARY:-0}" != "1" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<EOF_ROADMAP_SUMMARY
{
  "version": 1,
  "status": "$status",
  "rc": $rc,
  "vpn_track": {
    "readiness_status": "READY",
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "single_machine_ready": true
  }
}
EOF_ROADMAP_SUMMARY
elif [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<'EOF_ROADMAP_INVALID'
{
  "version": 1,
  "status": "pass",
  "rc": 0
}
EOF_ROADMAP_INVALID
fi

if [[ -n "$report_md" ]]; then
  mkdir -p "$(dirname "$report_md")"
  printf '# fake roadmap report\n' >"$report_md"
fi

if [[ "${FAKE_ROADMAP_FAIL:-0}" == "1" ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_ROADMAP
chmod +x "$FAKE_ROADMAP"

assert_capture_order() {
  local capture_file="$1"
  mapfile -t lines <"$capture_file"
  if [[ "${#lines[@]}" -ne 2 ]]; then
    echo "expected exactly two stage calls"
    cat "$capture_file"
    exit 1
  fi
  if [[ "${lines[0]}" != run$'\t'* || "${lines[1]}" != roadmap$'\t'* ]]; then
    echo "unexpected stage order"
    cat "$capture_file"
    exit 1
  fi
}

assert_wrapper_summary() {
  local summary_json="$1"
  shift
  jq -e "$@" "$summary_json" >/dev/null
}

echo "[signoff] explicit pass path"
: >"$CAPTURE"
PASS_WRAPPER_SUMMARY="$TMP_DIR/pass_wrapper_summary.json"
PASS_RUN_SUMMARY="$TMP_DIR/pass_run_summary.json"
PASS_ROADMAP_SUMMARY="$TMP_DIR/pass_roadmap_summary.json"
PASS_ROADMAP_REPORT="$TMP_DIR/pass_roadmap_report.md"
FAKE_SIGNOFF_CAPTURE_FILE="$CAPTURE" \
PHASE2_LINUX_PROD_CANDIDATE_RUN_SCRIPT="$FAKE_RUN" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
bash "$WRAPPER" \
  --run-summary-json "$PASS_RUN_SUMMARY" \
  --roadmap-summary-json "$PASS_ROADMAP_SUMMARY" \
  --roadmap-report-md "$PASS_ROADMAP_REPORT" \
  --summary-json "$PASS_WRAPPER_SUMMARY" \
  --print-summary-json 0 \
  --run-alpha 17 \
  --roadmap-beta two >"$PASS_STDOUT" 2>&1

assert_capture_order "$CAPTURE"
if ! rg -q -- '--alpha 17' "$CAPTURE"; then
  echo "missing forwarded run arg"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--beta two' "$CAPTURE"; then
  echo "missing forwarded roadmap arg"
  cat "$CAPTURE"
  exit 1
fi
if ! jq -e --arg run_summary "$PASS_RUN_SUMMARY" --arg roadmap_summary "$PASS_ROADMAP_SUMMARY" --arg roadmap_report "$PASS_ROADMAP_REPORT" '
  .version == 1
  and .schema.id == "phase2_linux_prod_candidate_signoff_summary"
  and .schema.major == 1
  and .status == "pass"
  and .rc == 0
  and .steps.phase2_linux_prod_candidate_run.status == "pass"
  and .steps.phase2_linux_prod_candidate_run.rc == 0
  and .steps.phase2_linux_prod_candidate_run.command_rc == 0
  and .steps.phase2_linux_prod_candidate_run.contract_valid == true
  and .steps.phase2_linux_prod_candidate_run.artifacts.summary_json == $run_summary
  and .steps.phase2_linux_prod_candidate_run.artifacts.summary_exists == true
  and (.steps.phase2_linux_prod_candidate_run.command | contains("--alpha 17"))
  and .steps.roadmap_progress_report.status == "pass"
  and .steps.roadmap_progress_report.rc == 0
  and .steps.roadmap_progress_report.command_rc == 0
  and .steps.roadmap_progress_report.contract_valid == true
  and .steps.roadmap_progress_report.artifacts.summary_json == $roadmap_summary
  and .steps.roadmap_progress_report.artifacts.summary_exists == true
  and .steps.roadmap_progress_report.artifacts.report_md == $roadmap_report
  and .steps.roadmap_progress_report.artifacts.report_exists == true
  and (.steps.roadmap_progress_report.command | contains("--beta two"))
  and .decision.pass == true
  and (.decision.reason_details | length) == 0
  and (.decision.warnings | length) == 0
' "$PASS_WRAPPER_SUMMARY" >/dev/null; then
  echo "pass path wrapper summary contract mismatch"
  cat "$PASS_WRAPPER_SUMMARY"
  exit 1
fi

echo "[signoff] dry-run default minimal-no-refresh path"
: >"$CAPTURE"
DRY_REPORTS_DIR="$TMP_DIR/dry_reports"
DRY_WRAPPER_SUMMARY="$DRY_REPORTS_DIR/phase2_linux_prod_candidate_signoff_summary.json"
DRY_RUN_SUMMARY="$DRY_REPORTS_DIR/phase2_linux_prod_candidate_run_summary.json"
DRY_ROADMAP_SUMMARY="$DRY_REPORTS_DIR/roadmap_progress_summary.json"
DRY_ROADMAP_REPORT="$DRY_REPORTS_DIR/roadmap_progress_report.md"
FAKE_SIGNOFF_CAPTURE_FILE="$CAPTURE" \
PHASE2_LINUX_PROD_CANDIDATE_RUN_SCRIPT="$FAKE_RUN" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
bash "$WRAPPER" \
  --reports-dir "$DRY_REPORTS_DIR" \
  --summary-json "$DRY_WRAPPER_SUMMARY" \
  --dry-run 1 \
  --print-summary-json 0 \
  --run-gamma 9 \
  --roadmap-delta four >"$DRY_STDOUT" 2>&1

assert_capture_order "$CAPTURE"
if ! rg -q -- '--dry-run 1' "$CAPTURE"; then
  echo "missing forwarded dry-run to run stage"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--gamma 9' "$CAPTURE"; then
  echo "missing forwarded dry-run run arg"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- "--summary-json $DRY_RUN_SUMMARY" "$CAPTURE"; then
  echo "missing reports-dir derived run summary path"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--refresh-manual-validation 0' "$CAPTURE" || ! rg -q -- '--refresh-single-machine-readiness 0' "$CAPTURE"; then
  echo "missing dry-run roadmap no-refresh defaults"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- "--phase2-linux-prod-candidate-summary-json $DRY_RUN_SUMMARY" "$CAPTURE"; then
  echo "missing dry-run roadmap handoff summary path"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--delta four' "$CAPTURE"; then
  echo "missing forwarded dry-run roadmap arg"
  cat "$CAPTURE"
  exit 1
fi
if ! jq -e --arg run_summary "$DRY_RUN_SUMMARY" --arg roadmap_summary "$DRY_ROADMAP_SUMMARY" --arg roadmap_report "$DRY_ROADMAP_REPORT" '
  .version == 1
  and .schema.id == "phase2_linux_prod_candidate_signoff_summary"
  and .status == "pass"
  and .rc == 0
  and .inputs.dry_run == true
  and .steps.phase2_linux_prod_candidate_run.contract_valid == true
  and .steps.phase2_linux_prod_candidate_run.artifacts.summary_json == $run_summary
  and (.steps.phase2_linux_prod_candidate_run.command | contains("--dry-run 1"))
  and .steps.roadmap_progress_report.contract_valid == true
  and .steps.roadmap_progress_report.artifacts.summary_json == $roadmap_summary
  and .steps.roadmap_progress_report.artifacts.report_md == $roadmap_report
  and (.steps.roadmap_progress_report.command | contains("--refresh-manual-validation 0"))
  and (.steps.roadmap_progress_report.command | contains("--refresh-single-machine-readiness 0"))
  and .decision.pass == true
  and (.decision.reason_details | length) == 0
' "$DRY_WRAPPER_SUMMARY" >/dev/null; then
  echo "dry-run default wrapper summary contract mismatch"
  cat "$DRY_WRAPPER_SUMMARY"
  exit 1
fi

echo "[signoff] dry-run explicit override path"
: >"$CAPTURE"
DRY_OVERRIDE_REPORTS_DIR="$TMP_DIR/dry_override_reports"
DRY_OVERRIDE_WRAPPER_SUMMARY="$DRY_OVERRIDE_REPORTS_DIR/phase2_linux_prod_candidate_signoff_summary.json"
DRY_OVERRIDE_RUN_SUMMARY="$DRY_OVERRIDE_REPORTS_DIR/phase2_linux_prod_candidate_run_summary.json"
DRY_OVERRIDE_ROADMAP_SUMMARY="$DRY_OVERRIDE_REPORTS_DIR/roadmap_progress_summary.json"
FAKE_SIGNOFF_CAPTURE_FILE="$CAPTURE" \
PHASE2_LINUX_PROD_CANDIDATE_RUN_SCRIPT="$FAKE_RUN" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
bash "$WRAPPER" \
  --reports-dir "$DRY_OVERRIDE_REPORTS_DIR" \
  --summary-json "$DRY_OVERRIDE_WRAPPER_SUMMARY" \
  --dry-run 1 \
  --roadmap-refresh-manual-validation 1 \
  --roadmap-refresh-single-machine-readiness 1 \
  --print-summary-json 0 >"$DRY_OVERRIDE_STDOUT" 2>&1

assert_capture_order "$CAPTURE"
if ! rg -q -- '--refresh-manual-validation 1' "$CAPTURE" || ! rg -q -- '--refresh-single-machine-readiness 1' "$CAPTURE"; then
  echo "explicit dry-run overrides were not forwarded"
  cat "$CAPTURE"
  exit 1
fi
if rg -q -- '--refresh-manual-validation 0' "$CAPTURE" || rg -q -- '--refresh-single-machine-readiness 0' "$CAPTURE"; then
  echo "explicit dry-run overrides were shadowed by wrapper defaults"
  cat "$CAPTURE"
  exit 1
fi
if ! jq -e --arg run_summary "$DRY_OVERRIDE_RUN_SUMMARY" --arg roadmap_summary "$DRY_OVERRIDE_ROADMAP_SUMMARY" '
  .status == "pass"
  and .rc == 0
  and .inputs.dry_run == true
  and .steps.phase2_linux_prod_candidate_run.artifacts.summary_json == $run_summary
  and .steps.roadmap_progress_report.artifacts.summary_json == $roadmap_summary
  and (.steps.roadmap_progress_report.command | contains("--refresh-manual-validation 1"))
  and (.steps.roadmap_progress_report.command | contains("--refresh-single-machine-readiness 1"))
  and .decision.pass == true
' "$DRY_OVERRIDE_WRAPPER_SUMMARY" >/dev/null; then
  echo "dry-run explicit override wrapper summary mismatch"
  cat "$DRY_OVERRIDE_WRAPPER_SUMMARY"
  exit 1
fi

echo "[signoff] run failure still executes roadmap stage"
: >"$CAPTURE"
FAIL_WRAPPER_SUMMARY="$TMP_DIR/fail_wrapper_summary.json"
FAIL_RUN_SUMMARY="$TMP_DIR/fail_run_summary.json"
FAIL_ROADMAP_SUMMARY="$TMP_DIR/fail_roadmap_summary.json"
FAIL_ROADMAP_REPORT="$TMP_DIR/fail_roadmap_report.md"
set +e
FAKE_SIGNOFF_CAPTURE_FILE="$CAPTURE" \
PHASE2_LINUX_PROD_CANDIDATE_RUN_SCRIPT="$FAKE_RUN" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
FAKE_RUN_FAIL=1 \
FAKE_RUN_FAIL_RC=31 \
bash "$WRAPPER" \
  --run-summary-json "$FAIL_RUN_SUMMARY" \
  --roadmap-summary-json "$FAIL_ROADMAP_SUMMARY" \
  --roadmap-report-md "$FAIL_ROADMAP_REPORT" \
  --summary-json "$FAIL_WRAPPER_SUMMARY" \
  --print-summary-json 0 >"$FAIL_STDOUT" 2>&1
FAIL_RC=$?
set -e
if [[ "$FAIL_RC" -ne 31 ]]; then
  echo "expected run failure rc to win, got $FAIL_RC"
  cat "$FAIL_STDOUT"
  exit 1
fi
assert_capture_order "$CAPTURE"
if ! jq -e --arg run_summary "$FAIL_RUN_SUMMARY" --arg roadmap_summary "$FAIL_ROADMAP_SUMMARY" '
  .status == "fail"
  and .rc == 31
  and .steps.phase2_linux_prod_candidate_run.status == "fail"
  and .steps.phase2_linux_prod_candidate_run.rc == 31
  and .steps.phase2_linux_prod_candidate_run.command_rc == 31
  and .steps.phase2_linux_prod_candidate_run.contract_valid == true
  and .steps.phase2_linux_prod_candidate_run.artifacts.summary_json == $run_summary
  and .steps.roadmap_progress_report.status == "pass"
  and .steps.roadmap_progress_report.rc == 0
  and .steps.roadmap_progress_report.command_rc == 0
  and .steps.roadmap_progress_report.contract_valid == true
  and .steps.roadmap_progress_report.artifacts.summary_json == $roadmap_summary
  and .decision.pass == false
  and ((.decision.reason_details // []) | any(.code == "run_step_not_pass"))
  and ((.decision.reason_codes // []) | index("run_step_not_pass") != null)
' "$FAIL_WRAPPER_SUMMARY" >/dev/null; then
  echo "run-failure wrapper summary mismatch"
  cat "$FAIL_WRAPPER_SUMMARY"
  exit 1
fi

echo "[signoff] roadmap contract failure is fail-closed"
: >"$CAPTURE"
ROADMAP_FAIL_WRAPPER_SUMMARY="$TMP_DIR/roadmap_fail_wrapper_summary.json"
ROADMAP_FAIL_RUN_SUMMARY="$TMP_DIR/roadmap_fail_run_summary.json"
ROADMAP_FAIL_SUMMARY="$TMP_DIR/roadmap_fail_summary.json"
ROADMAP_FAIL_REPORT="$TMP_DIR/roadmap_fail_report.md"
set +e
FAKE_SIGNOFF_CAPTURE_FILE="$CAPTURE" \
PHASE2_LINUX_PROD_CANDIDATE_RUN_SCRIPT="$FAKE_RUN" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
FAKE_ROADMAP_INVALID_SUMMARY=1 \
bash "$WRAPPER" \
  --run-summary-json "$ROADMAP_FAIL_RUN_SUMMARY" \
  --roadmap-summary-json "$ROADMAP_FAIL_SUMMARY" \
  --roadmap-report-md "$ROADMAP_FAIL_REPORT" \
  --summary-json "$ROADMAP_FAIL_WRAPPER_SUMMARY" \
  --print-summary-json 0 >"$ROADMAP_FAIL_STDOUT" 2>&1
ROADMAP_FAIL_RC=$?
set -e
if [[ "$ROADMAP_FAIL_RC" -ne 3 ]]; then
  echo "expected roadmap contract failure rc=3, got $ROADMAP_FAIL_RC"
  cat "$ROADMAP_FAIL_STDOUT"
  exit 1
fi
assert_capture_order "$CAPTURE"
if ! jq -e --arg run_summary "$ROADMAP_FAIL_RUN_SUMMARY" --arg roadmap_summary "$ROADMAP_FAIL_SUMMARY" '
  .status == "fail"
  and .rc == 3
  and .steps.phase2_linux_prod_candidate_run.status == "pass"
  and .steps.phase2_linux_prod_candidate_run.contract_valid == true
  and .steps.phase2_linux_prod_candidate_run.artifacts.summary_json == $run_summary
  and .steps.roadmap_progress_report.status == "fail"
  and .steps.roadmap_progress_report.rc == 3
  and .steps.roadmap_progress_report.command_rc == 0
  and .steps.roadmap_progress_report.contract_valid == false
  and .steps.roadmap_progress_report.contract_error != null
  and .steps.roadmap_progress_report.artifacts.summary_json == $roadmap_summary
  and .decision.pass == false
  and ((.decision.reason_details // []) | any(.code == "roadmap_summary_contract_invalid"))
  and ((.decision.reason_codes // []) | index("roadmap_summary_contract_invalid") != null)
' "$ROADMAP_FAIL_WRAPPER_SUMMARY" >/dev/null; then
  echo "roadmap contract failure wrapper summary mismatch"
  cat "$ROADMAP_FAIL_WRAPPER_SUMMARY"
  exit 1
fi

echo "phase2 linux prod candidate signoff integration ok"
