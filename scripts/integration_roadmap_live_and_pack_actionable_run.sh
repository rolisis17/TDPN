#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod mkdir cat grep tail; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

mkdir -p "$ROOT_DIR/.easy-node-logs"
TMP_DIR="$(mktemp -d "$ROOT_DIR/.easy-node-logs/integration_roadmap_live_and_pack_actionable_run_XXXXXX")"
ACTION_TMP_DIR="$(mktemp -d "$ROOT_DIR/scripts/.integration_roadmap_live_and_pack_actionable_run.XXXXXX")"
trap 'rm -rf "$TMP_DIR" "$ACTION_TMP_DIR"' EXIT

FAKE_LIVE_SCRIPT="$ACTION_TMP_DIR/fake_roadmap_live_evidence_actionable_run.sh"
FAKE_ARCHIVE_SCRIPT="$ACTION_TMP_DIR/fake_roadmap_live_evidence_archive_run.sh"
FAKE_PACK_SCRIPT="$ACTION_TMP_DIR/fake_roadmap_evidence_pack_actionable_run.sh"
LIVE_CAPTURE="$TMP_DIR/live_capture.tsv"
ARCHIVE_CAPTURE="$TMP_DIR/archive_capture.tsv"
PACK_CAPTURE="$TMP_DIR/pack_capture.tsv"
SHARED_ROADMAP_SUMMARY="$TMP_DIR/shared_roadmap_summary.json"
SHARED_ROADMAP_REPORT="$TMP_DIR/shared_roadmap_report.md"

echo '{"next_actions":[]}' >"$SHARED_ROADMAP_SUMMARY"
echo "# shared roadmap report" >"$SHARED_ROADMAP_REPORT"

cat >"$FAKE_LIVE_SCRIPT" <<'EOF_FAKE_LIVE'
#!/usr/bin/env bash
set -euo pipefail

capture_file="${FAKE_LIVE_CAPTURE_FILE:?}"
argv=("$@")
summary_json=""
reports_dir=""
roadmap_summary_json=""
roadmap_report_md=""

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
    --roadmap-summary-json)
      roadmap_summary_json="${2:-}"
      shift 2
      ;;
    --roadmap-report-md)
      roadmap_report_md="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

{
  printf 'argc=%s' "${#argv[@]}"
  for arg in "${argv[@]}"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"

if [[ -n "$reports_dir" ]]; then
  mkdir -p "$reports_dir"
fi

if [[ "${FAKE_LIVE_WRITE_SUMMARY:-1}" == "1" ]]; then
  if [[ -z "$summary_json" ]]; then
    echo "fake live: missing --summary-json"
    exit 2
  fi

  mkdir -p "$(dirname "$summary_json")"

  summary_rc="${FAKE_LIVE_SUMMARY_RC:-${FAKE_LIVE_RC:-0}}"
  summary_status="${FAKE_LIVE_STATUS:-}"
  if [[ -z "$summary_status" ]]; then
    if (( summary_rc == 0 )); then
      summary_status="pass"
    else
      summary_status="fail"
    fi
  fi

  if [[ -z "$roadmap_summary_json" ]]; then
    roadmap_summary_json="${FAKE_SHARED_ROADMAP_SUMMARY_JSON:-}"
  fi
  if [[ -z "$roadmap_report_md" ]]; then
    roadmap_report_md="${FAKE_SHARED_ROADMAP_REPORT_MD:-}"
  fi

  selected_action_ids_json="${FAKE_LIVE_SELECTED_IDS_JSON:-[]}"
  selected_actions_count="${FAKE_LIVE_SELECTED_COUNT:-}"
  if [[ -z "$selected_actions_count" ]]; then
    selected_actions_count="$(printf '%s\n' "$selected_action_ids_json" | jq -r 'length')"
  fi
  actions_executed="${FAKE_LIVE_ACTIONS_EXECUTED:-$selected_actions_count}"
  pass_count="${FAKE_LIVE_PASS:-}"
  fail_count="${FAKE_LIVE_FAIL:-}"
  if [[ -z "$pass_count" ]]; then
    if (( summary_rc == 0 )); then
      pass_count="$actions_executed"
    else
      pass_count="0"
    fi
  fi
  if [[ -z "$fail_count" ]]; then
    fail_count=$((actions_executed - pass_count))
    if (( fail_count < 0 )); then
      fail_count=0
    fi
  fi
  timed_out_count="${FAKE_LIVE_TIMED_OUT:-0}"
  soft_failed_count="${FAKE_LIVE_SOFT_FAILED:-0}"

  jq -n \
    --arg status "$summary_status" \
    --argjson rc "$summary_rc" \
    --argjson selected_action_ids "$selected_action_ids_json" \
    --argjson selected_actions_count "$selected_actions_count" \
    --argjson actions_executed "$actions_executed" \
    --argjson pass "$pass_count" \
    --argjson fail "$fail_count" \
    --argjson timed_out "$timed_out_count" \
    --argjson soft_failed "$soft_failed_count" \
    --arg roadmap_summary_json "$roadmap_summary_json" \
    --arg roadmap_report_md "$roadmap_report_md" \
    '{
      status: $status,
      rc: $rc,
      roadmap: {
        actions_selected_count: $selected_actions_count,
        selected_action_ids: $selected_action_ids
      },
      summary: {
        actions_executed: $actions_executed,
        pass: $pass,
        fail: $fail,
        timed_out: $timed_out,
        soft_failed: $soft_failed
      },
      actions: [],
      artifacts: {
        roadmap_summary_json: (if $roadmap_summary_json == "" then null else $roadmap_summary_json end),
        roadmap_report_md: (if $roadmap_report_md == "" then null else $roadmap_report_md end)
      }
    }' >"$summary_json"
fi

exit "${FAKE_LIVE_RC:-0}"
EOF_FAKE_LIVE
chmod +x "$FAKE_LIVE_SCRIPT"

cat >"$FAKE_ARCHIVE_SCRIPT" <<'EOF_FAKE_ARCHIVE'
#!/usr/bin/env bash
set -euo pipefail

capture_file="${FAKE_ARCHIVE_CAPTURE_FILE:?}"
argv=("$@")
summary_json=""
reports_dir=""
roadmap_summary_json=""
archive_root=""
scope=""

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
    --roadmap-summary-json)
      roadmap_summary_json="${2:-}"
      shift 2
      ;;
    --archive-root)
      archive_root="${2:-}"
      shift 2
      ;;
    --scope)
      scope="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

{
  printf 'argc=%s' "${#argv[@]}"
  for arg in "${argv[@]}"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"

if [[ -n "$reports_dir" ]]; then
  mkdir -p "$reports_dir"
fi
if [[ -n "$archive_root" ]]; then
  mkdir -p "$archive_root"
fi

if [[ "${FAKE_ARCHIVE_WRITE_SUMMARY:-1}" == "1" ]]; then
  if [[ -z "$summary_json" ]]; then
    echo "fake archive: missing --summary-json"
    exit 2
  fi
  mkdir -p "$(dirname "$summary_json")"

  summary_rc="${FAKE_ARCHIVE_SUMMARY_RC:-${FAKE_ARCHIVE_RC:-0}}"
  summary_status="${FAKE_ARCHIVE_STATUS:-}"
  if [[ -z "$summary_status" ]]; then
    if (( summary_rc == 0 )); then
      summary_status="pass"
    else
      summary_status="fail"
    fi
  fi

  candidate_total="${FAKE_ARCHIVE_CANDIDATE_TOTAL:-3}"
  copied_total="${FAKE_ARCHIVE_COPIED_TOTAL:-3}"
  missing_total="${FAKE_ARCHIVE_MISSING_TOTAL:-0}"
  copy_error_total="${FAKE_ARCHIVE_COPY_ERROR_TOTAL:-0}"
  missing_family_count="${FAKE_ARCHIVE_MISSING_FAMILY_COUNT:-0}"
  archive_dir="${FAKE_ARCHIVE_DIR:-$archive_root/archive_bundle}"

  jq -n \
    --arg status "$summary_status" \
    --argjson rc "$summary_rc" \
    --argjson candidate_total "$candidate_total" \
    --argjson copied_total "$copied_total" \
    --argjson missing_total "$missing_total" \
    --argjson copy_error_total "$copy_error_total" \
    --argjson missing_family_count "$missing_family_count" \
    --arg roadmap_summary_json "$roadmap_summary_json" \
    --arg archive_root "$archive_root" \
    --arg archive_dir "$archive_dir" \
    --arg scope "$scope" \
    '{
      status: $status,
      rc: $rc,
      scope: { resolved: $scope },
      summary: {
        candidate_total: $candidate_total,
        copied_total: $copied_total,
        missing_total: $missing_total,
        copy_error_total: $copy_error_total,
        missing_family_count: $missing_family_count
      },
      artifacts: {
        roadmap_summary_json: (if $roadmap_summary_json == "" then null else $roadmap_summary_json end),
        archive_root: (if $archive_root == "" then null else $archive_root end),
        archive_dir: (if $archive_dir == "" then null else $archive_dir end)
      }
    }' >"$summary_json"
fi

exit "${FAKE_ARCHIVE_RC:-0}"
EOF_FAKE_ARCHIVE
chmod +x "$FAKE_ARCHIVE_SCRIPT"

cat >"$FAKE_PACK_SCRIPT" <<'EOF_FAKE_PACK'
#!/usr/bin/env bash
set -euo pipefail

capture_file="${FAKE_PACK_CAPTURE_FILE:?}"
argv=("$@")
summary_json=""
reports_dir=""
roadmap_summary_json=""
roadmap_report_md=""
live_evidence_summary_json=""
require_live_derived_evidence_pack_actions="0"

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
    --roadmap-summary-json)
      roadmap_summary_json="${2:-}"
      shift 2
      ;;
    --roadmap-report-md)
      roadmap_report_md="${2:-}"
      shift 2
      ;;
    --live-evidence-summary-json)
      live_evidence_summary_json="${2:-}"
      shift 2
      ;;
    --require-live-derived-evidence-pack-actions)
      require_live_derived_evidence_pack_actions="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

{
  printf 'argc=%s' "${#argv[@]}"
  for arg in "${argv[@]}"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"

if [[ -n "$reports_dir" ]]; then
  mkdir -p "$reports_dir"
fi

required_live_check_failure=0
required_live_check_reason=""
if [[ "${FAKE_PACK_ENFORCE_REQUIRED_LIVE_SUMMARY:-1}" == "1" && "$require_live_derived_evidence_pack_actions" == "1" ]]; then
  if [[ -z "$live_evidence_summary_json" ]]; then
    required_live_check_failure=1
    required_live_check_reason="required_live_evidence_summary_not_provided"
  elif [[ ! -f "$live_evidence_summary_json" ]] || ! jq -e 'type == "object"' "$live_evidence_summary_json" >/dev/null 2>&1; then
    required_live_check_failure=1
    required_live_check_reason="required_live_evidence_summary_invalid"
  fi
fi

if [[ "${FAKE_PACK_WRITE_SUMMARY:-1}" == "1" ]]; then
  if [[ -z "$summary_json" ]]; then
    echo "fake pack: missing --summary-json"
    exit 2
  fi

  mkdir -p "$(dirname "$summary_json")"

  if (( required_live_check_failure == 1 )); then
    summary_rc="${FAKE_PACK_REQUIRED_LIVE_RC:-4}"
  else
    summary_rc="${FAKE_PACK_SUMMARY_RC:-${FAKE_PACK_RC:-0}}"
  fi
  summary_status="${FAKE_PACK_STATUS:-}"
  if [[ -z "$summary_status" ]]; then
    if (( summary_rc == 0 )); then
      summary_status="pass"
    else
      summary_status="fail"
    fi
  fi

  selected_action_ids_json="${FAKE_PACK_SELECTED_IDS_JSON:-[]}"
  selected_actions_count="${FAKE_PACK_SELECTED_COUNT:-}"
  if [[ -z "$selected_actions_count" ]]; then
    selected_actions_count="$(printf '%s\n' "$selected_action_ids_json" | jq -r 'length')"
  fi
  actions_executed="${FAKE_PACK_ACTIONS_EXECUTED:-$selected_actions_count}"
  pass_count="${FAKE_PACK_PASS:-}"
  fail_count="${FAKE_PACK_FAIL:-}"
  if [[ -z "$pass_count" ]]; then
    if (( summary_rc == 0 )); then
      pass_count="$actions_executed"
    else
      pass_count="0"
    fi
  fi
  if [[ -z "$fail_count" ]]; then
    fail_count=$((actions_executed - pass_count))
    if (( fail_count < 0 )); then
      fail_count=0
    fi
  fi
  timed_out_count="${FAKE_PACK_TIMED_OUT:-0}"
  soft_failed_count="${FAKE_PACK_SOFT_FAILED:-0}"

  jq -n \
    --arg status "$summary_status" \
    --argjson rc "$summary_rc" \
    --argjson selected_action_ids "$selected_action_ids_json" \
    --argjson selected_actions_count "$selected_actions_count" \
    --argjson actions_executed "$actions_executed" \
    --argjson pass "$pass_count" \
    --argjson fail "$fail_count" \
    --argjson timed_out "$timed_out_count" \
    --argjson soft_failed "$soft_failed_count" \
    --arg roadmap_summary_json "$roadmap_summary_json" \
    --arg roadmap_report_md "$roadmap_report_md" \
    --arg live_evidence_summary_json "$live_evidence_summary_json" \
    --arg required_live_check_reason "$required_live_check_reason" \
    '{
      status: $status,
      rc: $rc,
      roadmap: {
        actions_selected_count: $selected_actions_count,
        selected_action_ids: $selected_action_ids
      },
      summary: {
        actions_executed: $actions_executed,
        pass: $pass,
        fail: $fail,
        timed_out: $timed_out,
        soft_failed: $soft_failed
      },
      actions: [],
      enforcement: {
        live_evidence_summary_json: (if $live_evidence_summary_json == "" then null else $live_evidence_summary_json end),
        required_live_check_reason: (if $required_live_check_reason == "" then null else $required_live_check_reason end)
      },
      artifacts: {
        roadmap_summary_json: (if $roadmap_summary_json == "" then null else $roadmap_summary_json end),
        roadmap_report_md: (if $roadmap_report_md == "" then null else $roadmap_report_md end)
      }
    }' >"$summary_json"
fi

if (( required_live_check_failure == 1 )); then
  echo "fake pack: required live summary check failed ($required_live_check_reason)" >&2
  exit "${FAKE_PACK_REQUIRED_LIVE_RC:-4}"
fi

exit "${FAKE_PACK_RC:-0}"
EOF_FAKE_PACK
chmod +x "$FAKE_PACK_SCRIPT"

assert_token() {
  local line="$1"
  local token="$2"
  local message="$3"
  if [[ "$line" != *"$token"* ]]; then
    echo "$message"
    echo "line: $line"
    echo "live capture:"
    cat "$LIVE_CAPTURE" 2>/dev/null || true
    echo "archive capture:"
    cat "$ARCHIVE_CAPTURE" 2>/dev/null || true
    echo "pack capture:"
    cat "$PACK_CAPTURE" 2>/dev/null || true
    exit 1
  fi
}

echo "[roadmap-live-and-pack-actionable-run] help contract"
if ! bash ./scripts/roadmap_live_and_pack_actionable_run.sh --help | grep -F -- "--reports-dir DIR" >/dev/null; then
  echo "help output missing --reports-dir DIR"
  exit 1
fi
if ! bash ./scripts/roadmap_live_and_pack_actionable_run.sh --help | grep -F -- "--summary-json PATH" >/dev/null; then
  echo "help output missing --summary-json PATH"
  exit 1
fi
if ! bash ./scripts/roadmap_live_and_pack_actionable_run.sh --help | grep -F -- "--roadmap-summary-json PATH" >/dev/null; then
  echo "help output missing --roadmap-summary-json PATH"
  exit 1
fi
if ! bash ./scripts/roadmap_live_and_pack_actionable_run.sh --help | grep -F -- "--roadmap-report-md PATH" >/dev/null; then
  echo "help output missing --roadmap-report-md PATH"
  exit 1
fi
if ! bash ./scripts/roadmap_live_and_pack_actionable_run.sh --help | grep -F -- "--run-live-archive [0|1]" >/dev/null; then
  echo "help output missing --run-live-archive [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_live_and_pack_actionable_run.sh --help | grep -F -- "--archive-root DIR" >/dev/null; then
  echo "help output missing --archive-root DIR"
  exit 1
fi
if ! bash ./scripts/roadmap_live_and_pack_actionable_run.sh --help | grep -F -- "--action-timeout-sec N" >/dev/null; then
  echo "help output missing --action-timeout-sec N"
  exit 1
fi
if ! bash ./scripts/roadmap_live_and_pack_actionable_run.sh --help | grep -F -- "--refresh-manual-validation [0|1]" >/dev/null; then
  echo "help output missing --refresh-manual-validation [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_live_and_pack_actionable_run.sh --help | grep -F -- "--refresh-single-machine-readiness [0|1]" >/dev/null; then
  echo "help output missing --refresh-single-machine-readiness [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_live_and_pack_actionable_run.sh --help | grep -F -- "--scope auto|all|profile-default|runtime-actuation|multi-vm" >/dev/null; then
  echo "help output missing --scope auto|all|profile-default|runtime-actuation|multi-vm"
  exit 1
fi
if ! bash ./scripts/roadmap_live_and_pack_actionable_run.sh --help | grep -F -- "--parallel [0|1]" >/dev/null; then
  echo "help output missing --parallel [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_live_and_pack_actionable_run.sh --help | grep -F -- "--max-actions N" >/dev/null; then
  echo "help output missing --max-actions N"
  exit 1
fi
if ! bash ./scripts/roadmap_live_and_pack_actionable_run.sh --help | grep -F -- "--continue-on-live-fail [0|1]" >/dev/null; then
  echo "help output missing --continue-on-live-fail [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_live_and_pack_actionable_run.sh --help | grep -F -- "--print-summary-json [0|1]" >/dev/null; then
  echo "help output missing --print-summary-json [0|1]"
  exit 1
fi

echo "[roadmap-live-and-pack-actionable-run] success path runs live then evidence-pack"
SUMMARY_SUCCESS="$TMP_DIR/summary_success.json"
REPORTS_SUCCESS="$TMP_DIR/reports_success"
: >"$LIVE_CAPTURE"
: >"$ARCHIVE_CAPTURE"
: >"$PACK_CAPTURE"
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_LIVE_SCRIPT="$FAKE_LIVE_SCRIPT" \
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_ARCHIVE_SCRIPT="$FAKE_ARCHIVE_SCRIPT" \
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_LIVE_CAPTURE_FILE="$LIVE_CAPTURE" \
FAKE_ARCHIVE_CAPTURE_FILE="$ARCHIVE_CAPTURE" \
FAKE_PACK_CAPTURE_FILE="$PACK_CAPTURE" \
FAKE_SHARED_ROADMAP_SUMMARY_JSON="$SHARED_ROADMAP_SUMMARY" \
FAKE_SHARED_ROADMAP_REPORT_MD="$SHARED_ROADMAP_REPORT" \
FAKE_LIVE_RC=0 FAKE_LIVE_SUMMARY_RC=0 FAKE_LIVE_SELECTED_IDS_JSON='["profile_default_gate","runtime_actuation_promotion"]' FAKE_LIVE_SELECTED_COUNT=2 FAKE_LIVE_ACTIONS_EXECUTED=2 FAKE_LIVE_PASS=2 FAKE_LIVE_FAIL=0 \
FAKE_PACK_RC=0 FAKE_PACK_SUMMARY_RC=0 FAKE_PACK_SELECTED_IDS_JSON='["profile_default_gate_evidence_pack"]' FAKE_PACK_SELECTED_COUNT=1 FAKE_PACK_ACTIONS_EXECUTED=1 FAKE_PACK_PASS=1 FAKE_PACK_FAIL=0 \
bash ./scripts/roadmap_live_and_pack_actionable_run.sh \
  --reports-dir "$REPORTS_SUCCESS" \
  --summary-json "$SUMMARY_SUCCESS" \
  --refresh-manual-validation 1 \
  --refresh-single-machine-readiness 1 \
  --parallel 1 \
  --max-actions 3 \
  --action-timeout-sec 33 \
  --print-summary-json 0

if ! jq -e '
  .version == 1
  and .schema.id == "roadmap_live_and_pack_actionable_run_summary"
  and .status == "pass"
  and .rc == 0
  and .failure_substep == null
  and .inputs.refresh_manual_validation == true
  and .inputs.refresh_single_machine_readiness == true
  and .inputs.parallel == true
  and .inputs.scope == "auto"
  and .inputs.max_actions == 3
  and .inputs.action_timeout_sec == 33
  and .inputs.continue_on_live_fail == false
  and .inputs.run_live_archive == false
  and .steps.live_evidence.status == "pass"
  and .steps.live_evidence.rc == 0
  and .steps.live_evidence.summary_valid == true
  and .steps.live_evidence.contract_valid == true
  and .steps.live_evidence.contract_failure_reason == null
  and .steps.live_evidence.selected_actions_count == 2
  and .steps.live_evidence.selected_action_ids == ["profile_default_gate","runtime_actuation_promotion"]
  and .steps.live_evidence_archive.attempted == false
  and .steps.live_evidence_archive.status == "skipped"
  and .steps.live_evidence_archive.skip_reason == "archive_not_requested"
  and .steps.live_evidence_archive.summary_valid == false
  and .steps.live_evidence_archive.rc == null
  and .steps.evidence_pack.status == "pass"
  and .steps.evidence_pack.rc == 0
  and .steps.evidence_pack.summary_valid == true
  and .steps.evidence_pack.contract_valid == true
  and .steps.evidence_pack.contract_failure_reason == null
  and .steps.evidence_pack.selected_actions_count == 1
  and .steps.evidence_pack.selected_action_ids == ["profile_default_gate_evidence_pack"]
  and .summary.steps_total == 3
  and .summary.steps_executed == 2
  and .summary.steps_skipped == 1
  and .summary.steps_pass == 2
  and .summary.steps_fail == 0
  and .summary.selected_actions_total == 3
  and .summary.actions_executed_total == 3
  and .summary.pass_total == 3
  and .summary.fail_total == 0
  and (.artifacts.roadmap_summary_json | endswith("/shared_roadmap_summary.json"))
  and (.artifacts.roadmap_report_md | endswith("/shared_roadmap_report.md"))
' "$SUMMARY_SUCCESS" >/dev/null; then
  echo "success summary mismatch"
  cat "$SUMMARY_SUCCESS"
  exit 1
fi

live_line="$(tail -n 1 "$LIVE_CAPTURE" || true)"
pack_line="$(tail -n 1 "$PACK_CAPTURE" || true)"
if [[ -z "$live_line" || -z "$pack_line" ]]; then
  echo "expected both live and pack capture lines in success path"
  cat "$LIVE_CAPTURE"
  cat "$PACK_CAPTURE"
  exit 1
fi
if [[ -s "$ARCHIVE_CAPTURE" ]]; then
  echo "archive runner should not execute when --run-live-archive is disabled"
  cat "$ARCHIVE_CAPTURE"
  exit 1
fi
assert_token "$live_line" $'\t--action-timeout-sec\t33' "missing timeout forwarding to live runner"
assert_token "$live_line" $'\t--refresh-manual-validation\t1' "missing refresh-manual-validation forwarding to live runner"
assert_token "$live_line" $'\t--refresh-single-machine-readiness\t1' "missing refresh-single-machine-readiness forwarding to live runner"
assert_token "$live_line" $'\t--scope\tauto' "missing default scope forwarding to live runner"
assert_token "$live_line" $'\t--parallel\t1' "missing parallel forwarding to live runner"
assert_token "$live_line" $'\t--max-actions\t3' "missing max-actions forwarding to live runner"
assert_token "$live_line" $'\t--print-summary-json\t0' "missing print-summary-json forwarding to live runner"
assert_token "$pack_line" $'\t--roadmap-summary-json\t' "missing roadmap-summary-json forwarding to evidence-pack runner"
assert_token "$pack_line" "shared_roadmap_summary.json" "missing shared roadmap summary filename in evidence-pack forwarding"
assert_token "$pack_line" $'\t--roadmap-report-md\t' "missing roadmap-report-md forwarding to evidence-pack runner"
assert_token "$pack_line" "shared_roadmap_report.md" "missing shared roadmap report filename in evidence-pack forwarding"
assert_token "$pack_line" $'\t--scope\tauto' "missing default scope forwarding to evidence-pack runner"
assert_token "$pack_line" $'\t--action-timeout-sec\t33' "missing timeout forwarding to evidence-pack runner"
assert_token "$pack_line" $'\t--max-actions\t3' "missing max-actions forwarding to evidence-pack runner"
assert_token "$pack_line" $'\t--live-evidence-summary-json\t' "missing live-evidence-summary-json forwarding to evidence-pack runner"
assert_token "$pack_line" "$REPORTS_SUCCESS/roadmap_live_evidence_actionable_run_summary.json" "missing live summary path forwarding to evidence-pack runner"
assert_token "$pack_line" $'\t--require-live-derived-evidence-pack-actions\t1' "missing live-derived fail-closed enforcement forwarding to evidence-pack runner"

echo "[roadmap-live-and-pack-actionable-run] fail-closed path skips evidence-pack when live fails"
SUMMARY_FAIL_CLOSED="$TMP_DIR/summary_fail_closed.json"
REPORTS_FAIL_CLOSED="$TMP_DIR/reports_fail_closed"
: >"$LIVE_CAPTURE"
: >"$ARCHIVE_CAPTURE"
: >"$PACK_CAPTURE"
set +e
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_LIVE_SCRIPT="$FAKE_LIVE_SCRIPT" \
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_ARCHIVE_SCRIPT="$FAKE_ARCHIVE_SCRIPT" \
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_LIVE_CAPTURE_FILE="$LIVE_CAPTURE" \
FAKE_ARCHIVE_CAPTURE_FILE="$ARCHIVE_CAPTURE" \
FAKE_PACK_CAPTURE_FILE="$PACK_CAPTURE" \
FAKE_SHARED_ROADMAP_SUMMARY_JSON="$SHARED_ROADMAP_SUMMARY" \
FAKE_SHARED_ROADMAP_REPORT_MD="$SHARED_ROADMAP_REPORT" \
FAKE_LIVE_RC=41 FAKE_LIVE_SUMMARY_RC=41 FAKE_LIVE_SELECTED_IDS_JSON='["profile_default_gate"]' FAKE_LIVE_SELECTED_COUNT=1 FAKE_LIVE_ACTIONS_EXECUTED=1 FAKE_LIVE_PASS=0 FAKE_LIVE_FAIL=1 \
FAKE_PACK_RC=0 FAKE_PACK_SUMMARY_RC=0 FAKE_PACK_SELECTED_IDS_JSON='["profile_default_gate_evidence_pack"]' FAKE_PACK_SELECTED_COUNT=1 FAKE_PACK_ACTIONS_EXECUTED=1 FAKE_PACK_PASS=1 FAKE_PACK_FAIL=0 \
bash ./scripts/roadmap_live_and_pack_actionable_run.sh \
  --reports-dir "$REPORTS_FAIL_CLOSED" \
  --summary-json "$SUMMARY_FAIL_CLOSED" \
  --print-summary-json 0
fail_closed_rc=$?
set -e
if [[ "$fail_closed_rc" != "41" ]]; then
  echo "expected fail-closed rc=41, got rc=$fail_closed_rc"
  cat "$SUMMARY_FAIL_CLOSED"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 41
  and .failure_substep == "live_evidence_stage_failed"
  and .inputs.continue_on_live_fail == false
  and .inputs.run_live_archive == false
  and .inputs.scope == "auto"
  and .steps.live_evidence.status == "fail"
  and .steps.live_evidence.rc == 41
  and .steps.live_evidence.process_rc == 41
  and .steps.live_evidence.summary_valid == true
  and .steps.live_evidence.contract_valid == true
  and .steps.live_evidence.contract_failure_reason == null
  and .steps.live_evidence_archive.attempted == false
  and .steps.live_evidence_archive.status == "skipped"
  and .steps.live_evidence_archive.skip_reason == "archive_not_requested"
  and .steps.evidence_pack.status == "skipped"
  and .steps.evidence_pack.summary_valid == false
  and .steps.evidence_pack.skip_reason == "live_step_failed_fail_closed"
  and .steps.evidence_pack.rc == null
  and .steps.evidence_pack.process_rc == null
  and .summary.steps_total == 3
  and .summary.steps_executed == 1
  and .summary.steps_skipped == 2
  and .summary.steps_pass == 0
  and .summary.steps_fail == 1
  and .summary.selected_actions_total == 1
  and .summary.actions_executed_total == 1
  and .summary.pass_total == 0
  and .summary.fail_total == 1
' "$SUMMARY_FAIL_CLOSED" >/dev/null; then
  echo "fail-closed summary mismatch"
  cat "$SUMMARY_FAIL_CLOSED"
  exit 1
fi

if [[ -s "$PACK_CAPTURE" ]]; then
  echo "evidence-pack runner should not execute in fail-closed mode"
  cat "$PACK_CAPTURE"
  exit 1
fi
if [[ -s "$ARCHIVE_CAPTURE" ]]; then
  echo "archive runner should not execute when disabled"
  cat "$ARCHIVE_CAPTURE"
  exit 1
fi

echo "[roadmap-live-and-pack-actionable-run] continue-on-live-fail path executes evidence-pack"
SUMMARY_CONTINUE="$TMP_DIR/summary_continue.json"
REPORTS_CONTINUE="$TMP_DIR/reports_continue"
: >"$LIVE_CAPTURE"
: >"$ARCHIVE_CAPTURE"
: >"$PACK_CAPTURE"
set +e
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_LIVE_SCRIPT="$FAKE_LIVE_SCRIPT" \
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_ARCHIVE_SCRIPT="$FAKE_ARCHIVE_SCRIPT" \
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_LIVE_CAPTURE_FILE="$LIVE_CAPTURE" \
FAKE_ARCHIVE_CAPTURE_FILE="$ARCHIVE_CAPTURE" \
FAKE_PACK_CAPTURE_FILE="$PACK_CAPTURE" \
FAKE_SHARED_ROADMAP_SUMMARY_JSON="$SHARED_ROADMAP_SUMMARY" \
FAKE_SHARED_ROADMAP_REPORT_MD="$SHARED_ROADMAP_REPORT" \
FAKE_LIVE_RC=41 FAKE_LIVE_SUMMARY_RC=41 FAKE_LIVE_SELECTED_IDS_JSON='["profile_default_gate"]' FAKE_LIVE_SELECTED_COUNT=1 FAKE_LIVE_ACTIONS_EXECUTED=1 FAKE_LIVE_PASS=0 FAKE_LIVE_FAIL=1 \
FAKE_PACK_RC=0 FAKE_PACK_SUMMARY_RC=0 FAKE_PACK_SELECTED_IDS_JSON='["profile_default_gate_evidence_pack","runtime_actuation_promotion_evidence_pack"]' FAKE_PACK_SELECTED_COUNT=2 FAKE_PACK_ACTIONS_EXECUTED=2 FAKE_PACK_PASS=2 FAKE_PACK_FAIL=0 \
bash ./scripts/roadmap_live_and_pack_actionable_run.sh \
  --reports-dir "$REPORTS_CONTINUE" \
  --summary-json "$SUMMARY_CONTINUE" \
  --continue-on-live-fail 1 \
  --print-summary-json 0
continue_rc=$?
set -e
if [[ "$continue_rc" != "41" ]]; then
  echo "expected continue-on-live-fail rc=41, got rc=$continue_rc"
  cat "$SUMMARY_CONTINUE"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 41
  and .failure_substep == "live_evidence_stage_failed"
  and .inputs.continue_on_live_fail == true
  and .inputs.run_live_archive == false
  and .inputs.scope == "auto"
  and .steps.live_evidence.status == "fail"
  and .steps.live_evidence.rc == 41
  and .steps.live_evidence.contract_valid == true
  and .steps.live_evidence.contract_failure_reason == null
  and .steps.live_evidence_archive.attempted == false
  and .steps.live_evidence_archive.status == "skipped"
  and .steps.live_evidence_archive.skip_reason == "archive_not_requested"
  and .steps.evidence_pack.status == "pass"
  and .steps.evidence_pack.rc == 0
  and .steps.evidence_pack.summary_valid == true
  and .steps.evidence_pack.contract_valid == true
  and .steps.evidence_pack.contract_failure_reason == null
  and .steps.evidence_pack.skip_reason == null
  and .summary.steps_total == 3
  and .summary.steps_executed == 2
  and .summary.steps_skipped == 1
  and .summary.steps_pass == 1
  and .summary.steps_fail == 1
  and .summary.selected_actions_total == 3
  and .summary.actions_executed_total == 3
  and .summary.pass_total == 2
  and .summary.fail_total == 1
' "$SUMMARY_CONTINUE" >/dev/null; then
  echo "continue-on-live-fail summary mismatch"
  cat "$SUMMARY_CONTINUE"
  exit 1
fi

if [[ ! -s "$PACK_CAPTURE" ]]; then
  echo "expected evidence-pack runner invocation in continue-on-live-fail mode"
  exit 1
fi
continue_pack_line="$(tail -n 1 "$PACK_CAPTURE" || true)"
if [[ -z "$continue_pack_line" ]]; then
  echo "missing evidence-pack capture line in continue-on-live-fail mode"
  cat "$PACK_CAPTURE"
  exit 1
fi
assert_token "$continue_pack_line" $'\t--live-evidence-summary-json\t' "missing live-evidence-summary-json forwarding in continue-on-live-fail mode"
assert_token "$continue_pack_line" "$REPORTS_CONTINUE/roadmap_live_evidence_actionable_run_summary.json" "missing continue-mode live summary path forwarding"
assert_token "$continue_pack_line" $'\t--require-live-derived-evidence-pack-actions\t1' "missing continue-mode live-derived fail-closed enforcement forwarding"
if [[ -s "$ARCHIVE_CAPTURE" ]]; then
  echo "archive runner should not execute when disabled"
  cat "$ARCHIVE_CAPTURE"
  exit 1
fi

echo "[roadmap-live-and-pack-actionable-run] continue-on-live-fail keeps fail-closed contract when live summary is missing"
SUMMARY_CONTINUE_MISSING_LIVE_SUMMARY="$TMP_DIR/summary_continue_missing_live_summary.json"
REPORTS_CONTINUE_MISSING_LIVE_SUMMARY="$TMP_DIR/reports_continue_missing_live_summary"
: >"$LIVE_CAPTURE"
: >"$ARCHIVE_CAPTURE"
: >"$PACK_CAPTURE"
set +e
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_LIVE_SCRIPT="$FAKE_LIVE_SCRIPT" \
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_ARCHIVE_SCRIPT="$FAKE_ARCHIVE_SCRIPT" \
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_LIVE_CAPTURE_FILE="$LIVE_CAPTURE" \
FAKE_ARCHIVE_CAPTURE_FILE="$ARCHIVE_CAPTURE" \
FAKE_PACK_CAPTURE_FILE="$PACK_CAPTURE" \
FAKE_SHARED_ROADMAP_SUMMARY_JSON="$SHARED_ROADMAP_SUMMARY" \
FAKE_SHARED_ROADMAP_REPORT_MD="$SHARED_ROADMAP_REPORT" \
FAKE_LIVE_RC=41 FAKE_LIVE_WRITE_SUMMARY=0 \
bash ./scripts/roadmap_live_and_pack_actionable_run.sh \
  --reports-dir "$REPORTS_CONTINUE_MISSING_LIVE_SUMMARY" \
  --summary-json "$SUMMARY_CONTINUE_MISSING_LIVE_SUMMARY" \
  --continue-on-live-fail 1 \
  --print-summary-json 0
continue_missing_live_summary_rc=$?
set -e
if [[ "$continue_missing_live_summary_rc" != "41" ]]; then
  echo "expected continue-on-live-fail with missing live summary rc=41, got rc=$continue_missing_live_summary_rc"
  cat "$SUMMARY_CONTINUE_MISSING_LIVE_SUMMARY"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 41
  and .failure_substep == "live_evidence_summary_contract"
  and .inputs.continue_on_live_fail == true
  and .steps.live_evidence.status == "fail"
  and .steps.live_evidence.summary_valid == false
  and .steps.live_evidence.contract_valid == false
  and (.steps.live_evidence.contract_failure_reason | contains("missing or invalid"))
  and .steps.evidence_pack.status == "fail"
  and .steps.evidence_pack.rc == 4
  and .steps.evidence_pack.process_rc == 4
  and .steps.evidence_pack.summary_valid == true
  and .steps.evidence_pack.contract_valid == true
  and .summary.steps_total == 3
  and .summary.steps_executed == 2
  and .summary.steps_skipped == 1
  and .summary.steps_pass == 0
  and .summary.steps_fail == 2
' "$SUMMARY_CONTINUE_MISSING_LIVE_SUMMARY" >/dev/null; then
  echo "continue-on-live-fail missing-live-summary summary mismatch"
  cat "$SUMMARY_CONTINUE_MISSING_LIVE_SUMMARY"
  exit 1
fi

missing_live_summary_pack_line="$(tail -n 1 "$PACK_CAPTURE" || true)"
if [[ -z "$missing_live_summary_pack_line" ]]; then
  echo "expected evidence-pack capture line in missing-live-summary continue mode"
  cat "$PACK_CAPTURE"
  exit 1
fi
assert_token "$missing_live_summary_pack_line" $'\t--live-evidence-summary-json\t' "missing live-evidence-summary-json forwarding in missing-live-summary continue mode"
assert_token "$missing_live_summary_pack_line" "$REPORTS_CONTINUE_MISSING_LIVE_SUMMARY/roadmap_live_evidence_actionable_run_summary.json" "missing missing-live-summary path forwarding to evidence-pack runner"
assert_token "$missing_live_summary_pack_line" $'\t--require-live-derived-evidence-pack-actions\t1' "missing missing-live-summary fail-closed enforcement forwarding"
if [[ -s "$ARCHIVE_CAPTURE" ]]; then
  echo "archive runner should not execute in missing-live-summary continue mode when disabled"
  cat "$ARCHIVE_CAPTURE"
  exit 1
fi

echo "[roadmap-live-and-pack-actionable-run] archive-enabled path runs archive before evidence-pack"
SUMMARY_ARCHIVE_ENABLED="$TMP_DIR/summary_archive_enabled.json"
REPORTS_ARCHIVE_ENABLED="$TMP_DIR/reports_archive_enabled"
ARCHIVE_ROOT_ENABLED="$TMP_DIR/archive_root_enabled"
: >"$LIVE_CAPTURE"
: >"$ARCHIVE_CAPTURE"
: >"$PACK_CAPTURE"
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_LIVE_SCRIPT="$FAKE_LIVE_SCRIPT" \
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_ARCHIVE_SCRIPT="$FAKE_ARCHIVE_SCRIPT" \
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_LIVE_CAPTURE_FILE="$LIVE_CAPTURE" \
FAKE_ARCHIVE_CAPTURE_FILE="$ARCHIVE_CAPTURE" \
FAKE_PACK_CAPTURE_FILE="$PACK_CAPTURE" \
FAKE_SHARED_ROADMAP_SUMMARY_JSON="$SHARED_ROADMAP_SUMMARY" \
FAKE_SHARED_ROADMAP_REPORT_MD="$SHARED_ROADMAP_REPORT" \
FAKE_LIVE_RC=0 FAKE_LIVE_SUMMARY_RC=0 FAKE_LIVE_SELECTED_IDS_JSON='["profile_default_gate"]' FAKE_LIVE_SELECTED_COUNT=1 FAKE_LIVE_ACTIONS_EXECUTED=1 FAKE_LIVE_PASS=1 FAKE_LIVE_FAIL=0 \
FAKE_ARCHIVE_RC=0 FAKE_ARCHIVE_SUMMARY_RC=0 FAKE_ARCHIVE_STATUS=pass FAKE_ARCHIVE_CANDIDATE_TOTAL=4 FAKE_ARCHIVE_COPIED_TOTAL=4 FAKE_ARCHIVE_MISSING_TOTAL=0 FAKE_ARCHIVE_COPY_ERROR_TOTAL=0 FAKE_ARCHIVE_MISSING_FAMILY_COUNT=0 \
FAKE_PACK_RC=0 FAKE_PACK_SUMMARY_RC=0 FAKE_PACK_SELECTED_IDS_JSON='["profile_default_gate_evidence_pack"]' FAKE_PACK_SELECTED_COUNT=1 FAKE_PACK_ACTIONS_EXECUTED=1 FAKE_PACK_PASS=1 FAKE_PACK_FAIL=0 \
bash ./scripts/roadmap_live_and_pack_actionable_run.sh \
  --reports-dir "$REPORTS_ARCHIVE_ENABLED" \
  --summary-json "$SUMMARY_ARCHIVE_ENABLED" \
  --run-live-archive 1 \
  --archive-root "$ARCHIVE_ROOT_ENABLED" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .failure_substep == null
  and .inputs.run_live_archive == true
  and .steps.live_evidence_archive.attempted == true
  and .steps.live_evidence_archive.status == "pass"
  and .steps.live_evidence_archive.summary_valid == true
  and .steps.live_evidence_archive.contract_valid == true
  and .steps.live_evidence_archive.contract_failure_reason == null
  and .steps.live_evidence_archive.fail_closed_blocking == false
  and .steps.live_evidence_archive.candidate_total == 4
  and .steps.live_evidence_archive.copied_total == 4
  and .steps.live_evidence_archive.missing_total == 0
  and .steps.evidence_pack.status == "pass"
  and .summary.steps_total == 3
  and .summary.steps_executed == 3
  and .summary.steps_skipped == 0
  and .summary.steps_pass == 3
  and .summary.steps_fail == 0
' "$SUMMARY_ARCHIVE_ENABLED" >/dev/null; then
  echo "archive-enabled summary mismatch"
  cat "$SUMMARY_ARCHIVE_ENABLED"
  exit 1
fi

archive_line="$(tail -n 1 "$ARCHIVE_CAPTURE" || true)"
if [[ -z "$archive_line" ]]; then
  echo "expected archive runner invocation when enabled"
  cat "$ARCHIVE_CAPTURE"
  exit 1
fi
assert_token "$archive_line" $'\t--scope\tauto' "missing scope forwarding to archive runner"
assert_token "$archive_line" $'\t--archive-root\t' "missing archive-root forwarding to archive runner"
assert_token "$archive_line" "$ARCHIVE_ROOT_ENABLED" "missing configured archive root in archive runner invocation"

echo "[roadmap-live-and-pack-actionable-run] archive fail-closed blocks evidence-pack when archive is not pass"
SUMMARY_ARCHIVE_BLOCK="$TMP_DIR/summary_archive_block.json"
REPORTS_ARCHIVE_BLOCK="$TMP_DIR/reports_archive_block"
: >"$LIVE_CAPTURE"
: >"$ARCHIVE_CAPTURE"
: >"$PACK_CAPTURE"
set +e
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_LIVE_SCRIPT="$FAKE_LIVE_SCRIPT" \
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_ARCHIVE_SCRIPT="$FAKE_ARCHIVE_SCRIPT" \
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_LIVE_CAPTURE_FILE="$LIVE_CAPTURE" \
FAKE_ARCHIVE_CAPTURE_FILE="$ARCHIVE_CAPTURE" \
FAKE_PACK_CAPTURE_FILE="$PACK_CAPTURE" \
FAKE_SHARED_ROADMAP_SUMMARY_JSON="$SHARED_ROADMAP_SUMMARY" \
FAKE_SHARED_ROADMAP_REPORT_MD="$SHARED_ROADMAP_REPORT" \
FAKE_LIVE_RC=0 FAKE_LIVE_SUMMARY_RC=0 FAKE_LIVE_SELECTED_IDS_JSON='["profile_default_gate"]' FAKE_LIVE_SELECTED_COUNT=1 FAKE_LIVE_ACTIONS_EXECUTED=1 FAKE_LIVE_PASS=1 FAKE_LIVE_FAIL=0 \
FAKE_ARCHIVE_RC=0 FAKE_ARCHIVE_SUMMARY_RC=0 FAKE_ARCHIVE_STATUS=warn FAKE_ARCHIVE_CANDIDATE_TOTAL=4 FAKE_ARCHIVE_COPIED_TOTAL=2 FAKE_ARCHIVE_MISSING_TOTAL=2 FAKE_ARCHIVE_COPY_ERROR_TOTAL=0 FAKE_ARCHIVE_MISSING_FAMILY_COUNT=1 \
FAKE_PACK_RC=0 FAKE_PACK_SUMMARY_RC=0 FAKE_PACK_SELECTED_IDS_JSON='["profile_default_gate_evidence_pack"]' FAKE_PACK_SELECTED_COUNT=1 FAKE_PACK_ACTIONS_EXECUTED=1 FAKE_PACK_PASS=1 FAKE_PACK_FAIL=0 \
bash ./scripts/roadmap_live_and_pack_actionable_run.sh \
  --reports-dir "$REPORTS_ARCHIVE_BLOCK" \
  --summary-json "$SUMMARY_ARCHIVE_BLOCK" \
  --run-live-archive 1 \
  --print-summary-json 0
archive_block_rc=$?
set -e
if [[ "$archive_block_rc" != "1" ]]; then
  echo "expected archive fail-closed rc=1 when archive summary contract is non-pass/non-fail, got rc=$archive_block_rc"
  cat "$SUMMARY_ARCHIVE_BLOCK"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .failure_substep == "live_evidence_archive_summary_contract"
  and .inputs.run_live_archive == true
  and .steps.live_evidence.status == "pass"
  and .steps.live_evidence_archive.attempted == true
  and .steps.live_evidence_archive.status == "fail"
  and .steps.live_evidence_archive.contract_valid == false
  and (.steps.live_evidence_archive.contract_failure_reason | contains("status must be pass or fail"))
  and .steps.live_evidence_archive.fail_closed_blocking == true
  and .steps.evidence_pack.status == "skipped"
  and .steps.evidence_pack.skip_reason == "archive_step_failed_fail_closed"
  and .summary.steps_total == 3
  and .summary.steps_executed == 2
  and .summary.steps_skipped == 1
  and .summary.steps_pass == 1
  and .summary.steps_fail == 1
' "$SUMMARY_ARCHIVE_BLOCK" >/dev/null; then
  echo "archive fail-closed summary mismatch"
  cat "$SUMMARY_ARCHIVE_BLOCK"
  exit 1
fi

if [[ -s "$PACK_CAPTURE" ]]; then
  echo "evidence-pack runner should be blocked by archive fail-closed behavior"
  cat "$PACK_CAPTURE"
  exit 1
fi

echo "[roadmap-live-and-pack-actionable-run] stale pre-existing live summary is not reused as fresh stage output"
SUMMARY_STALE_LIVE_REUSE="$TMP_DIR/summary_stale_live_reuse.json"
REPORTS_STALE_LIVE_REUSE="$TMP_DIR/reports_stale_live_reuse"
STALE_LIVE_SUMMARY_PATH="$REPORTS_STALE_LIVE_REUSE/roadmap_live_evidence_actionable_run_summary.json"
mkdir -p "$REPORTS_STALE_LIVE_REUSE"
cat >"$STALE_LIVE_SUMMARY_PATH" <<'EOF_STALE_LIVE_SUMMARY'
{
  "status": "pass",
  "rc": 0,
  "summary": {
    "actions_executed": 1,
    "pass": 1,
    "fail": 0
  },
  "notes": "pre-existing stale summary fixture"
}
EOF_STALE_LIVE_SUMMARY
: >"$LIVE_CAPTURE"
: >"$ARCHIVE_CAPTURE"
: >"$PACK_CAPTURE"
set +e
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_LIVE_SCRIPT="$FAKE_LIVE_SCRIPT" \
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_ARCHIVE_SCRIPT="$FAKE_ARCHIVE_SCRIPT" \
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_LIVE_CAPTURE_FILE="$LIVE_CAPTURE" \
FAKE_ARCHIVE_CAPTURE_FILE="$ARCHIVE_CAPTURE" \
FAKE_PACK_CAPTURE_FILE="$PACK_CAPTURE" \
FAKE_SHARED_ROADMAP_SUMMARY_JSON="$SHARED_ROADMAP_SUMMARY" \
FAKE_SHARED_ROADMAP_REPORT_MD="$SHARED_ROADMAP_REPORT" \
FAKE_LIVE_RC=0 FAKE_LIVE_WRITE_SUMMARY=0 \
FAKE_PACK_RC=0 FAKE_PACK_SUMMARY_RC=0 FAKE_PACK_SELECTED_IDS_JSON='["profile_default_gate_evidence_pack"]' FAKE_PACK_SELECTED_COUNT=1 FAKE_PACK_ACTIONS_EXECUTED=1 FAKE_PACK_PASS=1 FAKE_PACK_FAIL=0 \
bash ./scripts/roadmap_live_and_pack_actionable_run.sh \
  --reports-dir "$REPORTS_STALE_LIVE_REUSE" \
  --summary-json "$SUMMARY_STALE_LIVE_REUSE" \
  --print-summary-json 0
stale_live_reuse_rc=$?
set -e
if [[ "$stale_live_reuse_rc" != "125" ]]; then
  echo "expected stale-live-summary reuse protection rc=125, got rc=$stale_live_reuse_rc"
  cat "$SUMMARY_STALE_LIVE_REUSE"
  exit 1
fi
if [[ -f "$STALE_LIVE_SUMMARY_PATH" ]]; then
  echo "expected stale pre-existing live summary to be cleared before stage run"
  cat "$SUMMARY_STALE_LIVE_REUSE"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 125
  and .failure_substep == "live_evidence_summary_contract"
  and .steps.live_evidence.status == "fail"
  and .steps.live_evidence.summary_valid == false
  and .steps.live_evidence.contract_valid == false
  and (.steps.live_evidence.contract_failure_reason | contains("missing or invalid"))
  and .steps.live_evidence.rc == 125
  and .steps.evidence_pack.status == "skipped"
  and .steps.evidence_pack.skip_reason == "live_step_failed_fail_closed"
  and .summary.steps_total == 3
  and .summary.steps_executed == 1
  and .summary.steps_skipped == 2
  and .summary.steps_pass == 0
  and .summary.steps_fail == 1
' "$SUMMARY_STALE_LIVE_REUSE" >/dev/null; then
  echo "stale-live-summary reuse protection summary mismatch"
  cat "$SUMMARY_STALE_LIVE_REUSE"
  exit 1
fi
if [[ -s "$PACK_CAPTURE" ]]; then
  echo "evidence-pack runner should not execute when live summary is stale/missing after pre-run cleanup"
  cat "$PACK_CAPTURE"
  exit 1
fi

echo "[roadmap-live-and-pack-actionable-run] live stage warn status with rc=0 is fail-closed"
SUMMARY_LIVE_WARN_RC0="$TMP_DIR/summary_live_warn_rc0.json"
REPORTS_LIVE_WARN_RC0="$TMP_DIR/reports_live_warn_rc0"
: >"$LIVE_CAPTURE"
: >"$ARCHIVE_CAPTURE"
: >"$PACK_CAPTURE"
set +e
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_LIVE_SCRIPT="$FAKE_LIVE_SCRIPT" \
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_ARCHIVE_SCRIPT="$FAKE_ARCHIVE_SCRIPT" \
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_LIVE_CAPTURE_FILE="$LIVE_CAPTURE" \
FAKE_ARCHIVE_CAPTURE_FILE="$ARCHIVE_CAPTURE" \
FAKE_PACK_CAPTURE_FILE="$PACK_CAPTURE" \
FAKE_SHARED_ROADMAP_SUMMARY_JSON="$SHARED_ROADMAP_SUMMARY" \
FAKE_SHARED_ROADMAP_REPORT_MD="$SHARED_ROADMAP_REPORT" \
FAKE_LIVE_RC=0 FAKE_LIVE_SUMMARY_RC=0 FAKE_LIVE_STATUS=warn FAKE_LIVE_SELECTED_IDS_JSON='["profile_default_gate"]' FAKE_LIVE_SELECTED_COUNT=1 FAKE_LIVE_ACTIONS_EXECUTED=1 FAKE_LIVE_PASS=1 FAKE_LIVE_FAIL=0 \
FAKE_PACK_RC=0 FAKE_PACK_SUMMARY_RC=0 FAKE_PACK_SELECTED_IDS_JSON='["profile_default_gate_evidence_pack"]' FAKE_PACK_SELECTED_COUNT=1 FAKE_PACK_ACTIONS_EXECUTED=1 FAKE_PACK_PASS=1 FAKE_PACK_FAIL=0 \
bash ./scripts/roadmap_live_and_pack_actionable_run.sh \
  --reports-dir "$REPORTS_LIVE_WARN_RC0" \
  --summary-json "$SUMMARY_LIVE_WARN_RC0" \
  --print-summary-json 0
live_warn_rc=$?
set -e
if [[ "$live_warn_rc" != "1" ]]; then
  echo "expected live warn/rc0 fail-closed rc=1, got rc=$live_warn_rc"
  cat "$SUMMARY_LIVE_WARN_RC0"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .failure_substep == "live_evidence_summary_contract"
  and .steps.live_evidence.status == "fail"
  and .steps.live_evidence.summary_valid == true
  and .steps.live_evidence.contract_valid == false
  and (.steps.live_evidence.contract_failure_reason | contains("status must be pass or fail"))
  and .steps.live_evidence.rc == 1
  and .steps.evidence_pack.status == "skipped"
  and .steps.evidence_pack.skip_reason == "live_step_failed_fail_closed"
  and .summary.steps_total == 3
  and .summary.steps_executed == 1
  and .summary.steps_skipped == 2
  and .summary.steps_pass == 0
  and .summary.steps_fail == 1
' "$SUMMARY_LIVE_WARN_RC0" >/dev/null; then
  echo "live warn/rc0 fail-closed summary mismatch"
  cat "$SUMMARY_LIVE_WARN_RC0"
  exit 1
fi
if [[ -s "$PACK_CAPTURE" ]]; then
  echo "evidence-pack runner should not execute when live status is warn with rc=0"
  cat "$PACK_CAPTURE"
  exit 1
fi

echo "[roadmap-live-and-pack-actionable-run] evidence-pack stage warn status with rc=0 is fail-closed"
SUMMARY_PACK_WARN_RC0="$TMP_DIR/summary_pack_warn_rc0.json"
REPORTS_PACK_WARN_RC0="$TMP_DIR/reports_pack_warn_rc0"
: >"$LIVE_CAPTURE"
: >"$ARCHIVE_CAPTURE"
: >"$PACK_CAPTURE"
set +e
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_LIVE_SCRIPT="$FAKE_LIVE_SCRIPT" \
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_ARCHIVE_SCRIPT="$FAKE_ARCHIVE_SCRIPT" \
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_LIVE_CAPTURE_FILE="$LIVE_CAPTURE" \
FAKE_ARCHIVE_CAPTURE_FILE="$ARCHIVE_CAPTURE" \
FAKE_PACK_CAPTURE_FILE="$PACK_CAPTURE" \
FAKE_SHARED_ROADMAP_SUMMARY_JSON="$SHARED_ROADMAP_SUMMARY" \
FAKE_SHARED_ROADMAP_REPORT_MD="$SHARED_ROADMAP_REPORT" \
FAKE_LIVE_RC=0 FAKE_LIVE_SUMMARY_RC=0 FAKE_LIVE_STATUS=pass FAKE_LIVE_SELECTED_IDS_JSON='["profile_default_gate"]' FAKE_LIVE_SELECTED_COUNT=1 FAKE_LIVE_ACTIONS_EXECUTED=1 FAKE_LIVE_PASS=1 FAKE_LIVE_FAIL=0 \
FAKE_PACK_RC=0 FAKE_PACK_SUMMARY_RC=0 FAKE_PACK_STATUS=warn FAKE_PACK_SELECTED_IDS_JSON='["profile_default_gate_evidence_pack"]' FAKE_PACK_SELECTED_COUNT=1 FAKE_PACK_ACTIONS_EXECUTED=1 FAKE_PACK_PASS=1 FAKE_PACK_FAIL=0 \
bash ./scripts/roadmap_live_and_pack_actionable_run.sh \
  --reports-dir "$REPORTS_PACK_WARN_RC0" \
  --summary-json "$SUMMARY_PACK_WARN_RC0" \
  --print-summary-json 0
pack_warn_rc=$?
set -e
if [[ "$pack_warn_rc" != "1" ]]; then
  echo "expected evidence-pack warn/rc0 fail-closed rc=1, got rc=$pack_warn_rc"
  cat "$SUMMARY_PACK_WARN_RC0"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .failure_substep == "evidence_pack_summary_contract"
  and .steps.live_evidence.status == "pass"
  and .steps.live_evidence.rc == 0
  and .steps.evidence_pack.status == "fail"
  and .steps.evidence_pack.summary_valid == true
  and .steps.evidence_pack.contract_valid == false
  and (.steps.evidence_pack.contract_failure_reason | contains("status must be pass or fail"))
  and .steps.evidence_pack.rc == 1
  and .steps.evidence_pack.skip_reason == null
  and .summary.steps_total == 3
  and .summary.steps_executed == 2
  and .summary.steps_skipped == 1
  and .summary.steps_pass == 1
  and .summary.steps_fail == 1
' "$SUMMARY_PACK_WARN_RC0" >/dev/null; then
  echo "evidence-pack warn/rc0 fail-closed summary mismatch"
  cat "$SUMMARY_PACK_WARN_RC0"
  exit 1
fi
if [[ ! -s "$PACK_CAPTURE" ]]; then
  echo "expected evidence-pack runner invocation in evidence-pack warn/rc0 fail-closed path"
  exit 1
fi

echo "roadmap live-and-pack actionable run integration check ok"
