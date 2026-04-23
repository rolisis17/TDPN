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
FAKE_PACK_SCRIPT="$ACTION_TMP_DIR/fake_roadmap_evidence_pack_actionable_run.sh"
LIVE_CAPTURE="$TMP_DIR/live_capture.tsv"
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

cat >"$FAKE_PACK_SCRIPT" <<'EOF_FAKE_PACK'
#!/usr/bin/env bash
set -euo pipefail

capture_file="${FAKE_PACK_CAPTURE_FILE:?}"
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

if [[ "${FAKE_PACK_WRITE_SUMMARY:-1}" == "1" ]]; then
  if [[ -z "$summary_json" ]]; then
    echo "fake pack: missing --summary-json"
    exit 2
  fi

  mkdir -p "$(dirname "$summary_json")"

  summary_rc="${FAKE_PACK_SUMMARY_RC:-${FAKE_PACK_RC:-0}}"
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
: >"$PACK_CAPTURE"
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_LIVE_SCRIPT="$FAKE_LIVE_SCRIPT" \
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_LIVE_CAPTURE_FILE="$LIVE_CAPTURE" \
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
  and .inputs.refresh_manual_validation == true
  and .inputs.refresh_single_machine_readiness == true
  and .inputs.parallel == true
  and .inputs.scope == "profile-default"
  and .inputs.max_actions == 3
  and .inputs.action_timeout_sec == 33
  and .inputs.continue_on_live_fail == false
  and .steps.live_evidence.status == "pass"
  and .steps.live_evidence.rc == 0
  and .steps.live_evidence.summary_valid == true
  and .steps.live_evidence.selected_actions_count == 2
  and .steps.live_evidence.selected_action_ids == ["profile_default_gate","runtime_actuation_promotion"]
  and .steps.evidence_pack.status == "pass"
  and .steps.evidence_pack.rc == 0
  and .steps.evidence_pack.summary_valid == true
  and .steps.evidence_pack.selected_actions_count == 1
  and .steps.evidence_pack.selected_action_ids == ["profile_default_gate_evidence_pack"]
  and .summary.steps_executed == 2
  and .summary.steps_skipped == 0
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
assert_token "$live_line" $'\t--action-timeout-sec\t33' "missing timeout forwarding to live runner"
assert_token "$live_line" $'\t--refresh-manual-validation\t1' "missing refresh-manual-validation forwarding to live runner"
assert_token "$live_line" $'\t--refresh-single-machine-readiness\t1' "missing refresh-single-machine-readiness forwarding to live runner"
assert_token "$live_line" $'\t--scope\tprofile-default' "missing default scope forwarding to live runner"
assert_token "$live_line" $'\t--parallel\t1' "missing parallel forwarding to live runner"
assert_token "$live_line" $'\t--max-actions\t3' "missing max-actions forwarding to live runner"
assert_token "$live_line" $'\t--print-summary-json\t0' "missing print-summary-json forwarding to live runner"
assert_token "$pack_line" $'\t--roadmap-summary-json\t' "missing roadmap-summary-json forwarding to evidence-pack runner"
assert_token "$pack_line" "shared_roadmap_summary.json" "missing shared roadmap summary filename in evidence-pack forwarding"
assert_token "$pack_line" $'\t--roadmap-report-md\t' "missing roadmap-report-md forwarding to evidence-pack runner"
assert_token "$pack_line" "shared_roadmap_report.md" "missing shared roadmap report filename in evidence-pack forwarding"
assert_token "$pack_line" $'\t--scope\tprofile-default' "missing default scope forwarding to evidence-pack runner"
assert_token "$pack_line" $'\t--action-timeout-sec\t33' "missing timeout forwarding to evidence-pack runner"
assert_token "$pack_line" $'\t--max-actions\t3' "missing max-actions forwarding to evidence-pack runner"

echo "[roadmap-live-and-pack-actionable-run] fail-closed path skips evidence-pack when live fails"
SUMMARY_FAIL_CLOSED="$TMP_DIR/summary_fail_closed.json"
REPORTS_FAIL_CLOSED="$TMP_DIR/reports_fail_closed"
: >"$LIVE_CAPTURE"
: >"$PACK_CAPTURE"
set +e
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_LIVE_SCRIPT="$FAKE_LIVE_SCRIPT" \
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_LIVE_CAPTURE_FILE="$LIVE_CAPTURE" \
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
  and .inputs.continue_on_live_fail == false
  and .inputs.scope == "profile-default"
  and .steps.live_evidence.status == "fail"
  and .steps.live_evidence.rc == 41
  and .steps.live_evidence.process_rc == 41
  and .steps.live_evidence.summary_valid == true
  and .steps.evidence_pack.status == "skipped"
  and .steps.evidence_pack.summary_valid == false
  and .steps.evidence_pack.skip_reason == "live_step_failed_fail_closed"
  and .steps.evidence_pack.rc == null
  and .steps.evidence_pack.process_rc == null
  and .summary.steps_executed == 1
  and .summary.steps_skipped == 1
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

echo "[roadmap-live-and-pack-actionable-run] continue-on-live-fail path executes evidence-pack"
SUMMARY_CONTINUE="$TMP_DIR/summary_continue.json"
REPORTS_CONTINUE="$TMP_DIR/reports_continue"
: >"$LIVE_CAPTURE"
: >"$PACK_CAPTURE"
set +e
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_LIVE_SCRIPT="$FAKE_LIVE_SCRIPT" \
ROADMAP_LIVE_AND_PACK_ACTIONABLE_RUN_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_LIVE_CAPTURE_FILE="$LIVE_CAPTURE" \
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
  and .inputs.continue_on_live_fail == true
  and .inputs.scope == "profile-default"
  and .steps.live_evidence.status == "fail"
  and .steps.live_evidence.rc == 41
  and .steps.evidence_pack.status == "pass"
  and .steps.evidence_pack.rc == 0
  and .steps.evidence_pack.summary_valid == true
  and .steps.evidence_pack.skip_reason == null
  and .summary.steps_executed == 2
  and .summary.steps_skipped == 0
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

echo "roadmap live-and-pack actionable run integration check ok"
