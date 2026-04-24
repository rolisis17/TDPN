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
TMP_DIR="$(mktemp -d "$ROOT_DIR/.easy-node-logs/integration_roadmap_live_evidence_cycle_batch_run_XXXXXX")"
SCRIPT_TMP_DIR="$(mktemp -d "$ROOT_DIR/scripts/.integration_roadmap_live_evidence_cycle_batch_run.XXXXXX")"
trap 'rm -rf "$TMP_DIR" "$SCRIPT_TMP_DIR"' EXIT

EXEC_LOG="$TMP_DIR/exec.log"
TRACK_A="$SCRIPT_TMP_DIR/profile_default_gate_stability_cycle.sh"
TRACK_B="$SCRIPT_TMP_DIR/runtime_actuation_promotion_cycle.sh"
TRACK_C="$SCRIPT_TMP_DIR/profile_compare_multi_vm_stability_promotion_cycle.sh"
VM_COMMAND_FILE="$TMP_DIR/profile_compare_multi_vm_stability_vm_commands.txt"
DEFAULT_ROADMAP_PROGRESS_SUMMARY_JSON="$TMP_DIR/roadmap_progress_summary_default.json"
FALLBACK_HOSTS_ROADMAP_PROGRESS_SUMMARY_JSON="$TMP_DIR/roadmap_progress_summary_fallback_hosts.json"
FALLBACK_ENV_ASSIGNMENTS_ROADMAP_PROGRESS_SUMMARY_JSON="$TMP_DIR/roadmap_progress_summary_fallback_env_assignments.json"
FALLBACK_PLACEHOLDER_ENV_ASSIGNMENTS_ROADMAP_PROGRESS_SUMMARY_JSON="$TMP_DIR/roadmap_progress_summary_fallback_placeholder_env_assignments.json"
FALLBACK_PLACEHOLDER_SUBJECT_ROADMAP_PROGRESS_SUMMARY_JSON="$TMP_DIR/roadmap_progress_summary_fallback_placeholder_subject.json"
FALLBACK_CONCRETE_SUBJECT_ROADMAP_PROGRESS_SUMMARY_JSON="$TMP_DIR/roadmap_progress_summary_fallback_concrete_subject.json"

cat >"$TRACK_A" <<'EOF_TRACK_A'
#!/usr/bin/env bash
set -euo pipefail
exec_log="${BATCH_TRACK_EXEC_LOG:?}"
behavior="${TRACK_A_BEHAVIOR:-pass}"
echo "A:$behavior" >>"$exec_log"
if [[ "$behavior" == "fail" ]]; then
  exit "${TRACK_A_RC:-17}"
fi
exit 0
EOF_TRACK_A
chmod +x "$TRACK_A"

cat >"$TRACK_B" <<'EOF_TRACK_B'
#!/usr/bin/env bash
set -euo pipefail
exec_log="${BATCH_TRACK_EXEC_LOG:?}"
behavior="${TRACK_B_BEHAVIOR:-pass}"
echo "B:$behavior" >>"$exec_log"
if [[ "$behavior" == "fail" ]]; then
  echo "runtime_actuation_promotion_cycle failed rc=${TRACK_B_RC:-23}"
  exit "${TRACK_B_RC:-23}"
fi
if [[ "$behavior" == "placeholder_fail" ]]; then
  echo "runtime-actuation-promotion-cycle: placeholder invite subject in signoff passthrough (--subject) cannot be resolved"
  echo "provide a real value via --subject or set CAMPAIGN_SUBJECT/INVITE_KEY"
  exit "${TRACK_B_RC:-2}"
fi
exit 0
EOF_TRACK_B
chmod +x "$TRACK_B"

cat >"$TRACK_C" <<'EOF_TRACK_C'
#!/usr/bin/env bash
set -euo pipefail
exec_log="${BATCH_TRACK_EXEC_LOG:?}"
behavior="${TRACK_C_BEHAVIOR:-pass}"
echo "C:$behavior" >>"$exec_log"
if [[ "$behavior" == "fail" ]]; then
  exit "${TRACK_C_RC:-31}"
fi
exit 0
EOF_TRACK_C
chmod +x "$TRACK_C"

cat >"$VM_COMMAND_FILE" <<'EOF_VM_COMMAND_FILE'
vm_a::ssh vm-a.example
EOF_VM_COMMAND_FILE

cat >"$DEFAULT_ROADMAP_PROGRESS_SUMMARY_JSON" <<'EOF_DEFAULT_ROADMAP_SUMMARY'
{
  "next_actions": []
}
EOF_DEFAULT_ROADMAP_SUMMARY

cat >"$FALLBACK_HOSTS_ROADMAP_PROGRESS_SUMMARY_JSON" <<'EOF_FALLBACK_HOSTS_ROADMAP_SUMMARY'
{
  "next_actions": [
    {
      "id": "profile_default_gate_stability_cycle",
      "command": "./scripts/easy_node.sh profile-default-gate-stability-cycle --host-a 198.51.100.41 --host-b=198.51.100.42 --campaign-subject INVITE_KEY --reports-dir .easy-node-logs --print-summary-json 1"
    }
  ]
}
EOF_FALLBACK_HOSTS_ROADMAP_SUMMARY

cat >"$FALLBACK_PLACEHOLDER_SUBJECT_ROADMAP_PROGRESS_SUMMARY_JSON" <<'EOF_FALLBACK_PLACEHOLDER_SUBJECT_ROADMAP_SUMMARY'
{
  "next_actions": [
    {
      "id": "runtime_actuation_promotion_cycle",
      "command": "./scripts/easy_node.sh runtime-actuation-promotion-cycle --subject CAMPAIGN_SUBJECT --reports-dir .easy-node-logs --print-summary-json 1"
    }
  ]
}
EOF_FALLBACK_PLACEHOLDER_SUBJECT_ROADMAP_SUMMARY

cat >"$FALLBACK_CONCRETE_SUBJECT_ROADMAP_PROGRESS_SUMMARY_JSON" <<'EOF_FALLBACK_CONCRETE_SUBJECT_ROADMAP_SUMMARY'
{
  "next_actions": [
    {
      "id": "runtime_actuation_promotion_cycle",
      "command": "./scripts/easy_node.sh runtime-actuation-promotion-cycle --invite-key=inv-real-010 --reports-dir .easy-node-logs --print-summary-json 1"
    }
  ]
}
EOF_FALLBACK_CONCRETE_SUBJECT_ROADMAP_SUMMARY

cat >"$FALLBACK_ENV_ASSIGNMENTS_ROADMAP_PROGRESS_SUMMARY_JSON" <<'EOF_FALLBACK_ENV_ASSIGNMENTS_ROADMAP_SUMMARY'
{
  "next_actions": [
    {
      "id": "profile_default_gate_stability_cycle",
      "command": "A_HOST=198.51.100.61 B_HOST=198.51.100.62 PROFILE_DEFAULT_GATE_STABILITY_CAMPAIGN_SUBJECT=inv-real-011 ./scripts/easy_node.sh profile-default-gate-stability-cycle --reports-dir .easy-node-logs --print-summary-json 1"
    },
    {
      "id": "runtime_actuation_promotion_cycle",
      "command": "CAMPAIGN_SUBJECT=inv-real-012 ./scripts/easy_node.sh runtime-actuation-promotion-cycle --reports-dir .easy-node-logs --print-summary-json 1"
    }
  ]
}
EOF_FALLBACK_ENV_ASSIGNMENTS_ROADMAP_SUMMARY

cat >"$FALLBACK_PLACEHOLDER_ENV_ASSIGNMENTS_ROADMAP_PROGRESS_SUMMARY_JSON" <<'EOF_FALLBACK_PLACEHOLDER_ENV_ASSIGNMENTS_ROADMAP_SUMMARY'
{
  "next_actions": [
    {
      "id": "profile_default_gate_stability_cycle",
      "command": "A_HOST=HOST_A B_HOST=HOST_B PROFILE_DEFAULT_GATE_STABILITY_CAMPAIGN_SUBJECT=INVITE_KEY ./scripts/easy_node.sh profile-default-gate-stability-cycle --reports-dir .easy-node-logs --print-summary-json 1"
    },
    {
      "id": "runtime_actuation_promotion_cycle",
      "command": "CAMPAIGN_SUBJECT=CAMPAIGN_SUBJECT ./scripts/easy_node.sh runtime-actuation-promotion-cycle --reports-dir .easy-node-logs --print-summary-json 1"
    }
  ]
}
EOF_FALLBACK_PLACEHOLDER_ENV_ASSIGNMENTS_ROADMAP_SUMMARY

export ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_ROADMAP_PROGRESS_SUMMARY_JSON="$DEFAULT_ROADMAP_PROGRESS_SUMMARY_JSON"

echo "[roadmap-live-evidence-cycle-batch-run] help contract"
if ! bash ./scripts/roadmap_live_evidence_cycle_batch_run.sh --help | grep -F -- "--reports-dir DIR" >/dev/null; then
  echo "help output missing --reports-dir DIR"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_cycle_batch_run.sh --help | grep -F -- "--summary-json PATH" >/dev/null; then
  echo "help output missing --summary-json PATH"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_cycle_batch_run.sh --help | grep -F -- "--iterations N" >/dev/null; then
  echo "help output missing --iterations N"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_cycle_batch_run.sh --help | grep -F -- "--continue-on-fail [0|1]" >/dev/null; then
  echo "help output missing --continue-on-fail [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_cycle_batch_run.sh --help | grep -F -- "--parallel [0|1]" >/dev/null; then
  echo "help output missing --parallel [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_cycle_batch_run.sh --help | grep -F -- "--include-track-id ID" >/dev/null; then
  echo "help output missing --include-track-id ID"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_cycle_batch_run.sh --help | grep -F -- "--exclude-track-id ID" >/dev/null; then
  echo "help output missing --exclude-track-id ID"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_cycle_batch_run.sh --help | grep -F -- "--print-summary-json [0|1]" >/dev/null; then
  echo "help output missing --print-summary-json [0|1]"
  exit 1
fi

echo "[roadmap-live-evidence-cycle-batch-run] success path"
SUCCESS_SUMMARY="$TMP_DIR/success_summary.json"
: >"$EXEC_LOG"
A_HOST=203.0.113.10 B_HOST=203.0.113.11 INVITE_KEY=inv-real-001 CAMPAIGN_SUBJECT=inv-real-001 \
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_VM_COMMAND_FILE="$VM_COMMAND_FILE" \
BATCH_TRACK_EXEC_LOG="$EXEC_LOG" \
TRACK_A_BEHAVIOR=pass TRACK_B_BEHAVIOR=pass TRACK_C_BEHAVIOR=pass \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_SCRIPT="$TRACK_A" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$TRACK_B" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_SCRIPT="$TRACK_C" \
bash ./scripts/roadmap_live_evidence_cycle_batch_run.sh \
  --reports-dir "$TMP_DIR/success_reports" \
  --summary-json "$SUCCESS_SUMMARY" \
  --iterations 2 \
  --parallel 1 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .failure_substep == null
  and .failure_reason == null
  and .selection_error == null
  and .stages.selection.status == "pass"
  and .stages.execution.status == "pass"
  and .inputs.iterations == 2
  and .inputs.parallel == true
  and .inputs.selected_track_ids == [
    "profile_default_gate_stability_cycle",
    "runtime_actuation_promotion_cycle",
    "profile_compare_multi_vm_stability_promotion_cycle"
  ]
  and (.inputs.track_runtime_requirements | length == 3)
  and .summary.iterations_requested == 2
  and .summary.iterations_completed == 2
  and .summary.selected_track_count == 3
  and .summary.executed_tracks == 6
  and .summary.skipped_tracks == 0
  and .summary.halt_after_iteration == false
  and .selection_accounting.include_track_ids_requested_count == 0
  and .selection_accounting.exclude_track_ids_requested_count == 0
  and .selection_accounting.base_track_count == 3
  and .selection_accounting.selected_track_ids_count == 3
  and (.selection_accounting.unresolved_required_track_count | type) == "number"
  and (.per_track | length == 3)
  and ([.per_track[].total_runs] == [2,2,2])
  and ([.per_track[].pass] == [2,2,2])
  and ([.per_track[].fail] == [0,0,0])
  and ([.per_track[].skipped] == [0,0,0])
  and (.iterations | length == 2)
  and ([.iterations[].status] == ["pass","pass"])
  and ([.iterations[].failure_substep] == [null,null])
' "$SUCCESS_SUMMARY" >/dev/null; then
  echo "success summary mismatch"
  cat "$SUCCESS_SUMMARY"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "6" ]]; then
  echo "expected 6 executions in success path"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-live-evidence-cycle-batch-run] no-selected-tracks fail-closed path"
NO_TRACKS_SUMMARY="$TMP_DIR/no_tracks_summary.json"
: >"$EXEC_LOG"
set +e
BATCH_TRACK_EXEC_LOG="$EXEC_LOG" \
TRACK_A_BEHAVIOR=pass TRACK_B_BEHAVIOR=pass TRACK_C_BEHAVIOR=pass \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_SCRIPT="$TRACK_A" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$TRACK_B" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_SCRIPT="$TRACK_C" \
bash ./scripts/roadmap_live_evidence_cycle_batch_run.sh \
  --reports-dir "$TMP_DIR/no_tracks_reports" \
  --summary-json "$NO_TRACKS_SUMMARY" \
  --include-track-id profile_default_gate_stability_cycle \
  --exclude-track-id profile_default_gate_stability_cycle \
  --print-summary-json 0
no_tracks_rc=$?
set -e

if [[ "$no_tracks_rc" != "1" ]]; then
  echo "expected no-selected-tracks fail-closed rc=1, got rc=$no_tracks_rc"
  cat "$NO_TRACKS_SUMMARY"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .failure_substep == "selection:no_tracks_selected"
  and .failure_reason == "selection failed before execution"
  and .selection_error == "no_tracks_selected"
  and .stages.selection.status == "fail"
  and .stages.selection.reason == "no_tracks_selected"
  and .stages.execution.status == "skip_due_to_selection_error"
  and .summary.iterations_completed == 0
  and .summary.executed_tracks == 0
  and .summary.skipped_tracks == 0
  and .inputs.selected_track_ids == []
  and .inputs.track_runtime_requirements == []
  and .selection_accounting.selected_track_ids_count == 0
  and .selection_accounting.unresolved_required_track_count == 0
  and (.per_track | length == 0)
  and (.iterations | length == 0)
' "$NO_TRACKS_SUMMARY" >/dev/null; then
  echo "no-selected-tracks fail-closed summary mismatch"
  cat "$NO_TRACKS_SUMMARY"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "0" ]]; then
  echo "expected 0 executions in no-selected-tracks fail-closed path"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-live-evidence-cycle-batch-run] fail-closed path"
FAIL_CLOSED_SUMMARY="$TMP_DIR/fail_closed_summary.json"
: >"$EXEC_LOG"
set +e
A_HOST=203.0.113.10 B_HOST=203.0.113.11 INVITE_KEY=inv-real-002 CAMPAIGN_SUBJECT=inv-real-002 \
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_VM_COMMAND_FILE="$VM_COMMAND_FILE" \
BATCH_TRACK_EXEC_LOG="$EXEC_LOG" \
TRACK_A_BEHAVIOR=pass TRACK_B_BEHAVIOR=fail TRACK_B_RC=23 TRACK_C_BEHAVIOR=pass \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_SCRIPT="$TRACK_A" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$TRACK_B" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_SCRIPT="$TRACK_C" \
bash ./scripts/roadmap_live_evidence_cycle_batch_run.sh \
  --reports-dir "$TMP_DIR/fail_closed_reports" \
  --summary-json "$FAIL_CLOSED_SUMMARY" \
  --iterations 3 \
  --continue-on-fail 0 \
  --parallel 0 \
  --print-summary-json 0
fail_closed_rc=$?
set -e

if [[ "$fail_closed_rc" != "23" ]]; then
  echo "expected fail-closed rc=23, got rc=$fail_closed_rc"
  cat "$FAIL_CLOSED_SUMMARY"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 23
  and .failure_substep == "execution:iteration_1:track_runtime_actuation_promotion_cycle"
  and .failure_reason == "first failing track in deterministic iteration/track order"
  and .summary.iterations_requested == 3
  and .summary.iterations_completed == 1
  and .summary.executed_tracks == 2
  and .summary.skipped_tracks == 1
  and .summary.halt_after_iteration == true
  and .summary.first_failure_iteration == 1
  and .summary.first_failure_track_id == "runtime_actuation_promotion_cycle"
  and (.per_track | length == 3)
  and .per_track[0].total_runs == 1
  and .per_track[0].pass == 1
  and .per_track[0].fail == 0
  and .per_track[0].skipped == 0
  and .per_track[1].total_runs == 1
  and .per_track[1].pass == 0
  and .per_track[1].fail == 1
  and .per_track[1].skipped == 0
  and .per_track[2].total_runs == 0
  and .per_track[2].pass == 0
  and .per_track[2].fail == 0
  and .per_track[2].skipped == 1
  and (.iterations | length == 1)
  and .iterations[0].status == "fail"
  and .iterations[0].rc == 23
  and .iterations[0].failure_substep == "track_failed:runtime_actuation_promotion_cycle"
  and (.iterations[0].tracks | length == 3)
  and ([.iterations[0].tracks[].status] == ["pass","fail","skipped"])
  and .iterations[0].tracks[1].failure_diagnostics.log_tail_lines == ["runtime_actuation_promotion_cycle failed rc=23"]
  and .iterations[0].tracks[1].failure_diagnostics.track_group == "m4_runtime_actuation_promotion"
  and .iterations[0].tracks[1].failure_diagnostics.failure_kind == "track_execution_failed"
  and .iterations[0].tracks[1].failure_diagnostics.failure_code == "m4_track_failed"
  and .iterations[0].tracks[1].failure_diagnostics.log_tail_line_count == 1
  and .iterations[0].tracks[1].failure_diagnostics.log_total_line_count == 1
  and .iterations[0].tracks[1].failure_diagnostics.log_tail_truncated == false
  and .iterations[0].tracks[2].track_id == "profile_compare_multi_vm_stability_promotion_cycle"
  and .iterations[0].tracks[2].rc == null
  and .iterations[0].tracks[2].failure_kind == "skipped_due_to_fail_closed"
' "$FAIL_CLOSED_SUMMARY" >/dev/null; then
  echo "fail-closed summary mismatch"
  cat "$FAIL_CLOSED_SUMMARY"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "2" ]]; then
  echo "expected 2 executions in fail-closed path"
  cat "$EXEC_LOG"
  exit 1
fi
if grep -F "C:" "$EXEC_LOG" >/dev/null; then
  echo "track C should not run in fail-closed path"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-live-evidence-cycle-batch-run] placeholder unresolved-input diagnostics path"
PLACEHOLDER_SUMMARY="$TMP_DIR/placeholder_summary.json"
: >"$EXEC_LOG"
set +e
A_HOST=A_HOST B_HOST=B_HOST CAMPAIGN_SUBJECT=CAMPAIGN_SUBJECT INVITE_KEY=INVITE_KEY \
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_VM_COMMAND_FILE="$VM_COMMAND_FILE" \
BATCH_TRACK_EXEC_LOG="$EXEC_LOG" \
TRACK_A_BEHAVIOR=pass TRACK_B_BEHAVIOR=placeholder_fail TRACK_B_RC=2 TRACK_C_BEHAVIOR=pass \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_SCRIPT="$TRACK_A" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$TRACK_B" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_SCRIPT="$TRACK_C" \
bash ./scripts/roadmap_live_evidence_cycle_batch_run.sh \
  --reports-dir "$TMP_DIR/placeholder_reports" \
  --summary-json "$PLACEHOLDER_SUMMARY" \
  --iterations 1 \
  --continue-on-fail 0 \
  --parallel 0 \
  --print-summary-json 0
placeholder_rc=$?
set -e

if [[ "$placeholder_rc" != "0" ]]; then
  echo "expected placeholder diagnostics path rc=0, got rc=$placeholder_rc"
  cat "$PLACEHOLDER_SUMMARY"
  exit 1
fi

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .failure_substep == null
  and .failure_reason == null
  and .stages.execution.status == "pass"
  and .stages.execution.partial_progress_runtime_input_skips == true
  and .summary.iterations_completed == 1
  and .summary.executed_tracks == 1
  and .summary.skipped_tracks == 2
  and .summary.skipped_unresolved_runtime_input_tracks == 2
  and (.inputs.track_runtime_requirements | length == 3)
  and .selection_accounting.unresolved_required_track_ids == [
    "profile_default_gate_stability_cycle",
    "runtime_actuation_promotion_cycle"
  ]
  and .selection_accounting.unresolved_required_track_count == 2
  and .iterations[0].status == "pass"
  and .iterations[0].rc == 0
  and .iterations[0].failure_substep == null
  and (.iterations[0].tracks | length == 3)
  and ([.iterations[0].tracks[].status] == ["skipped","skipped","pass"])
  and .iterations[0].tracks[0].failure_kind == "skipped_unresolved_runtime_inputs"
  and .iterations[0].tracks[0].failure_diagnostics.track_group == "m2_profile_default_gate_stability"
  and .iterations[0].tracks[0].failure_diagnostics.failure_kind == "required_runtime_input_unresolved"
  and .iterations[0].tracks[0].failure_diagnostics.unresolved_required_inputs == ["host_a","host_b","campaign_subject"]
  and .iterations[0].tracks[0].failure_diagnostics.unresolved_required_inputs_count == 3
  and .iterations[0].tracks[0].failure_diagnostics.partial_progress_skip == true
  and .iterations[0].tracks[1].failure_kind == "skipped_unresolved_runtime_inputs"
  and .iterations[0].tracks[1].failure_diagnostics.track_group == "m4_runtime_actuation_promotion"
  and .iterations[0].tracks[1].failure_diagnostics.failure_kind == "required_runtime_input_unresolved"
  and .iterations[0].tracks[1].failure_diagnostics.unresolved_required_inputs == ["campaign_subject"]
  and .iterations[0].tracks[1].failure_diagnostics.unresolved_required_inputs_count == 1
  and .iterations[0].tracks[1].failure_diagnostics.partial_progress_skip == true
  and .iterations[0].tracks[2].track_id == "profile_compare_multi_vm_stability_promotion_cycle"
  and .iterations[0].tracks[2].status == "pass"
  and .iterations[0].tracks[2].rc == 0
' "$PLACEHOLDER_SUMMARY" >/dev/null; then
  echo "placeholder unresolved-input diagnostics summary mismatch"
  cat "$PLACEHOLDER_SUMMARY"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected 1 execution in placeholder diagnostics path"
  cat "$EXEC_LOG"
  exit 1
fi
if grep -F "A:" "$EXEC_LOG" >/dev/null || grep -F "B:" "$EXEC_LOG" >/dev/null; then
  echo "tracks A/B should not run in placeholder diagnostics path"
  cat "$EXEC_LOG"
  exit 1
fi
if ! grep -F "C:pass" "$EXEC_LOG" >/dev/null; then
  echo "track C should run in placeholder diagnostics path"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-live-evidence-cycle-batch-run] roadmap-summary host fallback path"
ROADMAP_FALLBACK_HOSTS_SUMMARY="$TMP_DIR/roadmap_fallback_hosts_summary.json"
: >"$EXEC_LOG"
A_HOST= B_HOST= PROFILE_DEFAULT_GATE_STABILITY_HOST_A= PROFILE_DEFAULT_GATE_STABILITY_HOST_B= \
PROFILE_DEFAULT_GATE_STABILITY_CAMPAIGN_SUBJECT= INVITE_KEY=inv-real-009 CAMPAIGN_SUBJECT= \
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_VM_COMMAND_FILE="$VM_COMMAND_FILE" \
BATCH_TRACK_EXEC_LOG="$EXEC_LOG" \
TRACK_A_BEHAVIOR=pass TRACK_B_BEHAVIOR=pass TRACK_C_BEHAVIOR=pass \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_ROADMAP_PROGRESS_SUMMARY_JSON="$FALLBACK_HOSTS_ROADMAP_PROGRESS_SUMMARY_JSON" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_SCRIPT="$TRACK_A" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$TRACK_B" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_SCRIPT="$TRACK_C" \
bash ./scripts/roadmap_live_evidence_cycle_batch_run.sh \
  --reports-dir "$TMP_DIR/roadmap_fallback_hosts_reports" \
  --summary-json "$ROADMAP_FALLBACK_HOSTS_SUMMARY" \
  --iterations 1 \
  --include-track-id profile_default_gate_stability_cycle \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .summary.executed_tracks == 1
  and .summary.skipped_tracks == 0
  and .inputs.selected_track_ids == ["profile_default_gate_stability_cycle"]
  and .selection_accounting.unresolved_required_track_count == 0
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "profile_default_gate_stability_cycle")
    | .required_runtime_inputs[]
    | select(.id == "host_a")
    | .state
  ) == "resolved"
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "profile_default_gate_stability_cycle")
    | .required_runtime_inputs[]
    | select(.id == "host_a")
    | .resolution_source
    | test("^roadmap_summary:")
  )
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "profile_default_gate_stability_cycle")
    | .required_runtime_inputs[]
    | select(.id == "host_b")
    | .state
  ) == "resolved"
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "profile_default_gate_stability_cycle")
    | .required_runtime_inputs[]
    | select(.id == "host_b")
    | .resolution_source
    | test("^roadmap_summary:")
  )
  and (.iterations | length == 1)
  and (.iterations[0].tracks | length == 1)
  and .iterations[0].tracks[0].track_id == "profile_default_gate_stability_cycle"
  and .iterations[0].tracks[0].status == "pass"
' "$ROADMAP_FALLBACK_HOSTS_SUMMARY" >/dev/null; then
  echo "roadmap-summary host fallback summary mismatch"
  cat "$ROADMAP_FALLBACK_HOSTS_SUMMARY"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected 1 execution in roadmap-summary host fallback path"
  cat "$EXEC_LOG"
  exit 1
fi
if ! grep -F "A:pass" "$EXEC_LOG" >/dev/null; then
  echo "track A should run in roadmap-summary host fallback path"
  cat "$EXEC_LOG"
  exit 1
fi
if grep -F "B:" "$EXEC_LOG" >/dev/null || grep -F "C:" "$EXEC_LOG" >/dev/null; then
  echo "tracks B/C should not run in roadmap-summary host fallback path"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-live-evidence-cycle-batch-run] roadmap-summary env-assignment fallback path"
ROADMAP_FALLBACK_ENV_ASSIGNMENTS_SUMMARY="$TMP_DIR/roadmap_fallback_env_assignments_summary.json"
: >"$EXEC_LOG"
A_HOST= B_HOST= PROFILE_DEFAULT_GATE_STABILITY_HOST_A= PROFILE_DEFAULT_GATE_STABILITY_HOST_B= \
PROFILE_DEFAULT_GATE_STABILITY_CAMPAIGN_SUBJECT= CAMPAIGN_SUBJECT= INVITE_KEY= \
BATCH_TRACK_EXEC_LOG="$EXEC_LOG" \
TRACK_A_BEHAVIOR=pass TRACK_B_BEHAVIOR=pass TRACK_C_BEHAVIOR=pass \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_ROADMAP_PROGRESS_SUMMARY_JSON="$FALLBACK_ENV_ASSIGNMENTS_ROADMAP_PROGRESS_SUMMARY_JSON" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_SCRIPT="$TRACK_A" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$TRACK_B" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_SCRIPT="$TRACK_C" \
bash ./scripts/roadmap_live_evidence_cycle_batch_run.sh \
  --reports-dir "$TMP_DIR/roadmap_fallback_env_assignments_reports" \
  --summary-json "$ROADMAP_FALLBACK_ENV_ASSIGNMENTS_SUMMARY" \
  --iterations 1 \
  --include-track-id profile_default_gate_stability_cycle \
  --include-track-id runtime_actuation_promotion_cycle \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .summary.executed_tracks == 2
  and .summary.skipped_tracks == 0
  and .inputs.selected_track_ids == [
    "profile_default_gate_stability_cycle",
    "runtime_actuation_promotion_cycle"
  ]
  and .selection_accounting.unresolved_required_track_count == 0
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "profile_default_gate_stability_cycle")
    | .required_runtime_inputs[]
    | select(.id == "host_a")
    | .state
  ) == "resolved"
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "profile_default_gate_stability_cycle")
    | .required_runtime_inputs[]
    | select(.id == "host_a")
    | .resolution_source
    | test("^roadmap_summary:")
  )
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "profile_default_gate_stability_cycle")
    | .required_runtime_inputs[]
    | select(.id == "host_b")
    | .state
  ) == "resolved"
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "profile_default_gate_stability_cycle")
    | .required_runtime_inputs[]
    | select(.id == "host_b")
    | .resolution_source
    | test("^roadmap_summary:")
  )
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "profile_default_gate_stability_cycle")
    | .required_runtime_inputs[]
    | select(.id == "campaign_subject")
    | .state
  ) == "resolved"
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "profile_default_gate_stability_cycle")
    | .required_runtime_inputs[]
    | select(.id == "campaign_subject")
    | .resolution_source
    | test("^roadmap_summary:")
  )
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "runtime_actuation_promotion_cycle")
    | .required_runtime_inputs[]
    | select(.id == "campaign_subject")
    | .state
  ) == "resolved"
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "runtime_actuation_promotion_cycle")
    | .required_runtime_inputs[]
    | select(.id == "campaign_subject")
    | .resolution_source
    | test("^roadmap_summary:")
  )
  and (.iterations | length == 1)
  and ([.iterations[0].tracks[].status] == ["pass","pass"])
' "$ROADMAP_FALLBACK_ENV_ASSIGNMENTS_SUMMARY" >/dev/null; then
  echo "roadmap-summary env-assignment fallback summary mismatch"
  cat "$ROADMAP_FALLBACK_ENV_ASSIGNMENTS_SUMMARY"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "2" ]]; then
  echo "expected 2 executions in roadmap-summary env-assignment fallback path"
  cat "$EXEC_LOG"
  exit 1
fi
if ! grep -F "A:pass" "$EXEC_LOG" >/dev/null || ! grep -F "B:pass" "$EXEC_LOG" >/dev/null; then
  echo "tracks A/B should run in roadmap-summary env-assignment fallback path"
  cat "$EXEC_LOG"
  exit 1
fi
if grep -F "C:" "$EXEC_LOG" >/dev/null; then
  echo "track C should not run in roadmap-summary env-assignment fallback path"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-live-evidence-cycle-batch-run] roadmap-summary placeholder env-assignment fail-closed path"
ROADMAP_FALLBACK_PLACEHOLDER_ENV_ASSIGNMENTS_SUMMARY="$TMP_DIR/roadmap_fallback_placeholder_env_assignments_summary.json"
: >"$EXEC_LOG"
set +e
A_HOST= B_HOST= PROFILE_DEFAULT_GATE_STABILITY_HOST_A= PROFILE_DEFAULT_GATE_STABILITY_HOST_B= \
PROFILE_DEFAULT_GATE_STABILITY_CAMPAIGN_SUBJECT= CAMPAIGN_SUBJECT= INVITE_KEY= \
BATCH_TRACK_EXEC_LOG="$EXEC_LOG" \
TRACK_A_BEHAVIOR=pass TRACK_B_BEHAVIOR=pass TRACK_C_BEHAVIOR=pass \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_ROADMAP_PROGRESS_SUMMARY_JSON="$FALLBACK_PLACEHOLDER_ENV_ASSIGNMENTS_ROADMAP_PROGRESS_SUMMARY_JSON" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_SCRIPT="$TRACK_A" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$TRACK_B" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_SCRIPT="$TRACK_C" \
bash ./scripts/roadmap_live_evidence_cycle_batch_run.sh \
  --reports-dir "$TMP_DIR/roadmap_fallback_placeholder_env_assignments_reports" \
  --summary-json "$ROADMAP_FALLBACK_PLACEHOLDER_ENV_ASSIGNMENTS_SUMMARY" \
  --iterations 1 \
  --include-track-id profile_default_gate_stability_cycle \
  --include-track-id runtime_actuation_promotion_cycle \
  --print-summary-json 0
roadmap_fallback_placeholder_env_assignments_rc=$?
set -e

if [[ "$roadmap_fallback_placeholder_env_assignments_rc" != "1" ]]; then
  echo "expected roadmap-summary placeholder env-assignment fail-closed rc=1, got rc=$roadmap_fallback_placeholder_env_assignments_rc"
  cat "$ROADMAP_FALLBACK_PLACEHOLDER_ENV_ASSIGNMENTS_SUMMARY"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .failure_substep == "execution:no_tracks_executed"
  and .failure_reason == "no selected tracks executed; required runtime inputs unresolved across all selected tracks"
  and .summary.executed_tracks == 0
  and .summary.skipped_tracks == 2
  and .summary.skipped_unresolved_runtime_input_tracks == 2
  and .selection_accounting.unresolved_required_track_ids == [
    "profile_default_gate_stability_cycle",
    "runtime_actuation_promotion_cycle"
  ]
  and .selection_accounting.unresolved_required_track_count == 2
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "profile_default_gate_stability_cycle")
    | .required_runtime_inputs[]
    | select(.id == "host_a")
    | .state
  ) == "placeholder_unresolved"
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "profile_default_gate_stability_cycle")
    | .required_runtime_inputs[]
    | select(.id == "host_a")
    | .resolution_source
  ) == null
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "profile_default_gate_stability_cycle")
    | .required_runtime_inputs[]
    | select(.id == "host_b")
    | .state
  ) == "placeholder_unresolved"
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "profile_default_gate_stability_cycle")
    | .required_runtime_inputs[]
    | select(.id == "host_b")
    | .resolution_source
  ) == null
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "profile_default_gate_stability_cycle")
    | .required_runtime_inputs[]
    | select(.id == "campaign_subject")
    | .state
  ) == "placeholder_unresolved"
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "runtime_actuation_promotion_cycle")
    | .required_runtime_inputs[]
    | select(.id == "campaign_subject")
    | .state
  ) == "placeholder_unresolved"
  and (.iterations | length == 1)
  and ([.iterations[0].tracks[].status] == ["skipped","skipped"])
  and .iterations[0].tracks[0].failure_kind == "skipped_unresolved_runtime_inputs"
  and .iterations[0].tracks[0].failure_diagnostics.unresolved_required_inputs == ["host_a","host_b","campaign_subject"]
  and .iterations[0].tracks[1].failure_kind == "skipped_unresolved_runtime_inputs"
  and .iterations[0].tracks[1].failure_diagnostics.unresolved_required_inputs == ["campaign_subject"]
' "$ROADMAP_FALLBACK_PLACEHOLDER_ENV_ASSIGNMENTS_SUMMARY" >/dev/null; then
  echo "roadmap-summary placeholder env-assignment fail-closed summary mismatch"
  cat "$ROADMAP_FALLBACK_PLACEHOLDER_ENV_ASSIGNMENTS_SUMMARY"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "0" ]]; then
  echo "expected 0 executions in roadmap-summary placeholder env-assignment fail-closed path"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-live-evidence-cycle-batch-run] roadmap-summary placeholder subject ignore path"
ROADMAP_FALLBACK_PLACEHOLDER_SUBJECT_SUMMARY="$TMP_DIR/roadmap_fallback_placeholder_subject_summary.json"
: >"$EXEC_LOG"
CAMPAIGN_SUBJECT= INVITE_KEY= \
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_VM_COMMAND_FILE="$VM_COMMAND_FILE" \
BATCH_TRACK_EXEC_LOG="$EXEC_LOG" \
TRACK_A_BEHAVIOR=pass TRACK_B_BEHAVIOR=pass TRACK_C_BEHAVIOR=pass \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_ROADMAP_PROGRESS_SUMMARY_JSON="$FALLBACK_PLACEHOLDER_SUBJECT_ROADMAP_PROGRESS_SUMMARY_JSON" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_SCRIPT="$TRACK_A" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$TRACK_B" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_SCRIPT="$TRACK_C" \
bash ./scripts/roadmap_live_evidence_cycle_batch_run.sh \
  --reports-dir "$TMP_DIR/roadmap_fallback_placeholder_subject_reports" \
  --summary-json "$ROADMAP_FALLBACK_PLACEHOLDER_SUBJECT_SUMMARY" \
  --iterations 1 \
  --include-track-id runtime_actuation_promotion_cycle \
  --include-track-id profile_compare_multi_vm_stability_promotion_cycle \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .summary.executed_tracks == 1
  and .summary.skipped_tracks == 1
  and .summary.skipped_unresolved_runtime_input_tracks == 1
  and .inputs.selected_track_ids == [
    "runtime_actuation_promotion_cycle",
    "profile_compare_multi_vm_stability_promotion_cycle"
  ]
  and .selection_accounting.unresolved_required_track_ids == [
    "runtime_actuation_promotion_cycle"
  ]
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "runtime_actuation_promotion_cycle")
    | .unresolved_required_count
  ) == 1
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "runtime_actuation_promotion_cycle")
    | .required_runtime_inputs[]
    | select(.id == "campaign_subject")
    | .state
  ) != "resolved"
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "runtime_actuation_promotion_cycle")
    | .required_runtime_inputs[]
    | select(.id == "campaign_subject")
    | .resolution_source
  ) == null
  and (.iterations | length == 1)
  and ([.iterations[0].tracks[].status] == ["skipped","pass"])
  and .iterations[0].tracks[0].track_id == "runtime_actuation_promotion_cycle"
  and .iterations[0].tracks[0].failure_kind == "skipped_unresolved_runtime_inputs"
  and .iterations[0].tracks[1].track_id == "profile_compare_multi_vm_stability_promotion_cycle"
  and .iterations[0].tracks[1].status == "pass"
' "$ROADMAP_FALLBACK_PLACEHOLDER_SUBJECT_SUMMARY" >/dev/null; then
  echo "roadmap-summary placeholder subject ignore summary mismatch"
  cat "$ROADMAP_FALLBACK_PLACEHOLDER_SUBJECT_SUMMARY"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected 1 execution in roadmap-summary placeholder subject ignore path"
  cat "$EXEC_LOG"
  exit 1
fi
if ! grep -F "C:pass" "$EXEC_LOG" >/dev/null; then
  echo "track C should run in roadmap-summary placeholder subject ignore path"
  cat "$EXEC_LOG"
  exit 1
fi
if grep -F "B:" "$EXEC_LOG" >/dev/null || grep -F "A:" "$EXEC_LOG" >/dev/null; then
  echo "tracks A/B should not run in roadmap-summary placeholder subject ignore path"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-live-evidence-cycle-batch-run] roadmap-summary concrete subject fallback path"
ROADMAP_FALLBACK_CONCRETE_SUBJECT_SUMMARY="$TMP_DIR/roadmap_fallback_concrete_subject_summary.json"
: >"$EXEC_LOG"
CAMPAIGN_SUBJECT= INVITE_KEY= \
BATCH_TRACK_EXEC_LOG="$EXEC_LOG" \
TRACK_A_BEHAVIOR=pass TRACK_B_BEHAVIOR=pass TRACK_C_BEHAVIOR=pass \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_ROADMAP_PROGRESS_SUMMARY_JSON="$FALLBACK_CONCRETE_SUBJECT_ROADMAP_PROGRESS_SUMMARY_JSON" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_SCRIPT="$TRACK_A" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$TRACK_B" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_SCRIPT="$TRACK_C" \
bash ./scripts/roadmap_live_evidence_cycle_batch_run.sh \
  --reports-dir "$TMP_DIR/roadmap_fallback_concrete_subject_reports" \
  --summary-json "$ROADMAP_FALLBACK_CONCRETE_SUBJECT_SUMMARY" \
  --iterations 1 \
  --include-track-id runtime_actuation_promotion_cycle \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .summary.executed_tracks == 1
  and .summary.skipped_tracks == 0
  and .selection_accounting.unresolved_required_track_count == 0
  and .inputs.selected_track_ids == ["runtime_actuation_promotion_cycle"]
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "runtime_actuation_promotion_cycle")
    | .required_runtime_inputs[]
    | select(.id == "campaign_subject")
    | .state
  ) == "resolved"
  and (
    .inputs.track_runtime_requirements[]
    | select(.track_id == "runtime_actuation_promotion_cycle")
    | .required_runtime_inputs[]
    | select(.id == "campaign_subject")
    | .resolution_source
    | test("^roadmap_summary:")
  )
  and (.iterations | length == 1)
  and (.iterations[0].tracks | length == 1)
  and .iterations[0].tracks[0].track_id == "runtime_actuation_promotion_cycle"
  and .iterations[0].tracks[0].status == "pass"
' "$ROADMAP_FALLBACK_CONCRETE_SUBJECT_SUMMARY" >/dev/null; then
  echo "roadmap-summary concrete subject fallback summary mismatch"
  cat "$ROADMAP_FALLBACK_CONCRETE_SUBJECT_SUMMARY"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected 1 execution in roadmap-summary concrete subject fallback path"
  cat "$EXEC_LOG"
  exit 1
fi
if ! grep -F "B:pass" "$EXEC_LOG" >/dev/null; then
  echo "track B should run in roadmap-summary concrete subject fallback path"
  cat "$EXEC_LOG"
  exit 1
fi
if grep -F "A:" "$EXEC_LOG" >/dev/null || grep -F "C:" "$EXEC_LOG" >/dev/null; then
  echo "tracks A/C should not run in roadmap-summary concrete subject fallback path"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-live-evidence-cycle-batch-run] m5 unresolved runtime-input partial-progress path"
M5_UNRESOLVED_SUMMARY="$TMP_DIR/m5_unresolved_summary.json"
: >"$EXEC_LOG"
set +e
A_HOST=203.0.113.10 B_HOST=203.0.113.11 INVITE_KEY=inv-real-005 CAMPAIGN_SUBJECT=inv-real-005 \
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_VM_COMMAND_FILE= \
PROFILE_COMPARE_MULTI_VM_STABILITY_VM_COMMAND_FILE= \
PROFILE_COMPARE_MULTI_VM_VM_COMMAND_FILE= \
BATCH_TRACK_EXEC_LOG="$EXEC_LOG" \
TRACK_A_BEHAVIOR=pass TRACK_B_BEHAVIOR=pass TRACK_C_BEHAVIOR=pass \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_SCRIPT="$TRACK_A" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$TRACK_B" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_SCRIPT="$TRACK_C" \
bash ./scripts/roadmap_live_evidence_cycle_batch_run.sh \
  --reports-dir "$TMP_DIR/m5_unresolved_reports" \
  --summary-json "$M5_UNRESOLVED_SUMMARY" \
  --iterations 1 \
  --continue-on-fail 0 \
  --parallel 0 \
  --print-summary-json 0
m5_unresolved_rc=$?
set -e

if [[ "$m5_unresolved_rc" != "0" ]]; then
  echo "expected m5 unresolved partial-progress path rc=0, got rc=$m5_unresolved_rc"
  cat "$M5_UNRESOLVED_SUMMARY"
  exit 1
fi

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .failure_substep == null
  and .stages.execution.status == "pass"
  and .stages.execution.partial_progress_runtime_input_skips == true
  and .summary.iterations_completed == 1
  and .summary.executed_tracks == 2
  and .summary.skipped_tracks == 1
  and .summary.skipped_unresolved_runtime_input_tracks == 1
  and .selection_accounting.unresolved_required_track_ids == [
    "profile_compare_multi_vm_stability_promotion_cycle"
  ]
  and .selection_accounting.unresolved_required_track_count == 1
  and (.iterations | length == 1)
  and .iterations[0].status == "pass"
  and .iterations[0].rc == 0
  and ([.iterations[0].tracks[].status] == ["pass","pass","skipped"])
  and .iterations[0].tracks[2].track_id == "profile_compare_multi_vm_stability_promotion_cycle"
  and .iterations[0].tracks[2].failure_kind == "skipped_unresolved_runtime_inputs"
  and .iterations[0].tracks[2].failure_diagnostics.track_group == "m5_multi_vm_stability_promotion"
  and .iterations[0].tracks[2].failure_diagnostics.failure_kind == "required_runtime_input_unresolved"
  and .iterations[0].tracks[2].failure_diagnostics.unresolved_required_inputs == ["vm_command_source"]
  and .iterations[0].tracks[2].failure_diagnostics.unresolved_required_inputs_count == 1
  and .iterations[0].tracks[2].failure_diagnostics.partial_progress_skip == true
' "$M5_UNRESOLVED_SUMMARY" >/dev/null; then
  echo "m5 unresolved partial-progress summary mismatch"
  cat "$M5_UNRESOLVED_SUMMARY"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "2" ]]; then
  echo "expected 2 executions in m5 unresolved partial-progress path"
  cat "$EXEC_LOG"
  exit 1
fi
if ! grep -F "A:pass" "$EXEC_LOG" >/dev/null || ! grep -F "B:pass" "$EXEC_LOG" >/dev/null; then
  echo "tracks A/B should run in m5 unresolved partial-progress path"
  cat "$EXEC_LOG"
  exit 1
fi
if grep -F "C:" "$EXEC_LOG" >/dev/null; then
  echo "track C should not run in m5 unresolved partial-progress path"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-live-evidence-cycle-batch-run] all-selected-unresolved fail-closed path"
ALL_UNRESOLVED_SUMMARY="$TMP_DIR/all_unresolved_summary.json"
: >"$EXEC_LOG"
set +e
A_HOST=203.0.113.10 B_HOST=203.0.113.11 INVITE_KEY=inv-real-006 CAMPAIGN_SUBJECT=inv-real-006 \
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_VM_COMMAND_FILE= \
PROFILE_COMPARE_MULTI_VM_STABILITY_VM_COMMAND_FILE= \
PROFILE_COMPARE_MULTI_VM_VM_COMMAND_FILE= \
BATCH_TRACK_EXEC_LOG="$EXEC_LOG" \
TRACK_A_BEHAVIOR=pass TRACK_B_BEHAVIOR=pass TRACK_C_BEHAVIOR=pass \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_SCRIPT="$TRACK_A" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$TRACK_B" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_SCRIPT="$TRACK_C" \
bash ./scripts/roadmap_live_evidence_cycle_batch_run.sh \
  --reports-dir "$TMP_DIR/all_unresolved_reports" \
  --summary-json "$ALL_UNRESOLVED_SUMMARY" \
  --iterations 1 \
  --continue-on-fail 0 \
  --parallel 0 \
  --include-track-id profile_compare_multi_vm_stability_promotion_cycle \
  --print-summary-json 0
all_unresolved_rc=$?
set -e

if [[ "$all_unresolved_rc" != "1" ]]; then
  echo "expected all-selected-unresolved fail-closed rc=1, got rc=$all_unresolved_rc"
  cat "$ALL_UNRESOLVED_SUMMARY"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .failure_substep == "execution:no_tracks_executed"
  and .failure_reason == "no selected tracks executed; required runtime inputs unresolved across all selected tracks"
  and .summary.iterations_requested == 1
  and .summary.iterations_completed == 1
  and .summary.executed_tracks == 0
  and .summary.skipped_tracks == 1
  and .summary.skipped_unresolved_runtime_input_tracks == 1
  and .summary.selected_track_count == 1
  and .selection_accounting.unresolved_required_track_ids == [
    "profile_compare_multi_vm_stability_promotion_cycle"
  ]
  and .selection_accounting.unresolved_required_track_count == 1
  and (.per_track | length == 1)
  and .per_track[0].id == "profile_compare_multi_vm_stability_promotion_cycle"
  and .per_track[0].total_runs == 0
  and .per_track[0].pass == 0
  and .per_track[0].fail == 0
  and .per_track[0].skipped == 1
  and (.iterations | length == 1)
  and .iterations[0].status == "pass"
  and .iterations[0].rc == 0
  and (.iterations[0].tracks | length == 1)
  and .iterations[0].tracks[0].status == "skipped"
  and .iterations[0].tracks[0].failure_kind == "skipped_unresolved_runtime_inputs"
  and .iterations[0].tracks[0].failure_diagnostics.failure_kind == "required_runtime_input_unresolved"
  and .iterations[0].tracks[0].failure_diagnostics.unresolved_required_inputs == ["vm_command_source"]
' "$ALL_UNRESOLVED_SUMMARY" >/dev/null; then
  echo "all-selected-unresolved fail-closed summary mismatch"
  cat "$ALL_UNRESOLVED_SUMMARY"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "0" ]]; then
  echo "expected 0 executions in all-selected-unresolved fail-closed path"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-live-evidence-cycle-batch-run] continue-on-fail path"
CONTINUE_SUMMARY="$TMP_DIR/continue_summary.json"
: >"$EXEC_LOG"
set +e
A_HOST=203.0.113.10 B_HOST=203.0.113.11 INVITE_KEY=inv-real-003 CAMPAIGN_SUBJECT=inv-real-003 \
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_VM_COMMAND_FILE="$VM_COMMAND_FILE" \
BATCH_TRACK_EXEC_LOG="$EXEC_LOG" \
TRACK_A_BEHAVIOR=pass TRACK_B_BEHAVIOR=fail TRACK_B_RC=23 TRACK_C_BEHAVIOR=pass \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_SCRIPT="$TRACK_A" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$TRACK_B" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_SCRIPT="$TRACK_C" \
bash ./scripts/roadmap_live_evidence_cycle_batch_run.sh \
  --reports-dir "$TMP_DIR/continue_reports" \
  --summary-json "$CONTINUE_SUMMARY" \
  --iterations 2 \
  --continue-on-fail 1 \
  --parallel 0 \
  --print-summary-json 0
continue_rc=$?
set -e

if [[ "$continue_rc" != "23" ]]; then
  echo "expected continue-on-fail rc=23, got rc=$continue_rc"
  cat "$CONTINUE_SUMMARY"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 23
  and .failure_substep == "execution:iteration_1:track_runtime_actuation_promotion_cycle"
  and .failure_reason == "first failing track in deterministic iteration/track order"
  and .summary.iterations_requested == 2
  and .summary.iterations_completed == 2
  and .summary.executed_tracks == 6
  and .summary.skipped_tracks == 0
  and .summary.halt_after_iteration == false
  and .summary.first_failure_iteration == 1
  and .summary.first_failure_track_id == "runtime_actuation_promotion_cycle"
  and (.per_track | length == 3)
  and .per_track[0].total_runs == 2
  and .per_track[0].pass == 2
  and .per_track[0].fail == 0
  and .per_track[0].skipped == 0
  and .per_track[1].total_runs == 2
  and .per_track[1].pass == 0
  and .per_track[1].fail == 2
  and .per_track[1].skipped == 0
  and .per_track[2].total_runs == 2
  and .per_track[2].pass == 2
  and .per_track[2].fail == 0
  and .per_track[2].skipped == 0
  and (.iterations | length == 2)
  and ([.iterations[].status] == ["fail","fail"])
  and ([.iterations[].failure_substep] == ["track_failed:runtime_actuation_promotion_cycle","track_failed:runtime_actuation_promotion_cycle"])
  and .iterations[0].tracks[1].failure_diagnostics.failure_kind == "track_execution_failed"
  and .iterations[1].tracks[1].failure_diagnostics.failure_kind == "track_execution_failed"
  and .iterations[0].tracks[1].failure_diagnostics.log_tail_lines == ["runtime_actuation_promotion_cycle failed rc=23"]
  and .iterations[1].tracks[1].failure_diagnostics.log_tail_lines == ["runtime_actuation_promotion_cycle failed rc=23"]
' "$CONTINUE_SUMMARY" >/dev/null; then
  echo "continue-on-fail summary mismatch"
  cat "$CONTINUE_SUMMARY"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "6" ]]; then
  echo "expected 6 executions in continue-on-fail path"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-live-evidence-cycle-batch-run] filtering path"
FILTER_SUMMARY="$TMP_DIR/filter_summary.json"
: >"$EXEC_LOG"
A_HOST=203.0.113.10 B_HOST=203.0.113.11 INVITE_KEY=inv-real-004 CAMPAIGN_SUBJECT=inv-real-004 \
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_VM_COMMAND_FILE="$VM_COMMAND_FILE" \
BATCH_TRACK_EXEC_LOG="$EXEC_LOG" \
TRACK_A_BEHAVIOR=pass TRACK_B_BEHAVIOR=pass TRACK_C_BEHAVIOR=pass \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_SCRIPT="$TRACK_A" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$TRACK_B" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CYCLE_SCRIPT="$TRACK_C" \
bash ./scripts/roadmap_live_evidence_cycle_batch_run.sh \
  --reports-dir "$TMP_DIR/filter_reports" \
  --summary-json "$FILTER_SUMMARY" \
  --iterations 1 \
  --include-track-id "profile_default_gate_stability_cycle,runtime_actuation_promotion_cycle" \
  --exclude-track-id "runtime_actuation_promotion_cycle" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .failure_substep == null
  and .failure_reason == null
  and .inputs.include_track_ids == ["profile_default_gate_stability_cycle","runtime_actuation_promotion_cycle"]
  and .inputs.exclude_track_ids == ["runtime_actuation_promotion_cycle"]
  and .inputs.selected_track_ids == ["profile_default_gate_stability_cycle"]
  and .summary.selected_track_count == 1
  and .summary.executed_tracks == 1
  and .summary.skipped_tracks == 0
  and (.per_track | length == 1)
  and .per_track[0].id == "profile_default_gate_stability_cycle"
  and .per_track[0].total_runs == 1
  and .per_track[0].pass == 1
  and .per_track[0].fail == 0
  and .per_track[0].skipped == 0
  and (.iterations | length == 1)
  and (.iterations[0].tracks | length == 1)
  and .iterations[0].tracks[0].track_id == "profile_default_gate_stability_cycle"
' "$FILTER_SUMMARY" >/dev/null; then
  echo "filtering summary mismatch"
  cat "$FILTER_SUMMARY"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected 1 execution in filtering path"
  cat "$EXEC_LOG"
  exit 1
fi
if ! grep -F "A:pass" "$EXEC_LOG" >/dev/null; then
  echo "expected track A to execute in filtering path"
  cat "$EXEC_LOG"
  exit 1
fi
if grep -F "B:" "$EXEC_LOG" >/dev/null || grep -F "C:" "$EXEC_LOG" >/dev/null; then
  echo "unexpected track execution in filtering path"
  cat "$EXEC_LOG"
  exit 1
fi

echo "roadmap live evidence cycle batch run integration check ok"
