#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod mkdir cat grep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

mkdir -p "$ROOT_DIR/.easy-node-logs"
TMP_DIR="$(mktemp -d "$ROOT_DIR/.easy-node-logs/integration_roadmap_live_evidence_actionable_run_XXXXXX")"
ACTION_TMP_DIR="$(mktemp -d "$ROOT_DIR/scripts/.integration_roadmap_live_evidence_actionable_run.XXXXXX")"
trap 'rm -rf "$TMP_DIR" "$ACTION_TMP_DIR"' EXIT

FAKE_ROADMAP="$TMP_DIR/fake_roadmap_progress_report.sh"
EXEC_LOG="$TMP_DIR/executed_actions.log"
PASS_PROFILE_DEFAULT_GATE="$ACTION_TMP_DIR/pass_profile_default_gate.sh"
PASS_RUNTIME_ACTUATION_PROMOTION="$ACTION_TMP_DIR/pass_runtime_actuation_promotion.sh"
PASS_PROFILE_COMPARE_MULTI_VM_STABILITY="$ACTION_TMP_DIR/pass_profile_compare_multi_vm_stability.sh"
PASS_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION="$ACTION_TMP_DIR/pass_profile_compare_multi_vm_stability_promotion.sh"
FAIL_PROFILE_COMPARE_MULTI_VM_STABILITY="$ACTION_TMP_DIR/fail_profile_compare_multi_vm_stability.sh"
NON_TARGET_FAIL="$ACTION_TMP_DIR/non_target_should_not_run_fail.sh"

cat >"$PASS_PROFILE_DEFAULT_GATE" <<EOF_PASS_PROFILE_DEFAULT_GATE
#!/usr/bin/env bash
set -euo pipefail
echo "profile_default_gate" >>"$EXEC_LOG"
echo "profile_default_gate pass"
EOF_PASS_PROFILE_DEFAULT_GATE
chmod +x "$PASS_PROFILE_DEFAULT_GATE"

cat >"$PASS_RUNTIME_ACTUATION_PROMOTION" <<EOF_PASS_RUNTIME_ACTUATION_PROMOTION
#!/usr/bin/env bash
set -euo pipefail
echo "runtime_actuation_promotion" >>"$EXEC_LOG"
echo "runtime_actuation_promotion pass"
EOF_PASS_RUNTIME_ACTUATION_PROMOTION
chmod +x "$PASS_RUNTIME_ACTUATION_PROMOTION"

cat >"$PASS_PROFILE_COMPARE_MULTI_VM_STABILITY" <<EOF_PASS_PROFILE_COMPARE_MULTI_VM_STABILITY
#!/usr/bin/env bash
set -euo pipefail
echo "profile_compare_multi_vm_stability" >>"$EXEC_LOG"
echo "profile_compare_multi_vm_stability pass"
EOF_PASS_PROFILE_COMPARE_MULTI_VM_STABILITY
chmod +x "$PASS_PROFILE_COMPARE_MULTI_VM_STABILITY"

cat >"$PASS_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION" <<EOF_PASS_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION
#!/usr/bin/env bash
set -euo pipefail
echo "profile_compare_multi_vm_stability_promotion" >>"$EXEC_LOG"
echo "profile_compare_multi_vm_stability_promotion pass"
EOF_PASS_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION
chmod +x "$PASS_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION"

cat >"$FAIL_PROFILE_COMPARE_MULTI_VM_STABILITY" <<EOF_FAIL_PROFILE_COMPARE_MULTI_VM_STABILITY
#!/usr/bin/env bash
set -euo pipefail
echo "profile_compare_multi_vm_stability" >>"$EXEC_LOG"
echo "profile_compare_multi_vm_stability fail"
exit 17
EOF_FAIL_PROFILE_COMPARE_MULTI_VM_STABILITY
chmod +x "$FAIL_PROFILE_COMPARE_MULTI_VM_STABILITY"

cat >"$NON_TARGET_FAIL" <<EOF_NON_TARGET_FAIL
#!/usr/bin/env bash
set -euo pipefail
echo "non_target_should_not_run" >>"$EXEC_LOG"
echo "non-target action should never run"
exit 99
EOF_NON_TARGET_FAIL
chmod +x "$NON_TARGET_FAIL"

cat >"$FAKE_ROADMAP" <<'EOF_FAKE_ROADMAP'
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
  echo "fake roadmap: missing --summary-json or --report-md"
  exit 2
fi
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"
scenario="${ROADMAP_LIVE_EVIDENCE_ACTIONABLE_SCENARIO:-mixed_success}"
case "$scenario" in
  mixed_success)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"vpn_rc_standard_path","label":"Non-target (must not run)","command":"bash \"$NON_TARGET_FAIL\"","reason":"must-not-run"},
    {"id":"profile_default_gate","label":"Profile default gate","command":"bash \"$PASS_PROFILE_DEFAULT_GATE\"","reason":"live-cycle"},
    {"id":"runtime_actuation_promotion","label":"Runtime actuation promotion","command":"bash \"$PASS_RUNTIME_ACTUATION_PROMOTION\"","reason":"live-cycle"},
    {"id":"runtime_actuation_promotion_evidence_pack","label":"Evidence-pack publish action (must not run)","command":"bash \"$NON_TARGET_FAIL\"","reason":"must-not-run"},
    {"id":"profile_compare_multi_vm_stability_promotion","label":"Target id with empty command","command":"","reason":"empty-command"}
  ]
}
JSON
    ;;
  mixed_fail_first)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"client_vpn_smoke","label":"Non-target (must not run)","command":"bash \"$NON_TARGET_FAIL\"","reason":"must-not-run"},
    {"id":"profile_compare_multi_vm_stability","label":"Profile compare multi-vm stability fail","command":"bash \"$FAIL_PROFILE_COMPARE_MULTI_VM_STABILITY\"","reason":"live-cycle"},
    {"id":"runtime_actuation_promotion","label":"Runtime actuation promotion pass","command":"bash \"$PASS_RUNTIME_ACTUATION_PROMOTION\"","reason":"live-cycle"}
  ]
}
JSON
    ;;
  duplicates_ordering)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"runtime_actuation_promotion","label":"Runtime pass first","command":"bash \"$PASS_RUNTIME_ACTUATION_PROMOTION\"","reason":"live-cycle"},
    {"id":"profile_default_gate","label":"Profile pass second","command":"bash \"$PASS_PROFILE_DEFAULT_GATE\"","reason":"live-cycle"},
    {"id":"runtime_actuation_promotion","label":"Runtime duplicate must be deduped","command":"bash \"$NON_TARGET_FAIL\"","reason":"duplicate-should-not-run"},
    {"id":"profile_compare_multi_vm_stability","label":"Multi-vm pass third","command":"bash \"$PASS_PROFILE_COMPARE_MULTI_VM_STABILITY\"","reason":"live-cycle"},
    {"id":"profile_default_gate","label":"Profile duplicate must be deduped","command":"bash \"$NON_TARGET_FAIL\"","reason":"duplicate-should-not-run"},
    {"id":"profile_compare_multi_vm_stability_promotion","label":"Target id with empty command","command":"","reason":"empty-command"}
  ]
}
JSON
    ;;
  derived_projection)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"runtime_actuation_promotion","label":"Runtime pass first","command":"bash \"$PASS_RUNTIME_ACTUATION_PROMOTION\"","reason":"live-cycle"},
    {"id":"profile_default_gate","label":"Profile pass second","command":"bash \"$PASS_PROFILE_DEFAULT_GATE\"","reason":"live-cycle"},
    {"id":"profile_compare_multi_vm_stability","label":"Multi-vm pass third","command":"bash \"$PASS_PROFILE_COMPARE_MULTI_VM_STABILITY\"","reason":"live-cycle"},
    {"id":"runtime_actuation_promotion","label":"Runtime duplicate must be deduped","command":"bash \"$NON_TARGET_FAIL\"","reason":"duplicate-should-not-run"},
    {"id":"profile_compare_multi_vm_stability_promotion","label":"Multi-vm promotion pass fourth","command":"bash \"$PASS_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION\"","reason":"live-cycle"},
    {"id":"runtime_actuation_promotion_evidence_pack","label":"Derived evidence-pack present","command":"bash \"$NON_TARGET_FAIL\"","reason":"snapshot-only"},
    {"id":"profile_compare_multi_vm_stability_promotion_evidence_pack","label":"Derived evidence-pack present","command":"bash \"$NON_TARGET_FAIL\"","reason":"snapshot-only"},
    {"id":"profile_default_gate_evidence_pack_disabled","label":"Non-derived evidence-like id","command":"bash \"$NON_TARGET_FAIL\"","reason":"snapshot-only"}
  ]
}
JSON
    ;;
  no_targets)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate_evidence_pack","label":"Evidence-pack publish only","command":"bash \"$NON_TARGET_FAIL\"","reason":"must-not-run"},
    {"id":"runtime_actuation_promotion_evidence_pack","label":"Evidence-pack publish only","command":"bash \"$NON_TARGET_FAIL\"","reason":"must-not-run"}
  ]
}
JSON
    ;;
  *)
    echo "unknown fake scenario: $scenario"
    exit 2
    ;;
esac
echo "# fake roadmap report" >"$report_md"
EOF_FAKE_ROADMAP
chmod +x "$FAKE_ROADMAP"

echo "[roadmap-live-evidence-actionable-run] help contract"
if ! bash ./scripts/roadmap_live_evidence_actionable_run.sh --help | grep -F -- "--reports-dir DIR" >/dev/null; then
  echo "help output missing --reports-dir DIR"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_actionable_run.sh --help | grep -F -- "--summary-json PATH" >/dev/null; then
  echo "help output missing --summary-json PATH"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_actionable_run.sh --help | grep -F -- "--roadmap-summary-json PATH" >/dev/null; then
  echo "help output missing --roadmap-summary-json PATH"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_actionable_run.sh --help | grep -F -- "--roadmap-report-md PATH" >/dev/null; then
  echo "help output missing --roadmap-report-md PATH"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_actionable_run.sh --help | grep -F -- "--action-timeout-sec N" >/dev/null; then
  echo "help output missing --action-timeout-sec N"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_actionable_run.sh --help | grep -F -- "--allow-unsafe-shell-commands [0|1]" >/dev/null; then
  echo "help output missing --allow-unsafe-shell-commands [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_actionable_run.sh --help | grep -F -- "--refresh-manual-validation [0|1]" >/dev/null; then
  echo "help output missing --refresh-manual-validation [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_actionable_run.sh --help | grep -F -- "--refresh-single-machine-readiness [0|1]" >/dev/null; then
  echo "help output missing --refresh-single-machine-readiness [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_actionable_run.sh --help | grep -F -- "--scope auto|all|profile-default|runtime-actuation|multi-vm" >/dev/null; then
  echo "help output missing --scope auto|all|profile-default|runtime-actuation|multi-vm"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_actionable_run.sh --help | grep -F -- "--parallel [0|1]" >/dev/null; then
  echo "help output missing --parallel [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_actionable_run.sh --help | grep -F -- "--max-actions N" >/dev/null; then
  echo "help output missing --max-actions N"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_actionable_run.sh --help | grep -F -- "--print-derived-evidence-pack-ids [0|1]" >/dev/null; then
  echo "help output missing --print-derived-evidence-pack-ids [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_live_evidence_actionable_run.sh --help | grep -F -- "--print-summary-json [0|1]" >/dev/null; then
  echo "help output missing --print-summary-json [0|1]"
  exit 1
fi

echo "[roadmap-live-evidence-actionable-run] mixed success path selects only target ids and delegates execution"
SUMMARY_SUCCESS="$TMP_DIR/summary_success.json"
REPORTS_SUCCESS="$TMP_DIR/reports_success"
: >"$EXEC_LOG"
ROADMAP_LIVE_EVIDENCE_ACTIONABLE_SCENARIO=mixed_success \
PASS_PROFILE_DEFAULT_GATE="$PASS_PROFILE_DEFAULT_GATE" \
PASS_RUNTIME_ACTUATION_PROMOTION="$PASS_RUNTIME_ACTUATION_PROMOTION" \
PASS_PROFILE_COMPARE_MULTI_VM_STABILITY="$PASS_PROFILE_COMPARE_MULTI_VM_STABILITY" \
FAIL_PROFILE_COMPARE_MULTI_VM_STABILITY="$FAIL_PROFILE_COMPARE_MULTI_VM_STABILITY" \
NON_TARGET_FAIL="$NON_TARGET_FAIL" \
ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_live_evidence_actionable_run.sh \
  --reports-dir "$REPORTS_SUCCESS" \
  --summary-json "$SUMMARY_SUCCESS" \
  --refresh-manual-validation 1 \
  --refresh-single-machine-readiness 1 \
  --parallel 1 \
  --max-actions 1 \
  --action-timeout-sec 2 \
  --print-summary-json 0

if ! jq -e '
  .version == 1
  and .schema.id == "roadmap_live_evidence_actionable_run_summary"
  and .status == "pass"
  and .rc == 0
  and .inputs.refresh_manual_validation == true
  and .inputs.refresh_single_machine_readiness == true
  and .inputs.parallel == true
  and .inputs.scope == "profile-default"
  and .inputs.resolved_scope == "profile-default"
  and (.inputs.scope_inference_reason | contains("explicit scope: profile-default"))
  and .inputs.max_actions == 1
  and .inputs.action_timeout_sec == 2
  and .inputs.allow_unsafe_shell_commands == false
  and .inputs.target_action_ids == ["profile_default_gate","runtime_actuation_promotion","profile_compare_multi_vm_stability","profile_compare_multi_vm_stability_promotion"]
  and .roadmap.resolved_scope == "profile-default"
  and (.roadmap.scope_inference_reason | contains("explicit scope: profile-default"))
  and .roadmap.generated_this_run == true
  and .roadmap.target_match_count == 2
  and .roadmap.target_match_action_ids == ["profile_default_gate","runtime_actuation_promotion"]
  and .roadmap.target_match_unique_count == 2
  and .roadmap.target_match_unique_action_ids == ["profile_default_gate","runtime_actuation_promotion"]
  and .roadmap.scope_target_action_ids == ["profile_default_gate"]
  and .roadmap.scope_match_count == 1
  and .roadmap.scope_match_action_ids == ["profile_default_gate"]
  and .roadmap.scope_match_unique_count == 1
  and .roadmap.scope_match_unique_action_ids == ["profile_default_gate"]
  and .roadmap.derived_evidence_pack_map == [
    {"live_action_id":"profile_default_gate","evidence_pack_id":"profile_default_gate_evidence_pack"}
  ]
  and .roadmap.derived_evidence_pack_ids == ["profile_default_gate_evidence_pack"]
  and .roadmap.derived_evidence_pack_count == 1
  and .roadmap.derived_evidence_pack_missing_ids_in_snapshot == ["profile_default_gate_evidence_pack"]
  and .roadmap.derived_evidence_pack_missing_count_in_snapshot == 1
  and .roadmap.selected_unique_count == 1
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["profile_default_gate"]
  and .summary.derived_evidence_pack_count == 1
  and .summary.derived_evidence_pack_missing_count_in_snapshot == 1
  and .summary.selected_unique_count == 1
  and .summary.actions_executed == 1
  and .summary.pass == 1
  and .summary.fail == 0
  and .delegated_runner.summary_valid == true
  and .delegated_runner.status == "pass"
  and .delegated_runner.rc == 0
  and .delegated_runner.process_rc == 0
  and (.artifacts.summary_json | type == "string" and length > 0)
  and (.artifacts.next_actions_summary_json | type == "string" and length > 0)
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate"
  and .actions[0].status == "pass"
' "$SUMMARY_SUCCESS" >/dev/null; then
  echo "mixed success summary mismatch"
  cat "$SUMMARY_SUCCESS"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected exactly one executed action log entry for mixed success path"
  cat "$EXEC_LOG"
  exit 1
fi
if ! grep -Fx "profile_default_gate" "$EXEC_LOG" >/dev/null; then
  echo "expected executed log to contain profile_default_gate"
  cat "$EXEC_LOG"
  exit 1
fi
if grep -F "non_target_should_not_run" "$EXEC_LOG" >/dev/null; then
  echo "non-target action executed unexpectedly in mixed success path"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-live-evidence-actionable-run] mixed fail path preserves delegated rc semantics"
SUMMARY_FAIL="$TMP_DIR/summary_fail.json"
REPORTS_FAIL="$TMP_DIR/reports_fail"
: >"$EXEC_LOG"
set +e
ROADMAP_LIVE_EVIDENCE_ACTIONABLE_SCENARIO=mixed_fail_first \
PASS_PROFILE_DEFAULT_GATE="$PASS_PROFILE_DEFAULT_GATE" \
PASS_RUNTIME_ACTUATION_PROMOTION="$PASS_RUNTIME_ACTUATION_PROMOTION" \
PASS_PROFILE_COMPARE_MULTI_VM_STABILITY="$PASS_PROFILE_COMPARE_MULTI_VM_STABILITY" \
FAIL_PROFILE_COMPARE_MULTI_VM_STABILITY="$FAIL_PROFILE_COMPARE_MULTI_VM_STABILITY" \
NON_TARGET_FAIL="$NON_TARGET_FAIL" \
ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_live_evidence_actionable_run.sh \
  --reports-dir "$REPORTS_FAIL" \
  --summary-json "$SUMMARY_FAIL" \
  --scope all \
  --parallel 0 \
  --print-summary-json 0
fail_rc=$?
set -e
if [[ "$fail_rc" != "17" ]]; then
  echo "expected mixed fail rc=17, got rc=$fail_rc"
  cat "$SUMMARY_FAIL"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 17
  and .roadmap.target_match_count == 2
  and .roadmap.target_match_action_ids == ["profile_compare_multi_vm_stability","runtime_actuation_promotion"]
  and .roadmap.target_match_unique_count == 2
  and .roadmap.target_match_unique_action_ids == ["profile_compare_multi_vm_stability","runtime_actuation_promotion"]
  and .roadmap.derived_evidence_pack_map == [
    {"live_action_id":"profile_compare_multi_vm_stability","evidence_pack_id":"profile_compare_multi_vm_stability_promotion_evidence_pack"},
    {"live_action_id":"runtime_actuation_promotion","evidence_pack_id":"runtime_actuation_promotion_evidence_pack"}
  ]
  and .roadmap.derived_evidence_pack_ids == ["profile_compare_multi_vm_stability_promotion_evidence_pack","runtime_actuation_promotion_evidence_pack"]
  and .roadmap.derived_evidence_pack_count == 2
  and .roadmap.derived_evidence_pack_missing_ids_in_snapshot == ["profile_compare_multi_vm_stability_promotion_evidence_pack","runtime_actuation_promotion_evidence_pack"]
  and .roadmap.derived_evidence_pack_missing_count_in_snapshot == 2
  and .roadmap.selected_unique_count == 2
  and .roadmap.actions_selected_count == 2
  and .roadmap.selected_action_ids == ["profile_compare_multi_vm_stability","runtime_actuation_promotion"]
  and .summary.derived_evidence_pack_count == 2
  and .summary.derived_evidence_pack_missing_count_in_snapshot == 2
  and .summary.selected_unique_count == 2
  and .summary.actions_executed == 2
  and .summary.pass == 1
  and .summary.fail == 1
  and .delegated_runner.summary_valid == true
  and .delegated_runner.status == "fail"
  and .delegated_runner.rc == 17
  and .delegated_runner.process_rc == 17
  and ((.actions // []) | length == 2)
  and .actions[0].id == "profile_compare_multi_vm_stability"
  and .actions[0].status == "fail"
  and .actions[0].rc == 17
  and .actions[1].id == "runtime_actuation_promotion"
  and .actions[1].status == "pass"
' "$SUMMARY_FAIL" >/dev/null; then
  echo "mixed fail summary mismatch"
  cat "$SUMMARY_FAIL"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "2" ]]; then
  echo "expected exactly two executed action log entries for mixed fail path"
  cat "$EXEC_LOG"
  exit 1
fi
if ! grep -Fx "profile_compare_multi_vm_stability" "$EXEC_LOG" >/dev/null; then
  echo "expected executed log to contain profile_compare_multi_vm_stability"
  cat "$EXEC_LOG"
  exit 1
fi
if ! grep -Fx "runtime_actuation_promotion" "$EXEC_LOG" >/dev/null; then
  echo "expected executed log to contain runtime_actuation_promotion"
  cat "$EXEC_LOG"
  exit 1
fi
if grep -F "non_target_should_not_run" "$EXEC_LOG" >/dev/null; then
  echo "non-target action executed unexpectedly in mixed fail path"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-live-evidence-actionable-run] duplicate ids are delegated once and first-seen order stays stable"
SUMMARY_DEDUPE="$TMP_DIR/summary_dedupe.json"
REPORTS_DEDUPE="$TMP_DIR/reports_dedupe"
: >"$EXEC_LOG"
ROADMAP_LIVE_EVIDENCE_ACTIONABLE_SCENARIO=duplicates_ordering \
PASS_PROFILE_DEFAULT_GATE="$PASS_PROFILE_DEFAULT_GATE" \
PASS_RUNTIME_ACTUATION_PROMOTION="$PASS_RUNTIME_ACTUATION_PROMOTION" \
PASS_PROFILE_COMPARE_MULTI_VM_STABILITY="$PASS_PROFILE_COMPARE_MULTI_VM_STABILITY" \
FAIL_PROFILE_COMPARE_MULTI_VM_STABILITY="$FAIL_PROFILE_COMPARE_MULTI_VM_STABILITY" \
NON_TARGET_FAIL="$NON_TARGET_FAIL" \
ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_live_evidence_actionable_run.sh \
  --reports-dir "$REPORTS_DEDUPE" \
  --summary-json "$SUMMARY_DEDUPE" \
  --scope all \
  --parallel 0 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.target_match_count == 5
  and .roadmap.target_match_action_ids == ["runtime_actuation_promotion","profile_default_gate","runtime_actuation_promotion","profile_compare_multi_vm_stability","profile_default_gate"]
  and .roadmap.target_match_unique_count == 3
  and .roadmap.target_match_unique_action_ids == ["runtime_actuation_promotion","profile_default_gate","profile_compare_multi_vm_stability"]
  and .roadmap.derived_evidence_pack_map == [
    {"live_action_id":"runtime_actuation_promotion","evidence_pack_id":"runtime_actuation_promotion_evidence_pack"},
    {"live_action_id":"profile_default_gate","evidence_pack_id":"profile_default_gate_evidence_pack"},
    {"live_action_id":"profile_compare_multi_vm_stability","evidence_pack_id":"profile_compare_multi_vm_stability_promotion_evidence_pack"}
  ]
  and .roadmap.derived_evidence_pack_ids == ["runtime_actuation_promotion_evidence_pack","profile_default_gate_evidence_pack","profile_compare_multi_vm_stability_promotion_evidence_pack"]
  and .roadmap.derived_evidence_pack_count == 3
  and .roadmap.derived_evidence_pack_missing_ids_in_snapshot == ["runtime_actuation_promotion_evidence_pack","profile_default_gate_evidence_pack","profile_compare_multi_vm_stability_promotion_evidence_pack"]
  and .roadmap.derived_evidence_pack_missing_count_in_snapshot == 3
  and .roadmap.selected_unique_count == 3
  and .roadmap.actions_selected_count == 3
  and .roadmap.selected_action_ids == ["runtime_actuation_promotion","profile_default_gate","profile_compare_multi_vm_stability"]
  and .summary.derived_evidence_pack_count == 3
  and .summary.derived_evidence_pack_missing_count_in_snapshot == 3
  and .summary.selected_unique_count == 3
  and .summary.actions_executed == 3
  and .summary.pass == 3
  and .summary.fail == 0
  and ((.actions // []) | length == 3)
  and ([.actions[].id] == ["runtime_actuation_promotion","profile_default_gate","profile_compare_multi_vm_stability"])
' "$SUMMARY_DEDUPE" >/dev/null; then
  echo "duplicate-ordering summary mismatch"
  cat "$SUMMARY_DEDUPE"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "3" ]]; then
  echo "expected exactly three executed action log entries for dedupe path"
  cat "$EXEC_LOG"
  exit 1
fi
if [[ "$(grep -c '^runtime_actuation_promotion$' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected runtime_actuation_promotion to execute exactly once"
  cat "$EXEC_LOG"
  exit 1
fi
if [[ "$(grep -c '^profile_default_gate$' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected profile_default_gate to execute exactly once"
  cat "$EXEC_LOG"
  exit 1
fi
if [[ "$(grep -c '^profile_compare_multi_vm_stability$' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected profile_compare_multi_vm_stability to execute exactly once"
  cat "$EXEC_LOG"
  exit 1
fi
if grep -F "non_target_should_not_run" "$EXEC_LOG" >/dev/null; then
  echo "deduped duplicate fallback command executed unexpectedly"
  cat "$EXEC_LOG"
  exit 1
fi
mapfile -t deduped_executed_ids <"$EXEC_LOG"
if [[ "${deduped_executed_ids[0]:-}" != "runtime_actuation_promotion" || "${deduped_executed_ids[1]:-}" != "profile_default_gate" || "${deduped_executed_ids[2]:-}" != "profile_compare_multi_vm_stability" ]]; then
  echo "dedupe execution order mismatch"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-live-evidence-actionable-run] derived evidence-pack ids are deterministic, deduped, and missing-count aware"
SUMMARY_DERIVED="$TMP_DIR/summary_derived.json"
REPORTS_DERIVED="$TMP_DIR/reports_derived"
: >"$EXEC_LOG"
ROADMAP_LIVE_EVIDENCE_ACTIONABLE_SCENARIO=derived_projection \
PASS_PROFILE_DEFAULT_GATE="$PASS_PROFILE_DEFAULT_GATE" \
PASS_RUNTIME_ACTUATION_PROMOTION="$PASS_RUNTIME_ACTUATION_PROMOTION" \
PASS_PROFILE_COMPARE_MULTI_VM_STABILITY="$PASS_PROFILE_COMPARE_MULTI_VM_STABILITY" \
PASS_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION="$PASS_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION" \
FAIL_PROFILE_COMPARE_MULTI_VM_STABILITY="$FAIL_PROFILE_COMPARE_MULTI_VM_STABILITY" \
NON_TARGET_FAIL="$NON_TARGET_FAIL" \
ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_live_evidence_actionable_run.sh \
  --reports-dir "$REPORTS_DERIVED" \
  --summary-json "$SUMMARY_DERIVED" \
  --scope all \
  --parallel 0 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.target_match_count == 5
  and .roadmap.target_match_action_ids == ["runtime_actuation_promotion","profile_default_gate","profile_compare_multi_vm_stability","runtime_actuation_promotion","profile_compare_multi_vm_stability_promotion"]
  and .roadmap.target_match_unique_count == 4
  and .roadmap.target_match_unique_action_ids == ["runtime_actuation_promotion","profile_default_gate","profile_compare_multi_vm_stability","profile_compare_multi_vm_stability_promotion"]
  and .roadmap.derived_evidence_pack_map == [
    {"live_action_id":"runtime_actuation_promotion","evidence_pack_id":"runtime_actuation_promotion_evidence_pack"},
    {"live_action_id":"profile_default_gate","evidence_pack_id":"profile_default_gate_evidence_pack"},
    {"live_action_id":"profile_compare_multi_vm_stability","evidence_pack_id":"profile_compare_multi_vm_stability_promotion_evidence_pack"},
    {"live_action_id":"profile_compare_multi_vm_stability_promotion","evidence_pack_id":"profile_compare_multi_vm_stability_promotion_evidence_pack"}
  ]
  and .roadmap.derived_evidence_pack_ids == ["runtime_actuation_promotion_evidence_pack","profile_default_gate_evidence_pack","profile_compare_multi_vm_stability_promotion_evidence_pack"]
  and .roadmap.derived_evidence_pack_count == 3
  and .roadmap.derived_evidence_pack_missing_ids_in_snapshot == ["profile_default_gate_evidence_pack"]
  and .roadmap.derived_evidence_pack_missing_count_in_snapshot == 1
  and .roadmap.selected_unique_count == 4
  and .roadmap.actions_selected_count == 4
  and .roadmap.selected_action_ids == ["runtime_actuation_promotion","profile_default_gate","profile_compare_multi_vm_stability","profile_compare_multi_vm_stability_promotion"]
  and .summary.derived_evidence_pack_count == 3
  and .summary.derived_evidence_pack_missing_count_in_snapshot == 1
  and .summary.selected_unique_count == 4
  and .summary.actions_executed == 4
  and .summary.pass == 4
  and .summary.fail == 0
  and ((.actions // []) | length == 4)
  and ([.actions[].id] == ["runtime_actuation_promotion","profile_default_gate","profile_compare_multi_vm_stability","profile_compare_multi_vm_stability_promotion"])
' "$SUMMARY_DERIVED" >/dev/null; then
  echo "derived projection summary mismatch"
  cat "$SUMMARY_DERIVED"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "4" ]]; then
  echo "expected exactly four executed action log entries for derived projection path"
  cat "$EXEC_LOG"
  exit 1
fi
if [[ "$(grep -c '^runtime_actuation_promotion$' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected runtime_actuation_promotion to execute exactly once in derived projection path"
  cat "$EXEC_LOG"
  exit 1
fi
if [[ "$(grep -c '^profile_default_gate$' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected profile_default_gate to execute exactly once in derived projection path"
  cat "$EXEC_LOG"
  exit 1
fi
if [[ "$(grep -c '^profile_compare_multi_vm_stability$' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected profile_compare_multi_vm_stability to execute exactly once in derived projection path"
  cat "$EXEC_LOG"
  exit 1
fi
if [[ "$(grep -c '^profile_compare_multi_vm_stability_promotion$' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected profile_compare_multi_vm_stability_promotion to execute exactly once in derived projection path"
  cat "$EXEC_LOG"
  exit 1
fi
if grep -F "non_target_should_not_run" "$EXEC_LOG" >/dev/null; then
  echo "non-target action executed unexpectedly in derived projection path"
  cat "$EXEC_LOG"
  exit 1
fi
mapfile -t derived_executed_ids <"$EXEC_LOG"
if [[ "${derived_executed_ids[0]:-}" != "runtime_actuation_promotion" || "${derived_executed_ids[1]:-}" != "profile_default_gate" || "${derived_executed_ids[2]:-}" != "profile_compare_multi_vm_stability" || "${derived_executed_ids[3]:-}" != "profile_compare_multi_vm_stability_promotion" ]]; then
  echo "derived projection execution order mismatch"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-live-evidence-actionable-run] print-only mode outputs derived evidence-pack ids and skips delegation"
SUMMARY_DERIVED_PRINT_ONLY="$TMP_DIR/summary_derived_print_only.json"
REPORTS_DERIVED_PRINT_ONLY="$TMP_DIR/reports_derived_print_only"
PRINT_ONLY_STDOUT="$TMP_DIR/print_only_stdout.log"
: >"$EXEC_LOG"
ROADMAP_LIVE_EVIDENCE_ACTIONABLE_SCENARIO=derived_projection \
PASS_PROFILE_DEFAULT_GATE="$PASS_PROFILE_DEFAULT_GATE" \
PASS_RUNTIME_ACTUATION_PROMOTION="$PASS_RUNTIME_ACTUATION_PROMOTION" \
PASS_PROFILE_COMPARE_MULTI_VM_STABILITY="$PASS_PROFILE_COMPARE_MULTI_VM_STABILITY" \
PASS_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION="$PASS_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION" \
FAIL_PROFILE_COMPARE_MULTI_VM_STABILITY="$FAIL_PROFILE_COMPARE_MULTI_VM_STABILITY" \
NON_TARGET_FAIL="$NON_TARGET_FAIL" \
ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_live_evidence_actionable_run.sh \
  --reports-dir "$REPORTS_DERIVED_PRINT_ONLY" \
  --summary-json "$SUMMARY_DERIVED_PRINT_ONLY" \
  --scope all \
  --print-derived-evidence-pack-ids 1 \
  --print-summary-json 0 >"$PRINT_ONLY_STDOUT" 2>&1

if ! grep -Fx "runtime_actuation_promotion_evidence_pack" "$PRINT_ONLY_STDOUT" >/dev/null; then
  echo "print-only output missing runtime_actuation_promotion_evidence_pack"
  cat "$PRINT_ONLY_STDOUT"
  exit 1
fi
if ! grep -Fx "profile_default_gate_evidence_pack" "$PRINT_ONLY_STDOUT" >/dev/null; then
  echo "print-only output missing profile_default_gate_evidence_pack"
  cat "$PRINT_ONLY_STDOUT"
  exit 1
fi
if ! grep -Fx "profile_compare_multi_vm_stability_promotion_evidence_pack" "$PRINT_ONLY_STDOUT" >/dev/null; then
  echo "print-only output missing profile_compare_multi_vm_stability_promotion_evidence_pack"
  cat "$PRINT_ONLY_STDOUT"
  exit 1
fi
if grep -F "stage=roadmap_next_actions_run status=running" "$PRINT_ONLY_STDOUT" >/dev/null; then
  echo "print-only mode unexpectedly ran delegated next-actions stage"
  cat "$PRINT_ONLY_STDOUT"
  exit 1
fi
if [[ -s "$EXEC_LOG" ]]; then
  echo "print-only mode should not execute live actions"
  cat "$EXEC_LOG"
  exit 1
fi

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.print_derived_evidence_pack_ids == true
  and .inputs.print_only_mode == true
  and .roadmap.derived_evidence_pack_ids == ["runtime_actuation_promotion_evidence_pack","profile_default_gate_evidence_pack","profile_compare_multi_vm_stability_promotion_evidence_pack"]
  and .roadmap.derived_evidence_pack_count == 3
  and .roadmap.derived_evidence_pack_missing_count_in_snapshot == 1
  and .roadmap.selected_unique_count == 4
  and .roadmap.actions_selected_count == 4
  and .roadmap.selected_action_ids == ["runtime_actuation_promotion","profile_default_gate","profile_compare_multi_vm_stability","profile_compare_multi_vm_stability_promotion"]
  and .summary.derived_evidence_pack_count == 3
  and .summary.derived_evidence_pack_missing_count_in_snapshot == 1
  and .summary.selected_unique_count == 4
  and .summary.actions_executed == 0
  and .summary.pass == 0
  and .summary.fail == 0
  and ((.actions // []) | length == 0)
  and .delegated_runner.summary_valid == false
  and .delegated_runner.status == "skipped_print_derived_evidence_pack_ids"
  and .delegated_runner.rc == 0
  and .delegated_runner.process_rc == 0
' "$SUMMARY_DERIVED_PRINT_ONLY" >/dev/null; then
  echo "print-only summary mismatch"
  cat "$SUMMARY_DERIVED_PRINT_ONLY"
  exit 1
fi

echo "[roadmap-live-evidence-actionable-run] no-targets path is handled as pass with zero actions"
SUMMARY_EMPTY="$TMP_DIR/summary_empty.json"
REPORTS_EMPTY="$TMP_DIR/reports_empty"
: >"$EXEC_LOG"
ROADMAP_LIVE_EVIDENCE_ACTIONABLE_SCENARIO=no_targets \
PASS_PROFILE_DEFAULT_GATE="$PASS_PROFILE_DEFAULT_GATE" \
PASS_RUNTIME_ACTUATION_PROMOTION="$PASS_RUNTIME_ACTUATION_PROMOTION" \
PASS_PROFILE_COMPARE_MULTI_VM_STABILITY="$PASS_PROFILE_COMPARE_MULTI_VM_STABILITY" \
FAIL_PROFILE_COMPARE_MULTI_VM_STABILITY="$FAIL_PROFILE_COMPARE_MULTI_VM_STABILITY" \
NON_TARGET_FAIL="$NON_TARGET_FAIL" \
ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_live_evidence_actionable_run.sh \
  --reports-dir "$REPORTS_EMPTY" \
  --summary-json "$SUMMARY_EMPTY" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.target_match_count == 0
  and .roadmap.target_match_action_ids == []
  and .roadmap.target_match_unique_count == 0
  and .roadmap.target_match_unique_action_ids == []
  and .roadmap.derived_evidence_pack_map == []
  and .roadmap.derived_evidence_pack_ids == []
  and .roadmap.derived_evidence_pack_count == 0
  and .roadmap.derived_evidence_pack_missing_ids_in_snapshot == []
  and .roadmap.derived_evidence_pack_missing_count_in_snapshot == 0
  and .roadmap.selected_unique_count == 0
  and .roadmap.actions_selected_count == 0
  and .roadmap.selected_action_ids == []
  and .summary.derived_evidence_pack_count == 0
  and .summary.derived_evidence_pack_missing_count_in_snapshot == 0
  and .summary.selected_unique_count == 0
  and .summary.actions_executed == 0
  and .summary.pass == 0
  and .summary.fail == 0
  and .delegated_runner.summary_valid == true
  and .delegated_runner.status == "pass"
  and .delegated_runner.rc == 0
  and .delegated_runner.process_rc == 0
  and ((.actions // []) | length == 0)
' "$SUMMARY_EMPTY" >/dev/null; then
  echo "no-targets summary mismatch"
  cat "$SUMMARY_EMPTY"
  exit 1
fi

if [[ -s "$EXEC_LOG" ]]; then
  echo "expected no action executions in no-targets path"
  cat "$EXEC_LOG"
  exit 1
fi

echo "roadmap live evidence actionable run integration check ok"
