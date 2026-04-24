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
TMP_DIR="$(mktemp -d "$ROOT_DIR/.easy-node-logs/integration_roadmap_evidence_pack_actionable_run_XXXXXX")"
ACTION_TMP_DIR="$(mktemp -d "$ROOT_DIR/scripts/.integration_roadmap_evidence_pack_actionable_run.XXXXXX")"
trap 'rm -rf "$TMP_DIR" "$ACTION_TMP_DIR"' EXIT

FAKE_ROADMAP="$TMP_DIR/fake_roadmap_progress_report.sh"
FAKE_NEXT_ACTIONS_NO_SUMMARY="$TMP_DIR/fake_next_actions_no_summary.sh"
FAKE_NEXT_ACTIONS_PARTIAL_SUMMARY="$TMP_DIR/fake_next_actions_partial_summary.sh"
EXEC_LOG="$TMP_DIR/executed_actions.log"
PASS_EVIDENCE_1="$ACTION_TMP_DIR/pass_profile_default_gate_evidence_pack.sh"
PASS_EVIDENCE_2="$ACTION_TMP_DIR/pass_runtime_actuation_promotion_evidence_pack.sh"
PASS_EVIDENCE_MULTI_VM="$ACTION_TMP_DIR/pass_profile_compare_multi_vm_stability_promotion_evidence_pack.sh"
PASS_EVIDENCE_GENERIC="$ACTION_TMP_DIR/pass_any_other_evidence_pack.sh"
FAIL_EVIDENCE="$ACTION_TMP_DIR/fail_profile_default_gate_evidence_pack.sh"
NON_EVIDENCE_FAIL="$ACTION_TMP_DIR/non_evidence_should_not_run_fail.sh"
NON_EVIDENCE_PASS="$ACTION_TMP_DIR/non_evidence_should_not_run_pass.sh"

cat >"$PASS_EVIDENCE_1" <<EOF_PASS_EVIDENCE_1
#!/usr/bin/env bash
set -euo pipefail
echo "profile_default_gate_evidence_pack" >>"$EXEC_LOG"
echo "profile evidence pack pass"
EOF_PASS_EVIDENCE_1
chmod +x "$PASS_EVIDENCE_1"

cat >"$PASS_EVIDENCE_2" <<EOF_PASS_EVIDENCE_2
#!/usr/bin/env bash
set -euo pipefail
echo "runtime_actuation_promotion_evidence_pack" >>"$EXEC_LOG"
echo "runtime evidence pack pass"
EOF_PASS_EVIDENCE_2
chmod +x "$PASS_EVIDENCE_2"

cat >"$PASS_EVIDENCE_MULTI_VM" <<EOF_PASS_EVIDENCE_MULTI_VM
#!/usr/bin/env bash
set -euo pipefail
echo "profile_compare_multi_vm_stability_promotion_evidence_pack" >>"$EXEC_LOG"
echo "multi-vm evidence pack pass"
EOF_PASS_EVIDENCE_MULTI_VM
chmod +x "$PASS_EVIDENCE_MULTI_VM"

cat >"$PASS_EVIDENCE_GENERIC" <<EOF_PASS_EVIDENCE_GENERIC
#!/usr/bin/env bash
set -euo pipefail
echo "misc_evidence_pack" >>"$EXEC_LOG"
echo "generic evidence pack pass"
EOF_PASS_EVIDENCE_GENERIC
chmod +x "$PASS_EVIDENCE_GENERIC"

cat >"$FAIL_EVIDENCE" <<EOF_FAIL_EVIDENCE
#!/usr/bin/env bash
set -euo pipefail
echo "profile_default_gate_evidence_pack" >>"$EXEC_LOG"
echo "profile evidence pack fail"
exit 17
EOF_FAIL_EVIDENCE
chmod +x "$FAIL_EVIDENCE"

cat >"$NON_EVIDENCE_FAIL" <<EOF_NON_EVIDENCE_FAIL
#!/usr/bin/env bash
set -euo pipefail
echo "non_evidence_should_not_run_fail" >>"$EXEC_LOG"
echo "non evidence fail should not run"
exit 99
EOF_NON_EVIDENCE_FAIL
chmod +x "$NON_EVIDENCE_FAIL"

cat >"$NON_EVIDENCE_PASS" <<EOF_NON_EVIDENCE_PASS
#!/usr/bin/env bash
set -euo pipefail
echo "non_evidence_should_not_run_pass" >>"$EXEC_LOG"
echo "non evidence pass should not run"
EOF_NON_EVIDENCE_PASS
chmod +x "$NON_EVIDENCE_PASS"

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
scenario="${ROADMAP_EVIDENCE_PACK_ACTIONABLE_SCENARIO:-mixed_success}"
case "$scenario" in
  mixed_success)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"vpn_rc_standard_path","label":"Non evidence (must not run)","command":"bash \"$NON_EVIDENCE_FAIL\"","reason":"must-not-run"},
    {"id":"profile_default_gate_evidence_pack","label":"Profile evidence pack","command":"bash \"$PASS_EVIDENCE_1\"","reason":"evidence-pack"},
    {"id":"runtime_actuation_promotion","label":"Non evidence (must not run)","command":"bash \"$NON_EVIDENCE_FAIL\"","reason":"must-not-run"},
    {"id":"runtime_actuation_promotion_evidence_pack","label":"Runtime evidence pack","command":"bash \"$PASS_EVIDENCE_2\"","reason":"evidence-pack"},
    {"id":"profile_compare_multi_vm_stability_promotion_evidence_pack","label":"Multi-vm evidence pack","command":"bash \"$PASS_EVIDENCE_MULTI_VM\"","reason":"evidence-pack"},
    {"id":"misc_evidence_pack","label":"Generic evidence pack","command":"bash \"$PASS_EVIDENCE_GENERIC\"","reason":"evidence-pack"}
  ]
}
JSON
    ;;
  mixed_fail_first)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"client_vpn_smoke","label":"Non evidence (must not run)","command":"bash \"$NON_EVIDENCE_FAIL\"","reason":"must-not-run"},
    {"id":"profile_default_gate_evidence_pack","label":"Profile evidence pack fail","command":"bash \"$FAIL_EVIDENCE\"","reason":"evidence-pack"},
    {"id":"blockchain_fastlane","label":"Non evidence (must not run)","command":"bash \"$NON_EVIDENCE_PASS\"","reason":"must-not-run"},
    {"id":"runtime_actuation_promotion_evidence_pack","label":"Runtime evidence pack pass","command":"bash \"$PASS_EVIDENCE_2\"","reason":"evidence-pack"}
  ]
}
JSON
    ;;
  duplicates_ordering)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"runtime_actuation_promotion_evidence_pack","label":"Runtime evidence pack first","command":"bash \"$PASS_EVIDENCE_2\"","reason":"evidence-pack"},
    {"id":"profile_default_gate_evidence_pack","label":"Profile evidence pack second","command":"bash \"$PASS_EVIDENCE_1\"","reason":"evidence-pack"},
    {"id":"runtime_actuation_promotion_evidence_pack","label":"Runtime duplicate must be deduped","command":"bash \"$NON_EVIDENCE_FAIL\"","reason":"duplicate-should-not-run"},
    {"id":"misc_evidence_pack","label":"Generic evidence pack third","command":"bash \"$PASS_EVIDENCE_GENERIC\"","reason":"evidence-pack"},
    {"id":"profile_default_gate_evidence_pack","label":"Profile duplicate must be deduped","command":"bash \"$NON_EVIDENCE_FAIL\"","reason":"duplicate-should-not-run"},
    {"id":"profile_compare_multi_vm_stability_promotion_evidence_pack","label":"Multi-vm evidence pack fourth","command":"bash \"$PASS_EVIDENCE_MULTI_VM\"","reason":"evidence-pack"}
  ]
}
JSON
    ;;
  no_suffix)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate","label":"No suffix profile gate","command":"bash \"$NON_EVIDENCE_FAIL\"","reason":"must-not-run"},
    {"id":"runtime_actuation_promotion","label":"No suffix runtime gate","command":"bash \"$NON_EVIDENCE_FAIL\"","reason":"must-not-run"}
  ]
}
JSON
    ;;
  auto_single_family)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate_evidence_pack","label":"Profile evidence pack","command":"bash \"$PASS_EVIDENCE_1\"","reason":"evidence-pack"},
    {"id":"misc_evidence_pack","label":"Generic evidence pack","command":"bash \"$PASS_EVIDENCE_GENERIC\"","reason":"generic-evidence-pack"},
    {"id":"runtime_actuation_promotion","label":"Non evidence (must not run)","command":"bash \"$NON_EVIDENCE_FAIL\"","reason":"must-not-run"}
  ]
}
JSON
    ;;
  auto_mixed_families)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"runtime_actuation_promotion_evidence_pack","label":"Runtime evidence pack","command":"bash \"$PASS_EVIDENCE_2\"","reason":"evidence-pack"},
    {"id":"misc_evidence_pack","label":"Generic evidence pack","command":"bash \"$PASS_EVIDENCE_GENERIC\"","reason":"generic-evidence-pack"},
    {"id":"profile_compare_multi_vm_stability_promotion_evidence_pack","label":"Multi-vm evidence pack","command":"bash \"$PASS_EVIDENCE_MULTI_VM\"","reason":"evidence-pack"}
  ]
}
JSON
    ;;
  auto_none)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"misc_evidence_pack","label":"Generic evidence pack","command":"bash \"$PASS_EVIDENCE_GENERIC\"","reason":"generic-evidence-pack"},
    {"id":"vpn_rc_standard_path","label":"Non evidence (must not run)","command":"bash \"$NON_EVIDENCE_FAIL\"","reason":"must-not-run"}
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

cat >"$FAKE_NEXT_ACTIONS_NO_SUMMARY" <<'EOF_FAKE_NEXT_ACTIONS_NO_SUMMARY'
#!/usr/bin/env bash
set -euo pipefail
exit 0
EOF_FAKE_NEXT_ACTIONS_NO_SUMMARY
chmod +x "$FAKE_NEXT_ACTIONS_NO_SUMMARY"

cat >"$FAKE_NEXT_ACTIONS_PARTIAL_SUMMARY" <<'EOF_FAKE_NEXT_ACTIONS_PARTIAL_SUMMARY'
#!/usr/bin/env bash
set -euo pipefail
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
if [[ -z "$summary_json" ]]; then
  echo "fake next-actions: missing --summary-json"
  exit 2
fi
mkdir -p "$(dirname "$summary_json")"
cat >"$summary_json" <<'JSON_FAKE_NEXT_ACTIONS_PARTIAL_SUMMARY'
{
  "status": "pass",
  "rc": 0,
  "roadmap": {
    "actions_selected_count": 1,
    "selected_action_ids": ["profile_default_gate_evidence_pack"]
  },
  "summary": {
    "actions_executed": 1,
    "pass": 0,
    "fail": 0,
    "timed_out": 0,
    "soft_failed": 0
  },
  "actions": []
}
JSON_FAKE_NEXT_ACTIONS_PARTIAL_SUMMARY
exit 0
EOF_FAKE_NEXT_ACTIONS_PARTIAL_SUMMARY
chmod +x "$FAKE_NEXT_ACTIONS_PARTIAL_SUMMARY"

echo "[roadmap-evidence-pack-actionable-run] help contract"
if ! bash ./scripts/roadmap_evidence_pack_actionable_run.sh --help | grep -F -- "--reports-dir DIR" >/dev/null; then
  echo "help output missing --reports-dir DIR"
  exit 1
fi
if ! bash ./scripts/roadmap_evidence_pack_actionable_run.sh --help | grep -F -- "--summary-json PATH" >/dev/null; then
  echo "help output missing --summary-json PATH"
  exit 1
fi
if ! bash ./scripts/roadmap_evidence_pack_actionable_run.sh --help | grep -F -- "--roadmap-summary-json PATH" >/dev/null; then
  echo "help output missing --roadmap-summary-json PATH"
  exit 1
fi
if ! bash ./scripts/roadmap_evidence_pack_actionable_run.sh --help | grep -F -- "--roadmap-report-md PATH" >/dev/null; then
  echo "help output missing --roadmap-report-md PATH"
  exit 1
fi
if ! bash ./scripts/roadmap_evidence_pack_actionable_run.sh --help | grep -F -- "--live-evidence-summary-json PATH" >/dev/null; then
  echo "help output missing --live-evidence-summary-json PATH"
  exit 1
fi
if ! bash ./scripts/roadmap_evidence_pack_actionable_run.sh --help | grep -F -- "--require-live-derived-evidence-pack-actions [0|1]" >/dev/null; then
  echo "help output missing --require-live-derived-evidence-pack-actions [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_evidence_pack_actionable_run.sh --help | grep -F -- "--action-timeout-sec N" >/dev/null; then
  echo "help output missing --action-timeout-sec N"
  exit 1
fi
if ! bash ./scripts/roadmap_evidence_pack_actionable_run.sh --help | grep -F -- "--allow-unsafe-shell-commands [0|1]" >/dev/null; then
  echo "help output missing --allow-unsafe-shell-commands [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_evidence_pack_actionable_run.sh --help | grep -F -- "--refresh-manual-validation [0|1]" >/dev/null; then
  echo "help output missing --refresh-manual-validation [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_evidence_pack_actionable_run.sh --help | grep -F -- "--refresh-single-machine-readiness [0|1]" >/dev/null; then
  echo "help output missing --refresh-single-machine-readiness [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_evidence_pack_actionable_run.sh --help | grep -F -- "--scope auto|all|profile-default|runtime-actuation|multi-vm" >/dev/null; then
  echo "help output missing --scope auto|all|profile-default|runtime-actuation|multi-vm"
  exit 1
fi
if ! bash ./scripts/roadmap_evidence_pack_actionable_run.sh --help | grep -F -- "--parallel [0|1]" >/dev/null; then
  echo "help output missing --parallel [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_evidence_pack_actionable_run.sh --help | grep -F -- "--max-actions N" >/dev/null; then
  echo "help output missing --max-actions N"
  exit 1
fi
if ! bash ./scripts/roadmap_evidence_pack_actionable_run.sh --help | grep -F -- "--print-summary-json [0|1]" >/dev/null; then
  echo "help output missing --print-summary-json [0|1]"
  exit 1
fi

LIVE_SUMMARY_PROFILE_DEFAULT="$TMP_DIR/live_summary_profile_default.json"
cat >"$LIVE_SUMMARY_PROFILE_DEFAULT" <<'JSON_LIVE_SUMMARY_PROFILE_DEFAULT'
{
  "roadmap": {
    "derived_evidence_pack_ids": [
      "profile_default_gate_evidence_pack"
    ]
  }
}
JSON_LIVE_SUMMARY_PROFILE_DEFAULT

echo "[roadmap-evidence-pack-actionable-run] mixed success path defaults to profile-default family only (max-actions applied)"
SUMMARY_SUCCESS="$TMP_DIR/summary_success.json"
REPORTS_SUCCESS="$TMP_DIR/reports_success"
: >"$EXEC_LOG"
ROADMAP_EVIDENCE_PACK_ACTIONABLE_SCENARIO=mixed_success \
PASS_EVIDENCE_1="$PASS_EVIDENCE_1" PASS_EVIDENCE_2="$PASS_EVIDENCE_2" PASS_EVIDENCE_MULTI_VM="$PASS_EVIDENCE_MULTI_VM" PASS_EVIDENCE_GENERIC="$PASS_EVIDENCE_GENERIC" FAIL_EVIDENCE="$FAIL_EVIDENCE" \
NON_EVIDENCE_FAIL="$NON_EVIDENCE_FAIL" NON_EVIDENCE_PASS="$NON_EVIDENCE_PASS" \
ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_evidence_pack_actionable_run.sh \
  --reports-dir "$REPORTS_SUCCESS" \
  --summary-json "$SUMMARY_SUCCESS" \
  --refresh-manual-validation 1 \
  --refresh-single-machine-readiness 1 \
  --parallel 1 \
  --max-actions 1 \
  --action-timeout-sec 2 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.refresh_manual_validation == true
  and .inputs.refresh_single_machine_readiness == true
  and .inputs.parallel == true
  and .inputs.max_actions == 1
  and .inputs.action_timeout_sec == 2
  and .inputs.suffix_filter == "_evidence_pack"
  and .inputs.scope == "profile-default"
  and .inputs.resolved_scope == "profile-default"
  and (.inputs.scope_inference_reason | contains("explicit scope: profile-default"))
  and .roadmap.generated_this_run == true
  and .roadmap.suffix_match_count == 4
  and .roadmap.suffix_match_action_ids == ["profile_default_gate_evidence_pack","runtime_actuation_promotion_evidence_pack","profile_compare_multi_vm_stability_promotion_evidence_pack","misc_evidence_pack"]
  and .roadmap.recognized_family_match_count == 3
  and .roadmap.recognized_family_match_action_ids == ["profile_default_gate_evidence_pack","runtime_actuation_promotion_evidence_pack","profile_compare_multi_vm_stability_promotion_evidence_pack"]
  and .roadmap.scope_match_count == 1
  and .roadmap.scope_match_action_ids == ["profile_default_gate_evidence_pack"]
  and .roadmap.scope_match_unique_count == 1
  and .roadmap.scope_match_unique_action_ids == ["profile_default_gate_evidence_pack"]
  and .roadmap.selected_unique_count == 1
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["profile_default_gate_evidence_pack"]
  and .summary.selected_unique_count == 1
  and .summary.actions_executed == 1
  and .summary.pass == 1
  and .summary.fail == 0
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate_evidence_pack"
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
if ! grep -Fx "profile_default_gate_evidence_pack" "$EXEC_LOG" >/dev/null; then
  echo "expected executed log to contain profile_default_gate_evidence_pack"
  cat "$EXEC_LOG"
  exit 1
fi
if grep -F "non_evidence_should_not_run" "$EXEC_LOG" >/dev/null; then
  echo "non-evidence action executed unexpectedly in mixed success path"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-evidence-pack-actionable-run] mixed failure path returns first failing evidence-pack rc only"
SUMMARY_FAIL="$TMP_DIR/summary_fail.json"
REPORTS_FAIL="$TMP_DIR/reports_fail"
: >"$EXEC_LOG"
set +e
ROADMAP_EVIDENCE_PACK_ACTIONABLE_SCENARIO=mixed_fail_first \
PASS_EVIDENCE_1="$PASS_EVIDENCE_1" PASS_EVIDENCE_2="$PASS_EVIDENCE_2" PASS_EVIDENCE_MULTI_VM="$PASS_EVIDENCE_MULTI_VM" PASS_EVIDENCE_GENERIC="$PASS_EVIDENCE_GENERIC" FAIL_EVIDENCE="$FAIL_EVIDENCE" \
NON_EVIDENCE_FAIL="$NON_EVIDENCE_FAIL" NON_EVIDENCE_PASS="$NON_EVIDENCE_PASS" \
ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_evidence_pack_actionable_run.sh \
  --reports-dir "$REPORTS_FAIL" \
  --summary-json "$SUMMARY_FAIL" \
  --parallel 0 \
  --print-summary-json 0
fail_rc=$?
set -e
if [[ "$fail_rc" != "17" ]]; then
  echo "expected mixed failure rc=17, got rc=$fail_rc"
  cat "$SUMMARY_FAIL"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 17
  and .inputs.scope == "profile-default"
  and .roadmap.suffix_match_count == 2
  and .roadmap.recognized_family_match_count == 2
  and .roadmap.scope_match_count == 1
  and .roadmap.scope_match_unique_count == 1
  and .roadmap.scope_match_unique_action_ids == ["profile_default_gate_evidence_pack"]
  and .roadmap.selected_unique_count == 1
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["profile_default_gate_evidence_pack"]
  and .summary.selected_unique_count == 1
  and .summary.actions_executed == 1
  and .summary.pass == 0
  and .summary.fail == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate_evidence_pack"
  and .actions[0].status == "fail"
  and .actions[0].rc == 17
' "$SUMMARY_FAIL" >/dev/null; then
  echo "mixed failure summary mismatch"
  cat "$SUMMARY_FAIL"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected exactly one executed action log entry for mixed failure path"
  cat "$EXEC_LOG"
  exit 1
fi
if ! grep -Fx "profile_default_gate_evidence_pack" "$EXEC_LOG" >/dev/null; then
  echo "expected executed log to contain profile_default_gate_evidence_pack in mixed failure path"
  cat "$EXEC_LOG"
  exit 1
fi
if grep -F "non_evidence_should_not_run" "$EXEC_LOG" >/dev/null; then
  echo "non-evidence action executed unexpectedly in mixed failure path"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-evidence-pack-actionable-run] duplicate ids are delegated once and first-seen order stays stable"
SUMMARY_DEDUPE="$TMP_DIR/summary_dedupe.json"
REPORTS_DEDUPE="$TMP_DIR/reports_dedupe"
: >"$EXEC_LOG"
ROADMAP_EVIDENCE_PACK_ACTIONABLE_SCENARIO=duplicates_ordering \
PASS_EVIDENCE_1="$PASS_EVIDENCE_1" PASS_EVIDENCE_2="$PASS_EVIDENCE_2" PASS_EVIDENCE_MULTI_VM="$PASS_EVIDENCE_MULTI_VM" PASS_EVIDENCE_GENERIC="$PASS_EVIDENCE_GENERIC" FAIL_EVIDENCE="$FAIL_EVIDENCE" \
NON_EVIDENCE_FAIL="$NON_EVIDENCE_FAIL" NON_EVIDENCE_PASS="$NON_EVIDENCE_PASS" \
ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_evidence_pack_actionable_run.sh \
  --reports-dir "$REPORTS_DEDUPE" \
  --summary-json "$SUMMARY_DEDUPE" \
  --scope all \
  --parallel 0 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.scope == "all"
  and .roadmap.suffix_match_count == 6
  and .roadmap.suffix_match_action_ids == ["runtime_actuation_promotion_evidence_pack","profile_default_gate_evidence_pack","runtime_actuation_promotion_evidence_pack","misc_evidence_pack","profile_default_gate_evidence_pack","profile_compare_multi_vm_stability_promotion_evidence_pack"]
  and .roadmap.recognized_family_match_count == 5
  and .roadmap.recognized_family_match_action_ids == ["runtime_actuation_promotion_evidence_pack","profile_default_gate_evidence_pack","runtime_actuation_promotion_evidence_pack","profile_default_gate_evidence_pack","profile_compare_multi_vm_stability_promotion_evidence_pack"]
  and .roadmap.scope_match_count == 5
  and .roadmap.scope_match_action_ids == ["runtime_actuation_promotion_evidence_pack","profile_default_gate_evidence_pack","runtime_actuation_promotion_evidence_pack","profile_default_gate_evidence_pack","profile_compare_multi_vm_stability_promotion_evidence_pack"]
  and .roadmap.scope_match_unique_count == 3
  and .roadmap.scope_match_unique_action_ids == ["runtime_actuation_promotion_evidence_pack","profile_default_gate_evidence_pack","profile_compare_multi_vm_stability_promotion_evidence_pack"]
  and .roadmap.selected_unique_count == 3
  and .roadmap.actions_selected_count == 3
  and .roadmap.selected_action_ids == ["runtime_actuation_promotion_evidence_pack","profile_default_gate_evidence_pack","profile_compare_multi_vm_stability_promotion_evidence_pack"]
  and .summary.selected_unique_count == 3
  and .summary.actions_executed == 3
  and .summary.pass == 3
  and .summary.fail == 0
  and ((.actions // []) | length == 3)
  and ([.actions[].id] == ["runtime_actuation_promotion_evidence_pack","profile_default_gate_evidence_pack","profile_compare_multi_vm_stability_promotion_evidence_pack"])
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
if [[ "$(grep -c '^runtime_actuation_promotion_evidence_pack$' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected runtime_actuation_promotion_evidence_pack to execute exactly once"
  cat "$EXEC_LOG"
  exit 1
fi
if [[ "$(grep -c '^profile_default_gate_evidence_pack$' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected profile_default_gate_evidence_pack to execute exactly once"
  cat "$EXEC_LOG"
  exit 1
fi
if [[ "$(grep -c '^profile_compare_multi_vm_stability_promotion_evidence_pack$' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected profile_compare_multi_vm_stability_promotion_evidence_pack to execute exactly once"
  cat "$EXEC_LOG"
  exit 1
fi
if grep -F "non_evidence_should_not_run" "$EXEC_LOG" >/dev/null; then
  echo "deduped duplicate fallback command executed unexpectedly"
  cat "$EXEC_LOG"
  exit 1
fi
mapfile -t deduped_evidence_ids <"$EXEC_LOG"
if [[ "${deduped_evidence_ids[0]:-}" != "runtime_actuation_promotion_evidence_pack" || "${deduped_evidence_ids[1]:-}" != "profile_default_gate_evidence_pack" || "${deduped_evidence_ids[2]:-}" != "profile_compare_multi_vm_stability_promotion_evidence_pack" ]]; then
  echo "dedupe execution order mismatch"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-evidence-pack-actionable-run] no-suffix path performs zero action executions"
SUMMARY_EMPTY="$TMP_DIR/summary_empty.json"
REPORTS_EMPTY="$TMP_DIR/reports_empty"
: >"$EXEC_LOG"
ROADMAP_EVIDENCE_PACK_ACTIONABLE_SCENARIO=no_suffix \
PASS_EVIDENCE_1="$PASS_EVIDENCE_1" PASS_EVIDENCE_2="$PASS_EVIDENCE_2" PASS_EVIDENCE_MULTI_VM="$PASS_EVIDENCE_MULTI_VM" PASS_EVIDENCE_GENERIC="$PASS_EVIDENCE_GENERIC" FAIL_EVIDENCE="$FAIL_EVIDENCE" \
NON_EVIDENCE_FAIL="$NON_EVIDENCE_FAIL" NON_EVIDENCE_PASS="$NON_EVIDENCE_PASS" \
ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_evidence_pack_actionable_run.sh \
  --reports-dir "$REPORTS_EMPTY" \
  --summary-json "$SUMMARY_EMPTY" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.scope == "profile-default"
  and .roadmap.suffix_match_count == 0
  and .roadmap.recognized_family_match_count == 0
  and .roadmap.scope_match_count == 0
  and .roadmap.scope_match_unique_count == 0
  and .roadmap.scope_match_unique_action_ids == []
  and .roadmap.selected_unique_count == 0
  and .roadmap.actions_selected_count == 0
  and .roadmap.selected_action_ids == []
  and .summary.selected_unique_count == 0
  and .summary.actions_executed == 0
  and .summary.pass == 0
  and .summary.fail == 0
  and ((.actions // []) | length == 0)
' "$SUMMARY_EMPTY" >/dev/null; then
  echo "no-suffix summary mismatch"
  cat "$SUMMARY_EMPTY"
  exit 1
fi

if [[ -s "$EXEC_LOG" ]]; then
  echo "expected no executions in no-suffix path"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-evidence-pack-actionable-run] scope=profile-default selects only profile evidence action"
SUMMARY_SCOPE_PROFILE="$TMP_DIR/summary_scope_profile.json"
REPORTS_SCOPE_PROFILE="$TMP_DIR/reports_scope_profile"
: >"$EXEC_LOG"
ROADMAP_EVIDENCE_PACK_ACTIONABLE_SCENARIO=mixed_success \
PASS_EVIDENCE_1="$PASS_EVIDENCE_1" PASS_EVIDENCE_2="$PASS_EVIDENCE_2" PASS_EVIDENCE_MULTI_VM="$PASS_EVIDENCE_MULTI_VM" PASS_EVIDENCE_GENERIC="$PASS_EVIDENCE_GENERIC" FAIL_EVIDENCE="$FAIL_EVIDENCE" \
NON_EVIDENCE_FAIL="$NON_EVIDENCE_FAIL" NON_EVIDENCE_PASS="$NON_EVIDENCE_PASS" \
ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_evidence_pack_actionable_run.sh \
  --reports-dir "$REPORTS_SCOPE_PROFILE" \
  --summary-json "$SUMMARY_SCOPE_PROFILE" \
  --scope profile-default \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.scope == "profile-default"
  and .roadmap.suffix_match_count == 4
  and .roadmap.scope_match_count == 1
  and .roadmap.scope_match_action_ids == ["profile_default_gate_evidence_pack"]
  and .roadmap.scope_match_unique_count == 1
  and .roadmap.scope_match_unique_action_ids == ["profile_default_gate_evidence_pack"]
  and .roadmap.selected_unique_count == 1
  and .roadmap.selected_action_ids == ["profile_default_gate_evidence_pack"]
  and .summary.selected_unique_count == 1
  and .summary.actions_executed == 1
  and .summary.pass == 1
  and .summary.fail == 0
' "$SUMMARY_SCOPE_PROFILE" >/dev/null; then
  echo "scope profile-default summary mismatch"
  cat "$SUMMARY_SCOPE_PROFILE"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected one execution for scope=profile-default"
  cat "$EXEC_LOG"
  exit 1
fi
if ! grep -Fx "profile_default_gate_evidence_pack" "$EXEC_LOG" >/dev/null; then
  echo "expected profile_default_gate_evidence_pack execution for scope=profile-default"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-evidence-pack-actionable-run] scope=runtime-actuation selects only runtime evidence action"
SUMMARY_SCOPE_RUNTIME="$TMP_DIR/summary_scope_runtime.json"
REPORTS_SCOPE_RUNTIME="$TMP_DIR/reports_scope_runtime"
: >"$EXEC_LOG"
ROADMAP_EVIDENCE_PACK_ACTIONABLE_SCENARIO=mixed_success \
PASS_EVIDENCE_1="$PASS_EVIDENCE_1" PASS_EVIDENCE_2="$PASS_EVIDENCE_2" PASS_EVIDENCE_MULTI_VM="$PASS_EVIDENCE_MULTI_VM" PASS_EVIDENCE_GENERIC="$PASS_EVIDENCE_GENERIC" FAIL_EVIDENCE="$FAIL_EVIDENCE" \
NON_EVIDENCE_FAIL="$NON_EVIDENCE_FAIL" NON_EVIDENCE_PASS="$NON_EVIDENCE_PASS" \
ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_evidence_pack_actionable_run.sh \
  --reports-dir "$REPORTS_SCOPE_RUNTIME" \
  --summary-json "$SUMMARY_SCOPE_RUNTIME" \
  --scope runtime-actuation \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.scope == "runtime-actuation"
  and .roadmap.scope_match_count == 1
  and .roadmap.scope_match_action_ids == ["runtime_actuation_promotion_evidence_pack"]
  and .roadmap.scope_match_unique_count == 1
  and .roadmap.scope_match_unique_action_ids == ["runtime_actuation_promotion_evidence_pack"]
  and .roadmap.selected_unique_count == 1
  and .roadmap.selected_action_ids == ["runtime_actuation_promotion_evidence_pack"]
  and .summary.selected_unique_count == 1
  and .summary.actions_executed == 1
  and .summary.pass == 1
  and .summary.fail == 0
' "$SUMMARY_SCOPE_RUNTIME" >/dev/null; then
  echo "scope runtime-actuation summary mismatch"
  cat "$SUMMARY_SCOPE_RUNTIME"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected one execution for scope=runtime-actuation"
  cat "$EXEC_LOG"
  exit 1
fi
if ! grep -Fx "runtime_actuation_promotion_evidence_pack" "$EXEC_LOG" >/dev/null; then
  echo "expected runtime_actuation_promotion_evidence_pack execution for scope=runtime-actuation"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-evidence-pack-actionable-run] env alias scope selects multi-vm evidence action"
SUMMARY_SCOPE_MULTI_VM="$TMP_DIR/summary_scope_multi_vm.json"
REPORTS_SCOPE_MULTI_VM="$TMP_DIR/reports_scope_multi_vm"
: >"$EXEC_LOG"
ROADMAP_EVIDENCE_PACK_ACTIONABLE_SCENARIO=mixed_success \
PASS_EVIDENCE_1="$PASS_EVIDENCE_1" PASS_EVIDENCE_2="$PASS_EVIDENCE_2" PASS_EVIDENCE_MULTI_VM="$PASS_EVIDENCE_MULTI_VM" PASS_EVIDENCE_GENERIC="$PASS_EVIDENCE_GENERIC" FAIL_EVIDENCE="$FAIL_EVIDENCE" \
NON_EVIDENCE_FAIL="$NON_EVIDENCE_FAIL" NON_EVIDENCE_PASS="$NON_EVIDENCE_PASS" \
ROADMAP_EVIDENCE_PACK_ACTIONABLE_SCOPE=multi-vm \
ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_evidence_pack_actionable_run.sh \
  --reports-dir "$REPORTS_SCOPE_MULTI_VM" \
  --summary-json "$SUMMARY_SCOPE_MULTI_VM" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.scope == "multi-vm"
  and .roadmap.scope_match_count == 1
  and .roadmap.scope_match_action_ids == ["profile_compare_multi_vm_stability_promotion_evidence_pack"]
  and .roadmap.scope_match_unique_count == 1
  and .roadmap.scope_match_unique_action_ids == ["profile_compare_multi_vm_stability_promotion_evidence_pack"]
  and .roadmap.selected_unique_count == 1
  and .roadmap.selected_action_ids == ["profile_compare_multi_vm_stability_promotion_evidence_pack"]
  and .summary.selected_unique_count == 1
  and .summary.actions_executed == 1
  and .summary.pass == 1
  and .summary.fail == 0
' "$SUMMARY_SCOPE_MULTI_VM" >/dev/null; then
  echo "env alias scope summary mismatch"
  cat "$SUMMARY_SCOPE_MULTI_VM"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected one execution for env alias scope=multi-vm"
  cat "$EXEC_LOG"
  exit 1
fi
if ! grep -Fx "profile_compare_multi_vm_stability_promotion_evidence_pack" "$EXEC_LOG" >/dev/null; then
  echo "expected profile_compare_multi_vm_stability_promotion_evidence_pack execution for env alias scope=multi-vm"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-evidence-pack-actionable-run] default no-scope run is profile-default only (M2 hardening)"
SUMMARY_DEFAULT_SCOPE="$TMP_DIR/summary_default_scope.json"
REPORTS_DEFAULT_SCOPE="$TMP_DIR/reports_default_scope"
: >"$EXEC_LOG"
ROADMAP_EVIDENCE_PACK_ACTIONABLE_SCENARIO=mixed_success \
PASS_EVIDENCE_1="$PASS_EVIDENCE_1" PASS_EVIDENCE_2="$PASS_EVIDENCE_2" PASS_EVIDENCE_MULTI_VM="$PASS_EVIDENCE_MULTI_VM" PASS_EVIDENCE_GENERIC="$PASS_EVIDENCE_GENERIC" FAIL_EVIDENCE="$FAIL_EVIDENCE" \
NON_EVIDENCE_FAIL="$NON_EVIDENCE_FAIL" NON_EVIDENCE_PASS="$NON_EVIDENCE_PASS" \
ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_evidence_pack_actionable_run.sh \
  --reports-dir "$REPORTS_DEFAULT_SCOPE" \
  --summary-json "$SUMMARY_DEFAULT_SCOPE" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.scope == "profile-default"
  and .roadmap.suffix_match_count == 4
  and .roadmap.recognized_family_match_count == 3
  and .roadmap.scope_match_count == 1
  and .roadmap.scope_match_action_ids == ["profile_default_gate_evidence_pack"]
  and .roadmap.scope_match_unique_count == 1
  and .roadmap.scope_match_unique_action_ids == ["profile_default_gate_evidence_pack"]
  and .roadmap.selected_unique_count == 1
  and .roadmap.selected_action_ids == ["profile_default_gate_evidence_pack"]
  and .summary.selected_unique_count == 1
  and .summary.actions_executed == 1
  and .summary.pass == 1
  and .summary.fail == 0
' "$SUMMARY_DEFAULT_SCOPE" >/dev/null; then
  echo "default scope compatibility summary mismatch"
  cat "$SUMMARY_DEFAULT_SCOPE"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected one execution for default profile-default scope test"
  cat "$EXEC_LOG"
  exit 1
fi
if grep -F "non_evidence_should_not_run" "$EXEC_LOG" >/dev/null; then
  echo "non-evidence action executed unexpectedly in default scope compatibility test"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-evidence-pack-actionable-run] explicit --scope all matches default behavior"
SUMMARY_SCOPE_ALL="$TMP_DIR/summary_scope_all.json"
REPORTS_SCOPE_ALL="$TMP_DIR/reports_scope_all"
: >"$EXEC_LOG"
ROADMAP_EVIDENCE_PACK_ACTIONABLE_SCENARIO=mixed_success \
PASS_EVIDENCE_1="$PASS_EVIDENCE_1" PASS_EVIDENCE_2="$PASS_EVIDENCE_2" PASS_EVIDENCE_MULTI_VM="$PASS_EVIDENCE_MULTI_VM" PASS_EVIDENCE_GENERIC="$PASS_EVIDENCE_GENERIC" FAIL_EVIDENCE="$FAIL_EVIDENCE" \
NON_EVIDENCE_FAIL="$NON_EVIDENCE_FAIL" NON_EVIDENCE_PASS="$NON_EVIDENCE_PASS" \
ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_evidence_pack_actionable_run.sh \
  --reports-dir "$REPORTS_SCOPE_ALL" \
  --summary-json "$SUMMARY_SCOPE_ALL" \
  --scope all \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.scope == "all"
  and .roadmap.recognized_family_match_count == 3
  and .roadmap.scope_match_action_ids == ["profile_default_gate_evidence_pack","runtime_actuation_promotion_evidence_pack","profile_compare_multi_vm_stability_promotion_evidence_pack"]
  and .roadmap.scope_match_unique_count == 3
  and .roadmap.scope_match_unique_action_ids == ["profile_default_gate_evidence_pack","runtime_actuation_promotion_evidence_pack","profile_compare_multi_vm_stability_promotion_evidence_pack"]
  and .roadmap.selected_unique_count == 3
  and .roadmap.selected_action_ids == ["profile_default_gate_evidence_pack","runtime_actuation_promotion_evidence_pack","profile_compare_multi_vm_stability_promotion_evidence_pack"]
  and .summary.selected_unique_count == 3
  and .summary.actions_executed == 3
' "$SUMMARY_SCOPE_ALL" >/dev/null; then
  echo "scope all summary mismatch"
  cat "$SUMMARY_SCOPE_ALL"
  exit 1
fi

echo "[roadmap-evidence-pack-actionable-run] scope=auto infers single-family pending actions deterministically"
SUMMARY_SCOPE_AUTO_SINGLE="$TMP_DIR/summary_scope_auto_single.json"
REPORTS_SCOPE_AUTO_SINGLE="$TMP_DIR/reports_scope_auto_single"
: >"$EXEC_LOG"
ROADMAP_EVIDENCE_PACK_ACTIONABLE_SCENARIO=auto_single_family \
PASS_EVIDENCE_1="$PASS_EVIDENCE_1" PASS_EVIDENCE_2="$PASS_EVIDENCE_2" PASS_EVIDENCE_MULTI_VM="$PASS_EVIDENCE_MULTI_VM" PASS_EVIDENCE_GENERIC="$PASS_EVIDENCE_GENERIC" FAIL_EVIDENCE="$FAIL_EVIDENCE" \
NON_EVIDENCE_FAIL="$NON_EVIDENCE_FAIL" NON_EVIDENCE_PASS="$NON_EVIDENCE_PASS" \
ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_evidence_pack_actionable_run.sh \
  --reports-dir "$REPORTS_SCOPE_AUTO_SINGLE" \
  --summary-json "$SUMMARY_SCOPE_AUTO_SINGLE" \
  --scope auto \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.scope == "auto"
  and .inputs.resolved_scope == "profile-default"
  and (.inputs.scope_inference_reason | contains("single pending family (profile-default)"))
  and .roadmap.resolved_scope == "profile-default"
  and (.roadmap.scope_inference_reason | contains("single pending family (profile-default)"))
  and .roadmap.suffix_match_count == 2
  and .roadmap.scope_match_count == 1
  and .roadmap.scope_match_action_ids == ["profile_default_gate_evidence_pack"]
  and .roadmap.scope_match_unique_count == 1
  and .roadmap.scope_match_unique_action_ids == ["profile_default_gate_evidence_pack"]
  and .roadmap.selected_unique_count == 1
  and .roadmap.selected_action_ids == ["profile_default_gate_evidence_pack"]
  and .summary.selected_unique_count == 1
  and .summary.actions_executed == 1
  and .summary.pass == 1
  and .summary.fail == 0
' "$SUMMARY_SCOPE_AUTO_SINGLE" >/dev/null; then
  echo "scope auto single-family summary mismatch"
  cat "$SUMMARY_SCOPE_AUTO_SINGLE"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected one execution for scope=auto single-family inference"
  cat "$EXEC_LOG"
  exit 1
fi
if ! grep -Fx "profile_default_gate_evidence_pack" "$EXEC_LOG" >/dev/null; then
  echo "expected profile_default_gate_evidence_pack execution for scope=auto single-family inference"
  cat "$EXEC_LOG"
  exit 1
fi
if grep -Fx "misc_evidence_pack" "$EXEC_LOG" >/dev/null; then
  echo "generic evidence pack executed unexpectedly for scope=auto single-family inference"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-evidence-pack-actionable-run] scope=auto infers mixed families and selects all relevant deterministic family actions"
SUMMARY_SCOPE_AUTO_MIXED="$TMP_DIR/summary_scope_auto_mixed.json"
REPORTS_SCOPE_AUTO_MIXED="$TMP_DIR/reports_scope_auto_mixed"
: >"$EXEC_LOG"
ROADMAP_EVIDENCE_PACK_ACTIONABLE_SCENARIO=auto_mixed_families \
PASS_EVIDENCE_1="$PASS_EVIDENCE_1" PASS_EVIDENCE_2="$PASS_EVIDENCE_2" PASS_EVIDENCE_MULTI_VM="$PASS_EVIDENCE_MULTI_VM" PASS_EVIDENCE_GENERIC="$PASS_EVIDENCE_GENERIC" FAIL_EVIDENCE="$FAIL_EVIDENCE" \
NON_EVIDENCE_FAIL="$NON_EVIDENCE_FAIL" NON_EVIDENCE_PASS="$NON_EVIDENCE_PASS" \
ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_evidence_pack_actionable_run.sh \
  --reports-dir "$REPORTS_SCOPE_AUTO_MIXED" \
  --summary-json "$SUMMARY_SCOPE_AUTO_MIXED" \
  --scope auto \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.scope == "auto"
  and .inputs.resolved_scope == "all"
  and (.inputs.scope_inference_reason | contains("mixed pending families (runtime-actuation,multi-vm)"))
  and .roadmap.resolved_scope == "all"
  and (.roadmap.scope_inference_reason | contains("mixed pending families (runtime-actuation,multi-vm)"))
  and .roadmap.suffix_match_count == 3
  and .roadmap.scope_match_count == 2
  and .roadmap.scope_match_action_ids == ["runtime_actuation_promotion_evidence_pack","profile_compare_multi_vm_stability_promotion_evidence_pack"]
  and .roadmap.scope_match_unique_count == 2
  and .roadmap.scope_match_unique_action_ids == ["runtime_actuation_promotion_evidence_pack","profile_compare_multi_vm_stability_promotion_evidence_pack"]
  and .roadmap.selected_unique_count == 2
  and .roadmap.selected_action_ids == ["runtime_actuation_promotion_evidence_pack","profile_compare_multi_vm_stability_promotion_evidence_pack"]
  and .summary.selected_unique_count == 2
  and .summary.actions_executed == 2
  and .summary.pass == 2
  and .summary.fail == 0
' "$SUMMARY_SCOPE_AUTO_MIXED" >/dev/null; then
  echo "scope auto mixed-family summary mismatch"
  cat "$SUMMARY_SCOPE_AUTO_MIXED"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "2" ]]; then
  echo "expected two executions for scope=auto mixed-family inference"
  cat "$EXEC_LOG"
  exit 1
fi
if [[ "$(grep -c '^runtime_actuation_promotion_evidence_pack$' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected runtime_actuation_promotion_evidence_pack execution for scope=auto mixed-family inference"
  cat "$EXEC_LOG"
  exit 1
fi
if [[ "$(grep -c '^profile_compare_multi_vm_stability_promotion_evidence_pack$' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected profile_compare_multi_vm_stability_promotion_evidence_pack execution for scope=auto mixed-family inference"
  cat "$EXEC_LOG"
  exit 1
fi
if grep -Fx "misc_evidence_pack" "$EXEC_LOG" >/dev/null; then
  echo "generic evidence pack executed unexpectedly for scope=auto mixed-family inference"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-evidence-pack-actionable-run] scope=auto infers none when no recognized families are pending"
SUMMARY_SCOPE_AUTO_NONE="$TMP_DIR/summary_scope_auto_none.json"
REPORTS_SCOPE_AUTO_NONE="$TMP_DIR/reports_scope_auto_none"
: >"$EXEC_LOG"
ROADMAP_EVIDENCE_PACK_ACTIONABLE_SCENARIO=auto_none \
PASS_EVIDENCE_1="$PASS_EVIDENCE_1" PASS_EVIDENCE_2="$PASS_EVIDENCE_2" PASS_EVIDENCE_MULTI_VM="$PASS_EVIDENCE_MULTI_VM" PASS_EVIDENCE_GENERIC="$PASS_EVIDENCE_GENERIC" FAIL_EVIDENCE="$FAIL_EVIDENCE" \
NON_EVIDENCE_FAIL="$NON_EVIDENCE_FAIL" NON_EVIDENCE_PASS="$NON_EVIDENCE_PASS" \
ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_evidence_pack_actionable_run.sh \
  --reports-dir "$REPORTS_SCOPE_AUTO_NONE" \
  --summary-json "$SUMMARY_SCOPE_AUTO_NONE" \
  --scope auto \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.scope == "auto"
  and .inputs.resolved_scope == "none"
  and (.inputs.scope_inference_reason | contains("no recognized evidence-pack families are pending"))
  and .roadmap.resolved_scope == "none"
  and (.roadmap.scope_inference_reason | contains("no recognized evidence-pack families are pending"))
  and .roadmap.suffix_match_count == 1
  and .roadmap.scope_match_count == 0
  and .roadmap.scope_match_action_ids == []
  and .roadmap.scope_match_unique_count == 0
  and .roadmap.scope_match_unique_action_ids == []
  and .roadmap.selected_unique_count == 0
  and .roadmap.selected_action_ids == []
  and .summary.selected_unique_count == 0
  and .summary.actions_executed == 0
  and .summary.pass == 0
  and .summary.fail == 0
' "$SUMMARY_SCOPE_AUTO_NONE" >/dev/null; then
  echo "scope auto none summary mismatch"
  cat "$SUMMARY_SCOPE_AUTO_NONE"
  exit 1
fi

if [[ -s "$EXEC_LOG" ]]; then
  echo "expected no executions for scope=auto none inference"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-evidence-pack-actionable-run] fail-closed when required live summary path is invalid"
SUMMARY_REQUIRED_INVALID="$TMP_DIR/summary_required_invalid.json"
REPORTS_REQUIRED_INVALID="$TMP_DIR/reports_required_invalid"
: >"$EXEC_LOG"
set +e
ROADMAP_EVIDENCE_PACK_ACTIONABLE_SCENARIO=mixed_success \
PASS_EVIDENCE_1="$PASS_EVIDENCE_1" PASS_EVIDENCE_2="$PASS_EVIDENCE_2" PASS_EVIDENCE_MULTI_VM="$PASS_EVIDENCE_MULTI_VM" PASS_EVIDENCE_GENERIC="$PASS_EVIDENCE_GENERIC" FAIL_EVIDENCE="$FAIL_EVIDENCE" \
NON_EVIDENCE_FAIL="$NON_EVIDENCE_FAIL" NON_EVIDENCE_PASS="$NON_EVIDENCE_PASS" \
ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_evidence_pack_actionable_run.sh \
  --reports-dir "$REPORTS_REQUIRED_INVALID" \
  --summary-json "$SUMMARY_REQUIRED_INVALID" \
  --live-evidence-summary-json "$TMP_DIR/live_summary_missing.json" \
  --require-live-derived-evidence-pack-actions 1 \
  --print-summary-json 0
required_invalid_rc=$?
set -e

if [[ "$required_invalid_rc" != "4" ]]; then
  echo "expected required-live-summary invalid fail-closed rc=4, got rc=$required_invalid_rc"
  cat "$SUMMARY_REQUIRED_INVALID"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 4
  and .inputs.require_live_derived_evidence_pack_actions == true
  and ((.inputs.live_evidence_summary_json // "") | endswith("/live_summary_missing.json"))
  and .enforcement.live_evidence_summary_present == false
  and .enforcement.live_evidence_summary_valid == false
  and .enforcement.live_evidence_summary_load_error == "missing_or_invalid_live_evidence_summary"
  and .enforcement.live_requirement_fail_closed == true
  and .enforcement.live_requirement_failure_kind == "required_live_evidence_summary_invalid"
  and .summary.live_requirement_fail_closed == true
  and .summary.actions_executed == 0
  and ((.actions // []) | length == 0)
  and .delegated_runner.status == "skipped_required_live_evidence_summary_invalid"
  and .delegated_runner.skip_reason == "required_live_evidence_summary_invalid"
  and .delegated_runner.rc == 4
  and .delegated_runner.process_rc == 0
' "$SUMMARY_REQUIRED_INVALID" >/dev/null; then
  echo "required-live-summary invalid fail-closed summary mismatch"
  cat "$SUMMARY_REQUIRED_INVALID"
  exit 1
fi

if [[ -s "$EXEC_LOG" ]]; then
  echo "expected no executions when required live summary is invalid"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-evidence-pack-actionable-run] fail-closed when live-derived publish ids are missing from selected scope"
SUMMARY_REQUIRED_MISSING_SCOPE="$TMP_DIR/summary_required_missing_scope.json"
REPORTS_REQUIRED_MISSING_SCOPE="$TMP_DIR/reports_required_missing_scope"
: >"$EXEC_LOG"
set +e
ROADMAP_EVIDENCE_PACK_ACTIONABLE_SCENARIO=no_suffix \
PASS_EVIDENCE_1="$PASS_EVIDENCE_1" PASS_EVIDENCE_2="$PASS_EVIDENCE_2" PASS_EVIDENCE_MULTI_VM="$PASS_EVIDENCE_MULTI_VM" PASS_EVIDENCE_GENERIC="$PASS_EVIDENCE_GENERIC" FAIL_EVIDENCE="$FAIL_EVIDENCE" \
NON_EVIDENCE_FAIL="$NON_EVIDENCE_FAIL" NON_EVIDENCE_PASS="$NON_EVIDENCE_PASS" \
ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_evidence_pack_actionable_run.sh \
  --reports-dir "$REPORTS_REQUIRED_MISSING_SCOPE" \
  --summary-json "$SUMMARY_REQUIRED_MISSING_SCOPE" \
  --live-evidence-summary-json "$LIVE_SUMMARY_PROFILE_DEFAULT" \
  --require-live-derived-evidence-pack-actions 1 \
  --print-summary-json 0
required_missing_scope_rc=$?
set -e

if [[ "$required_missing_scope_rc" != "4" ]]; then
  echo "expected missing-live-derived publish ids fail-closed rc=4, got rc=$required_missing_scope_rc"
  cat "$SUMMARY_REQUIRED_MISSING_SCOPE"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 4
  and .inputs.require_live_derived_evidence_pack_actions == true
  and ((.inputs.live_evidence_summary_json // "") | endswith("/live_summary_profile_default.json"))
  and .roadmap.live_required_evidence_pack_ids == ["profile_default_gate_evidence_pack"]
  and .roadmap.live_required_evidence_pack_count == 1
  and .roadmap.live_required_missing_in_scope_ids == ["profile_default_gate_evidence_pack"]
  and .roadmap.live_required_missing_in_scope_count == 1
  and .enforcement.live_requirement_fail_closed == true
  and .enforcement.live_requirement_failure_kind == "required_live_derived_evidence_pack_actions_missing_from_scope"
  and .summary.live_requirement_fail_closed == true
  and .summary.live_required_missing_in_scope_count == 1
  and .summary.actions_executed == 0
  and ((.actions // []) | length == 0)
  and .delegated_runner.status == "skipped_required_live_derived_evidence_pack_actions_missing_from_scope"
  and .delegated_runner.skip_reason == "required_live_derived_evidence_pack_actions_missing_from_scope"
  and .delegated_runner.rc == 4
  and .delegated_runner.process_rc == 0
' "$SUMMARY_REQUIRED_MISSING_SCOPE" >/dev/null; then
  echo "missing-live-derived publish ids fail-closed summary mismatch"
  cat "$SUMMARY_REQUIRED_MISSING_SCOPE"
  exit 1
fi

if [[ -s "$EXEC_LOG" ]]; then
  echo "expected no executions when live-derived publish ids are missing from selected scope"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-evidence-pack-actionable-run] required live-derived publish ids pass when selected scope covers them"
SUMMARY_REQUIRED_PRESENT="$TMP_DIR/summary_required_present.json"
REPORTS_REQUIRED_PRESENT="$TMP_DIR/reports_required_present"
: >"$EXEC_LOG"
ROADMAP_EVIDENCE_PACK_ACTIONABLE_SCENARIO=mixed_success \
PASS_EVIDENCE_1="$PASS_EVIDENCE_1" PASS_EVIDENCE_2="$PASS_EVIDENCE_2" PASS_EVIDENCE_MULTI_VM="$PASS_EVIDENCE_MULTI_VM" PASS_EVIDENCE_GENERIC="$PASS_EVIDENCE_GENERIC" FAIL_EVIDENCE="$FAIL_EVIDENCE" \
NON_EVIDENCE_FAIL="$NON_EVIDENCE_FAIL" NON_EVIDENCE_PASS="$NON_EVIDENCE_PASS" \
ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_evidence_pack_actionable_run.sh \
  --reports-dir "$REPORTS_REQUIRED_PRESENT" \
  --summary-json "$SUMMARY_REQUIRED_PRESENT" \
  --live-evidence-summary-json "$LIVE_SUMMARY_PROFILE_DEFAULT" \
  --require-live-derived-evidence-pack-actions 1 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.require_live_derived_evidence_pack_actions == true
  and .roadmap.live_required_evidence_pack_ids == ["profile_default_gate_evidence_pack"]
  and .roadmap.live_required_evidence_pack_count == 1
  and .roadmap.live_required_missing_in_scope_ids == []
  and .roadmap.live_required_missing_in_scope_count == 0
  and .enforcement.live_requirement_fail_closed == false
  and .summary.live_requirement_fail_closed == false
  and .summary.live_required_missing_in_scope_count == 0
  and .summary.actions_executed == 1
  and .summary.pass == 1
  and .summary.fail == 0
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate_evidence_pack"
  and .delegated_runner.skip_reason == null
' "$SUMMARY_REQUIRED_PRESENT" >/dev/null; then
  echo "required-live-derived publish ids pass summary mismatch"
  cat "$SUMMARY_REQUIRED_PRESENT"
  exit 1
fi

if [[ "$(grep -c '.' "$EXEC_LOG" || true)" != "1" ]]; then
  echo "expected one execution when required live-derived publish ids are present"
  cat "$EXEC_LOG"
  exit 1
fi
if ! grep -Fx "profile_default_gate_evidence_pack" "$EXEC_LOG" >/dev/null; then
  echo "expected profile_default_gate_evidence_pack execution when required live-derived publish ids are present"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-evidence-pack-actionable-run] fail-closed when delegated runner returns rc=0 without summary artifact"
SUMMARY_DELEGATED_MISSING="$TMP_DIR/summary_delegated_missing.json"
REPORTS_DELEGATED_MISSING="$TMP_DIR/reports_delegated_missing"
: >"$EXEC_LOG"
set +e
ROADMAP_EVIDENCE_PACK_ACTIONABLE_SCENARIO=mixed_success \
PASS_EVIDENCE_1="$PASS_EVIDENCE_1" PASS_EVIDENCE_2="$PASS_EVIDENCE_2" PASS_EVIDENCE_MULTI_VM="$PASS_EVIDENCE_MULTI_VM" PASS_EVIDENCE_GENERIC="$PASS_EVIDENCE_GENERIC" FAIL_EVIDENCE="$FAIL_EVIDENCE" \
NON_EVIDENCE_FAIL="$NON_EVIDENCE_FAIL" NON_EVIDENCE_PASS="$NON_EVIDENCE_PASS" \
ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_NEXT_ACTIONS_SCRIPT="$FAKE_NEXT_ACTIONS_NO_SUMMARY" \
bash ./scripts/roadmap_evidence_pack_actionable_run.sh \
  --reports-dir "$REPORTS_DELEGATED_MISSING" \
  --summary-json "$SUMMARY_DELEGATED_MISSING" \
  --scope profile-default \
  --print-summary-json 0
delegated_missing_rc=$?
set -e

if [[ "$delegated_missing_rc" != "6" ]]; then
  echo "expected delegated-summary-missing fail-closed rc=6, got rc=$delegated_missing_rc"
  cat "$SUMMARY_DELEGATED_MISSING"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 6
  and .summary.delegated_summary_contract_fail_closed == true
  and .enforcement.delegated_summary_contract_fail_closed == true
  and .enforcement.delegated_summary_contract_failure_kind == "delegated_summary_missing_or_invalid"
  and ((.enforcement.delegated_summary_contract_failure_reason // "") | test("summary artifact"))
  and ((.enforcement.delegated_summary_contract_failure_reasons | length) >= 1)
  and ((.enforcement.delegated_summary_contract_next_operator_action // "") | test("roadmap_next_actions_run\\.sh"))
  and .delegated_runner.summary_valid == false
  and .delegated_runner.process_rc == 0
  and .delegated_runner.rc == 0
  and .summary.actions_executed == 0
  and ((.actions // []) | length == 0)
' "$SUMMARY_DELEGATED_MISSING" >/dev/null; then
  echo "delegated-summary-missing fail-closed summary mismatch"
  cat "$SUMMARY_DELEGATED_MISSING"
  exit 1
fi

if [[ -s "$EXEC_LOG" ]]; then
  echo "expected no executions when delegated summary artifact is missing"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-evidence-pack-actionable-run] fail-closed when stale delegated summary exists but runner emits no new summary"
SUMMARY_DELEGATED_STALE="$TMP_DIR/summary_delegated_stale.json"
REPORTS_DELEGATED_STALE="$TMP_DIR/reports_delegated_stale"
mkdir -p "$REPORTS_DELEGATED_STALE"
cat >"$REPORTS_DELEGATED_STALE/roadmap_next_actions_run_summary.json" <<'JSON_DELEGATED_STALE'
{
  "status": "pass",
  "rc": 0,
  "roadmap": {
    "actions_selected_count": 1,
    "selected_action_ids": ["profile_default_gate_evidence_pack"]
  },
  "summary": {
    "actions_executed": 1,
    "pass": 1,
    "fail": 0,
    "timed_out": 0,
    "soft_failed": 0
  },
  "actions": [
    {"id":"profile_default_gate_evidence_pack","status":"pass"}
  ]
}
JSON_DELEGATED_STALE
: >"$EXEC_LOG"
set +e
ROADMAP_EVIDENCE_PACK_ACTIONABLE_SCENARIO=mixed_success \
PASS_EVIDENCE_1="$PASS_EVIDENCE_1" PASS_EVIDENCE_2="$PASS_EVIDENCE_2" PASS_EVIDENCE_MULTI_VM="$PASS_EVIDENCE_MULTI_VM" PASS_EVIDENCE_GENERIC="$PASS_EVIDENCE_GENERIC" FAIL_EVIDENCE="$FAIL_EVIDENCE" \
NON_EVIDENCE_FAIL="$NON_EVIDENCE_FAIL" NON_EVIDENCE_PASS="$NON_EVIDENCE_PASS" \
ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_NEXT_ACTIONS_SCRIPT="$FAKE_NEXT_ACTIONS_NO_SUMMARY" \
bash ./scripts/roadmap_evidence_pack_actionable_run.sh \
  --reports-dir "$REPORTS_DELEGATED_STALE" \
  --summary-json "$SUMMARY_DELEGATED_STALE" \
  --scope profile-default \
  --print-summary-json 0
delegated_stale_rc=$?
set -e

if [[ "$delegated_stale_rc" != "6" ]]; then
  echo "expected delegated-stale-summary fail-closed rc=6, got rc=$delegated_stale_rc"
  cat "$SUMMARY_DELEGATED_STALE"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 6
  and .summary.delegated_summary_contract_fail_closed == true
  and .enforcement.delegated_summary_contract_fail_closed == true
  and .enforcement.delegated_summary_contract_failure_kind == "delegated_summary_missing_or_invalid"
  and .delegated_runner.summary_valid == false
  and .delegated_runner.process_rc == 0
  and .delegated_runner.rc == 0
  and .summary.actions_executed == 0
  and ((.actions // []) | length == 0)
' "$SUMMARY_DELEGATED_STALE" >/dev/null; then
  echo "delegated-stale-summary fail-closed mismatch"
  cat "$SUMMARY_DELEGATED_STALE"
  exit 1
fi

if [[ -e "$REPORTS_DELEGATED_STALE/roadmap_next_actions_run_summary.json" ]]; then
  echo "expected stale delegated summary to be cleared before runner invocation"
  exit 1
fi

if [[ -s "$EXEC_LOG" ]]; then
  echo "expected no executions when stale delegated summary is reused"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-evidence-pack-actionable-run] fail-closed when delegated summary counters are partial/inconsistent"
SUMMARY_DELEGATED_PARTIAL="$TMP_DIR/summary_delegated_partial.json"
REPORTS_DELEGATED_PARTIAL="$TMP_DIR/reports_delegated_partial"
: >"$EXEC_LOG"
set +e
ROADMAP_EVIDENCE_PACK_ACTIONABLE_SCENARIO=mixed_success \
PASS_EVIDENCE_1="$PASS_EVIDENCE_1" PASS_EVIDENCE_2="$PASS_EVIDENCE_2" PASS_EVIDENCE_MULTI_VM="$PASS_EVIDENCE_MULTI_VM" PASS_EVIDENCE_GENERIC="$PASS_EVIDENCE_GENERIC" FAIL_EVIDENCE="$FAIL_EVIDENCE" \
NON_EVIDENCE_FAIL="$NON_EVIDENCE_FAIL" NON_EVIDENCE_PASS="$NON_EVIDENCE_PASS" \
ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
ROADMAP_EVIDENCE_PACK_ACTIONABLE_RUN_NEXT_ACTIONS_SCRIPT="$FAKE_NEXT_ACTIONS_PARTIAL_SUMMARY" \
bash ./scripts/roadmap_evidence_pack_actionable_run.sh \
  --reports-dir "$REPORTS_DELEGATED_PARTIAL" \
  --summary-json "$SUMMARY_DELEGATED_PARTIAL" \
  --scope profile-default \
  --print-summary-json 0
delegated_partial_rc=$?
set -e

if [[ "$delegated_partial_rc" != "6" ]]; then
  echo "expected delegated-summary-partial fail-closed rc=6, got rc=$delegated_partial_rc"
  cat "$SUMMARY_DELEGATED_PARTIAL"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 6
  and .summary.actions_executed == 1
  and .summary.actions_results_count == 0
  and .summary.delegated_summary_contract_fail_closed == true
  and .enforcement.delegated_summary_contract_fail_closed == true
  and .enforcement.delegated_summary_contract_failure_kind == "delegated_summary_contract_violation"
  and ((.enforcement.delegated_summary_contract_failure_reasons | map(test("counters mismatch|actions length mismatch")) | any))
  and .delegated_runner.summary_valid == true
  and .delegated_runner.process_rc == 0
  and .delegated_runner.rc == 0
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["profile_default_gate_evidence_pack"]
  and ((.actions // []) | length == 0)
' "$SUMMARY_DELEGATED_PARTIAL" >/dev/null; then
  echo "delegated-summary-partial fail-closed summary mismatch"
  cat "$SUMMARY_DELEGATED_PARTIAL"
  exit 1
fi

if [[ -s "$EXEC_LOG" ]]; then
  echo "expected no executions when delegated summary contract is partial/inconsistent"
  cat "$EXEC_LOG"
  exit 1
fi

echo "[roadmap-evidence-pack-actionable-run] invalid scope is rejected"
set +e
bash ./scripts/roadmap_evidence_pack_actionable_run.sh --scope bad-scope --print-summary-json 0 >/dev/null 2>&1
invalid_scope_rc=$?
set -e
if [[ "$invalid_scope_rc" != "2" ]]; then
  echo "expected invalid scope rc=2, got rc=$invalid_scope_rc"
  exit 1
fi

echo "roadmap evidence-pack actionable run integration check ok"
