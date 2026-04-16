#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod mkdir cat grep timeout date; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

FAKE_ROADMAP="$TMP_DIR/fake_roadmap_progress_report.sh"
PASS1="$TMP_DIR/pass_action_1.sh"
PASS2="$TMP_DIR/pass_action_2.sh"
FAIL1="$TMP_DIR/fail_action_1.sh"
FAIL2="$TMP_DIR/fail_action_2.sh"
SLOW1="$TMP_DIR/slow_action_1.sh"
SLOW2="$TMP_DIR/slow_action_2.sh"
UNREACHABLE_PROFILE="$TMP_DIR/profile_unreachable.sh"
MISSING_SUBJECT_PROFILE="$TMP_DIR/profile_missing_subject.sh"
UNREACHABLE_PROFILE_MARKER="$TMP_DIR/profile_unreachable_marker.sh"
MISSING_SUBJECT_PROFILE_MARKER="$TMP_DIR/profile_missing_subject_marker.sh"
FAKE_EASY_NODE="$TMP_DIR/fake_easy_node.sh"
FAKE_EASY_NODE_CAPTURE="$TMP_DIR/fake_easy_node_capture.log"

cat >"$PASS1" <<'EOF_PASS1'
#!/usr/bin/env bash
set -euo pipefail
echo "pass action 1"
EOF_PASS1
chmod +x "$PASS1"

cat >"$PASS2" <<'EOF_PASS2'
#!/usr/bin/env bash
set -euo pipefail
echo "pass action 2"
EOF_PASS2
chmod +x "$PASS2"

cat >"$FAIL1" <<'EOF_FAIL1'
#!/usr/bin/env bash
set -euo pipefail
echo "fail action 1"
exit 7
EOF_FAIL1
chmod +x "$FAIL1"

cat >"$FAIL2" <<'EOF_FAIL2'
#!/usr/bin/env bash
set -euo pipefail
echo "fail action 2"
exit 13
EOF_FAIL2
chmod +x "$FAIL2"

cat >"$SLOW1" <<'EOF_SLOW1'
#!/usr/bin/env bash
set -euo pipefail
sleep 3
echo "slow action 1 done"
EOF_SLOW1
chmod +x "$SLOW1"

cat >"$SLOW2" <<'EOF_SLOW2'
#!/usr/bin/env bash
set -euo pipefail
sleep 4
echo "slow action 2 done"
EOF_SLOW2
chmod +x "$SLOW2"

cat >"$UNREACHABLE_PROFILE" <<'EOF_UNREACHABLE_PROFILE'
#!/usr/bin/env bash
set -euo pipefail
echo "[profile-default-gate-run] 2026-01-01T00:00:00Z wait-fail label=directory-a url=http://100.113.245.61:8081/v1/pubkeys attempt=3 error=curl rc=7"
echo "profile-default-gate-run failed: unreachable directory endpoint (directory-a) url=http://100.113.245.61:8081/v1/pubkeys timeout_sec=45"
echo "last_error: curl rc=7: Failed to connect"
exit 1
EOF_UNREACHABLE_PROFILE
chmod +x "$UNREACHABLE_PROFILE"

cat >"$MISSING_SUBJECT_PROFILE" <<'EOF_MISSING_SUBJECT_PROFILE'
#!/usr/bin/env bash
set -euo pipefail
echo "profile-default-gate-run failed: missing invite key subject"
echo "provide --campaign-subject/--subject, or set CAMPAIGN_SUBJECT/INVITE_KEY"
echo "or define CAMPAIGN_SUBJECT/INVITE_KEY in runtime/default/env.client"
exit 2
EOF_MISSING_SUBJECT_PROFILE
chmod +x "$MISSING_SUBJECT_PROFILE"

cat >"$UNREACHABLE_PROFILE_MARKER" <<'EOF_UNREACHABLE_PROFILE_MARKER'
#!/usr/bin/env bash
set -euo pipefail
echo "failure_kind=unreachable_directory_endpoint"
echo "marker-only unreachable endpoint"
exit 1
EOF_UNREACHABLE_PROFILE_MARKER
chmod +x "$UNREACHABLE_PROFILE_MARKER"

cat >"$MISSING_SUBJECT_PROFILE_MARKER" <<'EOF_MISSING_SUBJECT_PROFILE_MARKER'
#!/usr/bin/env bash
set -euo pipefail
echo "failure_kind=missing_invite_subject_precondition"
echo "marker-only missing subject"
exit 2
EOF_MISSING_SUBJECT_PROFILE_MARKER
chmod +x "$MISSING_SUBJECT_PROFILE_MARKER"

cat >"$FAKE_EASY_NODE" <<'EOF_FAKE_EASY_NODE'
#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${FAKE_EASY_NODE_CAPTURE:-}" ]]; then
  printf '%s\n' "$*" >>"$FAKE_EASY_NODE_CAPTURE"
fi
if [[ "$*" == *"--campaign-subject"* || "$*" == *"--subject"* || "$*" == *"--campaign-anon-cred"* || "$*" == *"--anon-cred"* ]]; then
  echo "fake easy_node profile-default-gate-run ok"
  exit 0
fi
echo "profile-default-gate-run failed: missing invite key subject"
echo "provide --campaign-subject/--subject, or set CAMPAIGN_SUBJECT/INVITE_KEY"
exit 2
EOF_FAKE_EASY_NODE
chmod +x "$FAKE_EASY_NODE"

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
scenario="${ROADMAP_NEXT_ACTIONS_SCENARIO:-success_with_empty}"
case "$scenario" in
  success_with_empty)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"next_pass_1","label":"Next pass 1","command":"bash \"$PASS1\"","reason":"test"},
    {"id":"next_empty","label":"Next empty","command":"","reason":"skip-empty"},
    {"id":"next_pass_2","label":"Next pass 2","command":"bash \"$PASS2\"","reason":"test"}
  ]
}
JSON
    ;;
  filter_mix)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"keep_a_1","label":"Keep A1","command":"bash \"$PASS1\"","reason":"test"},
    {"id":"drop_b_1","label":"Drop B1","command":"bash \"$PASS2\"","reason":"test"},
    {"id":"keep_a_2","label":"Keep A2","command":"bash \"$PASS2\"","reason":"test"},
    {"id":"keep_empty","label":"Keep empty","command":"","reason":"skip-empty"}
  ]
}
JSON
    ;;
  fail_first_rc)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"fail_first","label":"Fail first","command":"bash \"$FAIL1\"","reason":"test"},
    {"id":"fail_second","label":"Fail second","command":"bash \"$FAIL2\"","reason":"test"},
    {"id":"pass_last","label":"Pass last","command":"bash \"$PASS1\"","reason":"test"}
  ]
}
JSON
    ;;
  timeout_then_pass)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"timeout_one","label":"Timeout one","command":"bash \"$SLOW1\"","reason":"test-timeout"},
    {"id":"pass_after_timeout","label":"Pass after timeout","command":"bash \"$PASS1\"","reason":"test"}
  ]
}
JSON
    ;;
  no_actions)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"empty_1","label":"Empty 1","command":"","reason":"skip-empty"},
    {"id":"empty_2","label":"Empty 2","command":"","reason":"skip-empty"}
  ]
}
JSON
    ;;
  parallel_two_slow)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"par_slow_1","label":"Parallel slow 1","command":"bash \"$SLOW1\"","reason":"test-parallel"},
    {"id":"par_slow_2","label":"Parallel slow 2","command":"bash \"$SLOW2\"","reason":"test-parallel"}
  ]
}
JSON
    ;;
  profile_unreachable)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate","label":"Profile default decision gate","command":"bash \"$UNREACHABLE_PROFILE\"","reason":"test-unreachable"}
  ]
}
JSON
    ;;
  profile_missing_subject)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate","label":"Profile default decision gate","command":"bash \"$MISSING_SUBJECT_PROFILE\"","reason":"test-precondition"}
  ]
}
JSON
    ;;
  profile_missing_subject_marker)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate","label":"Profile default decision gate","command":"bash \"$MISSING_SUBJECT_PROFILE_MARKER\"","reason":"test-precondition-marker"}
  ]
}
JSON
    ;;
  profile_missing_subject_easy_node)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate","label":"Profile default decision gate","command":"bash \"$FAKE_EASY_NODE\" profile-default-gate-run --reports-dir /tmp/fake_profile_reports","reason":"test-precondition-override"}
  ]
}
JSON
    ;;
  profile_unreachable_marker)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate","label":"Profile default decision gate","command":"bash \"$UNREACHABLE_PROFILE_MARKER\"","reason":"test-unreachable-marker"}
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

echo "[roadmap-next-actions-run] help contract"
if ! bash ./scripts/roadmap_next_actions_run.sh --help | grep -F -- "--include-id-prefix PREFIX" >/dev/null; then
  echo "help output missing --include-id-prefix PREFIX"
  exit 1
fi
if ! bash ./scripts/roadmap_next_actions_run.sh --help | grep -F -- "--exclude-id-prefix PREFIX" >/dev/null; then
  echo "help output missing --exclude-id-prefix PREFIX"
  exit 1
fi
if ! bash ./scripts/roadmap_next_actions_run.sh --help | grep -F -- "--parallel [0|1]" >/dev/null; then
  echo "help output missing --parallel [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_next_actions_run.sh --help | grep -F -- "--allow-profile-default-gate-unreachable [0|1]" >/dev/null; then
  echo "help output missing --allow-profile-default-gate-unreachable [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_next_actions_run.sh --help | grep -F -- "--profile-default-gate-subject ID" >/dev/null; then
  echo "help output missing --profile-default-gate-subject ID"
  exit 1
fi

echo "[roadmap-next-actions-run] success path with empty command skipped"
SUMMARY_PASS="$TMP_DIR/summary_pass.json"
REPORTS_PASS="$TMP_DIR/reports_pass"
ROADMAP_NEXT_ACTIONS_SCENARIO=success_with_empty \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_PASS" \
  --summary-json "$SUMMARY_PASS" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.generated_this_run == true
  and .roadmap.actions_selected_count == 2
  and .roadmap.selected_action_ids == ["next_pass_1","next_pass_2"]
  and .summary.actions_executed == 2
  and .summary.pass == 2
  and .summary.fail == 0
  and .summary.timed_out == 0
  and ((.actions // []) | length == 2)
  and ((.actions // []) | all(.status == "pass"))
' "$SUMMARY_PASS" >/dev/null; then
  echo "success path summary mismatch"
  cat "$SUMMARY_PASS"
  exit 1
fi

echo "[roadmap-next-actions-run] max-actions truncation path"
SUMMARY_MAX="$TMP_DIR/summary_max.json"
REPORTS_MAX="$TMP_DIR/reports_max"
ROADMAP_NEXT_ACTIONS_SCENARIO=success_with_empty \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_MAX" \
  --summary-json "$SUMMARY_MAX" \
  --max-actions 1 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["next_pass_1"]
  and .summary.actions_executed == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "next_pass_1"
  and .actions[0].status == "pass"
' "$SUMMARY_MAX" >/dev/null; then
  echo "max-actions summary mismatch"
  cat "$SUMMARY_MAX"
  exit 1
fi

echo "[roadmap-next-actions-run] include/exclude id-prefix filtering path"
SUMMARY_FILTER="$TMP_DIR/summary_filter.json"
REPORTS_FILTER="$TMP_DIR/reports_filter"
ROADMAP_NEXT_ACTIONS_SCENARIO=filter_mix \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_FILTER" \
  --summary-json "$SUMMARY_FILTER" \
  --include-id-prefix keep_ \
  --exclude-id-prefix keep_a_2 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.include_id_prefix == "keep_"
  and .inputs.exclude_id_prefix == "keep_a_2"
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["keep_a_1"]
  and .summary.actions_executed == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "keep_a_1"
  and .actions[0].status == "pass"
' "$SUMMARY_FILTER" >/dev/null; then
  echo "include/exclude filtering summary mismatch"
  cat "$SUMMARY_FILTER"
  exit 1
fi

echo "[roadmap-next-actions-run] failure path keeps first failing rc and continues"
SUMMARY_FAIL="$TMP_DIR/summary_fail.json"
REPORTS_FAIL="$TMP_DIR/reports_fail"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=fail_first_rc \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_FAIL" \
  --summary-json "$SUMMARY_FAIL" \
  --print-summary-json 0
fail_rc=$?
set -e
if [[ "$fail_rc" != "7" ]]; then
  echo "expected failure rc=7, got rc=$fail_rc"
  cat "$SUMMARY_FAIL"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 7
  and .roadmap.actions_selected_count == 3
  and .summary.actions_executed == 3
  and .summary.pass == 1
  and .summary.fail == 2
  and ((.actions // []) | length == 3)
  and .actions[0].id == "fail_first"
  and .actions[0].status == "fail"
  and .actions[0].rc == 7
  and .actions[1].id == "fail_second"
  and .actions[1].status == "fail"
  and .actions[1].rc == 13
  and .actions[2].id == "pass_last"
  and .actions[2].status == "pass"
' "$SUMMARY_FAIL" >/dev/null; then
  echo "failure path summary mismatch"
  cat "$SUMMARY_FAIL"
  exit 1
fi

echo "[roadmap-next-actions-run] timeout path"
SUMMARY_TIMEOUT="$TMP_DIR/summary_timeout.json"
REPORTS_TIMEOUT="$TMP_DIR/reports_timeout"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=timeout_then_pass \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_TIMEOUT" \
  --summary-json "$SUMMARY_TIMEOUT" \
  --action-timeout-sec 1 \
  --print-summary-json 0
timeout_rc=$?
set -e
if [[ "$timeout_rc" != "124" ]]; then
  echo "expected timeout rc=124, got rc=$timeout_rc"
  cat "$SUMMARY_TIMEOUT"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 124
  and .inputs.action_timeout_sec == 1
  and .summary.actions_executed == 2
  and .summary.pass == 1
  and .summary.fail == 1
  and .summary.timed_out == 1
  and ((.actions // []) | length == 2)
  and .actions[0].id == "timeout_one"
  and .actions[0].status == "fail"
  and .actions[0].rc == 124
  and .actions[0].command_rc == 124
  and .actions[0].timed_out == true
  and .actions[0].failure_kind == "timed_out"
  and .actions[1].id == "pass_after_timeout"
  and .actions[1].status == "pass"
' "$SUMMARY_TIMEOUT" >/dev/null; then
  echo "timeout path summary mismatch"
  cat "$SUMMARY_TIMEOUT"
  exit 1
fi

echo "[roadmap-next-actions-run] profile missing-subject hard-fail default path"
SUMMARY_PROFILE_PRECONDITION_HARD_FAIL="$TMP_DIR/summary_profile_precondition_hard_fail.json"
REPORTS_PROFILE_PRECONDITION_HARD_FAIL="$TMP_DIR/reports_profile_precondition_hard_fail"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=profile_missing_subject \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" MISSING_SUBJECT_PROFILE="$MISSING_SUBJECT_PROFILE" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_PROFILE_PRECONDITION_HARD_FAIL" \
  --summary-json "$SUMMARY_PROFILE_PRECONDITION_HARD_FAIL" \
  --print-summary-json 0
profile_precondition_hard_fail_rc=$?
set -e
if [[ "$profile_precondition_hard_fail_rc" != "2" ]]; then
  echo "expected profile missing-subject hard-fail rc=2, got rc=$profile_precondition_hard_fail_rc"
  cat "$SUMMARY_PROFILE_PRECONDITION_HARD_FAIL"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 2
  and .summary.actions_executed == 1
  and .summary.pass == 0
  and .summary.fail == 1
  and .summary.soft_failed == 0
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate"
  and .actions[0].status == "fail"
  and .actions[0].rc == 2
  and .actions[0].failure_kind == "command_failed"
  and ((.actions[0].soft_failed // false) == false)
' "$SUMMARY_PROFILE_PRECONDITION_HARD_FAIL" >/dev/null; then
  echo "profile missing-subject hard-fail summary mismatch"
  cat "$SUMMARY_PROFILE_PRECONDITION_HARD_FAIL"
  exit 1
fi

echo "[roadmap-next-actions-run] profile subject override appends campaign-subject and avoids precondition hard-fail"
SUMMARY_PROFILE_SUBJECT_OVERRIDE="$TMP_DIR/summary_profile_subject_override.json"
REPORTS_PROFILE_SUBJECT_OVERRIDE="$TMP_DIR/reports_profile_subject_override"
: >"$FAKE_EASY_NODE_CAPTURE"
ROADMAP_NEXT_ACTIONS_SCENARIO=profile_missing_subject_easy_node \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" MISSING_SUBJECT_PROFILE="$MISSING_SUBJECT_PROFILE" FAKE_EASY_NODE="$FAKE_EASY_NODE" FAKE_EASY_NODE_CAPTURE="$FAKE_EASY_NODE_CAPTURE" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_PROFILE_SUBJECT_OVERRIDE" \
  --summary-json "$SUMMARY_PROFILE_SUBJECT_OVERRIDE" \
  --profile-default-gate-subject inv-override-subject \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.allow_profile_default_gate_unreachable == false
  and .inputs.action_timeout_sec == 0
  and .inputs.profile_default_gate_default_timeout_sec == 1200
  and .inputs.profile_default_gate_subject == "inv-override-subject"
  and .summary.actions_executed == 1
  and .summary.pass == 1
  and .summary.fail == 0
  and .summary.soft_failed == 0
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate"
  and ((.actions[0].command // "") | contains("fake_easy_node"))
  and .actions[0].status == "pass"
  and .actions[0].timeout_sec == 1200
  and ((.actions[0].command // "") | contains("--campaign-subject"))
  and ((.actions[0].soft_failed // false) == false)
' "$SUMMARY_PROFILE_SUBJECT_OVERRIDE" >/dev/null; then
  echo "profile subject override summary mismatch"
  cat "$SUMMARY_PROFILE_SUBJECT_OVERRIDE"
  exit 1
fi
if ! grep -E -- '--campaign-subject[[:space:]]+inv-override-subject([[:space:]]|$)' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "profile subject override command capture missing appended --campaign-subject"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi

echo "[roadmap-next-actions-run] profile default timeout env override path"
SUMMARY_PROFILE_TIMEOUT_OVERRIDE="$TMP_DIR/summary_profile_timeout_override.json"
REPORTS_PROFILE_TIMEOUT_OVERRIDE="$TMP_DIR/reports_profile_timeout_override"
: >"$FAKE_EASY_NODE_CAPTURE"
ROADMAP_NEXT_ACTIONS_SCENARIO=profile_missing_subject_easy_node \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" MISSING_SUBJECT_PROFILE="$MISSING_SUBJECT_PROFILE" FAKE_EASY_NODE="$FAKE_EASY_NODE" FAKE_EASY_NODE_CAPTURE="$FAKE_EASY_NODE_CAPTURE" \
ROADMAP_NEXT_ACTIONS_RUN_PROFILE_DEFAULT_GATE_DEFAULT_TIMEOUT_SEC=321 \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_PROFILE_TIMEOUT_OVERRIDE" \
  --summary-json "$SUMMARY_PROFILE_TIMEOUT_OVERRIDE" \
  --profile-default-gate-subject inv-timeout-override \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.action_timeout_sec == 0
  and .inputs.profile_default_gate_default_timeout_sec == 321
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate"
  and .actions[0].timeout_sec == 321
  and ((.actions[0].command // "") | contains("--campaign-subject"))
' "$SUMMARY_PROFILE_TIMEOUT_OVERRIDE" >/dev/null; then
  echo "profile default timeout override summary mismatch"
  cat "$SUMMARY_PROFILE_TIMEOUT_OVERRIDE"
  exit 1
fi

echo "[roadmap-next-actions-run] profile missing-subject soft-fail path"
SUMMARY_PROFILE_PRECONDITION_SOFT_FAIL="$TMP_DIR/summary_profile_precondition_soft_fail.json"
REPORTS_PROFILE_PRECONDITION_SOFT_FAIL="$TMP_DIR/reports_profile_precondition_soft_fail"
ROADMAP_NEXT_ACTIONS_SCENARIO=profile_missing_subject \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" MISSING_SUBJECT_PROFILE="$MISSING_SUBJECT_PROFILE" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_PROFILE_PRECONDITION_SOFT_FAIL" \
  --summary-json "$SUMMARY_PROFILE_PRECONDITION_SOFT_FAIL" \
  --allow-profile-default-gate-unreachable 1 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.allow_profile_default_gate_unreachable == true
  and .summary.actions_executed == 1
  and .summary.pass == 1
  and .summary.fail == 0
  and .summary.soft_failed == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate"
  and .actions[0].status == "pass"
  and .actions[0].rc == 0
  and .actions[0].command_rc == 2
  and .actions[0].failure_kind == "soft_failed_profile_default_gate_precondition"
  and .actions[0].soft_failed == true
' "$SUMMARY_PROFILE_PRECONDITION_SOFT_FAIL" >/dev/null; then
  echo "profile missing-subject soft-fail summary mismatch"
  cat "$SUMMARY_PROFILE_PRECONDITION_SOFT_FAIL"
  exit 1
fi

echo "[roadmap-next-actions-run] profile missing-subject marker soft-fail path"
SUMMARY_PROFILE_PRECONDITION_MARKER_SOFT_FAIL="$TMP_DIR/summary_profile_precondition_marker_soft_fail.json"
REPORTS_PROFILE_PRECONDITION_MARKER_SOFT_FAIL="$TMP_DIR/reports_profile_precondition_marker_soft_fail"
ROADMAP_NEXT_ACTIONS_SCENARIO=profile_missing_subject_marker \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" MISSING_SUBJECT_PROFILE_MARKER="$MISSING_SUBJECT_PROFILE_MARKER" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_PROFILE_PRECONDITION_MARKER_SOFT_FAIL" \
  --summary-json "$SUMMARY_PROFILE_PRECONDITION_MARKER_SOFT_FAIL" \
  --allow-profile-default-gate-unreachable 1 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .summary.actions_executed == 1
  and .summary.pass == 1
  and .summary.fail == 0
  and .summary.soft_failed == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate"
  and .actions[0].status == "pass"
  and .actions[0].rc == 0
  and .actions[0].command_rc == 2
  and .actions[0].failure_kind == "soft_failed_profile_default_gate_precondition"
  and .actions[0].soft_failed == true
' "$SUMMARY_PROFILE_PRECONDITION_MARKER_SOFT_FAIL" >/dev/null; then
  echo "profile missing-subject marker soft-fail summary mismatch"
  cat "$SUMMARY_PROFILE_PRECONDITION_MARKER_SOFT_FAIL"
  exit 1
fi

echo "[roadmap-next-actions-run] profile unreachable hard-fail default path"
SUMMARY_PROFILE_HARD_FAIL="$TMP_DIR/summary_profile_hard_fail.json"
REPORTS_PROFILE_HARD_FAIL="$TMP_DIR/reports_profile_hard_fail"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=profile_unreachable \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" UNREACHABLE_PROFILE="$UNREACHABLE_PROFILE" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_PROFILE_HARD_FAIL" \
  --summary-json "$SUMMARY_PROFILE_HARD_FAIL" \
  --print-summary-json 0
profile_hard_fail_rc=$?
set -e
if [[ "$profile_hard_fail_rc" != "1" ]]; then
  echo "expected profile unreachable hard-fail rc=1, got rc=$profile_hard_fail_rc"
  cat "$SUMMARY_PROFILE_HARD_FAIL"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .summary.actions_executed == 1
  and .summary.pass == 0
  and .summary.fail == 1
  and .summary.soft_failed == 0
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate"
  and .actions[0].status == "fail"
  and .actions[0].rc == 1
  and ((.actions[0].soft_failed // false) == false)
' "$SUMMARY_PROFILE_HARD_FAIL" >/dev/null; then
  echo "profile unreachable hard-fail summary mismatch"
  cat "$SUMMARY_PROFILE_HARD_FAIL"
  exit 1
fi

echo "[roadmap-next-actions-run] profile unreachable soft-fail path"
SUMMARY_PROFILE_SOFT_FAIL="$TMP_DIR/summary_profile_soft_fail.json"
REPORTS_PROFILE_SOFT_FAIL="$TMP_DIR/reports_profile_soft_fail"
ROADMAP_NEXT_ACTIONS_SCENARIO=profile_unreachable \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" UNREACHABLE_PROFILE="$UNREACHABLE_PROFILE" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_PROFILE_SOFT_FAIL" \
  --summary-json "$SUMMARY_PROFILE_SOFT_FAIL" \
  --profile-default-gate-subject inv-unreachable-override \
  --allow-profile-default-gate-unreachable 1 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.allow_profile_default_gate_unreachable == true
  and .inputs.profile_default_gate_subject == "inv-unreachable-override"
  and .summary.actions_executed == 1
  and .summary.pass == 1
  and .summary.fail == 0
  and .summary.soft_failed == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate"
  and ((.actions[0].command // "") | contains("--campaign-subject"))
  and .actions[0].status == "pass"
  and .actions[0].rc == 0
  and .actions[0].command_rc == 1
  and .actions[0].failure_kind == "soft_failed_unreachable_profile_default_gate"
  and .actions[0].soft_failed == true
' "$SUMMARY_PROFILE_SOFT_FAIL" >/dev/null; then
  echo "profile unreachable soft-fail summary mismatch"
  cat "$SUMMARY_PROFILE_SOFT_FAIL"
  exit 1
fi

echo "[roadmap-next-actions-run] profile unreachable marker soft-fail path"
SUMMARY_PROFILE_MARKER_SOFT_FAIL="$TMP_DIR/summary_profile_marker_soft_fail.json"
REPORTS_PROFILE_MARKER_SOFT_FAIL="$TMP_DIR/reports_profile_marker_soft_fail"
ROADMAP_NEXT_ACTIONS_SCENARIO=profile_unreachable_marker \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" UNREACHABLE_PROFILE_MARKER="$UNREACHABLE_PROFILE_MARKER" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_PROFILE_MARKER_SOFT_FAIL" \
  --summary-json "$SUMMARY_PROFILE_MARKER_SOFT_FAIL" \
  --allow-profile-default-gate-unreachable 1 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .summary.actions_executed == 1
  and .summary.pass == 1
  and .summary.fail == 0
  and .summary.soft_failed == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate"
  and .actions[0].status == "pass"
  and .actions[0].rc == 0
  and .actions[0].command_rc == 1
  and .actions[0].failure_kind == "soft_failed_unreachable_profile_default_gate"
  and .actions[0].soft_failed == true
' "$SUMMARY_PROFILE_MARKER_SOFT_FAIL" >/dev/null; then
  echo "profile unreachable marker soft-fail summary mismatch"
  cat "$SUMMARY_PROFILE_MARKER_SOFT_FAIL"
  exit 1
fi

echo "[roadmap-next-actions-run] no-actions path"
SUMMARY_EMPTY="$TMP_DIR/summary_empty.json"
REPORTS_EMPTY="$TMP_DIR/reports_empty"
ROADMAP_NEXT_ACTIONS_SCENARIO=no_actions \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_EMPTY" \
  --summary-json "$SUMMARY_EMPTY" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.actions_selected_count == 0
  and .roadmap.selected_action_ids == []
  and .summary.actions_executed == 0
  and .summary.pass == 0
  and .summary.fail == 0
  and .summary.timed_out == 0
  and ((.actions // []) | length == 0)
' "$SUMMARY_EMPTY" >/dev/null; then
  echo "no-actions summary mismatch"
  cat "$SUMMARY_EMPTY"
  exit 1
fi

echo "[roadmap-next-actions-run] parallel path timing sanity"
SUMMARY_PARALLEL="$TMP_DIR/summary_parallel.json"
REPORTS_PARALLEL="$TMP_DIR/reports_parallel"
parallel_started_epoch="$(date +%s)"
ROADMAP_NEXT_ACTIONS_SCENARIO=parallel_two_slow \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_PARALLEL" \
  --summary-json "$SUMMARY_PARALLEL" \
  --parallel 1 \
  --print-summary-json 0
parallel_finished_epoch="$(date +%s)"
parallel_elapsed_sec=$((parallel_finished_epoch - parallel_started_epoch))

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.parallel == true
  and .roadmap.actions_selected_count == 2
  and .summary.actions_executed == 2
  and .summary.pass == 2
  and .summary.fail == 0
  and ((.actions // []) | length == 2)
  and ((.actions // []) | all(.status == "pass"))
' "$SUMMARY_PARALLEL" >/dev/null; then
  echo "parallel path summary mismatch"
  cat "$SUMMARY_PARALLEL"
  exit 1
fi

if (( parallel_elapsed_sec > 6 )); then
  echo "parallel timing mismatch: expected <=6s, got ${parallel_elapsed_sec}s"
  cat "$SUMMARY_PARALLEL"
  exit 1
fi

echo "roadmap next-actions run integration check ok"
