#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Keep this integration hermetic: ambient subject overrides can bypass
# placeholder-precondition fail-closed paths and make assertions flaky.
unset ROADMAP_NEXT_ACTIONS_RUN_PROFILE_DEFAULT_GATE_SUBJECT
unset CAMPAIGN_SUBJECT
unset INVITE_KEY

for cmd in bash jq mktemp chmod mkdir cat grep timeout date ln; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

mkdir -p "$ROOT_DIR/.easy-node-logs"
TMP_DIR="$(mktemp -d "$ROOT_DIR/.easy-node-logs/integration_roadmap_next_actions_run_XXXXXX")"
ACTION_TMP_DIR="$(mktemp -d "$ROOT_DIR/scripts/.integration_roadmap_next_actions_run.XXXXXX")"
trap 'rm -rf "$TMP_DIR" "$ACTION_TMP_DIR"' EXIT

FAKE_ROADMAP="$TMP_DIR/fake_roadmap_progress_report.sh"
PASS1="$ACTION_TMP_DIR/pass_action_1.sh"
PASS2="$ACTION_TMP_DIR/pass_action_2.sh"
DEDUPE_MARK="$ACTION_TMP_DIR/dedupe_mark_action.sh"
DEDUP_MARK_COUNT_FILE="$ACTION_TMP_DIR/dedupe_mark_count.txt"
CONFLICT_CMD_A="$ACTION_TMP_DIR/conflict_cmd_a.sh"
CONFLICT_CMD_B="$ACTION_TMP_DIR/conflict_cmd_b.sh"
CONFLICT_MARK_A="$ACTION_TMP_DIR/conflict_cmd_a.marker"
CONFLICT_MARK_B="$ACTION_TMP_DIR/conflict_cmd_b.marker"
FAIL1="$ACTION_TMP_DIR/fail_action_1.sh"
FAIL2="$ACTION_TMP_DIR/fail_action_2.sh"
SLOW1="$ACTION_TMP_DIR/slow_action_1.sh"
SLOW2="$ACTION_TMP_DIR/slow_action_2.sh"
UNREACHABLE_PROFILE="$ACTION_TMP_DIR/profile_unreachable.sh"
MISSING_SUBJECT_PROFILE="$ACTION_TMP_DIR/profile_missing_subject.sh"
MISSING_SUBJECT_PROFILE_LIVE="$ACTION_TMP_DIR/profile_missing_subject_live.sh"
UNREACHABLE_PROFILE_MARKER="$ACTION_TMP_DIR/profile_unreachable_marker.sh"
MISSING_SUBJECT_PROFILE_MARKER="$ACTION_TMP_DIR/profile_missing_subject_marker.sh"
FAKE_EASY_NODE="$ACTION_TMP_DIR/fake_easy_node.sh"
FAKE_EASY_NODE_CAPTURE="$ACTION_TMP_DIR/fake_easy_node_capture.log"
SYMLINK_ESCAPE_TARGET="$TMP_DIR/symlink_escape_target.sh"
SYMLINK_ESCAPE_LINK="$ACTION_TMP_DIR/symlink_escape_action.sh"
SYMLINK_ESCAPE_MARKER="$TMP_DIR/symlink_escape_marker.txt"
PARENT_SYMLINK_ESCAPE_DIR_TARGET="$TMP_DIR/parent_symlink_escape_dir"
PARENT_SYMLINK_ESCAPE_DIR_LINK="$ACTION_TMP_DIR/parent_symlink_escape_link"
PARENT_SYMLINK_ESCAPE_SCRIPT="$PARENT_SYMLINK_ESCAPE_DIR_TARGET/parent_symlink_escape_action.sh"
PARENT_SYMLINK_ESCAPE_MARKER="$TMP_DIR/parent_symlink_escape_marker.txt"
TOCTOU_MUTATE_ACTION="$ACTION_TMP_DIR/toctou_mutate_action.sh"
TOCTOU_RACE_ACTION="$ACTION_TMP_DIR/toctou_race_action.sh"
TOCTOU_ESCAPE_TARGET="$TMP_DIR/toctou_escape_target.sh"
TOCTOU_ESCAPE_MARKER="$TMP_DIR/toctou_escape_marker.txt"

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

cat >"$DEDUPE_MARK" <<'EOF_DEDUPE_MARK'
#!/usr/bin/env bash
set -euo pipefail
count_file="${NEXT_ACTION_DEDUPE_COUNT_FILE:-}"
if [[ -z "$count_file" ]]; then
  echo "missing NEXT_ACTION_DEDUPE_COUNT_FILE"
  exit 2
fi
printf 'run\n' >>"$count_file"
echo "dedupe marker ran"
EOF_DEDUPE_MARK
chmod +x "$DEDUPE_MARK"

cat >"$CONFLICT_CMD_A" <<'EOF_CONFLICT_CMD_A'
#!/usr/bin/env bash
set -euo pipefail
marker="${NEXT_ACTION_CONFLICT_MARK_A:-}"
if [[ -z "$marker" ]]; then
  echo "missing NEXT_ACTION_CONFLICT_MARK_A"
  exit 2
fi
printf 'ran\n' >>"$marker"
echo "conflict command A ran"
EOF_CONFLICT_CMD_A
chmod +x "$CONFLICT_CMD_A"

cat >"$CONFLICT_CMD_B" <<'EOF_CONFLICT_CMD_B'
#!/usr/bin/env bash
set -euo pipefail
marker="${NEXT_ACTION_CONFLICT_MARK_B:-}"
if [[ -z "$marker" ]]; then
  echo "missing NEXT_ACTION_CONFLICT_MARK_B"
  exit 2
fi
printf 'ran\n' >>"$marker"
echo "conflict command B ran"
EOF_CONFLICT_CMD_B
chmod +x "$CONFLICT_CMD_B"

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
echo "[profile-default-gate-run] 2026-01-01T00:00:00Z wait-timeout label=directory-a url=http://100.113.245.61:8081/v1/pubkeys attempt=3 error=curl rc=7"
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

cat >"$MISSING_SUBJECT_PROFILE_LIVE" <<'EOF_MISSING_SUBJECT_PROFILE_LIVE'
#!/usr/bin/env bash
set -euo pipefail
echo "profile-default-gate-live requires invite subject (set --campaign-subject/--subject/--key or INVITE_KEY)"
exit 2
EOF_MISSING_SUBJECT_PROFILE_LIVE
chmod +x "$MISSING_SUBJECT_PROFILE_LIVE"

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
arg_value_for_flag() {
  local flag="$1"
  shift
  local -a argv=("$@")
  local idx=0
  local token=""
  for token in "${argv[@]}"; do
    if [[ "$token" == "$flag" ]]; then
      if (( idx + 1 < ${#argv[@]} )); then
        printf '%s' "${argv[$((idx + 1))]}"
      else
        printf '%s' ""
      fi
      return
    fi
    if [[ "$token" == "$flag="* ]]; then
      printf '%s' "${token#"$flag="}"
      return
    fi
    idx=$((idx + 1))
  done
  printf '%s' ""
}
if [[ -n "${FAKE_EASY_NODE_CAPTURE:-}" ]]; then
  printf '%s\n' "$*" >>"$FAKE_EASY_NODE_CAPTURE"
fi
reports_dir="$(arg_value_for_flag --reports-dir "$@")"
summary_json="$(arg_value_for_flag --summary-json "$@")"
subject_value="$(arg_value_for_flag --campaign-subject "$@")"
if [[ -z "$subject_value" ]]; then
  subject_value="$(arg_value_for_flag --subject "$@")"
fi
if [[ -z "$subject_value" ]]; then
  subject_value="$(arg_value_for_flag --key "$@")"
fi
if [[ -z "$subject_value" ]]; then
  subject_value="$(arg_value_for_flag --invite-key "$@")"
fi
anon_cred_value="$(arg_value_for_flag --campaign-anon-cred "$@")"
if [[ -z "$anon_cred_value" ]]; then
  anon_cred_value="$(arg_value_for_flag --anon-cred "$@")"
fi
if [[ -n "${FAKE_EASY_NODE_EXPECT_REPORTS_DIR:-}" && "$reports_dir" != "$FAKE_EASY_NODE_EXPECT_REPORTS_DIR" ]]; then
  echo "fake easy_node expected --reports-dir '$FAKE_EASY_NODE_EXPECT_REPORTS_DIR' but got '$reports_dir'"
  exit 9
fi
if [[ -n "${FAKE_EASY_NODE_EXPECT_SUMMARY_JSON:-}" && "$summary_json" != "$FAKE_EASY_NODE_EXPECT_SUMMARY_JSON" ]]; then
  echo "fake easy_node expected --summary-json '$FAKE_EASY_NODE_EXPECT_SUMMARY_JSON' but got '$summary_json'"
  exit 9
fi
if [[ -n "${FAKE_EASY_NODE_EXPECT_SUBJECT:-}" && "$subject_value" != "$FAKE_EASY_NODE_EXPECT_SUBJECT" ]]; then
  echo "fake easy_node expected subject '$FAKE_EASY_NODE_EXPECT_SUBJECT' but got '$subject_value'"
  exit 9
fi
if [[ -n "$subject_value" || -n "$anon_cred_value" ]]; then
  echo "fake easy_node profile-default-gate-run ok"
  exit 0
fi
echo "profile-default-gate-run failed: missing invite key subject"
echo "provide --campaign-subject/--subject, or set CAMPAIGN_SUBJECT/INVITE_KEY"
exit 2
EOF_FAKE_EASY_NODE
chmod +x "$FAKE_EASY_NODE"

cat >"$SYMLINK_ESCAPE_TARGET" <<'EOF_SYMLINK_ESCAPE_TARGET'
#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${SYMLINK_ESCAPE_MARKER:-}" ]]; then
  echo "symlink-escape-executed" >"$SYMLINK_ESCAPE_MARKER"
fi
echo "symlink escape payload executed"
EOF_SYMLINK_ESCAPE_TARGET
chmod +x "$SYMLINK_ESCAPE_TARGET"
ln -s "$SYMLINK_ESCAPE_TARGET" "$SYMLINK_ESCAPE_LINK"
mkdir -p "$PARENT_SYMLINK_ESCAPE_DIR_TARGET"
cat >"$PARENT_SYMLINK_ESCAPE_SCRIPT" <<'EOF_PARENT_SYMLINK_ESCAPE_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${PARENT_SYMLINK_ESCAPE_MARKER:-}" ]]; then
  echo "parent-symlink-escape-executed" >"$PARENT_SYMLINK_ESCAPE_MARKER"
fi
echo "parent symlink escape payload executed"
EOF_PARENT_SYMLINK_ESCAPE_SCRIPT
chmod +x "$PARENT_SYMLINK_ESCAPE_SCRIPT"
ln -s "$PARENT_SYMLINK_ESCAPE_DIR_TARGET" "$PARENT_SYMLINK_ESCAPE_DIR_LINK"

cat >"$TOCTOU_RACE_ACTION" <<'EOF_TOCTOU_RACE_ACTION'
#!/usr/bin/env bash
set -euo pipefail
echo "toctou race action executed"
EOF_TOCTOU_RACE_ACTION
chmod +x "$TOCTOU_RACE_ACTION"

cat >"$TOCTOU_ESCAPE_TARGET" <<'EOF_TOCTOU_ESCAPE_TARGET'
#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${TOCTOU_ESCAPE_MARKER:-}" ]]; then
  echo "toctou-escape-executed" >"$TOCTOU_ESCAPE_MARKER"
fi
echo "toctou escape payload executed"
EOF_TOCTOU_ESCAPE_TARGET
chmod +x "$TOCTOU_ESCAPE_TARGET"

cat >"$TOCTOU_MUTATE_ACTION" <<'EOF_TOCTOU_MUTATE_ACTION'
#!/usr/bin/env bash
set -euo pipefail
target_script="${TOCTOU_TARGET_SCRIPT:-}"
escape_script="${TOCTOU_ESCAPE_SCRIPT:-}"
if [[ -z "$target_script" || -z "$escape_script" ]]; then
  echo "missing TOCTOU_TARGET_SCRIPT or TOCTOU_ESCAPE_SCRIPT"
  exit 2
fi
(
  sleep 0.2
  rm -f "$target_script"
  ln -s "$escape_script" "$target_script"
) &
echo "toctou mutator armed"
EOF_TOCTOU_MUTATE_ACTION
chmod +x "$TOCTOU_MUTATE_ACTION"

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
  duplicate_actions)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"dedupe_once","label":"Dedupe once","command":"bash \"$DEDUPE_MARK\"","reason":"base"},
    {"id":"dedupe_once","label":"Dedupe once","command":"bash \"$DEDUPE_MARK\"","reason":"base"},
    {"id":"dedupe_once","label":"Dedupe once alternate","command":"bash \"$DEDUPE_MARK\"","reason":"same-id-command"}
  ]
}
JSON
    ;;
  duplicate_id_conflicting_commands)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"dup_conflict","label":"Duplicate conflict A","command":"bash \"$CONFLICT_CMD_A\"","reason":"stale-A"},
    {"id":"dup_conflict","label":"Duplicate conflict B","command":"bash \"$CONFLICT_CMD_B\"","reason":"stale-B"}
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
  multi_vm_stability_action)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_compare_multi_vm_stability","label":"Profile compare multi-VM stability cycle","command":"bash \"$PASS1\"","reason":"test-multi-vm-stability"}
  ]
}
JSON
    ;;
  evidence_pack_helper_conflict)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate_evidence_pack","label":"Profile default evidence-pack publish","command":"bash \"$PASS1\"","reason":"test-evidence-pack"},
    {"id":"roadmap_evidence_pack_actionable_run","label":"Roadmap evidence-pack actionable run","command":"bash \"$PASS2\"","reason":"test-batch-helper"}
  ]
}
JSON
    ;;
  live_evidence_helper_conflict)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate","label":"Profile default decision gate","command":"bash \"$PASS1\"","reason":"test-live-evidence"},
    {"id":"roadmap_live_evidence_actionable_run","label":"Roadmap live evidence actionable run","command":"bash \"$PASS2\"","reason":"test-batch-helper"}
  ]
}
JSON
    ;;
  live_and_pack_helper_conflict)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate","label":"Profile default decision gate","command":"bash \"$PASS1\"","reason":"test-live"},
    {"id":"profile_default_gate_evidence_pack","label":"Profile default evidence-pack publish","command":"bash \"$PASS2\"","reason":"test-pack"},
    {"id":"roadmap_live_evidence_actionable_run","label":"Roadmap live evidence actionable run","command":"bash \"$PASS2\"","reason":"test-live-helper"},
    {"id":"roadmap_evidence_pack_actionable_run","label":"Roadmap evidence-pack actionable run","command":"bash \"$PASS2\"","reason":"test-pack-helper"},
    {"id":"roadmap_live_and_pack_actionable_run","label":"Roadmap live-and-pack actionable run","command":"bash \"$PASS1\"","reason":"test-combined-helper"}
  ]
}
JSON
    ;;
  live_and_pack_with_cycle_batch_helper_conflict)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate","label":"Profile default decision gate","command":"bash \"$PASS1\"","reason":"test-live"},
    {"id":"runtime_actuation_promotion","label":"Runtime-actuation promotion cycle","command":"bash \"$PASS2\"","reason":"test-runtime-live"},
    {"id":"profile_default_gate_evidence_pack","label":"Profile default evidence-pack publish","command":"bash \"$PASS2\"","reason":"test-pack"},
    {"id":"roadmap_live_evidence_actionable_run","label":"Roadmap live evidence actionable run","command":"bash \"$PASS2\"","reason":"test-live-helper"},
    {"id":"roadmap_live_evidence_cycle_batch_run","label":"Roadmap live-evidence cycle-batch run","command":"bash \"$PASS2\"","reason":"test-cycle-batch-helper"},
    {"id":"roadmap_evidence_pack_actionable_run","label":"Roadmap evidence-pack actionable run","command":"bash \"$PASS2\"","reason":"test-pack-helper"},
    {"id":"roadmap_live_and_pack_actionable_run","label":"Roadmap live-and-pack actionable run","command":"bash \"$PASS1\"","reason":"test-combined-helper"}
  ]
}
JSON
    ;;
  live_evidence_cycle_batch_helper_conflict)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate","label":"Profile default decision gate","command":"bash \"$PASS1\"","reason":"test-cycle-live"},
    {"id":"runtime_actuation_promotion","label":"Runtime-actuation promotion cycle","command":"bash \"$PASS2\"","reason":"test-cycle-runtime"},
    {"id":"profile_compare_multi_vm_stability_promotion","label":"Profile compare multi-VM stability promotion cycle","command":"bash \"$PASS2\"","reason":"test-cycle-promotion"},
    {"id":"roadmap_live_evidence_actionable_run","label":"Roadmap live evidence actionable run","command":"bash \"$PASS2\"","reason":"test-live-helper"},
    {"id":"roadmap_live_evidence_cycle_batch_run","label":"Roadmap live-evidence cycle-batch run","command":"bash \"$PASS1\"","reason":"test-cycle-batch-helper"}
  ]
}
JSON
    ;;
  live_evidence_publish_bundle_actions)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate_live_evidence_publish_bundle","label":"Profile-default live-evidence publish bundle","command":"bash \"$PASS1\"","reason":"test-bundle-profile-default"},
    {"id":"runtime_actuation_live_evidence_publish_bundle","label":"Runtime-actuation live-evidence publish bundle","command":"bash \"$PASS2\"","reason":"test-bundle-runtime-actuation"},
    {"id":"profile_compare_multi_vm_live_evidence_publish_bundle","label":"Profile-compare multi-VM live-evidence publish bundle","command":"bash \"$PASS1\"","reason":"test-bundle-multi-vm"}
  ]
}
JSON
    ;;
  live_evidence_publish_bundle_runtime_overlap)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"runtime_actuation_promotion","label":"Runtime-actuation promotion cycle","command":"bash \"$PASS2\"","reason":"test-runtime-cycle"},
    {"id":"runtime_actuation_promotion_evidence_pack","label":"Runtime-actuation promotion evidence-pack publish","command":"bash \"$PASS2\"","reason":"test-runtime-pack"},
    {"id":"runtime_actuation_live_evidence_publish_bundle","label":"Runtime-actuation live-evidence publish bundle","command":"bash \"$PASS1\"","reason":"test-runtime-bundle"}
  ]
}
JSON
    ;;
  live_evidence_publish_bundle_profile_placeholder_subject)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate_live_evidence_publish_bundle","label":"Profile-default live-evidence publish bundle","command":"bash \"$FAKE_EASY_NODE\" profile-default-gate-live-evidence-publish-bundle --reports-dir /tmp/fake_profile_reports --campaign-subject INVITE_KEY --summary-json /tmp/fake_profile_bundle_summary.json --print-summary-json 1","reason":"test-bundle-profile-placeholder"}
  ]
}
JSON
    ;;
  live_evidence_publish_bundle_runtime_unsafe_shell)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"runtime_actuation_live_evidence_publish_bundle","label":"Runtime-actuation live-evidence publish bundle","command":"BASH_ENV=$UNSAFE_BUNDLE_PAYLOAD bash \"$PASS1\"","reason":"test-bundle-runtime-unsafe-shell"}
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
  profile_missing_subject_live)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate","label":"Profile default decision gate","command":"bash \"$MISSING_SUBJECT_PROFILE_LIVE\"","reason":"test-precondition-live"}
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
  profile_placeholder_subject_easy_node)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate","label":"Profile default decision gate","command":"bash \"$FAKE_EASY_NODE\" profile-default-gate-run --reports-dir /tmp/fake_profile_reports --subject INVITE_KEY","reason":"test-precondition-placeholder-override"}
  ]
}
JSON
    ;;
  profile_placeholder_subject_braced_easy_node)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate","label":"Profile default decision gate","command":"bash \"$FAKE_EASY_NODE\" profile-default-gate-run --reports-dir /tmp/fake_profile_reports --subject '\${CAMPAIGN_SUBJECT}'","reason":"test-precondition-placeholder-braced"}
  ]
}
JSON
    ;;
  profile_placeholder_key_easy_node)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate","label":"Profile default decision gate","command":"bash \"$FAKE_EASY_NODE\" profile-default-gate-live --reports-dir /tmp/fake_profile_reports --key INVITE_KEY","reason":"test-precondition-placeholder-key-override"}
  ]
}
JSON
    ;;
  profile_evidence_pack_placeholder_easy_node)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate_evidence_pack","label":"Profile default evidence-pack publish","command":"bash \"$FAKE_EASY_NODE\" profile-default-gate-stability-cycle --host-a HOST_A --host-b HOST_B --campaign-subject INVITE_KEY --reports-dir /tmp/fake_profile_reports --summary-json /tmp/fake_profile_summary.json --print-summary-json 1","reason":"test-profile-pack-placeholder-override"}
  ]
}
JSON
    ;;
  profile_existing_key_easy_node)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate","label":"Profile default decision gate","command":"bash \"$FAKE_EASY_NODE\" profile-default-gate-live --reports-dir /tmp/fake_profile_reports --key inv-existing-key","reason":"test-precondition-existing-key"}
  ]
}
JSON
    ;;
  profile_localhost_run_easy_node)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate","label":"Profile default decision gate","command":"bash \"$FAKE_EASY_NODE\" profile-default-gate-run --directory-a http://127.0.0.1:18081 --directory-b http://127.0.0.1:28081 --reports-dir /tmp/fake_profile_reports --campaign-timeout-sec 180 --summary-json /tmp/fake_profile_summary.json --print-summary-json 1 --subject INVITE_KEY","reason":"test-localhost-live-conversion"}
  ]
}
JSON
    ;;
  profile_localhost_run_easy_node_quoted)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate","label":"Profile default decision gate","command":"bash \"$FAKE_EASY_NODE\" profile-default-gate-run --directory-a 'http://127.0.0.1:18081' --directory-b \"http://127.0.0.1:28081\" --reports-dir '/tmp/fake profile reports' --campaign-timeout-sec 180 --summary-json \"/tmp/fake profile summary.json\" --print-summary-json 1 --subject 'inv quoted subject'","reason":"test-localhost-live-conversion-quoted"}
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
if ! bash ./scripts/roadmap_next_actions_run.sh --help | grep -F -- "--include-id ID" >/dev/null; then
  echo "help output missing --include-id ID"
  exit 1
fi
if ! bash ./scripts/roadmap_next_actions_run.sh --help | grep -F -- "--exclude-id ID" >/dev/null; then
  echo "help output missing --exclude-id ID"
  exit 1
fi
if ! bash ./scripts/roadmap_next_actions_run.sh --help | grep -F -- "--exclude-id-prefix PREFIX" >/dev/null; then
  echo "help output missing --exclude-id-prefix PREFIX"
  exit 1
fi
if ! bash ./scripts/roadmap_next_actions_run.sh --help | grep -F -- "--include-id-suffix SUFFIX" >/dev/null; then
  echo "help output missing --include-id-suffix SUFFIX"
  exit 1
fi
if ! bash ./scripts/roadmap_next_actions_run.sh --help | grep -F -- "--exclude-id-suffix SUFFIX" >/dev/null; then
  echo "help output missing --exclude-id-suffix SUFFIX"
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

echo "[roadmap-next-actions-run] dedupes duplicate next_actions entries (exact + id+command) and executes once"
SUMMARY_DEDUPE="$TMP_DIR/summary_dedupe.json"
REPORTS_DEDUPE="$TMP_DIR/reports_dedupe"
rm -f "$DEDUP_MARK_COUNT_FILE"
ROADMAP_NEXT_ACTIONS_SCENARIO=duplicate_actions \
PASS1="$PASS1" PASS2="$PASS2" DEDUPE_MARK="$DEDUPE_MARK" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
NEXT_ACTION_DEDUPE_COUNT_FILE="$DEDUP_MARK_COUNT_FILE" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_DEDUPE" \
  --summary-json "$SUMMARY_DEDUPE" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["dedupe_once"]
  and .roadmap.selection_accounting.non_empty_command_count == 3
  and .roadmap.selection_accounting.before_dedupe_count == 3
  and .roadmap.selection_accounting.deduped_actions_count == 2
  and .roadmap.selection_accounting.deduped_exact_duplicate_count == 1
  and .roadmap.selection_accounting.deduped_id_command_duplicate_count == 1
  and .roadmap.selection_accounting.after_dedupe_count == 1
  and .roadmap.selection_accounting.after_batch_deconflict_count == 1
  and .roadmap.selection_accounting.after_max_actions_count == 1
  and .summary.actions_executed == 1
  and .summary.pass == 1
  and .summary.fail == 0
  and ((.actions // []) | length == 1)
  and .actions[0].id == "dedupe_once"
  and .actions[0].status == "pass"
' "$SUMMARY_DEDUPE" >/dev/null; then
  echo "duplicate-actions dedupe summary mismatch"
  cat "$SUMMARY_DEDUPE"
  exit 1
fi

dedupe_run_count=0
if [[ -f "$DEDUP_MARK_COUNT_FILE" ]]; then
  dedupe_run_count="$(wc -l <"$DEDUP_MARK_COUNT_FILE" | tr -d '[:space:]')"
fi
if [[ "$dedupe_run_count" != "1" ]]; then
  echo "duplicate-actions dedupe execution mismatch: expected 1 run, got $dedupe_run_count"
  cat "$SUMMARY_DEDUPE"
  if [[ -f "$DEDUP_MARK_COUNT_FILE" ]]; then
    cat "$DEDUP_MARK_COUNT_FILE"
  fi
  exit 1
fi

echo "[roadmap-next-actions-run] fail-closed on duplicate id with conflicting commands"
SUMMARY_DUP_CONFLICT="$TMP_DIR/summary_dup_conflict.json"
REPORTS_DUP_CONFLICT="$TMP_DIR/reports_dup_conflict"
DUP_CONFLICT_OUTPUT="$TMP_DIR/dup_conflict_output.log"
rm -f "$CONFLICT_MARK_A" "$CONFLICT_MARK_B"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=duplicate_id_conflicting_commands \
PASS1="$PASS1" PASS2="$PASS2" DEDUPE_MARK="$DEDUPE_MARK" CONFLICT_CMD_A="$CONFLICT_CMD_A" CONFLICT_CMD_B="$CONFLICT_CMD_B" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
NEXT_ACTION_CONFLICT_MARK_A="$CONFLICT_MARK_A" NEXT_ACTION_CONFLICT_MARK_B="$CONFLICT_MARK_B" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_DUP_CONFLICT" \
  --summary-json "$SUMMARY_DUP_CONFLICT" \
  --print-summary-json 0 >"$DUP_CONFLICT_OUTPUT" 2>&1
dup_conflict_rc=$?
set -e
if [[ "$dup_conflict_rc" != "3" ]]; then
  echo "expected duplicate conflicting id fail-closed rc=3, got rc=$dup_conflict_rc"
  cat "$DUP_CONFLICT_OUTPUT"
  if [[ -f "$SUMMARY_DUP_CONFLICT" ]]; then
    cat "$SUMMARY_DUP_CONFLICT"
  fi
  exit 1
fi
if [[ -f "$CONFLICT_MARK_A" || -f "$CONFLICT_MARK_B" ]]; then
  echo "duplicate conflicting-id commands unexpectedly executed"
  cat "$DUP_CONFLICT_OUTPUT"
  exit 1
fi
if ! grep -F -- "fail-closed duplicate action ids with conflicting commands: dup_conflict" "$DUP_CONFLICT_OUTPUT" >/dev/null 2>&1; then
  echo "duplicate conflicting-id fail-closed message missing"
  cat "$DUP_CONFLICT_OUTPUT"
  exit 1
fi

echo "[roadmap-next-actions-run] multi-VM stability action path"
SUMMARY_MULTI_VM_STABILITY="$TMP_DIR/summary_multi_vm_stability.json"
REPORTS_MULTI_VM_STABILITY="$TMP_DIR/reports_multi_vm_stability"
ROADMAP_NEXT_ACTIONS_SCENARIO=multi_vm_stability_action \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_MULTI_VM_STABILITY" \
  --summary-json "$SUMMARY_MULTI_VM_STABILITY" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.generated_this_run == true
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["profile_compare_multi_vm_stability"]
  and .summary.actions_executed == 1
  and .summary.pass == 1
  and .summary.fail == 0
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_compare_multi_vm_stability"
  and .actions[0].status == "pass"
' "$SUMMARY_MULTI_VM_STABILITY" >/dev/null; then
  echo "multi-VM stability action summary mismatch"
  cat "$SUMMARY_MULTI_VM_STABILITY"
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

echo "[roadmap-next-actions-run] deconflicts evidence-pack batch helper when individual evidence-pack actions are selected"
SUMMARY_EVIDENCE_HELPER_CONFLICT="$TMP_DIR/summary_evidence_helper_conflict.json"
REPORTS_EVIDENCE_HELPER_CONFLICT="$TMP_DIR/reports_evidence_helper_conflict"
ROADMAP_NEXT_ACTIONS_SCENARIO=evidence_pack_helper_conflict \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_EVIDENCE_HELPER_CONFLICT" \
  --summary-json "$SUMMARY_EVIDENCE_HELPER_CONFLICT" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["profile_default_gate_evidence_pack"]
  and .roadmap.selection_accounting.after_batch_deconflict_count == 1
  and .summary.actions_executed == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate_evidence_pack"
  and .actions[0].status == "pass"
' "$SUMMARY_EVIDENCE_HELPER_CONFLICT" >/dev/null; then
  echo "evidence-pack helper deconflict summary mismatch"
  cat "$SUMMARY_EVIDENCE_HELPER_CONFLICT"
  exit 1
fi

echo "[roadmap-next-actions-run] deconflicts live-evidence batch helper when individual live-evidence actions are selected"
SUMMARY_LIVE_HELPER_CONFLICT="$TMP_DIR/summary_live_helper_conflict.json"
REPORTS_LIVE_HELPER_CONFLICT="$TMP_DIR/reports_live_helper_conflict"
ROADMAP_NEXT_ACTIONS_SCENARIO=live_evidence_helper_conflict \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_LIVE_HELPER_CONFLICT" \
  --summary-json "$SUMMARY_LIVE_HELPER_CONFLICT" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["profile_default_gate"]
  and .roadmap.selection_accounting.after_batch_deconflict_count == 1
  and .summary.actions_executed == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate"
  and .actions[0].status == "pass"
' "$SUMMARY_LIVE_HELPER_CONFLICT" >/dev/null; then
  echo "live-evidence helper deconflict summary mismatch"
  cat "$SUMMARY_LIVE_HELPER_CONFLICT"
  exit 1
fi

echo "[roadmap-next-actions-run] deconflicts combined live-and-pack helper against overlapping live/evidence actions"
SUMMARY_LIVE_AND_PACK_HELPER_CONFLICT="$TMP_DIR/summary_live_and_pack_helper_conflict.json"
REPORTS_LIVE_AND_PACK_HELPER_CONFLICT="$TMP_DIR/reports_live_and_pack_helper_conflict"
ROADMAP_NEXT_ACTIONS_SCENARIO=live_and_pack_helper_conflict \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_LIVE_AND_PACK_HELPER_CONFLICT" \
  --summary-json "$SUMMARY_LIVE_AND_PACK_HELPER_CONFLICT" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["roadmap_live_and_pack_actionable_run"]
  and .roadmap.selection_accounting.after_batch_deconflict_count == 1
  and .summary.actions_executed == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "roadmap_live_and_pack_actionable_run"
  and .actions[0].status == "pass"
' "$SUMMARY_LIVE_AND_PACK_HELPER_CONFLICT" >/dev/null; then
  echo "live-and-pack helper deconflict summary mismatch"
  cat "$SUMMARY_LIVE_AND_PACK_HELPER_CONFLICT"
  exit 1
fi

echo "[roadmap-next-actions-run] deconflicts combined live-and-pack helper against cycle-batch helper and overlapping live/pack actions"
SUMMARY_LIVE_AND_PACK_WITH_CYCLE_BATCH_HELPER_CONFLICT="$TMP_DIR/summary_live_and_pack_with_cycle_batch_helper_conflict.json"
REPORTS_LIVE_AND_PACK_WITH_CYCLE_BATCH_HELPER_CONFLICT="$TMP_DIR/reports_live_and_pack_with_cycle_batch_helper_conflict"
ROADMAP_NEXT_ACTIONS_SCENARIO=live_and_pack_with_cycle_batch_helper_conflict \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_LIVE_AND_PACK_WITH_CYCLE_BATCH_HELPER_CONFLICT" \
  --summary-json "$SUMMARY_LIVE_AND_PACK_WITH_CYCLE_BATCH_HELPER_CONFLICT" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["roadmap_live_and_pack_actionable_run"]
  and .roadmap.selection_accounting.after_batch_deconflict_count == 1
  and .summary.actions_executed == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "roadmap_live_and_pack_actionable_run"
  and .actions[0].status == "pass"
' "$SUMMARY_LIVE_AND_PACK_WITH_CYCLE_BATCH_HELPER_CONFLICT" >/dev/null; then
  echo "live-and-pack + cycle-batch helper deconflict summary mismatch"
  cat "$SUMMARY_LIVE_AND_PACK_WITH_CYCLE_BATCH_HELPER_CONFLICT"
  exit 1
fi

echo "[roadmap-next-actions-run] deconflicts live-evidence cycle-batch helper against overlapping cycle actions and live helper"
SUMMARY_LIVE_CYCLE_BATCH_HELPER_CONFLICT="$TMP_DIR/summary_live_cycle_batch_helper_conflict.json"
REPORTS_LIVE_CYCLE_BATCH_HELPER_CONFLICT="$TMP_DIR/reports_live_cycle_batch_helper_conflict"
ROADMAP_NEXT_ACTIONS_SCENARIO=live_evidence_cycle_batch_helper_conflict \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_LIVE_CYCLE_BATCH_HELPER_CONFLICT" \
  --summary-json "$SUMMARY_LIVE_CYCLE_BATCH_HELPER_CONFLICT" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["roadmap_live_evidence_cycle_batch_run"]
  and .roadmap.selection_accounting.after_batch_deconflict_count == 1
  and .summary.actions_executed == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "roadmap_live_evidence_cycle_batch_run"
  and .actions[0].status == "pass"
' "$SUMMARY_LIVE_CYCLE_BATCH_HELPER_CONFLICT" >/dev/null; then
  echo "live-evidence cycle-batch helper deconflict summary mismatch"
  cat "$SUMMARY_LIVE_CYCLE_BATCH_HELPER_CONFLICT"
  exit 1
fi

echo "[roadmap-next-actions-run] executes per-track live-evidence publish bundle action ids"
SUMMARY_LIVE_EVIDENCE_PUBLISH_BUNDLE_ACTIONS="$TMP_DIR/summary_live_evidence_publish_bundle_actions.json"
REPORTS_LIVE_EVIDENCE_PUBLISH_BUNDLE_ACTIONS="$TMP_DIR/reports_live_evidence_publish_bundle_actions"
ROADMAP_NEXT_ACTIONS_SCENARIO=live_evidence_publish_bundle_actions \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_LIVE_EVIDENCE_PUBLISH_BUNDLE_ACTIONS" \
  --summary-json "$SUMMARY_LIVE_EVIDENCE_PUBLISH_BUNDLE_ACTIONS" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.actions_selected_count == 3
  and .roadmap.selected_action_ids == [
    "profile_default_gate_live_evidence_publish_bundle",
    "runtime_actuation_live_evidence_publish_bundle",
    "profile_compare_multi_vm_live_evidence_publish_bundle"
  ]
  and .summary.actions_executed == 3
  and .summary.pass == 3
  and .summary.fail == 0
  and ((.actions // []) | length == 3)
  and ((.actions // []) | all(.status == "pass"))
' "$SUMMARY_LIVE_EVIDENCE_PUBLISH_BUNDLE_ACTIONS" >/dev/null; then
  echo "live-evidence publish bundle actions summary mismatch"
  cat "$SUMMARY_LIVE_EVIDENCE_PUBLISH_BUNDLE_ACTIONS"
  exit 1
fi

echo "[roadmap-next-actions-run] deterministic overlap filtering selects runtime bundle without redundant cycle/evidence actions"
SUMMARY_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_FILTER="$TMP_DIR/summary_live_evidence_publish_bundle_runtime_filter.json"
REPORTS_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_FILTER="$TMP_DIR/reports_live_evidence_publish_bundle_runtime_filter"
ROADMAP_NEXT_ACTIONS_SCENARIO=live_evidence_publish_bundle_runtime_overlap \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_FILTER" \
  --summary-json "$SUMMARY_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_FILTER" \
  --include-id runtime_actuation_live_evidence_publish_bundle \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.include_ids == ["runtime_actuation_live_evidence_publish_bundle"]
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["runtime_actuation_live_evidence_publish_bundle"]
  and .summary.actions_executed == 1
  and .summary.pass == 1
  and .summary.fail == 0
  and ((.actions // []) | length == 1)
  and .actions[0].id == "runtime_actuation_live_evidence_publish_bundle"
  and .actions[0].status == "pass"
' "$SUMMARY_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_FILTER" >/dev/null; then
  echo "runtime bundle deterministic overlap filtering summary mismatch"
  cat "$SUMMARY_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_FILTER"
  exit 1
fi

echo "[roadmap-next-actions-run] unresolved bundle placeholder subject fails closed before command execution"
SUMMARY_LIVE_EVIDENCE_PUBLISH_BUNDLE_PROFILE_PLACEHOLDER="$TMP_DIR/summary_live_evidence_publish_bundle_profile_placeholder.json"
REPORTS_LIVE_EVIDENCE_PUBLISH_BUNDLE_PROFILE_PLACEHOLDER="$TMP_DIR/reports_live_evidence_publish_bundle_profile_placeholder"
: >"$FAKE_EASY_NODE_CAPTURE"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=live_evidence_publish_bundle_profile_placeholder_subject \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" FAKE_EASY_NODE="$FAKE_EASY_NODE" FAKE_EASY_NODE_CAPTURE="$FAKE_EASY_NODE_CAPTURE" CAMPAIGN_SUBJECT="" INVITE_KEY="" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_LIVE_EVIDENCE_PUBLISH_BUNDLE_PROFILE_PLACEHOLDER" \
  --summary-json "$SUMMARY_LIVE_EVIDENCE_PUBLISH_BUNDLE_PROFILE_PLACEHOLDER" \
  --print-summary-json 0
live_evidence_publish_bundle_profile_placeholder_rc=$?
set -e
if [[ "$live_evidence_publish_bundle_profile_placeholder_rc" != "2" ]]; then
  echo "expected unresolved bundle placeholder hard-fail rc=2, got rc=$live_evidence_publish_bundle_profile_placeholder_rc"
  cat "$SUMMARY_LIVE_EVIDENCE_PUBLISH_BUNDLE_PROFILE_PLACEHOLDER"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 2
  and .summary.actions_executed == 1
  and .summary.pass == 0
  and .summary.fail == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate_live_evidence_publish_bundle"
  and .actions[0].status == "fail"
  and .actions[0].rc == 2
  and .actions[0].command_rc == 2
  and .actions[0].failure_kind == "missing_invite_subject_precondition"
  and ((.actions[0].next_operator_action // "") | contains("--profile-default-gate-subject REPLACE_WITH_INVITE_SUBJECT"))
' "$SUMMARY_LIVE_EVIDENCE_PUBLISH_BUNDLE_PROFILE_PLACEHOLDER" >/dev/null; then
  echo "unresolved bundle placeholder hard-fail summary mismatch"
  cat "$SUMMARY_LIVE_EVIDENCE_PUBLISH_BUNDLE_PROFILE_PLACEHOLDER"
  exit 1
fi
if [[ -s "$FAKE_EASY_NODE_CAPTURE" ]]; then
  echo "unresolved bundle placeholder should fail before fake easy_node execution"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi

echo "[roadmap-next-actions-run] runtime bundle unsafe shell requirement fails closed in safe mode"
SUMMARY_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_UNSAFE="$TMP_DIR/summary_live_evidence_publish_bundle_runtime_unsafe.json"
REPORTS_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_UNSAFE="$TMP_DIR/reports_live_evidence_publish_bundle_runtime_unsafe"
UNSAFE_BUNDLE_PAYLOAD_SCRIPT="$TMP_DIR/runtime_bundle_unsafe_payload.sh"
UNSAFE_BUNDLE_MARKER="$TMP_DIR/runtime_bundle_unsafe_marker.txt"
cat >"$UNSAFE_BUNDLE_PAYLOAD_SCRIPT" <<EOF_UNSAFE_BUNDLE
#!/usr/bin/env bash
set -euo pipefail
echo "runtime-bundle-unsafe-executed" >"$UNSAFE_BUNDLE_MARKER"
EOF_UNSAFE_BUNDLE
chmod +x "$UNSAFE_BUNDLE_PAYLOAD_SCRIPT"
rm -f "$UNSAFE_BUNDLE_MARKER"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=live_evidence_publish_bundle_runtime_unsafe_shell \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" UNSAFE_BUNDLE_PAYLOAD="$UNSAFE_BUNDLE_PAYLOAD_SCRIPT" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_UNSAFE" \
  --summary-json "$SUMMARY_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_UNSAFE" \
  --print-summary-json 0
live_evidence_publish_bundle_runtime_unsafe_rc=$?
set -e
if [[ "$live_evidence_publish_bundle_runtime_unsafe_rc" != "5" ]]; then
  echo "expected runtime bundle unsafe-shell rejection rc=5, got rc=$live_evidence_publish_bundle_runtime_unsafe_rc"
  cat "$SUMMARY_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_UNSAFE"
  exit 1
fi
if [[ -f "$UNSAFE_BUNDLE_MARKER" ]]; then
  echo "runtime bundle unsafe-shell payload unexpectedly executed in safe mode"
  cat "$SUMMARY_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_UNSAFE"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 5
  and .summary.actions_executed == 1
  and .summary.pass == 0
  and .summary.fail == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "runtime_actuation_live_evidence_publish_bundle"
  and .actions[0].status == "fail"
  and .actions[0].rc == 5
  and .actions[0].command_rc == 5
  and .actions[0].failure_kind == "command_failed"
' "$SUMMARY_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_UNSAFE" >/dev/null; then
  echo "runtime bundle unsafe-shell rejection summary mismatch"
  cat "$SUMMARY_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_UNSAFE"
  exit 1
fi
runtime_bundle_unsafe_log="$(jq -r '.actions[0].artifacts.log // ""' "$SUMMARY_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_UNSAFE")"
if [[ -z "$runtime_bundle_unsafe_log" || ! -f "$runtime_bundle_unsafe_log" ]]; then
  echo "missing runtime bundle unsafe-shell action log artifact"
  cat "$SUMMARY_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_UNSAFE"
  exit 1
fi
if ! grep -F -- "refusing env-prefixed action command" "$runtime_bundle_unsafe_log" >/dev/null; then
  echo "runtime bundle unsafe-shell action log missing safe-mode rejection marker"
  cat "$runtime_bundle_unsafe_log"
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

echo "[roadmap-next-actions-run] include/exclude exact id filtering path via repeatable args"
SUMMARY_FILTER_ID_ARGS="$TMP_DIR/summary_filter_id_args.json"
REPORTS_FILTER_ID_ARGS="$TMP_DIR/reports_filter_id_args"
ROADMAP_NEXT_ACTIONS_SCENARIO=filter_mix \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_FILTER_ID_ARGS" \
  --summary-json "$SUMMARY_FILTER_ID_ARGS" \
  --include-id keep_a_1 \
  --include-id keep_a_2 \
  --exclude-id keep_a_1 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.include_ids == ["keep_a_1","keep_a_2"]
  and .inputs.exclude_ids == ["keep_a_1"]
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["keep_a_2"]
  and .summary.actions_executed == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "keep_a_2"
  and .actions[0].status == "pass"
' "$SUMMARY_FILTER_ID_ARGS" >/dev/null; then
  echo "include/exclude exact id repeatable-args summary mismatch"
  cat "$SUMMARY_FILTER_ID_ARGS"
  exit 1
fi

echo "[roadmap-next-actions-run] include/exclude exact id filtering path via comma-separated env"
SUMMARY_FILTER_ID_ENV="$TMP_DIR/summary_filter_id_env.json"
REPORTS_FILTER_ID_ENV="$TMP_DIR/reports_filter_id_env"
ROADMAP_NEXT_ACTIONS_SCENARIO=filter_mix \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_INCLUDE_IDS="keep_a_1,drop_b_1" \
ROADMAP_NEXT_ACTIONS_RUN_EXCLUDE_IDS="drop_b_1" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_FILTER_ID_ENV" \
  --summary-json "$SUMMARY_FILTER_ID_ENV" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.include_ids == ["keep_a_1","drop_b_1"]
  and .inputs.exclude_ids == ["drop_b_1"]
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["keep_a_1"]
  and .summary.actions_executed == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "keep_a_1"
  and .actions[0].status == "pass"
' "$SUMMARY_FILTER_ID_ENV" >/dev/null; then
  echo "include/exclude exact id env summary mismatch"
  cat "$SUMMARY_FILTER_ID_ENV"
  exit 1
fi

echo "[roadmap-next-actions-run] exact id + suffix interaction path"
SUMMARY_FILTER_ID_SUFFIX_INTERACTION="$TMP_DIR/summary_filter_id_suffix_interaction.json"
REPORTS_FILTER_ID_SUFFIX_INTERACTION="$TMP_DIR/reports_filter_id_suffix_interaction"
ROADMAP_NEXT_ACTIONS_SCENARIO=filter_mix \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_FILTER_ID_SUFFIX_INTERACTION" \
  --summary-json "$SUMMARY_FILTER_ID_SUFFIX_INTERACTION" \
  --include-id-prefix keep_ \
  --include-id keep_a_1 \
  --include-id keep_a_2 \
  --exclude-id keep_a_1 \
  --include-id-suffix _2 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.include_id_prefix == "keep_"
  and .inputs.include_ids == ["keep_a_1","keep_a_2"]
  and .inputs.exclude_ids == ["keep_a_1"]
  and .inputs.include_id_suffixes == ["_2"]
  and .roadmap.selection_accounting.non_empty_command_count == 3
  and .roadmap.selection_accounting.after_prefix_filters_count == 2
  and .roadmap.selection_accounting.after_include_id_filters_count == 2
  and .roadmap.selection_accounting.after_exclude_id_filters_count == 1
  and .roadmap.selection_accounting.after_include_suffix_filters_count == 1
  and .roadmap.selection_accounting.after_exclude_suffix_filters_count == 1
  and .roadmap.selection_accounting.after_max_actions_count == 1
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["keep_a_2"]
  and .summary.actions_executed == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "keep_a_2"
  and .actions[0].status == "pass"
' "$SUMMARY_FILTER_ID_SUFFIX_INTERACTION" >/dev/null; then
  echo "exact-id + suffix interaction summary mismatch"
  cat "$SUMMARY_FILTER_ID_SUFFIX_INTERACTION"
  exit 1
fi

echo "[roadmap-next-actions-run] include/exclude id-suffix filtering path via repeatable args"
SUMMARY_FILTER_SUFFIX_ARGS="$TMP_DIR/summary_filter_suffix_args.json"
REPORTS_FILTER_SUFFIX_ARGS="$TMP_DIR/reports_filter_suffix_args"
ROADMAP_NEXT_ACTIONS_SCENARIO=filter_mix \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_FILTER_SUFFIX_ARGS" \
  --summary-json "$SUMMARY_FILTER_SUFFIX_ARGS" \
  --include-id-suffix _1 \
  --include-id-suffix _2 \
  --exclude-id-suffix _1 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.include_id_suffixes == ["_1","_2"]
  and .inputs.exclude_id_suffixes == ["_1"]
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["keep_a_2"]
  and .summary.actions_executed == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "keep_a_2"
  and .actions[0].status == "pass"
' "$SUMMARY_FILTER_SUFFIX_ARGS" >/dev/null; then
  echo "include/exclude id-suffix repeatable-args summary mismatch"
  cat "$SUMMARY_FILTER_SUFFIX_ARGS"
  exit 1
fi

echo "[roadmap-next-actions-run] include/exclude id-suffix filtering path via comma-separated env"
SUMMARY_FILTER_SUFFIX_ENV="$TMP_DIR/summary_filter_suffix_env.json"
REPORTS_FILTER_SUFFIX_ENV="$TMP_DIR/reports_filter_suffix_env"
ROADMAP_NEXT_ACTIONS_SCENARIO=filter_mix \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_INCLUDE_ID_SUFFIXES="_1,_2" \
ROADMAP_NEXT_ACTIONS_RUN_EXCLUDE_ID_SUFFIXES="_2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_FILTER_SUFFIX_ENV" \
  --summary-json "$SUMMARY_FILTER_SUFFIX_ENV" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.include_id_suffixes == ["_1","_2"]
  and .inputs.exclude_id_suffixes == ["_2"]
  and .roadmap.actions_selected_count == 2
  and .roadmap.selected_action_ids == ["keep_a_1","drop_b_1"]
  and .summary.actions_executed == 2
  and ((.actions // []) | length == 2)
  and .actions[0].id == "keep_a_1"
  and .actions[0].status == "pass"
  and .actions[1].id == "drop_b_1"
  and .actions[1].status == "pass"
' "$SUMMARY_FILTER_SUFFIX_ENV" >/dev/null; then
  echo "include/exclude id-suffix env summary mismatch"
  cat "$SUMMARY_FILTER_SUFFIX_ENV"
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
  and .inputs.profile_default_gate_default_timeout_sec == 2400
  and .inputs.profile_default_gate_subject == "[redacted]"
  and .inputs.profile_default_gate_subject_configured == true
  and .summary.actions_executed == 1
  and .summary.pass == 1
  and .summary.fail == 0
  and .summary.soft_failed == 0
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate"
  and ((.actions[0].command // "") | contains("fake_easy_node"))
  and .actions[0].status == "pass"
  and .actions[0].timeout_sec == 2400
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

echo "[roadmap-next-actions-run] profile subject override replaces INVITE_KEY placeholder subject"
SUMMARY_PROFILE_PLACEHOLDER_OVERRIDE="$TMP_DIR/summary_profile_placeholder_override.json"
REPORTS_PROFILE_PLACEHOLDER_OVERRIDE="$TMP_DIR/reports_profile_placeholder_override"
: >"$FAKE_EASY_NODE_CAPTURE"
ROADMAP_NEXT_ACTIONS_SCENARIO=profile_placeholder_subject_easy_node \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" MISSING_SUBJECT_PROFILE="$MISSING_SUBJECT_PROFILE" FAKE_EASY_NODE="$FAKE_EASY_NODE" FAKE_EASY_NODE_CAPTURE="$FAKE_EASY_NODE_CAPTURE" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_PROFILE_PLACEHOLDER_OVERRIDE" \
  --summary-json "$SUMMARY_PROFILE_PLACEHOLDER_OVERRIDE" \
  --profile-default-gate-subject inv-placeholder-replaced \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.profile_default_gate_subject == "[redacted]"
  and .inputs.profile_default_gate_subject_configured == true
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate"
  and .actions[0].status == "pass"
  and ((.actions[0].command // "") | contains("--subject [redacted]"))
  and (((.actions[0].command // "") | contains("INVITE_KEY")) | not)
  and (((.actions[0].command // "") | contains("--campaign-subject")) | not)
' "$SUMMARY_PROFILE_PLACEHOLDER_OVERRIDE" >/dev/null; then
  echo "profile placeholder override summary mismatch"
  cat "$SUMMARY_PROFILE_PLACEHOLDER_OVERRIDE"
  exit 1
fi
if ! grep -E -- '--subject[[:space:]]+inv-placeholder-replaced([[:space:]]|$)' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "profile placeholder override command capture missing replaced --subject"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi
if grep -E -- 'INVITE_KEY' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "profile placeholder override command capture still contains INVITE_KEY"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi

echo "[roadmap-next-actions-run] profile subject override replaces INVITE_KEY placeholder key"
SUMMARY_PROFILE_PLACEHOLDER_KEY_OVERRIDE="$TMP_DIR/summary_profile_placeholder_key_override.json"
REPORTS_PROFILE_PLACEHOLDER_KEY_OVERRIDE="$TMP_DIR/reports_profile_placeholder_key_override"
: >"$FAKE_EASY_NODE_CAPTURE"
ROADMAP_NEXT_ACTIONS_SCENARIO=profile_placeholder_key_easy_node \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" MISSING_SUBJECT_PROFILE="$MISSING_SUBJECT_PROFILE" FAKE_EASY_NODE="$FAKE_EASY_NODE" FAKE_EASY_NODE_CAPTURE="$FAKE_EASY_NODE_CAPTURE" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_PROFILE_PLACEHOLDER_KEY_OVERRIDE" \
  --summary-json "$SUMMARY_PROFILE_PLACEHOLDER_KEY_OVERRIDE" \
  --profile-default-gate-subject inv-key-placeholder-replaced \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.profile_default_gate_subject == "[redacted]"
  and .inputs.profile_default_gate_subject_configured == true
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate"
  and .actions[0].status == "pass"
  and ((.actions[0].command // "") | contains("--key [redacted]"))
  and (((.actions[0].command // "") | contains("INVITE_KEY")) | not)
  and (((.actions[0].command // "") | contains("--campaign-subject")) | not)
' "$SUMMARY_PROFILE_PLACEHOLDER_KEY_OVERRIDE" >/dev/null; then
  echo "profile placeholder key override summary mismatch"
  cat "$SUMMARY_PROFILE_PLACEHOLDER_KEY_OVERRIDE"
  exit 1
fi
if ! grep -E -- '--key[[:space:]]+inv-key-placeholder-replaced([[:space:]]|$)' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "profile placeholder key override command capture missing replaced --key"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi
if grep -E -- '--campaign-subject' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "profile placeholder key override command capture should not append --campaign-subject"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi
if grep -E -- 'INVITE_KEY' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "profile placeholder key override command capture still contains INVITE_KEY"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi

echo "[roadmap-next-actions-run] profile evidence-pack placeholders resolve host and subject from env/override"
SUMMARY_PROFILE_EVIDENCE_PACK_PLACEHOLDER="$TMP_DIR/summary_profile_evidence_pack_placeholder.json"
REPORTS_PROFILE_EVIDENCE_PACK_PLACEHOLDER="$TMP_DIR/reports_profile_evidence_pack_placeholder"
: >"$FAKE_EASY_NODE_CAPTURE"
ROADMAP_NEXT_ACTIONS_SCENARIO=profile_evidence_pack_placeholder_easy_node \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" MISSING_SUBJECT_PROFILE="$MISSING_SUBJECT_PROFILE" FAKE_EASY_NODE="$FAKE_EASY_NODE" FAKE_EASY_NODE_CAPTURE="$FAKE_EASY_NODE_CAPTURE" A_HOST="100.64.0.10" B_HOST="100.64.0.20" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_PROFILE_EVIDENCE_PACK_PLACEHOLDER" \
  --summary-json "$SUMMARY_PROFILE_EVIDENCE_PACK_PLACEHOLDER" \
  --profile-default-gate-subject inv-pack-placeholder-replaced \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate_evidence_pack"
  and .actions[0].status == "pass"
  and ((.actions[0].command // "") | contains("--host-a 100.64.0.10"))
  and ((.actions[0].command // "") | contains("--host-b 100.64.0.20"))
  and ((.actions[0].command // "") | contains("--campaign-subject [redacted]"))
  and (((.actions[0].command // "") | contains("HOST_A")) | not)
  and (((.actions[0].command // "") | contains("HOST_B")) | not)
  and (((.actions[0].command // "") | contains("INVITE_KEY")) | not)
' "$SUMMARY_PROFILE_EVIDENCE_PACK_PLACEHOLDER" >/dev/null; then
  echo "profile evidence-pack placeholder summary mismatch"
  cat "$SUMMARY_PROFILE_EVIDENCE_PACK_PLACEHOLDER"
  exit 1
fi
if ! grep -E -- '--host-a[[:space:]]+100\.64\.0\.10([[:space:]]|$)' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "profile evidence-pack placeholder command capture missing replaced --host-a"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi
if ! grep -E -- '--host-b[[:space:]]+100\.64\.0\.20([[:space:]]|$)' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "profile evidence-pack placeholder command capture missing replaced --host-b"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi
if ! grep -E -- '--campaign-subject[[:space:]]+inv-pack-placeholder-replaced([[:space:]]|$)' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "profile evidence-pack placeholder command capture missing replaced subject"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi
if grep -E -- 'HOST_A|HOST_B|INVITE_KEY' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "profile evidence-pack placeholder command capture still contains placeholders"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi

echo "[roadmap-next-actions-run] profile placeholder subject resolves via CAMPAIGN_SUBJECT fallback when CLI override is unset"
SUMMARY_PROFILE_PLACEHOLDER_ENV_FALLBACK="$TMP_DIR/summary_profile_placeholder_env_fallback.json"
REPORTS_PROFILE_PLACEHOLDER_ENV_FALLBACK="$TMP_DIR/reports_profile_placeholder_env_fallback"
: >"$FAKE_EASY_NODE_CAPTURE"
ROADMAP_NEXT_ACTIONS_SCENARIO=profile_placeholder_subject_braced_easy_node \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" MISSING_SUBJECT_PROFILE="$MISSING_SUBJECT_PROFILE" FAKE_EASY_NODE="$FAKE_EASY_NODE" FAKE_EASY_NODE_CAPTURE="$FAKE_EASY_NODE_CAPTURE" CAMPAIGN_SUBJECT="inv-campaign-fallback-subject" INVITE_KEY="inv-secondary-fallback-subject" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_PROFILE_PLACEHOLDER_ENV_FALLBACK" \
  --summary-json "$SUMMARY_PROFILE_PLACEHOLDER_ENV_FALLBACK" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.campaign_subject == "[redacted]"
  and .inputs.campaign_subject_configured == true
  and .inputs.campaign_subject_source == "env:CAMPAIGN_SUBJECT"
  and .inputs.profile_default_gate_subject == "[redacted]"
  and .inputs.profile_default_gate_subject_configured == true
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate"
  and .actions[0].status == "pass"
  and ((.actions[0].command // "") | contains("--subject [redacted]"))
  and (((.actions[0].command // "") | contains("CAMPAIGN_SUBJECT")) | not)
  and (((.actions[0].command // "") | contains("INVITE_KEY")) | not)
' "$SUMMARY_PROFILE_PLACEHOLDER_ENV_FALLBACK" >/dev/null; then
  echo "profile placeholder env-fallback summary mismatch"
  cat "$SUMMARY_PROFILE_PLACEHOLDER_ENV_FALLBACK"
  exit 1
fi
if ! grep -E -- '--subject[[:space:]]+inv-campaign-fallback-subject([[:space:]]|$)' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "profile placeholder env-fallback command capture missing replaced --subject from CAMPAIGN_SUBJECT"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi
if grep -E -- 'CAMPAIGN_SUBJECT|INVITE_KEY' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "profile placeholder env-fallback command capture still contains placeholder tokens"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi

echo "[roadmap-next-actions-run] unresolved profile placeholder subject fails closed before command execution"
SUMMARY_PROFILE_PLACEHOLDER_UNRESOLVED="$TMP_DIR/summary_profile_placeholder_unresolved.json"
REPORTS_PROFILE_PLACEHOLDER_UNRESOLVED="$TMP_DIR/reports_profile_placeholder_unresolved"
: >"$FAKE_EASY_NODE_CAPTURE"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=profile_placeholder_subject_braced_easy_node \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" MISSING_SUBJECT_PROFILE="$MISSING_SUBJECT_PROFILE" FAKE_EASY_NODE="$FAKE_EASY_NODE" FAKE_EASY_NODE_CAPTURE="$FAKE_EASY_NODE_CAPTURE" CAMPAIGN_SUBJECT="" INVITE_KEY="" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_PROFILE_PLACEHOLDER_UNRESOLVED" \
  --summary-json "$SUMMARY_PROFILE_PLACEHOLDER_UNRESOLVED" \
  --print-summary-json 0
profile_placeholder_unresolved_rc=$?
set -e
if [[ "$profile_placeholder_unresolved_rc" != "2" ]]; then
  echo "expected unresolved profile placeholder hard-fail rc=2, got rc=$profile_placeholder_unresolved_rc"
  cat "$SUMMARY_PROFILE_PLACEHOLDER_UNRESOLVED"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 2
  and .summary.actions_executed == 1
  and .summary.pass == 0
  and .summary.fail == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate"
  and .actions[0].status == "fail"
  and .actions[0].rc == 2
  and .actions[0].command_rc == 2
  and .actions[0].failure_kind == "missing_invite_subject_precondition"
  and ((.actions[0].next_operator_action // "") | contains("--profile-default-gate-subject REPLACE_WITH_INVITE_SUBJECT"))
' --arg reports_dir "$REPORTS_PROFILE_PLACEHOLDER_UNRESOLVED" --arg summary_json "$SUMMARY_PROFILE_PLACEHOLDER_UNRESOLVED" "$SUMMARY_PROFILE_PLACEHOLDER_UNRESOLVED" >/dev/null; then
  echo "unresolved profile placeholder hard-fail summary mismatch"
  cat "$SUMMARY_PROFILE_PLACEHOLDER_UNRESOLVED"
  exit 1
fi
PROFILE_PLACEHOLDER_UNRESOLVED_ACTION_LOG="$(jq -r '.actions[0].artifacts.log // ""' "$SUMMARY_PROFILE_PLACEHOLDER_UNRESOLVED")"
if [[ -z "$PROFILE_PLACEHOLDER_UNRESOLVED_ACTION_LOG" || ! -f "$PROFILE_PLACEHOLDER_UNRESOLVED_ACTION_LOG" ]]; then
  echo "missing unresolved profile placeholder action log artifact"
  cat "$SUMMARY_PROFILE_PLACEHOLDER_UNRESOLVED"
  exit 1
fi
if ! grep -F -- "operator_next_action: ./scripts/roadmap_next_actions_run.sh" "$PROFILE_PLACEHOLDER_UNRESOLVED_ACTION_LOG" >/dev/null; then
  echo "missing exact rerun command operator_next_action in unresolved profile placeholder action log"
  cat "$PROFILE_PLACEHOLDER_UNRESOLVED_ACTION_LOG"
  exit 1
fi
if ! grep -F -- "--profile-default-gate-subject REPLACE_WITH_INVITE_SUBJECT" "$PROFILE_PLACEHOLDER_UNRESOLVED_ACTION_LOG" >/dev/null; then
  echo "missing profile-default-gate-subject rerun guidance in unresolved profile placeholder action log"
  cat "$PROFILE_PLACEHOLDER_UNRESOLVED_ACTION_LOG"
  exit 1
fi
if [[ -s "$FAKE_EASY_NODE_CAPTURE" ]]; then
  echo "unresolved profile placeholder should fail before fake easy_node execution"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi

echo "[roadmap-next-actions-run] profile key present is overridden by explicit subject runtime input"
SUMMARY_PROFILE_EXISTING_KEY_NO_DUP="$TMP_DIR/summary_profile_existing_key_no_dup.json"
REPORTS_PROFILE_EXISTING_KEY_NO_DUP="$TMP_DIR/reports_profile_existing_key_no_dup"
: >"$FAKE_EASY_NODE_CAPTURE"
ROADMAP_NEXT_ACTIONS_SCENARIO=profile_existing_key_easy_node \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" MISSING_SUBJECT_PROFILE="$MISSING_SUBJECT_PROFILE" FAKE_EASY_NODE="$FAKE_EASY_NODE" FAKE_EASY_NODE_CAPTURE="$FAKE_EASY_NODE_CAPTURE" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_PROFILE_EXISTING_KEY_NO_DUP" \
  --summary-json "$SUMMARY_PROFILE_EXISTING_KEY_NO_DUP" \
  --profile-default-gate-subject inv-should-not-append \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.profile_default_gate_subject == "[redacted]"
  and .inputs.profile_default_gate_subject_configured == true
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate"
  and .actions[0].status == "pass"
  and ((.actions[0].command // "") | contains("--key [redacted]"))
  and (((.actions[0].command // "") | contains("--campaign-subject")) | not)
' "$SUMMARY_PROFILE_EXISTING_KEY_NO_DUP" >/dev/null; then
  echo "profile existing key no-dup summary mismatch"
  cat "$SUMMARY_PROFILE_EXISTING_KEY_NO_DUP"
  exit 1
fi
if ! grep -E -- '--key[[:space:]]+inv-should-not-append([[:space:]]|$)' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "profile existing key override command capture missing explicit runtime --key value"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi
if grep -E -- '--campaign-subject' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "profile existing key no-dup command capture unexpectedly appended --campaign-subject"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi

echo "[roadmap-next-actions-run] profile localhost run converts to live wrapper when A_HOST/B_HOST are set"
SUMMARY_PROFILE_LOCALHOST_TO_LIVE="$TMP_DIR/summary_profile_localhost_to_live.json"
REPORTS_PROFILE_LOCALHOST_TO_LIVE="$TMP_DIR/reports_profile_localhost_to_live"
: >"$FAKE_EASY_NODE_CAPTURE"
A_HOST=100.113.245.61 B_HOST=100.64.244.24 \
ROADMAP_NEXT_ACTIONS_SCENARIO=profile_localhost_run_easy_node \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" MISSING_SUBJECT_PROFILE="$MISSING_SUBJECT_PROFILE" FAKE_EASY_NODE="$FAKE_EASY_NODE" FAKE_EASY_NODE_CAPTURE="$FAKE_EASY_NODE_CAPTURE" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_PROFILE_LOCALHOST_TO_LIVE" \
  --summary-json "$SUMMARY_PROFILE_LOCALHOST_TO_LIVE" \
  --profile-default-gate-subject inv-live-converted \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.profile_default_gate_subject == "[redacted]"
  and .inputs.profile_default_gate_subject_configured == true
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate"
  and .actions[0].status == "pass"
  and ((.actions[0].command // "") | contains("profile-default-gate-live"))
  and ((.actions[0].command // "") | contains("--host-a 100.113.245.61"))
  and ((.actions[0].command // "") | contains("--host-b 100.64.244.24"))
  and ((.actions[0].command // "") | contains("--subject [redacted]"))
  and (((.actions[0].command // "") | contains("127.0.0.1")) | not)
' "$SUMMARY_PROFILE_LOCALHOST_TO_LIVE" >/dev/null; then
  echo "profile localhost-to-live conversion summary mismatch"
  cat "$SUMMARY_PROFILE_LOCALHOST_TO_LIVE"
  exit 1
fi
if ! grep -E -- 'profile-default-gate-live' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "profile localhost-to-live conversion command capture missing live wrapper command"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi
if ! grep -E -- '--host-a[[:space:]]+100\.113\.245\.61([[:space:]]|$)' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "profile localhost-to-live conversion command capture missing --host-a"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi
if ! grep -E -- '--host-b[[:space:]]+100\.64\.244\.24([[:space:]]|$)' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "profile localhost-to-live conversion command capture missing --host-b"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi
if grep -E -- '127\.0\.0\.1' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "profile localhost-to-live conversion command capture still contains localhost endpoints"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi

echo "[roadmap-next-actions-run] profile localhost run quoted values round-trip through live-wrapper rewrite"
SUMMARY_PROFILE_LOCALHOST_TO_LIVE_QUOTED="$TMP_DIR/summary_profile_localhost_to_live_quoted.json"
REPORTS_PROFILE_LOCALHOST_TO_LIVE_QUOTED="$TMP_DIR/reports_profile_localhost_to_live_quoted"
: >"$FAKE_EASY_NODE_CAPTURE"
A_HOST=100.113.245.61 B_HOST=100.64.244.24 \
ROADMAP_NEXT_ACTIONS_SCENARIO=profile_localhost_run_easy_node_quoted \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" MISSING_SUBJECT_PROFILE="$MISSING_SUBJECT_PROFILE" FAKE_EASY_NODE="$FAKE_EASY_NODE" FAKE_EASY_NODE_CAPTURE="$FAKE_EASY_NODE_CAPTURE" \
FAKE_EASY_NODE_EXPECT_REPORTS_DIR="/tmp/fake profile reports" \
FAKE_EASY_NODE_EXPECT_SUMMARY_JSON="/tmp/fake profile summary.json" \
FAKE_EASY_NODE_EXPECT_SUBJECT="inv quoted subject" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_PROFILE_LOCALHOST_TO_LIVE_QUOTED" \
  --summary-json "$SUMMARY_PROFILE_LOCALHOST_TO_LIVE_QUOTED" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate"
  and .actions[0].status == "pass"
  and ((.actions[0].command // "") | contains("profile-default-gate-live"))
  and ((.actions[0].command // "") | contains("--host-a 100.113.245.61"))
  and ((.actions[0].command // "") | contains("--host-b 100.64.244.24"))
  and ((.actions[0].command // "") | contains("--reports-dir"))
  and ((.actions[0].command // "") | contains("/tmp/fake profile reports"))
  and ((.actions[0].command // "") | contains("--summary-json"))
  and ((.actions[0].command // "") | contains("/tmp/fake profile summary.json"))
  and ((.actions[0].command // "") | contains("--subject [redacted]"))
  and (((.actions[0].command // "") | contains("127.0.0.1")) | not)
' "$SUMMARY_PROFILE_LOCALHOST_TO_LIVE_QUOTED" >/dev/null; then
  echo "profile localhost-to-live quoted rewrite summary mismatch"
  cat "$SUMMARY_PROFILE_LOCALHOST_TO_LIVE_QUOTED"
  exit 1
fi
if ! grep -E -- 'profile-default-gate-live' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "profile localhost-to-live quoted rewrite command capture missing live wrapper command"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi
if grep -E -- '127\.0\.0\.1' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "profile localhost-to-live quoted rewrite command capture still contains localhost endpoints"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi

echo "[roadmap-next-actions-run] no-python safe-mode path preserves quoted localhost-to-live rewrite"
SUMMARY_PROFILE_LOCALHOST_TO_LIVE_NO_PYTHON="$TMP_DIR/summary_profile_localhost_to_live_no_python.json"
REPORTS_PROFILE_LOCALHOST_TO_LIVE_NO_PYTHON="$TMP_DIR/reports_profile_localhost_to_live_no_python"
NO_PYTHON_BIN="$TMP_DIR/no_python_bin"
mkdir -p "$NO_PYTHON_BIN"
cat >"$NO_PYTHON_BIN/python3" <<'EOF_NO_PYTHON'
#!/usr/bin/env bash
exit 127
EOF_NO_PYTHON
chmod +x "$NO_PYTHON_BIN/python3"
: >"$FAKE_EASY_NODE_CAPTURE"
PATH="$NO_PYTHON_BIN:$PATH" \
A_HOST=100.113.245.61 B_HOST=100.64.244.24 \
ROADMAP_NEXT_ACTIONS_SCENARIO=profile_localhost_run_easy_node_quoted \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" MISSING_SUBJECT_PROFILE="$MISSING_SUBJECT_PROFILE" FAKE_EASY_NODE="$FAKE_EASY_NODE" FAKE_EASY_NODE_CAPTURE="$FAKE_EASY_NODE_CAPTURE" \
FAKE_EASY_NODE_EXPECT_REPORTS_DIR="/tmp/fake profile reports" \
FAKE_EASY_NODE_EXPECT_SUMMARY_JSON="/tmp/fake profile summary.json" \
FAKE_EASY_NODE_EXPECT_SUBJECT="inv quoted subject" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_PROFILE_LOCALHOST_TO_LIVE_NO_PYTHON" \
  --summary-json "$SUMMARY_PROFILE_LOCALHOST_TO_LIVE_NO_PYTHON" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate"
  and .actions[0].status == "pass"
  and ((.actions[0].command // "") | contains("profile-default-gate-live"))
  and ((.actions[0].command // "") | contains("--host-a 100.113.245.61"))
  and ((.actions[0].command // "") | contains("--host-b 100.64.244.24"))
  and ((.actions[0].command // "") | contains("--reports-dir"))
  and ((.actions[0].command // "") | contains("/tmp/fake profile reports"))
  and ((.actions[0].command // "") | contains("--summary-json"))
  and ((.actions[0].command // "") | contains("/tmp/fake profile summary.json"))
  and ((.actions[0].command // "") | contains("--subject [redacted]"))
  and (((.actions[0].command // "") | contains("inv quoted subject")) | not)
  and (((.actions[0].command // "") | contains("127.0.0.1")) | not)
' "$SUMMARY_PROFILE_LOCALHOST_TO_LIVE_NO_PYTHON" >/dev/null; then
  echo "no-python quoted localhost rewrite summary mismatch"
  cat "$SUMMARY_PROFILE_LOCALHOST_TO_LIVE_NO_PYTHON"
  exit 1
fi
if ! grep -E -- 'profile-default-gate-live' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "no-python quoted localhost rewrite command capture missing live wrapper command"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi
if grep -E -- '127\.0\.0\.1' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "no-python quoted localhost rewrite command capture still contains localhost endpoints"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi

echo "[roadmap-next-actions-run] provided roadmap summary path also converts localhost run to live wrapper"
SUMMARY_PROFILE_LOCALHOST_TO_LIVE_PROVIDED="$TMP_DIR/summary_profile_localhost_to_live_provided.json"
REPORTS_PROFILE_LOCALHOST_TO_LIVE_PROVIDED="$TMP_DIR/reports_profile_localhost_to_live_provided"
PROVIDED_ROADMAP_SUMMARY="$TMP_DIR/provided_roadmap_summary_profile_localhost.json"
PROVIDED_ROADMAP_REPORT="$TMP_DIR/provided_roadmap_report_profile_localhost.md"
cat >"$PROVIDED_ROADMAP_SUMMARY" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate","label":"Profile default decision gate","command":"bash \"$FAKE_EASY_NODE\" profile-default-gate-run --directory-a http://127.0.0.1:18081 --directory-b http://127.0.0.1:28081 --reports-dir /tmp/fake_profile_reports --campaign-timeout-sec 180 --summary-json /tmp/fake_profile_summary.json --print-summary-json 1 --subject INVITE_KEY","reason":"test-localhost-live-conversion-provided"}
  ]
}
JSON
echo "# provided roadmap report" >"$PROVIDED_ROADMAP_REPORT"
: >"$FAKE_EASY_NODE_CAPTURE"
A_HOST=100.113.245.61 B_HOST=100.64.244.24 \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" MISSING_SUBJECT_PROFILE="$MISSING_SUBJECT_PROFILE" FAKE_EASY_NODE="$FAKE_EASY_NODE" FAKE_EASY_NODE_CAPTURE="$FAKE_EASY_NODE_CAPTURE" \
bash ./scripts/roadmap_next_actions_run.sh \
  --roadmap-summary-json "$PROVIDED_ROADMAP_SUMMARY" \
  --roadmap-report-md "$PROVIDED_ROADMAP_REPORT" \
  --reports-dir "$REPORTS_PROFILE_LOCALHOST_TO_LIVE_PROVIDED" \
  --summary-json "$SUMMARY_PROFILE_LOCALHOST_TO_LIVE_PROVIDED" \
  --profile-default-gate-subject inv-live-provided-converted \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.generated_this_run == false
  and .roadmap.actions_selected_count == 1
  and .inputs.profile_default_gate_subject == "[redacted]"
  and .inputs.profile_default_gate_subject_configured == true
  and ((.actions // []) | length == 1)
  and .actions[0].id == "profile_default_gate"
  and .actions[0].status == "pass"
  and ((.actions[0].command // "") | contains("profile-default-gate-live"))
  and ((.actions[0].command // "") | contains("--host-a 100.113.245.61"))
  and ((.actions[0].command // "") | contains("--host-b 100.64.244.24"))
  and ((.actions[0].command // "") | contains("--subject [redacted]"))
  and (((.actions[0].command // "") | contains("127.0.0.1")) | not)
' "$SUMMARY_PROFILE_LOCALHOST_TO_LIVE_PROVIDED" >/dev/null; then
  echo "provided roadmap localhost-to-live conversion summary mismatch"
  cat "$SUMMARY_PROFILE_LOCALHOST_TO_LIVE_PROVIDED"
  exit 1
fi
if ! grep -E -- 'profile-default-gate-live' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "provided roadmap localhost-to-live conversion command capture missing live wrapper command"
  cat "$FAKE_EASY_NODE_CAPTURE"
  exit 1
fi
if grep -E -- '127\.0\.0\.1' "$FAKE_EASY_NODE_CAPTURE" >/dev/null; then
  echo "provided roadmap localhost-to-live conversion command capture still contains localhost endpoints"
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

echo "[roadmap-next-actions-run] profile missing-subject live-wrapper soft-fail path"
SUMMARY_PROFILE_PRECONDITION_LIVE_SOFT_FAIL="$TMP_DIR/summary_profile_precondition_live_soft_fail.json"
REPORTS_PROFILE_PRECONDITION_LIVE_SOFT_FAIL="$TMP_DIR/reports_profile_precondition_live_soft_fail"
ROADMAP_NEXT_ACTIONS_SCENARIO=profile_missing_subject_live \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" MISSING_SUBJECT_PROFILE_LIVE="$MISSING_SUBJECT_PROFILE_LIVE" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_PROFILE_PRECONDITION_LIVE_SOFT_FAIL" \
  --summary-json "$SUMMARY_PROFILE_PRECONDITION_LIVE_SOFT_FAIL" \
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
' "$SUMMARY_PROFILE_PRECONDITION_LIVE_SOFT_FAIL" >/dev/null; then
  echo "profile missing-subject live-wrapper soft-fail summary mismatch"
  cat "$SUMMARY_PROFILE_PRECONDITION_LIVE_SOFT_FAIL"
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
  and .inputs.profile_default_gate_subject == "[redacted]"
  and .inputs.profile_default_gate_subject_configured == true
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

echo "[roadmap-next-actions-run] rejects absolute out-of-repo action path in safe mode"
ABS_REJECT_SUMMARY_INPUT="$TMP_DIR/roadmap_abs_reject_input.json"
ABS_REJECT_SUMMARY="$TMP_DIR/summary_abs_reject.json"
ABS_REJECT_REPORT="$TMP_DIR/report_abs_reject.md"
ABS_REJECT_LOG_DIR="$TMP_DIR/reports_abs_reject"
ABS_OUTSIDE_DIR="$(mktemp -d)"
ABS_OUTSIDE_SCRIPT="$ABS_OUTSIDE_DIR/poc.sh"
ABS_OUTSIDE_MARKER="$ABS_OUTSIDE_DIR/poc.marker"
cat >"$ABS_OUTSIDE_SCRIPT" <<EOF_ABS_OUTSIDE
#!/usr/bin/env bash
set -euo pipefail
echo "executed" >"$ABS_OUTSIDE_MARKER"
EOF_ABS_OUTSIDE
chmod +x "$ABS_OUTSIDE_SCRIPT"
cat >"$ABS_REJECT_SUMMARY_INPUT" <<JSON_ABS_REJECT
{
  "next_actions": [
    {
      "id": "abs_reject",
      "label": "Absolute out-of-repo action",
      "command": "bash $ABS_OUTSIDE_SCRIPT",
      "reason": "security contract"
    }
  ]
}
JSON_ABS_REJECT
echo "# abs reject report" >"$ABS_REJECT_REPORT"
set +e
bash ./scripts/roadmap_next_actions_run.sh \
  --roadmap-summary-json "$ABS_REJECT_SUMMARY_INPUT" \
  --roadmap-report-md "$ABS_REJECT_REPORT" \
  --reports-dir "$ABS_REJECT_LOG_DIR" \
  --summary-json "$ABS_REJECT_SUMMARY" \
  --print-summary-json 0
abs_reject_rc=$?
set -e
if [[ "$abs_reject_rc" != "6" ]]; then
  echo "expected absolute out-of-repo rejection rc=6, got rc=$abs_reject_rc"
  cat "$ABS_REJECT_SUMMARY"
  exit 1
fi
if [[ -f "$ABS_OUTSIDE_MARKER" ]]; then
  echo "absolute out-of-repo action unexpectedly executed"
  cat "$ABS_REJECT_SUMMARY"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 6
  and .summary.actions_executed == 1
  and .summary.fail == 1
  and ((.actions // []) | length == 1)
  and .actions[0].status == "fail"
  and .actions[0].rc == 6
' "$ABS_REJECT_SUMMARY" >/dev/null; then
  echo "absolute out-of-repo rejection summary mismatch"
  cat "$ABS_REJECT_SUMMARY"
  exit 1
fi
rm -rf "$ABS_OUTSIDE_DIR"

echo "[roadmap-next-actions-run] rejects symlinked action path escaping scripts ancestry in safe mode"
SYMLINK_REJECT_SUMMARY_INPUT="$TMP_DIR/roadmap_symlink_reject_input.json"
SYMLINK_REJECT_SUMMARY="$TMP_DIR/summary_symlink_reject.json"
SYMLINK_REJECT_REPORT="$TMP_DIR/report_symlink_reject.md"
SYMLINK_REJECT_LOG_DIR="$TMP_DIR/reports_symlink_reject"
rm -f "$SYMLINK_ESCAPE_MARKER"
if [[ ! -L "$SYMLINK_ESCAPE_LINK" ]]; then
  echo "[roadmap-next-actions-run] symlink escape rejection skipped (symlink unsupported in current environment)"
else
cat >"$SYMLINK_REJECT_SUMMARY_INPUT" <<JSON_SYMLINK_REJECT
{
  "next_actions": [
    {
      "id": "symlink_reject",
      "label": "Symlink escape action",
      "command": "bash \"$SYMLINK_ESCAPE_LINK\"",
      "reason": "security contract"
    }
  ]
}
JSON_SYMLINK_REJECT
echo "# symlink reject report" >"$SYMLINK_REJECT_REPORT"
set +e
SYMLINK_ESCAPE_MARKER="$SYMLINK_ESCAPE_MARKER" \
bash ./scripts/roadmap_next_actions_run.sh \
  --roadmap-summary-json "$SYMLINK_REJECT_SUMMARY_INPUT" \
  --roadmap-report-md "$SYMLINK_REJECT_REPORT" \
  --reports-dir "$SYMLINK_REJECT_LOG_DIR" \
  --summary-json "$SYMLINK_REJECT_SUMMARY" \
  --print-summary-json 0
symlink_reject_rc=$?
set -e
if [[ "$symlink_reject_rc" != "6" ]]; then
  echo "expected symlink escape rejection rc=6, got rc=$symlink_reject_rc"
  cat "$SYMLINK_REJECT_SUMMARY"
  exit 1
fi
if [[ -f "$SYMLINK_ESCAPE_MARKER" ]]; then
  echo "symlink escape payload unexpectedly executed in safe mode"
  cat "$SYMLINK_REJECT_SUMMARY"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 6
  and .summary.actions_executed == 1
  and .summary.fail == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "symlink_reject"
  and .actions[0].status == "fail"
  and .actions[0].rc == 6
' "$SYMLINK_REJECT_SUMMARY" >/dev/null; then
  echo "symlink escape rejection summary mismatch"
  cat "$SYMLINK_REJECT_SUMMARY"
  exit 1
fi
fi

echo "[roadmap-next-actions-run] rejects action path with parent-directory symlink escape in safe mode"
PARENT_SYMLINK_REJECT_SUMMARY_INPUT="$TMP_DIR/roadmap_parent_symlink_reject_input.json"
PARENT_SYMLINK_REJECT_SUMMARY="$TMP_DIR/summary_parent_symlink_reject.json"
PARENT_SYMLINK_REJECT_REPORT="$TMP_DIR/report_parent_symlink_reject.md"
PARENT_SYMLINK_REJECT_LOG_DIR="$TMP_DIR/reports_parent_symlink_reject"
rm -f "$PARENT_SYMLINK_ESCAPE_MARKER"
if [[ ! -L "$PARENT_SYMLINK_ESCAPE_DIR_LINK" ]]; then
  echo "[roadmap-next-actions-run] parent symlink escape rejection skipped (symlink unsupported in current environment)"
else
cat >"$PARENT_SYMLINK_REJECT_SUMMARY_INPUT" <<JSON_PARENT_SYMLINK_REJECT
{
  "next_actions": [
    {
      "id": "parent_symlink_reject",
      "label": "Parent symlink escape action",
      "command": "bash \"$PARENT_SYMLINK_ESCAPE_DIR_LINK/parent_symlink_escape_action.sh\"",
      "reason": "security contract"
    }
  ]
}
JSON_PARENT_SYMLINK_REJECT
echo "# parent symlink reject report" >"$PARENT_SYMLINK_REJECT_REPORT"
set +e
PARENT_SYMLINK_ESCAPE_MARKER="$PARENT_SYMLINK_ESCAPE_MARKER" \
bash ./scripts/roadmap_next_actions_run.sh \
  --roadmap-summary-json "$PARENT_SYMLINK_REJECT_SUMMARY_INPUT" \
  --roadmap-report-md "$PARENT_SYMLINK_REJECT_REPORT" \
  --reports-dir "$PARENT_SYMLINK_REJECT_LOG_DIR" \
  --summary-json "$PARENT_SYMLINK_REJECT_SUMMARY" \
  --print-summary-json 0
parent_symlink_reject_rc=$?
set -e
if [[ "$parent_symlink_reject_rc" != "6" ]]; then
  echo "expected parent symlink escape rejection rc=6, got rc=$parent_symlink_reject_rc"
  cat "$PARENT_SYMLINK_REJECT_SUMMARY"
  exit 1
fi
if [[ -f "$PARENT_SYMLINK_ESCAPE_MARKER" ]]; then
  echo "parent symlink escape payload unexpectedly executed in safe mode"
  cat "$PARENT_SYMLINK_REJECT_SUMMARY"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 6
  and .summary.actions_executed == 1
  and .summary.fail == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "parent_symlink_reject"
  and .actions[0].status == "fail"
  and .actions[0].rc == 6
' "$PARENT_SYMLINK_REJECT_SUMMARY" >/dev/null; then
  echo "parent symlink escape rejection summary mismatch"
  cat "$PARENT_SYMLINK_REJECT_SUMMARY"
  exit 1
fi
fi

echo "[roadmap-next-actions-run] pre-exec revalidation catches TOCTOU path mutation and fails closed"
TOCTOU_REJECT_SUMMARY_INPUT="$TMP_DIR/roadmap_toctou_reject_input.json"
TOCTOU_REJECT_SUMMARY="$TMP_DIR/summary_toctou_reject.json"
TOCTOU_REJECT_REPORT="$TMP_DIR/report_toctou_reject.md"
TOCTOU_REJECT_LOG_DIR="$TMP_DIR/reports_toctou_reject"
rm -f "$TOCTOU_ESCAPE_MARKER"
cat >"$TOCTOU_REJECT_SUMMARY_INPUT" <<JSON_TOCTOU_REJECT
{
  "next_actions": [
    {
      "id": "toctou_mutate",
      "label": "TOCTOU mutator",
      "command": "bash \"$TOCTOU_MUTATE_ACTION\"",
      "reason": "security contract"
    },
    {
      "id": "toctou_race",
      "label": "TOCTOU race target",
      "command": "bash \"$TOCTOU_RACE_ACTION\"",
      "reason": "security contract"
    }
  ]
}
JSON_TOCTOU_REJECT
echo "# toctou reject report" >"$TOCTOU_REJECT_REPORT"
set +e
TOCTOU_TARGET_SCRIPT="$TOCTOU_RACE_ACTION" \
TOCTOU_ESCAPE_SCRIPT="$TOCTOU_ESCAPE_TARGET" \
TOCTOU_ESCAPE_MARKER="$TOCTOU_ESCAPE_MARKER" \
ROADMAP_NEXT_ACTIONS_RUN_PRE_EXEC_REVALIDATE_DELAY_SEC=1 \
bash ./scripts/roadmap_next_actions_run.sh \
  --roadmap-summary-json "$TOCTOU_REJECT_SUMMARY_INPUT" \
  --roadmap-report-md "$TOCTOU_REJECT_REPORT" \
  --reports-dir "$TOCTOU_REJECT_LOG_DIR" \
  --summary-json "$TOCTOU_REJECT_SUMMARY" \
  --print-summary-json 0
toctou_reject_rc=$?
set -e
if [[ "$toctou_reject_rc" != "6" ]]; then
  echo "expected TOCTOU revalidation rejection rc=6, got rc=$toctou_reject_rc"
  cat "$TOCTOU_REJECT_SUMMARY"
  exit 1
fi
if [[ -f "$TOCTOU_ESCAPE_MARKER" ]]; then
  echo "TOCTOU escape payload unexpectedly executed in safe mode"
  cat "$TOCTOU_REJECT_SUMMARY"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 6
  and .summary.actions_executed == 2
  and .summary.pass == 1
  and .summary.fail == 1
  and ((.actions // []) | length == 2)
  and .actions[0].id == "toctou_mutate"
  and .actions[0].status == "pass"
  and .actions[1].id == "toctou_race"
  and .actions[1].status == "fail"
  and .actions[1].rc == 6
' "$TOCTOU_REJECT_SUMMARY" >/dev/null; then
  echo "TOCTOU revalidation rejection summary mismatch"
  cat "$TOCTOU_REJECT_SUMMARY"
  exit 1
fi
if ! grep -R -F "pre-exec validation mismatch" "$TOCTOU_REJECT_LOG_DIR" >/dev/null; then
  echo "TOCTOU revalidation mismatch log marker missing"
  cat "$TOCTOU_REJECT_SUMMARY"
  exit 1
fi

echo "[roadmap-next-actions-run] rejects env-prefixed action in safe mode"
ENV_REJECT_SUMMARY_INPUT="$TMP_DIR/roadmap_env_reject_input.json"
ENV_REJECT_SUMMARY="$TMP_DIR/summary_env_reject.json"
ENV_REJECT_REPORT="$TMP_DIR/report_env_reject.md"
ENV_REJECT_LOG_DIR="$TMP_DIR/reports_env_reject"
ENV_REJECT_PAYLOAD="$TMP_DIR/env_reject_payload.sh"
ENV_REJECT_MARKER="$TMP_DIR/env_reject_marker.txt"
cat >"$ENV_REJECT_PAYLOAD" <<EOF_ENV_REJECT
#!/usr/bin/env bash
set -euo pipefail
echo "payload-executed" >"$ENV_REJECT_MARKER"
EOF_ENV_REJECT
chmod +x "$ENV_REJECT_PAYLOAD"
cat >"$ENV_REJECT_SUMMARY_INPUT" <<JSON_ENV_REJECT
{
  "next_actions": [
    {
      "id": "env_reject",
      "label": "Env-prefixed action",
      "command": "BASH_ENV=$ENV_REJECT_PAYLOAD bash ./scripts/roadmap_progress_report.sh --help",
      "reason": "security contract"
    }
  ]
}
JSON_ENV_REJECT
echo "# env reject report" >"$ENV_REJECT_REPORT"
set +e
bash ./scripts/roadmap_next_actions_run.sh \
  --roadmap-summary-json "$ENV_REJECT_SUMMARY_INPUT" \
  --roadmap-report-md "$ENV_REJECT_REPORT" \
  --reports-dir "$ENV_REJECT_LOG_DIR" \
  --summary-json "$ENV_REJECT_SUMMARY" \
  --print-summary-json 0
env_reject_rc=$?
set -e
if [[ "$env_reject_rc" != "5" ]]; then
  echo "expected env-prefixed safe-mode rejection rc=5, got rc=$env_reject_rc"
  cat "$ENV_REJECT_SUMMARY"
  exit 1
fi
if [[ -f "$ENV_REJECT_MARKER" ]]; then
  echo "env-prefixed action payload unexpectedly executed in safe mode"
  cat "$ENV_REJECT_SUMMARY"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 5
  and .summary.actions_executed == 1
  and .summary.fail == 1
  and ((.actions // []) | length == 1)
  and .actions[0].status == "fail"
  and .actions[0].rc == 5
' "$ENV_REJECT_SUMMARY" >/dev/null; then
  echo "env-prefixed safe-mode rejection summary mismatch"
  cat "$ENV_REJECT_SUMMARY"
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

if (( parallel_elapsed_sec > 12 )); then
  echo "parallel timing mismatch: expected <=12s, got ${parallel_elapsed_sec}s"
  cat "$SUMMARY_PARALLEL"
  exit 1
fi

echo "roadmap next-actions run integration check ok"
