#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Keep this integration hermetic: ambient ROADMAP_NEXT_ACTIONS_RUN_* overrides
# can relax fail-closed behavior or mutate selection/routing inputs.
unset ROADMAP_NEXT_ACTIONS_RUN_ACTION_TIMEOUT_SEC
unset ROADMAP_NEXT_ACTIONS_RUN_ACCESS_RECOVERY_MTLS_CA
unset ROADMAP_NEXT_ACTIONS_RUN_ACCESS_RECOVERY_MTLS_CLIENT_CERT
unset ROADMAP_NEXT_ACTIONS_RUN_ACCESS_RECOVERY_MTLS_CLIENT_KEY
unset ROADMAP_NEXT_ACTIONS_RUN_ACCESS_RECOVERY_TRUST_STORE
unset ROADMAP_NEXT_ACTIONS_RUN_ALLOW_PROFILE_DEFAULT_GATE_UNREACHABLE
unset ROADMAP_NEXT_ACTIONS_RUN_ALLOW_UNSAFE_SHELL_COMMANDS
unset ROADMAP_NEXT_ACTIONS_RUN_CAMPAIGN_SUBJECT
unset ROADMAP_NEXT_ACTIONS_RUN_EXCLUDE_IDS
unset ROADMAP_NEXT_ACTIONS_RUN_EXCLUDE_ID_PREFIX
unset ROADMAP_NEXT_ACTIONS_RUN_EXCLUDE_ID_SUFFIXES
unset ROADMAP_NEXT_ACTIONS_RUN_HOST_A
unset ROADMAP_NEXT_ACTIONS_RUN_HOST_B
unset ROADMAP_NEXT_ACTIONS_RUN_INCLUDE_IDS
unset ROADMAP_NEXT_ACTIONS_RUN_INCLUDE_ID_PREFIX
unset ROADMAP_NEXT_ACTIONS_RUN_INCLUDE_ID_SUFFIXES
unset ROADMAP_NEXT_ACTIONS_RUN_LOCAL_ONLY
unset ROADMAP_NEXT_ACTIONS_RUN_MAX_ACTIONS
unset ROADMAP_NEXT_ACTIONS_RUN_PARALLEL
unset ROADMAP_NEXT_ACTIONS_RUN_PRE_EXEC_REVALIDATE_DELAY_SEC
unset ROADMAP_NEXT_ACTIONS_RUN_PRINT_SUMMARY_JSON
unset ROADMAP_NEXT_ACTIONS_RUN_PROFILE_DEFAULT_GATE_DEFAULT_TIMEOUT_SEC
unset ROADMAP_NEXT_ACTIONS_RUN_PROFILE_DEFAULT_GATE_SUBJECT
unset ROADMAP_NEXT_ACTIONS_RUN_REFRESH_MANUAL_VALIDATION
unset ROADMAP_NEXT_ACTIONS_RUN_REFRESH_SINGLE_MACHINE_READINESS
unset ROADMAP_NEXT_ACTIONS_RUN_REPORTS_DIR
unset ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_REPORT_MD
unset ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT
unset ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SUMMARY_JSON
unset ROADMAP_NEXT_ACTIONS_RUN_SUMMARY_JSON
unset ROADMAP_NEXT_ACTIONS_RUN_VM_COMMAND_SOURCE
# Keep placeholder-subject precondition checks deterministic.
unset ACCESS_RECOVERY_TRUST_STORE
unset ACCESS_RECOVERY_MTLS_CA
unset ACCESS_RECOVERY_MTLS_CLIENT_CERT
unset ACCESS_RECOVERY_MTLS_CLIENT_KEY
unset ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_PLAN_ONLY
unset CAMPAIGN_SUBJECT
unset INVITE_KEY
unset MTLS_CA_FILE
unset MTLS_CLIENT_CERT_FILE
unset MTLS_CLIENT_KEY_FILE
unset TRUST_STORE

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
PLAN_ENV_CHECK="$ACTION_TMP_DIR/plan_env_check_action.sh"
CONFLICT_CMD_A="$ACTION_TMP_DIR/conflict_cmd_a.sh"
CONFLICT_CMD_B="$ACTION_TMP_DIR/conflict_cmd_b.sh"
CONFLICT_MARK_A="$ACTION_TMP_DIR/conflict_cmd_a.marker"
CONFLICT_MARK_B="$ACTION_TMP_DIR/conflict_cmd_b.marker"
FAIL1="$ACTION_TMP_DIR/fail_action_1.sh"
FAIL2="$ACTION_TMP_DIR/fail_action_2.sh"
SLOW1="$ACTION_TMP_DIR/slow_action_1.sh"
SLOW2="$ACTION_TMP_DIR/slow_action_2.sh"
MISSING_LIVE_EVIDENCE_PREREQ="$ACTION_TMP_DIR/missing_live_evidence_prereq.sh"
STALE_PREREQ_EVIDENCE="$ACTION_TMP_DIR/stale_prereq_evidence.sh"
REAL_HOST_SIGNOFF_REQUIRED="$ACTION_TMP_DIR/real_host_signoff_required.sh"
UNREACHABLE_PROFILE="$ACTION_TMP_DIR/profile_unreachable.sh"
MISSING_SUBJECT_PROFILE="$ACTION_TMP_DIR/profile_missing_subject.sh"
MISSING_SUBJECT_PROFILE_LIVE="$ACTION_TMP_DIR/profile_missing_subject_live.sh"
UNREACHABLE_PROFILE_MARKER="$ACTION_TMP_DIR/profile_unreachable_marker.sh"
MISSING_SUBJECT_PROFILE_MARKER="$ACTION_TMP_DIR/profile_missing_subject_marker.sh"
FAKE_EASY_NODE="$ACTION_TMP_DIR/fake_easy_node.sh"
FAKE_EASY_NODE_CAPTURE="$ACTION_TMP_DIR/fake_easy_node_capture.log"
FAKE_ACCESS_RECOVERY_VERIFY="$ACTION_TMP_DIR/fake_access_recovery_verify.sh"
FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE="$ACTION_TMP_DIR/fake_access_recovery_verify_capture.log"
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

cat >"$PLAN_ENV_CHECK" <<'EOF_PLAN_ENV_CHECK'
#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_PLAN_ONLY:-}" ]]; then
  echo "plan-only override leaked into action environment"
  exit 42
fi
echo "plan env isolated"
EOF_PLAN_ENV_CHECK
chmod +x "$PLAN_ENV_CHECK"

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

cat >"$MISSING_LIVE_EVIDENCE_PREREQ" <<'EOF_MISSING_LIVE_EVIDENCE_PREREQ'
#!/usr/bin/env bash
set -euo pipefail
echo "missing required live evidence summary_json: .easy-node-logs/profile-default-gate-live-summary.json not found"
exit 6
EOF_MISSING_LIVE_EVIDENCE_PREREQ
chmod +x "$MISSING_LIVE_EVIDENCE_PREREQ"

cat >"$STALE_PREREQ_EVIDENCE" <<'EOF_STALE_PREREQ_EVIDENCE'
#!/usr/bin/env bash
set -euo pipefail
echo "prerequisite evidence is stale: generated_at_utc is too old for promotion"
exit 6
EOF_STALE_PREREQ_EVIDENCE
chmod +x "$STALE_PREREQ_EVIDENCE"

cat >"$REAL_HOST_SIGNOFF_REQUIRED" <<'EOF_REAL_HOST_SIGNOFF_REQUIRED'
#!/usr/bin/env bash
set -euo pipefail
echo "three-machine production signoff requires current real-host evidence before pilot handoff"
exit 6
EOF_REAL_HOST_SIGNOFF_REQUIRED
chmod +x "$REAL_HOST_SIGNOFF_REQUIRED"

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

cat >"$FAKE_ACCESS_RECOVERY_VERIFY" <<'EOF_FAKE_ACCESS_RECOVERY_VERIFY'
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
if [[ -n "${FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE:-}" ]]; then
  printf '%s\n' "$*" >>"$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE"
fi
trust_store="$(arg_value_for_flag --trust-store "$@")"
if [[ -z "$trust_store" || "$trust_store" == "TRUST_STORE" || "$trust_store" == "ACCESS_RECOVERY_TRUST_STORE" || ! -f "$trust_store" ]]; then
  echo "fake access recovery verifier missing real trust store: ${trust_store:-<empty>}"
  exit 9
fi
echo "fake access recovery verifier ok"
EOF_FAKE_ACCESS_RECOVERY_VERIFY
chmod +x "$FAKE_ACCESS_RECOVERY_VERIFY"

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
  secret_redaction_extended_flags)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"secret_redaction_extended","label":"Secret redaction extended","command":"bash \"$PASS1\" --password pass-secret --api-key=api-secret --private-key-file /tmp/private.key --provenance-private-key-file /tmp/provenance.key --admin-key 'admin secret' --secret \"quoted secret\" --token legacy-token","reason":"test-secret-redaction"}
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
  local_only_mix)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"local_pack_action","label":"Local pack action","command":"bash \"$PASS1\"","reason":"test-local-pack","requires_real_hosts":false,"local_pack_only":true},
    {"id":"local_no_real_hosts_action","label":"Local no real hosts action","command":"bash \"$PASS2\"","reason":"test-local-no-real-hosts","requires_real_hosts":false,"local_pack_only":false},
    {"id":"real_host_action","label":"Real host action","command":"bash \"$FAIL1\"","reason":"test-real-host","requires_real_hosts":true,"local_pack_only":false},
    {"id":"unknown_metadata_action","label":"Unknown metadata action","command":"bash \"$FAIL2\"","reason":"test-unknown-metadata"}
  ]
}
JSON
    ;;
  blockchain_local_only_metrics_prefill)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"blockchain_mainnet_activation_refresh_evidence","label":"Blockchain mainnet activation refresh evidence","command":"bash \"$FAIL1\"","reason":"test-blockchain-refresh","requires_real_hosts":true,"local_pack_only":false,"missing_evidence_family":"blockchain-mainnet-activation","missing_evidence_action_kind":"real-evidence-refresh"},
    {"id":"blockchain_mainnet_activation_missing_metrics_prefill","label":"Blockchain missing-metrics prefill","command":"bash \"$PASS1\"","reason":"test-blockchain-prefill","requires_real_hosts":false,"local_pack_only":true,"missing_evidence_family":"blockchain-mainnet-activation","missing_evidence_action_kind":"metrics-prefill"}
  ]
}
JSON
    ;;
  local_pack_missing_live_prereq)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"profile_default_gate_evidence_pack","label":"Profile default evidence-pack publish","command":"bash \"$MISSING_LIVE_EVIDENCE_PREREQ\"","reason":"test-missing-live-prereq","requires_real_hosts":false,"local_pack_only":true}
  ]
}
JSON
    ;;
  local_pack_stale_prereq)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"runtime_actuation_promotion_evidence_pack","label":"Runtime-actuation evidence-pack publish","command":"bash \"$STALE_PREREQ_EVIDENCE\"","reason":"test-stale-prereq","requires_real_hosts":false,"local_pack_only":true}
  ]
}
JSON
    ;;
  local_pack_real_host_signoff_required)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"three_machine_real_host_validation_pack","label":"Three-machine real-host validation pack","command":"bash \"$REAL_HOST_SIGNOFF_REQUIRED\"","reason":"test-real-host-signoff-required","requires_real_hosts":false,"local_pack_only":true}
  ]
}
JSON
    ;;
  real_helper_https_only)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"real_helper_https_evidence","label":"Real helper HTTPS evidence","command":"bash \"$FAIL1\"","reason":"test-real-helper-required","requires_real_hosts":true,"local_pack_only":false}
  ]
}
JSON
    ;;
  real_helper_plan_env_isolation)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"real_helper_https_evidence","label":"Real helper HTTPS evidence","command":"bash \"$PLAN_ENV_CHECK\"","reason":"test-plan-env-isolation","requires_real_hosts":true,"local_pack_only":false}
  ]
}
JSON
    ;;
  real_helper_plan_only_arg)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"real_helper_https_evidence","label":"Real helper HTTPS evidence","command":"bash \"$PLAN_ENV_CHECK\" --plan-only 1","reason":"test-plan-only-arg-rejected","requires_real_hosts":true,"local_pack_only":false}
  ]
}
JSON
    ;;
  real_helper_no_roadmap_refresh_arg)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"real_helper_https_evidence","label":"Real helper HTTPS evidence","command":"bash \"$PLAN_ENV_CHECK\" --roadmap-refresh 0","reason":"test-roadmap-refresh-0-rejected","requires_real_hosts":true,"local_pack_only":false}
  ]
}
JSON
    ;;
  access_recovery_trust_store_placeholder)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"trusted_pilot_evidence_verify","label":"Trusted pilot evidence verifier","command":"bash \"$FAKE_ACCESS_RECOVERY_VERIFY\" --summary-json /tmp/fake_bundle.json --provenance-json /tmp/fake.provenance.json --trust-store TRUST_STORE --require-trusted-provenance 1 --verification-summary-json /tmp/fake_verify.json --print-verification-summary-json 1","reason":"test-access-recovery-trust-store"}
  ]
}
JSON
    ;;
  access_recovery_trust_store_placeholder_extra_tokens)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"trusted_pilot_evidence_verify","label":"Trusted pilot evidence verifier","command":"bash \"$FAKE_ACCESS_RECOVERY_VERIFY\" --summary-json /tmp/fake_bundle.json --provenance-json /tmp/fake.provenance.json --trust-store TRUST_STORE --require-trusted-provenance 1 --verification-summary-json /tmp/TRUST_STORE_receipt.json --label TRUST_STORE_AUDIT --print-verification-summary-json 1","reason":"test-access-recovery-trust-store-extra-tokens"}
  ]
}
JSON
    ;;
  access_recovery_real_helper_trust_store_placeholder)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"real_helper_https_evidence","label":"Real helper HTTPS evidence","command":"./scripts/easy_node.sh access-recovery-real-helper-evidence-run --base-url https://helper.gpm-pilot.net --path-id helper-web --code-file /tmp/bridge-code.txt --config-json /tmp/bridge-service-config.json --deploy-pack-dir /tmp/bridge-deploy --provenance-private-key-file /tmp/provenance.key --provenance-org-id pilot-org --provenance-org-name 'Pilot Org' --trust-store TRUST_STORE --reports-dir /tmp/access-recovery-pilot","reason":"test-real-helper-trust-store","requires_real_hosts":true}
  ]
}
JSON
    ;;
  access_recovery_real_helper_operator_placeholders)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"real_helper_https_evidence","label":"Real helper HTTPS evidence","command":"./scripts/easy_node.sh access-recovery-real-helper-evidence-run --base-url https://HELPER_PUBLIC_DNS --path-id helper-web --code-file PRIVATE_CODE_FILE --config-json BRIDGE_SERVICE_CONFIG --deploy-pack-dir BRIDGE_DEPLOY_PACK --provenance-private-key-file PROVENANCE_PRIVATE_KEY_FILE --provenance-org-id ORG_ID --provenance-org-name ORG_NAME --trust-store TRUST_STORE --reports-dir /tmp/access-recovery-pilot","reason":"test-real-helper-operator-placeholders","requires_real_hosts":true}
  ]
}
JSON
    ;;
  access_recovery_service_smoke_helper_id_placeholder)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"access_bridge_service_smoke","label":"Access bridge service smoke","command":"bash \"$PASS1\" --base-url https://helper.gpm-pilot.net --path-id helper-web --code-file /tmp/bridge-code.txt --expect-helper-id HELPER_ID --expect-org-id pilot-org --summary-json /tmp/access_bridge_service_smoke_summary.json","reason":"test-helper-id-placeholder"}
  ]
}
JSON
    ;;
  access_recovery_placeholder_like_concrete_values)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"access_bridge_service_smoke","label":"Access bridge service smoke","command":"bash \"$PASS1\" --base-url https://helper_public_dns-prod.example --path-id helper-web --code-file /tmp/private_code_file-prod.txt --config-json /tmp/bridge_service_config-prod.json --deploy-pack-dir /tmp/bridge_deploy_pack-prod --provenance-private-key-file /tmp/provenance_private_key_file-prod.key --provenance-org-id org_id-prod --provenance-org-name org_name-prod --expect-helper-id helper_id-prod --expect-org-id org_id-prod --cacert /tmp/mtls_ca_file-prod.crt --client-cert /tmp/mtls_client_cert_file-prod.crt --client-key /tmp/mtls_client_key_file-prod.key --summary-json /tmp/access_bridge_service_smoke_summary.json","reason":"test-placeholder-like-concrete-values"}
  ]
}
JSON
    ;;
  access_recovery_installed_host_operator_placeholders)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"access_bridge_installed_host_evidence","label":"Access bridge installed-host evidence","command":"bash \"$PASS1\" --evidence-mode installed-host --install-dir /etc/gpm/access-bridge --systemd-unit-file /etc/systemd/system/gpm-access-bridge.service --proxy-kind caddy --proxy-config-file /etc/caddy/Caddyfile.d/gpm-access-bridge.caddy --config-json BRIDGE_SERVICE_CONFIG --expected-base-url https://HELPER_PUBLIC_DNS --summary-json /tmp/access_bridge_host_install_check_summary.json","reason":"test-installed-host-operator-placeholders"}
  ]
}
JSON
    ;;
  access_recovery_installed_host_concrete)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"access_bridge_installed_host_evidence","label":"Access bridge installed-host evidence","command":"bash \"$PASS1\" --evidence-mode installed-host --install-dir /tmp/gpm/access-bridge --systemd-unit-file /tmp/gpm-access-bridge.service --proxy-kind caddy --proxy-config-file /tmp/gpm-access-bridge.caddy --config-json /tmp/bridge-service-config.json --expected-base-url https://helper.gpm-pilot.net --summary-json /tmp/access_bridge_host_install_check_summary.json","reason":"test-installed-host-concrete"}
  ]
}
JSON
    ;;
  access_recovery_mtls_operator_placeholders)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"access_bridge_service_smoke","label":"Access bridge service smoke","command":"bash \"$PASS1\" --base-url https://helper.gpm-pilot.net --path-id helper-web --code-file /tmp/bridge-code.txt --require-mtls 1 --cacert MTLS_CA_FILE --client-cert MTLS_CLIENT_CERT_FILE --client-key MTLS_CLIENT_KEY_FILE","reason":"test-access-recovery-mtls-placeholders"}
  ]
}
JSON
    ;;
  access_recovery_trust_store_concrete)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"trusted_pilot_evidence_verify","label":"Trusted pilot evidence verifier","command":"bash \"$FAKE_ACCESS_RECOVERY_VERIFY\" --summary-json /tmp/fake_bundle.json --provenance-json /tmp/fake.provenance.json --trust-store \"${ACTION_OWNED_TRUST_STORE:-/tmp/action-owned-trust-store.json}\" --require-trusted-provenance 1 --verification-summary-json /tmp/fake_verify.json --print-verification-summary-json 1","reason":"test-access-recovery-concrete-trust-store"}
  ]
}
JSON
    ;;
  access_recovery_public_key_handoff)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"trusted_pilot_evidence_verify","label":"Trusted pilot evidence verifier","command":"bash \"$FAKE_ACCESS_RECOVERY_VERIFY\" --summary-json /tmp/fake_bundle.json --provenance-json /tmp/fake.provenance.json --public-key-file /tmp/raw-recovery.pub --require-trusted-provenance 1 --verification-summary-json /tmp/fake_verify.json --print-verification-summary-json 1","reason":"test-access-recovery-public-key-handoff"}
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
if ! bash ./scripts/roadmap_next_actions_run.sh --help | grep -F -- "--local-only [0|1]" >/dev/null; then
  echo "help output missing --local-only [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_next_actions_run.sh --help | grep -F -- "--exclude-requires-real-hosts [0|1]" >/dev/null; then
  echo "help output missing --exclude-requires-real-hosts [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_next_actions_run.sh --help | grep -F -- "--allow-profile-default-gate-unreachable [0|1]" >/dev/null; then
  echo "help output missing --allow-profile-default-gate-unreachable [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_next_actions_run.sh --help | grep -F -- "--allow-empty-actions [0|1]" >/dev/null; then
  echo "help output missing --allow-empty-actions [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_next_actions_run.sh --help | grep -F -- "--profile-default-gate-subject ID" >/dev/null; then
  echo "help output missing --profile-default-gate-subject ID"
  exit 1
fi
if ! bash ./scripts/roadmap_next_actions_run.sh --help | grep -F -- "--access-recovery-trust-store PATH" >/dev/null; then
  echo "help output missing --access-recovery-trust-store PATH"
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

echo "[roadmap-next-actions-run] redacts extended secret-bearing flags from action summaries"
SUMMARY_REDACTION_EXTENDED="$TMP_DIR/summary_redaction_extended.json"
REPORTS_REDACTION_EXTENDED="$TMP_DIR/reports_redaction_extended"
ROADMAP_NEXT_ACTIONS_SCENARIO=secret_redaction_extended_flags \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_REDACTION_EXTENDED" \
  --summary-json "$SUMMARY_REDACTION_EXTENDED" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["secret_redaction_extended"]
  and .summary.actions_executed == 1
  and .summary.pass == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "secret_redaction_extended"
  and .actions[0].status == "pass"
  and ((.actions[0].command // "") | contains("--password [redacted]"))
  and ((.actions[0].command // "") | contains("--api-key=[redacted]"))
  and ((.actions[0].command // "") | contains("--private-key-file [redacted]"))
  and ((.actions[0].command // "") | contains("--provenance-private-key-file [redacted]"))
  and ((.actions[0].command // "") | contains("--admin-key [redacted]"))
  and ((.actions[0].command // "") | contains("--secret [redacted]"))
  and ((.actions[0].command // "") | contains("--token [redacted]"))
  and (((.actions[0].command // "") | contains("pass-secret")) | not)
  and (((.actions[0].command // "") | contains("api-secret")) | not)
  and (((.actions[0].command // "") | contains("/tmp/private.key")) | not)
  and (((.actions[0].command // "") | contains("/tmp/provenance.key")) | not)
  and (((.actions[0].command // "") | contains("admin secret")) | not)
  and (((.actions[0].command // "") | contains("quoted secret")) | not)
  and (((.actions[0].command // "") | contains("legacy-token")) | not)
' "$SUMMARY_REDACTION_EXTENDED" >/dev/null; then
  echo "extended secret redaction summary mismatch"
  cat "$SUMMARY_REDACTION_EXTENDED"
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

echo "[roadmap-next-actions-run] local-only filters out real-host and untagged actions"
SUMMARY_LOCAL_ONLY="$TMP_DIR/summary_local_only.json"
REPORTS_LOCAL_ONLY="$TMP_DIR/reports_local_only"
ROADMAP_NEXT_ACTIONS_SCENARIO=local_only_mix \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_LOCAL_ONLY" \
  --summary-json "$SUMMARY_LOCAL_ONLY" \
  --local-only 1 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.local_only == true
  and .roadmap.actions_selected_count == 2
  and .roadmap.selected_action_ids == ["local_pack_action","local_no_real_hosts_action"]
  and .roadmap.selection_accounting.non_empty_command_count == 4
  and .roadmap.selection_accounting.after_exclude_suffix_filters_count == 4
  and .roadmap.selection_accounting.after_local_only_filters_count == 2
  and .roadmap.selection_accounting.local_only_skipped_real_host_actions_count == 1
  and .roadmap.selection_accounting.local_only_skipped_real_host_action_ids == ["real_host_action"]
  and .summary.actions_executed == 2
  and .summary.pass == 2
  and .summary.fail == 0
' "$SUMMARY_LOCAL_ONLY" >/dev/null; then
  echo "local-only summary mismatch"
  cat "$SUMMARY_LOCAL_ONLY"
  exit 1
fi

echo "[roadmap-next-actions-run] local-only keeps blockchain metrics prefill and skips real evidence"
SUMMARY_BLOCKCHAIN_LOCAL_ONLY_PREFILL="$TMP_DIR/summary_blockchain_local_only_prefill.json"
REPORTS_BLOCKCHAIN_LOCAL_ONLY_PREFILL="$TMP_DIR/reports_blockchain_local_only_prefill"
ROADMAP_NEXT_ACTIONS_SCENARIO=blockchain_local_only_metrics_prefill \
PASS1="$PASS1" FAIL1="$FAIL1" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_BLOCKCHAIN_LOCAL_ONLY_PREFILL" \
  --summary-json "$SUMMARY_BLOCKCHAIN_LOCAL_ONLY_PREFILL" \
  --local-only 1 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.local_only == true
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["blockchain_mainnet_activation_missing_metrics_prefill"]
  and .roadmap.selection_accounting.non_empty_command_count == 2
  and .roadmap.selection_accounting.after_local_only_filters_count == 1
  and .roadmap.selection_accounting.local_only_skipped_real_host_actions_count == 1
  and .roadmap.selection_accounting.local_only_skipped_real_host_action_ids == ["blockchain_mainnet_activation_refresh_evidence"]
  and .actions[0].id == "blockchain_mainnet_activation_missing_metrics_prefill"
  and .actions[0].status == "pass"
  and .summary.actions_executed == 1
  and .summary.pass == 1
  and .summary.fail == 0
' "$SUMMARY_BLOCKCHAIN_LOCAL_ONLY_PREFILL" >/dev/null; then
  echo "blockchain local-only metrics prefill summary mismatch"
  cat "$SUMMARY_BLOCKCHAIN_LOCAL_ONLY_PREFILL"
  exit 1
fi

echo "[roadmap-next-actions-run] local-only empty pass records skipped real-host blockers"
SUMMARY_LOCAL_ONLY_REAL_HELPER_ONLY="$TMP_DIR/summary_local_only_real_helper_only.json"
REPORTS_LOCAL_ONLY_REAL_HELPER_ONLY="$TMP_DIR/reports_local_only_real_helper_only"
ROADMAP_NEXT_ACTIONS_SCENARIO=real_helper_https_only \
FAIL1="$FAIL1" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_LOCAL_ONLY_REAL_HELPER_ONLY" \
  --summary-json "$SUMMARY_LOCAL_ONLY_REAL_HELPER_ONLY" \
  --local-only 1 \
  --allow-empty-actions 1 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.local_only == true
  and .inputs.allow_empty_actions == true
  and .roadmap.actions_selected_count == 0
  and .roadmap.selection_accounting.non_empty_command_count == 1
  and .roadmap.selection_accounting.after_local_only_filters_count == 0
  and .roadmap.selection_accounting.local_only_skipped_real_host_actions_count == 1
  and .roadmap.selection_accounting.local_only_skipped_real_host_action_ids == ["real_helper_https_evidence"]
  and .summary.actions_executed == 0
' "$SUMMARY_LOCAL_ONLY_REAL_HELPER_ONLY" >/dev/null; then
  echo "local-only real-helper-only skipped blocker summary mismatch"
  cat "$SUMMARY_LOCAL_ONLY_REAL_HELPER_ONLY"
  exit 1
fi

echo "[roadmap-next-actions-run] classifies missing live evidence prerequisite action failures"
SUMMARY_LOCAL_PACK_MISSING_LIVE="$TMP_DIR/summary_local_pack_missing_live.json"
REPORTS_LOCAL_PACK_MISSING_LIVE="$TMP_DIR/reports_local_pack_missing_live"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=local_pack_missing_live_prereq \
MISSING_LIVE_EVIDENCE_PREREQ="$MISSING_LIVE_EVIDENCE_PREREQ" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_LOCAL_PACK_MISSING_LIVE" \
  --summary-json "$SUMMARY_LOCAL_PACK_MISSING_LIVE" \
  --local-only 1 \
  --print-summary-json 0 >"$TMP_DIR/local_pack_missing_live.log" 2>&1
local_pack_missing_live_rc=$?
set -e
if [[ "$local_pack_missing_live_rc" != "6" ]]; then
  echo "expected missing live evidence prerequisite rc=6, got rc=$local_pack_missing_live_rc"
  cat "$TMP_DIR/local_pack_missing_live.log"
  cat "$SUMMARY_LOCAL_PACK_MISSING_LIVE"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 6
  and .actions[0].id == "profile_default_gate_evidence_pack"
  and .actions[0].failure_kind == "missing_live_evidence_prerequisite"
  and (.actions[0].notes | contains("required live evidence is missing"))
' "$SUMMARY_LOCAL_PACK_MISSING_LIVE" >/dev/null; then
  echo "missing live evidence prerequisite classification mismatch"
  cat "$SUMMARY_LOCAL_PACK_MISSING_LIVE"
  exit 1
fi

echo "[roadmap-next-actions-run] classifies stale prerequisite evidence action failures"
SUMMARY_LOCAL_PACK_STALE="$TMP_DIR/summary_local_pack_stale.json"
REPORTS_LOCAL_PACK_STALE="$TMP_DIR/reports_local_pack_stale"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=local_pack_stale_prereq \
STALE_PREREQ_EVIDENCE="$STALE_PREREQ_EVIDENCE" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_LOCAL_PACK_STALE" \
  --summary-json "$SUMMARY_LOCAL_PACK_STALE" \
  --local-only 1 \
  --print-summary-json 0 >"$TMP_DIR/local_pack_stale.log" 2>&1
local_pack_stale_rc=$?
set -e
if [[ "$local_pack_stale_rc" != "6" ]]; then
  echo "expected stale prerequisite evidence rc=6, got rc=$local_pack_stale_rc"
  cat "$TMP_DIR/local_pack_stale.log"
  cat "$SUMMARY_LOCAL_PACK_STALE"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 6
  and .actions[0].id == "runtime_actuation_promotion_evidence_pack"
  and .actions[0].failure_kind == "stale_prerequisite_evidence"
  and (.actions[0].notes | contains("prerequisite evidence is stale"))
' "$SUMMARY_LOCAL_PACK_STALE" >/dev/null; then
  echo "stale prerequisite evidence classification mismatch"
  cat "$SUMMARY_LOCAL_PACK_STALE"
  exit 1
fi

echo "[roadmap-next-actions-run] classifies real-host signoff prerequisite action failures"
SUMMARY_REAL_HOST_SIGNOFF_REQUIRED="$TMP_DIR/summary_real_host_signoff_required.json"
REPORTS_REAL_HOST_SIGNOFF_REQUIRED="$TMP_DIR/reports_real_host_signoff_required"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=local_pack_real_host_signoff_required \
REAL_HOST_SIGNOFF_REQUIRED="$REAL_HOST_SIGNOFF_REQUIRED" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_REAL_HOST_SIGNOFF_REQUIRED" \
  --summary-json "$SUMMARY_REAL_HOST_SIGNOFF_REQUIRED" \
  --local-only 1 \
  --print-summary-json 0 >"$TMP_DIR/real_host_signoff_required.log" 2>&1
real_host_signoff_required_rc=$?
set -e
if [[ "$real_host_signoff_required_rc" != "6" ]]; then
  echo "expected real-host signoff required rc=6, got rc=$real_host_signoff_required_rc"
  cat "$TMP_DIR/real_host_signoff_required.log"
  cat "$SUMMARY_REAL_HOST_SIGNOFF_REQUIRED"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 6
  and .actions[0].id == "three_machine_real_host_validation_pack"
  and .actions[0].failure_kind == "real_host_signoff_required"
  and (.actions[0].notes | contains("real-host signoff evidence is required"))
' "$SUMMARY_REAL_HOST_SIGNOFF_REQUIRED" >/dev/null; then
  echo "real-host signoff required classification mismatch"
  cat "$SUMMARY_REAL_HOST_SIGNOFF_REQUIRED"
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

echo "[roadmap-next-actions-run] Access Recovery trusted verifier fails closed on unresolved trust-store placeholder"
SUMMARY_ACCESS_RECOVERY_TRUST_STORE_MISSING="$TMP_DIR/summary_access_recovery_trust_store_missing.json"
REPORTS_ACCESS_RECOVERY_TRUST_STORE_MISSING="$TMP_DIR/reports_access_recovery_trust_store_missing"
rm -f "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=access_recovery_trust_store_placeholder \
FAKE_ACCESS_RECOVERY_VERIFY="$FAKE_ACCESS_RECOVERY_VERIFY" \
FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE="$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_ACCESS_RECOVERY_TRUST_STORE_MISSING" \
  --summary-json "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_MISSING" \
  --include-id trusted_pilot_evidence_verify \
  --print-summary-json 0 >"$TMP_DIR/access_recovery_trust_store_missing.log" 2>&1
access_recovery_trust_store_missing_rc=$?
set -e
if [[ "$access_recovery_trust_store_missing_rc" != "2" ]]; then
  echo "expected unresolved Access Recovery trust-store hard-fail rc=2, got rc=$access_recovery_trust_store_missing_rc"
  cat "$TMP_DIR/access_recovery_trust_store_missing.log"
  if [[ -f "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_MISSING" ]]; then
    cat "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_MISSING"
  fi
  exit 1
fi
if [[ -f "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE" ]]; then
  echo "Access Recovery verifier ran despite unresolved trust-store placeholder"
  cat "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 2
  and .inputs.access_recovery_trust_store_configured == false
  and .actions[0].id == "trusted_pilot_evidence_verify"
  and .actions[0].status == "fail"
  and .actions[0].failure_kind == "missing_access_recovery_trust_store_precondition"
  and (.actions[0].next_operator_action | contains("--access-recovery-trust-store REPLACE_WITH_TRUST_STORE"))
' "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_MISSING" >/dev/null; then
  echo "Access Recovery missing trust-store precondition summary mismatch"
  cat "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_MISSING"
  exit 1
fi

echo "[roadmap-next-actions-run] Access Recovery real-helper action reports its own trust-store remediation id"
SUMMARY_ACCESS_RECOVERY_REAL_HELPER_TRUST_STORE_MISSING="$TMP_DIR/summary_access_recovery_real_helper_trust_store_missing.json"
REPORTS_ACCESS_RECOVERY_REAL_HELPER_TRUST_STORE_MISSING="$TMP_DIR/reports_access_recovery_real_helper_trust_store_missing"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=access_recovery_real_helper_trust_store_placeholder \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_ACCESS_RECOVERY_REAL_HELPER_TRUST_STORE_MISSING" \
  --summary-json "$SUMMARY_ACCESS_RECOVERY_REAL_HELPER_TRUST_STORE_MISSING" \
  --include-id real_helper_https_evidence \
  --print-summary-json 0 >"$TMP_DIR/access_recovery_real_helper_trust_store_missing.log" 2>&1
access_recovery_real_helper_trust_store_missing_rc=$?
set -e
if [[ "$access_recovery_real_helper_trust_store_missing_rc" != "2" ]]; then
  echo "expected real-helper Access Recovery trust-store hard-fail rc=2, got rc=$access_recovery_real_helper_trust_store_missing_rc"
  cat "$TMP_DIR/access_recovery_real_helper_trust_store_missing.log"
  if [[ -f "$SUMMARY_ACCESS_RECOVERY_REAL_HELPER_TRUST_STORE_MISSING" ]]; then
    cat "$SUMMARY_ACCESS_RECOVERY_REAL_HELPER_TRUST_STORE_MISSING"
  fi
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 2
  and .inputs.access_recovery_trust_store_configured == false
  and .actions[0].id == "real_helper_https_evidence"
  and .actions[0].status == "fail"
  and .actions[0].failure_kind == "missing_access_recovery_trust_store_precondition"
  and (.actions[0].next_operator_action | contains("--include-id real_helper_https_evidence"))
  and ((.actions[0].next_operator_action | contains("--include-id trusted_pilot_evidence_verify")) | not)
  and (.actions[0].next_operator_action | contains("--access-recovery-trust-store REPLACE_WITH_TRUST_STORE"))
' "$SUMMARY_ACCESS_RECOVERY_REAL_HELPER_TRUST_STORE_MISSING" >/dev/null; then
  echo "Access Recovery real-helper missing trust-store precondition summary mismatch"
  cat "$SUMMARY_ACCESS_RECOVERY_REAL_HELPER_TRUST_STORE_MISSING"
  exit 1
fi

echo "[roadmap-next-actions-run] Access Recovery trusted verifier ignores action-owned concrete trust store"
SUMMARY_ACCESS_RECOVERY_TRUST_STORE_CONCRETE_MISSING="$TMP_DIR/summary_access_recovery_trust_store_concrete_missing.json"
REPORTS_ACCESS_RECOVERY_TRUST_STORE_CONCRETE_MISSING="$TMP_DIR/reports_access_recovery_trust_store_concrete_missing"
ACTION_OWNED_TRUST_STORE="$ACTION_TMP_DIR/action-owned-trust-store.json"
printf '{"trusted_keys":[{"source":"action-owned"}]}\n' >"$ACTION_OWNED_TRUST_STORE"
rm -f "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=access_recovery_trust_store_concrete \
ACTION_OWNED_TRUST_STORE="$ACTION_OWNED_TRUST_STORE" \
FAKE_ACCESS_RECOVERY_VERIFY="$FAKE_ACCESS_RECOVERY_VERIFY" \
FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE="$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_ACCESS_RECOVERY_TRUST_STORE_CONCRETE_MISSING" \
  --summary-json "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_CONCRETE_MISSING" \
  --include-id trusted_pilot_evidence_verify \
  --print-summary-json 0 >"$TMP_DIR/access_recovery_trust_store_concrete_missing.log" 2>&1
access_recovery_trust_store_concrete_missing_rc=$?
set -e
if [[ "$access_recovery_trust_store_concrete_missing_rc" != "2" ]]; then
  echo "expected action-owned Access Recovery trust-store hard-fail rc=2, got rc=$access_recovery_trust_store_concrete_missing_rc"
  cat "$TMP_DIR/access_recovery_trust_store_concrete_missing.log"
  if [[ -f "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_CONCRETE_MISSING" ]]; then
    cat "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_CONCRETE_MISSING"
  fi
  exit 1
fi
if [[ -f "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE" ]]; then
  echo "Access Recovery verifier ran with action-owned trust store despite missing operator trust store"
  cat "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 2
  and .inputs.access_recovery_trust_store_configured == false
  and .actions[0].id == "trusted_pilot_evidence_verify"
  and .actions[0].failure_kind == "missing_access_recovery_trust_store_precondition"
' "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_CONCRETE_MISSING" >/dev/null; then
  echo "Access Recovery action-owned trust-store precondition summary mismatch"
  cat "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_CONCRETE_MISSING"
  exit 1
fi

echo "[roadmap-next-actions-run] Access Recovery trusted verifier fails closed on missing operator trust-store path"
SUMMARY_ACCESS_RECOVERY_TRUST_STORE_CLI_MISSING="$TMP_DIR/summary_access_recovery_trust_store_cli_missing.json"
REPORTS_ACCESS_RECOVERY_TRUST_STORE_CLI_MISSING="$TMP_DIR/reports_access_recovery_trust_store_cli_missing"
ACCESS_RECOVERY_TRUST_STORE_MISSING_FILE="$TMP_DIR/access_recovery_trust_store_missing.json"
rm -f "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE" "$ACCESS_RECOVERY_TRUST_STORE_MISSING_FILE"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=access_recovery_trust_store_placeholder \
FAKE_ACCESS_RECOVERY_VERIFY="$FAKE_ACCESS_RECOVERY_VERIFY" \
FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE="$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_ACCESS_RECOVERY_TRUST_STORE_CLI_MISSING" \
  --summary-json "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_CLI_MISSING" \
  --include-id trusted_pilot_evidence_verify \
  --access-recovery-trust-store "$ACCESS_RECOVERY_TRUST_STORE_MISSING_FILE" \
  --print-summary-json 0 >"$TMP_DIR/access_recovery_trust_store_cli_missing.log" 2>&1
access_recovery_trust_store_cli_missing_rc=$?
set -e
if [[ "$access_recovery_trust_store_cli_missing_rc" != "2" ]]; then
  echo "expected missing operator Access Recovery trust-store hard-fail rc=2, got rc=$access_recovery_trust_store_cli_missing_rc"
  cat "$TMP_DIR/access_recovery_trust_store_cli_missing.log"
  if [[ -f "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_CLI_MISSING" ]]; then
    cat "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_CLI_MISSING"
  fi
  exit 1
fi
if [[ -f "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE" ]]; then
  echo "Access Recovery verifier ran despite missing operator trust-store path"
  cat "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 2
  and .inputs.access_recovery_trust_store_configured == false
  and (.inputs.access_recovery_trust_store_source | contains("missing_or_unreadable"))
  and .actions[0].id == "trusted_pilot_evidence_verify"
  and .actions[0].status == "fail"
  and .actions[0].failure_kind == "missing_access_recovery_trust_store_precondition"
' "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_CLI_MISSING" >/dev/null; then
  echo "Access Recovery missing operator trust-store precondition summary mismatch"
  cat "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_CLI_MISSING"
  exit 1
fi

ACCESS_RECOVERY_TRUST_STORE_FILE="$TMP_DIR/access_recovery_trust_store.json"
printf '{"trusted_keys":[]}\n' >"$ACCESS_RECOVERY_TRUST_STORE_FILE"
ACCESS_RECOVERY_MTLS_CA_FILE="$TMP_DIR/access_recovery_mtls_ca.pem"
ACCESS_RECOVERY_MTLS_CLIENT_CERT_FILE="$TMP_DIR/access_recovery_mtls_client_cert.pem"
ACCESS_RECOVERY_MTLS_CLIENT_KEY_FILE="$TMP_DIR/access_recovery_mtls_client_key.pem"
printf 'test ca\n' >"$ACCESS_RECOVERY_MTLS_CA_FILE"
printf 'test cert\n' >"$ACCESS_RECOVERY_MTLS_CLIENT_CERT_FILE"
printf 'test key\n' >"$ACCESS_RECOVERY_MTLS_CLIENT_KEY_FILE"

echo "[roadmap-next-actions-run] Access Recovery real-helper actions ignore ambient plan-only override"
SUMMARY_ACCESS_RECOVERY_PLAN_ENV_ISOLATION="$TMP_DIR/summary_access_recovery_plan_env_isolation.json"
REPORTS_ACCESS_RECOVERY_PLAN_ENV_ISOLATION="$TMP_DIR/reports_access_recovery_plan_env_isolation"
set +e
ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_PLAN_ONLY=1 \
ROADMAP_NEXT_ACTIONS_SCENARIO=real_helper_plan_env_isolation \
PLAN_ENV_CHECK="$PLAN_ENV_CHECK" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_ACCESS_RECOVERY_PLAN_ENV_ISOLATION" \
  --summary-json "$SUMMARY_ACCESS_RECOVERY_PLAN_ENV_ISOLATION" \
  --include-id real_helper_https_evidence \
  --access-recovery-trust-store "$ACCESS_RECOVERY_TRUST_STORE_FILE" \
  --print-summary-json 0 >"$TMP_DIR/access_recovery_plan_env_isolation.log" 2>&1
access_recovery_plan_env_isolation_rc=$?
set -e
if [[ "$access_recovery_plan_env_isolation_rc" != "0" ]]; then
  echo "expected ambient plan-only override to be stripped before action execution, got rc=$access_recovery_plan_env_isolation_rc"
  cat "$TMP_DIR/access_recovery_plan_env_isolation.log"
  if [[ -f "$SUMMARY_ACCESS_RECOVERY_PLAN_ENV_ISOLATION" ]]; then
    cat "$SUMMARY_ACCESS_RECOVERY_PLAN_ENV_ISOLATION"
  fi
  exit 1
fi
if ! jq -e --arg trust_store "$ACCESS_RECOVERY_TRUST_STORE_FILE" '
  .status == "pass"
  and .rc == 0
  and .inputs.access_recovery_trust_store == $trust_store
  and .inputs.access_recovery_trust_store_configured == true
  and .actions[0].id == "real_helper_https_evidence"
  and .actions[0].status == "pass"
  and .actions[0].rc == 0
' "$SUMMARY_ACCESS_RECOVERY_PLAN_ENV_ISOLATION" >/dev/null; then
  echo "Access Recovery plan-only env isolation summary mismatch"
  cat "$SUMMARY_ACCESS_RECOVERY_PLAN_ENV_ISOLATION"
  exit 1
fi

echo "[roadmap-next-actions-run] Access Recovery real-helper actions reject diagnostic plan-only commands"
SUMMARY_ACCESS_RECOVERY_PLAN_ONLY_ARG="$TMP_DIR/summary_access_recovery_plan_only_arg.json"
REPORTS_ACCESS_RECOVERY_PLAN_ONLY_ARG="$TMP_DIR/reports_access_recovery_plan_only_arg"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=real_helper_plan_only_arg \
PLAN_ENV_CHECK="$PLAN_ENV_CHECK" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_ACCESS_RECOVERY_PLAN_ONLY_ARG" \
  --summary-json "$SUMMARY_ACCESS_RECOVERY_PLAN_ONLY_ARG" \
  --include-id real_helper_https_evidence \
  --access-recovery-trust-store "$ACCESS_RECOVERY_TRUST_STORE_FILE" \
  --print-summary-json 0 >"$TMP_DIR/access_recovery_plan_only_arg.log" 2>&1
access_recovery_plan_only_arg_rc=$?
set -e
if [[ "$access_recovery_plan_only_arg_rc" != "2" ]]; then
  echo "expected Access Recovery plan-only action hard-fail rc=2, got rc=$access_recovery_plan_only_arg_rc"
  cat "$TMP_DIR/access_recovery_plan_only_arg.log"
  if [[ -f "$SUMMARY_ACCESS_RECOVERY_PLAN_ONLY_ARG" ]]; then
    cat "$SUMMARY_ACCESS_RECOVERY_PLAN_ONLY_ARG"
  fi
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 2
  and .actions[0].id == "real_helper_https_evidence"
  and .actions[0].status == "fail"
  and .actions[0].failure_kind == "access_recovery_no_evidence_mode"
  and (.actions[0].notes | contains("must collect evidence"))
  and (.actions[0].command | contains("--plan-only"))
' "$SUMMARY_ACCESS_RECOVERY_PLAN_ONLY_ARG" >/dev/null; then
  echo "Access Recovery plan-only action precondition summary mismatch"
  cat "$SUMMARY_ACCESS_RECOVERY_PLAN_ONLY_ARG"
  exit 1
fi
if ! grep -Fq "failure_kind=access_recovery_no_evidence_mode" "$REPORTS_ACCESS_RECOVERY_PLAN_ONLY_ARG/action_1_real_helper_https_evidence.log"; then
  echo "Access Recovery plan-only action log missing failure kind"
  cat "$REPORTS_ACCESS_RECOVERY_PLAN_ONLY_ARG/action_1_real_helper_https_evidence.log"
  exit 1
fi

echo "[roadmap-next-actions-run] Access Recovery real-helper actions reject verifier-only roadmap-refresh 0 commands"
SUMMARY_ACCESS_RECOVERY_ROADMAP_REFRESH_ZERO_ARG="$TMP_DIR/summary_access_recovery_roadmap_refresh_zero_arg.json"
REPORTS_ACCESS_RECOVERY_ROADMAP_REFRESH_ZERO_ARG="$TMP_DIR/reports_access_recovery_roadmap_refresh_zero_arg"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=real_helper_no_roadmap_refresh_arg \
PLAN_ENV_CHECK="$PLAN_ENV_CHECK" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_ACCESS_RECOVERY_ROADMAP_REFRESH_ZERO_ARG" \
  --summary-json "$SUMMARY_ACCESS_RECOVERY_ROADMAP_REFRESH_ZERO_ARG" \
  --include-id real_helper_https_evidence \
  --access-recovery-trust-store "$ACCESS_RECOVERY_TRUST_STORE_FILE" \
  --print-summary-json 0 >"$TMP_DIR/access_recovery_roadmap_refresh_zero_arg.log" 2>&1
access_recovery_roadmap_refresh_zero_arg_rc=$?
set -e
if [[ "$access_recovery_roadmap_refresh_zero_arg_rc" != "2" ]]; then
  echo "expected Access Recovery roadmap-refresh 0 action hard-fail rc=2, got rc=$access_recovery_roadmap_refresh_zero_arg_rc"
  cat "$TMP_DIR/access_recovery_roadmap_refresh_zero_arg.log"
  if [[ -f "$SUMMARY_ACCESS_RECOVERY_ROADMAP_REFRESH_ZERO_ARG" ]]; then
    cat "$SUMMARY_ACCESS_RECOVERY_ROADMAP_REFRESH_ZERO_ARG"
  fi
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 2
  and .actions[0].id == "real_helper_https_evidence"
  and .actions[0].status == "fail"
  and .actions[0].failure_kind == "access_recovery_no_evidence_mode"
  and (.actions[0].notes | contains("must collect evidence"))
  and (.actions[0].notes | contains("roadmap-refresh 0"))
  and (.actions[0].command | contains("--roadmap-refresh 0"))
' "$SUMMARY_ACCESS_RECOVERY_ROADMAP_REFRESH_ZERO_ARG" >/dev/null; then
  echo "Access Recovery roadmap-refresh 0 action precondition summary mismatch"
  cat "$SUMMARY_ACCESS_RECOVERY_ROADMAP_REFRESH_ZERO_ARG"
  exit 1
fi
if ! grep -Fq "failure_kind=access_recovery_no_evidence_mode" "$REPORTS_ACCESS_RECOVERY_ROADMAP_REFRESH_ZERO_ARG/action_1_real_helper_https_evidence.log"; then
  echo "Access Recovery roadmap-refresh 0 action log missing failure kind"
  cat "$REPORTS_ACCESS_RECOVERY_ROADMAP_REFRESH_ZERO_ARG/action_1_real_helper_https_evidence.log"
  exit 1
fi

echo "[roadmap-next-actions-run] Access Recovery trusted verifier rejects demo-marked operator trust store"
SUMMARY_ACCESS_RECOVERY_TRUST_STORE_DEMO="$TMP_DIR/summary_access_recovery_trust_store_demo.json"
REPORTS_ACCESS_RECOVERY_TRUST_STORE_DEMO="$TMP_DIR/reports_access_recovery_trust_store_demo"
ACCESS_RECOVERY_DEMO_TRUST_STORE_FILE="$TMP_DIR/access_recovery_demo_trust_store.json"
printf '{"trusted_keys":[{"source":"generated demo bundle"}]}\n' >"$ACCESS_RECOVERY_DEMO_TRUST_STORE_FILE"
rm -f "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=access_recovery_trust_store_placeholder \
FAKE_ACCESS_RECOVERY_VERIFY="$FAKE_ACCESS_RECOVERY_VERIFY" \
FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE="$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_ACCESS_RECOVERY_TRUST_STORE_DEMO" \
  --summary-json "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_DEMO" \
  --include-id trusted_pilot_evidence_verify \
  --access-recovery-trust-store "$ACCESS_RECOVERY_DEMO_TRUST_STORE_FILE" \
  --print-summary-json 0 >"$TMP_DIR/access_recovery_trust_store_demo.log" 2>&1
access_recovery_trust_store_demo_rc=$?
set -e
if [[ "$access_recovery_trust_store_demo_rc" != "2" ]]; then
  echo "expected demo-marked Access Recovery trust-store hard-fail rc=2, got rc=$access_recovery_trust_store_demo_rc"
  cat "$TMP_DIR/access_recovery_trust_store_demo.log"
  if [[ -f "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_DEMO" ]]; then
    cat "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_DEMO"
  fi
  exit 1
fi
if [[ -f "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE" ]]; then
  echo "Access Recovery verifier ran despite demo-marked operator trust-store path"
  cat "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 2
  and .inputs.access_recovery_trust_store_configured == false
  and (.inputs.access_recovery_trust_store_source | contains("demo_marked"))
  and .actions[0].id == "trusted_pilot_evidence_verify"
  and .actions[0].status == "fail"
  and .actions[0].failure_kind == "missing_access_recovery_trust_store_precondition"
' "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_DEMO" >/dev/null; then
  echo "Access Recovery demo-marked trust-store precondition summary mismatch"
  cat "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_DEMO"
  exit 1
fi

echo "[roadmap-next-actions-run] Access Recovery trusted verifier rejects copied demo identity trust store"
SUMMARY_ACCESS_RECOVERY_TRUST_STORE_DEMO_IDENTITY="$TMP_DIR/summary_access_recovery_trust_store_demo_identity.json"
REPORTS_ACCESS_RECOVERY_TRUST_STORE_DEMO_IDENTITY="$TMP_DIR/reports_access_recovery_trust_store_demo_identity"
ACCESS_RECOVERY_DEMO_IDENTITY_TRUST_STORE_FILE="$TMP_DIR/access_recovery_demo_identity_trust_store.json"
printf '{"trusted_keys":[{"source":"pilot registry","org_id":"freenews-demo","name":"FreeNews Demo","helper_id":"helper-demo"}]}\n' >"$ACCESS_RECOVERY_DEMO_IDENTITY_TRUST_STORE_FILE"
rm -f "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=access_recovery_trust_store_placeholder \
FAKE_ACCESS_RECOVERY_VERIFY="$FAKE_ACCESS_RECOVERY_VERIFY" \
FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE="$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_ACCESS_RECOVERY_TRUST_STORE_DEMO_IDENTITY" \
  --summary-json "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_DEMO_IDENTITY" \
  --include-id trusted_pilot_evidence_verify \
  --access-recovery-trust-store "$ACCESS_RECOVERY_DEMO_IDENTITY_TRUST_STORE_FILE" \
  --print-summary-json 0 >"$TMP_DIR/access_recovery_trust_store_demo_identity.log" 2>&1
access_recovery_trust_store_demo_identity_rc=$?
set -e
if [[ "$access_recovery_trust_store_demo_identity_rc" != "2" ]]; then
  echo "expected demo-identity Access Recovery trust-store hard-fail rc=2, got rc=$access_recovery_trust_store_demo_identity_rc"
  cat "$TMP_DIR/access_recovery_trust_store_demo_identity.log"
  if [[ -f "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_DEMO_IDENTITY" ]]; then
    cat "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_DEMO_IDENTITY"
  fi
  exit 1
fi
if [[ -f "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE" ]]; then
  echo "Access Recovery verifier ran despite demo-identity operator trust-store"
  cat "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 2
  and .inputs.access_recovery_trust_store_configured == false
  and (.inputs.access_recovery_trust_store_source | contains("demo_marked"))
  and .actions[0].id == "trusted_pilot_evidence_verify"
  and .actions[0].status == "fail"
  and .actions[0].failure_kind == "missing_access_recovery_trust_store_precondition"
' "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_DEMO_IDENTITY" >/dev/null; then
  echo "Access Recovery demo-identity trust-store precondition summary mismatch"
  cat "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_DEMO_IDENTITY"
  exit 1
fi

echo "[roadmap-next-actions-run] Access Recovery trusted verifier rejects raw public-key handoff"
SUMMARY_ACCESS_RECOVERY_PUBLIC_KEY_HANDOFF="$TMP_DIR/summary_access_recovery_public_key_handoff.json"
REPORTS_ACCESS_RECOVERY_PUBLIC_KEY_HANDOFF="$TMP_DIR/reports_access_recovery_public_key_handoff"
: >"$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=access_recovery_public_key_handoff \
FAKE_ACCESS_RECOVERY_VERIFY="$FAKE_ACCESS_RECOVERY_VERIFY" \
FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE="$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_ACCESS_RECOVERY_PUBLIC_KEY_HANDOFF" \
  --summary-json "$SUMMARY_ACCESS_RECOVERY_PUBLIC_KEY_HANDOFF" \
  --include-id trusted_pilot_evidence_verify \
  --access-recovery-trust-store "$ACCESS_RECOVERY_TRUST_STORE_FILE" \
  --print-summary-json 0 >"$TMP_DIR/access_recovery_public_key_handoff.log" 2>&1
access_recovery_public_key_handoff_rc=$?
set -e
if [[ "$access_recovery_public_key_handoff_rc" != "2" ]]; then
  echo "expected raw public-key Access Recovery handoff hard-fail rc=2, got rc=$access_recovery_public_key_handoff_rc"
  cat "$TMP_DIR/access_recovery_public_key_handoff.log"
  if [[ -f "$SUMMARY_ACCESS_RECOVERY_PUBLIC_KEY_HANDOFF" ]]; then
    cat "$SUMMARY_ACCESS_RECOVERY_PUBLIC_KEY_HANDOFF"
  fi
  exit 1
fi
if [[ -s "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE" ]]; then
  echo "Access Recovery verifier ran despite raw public-key handoff"
  cat "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE"
  exit 1
fi
if ! jq -e --arg trust_store "$ACCESS_RECOVERY_TRUST_STORE_FILE" '
  .status == "fail"
  and .rc == 2
  and .inputs.access_recovery_trust_store == $trust_store
  and .inputs.access_recovery_trust_store_configured == true
  and .actions[0].id == "trusted_pilot_evidence_verify"
  and .actions[0].status == "fail"
  and .actions[0].failure_kind == "missing_access_recovery_trust_store_precondition"
  and (.actions[0].notes | contains("raw public-key handoff"))
  and (.actions[0].command | contains("--public-key-file"))
' "$SUMMARY_ACCESS_RECOVERY_PUBLIC_KEY_HANDOFF" >/dev/null; then
  echo "Access Recovery raw public-key handoff precondition summary mismatch"
  cat "$SUMMARY_ACCESS_RECOVERY_PUBLIC_KEY_HANDOFF"
  exit 1
fi

echo "[roadmap-next-actions-run] Access Recovery real-helper action fails closed on unresolved operator placeholders"
SUMMARY_ACCESS_RECOVERY_OPERATOR_PLACEHOLDERS="$TMP_DIR/summary_access_recovery_operator_placeholders.json"
REPORTS_ACCESS_RECOVERY_OPERATOR_PLACEHOLDERS="$TMP_DIR/reports_access_recovery_operator_placeholders"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=access_recovery_real_helper_operator_placeholders \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_ACCESS_RECOVERY_OPERATOR_PLACEHOLDERS" \
  --summary-json "$SUMMARY_ACCESS_RECOVERY_OPERATOR_PLACEHOLDERS" \
  --include-id real_helper_https_evidence \
  --access-recovery-trust-store "$ACCESS_RECOVERY_TRUST_STORE_FILE" \
  --print-summary-json 0 >"$TMP_DIR/access_recovery_operator_placeholders.log" 2>&1
access_recovery_operator_placeholders_rc=$?
set -e
if [[ "$access_recovery_operator_placeholders_rc" != "2" ]]; then
  echo "expected unresolved Access Recovery operator placeholder hard-fail rc=2, got rc=$access_recovery_operator_placeholders_rc"
  cat "$TMP_DIR/access_recovery_operator_placeholders.log"
  if [[ -f "$SUMMARY_ACCESS_RECOVERY_OPERATOR_PLACEHOLDERS" ]]; then
    cat "$SUMMARY_ACCESS_RECOVERY_OPERATOR_PLACEHOLDERS"
  fi
  exit 1
fi
if ! jq -e --arg trust_store "$ACCESS_RECOVERY_TRUST_STORE_FILE" '
  .status == "fail"
  and .rc == 2
  and .inputs.access_recovery_trust_store == $trust_store
  and .inputs.access_recovery_trust_store_configured == true
  and .actions[0].id == "real_helper_https_evidence"
  and .actions[0].status == "fail"
  and .actions[0].failure_kind == "missing_access_recovery_operator_input_precondition"
  and (.actions[0].notes | contains("HELPER_PUBLIC_DNS"))
  and (.actions[0].notes | contains("PROVENANCE_PRIVATE_KEY_FILE"))
  and (.actions[0].command | contains("--trust-store " + $trust_store))
  and (.actions[0].command | contains("HELPER_PUBLIC_DNS"))
  and (.actions[0].next_operator_action | contains("--include-id real_helper_https_evidence"))
  and (.actions[0].next_operator_action | contains("HELPER_PUBLIC_DNS"))
' "$SUMMARY_ACCESS_RECOVERY_OPERATOR_PLACEHOLDERS" >/dev/null; then
  echo "Access Recovery unresolved operator placeholder precondition summary mismatch"
  cat "$SUMMARY_ACCESS_RECOVERY_OPERATOR_PLACEHOLDERS"
  exit 1
fi

echo "[roadmap-next-actions-run] Access Recovery helper-id placeholders fail closed"
SUMMARY_ACCESS_RECOVERY_HELPER_ID_PLACEHOLDER="$TMP_DIR/summary_access_recovery_helper_id_placeholder.json"
REPORTS_ACCESS_RECOVERY_HELPER_ID_PLACEHOLDER="$TMP_DIR/reports_access_recovery_helper_id_placeholder"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=access_recovery_service_smoke_helper_id_placeholder \
PASS1="$PASS1" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_ACCESS_RECOVERY_HELPER_ID_PLACEHOLDER" \
  --summary-json "$SUMMARY_ACCESS_RECOVERY_HELPER_ID_PLACEHOLDER" \
  --include-id access_bridge_service_smoke \
  --print-summary-json 0 >"$TMP_DIR/access_recovery_helper_id_placeholder.log" 2>&1
access_recovery_helper_id_placeholder_rc=$?
set -e
if [[ "$access_recovery_helper_id_placeholder_rc" != "2" ]]; then
  echo "expected unresolved Access Recovery HELPER_ID placeholder hard-fail rc=2, got rc=$access_recovery_helper_id_placeholder_rc"
  cat "$TMP_DIR/access_recovery_helper_id_placeholder.log"
  if [[ -f "$SUMMARY_ACCESS_RECOVERY_HELPER_ID_PLACEHOLDER" ]]; then
    cat "$SUMMARY_ACCESS_RECOVERY_HELPER_ID_PLACEHOLDER"
  fi
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 2
  and .actions[0].id == "access_bridge_service_smoke"
  and .actions[0].status == "fail"
  and .actions[0].failure_kind == "missing_access_recovery_operator_input_precondition"
  and (.actions[0].notes | contains("HELPER_ID"))
  and (.actions[0].command | contains("--expect-helper-id HELPER_ID"))
  and (.actions[0].next_operator_action | contains("--include-id access_bridge_service_smoke"))
' "$SUMMARY_ACCESS_RECOVERY_HELPER_ID_PLACEHOLDER" >/dev/null; then
  echo "Access Recovery HELPER_ID placeholder precondition summary mismatch"
  cat "$SUMMARY_ACCESS_RECOVERY_HELPER_ID_PLACEHOLDER"
  exit 1
fi

echo "[roadmap-next-actions-run] Access Recovery installed-host action fails closed on unresolved operator placeholders"
SUMMARY_ACCESS_RECOVERY_INSTALLED_HOST_PLACEHOLDERS="$TMP_DIR/summary_access_recovery_installed_host_placeholders.json"
REPORTS_ACCESS_RECOVERY_INSTALLED_HOST_PLACEHOLDERS="$TMP_DIR/reports_access_recovery_installed_host_placeholders"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=access_recovery_installed_host_operator_placeholders \
PASS1="$PASS1" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_ACCESS_RECOVERY_INSTALLED_HOST_PLACEHOLDERS" \
  --summary-json "$SUMMARY_ACCESS_RECOVERY_INSTALLED_HOST_PLACEHOLDERS" \
  --include-id access_bridge_installed_host_evidence \
  --print-summary-json 0 >"$TMP_DIR/access_recovery_installed_host_placeholders.log" 2>&1
access_recovery_installed_host_placeholders_rc=$?
set -e
if [[ "$access_recovery_installed_host_placeholders_rc" != "2" ]]; then
  echo "expected unresolved Access Recovery installed-host placeholder hard-fail rc=2, got rc=$access_recovery_installed_host_placeholders_rc"
  cat "$TMP_DIR/access_recovery_installed_host_placeholders.log"
  if [[ -f "$SUMMARY_ACCESS_RECOVERY_INSTALLED_HOST_PLACEHOLDERS" ]]; then
    cat "$SUMMARY_ACCESS_RECOVERY_INSTALLED_HOST_PLACEHOLDERS"
  fi
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 2
  and .actions[0].id == "access_bridge_installed_host_evidence"
  and .actions[0].status == "fail"
  and .actions[0].failure_kind == "missing_access_recovery_operator_input_precondition"
  and (.actions[0].notes | contains("HELPER_PUBLIC_DNS"))
  and (.actions[0].notes | contains("BRIDGE_SERVICE_CONFIG"))
  and (.actions[0].command | contains("--evidence-mode installed-host"))
  and (.actions[0].command | contains("HELPER_PUBLIC_DNS"))
  and (.actions[0].next_operator_action | contains("--include-id access_bridge_installed_host_evidence"))
' "$SUMMARY_ACCESS_RECOVERY_INSTALLED_HOST_PLACEHOLDERS" >/dev/null; then
  echo "Access Recovery installed-host unresolved operator placeholder precondition summary mismatch"
  cat "$SUMMARY_ACCESS_RECOVERY_INSTALLED_HOST_PLACEHOLDERS"
  exit 1
fi

echo "[roadmap-next-actions-run] Access Recovery installed-host action executes with concrete operator inputs"
SUMMARY_ACCESS_RECOVERY_INSTALLED_HOST_CONCRETE="$TMP_DIR/summary_access_recovery_installed_host_concrete.json"
REPORTS_ACCESS_RECOVERY_INSTALLED_HOST_CONCRETE="$TMP_DIR/reports_access_recovery_installed_host_concrete"
ROADMAP_NEXT_ACTIONS_SCENARIO=access_recovery_installed_host_concrete \
PASS1="$PASS1" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_ACCESS_RECOVERY_INSTALLED_HOST_CONCRETE" \
  --summary-json "$SUMMARY_ACCESS_RECOVERY_INSTALLED_HOST_CONCRETE" \
  --include-id access_bridge_installed_host_evidence \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .actions[0].id == "access_bridge_installed_host_evidence"
  and .actions[0].status == "pass"
  and .actions[0].failure_kind == "none"
  and (.actions[0].command | contains("--evidence-mode installed-host"))
  and (.actions[0].command | contains("https://helper.gpm-pilot.net"))
  and ((.actions[0].command | contains("HELPER_PUBLIC_DNS")) | not)
  and ((.actions[0].command | contains("BRIDGE_SERVICE_CONFIG")) | not)
' "$SUMMARY_ACCESS_RECOVERY_INSTALLED_HOST_CONCRETE" >/dev/null; then
  echo "Access Recovery installed-host concrete action summary mismatch"
  cat "$SUMMARY_ACCESS_RECOVERY_INSTALLED_HOST_CONCRETE"
  exit 1
fi

echo "[roadmap-next-actions-run] Access Recovery placeholder-like concrete slugs execute"
SUMMARY_ACCESS_RECOVERY_PLACEHOLDER_LIKE_CONCRETE="$TMP_DIR/summary_access_recovery_placeholder_like_concrete.json"
REPORTS_ACCESS_RECOVERY_PLACEHOLDER_LIKE_CONCRETE="$TMP_DIR/reports_access_recovery_placeholder_like_concrete"
ROADMAP_NEXT_ACTIONS_SCENARIO=access_recovery_placeholder_like_concrete_values \
PASS1="$PASS1" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_ACCESS_RECOVERY_PLACEHOLDER_LIKE_CONCRETE" \
  --summary-json "$SUMMARY_ACCESS_RECOVERY_PLACEHOLDER_LIKE_CONCRETE" \
  --include-id access_bridge_service_smoke \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .actions[0].id == "access_bridge_service_smoke"
  and .actions[0].status == "pass"
  and .actions[0].failure_kind == "none"
  and (.actions[0].command | contains("helper_id-prod"))
  and (.actions[0].command | contains("org_id-prod"))
  and (.actions[0].command | contains("helper_public_dns-prod.example"))
' "$SUMMARY_ACCESS_RECOVERY_PLACEHOLDER_LIKE_CONCRETE" >/dev/null; then
  echo "Access Recovery placeholder-like concrete action summary mismatch"
  cat "$SUMMARY_ACCESS_RECOVERY_PLACEHOLDER_LIKE_CONCRETE"
  exit 1
fi

echo "[roadmap-next-actions-run] Access Recovery required-mTLS placeholders fail closed"
SUMMARY_ACCESS_RECOVERY_MTLS_PLACEHOLDERS="$TMP_DIR/summary_access_recovery_mtls_placeholders.json"
REPORTS_ACCESS_RECOVERY_MTLS_PLACEHOLDERS="$TMP_DIR/reports_access_recovery_mtls_placeholders"
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=access_recovery_mtls_operator_placeholders \
PASS1="$PASS1" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_ACCESS_RECOVERY_MTLS_PLACEHOLDERS" \
  --summary-json "$SUMMARY_ACCESS_RECOVERY_MTLS_PLACEHOLDERS" \
  --include-id access_bridge_service_smoke \
  --access-recovery-trust-store "$ACCESS_RECOVERY_TRUST_STORE_FILE" \
  --print-summary-json 0 >"$TMP_DIR/access_recovery_mtls_placeholders.log" 2>&1
access_recovery_mtls_placeholders_rc=$?
set -e
if [[ "$access_recovery_mtls_placeholders_rc" != "2" ]]; then
  echo "expected unresolved Access Recovery mTLS placeholder hard-fail rc=2, got rc=$access_recovery_mtls_placeholders_rc"
  cat "$TMP_DIR/access_recovery_mtls_placeholders.log"
  if [[ -f "$SUMMARY_ACCESS_RECOVERY_MTLS_PLACEHOLDERS" ]]; then
    cat "$SUMMARY_ACCESS_RECOVERY_MTLS_PLACEHOLDERS"
  fi
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 2
  and .actions[0].id == "access_bridge_service_smoke"
  and .actions[0].status == "fail"
  and .actions[0].failure_kind == "missing_access_recovery_operator_input_precondition"
  and (.actions[0].notes | contains("MTLS_CA_FILE"))
  and (.actions[0].notes | contains("MTLS_CLIENT_CERT_FILE"))
  and (.actions[0].notes | contains("MTLS_CLIENT_KEY_FILE"))
  and (.actions[0].command | contains("--require-mtls 1"))
  and (.actions[0].command | contains("MTLS_CLIENT_CERT_FILE"))
  and (.actions[0].next_operator_action | contains("--include-id access_bridge_service_smoke"))
' "$SUMMARY_ACCESS_RECOVERY_MTLS_PLACEHOLDERS" >/dev/null; then
  echo "Access Recovery unresolved mTLS placeholder precondition summary mismatch"
  cat "$SUMMARY_ACCESS_RECOVERY_MTLS_PLACEHOLDERS"
  exit 1
fi

echo "[roadmap-next-actions-run] Access Recovery required-mTLS placeholders use configured cert inputs"
SUMMARY_ACCESS_RECOVERY_MTLS_OVERRIDE="$TMP_DIR/summary_access_recovery_mtls_override.json"
REPORTS_ACCESS_RECOVERY_MTLS_OVERRIDE="$TMP_DIR/reports_access_recovery_mtls_override"
ROADMAP_NEXT_ACTIONS_SCENARIO=access_recovery_mtls_operator_placeholders \
PASS1="$PASS1" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_ACCESS_RECOVERY_MTLS_OVERRIDE" \
  --summary-json "$SUMMARY_ACCESS_RECOVERY_MTLS_OVERRIDE" \
  --include-id access_bridge_service_smoke \
  --access-recovery-mtls-ca "$ACCESS_RECOVERY_MTLS_CA_FILE" \
  --access-recovery-mtls-client-cert "$ACCESS_RECOVERY_MTLS_CLIENT_CERT_FILE" \
  --access-recovery-mtls-client-key "$ACCESS_RECOVERY_MTLS_CLIENT_KEY_FILE" \
  --print-summary-json 0

if ! jq -e \
  --arg mtls_ca "$ACCESS_RECOVERY_MTLS_CA_FILE" \
  --arg mtls_cert "$ACCESS_RECOVERY_MTLS_CLIENT_CERT_FILE" \
  --arg mtls_key "$ACCESS_RECOVERY_MTLS_CLIENT_KEY_FILE" \
  '
  .status == "pass"
  and .rc == 0
  and .inputs.access_recovery_mtls_ca == $mtls_ca
  and .inputs.access_recovery_mtls_ca_configured == true
  and .inputs.access_recovery_mtls_ca_source == "cli:--access-recovery-mtls-ca"
  and .inputs.access_recovery_mtls_client_cert == $mtls_cert
  and .inputs.access_recovery_mtls_client_cert_configured == true
  and .inputs.access_recovery_mtls_client_cert_source == "cli:--access-recovery-mtls-client-cert"
  and .inputs.access_recovery_mtls_client_key == $mtls_key
  and .inputs.access_recovery_mtls_client_key_configured == true
  and .inputs.access_recovery_mtls_client_key_source == "cli:--access-recovery-mtls-client-key"
  and .actions[0].id == "access_bridge_service_smoke"
  and .actions[0].status == "pass"
  and (.actions[0].command | contains("--require-mtls 1"))
  and (.actions[0].command | contains("--cacert " + $mtls_ca))
  and (.actions[0].command | contains("--client-cert " + $mtls_cert))
  and (.actions[0].command | contains("--client-key " + $mtls_key))
  and ((.actions[0].command | contains("MTLS_CA_FILE")) | not)
  and ((.actions[0].command | contains("MTLS_CLIENT_CERT_FILE")) | not)
  and ((.actions[0].command | contains("MTLS_CLIENT_KEY_FILE")) | not)
' "$SUMMARY_ACCESS_RECOVERY_MTLS_OVERRIDE" >/dev/null; then
  echo "Access Recovery mTLS cert override summary mismatch"
  cat "$SUMMARY_ACCESS_RECOVERY_MTLS_OVERRIDE"
  exit 1
fi

echo "[roadmap-next-actions-run] Access Recovery trusted verifier substitutes configured trust store"
SUMMARY_ACCESS_RECOVERY_TRUST_STORE_OVERRIDE="$TMP_DIR/summary_access_recovery_trust_store_override.json"
REPORTS_ACCESS_RECOVERY_TRUST_STORE_OVERRIDE="$TMP_DIR/reports_access_recovery_trust_store_override"
: >"$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE"
ROADMAP_NEXT_ACTIONS_SCENARIO=access_recovery_trust_store_placeholder \
FAKE_ACCESS_RECOVERY_VERIFY="$FAKE_ACCESS_RECOVERY_VERIFY" \
FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE="$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_ACCESS_RECOVERY_TRUST_STORE_OVERRIDE" \
  --summary-json "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_OVERRIDE" \
  --include-id trusted_pilot_evidence_verify \
  --access-recovery-trust-store "$ACCESS_RECOVERY_TRUST_STORE_FILE" \
  --print-summary-json 0

if ! jq -e --arg trust_store "$ACCESS_RECOVERY_TRUST_STORE_FILE" '
  .status == "pass"
  and .rc == 0
  and .inputs.access_recovery_trust_store == $trust_store
  and .inputs.access_recovery_trust_store_configured == true
  and .inputs.access_recovery_trust_store_source == "cli:--access-recovery-trust-store"
  and .actions[0].id == "trusted_pilot_evidence_verify"
  and .actions[0].status == "pass"
  and (.actions[0].command | contains("--trust-store " + $trust_store))
  and (.actions[0].command | contains("TRUST_STORE") | not)
' "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_OVERRIDE" >/dev/null; then
  echo "Access Recovery trust-store override summary mismatch"
  cat "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_OVERRIDE"
  exit 1
fi
if ! grep -F -- "--trust-store" "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE" >/dev/null || grep -F -- "TRUST_STORE" "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE" >/dev/null; then
  echo "Access Recovery verifier capture missing substituted trust store"
  cat "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE"
  exit 1
fi

echo "[roadmap-next-actions-run] Access Recovery trust-store substitution only rewrites trust-store argv"
SUMMARY_ACCESS_RECOVERY_TRUST_STORE_PRECISE_OVERRIDE="$TMP_DIR/summary_access_recovery_trust_store_precise_override.json"
REPORTS_ACCESS_RECOVERY_TRUST_STORE_PRECISE_OVERRIDE="$TMP_DIR/reports_access_recovery_trust_store_precise_override"
: >"$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE"
ROADMAP_NEXT_ACTIONS_SCENARIO=access_recovery_trust_store_placeholder_extra_tokens \
FAKE_ACCESS_RECOVERY_VERIFY="$FAKE_ACCESS_RECOVERY_VERIFY" \
FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE="$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_ACCESS_RECOVERY_TRUST_STORE_PRECISE_OVERRIDE" \
  --summary-json "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_PRECISE_OVERRIDE" \
  --include-id trusted_pilot_evidence_verify \
  --access-recovery-trust-store "$ACCESS_RECOVERY_TRUST_STORE_FILE" \
  --print-summary-json 0

if ! jq -e --arg trust_store "$ACCESS_RECOVERY_TRUST_STORE_FILE" '
  .status == "pass"
  and .rc == 0
  and .inputs.access_recovery_trust_store == $trust_store
  and .actions[0].status == "pass"
  and (.actions[0].command | contains("--trust-store " + $trust_store))
  and (.actions[0].command | contains("TRUST_STORE_receipt.json"))
  and (.actions[0].command | contains("TRUST_STORE_AUDIT"))
' "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_PRECISE_OVERRIDE" >/dev/null; then
  echo "Access Recovery precise trust-store override summary mismatch"
  cat "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_PRECISE_OVERRIDE"
  exit 1
fi
if ! grep -F -- "--trust-store $ACCESS_RECOVERY_TRUST_STORE_FILE" "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE" >/dev/null \
   || ! grep -F -- "TRUST_STORE_receipt.json" "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE" >/dev/null \
   || ! grep -F -- "TRUST_STORE_AUDIT" "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE" >/dev/null; then
  echo "Access Recovery verifier capture did not preserve non-trust-store placeholder-like tokens"
  cat "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE"
  exit 1
fi

echo "[roadmap-next-actions-run] Access Recovery override replaces action-owned concrete trust store"
SUMMARY_ACCESS_RECOVERY_TRUST_STORE_CONCRETE_OVERRIDE="$TMP_DIR/summary_access_recovery_trust_store_concrete_override.json"
REPORTS_ACCESS_RECOVERY_TRUST_STORE_CONCRETE_OVERRIDE="$TMP_DIR/reports_access_recovery_trust_store_concrete_override"
: >"$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE"
ROADMAP_NEXT_ACTIONS_SCENARIO=access_recovery_trust_store_concrete \
ACTION_OWNED_TRUST_STORE="$ACTION_OWNED_TRUST_STORE" \
FAKE_ACCESS_RECOVERY_VERIFY="$FAKE_ACCESS_RECOVERY_VERIFY" \
FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE="$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_ACCESS_RECOVERY_TRUST_STORE_CONCRETE_OVERRIDE" \
  --summary-json "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_CONCRETE_OVERRIDE" \
  --include-id trusted_pilot_evidence_verify \
  --access-recovery-trust-store "$ACCESS_RECOVERY_TRUST_STORE_FILE" \
  --print-summary-json 0

if ! jq -e --arg trust_store "$ACCESS_RECOVERY_TRUST_STORE_FILE" --arg action_store "$ACTION_OWNED_TRUST_STORE" '
  .status == "pass"
  and .rc == 0
  and .inputs.access_recovery_trust_store == $trust_store
  and .actions[0].status == "pass"
  and (.actions[0].command | contains("--trust-store " + $trust_store))
  and (.actions[0].command | contains($action_store) | not)
' "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_CONCRETE_OVERRIDE" >/dev/null; then
  echo "Access Recovery concrete trust-store override summary mismatch"
  cat "$SUMMARY_ACCESS_RECOVERY_TRUST_STORE_CONCRETE_OVERRIDE"
  exit 1
fi
if grep -F -- "$ACTION_OWNED_TRUST_STORE" "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE" >/dev/null; then
  echo "Access Recovery verifier capture retained action-owned trust store"
  cat "$FAKE_ACCESS_RECOVERY_VERIFY_CAPTURE"
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
if [[ ! -L "$SYMLINK_ESCAPE_LINK" ]]; then
  echo "[roadmap-next-actions-run] TOCTOU revalidation skipped (symlink unsupported in current environment)"
else
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
set +e
ROADMAP_NEXT_ACTIONS_SCENARIO=no_actions \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_EMPTY" \
  --summary-json "$SUMMARY_EMPTY" \
  --print-summary-json 0
empty_rc=$?
set -e
if [[ "$empty_rc" != "4" ]]; then
  echo "expected no-actions fail-closed rc=4, got rc=$empty_rc"
  cat "$SUMMARY_EMPTY"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 4
  and .roadmap.actions_selected_count == 0
  and .roadmap.selected_action_ids == []
  and .summary.actions_executed == 0
  and .summary.empty_actions_allowed == false
  and .summary.pass == 0
  and .summary.fail == 0
  and .summary.timed_out == 0
  and ((.actions // []) | length == 0)
' "$SUMMARY_EMPTY" >/dev/null; then
  echo "no-actions summary mismatch"
  cat "$SUMMARY_EMPTY"
  exit 1
fi

echo "[roadmap-next-actions-run] no-actions explicit allow override"
SUMMARY_EMPTY_ALLOWED="$TMP_DIR/summary_empty_allowed.json"
REPORTS_EMPTY_ALLOWED="$TMP_DIR/reports_empty_allowed"
ROADMAP_NEXT_ACTIONS_SCENARIO=no_actions \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_next_actions_run.sh \
  --reports-dir "$REPORTS_EMPTY_ALLOWED" \
  --summary-json "$SUMMARY_EMPTY_ALLOWED" \
  --allow-empty-actions 1 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.allow_empty_actions == true
  and .summary.empty_actions_allowed == true
  and .roadmap.actions_selected_count == 0
  and .summary.actions_executed == 0
  and ((.actions // []) | length == 0)
' "$SUMMARY_EMPTY_ALLOWED" >/dev/null; then
  echo "no-actions allow override summary mismatch"
  cat "$SUMMARY_EMPTY_ALLOWED"
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
