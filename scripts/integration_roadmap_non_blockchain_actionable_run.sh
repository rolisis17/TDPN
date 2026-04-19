#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod mkdir cat grep timeout; do
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
FAIL2="$TMP_DIR/fail_action_2.sh"
SLOW1="$TMP_DIR/slow_action_1.sh"
SLOW2="$TMP_DIR/slow_action_2.sh"

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

cat >"$FAIL2" <<'EOF_FAIL2'
#!/usr/bin/env bash
set -euo pipefail
echo "fail action 2"
exit 19
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
scenario="${ROADMAP_ACTIONABLE_SCENARIO:-pass}"
case "$scenario" in
  pass)
    cat >"$summary_json" <<JSON
{
  "vpn_track": {
    "non_blockchain_recommended_gate_id": "action_pass_1",
    "non_blockchain_actionable_no_sudo_or_github": [
      {"id":"action_pass_1","label":"Action pass 1","command":"bash \"$PASS1\"","reason":"test"},
      {"id":"action_pass_2","label":"Action pass 2","command":"bash \"$PASS2\"","reason":"test"}
    ]
  }
}
JSON
    ;;
  phase1_gate)
    cat >"$summary_json" <<JSON
{
  "vpn_track": {
    "non_blockchain_recommended_gate_id": "phase1_resilience_handoff_run_dry",
    "non_blockchain_actionable_no_sudo_or_github": [
      {"id":"phase1_resilience_handoff_run_dry","label":"Phase1 dry gate","command":"bash \"$PASS1\"","reason":"status=fail"}
    ]
  }
}
JSON
    ;;
  recommended_missing)
    cat >"$summary_json" <<JSON
{
  "vpn_track": {
    "non_blockchain_recommended_gate_id": "action_missing_1",
    "non_blockchain_actionable_no_sudo_or_github": [
      {"id":"action_pass_1","label":"Action pass 1","command":"bash \"$PASS1\"","reason":"test"},
      {"id":"action_pass_2","label":"Action pass 2","command":"bash \"$PASS2\"","reason":"test"}
    ]
  }
}
JSON
    ;;
  fail_second)
    cat >"$summary_json" <<JSON
{
  "vpn_track": {
    "non_blockchain_recommended_gate_id": "action_pass_1",
    "non_blockchain_actionable_no_sudo_or_github": [
      {"id":"action_pass_1","label":"Action pass 1","command":"bash \"$PASS1\"","reason":"test"},
      {"id":"action_fail_2","label":"Action fail 2","command":"bash \"$FAIL2\"","reason":"test"}
    ]
  }
}
JSON
    ;;
  timeout_first_then_pass)
    cat >"$summary_json" <<JSON
{
  "vpn_track": {
    "non_blockchain_recommended_gate_id": "action_timeout_1",
    "non_blockchain_actionable_no_sudo_or_github": [
      {"id":"action_timeout_1","label":"Action timeout 1","command":"bash \"$SLOW1\"","reason":"test-timeout"},
      {"id":"action_pass_2","label":"Action pass 2","command":"bash \"$PASS2\"","reason":"test"}
    ]
  }
}
JSON
    ;;
  parallel_two_slow)
    cat >"$summary_json" <<JSON
{
  "vpn_track": {
    "non_blockchain_recommended_gate_id": "action_slow_1",
    "non_blockchain_actionable_no_sudo_or_github": [
      {"id":"action_slow_1","label":"Action slow 1","command":"bash \"$SLOW1\"","reason":"test-parallel"},
      {"id":"action_slow_2","label":"Action slow 2","command":"bash \"$SLOW2\"","reason":"test-parallel"}
    ]
  }
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

echo "[roadmap-non-blockchain-actionable-run] help contract for --parallel"
if ! ./scripts/roadmap_non_blockchain_actionable_run.sh --help | grep -F -- "--parallel [0|1]" >/dev/null; then
  echo "help output missing --parallel [0|1]"
  exit 1
fi

echo "[roadmap-non-blockchain-actionable-run] --parallel forwarding contract (CLI + env)"
SUMMARY_PARALLEL_FORWARD_CLI="$TMP_DIR/summary_parallel_forward_cli.json"
REPORTS_PARALLEL_FORWARD_CLI="$TMP_DIR/reports_parallel_forward_cli"
ROADMAP_ACTIONABLE_SCENARIO=pass \
PASS1="$PASS1" PASS2="$PASS2" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
./scripts/roadmap_non_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_PARALLEL_FORWARD_CLI" \
  --summary-json "$SUMMARY_PARALLEL_FORWARD_CLI" \
  --parallel 1 \
  --max-actions 1 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.parallel == true
  and .roadmap.actions_selected_count == 1
  and .summary.actions_executed == 1
  and ((.actions // []) | length == 1)
  and .actions[0].status == "pass"
' "$SUMMARY_PARALLEL_FORWARD_CLI" >/dev/null; then
  echo "parallel forwarding CLI summary mismatch"
  cat "$SUMMARY_PARALLEL_FORWARD_CLI"
  exit 1
fi

SUMMARY_PARALLEL_FORWARD_ENV="$TMP_DIR/summary_parallel_forward_env.json"
REPORTS_PARALLEL_FORWARD_ENV="$TMP_DIR/reports_parallel_forward_env"
ROADMAP_ACTIONABLE_SCENARIO=pass \
PASS1="$PASS1" PASS2="$PASS2" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_PARALLEL=1 \
./scripts/roadmap_non_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_PARALLEL_FORWARD_ENV" \
  --summary-json "$SUMMARY_PARALLEL_FORWARD_ENV" \
  --max-actions 1 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.parallel == true
  and .roadmap.actions_selected_count == 1
  and .summary.actions_executed == 1
  and ((.actions // []) | length == 1)
  and .actions[0].status == "pass"
' "$SUMMARY_PARALLEL_FORWARD_ENV" >/dev/null; then
  echo "parallel forwarding env summary mismatch"
  cat "$SUMMARY_PARALLEL_FORWARD_ENV"
  exit 1
fi

echo "[roadmap-non-blockchain-actionable-run] success path"
SUMMARY_PASS="$TMP_DIR/summary_pass.json"
REPORTS_PASS="$TMP_DIR/reports_pass"
ROADMAP_ACTIONABLE_SCENARIO=pass \
PASS1="$PASS1" PASS2="$PASS2" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
./scripts/roadmap_non_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_PASS" \
  --summary-json "$SUMMARY_PASS" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.action_timeout_sec == 0
  and .inputs.parallel == false
  and .roadmap.actions_selected_count == 2
  and .summary.actions_executed == 2
  and .summary.pass == 2
  and .summary.fail == 0
  and .summary.timed_out == 0
  and ((.actions // []) | length == 2)
  and ((.actions // []) | all(.status == "pass" and .rc == 0 and ((.timed_out // false) == false)))
' "$SUMMARY_PASS" >/dev/null; then
  echo "success path summary mismatch"
  cat "$SUMMARY_PASS"
  exit 1
fi

echo "[roadmap-non-blockchain-actionable-run] recommended-only path"
SUMMARY_RECOMMENDED="$TMP_DIR/summary_recommended.json"
REPORTS_RECOMMENDED="$TMP_DIR/reports_recommended"
ROADMAP_ACTIONABLE_SCENARIO=pass \
PASS1="$PASS1" PASS2="$PASS2" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
./scripts/roadmap_non_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_RECOMMENDED" \
  --summary-json "$SUMMARY_RECOMMENDED" \
  --recommended-only 1 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.actions_selected_count == 1
  and .roadmap.recommended_gate_id_not_found == false
  and .summary.actions_executed == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "action_pass_1"
  and .actions[0].status == "pass"
' "$SUMMARY_RECOMMENDED" >/dev/null; then
  echo "recommended-only path summary mismatch"
  cat "$SUMMARY_RECOMMENDED"
  exit 1
fi

echo "[roadmap-non-blockchain-actionable-run] recommended-only stale id fails closed"
SUMMARY_RECOMMENDED_MISSING="$TMP_DIR/summary_recommended_missing.json"
REPORTS_RECOMMENDED_MISSING="$TMP_DIR/reports_recommended_missing"
set +e
ROADMAP_ACTIONABLE_SCENARIO=recommended_missing \
PASS1="$PASS1" PASS2="$PASS2" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
./scripts/roadmap_non_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_RECOMMENDED_MISSING" \
  --summary-json "$SUMMARY_RECOMMENDED_MISSING" \
  --recommended-only 1 \
  --print-summary-json 0
recommended_missing_rc=$?
set -e
if [[ "$recommended_missing_rc" != "5" ]]; then
  echo "expected stale recommended-id rc=5, got rc=$recommended_missing_rc"
  cat "$SUMMARY_RECOMMENDED_MISSING"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 5
  and .roadmap.recommended_gate_id == "action_missing_1"
  and .roadmap.recommended_gate_id_not_found == true
  and .roadmap.actions_selected_count == 0
  and .summary.actions_executed == 0
  and .summary.pass == 0
  and .summary.fail == 0
  and ((.actions // []) | length == 0)
' "$SUMMARY_RECOMMENDED_MISSING" >/dev/null; then
  echo "recommended-only stale-id summary mismatch"
  cat "$SUMMARY_RECOMMENDED_MISSING"
  exit 1
fi

echo "[roadmap-non-blockchain-actionable-run] allow-policy-no-go default/off compatibility"
SUMMARY_ALLOW_DEFAULT="$TMP_DIR/summary_allow_default.json"
REPORTS_ALLOW_DEFAULT="$TMP_DIR/reports_allow_default"
ROADMAP_ACTIONABLE_SCENARIO=phase1_gate \
PASS1="$PASS1" PASS2="$PASS2" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
./scripts/roadmap_non_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_ALLOW_DEFAULT" \
  --summary-json "$SUMMARY_ALLOW_DEFAULT" \
  --recommended-only 1 \
  --max-actions 1 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.allow_policy_no_go == false
  and ((.actions // []) | length == 1)
  and .actions[0].id == "phase1_resilience_handoff_run_dry"
  and ((.actions[0].allow_policy_no_go_applied // false) == false)
  and ((.actions[0].command // "") | contains("--allow-policy-no-go") | not)
' "$SUMMARY_ALLOW_DEFAULT" >/dev/null; then
  echo "allow-policy-no-go default/off compatibility mismatch"
  cat "$SUMMARY_ALLOW_DEFAULT"
  exit 1
fi

echo "[roadmap-non-blockchain-actionable-run] allow-policy-no-go forwarding for phase1 actionable"
SUMMARY_ALLOW_ENABLED="$TMP_DIR/summary_allow_enabled.json"
REPORTS_ALLOW_ENABLED="$TMP_DIR/reports_allow_enabled"
ROADMAP_ACTIONABLE_SCENARIO=phase1_gate \
PASS1="$PASS1" PASS2="$PASS2" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
./scripts/roadmap_non_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_ALLOW_ENABLED" \
  --summary-json "$SUMMARY_ALLOW_ENABLED" \
  --allow-policy-no-go 1 \
  --recommended-only 1 \
  --max-actions 1 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.allow_policy_no_go == true
  and ((.actions // []) | length == 1)
  and .actions[0].id == "phase1_resilience_handoff_run_dry"
  and ((.actions[0].allow_policy_no_go_applied // false) == true)
  and ((.actions[0].command // "") | contains("--allow-policy-no-go 1"))
  and ((.actions[0].reason // "") | contains("allow_policy_no_go=1"))
' "$SUMMARY_ALLOW_ENABLED" >/dev/null; then
  echo "allow-policy-no-go forwarding mismatch"
  cat "$SUMMARY_ALLOW_ENABLED"
  exit 1
fi

echo "[roadmap-non-blockchain-actionable-run] max-actions limit path"
SUMMARY_MAX="$TMP_DIR/summary_max.json"
REPORTS_MAX="$TMP_DIR/reports_max"
ROADMAP_ACTIONABLE_SCENARIO=pass \
PASS1="$PASS1" PASS2="$PASS2" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
./scripts/roadmap_non_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_MAX" \
  --summary-json "$SUMMARY_MAX" \
  --max-actions 1 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.actions_selected_count == 1
  and .summary.actions_executed == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "action_pass_1"
' "$SUMMARY_MAX" >/dev/null; then
  echo "max-actions path summary mismatch"
  cat "$SUMMARY_MAX"
  exit 1
fi

echo "[roadmap-non-blockchain-actionable-run] failure path continues and returns first failing rc"
SUMMARY_FAIL="$TMP_DIR/summary_fail.json"
REPORTS_FAIL="$TMP_DIR/reports_fail"
set +e
ROADMAP_ACTIONABLE_SCENARIO=fail_second \
PASS1="$PASS1" PASS2="$PASS2" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
./scripts/roadmap_non_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_FAIL" \
  --summary-json "$SUMMARY_FAIL" \
  --print-summary-json 0
fail_rc=$?
set -e
if [[ "$fail_rc" != "19" ]]; then
  echo "expected failure path rc=19, got rc=$fail_rc"
  cat "$SUMMARY_FAIL"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 19
  and .inputs.action_timeout_sec == 0
  and .roadmap.actions_selected_count == 2
  and .summary.actions_executed == 2
  and .summary.pass == 1
  and .summary.fail == 1
  and .summary.timed_out == 0
  and ((.actions // []) | length == 2)
  and .actions[0].status == "pass"
  and .actions[1].status == "fail"
  and .actions[1].rc == 19
' "$SUMMARY_FAIL" >/dev/null; then
  echo "failure path summary mismatch"
  cat "$SUMMARY_FAIL"
  exit 1
fi

echo "[roadmap-non-blockchain-actionable-run] action timeout path marks timed_out and keeps first-fail rc contract"
SUMMARY_TIMEOUT="$TMP_DIR/summary_timeout.json"
REPORTS_TIMEOUT="$TMP_DIR/reports_timeout"
set +e
ROADMAP_ACTIONABLE_SCENARIO=timeout_first_then_pass \
PASS1="$PASS1" PASS2="$PASS2" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
./scripts/roadmap_non_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_TIMEOUT" \
  --summary-json "$SUMMARY_TIMEOUT" \
  --action-timeout-sec 1 \
  --print-summary-json 0
timeout_rc=$?
set -e
if [[ "$timeout_rc" != "124" ]]; then
  echo "expected timeout path rc=124, got rc=$timeout_rc"
  cat "$SUMMARY_TIMEOUT"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 124
  and .inputs.action_timeout_sec == 1
  and .roadmap.actions_selected_count == 2
  and .summary.actions_executed == 2
  and .summary.pass == 1
  and .summary.fail == 1
  and .summary.timed_out == 1
  and ((.actions // []) | length == 2)
  and .actions[0].id == "action_timeout_1"
  and .actions[0].status == "fail"
  and .actions[0].rc == 124
  and .actions[0].command_rc == 124
  and .actions[0].timed_out == true
  and .actions[0].timeout_sec == 1
  and .actions[0].failure_kind == "timed_out"
  and ((.actions[0].notes // "") | test("timed out"))
  and .actions[1].id == "action_pass_2"
  and .actions[1].status == "pass"
  and ((.actions[1].timed_out // false) == false)
' "$SUMMARY_TIMEOUT" >/dev/null; then
  echo "timeout path summary mismatch"
  cat "$SUMMARY_TIMEOUT"
  exit 1
fi

echo "[roadmap-non-blockchain-actionable-run] action timeout env path"
SUMMARY_TIMEOUT_ENV="$TMP_DIR/summary_timeout_env.json"
REPORTS_TIMEOUT_ENV="$TMP_DIR/reports_timeout_env"
set +e
ROADMAP_ACTIONABLE_SCENARIO=timeout_first_then_pass \
PASS1="$PASS1" PASS2="$PASS2" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ACTION_TIMEOUT_SEC=1 \
./scripts/roadmap_non_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_TIMEOUT_ENV" \
  --summary-json "$SUMMARY_TIMEOUT_ENV" \
  --max-actions 1 \
  --print-summary-json 0
timeout_env_rc=$?
set -e
if [[ "$timeout_env_rc" != "124" ]]; then
  echo "expected timeout env path rc=124, got rc=$timeout_env_rc"
  cat "$SUMMARY_TIMEOUT_ENV"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 124
  and .inputs.action_timeout_sec == 1
  and .roadmap.actions_selected_count == 1
  and .summary.actions_executed == 1
  and .summary.timed_out == 1
  and ((.actions // []) | length == 1)
  and .actions[0].timed_out == true
  and .actions[0].failure_kind == "timed_out"
' "$SUMMARY_TIMEOUT_ENV" >/dev/null; then
  echo "timeout env path summary mismatch"
  cat "$SUMMARY_TIMEOUT_ENV"
  exit 1
fi

echo "[roadmap-non-blockchain-actionable-run] no-timeout path unchanged for slow action"
SUMMARY_NO_TIMEOUT="$TMP_DIR/summary_no_timeout.json"
REPORTS_NO_TIMEOUT="$TMP_DIR/reports_no_timeout"
ROADMAP_ACTIONABLE_SCENARIO=timeout_first_then_pass \
PASS1="$PASS1" PASS2="$PASS2" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
./scripts/roadmap_non_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_NO_TIMEOUT" \
  --summary-json "$SUMMARY_NO_TIMEOUT" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.action_timeout_sec == 0
  and .roadmap.actions_selected_count == 2
  and .summary.actions_executed == 2
  and .summary.pass == 2
  and .summary.fail == 0
  and .summary.timed_out == 0
  and ((.actions // []) | length == 2)
  and ((.actions // []) | all(.status == "pass" and ((.timed_out // false) == false)))
' "$SUMMARY_NO_TIMEOUT" >/dev/null; then
  echo "no-timeout path summary mismatch"
  cat "$SUMMARY_NO_TIMEOUT"
  exit 1
fi

echo "[roadmap-non-blockchain-actionable-run] functional parallel execution contract"
SUMMARY_PARALLEL="$TMP_DIR/summary_parallel.json"
REPORTS_PARALLEL="$TMP_DIR/reports_parallel"
parallel_started_epoch="$(date +%s)"
ROADMAP_ACTIONABLE_SCENARIO=parallel_two_slow \
PASS1="$PASS1" PASS2="$PASS2" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
./scripts/roadmap_non_blockchain_actionable_run.sh \
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
  echo "functional parallel summary mismatch"
  cat "$SUMMARY_PARALLEL"
  exit 1
fi

if (( parallel_elapsed_sec > 6 )); then
  echo "functional parallel timing mismatch: expected <=6s, got ${parallel_elapsed_sec}s"
  cat "$SUMMARY_PARALLEL"
  exit 1
fi

echo "roadmap non-blockchain actionable run integration check ok"
