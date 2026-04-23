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
ACTION_TMP_DIR="$(mktemp -d "$ROOT_DIR/scripts/.integration_roadmap_blockchain_actionable_run.XXXXXX")"
trap 'rm -rf "$TMP_DIR" "$ACTION_TMP_DIR"' EXIT

FAKE_ROADMAP="$TMP_DIR/fake_roadmap_progress_report.sh"
PASS1="$ACTION_TMP_DIR/pass_action_1.sh"
PASS2="$ACTION_TMP_DIR/pass_action_2.sh"
FAIL1="$ACTION_TMP_DIR/fail_action_1.sh"
FAIL2="$ACTION_TMP_DIR/fail_action_2.sh"
SLOW1="$ACTION_TMP_DIR/slow_action_1.sh"
SLOW2="$ACTION_TMP_DIR/slow_action_2.sh"
PREFILL="$ACTION_TMP_DIR/prefill_action_1.sh"
REFRESH="$ACTION_TMP_DIR/refresh_action_1.sh"
ASSERT_ARGS="$ACTION_TMP_DIR/assert_args_action_1.sh"
ENV_REJECT_PAYLOAD="$ACTION_TMP_DIR/env_reject_payload.sh"
ENV_REJECT_MARKER="$TMP_DIR/env_reject_marker.txt"

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

cat >"$PREFILL" <<'EOF_PREFILL'
#!/usr/bin/env bash
set -euo pipefail
echo "prefill action 1"
EOF_PREFILL
chmod +x "$PREFILL"

cat >"$REFRESH" <<'EOF_REFRESH'
#!/usr/bin/env bash
set -euo pipefail
echo "refresh action 1"
EOF_REFRESH
chmod +x "$REFRESH"

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

cat >"$ASSERT_ARGS" <<'EOF_ASSERT_ARGS'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -ne 3 || "${1:-}" != "alpha value" || "${2:-}" != "--campaign-subject" || "${3:-}" != "inv chain quoted subject" ]]; then
  echo "unexpected argv: count=$# args=[$*]"
  exit 23
fi
echo "quoted argv ok"
EOF_ASSERT_ARGS
chmod +x "$ASSERT_ARGS"

cat >"$ENV_REJECT_PAYLOAD" <<EOF_ENV_REJECT_PAYLOAD
#!/usr/bin/env bash
set -euo pipefail
echo "payload-executed" >"$ENV_REJECT_MARKER"
EOF_ENV_REJECT_PAYLOAD
chmod +x "$ENV_REJECT_PAYLOAD"

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
scenario="${ROADMAP_BLOCKCHAIN_ACTIONABLE_SCENARIO:-pass}"
case "$scenario" in
  pass)
    cat >"$summary_json" <<JSON
{
  "blockchain_track": {
    "recommended_gate_id": "blockchain_pass_2",
    "recommended_gate_reason": "canonical pass recommended gate",
    "recommended_gate_command": "bash \"$PASS2\" real-evidence",
    "mainnet_activation_missing_metrics_action": {
      "id": "blockchain_pass_2"
    }
  },
  "next_actions": [
    {"id":"blockchain_pass_1","label":"Blockchain pass 1","command":"bash \"$PASS1\"","reason":"test"},
    {"id":"integration_ci_phase1_resilience","label":"Non-blockchain control","command":"bash \"$PASS2\"","reason":"ignore"},
    {"id":"blockchain_mainnet_activation_missing_metrics_prefill","label":"Blockchain missing-metrics prefill","command":"bash \"$PREFILL\"","reason":"test"},
    {"id":"blockchain_pass_2","label":"Blockchain pass 2","command":"bash \"$PASS2\" real-evidence","reason":"test"}
  ]
}
JSON
    ;;
  refresh_evidence)
    cat >"$summary_json" <<JSON
{
  "blockchain_track": {
    "recommended_gate_id": "blockchain_mainnet_activation_refresh_evidence",
    "recommended_gate_reason": "canonical refresh-evidence gate",
    "recommended_gate_command": "bash \"$REFRESH\" stale-evidence",
    "mainnet_activation_missing_metrics_action": {
      "id": "blockchain_mainnet_activation_refresh_evidence"
    }
  },
  "next_actions": [
    {"id":"integration_ci_phase1_resilience","label":"Non-blockchain control","command":"bash \"$PASS1\"","reason":"ignore"},
    {"id":"blockchain_mainnet_activation_refresh_evidence","label":"Blockchain refresh evidence","command":"bash \"$REFRESH\" stale-evidence","reason":"test"}
  ]
}
JSON
    ;;
  pass_no_recommended_id)
    cat >"$summary_json" <<JSON
{
  "next_actions": [
    {"id":"blockchain_pass_1","label":"Blockchain pass 1","command":"bash \"$PASS1\"","reason":"test"},
    {"id":"integration_ci_phase1_resilience","label":"Non-blockchain control","command":"bash \"$PASS2\"","reason":"ignore"},
    {"id":"blockchain_mainnet_activation_missing_metrics_prefill","label":"Blockchain missing-metrics prefill","command":"bash \"$PREFILL\"","reason":"test"},
    {"id":"blockchain_pass_2","label":"Blockchain pass 2","command":"bash \"$PASS2\" operator-pack","reason":"test"}
  ]
}
JSON
    ;;
  pass_recommended_id_not_selected)
    cat >"$summary_json" <<JSON
{
  "blockchain_track": {
    "recommended_gate_id": "blockchain_not_selected_canonical",
    "recommended_gate_reason": "canonical recommended id is intentionally not selected",
    "recommended_gate_command": "bash \"$PASS2\" --canonical-not-selected",
    "mainnet_activation_missing_metrics_action": {
      "id": "blockchain_not_selected_legacy"
    }
  },
  "next_actions": [
    {"id":"blockchain_pass_1","label":"Blockchain pass 1","command":"bash \"$PASS1\"","reason":"test"},
    {"id":"integration_ci_phase1_resilience","label":"Non-blockchain control","command":"bash \"$PASS2\"","reason":"ignore"},
    {"id":"blockchain_mainnet_activation_missing_metrics_prefill","label":"Blockchain missing-metrics prefill","command":"bash \"$PREFILL\"","reason":"test"},
    {"id":"blockchain_pass_2","label":"Blockchain pass 2","command":"bash \"$PASS2\" operator-pack","reason":"test"}
  ]
}
JSON
    ;;
  fail_first_rc)
    cat >"$summary_json" <<JSON
{
  "blockchain_track": {
    "mainnet_activation_missing_metrics_action": {
      "id": "blockchain_fail_1"
    }
  },
  "next_actions": [
    {"id":"blockchain_fail_1","label":"Blockchain fail 1","command":"bash \"$FAIL1\"","reason":"test"},
    {"id":"blockchain_fail_2","label":"Blockchain fail 2","command":"bash \"$FAIL2\"","reason":"test"}
  ]
}
JSON
    ;;
  timeout_first_then_pass)
    cat >"$summary_json" <<JSON
{
  "blockchain_track": {
    "recommended_gate_id": "blockchain_timeout_1",
    "recommended_gate_reason": "canonical timeout-first gate",
    "recommended_gate_command": "bash \"$SLOW1\"",
    "mainnet_activation_missing_metrics_action": {
      "id": "blockchain_timeout_1"
    }
  },
  "next_actions": [
    {"id":"blockchain_timeout_1","label":"Blockchain timeout 1","command":"bash \"$SLOW1\"","reason":"test-timeout"},
    {"id":"blockchain_pass_2","label":"Blockchain pass 2","command":"bash \"$PASS2\"","reason":"test"}
  ]
}
JSON
    ;;
  no_actions)
    cat >"$summary_json" <<JSON
{
  "blockchain_track": {
    "recommended_gate_id": "",
    "recommended_gate_reason": "",
    "recommended_gate_command": "",
    "mainnet_activation_missing_metrics_action": {
      "id": ""
    }
  },
  "next_actions": [
    {"id":"integration_ci_phase1_resilience","label":"Non-blockchain control","command":"bash \"$PASS1\"","reason":"ignore"},
    {"id":"blockchain_empty","label":"Blockchain empty","command":"","reason":"empty"}
  ]
}
JSON
    ;;
  parallel_two_slow)
    cat >"$summary_json" <<JSON
{
  "blockchain_track": {
    "recommended_gate_id": "blockchain_slow_2",
    "recommended_gate_reason": "canonical parallel recommended gate",
    "recommended_gate_command": "bash \"$SLOW2\"",
    "mainnet_activation_missing_metrics_action": {
      "id": "blockchain_slow_2"
    }
  },
  "next_actions": [
    {"id":"blockchain_slow_1","label":"Blockchain slow 1","command":"bash \"$SLOW1\"","reason":"test-parallel"},
    {"id":"blockchain_slow_2","label":"Blockchain slow 2","command":"bash \"$SLOW2\"","reason":"test-parallel"}
  ]
}
JSON
    ;;
  redaction)
    cat >"$summary_json" <<JSON
{
  "blockchain_track": {
    "recommended_gate_id": "blockchain_redaction_1",
    "recommended_gate_reason": "redaction scenario",
    "recommended_gate_command": "bash \"$PASS1\" --token chain-secret --campaign-subject inv-chain-secret",
    "mainnet_activation_missing_metrics_action": {
      "id": "blockchain_redaction_1"
    }
  },
  "next_actions": [
    {"id":"blockchain_redaction_1","label":"Blockchain redaction 1","command":"bash \"$PASS1\" --token chain-secret --campaign-subject inv-chain-secret","reason":"test-redaction"}
  ]
}
JSON
    ;;
  no_python_quoted)
    cat >"$summary_json" <<JSON
{
  "blockchain_track": {
    "recommended_gate_id": "blockchain_no_python_quoted",
    "recommended_gate_reason": "no-python quoted parser scenario",
    "recommended_gate_command": "bash \"$ASSERT_ARGS\" \"alpha value\" --campaign-subject \"inv chain quoted subject\"",
    "mainnet_activation_missing_metrics_action": {
      "id": "blockchain_no_python_quoted"
    }
  },
  "next_actions": [
    {"id":"blockchain_no_python_quoted","label":"Blockchain no-python quoted","command":"bash \"$ASSERT_ARGS\" \"alpha value\" --campaign-subject \"inv chain quoted subject\"","reason":"test-no-python-quoted"}
  ]
}
JSON
    ;;
  env_prefixed_reject)
    cat >"$summary_json" <<JSON
{
  "blockchain_track": {
    "recommended_gate_id": "blockchain_env_prefixed_reject",
    "recommended_gate_reason": "env-prefixed rejection scenario",
    "recommended_gate_command": "BASH_ENV=\"$ENV_REJECT_PAYLOAD\" bash \"$PASS2\"",
    "mainnet_activation_missing_metrics_action": {
      "id": "blockchain_env_prefixed_reject"
    }
  },
  "next_actions": [
    {"id":"blockchain_env_prefixed_reject","label":"Blockchain env-prefixed reject","command":"BASH_ENV=\"$ENV_REJECT_PAYLOAD\" bash \"$PASS2\"","reason":"test-env-prefixed-reject"}
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

echo "[roadmap-blockchain-actionable-run] help contract"
if ! bash ./scripts/roadmap_blockchain_actionable_run.sh --help | grep -F -- "--parallel [0|1]" >/dev/null; then
  echo "help output missing --parallel [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_blockchain_actionable_run.sh --help | grep -F -- "--recommended-only [0|1]" >/dev/null; then
  echo "help output missing --recommended-only [0|1]"
  exit 1
fi
if ! bash ./scripts/roadmap_blockchain_actionable_run.sh --help | grep -F -- "--max-actions N" >/dev/null; then
  echo "help output missing --max-actions N"
  exit 1
fi

echo "[roadmap-blockchain-actionable-run] success path with fake actions"
SUMMARY_PASS="$TMP_DIR/summary_pass.json"
REPORTS_PASS="$TMP_DIR/reports_pass"
ROADMAP_BLOCKCHAIN_ACTIONABLE_SCENARIO=pass \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
PREFILL="$PREFILL" \
ROADMAP_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_PASS" \
  --summary-json "$SUMMARY_PASS" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.parallel == false
  and .inputs.recommended_only == false
  and .roadmap.generated_this_run == true
  and .roadmap.actions_selected_count == 3
  and .roadmap.recommended_gate_id == "blockchain_pass_2"
  and .roadmap.recommended_gate_reason == "canonical pass recommended gate"
  and ((.roadmap.recommended_gate_command // "") | test("real-evidence"))
  and ((.roadmap.recommended_gate_command // "") | test("pass_action_2.sh"))
  and .roadmap.selected_action_ids == ["blockchain_pass_1","blockchain_mainnet_activation_missing_metrics_prefill","blockchain_pass_2"]
  and .summary.actions_executed == 3
  and .summary.pass == 3
  and .summary.fail == 0
  and .summary.timed_out == 0
  and ((.actions // []) | length == 3)
  and ((.actions // []) | all(.status == "pass" and .rc == 0 and ((.timed_out // false) == false)))
  and .actions[1].id == "blockchain_mainnet_activation_missing_metrics_prefill"
  and .actions[1].status == "pass"
  and ((.actions // []) | any((.id == "blockchain_pass_2") and (((.command // "") | test("real-evidence|operator-pack")))))
' "$SUMMARY_PASS" >/dev/null; then
  echo "success path summary mismatch"
  cat "$SUMMARY_PASS"
  exit 1
fi

echo "[roadmap-blockchain-actionable-run] command redaction in action summaries"
SUMMARY_REDACTION="$TMP_DIR/summary_redaction.json"
REPORTS_REDACTION="$TMP_DIR/reports_redaction"
ROADMAP_BLOCKCHAIN_ACTIONABLE_SCENARIO=redaction \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
PREFILL="$PREFILL" \
ROADMAP_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_REDACTION" \
  --summary-json "$SUMMARY_REDACTION" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.actions_selected_count == 1
  and ((.roadmap.recommended_gate_command // "") | contains("--token [redacted]"))
  and ((.roadmap.recommended_gate_command // "") | contains("--campaign-subject [redacted]"))
  and (((.roadmap.recommended_gate_command // "") | contains("chain-secret")) | not)
  and (((.roadmap.recommended_gate_command // "") | contains("inv-chain-secret")) | not)
  and ((.actions // []) | length == 1)
  and .actions[0].id == "blockchain_redaction_1"
  and .actions[0].status == "pass"
  and ((.actions[0].command // "") | contains("--token [redacted]"))
  and ((.actions[0].command // "") | contains("--campaign-subject [redacted]"))
  and (((.actions[0].command // "") | contains("chain-secret")) | not)
  and (((.actions[0].command // "") | contains("inv-chain-secret")) | not)
' "$SUMMARY_REDACTION" >/dev/null; then
  echo "redaction summary mismatch"
  cat "$SUMMARY_REDACTION"
  exit 1
fi

echo "[roadmap-blockchain-actionable-run] no-python safe-mode path preserves quoted argv parsing"
SUMMARY_NO_PYTHON_QUOTED="$TMP_DIR/summary_no_python_quoted.json"
REPORTS_NO_PYTHON_QUOTED="$TMP_DIR/reports_no_python_quoted"
NO_PYTHON_BIN="$TMP_DIR/no_python_bin"
mkdir -p "$NO_PYTHON_BIN"
cat >"$NO_PYTHON_BIN/python3" <<'EOF_NO_PYTHON'
#!/usr/bin/env bash
exit 127
EOF_NO_PYTHON
chmod +x "$NO_PYTHON_BIN/python3"
PATH="$NO_PYTHON_BIN:$PATH" \
ROADMAP_BLOCKCHAIN_ACTIONABLE_SCENARIO=no_python_quoted \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" PREFILL="$PREFILL" REFRESH="$REFRESH" ASSERT_ARGS="$ASSERT_ARGS" \
ROADMAP_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_NO_PYTHON_QUOTED" \
  --summary-json "$SUMMARY_NO_PYTHON_QUOTED" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.actions_selected_count == 1
  and .summary.actions_executed == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "blockchain_no_python_quoted"
  and .actions[0].status == "pass"
  and ((.actions[0].command // "") | contains("--campaign-subject [redacted]"))
  and (((.actions[0].command // "") | contains("inv chain quoted subject")) | not)
' "$SUMMARY_NO_PYTHON_QUOTED" >/dev/null; then
  echo "no-python quoted safe-mode summary mismatch"
  cat "$SUMMARY_NO_PYTHON_QUOTED"
  exit 1
fi

echo "[roadmap-blockchain-actionable-run] env-prefixed action remains fail-closed in safe mode"
SUMMARY_ENV_REJECT="$TMP_DIR/summary_env_reject.json"
REPORTS_ENV_REJECT="$TMP_DIR/reports_env_reject"
rm -f "$ENV_REJECT_MARKER"
set +e
ROADMAP_BLOCKCHAIN_ACTIONABLE_SCENARIO=env_prefixed_reject \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" PREFILL="$PREFILL" REFRESH="$REFRESH" ENV_REJECT_PAYLOAD="$ENV_REJECT_PAYLOAD" \
ROADMAP_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_ENV_REJECT" \
  --summary-json "$SUMMARY_ENV_REJECT" \
  --print-summary-json 0
env_reject_rc=$?
set -e
if [[ "$env_reject_rc" != "5" ]]; then
  echo "expected env-prefixed safe-mode rejection rc=5, got rc=$env_reject_rc"
  cat "$SUMMARY_ENV_REJECT"
  exit 1
fi
if [[ -f "$ENV_REJECT_MARKER" ]]; then
  echo "env-prefixed payload unexpectedly executed in safe mode"
  cat "$SUMMARY_ENV_REJECT"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 5
  and .summary.actions_executed == 1
  and .summary.fail == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "blockchain_env_prefixed_reject"
  and .actions[0].status == "fail"
  and .actions[0].rc == 5
' "$SUMMARY_ENV_REJECT" >/dev/null; then
  echo "env-prefixed safe-mode rejection summary mismatch"
  cat "$SUMMARY_ENV_REJECT"
  exit 1
fi

echo "[roadmap-blockchain-actionable-run] refresh-evidence path"
SUMMARY_REFRESH="$TMP_DIR/summary_refresh.json"
REPORTS_REFRESH="$TMP_DIR/reports_refresh"
ROADMAP_BLOCKCHAIN_ACTIONABLE_SCENARIO=refresh_evidence \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
PREFILL="$PREFILL" REFRESH="$REFRESH" \
ROADMAP_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_REFRESH" \
  --summary-json "$SUMMARY_REFRESH" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.generated_this_run == true
  and .roadmap.recommended_gate_id == "blockchain_mainnet_activation_refresh_evidence"
  and .roadmap.recommended_gate_reason == "canonical refresh-evidence gate"
  and ((.roadmap.recommended_gate_command // "") | test("stale-evidence"))
  and ((.roadmap.recommended_gate_command // "") | test("refresh_action_1.sh"))
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["blockchain_mainnet_activation_refresh_evidence"]
  and .summary.actions_executed == 1
  and .summary.pass == 1
  and .summary.fail == 0
  and .summary.timed_out == 0
  and ((.actions // []) | length == 1)
  and .actions[0].id == "blockchain_mainnet_activation_refresh_evidence"
  and .actions[0].status == "pass"
  and ((.actions[0].command // "") | test("stale-evidence"))
' "$SUMMARY_REFRESH" >/dev/null; then
  echo "refresh-evidence path summary mismatch"
  cat "$SUMMARY_REFRESH"
  exit 1
fi

echo "[roadmap-blockchain-actionable-run] max-actions truncation path"
SUMMARY_MAX="$TMP_DIR/summary_max.json"
REPORTS_MAX="$TMP_DIR/reports_max"
ROADMAP_BLOCKCHAIN_ACTIONABLE_SCENARIO=pass \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
PREFILL="$PREFILL" \
ROADMAP_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_MAX" \
  --summary-json "$SUMMARY_MAX" \
  --max-actions 1 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["blockchain_pass_1"]
  and .summary.actions_executed == 1
  and ((.actions // []) | length == 1)
  and .actions[0].id == "blockchain_pass_1"
  and .actions[0].status == "pass"
' "$SUMMARY_MAX" >/dev/null; then
  echo "max-actions path summary mismatch"
  cat "$SUMMARY_MAX"
  exit 1
fi

echo "[roadmap-blockchain-actionable-run] recommended-only path"
SUMMARY_RECOMMENDED="$TMP_DIR/summary_recommended.json"
REPORTS_RECOMMENDED="$TMP_DIR/reports_recommended"
ROADMAP_BLOCKCHAIN_ACTIONABLE_SCENARIO=pass \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
PREFILL="$PREFILL" \
ROADMAP_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_RECOMMENDED" \
  --summary-json "$SUMMARY_RECOMMENDED" \
  --recommended-only 1 \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.recommended_only == true
  and .roadmap.recommended_gate_id == "blockchain_pass_2"
  and .roadmap.recommended_gate_reason == "canonical pass recommended gate"
  and ((.roadmap.recommended_gate_command // "") | test("real-evidence"))
  and ((.roadmap.recommended_gate_command // "") | test("pass_action_2.sh"))
  and .roadmap.actions_selected_count == 1
  and .roadmap.selected_action_ids == ["blockchain_pass_2"]
  and .summary.actions_executed == 1
  and .summary.pass == 1
  and .summary.fail == 0
  and ((.actions // []) | length == 1)
  and .actions[0].id == "blockchain_pass_2"
  and .actions[0].status == "pass"
  and ((.actions[0].command // "") | test("real-evidence|operator-pack"))
' "$SUMMARY_RECOMMENDED" >/dev/null; then
  echo "recommended-only path summary mismatch"
  cat "$SUMMARY_RECOMMENDED"
  exit 1
fi

echo "[roadmap-blockchain-actionable-run] recommended-only strict no-id path"
SUMMARY_RECOMMENDED_FALLBACK="$TMP_DIR/summary_recommended_fallback.json"
REPORTS_RECOMMENDED_FALLBACK="$TMP_DIR/reports_recommended_fallback"
RECOMMENDED_FALLBACK_LOG="$TMP_DIR/recommended_fallback.log"
set +e
ROADMAP_BLOCKCHAIN_ACTIONABLE_SCENARIO=pass_no_recommended_id \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
PREFILL="$PREFILL" \
ROADMAP_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_RECOMMENDED_FALLBACK" \
  --summary-json "$SUMMARY_RECOMMENDED_FALLBACK" \
  --recommended-only 1 \
  --print-summary-json 0 >"$RECOMMENDED_FALLBACK_LOG" 2>&1
recommended_fallback_rc=$?
set -e
if [[ "$recommended_fallback_rc" != "4" ]]; then
  echo "expected recommended-only strict no-id rc=4, got rc=$recommended_fallback_rc"
  cat "$RECOMMENDED_FALLBACK_LOG"
  cat "$SUMMARY_RECOMMENDED_FALLBACK"
  exit 1
fi

if ! grep -F -- "recommended-only strict mode: no actions selected; reason=missing_recommended_id" "$RECOMMENDED_FALLBACK_LOG" >/dev/null; then
  echo "recommended-only strict no-id log line missing"
  cat "$RECOMMENDED_FALLBACK_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 4
  and .inputs.recommended_only == true
  and .roadmap.recommended_gate_id == null
  and .roadmap.recommended_gate_reason == null
  and .roadmap.recommended_gate_command == null
  and .roadmap.recommended_only_selection_state == "missing_recommended_id"
  and .roadmap.recommended_only_selection_reason == "no recommended gate id was provided"
  and .roadmap.recommended_only_fail_closed == true
  and .roadmap.actions_selected_count == 0
  and .roadmap.selected_action_ids == []
  and .summary.actions_executed == 0
  and .summary.pass == 0
  and .summary.fail == 0
  and ((.actions // []) | length == 0)
' "$SUMMARY_RECOMMENDED_FALLBACK" >/dev/null; then
  echo "recommended-only strict no-id summary mismatch"
  cat "$SUMMARY_RECOMMENDED_FALLBACK"
  exit 1
fi

echo "[roadmap-blockchain-actionable-run] recommended-only strict missing-selected-id path"
SUMMARY_RECOMMENDED_NOT_SELECTED="$TMP_DIR/summary_recommended_not_selected.json"
REPORTS_RECOMMENDED_NOT_SELECTED="$TMP_DIR/reports_recommended_not_selected"
RECOMMENDED_NOT_SELECTED_LOG="$TMP_DIR/recommended_not_selected.log"
set +e
ROADMAP_BLOCKCHAIN_ACTIONABLE_SCENARIO=pass_recommended_id_not_selected \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
PREFILL="$PREFILL" \
ROADMAP_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_RECOMMENDED_NOT_SELECTED" \
  --summary-json "$SUMMARY_RECOMMENDED_NOT_SELECTED" \
  --recommended-only 1 \
  --print-summary-json 0 >"$RECOMMENDED_NOT_SELECTED_LOG" 2>&1
recommended_not_selected_rc=$?
set -e
if [[ "$recommended_not_selected_rc" != "4" ]]; then
  echo "expected recommended-only strict missing-selected-id rc=4, got rc=$recommended_not_selected_rc"
  cat "$RECOMMENDED_NOT_SELECTED_LOG"
  cat "$SUMMARY_RECOMMENDED_NOT_SELECTED"
  exit 1
fi

if ! grep -F -- "recommended-only strict mode: no actions selected; reason=recommended_id_not_selected recommended_gate_id=blockchain_not_selected_canonical" "$RECOMMENDED_NOT_SELECTED_LOG" >/dev/null; then
  echo "recommended-only strict missing-selected-id log line missing"
  cat "$RECOMMENDED_NOT_SELECTED_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 4
  and .inputs.recommended_only == true
  and .roadmap.recommended_gate_id == "blockchain_not_selected_canonical"
  and .roadmap.recommended_gate_reason == "canonical recommended id is intentionally not selected"
  and ((.roadmap.recommended_gate_command // "") | test("canonical-not-selected"))
  and .roadmap.recommended_only_selection_state == "recommended_id_not_selected"
  and .roadmap.recommended_only_selection_reason == "recommended gate id '\''blockchain_not_selected_canonical'\'' was not present in selected blockchain actions"
  and .roadmap.recommended_only_fail_closed == true
  and .roadmap.actions_selected_count == 0
  and .roadmap.selected_action_ids == []
  and .summary.actions_executed == 0
  and .summary.pass == 0
  and .summary.fail == 0
  and ((.actions // []) | length == 0)
' "$SUMMARY_RECOMMENDED_NOT_SELECTED" >/dev/null; then
  echo "recommended-only strict missing-selected-id summary mismatch"
  cat "$SUMMARY_RECOMMENDED_NOT_SELECTED"
  exit 1
fi

echo "[roadmap-blockchain-actionable-run] failure path keeps first failing rc"
SUMMARY_FAIL="$TMP_DIR/summary_fail.json"
REPORTS_FAIL="$TMP_DIR/reports_fail"
set +e
ROADMAP_BLOCKCHAIN_ACTIONABLE_SCENARIO=fail_first_rc \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_FAIL" \
  --summary-json "$SUMMARY_FAIL" \
  --print-summary-json 0
fail_rc=$?
set -e
if [[ "$fail_rc" != "7" ]]; then
  echo "expected failure path rc=7, got rc=$fail_rc"
  cat "$SUMMARY_FAIL"
  exit 1
fi

if ! jq -e '
  .status == "fail"
  and .rc == 7
  and .roadmap.recommended_gate_id == "blockchain_fail_1"
  and .roadmap.recommended_gate_reason == null
  and .roadmap.recommended_gate_command == null
  and .roadmap.actions_selected_count == 2
  and .summary.actions_executed == 2
  and .summary.pass == 0
  and .summary.fail == 2
  and .summary.timed_out == 0
  and ((.actions // []) | length == 2)
  and .actions[0].id == "blockchain_fail_1"
  and .actions[0].status == "fail"
  and .actions[0].rc == 7
  and .actions[1].id == "blockchain_fail_2"
  and .actions[1].status == "fail"
  and .actions[1].rc == 13
' "$SUMMARY_FAIL" >/dev/null; then
  echo "failure path summary mismatch"
  cat "$SUMMARY_FAIL"
  exit 1
fi

echo "[roadmap-blockchain-actionable-run] timeout path"
SUMMARY_TIMEOUT="$TMP_DIR/summary_timeout.json"
REPORTS_TIMEOUT="$TMP_DIR/reports_timeout"
set +e
ROADMAP_BLOCKCHAIN_ACTIONABLE_SCENARIO=timeout_first_then_pass \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_blockchain_actionable_run.sh \
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
  and .roadmap.recommended_gate_id == "blockchain_timeout_1"
  and .roadmap.recommended_gate_reason == "canonical timeout-first gate"
  and ((.roadmap.recommended_gate_command // "") | test("slow_action_1.sh"))
  and .roadmap.actions_selected_count == 2
  and .summary.actions_executed == 2
  and .summary.pass == 1
  and .summary.fail == 1
  and .summary.timed_out == 1
  and ((.actions // []) | length == 2)
  and .actions[0].id == "blockchain_timeout_1"
  and .actions[0].status == "fail"
  and .actions[0].rc == 124
  and .actions[0].timed_out == true
  and .actions[0].failure_kind == "timed_out"
  and .actions[1].id == "blockchain_pass_2"
  and .actions[1].status == "pass"
  and ((.actions[1].timed_out // false) == false)
' "$SUMMARY_TIMEOUT" >/dev/null; then
  echo "timeout path summary mismatch"
  cat "$SUMMARY_TIMEOUT"
  exit 1
fi

echo "[roadmap-blockchain-actionable-run] no-actions path"
SUMMARY_EMPTY="$TMP_DIR/summary_empty.json"
REPORTS_EMPTY="$TMP_DIR/reports_empty"
ROADMAP_BLOCKCHAIN_ACTIONABLE_SCENARIO=no_actions \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_blockchain_actionable_run.sh \
  --reports-dir "$REPORTS_EMPTY" \
  --summary-json "$SUMMARY_EMPTY" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.recommended_gate_id == null
  and .roadmap.recommended_gate_reason == null
  and .roadmap.recommended_gate_command == null
  and .roadmap.actions_selected_count == 0
  and .roadmap.selected_action_ids == []
  and .summary.actions_executed == 0
  and .summary.pass == 0
  and .summary.fail == 0
  and .summary.timed_out == 0
  and ((.actions // []) | length == 0)
' "$SUMMARY_EMPTY" >/dev/null; then
  echo "no-actions path summary mismatch"
  cat "$SUMMARY_EMPTY"
  exit 1
fi

echo "[roadmap-blockchain-actionable-run] parallel path"
SUMMARY_PARALLEL="$TMP_DIR/summary_parallel.json"
REPORTS_PARALLEL="$TMP_DIR/reports_parallel"
parallel_started_epoch="$(date +%s)"
ROADMAP_BLOCKCHAIN_ACTIONABLE_SCENARIO=parallel_two_slow \
PASS1="$PASS1" PASS2="$PASS2" FAIL1="$FAIL1" FAIL2="$FAIL2" SLOW1="$SLOW1" SLOW2="$SLOW2" \
ROADMAP_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
bash ./scripts/roadmap_blockchain_actionable_run.sh \
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
  and .roadmap.recommended_gate_id == "blockchain_slow_2"
  and .roadmap.recommended_gate_reason == "canonical parallel recommended gate"
  and ((.roadmap.recommended_gate_command // "") | test("slow_action_2.sh"))
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

echo "roadmap blockchain actionable run integration check ok"
