#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod grep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PHASE1_RESILIENCE_HANDOFF_CHECK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase1_resilience_handoff_check.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS_VPN_SUMMARY="$TMP_DIR/vpn_pass.json"
FAIL_VPN_SUMMARY="$TMP_DIR/vpn_fail.json"
SESSION_FALSE_VPN_SUMMARY="$TMP_DIR/vpn_session_false.json"
CI_PASS_SUMMARY="$TMP_DIR/ci_pass.json"
CI_FAIL_SUMMARY="$TMP_DIR/ci_fail.json"
CI_TIMEOUT_SUMMARY="$TMP_DIR/ci_timeout.json"
MISSING_SUMMARY="$TMP_DIR/does_not_exist.json"

PASS_OUTPUT_JSON="$TMP_DIR/pass_output.json"
FAIL_OUTPUT_JSON="$TMP_DIR/fail_output.json"
CI_PASS_OUTPUT_JSON="$TMP_DIR/ci_pass_output.json"
MISSING_OUTPUT_JSON="$TMP_DIR/missing_output.json"
PRECEDENCE_OUTPUT_JSON="$TMP_DIR/precedence_output.json"
TIMEOUT_OUTPUT_JSON="$TMP_DIR/timeout_output.json"

PASS_LOG="$TMP_DIR/pass.log"
FAIL_LOG="$TMP_DIR/fail.log"
CI_PASS_LOG="$TMP_DIR/ci_pass.log"
MISSING_LOG="$TMP_DIR/missing.log"
PRECEDENCE_LOG="$TMP_DIR/precedence.log"
TIMEOUT_LOG="$TMP_DIR/timeout.log"

cat >"$PASS_VPN_SUMMARY" <<'EOF_PASS_VPN'
{
  "version": 1,
  "profile_matrix_stable": true,
  "peer_loss_recovery_ok": true,
  "session_churn_guard_ok": true
}
EOF_PASS_VPN

cat >"$FAIL_VPN_SUMMARY" <<'EOF_FAIL_VPN'
{
  "version": 1,
  "profile_matrix_stable": true,
  "peer_loss_recovery_ok": false,
  "session_churn_guard_ok": true
}
EOF_FAIL_VPN

cat >"$SESSION_FALSE_VPN_SUMMARY" <<'EOF_SESSION_FALSE_VPN'
{
  "version": 1,
  "profile_matrix_stable": true,
  "peer_loss_recovery_ok": true,
  "session_churn_guard_ok": false
}
EOF_SESSION_FALSE_VPN

cat >"$CI_PASS_SUMMARY" <<EOF_CI_PASS
{
  "version": 1,
  "steps": {
    "three_machine_docker_profile_matrix": {
      "status": "pass"
    },
    "vpn_rc_resilience_path": {
      "status": "pass",
      "artifacts": {
        "summary_json": "$PASS_VPN_SUMMARY"
      }
    },
    "session_churn_guard": {
      "status": "pass"
    }
  }
}
EOF_CI_PASS

cat >"$CI_FAIL_SUMMARY" <<'EOF_CI_FAIL'
{
  "version": 1,
  "steps": {
    "three_machine_docker_profile_matrix": {
      "status": "fail"
    },
    "vpn_rc_resilience_path": {
      "status": "fail"
    },
    "session_churn_guard": {
      "status": "fail"
    }
  }
}
EOF_CI_FAIL

cat >"$CI_TIMEOUT_SUMMARY" <<'EOF_CI_TIMEOUT'
{
  "version": 1,
  "steps": {
    "three_machine_docker_profile_matrix": {
      "status": "pass"
    },
    "vpn_rc_resilience_path": {
      "status": "pass"
    },
    "session_churn_guard": {
      "status": "timeout"
    }
  }
}
EOF_CI_TIMEOUT

echo "[phase1-handoff-check] pass path with vpn summary"
"$SCRIPT_UNDER_TEST" \
  --vpn-rc-resilience-summary-json "$PASS_VPN_SUMMARY" \
  --summary-json "$PASS_OUTPUT_JSON" \
  --show-json 0 >"$PASS_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .automation.track == "non_blockchain"
  and .automation.requires_sudo == false
  and .automation.requires_github == false
  and .automation.automatable_without_sudo_or_github == true
  and .decision.pass == true
  and .handoff.profile_matrix_stable == true
  and .handoff.peer_loss_recovery_ok == true
  and .handoff.session_churn_guard_ok == true
  and .handoff.sources.profile_matrix_stable == "vpn_rc_resilience_summary"
  and .handoff.sources.peer_loss_recovery_ok == "vpn_rc_resilience_summary"
  and .handoff.sources.session_churn_guard_ok == "vpn_rc_resilience_summary"
  and .failure.kind == "none"
  and .policy_outcome.decision == "GO"
  and .policy_outcome.fail_closed_no_go == false
  and .handoff.failure_semantics.profile_matrix_stable.kind == "none"
  and .handoff.failure_semantics.peer_loss_recovery_ok.kind == "none"
  and .handoff.failure_semantics.session_churn_guard_ok.kind == "none"
' "$PASS_OUTPUT_JSON" >/dev/null; then
  echo "pass-path summary contract mismatch"
  cat "$PASS_OUTPUT_JSON"
  cat "$PASS_LOG"
  exit 1
fi

echo "[phase1-handoff-check] fail-closed path on false signal"
set +e
"$SCRIPT_UNDER_TEST" \
  --vpn-rc-resilience-summary-json "$FAIL_VPN_SUMMARY" \
  --summary-json "$FAIL_OUTPUT_JSON" \
  --show-json 0 >"$FAIL_LOG" 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for false signal fail-close, got rc=$fail_rc"
  cat "$FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .automation.track == "non_blockchain"
  and .automation.requires_sudo == false
  and .automation.requires_github == false
  and .automation.automatable_without_sudo_or_github == true
  and .decision.pass == false
  and .handoff.profile_matrix_stable == true
  and .handoff.peer_loss_recovery_ok == false
  and .handoff.session_churn_guard_ok == true
  and .handoff.failure_semantics.peer_loss_recovery_ok.kind == "policy_no_go"
  and .failure.kind == "policy_no_go"
  and .failure.policy_no_go == true
  and .failure.execution_failure == false
  and .failure.timeout == false
  and .policy_outcome.decision == "NO-GO"
  and .policy_outcome.fail_closed_no_go == true
  and ((.decision.reasons // []) | any(test("peer_loss_recovery_ok is false")))
' "$FAIL_OUTPUT_JSON" >/dev/null; then
  echo "false-signal fail-close summary mismatch"
  cat "$FAIL_OUTPUT_JSON"
  cat "$FAIL_LOG"
  exit 1
fi

echo "[phase1-handoff-check] ci-only backward-compatible step-status fallback"
"$SCRIPT_UNDER_TEST" \
  --ci-phase1-summary-json "$CI_PASS_SUMMARY" \
  --summary-json "$CI_PASS_OUTPUT_JSON" \
  --show-json 0 >"$CI_PASS_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .handoff.profile_matrix_stable == true
  and .handoff.peer_loss_recovery_ok == true
  and .handoff.session_churn_guard_ok == true
  and (.inputs.usable.ci_phase1_summary_json == true)
  and (.inputs.usable.vpn_rc_resilience_summary_json == true)
  and (.inputs.vpn_source_from_ci_artifacts == true)
' "$CI_PASS_OUTPUT_JSON" >/dev/null; then
  echo "ci-only fallback summary mismatch"
  cat "$CI_PASS_OUTPUT_JSON"
  cat "$CI_PASS_LOG"
  exit 1
fi

echo "[phase1-handoff-check] missing-artifact errors are explicit and fail-closed"
set +e
"$SCRIPT_UNDER_TEST" \
  --vpn-rc-resilience-summary-json "$MISSING_SUMMARY" \
  --summary-json "$MISSING_OUTPUT_JSON" \
  --show-json 1 >"$MISSING_LOG" 2>&1
missing_rc=$?
set -e
if [[ "$missing_rc" -ne 1 ]]; then
  echo "expected rc=1 for missing artifact fail-close, got rc=$missing_rc"
  cat "$MISSING_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .failure.kind == "execution_failure"
  and .failure.execution_failure == true
  and .policy_outcome.decision == "ERROR"
  and .policy_outcome.fail_closed_no_go == false
  and .handoff.failure_semantics.profile_matrix_stable.kind == "execution_failure"
  and .handoff.failure_semantics.peer_loss_recovery_ok.kind == "execution_failure"
  and .handoff.failure_semantics.session_churn_guard_ok.kind == "execution_failure"
  and ((.decision.reasons // []) | any(test("summary file not found")))
' "$MISSING_OUTPUT_JSON" >/dev/null; then
  echo "missing-artifact summary mismatch"
  cat "$MISSING_OUTPUT_JSON"
  cat "$MISSING_LOG"
  exit 1
fi
if ! grep -q '"schema"' "$MISSING_LOG"; then
  echo "--show-json 1 did not print summary payload"
  cat "$MISSING_LOG"
  exit 1
fi

echo "[phase1-handoff-check] vpn summary has precedence when both inputs are present"
"$SCRIPT_UNDER_TEST" \
  --ci-phase1-summary-json "$CI_FAIL_SUMMARY" \
  --vpn-rc-resilience-summary-json "$PASS_VPN_SUMMARY" \
  --summary-json "$PRECEDENCE_OUTPUT_JSON" \
  --show-json 0 >"$PRECEDENCE_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .handoff.profile_matrix_stable == true
  and .handoff.peer_loss_recovery_ok == true
  and .handoff.session_churn_guard_ok == true
  and .handoff.sources.profile_matrix_stable == "vpn_rc_resilience_summary"
  and .handoff.sources.peer_loss_recovery_ok == "vpn_rc_resilience_summary"
  and .handoff.sources.session_churn_guard_ok == "vpn_rc_resilience_summary"
' "$PRECEDENCE_OUTPUT_JSON" >/dev/null; then
  echo "input precedence summary mismatch"
  cat "$PRECEDENCE_OUTPUT_JSON"
  cat "$PRECEDENCE_LOG"
  exit 1
fi

echo "[phase1-handoff-check] session churn prefers CI pass signal over vpn false fallback"
SESSION_SOURCE_OUTPUT_JSON="$TMP_DIR/session_source_output.json"
SESSION_SOURCE_LOG="$TMP_DIR/session_source.log"
"$SCRIPT_UNDER_TEST" \
  --ci-phase1-summary-json "$CI_PASS_SUMMARY" \
  --vpn-rc-resilience-summary-json "$SESSION_FALSE_VPN_SUMMARY" \
  --summary-json "$SESSION_SOURCE_OUTPUT_JSON" \
  --show-json 0 >"$SESSION_SOURCE_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .handoff.profile_matrix_stable == true
  and .handoff.peer_loss_recovery_ok == true
  and .handoff.session_churn_guard_ok == true
  and .handoff.sources.profile_matrix_stable == "vpn_rc_resilience_summary"
  and .handoff.sources.peer_loss_recovery_ok == "vpn_rc_resilience_summary"
  and .handoff.sources.session_churn_guard_ok == "ci_phase1_summary.steps.session_churn_guard.status"
' "$SESSION_SOURCE_OUTPUT_JSON" >/dev/null; then
  echo "session-source precedence summary mismatch"
  cat "$SESSION_SOURCE_OUTPUT_JSON"
  cat "$SESSION_SOURCE_LOG"
  exit 1
fi

echo "[phase1-handoff-check] timeout status classifies as timeout failure semantics"
set +e
"$SCRIPT_UNDER_TEST" \
  --ci-phase1-summary-json "$CI_TIMEOUT_SUMMARY" \
  --summary-json "$TIMEOUT_OUTPUT_JSON" \
  --show-json 0 >"$TIMEOUT_LOG" 2>&1
timeout_rc=$?
set -e
if [[ "$timeout_rc" -ne 1 ]]; then
  echo "expected rc=1 for timeout fail-close, got rc=$timeout_rc"
  cat "$TIMEOUT_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .handoff.profile_matrix_stable == true
  and .handoff.peer_loss_recovery_ok == true
  and .handoff.session_churn_guard_ok == false
  and .handoff.sources.session_churn_guard_ok == "ci_phase1_summary.steps.session_churn_guard.status"
  and .handoff.failure_semantics.session_churn_guard_ok.kind == "timeout"
  and .failure.kind == "timeout"
  and .failure.timeout == true
  and .failure.policy_no_go == false
  and .failure.execution_failure == false
  and .policy_outcome.decision == "ERROR"
  and .policy_outcome.fail_closed_no_go == false
  and ((.decision.reasons // []) | any(test("session_churn_guard_ok is false")))
' "$TIMEOUT_OUTPUT_JSON" >/dev/null; then
  echo "timeout semantics summary mismatch"
  cat "$TIMEOUT_OUTPUT_JSON"
  cat "$TIMEOUT_LOG"
  exit 1
fi

echo "phase1 resilience handoff check integration ok"
