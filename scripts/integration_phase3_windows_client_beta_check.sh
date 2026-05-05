#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod grep cat; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PHASE3_WINDOWS_CLIENT_BETA_CHECK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase3_windows_client_beta_check.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS_SUMMARY="$TMP_DIR/ci_phase3_pass.json"
FAIL_SUMMARY="$TMP_DIR/ci_phase3_fail.json"
RELAXED_SUMMARY="$TMP_DIR/ci_phase3_relaxed.json"
MISSING_SUMMARY="$TMP_DIR/ci_phase3_missing.json"

PASS_OUTPUT="$TMP_DIR/pass_output.json"
FAIL_OUTPUT="$TMP_DIR/fail_output.json"
RELAXED_OUTPUT="$TMP_DIR/relaxed_output.json"
MISSING_OUTPUT="$TMP_DIR/missing_output.json"

PASS_LOG="$TMP_DIR/pass.log"
FAIL_LOG="$TMP_DIR/fail.log"
RELAXED_LOG="$TMP_DIR/relaxed.log"
MISSING_LOG="$TMP_DIR/missing.log"

cat >"$PASS_SUMMARY" <<'EOF_PASS'
{
  "version": 1,
  "schema": {
    "id": "ci_phase3_windows_client_beta_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "desktop_scaffold_contract": {
      "status": "pass"
    },
    "local_control_api_contract": {
      "status": "pass"
    },
    "local_api_config_defaults": {
      "status": "pass"
    },
    "easy_node_config_v1": {
      "status": "pass"
    },
    "easy_mode_launcher_wiring": {
      "status": "pass"
    },
    "windows_desktop_native_bootstrap_guardrails": {
      "status": "pass"
    },
    "easy_mode_launcher_runtime": {
      "status": "pass"
    }
  }
}
EOF_PASS

cat >"$FAIL_SUMMARY" <<'EOF_FAIL'
{
  "version": 1,
  "schema": {
    "id": "ci_phase3_windows_client_beta_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "desktop_scaffold_contract": {
      "status": "pass"
    },
    "local_control_api_contract": {
      "status": "fail"
    },
    "local_api_config_defaults": {
      "status": "pass"
    },
    "easy_node_config_v1": {
      "status": "pass"
    },
    "easy_mode_launcher_wiring": {
      "status": "pass"
    },
    "windows_desktop_native_bootstrap_guardrails": {
      "status": "pass"
    },
    "easy_mode_launcher_runtime": {
      "status": "pass"
    }
  }
}
EOF_FAIL

cat >"$RELAXED_SUMMARY" <<'EOF_RELAXED'
{
  "version": 1,
  "schema": {
    "id": "ci_phase3_windows_client_beta_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "desktop_scaffold_contract": {
      "status": "pass"
    },
    "local_control_api_contract": {
      "status": "fail"
    },
    "local_api_config_defaults": {
      "status": "pass"
    },
    "easy_node_config_v1": {
      "status": "pass"
    },
    "easy_mode_launcher_wiring": {
      "status": "pass"
    },
    "windows_desktop_native_bootstrap_guardrails": {
      "status": "pass"
    },
    "easy_mode_launcher_runtime": {
      "status": "pass"
    }
  }
}
EOF_RELAXED

echo "[phase3-windows-client-beta-check] stage-derived pass path"
"$SCRIPT_UNDER_TEST" \
  --ci-phase3-summary-json "$PASS_SUMMARY" \
  --summary-json "$PASS_OUTPUT" \
  --show-json 0 >"$PASS_LOG" 2>&1

if ! jq -e '
  .version == 1
  and .schema.id == "phase3_windows_client_beta_check_summary"
  and .status == "pass"
  and .rc == 0
  and .inputs.usable.ci_phase3_summary_json == true
  and .policy.require_desktop_scaffold_ok == true
  and .policy.require_local_control_api_ok == true
  and .policy.require_local_api_config_defaults_ok == true
  and .policy.require_easy_node_config_v1_ok == true
  and .policy.require_launcher_wiring_ok == true
  and .policy.require_windows_native_bootstrap_guardrails_ok == true
  and .policy.require_launcher_runtime_ok == true
  and .signals.desktop_scaffold_ok == true
  and .signals.local_control_api_ok == true
  and .signals.local_api_config_defaults_ok == true
  and .signals.easy_node_config_v1_ok == true
  and .signals.launcher_wiring_ok == true
  and .signals.windows_native_bootstrap_guardrails_ok == true
  and .signals.launcher_runtime_ok == true
  and .signals.windows_parity_ok == true
  and .signals.desktop_contract_ok == true
  and .signals.installer_update_ok == true
  and .signals.telemetry_stability_ok == true
  and .windows_parity_ok == true
  and .desktop_contract_ok == true
  and .installer_update_ok == true
  and .telemetry_stability_ok == true
  and .handoff.windows_parity_ok == true
  and .handoff.desktop_contract_ok == true
  and .handoff.installer_update_ok == true
  and .handoff.telemetry_stability_ok == true
  and .handoff.failure_semantics.desktop_scaffold_ok.kind == "none"
  and .handoff.failure_semantics.local_control_api_ok.kind == "none"
  and .handoff.failure_semantics.local_api_config_defaults_ok.kind == "none"
  and .handoff.failure_semantics.easy_node_config_v1_ok.kind == "none"
  and .handoff.failure_semantics.launcher_wiring_ok.kind == "none"
  and .handoff.failure_semantics.windows_native_bootstrap_guardrails_ok.kind == "none"
  and .handoff.failure_semantics.launcher_runtime_ok.kind == "none"
  and .failure.kind == "none"
  and .effective.policy_relaxed == false
  and .effective.strict_readiness_ok == true
  and .effective.status == "pass"
  and .effective.reason == null
  and .policy_outcome.decision == "GO"
  and .policy_outcome.fail_closed_no_go == false
  and .decision.actionable.count == 0
  and .decision.actionable.recommended_gate_id == null
  and .phase3_windows_client_beta_handoff.windows_parity_ok == true
  and .phase3_windows_client_beta_handoff.desktop_contract_ok == true
  and .phase3_windows_client_beta_handoff.installer_update_ok == true
  and .phase3_windows_client_beta_handoff.telemetry_stability_ok == true
' "$PASS_OUTPUT" >/dev/null; then
  echo "pass-path summary contract mismatch"
  cat "$PASS_OUTPUT"
  cat "$PASS_LOG"
  exit 1
fi

echo "[phase3-windows-client-beta-check] fail-closed path on stage failure"
set +e
"$SCRIPT_UNDER_TEST" \
  --ci-phase3-summary-json "$FAIL_SUMMARY" \
  --summary-json "$FAIL_OUTPUT" \
  --show-json 0 >"$FAIL_LOG" 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for fail-closed stage failure, got rc=$fail_rc"
  cat "$FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .signals.local_control_api_ok == false
  and .signals.windows_native_bootstrap_guardrails_ok == true
  and .signals.windows_parity_ok == false
  and .signals.desktop_contract_ok == false
  and .signals.installer_update_ok == true
  and .signals.telemetry_stability_ok == true
  and .windows_parity_ok == false
  and .desktop_contract_ok == false
  and .installer_update_ok == true
  and .telemetry_stability_ok == true
  and .handoff.windows_parity_ok == false
  and .handoff.desktop_contract_ok == false
  and .handoff.installer_update_ok == true
  and .handoff.telemetry_stability_ok == true
  and .handoff.failure_semantics.local_control_api_ok.kind == "policy_no_go"
  and .handoff.failure_semantics.windows_native_bootstrap_guardrails_ok.kind == "none"
  and .failure.kind == "policy_no_go"
  and .effective.policy_relaxed == false
  and .effective.strict_readiness_ok == false
  and .effective.status == "fail"
  and .effective.reason == "top_level_policy_no_go"
  and .policy_outcome.decision == "NO-GO"
  and .policy_outcome.fail_closed_no_go == true
  and .decision.actionable.count == 1
  and .decision.actionable.recommended_gate_id == "phase3_windows_client_beta_local_control_api_gate"
  and .decision.actionable.gates[0].signal == "local_control_api_ok"
  and .decision.actionable.gates[0].failure_kind == "policy_no_go"
  and .stages.local_control_api.status == "fail"
  and ((.decision.reasons // []) | any(test("local_control_api_ok is false")))
' "$FAIL_OUTPUT" >/dev/null; then
  echo "fail-path summary contract mismatch"
  cat "$FAIL_OUTPUT"
  cat "$FAIL_LOG"
  exit 1
fi

echo "[phase3-windows-client-beta-check] relaxed policy toggle path"
"$SCRIPT_UNDER_TEST" \
  --ci-phase3-summary-json "$RELAXED_SUMMARY" \
  --summary-json "$RELAXED_OUTPUT" \
  --require-local-control-api-ok 0 \
  --show-json 0 >"$RELAXED_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_local_control_api_ok == false
  and .policy.require_windows_native_bootstrap_guardrails_ok == true
  and .signals.local_control_api_ok == false
  and .signals.windows_native_bootstrap_guardrails_ok == true
  and .signals.windows_parity_ok == false
  and .signals.desktop_contract_ok == false
  and .signals.installer_update_ok == true
  and .signals.telemetry_stability_ok == true
  and .windows_parity_ok == false
  and .desktop_contract_ok == false
  and .installer_update_ok == true
  and .telemetry_stability_ok == true
  and .handoff.windows_parity_ok == false
  and .handoff.desktop_contract_ok == false
  and .handoff.installer_update_ok == true
  and .handoff.telemetry_stability_ok == true
  and .handoff.failure_semantics.local_control_api_ok.kind == "none"
  and .handoff.failure_semantics.windows_native_bootstrap_guardrails_ok.kind == "none"
  and .failure.kind == "none"
  and .effective.policy_relaxed == true
  and .effective.strict_readiness_ok == false
  and .effective.status == "warn_relaxed_policy"
  and .effective.reason == "strict_readiness_gap_relaxed_policy"
  and .policy_outcome.decision == "GO"
  and .decision.actionable.count == 0
  and .decision.actionable.recommended_gate_id == null
  and .stages.local_control_api.status == "fail"
' "$RELAXED_OUTPUT" >/dev/null; then
  echo "relaxed-policy summary mismatch"
  cat "$RELAXED_OUTPUT"
  cat "$RELAXED_LOG"
  exit 1
fi

echo "[phase3-windows-client-beta-check] missing-summary show-json path"
set +e
"$SCRIPT_UNDER_TEST" \
  --ci-phase3-summary-json "$MISSING_SUMMARY" \
  --summary-json "$MISSING_OUTPUT" \
  --show-json 1 >"$MISSING_LOG" 2>&1
missing_rc=$?
set -e
if [[ "$missing_rc" -ne 1 ]]; then
  echo "expected rc=1 for missing summary fail-close, got rc=$missing_rc"
  cat "$MISSING_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .inputs.usable.ci_phase3_summary_json == false
  and .signals.windows_parity_ok == false
  and .signals.desktop_contract_ok == false
  and .signals.installer_update_ok == false
  and .signals.telemetry_stability_ok == false
  and .windows_parity_ok == false
  and .desktop_contract_ok == false
  and .installer_update_ok == false
  and .telemetry_stability_ok == false
  and .handoff.windows_parity_ok == false
  and .handoff.desktop_contract_ok == false
  and .handoff.installer_update_ok == false
  and .handoff.telemetry_stability_ok == false
  and .handoff.failure_semantics.desktop_scaffold_ok.kind == "execution_failure"
  and .handoff.failure_semantics.local_control_api_ok.kind == "execution_failure"
  and .handoff.failure_semantics.windows_native_bootstrap_guardrails_ok.kind == "execution_failure"
  and .failure.kind == "execution_failure"
  and .effective.policy_relaxed == false
  and .effective.strict_readiness_ok == false
  and .effective.status == "fail"
  and .effective.reason == "top_level_execution_failure"
  and .policy_outcome.decision == "ERROR"
  and .policy_outcome.fail_closed_no_go == false
  and .decision.actionable.count == 7
  and .decision.actionable.recommended_gate_id == "phase3_windows_client_beta_desktop_scaffold_gate"
  and ((.decision.reasons // []) | any(test("summary file not found or invalid JSON")))
' "$MISSING_OUTPUT" >/dev/null; then
  echo "missing-summary contract mismatch"
  cat "$MISSING_OUTPUT"
  cat "$MISSING_LOG"
  exit 1
fi
if ! grep -q '"schema"' "$MISSING_LOG"; then
  echo "--show-json 1 did not print summary payload"
  cat "$MISSING_LOG"
  exit 1
fi

echo "phase3 windows client beta check integration ok"
