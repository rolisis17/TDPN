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

SCRIPT_UNDER_TEST="${PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_CHECK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase3_windows_client_beta_handoff_check.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS_RUN="$TMP_DIR/run_pass.json"
PASS_ROADMAP="$TMP_DIR/roadmap_pass.json"
PASS_CHECK="$TMP_DIR/check_pass.json"
PASS_OUTPUT="$TMP_DIR/pass_output.json"
PASS_LOG="$TMP_DIR/pass.log"

FALLBACK_RUN="$TMP_DIR/run_fallback.json"
FALLBACK_CHECK="$TMP_DIR/check_fallback.json"
FALLBACK_ROADMAP="$TMP_DIR/roadmap_fallback.json"
FALLBACK_OUTPUT="$TMP_DIR/fallback_output.json"
FALLBACK_LOG="$TMP_DIR/fallback.log"

UNRESOLVED_RUN="$TMP_DIR/run_unresolved.json"
UNRESOLVED_ROADMAP="$TMP_DIR/roadmap_unresolved.json"
UNRESOLVED_OUTPUT="$TMP_DIR/unresolved_output.json"
UNRESOLVED_LOG="$TMP_DIR/unresolved.log"

FAIL_RUN="$TMP_DIR/run_fail.json"
FAIL_ROADMAP="$TMP_DIR/roadmap_fail.json"
FAIL_OUTPUT="$TMP_DIR/fail_output.json"
FAIL_LOG="$TMP_DIR/fail.log"

UNRESOLVED_STRICT_OUTPUT="$TMP_DIR/unresolved_strict_output.json"
UNRESOLVED_STRICT_LOG="$TMP_DIR/unresolved_strict.log"

MISSING_OUTPUT="$TMP_DIR/missing_output.json"
MISSING_LOG="$TMP_DIR/missing.log"

cat >"$PASS_ROADMAP" <<'EOF_PASS_ROADMAP'
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "vpn_track": {
    "phase3_windows_client_beta_handoff": {
      "desktop_scaffold_ok": true,
      "local_control_api_ok": true,
      "local_api_config_defaults_ok": true,
      "easy_node_config_v1_ok": true,
      "launcher_wiring_ok": true,
      "launcher_runtime_ok": true,
      "windows_native_bootstrap_guardrails_ok": true
    }
  }
}
EOF_PASS_ROADMAP

cat >"$PASS_CHECK" <<'EOF_PASS_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase3_windows_client_beta_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "windows_parity_ok": true,
  "desktop_contract_ok": true,
  "installer_update_ok": true,
  "telemetry_stability_ok": true,
  "signals": {
    "desktop_scaffold_ok": true,
    "local_control_api_ok": true,
    "local_api_config_defaults_ok": true,
    "easy_node_config_v1_ok": true,
    "launcher_wiring_ok": true,
    "launcher_runtime_ok": true,
    "windows_native_bootstrap_guardrails_ok": true,
    "windows_parity_ok": true,
    "desktop_contract_ok": true,
    "installer_update_ok": true,
    "telemetry_stability_ok": true
  },
  "handoff": {
    "windows_parity_ok": true,
    "desktop_contract_ok": true,
    "installer_update_ok": true,
    "telemetry_stability_ok": true
  },
  "phase3_windows_client_beta_handoff": {
    "windows_parity_ok": true,
    "desktop_contract_ok": true,
    "installer_update_ok": true,
    "telemetry_stability_ok": true
  }
}
EOF_PASS_CHECK

if ! jq -e '
  .windows_parity_ok == true
  and .desktop_contract_ok == true
  and .installer_update_ok == true
  and .telemetry_stability_ok == true
  and .signals.windows_native_bootstrap_guardrails_ok == true
  and .signals.windows_parity_ok == true
  and .signals.desktop_contract_ok == true
  and .signals.installer_update_ok == true
  and .signals.telemetry_stability_ok == true
  and .handoff.windows_parity_ok == true
  and .handoff.desktop_contract_ok == true
  and .handoff.installer_update_ok == true
  and .handoff.telemetry_stability_ok == true
' "$PASS_CHECK" >/dev/null; then
  echo "pass-check fixture canonical alias contract mismatch"
  cat "$PASS_CHECK"
  exit 1
fi

cat >"$PASS_RUN" <<EOF_PASS_RUN
{
  "version": 1,
  "schema": {
    "id": "phase3_windows_client_beta_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "ci_phase3_windows_client_beta": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true
    },
    "phase3_windows_client_beta_check": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "$PASS_CHECK"
      }
    }
  },
  "artifacts": {
    "check_summary_json": "$PASS_CHECK"
  }
}
EOF_PASS_RUN

echo "[phase3-windows-client-beta-handoff-check] primary roadmap pass path"
"$SCRIPT_UNDER_TEST" \
  --phase3-run-summary-json "$PASS_RUN" \
  --roadmap-summary-json "$PASS_ROADMAP" \
  --summary-json "$PASS_OUTPUT" \
  --show-json 0 >"$PASS_LOG" 2>&1

if ! jq -e '
  .version == 1
  and .schema.id == "phase3_windows_client_beta_handoff_check_summary"
  and .status == "pass"
  and .rc == 0
  and .fail_closed == true
  and .inputs.usable.phase3_run_summary_json == true
  and .inputs.usable.roadmap_summary_json == true
  and .inputs.requirements.windows_native_bootstrap_guardrails_ok == true
  and .handoff.run_pipeline_ok == true
  and .handoff.desktop_scaffold_ok == true
  and .handoff.local_control_api_ok == true
  and .handoff.local_api_config_defaults_ok == true
  and .handoff.easy_node_config_v1_ok == true
  and .handoff.launcher_wiring_ok == true
  and .handoff.launcher_runtime_ok == true
  and .handoff.windows_native_bootstrap_guardrails_ok == true
  and .handoff.failure_semantics.run_pipeline_ok.kind == "none"
  and .handoff.failure_semantics.desktop_scaffold_ok.kind == "none"
  and .handoff.failure_semantics.local_control_api_ok.kind == "none"
  and .handoff.failure_semantics.local_api_config_defaults_ok.kind == "none"
  and .handoff.failure_semantics.easy_node_config_v1_ok.kind == "none"
  and .handoff.failure_semantics.launcher_wiring_ok.kind == "none"
  and .handoff.failure_semantics.launcher_runtime_ok.kind == "none"
  and .handoff.failure_semantics.windows_native_bootstrap_guardrails_ok.kind == "none"
  and .failure.kind == "none"
  and .policy_outcome.decision == "GO"
  and .policy_outcome.fail_closed_no_go == false
  and .decision.actionable.count == 0
  and .decision.actionable.recommended_gate_id == null
  and .handoff.sources.desktop_scaffold_ok == "roadmap_progress_summary.vpn_track.phase3_windows_client_beta_handoff.desktop_scaffold_ok"
  and .handoff.sources.windows_native_bootstrap_guardrails_ok == "roadmap_progress_summary.vpn_track.phase3_windows_client_beta_handoff.windows_native_bootstrap_guardrails_ok"
' "$PASS_OUTPUT" >/dev/null; then
  echo "primary pass-path summary mismatch"
  cat "$PASS_OUTPUT"
  cat "$PASS_LOG"
  exit 1
fi

cat >"$FALLBACK_CHECK" <<'EOF_FALLBACK_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase3_windows_client_beta_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "windows_parity_ok": true,
  "desktop_contract_ok": true,
  "installer_update_ok": true,
  "telemetry_stability_ok": true,
  "signals": {
    "desktop_scaffold_ok": true,
    "local_control_api_ok": true,
    "local_api_config_defaults_ok": true,
    "easy_node_config_v1_ok": true,
    "launcher_wiring_ok": true,
    "launcher_runtime_ok": true,
    "windows_native_bootstrap_guardrails_ok": true,
    "windows_parity_ok": true,
    "desktop_contract_ok": true,
    "installer_update_ok": true,
    "telemetry_stability_ok": true
  },
  "handoff": {
    "windows_parity_ok": true,
    "desktop_contract_ok": true,
    "installer_update_ok": true,
    "telemetry_stability_ok": true
  },
  "phase3_windows_client_beta_handoff": {
    "windows_parity_ok": true,
    "desktop_contract_ok": true,
    "installer_update_ok": true,
    "telemetry_stability_ok": true
  }
}
EOF_FALLBACK_CHECK

if ! jq -e '
  .windows_parity_ok == true
  and .desktop_contract_ok == true
  and .installer_update_ok == true
  and .telemetry_stability_ok == true
  and .signals.windows_native_bootstrap_guardrails_ok == true
  and .signals.windows_parity_ok == true
  and .signals.desktop_contract_ok == true
  and .signals.installer_update_ok == true
  and .signals.telemetry_stability_ok == true
  and .handoff.windows_parity_ok == true
  and .handoff.desktop_contract_ok == true
  and .handoff.installer_update_ok == true
  and .handoff.telemetry_stability_ok == true
' "$FALLBACK_CHECK" >/dev/null; then
  echo "fallback-check fixture canonical alias contract mismatch"
  cat "$FALLBACK_CHECK"
  exit 1
fi

cat >"$FALLBACK_RUN" <<EOF_FALLBACK_RUN
{
  "version": 1,
  "schema": {
    "id": "phase3_windows_client_beta_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "ci_phase3_windows_client_beta": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true
    },
    "phase3_windows_client_beta_check": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "$FALLBACK_CHECK"
      }
    }
  },
  "artifacts": {
    "check_summary_json": "$FALLBACK_CHECK"
  }
}
EOF_FALLBACK_RUN

cat >"$FALLBACK_ROADMAP" <<'EOF_FALLBACK_ROADMAP'
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "vpn_track": {
    "phase3_windows_client_beta_handoff": {
      "note": "missing booleans on purpose"
    }
  }
}
EOF_FALLBACK_ROADMAP

echo "[phase3-windows-client-beta-handoff-check] nested check fallback path"
"$SCRIPT_UNDER_TEST" \
  --phase3-run-summary-json "$FALLBACK_RUN" \
  --roadmap-summary-json "$FALLBACK_ROADMAP" \
  --summary-json "$FALLBACK_OUTPUT" \
  --show-json 0 >"$FALLBACK_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .handoff.desktop_scaffold_ok == true
  and .handoff.local_control_api_ok == true
  and .handoff.local_api_config_defaults_ok == true
  and .handoff.easy_node_config_v1_ok == true
  and .handoff.launcher_wiring_ok == true
  and .handoff.launcher_runtime_ok == true
  and .handoff.windows_native_bootstrap_guardrails_ok == true
  and .handoff.sources.desktop_scaffold_ok == "phase3_windows_client_beta_check_summary.desktop_scaffold_ok"
  and .handoff.sources.local_control_api_ok == "phase3_windows_client_beta_check_summary.local_control_api_ok"
  and .handoff.sources.local_api_config_defaults_ok == "phase3_windows_client_beta_check_summary.local_api_config_defaults_ok"
  and .handoff.sources.easy_node_config_v1_ok == "phase3_windows_client_beta_check_summary.easy_node_config_v1_ok"
  and .handoff.sources.launcher_wiring_ok == "phase3_windows_client_beta_check_summary.launcher_wiring_ok"
  and .handoff.sources.launcher_runtime_ok == "phase3_windows_client_beta_check_summary.launcher_runtime_ok"
  and .handoff.sources.windows_native_bootstrap_guardrails_ok == "phase3_windows_client_beta_check_summary.windows_native_bootstrap_guardrails_ok"
  and .handoff.failure_semantics.run_pipeline_ok.kind == "none"
  and .handoff.failure_semantics.desktop_scaffold_ok.kind == "none"
  and .handoff.failure_semantics.local_control_api_ok.kind == "none"
  and .handoff.failure_semantics.local_api_config_defaults_ok.kind == "none"
  and .handoff.failure_semantics.easy_node_config_v1_ok.kind == "none"
  and .handoff.failure_semantics.launcher_wiring_ok.kind == "none"
  and .handoff.failure_semantics.launcher_runtime_ok.kind == "none"
  and .handoff.failure_semantics.windows_native_bootstrap_guardrails_ok.kind == "none"
  and .failure.kind == "none"
  and .policy_outcome.decision == "GO"
  and .decision.actionable.count == 0
' "$FALLBACK_OUTPUT" >/dev/null; then
  echo "fallback-path summary mismatch"
  cat "$FALLBACK_OUTPUT"
  cat "$FALLBACK_LOG"
  exit 1
fi

cat >"$UNRESOLVED_RUN" <<'EOF_UNRESOLVED_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase3_windows_client_beta_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "ci_phase3_windows_client_beta": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true
    },
    "phase3_windows_client_beta_check": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "/tmp/does-not-exist-check-summary.json"
      }
    }
  }
}
EOF_UNRESOLVED_RUN

cat >"$UNRESOLVED_ROADMAP" <<'EOF_UNRESOLVED_ROADMAP'
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "vpn_track": {
    "phase3_windows_client_beta_handoff": {
      "note": "intentionally unresolved"
    }
  }
}
EOF_UNRESOLVED_ROADMAP

echo "[phase3-windows-client-beta-handoff-check] unresolved booleans with relaxed requirements"
"$SCRIPT_UNDER_TEST" \
  --phase3-run-summary-json "$UNRESOLVED_RUN" \
  --roadmap-summary-json "$UNRESOLVED_ROADMAP" \
  --summary-json "$UNRESOLVED_OUTPUT" \
  --require-run-pipeline-ok 0 \
  --require-desktop-scaffold-ok 0 \
  --require-local-control-api-ok 0 \
  --require-local-api-config-defaults-ok 0 \
  --require-easy-node-config-v1-ok 0 \
  --require-launcher-wiring-ok 0 \
  --require-launcher-runtime-ok 0 \
  --require-windows-native-bootstrap-guardrails-ok 0 \
  --show-json 0 >"$UNRESOLVED_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .handoff.run_pipeline_ok == true
  and .handoff.desktop_scaffold_ok == null
  and .handoff.local_control_api_ok == null
  and .handoff.local_api_config_defaults_ok == null
  and .handoff.easy_node_config_v1_ok == null
  and .handoff.launcher_wiring_ok == null
  and .handoff.launcher_runtime_ok == null
  and .handoff.windows_native_bootstrap_guardrails_ok == null
  and .failure.kind == "none"
  and .policy_outcome.decision == "GO"
  and .decision.actionable.count == 0
' "$UNRESOLVED_OUTPUT" >/dev/null; then
  echo "unresolved relaxed summary mismatch"
  cat "$UNRESOLVED_OUTPUT"
  cat "$UNRESOLVED_LOG"
  exit 1
fi

echo "[phase3-windows-client-beta-handoff-check] unresolved required handoff signals are fail-closed"
set +e
"$SCRIPT_UNDER_TEST" \
  --phase3-run-summary-json "$UNRESOLVED_RUN" \
  --roadmap-summary-json "$UNRESOLVED_ROADMAP" \
  --summary-json "$UNRESOLVED_STRICT_OUTPUT" \
  --show-json 0 >"$UNRESOLVED_STRICT_LOG" 2>&1
unresolved_strict_rc=$?
set -e
if [[ "$unresolved_strict_rc" -ne 1 ]]; then
  echo "expected rc=1 for unresolved strict fail-close, got rc=$unresolved_strict_rc"
  cat "$UNRESOLVED_STRICT_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .handoff.run_pipeline_ok == true
  and .handoff.desktop_scaffold_ok == null
  and .handoff.desktop_scaffold_resolved == false
  and .handoff.sources.desktop_scaffold_ok == "unresolved"
  and .handoff.failure_semantics.desktop_scaffold_ok.kind == "execution_failure"
  and .handoff.failure_semantics.desktop_scaffold_ok.execution_failure == true
  and .handoff.windows_native_bootstrap_guardrails_ok == null
  and .handoff.windows_native_bootstrap_guardrails_resolved == false
  and .handoff.sources.windows_native_bootstrap_guardrails_ok == "unresolved"
  and .handoff.failure_semantics.windows_native_bootstrap_guardrails_ok.kind == "execution_failure"
  and .handoff.failure_semantics.windows_native_bootstrap_guardrails_ok.execution_failure == true
  and .failure.kind == "execution_failure"
  and .failure.execution_failure == true
  and .policy_outcome.decision == "ERROR"
  and .policy_outcome.fail_closed_no_go == false
  and .decision.actionable.count >= 1
  and .decision.actionable.recommended_gate_id == "phase3_windows_client_beta_desktop_scaffold_gate"
  and ((.decision.reasons // []) | any(test("desktop_scaffold_ok unresolved from provided artifacts")))
' "$UNRESOLVED_STRICT_OUTPUT" >/dev/null; then
  echo "unresolved strict summary mismatch"
  cat "$UNRESOLVED_STRICT_OUTPUT"
  cat "$UNRESOLVED_STRICT_LOG"
  exit 1
fi

cat >"$FAIL_RUN" <<'EOF_FAIL_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase3_windows_client_beta_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "rc": 27,
  "steps": {
    "ci_phase3_windows_client_beta": {
      "status": "fail",
      "rc": 27,
      "command_rc": 27,
      "contract_valid": true
    },
    "phase3_windows_client_beta_check": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "/tmp/check_fail.json"
      }
    }
  }
}
EOF_FAIL_RUN

cat >"$FAIL_ROADMAP" <<'EOF_FAIL_ROADMAP'
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "vpn_track": {
    "phase3_windows_client_beta_handoff": {
      "desktop_scaffold_ok": true,
      "local_control_api_ok": true,
      "local_api_config_defaults_ok": true,
      "easy_node_config_v1_ok": true,
      "launcher_wiring_ok": true,
      "launcher_runtime_ok": true,
      "windows_native_bootstrap_guardrails_ok": true
    }
  }
}
EOF_FAIL_ROADMAP

echo "[phase3-windows-client-beta-handoff-check] run pipeline failure is fail-closed"
set +e
"$SCRIPT_UNDER_TEST" \
  --phase3-run-summary-json "$FAIL_RUN" \
  --roadmap-summary-json "$FAIL_ROADMAP" \
  --summary-json "$FAIL_OUTPUT" \
  --show-json 0 >"$FAIL_LOG" 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for run pipeline failure, got rc=$fail_rc"
  cat "$FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .handoff.run_pipeline_ok == false
  and .handoff.failure_semantics.run_pipeline_ok.kind == "execution_failure"
  and .failure.kind == "execution_failure"
  and .policy_outcome.decision == "ERROR"
  and .decision.actionable.count == 1
  and .decision.actionable.recommended_gate_id == "phase3_windows_client_beta_run_pipeline_gate"
  and ((.decision.reasons // []) | any(test("run_pipeline_ok is false|run_pipeline_ok unresolved")))
' "$FAIL_OUTPUT" >/dev/null; then
  echo "run pipeline failure summary mismatch"
  cat "$FAIL_OUTPUT"
  cat "$FAIL_LOG"
  exit 1
fi

echo "[phase3-windows-client-beta-handoff-check] missing run summary contract fail-close"
set +e
"$SCRIPT_UNDER_TEST" \
  --phase3-run-summary-json "$TMP_DIR/missing_run.json" \
  --roadmap-summary-json "$PASS_ROADMAP" \
  --summary-json "$MISSING_OUTPUT" \
  --show-json 1 >"$MISSING_LOG" 2>&1
missing_rc=$?
set -e
if [[ "$missing_rc" -ne 1 ]]; then
  echo "expected rc=1 for missing run summary fail-close, got rc=$missing_rc"
  cat "$MISSING_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .inputs.usable.phase3_run_summary_json == false
  and .handoff.run_pipeline_ok == null
  and .handoff.failure_semantics.run_pipeline_ok.kind == "execution_failure"
  and .failure.kind == "execution_failure"
  and .policy_outcome.decision == "ERROR"
  and .decision.actionable.count == 1
  and .decision.actionable.recommended_gate_id == "phase3_windows_client_beta_run_pipeline_gate"
  and ((.decision.reasons // []) | any(test("phase3 run summary file not found or invalid JSON")))
' "$MISSING_OUTPUT" >/dev/null; then
  echo "missing-run summary mismatch"
  cat "$MISSING_OUTPUT"
  cat "$MISSING_LOG"
  exit 1
fi
if ! grep -q '"schema"' "$MISSING_LOG"; then
  echo "--show-json 1 did not print summary payload"
  cat "$MISSING_LOG"
  exit 1
fi

echo "phase3 windows client beta handoff check integration ok"
