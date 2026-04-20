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

RUNNER="${PHASE3_WINDOWS_CLIENT_BETA_RUN_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase3_windows_client_beta_run.sh}"
if [[ ! -x "$RUNNER" ]]; then
  echo "missing executable script under test: $RUNNER"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/stage_capture.tsv"
DRY_RUN_LOG="$TMP_DIR/dry_run.log"
CI_FAIL_LOG="$TMP_DIR/ci_fail.log"
CONTRACT_FAIL_LOG="$TMP_DIR/contract_fail.log"

FAKE_CI="$TMP_DIR/fake_ci_phase3.sh"
cat >"$FAKE_CI" <<'EOF_FAKE_CI'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE3_WINDOWS_CLIENT_BETA_RUN_CAPTURE_FILE:?}"
printf 'ci\t%s\n' "$*" >>"$capture"

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

fail_rc="${FAKE_CI_FAIL_RC:-27}"
status="pass"
rc=0
if [[ "${FAKE_CI_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc="$fail_rc"
fi

if [[ -n "$summary_json" && "${FAKE_CI_OMIT_SUMMARY:-0}" != "1" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<EOF_CI_SUMMARY
{
  "version": 1,
  "schema": {
    "id": "ci_phase3_windows_client_beta_summary",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc,
  "steps": {
    "desktop_scaffold_contract": {
      "status": "$status"
    },
    "local_control_api_contract": {
      "status": "$status"
    },
    "local_api_config_defaults": {
      "status": "$status"
    },
    "easy_node_config_v1": {
      "status": "$status"
    },
    "easy_mode_launcher_wiring": {
      "status": "$status"
    },
    "easy_mode_launcher_runtime": {
      "status": "$status"
    }
  }
}
EOF_CI_SUMMARY
fi

if [[ "${FAKE_CI_FAIL:-0}" == "1" ]]; then
  exit "$fail_rc"
fi
exit 0
EOF_FAKE_CI
chmod +x "$FAKE_CI"

FAKE_CHECK="$TMP_DIR/fake_phase3_windows_client_beta_check.sh"
cat >"$FAKE_CHECK" <<'EOF_FAKE_CHECK'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE3_WINDOWS_CLIENT_BETA_RUN_CAPTURE_FILE:?}"
printf 'check\t%s\n' "$*" >>"$capture"

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

fail_rc="${FAKE_CHECK_FAIL_RC:-19}"
status="pass"
rc=0
failure_kind="none"
policy_decision="GO"
actionable_count=0
recommended_gate_id_json="null"
effective_policy_relaxed="false"
effective_strict_readiness_ok="true"
effective_status="pass"
effective_reason_json="null"
if [[ "${FAKE_CHECK_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc="$fail_rc"
  failure_kind="policy_no_go"
  policy_decision="NO-GO"
  actionable_count=1
  recommended_gate_id_json="\"phase3_windows_client_beta_local_control_api_gate\""
  effective_strict_readiness_ok="false"
  effective_status="fail"
  effective_reason_json="\"top_level_policy_no_go\""
fi

if [[ -n "$summary_json" && "${FAKE_CHECK_OMIT_SUMMARY:-0}" != "1" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<EOF_CHECK_SUMMARY
{
  "version": 1,
  "schema": {
    "id": "phase3_windows_client_beta_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc,
  "policy": {
    "require_desktop_scaffold_ok": true,
    "require_windows_native_bootstrap_guardrails_ok": true,
    "require_local_control_api_ok": true,
    "require_local_api_config_defaults_ok": true,
    "require_easy_node_config_v1_ok": true,
    "require_launcher_wiring_ok": true,
    "require_launcher_runtime_ok": true
  },
  "signals": {
    "desktop_scaffold_ok": true,
    "windows_native_bootstrap_guardrails_ok": true,
    "local_control_api_ok": true,
    "local_api_config_defaults_ok": true,
    "easy_node_config_v1_ok": true,
    "launcher_wiring_ok": true,
    "launcher_runtime_ok": true
  },
  "stages": {
    "desktop_scaffold": {
      "status": "$status",
      "resolved": true,
      "ok": true
    },
    "windows_native_bootstrap_guardrails": {
      "status": "$status",
      "resolved": true,
      "ok": true
    },
    "local_control_api": {
      "status": "$status",
      "resolved": true,
      "ok": true
    },
    "local_api_config_defaults": {
      "status": "$status",
      "resolved": true,
      "ok": true
    },
    "easy_node_config_v1": {
      "status": "$status",
      "resolved": true,
      "ok": true
    },
    "launcher_wiring": {
      "status": "$status",
      "resolved": true,
      "ok": true
    },
      "launcher_runtime": {
        "status": "$status",
        "resolved": true,
        "ok": true
      }
    },
    "failure": {
      "kind": "$failure_kind",
      "policy_no_go": $( [[ "$failure_kind" == "policy_no_go" ]] && printf '%s' "true" || printf '%s' "false" ),
      "execution_failure": false,
      "timeout": false
    },
    "policy_outcome": {
      "decision": "$policy_decision",
      "fail_closed_no_go": $( [[ "$failure_kind" == "policy_no_go" ]] && printf '%s' "true" || printf '%s' "false" )
    },
    "decision": {
      "pass": $( [[ "$status" == "pass" ]] && printf '%s' "true" || printf '%s' "false" ),
      "reasons": [],
      "actionable": {
        "count": $actionable_count,
        "recommended_gate_id": $recommended_gate_id_json,
        "gates": []
      }
    },
    "effective": {
      "policy_relaxed": $effective_policy_relaxed,
      "strict_readiness_ok": $effective_strict_readiness_ok,
      "status": "$effective_status",
      "reason": $effective_reason_json
    }
  }
EOF_CHECK_SUMMARY
fi

if [[ "${FAKE_CHECK_FAIL:-0}" == "1" ]]; then
  exit "$fail_rc"
fi
exit 0
EOF_FAKE_CHECK
chmod +x "$FAKE_CHECK"

DRY_RUN_RUN_SUMMARY="$TMP_DIR/run_dry.json"
CI_FAIL_RUN_SUMMARY="$TMP_DIR/run_ci_fail.json"
CONTRACT_FAIL_RUN_SUMMARY="$TMP_DIR/run_contract_fail.json"

echo "[phase3-windows-client-beta-run] dry-run forwarding contract"
: >"$CAPTURE"
PHASE3_WINDOWS_CLIENT_BETA_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE3_WINDOWS_CLIENT_BETA_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE3_WINDOWS_CLIENT_BETA_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_dry" \
  --ci-summary-json "$TMP_DIR/ci_dry_summary.json" \
  --check-summary-json "$TMP_DIR/check_dry_summary.json" \
  --summary-json "$DRY_RUN_RUN_SUMMARY" \
  --dry-run 1 \
  --print-summary-json 0 \
  --ci-run-desktop-scaffold-contract 1 \
  --check-require-desktop-scaffold-ok 1 \
  --check-require-windows-native-bootstrap-guardrails-ok 1 \
  --check-require-launcher-runtime-ok 1 \
  --check-show-json 1 >"$DRY_RUN_LOG" 2>&1

ci_line="$(grep '^ci	' "$CAPTURE" | tail -n 1 || true)"
check_line="$(grep '^check	' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$ci_line" || -z "$check_line" ]]; then
  echo "expected both stages to run in dry-run path"
  cat "$CAPTURE"
  cat "$DRY_RUN_LOG"
  exit 1
fi
if [[ "$ci_line" != *"--dry-run 1"* || "$ci_line" != *"--summary-json $TMP_DIR/ci_dry_summary.json"* ]]; then
  echo "dry-run ci forwarding contract mismatch"
  echo "$ci_line"
  exit 1
fi
if [[ "$ci_line" != *"--run-desktop-scaffold-contract 1"* ]]; then
  echo "ci passthrough contract mismatch"
  echo "$ci_line"
  exit 1
fi
if [[ "$check_line" != *"--ci-phase3-summary-json $TMP_DIR/ci_dry_summary.json"* ]]; then
  echo "dry-run check forwarding missing ci summary path"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" != *"--summary-json $TMP_DIR/check_dry_summary.json"* ]]; then
  echo "dry-run check forwarding missing check summary path"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" != *"--require-desktop-scaffold-ok 1"* || "$check_line" != *"--require-windows-native-bootstrap-guardrails-ok 1"* || "$check_line" != *"--require-launcher-runtime-ok 1"* ]]; then
  echo "check passthrough contract mismatch"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" != *"--show-json 1"* ]]; then
  echo "check show-json forwarding mismatch"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" == *"--dry-run 1"* || "$check_line" == *"--print-summary-json 0"* ]]; then
  echo "wrapper-only flags leaked into checker"
  echo "$check_line"
  exit 1
fi

if [[ ! -f "$DRY_RUN_RUN_SUMMARY" ]]; then
  echo "missing dry-run combined summary JSON: $DRY_RUN_RUN_SUMMARY"
  cat "$DRY_RUN_LOG"
  exit 1
fi
if ! jq -e '
  .version == 1
  and .schema.id == "phase3_windows_client_beta_run_summary"
  and .status == "pass"
  and .rc == 0
  and .inputs.dry_run == true
  and .steps.ci_phase3_windows_client_beta.status == "pass"
  and .steps.ci_phase3_windows_client_beta.rc == 0
  and .steps.ci_phase3_windows_client_beta.command_rc == 0
  and .steps.ci_phase3_windows_client_beta.contract_valid == true
  and .steps.ci_phase3_windows_client_beta.artifacts.summary_exists == true
  and .steps.phase3_windows_client_beta_check.status == "pass"
  and .steps.phase3_windows_client_beta_check.rc == 0
  and .steps.phase3_windows_client_beta_check.command_rc == 0
  and .steps.phase3_windows_client_beta_check.contract_valid == true
  and .steps.phase3_windows_client_beta_check.failure.kind == "none"
  and .steps.phase3_windows_client_beta_check.policy_outcome.decision == "GO"
  and .steps.phase3_windows_client_beta_check.actionable.count == 0
  and .steps.phase3_windows_client_beta_check.actionable.recommended_gate_id == null
  and .steps.phase3_windows_client_beta_check.effective.policy_relaxed == false
  and .steps.phase3_windows_client_beta_check.effective.strict_readiness_ok == true
  and .steps.phase3_windows_client_beta_check.effective.status == "pass"
  and .steps.phase3_windows_client_beta_check.effective.reason == null
  and .steps.phase3_windows_client_beta_check.artifacts.summary_exists == true
' "$DRY_RUN_RUN_SUMMARY" >/dev/null; then
  echo "dry-run combined summary contract mismatch"
  cat "$DRY_RUN_RUN_SUMMARY"
  exit 1
fi
if ! jq -e '
  .policy.require_windows_native_bootstrap_guardrails_ok == true
  and .signals.windows_native_bootstrap_guardrails_ok == true
  and .stages.windows_native_bootstrap_guardrails.status == "pass"
  and .stages.windows_native_bootstrap_guardrails.resolved == true
  and .stages.windows_native_bootstrap_guardrails.ok == true
' "$TMP_DIR/check_dry_summary.json" >/dev/null; then
  echo "dry-run checker summary missing windows native bootstrap guardrails contract fields"
  cat "$TMP_DIR/check_dry_summary.json"
  exit 1
fi

echo "[phase3-windows-client-beta-run] ci failure keeps checker execution"
: >"$CAPTURE"
set +e
PHASE3_WINDOWS_CLIENT_BETA_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE3_WINDOWS_CLIENT_BETA_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE3_WINDOWS_CLIENT_BETA_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CI_FAIL=1 \
FAKE_CI_FAIL_RC=27 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_fail" \
  --ci-summary-json "$TMP_DIR/ci_fail_summary.json" \
  --check-summary-json "$TMP_DIR/check_fail_summary.json" \
  --summary-json "$CI_FAIL_RUN_SUMMARY" \
  --print-summary-json 0 >"$CI_FAIL_LOG" 2>&1
ci_fail_rc=$?
set -e
if [[ "$ci_fail_rc" -ne 27 ]]; then
  echo "expected wrapper fail rc=27, got rc=$ci_fail_rc"
  cat "$CI_FAIL_LOG"
  exit 1
fi
ci_line="$(grep '^ci	' "$CAPTURE" | tail -n 1 || true)"
check_line="$(grep '^check	' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$ci_line" || -z "$check_line" ]]; then
  echo "expected both stages to run in ci-failure path"
  cat "$CAPTURE"
  cat "$CI_FAIL_LOG"
  exit 1
fi
if [[ "$check_line" != *"--show-json 0"* ]]; then
  echo "default checker show-json forwarding missing"
  echo "$check_line"
  exit 1
fi
if [[ ! -f "$CI_FAIL_RUN_SUMMARY" ]]; then
  echo "missing fail-path combined summary JSON: $CI_FAIL_RUN_SUMMARY"
  cat "$CI_FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 27
  and .steps.ci_phase3_windows_client_beta.status == "fail"
  and .steps.ci_phase3_windows_client_beta.rc == 27
  and .steps.ci_phase3_windows_client_beta.command_rc == 27
  and .steps.ci_phase3_windows_client_beta.contract_valid == true
  and .steps.phase3_windows_client_beta_check.status == "pass"
  and .steps.phase3_windows_client_beta_check.rc == 0
  and .steps.phase3_windows_client_beta_check.command_rc == 0
  and .steps.phase3_windows_client_beta_check.contract_valid == true
  and .steps.phase3_windows_client_beta_check.failure.kind == "none"
  and .steps.phase3_windows_client_beta_check.policy_outcome.decision == "GO"
  and .steps.phase3_windows_client_beta_check.actionable.count == 0
  and .steps.phase3_windows_client_beta_check.effective.policy_relaxed == false
  and .steps.phase3_windows_client_beta_check.effective.strict_readiness_ok == true
  and .steps.phase3_windows_client_beta_check.effective.status == "pass"
  and .steps.phase3_windows_client_beta_check.effective.reason == null
' "$CI_FAIL_RUN_SUMMARY" >/dev/null; then
  echo "ci-failure combined summary contract mismatch"
  cat "$CI_FAIL_RUN_SUMMARY"
  exit 1
fi

echo "[phase3-windows-client-beta-run] checker contract failure is fail-closed"
: >"$CAPTURE"
set +e
PHASE3_WINDOWS_CLIENT_BETA_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE3_WINDOWS_CLIENT_BETA_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE3_WINDOWS_CLIENT_BETA_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CHECK_OMIT_SUMMARY=1 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_contract_fail" \
  --ci-summary-json "$TMP_DIR/ci_contract_fail_summary.json" \
  --check-summary-json "$TMP_DIR/check_contract_fail_summary.json" \
  --summary-json "$CONTRACT_FAIL_RUN_SUMMARY" \
  --dry-run 1 \
  --print-summary-json 0 >"$CONTRACT_FAIL_LOG" 2>&1
contract_fail_rc=$?
set -e
if [[ "$contract_fail_rc" -ne 3 ]]; then
  echo "expected wrapper rc=3 when checker contract is missing, got rc=$contract_fail_rc"
  cat "$CONTRACT_FAIL_LOG"
  exit 1
fi
if [[ ! -f "$CONTRACT_FAIL_RUN_SUMMARY" ]]; then
  echo "missing contract-fail combined summary JSON: $CONTRACT_FAIL_RUN_SUMMARY"
  cat "$CONTRACT_FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 3
  and .steps.ci_phase3_windows_client_beta.status == "pass"
  and .steps.ci_phase3_windows_client_beta.contract_valid == true
  and .steps.phase3_windows_client_beta_check.status == "fail"
  and .steps.phase3_windows_client_beta_check.command_rc == 0
  and .steps.phase3_windows_client_beta_check.contract_valid == false
  and .steps.phase3_windows_client_beta_check.contract_error != null
  and .steps.phase3_windows_client_beta_check.effective.policy_relaxed == null
  and .steps.phase3_windows_client_beta_check.effective.strict_readiness_ok == null
  and .steps.phase3_windows_client_beta_check.effective.status == null
  and .steps.phase3_windows_client_beta_check.effective.reason == null
' "$CONTRACT_FAIL_RUN_SUMMARY" >/dev/null; then
  echo "checker-contract-fail combined summary mismatch"
  cat "$CONTRACT_FAIL_RUN_SUMMARY"
  exit 1
fi

echo "phase3 windows client beta run integration ok"
