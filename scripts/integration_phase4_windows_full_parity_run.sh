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

RUNNER="${PHASE4_WINDOWS_FULL_PARITY_RUN_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase4_windows_full_parity_run.sh}"
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

FAKE_CI="$TMP_DIR/fake_ci_phase4.sh"
cat >"$FAKE_CI" <<'EOF_FAKE_CI'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE4_WINDOWS_FULL_PARITY_RUN_CAPTURE_FILE:?}"
printf 'ci\t%s\n' "$*" >>"$capture"

summary_json=""
require_windows_server_packaging_ok="0"
require_windows_role_runbooks_ok="0"
require_cross_platform_interop_ok="0"
require_role_combination_validation_ok="0"
require_windows_native_bootstrap_guardrails_ok="0"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --require-windows-server-packaging-ok)
      require_windows_server_packaging_ok="${2:-1}"
      shift 2
      ;;
    --require-windows-role-runbooks-ok)
      require_windows_role_runbooks_ok="${2:-1}"
      shift 2
      ;;
    --require-cross-platform-interop-ok)
      require_cross_platform_interop_ok="${2:-1}"
      shift 2
      ;;
    --require-role-combination-validation-ok)
      require_role_combination_validation_ok="${2:-1}"
      shift 2
      ;;
    --require-windows-native-bootstrap-guardrails-ok)
      require_windows_native_bootstrap_guardrails_ok="${2:-1}"
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
    "id": "ci_phase4_windows_full_parity_summary",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc,
  "steps": {
    "windows_server_packaging": {
      "status": "$status"
    },
    "windows_role_runbooks": {
      "status": "$status"
    },
    "cross_platform_interop": {
      "status": "$status"
    },
    "role_combination_validation": {
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

FAKE_CHECK="$TMP_DIR/fake_phase4_windows_full_parity_check.sh"
cat >"$FAKE_CHECK" <<'EOF_FAKE_CHECK'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE4_WINDOWS_FULL_PARITY_RUN_CAPTURE_FILE:?}"
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
if [[ "${FAKE_CHECK_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc="$fail_rc"
fi

if [[ -n "$summary_json" && "${FAKE_CHECK_OMIT_SUMMARY:-0}" != "1" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<EOF_CHECK_SUMMARY
{
  "version": 1,
  "schema": {
    "id": "phase4_windows_full_parity_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc,
  "policy": {
    "require_windows_server_packaging_ok": true,
    "require_windows_role_runbooks_ok": true,
    "require_cross_platform_interop_ok": true,
    "require_role_combination_validation_ok": true,
    "require_windows_native_bootstrap_guardrails_ok": true
  },
  "signals": {
    "windows_server_packaging_ok": true,
    "windows_role_runbooks_ok": true,
    "cross_platform_interop_ok": true,
    "role_combination_validation_ok": true,
    "windows_native_bootstrap_guardrails_ok": true
  },
  "stages": {
    "windows_server_packaging": {
      "status": "$status",
      "resolved": true,
      "ok": true
    },
    "windows_role_runbooks": {
      "status": "$status",
      "resolved": true,
      "ok": true
    },
    "cross_platform_interop": {
      "status": "$status",
      "resolved": true,
      "ok": true
    },
    "role_combination_validation": {
      "status": "$status",
      "resolved": true,
      "ok": true
    },
    "windows_native_bootstrap_guardrails": {
      "status": "$status",
      "resolved": true,
      "ok": true
    }
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

echo "[phase4-windows-full-parity-run] dry-run forwarding contract"
: >"$CAPTURE"
PHASE4_WINDOWS_FULL_PARITY_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE4_WINDOWS_FULL_PARITY_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE4_WINDOWS_FULL_PARITY_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_dry" \
  --ci-summary-json "$TMP_DIR/ci_dry_summary.json" \
  --check-summary-json "$TMP_DIR/check_dry_summary.json" \
  --summary-json "$DRY_RUN_RUN_SUMMARY" \
  --dry-run 1 \
  --print-summary-json 0 \
  --ci-run-windows-server-packaging 1 \
  --check-require-windows-server-packaging-ok 1 \
  --check-require-cross-platform-interop-ok 1 \
  --check-require-windows-native-bootstrap-guardrails-ok 1 \
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
if [[ "$ci_line" != *"--run-windows-server-packaging 1"* ]]; then
  echo "ci passthrough contract mismatch"
  echo "$ci_line"
  exit 1
fi
if [[ "$check_line" != *"--ci-phase4-summary-json $TMP_DIR/ci_dry_summary.json"* ]]; then
  echo "dry-run check forwarding missing ci summary path"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" != *"--summary-json $TMP_DIR/check_dry_summary.json"* ]]; then
  echo "dry-run check forwarding missing check summary path"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" != *"--require-windows-server-packaging-ok 1"* || "$check_line" != *"--require-cross-platform-interop-ok 1"* ]]; then
  echo "check passthrough contract mismatch"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" != *"--require-windows-native-bootstrap-guardrails-ok 1"* ]]; then
  echo "check guardrail passthrough mismatch"
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
  and .schema.id == "phase4_windows_full_parity_run_summary"
  and .status == "pass"
  and .rc == 0
  and .inputs.dry_run == true
  and .steps.ci_phase4_windows_full_parity.status == "pass"
  and .steps.ci_phase4_windows_full_parity.rc == 0
  and .steps.ci_phase4_windows_full_parity.command_rc == 0
  and .steps.ci_phase4_windows_full_parity.contract_valid == true
  and .steps.ci_phase4_windows_full_parity.failure_kind == "none"
  and .steps.ci_phase4_windows_full_parity.artifacts.summary_exists == true
  and .steps.phase4_windows_full_parity_check.status == "pass"
  and .steps.phase4_windows_full_parity_check.rc == 0
  and .steps.phase4_windows_full_parity_check.command_rc == 0
  and .steps.phase4_windows_full_parity_check.contract_valid == true
  and .steps.phase4_windows_full_parity_check.failure_kind == "none"
  and .steps.phase4_windows_full_parity_check.artifacts.summary_exists == true
  and .decision.pass == true
  and .decision.failure_stage == null
  and .decision.failure_kind == "none"
  and ((.decision.reason_codes // []) | length) == 0
  and .failure.kind == "none"
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

echo "[phase4-windows-full-parity-run] ci failure keeps checker execution"
: >"$CAPTURE"
set +e
PHASE4_WINDOWS_FULL_PARITY_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE4_WINDOWS_FULL_PARITY_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE4_WINDOWS_FULL_PARITY_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
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
  and .steps.ci_phase4_windows_full_parity.status == "fail"
  and .steps.ci_phase4_windows_full_parity.rc == 27
  and .steps.ci_phase4_windows_full_parity.command_rc == 27
  and .steps.ci_phase4_windows_full_parity.contract_valid == true
  and .steps.ci_phase4_windows_full_parity.failure_kind == "command_failed"
  and .steps.phase4_windows_full_parity_check.status == "pass"
  and .steps.phase4_windows_full_parity_check.rc == 0
  and .steps.phase4_windows_full_parity_check.command_rc == 0
  and .steps.phase4_windows_full_parity_check.contract_valid == true
  and .decision.failure_stage == "ci_phase4_windows_full_parity"
  and .decision.failure_kind == "command_failed"
  and ((.decision.reason_codes // []) | any(. == "ci_phase4_stage_failed"))
  and .failure.kind == "stage_failed"
' "$CI_FAIL_RUN_SUMMARY" >/dev/null; then
  echo "ci-failure combined summary contract mismatch"
  cat "$CI_FAIL_RUN_SUMMARY"
  exit 1
fi

echo "[phase4-windows-full-parity-run] checker contract failure is fail-closed"
: >"$CAPTURE"
set +e
PHASE4_WINDOWS_FULL_PARITY_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE4_WINDOWS_FULL_PARITY_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE4_WINDOWS_FULL_PARITY_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
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
  and .steps.ci_phase4_windows_full_parity.status == "pass"
  and .steps.ci_phase4_windows_full_parity.contract_valid == true
  and .steps.phase4_windows_full_parity_check.status == "fail"
  and .steps.phase4_windows_full_parity_check.command_rc == 0
  and .steps.phase4_windows_full_parity_check.contract_valid == false
  and .steps.phase4_windows_full_parity_check.contract_error != null
  and .steps.phase4_windows_full_parity_check.failure_kind == "contract_invalid"
  and .decision.failure_stage == "phase4_windows_full_parity_check"
  and .decision.failure_kind == "contract_invalid"
  and ((.decision.reason_codes // []) | any(. == "phase4_windows_full_parity_check_contract_invalid"))
  and .failure.kind == "contract_invalid"
' "$CONTRACT_FAIL_RUN_SUMMARY" >/dev/null; then
  echo "checker-contract-fail combined summary mismatch"
  cat "$CONTRACT_FAIL_RUN_SUMMARY"
  exit 1
fi

echo "phase4 windows full parity run integration ok"
