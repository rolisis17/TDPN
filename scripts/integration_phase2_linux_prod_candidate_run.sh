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

RUNNER="${PHASE2_LINUX_PROD_CANDIDATE_RUN_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase2_linux_prod_candidate_run.sh}"
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

FAKE_CI="$TMP_DIR/fake_ci_phase2.sh"
cat >"$FAKE_CI" <<'EOF_FAKE_CI'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE2_LINUX_PROD_CANDIDATE_RUN_CAPTURE_FILE:?}"
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
    "id": "ci_phase2_linux_prod_candidate_summary",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc,
  "stages": {
    "release_integrity": {
      "status": "$status"
    },
    "release_policy": {
      "status": "$status"
    },
    "operator_lifecycle": {
      "status": "$status"
    },
    "pilot_signoff": {
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

FAKE_CHECK="$TMP_DIR/fake_phase2_linux_prod_candidate_check.sh"
cat >"$FAKE_CHECK" <<'EOF_FAKE_CHECK'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE2_LINUX_PROD_CANDIDATE_RUN_CAPTURE_FILE:?}"
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
    "id": "phase2_linux_prod_candidate_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc,
  "policy": {
    "require_release_integrity_ok": true,
    "require_release_policy_ok": true,
    "require_operator_lifecycle_ok": true,
    "require_pilot_signoff_ok": true
  },
  "signals": {
    "release_integrity_ok": true,
    "release_policy_ok": true,
    "operator_lifecycle_ok": true,
    "pilot_signoff_ok": true
  },
  "stages": {
    "release_integrity": {
      "status": "$status",
      "resolved": true,
      "ok": true
    },
    "release_policy": {
      "status": "$status",
      "resolved": true,
      "ok": true
    },
    "operator_lifecycle": {
      "status": "$status",
      "resolved": true,
      "ok": true
    },
    "pilot_signoff": {
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

echo "[phase2-linux-prod-candidate-run] dry-run forwarding contract"
: >"$CAPTURE"
PHASE2_LINUX_PROD_CANDIDATE_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE2_LINUX_PROD_CANDIDATE_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE2_LINUX_PROD_CANDIDATE_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_dry" \
  --ci-summary-json "$TMP_DIR/ci_dry_summary.json" \
  --check-summary-json "$TMP_DIR/check_dry_summary.json" \
  --summary-json "$DRY_RUN_RUN_SUMMARY" \
  --dry-run 1 \
  --print-summary-json 0 \
  --ci-run-release-integrity-batch 1 \
  --check-require-release-integrity-ok 1 \
  --check-require-pilot-signoff-ok 1 \
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
if [[ "$ci_line" != *"--run-release-integrity-batch 1"* ]]; then
  echo "ci passthrough contract mismatch"
  echo "$ci_line"
  exit 1
fi
if [[ "$check_line" != *"--ci-phase2-summary-json $TMP_DIR/ci_dry_summary.json"* ]]; then
  echo "dry-run check forwarding missing ci summary path"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" != *"--summary-json $TMP_DIR/check_dry_summary.json"* ]]; then
  echo "dry-run check forwarding missing check summary path"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" != *"--require-release-integrity-ok 1"* || "$check_line" != *"--require-pilot-signoff-ok 1"* ]]; then
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
  and .schema.id == "phase2_linux_prod_candidate_run_summary"
  and .status == "pass"
  and .rc == 0
  and .inputs.dry_run == true
  and .steps.ci_phase2.status == "pass"
  and .steps.ci_phase2.rc == 0
  and .steps.ci_phase2.command_rc == 0
  and .steps.ci_phase2.contract_valid == true
  and .steps.ci_phase2.artifacts.summary_exists == true
  and .steps.phase2_linux_prod_candidate_check.status == "pass"
  and .steps.phase2_linux_prod_candidate_check.rc == 0
  and .steps.phase2_linux_prod_candidate_check.command_rc == 0
  and .steps.phase2_linux_prod_candidate_check.contract_valid == true
  and .steps.phase2_linux_prod_candidate_check.artifacts.summary_exists == true
  and .decision.pass == true
  and (.decision.reason_details | length) == 0
  and (.decision.warnings | length) == 0
' "$DRY_RUN_RUN_SUMMARY" >/dev/null; then
  echo "dry-run combined summary contract mismatch"
  cat "$DRY_RUN_RUN_SUMMARY"
  exit 1
fi

echo "[phase2-linux-prod-candidate-run] ci failure keeps checker execution"
: >"$CAPTURE"
set +e
PHASE2_LINUX_PROD_CANDIDATE_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE2_LINUX_PROD_CANDIDATE_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE2_LINUX_PROD_CANDIDATE_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
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
  and .steps.ci_phase2.status == "fail"
  and .steps.ci_phase2.rc == 27
  and .steps.ci_phase2.command_rc == 27
  and .steps.ci_phase2.contract_valid == true
  and .steps.phase2_linux_prod_candidate_check.status == "pass"
  and .steps.phase2_linux_prod_candidate_check.rc == 0
  and .steps.phase2_linux_prod_candidate_check.command_rc == 0
  and .steps.phase2_linux_prod_candidate_check.contract_valid == true
  and .decision.pass == false
  and ((.decision.reason_details // []) | any(.code == "ci_step_not_pass"))
  and ((.decision.reason_codes // []) | index("ci_step_not_pass") != null)
' "$CI_FAIL_RUN_SUMMARY" >/dev/null; then
  echo "ci-failure combined summary contract mismatch"
  cat "$CI_FAIL_RUN_SUMMARY"
  exit 1
fi

echo "[phase2-linux-prod-candidate-run] checker contract failure is fail-closed"
: >"$CAPTURE"
set +e
PHASE2_LINUX_PROD_CANDIDATE_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE2_LINUX_PROD_CANDIDATE_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE2_LINUX_PROD_CANDIDATE_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
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
  and .steps.ci_phase2.status == "pass"
  and .steps.ci_phase2.contract_valid == true
  and .steps.phase2_linux_prod_candidate_check.status == "fail"
  and .steps.phase2_linux_prod_candidate_check.command_rc == 0
  and .steps.phase2_linux_prod_candidate_check.contract_valid == false
  and .steps.phase2_linux_prod_candidate_check.contract_error != null
  and .decision.pass == false
  and ((.decision.reason_details // []) | any(.code == "check_summary_contract_invalid"))
  and ((.decision.reason_codes // []) | index("check_summary_contract_invalid") != null)
' "$CONTRACT_FAIL_RUN_SUMMARY" >/dev/null; then
  echo "checker-contract-fail combined summary mismatch"
  cat "$CONTRACT_FAIL_RUN_SUMMARY"
  exit 1
fi

echo "phase2 linux prod candidate run integration ok"
