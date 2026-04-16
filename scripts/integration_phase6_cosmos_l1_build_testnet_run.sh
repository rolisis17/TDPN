#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod grep sed wc cat cmp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

RUNNER="${PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase6_cosmos_l1_build_testnet_run.sh}"
if [[ ! -x "$RUNNER" ]]; then
  echo "missing executable script under test: $RUNNER"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/stage_capture.tsv"
SUCCESS_LOG="$TMP_DIR/success.log"
DRY_RUN_LOG="$TMP_DIR/dry_run.log"
DRY_RUN_EXPLICIT_LOG="$TMP_DIR/dry_run_explicit.log"
CI_FAIL_LOG="$TMP_DIR/ci_fail.log"
CHECK_FAIL_LOG="$TMP_DIR/check_fail.log"

SUCCESS_RUN_SUMMARY="$TMP_DIR/run_success.json"
DRY_RUN_RUN_SUMMARY="$TMP_DIR/run_dry.json"
DRY_RUN_EXPLICIT_RUN_SUMMARY="$TMP_DIR/run_dry_explicit.json"
CI_FAIL_RUN_SUMMARY="$TMP_DIR/run_ci_fail.json"
CHECK_FAIL_RUN_SUMMARY="$TMP_DIR/run_check_fail.json"
SUCCESS_CANONICAL_SUMMARY="$TMP_DIR/canonical_run_success.json"
DRY_RUN_CANONICAL_SUMMARY="$TMP_DIR/canonical_run_dry.json"
DRY_RUN_EXPLICIT_CANONICAL_SUMMARY="$TMP_DIR/canonical_run_dry_explicit.json"
CI_FAIL_CANONICAL_SUMMARY="$TMP_DIR/canonical_run_ci_fail.json"
CHECK_FAIL_CANONICAL_SUMMARY="$TMP_DIR/canonical_run_check_fail.json"

FAKE_CI="$TMP_DIR/fake_ci_phase6.sh"
cat >"$FAKE_CI" <<'EOF_FAKE_CI'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CAPTURE_FILE:?}"
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
    "id": "ci_phase6_cosmos_l1_build_testnet_summary",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc
}
EOF_CI_SUMMARY
fi

if [[ "${FAKE_CI_FAIL:-0}" == "1" ]]; then
  exit "$fail_rc"
fi
exit 0
EOF_FAKE_CI
chmod +x "$FAKE_CI"

FAKE_CHECK="$TMP_DIR/fake_phase6_check.sh"
cat >"$FAKE_CHECK" <<'EOF_FAKE_CHECK'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CAPTURE_FILE:?}"
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
    "id": "phase6_cosmos_l1_build_testnet_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc
}
EOF_CHECK_SUMMARY
fi

if [[ "${FAKE_CHECK_FAIL:-0}" == "1" ]]; then
  exit "$fail_rc"
fi
exit 0
EOF_FAKE_CHECK
chmod +x "$FAKE_CHECK"

assert_ci_then_check_order() {
  local capture_file="$1"
  local line_count ci_line check_line
  line_count="$(wc -l <"$capture_file" | tr -d ' ')"
  if [[ "$line_count" -ne 2 ]]; then
    echo "expected 2 stage invocations (ci then check), got $line_count"
    cat "$capture_file"
    exit 1
  fi
  ci_line="$(sed -n '1p' "$capture_file" || true)"
  check_line="$(sed -n '2p' "$capture_file" || true)"
  if [[ "${ci_line%%$'\t'*}" != "ci" || "${check_line%%$'\t'*}" != "check" ]]; then
    echo "runner stage ordering mismatch; expected ci then check"
    cat "$capture_file"
    exit 1
  fi
}

assert_canonical_summary_artifact() {
  local run_summary_json="$1"
  local canonical_summary_json="$2"
  local log_path="$3"

  if [[ ! -f "$canonical_summary_json" ]]; then
    echo "missing canonical run summary: $canonical_summary_json"
    cat "$log_path"
    exit 1
  fi

  if ! jq -e --arg canonical "$canonical_summary_json" '.artifacts.canonical_summary_json == $canonical' "$run_summary_json" >/dev/null; then
    echo "run summary missing canonical_summary_json artifact field"
    cat "$run_summary_json"
    exit 1
  fi

  if ! cmp -s "$run_summary_json" "$canonical_summary_json"; then
    echo "canonical run summary content mismatch"
    cat "$run_summary_json"
    cat "$canonical_summary_json"
    exit 1
  fi

  if ! grep -Fq -- "[phase6-cosmos-l1-run] canonical_summary_json=$canonical_summary_json" "$log_path"; then
    echo "missing canonical summary log line"
    cat "$log_path"
    exit 1
  fi
}

echo "[phase6-cosmos-l1-run] success path"
: >"$CAPTURE"
PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CANONICAL_SUMMARY_JSON="$SUCCESS_CANONICAL_SUMMARY" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_success" \
  --ci-summary-json "$TMP_DIR/ci_success_summary.json" \
  --check-summary-json "$TMP_DIR/check_success_summary.json" \
  --summary-json "$SUCCESS_RUN_SUMMARY" \
  --print-summary-json 0 >"$SUCCESS_LOG" 2>&1

assert_ci_then_check_order "$CAPTURE"

check_line="$(grep '^check	' "$CAPTURE" | tail -n 1 || true)"
if [[ "$check_line" != *"--show-json 0"* ]]; then
  echo "success path missing default --show-json 0 forwarding to check stage"
  echo "$check_line"
  exit 1
fi

if [[ ! -f "$SUCCESS_RUN_SUMMARY" ]]; then
  echo "missing success combined summary JSON: $SUCCESS_RUN_SUMMARY"
  cat "$SUCCESS_LOG"
  exit 1
fi
if ! jq -e '
  .version == 1
  and .schema.id == "phase6_cosmos_l1_build_testnet_run_summary"
  and .status == "pass"
  and .rc == 0
  and .inputs.dry_run == false
  and .steps.ci_phase6_cosmos_l1_build_testnet.status == "pass"
  and .steps.ci_phase6_cosmos_l1_build_testnet.rc == 0
  and .steps.ci_phase6_cosmos_l1_build_testnet.command_rc == 0
  and .steps.ci_phase6_cosmos_l1_build_testnet.contract_valid == true
  and .steps.ci_phase6_cosmos_l1_build_testnet.artifacts.summary_exists == true
  and .steps.phase6_cosmos_l1_build_testnet_check.status == "pass"
  and .steps.phase6_cosmos_l1_build_testnet_check.rc == 0
  and .steps.phase6_cosmos_l1_build_testnet_check.command_rc == 0
  and .steps.phase6_cosmos_l1_build_testnet_check.contract_valid == true
  and .steps.phase6_cosmos_l1_build_testnet_check.artifacts.summary_exists == true
' "$SUCCESS_RUN_SUMMARY" >/dev/null; then
  echo "success combined summary contract mismatch"
  cat "$SUCCESS_RUN_SUMMARY"
  exit 1
fi
assert_canonical_summary_artifact "$SUCCESS_RUN_SUMMARY" "$SUCCESS_CANONICAL_SUMMARY" "$SUCCESS_LOG"

echo "[phase6-cosmos-l1-run] dry-run forwarding + toggle safety"
: >"$CAPTURE"
PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CANONICAL_SUMMARY_JSON="$DRY_RUN_CANONICAL_SUMMARY" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_dry" \
  --ci-summary-json "$TMP_DIR/ci_dry_summary.json" \
  --check-summary-json "$TMP_DIR/check_dry_summary.json" \
  --summary-json "$DRY_RUN_RUN_SUMMARY" \
  --dry-run 1 \
  --print-summary-json 0 \
  --ci-run-chain-scaffold 0 \
  --ci-run-proto-surface 0 \
  --check-require-chain-scaffold-ok 1 \
  --check-show-json 1 >"$DRY_RUN_LOG" 2>&1

assert_ci_then_check_order "$CAPTURE"

ci_line="$(grep '^ci	' "$CAPTURE" | tail -n 1 || true)"
check_line="$(grep '^check	' "$CAPTURE" | tail -n 1 || true)"
if [[ "$ci_line" != *"--dry-run 1"* || "$ci_line" != *"--summary-json $TMP_DIR/ci_dry_summary.json"* ]]; then
  echo "dry-run ci forwarding mismatch"
  echo "$ci_line"
  exit 1
fi
if [[ "$ci_line" != *"--run-chain-scaffold 0"* || "$ci_line" != *"--run-proto-surface 0"* ]]; then
  echo "ci toggle forwarding mismatch"
  echo "$ci_line"
  exit 1
fi
if [[ "$check_line" != *"--ci-phase6-summary-json $TMP_DIR/ci_dry_summary.json"* ]]; then
  echo "dry-run check forwarding missing ci summary path"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" != *"--summary-json $TMP_DIR/check_dry_summary.json"* ]]; then
  echo "dry-run check forwarding missing check summary path"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" != *"--require-chain-scaffold-ok 1"* ]]; then
  echo "explicit checker requirement forwarding mismatch"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" != *"--require-proto-surface-ok 0"* || "$check_line" != *"--require-proto-codegen-surface-ok 0"* || "$check_line" != *"--require-query-surface-ok 0"* || "$check_line" != *"--require-module-tx-surface-ok 0"* || "$check_line" != *"--require-grpc-app-roundtrip-ok 0"* || "$check_line" != *"--require-tdpnd-grpc-runtime-smoke-ok 0"* || "$check_line" != *"--require-tdpnd-grpc-live-smoke-ok 0"* || "$check_line" != *"--require-tdpnd-grpc-auth-live-smoke-ok 0"* ]]; then
  echo "dry-run default requirement relax forwarding mismatch"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" != *"--show-json 1"* ]]; then
  echo "check show-json explicit forwarding mismatch"
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
  .status == "pass"
  and .rc == 0
  and .inputs.dry_run == true
  and .steps.ci_phase6_cosmos_l1_build_testnet.contract_valid == true
  and .steps.phase6_cosmos_l1_build_testnet_check.contract_valid == true
' "$DRY_RUN_RUN_SUMMARY" >/dev/null; then
  echo "dry-run combined summary contract mismatch"
  cat "$DRY_RUN_RUN_SUMMARY"
  exit 1
fi
assert_canonical_summary_artifact "$DRY_RUN_RUN_SUMMARY" "$DRY_RUN_CANONICAL_SUMMARY" "$DRY_RUN_LOG"

echo "[phase6-cosmos-l1-run] dry-run explicit module requirement forwarding"
: >"$CAPTURE"
PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CANONICAL_SUMMARY_JSON="$DRY_RUN_EXPLICIT_CANONICAL_SUMMARY" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_dry_explicit" \
  --ci-summary-json "$TMP_DIR/ci_dry_explicit_summary.json" \
  --check-summary-json "$TMP_DIR/check_dry_explicit_summary.json" \
  --summary-json "$DRY_RUN_EXPLICIT_RUN_SUMMARY" \
  --dry-run 1 \
  --print-summary-json 0 \
  --check-require-module-tx-surface-ok 1 \
  --check-show-json 0 >"$DRY_RUN_EXPLICIT_LOG" 2>&1

assert_ci_then_check_order "$CAPTURE"

check_line="$(grep '^check	' "$CAPTURE" | tail -n 1 || true)"
if [[ "$check_line" != *"--require-module-tx-surface-ok 1"* ]]; then
  echo "explicit module checker requirement forwarding mismatch"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" == *"--require-module-tx-surface-ok 0"* ]]; then
  echo "explicit module checker requirement was overridden by dry-run relax logic"
  echo "$check_line"
  exit 1
fi

if [[ ! -f "$DRY_RUN_EXPLICIT_RUN_SUMMARY" ]]; then
  echo "missing explicit dry-run combined summary JSON: $DRY_RUN_EXPLICIT_RUN_SUMMARY"
  cat "$DRY_RUN_EXPLICIT_LOG"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.dry_run == true
  and .steps.ci_phase6_cosmos_l1_build_testnet.contract_valid == true
  and .steps.phase6_cosmos_l1_build_testnet_check.contract_valid == true
' "$DRY_RUN_EXPLICIT_RUN_SUMMARY" >/dev/null; then
  echo "explicit dry-run combined summary contract mismatch"
  cat "$DRY_RUN_EXPLICIT_RUN_SUMMARY"
  exit 1
fi
assert_canonical_summary_artifact "$DRY_RUN_EXPLICIT_RUN_SUMMARY" "$DRY_RUN_EXPLICIT_CANONICAL_SUMMARY" "$DRY_RUN_EXPLICIT_LOG"

echo "[phase6-cosmos-l1-run] ci-failure propagation"
: >"$CAPTURE"
set +e
PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CI_FAIL=1 \
FAKE_CI_FAIL_RC=27 \
PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CANONICAL_SUMMARY_JSON="$CI_FAIL_CANONICAL_SUMMARY" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_ci_fail" \
  --ci-summary-json "$TMP_DIR/ci_fail_summary.json" \
  --check-summary-json "$TMP_DIR/check_ci_fail_summary.json" \
  --summary-json "$CI_FAIL_RUN_SUMMARY" \
  --print-summary-json 0 >"$CI_FAIL_LOG" 2>&1
ci_fail_rc=$?
set -e

if [[ "$ci_fail_rc" -ne 27 ]]; then
  echo "expected wrapper rc=27 on ci failure, got rc=$ci_fail_rc"
  cat "$CI_FAIL_LOG"
  exit 1
fi
assert_ci_then_check_order "$CAPTURE"

if [[ ! -f "$CI_FAIL_RUN_SUMMARY" ]]; then
  echo "missing ci-fail combined summary JSON: $CI_FAIL_RUN_SUMMARY"
  cat "$CI_FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 27
  and .steps.ci_phase6_cosmos_l1_build_testnet.status == "fail"
  and .steps.ci_phase6_cosmos_l1_build_testnet.rc == 27
  and .steps.ci_phase6_cosmos_l1_build_testnet.command_rc == 27
  and .steps.ci_phase6_cosmos_l1_build_testnet.contract_valid == true
  and .steps.phase6_cosmos_l1_build_testnet_check.status == "pass"
  and .steps.phase6_cosmos_l1_build_testnet_check.rc == 0
  and .steps.phase6_cosmos_l1_build_testnet_check.command_rc == 0
  and .steps.phase6_cosmos_l1_build_testnet_check.contract_valid == true
' "$CI_FAIL_RUN_SUMMARY" >/dev/null; then
  echo "ci-fail combined summary contract mismatch"
  cat "$CI_FAIL_RUN_SUMMARY"
  exit 1
fi
assert_canonical_summary_artifact "$CI_FAIL_RUN_SUMMARY" "$CI_FAIL_CANONICAL_SUMMARY" "$CI_FAIL_LOG"

echo "[phase6-cosmos-l1-run] check-failure propagation"
: >"$CAPTURE"
set +e
PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
FAKE_CHECK_FAIL=1 \
FAKE_CHECK_FAIL_RC=19 \
PHASE6_COSMOS_L1_BUILD_TESTNET_RUN_CANONICAL_SUMMARY_JSON="$CHECK_FAIL_CANONICAL_SUMMARY" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_check_fail" \
  --ci-summary-json "$TMP_DIR/ci_check_fail_summary.json" \
  --check-summary-json "$TMP_DIR/check_fail_summary.json" \
  --summary-json "$CHECK_FAIL_RUN_SUMMARY" \
  --print-summary-json 0 >"$CHECK_FAIL_LOG" 2>&1
check_fail_rc=$?
set -e

if [[ "$check_fail_rc" -ne 19 ]]; then
  echo "expected wrapper rc=19 on check failure, got rc=$check_fail_rc"
  cat "$CHECK_FAIL_LOG"
  exit 1
fi
assert_ci_then_check_order "$CAPTURE"

if [[ ! -f "$CHECK_FAIL_RUN_SUMMARY" ]]; then
  echo "missing check-fail combined summary JSON: $CHECK_FAIL_RUN_SUMMARY"
  cat "$CHECK_FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 19
  and .steps.ci_phase6_cosmos_l1_build_testnet.status == "pass"
  and .steps.ci_phase6_cosmos_l1_build_testnet.rc == 0
  and .steps.ci_phase6_cosmos_l1_build_testnet.command_rc == 0
  and .steps.ci_phase6_cosmos_l1_build_testnet.contract_valid == true
  and .steps.phase6_cosmos_l1_build_testnet_check.status == "fail"
  and .steps.phase6_cosmos_l1_build_testnet_check.rc == 19
  and .steps.phase6_cosmos_l1_build_testnet_check.command_rc == 19
  and .steps.phase6_cosmos_l1_build_testnet_check.contract_valid == true
' "$CHECK_FAIL_RUN_SUMMARY" >/dev/null; then
  echo "check-fail combined summary contract mismatch"
  cat "$CHECK_FAIL_RUN_SUMMARY"
  exit 1
fi
assert_canonical_summary_artifact "$CHECK_FAIL_RUN_SUMMARY" "$CHECK_FAIL_CANONICAL_SUMMARY" "$CHECK_FAIL_LOG"

echo "phase6 cosmos l1 build testnet run integration ok"
