#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod grep cat sed wc cmp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SUITE_RUNNER="${PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase6_cosmos_l1_build_testnet_suite.sh}"
if [[ ! -x "$SUITE_RUNNER" ]]; then
  echo "missing executable script under test: $SUITE_RUNNER"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.tsv"
PASS_LOG="$TMP_DIR/pass.log"
DRY_RUN_LOG="$TMP_DIR/dry_run.log"
RUN_FAIL_LOG="$TMP_DIR/run_fail.log"
CONTRACT_FAIL_LOG="$TMP_DIR/contract_fail.log"

PASS_SUMMARY="$TMP_DIR/suite_pass_summary.json"
DRY_RUN_SUMMARY="$TMP_DIR/suite_dry_run_summary.json"
RUN_FAIL_SUMMARY="$TMP_DIR/suite_run_fail_summary.json"
CONTRACT_FAIL_SUMMARY="$TMP_DIR/suite_contract_fail_summary.json"
PASS_CANONICAL_SUMMARY="$TMP_DIR/canonical_suite_pass_summary.json"
DRY_RUN_CANONICAL_SUMMARY="$TMP_DIR/canonical_suite_dry_run_summary.json"
RUN_FAIL_CANONICAL_SUMMARY="$TMP_DIR/canonical_suite_run_fail_summary.json"
CONTRACT_FAIL_CANONICAL_SUMMARY="$TMP_DIR/canonical_suite_contract_fail_summary.json"

FAKE_CI="$TMP_DIR/fake_ci_phase6.sh"
cat >"$FAKE_CI" <<'EOF_FAKE_CI'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE6_SUITE_CAPTURE_FILE:?}"
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

status="pass"
rc=0
if [[ "${FAKE_CI_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc="${FAKE_CI_FAIL_RC:-31}"
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
  exit "$rc"
fi
exit 0
EOF_FAKE_CI
chmod +x "$FAKE_CI"

FAKE_RUN="$TMP_DIR/fake_phase6_run.sh"
cat >"$FAKE_RUN" <<'EOF_FAKE_RUN'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE6_SUITE_CAPTURE_FILE:?}"
printf 'run\t%s\n' "$*" >>"$capture"

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

status="pass"
rc=0
if [[ "${FAKE_RUN_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc="${FAKE_RUN_FAIL_RC:-27}"
fi

if [[ -n "$summary_json" && "${FAKE_RUN_OMIT_SUMMARY:-0}" != "1" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<EOF_RUN_SUMMARY
{
  "version": 1,
  "schema": {
    "id": "phase6_cosmos_l1_build_testnet_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc,
  "steps": {
    "ci_phase6_cosmos_l1_build_testnet": {
      "status": "$status",
      "rc": $rc,
      "command_rc": $rc,
      "contract_valid": true
    },
    "phase6_cosmos_l1_build_testnet_check": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true
    }
  }
}
EOF_RUN_SUMMARY
fi

if [[ "${FAKE_RUN_FAIL:-0}" == "1" ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_RUN
chmod +x "$FAKE_RUN"

FAKE_HANDOFF_RUN="$TMP_DIR/fake_phase6_handoff_run.sh"
cat >"$FAKE_HANDOFF_RUN" <<'EOF_FAKE_HANDOFF_RUN'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE6_SUITE_CAPTURE_FILE:?}"
printf 'handoff_run\t%s\n' "$*" >>"$capture"

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

status="pass"
rc=0
if [[ "${FAKE_HANDOFF_RUN_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc="${FAKE_HANDOFF_RUN_FAIL_RC:-19}"
fi

if [[ -n "$summary_json" && "${FAKE_HANDOFF_RUN_OMIT_SUMMARY:-0}" != "1" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<EOF_HANDOFF_RUN_SUMMARY
{
  "version": 1,
  "schema": {
    "id": "phase6_cosmos_l1_build_testnet_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc,
  "steps": {
    "phase6_cosmos_l1_build_testnet_run": {
      "status": "skipped",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": false
    },
    "phase6_cosmos_l1_build_testnet_handoff_check": {
      "status": "$status",
      "rc": $rc,
      "command_rc": $rc,
      "contract_valid": true
    }
  }
}
EOF_HANDOFF_RUN_SUMMARY
fi

if [[ "${FAKE_HANDOFF_RUN_FAIL:-0}" == "1" ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_HANDOFF_RUN
chmod +x "$FAKE_HANDOFF_RUN"

assert_stage_order() {
  local capture_file="$1"
  local line_count first second third
  line_count="$(wc -l <"$capture_file" | tr -d ' ')"
  if [[ "$line_count" -ne 3 ]]; then
    echo "expected 3 stage invocations (ci, run, handoff_run), got $line_count"
    cat "$capture_file"
    exit 1
  fi
  first="$(sed -n '1p' "$capture_file" || true)"
  second="$(sed -n '2p' "$capture_file" || true)"
  third="$(sed -n '3p' "$capture_file" || true)"
  if [[ "${first%%$'\t'*}" != "ci" || "${second%%$'\t'*}" != "run" || "${third%%$'\t'*}" != "handoff_run" ]]; then
    echo "suite stage ordering mismatch; expected ci -> run -> handoff_run"
    cat "$capture_file"
    exit 1
  fi
}

echo "[phase6-cosmos-l1-build-testnet-suite] pass path + summary contract"
: >"$CAPTURE"
PHASE6_SUITE_CAPTURE_FILE="$CAPTURE" \
PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_CI_SCRIPT="$FAKE_CI" \
PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_RUN_SCRIPT="$FAKE_RUN" \
PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_HANDOFF_RUN_SCRIPT="$FAKE_HANDOFF_RUN" \
PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_CANONICAL_SUMMARY_JSON="$PASS_CANONICAL_SUMMARY" \
bash "$SUITE_RUNNER" \
  --reports-dir "$TMP_DIR/reports_pass" \
  --ci-summary-json "$TMP_DIR/ci_pass.json" \
  --run-summary-json "$TMP_DIR/run_pass.json" \
  --handoff-run-summary-json "$TMP_DIR/handoff_run_pass.json" \
  --summary-json "$PASS_SUMMARY" \
  --print-summary-json 0 \
  --ci-alpha 1 \
  --run-beta 2 \
  --handoff-run-gamma 3 >"$PASS_LOG" 2>&1

assert_stage_order "$CAPTURE"

ci_line="$(grep '^ci	' "$CAPTURE" | tail -n 1 || true)"
run_line="$(grep '^run	' "$CAPTURE" | tail -n 1 || true)"
handoff_run_line="$(grep '^handoff_run	' "$CAPTURE" | tail -n 1 || true)"
if [[ "$ci_line" != *"--summary-json $TMP_DIR/ci_pass.json"* || "$ci_line" != *"--alpha 1"* ]]; then
  echo "ci forwarding mismatch"
  echo "$ci_line"
  exit 1
fi
if [[ "$run_line" != *"--ci-summary-json $TMP_DIR/ci_pass.json"* || "$run_line" != *"--summary-json $TMP_DIR/run_pass.json"* || "$run_line" != *"--beta 2"* ]]; then
  echo "run forwarding mismatch"
  echo "$run_line"
  exit 1
fi
if [[ "$handoff_run_line" != *"--run-summary-json $TMP_DIR/run_pass.json"* || "$handoff_run_line" != *"--summary-json $TMP_DIR/handoff_run_pass.json"* || "$handoff_run_line" != *"--gamma 3"* ]]; then
  echo "handoff-run forwarding mismatch"
  echo "$handoff_run_line"
  exit 1
fi
if [[ "$handoff_run_line" != *"--run-phase6-cosmos-l1-build-testnet-run 0"* ]]; then
  echo "handoff-run default nested run disable mismatch"
  echo "$handoff_run_line"
  exit 1
fi
if [[ ! -f "$PASS_CANONICAL_SUMMARY" ]]; then
  echo "missing pass-path canonical summary file: $PASS_CANONICAL_SUMMARY"
  exit 1
fi
if ! cmp -s "$PASS_SUMMARY" "$PASS_CANONICAL_SUMMARY"; then
  echo "pass-path canonical summary content mismatch"
  cat "$PASS_SUMMARY"
  cat "$PASS_CANONICAL_SUMMARY"
  exit 1
fi
if ! grep -Fq -- "[phase6-cosmos-l1-build-testnet-suite] canonical_summary_json=$PASS_CANONICAL_SUMMARY" "$PASS_LOG"; then
  echo "pass-path log missing canonical summary line"
  cat "$PASS_LOG"
  exit 1
fi

if ! jq -e --arg canonical "$PASS_CANONICAL_SUMMARY" '
  .version == 1
  and .schema.id == "phase6_cosmos_l1_build_testnet_suite_summary"
  and .status == "pass"
  and .rc == 0
  and .artifacts.canonical_summary_json == $canonical
  and .inputs.dry_run == false
  and .steps.ci_phase6_cosmos_l1_build_testnet.status == "pass"
  and .steps.ci_phase6_cosmos_l1_build_testnet.contract_valid == true
  and .steps.phase6_cosmos_l1_build_testnet_run.status == "pass"
  and .steps.phase6_cosmos_l1_build_testnet_run.contract_valid == true
  and .steps.phase6_cosmos_l1_build_testnet_handoff_run.status == "pass"
  and .steps.phase6_cosmos_l1_build_testnet_handoff_run.contract_valid == true
' "$PASS_SUMMARY" >/dev/null; then
  echo "pass-path suite summary contract mismatch"
  cat "$PASS_SUMMARY"
  exit 1
fi

echo "[phase6-cosmos-l1-build-testnet-suite] dry-run forwarding path"
: >"$CAPTURE"
PHASE6_SUITE_CAPTURE_FILE="$CAPTURE" \
PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_CI_SCRIPT="$FAKE_CI" \
PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_RUN_SCRIPT="$FAKE_RUN" \
PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_HANDOFF_RUN_SCRIPT="$FAKE_HANDOFF_RUN" \
PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_CANONICAL_SUMMARY_JSON="$DRY_RUN_CANONICAL_SUMMARY" \
bash "$SUITE_RUNNER" \
  --reports-dir "$TMP_DIR/reports_dry" \
  --ci-summary-json "$TMP_DIR/ci_dry.json" \
  --run-summary-json "$TMP_DIR/run_dry.json" \
  --handoff-run-summary-json "$TMP_DIR/handoff_run_dry.json" \
  --summary-json "$DRY_RUN_SUMMARY" \
  --dry-run 1 \
  --print-summary-json 0 \
  --run-check-require-chain-scaffold-ok 1 \
  --handoff-run-handoff-require-proto-surface-ok 1 >"$DRY_RUN_LOG" 2>&1

assert_stage_order "$CAPTURE"

ci_line="$(grep '^ci	' "$CAPTURE" | tail -n 1 || true)"
run_line="$(grep '^run	' "$CAPTURE" | tail -n 1 || true)"
handoff_run_line="$(grep '^handoff_run	' "$CAPTURE" | tail -n 1 || true)"
if [[ "$ci_line" != *"--dry-run 1"* ]]; then
  echo "ci dry-run forwarding mismatch"
  echo "$ci_line"
  exit 1
fi
if [[ "$run_line" != *"--dry-run 1"* || "$run_line" != *"--check-require-chain-scaffold-ok 1"* ]]; then
  echo "run dry-run forwarding mismatch"
  echo "$run_line"
  exit 1
fi
if [[ "$handoff_run_line" != *"--dry-run 1"* || "$handoff_run_line" != *"--handoff-require-proto-surface-ok 1"* ]]; then
  echo "handoff-run dry-run forwarding mismatch"
  echo "$handoff_run_line"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.dry_run == true
  and .steps.ci_phase6_cosmos_l1_build_testnet.contract_valid == true
  and .steps.phase6_cosmos_l1_build_testnet_run.contract_valid == true
  and .steps.phase6_cosmos_l1_build_testnet_handoff_run.contract_valid == true
' "$DRY_RUN_SUMMARY" >/dev/null; then
  echo "dry-run suite summary mismatch"
  cat "$DRY_RUN_SUMMARY"
  exit 1
fi

echo "[phase6-cosmos-l1-build-testnet-suite] stage-failure propagation path"
: >"$CAPTURE"
set +e
PHASE6_SUITE_CAPTURE_FILE="$CAPTURE" \
PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_CI_SCRIPT="$FAKE_CI" \
PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_RUN_SCRIPT="$FAKE_RUN" \
PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_HANDOFF_RUN_SCRIPT="$FAKE_HANDOFF_RUN" \
PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_CANONICAL_SUMMARY_JSON="$RUN_FAIL_CANONICAL_SUMMARY" \
FAKE_RUN_FAIL=1 \
FAKE_RUN_FAIL_RC=27 \
bash "$SUITE_RUNNER" \
  --reports-dir "$TMP_DIR/reports_run_fail" \
  --ci-summary-json "$TMP_DIR/ci_run_fail.json" \
  --run-summary-json "$TMP_DIR/run_fail.json" \
  --handoff-run-summary-json "$TMP_DIR/handoff_run_fail.json" \
  --summary-json "$RUN_FAIL_SUMMARY" \
  --print-summary-json 0 >"$RUN_FAIL_LOG" 2>&1
run_fail_rc=$?
set -e

if [[ "$run_fail_rc" -ne 27 ]]; then
  echo "expected suite rc=27 on run-stage failure, got rc=$run_fail_rc"
  cat "$RUN_FAIL_LOG"
  exit 1
fi
assert_stage_order "$CAPTURE"
if [[ ! -f "$RUN_FAIL_CANONICAL_SUMMARY" ]]; then
  echo "missing run-fail canonical summary file: $RUN_FAIL_CANONICAL_SUMMARY"
  exit 1
fi
if ! cmp -s "$RUN_FAIL_SUMMARY" "$RUN_FAIL_CANONICAL_SUMMARY"; then
  echo "run-fail canonical summary content mismatch"
  cat "$RUN_FAIL_SUMMARY"
  cat "$RUN_FAIL_CANONICAL_SUMMARY"
  exit 1
fi
if ! grep -Fq -- "[phase6-cosmos-l1-build-testnet-suite] canonical_summary_json=$RUN_FAIL_CANONICAL_SUMMARY" "$RUN_FAIL_LOG"; then
  echo "run-fail log missing canonical summary line"
  cat "$RUN_FAIL_LOG"
  exit 1
fi
if ! jq -e --arg canonical "$RUN_FAIL_CANONICAL_SUMMARY" '
  .status == "fail"
  and .rc == 27
  and .artifacts.canonical_summary_json == $canonical
  and .steps.ci_phase6_cosmos_l1_build_testnet.status == "pass"
  and .steps.phase6_cosmos_l1_build_testnet_run.status == "fail"
  and .steps.phase6_cosmos_l1_build_testnet_run.rc == 27
  and .steps.phase6_cosmos_l1_build_testnet_run.command_rc == 27
  and .steps.phase6_cosmos_l1_build_testnet_run.contract_valid == true
  and .steps.phase6_cosmos_l1_build_testnet_handoff_run.status == "pass"
' "$RUN_FAIL_SUMMARY" >/dev/null; then
  echo "stage-failure propagation summary mismatch"
  cat "$RUN_FAIL_SUMMARY"
  exit 1
fi

echo "[phase6-cosmos-l1-build-testnet-suite] fail-closed child summary contract path"
: >"$CAPTURE"
set +e
PHASE6_SUITE_CAPTURE_FILE="$CAPTURE" \
PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_CI_SCRIPT="$FAKE_CI" \
PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_RUN_SCRIPT="$FAKE_RUN" \
PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_HANDOFF_RUN_SCRIPT="$FAKE_HANDOFF_RUN" \
PHASE6_COSMOS_L1_BUILD_TESTNET_SUITE_CANONICAL_SUMMARY_JSON="$CONTRACT_FAIL_CANONICAL_SUMMARY" \
FAKE_HANDOFF_RUN_OMIT_SUMMARY=1 \
bash "$SUITE_RUNNER" \
  --reports-dir "$TMP_DIR/reports_contract_fail" \
  --ci-summary-json "$TMP_DIR/ci_contract_fail.json" \
  --run-summary-json "$TMP_DIR/run_contract_fail.json" \
  --handoff-run-summary-json "$TMP_DIR/handoff_run_contract_fail.json" \
  --summary-json "$CONTRACT_FAIL_SUMMARY" \
  --print-summary-json 0 >"$CONTRACT_FAIL_LOG" 2>&1
contract_fail_rc=$?
set -e

if [[ "$contract_fail_rc" -ne 3 ]]; then
  echo "expected suite rc=3 on handoff-run contract failure, got rc=$contract_fail_rc"
  cat "$CONTRACT_FAIL_LOG"
  exit 1
fi
assert_stage_order "$CAPTURE"
if ! jq -e '
  .status == "fail"
  and .rc == 3
  and .steps.phase6_cosmos_l1_build_testnet_handoff_run.status == "fail"
  and .steps.phase6_cosmos_l1_build_testnet_handoff_run.contract_valid == false
  and ((.steps.phase6_cosmos_l1_build_testnet_handoff_run.contract_error // "") | test("missing or invalid"))
' "$CONTRACT_FAIL_SUMMARY" >/dev/null; then
  echo "contract-fail summary mismatch"
  cat "$CONTRACT_FAIL_SUMMARY"
  exit 1
fi

echo "phase6 cosmos l1 build testnet suite integration ok"
