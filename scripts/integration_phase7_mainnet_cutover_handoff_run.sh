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

RUNNER="${PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase7_mainnet_cutover_handoff_run.sh}"
if [[ ! -x "$RUNNER" ]]; then
  echo "missing executable script under test: $RUNNER"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/stage_capture.tsv"

PASS_LOG="$TMP_DIR/pass.log"
DRY_LOG="$TMP_DIR/dry.log"
RUN_FAIL_LOG="$TMP_DIR/run_fail.log"
HANDOFF_FAIL_LOG="$TMP_DIR/handoff_fail.log"
INVALID_HANDOFF_LOG="$TMP_DIR/invalid_handoff.log"

PASS_SUMMARY="$TMP_DIR/pass_handoff_run_summary.json"
DRY_SUMMARY="$TMP_DIR/dry_handoff_run_summary.json"
RUN_FAIL_SUMMARY="$TMP_DIR/run_fail_handoff_run_summary.json"
HANDOFF_FAIL_SUMMARY="$TMP_DIR/handoff_fail_handoff_run_summary.json"
INVALID_HANDOFF_SUMMARY="$TMP_DIR/invalid_handoff_handoff_run_summary.json"

PASS_CANONICAL="$TMP_DIR/pass_handoff_run_canonical.json"
DRY_CANONICAL="$TMP_DIR/dry_handoff_run_canonical.json"
RUN_FAIL_CANONICAL="$TMP_DIR/run_fail_handoff_run_canonical.json"
HANDOFF_FAIL_CANONICAL="$TMP_DIR/handoff_fail_handoff_run_canonical.json"
INVALID_HANDOFF_CANONICAL="$TMP_DIR/invalid_handoff_handoff_run_canonical.json"

FAKE_RUN="$TMP_DIR/fake_phase7_mainnet_cutover_run.sh"
cat >"$FAKE_RUN" <<'EOF_FAKE_RUN'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE7_HANDOFF_RUN_CAPTURE_FILE:?}"
printf 'run\t%s\n' "$*" >>"$capture"

reports_dir=""
summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
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
if [[ "${FAKE_PHASE7_RUN_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc="${FAKE_PHASE7_RUN_FAIL_RC:-27}"
fi

check_summary="${FAKE_PHASE7_RUN_CHECK_SUMMARY:-${reports_dir}/phase7_mainnet_cutover_check_summary.json}"
mkdir -p "$(dirname "$check_summary")"
cat >"$check_summary" <<'EOF_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "signals": {
    "run_pipeline_ok": true,
    "module_tx_surface_ok": true,
    "tdpnd_grpc_runtime_smoke_ok": true,
    "tdpnd_grpc_live_smoke_ok": true,
    "tdpnd_grpc_auth_live_smoke_ok": true,
    "tdpnd_comet_runtime_smoke_ok": true,
    "dual_write_parity_ok": true,
    "rollback_path_ready": true,
    "operator_approval_ok": true
  }
}
EOF_CHECK

schema_id="phase7_mainnet_cutover_run_summary"
if [[ "${FAKE_PHASE7_RUN_INVALID_SUMMARY:-0}" == "1" ]]; then
  schema_id="phase7_mainnet_cutover_run_summary_invalid"
fi

if [[ -n "$summary_json" && "${FAKE_PHASE7_RUN_OMIT_SUMMARY:-0}" != "1" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<EOF_SUMMARY
{
  "version": 1,
  "schema": {
    "id": "$schema_id",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc,
  "steps": {
    "phase7_mainnet_cutover_check": {
      "status": "$status",
      "rc": $rc,
      "command_rc": $rc,
      "contract_valid": true,
      "signal_snapshot": {
        "run_pipeline_ok": true,
        "module_tx_surface_ok": true,
        "tdpnd_grpc_runtime_smoke_ok": true,
        "tdpnd_grpc_live_smoke_ok": true,
        "tdpnd_grpc_auth_live_smoke_ok": true,
        "tdpnd_comet_runtime_smoke_ok": true,
        "dual_write_parity_ok": true,
        "rollback_path_ready": true,
        "operator_approval_ok": true
      },
      "artifacts": {
        "summary_json": "$check_summary"
      }
    }
  },
  "artifacts": {
    "check_summary_json": "$check_summary"
  }
}
EOF_SUMMARY
fi

if [[ "${FAKE_PHASE7_RUN_FAIL:-0}" == "1" ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_RUN
chmod +x "$FAKE_RUN"

FAKE_HANDOFF="$TMP_DIR/fake_phase7_mainnet_cutover_handoff_check.sh"
cat >"$FAKE_HANDOFF" <<'EOF_FAKE_HANDOFF'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE7_HANDOFF_RUN_CAPTURE_FILE:?}"
printf 'handoff\t%s\n' "$*" >>"$capture"

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
if [[ "${FAKE_PHASE7_HANDOFF_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc="${FAKE_PHASE7_HANDOFF_FAIL_RC:-19}"
fi

schema_id="phase7_mainnet_cutover_handoff_check_summary"
if [[ "${FAKE_PHASE7_HANDOFF_INVALID_SUMMARY:-0}" == "1" ]]; then
  schema_id="phase7_mainnet_cutover_handoff_check_summary_invalid"
fi

if [[ -n "$summary_json" && "${FAKE_PHASE7_HANDOFF_OMIT_SUMMARY:-0}" != "1" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<EOF_SUMMARY
{
  "version": 1,
  "schema": {
    "id": "$schema_id",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc,
  "handoff": {
    "run_pipeline_ok": true,
    "module_tx_surface_ok": true,
    "tdpnd_grpc_runtime_smoke_ok": true,
    "tdpnd_grpc_live_smoke_ok": true,
    "tdpnd_grpc_auth_live_smoke_ok": true,
    "tdpnd_comet_runtime_smoke_ok": true,
    "dual_write_parity_ok": true,
    "rollback_path_ready": true,
    "operator_approval_ok": true
  },
  "decision": {
    "pass": true,
    "reasons": [],
    "warnings": []
  }
}
EOF_SUMMARY
fi

if [[ "${FAKE_PHASE7_HANDOFF_FAIL:-0}" == "1" ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_HANDOFF
chmod +x "$FAKE_HANDOFF"

assert_two_stage_invocations() {
  local capture_file="$1"
  local line_count
  line_count="$(wc -l <"$capture_file" | tr -d ' ')"
  if [[ "$line_count" -ne 2 ]]; then
    echo "expected exactly two stage invocations, got $line_count"
    cat "$capture_file"
    exit 1
  fi
}

assert_canonical_summary_artifact() {
  local wrapper_summary="$1"
  local canonical_summary="$2"
  local log_path="$3"

  if [[ ! -f "$canonical_summary" ]]; then
    echo "missing canonical summary: $canonical_summary"
    cat "$log_path"
    exit 1
  fi
  if ! jq -e --arg canonical "$canonical_summary" '.artifacts.canonical_summary_json == $canonical' "$wrapper_summary" >/dev/null; then
    echo "wrapper summary missing canonical_summary_json artifact field"
    cat "$wrapper_summary"
    exit 1
  fi
  if ! cmp -s "$wrapper_summary" "$canonical_summary"; then
    echo "canonical summary content mismatch"
    cat "$wrapper_summary"
    cat "$canonical_summary"
    exit 1
  fi
  if ! grep -Fq -- "[phase7-mainnet-cutover-handoff-run] canonical_summary_json=$canonical_summary" "$log_path"; then
    echo "missing canonical summary log line"
    cat "$log_path"
    exit 1
  fi
}

echo "[phase7-mainnet-cutover-handoff-run] pass path"
: >"$CAPTURE"
PHASE7_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_CANONICAL_SUMMARY_JSON="$PASS_CANONICAL" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_pass" \
  --run-summary-json "$TMP_DIR/pass_run_summary.json" \
  --handoff-summary-json "$TMP_DIR/pass_handoff_summary.json" \
  --summary-json "$PASS_SUMMARY" \
  --print-summary-json 0 \
  --run-alpha 7 \
  --handoff-require-run-pipeline-ok 1 \
  --handoff-require-tdpnd-comet-runtime-smoke-ok 1 >"$PASS_LOG" 2>&1

assert_two_stage_invocations "$CAPTURE"
run_line="$(grep '^run	' "$CAPTURE" | tail -n 1 || true)"
handoff_line="$(grep '^handoff	' "$CAPTURE" | tail -n 1 || true)"
if [[ "$run_line" != *"--reports-dir $TMP_DIR/reports_pass"* || "$run_line" != *"--summary-json $TMP_DIR/pass_run_summary.json"* || "$run_line" != *"--alpha 7"* ]]; then
  echo "pass path run forwarding mismatch"
  echo "$run_line"
  exit 1
fi
if [[ "$handoff_line" != *"--phase7-run-summary-json $TMP_DIR/pass_run_summary.json"* || "$handoff_line" != *"--phase7-check-summary-json $TMP_DIR/reports_pass/phase7_mainnet_cutover_check_summary.json"* ]]; then
  echo "pass path handoff summary forwarding mismatch"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" != *"--require-run-pipeline-ok 1"* || "$handoff_line" != *"--show-json 0"* ]]; then
  echo "pass path handoff defaults mismatch"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" != *"--require-tdpnd-comet-runtime-smoke-ok 1"* ]]; then
  echo "pass path comet forwarding mismatch"
  echo "$handoff_line"
  exit 1
fi
if ! jq -e --arg run_summary "$TMP_DIR/pass_run_summary.json" --arg handoff_summary "$TMP_DIR/pass_handoff_summary.json" '
  .version == 1
  and .schema.id == "phase7_mainnet_cutover_handoff_run_summary"
  and .status == "pass"
  and .rc == 0
  and .inputs.dry_run == false
  and .steps.phase7_mainnet_cutover_run.status == "pass"
  and .steps.phase7_mainnet_cutover_run.rc == 0
  and .steps.phase7_mainnet_cutover_run.command_rc == 0
  and .steps.phase7_mainnet_cutover_run.contract_valid == true
  and .steps.phase7_mainnet_cutover_run.artifacts.summary_json == $run_summary
  and .steps.phase7_mainnet_cutover_handoff_check.status == "pass"
  and .steps.phase7_mainnet_cutover_handoff_check.rc == 0
  and .steps.phase7_mainnet_cutover_handoff_check.command_rc == 0
  and .steps.phase7_mainnet_cutover_handoff_check.contract_valid == true
  and .steps.phase7_mainnet_cutover_handoff_check.artifacts.summary_json == $handoff_summary
  and .steps.phase7_mainnet_cutover_handoff_check.signal_snapshot.module_tx_surface_ok == true
  and .steps.phase7_mainnet_cutover_handoff_check.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok == true
  and .steps.phase7_mainnet_cutover_handoff_check.signal_snapshot.dual_write_parity_ok == true
  and .steps.phase7_mainnet_cutover_handoff_check.signal_snapshot.rollback_path_ready == true
  and .steps.phase7_mainnet_cutover_handoff_check.signal_snapshot.operator_approval_ok == true
' "$PASS_SUMMARY" >/dev/null; then
  echo "pass path summary contract mismatch"
  cat "$PASS_SUMMARY"
  exit 1
fi
if ! jq -e '.handoff.tdpnd_comet_runtime_smoke_ok == true' "$TMP_DIR/pass_handoff_summary.json" >/dev/null; then
  echo "pass path handoff fixture missing comet smoke signal"
  cat "$TMP_DIR/pass_handoff_summary.json"
  exit 1
fi
assert_canonical_summary_artifact "$PASS_SUMMARY" "$PASS_CANONICAL" "$PASS_LOG"

echo "[phase7-mainnet-cutover-handoff-run] dry-run relax behavior"
: >"$CAPTURE"
PHASE7_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_CANONICAL_SUMMARY_JSON="$DRY_CANONICAL" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_dry" \
  --run-summary-json "$TMP_DIR/dry_run_summary.json" \
  --handoff-summary-json "$TMP_DIR/dry_handoff_summary.json" \
  --summary-json "$DRY_SUMMARY" \
  --dry-run 1 \
  --print-summary-json 0 \
  --run-theta 9 \
  --handoff-require-module-tx-surface-ok 1 \
  --handoff-require-rollback-ready 1 \
  --handoff-require-tdpnd-comet-runtime-smoke-ok 1 >"$DRY_LOG" 2>&1

assert_two_stage_invocations "$CAPTURE"
run_line="$(grep '^run	' "$CAPTURE" | tail -n 1 || true)"
handoff_line="$(grep '^handoff	' "$CAPTURE" | tail -n 1 || true)"
if [[ "$run_line" != *"--dry-run 1"* || "$run_line" != *"--theta 9"* ]]; then
  echo "dry-run run forwarding mismatch"
  echo "$run_line"
  exit 1
fi
if [[ "$handoff_line" != *"--require-run-pipeline-ok 0"* || "$handoff_line" != *"--require-tdpnd-grpc-runtime-smoke-ok 0"* || "$handoff_line" != *"--require-tdpnd-grpc-live-smoke-ok 0"* || "$handoff_line" != *"--require-tdpnd-grpc-auth-live-smoke-ok 0"* || "$handoff_line" != *"--require-dual-write-parity-ok 0"* || "$handoff_line" != *"--require-operator-approval-ok 0"* ]]; then
  echo "dry-run relax forwarding mismatch"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" != *"--require-module-tx-surface-ok 1"* ]]; then
  echo "dry-run explicit module-tx override mismatch"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" != *"--require-tdpnd-comet-runtime-smoke-ok 1"* ]]; then
  echo "dry-run comet forwarding mismatch"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" != *"--require-rollback-ready 1"* || "$handoff_line" == *"--require-rollback-path-ready 0"* ]]; then
  echo "dry-run rollback alias override mismatch"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" == *"--dry-run 1"* ]]; then
  echo "dry-run should not leak to handoff checker"
  echo "$handoff_line"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.dry_run == true
  and .steps.phase7_mainnet_cutover_run.contract_valid == true
  and .steps.phase7_mainnet_cutover_handoff_check.contract_valid == true
  and .steps.phase7_mainnet_cutover_handoff_check.signal_snapshot.module_tx_surface_ok == true
  and .steps.phase7_mainnet_cutover_handoff_check.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok == true
  and .steps.phase7_mainnet_cutover_handoff_check.signal_snapshot.dual_write_parity_ok == true
' "$DRY_SUMMARY" >/dev/null; then
  echo "dry-run summary mismatch"
  cat "$DRY_SUMMARY"
  exit 1
fi
if ! jq -e '.handoff.tdpnd_comet_runtime_smoke_ok == true' "$TMP_DIR/dry_handoff_summary.json" >/dev/null; then
  echo "dry-run handoff fixture missing comet smoke signal"
  cat "$TMP_DIR/dry_handoff_summary.json"
  exit 1
fi
assert_canonical_summary_artifact "$DRY_SUMMARY" "$DRY_CANONICAL" "$DRY_LOG"

echo "[phase7-mainnet-cutover-handoff-run] run failure still runs handoff check"
: >"$CAPTURE"
set +e
PHASE7_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_CANONICAL_SUMMARY_JSON="$RUN_FAIL_CANONICAL" \
FAKE_PHASE7_RUN_FAIL=1 \
FAKE_PHASE7_RUN_FAIL_RC=27 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_run_fail" \
  --run-summary-json "$TMP_DIR/run_fail_run_summary.json" \
  --handoff-summary-json "$TMP_DIR/run_fail_handoff_summary.json" \
  --summary-json "$RUN_FAIL_SUMMARY" \
  --print-summary-json 0 >"$RUN_FAIL_LOG" 2>&1
run_fail_rc=$?
set -e

if [[ "$run_fail_rc" -ne 27 ]]; then
  echo "expected wrapper rc=27 on run failure, got rc=$run_fail_rc"
  cat "$RUN_FAIL_LOG"
  exit 1
fi
assert_two_stage_invocations "$CAPTURE"
if ! jq -e '
  .status == "fail"
  and .rc == 27
  and .steps.phase7_mainnet_cutover_run.status == "fail"
  and .steps.phase7_mainnet_cutover_run.rc == 27
  and .steps.phase7_mainnet_cutover_run.command_rc == 27
  and .steps.phase7_mainnet_cutover_run.contract_valid == true
  and .steps.phase7_mainnet_cutover_handoff_check.status == "pass"
  and .steps.phase7_mainnet_cutover_handoff_check.rc == 0
  and .steps.phase7_mainnet_cutover_handoff_check.command_rc == 0
  and .steps.phase7_mainnet_cutover_handoff_check.contract_valid == true
' "$RUN_FAIL_SUMMARY" >/dev/null; then
  echo "run-failure summary mismatch"
  cat "$RUN_FAIL_SUMMARY"
  exit 1
fi
assert_canonical_summary_artifact "$RUN_FAIL_SUMMARY" "$RUN_FAIL_CANONICAL" "$RUN_FAIL_LOG"

echo "[phase7-mainnet-cutover-handoff-run] handoff failure propagation"
: >"$CAPTURE"
set +e
PHASE7_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_CANONICAL_SUMMARY_JSON="$HANDOFF_FAIL_CANONICAL" \
FAKE_PHASE7_HANDOFF_FAIL=1 \
FAKE_PHASE7_HANDOFF_FAIL_RC=19 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_handoff_fail" \
  --run-summary-json "$TMP_DIR/handoff_fail_run_summary.json" \
  --handoff-summary-json "$TMP_DIR/handoff_fail_handoff_summary.json" \
  --summary-json "$HANDOFF_FAIL_SUMMARY" \
  --print-summary-json 0 >"$HANDOFF_FAIL_LOG" 2>&1
handoff_fail_rc=$?
set -e

if [[ "$handoff_fail_rc" -ne 19 ]]; then
  echo "expected wrapper rc=19 on handoff failure, got rc=$handoff_fail_rc"
  cat "$HANDOFF_FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 19
  and .steps.phase7_mainnet_cutover_run.status == "pass"
  and .steps.phase7_mainnet_cutover_run.contract_valid == true
  and .steps.phase7_mainnet_cutover_handoff_check.status == "fail"
  and .steps.phase7_mainnet_cutover_handoff_check.rc == 19
  and .steps.phase7_mainnet_cutover_handoff_check.command_rc == 19
  and .steps.phase7_mainnet_cutover_handoff_check.contract_valid == true
' "$HANDOFF_FAIL_SUMMARY" >/dev/null; then
  echo "handoff-failure summary mismatch"
  cat "$HANDOFF_FAIL_SUMMARY"
  exit 1
fi
assert_canonical_summary_artifact "$HANDOFF_FAIL_SUMMARY" "$HANDOFF_FAIL_CANONICAL" "$HANDOFF_FAIL_LOG"

echo "[phase7-mainnet-cutover-handoff-run] invalid handoff summary fails closed"
: >"$CAPTURE"
set +e
PHASE7_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_CANONICAL_SUMMARY_JSON="$INVALID_HANDOFF_CANONICAL" \
FAKE_PHASE7_HANDOFF_INVALID_SUMMARY=1 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_invalid_handoff" \
  --run-summary-json "$TMP_DIR/invalid_handoff_run_summary.json" \
  --handoff-summary-json "$TMP_DIR/invalid_handoff_handoff_summary.json" \
  --summary-json "$INVALID_HANDOFF_SUMMARY" \
  --print-summary-json 0 >"$INVALID_HANDOFF_LOG" 2>&1
invalid_handoff_rc=$?
set -e

if [[ "$invalid_handoff_rc" -ne 3 ]]; then
  echo "expected wrapper rc=3 for invalid handoff summary contract, got rc=$invalid_handoff_rc"
  cat "$INVALID_HANDOFF_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 3
  and .steps.phase7_mainnet_cutover_run.status == "pass"
  and .steps.phase7_mainnet_cutover_run.contract_valid == true
  and .steps.phase7_mainnet_cutover_handoff_check.status == "fail"
  and .steps.phase7_mainnet_cutover_handoff_check.rc == 3
  and .steps.phase7_mainnet_cutover_handoff_check.command_rc == 0
  and .steps.phase7_mainnet_cutover_handoff_check.contract_valid == false
  and (.steps.phase7_mainnet_cutover_handoff_check.contract_error | type) == "string"
  and .steps.phase7_mainnet_cutover_handoff_check.signal_snapshot.module_tx_surface_ok == null
  and .steps.phase7_mainnet_cutover_handoff_check.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok == null
  and .steps.phase7_mainnet_cutover_handoff_check.signal_snapshot.dual_write_parity_ok == null
' "$INVALID_HANDOFF_SUMMARY" >/dev/null; then
  echo "invalid-handoff-summary wrapper summary mismatch"
  cat "$INVALID_HANDOFF_SUMMARY"
  exit 1
fi
assert_canonical_summary_artifact "$INVALID_HANDOFF_SUMMARY" "$INVALID_HANDOFF_CANONICAL" "$INVALID_HANDOFF_LOG"

echo "phase7 mainnet cutover handoff run integration ok"
