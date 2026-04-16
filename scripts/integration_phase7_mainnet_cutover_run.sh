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

RUNNER="${PHASE7_MAINNET_CUTOVER_RUN_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase7_mainnet_cutover_run.sh}"
if [[ ! -x "$RUNNER" ]]; then
  echo "missing executable script under test: $RUNNER"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/stage_capture.tsv"
PASS_LOG="$TMP_DIR/pass.log"
DRY_LOG="$TMP_DIR/dry.log"
DRY_EXPLICIT_LOG="$TMP_DIR/dry_explicit.log"
FAIL_LOG="$TMP_DIR/fail.log"
INVALID_LOG="$TMP_DIR/invalid.log"
RESERVED_LOG="$TMP_DIR/reserved.log"

PASS_RUN_SUMMARY="$TMP_DIR/run_pass.json"
DRY_RUN_SUMMARY="$TMP_DIR/run_dry.json"
DRY_EXPLICIT_RUN_SUMMARY="$TMP_DIR/run_dry_explicit.json"
FAIL_RUN_SUMMARY="$TMP_DIR/run_fail.json"
INVALID_RUN_SUMMARY="$TMP_DIR/run_invalid.json"

PASS_CANONICAL_SUMMARY="$TMP_DIR/canonical_run_pass.json"
DRY_CANONICAL_SUMMARY="$TMP_DIR/canonical_run_dry.json"
DRY_EXPLICIT_CANONICAL_SUMMARY="$TMP_DIR/canonical_run_dry_explicit.json"
FAIL_CANONICAL_SUMMARY="$TMP_DIR/canonical_run_fail.json"
INVALID_CANONICAL_SUMMARY="$TMP_DIR/canonical_run_invalid.json"

FAKE_CHECK="$TMP_DIR/fake_phase7_mainnet_cutover_check.sh"
cat >"$FAKE_CHECK" <<'EOF_FAKE_CHECK'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE7_MAINNET_CUTOVER_RUN_CAPTURE_FILE:?}"
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

fail_rc="${FAKE_PHASE7_CHECK_FAIL_RC:-23}"
status="pass"
rc=0
if [[ "${FAKE_PHASE7_CHECK_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc="$fail_rc"
fi

schema_id="phase7_mainnet_cutover_check_summary"
if [[ "${FAKE_PHASE7_CHECK_INVALID_SUMMARY:-0}" == "1" ]]; then
  schema_id="phase7_mainnet_cutover_check_summary_invalid"
fi

if [[ -n "$summary_json" && "${FAKE_PHASE7_CHECK_OMIT_SUMMARY:-0}" != "1" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<EOF_CHECK_SUMMARY
{
  "version": 1,
  "schema": {
    "id": "$schema_id",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc,
  "signals": {
    "run_pipeline_ok": true,
    "module_tx_surface_ok": true,
    "tdpnd_grpc_runtime_smoke_ok": true,
    "tdpnd_grpc_live_smoke_ok": true,
    "tdpnd_grpc_auth_live_smoke_ok": true,
    "tdpnd_comet_runtime_smoke_ok": true,
    "dual_write_parity_ok": true,
    "mainnet_activation_gate_go": true,
    "rollback_path_ready": true,
    "operator_approval_ok": true
  }
}
EOF_CHECK_SUMMARY
fi

if [[ "${FAKE_PHASE7_CHECK_FAIL:-0}" == "1" ]]; then
  exit "$fail_rc"
fi
exit 0
EOF_FAKE_CHECK
chmod +x "$FAKE_CHECK"

assert_single_check_invocation() {
  local capture_file="$1"
  local line_count check_line
  line_count="$(wc -l <"$capture_file" | tr -d ' ')"
  if [[ "$line_count" -ne 1 ]]; then
    echo "expected exactly one stage invocation, got $line_count"
    cat "$capture_file"
    exit 1
  fi
  check_line="$(sed -n '1p' "$capture_file" || true)"
  if [[ "${check_line%%$'\t'*}" != "check" ]]; then
    echo "runner stage mismatch; expected check invocation"
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

  if ! grep -Fq -- "[phase7-mainnet-cutover-run] canonical_summary_json=$canonical_summary_json" "$log_path"; then
    echo "missing canonical summary log line"
    cat "$log_path"
    exit 1
  fi
}

echo "[phase7-mainnet-cutover-run] pass path"
: >"$CAPTURE"
PHASE7_MAINNET_CUTOVER_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE7_MAINNET_CUTOVER_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
PHASE7_MAINNET_CUTOVER_RUN_CANONICAL_SUMMARY_JSON="$PASS_CANONICAL_SUMMARY" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_pass" \
  --check-summary-json "$TMP_DIR/check_pass_summary.json" \
  --summary-json "$PASS_RUN_SUMMARY" \
  --print-summary-json 0 \
  --check-alpha 7 >"$PASS_LOG" 2>&1

assert_single_check_invocation "$CAPTURE"
check_line="$(grep '^check	' "$CAPTURE" | tail -n 1 || true)"
if [[ "$check_line" != *"--summary-json $TMP_DIR/check_pass_summary.json"* || "$check_line" != *"--alpha 7"* ]]; then
  echo "pass path forwarding mismatch"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" != *"--show-json 0"* ]]; then
  echo "pass path missing default --show-json 0 forwarding"
  echo "$check_line"
  exit 1
fi

if [[ ! -f "$PASS_RUN_SUMMARY" ]]; then
  echo "missing pass run summary JSON: $PASS_RUN_SUMMARY"
  cat "$PASS_LOG"
  exit 1
fi
if ! jq -e '
  .version == 1
  and .schema.id == "phase7_mainnet_cutover_run_summary"
  and .status == "pass"
  and .rc == 0
  and .inputs.dry_run == false
  and .steps.phase7_mainnet_cutover_check.status == "pass"
  and .steps.phase7_mainnet_cutover_check.rc == 0
  and .steps.phase7_mainnet_cutover_check.command_rc == 0
  and .steps.phase7_mainnet_cutover_check.contract_valid == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.module_tx_surface_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_comet_runtime_smoke_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.dual_write_parity_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.mainnet_activation_gate_go == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.rollback_path_ready == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.operator_approval_ok == true
  and .steps.phase7_mainnet_cutover_check.artifacts.summary_exists == true
' "$PASS_RUN_SUMMARY" >/dev/null; then
  echo "pass run summary contract mismatch"
  cat "$PASS_RUN_SUMMARY"
  exit 1
fi
assert_canonical_summary_artifact "$PASS_RUN_SUMMARY" "$PASS_CANONICAL_SUMMARY" "$PASS_LOG"

echo "[phase7-mainnet-cutover-run] dry-run relaxation injection"
: >"$CAPTURE"
PHASE7_MAINNET_CUTOVER_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE7_MAINNET_CUTOVER_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
PHASE7_MAINNET_CUTOVER_RUN_CANONICAL_SUMMARY_JSON="$DRY_CANONICAL_SUMMARY" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_dry" \
  --check-summary-json "$TMP_DIR/check_dry_summary.json" \
  --summary-json "$DRY_RUN_SUMMARY" \
  --dry-run 1 \
  --print-summary-json 0 >"$DRY_LOG" 2>&1

assert_single_check_invocation "$CAPTURE"
check_line="$(grep '^check	' "$CAPTURE" | tail -n 1 || true)"
if [[ "$check_line" != *"--require-rollback-path-ready 0"* || "$check_line" != *"--require-operator-approval-ok 0"* ]]; then
  echo "dry-run default manual-gate relax forwarding mismatch"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" == *"--dry-run 1"* || "$check_line" == *"--print-summary-json 0"* ]]; then
  echo "wrapper-only flags leaked into checker"
  echo "$check_line"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.dry_run == true
  and .steps.phase7_mainnet_cutover_check.contract_valid == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.module_tx_surface_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_comet_runtime_smoke_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.dual_write_parity_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.mainnet_activation_gate_go == true
' "$DRY_RUN_SUMMARY" >/dev/null; then
  echo "dry-run summary mismatch"
  cat "$DRY_RUN_SUMMARY"
  exit 1
fi
assert_canonical_summary_artifact "$DRY_RUN_SUMMARY" "$DRY_CANONICAL_SUMMARY" "$DRY_LOG"

echo "[phase7-mainnet-cutover-run] dry-run explicit manual gates are preserved"
: >"$CAPTURE"
PHASE7_MAINNET_CUTOVER_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE7_MAINNET_CUTOVER_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
PHASE7_MAINNET_CUTOVER_RUN_CANONICAL_SUMMARY_JSON="$DRY_EXPLICIT_CANONICAL_SUMMARY" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_dry_explicit" \
  --check-summary-json "$TMP_DIR/check_dry_explicit_summary.json" \
  --summary-json "$DRY_EXPLICIT_RUN_SUMMARY" \
  --dry-run 1 \
  --print-summary-json 0 \
  --check-require-rollback-path-ready 1 \
  --check-require-operator-approval-ok 1 >"$DRY_EXPLICIT_LOG" 2>&1

assert_single_check_invocation "$CAPTURE"
check_line="$(grep '^check	' "$CAPTURE" | tail -n 1 || true)"
if [[ "$check_line" != *"--require-rollback-path-ready 1"* || "$check_line" != *"--require-operator-approval-ok 1"* ]]; then
  echo "dry-run explicit manual-gate forwarding mismatch"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" == *"--require-rollback-path-ready 0"* || "$check_line" == *"--require-operator-approval-ok 0"* ]]; then
  echo "dry-run explicit manual-gate forwarding was overridden"
  echo "$check_line"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.dry_run == true
  and .steps.phase7_mainnet_cutover_check.contract_valid == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.module_tx_surface_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_comet_runtime_smoke_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.dual_write_parity_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.mainnet_activation_gate_go == true
' "$DRY_EXPLICIT_RUN_SUMMARY" >/dev/null; then
  echo "dry-run explicit summary mismatch"
  cat "$DRY_EXPLICIT_RUN_SUMMARY"
  exit 1
fi
assert_canonical_summary_artifact "$DRY_EXPLICIT_RUN_SUMMARY" "$DRY_EXPLICIT_CANONICAL_SUMMARY" "$DRY_EXPLICIT_LOG"

echo "[phase7-mainnet-cutover-run] child failure propagation"
: >"$CAPTURE"
set +e
PHASE7_MAINNET_CUTOVER_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE7_MAINNET_CUTOVER_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
PHASE7_MAINNET_CUTOVER_RUN_CANONICAL_SUMMARY_JSON="$FAIL_CANONICAL_SUMMARY" \
FAKE_PHASE7_CHECK_FAIL=1 \
FAKE_PHASE7_CHECK_FAIL_RC=23 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_fail" \
  --check-summary-json "$TMP_DIR/check_fail_summary.json" \
  --summary-json "$FAIL_RUN_SUMMARY" \
  --print-summary-json 0 >"$FAIL_LOG" 2>&1
fail_rc=$?
set -e

if [[ "$fail_rc" -ne 23 ]]; then
  echo "expected wrapper rc=23 on child failure, got rc=$fail_rc"
  cat "$FAIL_LOG"
  exit 1
fi
assert_single_check_invocation "$CAPTURE"
if ! jq -e '
  .status == "fail"
  and .rc == 23
  and .steps.phase7_mainnet_cutover_check.status == "fail"
  and .steps.phase7_mainnet_cutover_check.rc == 23
  and .steps.phase7_mainnet_cutover_check.command_rc == 23
  and .steps.phase7_mainnet_cutover_check.contract_valid == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.module_tx_surface_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.dual_write_parity_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.mainnet_activation_gate_go == true
' "$FAIL_RUN_SUMMARY" >/dev/null; then
  echo "child-fail run summary mismatch"
  cat "$FAIL_RUN_SUMMARY"
  exit 1
fi
assert_canonical_summary_artifact "$FAIL_RUN_SUMMARY" "$FAIL_CANONICAL_SUMMARY" "$FAIL_LOG"

echo "[phase7-mainnet-cutover-run] invalid child summary contract fails closed"
: >"$CAPTURE"
set +e
PHASE7_MAINNET_CUTOVER_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE7_MAINNET_CUTOVER_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
PHASE7_MAINNET_CUTOVER_RUN_CANONICAL_SUMMARY_JSON="$INVALID_CANONICAL_SUMMARY" \
FAKE_PHASE7_CHECK_INVALID_SUMMARY=1 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_invalid" \
  --check-summary-json "$TMP_DIR/check_invalid_summary.json" \
  --summary-json "$INVALID_RUN_SUMMARY" \
  --print-summary-json 0 >"$INVALID_LOG" 2>&1
invalid_rc=$?
set -e

if [[ "$invalid_rc" -ne 3 ]]; then
  echo "expected wrapper rc=3 on invalid child summary contract, got rc=$invalid_rc"
  cat "$INVALID_LOG"
  exit 1
fi
assert_single_check_invocation "$CAPTURE"
if ! jq -e '
  .status == "fail"
  and .rc == 3
  and .steps.phase7_mainnet_cutover_check.status == "fail"
  and .steps.phase7_mainnet_cutover_check.rc == 3
  and .steps.phase7_mainnet_cutover_check.command_rc == 0
  and .steps.phase7_mainnet_cutover_check.contract_valid == false
  and (.steps.phase7_mainnet_cutover_check.contract_error | type) == "string"
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.module_tx_surface_ok == null
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok == null
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_comet_runtime_smoke_ok == null
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.dual_write_parity_ok == null
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.mainnet_activation_gate_go == null
' "$INVALID_RUN_SUMMARY" >/dev/null; then
  echo "invalid-child-summary run summary mismatch"
  cat "$INVALID_RUN_SUMMARY"
  exit 1
fi
assert_canonical_summary_artifact "$INVALID_RUN_SUMMARY" "$INVALID_CANONICAL_SUMMARY" "$INVALID_LOG"

echo "[phase7-mainnet-cutover-run] reserved wrapper args are protected"
set +e
PHASE7_MAINNET_CUTOVER_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE7_MAINNET_CUTOVER_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_reserved" \
  --check-summary-json "$TMP_DIR/check_reserved_summary.json" \
  --summary-json "$TMP_DIR/run_reserved_summary.json" \
  --print-summary-json 0 \
  --check-dry-run 1 >"$RESERVED_LOG" 2>&1
reserved_rc=$?
set -e

if [[ "$reserved_rc" -ne 2 ]]; then
  echo "expected wrapper rc=2 for reserved pass-through arg, got rc=$reserved_rc"
  cat "$RESERVED_LOG"
  exit 1
fi
if ! grep -Fq -- "reserved wrapper arg via --check- prefix: --check-dry-run" "$RESERVED_LOG"; then
  echo "reserved-arg protection message mismatch"
  cat "$RESERVED_LOG"
  exit 1
fi

echo "phase7 mainnet cutover run integration ok"
