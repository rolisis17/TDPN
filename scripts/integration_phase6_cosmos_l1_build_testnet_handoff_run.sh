#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod grep cat sed wc; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

RUNNER="${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_RUN_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase6_cosmos_l1_build_testnet_handoff_run.sh}"
if [[ ! -x "$RUNNER" ]]; then
  echo "missing executable script under test: $RUNNER"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.tsv"
PASS_STDOUT="$TMP_DIR/pass.stdout"
DRY_STDOUT="$TMP_DIR/dry.stdout"
RUN_FAIL_STDOUT="$TMP_DIR/run_fail.stdout"
HANDOFF_FAIL_STDOUT="$TMP_DIR/handoff_fail.stdout"

FAKE_RUN="$TMP_DIR/fake_phase6_cosmos_l1_build_testnet_run.sh"
cat >"$FAKE_RUN" <<'EOF_FAKE_RUN'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE6_HANDOFF_RUN_CAPTURE_FILE:?}"
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
if [[ "${FAKE_RUN_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc="${FAKE_RUN_FAIL_RC:-27}"
fi

check_summary="${FAKE_RUN_CHECK_SUMMARY:-${reports_dir}/phase6_cosmos_l1_build_testnet_check_summary.json}"
roadmap_summary="${FAKE_RUN_ROADMAP_SUMMARY:-${reports_dir}/roadmap_progress_summary.json}"
mkdir -p "$(dirname "$check_summary")" "$(dirname "$roadmap_summary")"

cat >"$check_summary" <<'EOF_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase6_cosmos_l1_build_testnet_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "signals": {
    "chain_scaffold_ok": true,
    "proto_surface_ok": true,
    "proto_codegen_surface_ok": true,
    "query_surface_ok": true,
    "grpc_app_roundtrip_ok": true,
    "tdpnd_grpc_runtime_smoke_ok": true,
    "tdpnd_grpc_live_smoke_ok": true,
    "tdpnd_grpc_auth_live_smoke_ok": true
  }
}
EOF_CHECK

cat >"$roadmap_summary" <<'EOF_ROADMAP'
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "vpn_track": {
    "phase6_cosmos_l1_build_testnet_handoff": {
      "chain_scaffold_ok": true,
      "proto_surface_ok": true,
      "proto_codegen_surface_ok": true,
      "query_surface_ok": true,
      "grpc_app_roundtrip_ok": true,
      "tdpnd_grpc_runtime_smoke_ok": true,
      "tdpnd_grpc_live_smoke_ok": true,
      "tdpnd_grpc_auth_live_smoke_ok": true
    }
  }
}
EOF_ROADMAP

if [[ -n "$summary_json" && "${FAKE_RUN_OMIT_SUMMARY:-0}" != "1" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<EOF_SUMMARY
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
      "contract_valid": true,
      "artifacts": {
        "summary_json": "$check_summary",
        "roadmap_summary_json": "$roadmap_summary"
      }
    }
  },
  "artifacts": {
    "check_summary_json": "$check_summary",
    "roadmap_summary_json": "$roadmap_summary"
  }
}
EOF_SUMMARY
fi

if [[ "${FAKE_RUN_FAIL:-0}" == "1" ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_RUN
chmod +x "$FAKE_RUN"

FAKE_HANDOFF="$TMP_DIR/fake_phase6_cosmos_l1_build_testnet_handoff_check.sh"
cat >"$FAKE_HANDOFF" <<'EOF_FAKE_HANDOFF'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE6_HANDOFF_RUN_CAPTURE_FILE:?}"
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
if [[ "${FAKE_HANDOFF_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc="${FAKE_HANDOFF_FAIL_RC:-19}"
fi

if [[ -n "$summary_json" && "${FAKE_HANDOFF_OMIT_SUMMARY:-0}" != "1" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<EOF_SUMMARY
{
  "version": 1,
  "schema": {
    "id": "phase6_cosmos_l1_build_testnet_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc,
  "fail_closed": true,
  "handoff": {
    "run_pipeline_ok": true,
    "chain_scaffold_ok": true,
    "proto_surface_ok": true,
    "proto_codegen_surface_ok": true,
    "query_surface_ok": true,
    "grpc_app_roundtrip_ok": true,
    "tdpnd_grpc_runtime_smoke_ok": true,
    "tdpnd_grpc_live_smoke_ok": true,
    "tdpnd_grpc_auth_live_smoke_ok": true
  },
  "decision": {
    "pass": true,
    "reasons": [],
    "warnings": []
  }
}
EOF_SUMMARY
fi

if [[ "${FAKE_HANDOFF_FAIL:-0}" == "1" ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_HANDOFF
chmod +x "$FAKE_HANDOFF"

echo "[phase6-cosmos-l1-build-testnet-handoff-run] pass path"
: >"$CAPTURE"
PASS_WRAPPER_SUMMARY="$TMP_DIR/pass_wrapper.json"
PHASE6_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_pass" \
  --run-summary-json "$TMP_DIR/pass_run_summary.json" \
  --handoff-summary-json "$TMP_DIR/pass_handoff_summary.json" \
  --summary-json "$PASS_WRAPPER_SUMMARY" \
  --print-summary-json 0 \
  --run-alpha 7 \
  --handoff-require-run-pipeline-ok 1 >"$PASS_STDOUT" 2>&1

run_line="$(grep '^run	' "$CAPTURE" | tail -n 1 || true)"
handoff_line="$(grep '^handoff	' "$CAPTURE" | tail -n 1 || true)"
if [[ "$run_line" != *"--reports-dir $TMP_DIR/reports_pass"* || "$run_line" != *"--summary-json $TMP_DIR/pass_run_summary.json"* ]]; then
  echo "run forwarding mismatch"
  echo "$run_line"
  exit 1
fi
if [[ "$run_line" != *"--alpha 7"* ]]; then
  echo "run passthrough mismatch"
  echo "$run_line"
  exit 1
fi
if [[ "$handoff_line" != *"--phase6-run-summary-json $TMP_DIR/pass_run_summary.json"* || "$handoff_line" != *"--roadmap-summary-json $TMP_DIR/reports_pass/roadmap_progress_summary.json"* ]]; then
  echo "handoff forwarding mismatch"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" != *"--require-run-pipeline-ok 1"* || "$handoff_line" != *"--show-json 0"* ]]; then
  echo "handoff default forwarding mismatch"
  echo "$handoff_line"
  exit 1
fi

if ! jq -e --arg run_summary "$TMP_DIR/pass_run_summary.json" --arg handoff_summary "$TMP_DIR/pass_handoff_summary.json" '
  .version == 1
  and .schema.id == "phase6_cosmos_l1_build_testnet_handoff_run_summary"
  and .status == "pass"
  and .rc == 0
  and .inputs.dry_run == false
  and .steps.phase6_cosmos_l1_build_testnet_run.status == "pass"
  and .steps.phase6_cosmos_l1_build_testnet_run.rc == 0
  and .steps.phase6_cosmos_l1_build_testnet_run.command_rc == 0
  and .steps.phase6_cosmos_l1_build_testnet_run.contract_valid == true
  and .steps.phase6_cosmos_l1_build_testnet_run.artifacts.summary_json == $run_summary
  and .steps.phase6_cosmos_l1_build_testnet_handoff_check.status == "pass"
  and .steps.phase6_cosmos_l1_build_testnet_handoff_check.rc == 0
  and .steps.phase6_cosmos_l1_build_testnet_handoff_check.command_rc == 0
  and .steps.phase6_cosmos_l1_build_testnet_handoff_check.contract_valid == true
  and .steps.phase6_cosmos_l1_build_testnet_handoff_check.artifacts.summary_json == $handoff_summary
' "$PASS_WRAPPER_SUMMARY" >/dev/null; then
  echo "pass-path combined summary mismatch"
  cat "$PASS_WRAPPER_SUMMARY"
  exit 1
fi

echo "[phase6-cosmos-l1-build-testnet-handoff-run] dry-run forwarding and relax behavior"
: >"$CAPTURE"
DRY_WRAPPER_SUMMARY="$TMP_DIR/dry_wrapper.json"
PHASE6_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_dry" \
  --run-summary-json "$TMP_DIR/dry_run_summary.json" \
  --handoff-summary-json "$TMP_DIR/dry_handoff_summary.json" \
  --summary-json "$DRY_WRAPPER_SUMMARY" \
  --dry-run 1 \
  --print-summary-json 0 \
  --run-theta 9 \
  --handoff-require-proto-surface-ok 1 >"$DRY_STDOUT" 2>&1

run_line="$(grep '^run	' "$CAPTURE" | tail -n 1 || true)"
handoff_line="$(grep '^handoff	' "$CAPTURE" | tail -n 1 || true)"
if [[ "$run_line" != *"--dry-run 1"* || "$run_line" != *"--theta 9"* ]]; then
  echo "dry-run run forwarding mismatch"
  echo "$run_line"
  exit 1
fi
if [[ "$handoff_line" != *"--require-run-pipeline-ok 0"* || "$handoff_line" != *"--require-chain-scaffold-ok 0"* || "$handoff_line" != *"--require-proto-surface-ok 1"* || "$handoff_line" != *"--require-proto-codegen-surface-ok 0"* || "$handoff_line" != *"--require-query-surface-ok 0"* || "$handoff_line" != *"--require-grpc-app-roundtrip-ok 0"* || "$handoff_line" != *"--require-tdpnd-grpc-runtime-smoke-ok 0"* || "$handoff_line" != *"--require-tdpnd-grpc-live-smoke-ok 0"* || "$handoff_line" != *"--require-tdpnd-grpc-auth-live-smoke-ok 0"* ]]; then
  echo "dry-run handoff relax/override mismatch"
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
  and .steps.phase6_cosmos_l1_build_testnet_run.contract_valid == true
  and .steps.phase6_cosmos_l1_build_testnet_handoff_check.contract_valid == true
' "$DRY_WRAPPER_SUMMARY" >/dev/null; then
  echo "dry-run wrapper summary mismatch"
  cat "$DRY_WRAPPER_SUMMARY"
  exit 1
fi

echo "[phase6-cosmos-l1-build-testnet-handoff-run] run failure still runs handoff check"
: >"$CAPTURE"
RUN_FAIL_WRAPPER_SUMMARY="$TMP_DIR/run_fail_wrapper.json"
set +e
PHASE6_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
FAKE_RUN_FAIL=1 \
FAKE_RUN_FAIL_RC=27 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_run_fail" \
  --run-summary-json "$TMP_DIR/run_fail_run_summary.json" \
  --handoff-summary-json "$TMP_DIR/run_fail_handoff_summary.json" \
  --summary-json "$RUN_FAIL_WRAPPER_SUMMARY" \
  --print-summary-json 0 >"$RUN_FAIL_STDOUT" 2>&1
run_fail_rc=$?
set -e
if [[ "$run_fail_rc" -ne 27 ]]; then
  echo "expected wrapper rc=27, got rc=$run_fail_rc"
  cat "$RUN_FAIL_STDOUT"
  exit 1
fi
run_line="$(grep '^run	' "$CAPTURE" | tail -n 1 || true)"
handoff_line="$(grep '^handoff	' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$run_line" || -z "$handoff_line" ]]; then
  echo "expected both stages to run in run-failure path"
  cat "$CAPTURE"
  cat "$RUN_FAIL_STDOUT"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 27
  and .steps.phase6_cosmos_l1_build_testnet_run.status == "fail"
  and .steps.phase6_cosmos_l1_build_testnet_run.rc == 27
  and .steps.phase6_cosmos_l1_build_testnet_run.command_rc == 27
  and .steps.phase6_cosmos_l1_build_testnet_run.contract_valid == true
  and .steps.phase6_cosmos_l1_build_testnet_handoff_check.status == "pass"
  and .steps.phase6_cosmos_l1_build_testnet_handoff_check.rc == 0
  and .steps.phase6_cosmos_l1_build_testnet_handoff_check.command_rc == 0
  and .steps.phase6_cosmos_l1_build_testnet_handoff_check.contract_valid == true
' "$RUN_FAIL_WRAPPER_SUMMARY" >/dev/null; then
  echo "run-failure summary mismatch"
  cat "$RUN_FAIL_WRAPPER_SUMMARY"
  exit 1
fi

echo "[phase6-cosmos-l1-build-testnet-handoff-run] handoff failure propagation"
: >"$CAPTURE"
HANDOFF_FAIL_WRAPPER_SUMMARY="$TMP_DIR/handoff_fail_wrapper.json"
set +e
PHASE6_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
FAKE_HANDOFF_FAIL=1 \
FAKE_HANDOFF_FAIL_RC=19 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_handoff_fail" \
  --run-summary-json "$TMP_DIR/handoff_fail_run_summary.json" \
  --handoff-summary-json "$TMP_DIR/handoff_fail_handoff_summary.json" \
  --summary-json "$HANDOFF_FAIL_WRAPPER_SUMMARY" \
  --print-summary-json 0 >"$HANDOFF_FAIL_STDOUT" 2>&1
handoff_fail_rc=$?
set -e
if [[ "$handoff_fail_rc" -ne 19 ]]; then
  echo "expected wrapper rc=19, got rc=$handoff_fail_rc"
  cat "$HANDOFF_FAIL_STDOUT"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 19
  and .steps.phase6_cosmos_l1_build_testnet_run.status == "pass"
  and .steps.phase6_cosmos_l1_build_testnet_run.contract_valid == true
  and .steps.phase6_cosmos_l1_build_testnet_handoff_check.status == "fail"
  and .steps.phase6_cosmos_l1_build_testnet_handoff_check.contract_valid == true
  and .steps.phase6_cosmos_l1_build_testnet_handoff_check.command_rc == 19
  and .steps.phase6_cosmos_l1_build_testnet_handoff_check.rc == 19
' "$HANDOFF_FAIL_WRAPPER_SUMMARY" >/dev/null; then
  echo "handoff-failure summary mismatch"
  cat "$HANDOFF_FAIL_WRAPPER_SUMMARY"
  exit 1
fi

echo "phase6 cosmos l1 build testnet handoff run integration ok"
