#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod grep cat cmp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase6_cosmos_l1_build_testnet_check.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS_SUMMARY="$TMP_DIR/ci_phase6_pass.json"
FAIL_SUMMARY="$TMP_DIR/ci_phase6_fail.json"
RELAXED_SUMMARY="$TMP_DIR/ci_phase6_relaxed.json"

PASS_OUTPUT="$TMP_DIR/pass_output.json"
FAIL_OUTPUT="$TMP_DIR/fail_output.json"
RELAXED_OUTPUT="$TMP_DIR/relaxed_output.json"
PASS_CANONICAL="$TMP_DIR/pass_canonical_summary.json"
FAIL_CANONICAL="$TMP_DIR/fail_canonical_summary.json"
RELAXED_CANONICAL="$TMP_DIR/relaxed_canonical_summary.json"

PASS_LOG="$TMP_DIR/pass.log"
FAIL_LOG="$TMP_DIR/fail.log"
RELAXED_LOG="$TMP_DIR/relaxed.log"

cat >"$PASS_SUMMARY" <<'EOF_PASS'
{
  "version": 1,
  "schema": {
    "id": "ci_phase6_cosmos_l1_build_testnet_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "chain_scaffold": { "status": "pass" },
    "proto_surface": { "status": "pass" },
    "proto_codegen_surface": { "status": "pass" },
    "query_surface": { "status": "pass" },
    "module_tx_surface": { "status": "pass" },
    "grpc_app_roundtrip": { "status": "pass" },
    "tdpnd_grpc_runtime_smoke": { "status": "pass" },
    "tdpnd_grpc_live_smoke": { "status": "pass" },
    "tdpnd_grpc_auth_live_smoke": { "status": "pass" }
  }
}
EOF_PASS

cat >"$FAIL_SUMMARY" <<'EOF_FAIL'
{
  "version": 1,
  "schema": {
    "id": "ci_phase6_cosmos_l1_build_testnet_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "chain_scaffold": { "status": "pass" },
    "proto_surface": { "status": "pass" },
    "proto_codegen_surface": { "status": "pass" },
    "query_surface": { "status": "pass" },
    "module_tx_surface": { "status": "fail" },
    "grpc_app_roundtrip": { "status": "pass" },
    "tdpnd_grpc_runtime_smoke": { "status": "pass" },
    "tdpnd_grpc_live_smoke": { "status": "pass" },
    "tdpnd_grpc_auth_live_smoke": { "status": "pass" }
  }
}
EOF_FAIL

cat >"$RELAXED_SUMMARY" <<'EOF_RELAXED'
{
  "version": 1,
  "schema": {
    "id": "ci_phase6_cosmos_l1_build_testnet_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "chain_scaffold": { "status": "pass" },
    "proto_surface": { "status": "pass" },
    "proto_codegen_surface": { "status": "pass" },
    "query_surface": { "status": "pass" },
    "module_tx_surface": { "status": "fail" },
    "grpc_app_roundtrip": { "status": "pass" },
    "tdpnd_grpc_runtime_smoke": { "status": "pass" },
    "tdpnd_grpc_live_smoke": { "status": "pass" },
    "tdpnd_grpc_auth_live_smoke": { "status": "pass" }
  }
}
EOF_RELAXED

echo "[phase6-cosmos-l1-check] pass path"
PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_CANONICAL_SUMMARY_JSON="$PASS_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase6-summary-json "$PASS_SUMMARY" \
  --summary-json "$PASS_OUTPUT" \
  --show-json 0 >"$PASS_LOG" 2>&1

if [[ ! -f "$PASS_CANONICAL" ]]; then
  echo "missing canonical summary on pass path: $PASS_CANONICAL"
  cat "$PASS_LOG"
  exit 1
fi
if ! jq -e '
  .version == 1
  and .schema.id == "phase6_cosmos_l1_build_testnet_check_summary"
  and .status == "pass"
  and .rc == 0
  and .artifacts.canonical_summary_json == $expected_canonical
  and .inputs.usable.ci_phase6_summary_json == true
  and .policy.require_chain_scaffold_ok == true
  and .policy.require_proto_surface_ok == true
  and .policy.require_proto_codegen_surface_ok == true
  and .policy.require_query_surface_ok == true
  and .policy.require_module_tx_surface_ok == true
  and .policy.require_grpc_app_roundtrip_ok == true
  and .policy.require_tdpnd_grpc_runtime_smoke_ok == true
  and .policy.require_tdpnd_grpc_live_smoke_ok == true
  and .policy.require_tdpnd_grpc_auth_live_smoke_ok == true
  and .signals.chain_scaffold_ok == true
  and .signals.proto_surface_ok == true
  and .signals.proto_codegen_surface_ok == true
  and .signals.query_surface_ok == true
  and .signals.module_tx_surface_ok == true
  and .signals.grpc_app_roundtrip_ok == true
  and .signals.tdpnd_grpc_runtime_smoke_ok == true
  and .signals.tdpnd_grpc_live_smoke_ok == true
  and .signals.tdpnd_grpc_auth_live_smoke_ok == true
' --arg expected_canonical "$PASS_CANONICAL" "$PASS_OUTPUT" >/dev/null; then
  echo "pass-path summary contract mismatch"
  cat "$PASS_OUTPUT"
  cat "$PASS_LOG"
  exit 1
fi
if ! cmp -s "$PASS_OUTPUT" "$PASS_CANONICAL"; then
  echo "pass-path canonical summary diverges from run summary"
  cat "$PASS_OUTPUT"
  cat "$PASS_CANONICAL"
  exit 1
fi

echo "[phase6-cosmos-l1-check] fail-closed path"
set +e
PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_CANONICAL_SUMMARY_JSON="$FAIL_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase6-summary-json "$FAIL_SUMMARY" \
  --summary-json "$FAIL_OUTPUT" \
  --show-json 0 >"$FAIL_LOG" 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for fail-closed stage failure, got rc=$fail_rc"
  cat "$FAIL_LOG"
  exit 1
fi
if [[ ! -f "$FAIL_CANONICAL" ]]; then
  echo "missing canonical summary on fail path: $FAIL_CANONICAL"
  cat "$FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .artifacts.canonical_summary_json == $expected_canonical
  and .signals.module_tx_surface_ok == false
  and .stages.module_tx_surface.status == "fail"
  and ((.decision.reasons // []) | any(test("module_tx_surface_ok is false")))
' --arg expected_canonical "$FAIL_CANONICAL" "$FAIL_OUTPUT" >/dev/null; then
  echo "fail-path summary contract mismatch"
  cat "$FAIL_OUTPUT"
  cat "$FAIL_LOG"
  exit 1
fi
if ! cmp -s "$FAIL_OUTPUT" "$FAIL_CANONICAL"; then
  echo "fail-path canonical summary diverges from run summary"
  cat "$FAIL_OUTPUT"
  cat "$FAIL_CANONICAL"
  exit 1
fi

echo "[phase6-cosmos-l1-check] relaxed toggle path"
PHASE6_COSMOS_L1_BUILD_TESTNET_CHECK_CANONICAL_SUMMARY_JSON="$RELAXED_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase6-summary-json "$RELAXED_SUMMARY" \
  --summary-json "$RELAXED_OUTPUT" \
  --require-module-tx-surface-ok 0 \
  --show-json 0 >"$RELAXED_LOG" 2>&1

if [[ ! -f "$RELAXED_CANONICAL" ]]; then
  echo "missing canonical summary on relaxed path: $RELAXED_CANONICAL"
  cat "$RELAXED_LOG"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .artifacts.canonical_summary_json == $expected_canonical
  and .policy.require_module_tx_surface_ok == false
  and .signals.module_tx_surface_ok == false
  and .stages.module_tx_surface.status == "fail"
' --arg expected_canonical "$RELAXED_CANONICAL" "$RELAXED_OUTPUT" >/dev/null; then
  echo "relaxed-toggle summary contract mismatch"
  cat "$RELAXED_OUTPUT"
  cat "$RELAXED_LOG"
  exit 1
fi
if ! cmp -s "$RELAXED_OUTPUT" "$RELAXED_CANONICAL"; then
  echo "relaxed-path canonical summary diverges from run summary"
  cat "$RELAXED_OUTPUT"
  cat "$RELAXED_CANONICAL"
  exit 1
fi

echo "phase6 cosmos l1 build testnet check integration ok"
