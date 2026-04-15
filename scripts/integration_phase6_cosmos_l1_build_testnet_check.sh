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
    "grpc_app_roundtrip": { "status": "pass" },
    "tdpnd_grpc_runtime_smoke": { "status": "pass" },
    "tdpnd_grpc_live_smoke": { "status": "pass" },
    "tdpnd_grpc_auth_live_smoke": { "status": "fail" }
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
    "grpc_app_roundtrip": { "status": "pass" },
    "tdpnd_grpc_runtime_smoke": { "status": "pass" },
    "tdpnd_grpc_live_smoke": { "status": "pass" },
    "tdpnd_grpc_auth_live_smoke": { "status": "fail" }
  }
}
EOF_RELAXED

echo "[phase6-cosmos-l1-check] pass path"
"$SCRIPT_UNDER_TEST" \
  --ci-phase6-summary-json "$PASS_SUMMARY" \
  --summary-json "$PASS_OUTPUT" \
  --show-json 0 >"$PASS_LOG" 2>&1

if ! jq -e '
  .version == 1
  and .schema.id == "phase6_cosmos_l1_build_testnet_check_summary"
  and .status == "pass"
  and .rc == 0
  and .inputs.usable.ci_phase6_summary_json == true
  and .policy.require_chain_scaffold_ok == true
  and .policy.require_proto_surface_ok == true
  and .policy.require_proto_codegen_surface_ok == true
  and .policy.require_query_surface_ok == true
  and .policy.require_grpc_app_roundtrip_ok == true
  and .policy.require_tdpnd_grpc_runtime_smoke_ok == true
  and .policy.require_tdpnd_grpc_live_smoke_ok == true
  and .policy.require_tdpnd_grpc_auth_live_smoke_ok == true
  and .signals.chain_scaffold_ok == true
  and .signals.proto_surface_ok == true
  and .signals.proto_codegen_surface_ok == true
  and .signals.query_surface_ok == true
  and .signals.grpc_app_roundtrip_ok == true
  and .signals.tdpnd_grpc_runtime_smoke_ok == true
  and .signals.tdpnd_grpc_live_smoke_ok == true
  and .signals.tdpnd_grpc_auth_live_smoke_ok == true
' "$PASS_OUTPUT" >/dev/null; then
  echo "pass-path summary contract mismatch"
  cat "$PASS_OUTPUT"
  cat "$PASS_LOG"
  exit 1
fi

echo "[phase6-cosmos-l1-check] fail-closed path"
set +e
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
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .signals.tdpnd_grpc_auth_live_smoke_ok == false
  and .stages.tdpnd_grpc_auth_live_smoke.status == "fail"
  and ((.decision.reasons // []) | any(test("tdpnd_grpc_auth_live_smoke_ok is false")))
' "$FAIL_OUTPUT" >/dev/null; then
  echo "fail-path summary contract mismatch"
  cat "$FAIL_OUTPUT"
  cat "$FAIL_LOG"
  exit 1
fi

echo "[phase6-cosmos-l1-check] relaxed toggle path"
"$SCRIPT_UNDER_TEST" \
  --ci-phase6-summary-json "$RELAXED_SUMMARY" \
  --summary-json "$RELAXED_OUTPUT" \
  --require-tdpnd-grpc-auth-live-smoke-ok 0 \
  --show-json 0 >"$RELAXED_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_tdpnd_grpc_auth_live_smoke_ok == false
  and .signals.tdpnd_grpc_auth_live_smoke_ok == false
  and .stages.tdpnd_grpc_auth_live_smoke.status == "fail"
' "$RELAXED_OUTPUT" >/dev/null; then
  echo "relaxed-toggle summary contract mismatch"
  cat "$RELAXED_OUTPUT"
  cat "$RELAXED_LOG"
  exit 1
fi

echo "phase6 cosmos l1 build testnet check integration ok"
