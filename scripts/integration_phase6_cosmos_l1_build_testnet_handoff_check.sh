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

SCRIPT_UNDER_TEST="${PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase6_cosmos_l1_build_testnet_handoff_check.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS_RUN="$TMP_DIR/run_pass.json"
PASS_CHECK="$TMP_DIR/check_pass.json"
PASS_OUTPUT="$TMP_DIR/pass_output.json"
PASS_LOG="$TMP_DIR/pass.log"
PASS_CANONICAL="$TMP_DIR/pass_canonical_summary.json"

FAIL_RUN="$TMP_DIR/run_fail.json"
FAIL_CHECK="$TMP_DIR/check_fail.json"
FAIL_OUTPUT="$TMP_DIR/fail_output.json"
FAIL_LOG="$TMP_DIR/fail.log"
FAIL_CANONICAL="$TMP_DIR/fail_canonical_summary.json"

RELAXED_RUN="$TMP_DIR/run_relaxed.json"
RELAXED_CHECK="$TMP_DIR/check_relaxed.json"
RELAXED_OUTPUT="$TMP_DIR/relaxed_output.json"
RELAXED_LOG="$TMP_DIR/relaxed.log"
RELAXED_CANONICAL="$TMP_DIR/relaxed_canonical_summary.json"

cat >"$PASS_CHECK" <<'EOF_PASS_CHECK'
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
EOF_PASS_CHECK

cat >"$PASS_RUN" <<EOF_PASS_RUN
{
  "version": 1,
  "schema": {
    "id": "phase6_cosmos_l1_build_testnet_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "ci_phase6_cosmos_l1_build_testnet": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true
    },
    "phase6_cosmos_l1_build_testnet_check": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "$PASS_CHECK"
      }
    }
  },
  "artifacts": {
    "check_summary_json": "$PASS_CHECK"
  }
}
EOF_PASS_RUN

echo "[phase6-cosmos-l1-handoff-check] pass path"
PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_CANONICAL_SUMMARY_JSON="$PASS_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --phase6-run-summary-json "$PASS_RUN" \
  --summary-json "$PASS_OUTPUT" \
  --show-json 0 >"$PASS_LOG" 2>&1

if [[ ! -f "$PASS_CANONICAL" ]]; then
  echo "missing canonical summary on pass path: $PASS_CANONICAL"
  cat "$PASS_LOG"
  exit 1
fi
if ! jq -e '
  .version == 1
  and .schema.id == "phase6_cosmos_l1_build_testnet_handoff_check_summary"
  and .status == "pass"
  and .rc == 0
  and .artifacts.canonical_summary_json == $expected_canonical
  and .fail_closed == true
  and .inputs.usable.phase6_run_summary_json == true
  and .inputs.usable.phase6_check_summary_json == true
  and .handoff.run_pipeline_ok == true
  and .handoff.chain_scaffold_ok == true
  and .handoff.proto_surface_ok == true
  and .handoff.proto_codegen_surface_ok == true
  and .handoff.query_surface_ok == true
  and .handoff.grpc_app_roundtrip_ok == true
  and .handoff.tdpnd_grpc_runtime_smoke_ok == true
  and .handoff.tdpnd_grpc_live_smoke_ok == true
  and .handoff.tdpnd_grpc_auth_live_smoke_ok == true
' --arg expected_canonical "$PASS_CANONICAL" "$PASS_OUTPUT" >/dev/null; then
  echo "pass-path summary mismatch"
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

cat >"$FAIL_CHECK" <<'EOF_FAIL_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase6_cosmos_l1_build_testnet_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "rc": 1,
  "signals": {
    "chain_scaffold_ok": true,
    "proto_surface_ok": true,
    "proto_codegen_surface_ok": true,
    "query_surface_ok": true,
    "grpc_app_roundtrip_ok": true,
    "tdpnd_grpc_runtime_smoke_ok": true,
    "tdpnd_grpc_live_smoke_ok": true,
    "tdpnd_grpc_auth_live_smoke_ok": false
  }
}
EOF_FAIL_CHECK

cat >"$FAIL_RUN" <<EOF_FAIL_RUN
{
  "version": 1,
  "schema": {
    "id": "phase6_cosmos_l1_build_testnet_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "ci_phase6_cosmos_l1_build_testnet": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true
    },
    "phase6_cosmos_l1_build_testnet_check": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "$FAIL_CHECK"
      }
    }
  }
}
EOF_FAIL_RUN

echo "[phase6-cosmos-l1-handoff-check] fail-closed path"
set +e
PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_CANONICAL_SUMMARY_JSON="$FAIL_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --phase6-run-summary-json "$FAIL_RUN" \
  --summary-json "$FAIL_OUTPUT" \
  --show-json 0 >"$FAIL_LOG" 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for fail-closed path, got rc=$fail_rc"
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
  and .handoff.run_pipeline_ok == true
  and .handoff.proto_surface_ok == true
  and .handoff.tdpnd_grpc_auth_live_smoke_ok == false
  and .handoff.tdpnd_grpc_auth_live_smoke_status == "fail"
  and ((.decision.reasons // []) | any(test("tdpnd_grpc_auth_live_smoke_ok is false")))
' --arg expected_canonical "$FAIL_CANONICAL" "$FAIL_OUTPUT" >/dev/null; then
  echo "fail-path summary mismatch"
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

cat >"$RELAXED_CHECK" <<'EOF_RELAXED_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase6_cosmos_l1_build_testnet_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "rc": 1,
  "signals": {
    "chain_scaffold_ok": true,
    "proto_surface_ok": true,
    "proto_codegen_surface_ok": true,
    "query_surface_ok": true,
    "grpc_app_roundtrip_ok": true,
    "tdpnd_grpc_runtime_smoke_ok": true,
    "tdpnd_grpc_live_smoke_ok": false,
    "tdpnd_grpc_auth_live_smoke_ok": false
  }
}
EOF_RELAXED_CHECK

cat >"$RELAXED_RUN" <<EOF_RELAXED_RUN
{
  "version": 1,
  "schema": {
    "id": "phase6_cosmos_l1_build_testnet_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "ci_phase6_cosmos_l1_build_testnet": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true
    },
    "phase6_cosmos_l1_build_testnet_check": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "$RELAXED_CHECK"
      }
    }
  }
}
EOF_RELAXED_RUN

echo "[phase6-cosmos-l1-handoff-check] relaxed toggle path"
PHASE6_COSMOS_L1_BUILD_TESTNET_HANDOFF_CHECK_CANONICAL_SUMMARY_JSON="$RELAXED_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --phase6-run-summary-json "$RELAXED_RUN" \
  --summary-json "$RELAXED_OUTPUT" \
  --require-tdpnd-grpc-live-smoke-ok 0 \
  --require-tdpnd-auth-live-smoke-ok 0 \
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
  and .inputs.requirements.tdpnd_grpc_live_smoke_ok == false
  and .inputs.requirements.tdpnd_grpc_auth_live_smoke_ok == false
  and .handoff.tdpnd_grpc_live_smoke_ok == false
  and .handoff.tdpnd_grpc_live_smoke_status == "fail"
  and .handoff.tdpnd_grpc_auth_live_smoke_ok == false
  and .handoff.tdpnd_grpc_auth_live_smoke_status == "fail"
' --arg expected_canonical "$RELAXED_CANONICAL" "$RELAXED_OUTPUT" >/dev/null; then
  echo "relaxed-path summary mismatch"
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

echo "phase6 cosmos l1 build testnet handoff check integration ok"
