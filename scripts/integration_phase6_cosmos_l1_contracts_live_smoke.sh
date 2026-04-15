#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

GATE_SCRIPT="$ROOT_DIR/scripts/ci_phase6_cosmos_l1_contracts.sh"
if [[ ! -x "$GATE_SCRIPT" ]]; then
  echo "missing executable script under test: $GATE_SCRIPT"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

SUMMARY_JSON="$TMP_DIR/ci_phase6_cosmos_l1_contracts_summary.json"
TIMEOUT_SECONDS="${PHASE6_COSMOS_L1_CONTRACTS_LIVE_SMOKE_TIMEOUT_SECONDS:-240}"

if command -v timeout >/dev/null 2>&1; then
  timeout "${TIMEOUT_SECONDS}s" \
    "$GATE_SCRIPT" \
      --print-summary-json 0 \
      --summary-json "$SUMMARY_JSON"
else
  "$GATE_SCRIPT" \
    --print-summary-json 0 \
    --summary-json "$SUMMARY_JSON"
fi

if [[ ! -s "$SUMMARY_JSON" ]]; then
  echo "missing or empty summary json: $SUMMARY_JSON"
  exit 1
fi

if ! jq -e '
  .version == 1
  and .schema.id == "ci_phase6_cosmos_l1_contracts_summary"
  and (.schema.major | type) == "number"
  and (.schema.minor | type) == "number"
  and .status == "pass"
  and .rc == 0
  and (.steps | type) == "object"
  and (.steps.ci_phase6_cosmos_l1_build_testnet | type) == "object"
  and (.steps.phase6_cosmos_l1_build_testnet_check | type) == "object"
  and (.steps.phase6_cosmos_l1_build_testnet_run | type) == "object"
  and (.steps.phase6_cosmos_l1_build_testnet_handoff_check | type) == "object"
  and (.steps.phase6_cosmos_l1_build_testnet_handoff_run | type) == "object"
  and (.steps.phase6_cosmos_l1_build_testnet_suite | type) == "object"
  and .steps.ci_phase6_cosmos_l1_build_testnet.status == "pass"
  and .steps.phase6_cosmos_l1_build_testnet_check.status == "pass"
  and .steps.phase6_cosmos_l1_build_testnet_run.status == "pass"
  and .steps.phase6_cosmos_l1_build_testnet_handoff_check.status == "pass"
  and .steps.phase6_cosmos_l1_build_testnet_handoff_run.status == "pass"
  and .steps.phase6_cosmos_l1_build_testnet_suite.status == "pass"
  and .steps.ci_phase6_cosmos_l1_build_testnet.rc == 0
  and .steps.phase6_cosmos_l1_build_testnet_check.rc == 0
  and .steps.phase6_cosmos_l1_build_testnet_run.rc == 0
  and .steps.phase6_cosmos_l1_build_testnet_handoff_check.rc == 0
  and .steps.phase6_cosmos_l1_build_testnet_handoff_run.rc == 0
  and .steps.phase6_cosmos_l1_build_testnet_suite.rc == 0
' "$SUMMARY_JSON" >/dev/null; then
  echo "phase6 contracts live-smoke summary validation failed"
  cat "$SUMMARY_JSON"
  exit 1
fi

echo "phase6 cosmos l1 contracts live smoke integration check ok"
