#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp cmp cat; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

GATE_SCRIPT="$ROOT_DIR/scripts/ci_phase7_mainnet_cutover.sh"
if [[ ! -x "$GATE_SCRIPT" ]]; then
  echo "missing executable script under test: $GATE_SCRIPT"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

SUMMARY_JSON="$TMP_DIR/ci_phase7_mainnet_cutover_summary.json"
CANONICAL_SUMMARY_JSON="$TMP_DIR/ci_phase7_mainnet_cutover_canonical_summary.json"
TIMEOUT_SECONDS="${PHASE7_MAINNET_CUTOVER_LIVE_SMOKE_TIMEOUT_SECONDS:-240}"

if command -v timeout >/dev/null 2>&1; then
  timeout "${TIMEOUT_SECONDS}s" \
    env CI_PHASE7_MAINNET_CUTOVER_CANONICAL_SUMMARY_JSON="$CANONICAL_SUMMARY_JSON" \
    "$GATE_SCRIPT" \
      --print-summary-json 0 \
      --summary-json "$SUMMARY_JSON"
else
  CI_PHASE7_MAINNET_CUTOVER_CANONICAL_SUMMARY_JSON="$CANONICAL_SUMMARY_JSON" \
  "$GATE_SCRIPT" \
    --print-summary-json 0 \
    --summary-json "$SUMMARY_JSON"
fi

if [[ ! -s "$SUMMARY_JSON" ]]; then
  echo "missing or empty summary json: $SUMMARY_JSON"
  exit 1
fi
if [[ ! -s "$CANONICAL_SUMMARY_JSON" ]]; then
  echo "missing or empty canonical summary json: $CANONICAL_SUMMARY_JSON"
  exit 1
fi
if ! cmp -s "$SUMMARY_JSON" "$CANONICAL_SUMMARY_JSON"; then
  echo "summary json and canonical summary json differ"
  cat "$SUMMARY_JSON"
  cat "$CANONICAL_SUMMARY_JSON"
  exit 1
fi

if ! jq -e --arg summary "$SUMMARY_JSON" --arg canonical "$CANONICAL_SUMMARY_JSON" '
  .version == 1
  and .schema.id == "ci_phase7_mainnet_cutover_summary"
  and (.schema.major | type) == "number"
  and (.schema.minor | type) == "number"
  and .status == "pass"
  and .rc == 0
  and (.steps | type) == "object"
  and (.steps.phase7_mainnet_cutover_check | type) == "object"
  and (.steps.phase7_mainnet_cutover_run | type) == "object"
  and (.steps.phase7_mainnet_cutover_handoff_check | type) == "object"
  and (.steps.phase7_mainnet_cutover_handoff_run | type) == "object"
  and (.steps.phase7_mainnet_cutover_summary_report | type) == "object"
  and (.steps.phase7_mainnet_cutover_live_smoke | type) == "object"
  and .steps.phase7_mainnet_cutover_check.status == "pass"
  and .steps.phase7_mainnet_cutover_run.status == "pass"
  and .steps.phase7_mainnet_cutover_handoff_check.status == "pass"
  and .steps.phase7_mainnet_cutover_handoff_run.status == "pass"
  and .steps.phase7_mainnet_cutover_summary_report.status == "pass"
  and .steps.phase7_mainnet_cutover_check.rc == 0
  and .steps.phase7_mainnet_cutover_run.rc == 0
  and .steps.phase7_mainnet_cutover_handoff_check.rc == 0
  and .steps.phase7_mainnet_cutover_handoff_run.rc == 0
  and .steps.phase7_mainnet_cutover_summary_report.rc == 0
  and .steps.phase7_mainnet_cutover_live_smoke.rc == 0
  and .artifacts.summary_json == $summary
  and .artifacts.canonical_summary_json == $canonical
  and (
    (
      .inputs.run_phase7_mainnet_cutover_live_smoke == false
      and .steps.phase7_mainnet_cutover_live_smoke.enabled == false
      and .steps.phase7_mainnet_cutover_live_smoke.status == "skip"
      and .steps.phase7_mainnet_cutover_live_smoke.command == null
      and .steps.phase7_mainnet_cutover_live_smoke.reason == "disabled"
    ) or (
      .inputs.run_phase7_mainnet_cutover_live_smoke == true
      and .steps.phase7_mainnet_cutover_live_smoke.enabled == true
      and .steps.phase7_mainnet_cutover_live_smoke.status == "pass"
      and (.steps.phase7_mainnet_cutover_live_smoke.command | contains("CI_PHASE7_MAINNET_CUTOVER_RUN_PHASE7_MAINNET_CUTOVER_LIVE_SMOKE=0"))
    )
  )
' "$SUMMARY_JSON" >/dev/null; then
  echo "phase7 mainnet cutover live-smoke summary validation failed"
  cat "$SUMMARY_JSON"
  exit 1
fi

echo "phase7 mainnet cutover live smoke integration check ok"
