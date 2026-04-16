#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp chmod wc sed cat jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${EASY_NODE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/easy_node.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

# Scope contract:
# - This integration validates only summary-report wrapper forwarding.
# - Gate-wrapper forwarding coverage belongs in:
#   scripts/integration_easy_node_blockchain_gate_wrappers.sh
# Keep gate-wrapper assertions out of this file to prevent scope drift.
GATE_WRAPPER_INTEGRATION_SCRIPT="$ROOT_DIR/scripts/integration_easy_node_blockchain_gate_wrappers.sh"
if [[ ! -x "$GATE_WRAPPER_INTEGRATION_SCRIPT" ]]; then
  echo "missing executable gate-wrapper integration companion: $GATE_WRAPPER_INTEGRATION_SCRIPT"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.tsv"
PHASE5_FAKE="$TMP_DIR/fake_phase5_summary_report.sh"
PHASE6_FAKE="$TMP_DIR/fake_phase6_summary_report.sh"
PHASE7_FAKE="$TMP_DIR/fake_phase7_summary_report.sh"

cat >"$PHASE5_FAKE" <<'EOF_PHASE5_FAKE'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${EASY_NODE_BLOCKCHAIN_SUMMARY_CAPTURE_FILE:?}"
{
  printf '%s' "phase5"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
EOF_PHASE5_FAKE
chmod +x "$PHASE5_FAKE"

cat >"$PHASE6_FAKE" <<'EOF_PHASE6_FAKE'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${EASY_NODE_BLOCKCHAIN_SUMMARY_CAPTURE_FILE:?}"
{
  printf '%s' "phase6"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
EOF_PHASE6_FAKE
chmod +x "$PHASE6_FAKE"

cat >"$PHASE7_FAKE" <<'EOF_PHASE7_FAKE'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${EASY_NODE_BLOCKCHAIN_SUMMARY_CAPTURE_FILE:?}"
{
  printf '%s' "phase7"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
EOF_PHASE7_FAKE
chmod +x "$PHASE7_FAKE"

assert_single_line_capture() {
  local capture_file="$1"
  local expected_prefix="$2"
  local count
  count="$(wc -l <"$capture_file" | tr -d ' ')"
  if [[ "$count" -ne 1 ]]; then
    echo "expected exactly one capture line for $expected_prefix, got $count"
    cat "$capture_file"
    exit 1
  fi
}

assert_phase5_capture() {
  local capture_file="$1"
  local reports_dir="$2"
  local summary_json="$3"
  local sample_value="$4"
  local line

  line="$(sed -n '1p' "$capture_file" || true)"
  IFS=$'\t' read -r marker a1 a2 a3 a4 a5 a6 a7 a8 <<<"$line"

  if [[ "$marker" != "phase5" ]]; then
    echo "phase5 marker mismatch"
    echo "$line"
    exit 1
  fi
  if [[ "$a1" != "--reports-dir" || "$a2" != "$reports_dir" ]]; then
    echo "phase5 --reports-dir forwarding mismatch"
    echo "$line"
    exit 1
  fi
  if [[ "$a3" != "--summary-json" || "$a4" != "$summary_json" ]]; then
    echo "phase5 --summary-json forwarding mismatch"
    echo "$line"
    exit 1
  fi
  if [[ "$a5" != "--print-summary-json" || "$a6" != "0" ]]; then
    echo "phase5 --print-summary-json forwarding mismatch"
    echo "$line"
    exit 1
  fi
  if [[ "$a7" != "--sample-arg" || "$a8" != "$sample_value" ]]; then
    echo "phase5 custom arg forwarding mismatch"
    echo "$line"
    exit 1
  fi
}

assert_phase6_capture() {
  local capture_file="$1"
  local reports_dir="$2"
  local summary_json="$3"
  local sample_value="$4"
  local line

  line="$(sed -n '1p' "$capture_file" || true)"
  IFS=$'\t' read -r marker a1 a2 a3 a4 a5 a6 a7 a8 <<<"$line"

  if [[ "$marker" != "phase6" ]]; then
    echo "phase6 marker mismatch"
    echo "$line"
    exit 1
  fi
  if [[ "$a1" != "--reports-dir" || "$a2" != "$reports_dir" ]]; then
    echo "phase6 --reports-dir forwarding mismatch"
    echo "$line"
    exit 1
  fi
  if [[ "$a3" != "--summary-json" || "$a4" != "$summary_json" ]]; then
    echo "phase6 --summary-json forwarding mismatch"
    echo "$line"
    exit 1
  fi
  if [[ "$a5" != "--print-summary-json" || "$a6" != "0" ]]; then
    echo "phase6 --print-summary-json forwarding mismatch"
    echo "$line"
    exit 1
  fi
  if [[ "$a7" != "--sample-arg" || "$a8" != "$sample_value" ]]; then
    echo "phase6 custom arg forwarding mismatch"
    echo "$line"
    exit 1
  fi
}

assert_phase7_capture() {
  local capture_file="$1"
  local reports_dir="$2"
  local summary_json="$3"
  local sample_value="$4"
  local line

  line="$(sed -n '1p' "$capture_file" || true)"
  IFS=$'\t' read -r marker a1 a2 a3 a4 a5 a6 a7 a8 <<<"$line"

  if [[ "$marker" != "phase7" ]]; then
    echo "phase7 marker mismatch"
    echo "$line"
    exit 1
  fi
  if [[ "$a1" != "--reports-dir" || "$a2" != "$reports_dir" ]]; then
    echo "phase7 --reports-dir forwarding mismatch"
    echo "$line"
    exit 1
  fi
  if [[ "$a3" != "--summary-json" || "$a4" != "$summary_json" ]]; then
    echo "phase7 --summary-json forwarding mismatch"
    echo "$line"
    exit 1
  fi
  if [[ "$a5" != "--print-summary-json" || "$a6" != "0" ]]; then
    echo "phase7 --print-summary-json forwarding mismatch"
    echo "$line"
    exit 1
  fi
  if [[ "$a7" != "--sample-arg" || "$a8" != "$sample_value" ]]; then
    echo "phase7 custom arg forwarding mismatch"
    echo "$line"
    exit 1
  fi
}

PHASE5_REPORTS_DIR="$TMP_DIR/reports phase5"
PHASE5_SUMMARY_JSON="$TMP_DIR/summary phase5.json"
PHASE5_SAMPLE_VALUE="alpha beta"

: >"$CAPTURE"
EASY_NODE_BLOCKCHAIN_SUMMARY_CAPTURE_FILE="$CAPTURE" \
PHASE5_SETTLEMENT_LAYER_SUMMARY_REPORT_SCRIPT="$PHASE5_FAKE" \
bash "$SCRIPT_UNDER_TEST" \
  phase5-settlement-layer-summary-report \
  --reports-dir "$PHASE5_REPORTS_DIR" \
  --summary-json "$PHASE5_SUMMARY_JSON" \
  --print-summary-json 0 \
  --sample-arg "$PHASE5_SAMPLE_VALUE" >/dev/null 2>&1

assert_single_line_capture "$CAPTURE" "phase5"
assert_phase5_capture "$CAPTURE" "$PHASE5_REPORTS_DIR" "$PHASE5_SUMMARY_JSON" "$PHASE5_SAMPLE_VALUE"

PHASE6_REPORTS_DIR="$TMP_DIR/reports phase6"
PHASE6_SUMMARY_JSON="$TMP_DIR/summary phase6.json"
PHASE6_SAMPLE_VALUE="gamma delta"

: >"$CAPTURE"
EASY_NODE_BLOCKCHAIN_SUMMARY_CAPTURE_FILE="$CAPTURE" \
PHASE6_COSMOS_L1_SUMMARY_REPORT_SCRIPT="$PHASE6_FAKE" \
bash "$SCRIPT_UNDER_TEST" \
  phase6-cosmos-l1-summary-report \
  --reports-dir "$PHASE6_REPORTS_DIR" \
  --summary-json "$PHASE6_SUMMARY_JSON" \
  --print-summary-json 0 \
  --sample-arg "$PHASE6_SAMPLE_VALUE" >/dev/null 2>&1

assert_single_line_capture "$CAPTURE" "phase6"
assert_phase6_capture "$CAPTURE" "$PHASE6_REPORTS_DIR" "$PHASE6_SUMMARY_JSON" "$PHASE6_SAMPLE_VALUE"

PHASE7_REPORTS_DIR="$TMP_DIR/reports phase7"
PHASE7_SUMMARY_JSON="$TMP_DIR/summary phase7.json"
PHASE7_SAMPLE_VALUE="epsilon zeta"

: >"$CAPTURE"
EASY_NODE_BLOCKCHAIN_SUMMARY_CAPTURE_FILE="$CAPTURE" \
PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_SCRIPT="$PHASE7_FAKE" \
bash "$SCRIPT_UNDER_TEST" \
  phase7-mainnet-cutover-summary-report \
  --reports-dir "$PHASE7_REPORTS_DIR" \
  --summary-json "$PHASE7_SUMMARY_JSON" \
  --print-summary-json 0 \
  --sample-arg "$PHASE7_SAMPLE_VALUE" >/dev/null 2>&1

assert_single_line_capture "$CAPTURE" "phase7"
assert_phase7_capture "$CAPTURE" "$PHASE7_REPORTS_DIR" "$PHASE7_SUMMARY_JSON" "$PHASE7_SAMPLE_VALUE"

PHASE5_REAL_SUMMARY_SCRIPT="${PHASE5_SETTLEMENT_LAYER_SUMMARY_REPORT_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase5_settlement_layer_summary_report.sh}"
if [[ ! -x "$PHASE5_REAL_SUMMARY_SCRIPT" ]]; then
  echo "missing executable phase5 summary report script: $PHASE5_REAL_SUMMARY_SCRIPT"
  exit 2
fi

PHASE5_REAL_HANDOFF_CHECK="$TMP_DIR/phase5_handoff_check_with_sponsor.json"
PHASE5_REAL_AGG_SUMMARY="$TMP_DIR/phase5_aggregated_summary.json"
PHASE5_REAL_LOG="$TMP_DIR/phase5_aggregated.log"

cat >"$PHASE5_REAL_HANDOFF_CHECK" <<'EOF_PHASE5_REAL_HANDOFF_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "issuer_sponsor_api_live_smoke": {
      "status": "pass"
    }
  }
}
EOF_PHASE5_REAL_HANDOFF_CHECK

PHASE5_SETTLEMENT_LAYER_SUMMARY_REPORT_SCRIPT="$PHASE5_REAL_SUMMARY_SCRIPT" \
bash "$SCRIPT_UNDER_TEST" \
  phase5-settlement-layer-summary-report \
  --handoff-check-summary-json "$PHASE5_REAL_HANDOFF_CHECK" \
  --summary-json "$PHASE5_REAL_AGG_SUMMARY" \
  --print-summary-json 0 >"$PHASE5_REAL_LOG" 2>&1

if [[ ! -f "$PHASE5_REAL_AGG_SUMMARY" ]]; then
  echo "missing phase5 aggregated summary output"
  cat "$PHASE5_REAL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .summaries.phase5_settlement_layer_handoff_check_summary.status == "pass"
  and .signals.issuer_sponsor_api_live_smoke.status == "pass"
  and .signals.issuer_sponsor_api_live_smoke.ok == true
  and .signals.issuer_sponsor_api_live_smoke.resolved == true
  and .signals.issuer_sponsor_api_live_smoke.source == "phase5_settlement_layer_handoff_check_summary"
' "$PHASE5_REAL_AGG_SUMMARY" >/dev/null; then
  echo "phase5 aggregated summary missing sponsor live-smoke signal/health contract fields"
  cat "$PHASE5_REAL_AGG_SUMMARY"
  cat "$PHASE5_REAL_LOG"
  exit 1
fi

PHASE7_REAL_SUMMARY_SCRIPT="${PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase7_mainnet_cutover_summary_report.sh}"
if [[ ! -x "$PHASE7_REAL_SUMMARY_SCRIPT" ]]; then
  echo "missing executable phase7 summary report script: $PHASE7_REAL_SUMMARY_SCRIPT"
  exit 2
fi

PHASE7_REAL_CHECK="$TMP_DIR/phase7_check_with_signals.json"
PHASE7_REAL_RUN="$TMP_DIR/phase7_run_with_signals.json"
PHASE7_REAL_AGG_SUMMARY="$TMP_DIR/phase7_aggregated_summary.json"
PHASE7_REAL_LOG="$TMP_DIR/phase7_aggregated.log"

cat >"$PHASE7_REAL_CHECK" <<'EOF_PHASE7_REAL_CHECK'
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
    "module_tx_surface_ok": true,
    "tdpnd_grpc_auth_live_smoke_ok": true,
    "tdpnd_comet_runtime_smoke_ok": true,
    "rollback_path_ready": true,
    "operator_approval_ok": true
  }
}
EOF_PHASE7_REAL_CHECK

cat >"$PHASE7_REAL_RUN" <<'EOF_PHASE7_REAL_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "phase7_mainnet_cutover_check": {
      "signal_snapshot": {
        "module_tx_surface_ok": true,
        "tdpnd_grpc_auth_live_smoke_ok": true,
        "tdpnd_comet_runtime_smoke_ok": true,
        "dual_write_parity_ok": true,
        "rollback_path_ready": true,
        "operator_approval_ok": true
      }
    }
  }
}
EOF_PHASE7_REAL_RUN

if ! jq -e '
  .signals.module_tx_surface_ok == true
  and .signals.tdpnd_grpc_auth_live_smoke_ok == true
  and .signals.rollback_path_ready == true
  and .signals.operator_approval_ok == true
' "$PHASE7_REAL_CHECK" >/dev/null; then
  echo "phase7 check fixture missing required key-signal fields"
  cat "$PHASE7_REAL_CHECK"
  exit 1
fi
if ! jq -e '
  .steps.phase7_mainnet_cutover_check.signal_snapshot.module_tx_surface_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.tdpnd_grpc_auth_live_smoke_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.dual_write_parity_ok == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.rollback_path_ready == true
  and .steps.phase7_mainnet_cutover_check.signal_snapshot.operator_approval_ok == true
' "$PHASE7_REAL_RUN" >/dev/null; then
  echo "phase7 run fixture missing required key-signal snapshot fields"
  cat "$PHASE7_REAL_RUN"
  exit 1
fi

PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_SCRIPT="$PHASE7_REAL_SUMMARY_SCRIPT" \
bash "$SCRIPT_UNDER_TEST" \
  phase7-mainnet-cutover-summary-report \
  --check-summary-json "$PHASE7_REAL_CHECK" \
  --run-summary-json "$PHASE7_REAL_RUN" \
  --summary-json "$PHASE7_REAL_AGG_SUMMARY" \
  --print-report 1 \
  --show-json 0 >"$PHASE7_REAL_LOG" 2>&1

if [[ ! -f "$PHASE7_REAL_AGG_SUMMARY" ]]; then
  echo "missing phase7 aggregated summary output"
  cat "$PHASE7_REAL_LOG"
  exit 1
fi
if ! jq -e \
  --arg expected_check "$PHASE7_REAL_CHECK" \
  --arg expected_run "$PHASE7_REAL_RUN" \
  --arg expected_summary "$PHASE7_REAL_AGG_SUMMARY" \
  '
  .status == "pass"
  and .rc == 0
  and .counts.configured == 2
  and .counts.pass == 2
  and .counts.fail == 0
  and .counts.missing == 0
  and .counts.invalid == 0
  and .summaries.check.status == "pass"
  and .summaries.check.source_kind == "explicit"
  and .summaries.check.source_path == $expected_check
  and .summaries.check.raw_status == "pass"
  and .summaries.check.raw_rc == 0
  and .summaries.check.signal_snapshot.tdpnd_comet_runtime_smoke_ok == true
  and .summaries.run.status == "pass"
  and .summaries.run.source_kind == "explicit"
  and .summaries.run.source_path == $expected_run
  and .summaries.run.raw_status == "pass"
  and .summaries.run.raw_rc == 0
  and .summaries.run.signal_snapshot.tdpnd_comet_runtime_smoke_ok == true
  and .decision.pass == true
  and .artifacts.summary_json == $expected_summary
' "$PHASE7_REAL_AGG_SUMMARY" >/dev/null; then
  echo "phase7 aggregated summary missing expected output contract fields"
  cat "$PHASE7_REAL_AGG_SUMMARY"
  cat "$PHASE7_REAL_LOG"
  exit 1
fi

echo "easy-node blockchain summary-report wrapper integration ok"
