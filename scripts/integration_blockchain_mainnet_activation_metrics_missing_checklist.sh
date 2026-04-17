#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp grep cat cmp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_MISSING_CHECKLIST_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics_missing_checklist.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

HELP_LOG="$TMP_DIR/help.log"
VALIDATION_LOG="$TMP_DIR/validation.log"
COMPLETE_INPUT_JSON="$TMP_DIR/complete_metrics_summary.json"
COMPLETE_OUTPUT_JSON="$TMP_DIR/complete_checklist.json"
COMPLETE_LOG="$TMP_DIR/complete.log"
ALIAS_OUTPUT_JSON="$TMP_DIR/alias_checklist.json"
ALIAS_LOG="$TMP_DIR/alias.log"
MISSING_INPUT_JSON="$TMP_DIR/missing_metrics_from_bundle_summary.json"
MISSING_OUTPUT_JSON="$TMP_DIR/missing_checklist.json"
MISSING_OUTPUT_MD="$TMP_DIR/missing_checklist.md"
MISSING_LOG="$TMP_DIR/missing.log"
MISSING_FILE_INPUT_JSON="$TMP_DIR/does_not_exist_metrics_summary.json"
MISSING_FILE_OUTPUT_JSON="$TMP_DIR/missing_file_checklist.json"
MISSING_FILE_LOG="$TMP_DIR/missing_file.log"
DETERMINISTIC_SNAPSHOT_JSON="$TMP_DIR/deterministic_snapshot.json"

echo "[blockchain-mainnet-activation-metrics-missing-checklist] help surface"
bash "$SCRIPT_UNDER_TEST" --help >"$HELP_LOG" 2>&1
if ! grep -Fq "Usage:" "$HELP_LOG"; then
  echo "help output missing Usage header"
  cat "$HELP_LOG"
  exit 1
fi
if ! grep -Fq -- "--metrics-summary-json" "$HELP_LOG"; then
  echo "help output missing --metrics-summary-json"
  cat "$HELP_LOG"
  exit 1
fi
if ! grep -Fq -- "--output-json" "$HELP_LOG"; then
  echo "help output missing --output-json"
  cat "$HELP_LOG"
  exit 1
fi
if ! grep -Fq -- "--output-md" "$HELP_LOG"; then
  echo "help output missing --output-md"
  cat "$HELP_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics-missing-checklist] required arg validation"
set +e
bash "$SCRIPT_UNDER_TEST" --output-json "$TMP_DIR/invalid_should_not_exist.json" >"$VALIDATION_LOG" 2>&1
validation_rc=$?
set -e
if [[ "$validation_rc" -ne 2 ]]; then
  echo "expected missing --metrics-summary-json to return rc=2"
  cat "$VALIDATION_LOG"
  exit 1
fi
if ! grep -Fq -- "--metrics-summary-json is required" "$VALIDATION_LOG"; then
  echo "validation log missing required-arg message"
  cat "$VALIDATION_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics-missing-checklist] complete path"
cat >"$COMPLETE_INPUT_JSON" <<'EOF_COMPLETE_INPUT'
{
  "version": 1,
  "schema": {"id": "blockchain_mainnet_activation_metrics_summary", "major": 1, "minor": 0},
  "status": "complete",
  "required_missing_metrics": [],
  "counts": {"required": 15, "provided": 15, "missing": 0, "invalid": 0}
}
EOF_COMPLETE_INPUT

set +e
bash "$SCRIPT_UNDER_TEST" \
  --metrics-summary-json "$COMPLETE_INPUT_JSON" \
  --output-json "$COMPLETE_OUTPUT_JSON" \
  --print-output-json 1 >"$COMPLETE_LOG" 2>&1
complete_rc=$?
set -e
if [[ "$complete_rc" -ne 0 ]]; then
  echo "complete path must stay fail-soft and exit 0"
  cat "$COMPLETE_LOG"
  exit 1
fi
if [[ ! -f "$COMPLETE_OUTPUT_JSON" ]]; then
  echo "complete path output artifact missing"
  cat "$COMPLETE_LOG"
  exit 1
fi
if ! jq -e \
  --arg metrics_summary_json "$COMPLETE_INPUT_JSON" \
  --arg output_json "$COMPLETE_OUTPUT_JSON" \
  '
  .version == 1
  and .schema.id == "blockchain_mainnet_activation_metrics_missing_checklist"
  and .status == "complete"
  and .rc == 0
  and .input.metrics_summary_json == $metrics_summary_json
  and .input.state == "available"
  and .input.valid == true
  and .counts.required_expected == 15
  and .counts.missing == 0
  and .counts.checklist_entries == 0
  and (.missing_metric_keys | length) == 0
  and (.checklist | length) == 0
  and .artifacts.output_json == $output_json
  and .artifacts.output_md == null
  ' "$COMPLETE_OUTPUT_JSON" >/dev/null; then
  echo "complete path contract mismatch"
  cat "$COMPLETE_OUTPUT_JSON"
  cat "$COMPLETE_LOG"
  exit 1
fi
if ! grep -Fq '"status": "complete"' "$COMPLETE_LOG"; then
  echo "print-output-json did not emit complete JSON"
  cat "$COMPLETE_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics-missing-checklist] --print-summary-json alias compatibility"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --metrics-summary-json "$COMPLETE_INPUT_JSON" \
  --output-json "$ALIAS_OUTPUT_JSON" \
  --print-summary-json 0 >"$ALIAS_LOG" 2>&1
alias_rc=$?
set -e
if [[ "$alias_rc" -ne 0 ]]; then
  echo "print-summary-json alias path must exit 0"
  cat "$ALIAS_LOG"
  exit 1
fi
if [[ ! -f "$ALIAS_OUTPUT_JSON" ]]; then
  echo "alias output artifact missing"
  cat "$ALIAS_LOG"
  exit 1
fi
if ! jq -e '.status == "complete" and .counts.missing == 0' "$ALIAS_OUTPUT_JSON" >/dev/null; then
  echo "alias output contract mismatch"
  cat "$ALIAS_OUTPUT_JSON"
  cat "$ALIAS_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics-missing-checklist] missing path from gate bundle summary"
cat >"$MISSING_INPUT_JSON" <<'EOF_MISSING_INPUT'
{
  "schema": {"id": "blockchain_gate_bundle_summary", "version": "1.0.0"},
  "status": "pass",
  "decision": "NO-GO",
  "missing_required_metrics": [
    "paying_users_3mo_min",
    "validator_country_count"
  ]
}
EOF_MISSING_INPUT

set +e
bash "$SCRIPT_UNDER_TEST" \
  --metrics-summary-json "$MISSING_INPUT_JSON" \
  --output-json "$MISSING_OUTPUT_JSON" \
  --output-md "$MISSING_OUTPUT_MD" \
  --print-output-json 0 >"$MISSING_LOG" 2>&1
missing_rc=$?
set -e
if [[ "$missing_rc" -ne 0 ]]; then
  echo "missing path must remain fail-soft and exit 0"
  cat "$MISSING_LOG"
  exit 1
fi
if [[ ! -f "$MISSING_OUTPUT_JSON" || ! -f "$MISSING_OUTPUT_MD" ]]; then
  echo "missing path artifacts missing"
  ls -la "$TMP_DIR"
  cat "$MISSING_LOG"
  exit 1
fi
if ! jq -e '
  .status == "missing"
  and .rc == 0
  and .input.state == "available"
  and .input.valid == true
  and .input.source_schema_id == "blockchain_gate_bundle_summary"
  and .counts.required_expected == 15
  and .counts.missing == 2
  and .counts.checklist_entries == 2
  and .missing_metric_keys == ["paying_users_3mo_min", "validator_country_count"]
  and (.checklist | length) == 2
  and .checklist[0].key == "paying_users_3mo_min"
  and .checklist[0].category == "Demand"
  and .checklist[0].comparator == ">="
  and .checklist[0].threshold == "1000"
  and .checklist[0].unit == "clients"
  and (.checklist[0].hint | contains("3-month active paying-user floor"))
  and .checklist[1].key == "validator_country_count"
  and .checklist[1].category == "Validator decentralization"
  and .checklist[1].comparator == ">="
  and .checklist[1].threshold == "8"
  and .checklist[1].unit == "countries"
' "$MISSING_OUTPUT_JSON" >/dev/null; then
  echo "missing path contract mismatch"
  cat "$MISSING_OUTPUT_JSON"
  cat "$MISSING_LOG"
  exit 1
fi
if ! grep -Fq '| paying_users_3mo_min | Demand | >= | 1000 | clients |' "$MISSING_OUTPUT_MD"; then
  echo "missing checklist markdown row for paying_users_3mo_min"
  cat "$MISSING_OUTPUT_MD"
  exit 1
fi
if ! grep -Fq '| validator_country_count | Validator decentralization | >= | 8 | countries |' "$MISSING_OUTPUT_MD"; then
  echo "missing checklist markdown row for validator_country_count"
  cat "$MISSING_OUTPUT_MD"
  exit 1
fi

cp "$MISSING_OUTPUT_JSON" "$DETERMINISTIC_SNAPSHOT_JSON"
bash "$SCRIPT_UNDER_TEST" \
  --metrics-summary-json "$MISSING_INPUT_JSON" \
  --output-json "$MISSING_OUTPUT_JSON" \
  --output-md "$MISSING_OUTPUT_MD" \
  --print-output-json 0 >/dev/null 2>&1
if ! cmp -s "$DETERMINISTIC_SNAPSHOT_JSON" "$MISSING_OUTPUT_JSON"; then
  echo "missing checklist output is not deterministic across runs"
  cat "$DETERMINISTIC_SNAPSHOT_JSON"
  cat "$MISSING_OUTPUT_JSON"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics-missing-checklist] missing input summary remains fail-soft"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --metrics-summary-json "$MISSING_FILE_INPUT_JSON" \
  --output-json "$MISSING_FILE_OUTPUT_JSON" \
  --print-output-json 0 >"$MISSING_FILE_LOG" 2>&1
missing_file_rc=$?
set -e
if [[ "$missing_file_rc" -ne 0 ]]; then
  echo "missing input summary path must remain fail-soft and exit 0"
  cat "$MISSING_FILE_LOG"
  exit 1
fi
if ! jq -e '
  .status == "missing"
  and .input.state == "missing"
  and .input.valid == false
  and .counts.required_expected == 15
  and .counts.missing == 15
  and (.checklist | length) == 15
  and ((.missing_metric_keys | index("measurement_window_weeks")) != null)
  and ((.missing_metric_keys | index("vpn_connect_session_success_slo_pct")) != null)
  and ((.missing_metric_keys | index("contribution_margin_3mo")) != null)
' "$MISSING_FILE_OUTPUT_JSON" >/dev/null; then
  echo "missing input summary fallback contract mismatch"
  cat "$MISSING_FILE_OUTPUT_JSON"
  cat "$MISSING_FILE_LOG"
  exit 1
fi

echo "blockchain mainnet activation metrics missing checklist integration ok"
