#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp grep cat cmp cp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${BLOCKCHAIN_MAINNET_ACTIVATION_METRICS_MISSING_INPUT_TEMPLATE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/blockchain_mainnet_activation_metrics_missing_input_template.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
DEFAULT_OUTPUT="$ROOT_DIR/.easy-node-logs/blockchain_mainnet_activation_metrics_missing_input_template.json"
DEFAULT_BACKUP="$TMP_DIR/default_output_backup.json"
DEFAULT_HAD_FILE="0"

cleanup() {
  if [[ "$DEFAULT_HAD_FILE" == "1" ]]; then
    cp "$DEFAULT_BACKUP" "$DEFAULT_OUTPUT"
  else
    rm -f "$DEFAULT_OUTPUT"
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

if [[ -f "$DEFAULT_OUTPUT" ]]; then
  cp "$DEFAULT_OUTPUT" "$DEFAULT_BACKUP"
  DEFAULT_HAD_FILE="1"
fi

HELP_LOG="$TMP_DIR/help.log"
VALIDATION_LOG="$TMP_DIR/validation.log"
DEFAULT_LOG="$TMP_DIR/default.log"
DEFAULT_SNAPSHOT="$TMP_DIR/default_snapshot.json"
EXPLICIT_LOG="$TMP_DIR/explicit.log"
SAME_PATH_LOG="$TMP_DIR/same_path.log"
MISSING_LOG="$TMP_DIR/missing.log"
EXAMPLES_LOG="$TMP_DIR/examples.log"
MISSING_FILE_LOG="$TMP_DIR/missing_file.log"
INVALID_LOG="$TMP_DIR/invalid.log"

COMPLETE_INPUT_JSON="$TMP_DIR/complete_metrics_summary.json"
MISSING_INPUT_JSON="$TMP_DIR/missing_metrics_summary.json"
MISSING_FILE_INPUT_JSON="$TMP_DIR/does_not_exist_metrics_summary.json"
INVALID_INPUT_JSON="$TMP_DIR/invalid_metrics_summary.json"

EXPLICIT_OUTPUT="$TMP_DIR/template_output.json"
EXPLICIT_CANONICAL="$TMP_DIR/template_canonical.json"
SAME_PATH_OUTPUT="$TMP_DIR/template_same_path.json"
MISSING_OUTPUT="$TMP_DIR/template_missing.json"
EXAMPLES_OUTPUT="$TMP_DIR/template_examples.json"
MISSING_FILE_OUTPUT="$TMP_DIR/template_missing_file.json"
INVALID_OUTPUT="$TMP_DIR/template_invalid_input.json"
DETERMINISTIC_SNAPSHOT="$TMP_DIR/deterministic_snapshot.json"

cat >"$COMPLETE_INPUT_JSON" <<'EOF_COMPLETE_INPUT'
{
  "version": 1,
  "schema": {"id": "blockchain_mainnet_activation_metrics_summary", "major": 1, "minor": 0},
  "status": "complete",
  "required_missing_metrics": [],
  "counts": {"required": 15, "provided": 15, "missing": 0, "invalid": 0}
}
EOF_COMPLETE_INPUT

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

cat >"$INVALID_INPUT_JSON" <<'EOF_INVALID_INPUT'
{
  "schema": {"id": "broken"
EOF_INVALID_INPUT

echo "[blockchain-mainnet-activation-metrics-missing-input-template] help surface"
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
if ! grep -Fq -- "--canonical-output-json" "$HELP_LOG"; then
  echo "help output missing --canonical-output-json"
  cat "$HELP_LOG"
  exit 1
fi
if ! grep -Fq -- "--include-example-values" "$HELP_LOG"; then
  echo "help output missing --include-example-values"
  cat "$HELP_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics-missing-input-template] required arg validation"
set +e
bash "$SCRIPT_UNDER_TEST" --output-json "$TMP_DIR/should_not_exist.json" >"$VALIDATION_LOG" 2>&1
validation_rc=$?
set -e
if [[ "$validation_rc" -ne 2 ]]; then
  echo "expected missing --metrics-summary-json to return rc=2"
  cat "$VALIDATION_LOG"
  exit 1
fi
if ! grep -Fq -- "--metrics-summary-json is required" "$VALIDATION_LOG"; then
  echo "validation output missing required-arg message"
  cat "$VALIDATION_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics-missing-input-template] default path contract"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --metrics-summary-json "$COMPLETE_INPUT_JSON" \
  --print-output-json 0 >"$DEFAULT_LOG" 2>&1
default_rc=$?
set -e
if [[ "$default_rc" -ne 0 ]]; then
  echo "default path should exit 0"
  cat "$DEFAULT_LOG"
  exit 1
fi
if [[ ! -f "$DEFAULT_OUTPUT" ]]; then
  echo "default output file missing: $DEFAULT_OUTPUT"
  cat "$DEFAULT_LOG"
  exit 1
fi
if ! jq -e \
  --arg expected "$DEFAULT_OUTPUT" \
  '
  .version == 1
  and .schema.id == "blockchain_mainnet_activation_metrics_missing_input_template"
  and .status == "complete"
  and .rc == 0
  and .include_example_values == false
  and .missing_count == 0
  and (.missing_keys | length) == 0
  and (.template | length) == 0
  and (.general | length) == 0
  and (.reliability | length) == 0
  and (.demand | length) == 0
  and (.validator | length) == 0
  and (.governance | length) == 0
  and (.economics | length) == 0
  and .artifacts.output_json == $expected
  and .artifacts.canonical_output_json == $expected
  ' "$DEFAULT_OUTPUT" >/dev/null; then
  echo "default path contract mismatch"
  cat "$DEFAULT_OUTPUT"
  cat "$DEFAULT_LOG"
  exit 1
fi

cp "$DEFAULT_OUTPUT" "$DEFAULT_SNAPSHOT"
bash "$SCRIPT_UNDER_TEST" \
  --metrics-summary-json "$COMPLETE_INPUT_JSON" \
  --print-output-json 0 >/dev/null 2>&1
if ! cmp -s "$DEFAULT_SNAPSHOT" "$DEFAULT_OUTPUT"; then
  echo "default output is not deterministic across runs"
  cat "$DEFAULT_SNAPSHOT"
  cat "$DEFAULT_OUTPUT"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics-missing-input-template] explicit output + canonical paths"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --metrics-summary-json "$COMPLETE_INPUT_JSON" \
  --output-json "$EXPLICIT_OUTPUT" \
  --canonical-output-json "$EXPLICIT_CANONICAL" \
  --print-output-json 0 >"$EXPLICIT_LOG" 2>&1
explicit_rc=$?
set -e
if [[ "$explicit_rc" -ne 0 ]]; then
  echo "explicit path run must exit 0"
  cat "$EXPLICIT_LOG"
  exit 1
fi
if [[ ! -f "$EXPLICIT_OUTPUT" || ! -f "$EXPLICIT_CANONICAL" ]]; then
  echo "explicit output/canonical artifacts missing"
  cat "$EXPLICIT_LOG"
  exit 1
fi
if ! cmp -s "$EXPLICIT_OUTPUT" "$EXPLICIT_CANONICAL"; then
  echo "explicit output/canonical mismatch"
  cat "$EXPLICIT_OUTPUT"
  cat "$EXPLICIT_CANONICAL"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics-missing-input-template] canonical same-path support"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --metrics-summary-json "$COMPLETE_INPUT_JSON" \
  --output-json "$SAME_PATH_OUTPUT" \
  --canonical-output-json "$SAME_PATH_OUTPUT" \
  --print-output-json 0 >"$SAME_PATH_LOG" 2>&1
same_path_rc=$?
set -e
if [[ "$same_path_rc" -ne 0 ]]; then
  echo "same-path run must exit 0"
  cat "$SAME_PATH_LOG"
  exit 1
fi
if [[ ! -f "$SAME_PATH_OUTPUT" ]]; then
  echo "same-path output missing"
  cat "$SAME_PATH_LOG"
  exit 1
fi
if ! jq -e \
  --arg expected "$SAME_PATH_OUTPUT" \
  '.artifacts.output_json == $expected and .artifacts.canonical_output_json == $expected' \
  "$SAME_PATH_OUTPUT" >/dev/null; then
  echo "same-path artifacts metadata mismatch"
  cat "$SAME_PATH_OUTPUT"
  cat "$SAME_PATH_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics-missing-input-template] missing-keys template path"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --metrics-summary-json "$MISSING_INPUT_JSON" \
  --output-json "$MISSING_OUTPUT" \
  --print-output-json 0 >"$MISSING_LOG" 2>&1
missing_rc=$?
set -e
if [[ "$missing_rc" -ne 0 ]]; then
  echo "missing-keys path must remain fail-soft and exit 0"
  cat "$MISSING_LOG"
  exit 1
fi
if ! jq -e '
  .status == "missing"
  and .rc == 0
  and .include_example_values == false
  and .input.state == "available"
  and .input.valid == true
  and .input.source_schema_id == "blockchain_gate_bundle_summary"
  and .missing_count == 2
  and .missing_keys == ["paying_users_3mo_min", "validator_country_count"]
  and (.template | keys) == ["paying_users_3mo_min", "validator_country_count"]
  and .template.paying_users_3mo_min == null
  and .template.validator_country_count == null
  and (.demand | keys) == ["paying_users_3mo_min"]
  and (.validator | keys) == ["validator_country_count"]
  and (.general | length) == 0
  and (.reliability | length) == 0
  and (.governance | length) == 0
  and (.economics | length) == 0
' "$MISSING_OUTPUT" >/dev/null; then
  echo "missing-keys contract mismatch"
  cat "$MISSING_OUTPUT"
  cat "$MISSING_LOG"
  exit 1
fi

cp "$MISSING_OUTPUT" "$DETERMINISTIC_SNAPSHOT"
bash "$SCRIPT_UNDER_TEST" \
  --metrics-summary-json "$MISSING_INPUT_JSON" \
  --output-json "$MISSING_OUTPUT" \
  --print-output-json 0 >/dev/null 2>&1
if ! cmp -s "$DETERMINISTIC_SNAPSHOT" "$MISSING_OUTPUT"; then
  echo "missing-keys output is not deterministic across runs"
  cat "$DETERMINISTIC_SNAPSHOT"
  cat "$MISSING_OUTPUT"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics-missing-input-template] include-example-values toggle"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --metrics-summary-json "$MISSING_INPUT_JSON" \
  --output-json "$EXAMPLES_OUTPUT" \
  --include-example-values 1 \
  --print-output-json 1 >"$EXAMPLES_LOG" 2>&1
examples_rc=$?
set -e
if [[ "$examples_rc" -ne 0 ]]; then
  echo "example-values path must exit 0"
  cat "$EXAMPLES_LOG"
  exit 1
fi
if ! grep -Fq '"include_example_values": true' "$EXAMPLES_LOG"; then
  echo "print-output-json did not emit expected JSON payload"
  cat "$EXAMPLES_LOG"
  exit 1
fi
if ! jq -e '
  .status == "missing"
  and .include_example_values == true
  and .missing_count == 2
  and .template.paying_users_3mo_min == 1650
  and .template.validator_country_count == 9
  and .demand.paying_users_3mo_min == 1650
  and .validator.validator_country_count == 9
' "$EXAMPLES_OUTPUT" >/dev/null; then
  echo "example-values contract mismatch"
  cat "$EXAMPLES_OUTPUT"
  cat "$EXAMPLES_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics-missing-input-template] missing input summary fail-soft"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --metrics-summary-json "$MISSING_FILE_INPUT_JSON" \
  --output-json "$MISSING_FILE_OUTPUT" \
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
  and .missing_count == 15
  and (.missing_keys | length) == 15
  and (.template | length) == 15
  and ((.missing_keys | index("measurement_window_weeks")) != null)
  and ((.missing_keys | index("vpn_connect_session_success_slo_pct")) != null)
  and ((.missing_keys | index("contribution_margin_3mo")) != null)
' "$MISSING_FILE_OUTPUT" >/dev/null; then
  echo "missing input summary fail-soft contract mismatch"
  cat "$MISSING_FILE_OUTPUT"
  cat "$MISSING_FILE_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-metrics-missing-input-template] invalid input summary fail-soft"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --metrics-summary-json "$INVALID_INPUT_JSON" \
  --output-json "$INVALID_OUTPUT" \
  --print-output-json 0 >"$INVALID_LOG" 2>&1
invalid_rc=$?
set -e
if [[ "$invalid_rc" -ne 0 ]]; then
  echo "invalid input summary path must remain fail-soft and exit 0"
  cat "$INVALID_LOG"
  exit 1
fi
if ! jq -e '
  .status == "missing"
  and .input.state == "invalid"
  and .input.valid == false
  and .missing_count == 15
  and (.missing_keys | length) == 15
  and (.template | length) == 15
  and ((.missing_keys | index("measurement_window_weeks")) != null)
' "$INVALID_OUTPUT" >/dev/null; then
  echo "invalid input summary fail-soft contract mismatch"
  cat "$INVALID_OUTPUT"
  cat "$INVALID_LOG"
  exit 1
fi

echo "blockchain mainnet activation metrics missing input template integration ok"
