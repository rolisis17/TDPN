#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp grep cat awk sed chmod cmp wc tr; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/blockchain_mainnet_activation_operator_pack.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/stage_calls.tsv"

HELP_LOG="$TMP_DIR/help.log"

TEMPLATE_ONLY_REPORTS_DIR="$TMP_DIR/reports_template_only"
TEMPLATE_ONLY_SUMMARY_JSON="$TMP_DIR/template_only_summary.json"
TEMPLATE_ONLY_CANONICAL_SUMMARY_JSON="$TMP_DIR/template_only_summary_canonical.json"
TEMPLATE_ONLY_TEMPLATE_OUTPUT_JSON="$TEMPLATE_ONLY_REPORTS_DIR/blockchain_mainnet_activation_metrics_input_template.json"
TEMPLATE_ONLY_TEMPLATE_CANONICAL_JSON="$TEMPLATE_ONLY_REPORTS_DIR/blockchain_mainnet_activation_metrics_input_template.canonical.json"
TEMPLATE_ONLY_LOG="$TMP_DIR/template_only.log"

WITH_METRICS_REPORTS_DIR="$TMP_DIR/reports_with_metrics"
WITH_METRICS_SUMMARY_JSON="$TMP_DIR/with_metrics_summary.json"
WITH_METRICS_CANONICAL_SUMMARY_JSON="$TMP_DIR/with_metrics_summary_canonical.json"
WITH_METRICS_INPUT_SUMMARY_JSON="$TMP_DIR/metrics_summary_input.json"
WITH_METRICS_CHECKLIST_OUTPUT_JSON="$TMP_DIR/with_metrics_checklist.json"
WITH_METRICS_CHECKLIST_OUTPUT_MD="$TMP_DIR/with_metrics_checklist.md"
WITH_METRICS_LOG="$TMP_DIR/with_metrics.log"

MISSING_METRICS_REPORTS_DIR="$TMP_DIR/reports_missing_metrics"
MISSING_METRICS_SUMMARY_JSON="$TMP_DIR/missing_metrics_summary.json"
MISSING_METRICS_CANONICAL_SUMMARY_JSON="$TMP_DIR/missing_metrics_summary_canonical.json"
MISSING_METRICS_INPUT_SUMMARY_JSON="$TMP_DIR/does_not_exist_metrics_summary.json"
MISSING_METRICS_CHECKLIST_OUTPUT_JSON="$TMP_DIR/missing_metrics_checklist_should_not_exist.json"
MISSING_METRICS_CHECKLIST_OUTPUT_MD="$TMP_DIR/missing_metrics_checklist_should_not_exist.md"
MISSING_METRICS_LOG="$TMP_DIR/missing_metrics.log"

FAKE_TEMPLATE="$TMP_DIR/fake_template.sh"
cat >"$FAKE_TEMPLATE" <<'EOF_FAKE_TEMPLATE'
#!/usr/bin/env bash
set -euo pipefail

capture="${BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_CAPTURE_FILE:?}"
all_args=("$@")
{
  printf '%s' "template"
  for arg in "${all_args[@]}"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture"

output_json=""
canonical_output_json=""
include_example_values="0"
print_output_json="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-json)
      output_json="${2:-}"
      shift 2
      ;;
    --canonical-output-json)
      canonical_output_json="${2:-}"
      shift 2
      ;;
    --include-example-values)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        include_example_values="${2:-}"
        shift 2
      else
        include_example_values="1"
        shift
      fi
      ;;
    --print-output-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_output_json="${2:-}"
        shift 2
      else
        print_output_json="1"
        shift
      fi
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$output_json" || -z "$canonical_output_json" ]]; then
  echo "fake template missing required output paths"
  exit 7
fi

mkdir -p "$(dirname "$output_json")" "$(dirname "$canonical_output_json")"

jq -n \
  --arg output_json "$output_json" \
  --arg canonical_output_json "$canonical_output_json" \
  --argjson include_example_values "$( [[ "$include_example_values" == "1" ]] && echo true || echo false )" \
  '{
    schema: {id: "fake_blockchain_mainnet_activation_metrics_input_template", version: "1.0.0"},
    status: "ok",
    include_example_values: $include_example_values,
    artifacts: {
      output_json: $output_json,
      canonical_output_json: $canonical_output_json
    }
  }' >"$output_json"

if [[ "$canonical_output_json" == "$output_json" ]]; then
  :
else
  cp -f "$output_json" "$canonical_output_json"
fi

if [[ "$print_output_json" == "1" ]]; then
  cat "$output_json"
fi

template_rc="${BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_FAKE_TEMPLATE_RC:-0}"
if [[ "$template_rc" =~ ^-?[0-9]+$ ]]; then
  exit "$template_rc"
fi
exit 0
EOF_FAKE_TEMPLATE
chmod +x "$FAKE_TEMPLATE"

FAKE_CHECKLIST="$TMP_DIR/fake_checklist.sh"
cat >"$FAKE_CHECKLIST" <<'EOF_FAKE_CHECKLIST'
#!/usr/bin/env bash
set -euo pipefail

capture="${BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_CAPTURE_FILE:?}"
all_args=("$@")
{
  printf '%s' "checklist"
  for arg in "${all_args[@]}"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture"

metrics_summary_json=""
output_json=""
output_md=""
print_output_json="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --metrics-summary-json)
      metrics_summary_json="${2:-}"
      shift 2
      ;;
    --output-json)
      output_json="${2:-}"
      shift 2
      ;;
    --output-md)
      output_md="${2:-}"
      shift 2
      ;;
    --print-output-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_output_json="${2:-}"
        shift 2
      else
        print_output_json="1"
        shift
      fi
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$metrics_summary_json" || -z "$output_json" || -z "$output_md" ]]; then
  echo "fake checklist missing required args"
  exit 7
fi

if [[ ! -f "$metrics_summary_json" ]]; then
  echo "fake checklist input metrics summary missing: $metrics_summary_json"
  exit 8
fi

mkdir -p "$(dirname "$output_json")" "$(dirname "$output_md")"

jq -n \
  --arg metrics_summary_json "$metrics_summary_json" \
  --arg output_json "$output_json" \
  --arg output_md "$output_md" \
  '{
    schema: {id: "fake_blockchain_mainnet_activation_metrics_missing_checklist", version: "1.0.0"},
    status: "missing",
    rc: 0,
    input: {
      metrics_summary_json: $metrics_summary_json
    },
    artifacts: {
      output_json: $output_json,
      output_md: $output_md
    }
  }' >"$output_json"

{
  echo "# Fake Checklist"
  echo
  echo "- metrics_summary_json: $metrics_summary_json"
  echo "- status: missing"
} >"$output_md"

if [[ "$print_output_json" == "1" ]]; then
  cat "$output_json"
fi

checklist_rc="${BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_FAKE_CHECKLIST_RC:-0}"
if [[ "$checklist_rc" =~ ^-?[0-9]+$ ]]; then
  exit "$checklist_rc"
fi
exit 0
EOF_FAKE_CHECKLIST
chmod +x "$FAKE_CHECKLIST"

assert_stage_order() {
  local capture_file="$1"
  shift
  local expected_ids=("$@")
  local count idx line actual expected

  count="$(wc -l <"$capture_file" | tr -d ' ')"
  if [[ "$count" -ne "${#expected_ids[@]}" ]]; then
    echo "unexpected stage invocation count: expected ${#expected_ids[@]}, got $count"
    cat "$capture_file"
    exit 1
  fi

  for idx in "${!expected_ids[@]}"; do
    expected="${expected_ids[$idx]}"
    line="$(sed -n "$((idx + 1))p" "$capture_file" || true)"
    actual="${line%%$'\t'*}"
    if [[ "$actual" != "$expected" ]]; then
      echo "stage order mismatch at index $idx: expected $expected got $actual"
      cat "$capture_file"
      exit 1
    fi
  done
}

assert_stage_invocation_contains() {
  local capture_file="$1"
  local stage_id="$2"
  shift 2
  local line needle

  line="$(awk -F $'\t' -v stage="$stage_id" '$1 == stage { print; exit }' "$capture_file")"
  if [[ -z "$line" ]]; then
    echo "missing stage invocation: $stage_id"
    cat "$capture_file"
    exit 1
  fi

  for needle in "$@"; do
    if [[ "$line" != *$'\t'"$needle"* ]]; then
      echo "stage $stage_id missing token: $needle"
      cat "$capture_file"
      exit 1
    fi
  done
}

run_pack() {
  BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_CAPTURE_FILE="$CAPTURE" \
  BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_TEMPLATE_SCRIPT="$FAKE_TEMPLATE" \
  BLOCKCHAIN_MAINNET_ACTIVATION_OPERATOR_PACK_CHECKLIST_SCRIPT="$FAKE_CHECKLIST" \
  "$SCRIPT_UNDER_TEST" "$@"
}

echo "[blockchain-mainnet-activation-operator-pack] help surface"
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
if ! grep -Fq -- "--template-output-json" "$HELP_LOG"; then
  echo "help output missing --template-output-json"
  cat "$HELP_LOG"
  exit 1
fi
if ! grep -Fq -- "--checklist-output-json" "$HELP_LOG"; then
  echo "help output missing --checklist-output-json"
  cat "$HELP_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-operator-pack] template generation success"
: >"$CAPTURE"
if ! run_pack \
  --reports-dir "$TEMPLATE_ONLY_REPORTS_DIR" \
  --summary-json "$TEMPLATE_ONLY_SUMMARY_JSON" \
  --canonical-summary-json "$TEMPLATE_ONLY_CANONICAL_SUMMARY_JSON" \
  --template-include-example-values 1 \
  --print-summary-json 0 >"$TEMPLATE_ONLY_LOG" 2>&1; then
  echo "template-only operator pack run must exit 0"
  cat "$TEMPLATE_ONLY_LOG"
  exit 1
fi

assert_stage_order "$CAPTURE" "template"
assert_stage_invocation_contains "$CAPTURE" "template" \
  "--output-json" "$TEMPLATE_ONLY_TEMPLATE_OUTPUT_JSON" \
  "--canonical-output-json" "$TEMPLATE_ONLY_TEMPLATE_CANONICAL_JSON" \
  "--include-example-values" "1" \
  "--print-output-json" "0"

if [[ ! -f "$TEMPLATE_ONLY_TEMPLATE_OUTPUT_JSON" || ! -f "$TEMPLATE_ONLY_TEMPLATE_CANONICAL_JSON" ]]; then
  echo "template-only run missing template artifacts"
  ls -la "$TEMPLATE_ONLY_REPORTS_DIR"
  cat "$TEMPLATE_ONLY_LOG"
  exit 1
fi

if ! jq -e \
  --arg reports_dir "$TEMPLATE_ONLY_REPORTS_DIR" \
  --arg summary_json "$TEMPLATE_ONLY_SUMMARY_JSON" \
  --arg canonical_summary_json "$TEMPLATE_ONLY_CANONICAL_SUMMARY_JSON" \
  --arg template_output_json "$TEMPLATE_ONLY_TEMPLATE_OUTPUT_JSON" \
  --arg template_canonical_output_json "$TEMPLATE_ONLY_TEMPLATE_CANONICAL_JSON" \
  '
  .schema.id == "blockchain_mainnet_activation_operator_pack_summary"
  and .status == "pass"
  and .rc == 0
  and .inputs.metrics_summary_provided == false
  and .inputs.metrics_summary_exists == false
  and .inputs.metrics_summary_json == null
  and .steps.metrics_input_template.status == "pass"
  and .steps.metrics_input_template.rc == 0
  and .steps.metrics_missing_checklist.enabled == false
  and .steps.metrics_missing_checklist.status == "skipped"
  and .steps.metrics_missing_checklist.skipped_reason == "metrics-summary-json-not-provided"
  and .steps.metrics_missing_checklist.artifacts.output_json == null
  and .steps.metrics_missing_checklist.artifacts.output_md == null
  and .artifacts.reports_dir == $reports_dir
  and .artifacts.summary_json == $summary_json
  and .artifacts.canonical_summary_json == $canonical_summary_json
  and .artifacts.template_output_json == $template_output_json
  and .artifacts.template_canonical_output_json == $template_canonical_output_json
  and .artifacts.checklist_output_json == null
  and .artifacts.checklist_output_md == null
  ' "$TEMPLATE_ONLY_SUMMARY_JSON" >/dev/null; then
  echo "template-only summary contract mismatch"
  cat "$TEMPLATE_ONLY_SUMMARY_JSON"
  cat "$TEMPLATE_ONLY_LOG"
  exit 1
fi

if ! cmp -s "$TEMPLATE_ONLY_SUMMARY_JSON" "$TEMPLATE_ONLY_CANONICAL_SUMMARY_JSON"; then
  echo "template-only canonical summary does not match summary"
  cat "$TEMPLATE_ONLY_SUMMARY_JSON"
  cat "$TEMPLATE_ONLY_CANONICAL_SUMMARY_JSON"
  exit 1
fi

echo "[blockchain-mainnet-activation-operator-pack] checklist run when metrics summary exists"
cat >"$WITH_METRICS_INPUT_SUMMARY_JSON" <<'EOF_WITH_METRICS_INPUT_SUMMARY'
{
  "schema": {"id": "blockchain_mainnet_activation_metrics_summary", "version": "1.0.0"},
  "status": "partial",
  "required_missing_metrics": ["paying_users_3mo_min"]
}
EOF_WITH_METRICS_INPUT_SUMMARY

: >"$CAPTURE"
if ! run_pack \
  --reports-dir "$WITH_METRICS_REPORTS_DIR" \
  --summary-json "$WITH_METRICS_SUMMARY_JSON" \
  --canonical-summary-json "$WITH_METRICS_CANONICAL_SUMMARY_JSON" \
  --metrics-summary-json "$WITH_METRICS_INPUT_SUMMARY_JSON" \
  --checklist-output-json "$WITH_METRICS_CHECKLIST_OUTPUT_JSON" \
  --checklist-output-md "$WITH_METRICS_CHECKLIST_OUTPUT_MD" \
  --print-summary-json 0 >"$WITH_METRICS_LOG" 2>&1; then
  echo "with-metrics operator pack run must exit 0"
  cat "$WITH_METRICS_LOG"
  exit 1
fi

assert_stage_order "$CAPTURE" "template" "checklist"
assert_stage_invocation_contains "$CAPTURE" "checklist" \
  "--metrics-summary-json" "$WITH_METRICS_INPUT_SUMMARY_JSON" \
  "--output-json" "$WITH_METRICS_CHECKLIST_OUTPUT_JSON" \
  "--output-md" "$WITH_METRICS_CHECKLIST_OUTPUT_MD"

if [[ ! -f "$WITH_METRICS_CHECKLIST_OUTPUT_JSON" || ! -f "$WITH_METRICS_CHECKLIST_OUTPUT_MD" ]]; then
  echo "with-metrics run missing checklist artifacts"
  ls -la "$TMP_DIR"
  cat "$WITH_METRICS_LOG"
  exit 1
fi

if ! jq -e \
  --arg metrics_summary_json "$WITH_METRICS_INPUT_SUMMARY_JSON" \
  --arg checklist_output_json "$WITH_METRICS_CHECKLIST_OUTPUT_JSON" \
  --arg checklist_output_md "$WITH_METRICS_CHECKLIST_OUTPUT_MD" \
  '
  .status == "pass"
  and .rc == 0
  and .inputs.metrics_summary_provided == true
  and .inputs.metrics_summary_exists == true
  and .inputs.metrics_summary_json == $metrics_summary_json
  and .steps.metrics_missing_checklist.enabled == true
  and .steps.metrics_missing_checklist.status == "pass"
  and .steps.metrics_missing_checklist.rc == 0
  and .steps.metrics_missing_checklist.skipped_reason == null
  and .steps.metrics_missing_checklist.input.metrics_summary_json == $metrics_summary_json
  and .steps.metrics_missing_checklist.input.metrics_summary_exists == true
  and .steps.metrics_missing_checklist.artifacts.output_json == $checklist_output_json
  and .steps.metrics_missing_checklist.artifacts.output_md == $checklist_output_md
  and .artifacts.checklist_output_json == $checklist_output_json
  and .artifacts.checklist_output_md == $checklist_output_md
  ' "$WITH_METRICS_SUMMARY_JSON" >/dev/null; then
  echo "with-metrics summary contract mismatch"
  cat "$WITH_METRICS_SUMMARY_JSON"
  cat "$WITH_METRICS_LOG"
  exit 1
fi

if ! jq -e \
  --arg metrics_summary_json "$WITH_METRICS_INPUT_SUMMARY_JSON" \
  '.input.metrics_summary_json == $metrics_summary_json and .status == "missing"' \
  "$WITH_METRICS_CHECKLIST_OUTPUT_JSON" >/dev/null; then
  echo "with-metrics checklist output contract mismatch"
  cat "$WITH_METRICS_CHECKLIST_OUTPUT_JSON"
  exit 1
fi

if ! cmp -s "$WITH_METRICS_SUMMARY_JSON" "$WITH_METRICS_CANONICAL_SUMMARY_JSON"; then
  echo "with-metrics canonical summary does not match summary"
  cat "$WITH_METRICS_SUMMARY_JSON"
  cat "$WITH_METRICS_CANONICAL_SUMMARY_JSON"
  exit 1
fi

echo "[blockchain-mainnet-activation-operator-pack] fail-soft skip when metrics summary missing"
: >"$CAPTURE"
if ! run_pack \
  --reports-dir "$MISSING_METRICS_REPORTS_DIR" \
  --summary-json "$MISSING_METRICS_SUMMARY_JSON" \
  --canonical-summary-json "$MISSING_METRICS_CANONICAL_SUMMARY_JSON" \
  --metrics-summary-json "$MISSING_METRICS_INPUT_SUMMARY_JSON" \
  --checklist-output-json "$MISSING_METRICS_CHECKLIST_OUTPUT_JSON" \
  --checklist-output-md "$MISSING_METRICS_CHECKLIST_OUTPUT_MD" \
  --print-summary-json 0 >"$MISSING_METRICS_LOG" 2>&1; then
  echo "missing-metrics operator pack run must remain fail-soft and exit 0"
  cat "$MISSING_METRICS_LOG"
  exit 1
fi

assert_stage_order "$CAPTURE" "template"
if [[ -f "$MISSING_METRICS_CHECKLIST_OUTPUT_JSON" || -f "$MISSING_METRICS_CHECKLIST_OUTPUT_MD" ]]; then
  echo "missing-metrics run should skip checklist and not create checklist artifacts"
  ls -la "$TMP_DIR"
  cat "$MISSING_METRICS_LOG"
  exit 1
fi

if ! jq -e \
  --arg metrics_summary_json "$MISSING_METRICS_INPUT_SUMMARY_JSON" \
  '
  .status == "pass"
  and .rc == 0
  and .inputs.metrics_summary_provided == true
  and .inputs.metrics_summary_exists == false
  and .inputs.metrics_summary_json == $metrics_summary_json
  and .steps.metrics_input_template.status == "pass"
  and .steps.metrics_missing_checklist.enabled == false
  and .steps.metrics_missing_checklist.status == "skipped"
  and .steps.metrics_missing_checklist.skipped_reason == "metrics-summary-json-missing-file"
  and .steps.metrics_missing_checklist.artifacts.output_json == null
  and .steps.metrics_missing_checklist.artifacts.output_md == null
  and .artifacts.checklist_output_json == null
  and .artifacts.checklist_output_md == null
  ' "$MISSING_METRICS_SUMMARY_JSON" >/dev/null; then
  echo "missing-metrics summary contract mismatch"
  cat "$MISSING_METRICS_SUMMARY_JSON"
  cat "$MISSING_METRICS_LOG"
  exit 1
fi

if ! cmp -s "$MISSING_METRICS_SUMMARY_JSON" "$MISSING_METRICS_CANONICAL_SUMMARY_JSON"; then
  echo "missing-metrics canonical summary does not match summary"
  cat "$MISSING_METRICS_SUMMARY_JSON"
  cat "$MISSING_METRICS_CANONICAL_SUMMARY_JSON"
  exit 1
fi

echo "blockchain mainnet activation operator pack integration ok"
