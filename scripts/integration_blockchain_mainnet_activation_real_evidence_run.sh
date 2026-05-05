#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp jq grep awk sed cat chmod cmp wc tr; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/blockchain_mainnet_activation_real_evidence_run.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/stage_calls.tsv"
HELP_LOG="$TMP_DIR/help.log"
VALIDATION_LOG="$TMP_DIR/validation.log"
SUCCESS_LOG="$TMP_DIR/success.log"
FAIL_LOG="$TMP_DIR/fail.log"

INPUT_JSON="$TMP_DIR/real_metrics_input.json"
SUCCESS_REPORTS_DIR="$TMP_DIR/reports_success"
SUCCESS_SUMMARY_JSON="$TMP_DIR/success_summary.json"
SUCCESS_CANONICAL_SUMMARY_JSON="$TMP_DIR/success_summary_canonical.json"

FAIL_REPORTS_DIR="$TMP_DIR/reports_fail"
FAIL_SUMMARY_JSON="$TMP_DIR/fail_summary.json"
FAIL_CANONICAL_SUMMARY_JSON="$TMP_DIR/fail_summary_canonical.json"

VALIDATION_SUMMARY_JSON="$TMP_DIR/validation_should_not_exist.json"

cat >"$INPUT_JSON" <<'EOF_INPUT'
{
  "measurement_window_weeks": 13,
  "vpn_connect_session_success_slo_pct": 99.91,
  "vpn_recovery_mttr_p95_minutes": 16
}
EOF_INPUT

FAKE_TEMPLATE="$TMP_DIR/fake_template.sh"
cat >"$FAKE_TEMPLATE" <<'EOF_FAKE_TEMPLATE'
#!/usr/bin/env bash
set -euo pipefail

capture="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_CAPTURE_FILE:?}"
{
  printf '%s' "template"
  for arg in "$@"; do
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
  echo "fake template missing required args"
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
cp -f "$output_json" "$canonical_output_json"

if [[ "$print_output_json" == "1" ]]; then
  cat "$output_json"
fi

rc="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_FAKE_TEMPLATE_RC:-0}"
if [[ "$rc" =~ ^-?[0-9]+$ ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_TEMPLATE
chmod +x "$FAKE_TEMPLATE"

FAKE_GATE_CYCLE="$TMP_DIR/fake_gate_cycle.sh"
cat >"$FAKE_GATE_CYCLE" <<'EOF_FAKE_GATE_CYCLE'
#!/usr/bin/env bash
set -euo pipefail

capture="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_CAPTURE_FILE:?}"
{
  printf '%s' "gate_cycle"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture"

input_json=""
seed_example_input="1"
emit_missing_checklist="1"
reports_dir=""
summary_json=""
canonical_summary_json=""
refresh_roadmap="1"
print_summary_json="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --input-json)
      input_json="${2:-}"
      shift 2
      ;;
    --seed-example-input)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        seed_example_input="${2:-}"
        shift 2
      else
        seed_example_input="1"
        shift
      fi
      ;;
    --emit-missing-checklist)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        emit_missing_checklist="${2:-}"
        shift 2
      else
        emit_missing_checklist="1"
        shift
      fi
      ;;
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --canonical-summary-json)
      canonical_summary_json="${2:-}"
      shift 2
      ;;
    --refresh-roadmap)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        refresh_roadmap="${2:-}"
        shift 2
      else
        refresh_roadmap="1"
        shift
      fi
      ;;
    --print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_summary_json="${2:-}"
        shift 2
      else
        print_summary_json="1"
        shift
      fi
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$input_json" || -z "$reports_dir" || -z "$summary_json" || -z "$canonical_summary_json" ]]; then
  echo "fake gate cycle missing required args"
  exit 7
fi

mkdir -p "$reports_dir" "$(dirname "$summary_json")" "$(dirname "$canonical_summary_json")"
metrics_summary_json="$reports_dir/blockchain_mainnet_activation_metrics_summary.json"

decision="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_FAKE_GATE_CYCLE_DECISION:-GO}"
if [[ "$decision" != "GO" ]]; then
  decision="NO-GO"
fi

if [[ "$decision" == "GO" ]]; then
  missing_required_metrics='[]'
else
  missing_required_metrics='["measurement_window_weeks","validator_country_count"]'
fi

jq -n \
  --arg decision "$decision" \
  --arg metrics_summary_json "$metrics_summary_json" \
  --argjson missing_required_metrics "$missing_required_metrics" \
  '{
    schema: {id: "fake_blockchain_mainnet_activation_gate_cycle_summary", version: "1.0.0"},
    status: "pass",
    decision: $decision,
    rc: 0,
    steps: {
      gate_bundle: {
        status: "pass",
        missing_required_metrics: $missing_required_metrics,
        artifacts: {
          metrics_summary_json: $metrics_summary_json
        }
      }
    }
  }' >"$summary_json"
cp -f "$summary_json" "$canonical_summary_json"

jq -n \
  --argjson required_missing_metrics "$missing_required_metrics" \
  '{
    schema: {id: "fake_blockchain_mainnet_activation_metrics_summary", version: "1.0.0"},
    status: (if ($required_missing_metrics | length) == 0 then "complete" else "partial" end),
    required_missing_metrics: $required_missing_metrics
  }' >"$metrics_summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

rc="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_FAKE_GATE_CYCLE_RC:-0}"
if [[ "$rc" =~ ^-?[0-9]+$ ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_GATE_CYCLE
chmod +x "$FAKE_GATE_CYCLE"

FAKE_MISSING_CHECKLIST="$TMP_DIR/fake_missing_checklist.sh"
cat >"$FAKE_MISSING_CHECKLIST" <<'EOF_FAKE_MISSING_CHECKLIST'
#!/usr/bin/env bash
set -euo pipefail

capture="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_CAPTURE_FILE:?}"
{
  printf '%s' "missing_checklist"
  for arg in "$@"; do
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
  echo "fake missing-checklist missing required args"
  exit 7
fi
if [[ ! -f "$metrics_summary_json" ]]; then
  echo "fake missing-checklist missing metrics summary: $metrics_summary_json"
  exit 8
fi

mkdir -p "$(dirname "$output_json")" "$(dirname "$output_md")"

missing_keys="$(jq -c '(.required_missing_metrics // []) | if type == "array" then . else [] end' "$metrics_summary_json" 2>/dev/null || echo '[]')"
jq -n \
  --arg metrics_summary_json "$metrics_summary_json" \
  --arg output_json "$output_json" \
  --arg output_md "$output_md" \
  --argjson missing_keys "$missing_keys" \
  '{
    schema: {id: "fake_blockchain_mainnet_activation_metrics_missing_checklist", version: "1.0.0"},
    status: (if ($missing_keys | length) == 0 then "complete" else "missing" end),
    counts: {missing: ($missing_keys | length)},
    missing_metric_keys: $missing_keys,
    checklist: ($missing_keys | map({key: ., category: "required", comparator: ">=", threshold: "see gate", unit: "metric", hint: "collect and rerun"})),
    artifacts: {
      metrics_summary_json: $metrics_summary_json,
      output_json: $output_json,
      output_md: $output_md
    }
  }' >"$output_json"

{
  echo "# fake missing checklist"
  echo
  echo "- missing_count: $(jq -r '.counts.missing' "$output_json")"
} >"$output_md"

if [[ "$print_output_json" == "1" ]]; then
  cat "$output_json"
fi

rc="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_FAKE_MISSING_CHECKLIST_RC:-0}"
if [[ "$rc" =~ ^-?[0-9]+$ ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_MISSING_CHECKLIST
chmod +x "$FAKE_MISSING_CHECKLIST"

FAKE_OPERATOR_PACK="$TMP_DIR/fake_operator_pack.sh"
cat >"$FAKE_OPERATOR_PACK" <<'EOF_FAKE_OPERATOR_PACK'
#!/usr/bin/env bash
set -euo pipefail

capture="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_CAPTURE_FILE:?}"
{
  printf '%s' "operator_pack"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture"

reports_dir=""
summary_json=""
canonical_summary_json=""
metrics_summary_json=""
template_output_json=""
template_canonical_output_json=""
template_include_example_values="1"
checklist_output_json=""
checklist_output_md=""
print_summary_json="0"

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
    --canonical-summary-json)
      canonical_summary_json="${2:-}"
      shift 2
      ;;
    --metrics-summary-json)
      metrics_summary_json="${2:-}"
      shift 2
      ;;
    --template-output-json)
      template_output_json="${2:-}"
      shift 2
      ;;
    --template-canonical-output-json)
      template_canonical_output_json="${2:-}"
      shift 2
      ;;
    --template-include-example-values)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        template_include_example_values="${2:-}"
        shift 2
      else
        template_include_example_values="1"
        shift
      fi
      ;;
    --checklist-output-json)
      checklist_output_json="${2:-}"
      shift 2
      ;;
    --checklist-output-md)
      checklist_output_md="${2:-}"
      shift 2
      ;;
    --print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_summary_json="${2:-}"
        shift 2
      else
        print_summary_json="1"
        shift
      fi
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$reports_dir" || -z "$summary_json" || -z "$canonical_summary_json" || -z "$metrics_summary_json" || -z "$template_output_json" || -z "$template_canonical_output_json" || -z "$checklist_output_json" || -z "$checklist_output_md" ]]; then
  echo "fake operator-pack missing required args"
  exit 7
fi
if [[ ! -f "$metrics_summary_json" ]]; then
  echo "fake operator-pack missing metrics summary: $metrics_summary_json"
  exit 8
fi

mkdir -p "$reports_dir" "$(dirname "$summary_json")" "$(dirname "$canonical_summary_json")"
jq -n \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg canonical_summary_json "$canonical_summary_json" \
  --arg metrics_summary_json "$metrics_summary_json" \
  --arg template_output_json "$template_output_json" \
  --arg template_canonical_output_json "$template_canonical_output_json" \
  --arg checklist_output_json "$checklist_output_json" \
  --arg checklist_output_md "$checklist_output_md" \
  --argjson template_include_example_values "$( [[ "$template_include_example_values" == "1" ]] && echo true || echo false )" \
  '{
    schema: {id: "fake_blockchain_mainnet_activation_operator_pack_summary", version: "1.0.0"},
    status: "pass",
    rc: 0,
    inputs: {
      metrics_summary_json: $metrics_summary_json,
      template_include_example_values: $template_include_example_values
    },
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      canonical_summary_json: $canonical_summary_json,
      template_output_json: $template_output_json,
      template_canonical_output_json: $template_canonical_output_json,
      checklist_output_json: $checklist_output_json,
      checklist_output_md: $checklist_output_md
    }
  }' >"$summary_json"
cp -f "$summary_json" "$canonical_summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

rc="${BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_FAKE_OPERATOR_PACK_RC:-0}"
if [[ "$rc" =~ ^-?[0-9]+$ ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_OPERATOR_PACK
chmod +x "$FAKE_OPERATOR_PACK"

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

run_helper() {
  BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_CAPTURE_FILE="$CAPTURE" \
  BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_TEMPLATE_SCRIPT="$FAKE_TEMPLATE" \
  BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_GATE_CYCLE_SCRIPT="$FAKE_GATE_CYCLE" \
  BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_MISSING_CHECKLIST_SCRIPT="$FAKE_MISSING_CHECKLIST" \
  BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_OPERATOR_PACK_SCRIPT="$FAKE_OPERATOR_PACK" \
  "$SCRIPT_UNDER_TEST" "$@"
}

echo "[blockchain-mainnet-activation-real-evidence] help surface"
bash "$SCRIPT_UNDER_TEST" --help >"$HELP_LOG" 2>&1
if ! grep -Fq "Usage:" "$HELP_LOG"; then
  echo "help output missing Usage header"
  cat "$HELP_LOG"
  exit 1
fi
if ! grep -Fq -- "--input-json" "$HELP_LOG"; then
  echo "help output missing --input-json"
  cat "$HELP_LOG"
  exit 1
fi
if ! grep -Fq -- "--gate-cycle-reports-dir" "$HELP_LOG"; then
  echo "help output missing --gate-cycle-reports-dir"
  cat "$HELP_LOG"
  exit 1
fi
if ! grep -Fq -- "--operator-pack-summary-json" "$HELP_LOG"; then
  echo "help output missing --operator-pack-summary-json"
  cat "$HELP_LOG"
  exit 1
fi
if ! grep -Fq -- "--print-summary-json" "$HELP_LOG"; then
  echo "help output missing --print-summary-json"
  cat "$HELP_LOG"
  exit 1
fi
if ! grep -Fq -- "--print-output-json" "$HELP_LOG"; then
  echo "help output missing --print-output-json alias"
  cat "$HELP_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-real-evidence] success path"
: >"$CAPTURE"
if ! run_helper \
  --input-json "$INPUT_JSON" \
  --reports-dir "$SUCCESS_REPORTS_DIR" \
  --summary-json "$SUCCESS_SUMMARY_JSON" \
  --canonical-summary-json "$SUCCESS_CANONICAL_SUMMARY_JSON" \
  --refresh-roadmap 0 \
  --print-output-json 0 >"$SUCCESS_LOG" 2>&1; then
  echo "success path must exit 0"
  cat "$SUCCESS_LOG"
  exit 1
fi

SUCCESS_TEMPLATE_OUTPUT_JSON="$SUCCESS_REPORTS_DIR/blockchain_mainnet_activation_metrics_input_template.json"
SUCCESS_TEMPLATE_CANONICAL_OUTPUT_JSON="$SUCCESS_REPORTS_DIR/blockchain_mainnet_activation_metrics_input_template.canonical.json"
SUCCESS_MISSING_CHECKLIST_JSON="$SUCCESS_REPORTS_DIR/blockchain_mainnet_activation_metrics_missing_checklist.json"
SUCCESS_MISSING_CHECKLIST_MD="$SUCCESS_REPORTS_DIR/blockchain_mainnet_activation_metrics_missing_checklist.md"
SUCCESS_GATE_CYCLE_REPORTS_DIR="$SUCCESS_REPORTS_DIR/gate_cycle"
SUCCESS_GATE_CYCLE_SUMMARY_JSON="$SUCCESS_GATE_CYCLE_REPORTS_DIR/blockchain_mainnet_activation_gate_cycle_summary.json"
SUCCESS_GATE_CYCLE_CANONICAL_SUMMARY_JSON="$SUCCESS_GATE_CYCLE_REPORTS_DIR/blockchain_mainnet_activation_gate_cycle_summary.canonical.json"
SUCCESS_GATE_CYCLE_METRICS_SUMMARY_JSON="$SUCCESS_GATE_CYCLE_REPORTS_DIR/blockchain_mainnet_activation_metrics_summary.json"
SUCCESS_OPERATOR_PACK_REPORTS_DIR="$SUCCESS_REPORTS_DIR/operator_pack"
SUCCESS_OPERATOR_PACK_SUMMARY_JSON="$SUCCESS_OPERATOR_PACK_REPORTS_DIR/blockchain_mainnet_activation_operator_pack_summary.json"
SUCCESS_OPERATOR_PACK_CANONICAL_SUMMARY_JSON="$SUCCESS_OPERATOR_PACK_REPORTS_DIR/blockchain_mainnet_activation_operator_pack_summary.canonical.json"

assert_stage_order "$CAPTURE" "template" "gate_cycle" "missing_checklist" "operator_pack"
assert_stage_invocation_contains "$CAPTURE" "template" \
  "--output-json" "$SUCCESS_TEMPLATE_OUTPUT_JSON" \
  "--canonical-output-json" "$SUCCESS_TEMPLATE_CANONICAL_OUTPUT_JSON" \
  "--include-example-values" "0" \
  "--print-output-json" "0"
assert_stage_invocation_contains "$CAPTURE" "gate_cycle" \
  "--input-json" "$INPUT_JSON" \
  "--seed-example-input" "0" \
  "--emit-missing-checklist" "0" \
  "--reports-dir" "$SUCCESS_GATE_CYCLE_REPORTS_DIR" \
  "--summary-json" "$SUCCESS_GATE_CYCLE_SUMMARY_JSON" \
  "--canonical-summary-json" "$SUCCESS_GATE_CYCLE_CANONICAL_SUMMARY_JSON" \
  "--refresh-roadmap" "0" \
  "--print-summary-json" "0"
assert_stage_invocation_contains "$CAPTURE" "missing_checklist" \
  "--metrics-summary-json" "$SUCCESS_GATE_CYCLE_METRICS_SUMMARY_JSON" \
  "--output-json" "$SUCCESS_MISSING_CHECKLIST_JSON" \
  "--output-md" "$SUCCESS_MISSING_CHECKLIST_MD" \
  "--print-output-json" "0"
assert_stage_invocation_contains "$CAPTURE" "operator_pack" \
  "--reports-dir" "$SUCCESS_OPERATOR_PACK_REPORTS_DIR" \
  "--summary-json" "$SUCCESS_OPERATOR_PACK_SUMMARY_JSON" \
  "--canonical-summary-json" "$SUCCESS_OPERATOR_PACK_CANONICAL_SUMMARY_JSON" \
  "--metrics-summary-json" "$SUCCESS_GATE_CYCLE_METRICS_SUMMARY_JSON" \
  "--template-output-json" "$SUCCESS_TEMPLATE_OUTPUT_JSON" \
  "--template-canonical-output-json" "$SUCCESS_TEMPLATE_CANONICAL_OUTPUT_JSON" \
  "--template-include-example-values" "0" \
  "--checklist-output-json" "$SUCCESS_MISSING_CHECKLIST_JSON" \
  "--checklist-output-md" "$SUCCESS_MISSING_CHECKLIST_MD" \
  "--print-summary-json" "0"

if [[ ! -f "$SUCCESS_SUMMARY_JSON" || ! -f "$SUCCESS_CANONICAL_SUMMARY_JSON" || ! -f "$SUCCESS_TEMPLATE_OUTPUT_JSON" || ! -f "$SUCCESS_TEMPLATE_CANONICAL_OUTPUT_JSON" || ! -f "$SUCCESS_MISSING_CHECKLIST_JSON" || ! -f "$SUCCESS_MISSING_CHECKLIST_MD" || ! -f "$SUCCESS_GATE_CYCLE_SUMMARY_JSON" || ! -f "$SUCCESS_GATE_CYCLE_METRICS_SUMMARY_JSON" || ! -f "$SUCCESS_OPERATOR_PACK_SUMMARY_JSON" ]]; then
  echo "success path missing expected artifacts"
  ls -la "$TMP_DIR"
  cat "$SUCCESS_LOG"
  exit 1
fi

if ! cmp -s "$SUCCESS_SUMMARY_JSON" "$SUCCESS_CANONICAL_SUMMARY_JSON"; then
  echo "success canonical summary does not match summary"
  cat "$SUCCESS_SUMMARY_JSON"
  cat "$SUCCESS_CANONICAL_SUMMARY_JSON"
  exit 1
fi

if ! jq -e \
  --arg input_json "$INPUT_JSON" \
  --arg reports_dir "$SUCCESS_REPORTS_DIR" \
  --arg gate_cycle_metrics_summary_json "$SUCCESS_GATE_CYCLE_METRICS_SUMMARY_JSON" \
  --arg missing_checklist_json "$SUCCESS_MISSING_CHECKLIST_JSON" \
  --arg operator_pack_summary_json "$SUCCESS_OPERATOR_PACK_SUMMARY_JSON" \
  '
  .schema.id == "blockchain_mainnet_activation_real_evidence_summary"
  and .status == "pass"
  and .rc == 0
  and .inputs.input_json == $input_json
  and .inputs.reports_dir == $reports_dir
  and .inputs.refresh_roadmap == false
  and .steps.metrics_input_template.status == "pass"
  and .steps.gate_cycle.status == "pass"
  and .steps.gate_cycle.decision == "GO"
  and (.steps.gate_cycle.missing_required_metrics | length) == 0
  and .steps.missing_metrics_checklist.status == "pass"
  and .steps.missing_metrics_checklist.checklist_status == "complete"
  and .steps.missing_metrics_checklist.missing_count == 0
  and (.steps.missing_metrics_checklist.missing_keys | length) == 0
  and .steps.operator_pack.status == "pass"
  and .steps.operator_pack.observed_status == "pass"
  and .steps.operator_pack.observed_rc == 0
  and .artifacts.reports_dir == $reports_dir
  and .artifacts.gate_cycle_metrics_summary_json == $gate_cycle_metrics_summary_json
  and .artifacts.missing_checklist_json == $missing_checklist_json
  and .artifacts.operator_pack_summary_json == $operator_pack_summary_json
  ' "$SUCCESS_SUMMARY_JSON" >/dev/null; then
  echo "success summary contract mismatch"
  cat "$SUCCESS_SUMMARY_JSON"
  cat "$SUCCESS_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-real-evidence] failure propagation"
: >"$CAPTURE"
set +e
BLOCKCHAIN_MAINNET_ACTIVATION_REAL_EVIDENCE_FAKE_GATE_CYCLE_RC=37 \
run_helper \
  --input-json "$INPUT_JSON" \
  --reports-dir "$FAIL_REPORTS_DIR" \
  --summary-json "$FAIL_SUMMARY_JSON" \
  --canonical-summary-json "$FAIL_CANONICAL_SUMMARY_JSON" \
  --print-summary-json 0 >"$FAIL_LOG" 2>&1
fail_rc=$?
set -e

if [[ "$fail_rc" -ne 37 ]]; then
  echo "expected failure path rc=37"
  cat "$FAIL_LOG"
  exit 1
fi

assert_stage_order "$CAPTURE" "template" "gate_cycle"

if [[ ! -f "$FAIL_SUMMARY_JSON" || ! -f "$FAIL_CANONICAL_SUMMARY_JSON" ]]; then
  echo "failure path missing summary artifacts"
  cat "$FAIL_LOG"
  exit 1
fi
if ! cmp -s "$FAIL_SUMMARY_JSON" "$FAIL_CANONICAL_SUMMARY_JSON"; then
  echo "failure canonical summary does not match summary"
  cat "$FAIL_SUMMARY_JSON"
  cat "$FAIL_CANONICAL_SUMMARY_JSON"
  exit 1
fi

if ! jq -e '
  .status == "runtime-fail"
  and .rc == 37
  and .first_runtime_failure.step == "gate_cycle"
  and .first_runtime_failure.rc == 37
  and .steps.metrics_input_template.status == "pass"
  and .steps.gate_cycle.status == "fail"
  and .steps.gate_cycle.rc == 37
  and .steps.missing_metrics_checklist.status == "skipped"
  and .steps.missing_metrics_checklist.note == "gate-cycle-step-failed"
  and .steps.operator_pack.status == "skipped"
  and .steps.operator_pack.note == "gate-cycle-step-failed"
' "$FAIL_SUMMARY_JSON" >/dev/null; then
  echo "failure summary contract mismatch"
  cat "$FAIL_SUMMARY_JSON"
  cat "$FAIL_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-real-evidence] required arg validation"
set +e
run_helper \
  --reports-dir "$TMP_DIR/reports_validation" \
  --summary-json "$VALIDATION_SUMMARY_JSON" \
  --print-summary-json 0 >"$VALIDATION_LOG" 2>&1
validation_rc=$?
set -e
if [[ "$validation_rc" -ne 2 ]]; then
  echo "expected missing --input-json validation rc=2"
  cat "$VALIDATION_LOG"
  exit 1
fi
if ! grep -Fq -- "--input-json is required" "$VALIDATION_LOG"; then
  echo "validation log missing required-input message"
  cat "$VALIDATION_LOG"
  exit 1
fi
if [[ -f "$VALIDATION_SUMMARY_JSON" ]]; then
  echo "validation path should not create summary json"
  cat "$VALIDATION_SUMMARY_JSON"
  exit 1
fi

echo "blockchain mainnet activation real evidence run integration ok"
