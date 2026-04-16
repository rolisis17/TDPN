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

SCRIPT_UNDER_TEST="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/blockchain_mainnet_activation_gate_cycle.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/stage_calls.tsv"

PASS_INPUT_JSON="$TMP_DIR/input_pass.json"
PASS_REPORTS_DIR="$TMP_DIR/reports_pass"
PASS_SUMMARY_JSON="$TMP_DIR/pass_summary.json"
PASS_CANONICAL_SUMMARY_JSON="$TMP_DIR/pass_canonical_summary.json"
PASS_LOG="$TMP_DIR/pass.log"

NO_GO_INPUT_JSON="$TMP_DIR/input_no_go.json"
NO_GO_REPORTS_DIR="$TMP_DIR/reports_no_go"
NO_GO_SUMMARY_JSON="$TMP_DIR/no_go_summary.json"
NO_GO_CANONICAL_SUMMARY_JSON="$TMP_DIR/no_go_canonical_summary.json"
NO_GO_LOG="$TMP_DIR/no_go.log"

TOGGLE_INPUT_JSON="$TMP_DIR/input_toggle.json"
TOGGLE_REPORTS_DIR="$TMP_DIR/reports_toggle"
TOGGLE_SUMMARY_JSON="$TMP_DIR/toggle_summary.json"
TOGGLE_CANONICAL_SUMMARY_JSON="$TMP_DIR/toggle_canonical_summary.json"
TOGGLE_LOG="$TMP_DIR/toggle.log"

SEED_REPORTS_DIR="$TMP_DIR/reports_seed"
SEED_SUMMARY_JSON="$TMP_DIR/seed_summary.json"
SEED_CANONICAL_SUMMARY_JSON="$TMP_DIR/seed_canonical_summary.json"
SEED_LOG="$TMP_DIR/seed.log"

VALIDATION_SUMMARY_JSON="$TMP_DIR/validation_should_not_exist.json"
VALIDATION_LOG="$TMP_DIR/validation.log"

cat >"$PASS_INPUT_JSON" <<'EOF_PASS_INPUT_JSON'
{
  "measurement_window_weeks": 12
}
EOF_PASS_INPUT_JSON

cat >"$NO_GO_INPUT_JSON" <<'EOF_NO_GO_INPUT_JSON'
{
  "measurement_window_weeks": 12
}
EOF_NO_GO_INPUT_JSON

cat >"$TOGGLE_INPUT_JSON" <<'EOF_TOGGLE_INPUT_JSON'
{
  "measurement_window_weeks": 12
}
EOF_TOGGLE_INPUT_JSON

FAKE_METRICS_INPUT_TEMPLATE="$TMP_DIR/fake_metrics_input_template.sh"
cat >"$FAKE_METRICS_INPUT_TEMPLATE" <<'EOF_FAKE_METRICS_INPUT_TEMPLATE'
#!/usr/bin/env bash
set -euo pipefail

capture="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_CAPTURE_FILE:?}"
{
  printf '%s' "metrics_input_template"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture"

output_json=""
canonical_output_json=""
include_example_values="0"

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
        shift 2
      else
        shift
      fi
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$output_json" || -z "$canonical_output_json" ]]; then
  echo "fake metrics input template missing required args"
  exit 7
fi

mkdir -p "$(dirname "$output_json")" "$(dirname "$canonical_output_json")"
jq -n \
  --arg output_json "$output_json" \
  --arg canonical_output_json "$canonical_output_json" \
  --argjson include_example_values "$( [[ "$include_example_values" == "1" ]] && echo true || echo false )" \
  '{
    status: "ok",
    include_example_values: $include_example_values,
    measurement_window_weeks: 13,
    vpn_connect_session_success_slo_pct: 99.82,
    artifacts: {
      output_json: $output_json,
      canonical_output_json: $canonical_output_json
    }
  }' >"$output_json"
cp "$output_json" "$canonical_output_json"

rc="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_FAKE_METRICS_INPUT_TEMPLATE_RC:-0}"
if [[ "$rc" =~ ^-?[0-9]+$ ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_METRICS_INPUT_TEMPLATE
chmod +x "$FAKE_METRICS_INPUT_TEMPLATE"

FAKE_METRICS_INPUT="$TMP_DIR/fake_metrics_input.sh"
cat >"$FAKE_METRICS_INPUT" <<'EOF_FAKE_METRICS_INPUT'
#!/usr/bin/env bash
set -euo pipefail

capture="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_CAPTURE_FILE:?}"
{
  printf '%s' "metrics_input"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture"

input_json=""
summary_json=""
canonical_summary_json=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --input-json)
      input_json="${2:-}"
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
    --print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        shift 2
      else
        shift
      fi
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$input_json" || -z "$summary_json" || -z "$canonical_summary_json" ]]; then
  echo "fake metrics input missing required args"
  exit 7
fi

mkdir -p "$(dirname "$summary_json")" "$(dirname "$canonical_summary_json")"
jq -n \
  --arg input_json "$input_json" \
  --arg summary_json "$summary_json" \
  --arg canonical_summary_json "$canonical_summary_json" \
  '{
    status: "complete",
    rc: 0,
    ready_for_metrics_script: true,
    input: { input_json: $input_json },
    artifacts: {
      summary_json: $summary_json,
      canonical_summary_json: $canonical_summary_json
    }
  }' >"$summary_json"
cp "$summary_json" "$canonical_summary_json"

rc="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_FAKE_METRICS_INPUT_RC:-0}"
if [[ "$rc" =~ ^-?[0-9]+$ ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_METRICS_INPUT
chmod +x "$FAKE_METRICS_INPUT"

FAKE_GATE_BUNDLE="$TMP_DIR/fake_gate_bundle.sh"
cat >"$FAKE_GATE_BUNDLE" <<'EOF_FAKE_GATE_BUNDLE'
#!/usr/bin/env bash
set -euo pipefail

capture="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_CAPTURE_FILE:?}"
{
  printf '%s' "gate_bundle"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture"

reports_dir=""
summary_json=""
canonical_summary_json=""
metrics_json=""
metrics_summary_json=""
activation_summary_json=""
bootstrap_summary_json=""
metrics_input_json=""
metrics_input_summary_json=""
metrics_input_canonical_json=""

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
    --metrics-json)
      metrics_json="${2:-}"
      shift 2
      ;;
    --metrics-summary-json)
      metrics_summary_json="${2:-}"
      shift 2
      ;;
    --activation-summary-json)
      activation_summary_json="${2:-}"
      shift 2
      ;;
    --bootstrap-summary-json)
      bootstrap_summary_json="${2:-}"
      shift 2
      ;;
    --blockchain-mainnet-activation-metrics-input-json)
      metrics_input_json="${2:-}"
      shift 2
      ;;
    --blockchain-mainnet-activation-metrics-input-summary-json)
      metrics_input_summary_json="${2:-}"
      shift 2
      ;;
    --blockchain-mainnet-activation-metrics-input-canonical-json)
      metrics_input_canonical_json="${2:-}"
      shift 2
      ;;
    --print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        shift 2
      else
        shift
      fi
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$reports_dir" || -z "$summary_json" || -z "$canonical_summary_json" || -z "$metrics_json" || -z "$metrics_summary_json" || -z "$activation_summary_json" || -z "$bootstrap_summary_json" || -z "$metrics_input_json" || -z "$metrics_input_summary_json" || -z "$metrics_input_canonical_json" ]]; then
  echo "fake gate bundle missing required args"
  exit 7
fi

mkdir -p "$(dirname "$summary_json")" "$(dirname "$canonical_summary_json")" "$(dirname "$metrics_json")" "$(dirname "$metrics_summary_json")" "$(dirname "$activation_summary_json")" "$(dirname "$bootstrap_summary_json")"

decision="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_FAKE_GATE_BUNDLE_DECISION:-GO}"
if [[ "$decision" != "GO" ]]; then
  decision="NO-GO"
fi

if [[ "$decision" == "GO" ]]; then
  missing_required_metrics='[]'
else
  missing_required_metrics='["measurement_window_weeks","vpn_recovery_mttr_p95_minutes"]'
fi

jq -n \
  --arg decision "$decision" \
  --arg reports_dir "$reports_dir" \
  --arg metrics_json "$metrics_json" \
  --arg metrics_summary_json "$metrics_summary_json" \
  --arg activation_summary_json "$activation_summary_json" \
  --arg bootstrap_summary_json "$bootstrap_summary_json" \
  --argjson missing_required_metrics "$missing_required_metrics" \
  '{
    status: "pass",
    decision: $decision,
    rc: 0,
    missing_required_metrics: $missing_required_metrics,
    artifacts: {
      reports_dir: $reports_dir,
      metrics_json: $metrics_json,
      metrics_summary_json: $metrics_summary_json,
      activation_summary_json: $activation_summary_json,
      bootstrap_summary_json: $bootstrap_summary_json
    }
  }' >"$summary_json"

cp "$summary_json" "$canonical_summary_json"
jq -n '{measurement_window_weeks: 12}' >"$metrics_json"
jq -n \
  --argjson required_missing_metrics "$missing_required_metrics" \
  '{
    status: "complete",
    rc: 0,
    ready_for_gate: true,
    required_missing_metrics: $required_missing_metrics
  }' >"$metrics_summary_json"

jq -n \
  --arg decision "$decision" \
  --arg metrics_json "$metrics_json" \
  '{
    decision: $decision,
    status: (if $decision == "GO" then "go" else "no-go" end),
    rc: (if $decision == "GO" then 0 else 1 end),
    exit_code: 0,
    artifacts: { metrics_json: $metrics_json }
  }' >"$activation_summary_json"

jq -n \
  --arg decision "$decision" \
  --arg metrics_json "$metrics_json" \
  '{
    decision: $decision,
    status: (if $decision == "GO" then "go" else "no-go" end),
    rc: (if $decision == "GO" then 0 else 1 end),
    exit_code: 0,
    artifacts: { metrics_json: $metrics_json }
  }' >"$bootstrap_summary_json"

rc="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_FAKE_GATE_BUNDLE_RC:-0}"
if [[ "$rc" =~ ^-?[0-9]+$ ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_GATE_BUNDLE
chmod +x "$FAKE_GATE_BUNDLE"

FAKE_MISSING_CHECKLIST="$TMP_DIR/fake_missing_checklist.sh"
cat >"$FAKE_MISSING_CHECKLIST" <<'EOF_FAKE_MISSING_CHECKLIST'
#!/usr/bin/env bash
set -euo pipefail

capture="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_CAPTURE_FILE:?}"
{
  printf '%s' "missing_metrics_checklist"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture"

metrics_summary_json=""
output_json=""
output_md=""

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
        shift 2
      else
        shift
      fi
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$metrics_summary_json" || -z "$output_json" || -z "$output_md" ]]; then
  echo "fake missing checklist missing required args"
  exit 7
fi

mkdir -p "$(dirname "$output_json")" "$(dirname "$output_md")"
missing_keys="$(jq -c '(.required_missing_metrics // []) | if type == "array" then . else [] end | map(select(type == "string" and length > 0))' "$metrics_summary_json" 2>/dev/null || printf '%s' '[]')"

jq -n \
  --arg metrics_summary_json "$metrics_summary_json" \
  --arg output_json "$output_json" \
  --arg output_md "$output_md" \
  --argjson missing_keys "$missing_keys" \
  '{
    status: (if ($missing_keys | length) == 0 then "complete" else "missing" end),
    missing_count: ($missing_keys | length),
    missing_keys: $missing_keys,
    checklist: ($missing_keys | map({key: ., category: "required", comparator: ">=", threshold: "see gate", unit: "metric", hint: "Collect evidence and rerun activation gate cycle."})),
    artifacts: {
      metrics_summary_json: $metrics_summary_json,
      output_json: $output_json,
      output_md: $output_md
    }
  }' >"$output_json"

{
  printf '%s\n' "# fake missing metrics checklist"
  printf '%s\n' "status: $(jq -r '.status' "$output_json")"
  printf '%s\n' "missing_count: $(jq -r '.missing_count' "$output_json")"
} >"$output_md"

rc="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_FAKE_MISSING_CHECKLIST_RC:-0}"
if [[ "$rc" =~ ^-?[0-9]+$ ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_MISSING_CHECKLIST
chmod +x "$FAKE_MISSING_CHECKLIST"

FAKE_ROADMAP="$TMP_DIR/fake_roadmap.sh"
cat >"$FAKE_ROADMAP" <<'EOF_FAKE_ROADMAP'
#!/usr/bin/env bash
set -euo pipefail

capture="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_CAPTURE_FILE:?}"
{
  printf '%s' "roadmap_refresh"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture"

summary_json=""
report_md=""
activation_summary_json=""
bootstrap_summary_json=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --report-md)
      report_md="${2:-}"
      shift 2
      ;;
    --blockchain-mainnet-activation-gate-summary-json)
      activation_summary_json="${2:-}"
      shift 2
      ;;
    --blockchain-bootstrap-governance-graduation-gate-summary-json)
      bootstrap_summary_json="${2:-}"
      shift 2
      ;;
    --refresh-manual-validation|--refresh-single-machine-readiness|--print-summary-json|--print-report)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        shift 2
      else
        shift
      fi
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" || -z "$report_md" || -z "$activation_summary_json" || -z "$bootstrap_summary_json" ]]; then
  echo "fake roadmap refresh missing required args"
  exit 7
fi

mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"
jq -n \
  --arg activation_summary_json "$activation_summary_json" \
  --arg bootstrap_summary_json "$bootstrap_summary_json" \
  '{
    status: "pass",
    rc: 0,
    blockchain_track: {
      mainnet_activation_gate: { source_summary_json: $activation_summary_json },
      bootstrap_governance_graduation_gate: { source_summary_json: $bootstrap_summary_json }
    }
  }' >"$summary_json"
cat >"$report_md" <<'EOF_REPORT'
# fake roadmap report
EOF_REPORT

rc="${BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_FAKE_ROADMAP_RC:-0}"
if [[ "$rc" =~ ^-?[0-9]+$ ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_ROADMAP
chmod +x "$FAKE_ROADMAP"

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

run_cycle() {
  BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_CAPTURE_FILE="$CAPTURE" \
  BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_METRICS_INPUT_TEMPLATE_SCRIPT="$FAKE_METRICS_INPUT_TEMPLATE" \
  BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_METRICS_INPUT_SCRIPT="$FAKE_METRICS_INPUT" \
  BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_GATE_BUNDLE_SCRIPT="$FAKE_GATE_BUNDLE" \
  BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_METRICS_MISSING_CHECKLIST_SCRIPT="$FAKE_MISSING_CHECKLIST" \
  BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
  "$SCRIPT_UNDER_TEST" "$@"
}

echo "[blockchain-mainnet-activation-gate-cycle] pass wiring path"
: >"$CAPTURE"
if ! run_cycle \
  --input-json "$PASS_INPUT_JSON" \
  --reports-dir "$PASS_REPORTS_DIR" \
  --summary-json "$PASS_SUMMARY_JSON" \
  --canonical-summary-json "$PASS_CANONICAL_SUMMARY_JSON" \
  --print-summary-json 0 >"$PASS_LOG" 2>&1; then
  echo "expected pass cycle run to exit 0"
  cat "$PASS_LOG"
  exit 1
fi

PASS_METRICS_INPUT_SUMMARY_JSON="$PASS_REPORTS_DIR/blockchain_mainnet_activation_metrics_input_summary.json"
PASS_METRICS_INPUT_CANONICAL_JSON="$PASS_REPORTS_DIR/blockchain_mainnet_activation_metrics_input.json"
PASS_BUNDLE_SUMMARY_JSON="$PASS_REPORTS_DIR/blockchain_gate_bundle_summary.json"
PASS_BUNDLE_CANONICAL_SUMMARY_JSON="$PASS_REPORTS_DIR/blockchain_gate_bundle_canonical_summary.json"
PASS_BUNDLE_METRICS_JSON="$PASS_REPORTS_DIR/blockchain_mainnet_activation_metrics.json"
PASS_BUNDLE_METRICS_SUMMARY_JSON="$PASS_REPORTS_DIR/blockchain_mainnet_activation_metrics_summary.json"
PASS_BUNDLE_ACTIVATION_SUMMARY_JSON="$PASS_REPORTS_DIR/blockchain_mainnet_activation_gate_summary.json"
PASS_BUNDLE_BOOTSTRAP_SUMMARY_JSON="$PASS_REPORTS_DIR/blockchain_bootstrap_governance_graduation_gate_summary.json"
PASS_MISSING_CHECKLIST_JSON="$PASS_REPORTS_DIR/blockchain_mainnet_activation_metrics_missing_checklist.json"
PASS_MISSING_CHECKLIST_MD="$PASS_REPORTS_DIR/blockchain_mainnet_activation_metrics_missing_checklist.md"
PASS_ROADMAP_SUMMARY_JSON="$PASS_REPORTS_DIR/roadmap_progress_summary.json"
PASS_ROADMAP_REPORT_MD="$PASS_REPORTS_DIR/roadmap_progress_report.md"

assert_stage_order "$CAPTURE" "metrics_input" "gate_bundle" "missing_metrics_checklist" "roadmap_refresh"
assert_stage_invocation_contains "$CAPTURE" "metrics_input" \
  "--input-json" "$PASS_INPUT_JSON" \
  "--summary-json" "$PASS_METRICS_INPUT_SUMMARY_JSON" \
  "--canonical-summary-json" "$PASS_METRICS_INPUT_CANONICAL_JSON"
assert_stage_invocation_contains "$CAPTURE" "gate_bundle" \
  "--reports-dir" "$PASS_REPORTS_DIR" \
  "--summary-json" "$PASS_BUNDLE_SUMMARY_JSON" \
  "--canonical-summary-json" "$PASS_BUNDLE_CANONICAL_SUMMARY_JSON" \
  "--metrics-json" "$PASS_BUNDLE_METRICS_JSON" \
  "--metrics-summary-json" "$PASS_BUNDLE_METRICS_SUMMARY_JSON" \
  "--blockchain-mainnet-activation-metrics-input-json" "$PASS_INPUT_JSON" \
  "--blockchain-mainnet-activation-metrics-input-summary-json" "$PASS_METRICS_INPUT_SUMMARY_JSON" \
  "--blockchain-mainnet-activation-metrics-input-canonical-json" "$PASS_METRICS_INPUT_CANONICAL_JSON" \
  "--activation-summary-json" "$PASS_BUNDLE_ACTIVATION_SUMMARY_JSON" \
  "--bootstrap-summary-json" "$PASS_BUNDLE_BOOTSTRAP_SUMMARY_JSON"
assert_stage_invocation_contains "$CAPTURE" "missing_metrics_checklist" \
  "--metrics-summary-json" "$PASS_BUNDLE_METRICS_SUMMARY_JSON" \
  "--output-json" "$PASS_MISSING_CHECKLIST_JSON" \
  "--output-md" "$PASS_MISSING_CHECKLIST_MD"
assert_stage_invocation_contains "$CAPTURE" "roadmap_refresh" \
  "--refresh-manual-validation" "0" \
  "--refresh-single-machine-readiness" "0" \
  "--summary-json" "$PASS_ROADMAP_SUMMARY_JSON" \
  "--report-md" "$PASS_ROADMAP_REPORT_MD" \
  "--blockchain-mainnet-activation-gate-summary-json" "$PASS_BUNDLE_ACTIVATION_SUMMARY_JSON" \
  "--blockchain-bootstrap-governance-graduation-gate-summary-json" "$PASS_BUNDLE_BOOTSTRAP_SUMMARY_JSON"

if [[ ! -f "$PASS_SUMMARY_JSON" || ! -f "$PASS_CANONICAL_SUMMARY_JSON" ]]; then
  echo "missing pass cycle summary artifacts"
  ls -la "$TMP_DIR"
  cat "$PASS_LOG"
  exit 1
fi
if ! cmp -s "$PASS_SUMMARY_JSON" "$PASS_CANONICAL_SUMMARY_JSON"; then
  echo "canonical pass summary mismatch"
  cat "$PASS_SUMMARY_JSON"
  cat "$PASS_CANONICAL_SUMMARY_JSON"
  exit 1
fi

if ! jq -e \
  --arg input_json "$PASS_INPUT_JSON" \
  --arg reports_dir "$PASS_REPORTS_DIR" \
  --arg missing_checklist_json "$PASS_MISSING_CHECKLIST_JSON" \
  --arg missing_checklist_md "$PASS_MISSING_CHECKLIST_MD" \
  --arg roadmap_summary_json "$PASS_ROADMAP_SUMMARY_JSON" \
  '
  .status == "pass"
  and .rc == 0
  and .decision == "GO"
  and .inputs.input_json == $input_json
  and .inputs.emit_missing_checklist == true
  and .inputs.refresh_roadmap == true
  and .steps.metrics_input.status == "pass"
  and .steps.gate_bundle.status == "pass"
  and .steps.missing_metrics_checklist.enabled == true
  and .steps.missing_metrics_checklist.status == "pass"
  and .steps.missing_metrics_checklist.checklist_status == "complete"
  and .steps.missing_metrics_checklist.missing_count == 0
  and (.steps.missing_metrics_checklist.missing_keys | length) == 0
  and .steps.missing_metrics_checklist.artifacts.checklist_json == $missing_checklist_json
  and .steps.missing_metrics_checklist.artifacts.checklist_md == $missing_checklist_md
  and .steps.roadmap_refresh.enabled == true
  and .steps.roadmap_refresh.status == "pass"
  and .artifacts.reports_dir == $reports_dir
  and .artifacts.missing_metrics_checklist_json == $missing_checklist_json
  and .artifacts.missing_metrics_checklist_md == $missing_checklist_md
  and .artifacts.roadmap_summary_json == $roadmap_summary_json
  ' "$PASS_SUMMARY_JSON" >/dev/null; then
  echo "pass cycle summary contract mismatch"
  cat "$PASS_SUMMARY_JSON"
  cat "$PASS_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-gate-cycle] logical NO-GO still exits 0"
: >"$CAPTURE"
set +e
BLOCKCHAIN_MAINNET_ACTIVATION_GATE_CYCLE_FAKE_GATE_BUNDLE_DECISION="NO-GO" \
run_cycle \
  --input-json "$NO_GO_INPUT_JSON" \
  --reports-dir "$NO_GO_REPORTS_DIR" \
  --summary-json "$NO_GO_SUMMARY_JSON" \
  --canonical-summary-json "$NO_GO_CANONICAL_SUMMARY_JSON" \
  --print-summary-json 0 >"$NO_GO_LOG" 2>&1
no_go_rc=$?
set -e
if [[ "$no_go_rc" -ne 0 ]]; then
  echo "expected logical NO-GO cycle run to exit 0"
  cat "$NO_GO_LOG"
  exit 1
fi

NO_GO_BUNDLE_METRICS_SUMMARY_JSON="$NO_GO_REPORTS_DIR/blockchain_mainnet_activation_metrics_summary.json"
NO_GO_MISSING_CHECKLIST_JSON="$NO_GO_REPORTS_DIR/blockchain_mainnet_activation_metrics_missing_checklist.json"
NO_GO_MISSING_CHECKLIST_MD="$NO_GO_REPORTS_DIR/blockchain_mainnet_activation_metrics_missing_checklist.md"
assert_stage_order "$CAPTURE" "metrics_input" "gate_bundle" "missing_metrics_checklist" "roadmap_refresh"
assert_stage_invocation_contains "$CAPTURE" "missing_metrics_checklist" \
  "--metrics-summary-json" "$NO_GO_BUNDLE_METRICS_SUMMARY_JSON" \
  "--output-json" "$NO_GO_MISSING_CHECKLIST_JSON" \
  "--output-md" "$NO_GO_MISSING_CHECKLIST_MD"

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .decision == "NO-GO"
  and .steps.gate_bundle.status == "pass"
  and .steps.gate_bundle.decision == "NO-GO"
  and ((.steps.gate_bundle.missing_required_metrics | index("measurement_window_weeks")) != null)
  and ((.steps.gate_bundle.missing_required_metrics | index("vpn_recovery_mttr_p95_minutes")) != null)
  and .steps.missing_metrics_checklist.status == "pass"
  and .steps.missing_metrics_checklist.checklist_status == "missing"
  and ((.steps.missing_metrics_checklist.missing_keys | index("measurement_window_weeks")) != null)
  and ((.steps.missing_metrics_checklist.missing_keys | index("vpn_recovery_mttr_p95_minutes")) != null)
  and .steps.missing_metrics_checklist.missing_count == 2
  and .artifacts.missing_metrics_checklist_json != null
  and .artifacts.missing_metrics_checklist_md != null
' "$NO_GO_SUMMARY_JSON" >/dev/null; then
  echo "logical NO-GO summary contract mismatch"
  cat "$NO_GO_SUMMARY_JSON"
  cat "$NO_GO_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-gate-cycle] seed-example mode without input file"
: >"$CAPTURE"
if ! run_cycle \
  --seed-example-input 1 \
  --reports-dir "$SEED_REPORTS_DIR" \
  --summary-json "$SEED_SUMMARY_JSON" \
  --canonical-summary-json "$SEED_CANONICAL_SUMMARY_JSON" \
  --print-summary-json 0 >"$SEED_LOG" 2>&1; then
  echo "expected seed-example cycle run to exit 0"
  cat "$SEED_LOG"
  exit 1
fi

SEED_INPUT_JSON="$SEED_REPORTS_DIR/blockchain_mainnet_activation_metrics_input.seed.json"
SEED_INPUT_CANONICAL_JSON="$SEED_REPORTS_DIR/blockchain_mainnet_activation_metrics_input.seed.canonical.json"
SEED_METRICS_INPUT_SUMMARY_JSON="$SEED_REPORTS_DIR/blockchain_mainnet_activation_metrics_input_summary.json"
SEED_METRICS_INPUT_CANONICAL_JSON="$SEED_REPORTS_DIR/blockchain_mainnet_activation_metrics_input.json"
SEED_BUNDLE_SUMMARY_JSON="$SEED_REPORTS_DIR/blockchain_gate_bundle_summary.json"
SEED_BUNDLE_CANONICAL_SUMMARY_JSON="$SEED_REPORTS_DIR/blockchain_gate_bundle_canonical_summary.json"
SEED_BUNDLE_METRICS_JSON="$SEED_REPORTS_DIR/blockchain_mainnet_activation_metrics.json"
SEED_BUNDLE_METRICS_SUMMARY_JSON="$SEED_REPORTS_DIR/blockchain_mainnet_activation_metrics_summary.json"
SEED_BUNDLE_ACTIVATION_SUMMARY_JSON="$SEED_REPORTS_DIR/blockchain_mainnet_activation_gate_summary.json"
SEED_BUNDLE_BOOTSTRAP_SUMMARY_JSON="$SEED_REPORTS_DIR/blockchain_bootstrap_governance_graduation_gate_summary.json"
SEED_MISSING_CHECKLIST_JSON="$SEED_REPORTS_DIR/blockchain_mainnet_activation_metrics_missing_checklist.json"
SEED_MISSING_CHECKLIST_MD="$SEED_REPORTS_DIR/blockchain_mainnet_activation_metrics_missing_checklist.md"
SEED_ROADMAP_SUMMARY_JSON="$SEED_REPORTS_DIR/roadmap_progress_summary.json"
SEED_ROADMAP_REPORT_MD="$SEED_REPORTS_DIR/roadmap_progress_report.md"

assert_stage_order "$CAPTURE" "metrics_input_template" "metrics_input" "gate_bundle" "missing_metrics_checklist" "roadmap_refresh"
assert_stage_invocation_contains "$CAPTURE" "metrics_input_template" \
  "--output-json" "$SEED_INPUT_JSON" \
  "--canonical-output-json" "$SEED_INPUT_CANONICAL_JSON" \
  "--include-example-values" "1"
assert_stage_invocation_contains "$CAPTURE" "metrics_input" \
  "--input-json" "$SEED_INPUT_JSON" \
  "--summary-json" "$SEED_METRICS_INPUT_SUMMARY_JSON" \
  "--canonical-summary-json" "$SEED_METRICS_INPUT_CANONICAL_JSON"
assert_stage_invocation_contains "$CAPTURE" "gate_bundle" \
  "--reports-dir" "$SEED_REPORTS_DIR" \
  "--summary-json" "$SEED_BUNDLE_SUMMARY_JSON" \
  "--canonical-summary-json" "$SEED_BUNDLE_CANONICAL_SUMMARY_JSON" \
  "--metrics-json" "$SEED_BUNDLE_METRICS_JSON" \
  "--metrics-summary-json" "$SEED_BUNDLE_METRICS_SUMMARY_JSON" \
  "--blockchain-mainnet-activation-metrics-input-json" "$SEED_INPUT_JSON" \
  "--blockchain-mainnet-activation-metrics-input-summary-json" "$SEED_METRICS_INPUT_SUMMARY_JSON" \
  "--blockchain-mainnet-activation-metrics-input-canonical-json" "$SEED_METRICS_INPUT_CANONICAL_JSON" \
  "--activation-summary-json" "$SEED_BUNDLE_ACTIVATION_SUMMARY_JSON" \
  "--bootstrap-summary-json" "$SEED_BUNDLE_BOOTSTRAP_SUMMARY_JSON"
assert_stage_invocation_contains "$CAPTURE" "missing_metrics_checklist" \
  "--metrics-summary-json" "$SEED_BUNDLE_METRICS_SUMMARY_JSON" \
  "--output-json" "$SEED_MISSING_CHECKLIST_JSON" \
  "--output-md" "$SEED_MISSING_CHECKLIST_MD"
assert_stage_invocation_contains "$CAPTURE" "roadmap_refresh" \
  "--summary-json" "$SEED_ROADMAP_SUMMARY_JSON" \
  "--report-md" "$SEED_ROADMAP_REPORT_MD"

if [[ ! -f "$SEED_SUMMARY_JSON" || ! -f "$SEED_CANONICAL_SUMMARY_JSON" ]]; then
  echo "missing seed-example cycle summary artifacts"
  ls -la "$TMP_DIR"
  cat "$SEED_LOG"
  exit 1
fi
if ! cmp -s "$SEED_SUMMARY_JSON" "$SEED_CANONICAL_SUMMARY_JSON"; then
  echo "canonical seed-example summary mismatch"
  cat "$SEED_SUMMARY_JSON"
  cat "$SEED_CANONICAL_SUMMARY_JSON"
  exit 1
fi
if ! jq -e \
  --arg reports_dir "$SEED_REPORTS_DIR" \
  --arg seeded_input_json "$SEED_INPUT_JSON" \
  --arg seeded_input_canonical_json "$SEED_INPUT_CANONICAL_JSON" \
  --arg missing_checklist_json "$SEED_MISSING_CHECKLIST_JSON" \
  --arg missing_checklist_md "$SEED_MISSING_CHECKLIST_MD" \
  '
  .status == "pass"
  and .rc == 0
  and .decision == "GO"
  and .inputs.seed_example_input == true
  and .inputs.input_json == $seeded_input_json
  and .steps.metrics_input_template.enabled == true
  and .steps.metrics_input_template.status == "pass"
  and .steps.metrics_input_template.rc == 0
  and .steps.metrics_input_template.artifacts.summary_json == $seeded_input_json
  and .steps.metrics_input_template.artifacts.canonical_summary_json == $seeded_input_canonical_json
  and .steps.metrics_input_template.artifacts.seeded_input_json == $seeded_input_json
  and .steps.metrics_input.status == "pass"
  and .steps.gate_bundle.status == "pass"
  and .steps.missing_metrics_checklist.status == "pass"
  and .steps.missing_metrics_checklist.checklist_status == "complete"
  and .steps.missing_metrics_checklist.artifacts.checklist_json == $missing_checklist_json
  and .steps.missing_metrics_checklist.artifacts.checklist_md == $missing_checklist_md
  and .steps.roadmap_refresh.status == "pass"
  and .artifacts.reports_dir == $reports_dir
  and .artifacts.seeded_input_json == $seeded_input_json
  and .artifacts.metrics_input_template_summary_json == $seeded_input_json
  and .artifacts.metrics_input_template_canonical_json == $seeded_input_canonical_json
  and .artifacts.missing_metrics_checklist_json == $missing_checklist_json
  and .artifacts.missing_metrics_checklist_md == $missing_checklist_md
  ' "$SEED_SUMMARY_JSON" >/dev/null; then
  echo "seed-example summary contract mismatch"
  cat "$SEED_SUMMARY_JSON"
  cat "$SEED_LOG"
  exit 1
fi

echo "[blockchain-mainnet-activation-gate-cycle] required arg validation"
set +e
run_cycle \
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

echo "[blockchain-mainnet-activation-gate-cycle] roadmap refresh toggle behavior"
: >"$CAPTURE"
if ! run_cycle \
  --input-json "$TOGGLE_INPUT_JSON" \
  --reports-dir "$TOGGLE_REPORTS_DIR" \
  --summary-json "$TOGGLE_SUMMARY_JSON" \
  --canonical-summary-json "$TOGGLE_CANONICAL_SUMMARY_JSON" \
  --refresh-roadmap 0 \
  --print-summary-json 0 >"$TOGGLE_LOG" 2>&1; then
  echo "expected refresh-roadmap=0 path to exit 0"
  cat "$TOGGLE_LOG"
  exit 1
fi

assert_stage_order "$CAPTURE" "metrics_input" "gate_bundle" "missing_metrics_checklist"
if grep -Fq "roadmap_refresh" "$CAPTURE"; then
  echo "roadmap_refresh stage should not run when --refresh-roadmap=0"
  cat "$CAPTURE"
  exit 1
fi

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.refresh_roadmap == false
  and .inputs.emit_missing_checklist == true
  and .steps.missing_metrics_checklist.enabled == true
  and .steps.missing_metrics_checklist.status == "pass"
  and .steps.missing_metrics_checklist.checklist_status == "complete"
  and .steps.missing_metrics_checklist.missing_count == 0
  and .artifacts.missing_metrics_checklist_json != null
  and .artifacts.missing_metrics_checklist_md != null
  and .steps.roadmap_refresh.enabled == false
  and .steps.roadmap_refresh.status == "skipped"
  and .steps.roadmap_refresh.rc == 0
  and .artifacts.roadmap_summary_json == null
  and .artifacts.roadmap_report_md == null
' "$TOGGLE_SUMMARY_JSON" >/dev/null; then
  echo "refresh toggle summary contract mismatch"
  cat "$TOGGLE_SUMMARY_JSON"
  cat "$TOGGLE_LOG"
  exit 1
fi

echo "blockchain mainnet activation gate cycle integration ok"
