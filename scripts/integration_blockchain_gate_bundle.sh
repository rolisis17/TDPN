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

SCRIPT_UNDER_TEST="${BLOCKCHAIN_GATE_BUNDLE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/blockchain_gate_bundle.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/stage_calls.tsv"

PASS_REPORTS_DIR="$TMP_DIR/reports_pass"
PASS_SUMMARY_JSON="$TMP_DIR/summary_pass.json"
PASS_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_pass.json"
PASS_METRICS_JSON="$TMP_DIR/metrics_pass.json"
PASS_METRICS_SUMMARY_JSON="$TMP_DIR/metrics_summary_pass.json"
PASS_METRICS_INPUT_JSON="$TMP_DIR/metrics_input_pass.json"
PASS_METRICS_INPUT_SUMMARY_JSON="$PASS_REPORTS_DIR/blockchain_mainnet_activation_metrics_input_summary.json"
PASS_METRICS_INPUT_CANONICAL_JSON="$PASS_REPORTS_DIR/blockchain_mainnet_activation_metrics_input.json"
PASS_ACTIVATION_SUMMARY_JSON="$TMP_DIR/activation_summary_pass.json"
PASS_BOOTSTRAP_SUMMARY_JSON="$TMP_DIR/bootstrap_summary_pass.json"
PASS_LOG="$TMP_DIR/pass.log"

NO_GO_REPORTS_DIR="$TMP_DIR/reports_no_go"
NO_GO_SUMMARY_JSON="$TMP_DIR/summary_no_go.json"
NO_GO_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_no_go.json"
NO_GO_ACTIVATION_SUMMARY_JSON="$NO_GO_REPORTS_DIR/blockchain_mainnet_activation_gate_summary.json"
NO_GO_BOOTSTRAP_SUMMARY_JSON="$NO_GO_REPORTS_DIR/blockchain_bootstrap_governance_graduation_gate_summary.json"
NO_GO_LOG="$TMP_DIR/no_go.log"

FAIL_COSMOS_REPORTS_DIR="$TMP_DIR/reports_fail_cosmos"
FAIL_COSMOS_SUMMARY_JSON="$TMP_DIR/summary_fail_cosmos.json"
FAIL_COSMOS_CANONICAL_SUMMARY_JSON="$TMP_DIR/canonical_fail_cosmos.json"
FAIL_COSMOS_LOG="$TMP_DIR/fail_cosmos.log"

INVALID_SOURCE_REPORTS_DIR="$TMP_DIR/reports_invalid_source"
INVALID_SOURCE_SUMMARY_JSON="$TMP_DIR/summary_invalid_source.json"
INVALID_SOURCE_LOG="$TMP_DIR/invalid_source.log"

SOURCE_A="$TMP_DIR/source_a.json"
SOURCE_B="$TMP_DIR/source_b.json"
SOURCE_INVALID_JSON="$TMP_DIR/source_invalid.json"

cat >"$SOURCE_A" <<'EOF_SOURCE_A'
{"from":"a"}
EOF_SOURCE_A
cat >"$SOURCE_B" <<'EOF_SOURCE_B'
{"from":"b"}
EOF_SOURCE_B
cat >"$SOURCE_INVALID_JSON" <<'EOF_SOURCE_INVALID_JSON'
{"from":"broken"
EOF_SOURCE_INVALID_JSON
cat >"$PASS_METRICS_INPUT_JSON" <<'EOF_PASS_METRICS_INPUT_JSON'
{
  "measurement_window_weeks": 12,
  "reliability": {
    "vpn_connect_session_success_slo_pct": 99.9,
    "vpn_recovery_mttr_p95_minutes": 10
  },
  "demand": {
    "paying_users_3mo_min": 1500
  }
}
EOF_PASS_METRICS_INPUT_JSON

FAKE_COSMOS_ONLY_GUARDRAIL="$TMP_DIR/fake_cosmos_only_guardrail.sh"
cat >"$FAKE_COSMOS_ONLY_GUARDRAIL" <<'EOF_FAKE_COSMOS_ONLY_GUARDRAIL'
#!/usr/bin/env bash
set -euo pipefail

capture="${BLOCKCHAIN_GATE_BUNDLE_CAPTURE_FILE:?}"
all_args=("$@")
{
  printf '%s' "cosmos_only_guardrail"
  for arg in "${all_args[@]}"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture"

guardrail_rc="${BLOCKCHAIN_GATE_BUNDLE_FAKE_COSMOS_ONLY_GUARDRAIL_RC:-0}"
if [[ "$guardrail_rc" =~ ^-?[0-9]+$ ]]; then
  exit "$guardrail_rc"
fi
exit 0
EOF_FAKE_COSMOS_ONLY_GUARDRAIL
chmod +x "$FAKE_COSMOS_ONLY_GUARDRAIL"

FAKE_METRICS="$TMP_DIR/fake_metrics.sh"
cat >"$FAKE_METRICS" <<'EOF_FAKE_METRICS'
#!/usr/bin/env bash
set -euo pipefail

capture="${BLOCKCHAIN_GATE_BUNDLE_CAPTURE_FILE:?}"
all_args=("$@")
{
  printf '%s' "metrics"
  for arg in "${all_args[@]}"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture"

summary_json=""
canonical_json=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --canonical-summary-json|--canonical-metrics-json)
      canonical_json="${2:-}"
      shift 2
      ;;
    --print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        shift 2
      else
        shift
      fi
      ;;
    --source-json)
      shift 2
      ;;
    --measurement-window-weeks|--vpn-connect-session-success-slo-pct|--vpn-recovery-mttr-p95-minutes|--paying-users-3mo-min|--paid-sessions-per-day-30d-avg|--validator-candidate-depth|--validator-independent-operators|--validator-max-operator-seat-share-pct|--validator-max-asn-provider-seat-share-pct|--validator-region-count|--validator-country-count|--manual-sanctions-reversed-pct-90d|--abuse-report-to-decision-p95-hours|--subsidy-runway-months|--contribution-margin-3mo)
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" || -z "$canonical_json" ]]; then
  echo "fake metrics missing required output paths"
  exit 7
fi

mkdir -p "$(dirname "$summary_json")" "$(dirname "$canonical_json")"

missing_csv="${BLOCKCHAIN_GATE_BUNDLE_FAKE_METRICS_MISSING_REQUIRED_CSV:-}"
if [[ -n "$missing_csv" ]]; then
  missing_json="$(printf '%s' "$missing_csv" | tr ',' '\n' | sed '/^$/d' | jq -R . | jq -s .)"
else
  missing_json='[]'
fi

ready_json='true'
if [[ "${BLOCKCHAIN_GATE_BUNDLE_FAKE_METRICS_READY_FOR_GATE:-1}" != "1" ]]; then
  ready_json='false'
fi

jq -n \
  --argjson missing "$missing_json" \
  --argjson ready "$ready_json" \
  '{
    required_missing_metrics: $missing,
    ready_for_gate: $ready,
    status: (if $ready then "complete" else "partial" end)
  }' >"$summary_json"

jq -n '{measurement_window_weeks: 12}' >"$canonical_json"

metrics_rc="${BLOCKCHAIN_GATE_BUNDLE_FAKE_METRICS_RC:-0}"
if [[ "$metrics_rc" =~ ^-?[0-9]+$ ]]; then
  exit "$metrics_rc"
fi
exit 0
EOF_FAKE_METRICS
chmod +x "$FAKE_METRICS"

FAKE_ACTIVATION="$TMP_DIR/fake_activation_gate.sh"
cat >"$FAKE_ACTIVATION" <<'EOF_FAKE_ACTIVATION'
#!/usr/bin/env bash
set -euo pipefail

capture="${BLOCKCHAIN_GATE_BUNDLE_CAPTURE_FILE:?}"
all_args=("$@")
{
  printf '%s' "activation"
  for arg in "${all_args[@]}"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture"

summary_json=""
metrics_json=""
fail_close=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --metrics-json)
      metrics_json="${2:-}"
      shift 2
      ;;
    --fail-close)
      fail_close="${2:-}"
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

if [[ -z "$summary_json" || -z "$metrics_json" || -z "$fail_close" ]]; then
  echo "fake activation gate missing required args"
  exit 7
fi

decision="${BLOCKCHAIN_GATE_BUNDLE_FAKE_ACTIVATION_DECISION:-GO}"
if [[ "$decision" != "GO" ]]; then
  decision="NO-GO"
fi
generated_at="${BLOCKCHAIN_GATE_BUNDLE_FAKE_ACTIVATION_GENERATED_AT:-2026-01-01T00:00:00Z}"

mkdir -p "$(dirname "$summary_json")"
jq -n \
  --arg decision "$decision" \
  --arg generated_at "$generated_at" \
  --arg metrics_json "$metrics_json" \
  '{
    generated_at: $generated_at,
    decision: $decision,
    status: (if $decision == "GO" then "go" else "no-go" end),
    rc: (if $decision == "GO" then 0 else 1 end),
    exit_code: 0,
    artifacts: {
      metrics_json: $metrics_json
    }
  }' >"$summary_json"

activation_rc="${BLOCKCHAIN_GATE_BUNDLE_FAKE_ACTIVATION_RC:-0}"
if [[ "$activation_rc" =~ ^-?[0-9]+$ ]]; then
  exit "$activation_rc"
fi
exit 0
EOF_FAKE_ACTIVATION
chmod +x "$FAKE_ACTIVATION"

FAKE_BOOTSTRAP="$TMP_DIR/fake_bootstrap_gate.sh"
cat >"$FAKE_BOOTSTRAP" <<'EOF_FAKE_BOOTSTRAP'
#!/usr/bin/env bash
set -euo pipefail

capture="${BLOCKCHAIN_GATE_BUNDLE_CAPTURE_FILE:?}"
all_args=("$@")
{
  printf '%s' "bootstrap"
  for arg in "${all_args[@]}"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture"

summary_json=""
metrics_json=""
fail_close=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --metrics-json)
      metrics_json="${2:-}"
      shift 2
      ;;
    --fail-close)
      fail_close="${2:-}"
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

if [[ -z "$summary_json" || -z "$metrics_json" || -z "$fail_close" ]]; then
  echo "fake bootstrap gate missing required args"
  exit 7
fi

decision="${BLOCKCHAIN_GATE_BUNDLE_FAKE_BOOTSTRAP_DECISION:-GO}"
if [[ "$decision" != "GO" ]]; then
  decision="NO-GO"
fi
generated_at="${BLOCKCHAIN_GATE_BUNDLE_FAKE_BOOTSTRAP_GENERATED_AT:-2026-01-01T00:00:00Z}"

mkdir -p "$(dirname "$summary_json")"
jq -n \
  --arg decision "$decision" \
  --arg generated_at "$generated_at" \
  --arg metrics_json "$metrics_json" \
  '{
    generated_at: $generated_at,
    decision: $decision,
    status: (if $decision == "GO" then "go" else "no-go" end),
    rc: (if $decision == "GO" then 0 else 1 end),
    exit_code: 0,
    artifacts: {
      metrics_json: $metrics_json
    }
  }' >"$summary_json"

bootstrap_rc="${BLOCKCHAIN_GATE_BUNDLE_FAKE_BOOTSTRAP_RC:-0}"
if [[ "$bootstrap_rc" =~ ^-?[0-9]+$ ]]; then
  exit "$bootstrap_rc"
fi
exit 0
EOF_FAKE_BOOTSTRAP
chmod +x "$FAKE_BOOTSTRAP"

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

assert_stage_invocation_token_count() {
  local capture_file="$1"
  local stage_id="$2"
  local token="$3"
  local expected_count="$4"
  local line actual_count

  line="$(awk -F $'\t' -v stage="$stage_id" '$1 == stage { print; exit }' "$capture_file")"
  if [[ -z "$line" ]]; then
    echo "missing stage invocation: $stage_id"
    cat "$capture_file"
    exit 1
  fi

  actual_count="$(awk -F $'\t' -v stage="$stage_id" -v token="$token" '
    $1 == stage {
      c = 0
      for (i = 2; i <= NF; i++) {
        if ($i == token) c++
      }
      print c
      exit
    }
  ' "$capture_file")"

  if [[ "$actual_count" != "$expected_count" ]]; then
    echo "stage $stage_id token count mismatch for $token: expected $expected_count got $actual_count"
    cat "$capture_file"
    exit 1
  fi
}

assert_generated_at_iso_utc() {
  local summary_json_path="$1"
  local label="$2"

  if [[ ! -f "$summary_json_path" ]]; then
    echo "missing $label summary artifact: $summary_json_path"
    exit 1
  fi

  if ! jq -e '
    (.generated_at | type) == "string"
    and (.generated_at | length) > 0
    and (.generated_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
  ' "$summary_json_path" >/dev/null; then
    echo "$label summary missing ISO UTC generated_at contract"
    cat "$summary_json_path"
    exit 1
  fi
}

run_bundle() {
  BLOCKCHAIN_GATE_BUNDLE_CAPTURE_FILE="$CAPTURE" \
  BLOCKCHAIN_GATE_BUNDLE_COSMOS_ONLY_GUARDRAIL_SCRIPT="$FAKE_COSMOS_ONLY_GUARDRAIL" \
  BLOCKCHAIN_GATE_BUNDLE_METRICS_SCRIPT="$FAKE_METRICS" \
  BLOCKCHAIN_GATE_BUNDLE_ACTIVATION_GATE_SCRIPT="$FAKE_ACTIVATION" \
  BLOCKCHAIN_GATE_BUNDLE_BOOTSTRAP_GATE_SCRIPT="$FAKE_BOOTSTRAP" \
  "$SCRIPT_UNDER_TEST" "$@"
}

echo "[blockchain-gate-bundle] pass path + forwarding"
: >"$CAPTURE"
if ! run_bundle \
  --reports-dir "$PASS_REPORTS_DIR" \
  --summary-json "$PASS_SUMMARY_JSON" \
  --canonical-summary-json "$PASS_CANONICAL_SUMMARY_JSON" \
  --metrics-json "$PASS_METRICS_JSON" \
  --metrics-summary-json "$PASS_METRICS_SUMMARY_JSON" \
  --blockchain-mainnet-activation-metrics-input-json "$PASS_METRICS_INPUT_JSON" \
  --activation-summary-json "$PASS_ACTIVATION_SUMMARY_JSON" \
  --bootstrap-summary-json "$PASS_BOOTSTRAP_SUMMARY_JSON" \
  --source-json "$SOURCE_A" \
  --source-json "$SOURCE_B" \
  --paying-users-3mo-min 1234 \
  --vpn-connect-session-success-slo-pct 99.95 \
  --print-summary-json 0 >"$PASS_LOG" 2>&1; then
  echo "expected pass path to exit 0"
  cat "$PASS_LOG"
  exit 1
fi

assert_stage_order "$CAPTURE" "cosmos_only_guardrail" "metrics" "activation" "bootstrap"
assert_stage_invocation_contains "$CAPTURE" "cosmos_only_guardrail"
assert_stage_invocation_contains "$CAPTURE" "metrics" \
  "--summary-json" "$PASS_METRICS_SUMMARY_JSON" \
  "--canonical-summary-json" "$PASS_METRICS_JSON" \
  "--source-json" "$PASS_METRICS_INPUT_CANONICAL_JSON" \
  "--source-json" "$SOURCE_A" \
  "$SOURCE_B" \
  "--paying-users-3mo-min" "1234" \
  "--vpn-connect-session-success-slo-pct" "99.95"
assert_stage_invocation_token_count "$CAPTURE" "metrics" "--source-json" 3
assert_stage_invocation_contains "$CAPTURE" "activation" \
  "--metrics-json" "$PASS_METRICS_JSON" \
  "--summary-json" "$PASS_ACTIVATION_SUMMARY_JSON" \
  "--fail-close" "0"
assert_stage_invocation_contains "$CAPTURE" "bootstrap" \
  "--metrics-json" "$PASS_METRICS_JSON" \
  "--summary-json" "$PASS_BOOTSTRAP_SUMMARY_JSON" \
  "--fail-close" "0"

if [[ ! -f "$PASS_SUMMARY_JSON" || ! -f "$PASS_CANONICAL_SUMMARY_JSON" ]]; then
  echo "missing pass summary artifacts"
  ls -la "$TMP_DIR"
  cat "$PASS_LOG"
  exit 1
fi
if [[ ! -f "$PASS_METRICS_INPUT_SUMMARY_JSON" || ! -f "$PASS_METRICS_INPUT_CANONICAL_JSON" ]]; then
  echo "missing metrics-input normalizer artifacts in pass path"
  ls -la "$PASS_REPORTS_DIR"
  cat "$PASS_LOG"
  exit 1
fi

if ! jq -e \
  --arg source_a "$SOURCE_A" \
  --arg source_b "$SOURCE_B" \
  --arg source_input "$PASS_METRICS_INPUT_CANONICAL_JSON" \
  --arg input_json "$PASS_METRICS_INPUT_JSON" \
  --arg input_summary_json "$PASS_METRICS_INPUT_SUMMARY_JSON" \
  --arg input_canonical_json "$PASS_METRICS_INPUT_CANONICAL_JSON" \
  --arg metrics_json "$PASS_METRICS_JSON" \
  --arg metrics_summary "$PASS_METRICS_SUMMARY_JSON" \
  --arg cosmos_only_guardrail_script "$FAKE_COSMOS_ONLY_GUARDRAIL" \
  --arg activation_summary "$PASS_ACTIVATION_SUMMARY_JSON" \
  --arg bootstrap_summary "$PASS_BOOTSTRAP_SUMMARY_JSON" \
  --arg canonical_summary "$PASS_CANONICAL_SUMMARY_JSON" \
  '
  .status == "pass"
  and .rc == 0
  and .decision == "GO"
  and (.missing_required_metrics | length) == 0
  and .steps.cosmos_only_guardrail.status == "pass"
  and .steps.cosmos_only_guardrail.rc == 0
  and .steps.cosmos_only_guardrail.artifacts.script == $cosmos_only_guardrail_script
  and .steps.metrics.status == "pass"
  and .steps.metrics.rc == 0
  and .steps.mainnet_activation_gate.decision == "GO"
  and .steps.bootstrap_graduation_gate.decision == "GO"
  and .artifacts.metrics_json == $metrics_json
  and .artifacts.metrics_summary_json == $metrics_summary
  and .artifacts.activation_summary_json == $activation_summary
  and .artifacts.bootstrap_summary_json == $bootstrap_summary
  and .artifacts.canonical_summary_json == $canonical_summary
  and .inputs.blockchain_mainnet_activation_metrics_input_json == $input_json
  and .inputs.blockchain_mainnet_activation_metrics_input_summary_json == $input_summary_json
  and .inputs.blockchain_mainnet_activation_metrics_input_canonical_json == $input_canonical_json
  and .artifacts.blockchain_mainnet_activation_metrics_input_json == $input_json
  and .artifacts.blockchain_mainnet_activation_metrics_input_summary_json == $input_summary_json
  and .artifacts.blockchain_mainnet_activation_metrics_input_canonical_json == $input_canonical_json
  and .steps.metrics.artifacts.metrics_input_json == $input_json
  and .steps.metrics.artifacts.metrics_input_summary_json == $input_summary_json
  and .steps.metrics.artifacts.metrics_input_canonical_json == $input_canonical_json
  and .steps.metrics.artifacts.source_jsons == [$source_a, $source_b, $source_input]
  ' "$PASS_SUMMARY_JSON" >/dev/null; then
  echo "pass summary contract mismatch"
  cat "$PASS_SUMMARY_JSON"
  cat "$PASS_LOG"
  exit 1
fi

if ! cmp -s "$PASS_SUMMARY_JSON" "$PASS_CANONICAL_SUMMARY_JSON"; then
  echo "canonical summary does not match pass summary"
  cat "$PASS_SUMMARY_JSON"
  cat "$PASS_CANONICAL_SUMMARY_JSON"
  exit 1
fi
assert_generated_at_iso_utc "$PASS_ACTIVATION_SUMMARY_JSON" "mainnet activation gate"
assert_generated_at_iso_utc "$PASS_BOOTSTRAP_SUMMARY_JSON" "bootstrap graduation gate"

echo "[blockchain-gate-bundle] cosmos-only guardrail fail-closed"
: >"$CAPTURE"
set +e
BLOCKCHAIN_GATE_BUNDLE_FAKE_COSMOS_ONLY_GUARDRAIL_RC="17" \
run_bundle \
  --reports-dir "$FAIL_COSMOS_REPORTS_DIR" \
  --summary-json "$FAIL_COSMOS_SUMMARY_JSON" \
  --canonical-summary-json "$FAIL_COSMOS_CANONICAL_SUMMARY_JSON" \
  --print-summary-json 0 >"$FAIL_COSMOS_LOG" 2>&1
fail_cosmos_rc=$?
set -e
if [[ "$fail_cosmos_rc" -ne 17 ]]; then
  echo "expected cosmos-only guardrail failure to exit 17"
  cat "$FAIL_COSMOS_LOG"
  exit 1
fi
assert_stage_order "$CAPTURE" "cosmos_only_guardrail"
if [[ ! -f "$FAIL_COSMOS_SUMMARY_JSON" || ! -f "$FAIL_COSMOS_CANONICAL_SUMMARY_JSON" ]]; then
  echo "missing cosmos failure summary artifacts"
  ls -la "$TMP_DIR"
  cat "$FAIL_COSMOS_LOG"
  exit 1
fi
if ! jq -e '
  .status == "runtime-fail"
  and .rc == 17
  and .first_runtime_failure.step == "cosmos_only_guardrail"
  and .first_runtime_failure.rc == 17
  and .steps.cosmos_only_guardrail.status == "fail"
  and .steps.cosmos_only_guardrail.rc == 17
  and .steps.metrics.status == "pending"
  and .steps.mainnet_activation_gate.status == "pending"
  and .steps.bootstrap_graduation_gate.status == "pending"
' "$FAIL_COSMOS_SUMMARY_JSON" >/dev/null; then
  echo "cosmos-only guardrail failure summary contract mismatch"
  cat "$FAIL_COSMOS_SUMMARY_JSON"
  cat "$FAIL_COSMOS_LOG"
  exit 1
fi
if ! cmp -s "$FAIL_COSMOS_SUMMARY_JSON" "$FAIL_COSMOS_CANONICAL_SUMMARY_JSON"; then
  echo "canonical summary does not match cosmos failure summary"
  cat "$FAIL_COSMOS_SUMMARY_JSON"
  cat "$FAIL_COSMOS_CANONICAL_SUMMARY_JSON"
  exit 1
fi

echo "[blockchain-gate-bundle] logical NO-GO remains exit 0"
: >"$CAPTURE"
set +e
BLOCKCHAIN_GATE_BUNDLE_FAKE_ACTIVATION_DECISION="NO-GO" \
BLOCKCHAIN_GATE_BUNDLE_FAKE_BOOTSTRAP_DECISION="GO" \
BLOCKCHAIN_GATE_BUNDLE_FAKE_METRICS_MISSING_REQUIRED_CSV="vpn_recovery_mttr_p95_minutes,validator_region_count" \
run_bundle \
  --reports-dir "$NO_GO_REPORTS_DIR" \
  --summary-json "$NO_GO_SUMMARY_JSON" \
  --canonical-summary-json "$NO_GO_CANONICAL_SUMMARY_JSON" \
  --print-summary-json 0 >"$NO_GO_LOG" 2>&1
no_go_rc=$?
set -e
if [[ "$no_go_rc" -ne 0 ]]; then
  echo "expected logical NO-GO bundle run to exit 0"
  cat "$NO_GO_LOG"
  exit 1
fi
assert_stage_order "$CAPTURE" "cosmos_only_guardrail" "metrics" "activation" "bootstrap"

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .decision == "NO-GO"
  and .steps.mainnet_activation_gate.decision == "NO-GO"
  and .steps.bootstrap_graduation_gate.decision == "GO"
  and ((.missing_required_metrics | index("vpn_recovery_mttr_p95_minutes")) != null)
  and ((.missing_required_metrics | index("validator_region_count")) != null)
' "$NO_GO_SUMMARY_JSON" >/dev/null; then
  echo "no-go summary contract mismatch"
  cat "$NO_GO_SUMMARY_JSON"
  cat "$NO_GO_LOG"
  exit 1
fi

if ! cmp -s "$NO_GO_SUMMARY_JSON" "$NO_GO_CANONICAL_SUMMARY_JSON"; then
  echo "canonical summary does not match no-go summary"
  cat "$NO_GO_SUMMARY_JSON"
  cat "$NO_GO_CANONICAL_SUMMARY_JSON"
  exit 1
fi
assert_generated_at_iso_utc "$NO_GO_ACTIVATION_SUMMARY_JSON" "mainnet activation gate"
assert_generated_at_iso_utc "$NO_GO_BOOTSTRAP_SUMMARY_JSON" "bootstrap graduation gate"

echo "[blockchain-gate-bundle] invalid --source-json fails closed before stage execution"
: >"$CAPTURE"
set +e
run_bundle \
  --reports-dir "$INVALID_SOURCE_REPORTS_DIR" \
  --summary-json "$INVALID_SOURCE_SUMMARY_JSON" \
  --source-json "$SOURCE_INVALID_JSON" \
  --print-summary-json 0 >"$INVALID_SOURCE_LOG" 2>&1
invalid_source_rc=$?
set -e
if [[ "$invalid_source_rc" -ne 2 ]]; then
  echo "expected invalid --source-json path to exit 2, got rc=$invalid_source_rc"
  cat "$INVALID_SOURCE_LOG"
  exit 1
fi
if ! grep -Fq "source json is invalid JSON: $SOURCE_INVALID_JSON" "$INVALID_SOURCE_LOG"; then
  echo "invalid source-json error message mismatch"
  cat "$INVALID_SOURCE_LOG"
  exit 1
fi
if [[ -f "$INVALID_SOURCE_SUMMARY_JSON" ]]; then
  echo "invalid source-json path should fail before summary emission"
  cat "$INVALID_SOURCE_SUMMARY_JSON"
  cat "$INVALID_SOURCE_LOG"
  exit 1
fi
if [[ "$(wc -l <"$CAPTURE" | tr -d ' ')" != "0" ]]; then
  echo "invalid source-json path should fail before invoking any stage"
  cat "$CAPTURE"
  cat "$INVALID_SOURCE_LOG"
  exit 1
fi

echo "blockchain gate bundle integration check ok"
