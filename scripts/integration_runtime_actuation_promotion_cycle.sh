#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp grep chmod cat tail; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/runtime_actuation_promotion_cycle.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE_FILE="$TMP_DIR/cycle_capture.log"

FAKE_SIGNOFF_SCRIPT="$TMP_DIR/fake_profile_compare_campaign_signoff.sh"
cat >"$FAKE_SIGNOFF_SCRIPT" <<'EOF_FAKE_SIGNOFF'
#!/usr/bin/env bash
set -euo pipefail

scenario="${FAKE_RUNTIME_ACTUATION_CYCLE_SIGNOFF_SCENARIO:-pass}"
capture_file="${FAKE_RUNTIME_ACTUATION_CYCLE_CAPTURE_FILE:-}"
summary_json=""
campaign_check_summary_json=""
campaign_summary_json=""
campaign_report_md=""
reports_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --summary-json=*)
      summary_json="${1#*=}"
      shift
      ;;
    --campaign-check-summary-json)
      campaign_check_summary_json="${2:-}"
      shift 2
      ;;
    --campaign-check-summary-json=*)
      campaign_check_summary_json="${1#*=}"
      shift
      ;;
    --campaign-summary-json)
      campaign_summary_json="${2:-}"
      shift 2
      ;;
    --campaign-summary-json=*)
      campaign_summary_json="${1#*=}"
      shift
      ;;
    --campaign-report-md)
      campaign_report_md="${2:-}"
      shift 2
      ;;
    --campaign-report-md=*)
      campaign_report_md="${1#*=}"
      shift
      ;;
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --reports-dir=*)
      reports_dir="${1#*=}"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" ]]; then
  echo "fake signoff missing --summary-json" >&2
  exit 2
fi

cycle_index="0"
if [[ "$summary_json" =~ _signoff_([0-9]+)\.json$ ]]; then
  cycle_index="${BASH_REMATCH[1]}"
fi

if [[ -n "$capture_file" ]]; then
  printf 'signoff\tscenario=%s\tcycle=%s\treports_dir=%s\tsummary_json=%s\tcampaign_check_summary_json=%s\tcampaign_summary_json=%s\tcampaign_report_md=%s\n' \
    "$scenario" "$cycle_index" "$reports_dir" "$summary_json" "$campaign_check_summary_json" "$campaign_summary_json" "$campaign_report_md" >>"$capture_file"
fi

if [[ "$scenario" == "fail_cycle2" && "$cycle_index" == "2" ]]; then
  echo "simulated signoff cycle failure on cycle 2" >&2
  exit 23
fi

mkdir -p "$(dirname "$summary_json")"
if [[ -n "$campaign_check_summary_json" ]]; then
  mkdir -p "$(dirname "$campaign_check_summary_json")"
  jq -n '{
    version: 1,
    status: "ok",
    rc: 0,
    decision: "GO",
    decision_diagnostics: {
      m4_policy: {
        gate_evaluation: {
          runtime_actuation_status_pass: {
            required: true,
            observed: true,
            status: "pass",
            source: "explicit_campaign_summary"
          }
        }
      }
    }
  }' >"$campaign_check_summary_json"
fi
if [[ -n "$campaign_summary_json" ]]; then
  mkdir -p "$(dirname "$campaign_summary_json")"
  jq -n '{version: 1, status: "ok"}' >"$campaign_summary_json"
fi
if [[ -n "$campaign_report_md" ]]; then
  mkdir -p "$(dirname "$campaign_report_md")"
  printf '%s\n' "# fake campaign report" >"$campaign_report_md"
fi

jq -n \
  --arg campaign_check_summary_json "$campaign_check_summary_json" \
  '{
    version: 1,
    status: "ok",
    final_rc: 0,
    decision: {
      decision: "GO",
      campaign_check_gate_diagnostics: {
        runtime_actuation_status_pass: {
          required: true,
          available: true,
          blocking: false,
          status: "pass",
          observed: true,
          source: "explicit_campaign_summary"
        }
      },
      next_operator_action: "No action required"
    },
    artifacts: {
      campaign_check_summary_json: (if $campaign_check_summary_json == "" then null else $campaign_check_summary_json end)
    }
  }' >"$summary_json"

exit 0
EOF_FAKE_SIGNOFF
chmod +x "$FAKE_SIGNOFF_SCRIPT"

FAKE_PROMOTION_CHECK_SCRIPT="$TMP_DIR/fake_runtime_actuation_promotion_check.sh"
cat >"$FAKE_PROMOTION_CHECK_SCRIPT" <<'EOF_FAKE_PROMOTION_CHECK'
#!/usr/bin/env bash
set -euo pipefail

scenario="${FAKE_RUNTIME_ACTUATION_CYCLE_PROMOTION_SCENARIO:-go}"
capture_file="${FAKE_RUNTIME_ACTUATION_CYCLE_CAPTURE_FILE:-}"
summary_list=""
summary_json=""
reports_dir=""
fail_on_no_go="1"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-list)
      summary_list="${2:-}"
      shift 2
      ;;
    --summary-list=*)
      summary_list="${1#*=}"
      shift
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --summary-json=*)
      summary_json="${1#*=}"
      shift
      ;;
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --reports-dir=*)
      reports_dir="${1#*=}"
      shift
      ;;
    --fail-on-no-go)
      fail_on_no_go="${2:-}"
      shift 2
      ;;
    --fail-on-no-go=*)
      fail_on_no_go="${1#*=}"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_list" || -z "$summary_json" ]]; then
  echo "fake promotion check missing required arguments" >&2
  exit 2
fi

samples_total=0
missing_samples=0
if [[ -f "$summary_list" ]]; then
  while IFS= read -r path || [[ -n "$path" ]]; do
    path="${path#"${path%%[![:space:]]*}"}"
    path="${path%"${path##*[![:space:]]}"}"
    if [[ -z "$path" || "${path:0:1}" == "#" ]]; then
      continue
    fi
    samples_total=$((samples_total + 1))
    if [[ ! -f "$path" ]]; then
      missing_samples=$((missing_samples + 1))
    fi
  done <"$summary_list"
fi

if [[ -n "$capture_file" ]]; then
  printf 'promotion_check\tscenario=%s\tfail_on_no_go=%s\treports_dir=%s\tsummary_list=%s\tsummary_json=%s\tsamples_total=%s\tmissing_samples=%s\n' \
    "$scenario" "$fail_on_no_go" "$reports_dir" "$summary_list" "$summary_json" "$samples_total" "$missing_samples" >>"$capture_file"
fi

mkdir -p "$(dirname "$summary_json")"

if [[ "$scenario" == "no_go" ]]; then
  rc=0
  if [[ "$fail_on_no_go" == "1" ]]; then
    rc=1
  fi
  jq -n \
    --argjson rc "$rc" \
    --argjson samples_total "$samples_total" \
    --argjson missing_samples "$missing_samples" \
    '{
      version: 1,
      schema: { id: "runtime_actuation_promotion_check_summary" },
      decision: "NO-GO",
      status: "fail",
      rc: $rc,
      notes: "simulated NO-GO promotion decision",
      observed: {
        samples_total: $samples_total,
        samples_fail: (if $samples_total > 0 then 1 else 0 end),
        runtime_actuation_ready_rate_pct: 0
      },
      enforcement: {
        fail_on_no_go: true,
        no_go_detected: true,
        no_go_enforced: ($rc != 0)
      },
      outcome: {
        should_promote: false,
        action: (if $rc == 0 then "hold_promotion_warn_only" else "hold_promotion_blocked" end),
        next_operator_action: "resolve runtime actuation blockers"
      },
      violations: [
        {
          code: "simulated_no_go",
          message: "simulated NO-GO promotion policy violation"
        }
      ],
      errors: [],
      artifacts: {
        missing_samples: $missing_samples
      }
    }' >"$summary_json"
  exit "$rc"
fi

jq -n \
  --argjson samples_total "$samples_total" \
  --argjson missing_samples "$missing_samples" \
  '{
    version: 1,
    schema: { id: "runtime_actuation_promotion_check_summary" },
    decision: "GO",
    status: "ok",
    rc: 0,
    notes: "simulated GO promotion decision",
    observed: {
      samples_total: $samples_total,
      samples_pass: $samples_total,
      samples_fail: 0,
      runtime_actuation_ready_rate_pct: 100
    },
    enforcement: {
      fail_on_no_go: true,
      no_go_detected: false,
      no_go_enforced: false
    },
    outcome: {
      should_promote: true,
      action: "promote_allowed",
      next_operator_action: "No action required"
    },
    violations: [],
    errors: [],
    artifacts: {
      missing_samples: $missing_samples
    }
  }' >"$summary_json"
exit 0
EOF_FAKE_PROMOTION_CHECK
chmod +x "$FAKE_PROMOTION_CHECK_SCRIPT"

echo "[runtime-actuation-promotion-cycle] happy path"
HAPPY_SUMMARY="$TMP_DIR/cycle_happy_summary.json"
set +e
PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF_SCRIPT" \
RUNTIME_ACTUATION_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_CHECK_SCRIPT" \
FAKE_RUNTIME_ACTUATION_CYCLE_CAPTURE_FILE="$CAPTURE_FILE" \
FAKE_RUNTIME_ACTUATION_CYCLE_SIGNOFF_SCENARIO="pass" \
FAKE_RUNTIME_ACTUATION_CYCLE_PROMOTION_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --cycles 3 \
  --reports-dir "$TMP_DIR/happy_reports" \
  --fail-on-no-go 1 \
  --summary-json "$HAPPY_SUMMARY" \
  --print-summary-json 0 \
  --sample-arg sample-value >/tmp/integration_runtime_actuation_promotion_cycle_happy.log 2>&1
happy_rc=$?
set -e

if [[ "$happy_rc" -ne 0 ]]; then
  echo "expected happy path rc=0, got rc=$happy_rc"
  cat /tmp/integration_runtime_actuation_promotion_cycle_happy.log
  exit 1
fi
if ! jq -e '
  .schema.id == "runtime_actuation_promotion_cycle_summary"
  and .status == "pass"
  and .rc == 0
  and .decision == "GO"
  and .stages.cycles.requested == 3
  and .stages.cycles.completed == 3
  and .stages.cycles.failed == 0
  and .stages.cycles.all_passed == true
  and .stages.promotion_check.attempted == true
  and .stages.promotion_check.status == "pass"
  and .promotion_check.decision == "GO"
  and .outcome.should_promote == true
  and .outcome.action == "promote_allowed"
  and ((.artifacts.signoff_summary_paths | length) == 3)
' "$HAPPY_SUMMARY" >/dev/null 2>&1; then
  echo "happy path cycle summary mismatch"
  cat "$HAPPY_SUMMARY"
  exit 1
fi
if [[ "$(grep -c '^signoff' "$CAPTURE_FILE" || true)" -ne 3 ]]; then
  echo "expected 3 signoff cycle invocations in capture"
  cat "$CAPTURE_FILE"
  exit 1
fi
if ! grep -q $'^promotion_check\t.*\tfail_on_no_go=1\t' "$CAPTURE_FILE"; then
  echo "expected promotion check fail_on_no_go=1 capture not found"
  cat "$CAPTURE_FILE"
  exit 1
fi

echo "[runtime-actuation-promotion-cycle] NO-GO soft path"
NO_GO_SOFT_SUMMARY="$TMP_DIR/cycle_no_go_soft_summary.json"
NO_GO_SOFT_CAPTURE="$TMP_DIR/cycle_no_go_soft_capture.log"
set +e
PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF_SCRIPT" \
RUNTIME_ACTUATION_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_CHECK_SCRIPT" \
FAKE_RUNTIME_ACTUATION_CYCLE_CAPTURE_FILE="$NO_GO_SOFT_CAPTURE" \
FAKE_RUNTIME_ACTUATION_CYCLE_SIGNOFF_SCENARIO="pass" \
FAKE_RUNTIME_ACTUATION_CYCLE_PROMOTION_SCENARIO="no_go" \
bash "$SCRIPT_UNDER_TEST" \
  --cycles 2 \
  --reports-dir "$TMP_DIR/no_go_soft_reports" \
  --fail-on-no-go 0 \
  --summary-json "$NO_GO_SOFT_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_promotion_cycle_no_go_soft.log 2>&1
no_go_soft_rc=$?
set -e

if [[ "$no_go_soft_rc" -ne 0 ]]; then
  echo "expected NO-GO soft path rc=0, got rc=$no_go_soft_rc"
  cat /tmp/integration_runtime_actuation_promotion_cycle_no_go_soft.log
  exit 1
fi
if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .decision == "NO-GO"
  and .stages.cycles.failed == 0
  and .stages.promotion_check.attempted == true
  and .stages.promotion_check.status == "fail"
  and .promotion_check.decision == "NO-GO"
  and .promotion_check.rc == 0
  and .outcome.should_promote == false
  and .outcome.action == "hold_promotion_warn_only"
' "$NO_GO_SOFT_SUMMARY" >/dev/null 2>&1; then
  echo "NO-GO soft path summary mismatch"
  cat "$NO_GO_SOFT_SUMMARY"
  exit 1
fi
if ! grep -q $'^promotion_check\t.*\tfail_on_no_go=0\t' "$NO_GO_SOFT_CAPTURE"; then
  echo "expected promotion check fail_on_no_go=0 capture not found"
  cat "$NO_GO_SOFT_CAPTURE"
  exit 1
fi

echo "[runtime-actuation-promotion-cycle] signoff cycle failure is fail-closed"
CYCLE_FAIL_SUMMARY="$TMP_DIR/cycle_fail_closed_summary.json"
set +e
PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF_SCRIPT" \
RUNTIME_ACTUATION_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_CHECK_SCRIPT" \
FAKE_RUNTIME_ACTUATION_CYCLE_CAPTURE_FILE="$TMP_DIR/cycle_fail_capture.log" \
FAKE_RUNTIME_ACTUATION_CYCLE_SIGNOFF_SCENARIO="fail_cycle2" \
FAKE_RUNTIME_ACTUATION_CYCLE_PROMOTION_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --cycles 3 \
  --reports-dir "$TMP_DIR/cycle_fail_reports" \
  --fail-on-no-go 1 \
  --summary-json "$CYCLE_FAIL_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_promotion_cycle_fail_closed.log 2>&1
cycle_fail_rc=$?
set -e

if [[ "$cycle_fail_rc" -eq 0 ]]; then
  echo "expected cycle-failure path rc!=0"
  cat /tmp/integration_runtime_actuation_promotion_cycle_fail_closed.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .decision == "NO-GO"
  and .failure_stage == "cycles"
  and .stages.cycles.failed >= 1
  and .stages.promotion_check.attempted == true
  and .promotion_check.decision == "GO"
  and .outcome.should_promote == false
  and .outcome.action == "hold_promotion_blocked"
' "$CYCLE_FAIL_SUMMARY" >/dev/null 2>&1; then
  echo "cycle-failure fail-closed summary mismatch"
  cat "$CYCLE_FAIL_SUMMARY"
  exit 1
fi

echo "[runtime-actuation-promotion-cycle] signoff cycle failure remains fail-closed when fail-on-no-go=0"
CYCLE_FAIL_SOFT_FLAG_SUMMARY="$TMP_DIR/cycle_fail_soft_flag_summary.json"
set +e
PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF_SCRIPT" \
RUNTIME_ACTUATION_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_CHECK_SCRIPT" \
FAKE_RUNTIME_ACTUATION_CYCLE_CAPTURE_FILE="$TMP_DIR/cycle_fail_soft_flag_capture.log" \
FAKE_RUNTIME_ACTUATION_CYCLE_SIGNOFF_SCENARIO="fail_cycle2" \
FAKE_RUNTIME_ACTUATION_CYCLE_PROMOTION_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --cycles 3 \
  --reports-dir "$TMP_DIR/cycle_fail_soft_flag_reports" \
  --fail-on-no-go 0 \
  --summary-json "$CYCLE_FAIL_SOFT_FLAG_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_promotion_cycle_fail_soft_flag.log 2>&1
cycle_fail_soft_flag_rc=$?
set -e

if [[ "$cycle_fail_soft_flag_rc" -eq 0 ]]; then
  echo "expected cycle-failure with fail-on-no-go=0 path rc!=0"
  cat /tmp/integration_runtime_actuation_promotion_cycle_fail_soft_flag.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc != 0
  and .decision == "NO-GO"
  and .failure_stage == "cycles"
  and .stages.cycles.failed >= 1
  and .outcome.should_promote == false
  and .outcome.action == "hold_promotion_blocked"
' "$CYCLE_FAIL_SOFT_FLAG_SUMMARY" >/dev/null 2>&1; then
  echo "cycle-failure with fail-on-no-go=0 summary mismatch"
  cat "$CYCLE_FAIL_SOFT_FLAG_SUMMARY"
  exit 1
fi

echo "runtime actuation promotion cycle integration ok"
