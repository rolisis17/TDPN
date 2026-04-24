#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp grep chmod cat tail mkdir; do
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

canonical_json() {
  jq -cS . "$1"
}

assert_json_files_equal() {
  local expected_path="$1"
  local actual_path="$2"
  local label="$3"
  local expected_json=""
  local actual_json=""
  expected_json="$(canonical_json "$expected_path")"
  actual_json="$(canonical_json "$actual_path")"
  if [[ "$expected_json" != "$actual_json" ]]; then
    echo "$label mismatch"
    echo "expected path: $expected_path"
    echo "actual path: $actual_path"
    echo "expected json: $expected_json"
    echo "actual json: $actual_json"
    exit 1
  fi
}

assert_text_files_equal() {
  local expected_path="$1"
  local actual_path="$2"
  local label="$3"
  local expected_text=""
  local actual_text=""
  expected_text="$(cat "$expected_path")"
  actual_text="$(cat "$actual_path")"
  if [[ "$expected_text" != "$actual_text" ]]; then
    echo "$label mismatch"
    echo "expected path: $expected_path"
    echo "actual path: $actual_path"
    echo "expected text: $expected_text"
    echo "actual text: $actual_text"
    exit 1
  fi
}

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
campaign_subject=""
campaign_anon_cred=""

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
    --campaign-subject|--subject|--key|--invite-key)
      campaign_subject="${2:-}"
      shift 2
      ;;
    --campaign-subject=*|--subject=*|--key=*|--invite-key=*)
      campaign_subject="${1#*=}"
      shift
      ;;
    --campaign-anon-cred|--anon-cred)
      campaign_anon_cred="${2:-}"
      shift 2
      ;;
    --campaign-anon-cred=*|--anon-cred=*)
      campaign_anon_cred="${1#*=}"
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
  printf 'signoff\tscenario=%s\tcycle=%s\treports_dir=%s\tsummary_json=%s\tcampaign_check_summary_json=%s\tcampaign_summary_json=%s\tcampaign_report_md=%s\tcampaign_subject=%s\tcampaign_anon_cred=%s\n' \
    "$scenario" "$cycle_index" "$reports_dir" "$summary_json" "$campaign_check_summary_json" "$campaign_summary_json" "$campaign_report_md" "$campaign_subject" "$campaign_anon_cred" >>"$capture_file"
fi

if [[ "$scenario" == "fail_cycle2" && "$cycle_index" == "2" ]]; then
  echo "simulated signoff cycle failure on cycle 2" >&2
  exit 23
fi

mkdir -p "$(dirname "$summary_json")"
signoff_status="ok"
signoff_final_rc=0
signoff_decision="GO"
signoff_runtime_status="pass"
signoff_next_operator_action="No action required"
if [[ "$scenario" == "no_go_summary" ]]; then
  signoff_status="fail"
  signoff_final_rc=1
  signoff_decision="NO-GO"
  signoff_runtime_status="fail"
  signoff_next_operator_action="resolve runtime-actuation blockers"
fi
if [[ -n "$campaign_check_summary_json" ]]; then
  mkdir -p "$(dirname "$campaign_check_summary_json")"
  jq -n \
    --arg signoff_status "$signoff_status" \
    --arg signoff_decision "$signoff_decision" \
    --arg signoff_runtime_status "$signoff_runtime_status" \
    --argjson signoff_final_rc "$signoff_final_rc" \
    '{
    version: 1,
    status: $signoff_status,
    rc: $signoff_final_rc,
    decision: $signoff_decision,
    decision_diagnostics: {
      m4_policy: {
        gate_evaluation: {
          runtime_actuation_status_pass: {
            required: true,
            observed: ($signoff_decision == "GO"),
            status: $signoff_runtime_status,
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
  --arg signoff_status "$signoff_status" \
  --arg signoff_decision "$signoff_decision" \
  --arg signoff_runtime_status "$signoff_runtime_status" \
  --arg signoff_next_operator_action "$signoff_next_operator_action" \
  --argjson signoff_final_rc "$signoff_final_rc" \
  --arg campaign_check_summary_json "$campaign_check_summary_json" \
  '{
    version: 1,
    status: $signoff_status,
    final_rc: $signoff_final_rc,
    decision: {
      decision: $signoff_decision,
      campaign_check_gate_diagnostics: {
        runtime_actuation_status_pass: {
          required: true,
          available: true,
          blocking: ($signoff_decision != "GO"),
          status: $signoff_runtime_status,
          observed: ($signoff_decision == "GO"),
          source: "explicit_campaign_summary"
        }
      },
      next_operator_action: $signoff_next_operator_action
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

if [[ "$scenario" == "error_no_summary" ]]; then
  rm -f "$summary_json"
  echo "simulated promotion check failure without writing summary json" >&2
  exit 47
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

if [[ "$scenario" == "go_wrong_schema" ]]; then
  jq -n \
    --argjson samples_total "$samples_total" \
    --argjson missing_samples "$missing_samples" \
    '{
      version: 1,
      schema: { id: "runtime_actuation_unexpected_summary" },
      decision: "GO",
      status: "ok",
      rc: 0,
      notes: "simulated GO decision with wrong schema id",
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
HAPPY_REPORTS_DIR="$TMP_DIR/happy_reports"
set +e
PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF_SCRIPT" \
RUNTIME_ACTUATION_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_CHECK_SCRIPT" \
FAKE_RUNTIME_ACTUATION_CYCLE_CAPTURE_FILE="$CAPTURE_FILE" \
FAKE_RUNTIME_ACTUATION_CYCLE_SIGNOFF_SCENARIO="pass" \
FAKE_RUNTIME_ACTUATION_CYCLE_PROMOTION_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --cycles 3 \
  --reports-dir "$HAPPY_REPORTS_DIR" \
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
if ! jq -e --arg reports_dir "$HAPPY_REPORTS_DIR" '
  .artifacts.latest_aliases.cycle_orchestrator_summary_json == ($reports_dir + "/runtime_actuation_promotion_cycle_latest_summary.json")
  and .artifacts.latest_aliases.promotion_check_summary_json == ($reports_dir + "/runtime_actuation_promotion_cycle_latest_promotion_check_summary.json")
  and .artifacts.latest_aliases.signoff_summary_list == ($reports_dir + "/runtime_actuation_promotion_cycle_latest_signoff_summaries.list")
' "$HAPPY_SUMMARY" >/dev/null 2>&1; then
  echo "happy path latest alias metadata mismatch"
  cat "$HAPPY_SUMMARY"
  exit 1
fi
HAPPY_PROMOTION_SUMMARY="$(jq -r '.artifacts.promotion_summary_json // ""' "$HAPPY_SUMMARY")"
HAPPY_SIGNOFF_SUMMARY_LIST="$(jq -r '.artifacts.signoff_summary_list // ""' "$HAPPY_SUMMARY")"
HAPPY_LATEST_CYCLE_ALIAS="$(jq -r '.artifacts.latest_aliases.cycle_orchestrator_summary_json // ""' "$HAPPY_SUMMARY")"
HAPPY_LATEST_PROMOTION_ALIAS="$(jq -r '.artifacts.latest_aliases.promotion_check_summary_json // ""' "$HAPPY_SUMMARY")"
HAPPY_LATEST_SIGNOFF_LIST_ALIAS="$(jq -r '.artifacts.latest_aliases.signoff_summary_list // ""' "$HAPPY_SUMMARY")"
for path in \
  "$HAPPY_PROMOTION_SUMMARY" \
  "$HAPPY_SIGNOFF_SUMMARY_LIST" \
  "$HAPPY_LATEST_CYCLE_ALIAS" \
  "$HAPPY_LATEST_PROMOTION_ALIAS" \
  "$HAPPY_LATEST_SIGNOFF_LIST_ALIAS"; do
  if [[ -z "$path" || ! -f "$path" ]]; then
    echo "happy path expected alias/output file missing: $path"
    cat "$HAPPY_SUMMARY"
    exit 1
  fi
done
assert_json_files_equal "$HAPPY_SUMMARY" "$HAPPY_LATEST_CYCLE_ALIAS" "happy path latest cycle summary alias"
assert_json_files_equal "$HAPPY_PROMOTION_SUMMARY" "$HAPPY_LATEST_PROMOTION_ALIAS" "happy path latest promotion summary alias"
assert_text_files_equal "$HAPPY_SIGNOFF_SUMMARY_LIST" "$HAPPY_LATEST_SIGNOFF_LIST_ALIAS" "happy path latest signoff list alias"
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

echo "[runtime-actuation-promotion-cycle] latest alias files refresh from stale preseed"
STALE_ALIAS_REPORTS_DIR="$TMP_DIR/stale_alias_reports"
STALE_ALIAS_SUMMARY="$TMP_DIR/stale_alias_summary.json"
STALE_ALIAS_CYCLE="$STALE_ALIAS_REPORTS_DIR/runtime_actuation_promotion_cycle_latest_summary.json"
STALE_ALIAS_PROMOTION="$STALE_ALIAS_REPORTS_DIR/runtime_actuation_promotion_cycle_latest_promotion_check_summary.json"
STALE_ALIAS_SIGNOFF_LIST="$STALE_ALIAS_REPORTS_DIR/runtime_actuation_promotion_cycle_latest_signoff_summaries.list"
mkdir -p "$STALE_ALIAS_REPORTS_DIR"
printf '%s\n' '{"stale_preseeded":true,"kind":"cycle"}' >"$STALE_ALIAS_CYCLE"
printf '%s\n' '{"stale_preseeded":true,"kind":"promotion"}' >"$STALE_ALIAS_PROMOTION"
printf '%s\n' "stale-preseeded-signoff-list-entry" >"$STALE_ALIAS_SIGNOFF_LIST"

set +e
PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF_SCRIPT" \
RUNTIME_ACTUATION_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_CHECK_SCRIPT" \
FAKE_RUNTIME_ACTUATION_CYCLE_CAPTURE_FILE="$TMP_DIR/stale_alias_capture.log" \
FAKE_RUNTIME_ACTUATION_CYCLE_SIGNOFF_SCENARIO="pass" \
FAKE_RUNTIME_ACTUATION_CYCLE_PROMOTION_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --cycles 2 \
  --reports-dir "$STALE_ALIAS_REPORTS_DIR" \
  --fail-on-no-go 1 \
  --summary-json "$STALE_ALIAS_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_promotion_cycle_stale_alias.log 2>&1
stale_alias_rc=$?
set -e

if [[ "$stale_alias_rc" -ne 0 ]]; then
  echo "expected stale alias refresh path rc=0, got rc=$stale_alias_rc"
  cat /tmp/integration_runtime_actuation_promotion_cycle_stale_alias.log
  exit 1
fi
if ! jq -e --arg reports_dir "$STALE_ALIAS_REPORTS_DIR" '
  .status == "pass"
  and .rc == 0
  and .decision == "GO"
  and .artifacts.latest_aliases.cycle_orchestrator_summary_json == ($reports_dir + "/runtime_actuation_promotion_cycle_latest_summary.json")
  and .artifacts.latest_aliases.promotion_check_summary_json == ($reports_dir + "/runtime_actuation_promotion_cycle_latest_promotion_check_summary.json")
  and .artifacts.latest_aliases.signoff_summary_list == ($reports_dir + "/runtime_actuation_promotion_cycle_latest_signoff_summaries.list")
' "$STALE_ALIAS_SUMMARY" >/dev/null 2>&1; then
  echo "stale alias refresh summary metadata mismatch"
  cat "$STALE_ALIAS_SUMMARY"
  exit 1
fi
if grep -q 'stale_preseeded' "$STALE_ALIAS_CYCLE"; then
  echo "stale cycle alias content was not refreshed"
  cat "$STALE_ALIAS_CYCLE"
  exit 1
fi
if grep -q 'stale_preseeded' "$STALE_ALIAS_PROMOTION"; then
  echo "stale promotion alias content was not refreshed"
  cat "$STALE_ALIAS_PROMOTION"
  exit 1
fi
if grep -q 'stale-preseeded-signoff-list-entry' "$STALE_ALIAS_SIGNOFF_LIST"; then
  echo "stale signoff-list alias content was not refreshed"
  cat "$STALE_ALIAS_SIGNOFF_LIST"
  exit 1
fi
STALE_CURRENT_PROMOTION_SUMMARY="$(jq -r '.artifacts.promotion_summary_json // ""' "$STALE_ALIAS_SUMMARY")"
STALE_CURRENT_SIGNOFF_SUMMARY_LIST="$(jq -r '.artifacts.signoff_summary_list // ""' "$STALE_ALIAS_SUMMARY")"
for path in \
  "$STALE_CURRENT_PROMOTION_SUMMARY" \
  "$STALE_CURRENT_SIGNOFF_SUMMARY_LIST" \
  "$STALE_ALIAS_CYCLE" \
  "$STALE_ALIAS_PROMOTION" \
  "$STALE_ALIAS_SIGNOFF_LIST"; do
  if [[ -z "$path" || ! -f "$path" ]]; then
    echo "stale alias refresh expected file missing: $path"
    cat "$STALE_ALIAS_SUMMARY"
    exit 1
  fi
done
assert_json_files_equal "$STALE_ALIAS_SUMMARY" "$STALE_ALIAS_CYCLE" "stale refresh latest cycle summary alias"
assert_json_files_equal "$STALE_CURRENT_PROMOTION_SUMMARY" "$STALE_ALIAS_PROMOTION" "stale refresh latest promotion summary alias"
assert_text_files_equal "$STALE_CURRENT_SIGNOFF_SUMMARY_LIST" "$STALE_ALIAS_SIGNOFF_LIST" "stale refresh latest signoff list alias"

echo "[runtime-actuation-promotion-cycle] promotion-check nonzero without summary stays alias-safe and rc-consistent"
NO_PROMOTION_SUMMARY_REPORTS_DIR="$TMP_DIR/no_promotion_summary_reports"
NO_PROMOTION_SUMMARY_SUMMARY="$TMP_DIR/no_promotion_summary_summary.json"
NO_PROMOTION_SUMMARY_CAPTURE="$TMP_DIR/no_promotion_summary_capture.log"
NO_PROMOTION_SUMMARY_LATEST_CYCLE_ALIAS="$NO_PROMOTION_SUMMARY_REPORTS_DIR/runtime_actuation_promotion_cycle_latest_summary.json"
NO_PROMOTION_SUMMARY_LATEST_PROMOTION_ALIAS="$NO_PROMOTION_SUMMARY_REPORTS_DIR/runtime_actuation_promotion_cycle_latest_promotion_check_summary.json"
NO_PROMOTION_SUMMARY_LATEST_SIGNOFF_LIST_ALIAS="$NO_PROMOTION_SUMMARY_REPORTS_DIR/runtime_actuation_promotion_cycle_latest_signoff_summaries.list"
mkdir -p "$NO_PROMOTION_SUMMARY_REPORTS_DIR"
printf '%s\n' '{"stale_preseeded":true,"status":"ok","decision":"GO","rc":0,"kind":"cycle"}' >"$NO_PROMOTION_SUMMARY_LATEST_CYCLE_ALIAS"
printf '%s\n' '{"stale_preseeded":true,"status":"ok","decision":"GO","rc":0,"kind":"promotion"}' >"$NO_PROMOTION_SUMMARY_LATEST_PROMOTION_ALIAS"
printf '%s\n' "stale-preseeded-signoff-list-entry" >"$NO_PROMOTION_SUMMARY_LATEST_SIGNOFF_LIST_ALIAS"

set +e
PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF_SCRIPT" \
RUNTIME_ACTUATION_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_CHECK_SCRIPT" \
FAKE_RUNTIME_ACTUATION_CYCLE_CAPTURE_FILE="$NO_PROMOTION_SUMMARY_CAPTURE" \
FAKE_RUNTIME_ACTUATION_CYCLE_SIGNOFF_SCENARIO="pass" \
FAKE_RUNTIME_ACTUATION_CYCLE_PROMOTION_SCENARIO="error_no_summary" \
bash "$SCRIPT_UNDER_TEST" \
  --cycles 2 \
  --reports-dir "$NO_PROMOTION_SUMMARY_REPORTS_DIR" \
  --fail-on-no-go 1 \
  --summary-json "$NO_PROMOTION_SUMMARY_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_promotion_cycle_no_promotion_summary.log 2>&1
no_promotion_summary_rc=$?
set -e

if [[ "$no_promotion_summary_rc" -eq 0 ]]; then
  echo "expected nonzero rc when promotion check fails without summary"
  cat /tmp/integration_runtime_actuation_promotion_cycle_no_promotion_summary.log
  exit 1
fi
if [[ ! -f "$NO_PROMOTION_SUMMARY_SUMMARY" ]]; then
  echo "expected cycle summary to be written even when promotion summary is missing"
  cat /tmp/integration_runtime_actuation_promotion_cycle_no_promotion_summary.log
  exit 1
fi
if ! jq -e --arg reports_dir "$NO_PROMOTION_SUMMARY_REPORTS_DIR" '
  .status == "fail"
  and .decision == "NO-GO"
  and .failure_stage == "promotion_check"
  and .stages.promotion_check.attempted == true
  and .stages.promotion_check.rc != 0
  and .stages.promotion_check.summary_exists == false
  and .stages.promotion_check.summary_valid_json == false
  and .stages.promotion_check.summary_fresh == false
  and .diagnostics.no_go.primary_reason_code == "promotion_summary_invalid_json"
  and .diagnostics.no_go.primary_reason_category == "policy_violation"
  and .outcome.should_promote == false
  and .outcome.action == "hold_promotion_blocked"
  and (.outcome.remediation.next_command | contains("runtime-actuation-promotion-cycle"))
  and .artifacts.latest_aliases.cycle_orchestrator_summary_json == ($reports_dir + "/runtime_actuation_promotion_cycle_latest_summary.json")
  and .artifacts.latest_aliases.promotion_check_summary_json == ($reports_dir + "/runtime_actuation_promotion_cycle_latest_promotion_check_summary.json")
  and .artifacts.latest_aliases.signoff_summary_list == ($reports_dir + "/runtime_actuation_promotion_cycle_latest_signoff_summaries.list")
' "$NO_PROMOTION_SUMMARY_SUMMARY" >/dev/null 2>&1; then
  echo "promotion-check nonzero-without-summary summary mismatch"
  cat "$NO_PROMOTION_SUMMARY_SUMMARY"
  exit 1
fi
NO_PROMOTION_SUMMARY_SUMMARY_RC="$(jq -r '.rc' "$NO_PROMOTION_SUMMARY_SUMMARY")"
if [[ "$NO_PROMOTION_SUMMARY_SUMMARY_RC" != "$no_promotion_summary_rc" ]]; then
  echo "rc contract mismatch: process rc=$no_promotion_summary_rc summary rc=$NO_PROMOTION_SUMMARY_SUMMARY_RC"
  cat "$NO_PROMOTION_SUMMARY_SUMMARY"
  exit 1
fi
NO_PROMOTION_SUMMARY_PROMOTION_SUMMARY_PATH="$(jq -r '.artifacts.promotion_summary_json // ""' "$NO_PROMOTION_SUMMARY_SUMMARY")"
if [[ -n "$NO_PROMOTION_SUMMARY_PROMOTION_SUMMARY_PATH" && -f "$NO_PROMOTION_SUMMARY_PROMOTION_SUMMARY_PATH" ]]; then
  echo "expected promotion summary path to be missing in no-summary scenario"
  ls -l "$NO_PROMOTION_SUMMARY_PROMOTION_SUMMARY_PATH"
  exit 1
fi
NO_PROMOTION_SUMMARY_CURRENT_SIGNOFF_LIST="$(jq -r '.artifacts.signoff_summary_list // ""' "$NO_PROMOTION_SUMMARY_SUMMARY")"
NO_PROMOTION_SUMMARY_CURRENT_CYCLE_ALIAS="$(jq -r '.artifacts.latest_aliases.cycle_orchestrator_summary_json // ""' "$NO_PROMOTION_SUMMARY_SUMMARY")"
NO_PROMOTION_SUMMARY_CURRENT_PROMOTION_ALIAS="$(jq -r '.artifacts.latest_aliases.promotion_check_summary_json // ""' "$NO_PROMOTION_SUMMARY_SUMMARY")"
NO_PROMOTION_SUMMARY_CURRENT_SIGNOFF_LIST_ALIAS="$(jq -r '.artifacts.latest_aliases.signoff_summary_list // ""' "$NO_PROMOTION_SUMMARY_SUMMARY")"
for path in \
  "$NO_PROMOTION_SUMMARY_CURRENT_SIGNOFF_LIST" \
  "$NO_PROMOTION_SUMMARY_CURRENT_CYCLE_ALIAS" \
  "$NO_PROMOTION_SUMMARY_CURRENT_PROMOTION_ALIAS" \
  "$NO_PROMOTION_SUMMARY_CURRENT_SIGNOFF_LIST_ALIAS"; do
  if [[ -z "$path" || ! -f "$path" ]]; then
    echo "expected alias/runtime artifact missing in no-summary scenario: $path"
    cat "$NO_PROMOTION_SUMMARY_SUMMARY"
    exit 1
  fi
done
assert_json_files_equal "$NO_PROMOTION_SUMMARY_SUMMARY" "$NO_PROMOTION_SUMMARY_CURRENT_CYCLE_ALIAS" "no-summary latest cycle summary alias"
assert_text_files_equal "$NO_PROMOTION_SUMMARY_CURRENT_SIGNOFF_LIST" "$NO_PROMOTION_SUMMARY_CURRENT_SIGNOFF_LIST_ALIAS" "no-summary latest signoff list alias"
if grep -q 'stale_preseeded' "$NO_PROMOTION_SUMMARY_CURRENT_PROMOTION_ALIAS"; then
  echo "no-summary latest promotion alias retained stale preseeded GO content"
  cat "$NO_PROMOTION_SUMMARY_CURRENT_PROMOTION_ALIAS"
  exit 1
fi
if jq -e '(.decision | type) == "string" and (.decision | ascii_upcase) == "GO"' "$NO_PROMOTION_SUMMARY_CURRENT_PROMOTION_ALIAS" >/dev/null 2>&1; then
  echo "no-summary latest promotion alias should not remain GO"
  cat "$NO_PROMOTION_SUMMARY_CURRENT_PROMOTION_ALIAS"
  exit 1
fi
if ! jq -e '
  (.decision | type) == "string"
  and (.decision | ascii_upcase) == "NO-GO"
  and ((.status | type) == "string")
  and ((.status == "fail") or (.status == "warn"))
' "$NO_PROMOTION_SUMMARY_CURRENT_PROMOTION_ALIAS" >/dev/null 2>&1; then
  echo "no-summary latest promotion alias should be fail-closed NO-GO sentinel"
  cat "$NO_PROMOTION_SUMMARY_CURRENT_PROMOTION_ALIAS"
  exit 1
fi
if grep -q 'stale-preseeded-signoff-list-entry' "$NO_PROMOTION_SUMMARY_CURRENT_SIGNOFF_LIST_ALIAS"; then
  echo "no-summary latest signoff list alias retained stale preseeded content"
  cat "$NO_PROMOTION_SUMMARY_CURRENT_SIGNOFF_LIST_ALIAS"
  exit 1
fi

echo "[runtime-actuation-promotion-cycle] promotion-check schema mismatch fails closed"
SCHEMA_MISMATCH_SUMMARY="$TMP_DIR/schema_mismatch_summary.json"
set +e
PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF_SCRIPT" \
RUNTIME_ACTUATION_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_CHECK_SCRIPT" \
FAKE_RUNTIME_ACTUATION_CYCLE_CAPTURE_FILE="$TMP_DIR/schema_mismatch_capture.log" \
FAKE_RUNTIME_ACTUATION_CYCLE_SIGNOFF_SCENARIO="pass" \
FAKE_RUNTIME_ACTUATION_CYCLE_PROMOTION_SCENARIO="go_wrong_schema" \
bash "$SCRIPT_UNDER_TEST" \
  --cycles 2 \
  --reports-dir "$TMP_DIR/schema_mismatch_reports" \
  --fail-on-no-go 1 \
  --summary-json "$SCHEMA_MISMATCH_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_promotion_cycle_schema_mismatch.log 2>&1
schema_mismatch_rc=$?
set -e

if [[ "$schema_mismatch_rc" -eq 0 ]]; then
  echo "expected schema-mismatch path rc!=0"
  cat /tmp/integration_runtime_actuation_promotion_cycle_schema_mismatch.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .decision == "NO-GO"
  and .failure_stage == "promotion_check"
  and .failure_reason == "runtime actuation promotion summary schema mismatch"
  and .stages.promotion_check.attempted == true
  and .stages.promotion_check.rc == 0
  and .stages.promotion_check.summary_exists == true
  and .stages.promotion_check.summary_valid_json == true
  and .stages.promotion_check.summary_fresh == true
  and .stages.promotion_check.summary_schema_valid == false
  and .stages.promotion_check.summary_schema_id == "runtime_actuation_unexpected_summary"
  and .promotion_check.summary_schema_valid == false
  and .promotion_check.summary_schema_id == "runtime_actuation_unexpected_summary"
  and .diagnostics.no_go.primary_reason_code == "promotion_summary_schema_mismatch"
  and .diagnostics.no_go.primary_reason_category == "policy_violation"
  and .outcome.should_promote == false
  and .outcome.action == "hold_promotion_blocked"
  and (.outcome.remediation.next_command | contains("runtime-actuation-promotion-cycle"))
' "$SCHEMA_MISMATCH_SUMMARY" >/dev/null 2>&1; then
  echo "schema-mismatch fail-closed summary mismatch"
  cat "$SCHEMA_MISMATCH_SUMMARY"
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
  and .diagnostics.no_go.primary_reason_code == "simulated_no_go"
  and .diagnostics.no_go.primary_reason_category == "policy_violation"
  and .outcome.should_promote == false
  and .outcome.action == "hold_promotion_warn_only"
  and (.outcome.remediation.next_command | contains("runtime-actuation-promotion-cycle"))
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
  and .diagnostics.no_go.primary_reason_code == "signoff_command_failed"
  and .diagnostics.no_go.primary_reason_category == "cycle_signoff_failure"
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
  and .diagnostics.no_go.primary_reason_code == "signoff_command_failed"
  and .diagnostics.no_go.primary_reason_category == "cycle_signoff_failure"
  and .outcome.should_promote == false
  and .outcome.action == "hold_promotion_blocked"
' "$CYCLE_FAIL_SOFT_FLAG_SUMMARY" >/dev/null 2>&1; then
  echo "cycle-failure with fail-on-no-go=0 summary mismatch"
  cat "$CYCLE_FAIL_SOFT_FLAG_SUMMARY"
  exit 1
fi

echo "[runtime-actuation-promotion-cycle] signoff NO-GO summary is fail-closed even when command rc=0"
SIGNOFF_NOGO_SUMMARY="$TMP_DIR/signoff_nogo_summary.json"
set +e
PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF_SCRIPT" \
RUNTIME_ACTUATION_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_CHECK_SCRIPT" \
FAKE_RUNTIME_ACTUATION_CYCLE_CAPTURE_FILE="$TMP_DIR/signoff_nogo_capture.log" \
FAKE_RUNTIME_ACTUATION_CYCLE_SIGNOFF_SCENARIO="no_go_summary" \
FAKE_RUNTIME_ACTUATION_CYCLE_PROMOTION_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --cycles 2 \
  --reports-dir "$TMP_DIR/signoff_nogo_reports" \
  --fail-on-no-go 1 \
  --summary-json "$SIGNOFF_NOGO_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_promotion_cycle_signoff_nogo.log 2>&1
signoff_nogo_rc=$?
set -e

if [[ "$signoff_nogo_rc" -eq 0 ]]; then
  echo "expected signoff NO-GO summary path rc!=0"
  cat /tmp/integration_runtime_actuation_promotion_cycle_signoff_nogo.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc != 0
  and .decision == "NO-GO"
  and .failure_stage == "cycles"
  and .stages.cycles.failed >= 1
  and ((.cycles | length) == 2)
  and (.cycles[0].summary.decision == "NO-GO")
  and (.cycles[0].summary.has_usable_decision == true)
  and (.cycles[0].summary.rc != 0)
  and (.cycles[0].error_code == "signoff_summary_rc_nonzero")
  and .diagnostics.no_go.primary_reason_code == "signoff_summary_rc_nonzero"
  and .diagnostics.no_go.primary_reason_category == "cycle_signoff_failure"
  and (.promotion_check.decision == "GO")
  and .outcome.should_promote == false
  and .outcome.action == "hold_promotion_blocked"
' "$SIGNOFF_NOGO_SUMMARY" >/dev/null 2>&1; then
  echo "signoff NO-GO summary fail-closed contract mismatch"
  cat "$SIGNOFF_NOGO_SUMMARY"
  exit 1
fi

echo "[runtime-actuation-promotion-cycle] placeholder subject passthrough resolves from env"
PLACEHOLDER_RESOLVE_SUMMARY="$TMP_DIR/placeholder_resolve_summary.json"
PLACEHOLDER_RESOLVE_CAPTURE="$TMP_DIR/placeholder_resolve_capture.log"
set +e
INVITE_KEY="inv-resolved-from-env" \
PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF_SCRIPT" \
RUNTIME_ACTUATION_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_CHECK_SCRIPT" \
FAKE_RUNTIME_ACTUATION_CYCLE_CAPTURE_FILE="$PLACEHOLDER_RESOLVE_CAPTURE" \
FAKE_RUNTIME_ACTUATION_CYCLE_SIGNOFF_SCENARIO="pass" \
FAKE_RUNTIME_ACTUATION_CYCLE_PROMOTION_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --cycles 1 \
  --reports-dir "$TMP_DIR/placeholder_resolve_reports" \
  --subject INVITE_KEY \
  --summary-json "$PLACEHOLDER_RESOLVE_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_promotion_cycle_placeholder_resolve.log 2>&1
placeholder_resolve_rc=$?
set -e

if [[ "$placeholder_resolve_rc" -ne 0 ]]; then
  echo "expected placeholder subject resolution path rc=0, got rc=$placeholder_resolve_rc"
  cat /tmp/integration_runtime_actuation_promotion_cycle_placeholder_resolve.log
  exit 1
fi
if ! grep -q $'^signoff\t' "$PLACEHOLDER_RESOLVE_CAPTURE"; then
  echo "expected signoff capture for placeholder resolution path"
  cat "$PLACEHOLDER_RESOLVE_CAPTURE"
  exit 1
fi
if grep -q 'campaign_subject=INVITE_KEY' "$PLACEHOLDER_RESOLVE_CAPTURE"; then
  echo "placeholder subject was not resolved before signoff invocation"
  cat "$PLACEHOLDER_RESOLVE_CAPTURE"
  exit 1
fi
if ! grep -q 'campaign_subject=inv-resolved-from-env' "$PLACEHOLDER_RESOLVE_CAPTURE"; then
  echo "resolved invite key was not forwarded to signoff"
  cat "$PLACEHOLDER_RESOLVE_CAPTURE"
  exit 1
fi
if ! jq -e '
  .inputs.credential_resolution.campaign_subject_mode == "placeholder_replaced"
  and .inputs.credential_resolution.campaign_subject_source == "env:INVITE_KEY"
  and .inputs.credential_resolution.signoff_has_subject_credential == true
' "$PLACEHOLDER_RESOLVE_SUMMARY" >/dev/null 2>&1; then
  echo "placeholder resolution summary contract mismatch"
  cat "$PLACEHOLDER_RESOLVE_SUMMARY"
  exit 1
fi

echo "[runtime-actuation-promotion-cycle] unresolved placeholder subject fails closed before cycles"
PLACEHOLDER_FAIL_SUMMARY="$TMP_DIR/placeholder_fail_summary.json"
PLACEHOLDER_FAIL_CAPTURE="$TMP_DIR/placeholder_fail_capture.log"
set +e
PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF_SCRIPT" \
RUNTIME_ACTUATION_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_CHECK_SCRIPT" \
FAKE_RUNTIME_ACTUATION_CYCLE_CAPTURE_FILE="$PLACEHOLDER_FAIL_CAPTURE" \
FAKE_RUNTIME_ACTUATION_CYCLE_SIGNOFF_SCENARIO="pass" \
FAKE_RUNTIME_ACTUATION_CYCLE_PROMOTION_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --cycles 1 \
  --reports-dir "$TMP_DIR/placeholder_fail_reports" \
  --subject INVITE_KEY \
  --summary-json "$PLACEHOLDER_FAIL_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_promotion_cycle_placeholder_fail.log 2>&1
placeholder_fail_rc=$?
set -e

if [[ "$placeholder_fail_rc" != "2" ]]; then
  echo "expected unresolved placeholder subject path rc=2, got rc=$placeholder_fail_rc"
  cat /tmp/integration_runtime_actuation_promotion_cycle_placeholder_fail.log
  exit 1
fi
if [[ -s "$PLACEHOLDER_FAIL_CAPTURE" ]]; then
  echo "expected no signoff invocations when placeholder subject is unresolved"
  cat "$PLACEHOLDER_FAIL_CAPTURE"
  exit 1
fi
if ! grep -q 'placeholder invite subject' /tmp/integration_runtime_actuation_promotion_cycle_placeholder_fail.log; then
  echo "expected unresolved placeholder diagnostic in fail-closed path"
  cat /tmp/integration_runtime_actuation_promotion_cycle_placeholder_fail.log
  exit 1
fi
if ! grep -q 'operator_next_action: ./scripts/runtime_actuation_promotion_cycle.sh' /tmp/integration_runtime_actuation_promotion_cycle_placeholder_fail.log; then
  echo "expected exact rerun command operator guidance in unresolved placeholder path"
  cat /tmp/integration_runtime_actuation_promotion_cycle_placeholder_fail.log
  exit 1
fi
if ! grep -q -- '--subject REPLACE_WITH_INVITE_SUBJECT' /tmp/integration_runtime_actuation_promotion_cycle_placeholder_fail.log; then
  echo "expected placeholder subject rerun guidance in unresolved placeholder path"
  cat /tmp/integration_runtime_actuation_promotion_cycle_placeholder_fail.log
  exit 1
fi
if ! grep -q 'operator_next_action: CAMPAIGN_SUBJECT=REPLACE_WITH_INVITE_SUBJECT ./scripts/runtime_actuation_promotion_cycle.sh' /tmp/integration_runtime_actuation_promotion_cycle_placeholder_fail.log; then
  echo "expected CAMPAIGN_SUBJECT rerun guidance in unresolved placeholder path"
  cat /tmp/integration_runtime_actuation_promotion_cycle_placeholder_fail.log
  exit 1
fi

echo "[runtime-actuation-promotion-cycle] missing subject value fails closed before cycles"
MISSING_SUBJECT_VALUE_SUMMARY="$TMP_DIR/missing_subject_value_summary.json"
MISSING_SUBJECT_VALUE_CAPTURE="$TMP_DIR/missing_subject_value_capture.log"
set +e
PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF_SCRIPT" \
RUNTIME_ACTUATION_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_CHECK_SCRIPT" \
FAKE_RUNTIME_ACTUATION_CYCLE_CAPTURE_FILE="$MISSING_SUBJECT_VALUE_CAPTURE" \
FAKE_RUNTIME_ACTUATION_CYCLE_SIGNOFF_SCENARIO="pass" \
FAKE_RUNTIME_ACTUATION_CYCLE_PROMOTION_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --cycles 1 \
  --reports-dir "$TMP_DIR/missing_subject_value_reports" \
  --subject \
  --summary-json "$MISSING_SUBJECT_VALUE_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_promotion_cycle_missing_subject_value.log 2>&1
missing_subject_value_rc=$?
set -e

if [[ "$missing_subject_value_rc" != "2" ]]; then
  echo "expected missing subject value path rc=2, got rc=$missing_subject_value_rc"
  cat /tmp/integration_runtime_actuation_promotion_cycle_missing_subject_value.log
  exit 1
fi
if [[ -s "$MISSING_SUBJECT_VALUE_CAPTURE" ]]; then
  echo "expected no signoff invocation when subject value is missing"
  cat "$MISSING_SUBJECT_VALUE_CAPTURE"
  exit 1
fi
if ! grep -q 'requires a value in signoff passthrough args' /tmp/integration_runtime_actuation_promotion_cycle_missing_subject_value.log; then
  echo "expected missing subject value diagnostic"
  cat /tmp/integration_runtime_actuation_promotion_cycle_missing_subject_value.log
  exit 1
fi
if ! grep -q 'operator_next_action: ./scripts/runtime_actuation_promotion_cycle.sh' /tmp/integration_runtime_actuation_promotion_cycle_missing_subject_value.log; then
  echo "expected exact rerun command operator guidance in missing-subject-value path"
  cat /tmp/integration_runtime_actuation_promotion_cycle_missing_subject_value.log
  exit 1
fi
if ! grep -q -- '--subject REPLACE_WITH_INVITE_SUBJECT' /tmp/integration_runtime_actuation_promotion_cycle_missing_subject_value.log; then
  echo "expected placeholder subject rerun guidance in missing-subject-value path"
  cat /tmp/integration_runtime_actuation_promotion_cycle_missing_subject_value.log
  exit 1
fi

echo "runtime actuation promotion cycle integration ok"
