#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp grep cat chmod wc; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/profile_default_gate_stability_promotion_cycle.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE_FILE="$TMP_DIR/promotion_cycle_capture.log"
COUNTER_FILE="$TMP_DIR/fake_cycle_counter.txt"

FAKE_CYCLE_SCRIPT="$TMP_DIR/fake_profile_default_gate_stability_cycle.sh"
cat >"$FAKE_CYCLE_SCRIPT" <<'EOF_FAKE_CYCLE'
#!/usr/bin/env bash
set -euo pipefail

capture_file="${FAKE_PROMOTION_CYCLE_CAPTURE_FILE:-}"
counter_file="${FAKE_PROMOTION_CYCLE_COUNTER_FILE:-}"
scenarios_csv="${FAKE_PROMOTION_CYCLE_SCENARIOS:-pass}"

summary_json=""
run_summary_json=""
check_summary_json=""
fail_on_no_go="1"
host_a=""
host_b=""
campaign_subject=""

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
    --run-summary-json)
      run_summary_json="${2:-}"
      shift 2
      ;;
    --run-summary-json=*)
      run_summary_json="${1#*=}"
      shift
      ;;
    --check-summary-json)
      check_summary_json="${2:-}"
      shift 2
      ;;
    --check-summary-json=*)
      check_summary_json="${1#*=}"
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
    --host-a)
      host_a="${2:-}"
      shift 2
      ;;
    --host-a=*)
      host_a="${1#*=}"
      shift
      ;;
    --host-b)
      host_b="${2:-}"
      shift 2
      ;;
    --host-b=*)
      host_b="${1#*=}"
      shift
      ;;
    --campaign-subject)
      campaign_subject="${2:-}"
      shift 2
      ;;
    --campaign-subject=*)
      campaign_subject="${1#*=}"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" ]]; then
  echo "fake cycle missing --summary-json" >&2
  exit 2
fi

cycle_index=1
if [[ -n "$counter_file" ]]; then
  mkdir -p "$(dirname "$counter_file")"
  if [[ -f "$counter_file" ]]; then
    last_idx="$(cat "$counter_file" 2>/dev/null || printf '%s' "0")"
    if [[ "$last_idx" =~ ^[0-9]+$ ]]; then
      cycle_index=$((last_idx + 1))
    fi
  fi
  printf '%s\n' "$cycle_index" >"$counter_file"
fi

IFS=',' read -r -a scenarios <<<"$scenarios_csv"
scenario="${scenarios[0]}"
if (( cycle_index <= ${#scenarios[@]} )); then
  scenario="${scenarios[$((cycle_index - 1))]}"
elif ((${#scenarios[@]} > 0)); then
  scenario="${scenarios[$((${#scenarios[@]} - 1))]}"
fi
scenario="$(printf '%s' "$scenario" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
if [[ -z "$scenario" ]]; then
  scenario="pass"
fi
forced_exit_rc=0

if [[ -n "$capture_file" ]]; then
  printf 'cycle\tindex=%s\tscenario=%s\tfail_on_no_go=%s\thost_a=%s\thost_b=%s\tcampaign_subject=%s\tsummary_json=%s\trun_summary_json=%s\tcheck_summary_json=%s\n' \
    "$cycle_index" "$scenario" "$fail_on_no_go" "$host_a" "$host_b" "$campaign_subject" "$summary_json" "$run_summary_json" "$check_summary_json" >>"$capture_file"
fi

mkdir -p "$(dirname "$summary_json")"
mkdir -p "$(dirname "$run_summary_json")" "$(dirname "$check_summary_json")"

if [[ "$scenario" == "missing_summary" ]]; then
  exit 23
fi

if [[ "$scenario" == "invalid_json" ]]; then
  printf '%s\n' '{ invalid json' >"$summary_json"
  exit 0
fi

if [[ "$scenario" == "missing_supporting_summaries" ]]; then
  jq -n '{
    version: 1,
    schema: { id: "profile_default_gate_stability_cycle_summary" },
    status: "pass",
    rc: 0,
    decision: "GO",
    inputs: {
      check: {
        policy: {
          require_modal_decision: "GO"
        }
      }
    },
    check: {
      summary_schema_valid: true,
      has_usable_decision: true,
      decision: "GO"
    }
  }' >"$summary_json"
  exit 0
fi

if [[ "$scenario" == "missing_rc" ]]; then
  jq -n '{
    version: 1,
    schema: { id: "profile_default_gate_stability_cycle_summary" },
    status: "pass",
    decision: "GO",
    inputs: {
      check: {
        policy: {
          require_modal_decision: "GO"
        }
      }
    },
    check: {
      summary_schema_valid: true,
      has_usable_decision: true,
      decision: "GO"
    }
  }' >"$summary_json"
  jq -n '{version:1, schema:{id:"profile_default_gate_stability_summary"}, status:"pass", rc:0}' >"$run_summary_json"
  jq -n '{version:1, schema:{id:"profile_default_gate_stability_check_summary"}, decision:"GO", status:"ok", rc:0}' >"$check_summary_json"
  exit 0
fi

schema_id="profile_default_gate_stability_cycle_summary"
status="pass"
decision="GO"
rc=0
check_decision="GO"

if [[ "$scenario" == "bad_schema" ]]; then
  schema_id="profile_default_gate_cycle_summary"
fi
if [[ "$scenario" == "no_go" ]]; then
  decision="NO-GO"
  check_decision="NO-GO"
  if [[ "$fail_on_no_go" == "1" ]]; then
    status="fail"
    rc=1
  else
    status="warn"
    rc=0
  fi
elif [[ "$scenario" == "no_go_exit_nonzero" ]]; then
  decision="NO-GO"
  check_decision="NO-GO"
  status="fail"
  rc=41
  forced_exit_rc=41
elif [[ "$scenario" == "go_exit_nonzero" ]]; then
  forced_exit_rc=31
fi

jq -n \
  --arg schema_id "$schema_id" \
  --arg status "$status" \
  --arg decision "$decision" \
  --arg check_decision "$check_decision" \
  --argjson rc "$rc" \
  '{
    version: 1,
    schema: { id: $schema_id },
    status: $status,
    rc: $rc,
    decision: $decision,
    inputs: {
      check: {
        policy: {
          require_modal_decision: "GO"
        }
      }
    },
    check: {
      summary_schema_valid: true,
      has_usable_decision: true,
      decision: $check_decision
    }
  }' >"$summary_json"

jq -n '{version:1, schema:{id:"profile_default_gate_stability_summary"}, status:"pass", rc:0}' >"$run_summary_json"
jq -n '{version:1, schema:{id:"profile_default_gate_stability_check_summary"}, decision:"GO", status:"ok", rc:0}' >"$check_summary_json"

if [[ "$scenario" == "no_go" && "$fail_on_no_go" == "1" ]]; then
  exit 1
fi
if [[ "$forced_exit_rc" -ne 0 ]]; then
  exit "$forced_exit_rc"
fi
exit 0
EOF_FAKE_CYCLE
chmod +x "$FAKE_CYCLE_SCRIPT"

FAKE_PROMOTION_SCRIPT="$TMP_DIR/fake_profile_default_gate_stability_promotion_check.sh"
cat >"$FAKE_PROMOTION_SCRIPT" <<'EOF_FAKE_PROMOTION'
#!/usr/bin/env bash
set -euo pipefail

scenario="${FAKE_PROMOTION_CHECK_SCENARIO:-go}"
capture_file="${FAKE_PROMOTION_CYCLE_CAPTURE_FILE:-}"
summary_json=""
cycle_summary_list=""
fail_on_no_go="1"

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
    --cycle-summary-list)
      cycle_summary_list="${2:-}"
      shift 2
      ;;
    --cycle-summary-list=*)
      cycle_summary_list="${1#*=}"
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

if [[ -z "$summary_json" ]]; then
  echo "fake promotion check missing --summary-json" >&2
  exit 2
fi
if [[ -z "$cycle_summary_list" || ! -f "$cycle_summary_list" ]]; then
  echo "fake promotion check missing --cycle-summary-list artifact" >&2
  exit 2
fi

if [[ -n "$capture_file" ]]; then
  printf 'promotion\tscenario=%s\tfail_on_no_go=%s\tcycle_summary_list=%s\tsummary_json=%s\n' \
    "$scenario" "$fail_on_no_go" "$cycle_summary_list" "$summary_json" >>"$capture_file"
  while IFS= read -r list_line || [[ -n "$list_line" ]]; do
    printf 'list\t%s\n' "$list_line" >>"$capture_file"
  done <"$cycle_summary_list"
fi

mkdir -p "$(dirname "$summary_json")"

scenario="$(printf '%s' "$scenario" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
if [[ "$scenario" == "invalid" ]]; then
  jq -n '{
    version: 1,
    schema: { id: "profile_default_gate_stability_promotion_summary" },
    status: "fail",
    rc: 0,
    errors: ["invalid promotion summary contract"]
  }' >"$summary_json"
  exit 0
fi

if [[ "$scenario" == "go_exit_nonzero" ]]; then
  jq -n '{
    version: 1,
    schema: { id: "profile_default_gate_stability_promotion_check_summary" },
    decision: "GO",
    status: "ok",
    rc: 0,
    notes: "simulated stale GO with non-zero process rc",
    enforcement: {
      fail_on_no_go: true,
      no_go_detected: false,
      no_go_enforced: false
    },
    outcome: {
      should_promote: true,
      action: "promote_allowed"
    },
    violations: [],
    errors: []
  }' >"$summary_json"
  exit 41
fi

if [[ "$scenario" == "no_go_exit_nonzero" ]]; then
  jq -n '{
    version: 1,
    schema: { id: "profile_default_gate_stability_promotion_check_summary" },
    decision: "NO-GO",
    status: "fail",
    rc: 43,
    notes: "simulated NO-GO with non-zero process rc",
    enforcement: {
      fail_on_no_go: true,
      no_go_detected: true,
      no_go_enforced: true
    },
    outcome: {
      should_promote: false,
      action: "hold_promotion_blocked"
    },
    violations: [],
    errors: []
  }' >"$summary_json"
  exit 43
fi

if [[ "$scenario" == "missing_rc" ]]; then
  jq -n '{
    version: 1,
    schema: { id: "profile_default_gate_stability_promotion_check_summary" },
    decision: "GO",
    status: "ok",
    notes: "simulated missing rc field",
    enforcement: {
      fail_on_no_go: true,
      no_go_detected: false,
      no_go_enforced: false
    },
    outcome: {
      should_promote: true,
      action: "promote_allowed"
    },
    violations: [],
    errors: []
  }' >"$summary_json"
  exit 0
fi

if [[ "$scenario" == "go_semantic_mismatch" ]]; then
  jq -n '{
    version: 1,
    schema: { id: "profile_default_gate_stability_promotion_check_summary" },
    decision: "GO",
    status: "fail",
    rc: 0,
    notes: "simulated contradictory GO summary",
    enforcement: {
      fail_on_no_go: true,
      no_go_detected: false,
      no_go_enforced: true
    },
    outcome: {
      should_promote: false,
      action: "hold_promotion_blocked"
    },
    violations: [],
    errors: []
  }' >"$summary_json"
  exit 0
fi

if [[ "$scenario" == "no_go" ]]; then
  promotion_rc=0
  no_go_enforced=false
  outcome_action="hold_promotion_warn_only"
  if [[ "$fail_on_no_go" == "1" ]]; then
    promotion_rc=1
    no_go_enforced=true
    outcome_action="hold_promotion_blocked"
  fi
  jq -n \
    --argjson promotion_rc "$promotion_rc" \
    --arg outcome_action "$outcome_action" \
    --argjson no_go_enforced "$no_go_enforced" \
    '{
      version: 1,
      schema: { id: "profile_default_gate_stability_promotion_check_summary" },
      decision: "NO-GO",
      status: "fail",
      rc: $promotion_rc,
      notes: "simulated promotion no-go",
      enforcement: {
        fail_on_no_go: true,
        no_go_detected: true,
        no_go_enforced: $no_go_enforced
      },
      outcome: {
        should_promote: false,
        action: $outcome_action
      },
      violations: [
        {
          code: "simulated_no_go",
          field: "observed.cycles_status_fail",
          severity: "error",
          message: "simulated no-go for integration coverage"
        }
      ],
      errors: []
    }' >"$summary_json"
  if [[ "$promotion_rc" -ne 0 ]]; then
    exit "$promotion_rc"
  fi
  exit 0
fi

jq -n '{
  version: 1,
  schema: { id: "profile_default_gate_stability_promotion_check_summary" },
  decision: "GO",
  status: "ok",
  rc: 0,
  notes: "simulated promotion go",
  enforcement: {
    fail_on_no_go: true,
    no_go_detected: false,
    no_go_enforced: false
  },
  outcome: {
    should_promote: true,
    action: "promote_allowed"
  },
  violations: [],
  errors: []
}' >"$summary_json"
exit 0
EOF_FAKE_PROMOTION
chmod +x "$FAKE_PROMOTION_SCRIPT"

echo "[profile-default-gate-stability-promotion-cycle] placeholder subject precondition fails closed"
PLACEHOLDER_SUBJECT_SUMMARY="$TMP_DIR/promotion_cycle_placeholder_subject_summary.json"
PLACEHOLDER_SUBJECT_CAPTURE="$TMP_DIR/promotion_cycle_placeholder_subject_capture.log"
PLACEHOLDER_SUBJECT_COUNTER="$TMP_DIR/promotion_cycle_placeholder_subject_counter.txt"
set +e
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_STABILITY_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
FAKE_PROMOTION_CYCLE_CAPTURE_FILE="$PLACEHOLDER_SUBJECT_CAPTURE" \
FAKE_PROMOTION_CYCLE_COUNTER_FILE="$PLACEHOLDER_SUBJECT_COUNTER" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "a.test" \
  --host-b "b.test" \
  --campaign-subject "INVITE_KEY" \
  --cycles 1 \
  --sleep-between-cycles-sec 0 \
  --summary-json "$PLACEHOLDER_SUBJECT_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_promotion_cycle_placeholder_subject.log 2>&1
placeholder_subject_rc=$?
set -e

if [[ "$placeholder_subject_rc" -eq 0 ]]; then
  echo "expected placeholder subject precondition failure rc!=0"
  cat /tmp/integration_profile_default_gate_stability_promotion_cycle_placeholder_subject.log
  exit 1
fi
if ! grep -Eiq 'placeholder text|provide a real invite key' /tmp/integration_profile_default_gate_stability_promotion_cycle_placeholder_subject.log; then
  echo "expected placeholder subject failure guidance in stderr/stdout output"
  cat /tmp/integration_profile_default_gate_stability_promotion_cycle_placeholder_subject.log
  exit 1
fi
if [[ -s "$PLACEHOLDER_SUBJECT_CAPTURE" ]]; then
  echo "expected no stage script invocation when placeholder subject precondition fails"
  cat "$PLACEHOLDER_SUBJECT_CAPTURE"
  exit 1
fi
if [[ -f "$PLACEHOLDER_SUBJECT_SUMMARY" ]]; then
  echo "expected no summary artifact when placeholder subject precondition fails"
  cat "$PLACEHOLDER_SUBJECT_SUMMARY"
  exit 1
fi

echo "[profile-default-gate-stability-promotion-cycle] strict happy path"
HAPPY_SUMMARY="$TMP_DIR/promotion_cycle_happy_summary.json"
set +e
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_STABILITY_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
FAKE_PROMOTION_CYCLE_CAPTURE_FILE="$CAPTURE_FILE" \
FAKE_PROMOTION_CYCLE_COUNTER_FILE="$COUNTER_FILE" \
FAKE_PROMOTION_CYCLE_SCENARIOS="pass,pass,pass" \
FAKE_PROMOTION_CHECK_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "a.test" \
  --host-b "b.test" \
  --subject "inv-happy" \
  --cycles 3 \
  --sleep-between-cycles-sec 0 \
  --fail-on-no-go 1 \
  --summary-json "$HAPPY_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_promotion_cycle_happy.log 2>&1
happy_rc=$?
set -e

if [[ "$happy_rc" -ne 0 ]]; then
  echo "expected strict happy path rc=0, got rc=$happy_rc"
  cat /tmp/integration_profile_default_gate_stability_promotion_cycle_happy.log
  exit 1
fi
if ! jq -e '
  .schema.id == "profile_default_gate_stability_promotion_cycle_summary"
  and .status == "pass"
  and .rc == 0
  and .decision == "GO"
  and .failure_stage == null
  and .stages.cycle_collection.attempted == true
  and .stages.cycle_collection.cycles_requested == 3
  and .stages.cycle_collection.hard_failures == 0
  and (.stages.cycle_collection.cycles | length) == 3
  and .stages.promotion_check.attempted == true
  and .stages.promotion_check.status == "pass"
  and .promotion.decision == "GO"
  and .promotion.status == "ok"
  and .outcome.should_promote == true
  and .outcome.action == "promote_allowed"
' "$HAPPY_SUMMARY" >/dev/null 2>&1; then
  echo "strict happy-path summary mismatch"
  cat "$HAPPY_SUMMARY"
  exit 1
fi

HAPPY_LIST="$(jq -r '.artifacts.cycle_summary_list' "$HAPPY_SUMMARY")"
if [[ ! -f "$HAPPY_LIST" ]]; then
  echo "expected cycle-summary list artifact not found: $HAPPY_LIST"
  exit 1
fi
if [[ "$(wc -l <"$HAPPY_LIST")" -ne 3 ]]; then
  echo "expected deterministic list with 3 lines"
  cat "$HAPPY_LIST"
  exit 1
fi
if ! grep -q 'profile_default_gate_stability_cycle_01_summary.json' "$HAPPY_LIST"; then
  echo "expected cycle 01 summary path in list"
  cat "$HAPPY_LIST"
  exit 1
fi
if ! grep -q 'profile_default_gate_stability_cycle_02_summary.json' "$HAPPY_LIST"; then
  echo "expected cycle 02 summary path in list"
  cat "$HAPPY_LIST"
  exit 1
fi
if ! grep -q 'profile_default_gate_stability_cycle_03_summary.json' "$HAPPY_LIST"; then
  echo "expected cycle 03 summary path in list"
  cat "$HAPPY_LIST"
  exit 1
fi

if [[ "$(grep -c '^cycle' "$CAPTURE_FILE")" -lt 3 ]]; then
  echo "expected at least 3 cycle invocations in capture"
  cat "$CAPTURE_FILE"
  exit 1
fi
if ! grep -q '^promotion' "$CAPTURE_FILE"; then
  echo "expected promotion invocation in capture"
  cat "$CAPTURE_FILE"
  exit 1
fi
if ! grep -q 'campaign_subject=inv-happy' "$CAPTURE_FILE"; then
  echo "expected cycle command capture to include parsed campaign_subject from --subject alias"
  cat "$CAPTURE_FILE"
  exit 1
fi

echo "[profile-default-gate-stability-promotion-cycle] NO-GO soft path when fail-on-no-go=0"
SOFT_SUMMARY="$TMP_DIR/promotion_cycle_soft_summary.json"
SOFT_CAPTURE="$TMP_DIR/promotion_cycle_soft_capture.log"
SOFT_COUNTER="$TMP_DIR/promotion_cycle_soft_counter.txt"
set +e
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_STABILITY_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
FAKE_PROMOTION_CYCLE_CAPTURE_FILE="$SOFT_CAPTURE" \
FAKE_PROMOTION_CYCLE_COUNTER_FILE="$SOFT_COUNTER" \
FAKE_PROMOTION_CYCLE_SCENARIOS="pass,no_go,pass" \
FAKE_PROMOTION_CHECK_SCENARIO="no_go" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "a.test" \
  --host-b "b.test" \
  --campaign-subject "inv-soft" \
  --cycles 3 \
  --sleep-between-cycles-sec 0 \
  --fail-on-no-go 0 \
  --summary-json "$SOFT_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_promotion_cycle_soft.log 2>&1
soft_rc=$?
set -e

if [[ "$soft_rc" -ne 0 ]]; then
  echo "expected NO-GO soft path rc=0, got rc=$soft_rc"
  cat /tmp/integration_profile_default_gate_stability_promotion_cycle_soft.log
  exit 1
fi
if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .decision == "NO-GO"
  and .failure_stage == null
  and .stages.promotion_check.attempted == true
  and .promotion.decision == "NO-GO"
  and .promotion.status == "fail"
  and .enforcement.no_go_enforced == false
  and .outcome.action == "hold_promotion_warn_only"
' "$SOFT_SUMMARY" >/dev/null 2>&1; then
  echo "NO-GO soft summary mismatch"
  cat "$SOFT_SUMMARY"
  exit 1
fi

echo "[profile-default-gate-stability-promotion-cycle] cycle artifact contract failure is fail-closed"
HARD_FAIL_SUMMARY="$TMP_DIR/promotion_cycle_hard_fail_summary.json"
HARD_FAIL_CAPTURE="$TMP_DIR/promotion_cycle_hard_fail_capture.log"
HARD_FAIL_COUNTER="$TMP_DIR/promotion_cycle_hard_fail_counter.txt"
set +e
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_STABILITY_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
FAKE_PROMOTION_CYCLE_CAPTURE_FILE="$HARD_FAIL_CAPTURE" \
FAKE_PROMOTION_CYCLE_COUNTER_FILE="$HARD_FAIL_COUNTER" \
FAKE_PROMOTION_CYCLE_SCENARIOS="pass,missing_summary" \
FAKE_PROMOTION_CHECK_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "a.test" \
  --host-b "b.test" \
  --campaign-subject "inv-hard-fail" \
  --cycles 2 \
  --sleep-between-cycles-sec 0 \
  --fail-on-no-go 0 \
  --summary-json "$HARD_FAIL_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_promotion_cycle_hard_fail.log 2>&1
hard_fail_rc=$?
set -e

if [[ "$hard_fail_rc" -eq 0 ]]; then
  echo "expected cycle artifact contract failure path rc!=0"
  cat /tmp/integration_profile_default_gate_stability_promotion_cycle_hard_fail.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc != 0
  and .decision == "NO-GO"
  and .failure_stage == "cycle_collection"
  and .failure_reason == "cycle_collection_artifact_contract_failed"
  and .stages.cycle_collection.hard_failures >= 1
  and .stages.promotion_check.attempted == true
  and .promotion.decision == "GO"
' "$HARD_FAIL_SUMMARY" >/dev/null 2>&1; then
  echo "cycle artifact hard-fail summary mismatch"
  cat "$HARD_FAIL_SUMMARY"
  exit 1
fi

echo "[profile-default-gate-stability-promotion-cycle] invalid promotion summary contract fails closed"
PROMOTION_INVALID_SUMMARY="$TMP_DIR/promotion_cycle_invalid_promotion_summary.json"
PROMOTION_INVALID_CAPTURE="$TMP_DIR/promotion_cycle_invalid_promotion_capture.log"
PROMOTION_INVALID_COUNTER="$TMP_DIR/promotion_cycle_invalid_promotion_counter.txt"
set +e
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_STABILITY_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
FAKE_PROMOTION_CYCLE_CAPTURE_FILE="$PROMOTION_INVALID_CAPTURE" \
FAKE_PROMOTION_CYCLE_COUNTER_FILE="$PROMOTION_INVALID_COUNTER" \
FAKE_PROMOTION_CYCLE_SCENARIOS="pass" \
FAKE_PROMOTION_CHECK_SCENARIO="invalid" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "a.test" \
  --host-b "b.test" \
  --campaign-subject "inv-promotion-invalid" \
  --cycles 1 \
  --sleep-between-cycles-sec 0 \
  --fail-on-no-go 0 \
  --summary-json "$PROMOTION_INVALID_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_promotion_cycle_invalid_promotion.log 2>&1
promotion_invalid_rc=$?
set -e

if [[ "$promotion_invalid_rc" -eq 0 ]]; then
  echo "expected invalid promotion summary contract path rc!=0"
  cat /tmp/integration_profile_default_gate_stability_promotion_cycle_invalid_promotion.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc != 0
  and .decision == "NO-GO"
  and .failure_stage == "promotion_check"
  and .failure_reason == "promotion_summary_schema_invalid"
  and .stages.promotion_check.summary_valid_json == true
  and .stages.promotion_check.summary_schema_valid == false
' "$PROMOTION_INVALID_SUMMARY" >/dev/null 2>&1; then
  echo "invalid promotion summary fail-closed mismatch"
  cat "$PROMOTION_INVALID_SUMMARY"
  exit 1
fi

echo "[profile-default-gate-stability-promotion-cycle] contradictory GO promotion summary fails closed with deterministic diagnostics"
PROMOTION_SEMANTIC_MISMATCH_SUMMARY="$TMP_DIR/promotion_cycle_promotion_semantic_mismatch_summary.json"
PROMOTION_SEMANTIC_MISMATCH_CAPTURE="$TMP_DIR/promotion_cycle_promotion_semantic_mismatch_capture.log"
PROMOTION_SEMANTIC_MISMATCH_COUNTER="$TMP_DIR/promotion_cycle_promotion_semantic_mismatch_counter.txt"
set +e
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_STABILITY_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
FAKE_PROMOTION_CYCLE_CAPTURE_FILE="$PROMOTION_SEMANTIC_MISMATCH_CAPTURE" \
FAKE_PROMOTION_CYCLE_COUNTER_FILE="$PROMOTION_SEMANTIC_MISMATCH_COUNTER" \
FAKE_PROMOTION_CYCLE_SCENARIOS="pass" \
FAKE_PROMOTION_CHECK_SCENARIO="go_semantic_mismatch" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "a.test" \
  --host-b "b.test" \
  --campaign-subject "inv-promotion-semantic-mismatch" \
  --cycles 1 \
  --sleep-between-cycles-sec 0 \
  --fail-on-no-go 0 \
  --summary-json "$PROMOTION_SEMANTIC_MISMATCH_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_promotion_cycle_semantic_mismatch.log 2>&1
promotion_semantic_mismatch_rc=$?
set -e

if [[ "$promotion_semantic_mismatch_rc" -eq 0 ]]; then
  echo "expected semantic mismatch promotion summary path rc!=0"
  cat /tmp/integration_profile_default_gate_stability_promotion_cycle_semantic_mismatch.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc != 0
  and .decision == "NO-GO"
  and .failure_stage == "promotion_check"
  and .failure_reason == "promotion_summary_semantic_contract_mismatch"
  and .promotion.decision == "GO"
  and .promotion.contract.semantic_valid == false
  and ((.promotion.contract.mismatches.codes | index("status_mismatch")) != null)
  and ((.promotion.contract.mismatches.codes | index("outcome_action_mismatch")) != null)
  and .diagnostics.fail_closed.triggered == true
  and .diagnostics.fail_closed.primary_reason_code == "promotion_summary_semantic_contract_mismatch"
  and .diagnostics.fail_closed.primary_reason_category == "summary_contract"
  and (.diagnostics.fail_closed.next_operator_action_command | contains("profile_default_gate_stability_promotion_check.sh"))
' "$PROMOTION_SEMANTIC_MISMATCH_SUMMARY" >/dev/null 2>&1; then
  echo "semantic mismatch fail-closed summary mismatch"
  cat "$PROMOTION_SEMANTIC_MISMATCH_SUMMARY"
  exit 1
fi

echo "[profile-default-gate-stability-promotion-cycle] cycle command rc mismatch fails closed"
CYCLE_RC_MISMATCH_SUMMARY="$TMP_DIR/promotion_cycle_cycle_rc_mismatch_summary.json"
CYCLE_RC_MISMATCH_CAPTURE="$TMP_DIR/promotion_cycle_cycle_rc_mismatch_capture.log"
CYCLE_RC_MISMATCH_COUNTER="$TMP_DIR/promotion_cycle_cycle_rc_mismatch_counter.txt"
set +e
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_STABILITY_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
FAKE_PROMOTION_CYCLE_CAPTURE_FILE="$CYCLE_RC_MISMATCH_CAPTURE" \
FAKE_PROMOTION_CYCLE_COUNTER_FILE="$CYCLE_RC_MISMATCH_COUNTER" \
FAKE_PROMOTION_CYCLE_SCENARIOS="go_exit_nonzero" \
FAKE_PROMOTION_CHECK_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "a.test" \
  --host-b "b.test" \
  --campaign-subject "inv-cycle-rc-mismatch" \
  --cycles 1 \
  --sleep-between-cycles-sec 0 \
  --fail-on-no-go 0 \
  --summary-json "$CYCLE_RC_MISMATCH_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_promotion_cycle_cycle_rc_mismatch.log 2>&1
cycle_rc_mismatch_rc=$?
set -e

if [[ "$cycle_rc_mismatch_rc" -eq 0 ]]; then
  echo "expected cycle command rc mismatch path rc!=0"
  cat /tmp/integration_profile_default_gate_stability_promotion_cycle_cycle_rc_mismatch.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc != 0
  and .decision == "NO-GO"
  and .failure_stage == "cycle_collection"
  and .failure_reason == "cycle_collection_artifact_contract_failed"
  and .stages.cycle_collection.hard_failures >= 1
  and ((.stages.cycle_collection.cycles[0].failure_reason // "") == "cycle_command_rc_contract_mismatch")
' "$CYCLE_RC_MISMATCH_SUMMARY" >/dev/null 2>&1; then
  echo "cycle command rc mismatch summary mismatch"
  cat "$CYCLE_RC_MISMATCH_SUMMARY"
  exit 1
fi

echo "[profile-default-gate-stability-promotion-cycle] promotion command rc mismatch fails closed"
PROMOTION_RC_MISMATCH_SUMMARY="$TMP_DIR/promotion_cycle_promotion_rc_mismatch_summary.json"
PROMOTION_RC_MISMATCH_CAPTURE="$TMP_DIR/promotion_cycle_promotion_rc_mismatch_capture.log"
PROMOTION_RC_MISMATCH_COUNTER="$TMP_DIR/promotion_cycle_promotion_rc_mismatch_counter.txt"
set +e
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_STABILITY_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
FAKE_PROMOTION_CYCLE_CAPTURE_FILE="$PROMOTION_RC_MISMATCH_CAPTURE" \
FAKE_PROMOTION_CYCLE_COUNTER_FILE="$PROMOTION_RC_MISMATCH_COUNTER" \
FAKE_PROMOTION_CYCLE_SCENARIOS="pass" \
FAKE_PROMOTION_CHECK_SCENARIO="go_exit_nonzero" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "a.test" \
  --host-b "b.test" \
  --campaign-subject "inv-promotion-rc-mismatch" \
  --cycles 1 \
  --sleep-between-cycles-sec 0 \
  --fail-on-no-go 0 \
  --summary-json "$PROMOTION_RC_MISMATCH_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_promotion_cycle_promotion_rc_mismatch.log 2>&1
promotion_rc_mismatch_rc=$?
set -e

if [[ "$promotion_rc_mismatch_rc" -eq 0 ]]; then
  echo "expected promotion command rc mismatch path rc!=0"
  cat /tmp/integration_profile_default_gate_stability_promotion_cycle_promotion_rc_mismatch.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc != 0
  and .decision == "NO-GO"
  and .failure_stage == "promotion_check"
  and .failure_reason == "promotion_command_rc_contract_mismatch"
  and .outcome.should_promote == false
  and .outcome.action == "hold_promotion_blocked"
' "$PROMOTION_RC_MISMATCH_SUMMARY" >/dev/null 2>&1; then
  echo "promotion command rc mismatch summary mismatch"
  cat "$PROMOTION_RC_MISMATCH_SUMMARY"
  exit 1
fi

echo "[profile-default-gate-stability-promotion-cycle] cycle summary missing rc fails closed"
CYCLE_MISSING_RC_SUMMARY="$TMP_DIR/promotion_cycle_cycle_missing_rc_summary.json"
CYCLE_MISSING_RC_CAPTURE="$TMP_DIR/promotion_cycle_cycle_missing_rc_capture.log"
CYCLE_MISSING_RC_COUNTER="$TMP_DIR/promotion_cycle_cycle_missing_rc_counter.txt"
set +e
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_STABILITY_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
FAKE_PROMOTION_CYCLE_CAPTURE_FILE="$CYCLE_MISSING_RC_CAPTURE" \
FAKE_PROMOTION_CYCLE_COUNTER_FILE="$CYCLE_MISSING_RC_COUNTER" \
FAKE_PROMOTION_CYCLE_SCENARIOS="missing_rc" \
FAKE_PROMOTION_CHECK_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "a.test" \
  --host-b "b.test" \
  --campaign-subject "inv-cycle-missing-rc" \
  --cycles 1 \
  --sleep-between-cycles-sec 0 \
  --summary-json "$CYCLE_MISSING_RC_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_promotion_cycle_cycle_missing_rc.log 2>&1
cycle_missing_rc_rc=$?
set -e

if [[ "$cycle_missing_rc_rc" -eq 0 ]]; then
  echo "expected cycle missing-rc contract path rc!=0"
  cat /tmp/integration_profile_default_gate_stability_promotion_cycle_cycle_missing_rc.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc != 0
  and .decision == "NO-GO"
  and .failure_stage == "cycle_collection"
  and .failure_reason == "cycle_collection_artifact_contract_failed"
  and ((.stages.cycle_collection.cycles[0].failure_reason // "") == "cycle_command_rc_contract_mismatch")
' "$CYCLE_MISSING_RC_SUMMARY" >/dev/null 2>&1; then
  echo "cycle missing-rc summary mismatch"
  cat "$CYCLE_MISSING_RC_SUMMARY"
  exit 1
fi

echo "[profile-default-gate-stability-promotion-cycle] missing run/check evidence artifacts fail closed"
MISSING_SUPPORTING_SUMMARY="$TMP_DIR/promotion_cycle_missing_supporting_summary.json"
MISSING_SUPPORTING_CAPTURE="$TMP_DIR/promotion_cycle_missing_supporting_capture.log"
MISSING_SUPPORTING_COUNTER="$TMP_DIR/promotion_cycle_missing_supporting_counter.txt"
set +e
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_STABILITY_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
FAKE_PROMOTION_CYCLE_CAPTURE_FILE="$MISSING_SUPPORTING_CAPTURE" \
FAKE_PROMOTION_CYCLE_COUNTER_FILE="$MISSING_SUPPORTING_COUNTER" \
FAKE_PROMOTION_CYCLE_SCENARIOS="missing_supporting_summaries" \
FAKE_PROMOTION_CHECK_SCENARIO="go" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "a.test" \
  --host-b "b.test" \
  --campaign-subject "inv-missing-supporting-evidence" \
  --cycles 1 \
  --sleep-between-cycles-sec 0 \
  --fail-on-no-go 0 \
  --summary-json "$MISSING_SUPPORTING_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_promotion_cycle_missing_supporting.log 2>&1
missing_supporting_rc=$?
set -e

if [[ "$missing_supporting_rc" -eq 0 ]]; then
  echo "expected missing supporting evidence path rc!=0"
  cat /tmp/integration_profile_default_gate_stability_promotion_cycle_missing_supporting.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc != 0
  and .decision == "NO-GO"
  and .failure_stage == "cycle_collection"
  and .failure_reason == "cycle_collection_artifact_contract_failed"
  and .stages.cycle_collection.hard_failures >= 1
  and .stages.cycle_collection.cycles[0].run_summary_exists == false
  and .stages.cycle_collection.cycles[0].check_summary_exists == false
  and ((.stages.cycle_collection.cycles[0].failure_reason // "") == "cycle_run_summary_missing")
' "$MISSING_SUPPORTING_SUMMARY" >/dev/null 2>&1; then
  echo "missing supporting evidence summary mismatch"
  cat "$MISSING_SUPPORTING_SUMMARY"
  exit 1
fi

echo "[profile-default-gate-stability-promotion-cycle] promotion summary missing rc fails closed"
PROMOTION_MISSING_RC_SUMMARY="$TMP_DIR/promotion_cycle_promotion_missing_rc_summary.json"
PROMOTION_MISSING_RC_CAPTURE="$TMP_DIR/promotion_cycle_promotion_missing_rc_capture.log"
PROMOTION_MISSING_RC_COUNTER="$TMP_DIR/promotion_cycle_promotion_missing_rc_counter.txt"
set +e
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_STABILITY_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
FAKE_PROMOTION_CYCLE_CAPTURE_FILE="$PROMOTION_MISSING_RC_CAPTURE" \
FAKE_PROMOTION_CYCLE_COUNTER_FILE="$PROMOTION_MISSING_RC_COUNTER" \
FAKE_PROMOTION_CYCLE_SCENARIOS="pass" \
FAKE_PROMOTION_CHECK_SCENARIO="missing_rc" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "a.test" \
  --host-b "b.test" \
  --campaign-subject "inv-promotion-missing-rc" \
  --cycles 1 \
  --sleep-between-cycles-sec 0 \
  --summary-json "$PROMOTION_MISSING_RC_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_promotion_cycle_promotion_missing_rc.log 2>&1
promotion_missing_rc_rc=$?
set -e

if [[ "$promotion_missing_rc_rc" -eq 0 ]]; then
  echo "expected promotion missing-rc contract path rc!=0"
  cat /tmp/integration_profile_default_gate_stability_promotion_cycle_promotion_missing_rc.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc != 0
  and .decision == "NO-GO"
  and .failure_stage == "promotion_check"
  and .failure_reason == "promotion_command_rc_contract_mismatch"
  and .outcome.should_promote == false
  and .outcome.action == "hold_promotion_blocked"
' "$PROMOTION_MISSING_RC_SUMMARY" >/dev/null 2>&1; then
  echo "promotion missing-rc summary mismatch"
  cat "$PROMOTION_MISSING_RC_SUMMARY"
  exit 1
fi

echo "[profile-default-gate-stability-promotion-cycle] promotion non-zero NO-GO fails closed even when fail-on-no-go=0"
PROMOTION_NOGO_NONZERO_SUMMARY="$TMP_DIR/promotion_cycle_promotion_nogo_nonzero_summary.json"
PROMOTION_NOGO_NONZERO_CAPTURE="$TMP_DIR/promotion_cycle_promotion_nogo_nonzero_capture.log"
PROMOTION_NOGO_NONZERO_COUNTER="$TMP_DIR/promotion_cycle_promotion_nogo_nonzero_counter.txt"
set +e
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_STABILITY_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CYCLE_PROMOTION_CHECK_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
FAKE_PROMOTION_CYCLE_CAPTURE_FILE="$PROMOTION_NOGO_NONZERO_CAPTURE" \
FAKE_PROMOTION_CYCLE_COUNTER_FILE="$PROMOTION_NOGO_NONZERO_COUNTER" \
FAKE_PROMOTION_CYCLE_SCENARIOS="pass" \
FAKE_PROMOTION_CHECK_SCENARIO="no_go_exit_nonzero" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "a.test" \
  --host-b "b.test" \
  --campaign-subject "inv-promotion-no-go-exit-nonzero" \
  --cycles 1 \
  --sleep-between-cycles-sec 0 \
  --fail-on-no-go 0 \
  --summary-json "$PROMOTION_NOGO_NONZERO_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_promotion_cycle_promotion_nogo_nonzero.log 2>&1
promotion_nogo_nonzero_rc=$?
set -e

if [[ "$promotion_nogo_nonzero_rc" -eq 0 ]]; then
  echo "expected promotion non-zero NO-GO path rc!=0"
  cat /tmp/integration_profile_default_gate_stability_promotion_cycle_promotion_nogo_nonzero.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc != 0
  and .decision == "NO-GO"
  and .failure_stage == "promotion_check"
  and .failure_reason == "promotion_command_rc_contract_mismatch"
  and .outcome.should_promote == false
  and .outcome.action == "hold_promotion_blocked"
' "$PROMOTION_NOGO_NONZERO_SUMMARY" >/dev/null 2>&1; then
  echo "promotion non-zero NO-GO summary mismatch"
  cat "$PROMOTION_NOGO_NONZERO_SUMMARY"
  exit 1
fi

echo "profile default gate stability promotion cycle integration ok"
