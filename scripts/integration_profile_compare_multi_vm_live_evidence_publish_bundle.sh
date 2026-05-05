#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp cat chmod grep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/profile_compare_multi_vm_live_evidence_publish_bundle.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

assert_jq() {
  local file="$1"
  local query="$2"
  if ! jq -e "$query" "$file" >/dev/null 2>&1; then
    echo "assertion failed: $query"
    echo "file: $file"
    cat "$file"
    exit 1
  fi
}

FAKE_STABILITY_SCRIPT="$TMP_DIR/fake_profile_compare_multi_vm_stability_cycle.sh"
cat >"$FAKE_STABILITY_SCRIPT" <<'EOF_FAKE_STABILITY'
#!/usr/bin/env bash
set -euo pipefail

scenario="${FAKE_M5_STABILITY_SCENARIO:-pass}"
summary_json=""
capture_file="${FAKE_M5_CAPTURE_FILE:-}"

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
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" ]]; then
  echo "fake stability cycle missing --summary-json" >&2
  exit 2
fi

if [[ -n "$capture_file" ]]; then
  printf 'stability\tscenario=%s\tsummary_json=%s\n' "$scenario" "$summary_json" >>"$capture_file"
fi

scenario="$(printf '%s' "$scenario" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
if [[ "$scenario" == "missing_no_write" ]]; then
  exit 0
fi

mkdir -p "$(dirname "$summary_json")"

run_summary_fresh=true
check_summary_fresh=true
decision="GO"
status="pass"
rc=0
failure_reason_code=""
if [[ "$scenario" == "stale" ]]; then
  run_summary_fresh=false
  check_summary_fresh=false
  status="fail"
  rc=1
  decision="NO-GO"
  failure_reason_code="run_summary_stale"
fi

jq -n \
  --arg decision "$decision" \
  --arg status "$status" \
  --arg failure_reason_code "$failure_reason_code" \
  --argjson rc "$rc" \
  --argjson run_summary_fresh "$run_summary_fresh" \
  --argjson check_summary_fresh "$check_summary_fresh" \
  '{
    version: 1,
    schema: { id: "profile_compare_multi_vm_stability_cycle_summary" },
    status: $status,
    rc: $rc,
    decision: $decision,
    failure_reason_code: (if $failure_reason_code == "" then null else $failure_reason_code end),
    run: {
      summary_exists: true,
      summary_valid_json: true,
      summary_fresh: $run_summary_fresh
    },
    check: {
      summary_exists: true,
      summary_valid_json: true,
      summary_fresh: $check_summary_fresh
    },
    next_operator_action: "stability stage action"
  }' >"$summary_json"
exit 0
EOF_FAKE_STABILITY
chmod +x "$FAKE_STABILITY_SCRIPT"

FAKE_PROMOTION_SCRIPT="$TMP_DIR/fake_profile_compare_multi_vm_stability_promotion_cycle.sh"
cat >"$FAKE_PROMOTION_SCRIPT" <<'EOF_FAKE_PROMOTION'
#!/usr/bin/env bash
set -euo pipefail

scenario="${FAKE_M5_PROMOTION_SCENARIO:-pass}"
summary_json=""
capture_file="${FAKE_M5_CAPTURE_FILE:-}"
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
  echo "fake promotion cycle missing --summary-json" >&2
  exit 2
fi

if [[ -n "$capture_file" ]]; then
  printf 'promotion\tscenario=%s\tfail_on_no_go=%s\tsummary_json=%s\n' "$scenario" "$fail_on_no_go" "$summary_json" >>"$capture_file"
fi

scenario="$(printf '%s' "$scenario" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
if [[ "$scenario" == "missing_no_write" ]]; then
  exit 0
fi

mkdir -p "$(dirname "$summary_json")"

decision="GO"
status="pass"
rc=0
if [[ "$scenario" == "no_go" ]]; then
  decision="NO-GO"
  status="warn"
  rc=0
fi
if [[ "$scenario" == "runner_nonzero_with_summary" ]]; then
  decision="GO"
  status="pass"
  rc=0
fi

jq -n \
  --arg decision "$decision" \
  --arg status "$status" \
  --argjson rc "$rc" \
  '{
    version: 1,
    schema: { id: "profile_compare_multi_vm_stability_promotion_cycle_summary" },
    status: $status,
    rc: $rc,
    decision: $decision,
    promotion: {
      summary_exists: true,
      summary_valid_json: true,
      summary_fresh: true
    },
    next_operator_action: "promotion cycle action",
    operator_next_action_command: "./scripts/profile_compare_multi_vm_stability_promotion_cycle.sh --reports-dir .easy-node-logs --print-summary-json 1"
  }' >"$summary_json"
if [[ "$scenario" == "runner_nonzero_with_summary" ]]; then
  exit "${FAKE_M5_PROMOTION_RC:-7}"
fi
exit 0
EOF_FAKE_PROMOTION
chmod +x "$FAKE_PROMOTION_SCRIPT"

FAKE_PACK_SCRIPT="$TMP_DIR/fake_profile_compare_multi_vm_stability_promotion_evidence_pack.sh"
cat >"$FAKE_PACK_SCRIPT" <<'EOF_FAKE_PACK'
#!/usr/bin/env bash
set -euo pipefail

scenario="${FAKE_M5_PACK_SCENARIO:-pass}"
summary_json=""
capture_file="${FAKE_M5_CAPTURE_FILE:-}"

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
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" ]]; then
  echo "fake evidence-pack missing --summary-json" >&2
  exit 2
fi

if [[ -n "$capture_file" ]]; then
  printf 'pack\tscenario=%s\tsummary_json=%s\n' "$scenario" "$summary_json" >>"$capture_file"
fi

scenario="$(printf '%s' "$scenario" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
if [[ "$scenario" == "missing_no_write" ]]; then
  exit 0
fi

mkdir -p "$(dirname "$summary_json")"

decision="GO"
status="ok"
rc=0
next_command="./scripts/profile_compare_multi_vm_stability_promotion_cycle.sh --reports-dir .easy-node-logs --print-summary-json 1"
operator_next_action_command="$next_command"
  if [[ "$scenario" == "no_go_placeholder" ]]; then
    decision="NO-GO"
    status="warn"
    rc=0
    next_command="./scripts/profile_compare_multi_vm_stability_promotion_cycle.sh --campaign-subject INVITE_KEY --print-summary-json 1"
    operator_next_action_command="$next_command"
  fi
  if [[ "$scenario" == "unsafe_command_hint" ]]; then
    decision="NO-GO"
    status="warn"
    rc=0
    next_command="rm -rf /tmp/gpm-unsafe"
    operator_next_action_command="$next_command"
  fi

  jq -n \
    --arg decision "$decision" \
  --arg status "$status" \
  --arg next_command "$next_command" \
  --arg operator_next_action_command "$operator_next_action_command" \
  --argjson rc "$rc" \
  '{
    version: 1,
    schema: { id: "profile_compare_multi_vm_stability_promotion_evidence_pack_summary" },
    status: $status,
    rc: $rc,
    decision: $decision,
    next_operator_action: "promotion evidence-pack action",
    next_command: $next_command,
    operator_next_action_command: $operator_next_action_command,
    evidence: {
      promotion_cycle: {
        freshness: {
          fresh: true
        }
      }
    }
  }' >"$summary_json"
exit 0
EOF_FAKE_PACK
chmod +x "$FAKE_PACK_SCRIPT"

echo "[m5-live-evidence-publish-bundle] pass path"
PASS_SUMMARY="$TMP_DIR/pass_bundle_summary.json"
PASS_CAPTURE="$TMP_DIR/pass_capture.log"
set +e
PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_STABILITY_CYCLE_SCRIPT="$FAKE_STABILITY_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_PROMOTION_CYCLE_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_M5_CAPTURE_FILE="$PASS_CAPTURE" \
FAKE_M5_STABILITY_SCENARIO="pass" \
FAKE_M5_PROMOTION_SCENARIO="pass" \
FAKE_M5_PACK_SCENARIO="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/pass_reports" \
  --cycles 2 \
  --fail-on-no-go 1 \
  --summary-json "$PASS_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_live_evidence_publish_bundle_pass.log 2>&1
pass_rc=$?
set -e

if [[ "$pass_rc" -ne 0 ]]; then
  echo "expected pass path rc=0, got rc=$pass_rc"
  cat /tmp/integration_profile_compare_multi_vm_live_evidence_publish_bundle_pass.log
  exit 1
fi
assert_jq "$PASS_SUMMARY" '
  .schema.id == "profile_compare_multi_vm_live_evidence_publish_bundle_summary"
  and .status == "pass"
  and .rc == 0
  and .decision == "GO"
  and .stages.stability_cycle.attempted == true
  and .stages.promotion_cycle.attempted == true
  and .stages.promotion_evidence_pack_publish.attempted == true
  and .stages.stability_cycle.summary.usable == true
  and .stages.promotion_cycle.summary.usable == true
  and .stages.promotion_evidence_pack_publish.summary.usable == true
  and .next_command == null
'

echo "[m5-live-evidence-publish-bundle] missing prerequisite path"
MISSING_SUMMARY="$TMP_DIR/missing_bundle_summary.json"
MISSING_CAPTURE="$TMP_DIR/missing_capture.log"
set +e
PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_STABILITY_CYCLE_SCRIPT="$FAKE_STABILITY_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_PROMOTION_CYCLE_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_M5_CAPTURE_FILE="$MISSING_CAPTURE" \
FAKE_M5_STABILITY_SCENARIO="missing_no_write" \
FAKE_M5_PROMOTION_SCENARIO="pass" \
FAKE_M5_PACK_SCENARIO="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/missing_reports" \
  --cycles 2 \
  --fail-on-no-go 1 \
  --summary-json "$MISSING_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_live_evidence_publish_bundle_missing.log 2>&1
missing_rc=$?
set -e

if [[ "$missing_rc" -eq 0 ]]; then
  echo "expected missing prerequisite path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_live_evidence_publish_bundle_missing.log
  exit 1
fi
assert_jq "$MISSING_SUMMARY" '
  .status == "fail"
  and .decision == "NO-GO"
  and .rc != 0
  and .failure_reason_code == "stability_cycle_summary_missing_or_stale"
  and .stages.stability_cycle.attempted == true
  and .stages.stability_cycle.summary.summary_exists == false
  and .stages.promotion_cycle.attempted == false
  and .stages.promotion_evidence_pack_publish.attempted == false
  and (.next_command_reason | test("stability cycle summary artifact is missing or stale"))
'

echo "[m5-live-evidence-publish-bundle] NO-GO promotion path (warn-only compatibility)"
NOGO_SUMMARY="$TMP_DIR/nogo_bundle_summary.json"
NOGO_CAPTURE="$TMP_DIR/nogo_capture.log"
set +e
PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_STABILITY_CYCLE_SCRIPT="$FAKE_STABILITY_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_PROMOTION_CYCLE_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_M5_CAPTURE_FILE="$NOGO_CAPTURE" \
FAKE_M5_STABILITY_SCENARIO="pass" \
FAKE_M5_PROMOTION_SCENARIO="no_go" \
FAKE_M5_PACK_SCENARIO="no_go_placeholder" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/nogo_reports" \
  --cycles 2 \
  --fail-on-no-go 0 \
  --summary-json "$NOGO_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_live_evidence_publish_bundle_nogo.log 2>&1
nogo_rc=$?
set -e

if [[ "$nogo_rc" -ne 0 ]]; then
  echo "expected NO-GO warn-only path rc=0, got rc=$nogo_rc"
  cat /tmp/integration_profile_compare_multi_vm_live_evidence_publish_bundle_nogo.log
  exit 1
fi
assert_jq "$NOGO_SUMMARY" '
  .status == "warn"
  and .rc == 0
  and .decision == "NO-GO"
  and .failure_reason_code == "promotion_decision_no_go_warn_only"
  and .stages.promotion_cycle.attempted == true
  and .stages.promotion_evidence_pack_publish.attempted == true
  and (.next_command_reason | test("NO-GO"))
'
assert_jq "$NOGO_SUMMARY" '((.next_command // "") | test("INVITE_KEY") | not)'
assert_jq "$NOGO_SUMMARY" '((.next_command // "") | test("CAMPAIGN_SUBJECT") | not)'
assert_jq "$NOGO_SUMMARY" '((.next_command // "") | test("profile_compare_multi_vm_stability_promotion_cycle\\.sh|profile_compare_multi_vm_live_evidence_publish_bundle\\.sh"))'

echo "[m5-live-evidence-publish-bundle] unsafe next-command hint is dropped fail-closed"
UNSAFE_SUMMARY="$TMP_DIR/unsafe_bundle_summary.json"
UNSAFE_CAPTURE="$TMP_DIR/unsafe_capture.log"
set +e
PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_STABILITY_CYCLE_SCRIPT="$FAKE_STABILITY_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_PROMOTION_CYCLE_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_M5_CAPTURE_FILE="$UNSAFE_CAPTURE" \
FAKE_M5_STABILITY_SCENARIO="pass" \
FAKE_M5_PROMOTION_SCENARIO="pass" \
FAKE_M5_PACK_SCENARIO="unsafe_command_hint" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/unsafe_reports" \
  --cycles 2 \
  --fail-on-no-go 0 \
  --summary-json "$UNSAFE_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_live_evidence_publish_bundle_unsafe_hint.log 2>&1
unsafe_rc=$?
set -e

if [[ "$unsafe_rc" -ne 0 ]]; then
  echo "expected unsafe-hint warn-only path rc=0, got rc=$unsafe_rc"
  cat /tmp/integration_profile_compare_multi_vm_live_evidence_publish_bundle_unsafe_hint.log
  exit 1
fi
assert_jq "$UNSAFE_SUMMARY" '
  .status == "warn"
  and .decision == "NO-GO"
  and .rc == 0
  and ((.next_command // "") | contains("rm -rf") | not)
  and ((.next_command // "") | test("profile_compare_multi_vm_stability_promotion_cycle\\.sh|profile_compare_multi_vm_live_evidence_publish_bundle\\.sh"))
'

echo "[m5-live-evidence-publish-bundle] promotion runner nonzero with summary fail-closed path"
RUNNER_FAIL_SUMMARY="$TMP_DIR/runner_fail_bundle_summary.json"
RUNNER_FAIL_CAPTURE="$TMP_DIR/runner_fail_capture.log"
set +e
PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_STABILITY_CYCLE_SCRIPT="$FAKE_STABILITY_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_PROMOTION_CYCLE_SCRIPT="$FAKE_PROMOTION_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_LIVE_EVIDENCE_PUBLISH_BUNDLE_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_M5_CAPTURE_FILE="$RUNNER_FAIL_CAPTURE" \
FAKE_M5_STABILITY_SCENARIO="pass" \
FAKE_M5_PROMOTION_SCENARIO="runner_nonzero_with_summary" \
FAKE_M5_PROMOTION_RC="7" \
FAKE_M5_PACK_SCENARIO="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/runner_fail_reports" \
  --cycles 2 \
  --fail-on-no-go 1 \
  --summary-json "$RUNNER_FAIL_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_live_evidence_publish_bundle_runner_nonzero.log 2>&1
runner_fail_rc=$?
set -e

if [[ "$runner_fail_rc" -eq 0 ]]; then
  echo "expected promotion runner nonzero path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_live_evidence_publish_bundle_runner_nonzero.log
  exit 1
fi
assert_jq "$RUNNER_FAIL_SUMMARY" '
  .status == "fail"
  and .rc != 0
  and .decision == "NO-GO"
  and .failure_reason_code == "promotion_cycle_runner_nonzero"
  and .failure_substep == "promotion_cycle_runner_nonzero"
  and .stages.stability_cycle.attempted == true
  and .stages.stability_cycle.status == "pass"
  and .stages.promotion_cycle.attempted == true
  and .stages.promotion_cycle.status == "fail"
  and .stages.promotion_cycle.rc == 7
  and .stages.promotion_evidence_pack_publish.attempted == false
  and .stages.promotion_evidence_pack_publish.status == "skip"
'

echo "profile compare multi-vm live evidence publish bundle integration ok"
