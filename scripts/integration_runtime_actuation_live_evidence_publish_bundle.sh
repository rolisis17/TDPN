#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp grep cat; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/runtime_actuation_live_evidence_publish_bundle.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

FAKE_CYCLE_SCRIPT="$TMP_DIR/fake_runtime_actuation_promotion_cycle.sh"
FAKE_EVIDENCE_SCRIPT="$TMP_DIR/fake_runtime_actuation_promotion_evidence_pack.sh"

cat >"$FAKE_CYCLE_SCRIPT" <<'EOF_FAKE_CYCLE'
#!/usr/bin/env bash
set -euo pipefail

summary_json=""
print_summary_json="0"

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
    --print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_summary_json="${2:-}"
        shift 2
      else
        print_summary_json="1"
        shift
      fi
      ;;
    --print-summary-json=*)
      print_summary_json="${1#*=}"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" ]]; then
  echo "fake cycle: missing --summary-json" >&2
  exit 2
fi

mode="${FAKE_CYCLE_MODE:-pass}"
mkdir -p "$(dirname "$summary_json")"

case "$mode" in
  pass)
    cat >"$summary_json" <<'EOF_SUMMARY'
{
  "version": 1,
  "schema": { "id": "runtime_actuation_promotion_cycle_summary" },
  "status": "pass",
  "rc": 0,
  "decision": "GO"
}
EOF_SUMMARY
    exit_code=0
    ;;
  missing)
    rm -f "$summary_json"
    exit_code=0
    ;;
  reuse)
    # Intentionally do not modify summary_json; simulates stale summary reuse.
    exit_code=0
    ;;
  invalid)
    cat >"$summary_json" <<'EOF_INVALID'
{ invalid-json
EOF_INVALID
    exit_code=0
    ;;
  fail)
    cat >"$summary_json" <<'EOF_FAIL'
{
  "version": 1,
  "schema": { "id": "runtime_actuation_promotion_cycle_summary" },
  "status": "fail",
  "rc": 9,
  "decision": "NO-GO"
}
EOF_FAIL
    exit_code=9
    ;;
  no_go_fail_rc1)
    cat >"$summary_json" <<'EOF_FAIL_RC1'
{
  "version": 1,
  "schema": { "id": "runtime_actuation_promotion_cycle_summary" },
  "status": "fail",
  "rc": 1,
  "decision": "NO-GO"
}
EOF_FAIL_RC1
    exit_code=1
    ;;
  *)
    echo "fake cycle: unknown mode=$mode" >&2
    exit 2
    ;;
esac

if [[ "$print_summary_json" == "1" && -f "$summary_json" ]]; then
  cat "$summary_json"
fi

exit "$exit_code"
EOF_FAKE_CYCLE

cat >"$FAKE_EVIDENCE_SCRIPT" <<'EOF_FAKE_EVIDENCE'
#!/usr/bin/env bash
set -euo pipefail

summary_json=""
report_md=""
print_summary_json="0"
print_report="0"

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
    --report-md)
      report_md="${2:-}"
      shift 2
      ;;
    --report-md=*)
      report_md="${1#*=}"
      shift
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
    --print-summary-json=*)
      print_summary_json="${1#*=}"
      shift
      ;;
    --print-report)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_report="${2:-}"
        shift 2
      else
        print_report="1"
        shift
      fi
      ;;
    --print-report=*)
      print_report="${1#*=}"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" ]]; then
  echo "fake evidence pack: missing --summary-json" >&2
  exit 2
fi

mkdir -p "$(dirname "$summary_json")"
if [[ -n "$report_md" ]]; then
  mkdir -p "$(dirname "$report_md")"
fi

mode="${FAKE_EVIDENCE_MODE:-pass}"
case "$mode" in
  pass)
    cat >"$summary_json" <<'EOF_SUMMARY'
{
  "version": 1,
  "schema": { "id": "runtime_actuation_promotion_evidence_pack_summary" },
  "status": "pass",
  "rc": 0,
  "decision": "GO",
  "next_operator_action": "No action required",
  "next_command": null,
  "next_command_reason": null
}
EOF_SUMMARY
    if [[ -n "$report_md" ]]; then
      cat >"$report_md" <<'EOF_REPORT'
# Fake Runtime Actuation Promotion Evidence Pack
EOF_REPORT
    fi
    exit_code=0
    ;;
  no_go_fail)
    cat >"$summary_json" <<'EOF_NOGO'
{
  "version": 1,
  "schema": { "id": "runtime_actuation_promotion_evidence_pack_summary" },
  "status": "fail",
  "rc": 1,
  "decision": "NO-GO",
  "next_operator_action": "Use REPLACE_WITH_INVITE_SUBJECT and [redacted] values.",
  "next_command": "./scripts/easy_node.sh runtime-actuation-promotion-cycle --campaign-subject INVITE_KEY --subject REPLACE_WITH_INVITE_SUBJECT",
  "next_command_reason": "set [redacted] CAMPAIGN_SUBJECT/INVITE_KEY and rerun"
}
EOF_NOGO
    if [[ -n "$report_md" ]]; then
      cat >"$report_md" <<'EOF_REPORT'
# Fake Runtime Actuation Promotion Evidence Pack (NO-GO)
EOF_REPORT
    fi
    exit_code=1
    ;;
  no_go_fail_equals)
    cat >"$summary_json" <<'EOF_NOGO_EQUALS'
{
  "version": 1,
  "schema": { "id": "runtime_actuation_promotion_evidence_pack_summary" },
  "status": "fail",
  "rc": 1,
  "decision": "NO-GO",
  "next_operator_action": "Use CAMPAIGN_SUBJECT=INVITE_KEY values.",
  "next_command": "./scripts/easy_node.sh runtime-actuation-promotion-cycle --campaign-subject=INVITE_KEY --subject=${CAMPAIGN_SUBJECT}",
  "next_command_reason": "set CAMPAIGN_SUBJECT=INVITE_KEY and rerun"
}
EOF_NOGO_EQUALS
    if [[ -n "$report_md" ]]; then
      cat >"$report_md" <<'EOF_REPORT'
# Fake Runtime Actuation Promotion Evidence Pack (NO-GO equals placeholders)
EOF_REPORT
    fi
    exit_code=1
    ;;
  *)
    echo "fake evidence pack: unknown mode=$mode" >&2
    exit 2
    ;;
esac

if [[ "$print_report" == "1" && -n "$report_md" && -f "$report_md" ]]; then
  cat "$report_md"
fi
if [[ "$print_summary_json" == "1" && -f "$summary_json" ]]; then
  cat "$summary_json"
fi

exit "$exit_code"
EOF_FAKE_EVIDENCE

chmod +x "$FAKE_CYCLE_SCRIPT" "$FAKE_EVIDENCE_SCRIPT"

echo "[runtime-actuation-live-evidence-publish-bundle] pass path"
PASS_REPORTS="$TMP_DIR/pass_reports"
PASS_SUMMARY="$TMP_DIR/pass_bundle_summary.json"
set +e
RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_EVIDENCE_SCRIPT" \
FAKE_CYCLE_MODE="pass" \
FAKE_EVIDENCE_MODE="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$PASS_REPORTS" \
  --cycles 3 \
  --fail-on-no-go 1 \
  --summary-json "$PASS_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_live_evidence_publish_bundle_pass.log 2>&1
PASS_RC=$?
set -e
if [[ "$PASS_RC" -ne 0 ]]; then
  echo "expected pass path rc=0, got rc=$PASS_RC"
  cat /tmp/integration_runtime_actuation_live_evidence_publish_bundle_pass.log
  exit 1
fi
if [[ ! -f "$PASS_SUMMARY" ]]; then
  echo "pass path missing summary"
  exit 1
fi
PASS_REPORT="$(jq -r '.artifacts.report_md // ""' "$PASS_SUMMARY")"
if [[ -z "$PASS_REPORT" || ! -f "$PASS_REPORT" ]]; then
  echo "pass path missing report markdown"
  cat "$PASS_SUMMARY"
  exit 1
fi
if ! jq -e '
  .schema.id == "runtime_actuation_live_evidence_publish_bundle_summary"
  and .status == "pass"
  and .rc == 0
  and .failure_substep == null
  and .outcome.publish_ready == true
  and .stages.runtime_actuation_promotion_cycle.status == "pass"
  and .stages.runtime_actuation_promotion_cycle.publish_ready == true
  and .stages.runtime_actuation_promotion_evidence_pack.status == "pass"
  and .stages.runtime_actuation_promotion_evidence_pack.publish_ready == true
  and .next_command == null
  and .next_command_reason == null
' "$PASS_SUMMARY" >/dev/null 2>&1; then
  echo "pass path summary mismatch"
  cat "$PASS_SUMMARY"
  exit 1
fi

echo "[runtime-actuation-live-evidence-publish-bundle] cycle missing summary fail-closed"
MISSING_REPORTS="$TMP_DIR/missing_reports"
MISSING_SUMMARY="$TMP_DIR/missing_bundle_summary.json"
set +e
RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_EVIDENCE_SCRIPT" \
FAKE_CYCLE_MODE="missing" \
FAKE_EVIDENCE_MODE="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$MISSING_REPORTS" \
  --cycles 3 \
  --fail-on-no-go 1 \
  --summary-json "$MISSING_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_live_evidence_publish_bundle_missing.log 2>&1
MISSING_RC=$?
set -e
if [[ "$MISSING_RC" -eq 0 ]]; then
  echo "expected missing summary path rc!=0"
  cat /tmp/integration_runtime_actuation_live_evidence_publish_bundle_missing.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .failure_substep == "runtime_actuation_promotion_cycle_summary_missing_or_invalid"
  and .stages.runtime_actuation_promotion_cycle.status == "fail"
  and .stages.runtime_actuation_promotion_evidence_pack.status == "skipped"
  and (.next_command != null and (.next_command | test("runtime-actuation-promotion-cycle")))
' "$MISSING_SUMMARY" >/dev/null 2>&1; then
  echo "missing summary fail-closed mismatch"
  cat "$MISSING_SUMMARY"
  exit 1
fi

echo "[runtime-actuation-live-evidence-publish-bundle] cycle invalid summary fail-closed"
INVALID_REPORTS="$TMP_DIR/invalid_reports"
INVALID_SUMMARY="$TMP_DIR/invalid_bundle_summary.json"
set +e
RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_EVIDENCE_SCRIPT" \
FAKE_CYCLE_MODE="invalid" \
FAKE_EVIDENCE_MODE="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$INVALID_REPORTS" \
  --cycles 3 \
  --fail-on-no-go 1 \
  --summary-json "$INVALID_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_live_evidence_publish_bundle_invalid.log 2>&1
INVALID_RC=$?
set -e
if [[ "$INVALID_RC" -eq 0 ]]; then
  echo "expected invalid summary path rc!=0"
  cat /tmp/integration_runtime_actuation_live_evidence_publish_bundle_invalid.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .failure_substep == "runtime_actuation_promotion_cycle_summary_missing_or_invalid"
  and .stages.runtime_actuation_promotion_cycle.summary_valid_json == false
  and .stages.runtime_actuation_promotion_evidence_pack.status == "skipped"
' "$INVALID_SUMMARY" >/dev/null 2>&1; then
  echo "invalid summary fail-closed mismatch"
  cat "$INVALID_SUMMARY"
  exit 1
fi

echo "[runtime-actuation-live-evidence-publish-bundle] cycle stale summary reuse fail-closed"
STALE_REPORTS="$TMP_DIR/stale_reports"
STALE_SUMMARY="$TMP_DIR/stale_bundle_summary.json"
mkdir -p "$STALE_REPORTS"
cat >"$STALE_REPORTS/runtime_actuation_promotion_cycle_latest_summary.json" <<'EOF_STALE'
{
  "version": 1,
  "schema": { "id": "runtime_actuation_promotion_cycle_summary" },
  "status": "pass",
  "rc": 0,
  "decision": "GO"
}
EOF_STALE
set +e
RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_EVIDENCE_SCRIPT" \
FAKE_CYCLE_MODE="reuse" \
FAKE_EVIDENCE_MODE="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$STALE_REPORTS" \
  --cycles 3 \
  --fail-on-no-go 1 \
  --summary-json "$STALE_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_live_evidence_publish_bundle_stale.log 2>&1
STALE_RC=$?
set -e
if [[ "$STALE_RC" -eq 0 ]]; then
  echo "expected stale summary reuse path rc!=0"
  cat /tmp/integration_runtime_actuation_live_evidence_publish_bundle_stale.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .failure_substep == "runtime_actuation_promotion_cycle_summary_stale_reused"
  and .stages.runtime_actuation_promotion_cycle.summary_valid_json == true
  and .stages.runtime_actuation_promotion_cycle.summary_fresh_after_run == false
  and .stages.runtime_actuation_promotion_evidence_pack.status == "skipped"
' "$STALE_SUMMARY" >/dev/null 2>&1; then
  echo "stale summary reuse fail-closed mismatch"
  cat "$STALE_SUMMARY"
  exit 1
fi

echo "[runtime-actuation-live-evidence-publish-bundle] cycle NO-GO still runs evidence-pack diagnostics"
CYCLE_NOGO_REPORTS="$TMP_DIR/cycle_nogo_reports"
CYCLE_NOGO_SUMMARY="$TMP_DIR/cycle_nogo_bundle_summary.json"
set +e
RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_EVIDENCE_SCRIPT" \
FAKE_CYCLE_MODE="no_go_fail_rc1" \
FAKE_EVIDENCE_MODE="no_go_fail" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$CYCLE_NOGO_REPORTS" \
  --cycles 3 \
  --fail-on-no-go 1 \
  --summary-json "$CYCLE_NOGO_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_live_evidence_publish_bundle_cycle_nogo.log 2>&1
CYCLE_NOGO_RC=$?
set -e
if [[ "$CYCLE_NOGO_RC" -eq 0 ]]; then
  echo "expected cycle NO-GO path rc!=0"
  cat /tmp/integration_runtime_actuation_live_evidence_publish_bundle_cycle_nogo.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .failure_substep == "runtime_actuation_publish_blocked_cycle_not_publish_ready"
  and .stages.runtime_actuation_promotion_cycle.status == "fail"
  and .stages.runtime_actuation_promotion_cycle.summary_decision_normalized == "NO-GO"
  and .stages.runtime_actuation_promotion_evidence_pack.status == "fail"
  and .outcome.action == "publish_blocked"
  and .outcome.publish_blocked.blocked == true
  and .outcome.publish_blocked.cycle_publish_blocked == true
  and .outcome.publish_blocked.cycle_summary_usable_for_evidence_pack == true
  and .outcome.publish_blocked.evidence_pack_diagnostic_substep == "runtime_actuation_promotion_evidence_pack_runner_nonzero"
  and (.next_command != null and (.next_command | test("runtime-actuation-promotion-cycle")))
  and (.next_command_source != null)
  and (.outcome.publish_blocked.deterministic_next_command_source != null)
' "$CYCLE_NOGO_SUMMARY" >/dev/null 2>&1; then
  echo "cycle NO-GO diagnostics path mismatch"
  cat "$CYCLE_NOGO_SUMMARY"
  exit 1
fi

echo "[runtime-actuation-live-evidence-publish-bundle] evidence-pack NO-GO/fail path"
NOGO_REPORTS="$TMP_DIR/nogo_reports"
NOGO_SUMMARY="$TMP_DIR/nogo_bundle_summary.json"
set +e
RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_EVIDENCE_SCRIPT" \
FAKE_CYCLE_MODE="pass" \
FAKE_EVIDENCE_MODE="no_go_fail" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$NOGO_REPORTS" \
  --cycles 3 \
  --fail-on-no-go 1 \
  --summary-json "$NOGO_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_live_evidence_publish_bundle_nogo.log 2>&1
NOGO_RC=$?
set -e
if [[ "$NOGO_RC" -eq 0 ]]; then
  echo "expected evidence-pack NO-GO/fail path rc!=0"
  cat /tmp/integration_runtime_actuation_live_evidence_publish_bundle_nogo.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .failure_substep == "runtime_actuation_promotion_evidence_pack_runner_nonzero"
  and .stages.runtime_actuation_promotion_evidence_pack.status == "fail"
  and .stages.runtime_actuation_promotion_evidence_pack.summary_decision_normalized == "NO-GO"
  and (.next_command != null)
  and ((.next_command | test("REPLACE_WITH_INVITE_SUBJECT|INVITE_KEY|CAMPAIGN_SUBJECT|\\[redacted\\]|\\[REDACTED\\]")) | not)
  and ((.next_command_reason | test("REPLACE_WITH_INVITE_SUBJECT|INVITE_KEY|CAMPAIGN_SUBJECT|\\[redacted\\]|\\[REDACTED\\]")) | not)
' "$NOGO_SUMMARY" >/dev/null 2>&1; then
  echo "evidence-pack NO-GO/fail path mismatch"
  cat "$NOGO_SUMMARY"
  exit 1
fi

echo "[runtime-actuation-live-evidence-publish-bundle] evidence-pack equals-style placeholder sanitization"
NOGO_EQ_REPORTS="$TMP_DIR/nogo_eq_reports"
NOGO_EQ_SUMMARY="$TMP_DIR/nogo_eq_bundle_summary.json"
set +e
RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_EVIDENCE_SCRIPT" \
FAKE_CYCLE_MODE="pass" \
FAKE_EVIDENCE_MODE="no_go_fail_equals" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$NOGO_EQ_REPORTS" \
  --cycles 3 \
  --fail-on-no-go 1 \
  --summary-json "$NOGO_EQ_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_live_evidence_publish_bundle_nogo_eq.log 2>&1
NOGO_EQ_RC=$?
set -e
if [[ "$NOGO_EQ_RC" -eq 0 ]]; then
  echo "expected evidence-pack equals-placeholder path rc!=0"
  cat /tmp/integration_runtime_actuation_live_evidence_publish_bundle_nogo_eq.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .failure_substep == "runtime_actuation_promotion_evidence_pack_runner_nonzero"
  and (.next_command != null)
  and ((.next_command | test("INVITE_KEY|CAMPAIGN_SUBJECT|\\[redacted\\]|\\[REDACTED\\]")) | not)
  and ((.next_command_reason | test("INVITE_KEY|CAMPAIGN_SUBJECT|\\[redacted\\]|\\[REDACTED\\]")) | not)
  and ((.next_operator_action | test("INVITE_KEY|CAMPAIGN_SUBJECT|\\[redacted\\]|\\[REDACTED\\]")) | not)
' "$NOGO_EQ_SUMMARY" >/dev/null 2>&1; then
  echo "evidence-pack equals-placeholder sanitization mismatch"
  cat "$NOGO_EQ_SUMMARY"
  exit 1
fi

echo "runtime actuation live evidence publish bundle integration ok"
