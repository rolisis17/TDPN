#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp grep cat date; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/runtime_actuation_promotion_evidence_pack.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

EASY_NODE_SCRIPT_UNDER_TEST="${EASY_NODE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/easy_node.sh}"
if [[ ! -x "$EASY_NODE_SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable easy_node script under test: $EASY_NODE_SCRIPT_UNDER_TEST"
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

assert_no_blank_reason_entries() {
  local file="$1"
  assert_jq "$file" '
    ([.reasons[]?, .source.reasons[]?]
      | map(select((type == "string") and ((gsub("^\\s+|\\s+$"; "") | length) == 0)))
      | length) == 0
  '
}

assert_summary_written() {
  local file="$1"
  local label="$2"
  if [[ ! -s "$file" ]]; then
    echo "expected $label summary artifact to be written: $file"
    exit 1
  fi
}

write_cycle_summary() {
  local path="$1"
  local generated_at="$2"
  local decision="$3"
  local status="$4"
  local rc="$5"
  local freshness_mode="$6"
  local next_operator_action="$7"

  case "$freshness_mode" in
    fresh)
      jq -n \
        --arg generated_at_utc "$generated_at" \
        --arg decision "$decision" \
        --arg status "$status" \
        --arg next_operator_action "$next_operator_action" \
        --argjson rc "$rc" \
        '{
          version: 1,
          schema: { id: "runtime_actuation_promotion_cycle_summary" },
          generated_at_utc: $generated_at_utc,
          status: $status,
          rc: $rc,
          decision: $decision,
          stages: {
            promotion_check: {
              summary_fresh: true,
              next_operator_action: $next_operator_action
            }
          },
          promotion_check: {
            decision: $decision,
            status: $status,
            rc: $rc,
            next_operator_action: $next_operator_action
          }
        }' >"$path"
      ;;
    stale)
      jq -n \
        --arg generated_at_utc "$generated_at" \
        --arg decision "$decision" \
        --arg status "$status" \
        --arg next_operator_action "$next_operator_action" \
        --argjson rc "$rc" \
        '{
          version: 1,
          schema: { id: "runtime_actuation_promotion_cycle_summary" },
          generated_at_utc: $generated_at_utc,
          status: $status,
          rc: $rc,
          decision: $decision,
          stages: {
            promotion_check: {
              next_operator_action: $next_operator_action
            }
          },
          promotion_check: {
            decision: $decision,
            status: $status,
            rc: $rc,
            next_operator_action: $next_operator_action
          }
        }' >"$path"
      ;;
    unknown)
      jq -n \
        --arg decision "$decision" \
        --arg status "$status" \
        --arg next_operator_action "$next_operator_action" \
        --argjson rc "$rc" \
        '{
          version: 1,
          schema: { id: "runtime_actuation_promotion_cycle_summary" },
          status: $status,
          rc: $rc,
          decision: $decision,
          stages: {
            promotion_check: {
              next_operator_action: $next_operator_action
            }
          },
          promotion_check: {
            decision: $decision,
            status: $status,
            rc: $rc,
            next_operator_action: $next_operator_action
          }
        }' >"$path"
      ;;
    *)
      echo "unknown freshness_mode: $freshness_mode"
      exit 2
      ;;
  esac
}

echo "[runtime-actuation-promotion-evidence-pack] easy_node help contract"
HELP_OUT="$TMP_DIR/help.txt"
bash "$EASY_NODE_SCRIPT_UNDER_TEST" help >"$HELP_OUT"
if ! grep -F -- 'runtime-actuation-promotion-evidence-pack' "$HELP_OUT" >/dev/null 2>&1; then
  echo "easy_node help missing runtime-actuation-promotion-evidence-pack command contract"
  cat "$HELP_OUT"
  exit 1
fi

NOW_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
PAST_UTC="2001-01-01T00:00:00Z"

PASS_REPORTS="$TMP_DIR/pass_reports"
PASS_SOURCE="$PASS_REPORTS/runtime_actuation_promotion_cycle_latest_summary.json"
PASS_SUMMARY="$TMP_DIR/pass_summary.json"
PASS_REPORT="$TMP_DIR/pass_report.md"
mkdir -p "$PASS_REPORTS"
write_cycle_summary "$PASS_SOURCE" "$NOW_UTC" "GO" "pass" 0 "fresh" "No action required; runtime-actuation promotion evidence is healthy."

echo "[runtime-actuation-promotion-evidence-pack] happy path via easy_node wrapper"
set +e
RUNTIME_ACTUATION_MULTI_VM_EVIDENCE_PACK_SCRIPT="$SCRIPT_UNDER_TEST" \
bash "$EASY_NODE_SCRIPT_UNDER_TEST" runtime-actuation-promotion-evidence-pack \
  --reports-dir "$PASS_REPORTS" \
  --summary-json "$PASS_SUMMARY" \
  --report-md "$PASS_REPORT" \
  --max-age-sec 86400 \
  --fail-on-no-go 1 \
  --print-summary-json 0 \
  --print-report 0 >/tmp/integration_runtime_actuation_promotion_evidence_pack_pass.log 2>&1
PASS_RC=$?
set -e

if [[ "$PASS_RC" -ne 0 ]]; then
  echo "expected happy-path rc=0, got rc=$PASS_RC"
  cat /tmp/integration_runtime_actuation_promotion_evidence_pack_pass.log
  exit 1
fi
assert_jq "$PASS_SUMMARY" '.schema.id == "runtime_actuation_promotion_evidence_pack_summary"'
assert_jq "$PASS_SUMMARY" '.status == "pass"'
assert_jq "$PASS_SUMMARY" '.decision == "GO"'
assert_jq "$PASS_SUMMARY" '.rc == 0'
assert_jq "$PASS_SUMMARY" '.available == true and .helper_available == true and .needs_attention == false'
assert_jq "$PASS_SUMMARY" '.source.usable == true and .source.decision == "GO" and .source.status == "pass" and .source.rc == 0'
assert_jq "$PASS_SUMMARY" '.source.freshness.known == true and .source.freshness.fresh == true'
assert_jq "$PASS_SUMMARY" '.outcome.should_promote == true and .outcome.action == "promote_allowed"'
assert_no_blank_reason_entries "$PASS_SUMMARY"
if ! grep -F -- '# Runtime Actuation Promotion Evidence Pack' "$PASS_REPORT" >/dev/null 2>&1; then
  echo "happy-path report markdown header missing"
  cat "$PASS_REPORT"
  exit 1
fi

DISCOVERY_REPORTS="$TMP_DIR/discovery_reports"
DISCOVERY_CYCLE_SOURCE="$DISCOVERY_REPORTS/runtime_actuation_promotion_cycle_20260101_010101_summary.json"
DISCOVERY_PROMOTION_CHECK_SOURCE="$DISCOVERY_REPORTS/runtime_actuation_promotion_cycle_20260101_010101_promotion_check_summary.json"
DISCOVERY_SUMMARY="$TMP_DIR/discovery_summary.json"
DISCOVERY_REPORT="$TMP_DIR/discovery_report.md"
mkdir -p "$DISCOVERY_REPORTS"
write_cycle_summary "$DISCOVERY_CYCLE_SOURCE" "$NOW_UTC" "GO" "pass" 0 "fresh" "No action required; runtime-actuation promotion evidence is healthy."
sleep 1
jq -n \
  --arg generated_at_utc "$NOW_UTC" \
  '{
    version: 1,
    schema: { id: "runtime_actuation_promotion_check_summary" },
    generated_at_utc: $generated_at_utc,
    status: "pass",
    rc: 0,
    decision: "GO"
  }' >"$DISCOVERY_PROMOTION_CHECK_SOURCE"

echo "[runtime-actuation-promotion-evidence-pack] fallback discovery ignores promotion-check summary candidates"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$DISCOVERY_REPORTS" \
  --summary-json "$DISCOVERY_SUMMARY" \
  --report-md "$DISCOVERY_REPORT" \
  --max-age-sec 86400 \
  --print-summary-json 0 \
  --print-report 0 >/tmp/integration_runtime_actuation_promotion_evidence_pack_discovery.log 2>&1
DISCOVERY_RC=$?
set -e

if [[ "$DISCOVERY_RC" -ne 0 ]]; then
  echo "expected discovery fallback rc=0, got rc=$DISCOVERY_RC"
  cat /tmp/integration_runtime_actuation_promotion_evidence_pack_discovery.log
  exit 1
fi
assert_jq "$DISCOVERY_SUMMARY" '.decision == "GO" and .status == "pass" and .rc == 0'
if ! jq -e --arg source "$DISCOVERY_CYCLE_SOURCE" '.source.summary_json == $source' "$DISCOVERY_SUMMARY" >/dev/null 2>&1; then
  echo "assertion failed: discovery source.summary_json should point to canonical cycle summary"
  cat "$DISCOVERY_SUMMARY"
  exit 1
fi
assert_jq "$DISCOVERY_SUMMARY" '.source.schema_id == "runtime_actuation_promotion_cycle_summary" and .source.usable == true'
assert_no_blank_reason_entries "$DISCOVERY_SUMMARY"

SOFT_NOGO_REPORTS="$TMP_DIR/soft_nogo_reports"
SOFT_NOGO_SOURCE="$SOFT_NOGO_REPORTS/runtime_actuation_promotion_cycle_latest_summary.json"
SOFT_NOGO_SUMMARY="$TMP_DIR/soft_nogo_summary.json"
SOFT_NOGO_REPORT="$TMP_DIR/soft_nogo_report.md"
mkdir -p "$SOFT_NOGO_REPORTS"
write_cycle_summary "$SOFT_NOGO_SOURCE" "$NOW_UTC" "NO-GO" "fail" 0 "fresh" "resolve runtime-actuation blockers and rerun the promotion cycle."

echo "[runtime-actuation-promotion-evidence-pack] usable NO-GO soft path"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$SOFT_NOGO_REPORTS" \
  --summary-json "$SOFT_NOGO_SUMMARY" \
  --report-md "$SOFT_NOGO_REPORT" \
  --fail-on-no-go 0 \
  --max-age-sec 86400 \
  --print-summary-json 0 \
  --print-report 0 >/tmp/integration_runtime_actuation_promotion_evidence_pack_soft_nogo.log 2>&1
SOFT_NOGO_RC=$?
set -e

if [[ "$SOFT_NOGO_RC" -ne 0 ]]; then
  echo "expected soft NO-GO rc=0, got rc=$SOFT_NOGO_RC"
  cat /tmp/integration_runtime_actuation_promotion_evidence_pack_soft_nogo.log
  exit 1
fi
assert_jq "$SOFT_NOGO_SUMMARY" '.decision == "NO-GO"'
assert_jq "$SOFT_NOGO_SUMMARY" '.status == "warn"'
assert_jq "$SOFT_NOGO_SUMMARY" '.rc == 0'
assert_jq "$SOFT_NOGO_SUMMARY" '.available == true and .needs_attention == true'
assert_jq "$SOFT_NOGO_SUMMARY" '.fail_closed == false and .enforcement.fail_closed == false'
assert_jq "$SOFT_NOGO_SUMMARY" '.source.usable == true and .source.decision == "NO-GO" and .source.status == "fail" and .source.rc == 0'
assert_jq "$SOFT_NOGO_SUMMARY" '.outcome.should_promote == false and .outcome.action == "hold_promotion_warn_only"'
assert_jq "$SOFT_NOGO_SUMMARY" '(.notes | test("NO-GO")) and (.notes | test("compatibility mode"))'
assert_no_blank_reason_entries "$SOFT_NOGO_SUMMARY"

GO_WARN_REPORTS="$TMP_DIR/go_warn_reports"
GO_WARN_SOURCE="$GO_WARN_REPORTS/runtime_actuation_promotion_cycle_latest_summary.json"
GO_WARN_SUMMARY="$TMP_DIR/go_warn_summary.json"
GO_WARN_REPORT="$TMP_DIR/go_warn_report.md"
mkdir -p "$GO_WARN_REPORTS"
write_cycle_summary "$GO_WARN_SOURCE" "$NOW_UTC" "GO" "warn" 0 "fresh" "repair degraded source status and rerun runtime-actuation promotion-cycle evidence."

echo "[runtime-actuation-promotion-evidence-pack] GO with non-pass source status fails closed"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$GO_WARN_REPORTS" \
  --summary-json "$GO_WARN_SUMMARY" \
  --report-md "$GO_WARN_REPORT" \
  --fail-on-no-go 0 \
  --max-age-sec 86400 \
  --print-summary-json 0 \
  --print-report 0 >/tmp/integration_runtime_actuation_promotion_evidence_pack_go_warn.log 2>&1
GO_WARN_RC=$?
set -e

if [[ "$GO_WARN_RC" -eq 0 ]]; then
  echo "expected degraded-GO-status rc!=0"
  cat /tmp/integration_runtime_actuation_promotion_evidence_pack_go_warn.log
  exit 1
fi
assert_summary_written "$GO_WARN_SUMMARY" "go-warn-source"
assert_jq "$GO_WARN_SUMMARY" '.decision == "GO" and .status == "fail" and .rc != 0'
assert_jq "$GO_WARN_SUMMARY" '.available == true and .fail_closed == true and .enforcement.fail_closed == true and .needs_attention == true'
assert_jq "$GO_WARN_SUMMARY" '.source.usable == true and .source.decision == "GO" and .source.status == "warn" and .source.rc == 0'
assert_jq "$GO_WARN_SUMMARY" '((.reasons | index("runtime_actuation_promotion_cycle:go_status_not_pass")) != null)'
assert_jq "$GO_WARN_SUMMARY" '.outcome.should_promote == false and .outcome.action == "hold_evidence_pack_blocked"'
assert_jq "$GO_WARN_SUMMARY" '.notes | test("Fail-closed")'
assert_no_blank_reason_entries "$GO_WARN_SUMMARY"

GO_NONZERO_REPORTS="$TMP_DIR/go_nonzero_reports"
GO_NONZERO_SOURCE="$GO_NONZERO_REPORTS/runtime_actuation_promotion_cycle_latest_summary.json"
GO_NONZERO_SUMMARY="$TMP_DIR/go_nonzero_summary.json"
GO_NONZERO_REPORT="$TMP_DIR/go_nonzero_report.md"
mkdir -p "$GO_NONZERO_REPORTS"
write_cycle_summary "$GO_NONZERO_SOURCE" "$NOW_UTC" "GO" "pass" 2 "fresh" "repair degraded source rc and rerun runtime-actuation promotion-cycle evidence."

echo "[runtime-actuation-promotion-evidence-pack] GO with non-zero source rc fails closed"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$GO_NONZERO_REPORTS" \
  --summary-json "$GO_NONZERO_SUMMARY" \
  --report-md "$GO_NONZERO_REPORT" \
  --fail-on-no-go 0 \
  --max-age-sec 86400 \
  --print-summary-json 0 \
  --print-report 0 >/tmp/integration_runtime_actuation_promotion_evidence_pack_go_nonzero.log 2>&1
GO_NONZERO_RC=$?
set -e

if [[ "$GO_NONZERO_RC" -eq 0 ]]; then
  echo "expected degraded-GO-rc rc!=0"
  cat /tmp/integration_runtime_actuation_promotion_evidence_pack_go_nonzero.log
  exit 1
fi
assert_summary_written "$GO_NONZERO_SUMMARY" "go-nonzero-source"
assert_jq "$GO_NONZERO_SUMMARY" '.decision == "GO" and .status == "fail" and .rc != 0'
assert_jq "$GO_NONZERO_SUMMARY" '.available == true and .fail_closed == true and .enforcement.fail_closed == true and .needs_attention == true'
assert_jq "$GO_NONZERO_SUMMARY" '.source.usable == true and .source.decision == "GO" and .source.status == "pass" and .source.rc == 2'
assert_jq "$GO_NONZERO_SUMMARY" '((.reasons | index("runtime_actuation_promotion_cycle:go_rc_non_zero")) != null)'
assert_jq "$GO_NONZERO_SUMMARY" '.outcome.should_promote == false and .outcome.action == "hold_evidence_pack_blocked"'
assert_jq "$GO_NONZERO_SUMMARY" '.notes | test("Fail-closed")'
assert_no_blank_reason_entries "$GO_NONZERO_SUMMARY"

MISSING_REPORTS="$TMP_DIR/missing_reports"
MISSING_SUMMARY="$TMP_DIR/missing_summary.json"
MISSING_REPORT="$TMP_DIR/missing_report.md"
mkdir -p "$MISSING_REPORTS"

echo "[runtime-actuation-promotion-evidence-pack] missing source fails closed"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$MISSING_REPORTS" \
  --summary-json "$MISSING_SUMMARY" \
  --report-md "$MISSING_REPORT" \
  --max-age-sec 86400 \
  --print-summary-json 0 \
  --print-report 0 >/tmp/integration_runtime_actuation_promotion_evidence_pack_missing.log 2>&1
MISSING_RC=$?
set -e

if [[ "$MISSING_RC" -eq 0 ]]; then
  echo "expected missing-source rc!=0"
  cat /tmp/integration_runtime_actuation_promotion_evidence_pack_missing.log
  exit 1
fi
assert_summary_written "$MISSING_SUMMARY" "missing-source"
assert_jq "$MISSING_SUMMARY" '.decision == "NO-GO" and .status == "fail" and .rc != 0'
assert_jq "$MISSING_SUMMARY" '.available == false and .fail_closed == true and .needs_attention == true'
assert_jq "$MISSING_SUMMARY" '((.reasons | index("runtime_actuation_promotion_cycle:summary_missing")) != null)'
assert_jq "$MISSING_SUMMARY" '.source.freshness.known == false and .source.freshness.fresh == false'
assert_jq "$MISSING_SUMMARY" '.next_command != null and (.next_command | contains("--promotion-cycle-summary-json")) and (.next_command | contains("--summary-json")) and (.next_command | contains("--report-md"))'
assert_no_blank_reason_entries "$MISSING_SUMMARY"

INVALID_REPORTS="$TMP_DIR/invalid_reports"
INVALID_SOURCE="$INVALID_REPORTS/runtime_actuation_promotion_cycle_latest_summary.json"
INVALID_SUMMARY="$TMP_DIR/invalid_summary.json"
INVALID_REPORT="$TMP_DIR/invalid_report.md"
mkdir -p "$INVALID_REPORTS"
printf '%s\n' '{not json' >"$INVALID_SOURCE"

echo "[runtime-actuation-promotion-evidence-pack] invalid source fails closed"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$INVALID_REPORTS" \
  --summary-json "$INVALID_SUMMARY" \
  --report-md "$INVALID_REPORT" \
  --max-age-sec 86400 \
  --print-summary-json 0 \
  --print-report 0 >/tmp/integration_runtime_actuation_promotion_evidence_pack_invalid.log 2>&1
INVALID_RC=$?
set -e

if [[ "$INVALID_RC" -eq 0 ]]; then
  echo "expected invalid-source rc!=0"
  cat /tmp/integration_runtime_actuation_promotion_evidence_pack_invalid.log
  exit 1
fi
assert_summary_written "$INVALID_SUMMARY" "invalid-source"
assert_jq "$INVALID_SUMMARY" '.decision == "NO-GO" and .status == "fail" and .rc != 0'
assert_jq "$INVALID_SUMMARY" '.available == false and .fail_closed == true and .needs_attention == true'
assert_jq "$INVALID_SUMMARY" '((.reasons | index("runtime_actuation_promotion_cycle:summary_invalid_json")) != null)'
assert_no_blank_reason_entries "$INVALID_SUMMARY"

STALE_REPORTS="$TMP_DIR/stale_reports"
STALE_SOURCE="$STALE_REPORTS/runtime_actuation_promotion_cycle_latest_summary.json"
STALE_SUMMARY="$TMP_DIR/stale_summary.json"
STALE_REPORT="$TMP_DIR/stale_report.md"
mkdir -p "$STALE_REPORTS"
write_cycle_summary "$STALE_SOURCE" "$PAST_UTC" "GO" "pass" 0 "stale" "refresh runtime-actuation promotion-cycle evidence."

echo "[runtime-actuation-promotion-evidence-pack] stale source fails closed"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$STALE_REPORTS" \
  --summary-json "$STALE_SUMMARY" \
  --report-md "$STALE_REPORT" \
  --max-age-sec 3600 \
  --print-summary-json 0 \
  --print-report 0 >/tmp/integration_runtime_actuation_promotion_evidence_pack_stale.log 2>&1
STALE_RC=$?
set -e

if [[ "$STALE_RC" -eq 0 ]]; then
  echo "expected stale-source rc!=0"
  cat /tmp/integration_runtime_actuation_promotion_evidence_pack_stale.log
  exit 1
fi
assert_summary_written "$STALE_SUMMARY" "stale-source"
assert_jq "$STALE_SUMMARY" '.decision == "NO-GO" and .status == "fail" and .rc != 0'
assert_jq "$STALE_SUMMARY" '.available == false and .fail_closed == true and .needs_attention == true'
assert_jq "$STALE_SUMMARY" '((.reasons | index("runtime_actuation_promotion_cycle:freshness_stale")) != null)'
assert_jq "$STALE_SUMMARY" '.source.freshness.known == true and .source.freshness.fresh == false'
assert_no_blank_reason_entries "$STALE_SUMMARY"

STALE_FLAGGED_REPORTS="$TMP_DIR/stale_flagged_reports"
STALE_FLAGGED_SOURCE="$STALE_FLAGGED_REPORTS/runtime_actuation_promotion_cycle_latest_summary.json"
STALE_FLAGGED_SUMMARY="$TMP_DIR/stale_flagged_summary.json"
STALE_FLAGGED_REPORT="$TMP_DIR/stale_flagged_report.md"
mkdir -p "$STALE_FLAGGED_REPORTS"
write_cycle_summary "$STALE_FLAGGED_SOURCE" "$PAST_UTC" "GO" "pass" 0 "fresh" "refresh runtime-actuation promotion-cycle evidence."

echo "[runtime-actuation-promotion-evidence-pack] stale generated_at fails closed even when summary_fresh=true"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$STALE_FLAGGED_REPORTS" \
  --summary-json "$STALE_FLAGGED_SUMMARY" \
  --report-md "$STALE_FLAGGED_REPORT" \
  --max-age-sec 3600 \
  --print-summary-json 0 \
  --print-report 0 >/tmp/integration_runtime_actuation_promotion_evidence_pack_stale_flagged.log 2>&1
STALE_FLAGGED_RC=$?
set -e

if [[ "$STALE_FLAGGED_RC" -eq 0 ]]; then
  echo "expected stale-generated-at-with-summary_fresh rc!=0"
  cat /tmp/integration_runtime_actuation_promotion_evidence_pack_stale_flagged.log
  exit 1
fi
assert_summary_written "$STALE_FLAGGED_SUMMARY" "stale-generated-at-with-summary_fresh"
assert_jq "$STALE_FLAGGED_SUMMARY" '.decision == "NO-GO" and .status == "fail" and .rc != 0'
assert_jq "$STALE_FLAGGED_SUMMARY" '.available == false and .fail_closed == true and .needs_attention == true'
assert_jq "$STALE_FLAGGED_SUMMARY" '((.reasons | index("runtime_actuation_promotion_cycle:freshness_stale")) != null)'
assert_jq "$STALE_FLAGGED_SUMMARY" '.source.freshness.known == true and .source.freshness.fresh == false'
assert_jq "$STALE_FLAGGED_SUMMARY" '.source.freshness.source != null and (.source.freshness.source | contains("generated_at_utc"))'
assert_no_blank_reason_entries "$STALE_FLAGGED_SUMMARY"

UNKNOWN_REPORTS="$TMP_DIR/unknown_reports"
UNKNOWN_SOURCE="$UNKNOWN_REPORTS/runtime_actuation_promotion_cycle_latest_summary.json"
UNKNOWN_SUMMARY="$TMP_DIR/unknown_summary.json"
UNKNOWN_REPORT="$TMP_DIR/unknown_report.md"
mkdir -p "$UNKNOWN_REPORTS"
write_cycle_summary "$UNKNOWN_SOURCE" "$NOW_UTC" "GO" "pass" 0 "unknown" "refresh runtime-actuation promotion-cycle evidence."

echo "[runtime-actuation-promotion-evidence-pack] freshness-unknown source fails closed"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$UNKNOWN_REPORTS" \
  --summary-json "$UNKNOWN_SUMMARY" \
  --report-md "$UNKNOWN_REPORT" \
  --max-age-sec 86400 \
  --print-summary-json 0 \
  --print-report 0 >/tmp/integration_runtime_actuation_promotion_evidence_pack_unknown.log 2>&1
UNKNOWN_RC=$?
set -e

if [[ "$UNKNOWN_RC" -eq 0 ]]; then
  echo "expected freshness-unknown rc!=0"
  cat /tmp/integration_runtime_actuation_promotion_evidence_pack_unknown.log
  exit 1
fi
assert_summary_written "$UNKNOWN_SUMMARY" "freshness-unknown"
assert_jq "$UNKNOWN_SUMMARY" '.decision == "NO-GO" and .status == "fail" and .rc != 0'
assert_jq "$UNKNOWN_SUMMARY" '.available == false and .fail_closed == true and .needs_attention == true'
assert_jq "$UNKNOWN_SUMMARY" '((.reasons | index("runtime_actuation_promotion_cycle:freshness_unknown")) != null)'
assert_jq "$UNKNOWN_SUMMARY" '.source.freshness.known == false and .source.freshness.fresh == false'
assert_no_blank_reason_entries "$UNKNOWN_SUMMARY"

echo "[runtime-actuation-promotion-evidence-pack] rc/decision/status consistency"
assert_jq "$PASS_SUMMARY" '.decision == "GO" and .status == "pass" and .rc == 0'
assert_jq "$SOFT_NOGO_SUMMARY" '.decision == "NO-GO" and .status == "warn" and .rc == 0'
assert_jq "$GO_WARN_SUMMARY" '.decision == "GO" and .status == "fail" and .rc != 0'
assert_jq "$GO_NONZERO_SUMMARY" '.decision == "GO" and .status == "fail" and .rc != 0'
assert_jq "$MISSING_SUMMARY" '.decision == "NO-GO" and .status == "fail" and .rc != 0'

echo "runtime actuation promotion evidence pack integration ok"
