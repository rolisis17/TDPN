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
if ! grep -F -- '# Runtime Actuation Promotion Evidence Pack' "$PASS_REPORT" >/dev/null 2>&1; then
  echo "happy-path report markdown header missing"
  cat "$PASS_REPORT"
  exit 1
fi

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
assert_jq "$SOFT_NOGO_SUMMARY" '.source.usable == true and .source.decision == "NO-GO" and .source.status == "fail" and .source.rc == 0'
assert_jq "$SOFT_NOGO_SUMMARY" '.outcome.should_promote == false and .outcome.action == "hold_promotion_warn_only"'

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

echo "[runtime-actuation-promotion-evidence-pack] rc/decision/status consistency"
assert_jq "$PASS_SUMMARY" '.decision == "GO" and .status == "pass" and .rc == 0'
assert_jq "$SOFT_NOGO_SUMMARY" '.decision == "NO-GO" and .status == "warn" and .rc == 0'
assert_jq "$MISSING_SUMMARY" '.decision == "NO-GO" and .status == "fail" and .rc != 0'

echo "runtime actuation promotion evidence pack integration ok"
