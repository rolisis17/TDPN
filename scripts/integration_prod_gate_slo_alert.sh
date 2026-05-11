#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

OK_SUMMARY="$TMP_DIR/summary_ok.json"
WARN_SUMMARY="$TMP_DIR/summary_warn.json"
CRIT_SUMMARY="$TMP_DIR/summary_critical.json"
GOOD_BUNDLE_DIR="$TMP_DIR/good_bundle"
BAD_BUNDLE_DIR="$TMP_DIR/bad_bundle"
GOOD_RUN_REPORT="$GOOD_BUNDLE_DIR/prod_bundle_run_report.json"
BAD_RUN_REPORT="$BAD_BUNDLE_DIR/prod_bundle_run_report.json"
mkdir -p "$GOOD_BUNDLE_DIR" "$BAD_BUNDLE_DIR"

cat >"$GOOD_BUNDLE_DIR/prod_wg_validate_summary.json" <<'EOF_GOOD_WG_VALIDATE'
{
  "status": "ok",
  "started_at_utc": "2026-03-10T00:04:00Z",
  "finished_at_utc": "2026-03-10T00:04:10Z",
  "client_inner_source": "udp",
  "strict_distinct": true
}
EOF_GOOD_WG_VALIDATE
cat >"$GOOD_BUNDLE_DIR/prod_wg_soak_summary.json" <<'EOF_GOOD_WG_SOAK'
{
  "status": "ok",
  "summary_generated_at_utc": "2026-03-10T00:04:20Z",
  "selection_lines_total": 8,
  "selection_entry_operators": 2,
  "selection_exit_operators": 2,
  "selection_cross_operator_pairs": 1,
  "selection_diversity_failed": 0
}
EOF_GOOD_WG_SOAK
cat >"$GOOD_BUNDLE_DIR/prod_gate_summary.json" <<EOF_GOOD_GATE
{
  "started_at_utc": "2026-03-10T00:04:00Z",
  "finished_at_utc": "2026-03-10T00:04:25Z",
  "status": "ok",
  "failed_step": "",
  "failed_rc": 0,
  "wg_validate_summary_json": "$GOOD_BUNDLE_DIR/prod_wg_validate_summary.json",
  "wg_soak_summary_json": "$GOOD_BUNDLE_DIR/prod_wg_soak_summary.json",
  "steps": {
    "control_validate": "ok",
    "control_soak": "ok",
    "prod_wg_validate": "ok",
    "prod_wg_soak": "ok"
  },
  "wg_validate_status": "ok",
  "wg_validate_failed_step": "",
  "wg_soak_status": "ok",
  "wg_soak_rounds_passed": 12,
  "wg_soak_rounds_failed": 0,
  "wg_soak_top_failure_class": "none",
  "wg_soak_top_failure_count": 0
}
EOF_GOOD_GATE
cat >"$GOOD_RUN_REPORT" <<EOF_GOOD_RUN
{
  "generated_at_utc": "2026-03-10T00:04:30Z",
  "status": "ok",
  "final_rc": 0,
  "bundle_dir": "$GOOD_BUNDLE_DIR",
  "gate_summary_json": "$GOOD_BUNDLE_DIR/prod_gate_summary.json",
  "wg_validate_summary_json": "$GOOD_BUNDLE_DIR/prod_wg_validate_summary.json",
  "wg_soak_summary_json": "$GOOD_BUNDLE_DIR/prod_wg_soak_summary.json",
  "preflight": {"enabled": true, "status": "ok", "rc": 0},
  "bundle": {"status": "ok", "rc": 0},
  "integrity_verify": {"enabled": true, "status": "ok", "rc": 0},
  "signoff": {"enabled": true, "rc": 0},
  "incident_snapshot": {"enabled_on_fail": true, "status": "skipped", "rc": -1}
}
EOF_GOOD_RUN
cp "$GOOD_BUNDLE_DIR/prod_wg_validate_summary.json" "$BAD_BUNDLE_DIR/prod_wg_validate_summary.json"
cp "$GOOD_BUNDLE_DIR/prod_wg_soak_summary.json" "$BAD_BUNDLE_DIR/prod_wg_soak_summary.json"
cat >"$BAD_BUNDLE_DIR/prod_gate_summary.json" <<EOF_BAD_GATE
{
  "started_at_utc": "2026-03-10T00:04:00Z",
  "finished_at_utc": "2026-03-10T00:04:25Z",
  "status": "fail",
  "failed_step": "prod_wg_soak",
  "failed_rc": 1,
  "wg_validate_summary_json": "$BAD_BUNDLE_DIR/prod_wg_validate_summary.json",
  "wg_soak_summary_json": "$BAD_BUNDLE_DIR/prod_wg_soak_summary.json",
  "steps": {
    "control_validate": "ok",
    "control_soak": "ok",
    "prod_wg_validate": "ok",
    "prod_wg_soak": "fail"
  },
  "wg_validate_status": "ok",
  "wg_validate_failed_step": "",
  "wg_soak_status": "fail",
  "wg_soak_rounds_passed": 10,
  "wg_soak_rounds_failed": 2,
  "wg_soak_top_failure_class": "timeout",
  "wg_soak_top_failure_count": 2
}
EOF_BAD_GATE
cat >"$BAD_RUN_REPORT" <<EOF_BAD_RUN
{
  "generated_at_utc": "2026-03-10T00:04:35Z",
  "status": "fail",
  "final_rc": 1,
  "bundle_dir": "$BAD_BUNDLE_DIR",
  "gate_summary_json": "$BAD_BUNDLE_DIR/prod_gate_summary.json",
  "wg_validate_summary_json": "$BAD_BUNDLE_DIR/prod_wg_validate_summary.json",
  "wg_soak_summary_json": "$BAD_BUNDLE_DIR/prod_wg_soak_summary.json",
  "preflight": {"enabled": true, "status": "ok", "rc": 0},
  "bundle": {"status": "ok", "rc": 0},
  "integrity_verify": {"enabled": true, "status": "ok", "rc": 0},
  "signoff": {"enabled": true, "rc": 0},
  "incident_snapshot": {"enabled_on_fail": true, "status": "ok", "rc": 0}
}
EOF_BAD_RUN

cat >"$OK_SUMMARY" <<EOF_OK_SUMMARY
{
  "generated_at_utc": "2026-03-10T00:05:00Z",
  "go": 1,
  "go_rate_pct": 100,
  "no_go": 0,
  "evaluation_errors": 0,
  "reports_total": 1,
  "filters": {"max_reports": 25, "since_hours": 0, "max_evidence_age_sec": 0},
  "policy": {
    "require_full_sequence": 1,
    "require_wg_validate_ok": 1,
    "require_wg_soak_ok": 1,
    "max_wg_soak_failed_rounds": 0,
    "require_preflight_ok": 0,
    "require_bundle_ok": 0,
    "require_integrity_ok": 0,
    "require_signoff_ok": 0,
    "require_incident_snapshot_on_fail": 0,
    "require_incident_snapshot_artifacts": 0,
    "require_wg_validate_udp_source": 0,
    "require_wg_validate_strict_distinct": 0,
    "require_wg_soak_diversity_pass": 0,
    "min_wg_soak_selection_lines": 0,
    "min_wg_soak_entry_operators": 0,
    "min_wg_soak_exit_operators": 0,
    "min_wg_soak_cross_operator_pairs": 0,
    "max_evidence_age_sec": 0
  },
  "runs": [
    {"generated_at_utc": "2026-03-10T00:04:30Z", "decision": "GO", "report_path": "$GOOD_RUN_REPORT", "first_no_go_reason": ""}
  ],
  "top_no_go_reasons": []
}
EOF_OK_SUMMARY

cat >"$WARN_SUMMARY" <<EOF_WARN_SUMMARY
{
  "generated_at_utc": "2026-03-10T00:05:00Z",
  "go": 1,
  "go_rate_pct": 96.5,
  "no_go": 1,
  "evaluation_errors": 0,
  "reports_total": 2,
  "filters": {"max_reports": 25, "since_hours": 0, "max_evidence_age_sec": 0},
  "policy": {
    "require_full_sequence": 1,
    "require_wg_validate_ok": 1,
    "require_wg_soak_ok": 1,
    "max_wg_soak_failed_rounds": 0,
    "require_preflight_ok": 0,
    "require_bundle_ok": 0,
    "require_integrity_ok": 0,
    "require_signoff_ok": 0,
    "require_incident_snapshot_on_fail": 0,
    "require_incident_snapshot_artifacts": 0,
    "require_wg_validate_udp_source": 0,
    "require_wg_validate_strict_distinct": 0,
    "require_wg_soak_diversity_pass": 0,
    "min_wg_soak_selection_lines": 0,
    "min_wg_soak_entry_operators": 0,
    "min_wg_soak_exit_operators": 0,
    "min_wg_soak_cross_operator_pairs": 0,
    "max_evidence_age_sec": 0
  },
  "runs": [
    {"generated_at_utc": "2026-03-10T00:04:30Z", "decision": "GO", "report_path": "$GOOD_RUN_REPORT", "first_no_go_reason": ""},
    {"generated_at_utc": "2026-03-10T00:04:35Z", "decision": "NO-GO", "report_path": "$BAD_RUN_REPORT", "first_no_go_reason": "gate status is not ok"}
  ],
  "incident_snapshot": {
    "latest_failed_run_report": {
      "source_run_report_json": {"path": "/tmp/run_b/prod_bundle_run_report.json", "exists": true},
      "source_summary_json": {"path": "/tmp/run_b/prod_gate_summary.json", "exists": true, "valid_json": true},
      "path": "/tmp/run_b/prod_bundle_run_report.json",
      "enabled": true,
      "status": "ok",
      "bundle_dir": {"path": "/tmp/run_b/incident_bundle", "exists": true},
      "bundle_tar": {"path": "/tmp/run_b/incident_bundle.tar.gz", "exists": true},
      "summary_json": {"path": "/tmp/run_b/incident_summary.json", "exists": true, "valid_json": true},
      "report_md": {"path": "/tmp/run_b/incident_report.md", "exists": true},
      "attachment_manifest": {"path": "/tmp/run_b/incident_attachments_manifest.json", "exists": true},
      "attachment_skipped": {"path": "/tmp/run_b/incident_attachments_skipped.json", "exists": true},
      "attachment_count": 1
    }
  },
  "top_no_go_reasons": [
    {"count": 1, "reason": "wg_soak_rounds_failed exceeds limit"}
  ]
}
EOF_WARN_SUMMARY

cat >"$CRIT_SUMMARY" <<EOF_CRIT_SUMMARY
{
  "generated_at_utc": "2026-03-10T00:05:00Z",
  "go": 0,
  "go_rate_pct": 0,
  "no_go": 2,
  "evaluation_errors": 0,
  "reports_total": 2,
  "filters": {"max_reports": 25, "since_hours": 0, "max_evidence_age_sec": 0},
  "policy": {
    "require_full_sequence": 1,
    "require_wg_validate_ok": 1,
    "require_wg_soak_ok": 1,
    "max_wg_soak_failed_rounds": 0,
    "require_preflight_ok": 0,
    "require_bundle_ok": 0,
    "require_integrity_ok": 0,
    "require_signoff_ok": 0,
    "require_incident_snapshot_on_fail": 0,
    "require_incident_snapshot_artifacts": 0,
    "require_wg_validate_udp_source": 0,
    "require_wg_validate_strict_distinct": 0,
    "require_wg_soak_diversity_pass": 0,
    "min_wg_soak_selection_lines": 0,
    "min_wg_soak_entry_operators": 0,
    "min_wg_soak_exit_operators": 0,
    "min_wg_soak_cross_operator_pairs": 0,
    "max_evidence_age_sec": 0
  },
  "runs": [
    {"generated_at_utc": "2026-03-10T00:04:35Z", "decision": "NO-GO", "report_path": "$BAD_RUN_REPORT", "first_no_go_reason": "gate status is not ok"},
    {"generated_at_utc": "2026-03-10T00:04:35Z", "decision": "NO-GO", "report_path": "$BAD_RUN_REPORT", "first_no_go_reason": "gate status is not ok"}
  ],
  "top_no_go_reasons": [
    {"count": 2, "reason": "wg_soak_status is not ok"},
    {"count": 1, "reason": "gate status is not ok"}
  ]
}
EOF_CRIT_SUMMARY

echo "[prod-gate-slo-alert] OK severity baseline"
./scripts/prod_gate_slo_alert.sh \
  --trend-summary-json "$OK_SUMMARY" \
  --summary-json "$TMP_DIR/alert_ok_out.json" \
  --print-summary-json 1 >/tmp/integration_prod_gate_slo_alert_ok.log 2>&1

if ! rg -q '\[prod-gate-slo-alert\] severity=OK' /tmp/integration_prod_gate_slo_alert_ok.log; then
  echo "expected OK severity baseline not found"
  cat /tmp/integration_prod_gate_slo_alert_ok.log
  exit 1
fi
if ! jq -e '.severity == "OK" and .metrics.reports_total == 1' "$TMP_DIR/alert_ok_out.json" >/dev/null 2>&1; then
  echo "alert OK summary JSON missing expected fields"
  cat "$TMP_DIR/alert_ok_out.json"
  exit 1
fi
if ! jq -e '.wg_evidence_policy.require_wg_validate_udp_source == 0 and .wg_evidence_policy.require_wg_validate_strict_distinct == 0 and .wg_evidence_policy.require_wg_soak_diversity_pass == 0 and .wg_evidence_policy.min_wg_soak_selection_lines == 0 and .wg_evidence_policy.min_wg_soak_entry_operators == 0 and .wg_evidence_policy.min_wg_soak_exit_operators == 0 and .wg_evidence_policy.min_wg_soak_cross_operator_pairs == 0' "$TMP_DIR/alert_ok_out.json" >/dev/null 2>&1; then
  echo "alert OK summary JSON missing expected WG evidence policy defaults"
  cat "$TMP_DIR/alert_ok_out.json"
  exit 1
fi

echo "[prod-gate-slo-alert] WARN severity baseline"
./scripts/prod_gate_slo_alert.sh \
  --trend-summary-json "$WARN_SUMMARY" \
  --warn-go-rate-pct 98 \
  --critical-go-rate-pct 90 \
  --warn-no-go-count 1 \
  --critical-no-go-count 2 \
  --warn-eval-errors 1 \
  --critical-eval-errors 2 >/tmp/integration_prod_gate_slo_alert_warn.log 2>&1

if ! rg -q '\[prod-gate-slo-alert\] severity=WARN' /tmp/integration_prod_gate_slo_alert_warn.log; then
  echo "expected WARN severity baseline not found"
  cat /tmp/integration_prod_gate_slo_alert_warn.log
  exit 1
fi
if ! rg -q '\[prod-gate-slo-alert\] incident_handoff source_summary_json=' /tmp/integration_prod_gate_slo_alert_warn.log; then
  echo "expected normalized incident handoff output not found"
  cat /tmp/integration_prod_gate_slo_alert_warn.log
  exit 1
fi
if ! rg -q 'attachment_manifest=/tmp/run_b/incident_attachments_manifest.json' /tmp/integration_prod_gate_slo_alert_warn.log; then
  echo "expected incident attachment manifest in alert handoff output"
  cat /tmp/integration_prod_gate_slo_alert_warn.log
  exit 1
fi

echo "[prod-gate-slo-alert] provided trend freshness fail-close"
MISSING_FRESHNESS_JSON="$TMP_DIR/alert_missing_freshness.json"
MISSING_FRESHNESS_SUMMARY="$TMP_DIR/summary_missing_freshness.json"
cat >"$MISSING_FRESHNESS_SUMMARY" <<EOF_MISSING_FRESHNESS
{
  "go": 1,
  "go_rate_pct": 100,
  "no_go": 0,
  "evaluation_errors": 0,
  "reports_total": 1,
  "filters": {"max_reports": 25, "since_hours": 0, "max_evidence_age_sec": 600},
  "policy": {
    "require_full_sequence": 1,
    "require_wg_validate_ok": 1,
    "require_wg_soak_ok": 1,
    "max_wg_soak_failed_rounds": 0,
    "max_evidence_age_sec": 600
  },
  "runs": [
    {"decision": "GO", "report_path": "$GOOD_RUN_REPORT", "first_no_go_reason": ""}
  ],
  "top_no_go_reasons": []
}
EOF_MISSING_FRESHNESS
set +e
./scripts/prod_gate_slo_alert.sh \
  --trend-summary-json "$MISSING_FRESHNESS_SUMMARY" \
  --max-evidence-age-sec 600 \
  --fail-on-critical 1 \
  --summary-json "$MISSING_FRESHNESS_JSON" >/tmp/integration_prod_gate_slo_alert_missing_freshness.log 2>&1
missing_freshness_rc=$?
set -e
if [[ "$missing_freshness_rc" -ne 2 ]]; then
  echo "expected rc=2 for missing trend freshness fail-close (got $missing_freshness_rc)"
  cat /tmp/integration_prod_gate_slo_alert_missing_freshness.log
  exit 1
fi
if ! jq -e '.severity == "CRITICAL" and any(.evidence_freshness.reasons[]; test("generated_at_utc timestamp missing"))' "$MISSING_FRESHNESS_JSON" >/dev/null 2>&1; then
  echo "alert missing freshness summary JSON missing expected CRITICAL reason"
  cat "$MISSING_FRESHNESS_JSON"
  exit 1
fi

FRESH_POLICY_SUMMARY="$TMP_DIR/summary_fresh_policy.json"
cat >"$FRESH_POLICY_SUMMARY" <<EOF_FRESH_POLICY_SUMMARY
{
  "generated_at_utc": "2026-03-10T00:05:00Z",
  "go": 1,
  "go_rate_pct": 100,
  "no_go": 0,
  "evaluation_errors": 0,
  "reports_total": 1,
  "filters": {"max_reports": 25, "since_hours": 0, "max_evidence_age_sec": 600},
  "policy": {
    "require_full_sequence": 1,
    "require_wg_validate_ok": 1,
    "require_wg_soak_ok": 1,
    "max_wg_soak_failed_rounds": 0,
    "require_preflight_ok": 1,
    "require_bundle_ok": 1,
    "require_integrity_ok": 1,
    "require_signoff_ok": 1,
    "require_incident_snapshot_on_fail": 1,
    "require_incident_snapshot_artifacts": 1,
    "require_wg_validate_udp_source": 1,
    "require_wg_validate_strict_distinct": 1,
    "require_wg_soak_diversity_pass": 1,
    "min_wg_soak_selection_lines": 8,
    "min_wg_soak_entry_operators": 2,
    "min_wg_soak_exit_operators": 2,
    "min_wg_soak_cross_operator_pairs": 1,
    "max_evidence_age_sec": 600
  },
  "runs": [
    {"generated_at_utc": "2026-03-10T00:04:30Z", "decision": "GO", "report_path": "$GOOD_RUN_REPORT", "first_no_go_reason": ""}
  ],
  "top_no_go_reasons": []
}
EOF_FRESH_POLICY_SUMMARY

FRESH_POLICY_NOW_EPOCH="$(jq -nr '"2026-03-10T00:06:00Z" | fromdateiso8601 | floor')"
PROD_GATE_SLO_ALERT_NOW_EPOCH="$FRESH_POLICY_NOW_EPOCH" \
./scripts/prod_gate_slo_alert.sh \
  --trend-summary-json "$FRESH_POLICY_SUMMARY" \
  --max-evidence-age-sec 600 \
  --require-full-sequence 1 \
  --require-wg-validate-ok 1 \
  --require-wg-soak-ok 1 \
  --max-wg-soak-failed-rounds 0 \
  --require-preflight-ok 1 \
  --require-bundle-ok 1 \
  --require-integrity-ok 1 \
  --require-signoff-ok 1 \
  --require-incident-snapshot-on-fail 1 \
  --require-incident-snapshot-artifacts 1 \
  --require-wg-validate-udp-source 1 \
  --require-wg-validate-strict-distinct 1 \
  --require-wg-soak-diversity-pass 1 \
  --min-wg-soak-selection-lines 8 \
  --min-wg-soak-entry-operators 2 \
  --min-wg-soak-exit-operators 2 \
  --min-wg-soak-cross-operator-pairs 1 \
  --fail-on-critical 1 \
  --summary-json "$TMP_DIR/alert_fresh_policy_out.json" >/tmp/integration_prod_gate_slo_alert_fresh_policy.log 2>&1
if ! jq -e '.severity == "OK" and .evidence_freshness.status == "ok" and .trend_policy_check.status == "ok"' "$TMP_DIR/alert_fresh_policy_out.json" >/dev/null 2>&1; then
  echo "fresh policy alert did not stay OK"
  cat "$TMP_DIR/alert_fresh_policy_out.json"
  exit 1
fi

STALE_POLICY_SUMMARY="$TMP_DIR/summary_stale_policy.json"
jq '.generated_at_utc = "2026-03-10T00:00:00Z" | .runs[0].generated_at_utc = "2026-03-10T00:00:00Z"' "$FRESH_POLICY_SUMMARY" >"$STALE_POLICY_SUMMARY"
STALE_POLICY_NOW_EPOCH="$(jq -nr '"2026-03-10T00:30:00Z" | fromdateiso8601 | floor')"
set +e
PROD_GATE_SLO_ALERT_NOW_EPOCH="$STALE_POLICY_NOW_EPOCH" \
./scripts/prod_gate_slo_alert.sh \
  --trend-summary-json "$STALE_POLICY_SUMMARY" \
  --max-evidence-age-sec 600 \
  --fail-on-critical 1 \
  --summary-json "$TMP_DIR/alert_stale_policy_out.json" >/tmp/integration_prod_gate_slo_alert_stale_policy.log 2>&1
stale_policy_rc=$?
set -e
if [[ "$stale_policy_rc" -ne 2 ]]; then
  echo "expected rc=2 for stale provided trend summary (got $stale_policy_rc)"
  cat /tmp/integration_prod_gate_slo_alert_stale_policy.log
  exit 1
fi
if ! jq -e '.severity == "CRITICAL" and any(.evidence_freshness.reasons[]; test("timestamp is stale"))' "$TMP_DIR/alert_stale_policy_out.json" >/dev/null 2>&1; then
  echo "stale provided trend summary did not produce expected freshness reason"
  cat "$TMP_DIR/alert_stale_policy_out.json"
  exit 1
fi

WEAK_POLICY_SUMMARY="$TMP_DIR/summary_weak_policy.json"
jq '.policy.require_signoff_ok = 0 | .policy.require_wg_validate_udp_source = 0 | .policy.max_evidence_age_sec = 0 | .filters.max_evidence_age_sec = 0' "$FRESH_POLICY_SUMMARY" >"$WEAK_POLICY_SUMMARY"
set +e
PROD_GATE_SLO_ALERT_NOW_EPOCH="$FRESH_POLICY_NOW_EPOCH" \
./scripts/prod_gate_slo_alert.sh \
  --trend-summary-json "$WEAK_POLICY_SUMMARY" \
  --max-evidence-age-sec 600 \
  --require-signoff-ok 1 \
  --require-wg-validate-udp-source 1 \
  --fail-on-critical 1 \
  --summary-json "$TMP_DIR/alert_weak_policy_out.json" >/tmp/integration_prod_gate_slo_alert_weak_policy.log 2>&1
weak_policy_rc=$?
set -e
if [[ "$weak_policy_rc" -ne 2 ]]; then
  echo "expected rc=2 for weak trend policy fail-close (got $weak_policy_rc)"
  cat /tmp/integration_prod_gate_slo_alert_weak_policy.log
  exit 1
fi
if ! jq -e '.severity == "CRITICAL" and any(.trend_policy_check.reasons[]; test("require_signoff_ok")) and any(.trend_policy_check.reasons[]; test("require_wg_validate_udp_source")) and any(.trend_policy_check.reasons[]; test("max_evidence_age_sec"))' "$TMP_DIR/alert_weak_policy_out.json" >/dev/null 2>&1; then
  echo "weak trend policy summary missing expected policy reasons"
  cat "$TMP_DIR/alert_weak_policy_out.json"
  exit 1
fi

FORGED_METRICS_SUMMARY="$TMP_DIR/summary_forged_metrics.json"
jq --arg bad_run "$BAD_RUN_REPORT" '
  .runs[0].decision = "NO-GO"
  | .runs[0].report_path = $bad_run
  | .runs[0].first_no_go_reason = "gate status is not ok"
' "$FRESH_POLICY_SUMMARY" >"$FORGED_METRICS_SUMMARY"
set +e
PROD_GATE_SLO_ALERT_NOW_EPOCH="$FRESH_POLICY_NOW_EPOCH" \
./scripts/prod_gate_slo_alert.sh \
  --trend-summary-json "$FORGED_METRICS_SUMMARY" \
  --max-evidence-age-sec 600 \
  --fail-on-critical 1 \
  --summary-json "$TMP_DIR/alert_forged_metrics_out.json" >/tmp/integration_prod_gate_slo_alert_forged_metrics.log 2>&1
forged_metrics_rc=$?
set -e
if [[ "$forged_metrics_rc" -ne 2 ]]; then
  echo "expected rc=2 for forged provided trend metrics (got $forged_metrics_rc)"
  cat /tmp/integration_prod_gate_slo_alert_forged_metrics.log
  exit 1
fi
if ! jq -e '.severity == "CRITICAL" and any(.trend_integrity_check.reasons[]; test("does not match"))' "$TMP_DIR/alert_forged_metrics_out.json" >/dev/null 2>&1; then
  echo "forged provided trend summary missing expected integrity reason"
  cat "$TMP_DIR/alert_forged_metrics_out.json"
  exit 1
fi

MISMATCH_FILTER_SUMMARY="$TMP_DIR/summary_mismatch_filter.json"
jq '.filters.since_hours = 168' "$FRESH_POLICY_SUMMARY" >"$MISMATCH_FILTER_SUMMARY"
set +e
PROD_GATE_SLO_ALERT_NOW_EPOCH="$FRESH_POLICY_NOW_EPOCH" \
./scripts/prod_gate_slo_alert.sh \
  --trend-summary-json "$MISMATCH_FILTER_SUMMARY" \
  --max-evidence-age-sec 600 \
  --since-hours 24 \
  --fail-on-critical 1 \
  --summary-json "$TMP_DIR/alert_mismatch_filter_out.json" >/tmp/integration_prod_gate_slo_alert_mismatch_filter.log 2>&1
mismatch_filter_rc=$?
set -e
if [[ "$mismatch_filter_rc" -ne 2 ]]; then
  echo "expected rc=2 for provided trend filter mismatch (got $mismatch_filter_rc)"
  cat /tmp/integration_prod_gate_slo_alert_mismatch_filter.log
  exit 1
fi
if ! jq -e '.severity == "CRITICAL" and any(.trend_policy_check.reasons[]; test("since_hours"))' "$TMP_DIR/alert_mismatch_filter_out.json" >/dev/null 2>&1; then
  echo "filter-mismatch trend summary missing expected policy reason"
  cat "$TMP_DIR/alert_mismatch_filter_out.json"
  exit 1
fi

echo "[prod-gate-slo-alert] WARN fail-close"
set +e
./scripts/prod_gate_slo_alert.sh \
  --trend-summary-json "$WARN_SUMMARY" \
  --warn-go-rate-pct 98 \
  --critical-go-rate-pct 90 \
  --warn-no-go-count 1 \
  --critical-no-go-count 2 \
  --fail-on-warn 1 >/tmp/integration_prod_gate_slo_alert_warn_fail.log 2>&1
warn_fail_rc=$?
set -e
if [[ "$warn_fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for WARN fail-close (got $warn_fail_rc)"
  cat /tmp/integration_prod_gate_slo_alert_warn_fail.log
  exit 1
fi
WARN_ALERT_JSON="$TMP_DIR/alert_warn_out.json"
./scripts/prod_gate_slo_alert.sh \
  --trend-summary-json "$WARN_SUMMARY" \
  --summary-json "$WARN_ALERT_JSON" >/tmp/integration_prod_gate_slo_alert_warn_json.log 2>&1
if ! jq -e '.incident_snapshot.latest_failed_run_report.source_run_report_json.path == "/tmp/run_b/prod_bundle_run_report.json" and .incident_snapshot.latest_failed_run_report.source_summary_json.path == "/tmp/run_b/prod_gate_summary.json" and .incident_snapshot.latest_failed_run_report.summary_json.path == "/tmp/run_b/incident_summary.json" and .incident_snapshot.latest_failed_run_report.report_md.path == "/tmp/run_b/incident_report.md" and .incident_snapshot.latest_failed_run_report.attachment_manifest.path == "/tmp/run_b/incident_attachments_manifest.json" and .incident_snapshot.latest_failed_run_report.attachment_skipped.path == "/tmp/run_b/incident_attachments_skipped.json" and .incident_snapshot.latest_failed_run_report.attachment_count == 1' "$WARN_ALERT_JSON" >/dev/null 2>&1; then
  echo "alert WARN summary JSON missing incident handoff block"
  cat "$WARN_ALERT_JSON"
  exit 1
fi

echo "[prod-gate-slo-alert] CRITICAL fail-close"
set +e
./scripts/prod_gate_slo_alert.sh \
  --trend-summary-json "$CRIT_SUMMARY" \
  --fail-on-critical 1 >/tmp/integration_prod_gate_slo_alert_critical_fail.log 2>&1
crit_fail_rc=$?
set -e
if [[ "$crit_fail_rc" -ne 2 ]]; then
  echo "expected rc=2 for CRITICAL fail-close (got $crit_fail_rc)"
  cat /tmp/integration_prod_gate_slo_alert_critical_fail.log
  exit 1
fi
if ! rg -q '\[prod-gate-slo-alert\] severity=CRITICAL' /tmp/integration_prod_gate_slo_alert_critical_fail.log; then
  echo "expected CRITICAL severity marker not found"
  cat /tmp/integration_prod_gate_slo_alert_critical_fail.log
  exit 1
fi

echo "[prod-gate-slo-alert] generated trend summary path"
FAKE_TREND="$TMP_DIR/fake_prod_gate_slo_trend.sh"
TREND_CAPTURE="$TMP_DIR/trend_capture.log"
cat >"$FAKE_TREND" <<'EOF_FAKE_TREND'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${TREND_CAPTURE_FILE:?}"
summary_file=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_file="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$summary_file" ]]; then
  mkdir -p "$(dirname "$summary_file")"
  cat >"$summary_file" <<'EOF_TREND_SUMMARY'
{
  "generated_at_utc": "2026-03-10T00:05:00Z",
  "go_rate_pct": 99.2,
  "no_go": 0,
  "evaluation_errors": 0,
  "reports_total": 4,
  "filters": {"max_evidence_age_sec": 600},
  "policy": {
    "require_signoff_ok": 1,
    "require_incident_snapshot_on_fail": 1,
    "require_incident_snapshot_artifacts": 1,
    "require_wg_validate_udp_source": 1,
    "require_wg_validate_strict_distinct": 1,
    "require_wg_soak_diversity_pass": 1,
    "min_wg_soak_selection_lines": 8,
    "min_wg_soak_entry_operators": 2,
    "min_wg_soak_exit_operators": 2,
    "min_wg_soak_cross_operator_pairs": 1,
    "max_evidence_age_sec": 600
  },
  "runs": [
    {"generated_at_utc": "2026-03-10T00:04:30Z", "decision": "GO", "report_path": "/tmp/run_a/prod_bundle_run_report.json", "first_no_go_reason": ""}
  ],
  "top_no_go_reasons": []
}
EOF_TREND_SUMMARY
fi
exit 0
EOF_FAKE_TREND
chmod +x "$FAKE_TREND"

TREND_CAPTURE_FILE="$TREND_CAPTURE" \
PROD_GATE_SLO_TREND_SCRIPT="$FAKE_TREND" \
PROD_GATE_SLO_ALERT_NOW_EPOCH="$FRESH_POLICY_NOW_EPOCH" \
./scripts/prod_gate_slo_alert.sh \
  --reports-dir /tmp/prod_reports \
  --max-reports 7 \
  --since-hours 24 \
  --require-signoff-ok 1 \
  --require-incident-snapshot-on-fail 1 \
  --require-incident-snapshot-artifacts 1 \
  --require-wg-validate-udp-source 1 \
  --require-wg-validate-strict-distinct 1 \
  --require-wg-soak-diversity-pass 1 \
  --min-wg-soak-selection-lines 8 \
  --min-wg-soak-entry-operators 2 \
  --min-wg-soak-exit-operators 2 \
  --min-wg-soak-cross-operator-pairs 1 \
  --max-evidence-age-sec 600 \
  --show-top-reasons 3 >/tmp/integration_prod_gate_slo_alert_generated.log 2>&1

if ! rg -q -- '--reports-dir /tmp/prod_reports' "$TREND_CAPTURE"; then
  echo "alert-generated trend failed: missing reports-dir forwarding"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--max-reports 7' "$TREND_CAPTURE"; then
  echo "alert-generated trend failed: missing max-reports forwarding"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--since-hours 24' "$TREND_CAPTURE"; then
  echo "alert-generated trend failed: missing since-hours forwarding"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--summary-json ' "$TREND_CAPTURE"; then
  echo "alert-generated trend failed: missing summary-json forwarding"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-on-fail 1' "$TREND_CAPTURE"; then
  echo "alert-generated trend failed: missing --require-incident-snapshot-on-fail forwarding"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-artifacts 1' "$TREND_CAPTURE"; then
  echo "alert-generated trend failed: missing --require-incident-snapshot-artifacts forwarding"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-validate-udp-source 1' "$TREND_CAPTURE"; then
  echo "alert-generated trend failed: missing --require-wg-validate-udp-source forwarding"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-validate-strict-distinct 1' "$TREND_CAPTURE"; then
  echo "alert-generated trend failed: missing --require-wg-validate-strict-distinct forwarding"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-soak-diversity-pass 1' "$TREND_CAPTURE"; then
  echo "alert-generated trend failed: missing --require-wg-soak-diversity-pass forwarding"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-selection-lines 8' "$TREND_CAPTURE"; then
  echo "alert-generated trend failed: missing --min-wg-soak-selection-lines forwarding"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-entry-operators 2' "$TREND_CAPTURE"; then
  echo "alert-generated trend failed: missing --min-wg-soak-entry-operators forwarding"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-exit-operators 2' "$TREND_CAPTURE"; then
  echo "alert-generated trend failed: missing --min-wg-soak-exit-operators forwarding"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-cross-operator-pairs 1' "$TREND_CAPTURE"; then
  echo "alert-generated trend failed: missing --min-wg-soak-cross-operator-pairs forwarding"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--max-evidence-age-sec 600' "$TREND_CAPTURE"; then
  echo "alert-generated trend failed: missing --max-evidence-age-sec forwarding"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--print-summary-json 0' "$TREND_CAPTURE"; then
  echo "alert-generated trend failed: missing print-summary-json forwarding"
  cat "$TREND_CAPTURE"
  exit 1
fi

echo "[prod-gate-slo-alert] easy_node forwarding"
FAKE_ALERT="$TMP_DIR/fake_prod_gate_slo_alert.sh"
ALERT_CAPTURE="$TMP_DIR/alert_capture.log"
cat >"$FAKE_ALERT" <<'EOF_FAKE_ALERT'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${ALERT_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_ALERT
chmod +x "$FAKE_ALERT"

ALERT_CAPTURE_FILE="$ALERT_CAPTURE" \
PROD_GATE_SLO_ALERT_SCRIPT="$FAKE_ALERT" \
./scripts/easy_node.sh prod-gate-slo-alert \
  --reports-dir /tmp/prod_reports \
  --since-hours 12 \
  --require-incident-snapshot-on-fail 1 \
  --require-incident-snapshot-artifacts 1 \
  --require-wg-validate-udp-source 1 \
  --require-wg-validate-strict-distinct 1 \
  --require-wg-soak-diversity-pass 1 \
  --min-wg-soak-selection-lines 8 \
  --min-wg-soak-entry-operators 2 \
  --min-wg-soak-exit-operators 2 \
  --min-wg-soak-cross-operator-pairs 1 \
  --max-evidence-age-sec 600 \
  --warn-go-rate-pct 99 \
  --critical-go-rate-pct 95 \
  --fail-on-warn 1 \
  --summary-json /tmp/prod_alert.json \
  --print-summary-json 1 >/tmp/integration_prod_gate_slo_alert_easy_node.log 2>&1

if ! rg -q -- '--reports-dir /tmp/prod_reports' "$ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing reports-dir"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--since-hours 12' "$ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing since-hours"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--warn-go-rate-pct 99' "$ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing warn-go-rate-pct"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--critical-go-rate-pct 95' "$ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing critical-go-rate-pct"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-on-fail 1' "$ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing --require-incident-snapshot-on-fail"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-artifacts 1' "$ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing --require-incident-snapshot-artifacts"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-validate-udp-source 1' "$ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing --require-wg-validate-udp-source"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-validate-strict-distinct 1' "$ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing --require-wg-validate-strict-distinct"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-soak-diversity-pass 1' "$ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing --require-wg-soak-diversity-pass"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-selection-lines 8' "$ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing --min-wg-soak-selection-lines"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-entry-operators 2' "$ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing --min-wg-soak-entry-operators"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-exit-operators 2' "$ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing --min-wg-soak-exit-operators"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-cross-operator-pairs 1' "$ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing --min-wg-soak-cross-operator-pairs"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--max-evidence-age-sec 600' "$ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing --max-evidence-age-sec"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--summary-json /tmp/prod_alert.json' "$ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing summary-json"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--print-summary-json 1' "$ALERT_CAPTURE"; then
  echo "easy_node prod-gate-slo-alert forwarding failed: missing print-summary-json"
  cat "$ALERT_CAPTURE"
  exit 1
fi

echo "prod gate slo alert integration ok"
