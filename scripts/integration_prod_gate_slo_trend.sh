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

REPORTS_DIR="$TMP_DIR/reports"
mkdir -p "$REPORTS_DIR/run_a" "$REPORTS_DIR/run_b" "$REPORTS_DIR/run_c"
mkdir -p "$REPORTS_DIR/run_b/incident_bundle"
touch "$REPORTS_DIR/run_b/incident_attachments_manifest.json" "$REPORTS_DIR/run_b/incident_attachments_skipped.json"

cat >"$REPORTS_DIR/run_b/incident_summary.json" <<'EOF_INCIDENT_SUMMARY_B'
{
  "status": "ok"
}
EOF_INCIDENT_SUMMARY_B

cat >"$REPORTS_DIR/run_b/incident_report.md" <<'EOF_INCIDENT_REPORT_B'
# Incident Report
EOF_INCIDENT_REPORT_B

touch "$REPORTS_DIR/run_b/incident_bundle.tar.gz"

cat >"$REPORTS_DIR/run_a/prod_gate_summary.json" <<'EOF_GATE_A'
{
  "status": "ok",
  "failed_step": "",
  "failed_rc": 0,
  "steps": {
    "control_validate": "ok",
    "control_soak": "ok",
    "prod_wg_validate": "ok",
    "prod_wg_soak": "ok"
  },
  "wg_validate_status": "ok",
  "wg_validate_failed_step": "",
  "wg_soak_status": "ok",
  "wg_soak_rounds_passed": 10,
  "wg_soak_rounds_failed": 0,
  "wg_soak_top_failure_class": "none",
  "wg_soak_top_failure_count": 0
}
EOF_GATE_A

cat >"$REPORTS_DIR/run_b/prod_gate_summary.json" <<'EOF_GATE_B'
{
  "status": "ok",
  "failed_step": "",
  "failed_rc": 0,
  "steps": {
    "control_validate": "ok",
    "control_soak": "ok",
    "prod_wg_validate": "ok",
    "prod_wg_soak": "ok"
  },
  "wg_validate_status": "ok",
  "wg_validate_failed_step": "",
  "wg_soak_status": "ok",
  "wg_soak_rounds_passed": 7,
  "wg_soak_rounds_failed": 2,
  "wg_soak_top_failure_class": "endpoint_connectivity",
  "wg_soak_top_failure_count": 2
}
EOF_GATE_B

cat >"$REPORTS_DIR/run_c/prod_gate_summary.json" <<'EOF_GATE_C'
{
  "status": "ok",
  "failed_step": "",
  "failed_rc": 0,
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
EOF_GATE_C

cat >"$REPORTS_DIR/run_a/prod_bundle_run_report.json" <<EOF_RR_A
{
  "generated_at_utc": "2026-03-10T10:00:00Z",
  "bundle_dir": "$REPORTS_DIR/run_a",
  "gate_summary_json": "$REPORTS_DIR/run_a/prod_gate_summary.json",
  "preflight": {"enabled": true, "status": "ok", "rc": 0},
  "bundle": {"status": "ok", "rc": 0},
  "integrity_verify": {"enabled": true, "status": "ok", "rc": 0},
  "signoff": {"enabled": true, "rc": 0}
}
EOF_RR_A

cat >"$REPORTS_DIR/run_b/prod_bundle_run_report.json" <<EOF_RR_B
{
  "generated_at_utc": "2026-03-10T11:00:00Z",
  "bundle_dir": "$REPORTS_DIR/run_b",
  "gate_summary_json": "$REPORTS_DIR/run_b/prod_gate_summary.json",
  "preflight": {"enabled": true, "status": "ok", "rc": 0},
  "bundle": {"status": "ok", "rc": 0},
  "integrity_verify": {"enabled": true, "status": "ok", "rc": 0},
  "signoff": {"enabled": true, "rc": 0},
  "incident_snapshot": {
    "enabled_on_fail": true,
    "status": "ok",
    "rc": 0,
    "bundle_dir": "$REPORTS_DIR/run_b/incident_bundle",
    "bundle_tar": "$REPORTS_DIR/run_b/incident_bundle.tar.gz",
    "summary_json": "$REPORTS_DIR/run_b/incident_summary.json",
    "report_md": "$REPORTS_DIR/run_b/incident_report.md",
    "attachment_manifest": "$REPORTS_DIR/run_b/incident_attachments_manifest.json",
    "attachment_skipped": "$REPORTS_DIR/run_b/incident_attachments_skipped.json",
    "attachment_count": 1
  }
}
EOF_RR_B

cat >"$REPORTS_DIR/run_c/prod_bundle_run_report.json" <<EOF_RR_C
{
  "generated_at_utc": "2026-03-10T12:00:00Z",
  "bundle_dir": "$REPORTS_DIR/run_c",
  "gate_summary_json": "$REPORTS_DIR/run_c/prod_gate_summary.json",
  "preflight": {"enabled": true, "status": "ok", "rc": 0},
  "bundle": {"status": "ok", "rc": 0},
  "integrity_verify": {"enabled": true, "status": "ok", "rc": 0},
  "signoff": {"enabled": true, "rc": 0}
}
EOF_RR_C

echo "[prod-gate-slo-trend] baseline trend (2 GO, 1 NO-GO)"
SUMMARY_JSON="$TMP_DIR/slo_trend_summary.json"
./scripts/prod_gate_slo_trend.sh \
  --reports-dir "$REPORTS_DIR" \
  --max-reports 3 \
  --max-wg-soak-failed-rounds 0 \
  --summary-json "$SUMMARY_JSON" \
  --print-summary-json 1 \
  --show-details 0 \
  --show-top-reasons 3 >/tmp/integration_prod_gate_slo_trend_baseline.log 2>&1

if ! rg -q '\[prod-gate-slo-trend\] reports_total=3 go=2 no_go=1 go_rate_pct=66.67' /tmp/integration_prod_gate_slo_trend_baseline.log; then
  echo "expected baseline trend summary not found"
  cat /tmp/integration_prod_gate_slo_trend_baseline.log
  exit 1
fi
if ! rg -q 'reason=wg_soak_rounds_failed exceeds limit' /tmp/integration_prod_gate_slo_trend_baseline.log; then
  echo "expected top no-go reason not found"
  cat /tmp/integration_prod_gate_slo_trend_baseline.log
  exit 1
fi
if [[ ! -f "$SUMMARY_JSON" ]]; then
  echo "expected summary JSON output file not found"
  ls -la "$TMP_DIR"
  cat /tmp/integration_prod_gate_slo_trend_baseline.log
  exit 1
fi
if ! jq -e '.reports_total == 3 and .go == 2 and .no_go == 1 and .decision == "GO"' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "summary JSON missing expected baseline aggregate fields"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.incident_snapshot.latest_failed_run_report.source_run_report_json.path | endswith("/run_b/prod_bundle_run_report.json")' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "summary JSON missing incident source run report handoff"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.incident_snapshot.latest_failed_run_report.source_summary_json.path | endswith("/run_b/prod_gate_summary.json")' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "summary JSON missing incident source summary handoff"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '(.incident_snapshot.latest_failed_run_report.summary_json.path | endswith("/run_b/incident_summary.json")) and (.incident_snapshot.latest_failed_run_report.summary_json.valid_json == 1) and (.incident_snapshot.latest_failed_run_report.report_md.path | endswith("/run_b/incident_report.md"))' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "summary JSON missing incident summary/report handoff"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '(.incident_snapshot.latest_failed_run_report.attachment_manifest.path | endswith("/run_b/incident_attachments_manifest.json")) and (.incident_snapshot.latest_failed_run_report.attachment_skipped.path | endswith("/run_b/incident_attachments_skipped.json")) and (.incident_snapshot.latest_failed_run_report.attachment_count == 1)' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "summary JSON missing incident attachment handoff"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '.policy.require_wg_validate_udp_source == 0 and .policy.require_wg_validate_strict_distinct == 0 and .policy.require_wg_soak_diversity_pass == 0 and .policy.min_wg_soak_selection_lines == 0 and .policy.min_wg_soak_entry_operators == 0 and .policy.min_wg_soak_exit_operators == 0 and .policy.min_wg_soak_cross_operator_pairs == 0' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "summary JSON policy block missing expected WG evidence defaults"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! rg -q '\[prod-gate-slo-trend\] summary_json_payload:' /tmp/integration_prod_gate_slo_trend_baseline.log; then
  echo "expected printed summary payload marker not found"
  cat /tmp/integration_prod_gate_slo_trend_baseline.log
  exit 1
fi
if ! rg -q '\[prod-gate-slo-trend\] incident_handoff source_summary_json=' /tmp/integration_prod_gate_slo_trend_baseline.log; then
  echo "expected normalized incident handoff line not found"
  cat /tmp/integration_prod_gate_slo_trend_baseline.log
  exit 1
fi
if ! rg -q 'attachment_manifest=.*incident_attachments_manifest.json' /tmp/integration_prod_gate_slo_trend_baseline.log; then
  echo "expected incident attachment manifest in trend handoff line"
  cat /tmp/integration_prod_gate_slo_trend_baseline.log
  exit 1
fi

echo "[prod-gate-slo-trend] since-hours filter"
touch -t 202001010101 "$REPORTS_DIR/run_a/prod_bundle_run_report.json" "$REPORTS_DIR/run_b/prod_bundle_run_report.json"
./scripts/prod_gate_slo_trend.sh \
  --reports-dir "$REPORTS_DIR" \
  --max-reports 10 \
  --since-hours 1 \
  --max-wg-soak-failed-rounds 0 \
  --show-details 0 >/tmp/integration_prod_gate_slo_trend_since_hours.log 2>&1

if ! rg -q '\[prod-gate-slo-trend\] reports_total=1 go=1 no_go=0' /tmp/integration_prod_gate_slo_trend_since_hours.log; then
  echo "expected since-hours filtered aggregate not found"
  cat /tmp/integration_prod_gate_slo_trend_since_hours.log
  exit 1
fi

echo "[prod-gate-slo-trend] fail-close on any NO-GO"
set +e
./scripts/prod_gate_slo_trend.sh \
  --reports-dir "$REPORTS_DIR" \
  --max-reports 3 \
  --max-wg-soak-failed-rounds 0 \
  --fail-on-any-no-go 1 \
  --show-details 0 >/tmp/integration_prod_gate_slo_trend_fail_any.log 2>&1
fail_any_rc=$?
set -e
if [[ "$fail_any_rc" -eq 0 ]]; then
  echo "expected non-zero rc when --fail-on-any-no-go=1 and a NO-GO exists"
  cat /tmp/integration_prod_gate_slo_trend_fail_any.log
  exit 1
fi
if ! rg -q '\[prod-gate-slo-trend\] trend_decision=NO-GO' /tmp/integration_prod_gate_slo_trend_fail_any.log; then
  echo "expected NO-GO trend decision in fail-on-any output"
  cat /tmp/integration_prod_gate_slo_trend_fail_any.log
  exit 1
fi

echo "[prod-gate-slo-trend] fail-close on minimum GO rate"
set +e
./scripts/prod_gate_slo_trend.sh \
  --reports-dir "$REPORTS_DIR" \
  --max-reports 3 \
  --max-wg-soak-failed-rounds 0 \
  --min-go-rate-pct 70 \
  --show-details 0 >/tmp/integration_prod_gate_slo_trend_fail_rate.log 2>&1
fail_rate_rc=$?
set -e
if [[ "$fail_rate_rc" -eq 0 ]]; then
  echo "expected non-zero rc when GO rate is below --min-go-rate-pct"
  cat /tmp/integration_prod_gate_slo_trend_fail_rate.log
  exit 1
fi
if ! rg -q 'go_rate_pct=66.67' /tmp/integration_prod_gate_slo_trend_fail_rate.log; then
  echo "expected GO rate output not found"
  cat /tmp/integration_prod_gate_slo_trend_fail_rate.log
  exit 1
fi

echo "[prod-gate-slo-trend] easy_node forwarding"
FAKE_TREND="$TMP_DIR/fake_prod_gate_slo_trend.sh"
CAPTURE="$TMP_DIR/prod_gate_slo_trend_args.log"
cat >"$FAKE_TREND" <<'EOF_FAKE_TREND'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${CAPTURE_FILE:?}"
exit 0
EOF_FAKE_TREND
chmod +x "$FAKE_TREND"

CAPTURE_FILE="$CAPTURE" \
PROD_GATE_SLO_TREND_SCRIPT="$FAKE_TREND" \
./scripts/easy_node.sh prod-gate-slo-trend \
  --reports-dir /tmp/reports \
  --max-reports 10 \
  --since-hours 24 \
  --require-incident-snapshot-on-fail 1 \
  --require-incident-snapshot-artifacts 1 \
  --require-wg-validate-udp-source 1 \
  --require-wg-validate-strict-distinct 1 \
  --require-wg-soak-diversity-pass 1 \
  --min-wg-soak-selection-lines 8 \
  --min-wg-soak-entry-operators 2 \
  --min-wg-soak-exit-operators 2 \
  --min-wg-soak-cross-operator-pairs 1 \
  --summary-json /tmp/slo_trend.json \
  --print-summary-json 1 \
  --fail-on-any-no-go 1 \
  --min-go-rate-pct 95 \
  --show-top-reasons 7 >/tmp/integration_prod_gate_slo_trend_easy_node.log 2>&1

if ! rg -q -- '--reports-dir /tmp/reports' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --reports-dir"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--fail-on-any-no-go 1' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --fail-on-any-no-go"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-go-rate-pct 95' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --min-go-rate-pct"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--since-hours 24' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --since-hours"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-on-fail 1' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --require-incident-snapshot-on-fail"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-artifacts 1' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --require-incident-snapshot-artifacts"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-validate-udp-source 1' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --require-wg-validate-udp-source"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-validate-strict-distinct 1' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --require-wg-validate-strict-distinct"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-soak-diversity-pass 1' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --require-wg-soak-diversity-pass"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-selection-lines 8' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --min-wg-soak-selection-lines"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-entry-operators 2' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --min-wg-soak-entry-operators"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-exit-operators 2' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --min-wg-soak-exit-operators"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-cross-operator-pairs 1' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --min-wg-soak-cross-operator-pairs"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--summary-json /tmp/slo_trend.json' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --summary-json"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--print-summary-json 1' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --print-summary-json"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-top-reasons 7' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-trend forwarding failed: missing --show-top-reasons"
  cat "$CAPTURE"
  exit 1
fi

echo "prod gate slo trend integration ok"
