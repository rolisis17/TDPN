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

cat >"$OK_SUMMARY" <<'EOF_OK_SUMMARY'
{
  "go_rate_pct": 100,
  "no_go": 0,
  "evaluation_errors": 0,
  "reports_total": 8,
  "top_no_go_reasons": []
}
EOF_OK_SUMMARY

cat >"$WARN_SUMMARY" <<'EOF_WARN_SUMMARY'
{
  "go_rate_pct": 96.5,
  "no_go": 1,
  "evaluation_errors": 0,
  "reports_total": 10,
  "top_no_go_reasons": [
    {"count": 1, "reason": "wg_soak_rounds_failed exceeds limit"}
  ]
}
EOF_WARN_SUMMARY

cat >"$CRIT_SUMMARY" <<'EOF_CRIT_SUMMARY'
{
  "go_rate_pct": 84.2,
  "no_go": 3,
  "evaluation_errors": 2,
  "reports_total": 12,
  "top_no_go_reasons": [
    {"count": 2, "reason": "wg_soak_status is not ok"},
    {"count": 1, "reason": "preflight is not ok"}
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
if ! jq -e '.severity == "OK" and .metrics.reports_total == 8' "$TMP_DIR/alert_ok_out.json" >/dev/null 2>&1; then
  echo "alert OK summary JSON missing expected fields"
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
  "go_rate_pct": 99.2,
  "no_go": 0,
  "evaluation_errors": 0,
  "reports_total": 4,
  "top_no_go_reasons": []
}
EOF_TREND_SUMMARY
fi
exit 0
EOF_FAKE_TREND
chmod +x "$FAKE_TREND"

TREND_CAPTURE_FILE="$TREND_CAPTURE" \
PROD_GATE_SLO_TREND_SCRIPT="$FAKE_TREND" \
./scripts/prod_gate_slo_alert.sh \
  --reports-dir /tmp/prod_reports \
  --max-reports 7 \
  --since-hours 24 \
  --require-signoff-ok 1 \
  --require-incident-snapshot-on-fail 1 \
  --require-incident-snapshot-artifacts 1 \
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
