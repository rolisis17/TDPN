#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp jq rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
TMP_BIN="$TMP_DIR/bin"
mkdir -p "$TMP_BIN"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

FAKE_TREND="$TMP_DIR/fake_trend.sh"
FAKE_ALERT="$TMP_DIR/fake_alert.sh"
TREND_CAPTURE="$TMP_DIR/trend_args.log"
ALERT_CAPTURE="$TMP_DIR/alert_args.log"
DASHBOARD_MD="$TMP_DIR/dashboard.md"
TREND_JSON="$TMP_DIR/trend.json"
ALERT_JSON="$TMP_DIR/alert.json"

cat >"$FAKE_TREND" <<'EOF_FAKE_TREND'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${TREND_CAPTURE_FILE:?}"
summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -z "$summary_json" ]]; then
  echo "fake trend missing --summary-json"
  exit 2
fi
mkdir -p "$(dirname "$summary_json")"
cat >"$summary_json" <<'EOF_TREND_JSON'
{
  "version": 1,
  "generated_at_utc": "2026-03-10T00:00:00Z",
  "decision": "NO-GO",
  "reports_total": 8,
  "go": 6,
  "no_go": 2,
  "go_rate_pct": 75.00,
  "evaluation_errors": 1,
  "top_no_go_reasons": [
    {"count": 2, "reason": "wg soak failed rounds exceeded policy"},
    {"count": 1, "reason": "preflight status not ok"}
  ]
}
EOF_TREND_JSON
exit "${FAKE_TREND_RC:-0}"
EOF_FAKE_TREND
chmod +x "$FAKE_TREND"

cat >"$FAKE_ALERT" <<'EOF_FAKE_ALERT'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${ALERT_CAPTURE_FILE:?}"
summary_json=""
trend_summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --trend-summary-json)
      trend_summary_json="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -z "$summary_json" ]]; then
  echo "fake alert missing --summary-json"
  exit 2
fi
if [[ -z "$trend_summary_json" || ! -f "$trend_summary_json" ]]; then
  echo "fake alert missing readable --trend-summary-json"
  exit 2
fi
mkdir -p "$(dirname "$summary_json")"
cat >"$summary_json" <<'EOF_ALERT_JSON'
{
  "version": 1,
  "generated_at_utc": "2026-03-10T00:00:01Z",
  "severity": "WARN",
  "trigger_reasons": [
    "go_rate_pct 75 < warn_go_rate_pct 98",
    "no_go_count 2 >= warn_no_go_count 1"
  ]
}
EOF_ALERT_JSON
exit "${FAKE_ALERT_RC:-0}"
EOF_FAKE_ALERT
chmod +x "$FAKE_ALERT"

echo "[prod-gate-slo-dashboard] success path"
TREND_CAPTURE_FILE="$TREND_CAPTURE" \
ALERT_CAPTURE_FILE="$ALERT_CAPTURE" \
PROD_GATE_SLO_TREND_SCRIPT="$FAKE_TREND" \
PROD_GATE_SLO_ALERT_SCRIPT="$FAKE_ALERT" \
./scripts/prod_gate_slo_dashboard.sh \
  --reports-dir /tmp/prod_reports \
  --max-reports 10 \
  --since-hours 24 \
  --require-preflight-ok 1 \
  --require-signoff-ok 1 \
  --require-incident-snapshot-on-fail 1 \
  --require-incident-snapshot-artifacts 1 \
  --min-go-rate-pct 95 \
  --show-top-reasons 3 \
  --warn-go-rate-pct 98 \
  --critical-go-rate-pct 90 \
  --fail-on-warn 0 \
  --fail-on-critical 0 \
  --trend-summary-json "$TREND_JSON" \
  --alert-summary-json "$ALERT_JSON" \
  --dashboard-md "$DASHBOARD_MD" \
  --print-dashboard 0 \
  --print-summary-json 1 >/tmp/integration_prod_gate_slo_dashboard_success.log 2>&1

if [[ ! -s "$DASHBOARD_MD" ]]; then
  echo "dashboard markdown not generated"
  exit 1
fi
if ! rg -q 'Alert severity: WARN' "$DASHBOARD_MD"; then
  echo "dashboard missing alert severity line"
  cat "$DASHBOARD_MD"
  exit 1
fi
if ! rg -q 'count=2 reason=wg soak failed rounds exceeded policy' "$DASHBOARD_MD"; then
  echo "dashboard missing top no-go reason"
  cat "$DASHBOARD_MD"
  exit 1
fi
if ! rg -q -- '--require-preflight-ok 1' "$TREND_CAPTURE"; then
  echo "dashboard did not forward --require-preflight-ok to trend script"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-on-fail 1' "$TREND_CAPTURE"; then
  echo "dashboard did not forward --require-incident-snapshot-on-fail to trend script"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-artifacts 1' "$TREND_CAPTURE"; then
  echo "dashboard did not forward --require-incident-snapshot-artifacts to trend script"
  cat "$TREND_CAPTURE"
  exit 1
fi
if ! rg -q -- "--trend-summary-json $TREND_JSON" "$ALERT_CAPTURE"; then
  echo "dashboard did not forward trend summary path to alert script"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-on-fail 1' "$ALERT_CAPTURE"; then
  echo "dashboard did not forward --require-incident-snapshot-on-fail to alert script"
  cat "$ALERT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-artifacts 1' "$ALERT_CAPTURE"; then
  echo "dashboard did not forward --require-incident-snapshot-artifacts to alert script"
  cat "$ALERT_CAPTURE"
  exit 1
fi

echo "[prod-gate-slo-dashboard] return code: trend fail when alert succeeds"
set +e
TREND_CAPTURE_FILE="$TREND_CAPTURE" \
ALERT_CAPTURE_FILE="$ALERT_CAPTURE" \
FAKE_TREND_RC=1 \
FAKE_ALERT_RC=0 \
PROD_GATE_SLO_TREND_SCRIPT="$FAKE_TREND" \
PROD_GATE_SLO_ALERT_SCRIPT="$FAKE_ALERT" \
./scripts/prod_gate_slo_dashboard.sh \
  --reports-dir /tmp/prod_reports \
  --trend-summary-json "$TREND_JSON" \
  --alert-summary-json "$ALERT_JSON" \
  --dashboard-md "$DASHBOARD_MD" \
  --print-dashboard 0 >/tmp/integration_prod_gate_slo_dashboard_trend_fail.log 2>&1
rc=$?
set -e
if [[ "$rc" -ne 1 ]]; then
  echo "expected rc=1 when trend fails and alert succeeds; got rc=$rc"
  cat /tmp/integration_prod_gate_slo_dashboard_trend_fail.log
  exit 1
fi

echo "[prod-gate-slo-dashboard] return code: alert fail precedence"
set +e
TREND_CAPTURE_FILE="$TREND_CAPTURE" \
ALERT_CAPTURE_FILE="$ALERT_CAPTURE" \
FAKE_TREND_RC=1 \
FAKE_ALERT_RC=2 \
PROD_GATE_SLO_TREND_SCRIPT="$FAKE_TREND" \
PROD_GATE_SLO_ALERT_SCRIPT="$FAKE_ALERT" \
./scripts/prod_gate_slo_dashboard.sh \
  --reports-dir /tmp/prod_reports \
  --trend-summary-json "$TREND_JSON" \
  --alert-summary-json "$ALERT_JSON" \
  --dashboard-md "$DASHBOARD_MD" \
  --print-dashboard 0 >/tmp/integration_prod_gate_slo_dashboard_alert_fail.log 2>&1
rc=$?
set -e
if [[ "$rc" -ne 2 ]]; then
  echo "expected rc=2 when alert fails; got rc=$rc"
  cat /tmp/integration_prod_gate_slo_dashboard_alert_fail.log
  exit 1
fi

FAKE_EASY_NODE_DASHBOARD="$TMP_DIR/fake_easy_node_dashboard.sh"
EASY_NODE_DASHBOARD_CAPTURE="$TMP_DIR/easy_node_dashboard_args.log"
cat >"$FAKE_EASY_NODE_DASHBOARD" <<'EOF_FAKE_EASY_NODE_DASHBOARD'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${EASY_NODE_DASHBOARD_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_EASY_NODE_DASHBOARD
chmod +x "$FAKE_EASY_NODE_DASHBOARD"

cat >"$TMP_BIN/docker" <<'EOF_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "compose" && "${2:-}" == "version" ]]; then
  printf 'Docker Compose version vtest\n'
  exit 0
fi
if [[ "${1:-}" == "compose" ]]; then
  exit 0
fi
if [[ "${1:-}" == "--version" ]]; then
  printf 'Docker version test\n'
  exit 0
fi
if [[ "${1:-}" == "info" ]]; then
  exit 0
fi
exit 0
EOF_DOCKER
chmod +x "$TMP_BIN/docker"

echo "[prod-gate-slo-dashboard] easy-node forwarding"
PATH="$TMP_BIN:$PATH" \
EASY_NODE_DASHBOARD_CAPTURE_FILE="$EASY_NODE_DASHBOARD_CAPTURE" \
PROD_GATE_SLO_DASHBOARD_SCRIPT="$FAKE_EASY_NODE_DASHBOARD" \
./scripts/easy_node.sh prod-gate-slo-dashboard \
  --reports-dir /tmp/prod_reports \
  --since-hours 12 \
  --require-incident-snapshot-on-fail 1 \
  --require-incident-snapshot-artifacts 1 \
  --dashboard-md /tmp/prod_dashboard.md >/tmp/integration_prod_gate_slo_dashboard_easy_node.log 2>&1

if ! rg -q -- '--reports-dir /tmp/prod_reports' "$EASY_NODE_DASHBOARD_CAPTURE"; then
  echo "easy-node prod-gate-slo-dashboard forwarding missing --reports-dir"
  cat "$EASY_NODE_DASHBOARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--since-hours 12' "$EASY_NODE_DASHBOARD_CAPTURE"; then
  echo "easy-node prod-gate-slo-dashboard forwarding missing --since-hours"
  cat "$EASY_NODE_DASHBOARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-on-fail 1' "$EASY_NODE_DASHBOARD_CAPTURE"; then
  echo "easy-node prod-gate-slo-dashboard forwarding missing --require-incident-snapshot-on-fail"
  cat "$EASY_NODE_DASHBOARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-artifacts 1' "$EASY_NODE_DASHBOARD_CAPTURE"; then
  echo "easy-node prod-gate-slo-dashboard forwarding missing --require-incident-snapshot-artifacts"
  cat "$EASY_NODE_DASHBOARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--dashboard-md /tmp/prod_dashboard.md' "$EASY_NODE_DASHBOARD_CAPTURE"; then
  echo "easy-node prod-gate-slo-dashboard forwarding missing --dashboard-md"
  cat "$EASY_NODE_DASHBOARD_CAPTURE"
  exit 1
fi

echo "prod gate slo dashboard integration check ok"
