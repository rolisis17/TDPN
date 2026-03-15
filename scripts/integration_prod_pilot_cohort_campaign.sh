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
TMP_BIN="$TMP_DIR/bin"
mkdir -p "$TMP_BIN"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

FAKE_EASY_NODE="$TMP_DIR/fake_easy_node.sh"
CAPTURE="$TMP_DIR/prod_pilot_cohort_campaign_args.log"

cat >"$FAKE_EASY_NODE" <<'EOF_FAKE_EASY_NODE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${CAPTURE_FILE:?}"
if [[ "${1:-}" == "prod-pilot-cohort-quick-runbook" ]]; then
  reports_dir=""
  summary_json=""
  run_report_json=""
  signoff_json=""
  trend_summary_json=""
  alert_summary_json=""
  dashboard_md=""
  args=("$@")
  idx=0
  while ((idx < ${#args[@]})); do
    arg="${args[idx]}"
    case "$arg" in
      --reports-dir)
        idx=$((idx + 1))
        reports_dir="${args[idx]}"
        ;;
      --summary-json)
        idx=$((idx + 1))
        summary_json="${args[idx]}"
        ;;
      --run-report-json)
        idx=$((idx + 1))
        run_report_json="${args[idx]}"
        ;;
      --signoff-json)
        idx=$((idx + 1))
        signoff_json="${args[idx]}"
        ;;
      --trend-summary-json)
        idx=$((idx + 1))
        trend_summary_json="${args[idx]}"
        ;;
      --alert-summary-json)
        idx=$((idx + 1))
        alert_summary_json="${args[idx]}"
        ;;
      --dashboard-md)
        idx=$((idx + 1))
        dashboard_md="${args[idx]}"
        ;;
    esac
    idx=$((idx + 1))
  done
  signoff_status="ok"
  signoff_failure_step=""
  signoff_rc="0"
  trend_decision="GO"
  trend_go_rate_pct="100.00"
  trend_no_go="0"
  trend_reason=""
  if [[ "${FAKE_NO_GO:-0}" == "1" ]]; then
    signoff_status="fail"
    signoff_failure_step="synthetic_policy"
    signoff_rc="9"
    trend_decision="NO-GO"
    trend_go_rate_pct="83.33"
    trend_no_go="1"
    trend_reason="synthetic no-go"
  fi
  mkdir -p "$reports_dir"
  cat >"$run_report_json" <<EOF_RUN_REPORT
{"status":"ok","failure_step":"","final_rc":0,"signoff":{"attempted":true,"rc":0},"config":{"bootstrap_directory":"https://dir-a:8081","subject":"pilot-client"}}
EOF_RUN_REPORT
  cat >"$summary_json" <<EOF_SUMMARY
{"status":"ok","final_rc":0,"rounds":{"requested":6,"attempted":6,"passed":6,"failed":0},"bundle":{"created":true,"manifest_created":true},"artifacts":{"bundle_tar":"$reports_dir/prod_pilot_cohort_bundle.tar.gz","bundle_manifest_json":"$reports_dir/prod_pilot_cohort_bundle_manifest.json"}}
EOF_SUMMARY
  touch "$reports_dir/prod_pilot_cohort_bundle.tar.gz" "$reports_dir/prod_pilot_cohort_bundle_manifest.json"
  cat >"$signoff_json" <<EOF_SIGNOFF
{"status":"$signoff_status","failure_step":"$signoff_failure_step","final_rc":$signoff_rc,"observed":{"alert_severity":"WARN"}}
EOF_SIGNOFF
  cat >"$trend_summary_json" <<EOF_TREND
{"decision":"$trend_decision","go_rate_pct":$trend_go_rate_pct,"no_go":$trend_no_go,"evaluation_errors":0,"top_no_go_reasons":[{"reason":"$trend_reason"}]}
EOF_TREND
  cat >"$alert_summary_json" <<'EOF_ALERT'
{"severity":"WARN","trigger_reasons":["no_go_count 0 >= warn_no_go_count 0"]}
EOF_ALERT
  printf '# dashboard\n' >"$dashboard_md"
  cat >"$reports_dir/prod_pilot_cohort_quick_runbook_summary.json" <<EOF_RUNBOOK
{"status":"ok","failure_step":"","final_rc":0,"duration_sec":42,"stages":{"quick":{"rc":0},"quick_signoff":{"rc":0},"quick_dashboard":{"rc":0}},"config":{"rounds":6,"pause_sec":45,"max_alert_severity":"WARN"},"artifacts":{"reports_dir":"$reports_dir","summary_json":"$summary_json","run_report_json":"$run_report_json","signoff_json":"$signoff_json","trend_summary_json":"$trend_summary_json","alert_summary_json":"$alert_summary_json","dashboard_md":"$dashboard_md"}}
EOF_RUNBOOK
fi
exit 0
EOF_FAKE_EASY_NODE
chmod +x "$FAKE_EASY_NODE"

echo "[prod-pilot-cohort-campaign] wrapper defaults + forwarding"
WRAPPER_REPORTS_DIR="$TMP_DIR/wrapper_reports"
CAPTURE_FILE="$CAPTURE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
./scripts/prod_pilot_cohort_campaign.sh \
  --bootstrap-directory https://dir-a:8081 \
  --subject pilot-client \
  --reports-dir "$WRAPPER_REPORTS_DIR" \
  --rounds 7 \
  --bundle-fail-close 0 >/tmp/integration_prod_pilot_cohort_campaign_wrapper.log 2>&1

line="$(sed -n '1p' "$CAPTURE")"
if [[ -z "$line" ]]; then
  echo "prod-pilot-cohort-campaign wrapper did not dispatch"
  cat "$CAPTURE"
  exit 1
fi

if ! printf '%s\n' "$line" | rg -q -- '^prod-pilot-cohort-quick-runbook'; then
  echo "campaign wrapper did not dispatch prod-pilot-cohort-quick-runbook"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--continue-on-fail 1'; then
  echo "campaign wrapper missing default --continue-on-fail 1"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--require-all-rounds-ok 1'; then
  echo "campaign wrapper missing default --require-all-rounds-ok 1"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--max-round-failures 0'; then
  echo "campaign wrapper missing default --max-round-failures 0"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--trend-min-go-rate-pct 95'; then
  echo "campaign wrapper missing default --trend-min-go-rate-pct 95"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--max-alert-severity WARN'; then
  echo "campaign wrapper missing default --max-alert-severity WARN"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--bundle-outputs 1'; then
  echo "campaign wrapper missing default --bundle-outputs 1"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--pre-real-host-readiness 1'; then
  echo "campaign wrapper missing default --pre-real-host-readiness 1"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- "--pre-real-host-readiness-summary-json ${WRAPPER_REPORTS_DIR}/pre_real_host_readiness_summary.json"; then
  echo "campaign wrapper missing derived pre-real-host readiness summary path"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--signoff-require-cohort-signoff-policy 1'; then
  echo "campaign wrapper missing default --signoff-require-cohort-signoff-policy 1"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--signoff-require-trend-artifact-policy-match 1'; then
  echo "campaign wrapper missing default strict trend artifact policy"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--signoff-require-trend-wg-validate-udp-source 1'; then
  echo "campaign wrapper missing default strict udp-source policy"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--signoff-require-trend-wg-validate-strict-distinct 1'; then
  echo "campaign wrapper missing default strict distinct policy"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--signoff-require-trend-wg-soak-diversity-pass 1'; then
  echo "campaign wrapper missing default strict soak-diversity policy"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--signoff-min-trend-wg-soak-selection-lines 12'; then
  echo "campaign wrapper missing default selection-lines floor"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--signoff-min-trend-wg-soak-entry-operators 2'; then
  echo "campaign wrapper missing default entry-operator floor"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--signoff-min-trend-wg-soak-exit-operators 2'; then
  echo "campaign wrapper missing default exit-operator floor"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--signoff-min-trend-wg-soak-cross-operator-pairs 2'; then
  echo "campaign wrapper missing default cross-operator floor"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--dashboard-enable 1'; then
  echo "campaign wrapper missing default --dashboard-enable 1"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--dashboard-fail-close 0'; then
  echo "campaign wrapper missing default --dashboard-fail-close 0"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--bootstrap-directory https://dir-a:8081'; then
  echo "campaign wrapper missing forwarded --bootstrap-directory"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--subject pilot-client'; then
  echo "campaign wrapper missing forwarded --subject"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--rounds 7'; then
  echo "campaign wrapper missing caller override --rounds 7"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--bundle-fail-close 0'; then
  echo "campaign wrapper missing caller override --bundle-fail-close 0"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--reports-dir '; then
  echo "campaign wrapper missing derived --reports-dir"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--run-report-json '; then
  echo "campaign wrapper missing derived --run-report-json"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$line" | rg -q -- '--dashboard-md '; then
  echo "campaign wrapper missing derived --dashboard-md"
  cat "$CAPTURE"
  exit 1
fi

report_path="$(sed -nE 's/^\[prod-pilot-cohort-campaign\] campaign_report_md=(.*)$/\1/p' /tmp/integration_prod_pilot_cohort_campaign_wrapper.log | tail -n 1 || true)"
summary_path="$(sed -nE 's/^\[prod-pilot-cohort-campaign\] campaign_summary_json=(.*)$/\1/p' /tmp/integration_prod_pilot_cohort_campaign_wrapper.log | tail -n 1 || true)"
if [[ -z "$summary_path" || ! -f "$summary_path" ]]; then
  echo "campaign wrapper missing campaign_summary_json artifact"
  cat /tmp/integration_prod_pilot_cohort_campaign_wrapper.log
  exit 1
fi
if [[ -z "$report_path" || ! -f "$report_path" ]]; then
  echo "campaign wrapper missing campaign_report_md artifact"
  cat /tmp/integration_prod_pilot_cohort_campaign_wrapper.log
  exit 1
fi
if [[ "$(jq -r '.decision' "$summary_path")" != "GO" ]]; then
  echo "campaign wrapper generated unexpected campaign decision"
  cat "$summary_path"
  exit 1
fi
if ! rg -q -- '- Decision: GO' "$report_path"; then
  echo "campaign wrapper markdown report missing GO decision"
  cat "$report_path"
  exit 1
fi

echo "[prod-pilot-cohort-campaign] summary fail-close"
NOGO_REPORTS_DIR="$TMP_DIR/wrapper_reports_nogo"
set +e
CAPTURE_FILE="$CAPTURE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
FAKE_NO_GO=1 \
./scripts/prod_pilot_cohort_campaign.sh \
  --bootstrap-directory https://dir-a:8081 \
  --subject pilot-client \
  --reports-dir "$NOGO_REPORTS_DIR" \
  --campaign-print-report 0 \
  --campaign-summary-fail-close 1 >/tmp/integration_prod_pilot_cohort_campaign_nogo.log 2>&1
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
  echo "campaign wrapper should fail closed when campaign summary is NO-GO"
  cat /tmp/integration_prod_pilot_cohort_campaign_nogo.log
  exit 1
fi
if [[ ! -f "$NOGO_REPORTS_DIR/prod_pilot_campaign_summary.json" ]]; then
  echo "campaign wrapper missing NO-GO summary artifact"
  cat /tmp/integration_prod_pilot_cohort_campaign_nogo.log
  exit 1
fi
if [[ "$(jq -r '.decision' "$NOGO_REPORTS_DIR/prod_pilot_campaign_summary.json")" != "NO-GO" ]]; then
  echo "campaign wrapper should emit NO-GO summary artifact when failing closed"
  cat "$NOGO_REPORTS_DIR/prod_pilot_campaign_summary.json"
  exit 1
fi

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

FAKE_CAMPAIGN="$TMP_DIR/fake_prod_pilot_cohort_campaign.sh"
DISPATCH_CAPTURE="$TMP_DIR/prod_pilot_cohort_campaign_dispatch.log"
cat >"$FAKE_CAMPAIGN" <<'EOF_FAKE_CAMPAIGN'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${DISPATCH_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_CAMPAIGN
chmod +x "$FAKE_CAMPAIGN"

echo "[prod-pilot-cohort-campaign] easy-node command dispatch"
PATH="$TMP_BIN:$PATH" \
DISPATCH_CAPTURE_FILE="$DISPATCH_CAPTURE" \
PROD_PILOT_COHORT_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
./scripts/easy_node.sh prod-pilot-cohort-campaign --bootstrap-directory https://dir-b:8081 --pre-real-host-readiness 0 --pre-real-host-readiness-summary-json /tmp/campaign_pre_real_host.json --campaign-summary-fail-close 0 >/tmp/integration_prod_pilot_cohort_campaign_dispatch.log 2>&1

if ! rg -q -- '--bootstrap-directory https://dir-b:8081' "$DISPATCH_CAPTURE"; then
  echo "easy-node prod-pilot-cohort-campaign did not forward command arguments"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--pre-real-host-readiness 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node prod-pilot-cohort-campaign did not forward --pre-real-host-readiness"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--pre-real-host-readiness-summary-json /tmp/campaign_pre_real_host.json' "$DISPATCH_CAPTURE"; then
  echo "easy-node prod-pilot-cohort-campaign did not forward --pre-real-host-readiness-summary-json"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--campaign-summary-fail-close 0' /tmp/integration_prod_pilot_cohort_campaign_dispatch.log && ! rg -q -- '--campaign-summary-fail-close 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node prod-pilot-cohort-campaign lost wrapper-only command arguments"
  cat /tmp/integration_prod_pilot_cohort_campaign_dispatch.log
  cat "$DISPATCH_CAPTURE"
  exit 1
fi

echo "prod pilot cohort campaign integration check ok"
