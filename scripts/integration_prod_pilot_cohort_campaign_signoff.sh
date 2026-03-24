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

SIGNOFF_CAPTURE="$TMP_DIR/signoff_capture.log"
SUMMARY_CAPTURE="$TMP_DIR/summary_capture.log"
CHECK_CAPTURE="$TMP_DIR/check_capture.log"
SIGNOFF_SUMMARY_PASS_JSON="$TMP_DIR/signoff_summary_pass.json"
SIGNOFF_SUMMARY_FAIL_JSON="$TMP_DIR/signoff_summary_fail.json"
SIGNOFF_CHECK_FAIL_JSON="$TMP_DIR/signoff_check_fail.json"

FAKE_SUMMARY="$TMP_DIR/fake_summary.sh"
cat >"$FAKE_SUMMARY" <<'EOF_FAKE_SUMMARY'
#!/usr/bin/env bash
set -euo pipefail
printf 'summary %s\n' "$*" >>"${SIGNOFF_CAPTURE_FILE:?}"
printf '%s\n' "$*" >>"${SUMMARY_CAPTURE_FILE:?}"
exit "${FAKE_SUMMARY_RC:-0}"
EOF_FAKE_SUMMARY
chmod +x "$FAKE_SUMMARY"

FAKE_CHECK="$TMP_DIR/fake_check.sh"
cat >"$FAKE_CHECK" <<'EOF_FAKE_CHECK'
#!/usr/bin/env bash
set -euo pipefail
printf 'check %s\n' "$*" >>"${SIGNOFF_CAPTURE_FILE:?}"
printf '%s\n' "$*" >>"${CHECK_CAPTURE_FILE:?}"
exit "${FAKE_CHECK_RC:-0}"
EOF_FAKE_CHECK
chmod +x "$FAKE_CHECK"

echo "[prod-pilot-cohort-campaign-signoff] orchestration success path"
: >"$SIGNOFF_CAPTURE"
: >"$SUMMARY_CAPTURE"
: >"$CHECK_CAPTURE"
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
SUMMARY_CAPTURE_FILE="$SUMMARY_CAPTURE" \
CHECK_CAPTURE_FILE="$CHECK_CAPTURE" \
FAKE_SUMMARY_RC=0 \
FAKE_CHECK_RC=0 \
PROD_PILOT_COHORT_CAMPAIGN_SUMMARY_SCRIPT="$FAKE_SUMMARY" \
PROD_PILOT_COHORT_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
./scripts/prod_pilot_cohort_campaign_signoff.sh \
  --runbook-summary-json /tmp/campaign/runbook_summary.json \
  --campaign-run-report-json /tmp/campaign/run_report.json \
  --campaign-summary-json /tmp/campaign/summary.json \
  --campaign-report-md /tmp/campaign/report.md \
  --campaign-signoff-summary-json /tmp/campaign/signoff_stage_summary.json \
  --reports-dir /tmp/campaign \
  --refresh-summary 1 \
  --summary-fail-on-no-go 1 \
  --require-status-ok 1 \
  --require-runbook-summary-json 1 \
  --require-quick-run-report-json 1 \
  --require-campaign-summary-go 1 \
  --require-campaign-signoff-attempted 0 \
  --require-campaign-signoff-enabled 0 \
  --require-campaign-signoff-required 0 \
  --require-campaign-signoff-ok 0 \
  --require-campaign-signoff-summary-json 0 \
  --require-campaign-signoff-summary-json-valid 0 \
  --require-campaign-signoff-summary-status-ok 0 \
  --require-campaign-signoff-summary-final-rc-zero 0 \
  --require-campaign-summary-fail-close 1 \
  --require-campaign-signoff-check 1 \
  --require-campaign-run-report-required 1 \
  --require-campaign-run-report-json-required 1 \
  --require-artifact-path-match 1 \
  --require-summary-policy-match 1 \
  --require-incident-policy-clean 1 \
  --require-incident-snapshot-on-fail 1 \
  --require-incident-snapshot-artifacts 1 \
  --incident-snapshot-min-attachment-count 2 \
  --incident-snapshot-max-skipped-count 0 \
  --summary-json "$SIGNOFF_SUMMARY_PASS_JSON" \
  --print-summary-json 0 \
  --show-json 1 >/tmp/integration_prod_pilot_cohort_campaign_signoff_pass.log 2>&1

if [[ ! -f "$SIGNOFF_SUMMARY_PASS_JSON" ]]; then
  echo "campaign-signoff should emit summary JSON on success path"
  exit 1
fi
if [[ "$(jq -r '.status // ""' "$SIGNOFF_SUMMARY_PASS_JSON")" != "ok" ]]; then
  echo "campaign-signoff success summary should report status=ok"
  cat "$SIGNOFF_SUMMARY_PASS_JSON"
  exit 1
fi
if [[ "$(jq -r '.final_rc // -1' "$SIGNOFF_SUMMARY_PASS_JSON")" != "0" ]]; then
  echo "campaign-signoff success summary should report final_rc=0"
  cat "$SIGNOFF_SUMMARY_PASS_JSON"
  exit 1
fi

first_stage="$(sed -n '1p' "$SIGNOFF_CAPTURE" || true)"
second_stage="$(sed -n '2p' "$SIGNOFF_CAPTURE" || true)"
if [[ "$first_stage" != summary* ]]; then
  echo "campaign-signoff should run summary before check when --refresh-summary=1"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if [[ "$second_stage" != check* ]]; then
  echo "campaign-signoff should run check after summary when --refresh-summary=1"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi

if ! rg -q -- '--runbook-summary-json /tmp/campaign/runbook_summary.json' "$SUMMARY_CAPTURE"; then
  echo "campaign-signoff summary forwarding missing --runbook-summary-json"
  cat "$SUMMARY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--reports-dir /tmp/campaign' "$SUMMARY_CAPTURE"; then
  echo "campaign-signoff summary forwarding missing --reports-dir"
  cat "$SUMMARY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--summary-json /tmp/campaign/summary.json' "$SUMMARY_CAPTURE"; then
  echo "campaign-signoff summary forwarding missing --summary-json"
  cat "$SUMMARY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--report-md /tmp/campaign/report.md' "$SUMMARY_CAPTURE"; then
  echo "campaign-signoff summary forwarding missing --report-md"
  cat "$SUMMARY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--fail-on-no-go 1' "$SUMMARY_CAPTURE"; then
  echo "campaign-signoff summary forwarding missing --fail-on-no-go"
  cat "$SUMMARY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-snapshot-min-attachment-count 2' "$SUMMARY_CAPTURE"; then
  echo "campaign-signoff summary forwarding missing --incident-snapshot-min-attachment-count"
  cat "$SUMMARY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--incident-snapshot-max-skipped-count 0' "$SUMMARY_CAPTURE"; then
  echo "campaign-signoff summary forwarding missing --incident-snapshot-max-skipped-count"
  cat "$SUMMARY_CAPTURE"
  exit 1
fi

if ! rg -q -- '--campaign-run-report-json /tmp/campaign/run_report.json' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --campaign-run-report-json"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--campaign-summary-json /tmp/campaign/summary.json' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --campaign-summary-json"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--campaign-report-md /tmp/campaign/report.md' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --campaign-report-md"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--reports-dir /tmp/campaign' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --reports-dir"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-summary-go 1' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --require-campaign-summary-go"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--campaign-signoff-summary-json /tmp/campaign/signoff_stage_summary.json' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --campaign-signoff-summary-json"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-attempted 0' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --require-campaign-signoff-attempted"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-enabled 0' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --require-campaign-signoff-enabled"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-required 0' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --require-campaign-signoff-required"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-ok 0' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --require-campaign-signoff-ok"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-summary-json 0' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --require-campaign-signoff-summary-json"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-summary-json-valid 0' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --require-campaign-signoff-summary-json-valid"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-summary-status-ok 0' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --require-campaign-signoff-summary-status-ok"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-summary-final-rc-zero 0' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --require-campaign-signoff-summary-final-rc-zero"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-summary-fail-close 1' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --require-campaign-summary-fail-close"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-check 1' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --require-campaign-signoff-check"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-run-report-required 1' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --require-campaign-run-report-required"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-run-report-json-required 1' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --require-campaign-run-report-json-required"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-artifact-path-match 1' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --require-artifact-path-match"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-runbook-summary-json 1' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --require-runbook-summary-json"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-quick-run-report-json 1' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --require-quick-run-report-json"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-summary-policy-match 1' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --require-summary-policy-match"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-policy-clean 1' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --require-incident-policy-clean"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-json 1' "$CHECK_CAPTURE"; then
  echo "campaign-signoff check forwarding missing --show-json"
  cat "$CHECK_CAPTURE"
  exit 1
fi

echo "[prod-pilot-cohort-campaign-signoff] fail-close when summary stage fails"
: >"$SIGNOFF_CAPTURE"
: >"$SUMMARY_CAPTURE"
: >"$CHECK_CAPTURE"
set +e
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
SUMMARY_CAPTURE_FILE="$SUMMARY_CAPTURE" \
CHECK_CAPTURE_FILE="$CHECK_CAPTURE" \
FAKE_SUMMARY_RC=17 \
FAKE_CHECK_RC=0 \
PROD_PILOT_COHORT_CAMPAIGN_SUMMARY_SCRIPT="$FAKE_SUMMARY" \
PROD_PILOT_COHORT_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
./scripts/prod_pilot_cohort_campaign_signoff.sh \
  --reports-dir /tmp/campaign \
  --refresh-summary 1 \
  --summary-json "$SIGNOFF_SUMMARY_FAIL_JSON" >/tmp/integration_prod_pilot_cohort_campaign_signoff_summary_fail.log 2>&1
summary_fail_rc=$?
set -e
if [[ "$summary_fail_rc" -ne 17 ]]; then
  echo "campaign-signoff should return summary stage rc on summary failure"
  cat /tmp/integration_prod_pilot_cohort_campaign_signoff_summary_fail.log
  exit 1
fi
if [[ -s "$CHECK_CAPTURE" ]]; then
  echo "campaign-signoff should not run check when summary stage fails"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if [[ ! -f "$SIGNOFF_SUMMARY_FAIL_JSON" ]]; then
  echo "campaign-signoff should emit summary JSON on summary-stage failure path"
  exit 1
fi
if [[ "$(jq -r '.failure_stage // ""' "$SIGNOFF_SUMMARY_FAIL_JSON")" != "campaign-summary" ]]; then
  echo "campaign-signoff summary failure artifact should report failure_stage=campaign-summary"
  cat "$SIGNOFF_SUMMARY_FAIL_JSON"
  exit 1
fi
if [[ "$(jq -r '.final_rc // -1' "$SIGNOFF_SUMMARY_FAIL_JSON")" != "17" ]]; then
  echo "campaign-signoff summary failure artifact should report final_rc=17"
  cat "$SIGNOFF_SUMMARY_FAIL_JSON"
  exit 1
fi

echo "[prod-pilot-cohort-campaign-signoff] fail-close when check stage fails"
: >"$SIGNOFF_CAPTURE"
: >"$SUMMARY_CAPTURE"
: >"$CHECK_CAPTURE"
set +e
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
SUMMARY_CAPTURE_FILE="$SUMMARY_CAPTURE" \
CHECK_CAPTURE_FILE="$CHECK_CAPTURE" \
FAKE_SUMMARY_RC=0 \
FAKE_CHECK_RC=19 \
PROD_PILOT_COHORT_CAMPAIGN_SUMMARY_SCRIPT="$FAKE_SUMMARY" \
PROD_PILOT_COHORT_CAMPAIGN_CHECK_SCRIPT="$FAKE_CHECK" \
./scripts/prod_pilot_cohort_campaign_signoff.sh \
  --reports-dir /tmp/campaign \
  --refresh-summary 0 \
  --summary-json "$SIGNOFF_CHECK_FAIL_JSON" >/tmp/integration_prod_pilot_cohort_campaign_signoff_check_fail.log 2>&1
check_fail_rc=$?
set -e
if [[ "$check_fail_rc" -ne 19 ]]; then
  echo "campaign-signoff should return check stage rc on check failure"
  cat /tmp/integration_prod_pilot_cohort_campaign_signoff_check_fail.log
  exit 1
fi
if [[ -s "$SUMMARY_CAPTURE" ]]; then
  echo "campaign-signoff should skip summary stage when --refresh-summary=0"
  cat "$SUMMARY_CAPTURE"
  exit 1
fi
if [[ ! -s "$CHECK_CAPTURE" ]]; then
  echo "campaign-signoff should run check stage when --refresh-summary=0"
  cat /tmp/integration_prod_pilot_cohort_campaign_signoff_check_fail.log
  exit 1
fi
if [[ ! -f "$SIGNOFF_CHECK_FAIL_JSON" ]]; then
  echo "campaign-signoff should emit summary JSON on check-stage failure path"
  exit 1
fi
if [[ "$(jq -r '.failure_stage // ""' "$SIGNOFF_CHECK_FAIL_JSON")" != "campaign-check" ]]; then
  echo "campaign-signoff check-failure summary artifact should report failure_stage=campaign-check"
  cat "$SIGNOFF_CHECK_FAIL_JSON"
  exit 1
fi
if [[ "$(jq -r '.final_rc // -1' "$SIGNOFF_CHECK_FAIL_JSON")" != "19" ]]; then
  echo "campaign-signoff check-failure summary artifact should report final_rc=19"
  cat "$SIGNOFF_CHECK_FAIL_JSON"
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

FAKE_SIGNOFF="$TMP_DIR/fake_signoff.sh"
SIGNOFF_FORWARD_CAPTURE="$TMP_DIR/signoff_forward_capture.log"
cat >"$FAKE_SIGNOFF" <<'EOF_FAKE_SIGNOFF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${SIGNOFF_FORWARD_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_SIGNOFF
chmod +x "$FAKE_SIGNOFF"

echo "[prod-pilot-cohort-campaign-signoff] easy_node command forwarding"
PATH="$TMP_BIN:$PATH" \
SIGNOFF_FORWARD_CAPTURE_FILE="$SIGNOFF_FORWARD_CAPTURE" \
PROD_PILOT_COHORT_CAMPAIGN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
./scripts/easy_node.sh prod-pilot-cohort-campaign-signoff \
  --runbook-summary-json /tmp/campaign/runbook_summary.json \
  --campaign-run-report-json /tmp/campaign/run_report.json \
  --campaign-summary-json /tmp/campaign/summary.json \
  --campaign-report-md /tmp/campaign/report.md \
  --campaign-signoff-summary-json /tmp/campaign/signoff_stage_summary.json \
  --reports-dir /tmp/campaign \
  --refresh-summary 1 \
  --summary-fail-on-no-go 1 \
  --require-campaign-signoff-attempted 0 \
  --require-campaign-signoff-enabled 0 \
  --require-campaign-signoff-required 0 \
  --require-campaign-signoff-ok 0 \
  --require-campaign-signoff-summary-json 0 \
  --require-campaign-signoff-summary-json-valid 0 \
  --require-campaign-signoff-summary-status-ok 0 \
  --require-campaign-signoff-summary-final-rc-zero 0 \
  --require-campaign-summary-fail-close 0 \
  --require-campaign-signoff-check 0 \
  --require-campaign-run-report-required 0 \
  --require-campaign-run-report-json-required 0 \
  --require-artifact-path-match 0 \
  --require-runbook-summary-json 0 \
  --require-quick-run-report-json 0 \
  --summary-json /tmp/campaign/signoff_summary.json \
  --print-summary-json 1 \
  --require-summary-policy-match 0 \
  --show-json 1 >/tmp/integration_prod_pilot_cohort_campaign_signoff_easy_node.log 2>&1

if ! rg -q -- '--runbook-summary-json /tmp/campaign/runbook_summary.json' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --runbook-summary-json"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--campaign-run-report-json /tmp/campaign/run_report.json' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --campaign-run-report-json"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--reports-dir /tmp/campaign' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --reports-dir"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--refresh-summary 1' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --refresh-summary"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--summary-fail-on-no-go 1' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --summary-fail-on-no-go"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--campaign-signoff-summary-json /tmp/campaign/signoff_stage_summary.json' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --campaign-signoff-summary-json"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-attempted 0' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --require-campaign-signoff-attempted"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-enabled 0' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --require-campaign-signoff-enabled"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-required 0' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --require-campaign-signoff-required"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-ok 0' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --require-campaign-signoff-ok"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-summary-json 0' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --require-campaign-signoff-summary-json"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-summary-json-valid 0' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --require-campaign-signoff-summary-json-valid"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-summary-status-ok 0' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --require-campaign-signoff-summary-status-ok"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-summary-final-rc-zero 0' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --require-campaign-signoff-summary-final-rc-zero"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-summary-fail-close 0' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --require-campaign-summary-fail-close"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-signoff-check 0' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --require-campaign-signoff-check"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-run-report-required 0' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --require-campaign-run-report-required"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-campaign-run-report-json-required 0' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --require-campaign-run-report-json-required"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-artifact-path-match 0' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --require-artifact-path-match"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-runbook-summary-json 0' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --require-runbook-summary-json"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-quick-run-report-json 0' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --require-quick-run-report-json"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--summary-json /tmp/campaign/signoff_summary.json' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --summary-json"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--print-summary-json 1' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --print-summary-json"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-summary-policy-match 0' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --require-summary-policy-match"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-json 1' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node campaign-signoff forwarding failed: missing --show-json"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi

echo "prod pilot cohort campaign signoff integration check ok"
