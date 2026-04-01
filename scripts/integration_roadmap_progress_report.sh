#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq mktemp rg chmod; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.log"
SINGLE_MACHINE_SUMMARY_JSON="$TMP_DIR/single_machine_prod_readiness_latest.json"

FAKE_MANUAL="$TMP_DIR/fake_manual_validation_report.sh"
cat >"$FAKE_MANUAL" <<'EOF_FAKE_MANUAL'
#!/usr/bin/env bash
set -euo pipefail
printf 'manual-validation-report %s\n' "$*" >>"${FAKE_ROADMAP_CAPTURE_FILE:?}"
summary_json=""
report_md=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --report-md)
      report_md="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" || -z "$report_md" ]]; then
  echo "missing summary/report args" >&2
  exit 1
fi
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"

cat >"$summary_json" <<'EOF_SUMMARY'
{
  "version": 1,
  "checks": [
    {
      "check_id": "runtime_hygiene",
      "label": "Runtime hygiene",
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh runtime-doctor --show-json 1"
    },
    {
      "check_id": "wg_only_stack_selftest",
      "label": "WG-only stack selftest",
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh wg-only-stack-selftest-record --strict-beta 1 --print-summary-json 1"
    },
    {
      "check_id": "three_machine_docker_readiness",
      "label": "One-host docker 3-machine rehearsal",
      "status": "pass",
      "command": "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"
    },
    {
      "check_id": "real_wg_privileged_matrix",
      "label": "Linux root real-WG privileged matrix",
      "status": "skip",
      "command": "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"
    },
    {
      "check_id": "machine_c_vpn_smoke",
      "label": "Machine C VPN smoke test",
      "status": "pending",
      "command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
    },
    {
      "check_id": "three_machine_prod_signoff",
      "label": "True 3-machine production signoff",
      "status": "pending",
      "command": "sudo ./scripts/easy_node.sh three-machine-prod-signoff --bundle-dir .easy-node-logs/prod_gate_bundle --directory-a https://A_HOST:8081 --directory-b https://B_HOST:8081 --issuer-url https://A_HOST:8082 --entry-url https://A_HOST:8083 --exit-url https://A_HOST:8084 --pre-real-host-readiness 1 --runtime-fix 1 --print-summary-json 1"
    }
  ],
  "summary": {
    "total_checks": 6,
    "pass_checks": 3,
    "warn_checks": 0,
    "fail_checks": 0,
    "pending_checks": 2,
    "next_action_check_id": "machine_c_vpn_smoke",
    "next_action_label": "Machine C VPN smoke test",
    "next_action_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country",
    "blocking_check_ids": ["machine_c_vpn_smoke", "three_machine_prod_signoff"],
    "optional_check_ids": ["three_machine_docker_readiness", "real_wg_privileged_matrix"],
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "single_machine_ready": true,
    "pre_machine_c_gate": {
      "ready": true,
      "next_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
    },
    "real_host_gate": {
      "ready": false,
      "blockers": ["machine_c_vpn_smoke", "three_machine_prod_signoff"],
      "next_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
    },
    "profile_default_gate": {
      "status": "pending",
      "next_command": "sudo ./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --refresh-campaign 1 --fail-on-no-go 1 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1"
    },
    "docker_rehearsal_gate": {
      "status": "pass",
      "next_command": "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"
    },
    "real_wg_privileged_gate": {
      "status": "skip",
      "next_command": "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"
    }
  },
  "report": {
    "readiness_status": "NOT_READY",
    "ready": false
  }
}
EOF_SUMMARY

printf '# fake manual validation report\n' >"$report_md"
EOF_FAKE_MANUAL
chmod +x "$FAKE_MANUAL"

FAKE_SINGLE="$TMP_DIR/fake_single_machine_prod_readiness.sh"
cat >"$FAKE_SINGLE" <<'EOF_FAKE_SINGLE'
#!/usr/bin/env bash
set -euo pipefail
printf 'single-machine-prod-readiness %s\n' "$*" >>"${FAKE_ROADMAP_CAPTURE_FILE:?}"
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
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  printf '{"status":"warn"}\n' >"$summary_json"
fi
if [[ "${FAKE_SINGLE_SLEEP_SEC:-0}" =~ ^[0-9]+$ ]] && [[ "${FAKE_SINGLE_SLEEP_SEC:-0}" -gt 0 ]]; then
  sleep "${FAKE_SINGLE_SLEEP_SEC}"
fi
if [[ "${FAKE_SINGLE_FAIL:-0}" == "1" ]]; then
  exit 1
fi
exit 0
EOF_FAKE_SINGLE
chmod +x "$FAKE_SINGLE"

echo "[roadmap-progress-report] success path"
SUMMARY_JSON="$TMP_DIR/roadmap_progress_summary.json"
REPORT_MD="$TMP_DIR/roadmap_progress_report.md"
FAKE_ROADMAP_CAPTURE_FILE="$CAPTURE" \
ROADMAP_PROGRESS_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL" \
ROADMAP_PROGRESS_SINGLE_MACHINE_SCRIPT="$FAKE_SINGLE" \
./scripts/roadmap_progress_report.sh \
  --refresh-manual-validation 1 \
  --refresh-single-machine-readiness 0 \
  --single-machine-summary-json "$SINGLE_MACHINE_SUMMARY_JSON" \
  --summary-json "$SUMMARY_JSON" \
  --report-md "$REPORT_MD" \
  --print-report 0 \
  --print-summary-json 1 >/tmp/integration_roadmap_progress_report_ok.log 2>&1

if ! rg -q '\[roadmap-progress-report\] status=warn rc=0' /tmp/integration_roadmap_progress_report_ok.log; then
  echo "expected warn status in success path"
  cat /tmp/integration_roadmap_progress_report_ok.log
  exit 1
fi
if [[ ! -f "$SUMMARY_JSON" || ! -f "$REPORT_MD" ]]; then
  echo "expected roadmap progress artifacts missing"
  ls -la "$TMP_DIR"
  exit 1
fi
if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .vpn_track.readiness_status == "NOT_READY"
  and .vpn_track.roadmap_stage == "READY_FOR_MACHINE_C_SMOKE"
  and .vpn_track.vpn_rc_done_for_phase == true
  and (.vpn_track.pending_real_host_checks | length) == 2
  and .vpn_track.pending_real_host_checks[0].check_id == "machine_c_vpn_smoke"
  and .vpn_track.pending_real_host_checks[1].check_id == "three_machine_prod_signoff"
  and .blockchain_track.status == "deferred"
  and (.next_actions | length) >= 1
  and .refresh.manual_validation_report.status == "pass"
  and .refresh.manual_validation_report.timed_out == false
  and (.refresh.manual_validation_report.duration_sec >= 0)
  and .refresh.single_machine_prod_readiness.status == "skip"
  and .refresh.single_machine_prod_readiness.timed_out == false
  and (.refresh.single_machine_prod_readiness.duration_sec >= 0)
' "$SUMMARY_JSON" >/dev/null; then
  echo "summary JSON missing expected fields"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] refresh_step=manual_validation_report status=running' /tmp/integration_roadmap_progress_report_ok.log; then
  echo "expected manual refresh running heartbeat line"
  cat /tmp/integration_roadmap_progress_report_ok.log
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] refresh_step=manual_validation_report status=pass rc=0 timed_out=false' /tmp/integration_roadmap_progress_report_ok.log; then
  echo "expected manual refresh completion heartbeat line"
  cat /tmp/integration_roadmap_progress_report_ok.log
  exit 1
fi
if ! rg -q 'manual-validation-report --profile-compare-signoff-summary-json' "$CAPTURE"; then
  echo "expected manual-validation-report refresh call missing"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^## Pending Real-Host Checks$' "$REPORT_MD"; then
  echo "report markdown missing pending real-host checks section"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'VPN RC done for phase: `true`' "$REPORT_MD"; then
  echo "report markdown missing VPN RC done signal"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Pending real-host checks: machine_c_vpn_smoke,three_machine_prod_signoff' "$REPORT_MD"; then
  echo "report markdown missing pending real-host check list"
  cat "$REPORT_MD"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] partial manual summary schema path"
MINIMAL_MANUAL_SUMMARY_JSON="$TMP_DIR/manual_validation_minimal_summary.json"
cat >"$MINIMAL_MANUAL_SUMMARY_JSON" <<'EOF_MINIMAL_SUMMARY'
{"version":1,"summary":{"next_action_check_id":"machine_c_vpn_smoke"},"report":{"readiness_status":"NOT_READY"}}
EOF_MINIMAL_SUMMARY
if ! ./scripts/roadmap_progress_report.sh \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_minimal_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_minimal_report.md" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_report_minimal.log 2>&1; then
  echo "expected success when manual-validation summary has partial schema"
  cat /tmp/integration_roadmap_progress_report_minimal.log
  exit 1
fi
if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .vpn_track.readiness_status == "NOT_READY"
  and (.vpn_track.pending_real_host_checks | length) == 0
  and (.vpn_track.blocking_check_ids | length) == 0
' "$TMP_DIR/roadmap_progress_minimal_summary.json" >/dev/null; then
  echo "minimal-schema summary JSON missing expected fallback fields"
  cat "$TMP_DIR/roadmap_progress_minimal_summary.json"
  exit 1
fi

echo "[roadmap-progress-report] next action fallback from checks path"
FALLBACK_MANUAL_SUMMARY_JSON="$TMP_DIR/manual_validation_fallback_summary.json"
cat >"$FALLBACK_MANUAL_SUMMARY_JSON" <<'EOF_FALLBACK_SUMMARY'
{
  "version": 1,
  "checks": [
    {
      "check_id": "machine_c_vpn_smoke",
      "label": "Machine C VPN smoke test",
      "status": "pending",
      "command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
    }
  ],
  "summary": {
    "next_action_check_id": "machine_c_vpn_smoke",
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "single_machine_ready": true,
    "blocking_check_ids": ["machine_c_vpn_smoke"],
    "optional_check_ids": []
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_FALLBACK_SUMMARY
if ! ./scripts/roadmap_progress_report.sh \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$FALLBACK_MANUAL_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_fallback_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_fallback_report.md" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_report_fallback.log 2>&1; then
  echo "expected success when next_action_command is inferred from checks"
  cat /tmp/integration_roadmap_progress_report_fallback.log
  exit 1
fi
if ! jq -e '
  .vpn_track.next_action.check_id == "machine_c_vpn_smoke"
  and .vpn_track.next_action.command == "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
  and ((.next_actions // []) | any(.id == "machine_c_vpn_smoke"))
' "$TMP_DIR/roadmap_progress_fallback_summary.json" >/dev/null; then
  echo "fallback summary JSON missing inferred next action command"
  cat "$TMP_DIR/roadmap_progress_fallback_summary.json"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] single-machine refresh failure path"
if env \
  FAKE_ROADMAP_CAPTURE_FILE="$CAPTURE" \
  FAKE_SINGLE_FAIL=1 \
  ROADMAP_PROGRESS_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL" \
  ROADMAP_PROGRESS_SINGLE_MACHINE_SCRIPT="$FAKE_SINGLE" \
  ./scripts/roadmap_progress_report.sh \
    --refresh-manual-validation 1 \
    --refresh-single-machine-readiness 1 \
    --single-machine-summary-json "$SINGLE_MACHINE_SUMMARY_JSON" \
    --summary-json "$TMP_DIR/roadmap_progress_fail_summary.json" \
    --report-md "$TMP_DIR/roadmap_progress_fail_report.md" \
    --print-report 0 \
    --print-summary-json 0 >/tmp/integration_roadmap_progress_report_fail.log 2>&1; then
  echo "expected failure when single-machine refresh fails"
  cat /tmp/integration_roadmap_progress_report_fail.log
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] status=fail rc=1' /tmp/integration_roadmap_progress_report_fail.log; then
  echo "expected fail status when single-machine refresh fails"
  cat /tmp/integration_roadmap_progress_report_fail.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .refresh.single_machine_prod_readiness.status == "fail"
  and .refresh.single_machine_prod_readiness.rc == 1
  and .refresh.single_machine_prod_readiness.timed_out == false
' "$TMP_DIR/roadmap_progress_fail_summary.json" >/dev/null; then
  echo "failure summary JSON missing expected fields"
  cat "$TMP_DIR/roadmap_progress_fail_summary.json"
  exit 1
fi

: >"$CAPTURE"

if command -v timeout >/dev/null 2>&1; then
  echo "[roadmap-progress-report] single-machine refresh timeout path"
  if env \
    FAKE_ROADMAP_CAPTURE_FILE="$CAPTURE" \
    FAKE_SINGLE_SLEEP_SEC=3 \
    ROADMAP_PROGRESS_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL" \
    ROADMAP_PROGRESS_SINGLE_MACHINE_SCRIPT="$FAKE_SINGLE" \
    ./scripts/roadmap_progress_report.sh \
      --refresh-manual-validation 0 \
      --refresh-single-machine-readiness 1 \
      --single-machine-refresh-timeout-sec 1 \
      --single-machine-summary-json "$SINGLE_MACHINE_SUMMARY_JSON" \
      --summary-json "$TMP_DIR/roadmap_progress_timeout_summary.json" \
      --report-md "$TMP_DIR/roadmap_progress_timeout_report.md" \
      --print-report 0 \
      --print-summary-json 0 >/tmp/integration_roadmap_progress_report_timeout.log 2>&1; then
    echo "expected failure when single-machine refresh times out"
    cat /tmp/integration_roadmap_progress_report_timeout.log
    exit 1
  fi
  if ! rg -q '\[roadmap-progress-report\] refresh_step=single_machine_prod_readiness status=running timeout_sec=1' /tmp/integration_roadmap_progress_report_timeout.log; then
    echo "timeout path missing running heartbeat line"
    cat /tmp/integration_roadmap_progress_report_timeout.log
    exit 1
  fi
  if ! rg -q '\[roadmap-progress-report\] refresh_step=single_machine_prod_readiness status=fail rc=124 timed_out=true' /tmp/integration_roadmap_progress_report_timeout.log; then
    echo "timeout path missing timeout completion heartbeat line"
    cat /tmp/integration_roadmap_progress_report_timeout.log
    exit 1
  fi
  if ! jq -e '
    .status == "fail"
    and .rc == 1
    and .notes == "One or more requested refresh steps timed out; inspect refresh logs."
    and .refresh.single_machine_prod_readiness.status == "fail"
    and .refresh.single_machine_prod_readiness.rc == 124
    and .refresh.single_machine_prod_readiness.timed_out == true
    and .refresh.single_machine_prod_readiness.timeout_sec == 1
    and (.refresh.single_machine_prod_readiness.duration_sec >= 1)
  ' "$TMP_DIR/roadmap_progress_timeout_summary.json" >/dev/null; then
    echo "timeout summary JSON missing expected timeout fields"
    cat "$TMP_DIR/roadmap_progress_timeout_summary.json"
    exit 1
  fi
fi

: >"$CAPTURE"

FAKE_FORWARD="$TMP_DIR/fake_roadmap_progress_forward.sh"
cat >"$FAKE_FORWARD" <<'EOF_FAKE_FORWARD'
#!/usr/bin/env bash
set -euo pipefail
printf 'roadmap-progress-report %s\n' "$*" >>"${FORWARD_CAPTURE_FILE:?}"
EOF_FAKE_FORWARD
chmod +x "$FAKE_FORWARD"

echo "[roadmap-progress-report] easy_node forwarding"
FORWARD_CAPTURE_FILE="$CAPTURE" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_FORWARD" \
./scripts/easy_node.sh roadmap-progress-report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 1 \
  --summary-json /tmp/roadmap_progress.json \
  --print-summary-json 1 >/tmp/integration_roadmap_progress_report_forward.log 2>&1

forward_line="$(rg '^roadmap-progress-report ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$forward_line" ]]; then
  echo "missing roadmap-progress-report forward capture"
  cat "$CAPTURE"
  exit 1
fi
for expected in '--refresh-manual-validation 0' '--refresh-single-machine-readiness 1' '--summary-json /tmp/roadmap_progress.json' '--print-summary-json 1'; do
  if [[ "$forward_line" != *"$expected"* ]]; then
    echo "forwarded command missing expected fragment: $expected"
    echo "$forward_line"
    exit 1
  fi
done

echo "roadmap progress report integration check ok"
