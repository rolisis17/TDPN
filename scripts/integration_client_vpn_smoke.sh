#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp rg chmod; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
TMP_BIN="$TMP_DIR/bin"
mkdir -p "$TMP_BIN"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/easy_node_calls.log"
CURL_CAPTURE="$TMP_DIR/curl_calls.log"
FAKE_EASY_NODE="$TMP_DIR/fake_easy_node.sh"
FAKE_SMOKE="$TMP_DIR/fake_client_vpn_smoke.sh"

cat >"$FAKE_EASY_NODE" <<'EOF_FAKE_EASY'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_EASY_CAPTURE_FILE:?}"
cmd="${1:-}"
shift || true
case "$cmd" in
  runtime-doctor)
    count_file="${FAKE_RUNTIME_DOCTOR_COUNT_FILE:-}"
    sequence="${FAKE_RUNTIME_DOCTOR_STATUS_SEQUENCE:-OK}"
    call_index=1
    if [[ -n "$count_file" ]]; then
      if [[ -f "$count_file" ]]; then
        call_index="$(cat "$count_file")"
      fi
      printf '%s\n' $((call_index + 1)) >"$count_file"
    fi
    status="$(printf '%s\n' "$sequence" | cut -d, -f"$call_index")"
    if [[ -z "$status" ]]; then
      status="$(printf '%s\n' "$sequence" | awk -F, '{print $NF}')"
    fi
    findings_total=0
    if [[ "$status" != "OK" ]]; then
      findings_total=1
    fi
    echo "[runtime-doctor] status=$status findings=$findings_total warnings=$findings_total failures=0"
    echo "[runtime-doctor] summary_json_payload:"
    cat <<EOF_DOCTOR
{"version":1,"status":"$status","summary":{"findings_total":$findings_total},"findings":[{"code":"test_runtime"}]}
EOF_DOCTOR
    if [[ "$status" == "FAIL" ]]; then
      exit 1
    fi
    exit 0
    ;;
  runtime-fix)
    echo "[runtime-fix] before_status=WARN findings=1"
    echo "[runtime-fix] after_status=OK findings=0 actions_taken=1 actions_skipped=0 actions_failed=0"
    echo "[runtime-fix] summary_json_payload:"
    cat <<'EOF_FIX'
{"version":1,"doctor":{"before":{"status":"WARN","summary":{"findings_total":1}},"after":{"status":"OK","summary":{"findings_total":0}}},"actions":{"taken":["cleanup"],"failed":[]}}
EOF_FIX
    exit 0
    ;;
  client-vpn-preflight)
    echo "client-vpn preflight: OK"
    exit 0
    ;;
  client-vpn-up)
    if [[ "${FAKE_VPN_SMOKE_FAIL_UP:-0}" == "1" ]]; then
      echo "client-vpn up failed"
      exit 1
    fi
    echo "client-vpn started"
    exit 0
    ;;
  client-vpn-status)
    echo "client-vpn status:"
    echo "  running: yes"
    exit 0
    ;;
  client-vpn-down)
    echo "client-vpn state cleared"
    exit 0
    ;;
  manual-validation-record)
    echo "manual-validation-record ok"
    exit 0
    ;;
  pre-real-host-readiness)
    summary_json=""
    readiness_summary_json=""
    readiness_report_md=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --summary-json)
          summary_json="${2:-}"
          shift 2
          ;;
        --manual-validation-report-summary-json)
          readiness_summary_json="${2:-}"
          shift 2
          ;;
        --manual-validation-report-md)
          readiness_report_md="${2:-}"
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    if [[ -n "$readiness_summary_json" ]]; then
      mkdir -p "$(dirname "$readiness_summary_json")"
      cat >"$readiness_summary_json" <<'EOF_PRE_READY_JSON'
{"report":{"readiness_status":"NOT_READY"}}
EOF_PRE_READY_JSON
    fi
    if [[ -n "$readiness_report_md" ]]; then
      mkdir -p "$(dirname "$readiness_report_md")"
      cat >"$readiness_report_md" <<'EOF_PRE_READY_MD'
# Manual Validation Readiness Report
EOF_PRE_READY_MD
    fi
    if [[ -z "$summary_json" ]]; then
      echo "missing pre-real-host summary json" >&2
      exit 1
    fi
    mkdir -p "$(dirname "$summary_json")"
    cat >"$summary_json" <<EOF_PRE_REAL
{"status":"pass","machine_c_smoke_gate":{"ready":true,"blockers":[],"next_command":"sudo ./scripts/easy_node.sh client-vpn-smoke --runtime-fix 1"},"manual_validation_report":{"summary_json":"$readiness_summary_json","report_md":"$readiness_report_md","readiness_status":"NOT_READY"}}
EOF_PRE_REAL
    echo "[pre-real-host-readiness] status=PASS stage=complete"
    echo "[pre-real-host-readiness] machine_c_smoke_ready=true"
    echo "[pre-real-host-readiness] blockers=none"
    echo "[pre-real-host-readiness] manual_validation_readiness_status=NOT_READY"
    echo "[pre-real-host-readiness] next_machine_c_command=sudo ./scripts/easy_node.sh client-vpn-smoke --runtime-fix 1"
    echo "[pre-real-host-readiness] summary_json=$summary_json"
    echo "[pre-real-host-readiness] summary_log=${summary_json%.json}.log"
    if [[ -n "$readiness_summary_json" ]]; then
      echo "[pre-real-host-readiness] readiness_report_json=$readiness_summary_json"
    fi
    if [[ -n "$readiness_report_md" ]]; then
      echo "[pre-real-host-readiness] readiness_report_md=$readiness_report_md"
    fi
    echo "[pre-real-host-readiness] summary_json_payload:"
    cat "$summary_json"
    exit 0
    ;;
  manual-validation-report)
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
      echo "missing manual validation report outputs" >&2
      exit 1
    fi
    mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"
    cat >"$summary_json" <<'EOF_REPORT_JSON'
{"version":1,"summary":{"next_action_check_id":"runtime_hygiene"},"report":{"readiness_status":"NOT_READY"}}
EOF_REPORT_JSON
    cat >"$report_md" <<'EOF_REPORT_MD'
# Manual Validation Readiness Report
EOF_REPORT_MD
    echo "[manual-validation-report] readiness_status=NOT_READY total=3 pass=1 warn=1 fail=1 pending=0"
    echo "[manual-validation-report] summary_json=$summary_json"
    echo "[manual-validation-report] report_md=$report_md"
    echo "[manual-validation-report] next_action_check_id=runtime_hygiene"
    echo "[manual-validation-report] summary_json_payload:"
    cat "$summary_json"
    exit 0
    ;;
  incident-snapshot)
    bundle_dir=""
    declare -a attachments=()
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --bundle-dir)
          bundle_dir="${2:-}"
          shift 2
          ;;
        --attach-artifact)
          attachments+=("${2:-}")
          shift 2
          ;;
        *)
          shift
          ;;
      esac
    done
    if [[ -z "$bundle_dir" ]]; then
      echo "missing bundle dir" >&2
      exit 1
    fi
    mkdir -p "$bundle_dir/attachments"
    : >"$bundle_dir/attachments/manifest.tsv"
    : >"$bundle_dir/attachments/skipped.tsv"
    cat >"$bundle_dir/metadata.txt" <<'EOF_INCIDENT_META'
generated_at_utc=2026-03-15T00:00:00Z
host=test-client
mode=client
directory_url=http://127.0.0.1:18081
issuer_url=http://127.0.0.1:18082
entry_url=http://127.0.0.1:18083
exit_url=http://127.0.0.1:18084
EOF_INCIDENT_META
    artifact=""
    for artifact in "${attachments[@]}"; do
      if [[ -f "$artifact" ]]; then
        printf '%s\tfile\t%s\n' "$(basename "$artifact")" "$artifact" >>"$bundle_dir/attachments/manifest.tsv"
      else
        printf '%s\tmissing\n' "$artifact" >>"$bundle_dir/attachments/skipped.tsv"
      fi
    done
    cat <<'EOF_INCIDENT_JSON' >"$bundle_dir/incident_summary.json"
{"status":"ok"}
EOF_INCIDENT_JSON
    cat <<'EOF_INCIDENT_MD' >"$bundle_dir/incident_report.md"
# Incident Report
EOF_INCIDENT_MD
    : >"${bundle_dir}.tar.gz"
    echo "bundle_dir: $bundle_dir"
    echo "bundle_tar: ${bundle_dir}.tar.gz"
    echo "summary_json: $bundle_dir/incident_summary.json"
    echo "report_md: $bundle_dir/incident_report.md"
    exit 0
    ;;
esac
echo "unexpected command: $cmd"
exit 1
EOF_FAKE_EASY
chmod +x "$FAKE_EASY_NODE"

cat >"$TMP_BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_CURL_CAPTURE_FILE:?}"
url="${@: -1}"
case "$url" in
  https://ip.example)
    printf '%s\n' "203.0.113.19"
    ;;
  https://country.example)
    printf '%s\n' "AU"
    ;;
  *)
    echo "unexpected curl url: $url" >&2
    exit 1
    ;;
esac
EOF_CURL
chmod +x "$TMP_BIN/curl"

echo "[client-vpn-smoke] success path"
runtime_doctor_count="$TMP_DIR/runtime_doctor_count.txt"
printf '1\n' >"$runtime_doctor_count"
FAKE_EASY_CAPTURE_FILE="$CAPTURE" \
FAKE_CURL_CAPTURE_FILE="$CURL_CAPTURE" \
FAKE_RUNTIME_DOCTOR_COUNT_FILE="$runtime_doctor_count" \
CLIENT_VPN_SMOKE_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
CLIENT_VPN_SMOKE_CURL_BIN="$TMP_BIN/curl" \
./scripts/client_vpn_smoke.sh \
  --bootstrap-directory http://198.51.100.10:8081 \
  --subject inv-test \
  --interface wgvpn9 \
  --beta-profile 1 \
  --pre-real-host-readiness 1 \
  --public-ip-url https://ip.example \
  --country-url https://country.example \
  --print-summary-json 1 >/tmp/integration_client_vpn_smoke_ok.log 2>&1

if ! rg -q 'client-vpn-smoke: status=pass' /tmp/integration_client_vpn_smoke_ok.log; then
  echo "expected pass status for client-vpn-smoke success path"
  cat /tmp/integration_client_vpn_smoke_ok.log
  exit 1
fi
if ! rg -q '^client-vpn-preflight ' "$CAPTURE"; then
  echo "expected preflight call missing"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^pre-real-host-readiness ' "$CAPTURE"; then
  echo "expected pre-real-host-readiness call missing"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^runtime-doctor ' "$CAPTURE"; then
  echo "expected runtime-doctor call missing"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^client-vpn-up ' "$CAPTURE"; then
  echo "expected up call missing"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^client-vpn-status$' "$CAPTURE"; then
  echo "expected status call missing"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^client-vpn-down --force-iface-cleanup 1 --iface wgvpn9$' "$CAPTURE"; then
  echo "expected down cleanup call missing"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^manual-validation-record --check-id machine_c_vpn_smoke --status pass ' "$CAPTURE"; then
  echo "expected manual-validation-record pass call missing"
  cat "$CAPTURE"
  exit 1
fi
success_summary_json="$(sed -n 's/^summary_json: //p' /tmp/integration_client_vpn_smoke_ok.log | tail -n 1)"
if [[ -z "$success_summary_json" || ! -f "$success_summary_json" ]]; then
  echo "expected success summary json file missing"
  cat /tmp/integration_client_vpn_smoke_ok.log
  exit 1
fi
if ! jq -e '.status == "pass" and .outputs.public_ip_result == "203.0.113.19" and .outputs.country_result == "AU"' "$success_summary_json" >/dev/null 2>&1; then
  echo "success summary json missing expected outputs"
  cat "$success_summary_json"
  exit 1
fi
if ! jq -e '.pre_real_host_readiness.enabled == true and .pre_real_host_readiness.status == "pass" and .pre_real_host_readiness.machine_c_smoke_ready == true and (.pre_real_host_readiness.summary_json | length) > 0' "$success_summary_json" >/dev/null 2>&1; then
  echo "success summary json missing pre-real-host readiness info"
  cat "$success_summary_json"
  exit 1
fi
if ! jq -e '.runtime_gate.enabled == true and .runtime_gate.doctor_status_before == "OK"' "$success_summary_json" >/dev/null 2>&1; then
  echo "success summary json missing runtime gate info"
  cat "$success_summary_json"
  exit 1
fi
if ! jq -e '.incident_snapshot.enabled_on_fail == true and .incident_snapshot.status == "skipped"' "$success_summary_json" >/dev/null 2>&1; then
  echo "success summary json missing incident snapshot defaults"
  cat "$success_summary_json"
  exit 1
fi
if ! jq -e '.manual_validation_report.status == "ok" and .manual_validation_report.readiness_status == "NOT_READY" and (.manual_validation_report.summary_json | length) > 0 and (.manual_validation_report.report_md | length) > 0' "$success_summary_json" >/dev/null 2>&1; then
  echo "success summary json missing manual validation report info"
  cat "$success_summary_json"
  exit 1
fi
success_runtime_doctor_json="$(jq -r '.runtime_gate.artifacts.doctor_before_json // ""' "$success_summary_json")"
if [[ -z "$success_runtime_doctor_json" || ! -f "$success_runtime_doctor_json" ]]; then
  echo "expected success runtime doctor json artifact missing"
  cat "$success_summary_json"
  exit 1
fi
if ! rg -q '^manual-validation-report ' "$CAPTURE"; then
  echo "expected manual-validation-report call missing on success path"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q 'manual_validation_readiness_report\.md' "$CAPTURE"; then
  echo "expected success receipt artifacts to include manual validation report"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q 'pre_real_host_readiness' "$CAPTURE"; then
  echo "expected success receipt artifacts to include pre-real-host readiness evidence"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q 'runtime_doctor_before' "$CAPTURE"; then
  echo "expected receipt artifacts to include runtime doctor evidence"
  cat "$CAPTURE"
  exit 1
fi

echo "[client-vpn-smoke] up failure path"
: >"$CAPTURE"
printf '1\n' >"$runtime_doctor_count"
FAKE_EASY_CAPTURE_FILE="$CAPTURE" \
FAKE_RUNTIME_DOCTOR_COUNT_FILE="$runtime_doctor_count" \
CLIENT_VPN_SMOKE_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
FAKE_VPN_SMOKE_FAIL_UP=1 \
./scripts/client_vpn_smoke.sh \
  --bootstrap-directory http://198.51.100.10:8081 \
  --subject inv-fail \
  --interface wgvpn10 >/tmp/integration_client_vpn_smoke_fail.log 2>&1 && {
    echo "expected client-vpn-smoke up failure to return non-zero"
    cat /tmp/integration_client_vpn_smoke_fail.log
    exit 1
  }

if ! rg -q 'client-vpn-smoke: status=fail stage=up' /tmp/integration_client_vpn_smoke_fail.log; then
  echo "expected fail status for up failure path"
  cat /tmp/integration_client_vpn_smoke_fail.log
  exit 1
fi
if rg -q '^client-vpn-down ' "$CAPTURE"; then
  echo "did not expect cleanup down call when up never succeeded"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^manual-validation-record --check-id machine_c_vpn_smoke --status fail ' "$CAPTURE"; then
  echo "expected manual-validation-record fail call missing"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^incident-snapshot ' "$CAPTURE"; then
  echo "expected incident-snapshot call missing for fail path"
  cat "$CAPTURE"
  exit 1
fi
fail_summary_json="$(sed -n 's/^summary_json: //p' /tmp/integration_client_vpn_smoke_fail.log | tail -n 1)"
if [[ -z "$fail_summary_json" || ! -f "$fail_summary_json" ]]; then
  echo "expected fail summary json file missing"
  cat /tmp/integration_client_vpn_smoke_fail.log
  exit 1
fi
if ! jq -e '.status == "fail" and .stage == "up" and .incident_snapshot.status == "ok"' "$fail_summary_json" >/dev/null 2>&1; then
  echo "fail summary json missing expected incident snapshot status"
  cat "$fail_summary_json"
  exit 1
fi
if ! jq -e '.incident_snapshot.refresh_status == "ok" and (.incident_snapshot.refresh_log | length) > 0' "$fail_summary_json" >/dev/null 2>&1; then
  echo "fail summary json missing incident refresh metadata"
  cat "$fail_summary_json"
  exit 1
fi
if ! jq -e '.incident_snapshot.attachment_count >= 1 and (.incident_snapshot.requested_attachment_inputs | length) >= 1' "$fail_summary_json" >/dev/null 2>&1; then
  echo "fail summary json missing incident attachment metadata"
  cat "$fail_summary_json"
  exit 1
fi
if ! jq -e '.manual_validation_report.status == "ok" and .manual_validation_report.readiness_status == "NOT_READY"' "$fail_summary_json" >/dev/null 2>&1; then
  echo "fail summary json missing manual validation report info"
  cat "$fail_summary_json"
  exit 1
fi
if ! rg -q 'manual_validation_readiness_summary\.json' "$CAPTURE"; then
  echo "expected fail receipt artifacts to include manual validation readiness summary"
  cat "$CAPTURE"
  exit 1
fi
fail_incident_summary="$(jq -r '.incident_snapshot.summary_json // ""' "$fail_summary_json")"
if [[ -z "$fail_incident_summary" || ! -f "$fail_incident_summary" ]]; then
  echo "expected fail incident summary artifact missing"
  cat "$fail_summary_json"
  exit 1
fi
fail_attachment_manifest="$(jq -r '.incident_snapshot.attachment_manifest // ""' "$fail_summary_json")"
if [[ -z "$fail_attachment_manifest" || ! -f "$fail_attachment_manifest" ]]; then
  echo "expected fail incident attachment manifest missing"
  cat "$fail_summary_json"
  exit 1
fi
if ! rg -q 'manual_validation_readiness_summary\.json' "$fail_attachment_manifest"; then
  echo "expected fail incident attachment manifest to include readiness summary"
  cat "$fail_attachment_manifest"
  exit 1
fi
if ! rg -q 'manual_validation_readiness_report\.md' "$fail_attachment_manifest"; then
  echo "expected fail incident attachment manifest to include readiness report"
  cat "$fail_attachment_manifest"
  exit 1
fi
if ! rg -q 'incident_snapshot' "$CAPTURE"; then
  echo "expected fail receipt artifacts to include incident snapshot evidence"
  cat "$CAPTURE"
  exit 1
fi

echo "[client-vpn-smoke] runtime fix recovery path"
: >"$CAPTURE"
printf '1\n' >"$runtime_doctor_count"
FAKE_EASY_CAPTURE_FILE="$CAPTURE" \
FAKE_CURL_CAPTURE_FILE="$CURL_CAPTURE" \
FAKE_RUNTIME_DOCTOR_COUNT_FILE="$runtime_doctor_count" \
FAKE_RUNTIME_DOCTOR_STATUS_SEQUENCE="WARN,OK" \
CLIENT_VPN_SMOKE_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
CLIENT_VPN_SMOKE_CURL_BIN="$TMP_BIN/curl" \
./scripts/client_vpn_smoke.sh \
  --bootstrap-directory http://198.51.100.10:8081 \
  --subject inv-recover \
  --interface wgvpn12 \
  --runtime-fix 1 >/tmp/integration_client_vpn_smoke_recover.log 2>&1

if ! rg -q '^runtime-fix ' "$CAPTURE"; then
  echo "expected runtime-fix call missing in recovery path"
  cat "$CAPTURE"
  exit 1
fi
if [[ "$(rg -c '^runtime-doctor ' "$CAPTURE")" -lt 2 ]]; then
  echo "expected runtime-doctor to run before and after runtime-fix"
  cat "$CAPTURE"
  exit 1
fi
recover_summary_json="$(sed -n 's/^summary_json: //p' /tmp/integration_client_vpn_smoke_recover.log | tail -n 1)"
if [[ -z "$recover_summary_json" || ! -f "$recover_summary_json" ]]; then
  echo "expected recovery summary json file missing"
  cat /tmp/integration_client_vpn_smoke_recover.log
  exit 1
fi
if ! jq -e '.status == "pass" and .runtime_gate.fix_attempted == true and .runtime_gate.doctor_status_before == "WARN" and .runtime_gate.doctor_status_after == "OK"' "$recover_summary_json" >/dev/null 2>&1; then
  echo "recovery summary json missing expected runtime fix values"
  cat "$recover_summary_json"
  exit 1
fi
if ! jq -e '.manual_validation_report.status == "ok" and (.manual_validation_report.report_md | length) > 0' "$recover_summary_json" >/dev/null 2>&1; then
  echo "recovery summary json missing manual validation report info"
  cat "$recover_summary_json"
  exit 1
fi
if ! rg -q 'manual_validation_readiness_report\.md' "$CAPTURE"; then
  echo "expected recovery receipt artifacts to include manual validation report"
  cat "$CAPTURE"
  exit 1
fi
recover_runtime_fix_json="$(jq -r '.runtime_gate.artifacts.fix_json // ""' "$recover_summary_json")"
if [[ -z "$recover_runtime_fix_json" || ! -f "$recover_runtime_fix_json" ]]; then
  echo "expected recovery runtime fix json artifact missing"
  cat "$recover_summary_json"
  exit 1
fi
if ! jq -e '.incident_snapshot.status == "skipped"' "$recover_summary_json" >/dev/null 2>&1; then
  echo "recovery summary json should not capture incident snapshot on success"
  cat "$recover_summary_json"
  exit 1
fi

echo "[client-vpn-smoke] easy_node forwarding"
cat >"$FAKE_SMOKE" <<'EOF_FAKE_SMOKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_SMOKE_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_SMOKE
chmod +x "$FAKE_SMOKE"

FAKE_SMOKE_CAPTURE_FILE="$TMP_DIR/smoke_wrapper_calls.log" \
CLIENT_VPN_SMOKE_SCRIPT="$FAKE_SMOKE" \
./scripts/easy_node.sh client-vpn-smoke \
  --bootstrap-directory http://198.51.100.10:8081 \
  --subject inv-wrapper \
  --interface wgvpn11 \
  --pre-real-host-readiness 1 \
  --public-ip-url https://ip.example \
  --country-url https://country.example \
  --print-summary-json 1 >/tmp/integration_client_vpn_smoke_wrapper.log 2>&1

if ! rg -q -- '--bootstrap-directory http://198.51\.100\.10:8081' "$TMP_DIR/smoke_wrapper_calls.log"; then
  echo "easy_node client-vpn-smoke forwarding missing bootstrap-directory"
  cat "$TMP_DIR/smoke_wrapper_calls.log"
  exit 1
fi
if ! rg -q -- '--subject inv-wrapper' "$TMP_DIR/smoke_wrapper_calls.log"; then
  echo "easy_node client-vpn-smoke forwarding missing subject"
  cat "$TMP_DIR/smoke_wrapper_calls.log"
  exit 1
fi
if ! rg -q -- '--interface wgvpn11' "$TMP_DIR/smoke_wrapper_calls.log"; then
  echo "easy_node client-vpn-smoke forwarding missing interface"
  cat "$TMP_DIR/smoke_wrapper_calls.log"
  exit 1
fi
if ! rg -q -- '--pre-real-host-readiness 1' "$TMP_DIR/smoke_wrapper_calls.log"; then
  echo "easy_node client-vpn-smoke forwarding missing pre-real-host-readiness"
  cat "$TMP_DIR/smoke_wrapper_calls.log"
  exit 1
fi
if ! rg -q -- '--public-ip-url https://ip\.example' "$TMP_DIR/smoke_wrapper_calls.log"; then
  echo "easy_node client-vpn-smoke forwarding missing public-ip-url"
  cat "$TMP_DIR/smoke_wrapper_calls.log"
  exit 1
fi

echo "client vpn smoke integration check ok"
