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
REPORT_CAPTURE="$TMP_DIR/manual_validation_report_args.log"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

extract_json_payload() {
  local log_file="$1"
  awk '/^\[runtime-fix\] summary_json_payload:/{flag=1; next} flag{print}' "$log_file"
}

cat >"$TMP_BIN/docker" <<'EOF_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_DOCKER_CAPTURE_FILE:?}"
args=" $* "
if [[ "$args" == *" ps -aq "* && "$args" == *"deploy-client-demo-run-"* ]]; then
  printf '%s\n' "${FAKE_DOCKER_IDS:-}"
  exit 0
fi
if [[ "$args" == *" network inspect deploy_default "* ]]; then
  if [[ "${FAKE_DOCKER_NETWORK_PRESENT:-0}" == "1" ]]; then
    exit 0
  fi
  exit 1
fi
exit 0
EOF_DOCKER
chmod +x "$TMP_BIN/docker"

cat >"$TMP_BIN/chown" <<'EOF_CHOWN'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_CHOWN_CAPTURE_FILE:?}"
exit 0
EOF_CHOWN
chmod +x "$TMP_BIN/chown"

cat >"$TMP_BIN/chmod" <<'EOF_CHMOD'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_CHMOD_CAPTURE_FILE:?}"
exit 0
EOF_CHMOD
chmod +x "$TMP_BIN/chmod"

cat >"$TMP_BIN/runuser" <<'EOF_RUNUSER'
#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${FAKE_RUNUSER_CAPTURE_FILE:-}" ]]; then
  printf '%s\n' "$*" >>"${FAKE_RUNUSER_CAPTURE_FILE}"
fi
if [[ "${1:-}" == "-u" ]]; then
  shift 2
fi
if [[ "${1:-}" == "--" ]]; then
  shift
fi
exec "$@"
EOF_RUNUSER
chmod +x "$TMP_BIN/runuser"

FAKE_REPORT="$TMP_DIR/fake_manual_validation_report.sh"
cat >"$FAKE_REPORT" <<'EOF_FAKE_REPORT'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_MANUAL_VALIDATION_REPORT_CAPTURE_FILE:?}"
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
summary_payload='{"report":{"readiness_status":"NOT_READY","summary_json":"'"$summary_json"'","report_md":"'"$report_md"'"},"summary":{"next_action_check_id":"runtime_hygiene","next_action_command":"sudo ./scripts/easy_node.sh runtime-fix-record --prune-wg-only-dir 1 --print-summary-json 1"}}'
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  if [[ "${FAKE_MANUAL_VALIDATION_REPORT_INVALID_SCHEMA:-0}" == "1" ]]; then
    summary_payload='{"schema":{"id":"manual_validation_readiness_summary","major":2,"minor":0},"report":{"readiness_status":"NOT_READY","summary_json":"'"$summary_json"'","report_md":"'"$report_md"'"},"summary":{"next_action_check_id":"runtime_hygiene","next_action_command":"sudo ./scripts/easy_node.sh runtime-fix-record --prune-wg-only-dir 1 --print-summary-json 1"}}'
  fi
  cat >"$summary_json" <<EOF_SUMMARY
$summary_payload
EOF_SUMMARY
fi
if [[ -n "$report_md" ]]; then
  mkdir -p "$(dirname "$report_md")"
  printf '# fake readiness report\n' >"$report_md"
fi
cat <<EOF_OUT
[manual-validation-report] readiness_status=NOT_READY total=4 pass=1 warn=1 fail=0 pending=2
[manual-validation-report] summary_json=${summary_json}
[manual-validation-report] report_md=${report_md}
[manual-validation-report] summary_json_payload:
$summary_payload
EOF_OUT
exit 0
EOF_FAKE_REPORT
chmod +x "$FAKE_REPORT"

echo "[runtime-fix] baseline no-op"
BASE_DOCTOR="$TMP_DIR/fake_doctor_ok.sh"
cat >"$BASE_DOCTOR" <<'EOF_BASE_DOCTOR'
#!/usr/bin/env bash
set -euo pipefail
cat <<'OUT'
[runtime-doctor] status=OK findings=0 warnings=0 failures=0
[runtime-doctor] summary_json_payload:
{"version":1,"status":"OK","summary":{"findings_total":0,"warnings_total":0,"failures_total":0},"paths":{"wg_only_dir":"/tmp/wg_only"},"findings":[]}
OUT
exit 0
EOF_BASE_DOCTOR
chmod +x "$BASE_DOCTOR"

FAKE_MANUAL_VALIDATION_REPORT_CAPTURE_FILE="$REPORT_CAPTURE" \
MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_REPORT" \
RUNTIME_DOCTOR_SCRIPT="$BASE_DOCTOR" \
./scripts/runtime_fix.sh --show-json 1 >/tmp/integration_runtime_fix_ok.log 2>&1

if ! rg -q '\[runtime-fix\] before_status=OK findings=0' /tmp/integration_runtime_fix_ok.log; then
  echo "expected baseline runtime-fix OK status"
  cat /tmp/integration_runtime_fix_ok.log
  exit 1
fi
if ! rg -q '\[runtime-fix\] no cleanup actions were needed' /tmp/integration_runtime_fix_ok.log; then
  echo "expected baseline runtime-fix to report no actions needed"
  cat /tmp/integration_runtime_fix_ok.log
  exit 1
fi
if ! extract_json_payload /tmp/integration_runtime_fix_ok.log | jq -e '.doctor.before.status == "OK" and .doctor.after.status == "OK" and (.actions.taken | length) == 0' >/dev/null 2>&1; then
  echo "runtime-fix OK JSON payload missing expected fields"
  cat /tmp/integration_runtime_fix_ok.log
  exit 1
fi
if ! rg -q '\[runtime-fix\] manual_validation_report_status=ok' /tmp/integration_runtime_fix_ok.log; then
  echo "expected baseline runtime-fix manual validation refresh status"
  cat /tmp/integration_runtime_fix_ok.log
  exit 1
fi
if ! extract_json_payload /tmp/integration_runtime_fix_ok.log | jq -e '.manual_validation_report.status == "ok" and .manual_validation_report.summary.report.readiness_status == "NOT_READY"' >/dev/null 2>&1; then
  echo "runtime-fix OK JSON payload missing manual validation report metadata"
  cat /tmp/integration_runtime_fix_ok.log
  exit 1
fi

echo "[runtime-fix] manual report invalid schema fail-close path"
FAKE_MANUAL_VALIDATION_REPORT_CAPTURE_FILE="$REPORT_CAPTURE" \
FAKE_MANUAL_VALIDATION_REPORT_INVALID_SCHEMA="1" \
MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_REPORT" \
RUNTIME_DOCTOR_SCRIPT="$BASE_DOCTOR" \
./scripts/runtime_fix.sh --show-json 1 >/tmp/integration_runtime_fix_manual_report_invalid.log 2>&1

if ! rg -q '\[runtime-fix\] manual_validation_report_status=failed' /tmp/integration_runtime_fix_manual_report_invalid.log; then
  echo "expected runtime-fix invalid schema path to fail-close manual validation report status"
  cat /tmp/integration_runtime_fix_manual_report_invalid.log
  exit 1
fi
if ! rg -q '\[runtime-fix\] manual_validation_report_validation_error=summary_payload_invalid_or_incompatible' /tmp/integration_runtime_fix_manual_report_invalid.log; then
  echo "expected runtime-fix invalid schema path to emit validation error"
  cat /tmp/integration_runtime_fix_manual_report_invalid.log
  exit 1
fi
if ! extract_json_payload /tmp/integration_runtime_fix_manual_report_invalid.log | jq -e '.manual_validation_report.status == "failed" and .manual_validation_report.validation_error == "summary_payload_invalid_or_incompatible" and .manual_validation_report.summary == null' >/dev/null 2>&1; then
  echo "runtime-fix invalid schema JSON payload missing fail-closed manual validation fields"
  cat /tmp/integration_runtime_fix_manual_report_invalid.log
  exit 1
fi

echo "[runtime-fix] cleanup orchestration"
DOCTOR_STATE_DIR="$TMP_DIR/doctor_state"
mkdir -p "$DOCTOR_STATE_DIR"
DOCTOR_COUNTER="$DOCTOR_STATE_DIR/calls"
ORCH_DOCTOR="$TMP_DIR/fake_doctor_orch.sh"
cat >"$ORCH_DOCTOR" <<'EOF_ORCH_DOCTOR'
#!/usr/bin/env bash
set -euo pipefail
count=0
if [[ -f "${DOCTOR_COUNTER_FILE:?}" ]]; then
  count="$(cat "${DOCTOR_COUNTER_FILE}")"
fi
count=$((count + 1))
printf '%s\n' "$count" >"${DOCTOR_COUNTER_FILE}"
if [[ "$count" -eq 1 ]]; then
  cat <<'OUT'
[runtime-doctor] status=WARN findings=4 warnings=4 failures=0
[runtime-doctor] summary_json_payload:
{"version":1,"status":"WARN","summary":{"findings_total":4,"warnings_total":4,"failures_total":0},"paths":{"wg_only_dir":"/tmp/fake_wg_only"},"findings":[
{"severity":"WARN","code":"wg_only_state_stale","message":"stale wg-only state","remediation":"wg-only cleanup"},
{"severity":"WARN","code":"client_vpn_iface_present","message":"client iface present","remediation":"client cleanup"},
{"severity":"WARN","code":"stale_client_demo_containers","message":"stale docker demo","remediation":"docker cleanup"},
{"severity":"WARN","code":"wg_only_dir_not_writable","message":"wg-only dir not writable","remediation":"prune wg-only dir"}
]}
OUT
else
  cat <<'OUT'
[runtime-doctor] status=OK findings=0 warnings=0 failures=0
[runtime-doctor] summary_json_payload:
{"version":1,"status":"OK","summary":{"findings_total":0,"warnings_total":0,"failures_total":0},"paths":{"wg_only_dir":"/tmp/fake_wg_only"},"findings":[]}
OUT
fi
exit 0
EOF_ORCH_DOCTOR
chmod +x "$ORCH_DOCTOR"

FAKE_EASY_NODE="$TMP_DIR/fake_easy_node.sh"
EASY_CAPTURE="$TMP_DIR/easy_node_calls.log"
cat >"$FAKE_EASY_NODE" <<'EOF_FAKE_EASY'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_EASY_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_EASY
chmod +x "$FAKE_EASY_NODE"

DOCKER_CAPTURE="$TMP_DIR/docker_calls.log"
PATH="$TMP_BIN:$PATH" \
DOCTOR_COUNTER_FILE="$DOCTOR_COUNTER" \
RUNTIME_DOCTOR_SCRIPT="$ORCH_DOCTOR" \
MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_REPORT" \
FAKE_MANUAL_VALIDATION_REPORT_CAPTURE_FILE="$REPORT_CAPTURE" \
EASY_NODE_RUNTIME_FIX_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
FAKE_EASY_CAPTURE_FILE="$EASY_CAPTURE" \
FAKE_DOCKER_CAPTURE_FILE="$DOCKER_CAPTURE" \
FAKE_DOCKER_IDS="demo-run-id" \
FAKE_DOCKER_NETWORK_PRESENT="1" \
EASY_NODE_RUNTIME_FIX_EUID=0 \
./scripts/runtime_fix.sh --prune-wg-only-dir 1 --show-json 1 >/tmp/integration_runtime_fix_orch.log 2>&1

if ! rg -q '\[runtime-fix\] action=wg-only cleanup' /tmp/integration_runtime_fix_orch.log; then
  echo "expected wg-only cleanup action not found"
  cat /tmp/integration_runtime_fix_orch.log
  exit 1
fi
if ! rg -q '\[runtime-fix\] action=client-vpn cleanup' /tmp/integration_runtime_fix_orch.log; then
  echo "expected client-vpn cleanup action not found"
  cat /tmp/integration_runtime_fix_orch.log
  exit 1
fi
if ! rg -q '\[runtime-fix\] action=demo container cleanup' /tmp/integration_runtime_fix_orch.log; then
  echo "expected docker container cleanup action not found"
  cat /tmp/integration_runtime_fix_orch.log
  exit 1
fi
if ! rg -q '\[runtime-fix\] action=wg-only runtime dir prune' /tmp/integration_runtime_fix_orch.log; then
  echo "expected wg-only dir prune action not found"
  cat /tmp/integration_runtime_fix_orch.log
  exit 1
fi
if ! rg -q '^wg-only-stack-down --force-iface-cleanup 1 --base-port 19280 --client-iface wgcstack0 --exit-iface wgestack0$' "$EASY_CAPTURE"; then
  echo "expected wg-only cleanup command not found"
  cat "$EASY_CAPTURE"
  exit 1
fi
if ! rg -q '^client-vpn-down --force-iface-cleanup 1 --iface wgvpn0 --keep-key 1$' "$EASY_CAPTURE"; then
  echo "expected client-vpn cleanup command not found"
  cat "$EASY_CAPTURE"
  exit 1
fi
if ! rg -q '^rm -f demo-run-id$' "$DOCKER_CAPTURE"; then
  echo "expected docker rm cleanup command not found"
  cat "$DOCKER_CAPTURE"
  exit 1
fi
if ! rg -q '^network rm deploy_default$' "$DOCKER_CAPTURE"; then
  echo "expected docker network cleanup command not found"
  cat "$DOCKER_CAPTURE"
  exit 1
fi
if ! extract_json_payload /tmp/integration_runtime_fix_orch.log | jq -e '.doctor.before.status == "WARN" and .doctor.after.status == "OK" and (.actions.taken | index("wg-only cleanup")) != null and (.actions.taken | index("client-vpn cleanup")) != null' >/dev/null 2>&1; then
  echo "runtime-fix orchestration JSON payload missing expected action summary"
  cat /tmp/integration_runtime_fix_orch.log
  exit 1
fi

echo "[runtime-fix] sudo-user doctor perspective"
SUDO_WG_ONLY_DIR="$TMP_DIR/sudo_user_wg_only"
mkdir -p "$SUDO_WG_ONLY_DIR"
SUDO_DOCTOR_COUNTER="$TMP_DIR/sudo_doctor_calls"
SUDO_DOCTOR="$TMP_DIR/fake_doctor_sudo_user.sh"
cat >"$SUDO_DOCTOR" <<EOF_SUDO_DOCTOR
#!/usr/bin/env bash
set -euo pipefail
count=0
if [[ -f "\${DOCTOR_COUNTER_FILE:?}" ]]; then
  count="\$(cat "\${DOCTOR_COUNTER_FILE}")"
fi
count=\$((count + 1))
printf '%s\n' "\$count" >"\${DOCTOR_COUNTER_FILE}"
if [[ "\$count" -eq 1 ]]; then
  cat <<'OUT'
[runtime-doctor] status=WARN findings=1 warnings=1 failures=0
[runtime-doctor] summary_json_payload:
{"version":1,"status":"WARN","summary":{"findings_total":1,"warnings_total":1,"failures_total":0},"paths":{"wg_only_dir":"${SUDO_WG_ONLY_DIR}"},"findings":[
{"severity":"WARN","code":"wg_only_dir_not_writable","message":"wg-only dir not writable","remediation":"prune wg-only dir"}
]}
OUT
else
  cat <<'OUT'
[runtime-doctor] status=OK findings=0 warnings=0 failures=0
[runtime-doctor] summary_json_payload:
{"version":1,"status":"OK","summary":{"findings_total":0,"warnings_total":0,"failures_total":0},"paths":{"wg_only_dir":"${SUDO_WG_ONLY_DIR}"},"findings":[]}
OUT
fi
exit 0
EOF_SUDO_DOCTOR
chmod +x "$SUDO_DOCTOR"

RUNUSER_CAPTURE="$TMP_DIR/runuser_calls.log"
CHOWN_CAPTURE_SUDO="$TMP_DIR/chown_calls_sudo_user.log"
CHMOD_CAPTURE_SUDO="$TMP_DIR/chmod_calls_sudo_user.log"
: >"$RUNUSER_CAPTURE"
: >"$CHOWN_CAPTURE_SUDO"
: >"$CHMOD_CAPTURE_SUDO"
PATH="$TMP_BIN:$PATH" \
DOCTOR_COUNTER_FILE="$SUDO_DOCTOR_COUNTER" \
RUNTIME_DOCTOR_SCRIPT="$SUDO_DOCTOR" \
MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_REPORT" \
FAKE_MANUAL_VALIDATION_REPORT_CAPTURE_FILE="$REPORT_CAPTURE" \
FAKE_RUNUSER_CAPTURE_FILE="$RUNUSER_CAPTURE" \
FAKE_CHOWN_CAPTURE_FILE="$CHOWN_CAPTURE_SUDO" \
FAKE_CHMOD_CAPTURE_FILE="$CHMOD_CAPTURE_SUDO" \
EASY_NODE_RUNTIME_FIX_EUID=0 \
SUDO_USER="$(id -un)" \
./scripts/runtime_fix.sh --prune-wg-only-dir 1 --show-json 1 >/tmp/integration_runtime_fix_sudo_user.log 2>&1

if ! rg -q -- "-u $(id -un) -- ${SUDO_DOCTOR}" "$RUNUSER_CAPTURE"; then
  echo "expected runtime-fix to run runtime-doctor via runuser for SUDO_USER perspective"
  cat "$RUNUSER_CAPTURE"
  exit 1
fi
if ! rg -q '\[runtime-fix\] action=wg-only runtime dir ownership repair' /tmp/integration_runtime_fix_sudo_user.log; then
  echo "expected wg-only runtime dir ownership repair action not found in sudo-user perspective path"
  cat /tmp/integration_runtime_fix_sudo_user.log
  exit 1
fi
if ! rg -q -- "-R $(id -un):$(id -gn) ${SUDO_WG_ONLY_DIR}" "$CHOWN_CAPTURE_SUDO"; then
  echo "expected recursive chown on wg-only dir not found in sudo-user perspective path"
  cat "$CHOWN_CAPTURE_SUDO"
  exit 1
fi
if ! rg -q -- "700 ${SUDO_WG_ONLY_DIR}" "$CHMOD_CAPTURE_SUDO"; then
  echo "expected chmod 700 on wg-only dir not found in sudo-user perspective path"
  cat "$CHMOD_CAPTURE_SUDO"
  exit 1
fi
if ! extract_json_payload /tmp/integration_runtime_fix_sudo_user.log | jq -e '(.actions.taken | index("wg-only runtime dir prune")) != null and (.actions.taken | index("wg-only runtime dir ownership repair")) != null and .doctor.before.status == "WARN" and .doctor.after.status == "OK"' >/dev/null 2>&1; then
  echo "runtime-fix sudo-user JSON payload missing expected remediation actions"
  cat /tmp/integration_runtime_fix_sudo_user.log
  exit 1
fi

echo "[runtime-fix] ownership repair"
OWN_DIR="$TMP_DIR/ownership"
mkdir -p "$OWN_DIR/client_vpn" "$OWN_DIR/logs" "$OWN_DIR/wg_only"
touch "$OWN_DIR/client.env" "$OWN_DIR/server.env" "$OWN_DIR/provider.env"
OWN_DOCTOR_COUNTER="$TMP_DIR/own_calls"
OWN_DOCTOR="$TMP_DIR/fake_doctor_ownership.sh"
cat >"$OWN_DOCTOR" <<EOF_OWN_DOCTOR
#!/usr/bin/env bash
set -euo pipefail
count=0
if [[ -f "\${DOCTOR_COUNTER_FILE:?}" ]]; then
  count="\$(cat "\${DOCTOR_COUNTER_FILE}")"
fi
count=\$((count + 1))
printf '%s\n' "\$count" >"\${DOCTOR_COUNTER_FILE}"
if [[ "\$count" -eq 1 ]]; then
  cat <<'OUT'
[runtime-doctor] status=FAIL findings=5 warnings=1 failures=4
[runtime-doctor] summary_json_payload:
{"version":1,"status":"FAIL","summary":{"findings_total":5,"warnings_total":1,"failures_total":4},"paths":{
  "client_env_file":"${OWN_DIR}/client.env",
  "authority_env_file":"${OWN_DIR}/server.env",
  "provider_env_file":"${OWN_DIR}/provider.env",
  "wg_only_dir":"${OWN_DIR}/wg_only",
  "client_vpn_key_dir":"${OWN_DIR}/client_vpn",
  "log_dir":"${OWN_DIR}/logs"
},"findings":[
{"severity":"WARN","code":"client_env_file_not_writable","message":"client env file not writable","remediation":"client env chown"},
{"severity":"FAIL","code":"authority_env_file_not_writable","message":"authority env file not writable","remediation":"authority env chown"},
{"severity":"FAIL","code":"provider_env_file_not_writable","message":"provider env file not writable","remediation":"provider env chown"},
{"severity":"FAIL","code":"client_vpn_key_dir_not_writable","message":"client vpn key dir not writable","remediation":"client vpn dir repair"},
{"severity":"FAIL","code":"log_dir_not_writable","message":"log dir not writable","remediation":"log dir repair"}
]}
OUT
else
  cat <<'OUT'
[runtime-doctor] status=OK findings=0 warnings=0 failures=0
[runtime-doctor] summary_json_payload:
{"version":1,"status":"OK","summary":{"findings_total":0,"warnings_total":0,"failures_total":0},"paths":{"wg_only_dir":"${OWN_DIR}/wg_only"},"findings":[]}
OUT
fi
exit 0
EOF_OWN_DOCTOR
chmod +x "$OWN_DOCTOR"

CHOWN_CAPTURE="$TMP_DIR/chown_calls.log"
CHMOD_CAPTURE="$TMP_DIR/chmod_calls.log"
: >"$CHOWN_CAPTURE"
: >"$CHMOD_CAPTURE"
PATH="$TMP_BIN:$PATH" \
DOCTOR_COUNTER_FILE="$OWN_DOCTOR_COUNTER" \
RUNTIME_DOCTOR_SCRIPT="$OWN_DOCTOR" \
MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_REPORT" \
FAKE_MANUAL_VALIDATION_REPORT_CAPTURE_FILE="$REPORT_CAPTURE" \
FAKE_CHOWN_CAPTURE_FILE="$CHOWN_CAPTURE" \
FAKE_CHMOD_CAPTURE_FILE="$CHMOD_CAPTURE" \
EASY_NODE_RUNTIME_FIX_EUID=0 \
SUDO_USER="$(id -un)" \
./scripts/runtime_fix.sh --show-json 1 >/tmp/integration_runtime_fix_ownership.log 2>&1

if ! rg -q '\[runtime-fix\] action=client env ownership repair' /tmp/integration_runtime_fix_ownership.log; then
  echo "expected client env ownership repair action not found"
  cat /tmp/integration_runtime_fix_ownership.log
  exit 1
fi
if ! rg -q '\[runtime-fix\] action=authority env ownership repair' /tmp/integration_runtime_fix_ownership.log; then
  echo "expected authority env ownership repair action not found"
  cat /tmp/integration_runtime_fix_ownership.log
  exit 1
fi
if ! rg -q '\[runtime-fix\] action=provider env ownership repair' /tmp/integration_runtime_fix_ownership.log; then
  echo "expected provider env ownership repair action not found"
  cat /tmp/integration_runtime_fix_ownership.log
  exit 1
fi
if ! rg -q '\[runtime-fix\] action=client-vpn key dir ownership repair' /tmp/integration_runtime_fix_ownership.log; then
  echo "expected client-vpn key dir ownership repair action not found"
  cat /tmp/integration_runtime_fix_ownership.log
  exit 1
fi
if ! rg -q '\[runtime-fix\] action=log dir ownership repair' /tmp/integration_runtime_fix_ownership.log; then
  echo "expected log dir ownership repair action not found"
  cat /tmp/integration_runtime_fix_ownership.log
  exit 1
fi
if ! rg -q -- "$(id -un):$(id -gn) ${OWN_DIR}/client.env" "$CHOWN_CAPTURE"; then
  echo "expected client env chown command not found"
  cat "$CHOWN_CAPTURE"
  exit 1
fi
if ! rg -q -- "$(id -un):$(id -gn) ${OWN_DIR}/server.env" "$CHOWN_CAPTURE"; then
  echo "expected authority env chown command not found"
  cat "$CHOWN_CAPTURE"
  exit 1
fi
if ! rg -q -- '-R '"$(id -un):$(id -gn) ${OWN_DIR}/client_vpn" "$CHOWN_CAPTURE"; then
  echo "expected recursive client-vpn dir chown command not found"
  cat "$CHOWN_CAPTURE"
  exit 1
fi
if ! rg -q -- '700 '"${OWN_DIR}/client_vpn" "$CHMOD_CAPTURE"; then
  echo "expected client_vpn chmod command not found"
  cat "$CHMOD_CAPTURE"
  exit 1
fi
if ! rg -q -- '700 '"${OWN_DIR}/logs" "$CHMOD_CAPTURE"; then
  echo "expected log dir chmod command not found"
  cat "$CHMOD_CAPTURE"
  exit 1
fi
if ! extract_json_payload /tmp/integration_runtime_fix_ownership.log | jq -e '.doctor.before.status == "FAIL" and .doctor.after.status == "OK" and (.actions.taken | index("client env ownership repair")) != null and .inputs.target_owner_spec != ""' >/dev/null 2>&1; then
  echo "runtime-fix ownership JSON payload missing expected ownership fields"
  cat /tmp/integration_runtime_fix_ownership.log
  exit 1
fi

echo "[runtime-fix] non-root skip path"
SKIP_COUNTER="$TMP_DIR/skip_calls"
SKIP_DOCTOR="$TMP_DIR/fake_doctor_skip.sh"
cat >"$SKIP_DOCTOR" <<'EOF_SKIP_DOCTOR'
#!/usr/bin/env bash
set -euo pipefail
count=0
if [[ -f "${DOCTOR_COUNTER_FILE:?}" ]]; then
  count="$(cat "${DOCTOR_COUNTER_FILE}")"
fi
count=$((count + 1))
printf '%s\n' "$count" >"${DOCTOR_COUNTER_FILE}"
cat <<'OUT'
[runtime-doctor] status=WARN findings=1 warnings=1 failures=0
[runtime-doctor] summary_json_payload:
{"version":1,"status":"WARN","summary":{"findings_total":1,"warnings_total":1,"failures_total":0},"paths":{"wg_only_dir":"/tmp/fake_wg_only"},"findings":[
{"severity":"WARN","code":"wg_only_state_stale","message":"stale wg-only state","remediation":"wg-only cleanup"}
]}
OUT
exit 0
EOF_SKIP_DOCTOR
chmod +x "$SKIP_DOCTOR"

: >"$EASY_CAPTURE"
DOCTOR_COUNTER_FILE="$SKIP_COUNTER" \
RUNTIME_DOCTOR_SCRIPT="$SKIP_DOCTOR" \
MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_REPORT" \
FAKE_MANUAL_VALIDATION_REPORT_CAPTURE_FILE="$REPORT_CAPTURE" \
EASY_NODE_RUNTIME_FIX_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
FAKE_EASY_CAPTURE_FILE="$EASY_CAPTURE" \
EASY_NODE_RUNTIME_FIX_EUID=1000 \
./scripts/runtime_fix.sh --show-json 1 >/tmp/integration_runtime_fix_skip.log 2>&1

if ! rg -q '\[runtime-fix\] action_skipped=wg-only cleanup \(root required\)' /tmp/integration_runtime_fix_skip.log; then
  echo "expected non-root skip message not found"
  cat /tmp/integration_runtime_fix_skip.log
  exit 1
fi
if [[ -s "$EASY_CAPTURE" ]]; then
  echo "expected no easy_node privileged cleanup command for non-root skip path"
  cat "$EASY_CAPTURE"
  exit 1
fi
if ! extract_json_payload /tmp/integration_runtime_fix_skip.log | jq -e '(.actions.skipped | index("wg-only cleanup (root required)")) != null' >/dev/null 2>&1; then
  echo "runtime-fix skip JSON payload missing expected skipped action"
  cat /tmp/integration_runtime_fix_skip.log
  exit 1
fi

echo "[runtime-fix] easy_node forwarding"
FAKE_FIX="$TMP_DIR/fake_runtime_fix.sh"
FIX_CAPTURE="$TMP_DIR/runtime_fix_args.log"
cat >"$FAKE_FIX" <<'EOF_FAKE_FIX'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FIX_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_FIX
chmod +x "$FAKE_FIX"

FIX_CAPTURE_FILE="$FIX_CAPTURE" \
RUNTIME_FIX_SCRIPT="$FAKE_FIX" \
./scripts/easy_node.sh runtime-fix \
  --base-port 20000 \
  --client-iface wgcfoo0 \
  --exit-iface wgefoo0 \
  --vpn-iface wgvfoo0 \
  --prune-wg-only-dir 1 \
  --manual-validation-report-summary-json .easy-node-logs/custom_fix_summary.json \
  --manual-validation-report-md .easy-node-logs/custom_fix_report.md \
  --show-json 1 >/tmp/integration_runtime_fix_easy_node.log 2>&1

if ! rg -q -- '--base-port 20000' "$FIX_CAPTURE"; then
  echo "easy_node runtime-fix forwarding failed: missing --base-port"
  cat "$FIX_CAPTURE"
  exit 1
fi
if ! rg -q -- '--client-iface wgcfoo0' "$FIX_CAPTURE"; then
  echo "easy_node runtime-fix forwarding failed: missing --client-iface"
  cat "$FIX_CAPTURE"
  exit 1
fi
if ! rg -q -- '--exit-iface wgefoo0' "$FIX_CAPTURE"; then
  echo "easy_node runtime-fix forwarding failed: missing --exit-iface"
  cat "$FIX_CAPTURE"
  exit 1
fi
if ! rg -q -- '--vpn-iface wgvfoo0' "$FIX_CAPTURE"; then
  echo "easy_node runtime-fix forwarding failed: missing --vpn-iface"
  cat "$FIX_CAPTURE"
  exit 1
fi
if ! rg -q -- '--prune-wg-only-dir 1' "$FIX_CAPTURE"; then
  echo "easy_node runtime-fix forwarding failed: missing --prune-wg-only-dir"
  cat "$FIX_CAPTURE"
  exit 1
fi
if ! rg -q -- '--manual-validation-report-summary-json .easy-node-logs/custom_fix_summary.json' "$FIX_CAPTURE"; then
  echo "easy_node runtime-fix forwarding failed: missing --manual-validation-report-summary-json"
  cat "$FIX_CAPTURE"
  exit 1
fi
if ! rg -q -- '--manual-validation-report-md .easy-node-logs/custom_fix_report.md' "$FIX_CAPTURE"; then
  echo "easy_node runtime-fix forwarding failed: missing --manual-validation-report-md"
  cat "$FIX_CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-json 1' "$FIX_CAPTURE"; then
  echo "easy_node runtime-fix forwarding failed: missing --show-json"
  cat "$FIX_CAPTURE"
  exit 1
fi

echo "runtime fix integration check ok"
