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

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cat >"$TMP_BIN/ip" <<'EOF_IP'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "link" && "${2:-}" == "show" && "${3:-}" == "dev" ]]; then
  iface="${4:-}"
  if [[ " ${FAKE_IP_IFACES:-} " == *" ${iface} "* ]]; then
    printf '7: %s: <POINTOPOINT,UP> mtu 1420 qdisc noqueue state UNKNOWN mode DEFAULT group default\n' "$iface"
    exit 0
  fi
  exit 1
fi
exit 1
EOF_IP

cat >"$TMP_BIN/ss" <<'EOF_SS'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "${FAKE_SS_OUTPUT:-}"
EOF_SS

cat >"$TMP_BIN/docker" <<'EOF_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
args=" $* "
if [[ "$args" == *" ps -aq "* && "$args" == *"deploy-client-demo-run-"* ]]; then
  printf '%s\n' "${FAKE_DOCKER_IDS:-}"
  exit 0
fi
exit 0
EOF_DOCKER

chmod +x "$TMP_BIN/ip" "$TMP_BIN/ss" "$TMP_BIN/docker"

extract_json_payload() {
  local log_file="$1"
  awk '/^\[runtime-doctor\] summary_json_payload:/{flag=1; next} flag{print}' "$log_file"
}

echo "[runtime-doctor] baseline clean host"
BASE_DIR="$TMP_DIR/base"
mkdir -p "$BASE_DIR/logs" "$BASE_DIR/client_vpn" "$BASE_DIR/wg_only"
touch "$BASE_DIR/client.env" "$BASE_DIR/server.env" "$BASE_DIR/provider.env"

PATH="$TMP_BIN:$PATH" \
EASY_NODE_DOCTOR_CLIENT_ENV_FILE="$BASE_DIR/client.env" \
EASY_NODE_DOCTOR_AUTHORITY_ENV_FILE="$BASE_DIR/server.env" \
EASY_NODE_DOCTOR_PROVIDER_ENV_FILE="$BASE_DIR/provider.env" \
EASY_NODE_DOCTOR_WG_ONLY_DIR="$BASE_DIR/wg_only" \
EASY_NODE_DOCTOR_CLIENT_VPN_KEY_DIR="$BASE_DIR/client_vpn" \
EASY_NODE_DOCTOR_LOG_DIR="$BASE_DIR/logs" \
./scripts/runtime_doctor.sh --show-json 1 >/tmp/integration_runtime_doctor_ok.log 2>&1

if ! rg -q '\[runtime-doctor\] status=OK' /tmp/integration_runtime_doctor_ok.log; then
  echo "expected OK status for clean runtime doctor baseline"
  cat /tmp/integration_runtime_doctor_ok.log
  exit 1
fi
if ! extract_json_payload /tmp/integration_runtime_doctor_ok.log | jq -e '.status == "OK" and .summary.findings_total == 0' >/dev/null 2>&1; then
  echo "runtime doctor OK JSON payload missing expected fields"
  cat /tmp/integration_runtime_doctor_ok.log
  exit 1
fi

echo "[runtime-doctor] detect stale host hygiene issues"
FAIL_DIR="$TMP_DIR/fail"
mkdir -p "$FAIL_DIR"
touch "$FAIL_DIR/client.env" "$FAIL_DIR/server.env" "$FAIL_DIR/provider.env"
mkdir -p "$FAIL_DIR/logs" "$FAIL_DIR/client_vpn" "$FAIL_DIR/wg_only"
chmod 400 "$FAIL_DIR/client.env" "$FAIL_DIR/server.env"
chmod 500 "$FAIL_DIR/logs"
printf 'WG_ONLY_PID=999999\n' >"$FAIL_DIR/wg_only.state"
printf 'CLIENT_VPN_PID=999999\n' >"$FAIL_DIR/client_vpn.state"

set +e
PATH="$TMP_BIN:$PATH" \
FAKE_IP_IFACES="wgcstack0 wgestack0 wgvpn0" \
FAKE_SS_OUTPUT=$'tcp LISTEN 0 4096 0.0.0.0:19281 0.0.0.0:* users:(("node",pid=111,fd=5))\nudp UNCONN 0 0 127.0.0.1:19380 0.0.0.0:* users:(("node",pid=111,fd=6))' \
FAKE_DOCKER_IDS="demo-run-id" \
EASY_NODE_DOCTOR_CLIENT_ENV_FILE="$FAIL_DIR/client.env" \
EASY_NODE_DOCTOR_AUTHORITY_ENV_FILE="$FAIL_DIR/server.env" \
EASY_NODE_DOCTOR_PROVIDER_ENV_FILE="$FAIL_DIR/provider.env" \
EASY_NODE_DOCTOR_WG_ONLY_DIR="$FAIL_DIR/wg_only" \
EASY_NODE_DOCTOR_CLIENT_VPN_KEY_DIR="$FAIL_DIR/client_vpn" \
EASY_NODE_DOCTOR_LOG_DIR="$FAIL_DIR/logs" \
EASY_NODE_DOCTOR_WG_ONLY_STATE_FILE="$FAIL_DIR/wg_only.state" \
EASY_NODE_DOCTOR_CLIENT_VPN_STATE_FILE="$FAIL_DIR/client_vpn.state" \
./scripts/runtime_doctor.sh --show-json 1 >/tmp/integration_runtime_doctor_fail.log 2>&1
doctor_rc=$?
set -e

if [[ "$doctor_rc" -eq 0 ]]; then
  echo "expected non-zero rc for failing runtime doctor scenario"
  cat /tmp/integration_runtime_doctor_fail.log
  exit 1
fi
if ! rg -q '\[runtime-doctor\] status=FAIL' /tmp/integration_runtime_doctor_fail.log; then
  echo "expected FAIL status for runtime doctor failure scenario"
  cat /tmp/integration_runtime_doctor_fail.log
  exit 1
fi
if ! rg -q 'authority_env_file_not_writable' /tmp/integration_runtime_doctor_fail.log; then
  echo "expected authority env finding not found"
  cat /tmp/integration_runtime_doctor_fail.log
  exit 1
fi
if ! rg -q 'client_env_file_not_writable' /tmp/integration_runtime_doctor_fail.log; then
  echo "expected client env finding not found"
  cat /tmp/integration_runtime_doctor_fail.log
  exit 1
fi
if ! rg -q 'wg_only_state_stale' /tmp/integration_runtime_doctor_fail.log; then
  echo "expected stale wg-only state finding not found"
  cat /tmp/integration_runtime_doctor_fail.log
  exit 1
fi
if ! rg -q 'client_vpn_state_stale' /tmp/integration_runtime_doctor_fail.log; then
  echo "expected stale client-vpn state finding not found"
  cat /tmp/integration_runtime_doctor_fail.log
  exit 1
fi
if ! rg -q 'wg_only_port_busy_19281' /tmp/integration_runtime_doctor_fail.log; then
  echo "expected wg-only control port busy finding not found"
  cat /tmp/integration_runtime_doctor_fail.log
  exit 1
fi
if ! rg -q 'stale_client_demo_containers' /tmp/integration_runtime_doctor_fail.log; then
  echo "expected stale client demo container finding not found"
  cat /tmp/integration_runtime_doctor_fail.log
  exit 1
fi
if ! rg -q "wg-only-stack-down --force-iface-cleanup 1 --base-port 19280 --client-iface wgcstack0 --exit-iface wgestack0" /tmp/integration_runtime_doctor_fail.log; then
  echo "expected wg-only cleanup remediation not found"
  cat /tmp/integration_runtime_doctor_fail.log
  exit 1
fi
if ! rg -q "docker rm -f demo-run-id" /tmp/integration_runtime_doctor_fail.log; then
  echo "expected docker cleanup remediation not found"
  cat /tmp/integration_runtime_doctor_fail.log
  exit 1
fi
if ! extract_json_payload /tmp/integration_runtime_doctor_fail.log | jq -e '.status == "FAIL" and .summary.failures_total >= 1 and (.findings | map(.code) | index("authority_env_file_not_writable")) != null and (.findings | map(.code) | index("stale_client_demo_containers")) != null' >/dev/null 2>&1; then
  echo "runtime doctor FAIL JSON payload missing expected findings"
  cat /tmp/integration_runtime_doctor_fail.log
  exit 1
fi

echo "[runtime-doctor] easy_node forwarding"
FAKE_DOCTOR="$TMP_DIR/fake_runtime_doctor.sh"
CAPTURE="$TMP_DIR/runtime_doctor_args.log"
cat >"$FAKE_DOCTOR" <<'EOF_FAKE_DOCTOR'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${CAPTURE_FILE:?}"
exit 0
EOF_FAKE_DOCTOR
chmod +x "$FAKE_DOCTOR"

CAPTURE_FILE="$CAPTURE" \
RUNTIME_DOCTOR_SCRIPT="$FAKE_DOCTOR" \
./scripts/easy_node.sh runtime-doctor \
  --base-port 20000 \
  --client-iface wgcfoo0 \
  --exit-iface wgefoo0 \
  --vpn-iface wgvfoo0 \
  --show-json 1 >/tmp/integration_runtime_doctor_easy_node.log 2>&1

if ! rg -q -- '--base-port 20000' "$CAPTURE"; then
  echo "easy_node runtime-doctor forwarding failed: missing --base-port"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--client-iface wgcfoo0' "$CAPTURE"; then
  echo "easy_node runtime-doctor forwarding failed: missing --client-iface"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--exit-iface wgefoo0' "$CAPTURE"; then
  echo "easy_node runtime-doctor forwarding failed: missing --exit-iface"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--vpn-iface wgvfoo0' "$CAPTURE"; then
  echo "easy_node runtime-doctor forwarding failed: missing --vpn-iface"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-json 1' "$CAPTURE"; then
  echo "easy_node runtime-doctor forwarding failed: missing --show-json"
  cat "$CAPTURE"
  exit 1
fi

echo "runtime doctor integration check ok"
