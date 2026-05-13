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
TMP_ID_BIN="$TMP_DIR/idbin"
mkdir -p "$TMP_BIN" "$TMP_ID_BIN"
EXTRA_CLEANUP_PATHS=()

cleanup() {
  rm -rf "$TMP_DIR"
  local path
  for path in "${EXTRA_CLEANUP_PATHS[@]}"; do
    rm -f "$path"
  done
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
if [[ "${1:-}" == "inspect" ]]; then
  container="${@: -1}"
  case "$container" in
    deploy-entry-exit-1)
      if [[ "${FAKE_DOCKER_ENTRY_EXIT_PRESENT:-0}" == "1" ]]; then
        printf '%s\n' "${FAKE_DOCKER_ENTRY_EXIT_STATE:-restarting	true	7}"
        exit 0
      fi
      ;;
    deploy-directory-1)
      if [[ "${FAKE_DOCKER_DIRECTORY_PRESENT:-0}" == "1" ]]; then
        printf '%s\n' "${FAKE_DOCKER_DIRECTORY_STATE:-running	false	0}"
        exit 0
      fi
      ;;
    deploy-issuer-1)
      if [[ "${FAKE_DOCKER_ISSUER_PRESENT:-0}" == "1" ]]; then
        printf '%s\n' "${FAKE_DOCKER_ISSUER_STATE:-running	false	0}"
        exit 0
      fi
      ;;
  esac
  exit 1
fi
if [[ "${1:-}" == "logs" ]]; then
  container="${@: -1}"
  if [[ "$container" == "deploy-entry-exit-1" ]]; then
    printf '%s\n' "${FAKE_DOCKER_ENTRY_EXIT_LOGS:-}"
    exit 0
  fi
  exit 0
fi
if [[ "$args" == *" ps -aq "* && "$args" == *"deploy-client-demo-run-"* ]]; then
  printf '%s\n' "${FAKE_DOCKER_IDS:-}"
  exit 0
fi
exit 0
EOF_DOCKER

chmod +x "$TMP_BIN/ip" "$TMP_BIN/ss" "$TMP_BIN/docker"

cat >"$TMP_ID_BIN/id" <<'EOF_ID'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  -un)
    printf 'dracsis\n'
    ;;
  -u)
    printf '1000\n'
    ;;
  -gn)
    printf 'id: cannot find name for group ID 197121\n' >&2
    exit 1
    ;;
  -g)
    printf '197121\n'
    ;;
  *)
    exec /usr/bin/id "$@"
    ;;
esac
EOF_ID
chmod +x "$TMP_ID_BIN/id"

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
EASY_NODE_DOCTOR_WG_ONLY_STATE_FILE="$BASE_DIR/wg_only.state" \
EASY_NODE_DOCTOR_CLIENT_VPN_STATE_FILE="$BASE_DIR/client_vpn.state" \
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

echo "[runtime-doctor] unnamed current group falls back to numeric gid"
UNNAMED_GROUP_DIR="$TMP_DIR/unnamed_group"
mkdir -p "$UNNAMED_GROUP_DIR/logs" "$UNNAMED_GROUP_DIR/client_vpn" "$UNNAMED_GROUP_DIR/wg_only"
touch "$UNNAMED_GROUP_DIR/client.env" "$UNNAMED_GROUP_DIR/server.env" "$UNNAMED_GROUP_DIR/provider.env"

PATH="$TMP_ID_BIN:$TMP_BIN:$PATH" \
EASY_NODE_DOCTOR_CLIENT_ENV_FILE="$UNNAMED_GROUP_DIR/client.env" \
EASY_NODE_DOCTOR_AUTHORITY_ENV_FILE="$UNNAMED_GROUP_DIR/server.env" \
EASY_NODE_DOCTOR_PROVIDER_ENV_FILE="$UNNAMED_GROUP_DIR/provider.env" \
EASY_NODE_DOCTOR_WG_ONLY_DIR="$UNNAMED_GROUP_DIR/wg_only" \
EASY_NODE_DOCTOR_CLIENT_VPN_KEY_DIR="$UNNAMED_GROUP_DIR/client_vpn" \
EASY_NODE_DOCTOR_LOG_DIR="$UNNAMED_GROUP_DIR/logs" \
EASY_NODE_DOCTOR_WG_ONLY_STATE_FILE="$UNNAMED_GROUP_DIR/wg_only.state" \
EASY_NODE_DOCTOR_CLIENT_VPN_STATE_FILE="$UNNAMED_GROUP_DIR/client_vpn.state" \
./scripts/runtime_doctor.sh --show-json 1 >/tmp/integration_runtime_doctor_unnamed_group.log 2>&1

if rg -q 'cannot find name for group ID' /tmp/integration_runtime_doctor_unnamed_group.log; then
  echo "runtime doctor leaked id -gn failure instead of falling back"
  cat /tmp/integration_runtime_doctor_unnamed_group.log
  exit 1
fi
if ! extract_json_payload /tmp/integration_runtime_doctor_unnamed_group.log | jq -e '
  .status == "OK"
  and .summary.findings_total == 0
  and .ownership.preferred_user == "dracsis"
  and .ownership.preferred_group == "197121"
' >/dev/null 2>&1; then
  echo "runtime doctor unnamed group JSON payload missing fallback ownership"
  cat /tmp/integration_runtime_doctor_unnamed_group.log
  exit 1
fi

echo "[runtime-doctor] normal prod container env refs resolve to mounted host files"
PROD_REF_DIR="$TMP_DIR/prod_refs"
mkdir -p "$PROD_REF_DIR/logs" "$PROD_REF_DIR/client_vpn" "$PROD_REF_DIR/wg_only" "$ROOT_DIR/deploy/tls" "$ROOT_DIR/deploy/data/entry-exit"
PROD_CA_BASENAME="integration_runtime_doctor_ca.crt"
PROD_CERT_BASENAME="integration_runtime_doctor_node.crt"
PROD_EXIT_WG_BASENAME="integration_runtime_doctor_exit_wg.key"
PROD_CA_PATH="$ROOT_DIR/deploy/tls/$PROD_CA_BASENAME"
PROD_CERT_PATH="$ROOT_DIR/deploy/tls/$PROD_CERT_BASENAME"
PROD_EXIT_WG_PATH="$ROOT_DIR/deploy/data/entry-exit/$PROD_EXIT_WG_BASENAME"
EXTRA_CLEANUP_PATHS+=("$PROD_CA_PATH" "$PROD_CERT_PATH" "$PROD_EXIT_WG_PATH")
touch "$PROD_CA_PATH" "$PROD_CERT_PATH" "$PROD_EXIT_WG_PATH"
touch "$PROD_REF_DIR/client.env" "$PROD_REF_DIR/provider.env"
cat >"$PROD_REF_DIR/server.env" <<EOF_PROD_REF
MTLS_CA_FILE=/app/tls/$PROD_CA_BASENAME
MTLS_SERVER_CERT_FILE=/app/tls/$PROD_CERT_BASENAME
EXIT_WG_PRIVATE_KEY_PATH=/app/data/$PROD_EXIT_WG_BASENAME
EOF_PROD_REF

PATH="$TMP_BIN:$PATH" \
EASY_NODE_DOCTOR_CLIENT_ENV_FILE="$PROD_REF_DIR/client.env" \
EASY_NODE_DOCTOR_AUTHORITY_ENV_FILE="$PROD_REF_DIR/server.env" \
EASY_NODE_DOCTOR_PROVIDER_ENV_FILE="$PROD_REF_DIR/provider.env" \
EASY_NODE_DOCTOR_WG_ONLY_DIR="$PROD_REF_DIR/wg_only" \
EASY_NODE_DOCTOR_CLIENT_VPN_KEY_DIR="$PROD_REF_DIR/client_vpn" \
EASY_NODE_DOCTOR_LOG_DIR="$PROD_REF_DIR/logs" \
EASY_NODE_DOCTOR_WG_ONLY_STATE_FILE="$PROD_REF_DIR/wg_only.state" \
EASY_NODE_DOCTOR_CLIENT_VPN_STATE_FILE="$PROD_REF_DIR/client_vpn.state" \
./scripts/runtime_doctor.sh --show-json 1 >/tmp/integration_runtime_doctor_prod_refs.log 2>&1

if ! rg -q '\[runtime-doctor\] status=OK' /tmp/integration_runtime_doctor_prod_refs.log; then
  echo "expected OK status for normal prod container env refs"
  cat /tmp/integration_runtime_doctor_prod_refs.log
  exit 1
fi
if ! extract_json_payload /tmp/integration_runtime_doctor_prod_refs.log | jq -e '.status == "OK" and .summary.findings_total == 0' >/dev/null 2>&1; then
  echo "runtime doctor normal prod env ref JSON payload missing expected OK fields"
  cat /tmp/integration_runtime_doctor_prod_refs.log
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

echo "[runtime-doctor] detect entry-exit restart loop with WG pubkey mismatch"
RESTART_DIR="$TMP_DIR/restart"
mkdir -p "$RESTART_DIR/logs" "$RESTART_DIR/client_vpn" "$RESTART_DIR/wg_only"
touch "$RESTART_DIR/client.env" "$RESTART_DIR/server.env" "$RESTART_DIR/provider.env"

set +e
PATH="$TMP_BIN:$PATH" \
FAKE_DOCKER_ENTRY_EXIT_PRESENT=1 \
FAKE_DOCKER_ENTRY_EXIT_STATE=$'restarting\ttrue\t42' \
FAKE_DOCKER_ENTRY_EXIT_LOGS='node stopped: exit wg pubkey init failed: configured EXIT_WG_PUBKEY does not match EXIT_WG_PRIVATE_KEY_PATH' \
EASY_NODE_DOCTOR_CLIENT_ENV_FILE="$RESTART_DIR/client.env" \
EASY_NODE_DOCTOR_AUTHORITY_ENV_FILE="$RESTART_DIR/server.env" \
EASY_NODE_DOCTOR_PROVIDER_ENV_FILE="$RESTART_DIR/provider.env" \
EASY_NODE_DOCTOR_WG_ONLY_DIR="$RESTART_DIR/wg_only" \
EASY_NODE_DOCTOR_CLIENT_VPN_KEY_DIR="$RESTART_DIR/client_vpn" \
EASY_NODE_DOCTOR_LOG_DIR="$RESTART_DIR/logs" \
EASY_NODE_DOCTOR_WG_ONLY_STATE_FILE="$RESTART_DIR/wg_only.state" \
EASY_NODE_DOCTOR_CLIENT_VPN_STATE_FILE="$RESTART_DIR/client_vpn.state" \
./scripts/runtime_doctor.sh --show-json 1 >/tmp/integration_runtime_doctor_entry_exit_restart.log 2>&1
doctor_restart_rc=$?
set -e

if [[ "$doctor_restart_rc" -eq 0 ]]; then
  echo "expected non-zero rc for entry-exit restart-loop doctor scenario"
  cat /tmp/integration_runtime_doctor_entry_exit_restart.log
  exit 1
fi
if ! rg -q 'entry_exit_exit_wg_pubkey_mismatch' /tmp/integration_runtime_doctor_entry_exit_restart.log; then
  echo "expected entry-exit WG pubkey mismatch finding not found"
  cat /tmp/integration_runtime_doctor_entry_exit_restart.log
  exit 1
fi
if ! rg -q 'prod-preflight --days-min 0' /tmp/integration_runtime_doctor_entry_exit_restart.log; then
  echo "expected prod-preflight remediation hint not found"
  cat /tmp/integration_runtime_doctor_entry_exit_restart.log
  exit 1
fi
if ! extract_json_payload /tmp/integration_runtime_doctor_entry_exit_restart.log | jq -e '.status == "FAIL" and .summary.failures_total >= 1 and (.findings | map(.code) | index("entry_exit_exit_wg_pubkey_mismatch")) != null' >/dev/null 2>&1; then
  echo "runtime doctor entry-exit restart JSON payload missing expected finding"
  cat /tmp/integration_runtime_doctor_entry_exit_restart.log
  exit 1
fi

echo "[runtime-doctor] detect env references to missing local key files"
ENV_REF_DIR="$TMP_DIR/env_ref"
mkdir -p "$ENV_REF_DIR/logs" "$ENV_REF_DIR/client_vpn" "$ENV_REF_DIR/wg_only"
touch "$ENV_REF_DIR/client.env"
NON_TEMP_MISSING_PATH="$ROOT_DIR/deploy/data/integration_runtime_doctor_missing_key_$$.key"
rm -f "$NON_TEMP_MISSING_PATH"
cat >"$ENV_REF_DIR/server.env" <<EOF_ENV_REF
MTLS_CA_FILE=$ENV_REF_DIR/missing-ca.crt
MTLS_SERVER_CERT_FILE=$ENV_REF_DIR/missing-node.crt
EXIT_WG_PRIVATE_KEY_PATH=$ENV_REF_DIR/missing-exit-wg.key
ISSUER_ADMIN_SIGNING_PRIVATE_KEY_FILE_LOCAL=$ENV_REF_DIR/missing-admin-signer.key
EOF_ENV_REF
cat >"$ENV_REF_DIR/provider.env" <<EOF_ENV_REF_PROVIDER
EXIT_WG_PRIVATE_KEY_PATH=$NON_TEMP_MISSING_PATH
EOF_ENV_REF_PROVIDER

set +e
PATH="$TMP_BIN:$PATH" \
EASY_NODE_DOCTOR_CLIENT_ENV_FILE="$ENV_REF_DIR/client.env" \
EASY_NODE_DOCTOR_AUTHORITY_ENV_FILE="$ENV_REF_DIR/server.env" \
EASY_NODE_DOCTOR_PROVIDER_ENV_FILE="$ENV_REF_DIR/provider.env" \
EASY_NODE_DOCTOR_WG_ONLY_DIR="$ENV_REF_DIR/wg_only" \
EASY_NODE_DOCTOR_CLIENT_VPN_KEY_DIR="$ENV_REF_DIR/client_vpn" \
EASY_NODE_DOCTOR_LOG_DIR="$ENV_REF_DIR/logs" \
EASY_NODE_DOCTOR_WG_ONLY_STATE_FILE="$ENV_REF_DIR/wg_only.state" \
EASY_NODE_DOCTOR_CLIENT_VPN_STATE_FILE="$ENV_REF_DIR/client_vpn.state" \
./scripts/runtime_doctor.sh --show-json 1 >/tmp/integration_runtime_doctor_env_refs.log 2>&1
doctor_env_refs_rc=$?
set -e

if [[ "$doctor_env_refs_rc" -eq 0 ]]; then
  echo "expected non-zero rc for missing env referenced files"
  cat /tmp/integration_runtime_doctor_env_refs.log
  exit 1
fi
if ! rg -q 'authority_env_temp_backed_key_material_missing' /tmp/integration_runtime_doctor_env_refs.log; then
  echo "expected temp-backed authority env referenced file finding not found"
  cat /tmp/integration_runtime_doctor_env_refs.log
  exit 1
fi
if ! rg -q 'provider_env_referenced_file_missing' /tmp/integration_runtime_doctor_env_refs.log; then
  echo "expected generic provider env referenced file finding not found"
  cat /tmp/integration_runtime_doctor_env_refs.log
  exit 1
fi
if ! rg -q 'missing-exit-wg.key' /tmp/integration_runtime_doctor_env_refs.log; then
  echo "expected missing EXIT_WG_PRIVATE_KEY_PATH detail not found"
  cat /tmp/integration_runtime_doctor_env_refs.log
  exit 1
fi
if ! rg -q 'stale prod-preflight/bootstrap key material leakage' /tmp/integration_runtime_doctor_env_refs.log; then
  echo "expected temp-backed prod-preflight leakage diagnostic not found"
  cat /tmp/integration_runtime_doctor_env_refs.log
  exit 1
fi
if ! rg -q 'bootstrap-mtls --out-dir deploy/tls --public-host <PUBLIC_HOST>' /tmp/integration_runtime_doctor_env_refs.log; then
  echo "expected bootstrap/server-up remediation hint not found"
  cat /tmp/integration_runtime_doctor_env_refs.log
  exit 1
fi
if ! extract_json_payload /tmp/integration_runtime_doctor_env_refs.log | jq -e '.status == "FAIL" and .summary.failures_total >= 5 and ([.findings[].code] | map(select(. == "authority_env_temp_backed_key_material_missing")) | length) >= 4 and ([.findings[].code] | map(select(. == "provider_env_referenced_file_missing")) | length) >= 1' >/dev/null 2>&1; then
  echo "runtime doctor env referenced file JSON payload missing expected findings"
  cat /tmp/integration_runtime_doctor_env_refs.log
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
