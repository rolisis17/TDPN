#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq mktemp rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
STATE_FILE="$ROOT_DIR/deploy/data/client_vpn.state"
BACKUP_STATE=""

cleanup() {
  if [[ -n "$BACKUP_STATE" && -f "$BACKUP_STATE" ]]; then
    cp "$BACKUP_STATE" "$STATE_FILE"
    rm -f "$BACKUP_STATE"
  else
    rm -f "$STATE_FILE"
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

mkdir -p "$(dirname "$STATE_FILE")"
if [[ -f "$STATE_FILE" ]]; then
  BACKUP_STATE="$(mktemp)"
  cp "$STATE_FILE" "$BACKUP_STATE"
fi

STATUS_JSON="$TMP_DIR/client_status.json"
cat >"$STATUS_JSON" <<'JSON'
{
  "path_mode": "2hop",
  "session_active": true,
  "entry_relay_id": "entry-a",
  "exit_relay_id": "exit-a",
  "control_url": "https://user:pw-secret@control.example:8083?token=control-secret",
  "endpoint": "https://user:pw-secret@endpoint.example:8084?token=endpoint-secret",
  "directory_urls": [
    "https://user:pw-secret@dir.example:8081?token=dir-secret"
  ],
  "nested": {
    "issuer_url": "https://user:pw-secret@issuer.example:8082?token=issuer-secret"
  }
}
JSON

cat >"$STATE_FILE" <<EOF_STATE
CLIENT_VPN_PID=999999
CLIENT_VPN_IFACE=wgvpn-test
CLIENT_VPN_LOG_FILE=$TMP_DIR/missing.log
CLIENT_VPN_STATUS_FILE=$STATUS_JSON
CLIENT_VPN_KEY_FILE=$TMP_DIR/client.key
CLIENT_VPN_TRUST_FILE=$TMP_DIR/trusted.txt
CLIENT_VPN_TRUST_SCOPE=scoped
CLIENT_VPN_PROXY_ADDR=127.0.0.1:18080
CLIENT_VPN_DIRECTORY_URLS=https://user:pw-secret@dir.example:8081?token=dir-secret,https://user:pw-secret@dir-b.example:8081?token=dir-secret-b
CLIENT_VPN_ISSUER_URL=https://user:pw-secret@issuer.example:8082?token=issuer-secret
CLIENT_VPN_ISSUER_URLS=https://user:pw-secret@issuer.example:8082?token=issuer-secret
CLIENT_VPN_ENTRY_URL=https://user:pw-secret@entry.example:8083?token=entry-secret
CLIENT_VPN_EXIT_URL=https://user:pw-secret@exit.example:8084?token=exit-secret
CLIENT_VPN_PATH_PROFILE=balanced
CLIENT_VPN_ALLOWED_IPS=0.0.0.0/0
CLIENT_VPN_INSTALL_ROUTE=0
CLIENT_VPN_ROUTE_MODE=no-route
CLIENT_VPN_SESSION_REUSE=1
CLIENT_VPN_ALLOW_SESSION_CHURN=0
CLIENT_VPN_BETA_PROFILE=1
CLIENT_VPN_PROD_PROFILE=0
EOF_STATE

echo "[client-vpn-status] redacts URL credentials in human output"
./scripts/easy_node.sh client-vpn-status >"$TMP_DIR/status.txt" 2>&1

echo "[client-vpn-status] redacts URL credentials in JSON output"
./scripts/easy_node.sh client-vpn-status --show-json 1 >"$TMP_DIR/status.json" 2>&1

for forbidden in 'pw-secret' 'token=' 'control.example:8083' 'endpoint.example:8084'; do
  if grep -F -- "$forbidden" "$TMP_DIR/status.txt" "$TMP_DIR/status.json" >/dev/null; then
    echo "client-vpn-status leaked forbidden value: $forbidden"
    cat "$TMP_DIR/status.txt"
    cat "$TMP_DIR/status.json"
    exit 1
  fi
done

if ! jq -e '
  .directory_urls == "https://dir.example:8081,https://dir-b.example:8081"
  and .issuer_url == "https://issuer.example:8082"
  and .issuer_urls == "https://issuer.example:8082"
  and .entry_url == "https://entry.example:8083"
  and .exit_url == "https://exit.example:8084"
  and .client_status.control_url == "[redacted]"
  and .client_status.endpoint == "[redacted]"
  and .client_status.directory_urls[0] == "[redacted]"
  and .client_status.nested.issuer_url == "[redacted]"
' "$TMP_DIR/status.json" >/dev/null; then
  echo "client-vpn-status JSON missing expected redacted fields"
  cat "$TMP_DIR/status.json"
  exit 1
fi

echo "client vpn status redaction integration check ok"
