#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in chmod grep jq mktemp rg; do
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
LOG_FILE="$TMP_DIR/client.log"
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
cat >"$LOG_FILE" <<'LOG'
client connected to https://user:pw-secret@control.example:8083?token=control-secret
endpoint=https://user:pw-secret@endpoint.example:8084?token=endpoint-secret
LOG

cat >"$STATE_FILE" <<EOF_STATE
CLIENT_VPN_PID=999999
CLIENT_VPN_IFACE=wgvpn-test
CLIENT_VPN_LOG_FILE=$LOG_FILE
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

TMP_BIN="$TMP_DIR/bin"
mkdir -p "$TMP_BIN"
cat >"$TMP_BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
url="${@: -1}"
case "$url" in
  */v1/pubkeys)
    printf '{"issuer":"issuer-a","pub_keys":["k1"]}\n'
    ;;
  */v1/health)
    printf '{"ok":true}\n'
    ;;
  *)
    printf '{}\n'
    ;;
esac
EOF_CURL
cat >"$TMP_BIN/go" <<'EOF_GO'
#!/usr/bin/env bash
set -euo pipefail
exit 0
EOF_GO
cat >"$TMP_BIN/wg" <<'EOF_WG'
#!/usr/bin/env bash
set -euo pipefail
exit 0
EOF_WG
cat >"$TMP_BIN/ip" <<'EOF_IP'
#!/usr/bin/env bash
set -euo pipefail
exit 0
EOF_IP
cat >"$TMP_BIN/timeout" <<'EOF_TIMEOUT'
#!/usr/bin/env bash
set -euo pipefail
if [[ $# -gt 0 && "$1" =~ ^[0-9]+$ ]]; then
  shift
fi
"$@"
EOF_TIMEOUT
chmod +x "$TMP_BIN/curl" "$TMP_BIN/go" "$TMP_BIN/wg" "$TMP_BIN/ip" "$TMP_BIN/timeout"

echo "[client-vpn-preflight] redacts URL credentials in output"
PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh client-vpn-preflight \
  --directory-urls "https://user:pw-secret@dir.example:8081?token=dir-secret" \
  --issuer-url "https://user:pw-secret@issuer.example:8082?token=issuer-secret" \
  --entry-url "https://user:pw-secret@entry.example:8083?token=entry-secret" \
  --exit-url "https://user:pw-secret@exit.example:8084?token=exit-secret" \
  --require-root 0 \
  --timeout-sec 1 \
  --operator-floor-check 0 \
  --issuer-quorum-check 0 >"$TMP_DIR/preflight.log" 2>&1
for forbidden in 'pw-secret' 'token='; do
  if grep -F -- "$forbidden" "$TMP_DIR/preflight.log" >/dev/null; then
    echo "client-vpn-preflight leaked forbidden value: $forbidden"
    cat "$TMP_DIR/preflight.log"
    exit 1
  fi
done
for expected in 'https://dir.example:8081' 'https://issuer.example:8082' 'https://entry.example:8083' 'https://exit.example:8084'; do
  if ! grep -F -- "$expected" "$TMP_DIR/preflight.log" >/dev/null; then
    echo "client-vpn-preflight missing expected redacted URL: $expected"
    cat "$TMP_DIR/preflight.log"
    exit 1
  fi
done

echo "client vpn status redaction integration check ok"
