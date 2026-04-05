#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

AUTH_ENV="$ROOT_DIR/deploy/.env.easy.server"
PROVIDER_ENV="$ROOT_DIR/deploy/.env.easy.provider"
MODE_FILE="$ROOT_DIR/deploy/data/easy_node_server_mode.conf"
IDENTITY_FILE="$ROOT_DIR/deploy/data/easy_node_identity.conf"
HOSTS_FILE="$ROOT_DIR/data/easy_mode_hosts.conf"

TMP_DIR="$(mktemp -d)"
TMP_BIN="$TMP_DIR/bin"
mkdir -p "$TMP_BIN"

backup_file() {
  local src="$1"
  local name="$2"
  if [[ -f "$src" ]]; then
    cp "$src" "$TMP_DIR/${name}.bak"
  fi
}

restore_file() {
  local dst="$1"
  local name="$2"
  if [[ -f "$TMP_DIR/${name}.bak" ]]; then
    cp "$TMP_DIR/${name}.bak" "$dst"
  else
    rm -f "$dst"
  fi
}

cleanup() {
  restore_file "$AUTH_ENV" "auth_env"
  restore_file "$PROVIDER_ENV" "provider_env"
  restore_file "$MODE_FILE" "mode_file"
  restore_file "$IDENTITY_FILE" "identity_file"
  restore_file "$HOSTS_FILE" "hosts_file"
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

backup_file "$AUTH_ENV" "auth_env"
backup_file "$PROVIDER_ENV" "provider_env"
backup_file "$MODE_FILE" "mode_file"
backup_file "$IDENTITY_FILE" "identity_file"
backup_file "$HOSTS_FILE" "hosts_file"

cat >"$TMP_BIN/docker" <<'EOF_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "compose" && "${2:-}" == "version" ]]; then
  echo "Docker Compose version vtest"
  exit 0
fi
if [[ "${1:-}" == "compose" ]]; then
  exit 0
fi
if [[ "${1:-}" == "--version" ]]; then
  echo "Docker version test"
  exit 0
fi
if [[ "${1:-}" == "info" ]]; then
  exit 0
fi
exit 0
EOF_DOCKER

cat >"$TMP_BIN/wg" <<'EOF_WG'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "genkey" ]]; then
  echo "test-wg-private-key"
  exit 0
fi
exit 0
EOF_WG

cat >"$TMP_BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
url="${@: -1}"

peer_operator="${FAKE_CURL_PEER_OPERATOR_ID:-op-peer}"
peer_issuer="${FAKE_CURL_PEER_ISSUER_ID:-issuer-peer}"
peer_control_host="${FAKE_CURL_PEER_CONTROL_HOST:-203.0.113.10}"

case "$url" in
  *"203.0.113.10:8081/v1/relays")
    if [[ "${FAKE_CURL_FAIL_PEER_RELAYS:-0}" == "1" ]]; then
      exit 7
    fi
    printf '{"relays":[{"relay_id":"entry-peer","role":"entry","operator_id":"%s","control_url":"http://%s:8083"},{"relay_id":"exit-peer","role":"exit","operator_id":"%s","control_url":"http://%s:8084"}]}\n' "$peer_operator" "$peer_control_host" "$peer_operator" "$peer_control_host"
    ;;
  *"127.0.0.1:8081/v1/relays")
    printf '{"relays":[{"relay_id":"entry-local","role":"entry","operator_id":"op-local"},{"relay_id":"exit-local","role":"exit","operator_id":"op-local"}]}\n'
    ;;
  *"203.0.113.10:8082/v1/pubkeys")
    if [[ "${FAKE_CURL_FAIL_PEER_ISSUER:-0}" == "1" ]]; then
      exit 7
    fi
    printf '{"issuer":"%s","pub_keys":["peer-key"]}\n' "$peer_issuer"
    ;;
  *"127.0.0.1:8082/v1/pubkeys")
    printf '{"issuer":"issuer-local","pub_keys":["local-key"]}\n'
    ;;
  *"/v1/health"|*"/v1/peers"|*"/v1/metrics")
    printf '{}\n'
    ;;
  *)
    printf '{}\n'
    ;;
esac
EOF_CURL

chmod +x "$TMP_BIN/docker" "$TMP_BIN/wg" "$TMP_BIN/curl"

reset_local_state() {
  rm -f "$PROVIDER_ENV" "$AUTH_ENV" "$MODE_FILE" "$IDENTITY_FILE"
}

reset_local_state

set +e
PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
FAKE_CURL_FAIL_PEER_RELAYS=1 \
./scripts/easy_node.sh server-up \
  --mode provider \
  --public-host 198.51.100.20 \
  --authority-directory http://203.0.113.10:8081 \
  --authority-issuer http://203.0.113.10:8082 \
  --peer-directories http://203.0.113.10:8081 \
  --beta-profile 1 >/tmp/integration_easy_node_peer_identity_guard_strict.log 2>&1
strict_rc=$?
set -e
if [[ "$strict_rc" -eq 0 ]]; then
  echo "expected server-up to fail when strict peer identity check cannot verify peer directory"
  cat /tmp/integration_easy_node_peer_identity_guard_strict.log
  exit 1
fi
if ! rg -q "could not verify operator-id uniqueness against peer directories" /tmp/integration_easy_node_peer_identity_guard_strict.log; then
  echo "missing expected strict peer-identity failure message"
  cat /tmp/integration_easy_node_peer_identity_guard_strict.log
  exit 1
fi

reset_local_state

PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
FAKE_CURL_FAIL_PEER_RELAYS=1 \
./scripts/easy_node.sh server-up \
  --mode provider \
  --public-host 198.51.100.20 \
  --authority-directory http://203.0.113.10:8081 \
  --authority-issuer http://203.0.113.10:8082 \
  --peer-directories http://203.0.113.10:8081 \
  --peer-identity-strict 0 \
  --beta-profile 1 >/tmp/integration_easy_node_peer_identity_guard_bypass.log 2>&1

if ! rg -q "warning: operator-id uniqueness check skipped" /tmp/integration_easy_node_peer_identity_guard_bypass.log; then
  echo "expected warning when bypassing peer identity strict mode"
  cat /tmp/integration_easy_node_peer_identity_guard_bypass.log
  exit 1
fi
if ! rg -q "server stack started" /tmp/integration_easy_node_peer_identity_guard_bypass.log; then
  echo "expected provider stack startup when peer identity strict bypass is enabled"
  cat /tmp/integration_easy_node_peer_identity_guard_bypass.log
  exit 1
fi

reset_local_state

set +e
PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
./scripts/easy_node.sh server-up \
  --mode provider \
  --public-host 198.51.100.20 \
  --authority-directory http://203.0.113.10:8081 \
  --authority-issuer http://203.0.113.10:8082 \
  --peer-directories http://203.0.113.10:8081 \
  --operator-id op-peer \
  --beta-profile 1 >/tmp/integration_easy_node_peer_identity_guard_operator_collision.log 2>&1
operator_collision_rc=$?
set -e
if [[ "$operator_collision_rc" -eq 0 ]]; then
  echo "expected server-up to fail on explicit operator-id collision"
  cat /tmp/integration_easy_node_peer_identity_guard_operator_collision.log
  exit 1
fi
if ! rg -q -- "--operator-id 'op-peer' already exists on peer directories" /tmp/integration_easy_node_peer_identity_guard_operator_collision.log; then
  echo "missing expected operator-id collision failure message"
  cat /tmp/integration_easy_node_peer_identity_guard_operator_collision.log
  exit 1
fi

reset_local_state

PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
FAKE_CURL_PEER_OPERATOR_ID=op-self \
FAKE_CURL_PEER_CONTROL_HOST=198.51.100.20 \
./scripts/easy_node.sh server-up \
  --mode provider \
  --public-host 198.51.100.20 \
  --authority-directory http://203.0.113.10:8081 \
  --authority-issuer http://203.0.113.10:8082 \
  --peer-directories http://203.0.113.10:8081 \
  --operator-id op-self \
  --beta-profile 1 >/tmp/integration_easy_node_peer_identity_guard_self_echo.log 2>&1

if ! rg -q "server stack started" /tmp/integration_easy_node_peer_identity_guard_self_echo.log; then
  echo "expected server-up to allow self-echoed operator-id from peer relay cache"
  cat /tmp/integration_easy_node_peer_identity_guard_self_echo.log
  exit 1
fi
if rg -q -- "--operator-id 'op-self' already exists on peer directories" /tmp/integration_easy_node_peer_identity_guard_self_echo.log; then
  echo "self-echo operator-id should not be treated as collision"
  cat /tmp/integration_easy_node_peer_identity_guard_self_echo.log
  exit 1
fi

reset_local_state

set +e
PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
./scripts/easy_node.sh server-up \
  --mode authority \
  --public-host 198.51.100.20 \
  --peer-directories http://203.0.113.10:8081 \
  --operator-id op-local-a \
  --issuer-id issuer-peer \
  --beta-profile 1 >/tmp/integration_easy_node_peer_identity_guard_issuer_collision.log 2>&1
issuer_collision_rc=$?
set -e
if [[ "$issuer_collision_rc" -eq 0 ]]; then
  echo "expected authority server-up to fail on explicit issuer-id collision"
  cat /tmp/integration_easy_node_peer_identity_guard_issuer_collision.log
  exit 1
fi
if ! rg -q -- "--issuer-id 'issuer-peer' already exists on peer directories" /tmp/integration_easy_node_peer_identity_guard_issuer_collision.log; then
  echo "missing expected issuer-id collision failure message"
  cat /tmp/integration_easy_node_peer_identity_guard_issuer_collision.log
  exit 1
fi

reset_local_state

PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
FAKE_CURL_FAIL_PEER_ISSUER=1 \
./scripts/easy_node.sh server-up \
  --mode authority \
  --public-host 198.51.100.20 \
  --peer-directories http://203.0.113.10:8081 \
  --beta-profile 1 >/tmp/integration_easy_node_peer_identity_guard_authority_provider_auto.log 2>&1

if ! rg -q "peer issuer identity strict checks auto-relaxed" /tmp/integration_easy_node_peer_identity_guard_authority_provider_auto.log; then
  echo "expected authority auto-relax note when peer issuer is unreachable in non-prod auto strict mode"
  cat /tmp/integration_easy_node_peer_identity_guard_authority_provider_auto.log
  exit 1
fi
if ! rg -q "warning: issuer-id uniqueness check skipped" /tmp/integration_easy_node_peer_identity_guard_authority_provider_auto.log; then
  echo "expected issuer-id warning after authority auto-relax path"
  cat /tmp/integration_easy_node_peer_identity_guard_authority_provider_auto.log
  exit 1
fi
if ! rg -q "server stack started" /tmp/integration_easy_node_peer_identity_guard_authority_provider_auto.log; then
  echo "expected authority stack startup for provider-only peer in auto strict mode"
  cat /tmp/integration_easy_node_peer_identity_guard_authority_provider_auto.log
  exit 1
fi

echo "easy-node peer identity guard integration check ok"
