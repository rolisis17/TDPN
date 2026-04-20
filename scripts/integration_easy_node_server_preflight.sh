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

IDENTITY_FILE="$ROOT_DIR/deploy/data/easy_node_identity.conf"
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
  restore_file "$IDENTITY_FILE" "identity_file"
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

backup_file "$IDENTITY_FILE" "identity_file"
mkdir -p "$(dirname "$IDENTITY_FILE")"

cat >"$TMP_BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
url="${@: -1}"

peer_operator="${FAKE_CURL_PEER_OPERATOR_ID:-op-peer}"
peer_issuer="${FAKE_CURL_PEER_ISSUER_ID:-issuer-peer}"

if [[ "${FAKE_CURL_HTTP_ONLY:-0}" == "1" && "$url" == https://203.0.113.10:* ]]; then
  exit 7
fi

case "$url" in
  *"203.0.113.10:8081/v1/relays")
    if [[ "${FAKE_CURL_FAIL_PEER_RELAYS:-0}" == "1" ]]; then
      exit 7
    fi
    printf '{"relays":[{"relay_id":"entry-peer","role":"entry","operator_id":"%s"},{"relay_id":"exit-peer","role":"exit","operator_id":"%s"}]}\n' "$peer_operator" "$peer_operator"
    ;;
  *"203.0.113.10:8082/v1/pubkeys")
    if [[ "${FAKE_CURL_FAIL_PEER_ISSUER:-0}" == "1" ]]; then
      exit 7
    fi
    printf '{"issuer":"%s","pub_keys":["peer-key"]}\n' "$peer_issuer"
    ;;
  *)
    printf '{}\n'
    ;;
esac
EOF_CURL
chmod +x "$TMP_BIN/curl"

set +e
PATH="$TMP_BIN:$PATH" \
FAKE_CURL_HTTP_ONLY=1 \
./scripts/easy_node.sh server-preflight \
  --mode provider \
  --authority-directory http://203.0.113.10:8081 \
  --authority-issuer http://203.0.113.10:8082 \
  --peer-directories http://203.0.113.10:8081 \
  --prod-profile 1 \
  --min-peer-operators 0 >/tmp/integration_easy_node_server_preflight_prod_http_mismatch.log 2>&1
prod_http_mismatch_rc=$?
set -e
if [[ "$prod_http_mismatch_rc" -eq 0 ]]; then
  echo "expected prod-profile provider preflight to fail when authority is non-prod/http"
  cat /tmp/integration_easy_node_server_preflight_prod_http_mismatch.log
  exit 1
fi
if ! rg -q "provider preflight is running with --prod-profile 1, so authority URLs are normalized to https before probing" /tmp/integration_easy_node_server_preflight_prod_http_mismatch.log; then
  echo "missing expected provider prod-profile mismatch diagnostic"
  cat /tmp/integration_easy_node_server_preflight_prod_http_mismatch.log
  exit 1
fi
if ! rg -q "configured authority looks non-prod/http" /tmp/integration_easy_node_server_preflight_prod_http_mismatch.log; then
  echo "missing expected non-prod authority hint"
  cat /tmp/integration_easy_node_server_preflight_prod_http_mismatch.log
  exit 1
fi
if ! rg -q "appears reachable over plain HTTP" /tmp/integration_easy_node_server_preflight_prod_http_mismatch.log; then
  echo "missing expected plain HTTP mismatch hint"
  cat /tmp/integration_easy_node_server_preflight_prod_http_mismatch.log
  exit 1
fi
if ! rg -q "prod profile is fail-closed and requires TLS/mTLS-capable peer and authority endpoints" /tmp/integration_easy_node_server_preflight_prod_http_mismatch.log; then
  echo "missing expected prod fail-closed TLS posture diagnostic"
  cat /tmp/integration_easy_node_server_preflight_prod_http_mismatch.log
  exit 1
fi
if ! rg -q "either run all peered nodes with --prod-profile 1, or use --prod-profile 0 for non-TLS lab peering" /tmp/integration_easy_node_server_preflight_prod_http_mismatch.log; then
  echo "missing expected profile alignment remediation diagnostic"
  cat /tmp/integration_easy_node_server_preflight_prod_http_mismatch.log
  exit 1
fi

PATH="$TMP_BIN:$PATH" \
FAKE_CURL_FAIL_PEER_RELAYS=1 \
./scripts/easy_node.sh server-preflight \
  --mode provider \
  --authority-directory http://203.0.113.10:8081 \
  --authority-issuer http://203.0.113.10:8082 \
  --peer-directories http://203.0.113.10:8081 \
  --beta-profile 1 \
  --min-peer-operators 0 >/tmp/integration_easy_node_server_preflight_auto_relax.log 2>&1

if ! rg -q "auto-relaxed" /tmp/integration_easy_node_server_preflight_auto_relax.log; then
  echo "missing expected auto-relax signal in non-prod auto peer identity mode"
  cat /tmp/integration_easy_node_server_preflight_auto_relax.log
  exit 1
fi
if ! rg -q "server preflight: ok" /tmp/integration_easy_node_server_preflight_auto_relax.log; then
  echo "expected server-preflight auto mode to pass after non-prod auto-relax"
  cat /tmp/integration_easy_node_server_preflight_auto_relax.log
  exit 1
fi

set +e
PATH="$TMP_BIN:$PATH" \
FAKE_CURL_FAIL_PEER_RELAYS=1 \
./scripts/easy_node.sh server-preflight \
  --mode provider \
  --authority-directory http://203.0.113.10:8081 \
  --authority-issuer http://203.0.113.10:8082 \
  --peer-directories http://203.0.113.10:8081 \
  --peer-identity-strict 1 \
  --beta-profile 1 \
  --min-peer-operators 0 >/tmp/integration_easy_node_server_preflight_strict.log 2>&1
strict_rc=$?
set -e
if [[ "$strict_rc" -eq 0 ]]; then
  echo "expected server-preflight explicit strict mode to fail when peer relays are unreachable"
  cat /tmp/integration_easy_node_server_preflight_strict.log
  exit 1
fi
if ! rg -q "peer directory verification incomplete" /tmp/integration_easy_node_server_preflight_strict.log; then
  echo "missing expected strict peer verification failure signal"
  cat /tmp/integration_easy_node_server_preflight_strict.log
  exit 1
fi

PATH="$TMP_BIN:$PATH" \
FAKE_CURL_FAIL_PEER_RELAYS=1 \
./scripts/easy_node.sh server-preflight \
  --mode provider \
  --authority-directory http://203.0.113.10:8081 \
  --authority-issuer http://203.0.113.10:8082 \
  --peer-directories http://203.0.113.10:8081 \
  --peer-identity-strict 0 \
  --beta-profile 1 \
  --min-peer-operators 0 >/tmp/integration_easy_node_server_preflight_bypass.log 2>&1

if ! rg -q "server preflight: ok" /tmp/integration_easy_node_server_preflight_bypass.log; then
  echo "expected server-preflight bypass mode to pass"
  cat /tmp/integration_easy_node_server_preflight_bypass.log
  exit 1
fi

set +e
PATH="$TMP_BIN:$PATH" \
./scripts/easy_node.sh server-preflight \
  --mode provider \
  --authority-directory http://203.0.113.10:8081 \
  --authority-issuer http://203.0.113.10:8082 \
  --peer-directories http://203.0.113.10:8081 \
  --operator-id op-peer \
  --beta-profile 1 \
  --min-peer-operators 0 >/tmp/integration_easy_node_server_preflight_operator_collision.log 2>&1
operator_collision_rc=$?
set -e
if [[ "$operator_collision_rc" -eq 0 ]]; then
  echo "expected server-preflight to fail on operator-id collision"
  cat /tmp/integration_easy_node_server_preflight_operator_collision.log
  exit 1
fi
if ! rg -q "operator_id collision with peers" /tmp/integration_easy_node_server_preflight_operator_collision.log; then
  echo "missing expected operator collision signal"
  cat /tmp/integration_easy_node_server_preflight_operator_collision.log
  exit 1
fi

set +e
PATH="$TMP_BIN:$PATH" \
./scripts/easy_node.sh server-preflight \
  --mode authority \
  --peer-directories http://203.0.113.10:8081 \
  --operator-id op-local-a \
  --issuer-id issuer-peer \
  --beta-profile 1 \
  --min-peer-operators 0 >/tmp/integration_easy_node_server_preflight_issuer_collision.log 2>&1
issuer_collision_rc=$?
set -e
if [[ "$issuer_collision_rc" -eq 0 ]]; then
  echo "expected authority server-preflight to fail on issuer-id collision"
  cat /tmp/integration_easy_node_server_preflight_issuer_collision.log
  exit 1
fi
if ! rg -q "issuer_id collision with peers" /tmp/integration_easy_node_server_preflight_issuer_collision.log; then
  echo "missing expected issuer collision signal"
  cat /tmp/integration_easy_node_server_preflight_issuer_collision.log
  exit 1
fi

# Targeted diagnostics scenario: prod issuer quorum/membership mismatch
# plus mixed-scheme posture warning (HTTPS probe fails, HTTP fallback reachable).
set +e
PATH="$TMP_BIN:$PATH" \
FAKE_CURL_HTTP_ONLY=1 \
./scripts/easy_node.sh server-preflight \
  --mode authority \
  --peer-directories https://203.0.113.10:8081 \
  --prod-profile 1 \
  --min-peer-operators 0 >/tmp/integration_easy_node_server_preflight_prod_issuer_mixed_scheme.log 2>&1
prod_issuer_mixed_scheme_rc=$?
set -e
if [[ "$prod_issuer_mixed_scheme_rc" -eq 0 ]]; then
  echo "expected prod authority preflight to fail when peer issuer quorum cannot be established over HTTPS"
  cat /tmp/integration_easy_node_server_preflight_prod_issuer_mixed_scheme.log
  exit 1
fi
if ! rg -q "prod profile requires at least one reachable peer issuer id" /tmp/integration_easy_node_server_preflight_prod_issuer_mixed_scheme.log; then
  echo "missing expected issuer quorum/membership mismatch diagnostic"
  cat /tmp/integration_easy_node_server_preflight_prod_issuer_mixed_scheme.log
  exit 1
fi
if ! rg -q "peer issuer https://203.0.113.10:8082 appears reachable over plain HTTP" /tmp/integration_easy_node_server_preflight_prod_issuer_mixed_scheme.log; then
  echo "missing expected mixed-scheme peer issuer posture diagnostic"
  cat /tmp/integration_easy_node_server_preflight_prod_issuer_mixed_scheme.log
  exit 1
fi
if ! rg -q "prod profile is fail-closed and requires TLS/mTLS-capable peer and authority endpoints" /tmp/integration_easy_node_server_preflight_prod_issuer_mixed_scheme.log; then
  echo "missing expected prod fail-closed TLS posture diagnostic for mixed-scheme issuer scenario"
  cat /tmp/integration_easy_node_server_preflight_prod_issuer_mixed_scheme.log
  exit 1
fi

set +e
PATH="$TMP_BIN:$PATH" \
FAKE_CURL_FAIL_PEER_ISSUER=1 \
./scripts/easy_node.sh server-preflight \
  --mode authority \
  --peer-directories https://203.0.113.10:8081 \
  --prod-profile 1 \
  --min-peer-operators 0 >/tmp/integration_easy_node_server_preflight_prod_issuer.log 2>&1
prod_issuer_rc=$?
set -e
if [[ "$prod_issuer_rc" -eq 0 ]]; then
  echo "expected prod authority preflight to fail when peer issuer identity is unavailable"
  cat /tmp/integration_easy_node_server_preflight_prod_issuer.log
  exit 1
fi
if ! rg -q "prod profile requires at least one reachable peer issuer id" /tmp/integration_easy_node_server_preflight_prod_issuer.log; then
  echo "missing expected prod issuer readiness failure signal"
  cat /tmp/integration_easy_node_server_preflight_prod_issuer.log
  exit 1
fi

echo "easy-node server preflight integration check ok"
