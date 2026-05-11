#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in go jq mktemp curl sha256sum tr; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "access bridge service serve integration failed: missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
BRIDGE_PID=""
cleanup() {
  if [[ -n "$BRIDGE_PID" ]]; then
    kill "$BRIDGE_PID" >/dev/null 2>&1 || true
    wait "$BRIDGE_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

BUNDLE_DIR="$TMP_DIR/access-recovery-demo"
PORT="${ACCESS_BRIDGE_TEST_PORT:-19789}"
BASE_URL="http://127.0.0.1:${PORT}"
CODE_FILE="$TMP_DIR/bridge-code.txt"
CODE_HASH_JSON="$TMP_DIR/bridge-code-hash.json"
SERVICE_CONFIG="$TMP_DIR/bridge-service-config.json"
DEPLOY_PACK="$TMP_DIR/bridge-deploy-pack"
ABUSE_LOG="$TMP_DIR/bridge-abuse.jsonl"
SERVER_LOG="$TMP_DIR/bridge-service.log"

go run ./cmd/gpmrecover demo-bundle \
  --out-dir "$BUNDLE_DIR" \
  --org-id serve-org \
  --org-name "Serve Org" \
  --base-url https://serve.gpm-pilot.net \
  --helper-id helper-serve \
  --helper-name "Serve Helper" \
  --helper-url https://helper.gpm-pilot.net/serve/bootstrap \
  --helper-contact mailto:helper-serve@example.com \
  >"$TMP_DIR/demo-bundle.stdout.json"

trust_store="$(jq -r '.files.trust_store' "$BUNDLE_DIR/demo-manifest.json")"
bridge_invite="$(jq -r '.files.bridge_invite_signed' "$BUNDLE_DIR/demo-manifest.json")"
signed_registry="$(jq -r '.files.bridge_helper_registry_signed' "$BUNDLE_DIR/demo-manifest.json")"

go run ./cmd/gpmrecover bridge-service-config \
  --invite "$bridge_invite" \
  --trust-store "$trust_store" \
  --signed-helper-registry "$signed_registry" \
  --out "$SERVICE_CONFIG" >/dev/null
config_sha256="$(sha256sum "$SERVICE_CONFIG" | awk '{print $1}')"
go run ./cmd/gpmrecover bridge-service-code-generate --code-out "$CODE_FILE" --hash-out "$CODE_HASH_JSON" >/dev/null
code_value="$(tr -d '\r\n' <"$CODE_FILE")"
code_hash="$(jq -r '.sha256' "$CODE_HASH_JSON")"

go run ./cmd/gpmrecover bridge-service-deploy-pack \
  --out-dir "$DEPLOY_PACK" \
  --service-name gpm-access-bridge-serve \
  --install-dir /etc/gpm/access-bridge-serve \
  --config /etc/gpm/access-bridge-serve/bridge-service-config.json \
  --config-sha256 "$config_sha256" \
  --access-code-sha256 "$code_hash" >/dev/null

go run ./cmd/gpmrecover bridge-service-serve \
  --config "$SERVICE_CONFIG" \
  --config-sha256 "$config_sha256" \
  --addr "127.0.0.1:${PORT}" \
  --rps 20 \
  --abuse-log "$ABUSE_LOG" \
  --access-code-sha256 "$code_hash" \
  >"$SERVER_LOG" 2>&1 &
BRIDGE_PID=$!

for _ in $(seq 1 60); do
  if curl -fsS "${BASE_URL}/health" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$BRIDGE_PID" >/dev/null 2>&1; then
    echo "access bridge service serve integration failed: server exited early"
    cat "$SERVER_LOG"
    exit 1
  fi
  sleep 0.5
done

if ! curl -fsS "${BASE_URL}/health" >/dev/null 2>&1; then
  echo "access bridge service serve integration failed: health did not become ready"
  cat "$SERVER_LOG"
  exit 1
fi

missing_code_status="$(curl -sS -o "$TMP_DIR/missing-code.json" -w '%{http_code}' "${BASE_URL}/bridge/helper-web")"
if [[ "$missing_code_status" != "401" ]]; then
  echo "access bridge service serve integration failed: expected missing code 401, got $missing_code_status"
  cat "$TMP_DIR/missing-code.json"
  exit 1
fi

headers_file="$TMP_DIR/bridge.headers"
allowed_body="$TMP_DIR/bridge.allowed.json"
allowed_status="$(curl -sS -D "$headers_file" -H "X-GPM-Bridge-Code: ${code_value}" -o "$allowed_body" -w '%{http_code}' "${BASE_URL}/bridge/helper-web")"
if [[ "$allowed_status" != "200" ]]; then
  echo "access bridge service serve integration failed: expected allowed code 200, got $allowed_status"
  cat "$allowed_body"
  exit 1
fi
if [[ "$(jq -r '.status // ""' "$allowed_body")" != "ok" ]]; then
  echo "access bridge service serve integration failed: allowed response was not ok"
  cat "$allowed_body"
  exit 1
fi
if ! grep -iq '^Referrer-Policy: no-referrer' "$headers_file" ||
  ! grep -iq '^Cache-Control: no-store' "$headers_file" ||
  ! grep -iq '^X-Content-Type-Options: nosniff' "$headers_file"; then
  echo "access bridge service serve integration failed: security headers missing"
  cat "$headers_file"
  exit 1
fi

abuse_status="$(curl -sS -X POST -H 'Content-Type: application/json' -d '{"path_id":"helper-web","message":"serve smoke"}' -o "$TMP_DIR/abuse.json" -w '%{http_code}' "${BASE_URL}/abuse")"
if [[ "$abuse_status" != "202" ]]; then
  echo "access bridge service serve integration failed: expected abuse 202, got $abuse_status"
  cat "$TMP_DIR/abuse.json"
  exit 1
fi
if ! grep -q '"message":"serve smoke"' "$ABUSE_LOG"; then
  echo "access bridge service serve integration failed: abuse log missing report"
  cat "$ABUSE_LOG"
  exit 1
fi

bash ./scripts/access_bridge_service_smoke.sh \
  --base-url "$BASE_URL" \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --expect-helper-id helper-serve \
  --expect-org-id serve-org \
  --expect-registry-id "$(jq -r '.registry_id' "$SERVICE_CONFIG")" \
  --summary-json "$TMP_DIR/operator-smoke-summary.json" \
  --abuse-message "operator smoke" >/dev/null
if [[ "$(jq -r '.status // ""' "$TMP_DIR/operator-smoke-summary.json")" != "pass" ]]; then
  echo "access bridge service serve integration failed: operator smoke summary not pass"
  cat "$TMP_DIR/operator-smoke-summary.json"
  exit 1
fi
if [[ "$(jq -r '.health.config_sha256 // ""' "$TMP_DIR/operator-smoke-summary.json")" != "$config_sha256" ]]; then
  echo "access bridge service serve integration failed: operator smoke did not capture live config sha256"
  cat "$TMP_DIR/operator-smoke-summary.json"
  exit 1
fi
if ! jq -e '
    .schema.minor >= 3
    and .transport.base_url_scheme == "http"
    and .transport.loopback == true
    and .transport.https == false
    and .transport.tls.checked == false
    and .transport.tls.verified == false
    and .transport.mtls.required == false
    and .transport.mtls.client_certificate_configured == false
    and .transport.mtls.client_certificate_used == false
  ' "$TMP_DIR/operator-smoke-summary.json" >/dev/null; then
  echo "access bridge service serve integration failed: operator smoke did not capture expected transport facts"
  cat "$TMP_DIR/operator-smoke-summary.json"
  exit 1
fi

set +e
bash ./scripts/access_bridge_service_smoke.sh \
  --base-url "$BASE_URL" \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --require-mtls 1 \
  --summary-json "$TMP_DIR/operator-smoke-require-mtls-http-summary.json" \
  --abuse-message "operator smoke require mtls over http" >/dev/null 2>"$TMP_DIR/operator-smoke-require-mtls-http.stderr"
require_mtls_http_rc=$?
set -e
if [[ "$require_mtls_http_rc" -eq 0 ]]; then
  echo "access bridge service serve integration failed: require-mtls over HTTP unexpectedly passed"
  cat "$TMP_DIR/operator-smoke-require-mtls-http-summary.json"
  exit 1
fi
if ! jq -e '
    .status == "fail"
    and .transport.https == false
    and .transport.mtls.required == true
    and .transport.mtls.client_certificate_used == false
    and (.notes | contains("mTLS"))
  ' "$TMP_DIR/operator-smoke-require-mtls-http-summary.json" >/dev/null; then
  echo "access bridge service serve integration failed: require-mtls over HTTP summary mismatch"
  cat "$TMP_DIR/operator-smoke-require-mtls-http-summary.json"
  exit 1
fi

FAKE_CURL_DIR="$TMP_DIR/fake-curl-bin"
mkdir -p "$FAKE_CURL_DIR"
cat >"$FAKE_CURL_DIR/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

scenario="${ACCESS_BRIDGE_FAKE_CURL_SCENARIO:-app_403}"
out_file=""
headers_file=""
write_out=""
has_cert="0"
url=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o)
      out_file="${2:-}"
      shift 2
      ;;
    -D)
      headers_file="${2:-}"
      shift 2
      ;;
    -w)
      write_out="${2:-}"
      shift 2
      ;;
    --cert)
      has_cert="1"
      shift 2
      ;;
    --cacert|--key|--config|-H|-d|-X)
      shift 2
      ;;
    -s|-S|-f|-sS|-fsS)
      shift
      ;;
    --*)
      shift
      ;;
    *)
      url="$1"
      shift
      ;;
  esac
done

write_body() {
  local body="${1:-}"
  if [[ -n "$out_file" ]]; then
    printf '%s' "$body" >"$out_file"
  else
    printf '%s' "$body"
  fi
}

emit_write_out() {
  local http_code="$1"
  local ssl_verify_result="${2:-0}"
  local remote_ip="${3:-203.0.113.10}"
  local remote_port="${4:-443}"
  local http_version="${5:-1.1}"
  local time_connect="${6:-0.001000}"
  local time_appconnect="${7:-0.002000}"
  local rendered="$write_out"
  rendered="${rendered//\%\{http_code\}/$http_code}"
  rendered="${rendered//\%\{ssl_verify_result\}/$ssl_verify_result}"
  rendered="${rendered//\%\{remote_ip\}/$remote_ip}"
  rendered="${rendered//\%\{remote_port\}/$remote_port}"
  rendered="${rendered//\%\{http_version\}/$http_version}"
  rendered="${rendered//\%\{time_connect\}/$time_connect}"
  rendered="${rendered//\%\{time_appconnect\}/$time_appconnect}"
  rendered="${rendered//\%\{url_effective\}/$url}"
  printf '%s' "$rendered"
}

if [[ "$url" == */health ]]; then
  if [[ "$has_cert" == "1" ]]; then
    write_body '{"status":"ok","decision":{"helper_id":"helper-fake","organization_id":"org-fake","registry_id":"registry-fake"},"config_sha256":"fake-config-sha256"}'
    emit_write_out "200"
    exit 0
  fi
  if [[ "$scenario" == "proxy_496" ]]; then
    write_body '{"error":"client certificate required"}'
    emit_write_out "496"
    exit 0
  fi
  if [[ "$scenario" == "tls_000" ]]; then
    write_body ''
    printf 'curl: (56) OpenSSL SSL_read: tlsv13 alert certificate required, errno 0\n' >&2
    emit_write_out "000" "0" "" ""
    exit 56
  fi
  write_body '{"error":"mTLS required"}'
  emit_write_out "403"
  exit 0
fi

if [[ "$url" == */bridge/helper-web ]]; then
  if [[ -n "$headers_file" ]]; then
    {
      printf 'HTTP/1.1 200 OK\r\n'
      printf 'Referrer-Policy: no-referrer\r\n'
      printf 'Cache-Control: no-store\r\n'
      printf 'X-Content-Type-Options: nosniff\r\n'
      printf '\r\n'
    } >"$headers_file"
    write_body '{"status":"ok"}'
    emit_write_out "200"
  else
    write_body '{"status":"denied"}'
    emit_write_out "401"
  fi
  exit 0
fi

if [[ "$url" == */abuse ]]; then
  write_body '{"status":"accepted"}'
  emit_write_out "202"
  exit 0
fi

write_body '{"status":"not_found"}'
emit_write_out "404"
EOF
chmod +x "$FAKE_CURL_DIR/curl"
FAKE_CERT="$TMP_DIR/fake-client.crt"
FAKE_KEY="$TMP_DIR/fake-client.key"
FAKE_CA="$TMP_DIR/fake-ca.crt"
printf 'fake cert\n' >"$FAKE_CERT"
printf 'fake key\n' >"$FAKE_KEY"
printf 'fake ca\n' >"$FAKE_CA"

set +e
ACCESS_BRIDGE_FAKE_CURL_SCENARIO=app_403 PATH="$FAKE_CURL_DIR:$PATH" bash ./scripts/access_bridge_service_smoke.sh \
  --base-url "https://bridge-fake.example.test" \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --cacert "$FAKE_CA" \
  --client-cert "$FAKE_CERT" \
  --client-key "$FAKE_KEY" \
  --require-mtls 1 \
  --summary-json "$TMP_DIR/operator-smoke-require-mtls-app-403-summary.json" \
  --abuse-message "operator smoke require mtls app 403" >/dev/null 2>"$TMP_DIR/operator-smoke-require-mtls-app-403.stderr"
require_mtls_app_403_rc=$?
set -e
if [[ "$require_mtls_app_403_rc" -eq 0 ]]; then
  echo "access bridge service serve integration failed: app-level 403 mTLS text unexpectedly proved missing-client rejection"
  cat "$TMP_DIR/operator-smoke-require-mtls-app-403-summary.json"
  exit 1
fi
if ! jq -e '
    .status == "fail"
    and .transport.https == true
    and .transport.tls.verified == true
    and .transport.mtls.required == true
    and .transport.mtls.missing_client_certificate_health_http_status == "403"
    and .transport.mtls.missing_client_certificate_rejection_signal == false
    and .transport.mtls.missing_client_certificate_rejected == false
    and (.notes | contains("missing-client-certificate rejection was not proven"))
  ' "$TMP_DIR/operator-smoke-require-mtls-app-403-summary.json" >/dev/null; then
  echo "access bridge service serve integration failed: app-level 403 mTLS summary mismatch"
  cat "$TMP_DIR/operator-smoke-require-mtls-app-403-summary.json"
  exit 1
fi

ACCESS_BRIDGE_FAKE_CURL_SCENARIO=proxy_496 PATH="$FAKE_CURL_DIR:$PATH" bash ./scripts/access_bridge_service_smoke.sh \
  --base-url "https://bridge-fake.example.test" \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --cacert "$FAKE_CA" \
  --client-cert "$FAKE_CERT" \
  --client-key "$FAKE_KEY" \
  --require-mtls 1 \
  --summary-json "$TMP_DIR/operator-smoke-require-mtls-proxy-496-summary.json" \
  --abuse-message "operator smoke require mtls proxy 496" >/dev/null
if ! jq -e '
    .status == "pass"
    and .transport.mtls.missing_client_certificate_health_http_status == "496"
    and .transport.mtls.missing_client_certificate_rejection_signal == true
    and .transport.mtls.missing_client_certificate_rejected == true
    and .transport.mtls.client_certificate_used == true
  ' "$TMP_DIR/operator-smoke-require-mtls-proxy-496-summary.json" >/dev/null; then
  echo "access bridge service serve integration failed: proxy-native 496 mTLS summary mismatch"
  cat "$TMP_DIR/operator-smoke-require-mtls-proxy-496-summary.json"
  exit 1
fi

ACCESS_BRIDGE_FAKE_CURL_SCENARIO=tls_000 PATH="$FAKE_CURL_DIR:$PATH" bash ./scripts/access_bridge_service_smoke.sh \
  --base-url "https://bridge-fake.example.test" \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --cacert "$FAKE_CA" \
  --client-cert "$FAKE_CERT" \
  --client-key "$FAKE_KEY" \
  --require-mtls 1 \
  --summary-json "$TMP_DIR/operator-smoke-require-mtls-tls-000-summary.json" \
  --abuse-message "operator smoke require mtls tls 000" >/dev/null
if ! jq -e '
    .status == "pass"
    and .transport.mtls.missing_client_certificate_health_http_status == "000"
    and .transport.mtls.missing_client_certificate_health_curl_rc == 56
    and (.transport.mtls.missing_client_certificate_health_curl_error | contains("alert certificate required"))
    and .transport.mtls.missing_client_certificate_rejection_signal == true
    and .transport.mtls.missing_client_certificate_rejected == true
    and .transport.mtls.client_certificate_used == true
  ' "$TMP_DIR/operator-smoke-require-mtls-tls-000-summary.json" >/dev/null; then
  echo "access bridge service serve integration failed: TLS-layer 000 mTLS summary mismatch"
  cat "$TMP_DIR/operator-smoke-require-mtls-tls-000-summary.json"
  exit 1
fi

bash ./scripts/access_bridge_deployment_evidence.sh \
  --base-url "$BASE_URL" \
  --path-id helper-web \
  --code-file "$CODE_FILE" \
  --expect-helper-id helper-serve \
  --expect-org-id serve-org \
  --expect-registry-id "$(jq -r '.registry_id' "$SERVICE_CONFIG")" \
  --config-json "$SERVICE_CONFIG" \
  --deploy-pack-dir "$DEPLOY_PACK" \
  --service-name gpm-access-bridge-serve \
  --summary-json "$TMP_DIR/operator-deployment-evidence-summary.json" \
  --abuse-message "operator deployment evidence" \
  --print-summary-json 0 >/dev/null
if [[ "$(jq -r '.status // ""' "$TMP_DIR/operator-deployment-evidence-summary.json")" != "pass" ]]; then
  echo "access bridge service serve integration failed: deployment evidence summary not pass"
  cat "$TMP_DIR/operator-deployment-evidence-summary.json"
  exit 1
fi

echo "access bridge service serve integration check ok"
