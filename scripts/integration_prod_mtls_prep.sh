#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing dependency: $1" >&2
    exit 2
  fi
}

need_cmd jq
need_cmd openssl
need_cmd rg
need_cmd curl

tmp_dir="$(mktemp -d)"
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

invalid_log="$tmp_dir/invalid_host.log"
if ./scripts/prod_mtls_prep.sh \
  --authority-host https://example.com:8081 \
  --provider-host 198.51.100.20 \
  --out-dir "$tmp_dir/invalid" >"$invalid_log" 2>&1; then
  echo "expected prod-mtls-prep to reject URL-shaped hosts"
  cat "$invalid_log"
  exit 1
fi
if ! rg -q "bare host|not a URL" "$invalid_log"; then
  echo "missing expected bare-host failure signal"
  cat "$invalid_log"
  exit 1
fi

host_port_log="$tmp_dir/host_port.log"
if ./scripts/prod_mtls_prep.sh \
  --authority-host example.com:8081 \
  --provider-host 198.51.100.20 \
  --out-dir "$tmp_dir/host-port" >"$host_port_log" 2>&1; then
  echo "expected prod-mtls-prep to reject host:port values"
  cat "$host_port_log"
  exit 1
fi
if ! rg -q "not host:port" "$host_port_log"; then
  echo "missing expected host:port failure signal"
  cat "$host_port_log"
  exit 1
fi

private_dir="$tmp_dir/private"
private_log="$tmp_dir/private.log"
if ./scripts/prod_mtls_prep.sh \
  --authority-host 100.113.245.61 \
  --provider-host 100.64.244.24 \
  --out-dir "$private_dir" \
  --print-summary-json 1 >"$private_log" 2>&1; then
  echo "expected prod-mtls-prep to fail closed on Tailscale/private hosts by default"
  cat "$private_log"
  exit 1
fi
if ! jq -e '.status=="fail" and .prod_ready==false and (.blockers | length >= 1)' "$private_dir/prod_mtls_prep_summary.json" >/dev/null; then
  echo "unexpected private-host summary"
  cat "$private_dir/prod_mtls_prep_summary.json"
  exit 1
fi
if ! rg -q "Tailscale|private" "$private_dir/prod_mtls_prep_report.md"; then
  echo "missing private-host blocker in report"
  cat "$private_dir/prod_mtls_prep_report.md"
  exit 1
fi

rehearsal_dir="$tmp_dir/rehearsal"
./scripts/prod_mtls_prep.sh \
  --authority-host 100.113.245.61 \
  --provider-host 100.64.244.24 \
  --allow-private-hosts 1 \
  --out-dir "$rehearsal_dir" \
  --print-summary-json 1 >/tmp/integration_prod_mtls_prep_rehearsal.log
if ! jq -e '.status=="pass" and .prod_ready==false and .rehearsal_only==true and .beta_http_unchanged==true' "$rehearsal_dir/prod_mtls_prep_summary.json" >/dev/null; then
  echo "unexpected rehearsal summary"
  cat "$rehearsal_dir/prod_mtls_prep_summary.json"
  exit 1
fi
for file_name in ca.crt ca.key node.crt node.key client.crt client.key; do
  if [[ ! -s "$rehearsal_dir/tls/$file_name" ]]; then
    echo "missing rehearsal mTLS file: $file_name"
    exit 1
  fi
done
if ! rg -q "rehearsal_only: true" "$rehearsal_dir/prod_mtls_prep_report.md"; then
  echo "missing rehearsal-only warning in report"
  cat "$rehearsal_dir/prod_mtls_prep_report.md"
  exit 1
fi
if ! rg -q "Replace private/Tailscale hosts with public DNS/IPs" "$rehearsal_dir/prod_mtls_prep_report.md"; then
  echo "missing rehearsal cutover warning in report"
  cat "$rehearsal_dir/prod_mtls_prep_report.md"
  exit 1
fi

handshake_dir="$tmp_dir/handshake"
./scripts/prod_mtls_prep.sh \
  --authority-host 127.0.0.1 \
  --provider-host 127.0.0.2 \
  --allow-private-hosts 1 \
  --out-dir "$handshake_dir" >/tmp/integration_prod_mtls_prep_handshake.log
port=$((24000 + RANDOM % 10000))
openssl s_server \
  -accept "$port" \
  -cert "$handshake_dir/tls/node.crt" \
  -key "$handshake_dir/tls/node.key" \
  -CAfile "$handshake_dir/tls/ca.crt" \
  -Verify 1 \
  -tls1_3 \
  -www >"$handshake_dir/s_server.log" 2>&1 &
server_pid=$!
server_ready=0
for _ in $(seq 1 50); do
  if (: >/dev/tcp/127.0.0.1/"$port") >/dev/null 2>&1; then
    server_ready=1
    break
  fi
  sleep 0.1
done
if [[ "$server_ready" != "1" ]]; then
  echo "mTLS handshake test server did not become ready"
  cat "$handshake_dir/s_server.log" 2>/dev/null || true
  exit 1
fi
if curl -fsS --connect-timeout 2 --max-time 4 \
  --cacert "$handshake_dir/tls/ca.crt" \
  "https://127.0.0.1:${port}/" >"$handshake_dir/no_client_cert.out" 2>"$handshake_dir/no_client_cert.err"; then
  echo "expected mTLS endpoint to reject a request without a client certificate"
  cat "$handshake_dir/no_client_cert.out" 2>/dev/null || true
  exit 1
fi
curl -fsS --connect-timeout 2 --max-time 4 \
  --cacert "$handshake_dir/tls/ca.crt" \
  --cert "$handshake_dir/tls/client.crt" \
  --key "$handshake_dir/tls/client.key" \
  "https://127.0.0.1:${port}/" >"$handshake_dir/client_cert.out"
kill "$server_pid" 2>/dev/null || true
wait "$server_pid" 2>/dev/null || true
server_pid=""

public_dir="$tmp_dir/public"
./scripts/easy_node.sh prod-mtls-prep \
  --authority-host 203.0.113.10 \
  --provider-host 198.51.100.11 \
  --provider-host provider.example \
  --out-dir "$public_dir" \
  --print-summary-json 1 >/tmp/integration_prod_mtls_prep_public.log
if ! jq -e '.status=="pass" and .prod_ready==true and .rehearsal_only==false and .non_disruptive==true' "$public_dir/prod_mtls_prep_summary.json" >/dev/null; then
  echo "unexpected public prep summary"
  cat "$public_dir/prod_mtls_prep_summary.json"
  exit 1
fi
if ! openssl x509 -in "$public_dir/tls/node.crt" -noout -ext subjectAltName >/tmp/integration_prod_mtls_prep_san.log 2>&1; then
  echo "expected readable node certificate SAN extension"
  cat "$public_dir/bootstrap_mtls.log" 2>/dev/null || true
  exit 1
fi
for expected in "IP Address:203.0.113.10" "IP Address:198.51.100.11" "DNS:provider.example"; do
  if ! rg -q "$expected" /tmp/integration_prod_mtls_prep_san.log; then
    echo "missing expected SAN: $expected"
    cat /tmp/integration_prod_mtls_prep_san.log
    exit 1
  fi
done
if ! rg -q "server-up --mode authority" "$public_dir/prod_mtls_prep_report.md"; then
  echo "missing authority cutover command in report"
  cat "$public_dir/prod_mtls_prep_report.md"
  exit 1
fi
if ! rg -q "three-machine-prod-signoff" "$public_dir/prod_mtls_prep_report.md"; then
  echo "missing signoff command in report"
  cat "$public_dir/prod_mtls_prep_report.md"
  exit 1
fi

echo "integration_prod_mtls_prep: ok"
