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

reserved_dir="$tmp_dir/reserved"
reserved_log="$tmp_dir/reserved.log"
if ./scripts/prod_mtls_prep.sh \
  --authority-host 203.0.113.10 \
  --provider-host 198.51.100.20 \
  --out-dir "$reserved_dir" \
  --print-summary-json 1 >"$reserved_log" 2>&1; then
  echo "expected prod-mtls-prep to fail closed on TEST-NET/reserved hosts by default"
  cat "$reserved_log"
  exit 1
fi
if ! jq -e '.status=="fail" and .prod_ready==false and (.blockers[]? | select(.code=="private_or_loopback_host"))' "$reserved_dir/prod_mtls_prep_summary.json" >/dev/null; then
  echo "unexpected reserved-host summary"
  cat "$reserved_dir/prod_mtls_prep_summary.json"
  exit 1
fi
if ! rg -q "reserved/test" "$reserved_dir/prod_mtls_prep_report.md"; then
  echo "missing reserved-host blocker in report"
  cat "$reserved_dir/prod_mtls_prep_report.md"
  exit 1
fi

non_public_cases=(
  "placeholder.prod.example.net"
  "authority.example"
  "provider.test"
  "node.internal"
  "node.local"
  "prod-node.ts.net"
  "192.0.2.10"
  "198.18.0.1"
  "224.0.0.1"
  "2001:0db8::1"
  "fe90::1"
  "fd00::1"
  "ff02::1"
  "::ffff:192.168.1.10"
)
for non_public_host in "${non_public_cases[@]}"; do
  case_dir="$tmp_dir/non-public-$(printf '%s' "$non_public_host" | tr -c 'A-Za-z0-9._-' '_')"
  case_log="$case_dir.log"
  if ./scripts/prod_mtls_prep.sh \
    --authority-host "$non_public_host" \
    --provider-host provider-a.prod.privacynode.net \
    --out-dir "$case_dir" \
    --print-summary-json 1 >"$case_log" 2>&1; then
    echo "expected prod-mtls-prep to reject non-production host: $non_public_host"
    cat "$case_log"
    exit 1
  fi
  if ! jq -e '.status=="fail" and .prod_ready==false and (.blockers[]? | select(.code=="private_or_loopback_host")) and (.hosts[]? | select(.private_or_loopback==true))' "$case_dir/prod_mtls_prep_summary.json" >/dev/null; then
    echo "unexpected non-production host summary for: $non_public_host"
    cat "$case_dir/prod_mtls_prep_summary.json"
    exit 1
  fi
done

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
handshake_server_bundle="$(jq -r '.certificate_generation.host_server_bundles[] | select(.role=="authority") | .dir' "$handshake_dir/prod_mtls_prep_summary.json")"
if [[ -z "$handshake_server_bundle" || ! -d "$handshake_server_bundle" ]]; then
  echo "missing authority host-specific server bundle for handshake test"
  cat "$handshake_dir/prod_mtls_prep_summary.json"
  exit 1
fi
port=$((24000 + RANDOM % 10000))
openssl s_server \
  -accept "$port" \
  -cert "$handshake_server_bundle/node.crt" \
  -key "$handshake_server_bundle/node.key" \
  -CAfile "$handshake_server_bundle/ca.crt" \
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
  --cacert "$handshake_server_bundle/ca.crt" \
  "https://127.0.0.1:${port}/" >"$handshake_dir/no_client_cert.out" 2>"$handshake_dir/no_client_cert.err"; then
  echo "expected mTLS endpoint to reject a request without a client certificate"
  cat "$handshake_dir/no_client_cert.out" 2>/dev/null || true
  exit 1
fi
curl -fsS --connect-timeout 2 --max-time 4 \
  --cacert "$handshake_server_bundle/ca.crt" \
  --cert "$handshake_dir/tls/client.crt" \
  --key "$handshake_dir/tls/client.key" \
  "https://127.0.0.1:${port}/" >"$handshake_dir/client_cert.out"
kill "$server_pid" 2>/dev/null || true
wait "$server_pid" 2>/dev/null || true
server_pid=""

public_dir="$tmp_dir/public"
./scripts/easy_node.sh prod-mtls-prep \
  --authority-host authority.prod.privacynode.net \
  --provider-host provider-a.prod.privacynode.net \
  --provider-host provider-b.prod.privacynode.net \
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
for expected in "DNS:authority.prod.privacynode.net" "DNS:provider-a.prod.privacynode.net" "DNS:provider-b.prod.privacynode.net"; do
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
for expected_signoff_arg in \
  "--mtls-ca-file deploy/tls/ca.crt" \
  "--mtls-client-cert-file deploy/tls/client.crt" \
  "--mtls-client-key-file deploy/tls/client.key"; do
  if ! jq -e --arg expected "$expected_signoff_arg" '.next_commands.three_machine_prod_signoff | contains($expected)' "$public_dir/prod_mtls_prep_summary.json" >/dev/null; then
    echo "missing mTLS signoff argument in summary command: $expected_signoff_arg"
    cat "$public_dir/prod_mtls_prep_summary.json"
    exit 1
  fi
  if ! rg -Fq -- "$expected_signoff_arg" "$public_dir/prod_mtls_prep_report.md"; then
    echo "missing mTLS signoff argument in report command: $expected_signoff_arg"
    cat "$public_dir/prod_mtls_prep_report.md"
    exit 1
  fi
done
if ! rg -q "do not distribute the CA private key" "$public_dir/prod_mtls_prep_report.md"; then
  echo "missing CA private-key handling warning in report"
  cat "$public_dir/prod_mtls_prep_report.md"
  exit 1
fi
if ! rg -q "prod-mtls-bundle-verify" "$public_dir/prod_mtls_prep_report.md"; then
  echo "missing host-bundle verify command in report"
  cat "$public_dir/prod_mtls_prep_report.md"
  exit 1
fi
if ! rg -q "prod-mtls-bundle-stage" "$public_dir/prod_mtls_prep_report.md"; then
  echo "missing host-bundle stage command in report"
  cat "$public_dir/prod_mtls_prep_report.md"
  exit 1
fi
if ! jq -e '(.certificate_generation.host_server_bundles | length) == 3' "$public_dir/prod_mtls_prep_summary.json" >/dev/null; then
  echo "expected host-specific server bundles for authority plus both providers"
  cat "$public_dir/prod_mtls_prep_summary.json"
  exit 1
fi
authority_bundle="$(jq -r '.certificate_generation.host_server_bundles[] | select(.role=="authority") | .dir' "$public_dir/prod_mtls_prep_summary.json")"
provider_bundle="$(jq -r '.certificate_generation.host_server_bundles[] | select(.role=="provider" and .host=="provider-a.prod.privacynode.net") | .dir' "$public_dir/prod_mtls_prep_summary.json")"
if [[ -z "$authority_bundle" || -z "$provider_bundle" || ! -d "$authority_bundle" || ! -d "$provider_bundle" ]]; then
  echo "missing expected public host-specific bundle"
  cat "$public_dir/prod_mtls_prep_summary.json"
  exit 1
fi
if [[ -e "$authority_bundle/ca.key" || -e "$provider_bundle/ca.key" ]]; then
  echo "host-specific server bundles must not include ca.key"
  exit 1
fi
if ! openssl verify -CAfile "$public_dir/tls/ca.crt" "$authority_bundle/node.crt" >/tmp/integration_prod_mtls_prep_auth_verify.log 2>&1; then
  echo "authority host-specific certificate failed CA verification"
  cat /tmp/integration_prod_mtls_prep_auth_verify.log
  exit 1
fi
if ! openssl verify -CAfile "$public_dir/tls/ca.crt" "$provider_bundle/node.crt" >/tmp/integration_prod_mtls_prep_provider_verify.log 2>&1; then
  echo "provider host-specific certificate failed CA verification"
  cat /tmp/integration_prod_mtls_prep_provider_verify.log
  exit 1
fi
auth_key_fp="$(openssl pkey -in "$authority_bundle/node.key" -pubout 2>/dev/null | openssl dgst -sha256 | awk '{print $2}')"
provider_key_fp="$(openssl pkey -in "$provider_bundle/node.key" -pubout 2>/dev/null | openssl dgst -sha256 | awk '{print $2}')"
if [[ -z "$auth_key_fp" || -z "$provider_key_fp" || "$auth_key_fp" == "$provider_key_fp" ]]; then
  echo "expected host-specific server bundles to use distinct node keys"
  exit 1
fi
openssl x509 -in "$authority_bundle/node.crt" -noout -ext subjectAltName >/tmp/integration_prod_mtls_prep_auth_host_san.log
openssl x509 -in "$provider_bundle/node.crt" -noout -ext subjectAltName >/tmp/integration_prod_mtls_prep_provider_host_san.log
if ! rg -q "DNS:authority.prod.privacynode.net" /tmp/integration_prod_mtls_prep_auth_host_san.log || rg -q "DNS:provider-a.prod.privacynode.net" /tmp/integration_prod_mtls_prep_auth_host_san.log; then
  echo "authority host-specific SANs are not isolated to the authority host"
  cat /tmp/integration_prod_mtls_prep_auth_host_san.log
  exit 1
fi
if ! rg -q "DNS:provider-a.prod.privacynode.net" /tmp/integration_prod_mtls_prep_provider_host_san.log || rg -q "DNS:authority.prod.privacynode.net" /tmp/integration_prod_mtls_prep_provider_host_san.log; then
  echo "provider host-specific SANs are not isolated to the provider host"
  cat /tmp/integration_prod_mtls_prep_provider_host_san.log
  exit 1
fi

./scripts/easy_node.sh prod-mtls-bundle-verify \
  --bundle-dir "$authority_bundle" \
  --host authority.prod.privacynode.net \
  --summary-json "$tmp_dir/authority_bundle_verify.json" \
  --print-summary-json 1 >"$tmp_dir/authority_bundle_verify.log"
if ! jq -e '.status=="pass" and .failures==0 and (.inputs.expected_hosts == ["authority.prod.privacynode.net"])' "$tmp_dir/authority_bundle_verify.json" >/dev/null; then
  echo "expected authority host-specific bundle verify to pass"
  cat "$tmp_dir/authority_bundle_verify.json"
  exit 1
fi

./scripts/prod_mtls_bundle_verify.sh \
  --bundle-dir "$provider_bundle" \
  --host provider-a.prod.privacynode.net \
  --summary-json "$tmp_dir/provider_bundle_verify.json" >"$tmp_dir/provider_bundle_verify.log"
if ! jq -e '.status=="pass" and .failures==0' "$tmp_dir/provider_bundle_verify.json" >/dev/null; then
  echo "expected provider host-specific bundle verify to pass"
  cat "$tmp_dir/provider_bundle_verify.json"
  exit 1
fi

wrong_host_log="$tmp_dir/wrong_host_bundle_verify.log"
if ./scripts/prod_mtls_bundle_verify.sh \
  --bundle-dir "$authority_bundle" \
  --host provider-a.prod.privacynode.net \
  --summary-json "$tmp_dir/wrong_host_bundle_verify.json" >"$wrong_host_log" 2>&1; then
  echo "expected bundle verify to fail when host SAN does not match"
  cat "$wrong_host_log"
  exit 1
fi
if ! jq -e '.status=="fail" and (.blockers[]? | select(.code | startswith("node_cert_san_")))' "$tmp_dir/wrong_host_bundle_verify.json" >/dev/null; then
  echo "expected wrong-host bundle verify summary to identify SAN mismatch"
  cat "$tmp_dir/wrong_host_bundle_verify.json"
  exit 1
fi

server_only_bundle="$tmp_dir/server_only_authority_bundle"
mkdir -p "$server_only_bundle"
cp "$authority_bundle/ca.crt" "$authority_bundle/node.key" "$server_only_bundle/"
cat >"$server_only_bundle/server_only.cnf" <<'EOF_SERVER_ONLY_CNF'
[req]
distinguished_name = dn
prompt = no
req_extensions = req_ext
[dn]
CN = server-only-authority
[req_ext]
subjectAltName = DNS:authority.prod.privacynode.net
extendedKeyUsage = serverAuth
EOF_SERVER_ONLY_CNF
openssl req -new \
  -key "$server_only_bundle/node.key" \
  -out "$server_only_bundle/node.csr" \
  -config "$server_only_bundle/server_only.cnf" >/dev/null 2>&1
openssl x509 -req \
  -in "$server_only_bundle/node.csr" \
  -CA "$public_dir/tls/ca.crt" \
  -CAkey "$public_dir/tls/ca.key" \
  -CAcreateserial \
  -out "$server_only_bundle/node.crt" \
  -days 30 \
  -sha256 \
  -extfile "$server_only_bundle/server_only.cnf" \
  -extensions req_ext >/dev/null 2>&1
server_only_log="$tmp_dir/server_only_bundle_verify.log"
if ./scripts/prod_mtls_bundle_verify.sh \
  --bundle-dir "$server_only_bundle" \
  --host authority.prod.privacynode.net \
  --summary-json "$tmp_dir/server_only_bundle_verify.json" >"$server_only_log" 2>&1; then
  echo "expected bundle verify to fail when node.crt is missing clientAuth"
  cat "$server_only_log"
  exit 1
fi
if ! jq -e '.status=="fail" and (.blockers[]? | select(.code=="node_cert_client_auth"))' "$tmp_dir/server_only_bundle_verify.json" >/dev/null; then
  echo "expected server-only bundle verify summary to identify missing node clientAuth"
  cat "$tmp_dir/server_only_bundle_verify.json"
  exit 1
fi

leaky_bundle="$tmp_dir/leaky_authority_bundle"
mkdir -p "$leaky_bundle"
cp "$authority_bundle/ca.crt" "$authority_bundle/node.crt" "$authority_bundle/node.key" "$leaky_bundle/"
cp "$public_dir/tls/ca.key" "$leaky_bundle/ca.key"
leaky_log="$tmp_dir/leaky_bundle_verify.log"
if ./scripts/prod_mtls_bundle_verify.sh \
  --bundle-dir "$leaky_bundle" \
  --host authority.prod.privacynode.net \
  --summary-json "$tmp_dir/leaky_bundle_verify.json" >"$leaky_log" 2>&1; then
  echo "expected bundle verify to fail when ca.key is staged in a server bundle"
  cat "$leaky_log"
  exit 1
fi
if ! jq -e '.status=="fail" and (.blockers[]? | select(.code=="ca_key_absent"))' "$tmp_dir/leaky_bundle_verify.json" >/dev/null; then
  echo "expected leaky bundle verify summary to identify ca.key"
  cat "$tmp_dir/leaky_bundle_verify.json"
  exit 1
fi

stage_target="$tmp_dir/staged_tls"
./scripts/easy_node.sh prod-mtls-bundle-stage \
  --bundle-dir "$authority_bundle" \
  --host authority.prod.privacynode.net \
  --target-dir "$stage_target" \
  --summary-json "$tmp_dir/stage_authority_bundle.json" \
  --print-summary-json 1 >"$tmp_dir/stage_authority_bundle.log"
if ! jq -e '.status=="pass" and .client_material_copied==true and .restarted_services==false' "$tmp_dir/stage_authority_bundle.json" >/dev/null; then
  echo "expected authority bundle stage to pass and copy client material"
  cat "$tmp_dir/stage_authority_bundle.json"
  exit 1
fi
for staged_file in ca.crt node.crt node.key client.crt client.key; do
  if [[ ! -s "$stage_target/$staged_file" ]]; then
    echo "missing staged file: $staged_file"
    cat "$tmp_dir/stage_authority_bundle.json"
    exit 1
  fi
done
if [[ -e "$stage_target/ca.key" ]]; then
  echo "staged server target must not contain ca.key"
  exit 1
fi
./scripts/prod_mtls_bundle_verify.sh \
  --bundle-dir "$stage_target" \
  --host authority.prod.privacynode.net \
  --require-client-material 1 \
  --summary-json "$tmp_dir/stage_target_verify.json" >"$tmp_dir/stage_target_verify.log"
if ! jq -e '.status=="pass" and .failures==0' "$tmp_dir/stage_target_verify.json" >/dev/null; then
  echo "expected staged target verify to pass"
  cat "$tmp_dir/stage_target_verify.json"
  exit 1
fi

mismatched_client_bundle="$tmp_dir/mismatched_client_bundle"
mkdir -p "$mismatched_client_bundle"
cp "$stage_target/ca.crt" "$stage_target/node.crt" "$stage_target/node.key" "$stage_target/client.crt" "$mismatched_client_bundle/"
cp "$provider_bundle/node.key" "$mismatched_client_bundle/client.key"
if ./scripts/prod_mtls_bundle_verify.sh \
  --bundle-dir "$mismatched_client_bundle" \
  --host authority.prod.privacynode.net \
  --require-client-material 1 \
  --summary-json "$tmp_dir/mismatched_client_bundle_verify.json" >"$tmp_dir/mismatched_client_bundle_verify.log" 2>&1; then
  echo "expected bundle verify to fail when client.crt and client.key do not match"
  cat "$tmp_dir/mismatched_client_bundle_verify.log"
  exit 1
fi
if ! jq -e '.status=="fail" and (.blockers[]? | select(.code=="client_cert_key_match"))' "$tmp_dir/mismatched_client_bundle_verify.json" >/dev/null; then
  echo "expected mismatched client bundle verify summary to identify client key mismatch"
  cat "$tmp_dir/mismatched_client_bundle_verify.json"
  exit 1
fi

echo "integration_prod_mtls_prep: ok"
