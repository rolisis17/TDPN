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

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

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
