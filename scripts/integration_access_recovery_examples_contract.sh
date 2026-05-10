#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in go jq mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "access recovery examples contract failed: missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

private_key="$TMP_DIR/recovery.key"
public_key="$TMP_DIR/recovery.pub"
trust_store="$TMP_DIR/recovery-trust.json"
signed_pack="$TMP_DIR/access-pack.signed.json"
signed_invite="$TMP_DIR/bridge-invite.signed.json"
signed_registry="$TMP_DIR/bridge-helper-registry.signed.json"
verified_registry="$TMP_DIR/bridge-helper-registry.verified.json"

go run ./cmd/gpmrecover gen --private-key-out "$private_key" --public-key-out "$public_key" >"$TMP_DIR/gen.json"
go run ./cmd/gpmrecover trust-add \
  --trust-store "$trust_store" \
  --org-id freenews-demo \
  --org-name "FreeNews Demo" \
  --public-key-file "$public_key" \
  --source "examples contract" \
  >"$TMP_DIR/trust-add.json"

key_id="$(jq -r '.key_id // ""' "$TMP_DIR/trust-add.json")"
if [[ -z "$key_id" ]]; then
  echo "access recovery examples contract failed: trust-add did not return key_id"
  cat "$TMP_DIR/trust-add.json"
  exit 1
fi

go run ./cmd/gpmrecover sign \
  --pack docs/examples/access-recovery-pack.example.json \
  --private-key-file "$private_key" \
  --out "$signed_pack" \
  >/dev/null
go run ./cmd/gpmrecover verify \
  --pack "$signed_pack" \
  --trust-store "$trust_store" \
  --show-paths \
  >/dev/null

go run ./cmd/gpmrecover bridge-sign \
  --invite docs/examples/access-recovery-bridge-invite.example.json \
  --private-key-file "$private_key" \
  --out "$signed_invite" \
  >/dev/null
go run ./cmd/gpmrecover bridge-verify \
  --invite "$signed_invite" \
  --trust-store "$trust_store" \
  --show-paths \
  >/dev/null

go run ./cmd/gpmrecover bridge-registry-check \
  --helper-registry docs/examples/access-recovery-bridge-helper-registry.example.json \
  --helper-id helper-perth-1 \
  --org-id freenews-demo \
  --require-active \
  >/dev/null
go run ./cmd/gpmrecover bridge-registry-sign \
  --helper-registry docs/examples/access-recovery-bridge-helper-registry.example.json \
  --org-id freenews-demo \
  --org-name "FreeNews Demo" \
  --private-key-file "$private_key" \
  --out "$signed_registry" \
  >/dev/null
go run ./cmd/gpmrecover bridge-registry-verify \
  --signed-registry "$signed_registry" \
  --trust-store "$trust_store" \
  --out-registry "$verified_registry" \
  >/dev/null

set +e
go run ./cmd/gpmrecover bridge-policy \
  --invite "$signed_invite" \
  --trust-store "$trust_store" \
  --helper-registry docs/examples/access-recovery-bridge-helper-registry.example.json \
  --require-helper-registry \
  >"$TMP_DIR/unsigned-registry-policy.log" 2>&1
unsigned_registry_policy_rc=$?
set -e
if [[ "$unsigned_registry_policy_rc" -eq 0 ]]; then
  echo "access recovery examples contract failed: unsigned helper registry policy succeeded without diagnostic opt-in"
  cat "$TMP_DIR/unsigned-registry-policy.log"
  exit 1
fi
go run ./cmd/gpmrecover bridge-policy \
  --invite "$signed_invite" \
  --trust-store "$trust_store" \
  --helper-registry docs/examples/access-recovery-bridge-helper-registry.example.json \
  --allow-unsigned-helper-registry \
  >/dev/null
go run ./cmd/gpmrecover bridge-policy \
  --invite "$signed_invite" \
  --trust-store "$trust_store" \
  --signed-helper-registry "$signed_registry" \
  --require-helper-registry \
  >/dev/null

go run ./cmd/gpmrecover text-export \
  --kind trusted-key \
  --in docs/examples/access-recovery-trusted-key.example.json \
  --out "$TMP_DIR/example-trusted-key.txt" \
  >/dev/null
go run ./cmd/gpmrecover text-import \
  --text-file "$TMP_DIR/example-trusted-key.txt" \
  --expect-kind trusted-key \
  --out "$TMP_DIR/example-trusted-key.imported.json" \
  >/dev/null

echo "access recovery examples contract integration check ok"
