#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in go jq mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "access recovery demo contract failed: missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

BUNDLE_DIR="$TMP_DIR/access-recovery-demo"
go run ./cmd/gpmrecover demo-bundle \
  --out-dir "$BUNDLE_DIR" \
  --org-id contract-org \
  --org-name "Contract Org" \
  --base-url https://contract.example \
  --helper-id helper-contract \
  --helper-name "Contract Helper" \
  --helper-url https://helper.example/contract/bootstrap \
  --helper-contact mailto:helper-contract@example.com \
  >"$TMP_DIR/demo-bundle.stdout.json"

MANIFEST="$BUNDLE_DIR/demo-manifest.json"
if [[ ! -f "$MANIFEST" ]]; then
  echo "access recovery demo contract failed: missing manifest: $MANIFEST"
  exit 1
fi

if [[ "$(jq -r '.status // ""' "$MANIFEST")" != "ok" ]]; then
  echo "access recovery demo contract failed: manifest status is not ok"
  cat "$MANIFEST"
  exit 1
fi
if [[ "$(jq -r '.bridge_policy.status // ""' "$MANIFEST")" != "pass" ]]; then
  echo "access recovery demo contract failed: manifest bridge policy is not pass"
  cat "$MANIFEST"
  exit 1
fi
if [[ -z "$(jq -r '.key_id // ""' "$MANIFEST")" ]]; then
  echo "access recovery demo contract failed: manifest key_id is empty"
  cat "$MANIFEST"
  exit 1
fi

required_file_keys=(
  private_key
  public_key
  trust_store
  trusted_key
  trusted_key_text
  trusted_key_qr
  access_pack_signed
  bridge_invite_signed
  bridge_helper_registry
  bridge_helper_registry_signed
  access_pack_text
  bridge_invite_text
  trust_store_text
  bridge_helper_registry_signed_text
)

for key in "${required_file_keys[@]}"; do
  path="$(jq -r --arg key "$key" '.files[$key] // ""' "$MANIFEST")"
  if [[ -z "$path" || ! -s "$path" ]]; then
    echo "access recovery demo contract failed: missing or empty files[$key]: ${path:-unset}"
    cat "$MANIFEST"
    exit 1
  fi
done

trust_store="$(jq -r '.files.trust_store' "$MANIFEST")"
trusted_key="$(jq -r '.files.trusted_key' "$MANIFEST")"
trusted_key_text="$(jq -r '.files.trusted_key_text' "$MANIFEST")"
access_pack="$(jq -r '.files.access_pack_signed' "$MANIFEST")"
bridge_invite="$(jq -r '.files.bridge_invite_signed' "$MANIFEST")"
signed_registry="$(jq -r '.files.bridge_helper_registry_signed' "$MANIFEST")"
verified_registry="$TMP_DIR/bridge-helper-registry.verified.json"

manifest_key_id="$(jq -r '.key_id' "$MANIFEST")"
trusted_key_id="$(jq -r '.key_id // ""' "$trusted_key")"
if [[ "$trusted_key_id" != "$manifest_key_id" ]]; then
  echo "access recovery demo contract failed: trusted-key key_id mismatch"
  echo "manifest=$manifest_key_id trusted_key=$trusted_key_id"
  exit 1
fi

go run ./cmd/gpmrecover verify --pack "$access_pack" --trust-store "$trust_store" --show-paths >/dev/null
go run ./cmd/gpmrecover bridge-verify --invite "$bridge_invite" --trust-store "$trust_store" --show-paths >/dev/null
go run ./cmd/gpmrecover bridge-registry-verify --signed-registry "$signed_registry" --trust-store "$trust_store" --out-registry "$verified_registry" >/dev/null
go run ./cmd/gpmrecover bridge-policy --invite "$bridge_invite" --trust-store "$trust_store" --signed-helper-registry "$signed_registry" --require-helper-registry >/dev/null

go run ./cmd/gpmrecover text-import --text-file "$trusted_key_text" --expect-kind trusted-key --out "$TMP_DIR/trusted-key.imported.json" >/dev/null
go run ./cmd/gpmrecover text-import --text-file "$(jq -r '.files.trust_store_text' "$MANIFEST")" --expect-kind trust-store --out "$TMP_DIR/trust-store.imported.json" >/dev/null
go run ./cmd/gpmrecover text-import --text-file "$(jq -r '.files.bridge_invite_text' "$MANIFEST")" --expect-kind bridge-invite --out "$TMP_DIR/bridge-invite.imported.json" >/dev/null
go run ./cmd/gpmrecover text-import --text-file "$(jq -r '.files.bridge_helper_registry_signed_text' "$MANIFEST")" --expect-kind bridge-helper-registry-signed --out "$TMP_DIR/bridge-helper-registry.signed.imported.json" >/dev/null

set +e
go run ./cmd/gpmrecover bridge-policy --invite "$bridge_invite" --trust-store "$trust_store" --require-helper-registry >"$TMP_DIR/missing-registry.log" 2>&1
missing_registry_rc=$?
set -e
if [[ "$missing_registry_rc" -eq 0 ]]; then
  echo "access recovery demo contract failed: bridge-policy succeeded without required helper registry"
  cat "$TMP_DIR/missing-registry.log"
  exit 1
fi

echo "access recovery demo contract integration check ok"
