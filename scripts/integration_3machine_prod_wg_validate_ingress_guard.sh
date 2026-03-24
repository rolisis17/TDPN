#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

OUT_BLOCK="$TMP_DIR/out_block.log"
OUT_ALLOW="$TMP_DIR/out_allow.log"
OUT_INVALID="$TMP_DIR/out_invalid.log"

set +e
./scripts/integration_3machine_prod_wg_validate.sh \
  --client-inner-source synthetic >"$OUT_BLOCK" 2>&1
rc_block=$?
set -e
if [[ "$rc_block" -eq 0 ]]; then
  echo "expected synthetic ingress guard to fail by default"
  cat "$OUT_BLOCK"
  exit 1
fi
if ! rg -q 'blocked in production real-WG validation' "$OUT_BLOCK"; then
  echo "missing synthetic ingress guard failure message"
  cat "$OUT_BLOCK"
  exit 1
fi
if rg -q 'run as root' "$OUT_BLOCK"; then
  echo "synthetic ingress guard should fail before root check"
  cat "$OUT_BLOCK"
  exit 1
fi

set +e
./scripts/integration_3machine_prod_wg_validate.sh \
  --client-inner-source synthetic \
  --allow-synthetic-ingress 1 >"$OUT_ALLOW" 2>&1
rc_allow=$?
set -e
if [[ "$rc_allow" -eq 0 ]]; then
  echo "expected synthetic ingress allowed path to continue into later checks and fail"
  cat "$OUT_ALLOW"
  exit 1
fi
if rg -q 'blocked in production real-WG validation' "$OUT_ALLOW"; then
  echo "synthetic ingress allowed path unexpectedly hit guard message"
  cat "$OUT_ALLOW"
  exit 1
fi
if ! rg -q 'run as root|missing required endpoints' "$OUT_ALLOW"; then
  echo "synthetic ingress allowed path did not reach expected downstream checks"
  cat "$OUT_ALLOW"
  exit 1
fi

set +e
./scripts/integration_3machine_prod_wg_validate.sh \
  --allow-synthetic-ingress 2 >"$OUT_INVALID" 2>&1
rc_invalid=$?
set -e
if [[ "$rc_invalid" -eq 0 ]]; then
  echo "expected invalid allow-synthetic-ingress value to fail"
  cat "$OUT_INVALID"
  exit 1
fi
if ! rg -q -- '--allow-synthetic-ingress must be 0 or 1' "$OUT_INVALID"; then
  echo "missing invalid allow-synthetic-ingress validation message"
  cat "$OUT_INVALID"
  exit 1
fi

echo "3-machine prod wg validate ingress guard integration check ok"
