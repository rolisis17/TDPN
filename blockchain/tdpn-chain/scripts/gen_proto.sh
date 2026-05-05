#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHAIN_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LINT_ONLY=0

if [[ "${1:-}" == "--lint-only" ]]; then
  LINT_ONLY=1
fi

cd "${CHAIN_ROOT}"

if ! command -v buf >/dev/null 2>&1; then
  cat >&2 <<'EOF'
error: 'buf' CLI is not installed or not in PATH.

Install Buf:
  https://docs.buf.build/installation

Then rerun:
  ./scripts/gen_proto.sh
EOF
  exit 1
fi

echo "==> buf lint"
buf lint

if [[ "$LINT_ONLY" == "1" ]]; then
  echo "lint-only mode complete"
  exit 0
fi

echo "==> buf generate"
buf generate

echo "proto generation complete"
echo "generated files path: ${CHAIN_ROOT}/proto/gen/go"
