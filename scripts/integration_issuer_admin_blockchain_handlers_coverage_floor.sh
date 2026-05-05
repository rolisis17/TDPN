#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash go awk mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

FLOOR="${ISSUER_BLOCKCHAIN_HANDLER_COVERAGE_FLOOR:-60.0}"

is_valid_floor() {
  local value="${1:-}"
  awk -v v="$value" 'BEGIN {
    if (v ~ /^[0-9]+([.][0-9]+)?$/) {
      exit 0
    }
    exit 1
  }'
}

meets_floor() {
  local actual="$1"
  local floor="$2"
  awk -v a="$actual" -v b="$floor" 'BEGIN { exit ((a + 0.0) >= (b + 0.0) ? 0 : 1) }'
}

if ! is_valid_floor "$FLOOR"; then
  echo "invalid ISSUER_BLOCKCHAIN_HANDLER_COVERAGE_FLOOR value: $FLOOR (expected numeric format like 60 or 60.0)"
  exit 2
fi

run_with_optional_timeout() {
  if command -v timeout >/dev/null 2>&1; then
    timeout "${COVERAGE_TEST_TIMEOUT_SECONDS:-240}s" "$@"
  else
    "$@"
  fi
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

COVER_PROFILE="$TMP_DIR/issuer.cover"
TEST_LOG="$TMP_DIR/issuer.test.log"

if ! run_with_optional_timeout go test ./services/issuer -count=1 -coverprofile="$COVER_PROFILE" >"$TEST_LOG" 2>&1; then
  echo "issuer blockchain handler coverage floor failed: go test ./services/issuer failed"
  cat "$TEST_LOG"
  exit 1
fi

declare -a handlers=(
  "handleUpsertSubject"
  "handlePromoteSubject"
  "handleApplyReputation"
  "handleApplyBond"
  "handleRecomputeTier"
  "handleGetSubject"
  "handleIssueAnonymousCredential"
  "handleRevokeAnonymousCredential"
  "handleGetAudit"
  "handleRevokeToken"
)

for fn in "${handlers[@]}"; do
  coverage="$(go tool cover -func="$COVER_PROFILE" | awk -v fn="$fn" '
    $2 == fn {
      gsub(/%/, "", $3)
      print $3
      found = 1
      exit
    }
    END {
      if (!found) {
        exit 1
      }
    }
  ' || true)"

  if [[ -z "$coverage" ]]; then
    echo "issuer blockchain handler coverage floor failed: missing coverage entry for $fn"
    go tool cover -func="$COVER_PROFILE"
    exit 1
  fi

  if ! meets_floor "$coverage" "$FLOOR"; then
    echo "issuer blockchain handler coverage floor failed: $fn coverage ${coverage}% is below floor ${FLOOR}%"
    go tool cover -func="$COVER_PROFILE" | awk -v fn="$fn" '$2 == fn || /total:/'
    exit 1
  fi

  echo "issuer blockchain handler coverage ok: $fn coverage ${coverage}% >= floor ${FLOOR}%"
done

echo "issuer blockchain handler coverage floor integration check ok"
