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

DEFAULT_FLOOR="${COSMOS_APP_COVERAGE_FLOOR_DEFAULT:-85.0}"
APP_FLOOR="${COSMOS_APP_COVERAGE_FLOOR:-$DEFAULT_FLOOR}"

is_valid_floor() {
  local value="${1:-}"
  awk -v v="$value" 'BEGIN {
    if (v ~ /^[0-9]+([.][0-9]+)?$/) {
      exit 0
    }
    exit 1
  }'
}

for floor_name in \
  "COSMOS_APP_COVERAGE_FLOOR_DEFAULT:$DEFAULT_FLOOR" \
  "COSMOS_APP_COVERAGE_FLOOR:$APP_FLOOR"; do
  key="${floor_name%%:*}"
  val="${floor_name#*:}"
  if ! is_valid_floor "$val"; then
    echo "invalid floor value for $key: $val (expected numeric format like 85 or 85.0)"
    exit 2
  fi
done

extract_coverage() {
  local output_file="$1"
  awk '
    match($0, /coverage:[[:space:]]*([0-9]+([.][0-9]+)?)%/, m) {
      cov = m[1]
      found = 1
    }
    END {
      if (!found) {
        exit 1
      }
      print cov
    }
  ' "$output_file"
}

meets_floor() {
  local actual="$1"
  local floor="$2"
  awk -v a="$actual" -v b="$floor" 'BEGIN { exit ((a + 0.0) >= (b + 0.0) ? 0 : 1) }'
}

run_with_optional_timeout() {
  if command -v timeout >/dev/null 2>&1; then
    timeout "${COVERAGE_TEST_TIMEOUT_SECONDS:-180}s" "$@"
  else
    "$@"
  fi
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

OUT_FILE="$TMP_DIR/cosmos_app_coverage.out"

set +e
(
  cd blockchain/tdpn-chain
  run_with_optional_timeout go test ./app -count=1 -cover
) >"$OUT_FILE" 2>&1
test_rc=$?
set -e

if (( test_rc != 0 )); then
  echo "app coverage floor check failed: go test failed for ./app (rc=$test_rc)"
  cat "$OUT_FILE"
  exit "$test_rc"
fi

coverage="$(extract_coverage "$OUT_FILE" || true)"
if [[ -z "$coverage" ]]; then
  echo "app coverage floor check failed: unable to parse coverage from go test output for ./app"
  cat "$OUT_FILE"
  exit 1
fi

if ! meets_floor "$coverage" "$APP_FLOOR"; then
  echo "app coverage floor check failed: ./app coverage ${coverage}% is below floor ${APP_FLOOR}%"
  cat "$OUT_FILE"
  exit 1
fi

echo "app coverage floor ok: ./app coverage ${coverage}% >= floor ${APP_FLOOR}%"
echo "cosmos app coverage floor integration check ok"
