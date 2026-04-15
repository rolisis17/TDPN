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

DEFAULT_FLOOR="${COSMOS_MODULE_COVERAGE_FLOOR_DEFAULT:-90.0}"
FLOOR_VPNBILLING="${COSMOS_MODULE_COVERAGE_FLOOR_VPNBILLING_MODULE:-$DEFAULT_FLOOR}"
FLOOR_VPNREWARDS="${COSMOS_MODULE_COVERAGE_FLOOR_VPNREWARDS_MODULE:-$DEFAULT_FLOOR}"
FLOOR_VPNSLASHING="${COSMOS_MODULE_COVERAGE_FLOOR_VPNSLASHING_MODULE:-$DEFAULT_FLOOR}"
FLOOR_VPNSPONSOR="${COSMOS_MODULE_COVERAGE_FLOOR_VPNSPONSOR_MODULE:-$DEFAULT_FLOOR}"

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
  "COSMOS_MODULE_COVERAGE_FLOOR_DEFAULT:$DEFAULT_FLOOR" \
  "COSMOS_MODULE_COVERAGE_FLOOR_VPNBILLING_MODULE:$FLOOR_VPNBILLING" \
  "COSMOS_MODULE_COVERAGE_FLOOR_VPNREWARDS_MODULE:$FLOOR_VPNREWARDS" \
  "COSMOS_MODULE_COVERAGE_FLOOR_VPNSLASHING_MODULE:$FLOOR_VPNSLASHING" \
  "COSMOS_MODULE_COVERAGE_FLOOR_VPNSPONSOR_MODULE:$FLOOR_VPNSPONSOR"; do
  key="${floor_name%%:*}"
  val="${floor_name#*:}"
  if ! is_valid_floor "$val"; then
    echo "invalid floor value for $key: $val (expected numeric format like 90 or 90.0)"
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

declare -a packages=(
  "./x/vpnbilling/module"
  "./x/vpnrewards/module"
  "./x/vpnslashing/module"
  "./x/vpnsponsor/module"
)

declare -A floors=(
  ["./x/vpnbilling/module"]="$FLOOR_VPNBILLING"
  ["./x/vpnrewards/module"]="$FLOOR_VPNREWARDS"
  ["./x/vpnslashing/module"]="$FLOOR_VPNSLASHING"
  ["./x/vpnsponsor/module"]="$FLOOR_VPNSPONSOR"
)

for pkg in "${packages[@]}"; do
  floor="${floors[$pkg]}"
  out_file="$TMP_DIR/$(echo "$pkg" | tr '/.' '_').out"

  set +e
  (
    cd blockchain/tdpn-chain
    run_with_optional_timeout go test "$pkg" -count=1 -cover
  ) >"$out_file" 2>&1
  test_rc=$?
  set -e

  if (( test_rc != 0 )); then
    echo "coverage floor check failed: go test failed for $pkg (rc=$test_rc)"
    cat "$out_file"
    exit "$test_rc"
  fi

  coverage="$(extract_coverage "$out_file" || true)"
  if [[ -z "$coverage" ]]; then
    echo "coverage floor check failed: unable to parse coverage from go test output for $pkg"
    cat "$out_file"
    exit 1
  fi

  if ! meets_floor "$coverage" "$floor"; then
    echo "coverage floor check failed: $pkg coverage ${coverage}% is below floor ${floor}%"
    cat "$out_file"
    exit 1
  fi

  echo "coverage floor ok: $pkg coverage ${coverage}% >= floor ${floor}%"
done

echo "cosmos module coverage floor integration check ok"
