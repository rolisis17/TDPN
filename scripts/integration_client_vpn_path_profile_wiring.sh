#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TARGET="scripts/easy_node.sh"

for cmd in rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

if [[ ! -f "$TARGET" ]]; then
  echo "missing script: $TARGET"
  exit 1
fi

check_pattern() {
  local pattern="$1"
  local message="$2"
  if ! rg -q -- "$pattern" "$TARGET"; then
    echo "$message"
    exit 1
  fi
}

check_absent() {
  local pattern="$1"
  local message="$2"
  if rg -q -- "$pattern" "$TARGET"; then
    echo "$message"
    exit 1
  fi
}

echo "[client-vpn-path-profile] 1-hop guardrails"
check_pattern 'client-vpn-up --path-profile 1hop/speed-1hop requires --beta-profile 0 and --prod-profile 0' \
  "client-vpn-up missing non-strict guardrail for 1hop/speed-1hop"
check_pattern 'client-vpn-up --path-profile 1hop/speed-1hop requires --distinct-operators 0 \(one-hop direct-exit mode\)' \
  "client-vpn-up missing distinct-operators guardrail for 1hop/speed-1hop"
check_absent 'client-vpn-up does not support --path-profile 1hop/speed-1hop yet' \
  "client-vpn-up still hard-blocks 1hop/speed-1hop"

echo "[client-vpn-path-profile] 1-hop runtime wiring"
check_pattern 'if \[\[ "\$speed_onehop_profile" == "1" && "\$distinct_set" -eq 0 \]\]; then' \
  "client-vpn-up missing default distinct-operators override for 1hop/speed-1hop"
check_pattern '"CLIENT_ALLOW_DIRECT_EXIT_FALLBACK=1"' \
  "client-vpn-up missing direct-exit fallback wiring for 1hop/speed-1hop"
check_pattern '"CLIENT_FORCE_DIRECT_EXIT=1"' \
  "client-vpn-up missing force-direct-exit wiring for 1hop/speed-1hop"

echo "[client-vpn-path-profile] status/state visibility"
check_pattern 'CLIENT_VPN_PATH_PROFILE=\$normalized_path_profile' \
  "client-vpn-up missing state record for path profile"
check_pattern 'echo "  path_profile: \$\{normalized_path_profile:-default\}"' \
  "client-vpn-up output missing path profile visibility"
check_pattern 'path_profile="\$\(identity_value "\$state_file" "CLIENT_VPN_PATH_PROFILE"\)"' \
  "client-vpn-status missing path profile state read"
check_pattern 'echo "  path_profile: \$\{path_profile:-default\}"' \
  "client-vpn-status missing path profile output"

echo "client-vpn path-profile wiring integration check ok"
