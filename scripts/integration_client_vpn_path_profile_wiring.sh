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
check_pattern '"CLIENT_SESSION_REUSE=1"' \
  "client-vpn-up missing session reuse wiring for 1hop/speed-1hop"
check_pattern '"CLIENT_STICKY_PAIR_SEC=300"' \
  "client-vpn-up missing sticky-pair wiring for 1hop/speed-1hop"

echo "[client-vpn-path-profile] route install defaults"
check_pattern 'local install_route="\$\{CLIENT_WG_INSTALL_ROUTE:-0\}"' \
  "client-vpn-up must default CLIENT_WG_INSTALL_ROUTE to 0"
check_pattern 'local allow_no_route="\$\{GPM_CLIENT_VPN_ALLOW_NO_ROUTE:-\$\{TDPN_CLIENT_VPN_ALLOW_NO_ROUTE:-\$\{CLIENT_WG_ALLOW_NO_ROUTE:-0\}\}\}"' \
  "client-vpn-up must default no-route override to disabled"
check_pattern 'local install_route="0"' \
  "simple-client-vpn-session must default --install-route to 0"
check_pattern 'client_vpn_route_mode_for\(\)' \
  "client-vpn-up missing route mode classifier"
check_pattern 'client-vpn-up refuses no-route full-tunnel in prod profile' \
  "client-vpn-up must fail closed for prod full-tunnel no-route starts"
check_pattern 'set --install-route 1, use split AllowedIPs, or disable --prod-profile for controlled diagnostics' \
  "client-vpn-up missing operator remediation hint for prod no-route refusal"
check_pattern 'client-vpn-up route mode: no-route \(full-tunnel AllowedIPs=\$allowed_ips with install_route=0; host traffic will not be routed through the VPN\)' \
  "client-vpn-up missing explicit no-route warning for full-tunnel AllowedIPs with install_route=0"
check_pattern 'CLIENT_VPN_ROUTE_MODE=\$route_mode' \
  "client-vpn-up missing state record for route mode"
check_pattern 'CLIENT_VPN_ALLOW_NO_ROUTE=\$allow_no_route' \
  "client-vpn-up missing state record for explicit no-route override"
check_pattern '"CLIENT_WG_ALLOW_NO_ROUTE=\$allow_no_route"' \
  "client-vpn-up missing runtime env record for explicit no-route override"
check_pattern '"CLIENT_ALLOW_INSECURE_CONTROL_URL_HTTP=1"' \
  "client-vpn-up missing runtime env for explicit lab remote HTTP opt-in"
check_pattern '"CLIENT_ALLOW_LAB_CONTROL_PLANE_LITERAL_IPS=1"' \
  "client-vpn-up missing literal lab control-plane IP runtime env for explicit lab remote HTTP opt-in"
check_pattern 'echo "  route_mode: \$route_mode"' \
  "client-vpn-up output missing route mode visibility"
check_pattern 'route_warning: full-tunnel AllowedIPs are configured but install_route=0, so host traffic is not routed through the VPN' \
  "client-vpn-up/status missing explicit no-route warning"

echo "[client-vpn-path-profile] wireguard runtime readiness marker"
check_pattern 'client wireguard traffic verified:|client wg-kernel proxy uplink observed:' \
  "client-vpn-up must wait for post-WireGuard-config runtime readiness marker"
check_pattern 'wireguard runtime did not become ready' \
  "client-vpn-up timeout must describe WireGuard runtime readiness"
check_absent 'if rg -q "client received wg-session config" "\$log_file"; then' \
  "client-vpn-up still treats session config receipt as tunnel readiness"

echo "[client-vpn-path-profile] background process cleanup"
check_pattern "nohup setsid bash -c 'exec go run ./cmd/node --client'" \
  "client-vpn-up must launch background go-run in its own process group when setsid is available"
check_pattern 'CLIENT_VPN_PROCESS_GROUP=\$process_group' \
  "client-vpn-up state file missing process group marker"
check_pattern 'client_vpn_stop_pid "\$pid" "\$process_group"' \
  "client-vpn-up/down must stop the full recorded process group"

echo "[client-vpn-path-profile] 3-hop middle runtime parity"
check_pattern 'client_vpn_runtime_middle_relay_eligible\(\)' \
  "client-vpn-up/preflight missing runtime middle admission helper"
check_pattern 'client_vpn_middle_relay_summary "\$directory_urls" "\$timeout_sec" "\$middle_runtime_strict"' \
  "client-vpn-preflight missing strict runtime middle summary wiring"
check_pattern 'client_vpn_middle_relay_summary "\$directory_urls" 8 "\$middle_runtime_strict"' \
  "client-vpn-up missing strict runtime middle summary wiring"
check_pattern 'if \[\[ "\$normalized_path_profile" == "privacy" \]\]; then' \
  "client-vpn-up/preflight must branch on 3hop/private for middle-relay enforcement"
check_pattern 'middle_relay_check="1"' \
  "client-vpn-up/preflight must force middle-relay check for 3hop/private"
check_pattern 'runtime_strict=\$middle_runtime_strict' \
  "client-vpn-preflight should expose strict runtime middle mode"

echo "[client-vpn-path-profile] selection-policy defaults by profile"
check_pattern '1\|0\|1\|1\.80\|1\.35\|1\.15\|180\|120\|20\|25' \
  "path-profile speed/fast defaults missing expected selection-policy tuple"
check_pattern '1\|0\|1\|1\.80\|1\.35\|1\.15\|300\|120\|20\|20' \
  "path-profile speed-1hop defaults missing expected selection-policy tuple"
check_pattern '1\|1\|0\|1\.60\|1\.25\|1\.10\|420\|240\|10\|5' \
  "path-profile private/privacy defaults missing expected selection-policy tuple"
check_pattern '"CLIENT_STICKY_PAIR_SEC=\$sticky_pair_sec"' \
  "client-vpn-up missing exported CLIENT_STICKY_PAIR_SEC runtime env"
check_pattern '"CLIENT_ENTRY_ROTATION_SEC=\$entry_rotation_sec"' \
  "client-vpn-up missing exported CLIENT_ENTRY_ROTATION_SEC runtime env"
check_pattern '"CLIENT_ENTRY_ROTATION_JITTER_PCT=\$entry_rotation_jitter_pct"' \
  "client-vpn-up missing exported CLIENT_ENTRY_ROTATION_JITTER_PCT runtime env"
check_pattern '"CLIENT_EXIT_EXPLORATION_PCT=\$exit_exploration_pct"' \
  "client-vpn-up missing exported CLIENT_EXIT_EXPLORATION_PCT runtime env"

echo "[client-vpn-path-profile] session lifecycle defaults"
check_pattern 'local session_reuse="\$\{CLIENT_SESSION_REUSE:-1\}"' \
  "client-vpn-up missing CLIENT_SESSION_REUSE default wiring"
check_pattern 'local session_refresh_lead_sec="\$\{CLIENT_SESSION_REFRESH_LEAD_SEC:-20\}"' \
  "client-vpn-up missing CLIENT_SESSION_REFRESH_LEAD_SEC default wiring"
check_pattern '"CLIENT_SESSION_REUSE=\$session_reuse"' \
  "client-vpn-up missing exported CLIENT_SESSION_REUSE runtime env"
check_pattern '"CLIENT_SESSION_REFRESH_LEAD_SEC=\$session_refresh_lead_sec"' \
  "client-vpn-up missing exported CLIENT_SESSION_REFRESH_LEAD_SEC runtime env"
check_pattern 'client-vpn-up requires CLIENT_SESSION_REUSE to be 0 or 1' \
  "client-vpn-up missing CLIENT_SESSION_REUSE validation guardrail"
check_pattern 'client-vpn-up requires CLIENT_SESSION_REFRESH_LEAD_SEC >= 1' \
  "client-vpn-up missing CLIENT_SESSION_REFRESH_LEAD_SEC validation guardrail"
check_pattern 'client-vpn-up beta/prod profile requires --subject, --subject-file, or --anon-cred' \
  "client-vpn-up missing beta/prod identity guardrail"

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
