#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/runtime_doctor.sh \
    [--base-port N] \
    [--client-iface IFACE] \
    [--exit-iface IFACE] \
    [--vpn-iface IFACE] \
    [--show-json [0|1]]

Purpose:
  Check local runtime hygiene before manual client/WG-only/3-machine validation.

What it checks:
  - unwritable runtime env/state/log paths
  - stale client-vpn / wg-only state files
  - lingering wg-only / client VPN interfaces
  - busy default wg-only ports
  - stale deploy-client-demo-run-* containers

Notes:
  - The command is diagnostic only; it does not mutate state.
  - Use the emitted remediation commands to clean up before the next real-host test.
USAGE
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

validate_iface_or_die() {
  local name="$1"
  local value="$2"
  if [[ -z "$value" || ! "$value" =~ ^[A-Za-z0-9_.:-]+$ ]]; then
    echo "$name contains invalid characters"
    exit 2
  fi
}

sanitize_owner_component() {
  local value="$1"
  value="$(trim "$value")"
  if [[ -z "$value" ]]; then
    printf '%s' ""
    return
  fi
  if [[ "$value" =~ ^[A-Za-z0-9_.:-]+$ ]]; then
    printf '%s' "$value"
    return
  fi
  printf '%s' ""
}

shell_quote() {
  local value="$1"
  printf '%q' "$value"
}

abs_path() {
  local path="$1"
  path="$(trim "$path")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
  elif [[ "$path" = /* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

path_is_within() {
  local path="$1"
  local base="$2"
  [[ "$path" == "$base" || "$path" == "$base/"* ]]
}

path_has_invalid_segments() {
  local path="$1"
  local normalized="${path#/}"
  local segment
  local -a segments=()
  local IFS='/'
  read -r -a segments <<<"$normalized"
  for segment in "${segments[@]}"; do
    if [[ -z "$segment" || "$segment" == "." || "$segment" == ".." ]]; then
      return 0
    fi
  done
  return 1
}

wg_only_prune_remediation() {
  local path="$1"
  local allowlist="$2"
  if [[ -z "$path" || "$path" != /* ]]; then
    printf 'refuse prune: unsafe wg-only path (%s); inspect EASY_NODE_DOCTOR_WG_ONLY_DIR' "$path"
    return
  fi
  if path_has_invalid_segments "$path"; then
    printf 'refuse prune: unsafe wg-only path (%s); inspect EASY_NODE_DOCTOR_WG_ONLY_DIR' "$path"
    return
  fi
  local prefix trimmed
  local -a prefixes=()
  local IFS=','
  read -r -a prefixes <<<"$allowlist"
  for prefix in "${prefixes[@]}"; do
    trimmed="$(trim "$prefix")"
    if [[ -z "$trimmed" || "$trimmed" != /* ]]; then
      continue
    fi
    if path_has_invalid_segments "$trimmed"; then
      continue
    fi
    if path_is_within "$path" "$trimmed"; then
      printf "sudo rm -rf '%s'" "$path"
      return
    fi
  done
  printf 'refuse prune outside allowlist (%s): %s' "$allowlist" "$path"
}

preferred_local_user() {
  if [[ -n "${EASY_NODE_DOCTOR_PREFERRED_USER:-}" ]]; then
    local candidate
    candidate="$(sanitize_owner_component "${EASY_NODE_DOCTOR_PREFERRED_USER}")"
    if [[ -n "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  fi
  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER:-}" != "root" ]]; then
    printf '%s\n' "${SUDO_USER}"
    return
  fi
  id -un
}

preferred_local_group() {
  if [[ -n "${EASY_NODE_DOCTOR_PREFERRED_GROUP:-}" ]]; then
    local candidate
    candidate="$(sanitize_owner_component "${EASY_NODE_DOCTOR_PREFERRED_GROUP}")"
    if [[ -n "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  fi
  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER:-}" != "root" ]]; then
    if id -gn "${SUDO_USER}" >/dev/null 2>&1; then
      id -gn "${SUDO_USER}"
      return
    fi
    if [[ -n "${SUDO_GID:-}" ]]; then
      printf '%s\n' "${SUDO_GID}"
      return
    fi
  fi
  id -gn
}

default_client_vpn_key_dir() {
  local dir="${EASY_NODE_CLIENT_VPN_KEY_DIR:-}"
  if [[ -n "$dir" ]]; then
    printf '%s\n' "$dir"
    return
  fi
  if [[ "$ROOT_DIR" == /mnt/* ]]; then
    if [[ -n "${XDG_STATE_HOME:-}" ]]; then
      dir="$XDG_STATE_HOME/privacynode/client_vpn"
    elif [[ -n "${HOME:-}" ]]; then
      dir="$HOME/.local/state/privacynode/client_vpn"
    else
      dir="/tmp/privacynode_client_vpn"
    fi
  else
    dir="$ROOT_DIR/deploy/data/client_vpn"
  fi
  printf '%s\n' "$dir"
}

path_exists01() {
  local path="$1"
  if [[ -n "$path" && -e "$path" ]]; then
    echo "1"
  else
    echo "0"
  fi
}

json_escape() {
  jq -Rn --arg v "$1" '$v'
}

owner_mode_summary() {
  local path="$1"
  if [[ -z "$path" || ! -e "$path" ]]; then
    printf '%s' "missing"
    return
  fi
  if stat -c '%U:%G mode=%a' "$path" >/dev/null 2>&1; then
    stat -c '%U:%G mode=%a' "$path"
    return
  fi
  if stat -f '%Su:%Sg mode=%Lp' "$path" >/dev/null 2>&1; then
    stat -f '%Su:%Sg mode=%Lp' "$path"
    return
  fi
  printf '%s' "present"
}

state_value() {
  local file="$1"
  local key="$2"
  if [[ -z "$file" || ! -f "$file" ]]; then
    printf '%s' ""
    return
  fi
  awk -F= -v k="$key" '$1 == k { sub(/^[[:space:]]+/, "", $2); print $2; exit }' "$file" 2>/dev/null || true
}

declare -a finding_lines=()
declare -a remediation_lines=()
overall_status="OK"

set_status() {
  local severity="$1"
  case "$severity" in
    FAIL)
      overall_status="FAIL"
      ;;
    WARN)
      if [[ "$overall_status" == "OK" ]]; then
        overall_status="WARN"
      fi
      ;;
  esac
}

add_finding() {
  local severity="$1"
  local code="$2"
  local message="$3"
  local remediation="${4:-}"
  set_status "$severity"
  finding_lines+=("${severity}"$'\t'"${code}"$'\t'"${message}"$'\t'"${remediation}")
  if [[ -n "$remediation" ]]; then
    remediation_lines+=("$remediation")
  fi
}

check_writable_target() {
  local severity="$1"
  local code="$2"
  local label="$3"
  local path="$4"
  local fallback_allowed="${5:-0}"
  local remediation="$6"
  local owner_mode
  local parent

  path="$(abs_path "$path")"
  owner_mode="$(owner_mode_summary "$path")"
  if [[ -e "$path" ]]; then
    if [[ -w "$path" ]]; then
      return
    fi
    if [[ "$fallback_allowed" == "1" ]]; then
      add_finding "$severity" "$code" "$label not writable ($path, $owner_mode); client tooling will fall back but repo state is stale" "$remediation"
    else
      add_finding "$severity" "$code" "$label not writable ($path, $owner_mode)" "$remediation"
    fi
    return
  fi
  parent="$(dirname "$path")"
  if [[ ! -d "$parent" || ! -w "$parent" ]]; then
    add_finding "$severity" "$code" "$label parent directory not writable ($parent, $(owner_mode_summary "$parent"))" "$remediation"
  fi
}

port_busy_detail() {
  local port="$1"
  if ! command -v ss >/dev/null 2>&1; then
    printf '%s' ""
    return
  fi
  ss -ltnupH "( sport = :$port )" 2>/dev/null | head -n1 || true
}

port_busy01() {
  local port="$1"
  if [[ -n "$(port_busy_detail "$port")" ]]; then
    echo "1"
  else
    echo "0"
  fi
}

iface_present01() {
  local iface="$1"
  if ! command -v ip >/dev/null 2>&1; then
    echo "0"
    return
  fi
  if ip link show dev "$iface" >/dev/null 2>&1; then
    echo "1"
  else
    echo "0"
  fi
}

show_json="0"
base_port="${EASY_NODE_DOCTOR_WG_ONLY_BASE_PORT:-19280}"
client_iface="${EASY_NODE_DOCTOR_CLIENT_IFACE:-wgcstack0}"
exit_iface="${EASY_NODE_DOCTOR_EXIT_IFACE:-wgestack0}"
vpn_iface="${EASY_NODE_DOCTOR_VPN_IFACE:-wgvpn0}"
wg_only_prune_allowlist="${EASY_NODE_RUNTIME_FIX_WG_ONLY_PRUNE_ALLOWLIST:-$ROOT_DIR/deploy/data/wg_only}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-port)
      base_port="${2:-}"
      shift 2
      ;;
    --client-iface)
      client_iface="${2:-}"
      shift 2
      ;;
    --exit-iface)
      exit_iface="${2:-}"
      shift 2
      ;;
    --vpn-iface)
      vpn_iface="${2:-}"
      shift 2
      ;;
    --show-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        show_json="${2:-}"
        shift 2
      else
        show_json="1"
        shift
      fi
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

bool_arg_or_die "--show-json" "$show_json"
if [[ ! "$base_port" =~ ^[0-9]+$ ]]; then
  echo "--base-port must be an integer"
  exit 2
fi
validate_iface_or_die "--client-iface" "$client_iface"
validate_iface_or_die "--exit-iface" "$exit_iface"
validate_iface_or_die "--vpn-iface" "$vpn_iface"

client_env_file="$(abs_path "${EASY_NODE_DOCTOR_CLIENT_ENV_FILE:-${EASY_NODE_CLIENT_ENV_FILE:-$ROOT_DIR/deploy/.env.easy.client}}")"
authority_env_file="$(abs_path "${EASY_NODE_DOCTOR_AUTHORITY_ENV_FILE:-$ROOT_DIR/deploy/.env.easy.server}")"
provider_env_file="$(abs_path "${EASY_NODE_DOCTOR_PROVIDER_ENV_FILE:-$ROOT_DIR/deploy/.env.easy.provider}")"
wg_only_dir="$(abs_path "${EASY_NODE_DOCTOR_WG_ONLY_DIR:-$ROOT_DIR/deploy/data/wg_only}")"
client_vpn_key_dir="$(abs_path "${EASY_NODE_DOCTOR_CLIENT_VPN_KEY_DIR:-$(default_client_vpn_key_dir)}")"
log_dir="$(abs_path "${EASY_NODE_DOCTOR_LOG_DIR:-${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}}")"
wg_only_state_file="$(abs_path "${EASY_NODE_DOCTOR_WG_ONLY_STATE_FILE:-$ROOT_DIR/deploy/data/wg_only_stack.state}")"
client_vpn_state_file="$(abs_path "${EASY_NODE_DOCTOR_CLIENT_VPN_STATE_FILE:-$ROOT_DIR/deploy/data/client_vpn.state}")"
preferred_owner_user="$(preferred_local_user)"
preferred_owner_group="$(preferred_local_group)"
preferred_owner_user="$(sanitize_owner_component "$preferred_owner_user")"
preferred_owner_group="$(sanitize_owner_component "$preferred_owner_group")"
preferred_owner_spec="${preferred_owner_user}:${preferred_owner_group}"
wg_only_prune_hint="$(wg_only_prune_remediation "$wg_only_dir" "$wg_only_prune_allowlist")"

check_writable_target "WARN" "client_env_file_not_writable" "client env file" "$client_env_file" "1" "sudo chown $(shell_quote "$preferred_owner_spec") $(shell_quote "$client_env_file")"
check_writable_target "FAIL" "authority_env_file_not_writable" "authority env file" "$authority_env_file" "0" "sudo chown $(shell_quote "$preferred_owner_spec") $(shell_quote "$authority_env_file")"
check_writable_target "FAIL" "provider_env_file_not_writable" "provider env file" "$provider_env_file" "0" "sudo chown $(shell_quote "$preferred_owner_spec") $(shell_quote "$provider_env_file")"
check_writable_target "WARN" "wg_only_dir_not_writable" "wg-only runtime dir" "$wg_only_dir" "0" "$wg_only_prune_hint"
check_writable_target "FAIL" "client_vpn_key_dir_not_writable" "client VPN key dir" "$client_vpn_key_dir" "0" "mkdir -p $(shell_quote "$client_vpn_key_dir") && sudo chown -R $(shell_quote "$preferred_owner_spec") $(shell_quote "$client_vpn_key_dir") && chmod 700 $(shell_quote "$client_vpn_key_dir")"
check_writable_target "FAIL" "log_dir_not_writable" "log dir" "$log_dir" "0" "mkdir -p $(shell_quote "$log_dir") && sudo chown $(shell_quote "$preferred_owner_spec") $(shell_quote "$log_dir") && chmod 700 $(shell_quote "$log_dir")"

if [[ "$client_vpn_key_dir" == /mnt/* ]]; then
  add_finding "WARN" "client_vpn_key_dir_on_drvfs" "client VPN key dir resolves under /mnt ($client_vpn_key_dir); Linux-private state dir is safer for keys" "export EASY_NODE_CLIENT_VPN_KEY_DIR=\"\$HOME/.local/state/privacynode/client_vpn\""
fi

if [[ -f "$wg_only_state_file" ]]; then
  wg_only_pid="$(state_value "$wg_only_state_file" "WG_ONLY_PID")"
  if [[ -z "$wg_only_pid" || ! "$wg_only_pid" =~ ^[0-9]+$ || ! -d "/proc/$wg_only_pid" ]]; then
    add_finding "WARN" "wg_only_state_stale" "wg-only stack state file looks stale ($wg_only_state_file, pid=${wg_only_pid:-unset})" "sudo ./scripts/easy_node.sh wg-only-stack-down --force-iface-cleanup 1 --base-port $(shell_quote "$base_port") --client-iface $(shell_quote "$client_iface") --exit-iface $(shell_quote "$exit_iface")"
  fi
fi

if [[ -f "$client_vpn_state_file" ]]; then
  client_vpn_pid="$(state_value "$client_vpn_state_file" "CLIENT_VPN_PID")"
  if [[ -z "$client_vpn_pid" || ! "$client_vpn_pid" =~ ^[0-9]+$ || ! -d "/proc/$client_vpn_pid" ]]; then
    add_finding "WARN" "client_vpn_state_stale" "client-vpn state file looks stale ($client_vpn_state_file, pid=${client_vpn_pid:-unset})" "sudo ./scripts/easy_node.sh client-vpn-down --force-iface-cleanup 1 --iface $(shell_quote "$vpn_iface")"
  fi
fi

if [[ "$(iface_present01 "$client_iface")" == "1" ]]; then
  add_finding "WARN" "wg_only_client_iface_present" "wg-only client interface still exists ($client_iface)" "sudo ./scripts/easy_node.sh wg-only-stack-down --force-iface-cleanup 1 --base-port $(shell_quote "$base_port") --client-iface $(shell_quote "$client_iface") --exit-iface $(shell_quote "$exit_iface")"
fi
if [[ "$(iface_present01 "$exit_iface")" == "1" ]]; then
  add_finding "WARN" "wg_only_exit_iface_present" "wg-only exit interface still exists ($exit_iface)" "sudo ./scripts/easy_node.sh wg-only-stack-down --force-iface-cleanup 1 --base-port $(shell_quote "$base_port") --client-iface $(shell_quote "$client_iface") --exit-iface $(shell_quote "$exit_iface")"
fi
if [[ "$(iface_present01 "$vpn_iface")" == "1" ]]; then
  add_finding "WARN" "client_vpn_iface_present" "client VPN interface still exists ($vpn_iface)" "sudo ./scripts/easy_node.sh client-vpn-down --force-iface-cleanup 1 --iface $(shell_quote "$vpn_iface")"
fi

for port in "$((base_port + 1))" "$((base_port + 2))" "$((base_port + 3))" "$((base_port + 4))" "$((base_port + 100))" "$((base_port + 101))" "$((base_port + 102))" "$((base_port + 103))"; do
  if [[ "$(port_busy01 "$port")" == "1" ]]; then
    add_finding "WARN" "wg_only_port_busy_${port}" "wg-only default port still busy ($port): $(port_busy_detail "$port")" "sudo ./scripts/easy_node.sh wg-only-stack-down --force-iface-cleanup 1 --base-port $(shell_quote "$base_port") --client-iface $(shell_quote "$client_iface") --exit-iface $(shell_quote "$exit_iface")"
  fi
done

stale_demo_containers=""
if command -v docker >/dev/null 2>&1; then
  stale_demo_containers="$(docker ps -aq --filter 'name=^deploy-client-demo-run-' 2>/dev/null | tr '\n' ' ' | xargs 2>/dev/null || true)"
fi
if [[ -n "$stale_demo_containers" ]]; then
  add_finding "WARN" "stale_client_demo_containers" "stale deploy-client-demo containers found: $stale_demo_containers" "docker rm -f $stale_demo_containers"
fi

findings_total="${#finding_lines[@]}"
warnings_total=0
failures_total=0
for line in "${finding_lines[@]}"; do
  severity="${line%%$'\t'*}"
  if [[ "$severity" == "FAIL" ]]; then
    failures_total=$((failures_total + 1))
  elif [[ "$severity" == "WARN" ]]; then
    warnings_total=$((warnings_total + 1))
  fi
done

echo "[runtime-doctor] status=$overall_status findings=$findings_total warnings=$warnings_total failures=$failures_total"
echo "[runtime-doctor] inputs base_port=$base_port client_iface=$client_iface exit_iface=$exit_iface vpn_iface=$vpn_iface"
echo "[runtime-doctor] paths client_env_file=$client_env_file authority_env_file=$authority_env_file provider_env_file=$provider_env_file wg_only_dir=$wg_only_dir client_vpn_key_dir=$client_vpn_key_dir log_dir=$log_dir"

if ((findings_total == 0)); then
  echo "[runtime-doctor] no findings"
else
  echo "[runtime-doctor] findings:"
  for line in "${finding_lines[@]}"; do
    IFS=$'\t' read -r severity code message remediation <<<"$line"
    echo "  - [$severity] $code: $message"
    if [[ -n "$remediation" ]]; then
      echo "    remediation: $remediation"
    fi
  done
fi

if [[ "$show_json" == "1" ]]; then
  findings_file="$(mktemp)"
  for line in "${finding_lines[@]}"; do
    printf '%s\n' "$line" >>"$findings_file"
  done
  summary_json="$(
    jq -Rn \
      --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg status "$overall_status" \
      --arg client_env_file "$client_env_file" \
      --arg authority_env_file "$authority_env_file" \
      --arg provider_env_file "$provider_env_file" \
      --arg wg_only_dir "$wg_only_dir" \
      --arg client_vpn_key_dir "$client_vpn_key_dir" \
      --arg log_dir "$log_dir" \
      --arg wg_only_state_file "$wg_only_state_file" \
      --arg client_vpn_state_file "$client_vpn_state_file" \
      --argjson base_port "$base_port" \
      --arg client_iface "$client_iface" \
      --arg exit_iface "$exit_iface" \
      --arg vpn_iface "$vpn_iface" \
      --arg preferred_owner_user "$preferred_owner_user" \
      --arg preferred_owner_group "$preferred_owner_group" \
      --argjson findings_total "$findings_total" \
      --argjson warnings_total "$warnings_total" \
      --argjson failures_total "$failures_total" \
      --slurpfile findings <(jq -Rn '[inputs | split("\t") | {severity: .[0], code: .[1], message: .[2], remediation: .[3]}]' "$findings_file") \
      '{
        version: 1,
        generated_at_utc: $generated_at_utc,
        status: $status,
        summary: {
          findings_total: $findings_total,
          warnings_total: $warnings_total,
          failures_total: $failures_total
        },
        inputs: {
          base_port: $base_port,
          client_iface: $client_iface,
          exit_iface: $exit_iface,
          vpn_iface: $vpn_iface
        },
        ownership: {
          preferred_user: $preferred_owner_user,
          preferred_group: $preferred_owner_group
        },
        paths: {
          client_env_file: $client_env_file,
          authority_env_file: $authority_env_file,
          provider_env_file: $provider_env_file,
          wg_only_dir: $wg_only_dir,
          client_vpn_key_dir: $client_vpn_key_dir,
          log_dir: $log_dir,
          wg_only_state_file: $wg_only_state_file,
          client_vpn_state_file: $client_vpn_state_file
        },
        findings: ($findings[0] // [])
      }'
  )"
  echo "[runtime-doctor] summary_json_payload:"
  printf '%s\n' "$summary_json"
  rm -f "$findings_file"
fi

if [[ "$overall_status" == "FAIL" ]]; then
  exit 1
fi
exit 0
