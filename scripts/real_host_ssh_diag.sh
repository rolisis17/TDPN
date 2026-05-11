#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/real_host_ssh_diag.sh \
    --host-a HOST \
    --host-b HOST \
    [--ssh-user USER] \
    [--ssh-port PORT] \
    [--ssh-key PATH] \
    [--repo-a PATH] \
    [--repo-b PATH] \
    [--remote-repo-check [0|1]] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Diagnose real-host SSH reachability in layers before declaring a machine
  unreachable: local Tailscale availability, Tailscale peer status/ping, TCP
  port reachability, SSH key auth, and optional remote repo/docker health.

Defaults:
  --ssh-user stella
  --ssh-port 2222
  --ssh-key ~/.ssh/tdpn_codex_test when present, else ~/.ssh/id_ed25519
  --remote-repo-check 1
  --summary-json .easy-node-logs/real_host_ssh_diag_summary.json
  --print-summary-json 1
USAGE
}

trim() {
  local value="${1:-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

abs_path() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
  elif [[ "$path" == "~/"* ]]; then
    printf '%s/%s' "${HOME:-}" "${path#"~/"}"
  elif [[ "$path" == /* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
}

require_value_or_die() {
  local flag="$1"
  local value="${2:-}"
  if [[ -z "$value" || "$value" == --* ]]; then
    echo "$flag requires a value"
    exit 2
  fi
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

positive_int_arg_or_die() {
  local name="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]] || [[ "$value" -lt 1 ]]; then
    echo "$name must be an integer >= 1"
    exit 2
  fi
}

timestamp_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

default_ssh_key() {
  if [[ -n "${REAL_HOST_SSH_DIAG_SSH_KEY:-}" ]]; then
    printf '%s' "$REAL_HOST_SSH_DIAG_SSH_KEY"
  elif [[ -n "${HOME:-}" && -f "$HOME/.ssh/tdpn_codex_test" ]]; then
    printf '%s' "$HOME/.ssh/tdpn_codex_test"
  elif [[ -n "${HOME:-}" ]]; then
    printf '%s' "$HOME/.ssh/id_ed25519"
  else
    printf '%s' ""
  fi
}

status_from_rc() {
  local rc="$1"
  if [[ "$rc" -eq 0 ]]; then
    printf '%s' "pass"
  else
    printf '%s' "fail"
  fi
}

first_lines_json() {
  local path="$1"
  local max_lines="${2:-12}"
  if [[ -f "$path" ]]; then
    sed -n "1,${max_lines}p" "$path" | jq -R -s 'split("\n") | map(select(length > 0))'
  else
    jq -n '[]'
  fi
}

tcp_probe() {
  local host="$1"
  local port="$2"
  local timeout_sec="$3"
  if command -v nc >/dev/null 2>&1; then
    nc -z -w "$timeout_sec" "$host" "$port" >/dev/null 2>&1
    return $?
  fi
  if command -v timeout >/dev/null 2>&1; then
    timeout "$timeout_sec" bash -c "</dev/tcp/$host/$port" >/dev/null 2>&1
    return $?
  fi
  bash -c "</dev/tcp/$host/$port" >/dev/null 2>&1
}

host_remote_command() {
  local repo="$1"
  local quoted_repo=""
  if [[ -n "$repo" ]]; then
    printf -v quoted_repo '%q' "$repo"
    cat <<REMOTE
set -e
printf 'remote_hostname='
hostname
cd $quoted_repo
printf 'repo_pwd='
pwd
if command -v git >/dev/null 2>&1; then
  printf 'git_branch='
  git rev-parse --abbrev-ref HEAD 2>/dev/null || true
  printf 'git_head='
  git rev-parse --short HEAD 2>/dev/null || true
  printf 'git_dirty_count='
  git status --short 2>/dev/null | wc -l | tr -d ' '
fi
if command -v docker >/dev/null 2>&1; then
  printf 'docker_container_count='
  docker ps -q 2>/dev/null | wc -l | tr -d ' '
  docker ps --format 'docker_container={{.Names}} {{.Status}}' 2>/dev/null || true
fi
REMOTE
  else
    cat <<'REMOTE'
set -e
printf 'remote_hostname='
hostname
REMOTE
  fi
}

host_a="${A_HOST:-}"
host_b="${B_HOST:-}"
ssh_user="${REAL_HOST_SSH_DIAG_SSH_USER:-stella}"
ssh_port="${REAL_HOST_SSH_DIAG_SSH_PORT:-2222}"
ssh_key="$(default_ssh_key)"
repo_a="${REAL_HOST_SSH_DIAG_REPO_A:-}"
repo_b="${REAL_HOST_SSH_DIAG_REPO_B:-}"
remote_repo_check="${REAL_HOST_SSH_DIAG_REMOTE_REPO_CHECK:-1}"
connect_timeout_sec="${REAL_HOST_SSH_DIAG_CONNECT_TIMEOUT_SEC:-10}"
tailscale_ping_timeout_sec="${REAL_HOST_SSH_DIAG_TAILSCALE_PING_TIMEOUT_SEC:-5}"
summary_json="${REAL_HOST_SSH_DIAG_SUMMARY_JSON:-.easy-node-logs/real_host_ssh_diag_summary.json}"
print_summary_json="${REAL_HOST_SSH_DIAG_PRINT_SUMMARY_JSON:-1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host-a|--a-host)
      require_value_or_die "$1" "${2:-}"
      host_a="$2"
      shift 2
      ;;
    --host-b|--b-host)
      require_value_or_die "$1" "${2:-}"
      host_b="$2"
      shift 2
      ;;
    --ssh-user)
      require_value_or_die "$1" "${2:-}"
      ssh_user="$2"
      shift 2
      ;;
    --ssh-port)
      require_value_or_die "$1" "${2:-}"
      ssh_port="$2"
      shift 2
      ;;
    --ssh-key)
      require_value_or_die "$1" "${2:-}"
      ssh_key="$2"
      shift 2
      ;;
    --repo-a)
      require_value_or_die "$1" "${2:-}"
      repo_a="$2"
      shift 2
      ;;
    --repo-b)
      require_value_or_die "$1" "${2:-}"
      repo_b="$2"
      shift 2
      ;;
    --remote-repo-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        remote_repo_check="$2"
        shift 2
      else
        remote_repo_check="1"
        shift
      fi
      ;;
    --connect-timeout-sec)
      require_value_or_die "$1" "${2:-}"
      connect_timeout_sec="$2"
      shift 2
      ;;
    --tailscale-ping-timeout-sec)
      require_value_or_die "$1" "${2:-}"
      tailscale_ping_timeout_sec="$2"
      shift 2
      ;;
    --summary-json)
      require_value_or_die "$1" "${2:-}"
      summary_json="$2"
      shift 2
      ;;
    --print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_summary_json="$2"
        shift 2
      else
        print_summary_json="1"
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

for cmd in bash date jq mkdir ssh; do
  need_cmd "$cmd"
done

if [[ -z "$host_a" || -z "$host_b" ]]; then
  echo "real-host-ssh-diag requires --host-a and --host-b, or A_HOST/B_HOST env vars"
  exit 2
fi
positive_int_arg_or_die "--ssh-port" "$ssh_port"
positive_int_arg_or_die "--connect-timeout-sec" "$connect_timeout_sec"
positive_int_arg_or_die "--tailscale-ping-timeout-sec" "$tailscale_ping_timeout_sec"
bool_arg_or_die "--remote-repo-check" "$remote_repo_check"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

ssh_key="$(abs_path "$ssh_key")"
if [[ -z "$ssh_key" || ! -f "$ssh_key" ]]; then
  echo "real-host-ssh-diag ssh key not found: ${ssh_key:-<empty>}"
  exit 2
fi

summary_json="$(abs_path "$summary_json")"
mkdir -p "$(dirname "$summary_json")" "$(dirname "$summary_json")/real_host_ssh_diag"
reports_dir="$(dirname "$summary_json")/real_host_ssh_diag"
hosts_jsonl="$reports_dir/hosts.jsonl"
: >"$hosts_jsonl"

tailscale_available=false
tailscale_status_rc=127
tailscale_status_log="$reports_dir/tailscale_status.log"
if command -v tailscale >/dev/null 2>&1; then
  tailscale_available=true
  set +e
  tailscale status >"$tailscale_status_log" 2>&1
  tailscale_status_rc=$?
  set -e
else
  printf '%s\n' "tailscale command not found" >"$tailscale_status_log"
fi

run_host_diag() {
  local host_id="$1"
  local host="$2"
  local repo="$3"
  local host_dir="$reports_dir/$host_id"
  local tailscale_ping_log tcp_log ssh_log remote_command
  local tailscale_ping_rc tcp_rc ssh_rc
  local tailscale_ping_status tcp_status ssh_status
  local repo_arg=""

  mkdir -p "$host_dir"
  tailscale_ping_log="$host_dir/tailscale_ping.log"
  tcp_log="$host_dir/tcp_probe.log"
  ssh_log="$host_dir/ssh.log"

  tailscale_ping_rc=127
  if [[ "$tailscale_available" == "true" ]]; then
    set +e
    tailscale ping --timeout="${tailscale_ping_timeout_sec}s" "$host" >"$tailscale_ping_log" 2>&1
    tailscale_ping_rc=$?
    set -e
  else
    printf '%s\n' "tailscale command not found" >"$tailscale_ping_log"
  fi
  tailscale_ping_status="$(status_from_rc "$tailscale_ping_rc")"
  if [[ "$tailscale_available" != "true" ]]; then
    tailscale_ping_status="skip"
  fi

  set +e
  tcp_probe "$host" "$ssh_port" "$connect_timeout_sec" >"$tcp_log" 2>&1
  tcp_rc=$?
  set -e
  tcp_status="$(status_from_rc "$tcp_rc")"

  if [[ "$remote_repo_check" == "1" ]]; then
    repo_arg="$repo"
  fi
  remote_command="$(host_remote_command "$repo_arg")"
  set +e
  ssh \
    -i "$ssh_key" \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=no \
    -o ConnectTimeout="$connect_timeout_sec" \
    -p "$ssh_port" \
    "$ssh_user@$host" \
    bash -s >"$ssh_log" 2>&1 <<<"$remote_command"
  ssh_rc=$?
  set -e
  ssh_status="$(status_from_rc "$ssh_rc")"

  printf '[real-host-ssh-diag] host=%s addr=%s tailscale=%s tcp=%s ssh=%s log=%s\n' \
    "$host_id" "$host" "$tailscale_ping_status" "$tcp_status" "$ssh_status" "$ssh_log"

  jq -n \
    --arg id "$host_id" \
    --arg host "$host" \
    --arg repo "$repo_arg" \
    --argjson tailscale_ping_rc "$tailscale_ping_rc" \
    --arg tailscale_ping_status "$tailscale_ping_status" \
    --arg tailscale_ping_log "$tailscale_ping_log" \
    --argjson tcp_rc "$tcp_rc" \
    --arg tcp_status "$tcp_status" \
    --arg tcp_log "$tcp_log" \
    --argjson ssh_rc "$ssh_rc" \
    --arg ssh_status "$ssh_status" \
    --arg ssh_log "$ssh_log" \
    --argjson tailscale_ping_excerpt "$(first_lines_json "$tailscale_ping_log" 8)" \
    --argjson tcp_excerpt "$(first_lines_json "$tcp_log" 8)" \
    --argjson ssh_excerpt "$(first_lines_json "$ssh_log" 16)" \
    '{
      id: $id,
      host: $host,
      remote_repo_path: $repo,
      checks: {
        tailscale_ping: {
          status: $tailscale_ping_status,
          rc: $tailscale_ping_rc,
          log: $tailscale_ping_log,
          excerpt: $tailscale_ping_excerpt
        },
        tcp_ssh_port: {
          status: $tcp_status,
          rc: $tcp_rc,
          log: $tcp_log,
          excerpt: $tcp_excerpt
        },
        ssh_key_auth: {
          status: $ssh_status,
          rc: $ssh_rc,
          log: $ssh_log,
          excerpt: $ssh_excerpt
        }
      }
    }' >>"$hosts_jsonl"
}

run_host_diag "A" "$host_a" "$repo_a"
run_host_diag "B" "$host_b" "$repo_b"

hosts_json="$(jq -s '.' "$hosts_jsonl")"
failed_hosts="$(printf '%s\n' "$hosts_json" | jq '[.[] | select(.checks.ssh_key_auth.status != "pass")] | length')"
tcp_failed_hosts="$(printf '%s\n' "$hosts_json" | jq '[.[] | select(.checks.tcp_ssh_port.status != "pass")] | length')"
tailscale_failed_hosts="$(printf '%s\n' "$hosts_json" | jq '[.[] | select(.checks.tailscale_ping.status == "fail")] | length')"

status="pass"
rc=0
notes="A/B SSH key auth is reachable"
if [[ "$failed_hosts" -gt 0 ]]; then
  status="fail"
  rc=1
  notes="one or more hosts failed SSH key auth"
elif [[ "$tcp_failed_hosts" -gt 0 || "$tailscale_failed_hosts" -gt 0 ]]; then
  status="warn"
  rc=0
  notes="SSH key auth passed, but one or more lower-layer probes need review"
fi

next_actions_json="$(printf '%s\n' "$hosts_json" | jq '
  [
    .[] as $host
    | (
      if $host.checks.tailscale_ping.status == "fail" then
        {host: $host.id, layer: "tailscale_ping", action: "Check Tailscale daemon/login and peer status before retrying SSH."}
      else empty end
    ),
    (
      if $host.checks.tcp_ssh_port.status == "fail" then
        {host: $host.id, layer: "tcp_ssh_port", action: "Confirm sshd is listening on the configured port and local firewall allows it."}
      else empty end
    ),
    (
      if $host.checks.ssh_key_auth.status == "fail" then
        {host: $host.id, layer: "ssh_key_auth", action: "Confirm the selected public key is in authorized_keys for the remote user."}
      else empty end
    )
  ]')"

tailscale_status_excerpt="$(first_lines_json "$tailscale_status_log" 20)"

jq -n \
  --arg generated_at_utc "$(timestamp_utc)" \
  --arg status "$status" \
  --argjson rc "$rc" \
  --arg notes "$notes" \
  --arg ssh_user "$ssh_user" \
  --argjson ssh_port "$ssh_port" \
  --arg ssh_key "$ssh_key" \
  --argjson remote_repo_check "$remote_repo_check" \
  --argjson connect_timeout_sec "$connect_timeout_sec" \
  --argjson tailscale_ping_timeout_sec "$tailscale_ping_timeout_sec" \
  --argjson tailscale_available "$tailscale_available" \
  --argjson tailscale_status_rc "$tailscale_status_rc" \
  --arg tailscale_status_log "$tailscale_status_log" \
  --argjson tailscale_status_excerpt "$tailscale_status_excerpt" \
  --argjson hosts "$hosts_json" \
  --argjson next_actions "$next_actions_json" \
  --arg summary_json "$summary_json" \
  '{
    version: 1,
    schema: {
      id: "real_host_ssh_diag_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    notes: $notes,
    inputs: {
      ssh_user: $ssh_user,
      ssh_port: $ssh_port,
      ssh_key_path: $ssh_key,
      remote_repo_check: ($remote_repo_check == 1),
      connect_timeout_sec: $connect_timeout_sec,
      tailscale_ping_timeout_sec: $tailscale_ping_timeout_sec
    },
    local: {
      tailscale_available: $tailscale_available,
      tailscale_status_rc: $tailscale_status_rc,
      tailscale_status_log: $tailscale_status_log,
      tailscale_status_excerpt: $tailscale_status_excerpt
    },
    hosts: $hosts,
    next_actions: $next_actions,
    artifacts: {
      summary_json: $summary_json
    }
  }' >"$summary_json"

echo "real-host-ssh-diag: status=$status"
echo "summary_json: $summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$rc"
