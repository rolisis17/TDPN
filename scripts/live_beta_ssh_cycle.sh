#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

branch="${LIVE_BETA_BRANCH:-codex/gpm-productization-checkpoint}"
ssh_key="${LIVE_BETA_SSH_KEY:-$HOME/.ssh/tdpn_codex_test}"
a_user="${LIVE_BETA_A_USER:-stella}"
a_host="${LIVE_BETA_A_HOST:-100.113.245.61}"
a_port="${LIVE_BETA_A_PORT:-2222}"
a_repo="${LIVE_BETA_A_REPO:-/mnt/c/Users/Stella/Downloads/TDPN}"
a_operator="${LIVE_BETA_A_OPERATOR:-op-a}"
a_issuer="${LIVE_BETA_A_ISSUER:-issuer-a}"
b_user="${LIVE_BETA_B_USER:-stella}"
b_host="${LIVE_BETA_B_HOST:-100.64.244.24}"
b_port="${LIVE_BETA_B_PORT:-2222}"
b_repo="${LIVE_BETA_B_REPO:-/home/stella/myfirstproject/trust-tiered decentralized privacy network}"
b_operator="${LIVE_BETA_B_OPERATOR:-op-b}"
subject="${LIVE_BETA_SUBJECT:-}"
generate_subject="${LIVE_BETA_GENERATE_SUBJECT:-0}"
invite_prefix="${LIVE_BETA_INVITE_PREFIX:-inv}"
invite_tier="${LIVE_BETA_INVITE_TIER:-1}"
invite_wait_sec="${LIVE_BETA_INVITE_WAIT_SEC:-10}"
mode="${LIVE_BETA_MODE:-full}"
timeout_sec="${LIVE_BETA_TIMEOUT_SEC:-180}"
client_timeout_sec="${LIVE_BETA_CLIENT_TIMEOUT_SEC:-180}"
client_force_build="${LIVE_BETA_CLIENT_FORCE_BUILD:-1}"
ssh_connect_timeout_sec="${LIVE_BETA_SSH_CONNECT_TIMEOUT_SEC:-15}"
ssh_attempts="${LIVE_BETA_SSH_ATTEMPTS:-3}"
skip_pull="${LIVE_BETA_SKIP_PULL:-0}"
skip_up="${LIVE_BETA_SKIP_UP:-0}"
skip_client="${LIVE_BETA_SKIP_CLIENT:-0}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/live_beta_ssh_cycle.sh [--mode ssh-check|pull|up|health|topology|client|full] [--subject INVITE] [--generate-subject]

Defaults target the current two-machine Tailscale lab:
  A: stella@100.113.245.61:2222  repo=/mnt/c/Users/Stella/Downloads/TDPN
  B: stella@100.64.244.24:2222   repo=/home/stella/myfirstproject/trust-tiered decentralized privacy network

Environment overrides:
  LIVE_BETA_SSH_KEY, LIVE_BETA_BRANCH
  LIVE_BETA_A_USER, LIVE_BETA_A_HOST, LIVE_BETA_A_PORT, LIVE_BETA_A_REPO
  LIVE_BETA_B_USER, LIVE_BETA_B_HOST, LIVE_BETA_B_PORT, LIVE_BETA_B_REPO
  LIVE_BETA_SUBJECT, LIVE_BETA_GENERATE_SUBJECT=1, LIVE_BETA_INVITE_PREFIX, LIVE_BETA_INVITE_TIER
  LIVE_BETA_CLIENT_FORCE_BUILD=0
  LIVE_BETA_SKIP_PULL=1, LIVE_BETA_SKIP_UP=1, LIVE_BETA_SKIP_CLIENT=1
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      mode="${2:-}"
      shift 2
      ;;
    --subject)
      subject="${2:-}"
      shift 2
      ;;
    --generate-subject)
      generate_subject="1"
      shift
      ;;
    --branch)
      branch="${2:-}"
      shift 2
      ;;
    --ssh-key)
      ssh_key="${2:-}"
      shift 2
      ;;
    --timeout-sec)
      timeout_sec="${2:-}"
      shift 2
      ;;
    --client-timeout-sec)
      client_timeout_sec="${2:-}"
      shift 2
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

case "$mode" in
  ssh-check|pull|up|health|topology|client|full)
    ;;
  *)
    echo "invalid --mode: $mode"
    usage
    exit 2
    ;;
esac

for n in timeout_sec client_timeout_sec ssh_connect_timeout_sec ssh_attempts; do
  v="${!n}"
  if ! [[ "$v" =~ ^[0-9]+$ ]] || ((v < 1)); then
    echo "$n must be a positive integer"
    exit 2
  fi
done
if [[ "$generate_subject" != "0" && "$generate_subject" != "1" ]]; then
  echo "generate_subject must be 0 or 1"
  exit 2
fi
if [[ "$client_force_build" != "0" && "$client_force_build" != "1" ]]; then
  echo "client_force_build must be 0 or 1"
  exit 2
fi
if [[ "$invite_tier" != "1" && "$invite_tier" != "2" && "$invite_tier" != "3" ]]; then
  echo "invite_tier must be 1, 2, or 3"
  exit 2
fi
if ! [[ "$invite_wait_sec" =~ ^[0-9]+$ ]]; then
  echo "invite_wait_sec must be a non-negative integer"
  exit 2
fi

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

need_cmd ssh
need_cmd curl
need_cmd jq

if [[ ! -f "$ssh_key" ]]; then
  echo "ssh key not found: $ssh_key"
  exit 2
fi

quote() {
  printf '%q' "$1"
}

ssh_run() {
  local user="$1"
  local host="$2"
  local port="$3"
  shift 3
  local attempt rc
  for ((attempt = 1; attempt <= ssh_attempts; attempt++)); do
    set +e
    ssh -i "$ssh_key" \
      -p "$port" \
      -o BatchMode=yes \
      -o ConnectTimeout="$ssh_connect_timeout_sec" \
      -o ServerAliveInterval=15 \
      -o ServerAliveCountMax=4 \
      -o StrictHostKeyChecking=accept-new \
      "${user}@${host}" "$@"
    rc=$?
    set -e
    if [[ "$rc" -eq 0 ]]; then
      return 0
    fi
    if ((attempt < ssh_attempts)); then
      echo "ssh retry ${attempt}/${ssh_attempts} for ${user}@${host}:${port} after rc=${rc}" >&2
      sleep $((attempt * 2))
    fi
  done
  return "$rc"
}

remote_repo_cmd() {
  local user="$1"
  local host="$2"
  local port="$3"
  local repo="$4"
  local cmd="$5"
  ssh_run "$user" "$host" "$port" "cd $(quote "$repo") && $cmd"
}

section() {
  printf '\n== %s ==\n' "$1"
}

ssh_check() {
  section "ssh check"
  remote_repo_cmd "$a_user" "$a_host" "$a_port" "$a_repo" "printf 'A user='; whoami; printf 'A head='; git rev-parse --short=8 HEAD; test -x scripts/easy_node.sh && echo A repo-ok"
  remote_repo_cmd "$b_user" "$b_host" "$b_port" "$b_repo" "printf 'B user='; whoami; printf 'B head='; git rev-parse --short=8 HEAD; test -x scripts/easy_node.sh && echo B repo-ok"
}

pull_hosts() {
  section "pull B"
  remote_repo_cmd "$b_user" "$b_host" "$b_port" "$b_repo" "git fetch origin && git checkout $(quote "$branch") && git pull --ff-only origin $(quote "$branch") && git rev-parse --short=8 HEAD"
  section "pull A"
  remote_repo_cmd "$a_user" "$a_host" "$a_port" "$a_repo" "git fetch origin && git checkout $(quote "$branch") && git pull --ff-only origin $(quote "$branch") && git rev-parse --short=8 HEAD"
}

server_up_hosts() {
  section "server-up B"
  remote_repo_cmd "$b_user" "$b_host" "$b_port" "$b_repo" "
    unset DIRECTORY_PUBLISHED_BIND_ADDR ISSUER_PUBLISHED_BIND_ADDR ENTRY_PUBLISHED_BIND_ADDR EXIT_PUBLISHED_BIND_ADDR ENTRY_UDP_PUBLISHED_BIND_ADDR EXIT_UDP_PUBLISHED_BIND_ADDR
    EASY_NODE_ENTRY_ROUTE_ASSERTION_KEYGEN=openssl ./scripts/easy_node.sh server-up \
      --mode provider \
      --public-host $(quote "$b_host") \
      --operator-id $(quote "$b_operator") \
      --authority-directory http://$(quote "$a_host"):8081 \
      --authority-issuer http://$(quote "$a_host"):8082 \
      --peer-directories http://$(quote "$a_host"):8081 \
      --beta-profile 1 \
      --prod-profile 0
  "
  section "server-up A"
  remote_repo_cmd "$a_user" "$a_host" "$a_port" "$a_repo" "
    unset DIRECTORY_PUBLISHED_BIND_ADDR ISSUER_PUBLISHED_BIND_ADDR ENTRY_PUBLISHED_BIND_ADDR EXIT_PUBLISHED_BIND_ADDR ENTRY_UDP_PUBLISHED_BIND_ADDR EXIT_UDP_PUBLISHED_BIND_ADDR
    EASY_NODE_ENTRY_ROUTE_ASSERTION_KEYGEN=openssl ./scripts/easy_node.sh server-up \
      --mode authority \
      --public-host $(quote "$a_host") \
      --operator-id $(quote "$a_operator") \
      --issuer-id $(quote "$a_issuer") \
      --peer-directories http://$(quote "$b_host"):8081 \
      --beta-profile 1 \
      --prod-profile 0
  "
}

wait_url() {
  local url="$1"
  local label="$2"
  local deadline=$((SECONDS + timeout_sec))
  while ((SECONDS < deadline)); do
    if curl -fsS --connect-timeout 2 --max-time 5 "$url" >/dev/null 2>&1; then
      echo "$label ok"
      return 0
    fi
    sleep 2
  done
  echo "$label failed: $url"
  return 1
}

health_check() {
  section "health"
  wait_url "http://${a_host}:8081/v1/relays" "A directory"
  wait_url "http://${a_host}:8082/v1/pubkeys" "A issuer"
  wait_url "http://${a_host}:8083/v1/health" "A entry"
  wait_url "http://${a_host}:8084/v1/health" "A exit"
  wait_url "http://${b_host}:8081/v1/relays" "B directory"
  wait_url "http://${b_host}:8083/v1/health" "B entry"
  wait_url "http://${b_host}:8084/v1/health" "B exit"
}

print_topology() {
  section "topology"
  local label url
  for label in "A directory relays" "B directory relays"; do
    case "$label" in
      A*) url="http://${a_host}:8081/v1/relays" ;;
      B*) url="http://${b_host}:8081/v1/relays" ;;
    esac
    echo "$label"
    curl -fsS --connect-timeout 3 --max-time 15 "$url" |
      jq -r '.relays[]? | [.relay_id, .role, (.operator_id // .operator // .origin_operator // ""), (if ((.control_url // "") == "") then "no-control-url" else "control-url" end), (if ((.endpoint // "") == "") then "no-endpoint" else "endpoint" end), (if (.entry_route_assertion_pub_key // "") == "" then "no-entry-assertion-key" else "entry-assertion-key" end)] | @tsv'
  done
}

generate_client_subject() {
  section "invite"
  if [[ -n "$subject" ]]; then
    echo "using provided invite subject"
    return 0
  fi
  local safe_prefix raw rc generated
  safe_prefix="$(printf '%s' "$invite_prefix" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-_')"
  if [[ -z "$safe_prefix" ]]; then
    safe_prefix="inv"
  fi
  set +e
  raw="$(remote_repo_cmd "$a_user" "$a_host" "$a_port" "$a_repo" "./scripts/easy_node.sh invite-generate --issuer-url http://127.0.0.1:8082 --count 1 --prefix $(quote "$safe_prefix") --tier $(quote "$invite_tier") --wait-sec $(quote "$invite_wait_sec")" 2>&1)"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    printf '%s\n' "$raw"
    return "$rc"
  fi
  generated="$(printf '%s\n' "$raw" | grep -E "^${safe_prefix}-[a-z0-9]{22}$" | head -n 1 || true)"
  if [[ -z "$generated" ]]; then
    echo "invite generation succeeded but no generated key was found in output"
    return 1
  fi
  subject="$generated"
  echo "generated invite subject from A"
}

client_test() {
  section "client-test"
  if [[ "$skip_client" == "1" ]]; then
    echo "client-test skipped by LIVE_BETA_SKIP_CLIENT=1"
    return 0
  fi
  if [[ -z "$subject" ]]; then
    echo "client-test failed: pass --subject INVITE, set LIVE_BETA_SUBJECT, or use --generate-subject"
    return 2
  fi
  (
    cd "$ROOT_DIR"
    EASY_NODE_CLIENT_FORCE_BUILD="$client_force_build" ./scripts/easy_node.sh client-test \
      --directory-urls "http://${a_host}:8081,http://${b_host}:8081" \
      --bootstrap-directory "http://${a_host}:8081" \
      --issuer-url "http://${a_host}:8082" \
      --entry-url "http://${a_host}:8083" \
      --exit-url "http://${a_host}:8084" \
      --subject "$subject" \
      --min-sources 2 \
      --path-profile balanced \
      --timeout-sec "$client_timeout_sec" \
      --beta-profile 1 \
      --allow-insecure-remote-http 1
  )
}

case "$mode" in
  ssh-check)
    ssh_check
    ;;
  pull)
    pull_hosts
    ;;
  up)
    server_up_hosts
    ;;
  health)
    health_check
    ;;
  topology)
    print_topology
    ;;
  client)
    if [[ "$generate_subject" == "1" ]]; then
      generate_client_subject
    fi
    client_test
    ;;
  full)
    ssh_check
    if [[ "$skip_pull" != "1" ]]; then
      pull_hosts
    fi
    if [[ "$skip_up" != "1" ]]; then
      server_up_hosts
    fi
    health_check
    print_topology
    if [[ "$skip_client" != "1" ]]; then
      if [[ "$generate_subject" == "1" ]]; then
        generate_client_subject
      fi
      client_test
    fi
    ;;
esac
