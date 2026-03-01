#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$ROOT_DIR/deploy"
SERVER_ENV_FILE="$DEPLOY_DIR/.env.easy.server"
CLIENT_ENV_FILE="$DEPLOY_DIR/.env.easy.client"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/easy_node.sh check
  ./scripts/easy_node.sh server-up --public-host HOST [--operator-id ID] [--issuer-admin-token TOKEN] [--peer-directories URLS]
  ./scripts/easy_node.sh server-status
  ./scripts/easy_node.sh server-logs
  ./scripts/easy_node.sh server-down
  ./scripts/easy_node.sh client-test --directory-urls URL[,URL...] --issuer-url URL --entry-url URL --exit-url URL [--min-sources N] [--exit-country CC] [--exit-region REGION] [--timeout-sec N]
  ./scripts/easy_node.sh three-machine-validate --directory-a URL --directory-b URL --issuer-url URL --entry-url URL --exit-url URL [--min-sources N] [--min-operators N] [--federation-timeout-sec N] [--timeout-sec N] [--exit-country CC] [--exit-region REGION]
  ./scripts/easy_node.sh machine-a-test [--public-host HOST] [--report-file PATH]
  ./scripts/easy_node.sh machine-b-test --peer-directory-a URL [--public-host HOST] [--min-operators N] [--federation-timeout-sec N] [--report-file PATH]
  ./scripts/easy_node.sh machine-c-test --directory-a URL --directory-b URL --issuer-url URL --entry-url URL --exit-url URL [--min-sources N] [--min-operators N] [--federation-timeout-sec N] [--timeout-sec N] [--exit-country CC] [--exit-region REGION] [--report-file PATH]

Notes:
  - server-up runs directory + issuer + entry-exit using deploy/docker-compose.yml.
  - client-test runs client-demo with --no-deps (no local server required on the client machine).
  - three-machine-validate runs health + federation checks then runs client-test with both directories.
  - machine-a-test/machine-b-test/machine-c-test are machine-role-specific automated validations with optional report files.
  - For a 3-machine test: run server-up on machine A and B, then run client-test on machine C with both directory URLs.
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing dependency: $1"
    return 1
  fi
}

check_dependencies() {
  local ok=1
  need_cmd docker || ok=0
  need_cmd curl || ok=0
  need_cmd timeout || ok=0
  need_cmd rg || ok=0

  if ! docker compose version >/dev/null 2>&1; then
    echo "missing dependency: docker compose plugin"
    ok=0
  fi

  if [[ $ok -eq 1 ]]; then
    echo "dependency check: ok"
    docker --version
    docker compose version
    if ! docker info >/dev/null 2>&1; then
      echo "note: docker daemon is not reachable for this user yet"
      echo "      fix by adding your user to docker group or use sudo"
    fi
    return 0
  fi
  return 1
}

wait_http_ok() {
  local url="$1"
  local name="$2"
  local attempts="${3:-30}"
  local i
  for ((i = 1; i <= attempts; i++)); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "$name did not become healthy at $url"
  return 1
}

random_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 16
    return
  fi
  # Fallback token when openssl is unavailable.
  date +%s%N
}

ensure_deps_or_die() {
  if ! check_dependencies >/tmp/easy_node_depcheck.log 2>&1; then
    cat /tmp/easy_node_depcheck.log
    exit 1
  fi
}

compose_server() {
  if [[ -f "$SERVER_ENV_FILE" ]]; then
    (cd "$DEPLOY_DIR" && docker compose --env-file "$SERVER_ENV_FILE" "$@")
  else
    (cd "$DEPLOY_DIR" && docker compose "$@")
  fi
}

write_server_env() {
  local public_host="$1"
  local operator_id="$2"
  local issuer_admin_token="$3"
  local peer_dirs="$4"

  cat >"$SERVER_ENV_FILE" <<EOF_ENV
DIRECTORY_PUBLIC_URL=http://${public_host}:8081
ENTRY_URL_PUBLIC=http://${public_host}:8083
EXIT_CONTROL_URL_PUBLIC=http://${public_host}:8084
ENTRY_ENDPOINT_PUBLIC=${public_host}:51820
EXIT_ENDPOINT_PUBLIC=${public_host}:51821
DIRECTORY_OPERATOR_ID=${operator_id}
ISSUER_ADMIN_TOKEN=${issuer_admin_token}
EOF_ENV

  if [[ -n "$peer_dirs" ]]; then
    echo "DIRECTORY_PEERS=${peer_dirs}" >>"$SERVER_ENV_FILE"
    echo "DIRECTORY_SYNC_SEC=5" >>"$SERVER_ENV_FILE"
    echo "DIRECTORY_GOSSIP_SEC=5" >>"$SERVER_ENV_FILE"
  fi
}

first_csv_item() {
  local csv="$1"
  IFS=',' read -r first _ <<<"$csv"
  echo "${first//[[:space:]]/}"
}

looks_like_loopback_url() {
  local u="$1"
  [[ "$u" == *"127.0.0.1"* || "$u" == *"localhost"* ]]
}

server_up() {
  local public_host=""
  local operator_id=""
  local issuer_admin_token=""
  local peer_dirs=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --public-host)
        public_host="${2:-}"
        shift 2
        ;;
      --operator-id)
        operator_id="${2:-}"
        shift 2
        ;;
      --issuer-admin-token)
        issuer_admin_token="${2:-}"
        shift 2
        ;;
      --peer-directories)
        peer_dirs="${2:-}"
        shift 2
        ;;
      *)
        echo "unknown arg for server-up: $1"
        exit 2
        ;;
    esac
  done

  if [[ -z "$public_host" ]]; then
    echo "server-up requires --public-host"
    exit 2
  fi

  ensure_deps_or_die

  if [[ -z "$operator_id" ]]; then
    operator_id="op-${HOSTNAME:-node}"
  fi
  if [[ -z "$issuer_admin_token" ]]; then
    issuer_admin_token="$(random_token)"
  fi

  write_server_env "$public_host" "$operator_id" "$issuer_admin_token" "$peer_dirs"

  compose_server up -d --build directory issuer entry-exit

  wait_http_ok "http://${public_host}:8081/v1/relays" "directory" 40 || { compose_server logs --tail=80 directory; exit 1; }
  wait_http_ok "http://${public_host}:8082/v1/pubkeys" "issuer" 40 || { compose_server logs --tail=80 issuer; exit 1; }
  wait_http_ok "http://${public_host}:8083/v1/health" "entry" 40 || { compose_server logs --tail=120 entry-exit; exit 1; }
  wait_http_ok "http://${public_host}:8084/v1/health" "exit" 40 || { compose_server logs --tail=120 entry-exit; exit 1; }

  echo "server stack started"
  echo "env file: $SERVER_ENV_FILE"
  echo "operator_id: $operator_id"
  echo "issuer_admin_token: $issuer_admin_token"
  echo "health checks:"
  echo "  curl http://${public_host}:8081/v1/relays"
  echo "  curl http://${public_host}:8082/v1/pubkeys"
  echo "  curl http://${public_host}:8083/v1/health"
  echo "  curl http://${public_host}:8084/v1/health"
}

server_status() {
  ensure_deps_or_die
  compose_server ps
}

server_logs() {
  ensure_deps_or_die
  compose_server logs --tail=150 directory issuer entry-exit
}

server_down() {
  ensure_deps_or_die
  compose_server down --remove-orphans
}

three_machine_validate() {
  ensure_deps_or_die
  "$ROOT_DIR/scripts/integration_3machine_beta_validate.sh" "$@"
}

machine_a_test() {
  ensure_deps_or_die
  "$ROOT_DIR/scripts/integration_machine_a_server_check.sh" "$@"
}

machine_b_test() {
  ensure_deps_or_die
  "$ROOT_DIR/scripts/integration_machine_b_federation_check.sh" "$@"
}

machine_c_test() {
  ensure_deps_or_die
  "$ROOT_DIR/scripts/integration_machine_c_client_check.sh" "$@"
}

client_test() {
  local directory_urls=""
  local issuer_url=""
  local entry_url=""
  local exit_url=""
  local min_sources="1"
  local exit_country=""
  local exit_region=""
  local timeout_sec="35"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --directory-urls)
        directory_urls="${2:-}"
        shift 2
        ;;
      --issuer-url)
        issuer_url="${2:-}"
        shift 2
        ;;
      --entry-url)
        entry_url="${2:-}"
        shift 2
        ;;
      --exit-url)
        exit_url="${2:-}"
        shift 2
        ;;
      --min-sources)
        min_sources="${2:-}"
        shift 2
        ;;
      --exit-country)
        exit_country="${2:-}"
        shift 2
        ;;
      --exit-region)
        exit_region="${2:-}"
        shift 2
        ;;
      --timeout-sec)
        timeout_sec="${2:-}"
        shift 2
        ;;
      *)
        echo "unknown arg for client-test: $1"
        exit 2
        ;;
    esac
  done

  if [[ -z "$directory_urls" || -z "$issuer_url" || -z "$entry_url" || -z "$exit_url" ]]; then
    echo "client-test requires --directory-urls --issuer-url --entry-url --exit-url"
    exit 2
  fi

  ensure_deps_or_die

  local first_dir
  first_dir="$(first_csv_item "$directory_urls")"

  cat >"$CLIENT_ENV_FILE" <<EOF_CLIENT
CLIENT_DIRECTORY_URL=${first_dir}
CLIENT_ISSUER_URL=${issuer_url}
CLIENT_ENTRY_URL=${entry_url}
CLIENT_EXIT_CONTROL_URL=${exit_url}
EOF_CLIENT

  local out="/tmp/easy_node_client_test.log"
  rm -f "$out"

  if looks_like_loopback_url "$first_dir" || looks_like_loopback_url "$issuer_url" || looks_like_loopback_url "$entry_url" || looks_like_loopback_url "$exit_url"; then
    echo "note: one or more URLs use localhost/127.0.0.1"
    echo "      this only works when those addresses are reachable from inside the client container."
  fi

  wait_http_ok "${first_dir%/}/v1/pubkeys" "directory" 8 || return 1
  wait_http_ok "${issuer_url%/}/v1/pubkeys" "issuer" 8 || return 1
  wait_http_ok "${entry_url%/}/v1/health" "entry" 8 || return 1
  wait_http_ok "${exit_url%/}/v1/health" "exit" 8 || return 1

  (cd "$DEPLOY_DIR" && docker compose --profile demo build client-demo >/dev/null)

  local -a run_cmd
  run_cmd=(
    docker compose
    --env-file "$CLIENT_ENV_FILE"
    --profile demo
    run --no-deps --rm
    -e "DIRECTORY_URLS=$directory_urls"
    -e "DIRECTORY_MIN_SOURCES=$min_sources"
    -e "ISSUER_URL=$issuer_url"
    -e "ENTRY_URL=$entry_url"
    -e "EXIT_CONTROL_URL=$exit_url"
    -e "CLIENT_BOOTSTRAP_INTERVAL_SEC=2"
  )
  if [[ -n "$exit_country" ]]; then
    run_cmd+=(-e "CLIENT_EXIT_COUNTRY=$exit_country")
  fi
  if [[ -n "$exit_region" ]]; then
    run_cmd+=(-e "CLIENT_EXIT_REGION=$exit_region")
  fi
  run_cmd+=(client-demo)

  (
    cd "$DEPLOY_DIR"
    timeout "${timeout_sec}s" "${run_cmd[@]}" >"$out" 2>&1
  ) || true

  if rg -q 'client selected entry=' "$out"; then
    echo "client test: ok"
    echo "key log lines:"
    rg 'client selected entry=|client received wg-session config|bootstrap failed' "$out" || true
    return 0
  fi

  echo "client test: failed"
  cat "$out"
  return 1
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    check)
      check_dependencies
      ;;
    server-up)
      shift
      server_up "$@"
      ;;
    server-status)
      server_status
      ;;
    server-logs)
      server_logs
      ;;
    server-down)
      server_down
      ;;
    client-test)
      shift
      client_test "$@"
      ;;
    three-machine-validate)
      shift
      three_machine_validate "$@"
      ;;
    machine-a-test)
      shift
      machine_a_test "$@"
      ;;
    machine-b-test)
      shift
      machine_b_test "$@"
      ;;
    machine-c-test)
      shift
      machine_c_test "$@"
      ;;
    -h|--help|help|"")
      usage
      ;;
    *)
      echo "unknown command: $cmd"
      usage
      exit 2
      ;;
  esac
}

main "$@"
