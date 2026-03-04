#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$ROOT_DIR/deploy"
SERVER_ENV_FILE="$DEPLOY_DIR/.env.easy.server"
CLIENT_ENV_FILE="$DEPLOY_DIR/.env.easy.client"

default_log_dir() {
  echo "${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
}

prepare_log_dir() {
  local dir
  dir="$(default_log_dir)"
  mkdir -p "$dir"
  echo "$dir"
}

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/easy_node.sh check
  ./scripts/easy_node.sh server-up [--public-host HOST] [--operator-id ID] [--issuer-id ID] [--issuer-admin-token TOKEN] [--peer-directories URLS] [--bootstrap-directory URL] [--client-allowlist [0|1]] [--allow-anon-cred [0|1]] [--beta-profile [0|1]]
  ./scripts/easy_node.sh server-status
  ./scripts/easy_node.sh server-logs
  ./scripts/easy_node.sh server-down
  ./scripts/easy_node.sh stop-all
  ./scripts/easy_node.sh install-deps-ubuntu
  ./scripts/easy_node.sh client-test [--directory-urls URL[,URL...]] [--bootstrap-directory URL] [--discovery-wait-sec N] [--issuer-url URL] [--entry-url URL] [--exit-url URL] [--subject ID] [--anon-cred TOKEN] [--min-sources N] [--exit-country CC] [--exit-region REGION] [--timeout-sec N] [--distinct-operators [0|1]] [--min-selection-lines N] [--min-entry-operators N] [--min-exit-operators N] [--require-cross-operator-pair [0|1]] [--beta-profile [0|1]]
  ./scripts/easy_node.sh three-machine-validate [--directory-a URL] [--directory-b URL] [--bootstrap-directory URL] [--discovery-wait-sec N] [--issuer-url URL] [--issuer-a-url URL] [--issuer-b-url URL] [--entry-url URL] [--exit-url URL] [--subject ID] [--anon-cred TOKEN] [--min-sources N] [--min-operators N] [--federation-timeout-sec N] [--timeout-sec N] [--client-min-selection-lines N] [--client-min-entry-operators N] [--client-min-exit-operators N] [--client-require-cross-operator-pair [0|1]] [--exit-country CC] [--exit-region REGION] [--distinct-operators [0|1]] [--require-issuer-quorum [0|1]] [--beta-profile [0|1]]
  ./scripts/easy_node.sh three-machine-soak [--directory-a URL] [--directory-b URL] [--bootstrap-directory URL] [--discovery-wait-sec N] [--issuer-url URL] [--issuer-a-url URL] [--issuer-b-url URL] [--entry-url URL] [--exit-url URL] [--subject ID] [--anon-cred TOKEN] [--rounds N] [--pause-sec N] [--fault-every N] [--fault-command CMD] [--continue-on-fail [0|1]] [--min-sources N] [--min-operators N] [--federation-timeout-sec N] [--timeout-sec N] [--client-min-selection-lines N] [--client-min-entry-operators N] [--client-min-exit-operators N] [--client-require-cross-operator-pair [0|1]] [--exit-country CC] [--exit-region REGION] [--distinct-operators [0|1]] [--require-issuer-quorum [0|1]] [--beta-profile [0|1]] [--report-file PATH]
  ./scripts/easy_node.sh pilot-runbook [--directory-a URL] [--directory-b URL] [--bootstrap-directory URL] [--discovery-wait-sec N] [--issuer-url URL] [--issuer-a-url URL] [--issuer-b-url URL] [--entry-url URL] [--exit-url URL] [--subject ID] [--anon-cred TOKEN] [--rounds N] [--pause-sec N] [--min-sources N] [--min-operators N] [--federation-timeout-sec N] [--timeout-sec N] [--client-min-selection-lines N] [--client-min-entry-operators N] [--client-min-exit-operators N] [--client-require-cross-operator-pair [0|1]] [--distinct-operators [0|1]] [--require-issuer-quorum [0|1]] [--beta-profile [0|1]] [--bundle-dir PATH]
  ./scripts/easy_node.sh invite-generate [--issuer-url URL] [--admin-token TOKEN] [--count N] [--prefix PREFIX] [--tier 1|2|3]
  ./scripts/easy_node.sh invite-check --key KEY [--issuer-url URL] [--admin-token TOKEN]
  ./scripts/easy_node.sh invite-disable --key KEY [--issuer-url URL] [--admin-token TOKEN]
  ./scripts/easy_node.sh machine-a-test [--public-host HOST] [--report-file PATH]
  ./scripts/easy_node.sh machine-b-test --peer-directory-a URL [--public-host HOST] [--min-operators N] [--federation-timeout-sec N] [--report-file PATH]
  ./scripts/easy_node.sh machine-c-test [--directory-a URL] [--directory-b URL] [--bootstrap-directory URL] [--discovery-wait-sec N] [--issuer-url URL] [--entry-url URL] [--exit-url URL] [--subject ID] [--anon-cred TOKEN] [--min-sources N] [--min-operators N] [--federation-timeout-sec N] [--timeout-sec N] [--exit-country CC] [--exit-region REGION] [--distinct-operators [0|1]] [--beta-profile [0|1]] [--report-file PATH]
  ./scripts/easy_node.sh discover-hosts --bootstrap-directory URL [--wait-sec N] [--min-hosts N] [--write-config [0|1]]

Notes:
  - server-up runs directory + issuer + entry-exit using deploy/docker-compose.yml.
  - client-test runs client-demo with --no-deps (no local server required on the client machine).
  - three-machine-validate runs health + federation checks then runs client-test with both directories.
  - bootstrap discovery mode lets you provide one directory URL and auto-discover other server hosts.
  - machine-a-test/machine-b-test/machine-c-test are machine-role-specific automated validations with optional report files.
  - default logs are written to ./.easy-node-logs (override with EASY_NODE_LOG_DIR).
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
    if curl -fsS --connect-timeout 2 --max-time 4 "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "$name did not become healthy at $url"
  return 1
}

host_is_loopback() {
  local host="$1"
  [[ "$host" == "127.0.0.1" || "$host" == "localhost" || "$host" == "::1" ]]
}

hosts_config_file() {
  echo "$ROOT_DIR/data/easy_mode_hosts.conf"
}

trim_url() {
  local value="$1"
  while [[ "$value" == */ ]]; do
    value="${value%/}"
  done
  echo "$value"
}

hostport_from_url() {
  local value="$1"
  value="${value#http://}"
  value="${value#https://}"
  value="${value%%/*}"
  echo "$value"
}

host_from_hostport() {
  local value="$1"
  if [[ "$value" == \[*\]* ]]; then
    # Bracketed IPv6 literal, with optional :port.
    echo "${value%%]*}]"
    return
  fi
  local colon_count
  colon_count="$(printf '%s' "$value" | awk -F: '{print NF-1}')"
  if [[ "$colon_count" == "1" ]]; then
    local maybe_port="${value##*:}"
    if [[ "$maybe_port" =~ ^[0-9]+$ ]]; then
      echo "${value%:*}"
      return
    fi
  fi
  echo "$value"
}

host_from_url() {
  local value="$1"
  host_from_hostport "$(hostport_from_url "$value")"
}

normalize_host_for_endpoint() {
  local host="$1"
  host="$(trim_url "$host")"
  if [[ "$host" == \[*\] ]]; then
    echo "$host"
    return
  fi
  if [[ "$host" == *:* ]]; then
    echo "[$host]"
    return
  fi
  echo "$host"
}

url_from_host_port() {
  local host="$1"
  local port="$2"
  printf 'http://%s:%s' "$(normalize_host_for_endpoint "$host")" "$port"
}

discover_directory_urls() {
  local bootstrap_url="$1"
  local wait_sec="${2:-12}"
  local min_hosts="${3:-2}"
  local seed_host
  bootstrap_url="$(trim_url "$bootstrap_url")"
  seed_host="$(host_from_url "$bootstrap_url")"

  declare -A seen_hosts=()
  if [[ -n "$seed_host" ]]; then
    seen_hosts["$seed_host"]=1
  fi

  local i payload relay_urls peer_urls endpoint_values u h count
  for ((i = 1; i <= wait_sec; i++)); do
    payload="$(curl -fsS --connect-timeout 2 --max-time 4 "${bootstrap_url}/v1/relays" 2>/dev/null || true)"
    relay_urls="$(printf '%s\n' "$payload" | rg -o '"control_url":"https?://[^"]+"' || true)"
    endpoint_values="$(printf '%s\n' "$payload" | rg -o '"endpoint":"[^"]+"' || true)"
    while IFS= read -r u; do
      u="$(printf '%s' "$u" | sed -E 's/^"control_url":"(https?:\/\/[^"]+)"$/\1/')"
      h="$(host_from_url "$u")"
      if [[ -n "$h" ]]; then
        seen_hosts["$h"]=1
      fi
    done <<<"$relay_urls"
    while IFS= read -r u; do
      u="$(printf '%s' "$u" | sed -E 's/^"endpoint":"([^"]+)"$/\1/')"
      h="$(host_from_hostport "$u")"
      if [[ -n "$h" ]]; then
        seen_hosts["$h"]=1
      fi
    done <<<"$endpoint_values"

    payload="$(curl -fsS --connect-timeout 2 --max-time 4 "${bootstrap_url}/v1/peers" 2>/dev/null || true)"
    peer_urls="$(printf '%s\n' "$payload" | rg -o '"url":"https?://[^"]+"' || true)"
    while IFS= read -r u; do
      u="$(printf '%s' "$u" | sed -E 's/^"url":"(https?:\/\/[^"]+)"$/\1/')"
      h="$(host_from_url "$u")"
      if [[ -n "$h" ]]; then
        seen_hosts["$h"]=1
      fi
    done <<<"$peer_urls"

    count="${#seen_hosts[@]}"
    if ((count >= min_hosts)); then
      break
    fi
    sleep 1
  done

  if [[ -z "$seed_host" ]]; then
    seed_host="$(host_from_url "$bootstrap_url")"
  fi

  local out=()
  if [[ -n "$seed_host" ]]; then
    out+=("$(url_from_host_port "$seed_host" 8081)")
    unset 'seen_hosts[$seed_host]'
  fi

  local sorted_hosts
  sorted_hosts="$(printf '%s\n' "${!seen_hosts[@]}" | awk 'NF > 0' | sort -u)"
  while IFS= read -r h; do
    [[ -z "$h" ]] && continue
    out+=("$(url_from_host_port "$h" 8081)")
  done <<<"$sorted_hosts"

  local joined=""
  local item
  for item in "${out[@]}"; do
    if [[ -n "$joined" ]]; then
      joined+=","
    fi
    joined+="$item"
  done
  echo "$joined"
}

merge_url_csv() {
  local left="$1"
  local right="$2"
  local combined
  combined="$(
    {
      printf '%s' "$left" | tr ',' '\n'
      printf '\n'
      printf '%s' "$right" | tr ',' '\n'
    } | awk 'NF > 0' | awk '!seen[$0]++'
  )"
  printf '%s\n' "$combined" | paste -sd, -
}

split_csv_lines() {
  local csv="$1"
  printf '%s' "$csv" |
    tr ',' '\n' |
    sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' |
    awk 'NF > 0'
}

filter_peer_dirs_excluding_host() {
  local peer_dirs="$1"
  local local_host="$2"
  local out=""
  local peer
  local peer_host
  while IFS= read -r peer; do
    [[ -z "$peer" ]] && continue
    peer_host="$(host_from_url "$peer")"
    if [[ -n "$local_host" && -n "$peer_host" && "$peer_host" == "$local_host" ]]; then
      continue
    fi
    if [[ -n "$out" ]]; then
      out+=","
    fi
    out+="$peer"
  done < <(split_csv_lines "$peer_dirs")
  echo "$out"
}

detect_local_host() {
  local candidate=""
  if command -v tailscale >/dev/null 2>&1; then
    candidate="$(tailscale ip -4 2>/dev/null | awk 'NF > 0 {print; exit}' || true)"
    if [[ -n "$candidate" ]]; then
      echo "$candidate"
      return
    fi
  fi

  if command -v ip >/dev/null 2>&1; then
    candidate="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}' || true)"
    if [[ -n "$candidate" && "$candidate" != "127.0.0.1" ]]; then
      echo "$candidate"
      return
    fi
  fi

  if command -v hostname >/dev/null 2>&1; then
    candidate="$(hostname -I 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i !~ /^127\./) {print $i; exit}}' || true)"
    if [[ -n "$candidate" ]]; then
      echo "$candidate"
      return
    fi
  fi
}

write_hosts_config() {
  local host_a="$1"
  local host_b="$2"
  local file
  file="$(hosts_config_file)"
  mkdir -p "$(dirname "$file")"
  cat >"$file" <<EOF_HOSTS
MACHINE_A_HOST=$host_a
MACHINE_B_HOST=$host_b
EOF_HOSTS
}

identity_config_file() {
  echo "$DEPLOY_DIR/data/easy_node_identity.conf"
}

sanitize_id_component() {
  local raw="$1"
  local out
  out="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9-' '-')"
  out="${out#-}"
  out="${out%-}"
  if [[ -z "$out" ]]; then
    out="node"
  fi
  echo "$out"
}

random_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 16
    return
  fi
  # Fallback token when openssl is unavailable.
  date +%s%N
}

random_id_suffix() {
  local token
  token="$(random_token | tr -cd 'a-zA-Z0-9' | tr '[:upper:]' '[:lower:]' | head -c 10)"
  if [[ -z "$token" ]]; then
    token="$(date +%s%N | tail -c 11)"
  fi
  echo "$token"
}

identity_value() {
  local file="$1"
  local key="$2"
  if [[ ! -f "$file" ]]; then
    return 0
  fi
  awk -F= -v k="$key" '$1 == k {print substr($0, index($0, "=") + 1); exit}' "$file"
}

write_identity_config() {
  local operator_id="$1"
  local issuer_id="$2"
  local file
  file="$(identity_config_file)"
  mkdir -p "$(dirname "$file")"
  cat >"$file" <<EOF_ID
EASY_NODE_OPERATOR_ID=${operator_id}
EASY_NODE_ISSUER_ID=${issuer_id}
EOF_ID
}

directory_has_operator_id() {
  local directory_url="$1"
  local operator_id="$2"
  local payload
  payload="$(curl -fsS --connect-timeout 2 --max-time 4 "$(trim_url "$directory_url")/v1/relays" 2>/dev/null || true)"
  if [[ -z "$payload" ]]; then
    return 1
  fi
  if printf '%s\n' "$payload" |
    rg -o '"(operator_id|operator|origin_operator)":"[^"]+"' |
    sed -E 's/^"(operator_id|operator|origin_operator)":"([^"]+)"$/\2/' |
    awk -v target="$operator_id" '$0 == target {found=1} END {exit(found ? 0 : 1)}'; then
    return 0
  fi
  return 1
}

issuer_id_from_url() {
  local issuer_url="$1"
  local payload
  payload="$(curl -fsS --connect-timeout 2 --max-time 4 "$(trim_url "$issuer_url")/v1/pubkeys" 2>/dev/null || true)"
  if [[ -z "$payload" ]]; then
    return 0
  fi
  printf '%s\n' "$payload" |
    rg -o '"issuer":"[^"]+"' |
    head -n 1 |
    sed -E 's/^"issuer":"([^"]+)"$/\1/'
}

operator_id_conflicts_with_peers() {
  local operator_id="$1"
  local peer_dirs="$2"
  local peer
  while IFS= read -r peer; do
    [[ -z "$peer" ]] && continue
    if directory_has_operator_id "$peer" "$operator_id"; then
      return 0
    fi
  done < <(split_csv_lines "$peer_dirs")
  return 1
}

issuer_id_conflicts_with_peers() {
  local issuer_id="$1"
  local peer_dirs="$2"
  local peer
  local peer_host
  local peer_issuer_url
  local peer_issuer_id
  while IFS= read -r peer; do
    [[ -z "$peer" ]] && continue
    peer_host="$(host_from_url "$peer")"
    [[ -z "$peer_host" ]] && continue
    peer_issuer_url="$(url_from_host_port "$peer_host" 8082)"
    peer_issuer_id="$(issuer_id_from_url "$peer_issuer_url")"
    if [[ -n "$peer_issuer_id" && "$peer_issuer_id" == "$issuer_id" ]]; then
      return 0
    fi
  done < <(split_csv_lines "$peer_dirs")
  return 1
}

ensure_deps_or_die() {
  local log_dir
  local log_file
  log_dir="$(prepare_log_dir)"
  log_file="$log_dir/easy_node_depcheck.log"
  if ! check_dependencies >"$log_file" 2>&1; then
    cat "$log_file"
    echo "dependency check log: $log_file"
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
  local issuer_id="$3"
  local issuer_admin_token="$4"
  local peer_dirs="$5"
  local beta_profile="$6"
  local client_allowlist="$7"
  local allow_anon_cred="$8"
  local relay_suffix
  local issuer_suffix
  relay_suffix="$(sanitize_id_component "$operator_id")"
  if [[ -z "$issuer_id" ]]; then
    issuer_id="issuer-$(random_id_suffix)"
  fi
  issuer_suffix="$(sanitize_id_component "$issuer_id")"

  cat >"$SERVER_ENV_FILE" <<EOF_ENV
DIRECTORY_PUBLIC_URL=http://${public_host}:8081
ENTRY_URL_PUBLIC=http://${public_host}:8083
EXIT_CONTROL_URL_PUBLIC=http://${public_host}:8084
ENTRY_ENDPOINT_PUBLIC=${public_host}:51820
EXIT_ENDPOINT_PUBLIC=${public_host}:51821
DIRECTORY_OPERATOR_ID=${operator_id}
ENTRY_RELAY_ID=entry-${relay_suffix}
EXIT_RELAY_ID=exit-${relay_suffix}
DIRECTORY_PRIVATE_KEY_FILE=/app/data/directory_${relay_suffix}_ed25519.key
DIRECTORY_PREVIOUS_PUBKEYS_FILE=/app/data/directory_${relay_suffix}_previous_pubkeys.txt
ISSUER_ID=${issuer_id}
ISSUER_PRIVATE_KEY_FILE=/app/data/issuer_${issuer_suffix}_ed25519.key
ISSUER_PREVIOUS_PUBKEYS_FILE=/app/data/issuer_${issuer_suffix}_previous_pubkeys.txt
ISSUER_EPOCHS_FILE=/app/data/issuer_${issuer_suffix}_epochs.json
ISSUER_SUBJECTS_FILE=/app/data/issuer_${issuer_suffix}_subjects.json
ISSUER_REVOCATIONS_FILE=/app/data/issuer_${issuer_suffix}_revocations.json
ISSUER_ANON_REVOCATIONS_FILE=/app/data/issuer_${issuer_suffix}_anon_revocations.json
ISSUER_ANON_DISPUTES_FILE=/app/data/issuer_${issuer_suffix}_anon_disputes.json
ISSUER_AUDIT_FILE=/app/data/issuer_${issuer_suffix}_audit.json
ISSUER_ADMIN_TOKEN=${issuer_admin_token}
ISSUER_CLIENT_ALLOWLIST_ONLY=${client_allowlist}
ISSUER_ALLOW_ANON_CRED=${allow_anon_cred}
EOF_ENV

  if [[ -n "$peer_dirs" ]]; then
    echo "DIRECTORY_PEERS=${peer_dirs}" >>"$SERVER_ENV_FILE"
    echo "DIRECTORY_SYNC_SEC=5" >>"$SERVER_ENV_FILE"
    echo "DIRECTORY_GOSSIP_SEC=5" >>"$SERVER_ENV_FILE"
  fi

  if [[ "$beta_profile" == "1" ]]; then
    cat >>"$SERVER_ENV_FILE" <<'EOF_BETA'
DIRECTORY_MIN_OPERATORS=2
DIRECTORY_MIN_RELAY_VOTES=2
ENTRY_DIRECTORY_MIN_OPERATORS=2
ENTRY_DIRECTORY_MIN_RELAY_VOTES=2
ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR=1
DIRECTORY_PEER_MIN_OPERATORS=2
DIRECTORY_PEER_MIN_VOTES=2
DIRECTORY_PEER_DISCOVERY_MIN_VOTES=2
DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE=8
DIRECTORY_PEER_DISCOVERY_MAX_PER_OPERATOR=4
DIRECTORY_PROVIDER_MAX_RELAYS_PER_OPERATOR=32
DIRECTORY_PROVIDER_SPLIT_ROLES=1
ISSUER_TOKEN_TTL_SEC=300
EOF_BETA
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
  local operator_id_explicit="0"
  local issuer_id=""
  local issuer_id_explicit="0"
  local issuer_admin_token=""
  local peer_dirs=""
  local bootstrap_directory=""
  local client_allowlist="${EASY_NODE_CLIENT_ALLOWLIST_ONLY:-0}"
  local allow_anon_cred="${EASY_NODE_ALLOW_ANON_CRED:-1}"
  local beta_profile="${EASY_NODE_BETA_PROFILE:-0}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --public-host)
        public_host="${2:-}"
        shift 2
        ;;
      --operator-id)
        operator_id="${2:-}"
        operator_id_explicit="1"
        shift 2
        ;;
      --issuer-id)
        issuer_id="${2:-}"
        issuer_id_explicit="1"
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
      --bootstrap-directory)
        bootstrap_directory="${2:-}"
        shift 2
        ;;
      --client-allowlist)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          client_allowlist="${2:-}"
          shift 2
        else
          client_allowlist="1"
          shift
        fi
        ;;
      --allow-anon-cred)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          allow_anon_cred="${2:-}"
          shift 2
        else
          allow_anon_cred="0"
          shift
        fi
        ;;
      --beta-profile)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          beta_profile="${2:-}"
          shift 2
        else
          beta_profile="1"
          shift
        fi
        ;;
      *)
        echo "unknown arg for server-up: $1"
        exit 2
        ;;
    esac
  done

  if [[ "$beta_profile" != "0" && "$beta_profile" != "1" ]]; then
    echo "server-up requires --beta-profile (or EASY_NODE_BETA_PROFILE) to be 0 or 1"
    exit 2
  fi
  if [[ "$client_allowlist" != "0" && "$client_allowlist" != "1" ]]; then
    echo "server-up requires --client-allowlist (or EASY_NODE_CLIENT_ALLOWLIST_ONLY) to be 0 or 1"
    exit 2
  fi
  if [[ "$allow_anon_cred" != "0" && "$allow_anon_cred" != "1" ]]; then
    echo "server-up requires --allow-anon-cred (or EASY_NODE_ALLOW_ANON_CRED) to be 0 or 1"
    exit 2
  fi

  if [[ -n "$bootstrap_directory" ]]; then
    bootstrap_directory="$(trim_url "$bootstrap_directory")"
    if [[ -z "$peer_dirs" ]]; then
      peer_dirs="$bootstrap_directory"
    else
      peer_dirs="$(merge_url_csv "$peer_dirs" "$bootstrap_directory")"
    fi
  fi

  if [[ -z "$public_host" ]]; then
    public_host="$(detect_local_host || true)"
    if [[ -n "$public_host" ]]; then
      echo "server-up auto-detected public host: $public_host"
    else
      echo "server-up requires --public-host (or a detectable local host)"
      exit 2
    fi
  fi

  local local_host
  local_host="$(host_from_hostport "$public_host")"
  if [[ -n "$peer_dirs" ]]; then
    peer_dirs="$(filter_peer_dirs_excluding_host "$peer_dirs" "$local_host")"
  fi

  ensure_deps_or_die

  local identity_file
  local stored_operator_id
  local stored_issuer_id
  identity_file="$(identity_config_file)"
  stored_operator_id="$(identity_value "$identity_file" "EASY_NODE_OPERATOR_ID")"
  stored_issuer_id="$(identity_value "$identity_file" "EASY_NODE_ISSUER_ID")"

  if [[ -z "$operator_id" ]]; then
    if [[ -n "$stored_operator_id" ]]; then
      operator_id="$stored_operator_id"
    else
      operator_id="op-$(random_id_suffix)"
    fi
  fi
  if [[ -z "$issuer_id" ]]; then
    if [[ -n "$stored_issuer_id" ]]; then
      issuer_id="$stored_issuer_id"
    else
      issuer_id="issuer-$(random_id_suffix)"
    fi
  fi
  if [[ -z "$issuer_admin_token" ]]; then
    issuer_admin_token="$(random_token)"
  fi

  if [[ -n "$peer_dirs" ]]; then
    local operator_attempts=0
    while operator_id_conflicts_with_peers "$operator_id" "$peer_dirs"; do
      if [[ "$operator_id_explicit" == "1" ]]; then
        echo "server-up refused: --operator-id '$operator_id' already exists on peer directories."
        echo "choose a unique operator id or omit --operator-id for automatic unique generation."
        exit 2
      fi
      operator_id="op-$(random_id_suffix)"
      operator_attempts=$((operator_attempts + 1))
      if ((operator_attempts >= 8)); then
        echo "server-up could not generate a unique operator id after ${operator_attempts} attempts."
        exit 1
      fi
    done

    local issuer_attempts=0
    while issuer_id_conflicts_with_peers "$issuer_id" "$peer_dirs"; do
      if [[ "$issuer_id_explicit" == "1" ]]; then
        echo "server-up refused: --issuer-id '$issuer_id' already exists on peer directories."
        echo "choose a unique issuer id or omit --issuer-id for automatic unique generation."
        exit 2
      fi
      issuer_id="issuer-$(random_id_suffix)"
      issuer_attempts=$((issuer_attempts + 1))
      if ((issuer_attempts >= 8)); then
        echo "server-up could not generate a unique issuer id after ${issuer_attempts} attempts."
        exit 1
      fi
    done
  fi

  write_identity_config "$operator_id" "$issuer_id"
  write_server_env "$public_host" "$operator_id" "$issuer_id" "$issuer_admin_token" "$peer_dirs" "$beta_profile" "$client_allowlist" "$allow_anon_cred"

  compose_server up -d --build directory issuer entry-exit

  # Always validate local container reachability first.
  wait_http_ok "http://127.0.0.1:8081/v1/relays" "local directory" 40 || { compose_server logs --tail=80 directory; exit 1; }
  wait_http_ok "http://127.0.0.1:8082/v1/pubkeys" "local issuer" 40 || { compose_server logs --tail=80 issuer; exit 1; }
  wait_http_ok "http://127.0.0.1:8083/v1/health" "local entry" 40 || { compose_server logs --tail=120 entry-exit; exit 1; }
  wait_http_ok "http://127.0.0.1:8084/v1/health" "local exit" 40 || { compose_server logs --tail=120 entry-exit; exit 1; }

  # Optional public endpoint validation (can fail on NAT loopback setups).
  if [[ "${EASY_NODE_VERIFY_PUBLIC:-0}" == "1" ]] && ! host_is_loopback "$public_host"; then
    wait_http_ok "http://${public_host}:8081/v1/relays" "public directory" 15 || { compose_server logs --tail=80 directory; exit 1; }
    wait_http_ok "http://${public_host}:8082/v1/pubkeys" "public issuer" 15 || { compose_server logs --tail=80 issuer; exit 1; }
    wait_http_ok "http://${public_host}:8083/v1/health" "public entry" 15 || { compose_server logs --tail=120 entry-exit; exit 1; }
    wait_http_ok "http://${public_host}:8084/v1/health" "public exit" 15 || { compose_server logs --tail=120 entry-exit; exit 1; }
  fi

  echo "server stack started"
  echo "env file: $SERVER_ENV_FILE"
  echo "operator_id: $operator_id"
  echo "issuer_id: $issuer_id"
  echo "identity file: $identity_file"
  echo "issuer_admin_token: $issuer_admin_token"
  if [[ "$beta_profile" == "1" ]]; then
    echo "beta profile: enabled (quorum and anti-concentration defaults applied)"
  fi
  echo "client_allowlist: $client_allowlist"
  echo "allow_anon_cred: $allow_anon_cred"
  echo "health checks:"
  echo "  curl http://${public_host}:8081/v1/relays"
  echo "  curl http://${public_host}:8082/v1/pubkeys"
  echo "  curl http://${public_host}:8083/v1/health"
  echo "  curl http://${public_host}:8084/v1/health"

  if [[ -n "$peer_dirs" ]]; then
    local bootstrap_host
    bootstrap_host="$(host_from_url "$(first_csv_item "$peer_dirs")")"
    if [[ -n "$local_host" && -n "$bootstrap_host" && "$local_host" != "$bootstrap_host" ]]; then
      write_hosts_config "$bootstrap_host" "$local_host"
      echo "updated host config: $(hosts_config_file)"
    fi
  fi
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

cleanup_client_demo_artifacts() {
  local stale_runs=""

  stale_runs="$(docker ps -aq --filter "name=deploy-client-demo-run-" || true)"
  if [[ -n "$stale_runs" ]]; then
    # Best-effort cleanup for interrupted client runs.
    docker rm -f $stale_runs >/dev/null 2>&1 || true
  fi

  # Remove dangling default network if it is no longer in use.
  if docker network inspect deploy_default >/dev/null 2>&1; then
    docker network rm deploy_default >/dev/null 2>&1 || true
  fi
}

stop_all() {
  ensure_deps_or_die

  compose_server down --remove-orphans >/dev/null 2>&1 || true
  (
    cd "$DEPLOY_DIR"
    env COMPOSE_INTERACTIVE_NO_CLI=1 COMPOSE_MENU=0 docker compose --profile demo down --remove-orphans >/dev/null 2>&1 || true
  )
  cleanup_client_demo_artifacts

  local compose_ids=""
  compose_ids="$(docker ps -aq --filter "label=com.docker.compose.project=deploy" || true)"
  if [[ -n "$compose_ids" ]]; then
    docker rm -f $compose_ids >/dev/null 2>&1 || true
  fi

  local compose_networks=""
  compose_networks="$(docker network ls -q --filter "label=com.docker.compose.project=deploy" || true)"
  if [[ -n "$compose_networks" ]]; then
    docker network rm $compose_networks >/dev/null 2>&1 || true
  fi

  echo "all local Privacynode docker resources are stopped"
}

install_deps_ubuntu() {
  local installer="$ROOT_DIR/scripts/install_deps_ubuntu.sh"
  if [[ ! -x "$installer" ]]; then
    echo "missing installer script: $installer"
    exit 2
  fi
  "$installer"
}

three_machine_validate() {
  ensure_deps_or_die
  "$ROOT_DIR/scripts/integration_3machine_beta_validate.sh" "$@"
}

three_machine_soak() {
  ensure_deps_or_die
  "$ROOT_DIR/scripts/integration_3machine_beta_soak.sh" "$@"
}

discover_hosts() {
  local bootstrap_directory=""
  local wait_sec="${EASY_NODE_DISCOVERY_WAIT_SEC:-12}"
  local min_hosts="2"
  local write_config="0"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --bootstrap-directory)
        bootstrap_directory="${2:-}"
        shift 2
        ;;
      --wait-sec)
        wait_sec="${2:-}"
        shift 2
        ;;
      --min-hosts)
        min_hosts="${2:-}"
        shift 2
        ;;
      --write-config)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          write_config="${2:-}"
          shift 2
        else
          write_config="1"
          shift
        fi
        ;;
      -h|--help|help)
        usage
        return 0
        ;;
      *)
        echo "unknown arg for discover-hosts: $1"
        exit 2
        ;;
    esac
  done

  if [[ -z "$bootstrap_directory" ]]; then
    echo "discover-hosts requires --bootstrap-directory URL"
    exit 2
  fi
  if ! [[ "$wait_sec" =~ ^[0-9]+$ && "$min_hosts" =~ ^[0-9]+$ ]]; then
    echo "discover-hosts requires numeric --wait-sec and --min-hosts"
    exit 2
  fi
  if [[ "$write_config" != "0" && "$write_config" != "1" ]]; then
    echo "discover-hosts requires --write-config to be 0 or 1"
    exit 2
  fi

  need_cmd curl || exit 2
  need_cmd rg || exit 2

  bootstrap_directory="$(trim_url "$bootstrap_directory")"
  local discovered_csv
  discovered_csv="$(discover_directory_urls "$bootstrap_directory" "$wait_sec" "$min_hosts")"
  if [[ -z "$discovered_csv" ]]; then
    echo "no hosts discovered from $bootstrap_directory"
    exit 1
  fi

  echo "bootstrap_directory=$bootstrap_directory"
  echo "discovered_directory_urls=$discovered_csv"

  local discovered_hosts
  discovered_hosts="$(
    printf '%s\n' "$discovered_csv" | tr ',' '\n' | sed '/^$/d' |
      while IFS= read -r u; do host_from_url "$u"; done |
      awk 'NF > 0' | sort -u
  )"
  echo "discovered_hosts:"
  printf '%s\n' "$discovered_hosts"

  if [[ "$write_config" == "1" ]]; then
    local host_a host_b bootstrap_host
    bootstrap_host="$(host_from_url "$bootstrap_directory")"
    if [[ -n "$bootstrap_host" ]]; then
      host_a="$bootstrap_host"
      host_b="$(printf '%s\n' "$discovered_hosts" | awk -v bootstrap="$bootstrap_host" '$0 != bootstrap {print; exit}')"
    else
      host_a="$(printf '%s\n' "$discovered_hosts" | sed -n '1p')"
      host_b="$(printf '%s\n' "$discovered_hosts" | sed -n '2p')"
    fi
    if [[ -n "$host_a" && -n "$host_b" ]]; then
      write_hosts_config "$host_a" "$host_b"
      echo "updated host config: $(hosts_config_file)"
    else
      echo "not enough hosts to update config (need at least 2)"
      exit 1
    fi
  fi
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

pilot_runbook() {
  ensure_deps_or_die
  "$ROOT_DIR/scripts/beta_pilot_runbook.sh" "$@"
}

server_env_value() {
  local key="$1"
  identity_value "$SERVER_ENV_FILE" "$key"
}

default_issuer_url_for_invites() {
  local issuer_url=""
  local directory_public_url=""
  local public_host=""

  directory_public_url="$(server_env_value "DIRECTORY_PUBLIC_URL")"
  if [[ -n "$directory_public_url" ]]; then
    public_host="$(host_from_url "$directory_public_url")"
    if [[ -n "$public_host" ]]; then
      issuer_url="$(url_from_host_port "$public_host" 8082)"
    fi
  fi
  if [[ -z "$issuer_url" ]]; then
    issuer_url="http://127.0.0.1:8082"
  fi
  echo "$issuer_url"
}

invite_generate() {
  local issuer_url="${ISSUER_URL:-}"
  local admin_token="${ISSUER_ADMIN_TOKEN:-}"
  local count="1"
  local prefix="inv"
  local tier="1"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --issuer-url)
        issuer_url="${2:-}"
        shift 2
        ;;
      --admin-token)
        admin_token="${2:-}"
        shift 2
        ;;
      --count)
        count="${2:-}"
        shift 2
        ;;
      --prefix)
        prefix="${2:-}"
        shift 2
        ;;
      --tier)
        tier="${2:-}"
        shift 2
        ;;
      -h|--help|help)
        usage
        return 0
        ;;
      *)
        echo "unknown arg for invite-generate: $1"
        exit 2
        ;;
    esac
  done

  if [[ -z "$issuer_url" ]]; then
    issuer_url="$(default_issuer_url_for_invites)"
  fi
  issuer_url="$(trim_url "$issuer_url")"

  if [[ -z "$admin_token" ]]; then
    admin_token="$(server_env_value "ISSUER_ADMIN_TOKEN")"
  fi
  if [[ -z "$admin_token" ]]; then
    echo "invite-generate requires --admin-token or ISSUER_ADMIN_TOKEN in $SERVER_ENV_FILE"
    exit 2
  fi
  if ! [[ "$count" =~ ^[0-9]+$ ]] || ((count < 1)); then
    echo "invite-generate requires --count >= 1"
    exit 2
  fi
  if [[ "$tier" != "1" && "$tier" != "2" && "$tier" != "3" ]]; then
    echo "invite-generate requires --tier 1|2|3"
    exit 2
  fi
  prefix="$(printf '%s' "$prefix" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9-_')"
  if [[ -z "$prefix" ]]; then
    prefix="inv"
  fi

  local upsert_script="$ROOT_DIR/scripts/beta_subject_upsert.sh"
  if [[ ! -x "$upsert_script" ]]; then
    echo "missing helper script: $upsert_script"
    exit 2
  fi

  local generated=0
  local attempts=0
  local max_attempts=$((count * 8))
  if ((max_attempts < 8)); then
    max_attempts=8
  fi
  local key
  while ((generated < count)); do
    attempts=$((attempts + 1))
    if ((attempts > max_attempts)); then
      echo "invite-generate failed: could not create requested keys after $max_attempts attempts"
      echo "check issuer URL/admin token: issuer=$issuer_url"
      exit 1
    fi
    key="${prefix}-$(random_token | tr -cd 'a-zA-Z0-9' | tr '[:upper:]' '[:lower:]' | head -c 22)"
    if [[ -z "$key" ]]; then
      continue
    fi
    if "$upsert_script" \
      --issuer-url "$issuer_url" \
      --admin-token "$admin_token" \
      --subject "$key" \
      --kind "client" \
      --tier "$tier" >/dev/null 2>&1; then
      generated=$((generated + 1))
      echo "$key"
    fi
  done
  echo "invite keys generated: $generated (issuer=$issuer_url)"
}

invite_check() {
  local key=""
  local issuer_url="${ISSUER_URL:-}"
  local admin_token="${ISSUER_ADMIN_TOKEN:-}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --key|--subject)
        key="${2:-}"
        shift 2
        ;;
      --issuer-url)
        issuer_url="${2:-}"
        shift 2
        ;;
      --admin-token)
        admin_token="${2:-}"
        shift 2
        ;;
      -h|--help|help)
        usage
        return 0
        ;;
      *)
        echo "unknown arg for invite-check: $1"
        exit 2
        ;;
    esac
  done

  key="$(trim "$key")"
  if [[ -z "$key" ]]; then
    echo "invite-check requires --key"
    exit 2
  fi
  if [[ -z "$issuer_url" ]]; then
    issuer_url="$(default_issuer_url_for_invites)"
  fi
  issuer_url="$(trim_url "$issuer_url")"
  if [[ -z "$admin_token" ]]; then
    admin_token="$(server_env_value "ISSUER_ADMIN_TOKEN")"
  fi
  if [[ -z "$admin_token" ]]; then
    echo "invite-check requires --admin-token or ISSUER_ADMIN_TOKEN in $SERVER_ENV_FILE"
    exit 2
  fi

  local payload
  payload="$(curl -fsS "${issuer_url}/v1/admin/subject/get?subject=${key}" \
    -H "Authorization: Bearer ${admin_token}" 2>/dev/null || true)"
  if [[ -z "$payload" ]]; then
    echo "invite key not found: $key"
    exit 1
  fi

  local kind tier
  kind="$(printf '%s\n' "$payload" | rg -o '"kind":"[^"]+"' | head -n 1 | sed -E 's/^"kind":"([^"]+)"$/\1/')"
  tier="$(printf '%s\n' "$payload" | rg -o '"tier":[0-9]+' | head -n 1 | sed -E 's/^"tier":([0-9]+)$/\1/')"
  if [[ "$kind" == "client" && "${tier:-0}" -ge 1 ]]; then
    echo "invite key valid: key=$key kind=$kind tier=$tier issuer=$issuer_url"
    return 0
  fi
  echo "invite key not eligible for client use: key=$key kind=${kind:-unknown} tier=${tier:-unknown}"
  return 1
}

invite_disable() {
  local key=""
  local issuer_url="${ISSUER_URL:-}"
  local admin_token="${ISSUER_ADMIN_TOKEN:-}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --key|--subject)
        key="${2:-}"
        shift 2
        ;;
      --issuer-url)
        issuer_url="${2:-}"
        shift 2
        ;;
      --admin-token)
        admin_token="${2:-}"
        shift 2
        ;;
      -h|--help|help)
        usage
        return 0
        ;;
      *)
        echo "unknown arg for invite-disable: $1"
        exit 2
        ;;
    esac
  done

  key="$(trim "$key")"
  if [[ -z "$key" ]]; then
    echo "invite-disable requires --key"
    exit 2
  fi
  if [[ -z "$issuer_url" ]]; then
    issuer_url="$(default_issuer_url_for_invites)"
  fi
  issuer_url="$(trim_url "$issuer_url")"
  if [[ -z "$admin_token" ]]; then
    admin_token="$(server_env_value "ISSUER_ADMIN_TOKEN")"
  fi
  if [[ -z "$admin_token" ]]; then
    echo "invite-disable requires --admin-token or ISSUER_ADMIN_TOKEN in $SERVER_ENV_FILE"
    exit 2
  fi

  local upsert_script="$ROOT_DIR/scripts/beta_subject_upsert.sh"
  if [[ ! -x "$upsert_script" ]]; then
    echo "missing helper script: $upsert_script"
    exit 2
  fi
  "$upsert_script" \
    --issuer-url "$issuer_url" \
    --admin-token "$admin_token" \
    --subject "$key" \
    --kind "relay-exit" \
    --tier "1" >/dev/null
  echo "invite key disabled: $key (issuer=$issuer_url)"
}

client_test() {
  local directory_urls=""
  local issuer_url=""
  local entry_url=""
  local exit_url=""
  local min_sources="1"
  local client_subject="${CLIENT_SUBJECT:-}"
  local client_anon_cred="${CLIENT_ANON_CRED:-}"
  local exit_country=""
  local exit_region=""
  local timeout_sec="35"
  local build_timeout_sec="${EASY_NODE_CLIENT_BUILD_TIMEOUT_SEC:-180}"
  local force_build="${EASY_NODE_CLIENT_FORCE_BUILD:-0}"
  local require_distinct_operators="${CLIENT_REQUIRE_DISTINCT_OPERATORS:-0}"
  local entry_rotation_sec="${CLIENT_ENTRY_ROTATION_SEC:-0}"
  local entry_rotation_seed="${CLIENT_ENTRY_ROTATION_SEED:-0}"
  local min_selection_lines="${EASY_NODE_CLIENT_MIN_SELECTION_LINES:-1}"
  local min_entry_operators="${EASY_NODE_CLIENT_MIN_ENTRY_OPERATORS:-1}"
  local min_exit_operators="${EASY_NODE_CLIENT_MIN_EXIT_OPERATORS:-1}"
  local require_cross_operator_pair="${EASY_NODE_CLIENT_REQUIRE_CROSS_OPERATOR_PAIR:-0}"
  local beta_profile="${EASY_NODE_BETA_PROFILE:-0}"
  local bootstrap_directory=""
  local discovery_wait_sec="${EASY_NODE_DISCOVERY_WAIT_SEC:-12}"
  local min_sources_set=0
  local distinct_set=0

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
      --bootstrap-directory)
        bootstrap_directory="${2:-}"
        shift 2
        ;;
      --discovery-wait-sec)
        discovery_wait_sec="${2:-}"
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
        min_sources_set=1
        shift 2
        ;;
      --subject)
        client_subject="${2:-}"
        shift 2
        ;;
      --anon-cred)
        client_anon_cred="${2:-}"
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
      --distinct-operators)
        if [[ "${2:-}" == "0" || "${2:-}" == "1" ]]; then
          require_distinct_operators="${2:-}"
          distinct_set=1
          shift 2
        else
          require_distinct_operators="1"
          distinct_set=1
          shift
        fi
        ;;
      --min-selection-lines)
        min_selection_lines="${2:-}"
        shift 2
        ;;
      --min-entry-operators)
        min_entry_operators="${2:-}"
        shift 2
        ;;
      --min-exit-operators)
        min_exit_operators="${2:-}"
        shift 2
        ;;
      --require-cross-operator-pair)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          require_cross_operator_pair="${2:-}"
          shift 2
        else
          require_cross_operator_pair="1"
          shift
        fi
        ;;
      --beta-profile)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          beta_profile="${2:-}"
          shift 2
        else
          beta_profile="1"
          shift
        fi
        ;;
      *)
        echo "unknown arg for client-test: $1"
        exit 2
        ;;
    esac
  done

  if [[ "$require_distinct_operators" != "0" && "$require_distinct_operators" != "1" ]]; then
    echo "client-test requires CLIENT_REQUIRE_DISTINCT_OPERATORS or --distinct-operators to be 0 or 1"
    exit 2
  fi
  if [[ "$require_cross_operator_pair" != "0" && "$require_cross_operator_pair" != "1" ]]; then
    echo "client-test requires --require-cross-operator-pair to be 0 or 1"
    exit 2
  fi
  if ! [[ "$entry_rotation_sec" =~ ^[0-9]+$ ]]; then
    echo "client-test requires CLIENT_ENTRY_ROTATION_SEC to be numeric"
    exit 2
  fi
  if ! [[ "$entry_rotation_seed" =~ ^-?[0-9]+$ ]]; then
    echo "client-test requires CLIENT_ENTRY_ROTATION_SEED to be numeric"
    exit 2
  fi
  if ! [[ "$min_selection_lines" =~ ^[0-9]+$ && "$min_entry_operators" =~ ^[0-9]+$ && "$min_exit_operators" =~ ^[0-9]+$ ]]; then
    echo "client-test requires --min-selection-lines, --min-entry-operators and --min-exit-operators to be numeric"
    exit 2
  fi
  if [[ "$beta_profile" != "0" && "$beta_profile" != "1" ]]; then
    echo "client-test requires --beta-profile (or EASY_NODE_BETA_PROFILE) to be 0 or 1"
    exit 2
  fi
  if [[ "$beta_profile" == "1" ]]; then
    if [[ "$distinct_set" -eq 0 ]]; then
      require_distinct_operators="1"
    fi
    if [[ "$min_sources_set" -eq 0 ]] && [[ "$directory_urls" == *,* ]]; then
      min_sources="2"
    fi
  fi
  if [[ -n "$client_subject" && -n "$client_anon_cred" ]]; then
    echo "client-test requires exactly one of --subject or --anon-cred"
    exit 2
  fi

  if [[ -n "$bootstrap_directory" ]]; then
    bootstrap_directory="$(trim_url "$bootstrap_directory")"
    if ! [[ "$discovery_wait_sec" =~ ^[0-9]+$ ]]; then
      echo "client-test requires --discovery-wait-sec to be numeric"
      exit 2
    fi
    local discovered
    discovered="$(discover_directory_urls "$bootstrap_directory" "$discovery_wait_sec" "$min_sources")"
    if [[ -z "$directory_urls" ]]; then
      directory_urls="$discovered"
    else
      directory_urls="$(merge_url_csv "$directory_urls" "$discovered")"
    fi

    local bootstrap_host
    bootstrap_host="$(host_from_url "$bootstrap_directory")"
    if [[ -z "$issuer_url" && -n "$bootstrap_host" ]]; then
      issuer_url="$(url_from_host_port "$bootstrap_host" 8082)"
    fi
    if [[ -z "$entry_url" && -n "$bootstrap_host" ]]; then
      entry_url="$(url_from_host_port "$bootstrap_host" 8083)"
    fi
    if [[ -z "$exit_url" && -n "$bootstrap_host" ]]; then
      exit_url="$(url_from_host_port "$bootstrap_host" 8084)"
    fi
  fi

  if [[ -z "$directory_urls" || -z "$issuer_url" || -z "$entry_url" || -z "$exit_url" ]]; then
    echo "client-test requires directory, issuer, entry and exit URLs."
    echo "provide explicit --directory-urls/--issuer-url/--entry-url/--exit-url"
    echo "or use --bootstrap-directory for automatic discovery."
    exit 2
  fi

  ensure_deps_or_die
  cleanup_client_demo_artifacts

  local first_dir
  first_dir="$(first_csv_item "$directory_urls")"

  cat >"$CLIENT_ENV_FILE" <<EOF_CLIENT
CLIENT_DIRECTORY_URL=${first_dir}
CLIENT_ISSUER_URL=${issuer_url}
CLIENT_ENTRY_URL=${entry_url}
CLIENT_EXIT_CONTROL_URL=${exit_url}
CLIENT_ENTRY_ROTATION_SEC=${entry_rotation_sec}
CLIENT_ENTRY_ROTATION_SEED=${entry_rotation_seed}
EOF_CLIENT

  local log_dir
  local out
  local build_log
  log_dir="$(prepare_log_dir)"
  build_log="$log_dir/easy_node_client_build_$(date +%Y%m%d_%H%M%S).log"
  out="$log_dir/easy_node_client_test_$(date +%Y%m%d_%H%M%S).log"
  rm -f "$out"

  if looks_like_loopback_url "$first_dir" || looks_like_loopback_url "$issuer_url" || looks_like_loopback_url "$entry_url" || looks_like_loopback_url "$exit_url"; then
    echo "note: one or more URLs use localhost/127.0.0.1"
    echo "      this only works when those addresses are reachable from inside the client container."
  fi

  wait_http_ok "${first_dir%/}/v1/pubkeys" "directory" 8 || return 1
  wait_http_ok "${issuer_url%/}/v1/pubkeys" "issuer" 8 || return 1
  wait_http_ok "${entry_url%/}/v1/health" "entry" 8 || return 1
  wait_http_ok "${exit_url%/}/v1/health" "exit" 8 || return 1

  local do_build=0
  if [[ "$force_build" == "1" ]]; then
    do_build=1
  elif ! docker image inspect deploy-client-demo:latest >/dev/null 2>&1; then
    do_build=1
  fi

  if [[ "$do_build" -eq 1 ]]; then
    echo "client test: building client image (timeout=${build_timeout_sec}s)"
    if ! (
      cd "$DEPLOY_DIR"
      timeout --foreground -k 15s "${build_timeout_sec}s" env COMPOSE_INTERACTIVE_NO_CLI=1 COMPOSE_MENU=0 docker compose --profile demo build client-demo >"$build_log" 2>&1
    ); then
      echo "client image build failed or timed out"
      echo "client build log: $build_log"
      cat "$build_log"
      return 1
    fi
    echo "client test: build done"
  else
    echo "client test: using existing deploy-client-demo:latest image (set EASY_NODE_CLIENT_FORCE_BUILD=1 to rebuild)"
  fi
  if [[ "$beta_profile" == "1" ]]; then
    echo "client test: beta profile enabled (distinct operators + multi-source defaults)"
  fi

  local -a run_cmd
  run_cmd=(
    env
    COMPOSE_INTERACTIVE_NO_CLI=1
    COMPOSE_MENU=0
    docker compose
    --env-file "$CLIENT_ENV_FILE"
    --profile demo
    run -T --no-deps --rm
    -e "DIRECTORY_URLS=$directory_urls"
    -e "DIRECTORY_MIN_SOURCES=$min_sources"
    -e "ISSUER_URL=$issuer_url"
    -e "ENTRY_URL=$entry_url"
    -e "EXIT_CONTROL_URL=$exit_url"
    -e "CLIENT_BOOTSTRAP_INTERVAL_SEC=2"
    -e "CLIENT_REQUIRE_DISTINCT_OPERATORS=$require_distinct_operators"
    -e "CLIENT_ENTRY_ROTATION_SEC=$entry_rotation_sec"
    -e "CLIENT_ENTRY_ROTATION_SEED=$entry_rotation_seed"
  )
  if [[ -n "$client_subject" ]]; then
    run_cmd+=(-e "CLIENT_SUBJECT=$client_subject")
  fi
  if [[ -n "$client_anon_cred" ]]; then
    run_cmd+=(-e "CLIENT_ANON_CRED=$client_anon_cred")
  fi
  if [[ "$beta_profile" == "1" ]]; then
    run_cmd+=(
      -e "DIRECTORY_MIN_OPERATORS=2"
      -e "CLIENT_DIRECTORY_MIN_OPERATORS=2"
    )
  fi
  if [[ -n "$exit_country" ]]; then
    run_cmd+=(-e "CLIENT_EXIT_COUNTRY=$exit_country")
  fi
  if [[ -n "$exit_region" ]]; then
    run_cmd+=(-e "CLIENT_EXIT_REGION=$exit_region")
  fi
  run_cmd+=(client-demo)

  (
    cd "$DEPLOY_DIR"
    timeout --foreground -k 10s "${timeout_sec}s" "${run_cmd[@]}" >"$out" 2>&1
  ) || true

  if rg -q 'client selected entry=' "$out"; then
    local same_ops missing_ops selection_count entry_op_count exit_op_count cross_pair_count
    read -r same_ops missing_ops selection_count entry_op_count exit_op_count cross_pair_count < <(
        awk '
          /client selected entry=/ {
            selected++
            entry_op=""
            exit_op=""
            for (i = 1; i <= NF; i++) {
              if ($i ~ /^entry_op=/) {
                entry_op = substr($i, 10)
              } else if ($i ~ /^exit_op=/) {
                exit_op = substr($i, 9)
              }
            }
            if (entry_op == "" || exit_op == "") {
              missing++
            } else if (entry_op == exit_op) {
              same++
            } else {
              cross++
            }
            if (entry_op != "") {
              entry_seen[entry_op] = 1
            }
            if (exit_op != "") {
              exit_seen[exit_op] = 1
            }
          }
          END {
            entry_count = 0
            exit_count = 0
            for (k in entry_seen) {
              entry_count++
            }
            for (k in exit_seen) {
              exit_count++
            }
            if (same == "") {
              same = 0
            }
            if (missing == "") {
              missing = 0
            }
            if (selected == "") {
              selected = 0
            }
            if (cross == "") {
              cross = 0
            }
            printf "%d %d %d %d %d %d\n", same, missing, selected, entry_count, exit_count, cross
          }
        ' "$out"
      )
    echo "client selection summary: selections=$selection_count entry_ops=$entry_op_count exit_ops=$exit_op_count cross_pairs=$cross_pair_count same_ops=$same_ops missing_ops=$missing_ops"
    if ((selection_count < min_selection_lines)); then
      echo "client test: failed selection volume validation (observed=$selection_count required=$min_selection_lines)"
      echo "client test log: $out"
      rg 'client selected entry=' "$out" || true
      return 1
    fi
    if ((entry_op_count < min_entry_operators)); then
      echo "client test: failed entry-operator diversity validation (observed=$entry_op_count required=$min_entry_operators)"
      echo "client test log: $out"
      rg 'client selected entry=' "$out" || true
      return 1
    fi
    if ((exit_op_count < min_exit_operators)); then
      echo "client test: failed exit-operator diversity validation (observed=$exit_op_count required=$min_exit_operators)"
      echo "client test log: $out"
      rg 'client selected entry=' "$out" || true
      return 1
    fi
    if [[ "$require_cross_operator_pair" == "1" ]] && ((cross_pair_count < 1)); then
      echo "client test: failed cross-operator-pair validation (observed=$cross_pair_count required>=1)"
      echo "client test log: $out"
      rg 'client selected entry=' "$out" || true
      return 1
    fi
    if [[ "$require_distinct_operators" == "1" ]]; then
      if ((same_ops > 0 || missing_ops > 0)); then
        echo "client test: failed distinct-operator validation (same_ops=$same_ops missing_ops=$missing_ops)"
        echo "client test log: $out"
        rg 'client selected entry=' "$out" || true
        return 1
      fi
    fi
    echo "client test: ok"
    echo "client test log: $out"
    echo "key log lines:"
    rg 'client selected entry=|client received wg-session config|bootstrap failed' "$out" || true
    return 0
  fi

  echo "client test: failed"
  echo "client test log: $out"
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
    stop-all)
      stop_all
      ;;
    install-deps-ubuntu)
      install_deps_ubuntu
      ;;
    client-test)
      shift
      client_test "$@"
      ;;
    three-machine-validate)
      shift
      three_machine_validate "$@"
      ;;
    three-machine-soak)
      shift
      three_machine_soak "$@"
      ;;
    invite-generate)
      shift
      invite_generate "$@"
      ;;
    invite-check)
      shift
      invite_check "$@"
      ;;
    invite-disable)
      shift
      invite_disable "$@"
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
    pilot-runbook)
      shift
      pilot_runbook "$@"
      ;;
    discover-hosts)
      shift
      discover_hosts "$@"
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
