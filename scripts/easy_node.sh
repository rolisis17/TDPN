#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$ROOT_DIR/deploy"
AUTHORITY_ENV_FILE="$DEPLOY_DIR/.env.easy.server"
PROVIDER_ENV_FILE="$DEPLOY_DIR/.env.easy.provider"
# Backward-compatible alias for older helpers that expect SERVER_ENV_FILE.
SERVER_ENV_FILE="$AUTHORITY_ENV_FILE"
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
  ./scripts/easy_node.sh server-up [--mode authority|provider] [--public-host HOST] [--operator-id ID] [--issuer-id ID] [--issuer-admin-token TOKEN] [--directory-admin-token TOKEN] [--entry-puzzle-secret SECRET] [--authority-directory URL] [--authority-issuer URL] [--peer-directories URLS] [--bootstrap-directory URL] [--client-allowlist [0|1]] [--allow-anon-cred [0|1]] [--beta-profile [0|1]] [--prod-profile [0|1]] [--show-admin-token [0|1]]
  ./scripts/easy_node.sh server-status
  ./scripts/easy_node.sh server-logs
  ./scripts/easy_node.sh server-down
  ./scripts/easy_node.sh rotate-server-secrets [--restart [0|1]] [--rotate-issuer-admin [0|1]] [--show-secrets [0|1]]
  ./scripts/easy_node.sh stop-all [--with-wg-only [0|1]] [--force-iface-cleanup [0|1]]
  ./scripts/easy_node.sh install-deps-ubuntu
  ./scripts/easy_node.sh wg-only-check
  ./scripts/easy_node.sh wg-only-local-test [--matrix [0|1]] [--strict-beta [0|1]] [--timeout-sec N]
  ./scripts/easy_node.sh wg-only-stack-up [--strict-beta [0|1]] [--detach [0|1]] [--base-port N] [--client-iface IFACE] [--exit-iface IFACE] [--force-iface-reset [0|1]] [--cleanup-ifaces [0|1]] [--log-file PATH]
  ./scripts/easy_node.sh wg-only-stack-status
  ./scripts/easy_node.sh wg-only-stack-down [--force-iface-cleanup [0|1]]
  ./scripts/easy_node.sh wg-only-stack-selftest [--strict-beta [0|1]] [--base-port N] [--timeout-sec N] [--min-selection-lines N] [--force-iface-reset [0|1]] [--cleanup-ifaces [0|1]] [--keep-stack [0|1]]
  ./scripts/easy_node.sh client-test [--directory-urls URL[,URL...]] [--bootstrap-directory URL] [--discovery-wait-sec N] [--issuer-url URL] [--entry-url URL] [--exit-url URL] [--subject ID] [--anon-cred TOKEN] [--min-sources N] [--exit-country CC] [--exit-region REGION] [--timeout-sec N] [--distinct-operators [0|1]] [--min-selection-lines N] [--min-entry-operators N] [--min-exit-operators N] [--require-cross-operator-pair [0|1]] [--beta-profile [0|1]] [--prod-profile [0|1]]
  ./scripts/easy_node.sh three-machine-validate [--directory-a URL] [--directory-b URL] [--bootstrap-directory URL] [--discovery-wait-sec N] [--issuer-url URL] [--issuer-a-url URL] [--issuer-b-url URL] [--entry-url URL] [--exit-url URL] [--subject ID] [--anon-cred TOKEN] [--min-sources N] [--min-operators N] [--federation-timeout-sec N] [--timeout-sec N] [--client-min-selection-lines N] [--client-min-entry-operators N] [--client-min-exit-operators N] [--client-require-cross-operator-pair [0|1]] [--exit-country CC] [--exit-region REGION] [--distinct-operators [0|1]] [--require-issuer-quorum [0|1]] [--beta-profile [0|1]]
  ./scripts/easy_node.sh three-machine-soak [--directory-a URL] [--directory-b URL] [--bootstrap-directory URL] [--discovery-wait-sec N] [--issuer-url URL] [--issuer-a-url URL] [--issuer-b-url URL] [--entry-url URL] [--exit-url URL] [--subject ID] [--anon-cred TOKEN] [--rounds N] [--pause-sec N] [--fault-every N] [--fault-command CMD] [--continue-on-fail [0|1]] [--min-sources N] [--min-operators N] [--federation-timeout-sec N] [--timeout-sec N] [--client-min-selection-lines N] [--client-min-entry-operators N] [--client-min-exit-operators N] [--client-require-cross-operator-pair [0|1]] [--exit-country CC] [--exit-region REGION] [--distinct-operators [0|1]] [--require-issuer-quorum [0|1]] [--beta-profile [0|1]] [--report-file PATH]
  ./scripts/easy_node.sh pilot-runbook [--directory-a URL] [--directory-b URL] [--bootstrap-directory URL] [--discovery-wait-sec N] [--issuer-url URL] [--issuer-a-url URL] [--issuer-b-url URL] [--entry-url URL] [--exit-url URL] [--subject ID] [--anon-cred TOKEN] [--rounds N] [--pause-sec N] [--min-sources N] [--min-operators N] [--federation-timeout-sec N] [--timeout-sec N] [--client-min-selection-lines N] [--client-min-entry-operators N] [--client-min-exit-operators N] [--client-require-cross-operator-pair [0|1]] [--distinct-operators [0|1]] [--require-issuer-quorum [0|1]] [--beta-profile [0|1]] [--bundle-dir PATH]
  ./scripts/easy_node.sh invite-generate [--issuer-url URL] [--admin-token TOKEN] [--admin-key-file FILE] [--admin-key-id ID] [--count N] [--prefix PREFIX] [--tier 1|2|3]
  ./scripts/easy_node.sh invite-check --key KEY [--issuer-url URL] [--admin-token TOKEN] [--admin-key-file FILE] [--admin-key-id ID]
  ./scripts/easy_node.sh invite-disable --key KEY [--issuer-url URL] [--admin-token TOKEN] [--admin-key-file FILE] [--admin-key-id ID]
  ./scripts/easy_node.sh admin-signing-status
  ./scripts/easy_node.sh admin-signing-rotate [--restart-issuer [0|1]] [--key-history N]
  ./scripts/easy_node.sh prod-preflight [--days-min N] [--check-live [0|1]] [--timeout-sec N]
  ./scripts/easy_node.sh bootstrap-mtls [--out-dir DIR] [--public-host HOST] [--san HOST] [--days N] [--rotate-leaf [0|1]] [--rotate-ca [0|1]]
  ./scripts/easy_node.sh machine-a-test [--public-host HOST] [--report-file PATH]
  ./scripts/easy_node.sh machine-b-test --peer-directory-a URL [--public-host HOST] [--min-operators N] [--federation-timeout-sec N] [--report-file PATH]
  ./scripts/easy_node.sh machine-c-test [--directory-a URL] [--directory-b URL] [--bootstrap-directory URL] [--discovery-wait-sec N] [--issuer-url URL] [--entry-url URL] [--exit-url URL] [--subject ID] [--anon-cred TOKEN] [--min-sources N] [--min-operators N] [--federation-timeout-sec N] [--timeout-sec N] [--exit-country CC] [--exit-region REGION] [--distinct-operators [0|1]] [--beta-profile [0|1]] [--report-file PATH]
  ./scripts/easy_node.sh discover-hosts --bootstrap-directory URL [--wait-sec N] [--min-hosts N] [--write-config [0|1]]

Notes:
  - server-up --mode authority runs directory + issuer + entry-exit.
  - server-up --mode provider runs directory + entry-exit only (no local issuer/admin token).
  - rotate-server-secrets rotates local server secret material in env files; use --restart 1 to apply immediately.
  - --prod-profile enables fail-closed production strict mode (requires mTLS + signed issuer-admin auth).
  - admin-signing-status/admin-signing-rotate are authority-only issuer admin signer maintenance tools.
  - prod-preflight validates strict prod profile wiring (mTLS material, HTTPS URLs, and authority signer config).
  - client-test runs client-demo with --no-deps (no local server required on the client machine).
  - wg-only-local-test runs host real-WireGuard integration checks (Linux + root required).
  - wg-only-stack-up/status/down manages a reusable host real-WireGuard demo stack (Linux + root required).
  - wg-only-stack-selftest runs stack-up + client-test + stack-down as one command (Linux + root required).
  - stop-all can also clean WG-only stack state/process/interfaces when requested (root needed for interface cleanup).
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

secure_file_permissions() {
  local file="$1"
  if [[ -f "$file" ]]; then
    chmod 600 "$file" 2>/dev/null || true
  fi
}

check_dependencies() {
  local ok=1
  need_cmd docker || ok=0
  need_cmd curl || ok=0
  need_cmd timeout || ok=0
  need_cmd rg || ok=0
  need_cmd jq || ok=0
  need_cmd go || ok=0
  need_cmd openssl || ok=0

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

wait_http_ok_with_opts() {
  local url="$1"
  local name="$2"
  local attempts="${3:-30}"
  shift 3
  local i
  local -a opts=("$@")
  for ((i = 1; i <= attempts; i++)); do
    if curl -fsS --connect-timeout 2 --max-time 6 "${opts[@]}" "$url" >/dev/null 2>&1; then
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

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
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

ensure_url_scheme() {
  local raw="$1"
  local scheme="$2"
  raw="$(trim_url "$raw")"
  scheme="$(trim "$scheme")"
  if [[ -z "$raw" || -z "$scheme" ]]; then
    echo "$raw"
    return
  fi
  if [[ "$raw" == "$scheme://"* ]]; then
    echo "$raw"
    return
  fi
  if [[ "$raw" == http://* || "$raw" == https://* ]]; then
    echo "${scheme}://${raw#*://}"
    return
  fi
  echo "${scheme}://${raw}"
}

is_https_url() {
  local raw
  raw="$(trim "$1")"
  [[ "$raw" == https://* ]]
}

bootstrap_mtls() {
  local script="$ROOT_DIR/scripts/bootstrap_mtls.sh"
  if [[ ! -x "$script" ]]; then
    echo "missing helper script: $script"
    exit 2
  fi
  "$script" "$@"
}

ensure_admin_signing_material() {
  local rotate="${1:-0}"
  local history_raw="${2:-${EASY_NODE_ADMIN_SIGNING_KEY_HISTORY:-3}}"
  local issuer_data_dir="$DEPLOY_DIR/data/issuer"
  local key_file="$issuer_data_dir/issuer_admin_signer.key"
  local key_id_file="$issuer_data_dir/issuer_admin_signer.keyid"
  local signers_file="$issuer_data_dir/issuer_admin_signers.txt"
  local signers_file_container="/app/data/issuer_admin_signers.txt"
  local inspect_json key_id pub_key
  local key_history=3

  if [[ "$history_raw" =~ ^[0-9]+$ ]] && ((history_raw > 0)); then
    key_history="$history_raw"
  fi

  mkdir -p "$issuer_data_dir"
  if [[ "$rotate" == "1" ]]; then
    rm -f "$key_file" "$key_id_file"
  fi
  if [[ ! -f "$key_file" ]]; then
    (
      cd "$ROOT_DIR"
      go run ./cmd/adminsig gen --private-key-out "$key_file" --key-id-out "$key_id_file" >/dev/null
    )
  fi

  inspect_json="$(
    cd "$ROOT_DIR"
    go run ./cmd/adminsig inspect --private-key-file "$key_file"
  )"
  key_id="$(printf '%s\n' "$inspect_json" | jq -r '.key_id')"
  pub_key="$(printf '%s\n' "$inspect_json" | jq -r '.public_key')"
  if [[ -z "$key_id" || -z "$pub_key" || "$key_id" == "null" || "$pub_key" == "null" ]]; then
    echo "failed to inspect issuer admin signing key material"
    exit 1
  fi

  local signers_tmp
  signers_tmp="$(mktemp)"
  {
    printf '%s=%s\n' "$key_id" "$pub_key"
    if [[ -f "$signers_file" ]]; then
      cat "$signers_file"
    fi
  } | awk '
      NF == 0 { next }
      /^#/ { next }
      {
        split($0, p, "=")
        k = p[1]
        if (k == "") next
        if (!(k in seen)) {
          seen[k] = 1
          print $0
        }
      }
    ' | head -n "$key_history" >"$signers_tmp"
  mv "$signers_tmp" "$signers_file"

  printf '%s\n' "$key_id" >"$key_id_file"
  secure_file_permissions "$key_file"
  chmod 644 "$signers_file" "$key_id_file" 2>/dev/null || true

  echo "$key_file|$key_id|$signers_file|$signers_file_container"
}

resolve_invite_admin_auth() {
  local cli_token="${1:-}"
  local cli_key_file="${2:-}"
  local cli_key_id="${3:-}"
  local env_token env_key_file env_key_id

  if [[ -n "$cli_token" ]]; then
    echo "token|$cli_token||"
    return
  fi
  if [[ -n "$cli_key_file" && -n "$cli_key_id" ]]; then
    echo "signed||$cli_key_file|$cli_key_id"
    return
  fi

  env_key_file="$(server_env_value "ISSUER_ADMIN_SIGNING_PRIVATE_KEY_FILE_LOCAL" | tr -d '\r')"
  env_key_id="$(server_env_value "ISSUER_ADMIN_SIGNING_KEY_ID" | tr -d '\r')"
  if [[ -n "$env_key_file" && -n "$env_key_id" ]]; then
    echo "signed||$env_key_file|$env_key_id"
    return
  fi

  env_token="$(resolve_invite_admin_token "")"
  if [[ -n "$env_token" ]]; then
    echo "token|$env_token||"
    return
  fi

  echo "none|||"
}

resolve_local_mtls_material() {
  local ca cert key
  ca="$(server_env_value "EASY_NODE_MTLS_CA_FILE_LOCAL" | tr -d '\r')"
  cert="$(server_env_value "EASY_NODE_MTLS_CLIENT_CERT_FILE_LOCAL" | tr -d '\r')"
  key="$(server_env_value "EASY_NODE_MTLS_CLIENT_KEY_FILE_LOCAL" | tr -d '\r')"
  if [[ -z "$ca" ]]; then
    ca="$DEPLOY_DIR/tls/ca.crt"
  fi
  if [[ -z "$cert" ]]; then
    cert="$DEPLOY_DIR/tls/client.crt"
  fi
  if [[ -z "$key" ]]; then
    key="$DEPLOY_DIR/tls/client.key"
  fi
  echo "$ca|$cert|$key"
}

curl_tls_opts_for_url() {
  local url="$1"
  if ! is_https_url "$url"; then
    return
  fi
  local triple ca cert key
  triple="$(resolve_local_mtls_material)"
  IFS='|' read -r ca cert key <<<"$triple"
  if [[ -f "$ca" ]]; then
    printf '%s\n' "--cacert" "$ca"
  fi
  if [[ -f "$cert" && -f "$key" ]]; then
    printf '%s\n' "--cert" "$cert" "--key" "$key"
  fi
}

build_admin_header_args() {
  local method="$1"
  local url="$2"
  local body_file="$3"
  local auth_mode="$4"
  local admin_token="$5"
  local admin_key_file="$6"
  local admin_key_id="$7"
  local out_var="$8"
  local -a header_args=()

  if [[ "$auth_mode" == "signed" ]]; then
    if [[ -z "$admin_key_file" || -z "$admin_key_id" ]]; then
      echo "missing admin signing credentials" >&2
      return 1
    fi
    if [[ ! -f "$admin_key_file" ]]; then
      echo "admin signing key file not found: $admin_key_file" >&2
      return 1
    fi
    local sign_json
    local -a sign_cmd=(
      go run ./cmd/adminsig sign
      --private-key-file "$admin_key_file"
      --key-id "$admin_key_id"
      --method "$method"
      --url "$url"
    )
    if [[ -n "$body_file" ]]; then
      sign_cmd+=(--body-file "$body_file")
    fi
    sign_json="$(
      cd "$ROOT_DIR"
      "${sign_cmd[@]}"
    )"

    local h_key_id h_ts h_nonce h_sig
    h_key_id="$(printf '%s\n' "$sign_json" | jq -r '.headers["X-Admin-Key-Id"]')"
    h_ts="$(printf '%s\n' "$sign_json" | jq -r '.headers["X-Admin-Timestamp"]')"
    h_nonce="$(printf '%s\n' "$sign_json" | jq -r '.headers["X-Admin-Nonce"]')"
    h_sig="$(printf '%s\n' "$sign_json" | jq -r '.headers["X-Admin-Signature"]')"
    if [[ -z "$h_key_id" || -z "$h_ts" || -z "$h_nonce" || -z "$h_sig" || "$h_key_id" == "null" || "$h_sig" == "null" ]]; then
      echo "failed to generate signed admin headers" >&2
      return 1
    fi
    header_args+=(-H "X-Admin-Key-Id: ${h_key_id}")
    header_args+=(-H "X-Admin-Timestamp: ${h_ts}")
    header_args+=(-H "X-Admin-Nonce: ${h_nonce}")
    header_args+=(-H "X-Admin-Signature: ${h_sig}")
  else
    if [[ -z "$admin_token" ]]; then
      echo "missing admin token" >&2
      return 1
    fi
    header_args+=(-H "X-Admin-Token: ${admin_token}")
  fi

  eval "$out_var=(\"\${header_args[@]}\")"
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

normalize_url_csv_scheme() {
  local csv="$1"
  local scheme="$2"
  local out=""
  local item normalized
  while IFS= read -r item; do
    [[ -z "$item" ]] && continue
    normalized="$(ensure_url_scheme "$item" "$scheme")"
    if [[ -n "$out" ]]; then
      out+=","
    fi
    out+="$normalized"
  done < <(split_csv_lines "$csv")
  echo "$out"
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

server_mode_file() {
  echo "$DEPLOY_DIR/data/easy_node_server_mode.conf"
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
  # Fallback entropy path when openssl is unavailable.
  if [[ -r /dev/urandom ]] && command -v od >/dev/null 2>&1; then
    od -An -N16 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n'
    return
  fi
  # Last-resort fallback.
  date +%s%N | sha256sum | awk '{print substr($1,1,32)}'
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
  awk -F= -v k="$key" '
    $1 == k {
      v = substr($0, index($0, "=") + 1)
      gsub(/\r/, "", v)
      sub(/^[[:space:]]+/, "", v)
      sub(/[[:space:]]+$/, "", v)
      print v
      exit
    }
  ' "$file"
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
  secure_file_permissions "$file"
}

write_server_mode() {
  local mode="$1"
  local file
  file="$(server_mode_file)"
  mkdir -p "$(dirname "$file")"
  cat >"$file" <<EOF_MODE
EASY_NODE_SERVER_MODE=${mode}
EASY_NODE_SERVER_MODE_UPDATED_UNIX=$(date +%s)
EOF_MODE
  secure_file_permissions "$file"
}

active_server_mode() {
  local mode_file mode
  mode_file="$(server_mode_file)"
  mode="$(identity_value "$mode_file" "EASY_NODE_SERVER_MODE")"
  if [[ -n "$mode" ]]; then
    echo "$mode"
    return
  fi
  if [[ -f "$AUTHORITY_ENV_FILE" && ! -f "$PROVIDER_ENV_FILE" ]]; then
    echo "authority"
    return
  fi
  if [[ -f "$PROVIDER_ENV_FILE" && ! -f "$AUTHORITY_ENV_FILE" ]]; then
    echo "provider"
    return
  fi
  echo "unknown"
}

active_server_env_file() {
  local mode
  mode="$(active_server_mode)"
  if [[ "$mode" == "provider" ]]; then
    echo "$PROVIDER_ENV_FILE"
    return
  fi
  echo "$AUTHORITY_ENV_FILE"
}

require_authority_mode() {
  local action="$1"
  local mode
  mode="$(active_server_mode)"
  if [[ "$mode" == "authority" ]]; then
    return
  fi
  echo "$action is allowed only on authority nodes."
  echo "detected mode: $mode"
  echo "run server-up --mode authority on your admin machine."
  exit 2
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

compose_with_env() {
  local env_file="$1"
  shift
  if [[ -f "$env_file" ]]; then
    (cd "$DEPLOY_DIR" && docker compose --env-file "$env_file" "$@")
  else
    (cd "$DEPLOY_DIR" && docker compose "$@")
  fi
}

compose_server() {
  compose_with_env "$AUTHORITY_ENV_FILE" "$@"
}

write_authority_env() {
  local public_host="$1"
  local operator_id="$2"
  local issuer_id="$3"
  local issuer_admin_token="$4"
  local directory_admin_token="$5"
  local entry_puzzle_secret="$6"
  local peer_dirs="$7"
  local beta_profile="$8"
  local client_allowlist="$9"
  local allow_anon_cred="${10}"
  local prod_profile="${11}"
  local admin_signers_file_container="${12:-}"
  local admin_sign_key_id="${13:-}"
  local admin_sign_key_file_local="${14:-}"
  local public_scheme="http"
  local relay_suffix
  local issuer_suffix
  if [[ "$prod_profile" == "1" ]]; then
    public_scheme="https"
  fi
  relay_suffix="$(sanitize_id_component "$operator_id")"
  if [[ -z "$issuer_id" ]]; then
    issuer_id="issuer-$(random_id_suffix)"
  fi
  issuer_suffix="$(sanitize_id_component "$issuer_id")"

  cat >"$AUTHORITY_ENV_FILE" <<EOF_ENV
EASY_NODE_SERVER_MODE=authority
DIRECTORY_PUBLIC_URL=${public_scheme}://${public_host}:8081
ENTRY_URL_PUBLIC=${public_scheme}://${public_host}:8083
EXIT_CONTROL_URL_PUBLIC=${public_scheme}://${public_host}:8084
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
DIRECTORY_ADMIN_TOKEN=${directory_admin_token}
ENTRY_PUZZLE_SECRET=${entry_puzzle_secret}
ISSUER_CLIENT_ALLOWLIST_ONLY=${client_allowlist}
ISSUER_ALLOW_ANON_CRED=${allow_anon_cred}
EOF_ENV
  secure_file_permissions "$AUTHORITY_ENV_FILE"

  if [[ -n "$peer_dirs" ]]; then
    echo "DIRECTORY_PEERS=${peer_dirs}" >>"$AUTHORITY_ENV_FILE"
    echo "DIRECTORY_SYNC_SEC=5" >>"$AUTHORITY_ENV_FILE"
    echo "DIRECTORY_GOSSIP_SEC=5" >>"$AUTHORITY_ENV_FILE"
  fi

  if [[ "$beta_profile" == "1" ]]; then
    cat >>"$AUTHORITY_ENV_FILE" <<'EOF_BETA'
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
  if [[ "$prod_profile" == "1" ]]; then
    cat >>"$AUTHORITY_ENV_FILE" <<EOF_PROD
BETA_STRICT_MODE=1
PROD_STRICT_MODE=1
MTLS_ENABLE=1
MTLS_CA_FILE=/app/tls/ca.crt
MTLS_CERT_FILE=/app/tls/node.crt
MTLS_KEY_FILE=/app/tls/node.key
MTLS_CLIENT_CERT_FILE=/app/tls/node.crt
MTLS_CLIENT_KEY_FILE=/app/tls/node.key
MTLS_REQUIRE_CLIENT_CERT=1
MTLS_MIN_VERSION=1.3
DIRECTORY_TRUST_STRICT=1
DIRECTORY_TRUST_TOFU=0
ENTRY_DIRECTORY_TRUST_STRICT=1
ENTRY_DIRECTORY_TRUST_TOFU=0
DIRECTORY_PEER_TRUST_STRICT=1
DIRECTORY_PEER_TRUST_TOFU=0
ISSUER_ADMIN_REQUIRE_SIGNED=1
ISSUER_ADMIN_ALLOW_TOKEN=0
ISSUER_ADMIN_SIGNED_WINDOW_SEC=90
ISSUER_ADMIN_SIGNING_KEYS_FILE=${admin_signers_file_container}
ISSUER_ADMIN_SIGNING_PRIVATE_KEY_FILE_LOCAL=${admin_sign_key_file_local}
ISSUER_ADMIN_SIGNING_KEY_ID=${admin_sign_key_id}
EASY_NODE_MTLS_CA_FILE_LOCAL=${DEPLOY_DIR}/tls/ca.crt
EASY_NODE_MTLS_CLIENT_CERT_FILE_LOCAL=${DEPLOY_DIR}/tls/client.crt
EASY_NODE_MTLS_CLIENT_KEY_FILE_LOCAL=${DEPLOY_DIR}/tls/client.key
EOF_PROD
  fi
  secure_file_permissions "$AUTHORITY_ENV_FILE"
}

write_provider_env() {
  local public_host="$1"
  local operator_id="$2"
  local directory_admin_token="$3"
  local entry_puzzle_secret="$4"
  local peer_dirs="$5"
  local beta_profile="$6"
  local authority_issuer="$7"
  local prod_profile="$8"
  local public_scheme="http"
  local relay_suffix

  if [[ "$prod_profile" == "1" ]]; then
    public_scheme="https"
  fi
  relay_suffix="$(sanitize_id_component "$operator_id")"
  authority_issuer="$(trim_url "$authority_issuer")"

  cat >"$PROVIDER_ENV_FILE" <<EOF_ENV
EASY_NODE_SERVER_MODE=provider
DIRECTORY_PUBLIC_URL=${public_scheme}://${public_host}:8081
ENTRY_URL_PUBLIC=${public_scheme}://${public_host}:8083
EXIT_CONTROL_URL_PUBLIC=${public_scheme}://${public_host}:8084
ENTRY_ENDPOINT_PUBLIC=${public_host}:51820
EXIT_ENDPOINT_PUBLIC=${public_host}:51821
DIRECTORY_OPERATOR_ID=${operator_id}
ENTRY_RELAY_ID=entry-${relay_suffix}
EXIT_RELAY_ID=exit-${relay_suffix}
DIRECTORY_PRIVATE_KEY_FILE=/app/data/directory_${relay_suffix}_ed25519.key
DIRECTORY_PREVIOUS_PUBKEYS_FILE=/app/data/directory_${relay_suffix}_previous_pubkeys.txt
DIRECTORY_ADMIN_TOKEN=${directory_admin_token}
ENTRY_PUZZLE_SECRET=${entry_puzzle_secret}
CORE_DIRECTORY_URL=${public_scheme}://directory:8081
CORE_ISSUER_URL=${authority_issuer}
EOF_ENV
  secure_file_permissions "$PROVIDER_ENV_FILE"

  if [[ -n "$peer_dirs" ]]; then
    echo "DIRECTORY_PEERS=${peer_dirs}" >>"$PROVIDER_ENV_FILE"
    echo "DIRECTORY_SYNC_SEC=5" >>"$PROVIDER_ENV_FILE"
    echo "DIRECTORY_GOSSIP_SEC=5" >>"$PROVIDER_ENV_FILE"
  fi

  if [[ "$beta_profile" == "1" ]]; then
    cat >>"$PROVIDER_ENV_FILE" <<'EOF_BETA'
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
EOF_BETA
  fi
  if [[ "$prod_profile" == "1" ]]; then
    cat >>"$PROVIDER_ENV_FILE" <<'EOF_PROD'
BETA_STRICT_MODE=1
PROD_STRICT_MODE=1
MTLS_ENABLE=1
MTLS_CA_FILE=/app/tls/ca.crt
MTLS_CERT_FILE=/app/tls/node.crt
MTLS_KEY_FILE=/app/tls/node.key
MTLS_CLIENT_CERT_FILE=/app/tls/node.crt
MTLS_CLIENT_KEY_FILE=/app/tls/node.key
MTLS_REQUIRE_CLIENT_CERT=1
MTLS_MIN_VERSION=1.3
DIRECTORY_TRUST_STRICT=1
DIRECTORY_TRUST_TOFU=0
ENTRY_DIRECTORY_TRUST_STRICT=1
ENTRY_DIRECTORY_TRUST_TOFU=0
DIRECTORY_PEER_TRUST_STRICT=1
DIRECTORY_PEER_TRUST_TOFU=0
EASY_NODE_MTLS_CA_FILE_LOCAL=${DEPLOY_DIR}/tls/ca.crt
EASY_NODE_MTLS_CLIENT_CERT_FILE_LOCAL=${DEPLOY_DIR}/tls/client.crt
EASY_NODE_MTLS_CLIENT_KEY_FILE_LOCAL=${DEPLOY_DIR}/tls/client.key
EOF_PROD
  fi
  secure_file_permissions "$PROVIDER_ENV_FILE"
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
  local mode="${EASY_NODE_SERVER_MODE:-authority}"
  local public_host=""
  local operator_id=""
  local operator_id_explicit="0"
  local issuer_id=""
  local issuer_id_explicit="0"
  local issuer_admin_token=""
  local issuer_admin_token_explicit="0"
  local directory_admin_token="${EASY_NODE_DIRECTORY_ADMIN_TOKEN:-}"
  local entry_puzzle_secret="${EASY_NODE_ENTRY_PUZZLE_SECRET:-}"
  local peer_dirs=""
  local bootstrap_directory=""
  local authority_directory="${EASY_NODE_AUTHORITY_DIRECTORY:-}"
  local authority_issuer="${EASY_NODE_AUTHORITY_ISSUER:-}"
  local client_allowlist="${EASY_NODE_CLIENT_ALLOWLIST_ONLY:-0}"
  local client_allowlist_explicit="0"
  local allow_anon_cred="${EASY_NODE_ALLOW_ANON_CRED:-1}"
  local allow_anon_cred_explicit="0"
  local beta_profile="${EASY_NODE_BETA_PROFILE:-0}"
  local prod_profile="${EASY_NODE_PROD_PROFILE:-0}"
  local show_admin_token="${EASY_NODE_SHOW_ADMIN_TOKEN:-0}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mode)
        mode="${2:-}"
        shift 2
        ;;
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
        issuer_admin_token_explicit="1"
        shift 2
        ;;
      --directory-admin-token)
        directory_admin_token="${2:-}"
        shift 2
        ;;
      --entry-puzzle-secret)
        entry_puzzle_secret="${2:-}"
        shift 2
        ;;
      --authority-directory)
        authority_directory="${2:-}"
        shift 2
        ;;
      --authority-issuer)
        authority_issuer="${2:-}"
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
          client_allowlist_explicit="1"
          shift 2
        else
          client_allowlist="1"
          client_allowlist_explicit="1"
          shift
        fi
        ;;
      --allow-anon-cred)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          allow_anon_cred="${2:-}"
          allow_anon_cred_explicit="1"
          shift 2
        else
          allow_anon_cred="0"
          allow_anon_cred_explicit="1"
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
      --prod-profile)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          prod_profile="${2:-}"
          shift 2
        else
          prod_profile="1"
          shift
        fi
        ;;
      --show-admin-token)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          show_admin_token="${2:-}"
          shift 2
        else
          show_admin_token="1"
          shift
        fi
        ;;
      *)
        echo "unknown arg for server-up: $1"
        exit 2
        ;;
    esac
  done

  if [[ "$mode" != "authority" && "$mode" != "provider" ]]; then
    echo "server-up requires --mode authority|provider"
    exit 2
  fi
  if [[ "$beta_profile" != "0" && "$beta_profile" != "1" ]]; then
    echo "server-up requires --beta-profile (or EASY_NODE_BETA_PROFILE) to be 0 or 1"
    exit 2
  fi
  if [[ "$prod_profile" != "0" && "$prod_profile" != "1" ]]; then
    echo "server-up requires --prod-profile (or EASY_NODE_PROD_PROFILE) to be 0 or 1"
    exit 2
  fi
  if [[ "$prod_profile" == "1" ]]; then
    beta_profile="1"
  fi
  if [[ "$show_admin_token" != "0" && "$show_admin_token" != "1" ]]; then
    echo "server-up requires --show-admin-token (or EASY_NODE_SHOW_ADMIN_TOKEN) to be 0 or 1"
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

  local url_scheme="http"
  if [[ "$prod_profile" == "1" ]]; then
    url_scheme="https"
  fi

  if [[ -n "$bootstrap_directory" ]]; then
    bootstrap_directory="$(ensure_url_scheme "$bootstrap_directory" "$url_scheme")"
    if [[ -z "$peer_dirs" ]]; then
      peer_dirs="$bootstrap_directory"
    else
      peer_dirs="$(merge_url_csv "$peer_dirs" "$bootstrap_directory")"
    fi
    if [[ "$mode" == "provider" && -z "$authority_directory" ]]; then
      authority_directory="$bootstrap_directory"
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
  if [[ "$mode" == "provider" ]]; then
    if [[ -z "$authority_directory" && -n "$peer_dirs" ]]; then
      authority_directory="$(first_csv_item "$peer_dirs")"
    fi
    if [[ -z "$authority_directory" ]]; then
      echo "server-up --mode provider requires --authority-directory (or --bootstrap-directory)"
      exit 2
    fi
    authority_directory="$(ensure_url_scheme "$authority_directory" "$url_scheme")"
    local authority_host
    authority_host="$(host_from_url "$authority_directory")"
    if [[ -z "$authority_issuer" && -n "$authority_host" ]]; then
      authority_issuer="$(url_from_host_port "$authority_host" 8082)"
    fi
    if [[ -z "$authority_issuer" ]]; then
      echo "server-up --mode provider requires --authority-issuer URL"
      exit 2
    fi
    authority_issuer="$(ensure_url_scheme "$authority_issuer" "$url_scheme")"
    if [[ -z "$peer_dirs" ]]; then
      peer_dirs="$authority_directory"
    else
      peer_dirs="$(merge_url_csv "$peer_dirs" "$authority_directory")"
    fi
    if [[ "$issuer_admin_token_explicit" == "1" ]]; then
      echo "note: --issuer-admin-token is ignored in provider mode (no local issuer/admin)."
    fi
    if [[ "$issuer_id_explicit" == "1" ]]; then
      echo "note: --issuer-id is ignored in provider mode."
    fi
    if [[ "$client_allowlist_explicit" == "1" || "$allow_anon_cred_explicit" == "1" ]]; then
      echo "note: --client-allowlist/--allow-anon-cred are issuer settings and are ignored in provider mode."
    fi
  fi

  if [[ -n "$peer_dirs" ]]; then
    peer_dirs="$(normalize_url_csv_scheme "$peer_dirs" "$url_scheme")"
  fi

  if [[ -n "$peer_dirs" ]]; then
    peer_dirs="$(filter_peer_dirs_excluding_host "$peer_dirs" "$local_host")"
  fi

  ensure_deps_or_die

  if [[ -z "$directory_admin_token" ]]; then
    directory_admin_token="$(random_token)"
  fi
  if [[ -z "$entry_puzzle_secret" ]]; then
    entry_puzzle_secret="$(random_token)"
  fi
  if [[ "$prod_profile" == "1" ]]; then
    if [[ "$directory_admin_token" == "dev-admin-token" || "${#directory_admin_token}" -lt 16 ]]; then
      echo "server-up requires a strong DIRECTORY_ADMIN_TOKEN in prod profile (len>=16, non-default)"
      exit 2
    fi
    if [[ "$entry_puzzle_secret" == "entry-secret-default" || "${#entry_puzzle_secret}" -lt 16 ]]; then
      echo "server-up requires a strong ENTRY_PUZZLE_SECRET in prod profile (len>=16, non-default)"
      exit 2
    fi
  fi

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

  if [[ "$mode" == "authority" ]]; then
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
  else
    issuer_id="${stored_issuer_id:-}"
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
  fi

  if [[ "$mode" == "authority" && -n "$peer_dirs" ]]; then
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

  local admin_sign_key_file_local=""
  local admin_sign_key_id=""
  local admin_signers_file_local=""
  local admin_signers_file_container=""
  if [[ "$prod_profile" == "1" ]]; then
    local -a mtls_args
    mtls_args=(--out-dir "$DEPLOY_DIR/tls")
    if [[ -n "$local_host" ]]; then
      mtls_args+=(--public-host "$local_host")
    fi
    if [[ -n "$public_host" && "$public_host" != "$local_host" ]]; then
      mtls_args+=(--san "$public_host")
    fi
    if [[ -n "$peer_dirs" ]]; then
      local peer_url peer_host
      while IFS= read -r peer_url; do
        [[ -z "$peer_url" ]] && continue
        peer_host="$(host_from_url "$peer_url")"
        if [[ -n "$peer_host" ]]; then
          mtls_args+=(--san "$peer_host")
        fi
      done < <(split_csv_lines "$peer_dirs")
    fi
    if [[ "$mode" == "provider" && -n "$authority_directory" ]]; then
      local authority_host
      authority_host="$(host_from_url "$authority_directory")"
      if [[ -n "$authority_host" ]]; then
        mtls_args+=(--san "$authority_host")
      fi
    fi
    bootstrap_mtls "${mtls_args[@]}"
    if [[ "$mode" == "authority" ]]; then
      local signer_material
      signer_material="$(ensure_admin_signing_material)"
      IFS='|' read -r admin_sign_key_file_local admin_sign_key_id admin_signers_file_local admin_signers_file_container <<<"$signer_material"
      if [[ -z "$admin_sign_key_file_local" || -z "$admin_sign_key_id" || -z "$admin_signers_file_container" ]]; then
        echo "server-up failed to initialize issuer admin signing material"
        exit 1
      fi
    fi
  fi

  write_identity_config "$operator_id" "$issuer_id"

  if [[ "$mode" == "authority" ]]; then
    write_authority_env "$public_host" "$operator_id" "$issuer_id" "$issuer_admin_token" "$directory_admin_token" "$entry_puzzle_secret" "$peer_dirs" "$beta_profile" "$client_allowlist" "$allow_anon_cred" "$prod_profile" "$admin_signers_file_container" "$admin_sign_key_id" "$admin_sign_key_file_local"
    compose_with_env "$AUTHORITY_ENV_FILE" up -d --build directory issuer entry-exit

    local -a local_opts
    local -a public_opts
    mapfile -t local_opts < <(curl_tls_opts_for_url "${url_scheme}://127.0.0.1:8081")
    mapfile -t public_opts < <(curl_tls_opts_for_url "${url_scheme}://${public_host}:8081")

    # Always validate local container reachability first.
    wait_http_ok_with_opts "${url_scheme}://127.0.0.1:8081/v1/relays" "local directory" 40 "${local_opts[@]}" || { compose_with_env "$AUTHORITY_ENV_FILE" logs --tail=80 directory; exit 1; }
    wait_http_ok_with_opts "${url_scheme}://127.0.0.1:8082/v1/pubkeys" "local issuer" 40 "${local_opts[@]}" || { compose_with_env "$AUTHORITY_ENV_FILE" logs --tail=80 issuer; exit 1; }
    wait_http_ok_with_opts "${url_scheme}://127.0.0.1:8083/v1/health" "local entry" 40 "${local_opts[@]}" || { compose_with_env "$AUTHORITY_ENV_FILE" logs --tail=120 entry-exit; exit 1; }
    wait_http_ok_with_opts "${url_scheme}://127.0.0.1:8084/v1/health" "local exit" 40 "${local_opts[@]}" || { compose_with_env "$AUTHORITY_ENV_FILE" logs --tail=120 entry-exit; exit 1; }

    # Optional public endpoint validation (can fail on NAT loopback setups).
    if [[ "${EASY_NODE_VERIFY_PUBLIC:-0}" == "1" ]] && ! host_is_loopback "$public_host"; then
      wait_http_ok_with_opts "${url_scheme}://${public_host}:8081/v1/relays" "public directory" 15 "${public_opts[@]}" || { compose_with_env "$AUTHORITY_ENV_FILE" logs --tail=80 directory; exit 1; }
      wait_http_ok_with_opts "${url_scheme}://${public_host}:8082/v1/pubkeys" "public issuer" 15 "${public_opts[@]}" || { compose_with_env "$AUTHORITY_ENV_FILE" logs --tail=80 issuer; exit 1; }
      wait_http_ok_with_opts "${url_scheme}://${public_host}:8083/v1/health" "public entry" 15 "${public_opts[@]}" || { compose_with_env "$AUTHORITY_ENV_FILE" logs --tail=120 entry-exit; exit 1; }
      wait_http_ok_with_opts "${url_scheme}://${public_host}:8084/v1/health" "public exit" 15 "${public_opts[@]}" || { compose_with_env "$AUTHORITY_ENV_FILE" logs --tail=120 entry-exit; exit 1; }
    fi
    write_server_mode "authority"

    echo "server stack started"
    echo "mode: authority"
    echo "env file: $AUTHORITY_ENV_FILE"
    echo "operator_id: $operator_id"
    echo "issuer_id: $issuer_id"
    echo "identity file: $identity_file"
    if [[ "$show_admin_token" == "1" ]]; then
      echo "issuer_admin_token: $issuer_admin_token"
    else
      echo "issuer_admin_token: [hidden] (set --show-admin-token to print)"
    fi
    echo "directory_admin_token: [hidden]"
    echo "entry_puzzle_secret: [hidden]"
    if [[ "$beta_profile" == "1" ]]; then
      echo "beta profile: enabled (quorum and anti-concentration defaults applied)"
    fi
    echo "client_allowlist: $client_allowlist"
    echo "allow_anon_cred: $allow_anon_cred"
    if [[ "$prod_profile" == "1" ]]; then
      echo "prod profile: enabled (mTLS + signed admin controls enforced)"
      echo "admin_signing_key_id: $admin_sign_key_id"
      echo "admin_signing_public_keys_file: $admin_signers_file_local"
    fi
    echo "health checks:"
    if [[ "$prod_profile" == "1" ]]; then
      local mtls_material ca_file cert_file key_file
      mtls_material="$(resolve_local_mtls_material)"
      IFS='|' read -r ca_file cert_file key_file <<<"$mtls_material"
      echo "  curl --cacert $ca_file --cert $cert_file --key $key_file ${url_scheme}://${public_host}:8081/v1/relays"
      echo "  curl --cacert $ca_file --cert $cert_file --key $key_file ${url_scheme}://${public_host}:8082/v1/pubkeys"
      echo "  curl --cacert $ca_file --cert $cert_file --key $key_file ${url_scheme}://${public_host}:8083/v1/health"
      echo "  curl --cacert $ca_file --cert $cert_file --key $key_file ${url_scheme}://${public_host}:8084/v1/health"
    else
      echo "  curl ${url_scheme}://${public_host}:8081/v1/relays"
      echo "  curl ${url_scheme}://${public_host}:8082/v1/pubkeys"
      echo "  curl ${url_scheme}://${public_host}:8083/v1/health"
      echo "  curl ${url_scheme}://${public_host}:8084/v1/health"
    fi
  else
    write_provider_env "$public_host" "$operator_id" "$directory_admin_token" "$entry_puzzle_secret" "$peer_dirs" "$beta_profile" "$authority_issuer" "$prod_profile"
    compose_with_env "$PROVIDER_ENV_FILE" up -d --build --no-deps directory entry-exit

    local -a local_opts
    local -a public_opts
    local -a issuer_opts
    mapfile -t local_opts < <(curl_tls_opts_for_url "${url_scheme}://127.0.0.1:8081")
    mapfile -t public_opts < <(curl_tls_opts_for_url "${url_scheme}://${public_host}:8081")
    mapfile -t issuer_opts < <(curl_tls_opts_for_url "${authority_issuer}")

    wait_http_ok_with_opts "${url_scheme}://127.0.0.1:8081/v1/relays" "local directory" 40 "${local_opts[@]}" || { compose_with_env "$PROVIDER_ENV_FILE" logs --tail=80 directory; exit 1; }
    wait_http_ok_with_opts "${url_scheme}://127.0.0.1:8083/v1/health" "local entry" 40 "${local_opts[@]}" || { compose_with_env "$PROVIDER_ENV_FILE" logs --tail=120 entry-exit; exit 1; }
    wait_http_ok_with_opts "${url_scheme}://127.0.0.1:8084/v1/health" "local exit" 40 "${local_opts[@]}" || { compose_with_env "$PROVIDER_ENV_FILE" logs --tail=120 entry-exit; exit 1; }
    wait_http_ok_with_opts "${authority_issuer}/v1/pubkeys" "authority issuer" 20 "${issuer_opts[@]}" || {
      echo "provider mode requires reachable authority issuer."
      exit 1
    }

    if [[ "${EASY_NODE_VERIFY_PUBLIC:-0}" == "1" ]] && ! host_is_loopback "$public_host"; then
      wait_http_ok_with_opts "${url_scheme}://${public_host}:8081/v1/relays" "public directory" 15 "${public_opts[@]}" || { compose_with_env "$PROVIDER_ENV_FILE" logs --tail=80 directory; exit 1; }
      wait_http_ok_with_opts "${url_scheme}://${public_host}:8083/v1/health" "public entry" 15 "${public_opts[@]}" || { compose_with_env "$PROVIDER_ENV_FILE" logs --tail=120 entry-exit; exit 1; }
      wait_http_ok_with_opts "${url_scheme}://${public_host}:8084/v1/health" "public exit" 15 "${public_opts[@]}" || { compose_with_env "$PROVIDER_ENV_FILE" logs --tail=120 entry-exit; exit 1; }
    fi
    write_server_mode "provider"

    echo "server stack started"
    echo "mode: provider"
    echo "env file: $PROVIDER_ENV_FILE"
    echo "operator_id: $operator_id"
    echo "identity file: $identity_file"
    echo "directory_admin_token: [hidden]"
    echo "entry_puzzle_secret: [hidden]"
    if [[ "$beta_profile" == "1" ]]; then
      echo "beta profile: enabled (quorum and anti-concentration defaults applied)"
    fi
    if [[ "$prod_profile" == "1" ]]; then
      echo "prod profile: enabled (mTLS + strict trust checks enforced)"
    fi
    echo "authority_directory: $authority_directory"
    echo "authority_issuer: $authority_issuer"
    echo "health checks:"
    if [[ "$prod_profile" == "1" ]]; then
      local mtls_material ca_file cert_file key_file
      mtls_material="$(resolve_local_mtls_material)"
      IFS='|' read -r ca_file cert_file key_file <<<"$mtls_material"
      echo "  curl --cacert $ca_file --cert $cert_file --key $key_file ${url_scheme}://${public_host}:8081/v1/relays"
      echo "  curl --cacert $ca_file --cert $cert_file --key $key_file ${url_scheme}://${public_host}:8083/v1/health"
      echo "  curl --cacert $ca_file --cert $cert_file --key $key_file ${url_scheme}://${public_host}:8084/v1/health"
    else
      echo "  curl ${url_scheme}://${public_host}:8081/v1/relays"
      echo "  curl ${url_scheme}://${public_host}:8083/v1/health"
      echo "  curl ${url_scheme}://${public_host}:8084/v1/health"
    fi
  fi

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
  local env_file
  env_file="$(active_server_env_file)"
  compose_with_env "$env_file" ps
}

server_logs() {
  ensure_deps_or_die
  local env_file mode
  env_file="$(active_server_env_file)"
  mode="$(active_server_mode)"
  if [[ "$mode" == "provider" ]]; then
    compose_with_env "$env_file" logs --tail=150 directory entry-exit
  else
    compose_with_env "$env_file" logs --tail=150 directory issuer entry-exit
  fi
}

server_down() {
  ensure_deps_or_die
  local env_file
  env_file="$(active_server_env_file)"
  compose_with_env "$env_file" down --remove-orphans
}

rotate_server_secrets() {
  local restart="1"
  local rotate_issuer_admin="1"
  local show_secrets="0"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --restart)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          restart="${2:-}"
          shift 2
        else
          restart="1"
          shift
        fi
        ;;
      --rotate-issuer-admin)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          rotate_issuer_admin="${2:-}"
          shift 2
        else
          rotate_issuer_admin="1"
          shift
        fi
        ;;
      --show-secrets)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          show_secrets="${2:-}"
          shift 2
        else
          show_secrets="1"
          shift
        fi
        ;;
      -h|--help|help)
        usage
        return 0
        ;;
      *)
        echo "unknown arg for rotate-server-secrets: $1"
        exit 2
        ;;
    esac
  done

  if [[ "$restart" != "0" && "$restart" != "1" ]]; then
    echo "rotate-server-secrets requires --restart to be 0 or 1"
    exit 2
  fi
  if [[ "$rotate_issuer_admin" != "0" && "$rotate_issuer_admin" != "1" ]]; then
    echo "rotate-server-secrets requires --rotate-issuer-admin to be 0 or 1"
    exit 2
  fi
  if [[ "$show_secrets" != "0" && "$show_secrets" != "1" ]]; then
    echo "rotate-server-secrets requires --show-secrets to be 0 or 1"
    exit 2
  fi

  local mode env_file
  mode="$(active_server_mode)"
  env_file="$(active_server_env_file)"
  if [[ ! -f "$env_file" ]]; then
    echo "rotate-server-secrets requires existing env file: $env_file"
    exit 2
  fi

  local directory_admin_token entry_puzzle_secret issuer_admin_token=""
  directory_admin_token="$(random_token)"
  entry_puzzle_secret="$(random_token)"

  set_env_kv "$env_file" "DIRECTORY_ADMIN_TOKEN" "$directory_admin_token"
  set_env_kv "$env_file" "ENTRY_PUZZLE_SECRET" "$entry_puzzle_secret"

  if [[ "$mode" == "authority" && "$rotate_issuer_admin" == "1" ]]; then
    issuer_admin_token="$(random_token)"
    set_env_kv "$env_file" "ISSUER_ADMIN_TOKEN" "$issuer_admin_token"
  fi
  secure_file_permissions "$env_file"

  if [[ "$restart" == "1" ]]; then
    ensure_deps_or_die
    if [[ "$mode" == "authority" ]]; then
      compose_with_env "$env_file" up -d directory issuer entry-exit
    else
      compose_with_env "$env_file" up -d --no-deps directory entry-exit
    fi
  fi

  echo "server secrets rotated"
  echo "mode: $mode"
  echo "env file: $env_file"
  echo "restart: $restart"
  if [[ "$show_secrets" == "1" ]]; then
    echo "directory_admin_token: $directory_admin_token"
    echo "entry_puzzle_secret: $entry_puzzle_secret"
    if [[ -n "$issuer_admin_token" ]]; then
      echo "issuer_admin_token: $issuer_admin_token"
    elif [[ "$mode" == "authority" ]]; then
      echo "issuer_admin_token: [unchanged]"
    fi
  else
    echo "directory_admin_token: [hidden]"
    echo "entry_puzzle_secret: [hidden]"
    if [[ "$mode" == "authority" ]]; then
      if [[ "$rotate_issuer_admin" == "1" ]]; then
        echo "issuer_admin_token: [hidden]"
      else
        echo "issuer_admin_token: [unchanged]"
      fi
    fi
    echo "use --show-secrets 1 only when explicitly needed."
  fi
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
  local with_wg_only="1"
  local force_iface_cleanup="1"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --with-wg-only)
        if [[ $# -ge 2 && "${2:-}" != --* ]]; then
          with_wg_only="${2:-}"
          shift 2
        else
          with_wg_only="1"
          shift
        fi
        ;;
      --force-iface-cleanup)
        if [[ $# -ge 2 && "${2:-}" != --* ]]; then
          force_iface_cleanup="${2:-}"
          shift 2
        else
          force_iface_cleanup="1"
          shift
        fi
        ;;
      *)
        echo "unknown arg for stop-all: $1"
        exit 2
        ;;
    esac
  done
  if [[ "$with_wg_only" != "0" && "$with_wg_only" != "1" ]]; then
    echo "stop-all requires --with-wg-only to be 0 or 1"
    exit 2
  fi
  if [[ "$force_iface_cleanup" != "0" && "$force_iface_cleanup" != "1" ]]; then
    echo "stop-all requires --force-iface-cleanup to be 0 or 1"
    exit 2
  fi

  ensure_deps_or_die

  if [[ "$with_wg_only" == "1" ]]; then
    local state_file
    state_file="$(wg_only_state_file)"
    if [[ -f "$state_file" ]]; then
      if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        wg_only_stack_down --force-iface-cleanup "$force_iface_cleanup" >/dev/null 2>&1 || true
        echo "wg-only stack cleanup: done"
      else
        local pid
        pid="$(identity_value "$state_file" "WG_ONLY_PID")"
        if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
          echo "wg-only stack cleanup: skipped (root required)."
          echo "run: sudo ./scripts/easy_node.sh wg-only-stack-down --force-iface-cleanup $force_iface_cleanup"
        else
          rm -f "$state_file" >/dev/null 2>&1 || true
          echo "wg-only stack cleanup: cleared stale state file"
        fi
      fi
    fi
  fi

  compose_with_env "$AUTHORITY_ENV_FILE" down --remove-orphans >/dev/null 2>&1 || true
  compose_with_env "$PROVIDER_ENV_FILE" down --remove-orphans >/dev/null 2>&1 || true
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

wg_only_check() {
  local ok=1
  echo "wg-only preflight checks:"
  if [[ "$(uname -s)" == "Linux" ]]; then
    echo "  [ok] linux kernel"
  else
    echo "  [fail] requires Linux (found: $(uname -s))"
    ok=0
  fi

  for cmd in go wg ip timeout rg curl; do
    if command -v "$cmd" >/dev/null 2>&1; then
      echo "  [ok] command: $cmd"
    else
      echo "  [fail] missing command: $cmd"
      ok=0
    fi
  done

  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    echo "  [ok] running as root"
  else
    echo "  [fail] root privileges required (re-run with sudo)"
    ok=0
  fi

  if [[ $ok -eq 1 ]]; then
    local probe_iface="wgpvtst$RANDOM"
    if ip link add dev "$probe_iface" type wireguard >/dev/null 2>&1; then
      ip link delete "$probe_iface" >/dev/null 2>&1 || true
      echo "  [ok] can create wireguard interface"
    else
      echo "  [fail] cannot create wireguard interface (kernel module/capabilities issue)"
      ok=0
    fi
  fi

  if [[ $ok -eq 1 ]]; then
    echo "wg-only preflight: ok"
    return 0
  fi
  echo "wg-only preflight: failed"
  return 1
}

wg_only_local_test() {
  local matrix="${EASY_NODE_WG_ONLY_MATRIX:-1}"
  local strict_beta="${EASY_NODE_WG_ONLY_STRICT_BETA:-1}"
  local timeout_sec="${EASY_NODE_WG_ONLY_TIMEOUT_SEC:-150}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --matrix)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          matrix="${2:-}"
          shift 2
        else
          matrix="1"
          shift
        fi
        ;;
      --strict-beta)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          strict_beta="${2:-}"
          shift 2
        else
          strict_beta="1"
          shift
        fi
        ;;
      --timeout-sec)
        timeout_sec="${2:-}"
        shift 2
        ;;
      *)
        echo "unknown arg for wg-only-local-test: $1"
        exit 2
        ;;
    esac
  done

  if [[ "$matrix" != "0" && "$matrix" != "1" ]]; then
    echo "wg-only-local-test requires --matrix to be 0 or 1"
    exit 2
  fi
  if [[ "$strict_beta" != "0" && "$strict_beta" != "1" ]]; then
    echo "wg-only-local-test requires --strict-beta to be 0 or 1"
    exit 2
  fi
  if ! [[ "$timeout_sec" =~ ^[0-9]+$ ]] || ((timeout_sec < 30)); then
    echo "wg-only-local-test requires --timeout-sec >= 30"
    exit 2
  fi

  if ! wg_only_check; then
    exit 1
  fi

  local log_dir out
  log_dir="$(prepare_log_dir)"
  out="$log_dir/easy_node_wg_only_test_$(date +%Y%m%d_%H%M%S).log"
  rm -f "$out"

  echo "wg-only local test started"
  echo "matrix: $matrix"
  echo "strict_beta: $strict_beta"
  echo "timeout_sec: $timeout_sec"
  echo "report: $out"

  local -a cmd
  if [[ "$matrix" == "1" ]]; then
    cmd=("./scripts/integration_real_wg_privileged_matrix.sh")
  else
    cmd=(
      env
      "SCRIPT_TIMEOUT_SEC=$timeout_sec"
      "STRICT_BETA_PROFILE=$strict_beta"
      "./scripts/integration_real_wg_privileged.sh"
    )
  fi

  if "${cmd[@]}" >"$out" 2>&1; then
    echo "wg-only local test: ok"
    echo "log: $out"
    rg "real wg privileged integration check ok|real wg privileged matrix integration check ok|profile=.* ok" "$out" || true
    return 0
  fi

  echo "wg-only local test: failed"
  echo "log: $out"
  cat "$out"
  return 1
}

wg_only_state_file() {
  echo "$DEPLOY_DIR/data/wg_only_stack.state"
}

wg_only_stack_status() {
  local state_file
  state_file="$(wg_only_state_file)"
  if [[ ! -f "$state_file" ]]; then
    echo "wg-only stack status: not running"
    return 0
  fi

  local pid client_iface exit_iface log_file strict_beta dir_url issuer_url entry_url exit_url
  pid="$(identity_value "$state_file" "WG_ONLY_PID")"
  client_iface="$(identity_value "$state_file" "WG_ONLY_CLIENT_IFACE")"
  exit_iface="$(identity_value "$state_file" "WG_ONLY_EXIT_IFACE")"
  log_file="$(identity_value "$state_file" "WG_ONLY_LOG_FILE")"
  strict_beta="$(identity_value "$state_file" "WG_ONLY_STRICT_BETA")"
  dir_url="$(identity_value "$state_file" "WG_ONLY_DIRECTORY_URL")"
  issuer_url="$(identity_value "$state_file" "WG_ONLY_ISSUER_URL")"
  entry_url="$(identity_value "$state_file" "WG_ONLY_ENTRY_URL")"
  exit_url="$(identity_value "$state_file" "WG_ONLY_EXIT_URL")"

  local running="0"
  if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
    running="1"
  fi

  echo "wg-only stack status:"
  echo "  running: $running"
  echo "  pid: ${pid:-unknown}"
  echo "  strict_beta: ${strict_beta:-unknown}"
  echo "  client_iface: ${client_iface:-unknown}"
  echo "  exit_iface: ${exit_iface:-unknown}"
  echo "  directory_url: ${dir_url:-unknown}"
  echo "  issuer_url: ${issuer_url:-unknown}"
  echo "  entry_url: ${entry_url:-unknown}"
  echo "  exit_url: ${exit_url:-unknown}"
  echo "  log_file: ${log_file:-unknown}"
  if [[ "$running" == "0" ]]; then
    echo "note: state file is stale; run wg-only-stack-down to clean up."
  fi
  return 0
}

wg_only_stack_up() {
  local strict_beta="${EASY_NODE_WG_ONLY_STACK_STRICT_BETA:-1}"
  local detach="${EASY_NODE_WG_ONLY_STACK_DETACH:-1}"
  local base_port="${EASY_NODE_WG_ONLY_STACK_BASE_PORT:-19080}"
  local client_iface="${EASY_NODE_WG_ONLY_STACK_CLIENT_IFACE:-wgcstack0}"
  local exit_iface="${EASY_NODE_WG_ONLY_STACK_EXIT_IFACE:-wgestack0}"
  local force_iface_reset="${EASY_NODE_WG_ONLY_STACK_FORCE_IFACE_RESET:-0}"
  local cleanup_ifaces="${EASY_NODE_WG_ONLY_STACK_CLEANUP_IFACES:-1}"
  local log_file="${EASY_NODE_WG_ONLY_STACK_LOG_FILE:-}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --strict-beta)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          strict_beta="${2:-}"
          shift 2
        else
          strict_beta="1"
          shift
        fi
        ;;
      --detach)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          detach="${2:-}"
          shift 2
        else
          detach="1"
          shift
        fi
        ;;
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
      --force-iface-reset)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          force_iface_reset="${2:-}"
          shift 2
        else
          force_iface_reset="1"
          shift
        fi
        ;;
      --cleanup-ifaces)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          cleanup_ifaces="${2:-}"
          shift 2
        else
          cleanup_ifaces="1"
          shift
        fi
        ;;
      --log-file)
        log_file="${2:-}"
        shift 2
        ;;
      *)
        echo "unknown arg for wg-only-stack-up: $1"
        exit 2
        ;;
    esac
  done

  if [[ "$strict_beta" != "0" && "$strict_beta" != "1" ]]; then
    echo "wg-only-stack-up requires --strict-beta to be 0 or 1"
    exit 2
  fi
  if [[ "$detach" != "0" && "$detach" != "1" ]]; then
    echo "wg-only-stack-up requires --detach to be 0 or 1"
    exit 2
  fi
  if [[ "$force_iface_reset" != "0" && "$force_iface_reset" != "1" ]]; then
    echo "wg-only-stack-up requires --force-iface-reset to be 0 or 1"
    exit 2
  fi
  if [[ "$cleanup_ifaces" != "0" && "$cleanup_ifaces" != "1" ]]; then
    echo "wg-only-stack-up requires --cleanup-ifaces to be 0 or 1"
    exit 2
  fi
  if ! [[ "$base_port" =~ ^[0-9]+$ ]] || ((base_port < 1024 || base_port > 65400)); then
    echo "wg-only-stack-up requires --base-port in 1024..65400"
    exit 2
  fi
  if [[ -z "$client_iface" || -z "$exit_iface" ]]; then
    echo "wg-only-stack-up requires non-empty --client-iface and --exit-iface"
    exit 2
  fi

  if ! wg_only_check; then
    exit 1
  fi

  local state_file
  state_file="$(wg_only_state_file)"
  mkdir -p "$(dirname "$state_file")"
  if [[ -f "$state_file" ]]; then
    local existing_pid
    existing_pid="$(identity_value "$state_file" "WG_ONLY_PID")"
    if [[ -n "$existing_pid" ]] && kill -0 "$existing_pid" >/dev/null 2>&1; then
      echo "wg-only stack appears to be already running (pid=$existing_pid)"
      echo "use './scripts/easy_node.sh wg-only-stack-status' or './scripts/easy_node.sh wg-only-stack-down'"
      exit 1
    fi
    rm -f "$state_file"
  fi

  local dir_port issuer_port entry_port exit_port entry_data_port exit_data_port exit_wg_port proxy_port sink_port source_port
  dir_port=$((base_port + 1))
  issuer_port=$((base_port + 2))
  entry_port=$((base_port + 3))
  exit_port=$((base_port + 4))
  entry_data_port=$((base_port + 100))
  exit_data_port=$((base_port + 101))
  exit_wg_port=$((base_port + 102))
  proxy_port=$((base_port + 103))
  sink_port=$((base_port + 104))
  source_port=$((base_port + 105))
  if ((source_port > 65535)); then
    echo "wg-only-stack-up computed ports exceed 65535; lower --base-port"
    exit 2
  fi

  local directory_url issuer_url entry_url exit_url entry_data_addr exit_data_addr
  directory_url="http://127.0.0.1:${dir_port}"
  issuer_url="http://127.0.0.1:${issuer_port}"
  entry_url="http://127.0.0.1:${entry_port}"
  exit_url="http://127.0.0.1:${exit_port}"
  entry_data_addr="127.0.0.1:${entry_data_port}"
  exit_data_addr="127.0.0.1:${exit_data_port}"

  if [[ "$force_iface_reset" == "1" ]]; then
    ip link delete "$client_iface" >/dev/null 2>&1 || true
    ip link delete "$exit_iface" >/dev/null 2>&1 || true
  fi
  if ip link show dev "$client_iface" >/dev/null 2>&1; then
    echo "wg-only-stack-up refused: interface '$client_iface' already exists"
    echo "use --force-iface-reset 1 or choose a different --client-iface"
    exit 1
  fi
  if ip link show dev "$exit_iface" >/dev/null 2>&1; then
    echo "wg-only-stack-up refused: interface '$exit_iface' already exists"
    echo "use --force-iface-reset 1 or choose a different --exit-iface"
    exit 1
  fi

  if ! ip link add dev "$client_iface" type wireguard >/dev/null 2>&1; then
    echo "failed to create wireguard interface '$client_iface'"
    exit 1
  fi
  if ! ip link add dev "$exit_iface" type wireguard >/dev/null 2>&1; then
    ip link delete "$client_iface" >/dev/null 2>&1 || true
    echo "failed to create wireguard interface '$exit_iface'"
    exit 1
  fi

  local key_dir client_key_file exit_key_file client_wg_pub exit_wg_pub
  key_dir="$DEPLOY_DIR/data/wg_only"
  mkdir -p "$key_dir"
  client_key_file="$key_dir/client_${client_iface}.key"
  exit_key_file="$key_dir/exit_${exit_iface}.key"
  if [[ ! -f "$client_key_file" ]]; then
    wg genkey >"$client_key_file"
  fi
  if [[ ! -f "$exit_key_file" ]]; then
    wg genkey >"$exit_key_file"
  fi
  chmod 600 "$client_key_file" "$exit_key_file" 2>/dev/null || true
  if ! client_wg_pub="$(wg pubkey <"$client_key_file")"; then
    ip link delete "$client_iface" >/dev/null 2>&1 || true
    ip link delete "$exit_iface" >/dev/null 2>&1 || true
    echo "failed to derive client wireguard public key"
    exit 1
  fi
  if ! exit_wg_pub="$(wg pubkey <"$exit_key_file")"; then
    ip link delete "$client_iface" >/dev/null 2>&1 || true
    ip link delete "$exit_iface" >/dev/null 2>&1 || true
    echo "failed to derive exit wireguard public key"
    exit 1
  fi

  local log_dir
  log_dir="$(prepare_log_dir)"
  if [[ -z "$log_file" ]]; then
    log_file="$log_dir/easy_node_wg_only_stack_$(date +%Y%m%d_%H%M%S).log"
  fi
  mkdir -p "$(dirname "$log_file")"

  local -a env_vars
  env_vars=(
    "WG_ONLY_MODE=1"
    "DATA_PLANE_MODE=opaque"
    "DIRECTORY_ADDR=127.0.0.1:${dir_port}"
    "ISSUER_ADDR=127.0.0.1:${issuer_port}"
    "ENTRY_ADDR=127.0.0.1:${entry_port}"
    "EXIT_ADDR=127.0.0.1:${exit_port}"
    "DIRECTORY_URL=${directory_url}"
    "ISSUER_URL=${issuer_url}"
    "ENTRY_URL=${entry_url}"
    "EXIT_CONTROL_URL=${exit_url}"
    "ENTRY_DATA_ADDR=${entry_data_addr}"
    "ENTRY_ENDPOINT=${entry_data_addr}"
    "EXIT_DATA_ADDR=${exit_data_addr}"
    "EXIT_ENDPOINT=${exit_data_addr}"
    "CLIENT_WG_BACKEND=command"
    "WG_BACKEND=command"
    "CLIENT_WG_PRIVATE_KEY_PATH=${client_key_file}"
    "CLIENT_WG_PUBLIC_KEY=${client_wg_pub}"
    "EXIT_WG_PRIVATE_KEY_PATH=${exit_key_file}"
    "EXIT_WG_PUBKEY=${exit_wg_pub}"
    "CLIENT_WG_INTERFACE=${client_iface}"
    "EXIT_WG_INTERFACE=${exit_iface}"
    "CLIENT_WG_INSTALL_ROUTE=0"
    "CLIENT_WG_KERNEL_PROXY=1"
    "CLIENT_WG_PROXY_ADDR=127.0.0.1:${proxy_port}"
    "CLIENT_INNER_SOURCE=udp"
    "CLIENT_DISABLE_SYNTHETIC_FALLBACK=1"
    "CLIENT_LIVE_WG_MODE=1"
    "DIRECTORY_TRUST_STRICT=1"
    "ENTRY_LIVE_WG_MODE=1"
    "ENTRY_DIRECTORY_TRUST_STRICT=1"
    "EXIT_LIVE_WG_MODE=1"
    "EXIT_TOKEN_PROOF_REPLAY_GUARD=1"
    "EXIT_PEER_REBIND_SEC=0"
    "EXIT_STARTUP_SYNC_TIMEOUT_SEC=8"
    "CLIENT_STARTUP_SYNC_TIMEOUT_SEC=8"
    "EXIT_OPAQUE_SINK_ADDR=127.0.0.1:${sink_port}"
    "EXIT_OPAQUE_SOURCE_ADDR=127.0.0.1:${source_port}"
    "EXIT_WG_LISTEN_PORT=${exit_wg_port}"
    "EXIT_WG_KERNEL_PROXY=1"
  )

  if [[ "$strict_beta" == "1" ]]; then
    env_vars+=(
      "BETA_STRICT_MODE=1"
      "CLIENT_BETA_STRICT=1"
      "ENTRY_BETA_STRICT=1"
      "EXIT_BETA_STRICT=1"
      "CLIENT_REQUIRE_DISTINCT_OPERATORS=1"
      "ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR=1"
      "ENTRY_OPERATOR_ID=op-entry"
      "EXIT_OPERATOR_ID=op-exit"
    )
  fi

  local pid=""
  if [[ "$detach" == "1" ]]; then
    local pid_tmp
    pid_tmp="$(mktemp)"
    (
      cd "$ROOT_DIR"
      nohup env "${env_vars[@]}" go run ./cmd/node --directory --issuer --entry --exit --client >"$log_file" 2>&1 &
      echo "$!" >"$pid_tmp"
    )
    pid="$(cat "$pid_tmp")"
    rm -f "$pid_tmp"
    sleep 1
    if [[ -z "$pid" ]] || ! kill -0 "$pid" >/dev/null 2>&1; then
      echo "wg-only stack failed to start; log follows:"
      cat "$log_file"
      ip link delete "$client_iface" >/dev/null 2>&1 || true
      ip link delete "$exit_iface" >/dev/null 2>&1 || true
      exit 1
    fi

    if ! wait_http_ok "${directory_url}/v1/relays" "wg-only directory" 30; then
      kill "$pid" >/dev/null 2>&1 || true
      sleep 1
      ip link delete "$client_iface" >/dev/null 2>&1 || true
      ip link delete "$exit_iface" >/dev/null 2>&1 || true
      echo "wg-only stack did not become healthy; log follows:"
      cat "$log_file"
      exit 1
    fi
    if ! wait_http_ok "${issuer_url}/v1/pubkeys" "wg-only issuer" 30; then
      kill "$pid" >/dev/null 2>&1 || true
      sleep 1
      ip link delete "$client_iface" >/dev/null 2>&1 || true
      ip link delete "$exit_iface" >/dev/null 2>&1 || true
      echo "wg-only stack issuer did not become healthy; log follows:"
      cat "$log_file"
      exit 1
    fi
    if ! wait_http_ok "${entry_url}/v1/health" "wg-only entry" 30; then
      kill "$pid" >/dev/null 2>&1 || true
      sleep 1
      ip link delete "$client_iface" >/dev/null 2>&1 || true
      ip link delete "$exit_iface" >/dev/null 2>&1 || true
      echo "wg-only stack entry did not become healthy; log follows:"
      cat "$log_file"
      exit 1
    fi
    if ! wait_http_ok "${exit_url}/v1/health" "wg-only exit" 30; then
      kill "$pid" >/dev/null 2>&1 || true
      sleep 1
      ip link delete "$client_iface" >/dev/null 2>&1 || true
      ip link delete "$exit_iface" >/dev/null 2>&1 || true
      echo "wg-only stack exit did not become healthy; log follows:"
      cat "$log_file"
      exit 1
    fi

    cat >"$state_file" <<EOF_STATE
WG_ONLY_PID=$pid
WG_ONLY_CLIENT_IFACE=$client_iface
WG_ONLY_EXIT_IFACE=$exit_iface
WG_ONLY_LOG_FILE=$log_file
WG_ONLY_STRICT_BETA=$strict_beta
WG_ONLY_CLEANUP_IFACES=$cleanup_ifaces
WG_ONLY_DIRECTORY_URL=$directory_url
WG_ONLY_ISSUER_URL=$issuer_url
WG_ONLY_ENTRY_URL=$entry_url
WG_ONLY_EXIT_URL=$exit_url
EOF_STATE
    secure_file_permissions "$state_file"

    echo "wg-only stack started"
    echo "  pid: $pid"
    echo "  strict_beta: $strict_beta"
    echo "  directory: $directory_url"
    echo "  issuer: $issuer_url"
    echo "  entry: $entry_url"
    echo "  exit: $exit_url"
    echo "  log: $log_file"
    echo "use './scripts/easy_node.sh wg-only-stack-status' to inspect"
    echo "use './scripts/easy_node.sh wg-only-stack-down' to stop"
    return 0
  fi

  echo "wg-only stack starting in foreground (strict_beta=$strict_beta)"
  echo "log: $log_file"
  echo "press Ctrl+C to stop"
  (
    cd "$ROOT_DIR"
    env "${env_vars[@]}" go run ./cmd/node --directory --issuer --entry --exit --client
  ) 2>&1 | tee "$log_file"
  local rc=$?
  if [[ "$cleanup_ifaces" == "1" ]]; then
    ip link delete "$client_iface" >/dev/null 2>&1 || true
    ip link delete "$exit_iface" >/dev/null 2>&1 || true
  fi
  return "$rc"
}

wg_only_stack_down() {
  local force_iface_cleanup="0"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --force-iface-cleanup)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          force_iface_cleanup="${2:-}"
          shift 2
        else
          force_iface_cleanup="1"
          shift
        fi
        ;;
      *)
        echo "unknown arg for wg-only-stack-down: $1"
        exit 2
        ;;
    esac
  done
  if [[ "$force_iface_cleanup" != "0" && "$force_iface_cleanup" != "1" ]]; then
    echo "wg-only-stack-down requires --force-iface-cleanup to be 0 or 1"
    exit 2
  fi
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "wg-only-stack-down requires root privileges (run with sudo)"
    exit 1
  fi

  local state_file
  state_file="$(wg_only_state_file)"
  if [[ ! -f "$state_file" ]]; then
    echo "wg-only stack is not running (no state file)"
    return 0
  fi

  local pid client_iface exit_iface cleanup_ifaces
  pid="$(identity_value "$state_file" "WG_ONLY_PID")"
  client_iface="$(identity_value "$state_file" "WG_ONLY_CLIENT_IFACE")"
  exit_iface="$(identity_value "$state_file" "WG_ONLY_EXIT_IFACE")"
  cleanup_ifaces="$(identity_value "$state_file" "WG_ONLY_CLEANUP_IFACES")"
  if [[ "$cleanup_ifaces" != "1" ]]; then
    cleanup_ifaces="0"
  fi

  if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    local i
    for i in $(seq 1 20); do
      if ! kill -0 "$pid" >/dev/null 2>&1; then
        break
      fi
      sleep 0.2
    done
    if kill -0 "$pid" >/dev/null 2>&1; then
      kill -9 "$pid" >/dev/null 2>&1 || true
    fi
    echo "wg-only stack process stopped (pid=$pid)"
  else
    echo "wg-only stack process was not running"
  fi

  if [[ "$cleanup_ifaces" == "1" || "$force_iface_cleanup" == "1" ]]; then
    if [[ -n "$client_iface" ]]; then
      ip link delete "$client_iface" >/dev/null 2>&1 || true
    fi
    if [[ -n "$exit_iface" ]]; then
      ip link delete "$exit_iface" >/dev/null 2>&1 || true
    fi
    echo "wg-only stack interfaces cleaned up"
  else
    echo "wg-only stack interfaces left intact (set --force-iface-cleanup 1 to remove)"
  fi

  rm -f "$state_file"
  echo "wg-only stack state cleared"
  return 0
}

wg_only_stack_selftest() {
  local strict_beta="${EASY_NODE_WG_ONLY_SELFTEST_STRICT_BETA:-1}"
  local base_port="${EASY_NODE_WG_ONLY_SELFTEST_BASE_PORT:-19080}"
  local timeout_sec="${EASY_NODE_WG_ONLY_SELFTEST_TIMEOUT_SEC:-80}"
  local min_selection_lines="${EASY_NODE_WG_ONLY_SELFTEST_MIN_SELECTION_LINES:-8}"
  local force_iface_reset="${EASY_NODE_WG_ONLY_SELFTEST_FORCE_IFACE_RESET:-1}"
  local cleanup_ifaces="${EASY_NODE_WG_ONLY_SELFTEST_CLEANUP_IFACES:-1}"
  local keep_stack="${EASY_NODE_WG_ONLY_SELFTEST_KEEP_STACK:-0}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --strict-beta)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          strict_beta="${2:-}"
          shift 2
        else
          strict_beta="1"
          shift
        fi
        ;;
      --base-port)
        base_port="${2:-}"
        shift 2
        ;;
      --timeout-sec)
        timeout_sec="${2:-}"
        shift 2
        ;;
      --min-selection-lines)
        min_selection_lines="${2:-}"
        shift 2
        ;;
      --force-iface-reset)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          force_iface_reset="${2:-}"
          shift 2
        else
          force_iface_reset="1"
          shift
        fi
        ;;
      --cleanup-ifaces)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          cleanup_ifaces="${2:-}"
          shift 2
        else
          cleanup_ifaces="1"
          shift
        fi
        ;;
      --keep-stack)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          keep_stack="${2:-}"
          shift 2
        else
          keep_stack="1"
          shift
        fi
        ;;
      *)
        echo "unknown arg for wg-only-stack-selftest: $1"
        exit 2
        ;;
    esac
  done

  if [[ "$strict_beta" != "0" && "$strict_beta" != "1" ]]; then
    echo "wg-only-stack-selftest requires --strict-beta to be 0 or 1"
    exit 2
  fi
  if [[ "$force_iface_reset" != "0" && "$force_iface_reset" != "1" ]]; then
    echo "wg-only-stack-selftest requires --force-iface-reset to be 0 or 1"
    exit 2
  fi
  if [[ "$cleanup_ifaces" != "0" && "$cleanup_ifaces" != "1" ]]; then
    echo "wg-only-stack-selftest requires --cleanup-ifaces to be 0 or 1"
    exit 2
  fi
  if [[ "$keep_stack" != "0" && "$keep_stack" != "1" ]]; then
    echo "wg-only-stack-selftest requires --keep-stack to be 0 or 1"
    exit 2
  fi
  if ! [[ "$base_port" =~ ^[0-9]+$ ]] || ((base_port < 1024 || base_port > 65400)); then
    echo "wg-only-stack-selftest requires --base-port in 1024..65400"
    exit 2
  fi
  if ! [[ "$timeout_sec" =~ ^[0-9]+$ ]] || ((timeout_sec < 40)); then
    echo "wg-only-stack-selftest requires --timeout-sec >= 40"
    exit 2
  fi
  if ! [[ "$min_selection_lines" =~ ^[0-9]+$ ]] || ((min_selection_lines < 1)); then
    echo "wg-only-stack-selftest requires --min-selection-lines >= 1"
    exit 2
  fi

  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "wg-only-stack-selftest requires root privileges (run with sudo)"
    exit 1
  fi

  local started="0"
  wg_only_stack_selftest_cleanup() {
    if [[ "$started" == "1" && "$keep_stack" == "0" ]]; then
      wg_only_stack_down --force-iface-cleanup "$cleanup_ifaces" >/dev/null 2>&1 || true
    fi
  }
  trap wg_only_stack_selftest_cleanup EXIT INT TERM

  echo "wg-only stack selftest: starting stack"
  wg_only_stack_up \
    --strict-beta "$strict_beta" \
    --detach 1 \
    --base-port "$base_port" \
    --force-iface-reset "$force_iface_reset" \
    --cleanup-ifaces "$cleanup_ifaces"
  started="1"

  local state_file directory_url issuer_url entry_url exit_url
  state_file="$(wg_only_state_file)"
  directory_url="$(identity_value "$state_file" "WG_ONLY_DIRECTORY_URL")"
  issuer_url="$(identity_value "$state_file" "WG_ONLY_ISSUER_URL")"
  entry_url="$(identity_value "$state_file" "WG_ONLY_ENTRY_URL")"
  exit_url="$(identity_value "$state_file" "WG_ONLY_EXIT_URL")"
  if [[ -z "$directory_url" || -z "$issuer_url" || -z "$entry_url" || -z "$exit_url" ]]; then
    echo "wg-only-stack-selftest failed: missing stack endpoint state"
    exit 1
  fi

  echo "wg-only stack selftest: running client validation"
  if ! client_test \
    --directory-urls "$directory_url" \
    --issuer-url "$issuer_url" \
    --entry-url "$entry_url" \
    --exit-url "$exit_url" \
    --timeout-sec "$timeout_sec" \
    --min-sources 1 \
    --min-selection-lines "$min_selection_lines" \
    --min-entry-operators 1 \
    --min-exit-operators 1 \
    --require-cross-operator-pair 1 \
    --distinct-operators "$strict_beta" \
    --beta-profile "$strict_beta"; then
    echo "wg-only stack selftest: failed"
    exit 1
  fi

  if [[ "$keep_stack" == "1" ]]; then
    echo "wg-only stack selftest: ok (stack left running)"
    trap - EXIT INT TERM
    return 0
  fi

  wg_only_stack_down --force-iface-cleanup "$cleanup_ifaces"
  started="0"
  trap - EXIT INT TERM
  echo "wg-only stack selftest: ok"
  return 0
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

cert_not_after_unix() {
  local cert_file="$1"
  local end_raw end_epoch
  end_raw="$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | sed -E 's/^notAfter=//')"
  if [[ -z "$end_raw" ]]; then
    return 1
  fi
  end_epoch="$(date -u -d "$end_raw" +%s 2>/dev/null || true)"
  if [[ -z "$end_epoch" ]]; then
    return 1
  fi
  echo "$end_epoch"
}

file_mode_octal() {
  local file="$1"
  local mode=""
  if mode="$(stat -c "%a" "$file" 2>/dev/null)"; then
    :
  elif mode="$(stat -f "%Lp" "$file" 2>/dev/null)"; then
    :
  else
    return 1
  fi
  mode="$(printf '%s' "$mode" | tr -cd '0-7')"
  if [[ -z "$mode" ]]; then
    return 1
  fi
  echo "$mode"
}

private_file_mode_secure() {
  local file="$1"
  local mode oct
  mode="$(file_mode_octal "$file" || true)"
  if [[ -z "$mode" ]]; then
    return 2
  fi
  oct=$((8#$mode))
  if (( (oct & 0077) == 0 )); then
    return 0
  fi
  return 1
}

default_issuer_url_for_invites() {
  local issuer_url=""
  local directory_public_url=""
  local public_host=""
  local scheme="http"
  local local_issuer_url=""
  local -a local_opts

  directory_public_url="$(trim_url "$(server_env_value "DIRECTORY_PUBLIC_URL")")"
  if is_https_url "$directory_public_url"; then
    scheme="https"
  fi
  local_issuer_url="$(ensure_url_scheme "127.0.0.1:8082" "$scheme")"
  mapfile -t local_opts < <(curl_tls_opts_for_url "$local_issuer_url")

  # Prefer local issuer endpoint when this command runs on a server machine.
  if curl -fsS --connect-timeout 2 --max-time 6 "${local_opts[@]}" "${local_issuer_url}/v1/pubkeys" >/dev/null 2>&1; then
    echo "$local_issuer_url"
    return
  fi

  if [[ -n "$directory_public_url" ]]; then
    public_host="$(host_from_url "$directory_public_url")"
    if [[ -n "$public_host" ]]; then
      issuer_url="$(ensure_url_scheme "$(url_from_host_port "$public_host" 8082)" "$scheme")"
    fi
  fi
  if [[ -z "$issuer_url" ]]; then
    issuer_url="$local_issuer_url"
  fi
  echo "$issuer_url"
}

resolve_invite_admin_token() {
  local cli_token="${1:-}"
  local file_token=""

  if [[ -n "$cli_token" ]]; then
    printf '%s\n' "$cli_token" | tr -d '\r'
    return
  fi

  file_token="$(server_env_value "ISSUER_ADMIN_TOKEN" | tr -d '\r')"
  if [[ -n "$file_token" ]]; then
    echo "$file_token"
    return
  fi

  if [[ -n "${ISSUER_ADMIN_TOKEN:-}" ]]; then
    printf '%s\n' "${ISSUER_ADMIN_TOKEN}" | tr -d '\r'
    return
  fi
}

invite_generate() {
  require_authority_mode "invite-generate"
  local issuer_url="${ISSUER_URL:-}"
  local admin_token=""
  local admin_key_file=""
  local admin_key_id=""
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
      --admin-key-file)
        admin_key_file="${2:-}"
        shift 2
        ;;
      --admin-key-id)
        admin_key_id="${2:-}"
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
  if [[ "$issuer_url" != http://* && "$issuer_url" != https://* ]]; then
    issuer_url="$(ensure_url_scheme "$issuer_url" "http")"
  fi
  if [[ -n "$admin_key_file" || -n "$admin_key_id" ]]; then
    if [[ -z "$admin_key_file" || -z "$admin_key_id" ]]; then
      echo "invite-generate requires --admin-key-file and --admin-key-id together"
      exit 2
    fi
  fi

  local auth_details auth_mode
  auth_details="$(resolve_invite_admin_auth "$admin_token" "$admin_key_file" "$admin_key_id")"
  IFS='|' read -r auth_mode admin_token admin_key_file admin_key_id <<<"$auth_details"
  if [[ "$auth_mode" == "none" ]]; then
    echo "invite-generate requires admin auth (--admin-token or --admin-key-file + --admin-key-id)"
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
  local last_error=""
  if ((max_attempts < 8)); then
    max_attempts=8
  fi
  local key
  while ((generated < count)); do
    attempts=$((attempts + 1))
    if ((attempts > max_attempts)); then
      echo "invite-generate failed: could not create requested keys after $max_attempts attempts"
      echo "check issuer URL/admin auth: issuer=$issuer_url"
      if [[ -n "$last_error" ]]; then
        echo "last error:"
        echo "$last_error"
      fi
      exit 1
    fi
    key="${prefix}-$(random_token | tr -cd 'a-zA-Z0-9' | tr '[:upper:]' '[:lower:]' | head -c 22)"
    if [[ -z "$key" ]]; then
      continue
    fi
    local upsert_out=""
    local -a upsert_cmd=(
      "$upsert_script"
      --issuer-url "$issuer_url"
      --subject "$key"
      --kind "client"
      --tier "$tier"
    )
    if [[ "$auth_mode" == "signed" ]]; then
      upsert_cmd+=(--admin-key-file "$admin_key_file" --admin-key-id "$admin_key_id")
    else
      upsert_cmd+=(--admin-token "$admin_token")
    fi
    set +e
    upsert_out="$("${upsert_cmd[@]}" 2>&1)"
    local upsert_rc=$?
    set -e
    if [[ $upsert_rc -eq 0 ]]; then
      generated=$((generated + 1))
      echo "$key"
    else
      last_error="$upsert_out"
      if [[ "$upsert_out" == *"401"* || "$upsert_out" == *"403"* ]]; then
        echo "invite-generate failed: issuer rejected admin auth (issuer=$issuer_url)"
        if [[ -n "$last_error" ]]; then
          echo "$last_error"
        fi
        exit 1
      fi
    fi
  done
  echo "invite keys generated: $generated (issuer=$issuer_url)"
  if [[ -n "$last_error" && "$generated" -lt "$count" ]]; then
    echo "last invite-generate error:"
    echo "$last_error"
  fi
}

invite_check() {
  require_authority_mode "invite-check"
  local key=""
  local issuer_url="${ISSUER_URL:-}"
  local admin_token=""
  local admin_key_file=""
  local admin_key_id=""

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
      --admin-key-file)
        admin_key_file="${2:-}"
        shift 2
        ;;
      --admin-key-id)
        admin_key_id="${2:-}"
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
  if [[ "$issuer_url" != http://* && "$issuer_url" != https://* ]]; then
    issuer_url="$(ensure_url_scheme "$issuer_url" "http")"
  fi
  if [[ -n "$admin_key_file" || -n "$admin_key_id" ]]; then
    if [[ -z "$admin_key_file" || -z "$admin_key_id" ]]; then
      echo "invite-check requires --admin-key-file and --admin-key-id together"
      exit 2
    fi
  fi

  local auth_details auth_mode
  auth_details="$(resolve_invite_admin_auth "$admin_token" "$admin_key_file" "$admin_key_id")"
  IFS='|' read -r auth_mode admin_token admin_key_file admin_key_id <<<"$auth_details"
  if [[ "$auth_mode" == "none" ]]; then
    echo "invite-check requires admin auth (--admin-token or --admin-key-file + --admin-key-id)"
    exit 2
  fi

  local request_url="${issuer_url}/v1/admin/subject/get?subject=${key}"
  local -a header_args=()
  local -a tls_args=()
  build_admin_header_args "GET" "$request_url" "" "$auth_mode" "$admin_token" "$admin_key_file" "$admin_key_id" header_args
  mapfile -t tls_args < <(curl_tls_opts_for_url "$issuer_url")

  local payload
  payload="$(curl -fsS --connect-timeout 4 --max-time 12 "${tls_args[@]}" "${header_args[@]}" "$request_url" 2>/dev/null || true)"
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
  require_authority_mode "invite-disable"
  local key=""
  local issuer_url="${ISSUER_URL:-}"
  local admin_token=""
  local admin_key_file=""
  local admin_key_id=""

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
      --admin-key-file)
        admin_key_file="${2:-}"
        shift 2
        ;;
      --admin-key-id)
        admin_key_id="${2:-}"
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
  if [[ "$issuer_url" != http://* && "$issuer_url" != https://* ]]; then
    issuer_url="$(ensure_url_scheme "$issuer_url" "http")"
  fi
  if [[ -n "$admin_key_file" || -n "$admin_key_id" ]]; then
    if [[ -z "$admin_key_file" || -z "$admin_key_id" ]]; then
      echo "invite-disable requires --admin-key-file and --admin-key-id together"
      exit 2
    fi
  fi

  local auth_details auth_mode
  auth_details="$(resolve_invite_admin_auth "$admin_token" "$admin_key_file" "$admin_key_id")"
  IFS='|' read -r auth_mode admin_token admin_key_file admin_key_id <<<"$auth_details"
  if [[ "$auth_mode" == "none" ]]; then
    echo "invite-disable requires admin auth (--admin-token or --admin-key-file + --admin-key-id)"
    exit 2
  fi

  local upsert_script="$ROOT_DIR/scripts/beta_subject_upsert.sh"
  if [[ ! -x "$upsert_script" ]]; then
    echo "missing helper script: $upsert_script"
    exit 2
  fi
  local -a upsert_cmd=(
    "$upsert_script"
    --issuer-url "$issuer_url"
    --subject "$key"
    --kind "relay-exit"
    --tier "1"
  )
  if [[ "$auth_mode" == "signed" ]]; then
    upsert_cmd+=(--admin-key-file "$admin_key_file" --admin-key-id "$admin_key_id")
  else
    upsert_cmd+=(--admin-token "$admin_token")
  fi
  "${upsert_cmd[@]}" >/dev/null
  echo "invite key disabled: $key (issuer=$issuer_url)"
}

set_env_kv() {
  local env_file="$1"
  local key="$2"
  local value="$3"
  local escaped
  escaped="$(printf '%s' "$value" | sed -e 's/[&|]/\\&/g')"
  if rg -q "^${key}=" "$env_file"; then
    sed -i -E "s|^${key}=.*$|${key}=${escaped}|" "$env_file"
  else
    printf '%s=%s\n' "$key" "$value" >>"$env_file"
  fi
}

admin_signing_status() {
  require_authority_mode "admin-signing-status"
  ensure_deps_or_die
  need_cmd go || exit 2

  local env_file="$AUTHORITY_ENV_FILE"
  if [[ ! -f "$env_file" ]]; then
    echo "admin-signing-status requires authority env file: $env_file"
    exit 2
  fi

  local key_file key_id signers_container signers_local
  key_file="$(identity_value "$env_file" "ISSUER_ADMIN_SIGNING_PRIVATE_KEY_FILE_LOCAL")"
  key_id="$(identity_value "$env_file" "ISSUER_ADMIN_SIGNING_KEY_ID")"
  signers_container="$(identity_value "$env_file" "ISSUER_ADMIN_SIGNING_KEYS_FILE")"

  if [[ -z "$key_file" ]]; then
    key_file="$DEPLOY_DIR/data/issuer/issuer_admin_signer.key"
  fi
  if [[ -z "$signers_container" ]]; then
    signers_container="/app/data/issuer_admin_signers.txt"
  fi
  signers_local="$DEPLOY_DIR/data/issuer/$(basename "$signers_container")"
  if [[ -z "$key_id" && -f "${key_file}.keyid" ]]; then
    key_id="$(tr -d '\r\n' <"${key_file}.keyid")"
  fi

  echo "authority env: $env_file"
  echo "admin_signing_key_file: $key_file"
  echo "admin_signing_key_id: ${key_id:-<unset>}"
  echo "admin_signing_pubkeys_file(local): $signers_local"
  echo "admin_signing_pubkeys_file(container): $signers_container"

  if [[ ! -f "$key_file" ]]; then
    echo "status: missing private signing key file"
    return 1
  fi
  if [[ ! -f "$signers_local" ]]; then
    echo "status: missing signer public-key file"
    return 1
  fi

  local inspect_json derived_id derived_pub
  inspect_json="$(
    cd "$ROOT_DIR"
    go run ./cmd/adminsig inspect --private-key-file "$key_file"
  )"
  derived_id="$(printf '%s\n' "$inspect_json" | rg -o '"key_id":"[^"]+"' | head -n1 | sed -E 's/^"key_id":"([^"]+)"$/\1/')"
  derived_pub="$(printf '%s\n' "$inspect_json" | rg -o '"public_key":"[^"]+"' | head -n1 | sed -E 's/^"public_key":"([^"]+)"$/\1/')"
  if [[ -z "$derived_id" || -z "$derived_pub" ]]; then
    echo "status: failed to inspect signing key"
    return 1
  fi
  echo "derived_key_id: $derived_id"

  if [[ -n "$key_id" && "$key_id" != "$derived_id" ]]; then
    echo "status: key id mismatch (env=$key_id derived=$derived_id)"
    return 1
  fi
  if ! rg -q "^${derived_id}=${derived_pub}$" "$signers_local"; then
    echo "status: signer public-key file missing derived key mapping"
    return 1
  fi
  local first_key_id key_count
  first_key_id="$(awk -F= 'NF > 0 {print $1; exit}' "$signers_local")"
  key_count="$(awk 'NF > 0 && $0 !~ /^#/ {n++} END {print n + 0}' "$signers_local")"
  echo "signing_key_history_count: $key_count"
  if [[ "$first_key_id" != "$derived_id" ]]; then
    echo "status: signer public-key file does not prioritize active key"
    return 1
  fi
  echo "status: ok"
}

admin_signing_rotate() {
  require_authority_mode "admin-signing-rotate"
  ensure_deps_or_die
  need_cmd go || exit 2

  local restart_issuer="1"
  local key_history="${EASY_NODE_ADMIN_SIGNING_KEY_HISTORY:-3}"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --restart-issuer)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          restart_issuer="${2:-}"
          shift 2
        else
          restart_issuer="1"
          shift
        fi
        ;;
      --key-history)
        key_history="${2:-}"
        shift 2
        ;;
      -h|--help|help)
        usage
        return 0
        ;;
      *)
        echo "unknown arg for admin-signing-rotate: $1"
        exit 2
        ;;
    esac
  done
  if ! [[ "$key_history" =~ ^[0-9]+$ ]] || ((key_history < 1)); then
    echo "admin-signing-rotate requires --key-history >= 1"
    exit 2
  fi

  local material key_file key_id signers_local signers_container
  material="$(ensure_admin_signing_material 1 "$key_history")"
  IFS='|' read -r key_file key_id signers_local signers_container <<<"$material"
  if [[ -z "$key_file" || -z "$key_id" || -z "$signers_container" ]]; then
    echo "admin-signing-rotate failed to generate signing material"
    exit 1
  fi

  set_env_kv "$AUTHORITY_ENV_FILE" "ISSUER_ADMIN_SIGNING_PRIVATE_KEY_FILE_LOCAL" "$key_file"
  set_env_kv "$AUTHORITY_ENV_FILE" "ISSUER_ADMIN_SIGNING_KEY_ID" "$key_id"
  set_env_kv "$AUTHORITY_ENV_FILE" "ISSUER_ADMIN_SIGNING_KEYS_FILE" "$signers_container"
  set_env_kv "$AUTHORITY_ENV_FILE" "ISSUER_ADMIN_REQUIRE_SIGNED" "1"
  set_env_kv "$AUTHORITY_ENV_FILE" "ISSUER_ADMIN_ALLOW_TOKEN" "0"
  set_env_kv "$AUTHORITY_ENV_FILE" "EASY_NODE_ADMIN_SIGNING_KEY_HISTORY" "$key_history"
  secure_file_permissions "$AUTHORITY_ENV_FILE"

  echo "admin signing key rotated"
  echo "key_id: $key_id"
  echo "key_file: $key_file"
  echo "signers_file: $signers_local"
  echo "key_history: $key_history"

  if [[ "$restart_issuer" == "1" ]]; then
    compose_with_env "$AUTHORITY_ENV_FILE" up -d issuer
    local scheme issuer_url
    scheme="http"
    if [[ "$(identity_value "$AUTHORITY_ENV_FILE" "PROD_STRICT_MODE")" == "1" ]]; then
      scheme="https"
    fi
    issuer_url="${scheme}://127.0.0.1:8082/v1/pubkeys"
    local -a tls_opts
    mapfile -t tls_opts < <(curl_tls_opts_for_url "${scheme}://127.0.0.1:8082")
    wait_http_ok_with_opts "$issuer_url" "issuer after signer rotate" 40 "${tls_opts[@]}" || {
      compose_with_env "$AUTHORITY_ENV_FILE" logs --tail=120 issuer
      exit 1
    }
    echo "issuer restarted with rotated signing key"
  fi
}

prod_preflight() {
  ensure_deps_or_die
  need_cmd openssl || exit 2
  need_cmd go || exit 2

  local days_min="14"
  local check_live="${EASY_NODE_PROD_PREFLIGHT_CHECK_LIVE:-0}"
  local timeout_sec="${EASY_NODE_PROD_PREFLIGHT_TIMEOUT_SEC:-12}"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --days-min)
        days_min="${2:-}"
        shift 2
        ;;
      --check-live)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          check_live="${2:-}"
          shift 2
        else
          check_live="1"
          shift
        fi
        ;;
      --timeout-sec)
        timeout_sec="${2:-}"
        shift 2
        ;;
      -h|--help|help)
        usage
        return 0
        ;;
      *)
        echo "unknown arg for prod-preflight: $1"
        exit 2
        ;;
    esac
  done
  if ! [[ "$days_min" =~ ^[0-9]+$ ]]; then
    echo "prod-preflight requires --days-min to be numeric"
    exit 2
  fi
  if [[ "$check_live" != "0" && "$check_live" != "1" ]]; then
    echo "prod-preflight requires --check-live to be 0 or 1"
    exit 2
  fi
  if ! [[ "$timeout_sec" =~ ^[0-9]+$ ]] || ((timeout_sec < 1)); then
    echo "prod-preflight requires --timeout-sec >= 1"
    exit 2
  fi

  local mode env_file
  mode="$(active_server_mode)"
  env_file="$(active_server_env_file)"
  if [[ ! -f "$env_file" ]]; then
    echo "prod-preflight requires an existing server env file: $env_file"
    exit 2
  fi

  local fail=0
  local check_total=0
  check_ok() {
    local msg="$1"
    check_total=$((check_total + 1))
    echo "[ok] $msg"
  }
  check_fail() {
    local msg="$1"
    check_total=$((check_total + 1))
    fail=$((fail + 1))
    echo "[fail] $msg"
  }

  local prod_strict beta_strict mtls_enable
  prod_strict="$(identity_value "$env_file" "PROD_STRICT_MODE")"
  beta_strict="$(identity_value "$env_file" "BETA_STRICT_MODE")"
  mtls_enable="$(identity_value "$env_file" "MTLS_ENABLE")"
  if [[ "$prod_strict" == "1" ]]; then
    check_ok "PROD_STRICT_MODE=1"
  else
    check_fail "PROD_STRICT_MODE must be 1"
  fi
  if [[ "$beta_strict" == "1" ]]; then
    check_ok "BETA_STRICT_MODE=1"
  else
    check_fail "BETA_STRICT_MODE must be 1"
  fi
  if [[ "$mtls_enable" == "1" ]]; then
    check_ok "MTLS_ENABLE=1"
  else
    check_fail "MTLS_ENABLE must be 1"
  fi

  local public_urls=()
  local directory_public_url entry_public_url exit_public_url
  directory_public_url="$(identity_value "$env_file" "DIRECTORY_PUBLIC_URL")"
  entry_public_url="$(identity_value "$env_file" "ENTRY_URL_PUBLIC")"
  exit_public_url="$(identity_value "$env_file" "EXIT_CONTROL_URL_PUBLIC")"
  [[ -n "$directory_public_url" ]] && public_urls+=("$directory_public_url")
  [[ -n "$entry_public_url" ]] && public_urls+=("$entry_public_url")
  [[ -n "$exit_public_url" ]] && public_urls+=("$exit_public_url")
  local u
  for u in "${public_urls[@]}"; do
    if is_https_url "$u"; then
      check_ok "HTTPS URL set: $u"
    else
      check_fail "non-HTTPS URL in prod profile: $u"
    fi
  done

  local ca_file cert_file key_file client_cert_file client_key_file
  ca_file="$(identity_value "$env_file" "EASY_NODE_MTLS_CA_FILE_LOCAL")"
  cert_file="$(identity_value "$env_file" "MTLS_CERT_FILE")"
  key_file="$(identity_value "$env_file" "MTLS_KEY_FILE")"
  client_cert_file="$(identity_value "$env_file" "EASY_NODE_MTLS_CLIENT_CERT_FILE_LOCAL")"
  client_key_file="$(identity_value "$env_file" "EASY_NODE_MTLS_CLIENT_KEY_FILE_LOCAL")"
  [[ -z "$ca_file" ]] && ca_file="$DEPLOY_DIR/tls/ca.crt"
  if [[ -z "$cert_file" ]]; then
    cert_file="$DEPLOY_DIR/tls/node.crt"
  elif [[ "$cert_file" == /app/tls/* ]]; then
    cert_file="$DEPLOY_DIR/tls/$(basename "$cert_file")"
  fi
  if [[ -z "$key_file" ]]; then
    key_file="$DEPLOY_DIR/tls/node.key"
  elif [[ "$key_file" == /app/tls/* ]]; then
    key_file="$DEPLOY_DIR/tls/$(basename "$key_file")"
  fi
  [[ -z "$client_cert_file" ]] && client_cert_file="$DEPLOY_DIR/tls/client.crt"
  [[ -z "$client_key_file" ]] && client_key_file="$DEPLOY_DIR/tls/client.key"

  local required_files=("$ca_file" "$cert_file" "$key_file" "$client_cert_file" "$client_key_file")
  local f
  for f in "${required_files[@]}"; do
    if [[ -f "$f" ]]; then
      check_ok "file exists: $f"
    else
      check_fail "missing file: $f"
    fi
  done

  local directory_admin_token entry_puzzle_secret
  directory_admin_token="$(identity_value "$env_file" "DIRECTORY_ADMIN_TOKEN")"
  entry_puzzle_secret="$(identity_value "$env_file" "ENTRY_PUZZLE_SECRET")"
  if [[ -n "$directory_admin_token" && "$directory_admin_token" != "dev-admin-token" && "${#directory_admin_token}" -ge 16 ]]; then
    check_ok "DIRECTORY_ADMIN_TOKEN configured and non-default"
  else
    check_fail "DIRECTORY_ADMIN_TOKEN must be set, non-default, and len>=16"
  fi
  if [[ -n "$entry_puzzle_secret" && "$entry_puzzle_secret" != "entry-secret-default" && "${#entry_puzzle_secret}" -ge 16 ]]; then
    check_ok "ENTRY_PUZZLE_SECRET configured and non-default"
  else
    check_fail "ENTRY_PUZZLE_SECRET must be set, non-default, and len>=16"
  fi

  local private_files=("$env_file" "$key_file" "$client_key_file")
  local pf pf_mode
  for pf in "${private_files[@]}"; do
    if [[ ! -f "$pf" ]]; then
      continue
    fi
    pf_mode="$(file_mode_octal "$pf" || true)"
    if private_file_mode_secure "$pf"; then
      check_ok "private file permissions secure (no group/other access): $pf mode=${pf_mode:-unknown}"
    else
      if [[ -n "$pf_mode" ]]; then
        check_fail "private file permissions too open: $pf mode=${pf_mode} (expected group/other=0)"
      else
        check_fail "unable to read file permissions: $pf"
      fi
    fi
  done

  local now_epoch min_epoch
  now_epoch="$(date -u +%s)"
  min_epoch=$((now_epoch + days_min * 86400))
  local certs_to_check=("$ca_file" "$cert_file" "$client_cert_file")
  for f in "${certs_to_check[@]}"; do
    if [[ ! -f "$f" ]]; then
      continue
    fi
    local not_after
    not_after="$(cert_not_after_unix "$f" || true)"
    if [[ -z "$not_after" ]]; then
      check_fail "failed to parse certificate expiry: $f"
      continue
    fi
    if ((not_after > min_epoch)); then
      local days_left
      days_left=$(((not_after - now_epoch) / 86400))
      check_ok "certificate valid >= ${days_min}d: $f (${days_left}d left)"
    else
      check_fail "certificate expires too soon (<${days_min}d): $f"
    fi
  done

  if [[ "$mode" == "authority" ]]; then
    local require_signed allow_token key_id key_path signers_container signers_local
    require_signed="$(identity_value "$env_file" "ISSUER_ADMIN_REQUIRE_SIGNED")"
    allow_token="$(identity_value "$env_file" "ISSUER_ADMIN_ALLOW_TOKEN")"
    key_id="$(identity_value "$env_file" "ISSUER_ADMIN_SIGNING_KEY_ID")"
    key_path="$(identity_value "$env_file" "ISSUER_ADMIN_SIGNING_PRIVATE_KEY_FILE_LOCAL")"
    signers_container="$(identity_value "$env_file" "ISSUER_ADMIN_SIGNING_KEYS_FILE")"
    [[ -z "$key_path" ]] && key_path="$DEPLOY_DIR/data/issuer/issuer_admin_signer.key"
    [[ -z "$signers_container" ]] && signers_container="/app/data/issuer_admin_signers.txt"
    signers_local="$DEPLOY_DIR/data/issuer/$(basename "$signers_container")"

    if [[ "$require_signed" == "1" ]]; then
      check_ok "ISSUER_ADMIN_REQUIRE_SIGNED=1"
    else
      check_fail "ISSUER_ADMIN_REQUIRE_SIGNED must be 1 on authority prod profile"
    fi
    if [[ "$allow_token" == "0" ]]; then
      check_ok "ISSUER_ADMIN_ALLOW_TOKEN=0"
    else
      check_fail "ISSUER_ADMIN_ALLOW_TOKEN must be 0 on authority prod profile"
    fi
    if [[ -n "$key_id" ]]; then
      check_ok "admin signing key id configured"
    else
      check_fail "missing ISSUER_ADMIN_SIGNING_KEY_ID"
    fi
      if [[ -f "$key_path" ]]; then
        check_ok "admin signing key exists: $key_path"
        local key_mode
        key_mode="$(file_mode_octal "$key_path" || true)"
        if private_file_mode_secure "$key_path"; then
          check_ok "admin signing private key permissions secure (no group/other access): $key_path mode=${key_mode:-unknown}"
        else
          if [[ -n "$key_mode" ]]; then
            check_fail "admin signing private key permissions too open: $key_path mode=${key_mode} (expected group/other=0)"
          else
            check_fail "unable to read admin signing private key permissions: $key_path"
          fi
        fi
        local inspect_json derived_id derived_pub
        inspect_json="$(
          cd "$ROOT_DIR"
        go run ./cmd/adminsig inspect --private-key-file "$key_path"
      )"
      derived_id="$(printf '%s\n' "$inspect_json" | rg -o '"key_id":"[^"]+"' | head -n1 | sed -E 's/^"key_id":"([^"]+)"$/\1/')"
      derived_pub="$(printf '%s\n' "$inspect_json" | rg -o '"public_key":"[^"]+"' | head -n1 | sed -E 's/^"public_key":"([^"]+)"$/\1/')"
      if [[ -n "$derived_id" && -n "$key_id" && "$derived_id" == "$key_id" ]]; then
        check_ok "admin signing key id matches private key"
      else
        check_fail "admin signing key id does not match private key"
      fi
      if [[ -f "$signers_local" && -n "$derived_id" && -n "$derived_pub" ]]; then
        if rg -q "^${derived_id}=${derived_pub}$" "$signers_local"; then
          check_ok "signers file includes active signing key mapping"
        else
          check_fail "signers file missing active signing key mapping"
        fi
      else
        check_fail "missing admin signers file: $signers_local"
      fi
    else
      check_fail "missing admin signing private key file: $key_path"
    fi
  fi

  if [[ "$check_live" == "1" ]]; then
    local live_issuer_url=""
    if [[ "$mode" == "authority" ]]; then
      if [[ -n "$directory_public_url" ]]; then
        local directory_host
        directory_host="$(host_from_url "$directory_public_url")"
        if [[ -n "$directory_host" ]]; then
          live_issuer_url="$(url_from_host_port "$directory_host" 8082)"
          if is_https_url "$directory_public_url"; then
            live_issuer_url="$(ensure_url_scheme "$live_issuer_url" "https")"
          else
            live_issuer_url="$(ensure_url_scheme "$live_issuer_url" "http")"
          fi
        fi
      fi
      if [[ -z "$live_issuer_url" ]]; then
        live_issuer_url="$(ensure_url_scheme "127.0.0.1:8082" "https")"
      fi
    else
      live_issuer_url="$(identity_value "$env_file" "CORE_ISSUER_URL")"
      if [[ -z "$live_issuer_url" ]]; then
        live_issuer_url="$(identity_value "$env_file" "ISSUER_URL")"
      fi
    fi

    check_live_endpoint() {
      local label="$1"
      local url="$2"
      local -a tls_opts=()
      mapfile -t tls_opts < <(curl_tls_opts_for_url "$url")
      if wait_http_ok_with_opts "$url" "live ${label}" "$timeout_sec" "${tls_opts[@]}"; then
        check_ok "live endpoint healthy: $label ($url)"
      else
        check_fail "live endpoint unreachable: $label ($url)"
      fi
    }

    if [[ -n "$directory_public_url" ]]; then
      check_live_endpoint "directory" "${directory_public_url%/}/v1/relays"
    fi
    if [[ -n "$entry_public_url" ]]; then
      check_live_endpoint "entry" "${entry_public_url%/}/v1/health"
    fi
    if [[ -n "$exit_public_url" ]]; then
      check_live_endpoint "exit" "${exit_public_url%/}/v1/health"
    fi
    if [[ -n "$live_issuer_url" ]]; then
      check_live_endpoint "issuer" "${live_issuer_url%/}/v1/pubkeys"
    fi

    if [[ "$mode" == "authority" && -n "$live_issuer_url" ]]; then
      local token_probe_code token_probe_body
      token_probe_body="$(mktemp)"
      local -a tls_opts=()
      mapfile -t tls_opts < <(curl_tls_opts_for_url "$live_issuer_url")
      token_probe_code="$(
        curl -sS -o "$token_probe_body" -w "%{http_code}" \
          --connect-timeout 3 --max-time 8 \
          "${tls_opts[@]}" \
          -H "X-Admin-Token: preflight-invalid-token" \
          "${live_issuer_url%/}/v1/admin/subject/get?subject=preflight-token-check" || true
      )"
      if [[ "$token_probe_code" == "401" || "$token_probe_code" == "403" ]]; then
        check_ok "issuer admin token path rejected as expected in strict mode (code=$token_probe_code)"
      else
        check_fail "issuer admin token path unexpectedly accepted/unreachable (code=${token_probe_code:-none})"
      fi
      rm -f "$token_probe_body"
    fi
  fi

  echo "prod preflight summary: checks=$check_total failures=$fail mode=$mode env=$env_file check_live=$check_live"
  if ((fail > 0)); then
    return 1
  fi
  return 0
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
  local prod_profile="${EASY_NODE_PROD_PROFILE:-0}"
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
      --prod-profile)
        if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
          prod_profile="${2:-}"
          shift 2
        else
          prod_profile="1"
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
  if [[ "$prod_profile" != "0" && "$prod_profile" != "1" ]]; then
    echo "client-test requires --prod-profile (or EASY_NODE_PROD_PROFILE) to be 0 or 1"
    exit 2
  fi
  if [[ "$prod_profile" == "1" ]]; then
    beta_profile="1"
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

  local client_url_scheme="http"
  if [[ "$prod_profile" == "1" ]]; then
    client_url_scheme="https"
  fi

  if [[ -n "$bootstrap_directory" ]]; then
    bootstrap_directory="$(ensure_url_scheme "$bootstrap_directory" "$client_url_scheme")"
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
  directory_urls="$(normalize_url_csv_scheme "$directory_urls" "$client_url_scheme")"
  issuer_url="$(ensure_url_scheme "$issuer_url" "$client_url_scheme")"
  entry_url="$(ensure_url_scheme "$entry_url" "$client_url_scheme")"
  exit_url="$(ensure_url_scheme "$exit_url" "$client_url_scheme")"

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

  local -a dir_opts issuer_opts entry_opts exit_opts
  mapfile -t dir_opts < <(curl_tls_opts_for_url "$first_dir")
  mapfile -t issuer_opts < <(curl_tls_opts_for_url "$issuer_url")
  mapfile -t entry_opts < <(curl_tls_opts_for_url "$entry_url")
  mapfile -t exit_opts < <(curl_tls_opts_for_url "$exit_url")
  wait_http_ok_with_opts "${first_dir%/}/v1/pubkeys" "directory" 8 "${dir_opts[@]}" || return 1
  wait_http_ok_with_opts "${issuer_url%/}/v1/pubkeys" "issuer" 8 "${issuer_opts[@]}" || return 1
  wait_http_ok_with_opts "${entry_url%/}/v1/health" "entry" 8 "${entry_opts[@]}" || return 1
  wait_http_ok_with_opts "${exit_url%/}/v1/health" "exit" 8 "${exit_opts[@]}" || return 1

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
  if [[ "$prod_profile" == "1" ]]; then
    echo "client test: prod profile enabled (mTLS + fail-closed strict mode)"
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
      -e "BETA_STRICT_MODE=1"
    )
  fi
  if [[ "$prod_profile" == "1" ]]; then
    run_cmd+=(
      -e "PROD_STRICT_MODE=1"
      -e "MTLS_ENABLE=1"
      -e "MTLS_CA_FILE=/app/tls/ca.crt"
      -e "MTLS_CLIENT_CERT_FILE=/app/tls/client.crt"
      -e "MTLS_CLIENT_KEY_FILE=/app/tls/client.key"
      -e "MTLS_CERT_FILE=/app/tls/client.crt"
      -e "MTLS_KEY_FILE=/app/tls/client.key"
      -e "DIRECTORY_TRUST_STRICT=1"
      -e "DIRECTORY_TRUST_TOFU=0"
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
    rotate-server-secrets)
      shift
      rotate_server_secrets "$@"
      ;;
    stop-all)
      shift
      stop_all "$@"
      ;;
    install-deps-ubuntu)
      install_deps_ubuntu
      ;;
    wg-only-check)
      wg_only_check
      ;;
    wg-only-stack-up)
      shift
      wg_only_stack_up "$@"
      ;;
    wg-only-stack-status)
      wg_only_stack_status
      ;;
    wg-only-stack-down)
      shift
      wg_only_stack_down "$@"
      ;;
    wg-only-stack-selftest)
      shift
      wg_only_stack_selftest "$@"
      ;;
    wg-only-local-test)
      shift
      wg_only_local_test "$@"
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
    admin-signing-status)
      shift
      admin_signing_status "$@"
      ;;
    admin-signing-rotate)
      shift
      admin_signing_rotate "$@"
      ;;
    prod-preflight)
      shift
      prod_preflight "$@"
      ;;
    bootstrap-mtls)
      shift
      bootstrap_mtls "$@"
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
