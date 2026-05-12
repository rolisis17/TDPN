#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/three_machine_docker_readiness.sh \
    [--run-validate [0|1]] \
    [--run-soak [0|1]] \
    [--run-peer-failover [0|1]] \
    [--peer-failover-downtime-sec N] \
    [--peer-failover-timeout-sec N] \
    [--soak-rounds N] \
    [--soak-pause-sec N] \
    [--keep-stacks [0|1]] \
    [--reset-data [0|1]] \
    [--stack-a-base-port N] \
    [--stack-b-base-port N] \
    [--docker-host-alias HOST] \
    [--subject ID] \
    [--anon-cred TOKEN] \
    [--bootstrap-directory URL] \
    [--discovery-wait-sec N] \
    [--min-sources N] \
    [--min-operators N] \
    [--federation-timeout-sec N] \
    [--timeout-sec N] \
    [--path-profile 1hop|2hop|3hop|speed|balanced|private] \
    [--distinct-operators [0|1]] \
    [--require-issuer-quorum [0|1]] \
    [--beta-profile [0|1]] \
    [--prod-profile [0|1]] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Run a local dockerized 3-machine rehearsal on one host by starting two
  independent operator stacks (A/B) and then running machine-C style
  control-plane validate/soak checks against them.

Notes:
  - This is a one-host rehearsal helper; it does not replace final real
    multi-host production signoff.
  - Real WireGuard host dataplane validation remains outside this script.
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
  elif [[ "$path" == /* ]]; then
    printf '%s' "$path"
  elif [[ "$path" =~ ^[A-Za-z]:[\\/].* ]]; then
    if command -v cygpath >/dev/null 2>&1; then
      cygpath -u "$path"
    else
      local drive="${path:0:1}"
      local tail="${path:2}"
      tail="${tail//\\//}"
      printf '/mnt/%s/%s' "${drive,,}" "${tail#/}"
    fi
  else
    printf '%s' "$ROOT_DIR/$path"
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

int_arg_or_die() {
  local name="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be an integer"
    exit 2
  fi
}

normalize_docker_path_profile() {
  local profile
  profile="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case "$profile" in
    ""|balanced|2hop|2-hop|hop2|hop-2|twohop|speed|fast)
      printf '%s\n' "2hop"
      ;;
    speed-1hop|speed1hop|fast-1hop|fast1hop|onehop|1hop|1-hop|hop1|hop-1)
      printf '%s\n' "1hop"
      ;;
    private|privacy|3hop|3-hop|hop3|hop-3|threehop)
      printf '%s\n' "3hop"
      ;;
    *)
      return 1
      ;;
  esac
}

generate_strong_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
    return
  fi
  # Fallback for minimal environments without openssl.
  LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 48
}

base64url_from_file() {
  local file="$1"
  openssl base64 -A <"$file" | tr '+/' '-_' | tr -d '=\r\n'
}

generate_entry_route_assertion_key_with_openssl() {
  local private_file="$1"
  local public_file="$2"
  local tmp_dir pem_file seed_file pub_raw_file private_raw_file seed_size pub_size private_size

  if ! command -v openssl >/dev/null 2>&1; then
    echo "missing dependency: openssl" >&2
    return 1
  fi

  tmp_dir="$(mktemp -d)"
  pem_file="$tmp_dir/entry_route_assertion.pem"
  seed_file="$tmp_dir/seed.raw"
  pub_raw_file="$tmp_dir/public.raw"
  private_raw_file="$tmp_dir/private.raw"

  if ! openssl genpkey -algorithm Ed25519 -out "$pem_file" >/dev/null 2>&1; then
    rm -rf "$tmp_dir"
    return 1
  fi
  if ! openssl pkey -in "$pem_file" -outform DER 2>/dev/null | tail -c 32 >"$seed_file"; then
    rm -rf "$tmp_dir"
    return 1
  fi
  if ! openssl pkey -in "$pem_file" -pubout -outform DER 2>/dev/null | tail -c 32 >"$pub_raw_file"; then
    rm -rf "$tmp_dir"
    return 1
  fi

  seed_size="$(wc -c <"$seed_file" | tr -d '[:space:]')"
  pub_size="$(wc -c <"$pub_raw_file" | tr -d '[:space:]')"
  if [[ "$seed_size" != "32" || "$pub_size" != "32" ]]; then
    echo "openssl Ed25519 key material had unexpected size (seed=$seed_size pub=$pub_size)" >&2
    rm -rf "$tmp_dir"
    return 1
  fi

  cat "$seed_file" "$pub_raw_file" >"$private_raw_file"
  private_size="$(wc -c <"$private_raw_file" | tr -d '[:space:]')"
  if [[ "$private_size" != "64" ]]; then
    echo "openssl Ed25519 private key material had unexpected size (private=$private_size)" >&2
    rm -rf "$tmp_dir"
    return 1
  fi

  (umask 077 && base64url_from_file "$private_raw_file" >"$private_file")
  base64url_from_file "$pub_raw_file" >"$public_file"
  rm -rf "$tmp_dir"
}

need_cmd_path_or_die() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
}

generate_entry_route_assertion_key() {
  local private_file="$1"
  local public_file="$2"
  local keygen_mode="${THREE_MACHINE_DOCKER_ENTRY_ROUTE_ASSERTION_KEYGEN:-auto}"
  local go_err go_rc

  case "$keygen_mode" in
    auto|go|openssl)
      ;;
    *)
      echo "invalid THREE_MACHINE_DOCKER_ENTRY_ROUTE_ASSERTION_KEYGEN: $keygen_mode (expected auto|go|openssl)"
      exit 2
      ;;
  esac

  rm -f "$private_file" "$public_file"
  go_err="$(mktemp)"
  go_rc=1
  if [[ "$keygen_mode" != "openssl" && -n "$(command -v go 2>/dev/null || true)" ]]; then
    set +e
    (umask 077 && go run ./cmd/adminsig gen --private-key-out "$private_file" --public-key-out "$public_file" >/dev/null) 2>"$go_err"
    go_rc=$?
    set -e
  fi

  if ((go_rc != 0)); then
    rm -f "$private_file" "$public_file"
    if [[ "$keygen_mode" == "go" ]]; then
      cat "$go_err" >&2
      rm -f "$go_err"
      echo "entry route assertion key generation failed with go" >&2
      exit 1
    fi
    if [[ -s "$go_err" ]]; then
      echo "note: host Go entry route assertion keygen unavailable; using openssl fallback" >&2
    fi
    if ! generate_entry_route_assertion_key_with_openssl "$private_file" "$public_file"; then
      rm -f "$go_err"
      echo "entry route assertion key generation failed; install openssl or a Go toolchain that can parse this repo's go.mod" >&2
      exit 1
    fi
  fi
  rm -f "$go_err"
  chmod 600 "$private_file" 2>/dev/null || true
  chmod 600 "$public_file" 2>/dev/null || true
  tr -d '\r\n[:space:]' <"$public_file"
}

print_cmd() {
  local arg
  local redact_next=0
  for arg in "$@"; do
    if ((redact_next)); then
      printf '%q ' "[REDACTED]"
      redact_next=0
      continue
    fi
    case "$arg" in
      --anon-cred|--invite-key|--campaign-subject|--subject|--token|--auth-token|--admin-token|--authorization|--bearer)
        printf '%q ' "$arg"
        redact_next=1
        continue
        ;;
      --anon-cred=*|--invite-key=*|--campaign-subject=*|--subject=*|--token=*|--auth-token=*|--admin-token=*|--authorization=*|--bearer=*)
        printf '%q ' "${arg%%=*}=[REDACTED]"
        continue
        ;;
    esac
    printf '%q ' "$arg"
  done
  printf '\n'
}

wait_http_ok() {
  local curl_bin="$1"
  local url="$2"
  local label="$3"
  local attempts="${4:-20}"
  local i
  for ((i = 1; i <= attempts; i++)); do
    if "$curl_bin" -fsS --connect-timeout 2 --max-time 4 "$url" >/dev/null 2>&1; then
      echo "[health] $label ok ($url)"
      return 0
    fi
    if ((i == 1 || i % 5 == 0)); then
      echo "[health] waiting for $label ($url) attempt=$i/$attempts"
    fi
    sleep 1
  done
  echo "[health] $label failed ($url)"
  return 1
}

upsert_issuer_subject() {
  local curl_bin="$1"
  local issuer_url="$2"
  local admin_token="$3"
  local subject="$4"
  local label="$5"
  local payload response

  if [[ -z "$subject" ]]; then
    return 0
  fi
  payload="$(
    jq -cn \
      --arg subject "$subject" \
      '{subject:$subject, kind:"client", tier:1, reputation:0, bond:0, stake:0}'
  )"

  echo "[issuer-allowlist] upserting client subject on $label"
  if response="$(
    "$curl_bin" -fsS -X POST "${issuer_url%/}/v1/admin/subject/upsert" \
      --connect-timeout 2 \
      --max-time 8 \
      -H "X-Admin-Token: ${admin_token}" \
      -H "Content-Type: application/json" \
      --data "$payload" 2>&1
  )"; then
    echo "[issuer-allowlist] $label subject upsert ok"
    return 0
  fi

  echo "[issuer-allowlist] $label subject upsert failed"
  printf '%s\n' "$response"
  return 1
}

wait_sync_peer_success_state() {
  local curl_bin="$1"
  local status_url="$2"
  local admin_token="$3"
  local expected_success="$4"
  local timeout_sec="$5"
  local i body header_cfg
  header_cfg="$(mktemp)"
  (umask 077 && printf 'header = "X-Admin-Token: %s"\n' "$admin_token" >"$header_cfg")
  for ((i = 1; i <= timeout_sec; i++)); do
    body="$("$curl_bin" -fsS --config "$header_cfg" "$status_url" 2>/dev/null || true)"
    if [[ -n "$body" ]] && printf '%s' "$body" | jq -e --argjson expected "$expected_success" '.peer.success == $expected' >/dev/null 2>&1; then
      rm -f "$header_cfg"
      return 0
    fi
    sleep 1
  done
  rm -f "$header_cfg"
  return 1
}

write_stack_override() {
  local file="$1"
  local stack_id="$2"
  local operator_id="$3"
  local issuer_id="$4"
  local base_port="$5"
  local peer_base_port="$6"
  local data_root="$7"
  local docker_host_alias="$8"
  local directory_admin_token="$9"
  local issuer_admin_token="${10}"
  local entry_route_assertion_pub="${11}"
  local trusted_entry_route_assertion_pubs="${12}"

  local dir_port issuer_port entry_port exit_port middle_port entry_udp_port exit_udp_port middle_udp_port peer_dir_port peer_issuer_port
  local entry_country exit_country middle_country
  dir_port="$((base_port + 1))"
  issuer_port="$((base_port + 2))"
  entry_port="$((base_port + 3))"
  exit_port="$((base_port + 4))"
  middle_port="$((base_port + 5))"
  entry_udp_port="$((base_port + 40))"
  exit_udp_port="$((base_port + 41))"
  middle_udp_port="$((base_port + 42))"
  peer_dir_port="$((peer_base_port + 1))"
  peer_issuer_port="$((peer_base_port + 2))"
  case "$stack_id" in
    a)
      entry_country="AU"
      exit_country="US"
      middle_country="NL"
      ;;
    *)
      entry_country="CA"
      exit_country="DE"
      middle_country="SE"
      ;;
  esac

  cat >"$file" <<EOF_YAML
services:
  directory:
    extra_hosts:
      - "host.docker.internal:host-gateway"
    environment:
      DIRECTORY_PUBLIC_URL: "http://${docker_host_alias}:${dir_port}"
      DIRECTORY_OPERATOR_ID: "${operator_id}"
      ENTRY_RELAY_ID: "entry-${stack_id}"
      EXIT_RELAY_ID: "exit-${stack_id}"
      ENTRY_ROUTE_ASSERTION_PUBLIC_KEY: "${entry_route_assertion_pub}"
      ENTRY_URL: "http://${docker_host_alias}:${entry_port}"
      EXIT_CONTROL_URL: "http://${docker_host_alias}:${exit_port}"
      ENTRY_ENDPOINT: "${docker_host_alias}:${entry_udp_port}"
      EXIT_ENDPOINT: "${docker_host_alias}:${exit_udp_port}"
      ENTRY_COUNTRY_CODE: "${entry_country}"
      EXIT_COUNTRY_CODE: "${exit_country}"
      MIDDLE_RELAY_ENABLED: "${middle_relay_enabled}"
      MIDDLE_RELAY_ID: "middle-${stack_id}"
      MIDDLE_OPERATOR_ID: "${operator_id}-middle"
      MIDDLE_ENDPOINT_PUBLIC: "${docker_host_alias}:${middle_udp_port}"
      MIDDLE_CONTROL_URL_PUBLIC: "http://${docker_host_alias}:${middle_port}"
      MIDDLE_COUNTRY_CODE: "${middle_country}"
      DIRECTORY_PEERS: "http://${docker_host_alias}:${peer_dir_port}"
      DIRECTORY_SYNC_SEC: "2"
      DIRECTORY_GOSSIP_SEC: "2"
      DIRECTORY_PEER_DISCOVERY: "0"
      DIRECTORY_ISSUER_TRUST_URLS: "http://${docker_host_alias}:${issuer_port},http://${docker_host_alias}:${peer_issuer_port}"
      DIRECTORY_PROVIDER_ISSUER_URLS: "http://${docker_host_alias}:${issuer_port},http://${docker_host_alias}:${peer_issuer_port}"
      DIRECTORY_MIN_OPERATORS: "1"
      DIRECTORY_MIN_RELAY_VOTES: "1"
      DIRECTORY_ADMIN_TOKEN: "${directory_admin_token}"
      DIRECTORY_ALLOW_DANGEROUS_INSECURE_ADMIN_PUBLIC_BIND: "1"
      DIRECTORY_ALLOW_INSECURE_CONTROL_URL_HTTP: "1"
      DIRECTORY_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS: "1"
      DIRECTORY_ALLOW_DANGEROUS_ISSUER_TRUST_WITHOUT_ANCHORS: "1"
    volumes:
      - "${data_root}/${stack_id}/directory:/app/data"
      - ./tls:/app/tls:ro

  issuer:
    extra_hosts:
      - "host.docker.internal:host-gateway"
    environment:
      ISSUER_ID: "${issuer_id}"
      ISSUER_ADMIN_TOKEN: "${issuer_admin_token}"
      ISSUER_ADMIN_ALLOW_TOKEN: "1"
      ISSUER_ADMIN_REQUIRE_SIGNED: "0"
      ISSUER_ALLOW_DANGEROUS_INSECURE_TOKEN_AUTH_PUBLIC_BIND: "1"
      ISSUER_ALLOW_DANGEROUS_PUBLIC_ISSUE_WITHOUT_PAYMENT_PROOF: "1"
    volumes:
      - "${data_root}/${stack_id}/issuer:/app/data"
      - ./tls:/app/tls:ro

  entry-exit:
    extra_hosts:
      - "host.docker.internal:host-gateway"
    environment:
      DIRECTORY_URL: "http://directory:8081"
      DIRECTORY_URLS: "http://${docker_host_alias}:${dir_port},http://${docker_host_alias}:${peer_dir_port}"
      DIRECTORY_MIN_SOURCES: "1"
      DIRECTORY_MIN_OPERATORS: "1"
      ISSUER_URL: "http://issuer:8082"
      ISSUER_URLS: "http://${docker_host_alias}:${issuer_port},http://${docker_host_alias}:${peer_issuer_port}"
      ENTRY_RELAY_ID: "entry-${stack_id}"
      EXIT_RELAY_ID: "exit-${stack_id}"
      ENTRY_OPERATOR_ID: "${operator_id}"
      EXIT_OPERATOR_ID: "${operator_id}"
      ENTRY_LIVE_WG_MODE: "0"
      EXIT_LIVE_WG_MODE: "0"
      WG_BACKEND: "noop"
      ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR: "0"
      ENTRY_ALLOW_INSECURE_CONTROL_URL_HTTP: "1"
      EXIT_ALLOW_INSECURE_CONTROL_URL_HTTP: "1"
      ENTRY_ALLOW_DANGEROUS_INSECURE_PUBLIC_BIND: "1"
      EXIT_ALLOW_DANGEROUS_INSECURE_PUBLIC_BIND: "1"
      ENTRY_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS: "1"
      EXIT_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS: "1"
      ENTRY_ROUTE_ASSERTION_PRIVATE_KEY_FILE: "/app/data/entry_route_assertion.key"
      EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS: "${trusted_entry_route_assertion_pubs}"
    volumes:
      - "${data_root}/${stack_id}/entry-exit:/app/data"
      - ./tls:/app/tls:ro
EOF_YAML
}

run_validate="1"
run_soak="1"
run_peer_failover="0"
peer_failover_downtime_sec="8"
peer_failover_timeout_sec="45"
soak_rounds="6"
soak_pause_sec="3"
keep_stacks="0"
reset_data="1"
stack_a_base_port="18080"
stack_b_base_port="28080"
docker_host_alias="${THREE_MACHINE_DOCKER_HOST_ALIAS:-host.docker.internal}"
client_subject=""
client_anon_cred=""
client_min_selection_lines="${THREE_MACHINE_DOCKER_CLIENT_MIN_SELECTION_LINES:-1}"
client_min_entry_operators_explicit="0"
if [[ -n "${THREE_MACHINE_DOCKER_CLIENT_MIN_ENTRY_OPERATORS+x}" ]]; then
  client_min_entry_operators_explicit="1"
fi
client_min_entry_operators="${THREE_MACHINE_DOCKER_CLIENT_MIN_ENTRY_OPERATORS:-1}"
client_min_exit_operators="${THREE_MACHINE_DOCKER_CLIENT_MIN_EXIT_OPERATORS:-1}"
bootstrap_directory=""
discovery_wait_sec="${THREE_MACHINE_DISCOVERY_WAIT_SEC:-12}"
min_sources="2"
min_operators="2"
federation_timeout_sec="90"
validate_timeout_sec="45"
path_profile="balanced"
distinct_operators="1"
require_issuer_quorum="1"
beta_profile="1"
prod_profile="0"
summary_json=""
print_summary_json="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-validate)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_validate="${2:-}"
        shift 2
      else
        run_validate="1"
        shift
      fi
      ;;
    --run-soak)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_soak="${2:-}"
        shift 2
      else
        run_soak="1"
        shift
      fi
      ;;
    --run-peer-failover)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_peer_failover="${2:-}"
        shift 2
      else
        run_peer_failover="1"
        shift
      fi
      ;;
    --peer-failover-downtime-sec)
      peer_failover_downtime_sec="${2:-}"
      shift 2
      ;;
    --peer-failover-timeout-sec)
      peer_failover_timeout_sec="${2:-}"
      shift 2
      ;;
    --soak-rounds)
      soak_rounds="${2:-}"
      shift 2
      ;;
    --soak-pause-sec)
      soak_pause_sec="${2:-}"
      shift 2
      ;;
    --keep-stacks)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        keep_stacks="${2:-}"
        shift 2
      else
        keep_stacks="1"
        shift
      fi
      ;;
    --reset-data)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        reset_data="${2:-}"
        shift 2
      else
        reset_data="1"
        shift
      fi
      ;;
    --stack-a-base-port)
      stack_a_base_port="${2:-}"
      shift 2
      ;;
    --stack-b-base-port)
      stack_b_base_port="${2:-}"
      shift 2
      ;;
    --docker-host-alias)
      docker_host_alias="${2:-}"
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
    --bootstrap-directory)
      bootstrap_directory="${2:-}"
      shift 2
      ;;
    --discovery-wait-sec)
      discovery_wait_sec="${2:-}"
      shift 2
      ;;
    --min-sources)
      min_sources="${2:-}"
      shift 2
      ;;
    --min-operators)
      min_operators="${2:-}"
      shift 2
      ;;
    --federation-timeout-sec)
      federation_timeout_sec="${2:-}"
      shift 2
      ;;
    --timeout-sec)
      validate_timeout_sec="${2:-}"
      shift 2
      ;;
    --path-profile)
      path_profile="${2:-}"
      shift 2
      ;;
    --distinct-operators)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        distinct_operators="${2:-}"
        shift 2
      else
        distinct_operators="1"
        shift
      fi
      ;;
    --require-issuer-quorum)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_issuer_quorum="${2:-}"
        shift 2
      else
        require_issuer_quorum="1"
        shift
      fi
      ;;
    --beta-profile)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        beta_profile="${2:-}"
        shift 2
      else
        beta_profile="1"
        shift
      fi
      ;;
    --prod-profile)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        prod_profile="${2:-}"
        shift 2
      else
        prod_profile="1"
        shift
      fi
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_summary_json="${2:-}"
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

bool_arg_or_die "--run-validate" "$run_validate"
bool_arg_or_die "--run-soak" "$run_soak"
bool_arg_or_die "--run-peer-failover" "$run_peer_failover"
bool_arg_or_die "--keep-stacks" "$keep_stacks"
bool_arg_or_die "--reset-data" "$reset_data"
bool_arg_or_die "--distinct-operators" "$distinct_operators"
bool_arg_or_die "--require-issuer-quorum" "$require_issuer_quorum"
bool_arg_or_die "--beta-profile" "$beta_profile"
bool_arg_or_die "--prod-profile" "$prod_profile"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
int_arg_or_die "--soak-rounds" "$soak_rounds"
int_arg_or_die "--soak-pause-sec" "$soak_pause_sec"
int_arg_or_die "--peer-failover-downtime-sec" "$peer_failover_downtime_sec"
int_arg_or_die "--peer-failover-timeout-sec" "$peer_failover_timeout_sec"
int_arg_or_die "--stack-a-base-port" "$stack_a_base_port"
int_arg_or_die "--stack-b-base-port" "$stack_b_base_port"
int_arg_or_die "--discovery-wait-sec" "$discovery_wait_sec"
int_arg_or_die "THREE_MACHINE_DOCKER_CLIENT_MIN_SELECTION_LINES" "$client_min_selection_lines"
int_arg_or_die "THREE_MACHINE_DOCKER_CLIENT_MIN_ENTRY_OPERATORS" "$client_min_entry_operators"
int_arg_or_die "THREE_MACHINE_DOCKER_CLIENT_MIN_EXIT_OPERATORS" "$client_min_exit_operators"
int_arg_or_die "--min-sources" "$min_sources"
int_arg_or_die "--min-operators" "$min_operators"
int_arg_or_die "--federation-timeout-sec" "$federation_timeout_sec"
int_arg_or_die "--timeout-sec" "$validate_timeout_sec"

normalized_path_profile="$(normalize_docker_path_profile "$path_profile")" || {
  echo "--path-profile must be one of: 1hop, 2hop, 3hop, speed, balanced, private (legacy aliases: fast, privacy)"
  exit 2
}
middle_relay_enabled="0"
if [[ "$normalized_path_profile" == "3hop" ]]; then
  middle_relay_enabled="1"
fi
if [[ "$normalized_path_profile" == "1hop" && ( "$beta_profile" != "0" || "$prod_profile" != "0" ) ]]; then
  beta_profile="0"
  prod_profile="0"
fi
if [[ "$normalized_path_profile" == "1hop" && "$client_min_entry_operators_explicit" != "1" ]]; then
  client_min_entry_operators="0"
fi

if [[ -n "$client_subject" && -n "$client_anon_cred" ]]; then
  echo "set only one of --subject or --anon-cred"
  exit 2
fi
client_subject="$(trim "$client_subject")"
client_anon_cred="$(trim "$client_anon_cred")"
if [[ -z "$client_subject" && -z "$client_anon_cred" ]]; then
  client_subject="$(trim "${THREE_MACHINE_DOCKER_DEFAULT_SUBJECT:-docker-rehearsal-client}")"
fi
if [[ -n "$bootstrap_directory" ]]; then
  bootstrap_directory="$(trim "$bootstrap_directory")"
fi
if [[ -z "$docker_host_alias" ]]; then
  echo "--docker-host-alias must be non-empty"
  exit 2
fi
if ((stack_a_base_port < 1024 || stack_b_base_port < 1024)); then
  echo "--stack-a-base-port and --stack-b-base-port must be >= 1024"
  exit 2
fi
if ((client_min_selection_lines < 1 || client_min_exit_operators < 1)); then
  echo "THREE_MACHINE_DOCKER_CLIENT_MIN_SELECTION_LINES and THREE_MACHINE_DOCKER_CLIENT_MIN_EXIT_OPERATORS must be >= 1"
  exit 2
fi
if ((client_min_entry_operators < 0)); then
  echo "THREE_MACHINE_DOCKER_CLIENT_MIN_ENTRY_OPERATORS must be >= 0"
  exit 2
fi
if [[ "$prod_profile" == "1" ]]; then
  echo "three-machine-docker-readiness currently supports --prod-profile 0 only"
  echo "use true multi-host prod signoff for final production gate."
  exit 2
fi

docker_bin="${THREE_MACHINE_DOCKER_DOCKER_BIN:-docker}"
curl_bin="${THREE_MACHINE_DOCKER_CURL_BIN:-curl}"
validate_script="${THREE_MACHINE_DOCKER_VALIDATE_SCRIPT:-$ROOT_DIR/scripts/integration_3machine_beta_validate.sh}"
soak_script="${THREE_MACHINE_DOCKER_SOAK_SCRIPT:-$ROOT_DIR/scripts/integration_3machine_beta_soak.sh}"
deploy_dir="${THREE_MACHINE_DOCKER_DEPLOY_DIR:-$ROOT_DIR/deploy}"
compose_file="${THREE_MACHINE_DOCKER_COMPOSE_FILE:-$deploy_dir/docker-compose.yml}"
project_a="${THREE_MACHINE_DOCKER_PROJECT_A:-pn3a}"
project_b="${THREE_MACHINE_DOCKER_PROJECT_B:-pn3b}"
if [[ -n "${THREE_MACHINE_DOCKER_DATA_ROOT:-}" ]]; then
  data_root="$(abs_path "$THREE_MACHINE_DOCKER_DATA_ROOT")"
elif [[ -n "${XDG_STATE_HOME:-}" ]]; then
  data_root="$(abs_path "$XDG_STATE_HOME/privacynode/docker_three_machine")"
elif [[ -n "${HOME:-}" ]]; then
  data_root="$(abs_path "$HOME/.local/state/privacynode/docker_three_machine")"
else
  data_root="$(abs_path "$ROOT_DIR/deploy/data/docker_three_machine")"
fi
compose_up_max_attempts="${THREE_MACHINE_DOCKER_COMPOSE_UP_MAX_ATTEMPTS:-3}"
compose_up_initial_backoff_sec="${THREE_MACHINE_DOCKER_COMPOSE_UP_INITIAL_BACKOFF_SEC:-2}"

need_cmd_path_or_die "$docker_bin"
need_cmd_path_or_die "$curl_bin"
need_cmd_path_or_die rg
need_cmd_path_or_die jq
need_cmd_path_or_die date
if [[ ! -x "$validate_script" ]]; then
  echo "validate script not executable: $validate_script"
  exit 2
fi
if [[ ! -x "$soak_script" ]]; then
  echo "soak script not executable: $soak_script"
  exit 2
fi
if [[ ! -f "$compose_file" ]]; then
  echo "compose file not found: $compose_file"
  exit 2
fi
if [[ ! -d "$deploy_dir" ]]; then
  echo "deploy directory not found: $deploy_dir"
  exit 2
fi
int_arg_or_die "THREE_MACHINE_DOCKER_COMPOSE_UP_MAX_ATTEMPTS" "$compose_up_max_attempts"
int_arg_or_die "THREE_MACHINE_DOCKER_COMPOSE_UP_INITIAL_BACKOFF_SEC" "$compose_up_initial_backoff_sec"
if ((compose_up_max_attempts < 1)); then
  echo "THREE_MACHINE_DOCKER_COMPOSE_UP_MAX_ATTEMPTS must be >= 1"
  exit 2
fi

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
log_dir="${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
mkdir -p "$log_dir"
summary_log="$log_dir/three_machine_docker_readiness_${run_stamp}.log"
if [[ -z "$summary_json" ]]; then
  summary_json="$log_dir/three_machine_docker_readiness_${run_stamp}.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
mkdir -p "$(dirname "$summary_json")"

runtime_dir="$log_dir/three_machine_docker_runtime_${run_stamp}"
mkdir -p "$runtime_dir"
chmod 700 "$runtime_dir" 2>/dev/null || true
override_a="$runtime_dir/compose_stack_a.override.yml"
override_b="$runtime_dir/compose_stack_b.override.yml"
env_a="$runtime_dir/compose_stack_a.env"
env_b="$runtime_dir/compose_stack_b.env"
steps_file="$(mktemp)"
trap 'rm -f "$steps_file"' EXIT

exec > >(tee -a "$summary_log") 2>&1

record_step() {
  local step_id="$1"
  local status="$2"
  local rc="$3"
  local note="${4:-}"
  local command="${5:-}"
  jq -n \
    --arg step_id "$step_id" \
    --arg status "$status" \
    --arg note "$note" \
    --arg command "$command" \
    --argjson rc "$rc" \
    '{
      "step_id": $step_id,
      "status": $status,
      "rc": $rc,
      "note": $note,
      "command": $command
    }' >>"$steps_file"
}

compose_cmd() {
  local project="$1"
  local override_file="$2"
  local env_file="$3"
  shift 3
  (
    cd "$deploy_dir"
    "$docker_bin" compose --env-file "$env_file" -p "$project" -f "$compose_file" -f "$override_file" "$@"
  )
}

compose_up_stack() {
  local project="$1"
  local override_file="$2"
  local env_file="$3"
  compose_cmd "$project" "$override_file" "$env_file" up -d --build "${compose_services[@]}"
}

compose_down_stack() {
  local project="$1"
  local override_file="$2"
  local env_file="$3"
  compose_cmd "$project" "$override_file" "$env_file" down --remove-orphans
}

entry_route_assertion_logs_ok() {
  local project="$1"
  local override_file="$2"
  local env_file="$3"
  local label="$4"
  local logs

  if ! logs="$(compose_cmd "$project" "$override_file" "$env_file" logs --no-color entry-exit 2>&1)"; then
    echo "[route-assertion] $label entry-exit logs unavailable"
    printf '%s\n' "$logs"
    return 1
  fi
  if printf '%s' "$logs" | rg -qi 'entry route assertion signing disabled'; then
    echo "[route-assertion] $label entry-exit log reports signing disabled"
    printf '%s\n' "$logs" | rg -ni -C 2 'entry route assertion signing disabled' || true
    return 1
  fi
  return 0
}

compose_up_retryable_failure() {
  local output_file="$1"
  rg -qi \
    'server misbehaving|temporary failure in name resolution|tls handshake timeout|i/o timeout|context deadline exceeded|connection reset by peer|failed to do request|request canceled while waiting for connection' \
    "$output_file"
}

compose_up_stack_with_retry() {
  local step_id="$1"
  local project="$2"
  local override_file="$3"
  local env_file="$4"
  local compose_cmd_print="$5"
  local attempt=1
  local backoff_sec="$compose_up_initial_backoff_sec"
  local output_file=""
  local rc=1

  while ((attempt <= compose_up_max_attempts)); do
    output_file="$(mktemp)"
    if compose_up_stack "$project" "$override_file" "$env_file" >"$output_file" 2>&1; then
      cat "$output_file"
      rm -f "$output_file"
      if ((attempt > 1)); then
        record_step "$step_id" "pass" 0 "docker compose up recovered after retry attempt=${attempt}/${compose_up_max_attempts}" "$compose_cmd_print"
      else
        record_step "$step_id" "pass" 0 "" "$compose_cmd_print"
      fi
      return 0
    else
      rc=$?
    fi
    cat "$output_file"
    if ((attempt < compose_up_max_attempts)) && compose_up_retryable_failure "$output_file"; then
      echo "[docker-retry] step=$step_id attempt=${attempt}/${compose_up_max_attempts} rc=$rc transient_failure=true next_backoff_sec=$backoff_sec"
      rm -f "$output_file"
      if ((backoff_sec > 0)); then
        sleep "$backoff_sec"
      fi
      backoff_sec=$((backoff_sec * 2))
      attempt=$((attempt + 1))
      continue
    fi
    if compose_up_retryable_failure "$output_file"; then
      record_step "$step_id" "fail" "$rc" "docker compose up failed after retryable errors attempts=${attempt}/${compose_up_max_attempts}" "$compose_cmd_print"
    else
      record_step "$step_id" "fail" "$rc" "docker compose up failed" "$compose_cmd_print"
    fi
    rm -f "$output_file"
    return "$rc"
  done

  return "$rc"
}

stack_a_dir_port="$((stack_a_base_port + 1))"
stack_a_issuer_port="$((stack_a_base_port + 2))"
stack_a_entry_port="$((stack_a_base_port + 3))"
stack_a_exit_port="$((stack_a_base_port + 4))"
stack_a_middle_port="$((stack_a_base_port + 5))"
stack_a_entry_udp_port="$((stack_a_base_port + 40))"
stack_a_exit_udp_port="$((stack_a_base_port + 41))"
stack_a_middle_udp_port="$((stack_a_base_port + 42))"
stack_b_dir_port="$((stack_b_base_port + 1))"
stack_b_issuer_port="$((stack_b_base_port + 2))"
stack_b_entry_port="$((stack_b_base_port + 3))"
stack_b_exit_port="$((stack_b_base_port + 4))"
stack_b_middle_port="$((stack_b_base_port + 5))"
stack_b_entry_udp_port="$((stack_b_base_port + 40))"
stack_b_exit_udp_port="$((stack_b_base_port + 41))"
stack_b_middle_udp_port="$((stack_b_base_port + 42))"

directory_a_url="http://127.0.0.1:${stack_a_dir_port}"
directory_b_url="http://127.0.0.1:${stack_b_dir_port}"
issuer_url="http://127.0.0.1:${stack_a_issuer_port}"
issuer_a_url="$issuer_url"
issuer_b_url="http://127.0.0.1:${stack_b_issuer_port}"
entry_url="http://127.0.0.1:${stack_a_entry_port}"
exit_url="http://127.0.0.1:${stack_a_exit_port}"
middle_a_url="http://127.0.0.1:${stack_a_middle_port}"
middle_b_url="http://127.0.0.1:${stack_b_middle_port}"

if [[ "$reset_data" == "1" ]]; then
  rm -rf "$data_root/a" "$data_root/b"
fi
mkdir -p \
  "$data_root/a/directory" "$data_root/a/issuer" "$data_root/a/entry-exit" \
  "$data_root/a/middle" \
  "$data_root/b/directory" "$data_root/b/issuer" "$data_root/b/entry-exit" \
  "$data_root/b/middle"

directory_admin_token_a="${THREE_MACHINE_DOCKER_DIRECTORY_ADMIN_TOKEN_A:-$(generate_strong_token)}"
directory_admin_token_b="${THREE_MACHINE_DOCKER_DIRECTORY_ADMIN_TOKEN_B:-$(generate_strong_token)}"
issuer_admin_token_a="${THREE_MACHINE_DOCKER_ISSUER_ADMIN_TOKEN_A:-$(generate_strong_token)}"
issuer_admin_token_b="${THREE_MACHINE_DOCKER_ISSUER_ADMIN_TOKEN_B:-$(generate_strong_token)}"
entry_puzzle_secret_a="${THREE_MACHINE_DOCKER_ENTRY_PUZZLE_SECRET_A:-$(generate_strong_token)}"
entry_puzzle_secret_b="${THREE_MACHINE_DOCKER_ENTRY_PUZZLE_SECRET_B:-$(generate_strong_token)}"
entry_exit_user="${THREE_MACHINE_DOCKER_ENTRY_EXIT_USER:-}"
if [[ -z "$entry_exit_user" ]]; then
  if ! command -v id >/dev/null 2>&1; then
    echo "missing required command: id"
    exit 2
  fi
  entry_exit_user="$(id -u):$(id -g)"
fi
if ! [[ "$entry_exit_user" =~ ^[0-9]+:[0-9]+$ ]]; then
  echo "THREE_MACHINE_DOCKER_ENTRY_EXIT_USER must be numeric UID:GID so the container can read generated route assertion keys"
  exit 2
fi

entry_route_assertion_key_a="$data_root/a/entry-exit/entry_route_assertion.key"
entry_route_assertion_key_b="$data_root/b/entry-exit/entry_route_assertion.key"
entry_route_assertion_pub_file_a="$runtime_dir/entry_route_assertion_a.key.pub"
entry_route_assertion_pub_file_b="$runtime_dir/entry_route_assertion_b.key.pub"
entry_route_assertion_pub_a="$(generate_entry_route_assertion_key "$entry_route_assertion_key_a" "$entry_route_assertion_pub_file_a")"
entry_route_assertion_pub_b="$(generate_entry_route_assertion_key "$entry_route_assertion_key_b" "$entry_route_assertion_pub_file_b")"
trusted_entry_route_assertion_pubs="${entry_route_assertion_pub_a},${entry_route_assertion_pub_b}"
stack_data_plane_mode="json"
if [[ "$beta_profile" == "1" || "$prod_profile" == "1" ]]; then
  stack_data_plane_mode="opaque"
fi

write_stack_override "$override_a" "a" "op-docker-a" "issuer-docker-a" "$stack_a_base_port" "$stack_b_base_port" "$data_root" "$docker_host_alias" "$directory_admin_token_a" "$issuer_admin_token_a" "$entry_route_assertion_pub_a" "$trusted_entry_route_assertion_pubs"
write_stack_override "$override_b" "b" "op-docker-b" "issuer-docker-b" "$stack_b_base_port" "$stack_a_base_port" "$data_root" "$docker_host_alias" "$directory_admin_token_b" "$issuer_admin_token_b" "$entry_route_assertion_pub_b" "$trusted_entry_route_assertion_pubs"

cat >"$env_a" <<EOF_ENV_A
DIRECTORY_PUBLISHED_BIND_ADDR=0.0.0.0
ISSUER_PUBLISHED_BIND_ADDR=0.0.0.0
ENTRY_PUBLISHED_BIND_ADDR=0.0.0.0
EXIT_PUBLISHED_BIND_ADDR=0.0.0.0
MIDDLE_PUBLISHED_BIND_ADDR=0.0.0.0
ENTRY_UDP_PUBLISHED_BIND_ADDR=0.0.0.0
EXIT_UDP_PUBLISHED_BIND_ADDR=0.0.0.0
MIDDLE_UDP_PUBLISHED_BIND_ADDR=0.0.0.0
DIRECTORY_PUBLISHED_PORT=$stack_a_dir_port
ISSUER_PUBLISHED_PORT=$stack_a_issuer_port
ENTRY_PUBLISHED_PORT=$stack_a_entry_port
EXIT_PUBLISHED_PORT=$stack_a_exit_port
MIDDLE_PUBLISHED_PORT=$stack_a_middle_port
ENTRY_UDP_PUBLISHED_PORT=$stack_a_entry_udp_port
EXIT_UDP_PUBLISHED_PORT=$stack_a_exit_udp_port
MIDDLE_UDP_PUBLISHED_PORT=$stack_a_middle_udp_port
ENTRY_ENDPOINT_PUBLIC=${docker_host_alias}:$stack_a_entry_udp_port
EXIT_ENDPOINT_PUBLIC=${docker_host_alias}:$stack_a_exit_udp_port
ENTRY_PUZZLE_SECRET=$entry_puzzle_secret_a
DATA_PLANE_MODE=$stack_data_plane_mode
BETA_STRICT_MODE=0
PROD_STRICT_MODE=0
ENTRY_EXIT_USER=$entry_exit_user
EOF_ENV_A

cat >"$env_b" <<EOF_ENV_B
DIRECTORY_PUBLISHED_BIND_ADDR=0.0.0.0
ISSUER_PUBLISHED_BIND_ADDR=0.0.0.0
ENTRY_PUBLISHED_BIND_ADDR=0.0.0.0
EXIT_PUBLISHED_BIND_ADDR=0.0.0.0
MIDDLE_PUBLISHED_BIND_ADDR=0.0.0.0
ENTRY_UDP_PUBLISHED_BIND_ADDR=0.0.0.0
EXIT_UDP_PUBLISHED_BIND_ADDR=0.0.0.0
MIDDLE_UDP_PUBLISHED_BIND_ADDR=0.0.0.0
DIRECTORY_PUBLISHED_PORT=$stack_b_dir_port
ISSUER_PUBLISHED_PORT=$stack_b_issuer_port
ENTRY_PUBLISHED_PORT=$stack_b_entry_port
EXIT_PUBLISHED_PORT=$stack_b_exit_port
MIDDLE_PUBLISHED_PORT=$stack_b_middle_port
ENTRY_UDP_PUBLISHED_PORT=$stack_b_entry_udp_port
EXIT_UDP_PUBLISHED_PORT=$stack_b_exit_udp_port
MIDDLE_UDP_PUBLISHED_PORT=$stack_b_middle_udp_port
ENTRY_ENDPOINT_PUBLIC=${docker_host_alias}:$stack_b_entry_udp_port
EXIT_ENDPOINT_PUBLIC=${docker_host_alias}:$stack_b_exit_udp_port
ENTRY_PUZZLE_SECRET=$entry_puzzle_secret_b
DATA_PLANE_MODE=$stack_data_plane_mode
BETA_STRICT_MODE=0
PROD_STRICT_MODE=0
ENTRY_EXIT_USER=$entry_exit_user
EOF_ENV_B

chmod 600 "$override_a" "$override_b" "$env_a" "$env_b" "$entry_route_assertion_pub_file_a" "$entry_route_assertion_pub_file_b" 2>/dev/null || true

echo "[three-machine-docker-readiness] starting local docker rehearsal"
echo "[three-machine-docker-readiness] stack_a directory=$directory_a_url issuer=$issuer_a_url entry=$entry_url exit=$exit_url"
echo "[three-machine-docker-readiness] stack_b directory=$directory_b_url issuer=$issuer_b_url entry=http://127.0.0.1:${stack_b_entry_port} exit=http://127.0.0.1:${stack_b_exit_port}"
if [[ "$middle_relay_enabled" == "1" ]]; then
  echo "[three-machine-docker-readiness] middle relays enabled for path-profile=$path_profile"
fi
echo "[three-machine-docker-readiness] overrides: $override_a $override_b"
echo "[three-machine-docker-readiness] env-files: $env_a $env_b"

status="pass"
final_rc=0
failed_step=""
stack_a_up=0
stack_b_up=0
compose_services=(directory issuer entry-exit)
if [[ "$middle_relay_enabled" == "1" ]]; then
  compose_services+=(middle)
fi

up_a_cmd_print="$(print_cmd "$docker_bin" compose --env-file "$env_a" -p "$project_a" -f "$compose_file" -f "$override_a" up -d --build "${compose_services[@]}")"
if compose_up_stack_with_retry "stack_a_up" "$project_a" "$override_a" "$env_a" "$up_a_cmd_print"; then
  stack_a_up=1
else
  rc=$?
  status="fail"
  final_rc=$rc
  failed_step="stack_a_up"
fi

if [[ "$status" == "pass" ]]; then
  up_b_cmd_print="$(print_cmd "$docker_bin" compose --env-file "$env_b" -p "$project_b" -f "$compose_file" -f "$override_b" up -d --build "${compose_services[@]}")"
  if compose_up_stack_with_retry "stack_b_up" "$project_b" "$override_b" "$env_b" "$up_b_cmd_print"; then
    stack_b_up=1
  else
    rc=$?
    status="fail"
    final_rc=$rc
    failed_step="stack_b_up"
  fi
fi

if [[ "$status" == "pass" ]]; then
  if wait_http_ok "$curl_bin" "${directory_a_url}/v1/relays" "directory A" 30 &&
    wait_http_ok "$curl_bin" "${directory_b_url}/v1/relays" "directory B" 30 &&
    wait_http_ok "$curl_bin" "${issuer_a_url}/v1/pubkeys" "issuer A" 30 &&
    wait_http_ok "$curl_bin" "${issuer_b_url}/v1/pubkeys" "issuer B" 30 &&
    wait_http_ok "$curl_bin" "${entry_url}/v1/health" "entry A" 30 &&
    wait_http_ok "$curl_bin" "${exit_url}/v1/health" "exit A" 30 &&
    { [[ "$middle_relay_enabled" != "1" ]] || wait_http_ok "$curl_bin" "${middle_a_url}/v1/health" "middle A" 30; } &&
    { [[ "$middle_relay_enabled" != "1" ]] || wait_http_ok "$curl_bin" "${middle_b_url}/v1/health" "middle B" 30; }; then
    if entry_route_assertion_logs_ok "$project_a" "$override_a" "$env_a" "stack A" &&
      entry_route_assertion_logs_ok "$project_b" "$override_b" "$env_b" "stack B"; then
      record_step "health" "pass" 0
    else
      status="fail"
      final_rc=1
      failed_step="health"
      record_step "health" "fail" 1 "entry route assertion log check failed"
    fi
  else
    rc=$?
    status="fail"
    final_rc=$rc
    failed_step="health"
    record_step "health" "fail" "$rc" "one or more endpoints failed health checks"
  fi
fi

if [[ "$status" == "pass" ]]; then
  if [[ -n "$client_subject" ]]; then
    if upsert_issuer_subject "$curl_bin" "$issuer_a_url" "$issuer_admin_token_a" "$client_subject" "issuer A" &&
      upsert_issuer_subject "$curl_bin" "$issuer_b_url" "$issuer_admin_token_b" "$client_subject" "issuer B"; then
      record_step "issuer_allowlist" "pass" 0 "client subject allowlisted on both issuers"
    else
      rc=$?
      status="fail"
      final_rc=$rc
      failed_step="issuer_allowlist"
      record_step "issuer_allowlist" "fail" "$rc" "client subject allowlist upsert failed"
    fi
  else
    record_step "issuer_allowlist" "skip" 0 "no client subject configured"
  fi
fi

if [[ "$run_validate" == "1" ]]; then
  if [[ "$status" == "pass" ]]; then
    validate_cmd=(
      "$validate_script"
      --directory-a "$directory_a_url"
      --directory-b "$directory_b_url"
      --issuer-url "$issuer_url"
      --issuer-a-url "$issuer_a_url"
      --issuer-b-url "$issuer_b_url"
      --entry-url "$entry_url"
      --exit-url "$exit_url"
      --min-sources "$min_sources"
      --min-operators "$min_operators"
      --federation-timeout-sec "$federation_timeout_sec"
      --timeout-sec "$validate_timeout_sec"
      --client-min-selection-lines "$client_min_selection_lines"
      --client-min-entry-operators "$client_min_entry_operators"
      --client-min-exit-operators "$client_min_exit_operators"
      --path-profile "$path_profile"
      --distinct-operators "$distinct_operators"
      --require-issuer-quorum "$require_issuer_quorum"
      --beta-profile "$beta_profile"
      --prod-profile "$prod_profile"
    )
    if [[ -n "$client_subject" ]]; then
      validate_cmd+=(--subject "$client_subject")
    fi
    if [[ -n "$client_anon_cred" ]]; then
      validate_cmd+=(--anon-cred "$client_anon_cred")
    fi
    if [[ -n "$bootstrap_directory" ]]; then
      validate_cmd+=(--bootstrap-directory "$bootstrap_directory" --discovery-wait-sec "$discovery_wait_sec")
    fi
    validate_cmd_print="$(print_cmd "${validate_cmd[@]}")"
    if THREE_MACHINE_CLIENT_INNER_SOURCE="${THREE_MACHINE_CLIENT_INNER_SOURCE:-synthetic}" THREE_MACHINE_VALIDATE_REWRITE_LOOPBACK_FOR_DOCKER=1 THREE_MACHINE_DOCKER_HOST_ALIAS="$docker_host_alias" "${validate_cmd[@]}"; then
      record_step "validate" "pass" 0 "" "$validate_cmd_print"
    else
      rc=$?
      status="fail"
      final_rc=$rc
      failed_step="validate"
      record_step "validate" "fail" "$rc" "3-machine validate failed" "$validate_cmd_print"
    fi
  else
    record_step "validate" "skip" 0 "skipped due to earlier failure"
  fi
else
  record_step "validate" "skip" 0 "disabled by flag"
fi

if [[ "$run_peer_failover" == "1" ]]; then
  if [[ "$status" == "pass" ]]; then
    failover_token_a="$directory_admin_token_a"
    failover_status_url_a="${directory_a_url}/v1/admin/sync-status"
    failover_stop_cmd_print="$(print_cmd "$docker_bin" compose --env-file "$env_b" -p "$project_b" -f "$compose_file" -f "$override_b" stop directory)"
    failover_start_cmd_print="$(print_cmd "$docker_bin" compose --env-file "$env_b" -p "$project_b" -f "$compose_file" -f "$override_b" up -d directory)"
    failover_note=""
    failover_rc=0

    if ! wait_sync_peer_success_state "$curl_bin" "$failover_status_url_a" "$failover_token_a" true "$peer_failover_timeout_sec"; then
      failover_rc=1
      failover_note="pre-failover sync-status did not reach peer.success=true"
    fi

    if [[ "$failover_rc" == "0" ]]; then
      if ! compose_cmd "$project_b" "$override_b" "$env_b" stop directory >/dev/null 2>&1; then
        failover_rc=1
        failover_note="failed to stop stack B directory"
      fi
    fi

    if [[ "$failover_rc" == "0" ]]; then
      sleep "$peer_failover_downtime_sec"
      if ! wait_sync_peer_success_state "$curl_bin" "$failover_status_url_a" "$failover_token_a" false "$peer_failover_timeout_sec"; then
        failover_rc=1
        failover_note="stack A did not observe peer.success=false during failover window"
      fi
    fi

    if [[ "$failover_rc" == "0" ]]; then
      if ! wait_http_ok "$curl_bin" "${directory_a_url}/v1/relays" "directory A during peer failover" 20; then
        failover_rc=1
        failover_note="directory A relays endpoint failed while peer was down"
      fi
    fi

    if [[ "$failover_rc" == "0" ]]; then
      if ! compose_cmd "$project_b" "$override_b" "$env_b" up -d directory >/dev/null 2>&1; then
        failover_rc=1
        failover_note="failed to restart stack B directory"
      fi
    fi

    if [[ "$failover_rc" == "0" ]]; then
      if ! wait_http_ok "$curl_bin" "${directory_b_url}/v1/relays" "directory B after failover restart" 30; then
        failover_rc=1
        failover_note="directory B did not recover after restart"
      fi
    fi

    if [[ "$failover_rc" == "0" ]]; then
      if ! wait_sync_peer_success_state "$curl_bin" "$failover_status_url_a" "$failover_token_a" true "$peer_failover_timeout_sec"; then
        failover_rc=1
        failover_note="stack A did not recover peer.success=true after stack B restart"
      fi
    fi

    if [[ "$failover_rc" == "0" ]]; then
      record_step "peer_failover" "pass" 0 "" "${failover_stop_cmd_print} && ${failover_start_cmd_print}"
    else
      status="fail"
      final_rc=1
      failed_step="peer_failover"
      record_step "peer_failover" "fail" 1 "$failover_note" "${failover_stop_cmd_print} && ${failover_start_cmd_print}"
      # Best-effort recovery so cleanup/down steps have a healthy compose state.
      compose_cmd "$project_b" "$override_b" "$env_b" up -d directory >/dev/null 2>&1 || true
    fi
  else
    record_step "peer_failover" "skip" 0 "skipped due to earlier failure"
  fi
else
  record_step "peer_failover" "skip" 0 "disabled by flag"
fi

if [[ "$run_soak" == "1" ]]; then
  if [[ "$status" == "pass" ]]; then
    soak_cmd=(
      "$soak_script"
      --directory-a "$directory_a_url"
      --directory-b "$directory_b_url"
      --issuer-url "$issuer_url"
      --issuer-a-url "$issuer_a_url"
      --issuer-b-url "$issuer_b_url"
      --entry-url "$entry_url"
      --exit-url "$exit_url"
      --rounds "$soak_rounds"
      --pause-sec "$soak_pause_sec"
      --continue-on-fail 0
      --min-sources "$min_sources"
      --min-operators "$min_operators"
      --federation-timeout-sec "$federation_timeout_sec"
      --timeout-sec "$validate_timeout_sec"
      --client-min-selection-lines "$client_min_selection_lines"
      --client-min-entry-operators "$client_min_entry_operators"
      --client-min-exit-operators "$client_min_exit_operators"
      --path-profile "$path_profile"
      --distinct-operators "$distinct_operators"
      --require-issuer-quorum "$require_issuer_quorum"
      --beta-profile "$beta_profile"
      --prod-profile "$prod_profile"
    )
    if [[ -n "$client_subject" ]]; then
      soak_cmd+=(--subject "$client_subject")
    fi
    if [[ -n "$client_anon_cred" ]]; then
      soak_cmd+=(--anon-cred "$client_anon_cred")
    fi
    if [[ -n "$bootstrap_directory" ]]; then
      soak_cmd+=(--bootstrap-directory "$bootstrap_directory" --discovery-wait-sec "$discovery_wait_sec")
    fi
    soak_cmd_print="$(print_cmd "${soak_cmd[@]}")"
    if THREE_MACHINE_CLIENT_INNER_SOURCE="${THREE_MACHINE_CLIENT_INNER_SOURCE:-synthetic}" THREE_MACHINE_VALIDATE_REWRITE_LOOPBACK_FOR_DOCKER=1 THREE_MACHINE_DOCKER_HOST_ALIAS="$docker_host_alias" "${soak_cmd[@]}"; then
      record_step "soak" "pass" 0 "" "$soak_cmd_print"
    else
      rc=$?
      status="fail"
      final_rc=$rc
      failed_step="soak"
      record_step "soak" "fail" "$rc" "3-machine soak failed" "$soak_cmd_print"
    fi
  else
    record_step "soak" "skip" 0 "skipped due to earlier failure"
  fi
else
  record_step "soak" "skip" 0 "disabled by flag"
fi

if [[ "$keep_stacks" == "0" ]]; then
  down_fail=0
  if ((stack_b_up == 1)); then
    down_b_cmd_print="$(print_cmd "$docker_bin" compose --env-file "$env_b" -p "$project_b" -f "$compose_file" -f "$override_b" down --remove-orphans)"
    if compose_down_stack "$project_b" "$override_b" "$env_b"; then
      record_step "stack_b_down" "pass" 0 "" "$down_b_cmd_print"
    else
      rc=$?
      down_fail=1
      record_step "stack_b_down" "fail" "$rc" "docker compose down failed" "$down_b_cmd_print"
    fi
  else
    record_step "stack_b_down" "skip" 0 "stack B was not started"
  fi

  if ((stack_a_up == 1)); then
    down_a_cmd_print="$(print_cmd "$docker_bin" compose --env-file "$env_a" -p "$project_a" -f "$compose_file" -f "$override_a" down --remove-orphans)"
    if compose_down_stack "$project_a" "$override_a" "$env_a"; then
      record_step "stack_a_down" "pass" 0 "" "$down_a_cmd_print"
    else
      rc=$?
      down_fail=1
      record_step "stack_a_down" "fail" "$rc" "docker compose down failed" "$down_a_cmd_print"
    fi
  else
    record_step "stack_a_down" "skip" 0 "stack A was not started"
  fi

  if [[ "$down_fail" == "1" && "$final_rc" == "0" ]]; then
    status="fail"
    final_rc=1
    if [[ -z "$failed_step" ]]; then
      failed_step="stack_down"
    fi
  fi
else
  record_step "stack_down" "skip" 0 "keep-stacks=1"
fi

if [[ "$final_rc" != "0" ]]; then
  status="fail"
fi

steps_json="$(jq -s '.' "$steps_file")"
generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
notes="Docker 3-machine rehearsal completed"
if [[ "$status" != "pass" ]]; then
  notes="Docker 3-machine rehearsal failed at step: ${failed_step:-unknown}"
fi

jq -n \
  --arg generated_at_utc "$generated_at_utc" \
  --arg status "$status" \
  --arg notes "$notes" \
  --arg summary_log "$summary_log" \
  --arg summary_json "$summary_json" \
  --arg override_a "$override_a" \
  --arg override_b "$override_b" \
  --arg env_a "$env_a" \
  --arg env_b "$env_b" \
  --arg data_root "$data_root" \
  --arg failed_step "$failed_step" \
  --arg directory_a "$directory_a_url" \
  --arg directory_b "$directory_b_url" \
  --arg issuer_a "$issuer_a_url" \
  --arg issuer_b "$issuer_b_url" \
  --arg entry "$entry_url" \
  --arg exit "$exit_url" \
  --arg project_a "$project_a" \
  --arg project_b "$project_b" \
  --arg docker_host_alias "$docker_host_alias" \
  --arg path_profile "$path_profile" \
  --arg normalized_path_profile "$normalized_path_profile" \
  --arg bootstrap_directory "$bootstrap_directory" \
  --argjson compose_up_max_attempts "$compose_up_max_attempts" \
  --argjson compose_up_initial_backoff_sec "$compose_up_initial_backoff_sec" \
  --argjson rc "$final_rc" \
  --argjson run_validate "$run_validate" \
  --argjson run_soak "$run_soak" \
  --argjson run_peer_failover "$run_peer_failover" \
  --argjson peer_failover_downtime_sec "$peer_failover_downtime_sec" \
  --argjson peer_failover_timeout_sec "$peer_failover_timeout_sec" \
  --argjson soak_rounds "$soak_rounds" \
  --argjson soak_pause_sec "$soak_pause_sec" \
  --argjson keep_stacks "$keep_stacks" \
  --argjson reset_data "$reset_data" \
  --argjson stack_a_base_port "$stack_a_base_port" \
  --argjson stack_b_base_port "$stack_b_base_port" \
  --argjson discovery_wait_sec "$discovery_wait_sec" \
  --argjson min_sources "$min_sources" \
  --argjson min_operators "$min_operators" \
  --argjson federation_timeout_sec "$federation_timeout_sec" \
  --argjson timeout_sec "$validate_timeout_sec" \
  --argjson client_min_selection_lines "$client_min_selection_lines" \
  --argjson client_min_entry_operators "$client_min_entry_operators" \
  --argjson client_min_exit_operators "$client_min_exit_operators" \
  --argjson distinct_operators "$distinct_operators" \
  --argjson middle_relay_enabled "$middle_relay_enabled" \
  --argjson require_issuer_quorum "$require_issuer_quorum" \
  --argjson beta_profile "$beta_profile" \
  --argjson prod_profile "$prod_profile" \
  --argjson steps "$steps_json" \
  '{
    "version": 1,
    "schema": {
      "id": "three_machine_docker_readiness_summary",
      "major": 1,
      "minor": 0
    },
    "generated_at_utc": $generated_at_utc,
    "status": $status,
    "rc": $rc,
    "notes": $notes,
    "failed_step": $failed_step,
    "config": {
      "run_validate": ($run_validate == 1),
      "run_soak": ($run_soak == 1),
      "run_peer_failover": ($run_peer_failover == 1),
      "peer_failover_downtime_sec": $peer_failover_downtime_sec,
      "peer_failover_timeout_sec": $peer_failover_timeout_sec,
      "soak_rounds": $soak_rounds,
      "soak_pause_sec": $soak_pause_sec,
      "keep_stacks": ($keep_stacks == 1),
      "reset_data": ($reset_data == 1),
      "stack_a_base_port": $stack_a_base_port,
      "stack_b_base_port": $stack_b_base_port,
      "docker_host_alias": $docker_host_alias,
      "bootstrap_directory": $bootstrap_directory,
      "discovery_wait_sec": $discovery_wait_sec,
      "min_sources": $min_sources,
      "min_operators": $min_operators,
      "federation_timeout_sec": $federation_timeout_sec,
      "timeout_sec": $timeout_sec,
      "client_min_selection_lines": $client_min_selection_lines,
      "client_min_entry_operators": $client_min_entry_operators,
      "client_min_exit_operators": $client_min_exit_operators,
      "path_profile": $path_profile,
      "normalized_path_profile": $normalized_path_profile,
      "middle_relay_enabled": ($middle_relay_enabled == 1),
      "compose_up_max_attempts": $compose_up_max_attempts,
      "compose_up_initial_backoff_sec": $compose_up_initial_backoff_sec,
      "distinct_operators": ($distinct_operators == 1),
      "require_issuer_quorum": ($require_issuer_quorum == 1),
      "beta_profile": ($beta_profile == 1),
      "prod_profile": ($prod_profile == 1)
    },
    "projects": {
      "stack_a": $project_a,
      "stack_b": $project_b
    },
    "endpoints": {
      "directory_a": $directory_a,
      "directory_b": $directory_b,
      "issuer_a": $issuer_a,
      "issuer_b": $issuer_b,
      "entry": $entry,
      "exit": $exit
    },
    "artifacts": {
      "summary_log": $summary_log,
      "summary_json": $summary_json,
      "override_a": $override_a,
      "override_b": $override_b,
      "env_a": $env_a,
      "env_b": $env_b,
      "data_root": $data_root
    },
    "steps": $steps
  }' >"$summary_json"

echo "three-machine-docker-readiness: status=$status"
echo "summary_log: $summary_log"
echo "summary_json: $summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
