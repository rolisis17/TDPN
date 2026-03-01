#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/integration_3machine_beta_validate.sh \
    --directory-a URL \
    --directory-b URL \
    --issuer-url URL \
    --entry-url URL \
    --exit-url URL \
    [--min-sources N] \
    [--min-operators N] \
    [--federation-timeout-sec N] \
    [--timeout-sec N] \
    [--exit-country CC] \
    [--exit-region REGION]

Purpose:
  Run from machine C (client host) to validate a 3-machine beta setup:
  - machine A: directory+issuer+entry+exit
  - machine B: directory+issuer+entry+exit (federated with A)
  - machine C: client-only validation runner
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

trim_url() {
  local value="$1"
  while [[ "$value" == */ ]]; do
    value="${value%/}"
  done
  echo "$value"
}

looks_loopback() {
  local value="$1"
  [[ "$value" == *"127.0.0.1"* || "$value" == *"localhost"* ]]
}

wait_http_ok() {
  local url="$1"
  local name="$2"
  local attempts="$3"
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

unique_operator_count() {
  local base_url
  base_url="$(trim_url "$1")"
  local payload
  payload="$(curl -fsS "${base_url}/v1/relays" 2>/dev/null || true)"
  if [[ -z "$payload" ]]; then
    echo "0"
    return
  fi
  local matches
  matches="$(printf '%s\n' "$payload" | rg -o '"operator":"[^"]+"' || true)"
  local count
  count="$(
    printf '%s\n' "$matches" |
      sed -E 's/^"operator":"([^"]+)"$/\1/' |
      awk 'NF > 0' |
      sort -u |
      wc -l |
      tr -d ' '
  )"
  if [[ -z "$count" ]]; then
    count="0"
  fi
  echo "$count"
}

directory_a=""
directory_b=""
issuer_url=""
entry_url=""
exit_url=""
min_sources="2"
min_operators="2"
federation_timeout_sec="90"
client_timeout_sec="45"
exit_country=""
exit_region=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --directory-a)
      directory_a="${2:-}"
      shift 2
      ;;
    --directory-b)
      directory_b="${2:-}"
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
    --min-operators)
      min_operators="${2:-}"
      shift 2
      ;;
    --federation-timeout-sec)
      federation_timeout_sec="${2:-}"
      shift 2
      ;;
    --timeout-sec)
      client_timeout_sec="${2:-}"
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

if [[ -z "$directory_a" || -z "$directory_b" || -z "$issuer_url" || -z "$entry_url" || -z "$exit_url" ]]; then
  echo "all endpoint URLs are required"
  usage
  exit 2
fi

need_cmd curl
need_cmd rg
need_cmd timeout
need_cmd docker
if ! docker compose version >/dev/null 2>&1; then
  echo "missing required dependency: docker compose plugin"
  exit 2
fi

directory_a="$(trim_url "$directory_a")"
directory_b="$(trim_url "$directory_b")"
issuer_url="$(trim_url "$issuer_url")"
entry_url="$(trim_url "$entry_url")"
exit_url="$(trim_url "$exit_url")"

for endpoint in "$directory_a" "$directory_b" "$issuer_url" "$entry_url" "$exit_url"; do
  if looks_loopback "$endpoint"; then
    echo "warning: loopback URL detected: $endpoint"
    echo "         for real 3-machine tests, use reachable public/private hostnames."
  fi
done

wait_http_ok "${directory_a}/v1/relays" "directory A" 30
wait_http_ok "${directory_b}/v1/relays" "directory B" 30
wait_http_ok "${issuer_url}/v1/pubkeys" "issuer" 30
wait_http_ok "${entry_url}/v1/health" "entry" 30
wait_http_ok "${exit_url}/v1/health" "exit" 30

federated=0
for _ in $(seq 1 "$federation_timeout_sec"); do
  a_ops="$(unique_operator_count "$directory_a")"
  b_ops="$(unique_operator_count "$directory_b")"
  if [[ "$a_ops" =~ ^[0-9]+$ ]] && [[ "$b_ops" =~ ^[0-9]+$ ]] && ((a_ops >= min_operators)) && ((b_ops >= min_operators)); then
    federated=1
    break
  fi
  sleep 1
done

if [[ "$federated" -ne 1 ]]; then
  echo "federation check failed: operator floor not reached on both directories"
  echo "required min operators per directory: $min_operators"
  echo "directory A operators: $(unique_operator_count "$directory_a")"
  echo "directory B operators: $(unique_operator_count "$directory_b")"
  echo "--- directory A relays ---"
  curl -fsS "${directory_a}/v1/relays" || true
  echo
  echo "--- directory B relays ---"
  curl -fsS "${directory_b}/v1/relays" || true
  echo
  exit 1
fi

client_cmd=(
  ./scripts/easy_node.sh client-test
  --directory-urls "${directory_a},${directory_b}"
  --issuer-url "$issuer_url"
  --entry-url "$entry_url"
  --exit-url "$exit_url"
  --min-sources "$min_sources"
  --timeout-sec "$client_timeout_sec"
)
if [[ -n "$exit_country" ]]; then
  client_cmd+=(--exit-country "$exit_country")
fi
if [[ -n "$exit_region" ]]; then
  client_cmd+=(--exit-region "$exit_region")
fi

"${client_cmd[@]}"

echo "3-machine beta validation check ok"
