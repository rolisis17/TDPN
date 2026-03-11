#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$ROOT_DIR/deploy"

default_log_dir() {
  echo "${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
}

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/incident_snapshot.sh \
    [--bundle-dir PATH] \
    [--mode auto|authority|provider|client] \
    [--env-file PATH] \
    [--directory-url URL] \
    [--issuer-url URL] \
    [--entry-url URL] \
    [--exit-url URL] \
    [--compose-project NAME] \
    [--include-docker-logs [0|1]] \
    [--docker-log-lines N] \
    [--timeout-sec N]

Purpose:
  Capture a production incident snapshot bundle with endpoint probes,
  docker status/log tails, and system metadata for triage/share.
USAGE
}

trim_url() {
  local value="$1"
  while [[ "$value" == */ ]]; do
    value="${value%/}"
  done
  echo "$value"
}

env_value() {
  local file="$1"
  local key="$2"
  if [[ ! -f "$file" ]]; then
    return 0
  fi
  sed -nE "s/^${key}=(.*)$/\\1/p" "$file" | head -n1
}

first_csv_value() {
  local csv="$1"
  if [[ -z "$csv" ]]; then
    return 0
  fi
  printf '%s' "$csv" | cut -d',' -f1
}

snapshot_url() {
  local output="$1"
  local url="$2"
  local timeout_sec="$3"

  if [[ -z "$url" ]]; then
    printf 'skipped: empty url\n' >"$output"
    return 0
  fi
  if ! command -v curl >/dev/null 2>&1; then
    printf 'skipped: curl missing\n' >"$output"
    return 0
  fi

  if curl -fsS --connect-timeout 3 --max-time "$timeout_sec" "$url" >"$output" 2>"$output.err"; then
    rm -f "$output.err"
  else
    {
      echo "probe_failed: $url"
      cat "$output.err" 2>/dev/null || true
    } >"$output"
    rm -f "$output.err"
  fi
}

write_safe_env_summary() {
  local output="$1"
  local env_file="$2"
  if [[ -z "$env_file" || ! -f "$env_file" ]]; then
    printf 'env_file_missing_or_not_selected\n' >"$output"
    return 0
  fi

  local keys=(
    EASY_NODE_SERVER_MODE
    DIRECTORY_OPERATOR_ID
    ISSUER_ID
    BETA_STRICT_MODE
    PROD_STRICT_MODE
    MTLS_ENABLE
    DIRECTORY_PUBLIC_URL
    ENTRY_URL_PUBLIC
    EXIT_CONTROL_URL_PUBLIC
    CORE_ISSUER_URL
    ISSUER_URLS
    DIRECTORY_PEERS
  )
  : >"$output"
  local key value
  for key in "${keys[@]}"; do
    value="$(env_value "$env_file" "$key")"
    if [[ -n "$value" ]]; then
      printf '%s=%s\n' "$key" "$value" >>"$output"
    fi
  done
}

hash_file_line() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file"
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file"
    return 0
  fi
  return 1
}

directory_url=""
issuer_url=""
entry_url=""
exit_url=""
bundle_dir=""
mode="auto"
env_file=""
compose_project="deploy"
include_docker_logs="1"
docker_log_lines="200"
timeout_sec="8"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle-dir)
      bundle_dir="${2:-}"
      shift 2
      ;;
    --mode)
      mode="${2:-}"
      shift 2
      ;;
    --env-file)
      env_file="${2:-}"
      shift 2
      ;;
    --directory-url)
      directory_url="${2:-}"
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
    --compose-project)
      compose_project="${2:-}"
      shift 2
      ;;
    --include-docker-logs)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        include_docker_logs="${2:-}"
        shift 2
      else
        include_docker_logs="1"
        shift
      fi
      ;;
    --docker-log-lines)
      docker_log_lines="${2:-}"
      shift 2
      ;;
    --timeout-sec)
      timeout_sec="${2:-}"
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

if [[ "$mode" != "auto" && "$mode" != "authority" && "$mode" != "provider" && "$mode" != "client" ]]; then
  echo "--mode must be one of: auto, authority, provider, client"
  exit 2
fi
if [[ "$include_docker_logs" != "0" && "$include_docker_logs" != "1" ]]; then
  echo "--include-docker-logs must be 0 or 1"
  exit 2
fi
if ! [[ "$docker_log_lines" =~ ^[0-9]+$ ]] || ((docker_log_lines < 1)); then
  echo "--docker-log-lines must be >= 1"
  exit 2
fi
if ! [[ "$timeout_sec" =~ ^[0-9]+$ ]] || ((timeout_sec < 1)); then
  echo "--timeout-sec must be >= 1"
  exit 2
fi

if [[ -z "$bundle_dir" ]]; then
  bundle_dir="$(default_log_dir)/incident_snapshot_$(date +%Y%m%d_%H%M%S)"
fi
if [[ "$bundle_dir" != /* ]]; then
  bundle_dir="$ROOT_DIR/$bundle_dir"
fi
mkdir -p "$bundle_dir/endpoints" "$bundle_dir/docker" "$bundle_dir/system"

if [[ -z "$env_file" ]]; then
  case "$mode" in
    authority)
      env_file="$DEPLOY_DIR/.env.easy.server"
      ;;
    provider)
      env_file="$DEPLOY_DIR/.env.easy.provider"
      ;;
    client)
      env_file="$DEPLOY_DIR/.env.easy.client"
      ;;
    auto)
      if [[ -f "$DEPLOY_DIR/.env.easy.server" ]]; then
        env_file="$DEPLOY_DIR/.env.easy.server"
      elif [[ -f "$DEPLOY_DIR/.env.easy.provider" ]]; then
        env_file="$DEPLOY_DIR/.env.easy.provider"
      elif [[ -f "$DEPLOY_DIR/.env.easy.client" ]]; then
        env_file="$DEPLOY_DIR/.env.easy.client"
      fi
      ;;
  esac
fi
if [[ -n "$env_file" && "$env_file" != /* ]]; then
  env_file="$ROOT_DIR/$env_file"
fi

if [[ -z "$directory_url" && -n "$env_file" ]]; then
  directory_url="$(env_value "$env_file" "DIRECTORY_PUBLIC_URL")"
  if [[ -z "$directory_url" ]]; then
    directory_url="$(env_value "$env_file" "CORE_DIRECTORY_URL")"
  fi
fi
if [[ -z "$issuer_url" && -n "$env_file" ]]; then
  issuer_url="$(first_csv_value "$(env_value "$env_file" "ISSUER_URLS")")"
  if [[ -z "$issuer_url" ]]; then
    issuer_url="$(env_value "$env_file" "CORE_ISSUER_URL")"
  fi
fi
if [[ -z "$entry_url" && -n "$env_file" ]]; then
  entry_url="$(env_value "$env_file" "ENTRY_URL_PUBLIC")"
fi
if [[ -z "$exit_url" && -n "$env_file" ]]; then
  exit_url="$(env_value "$env_file" "EXIT_CONTROL_URL_PUBLIC")"
fi

directory_url="$(trim_url "$directory_url")"
issuer_url="$(trim_url "$issuer_url")"
entry_url="$(trim_url "$entry_url")"
exit_url="$(trim_url "$exit_url")"

{
  echo "generated_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host=$(hostname 2>/dev/null || echo unknown)"
  echo "user=$(id -un 2>/dev/null || echo unknown)"
  echo "uid=$(id -u 2>/dev/null || echo unknown)"
  echo "mode=$mode"
  echo "env_file=$env_file"
  echo "directory_url=$directory_url"
  echo "issuer_url=$issuer_url"
  echo "entry_url=$entry_url"
  echo "exit_url=$exit_url"
  echo "compose_project=$compose_project"
} >"$bundle_dir/metadata.txt"

{
  echo "uname: $(uname -a 2>/dev/null || true)"
  echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "pwd: $PWD"
  if command -v git >/dev/null 2>&1; then
    echo "git_head: $(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "git_branch: $(git -C "$ROOT_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
  fi
} >"$bundle_dir/system/system_info.txt"

if command -v ip >/dev/null 2>&1; then
  ip -brief addr >"$bundle_dir/system/ip_addr.txt" 2>&1 || true
fi

write_safe_env_summary "$bundle_dir/system/env_summary.txt" "$env_file"

snapshot_url "$bundle_dir/endpoints/directory_relays.json" "${directory_url:+${directory_url}/v1/relays}" "$timeout_sec"
snapshot_url "$bundle_dir/endpoints/directory_peers.json" "${directory_url:+${directory_url}/v1/peers}" "$timeout_sec"
snapshot_url "$bundle_dir/endpoints/directory_health.json" "${directory_url:+${directory_url}/v1/health}" "$timeout_sec"
snapshot_url "$bundle_dir/endpoints/issuer_pubkeys.json" "${issuer_url:+${issuer_url}/v1/pubkeys}" "$timeout_sec"
snapshot_url "$bundle_dir/endpoints/entry_health.json" "${entry_url:+${entry_url}/v1/health}" "$timeout_sec"
snapshot_url "$bundle_dir/endpoints/exit_health.json" "${exit_url:+${exit_url}/v1/health}" "$timeout_sec"
snapshot_url "$bundle_dir/endpoints/exit_metrics.json" "${exit_url:+${exit_url}/v1/metrics}" "$timeout_sec"

if command -v docker >/dev/null 2>&1; then
  docker ps >"$bundle_dir/docker/docker_ps.txt" 2>&1 || true
  docker info >"$bundle_dir/docker/docker_info.txt" 2>&1 || true
  if docker compose version >/dev/null 2>&1; then
    (cd "$DEPLOY_DIR" && docker compose --project-name "$compose_project" ps) >"$bundle_dir/docker/compose_ps.txt" 2>&1 || true
    if [[ "$include_docker_logs" == "1" ]]; then
      for service in directory issuer entry-exit; do
        (cd "$DEPLOY_DIR" && docker compose --project-name "$compose_project" logs --no-color --tail "$docker_log_lines" "$service") \
          >"$bundle_dir/docker/${service}_tail.log" 2>&1 || true
      done
    fi
  else
    echo "docker compose plugin missing" >"$bundle_dir/docker/compose_ps.txt"
  fi
else
  echo "docker command missing" >"$bundle_dir/docker/docker_ps.txt"
fi

manifest_file="$bundle_dir/manifest.sha256"
if hash_file_line "$bundle_dir/metadata.txt" >/dev/null 2>&1; then
  (
    cd "$bundle_dir"
    while IFS= read -r rel_path; do
      hash_file_line "$rel_path"
    done < <(find . -type f ! -name 'manifest.sha256' -print | sed 's#^\./##' | sort)
  ) >"$manifest_file"
else
  echo "sha256 tooling missing (sha256sum/shasum)" >"$manifest_file"
fi

bundle_tar="${bundle_dir}.tar.gz"
tar -czf "$bundle_tar" -C "$(dirname "$bundle_dir")" "$(basename "$bundle_dir")"

bundle_tar_sha="$bundle_tar.sha256"
if hash_file_line "$bundle_tar" >"$bundle_tar_sha" 2>/dev/null; then
  :
else
  echo "sha256 tooling missing (sha256sum/shasum)" >"$bundle_tar_sha"
fi

echo "incident snapshot ready"
echo "bundle_dir: $bundle_dir"
echo "bundle_tar: $bundle_tar"
echo "bundle_tar_sha256: $bundle_tar_sha"
