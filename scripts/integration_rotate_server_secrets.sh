#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

AUTH_ENV="$ROOT_DIR/deploy/.env.easy.server"
PROVIDER_ENV="$ROOT_DIR/deploy/.env.easy.provider"
MODE_FILE="$ROOT_DIR/deploy/data/easy_node_server_mode.conf"

backup_auth=""
backup_provider=""
backup_mode=""

env_value() {
  local file="$1"
  local key="$2"
  awk -F= -v k="$key" '$1==k{print substr($0,index($0,"=")+1); exit}' "$file"
}

assert_mode_600_or_skip() {
  local file="$1"
  local label="$2"
  local mode=""
  local probe_dir=""
  local probe_file=""
  local probe_mode=""
  mode="$(stat -c '%a' "$file" 2>/dev/null || true)"
  if [[ -z "$mode" ]]; then
    return
  fi
  if [[ "$mode" == "600" ]]; then
    return
  fi
  probe_dir="$(dirname "$file")"
  mkdir -p "$probe_dir" >/dev/null 2>&1 || true
  probe_file="$(mktemp "$probe_dir/.perm_probe.XXXXXX" 2>/dev/null || true)"
  if [[ -n "$probe_file" ]]; then
    chmod 600 "$probe_file" 2>/dev/null || true
    probe_mode="$(stat -c '%a' "$probe_file" 2>/dev/null || true)"
    rm -f "$probe_file"
  fi
  if [[ "$probe_mode" != "600" ]]; then
    echo "[rotate-server-secrets] note: skipping ${label} mode check on filesystem without POSIX chmod enforcement (mode=${mode})"
    return
  fi
  echo "${label} permissions not hardened after rotate (expected 600, got ${mode})"
  exit 1
}

restore_files() {
  if [[ -n "$backup_auth" && -f "$backup_auth" ]]; then
    cp "$backup_auth" "$AUTH_ENV"
    rm -f "$backup_auth"
  else
    rm -f "$AUTH_ENV"
  fi
  if [[ -n "$backup_provider" && -f "$backup_provider" ]]; then
    cp "$backup_provider" "$PROVIDER_ENV"
    rm -f "$backup_provider"
  else
    rm -f "$PROVIDER_ENV"
  fi
  if [[ -n "$backup_mode" && -f "$backup_mode" ]]; then
    cp "$backup_mode" "$MODE_FILE"
    rm -f "$backup_mode"
  else
    rm -f "$MODE_FILE"
  fi
}
trap restore_files EXIT

mkdir -p "$ROOT_DIR/deploy/data"
if [[ -f "$AUTH_ENV" ]]; then
  backup_auth="$(mktemp)"
  cp "$AUTH_ENV" "$backup_auth"
fi
if [[ -f "$PROVIDER_ENV" ]]; then
  backup_provider="$(mktemp)"
  cp "$PROVIDER_ENV" "$backup_provider"
fi
if [[ -f "$MODE_FILE" ]]; then
  backup_mode="$(mktemp)"
  cp "$MODE_FILE" "$backup_mode"
fi

cat >"$AUTH_ENV" <<'EOF_AUTH'
DIRECTORY_ADMIN_TOKEN=old-directory-token
ENTRY_PUZZLE_SECRET=old-entry-secret
ISSUER_ADMIN_TOKEN=old-issuer-token
EOF_AUTH

cat >"$MODE_FILE" <<'EOF_MODE'
EASY_NODE_SERVER_MODE=authority
EOF_MODE

./scripts/easy_node.sh rotate-server-secrets --restart 0 --rotate-issuer-admin 1 >/tmp/integration_rotate_server_secrets_authority.log 2>&1

new_dir_token="$(env_value "$AUTH_ENV" "DIRECTORY_ADMIN_TOKEN")"
new_entry_secret="$(env_value "$AUTH_ENV" "ENTRY_PUZZLE_SECRET")"
new_issuer_token="$(env_value "$AUTH_ENV" "ISSUER_ADMIN_TOKEN")"
if [[ -z "$new_dir_token" || "$new_dir_token" == "old-directory-token" || "${#new_dir_token}" -lt 16 ]]; then
  echo "authority rotate did not refresh DIRECTORY_ADMIN_TOKEN"
  cat /tmp/integration_rotate_server_secrets_authority.log
  exit 1
fi
if [[ -z "$new_entry_secret" || "$new_entry_secret" == "old-entry-secret" || "${#new_entry_secret}" -lt 16 ]]; then
  echo "authority rotate did not refresh ENTRY_PUZZLE_SECRET"
  cat /tmp/integration_rotate_server_secrets_authority.log
  exit 1
fi
if [[ -z "$new_issuer_token" || "$new_issuer_token" == "old-issuer-token" || "${#new_issuer_token}" -lt 16 ]]; then
  echo "authority rotate did not refresh ISSUER_ADMIN_TOKEN"
  cat /tmp/integration_rotate_server_secrets_authority.log
  exit 1
fi

cat >"$AUTH_ENV" <<'EOF_AUTH_SIGNED_ONLY'
DIRECTORY_ADMIN_TOKEN=old-directory-token-2
ENTRY_PUZZLE_SECRET=old-entry-secret-2
ISSUER_ADMIN_TOKEN=legacy-admin-token
ISSUER_ADMIN_ALLOW_TOKEN=0
EOF_AUTH_SIGNED_ONLY

./scripts/easy_node.sh rotate-server-secrets --restart 0 --rotate-issuer-admin 1 >/tmp/integration_rotate_server_secrets_authority_signed_only.log 2>&1

new_dir_token_signed_only="$(env_value "$AUTH_ENV" "DIRECTORY_ADMIN_TOKEN")"
new_entry_secret_signed_only="$(env_value "$AUTH_ENV" "ENTRY_PUZZLE_SECRET")"
new_issuer_token_signed_only="$(env_value "$AUTH_ENV" "ISSUER_ADMIN_TOKEN")"
if [[ -z "$new_dir_token_signed_only" || "$new_dir_token_signed_only" == "old-directory-token-2" || "${#new_dir_token_signed_only}" -lt 16 ]]; then
  echo "authority signed-only rotate did not refresh DIRECTORY_ADMIN_TOKEN"
  cat /tmp/integration_rotate_server_secrets_authority_signed_only.log
  exit 1
fi
if [[ -z "$new_entry_secret_signed_only" || "$new_entry_secret_signed_only" == "old-entry-secret-2" || "${#new_entry_secret_signed_only}" -lt 16 ]]; then
  echo "authority signed-only rotate did not refresh ENTRY_PUZZLE_SECRET"
  cat /tmp/integration_rotate_server_secrets_authority_signed_only.log
  exit 1
fi
if [[ -n "$new_issuer_token_signed_only" ]]; then
  echo "authority signed-only rotate unexpectedly left ISSUER_ADMIN_TOKEN set"
  cat /tmp/integration_rotate_server_secrets_authority_signed_only.log
  exit 1
fi

assert_mode_600_or_skip "$AUTH_ENV" "authority env"

cat >"$PROVIDER_ENV" <<'EOF_PROVIDER'
DIRECTORY_ADMIN_TOKEN=provider-old-directory-token
ENTRY_PUZZLE_SECRET=provider-old-entry-secret
EOF_PROVIDER

cat >"$MODE_FILE" <<'EOF_MODE'
EASY_NODE_SERVER_MODE=provider
EOF_MODE

./scripts/easy_node.sh rotate-server-secrets --restart 0 --rotate-issuer-admin 1 >/tmp/integration_rotate_server_secrets_provider.log 2>&1

provider_dir_token="$(env_value "$PROVIDER_ENV" "DIRECTORY_ADMIN_TOKEN")"
provider_entry_secret="$(env_value "$PROVIDER_ENV" "ENTRY_PUZZLE_SECRET")"
provider_issuer_token="$(env_value "$PROVIDER_ENV" "ISSUER_ADMIN_TOKEN")"
if [[ -z "$provider_dir_token" || "$provider_dir_token" == "provider-old-directory-token" || "${#provider_dir_token}" -lt 16 ]]; then
  echo "provider rotate did not refresh DIRECTORY_ADMIN_TOKEN"
  cat /tmp/integration_rotate_server_secrets_provider.log
  exit 1
fi
if [[ -z "$provider_entry_secret" || "$provider_entry_secret" == "provider-old-entry-secret" || "${#provider_entry_secret}" -lt 16 ]]; then
  echo "provider rotate did not refresh ENTRY_PUZZLE_SECRET"
  cat /tmp/integration_rotate_server_secrets_provider.log
  exit 1
fi
if [[ -n "$provider_issuer_token" ]]; then
  echo "provider rotate unexpectedly set ISSUER_ADMIN_TOKEN"
  cat /tmp/integration_rotate_server_secrets_provider.log
  exit 1
fi

assert_mode_600_or_skip "$PROVIDER_ENV" "provider env"

echo "rotate server secrets integration check ok"
