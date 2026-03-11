#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

EASY_NODE_SH="${EASY_NODE_SH:-$ROOT_DIR/scripts/easy_node.sh}"
DOCKER_BIN="${PROD_KEY_ROTATION_DOCKER_BIN:-docker}"

MODE_FILE="$ROOT_DIR/deploy/data/easy_node_server_mode.conf"
AUTH_ENV_FILE="$ROOT_DIR/deploy/.env.easy.server"
PROVIDER_ENV_FILE="$ROOT_DIR/deploy/.env.easy.provider"

default_log_dir() {
  echo "${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

abs_path() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    echo ""
    return
  fi
  if [[ "$path" == /* ]]; then
    echo "$path"
  else
    echo "$ROOT_DIR/$path"
  fi
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

bool_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

int_or_die() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be an integer >= 0"
    exit 2
  fi
}

active_mode_from_file() {
  if [[ -f "$MODE_FILE" ]]; then
    local mode
    mode="$(awk -F= '$1=="EASY_NODE_SERVER_MODE"{print $2; exit}' "$MODE_FILE")"
    mode="$(trim "$mode")"
    if [[ "$mode" == "authority" || "$mode" == "provider" ]]; then
      echo "$mode"
      return
    fi
  fi
  echo "authority"
}

mode_env_file() {
  local mode="$1"
  if [[ "$mode" == "provider" ]]; then
    echo "$PROVIDER_ENV_FILE"
  else
    echo "$AUTH_ENV_FILE"
  fi
}

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_key_rotation_runbook.sh \
    [--mode auto|authority|provider] \
    [--backup-dir PATH] \
    [--summary-json PATH] \
    [--preflight-check [0|1]] \
    [--preflight-live [0|1]] \
    [--preflight-timeout-sec N] \
    [--rotate-server-secrets [0|1]] \
    [--rotate-admin-signing [0|1]] \
    [--key-history N] \
    [--restart [0|1]] \
    [--restart-issuer [0|1]] \
    [--show-secrets [0|1]] \
    [--rollback-on-fail [0|1]] \
    [--restart-after-rollback [0|1]] \
    [--print-summary-json [0|1]]

  ./scripts/prod_key_rotation_runbook.sh \
    --rollback-from PATH \
    [--mode auto|authority|provider] \
    [--restart-after-rollback [0|1]] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Operator-safe production maintenance runbook for key/secret rotation with
  rollback support.

Actions:
  - apply (default): backup -> optional preflight -> rotations -> optional preflight
    -> auto rollback on failure (configurable).
  - rollback: restore from a previously created backup directory.

Notes:
  - Backups include env/mode/identity plus deploy TLS and issuer key material.
  - Rollback restore is path-scoped to runbook-managed files only.
  - This script delegates service operations to easy_node commands and docker compose.
USAGE
}

create_backup() {
  local backup_dir="$1"
  local manifest_file="$backup_dir/backup_manifest.jsonl"
  local snapshot_dir="$backup_dir/snapshot"
  local rel src dst
  local -a paths=(
    "deploy/data/easy_node_server_mode.conf"
    "deploy/.env.easy.server"
    "deploy/.env.easy.provider"
    "deploy/data/easy_node_identity.conf"
    "deploy/data/issuer"
    "deploy/tls"
    "data/easy_mode_hosts.conf"
  )

  mkdir -p "$snapshot_dir"
  : >"$manifest_file"

  for rel in "${paths[@]}"; do
    src="$ROOT_DIR/$rel"
    if [[ -e "$src" ]]; then
      dst="$snapshot_dir/$rel"
      mkdir -p "$(dirname "$dst")"
      cp -a "$src" "$dst"
      jq -nc --arg path "$rel" --arg exists "1" '{"path":$path,"exists":($exists=="1")}' >>"$manifest_file"
    else
      jq -nc --arg path "$rel" --arg exists "0" '{"path":$path,"exists":($exists=="1")}' >>"$manifest_file"
    fi
  done

  jq -s '.' "$manifest_file" >"$backup_dir/backup_manifest.json"
  rm -f "$manifest_file"

  tar -czf "$backup_dir/prod_key_rotation_snapshot.tar.gz" -C "$snapshot_dir" .
}

restore_from_backup() {
  local backup_dir="$1"
  local snapshot_dir="$backup_dir/snapshot"
  local manifest_json="$backup_dir/backup_manifest.json"
  local rel src dst
  local idx count

  if [[ ! -d "$snapshot_dir" ]]; then
    echo "rollback failed: missing snapshot directory: $snapshot_dir"
    return 1
  fi
  if [[ ! -f "$manifest_json" ]]; then
    echo "rollback failed: missing backup manifest: $manifest_json"
    return 1
  fi

  count="$(jq 'length' "$manifest_json" 2>/dev/null || echo 0)"
  if [[ ! "$count" =~ ^[0-9]+$ ]]; then
    echo "rollback failed: invalid backup manifest: $manifest_json"
    return 1
  fi

  for ((idx = 0; idx < count; idx++)); do
    rel="$(jq -r ".[$idx].path // \"\"" "$manifest_json")"
    [[ -z "$rel" ]] && continue
    src="$snapshot_dir/$rel"
    dst="$ROOT_DIR/$rel"
    if [[ -e "$src" ]]; then
      rm -rf "$dst"
      mkdir -p "$(dirname "$dst")"
      cp -a "$src" "$dst"
    fi
  done
}

restart_services() {
  local mode="$1"
  local env_file
  env_file="$(mode_env_file "$mode")"
  if [[ ! -f "$env_file" ]]; then
    echo "restart failed: missing env file for mode=$mode ($env_file)"
    return 1
  fi
  if ! command -v "$DOCKER_BIN" >/dev/null 2>&1; then
    echo "restart failed: missing docker command: $DOCKER_BIN"
    return 1
  fi

  if [[ "$mode" == "provider" ]]; then
    "$DOCKER_BIN" compose --env-file "$env_file" up -d directory entry-exit
  else
    "$DOCKER_BIN" compose --env-file "$env_file" up -d directory issuer entry-exit
  fi
}

run_preflight() {
  local check_live="$1"
  local timeout_sec="$2"
  "$EASY_NODE_SH" prod-preflight --check-live "$check_live" --timeout-sec "$timeout_sec"
}

run_apply() {
  local mode="$1"
  local backup_dir="$2"
  local summary_json="$3"
  local preflight_check="$4"
  local preflight_live="$5"
  local preflight_timeout_sec="$6"
  local rotate_server_secrets="$7"
  local rotate_admin_signing="$8"
  local key_history="$9"
  local restart="${10}"
  local restart_issuer="${11}"
  local show_secrets="${12}"
  local rollback_on_fail="${13}"
  local restart_after_rollback="${14}"
  local print_summary_json="${15}"

  local status="ok"
  local failure_step=""
  local failure_rc=0
  local rollback_performed=0
  local rollback_rc=0
  local restart_rollback_rc=0
  local completed_steps_json='[]'

  step_ok() {
    local name="$1"
    completed_steps_json="$(
      jq -nc --argjson steps "$completed_steps_json" --arg name "$name" '$steps + [$name]'
    )"
  }

  maybe_fail() {
    local step="$1"
    local rc="$2"
    if [[ "$rc" -ne 0 ]]; then
      status="fail"
      failure_step="$step"
      failure_rc="$rc"
      return 0
    fi
    step_ok "$step"
    return 1
  }

  if [[ "$preflight_check" == "1" ]]; then
    set +e
    run_preflight "$preflight_live" "$preflight_timeout_sec"
    rc=$?
    set -e
    if maybe_fail "preflight_before" "$rc"; then
      :
    fi
  fi

  if [[ "$status" == "ok" && "$rotate_server_secrets" == "1" ]]; then
    set +e
    "$EASY_NODE_SH" rotate-server-secrets \
      --restart "$restart" \
      --rotate-issuer-admin 1 \
      --show-secrets "$show_secrets"
    rc=$?
    set -e
    if maybe_fail "rotate_server_secrets" "$rc"; then
      :
    fi
  fi

  if [[ "$status" == "ok" && "$mode" == "authority" && "$rotate_admin_signing" == "1" ]]; then
    set +e
    "$EASY_NODE_SH" admin-signing-rotate \
      --restart-issuer "$restart_issuer" \
      --key-history "$key_history"
    rc=$?
    set -e
    if maybe_fail "admin_signing_rotate" "$rc"; then
      :
    fi
  fi

  if [[ "$status" == "ok" && "$preflight_check" == "1" ]]; then
    set +e
    run_preflight "$preflight_live" "$preflight_timeout_sec"
    rc=$?
    set -e
    if maybe_fail "preflight_after" "$rc"; then
      :
    fi
  fi

  if [[ "$status" == "fail" && "$rollback_on_fail" == "1" ]]; then
    rollback_performed=1
    set +e
    restore_from_backup "$backup_dir"
    rollback_rc=$?
    set -e
    if [[ "$rollback_rc" -eq 0 && "$restart_after_rollback" == "1" ]]; then
      set +e
      restart_services "$mode"
      restart_rollback_rc=$?
      set -e
    fi
  fi

  summary_payload="$(
    jq -n \
      --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg action "apply" \
      --arg mode "$mode" \
      --arg status "$status" \
      --arg failure_step "$failure_step" \
      --arg backup_dir "$backup_dir" \
      --arg backup_tar "$backup_dir/prod_key_rotation_snapshot.tar.gz" \
      --argjson failure_rc "$failure_rc" \
      --argjson rollback_performed "$rollback_performed" \
      --argjson rollback_rc "$rollback_rc" \
      --argjson rollback_restart_rc "$restart_rollback_rc" \
      --argjson preflight_check "$preflight_check" \
      --argjson preflight_live "$preflight_live" \
      --argjson preflight_timeout_sec "$preflight_timeout_sec" \
      --argjson rotate_server_secrets "$rotate_server_secrets" \
      --argjson rotate_admin_signing "$rotate_admin_signing" \
      --argjson key_history "$key_history" \
      --argjson restart "$restart" \
      --argjson restart_issuer "$restart_issuer" \
      --argjson rollback_on_fail "$rollback_on_fail" \
      --argjson restart_after_rollback "$restart_after_rollback" \
      --argjson completed_steps "$completed_steps_json" \
      '{
        version: 1,
        generated_at_utc: $generated_at_utc,
        action: $action,
        mode: $mode,
        status: $status,
        failure_step: (if $failure_step == "" then null else $failure_step end),
        failure_rc: $failure_rc,
        backup: {
          dir: $backup_dir,
          tarball: $backup_tar
        },
        rollback: {
          enabled: ($rollback_on_fail == 1),
          performed: ($rollback_performed == 1),
          restore_rc: $rollback_rc,
          restart_rc: $rollback_restart_rc
        },
        policy: {
          preflight_check: ($preflight_check == 1),
          preflight_live: ($preflight_live == 1),
          preflight_timeout_sec: $preflight_timeout_sec,
          rotate_server_secrets: ($rotate_server_secrets == 1),
          rotate_admin_signing: ($rotate_admin_signing == 1),
          key_history: $key_history,
          restart: ($restart == 1),
          restart_issuer: ($restart_issuer == 1),
          restart_after_rollback: ($restart_after_rollback == 1)
        },
        completed_steps: $completed_steps
      }'
  )"

  mkdir -p "$(dirname "$summary_json")"
  printf '%s\n' "$summary_payload" >"$summary_json"
  echo "[prod-key-rotation-runbook] summary_json=$summary_json"
  if [[ "$print_summary_json" == "1" ]]; then
    echo "[prod-key-rotation-runbook] summary_json_payload:"
    printf '%s\n' "$summary_payload"
  fi

  if [[ "$status" != "ok" ]]; then
    return "$failure_rc"
  fi
  return 0
}

run_rollback() {
  local mode="$1"
  local rollback_from="$2"
  local summary_json="$3"
  local restart_after_rollback="$4"
  local print_summary_json="$5"

  local status="ok"
  local restore_rc=0
  local restart_rc=0

  set +e
  restore_from_backup "$rollback_from"
  restore_rc=$?
  set -e

  if [[ "$restore_rc" -ne 0 ]]; then
    status="fail"
  fi

  if [[ "$status" == "ok" && "$restart_after_rollback" == "1" ]]; then
    set +e
    restart_services "$mode"
    restart_rc=$?
    set -e
    if [[ "$restart_rc" -ne 0 ]]; then
      status="fail"
    fi
  fi

  summary_payload="$(
    jq -n \
      --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg action "rollback" \
      --arg mode "$mode" \
      --arg status "$status" \
      --arg rollback_from "$rollback_from" \
      --argjson restore_rc "$restore_rc" \
      --argjson restart_after_rollback "$restart_after_rollback" \
      --argjson restart_rc "$restart_rc" \
      '{
        version: 1,
        generated_at_utc: $generated_at_utc,
        action: $action,
        mode: $mode,
        status: $status,
        rollback_from: $rollback_from,
        restore_rc: $restore_rc,
        restart_after_rollback: ($restart_after_rollback == 1),
        restart_rc: $restart_rc
      }'
  )"

  mkdir -p "$(dirname "$summary_json")"
  printf '%s\n' "$summary_payload" >"$summary_json"
  echo "[prod-key-rotation-runbook] summary_json=$summary_json"
  if [[ "$print_summary_json" == "1" ]]; then
    echo "[prod-key-rotation-runbook] summary_json_payload:"
    printf '%s\n' "$summary_payload"
  fi

  if [[ "$status" != "ok" ]]; then
    if [[ "$restore_rc" -ne 0 ]]; then
      return "$restore_rc"
    fi
    return "$restart_rc"
  fi
  return 0
}

for cmd in bash jq tar cp awk date mktemp; do
  need_cmd "$cmd"
done
if [[ ! -x "$EASY_NODE_SH" ]]; then
  echo "missing executable easy_node wrapper: $EASY_NODE_SH"
  exit 2
fi

mode="auto"
backup_dir=""
summary_json=""
preflight_check="${PROD_KEY_ROTATION_PREFLIGHT_CHECK:-1}"
preflight_live="${PROD_KEY_ROTATION_PREFLIGHT_LIVE:-0}"
preflight_timeout_sec="${PROD_KEY_ROTATION_PREFLIGHT_TIMEOUT_SEC:-12}"
rotate_server_secrets="${PROD_KEY_ROTATION_ROTATE_SERVER_SECRETS:-1}"
rotate_admin_signing="${PROD_KEY_ROTATION_ROTATE_ADMIN_SIGNING:-1}"
key_history="${PROD_KEY_ROTATION_KEY_HISTORY:-3}"
restart="${PROD_KEY_ROTATION_RESTART:-1}"
restart_issuer="${PROD_KEY_ROTATION_RESTART_ISSUER:-1}"
show_secrets="${PROD_KEY_ROTATION_SHOW_SECRETS:-0}"
rollback_on_fail="${PROD_KEY_ROTATION_ROLLBACK_ON_FAIL:-1}"
restart_after_rollback="${PROD_KEY_ROTATION_RESTART_AFTER_ROLLBACK:-1}"
print_summary_json="${PROD_KEY_ROTATION_PRINT_SUMMARY_JSON:-0}"
rollback_from=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      mode="${2:-}"
      shift 2
      ;;
    --backup-dir)
      backup_dir="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --preflight-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        preflight_check="${2:-}"
        shift 2
      else
        preflight_check="1"
        shift
      fi
      ;;
    --preflight-live)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        preflight_live="${2:-}"
        shift 2
      else
        preflight_live="1"
        shift
      fi
      ;;
    --preflight-timeout-sec)
      preflight_timeout_sec="${2:-}"
      shift 2
      ;;
    --rotate-server-secrets)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        rotate_server_secrets="${2:-}"
        shift 2
      else
        rotate_server_secrets="1"
        shift
      fi
      ;;
    --rotate-admin-signing)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        rotate_admin_signing="${2:-}"
        shift 2
      else
        rotate_admin_signing="1"
        shift
      fi
      ;;
    --key-history)
      key_history="${2:-}"
      shift 2
      ;;
    --restart)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        restart="${2:-}"
        shift 2
      else
        restart="1"
        shift
      fi
      ;;
    --restart-issuer)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        restart_issuer="${2:-}"
        shift 2
      else
        restart_issuer="1"
        shift
      fi
      ;;
    --show-secrets)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        show_secrets="${2:-}"
        shift 2
      else
        show_secrets="1"
        shift
      fi
      ;;
    --rollback-on-fail)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        rollback_on_fail="${2:-}"
        shift 2
      else
        rollback_on_fail="1"
        shift
      fi
      ;;
    --restart-after-rollback)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        restart_after_rollback="${2:-}"
        shift 2
      else
        restart_after_rollback="1"
        shift
      fi
      ;;
    --rollback-from)
      rollback_from="${2:-}"
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

mode="$(trim "$mode")"
if [[ "$mode" != "auto" && "$mode" != "authority" && "$mode" != "provider" ]]; then
  echo "--mode must be one of: auto, authority, provider"
  exit 2
fi
if [[ "$mode" == "auto" ]]; then
  mode="$(active_mode_from_file)"
fi

bool_or_die "--preflight-check" "$preflight_check"
bool_or_die "--preflight-live" "$preflight_live"
bool_or_die "--rotate-server-secrets" "$rotate_server_secrets"
bool_or_die "--rotate-admin-signing" "$rotate_admin_signing"
bool_or_die "--restart" "$restart"
bool_or_die "--restart-issuer" "$restart_issuer"
bool_or_die "--show-secrets" "$show_secrets"
bool_or_die "--rollback-on-fail" "$rollback_on_fail"
bool_or_die "--restart-after-rollback" "$restart_after_rollback"
bool_or_die "--print-summary-json" "$print_summary_json"

int_or_die "--preflight-timeout-sec" "$preflight_timeout_sec"
int_or_die "--key-history" "$key_history"

timestamp="$(date +%Y%m%d_%H%M%S)"
if [[ -z "$backup_dir" ]]; then
  backup_dir="$(default_log_dir)/prod_key_rotation_$timestamp"
fi
backup_dir="$(abs_path "$backup_dir")"

if [[ -z "$summary_json" ]]; then
  summary_json="$backup_dir/prod_key_rotation_summary.json"
fi
summary_json="$(abs_path "$summary_json")"

if [[ -n "$rollback_from" ]]; then
  rollback_from="$(abs_path "$rollback_from")"
  run_rollback "$mode" "$rollback_from" "$summary_json" "$restart_after_rollback" "$print_summary_json"
  exit $?
fi

mkdir -p "$backup_dir"
create_backup "$backup_dir"
echo "[prod-key-rotation-runbook] backup_dir=$backup_dir"
echo "[prod-key-rotation-runbook] mode=$mode"

run_apply \
  "$mode" \
  "$backup_dir" \
  "$summary_json" \
  "$preflight_check" \
  "$preflight_live" \
  "$preflight_timeout_sec" \
  "$rotate_server_secrets" \
  "$rotate_admin_signing" \
  "$key_history" \
  "$restart" \
  "$restart_issuer" \
  "$show_secrets" \
  "$rollback_on_fail" \
  "$restart_after_rollback" \
  "$print_summary_json"
