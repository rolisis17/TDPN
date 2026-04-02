#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/manual_validation_record.sh \
    --check-id CHECK_ID \
    --status pass|fail|warn|pending|skip \
    [--notes TEXT] \
    [--artifact PATH]... \
    [--command TEXT] \
    [--show-json [0|1]]

Purpose:
  Record the outcome of a manual real-host validation step so production
  readiness does not depend on chat history or ad hoc notes.

Examples:
  ./scripts/manual_validation_record.sh \
    --check-id wg_only_stack_selftest \
    --status pass \
    --notes "Linux root host rerun passed" \
    --artifact .easy-node-logs/easy_node_wg_only_stack_20260314_111744.log
USAGE
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

abs_path() {
  local path="$1"
  path="$(trim "$path")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
  elif [[ "$path" = /* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

manual_validation_state_dir() {
  if [[ -n "${EASY_NODE_MANUAL_VALIDATION_STATE_DIR:-}" ]]; then
    printf '%s\n' "${EASY_NODE_MANUAL_VALIDATION_STATE_DIR}"
    return
  fi

  local home_dir=""
  local state_home=""
  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER:-}" != "root" ]]; then
    home_dir="$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6 || true)"
    if [[ -z "$home_dir" ]]; then
      home_dir="$(eval echo "~$SUDO_USER" 2>/dev/null || true)"
    fi
    if [[ -n "$home_dir" && "$home_dir" != "~$SUDO_USER" ]]; then
      state_home="$home_dir/.local/state"
    fi
  fi
  if [[ -z "$state_home" ]]; then
    if [[ -n "${XDG_STATE_HOME:-}" ]]; then
      state_home="${XDG_STATE_HOME}"
    elif [[ -n "${HOME:-}" ]]; then
      state_home="${HOME}/.local/state"
    else
      state_home="${ROOT_DIR}/.easy-node-logs"
    fi
  fi
  printf '%s\n' "${state_home}/privacynode/manual_validation"
}

show_json="0"
check_id=""
status=""
notes=""
command_text=""
state_lock_dir=""
state_lock_held="0"
state_lock_timeout_sec="${MANUAL_VALIDATION_RECORD_LOCK_TIMEOUT_SEC:-15}"
declare -a artifacts=()

release_state_lock() {
  if [[ "$state_lock_held" == "1" && -n "$state_lock_dir" ]]; then
    rm -rf "$state_lock_dir" 2>/dev/null || true
  fi
  state_lock_held="0"
}

acquire_state_lock() {
  local lock_dir="$1"
  local timeout_sec="$2"
  local deadline=$((SECONDS + timeout_sec))
  local lock_pid_file="${lock_dir}/pid"
  local lock_pid=""

  while true; do
    if mkdir "$lock_dir" 2>/dev/null; then
      printf '%s\n' "$$" >"$lock_pid_file"
      state_lock_dir="$lock_dir"
      state_lock_held="1"
      return 0
    fi

    if [[ -f "$lock_pid_file" ]]; then
      lock_pid="$(cat "$lock_pid_file" 2>/dev/null || true)"
      if [[ "$lock_pid" =~ ^[0-9]+$ ]] && ! kill -0 "$lock_pid" 2>/dev/null; then
        rm -rf "$lock_dir" 2>/dev/null || true
        continue
      fi
    fi

    if ((SECONDS >= deadline)); then
      echo "timed out acquiring manual-validation state lock: $lock_dir"
      return 1
    fi
    sleep 0.1
  done
}

backup_invalid_status_json() {
  local source_json="$1"
  local backup_dir="$2"
  local backup_stamp=""
  local backup_path=""
  local backup_tmp=""

  if [[ ! -f "$source_json" ]]; then
    return 1
  fi

  backup_stamp="$(date -u +"%Y%m%d_%H%M%S")"
  mkdir -p "$backup_dir"
  backup_path="${backup_dir}/status_invalid_${backup_stamp}_pid$$.json"
  backup_tmp="$(mktemp "${backup_path}.tmp.XXXXXX")"
  if ! cat "$source_json" >"$backup_tmp"; then
    rm -f "$backup_tmp"
    return 1
  fi
  mv -f "$backup_tmp" "$backup_path"
  printf '%s\n' "$backup_path"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check-id)
      check_id="${2:-}"
      shift 2
      ;;
    --status)
      status="${2:-}"
      shift 2
      ;;
    --notes)
      notes="${2:-}"
      shift 2
      ;;
    --artifact)
      artifacts+=("$(abs_path "${2:-}")")
      shift 2
      ;;
    --command)
      command_text="${2:-}"
      shift 2
      ;;
    --show-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        show_json="${2:-}"
        shift 2
      else
        show_json="1"
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

bool_arg_or_die "--show-json" "$show_json"
check_id="$(trim "$check_id")"
status="$(trim "$status")"
notes="$(trim "$notes")"
command_text="$(trim "$command_text")"

if [[ ! "$check_id" =~ ^[a-z0-9_]+$ ]]; then
  echo "--check-id must match ^[a-z0-9_]+\$"
  exit 2
fi
case "$status" in
  pass|fail|warn|pending|skip)
    ;;
  *)
    echo "--status must be one of: pass fail warn pending skip"
    exit 2
    ;;
esac
if ! [[ "$state_lock_timeout_sec" =~ ^[0-9]+$ ]]; then
  echo "MANUAL_VALIDATION_RECORD_LOCK_TIMEOUT_SEC must be an integer >= 0"
  exit 2
fi

state_dir="$(manual_validation_state_dir)"
receipts_dir="${state_dir}/receipts"
status_json="${state_dir}/status.json"
mkdir -p "$receipts_dir"
state_lock_path="${state_dir}/status.lock"
trap 'release_state_lock' EXIT
if ! acquire_state_lock "$state_lock_path" "$state_lock_timeout_sec"; then
  exit 1
fi

recorded_at_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
receipt_stamp="$(date -u +"%Y%m%d_%H%M%S")"
receipt_json="$(mktemp "${receipts_dir}/${receipt_stamp}_${check_id}_XXXXXX.json")"
recorded_by="$(id -un 2>/dev/null || printf '%s' "${USER:-unknown}")"
artifact_list_json="$(printf '%s\n' "${artifacts[@]:-}" | jq -Rsc 'split("\n") | map(select(length > 0))')"
invalid_status_fallback_used="0"
invalid_status_warning=""
invalid_status_backup_path=""

receipt_payload="$(
  jq -n \
  --arg check_id "$check_id" \
  --arg status "$status" \
  --arg notes "$notes" \
  --arg command "$command_text" \
  --arg recorded_at_utc "$recorded_at_utc" \
  --arg recorded_by "$recorded_by" \
  --arg receipt_json "$receipt_json" \
  --argjson artifacts "$artifact_list_json" \
  '{
    version: 1,
    check_id: $check_id,
    status: $status,
    notes: $notes,
    command: $command,
    artifacts: $artifacts,
    recorded_at_utc: $recorded_at_utc,
    recorded_by: $recorded_by,
    receipt_json: $receipt_json
  }'
)"
receipt_tmp="$(mktemp "${receipt_json}.tmp.XXXXXX")"
printf '%s\n' "$receipt_payload" >"$receipt_tmp"
mv -f "$receipt_tmp" "$receipt_json"

if [[ -f "$status_json" ]]; then
  if jq -e . "$status_json" >/dev/null 2>&1; then
    existing_status_json="$(cat "$status_json")"
  else
    existing_status_json='{"version":1,"checks":{}}'
    invalid_status_fallback_used="1"
    invalid_status_warning="existing status JSON invalid; resetting status ledger before recording new check"
    invalid_status_backup_path="$(backup_invalid_status_json "$status_json" "${state_dir}/invalid_status_backups" || true)"
  fi
else
  existing_status_json='{"version":1,"checks":{}}'
fi

updated_status_json="$(
  printf '%s\n' "$existing_status_json" | jq \
    --arg check_id "$check_id" \
    --arg status "$status" \
    --arg notes "$notes" \
    --arg command "$command_text" \
    --arg recorded_at_utc "$recorded_at_utc" \
    --arg receipt_json "$receipt_json" \
    --argjson artifacts "$artifact_list_json" \
    '
      .version = 1
      | .checks = (.checks // {})
      | .checks[$check_id] = {
          status: $status,
          notes: $notes,
          command: $command,
          artifacts: $artifacts,
          recorded_at_utc: $recorded_at_utc,
          receipt_json: $receipt_json
        }
    '
)"
status_tmp="$(mktemp "${status_json}.tmp.XXXXXX")"
printf '%s\n' "$updated_status_json" >"$status_tmp"
mv -f "$status_tmp" "$status_json"

echo "[manual-validation-record] check_id=$check_id status=$status state_dir=$state_dir"
echo "[manual-validation-record] receipt_json=$receipt_json"
if [[ "$invalid_status_fallback_used" == "1" ]]; then
  echo "[manual-validation-record] warn=$invalid_status_warning"
  if [[ -n "$invalid_status_backup_path" ]]; then
    echo "[manual-validation-record] invalid_status_backup_path=$invalid_status_backup_path"
  else
    echo "[manual-validation-record] warn=failed to preserve invalid status backup"
  fi
fi
if [[ -n "$notes" ]]; then
  echo "[manual-validation-record] notes=$notes"
fi
if [[ ${#artifacts[@]} -gt 0 ]]; then
  echo "[manual-validation-record] artifacts=${artifacts[*]}"
fi
if [[ "$show_json" == "1" ]]; then
  echo "[manual-validation-record] receipt_json_payload:"
  cat "$receipt_json"
fi
