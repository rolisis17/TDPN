#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

for cmd in go rg timeout; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

count_matches() {
  local pattern="$1"
  local file="$2"
  local count
  count="$(rg -c --no-filename -- "$pattern" "$file" 2>/dev/null || true)"
  if [[ -z "$count" ]]; then
    echo 0
    return
  fi
  echo "$count"
}

run_scenario() {
  local scenario="$1"
  local base_port="$2"
  local allow_session_churn="$3"
  local log_file="$4"

  local dir_port=$((base_port + 1))
  local issuer_port=$((base_port + 2))
  local entry_port=$((base_port + 3))
  local exit_port=$((base_port + 4))
  local entry_data_port=$((base_port + 20))
  local exit_data_port=$((base_port + 21))

  local -a env_args=(
    "DIRECTORY_ADDR=127.0.0.1:${dir_port}"
    "ISSUER_ADDR=127.0.0.1:${issuer_port}"
    "ENTRY_ADDR=127.0.0.1:${entry_port}"
    "EXIT_ADDR=127.0.0.1:${exit_port}"
    "ENTRY_DATA_ADDR=127.0.0.1:${entry_data_port}"
    "EXIT_DATA_ADDR=127.0.0.1:${exit_data_port}"
    "ENTRY_ENDPOINT=127.0.0.1:${entry_data_port}"
    "EXIT_ENDPOINT=127.0.0.1:${exit_data_port}"
    "DIRECTORY_URL=http://127.0.0.1:${dir_port}"
    "ISSUER_URL=http://127.0.0.1:${issuer_port}"
    "ENTRY_URL=http://127.0.0.1:${entry_port}"
    "EXIT_CONTROL_URL=http://127.0.0.1:${exit_port}"
    "CLIENT_FORCE_DIRECT_EXIT=1"
    "CLIENT_ALLOW_DIRECT_EXIT_FALLBACK=1"
    "CLIENT_REQUIRE_DISTINCT_OPERATORS=0"
    "CLIENT_SESSION_REUSE=0"
    "CLIENT_BOOTSTRAP_INTERVAL_SEC=1"
    "CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC=1"
    "CLIENT_BOOTSTRAP_JITTER_PCT=0"
    "ISSUER_TOKEN_TTL_SEC=60"
  )
  if [[ -n "$allow_session_churn" ]]; then
    env_args+=("CLIENT_DIRECT_EXIT_ALLOW_SESSION_CHURN=$allow_session_churn")
  fi

  rm -f "$log_file"

  local run_rc
  set +e
  env "${env_args[@]}" timeout 30s go run ./cmd/node --directory --issuer --entry --exit --client >"$log_file" 2>&1
  run_rc=$?
  set -e
  if [[ "$run_rc" -ne 0 && "$run_rc" -ne 124 ]]; then
    echo "${scenario}: node run failed rc=${run_rc}"
    cat "$log_file"
    exit 1
  fi
  if rg -q "panic:" "$log_file"; then
    echo "${scenario}: unexpected panic in log"
    cat "$log_file"
    exit 1
  fi
}

GUARDED_LOG="/tmp/integration_session_churn_guard_guarded.log"
CHURN_LOG="/tmp/integration_session_churn_guard_churn.log"
GUARDED_BASE_PORT="${INTEGRATION_SESSION_CHURN_GUARD_BASE_PORT:-21300}"
CHURN_BASE_PORT="${INTEGRATION_SESSION_CHURN_GUARD_CHURN_BASE_PORT:-21400}"

run_scenario "guarded-default" "$GUARDED_BASE_PORT" "" "$GUARDED_LOG"

if ! rg -q "client direct-exit mode overriding CLIENT_SESSION_REUSE=0" "$GUARDED_LOG"; then
  echo "guarded-default: missing direct-exit override log"
  cat "$GUARDED_LOG"
  exit 1
fi
if ! rg -q "client role enabled: .*session_reuse=true.*min_refresh_sec=6.*direct_exit_forced=true" "$GUARDED_LOG"; then
  echo "guarded-default: missing forced session_reuse/min_refresh config signal"
  cat "$GUARDED_LOG"
  exit 1
fi
if ! rg -q "client selected entry=" "$GUARDED_LOG"; then
  echo "guarded-default: missing client selection log"
  cat "$GUARDED_LOG"
  exit 1
fi
if ! rg -q "client reused active session session=" "$GUARDED_LOG"; then
  echo "guarded-default: missing active-session reuse log"
  cat "$GUARDED_LOG"
  exit 1
fi

guarded_selected_count="$(count_matches "client selected entry=" "$GUARDED_LOG")"
guarded_reuse_count="$(count_matches "client reused active session session=" "$GUARDED_LOG")"
guarded_keep_count="$(count_matches "client keeping active session" "$GUARDED_LOG")"

if [[ "$guarded_selected_count" -gt 5 ]]; then
  echo "guarded-default: expected bounded selection churn, got selected_count=${guarded_selected_count}"
  cat "$GUARDED_LOG"
  exit 1
fi
if [[ "$guarded_reuse_count" -lt 1 ]]; then
  echo "guarded-default: expected at least one reuse cycle, got reuse_count=${guarded_reuse_count}"
  cat "$GUARDED_LOG"
  exit 1
fi
if [[ "$guarded_keep_count" -lt 1 ]]; then
  echo "guarded-default: expected active-session keep signal, got keep_count=${guarded_keep_count}"
  cat "$GUARDED_LOG"
  exit 1
fi

run_scenario "explicit-churn-override" "$CHURN_BASE_PORT" "1" "$CHURN_LOG"

if rg -q "client direct-exit mode overriding CLIENT_SESSION_REUSE=0" "$CHURN_LOG"; then
  echo "explicit-churn-override: unexpected direct-exit override log"
  cat "$CHURN_LOG"
  exit 1
fi
if ! rg -q "client role enabled: .*session_reuse=false.*min_refresh_sec=0.*direct_exit_forced=true" "$CHURN_LOG"; then
  echo "explicit-churn-override: missing explicit churn runtime config signal"
  cat "$CHURN_LOG"
  exit 1
fi

churn_selected_count="$(count_matches "client selected entry=" "$CHURN_LOG")"
churn_reuse_count="$(count_matches "client reused active session session=" "$CHURN_LOG")"
churn_keep_count="$(count_matches "client keeping active session" "$CHURN_LOG")"

if [[ "$churn_selected_count" -lt 4 ]]; then
  echo "explicit-churn-override: expected rapid open/close churn, got selected_count=${churn_selected_count}"
  cat "$CHURN_LOG"
  exit 1
fi
if [[ "$churn_reuse_count" -ne 0 ]]; then
  echo "explicit-churn-override: expected no reuse when churn override enabled, got reuse_count=${churn_reuse_count}"
  cat "$CHURN_LOG"
  exit 1
fi
if [[ "$churn_keep_count" -ne 0 ]]; then
  echo "explicit-churn-override: expected no active-session keep signal, got keep_count=${churn_keep_count}"
  cat "$CHURN_LOG"
  exit 1
fi

if [[ "$churn_selected_count" -le "$guarded_selected_count" ]]; then
  echo "expected churn override to increase selection churn (guarded=${guarded_selected_count} churn=${churn_selected_count})"
  cat "$GUARDED_LOG"
  cat "$CHURN_LOG"
  exit 1
fi

echo "session churn guard integration check ok (guarded_selected=${guarded_selected_count} guarded_reused=${guarded_reuse_count} churn_selected=${churn_selected_count})"
