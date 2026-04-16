#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

for cmd in go rg timeout sed; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

LOG_FILE=/tmp/integration_client_3hop_runtime.log
rm -f "$LOG_FILE"

CLIENT_PATH_PROFILE=3hop \
CLIENT_BOOTSTRAP_INTERVAL_SEC=1 \
CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC=1 \
CLIENT_BOOTSTRAP_JITTER_PCT=0 \
timeout 40s go run ./cmd/node --directory --issuer --entry --exit --client >"$LOG_FILE" 2>&1 &
node_pid=$!
trap 'kill "$node_pid" >/dev/null 2>&1 || true' EXIT

startup_ok=0
for _ in $(seq 1 200); do
  if rg -q "client role enabled: .*path_profile=3hop.*middle_pref=true.*middle_required=true" "$LOG_FILE"; then
    startup_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$startup_ok" -ne 1 ]]; then
  echo "expected 3hop runtime config signal in client startup log"
  cat "$LOG_FILE"
  exit 1
fi

selected_with_middle=0
strict_middle_fail=0
for _ in $(seq 1 200); do
  if rg -q "client selected entry=.* middle=[^ ]+" "$LOG_FILE"; then
    selected_with_middle=1
    break
  fi
  if rg -q "client bootstrap (failed|retry failed): no suitable relay path found: middle-hop relay requirement not met" "$LOG_FILE"; then
    strict_middle_fail=1
    break
  fi
  sleep 0.2
done

if [[ "$selected_with_middle" -eq 1 ]]; then
  selected_line="$(rg -N "client selected entry=.* middle=[^ ]+" "$LOG_FILE" | tail -n1)"
  middle_relay="$(echo "$selected_line" | sed -E 's/.* middle=([^ ]+) .*/\1/')"
  if [[ -z "$middle_relay" || "$middle_relay" == "none" ]]; then
    echo "expected selected 3hop path to include non-empty middle relay"
    echo "$selected_line"
    cat "$LOG_FILE"
    exit 1
  fi
  echo "client 3hop runtime integration check ok (selected-middle=${middle_relay})"
  exit 0
fi

if [[ "$strict_middle_fail" -eq 1 ]]; then
  if rg -q "client selected entry=" "$LOG_FILE"; then
    echo "expected strict middle-hop requirement to prevent entry/exit-only selection"
    cat "$LOG_FILE"
    exit 1
  fi
  if ! rg -q "client middle-relay filter applied:" "$LOG_FILE"; then
    echo "expected middle-relay filter diagnostics when strict 3hop fails"
    cat "$LOG_FILE"
    exit 1
  fi
  echo "client 3hop runtime integration check ok (strict-middle-hop failure semantics observed)"
  exit 0
fi

echo "expected either middle-hop selection or strict middle-hop failure semantics"
cat "$LOG_FILE"
exit 1
