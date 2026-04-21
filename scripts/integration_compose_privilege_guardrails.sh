#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BASE_COMPOSE="deploy/docker-compose.yml"
PRIV_OVERRIDE_COMPOSE="deploy/docker-compose.privileged.yml"
EASY_NODE_SCRIPT="scripts/easy_node.sh"

fail() {
  echo "compose privilege guardrails failed: $1" >&2
  exit 1
}

extract_service_block() {
  local file="$1"
  local service="$2"
  awk -v svc="$service" '
    BEGIN { in_service = 0 }
    $0 ~ "^  " svc ":" {
      in_service = 1
      next
    }
    in_service && $0 ~ "^  [A-Za-z0-9_.-]+:" {
      exit
    }
    in_service {
      print
    }
  ' "$file"
}

[[ -f "$BASE_COMPOSE" ]] || fail "missing base compose file: $BASE_COMPOSE"
[[ -f "$PRIV_OVERRIDE_COMPOSE" ]] || fail "missing privileged override compose file: $PRIV_OVERRIDE_COMPOSE"
[[ -f "$EASY_NODE_SCRIPT" ]] || fail "missing easy_node wrapper: $EASY_NODE_SCRIPT"

base_entry_block="$(extract_service_block "$BASE_COMPOSE" "entry-exit")"
[[ -n "$base_entry_block" ]] || fail "base compose is missing services.entry-exit block"

base_privileged_line="$(printf '%s\n' "$base_entry_block" | awk '/^[[:space:]]*privileged:[[:space:]]*/ { print; exit }')"
[[ -n "$base_privileged_line" ]] || fail "base compose services.entry-exit must declare privileged"
if [[ ! "$base_privileged_line" =~ ^[[:space:]]*privileged:[[:space:]]*false[[:space:]]*$ ]]; then
  fail "base compose services.entry-exit must hardcode privileged: false (found: $base_privileged_line)"
fi
if [[ "$base_privileged_line" == *'$'* || "$base_privileged_line" == *'{'* ]]; then
  fail "base compose services.entry-exit privileged must not interpolate env vars (found: $base_privileged_line)"
fi
if grep -q 'ENTRY_EXIT_PRIVILEGED' "$BASE_COMPOSE"; then
  fail "base compose must not reference ENTRY_EXIT_PRIVILEGED"
fi

override_entry_block="$(extract_service_block "$PRIV_OVERRIDE_COMPOSE" "entry-exit")"
[[ -n "$override_entry_block" ]] || fail "privileged override compose is missing services.entry-exit block"

override_privileged_line="$(printf '%s\n' "$override_entry_block" | awk '/^[[:space:]]*privileged:[[:space:]]*/ { print; exit }')"
[[ -n "$override_privileged_line" ]] || fail "privileged override compose must declare services.entry-exit privileged"
if [[ ! "$override_privileged_line" =~ ^[[:space:]]*privileged:[[:space:]]*true[[:space:]]*$ ]]; then
  fail "privileged override compose must set services.entry-exit privileged: true (found: $override_privileged_line)"
fi
if [[ "$override_privileged_line" == *'$'* || "$override_privileged_line" == *'{'* ]]; then
  fail "privileged override compose must not interpolate env vars for privileged (found: $override_privileged_line)"
fi

if ! grep -qF -- "docker-compose.privileged.yml" "$EASY_NODE_SCRIPT"; then
  fail "easy_node wrapper must reference docker-compose.privileged.yml override path"
fi
if ! grep -qF -- "ENTRY_EXIT_PRIVILEGED" "$EASY_NODE_SCRIPT"; then
  fail "easy_node wrapper must gate privileged override via ENTRY_EXIT_PRIVILEGED"
fi
if ! grep -qF -- "compose config error: ENTRY_EXIT_PRIVILEGED=true" "$EASY_NODE_SCRIPT"; then
  fail "easy_node wrapper must fail clearly when privileged override file is missing"
fi

echo "compose privilege guardrails integration check ok"
