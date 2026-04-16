#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MEMORY_ALLOWLIST_FILE="pkg/settlement/memory.go"
BRIDGE_ALLOWLIST_FILE="blockchain/tdpn-chain/cmd/tdpnd/settlement_bridge.go"
CHAIN_ALLOWLIST_FILE="blockchain/tdpn-chain/x/vpnslashing/types/records.go"

extract_allowlist_keys() {
  local file_path="$1"
  local variable_name="$2"

  awk -v variable_name="$variable_name" '
    BEGIN {
      in_map = 0
      found = 0
    }
    {
      if (!in_map && $0 ~ ("^[[:space:]]*var[[:space:]]+" variable_name "[[:space:]]*=[[:space:]]*map\\[string\\]struct\\{\\}[[:space:]]*\\{")) {
        in_map = 1
        found = 1
        next
      }
      if (in_map) {
        if ($0 ~ /^[[:space:]]*}[[:space:]]*$/) {
          in_map = 0
          exit
        }
        if (match($0, /"[^"]+"[[:space:]]*:/)) {
          entry = substr($0, RSTART, RLENGTH)
          sub(/:.*/, "", entry)
          gsub(/"/, "", entry)
          gsub(/[[:space:]]+/, "", entry)
          if (entry != "") {
            print entry
          }
        }
      }
    }
    END {
      if (!found) {
        printf("allowlist variable not found: %s\n", variable_name) > "/dev/stderr"
        exit 1
      }
      if (in_map) {
        printf("allowlist map was not closed for variable: %s\n", variable_name) > "/dev/stderr"
        exit 1
      }
    }
  ' "$file_path" | sort -u
}

memory_allowlist="$(
  extract_allowlist_keys "$MEMORY_ALLOWLIST_FILE" "supportedObjectiveViolationTypes"
)"
bridge_allowlist="$(
  extract_allowlist_keys "$BRIDGE_ALLOWLIST_FILE" "bridgeObjectiveViolationTypeSet"
)"
chain_allowlist="$(
  extract_allowlist_keys "$CHAIN_ALLOWLIST_FILE" "objectiveViolationTypeSet"
)"

if [[ "$memory_allowlist" != "$bridge_allowlist" || "$memory_allowlist" != "$chain_allowlist" ]]; then
  echo "slash violation-type allowlist drift detected across settlement, bridge, and chain"
  echo "--- ${MEMORY_ALLOWLIST_FILE}:supportedObjectiveViolationTypes ---"
  if [[ -n "$memory_allowlist" ]]; then
    printf '%s\n' "$memory_allowlist"
  else
    echo "(empty)"
  fi
  echo "--- ${BRIDGE_ALLOWLIST_FILE}:bridgeObjectiveViolationTypeSet ---"
  if [[ -n "$bridge_allowlist" ]]; then
    printf '%s\n' "$bridge_allowlist"
  else
    echo "(empty)"
  fi
  echo "--- ${CHAIN_ALLOWLIST_FILE}:objectiveViolationTypeSet ---"
  if [[ -n "$chain_allowlist" ]]; then
    printf '%s\n' "$chain_allowlist"
  else
    echo "(empty)"
  fi
  exit 1
fi

echo "slash violation-type allowlist consistency check ok"
