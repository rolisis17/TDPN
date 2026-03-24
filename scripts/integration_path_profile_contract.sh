#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

EASY_NODE="scripts/easy_node.sh"
EASY_MODE_UI="tools/easy_mode/easy_mode_ui.cpp"
USAGE_WRAPPERS=(
  "scripts/client_vpn_smoke.sh"
  "scripts/beta_pilot_runbook.sh"
  "scripts/integration_3machine_beta_validate.sh"
  "scripts/integration_3machine_beta_soak.sh"
  "scripts/integration_machine_c_client_check.sh"
)

check_fixed() {
  local file="$1"
  local needle="$2"
  local message="$3"
  if ! rg -Fq -- "$needle" "$file"; then
    echo "$message"
    exit 1
  fi
}

check_absent_regex() {
  local pattern="$1"
  local message="$2"
  shift 2
  local files=("$@")
  if rg -n -- "$pattern" "${files[@]}" >/dev/null 2>&1; then
    echo "$message"
    rg -n -- "$pattern" "${files[@]}"
    exit 1
  fi
}

echo "[path-profile-contract] easy_node usage exposes canonical public profiles"
check_fixed "$EASY_NODE" "[--path-profile speed|speed-1hop|balanced|private]" \
  "path-profile contract failed: easy_node client-test usage is not canonical"
check_fixed "$EASY_NODE" "[--path-profile speed|balanced|private]" \
  "path-profile contract failed: easy_node usage missing canonical non-experimental path-profile contract"
check_absent_regex '\[--path-profile [^]]*fast\|privacy' \
  "path-profile contract failed: easy_node usage still exposes legacy aliases in public profile list" \
  "$EASY_NODE"

echo "[path-profile-contract] wrapper usages expose canonical public profiles"
for wrapper in "${USAGE_WRAPPERS[@]}"; do
  check_fixed "$wrapper" "[--path-profile speed|balanced|private]" \
    "path-profile contract failed: ${wrapper} usage is not canonical"
done
check_absent_regex '\[--path-profile [^]]*fast\|privacy' \
  "path-profile contract failed: one or more wrapper usage blocks still expose legacy aliases in public profile list" \
  "${USAGE_WRAPPERS[@]}"

echo "[path-profile-contract] launcher prompts use Speed/Balanced/Private contract"
check_fixed "$EASY_MODE_UI" "Path profile (1=Speed, 2=Balanced, 3=Private)" \
  "path-profile contract failed: easy-mode launcher prompt is not canonical"
check_fixed "$EASY_MODE_UI" "  1) Speed     :" \
  "path-profile contract failed: easy-mode launcher speed preset label missing"
check_fixed "$EASY_MODE_UI" "  2) Balanced  :" \
  "path-profile contract failed: easy-mode launcher balanced preset label missing"
check_fixed "$EASY_MODE_UI" "  3) Private   :" \
  "path-profile contract failed: easy-mode launcher private preset label missing"

echo "[path-profile-contract] legacy aliases remain compatibility-only internals"
check_fixed "$EASY_NODE" "speed|fast)" \
  "path-profile contract failed: easy_node no longer accepts legacy alias fast"
check_fixed "$EASY_NODE" "private|privacy)" \
  "path-profile contract failed: easy_node no longer accepts legacy alias privacy"
check_fixed "$EASY_NODE" "legacy aliases: fast, privacy" \
  "path-profile contract failed: easy_node no longer documents legacy alias compatibility in validation errors"

echo "path profile contract integration check ok"
