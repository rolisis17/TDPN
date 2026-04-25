#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCAN_ROOT="$ROOT_DIR"
TARGET_MODEL="${OPENAI_MODEL_POLICY_TARGET_MODEL:-gpt-5.5}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/openai_model_policy_guard.sh \
    [--root DIR] \
    [--target-model MODEL]

Description:
  Fail-closed guardrail for OpenAI model policy.

Policy:
  - Disallow legacy/pinned pre-migration model ids in runtime code/config paths.
  - If OpenAI runtime usage is present, require the target model string.

Defaults:
  --root .
  --target-model gpt-5.5
USAGE
}

require_value_or_die() {
  local flag="$1"
  local value="${2:-}"
  if [[ -z "$value" || "$value" == --* ]]; then
    echo "$flag requires a value"
    exit 2
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      require_value_or_die "$1" "${2:-}"
      SCAN_ROOT="${2:-}"
      shift 2
      ;;
    --root=*)
      SCAN_ROOT="${1#*=}"
      shift
      ;;
    --target-model)
      require_value_or_die "$1" "${2:-}"
      TARGET_MODEL="${2:-}"
      shift 2
      ;;
    --target-model=*)
      TARGET_MODEL="${1#*=}"
      shift
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

if ! command -v rg >/dev/null 2>&1; then
  echo "missing required command: rg"
  exit 2
fi

if [[ ! -d "$SCAN_ROOT" ]]; then
  echo "scan root missing: $SCAN_ROOT"
  exit 2
fi

cd "$SCAN_ROOT"

scan_paths=()
for p in apps cmd internal services scripts tools blockchain; do
  if [[ -e "$p" ]]; then
    scan_paths+=("$p")
  fi
done

if [[ "${#scan_paths[@]}" -eq 0 ]]; then
  echo "[openai-model-policy-guard] no runtime source paths found under scan root; skipping"
  exit 0
fi

common_globs=(
  --hidden
  --glob '!.git/**'
  --glob '!User/**'
  --glob '!.vscode/**'
  --glob '!node_modules/**'
  --glob '!dist/**'
  --glob '!build/**'
  --glob '!vendor/**'
  --glob '!docs/**'
  --glob '!scripts/openai_model_policy_guard.sh'
  --glob '!scripts/integration_openai_model_policy_guard.sh'
)

disallowed_models_regex='gpt-4o|gpt-4\.1([-_.](mini|nano))?|gpt-4([-_.][[:alnum:]]+)?|gpt-3\.5([-_.][[:alnum:]]+)?|gpt-5\.(0|1|2|3|4)([-_.][[:alnum:]]+)?'

if rg -n "${common_globs[@]}" -e "$disallowed_models_regex" "${scan_paths[@]}" >/tmp/openai_model_policy_disallowed_hits.log 2>/dev/null; then
  echo "[openai-model-policy-guard] disallowed model ids found in runtime paths:"
  cat /tmp/openai_model_policy_disallowed_hits.log
  exit 1
fi

openai_usage_regex='OPENAI_API_KEY|api\.openai\.com|responses\.create|chat\.completions|new[[:space:]]+OpenAI[[:space:]]*\(|from[[:space:]]+["'"'"']openai["'"'"']|require\(["'"'"']openai["'"'"']\)'
openai_usage_found=0
if rg -n "${common_globs[@]}" -e "$openai_usage_regex" "${scan_paths[@]}" >/tmp/openai_model_policy_usage_hits.log 2>/dev/null; then
  openai_usage_found=1
fi

if [[ "$openai_usage_found" == "1" ]]; then
  target_model_regex="$(printf '%s' "$TARGET_MODEL" | sed -E 's/[][\.^$*+?(){}|/]/\\&/g')"
  if ! rg -n "${common_globs[@]}" -e "$target_model_regex" "${scan_paths[@]}" >/tmp/openai_model_policy_target_hits.log 2>/dev/null; then
    echo "[openai-model-policy-guard] OpenAI usage detected but target model '$TARGET_MODEL' was not found in runtime paths."
    echo "[openai-model-policy-guard] usage hits:"
    cat /tmp/openai_model_policy_usage_hits.log
    exit 1
  fi
fi

echo "[openai-model-policy-guard] status=ok target_model=$TARGET_MODEL openai_usage_found=$openai_usage_found"

