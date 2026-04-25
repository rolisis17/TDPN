#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SCRIPT_UNDER_TEST="./scripts/openai_model_policy_guard.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

run_expect_fail() {
  local label="$1"
  local expected_regex="$2"
  shift 2
  local log_path="$TMP_DIR/${label}.log"
  set +e
  "$@" >"$log_path" 2>&1
  local rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    echo "expected failure for $label"
    cat "$log_path"
    exit 1
  fi
  if ! rg -q -- "$expected_regex" "$log_path"; then
    echo "missing expected error output for $label"
    cat "$log_path"
    exit 1
  fi
}

run_expect_success() {
  local label="$1"
  shift
  local log_path="$TMP_DIR/${label}.log"
  if ! "$@" >"$log_path" 2>&1; then
    echo "expected success for $label"
    cat "$log_path"
    exit 1
  fi
}

echo "[openai-model-policy-guard] baseline repository policy scan passes"
run_expect_success "baseline_repo" bash "$SCRIPT_UNDER_TEST"

echo "[openai-model-policy-guard] disallowed model string fails closed"
FIXTURE_DISALLOWED="$TMP_DIR/disallowed_model_fixture"
mkdir -p "$FIXTURE_DISALLOWED/apps/demo"
cat >"$FIXTURE_DISALLOWED/apps/demo/main.js" <<'EOF'
const model = "gpt-4.1";
console.log(model);
EOF
run_expect_fail \
  "disallowed_model" \
  "disallowed model ids found" \
  bash "$SCRIPT_UNDER_TEST" --root "$FIXTURE_DISALLOWED"

echo "[openai-model-policy-guard] OpenAI usage without target model fails closed"
FIXTURE_USAGE_NO_TARGET="$TMP_DIR/usage_no_target_fixture"
mkdir -p "$FIXTURE_USAGE_NO_TARGET/apps/demo"
cat >"$FIXTURE_USAGE_NO_TARGET/apps/demo/main.js" <<'EOF'
import OpenAI from "openai";
const client = new OpenAI();
console.log(client);
EOF
run_expect_fail \
  "usage_without_target_model" \
  "OpenAI usage detected but target model 'gpt-5.5'" \
  bash "$SCRIPT_UNDER_TEST" --root "$FIXTURE_USAGE_NO_TARGET"

echo "[openai-model-policy-guard] OpenAI usage with target model passes"
FIXTURE_USAGE_WITH_TARGET="$TMP_DIR/usage_with_target_fixture"
mkdir -p "$FIXTURE_USAGE_WITH_TARGET/apps/demo"
cat >"$FIXTURE_USAGE_WITH_TARGET/apps/demo/main.js" <<'EOF'
import OpenAI from "openai";
const client = new OpenAI();
const request = { model: "gpt-5.5" };
console.log(client, request);
EOF
run_expect_success \
  "usage_with_target_model" \
  bash "$SCRIPT_UNDER_TEST" --root "$FIXTURE_USAGE_WITH_TARGET"

echo "openai model policy guard integration check ok"

