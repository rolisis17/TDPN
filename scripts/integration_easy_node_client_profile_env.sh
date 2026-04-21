#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash rg timeout; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
TMP_BIN="$TMP_DIR/bin"
LOG_DIR="$TMP_DIR/logs"
CLIENT_ENV_FILE="$TMP_DIR/.env.easy.client"
mkdir -p "$TMP_BIN" "$LOG_DIR"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cat >"$TMP_BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
printf '{}\n'
EOF_CURL

cat >"$TMP_BIN/docker" <<'EOF_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${FAKE_DOCKER_CAPTURE_FILE:-}"
if [[ -n "$capture_file" ]]; then
  printf '%s\n' "$*" >>"$capture_file"
fi

if [[ "${1:-}" == "image" && "${2:-}" == "inspect" ]]; then
  exit 0
fi

if [[ "${1:-}" == "ps" && "${2:-}" == "-aq" ]]; then
  args=" $* "
  if [[ "$args" == *"deploy-client-demo-run-"* ]]; then
    printf 'demo-run-id\n'
  fi
  exit 0
fi

if [[ "${1:-}" == "compose" ]]; then
  args=" $* "
  if [[ "$args" == *" run "* ]]; then
    printf '2026/01/01 client selected entry=entry-op-a (http://entry-a) exit=exit-op-b (http://exit-b) entry_op=op-a exit_op=op-b token_exp=1\n'
    exit 0
  fi
  if [[ "$args" == *" build "* ]]; then
    exit 0
  fi
  if [[ "$args" == *" version "* ]]; then
    printf 'Docker Compose version vtest\n'
    exit 0
  fi
fi

if [[ "${1:-}" == "--version" ]]; then
  printf 'Docker version test\n'
  exit 0
fi

if [[ "${1:-}" == "info" ]]; then
  exit 0
fi

exit 0
EOF_DOCKER

chmod +x "$TMP_BIN/curl" "$TMP_BIN/docker"

run_client_test_capture() {
  local capture_file="$1"
  local beta_profile="$2"
  local prod_profile="$3"
  shift 3
  rm -f "$capture_file"
  PATH="$TMP_BIN:$PATH" \
  EASY_NODE_LOG_DIR="$LOG_DIR" \
  EASY_NODE_CLIENT_ENV_FILE="$CLIENT_ENV_FILE" \
  FAKE_DOCKER_CAPTURE_FILE="$capture_file" \
  ./scripts/easy_node.sh client-test \
    --directory-urls "https://dir-a:8081,https://dir-b:8081" \
    --issuer-url "https://issuer-a:8082" \
    --entry-url "https://entry-a:8083" \
    --exit-url "https://exit-a:8084" \
    --subject "integration-client" \
    --min-selection-lines 1 \
    --min-entry-operators 1 \
    --min-exit-operators 1 \
    --require-cross-operator-pair 1 \
    --timeout-sec 10 \
    --beta-profile "$beta_profile" \
    --prod-profile "$prod_profile" \
    "$@" >/dev/null
}

run_client_test_expect_fail() {
  local output_file="$1"
  local beta_profile="$2"
  local prod_profile="$3"
  shift 3
  set +e
  PATH="$TMP_BIN:$PATH" \
  EASY_NODE_LOG_DIR="$LOG_DIR" \
  EASY_NODE_CLIENT_ENV_FILE="$CLIENT_ENV_FILE" \
  FAKE_DOCKER_CAPTURE_FILE="$TMP_DIR/fail_capture.log" \
  ./scripts/easy_node.sh client-test \
    --directory-urls "https://dir-a:8081,https://dir-b:8081" \
    --issuer-url "https://issuer-a:8082" \
    --entry-url "https://entry-a:8083" \
    --exit-url "https://exit-a:8084" \
    --subject "integration-client" \
    --min-selection-lines 1 \
    --min-entry-operators 1 \
    --min-exit-operators 1 \
    --require-cross-operator-pair 1 \
    --timeout-sec 10 \
    --beta-profile "$beta_profile" \
    --prod-profile "$prod_profile" \
    "$@" >"$output_file" 2>&1
  local rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    echo "expected client-test failure but command succeeded"
    cat "$output_file"
    exit 1
  fi
}

BETA_CAPTURE="$TMP_DIR/beta_capture.log"
run_client_test_capture "$BETA_CAPTURE" "1" "0"
if ! rg -q -- "-e DIRECTORY_MIN_OPERATORS=2" "$BETA_CAPTURE"; then
  echo "missing expected beta-profile directory operator floor env"
  cat "$BETA_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_DIRECTORY_MIN_OPERATORS=2" "$BETA_CAPTURE"; then
  echo "missing expected beta-profile client directory operator floor env"
  cat "$BETA_CAPTURE"
  exit 1
fi
if rg -q -- "-e BETA_STRICT_MODE=1" "$BETA_CAPTURE"; then
  echo "unexpected strict-mode env injected for client-test beta profile"
  cat "$BETA_CAPTURE"
  exit 1
fi
if rg -q -- "-e PROD_STRICT_MODE=1" "$BETA_CAPTURE"; then
  echo "unexpected prod strict-mode env injected for client-test beta profile"
  cat "$BETA_CAPTURE"
  exit 1
fi
beta_cleanup_count="$(rg -c -- "rm -f demo-run-id" "$BETA_CAPTURE" || echo "0")"
if [[ -z "$beta_cleanup_count" || "$beta_cleanup_count" -lt 2 ]]; then
  echo "missing expected pre/post client demo cleanup calls in beta profile (rm count=$beta_cleanup_count)"
  cat "$BETA_CAPTURE"
  exit 1
fi

PROD_CAPTURE="$TMP_DIR/prod_capture.log"
run_client_test_capture "$PROD_CAPTURE" "0" "1"
if ! rg -q -- "-e MTLS_ENABLE=1" "$PROD_CAPTURE"; then
  echo "missing expected prod-profile mTLS env"
  cat "$PROD_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e DIRECTORY_TRUST_STRICT=1" "$PROD_CAPTURE"; then
  echo "missing expected prod-profile trust strict env"
  cat "$PROD_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e DIRECTORY_TRUST_TOFU=0" "$PROD_CAPTURE"; then
  echo "missing expected prod-profile trust tofu disable env"
  cat "$PROD_CAPTURE"
  exit 1
fi
if rg -q -- "-e BETA_STRICT_MODE=1" "$PROD_CAPTURE"; then
  echo "unexpected strict-mode env injected for client-test prod profile"
  cat "$PROD_CAPTURE"
  exit 1
fi
if rg -q -- "-e PROD_STRICT_MODE=1" "$PROD_CAPTURE"; then
  echo "unexpected prod strict-mode env injected for client-test prod profile"
  cat "$PROD_CAPTURE"
  exit 1
fi
prod_cleanup_count="$(rg -c -- "rm -f demo-run-id" "$PROD_CAPTURE" || echo "0")"
if [[ -z "$prod_cleanup_count" || "$prod_cleanup_count" -lt 2 ]]; then
  echo "missing expected pre/post client demo cleanup calls in prod profile (rm count=$prod_cleanup_count)"
  cat "$PROD_CAPTURE"
  exit 1
fi

PATH_PROFILE_CAPTURE="$TMP_DIR/path_profile_capture.log"
run_client_test_capture "$PATH_PROFILE_CAPTURE" "0" "0" --path-profile private
if ! rg -q -- "-e CLIENT_REQUIRE_DISTINCT_OPERATORS=1" "$PATH_PROFILE_CAPTURE"; then
  echo "missing expected path-profile distinct operators env"
  cat "$PATH_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_REQUIRE_DISTINCT_ENTRY_EXIT_COUNTRY=1" "$PATH_PROFILE_CAPTURE"; then
  echo "missing expected path-profile distinct countries env"
  cat "$PATH_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_EXIT_LOCALITY_SOFT_BIAS=0" "$PATH_PROFILE_CAPTURE"; then
  echo "missing expected path-profile locality soft-bias env"
  cat "$PATH_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_EXIT_COUNTRY_BIAS=1.60" "$PATH_PROFILE_CAPTURE"; then
  echo "missing expected path-profile country-bias env"
  cat "$PATH_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_EXIT_REGION_BIAS=1.25" "$PATH_PROFILE_CAPTURE"; then
  echo "missing expected path-profile region-bias env"
  cat "$PATH_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_EXIT_REGION_PREFIX_BIAS=1.10" "$PATH_PROFILE_CAPTURE"; then
  echo "missing expected path-profile region-prefix-bias env"
  cat "$PATH_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_PATH_PROFILE=3hop" "$PATH_PROFILE_CAPTURE"; then
  echo "missing expected private-profile canonical path-profile env"
  cat "$PATH_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_STICKY_PAIR_SEC=420" "$PATH_PROFILE_CAPTURE"; then
  echo "missing expected private-profile sticky-pair env"
  cat "$PATH_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_ENTRY_ROTATION_SEC=240" "$PATH_PROFILE_CAPTURE"; then
  echo "missing expected private-profile entry-rotation env"
  cat "$PATH_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_ENTRY_ROTATION_JITTER_PCT=10" "$PATH_PROFILE_CAPTURE"; then
  echo "missing expected private-profile entry-rotation-jitter env"
  cat "$PATH_PROFILE_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_EXIT_EXPLORATION_PCT=5" "$PATH_PROFILE_CAPTURE"; then
  echo "missing expected private-profile exit-exploration env"
  cat "$PATH_PROFILE_CAPTURE"
  exit 1
fi

PATH_PROFILE_SPEED_CAPTURE="$TMP_DIR/path_profile_speed_capture.log"
run_client_test_capture "$PATH_PROFILE_SPEED_CAPTURE" "0" "0" --path-profile speed
if ! rg -q -- "-e CLIENT_EXIT_COUNTRY_BIAS=1.80" "$PATH_PROFILE_SPEED_CAPTURE"; then
  echo "missing expected speed-profile country-bias env"
  cat "$PATH_PROFILE_SPEED_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_EXIT_REGION_BIAS=1.35" "$PATH_PROFILE_SPEED_CAPTURE"; then
  echo "missing expected speed-profile region-bias env"
  cat "$PATH_PROFILE_SPEED_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_EXIT_REGION_PREFIX_BIAS=1.15" "$PATH_PROFILE_SPEED_CAPTURE"; then
  echo "missing expected speed-profile region-prefix-bias env"
  cat "$PATH_PROFILE_SPEED_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_REQUIRE_DISTINCT_ENTRY_EXIT_COUNTRY=0" "$PATH_PROFILE_SPEED_CAPTURE"; then
  echo "missing expected speed-profile distinct-country env"
  cat "$PATH_PROFILE_SPEED_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_PATH_PROFILE=2hop" "$PATH_PROFILE_SPEED_CAPTURE"; then
  echo "missing expected speed-profile canonical path-profile env"
  cat "$PATH_PROFILE_SPEED_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_STICKY_PAIR_SEC=180" "$PATH_PROFILE_SPEED_CAPTURE"; then
  echo "missing expected speed-profile sticky-pair env"
  cat "$PATH_PROFILE_SPEED_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_ENTRY_ROTATION_SEC=120" "$PATH_PROFILE_SPEED_CAPTURE"; then
  echo "missing expected speed-profile entry-rotation env"
  cat "$PATH_PROFILE_SPEED_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_ENTRY_ROTATION_JITTER_PCT=20" "$PATH_PROFILE_SPEED_CAPTURE"; then
  echo "missing expected speed-profile entry-rotation-jitter env"
  cat "$PATH_PROFILE_SPEED_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_EXIT_EXPLORATION_PCT=25" "$PATH_PROFILE_SPEED_CAPTURE"; then
  echo "missing expected speed-profile exit-exploration env"
  cat "$PATH_PROFILE_SPEED_CAPTURE"
  exit 1
fi

PATH_PROFILE_SPEED_1HOP_CAPTURE="$TMP_DIR/path_profile_speed_1hop_capture.log"
run_client_test_capture "$PATH_PROFILE_SPEED_1HOP_CAPTURE" "0" "0" --path-profile speed-1hop
if ! rg -q -- "-e CLIENT_REQUIRE_DISTINCT_OPERATORS=0" "$PATH_PROFILE_SPEED_1HOP_CAPTURE"; then
  echo "missing expected speed-1hop distinct-operators env"
  cat "$PATH_PROFILE_SPEED_1HOP_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_ALLOW_DIRECT_EXIT_FALLBACK=1" "$PATH_PROFILE_SPEED_1HOP_CAPTURE"; then
  echo "missing expected speed-1hop direct-exit fallback env"
  cat "$PATH_PROFILE_SPEED_1HOP_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_FORCE_DIRECT_EXIT=1" "$PATH_PROFILE_SPEED_1HOP_CAPTURE"; then
  echo "missing expected speed-1hop force-direct env"
  cat "$PATH_PROFILE_SPEED_1HOP_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_PATH_PROFILE=1hop" "$PATH_PROFILE_SPEED_1HOP_CAPTURE"; then
  echo "missing expected speed-1hop canonical path-profile env"
  cat "$PATH_PROFILE_SPEED_1HOP_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_STICKY_PAIR_SEC=300" "$PATH_PROFILE_SPEED_1HOP_CAPTURE"; then
  echo "missing expected speed-1hop sticky-pair env"
  cat "$PATH_PROFILE_SPEED_1HOP_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_ENTRY_ROTATION_SEC=120" "$PATH_PROFILE_SPEED_1HOP_CAPTURE"; then
  echo "missing expected speed-1hop entry-rotation env"
  cat "$PATH_PROFILE_SPEED_1HOP_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_ENTRY_ROTATION_JITTER_PCT=20" "$PATH_PROFILE_SPEED_1HOP_CAPTURE"; then
  echo "missing expected speed-1hop entry-rotation-jitter env"
  cat "$PATH_PROFILE_SPEED_1HOP_CAPTURE"
  exit 1
fi
if ! rg -q -- "-e CLIENT_EXIT_EXPLORATION_PCT=20" "$PATH_PROFILE_SPEED_1HOP_CAPTURE"; then
  echo "missing expected speed-1hop exit-exploration env"
  cat "$PATH_PROFILE_SPEED_1HOP_CAPTURE"
  exit 1
fi

MIDDLE_RELAY_CAPTURE="$TMP_DIR/middle_relay_capture.log"
CLIENT_REQUIRE_MIDDLE_RELAY=0 run_client_test_capture "$MIDDLE_RELAY_CAPTURE" "0" "0" --path-profile private
if ! rg -q -- "-e CLIENT_REQUIRE_MIDDLE_RELAY=0" "$MIDDLE_RELAY_CAPTURE"; then
  echo "missing expected CLIENT_REQUIRE_MIDDLE_RELAY passthrough env when set"
  cat "$MIDDLE_RELAY_CAPTURE"
  exit 1
fi

SPEED_1HOP_BETA_FAIL_LOG="$TMP_DIR/speed_1hop_beta_fail.log"
run_client_test_expect_fail "$SPEED_1HOP_BETA_FAIL_LOG" "1" "0" --path-profile speed-1hop
if ! rg -q -- "client-test --path-profile 1hop/speed-1hop requires --beta-profile 0 and --prod-profile 0" "$SPEED_1HOP_BETA_FAIL_LOG"; then
  echo "missing expected speed-1hop strict-profile guardrail message"
  cat "$SPEED_1HOP_BETA_FAIL_LOG"
  exit 1
fi

echo "easy-node client profile env integration check ok"
