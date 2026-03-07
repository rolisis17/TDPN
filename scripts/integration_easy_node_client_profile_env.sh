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
CLIENT_ENV_FILE="$ROOT_DIR/deploy/.env.easy.client"
CLIENT_ENV_BACKUP=""
mkdir -p "$TMP_BIN" "$LOG_DIR"

cleanup() {
  if [[ -n "$CLIENT_ENV_BACKUP" && -f "$CLIENT_ENV_BACKUP" ]]; then
    cp "$CLIENT_ENV_BACKUP" "$CLIENT_ENV_FILE"
  else
    rm -f "$CLIENT_ENV_FILE"
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

if [[ -f "$CLIENT_ENV_FILE" ]]; then
  CLIENT_ENV_BACKUP="$(mktemp)"
  cp "$CLIENT_ENV_FILE" "$CLIENT_ENV_BACKUP"
fi

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
  rm -f "$capture_file"
  PATH="$TMP_BIN:$PATH" \
  EASY_NODE_LOG_DIR="$LOG_DIR" \
  FAKE_DOCKER_CAPTURE_FILE="$capture_file" \
  ./scripts/easy_node.sh client-test \
    --directory-urls "http://dir-a:8081,http://dir-b:8081" \
    --issuer-url "http://issuer-a:8082" \
    --entry-url "http://entry-a:8083" \
    --exit-url "http://exit-a:8084" \
    --subject "integration-client" \
    --min-selection-lines 1 \
    --min-entry-operators 1 \
    --min-exit-operators 1 \
    --require-cross-operator-pair 1 \
    --timeout-sec 10 \
    --beta-profile "$beta_profile" \
    --prod-profile "$prod_profile" >/dev/null
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

echo "easy-node client profile env integration check ok"
