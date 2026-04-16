#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in go curl jq mktemp awk grep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
FAKE_SCRIPT="$TMP_DIR/fake_easy_node.sh"
CALLS_FILE="$TMP_DIR/easy_node_calls.tsv"
SERVER_LOG="$TMP_DIR/local_api_server.log"
CFG_A="$TMP_DIR/easy_mode_config_a.conf"
CFG_B="$TMP_DIR/easy_mode_config_b.conf"
LOCAL_API_BASE=""
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cat >"$FAKE_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail

calls_file="${LOCAL_API_CONFIG_DEFAULTS_CALLS_FILE:?}"
cmd="${1:-}"
if [[ -z "$cmd" ]]; then
  echo "missing command" >&2
  exit 2
fi
shift || true

{
  printf '%s' "$cmd"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$calls_file"

case "$cmd" in
  client-vpn-status)
    echo '{"ok":true,"running":true,"interface":"wgvpn0"}'
    ;;
  client-vpn-preflight)
    echo "preflight ok"
    ;;
  client-vpn-up)
    echo "connect ok"
    ;;
  *)
    echo "$cmd ok"
    ;;
esac
EOF_FAKE
chmod +x "$FAKE_SCRIPT"

cat >"$CFG_A" <<'EOF_CFG_A'
EASY_MODE_CONFIG_VERSION=1
SIMPLE_CLIENT_PROFILE_DEFAULT=private
SIMPLE_CLIENT_INTERFACE=wgcfg3
SIMPLE_CLIENT_RUN_PREFLIGHT=0
SIMPLE_CLIENT_PROD_PROFILE_DEFAULT=1
EOF_CFG_A

cat >"$CFG_B" <<'EOF_CFG_B'
EASY_MODE_CONFIG_VERSION=1
SIMPLE_CLIENT_PROFILE_DEFAULT=speed-1hop
SIMPLE_CLIENT_INTERFACE=wgfast1
SIMPLE_CLIENT_RUN_PREFLIGHT=1
SIMPLE_CLIENT_PROD_PROFILE_DEFAULT=auto
EOF_CFG_B

pick_port() {
  local candidate=""
  local i=0
  for i in $(seq 1 50); do
    candidate="$((20000 + RANDOM % 20000))"
    if ! curl -fsS "http://127.0.0.1:${candidate}/v1/health" >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  echo "failed to pick free local API port" >&2
  return 1
}

wait_for_local_api() {
  local url="$1"
  local i=0
  for i in $(seq 1 120); do
    if curl -fsS "${url}/v1/health" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
      echo "local API process exited before readiness"
      cat "$SERVER_LOG"
      return 1
    fi
    sleep 0.1
  done
  echo "timeout waiting for local API readiness: ${url}"
  cat "$SERVER_LOG"
  return 1
}

start_local_api() {
  local config_path="$1"
  local port=""
  port="$(pick_port)"
  : >"$CALLS_FILE"
  : >"$SERVER_LOG"

  LOCAL_API_BASE="http://127.0.0.1:${port}"
  LOCAL_CONTROL_API_ADDR="127.0.0.1:${port}" \
  LOCAL_CONTROL_API_SCRIPT="$FAKE_SCRIPT" \
  LOCAL_CONTROL_API_ALLOW_UPDATE="0" \
  LOCAL_CONTROL_API_CONNECT_PATH_PROFILE="" \
  LOCAL_CONTROL_API_CONNECT_INTERFACE="" \
  LOCAL_CONTROL_API_CONNECT_RUN_PREFLIGHT="" \
  LOCAL_CONTROL_API_CONNECT_PROD_PROFILE_DEFAULT="" \
  SIMPLE_CLIENT_RUN_PREFLIGHT="" \
  SIMPLE_CLIENT_PROD_PROFILE_DEFAULT="" \
  CLIENT_PATH_PROFILE="" \
  CLIENT_WG_INTERFACE="" \
  LOCAL_API_CONFIG_DEFAULTS_CALLS_FILE="$CALLS_FILE" \
    go run ./cmd/node --local-api --config "$config_path" >"$SERVER_LOG" 2>&1 &
  SERVER_PID=$!

  wait_for_local_api "$LOCAL_API_BASE"
}

stop_local_api() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  SERVER_PID=""
}

api_post_json() {
  local path="$1"
  local payload="$2"
  curl -fsS -X POST -H 'Content-Type: application/json' --data "$payload" "${LOCAL_API_BASE}${path}"
}

call_count() {
  local command="$1"
  awk -F '\t' -v cmd="$command" '$1 == cmd { c++ } END { print c + 0 }' "$CALLS_FILE"
}

last_call() {
  local command="$1"
  awk -F '\t' -v cmd="$command" '$1 == cmd { line = $0 } END { if (line != "") print line }' "$CALLS_FILE"
}

require_last_call() {
  local command="$1"
  local line=""
  line="$(last_call "$command")"
  if [[ -z "$line" ]]; then
    echo "missing expected command call: $command"
    cat "$CALLS_FILE"
    exit 1
  fi
  printf '%s\n' "$line"
}

assert_line_has() {
  local line="$1"
  local pattern="$2"
  local message="$3"
  if ! printf '%s\n' "$line" | grep -F -- "$pattern" >/dev/null 2>&1; then
    echo "$message"
    echo "line: $line"
    echo "calls:"
    cat "$CALLS_FILE"
    exit 1
  fi
}

echo "[local-api-config-defaults] case A: config v1 maps profile/interface/preflight/prod defaults (private->3hop)"
start_local_api "$CFG_A"

connect_a_json="$(api_post_json "/v1/connect" '{"bootstrap_directory":"http://127.0.0.1:8081","invite_key":"inv-config-a"}')"
if ! jq -e '.ok == true and .stage == "connect" and .profile == "3hop"' <<<"$connect_a_json" >/dev/null; then
  echo "case A connect response mismatch"
  echo "$connect_a_json"
  exit 1
fi

if [[ "$(call_count "client-vpn-preflight")" != "0" ]]; then
  echo "case A expected no preflight call from SIMPLE_CLIENT_RUN_PREFLIGHT=0"
  cat "$CALLS_FILE"
  exit 1
fi

up_a_call="$(require_last_call "client-vpn-up")"
assert_line_has "$up_a_call" $'\t--subject\tinv-config-a' "case A missing invite subject"
assert_line_has "$up_a_call" $'\t--path-profile\t3hop' "case A missing 3hop profile default from config"
assert_line_has "$up_a_call" $'\t--interface\twgcfg3' "case A missing interface default from config"
assert_line_has "$up_a_call" $'\t--prod-profile\t1' "case A missing prod default=1 from config"
assert_line_has "$up_a_call" $'\t--install-route\t1' "case A unexpected install-route for 3hop"

stop_local_api

echo "[local-api-config-defaults] case B: config v1 maps speed-1hop defaults (preflight on, prod auto->0)"
start_local_api "$CFG_B"

connect_b_json="$(api_post_json "/v1/connect" '{"bootstrap_directory":"http://127.0.0.1:8081","invite_key":"inv-config-b"}')"
if ! jq -e '.ok == true and .stage == "connect" and .profile == "1hop"' <<<"$connect_b_json" >/dev/null; then
  echo "case B connect response mismatch"
  echo "$connect_b_json"
  exit 1
fi

if [[ "$(call_count "client-vpn-preflight")" != "1" ]]; then
  echo "case B expected one preflight call from SIMPLE_CLIENT_RUN_PREFLIGHT=1"
  cat "$CALLS_FILE"
  exit 1
fi

preflight_b_call="$(require_last_call "client-vpn-preflight")"
assert_line_has "$preflight_b_call" $'\t--interface\twgfast1' "case B preflight missing interface default from config"
assert_line_has "$preflight_b_call" $'\t--prod-profile\t0' "case B preflight missing prod auto->0 for 1hop"
assert_line_has "$preflight_b_call" $'\t--operator-floor-check\t0' "case B preflight missing 1hop operator floor policy"

up_b_call="$(require_last_call "client-vpn-up")"
assert_line_has "$up_b_call" $'\t--subject\tinv-config-b' "case B missing invite subject"
assert_line_has "$up_b_call" $'\t--path-profile\t1hop' "case B missing 1hop profile default from config"
assert_line_has "$up_b_call" $'\t--interface\twgfast1' "case B missing interface default from config"
assert_line_has "$up_b_call" $'\t--prod-profile\t0' "case B missing prod auto->0 for 1hop"
assert_line_has "$up_b_call" $'\t--install-route\t0' "case B missing 1hop install-route default"

stop_local_api

echo "local API config defaults integration check ok"
