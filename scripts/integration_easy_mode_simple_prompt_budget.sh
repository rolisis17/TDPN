#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in g++ mktemp grep awk wc tr; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
TMP_ROOT="$TMP_DIR/fake_root"
BIN="$TMP_DIR/easy_mode_ui"
INSTRUMENTED_CPP="$TMP_DIR/easy_mode_ui_prompt_budget.cpp"
CAPTURE="$TMP_DIR/easy_node_calls.log"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

mkdir -p "$TMP_ROOT/scripts" "$TMP_ROOT/data" "$TMP_ROOT/deploy/config"

cat >"$TMP_ROOT/deploy/config/easy_mode_config_v1.conf" <<'EOF_CFG'
EASY_MODE_CONFIG_VERSION=1
SIMPLE_CLIENT_PROFILE_DEFAULT=2hop
SIMPLE_CLIENT_REAL_VPN_DEFAULT=0
SIMPLE_CLIENT_DISCOVERY_WAIT_SEC=20
SIMPLE_CLIENT_PROD_PROFILE_DEFAULT=auto
SIMPLE_CLIENT_RUN_PREFLIGHT=1
SIMPLE_CLIENT_OPEN_TERMINAL=0
SIMPLE_CLIENT_PREFLIGHT_USE_SUDO=0
SIMPLE_CLIENT_SESSION_USE_SUDO=0
SIMPLE_CLIENT_PROMPT_REAL_VPN_IN_SIMPLE=0
SIMPLE_SERVER_PROD_PROFILE_DEFAULT=1
SIMPLE_SERVER_RUN_PREFLIGHT=1
SIMPLE_SERVER_SESSION_USE_SUDO=0
SIMPLE_SERVER_PEER_IDENTITY_STRICT=auto
SIMPLE_SERVER_PREFLIGHT_TIMEOUT_SEC=8
SIMPLE_SERVER_AUTO_INVITE=1
SIMPLE_SERVER_AUTO_INVITE_COUNT=1
SIMPLE_SERVER_AUTO_INVITE_TIER=1
SIMPLE_SERVER_AUTO_INVITE_WAIT_SEC=10
EOF_CFG

cat >"$TMP_ROOT/data/easy_mode_hosts.conf" <<'EOF_HOSTS'
MACHINE_A_HOST=198.51.100.10
MACHINE_B_HOST=203.0.113.20
EOF_HOSTS

cat >"$TMP_ROOT/scripts/easy_node.sh" <<'EOF_FAKE_EASY'
#!/usr/bin/env bash
set -euo pipefail
subcommand="${1:-}"
if [[ $# -gt 0 ]]; then
  shift
fi
printf '%s\n' "${subcommand}${*:+ }$*" >>"${EASY_MODE_RUNTIME_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_EASY
chmod +x "$TMP_ROOT/scripts/easy_node.sh"

assert_absent() {
  local file="$1"
  local needle="$2"
  local message="$3"
  if grep -Fq "$needle" "$file"; then
    echo "$message"
    echo "--- output ---"
    cat "$file"
    exit 1
  fi
}

count_prompt_emissions() {
  local trace_file="$1"
  if [[ ! -f "$trace_file" ]]; then
    echo "0"
    return
  fi
  wc -l <"$trace_file" | tr -d '[:space:]'
}

assert_prompt_count() {
  local trace_file="$1"
  local flow_name="$2"
  local expected="$3"
  local total

  total="$(count_prompt_emissions "$trace_file")"

  if [[ "$total" -eq 0 ]]; then
    echo "${flow_name} prompt budget regression: observed zero prompt emissions (harness stale or launcher output changed)"
    if [[ -f "$trace_file" ]]; then
      echo "--- prompt trace ---"
      cat "$trace_file"
    fi
    exit 1
  fi

  if (( total != expected )); then
    echo "${flow_name} prompt-count mismatch: observed=${total}, expected=${expected}"
    echo "--- prompt trace ---"
    cat "$trace_file"
    exit 1
  fi

  echo "[easy-mode-simple-prompt-budget] ${flow_name}: prompts=${total} expected=${expected}"
}

run_ui() {
  local input_file="$1"
  local out_file="$2"
  local prompt_trace="$3"
  EASY_MODE_RUNTIME_CAPTURE_FILE="$CAPTURE" \
  EASY_MODE_PROMPT_TRACE_FILE="$prompt_trace" \
  PRIVACYNODE_ALLOW_ENV_ROOT=1 \
  PRIVACYNODE_ROOT="$TMP_ROOT" \
  "$BIN" <"$input_file" >"$out_file" 2>&1
}

echo "[easy-mode-simple-prompt-budget] compile launcher"
awk '
BEGIN {
  inserted_trace_helper = 0
}
{
  if (!inserted_trace_helper && $0 ~ /^std::string readLine\(const std::string &prompt, const std::string &def = ""\) \{$/) {
    print "void promptBudgetTrace(const std::string &prompt) {"
    print "  const char *traceFile = std::getenv(\"EASY_MODE_PROMPT_TRACE_FILE\");"
    print "  if (!traceFile || *traceFile == '\''\\0'\'') {"
    print "    return;"
    print "  }"
    print "  std::ofstream out(traceFile, std::ios::app);"
    print "  if (!out) {"
    print "    return;"
    print "  }"
    print "  out << prompt << \"\\n\";"
    print "}"
    print ""
    inserted_trace_helper = 1
  }
  print $0
  if ($0 ~ /^std::string readLine\(const std::string &prompt, const std::string &def = ""\) \{$/) {
    print "  promptBudgetTrace(prompt);"
  }
  if ($0 ~ /^std::string readOptionalLine\(const std::string &prompt, const std::string &suggested = ""\) \{$/) {
    print "  promptBudgetTrace(prompt);"
  }
}
' tools/easy_mode/easy_mode_ui.cpp >"$INSTRUMENTED_CPP"
g++ -std=c++17 -O2 -o "$BIN" "$INSTRUMENTED_CPP"

echo "[easy-mode-simple-prompt-budget] option 1 prompt budget"
: >"$CAPTURE"
INPUT_CLIENT="$TMP_DIR/input_client.txt"
{
  printf '1\n'
  printf '\n'
  printf 'inv-prompt-budget\n'
  printf '\n'
  printf '0\n'
} >"$INPUT_CLIENT"
CLIENT_OUT="$TMP_DIR/client.log"
CLIENT_PROMPT_TRACE="$TMP_DIR/client.prompt_trace.log"
: >"$CLIENT_PROMPT_TRACE"
run_ui "$INPUT_CLIENT" "$CLIENT_OUT" "$CLIENT_PROMPT_TRACE"

if ! grep -q '^simple-client-test ' "$CAPTURE"; then
  echo "simple client regression: launcher did not invoke simple-client-test"
  echo "--- output ---"
  cat "$CLIENT_OUT"
  echo "--- captured commands ---"
  cat "$CAPTURE"
  exit 1
fi

assert_absent "$CLIENT_OUT" "Need expert client overrides now?" \
  "simple client regression: inline expert override prompt reappeared"
assert_absent "$CLIENT_OUT" "Need expert server overrides now?" \
  "simple client regression: server expert prompt leaked into simple client flow"
assert_prompt_count "$CLIENT_PROMPT_TRACE" "simple client" 3

echo "[easy-mode-simple-prompt-budget] option 2 prompt budget"
: >"$CAPTURE"
INPUT_SERVER="$TMP_DIR/input_server.txt"
{
  printf '2\n'
  printf '\n'
  printf '\n'
  printf '0\n'
} >"$INPUT_SERVER"
SERVER_OUT="$TMP_DIR/server.log"
SERVER_PROMPT_TRACE="$TMP_DIR/server.prompt_trace.log"
: >"$SERVER_PROMPT_TRACE"
run_ui "$INPUT_SERVER" "$SERVER_OUT" "$SERVER_PROMPT_TRACE"

if ! grep -q '^simple-server-preflight ' "$CAPTURE"; then
  echo "simple server regression: launcher did not invoke simple-server-preflight"
  echo "--- output ---"
  cat "$SERVER_OUT"
  echo "--- captured commands ---"
  cat "$CAPTURE"
  exit 1
fi
if ! grep -q '^simple-server-session ' "$CAPTURE"; then
  echo "simple server regression: launcher did not invoke simple-server-session"
  echo "--- output ---"
  cat "$SERVER_OUT"
  echo "--- captured commands ---"
  cat "$CAPTURE"
  exit 1
fi

assert_absent "$SERVER_OUT" "Need expert client overrides now?" \
  "simple server regression: client expert prompt leaked into simple server flow"
assert_absent "$SERVER_OUT" "Need expert server overrides now?" \
  "simple server regression: inline expert override prompt reappeared"
assert_prompt_count "$SERVER_PROMPT_TRACE" "simple server" 2

echo "[easy-mode-simple-prompt-budget] option 2 authority prompt budget"
: >"$CAPTURE"
INPUT_SERVER_AUTH="$TMP_DIR/input_server_authority.txt"
{
  printf '2\n'
  printf '198.51.100.11\n'
  printf 'y\n'
  printf '0\n'
} >"$INPUT_SERVER_AUTH"
SERVER_AUTH_OUT="$TMP_DIR/server_authority.log"
SERVER_AUTH_PROMPT_TRACE="$TMP_DIR/server_authority.prompt_trace.log"
: >"$SERVER_AUTH_PROMPT_TRACE"
run_ui "$INPUT_SERVER_AUTH" "$SERVER_AUTH_OUT" "$SERVER_AUTH_PROMPT_TRACE"

if ! grep -q '^simple-server-preflight ' "$CAPTURE"; then
  echo "simple server authority regression: launcher did not invoke simple-server-preflight"
  echo "--- output ---"
  cat "$SERVER_AUTH_OUT"
  echo "--- captured commands ---"
  cat "$CAPTURE"
  exit 1
fi
if ! grep -q '^simple-server-session ' "$CAPTURE"; then
  echo "simple server authority regression: launcher did not invoke simple-server-session"
  echo "--- output ---"
  cat "$SERVER_AUTH_OUT"
  echo "--- captured commands ---"
  cat "$CAPTURE"
  exit 1
fi

assert_absent "$SERVER_AUTH_OUT" "Peer server IP/host (optional)" \
  "simple server authority regression: peer override prompt should be expert-only"
assert_absent "$SERVER_AUTH_OUT" "Authority peer server IP/host" \
  "simple server authority regression: authority peer prompt should be expert-only"
assert_prompt_count "$SERVER_AUTH_PROMPT_TRACE" "simple server authority" 2

echo "easy-mode simple prompt budget integration check ok"
