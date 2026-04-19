#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in go curl jq mktemp date; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
FAKE_SCRIPT="$TMP_DIR/fake_easy_node.sh"
SERVER_LOG="$TMP_DIR/local_api_server.log"
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
cmd="${1:-}"
if [[ -z "$cmd" ]]; then
  echo "missing command" >&2
  exit 2
fi
echo "$cmd ok"
EOF_FAKE
chmod +x "$FAKE_SCRIPT"

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
  local main_domain="$1"
  local manifest_url="$2"
  local cache_path="$3"
  local port=""
  local attempt=0
  local max_attempts=8

  for attempt in $(seq 1 "$max_attempts"); do
    port="$(pick_port)"
    : >"$SERVER_LOG"

    LOCAL_API_BASE="http://127.0.0.1:${port}"
    LOCAL_CONTROL_API_ADDR="127.0.0.1:${port}" \
    LOCAL_CONTROL_API_SCRIPT="$FAKE_SCRIPT" \
    LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK="1" \
    GPM_MAIN_DOMAIN="$main_domain" \
    GPM_BOOTSTRAP_MANIFEST_URL="$manifest_url" \
    GPM_BOOTSTRAP_MANIFEST_CACHE_PATH="$cache_path" \
    GPM_STATE_STORE_PATH="$TMP_DIR/gpm_state.json" \
    GPM_AUDIT_LOG_PATH="$TMP_DIR/gpm_audit.jsonl" \
      go run ./cmd/node --local-api >"$SERVER_LOG" 2>&1 &
    SERVER_PID=$!

    if wait_for_local_api "$LOCAL_API_BASE"; then
      return 0
    fi

    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then
      kill "$SERVER_PID" >/dev/null 2>&1 || true
      wait "$SERVER_PID" >/dev/null 2>&1 || true
    fi
    SERVER_PID=""

    if grep -F 'address already in use' "$SERVER_LOG" >/dev/null 2>&1; then
      if (( attempt < max_attempts )); then
        echo "local API bind conflict on port ${port}; retrying (${attempt}/${max_attempts})"
        sleep 0.1
        continue
      fi
      echo "local API bind conflict persisted after ${max_attempts} attempts"
      cat "$SERVER_LOG"
      return 1
    fi

    return 1
  done

  echo "failed to start local API"
  return 1
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
  curl -fsS -X POST -H 'Content-Type: application/json' -H "Origin: ${LOCAL_API_BASE}" --data "$payload" "${LOCAL_API_BASE}${path}"
}

mint_session_token() {
  local wallet="$1"
  local challenge_json=""
  local challenge_id=""
  local verify_json=""
  local session_token=""

  challenge_json="$(api_post_json "/v1/gpm/auth/challenge" "{\"wallet_address\":\"${wallet}\",\"wallet_provider\":\"keplr\"}")"
  challenge_id="$(jq -r '.challenge_id // ""' <<<"$challenge_json")"
  if [[ -z "$challenge_id" ]]; then
    echo "failed to get challenge_id"
    echo "$challenge_json"
    exit 1
  fi

  verify_json="$(api_post_json "/v1/gpm/auth/verify" "{\"wallet_address\":\"${wallet}\",\"wallet_provider\":\"keplr\",\"challenge_id\":\"${challenge_id}\",\"signature\":\"sig-contract-0123456789\"}")"
  session_token="$(jq -r '.session_token // ""' <<<"$verify_json")"
  if [[ -z "$session_token" ]]; then
    echo "failed to get session_token"
    echo "$verify_json"
    exit 1
  fi

  printf '%s\n' "$session_token"
}

write_manifest_cache() {
  local cache_path="$1"
  local source_url="$2"
  local bootstrap_directory="$3"
  local signature_verified="$4"
  local fetched_at_utc=""
  fetched_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  jq -n \
    --arg fetched_at_utc "$fetched_at_utc" \
    --arg source_url "$source_url" \
    --arg bootstrap_directory "$bootstrap_directory" \
    --argjson signature_verified "$signature_verified" \
    '{
      version: 1,
      fetched_at_utc: $fetched_at_utc,
      source_url: $source_url,
      signature_verified: $signature_verified,
      manifest: {
        version: 1,
        generated_at_utc: "2026-01-01T00:00:00Z",
        expires_at_utc: "2099-01-01T00:00:00Z",
        bootstrap_directories: [$bootstrap_directory]
      }
    }' >"$cache_path"
}

assert_json_expr() {
  local json_path="$1"
  local jq_expr="$2"
  local message="$3"
  if ! jq -e "$jq_expr" "$json_path" >/dev/null; then
    echo "$message"
    cat "$json_path"
    exit 1
  fi
}

echo "[local-control-api-gpm-manifest-trust] pinned host mismatch rejects onboarding manifest resolution"
mismatch_cache="$TMP_DIR/mismatch_cache.json"
start_local_api \
  "https://pinned.globalprivatemesh.example:8443" \
  "https://mismatch.globalprivatemesh.example:8443/v1/bootstrap/manifest" \
  "$mismatch_cache"

session_token_mismatch="$(mint_session_token "cosmos1hostmismatch")"
mismatch_register_body="$TMP_DIR/mismatch_register.json"
mismatch_register_code="$(curl -sS -o "$mismatch_register_body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -H "Origin: ${LOCAL_API_BASE}" --data "{\"session_token\":\"${session_token_mismatch}\",\"path_profile\":\"3hop\"}" "${LOCAL_API_BASE}/v1/gpm/onboarding/client/register")"
if [[ "$mismatch_register_code" != "502" ]]; then
  echo "expected host mismatch registration to fail with 502, got $mismatch_register_code"
  cat "$mismatch_register_body"
  exit 1
fi
assert_json_expr \
  "$mismatch_register_body" \
  '.ok == false and (.error | contains("host mismatch")) and (.error | contains("pinned gpm main domain"))' \
  "expected pinned-host mismatch error details"
stop_local_api

echo "[local-control-api-gpm-manifest-trust] cache fallback succeeds when source host matches pinned domain"
cache_manifest_url="http://127.0.0.1:1/v1/bootstrap/manifest"
cache_bootstrap_directory="https://directory.cache.globalprivatemesh.example:8081"
cache_success_path="$TMP_DIR/cache_success.json"
write_manifest_cache "$cache_success_path" "$cache_manifest_url" "$cache_bootstrap_directory" true
start_local_api \
  "http://127.0.0.1:1" \
  "$cache_manifest_url" \
  "$cache_success_path"

session_token_cache_ok="$(mint_session_token "cosmos1cacheok")"
cache_ok_body="$TMP_DIR/cache_ok_register.json"
cache_ok_code="$(curl -sS -o "$cache_ok_body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -H "Origin: ${LOCAL_API_BASE}" --data "{\"session_token\":\"${session_token_cache_ok}\",\"path_profile\":\"balanced\"}" "${LOCAL_API_BASE}/v1/gpm/onboarding/client/register")"
if [[ "$cache_ok_code" != "200" ]]; then
  echo "expected cache fallback registration to succeed with 200, got $cache_ok_code"
  cat "$cache_ok_body"
  exit 1
fi
if ! jq -e --arg expected_bootstrap "$cache_bootstrap_directory" '.ok == true and .source == "cache" and .signature_verified == true and .profile.bootstrap_directory == $expected_bootstrap' "$cache_ok_body" >/dev/null; then
  echo "expected successful cache fallback payload markers"
  cat "$cache_ok_body"
  exit 1
fi
stop_local_api

echo "[local-control-api-gpm-manifest-trust] cache fallback fails closed on cached source host mismatch"
cache_mismatch_path="$TMP_DIR/cache_source_mismatch.json"
write_manifest_cache "$cache_mismatch_path" "http://127.0.0.2:1/v1/bootstrap/manifest" "$cache_bootstrap_directory" true
start_local_api \
  "http://127.0.0.1:1" \
  "$cache_manifest_url" \
  "$cache_mismatch_path"

session_token_cache_bad="$(mint_session_token "cosmos1cachebad")"
cache_bad_body="$TMP_DIR/cache_bad_register.json"
cache_bad_code="$(curl -sS -o "$cache_bad_body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -H "Origin: ${LOCAL_API_BASE}" --data "{\"session_token\":\"${session_token_cache_bad}\",\"path_profile\":\"2hop\"}" "${LOCAL_API_BASE}/v1/gpm/onboarding/client/register")"
if [[ "$cache_bad_code" != "502" ]]; then
  echo "expected mismatched cache source registration to fail with 502, got $cache_bad_code"
  cat "$cache_bad_body"
  exit 1
fi
assert_json_expr \
  "$cache_bad_body" \
  '.ok == false and (.error | contains("cache fallback failed")) and (.error | contains("cached manifest source host mismatch")) and (.error | contains("pinned gpm main domain"))' \
  "expected cache source-host mismatch error details"
stop_local_api

echo "local control API gpm manifest trust integration check ok"
