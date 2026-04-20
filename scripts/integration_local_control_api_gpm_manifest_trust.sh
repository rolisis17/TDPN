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
CALLS_FILE="$TMP_DIR/easy_node_calls.tsv"
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
shift || true
calls_file="${LOCAL_API_GPM_MANIFEST_TRUST_CALLS_FILE:-}"
if [[ -n "$calls_file" ]]; then
  {
    printf '%s' "$cmd"
    for arg in "$@"; do
      printf '\t%s' "$arg"
    done
    printf '\n'
  } >>"$calls_file"
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
  local require_verify_command="${4-0}"
  local require_metadata="${5-0}"
  local require_wallet_extension_source="${6-0}"
  local manifest_hmac_key="${7-}"
  local production_mode="${8-0}"
  local manifest_require_https="${9-}"
  local manifest_require_signature="${10-}"
  local connect_require_session="${11-}"
  local allow_legacy_connect_override="${12-}"
  local port=""
  local attempt=0
  local max_attempts=8

  for attempt in $(seq 1 "$max_attempts"); do
    port="$(pick_port)"
    : >"$SERVER_LOG"

    LOCAL_API_BASE="http://127.0.0.1:${port}"
    local api_env=(
      "LOCAL_CONTROL_API_ADDR=127.0.0.1:${port}"
      "LOCAL_CONTROL_API_SCRIPT=$FAKE_SCRIPT"
      "LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK=1"
      "GPM_MAIN_DOMAIN=$main_domain"
      "GPM_BOOTSTRAP_MANIFEST_URL=$manifest_url"
      "GPM_BOOTSTRAP_MANIFEST_CACHE_PATH=$cache_path"
      "GPM_BOOTSTRAP_MANIFEST_HMAC_KEY=$manifest_hmac_key"
      "GPM_BOOTSTRAP_MANIFEST_REQUIRE_HTTPS=$manifest_require_https"
      "GPM_BOOTSTRAP_MANIFEST_REQUIRE_SIGNATURE=$manifest_require_signature"
      "GPM_PRODUCTION_MODE=$production_mode"
      "GPM_AUTH_VERIFY_REQUIRE_COMMAND=$require_verify_command"
      "GPM_AUTH_VERIFY_REQUIRE_METADATA=$require_metadata"
      "GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE=$require_wallet_extension_source"
      "LOCAL_API_GPM_MANIFEST_TRUST_CALLS_FILE=$CALLS_FILE"
      "GPM_STATE_STORE_PATH=$TMP_DIR/gpm_state.json"
      "GPM_AUDIT_LOG_PATH=$TMP_DIR/gpm_audit.jsonl"
    )
    if [[ -n "$connect_require_session" ]]; then
      api_env+=("GPM_CONNECT_REQUIRE_SESSION=$connect_require_session")
    fi
    if [[ -n "$allow_legacy_connect_override" ]]; then
      api_env+=("GPM_ALLOW_LEGACY_CONNECT_OVERRIDE=$allow_legacy_connect_override")
    fi
    env "${api_env[@]}" go run ./cmd/node --local-api >"$SERVER_LOG" 2>&1 &
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

api_get_json() {
  local path="$1"
  curl -fsS -H "Origin: ${LOCAL_API_BASE}" "${LOCAL_API_BASE}${path}"
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
  write_manifest_cache_with_directories "$cache_path" "$source_url" "$signature_verified" "$bootstrap_directory"
}

write_manifest_cache_with_directories() {
  local cache_path="$1"
  local source_url="$2"
  local signature_verified="$3"
  shift 3
  local bootstrap_directories_json="[]"

  if [[ "$#" -eq 0 ]]; then
    echo "write_manifest_cache_with_directories requires at least one bootstrap directory"
    exit 1
  fi

  bootstrap_directories_json="$(printf '%s\n' "$@" | jq -R 'select(length > 0)' | jq -s '.')"
  if [[ -z "$bootstrap_directories_json" || "$bootstrap_directories_json" == "[]" ]]; then
    echo "write_manifest_cache_with_directories received only empty bootstrap directories"
    exit 1
  fi

  local fetched_at_utc=""
  fetched_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  jq -n \
    --arg fetched_at_utc "$fetched_at_utc" \
    --arg source_url "$source_url" \
    --argjson signature_verified "$signature_verified" \
    --argjson bootstrap_directories "$bootstrap_directories_json" \
    '{
      version: 1,
      fetched_at_utc: $fetched_at_utc,
      source_url: $source_url,
      signature_verified: $signature_verified,
      manifest: {
        version: 1,
        generated_at_utc: "2026-01-01T00:00:00Z",
        expires_at_utc: "2099-01-01T00:00:00Z",
        bootstrap_directories: $bootstrap_directories
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

echo "[local-control-api-gpm-manifest-trust] /v1/config surfaces strict auth policy keys"
strict_manifest_url="http://127.0.0.1:1/v1/bootstrap/manifest"
strict_bootstrap_directory="https://directory.strict.globalprivatemesh.example:8081"
strict_cache_path="$TMP_DIR/strict_policy_cache.json"
write_manifest_cache "$strict_cache_path" "$strict_manifest_url" "$strict_bootstrap_directory" true
start_local_api \
  "http://127.0.0.1:1" \
  "$strict_manifest_url" \
  "$strict_cache_path" \
  0 \
  1 \
  1

strict_config_json="$(api_get_json "/v1/config")"
if ! jq -e '.ok == true and .config.gpm_auth_verify_require_metadata == true and .config.gpm_auth_verify_require_wallet_extension_source == true' <<<"$strict_config_json" >/dev/null; then
  echo "expected /v1/config strict auth policy keys to be surfaced as true"
  echo "$strict_config_json"
  exit 1
fi

echo "[local-control-api-gpm-manifest-trust] strict auth policy rejects missing verify metadata"
strict_wallet="cosmos1strictauth"
strict_challenge_json="$(api_post_json "/v1/gpm/auth/challenge" "{\"wallet_address\":\"${strict_wallet}\",\"wallet_provider\":\"keplr\"}")"
strict_challenge_id="$(jq -r '.challenge_id // ""' <<<"$strict_challenge_json")"
if [[ -z "$strict_challenge_id" ]]; then
  echo "failed to get strict auth challenge_id"
  echo "$strict_challenge_json"
  exit 1
fi
strict_verify_missing_metadata_body="$TMP_DIR/strict_verify_missing_metadata.json"
strict_verify_missing_metadata_code="$(curl -sS -o "$strict_verify_missing_metadata_body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -H "Origin: ${LOCAL_API_BASE}" --data "{\"wallet_address\":\"${strict_wallet}\",\"wallet_provider\":\"keplr\",\"challenge_id\":\"${strict_challenge_id}\",\"signature\":\"sig-contract-0123456789\"}" "${LOCAL_API_BASE}/v1/gpm/auth/verify")"
if [[ "$strict_verify_missing_metadata_code" != "401" && "$strict_verify_missing_metadata_code" != "400" ]]; then
  echo "expected strict auth verify without metadata to fail with 401/400, got $strict_verify_missing_metadata_code"
  cat "$strict_verify_missing_metadata_body"
  exit 1
fi
assert_json_expr \
  "$strict_verify_missing_metadata_body" \
  '.ok == false and ((.error // "") | type == "string") and ((((.error // "") | ascii_downcase) | contains("metadata")) or (((.error // "") | ascii_downcase) | contains("wallet_extension_source")) or (((.error // "") | ascii_downcase) | contains("wallet extension source")) or (((.error // "") | ascii_downcase) | contains("signature_source")) or (((.error // "") | ascii_downcase) | contains("policy")))' \
  "expected strict auth verify error to reference metadata/wallet-extension-source policy"
stop_local_api

echo "[local-control-api-gpm-manifest-trust] connect policy rejects manual overrides when legacy override is disabled even if session is not globally required"
connect_policy_manifest_url="http://127.0.0.1:1/v1/bootstrap/manifest"
connect_policy_bootstrap_directory="https://directory.connect-policy.globalprivatemesh.example:8081"
connect_policy_cache_path="$TMP_DIR/connect_policy_cache.json"
write_manifest_cache "$connect_policy_cache_path" "$connect_policy_manifest_url" "$connect_policy_bootstrap_directory" true
start_local_api \
  "http://127.0.0.1:1" \
  "$connect_policy_manifest_url" \
  "$connect_policy_cache_path" \
  0 \
  0 \
  0 \
  "" \
  0 \
  "" \
  "" \
  0 \
  0

connect_policy_config_json="$(api_get_json "/v1/config")"
if ! jq -e '.ok == true and .config.connect_require_session == false and .config.allow_legacy_connect_override == false' <<<"$connect_policy_config_json" >/dev/null; then
  echo "expected explicit connect policy override to surface connect_require_session=false and allow_legacy_connect_override=false"
  echo "$connect_policy_config_json"
  exit 1
fi

: >"$CALLS_FILE"
connect_policy_manual_body="$TMP_DIR/connect_policy_manual_override.json"
connect_policy_manual_code="$(curl -sS -o "$connect_policy_manual_body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -H "Origin: ${LOCAL_API_BASE}" --data "{\"bootstrap_directory\":\"https://directory.manual-override.globalprivatemesh.example:8081\",\"invite_key\":\"inv-manual-override-disabled\"}" "${LOCAL_API_BASE}/v1/connect")"
if [[ "$connect_policy_manual_code" != "400" ]]; then
  echo "expected manual connect override without session_token to fail with 400 when legacy overrides are disabled, got $connect_policy_manual_code"
  cat "$connect_policy_manual_body"
  exit 1
fi
assert_json_expr \
  "$connect_policy_manual_body" \
  '.ok == false and ((.error // "") | type == "string") and (((.error // "") | ascii_downcase) | contains("manual")) and ((((.error // "") | ascii_downcase) | contains("override")) or (((.error // "") | ascii_downcase) | contains("bootstrap_directory"))) and (((.error // "") | contains("session_token")) or (((.error // "") | ascii_downcase) | contains("session token")))' \
  "expected connect policy override error to indicate manual overrides are disabled and session token is required"
if grep -E '^client-vpn-up(\t|$)' "$CALLS_FILE" >/dev/null 2>&1; then
  echo "expected connect policy rejection to fail closed without invoking client-vpn-up"
  cat "$CALLS_FILE"
  cat "$connect_policy_manual_body"
  exit 1
fi

: >"$CALLS_FILE"
connect_policy_invalid_session_body="$TMP_DIR/connect_policy_invalid_session.json"
connect_policy_invalid_session_code="$(curl -sS -o "$connect_policy_invalid_session_body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -H "Origin: ${LOCAL_API_BASE}" --data '{"session_token":"gpm-connect-invalid-session-token","run_preflight":false}' "${LOCAL_API_BASE}/v1/connect")"
if [[ "$connect_policy_invalid_session_code" != "401" ]]; then
  echo "expected invalid connect session_token to fail with 401, got $connect_policy_invalid_session_code"
  cat "$connect_policy_invalid_session_body"
  exit 1
fi
assert_json_expr \
  "$connect_policy_invalid_session_body" \
  '.ok == false and ((.error // "") | type == "string") and (((.error // "") | ascii_downcase) == "invalid or expired session_token")' \
  "expected invalid connect session_token error to fail closed with invalid-or-expired guidance"
if grep -E '^client-vpn-up(\t|$)' "$CALLS_FILE" >/dev/null 2>&1; then
  echo "expected invalid session_token connect rejection to avoid invoking client-vpn-up"
  cat "$CALLS_FILE"
  cat "$connect_policy_invalid_session_body"
  exit 1
fi
stop_local_api

echo "[local-control-api-gpm-manifest-trust] production mode fails closed when external auth verifier command is not configured"
prod_auth_cache_path="$TMP_DIR/prod_auth_cache.json"
start_local_api \
  "https://bootstrap.globalprivatemesh.example" \
  "https://bootstrap.globalprivatemesh.example/v1/bootstrap/manifest" \
  "$prod_auth_cache_path" \
  "" \
  0 \
  0 \
  "" \
  1

echo "[local-control-api-gpm-manifest-trust] production mode /v1/config surfaces fail-closed connect policy defaults"
prod_auth_config_json="$(api_get_json "/v1/config")"
if ! jq -e '.ok == true and .config.connect_require_session == true and .config.allow_legacy_connect_override == false' <<<"$prod_auth_config_json" >/dev/null; then
  echo "expected production mode /v1/config to surface connect_require_session=true and allow_legacy_connect_override=false"
  echo "$prod_auth_config_json"
  exit 1
fi

echo "[local-control-api-gpm-manifest-trust] production mode rejects manual connect overrides without session token"
prod_auth_connect_manual_body="$TMP_DIR/prod_auth_connect_manual_override.json"
prod_auth_connect_manual_code="$(curl -sS -o "$prod_auth_connect_manual_body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -H "Origin: ${LOCAL_API_BASE}" --data "{\"bootstrap_directory\":\"https://directory.prod-connect.globalprivatemesh.example:8081\",\"invite_key\":\"inv-prod-connect-manual-override\"}" "${LOCAL_API_BASE}/v1/connect")"
if [[ "$prod_auth_connect_manual_code" != "400" ]]; then
  echo "expected production mode manual connect override without session_token to fail with 400, got $prod_auth_connect_manual_code"
  cat "$prod_auth_connect_manual_body"
  exit 1
fi
assert_json_expr \
  "$prod_auth_connect_manual_body" \
  '.ok == false and ((.error // "") | type == "string") and (((.error // "") | ascii_downcase) | contains("manual")) and ((((.error // "") | ascii_downcase) | contains("override")) or (((.error // "") | ascii_downcase) | contains("bootstrap_directory"))) and (((.error // "") | contains("session_token")) or (((.error // "") | ascii_downcase) | contains("session token")))' \
  "expected production mode manual connect override error to indicate overrides are disabled and session token is required"

prod_auth_wallet="cosmos1prodauthstrict"
prod_auth_challenge_json="$(api_post_json "/v1/gpm/auth/challenge" "{\"wallet_address\":\"${prod_auth_wallet}\",\"wallet_provider\":\"keplr\"}")"
prod_auth_challenge_id="$(jq -r '.challenge_id // ""' <<<"$prod_auth_challenge_json")"
if [[ -z "$prod_auth_challenge_id" ]]; then
  echo "failed to get production auth challenge_id"
  echo "$prod_auth_challenge_json"
  exit 1
fi
prod_auth_verify_body="$TMP_DIR/prod_auth_verify_missing_command.json"
prod_auth_verify_code="$(curl -sS -o "$prod_auth_verify_body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -H "Origin: ${LOCAL_API_BASE}" --data "{\"wallet_address\":\"${prod_auth_wallet}\",\"wallet_provider\":\"keplr\",\"challenge_id\":\"${prod_auth_challenge_id}\",\"signature\":\"sig-contract-0123456789\"}" "${LOCAL_API_BASE}/v1/gpm/auth/verify")"
if [[ "$prod_auth_verify_code" != "401" && "$prod_auth_verify_code" != "400" ]]; then
  echo "expected production auth verify without external verifier command to fail with 401/400, got $prod_auth_verify_code"
  cat "$prod_auth_verify_body"
  exit 1
fi
assert_json_expr \
  "$prod_auth_verify_body" \
  '.ok == false and ((.error // "") | type == "string") and (((.error // "") | ascii_downcase) | contains("verifier command is required"))' \
  "expected production auth verify to fail closed when verifier command is not configured"
stop_local_api

echo "[local-control-api-gpm-manifest-trust] production mode requires https bootstrap manifest URLs when pinned domain is configured"
prod_https_cache="$TMP_DIR/prod_https_cache.json"
start_local_api \
  "https://pinned.globalprivatemesh.example:8443" \
  "http://pinned.globalprivatemesh.example:8443/v1/bootstrap/manifest" \
  "$prod_https_cache" \
  0 \
  0 \
  0 \
  "" \
  1

session_token_prod_https="$(mint_session_token "cosmos1prodhttpsrequired")"
prod_https_register_body="$TMP_DIR/prod_https_register.json"
prod_https_register_code="$(curl -sS -o "$prod_https_register_body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -H "Origin: ${LOCAL_API_BASE}" --data "{\"session_token\":\"${session_token_prod_https}\",\"path_profile\":\"2hop\"}" "${LOCAL_API_BASE}/v1/gpm/onboarding/client/register")"
if [[ "$prod_https_register_code" != "502" ]]; then
  echo "expected production manifest trust to reject pinned HTTP manifest URL with 502, got $prod_https_register_code"
  cat "$prod_https_register_body"
  exit 1
fi
assert_json_expr \
  "$prod_https_register_body" \
  '.ok == false and ((.error // "") | contains("must use https")) and ((.error // "") | contains("pinned gpm main domain"))' \
  "expected production manifest trust to fail closed for pinned HTTP manifest URLs"
stop_local_api

echo "[local-control-api-gpm-manifest-trust] production mode requires manifest signature verifier key for cache fallback"
prod_sig_manifest_url="https://127.0.0.1:1/v1/bootstrap/manifest"
prod_sig_bootstrap_directory="https://directory.prod-sig.globalprivatemesh.example:8081"
prod_sig_cache_path="$TMP_DIR/prod_sig_cache_missing_key.json"
write_manifest_cache "$prod_sig_cache_path" "$prod_sig_manifest_url" "$prod_sig_bootstrap_directory" true
start_local_api \
  "https://127.0.0.1:1" \
  "$prod_sig_manifest_url" \
  "$prod_sig_cache_path" \
  0 \
  0 \
  0 \
  "" \
  1

session_token_prod_sig="$(mint_session_token "cosmos1prodsigrequired")"
prod_sig_register_body="$TMP_DIR/prod_sig_register.json"
prod_sig_register_code="$(curl -sS -o "$prod_sig_register_body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -H "Origin: ${LOCAL_API_BASE}" --data "{\"session_token\":\"${session_token_prod_sig}\",\"path_profile\":\"2hop\"}" "${LOCAL_API_BASE}/v1/gpm/onboarding/client/register")"
if [[ "$prod_sig_register_code" != "502" ]]; then
  echo "expected production signature policy without verifier key to fail with 502, got $prod_sig_register_code"
  cat "$prod_sig_register_body"
  exit 1
fi
assert_json_expr \
  "$prod_sig_register_body" \
  '.ok == false and (.error | contains("manifest cache read failed")) and (.error | contains("verification key is required by policy"))' \
  "expected production manifest trust to require signature verifier key for cache fallback"
stop_local_api

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

echo "[local-control-api-gpm-manifest-trust] session-bound path profile rejects conflicting connect override"
: >"$CALLS_FILE"
connect_conflict_body="$TMP_DIR/connect_conflict.json"
connect_conflict_code="$(curl -sS -o "$connect_conflict_body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -H "Origin: ${LOCAL_API_BASE}" --data "{\"session_token\":\"${session_token_cache_ok}\",\"path_profile\":\"1hop\",\"policy_profile\":\"1hop\",\"run_preflight\":false}" "${LOCAL_API_BASE}/v1/connect")"
if [[ "$connect_conflict_code" != "409" && "$connect_conflict_code" != "400" ]]; then
  echo "expected conflicting session-bound path_profile connect to fail closed with 409/400, got $connect_conflict_code"
  cat "$connect_conflict_body"
  exit 1
fi
assert_json_expr \
  "$connect_conflict_body" \
  '.ok == false and ((.error // "") | type == "string") and ((.error // "") | contains("path_profile")) and ((.error // "") | contains("session")) and (((.error // "") | contains("conflict")) or ((.error // "") | contains("authoritative")) or ((.error // "") | contains("must match")))' \
  "expected clear session-bound path_profile conflict error semantics"
if grep -E '^client-vpn-up(\t|$)' "$CALLS_FILE" >/dev/null 2>&1; then
  echo "expected fail-closed connect rejection to avoid invoking client-vpn-up"
  cat "$CALLS_FILE"
  cat "$connect_conflict_body"
  exit 1
fi

echo "[local-control-api-gpm-manifest-trust] connect-time session bootstrap trust revalidation fails closed when manifest drops session directories"
cache_revalidation_blocked_directory="https://directory.cache.revalidation.blocked.globalprivatemesh.example:8081"
write_manifest_cache "$cache_success_path" "$cache_manifest_url" "$cache_revalidation_blocked_directory" true

: >"$CALLS_FILE"
connect_revalidation_reject_body="$TMP_DIR/connect_revalidation_reject.json"
connect_revalidation_reject_code="$(curl -sS -o "$connect_revalidation_reject_body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -H "Origin: ${LOCAL_API_BASE}" --data "{\"session_token\":\"${session_token_cache_ok}\",\"run_preflight\":false}" "${LOCAL_API_BASE}/v1/connect")"
if [[ "$connect_revalidation_reject_code" != "403" ]]; then
  echo "expected connect-time session bootstrap trust revalidation rejection to fail with 403 when manifest drops all registered directories, got $connect_revalidation_reject_code"
  cat "$connect_revalidation_reject_body"
  exit 1
fi
assert_json_expr \
  "$connect_revalidation_reject_body" \
  '.ok == false and ((.error // "") | type == "string") and (((.error // "") | ascii_downcase) | contains("no registered bootstrap_directory remains trusted by the current manifest"))' \
  "expected connect-time session bootstrap trust revalidation rejection message when manifest drops all registered directories"
if grep -E '^client-vpn-up(\t|$)' "$CALLS_FILE" >/dev/null 2>&1; then
  echo "expected connect-time revalidation rejection to fail closed without invoking client-vpn-up"
  cat "$CALLS_FILE"
  cat "$connect_revalidation_reject_body"
  exit 1
fi

echo "[local-control-api-gpm-manifest-trust] connect-time session bootstrap trust revalidation proceeds when manifest retains at least one session directory"
cache_revalidation_extra_directory="https://directory.cache.revalidation.extra.globalprivatemesh.example:8081"
write_manifest_cache_with_directories \
  "$cache_success_path" \
  "$cache_manifest_url" \
  true \
  "$cache_revalidation_extra_directory" \
  "$cache_bootstrap_directory"

: >"$CALLS_FILE"
connect_revalidation_ok_body="$TMP_DIR/connect_revalidation_ok.json"
connect_revalidation_ok_code="$(curl -sS -o "$connect_revalidation_ok_body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -H "Origin: ${LOCAL_API_BASE}" --data "{\"session_token\":\"${session_token_cache_ok}\",\"run_preflight\":false}" "${LOCAL_API_BASE}/v1/connect")"
if [[ "$connect_revalidation_ok_code" != "200" ]]; then
  echo "expected connect-time session bootstrap trust revalidation to proceed with 200 when manifest retains a registered directory, got $connect_revalidation_ok_code"
  cat "$connect_revalidation_ok_body"
  exit 1
fi
if ! jq -e --arg expected_bootstrap "$cache_bootstrap_directory" '.ok == true and .stage == "connect" and .bootstrap_directory == $expected_bootstrap' "$connect_revalidation_ok_body" >/dev/null; then
  echo "expected successful connect-time revalidation response markers"
  cat "$connect_revalidation_ok_body"
  exit 1
fi
if ! grep -F "client-vpn-up"$'\t'"--bootstrap-directory"$'\t'"$cache_bootstrap_directory" "$CALLS_FILE" >/dev/null 2>&1; then
  echo "expected successful connect-time revalidation to invoke client-vpn-up with a still-trusted session bootstrap directory"
  cat "$CALLS_FILE"
  cat "$connect_revalidation_ok_body"
  exit 1
fi
stop_local_api

echo "[local-control-api-gpm-manifest-trust] cache fallback fails closed when hmac key is configured and cache lacks signed payload evidence"
cache_hmac_required_path="$TMP_DIR/cache_hmac_required_missing_evidence.json"
write_manifest_cache "$cache_hmac_required_path" "$cache_manifest_url" "$cache_bootstrap_directory" true
start_local_api \
  "http://127.0.0.1:1" \
  "$cache_manifest_url" \
  "$cache_hmac_required_path" \
  0 \
  0 \
  0 \
  "integration-manifest-hmac-key"

session_token_cache_hmac_required="$(mint_session_token "cosmos1cachehmacrequired")"
cache_hmac_required_body="$TMP_DIR/cache_hmac_required_register.json"
cache_hmac_required_code="$(curl -sS -o "$cache_hmac_required_body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' -H "Origin: ${LOCAL_API_BASE}" --data "{\"session_token\":\"${session_token_cache_hmac_required}\",\"path_profile\":\"balanced\"}" "${LOCAL_API_BASE}/v1/gpm/onboarding/client/register")"
if [[ "$cache_hmac_required_code" != "502" ]]; then
  echo "expected cache fallback without signed payload evidence to fail with 502 when hmac key is configured, got $cache_hmac_required_code"
  cat "$cache_hmac_required_body"
  exit 1
fi
assert_json_expr \
  "$cache_hmac_required_body" \
  '.ok == false and (.error | contains("manifest cache read failed")) and (.error | contains("missing signed payload evidence"))' \
  "expected hmac-required cache fallback to fail closed without signed payload evidence"
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
  '.ok == false and (.error | contains("manifest cache read failed")) and (.error | contains("cached manifest source host mismatch")) and (.error | contains("pinned gpm main domain"))' \
  "expected cache source-host mismatch error details"
stop_local_api

echo "local control API gpm manifest trust integration check ok"
