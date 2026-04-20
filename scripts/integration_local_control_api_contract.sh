#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
GPM_API_FILE="services/localapi/gpm_api.go"
LOCAL_API_SERVICE_FILE="services/localapi/service.go"

for cmd in go curl jq mktemp; do
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
LOCAL_API_AUTH_TOKEN="local-api-contract-token"
LOCAL_API_OPERATOR_ADMIN_TOKEN="local-api-contract-admin-token"

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

calls_file="${LOCAL_API_CONTRACT_CALLS_FILE:?}"
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
    echo '{"ok":true,"running":false,"interface":"wgvpn0"}'
    ;;
  runtime-doctor)
    echo '{"ok":true,"status":"green","checks":[]}'
    ;;
  *)
    echo "$cmd ok"
    ;;
esac
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
  local allow_update="$1"
  local port=""
  local attempt=0
  local max_attempts=8

  for attempt in $(seq 1 "$max_attempts"); do
    port="$(pick_port)"
    : >"$CALLS_FILE"
    : >"$SERVER_LOG"

    LOCAL_API_BASE="http://127.0.0.1:${port}"
    LOCAL_CONTROL_API_ADDR="127.0.0.1:${port}" \
    LOCAL_CONTROL_API_SCRIPT="$FAKE_SCRIPT" \
    LOCAL_CONTROL_API_ALLOW_UPDATE="$allow_update" \
    LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK="1" \
    LOCAL_CONTROL_API_AUTH_TOKEN="$LOCAL_API_AUTH_TOKEN" \
    GPM_OPERATOR_APPROVAL_TOKEN="$LOCAL_API_OPERATOR_ADMIN_TOKEN" \
    LOCAL_CONTROL_API_SERVICE_START_COMMAND="printf gpm-service-start-ok" \
    LOCAL_CONTROL_API_SERVICE_STOP_COMMAND="printf gpm-service-stop-ok" \
    LOCAL_CONTROL_API_SERVICE_RESTART_COMMAND="printf gpm-service-restart-ok" \
    LOCAL_API_CONTRACT_CALLS_FILE="$CALLS_FILE" \
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

last_call() {
  local command="$1"
  awk -F '\t' -v cmd="$command" '$1 == cmd { line = $0 } END { if (line != "") print line }' "$CALLS_FILE"
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

require_gpm_api_marker() {
  local pattern="$1"
  local description="$2"
  if ! grep -qE "$pattern" "$GPM_API_FILE"; then
    echo "local control API contract failed: missing ${description} marker /${pattern}/ in $GPM_API_FILE"
    exit 1
  fi
}

require_localapi_service_marker() {
  local pattern="$1"
  local description="$2"
  if ! grep -qE "$pattern" "$LOCAL_API_SERVICE_FILE"; then
    echo "local control API contract failed: missing ${description} marker /${pattern}/ in $LOCAL_API_SERVICE_FILE"
    exit 1
  fi
}

api_get() {
  local path="$1"
  curl -fsS -H "Authorization: Bearer ${LOCAL_API_AUTH_TOKEN}" "${LOCAL_API_BASE}${path}"
}

api_post_json() {
  local path="$1"
  local payload="$2"
  curl -fsS -X POST -H "Authorization: Bearer ${LOCAL_API_AUTH_TOKEN}" -H 'Content-Type: application/json' --data "$payload" "${LOCAL_API_BASE}${path}"
}

if [[ ! -f "$GPM_API_FILE" ]]; then
  echo "local control API contract failed: missing source file: $GPM_API_FILE"
  exit 1
fi
if [[ ! -f "$LOCAL_API_SERVICE_FILE" ]]; then
  echo "local control API contract failed: missing source file: $LOCAL_API_SERVICE_FILE"
  exit 1
fi

# Verify-request metadata fields remain optional and presence-aware.
VERIFY_REQUEST_METADATA_MARKERS=(
  'SignatureKind[[:space:]]+\*string[[:space:]]+`json:"signature_kind,omitempty"`'
  'SignaturePublicKey[[:space:]]+string[[:space:]]+`json:"signature_public_key,omitempty"`'
  'SignaturePublicKeyType[[:space:]]+\*string[[:space:]]+`json:"signature_public_key_type,omitempty"`'
  'SignatureSource[[:space:]]+\*string[[:space:]]+`json:"signature_source,omitempty"`'
  'ChainID[[:space:]]+string[[:space:]]+`json:"chain_id,omitempty"`'
  'SignedMessage[[:space:]]+\*string[[:space:]]+`json:"signed_message,omitempty"`'
  'SignatureEnvelope[[:space:]]+json\.RawMessage[[:space:]]+`json:"signature_envelope,omitempty"`'
  'if[[:space:]]+in\.SignedMessage[[:space:]]*!=[[:space:]]*nil[[:space:]]*\{'
  'normalizeOptionalJSONStringOrScalar\(in\.SignatureEnvelope\)'
  'HasSignedMessage[[:space:]]*=[[:space:]]*true'
  'HasSignatureEnvelope[[:space:]]*=[[:space:]]*true'
)
for marker in "${VERIFY_REQUEST_METADATA_MARKERS[@]}"; do
  require_gpm_api_marker "$marker" "verify-request optional metadata"
done

# Validation paths: signed_message challenge binding, enum allow-lists, and envelope length bound.
VERIFY_METADATA_VALIDATION_MARKERS=(
  'func[[:space:]]+validateGPMAuthSignatureMetadata\('
  'if[[:space:]]+signatureMetadata\.HasSignedMessage[[:space:]]+&&[[:space:]]+!subtleEqual\(challenge\.Message,[[:space:]]*signatureMetadata\.SignedMessage\)'
  'signed_message does not match issued challenge message'
  'case[[:space:]]+"sign_arbitrary",[[:space:]]*"eip191"'
  'unsupported signature_kind'
  'case[[:space:]]+"wallet_extension",[[:space:]]*"manual"'
  'unsupported signature_source'
  'case[[:space:]]+"secp256k1",[[:space:]]*"ed25519"'
  'unsupported signature_public_key_type'
  'gpmAuthSignatureEnvelopeMaxLen'
  'if[[:space:]]+signatureMetadata\.HasSignatureEnvelope[[:space:]]+&&[[:space:]]+len\(signatureMetadata\.SignatureEnvelope\)[[:space:]]*>[[:space:]]*gpmAuthSignatureEnvelopeMaxLen'
  'signature_envelope is too long'
  'if[[:space:]]+err[[:space:]]*:=[[:space:]]+validateGPMAuthSignatureMetadata\(challenge,[[:space:]]*signatureMetadata\);[[:space:]]+err[[:space:]]*!=[[:space:]]*nil'
)
for marker in "${VERIFY_METADATA_VALIDATION_MARKERS[@]}"; do
  require_gpm_api_marker "$marker" "verify metadata validation"
done

# Auth verifier command must receive metadata in environment for external verifier hooks.
VERIFY_METADATA_ENV_MARKERS=(
  'func[[:space:]]+\(s[[:space:]]+\*Service\)[[:space:]]+runGPMAuthVerifierCommand\([^)]*signatureMetadata[[:space:]]+gpmAuthSignatureMetadata\)'
  'GPM_AUTH_VERIFY_SIGNATURE_KIND='
  'GPM_AUTH_VERIFY_SIGNATURE_PUBLIC_KEY='
  'GPM_AUTH_VERIFY_SIGNATURE_PUBLIC_KEY_TYPE='
  'GPM_AUTH_VERIFY_SIGNATURE_SOURCE='
  'GPM_AUTH_VERIFY_CHAIN_ID='
  'GPM_AUTH_VERIFY_SIGNED_MESSAGE='
  'GPM_AUTH_VERIFY_SIGNATURE_ENVELOPE='
)
for marker in "${VERIFY_METADATA_ENV_MARKERS[@]}"; do
  require_gpm_api_marker "$marker" "verifier metadata env propagation"
done
echo "[local-control-api-contract] gpm auth verify metadata markers in source are present"

# Strict verifier-command policy must be wired end-to-end:
# - env parsing for strict policy toggle
# - /v1/config policy/configured surface
# - fail-closed policy check in verify path
STRICT_VERIFY_POLICY_SERVICE_MARKERS=(
  '"GPM_AUTH_VERIFY_REQUIRE_COMMAND",[[:space:]]*$'
  '"TDPN_AUTH_VERIFY_REQUIRE_COMMAND",[[:space:]]*$'
  '"gpm_auth_verify_require_command":[[:space:]]*s\.gpmAuthVerifyRequireCommand'
  '"gpm_auth_verify_command_configured":[[:space:]]*strings\.TrimSpace\(s\.gpmAuthVerifyCommand\)[[:space:]]*!=[[:space:]]*""'
)
for marker in "${STRICT_VERIFY_POLICY_SERVICE_MARKERS[@]}"; do
  require_localapi_service_marker "$marker" "strict verifier-command policy service wiring"
done
STRICT_VERIFY_POLICY_GPM_MARKERS=(
  'if[[:space:]]+s\.gpmAuthVerifyRequireCommand[[:space:]]+&&[[:space:]]+strings\.TrimSpace\(s\.gpmAuthVerifyCommand\)[[:space:]]*==[[:space:]]*""[[:space:]]*\{'
  'signature verifier command is required by policy'
)
for marker in "${STRICT_VERIFY_POLICY_GPM_MARKERS[@]}"; do
  require_gpm_api_marker "$marker" "strict verifier-command policy fail-closed check"
done
echo "[local-control-api-contract] strict verifier-command policy markers in source are present"

# Strict chain-binding lifecycle unlock checks must remain fail-closed for
# operator sessions (both session/application chain_operator_id must be present
# and matching).
STRICT_CHAIN_BINDING_MARKERS=(
  'func[[:space:]]+gpmStrictOperatorChainBinding\('
  'operator session chain_operator_id is missing'
  'approved operator application chain_operator_id is missing'
  'bound,[[:space:]]*reason[[:space:]]*:=[[:space:]]*gpmStrictOperatorChainBinding'
  'strictChainBound,[[:space:]]*strictChainBindingReason[[:space:]]*=[[:space:]]*gpmStrictOperatorChainBinding'
  'lifecycleActionsUnlocked[[:space:]]*:=[[:space:]]*role[[:space:]]*==[[:space:]]*"admin"[[:space:]]*\|\|'
)
for marker in "${STRICT_CHAIN_BINDING_MARKERS[@]}"; do
  require_gpm_api_marker "$marker" "strict chain-binding lifecycle enforcement"
done
echo "[local-control-api-contract] strict chain-binding lifecycle markers in source are present"

echo "[local-control-api-contract] start local API (update disabled)"
start_local_api 0

echo "[local-control-api-contract] status endpoint forwards client-vpn-status --show-json 1"
status_json="$(api_get "/v1/status")"
if ! jq -e '.ok == true and .status.ok == true' <<<"$status_json" >/dev/null; then
  echo "status endpoint did not return expected payload"
  echo "$status_json"
  exit 1
fi
status_call="$(require_last_call "client-vpn-status")"
assert_line_has "$status_call" $'\t--show-json\t1' "status forwarding missing --show-json 1"

echo "[local-control-api-contract] diagnostics endpoint forwards runtime-doctor --show-json 1"
diag_json="$(api_get "/v1/get_diagnostics")"
if ! jq -e '.ok == true and .diagnostics.ok == true' <<<"$diag_json" >/dev/null; then
  echo "diagnostics endpoint did not return expected payload"
  echo "$diag_json"
  exit 1
fi
diag_call="$(require_last_call "runtime-doctor")"
assert_line_has "$diag_call" $'\t--show-json\t1' "diagnostics forwarding missing --show-json 1"

echo "[local-control-api-contract] onboarding overview requires session_token"
overview_missing_body="$TMP_DIR/onboarding_overview_missing_session_token.json"
overview_missing_code="$(curl -sS -o "$overview_missing_body" -w '%{http_code}' -X POST -H "Authorization: Bearer ${LOCAL_API_AUTH_TOKEN}" -H 'Content-Type: application/json' --data '{}' "${LOCAL_API_BASE}/v1/gpm/onboarding/overview")"
if [[ "$overview_missing_code" != "400" ]]; then
  echo "expected /v1/gpm/onboarding/overview to return 400 for missing session_token, got $overview_missing_code"
  cat "$overview_missing_body"
  exit 1
fi
if ! jq -e '.ok == false and (.error | contains("session_token is required"))' "$overview_missing_body" >/dev/null; then
  echo "overview missing-session response payload mismatch"
  cat "$overview_missing_body"
  exit 1
fi

echo "[local-control-api-contract] gpm service start requires session_token (fail-closed)"
gpm_start_missing_body="$TMP_DIR/gpm_service_start_missing_session_token.json"
gpm_start_missing_code="$(curl -sS -o "$gpm_start_missing_body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data '{}' "${LOCAL_API_BASE}/v1/gpm/service/start")"
if [[ "$gpm_start_missing_code" != "401" ]]; then
  echo "expected /v1/gpm/service/start to return 401 for missing session_token, got $gpm_start_missing_code"
  cat "$gpm_start_missing_body"
  exit 1
fi
if ! jq -e '.ok == false and (.error | contains("session token is required"))' "$gpm_start_missing_body" >/dev/null; then
  echo "gpm service start missing-session response payload mismatch"
  cat "$gpm_start_missing_body"
  exit 1
fi

echo "[local-control-api-contract] onboarding overview returns consolidated session + registration + readiness"
challenge_json="$(api_post_json "/v1/gpm/auth/challenge" '{"wallet_address":"cosmos1overviewcontract","wallet_provider":"keplr"}')"
if ! jq -e '.ok == true and (.challenge_id | type == "string" and length > 0) and (.message | type == "string" and length > 0)' <<<"$challenge_json" >/dev/null; then
  echo "auth challenge did not return expected payload"
  echo "$challenge_json"
  exit 1
fi
challenge_id="$(jq -r '.challenge_id // ""' <<<"$challenge_json")"
if [[ -z "$challenge_id" ]]; then
  echo "auth challenge missing challenge_id"
  echo "$challenge_json"
  exit 1
fi
verify_json="$(api_post_json "/v1/gpm/auth/verify" "{\"wallet_address\":\"cosmos1overviewcontract\",\"wallet_provider\":\"keplr\",\"challenge_id\":\"${challenge_id}\",\"signature\":\"sig-contract-overview-123\"}")"
if ! jq -e '.ok == true and .session.wallet_address == "cosmos1overviewcontract" and .session.role == "client" and (.session_token | type == "string" and length > 0)' <<<"$verify_json" >/dev/null; then
  echo "auth verify did not return expected session payload"
  echo "$verify_json"
  exit 1
fi
overview_session_token="$(jq -r '.session_token // ""' <<<"$verify_json")"
if [[ -z "$overview_session_token" ]]; then
  echo "auth verify missing session_token"
  echo "$verify_json"
  exit 1
fi

echo "[local-control-api-contract] gpm service start rejects client session role (fail-closed)"
gpm_start_client_body="$TMP_DIR/gpm_service_start_client_forbidden.json"
gpm_start_client_code="$(curl -sS -o "$gpm_start_client_body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data "{\"session_token\":\"${overview_session_token}\"}" "${LOCAL_API_BASE}/v1/gpm/service/start")"
if [[ "$gpm_start_client_code" != "403" ]]; then
  echo "expected /v1/gpm/service/start to return 403 for client session role, got $gpm_start_client_code"
  cat "$gpm_start_client_body"
  exit 1
fi
if ! jq -e '.ok == false and (.error | contains("session role")) and (.error | contains("operator or admin"))' "$gpm_start_client_body" >/dev/null; then
  echo "gpm service start client-role response payload mismatch"
  cat "$gpm_start_client_body"
  exit 1
fi

overview_json="$(api_post_json "/v1/gpm/onboarding/overview" "{\"session_token\":\"${overview_session_token}\"}")"
if ! jq -e '.ok == true and .session.wallet_address == "cosmos1overviewcontract" and .registration.wallet_address == "cosmos1overviewcontract" and .registration.status == "not_registered" and .readiness.role == "client" and .readiness.session_present == true and (.readiness.lifecycle_actions_unlocked | type == "boolean")' <<<"$overview_json" >/dev/null; then
  echo "onboarding overview did not return expected consolidated payload"
  echo "$overview_json"
  exit 1
fi
if ! jq -e '.ok == true and (.readiness.chain_binding_status == "not_applicable") and (.readiness.chain_binding_ok == false) and ((.readiness.chain_binding_reason // "") == "")' <<<"$overview_json" >/dev/null; then
  echo "onboarding overview missing expected default chain-binding readiness fields"
  echo "$overview_json"
  exit 1
fi

echo "[local-control-api-contract] chain-binding readiness reports bound status after operator approval"
operator_apply_bound_json="$(api_post_json "/v1/gpm/onboarding/operator/apply" "{\"session_token\":\"${overview_session_token}\",\"chain_operator_id\":\"operator-contract-a\",\"server_label\":\"contract-bound\"}")"
if ! jq -e '.ok == true and .application.status == "pending" and .application.chain_operator_id == "operator-contract-a"' <<<"$operator_apply_bound_json" >/dev/null; then
  echo "operator apply (bound setup) did not return expected payload"
  echo "$operator_apply_bound_json"
  exit 1
fi
operator_approve_bound_json="$(api_post_json "/v1/gpm/onboarding/operator/approve" "{\"wallet_address\":\"cosmos1overviewcontract\",\"approved\":true,\"admin_token\":\"${LOCAL_API_OPERATOR_ADMIN_TOKEN}\"}")"
if ! jq -e '.ok == true and .decision == "approved" and .application.status == "approved"' <<<"$operator_approve_bound_json" >/dev/null; then
  echo "operator approve (bound setup) did not return expected payload"
  echo "$operator_approve_bound_json"
  exit 1
fi
server_bound_json="$(api_post_json "/v1/gpm/onboarding/server/status" "{\"session_token\":\"${overview_session_token}\"}")"
if ! jq -e '.ok == true and .readiness.role == "operator" and .readiness.operator_application_status == "approved" and .readiness.chain_binding_status == "bound" and .readiness.chain_binding_ok == true and ((.readiness.chain_binding_reason // "") == "")' <<<"$server_bound_json" >/dev/null; then
  echo "server readiness did not report expected bound chain-binding state"
  echo "$server_bound_json"
  exit 1
fi
overview_bound_json="$(api_post_json "/v1/gpm/onboarding/overview" "{\"session_token\":\"${overview_session_token}\"}")"
if ! jq -e '.ok == true and .readiness.chain_binding_status == "bound" and .readiness.chain_binding_ok == true and ((.readiness.chain_binding_reason // "") == "")' <<<"$overview_bound_json" >/dev/null; then
  echo "onboarding overview did not report expected bound chain-binding state"
  echo "$overview_bound_json"
  exit 1
fi

echo "[local-control-api-contract] gpm service start succeeds for approved operator session"
gpm_start_approved_body="$TMP_DIR/gpm_service_start_operator_approved_success.json"
gpm_start_approved_code="$(curl -sS -o "$gpm_start_approved_body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data "{\"session_token\":\"${overview_session_token}\"}" "${LOCAL_API_BASE}/v1/gpm/service/start")"
if [[ "$gpm_start_approved_code" != "200" ]]; then
  echo "expected /v1/gpm/service/start to return 200 for approved operator session, got $gpm_start_approved_code"
  cat "$gpm_start_approved_body"
  exit 1
fi
if ! jq -e '.ok == true and .action == "start"' "$gpm_start_approved_body" >/dev/null; then
  echo "gpm service start did not return expected success payload for approved operator session"
  cat "$gpm_start_approved_body"
  exit 1
fi

echo "[local-control-api-contract] chain-binding readiness reports pending_approval in negative scenario"
operator_apply_pending_json="$(api_post_json "/v1/gpm/onboarding/operator/apply" "{\"session_token\":\"${overview_session_token}\",\"chain_operator_id\":\"operator-contract-b\",\"server_label\":\"contract-pending\"}")"
if ! jq -e '.ok == true and .application.status == "pending" and .application.chain_operator_id == "operator-contract-b"' <<<"$operator_apply_pending_json" >/dev/null; then
  echo "operator apply (negative setup) did not return expected payload"
  echo "$operator_apply_pending_json"
  exit 1
fi
server_pending_json="$(api_post_json "/v1/gpm/onboarding/server/status" "{\"session_token\":\"${overview_session_token}\"}")"
if ! jq -e '.ok == true and .readiness.role == "operator" and .readiness.operator_application_status == "pending" and .readiness.chain_binding_status == "pending_approval" and .readiness.chain_binding_ok == false and (.readiness.chain_binding_reason | type == "string") and (.readiness.chain_binding_reason | contains("pending approval"))' <<<"$server_pending_json" >/dev/null; then
  echo "server readiness did not report expected pending_approval chain-binding state"
  echo "$server_pending_json"
  exit 1
fi
overview_pending_json="$(api_post_json "/v1/gpm/onboarding/overview" "{\"session_token\":\"${overview_session_token}\"}")"
if ! jq -e '.ok == true and .readiness.operator_application_status == "pending" and .readiness.chain_binding_status == "pending_approval" and .readiness.chain_binding_ok == false and (.readiness.chain_binding_reason | contains("pending approval"))' <<<"$overview_pending_json" >/dev/null; then
  echo "onboarding overview did not report expected pending_approval chain-binding state"
  echo "$overview_pending_json"
  exit 1
fi

echo "[local-control-api-contract] gpm service start fails closed for pending operator status"
gpm_start_pending_body="$TMP_DIR/gpm_service_start_pending_forbidden.json"
gpm_start_pending_code="$(curl -sS -o "$gpm_start_pending_body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data "{\"session_token\":\"${overview_session_token}\"}" "${LOCAL_API_BASE}/v1/gpm/service/start")"
if [[ "$gpm_start_pending_code" != "403" ]]; then
  echo "expected /v1/gpm/service/start to return 403 for pending operator status, got $gpm_start_pending_code"
  cat "$gpm_start_pending_body"
  exit 1
fi
if ! jq -e '.ok == false and ((.error | contains("not approved")) or (.error | contains("pending")))' "$gpm_start_pending_body" >/dev/null; then
  echo "gpm service start pending-operator response payload mismatch"
  cat "$gpm_start_pending_body"
  exit 1
fi

echo "[local-control-api-contract] set_profile normalizes alias and forwards config-v1-set-profile"
set_profile_json="$(api_post_json "/v1/set_profile" '{"path_profile":"private"}')"
if ! jq -e '.ok == true and .path_profile == "3hop"' <<<"$set_profile_json" >/dev/null; then
  echo "set_profile endpoint did not normalize to 3hop"
  echo "$set_profile_json"
  exit 1
fi
set_profile_call="$(require_last_call "config-v1-set-profile")"
assert_line_has "$set_profile_call" $'\t--path-profile\t3hop' "set_profile forwarding missing --path-profile 3hop"

echo "[local-control-api-contract] connect (2hop) forwards preflight + up contract flags"
connect_2hop_json="$(api_post_json "/v1/connect" '{"bootstrap_directory":"http://127.0.0.1:8081","invite_key":"inv-contract-2hop","path_profile":"2hop","interface":"wgvpn0","discovery_wait_sec":17,"ready_timeout_sec":40}')"
if ! jq -e '.ok == true and .stage == "connect" and .profile == "2hop"' <<<"$connect_2hop_json" >/dev/null; then
  echo "connect 2hop endpoint did not return expected payload"
  echo "$connect_2hop_json"
  exit 1
fi
preflight_2hop_call="$(require_last_call "client-vpn-preflight")"
assert_line_has "$preflight_2hop_call" $'\t--bootstrap-directory\thttp://127.0.0.1:8081' "connect preflight missing bootstrap directory"
assert_line_has "$preflight_2hop_call" $'\t--discovery-wait-sec\t17' "connect preflight missing discovery wait"
assert_line_has "$preflight_2hop_call" $'\t--operator-floor-check\t1' "connect preflight missing operator floor check default"
assert_line_has "$preflight_2hop_call" $'\t--issuer-quorum-check\t1' "connect preflight missing issuer quorum check default"
up_2hop_call="$(require_last_call "client-vpn-up")"
if ! printf '%s\n' "$up_2hop_call" | grep -F -- $'\t--subject\tinv-contract-2hop' >/dev/null 2>&1 && \
   ! printf '%s\n' "$up_2hop_call" | grep -F -- $'\t--subject-file\t' >/dev/null 2>&1; then
  echo "connect up missing invite subject forwarding (--subject or --subject-file)"
  echo "line: $up_2hop_call"
  echo "calls:"
  cat "$CALLS_FILE"
  exit 1
fi
assert_line_has "$up_2hop_call" $'\t--path-profile\t2hop' "connect up missing --path-profile 2hop"
assert_line_has "$up_2hop_call" $'\t--session-reuse\t1' "connect up missing deterministic --session-reuse 1"
assert_line_has "$up_2hop_call" $'\t--allow-session-churn\t0' "connect up missing deterministic --allow-session-churn 0"
assert_line_has "$up_2hop_call" $'\t--min-operators\t2' "connect up missing 2hop min operators"
assert_line_has "$up_2hop_call" $'\t--operator-floor-check\t1' "connect up missing 2hop operator floor check"
assert_line_has "$up_2hop_call" $'\t--issuer-quorum-check\t1' "connect up missing 2hop issuer quorum check"
assert_line_has "$up_2hop_call" $'\t--force-restart\t1' "connect up missing force restart"
assert_line_has "$up_2hop_call" $'\t--foreground\t0' "connect up missing detached foreground flag"

echo "[local-control-api-contract] connect (1hop speed-1hop alias) applies direct-exit defaults and can skip preflight"
connect_1hop_json="$(api_post_json "/v1/connect" '{"bootstrap_directory":"http://127.0.0.1:8081","invite_key":"inv-contract-1hop","path_profile":"speed-1hop","run_preflight":false}')"
if ! jq -e '.ok == true and .profile == "1hop"' <<<"$connect_1hop_json" >/dev/null; then
  echo "connect 1hop endpoint did not return expected profile"
  echo "$connect_1hop_json"
  exit 1
fi
up_1hop_call="$(require_last_call "client-vpn-up")"
assert_line_has "$up_1hop_call" $'\t--path-profile\t1hop' "connect 1hop missing normalized --path-profile 1hop"
assert_line_has "$up_1hop_call" $'\t--session-reuse\t1' "connect 1hop missing deterministic --session-reuse 1"
assert_line_has "$up_1hop_call" $'\t--allow-session-churn\t0' "connect 1hop missing deterministic --allow-session-churn 0"
assert_line_has "$up_1hop_call" $'\t--min-operators\t1' "connect 1hop missing min-operators 1"
assert_line_has "$up_1hop_call" $'\t--operator-floor-check\t0' "connect 1hop missing operator floor disable"
assert_line_has "$up_1hop_call" $'\t--issuer-quorum-check\t0' "connect 1hop missing issuer quorum disable"
assert_line_has "$up_1hop_call" $'\t--beta-profile\t0' "connect 1hop missing beta-profile 0"
assert_line_has "$up_1hop_call" $'\t--prod-profile\t0' "connect 1hop missing prod-profile 0"
assert_line_has "$up_1hop_call" $'\t--install-route\t0' "connect 1hop missing default install-route 0"

echo "[local-control-api-contract] disconnect endpoint forwards client-vpn-down --force-iface-cleanup 1"
disconnect_json="$(api_post_json "/v1/disconnect" '{}')"
if ! jq -e '.ok == true and .stage == "disconnect"' <<<"$disconnect_json" >/dev/null; then
  echo "disconnect endpoint did not return expected payload"
  echo "$disconnect_json"
  exit 1
fi
disconnect_call="$(require_last_call "client-vpn-down")"
assert_line_has "$disconnect_call" $'\t--force-iface-cleanup\t1' "disconnect forwarding missing --force-iface-cleanup 1"

echo "[local-control-api-contract] update endpoint is fail-closed by default"
: >"$CALLS_FILE"
update_disabled_body="$TMP_DIR/update_disabled.json"
update_disabled_code="$(curl -sS -o "$update_disabled_body" -w '%{http_code}' -X POST -H "Authorization: Bearer ${LOCAL_API_AUTH_TOKEN}" -H 'Content-Type: application/json' --data '{"remote":"origin","branch":"main","allow_dirty":true}' "${LOCAL_API_BASE}/v1/update")"
if [[ "$update_disabled_code" != "403" ]]; then
  echo "expected /v1/update to return 403 when LOCAL_CONTROL_API_ALLOW_UPDATE=0, got $update_disabled_code"
  cat "$update_disabled_body"
  exit 1
fi
if ! jq -e '.ok == false and (.error | contains("update endpoint disabled"))' "$update_disabled_body" >/dev/null; then
  echo "update disabled response payload mismatch"
  cat "$update_disabled_body"
  exit 1
fi
if grep -q '^self-update' "$CALLS_FILE"; then
  echo "update disabled path unexpectedly executed self-update command"
  cat "$CALLS_FILE"
  exit 1
fi

stop_local_api

echo "[local-control-api-contract] start local API (update enabled)"
start_local_api 1

echo "[local-control-api-contract] update endpoint forwards self-update command form"
update_enabled_json="$(api_post_json "/v1/update" '{"remote":"origin","branch":"main","allow_dirty":true}')"
if ! jq -e '.ok == true' <<<"$update_enabled_json" >/dev/null; then
  echo "update enabled endpoint did not return success"
  echo "$update_enabled_json"
  exit 1
fi
update_call="$(require_last_call "self-update")"
assert_line_has "$update_call" $'\t--show-status\t1' "update forwarding missing --show-status 1"
assert_line_has "$update_call" $'\t--remote\torigin' "update forwarding missing --remote origin"
assert_line_has "$update_call" $'\t--branch\tmain' "update forwarding missing --branch main"
assert_line_has "$update_call" $'\t--allow-dirty\t1' "update forwarding missing --allow-dirty 1"

stop_local_api

echo "local control API contract integration check ok"
