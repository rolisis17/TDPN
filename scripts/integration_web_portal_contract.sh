#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

REQUIRED_FILES=(
  "apps/web/portal.html"
  "apps/web/assets/portal.js"
  "apps/web/README.md"
)

for path in "${REQUIRED_FILES[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "web portal contract failed: missing required file: $path"
    exit 1
  fi
done
echo "[web-portal] required files exist"

PORTAL_HTML="apps/web/portal.html"
PORTAL_JS="apps/web/assets/portal.js"
README_FILE="apps/web/README.md"

require_regex_marker() {
  local file="$1"
  local pattern="$2"
  local description="$3"
  if ! grep -qE "$pattern" "$file"; then
    echo "web portal contract failed: missing ${description} marker /${pattern}/ in $file"
    exit 1
  fi
}

require_absent_regex_marker() {
  local file="$1"
  local pattern="$2"
  local description="$3"
  if grep -qiE "$pattern" "$file"; then
    echo "web portal contract failed: found stale ${description} marker /${pattern}/ in $file"
    exit 1
  fi
}

# Client-readiness UI markers in portal scaffold.
if ! grep -qF 'id="status_banner"' "$PORTAL_HTML"; then
  echo "web portal contract failed: missing readiness banner marker id=status_banner in $PORTAL_HTML"
  exit 1
fi
if ! grep -qF 'id="status_title"' "$PORTAL_HTML"; then
  echo "web portal contract failed: missing readiness status marker id=status_title in $PORTAL_HTML"
  exit 1
fi
if ! grep -qF 'id="status_detail"' "$PORTAL_HTML"; then
  echo "web portal contract failed: missing readiness guidance marker id=status_detail in $PORTAL_HTML"
  exit 1
fi
if ! grep -qF 'id="local_api_auth_token"' "$PORTAL_HTML"; then
  echo "web portal contract failed: missing local API bearer token marker id=local_api_auth_token in $PORTAL_HTML"
  exit 1
fi
if ! grep -qF 'id="onboarding_step_client"' "$PORTAL_HTML"; then
  echo "web portal contract failed: missing client-step readiness marker id=onboarding_step_client in $PORTAL_HTML"
  exit 1
fi
if ! grep -qF 'id="register_client_btn"' "$PORTAL_HTML"; then
  echo "web portal contract failed: missing register-client action marker id=register_client_btn in $PORTAL_HTML"
  exit 1
fi
if ! grep -qF 'id="compat_override_section"' "$PORTAL_HTML"; then
  echo "web portal contract failed: missing compatibility-override section marker id=compat_override_section in $PORTAL_HTML"
  exit 1
fi
if ! grep -qF 'id="client_readiness"' "$PORTAL_HTML"; then
  echo "web portal contract failed: missing client readiness marker id=client_readiness in $PORTAL_HTML"
  exit 1
fi
if ! grep -qF 'id="client_readiness_status"' "$PORTAL_HTML"; then
  echo "web portal contract failed: missing client readiness status marker id=client_readiness_status in $PORTAL_HTML"
  exit 1
fi
if ! grep -qF 'id="client_readiness_guidance"' "$PORTAL_HTML"; then
  echo "web portal contract failed: missing client readiness guidance marker id=client_readiness_guidance in $PORTAL_HTML"
  exit 1
fi
echo "[web-portal] portal readiness UI markers are present"

# Bootstrap trust panel markers in portal scaffold.
BOOTSTRAP_TRUST_UI_MARKERS=(
  'id="bootstrap_trust_status"'
  'id="bootstrap_trust_status_line"'
  'id="bootstrap_trust_state"'
  'id="bootstrap_trust_guidance"'
  'id="bootstrap_trust_summary"'
)
for pattern in "${BOOTSTRAP_TRUST_UI_MARKERS[@]}"; do
  require_regex_marker "$PORTAL_HTML" "$pattern" "bootstrap-trust UI"
done
require_regex_marker "$PORTAL_HTML" 'Bootstrap trust status' "bootstrap-trust label"
echo "[web-portal] bootstrap trust UI markers are present"

# Connection console parity markers (single-window tabs + controls).
CONNECTION_UI_MARKERS=(
  'id="connection_console"'
  'id="connection_snapshot"'
  'id="connection_state"'
  'id="connection_detail"'
  'id="connection_routing_mode"'
  'id="connection_routing_detail"'
  'id="tab_client"'
  'id="tab_server"'
  'id="panel_client"'
  'id="panel_server"'
  'id="client_lock_hint"'
  'id="server_lock_hint"'
  'id="operator_approval_policy_hint"'
  'id="config_endpoint_hint"'
  'id="connect_policy_hint"'
  'id="connect_interface"'
  'id="connect_discovery_wait_sec"'
  'id="connect_ready_timeout_sec"'
  'id="connect_run_preflight"'
  'id="connect_prod_profile"'
  'id="connect_install_route"'
  'id="connect_btn"'
  'id="disconnect_btn"'
  'id="status_btn"'
  'id="server_lifecycle_hint"'
  'id="server_start_btn"'
  'id="server_stop_btn"'
  'id="server_restart_btn"'
  'id="status_btn_server"'
)
for marker in "${CONNECTION_UI_MARKERS[@]}"; do
  if ! grep -qF "$marker" "$PORTAL_HTML"; then
    echo "web portal contract failed: missing connection console UI marker '$marker' in $PORTAL_HTML"
    exit 1
  fi
done
echo "[web-portal] connection console UI markers are present"

# Readiness field markers (new + compatibility aliases).
if ! grep -qE 'client_tab_visible|tab_visible' "$PORTAL_JS"; then
  echo "web portal contract failed: missing readiness marker for client_tab_visible/tab_visible in $PORTAL_JS"
  exit 1
fi
if ! grep -qE 'client_lock_reason|lock_reason' "$PORTAL_JS"; then
  echo "web portal contract failed: missing readiness marker for client_lock_reason/lock_reason in $PORTAL_JS"
  exit 1
fi

# Compute/render/gating markers for client-readiness flow.
JS_MARKERS=(
  'function parseServerReadiness('
  'function parseClientRegistrationStatus('
  'const CLIENT_REGISTRATION_TRUST_DRIFT_STATUS_KEYS = new Set(['
  'function parseClientRegistrationTrustDriftState('
  'function applyClientRegistrationPayload('
  'function composeClientRegistrationTrustDriftGuidance('
  'function setClientReadiness('
  'function computeClientReadiness('
  'function assertClientRegistrationActionAllowed('
  'function refreshClientReadiness('
  'function syncClientRegistrationAction('
  'function refreshOnboardingSteps('
  'setStepState(onboardingStepClientEl'
  'const clientLockReason = nonEmptyString(firstDefined(readiness.client_lock_reason, readiness.clientLockReason));'
  'clientTabVisible: parseBooleanLike(firstDefined(readiness.client_tab_visible, readiness.clientTabVisible))'
  'const endpointPostureRaw = firstDefined(readiness.endpoint_posture, readiness.endpointPosture);'
  'endpointPostureRaw && typeof endpointPostureRaw === "object" && !Array.isArray(endpointPostureRaw)'
  'endpointPosture.endpoint_warnings'
  'function parseEndpointPostureObject('
  'function formatEndpointPostureCountSummary('
  'function endpointPostureGuidanceFromObject('
  'const localApiAuthTokenEl = byId("local_api_auth_token");'
  'function localApiAuthToken() {'
  'response.status === 401 && !localApiAuthToken()'
  'Local API bearer token is missing. Set Local API auth token in the portal and retry.'
  'const token = localApiAuthToken();'
  'const operatorApprovalPolicyHintEl = byId("operator_approval_policy_hint");'
  'function parseOperatorApprovalRequireSessionConfig('
  'function parseOperatorApprovalRequireSessionPolicySourceConfig('
  'function parseAuthVerifyRequireCryptoProofConfig('
  'function parseAuthVerifyRequireCryptoProofPolicySourceConfig('
  'authVerifyRequireCryptoProof = parseAuthVerifyRequireCryptoProofConfig(config);'
  'authVerifyRequireCryptoProofPolicySource = parseAuthVerifyRequireCryptoProofPolicySourceConfig(config);'
  'function refreshServerReadinessStatus('
  'byId("register_client_btn").addEventListener'
  'assertClientRegistrationActionAllowed();'
  'session_token: byId("session_token").value.trim()'
  'compatibilityOverrideEnabled()'
  'allowLegacyConnectOverride'
  'function parseAllowLegacyConnectOverrideConfig('
  'compatOverrideSectionEl.hidden = !allowLegacyConnectOverride;'
  'if (clientRegistrationTrustDriftDetected) {'
  'state: "re_registration_required",'
  'statusText: "Re-registration required",'
  '"Registration trust is stale or degraded against the current manifest."'
  '"Use Register Client to re-register and refresh trusted bootstrap directories."'
  'Manual verify is disabled by active auth policy. Use Sign + Verify (Wallet).'
  'Manual verify is disabled by active auth policy (wallet-extension-source required; source:'
)
for marker in "${JS_MARKERS[@]}"; do
  if ! grep -qF "$marker" "$PORTAL_JS"; then
    echo "web portal contract failed: missing portal JS readiness/gating marker '$marker' in $PORTAL_JS"
    exit 1
  fi
done
echo "[web-portal] portal JS readiness compute/render/gating markers are present"

# Production-mode lock markers (config telemetry + UX gating).
PRODUCTION_LOCK_JS_MARKERS=(
  'function[[:space:]]+parseGpmProductionModeConfig[[:space:]]*\('
  'gpm_production_mode'
  'function[[:space:]]+deriveGpmProductionModeFromPolicyHints[[:space:]]*\('
  'parsedGpmProductionMode[[:space:]]*!==[[:space:]]*undefined'
  'manualSource[[:space:]]*&&[[:space:]]*gpmProductionMode'
  'Compatibility override is disabled in production mode\. Use session-based registration\.'
  'Manual verify is disabled in production mode\. Use Sign \+ Verify \(Wallet\)\.'
)
for pattern in "${PRODUCTION_LOCK_JS_MARKERS[@]}"; do
  require_regex_marker "$PORTAL_JS" "$pattern" "production-lock JS"
done
echo "[web-portal] production-mode lock markers are present"

# Bootstrap trust telemetry parse/render markers.
BOOTSTRAP_TRUST_JS_MARKERS=(
  'const[[:space:]]+bootstrapTrustStatusEl[[:space:]]*=[[:space:]]*byId\("bootstrap_trust_status"\)'
  'const[[:space:]]+bootstrapTrustStatusLineEl[[:space:]]*=[[:space:]]*byId\("bootstrap_trust_status_line"\)'
  'const[[:space:]]+bootstrapTrustStateEl[[:space:]]*=[[:space:]]*byId\("bootstrap_trust_state"\)'
  'const[[:space:]]+bootstrapTrustGuidanceEl[[:space:]]*=[[:space:]]*byId\("bootstrap_trust_guidance"\)'
  'const[[:space:]]+bootstrapTrustSummaryEl[[:space:]]*=[[:space:]]*byId\("bootstrap_trust_summary"\)'
  'let[[:space:]]+bootstrapTrustTelemetry[[:space:]]*=[[:space:]]*null'
  'function[[:space:]]+parseTimestampMs[[:space:]]*\('
  'function[[:space:]]+formatBootstrapManifestExpiryLabel[[:space:]]*\('
  'function[[:space:]]+normalizeBootstrapManifestSource[[:space:]]*\('
  'function[[:space:]]+formatBootstrapManifestSourceLabel[[:space:]]*\('
  'function[[:space:]]+extractBootstrapTrustTelemetry[[:space:]]*\('
  'function[[:space:]]+summarizeBootstrapTrustTelemetry[[:space:]]*\('
  'function[[:space:]]+classifyBootstrapTrustTelemetry[[:space:]]*\('
  'function[[:space:]]+setBootstrapTrustStatus[[:space:]]*\('
  'function[[:space:]]+applyBootstrapTrustStatusPayload[[:space:]]*\('
  'function[[:space:]]+markBootstrapTrustStatusRefreshIssue[[:space:]]*\('
  'async[[:space:]]+function[[:space:]]+requestBootstrapManifest[[:space:]]*\('
  'get\("/v1/gpm/bootstrap/manifest"\)'
  'applyBootstrapTrustStatusPayload\(result\)'
  'async[[:space:]]+function[[:space:]]+refreshBootstrapTrustStatusBestEffort[[:space:]]*\('
  'bootstrapTrustStatusEl\.dataset\.kind'
  'bootstrapTrustStatusLineEl\.classList\.remove\("good",[[:space:]]*"warn",[[:space:]]*"bad"\)'
  'bootstrapTrustStateEl\.textContent'
  'bootstrapTrustGuidanceEl\.textContent'
  'bootstrapTrustSummaryEl\.textContent'
  'applyBootstrapTrustStatusPayload\(payload\)'
  'run\("bootstrap_manifest",[[:space:]]*requestBootstrapManifest\)'
)
for pattern in "${BOOTSTRAP_TRUST_JS_MARKERS[@]}"; do
  require_regex_marker "$PORTAL_JS" "$pattern" "bootstrap-trust JS"
done

BOOTSTRAP_TRUST_TELEMETRY_FIELDS=(
  'source'
  'manifest_source'
  'signature_verified'
  'expires_at_utc'
  'generated_at_utc'
  'cache_age_sec'
  'resolve_policy'
  'trust_state'
  'trust_reason'
  'manifest_warnings'
)
for field in "${BOOTSTRAP_TRUST_TELEMETRY_FIELDS[@]}"; do
  if ! grep -qF "$field" "$PORTAL_JS"; then
    echo "web portal contract failed: missing bootstrap trust telemetry field marker '$field' in $PORTAL_JS"
    exit 1
  fi
done
echo "[web-portal] bootstrap trust telemetry markers are present"

ENDPOINT_POSTURE_OBJECT_FIELDS=(
  'server_mode'
  'total_urls'
  'http_urls'
  'https_urls'
  'mixed_scheme'
  'has_remote_http'
)
for field in "${ENDPOINT_POSTURE_OBJECT_FIELDS[@]}"; do
  if ! grep -qF "$field" "$PORTAL_JS"; then
    echo "web portal contract failed: missing endpoint posture object field marker '$field' in $PORTAL_JS"
    exit 1
  fi
done
echo "[web-portal] endpoint posture object markers are present"

# Connection console JS contract markers.
CONNECTION_JS_MARKERS=(
  'const tabClientEl = byId("tab_client");'
  'const tabServerEl = byId("tab_server");'
  'function refreshConnectPolicyHint('
  'function configEndpointUnavailableFailClosedMode('
  'function failClosedMutatingActionStatusDetail('
  'function syncFailClosedMutatingActionState('
  'function activateWorkspaceTab('
  'function syncWorkspaceTabLockState('
  'function buildConnectRequest('
  'function assertConnectActionAllowed('
  'function requestConnectControl('
  'assertConnectActionAllowed(request);'
  'function requestDisconnectControl('
  'function requestConnectionStatus('
  'function computeServerLifecycleControlState('
  'if (serverReadiness?.serviceMutationsConfigured === false) {'
  '"Lifecycle commands are unavailable because service mutations are not configured on this daemon."'
  'function syncServerLifecycleActionState('
  'const state = computeServerLifecycleControlState();'
  'const disabled = isBusy || state.disabled;'
  'function assertServiceLifecycleActionAllowed('
  'function requestServiceLifecycle('
  'assertServiceLifecycleActionAllowed(normalizedAction);'
  'function assertOperatorMutationActionAllowed('
  'function buildOperatorModerationAuthRequest('
  'assertOperatorMutationActionAllowed("Operator apply");'
  'assertOperatorMutationActionAllowed("Operator approve");'
  'assertOperatorMutationActionAllowed("Operator reject");'
  'Restricted fail-closed mode: /v1/config is unavailable.'
  'Connect policy: restricted fail-closed (source: unavailable; legacy override locked).'
  'Compatibility override is disabled in restricted fail-closed mode because /v1/config is unavailable.'
  'operatorApprovalRequireSession = parseOperatorApprovalRequireSessionConfig(config);'
  'operatorApprovalRequireSessionPolicySource = parseOperatorApprovalRequireSessionPolicySourceConfig(config);'
  'Operator approval auth policy: admin session token required'
  'Operator approval auth policy is unavailable because /v1/config could not be read.'
  'function updateConnectionDashboard('
  'function inferConnectionRoutingSnapshot('
  'function applyConnectionRoutingSnapshot('
  'connectionRoutingModeEl'
  'connectionRoutingDetailEl'
  'function restoreWorkspaceTabPreference('
  'function persistWorkspaceTabPreference('
  'connectRequireSession'
  'allowLegacyConnectOverride'
  'compatibilityOverrideEnabled()'
  'byId("connect_btn").addEventListener'
  'byId("disconnect_btn").addEventListener'
  'byId("status_btn").addEventListener'
  'serverStartBtnEl.addEventListener("click"'
  'serverStopBtnEl.addEventListener("click"'
  'serverRestartBtnEl.addEventListener("click"'
  'byId("status_btn_server").addEventListener'
  'tabClientEl.addEventListener("click"'
  'tabServerEl.addEventListener("click"'
)
for marker in "${CONNECTION_JS_MARKERS[@]}"; do
  if ! grep -qF "$marker" "$PORTAL_JS"; then
    echo "web portal contract failed: missing portal JS connection marker '$marker' in $PORTAL_JS"
    exit 1
  fi
done
echo "[web-portal] portal JS connection markers are present"

# Wallet-extension assisted signing markers.
WALLET_UI_MARKERS=(
  'id="wallet_chain_id"'
  'id="challenge_message"'
  'id="wallet_sign_btn"'
  'id="wallet_signin_btn"'
  'id="signature"'
)
for pattern in "${WALLET_UI_MARKERS[@]}"; do
  require_regex_marker "$PORTAL_HTML" "$pattern" "wallet-assist UI"
done

WALLET_JS_MARKERS=(
  'function[[:space:]]+normalizeWalletProviderValue[[:space:]]*\('
  'function[[:space:]]+resolveWalletExtensionClient[[:space:]]*\('
  'async[[:space:]]+function[[:space:]]+signChallengeWithWalletExtension[[:space:]]*\('
  'async[[:space:]]+function[[:space:]]+requestWalletSignIn[[:space:]]*\('
  'function[[:space:]]+buildWalletSignatureContext[[:space:]]*\('
  'function[[:space:]]+isWalletSignatureContextValidForRequest[[:space:]]*\('
  'function[[:space:]]+authVerifySignatureContext[[:space:]]*\('
  'signArbitrary[[:space:]]*\('
  'signature_kind:[[:space:]]*"sign_arbitrary"'
  'signature_source:[[:space:]]*"wallet_extension"'
  'signed_message:[[:space:]]*normalizedChallengeMessage'
  'metadata\.signature_public_key[[:space:]]*=[[:space:]]*publicKey'
  'metadata\.signature_public_key_type[[:space:]]*=[[:space:]]*publicKeyType'
  'metadata\.signature_envelope[[:space:]]*=[[:space:]]*signatureEnvelope'
  'requestChallengeId[[:space:]]*!==[[:space:]]*\(nonEmptyString\(context\.challenge_id\)[[:space:]]*\|\|[[:space:]]*""\)'
  'requestSignature[[:space:]]*!==[[:space:]]*\(nonEmptyString\(context\.signature\)[[:space:]]*\|\|[[:space:]]*""\)'
  'const[[:space:]]+signatureContext[[:space:]]*=[[:space:]]*authVerifySignatureContext\(request\)'
  'Object\.assign\(request,[[:space:]]*signatureContext\)'
  'clearWalletSignatureContext\(\)'
  'byId\("wallet_sign_btn"\)[[:space:]]*\.addEventListener\("click"'
  'byId\("wallet_signin_btn"\)[[:space:]]*\.addEventListener\("click"'
  'byId\("signature"\)[[:space:]]*\.value[[:space:]]*=[[:space:]]*signature'
  'byId\("signature"\)[[:space:]]*\.value[[:space:]]*\.trim\(\)'
)
for pattern in "${WALLET_JS_MARKERS[@]}"; do
  require_regex_marker "$PORTAL_JS" "$pattern" "wallet-assist JS"
done
echo "[web-portal] wallet-extension assisted signing markers are present"

require_absent_regex_marker "$PORTAL_HTML" 'wallet-?extension signing is tracked next' "wallet sign-in roadmap"
require_absent_regex_marker "$README_FILE" 'wallet-?extension signing is tracked next' "wallet sign-in roadmap"
if ! grep -qF 'Keplr and Leap wallet-extension sign + verify are available now.' "$PORTAL_HTML"; then
  echo "web portal contract failed: portal copy must state Keplr/Leap wallet-extension sign + verify availability"
  exit 1
fi
if ! grep -qF 'Wallet sign-in support is available now for Keplr/Leap wallet-extension assisted signing in portal' "$README_FILE"; then
  echo "web portal contract failed: README must state wallet sign-in support is available now for Keplr/Leap"
  exit 1
fi
echo "[web-portal] wallet-support copy no longer uses tracked-next language"

if ! grep -qF 'client_tab_visible' "$README_FILE"; then
  echo "web portal contract failed: README must mention readiness.client_tab_visible"
  exit 1
fi
if ! grep -qF 'client_lock_reason' "$README_FILE"; then
  echo "web portal contract failed: README must mention readiness.client_lock_reason"
  exit 1
fi
if ! grep -qiE 'local api auth token.*authorization: bearer|authorization: bearer.*local api auth token' "$README_FILE"; then
  echo "web portal contract failed: README must mention local API auth token bearer transport"
  exit 1
fi
if ! grep -qiE '401.*local api auth token|local api auth token.*401' "$README_FILE"; then
  echo "web portal contract failed: README must mention 401 guidance for missing local API auth token"
  exit 1
fi
for field in server_mode total_urls http_urls https_urls mixed_scheme has_remote_http; do
  if ! grep -qF "$field" "$README_FILE"; then
    echo "web portal contract failed: README must mention readiness.endpoint_posture.$field"
    exit 1
  fi
done
if ! grep -qiE 'register(ing|ed)? client|client registration|register-client' "$README_FILE"; then
  echo "web portal contract failed: README must describe client registration lock/readiness behavior"
  exit 1
fi
if ! grep -qiE '/v1/config.*(fail-closed|restricted)|fail-closed.*(/v1/config|runtime config endpoint)' "$README_FILE"; then
  echo "web portal contract failed: README must document fail-closed behavior when /v1/config is unavailable"
  exit 1
fi
if ! grep -qF 'gpm_operator_approval_require_session' "$README_FILE"; then
  echo "web portal contract failed: README must mention gpm_operator_approval_require_session"
  exit 1
fi
if ! grep -qF 'gpm_operator_approval_require_session_policy_source' "$README_FILE"; then
  echo "web portal contract failed: README must mention gpm_operator_approval_require_session_policy_source"
  exit 1
fi
if ! grep -qF 'GPM_OPERATOR_APPROVAL_REQUIRE_SESSION' "$README_FILE"; then
  echo "web portal contract failed: README must mention GPM_OPERATOR_APPROVAL_REQUIRE_SESSION override behavior"
  exit 1
fi
if ! grep -qF 'gpm_auth_verify_require_crypto_proof' "$README_FILE"; then
  echo "web portal contract failed: README must mention gpm_auth_verify_require_crypto_proof policy visibility"
  exit 1
fi
if ! grep -qF 'gpm_auth_verify_require_crypto_proof_policy_source' "$README_FILE"; then
  echo "web portal contract failed: README must mention gpm_auth_verify_require_crypto_proof_policy_source policy visibility"
  exit 1
fi
if ! grep -qF 'GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF' "$README_FILE"; then
  echo "web portal contract failed: README must mention GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF override behavior"
  exit 1
fi
if ! grep -qF 'gpm_production_mode' "$README_FILE"; then
  echo "web portal contract failed: README must mention gpm_production_mode config telemetry"
  exit 1
fi
if ! grep -qiE 'production mode.*compatibility override.*(disabled|locked)|compatibility override.*production mode' "$README_FILE"; then
  echo "web portal contract failed: README must explain production-mode compatibility override lock"
  exit 1
fi
if ! grep -qiE 'production mode.*manual.*(wallet|Sign \\+ Verify)|manual.*production mode.*wallet' "$README_FILE"; then
  echo "web portal contract failed: README must explain production-mode manual verify wallet-only guidance"
  exit 1
fi
if ! grep -qiE 'admin_token.*(disabled|fail-closed)|session_token.*(required|policy)' "$README_FILE"; then
  echo "web portal contract failed: README must document strict operator approval auth policy behavior"
  exit 1
fi
if ! grep -qiE 'wallet-?extension.*(keplr|leap)|(keplr|leap).*wallet-?extension' "$README_FILE"; then
  echo "web portal contract failed: README must mention wallet-extension assisted signing for Keplr/Leap"
  exit 1
fi
if ! grep -qiE 'single-window connection console|connection console' "$README_FILE"; then
  echo "web portal contract failed: README must mention single-window connection console"
  exit 1
fi
if ! grep -qiE 'client[^[:alnum:]]*/[^[:alnum:]]*server.*tabs|tabs.*client.*server' "$README_FILE"; then
  echo "web portal contract failed: README must mention Client/Server tabs"
  exit 1
fi
if ! grep -qiE 'connect.*disconnect.*status|/v1/connect.*/v1/disconnect.*/v1/status' "$README_FILE"; then
  echo "web portal contract failed: README must mention connect/disconnect/status controls"
  exit 1
fi
if ! grep -qiE 'server tab lifecycle controls|start.*stop.*restart.*gpm/service' "$README_FILE"; then
  echo "web portal contract failed: README must mention server lifecycle controls"
  exit 1
fi
if ! grep -qF 'signArbitrary' "$README_FILE"; then
  echo "web portal contract failed: README must mention signArbitrary-assisted signing flow"
  exit 1
fi
if ! grep -qF 'signature_public_key' "$README_FILE"; then
  echo "web portal contract failed: README must mention signature_public_key"
  exit 1
fi
if ! grep -qF 'signature_public_key_type' "$README_FILE"; then
  echo "web portal contract failed: README must mention signature_public_key_type"
  exit 1
fi
if ! grep -qiE 'manual (signature|signing).*(fallback|retained)|fallback.*manual (signature|signing)' "$README_FILE"; then
  echo "web portal contract failed: README must mention retained manual signature fallback"
  exit 1
fi
echo "[web-portal] README readiness + wallet-signing notes are present"

echo "web portal contract integration check ok"
