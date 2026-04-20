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

# Connection console parity markers (single-window tabs + controls).
CONNECTION_UI_MARKERS=(
  'id="connection_console"'
  'id="connection_snapshot"'
  'id="connection_state"'
  'id="connection_detail"'
  'id="tab_client"'
  'id="tab_server"'
  'id="panel_client"'
  'id="panel_server"'
  'id="client_lock_hint"'
  'id="server_lock_hint"'
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
  'function updateConnectionDashboard('
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
