#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

REQUIRED_FILES=(
  "apps/web/portal.html"
  "apps/web/assets/portal.js"
  "apps/web/assets/gpm.css"
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
GPM_CSS="apps/web/assets/gpm.css"
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

# Product-lane messaging: the portal is a supporting client workspace. Access
# Recovery remains the beta starting point, so the first viewport must not drift
# back into generic "start here / connect VPN" positioning.
PORTAL_POSITIONING_REQUIRED_MARKERS=(
  'Client workspace'
  'Wallet and runtime controls.'
  'Access Recovery is the beta starting point.'
  'Start with <a href="./recovery.html">Access Recovery</a>'
  'Open Access Recovery for beta handoffs, or connect a wallet for client controls.'
  'Wallet session. Device registration. Connection controls.'
)
for marker in "${PORTAL_POSITIONING_REQUIRED_MARKERS[@]}"; do
  if ! grep -qF "$marker" "$PORTAL_HTML" "$PORTAL_JS"; then
    echo "web portal contract failed: missing product-lane positioning marker '$marker'"
    exit 1
  fi
done
PORTAL_POSITIONING_STALE_HTML_MARKERS=(
  '<p class="eyebrow">Start here</p>'
  '<h1>Connect your wallet.</h1>'
  'Wallet. Device. Connect.'
  '<p class="eyebrow">VPN</p>'
)
for marker in "${PORTAL_POSITIONING_STALE_HTML_MARKERS[@]}"; do
  if grep -qF "$marker" "$PORTAL_HTML"; then
    echo "web portal contract failed: stale primary portal positioning marker '$marker'"
    exit 1
  fi
done
PORTAL_POSITIONING_STALE_JS_MARKERS=(
  'return "Connect Wallet.";'
  'return "Use Connect Wallet, or use advanced Sign Challenge.";'
  'return "Use Connect Wallet.";'
)
for marker in "${PORTAL_POSITIONING_STALE_JS_MARKERS[@]}"; do
  if grep -qF "$marker" "$PORTAL_JS"; then
    echo "web portal contract failed: stale runtime portal positioning marker '$marker'"
    exit 1
  fi
done
if ! grep -qF '`portal.html` must present itself as the client workspace' "$README_FILE"; then
  echo "web portal contract failed: README must document portal messaging contract"
  exit 1
fi
echo "[web-portal] portal product-lane positioning markers are present"

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

# Public/admin split: public portal release builds ship only the client
# workspace plus signed-in contribution/reward status. Server hosting
# applications, admin approval/refusal queues, service lifecycle, audit,
# slashing, settlement, and payout controls belong outside apps/web.
PUBLIC_ADMIN_FORBIDDEN_HTML_MARKERS=(
  'data-admin-only'
  'id="onboarding_step_operator"'
  'id="onboarding_step_server"'
  'id="audit_recent_btn"'
  'id="operator"'
  'id="server_application"'
  'id="server_application_status"'
  'id="tab_server"'
  'id="panel_server"'
  'id="server_start_btn"'
  'id="server_stop_btn"'
  'id="server_restart_btn"'
  'id="status_btn_server"'
  'id="server_status_btn"'
  'id="apply_server_btn"'
  'id="apply_operator_btn"'
  'id="approve_operator_btn"'
  'id="reject_operator_btn"'
  'id="admin_token"'
)
for marker in "${PUBLIC_ADMIN_FORBIDDEN_HTML_MARKERS[@]}"; do
  if grep -qF "$marker" "$PORTAL_HTML"; then
    echo "web portal contract failed: public portal ships forbidden admin/operator/server HTML marker '$marker'"
    exit 1
  fi
done
PUBLIC_ADMIN_FORBIDDEN_JS_MARKERS=(
  'byId("audit_recent_btn").addEventListener'
  'byId("apply_operator_btn").addEventListener'
  'byId("approve_operator_btn").addEventListener'
  'byId("reject_operator_btn").addEventListener'
  'serverStartBtnEl.addEventListener("click"'
  'serverStopBtnEl.addEventListener("click"'
  'serverRestartBtnEl.addEventListener("click"'
  'byId("status_btn_server").addEventListener'
  'post("/v1/gpm/onboarding/operator/list'
  'post("/v1/gpm/onboarding/operator/approve'
  'post("/v1/gpm/onboarding/operator/apply'
  'post("/v1/gpm/onboarding/server/status'
  'post(`/v1/gpm/service/'
  '/v1/gpm/audit/recent'
  'requestServerApply'
  'requestServerStatus'
  'publicServerSessionRequest'
  'apply_server_btn'
  'server_status_btn'
  'server_application_status'
)
for marker in "${PUBLIC_ADMIN_FORBIDDEN_JS_MARKERS[@]}"; do
  if grep -qF "$marker" "$PORTAL_JS"; then
    echo "web portal contract failed: public portal ships forbidden admin/operator/server JS marker '$marker'"
    exit 1
  fi
done
require_absent_regex_marker "$PORTAL_JS" 'admin_token|data-admin-only|PUBLIC_WEB_RELEASE|portalAdminMode|adminOnlyEls|requestOperatorList|requestOperatorApprove|requestServiceLifecycle|requestAuditRecent|operatorList|selected_application_updated_at|requestServerApply|requestServerStatus|publicServerSessionRequest|apply_operator_btn|approve_operator_btn|reject_operator_btn|audit_recent_btn|tab_server|panel_server|server_start_btn|server_stop_btn|server_restart_btn|status_btn_server|apply_server_btn|server_status_btn|server_application_status|/v1/gpm/onboarding/operator/apply|/v1/gpm/onboarding/server/status' "public release admin/operator/server JS bundle"
require_absent_regex_marker "$GPM_CSS" 'admin-portal-mode|data-admin-only|operator-readiness|onboarding-checklist' "admin portal reveal/hide CSS"
if grep -qF 'portal.html#operator' apps/web/index.html; then
  echo "web portal contract failed: public homepage must not deep-link to hidden operator lane"
  exit 1
fi
echo "[web-portal] public admin/operator/server-management surface is absent"

echo "[web-portal] public self-service server application surface is absent"

# Public contribution/reward parity markers: signed-in-user-only controls must stay
# in the public portal while admin review/hold routes remain absent from the portal.
PUBLIC_CONTRIBUTION_HTML_MARKERS=(
  'id="public_contribution_console"'
  'id="contribution_status"'
  'id="contribution_state"'
  'id="contribution_detail"'
  'id="contribution_eligibility_summary"'
  'id="contribution_role"'
  'id="contribution_status_btn"'
  'id="contribution_enable_btn"'
  'id="contribution_disable_btn"'
  'id="reward_current_week_btn"'
  'id="reward_history_btn"'
  'id="contribution_reward_current_week"'
  'id="contribution_reward_week"'
  'id="contribution_reward_units"'
  'id="contribution_reward_status"'
  'id="contribution_reward_settlement"'
  'id="contribution_reward_metering"'
  'id="contribution_history"'
  'id="contribution_history_summary"'
  'id="contribution_history_list"'
)
for marker in "${PUBLIC_CONTRIBUTION_HTML_MARKERS[@]}"; do
  if ! grep -qF "$marker" "$PORTAL_HTML"; then
    echo "web portal contract failed: missing public contribution HTML marker '$marker' in $PORTAL_HTML"
    exit 1
  fi
done
PUBLIC_CONTRIBUTION_JS_MARKERS=(
  'const contributionStatusEl = byId("contribution_status");'
  'const contributionRoleEl = byId("contribution_role");'
  'const PUBLIC_CONTRIBUTION_ROLES = new Set(["micro-relay", "micro-exit"]);'
  'function publicContributionSessionRequest(actionLabel)'
  'function assertPublicContributionMutationAllowed(actionLabel)'
  'const failClosed = configEndpointUnavailableFailClosedMode();'
  'state.failClosed'
  'session_token: byId("session_token").value.trim()'
  'post("/v1/gpm/contribution/status", publicContributionSessionRequest("Contribution status"))'
  'request.role = role;'
  'assertPublicContributionMutationAllowed("Enable contribution")'
  'assertPublicContributionMutationAllowed("Disable contribution")'
  'post("/v1/gpm/contribution/enable", request)'
  'post("/v1/gpm/contribution/disable", publicContributionSessionRequest("Disable contribution"))'
  'post("/v1/gpm/rewards/current-week", publicContributionSessionRequest("Current week reward"))'
  'post("/v1/gpm/rewards/history", publicContributionSessionRequest("Reward history"))'
  'applyPublicContributionStatusPayload(payload.contribution);'
  'function refreshPublicContributionBestEffort('
  'function syncContributionActionState('
  'contributionEnableBtnEl.addEventListener("click"'
  'contributionDisableBtnEl.addEventListener("click"'
  'rewardCurrentWeekBtnEl.addEventListener("click"'
  'rewardHistoryBtnEl.addEventListener("click"'
)
for marker in "${PUBLIC_CONTRIBUTION_JS_MARKERS[@]}"; do
  if ! grep -qF "$marker" "$PORTAL_JS"; then
    echo "web portal contract failed: missing public contribution JS marker '$marker' in $PORTAL_JS"
    exit 1
  fi
done
PUBLIC_CONTRIBUTION_CSS_MARKERS=(
  '.contribution-status'
  '.contribution-reward-grid'
  '.contribution-panel'
  '.metric-list'
  '.reward-history-list'
)
for marker in "${PUBLIC_CONTRIBUTION_CSS_MARKERS[@]}"; do
  if ! grep -qF "$marker" "$GPM_CSS"; then
    echo "web portal contract failed: missing public contribution CSS marker '$marker' in $GPM_CSS"
    exit 1
  fi
done
require_absent_regex_marker "$PORTAL_HTML" '/v1/gpm/admin/(contributions|rewards)' "public contribution admin route"
require_absent_regex_marker "$PORTAL_JS" '/v1/gpm/admin/(contributions|rewards)' "public contribution admin route"
if ! grep -qiE 'public contribution/reward parity|public contribution and reward requests' "$README_FILE"; then
  echo "web portal contract failed: README must document public contribution/reward parity"
  exit 1
fi
if ! grep -qF '/v1/gpm/contribution/status' "$README_FILE" || ! grep -qF '/v1/gpm/rewards/current-week' "$README_FILE"; then
  echo "web portal contract failed: README must mention public contribution/reward endpoints"
  exit 1
fi
if ! grep -qiE 'does not expose admin contribution listing|reward review|reward hold' "$README_FILE"; then
  echo "web portal contract failed: README must document no admin reward/contribution controls in public portal"
  exit 1
fi
echo "[web-portal] public contribution/reward parity markers are present"

# Connection console parity markers (single-window tabs + controls).
CONNECTION_UI_MARKERS=(
  'id="connection_console"'
  'id="connection_snapshot"'
  'id="connection_state"'
  'id="connection_detail"'
  'id="connection_routing_mode"'
  'id="connection_routing_detail"'
  'id="tab_client"'
  'id="panel_client"'
  'id="client_lock_hint"'
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
)
for marker in "${CONNECTION_UI_MARKERS[@]}"; do
  if ! grep -qF "$marker" "$PORTAL_HTML"; then
    echo "web portal contract failed: missing connection console UI marker '$marker' in $PORTAL_HTML"
    exit 1
  fi
done
echo "[web-portal] connection console UI markers are present"

# VPN public portal safety: default/full-route installation must be explicit.
require_absent_regex_marker "$PORTAL_HTML" 'id="connect_install_route"[^>]*checked|checked[^>]*id="connect_install_route"' "checked-by-default install route"
if ! grep -qF 'Expert full-tunnel route' "$PORTAL_HTML"; then
  echo "web portal contract failed: install route control must be labeled as an expert full-tunnel route"
  exit 1
fi
if ! grep -qF 'id="connect_install_route_hint"' "$PORTAL_HTML"; then
  echo "web portal contract failed: missing install route expert warning hint"
  exit 1
fi
if ! grep -qF '.expert-route-warning' "$GPM_CSS"; then
  echo "web portal contract failed: missing expert route warning styling"
  exit 1
fi
if ! grep -qF 'function confirmExpertInstallRouteRequest(request)' "$PORTAL_JS"; then
  echo "web portal contract failed: missing install_route confirmation guard"
  exit 1
fi
if ! grep -qF 'window.confirm(' "$PORTAL_JS" || ! grep -qF 'install_route=true' "$PORTAL_JS"; then
  echo "web portal contract failed: install_route=true must require an explicit confirmation dialog"
  exit 1
fi
if ! grep -qF 'confirmExpertInstallRouteRequest(request);' "$PORTAL_JS"; then
  echo "web portal contract failed: connect request must invoke install_route confirmation before POST"
  exit 1
fi
require_absent_regex_marker "$PORTAL_JS" 'install_route:[[:space:]]*true' "silent install_route=true literal"
if ! grep -qiE 'install/default-route connect control.*unchecked expert full-tunnel|install_route=true.*confirms the warning dialog' "$README_FILE"; then
  echo "web portal contract failed: README must document expert full-tunnel install_route confirmation behavior"
  exit 1
fi
echo "[web-portal] expert full-tunnel install route safety markers are present"

# Public client-readiness field markers.
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
  'function parsePublicReadiness('
  'function parseClientRegistrationStatus('
  'const CLIENT_REGISTRATION_TRUST_DRIFT_STATUS_KEYS = new Set(['
  'function parseClientRegistrationTrustDriftState('
  'function applyClientRegistrationPayload('
  'function composeClientRegistrationTrustDriftGuidance('
  'function setClientReadiness('
  'function computeClientReadiness('
  'function composeClientLaneLockedPortalGuidance('
  'function assertClientRegistrationActionAllowed('
  'function refreshClientReadiness('
  'function syncClientRegistrationAction('
  'function refreshOnboardingSteps('
  'setStepState(onboardingStepClientEl'
  'Open Access Recovery or the Admin Console activation path before retrying.'
  'title: "Client lane locked",'
  'const clientLockReason = nonEmptyString(firstDefined(readiness.client_lock_reason, readiness.clientLockReason));'
  'clientTabVisible: parseBooleanLike(firstDefined(readiness.client_tab_visible, readiness.clientTabVisible))'
  'const localApiAuthTokenEl = byId("local_api_auth_token");'
  'function localApiAuthToken() {'
  'response.status === 401 && !localApiAuthToken()'
  'Local API bearer token is missing. Set Local API auth token in the portal and retry.'
  'const token = localApiAuthToken();'
  'function parseAuthVerifyRequireCryptoProofConfig('
  'function parseAuthVerifyRequireCryptoProofPolicySourceConfig('
  'authVerifyRequireCryptoProof = parseAuthVerifyRequireCryptoProofConfig(config);'
  'authVerifyRequireCryptoProofPolicySource = parseAuthVerifyRequireCryptoProofPolicySourceConfig(config);'
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
  'Manual verify is disabled by active auth policy. Use Connect Wallet.'
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
  'Manual verify is disabled in production mode\. Use Connect Wallet\.'
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

# Connection console JS contract markers.
CONNECTION_JS_MARKERS=(
  'const tabClientEl = byId("tab_client");'
  'function refreshConnectPolicyHint('
  'function configEndpointUnavailableFailClosedMode('
  'function failClosedMutatingActionStatusDetail('
  'function syncFailClosedMutatingActionState('
  'function activateWorkspaceTab('
  'function syncWorkspaceTabLockState('
  'function buildConnectRequest('
  'function attachProductionConnectReservation('
  'function productionReservationConfirmed('
  'PRODUCTION_CONNECT_RESERVATION_MAX_ATTEMPTS'
  'productionConnectReservationCache'
  '/v1/gpm/settlement/reserve-funds'
  'function assertConnectActionAllowed('
  'const readiness = computeClientReadiness();'
  'throw new Error(`Connect is unavailable: ${connectValidationHint()}`);'
  'function requestConnectControl('
  'assertConnectActionAllowed(request);'
  'function requestDisconnectControl('
  'function requestConnectionStatus('
  'Restricted fail-closed mode: /v1/config is unavailable.'
  'Connect policy: restricted fail-closed (source: unavailable; legacy override locked).'
  'Compatibility override is disabled in restricted fail-closed mode because /v1/config is unavailable.'
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
  'tabClientEl.addEventListener("click"'
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
if ! grep -qF 'Keplr and Leap wallet-extension sign + verify are wired for local beta runtime checks.' "$PORTAL_HTML"; then
  echo "web portal contract failed: portal copy must state Keplr/Leap wallet-extension sign + verify local beta support"
  exit 1
fi
if ! grep -qF 'Wallet sign-in support is wired for Keplr/Leap wallet-extension assisted signing in the local/beta portal' "$README_FILE"; then
  echo "web portal contract failed: README must state Keplr/Leap wallet sign-in local beta support"
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
if ! grep -qiE 'separate GPM Admin Console|Admin Console is separate' "$README_FILE"; then
  echo "web portal contract failed: README must point admin/operator workflows to the separate GPM Admin Console"
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
if ! grep -qiE 'public portal exposes only the client workspace|client workspace only' "$README_FILE"; then
  echo "web portal contract failed: README must document that public portal exposes only the client workspace"
  exit 1
fi
if ! grep -qiE 'connect.*disconnect.*status|/v1/connect.*/v1/disconnect.*/v1/status' "$README_FILE"; then
  echo "web portal contract failed: README must mention connect/disconnect/status controls"
  exit 1
fi
if grep -qiE 'server tab lifecycle controls|start.*stop.*restart.*gpm/service' "$README_FILE"; then
  echo "web portal contract failed: README must not describe server lifecycle controls as part of public portal"
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
