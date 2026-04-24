import { invoke } from "@tauri-apps/api/core";

function byId(id) {
  const el = document.getElementById(id);
  if (!el) {
    throw new Error(`Missing element: ${id}`);
  }
  return el;
}

const outputEl = byId("output");
const apiBaseEl = byId("api_base");
const apiHintsEl = byId("api_hints");
const legacyAliasRuntimeHintEl = document.getElementById("legacy_alias_runtime_hint");
const manifestSourceEl = byId("manifest_source");
const bootstrapTrustCardEl = document.getElementById("bootstrap_trust_card");
const bootstrapTrustStateEl = document.getElementById("bootstrap_trust_state");
const bootstrapTrustSourceEl = document.getElementById("bootstrap_trust_source");
const bootstrapTrustSignatureEl = document.getElementById("bootstrap_trust_signature");
const bootstrapTrustExpiryEl = document.getElementById("bootstrap_trust_expiry");
const bootstrapTrustGuidanceEl = document.getElementById("bootstrap_trust_guidance");
const currentRoleEl = byId("current_role");
const sessionTokenEl = byId("session_token");
const walletProviderEl = byId("wallet_provider");
const walletAddressEl = byId("wallet_address");
const challengeIdEl = byId("challenge_id");
const walletSignatureEl = byId("wallet_signature");
const signatureKindEl = byId("signature_kind");
const signaturePublicKeyEl = byId("signature_public_key");
const signaturePublicKeyTypeEl = byId("signature_public_key_type");
const signatureSourceEl = byId("signature_source");
const signatureChainIdEl = byId("chain_id");
const signedMessageEl = byId("signed_message");
const signatureEnvelopeEl = byId("signature_envelope");
const chainOperatorIdEl = byId("chain_operator_id");
const selectedApplicationUpdatedAtEl = byId("selected_application_updated_at");
const operatorReasonEl = byId("operator_reason");
const operatorListStatusEl = byId("operator_list_status");
const operatorListSearchEl = byId("operator_list_search");
const operatorListLimitEl = byId("operator_list_limit");
const operatorListNextCursorEl = byId("operator_list_next_cursor");
const auditLimitEl = byId("audit_limit");
const auditOffsetEl = byId("audit_offset");
const auditEventEl = byId("audit_event");
const auditWalletAddressEl = byId("audit_wallet_address");
const auditOrderEl = byId("audit_order");
const pathProfileEl = byId("path_profile");
const serverLockHintEl = byId("server_lock_hint");
const clientLockHintEl = byId("client_lock_hint");
const connectPolicyHintEl = document.getElementById("connect_policy_hint");
const authVerifyPolicyHintEl = document.getElementById("auth_verify_policy_hint");
const operatorApprovalPolicyHintEl = document.getElementById("operator_approval_policy_hint");
const connectionStateEl = document.getElementById("connection_state");
const connectionDetailEl = document.getElementById("connection_detail");
const routingModeEl = document.getElementById("routing_mode");
const routingDetailEl = document.getElementById("routing_detail");
const readinessFreshnessCardEl = document.getElementById("readiness_freshness_card");
const readinessFreshnessStateEl = document.getElementById("readiness_freshness_state");
const readinessFreshnessDetailEl = document.getElementById("readiness_freshness_detail");
const signInPolicyHintEl = document.getElementById("signin_policy_hint");
const sessionBootstrapDirectoryEl = byId("session_bootstrap_directory");

const updateBtnEl = byId("update_btn");
const walletSignInBtnEl = byId("wallet_signin_btn");
const signInBtnEl = byId("signin_btn");
const setProfileBtnEl = byId("set_profile_btn");
const serviceStartBtnEl = byId("service_start_btn");
const serviceStopBtnEl = byId("service_stop_btn");
const serviceRestartBtnEl = byId("service_restart_btn");
const tabClientEl = byId("tab_client");
const tabServerEl = byId("tab_server");
const panelClientEl = byId("panel_client");
const panelServerEl = byId("panel_server");
const tabLockHintEl = document.getElementById("tab_lock_hint");
const workspaceFirstRunHintEl = document.getElementById("workspace_first_run_hint");
const workspacePlatformHintEl = document.getElementById("workspace_platform_hint");
const workspaceNextActionHintEl = document.getElementById("workspace_next_action_hint");
const compatAdvancedSectionEl = document.getElementById("legacy_compat_section");
const compatEnableEl = byId("compat_enable");
const bootstrapDirectoryEl = byId("bootstrap_directory");
const inviteKeyEl = byId("invite_key");
const connectBtnEl = byId("connect_btn");
const disconnectBtnEl = byId("disconnect_btn");
const compatAdvancedHintEl =
  document.getElementById("legacy_compat_hint") || document.querySelector("details#legacy_compat_section > p");
const desktopStepSessionEl = document.getElementById("desktop_step_session");
const desktopStepClientEl = document.getElementById("desktop_step_client");
const desktopStepOperatorEl = document.getElementById("desktop_step_operator");
const desktopOnboardingBannerEl = document.getElementById("desktop_onboarding_banner");
const desktopOnboardingStateEl = document.getElementById("desktop_onboarding_state");
const desktopOnboardingDetailEl = document.getElementById("desktop_onboarding_detail");
const desktopOnboardingNextActionEl = document.getElementById("desktop_onboarding_next_action");
const operatorListNextBtnEl = byId("operator_list_next_btn");
const approveOperatorBtnEl = byId("approve_operator_btn");
const rejectOperatorBtnEl = byId("reject_operator_btn");
const MAX_OUTPUT_CHARS = 64 * 1024;
const OPERATOR_PENDING_LIST_LIMIT = 25;
const OPERATOR_LOAD_NEXT_LIMIT = 1;
const OPERATOR_LIST_ALL_LIMIT = 100;
const OPERATOR_FILTER_DEFAULT_LIMIT = 25;
const OPERATOR_DECISION_CONFLICT_GUIDANCE =
  "Decision conflict detected: the selected application was updated by another reviewer. Reload pending queue with Load Next Pending and retry.";
const CONNECTION_DEFAULT_STATE = "Unknown";
const CONNECTION_DEFAULT_DETAIL = "Not checked yet";
const ROUTING_DEFAULT_MODE = "Unknown";
const ROUTING_DEFAULT_DETAIL = "No routing telemetry yet";
const SESSION_EXPIRING_SOON_MS = 10 * 60 * 1000;
const READINESS_HEARTBEAT_INTERVAL_MS = 90 * 1000;
const READINESS_HEARTBEAT_STALE_MS = 5 * 60 * 1000;
const READINESS_HEARTBEAT_ERROR_MAX_CHARS = 160;
const OPERATOR_APPLICATION_STATUSES = new Set(["not_submitted", "pending", "approved", "rejected"]);
const WALLET_EXTENSION_PROVIDERS = new Set(["keplr", "leap"]);
const COMPAT_ADVANCED_DEFAULT_HINT = "Optional legacy fields for support-only compatibility flows.";
const COMPAT_ADVANCED_LOCKED_HINT =
  "Manual bootstrap/invite overrides are locked by policy; connect uses session token only.";
const COMPAT_ADVANCED_DISABLED_HINT =
  "Legacy bootstrap/invite overrides are disabled by policy in this build.";
const COMPAT_ADVANCED_PRODUCTION_HINT =
  "Production mode is active; manual bootstrap/invite compatibility controls are hidden and locked.";
const SESSION_BOOTSTRAP_DIRECTORY_AUTO_LABEL = "Auto (preferred trusted bootstrap)";
const CONNECT_POLICY_SOURCE_ENV_DEFAULT = "env_default";
const CONNECT_POLICY_SOURCE_RUNTIME_CONFIG = "runtime_config";
const CONNECT_POLICY_MODE_SESSION_REQUIRED = "session_required";
const CONNECT_POLICY_MODE_COMPAT_ALLOWED = "compat_allowed";
const PRODUCTION_MODE_SOURCE_POLICY_FALLBACK_CONNECT = "policy_fallback_connect";
const PRODUCTION_MODE_SOURCE_POLICY_FALLBACK_AUTH_VERIFY = "policy_fallback_auth_verify";
const AUTH_VERIFY_POLICY_SOURCE_ENV_DEFAULT = "env_default";
const AUTH_VERIFY_POLICY_SOURCE_RUNTIME_CONFIG = "runtime_config";
const OPERATOR_APPROVAL_POLICY_SOURCE_ENV_DEFAULT = "env_default";
const OPERATOR_APPROVAL_POLICY_SOURCE_RUNTIME_CONFIG = "runtime_config";
const BOOTSTRAP_TRUST_POLICY_SOURCE_ENV_DEFAULT = "env_default";
const BOOTSTRAP_TRUST_POLICY_SOURCE_RUNTIME_CONFIG = "runtime_config";
const PROFILE_GATE_PROBE_POLICY_SOURCE_ENV_DEFAULT = "env_default";
const PROFILE_GATE_PROBE_POLICY_SOURCE_RUNTIME_CONFIG = "runtime_config";
const WALLET_SIGN_IN_LABEL_RECOMMENDED = "Wallet Sign-In (Recommended)";
const WALLET_SIGN_IN_LABEL_REQUIRED = "Wallet Sign-In (Required)";
const MANUAL_SIGN_IN_LABEL = "Sign In (Manual)";
const MANUAL_SIGN_IN_LABEL_DISABLED = "Sign In (Manual Disabled)";
const SIGN_IN_POLICY_PRODUCTION_LOCK_HINT =
  "Production mode is active; Wallet Sign-In is required and manual Sign In is disabled.";
const SIGN_IN_POLICY_RUNTIME_LOCK_HINT =
  "Wallet Sign-In is required by active auth policy; manual Sign In is disabled.";
const SIGN_IN_VALIDATION_PRODUCTION_LOCK_HINT =
  "Manual Sign In is disabled by production mode; use Wallet Sign-In.";
const SIGN_IN_VALIDATION_RUNTIME_LOCK_HINT =
  "Manual Sign In is disabled by active auth policy; use Wallet Sign-In (signature_source must be wallet_extension).";
const TDPN_ENV_NAME_REGEX = /\bTDPN_([A-Z0-9_]+)\b/g;
const LEGACY_SECRET_STORAGE_KEYS = Object.freeze(["gpm.desktop.session_token"]);
const STORAGE_KEYS = Object.freeze({
  role: "gpm.desktop.role",
  walletAddress: "gpm.desktop.wallet_address",
  walletProvider: "gpm.desktop.wallet_provider",
  chainOperatorId: "gpm.desktop.chain_operator_id",
  selectedApplicationUpdatedAt: "gpm.desktop.selected_application_updated_at",
  pathProfile: "gpm.desktop.path_profile"
});
const REGISTRATION_TRUST_DRIFT_STATUS_FRAGMENTS = Object.freeze([
  "degrad",
  "drift",
  "revok",
  "stale",
  "untrust",
  "invalid",
  "mismatch"
]);
const BOOTSTRAP_MANIFEST_TRUST_DEGRADED_STATUS_FRAGMENTS = Object.freeze([
  "degrad",
  "revok",
  "invalid",
  "untrust",
  "stale",
  "expired",
  "fail",
  "mismatch",
  "drift"
]);

const state = {
  sessionToken: "",
  sessionExpiryAtMs: undefined,
  sessionExpiryToken: "",
  role: "client",
  operatorApplicationStatus: undefined,
  selectedApplicationUpdatedAtUtc: "",
  serverReadiness: null,
  clientRegistered: false,
  clientRegistrationTrustDegraded: false,
  clientRegistrationReregisterRequired: false,
  clientRegistrationTrustReason: "",
  clientRegistrationTrustStatus: "",
  serviceMutationsAllowed: false,
  allowLegacyConnectOverride: false,
  connectRequireSession: false,
  productionMode: false,
  productionModeSource: CONNECT_POLICY_SOURCE_ENV_DEFAULT,
  connectPolicySource: CONNECT_POLICY_SOURCE_ENV_DEFAULT,
  connectPolicyMode: CONNECT_POLICY_MODE_COMPAT_ALLOWED,
  authVerifyRequireMetadata: false,
  authVerifyRequireWalletExtensionSource: false,
  authVerifyRequireCryptoProof: false,
  authVerifyRuntimeRequireWalletExtensionSource: false,
  authVerifyPolicySource: AUTH_VERIFY_POLICY_SOURCE_ENV_DEFAULT,
  operatorApprovalRequireSession: false,
  operatorApprovalPolicySource: OPERATOR_APPROVAL_POLICY_SOURCE_ENV_DEFAULT,
  manifestRequireHTTPS: undefined,
  manifestRequireSignature: undefined,
  manifestTrustPolicySource: BOOTSTRAP_TRUST_POLICY_SOURCE_ENV_DEFAULT,
  profileGateAllowRemoteHttpProbe: undefined,
  profileGateAllowInsecureProbe: undefined,
  profileGateProbePolicySource: PROFILE_GATE_PROBE_POLICY_SOURCE_ENV_DEFAULT,
  legacyEnvAliasesActive: [],
  legacyEnvAliasWarnings: [],
  legacyEnvAliasActiveCount: 0,
  sessionBootstrapDirectoryOptions: [],
  manifest: null,
  connectionState: CONNECTION_DEFAULT_STATE,
  connectionDetail: CONNECTION_DEFAULT_DETAIL,
  connectionMutationInFlight: "",
  routingMode: ROUTING_DEFAULT_MODE,
  routingDetail: ROUTING_DEFAULT_DETAIL,
  readinessHeartbeatInFlight: false,
  readinessFreshnessLastAttemptMs: 0,
  readinessFreshnessLastUpdatedMs: 0,
  readinessFreshnessLastError: "",
  operatorListNextCursor: "",
  operatorListRequestContext: null,
  walletSignatureContext: null,
  authChallengeMessage: ""
};

let readinessHeartbeatTimer = null;
let readinessHeartbeatListenersBound = false;

function readPersistedValue(key) {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writePersistedValue(key, value) {
  try {
    const normalized = typeof value === "string" ? value.trim() : "";
    if (!normalized) {
      window.localStorage.removeItem(key);
      return;
    }
    window.localStorage.setItem(key, normalized);
  } catch {
    // Ignore storage failures in this scaffold-level persistence.
  }
}

function clearLegacySecretStorage() {
  try {
    for (const key of LEGACY_SECRET_STORAGE_KEYS) {
      window.localStorage.removeItem(key);
    }
  } catch {
    // Ignore storage failures in this scaffold-level persistence.
  }
}

function isSensitiveFieldKey(key) {
  if (typeof key !== "string" || !key) {
    return false;
  }
  const normalized = key.trim().toLowerCase();
  const compact = normalized.replace(/[_-]/g, "");
  return (
    normalized === "token" ||
    normalized === "auth_token" ||
    normalized === "authtoken" ||
    normalized === "access_token" ||
    normalized === "accesstoken" ||
    normalized === "refresh_token" ||
    normalized === "refreshtoken" ||
    normalized === "secret" ||
    normalized === "password" ||
    normalized === "private_key" ||
    normalized === "privatekey" ||
    normalized === "invite_key" ||
    normalized === "invitekey" ||
    normalized === "bearer" ||
    normalized === "api_key" ||
    normalized === "apikey" ||
    normalized === "signature" ||
    normalized === "signature_envelope" ||
    normalized === "signed_message" ||
    normalized.endsWith("_token") ||
    normalized.endsWith("_secret") ||
    normalized.endsWith("_password") ||
    normalized.endsWith("_private_key") ||
    normalized.endsWith("_invite_key") ||
    normalized.endsWith("_api_key") ||
    normalized.endsWith("_signature") ||
    normalized.includes("private_key") ||
    normalized.includes("privatekey") ||
    normalized.includes("invite_key") ||
    normalized.includes("invitekey") ||
    normalized.includes("bearer") ||
    normalized.includes("signature") ||
    normalized.includes("secret") ||
    normalized.includes("password") ||
    compact.endsWith("token") ||
    compact.endsWith("secret") ||
    compact.endsWith("apikey")
  );
}

function sanitizePayloadForDisplay(payload, depth = 0) {
  if (depth > 8 || payload === null || payload === undefined) {
    return payload;
  }
  if (typeof payload === "string") {
    return payload;
  }
  if (Array.isArray(payload)) {
    return payload.map((entry) => sanitizePayloadForDisplay(entry, depth + 1));
  }
  if (typeof payload === "object") {
    const sanitized = {};
    for (const [key, value] of Object.entries(payload)) {
      if (isSensitiveFieldKey(key)) {
        sanitized[key] = "[REDACTED]";
      } else {
        sanitized[key] = sanitizePayloadForDisplay(value, depth + 1);
      }
    }
    return sanitized;
  }
  return payload;
}

function restoreSelectValue(selectEl, value) {
  if (!value) {
    return;
  }
  const hasOption = Array.from(selectEl.options).some((option) => option.value === value);
  if (hasOption) {
    selectEl.value = value;
  }
}

function createBootstrapDirectoryOption(value, label) {
  const option = document.createElement("option");
  option.value = value;
  option.textContent = label;
  return option;
}

function syncSessionBootstrapDirectoryOptions() {
  const options = Array.isArray(state.sessionBootstrapDirectoryOptions)
    ? state.sessionBootstrapDirectoryOptions
    : [];
  const compatOverrideActive =
    state.allowLegacyConnectOverride && !state.connectRequireSession && !state.productionMode && compatEnableEl.checked;
  const previousValue = sessionBootstrapDirectoryEl.value.trim();
  sessionBootstrapDirectoryEl.replaceChildren(
    createBootstrapDirectoryOption("", SESSION_BOOTSTRAP_DIRECTORY_AUTO_LABEL),
    ...options.map((value) => createBootstrapDirectoryOption(value, value))
  );
  sessionBootstrapDirectoryEl.value = options.includes(previousValue) ? previousValue : "";
  sessionBootstrapDirectoryEl.disabled = !state.sessionToken || compatOverrideActive;
}

function ingestSessionBootstrapDirectoryOptionsFromPayload(payload) {
  const payloadSessionToken = nonEmptyStringOrUndefined(
    firstDefined(
      payload?.session_token,
      payload?.sessionToken,
      payload?.session?.session_token,
      payload?.session?.sessionToken
    )
  );
  if (!state.sessionToken && !payloadSessionToken) {
    return;
  }
  const metadata = extractBootstrapRegistrationMetadata(payload);
  for (const value of [metadata.directBootstrapDirectory, ...metadata.bootstrapDirectories]) {
    pushUniqueNonEmptyString(state.sessionBootstrapDirectoryOptions, value);
  }
  syncSessionBootstrapDirectoryOptions();
}

function formatPayloadForDisplay(payload) {
  const normalizedPayload = normalizeLegacyEnvNameDisplayPayload(sanitizePayloadForDisplay(payload));
  const text =
    typeof normalizedPayload === "string"
      ? normalizedPayload
      : JSON.stringify(normalizedPayload, null, 2);
  if (text.length <= MAX_OUTPUT_CHARS) {
    return text;
  }
  const omitted = text.length - MAX_OUTPUT_CHARS;
  return `${text.slice(0, MAX_OUTPUT_CHARS)}\n...[TRUNCATED ${omitted} chars]`;
}

function normalizeLegacyEnvNameDisplayText(value) {
  if (typeof value !== "string" || !value.includes("TDPN_")) {
    return value;
  }
  if (value.includes("GPM_")) {
    return value;
  }
  return value.replace(TDPN_ENV_NAME_REGEX, (_match, suffix) => {
    const tdpnName = `TDPN_${suffix}`;
    return `GPM_${suffix} (legacy alias: ${tdpnName})`;
  });
}

function normalizeLegacyEnvNameDisplayPayload(payload, depth = 0) {
  if (depth > 6 || payload === null || payload === undefined) {
    return payload;
  }
  if (typeof payload === "string") {
    return normalizeLegacyEnvNameDisplayText(payload);
  }
  if (Array.isArray(payload)) {
    return payload.map((entry) => normalizeLegacyEnvNameDisplayPayload(entry, depth + 1));
  }
  if (typeof payload === "object") {
    const normalized = {};
    for (const [key, value] of Object.entries(payload)) {
      normalized[key] = normalizeLegacyEnvNameDisplayPayload(value, depth + 1);
    }
    return normalized;
  }
  return payload;
}

function print(label, payload) {
  const text = formatPayloadForDisplay(payload);
  outputEl.textContent = `[${new Date().toISOString()}] ${label}\n${text}`;
}

function truncateOneLineText(value, maxChars = READINESS_HEARTBEAT_ERROR_MAX_CHARS) {
  if (typeof value !== "string") {
    return "";
  }
  const normalized = value.replace(/\s+/g, " ").trim();
  if (!normalized) {
    return "";
  }
  if (normalized.length <= maxChars) {
    return normalized;
  }
  return `${normalized.slice(0, Math.max(0, maxChars - 1))}\u2026`;
}

function heartbeatErrorText(err) {
  const raw =
    err && typeof err === "object" && typeof err.message === "string" && err.message.trim()
      ? err.message
      : String(err ?? "");
  return truncateOneLineText(raw, READINESS_HEARTBEAT_ERROR_MAX_CHARS);
}

function formatDurationSince(epochMs) {
  if (!Number.isFinite(epochMs) || epochMs <= 0) {
    return "";
  }
  const elapsedMs = Math.max(0, Date.now() - epochMs);
  const elapsedSec = Math.floor(elapsedMs / 1000);
  if (elapsedSec < 60) {
    return `${elapsedSec}s ago`;
  }
  const elapsedMin = Math.floor(elapsedSec / 60);
  if (elapsedMin < 60) {
    return `${elapsedMin}m ago`;
  }
  const elapsedHours = Math.floor(elapsedMin / 60);
  if (elapsedHours < 24) {
    return `${elapsedHours}h ago`;
  }
  const elapsedDays = Math.floor(elapsedHours / 24);
  return `${elapsedDays}d ago`;
}

function formatLocalTimestamp(epochMs) {
  if (!Number.isFinite(epochMs) || epochMs <= 0) {
    return "";
  }
  const timestamp = new Date(epochMs);
  if (Number.isNaN(timestamp.getTime())) {
    return "";
  }
  return timestamp.toLocaleString();
}

function syncReadinessFreshnessIndicator() {
  if (!readinessFreshnessStateEl || !readinessFreshnessDetailEl) {
    return;
  }

  const hasSession = !!state.sessionToken;
  const hasLastUpdate = Number.isFinite(state.readinessFreshnessLastUpdatedMs) && state.readinessFreshnessLastUpdatedMs > 0;
  const hasLastAttempt = Number.isFinite(state.readinessFreshnessLastAttemptMs) && state.readinessFreshnessLastAttemptMs > 0;
  const staleByAge = hasLastUpdate && Date.now() - state.readinessFreshnessLastUpdatedMs > READINESS_HEARTBEAT_STALE_MS;
  const lastError = truncateOneLineText(state.readinessFreshnessLastError, READINESS_HEARTBEAT_ERROR_MAX_CHARS);

  let indicatorState = "idle";
  let title = "Idle";
  let detail = "Sign in to start readiness/auth heartbeat.";

  if (hasSession) {
    indicatorState = "refreshing";
    title = "Refreshing";
    detail = "Readiness/auth heartbeat is initializing.";

    if (hasLastUpdate) {
      const ageText = formatDurationSince(state.readinessFreshnessLastUpdatedMs);
      const localTime = formatLocalTimestamp(state.readinessFreshnessLastUpdatedMs);
      indicatorState = staleByAge ? "stale" : "fresh";
      title = staleByAge ? "Stale" : "Fresh";
      detail = `Last updated ${ageText}${localTime ? ` (${localTime})` : ""}.`;
      if (lastError && staleByAge) {
        detail += ` Last refresh error: ${lastError}`;
      }
    } else if (lastError) {
      indicatorState = "warning";
      title = "Attention";
      detail = `Unable to refresh readiness/auth state yet: ${lastError}`;
    } else if (hasLastAttempt) {
      const ageText = formatDurationSince(state.readinessFreshnessLastAttemptMs);
      const localTime = formatLocalTimestamp(state.readinessFreshnessLastAttemptMs);
      indicatorState = "warning";
      title = "Pending";
      detail = `Last attempt ${ageText}${localTime ? ` (${localTime})` : ""}; waiting for first successful refresh.`;
    }
  }

  if (state.readinessHeartbeatInFlight && hasSession && !hasLastUpdate) {
    indicatorState = "refreshing";
    title = "Refreshing";
    detail = "Refreshing readiness/auth state\u2026";
  }

  readinessFreshnessStateEl.textContent = title;
  readinessFreshnessDetailEl.textContent = detail;
  if (readinessFreshnessCardEl) {
    readinessFreshnessCardEl.dataset.state = indicatorState;
  }
}

function markReadinessHeartbeatSuccess(options = {}) {
  const expectedSessionToken =
    options && typeof options.expectedSessionToken === "string" ? options.expectedSessionToken.trim() : "";
  const currentSessionToken = typeof state.sessionToken === "string" ? state.sessionToken.trim() : "";
  if (!currentSessionToken) {
    syncReadinessFreshnessIndicator();
    return false;
  }
  if (expectedSessionToken && expectedSessionToken !== currentSessionToken) {
    syncReadinessFreshnessIndicator();
    return false;
  }
  const now = Date.now();
  state.readinessFreshnessLastAttemptMs = now;
  state.readinessFreshnessLastUpdatedMs = now;
  state.readinessFreshnessLastError = "";
  syncReadinessFreshnessIndicator();
  return true;
}

function numberOrUndefined(value) {
  const n = Number(value);
  if (Number.isFinite(n) && n > 0) {
    return n;
  }
  return undefined;
}

function nonNegativeIntegerOrUndefined(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) {
    return undefined;
  }
  return Math.trunc(n);
}

function nonEmptyStringOrUndefined(value) {
  if (typeof value !== "string") {
    return undefined;
  }
  const normalized = value.trim();
  return normalized || undefined;
}

function pushUniqueNonEmptyString(target, value) {
  const parsed = nonEmptyStringOrUndefined(value);
  if (!parsed) {
    return;
  }
  if (!target.includes(parsed)) {
    target.push(parsed);
  }
}

function appendBootstrapDirectoryEntries(target, value) {
  if (Array.isArray(value)) {
    for (const entry of value) {
      pushUniqueNonEmptyString(target, entry);
    }
    return;
  }
  pushUniqueNonEmptyString(target, value);
}

function extractBootstrapRegistrationMetadata(payload) {
  const directBootstrapDirectory =
    nonEmptyStringOrUndefined(
      firstDefined(
        payload?.registration?.bootstrap_directory,
        payload?.registration?.bootstrapDirectory,
        payload?.session?.bootstrap_directory,
        payload?.session?.bootstrapDirectory,
        payload?.profile?.bootstrap_directory,
        payload?.profile?.bootstrapDirectory,
        payload?.bootstrap_directory,
        payload?.bootstrapDirectory
      )
    ) || "";

  const bootstrapDirectories = [];
  for (const candidate of [
    payload?.registration?.bootstrap_directories,
    payload?.registration?.bootstrapDirectories,
    payload?.session?.bootstrap_directories,
    payload?.session?.bootstrapDirectories,
    payload?.profile?.bootstrap_directories,
    payload?.profile?.bootstrapDirectories,
    payload?.bootstrap_directories,
    payload?.bootstrapDirectories
  ]) {
    appendBootstrapDirectoryEntries(bootstrapDirectories, candidate);
  }

  const fallbackBootstrapDirectory =
    directBootstrapDirectory || bootstrapDirectories.length === 0 ? "" : bootstrapDirectories[0];
  const resolvedBootstrapDirectory = directBootstrapDirectory || fallbackBootstrapDirectory;

  return {
    directBootstrapDirectory,
    bootstrapDirectories,
    fallbackBootstrapDirectory,
    resolvedBootstrapDirectory,
    usesFallbackDirectory: fallbackBootstrapDirectory.length > 0,
    hasBootstrapDirectory: resolvedBootstrapDirectory.length > 0
  };
}

function parseJSONOrRawString(value) {
  const normalized = nonEmptyStringOrUndefined(value);
  if (!normalized) {
    return undefined;
  }
  try {
    return JSON.parse(normalized);
  } catch {
    return normalized;
  }
}

function readAuthVerifySignatureMetadata() {
  const signatureEnvelope = parseJSONOrRawString(signatureEnvelopeEl.value);
  return compactObject({
    signature_kind: nonEmptyStringOrUndefined(signatureKindEl.value),
    signature_public_key: nonEmptyStringOrUndefined(signaturePublicKeyEl.value),
    signature_public_key_type: nonEmptyStringOrUndefined(signaturePublicKeyTypeEl.value),
    signature_source: nonEmptyStringOrUndefined(signatureSourceEl.value),
    chain_id: nonEmptyStringOrUndefined(signatureChainIdEl.value),
    signed_message: nonEmptyStringOrUndefined(signedMessageEl.value),
    signature_envelope: signatureEnvelope
  });
}

function compactObject(value) {
  const out = {};
  for (const [key, entry] of Object.entries(value)) {
    if (entry !== undefined) {
      out[key] = entry;
    }
  }
  return out;
}

function firstDefined(...values) {
  for (const value of values) {
    if (value !== undefined && value !== null) {
      return value;
    }
  }
  return undefined;
}

function setWalletSignatureContext(context) {
  state.walletSignatureContext = context && typeof context === "object" ? context : null;
}

function clearWalletSignatureContext() {
  state.walletSignatureContext = null;
}

function normalizeWalletProviderValue(value) {
  if (typeof value !== "string") {
    return undefined;
  }
  const normalized = value.trim().toLowerCase();
  return WALLET_EXTENSION_PROVIDERS.has(normalized) ? normalized : undefined;
}

function walletProviderDisplayName(value) {
  const normalized = normalizeWalletProviderValue(value);
  if (normalized === "leap") {
    return "Leap";
  }
  if (normalized === "keplr") {
    return "Keplr";
  }
  return "Wallet";
}

function challengeMessageFromPayload(payload) {
  return (
    nonEmptyStringOrUndefined(
      firstDefined(
        payload?.message,
        payload?.challenge_message,
        payload?.challengeMessage,
        payload?.challenge?.message,
        payload?.challenge?.challenge_message,
        payload?.challenge?.challengeMessage
      )
    ) || ""
  );
}

function challengeIdFromPayload(payload) {
  return (
    nonEmptyStringOrUndefined(
      firstDefined(
        payload?.challenge_id,
        payload?.challengeId,
        payload?.challenge?.challenge_id,
        payload?.challenge?.challengeId
      )
    ) || ""
  );
}

function applyChallengePayload(payload) {
  const challengeId = challengeIdFromPayload(payload);
  if (challengeId) {
    challengeIdEl.value = challengeId;
  }
  state.authChallengeMessage = challengeMessageFromPayload(payload);
  if (state.authChallengeMessage) {
    signedMessageEl.value = state.authChallengeMessage;
  }
  syncDesktopOnboardingBanner();
}

function readWalletPayload() {
  return {
    wallet_address: walletAddressEl.value.trim(),
    wallet_provider: walletProviderEl.value
  };
}

function normalizeWalletAddressForCompare(value) {
  return (nonEmptyStringOrUndefined(value) || "").toLowerCase();
}

function cloneJSONSerializable(value) {
  if (value === undefined) {
    return undefined;
  }
  try {
    return JSON.parse(JSON.stringify(value));
  } catch {
    return undefined;
  }
}

function extractSignArbitraryPublicKey(payload) {
  const publicKey = nonEmptyStringOrUndefined(
    firstDefined(
      payload?.pub_key?.value,
      payload?.pubKey?.value,
      payload?.signature?.pub_key?.value,
      payload?.signature?.pubKey?.value,
      payload?.result?.pub_key?.value,
      payload?.result?.pubKey?.value,
      payload?.result?.signature?.pub_key?.value,
      payload?.result?.signature?.pubKey?.value,
      payload?.pub_key,
      payload?.pubKey
    )
  );
  const publicKeyType = nonEmptyStringOrUndefined(
    firstDefined(
      payload?.pub_key?.type,
      payload?.pubKey?.type,
      payload?.signature?.pub_key?.type,
      payload?.signature?.pubKey?.type,
      payload?.result?.pub_key?.type,
      payload?.result?.pubKey?.type,
      payload?.result?.signature?.pub_key?.type,
      payload?.result?.signature?.pubKey?.type
    )
  );
  return { publicKey, publicKeyType };
}

function extractSignArbitrarySignature(payload) {
  return (
    nonEmptyStringOrUndefined(
      firstDefined(
        payload?.signature?.signature,
        payload?.signature,
        payload?.result?.signature?.signature,
        payload?.result?.signature
      )
    ) || ""
  );
}

function buildWalletSignatureContext({
  walletProvider,
  walletAddress,
  challengeId,
  challengeMessage,
  chainId,
  signature,
  signaturePayload
}) {
  const normalizedProvider = normalizeWalletProviderValue(walletProvider);
  const normalizedWalletAddress = nonEmptyStringOrUndefined(walletAddress);
  const normalizedChallengeId = nonEmptyStringOrUndefined(challengeId);
  const normalizedChallengeMessage = nonEmptyStringOrUndefined(challengeMessage);
  const normalizedChainId = nonEmptyStringOrUndefined(chainId);
  const normalizedSignature = nonEmptyStringOrUndefined(signature);
  if (
    !normalizedProvider ||
    !normalizedWalletAddress ||
    !normalizedChallengeId ||
    !normalizedChallengeMessage ||
    !normalizedChainId ||
    !normalizedSignature
  ) {
    return null;
  }
  const metadata = {
    signature_kind: "sign_arbitrary",
    signature_source: "wallet_extension",
    chain_id: normalizedChainId,
    signed_message: normalizedChallengeMessage
  };
  const { publicKey, publicKeyType } = extractSignArbitraryPublicKey(signaturePayload);
  if (publicKey) {
    metadata.signature_public_key = publicKey;
  }
  if (publicKeyType) {
    metadata.signature_public_key_type = publicKeyType;
  }
  const signatureEnvelope = cloneJSONSerializable(signaturePayload);
  if (signatureEnvelope !== undefined) {
    metadata.signature_envelope = signatureEnvelope;
  }
  return {
    wallet_provider: normalizedProvider,
    wallet_address: normalizedWalletAddress,
    challenge_id: normalizedChallengeId,
    challenge_message: normalizedChallengeMessage,
    chain_id: normalizedChainId,
    signature: normalizedSignature,
    metadata
  };
}

function isWalletSignatureContextValidForRequest(context, request) {
  if (!context || typeof context !== "object" || !request || typeof request !== "object") {
    return false;
  }
  const requestWalletProvider = normalizeWalletProviderValue(request.wallet_provider);
  const contextWalletProvider = normalizeWalletProviderValue(context.wallet_provider);
  if (!requestWalletProvider || !contextWalletProvider || requestWalletProvider !== contextWalletProvider) {
    return false;
  }
  if (
    normalizeWalletAddressForCompare(request.wallet_address) !== normalizeWalletAddressForCompare(context.wallet_address)
  ) {
    return false;
  }
  const requestChallengeId = nonEmptyStringOrUndefined(request.challenge_id) || "";
  const requestSignature = nonEmptyStringOrUndefined(request.signature) || "";
  if (!requestChallengeId || !requestSignature) {
    return false;
  }
  if (requestChallengeId !== (nonEmptyStringOrUndefined(context.challenge_id) || "")) {
    return false;
  }
  if (requestSignature !== (nonEmptyStringOrUndefined(context.signature) || "")) {
    return false;
  }
  const currentChallengeMessage = state.authChallengeMessage || signedMessageEl.value.trim();
  if (currentChallengeMessage !== (nonEmptyStringOrUndefined(context.challenge_message) || "")) {
    return false;
  }
  const currentChainId = signatureChainIdEl.value.trim();
  if (currentChainId !== (nonEmptyStringOrUndefined(context.chain_id) || "")) {
    return false;
  }
  return true;
}

function authVerifySignatureContext(request) {
  if (!isWalletSignatureContextValidForRequest(state.walletSignatureContext, request)) {
    return undefined;
  }
  const context = state.walletSignatureContext?.metadata;
  return context && typeof context === "object" ? context : undefined;
}

async function readWalletAddressFromSignerFactory(source, methodName, chainId) {
  if (!source || typeof source[methodName] !== "function") {
    return undefined;
  }
  const signer = await source[methodName](chainId);
  if (!signer || typeof signer.getAccounts !== "function") {
    return undefined;
  }
  const accounts = await signer.getAccounts();
  if (!Array.isArray(accounts) || accounts.length === 0) {
    return undefined;
  }
  return (
    nonEmptyStringOrUndefined(
      firstDefined(accounts[0]?.address, accounts[0]?.bech32Address, accounts[0]?.wallet_address)
    ) || undefined
  );
}

function resolveWalletExtensionClient(walletProvider) {
  const provider = normalizeWalletProviderValue(walletProvider);
  if (!provider) {
    throw new Error("wallet_provider must be keplr or leap.");
  }
  const view = window;
  const candidates = provider === "keplr" ? [view.keplr] : [view.leap, view.leap?.cosmos];
  const availableCandidates = candidates.filter((entry) => entry && typeof entry === "object");
  if (availableCandidates.length === 0) {
    throw new Error(`${walletProviderDisplayName(provider)} extension was not detected. Install it and reload the desktop app.`);
  }
  const extension = availableCandidates.find(
    (entry) => typeof entry.enable === "function" && typeof entry.signArbitrary === "function"
  );
  if (!extension) {
    throw new Error(
      `${walletProviderDisplayName(provider)} extension is missing required enable(chainId) and signArbitrary(chainId, signer, data) methods.`
    );
  }
  return { provider, extension };
}

async function resolveWalletAddressFromExtension(extension, chainId) {
  if (typeof extension.getKey === "function") {
    const key = await extension.getKey(chainId);
    const bech32Address = nonEmptyStringOrUndefined(
      firstDefined(key?.bech32Address, key?.address, key?.wallet_address)
    );
    if (bech32Address) {
      return bech32Address;
    }
  }
  const signerFactories = [
    [extension, "getOfflineSignerAuto"],
    [extension, "getOfflineSigner"],
    [extension, "getOfflineSignerOnlyAmino"],
    [window, "getOfflineSignerAuto"],
    [window, "getOfflineSigner"],
    [window, "getOfflineSignerOnlyAmino"]
  ];
  for (const [source, methodName] of signerFactories) {
    try {
      const address = await readWalletAddressFromSignerFactory(source, methodName, chainId);
      if (address) {
        return address;
      }
    } catch {
      // Continue trying alternate signer APIs.
    }
  }
  return "";
}

async function completeAuthVerifyFlow(result) {
  setSessionToken(result?.session_token || "");
  refreshSessionFreshnessFromPayload(result, { tokenOverride: state.sessionToken, clearWhenMissing: true });
  setClientRegistrationStateFromPayload(result, { allowFallback: true });
  setRole(parseSessionRole(result));
  await refreshClientRegistrationStatus({ quiet: true });
  await refreshOperatorApplicationStatus({ quiet: true });
  await refreshServerReadinessStatus({ quiet: true });
}

async function runWalletExtensionSignIn() {
  const chainId = signatureChainIdEl.value.trim();
  if (!chainId) {
    throw new Error("chain_id is required for wallet-extension one-click sign-in.");
  }
  const { wallet_provider: walletProvider } = readWalletPayload();
  const { extension, provider } = resolveWalletExtensionClient(walletProvider);
  await extension.enable(chainId);

  let walletAddress = walletAddressEl.value.trim();
  if (!walletAddress) {
    walletAddress = await resolveWalletAddressFromExtension(extension, chainId);
    if (!walletAddress) {
      throw new Error(
        `Unable to resolve wallet address from ${walletProviderDisplayName(provider)} extension. Enter wallet_address and retry.`
      );
    }
    walletAddressEl.value = walletAddress;
    writePersistedValue(STORAGE_KEYS.walletAddress, walletAddress);
  }

  clearWalletSignatureContext();
  const challengeResult = await call("gpm_auth_challenge", "control_gpm_auth_challenge", {
    request: { wallet_address: walletAddress, wallet_provider: provider }
  });
  applyChallengePayload(challengeResult);
  const challengeId = challengeIdEl.value.trim();
  const challengeMessage = state.authChallengeMessage || signedMessageEl.value.trim();
  if (!challengeId) {
    throw new Error("challenge_id is required. Request challenge first.");
  }
  if (!challengeMessage) {
    throw new Error("challenge message is required. Request challenge first.");
  }

  const signaturePayload = await extension.signArbitrary(chainId, walletAddress, challengeMessage);
  const signature = extractSignArbitrarySignature(signaturePayload);
  if (!signature) {
    throw new Error("Wallet extension returned an empty signature for signArbitrary.");
  }

  walletSignatureEl.value = signature;
  setWalletSignatureContext(
    buildWalletSignatureContext({
      walletProvider: provider,
      walletAddress,
      challengeId,
      challengeMessage,
      chainId,
      signature,
      signaturePayload
    })
  );

  const request = {
    wallet_address: walletAddress,
    wallet_provider: provider,
    challenge_id: challengeId,
    signature
  };
  const signatureMetadata = authVerifySignatureContext(request) || readAuthVerifySignatureMetadata();
  Object.assign(request, signatureMetadata);
  const verifyResult = await call("gpm_auth_verify", "control_gpm_auth_verify", { request });
  await completeAuthVerifyFlow(verifyResult);
}

const CONNECTION_HINT_KEYS = {
  state: ["connection_state", "state", "status", "phase", "mode"],
  connected: ["connected", "is_connected", "online", "active"],
  disconnected: ["disconnected", "is_disconnected", "offline"],
  healthy: ["healthy", "ok", "is_ok", "alive"],
  detail: ["detail", "details", "message", "reason", "error", "description"]
};
const ROUTING_HINT_KEYS = {
  mode: [
    "mode",
    "routing_mode",
    "routingmode",
    "route_mode",
    "routemode",
    "strategy",
    "routing_strategy",
    "routingstrategy",
    "route_strategy",
    "routestrategy"
  ],
  detail: [
    "detail",
    "details",
    "routing_detail",
    "routingdetail",
    "route_detail",
    "routedetail",
    "message",
    "reason",
    "description",
    "status_reason"
  ],
  profile: ["path_profile", "pathprofile", "policy_profile", "policyprofile", "profile"],
  relay: [
    "relay",
    "relay_active",
    "relayactive",
    "managed_relay",
    "managedrelay",
    "using_relay",
    "usingrelay",
    "relay_fallback",
    "relayfallback"
  ],
  direct: ["direct", "direct_path", "directpath", "direct_active", "directactive", "mesh_direct", "meshdirect"],
  fallback: ["fallback", "fallback_active", "fallbackactive", "degraded", "needs_relay", "needsrelay"]
};

function findHintValue(payload, keys, depth = 0) {
  if (payload === null || payload === undefined || depth > 4) {
    return undefined;
  }
  if (Array.isArray(payload)) {
    for (const item of payload) {
      const found = findHintValue(item, keys, depth + 1);
      if (found !== undefined && found !== null) {
        return found;
      }
    }
    return undefined;
  }
  if (typeof payload !== "object") {
    return undefined;
  }
  for (const [key, value] of Object.entries(payload)) {
    if (keys.includes(key.toLowerCase()) && value !== undefined && value !== null) {
      return value;
    }
  }
  for (const value of Object.values(payload)) {
    const found = findHintValue(value, keys, depth + 1);
    if (found !== undefined && found !== null) {
      return found;
    }
  }
  return undefined;
}

function toBooleanLike(value) {
  if (typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    return value !== 0;
  }
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (["1", "true", "yes", "ok", "healthy", "online", "up", "connected", "ready"].includes(normalized)) {
      return true;
    }
    if (["0", "false", "no", "offline", "down", "disconnected", "unhealthy", "error"].includes(normalized)) {
      return false;
    }
  }
  return undefined;
}

function normalizeConnectionState(value) {
  if (typeof value !== "string") {
    return undefined;
  }
  const text = value.trim().toLowerCase();
  if (!text) {
    return undefined;
  }
  if (text.includes("connecting") || text.includes("pending") || text.includes("starting")) {
    return "connecting";
  }
  if (text.includes("disconnecting") || text.includes("stopping")) {
    return "disconnecting";
  }
  if (text.includes("degrad") || text.includes("unhealthy") || text.includes("error") || text.includes("failed")) {
    return "degraded";
  }
  if (text.includes("disconnect") || text.includes("offline") || text === "down" || text === "stopped") {
    return "disconnected";
  }
  if (text.includes("connect") || text.includes("online") || text === "up" || text === "active" || text === "ready") {
    return "connected";
  }
  if (text.includes("healthy") || text === "ok" || text === "pass") {
    return "healthy";
  }
  return undefined;
}

function formatConnectionStateLabel(stateKey) {
  switch (stateKey) {
    case "connected":
      return "Connected";
    case "disconnected":
      return "Disconnected";
    case "connecting":
      return "Connecting";
    case "disconnecting":
      return "Disconnecting";
    case "healthy":
      return "Healthy";
    case "degraded":
      return "Degraded";
    default:
      return CONNECTION_DEFAULT_STATE;
  }
}

function toDetailText(value) {
  if (typeof value === "string" && value.trim()) {
    return value.trim();
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return undefined;
}

function findSessionReconciledHint(payload, depth = 0) {
  if (payload === null || payload === undefined || depth > 4) {
    return undefined;
  }
  if (Array.isArray(payload)) {
    for (const item of payload) {
      const found = findSessionReconciledHint(item, depth + 1);
      if (found !== undefined && found !== null) {
        return found;
      }
    }
    return undefined;
  }
  if (typeof payload !== "object") {
    return undefined;
  }
  if (Object.prototype.hasOwnProperty.call(payload, "session_reconciled")) {
    return payload.session_reconciled;
  }
  if (Object.prototype.hasOwnProperty.call(payload, "sessionReconciled")) {
    return payload.sessionReconciled;
  }
  for (const value of Object.values(payload)) {
    const found = findSessionReconciledHint(value, depth + 1);
    if (found !== undefined && found !== null) {
      return found;
    }
  }
  return undefined;
}

function formatSessionReconciledHint(payload) {
  const hint = findSessionReconciledHint(payload);
  if (hint === undefined || hint === null) {
    return undefined;
  }
  if (typeof hint === "string") {
    const trimmed = hint.trim();
    return trimmed || undefined;
  }
  if (typeof hint === "number" || typeof hint === "boolean") {
    return String(hint);
  }
  try {
    return JSON.stringify(hint);
  } catch {
    return String(hint);
  }
}

function withSessionReconciledHint(payload, hintSource = payload) {
  const hint = formatSessionReconciledHint(hintSource);
  if (!hint) {
    return payload;
  }
  if (payload && typeof payload === "object" && !Array.isArray(payload)) {
    return {
      ...payload,
      session_reconciled_hint: hint
    };
  }
  return {
    result: payload,
    session_reconciled_hint: hint
  };
}

function formatBootstrapDirectoryFallbackHint(payload) {
  const metadata = extractBootstrapRegistrationMetadata(payload);
  if (!metadata.usesFallbackDirectory || !metadata.resolvedBootstrapDirectory) {
    return undefined;
  }
  const count = metadata.bootstrapDirectories.length;
  return {
    bootstrapDirectory: metadata.resolvedBootstrapDirectory,
    message: `Using bootstrap_directories[0] fallback (${count} candidate${count === 1 ? "" : "s"}).`
  };
}

function withBootstrapDirectoryFallbackHint(payload, hintSource = payload) {
  const hint = formatBootstrapDirectoryFallbackHint(hintSource);
  if (!hint) {
    return payload;
  }
  if (payload && typeof payload === "object" && !Array.isArray(payload)) {
    if (
      Object.prototype.hasOwnProperty.call(payload, "bootstrap_directory_fallback") ||
      Object.prototype.hasOwnProperty.call(payload, "bootstrap_directory_fallback_hint")
    ) {
      return payload;
    }
    return {
      ...payload,
      bootstrap_directory_fallback: hint.bootstrapDirectory,
      bootstrap_directory_fallback_hint: hint.message
    };
  }
  return {
    result: payload,
    bootstrap_directory_fallback: hint.bootstrapDirectory,
    bootstrap_directory_fallback_hint: hint.message
  };
}

function inferConnectionDetail(payload, source, stateKey, stateHint) {
  const detailHint = toDetailText(findHintValue(payload, CONNECTION_HINT_KEYS.detail));
  if (detailHint) {
    return detailHint;
  }
  const stateText = toDetailText(stateHint);
  if (stateText) {
    return stateText;
  }
  const payloadText = toDetailText(payload);
  if (payloadText) {
    return payloadText;
  }
  if (source === "connect") {
    return "Connect request completed.";
  }
  if (source === "disconnect") {
    return "Disconnect request completed.";
  }
  if (source === "status") {
    return "Status refreshed.";
  }
  if (source === "health") {
    return stateKey === "degraded" ? "Health check reported issues." : "Health check completed.";
  }
  return CONNECTION_DEFAULT_DETAIL;
}

function normalizeRoutingProfileHint(value) {
  if (typeof value !== "string") {
    return undefined;
  }
  const text = value.trim().toLowerCase();
  if (!text) {
    return undefined;
  }
  if (text.includes("1hop") || text.includes("1-hop") || text.includes("speed")) {
    return "1hop";
  }
  if (text.includes("2hop") || text.includes("2-hop") || text.includes("balanced")) {
    return "2hop";
  }
  if (text.includes("3hop") || text.includes("3-hop") || text.includes("private")) {
    return "3hop";
  }
  const hopMatch = text.match(/\b([1-9])\s*hop\b/);
  if (hopMatch?.[1]) {
    return `${hopMatch[1]}hop`;
  }
  return undefined;
}

function normalizeRoutingModeKey(value) {
  if (typeof value !== "string") {
    return undefined;
  }
  const text = value.trim().toLowerCase();
  if (!text) {
    return undefined;
  }
  if (text.includes("inactive") || text.includes("disconnect") || text.includes("offline") || text === "down") {
    return "inactive";
  }
  if (text.includes("hybrid") || text.includes("auto")) {
    return "hybrid_auto";
  }
  if (
    text.includes("relay") ||
    text.includes("fallback") ||
    text.includes("proxy") ||
    text.includes("turn") ||
    text.includes("transit")
  ) {
    return "managed_relay";
  }
  if (
    text.includes("direct") ||
    text.includes("mesh") ||
    text.includes("p2p") ||
    text.includes("hop") ||
    text === "1hop" ||
    text === "2hop" ||
    text === "3hop"
  ) {
    return "direct_mesh";
  }
  return undefined;
}

function formatRoutingModeLabel(modeKey, profileHint = "") {
  switch (modeKey) {
    case "direct_mesh":
      return profileHint ? `Direct Mesh (${profileHint})` : "Direct Mesh";
    case "managed_relay":
      return "Managed Relay";
    case "hybrid_auto":
      return "Hybrid Auto";
    case "inactive":
      return "Inactive";
    default:
      return ROUTING_DEFAULT_MODE;
  }
}

function inferRoutingModeHints(candidate) {
  const modeHint = toDetailText(findHintValue(candidate, ROUTING_HINT_KEYS.mode));
  const profileHint = normalizeRoutingProfileHint(toDetailText(findHintValue(candidate, ROUTING_HINT_KEYS.profile)) || "");
  const relayHint = toBooleanLike(findHintValue(candidate, ROUTING_HINT_KEYS.relay));
  const directHint = toBooleanLike(findHintValue(candidate, ROUTING_HINT_KEYS.direct));
  const fallbackHint = toBooleanLike(findHintValue(candidate, ROUTING_HINT_KEYS.fallback));
  let modeKey = normalizeRoutingModeKey(modeHint);
  if (!modeKey && relayHint === true) {
    modeKey = "managed_relay";
  }
  if (!modeKey && (directHint === true || profileHint)) {
    modeKey = "direct_mesh";
  }
  if (!modeKey && fallbackHint === true) {
    modeKey = "managed_relay";
  }
  return {
    modeKey,
    modeHint,
    profileHint,
    relayHint,
    directHint,
    fallbackHint
  };
}

function inferRoutingDetail(modeHints, candidate) {
  const detailHint = toDetailText(findHintValue(candidate, ROUTING_HINT_KEYS.detail));
  if (detailHint) {
    return detailHint;
  }
  if (modeHints.modeKey === "managed_relay") {
    return modeHints.fallbackHint === true ? "Managed relay fallback is active." : "Managed relay path selected.";
  }
  if (modeHints.modeKey === "direct_mesh") {
    return modeHints.profileHint ? `Direct mesh path profile ${modeHints.profileHint}.` : "Direct mesh path selected.";
  }
  if (modeHints.modeKey === "hybrid_auto") {
    return "Hybrid auto routing prefers direct mesh and falls back to relay when needed.";
  }
  if (modeHints.modeKey === "inactive") {
    return "Routing is inactive while disconnected.";
  }
  if (modeHints.modeHint) {
    return modeHints.modeHint;
  }
  return undefined;
}

function inferRoutingSnapshotFromCandidate(candidate) {
  if (candidate === null || candidate === undefined) {
    return { mode: undefined, detail: undefined };
  }
  const modeHints = inferRoutingModeHints(candidate);
  return {
    mode: modeHints.modeKey ? formatRoutingModeLabel(modeHints.modeKey, modeHints.profileHint) : undefined,
    detail: inferRoutingDetail(modeHints, candidate)
  };
}

function readTopLevelRoutingHint(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return undefined;
  }
  if (Object.prototype.hasOwnProperty.call(payload, "routing")) {
    return payload.routing;
  }
  const mode = firstDefined(payload.routing_mode, payload.routingMode, payload.route_mode, payload.routeMode);
  const detail = firstDefined(
    payload.routing_detail,
    payload.routingDetail,
    payload.route_detail,
    payload.routeDetail,
    payload.routing_reason,
    payload.routingReason,
    payload.route_reason,
    payload.routeReason
  );
  const profile = firstDefined(payload.routing_profile, payload.routingProfile, payload.path_profile, payload.pathProfile);
  const relay = firstDefined(
    payload.relay_active,
    payload.relayActive,
    payload.using_relay,
    payload.usingRelay,
    payload.managed_relay,
    payload.managedRelay
  );
  const direct = firstDefined(payload.direct_active, payload.directActive, payload.direct_path, payload.directPath);
  const fallback = firstDefined(payload.relay_fallback, payload.relayFallback, payload.fallback_active, payload.fallbackActive);
  if (
    mode === undefined &&
    detail === undefined &&
    profile === undefined &&
    relay === undefined &&
    direct === undefined &&
    fallback === undefined
  ) {
    return undefined;
  }
  return {
    mode,
    detail,
    profile,
    relay,
    direct,
    fallback
  };
}

function inferRoutingSnapshot(source, payload) {
  const topLevelRouting = inferRoutingSnapshotFromCandidate(readTopLevelRoutingHint(payload));
  if (topLevelRouting.mode || topLevelRouting.detail) {
    return {
      mode: topLevelRouting.mode || state.routingMode || ROUTING_DEFAULT_MODE,
      detail: topLevelRouting.detail || state.routingDetail || ROUTING_DEFAULT_DETAIL
    };
  }

  const statusRouting = inferRoutingSnapshotFromCandidate(payload?.status);
  if (statusRouting.mode || statusRouting.detail) {
    return {
      mode: statusRouting.mode || state.routingMode || ROUTING_DEFAULT_MODE,
      detail: statusRouting.detail || state.routingDetail || ROUTING_DEFAULT_DETAIL
    };
  }

  const fallbackRouting = inferRoutingSnapshotFromCandidate(payload);
  if (fallbackRouting.mode || fallbackRouting.detail) {
    return {
      mode: fallbackRouting.mode || state.routingMode || ROUTING_DEFAULT_MODE,
      detail: fallbackRouting.detail || state.routingDetail || ROUTING_DEFAULT_DETAIL
    };
  }

  if (source === "disconnect") {
    return {
      mode: formatRoutingModeLabel("inactive"),
      detail: "Routing is inactive after disconnect."
    };
  }
  if (source === "connect") {
    const profileHint = normalizeRoutingProfileHint(pathProfileEl.value);
    return {
      mode: formatRoutingModeLabel("direct_mesh", profileHint),
      detail: profileHint
        ? `Connect requested ${profileHint} path profile; waiting for runtime routing telemetry.`
        : "Connect request completed; waiting for runtime routing telemetry."
    };
  }
  if (source === "status") {
    return {
      mode: state.routingMode || ROUTING_DEFAULT_MODE,
      detail: "Status refreshed; routing telemetry unavailable."
    };
  }
  if (source === "health") {
    return {
      mode: state.routingMode || ROUTING_DEFAULT_MODE,
      detail: "Health check completed; routing telemetry unavailable."
    };
  }
  return {
    mode: state.routingMode || ROUTING_DEFAULT_MODE,
    detail: state.routingDetail || ROUTING_DEFAULT_DETAIL
  };
}

function inferConnectionSnapshot(source, payload) {
  const stateHint = findHintValue(payload, CONNECTION_HINT_KEYS.state);
  const connected = toBooleanLike(findHintValue(payload, CONNECTION_HINT_KEYS.connected));
  const disconnected = toBooleanLike(findHintValue(payload, CONNECTION_HINT_KEYS.disconnected));
  const healthy = toBooleanLike(findHintValue(payload, CONNECTION_HINT_KEYS.healthy));

  let stateKey = normalizeConnectionState(stateHint);
  if (!stateKey && connected === true) {
    stateKey = "connected";
  }
  if (!stateKey && disconnected === true) {
    stateKey = "disconnected";
  }
  if (!stateKey && connected === false) {
    stateKey = "disconnected";
  }
  if (!stateKey && disconnected === false) {
    stateKey = "connected";
  }
  if (!stateKey && source === "connect") {
    stateKey = "connected";
  }
  if (!stateKey && source === "disconnect") {
    stateKey = "disconnected";
  }
  if (!stateKey && source === "health" && healthy !== undefined) {
    stateKey = healthy ? "healthy" : "degraded";
  }
  if (!stateKey) {
    stateKey = normalizeConnectionState(state.connectionState) || "unknown";
  }
  const routingSnapshot = inferRoutingSnapshot(source, payload);

  return {
    state: formatConnectionStateLabel(stateKey),
    detail: inferConnectionDetail(payload, source, stateKey, stateHint),
    routingMode: routingSnapshot.mode,
    routingDetail: routingSnapshot.detail
  };
}

function applyConnectionSnapshot(snapshot) {
  state.connectionState = snapshot?.state || state.connectionState || CONNECTION_DEFAULT_STATE;
  state.connectionDetail = snapshot?.detail || state.connectionDetail || CONNECTION_DEFAULT_DETAIL;
  state.routingMode = snapshot?.routingMode || state.routingMode || ROUTING_DEFAULT_MODE;
  state.routingDetail = snapshot?.routingDetail || state.routingDetail || ROUTING_DEFAULT_DETAIL;
  if (connectionStateEl) {
    connectionStateEl.textContent = state.connectionState;
  }
  if (connectionDetailEl) {
    connectionDetailEl.textContent = state.connectionDetail;
  }
  if (routingModeEl) {
    routingModeEl.textContent = state.routingMode;
  }
  if (routingDetailEl) {
    routingDetailEl.textContent = state.routingDetail;
  }
  syncConnectActionButtons();
}

function normalizeConnectionMutationKind(value) {
  if (value === "connect" || value === "disconnect") {
    return value;
  }
  return "";
}

function describeConnectionMutationInFlight(value) {
  const normalized = normalizeConnectionMutationKind(value);
  if (normalized === "connect") {
    return "Connect request in progress; wait for completion before issuing another tunnel command.";
  }
  if (normalized === "disconnect") {
    return "Disconnect request in progress; wait for completion before issuing another tunnel command.";
  }
  return "";
}

function beginConnectionMutation(kind) {
  const normalized = normalizeConnectionMutationKind(kind);
  if (!normalized) {
    return false;
  }
  if (state.connectionMutationInFlight) {
    return false;
  }
  state.connectionMutationInFlight = normalized;
  if (normalized === "connect") {
    applyConnectionSnapshot({
      state: formatConnectionStateLabel("connecting"),
      detail: "Connect request in progress. Avoid repeated connect/disconnect actions until state settles.",
      routingMode: state.routingMode || ROUTING_DEFAULT_MODE,
      routingDetail: state.routingDetail || ROUTING_DEFAULT_DETAIL
    });
  } else {
    applyConnectionSnapshot({
      state: formatConnectionStateLabel("disconnecting"),
      detail: "Disconnect request in progress. Avoid repeated connect/disconnect actions until state settles.",
      routingMode: state.routingMode || ROUTING_DEFAULT_MODE,
      routingDetail: state.routingDetail || ROUTING_DEFAULT_DETAIL
    });
  }
  return true;
}

function endConnectionMutation(kind) {
  const normalized = normalizeConnectionMutationKind(kind);
  if (!normalized) {
    return;
  }
  if (state.connectionMutationInFlight !== normalized) {
    return;
  }
  state.connectionMutationInFlight = "";
  syncConnectActionButtons();
}

function syncConnectActionButtons() {
  if (!connectBtnEl || !disconnectBtnEl) {
    return;
  }
  const stateKey = normalizeConnectionState(state.connectionState) || "unknown";
  const mutationInFlight = normalizeConnectionMutationKind(state.connectionMutationInFlight);
  const clientControlsUnlocked = isClientTabVisibleRole();
  const clientLockReason = computeClientLockHintText();
  let connectLabel = "Connect";
  let connectDisabled = !clientControlsUnlocked;
  let connectTitle = clientControlsUnlocked
    ? "Establish GPM tunnel connection."
    : `Connect is unavailable: ${clientLockReason}`;
  let disconnectDisabled = false;
  let disconnectTitle = "Disconnect GPM tunnel connection.";

  if (mutationInFlight === "connect") {
    connectLabel = "Connecting...";
    connectDisabled = true;
    connectTitle = "Connect request in progress.";
    disconnectDisabled = true;
    disconnectTitle = "Wait for connect request to complete.";
  } else if (mutationInFlight === "disconnect") {
    connectLabel = "Connect";
    connectDisabled = true;
    connectTitle = "Wait for disconnect request to complete.";
    disconnectDisabled = true;
    disconnectTitle = "Disconnect request in progress.";
  } else if (stateKey === "connected" || stateKey === "healthy") {
    connectLabel = "Connected";
    connectDisabled = true;
    connectTitle = "GPM tunnel connection is active.";
    disconnectDisabled = false;
  } else if (stateKey === "connecting") {
    connectLabel = "Connecting...";
    connectDisabled = true;
    connectTitle = "Connect request in progress.";
    disconnectDisabled = true;
    disconnectTitle = "Wait for connect request to complete.";
  } else if (stateKey === "disconnecting") {
    connectLabel = "Connect";
    connectDisabled = true;
    connectTitle = "Wait for disconnect request to complete.";
    disconnectDisabled = true;
    disconnectTitle = "Disconnect request in progress.";
  } else if (stateKey === "degraded") {
    connectLabel = "Reconnect";
    connectDisabled = !clientControlsUnlocked;
    connectTitle = clientControlsUnlocked
      ? "Connection health is degraded; reconnect is recommended."
      : `Reconnect is unavailable: ${clientLockReason}`;
    disconnectDisabled = false;
  } else if (stateKey === "disconnected") {
    disconnectDisabled = true;
  }

  connectBtnEl.textContent = connectLabel;
  connectBtnEl.disabled = connectDisabled;
  connectBtnEl.title = connectTitle;
  connectBtnEl.setAttribute("aria-pressed", stateKey === "connected" || stateKey === "healthy" ? "true" : "false");
  connectBtnEl.classList.toggle("vpn-connected", stateKey === "connected" || stateKey === "healthy");
  connectBtnEl.classList.toggle("vpn-transition", stateKey === "connecting" || mutationInFlight === "connect");

  disconnectBtnEl.disabled = disconnectDisabled;
  disconnectBtnEl.title = disconnectTitle;
  disconnectBtnEl.classList.toggle("vpn-transition", stateKey === "disconnecting" || mutationInFlight === "disconnect");
}

function updateConnectionDashboard(source, payload) {
  ingestSessionBootstrapDirectoryOptionsFromPayload(payload);
  applyConnectionSnapshot(inferConnectionSnapshot(source, payload));
}

function readConfigBoolean(cfg, candidates) {
  const source = cfg && typeof cfg === "object" ? cfg : {};
  const raw = firstDefined(...candidates.map((key) => source[key]));
  if (typeof raw === "boolean") {
    return raw;
  }
  if (typeof raw === "number") {
    return raw !== 0;
  }
  if (typeof raw === "string") {
    const normalized = raw.trim().toLowerCase();
    if (normalized === "1" || normalized === "true" || normalized === "yes") {
      return true;
    }
    if (normalized === "0" || normalized === "false" || normalized === "no") {
      return false;
    }
  }
  return undefined;
}

function readConfigString(cfg, candidates) {
  const source = cfg && typeof cfg === "object" ? cfg : {};
  const raw = firstDefined(...candidates.map((key) => source[key]));
  if (typeof raw === "string") {
    const value = raw.trim();
    if (value) {
      return value;
    }
  }
  return undefined;
}

function readConfigObject(cfg, candidates) {
  const source = cfg && typeof cfg === "object" ? cfg : {};
  for (const key of candidates) {
    const value = source[key];
    if (value && typeof value === "object" && !Array.isArray(value)) {
      return value;
    }
  }
  return undefined;
}

function appendRuntimeConfigScope(target, seen, value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return;
  }
  if (seen.has(value)) {
    return;
  }
  seen.add(value);
  target.push(value);
}

function collectRuntimeConfigScopes(runtimeCfg) {
  const runtime = runtimeCfg && typeof runtimeCfg === "object" ? runtimeCfg : {};
  const scopes = [];
  const seen = new Set();
  appendRuntimeConfigScope(scopes, seen, runtime);
  for (let index = 0; index < scopes.length; index += 1) {
    const scope = scopes[index];
    appendRuntimeConfigScope(scopes, seen, readConfigObject(scope, ["config"]));
    appendRuntimeConfigScope(scopes, seen, readConfigObject(scope, ["data"]));
    appendRuntimeConfigScope(scopes, seen, readConfigObject(scope, ["policy", "policies"]));
  }
  return scopes;
}

function collectRuntimeSectionScopes(baseScopes, sectionCandidates) {
  const scopes = [];
  const seen = new Set();
  for (const scope of baseScopes) {
    appendRuntimeConfigScope(scopes, seen, scope);
  }
  for (let index = 0; index < scopes.length; index += 1) {
    const scope = scopes[index];
    appendRuntimeConfigScope(scopes, seen, readConfigObject(scope, ["policy", "policies"]));
    for (const candidates of sectionCandidates) {
      appendRuntimeConfigScope(scopes, seen, readConfigObject(scope, candidates));
    }
  }
  return scopes;
}

function normalizePolicySource(value, runtimeSource, envSource) {
  const normalized = nonEmptyStringOrUndefined(value);
  if (!normalized) {
    return undefined;
  }
  const compact = normalized.toLowerCase().replace(/[\s-]+/g, "_");
  if (compact === runtimeSource || compact === "runtime" || compact === "runtime_policy") {
    return runtimeSource;
  }
  if (compact === envSource || compact === "env" || compact === "environment" || compact === "default") {
    return envSource;
  }
  return compact;
}

function normalizeConnectPolicySource(value) {
  return normalizePolicySource(value, CONNECT_POLICY_SOURCE_RUNTIME_CONFIG, CONNECT_POLICY_SOURCE_ENV_DEFAULT);
}

function normalizeAuthVerifyPolicySource(value) {
  return normalizePolicySource(
    value,
    AUTH_VERIFY_POLICY_SOURCE_RUNTIME_CONFIG,
    AUTH_VERIFY_POLICY_SOURCE_ENV_DEFAULT
  );
}

function normalizeOperatorApprovalPolicySource(value) {
  return normalizePolicySource(
    value,
    OPERATOR_APPROVAL_POLICY_SOURCE_RUNTIME_CONFIG,
    OPERATOR_APPROVAL_POLICY_SOURCE_ENV_DEFAULT
  );
}

function normalizeBootstrapTrustPolicySource(value) {
  return normalizePolicySource(
    value,
    BOOTSTRAP_TRUST_POLICY_SOURCE_RUNTIME_CONFIG,
    BOOTSTRAP_TRUST_POLICY_SOURCE_ENV_DEFAULT
  );
}

function normalizeProfileGateProbePolicySource(value) {
  return normalizePolicySource(
    value,
    PROFILE_GATE_PROBE_POLICY_SOURCE_RUNTIME_CONFIG,
    PROFILE_GATE_PROBE_POLICY_SOURCE_ENV_DEFAULT
  );
}

function normalizePolicyRequirement(value) {
  if (typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    return value !== 0;
  }
  const normalized = nonEmptyStringOrUndefined(value);
  if (!normalized) {
    return undefined;
  }
  const compact = normalized.toLowerCase().replace(/[\s-]+/g, "_");
  if (
    compact === "1" ||
    compact === "true" ||
    compact === "yes" ||
    compact === "required" ||
    compact === "require" ||
    compact === "strict" ||
    compact === "enabled" ||
    compact === "enforced" ||
    compact === "on"
  ) {
    return true;
  }
  if (
    compact === "0" ||
    compact === "false" ||
    compact === "no" ||
    compact === "optional" ||
    compact === "compat" ||
    compact === "disabled" ||
    compact === "off" ||
    compact === "none" ||
    compact === "any"
  ) {
    return false;
  }
  return undefined;
}

function normalizeAuthVerifySourceRequirement(value) {
  const normalized = normalizePolicyRequirement(value);
  if (normalized !== undefined) {
    return normalized;
  }
  const compact = nonEmptyStringOrUndefined(value)?.toLowerCase().replace(/[\s-]+/g, "_");
  if (!compact) {
    return undefined;
  }
  if (
    compact === "wallet_extension" ||
    compact === "wallet" ||
    compact === "wallet_extension_only" ||
    compact === "extension_only"
  ) {
    return true;
  }
  if (
    compact === "manual" ||
    compact === "manual_or_wallet" ||
    compact === "any_source" ||
    compact === "wallet_or_manual"
  ) {
    return false;
  }
  return undefined;
}

function normalizeConnectPolicyMode(value) {
  const normalized = nonEmptyStringOrUndefined(value);
  if (!normalized) {
    return undefined;
  }
  const compact = normalized.toLowerCase().replace(/[\s-]+/g, "_");
  if (
    compact === CONNECT_POLICY_MODE_SESSION_REQUIRED ||
    compact === "require_session" ||
    compact === "session_only" ||
    compact === "strict"
  ) {
    return CONNECT_POLICY_MODE_SESSION_REQUIRED;
  }
  if (
    compact === CONNECT_POLICY_MODE_COMPAT_ALLOWED ||
    compact === "compat" ||
    compact === "session_optional" ||
    compact === "legacy_allowed" ||
    compact === "manual_override_allowed"
  ) {
    return CONNECT_POLICY_MODE_COMPAT_ALLOWED;
  }
  return compact;
}

function connectPolicyModeFromRequireSession(connectRequireSession) {
  return connectRequireSession ? CONNECT_POLICY_MODE_SESSION_REQUIRED : CONNECT_POLICY_MODE_COMPAT_ALLOWED;
}

function formatConnectPolicyModeLabel(mode) {
  if (mode === CONNECT_POLICY_MODE_SESSION_REQUIRED) {
    return "session-required";
  }
  if (mode === CONNECT_POLICY_MODE_COMPAT_ALLOWED) {
    return "compat";
  }
  return nonEmptyStringOrUndefined(mode)?.replace(/_/g, " ") || "compat";
}

function formatConnectPolicySourceLabel(source) {
  if (source === CONNECT_POLICY_SOURCE_RUNTIME_CONFIG) {
    return "runtime config";
  }
  if (source === CONNECT_POLICY_SOURCE_ENV_DEFAULT) {
    return "env default";
  }
  return nonEmptyStringOrUndefined(source)?.replace(/_/g, " ") || "env default";
}

function formatConnectPolicyClientSourceLabel(source) {
  if (source === CONNECT_POLICY_SOURCE_RUNTIME_CONFIG) {
    return "runtime config (/v1/config)";
  }
  return "env defaults (GPM_CONNECT_REQUIRE_SESSION / GPM_ALLOW_LEGACY_CONNECT_OVERRIDE; legacy aliases: TDPN_CONNECT_REQUIRE_SESSION / TDPN_ALLOW_LEGACY_CONNECT_OVERRIDE)";
}

function readRuntimeConnectPolicyMetadata(runtimeCfg) {
  const baseScopes = collectRuntimeConfigScopes(runtimeCfg);
  const scopes = collectRuntimeSectionScopes(baseScopes, [
    ["connect_policy", "connectPolicy"],
    ["connect"]
  ]);

  const connectRequireSession = firstDefined(
    ...scopes.map((scope) =>
      readConfigBoolean(scope, [
        "connect_require_session",
        "connectRequireSession",
        "require_session",
        "requireSession"
      ])
    )
  );
  const allowLegacyConnectOverride = firstDefined(
    ...scopes.map((scope) =>
      readConfigBoolean(scope, [
        "allow_legacy_connect_override",
        "allowLegacyConnectOverride",
        "allow_manual_connect_override",
        "allowManualConnectOverride",
        "allow_manual_bootstrap_invite",
        "allowManualBootstrapInvite"
      ])
    )
  );
  const connectPolicySource = normalizeConnectPolicySource(
    firstDefined(
      ...scopes.map((scope) =>
        readConfigString(scope, [
          "connect_policy_source",
          "connectPolicySource",
          "policy_source",
          "policySource",
          "source"
        ])
      )
    )
  );
  const connectPolicyMode = normalizeConnectPolicyMode(
    firstDefined(
      ...scopes.map((scope) =>
        readConfigString(scope, [
          "connect_policy_mode",
          "connectPolicyMode",
          "connect_mode",
          "connectMode",
          "mode"
        ])
      )
    )
  );

  return {
    connectRequireSession,
    allowLegacyConnectOverride,
    connectPolicySource,
    connectPolicyMode
  };
}

function readRuntimeAuthVerifyPolicyMetadata(runtimeCfg) {
  const baseScopes = collectRuntimeConfigScopes(runtimeCfg);
  const scopes = collectRuntimeSectionScopes(baseScopes, [
    ["auth_verify_policy", "authVerifyPolicy"],
    ["auth_verify", "authVerify"],
    ["auth"]
  ]);

  let authVerifyRequireMetadata = firstDefined(
    ...scopes.map((scope) =>
      readConfigBoolean(scope, [
        "gpm_auth_verify_require_metadata",
        "auth_verify_require_metadata",
        "authVerifyRequireMetadata",
        "require_metadata",
        "requireMetadata",
        "metadata_required",
        "metadataRequired"
      ])
    )
  );
  if (authVerifyRequireMetadata === undefined) {
    authVerifyRequireMetadata = firstDefined(
      ...scopes.map((scope) =>
        normalizePolicyRequirement(
          readConfigString(scope, [
            "auth_verify_metadata_mode",
            "authVerifyMetadataMode",
            "metadata_mode",
            "metadataMode",
            "metadata_policy",
            "metadataPolicy"
          ])
        )
      )
    );
  }

  let authVerifyRequireWalletExtensionSource = firstDefined(
    ...scopes.map((scope) =>
      readConfigBoolean(scope, [
        "gpm_auth_verify_require_wallet_extension_source",
        "auth_verify_require_wallet_extension_source",
        "authVerifyRequireWalletExtensionSource",
        "require_wallet_extension_source",
        "requireWalletExtensionSource",
        "wallet_extension_source_required",
        "walletExtensionSourceRequired"
      ])
    )
  );
  if (authVerifyRequireWalletExtensionSource === undefined) {
    authVerifyRequireWalletExtensionSource = firstDefined(
      ...scopes.map((scope) =>
        normalizeAuthVerifySourceRequirement(
          readConfigString(scope, [
            "gpm_auth_verify_required_signature_source",
            "auth_verify_required_signature_source",
            "authVerifyRequiredSignatureSource",
            "required_signature_source",
            "requiredSignatureSource",
            "signature_source_policy",
            "signatureSourcePolicy"
          ])
        )
      )
    );
  }

  const authVerifyRequireCryptoProof = firstDefined(
    ...scopes.map((scope) =>
      readConfigBoolean(scope, [
        "gpm_auth_verify_require_crypto_proof",
        "auth_verify_require_crypto_proof",
        "authVerifyRequireCryptoProof",
        "require_crypto_proof",
        "requireCryptoProof",
        "crypto_proof_required",
        "cryptoProofRequired"
      ])
    )
  );
  const authVerifyRequireCryptoProofPolicySource = firstDefined(
    ...scopes.map((scope) =>
      readConfigString(scope, [
        "gpm_auth_verify_require_crypto_proof_policy_source",
        "auth_verify_require_crypto_proof_policy_source",
        "authVerifyRequireCryptoProofPolicySource"
      ])
    )
  );

  const authVerifyPolicySource = normalizeAuthVerifyPolicySource(
    firstDefined(
      ...scopes.map((scope) =>
        readConfigString(scope, [
          "auth_verify_policy_source",
          "authVerifyPolicySource",
          "auth_policy_source",
          "authPolicySource"
        ])
      )
    )
  );

  return {
    authVerifyRequireMetadata,
    authVerifyRequireWalletExtensionSource,
    authVerifyRequireCryptoProof,
    authVerifyRequireCryptoProofPolicySource,
    authVerifyPolicySource
  };
}

function readRuntimeOperatorApprovalPolicyMetadata(runtimeCfg) {
  const baseScopes = collectRuntimeConfigScopes(runtimeCfg);
  const scopes = collectRuntimeSectionScopes(baseScopes, [["operator_approval_policy", "operatorApprovalPolicy"], ["operator_approval", "operatorApproval"], ["operator"]]);
  const operatorApprovalRequireSession = firstDefined(
    ...scopes.map((scope) =>
      readConfigBoolean(scope, [
        "gpm_operator_approval_require_session",
        "gpmOperatorApprovalRequireSession",
        "operator_approval_require_session",
        "operatorApprovalRequireSession",
        "approval_require_session",
        "approvalRequireSession"
      ])
    )
  );
  const operatorApprovalPolicySource = normalizeOperatorApprovalPolicySource(
    firstDefined(
      ...scopes.map((scope) =>
        readConfigString(scope, [
          "gpm_operator_approval_require_session_policy_source",
          "gpmOperatorApprovalRequireSessionPolicySource",
          "operator_approval_require_session_policy_source",
          "operatorApprovalRequireSessionPolicySource",
          "operator_approval_policy_source",
          "operatorApprovalPolicySource",
          "approval_policy_source",
          "approvalPolicySource"
        ])
      )
    )
  );
  return {
    operatorApprovalRequireSession,
    operatorApprovalPolicySource
  };
}

function readRuntimeBootstrapTrustPolicyMetadata(runtimeCfg) {
  const baseScopes = collectRuntimeConfigScopes(runtimeCfg);
  const scopes = collectRuntimeSectionScopes(baseScopes, [
    ["manifest_trust_policy", "manifestTrustPolicy"],
    ["bootstrap_manifest_policy", "bootstrapManifestPolicy"],
    ["bootstrap_manifest", "bootstrapManifest"],
    ["manifest"]
  ]);
  const manifestRequireHttps = firstDefined(
    ...scopes.map((scope) =>
      readConfigBoolean(scope, [
        "gpm_manifest_require_https",
        "gpmManifestRequireHttps",
        "manifest_require_https",
        "manifestRequireHttps",
        "require_https",
        "requireHttps",
        "https_required_by_policy",
        "httpsRequiredByPolicy"
      ])
    )
  );
  const manifestRequireSignature = firstDefined(
    ...scopes.map((scope) =>
      readConfigBoolean(scope, [
        "gpm_manifest_require_signature",
        "gpmManifestRequireSignature",
        "manifest_require_signature",
        "manifestRequireSignature",
        "require_signature",
        "requireSignature",
        "signature_required_by_policy",
        "signatureRequiredByPolicy"
      ])
    )
  );
  const manifestTrustPolicySource = normalizeBootstrapTrustPolicySource(
    firstDefined(
      ...scopes.map((scope) =>
        readConfigString(scope, [
          "gpm_manifest_trust_policy_source",
          "gpmManifestTrustPolicySource",
          "manifest_trust_policy_source",
          "manifestTrustPolicySource",
          "manifest_policy_source",
          "manifestPolicySource",
          "policy_source",
          "policySource"
        ])
      )
    )
  );
  return {
    manifestRequireHttps,
    manifestRequireSignature,
    manifestTrustPolicySource
  };
}

function readRuntimeProfileGateProbePolicyMetadata(runtimeCfg) {
  const baseScopes = collectRuntimeConfigScopes(runtimeCfg);
  const scopes = collectRuntimeSectionScopes(baseScopes, [
    ["profile_default_gate_policy", "profileDefaultGatePolicy"],
    ["profile_default_gate", "profileDefaultGate"],
    ["profile_gate", "profileGate"],
    ["profile"]
  ]);
  const allowRemoteHttpProbe = firstDefined(
    ...scopes.map((scope) =>
      readConfigBoolean(scope, [
        "profile_default_gate_allow_remote_http_probe",
        "profileDefaultGateAllowRemoteHttpProbe",
        "gpm_profile_default_gate_allow_remote_http_probe",
        "gpmProfileDefaultGateAllowRemoteHttpProbe",
        "allow_remote_http_probe",
        "allowRemoteHttpProbe"
      ])
    )
  );
  const allowInsecureProbe = firstDefined(
    ...scopes.map((scope) =>
      readConfigBoolean(scope, [
        "profile_default_gate_allow_insecure_probe",
        "profileDefaultGateAllowInsecureProbe",
        "gpm_profile_default_gate_allow_insecure_probe",
        "gpmProfileDefaultGateAllowInsecureProbe",
        "allow_insecure_probe",
        "allowInsecureProbe"
      ])
    )
  );
  const profileGateProbePolicySource = normalizeProfileGateProbePolicySource(
    firstDefined(
      ...scopes.map((scope) =>
        readConfigString(scope, [
          "profile_default_gate_probe_policy_source",
          "profileDefaultGateProbePolicySource",
          "profile_gate_probe_policy_source",
          "profileGateProbePolicySource",
          "probe_policy_source",
          "probePolicySource",
          "policy_source",
          "policySource"
        ])
      )
    )
  );
  return {
    allowRemoteHttpProbe,
    allowInsecureProbe,
    profileGateProbePolicySource
  };
}

function readRuntimeProductionModeMetadata(runtimeCfg, runtimeConnectPolicy, runtimeAuthVerifyPolicy) {
  const baseScopes = collectRuntimeConfigScopes(runtimeCfg);
  const scopes = collectRuntimeSectionScopes(baseScopes, [["production_mode", "productionMode"], ["production"]]);

  const productionMode = firstDefined(
    ...scopes.map((scope) =>
      readConfigBoolean(scope, [
        "gpm_production_mode",
        "gpmProductionMode",
        "production_mode",
        "productionMode"
      ])
    )
  );
  const productionModeSource = normalizeConnectPolicySource(
    firstDefined(
      ...scopes.map((scope) =>
        readConfigString(scope, [
          "gpm_production_mode_policy_source",
          "gpmProductionModePolicySource",
          "production_mode_policy_source",
          "productionModePolicySource",
          "gpm_production_mode_source",
          "gpmProductionModeSource",
          "production_mode_source",
          "productionModeSource"
        ])
      )
    )
  );
  if (productionMode !== undefined) {
    return {
      productionMode: productionMode === true,
      productionModeSource: productionModeSource || CONNECT_POLICY_SOURCE_RUNTIME_CONFIG
    };
  }

  const connectPolicySource = normalizeConnectPolicySource(runtimeConnectPolicy?.connectPolicySource);
  const connectPolicyMode =
    normalizeConnectPolicyMode(runtimeConnectPolicy?.connectPolicyMode) ||
    connectPolicyModeFromRequireSession(runtimeConnectPolicy?.connectRequireSession === true);
  if (
    connectPolicySource === CONNECT_POLICY_SOURCE_RUNTIME_CONFIG &&
    connectPolicyMode === CONNECT_POLICY_MODE_SESSION_REQUIRED
  ) {
    return {
      productionMode: true,
      productionModeSource: PRODUCTION_MODE_SOURCE_POLICY_FALLBACK_CONNECT
    };
  }

  const authVerifyPolicySource = normalizeAuthVerifyPolicySource(runtimeAuthVerifyPolicy?.authVerifyPolicySource);
  if (
    authVerifyPolicySource === AUTH_VERIFY_POLICY_SOURCE_RUNTIME_CONFIG &&
    runtimeAuthVerifyPolicy?.authVerifyRequireWalletExtensionSource === true
  ) {
    return {
      productionMode: true,
      productionModeSource: PRODUCTION_MODE_SOURCE_POLICY_FALLBACK_AUTH_VERIFY
    };
  }

  return {
    productionMode: false,
    productionModeSource: CONNECT_POLICY_SOURCE_ENV_DEFAULT
  };
}

function normalizeLegacyAliasEnvName(value) {
  const parsed = nonEmptyStringOrUndefined(value);
  if (!parsed) {
    return undefined;
  }
  const upper = parsed.toUpperCase();
  if (!upper.startsWith("TDPN_")) {
    return undefined;
  }
  return upper;
}

function appendLegacyAliasEnvNames(target, value) {
  if (Array.isArray(value)) {
    for (const entry of value) {
      appendLegacyAliasEnvNames(target, entry);
    }
    return;
  }
  if (typeof value === "string" && value.includes(",")) {
    for (const entry of value.split(",")) {
      appendLegacyAliasEnvNames(target, entry);
    }
    return;
  }
  const alias = normalizeLegacyAliasEnvName(value);
  if (alias) {
    pushUniqueNonEmptyString(target, alias);
  }
}

function appendLegacyAliasWarnings(target, value) {
  if (Array.isArray(value)) {
    for (const entry of value) {
      appendLegacyAliasWarnings(target, entry);
    }
    return;
  }
  if (typeof value === "string" && value.includes(";")) {
    for (const entry of value.split(";")) {
      appendLegacyAliasWarnings(target, entry);
    }
    return;
  }
  const warning = nonEmptyStringOrUndefined(value);
  if (!warning) {
    return;
  }
  pushUniqueNonEmptyString(target, normalizeLegacyEnvNameDisplayText(warning));
}

function readRuntimeLegacyAliasTelemetry(runtimeCfg) {
  const scopes = collectRuntimeConfigScopes(runtimeCfg);
  const activeAliases = [];
  const warnings = [];
  let activeCount;
  for (const scope of scopes) {
    appendLegacyAliasEnvNames(
      activeAliases,
      firstDefined(
        scope.gpm_legacy_env_aliases_active,
        scope.gpmLegacyEnvAliasesActive,
        scope.legacy_env_aliases_active,
        scope.legacyEnvAliasesActive
      )
    );
    appendLegacyAliasWarnings(
      warnings,
      firstDefined(
        scope.gpm_legacy_env_alias_warnings,
        scope.gpmLegacyEnvAliasWarnings,
        scope.legacy_env_alias_warnings,
        scope.legacyEnvAliasWarnings
      )
    );
    appendLegacyAliasWarnings(
      warnings,
      readConfigString(scope, [
        "gpm_legacy_env_aliases_warning",
        "gpmLegacyEnvAliasesWarning",
        "legacy_env_aliases_warning",
        "legacyEnvAliasesWarning",
        "gpm_legacy_env_alias_warning",
        "gpmLegacyEnvAliasWarning",
        "legacy_env_alias_warning",
        "legacyEnvAliasWarning"
      ])
    );
    if (activeCount === undefined) {
      activeCount = nonNegativeIntegerOrUndefined(
        firstDefined(
          scope.gpm_legacy_env_aliases_active_count,
          scope.gpmLegacyEnvAliasesActiveCount,
          scope.legacy_env_aliases_active_count,
          scope.legacyEnvAliasesActiveCount
        )
      );
    }
  }
  if (activeCount === undefined) {
    activeCount = activeAliases.length;
  }
  return {
    activeAliases,
    warnings,
    activeCount
  };
}

function mergeLegacyAliasTelemetry(baseTelemetry, runtimeTelemetry) {
  const activeAliases = [];
  const warnings = [];
  let activeCount = 0;
  for (const telemetry of [baseTelemetry, runtimeTelemetry]) {
    if (!telemetry || typeof telemetry !== "object") {
      continue;
    }
    for (const alias of Array.isArray(telemetry.activeAliases) ? telemetry.activeAliases : []) {
      appendLegacyAliasEnvNames(activeAliases, alias);
    }
    for (const warning of Array.isArray(telemetry.warnings) ? telemetry.warnings : []) {
      appendLegacyAliasWarnings(warnings, warning);
    }
    const parsedCount = nonNegativeIntegerOrUndefined(telemetry.activeCount);
    if (parsedCount !== undefined && parsedCount > activeCount) {
      activeCount = parsedCount;
    }
  }
  if (activeAliases.length > activeCount) {
    activeCount = activeAliases.length;
  }
  return {
    activeAliases,
    warnings,
    activeCount
  };
}

function formatConfigMeta(cfg) {
  const baseUrl = readConfigString(cfg, ["base_url", "api_base_url", "api_url"]) || "unknown";
  const timeout = numberOrUndefined(firstDefined(cfg.timeout_sec, cfg.timeoutSeconds, cfg.api_timeout_sec));
  const updateChannel = readConfigString(cfg, ["update_channel", "updateChannel", "channel", "release_channel"]);
  const contract = readConfigString(cfg, ["api_contract"]) || "unknown-contract";
  const product = readConfigString(cfg, ["product_name"]) || "Global Private Mesh";

  const authConfigured = readConfigBoolean(cfg, ["auth_bearer_configured", "authConfigured"]);
  const remoteAllowed = readConfigBoolean(cfg, ["allow_remote", "remote_allowed", "remoteAllowed"]);
  const updateFeedConfigured = readConfigBoolean(cfg, ["update_feed_configured", "updateFeedConfigured"]);
  const updateMutationsEnabled = readConfigBoolean(cfg, [
    "allow_update_mutations",
    "allowUpdateMutations"
  ]);
  const serviceMutationsEnabled = readConfigBoolean(cfg, [
    "allow_service_mutations",
    "allowServiceMutations"
  ]);
  const connectRequireSession = readConfigBoolean(cfg, [
    "connect_require_session",
    "connectRequireSession"
  ]);
  const productionMode = readConfigBoolean(cfg, [
    "gpm_production_mode",
    "gpmProductionMode",
    "production_mode",
    "productionMode"
  ]);
  const allowLegacyConnectOverride = readConfigBoolean(cfg, [
    "allow_legacy_connect_override",
    "allowLegacyConnectOverride"
  ]);
  const authVerifyRequireMetadata = firstDefined(
    readConfigBoolean(cfg, [
      "gpm_auth_verify_require_metadata",
      "auth_verify_require_metadata",
      "authVerifyRequireMetadata"
    ]),
    normalizePolicyRequirement(
      readConfigString(cfg, ["auth_verify_metadata_mode", "authVerifyMetadataMode", "metadata_mode", "metadataMode"])
    )
  );
  const authVerifyRequireWalletExtensionSource = firstDefined(
    readConfigBoolean(cfg, [
      "gpm_auth_verify_require_wallet_extension_source",
      "auth_verify_require_wallet_extension_source",
      "authVerifyRequireWalletExtensionSource"
    ]),
    normalizeAuthVerifySourceRequirement(
      readConfigString(cfg, [
        "gpm_auth_verify_required_signature_source",
        "auth_verify_required_signature_source",
        "authVerifyRequiredSignatureSource",
        "required_signature_source",
        "requiredSignatureSource"
      ])
    )
  );
  const authVerifyRequireCryptoProof = firstDefined(
    readConfigBoolean(cfg, [
      "gpm_auth_verify_require_crypto_proof",
      "auth_verify_require_crypto_proof",
      "authVerifyRequireCryptoProof"
    ])
  );
  const authVerifyRequireCryptoProofPolicySource = readConfigString(cfg, [
    "gpm_auth_verify_require_crypto_proof_policy_source",
    "auth_verify_require_crypto_proof_policy_source",
    "authVerifyRequireCryptoProofPolicySource"
  ]);

  const hints = [`contract: ${contract}`];
  if (authConfigured !== undefined) {
    hints.push(authConfigured ? "auth configured" : "auth not configured");
  }
  if (remoteAllowed !== undefined) {
    hints.push(remoteAllowed ? "remote allowed" : "remote local-only");
  }
  if (updateChannel) {
    hints.push(`channel: ${updateChannel}`);
  }
  if (updateFeedConfigured !== undefined) {
    hints.push(updateFeedConfigured ? "feed configured" : "feed not set");
  }
  if (updateMutationsEnabled !== undefined) {
    hints.push(updateMutationsEnabled ? "update enabled" : "update locked");
  }
  if (serviceMutationsEnabled !== undefined) {
    hints.push(serviceMutationsEnabled ? "service actions enabled" : "service actions locked");
  }
  if (connectRequireSession !== undefined) {
    hints.push(connectRequireSession ? "session-required connect mode" : "compat connect mode allowed");
  }
  if (productionMode !== undefined) {
    hints.push(productionMode ? "production mode enabled" : "production mode disabled");
  }
  if (allowLegacyConnectOverride !== undefined) {
    hints.push(allowLegacyConnectOverride ? "legacy compat controls enabled" : "legacy compat controls locked");
  }
  if (authVerifyRequireMetadata !== undefined) {
    hints.push(authVerifyRequireMetadata ? "auth verify metadata required" : "auth verify metadata optional");
  }
  if (authVerifyRequireWalletExtensionSource !== undefined) {
    hints.push(
      authVerifyRequireWalletExtensionSource
        ? "auth verify source requires wallet_extension"
        : "auth verify source allows manual or wallet_extension"
    );
  }
  if (authVerifyRequireCryptoProof !== undefined) {
    hints.push(authVerifyRequireCryptoProof ? "auth verify crypto proof required" : "auth verify crypto proof optional");
  }
  if (authVerifyRequireCryptoProofPolicySource) {
    hints.push(`auth verify crypto proof source: ${authVerifyRequireCryptoProofPolicySource}`);
  }

  return {
    apiLine: timeout ? `${product} API: ${baseUrl} (timeout: ${timeout}s)` : `${product} API: ${baseUrl}`,
    hintLine: hints.join(" | "),
    updateMutationsEnabled: updateMutationsEnabled === true,
    serviceMutationsEnabled: serviceMutationsEnabled === true,
    connectRequireSession: connectRequireSession === true,
    productionMode: productionMode === true,
    allowLegacyConnectOverride: allowLegacyConnectOverride === true,
    authVerifyRequireMetadata: authVerifyRequireMetadata === true,
    authVerifyRequireWalletExtensionSource: authVerifyRequireWalletExtensionSource === true,
    authVerifyRequireCryptoProof: authVerifyRequireCryptoProof === true,
    authVerifyRequireCryptoProofPolicySource: authVerifyRequireCryptoProofPolicySource || ""
  };
}

function formatConnectPolicySourceHint(source, mode) {
  return `connect policy: ${formatConnectPolicyModeLabel(mode)} (${formatConnectPolicySourceLabel(source)})`;
}

function formatProductionModeSourceLabel(source) {
  if (source === CONNECT_POLICY_SOURCE_RUNTIME_CONFIG) {
    return "runtime config";
  }
  if (source === PRODUCTION_MODE_SOURCE_POLICY_FALLBACK_CONNECT) {
    return "connect policy fallback";
  }
  if (source === PRODUCTION_MODE_SOURCE_POLICY_FALLBACK_AUTH_VERIFY) {
    return "auth verify policy fallback";
  }
  if (source === CONNECT_POLICY_SOURCE_ENV_DEFAULT) {
    return "env default";
  }
  return nonEmptyStringOrUndefined(source)?.replace(/_/g, " ") || "env default";
}

function formatProductionModeSourceHint(enabled, source) {
  return `production mode: ${enabled ? "enabled" : "disabled"} (${formatProductionModeSourceLabel(source)})`;
}

function formatAuthVerifyPolicyModeLabel(requireMetadata, requireWalletExtensionSource, requireCryptoProof) {
  const labels = [];
  if (requireMetadata) {
    labels.push("metadata-required");
  }
  if (requireWalletExtensionSource) {
    labels.push("wallet-extension-source-required");
  }
  if (requireCryptoProof) {
    labels.push("crypto-proof-required");
  }
  return labels.length > 0 ? labels.join(" + ") : "compat";
}

function formatAuthVerifyPolicySourceLabel(source) {
  if (source === AUTH_VERIFY_POLICY_SOURCE_RUNTIME_CONFIG) {
    return "runtime config";
  }
  if (source === AUTH_VERIFY_POLICY_SOURCE_ENV_DEFAULT) {
    return "env default";
  }
  return nonEmptyStringOrUndefined(source)?.replace(/_/g, " ") || "env default";
}

function formatAuthVerifyPolicyClientSourceLabel(source) {
  if (source === AUTH_VERIFY_POLICY_SOURCE_RUNTIME_CONFIG) {
    return "runtime config (/v1/config)";
  }
  return "env defaults (GPM_AUTH_VERIFY_REQUIRE_METADATA / GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE / GPM_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF; legacy aliases: TDPN_AUTH_VERIFY_REQUIRE_METADATA / TDPN_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE / TDPN_AUTH_VERIFY_REQUIRE_CRYPTO_PROOF)";
}

function formatAuthVerifyPolicySourceHint(source, requireMetadata, requireWalletExtensionSource, requireCryptoProof) {
  return `auth verify policy: ${formatAuthVerifyPolicyModeLabel(
    requireMetadata,
    requireWalletExtensionSource,
    requireCryptoProof
  )} (${formatAuthVerifyPolicySourceLabel(source)})`;
}

function formatOperatorApprovalPolicySourceLabel(source) {
  if (source === OPERATOR_APPROVAL_POLICY_SOURCE_RUNTIME_CONFIG) {
    return "runtime config";
  }
  if (source === OPERATOR_APPROVAL_POLICY_SOURCE_ENV_DEFAULT) {
    return "env default";
  }
  return nonEmptyStringOrUndefined(source)?.replace(/_/g, " ") || "env default";
}

function formatOperatorApprovalPolicyClientSourceLabel(source) {
  if (source === OPERATOR_APPROVAL_POLICY_SOURCE_RUNTIME_CONFIG) {
    return "runtime config (/v1/config)";
  }
  return "env defaults (GPM_OPERATOR_APPROVAL_REQUIRE_SESSION; legacy alias: TDPN_OPERATOR_APPROVAL_REQUIRE_SESSION)";
}

function formatOperatorApprovalPolicySourceHint(source, requireSession) {
  const mode = requireSession ? "session-required" : "compat";
  return `operator approval policy: ${mode} (${formatOperatorApprovalPolicySourceLabel(source)})`;
}

function formatBootstrapTrustPolicySourceLabel(source) {
  if (source === BOOTSTRAP_TRUST_POLICY_SOURCE_RUNTIME_CONFIG) {
    return "runtime config";
  }
  if (source === BOOTSTRAP_TRUST_POLICY_SOURCE_ENV_DEFAULT) {
    return "env default";
  }
  return nonEmptyStringOrUndefined(source)?.replace(/_/g, " ") || "env default";
}

function formatBootstrapTrustPolicyHint(manifestRequireHttps, manifestRequireSignature, source) {
  const requirements = [];
  if (manifestRequireHttps !== undefined) {
    requirements.push(manifestRequireHttps ? "https-required" : "https-compat");
  }
  if (manifestRequireSignature !== undefined) {
    requirements.push(manifestRequireSignature ? "signature-required" : "signature-compat");
  }
  if (requirements.length === 0) {
    return "";
  }
  return `bootstrap trust policy: ${requirements.join(" + ")} (${formatBootstrapTrustPolicySourceLabel(source)})`;
}

function formatProfileGateProbePolicySourceLabel(source) {
  if (source === PROFILE_GATE_PROBE_POLICY_SOURCE_RUNTIME_CONFIG) {
    return "runtime config";
  }
  if (source === PROFILE_GATE_PROBE_POLICY_SOURCE_ENV_DEFAULT) {
    return "env default";
  }
  return nonEmptyStringOrUndefined(source)?.replace(/_/g, " ") || "env default";
}

function formatProfileGateProbePolicyHint(allowRemoteHttpProbe, allowInsecureProbe, source) {
  const policies = [];
  if (allowRemoteHttpProbe !== undefined) {
    policies.push(allowRemoteHttpProbe ? "remote-http-probe-opt-in" : "remote-http-probe-blocked");
  }
  if (allowInsecureProbe !== undefined) {
    policies.push(allowInsecureProbe ? "insecure-probe-enabled" : "insecure-probe-disabled");
  }
  if (policies.length === 0) {
    return "";
  }
  return `profile gate probe policy: ${policies.join(" + ")} (${formatProfileGateProbePolicySourceLabel(source)})`;
}

function normalizeOperatorApplicationStatus(value) {
  if (typeof value !== "string") {
    return undefined;
  }
  const normalized = value.trim().toLowerCase();
  if (OPERATOR_APPLICATION_STATUSES.has(normalized)) {
    return normalized;
  }
  return undefined;
}

function parseOperatorApplicationStatus(payload) {
  return normalizeOperatorApplicationStatus(payload?.application?.status);
}

function normalizeOperatorListStatusFilter(value) {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  if (!normalized || normalized === "all") {
    return "";
  }
  if (normalized === "pending" || normalized === "approved" || normalized === "rejected") {
    return normalized;
  }
  return "";
}

function extractOperatorListEntries(payload) {
  const containers = [payload, payload?.data, payload?.result, payload?.queue, payload?.list];
  for (const container of containers) {
    if (!container || typeof container !== "object") {
      continue;
    }
    for (const key of ["operators", "items", "results", "entries", "applications", "queue"]) {
      if (Array.isArray(container[key])) {
        return container[key];
      }
    }
  }
  return [];
}

function readOperatorEntryField(entry, candidates) {
  if (!entry || typeof entry !== "object") {
    return "";
  }
  const scopes = [entry, entry.application, entry.request, entry.profile, entry.operator];
  for (const scope of scopes) {
    if (!scope || typeof scope !== "object") {
      continue;
    }
    for (const key of candidates) {
      const text = toDetailText(scope[key]);
      if (text) {
        return text;
      }
    }
  }
  return "";
}

function extractOperatorPrefillValues(entry) {
  if (typeof entry === "string") {
    const chainOperatorId = entry.trim();
    return {
      walletAddress: "",
      chainOperatorId,
      selectedApplicationUpdatedAtUtc: ""
    };
  }
  return {
    walletAddress: readOperatorEntryField(entry, [
      "wallet_address",
      "walletAddress",
      "address",
      "subject_wallet",
      "subjectWallet"
    ]),
    chainOperatorId: readOperatorEntryField(entry, [
      "chain_operator_id",
      "chainOperatorId",
      "operator_id",
      "operatorId",
      "id"
    ]),
    selectedApplicationUpdatedAtUtc: readOperatorEntryField(entry, [
      "updated_at_utc",
      "updatedAtUtc",
      "updated_at",
      "updatedAt",
      "application_updated_at_utc",
      "applicationUpdatedAtUtc",
      "if_updated_at_utc",
      "ifUpdatedAtUtc"
    ])
  };
}

function setSelectedApplicationUpdatedAt(value, options = {}) {
  const { persist = true } = options;
  const normalized = typeof value === "string" ? value.trim() : "";
  state.selectedApplicationUpdatedAtUtc = normalized;
  selectedApplicationUpdatedAtEl.value = normalized;
  if (persist) {
    writePersistedValue(STORAGE_KEYS.selectedApplicationUpdatedAt, normalized);
  }
}

function applySelectedOperatorPrefill(values, options = {}) {
  const { mode = "merge", persist = true } = options;
  const walletAddress = typeof values?.walletAddress === "string" ? values.walletAddress.trim() : "";
  const chainOperatorId = typeof values?.chainOperatorId === "string" ? values.chainOperatorId.trim() : "";
  const selectedUpdatedAtUtc =
    typeof values?.selectedApplicationUpdatedAtUtc === "string"
      ? values.selectedApplicationUpdatedAtUtc.trim()
      : "";
  if (mode === "replace" || walletAddress) {
    walletAddressEl.value = walletAddress;
    if (persist) {
      writePersistedValue(STORAGE_KEYS.walletAddress, walletAddress);
    }
  }
  if (mode === "replace" || chainOperatorId) {
    chainOperatorIdEl.value = chainOperatorId;
    if (persist) {
      writePersistedValue(STORAGE_KEYS.chainOperatorId, chainOperatorId);
    }
  }
  if (mode === "replace" || selectedUpdatedAtUtc) {
    setSelectedApplicationUpdatedAt(selectedUpdatedAtUtc, { persist });
  }
}

function prefillSelectedOperatorFromListPayload(payload, options = {}) {
  const entries = extractOperatorListEntries(payload);
  if (entries.length === 0) {
    return false;
  }
  applySelectedOperatorPrefill(extractOperatorPrefillValues(entries[0]), options);
  return true;
}

function extractOperatorListPageInfo(payload) {
  const entries = extractOperatorListEntries(payload);
  const containers = [
    payload,
    payload?.data,
    payload?.result,
    payload?.queue,
    payload?.list,
    payload?.meta,
    payload?.page,
    payload?.pagination
  ];
  let returned;
  let hasMore;
  let nextCursor;
  for (const container of containers) {
    if (!container || typeof container !== "object") {
      continue;
    }
    if (returned === undefined) {
      returned = nonNegativeIntegerOrUndefined(
        firstDefined(
          container.returned,
          container.count,
          container.returned_count,
          container.results_count,
          container.result_count,
          container.items_count,
          container.item_count
        )
      );
    }
    if (hasMore === undefined) {
      hasMore = toBooleanLike(
        firstDefined(
          container.has_more,
          container.hasMore,
          container.has_next,
          container.hasNext,
          container.more
        )
      );
    }
    if (!nextCursor) {
      nextCursor = nonEmptyStringOrUndefined(
        firstDefined(
          container.next_cursor,
          container.nextCursor,
          container.next_page_cursor,
          container.nextPageCursor,
          container.continuation_cursor,
          container.continuationCursor
        )
      );
    }
  }
  if (returned === undefined) {
    returned = entries.length;
  }
  if (hasMore === undefined && nextCursor) {
    hasMore = true;
  }
  return {
    returned,
    hasMore,
    nextCursor: nextCursor || ""
  };
}

function normalizeOperatorListFilterContext(context = {}) {
  const status = Object.prototype.hasOwnProperty.call(context, "status")
    ? normalizeOperatorListStatusFilter(context.status)
    : "";
  const search = nonEmptyStringOrUndefined(context.search);
  const limit = numberOrUndefined(context.limit);
  return {
    status,
    search,
    limit: limit || OPERATOR_FILTER_DEFAULT_LIMIT
  };
}

function syncOperatorListPaginationControlState() {
  const canPage =
    !!state.sessionToken &&
    !!state.operatorListNextCursor &&
    !!state.operatorListRequestContext;
  operatorListNextBtnEl.disabled = !canPage;
}

function setOperatorListRequestContext(context) {
  state.operatorListRequestContext = context ? normalizeOperatorListFilterContext(context) : null;
  syncOperatorListPaginationControlState();
}

function setOperatorListNextCursor(value) {
  const cursor = nonEmptyStringOrUndefined(value) || "";
  state.operatorListNextCursor = cursor;
  operatorListNextCursorEl.value = cursor;
  syncOperatorListPaginationControlState();
}

function clearOperatorListPaginationState() {
  state.operatorListRequestContext = null;
  setOperatorListNextCursor("");
}

function readOperatorListFilterControls() {
  return normalizeOperatorListFilterContext({
    status: operatorListStatusEl.value,
    search: operatorListSearchEl.value,
    limit: operatorListLimitEl.value
  });
}

function buildOperatorListRequest(filter, options = {}) {
  const request = {
    session_token: state.sessionToken
  };
  if (Object.prototype.hasOwnProperty.call(filter, "status")) {
    request.status = filter.status;
  }
  if (filter.limit !== undefined) {
    request.limit = filter.limit;
  }
  if (filter.search) {
    request.search = filter.search;
  }
  const cursor = nonEmptyStringOrUndefined(options.cursor);
  if (cursor) {
    request.cursor = cursor;
  }
  return request;
}

function formatOperatorListDisplayPayload(result, request) {
  const page = extractOperatorListPageInfo(result);
  if (result && typeof result === "object" && !Array.isArray(result)) {
    return {
      ...result,
      queue_page: {
        returned: page.returned,
        has_more: page.hasMore ?? null,
        next_cursor: page.nextCursor || null
      },
      request_page: {
        status: request.status ?? null,
        search: request.search ?? null,
        limit: request.limit ?? null,
        cursor: request.cursor ?? null
      }
    };
  }
  return {
    result,
    queue_page: {
      returned: page.returned,
      has_more: page.hasMore ?? null,
      next_cursor: page.nextCursor || null
    },
    request_page: {
      status: request.status ?? null,
      search: request.search ?? null,
      limit: request.limit ?? null,
      cursor: request.cursor ?? null
    }
  };
}

async function requestOperatorList(label, filter, options = {}) {
  const { cursor, prefillMode = "merge", syncControls = false } = options;
  const normalizedFilter = normalizeOperatorListFilterContext(filter);
  const request = buildOperatorListRequest(normalizedFilter, { cursor });
  const result = await call(label, "control_gpm_operator_list", { request }, {
    formatResultForDisplay: (payload) => formatOperatorListDisplayPayload(payload, request)
  });
  prefillSelectedOperatorFromListPayload(result, { mode: prefillMode });
  const page = extractOperatorListPageInfo(result);
  setOperatorListRequestContext(normalizedFilter);
  setOperatorListNextCursor(page.nextCursor);
  if (syncControls) {
    operatorListStatusEl.value = normalizedFilter.status;
    operatorListSearchEl.value = normalizedFilter.search || "";
    operatorListLimitEl.value = String(normalizedFilter.limit);
  }
  return result;
}

function normalizeAuditOrder(value) {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  if (normalized === "asc") {
    return "asc";
  }
  return "desc";
}

function normalizeAuditRecentRequestContext(context = {}) {
  const limit = numberOrUndefined(context.limit) || 25;
  const offset = nonNegativeIntegerOrUndefined(context.offset);
  return {
    limit,
    offset: offset === undefined ? 0 : offset,
    event: nonEmptyStringOrUndefined(context.event),
    wallet_address: nonEmptyStringOrUndefined(context.wallet_address),
    order: normalizeAuditOrder(context.order)
  };
}

function readAuditRecentControls() {
  return normalizeAuditRecentRequestContext({
    limit: auditLimitEl.value,
    offset: auditOffsetEl.value,
    event: auditEventEl.value,
    wallet_address: auditWalletAddressEl.value,
    order: auditOrderEl.value
  });
}

function buildAuditRecentRequest(context) {
  const request = {
    limit: context.limit
  };
  if (context.offset !== undefined) {
    request.offset = context.offset;
  }
  if (context.event) {
    request.event = context.event;
  }
  if (context.wallet_address) {
    request.wallet_address = context.wallet_address;
  }
  if (context.order) {
    request.order = context.order;
  }
  return request;
}

function extractAuditRecentEntries(payload) {
  const containers = [payload, payload?.data, payload?.result, payload?.audit, payload?.records];
  for (const container of containers) {
    if (!container || typeof container !== "object") {
      continue;
    }
    for (const key of ["entries", "items", "results", "events", "records", "logs"]) {
      if (Array.isArray(container[key])) {
        return container[key];
      }
    }
  }
  return [];
}

function extractAuditRecentPageInfo(payload) {
  const entries = extractAuditRecentEntries(payload);
  const containers = [payload, payload?.data, payload?.result, payload?.meta, payload?.page, payload?.pagination];
  let returned;
  let total;
  let limit;
  let offset;
  let hasMore;
  let nextOffset;
  for (const container of containers) {
    if (!container || typeof container !== "object") {
      continue;
    }
    if (returned === undefined) {
      returned = nonNegativeIntegerOrUndefined(
        firstDefined(container.count, container.returned, container.returned_count, container.result_count)
      );
    }
    if (total === undefined) {
      total = nonNegativeIntegerOrUndefined(
        firstDefined(container.total, container.total_count, container.total_results, container.results_total)
      );
    }
    if (limit === undefined) {
      limit = nonNegativeIntegerOrUndefined(
        firstDefined(container.limit, container.page_size, container.pageSize)
      );
    }
    if (offset === undefined) {
      offset = nonNegativeIntegerOrUndefined(
        firstDefined(container.offset, container.page_offset, container.pageOffset)
      );
    }
    if (hasMore === undefined) {
      hasMore = toBooleanLike(
        firstDefined(container.has_more, container.hasMore, container.has_next, container.hasNext, container.more)
      );
    }
    if (nextOffset === undefined) {
      nextOffset = nonNegativeIntegerOrUndefined(
        firstDefined(container.next_offset, container.nextOffset, container.next_page_offset, container.nextPageOffset)
      );
    }
  }
  if (returned === undefined) {
    returned = entries.length;
  }
  if (nextOffset === undefined && returned !== undefined && offset !== undefined) {
    nextOffset = offset + returned;
  }
  if (hasMore === undefined && total !== undefined && nextOffset !== undefined) {
    hasMore = nextOffset < total;
  }
  return {
    returned,
    total,
    limit,
    offset,
    hasMore,
    nextOffset
  };
}

function formatAuditRecentDisplayPayload(result, request) {
  const page = extractAuditRecentPageInfo(result);
  const auditPage = compactObject({
    returned: page.returned,
    total: page.total,
    limit: page.limit,
    offset: page.offset,
    has_more: page.hasMore,
    next_offset: page.nextOffset
  });
  const requestPage = compactObject({
    limit: request.limit,
    offset: request.offset,
    event: request.event,
    wallet_address: request.wallet_address,
    order: request.order
  });
  if (result && typeof result === "object" && !Array.isArray(result)) {
    return {
      ...result,
      ...(Object.keys(auditPage).length > 0 ? { audit_page: auditPage } : {}),
      request_page: requestPage
    };
  }
  const payload = {
    result,
    request_page: requestPage
  };
  if (Object.keys(auditPage).length > 0) {
    payload.audit_page = auditPage;
  }
  return payload;
}

function normalizeTrimmedStringArray(value) {
  if (Array.isArray(value)) {
    return value
      .map((entry) => (typeof entry === "string" ? entry.trim() : ""))
      .filter((entry) => entry.length > 0);
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed ? [trimmed] : [];
  }
  return [];
}

function parseServerReadiness(payload) {
  const readiness = payload?.readiness;
  if (!readiness || typeof readiness !== "object") {
    return null;
  }
  const unlockActionsRaw = firstDefined(readiness.unlock_actions, readiness.unlockActions);
  const unlockActions = Array.isArray(unlockActionsRaw)
    ? unlockActionsRaw
        .map((entry) => (typeof entry === "string" ? entry.trim() : ""))
        .filter((entry) => entry.length > 0)
    : [];
  const endpointPostureRaw = firstDefined(readiness.endpoint_posture, readiness.endpointPosture);
  const endpointPosture =
    endpointPostureRaw && typeof endpointPostureRaw === "object" && !Array.isArray(endpointPostureRaw)
      ? endpointPostureRaw
      : undefined;
  const endpointWarnings = [];
  for (const warning of normalizeTrimmedStringArray(firstDefined(readiness.endpoint_warnings, readiness.endpointWarnings))) {
    if (!endpointWarnings.includes(warning)) {
      endpointWarnings.push(warning);
    }
  }
  for (const warning of normalizeTrimmedStringArray(
    firstDefined(
      endpointPosture?.endpoint_warnings,
      endpointPosture?.endpointWarnings,
      endpointPosture?.warnings,
      endpointPosture?.warning
    )
  )) {
    if (!endpointWarnings.includes(warning)) {
      endpointWarnings.push(warning);
    }
  }
  const normalizedRole = typeof readiness.role === "string" ? readiness.role.trim().toLowerCase() : "";
  return {
    role: normalizedRole || undefined,
    tabVisible: toBooleanLike(firstDefined(readiness.tab_visible, readiness.tabVisible)),
    clientTabVisible: toBooleanLike(
      firstDefined(readiness.client_tab_visible, readiness.clientTabVisible, readiness.client_tab_enabled)
    ),
    lifecycleActionsUnlocked: toBooleanLike(
      firstDefined(readiness.lifecycle_actions_unlocked, readiness.lifecycleActionsUnlocked)
    ),
    serviceMutationsConfigured: toBooleanLike(
      firstDefined(readiness.service_mutations_configured, readiness.serviceMutationsConfigured)
    ),
    operatorApplicationStatus: normalizeOperatorApplicationStatus(
      firstDefined(readiness.operator_application_status, readiness.operatorApplicationStatus)
    ),
    lockReason: toDetailText(firstDefined(readiness.lock_reason, readiness.lockReason)),
    clientLockReason: toDetailText(
      firstDefined(readiness.client_lock_reason, readiness.clientLockReason, readiness.client_lock_hint)
    ),
    chainBindingStatus: toDetailText(
      firstDefined(readiness.chain_binding_status, readiness.chainBindingStatus)
    ),
    chainBindingOk: toBooleanLike(firstDefined(readiness.chain_binding_ok, readiness.chainBindingOk)),
    chainBindingReason: toDetailText(
      firstDefined(readiness.chain_binding_reason, readiness.chainBindingReason)
    ),
    clientRegistrationStatus: toDetailText(
      firstDefined(
        readiness.client_registration_status,
        readiness.clientRegistrationStatus,
        readiness.registration_status,
        readiness.registrationStatus
      )
    ),
    registrationTrustStatus: toDetailText(
      firstDefined(
        readiness.registration_trust_status,
        readiness.registrationTrustStatus,
        readiness.bootstrap_trust_status,
        readiness.bootstrapTrustStatus,
        readiness.session_bootstrap_trust_status,
        readiness.sessionBootstrapTrustStatus,
        readiness.trust_status,
        readiness.trustStatus
      )
    ),
    registrationTrustDegraded: toBooleanLike(
      firstDefined(
        readiness.registration_trust_degraded,
        readiness.registrationTrustDegraded,
        readiness.bootstrap_trust_degraded,
        readiness.bootstrapTrustDegraded,
        readiness.session_bootstrap_trust_degraded,
        readiness.sessionBootstrapTrustDegraded,
        readiness.manifest_drift_detected,
        readiness.manifestDriftDetected,
        readiness.trust_drift_detected,
        readiness.trustDriftDetected,
        readiness.trust_degraded,
        readiness.trustDegraded,
        readiness.bootstrap_trust_revoked,
        readiness.bootstrapTrustRevoked,
        readiness.session_bootstrap_revoked,
        readiness.sessionBootstrapRevoked
      )
    ),
    registrationReregisterRequired: toBooleanLike(
      firstDefined(
        readiness.re_register_required,
        readiness.reRegisterRequired,
        readiness.reregister_required,
        readiness.reregisterRequired,
        readiness.registration_refresh_required,
        readiness.registrationRefreshRequired,
        readiness.requires_reregistration,
        readiness.requiresReregistration
      )
    ),
    registrationTrustReason: toDetailText(
      firstDefined(
        readiness.registration_trust_reason,
        readiness.registrationTrustReason,
        readiness.bootstrap_trust_reason,
        readiness.bootstrapTrustReason,
        readiness.session_bootstrap_trust_reason,
        readiness.sessionBootstrapTrustReason,
        readiness.trust_reason,
        readiness.trustReason,
        readiness.manifest_drift_reason,
        readiness.manifestDriftReason,
        readiness.re_register_reason,
        readiness.reRegisterReason,
        readiness.registration_lock_reason,
        readiness.registrationLockReason
      )
    ),
    unlockActions,
    endpointWarnings,
    endpointPosture
  };
}

function setServerReadiness(readiness) {
  state.serverReadiness = readiness || null;
  if (readiness?.operatorApplicationStatus !== undefined) {
    state.operatorApplicationStatus = readiness.operatorApplicationStatus;
  }
  if (readiness) {
    setClientRegistrationStateFromPayload({ readiness }, { allowFallback: false, preserveWhenUnknown: true });
  }
  syncServerRoleLockState();
}

function isServerTabVisibleRole(role = state.role) {
  if (state.serverReadiness && typeof state.serverReadiness.tabVisible === "boolean") {
    return state.serverReadiness.tabVisible;
  }
  const normalized = (state.serverReadiness?.role || role || "client").toLowerCase();
  return normalized === "operator" || normalized === "admin" || normalized === "server" || normalized === "server_only";
}

function isClientTabVisibleRole(role = state.role) {
  if (state.serverReadiness && typeof state.serverReadiness.clientTabVisible === "boolean") {
    return state.serverReadiness.clientTabVisible;
  }
  const normalized = (state.serverReadiness?.role || role || "client").toLowerCase();
  if (normalized === "server" || normalized === "server_only") {
    return false;
  }
  if (normalized === "operator" || normalized === "admin") {
    return !!state.clientRegistered;
  }
  return true;
}

function isServerMutationRoleEligible(role = state.role, operatorApplicationStatus = state.operatorApplicationStatus) {
  if (state.serverReadiness && typeof state.serverReadiness.lifecycleActionsUnlocked === "boolean") {
    return state.serverReadiness.lifecycleActionsUnlocked;
  }
  const normalized = (state.serverReadiness?.role || role || "client").toLowerCase();
  const effectiveOperatorStatus = state.serverReadiness?.operatorApplicationStatus || operatorApplicationStatus;
  if (normalized === "admin") {
    return true;
  }
  if (normalized === "server" || normalized === "server_only") {
    return true;
  }
  if (normalized === "operator") {
    return effectiveOperatorStatus === "approved";
  }
  return false;
}

function setDesktopStepState(el, value) {
  if (!el) {
    return;
  }
  el.dataset.state = value;
}

function formatDirectActionGuidance(directPath, requiredConditions) {
  return `Direct path: ${directPath}. Required conditions: ${requiredConditions}.`;
}

function effectiveDesktopOperatorApplicationStatus() {
  return normalizeOperatorApplicationStatus(
    state.serverReadiness?.operatorApplicationStatus || state.operatorApplicationStatus
  );
}

function computeDesktopNextRecommendedAction() {
  const role = (state.serverReadiness?.role || state.role || "client").toLowerCase();
  if (!state.sessionToken) {
    const challengeId = challengeIdEl.value.trim();
    const signature = walletSignatureEl.value.trim();
    if (!challengeId) {
      return "Request Challenge.";
    }
    if (!signature) {
      return "Use Wallet Sign-In (Recommended) or provide a manual signature.";
    }
    return "Use Sign In to verify and create a session.";
  }

  const sessionFreshness = computeSessionFreshnessState();
  if (sessionFreshness.state === "expired") {
    return "Use Wallet Sign-In (Recommended) or Sign In to re-authenticate.";
  }
  if (sessionFreshness.state === "expiring_soon") {
    return "Rotate Session.";
  }
  if (sessionFreshness.state === "unknown") {
    return "Run Session to validate session freshness.";
  }

  if (state.clientRegistrationTrustDegraded || state.clientRegistrationReregisterRequired) {
    if (isClientLaneRoleLocked(role, state.serverReadiness)) {
      return "Client lane is role-locked for this session. Continue in server/operator readiness checks.";
    }
    return "Register Client.";
  }
  if (!state.clientRegistered) {
    if (isClientLaneRoleLocked(role, state.serverReadiness)) {
      return "Client lane is role-locked for this session. Continue in server/operator readiness checks.";
    }
    return "Register Client.";
  }

  const operatorStatus = effectiveDesktopOperatorApplicationStatus();
  if (operatorStatus === "pending") {
    return "Wait for operator approval, then run Session or Operator Status.";
  }
  if (operatorStatus === "rejected") {
    return "Apply Operator Role again after updating operator details.";
  }
  if (operatorStatus !== "approved" && role !== "admin" && role !== "server" && role !== "server_only") {
    return "Apply Operator Role.";
  }
  if (state.serverReadiness?.lifecycleActionsUnlocked === false) {
    return "Run Session and Operator Status to refresh Step 3 readiness.";
  }
  return "Continue in Client or Server controls based on your role.";
}

function computeDesktopOnboardingBannerState() {
  if (!state.sessionToken) {
    const challengeId = challengeIdEl.value.trim();
    const signature = walletSignatureEl.value.trim();
    if (!challengeId) {
      return {
        state: "warn",
        title: "Signed out",
        detail: "No active session token is loaded."
      };
    }
    if (!signature) {
      return {
        state: "warn",
        title: "Signed out",
        detail: "Challenge is ready, but signature verification is still pending."
      };
    }
    return {
      state: "warn",
      title: "Signed out",
      detail: "Challenge and signature are ready, but session verification is still pending."
    };
  }

  const sessionFreshness = computeSessionFreshnessState();
  if (sessionFreshness.state === "expired") {
    return {
      state: "bad",
      title: "Session expired",
      detail: sessionFreshness.detail
    };
  }
  if (sessionFreshness.state === "expiring_soon") {
    return {
      state: "warn",
      title: "Session expiring soon",
      detail: sessionFreshness.detail
    };
  }
  if (sessionFreshness.state === "unknown") {
    return {
      state: "warn",
      title: "Session expiry unknown",
      detail: sessionFreshness.detail
    };
  }

  const clientLaneRoleLocked = isClientLaneRoleLocked(
    (state.serverReadiness?.role || state.role || "client").toLowerCase(),
    state.serverReadiness
  );
  const operatorStatus = effectiveDesktopOperatorApplicationStatus();
  if (operatorStatus === "pending") {
    return {
      state: "warn",
      title: "Operator pending",
      detail: `${sessionFreshness.detail} Operator approval is pending.`
    };
  }
  if (operatorStatus === "approved") {
    return {
      state: "good",
      title: "Operator approved",
      detail: `${sessionFreshness.detail} Operator approval is complete.`
    };
  }
  if (operatorStatus === "rejected") {
    return {
      state: "bad",
      title: "Operator rejected",
      detail: `${sessionFreshness.detail} Operator application was rejected.`
    };
  }
  return {
    state: "good",
    title: "Session active",
    detail: clientLaneRoleLocked
      ? `${sessionFreshness.detail} Continue with operator/server workflow for this role.`
      : `${sessionFreshness.detail} Continue with client registration and operator onboarding.`
  };
}

function syncDesktopOnboardingBanner() {
  if (
    !desktopOnboardingBannerEl ||
    !desktopOnboardingStateEl ||
    !desktopOnboardingDetailEl ||
    !desktopOnboardingNextActionEl
  ) {
    return;
  }
  const onboardingState = computeDesktopOnboardingBannerState();
  desktopOnboardingBannerEl.dataset.state = onboardingState.state;
  desktopOnboardingStateEl.textContent = onboardingState.title;
  desktopOnboardingDetailEl.textContent = onboardingState.detail;
  desktopOnboardingNextActionEl.textContent = `Next recommended action: ${computeDesktopNextRecommendedAction()}`;
  syncWorkspaceNextActionHint(isClientTabVisibleRole(), isServerTabVisibleRole());
}

function inferClientRegistrationFromPayload(payload) {
  return extractBootstrapRegistrationMetadata(payload).hasBootstrapDirectory;
}

function normalizeRegistrationStatusValue(value) {
  if (typeof value !== "string") {
    return "";
  }
  return value.trim().toLowerCase();
}

function registrationStatusHasFragment(status, fragment) {
  return typeof status === "string" && status.includes(fragment);
}

function isRegistrationTrustDriftStatus(status) {
  if (!status) {
    return false;
  }
  for (const fragment of REGISTRATION_TRUST_DRIFT_STATUS_FRAGMENTS) {
    if (registrationStatusHasFragment(status, fragment)) {
      return true;
    }
  }
  return false;
}

function parseClientRegistrationStatus(payload) {
  const status = normalizeRegistrationStatusValue(
    firstDefined(
      payload?.registration?.status,
      payload?.registration?.registration_status,
      payload?.registration?.registrationStatus,
      payload?.registration_status,
      payload?.registrationStatus,
      payload?.status,
      payload?.readiness?.client_registration_status,
      payload?.readiness?.clientRegistrationStatus,
      payload?.readiness?.registration_status,
      payload?.readiness?.registrationStatus
    )
  );
  if (!status) {
    return undefined;
  }
  if (
    status === "registered" ||
    status === "ready" ||
    status === "active" ||
    status === "trusted" ||
    status === "ok"
  ) {
    return true;
  }
  if (
    status === "not_registered" ||
    status === "not registered" ||
    status === "unregistered" ||
    status === "missing" ||
    status === "registration_required" ||
    status === "required" ||
    status.endsWith("_required") ||
    registrationStatusHasFragment(status, "reregister") ||
    registrationStatusHasFragment(status, "re_register") ||
    isRegistrationTrustDriftStatus(status)
  ) {
    return false;
  }
  if (status.endsWith("_registered") && status !== "not_registered") {
    return true;
  }
  if (registrationStatusHasFragment(status, "registered")) {
    return true;
  }
  return undefined;
}

function parseClientRegistrationTrustState(payload) {
  const registration = payload?.registration;
  const readiness = payload?.readiness;
  const registrationStatus = normalizeRegistrationStatusValue(
    firstDefined(
      registration?.status,
      registration?.registration_status,
      registration?.registrationStatus,
      payload?.registration_status,
      payload?.registrationStatus,
      payload?.status,
      readiness?.client_registration_status,
      readiness?.clientRegistrationStatus,
      readiness?.registration_status,
      readiness?.registrationStatus
    )
  );
  const trustStatusRaw = toDetailText(
    firstDefined(
      registration?.registration_trust_status,
      registration?.registrationTrustStatus,
      registration?.bootstrap_trust_status,
      registration?.bootstrapTrustStatus,
      registration?.session_bootstrap_trust_status,
      registration?.sessionBootstrapTrustStatus,
      registration?.trust_status,
      registration?.trustStatus,
      readiness?.registration_trust_status,
      readiness?.registrationTrustStatus,
      readiness?.bootstrap_trust_status,
      readiness?.bootstrapTrustStatus,
      readiness?.session_bootstrap_trust_status,
      readiness?.sessionBootstrapTrustStatus,
      readiness?.trust_status,
      readiness?.trustStatus
    )
  );
  const trustStatus = normalizeRegistrationStatusValue(trustStatusRaw);
  const trustDegradedRaw = toBooleanLike(
    firstDefined(
      registration?.registration_trust_degraded,
      registration?.registrationTrustDegraded,
      registration?.bootstrap_trust_degraded,
      registration?.bootstrapTrustDegraded,
      registration?.session_bootstrap_trust_degraded,
      registration?.sessionBootstrapTrustDegraded,
      registration?.manifest_drift_detected,
      registration?.manifestDriftDetected,
      registration?.trust_drift_detected,
      registration?.trustDriftDetected,
      registration?.trust_degraded,
      registration?.trustDegraded,
      registration?.bootstrap_trust_revoked,
      registration?.bootstrapTrustRevoked,
      registration?.session_bootstrap_revoked,
      registration?.sessionBootstrapRevoked,
      readiness?.registration_trust_degraded,
      readiness?.registrationTrustDegraded,
      readiness?.bootstrap_trust_degraded,
      readiness?.bootstrapTrustDegraded,
      readiness?.session_bootstrap_trust_degraded,
      readiness?.sessionBootstrapTrustDegraded,
      readiness?.manifest_drift_detected,
      readiness?.manifestDriftDetected,
      readiness?.trust_drift_detected,
      readiness?.trustDriftDetected,
      readiness?.trust_degraded,
      readiness?.trustDegraded,
      readiness?.bootstrap_trust_revoked,
      readiness?.bootstrapTrustRevoked,
      readiness?.session_bootstrap_revoked,
      readiness?.sessionBootstrapRevoked
    )
  );
  const reRegisterRequiredRaw = toBooleanLike(
    firstDefined(
      registration?.re_register_required,
      registration?.reRegisterRequired,
      registration?.reregister_required,
      registration?.reregisterRequired,
      registration?.registration_refresh_required,
      registration?.registrationRefreshRequired,
      registration?.requires_reregistration,
      registration?.requiresReregistration,
      readiness?.re_register_required,
      readiness?.reRegisterRequired,
      readiness?.reregister_required,
      readiness?.reregisterRequired,
      readiness?.registration_refresh_required,
      readiness?.registrationRefreshRequired,
      readiness?.requires_reregistration,
      readiness?.requiresReregistration
    )
  );
  const trustReason =
    toDetailText(
      firstDefined(
        registration?.registration_trust_reason,
        registration?.registrationTrustReason,
        registration?.bootstrap_trust_reason,
        registration?.bootstrapTrustReason,
        registration?.session_bootstrap_trust_reason,
        registration?.sessionBootstrapTrustReason,
        registration?.trust_reason,
        registration?.trustReason,
        registration?.manifest_drift_reason,
        registration?.manifestDriftReason,
        registration?.re_register_reason,
        registration?.reRegisterReason,
        registration?.registration_lock_reason,
        registration?.registrationLockReason,
        readiness?.registration_trust_reason,
        readiness?.registrationTrustReason,
        readiness?.bootstrap_trust_reason,
        readiness?.bootstrapTrustReason,
        readiness?.session_bootstrap_trust_reason,
        readiness?.sessionBootstrapTrustReason,
        readiness?.trust_reason,
        readiness?.trustReason,
        readiness?.manifest_drift_reason,
        readiness?.manifestDriftReason,
        readiness?.re_register_reason,
        readiness?.reRegisterReason,
        readiness?.registration_lock_reason,
        readiness?.registrationLockReason,
        registration?.client_lock_reason,
        registration?.clientLockReason,
        readiness?.client_lock_reason,
        readiness?.clientLockReason
      )
    ) ||
    "";
  const statusDrift = isRegistrationTrustDriftStatus(trustStatus);
  const registrationStatusDrift =
    isRegistrationTrustDriftStatus(registrationStatus) ||
    registrationStatusHasFragment(registrationStatus, "reregister") ||
    registrationStatusHasFragment(registrationStatus, "re_register");
  const trustDegraded = trustDegradedRaw === true || statusDrift || registrationStatusDrift;
  const reRegisterRequired =
    reRegisterRequiredRaw === true ||
    trustDegraded ||
    registrationStatusHasFragment(registrationStatus, "reregister") ||
    registrationStatusHasFragment(registrationStatus, "re_register") ||
    registrationStatusHasFragment(registrationStatus, "required") ||
    registrationStatusHasFragment(trustStatus, "reregister") ||
    registrationStatusHasFragment(trustStatus, "re_register");
  const hasSignals =
    registrationStatusDrift ||
    trustStatus.length > 0 ||
    trustDegradedRaw !== undefined ||
    reRegisterRequiredRaw !== undefined ||
    trustReason.length > 0;
  return {
    hasSignals,
    trustDegraded,
    reRegisterRequired,
    trustReason,
    trustStatus
  };
}

function clearClientRegistrationTrustState() {
  state.clientRegistrationTrustDegraded = false;
  state.clientRegistrationReregisterRequired = false;
  state.clientRegistrationTrustReason = "";
  state.clientRegistrationTrustStatus = "";
}

function setClientRegistrationStateFromPayload(payload, options = {}) {
  const { allowFallback = true, preserveWhenUnknown = false } = options;
  const parsedStatus = parseClientRegistrationStatus(payload);
  const trustState = parseClientRegistrationTrustState(payload);
  let registrationResolved = parsedStatus;
  if (trustState.trustDegraded || trustState.reRegisterRequired) {
    registrationResolved = false;
  } else if (registrationResolved === undefined && allowFallback) {
    registrationResolved = inferClientRegistrationFromPayload(payload);
  }
  if (registrationResolved !== undefined) {
    state.clientRegistered = !!registrationResolved;
  } else if (!preserveWhenUnknown) {
    state.clientRegistered = false;
  }
  if (trustState.hasSignals || !preserveWhenUnknown) {
    state.clientRegistrationTrustDegraded = trustState.trustDegraded;
    state.clientRegistrationReregisterRequired = trustState.reRegisterRequired;
    state.clientRegistrationTrustReason = trustState.trustReason;
    state.clientRegistrationTrustStatus = trustState.trustStatus;
  }
  ingestSessionBootstrapDirectoryOptionsFromPayload(payload);
}

function clientRegistrationTrustHintText() {
  const baseReason =
    state.clientRegistrationTrustReason ||
    "Session bootstrap trust has drifted from the current trusted manifest.";
  if (/\bre-?register\b/i.test(baseReason)) {
    return baseReason;
  }
  return `${baseReason} Re-register client profile to refresh trusted bootstrap directories before connecting.`;
}

function syncDesktopOnboardingSteps() {
  const sessionFreshness = computeSessionFreshnessState();
  const hasSession = !!state.sessionToken && sessionFreshness.state !== "expired";
  const backendReadiness = state.serverReadiness;
  const role = (backendReadiness?.role || state.role || "client").toLowerCase();
  const clientLaneRoleLocked = isClientLaneRoleLocked(role, backendReadiness);
  const operatorStatus = backendReadiness?.operatorApplicationStatus || state.operatorApplicationStatus;
  const operatorReady =
    typeof backendReadiness?.lifecycleActionsUnlocked === "boolean"
      ? backendReadiness.lifecycleActionsUnlocked
      : role === "admin" || (role === "operator" && operatorStatus === "approved");

  if (!hasSession) {
    setDesktopStepState(desktopStepSessionEl, "active");
    setDesktopStepState(desktopStepClientEl, "blocked");
    setDesktopStepState(desktopStepOperatorEl, "blocked");
    return;
  }

  setDesktopStepState(desktopStepSessionEl, "done");
  if (clientLaneRoleLocked) {
    setDesktopStepState(desktopStepClientEl, "blocked");
  } else if (!state.clientRegistered) {
    setDesktopStepState(desktopStepClientEl, "active");
    setDesktopStepState(desktopStepOperatorEl, "blocked");
    return;
  } else {
    setDesktopStepState(desktopStepClientEl, "done");
  }
  if (operatorReady) {
    setDesktopStepState(desktopStepOperatorEl, "done");
    return;
  }
  if (
    operatorStatus === "rejected" ||
    (backendReadiness && backendReadiness.tabVisible === false)
  ) {
    setDesktopStepState(desktopStepOperatorEl, "blocked");
    return;
  }
  setDesktopStepState(desktopStepOperatorEl, "active");
}

function syncServerMutationControls() {
  const serviceMutationsConfigured = state.serverReadiness?.serviceMutationsConfigured !== false;
  const mutationsEnabled =
    state.serviceMutationsAllowed && serviceMutationsConfigured && isServerMutationRoleEligible();
  setProfileBtnEl.disabled = !mutationsEnabled;
  serviceStartBtnEl.disabled = !mutationsEnabled;
  serviceStopBtnEl.disabled = !mutationsEnabled;
  serviceRestartBtnEl.disabled = !mutationsEnabled;
}

function appendReadinessDiagnosticsHint(baseHint, readiness) {
  const warnings = Array.isArray(readiness?.endpointWarnings) ? readiness.endpointWarnings : [];
  if (warnings.length === 0) {
    return baseHint;
  }
  const summarized = warnings.slice(0, 3).join("; ");
  const remaining = warnings.length - 3;
  const suffix = remaining > 0 ? `; +${remaining} more` : "";
  return `${baseHint} Diagnostics: ${summarized}${suffix}`;
}

function chainBindingActionHint(statusKey, ok) {
  if (statusKey === "mismatch") {
    return "Next: refresh session to resync chain_operator_id; if mismatch persists, re-apply and re-approve with the intended chain_operator_id.";
  }
  if (statusKey === "pending_approval" || statusKey === "pending approval") {
    return "Next: wait for operator approval, then refresh session to lift server lifecycle locks.";
  }
  if (ok === false) {
    return "Next: refresh session and operator status to reconcile strict chain binding.";
  }
  return "";
}

function appendChainBindingHint(baseHint, readiness) {
  const statusRaw = typeof readiness?.chainBindingStatus === "string" ? readiness.chainBindingStatus.trim() : "";
  const statusKey = statusRaw.toLowerCase();
  const status = statusRaw ? statusRaw.replace(/[_-]+/g, " ") : "";
  const ok = readiness?.chainBindingOk;
  const reason = typeof readiness?.chainBindingReason === "string" ? readiness.chainBindingReason.trim() : "";
  if (!status && ok === undefined && !reason) {
    return baseHint;
  }
  let bindingHint = "";
  if (ok === true) {
    bindingHint =
      statusKey === "bound"
        ? "Chain binding: bound. Strict chain binding is satisfied (session/app chain_operator_id match)."
        : status
          ? `Chain binding: ${status}. Strict chain binding is satisfied.`
          : "Chain binding: ready. Strict chain binding is satisfied.";
  } else if (ok === false) {
    bindingHint =
      status
        ? `Chain binding: ${status}. Strict chain binding requires both session and approved-application chain_operator_id values to be present and matching.`
        : "Chain binding: not ready. Strict chain binding requires both session and approved-application chain_operator_id values to be present and matching.";
  } else {
    bindingHint = status ? `Chain binding: ${status}.` : "Chain binding: unknown.";
  }
  if (reason) {
    bindingHint = `${bindingHint} ${reason}`;
  }
  const actionHint = chainBindingActionHint(statusKey, ok);
  if (actionHint) {
    bindingHint = `${bindingHint} ${actionHint}`;
  }
  return `${baseHint} ${bindingHint}`;
}

function computeServerLockHintText() {
  if (state.serverReadiness) {
    const readiness = state.serverReadiness;
    let hintText;
    if (readiness.lifecycleActionsUnlocked === true) {
      if (!state.serviceMutationsAllowed) {
        hintText =
          "Server role is unlocked by backend readiness, but service lifecycle actions are disabled by environment policy.";
      } else if (readiness.serviceMutationsConfigured === false) {
        hintText = "Server role is unlocked, but service lifecycle commands are not configured in the daemon.";
      } else {
        hintText = "Server controls are unlocked by backend readiness policy.";
      }
    } else {
      const reason = readiness.lockReason || "Server lifecycle actions are locked by backend readiness policy.";
      const requiredConditions =
        readiness.unlockActions.length > 0
          ? readiness.unlockActions.join("; ")
          : "approved operator application and matching session/application chain_operator_id values";
      hintText = `${reason} ${formatDirectActionGuidance(
        "Use Apply Operator Role or Operator Status, then refresh Session",
        requiredConditions
      )}`;
    }
    return appendReadinessDiagnosticsHint(appendChainBindingHint(hintText, readiness), readiness);
  }
  if (!state.sessionToken) {
    return `Sign in first to unlock server onboarding. ${formatDirectActionGuidance(
      "Request Challenge, then run Wallet Sign-In or Sign In",
      "an active session token"
    )}`;
  }
  const role = (state.role || "client").toLowerCase();
  if (role === "admin") {
    if (!state.serviceMutationsAllowed) {
      return "Server tab is available. Service lifecycle actions are disabled by environment policy.";
    }
    return "Server controls are unlocked for admin role.";
  }
  if (role === "operator") {
    if (state.operatorApplicationStatus === "approved") {
      if (!state.serviceMutationsAllowed) {
        return "Operator approved. Service lifecycle actions are disabled by environment policy; strict chain binding still requires matching session/application chain_operator_id values.";
      }
      return "Operator approved. Final unlock still requires strict chain binding (matching session/application chain_operator_id); refresh server readiness to confirm.";
    }
    if (state.operatorApplicationStatus === "pending") {
      return `Operator application pending approval. ${formatDirectActionGuidance(
        "Wait for approval, then run Session",
        "approved operator application and matching session/application chain_operator_id values"
      )}`;
    }
    if (state.operatorApplicationStatus === "rejected") {
      return `Operator application rejected. ${formatDirectActionGuidance(
        "Apply Operator Role again and refresh Session",
        "approved operator application and matching session/application chain_operator_id values"
      )}`;
    }
    if (state.operatorApplicationStatus === "not_submitted") {
      return `Operator role detected with no approved application. ${formatDirectActionGuidance(
        "Apply Operator Role",
        "approved operator application and matching session/application chain_operator_id values"
      )}`;
    }
    return `Operator role detected. ${formatDirectActionGuidance(
      "Check Operator Status, then refresh Session after approval",
      "approved operator application and matching session/application chain_operator_id values"
    )}`;
  }
  if (role === "server" || role === "server_only") {
    if (!state.serviceMutationsAllowed) {
      return "Server-only role detected. Service lifecycle actions are disabled by environment policy.";
    }
    return "Server controls are unlocked for server-only role.";
  }
  return `Server lane is locked for this role. ${formatDirectActionGuidance(
    "Apply Operator Role",
    "approved operator application and matching session/application chain_operator_id values"
  )}`;
}

function computeClientLockHintText() {
  if (state.clientRegistrationTrustDegraded || state.clientRegistrationReregisterRequired) {
    return clientRegistrationTrustHintText();
  }
  if (state.serverReadiness) {
    const readiness = state.serverReadiness;
    if (readiness.clientTabVisible === false) {
      const reason = readiness.clientLockReason || "Client controls are locked by backend readiness policy for this role.";
      return `${reason} ${formatDirectActionGuidance(
        "Use Register Client when the role allows client lane access",
        "client-capable role with an active session token"
      )}`;
    }
    if (readiness.clientTabVisible === true) {
      if (state.connectRequireSession && !state.sessionToken) {
        return "Client controls are unlocked. Sign in to connect while session-required mode is enabled.";
      }
      return "Client controls are unlocked by backend readiness policy.";
    }
  }
  if (!isClientTabVisibleRole()) {
    const role = (state.serverReadiness?.role || state.role || "client").toLowerCase();
    if (!state.sessionToken) {
      return "Sign in first to unlock client controls.";
    }
    if ((role === "operator" || role === "admin") && !state.clientRegistered) {
      return `Server-capable session detected. ${formatDirectActionGuidance(
        "Register Client",
        "active session token and successful client registration"
      )}`;
    }
    if (role === "server" || role === "server_only") {
      return `Client controls are disabled for server-only role. ${formatDirectActionGuidance(
        "Continue in Server lane",
        "operator/server readiness in Step 3"
      )}`;
    }
    return "Client controls are locked by current role policy.";
  }
  const role = (state.serverReadiness?.role || state.role || "client").toLowerCase();
  if ((role === "operator" || role === "admin") && state.clientRegistered) {
    return "Client controls are unlocked for dual-role operation.";
  }
  if (state.connectRequireSession && !state.sessionToken) {
    return "Client controls are available. Sign in to connect while session-required mode is enabled.";
  }
  return "Client controls are available for client-capable roles.";
}

function ensureSentence(value) {
  const normalized = typeof value === "string" ? value.trim() : "";
  if (!normalized) {
    return "";
  }
  if (/[.!?]$/.test(normalized)) {
    return normalized;
  }
  return `${normalized}.`;
}

function isWindowsRuntimePlatform() {
  const platform = String(
    firstDefined(navigator.userAgentData && navigator.userAgentData.platform, navigator.platform, navigator.userAgent) || ""
  ).toLowerCase();
  return platform.includes("win");
}

function formatWorkspaceTabAvailabilityHint(clientTabVisible, serverTabVisible) {
  if (clientTabVisible && serverTabVisible) {
    return "Both Client and Server tabs are available for this session.";
  }
  if (!clientTabVisible && !serverTabVisible) {
    return "Client and Server tabs are disabled by role/readiness policy. Use the lock message activation paths before retrying.";
  }
  if (!clientTabVisible) {
    return "Client tab is disabled for this session. Use the lock message activation path to finish Step 2 and unlock client actions.";
  }
  return "Server tab is disabled for this session. Use the lock message activation path to finish Step 3 and unlock server actions.";
}

function syncWorkspaceNextActionHint(clientTabVisible, serverTabVisible) {
  if (!workspaceNextActionHintEl) {
    return;
  }
  const nextAction = ensureSentence(computeDesktopNextRecommendedAction());
  const lockContext =
    !clientTabVisible || !serverTabVisible
      ? ` ${formatWorkspaceTabAvailabilityHint(clientTabVisible, serverTabVisible)}`
      : "";
  workspaceNextActionHintEl.textContent = `Workspace next action: ${nextAction}${lockContext}`;
  workspaceNextActionHintEl.classList.toggle("locked", !clientTabVisible || !serverTabVisible);
}

function syncWorkspaceFirstRunHints(clientTabVisible, serverTabVisible) {
  if (workspaceFirstRunHintEl) {
    workspaceFirstRunHintEl.textContent =
      `Single-window tabs keep both lanes visible. ${formatWorkspaceTabAvailabilityHint(clientTabVisible, serverTabVisible)}`;
    workspaceFirstRunHintEl.classList.toggle("locked", !clientTabVisible || !serverTabVisible);
  }
  if (workspacePlatformHintEl) {
    workspacePlatformHintEl.textContent = isWindowsRuntimePlatform()
      ? "Windows-native first run: verify local GPM/WireGuard readiness, sign in, run Session, then run Status before Connect. Use Operator Status and Service Status before server lifecycle actions."
      : "First run: verify local GPM readiness, sign in, run Session, then run Status before Connect. Use Operator Status and Service Status before server lifecycle actions.";
  }
  syncWorkspaceNextActionHint(clientTabVisible, serverTabVisible);
}

function inferTabActivationPathHint(tabName, reason) {
  const normalizedReason = typeof reason === "string" ? reason : "";
  const directPathMatch = normalizedReason.match(/Direct path:\s*([^.;]+)\s*[.;]?/i);
  if (directPathMatch && directPathMatch[1]) {
    return directPathMatch[1].trim();
  }
  if (tabName === "client") {
    if (!state.sessionToken) {
      return "Request Challenge, complete Wallet Sign-In or Sign In, then Register Client";
    }
    return "Register Client to unlock client-capable session controls";
  }
  if (!state.sessionToken) {
    return "Request Challenge, complete Wallet Sign-In or Sign In, then Apply Operator Role";
  }
  return "Apply Operator Role, wait for approval, then refresh Session or Operator Status";
}

function formatLockedTabMessage(tabName, reason) {
  const normalizedReason = ensureSentence(reason) || `${tabName} tab is currently locked by role policy.`;
  const activationPath = ensureSentence(inferTabActivationPathHint(tabName.toLowerCase(), normalizedReason));
  return `${tabName} tab is disabled for this session. Lock reason: ${normalizedReason} Activation path: ${activationPath}`;
}

function syncTabLockHint(clientTabVisible, serverTabVisible, clientReason, serverReason) {
  if (!tabLockHintEl) {
    return;
  }
  const lockMessages = [];
  if (!clientTabVisible && clientReason) {
    lockMessages.push(formatLockedTabMessage("Client", clientReason));
  }
  if (!serverTabVisible && serverReason) {
    lockMessages.push(formatLockedTabMessage("Server", serverReason));
  }
  if (lockMessages.length === 0) {
    tabLockHintEl.textContent = "";
    tabLockHintEl.hidden = true;
    return;
  }
  const headline = lockMessages.length > 1 ? "Role locks active." : "Role lock active.";
  tabLockHintEl.textContent = `${headline} ${lockMessages.join(" ")}`;
  tabLockHintEl.hidden = false;
}

function syncServerRoleLockState() {
  const clientTabVisible = isClientTabVisibleRole();
  const serverTabVisible = isServerTabVisibleRole();
  const clientReason = computeClientLockHintText();
  const serverReason = computeServerLockHintText();
  const clientLockedMessage = formatLockedTabMessage("Client", clientReason);
  const serverLockedMessage = formatLockedTabMessage("Server", serverReason);

  tabClientEl.disabled = !clientTabVisible;
  tabClientEl.classList.toggle("locked", !clientTabVisible);
  panelClientEl.classList.toggle("locked", !clientTabVisible);
  tabClientEl.setAttribute("aria-disabled", clientTabVisible ? "false" : "true");
  tabClientEl.title = clientTabVisible ? "Open Client workspace." : clientLockedMessage;
  tabClientEl.setAttribute(
    "aria-label",
    clientTabVisible ? "Client workspace tab." : `Client workspace tab locked. ${clientLockedMessage}`
  );
  if (!clientTabVisible && tabLockHintEl) {
    tabClientEl.setAttribute("aria-describedby", "tab_lock_hint");
  } else {
    tabClientEl.removeAttribute("aria-describedby");
  }

  tabServerEl.disabled = !serverTabVisible;
  tabServerEl.classList.toggle("locked", !serverTabVisible);
  panelServerEl.classList.toggle("locked", !serverTabVisible);
  tabServerEl.setAttribute("aria-disabled", serverTabVisible ? "false" : "true");
  tabServerEl.title = serverTabVisible ? "Open Server workspace." : serverLockedMessage;
  tabServerEl.setAttribute(
    "aria-label",
    serverTabVisible ? "Server workspace tab." : `Server workspace tab locked. ${serverLockedMessage}`
  );
  if (!serverTabVisible && tabLockHintEl) {
    tabServerEl.setAttribute("aria-describedby", "tab_lock_hint");
  } else {
    tabServerEl.removeAttribute("aria-describedby");
  }

  const clientTabActive = tabClientEl.classList.contains("active");
  const serverTabActive = tabServerEl.classList.contains("active");
  if ((clientTabActive && !clientTabVisible) || (serverTabActive && !serverTabVisible)) {
    if (clientTabVisible) {
      activateTab("client");
    } else if (serverTabVisible) {
      activateTab("server");
    }
  }
  syncServerMutationControls();
  if (clientLockHintEl) {
    clientLockHintEl.textContent = clientReason;
    clientLockHintEl.classList.toggle("locked", !clientTabVisible);
  }
  serverLockHintEl.textContent = serverReason;
  serverLockHintEl.classList.toggle("locked", !serverTabVisible);
  syncTabLockHint(clientTabVisible, serverTabVisible, clientReason, serverReason);
  syncWorkspaceFirstRunHints(clientTabVisible, serverTabVisible);
  syncConnectActionButtons();
  syncDesktopOnboardingSteps();
  syncDesktopOnboardingBanner();
  updateOperatorApprovalPolicyHint();
}

function setRole(role, options = {}) {
  const { persist = true } = options;
  const normalized = (role || "client").toLowerCase();
  state.role = normalized;
  currentRoleEl.value = normalized;
  if (persist) {
    writePersistedValue(STORAGE_KEYS.role, normalized);
  }
  syncServerRoleLockState();
}

function setSessionToken(value, options = {}) {
  const { persist = true } = options;
  const nextValue = (value || "").trim();
  if (state.sessionToken !== nextValue) {
    state.operatorApplicationStatus = undefined;
    setSelectedApplicationUpdatedAt("", { persist });
    state.serverReadiness = null;
    state.clientRegistered = false;
    clearClientRegistrationTrustState();
    clearOperatorListPaginationState();
    state.sessionBootstrapDirectoryOptions = [];
    state.readinessHeartbeatInFlight = false;
    state.readinessFreshnessLastAttemptMs = 0;
    state.readinessFreshnessLastUpdatedMs = 0;
    state.readinessFreshnessLastError = "";
    markSessionFreshnessUnknownForToken(nextValue);
  }
  state.sessionToken = nextValue;
  if (!state.sessionToken) {
    clearSessionFreshnessTelemetry();
  }
  sessionTokenEl.value = state.sessionToken;
  if (persist) {
    clearLegacySecretStorage();
  }
  syncSessionBootstrapDirectoryOptions();
  syncServerRoleLockState();
  syncOperatorListPaginationControlState();
  syncReadinessFreshnessIndicator();
}

function setOperatorApplicationStatus(value) {
  state.operatorApplicationStatus = normalizeOperatorApplicationStatus(value);
  syncServerRoleLockState();
}

function restorePersistedSessionErgonomics() {
  clearLegacySecretStorage();
  restoreSelectValue(walletProviderEl, readPersistedValue(STORAGE_KEYS.walletProvider));
  walletAddressEl.value = readPersistedValue(STORAGE_KEYS.walletAddress) || "";
  chainOperatorIdEl.value = readPersistedValue(STORAGE_KEYS.chainOperatorId) || "";
  restoreSelectValue(pathProfileEl, readPersistedValue(STORAGE_KEYS.pathProfile));
  setSessionToken("", { persist: false });
  setRole(readPersistedValue(STORAGE_KEYS.role) || "client", { persist: false });
  setSelectedApplicationUpdatedAt(readPersistedValue(STORAGE_KEYS.selectedApplicationUpdatedAt) || "", {
    persist: false
  });
}

function requireSessionToken(actionLabel) {
  if (!state.sessionToken) {
    print("validation", `session_token is required to ${actionLabel}; sign in first`);
    return false;
  }
  return true;
}

function isClientLaneRoleLocked(role = state.role, readiness = state.serverReadiness) {
  const normalized = (readiness?.role || role || "client").toLowerCase();
  if (normalized === "server" || normalized === "server_only") {
    return true;
  }
  return readiness?.clientTabVisible === false && normalized !== "operator" && normalized !== "admin";
}

function requireClientControlEligibility(actionLabel) {
  if (isClientTabVisibleRole()) {
    return true;
  }
  const reason = computeClientLockHintText();
  print("validation", `${actionLabel} is unavailable: ${reason}`);
  return false;
}

function requireServerTabEligibility(actionLabel) {
  if (isServerTabVisibleRole()) {
    return true;
  }
  const reason = computeServerLockHintText();
  print("validation", `${actionLabel} is unavailable: ${reason}`);
  return false;
}

function requireServerLifecycleEligibility(actionLabel) {
  if (!requireServerTabEligibility(actionLabel)) {
    return false;
  }
  const serviceMutationsConfigured = state.serverReadiness?.serviceMutationsConfigured !== false;
  const mutationsEnabled =
    state.serviceMutationsAllowed && serviceMutationsConfigured && isServerMutationRoleEligible();
  if (mutationsEnabled) {
    return true;
  }
  const reason = computeServerLockHintText();
  print("validation", `${actionLabel} is unavailable: ${reason}`);
  return false;
}

function operatorModerationReason() {
  return operatorReasonEl.value.trim();
}

function selectedApplicationUpdatedAt() {
  return state.selectedApplicationUpdatedAtUtc || selectedApplicationUpdatedAtEl.value.trim();
}

function isDecisionConflictError(err) {
  const message = String(err && err.message ? err.message : err || "");
  return /\b409\b/.test(message);
}

function serviceLifecycleRequest() {
  return {
    session_token: state.sessionToken
  };
}

function setCompatOverrideEnabled(enabled) {
  const productionModeLocked = state.productionMode === true;
  const allow = !!enabled && state.allowLegacyConnectOverride && !state.connectRequireSession && !productionModeLocked;
  compatEnableEl.checked = allow;
  compatEnableEl.disabled = productionModeLocked || !state.allowLegacyConnectOverride || state.connectRequireSession;
  bootstrapDirectoryEl.disabled =
    productionModeLocked || !state.allowLegacyConnectOverride || state.connectRequireSession || !allow;
  inviteKeyEl.disabled =
    productionModeLocked || !state.allowLegacyConnectOverride || state.connectRequireSession || !allow;
  if (allow) {
    sessionBootstrapDirectoryEl.value = "";
  }
  syncSessionBootstrapDirectoryOptions();
}

function syncCompatAdvancedVisibility() {
  if (!compatAdvancedSectionEl) {
    return;
  }
  const visible = state.allowLegacyConnectOverride && !state.productionMode;
  compatAdvancedSectionEl.hidden = !visible;
  if (!visible) {
    compatAdvancedSectionEl.open = false;
  }
}

function updateCompatOverrideHint() {
  if (!compatAdvancedHintEl) {
    return;
  }
  if (state.productionMode) {
    compatAdvancedHintEl.textContent = COMPAT_ADVANCED_PRODUCTION_HINT;
    return;
  }
  if (!state.allowLegacyConnectOverride) {
    compatAdvancedHintEl.textContent = COMPAT_ADVANCED_DISABLED_HINT;
    return;
  }
  compatAdvancedHintEl.textContent = state.connectRequireSession
    ? COMPAT_ADVANCED_LOCKED_HINT
    : COMPAT_ADVANCED_DEFAULT_HINT;
}

function updateConnectPolicyHint() {
  if (!connectPolicyHintEl) {
    return;
  }
  const modeLabel = formatConnectPolicyModeLabel(state.connectPolicyMode);
  const sourceLabel = formatConnectPolicyClientSourceLabel(state.connectPolicySource);
  let postureHint = "manual bootstrap/invite fields are optional compatibility controls.";
  if (state.productionMode) {
    postureHint = "production mode is active; manual bootstrap/invite fields are hidden and locked.";
  } else if (state.connectRequireSession) {
    postureHint = "manual bootstrap/invite fields are intentionally locked by production policy.";
  } else if (!state.allowLegacyConnectOverride) {
    postureHint = "manual bootstrap/invite fields are policy-locked in this build.";
  }
  connectPolicyHintEl.textContent = `Connect policy: ${modeLabel} from ${sourceLabel}; ${postureHint}`;
  connectPolicyHintEl.classList.toggle(
    "locked",
    state.productionMode || state.connectRequireSession || !state.allowLegacyConnectOverride
  );
}

function summarizeLegacyAliasNames(aliasNames, maxVisible = 3) {
  const names = Array.isArray(aliasNames) ? aliasNames.filter((value) => typeof value === "string" && value) : [];
  if (names.length === 0) {
    return "";
  }
  if (names.length <= maxVisible) {
    return names.join(", ");
  }
  const visible = names.slice(0, maxVisible).join(", ");
  return `${visible}, +${names.length - maxVisible} more`;
}

function updateLegacyAliasRuntimeHint() {
  if (!legacyAliasRuntimeHintEl) {
    return;
  }
  const aliases = Array.isArray(state.legacyEnvAliasesActive) ? state.legacyEnvAliasesActive : [];
  const warningList = Array.isArray(state.legacyEnvAliasWarnings) ? state.legacyEnvAliasWarnings : [];
  const parsedCount = nonNegativeIntegerOrUndefined(state.legacyEnvAliasActiveCount) || 0;
  const aliasCount = Math.max(parsedCount, aliases.length);
  if (aliasCount <= 0) {
    legacyAliasRuntimeHintEl.textContent = "";
    legacyAliasRuntimeHintEl.classList.remove("locked");
    return;
  }
  const aliasSummary = summarizeLegacyAliasNames(aliases);
  let hintText = `GPM runtime detected legacy TDPN_* env aliases (${aliasCount})`;
  if (aliasSummary) {
    hintText = `${hintText}: ${aliasSummary}.`;
  } else {
    hintText = `${hintText}.`;
  }
  hintText =
    `${hintText} Migration: replace TDPN_* variables with equivalent GPM_* names ` +
    "(for example TDPN_MAIN_DOMAIN -> GPM_MAIN_DOMAIN) to stay forward-compatible.";
  if (warningList.length > 0) {
    hintText = `${hintText} ${warningList[0]}`;
  }
  legacyAliasRuntimeHintEl.textContent = hintText;
  legacyAliasRuntimeHintEl.classList.add("locked");
}

function isManualSignInLockedByRuntimePolicy() {
  return state.productionMode === true || state.authVerifyRequireWalletExtensionSource === true;
}

function manualSignInLockPolicyHintText() {
  if (state.productionMode) {
    return SIGN_IN_POLICY_PRODUCTION_LOCK_HINT;
  }
  return SIGN_IN_POLICY_RUNTIME_LOCK_HINT;
}

function manualSignInLockValidationText() {
  if (state.productionMode) {
    return SIGN_IN_VALIDATION_PRODUCTION_LOCK_HINT;
  }
  return SIGN_IN_VALIDATION_RUNTIME_LOCK_HINT;
}

function syncIdentitySignInPolicyControls() {
  const manualSignInLocked = isManualSignInLockedByRuntimePolicy();
  walletSignInBtnEl.disabled = false;
  walletSignInBtnEl.textContent = manualSignInLocked
    ? WALLET_SIGN_IN_LABEL_REQUIRED
    : WALLET_SIGN_IN_LABEL_RECOMMENDED;
  walletSignInBtnEl.title = manualSignInLocked
    ? state.productionMode
      ? "Production mode requires Wallet Sign-In."
      : "Active auth policy requires signature_source=wallet_extension."
    : "Recommended sign-in path.";
  signInBtnEl.disabled = manualSignInLocked;
  signInBtnEl.textContent = manualSignInLocked ? MANUAL_SIGN_IN_LABEL_DISABLED : MANUAL_SIGN_IN_LABEL;
  signInBtnEl.title = manualSignInLocked
    ? state.productionMode
      ? "Manual Sign In is disabled by production mode; use Wallet Sign-In."
      : "Manual Sign In is locked by active auth policy requiring signature_source=wallet_extension."
    : "Manual fallback path when policy allows manual source.";
  if (!signInPolicyHintEl) {
    return;
  }
  if (manualSignInLocked) {
    signInPolicyHintEl.textContent = manualSignInLockPolicyHintText();
    signInPolicyHintEl.classList.add("locked");
    return;
  }
  signInPolicyHintEl.textContent =
    "Wallet Sign-In is recommended; manual Sign In remains available when policy allows.";
  signInPolicyHintEl.classList.remove("locked");
}

function updateAuthVerifyPolicyHint() {
  if (!authVerifyPolicyHintEl) {
    syncIdentitySignInPolicyControls();
    return;
  }
  const manualSignInLocked = isManualSignInLockedByRuntimePolicy();
  const manualSignInLockedByProductionMode = state.productionMode === true;
  const modeLabel = formatAuthVerifyPolicyModeLabel(
    state.authVerifyRequireMetadata,
    state.authVerifyRequireWalletExtensionSource,
    state.authVerifyRequireCryptoProof
  );
  const sourceLabel = formatAuthVerifyPolicyClientSourceLabel(state.authVerifyPolicySource);
  let postureHint = "signature metadata and signature_source checks are compatibility-optional.";
  if (manualSignInLockedByProductionMode) {
    postureHint =
      "production mode is active; Wallet Sign-In is required and manual Sign In is disabled.";
  } else {
    const requirementHints = [];
    if (state.authVerifyRequireMetadata) {
      requirementHints.push("signature metadata is required (signature_kind, signature_source, signed_message)");
    }
    if (state.authVerifyRequireWalletExtensionSource) {
      requirementHints.push("signature_source must be wallet_extension");
    }
    if (state.authVerifyRequireCryptoProof) {
      requirementHints.push(
        "cryptographic proof metadata is required (signature_public_key, signature_public_key_type, signed_message)"
      );
    }
    if (requirementHints.length > 0) {
      postureHint = requirementHints.join("; ");
      if (manualSignInLocked) {
        postureHint = `${postureHint}; use Wallet Sign-In (manual Sign In is disabled).`;
      } else if (state.authVerifyRequireCryptoProof) {
        postureHint = `${postureHint}; manual Sign In remains available if it includes the required proof metadata.`;
      } else {
        postureHint = `${postureHint}.`;
      }
    }
  }
  authVerifyPolicyHintEl.textContent = `Auth verify policy: ${modeLabel} from ${sourceLabel}; ${postureHint}`;
  authVerifyPolicyHintEl.classList.toggle(
    "locked",
    state.productionMode ||
      state.authVerifyRequireMetadata ||
      state.authVerifyRequireWalletExtensionSource ||
      state.authVerifyRequireCryptoProof
  );
  syncIdentitySignInPolicyControls();
}

function updateOperatorApprovalPolicyHint() {
  if (!operatorApprovalPolicyHintEl || !approveOperatorBtnEl || !rejectOperatorBtnEl) {
    return;
  }
  const computeModerationReadiness = () => {
    if (!state.sessionToken) {
      return {
        locked: true,
        detail: "Sign in with an admin session token to approve or reject operators."
      };
    }
    const freshness = computeSessionFreshnessState();
    if (freshness.state === "expired") {
      return {
        locked: true,
        detail: freshness.detail
      };
    }
    if (freshness.state === "unknown") {
      return {
        locked: true,
        detail: `${freshness.detail} Run Session before moderation actions.`
      };
    }
    const role = (state.serverReadiness?.role || state.role || "client").toLowerCase();
    if (role !== "admin") {
      return {
        locked: true,
        detail: `Current session role is ${role}; admin role is required for approve/reject actions.`
      };
    }
    if (!walletAddressEl.value.trim()) {
      return {
        locked: true,
        detail: "Set wallet_address before approving or rejecting an operator."
      };
    }
    if (freshness.state === "expiring_soon") {
      return {
        locked: false,
        detail: `Ready with caution: ${freshness.detail}`
      };
    }
    return {
      locked: false,
      detail: "Ready: admin session is active for moderation actions."
    };
  };
  const sourceLabel = formatOperatorApprovalPolicyClientSourceLabel(state.operatorApprovalPolicySource);
  const readiness = computeModerationReadiness();
  const policyLine = state.operatorApprovalRequireSession
    ? `Operator approval policy: admin session token required from ${sourceLabel}; legacy admin_token fallback is disabled by policy.`
    : `Operator approval policy: session token preferred from ${sourceLabel}; legacy admin_token fallback may exist in backend policy, but desktop moderation actions remain session-token only.`;
  const readinessLine = readiness.locked
    ? `Moderation readiness: locked. ${readiness.detail}`
    : `Moderation readiness: ready. ${readiness.detail}`;
  operatorApprovalPolicyHintEl.textContent = `${policyLine} ${readinessLine}`;
  operatorApprovalPolicyHintEl.classList.toggle("locked", state.operatorApprovalRequireSession || readiness.locked);

  const isBusy = document.body.classList.contains("is-busy");
  const disabled = isBusy || readiness.locked;
  for (const button of [approveOperatorBtnEl, rejectOperatorBtnEl]) {
    button.disabled = disabled;
    button.setAttribute("aria-disabled", String(disabled));
    if (isBusy && !readiness.locked) {
      button.title = "Action in progress; wait for current request to finish.";
      continue;
    }
    if (readiness.locked) {
      button.title = readiness.detail;
      continue;
    }
    button.removeAttribute("title");
  }
}

function applyConnectModePolicy(enabled) {
  state.connectRequireSession = !!enabled;
  syncCompatAdvancedVisibility();
  if (state.connectRequireSession || state.productionMode) {
    bootstrapDirectoryEl.value = "";
    inviteKeyEl.value = "";
    setCompatOverrideEnabled(false);
  } else {
    setCompatOverrideEnabled(compatEnableEl.checked);
  }
  updateCompatOverrideHint();
  updateConnectPolicyHint();
}

function activateTab(name) {
  const wantsClient = name === "client";
  const clientEnabled = !tabClientEl.disabled;
  const serverEnabled = !tabServerEl.disabled;
  let selectedTab = wantsClient ? "client" : "server";
  if (selectedTab === "client" && !clientEnabled && serverEnabled) {
    selectedTab = "server";
  } else if (selectedTab === "server" && !serverEnabled && clientEnabled) {
    selectedTab = "client";
  }
  const isClient = selectedTab === "client";
  tabClientEl.classList.toggle("active", isClient);
  tabServerEl.classList.toggle("active", !isClient);
  tabClientEl.setAttribute("aria-selected", isClient ? "true" : "false");
  tabServerEl.setAttribute("aria-selected", !isClient ? "true" : "false");
  panelClientEl.classList.toggle("active", isClient);
  panelServerEl.classList.toggle("active", !isClient);
  panelClientEl.hidden = !isClient;
  panelServerEl.hidden = isClient;
}

function parseSessionRole(payload) {
  return (
    payload?.session?.role ||
    payload?.role ||
    payload?.profile?.role ||
    state.role ||
    "client"
  );
}

function applyOnboardingOverviewState(payload) {
  if (!payload || typeof payload !== "object") {
    return;
  }
  if (typeof payload?.session_token === "string" && payload.session_token.trim()) {
    setSessionToken(payload.session_token);
  }
  refreshSessionFreshnessFromPayload(payload, { tokenOverride: state.sessionToken });
  setClientRegistrationStateFromPayload(payload, { allowFallback: true });
  setRole(parseSessionRole(payload));
  setServerReadiness(parseServerReadiness(payload));
}

async function requestOnboardingOverview(options = {}) {
  const { quiet = true } = options;
  if (!state.sessionToken) {
    return undefined;
  }
  const request = {
    session_token: state.sessionToken
  };
  try {
    const result = quiet
      ? await invoke("control_gpm_onboarding_overview", { request })
      : await call("gpm_onboarding_overview", "control_gpm_onboarding_overview", { request });
    applyOnboardingOverviewState(result);
    markReadinessHeartbeatSuccess();
    return result;
  } catch (err) {
    if (quiet) {
      return undefined;
    }
    throw err;
  }
}

async function call(label, command, args = {}, options = {}) {
  const { formatResultForDisplay } = options;
  try {
    const result = await invoke(command, args);
    const payloadForDisplay =
      typeof formatResultForDisplay === "function"
        ? formatResultForDisplay(result)
        : result;
    print(
      label,
      withBootstrapDirectoryFallbackHint(withSessionReconciledHint(payloadForDisplay, result), result)
    );
    return result;
  } catch (err) {
    print(`${label} (error)`, err);
    throw err;
  }
}

function connectPayload() {
  const compatOverrideActive =
    state.allowLegacyConnectOverride && !state.connectRequireSession && !state.productionMode && compatEnableEl.checked;
  const sessionBootstrapDirectory = nonEmptyStringOrUndefined(sessionBootstrapDirectoryEl.value);
  const payload = {
    session_token: state.sessionToken || undefined,
    path_profile: pathProfileEl.value,
    policy_profile: pathProfileEl.value,
    interface: byId("interface").value.trim() || undefined,
    discovery_wait_sec: numberOrUndefined(byId("discovery_wait_sec").value),
    ready_timeout_sec: numberOrUndefined(byId("ready_timeout_sec").value),
    run_preflight: byId("run_preflight").checked,
    prod_profile: byId("prod_profile").checked,
    install_route: byId("install_route").checked
  };

  if (state.sessionToken && !compatOverrideActive && sessionBootstrapDirectory) {
    payload.session_bootstrap_directory = sessionBootstrapDirectory;
  }

  if (compatOverrideActive) {
    const bootstrap = bootstrapDirectoryEl.value.trim();
    const invite = inviteKeyEl.value.trim();
    if (bootstrap) {
      payload.bootstrap_directory = bootstrap;
    }
    if (invite) {
      payload.invite_key = invite;
    }
  }
  return payload;
}

function parseEpochMilliseconds(value) {
  if (value === null || value === undefined) {
    return undefined;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    if (value <= 0) {
      return undefined;
    }
    if (value > 1e12) {
      return Math.trunc(value);
    }
    return Math.trunc(value * 1000);
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) {
      return undefined;
    }
    if (/^[0-9]+$/.test(trimmed)) {
      return parseEpochMilliseconds(Number(trimmed));
    }
    const parsed = Date.parse(trimmed);
    if (Number.isFinite(parsed)) {
      return Math.trunc(parsed);
    }
  }
  return undefined;
}

function formatDurationCompact(seconds) {
  if (!Number.isFinite(seconds)) {
    return "unknown";
  }
  const abs = Math.abs(Math.trunc(seconds));
  if (abs < 60) {
    return `${abs}s`;
  }
  if (abs < 3600) {
    return `${Math.floor(abs / 60)}m`;
  }
  if (abs < 86400) {
    return `${Math.floor(abs / 3600)}h`;
  }
  return `${Math.floor(abs / 86400)}d`;
}

function sessionReauthGuidance() {
  return "Rotate Session if still valid; otherwise use Wallet Sign-In (Recommended) or Sign In.";
}

function extractSessionExpiryMs(payload) {
  if (!payload || typeof payload !== "object") {
    return undefined;
  }
  const candidates = [
    payload?.session?.expires_at_utc,
    payload?.session?.expiresAtUtc,
    payload?.session?.expires_at,
    payload?.session?.expiresAt,
    payload?.expires_at_utc,
    payload?.expiresAtUtc,
    payload?.expires_at,
    payload?.expiresAt,
    payload?.profile?.expires_at_utc,
    payload?.profile?.expiresAtUtc
  ];
  for (const candidate of candidates) {
    const parsed = parseEpochMilliseconds(candidate);
    if (parsed !== undefined) {
      return parsed;
    }
  }
  const expiresInRaw = firstDefined(
    payload?.session?.expires_in_sec,
    payload?.session?.expiresInSec,
    payload?.session?.expires_in,
    payload?.session?.expiresIn,
    payload?.expires_in_sec,
    payload?.expiresInSec,
    payload?.expires_in,
    payload?.expiresIn
  );
  if (expiresInRaw === undefined || expiresInRaw === null || String(expiresInRaw).trim() === "") {
    return undefined;
  }
  const expiresInSec = Number(expiresInRaw);
  if (!Number.isFinite(expiresInSec)) {
    return undefined;
  }
  return Date.now() + Math.trunc(expiresInSec * 1000);
}

function clearSessionFreshnessTelemetry() {
  state.sessionExpiryAtMs = undefined;
  state.sessionExpiryToken = "";
}

function refreshSessionFreshnessFromPayload(payload, options = {}) {
  const { clearWhenMissing = false, tokenOverride } = options;
  const token =
    nonEmptyStringOrUndefined(
      firstDefined(tokenOverride, payload?.session_token, payload?.session?.session_token, payload?.token)
    ) || nonEmptyStringOrUndefined(state.sessionToken);
  if (!token) {
    clearSessionFreshnessTelemetry();
    return;
  }
  state.sessionExpiryToken = token;
  const expiresAtMs = extractSessionExpiryMs(payload);
  if (expiresAtMs !== undefined) {
    state.sessionExpiryAtMs = expiresAtMs;
    return;
  }
  if (clearWhenMissing) {
    state.sessionExpiryAtMs = undefined;
  }
}

function markSessionFreshnessUnknownForToken(token = state.sessionToken) {
  const normalizedToken = nonEmptyStringOrUndefined(token);
  if (!normalizedToken) {
    clearSessionFreshnessTelemetry();
    return;
  }
  state.sessionExpiryToken = normalizedToken;
  state.sessionExpiryAtMs = undefined;
}

function computeSessionFreshnessState() {
  const token = nonEmptyStringOrUndefined(state.sessionToken);
  if (!token) {
    return {
      state: "signed_out",
      title: "Signed out",
      detail: "No active session token is loaded."
    };
  }
  if (state.sessionExpiryToken && state.sessionExpiryToken !== token) {
    return {
      state: "unknown",
      title: "Session expiry unknown",
      detail: "Session token changed. Run Session to validate expiry and avoid stale auth."
    };
  }
  if (typeof state.sessionExpiryAtMs !== "number" || !Number.isFinite(state.sessionExpiryAtMs) || state.sessionExpiryAtMs <= 0) {
    return {
      state: "unknown",
      title: "Session expiry unknown",
      detail: "Session token is loaded, but expires_at_utc is unavailable. Run Session to validate freshness."
    };
  }
  const deltaMs = state.sessionExpiryAtMs - Date.now();
  const deltaSec = Math.floor(deltaMs / 1000);
  const expiresAtIso = new Date(state.sessionExpiryAtMs).toISOString();
  if (deltaMs <= 0) {
    return {
      state: "expired",
      title: "Session expired",
      detail: `Session expired ${formatDurationCompact(deltaSec)} ago (${expiresAtIso}). ${sessionReauthGuidance()}`,
      expiresAtMs: state.sessionExpiryAtMs
    };
  }
  if (deltaMs <= SESSION_EXPIRING_SOON_MS) {
    return {
      state: "expiring_soon",
      title: "Session expiring soon",
      detail: `Session expires in ${formatDurationCompact(deltaSec)} (${expiresAtIso}). Rotate Session now to avoid auth failures.`,
      expiresAtMs: state.sessionExpiryAtMs
    };
  }
  return {
    state: "active",
    title: "Session active",
    detail: `Session expires in ${formatDurationCompact(deltaSec)} (${expiresAtIso}).`,
    expiresAtMs: state.sessionExpiryAtMs
  };
}

function normalizeBootstrapManifestSource(value) {
  const source = nonEmptyStringOrUndefined(value);
  if (!source) {
    return "unknown";
  }
  const compact = source.toLowerCase().replace(/[\s-]+/g, "_");
  if (compact.includes("remote")) {
    return "remote";
  }
  if (compact.includes("cache") || compact.includes("cached") || compact.includes("local")) {
    return "cache";
  }
  return source;
}

function normalizeManifestSignatureVerified(value) {
  const direct = toBooleanLike(value);
  if (direct !== undefined) {
    return direct;
  }
  const text = nonEmptyStringOrUndefined(value)?.toLowerCase();
  if (!text) {
    return undefined;
  }
  if (text.includes("unverified") || text.includes("not_verified") || text.includes("invalid") || text.includes("fail")) {
    return false;
  }
  if (text.includes("verified") || text.includes("valid") || text.includes("trusted") || text === "pass") {
    return true;
  }
  return undefined;
}

function hasBootstrapManifestTrustDegradedFragment(value) {
  const text = nonEmptyStringOrUndefined(value)?.toLowerCase();
  if (!text) {
    return false;
  }
  return BOOTSTRAP_MANIFEST_TRUST_DEGRADED_STATUS_FRAGMENTS.some((fragment) => text.includes(fragment));
}

function isBootstrapManifestPayloadCandidate(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  return (
    Object.prototype.hasOwnProperty.call(value, "bootstrap_directories") ||
    Object.prototype.hasOwnProperty.call(value, "bootstrapDirectories") ||
    Object.prototype.hasOwnProperty.call(value, "expires_at_utc") ||
    Object.prototype.hasOwnProperty.call(value, "expiresAtUtc") ||
    Object.prototype.hasOwnProperty.call(value, "generated_at_utc") ||
    Object.prototype.hasOwnProperty.call(value, "generatedAtUtc") ||
    Object.prototype.hasOwnProperty.call(value, "version")
  );
}

function deriveBootstrapManifestTrustTelemetry(result) {
  const response = result && typeof result === "object" ? result : {};
  const manifestCandidates = [
    response?.manifest,
    response?.bootstrap_manifest,
    response?.bootstrapManifest,
    response?.trusted_manifest,
    response?.trustedManifest,
    response?.data?.manifest,
    response?.data?.bootstrap_manifest,
    response?.data?.bootstrapManifest,
    response?.result?.manifest,
    response?.result?.bootstrap_manifest,
    response?.result?.bootstrapManifest,
    response
  ];

  let manifest = null;
  for (const candidate of manifestCandidates) {
    if (isBootstrapManifestPayloadCandidate(candidate)) {
      manifest = candidate;
      break;
    }
  }

  const source = normalizeBootstrapManifestSource(
    firstDefined(
      response?.source,
      response?.manifest_source,
      response?.manifestSource,
      response?.trust_source,
      response?.trustSource,
      response?.telemetry?.source,
      response?.trust?.source,
      manifest?.source,
      manifest?.manifest_source,
      manifest?.manifestSource
    )
  );
  const manifestSourceUrl =
    toDetailText(
      firstDefined(
        response?.manifest_source_url,
        response?.manifestSourceUrl,
        response?.source_url,
        response?.sourceUrl,
        response?.trust?.manifest_source_url,
        response?.trust?.manifestSourceUrl
      )
    ) || "";
  const signatureVerified = normalizeManifestSignatureVerified(
    firstDefined(
      response?.signature_verified,
      response?.signatureVerified,
      response?.manifest_signature_verified,
      response?.manifestSignatureVerified,
      response?.trust?.signature_verified,
      response?.trust?.signatureVerified,
      response?.telemetry?.signature_verified,
      response?.telemetry?.signatureVerified,
      manifest?.signature_verified,
      manifest?.signatureVerified
    )
  );
  const signatureRequiredByPolicy = toBooleanLike(
    firstDefined(
      response?.signature_required_by_policy,
      response?.signatureRequiredByPolicy,
      response?.manifest_signature_required_by_policy,
      response?.manifestSignatureRequiredByPolicy,
      response?.trust?.signature_required_by_policy,
      response?.trust?.signatureRequiredByPolicy,
      state.manifestRequireSignature
    )
  );
  const httpsRequiredByPolicy = toBooleanLike(
    firstDefined(
      response?.https_required_by_policy,
      response?.httpsRequiredByPolicy,
      response?.manifest_https_required_by_policy,
      response?.manifestHttpsRequiredByPolicy,
      response?.trust?.https_required_by_policy,
      response?.trust?.httpsRequiredByPolicy,
      state.manifestRequireHTTPS
    )
  );
  const trustStatus =
    toDetailText(
      firstDefined(
        response?.trust_status,
        response?.trustStatus,
        response?.manifest_trust_status,
        response?.manifestTrustStatus,
        response?.status,
        response?.trust?.status,
        manifest?.trust_status,
        manifest?.trustStatus
      )
    ) || "";
  const trustReason =
    toDetailText(
      firstDefined(
        response?.trust_reason,
        response?.trustReason,
        response?.status_reason,
        response?.statusReason,
        response?.degraded_reason,
        response?.degradedReason,
        response?.message,
        response?.warning,
        response?.warnings,
        response?.recommendation,
        response?.guidance,
        response?.next_action,
        response?.nextAction,
        response?.remediation,
        response?.trust?.reason,
        manifest?.trust_reason,
        manifest?.trustReason
      )
    ) || "";
  const explicitDegraded = toBooleanLike(
    firstDefined(
      response?.degraded,
      response?.is_degraded,
      response?.isDegraded,
      response?.trust_degraded,
      response?.trustDegraded,
      response?.manifest_degraded,
      response?.manifestDegraded,
      response?.signature_degraded,
      response?.signatureDegraded
    )
  );
  const explicitRevoked = toBooleanLike(
    firstDefined(response?.revoked, response?.is_revoked, response?.isRevoked, response?.trust_revoked, response?.trustRevoked)
  );
  const guidanceText =
    toDetailText(
      firstDefined(
        response?.guidance,
        response?.recommended_action,
        response?.recommendedAction,
        response?.next_action,
        response?.nextAction,
        response?.remediation,
        response?.action_hint,
        response?.actionHint,
        response?.trust?.guidance
      )
    ) || "";

  const expiresAtRaw =
    toDetailText(
      firstDefined(
        manifest?.expires_at_utc,
        manifest?.expiresAtUtc,
        manifest?.expires_at,
        manifest?.expiresAt,
        response?.expires_at_utc,
        response?.expiresAtUtc,
        response?.expires_at,
        response?.expiresAt,
        response?.trust?.expires_at_utc,
        response?.trust?.expiresAtUtc
      )
    ) || "";
  const expiresAtMs = parseEpochMilliseconds(expiresAtRaw);
  const expiresInRaw = firstDefined(
    response?.expires_in_sec,
    response?.expiresInSec,
    response?.expiry_in_sec,
    response?.expiryInSec,
    response?.manifest_expires_in_sec,
    response?.manifestExpiresInSec,
    manifest?.expires_in_sec,
    manifest?.expiresInSec,
    manifest?.expiry_in_sec,
    manifest?.expiryInSec
  );
  let expiresInSec;
  if (expiresInRaw !== undefined && expiresInRaw !== null && String(expiresInRaw).trim() !== "") {
    const parsed = Number(expiresInRaw);
    if (Number.isFinite(parsed)) {
      expiresInSec = Math.trunc(parsed);
    }
  }
  if (!Number.isFinite(expiresInSec) && Number.isFinite(expiresAtMs)) {
    expiresInSec = Math.floor((expiresAtMs - Date.now()) / 1000);
  }
  const expired = Number.isFinite(expiresInSec) ? expiresInSec <= 0 : Number.isFinite(expiresAtMs) ? expiresAtMs <= Date.now() : false;
  const expiringSoon = Number.isFinite(expiresInSec) ? expiresInSec > 0 && expiresInSec <= 900 : false;

  const sourceUrlLower = manifestSourceUrl.toLowerCase();
  const sourceUrlUsesHttp = sourceUrlLower.startsWith("http://");
  const degradedByStatus = hasBootstrapManifestTrustDegradedFragment(trustStatus) || hasBootstrapManifestTrustDegradedFragment(trustReason);
  const signatureFailureIsDegraded = signatureVerified === false && signatureRequiredByPolicy !== false;
  const httpsPolicyViolation = httpsRequiredByPolicy === true && sourceUrlUsesHttp;
  const degraded =
    explicitRevoked === true ||
    explicitDegraded === true ||
    degradedByStatus ||
    signatureFailureIsDegraded ||
    httpsPolicyViolation ||
    expired;

  let stateKey = "unknown";
  if (degraded) {
    stateKey = "degraded";
  } else if (expiringSoon) {
    stateKey = "warning";
  } else if (signatureVerified === true) {
    stateKey = "healthy";
  }
  const stateLabel =
    stateKey === "degraded"
      ? "Degraded"
      : stateKey === "warning"
        ? "Warning"
        : stateKey === "healthy"
          ? "Healthy"
          : "Unknown";

  const sourceLabel = source === "remote" ? "remote" : source === "cache" ? "cache" : source || "unknown";
  const signatureLabel =
    signatureVerified === true ? "verified" : signatureVerified === false ? "not verified" : "unknown";
  let expiryLabel = "unknown";
  if (Number.isFinite(expiresInSec)) {
    if (expiresInSec <= 0) {
      expiryLabel = `expired ${formatDurationCompact(expiresInSec)} ago`;
    } else {
      const expiresAtLabel = expiresAtRaw || (Number.isFinite(expiresAtMs) ? new Date(expiresAtMs).toISOString() : "");
      expiryLabel = `in ${formatDurationCompact(expiresInSec)}${expiresAtLabel ? ` (${expiresAtLabel})` : ""}`;
    }
  } else if (expiresAtRaw) {
    expiryLabel = expiresAtRaw;
  }

  let guidance = guidanceText || trustReason;
  if (!guidance) {
    if (httpsPolicyViolation) {
      guidance = "Bootstrap manifest source uses http while https is required by policy; refresh from a trusted https endpoint.";
    } else if (signatureFailureIsDegraded) {
      guidance = "Signature verification failed; refresh manifest from a trusted remote source and verify signer policy.";
    } else if (signatureVerified === false && signatureRequiredByPolicy === false) {
      guidance = "Signature is not verified, but current policy allows compatibility mode.";
    } else if (expired) {
      guidance = "Manifest is expired; refresh bootstrap manifest before registering or connecting clients.";
    } else if (degraded) {
      guidance = "Bootstrap trust is degraded; refresh manifest and re-register client profile.";
    } else if (expiringSoon) {
      guidance = "Manifest expires soon; plan a refresh to avoid bootstrap trust drift.";
    } else {
      guidance = "Bootstrap trust posture is healthy.";
    }
  }

  return {
    source,
    sourceLabel,
    manifestSourceUrl,
    signatureRequiredByPolicy,
    httpsRequiredByPolicy,
    signatureVerified,
    signatureLabel,
    trustStatus,
    trustReason,
    stateKey,
    stateLabel,
    degraded,
    expiryLabel,
    guidance
  };
}

function renderBootstrapManifestTrustTelemetry(telemetry) {
  const trust = telemetry && typeof telemetry === "object" ? telemetry : deriveBootstrapManifestTrustTelemetry(null);
  const sourceLabel = trust.sourceLabel || "unknown";
  const signatureLabel = trust.signatureLabel || "unknown";
  const signaturePolicyLabel =
    trust.signatureRequiredByPolicy === true
      ? "required"
      : trust.signatureRequiredByPolicy === false
        ? "compat"
        : "unknown";
  const httpsPolicyLabel =
    trust.httpsRequiredByPolicy === true
      ? "https-required"
      : trust.httpsRequiredByPolicy === false
        ? "https-compat"
        : "https-policy-unknown";
  const signatureSummary =
    trust.signatureVerified === true
      ? "signature verified"
      : trust.signatureVerified === false
        ? "signature not verified"
        : "signature unknown";

  manifestSourceEl.textContent = `Manifest: ${sourceLabel} (${signatureSummary})`;

  if (!bootstrapTrustStateEl || !bootstrapTrustSourceEl || !bootstrapTrustSignatureEl || !bootstrapTrustExpiryEl || !bootstrapTrustGuidanceEl) {
    return;
  }

  bootstrapTrustStateEl.textContent = trust.stateLabel || "Unknown";
  bootstrapTrustSourceEl.textContent = `Source: ${sourceLabel} (${httpsPolicyLabel})`;
  bootstrapTrustSignatureEl.textContent = `Signature: ${signatureLabel} (${signaturePolicyLabel})`;
  bootstrapTrustExpiryEl.textContent = `Expiry: ${trust.expiryLabel || "unknown"}`;
  bootstrapTrustGuidanceEl.textContent = `Guidance: ${trust.guidance || "Load manifest to evaluate bootstrap trust posture."}`;

  if (bootstrapTrustCardEl) {
    bootstrapTrustCardEl.dataset.state = trust.stateKey || "unknown";
  }
  bootstrapTrustGuidanceEl.classList.toggle("locked", trust.degraded === true);
}

function renderBootstrapManifestTrustUnavailable(detail) {
  renderBootstrapManifestTrustTelemetry({
    source: "unknown",
    sourceLabel: "unavailable",
    signatureVerified: undefined,
    signatureLabel: "unknown",
    stateKey: "unknown",
    stateLabel: "Unknown",
    degraded: false,
    expiryLabel: "unavailable",
    guidance: detail || "Manifest lookup is unavailable; retry Manifest and verify local API connectivity."
  });
}

async function loadManifest() {
  const result = await call("gpm_manifest", "control_gpm_bootstrap_manifest");
  const manifestPayloadCandidates = [result?.manifest, result?.bootstrap_manifest, result?.bootstrapManifest, result];
  state.manifest = null;
  for (const candidate of manifestPayloadCandidates) {
    if (isBootstrapManifestPayloadCandidate(candidate)) {
      state.manifest = candidate;
      break;
    }
  }
  renderBootstrapManifestTrustTelemetry(deriveBootstrapManifestTrustTelemetry(result));
  return result;
}

async function refreshOperatorApplicationStatus(options = {}) {
  const { quiet = true } = options;
  if (!state.sessionToken) {
    setOperatorApplicationStatus(undefined);
    return undefined;
  }
  const request = {
    session_token: state.sessionToken || undefined,
    wallet_address: walletAddressEl.value.trim() || undefined
  };
  try {
    const result = quiet
      ? await invoke("control_gpm_operator_status", { request })
      : await call("gpm_operator_status", "control_gpm_operator_status", { request });
    setOperatorApplicationStatus(parseOperatorApplicationStatus(result));
    applySelectedOperatorPrefill(extractOperatorPrefillValues(result), { mode: "merge" });
    markReadinessHeartbeatSuccess();
    return result;
  } catch (err) {
    if (quiet) {
      return undefined;
    }
    throw err;
  }
}

async function refreshServerReadinessStatus(options = {}) {
  const { quiet = true } = options;
  const sessionToken = state.sessionToken || undefined;
  const walletAddress = walletAddressEl.value.trim() || undefined;
  if (!sessionToken && !walletAddress) {
    setServerReadiness(null);
    return undefined;
  }
  const request = {
    session_token: sessionToken,
    wallet_address: walletAddress
  };
  try {
    const result = quiet
      ? await invoke("control_gpm_server_status", { request })
      : await call("gpm_server_status", "control_gpm_server_status", { request });
    setServerReadiness(parseServerReadiness(result));
    markReadinessHeartbeatSuccess();
    return result;
  } catch (err) {
    setServerReadiness(null);
    if (quiet) {
      return undefined;
    }
    throw err;
  }
}

async function refreshClientRegistrationStatus(options = {}) {
  const { quiet = true } = options;
  if (!state.sessionToken) {
    state.clientRegistered = false;
    clearClientRegistrationTrustState();
    syncDesktopOnboardingSteps();
    return undefined;
  }
  const request = {
    session_token: state.sessionToken,
    wallet_address: walletAddressEl.value.trim() || undefined
  };
  try {
    const result = quiet
      ? await invoke("control_gpm_client_status", { request })
      : await call("gpm_client_status", "control_gpm_client_status", { request });
    setClientRegistrationStateFromPayload(result, { allowFallback: true });
    syncDesktopOnboardingSteps();
    markReadinessHeartbeatSuccess();
    return result;
  } catch (err) {
    if (quiet) {
      return undefined;
    }
    throw err;
  }
}

async function refreshSession(action = "status") {
  if (!state.sessionToken) {
    clearSessionFreshnessTelemetry();
    setOperatorApplicationStatus(undefined);
    setServerReadiness(null);
    syncReadinessFreshnessIndicator();
    return;
  }
  const sessionAction = action || "status";
  const label =
    sessionAction === "refresh"
      ? "gpm_session_refresh"
      : sessionAction === "revoke"
        ? "gpm_session_revoke"
        : "gpm_session";
  const result = await call(label, "control_gpm_session", {
    request: { session_token: state.sessionToken, action: sessionAction }
  });
  if (sessionAction === "refresh") {
    setSessionToken(result?.session_token || state.sessionToken);
  }
  if (sessionAction === "revoke") {
    setSessionToken("");
    setRole("client");
    setOperatorApplicationStatus(undefined);
    setServerReadiness(null);
    syncReadinessFreshnessIndicator();
    return result;
  }
  refreshSessionFreshnessFromPayload(result, { tokenOverride: state.sessionToken, clearWhenMissing: true });
  setClientRegistrationStateFromPayload(result, { allowFallback: true });
  setRole(parseSessionRole(result));
  const overview = await requestOnboardingOverview({ quiet: true });
  if (!overview) {
    await refreshClientRegistrationStatus({ quiet: true });
    await refreshServerReadinessStatus({ quiet: true });
  }
  await refreshOperatorApplicationStatus({ quiet: true });
  markReadinessHeartbeatSuccess();
  return result;
}

async function refreshSessionOnInit() {
  if (!state.sessionToken) {
    clearSessionFreshnessTelemetry();
    setServerReadiness(null);
    syncReadinessFreshnessIndicator();
    return;
  }
  let overview;
  let refreshed = false;
  try {
    const result = await invoke("control_gpm_session", {
      request: { session_token: state.sessionToken, action: "status" }
    });
    refreshSessionFreshnessFromPayload(result, { tokenOverride: state.sessionToken, clearWhenMissing: true });
    setClientRegistrationStateFromPayload(result, { allowFallback: true });
    setRole(parseSessionRole(result));
    refreshed = true;
    overview = await requestOnboardingOverview({ quiet: true });
    refreshed = refreshed || !!overview;
  } catch {
    // Startup status refresh is best-effort and should not block the scaffold.
  }
  if (!overview) {
    const registrationResult = await refreshClientRegistrationStatus({ quiet: true });
    const readinessResult = await refreshServerReadinessStatus({ quiet: true });
    refreshed = refreshed || !!registrationResult || !!readinessResult;
  }
  const operatorResult = await refreshOperatorApplicationStatus({ quiet: true });
  refreshed = refreshed || !!operatorResult;
  if (refreshed) {
    markReadinessHeartbeatSuccess();
  } else {
    syncReadinessFreshnessIndicator();
  }
}

async function runReadinessHeartbeat(reason = "interval") {
  if (state.readinessHeartbeatInFlight) {
    return;
  }
  const heartbeatSessionToken = typeof state.sessionToken === "string" ? state.sessionToken.trim() : "";
  if (!heartbeatSessionToken) {
    syncReadinessFreshnessIndicator();
    return;
  }
  if (document.hidden && reason === "interval") {
    syncReadinessFreshnessIndicator();
    return;
  }

  state.readinessHeartbeatInFlight = true;
  state.readinessFreshnessLastAttemptMs = Date.now();
  syncReadinessFreshnessIndicator();

  let refreshed = false;
  let errorText = "";
  let aborted = false;
  try {
    const overview = await requestOnboardingOverview({ quiet: true });
    if (state.sessionToken !== heartbeatSessionToken) {
      aborted = true;
      return;
    }
    refreshed = !!overview;
    if (!overview) {
      try {
        const sessionResult = await invoke("control_gpm_session", {
          request: { session_token: heartbeatSessionToken, action: "status" }
        });
        if (state.sessionToken !== heartbeatSessionToken) {
          aborted = true;
          return;
        }
        refreshSessionFreshnessFromPayload(sessionResult, {
          tokenOverride: heartbeatSessionToken,
          clearWhenMissing: true
        });
        setClientRegistrationStateFromPayload(sessionResult, { allowFallback: true });
        setRole(parseSessionRole(sessionResult));
        refreshed = true;
      } catch (err) {
        errorText = heartbeatErrorText(err);
      }

      const registrationResult = await refreshClientRegistrationStatus({ quiet: true });
      const readinessResult = await refreshServerReadinessStatus({ quiet: true });
      const operatorResult = await refreshOperatorApplicationStatus({ quiet: true });
      if (state.sessionToken !== heartbeatSessionToken) {
        aborted = true;
        return;
      }
      refreshed = refreshed || !!registrationResult || !!readinessResult || !!operatorResult;
    } else {
      const operatorResult = await refreshOperatorApplicationStatus({ quiet: true });
      if (state.sessionToken !== heartbeatSessionToken) {
        aborted = true;
        return;
      }
      refreshed = refreshed || !!operatorResult;
    }
  } catch (err) {
    errorText = heartbeatErrorText(err);
  } finally {
    state.readinessHeartbeatInFlight = false;
    if (aborted) {
      syncReadinessFreshnessIndicator();
      return;
    }
    if (refreshed) {
      markReadinessHeartbeatSuccess({ expectedSessionToken: heartbeatSessionToken });
    } else {
      state.readinessFreshnessLastAttemptMs = Date.now();
      if (errorText) {
        state.readinessFreshnessLastError = errorText;
      } else if (!state.readinessFreshnessLastError) {
        state.readinessFreshnessLastError = "readiness/auth heartbeat returned no data";
      }
      syncReadinessFreshnessIndicator();
    }
  }
}

function startReadinessHeartbeat() {
  if (readinessHeartbeatTimer) {
    clearInterval(readinessHeartbeatTimer);
    readinessHeartbeatTimer = null;
  }
  readinessHeartbeatTimer = window.setInterval(() => {
    void runReadinessHeartbeat("interval");
  }, READINESS_HEARTBEAT_INTERVAL_MS);
}

function stopReadinessHeartbeat() {
  if (readinessHeartbeatTimer) {
    clearInterval(readinessHeartbeatTimer);
    readinessHeartbeatTimer = null;
  }
}

function bindReadinessHeartbeatListeners() {
  if (readinessHeartbeatListenersBound) {
    return;
  }
  readinessHeartbeatListenersBound = true;

  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      syncReadinessFreshnessIndicator();
      return;
    }
    void runReadinessHeartbeat("visibility");
  });

  window.addEventListener("focus", () => {
    void runReadinessHeartbeat("focus");
  });

  window.addEventListener("beforeunload", () => {
    stopReadinessHeartbeat();
  });
}

async function loadNextPendingOperator() {
  if (!requireSessionToken("load the next pending operator")) {
    return undefined;
  }
  const request = {
    session_token: state.sessionToken,
    status: "pending",
    limit: OPERATOR_LOAD_NEXT_LIMIT
  };
  const result = await call("gpm_operator_load_next_pending", "control_gpm_operator_list", { request });
  const page = extractOperatorListPageInfo(result);
  setOperatorListRequestContext({ status: "pending", limit: OPERATOR_LOAD_NEXT_LIMIT });
  setOperatorListNextCursor(page.nextCursor);
  const entries = extractOperatorListEntries(result);
  if (entries.length === 0) {
    print(
      "operator_load_next_pending",
      withSessionReconciledHint(
        {
          message: "No pending operator applications are currently queued.",
          status: "pending",
          limit: OPERATOR_LOAD_NEXT_LIMIT,
          returned: page.returned,
          has_more: page.hasMore ?? null,
          next_cursor: page.nextCursor || null
        },
        result
      )
    );
    return result;
  }
  const nextEntry = entries[0];
  const { walletAddress, chainOperatorId, selectedApplicationUpdatedAtUtc } = extractOperatorPrefillValues(nextEntry);
  applySelectedOperatorPrefill(
    { walletAddress, chainOperatorId, selectedApplicationUpdatedAtUtc },
    { mode: "replace" }
  );
  await refreshServerReadinessStatus({ quiet: true });
  const loadedMessage =
    walletAddress || chainOperatorId
      ? "Loaded next pending operator into moderation fields."
      : "Loaded next pending queue entry, but wallet/chain operator values were empty.";
  print(
    "operator_load_next_pending",
    withSessionReconciledHint(
      {
        message: loadedMessage,
        wallet_address: walletAddress || null,
        chain_operator_id: chainOperatorId || null,
        selected_application_updated_at: selectedApplicationUpdatedAtUtc || null,
        status: "pending",
        limit: OPERATOR_LOAD_NEXT_LIMIT,
        returned: page.returned,
        has_more: page.hasMore ?? null,
        next_cursor: page.nextCursor || null
      },
      result
    )
  );
  return result;
}

async function loadNextOperatorListPage() {
  if (!requireSessionToken("load the next operator queue page")) {
    return undefined;
  }
  const cursor = nonEmptyStringOrUndefined(state.operatorListNextCursor);
  if (!cursor) {
    print("validation", "next_cursor is not available; run an operator list request first");
    return undefined;
  }
  const filter = state.operatorListRequestContext || readOperatorListFilterControls();
  return requestOperatorList("gpm_operator_list_next_page", filter, { cursor });
}

tabClientEl.addEventListener("click", () => {
  if (!tabClientEl.disabled) {
    activateTab("client");
  }
});
tabServerEl.addEventListener("click", () => {
  if (!tabServerEl.disabled) {
    activateTab("server");
  }
});
sessionTokenEl.addEventListener("input", () => {
  setSessionToken(sessionTokenEl.value);
});
walletProviderEl.addEventListener("change", () => {
  writePersistedValue(STORAGE_KEYS.walletProvider, walletProviderEl.value);
  clearWalletSignatureContext();
});
walletAddressEl.addEventListener("input", () => {
  writePersistedValue(STORAGE_KEYS.walletAddress, walletAddressEl.value);
  clearWalletSignatureContext();
  state.authChallengeMessage = "";
  setSelectedApplicationUpdatedAt("");
  syncDesktopOnboardingBanner();
  updateOperatorApprovalPolicyHint();
});
challengeIdEl.addEventListener("input", () => {
  clearWalletSignatureContext();
  state.authChallengeMessage = "";
  syncDesktopOnboardingBanner();
});
walletSignatureEl.addEventListener("input", () => {
  clearWalletSignatureContext();
  syncDesktopOnboardingBanner();
});
signatureChainIdEl.addEventListener("input", () => {
  clearWalletSignatureContext();
});
signedMessageEl.addEventListener("input", () => {
  clearWalletSignatureContext();
  syncDesktopOnboardingBanner();
});
chainOperatorIdEl.addEventListener("input", () => {
  writePersistedValue(STORAGE_KEYS.chainOperatorId, chainOperatorIdEl.value);
  setSelectedApplicationUpdatedAt("");
});
pathProfileEl.addEventListener("change", () => {
  writePersistedValue(STORAGE_KEYS.pathProfile, pathProfileEl.value);
});
operatorListStatusEl.addEventListener("change", () => {
  clearOperatorListPaginationState();
});
operatorListSearchEl.addEventListener("input", () => {
  clearOperatorListPaginationState();
});
operatorListLimitEl.addEventListener("input", () => {
  clearOperatorListPaginationState();
});

byId("challenge_btn").addEventListener("click", async () => {
  const { wallet_address, wallet_provider } = readWalletPayload();
  clearWalletSignatureContext();
  const result = await call("gpm_auth_challenge", "control_gpm_auth_challenge", {
    request: { wallet_address, wallet_provider }
  });
  applyChallengePayload(result);
});

walletSignInBtnEl.addEventListener("click", async () => {
  try {
    await runWalletExtensionSignIn();
  } catch (err) {
    print("wallet_signin (error)", {
      error: String(err && err.message ? err.message : err)
    });
  }
});

signInBtnEl.addEventListener("click", async () => {
  if (isManualSignInLockedByRuntimePolicy()) {
    print("validation", manualSignInLockValidationText());
    return;
  }
  const request = {
    wallet_address: walletAddressEl.value.trim(),
    wallet_provider: walletProviderEl.value,
    challenge_id: challengeIdEl.value.trim(),
    signature: walletSignatureEl.value.trim()
  };
  const contextSignatureMetadata = authVerifySignatureContext(request) || {};
  const manualSignatureMetadata = readAuthVerifySignatureMetadata();
  const signatureMetadata =
    Object.keys(manualSignatureMetadata).length > 0
      ? { ...contextSignatureMetadata, ...manualSignatureMetadata }
      : contextSignatureMetadata;
  Object.assign(request, signatureMetadata);
  const result = await call("gpm_auth_verify", "control_gpm_auth_verify", { request });
  await completeAuthVerifyFlow(result);
});

byId("session_btn").addEventListener("click", async () => {
  await refreshSession();
});

byId("session_rotate_btn").addEventListener("click", async () => {
  if (!requireSessionToken("rotate the session")) {
    return;
  }
  await refreshSession("refresh");
});

byId("session_revoke_btn").addEventListener("click", async () => {
  if (!requireSessionToken("revoke the session")) {
    return;
  }
  await refreshSession("revoke");
});

byId("manifest_btn").addEventListener("click", async () => {
  await loadManifest();
});

byId("audit_recent_btn").addEventListener("click", async () => {
  const requestContext = readAuditRecentControls();
  const request = buildAuditRecentRequest(requestContext);
  await call("gpm_audit_recent", "control_gpm_audit_recent", request, {
    formatResultForDisplay: (payload) => formatAuditRecentDisplayPayload(payload, requestContext)
  });
});

byId("register_client_btn").addEventListener("click", async () => {
  if (!requireClientControlEligibility("Register client profile")) {
    return;
  }
  if (!state.sessionToken) {
    print("validation", "session_token is required; sign in first");
    return;
  }
  const request = {
    session_token: state.sessionToken,
    path_profile: pathProfileEl.value
  };
  if (state.allowLegacyConnectOverride && !state.connectRequireSession && !state.productionMode && compatEnableEl.checked) {
    const bootstrap = bootstrapDirectoryEl.value.trim();
    const invite = inviteKeyEl.value.trim();
    if (bootstrap) {
      request.bootstrap_directory = bootstrap;
    }
    if (invite) {
      request.invite_key = invite;
    }
  }
  const result = await call("gpm_client_register", "control_gpm_client_register", { request });
  setClientRegistrationStateFromPayload(result, { allowFallback: true });
  if (!state.clientRegistered) {
    state.clientRegistered = true;
  }
  clearClientRegistrationTrustState();
  setRole(parseSessionRole(result));
  await refreshClientRegistrationStatus({ quiet: true });
});

byId("apply_operator_btn").addEventListener("click", async () => {
  if (!state.sessionToken) {
    print("validation", "session_token is required; sign in first");
    return;
  }
  const request = {
    session_token: state.sessionToken,
    chain_operator_id: chainOperatorIdEl.value.trim(),
    server_label: "desktop-operator"
  };
  await call("gpm_operator_apply", "control_gpm_operator_apply", { request });
  await refreshOperatorApplicationStatus({ quiet: true });
  await refreshServerReadinessStatus({ quiet: true });
});

byId("operator_status_btn").addEventListener("click", async () => {
  await refreshOperatorApplicationStatus({ quiet: false });
  await refreshServerReadinessStatus({ quiet: true });
});

byId("operator_list_filter_btn").addEventListener("click", async () => {
  if (!requireSessionToken("list the operator queue")) {
    return;
  }
  await requestOperatorList("gpm_operator_list_filtered", readOperatorListFilterControls(), {
    syncControls: true
  });
});

byId("operator_list_pending_btn").addEventListener("click", async () => {
  if (!requireSessionToken("list pending operators")) {
    return;
  }
  await requestOperatorList("gpm_operator_list_pending", {
    status: "pending",
    limit: OPERATOR_PENDING_LIST_LIMIT
  }, { syncControls: true });
});

byId("operator_load_next_pending_btn").addEventListener("click", async () => {
  await loadNextPendingOperator();
});

byId("operator_list_all_btn").addEventListener("click", async () => {
  if (!requireSessionToken("list all operators")) {
    return;
  }
  await requestOperatorList("gpm_operator_list_all", {
    status: "",
    limit: OPERATOR_LIST_ALL_LIMIT
  }, { syncControls: true });
});

byId("operator_list_next_btn").addEventListener("click", async () => {
  await loadNextOperatorListPage();
});

byId("approve_operator_btn").addEventListener("click", async () => {
  if (!requireSessionToken("approve an operator")) {
    return;
  }
  const request = {
    wallet_address: walletAddressEl.value.trim(),
    approved: true,
    session_token: state.sessionToken
  };
  const ifUpdatedAtUtc = selectedApplicationUpdatedAt();
  if (ifUpdatedAtUtc) {
    request.if_updated_at_utc = ifUpdatedAtUtc;
  }
  const reason = operatorModerationReason();
  if (reason) {
    request.reason = reason;
  }
  try {
    await call("gpm_operator_approve", "control_gpm_operator_approve", { request });
  } catch (err) {
    if (isDecisionConflictError(err)) {
      print("gpm_operator_approve (conflict)", {
        error: String(err && err.message ? err.message : err),
        guidance: OPERATOR_DECISION_CONFLICT_GUIDANCE
      });
      return;
    }
    throw err;
  }
  await refreshSession();
});

byId("reject_operator_btn").addEventListener("click", async () => {
  if (!requireSessionToken("reject an operator")) {
    return;
  }
  const reason = operatorModerationReason();
  if (!reason) {
    print("validation", "moderation reason is required to reject an operator");
    return;
  }
  const request = {
    wallet_address: walletAddressEl.value.trim(),
    approved: false,
    reason,
    session_token: state.sessionToken
  };
  const ifUpdatedAtUtc = selectedApplicationUpdatedAt();
  if (ifUpdatedAtUtc) {
    request.if_updated_at_utc = ifUpdatedAtUtc;
  }
  try {
    await call("gpm_operator_reject", "control_gpm_operator_approve", { request });
  } catch (err) {
    if (isDecisionConflictError(err)) {
      print("gpm_operator_reject (conflict)", {
        error: String(err && err.message ? err.message : err),
        guidance: OPERATOR_DECISION_CONFLICT_GUIDANCE
      });
      return;
    }
    throw err;
  }
  await refreshSession();
});

byId("connect_btn").addEventListener("click", async () => {
  if (!requireClientControlEligibility("Connect")) {
    return;
  }
  if (!beginConnectionMutation("connect")) {
    const activeMutation = describeConnectionMutationInFlight(state.connectionMutationInFlight);
    print("validation", activeMutation || "A connection command is already in progress; wait for it to finish.");
    return;
  }
  const request = connectPayload();
  if (!request.session_token && (!request.bootstrap_directory || !request.invite_key)) {
    endConnectionMutation("connect");
    const hint = state.connectRequireSession
      ? "session_token is required in session-required connect mode; sign in first"
      : state.allowLegacyConnectOverride && !state.productionMode
        ? "sign in + register client, or provide compatibility bootstrap_directory + invite"
        : "sign in and register the client profile before connecting";
    print("validation", hint);
    return;
  }
  inviteKeyEl.value = "";
  try {
    const result = await call("connect", "control_connect", { request });
    updateConnectionDashboard("connect", result);
  } catch {
    applyConnectionSnapshot({
      state: formatConnectionStateLabel("disconnected"),
      detail: "Connect request failed. Review output diagnostics and retry.",
      routingMode: state.routingMode || ROUTING_DEFAULT_MODE,
      routingDetail: state.routingDetail || ROUTING_DEFAULT_DETAIL
    });
  } finally {
    endConnectionMutation("connect");
  }
});

compatEnableEl.addEventListener("change", () => {
  setCompatOverrideEnabled(compatEnableEl.checked);
  if (!compatEnableEl.checked) {
    bootstrapDirectoryEl.value = "";
    inviteKeyEl.value = "";
  }
});

disconnectBtnEl.addEventListener("click", async () => {
  if (!beginConnectionMutation("disconnect")) {
    const activeMutation = describeConnectionMutationInFlight(state.connectionMutationInFlight);
    print("validation", activeMutation || "A connection command is already in progress; wait for it to finish.");
    return;
  }
  try {
    const result = await call("disconnect", "control_disconnect");
    updateConnectionDashboard("disconnect", result);
  } catch {
    applyConnectionSnapshot({
      state: formatConnectionStateLabel("degraded"),
      detail: "Disconnect request failed. Verify tunnel status with Status/Health before retrying.",
      routingMode: state.routingMode || ROUTING_DEFAULT_MODE,
      routingDetail: state.routingDetail || ROUTING_DEFAULT_DETAIL
    });
  } finally {
    endConnectionMutation("disconnect");
  }
});

byId("status_btn").addEventListener("click", async () => {
  const result = await call("status", "control_status");
  updateConnectionDashboard("status", result);
});

byId("status_btn_server").addEventListener("click", async () => {
  const result = await call("status_server", "control_status");
  updateConnectionDashboard("status", result);
});

byId("diagnostics_btn").addEventListener("click", async () => {
  await call("diagnostics", "control_get_diagnostics");
});

byId("health_btn").addEventListener("click", async () => {
  const result = await call("health", "control_health");
  updateConnectionDashboard("health", result);
});

byId("set_profile_btn").addEventListener("click", async () => {
  if (!requireServerLifecycleEligibility("Set profile")) {
    return;
  }
  const request = { path_profile: byId("set_profile").value };
  await call("set_profile", "control_set_profile", { request });
});

byId("update_btn").addEventListener("click", async () => {
  await call("update", "control_update");
});

byId("service_status_btn").addEventListener("click", async () => {
  if (!requireServerTabEligibility("Check service status")) {
    return;
  }
  await call("service_status", "control_service_status");
});

byId("service_start_btn").addEventListener("click", async () => {
  if (!requireServerLifecycleEligibility("Start service")) {
    return;
  }
  if (!requireSessionToken("start the service")) {
    return;
  }
  await call("service_start", "control_service_start", { request: serviceLifecycleRequest() });
});

byId("service_stop_btn").addEventListener("click", async () => {
  if (!requireServerLifecycleEligibility("Stop service")) {
    return;
  }
  if (!requireSessionToken("stop the service")) {
    return;
  }
  await call("service_stop", "control_service_stop", { request: serviceLifecycleRequest() });
});

byId("service_restart_btn").addEventListener("click", async () => {
  if (!requireServerLifecycleEligibility("Restart service")) {
    return;
  }
  if (!requireSessionToken("restart the service")) {
    return;
  }
  await call("service_restart", "control_service_restart", { request: serviceLifecycleRequest() });
});

async function init() {
  setRole("client", { persist: false });
  restorePersistedSessionErgonomics();
  activateTab("client");
  applyConnectModePolicy(false);
  updateAuthVerifyPolicyHint();
  applyConnectionSnapshot({
    state: CONNECTION_DEFAULT_STATE,
    detail: CONNECTION_DEFAULT_DETAIL
  });
  syncReadinessFreshnessIndicator();
  try {
    const cfg = await invoke("control_config");
    const meta = formatConfigMeta(cfg || {});
    let legacyAliasTelemetry = readRuntimeLegacyAliasTelemetry(cfg || {});
    let connectRequireSession = meta.connectRequireSession;
    let productionMode = meta.productionMode;
    let productionModeSource = CONNECT_POLICY_SOURCE_ENV_DEFAULT;
    let allowLegacyConnectOverride = meta.allowLegacyConnectOverride;
    let connectPolicySource = CONNECT_POLICY_SOURCE_ENV_DEFAULT;
    let connectPolicyMode = connectPolicyModeFromRequireSession(connectRequireSession);
    let authVerifyRequireMetadata = meta.authVerifyRequireMetadata;
    let authVerifyRequireWalletExtensionSource = meta.authVerifyRequireWalletExtensionSource;
    let authVerifyRequireCryptoProof = meta.authVerifyRequireCryptoProof;
    let authVerifyRuntimeRequireWalletExtensionSource = false;
    let authVerifyPolicySource = AUTH_VERIFY_POLICY_SOURCE_ENV_DEFAULT;
    let operatorApprovalRequireSession = false;
    let operatorApprovalPolicySource = OPERATOR_APPROVAL_POLICY_SOURCE_ENV_DEFAULT;
    let manifestRequireHttps = state.manifestRequireHTTPS;
    let manifestRequireSignature = state.manifestRequireSignature;
    let manifestTrustPolicySource = BOOTSTRAP_TRUST_POLICY_SOURCE_ENV_DEFAULT;
    let profileGateAllowRemoteHttpProbe = state.profileGateAllowRemoteHttpProbe;
    let profileGateAllowInsecureProbe = state.profileGateAllowInsecureProbe;
    let profileGateProbePolicySource = PROFILE_GATE_PROBE_POLICY_SOURCE_ENV_DEFAULT;
    try {
      const runtimeCfg = await invoke("control_runtime_config");
      const runtimeConnectPolicy = readRuntimeConnectPolicyMetadata(runtimeCfg || {});
      const runtimeAuthVerifyPolicy = readRuntimeAuthVerifyPolicyMetadata(runtimeCfg || {});
      const runtimeOperatorApprovalPolicy = readRuntimeOperatorApprovalPolicyMetadata(runtimeCfg || {});
      const runtimeBootstrapPolicy = readRuntimeBootstrapTrustPolicyMetadata(runtimeCfg || {});
      const runtimeProfileGateProbePolicy = readRuntimeProfileGateProbePolicyMetadata(runtimeCfg || {});
      const runtimeProductionMode = readRuntimeProductionModeMetadata(
        runtimeCfg || {},
        runtimeConnectPolicy,
        runtimeAuthVerifyPolicy
      );
      legacyAliasTelemetry = mergeLegacyAliasTelemetry(
        legacyAliasTelemetry,
        readRuntimeLegacyAliasTelemetry(runtimeCfg || {})
      );
      productionMode = runtimeProductionMode.productionMode === true;
      productionModeSource = runtimeProductionMode.productionModeSource || CONNECT_POLICY_SOURCE_RUNTIME_CONFIG;
      if (runtimeConnectPolicy.connectRequireSession !== undefined) {
        connectRequireSession = runtimeConnectPolicy.connectRequireSession;
      }
      if (runtimeConnectPolicy.allowLegacyConnectOverride !== undefined) {
        allowLegacyConnectOverride = runtimeConnectPolicy.allowLegacyConnectOverride;
      }
      if (runtimeConnectPolicy.connectPolicySource) {
        connectPolicySource = runtimeConnectPolicy.connectPolicySource;
      } else if (
        runtimeConnectPolicy.connectRequireSession !== undefined ||
        runtimeConnectPolicy.allowLegacyConnectOverride !== undefined ||
        runtimeConnectPolicy.connectPolicyMode
      ) {
        connectPolicySource = CONNECT_POLICY_SOURCE_RUNTIME_CONFIG;
      }
      connectPolicyMode =
        runtimeConnectPolicy.connectPolicyMode || connectPolicyModeFromRequireSession(connectRequireSession);
      if (runtimeAuthVerifyPolicy.authVerifyRequireMetadata !== undefined) {
        authVerifyRequireMetadata = runtimeAuthVerifyPolicy.authVerifyRequireMetadata;
      }
      if (runtimeAuthVerifyPolicy.authVerifyRequireWalletExtensionSource !== undefined) {
        authVerifyRequireWalletExtensionSource = runtimeAuthVerifyPolicy.authVerifyRequireWalletExtensionSource;
        authVerifyRuntimeRequireWalletExtensionSource =
          runtimeAuthVerifyPolicy.authVerifyRequireWalletExtensionSource === true;
      }
      if (runtimeAuthVerifyPolicy.authVerifyRequireCryptoProof !== undefined) {
        authVerifyRequireCryptoProof = runtimeAuthVerifyPolicy.authVerifyRequireCryptoProof;
      }
      if (runtimeAuthVerifyPolicy.authVerifyPolicySource) {
        authVerifyPolicySource = runtimeAuthVerifyPolicy.authVerifyPolicySource;
      } else if (
        runtimeAuthVerifyPolicy.authVerifyRequireMetadata !== undefined ||
        runtimeAuthVerifyPolicy.authVerifyRequireWalletExtensionSource !== undefined ||
        runtimeAuthVerifyPolicy.authVerifyRequireCryptoProof !== undefined ||
        runtimeAuthVerifyPolicy.authVerifyRequireCryptoProofPolicySource
      ) {
        authVerifyPolicySource = AUTH_VERIFY_POLICY_SOURCE_RUNTIME_CONFIG;
      }
      if (runtimeOperatorApprovalPolicy.operatorApprovalRequireSession !== undefined) {
        operatorApprovalRequireSession = runtimeOperatorApprovalPolicy.operatorApprovalRequireSession === true;
      }
      if (runtimeOperatorApprovalPolicy.operatorApprovalPolicySource) {
        operatorApprovalPolicySource = runtimeOperatorApprovalPolicy.operatorApprovalPolicySource;
      } else if (runtimeOperatorApprovalPolicy.operatorApprovalRequireSession !== undefined) {
        operatorApprovalPolicySource = OPERATOR_APPROVAL_POLICY_SOURCE_RUNTIME_CONFIG;
      }
      if (runtimeBootstrapPolicy.manifestRequireHttps !== undefined) {
        manifestRequireHttps = runtimeBootstrapPolicy.manifestRequireHttps;
      }
      if (runtimeBootstrapPolicy.manifestRequireSignature !== undefined) {
        manifestRequireSignature = runtimeBootstrapPolicy.manifestRequireSignature;
      }
      if (runtimeBootstrapPolicy.manifestTrustPolicySource) {
        manifestTrustPolicySource = runtimeBootstrapPolicy.manifestTrustPolicySource;
      } else if (
        runtimeBootstrapPolicy.manifestRequireHttps !== undefined ||
        runtimeBootstrapPolicy.manifestRequireSignature !== undefined
      ) {
        manifestTrustPolicySource = BOOTSTRAP_TRUST_POLICY_SOURCE_RUNTIME_CONFIG;
      }
      if (runtimeProfileGateProbePolicy.allowRemoteHttpProbe !== undefined) {
        profileGateAllowRemoteHttpProbe = runtimeProfileGateProbePolicy.allowRemoteHttpProbe;
      }
      if (runtimeProfileGateProbePolicy.allowInsecureProbe !== undefined) {
        profileGateAllowInsecureProbe = runtimeProfileGateProbePolicy.allowInsecureProbe;
      }
      if (runtimeProfileGateProbePolicy.profileGateProbePolicySource) {
        profileGateProbePolicySource = runtimeProfileGateProbePolicy.profileGateProbePolicySource;
      } else if (
        runtimeProfileGateProbePolicy.allowRemoteHttpProbe !== undefined ||
        runtimeProfileGateProbePolicy.allowInsecureProbe !== undefined
      ) {
        profileGateProbePolicySource = PROFILE_GATE_PROBE_POLICY_SOURCE_RUNTIME_CONFIG;
      }
    } catch {
      productionModeSource = CONNECT_POLICY_SOURCE_ENV_DEFAULT;
      connectPolicySource = CONNECT_POLICY_SOURCE_ENV_DEFAULT;
      connectPolicyMode = connectPolicyModeFromRequireSession(connectRequireSession);
      authVerifyRuntimeRequireWalletExtensionSource = false;
      authVerifyRequireCryptoProof = false;
      authVerifyPolicySource = AUTH_VERIFY_POLICY_SOURCE_ENV_DEFAULT;
      operatorApprovalRequireSession = false;
      operatorApprovalPolicySource = OPERATOR_APPROVAL_POLICY_SOURCE_ENV_DEFAULT;
      manifestTrustPolicySource = BOOTSTRAP_TRUST_POLICY_SOURCE_ENV_DEFAULT;
      profileGateProbePolicySource = PROFILE_GATE_PROBE_POLICY_SOURCE_ENV_DEFAULT;
    }
    state.connectPolicySource = connectPolicySource;
    state.connectPolicyMode = connectPolicyMode;
    state.productionMode = productionMode === true;
    state.productionModeSource = productionModeSource || CONNECT_POLICY_SOURCE_ENV_DEFAULT;
    state.allowLegacyConnectOverride = !!allowLegacyConnectOverride;
    state.authVerifyRequireMetadata = !!authVerifyRequireMetadata;
    state.authVerifyRequireWalletExtensionSource = !!authVerifyRequireWalletExtensionSource;
    state.authVerifyRequireCryptoProof = !!authVerifyRequireCryptoProof;
    state.authVerifyRuntimeRequireWalletExtensionSource = authVerifyRuntimeRequireWalletExtensionSource;
    state.authVerifyPolicySource = authVerifyPolicySource;
    state.operatorApprovalRequireSession = operatorApprovalRequireSession === true;
    state.operatorApprovalPolicySource = operatorApprovalPolicySource;
    state.manifestRequireHTTPS = manifestRequireHttps;
    state.manifestRequireSignature = manifestRequireSignature;
    state.manifestTrustPolicySource = manifestTrustPolicySource;
    state.profileGateAllowRemoteHttpProbe = profileGateAllowRemoteHttpProbe;
    state.profileGateAllowInsecureProbe = profileGateAllowInsecureProbe;
    state.profileGateProbePolicySource = profileGateProbePolicySource;
    state.legacyEnvAliasesActive = legacyAliasTelemetry.activeAliases;
    state.legacyEnvAliasWarnings = legacyAliasTelemetry.warnings;
    state.legacyEnvAliasActiveCount = legacyAliasTelemetry.activeCount;
    apiBaseEl.textContent = meta.apiLine;
    apiHintsEl.textContent = [
      meta.hintLine,
      formatProductionModeSourceHint(state.productionMode, state.productionModeSource),
      formatConnectPolicySourceHint(connectPolicySource, connectPolicyMode),
      formatAuthVerifyPolicySourceHint(
        authVerifyPolicySource,
        state.authVerifyRequireMetadata,
        state.authVerifyRequireWalletExtensionSource,
        state.authVerifyRequireCryptoProof
      ),
      formatOperatorApprovalPolicySourceHint(operatorApprovalPolicySource, state.operatorApprovalRequireSession),
      formatBootstrapTrustPolicyHint(state.manifestRequireHTTPS, state.manifestRequireSignature, state.manifestTrustPolicySource),
      formatProfileGateProbePolicyHint(
        state.profileGateAllowRemoteHttpProbe,
        state.profileGateAllowInsecureProbe,
        state.profileGateProbePolicySource
      )
    ]
      .filter((value) => typeof value === "string" && value.trim().length > 0)
      .join(" | ");
    updateBtnEl.disabled = !meta.updateMutationsEnabled;
    state.serviceMutationsAllowed = meta.serviceMutationsEnabled;
    applyConnectModePolicy(connectRequireSession);
    updateAuthVerifyPolicyHint();
    updateOperatorApprovalPolicyHint();
    updateLegacyAliasRuntimeHint();
    syncServerRoleLockState();
  } catch (err) {
    apiBaseEl.textContent = "API: unavailable";
    apiHintsEl.textContent = "";
    updateBtnEl.disabled = true;
    state.serviceMutationsAllowed = false;
    state.connectPolicySource = CONNECT_POLICY_SOURCE_ENV_DEFAULT;
    state.connectPolicyMode = CONNECT_POLICY_MODE_COMPAT_ALLOWED;
    state.productionMode = false;
    state.productionModeSource = CONNECT_POLICY_SOURCE_ENV_DEFAULT;
    state.allowLegacyConnectOverride = false;
    state.authVerifyRequireMetadata = false;
    state.authVerifyRequireWalletExtensionSource = false;
    state.authVerifyRequireCryptoProof = false;
    state.authVerifyRuntimeRequireWalletExtensionSource = false;
    state.authVerifyPolicySource = AUTH_VERIFY_POLICY_SOURCE_ENV_DEFAULT;
    state.operatorApprovalRequireSession = false;
    state.operatorApprovalPolicySource = OPERATOR_APPROVAL_POLICY_SOURCE_ENV_DEFAULT;
    state.manifestRequireHTTPS = undefined;
    state.manifestRequireSignature = undefined;
    state.manifestTrustPolicySource = BOOTSTRAP_TRUST_POLICY_SOURCE_ENV_DEFAULT;
    state.profileGateAllowRemoteHttpProbe = undefined;
    state.profileGateAllowInsecureProbe = undefined;
    state.profileGateProbePolicySource = PROFILE_GATE_PROBE_POLICY_SOURCE_ENV_DEFAULT;
    state.legacyEnvAliasesActive = [];
    state.legacyEnvAliasWarnings = [];
    state.legacyEnvAliasActiveCount = 0;
    applyConnectModePolicy(false);
    updateAuthVerifyPolicyHint();
    updateOperatorApprovalPolicyHint();
    updateLegacyAliasRuntimeHint();
    syncServerRoleLockState();
    print("init (error)", err);
  }

  try {
    await loadManifest();
  } catch {
    renderBootstrapManifestTrustUnavailable("Manifest lookup failed; use Manifest to retry and confirm trust posture.");
  }

  await refreshSessionOnInit();
  bindReadinessHeartbeatListeners();
  startReadinessHeartbeat();
  void runReadinessHeartbeat("init");
}

init();
