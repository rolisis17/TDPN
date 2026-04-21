function byId(id) {
  const el = document.getElementById(id);
  if (!el) {
    throw new Error(`missing element: ${id}`);
  }
  return el;
}

const outputEl = byId("output");
const statusBannerEl = byId("status_banner");
const statusTitleEl = byId("status_title");
const statusDetailEl = byId("status_detail");
const statusLineEl = byId("status_line");
const onboardingStateBannerEl = byId("onboarding_state_banner");
const onboardingStateLineEl = byId("onboarding_state_line");
const onboardingStateTitleEl = byId("onboarding_state_title");
const onboardingStateDetailEl = byId("onboarding_state_detail");
const onboardingNextActionEl = byId("onboarding_next_action");
const policyPostureEl = byId("policy_posture");
const policyPostureLineEl = byId("policy_posture_line");
const policyConnectPolicyEl = byId("policy_connect_policy");
const policyAuthVerifyEl = byId("policy_auth_verify");
const configEndpointHintEl = byId("config_endpoint_hint");
const legacyAliasWarningEl = byId("legacy_alias_warning");
const legacyAliasWarningLineEl = byId("legacy_alias_warning_line");
const legacyAliasWarningTitleEl = byId("legacy_alias_warning_title");
const legacyAliasWarningDetailEl = byId("legacy_alias_warning_detail");
const operatorReadinessEl = byId("operator_readiness");
const operatorReadinessLineEl = byId("operator_readiness_line");
const operatorReadinessStatusEl = byId("operator_readiness_status");
const operatorReadinessGuidanceEl = byId("operator_readiness_guidance");
const endpointPostureEl = byId("endpoint_posture");
const endpointPostureLineEl = byId("endpoint_posture_line");
const endpointPostureStatusEl = byId("endpoint_posture_status");
const endpointPostureGuidanceEl = byId("endpoint_posture_guidance");
const localApiAuthTokenEl = byId("local_api_auth_token");
const clientReadinessEl = byId("client_readiness");
const clientReadinessLineEl = byId("client_readiness_line");
const clientReadinessStatusEl = byId("client_readiness_status");
const clientReadinessGuidanceEl = byId("client_readiness_guidance");
const bootstrapTrustStatusEl = byId("bootstrap_trust_status");
const bootstrapTrustStatusLineEl = byId("bootstrap_trust_status_line");
const bootstrapTrustStateEl = byId("bootstrap_trust_state");
const bootstrapTrustGuidanceEl = byId("bootstrap_trust_guidance");
const bootstrapTrustSummaryEl = byId("bootstrap_trust_summary");
const selectedApplicationUpdatedAtEl = byId("selected_application_updated_at");
const walletChainIdEl = byId("wallet_chain_id");
const challengeMessageEl = byId("challenge_message");
const operatorListStatusEl = byId("operator_list_status");
const operatorListSearchEl = byId("operator_list_search");
const operatorListLimitEl = byId("operator_list_limit");
const operatorListNextCursorEl = byId("operator_list_next_cursor");
const operatorListNextPageBtnEl = byId("operator_list_next_page_btn");
const auditLimitEl = byId("audit_limit");
const auditOffsetEl = byId("audit_offset");
const auditEventEl = byId("audit_event");
const auditWalletAddressEl = byId("audit_wallet_address");
const auditOrderEl = byId("audit_order");
const compatOverrideSectionEl = document.getElementById("compat_override_section");
const compatOverrideEl = byId("compat_override");
const compatOverrideHintEl = byId("compat_override_hint");
const bootstrapDirectoryEl = byId("bootstrap_directory");
const sessionBootstrapDirectoryEl = byId("session_bootstrap_directory");
const inviteKeyEl = byId("invite_key");
const registerClientBtnEl = byId("register_client_btn");
const applyOperatorBtnEl = byId("apply_operator_btn");
const approveOperatorBtnEl = byId("approve_operator_btn");
const rejectOperatorBtnEl = byId("reject_operator_btn");
const adminTokenEl = byId("admin_token");
const operatorApprovalPolicyHintEl = byId("operator_approval_policy_hint");
const manualSignInBtnEl = byId("signin_btn");
const signinPolicyHintEl = document.getElementById("signin_policy_hint");
const walletExtensionHintEl = document.getElementById("wallet_extension_hint");
const connectionSnapshotEl = byId("connection_snapshot");
const connectionSnapshotLineEl = byId("connection_snapshot_line");
const connectionStateEl = byId("connection_state");
const connectionDetailEl = byId("connection_detail");
const connectionRoutingLineEl = byId("connection_routing_line");
const connectionRoutingModeEl = byId("connection_routing_mode");
const connectionRoutingDetailEl = byId("connection_routing_detail");
const tabClientEl = byId("tab_client");
const tabServerEl = byId("tab_server");
const panelClientEl = byId("panel_client");
const panelServerEl = byId("panel_server");
const clientLockHintEl = byId("client_lock_hint");
const serverLockHintEl = byId("server_lock_hint");
const serverLifecycleHintEl = byId("server_lifecycle_hint");
const serverStartBtnEl = byId("server_start_btn");
const serverStopBtnEl = byId("server_stop_btn");
const serverRestartBtnEl = byId("server_restart_btn");
const connectBtnEl = byId("connect_btn");
const connectPolicyHintEl = byId("connect_policy_hint");
const connectInterfaceEl = byId("connect_interface");
const connectDiscoveryWaitSecEl = byId("connect_discovery_wait_sec");
const connectReadyTimeoutSecEl = byId("connect_ready_timeout_sec");
const connectRunPreflightEl = byId("connect_run_preflight");
const connectProdProfileEl = byId("connect_prod_profile");
const connectInstallRouteEl = byId("connect_install_route");
const onboardingStepSigninEl = document.getElementById("onboarding_step_signin");
const onboardingStepClientEl = document.getElementById("onboarding_step_client");
const onboardingStepOperatorEl = document.getElementById("onboarding_step_operator");
const actionButtons = Array.from(document.querySelectorAll(".actions button"));
const OPERATOR_APPLICATION_STATUSES = new Set(["not_submitted", "pending", "approved", "rejected"]);
const SERVER_ONLY_ROLES = new Set(["server", "server_only"]);
const CLIENT_REGISTRATION_TRUST_DRIFT_STATUS_KEYS = new Set([
  "trust_drift",
  "registration_trust_drift",
  "manifest_drift",
  "degraded_trust",
  "trust_degraded",
  "stale",
  "stale_readiness",
  "stale_registration",
  "revoked",
  "untrusted",
  "re_registration_required",
  "reregister_required",
  "re_register_required"
]);
const OPERATOR_LIST_STATUS_FILTERS = new Set(["pending", "approved", "rejected"]);
const OPERATOR_PENDING_LIST_LIMIT = 25;
const OPERATOR_LOAD_NEXT_LIMIT = 1;
const OPERATOR_LIST_ALL_LIMIT = 100;
const AUDIT_RECENT_DEFAULT_LIMIT = 25;
const AUDIT_RECENT_MAX_LIMIT = 200;
const AUDIT_RECENT_DEFAULT_ORDER = "desc";
const AUDIT_RECENT_ORDERS = new Set(["desc", "asc"]);
const OPERATOR_DECISION_CONFLICT_GUIDANCE =
  "Decision conflict detected: the selected application was updated by another reviewer. Reload pending queue with Load Next Pending and retry.";
const WALLET_EXTENSION_PROVIDERS = new Set(["keplr", "leap"]);
const CONNECT_POLICY_MODE_SESSION_REQUIRED = "session_required";
const CONNECT_POLICY_MODE_COMPAT_ALLOWED = "compat_allowed";
const CONNECT_POLICY_SOURCE_RUNTIME_CONFIG = "runtime_config";
const CONNECT_POLICY_SOURCE_ENV_DEFAULT = "env_default";
const CONNECT_POLICY_SOURCE_LEGACY_DERIVED = "legacy_payload";
const CONNECT_POLICY_SOURCE_CONFIG_UNAVAILABLE = "config_unavailable";
const LEGACY_ALIAS_ENV_NAME_REGEX = /\bTDPN_[A-Z0-9_]+\b/gi;
const PORTAL_STORAGE_KEY = "gpm.portal.state.v1";
const PORTAL_WORKSPACE_TAB_STORAGE_KEY = "gpm.portal.workspace_tab.v1";
const MAX_OUTPUT_CHARS = 64 * 1024;
const CONNECTION_DEFAULT_STATE = "Unknown";
const CONNECTION_DEFAULT_DETAIL = "Not checked yet";
const CONNECTION_DEFAULT_ROUTING_MODE = "Unknown";
const CONNECTION_DEFAULT_ROUTING_DETAIL = "Run Status to fetch current routing posture.";
const CONNECTION_HINT_KEYS = {
  state: ["connection_state", "state", "status", "phase", "mode"],
  connected: ["connected", "is_connected", "online", "active"],
  disconnected: ["disconnected", "is_disconnected", "offline"],
  healthy: ["healthy", "ok", "is_ok", "alive"],
  detail: ["detail", "details", "message", "reason", "error", "description"]
};
const CONNECTION_ROUTING_HINT_KEYS = {
  mode: [
    "routing_mode",
    "route_mode",
    "path_mode",
    "routing_strategy",
    "route_strategy",
    "resolve_policy",
    "routing_posture",
    "routing_state"
  ],
  detail: [
    "routing_detail",
    "route_detail",
    "resolve_policy_detail",
    "routing_reason",
    "route_reason",
    "fallback_reason",
    "relay_reason"
  ],
  direct: ["direct_path", "direct_mesh", "direct_mode", "using_direct", "direct_preferred", "direct_exit_forced"],
  relay: [
    "relay_active",
    "using_relay",
    "managed_relay",
    "relay_mode",
    "relay_fallback",
    "fallback_to_relay",
    "direct_exit_fallback"
  ]
};
const PERSISTED_FIELD_IDS = [
  "api_base",
  "role",
  "wallet_address",
  "wallet_provider",
  "wallet_chain_id",
  "chain_operator_id",
  "selected_application_updated_at",
  "server_label",
  "operator_list_status",
  "operator_list_search",
  "operator_list_limit",
  "audit_limit",
  "audit_offset",
  "audit_event",
  "audit_wallet_address",
  "audit_order",
  "path_profile",
  "bootstrap_directory",
  "session_bootstrap_directory",
  "connect_interface",
  "connect_discovery_wait_sec",
  "connect_ready_timeout_sec"
];
let operatorApplicationStatus = undefined;
let selectedApplicationUpdatedAtUtc = "";
let serverReadiness = null;
let clientRegistered = false;
let clientRegistrationTrustDriftDetected = false;
let clientRegistrationTrustDriftGuidance = "";
let connectRequireSession = false;
let allowLegacyConnectOverride = false;
let connectPolicyMode = CONNECT_POLICY_MODE_COMPAT_ALLOWED;
let connectPolicySource = CONNECT_POLICY_SOURCE_CONFIG_UNAVAILABLE;
let gpmProductionMode = false;
let authVerifyRequireMetadata = false;
let authVerifyRequireMetadataPolicySource = CONNECT_POLICY_SOURCE_LEGACY_DERIVED;
let authVerifyRequireWalletExtensionSource = false;
let authVerifyRequireWalletExtensionPolicySource = CONNECT_POLICY_SOURCE_LEGACY_DERIVED;
let authVerifyRequireCryptoProof = false;
let authVerifyRequireCryptoProofPolicySource = CONNECT_POLICY_SOURCE_LEGACY_DERIVED;
let operatorApprovalRequireSession = false;
let operatorApprovalRequireSessionPolicySource = CONNECT_POLICY_SOURCE_LEGACY_DERIVED;
let legacyAliasTelemetry = {
  active: false,
  aliases: [],
  migrationHints: []
};
let operatorListActiveFilters = {
  status: "",
  search: "",
  limit: OPERATOR_LIST_ALL_LIMIT
};
let operatorListNextCursor = "";
let walletSignatureContext = null;
let activeWorkspaceTab = "client";
let connectionState = CONNECTION_DEFAULT_STATE;
let connectionDetail = CONNECTION_DEFAULT_DETAIL;
let connectionRoutingMode = CONNECTION_DEFAULT_ROUTING_MODE;
let connectionRoutingDetail = CONNECTION_DEFAULT_ROUTING_DETAIL;
let bootstrapTrustTelemetry = null;

function localStore() {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

function snapshotPortalState() {
  const state = {};
  for (const id of PERSISTED_FIELD_IDS) {
    const el = document.getElementById(id);
    if (!el || typeof el.value !== "string") {
      continue;
    }
    state[id] = el.value;
  }
  return state;
}

function persistPortalState(overrides) {
  const store = localStore();
  if (!store) {
    return;
  }
  const state = snapshotPortalState();
  if (overrides && typeof overrides === "object") {
    Object.assign(state, overrides);
  }
  try {
    store.setItem(PORTAL_STORAGE_KEY, JSON.stringify(state));
  } catch {
    // Best effort only: ignore quota or browser storage errors.
  }
}

function restorePortalState() {
  const store = localStore();
  if (!store) {
    return;
  }
  const raw = store.getItem(PORTAL_STORAGE_KEY);
  if (!raw) {
    return;
  }
  let state = null;
  try {
    state = JSON.parse(raw);
  } catch {
    return;
  }
  if (!state || typeof state !== "object") {
    return;
  }
  if (typeof state.session_token === "string") {
    delete state.session_token;
    try {
      store.setItem(PORTAL_STORAGE_KEY, JSON.stringify(state));
    } catch {
      // Best effort only: ignore quota or browser storage errors.
    }
  }
  if (typeof state.local_api_auth_token === "string") {
    delete state.local_api_auth_token;
    try {
      store.setItem(PORTAL_STORAGE_KEY, JSON.stringify(state));
    } catch {
      // Best effort only: ignore quota or browser storage errors.
    }
  }
  for (const id of PERSISTED_FIELD_IDS) {
    if (typeof state[id] !== "string") {
      continue;
    }
    const el = document.getElementById(id);
    if (!el || typeof el.value !== "string") {
      continue;
    }
    el.value = state[id];
  }
}

function bindPersistenceListeners() {
  const persist = () => persistPortalState();
  for (const id of PERSISTED_FIELD_IDS) {
    const el = document.getElementById(id);
    if (!el) {
      continue;
    }
    el.addEventListener("input", persist);
    el.addEventListener("change", persist);
  }
}

function restoreWorkspaceTabPreference() {
  const store = localStore();
  if (!store) {
    activeWorkspaceTab = "client";
    return;
  }
  const persisted = store.getItem(PORTAL_WORKSPACE_TAB_STORAGE_KEY);
  activeWorkspaceTab = persisted === "server" ? "server" : "client";
}

function persistWorkspaceTabPreference() {
  const store = localStore();
  if (!store) {
    return;
  }
  try {
    store.setItem(PORTAL_WORKSPACE_TAB_STORAGE_KEY, activeWorkspaceTab === "server" ? "server" : "client");
  } catch {
    // Best effort only: ignore quota or browser storage errors.
  }
}

function readConfigObject(payload, candidates) {
  const source = payload && typeof payload === "object" ? payload : {};
  for (const key of candidates) {
    const value = source[key];
    if (value && typeof value === "object" && !Array.isArray(value)) {
      return value;
    }
  }
  return undefined;
}

function readConfigBoolean(payload, candidates) {
  const source = payload && typeof payload === "object" ? payload : {};
  const raw = firstDefined(...candidates.map((key) => source[key]));
  return parseBooleanLike(raw);
}

function readConfigString(payload, candidates) {
  const source = payload && typeof payload === "object" ? payload : {};
  return nonEmptyString(firstDefined(...candidates.map((key) => source[key])));
}

function runtimeConfigScopes(payload) {
  const root = payload && typeof payload === "object" ? payload : {};
  const rootConfig = readConfigObject(root, ["config"]) || {};
  const rootData = readConfigObject(root, ["data"]) || {};
  const rootDataConfig = readConfigObject(rootData, ["config"]) || {};
  const policy =
    readConfigObject(root, ["policy"]) ||
    readConfigObject(rootConfig, ["policy"]) ||
    readConfigObject(rootDataConfig, ["policy"]) ||
    {};
  const connectPolicy =
    readConfigObject(root, ["connect_policy", "connectPolicy"]) ||
    readConfigObject(rootConfig, ["connect_policy", "connectPolicy"]) ||
    readConfigObject(rootDataConfig, ["connect_policy", "connectPolicy"]) ||
    readConfigObject(policy, ["connect_policy", "connectPolicy", "connect"]) ||
    {};
  const authVerifyPolicy =
    readConfigObject(root, ["gpm_auth_verify_policy", "auth_verify_policy", "authVerifyPolicy"]) ||
    readConfigObject(rootConfig, ["gpm_auth_verify_policy", "auth_verify_policy", "authVerifyPolicy"]) ||
    readConfigObject(rootDataConfig, ["gpm_auth_verify_policy", "auth_verify_policy", "authVerifyPolicy"]) ||
    readConfigObject(policy, ["gpm_auth_verify", "auth_verify", "authVerify"]) ||
    {};
  return [root, rootConfig, rootDataConfig, policy, connectPolicy, authVerifyPolicy];
}

function normalizePolicySourceValue(value) {
  const raw = nonEmptyString(value);
  if (!raw) {
    return undefined;
  }
  const compact = raw.toLowerCase().replace(/[\s-]+/g, "_");
  if (
    compact === CONNECT_POLICY_SOURCE_RUNTIME_CONFIG ||
    compact === "runtime" ||
    compact === "runtime_policy"
  ) {
    return CONNECT_POLICY_SOURCE_RUNTIME_CONFIG;
  }
  if (
    compact === CONNECT_POLICY_SOURCE_ENV_DEFAULT ||
    compact === "default" ||
    compact === "env" ||
    compact === "environment"
  ) {
    return CONNECT_POLICY_SOURCE_ENV_DEFAULT;
  }
  if (compact === "legacy_config" || compact === "legacy_derived" || compact === CONNECT_POLICY_SOURCE_LEGACY_DERIVED) {
    return CONNECT_POLICY_SOURCE_LEGACY_DERIVED;
  }
  if (compact === "unavailable" || compact === CONNECT_POLICY_SOURCE_CONFIG_UNAVAILABLE) {
    return CONNECT_POLICY_SOURCE_CONFIG_UNAVAILABLE;
  }
  return raw;
}

function normalizeConnectPolicyMode(value) {
  const raw = nonEmptyString(value);
  if (!raw) {
    return undefined;
  }
  const compact = raw.toLowerCase().replace(/[\s-]+/g, "_");
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
  if (compact === "production" || compact === "default") {
    return compact;
  }
  return compact;
}

function connectPolicyModeFromRequireSession(requireSession) {
  return requireSession ? CONNECT_POLICY_MODE_SESSION_REQUIRED : CONNECT_POLICY_MODE_COMPAT_ALLOWED;
}

function deriveGpmProductionModeFromPolicyHints(mode, source) {
  const normalizedMode = normalizeConnectPolicyMode(mode);
  const normalizedSource = normalizePolicySourceValue(source);
  if (normalizedMode === "production") {
    return true;
  }
  if (
    normalizedSource === CONNECT_POLICY_SOURCE_ENV_DEFAULT &&
    (normalizedMode === CONNECT_POLICY_MODE_SESSION_REQUIRED || normalizedMode === "default")
  ) {
    return true;
  }
  return false;
}

function parseConnectRequireSessionConfig(payload) {
  const scopes = runtimeConfigScopes(payload);
  const parsed = firstDefined(
    ...scopes.map((scope) =>
      readConfigBoolean(scope, [
        "connect_require_session",
        "connectRequireSession",
        "require_session",
        "requireSession"
      ])
    )
  );
  return parsed === true;
}

function parseAllowLegacyConnectOverrideConfig(payload) {
  const scopes = runtimeConfigScopes(payload);
  const parsed = firstDefined(
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
  return parsed === true;
}

function parseConnectPolicyModeConfig(payload) {
  const scopes = runtimeConfigScopes(payload);
  const mode = firstDefined(
    ...scopes.map((scope) =>
      readConfigString(scope, ["connect_policy_mode", "connectPolicyMode", "connect_mode", "connectMode", "mode"])
    )
  );
  return normalizeConnectPolicyMode(mode);
}

function parseConnectPolicySourceConfig(payload) {
  const scopes = runtimeConfigScopes(payload);
  const source = firstDefined(
    ...scopes.map((scope) =>
      readConfigString(scope, ["connect_policy_source", "connectPolicySource", "policy_source", "policySource", "source"])
    )
  );
  return normalizePolicySourceValue(source) || CONNECT_POLICY_SOURCE_LEGACY_DERIVED;
}

function parseGpmProductionModeConfig(payload) {
  const scopes = runtimeConfigScopes(payload);
  return firstDefined(
    ...scopes.map((scope) =>
      readConfigBoolean(scope, [
        "gpm_production_mode",
        "gpmProductionMode",
        "production_mode",
        "productionMode",
        "tdpn_production_mode",
        "tdpnProductionMode"
      ])
    )
  );
}

function parseAuthVerifyRequireMetadataConfig(payload) {
  const scopes = runtimeConfigScopes(payload);
  const parsed = firstDefined(
    ...scopes.map((scope) =>
      readConfigBoolean(scope, [
        "gpm_auth_verify_require_metadata",
        "gpmAuthVerifyRequireMetadata",
        "auth_verify_require_metadata",
        "authVerifyRequireMetadata"
      ])
    )
  );
  return parsed === true;
}

function parseAuthVerifyRequireMetadataPolicySourceConfig(payload) {
  const scopes = runtimeConfigScopes(payload);
  const source = firstDefined(
    ...scopes.map((scope) =>
      readConfigString(scope, [
        "gpm_auth_verify_require_metadata_policy_source",
        "gpmAuthVerifyRequireMetadataPolicySource",
        "auth_verify_require_metadata_policy_source",
        "authVerifyRequireMetadataPolicySource"
      ])
    )
  );
  return normalizePolicySourceValue(source) || CONNECT_POLICY_SOURCE_LEGACY_DERIVED;
}

function parseAuthVerifyRequireWalletExtensionSourceConfig(payload) {
  const scopes = runtimeConfigScopes(payload);
  const parsed = firstDefined(
    ...scopes.map((scope) =>
      readConfigBoolean(scope, [
        "gpm_auth_verify_require_wallet_extension_source",
        "gpmAuthVerifyRequireWalletExtensionSource",
        "auth_verify_require_wallet_extension_source",
        "authVerifyRequireWalletExtensionSource",
        "require_wallet_extension_source",
        "requireWalletExtensionSource"
      ])
    )
  );
  return parsed === true;
}

function parseAuthVerifyRequireWalletExtensionPolicySourceConfig(payload) {
  const scopes = runtimeConfigScopes(payload);
  const source = firstDefined(
    ...scopes.map((scope) =>
      readConfigString(scope, [
        "gpm_auth_verify_require_wallet_extension_policy_source",
        "gpmAuthVerifyRequireWalletExtensionPolicySource",
        "auth_verify_require_wallet_extension_policy_source",
        "authVerifyRequireWalletExtensionPolicySource"
      ])
    )
  );
  return normalizePolicySourceValue(source) || CONNECT_POLICY_SOURCE_LEGACY_DERIVED;
}

function parseAuthVerifyRequireCryptoProofConfig(payload) {
  const scopes = runtimeConfigScopes(payload);
  const parsed = firstDefined(
    ...scopes.map((scope) =>
      readConfigBoolean(scope, [
        "gpm_auth_verify_require_crypto_proof",
        "gpmAuthVerifyRequireCryptoProof",
        "auth_verify_require_crypto_proof",
        "authVerifyRequireCryptoProof",
        "require_crypto_proof",
        "requireCryptoProof"
      ])
    )
  );
  return parsed === true;
}

function parseAuthVerifyRequireCryptoProofPolicySourceConfig(payload) {
  const scopes = runtimeConfigScopes(payload);
  const source = firstDefined(
    ...scopes.map((scope) =>
      readConfigString(scope, [
        "gpm_auth_verify_require_crypto_proof_policy_source",
        "gpmAuthVerifyRequireCryptoProofPolicySource",
        "auth_verify_require_crypto_proof_policy_source",
        "authVerifyRequireCryptoProofPolicySource"
      ])
    )
  );
  return normalizePolicySourceValue(source) || CONNECT_POLICY_SOURCE_LEGACY_DERIVED;
}

function parseOperatorApprovalRequireSessionConfig(payload) {
  const scopes = runtimeConfigScopes(payload);
  const parsed = firstDefined(
    ...scopes.map((scope) =>
      readConfigBoolean(scope, [
        "gpm_operator_approval_require_session",
        "gpmOperatorApprovalRequireSession",
        "operator_approval_require_session",
        "operatorApprovalRequireSession"
      ])
    )
  );
  return parsed === true;
}

function parseOperatorApprovalRequireSessionPolicySourceConfig(payload) {
  const scopes = runtimeConfigScopes(payload);
  const source = firstDefined(
    ...scopes.map((scope) =>
      readConfigString(scope, [
        "gpm_operator_approval_require_session_policy_source",
        "gpmOperatorApprovalRequireSessionPolicySource",
        "operator_approval_require_session_policy_source",
        "operatorApprovalRequireSessionPolicySource"
      ])
    )
  );
  return normalizePolicySourceValue(source) || CONNECT_POLICY_SOURCE_LEGACY_DERIVED;
}

function normalizeLegacyAliasName(value) {
  const text = nonEmptyString(value);
  if (!text) {
    return "";
  }
  const candidate = text.toUpperCase();
  if (/^TDPN_[A-Z0-9_]+$/.test(candidate)) {
    return candidate;
  }
  return "";
}

function pushLegacyAliasNames(target, value, depth = 0) {
  if (depth > 6 || value === null || value === undefined) {
    return;
  }
  if (typeof value === "string") {
    LEGACY_ALIAS_ENV_NAME_REGEX.lastIndex = 0;
    const matches = value.match(LEGACY_ALIAS_ENV_NAME_REGEX);
    if (!matches) {
      return;
    }
    for (const match of matches) {
      const aliasName = normalizeLegacyAliasName(match);
      if (aliasName) {
        pushUniqueNonEmptyString(target, aliasName);
      }
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const entry of value) {
      pushLegacyAliasNames(target, entry, depth + 1);
    }
    return;
  }
  if (typeof value === "object") {
    for (const [key, entry] of Object.entries(value)) {
      const keyAliasName = normalizeLegacyAliasName(key);
      if (keyAliasName) {
        pushUniqueNonEmptyString(target, keyAliasName);
      }
      pushLegacyAliasNames(target, entry, depth + 1);
    }
  }
}

function pushLegacyAliasMigrationHint(target, value) {
  const text = nonEmptyString(value);
  if (!text) {
    return;
  }
  pushUniqueNonEmptyString(target, text);
}

function pushLegacyAliasMappingHints(aliases, hints, value, depth = 0) {
  if (depth > 4 || value === null || value === undefined) {
    return;
  }
  if (Array.isArray(value)) {
    for (const entry of value) {
      pushLegacyAliasMappingHints(aliases, hints, entry, depth + 1);
    }
    return;
  }
  if (typeof value !== "object") {
    pushLegacyAliasMigrationHint(hints, value);
    pushLegacyAliasNames(aliases, value);
    return;
  }

  const legacyAlias = normalizeLegacyAliasName(
    firstDefined(
      value.legacy_alias,
      value.legacyAlias,
      value.legacy_env,
      value.legacyEnv,
      value.alias,
      value.name,
      value.key
    )
  );
  const primaryEnv = nonEmptyString(
    firstDefined(
      value.primary_env,
      value.primaryEnv,
      value.primary_key,
      value.primaryKey,
      value.preferred_env,
      value.preferredEnv,
      value.replacement,
      value.target
    )
  );
  if (legacyAlias) {
    pushUniqueNonEmptyString(aliases, legacyAlias);
    const resolvedPrimary = primaryEnv || legacyAlias.replace(/^TDPN_/, "GPM_");
    pushUniqueNonEmptyString(hints, `Migrate ${legacyAlias} to ${resolvedPrimary}.`);
  }
  pushLegacyAliasMigrationHint(
    hints,
    firstDefined(value.hint, value.message, value.note, value.description, value.migration_hint, value.migrationHint)
  );

  for (const [key, entry] of Object.entries(value)) {
    const keyAlias = normalizeLegacyAliasName(key);
    if (keyAlias) {
      pushUniqueNonEmptyString(aliases, keyAlias);
      if (typeof entry === "string") {
        const preferredEnv = nonEmptyString(entry) || keyAlias.replace(/^TDPN_/, "GPM_");
        pushUniqueNonEmptyString(hints, `Migrate ${keyAlias} to ${preferredEnv}.`);
      }
    }
    pushLegacyAliasMappingHints(aliases, hints, entry, depth + 1);
  }
}

function parseLegacyAliasTelemetryConfig(payload, options = {}) {
  const policySources = Array.isArray(options.policySources) ? options.policySources : [];
  const scopes = runtimeConfigScopes(payload);
  const telemetryScopes = [...scopes];
  for (const scope of scopes) {
    const telemetryObject = readConfigObject(scope, [
      "legacy_alias_telemetry",
      "legacyAliasTelemetry",
      "legacy_aliases_telemetry",
      "legacyAliasesTelemetry",
      "compat_alias_telemetry",
      "compatAliasTelemetry"
    ]);
    if (telemetryObject) {
      telemetryScopes.push(telemetryObject);
    }
  }

  const explicitActive = firstDefined(
    ...telemetryScopes.map((scope) =>
      readConfigBoolean(scope, [
        "legacy_aliases_active",
        "legacyAliasesActive",
        "legacy_alias_active",
        "legacyAliasActive",
        "tdpn_aliases_active",
        "tdpnAliasesActive",
        "has_legacy_aliases",
        "hasLegacyAliases",
        "active"
      ])
    )
  );

  const aliases = [];
  const migrationHints = [];

  for (const scope of telemetryScopes) {
    for (const key of [
      "legacy_aliases",
      "legacyAliases",
      "legacy_alias_keys",
      "legacyAliasKeys",
      "active_aliases",
      "activeAliases",
      "tdpn_aliases",
      "tdpnAliases",
      "aliases",
      "env_aliases",
      "envAliases",
      "source_keys",
      "sourceKeys"
    ]) {
      pushLegacyAliasNames(aliases, scope?.[key]);
    }
    for (const key of [
      "legacy_alias_migration_hints",
      "legacyAliasMigrationHints",
      "migration_hints",
      "migrationHints",
      "messages",
      "notes"
    ]) {
      pushLegacyAliasMappingHints(aliases, migrationHints, scope?.[key]);
    }
    for (const key of [
      "legacy_alias_map",
      "legacyAliasMap",
      "alias_map",
      "aliasMap",
      "legacy_alias_mapping",
      "legacyAliasMapping",
      "migration_map",
      "migrationMap"
    ]) {
      pushLegacyAliasMappingHints(aliases, migrationHints, scope?.[key]);
    }
  }

  for (const source of policySources) {
    pushLegacyAliasNames(aliases, source);
  }

  const active = explicitActive === true || aliases.length > 0;
  return {
    active,
    aliases,
    migrationHints
  };
}

function formatConnectPolicyModeLabel(mode) {
  if (mode === "production") {
    return "production";
  }
  if (mode === "default") {
    return "default";
  }
  if (mode === CONNECT_POLICY_MODE_SESSION_REQUIRED) {
    return "session-required";
  }
  if (mode === CONNECT_POLICY_MODE_COMPAT_ALLOWED) {
    return "compat";
  }
  return nonEmptyString(mode)?.replace(/_/g, " ") || "compat";
}

function formatPolicySourceLabel(source) {
  const normalized = normalizePolicySourceValue(source);
  if (normalized === CONNECT_POLICY_SOURCE_RUNTIME_CONFIG) {
    return "runtime config";
  }
  if (normalized === CONNECT_POLICY_SOURCE_ENV_DEFAULT) {
    return "env default";
  }
  if (normalized === CONNECT_POLICY_SOURCE_LEGACY_DERIVED) {
    return "legacy /v1/config (derived)";
  }
  if (normalized === CONNECT_POLICY_SOURCE_CONFIG_UNAVAILABLE) {
    return "unavailable";
  }
  return nonEmptyString(source) || "default";
}

function configEndpointUnavailableFailClosedMode() {
  return connectPolicySource === CONNECT_POLICY_SOURCE_CONFIG_UNAVAILABLE;
}

function failClosedMutatingActionGuidance() {
  return "Restore the daemon config endpoint (/v1/config) first to re-enable Register Client, Connect, Operator Apply/Approve/Reject, and server lifecycle actions.";
}

function failClosedMutatingActionStatusDetail() {
  return `Restricted fail-closed mode: /v1/config is unavailable. ${failClosedMutatingActionGuidance()} Read-only status/session/audit actions remain available.`;
}

function refreshConfigEndpointHint() {
  if (configEndpointUnavailableFailClosedMode()) {
    configEndpointHintEl.textContent = failClosedMutatingActionStatusDetail();
    configEndpointHintEl.classList.add("locked");
    return;
  }
  configEndpointHintEl.textContent =
    "Runtime config endpoint /v1/config is available. Compatibility mode behavior is applied only when runtime config policy explicitly allows it.";
  configEndpointHintEl.classList.remove("locked");
}

function operatorApprovalAdminTokenFallbackAllowed() {
  return configEndpointUnavailableFailClosedMode() !== true && operatorApprovalRequireSession !== true;
}

function refreshOperatorApprovalPolicyHint() {
  if (!operatorApprovalPolicyHintEl || !adminTokenEl) {
    return;
  }

  const isBusy = document.body.classList.contains("is-busy");
  const configUnavailable = configEndpointUnavailableFailClosedMode();
  const adminTokenFallbackAllowed = operatorApprovalAdminTokenFallbackAllowed();
  const strictSessionPolicy = !configUnavailable && !adminTokenFallbackAllowed;
  const sourceLabel = formatPolicySourceLabel(operatorApprovalRequireSessionPolicySource);

  const lockByPolicy = configUnavailable || strictSessionPolicy;
  const disabled = isBusy || lockByPolicy;
  adminTokenEl.disabled = disabled;
  adminTokenEl.setAttribute("aria-disabled", String(disabled));

  if (configUnavailable) {
    adminTokenEl.value = "";
    adminTokenEl.title = failClosedMutatingActionStatusDetail();
    operatorApprovalPolicyHintEl.classList.add("locked");
    operatorApprovalPolicyHintEl.textContent =
      "Operator approval auth policy is unavailable because /v1/config could not be read. Approval/rejection mutations remain fail-closed until runtime config is reachable.";
    return;
  }

  if (strictSessionPolicy) {
    adminTokenEl.value = "";
    adminTokenEl.title = "Legacy admin token fallback is disabled by policy.";
    operatorApprovalPolicyHintEl.classList.add("locked");
    operatorApprovalPolicyHintEl.textContent =
      `Operator approval auth policy: admin session token required (source: ${sourceLabel}); legacy admin token fallback is disabled.`;
    return;
  }

  adminTokenEl.removeAttribute("title");
  operatorApprovalPolicyHintEl.classList.remove("locked");
  operatorApprovalPolicyHintEl.textContent =
    `Operator approval auth policy: session token preferred (source: ${sourceLabel}); legacy admin token fallback is available when needed.`;
}

function refreshConnectPolicyHint() {
  if (!connectPolicyHintEl) {
    return;
  }
  if (configEndpointUnavailableFailClosedMode()) {
    connectPolicyHintEl.textContent = failClosedMutatingActionStatusDetail();
    connectPolicyHintEl.classList.add("locked");
    return;
  }
  const mode = formatConnectPolicyModeLabel(connectPolicyMode);
  const source = formatPolicySourceLabel(connectPolicySource);
  let posture = "manual bootstrap/invite fields are optional compatibility controls.";
  if (gpmProductionMode) {
    posture = "manual bootstrap/invite overrides are disabled in production mode.";
  } else if (connectRequireSession) {
    posture = "manual bootstrap/invite overrides are locked by session-required policy.";
  } else if (!allowLegacyConnectOverride) {
    posture = "manual bootstrap/invite overrides are disabled by policy.";
  }
  connectPolicyHintEl.textContent = `Connect policy: ${mode} (source: ${source}); ${posture}`;
  connectPolicyHintEl.classList.toggle("locked", gpmProductionMode || connectRequireSession || !allowLegacyConnectOverride);
}

function refreshPolicyPostureBanner() {
  const configUnavailable = configEndpointUnavailableFailClosedMode();
  const strict =
    connectRequireSession ||
    authVerifyRequireMetadata ||
    authVerifyRequireWalletExtensionSource ||
    authVerifyRequireCryptoProof;
  const kind = configUnavailable ? "bad" : strict ? "warn" : "good";
  policyPostureEl.dataset.kind = kind;
  policyPostureLineEl.classList.remove("good", "warn", "bad");
  policyPostureLineEl.classList.add(kind);

  const connectMode = formatConnectPolicyModeLabel(connectPolicyMode);
  const connectSource = formatPolicySourceLabel(connectPolicySource);
  const legacyOverride = allowLegacyConnectOverride ? "legacy override enabled" : "legacy override locked";

  if (configUnavailable) {
    policyConnectPolicyEl.textContent = "Connect policy: restricted fail-closed (source: unavailable; legacy override locked).";
    policyAuthVerifyEl.textContent = failClosedMutatingActionStatusDetail();
    syncManualSignInAction();
    refreshConnectPolicyHint();
    refreshConfigEndpointHint();
    refreshOperatorApprovalPolicyHint();
    return;
  }
  policyConnectPolicyEl.textContent = `Connect policy: ${connectMode} (source: ${connectSource}; ${legacyOverride}).`;
  const metadataRequired = authVerifyRequireMetadata ? "required" : "optional";
  const metadataSource = formatPolicySourceLabel(authVerifyRequireMetadataPolicySource);
  const walletRequired = authVerifyRequireWalletExtensionSource ? "required" : "optional";
  const walletSource = formatPolicySourceLabel(authVerifyRequireWalletExtensionPolicySource);
  const cryptoProofRequired = authVerifyRequireCryptoProof ? "required" : "optional";
  const cryptoProofSource = nonEmptyString(authVerifyRequireCryptoProofPolicySource) || "default";
  const manualSignInGuidance = gpmProductionMode
    ? " Manual Verify + Create Session is disabled in production mode; use Sign + Verify (Wallet)."
    : authVerifyRequireWalletExtensionSource
      ? " Manual Verify + Create Session is disabled; use Sign + Verify (Wallet)."
      : authVerifyRequireCryptoProof
        ? " Manual Verify + Create Session is available for compatibility, but cryptographic proof metadata is required by policy; use Sign + Verify (Wallet) when possible."
        : " Manual Verify + Create Session is available for compatibility.";
  policyAuthVerifyEl.textContent =
    `Auth verify strictness: metadata ${metadataRequired} (source: ${metadataSource}); ` +
    `wallet-extension-source ${walletRequired} (source: ${walletSource}); ` +
    `crypto-proof ${cryptoProofRequired} (source: ${cryptoProofSource}).${manualSignInGuidance}`;
  syncManualSignInAction();
  refreshConnectPolicyHint();
  refreshConfigEndpointHint();
  refreshOperatorApprovalPolicyHint();
}

function refreshLegacyAliasWarningBanner() {
  const aliases = Array.isArray(legacyAliasTelemetry.aliases) ? legacyAliasTelemetry.aliases : [];
  const migrationHints = Array.isArray(legacyAliasTelemetry.migrationHints)
    ? legacyAliasTelemetry.migrationHints
    : [];
  const active = legacyAliasTelemetry.active === true || aliases.length > 0;

  legacyAliasWarningEl.hidden = !active;
  if (!active) {
    return;
  }

  legacyAliasWarningEl.dataset.kind = "warn";
  legacyAliasWarningLineEl.classList.remove("good", "warn", "bad");
  legacyAliasWarningLineEl.classList.add("warn");

  const aliasMappings = aliases.slice(0, 3).map((aliasName) => `${aliasName} -> ${aliasName.replace(/^TDPN_/, "GPM_")}`);
  const aliasOverflowCount = aliases.length > 3 ? aliases.length - 3 : 0;
  const mappingSummary = aliasMappings.length > 0 ? aliasMappings.join("; ") : "";
  const mappingOverflow = aliasOverflowCount > 0 ? ` (+${aliasOverflowCount} more)` : "";

  legacyAliasWarningTitleEl.textContent = mappingSummary
    ? `Legacy alias telemetry detected: ${mappingSummary}${mappingOverflow}.`
    : "Legacy TDPN_* alias telemetry detected.";

  const defaultHint =
    aliases.length > 0
      ? "Migrate active TDPN_* aliases to their matching GPM_* env names."
      : "Migrate TDPN_* aliases to GPM_* env names to avoid future breakage.";
  const hintSummary = migrationHints.slice(0, 2).join(" ");
  legacyAliasWarningDetailEl.textContent = hintSummary ? `${hintSummary} ${defaultHint}` : defaultHint;
}

function strictWalletExtensionSourceRequired() {
  return authVerifyRequireWalletExtensionSource === true;
}

function syncManualSignInAction() {
  if (!manualSignInBtnEl) {
    syncWalletExtensionReadinessHint();
    return;
  }
  const isBusy = document.body.classList.contains("is-busy");
  const productionLocked = gpmProductionMode === true;
  const authPolicyLocked = strictWalletExtensionSourceRequired();
  const policyLocked = productionLocked || authPolicyLocked;
  const cryptoProofGuidance = authVerifyRequireCryptoProof
    ? " Cryptographic proof metadata is required by policy; wallet-assisted verify can attach the active challenge context fields."
    : "";
  const disabled = isBusy || policyLocked;
  const guidance = productionLocked
    ? "Manual verify is disabled in production mode. Use Sign + Verify (Wallet)."
    : authPolicyLocked
      ? "Manual verify is disabled by active auth policy. Use Sign + Verify (Wallet)."
      : "Manual verify is available in compatibility mode.";

  manualSignInBtnEl.disabled = disabled;
  manualSignInBtnEl.setAttribute("aria-disabled", String(disabled));

  if (policyLocked) {
    manualSignInBtnEl.title = guidance;
  } else {
    manualSignInBtnEl.removeAttribute("title");
  }

  if (signinPolicyHintEl) {
    signinPolicyHintEl.textContent = `${guidance}${cryptoProofGuidance}`;
  }
  syncWalletExtensionReadinessHint();
}

function compatibilityOverrideEnabled() {
  return (
    gpmProductionMode !== true &&
    configEndpointUnavailableFailClosedMode() !== true &&
    allowLegacyConnectOverride === true &&
    compatOverrideEl.checked === true &&
    connectRequireSession !== true
  );
}

function refreshCompatibilityOverrideControls() {
  const failClosed = configEndpointUnavailableFailClosedMode();
  const productionLocked = gpmProductionMode === true;
  if (!allowLegacyConnectOverride && compatOverrideEl.checked) {
    compatOverrideEl.checked = false;
  }
  if (productionLocked && compatOverrideEl.checked) {
    compatOverrideEl.checked = false;
  }
  if (failClosed && compatOverrideEl.checked) {
    compatOverrideEl.checked = false;
  }
  if (connectRequireSession && compatOverrideEl.checked) {
    compatOverrideEl.checked = false;
  }
  const policyLocked = connectRequireSession === true || failClosed || productionLocked;
  const overrideEnabled = compatibilityOverrideEnabled();

  const compatDisabled = !allowLegacyConnectOverride || policyLocked;
  compatOverrideEl.disabled = compatDisabled;
  compatOverrideEl.setAttribute("aria-disabled", String(compatDisabled));

  bootstrapDirectoryEl.disabled = productionLocked || !allowLegacyConnectOverride || !overrideEnabled;
  bootstrapDirectoryEl.setAttribute("aria-disabled", String(!overrideEnabled));
  inviteKeyEl.disabled = productionLocked || !allowLegacyConnectOverride || !overrideEnabled;
  inviteKeyEl.setAttribute("aria-disabled", String(!overrideEnabled));
  refreshSessionBootstrapDirectoryControls();

  if (compatOverrideSectionEl) {
    compatOverrideSectionEl.hidden = !allowLegacyConnectOverride;
    if (gpmProductionMode) {
      compatOverrideSectionEl.hidden = true;
    }
  }

  if (failClosed) {
    compatOverrideHintEl.textContent =
      "Compatibility override is disabled in restricted fail-closed mode because /v1/config is unavailable. Restore the daemon config endpoint first.";
    return;
  }

  if (gpmProductionMode) {
    compatOverrideHintEl.textContent = "Compatibility override is disabled in production mode. Use session-based registration.";
    return;
  }

  if (!allowLegacyConnectOverride) {
    compatOverrideHintEl.textContent =
      "Compatibility override controls are disabled by policy. Use session-based registration.";
    return;
  }

  if (policyLocked) {
    compatOverrideHintEl.textContent =
      "Manual bootstrap/invite overrides are locked by policy. Session-based registration is required.";
    return;
  }
  if (overrideEnabled) {
    compatOverrideHintEl.textContent =
      "Compatibility override is on. Manual bootstrap/invite values will be sent when provided.";
    return;
  }
  compatOverrideHintEl.textContent =
    "Compatibility override is off by default. Keep it off for standard session-based registration.";
}

async function refreshConnectPolicyConfigBestEffort(options = {}) {
  const { quiet = true } = options;
  try {
    const config = await get("/v1/config");
    connectRequireSession = parseConnectRequireSessionConfig(config);
    allowLegacyConnectOverride = parseAllowLegacyConnectOverrideConfig(config);
    connectPolicyMode = parseConnectPolicyModeConfig(config) || connectPolicyModeFromRequireSession(connectRequireSession);
    connectPolicySource = parseConnectPolicySourceConfig(config);
    const parsedGpmProductionMode = parseGpmProductionModeConfig(config);
    gpmProductionMode =
      parsedGpmProductionMode !== undefined
        ? parsedGpmProductionMode
        : deriveGpmProductionModeFromPolicyHints(connectPolicyMode, connectPolicySource);
    authVerifyRequireMetadata = parseAuthVerifyRequireMetadataConfig(config);
    authVerifyRequireMetadataPolicySource = parseAuthVerifyRequireMetadataPolicySourceConfig(config);
    authVerifyRequireWalletExtensionSource = parseAuthVerifyRequireWalletExtensionSourceConfig(config);
    authVerifyRequireWalletExtensionPolicySource = parseAuthVerifyRequireWalletExtensionPolicySourceConfig(config);
    authVerifyRequireCryptoProof = parseAuthVerifyRequireCryptoProofConfig(config);
    authVerifyRequireCryptoProofPolicySource = parseAuthVerifyRequireCryptoProofPolicySourceConfig(config);
    operatorApprovalRequireSession = parseOperatorApprovalRequireSessionConfig(config);
    operatorApprovalRequireSessionPolicySource = parseOperatorApprovalRequireSessionPolicySourceConfig(config);
    legacyAliasTelemetry = parseLegacyAliasTelemetryConfig(config, {
      policySources: [
        connectPolicySource,
        authVerifyRequireMetadataPolicySource,
        authVerifyRequireWalletExtensionPolicySource,
        authVerifyRequireCryptoProofPolicySource,
        operatorApprovalRequireSessionPolicySource
      ]
    });
    refreshCompatibilityOverrideControls();
    refreshPolicyPostureBanner();
    refreshLegacyAliasWarningBanner();
    refreshClientReadiness();
    persistPortalState();
    return config;
  } catch (err) {
    connectRequireSession = false;
    allowLegacyConnectOverride = false;
    connectPolicyMode = connectPolicyModeFromRequireSession(connectRequireSession);
    connectPolicySource = CONNECT_POLICY_SOURCE_CONFIG_UNAVAILABLE;
    gpmProductionMode = false;
    authVerifyRequireMetadata = false;
    authVerifyRequireMetadataPolicySource = CONNECT_POLICY_SOURCE_CONFIG_UNAVAILABLE;
    authVerifyRequireWalletExtensionSource = false;
    authVerifyRequireWalletExtensionPolicySource = CONNECT_POLICY_SOURCE_CONFIG_UNAVAILABLE;
    authVerifyRequireCryptoProof = false;
    authVerifyRequireCryptoProofPolicySource = CONNECT_POLICY_SOURCE_CONFIG_UNAVAILABLE;
    operatorApprovalRequireSession = false;
    operatorApprovalRequireSessionPolicySource = CONNECT_POLICY_SOURCE_CONFIG_UNAVAILABLE;
    legacyAliasTelemetry = {
      active: false,
      aliases: [],
      migrationHints: []
    };
    refreshCompatibilityOverrideControls();
    refreshPolicyPostureBanner();
    refreshLegacyAliasWarningBanner();
    refreshClientReadiness();
    persistPortalState();
    if (!quiet) {
      throw err;
    }
    return undefined;
  }
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

function firstDefined(...values) {
  for (const value of values) {
    if (value !== undefined && value !== null) {
      return value;
    }
  }
  return undefined;
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

function isLiteralLoopbackHost(hostname) {
  if (typeof hostname !== "string") {
    return false;
  }
  const normalized = hostname.trim().toLowerCase();
  return normalized === "127.0.0.1" || normalized === "::1" || normalized === "[::1]";
}

function nonEmptyString(value) {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed || undefined;
}

function parseNonEmptyStringList(value) {
  const values = [];
  if (Array.isArray(value)) {
    for (const entry of value) {
      pushUniqueNonEmptyString(values, entry);
    }
    return values;
  }

  const text = nonEmptyString(value);
  if (!text) {
    return values;
  }

  if (text.includes("\n") || text.includes(";")) {
    for (const entry of text.split(/[\n;]+/)) {
      pushUniqueNonEmptyString(values, entry);
    }
    return values;
  }

  pushUniqueNonEmptyString(values, text);
  return values;
}

function pushUniqueNonEmptyString(target, value) {
  const parsed = nonEmptyString(value);
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
    nonEmptyString(
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

function extractBootstrapDirectoryOptions(payload) {
  const metadata = extractBootstrapRegistrationMetadata(payload);
  const directories = [];
  appendBootstrapDirectoryEntries(directories, metadata.directBootstrapDirectory);
  appendBootstrapDirectoryEntries(directories, metadata.bootstrapDirectories);
  return directories;
}

function refreshSessionBootstrapDirectoryControls() {
  if (!sessionBootstrapDirectoryEl) {
    return;
  }
  const hasSessionToken = Boolean(byId("session_token").value.trim());
  const disabled = !hasSessionToken || compatibilityOverrideEnabled();
  sessionBootstrapDirectoryEl.disabled = disabled;
  sessionBootstrapDirectoryEl.setAttribute("aria-disabled", String(disabled));
}

function refreshSessionBootstrapDirectoryOptions(payload) {
  if (!sessionBootstrapDirectoryEl) {
    return;
  }
  const directories = extractBootstrapDirectoryOptions(payload);
  const previousValue = nonEmptyString(sessionBootstrapDirectoryEl.value) || "";
  const optionNodes = [new Option("Auto (preferred entry)", "")];
  for (const directory of directories) {
    optionNodes.push(new Option(directory, directory));
  }
  sessionBootstrapDirectoryEl.replaceChildren(...optionNodes);
  const nextValue = previousValue && directories.includes(previousValue) ? previousValue : "";
  sessionBootstrapDirectoryEl.value = nextValue;
  if (nextValue !== previousValue) {
    persistPortalState();
  }
  refreshSessionBootstrapDirectoryControls();
}

function numberOrUndefined(value) {
  const parsed = Number(value);
  if (Number.isFinite(parsed) && parsed >= 0) {
    return parsed;
  }
  return undefined;
}

function positiveIntegerOrUndefined(value, minimum = 1) {
  const parsed = numberOrUndefined(value);
  if (parsed !== undefined && parsed >= minimum) {
    return Math.floor(parsed);
  }
  return undefined;
}

function normalizeOperatorListStatusFilter(value, fallback = "") {
  const normalize = (input) => {
    if (typeof input !== "string") {
      return undefined;
    }
    const normalized = input.trim().toLowerCase();
    if (!normalized || normalized === "all") {
      return "";
    }
    if (OPERATOR_LIST_STATUS_FILTERS.has(normalized)) {
      return normalized;
    }
    return undefined;
  };
  const parsed = normalize(value);
  if (parsed !== undefined) {
    return parsed;
  }
  const fallbackParsed = normalize(fallback);
  return fallbackParsed !== undefined ? fallbackParsed : "";
}

function normalizeOperatorListSearch(value) {
  if (typeof value !== "string") {
    return "";
  }
  return value.trim();
}

function normalizeOperatorListLimit(value, fallback = OPERATOR_LIST_ALL_LIMIT) {
  const parsed = numberOrUndefined(value);
  if (parsed !== undefined && parsed >= 1) {
    return Math.floor(parsed);
  }
  const fallbackParsed = numberOrUndefined(fallback);
  if (fallbackParsed !== undefined && fallbackParsed >= 1) {
    return Math.floor(fallbackParsed);
  }
  return OPERATOR_LIST_ALL_LIMIT;
}

function normalizeAuditRecentLimit(value, fallback = AUDIT_RECENT_DEFAULT_LIMIT) {
  const parsed = numberOrUndefined(value);
  if (parsed !== undefined && parsed >= 1) {
    return Math.min(Math.floor(parsed), AUDIT_RECENT_MAX_LIMIT);
  }
  const fallbackParsed = numberOrUndefined(fallback);
  if (fallbackParsed !== undefined && fallbackParsed >= 1) {
    return Math.min(Math.floor(fallbackParsed), AUDIT_RECENT_MAX_LIMIT);
  }
  return AUDIT_RECENT_DEFAULT_LIMIT;
}

function normalizeAuditRecentOffset(value, fallback = 0) {
  const parsed = numberOrUndefined(value);
  if (parsed !== undefined && parsed >= 0) {
    return Math.floor(parsed);
  }
  const fallbackParsed = numberOrUndefined(fallback);
  if (fallbackParsed !== undefined && fallbackParsed >= 0) {
    return Math.floor(fallbackParsed);
  }
  return 0;
}

function normalizeAuditRecentOrder(value, fallback = AUDIT_RECENT_DEFAULT_ORDER) {
  const normalized = nonEmptyString(value)?.toLowerCase();
  if (normalized && AUDIT_RECENT_ORDERS.has(normalized)) {
    return normalized;
  }
  const fallbackNormalized = nonEmptyString(fallback)?.toLowerCase();
  if (fallbackNormalized && AUDIT_RECENT_ORDERS.has(fallbackNormalized)) {
    return fallbackNormalized;
  }
  return AUDIT_RECENT_DEFAULT_ORDER;
}

function readAuditRecentFilters(options = {}) {
  return {
    limit: normalizeAuditRecentLimit(auditLimitEl.value, options.fallbackLimit),
    offset: normalizeAuditRecentOffset(auditOffsetEl.value, options.fallbackOffset),
    event: nonEmptyString(auditEventEl.value) || "",
    walletAddress: nonEmptyString(auditWalletAddressEl.value) || "",
    order: normalizeAuditRecentOrder(auditOrderEl.value, options.fallbackOrder)
  };
}

function buildAuditRecentPath(filters = {}) {
  const limit = normalizeAuditRecentLimit(filters.limit, AUDIT_RECENT_DEFAULT_LIMIT);
  const offset = normalizeAuditRecentOffset(filters.offset, 0);
  const event = nonEmptyString(filters.event) || "";
  const walletAddress = nonEmptyString(filters.walletAddress) || "";
  const order = normalizeAuditRecentOrder(filters.order, AUDIT_RECENT_DEFAULT_ORDER);
  const params = new URLSearchParams();
  params.set("limit", String(limit));
  if (offset > 0) {
    params.set("offset", String(offset));
  }
  if (event) {
    params.set("event", event);
  }
  if (walletAddress) {
    params.set("wallet_address", walletAddress);
  }
  if (order !== AUDIT_RECENT_DEFAULT_ORDER) {
    params.set("order", order);
  }
  return {
    path: `/v1/gpm/audit/recent?${params.toString()}`,
    request: {
      limit,
      offset,
      event,
      wallet_address: walletAddress,
      order
    }
  };
}

function operatorListStatusLabel(statusValue) {
  const normalized = normalizeOperatorListStatusFilter(statusValue, "");
  return normalized || "all";
}

function readOperatorListFilters(options = {}) {
  const { fallbackStatus = "", fallbackLimit = OPERATOR_LIST_ALL_LIMIT } = options;
  return {
    status: normalizeOperatorListStatusFilter(operatorListStatusEl.value, fallbackStatus),
    search: normalizeOperatorListSearch(operatorListSearchEl.value),
    limit: normalizeOperatorListLimit(operatorListLimitEl.value, fallbackLimit)
  };
}

function writeOperatorListFilters(filters = {}) {
  const status = normalizeOperatorListStatusFilter(filters.status, "");
  const search = normalizeOperatorListSearch(filters.search);
  const limit = normalizeOperatorListLimit(filters.limit, OPERATOR_LIST_ALL_LIMIT);
  operatorListStatusEl.value = status;
  operatorListSearchEl.value = search;
  operatorListLimitEl.value = String(limit);
}

function syncOperatorListNextPageAction() {
  const isBusy = document.body.classList.contains("is-busy");
  const disabled = isBusy || operatorListNextCursor.length === 0;
  operatorListNextPageBtnEl.disabled = disabled;
  operatorListNextPageBtnEl.setAttribute("aria-disabled", String(disabled));
}

function setOperatorListNextCursor(value) {
  operatorListNextCursor = normalizeOperatorListSearch(value);
  operatorListNextCursorEl.value = operatorListNextCursor;
  syncOperatorListNextPageAction();
}

function updateOperatorListContext(filters, nextCursor) {
  operatorListActiveFilters = {
    status: normalizeOperatorListStatusFilter(filters?.status, ""),
    search: normalizeOperatorListSearch(filters?.search),
    limit: normalizeOperatorListLimit(filters?.limit, OPERATOR_LIST_ALL_LIMIT)
  };
  writeOperatorListFilters(operatorListActiveFilters);
  setOperatorListNextCursor(nextCursor);
}

function operatorModerationReason() {
  return byId("operator_reason").value.trim();
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

function formatOperatorListItemLabel(entry, index) {
  if (typeof entry === "string") {
    return entry.trim() || `item-${index + 1}`;
  }
  if (!entry || typeof entry !== "object") {
    return `item-${index + 1}`;
  }
  return (
    nonEmptyString(entry.chain_operator_id) ||
    nonEmptyString(entry.operator_id) ||
    nonEmptyString(entry.wallet_address) ||
    nonEmptyString(entry.server_label) ||
    nonEmptyString(entry.id) ||
    `item-${index + 1}`
  );
}

function extractOperatorListPagination(payload, options = {}) {
  const { fallbackCursor = "" } = options;
  const cursor = nonEmptyString(
    firstDefined(
      payload?.cursor,
      payload?.request?.cursor,
      payload?.pagination?.cursor,
      payload?.pagination?.current_cursor,
      payload?.meta?.cursor,
      payload?.meta?.current_cursor,
      payload?.page?.cursor,
      fallbackCursor
    )
  );
  const nextCursor = nonEmptyString(
    firstDefined(
      payload?.next_cursor,
      payload?.nextCursor,
      payload?.pagination?.next_cursor,
      payload?.pagination?.nextCursor,
      payload?.pagination?.cursor_next,
      payload?.meta?.next_cursor,
      payload?.meta?.nextCursor,
      payload?.meta?.cursor_next,
      payload?.queue?.next_cursor,
      payload?.queue?.nextCursor,
      payload?.list?.next_cursor,
      payload?.list?.nextCursor,
      payload?.data?.next_cursor,
      payload?.data?.nextCursor,
      payload?.result?.next_cursor,
      payload?.result?.nextCursor
    )
  );
  const hasMoreValue = parseBooleanLike(
    firstDefined(
      payload?.has_more,
      payload?.hasMore,
      payload?.pagination?.has_more,
      payload?.pagination?.hasMore,
      payload?.meta?.has_more,
      payload?.meta?.hasMore
    )
  );
  return {
    cursor,
    nextCursor,
    hasMore: hasMoreValue !== undefined ? hasMoreValue : nextCursor ? true : undefined
  };
}

function summarizeOperatorList(payload, options = {}) {
  const {
    fallbackStatus = "pending",
    fallbackLimit = OPERATOR_PENDING_LIST_LIMIT,
    fallbackSearch = "",
    fallbackCursor = ""
  } = options;
  const entries = extractOperatorListEntries(payload);
  const status =
    nonEmptyString(
      firstDefined(
        payload?.status,
        payload?.filter?.status,
        payload?.request?.status,
        payload?.meta?.status,
        fallbackStatus
      )
    ) || "pending";
  const limit =
    numberOrUndefined(
      firstDefined(
        payload?.limit,
        payload?.request?.limit,
        payload?.meta?.limit,
        payload?.pagination?.limit,
        fallbackLimit
      )
    ) ?? OPERATOR_PENDING_LIST_LIMIT;
  const total =
    numberOrUndefined(
      firstDefined(
        payload?.total,
        payload?.count,
        payload?.total_count,
        payload?.pending_total,
        payload?.meta?.total,
        payload?.pagination?.total
      )
    ) ?? entries.length;
  const search = normalizeOperatorListSearch(
    firstDefined(payload?.search, payload?.filter?.search, payload?.request?.search, payload?.meta?.search, fallbackSearch)
  );
  const pagination = extractOperatorListPagination(payload, { fallbackCursor });
  const sample = entries.slice(0, 3).map(formatOperatorListItemLabel);
  const detailParts = [
    `status=${operatorListStatusLabel(status)}`,
    `returned=${entries.length}`,
    `limit=${limit}`,
    `total=${total}`
  ];
  if (search) {
    detailParts.push(`search=${search}`);
  }
  if (pagination.cursor) {
    detailParts.push(`cursor=${pagination.cursor}`);
  }
  if (pagination.nextCursor) {
    detailParts.push(`next_cursor=${pagination.nextCursor}`);
  }
  if (pagination.hasMore !== undefined) {
    detailParts.push(`has_more=${pagination.hasMore}`);
  }
  if (sample.length > 0) {
    detailParts.push(`sample=${sample.join(", ")}`);
  }
  return {
    detail: `Operator queue: ${detailParts.join(" | ")}`,
    output: {
      status: operatorListStatusLabel(status),
      returned: entries.length,
      limit,
      total,
      search,
      cursor: pagination.cursor || null,
      next_cursor: pagination.nextCursor || null,
      has_more: pagination.hasMore,
      sample
    }
  };
}

function extractAuditRecentEntries(payload) {
  const containers = [payload, payload?.data, payload?.result, payload?.audit, payload?.recent, payload?.page];
  for (const container of containers) {
    if (!container || typeof container !== "object") {
      continue;
    }
    for (const key of ["entries", "items", "records", "results", "events", "logs"]) {
      if (Array.isArray(container[key])) {
        return container[key];
      }
    }
  }
  return [];
}

function formatAuditEntryLabel(entry, index) {
  if (!entry || typeof entry !== "object") {
    return `entry-${index + 1}`;
  }
  const event = nonEmptyString(entry.event);
  const timestamp = nonEmptyString(firstDefined(entry.timestamp, entry.time, entry.created_at, entry.createdAt));
  if (event && timestamp) {
    return `${event}@${timestamp}`;
  }
  return event || timestamp || `entry-${index + 1}`;
}

function summarizeAuditRecent(payload, request = {}) {
  const entries = extractAuditRecentEntries(payload);
  const returnedFromPayload = numberOrUndefined(
    firstDefined(
      payload?.returned,
      payload?.result_count,
      payload?.entries_count,
      payload?.meta?.returned,
      payload?.pagination?.returned
    )
  );
  const returnedCountHint = numberOrUndefined(firstDefined(payload?.count, payload?.meta?.count, payload?.pagination?.count));
  const returned = Math.max(
    entries.length,
    Math.floor(returnedFromPayload ?? returnedCountHint ?? entries.length)
  );
  const limit = normalizeAuditRecentLimit(
    firstDefined(
      payload?.limit,
      payload?.request?.limit,
      payload?.meta?.limit,
      payload?.pagination?.limit,
      request.limit
    ),
    request.limit
  );
  const offset = normalizeAuditRecentOffset(
    firstDefined(
      payload?.offset,
      payload?.request?.offset,
      payload?.meta?.offset,
      payload?.pagination?.offset,
      request.offset
    ),
    request.offset
  );
  const total = numberOrUndefined(
    firstDefined(payload?.total, payload?.total_count, payload?.meta?.total, payload?.pagination?.total)
  );
  const nextOffsetRaw = numberOrUndefined(
    firstDefined(
      payload?.next_offset,
      payload?.nextOffset,
      payload?.meta?.next_offset,
      payload?.meta?.nextOffset,
      payload?.pagination?.next_offset,
      payload?.pagination?.nextOffset
    )
  );
  const hasMoreRaw = parseBooleanLike(
    firstDefined(
      payload?.has_more,
      payload?.hasMore,
      payload?.meta?.has_more,
      payload?.meta?.hasMore,
      payload?.pagination?.has_more,
      payload?.pagination?.hasMore
    )
  );
  const hasMore = hasMoreRaw !== undefined ? hasMoreRaw : total !== undefined ? offset + returned < total : undefined;
  const nextOffset = nextOffsetRaw !== undefined ? Math.floor(nextOffsetRaw) : hasMore ? offset + returned : undefined;
  const order = normalizeAuditRecentOrder(
    firstDefined(
      payload?.order,
      payload?.request?.order,
      payload?.meta?.order,
      payload?.pagination?.order,
      request.order
    ),
    request.order
  );
  const event = nonEmptyString(
    firstDefined(payload?.event, payload?.request?.event, payload?.meta?.event, request.event)
  );
  const walletAddress = nonEmptyString(
    firstDefined(
      payload?.wallet_address,
      payload?.request?.wallet_address,
      payload?.meta?.wallet_address,
      request.wallet_address
    )
  );
  const sample = entries.slice(0, 3).map(formatAuditEntryLabel);
  const detailParts = [
    `returned=${returned}`,
    `limit=${limit}`,
    `offset=${offset}`,
    `order=${order}`
  ];
  if (total !== undefined) {
    detailParts.push(`total=${Math.floor(total)}`);
  }
  if (nextOffset !== undefined) {
    detailParts.push(`next_offset=${nextOffset}`);
  }
  if (hasMore !== undefined) {
    detailParts.push(`has_more=${hasMore}`);
  }
  if (event) {
    detailParts.push(`event=${event}`);
  }
  if (walletAddress) {
    detailParts.push(`wallet_address=${walletAddress}`);
  }
  return {
    detail: `Audit recent: ${detailParts.join(" | ")}`,
    output: {
      request: {
        limit,
        offset,
        event: event || null,
        wallet_address: walletAddress || null,
        order
      },
      pagination: {
        returned,
        limit,
        offset,
        total: total !== undefined ? Math.floor(total) : null,
        next_offset: nextOffset !== undefined ? nextOffset : null,
        has_more: hasMore
      },
      sample,
      entries
    }
  };
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

function appendSessionReconciledDetail(detail, hintSource) {
  const hint = formatSessionReconciledHint(hintSource);
  if (!hint) {
    return detail;
  }
  return `${detail} session_reconciled=${hint}.`;
}

function appendBootstrapDirectoryFallbackDetail(detail, hintSource) {
  const hint = formatBootstrapDirectoryFallbackHint(hintSource);
  if (!hint) {
    return detail;
  }
  return `${detail} bootstrap_directory fallback=${hint.bootstrapDirectory}.`;
}

function readOperatorEntryText(entry, candidates) {
  if (!entry || typeof entry !== "object") {
    return "";
  }
  const scopes = [entry, entry.application, entry.request, entry.profile, entry.operator];
  for (const scope of scopes) {
    if (!scope || typeof scope !== "object") {
      continue;
    }
    for (const candidate of candidates) {
      const value = nonEmptyString(scope[candidate]);
      if (value) {
        return value;
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
    walletAddress: readOperatorEntryText(entry, [
      "wallet_address",
      "walletAddress",
      "address",
      "subject_wallet",
      "subjectWallet"
    ]),
    chainOperatorId: readOperatorEntryText(entry, [
      "chain_operator_id",
      "chainOperatorId",
      "operator_id",
      "operatorId",
      "id"
    ]),
    selectedApplicationUpdatedAtUtc: readOperatorEntryText(entry, [
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
  selectedApplicationUpdatedAtUtc = normalized;
  selectedApplicationUpdatedAtEl.value = normalized;
  if (persist) {
    persistPortalState();
  }
}

function selectedApplicationUpdatedAt() {
  return selectedApplicationUpdatedAtUtc || selectedApplicationUpdatedAtEl.value.trim();
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
    byId("wallet_address").value = walletAddress;
  }
  if (mode === "replace" || chainOperatorId) {
    byId("chain_operator_id").value = chainOperatorId;
  }
  if (mode === "replace" || selectedUpdatedAtUtc) {
    setSelectedApplicationUpdatedAt(selectedUpdatedAtUtc, { persist: false });
  }
  if (persist) {
    persistPortalState();
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

function parseBooleanLike(value) {
  if (typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    return value !== 0;
  }
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (["1", "true", "yes", "on"].includes(normalized)) {
      return true;
    }
    if (["0", "false", "no", "off"].includes(normalized)) {
      return false;
    }
  }
  return undefined;
}

function parseConnectionBooleanLike(value) {
  const parsed = parseBooleanLike(value);
  if (parsed !== undefined) {
    return parsed;
  }
  if (typeof value !== "string") {
    return undefined;
  }
  const normalized = value.trim().toLowerCase();
  if (["ok", "healthy", "online", "up", "connected", "ready", "active", "pass"].includes(normalized)) {
    return true;
  }
  if (["offline", "down", "disconnected", "unhealthy", "error", "failed"].includes(normalized)) {
    return false;
  }
  return undefined;
}

function parseTimestampMs(value) {
  if (value === undefined || value === null || value === "") {
    return undefined;
  }
  if (typeof value === "number" && Number.isFinite(value) && value > 0) {
    return value > 1e12 ? value : value * 1000;
  }
  if (typeof value !== "string") {
    return undefined;
  }
  const normalized = value.trim();
  if (!normalized) {
    return undefined;
  }
  const asNumber = Number(normalized);
  if (Number.isFinite(asNumber) && asNumber > 0) {
    return asNumber > 1e12 ? asNumber : asNumber * 1000;
  }
  const parsed = Date.parse(normalized);
  if (Number.isFinite(parsed) && parsed > 0) {
    return parsed;
  }
  return undefined;
}

function formatDurationCompact(deltaMs) {
  const totalSeconds = Math.floor(Math.abs(deltaMs) / 1000);
  if (totalSeconds < 60) {
    return `${totalSeconds}s`;
  }
  const totalMinutes = Math.floor(totalSeconds / 60);
  if (totalMinutes < 60) {
    return `${totalMinutes}m`;
  }
  const totalHours = Math.floor(totalMinutes / 60);
  if (totalHours < 24) {
    const minutesRemainder = totalMinutes % 60;
    return minutesRemainder > 0 ? `${totalHours}h ${minutesRemainder}m` : `${totalHours}h`;
  }
  const totalDays = Math.floor(totalHours / 24);
  const hoursRemainder = totalHours % 24;
  return hoursRemainder > 0 ? `${totalDays}d ${hoursRemainder}h` : `${totalDays}d`;
}

function formatBootstrapManifestExpiryLabel(expiresAtMs) {
  if (typeof expiresAtMs !== "number" || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    return "unknown";
  }
  const deltaMs = expiresAtMs - Date.now();
  const iso = new Date(expiresAtMs).toISOString();
  if (deltaMs <= 0) {
    return `expired ${formatDurationCompact(deltaMs)} ago (${iso})`;
  }
  return `in ${formatDurationCompact(deltaMs)} (${iso})`;
}

function normalizeBootstrapManifestSource(value) {
  const raw = nonEmptyString(value);
  if (!raw) {
    return "";
  }
  const normalized = raw.toLowerCase().replace(/[\s-]+/g, "_");
  if (normalized === "remote" || normalized === "cache") {
    return normalized;
  }
  return raw;
}

function formatBootstrapManifestSourceLabel(source) {
  const normalized = normalizeBootstrapManifestSource(source);
  if (normalized === "remote") {
    return "remote";
  }
  if (normalized === "cache") {
    return "cache";
  }
  return nonEmptyString(source) || "unknown";
}

function extractBootstrapTrustTelemetry(payload) {
  if (!payload || typeof payload !== "object") {
    return null;
  }
  const manifest = readConfigObject(payload, ["manifest"]) || {};
  const source = normalizeBootstrapManifestSource(
    firstDefined(
      payload?.source,
      payload?.manifest_source,
      payload?.manifestSource,
      payload?.telemetry?.source,
      payload?.trust?.source
    )
  );
  const signatureVerified = firstDefined(
    parseBooleanLike(payload?.signature_verified),
    parseBooleanLike(payload?.signatureVerified),
    parseBooleanLike(payload?.telemetry?.signature_verified),
    parseBooleanLike(payload?.telemetry?.signatureVerified),
    parseBooleanLike(payload?.trust?.signature_verified),
    parseBooleanLike(payload?.trust?.signatureVerified),
    parseBooleanLike(manifest?.signature_verified),
    parseBooleanLike(manifest?.signatureVerified)
  );
  const expiresAtMs = parseTimestampMs(
    firstDefined(
      manifest?.expires_at_utc,
      manifest?.expiresAtUtc,
      payload?.expires_at_utc,
      payload?.expiresAtUtc,
      payload?.manifest_expires_at_utc,
      payload?.manifestExpiresAtUtc,
      payload?.telemetry?.expires_at_utc,
      payload?.telemetry?.expiresAtUtc
    )
  );
  const generatedAtMs = parseTimestampMs(
    firstDefined(
      manifest?.generated_at_utc,
      manifest?.generatedAtUtc,
      payload?.generated_at_utc,
      payload?.generatedAtUtc,
      payload?.manifest_generated_at_utc,
      payload?.manifestGeneratedAtUtc,
      payload?.telemetry?.generated_at_utc,
      payload?.telemetry?.generatedAtUtc
    )
  );
  const fetchedAtMs = parseTimestampMs(
    firstDefined(
      payload?.fetched_at_utc,
      payload?.fetchedAtUtc,
      payload?.telemetry?.fetched_at_utc,
      payload?.telemetry?.fetchedAtUtc,
      payload?.trust?.fetched_at_utc,
      payload?.trust?.fetchedAtUtc
    )
  );
  const cacheAgeSec = positiveIntegerOrUndefined(
    firstDefined(
      payload?.cache_age_sec,
      payload?.cacheAgeSec,
      payload?.telemetry?.cache_age_sec,
      payload?.telemetry?.cacheAgeSec
    ),
    0
  );
  const resolvePolicy = nonEmptyString(
    firstDefined(
      payload?.resolve_policy,
      payload?.resolvePolicy,
      payload?.manifest_resolve_policy,
      payload?.manifestResolvePolicy,
      payload?.telemetry?.resolve_policy,
      payload?.telemetry?.resolvePolicy
    )
  );
  const trustState = nonEmptyString(
    firstDefined(
      payload?.trust_state,
      payload?.trustState,
      payload?.manifest_trust_state,
      payload?.manifestTrustState,
      payload?.trust?.state
    )
  );
  const trustReason = nonEmptyString(
    firstDefined(
      payload?.trust_reason,
      payload?.trustReason,
      payload?.status_reason,
      payload?.statusReason,
      payload?.warning,
      payload?.telemetry?.trust_reason,
      payload?.telemetry?.trustReason
    )
  );
  const trustDegraded = firstDefined(
    parseBooleanLike(payload?.trust_degraded),
    parseBooleanLike(payload?.trustDegraded),
    parseBooleanLike(payload?.degraded),
    parseBooleanLike(payload?.telemetry?.trust_degraded),
    parseBooleanLike(payload?.telemetry?.trustDegraded),
    parseBooleanLike(payload?.trust?.degraded)
  );
  const warnings = [];
  for (const candidate of [
    payload?.warnings,
    payload?.warning,
    payload?.manifest_warnings,
    payload?.manifestWarnings,
    payload?.telemetry?.warnings,
    payload?.telemetry?.warning,
    payload?.trust?.warnings,
    payload?.trust?.warning
  ]) {
    for (const warning of parseNonEmptyStringList(candidate)) {
      pushUniqueNonEmptyString(warnings, warning);
    }
  }
  if (trustReason) {
    pushUniqueNonEmptyString(warnings, trustReason);
  }
  return {
    source,
    signatureVerified,
    expiresAtMs,
    generatedAtMs,
    fetchedAtMs,
    cacheAgeSec,
    resolvePolicy,
    trustState,
    trustReason,
    trustDegraded,
    warnings
  };
}

function summarizeBootstrapTrustTelemetry(telemetry) {
  const sourceLabel = formatBootstrapManifestSourceLabel(telemetry?.source);
  const signatureLabel =
    telemetry?.signatureVerified === true
      ? "verified"
      : telemetry?.signatureVerified === false
        ? "not verified"
        : "unknown";
  const summaryParts = [
    `Source: ${sourceLabel}`,
    `Signature: ${signatureLabel}`,
    `Expiry: ${formatBootstrapManifestExpiryLabel(telemetry?.expiresAtMs)}`
  ];
  if (typeof telemetry?.cacheAgeSec === "number" && Number.isFinite(telemetry.cacheAgeSec)) {
    summaryParts.push(`Cache age: ${Math.max(0, Math.floor(telemetry.cacheAgeSec))}s`);
  }
  if (telemetry?.resolvePolicy) {
    summaryParts.push(`Policy: ${telemetry.resolvePolicy}`);
  }
  return summaryParts.join(" | ");
}

function classifyBootstrapTrustTelemetry(telemetry) {
  if (!telemetry) {
    return {
      kind: "warn",
      stateText: "Unknown",
      guidanceText: "Fetch manifest to load bootstrap trust details.",
      summaryText: "Source: unknown | Signature: unknown | Expiry: unknown"
    };
  }
  const trustStateKey = (telemetry.trustState || "").toLowerCase();
  const hasBadTrustState =
    trustStateKey.includes("degrad") ||
    trustStateKey.includes("untrust") ||
    trustStateKey.includes("invalid") ||
    trustStateKey.includes("revok") ||
    trustStateKey.includes("stale") ||
    trustStateKey.includes("expired") ||
    trustStateKey.includes("fail");
  const hasWarnings = Array.isArray(telemetry.warnings) && telemetry.warnings.length > 0;
  const expiresAtMs = telemetry.expiresAtMs;
  const expiresInMs = typeof expiresAtMs === "number" ? expiresAtMs - Date.now() : undefined;
  const expiresSoon = typeof expiresInMs === "number" && expiresInMs > 0 && expiresInMs <= 60 * 60 * 1000;
  let kind = "good";
  let stateText = "Healthy";
  let guidanceText = "Manifest trust is healthy for current bootstrap onboarding.";
  if (typeof expiresInMs === "number" && expiresInMs <= 0) {
    kind = "bad";
    stateText = "Expired";
    guidanceText = "Manifest trust has expired. Fetch manifest again and re-register client before connecting.";
  } else if (telemetry.trustDegraded === true || hasBadTrustState) {
    kind = "bad";
    stateText = "Degraded trust";
    guidanceText =
      telemetry.trustReason ||
      "Bootstrap trust is degraded. Resolve trust warnings before registering or connecting.";
  } else if (telemetry.signatureVerified === false) {
    kind = "warn";
    stateText = "Signature not verified";
    guidanceText =
      "Manifest signature verification is not confirmed. Treat bootstrap trust as degraded until verification succeeds.";
  } else if (telemetry.signatureVerified === undefined) {
    kind = "warn";
    stateText = "Signature unknown";
    guidanceText = "Manifest signature verification status is unavailable. Fetch manifest again to confirm trust.";
  } else if (hasWarnings || expiresSoon) {
    kind = "warn";
    stateText = expiresSoon ? "Expiring soon" : "Warning";
    guidanceText = expiresSoon
      ? "Manifest trust expires soon. Refresh manifest and complete registration updates before expiry."
      : "Manifest trust has warnings. Review warning details before registering or connecting.";
  } else if (telemetry.source === "cache") {
    guidanceText =
      "Using trusted cache fallback. Periodically fetch manifest to confirm remote trust source availability.";
  } else if (telemetry.source === "remote") {
    guidanceText = "Using remote manifest source with verified trust state.";
  }
  if (hasWarnings) {
    const warningSummary = telemetry.warnings.slice(0, 2).join(" ");
    guidanceText = `${guidanceText} ${warningSummary}`;
  }
  if (telemetry.generatedAtMs && kind !== "bad") {
    guidanceText = `${guidanceText} Generated at ${new Date(telemetry.generatedAtMs).toISOString()}.`;
  }
  return {
    kind,
    stateText,
    guidanceText,
    summaryText: summarizeBootstrapTrustTelemetry(telemetry)
  };
}

function setBootstrapTrustStatus(kind, stateText, guidanceText, summaryText) {
  bootstrapTrustStatusEl.dataset.kind = kind || "warn";
  bootstrapTrustStatusLineEl.classList.remove("good", "warn", "bad");
  if (kind) {
    bootstrapTrustStatusLineEl.classList.add(kind);
  }
  bootstrapTrustStateEl.textContent = stateText;
  bootstrapTrustGuidanceEl.textContent = guidanceText;
  bootstrapTrustSummaryEl.textContent = summaryText;
}

function applyBootstrapTrustStatusPayload(payload) {
  const parsedTelemetry = extractBootstrapTrustTelemetry(payload);
  if (parsedTelemetry) {
    bootstrapTrustTelemetry = parsedTelemetry;
  }
  const classification = classifyBootstrapTrustTelemetry(bootstrapTrustTelemetry);
  setBootstrapTrustStatus(
    classification.kind,
    classification.stateText,
    classification.guidanceText,
    classification.summaryText
  );
}

function markBootstrapTrustStatusRefreshIssue(error) {
  const message = nonEmptyString(String(error && error.message ? error.message : error || ""));
  if (bootstrapTrustTelemetry) {
    const classified = classifyBootstrapTrustTelemetry(bootstrapTrustTelemetry);
    const guidance = message
      ? `${classified.guidanceText} Auto refresh issue: ${message}`
      : classified.guidanceText;
    setBootstrapTrustStatus(classified.kind, classified.stateText, guidance, classified.summaryText);
    return;
  }
  const guidance = message
    ? `Manifest trust could not be loaded automatically. ${message}`
    : "Manifest trust could not be loaded automatically. Use Fetch Manifest to retry.";
  setBootstrapTrustStatus("warn", "Unavailable", guidance, "Source: unknown | Signature: unknown | Expiry: unknown");
}

async function requestBootstrapManifest() {
  const result = await get("/v1/gpm/bootstrap/manifest");
  applyBootstrapTrustStatusPayload(result);
  return result;
}

async function refreshBootstrapTrustStatusBestEffort(options = {}) {
  const { quiet = true } = options;
  try {
    return await requestBootstrapManifest();
  } catch (err) {
    markBootstrapTrustStatusRefreshIssue(err);
    if (!quiet) {
      throw err;
    }
    return undefined;
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
  return stateKey === "degraded" ? "Connection check reported issues." : CONNECTION_DEFAULT_DETAIL;
}

function formatConnectionRoutingModeLabel(value) {
  const text = nonEmptyString(value);
  if (!text) {
    return undefined;
  }
  const compact = text.toLowerCase().replace(/[\s-]+/g, "_");
  if (compact.includes("direct")) {
    return "Direct mesh";
  }
  if (compact.includes("relay")) {
    return "Managed relay";
  }
  if (compact.includes("hybrid") || compact === "auto" || compact.includes("fallback")) {
    return "Auto (hybrid)";
  }
  if (compact === "inactive" || compact === "disconnected" || compact === "none" || compact === "off") {
    return "Inactive";
  }
  if (compact === "unknown") {
    return CONNECTION_DEFAULT_ROUTING_MODE;
  }
  const normalized = text.replace(/[_-]+/g, " ").trim();
  if (!normalized) {
    return undefined;
  }
  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

function parseConnectionRoutingFromObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const mode = formatConnectionRoutingModeLabel(
    toDetailText(
      firstDefined(
        value.mode,
        value.routing_mode,
        value.route_mode,
        value.path_mode,
        value.strategy,
        value.routing_strategy,
        value.resolve_policy,
        value.routing_posture,
        value.routing_state
      )
    )
  );
  const detail = toDetailText(
    firstDefined(
      value.detail,
      value.routing_detail,
      value.route_detail,
      value.resolve_policy_detail,
      value.reason,
      value.status_reason,
      value.description,
      value.hint,
      value.note
    )
  );
  if (!mode && !detail) {
    return null;
  }
  return {
    mode: mode || CONNECTION_DEFAULT_ROUTING_MODE,
    detail
  };
}

function parseConnectionRoutingFromValue(value) {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return parseConnectionRoutingFromObject(value);
  }
  const mode = formatConnectionRoutingModeLabel(toDetailText(value));
  if (!mode) {
    return null;
  }
  return { mode };
}

function inferConnectionRoutingDetailFallback(source, mode) {
  if (source === "disconnect" || mode === "Inactive") {
    return "Routing is inactive while disconnected.";
  }
  if (source === "connect") {
    return "Connect request completed. Run Status to confirm current routing posture.";
  }
  if (source === "status") {
    if (mode === CONNECTION_DEFAULT_ROUTING_MODE) {
      return "Routing payload unavailable in status response.";
    }
    return "Routing posture refreshed.";
  }
  return CONNECTION_DEFAULT_ROUTING_DETAIL;
}

function inferConnectionRoutingSnapshotHeuristic(source, payload, stateKey) {
  const nestedRouting = parseConnectionRoutingFromValue(findHintValue(payload, ["routing"]));
  const modeHint = formatConnectionRoutingModeLabel(toDetailText(findHintValue(payload, CONNECTION_ROUTING_HINT_KEYS.mode)));
  const detailHint = toDetailText(findHintValue(payload, CONNECTION_ROUTING_HINT_KEYS.detail));
  const directHint = parseConnectionBooleanLike(findHintValue(payload, CONNECTION_ROUTING_HINT_KEYS.direct));
  const relayHint = parseConnectionBooleanLike(findHintValue(payload, CONNECTION_ROUTING_HINT_KEYS.relay));

  let mode = nestedRouting?.mode || modeHint;
  if (!mode && relayHint === true) {
    mode = "Managed relay";
  }
  if (!mode && directHint === true && relayHint !== true) {
    mode = "Direct mesh";
  }
  if (!mode && (source === "disconnect" || stateKey === "disconnected")) {
    mode = "Inactive";
  }
  if (!mode) {
    mode = CONNECTION_DEFAULT_ROUTING_MODE;
  }

  let detail = nestedRouting?.detail || detailHint;
  if (!detail) {
    detail = inferConnectionRoutingDetailFallback(source, mode);
  }
  return { mode, detail };
}

function inferConnectionRoutingSnapshot(source, payload, stateKey) {
  const root = payload && typeof payload === "object" && !Array.isArray(payload) ? payload : null;
  const topLevelRouting = parseConnectionRoutingFromValue(root ? root.routing : undefined);
  const heuristic = inferConnectionRoutingSnapshotHeuristic(source, payload, stateKey);
  return {
    mode: topLevelRouting?.mode || heuristic.mode || connectionRoutingMode || CONNECTION_DEFAULT_ROUTING_MODE,
    detail: topLevelRouting?.detail || heuristic.detail || connectionRoutingDetail || CONNECTION_DEFAULT_ROUTING_DETAIL
  };
}

function inferConnectionSnapshot(source, payload) {
  const stateHint = findHintValue(payload, CONNECTION_HINT_KEYS.state);
  const connected = parseConnectionBooleanLike(findHintValue(payload, CONNECTION_HINT_KEYS.connected));
  const disconnected = parseConnectionBooleanLike(findHintValue(payload, CONNECTION_HINT_KEYS.disconnected));
  const healthy = parseConnectionBooleanLike(findHintValue(payload, CONNECTION_HINT_KEYS.healthy));

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
  if (!stateKey && source === "status" && healthy !== undefined) {
    stateKey = healthy ? "healthy" : "degraded";
  }
  if (!stateKey) {
    stateKey = normalizeConnectionState(connectionState) || "unknown";
  }
  return {
    stateKey,
    state: formatConnectionStateLabel(stateKey),
    detail: inferConnectionDetail(payload, source, stateKey, stateHint)
  };
}

function connectionSnapshotKind(stateKey) {
  if (stateKey === "connected" || stateKey === "healthy") {
    return "good";
  }
  if (stateKey === "degraded") {
    return "bad";
  }
  return "warn";
}

function applyConnectionSnapshot(snapshot) {
  connectionState = snapshot?.state || connectionState || CONNECTION_DEFAULT_STATE;
  connectionDetail = snapshot?.detail || connectionDetail || CONNECTION_DEFAULT_DETAIL;
  if (connectionStateEl) {
    connectionStateEl.textContent = connectionState;
  }
  if (connectionDetailEl) {
    connectionDetailEl.textContent = connectionDetail;
  }
  const kind = connectionSnapshotKind(snapshot?.stateKey);
  connectionSnapshotEl.dataset.kind = kind;
  connectionSnapshotLineEl.classList.remove("good", "warn", "bad");
  connectionSnapshotLineEl.classList.add(kind);
}

function applyConnectionRoutingSnapshot(snapshot, stateKey) {
  connectionRoutingMode = snapshot?.mode || connectionRoutingMode || CONNECTION_DEFAULT_ROUTING_MODE;
  connectionRoutingDetail = snapshot?.detail || connectionRoutingDetail || CONNECTION_DEFAULT_ROUTING_DETAIL;
  if (connectionRoutingModeEl) {
    connectionRoutingModeEl.textContent = connectionRoutingMode;
  }
  if (connectionRoutingDetailEl) {
    connectionRoutingDetailEl.textContent = connectionRoutingDetail;
  }
  if (connectionRoutingLineEl) {
    const kind = connectionSnapshotKind(stateKey);
    connectionRoutingLineEl.classList.remove("good", "warn", "bad");
    connectionRoutingLineEl.classList.add(kind);
  }
}

function updateConnectionDashboard(source, payload) {
  const snapshot = inferConnectionSnapshot(source, payload);
  applyConnectionSnapshot(snapshot);
  applyConnectionRoutingSnapshot(inferConnectionRoutingSnapshot(source, payload, snapshot?.stateKey), snapshot?.stateKey);
}

function parseServerReadiness(payload) {
  const readiness = payload?.readiness;
  if (!readiness || typeof readiness !== "object") {
    return null;
  }
  const unlockActions = Array.isArray(readiness.unlock_actions)
    ? readiness.unlock_actions
        .map((entry) => (typeof entry === "string" ? entry.trim() : ""))
        .filter((entry) => entry.length > 0)
    : [];
  const role = typeof readiness.role === "string" ? readiness.role.trim().toLowerCase() : "";
  const lockReason = nonEmptyString(firstDefined(readiness.lock_reason, readiness.lockReason));
  const clientLockReason = nonEmptyString(firstDefined(readiness.client_lock_reason, readiness.clientLockReason));
  const endpointPostureRaw = firstDefined(readiness.endpoint_posture, readiness.endpointPosture);
  const endpointPosture =
    endpointPostureRaw && typeof endpointPostureRaw === "object" && !Array.isArray(endpointPostureRaw)
      ? endpointPostureRaw
      : nonEmptyString(endpointPostureRaw);
  const endpointWarnings = parseNonEmptyStringList(
    firstDefined(readiness.endpoint_warnings, readiness.endpointWarnings)
  );
  if (endpointPosture && typeof endpointPosture === "object" && !Array.isArray(endpointPosture)) {
    for (const warning of parseNonEmptyStringList(
      firstDefined(
        endpointPosture.endpoint_warnings,
        endpointPosture.endpointWarnings,
        endpointPosture.warnings,
        endpointPosture.warning
      )
    )) {
      pushUniqueNonEmptyString(endpointWarnings, warning);
    }
  }
  return {
    role: role || undefined,
    tabVisible: parseBooleanLike(readiness.tab_visible),
    clientTabVisible: parseBooleanLike(firstDefined(readiness.client_tab_visible, readiness.clientTabVisible)),
    lifecycleActionsUnlocked: parseBooleanLike(readiness.lifecycle_actions_unlocked),
    serviceMutationsConfigured: parseBooleanLike(readiness.service_mutations_configured),
    operatorApplicationStatus: normalizeOperatorApplicationStatus(readiness.operator_application_status),
    lockReason: lockReason || undefined,
    clientLockReason: clientLockReason || undefined,
    chainBindingStatus: nonEmptyString(firstDefined(readiness.chain_binding_status, readiness.chainBindingStatus)),
    chainBindingOk: parseBooleanLike(firstDefined(readiness.chain_binding_ok, readiness.chainBindingOk)),
    chainBindingReason: nonEmptyString(firstDefined(readiness.chain_binding_reason, readiness.chainBindingReason)),
    endpointPosture: endpointPosture || undefined,
    endpointWarnings,
    unlockActions
  };
}

function appendChainBindingGuidance(guidanceText, readiness) {
  const statusRaw = nonEmptyString(readiness?.chainBindingStatus);
  const statusKey = statusRaw.toLowerCase();
  const status = statusRaw ? statusRaw.replace(/[_-]+/g, " ") : "";
  const ok = readiness?.chainBindingOk;
  const reason = nonEmptyString(readiness?.chainBindingReason);
  if (!status && ok === undefined && !reason) {
    return guidanceText;
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
  if (statusKey === "mismatch") {
    bindingHint =
      `${bindingHint} Next: refresh session to resync chain_operator_id; ` +
      "if mismatch persists, re-apply and re-approve with the intended chain_operator_id.";
  } else if (statusKey === "pending_approval" || statusKey === "pending approval") {
    bindingHint = `${bindingHint} Next: wait for operator approval, then refresh session to lift server lifecycle locks.`;
  } else if (ok === false) {
    bindingHint = `${bindingHint} Next: refresh session and operator status to reconcile strict chain binding.`;
  }
  return `${guidanceText} ${bindingHint}`;
}

function setServerReadiness(value) {
  serverReadiness = value || null;
  if (serverReadiness?.operatorApplicationStatus !== undefined) {
    operatorApplicationStatus = serverReadiness.operatorApplicationStatus;
  }
  refreshOperatorReadiness();
}

function isServerRoleUnlocked(roleValue) {
  const role = String(roleValue || "").trim().toLowerCase();
  return role === "operator" || role === "admin";
}

function isServerOnlyRole(roleValue) {
  const role = String(roleValue || "").trim().toLowerCase();
  return SERVER_ONLY_ROLES.has(role);
}

function isServerTabVisibleRole(roleValue = byId("role").value) {
  if (serverReadiness && typeof serverReadiness.tabVisible === "boolean") {
    return serverReadiness.tabVisible;
  }
  const role = String(serverReadiness?.role || roleValue || "").trim().toLowerCase();
  return role === "operator" || role === "admin" || role === "server" || role === "server_only";
}

function isClientTabVisibleRole(roleValue = byId("role").value) {
  if (serverReadiness && typeof serverReadiness.clientTabVisible === "boolean") {
    return serverReadiness.clientTabVisible;
  }
  const role = String(serverReadiness?.role || roleValue || "").trim().toLowerCase();
  if (role === "server" || role === "server_only") {
    return false;
  }
  if (role === "operator" || role === "admin") {
    return clientRegistered === true;
  }
  return true;
}

function formatDirectActionGuidance(directPath, requiredConditions) {
  return `Direct path: ${directPath}. Required conditions: ${requiredConditions}.`;
}

function computeClientTabLockHintText() {
  const readiness = computeClientReadiness();
  return readiness.guidanceText;
}

function computeServerTabLockHintText() {
  const readiness = computeOperatorReadiness();
  if (!isServerTabVisibleRole()) {
    const reason = serverReadiness?.lockReason || "Server tab is locked for the current role.";
    return `${reason} ${formatDirectActionGuidance(
      "Use Apply Operator Role, then Check Operator Status and Refresh Session",
      "active session token, approved operator application, and matching session/application chain_operator_id values"
    )}`;
  }
  return readiness.guidanceText;
}

function computeServerLifecycleControlState() {
  const role = (serverReadiness?.role || byId("role").value).trim().toLowerCase() || "client";
  const sessionToken = byId("session_token").value.trim();
  if (!isServerTabVisibleRole(role)) {
    return {
      disabled: true,
      locked: true,
      hint: computeServerTabLockHintText()
    };
  }

  if (configEndpointUnavailableFailClosedMode()) {
    return {
      disabled: true,
      locked: true,
      hint: failClosedMutatingActionStatusDetail()
    };
  }

  if (serverReadiness?.serviceMutationsConfigured === false) {
    return {
      disabled: true,
      locked: true,
      hint: appendChainBindingGuidance(
        "Lifecycle commands are unavailable because service mutations are not configured on this daemon.",
        serverReadiness
      )
    };
  }

  if (serverReadiness?.lifecycleActionsUnlocked === false) {
    const reason = serverReadiness.lockReason || "Lifecycle commands are locked by backend readiness policy.";
    const unlockActions = Array.isArray(serverReadiness.unlockActions) ? serverReadiness.unlockActions : [];
    const nextActions = unlockActions.length > 0 ? ` Next: ${unlockActions.join("; ")}` : "";
    return {
      disabled: true,
      locked: true,
      hint: appendChainBindingGuidance(`${reason}${nextActions}`, serverReadiness)
    };
  }

  if (serverReadiness?.lifecycleActionsUnlocked === true) {
    return {
      disabled: false,
      locked: false,
      hint: "Lifecycle commands are unlocked by backend readiness. Use Start, Stop, or Restart to manage the service."
    };
  }

  if (!sessionToken) {
    return {
      disabled: true,
      locked: true,
      hint: "Sign in and refresh server readiness to confirm lifecycle command availability."
    };
  }

  if (!isServerRoleUnlocked(role)) {
    return {
      disabled: true,
      locked: true,
      hint: "Operator or admin role is required for lifecycle commands."
    };
  }

  return {
    disabled: false,
    locked: false,
    hint: "Lifecycle commands are available for this role. Refresh readiness if a command is rejected."
  };
}

function syncServerLifecycleActionState() {
  const isBusy = document.body.classList.contains("is-busy");
  const state = computeServerLifecycleControlState();
  const disabled = isBusy || state.disabled;
  for (const button of [serverStartBtnEl, serverStopBtnEl, serverRestartBtnEl]) {
    button.disabled = disabled;
    button.setAttribute("aria-disabled", String(disabled));
    if (state.locked && state.hint) {
      button.title = state.hint;
    } else {
      button.removeAttribute("title");
    }
  }
  serverLifecycleHintEl.textContent = state.hint;
  serverLifecycleHintEl.classList.toggle("locked", state.locked);
}

function activateWorkspaceTab(name) {
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
  tabClientEl.setAttribute("aria-selected", String(isClient));
  tabServerEl.classList.toggle("active", !isClient);
  tabServerEl.setAttribute("aria-selected", String(!isClient));
  panelClientEl.classList.toggle("active", isClient);
  panelServerEl.classList.toggle("active", !isClient);
  activeWorkspaceTab = selectedTab;
  persistWorkspaceTabPreference();
}

function syncWorkspaceTabLockState() {
  const clientTabVisible = isClientTabVisibleRole();
  const serverTabVisible = isServerTabVisibleRole();
  tabClientEl.disabled = !clientTabVisible;
  tabClientEl.classList.toggle("locked", !clientTabVisible);
  panelClientEl.classList.toggle("locked", !clientTabVisible);
  tabServerEl.disabled = !serverTabVisible;
  tabServerEl.classList.toggle("locked", !serverTabVisible);
  panelServerEl.classList.toggle("locked", !serverTabVisible);

  const clientTabActive = tabClientEl.classList.contains("active");
  const serverTabActive = tabServerEl.classList.contains("active");
  if ((clientTabActive && !clientTabVisible) || (serverTabActive && !serverTabVisible)) {
    if (clientTabVisible) {
      activateWorkspaceTab("client");
    } else if (serverTabVisible) {
      activateWorkspaceTab("server");
    }
  } else {
    activateWorkspaceTab(activeWorkspaceTab);
  }

  clientLockHintEl.textContent = computeClientTabLockHintText();
  clientLockHintEl.classList.toggle("locked", !clientTabVisible);
  serverLockHintEl.textContent = computeServerTabLockHintText();
  serverLockHintEl.classList.toggle("locked", !serverTabVisible);
  syncServerLifecycleActionState();
}

function formatOperatorApplicationStatusLabel(status) {
  switch (status) {
    case "not_submitted":
      return "Not submitted";
    case "pending":
      return "Pending";
    case "approved":
      return "Approved";
    case "rejected":
      return "Rejected";
    default:
      return "Unknown";
  }
}

function setStepState(el, state) {
  if (!el) {
    return;
  }
  el.dataset.state = state;
}

function refreshOnboardingSteps() {
  const clientReadiness = computeClientReadiness();
  const hasSession = clientReadiness.state !== "not_signed_in";
  const role = (serverReadiness?.role || byId("role").value).trim().toLowerCase();
  const backendOperatorStatus = serverReadiness?.operatorApplicationStatus || operatorApplicationStatus;
  const step3Done =
    typeof serverReadiness?.lifecycleActionsUnlocked === "boolean"
      ? serverReadiness.lifecycleActionsUnlocked
      : role === "admin" || (role === "operator" && backendOperatorStatus === "approved");

  if (!hasSession) {
    setStepState(onboardingStepSigninEl, "active");
    setStepState(onboardingStepClientEl, "blocked");
    setStepState(onboardingStepOperatorEl, "blocked");
    return;
  }

  setStepState(onboardingStepSigninEl, "done");
  const clientLaneRoleLocked = clientReadiness.state === "role_locked";
  if (!clientRegistered && !clientLaneRoleLocked) {
    setStepState(onboardingStepClientEl, "active");
  } else if (clientReadiness.state === "registered") {
    setStepState(onboardingStepClientEl, "done");
  } else if (clientLaneRoleLocked) {
    setStepState(onboardingStepClientEl, "blocked");
  } else {
    setStepState(onboardingStepClientEl, "active");
  }
  if (step3Done) {
    setStepState(onboardingStepOperatorEl, "done");
    return;
  }
  if (
    backendOperatorStatus === "rejected" ||
    (serverReadiness && serverReadiness.tabVisible === false)
  ) {
    setStepState(onboardingStepOperatorEl, "blocked");
    return;
  }
  setStepState(onboardingStepOperatorEl, "active");
}

function effectivePortalOperatorApplicationStatus() {
  return normalizeOperatorApplicationStatus(serverReadiness?.operatorApplicationStatus || operatorApplicationStatus);
}

function computePortalNextRecommendedAction() {
  const sessionToken = byId("session_token").value.trim();
  if (!sessionToken) {
    const challengeId = byId("challenge_id").value.trim();
    const signature = byId("signature").value.trim();
    if (!challengeId) {
      return "Request Challenge.";
    }
    if (!signature) {
      return "Sign Challenge (Wallet) or run Sign + Verify (Wallet).";
    }
    return "Verify + Create Session.";
  }

  const clientReadiness = computeClientReadiness();
  if (
    clientReadiness.state === "ready_to_register" ||
    clientReadiness.state === "re_registration_required"
  ) {
    return "Register Client.";
  }

  const operatorStatus = effectivePortalOperatorApplicationStatus();
  if (operatorStatus === "pending") {
    return "Wait for operator approval, then refresh Session or Check Operator Status.";
  }
  if (operatorStatus === "rejected") {
    return "Apply Operator Role again after updating operator details.";
  }
  const role = (serverReadiness?.role || byId("role").value).trim().toLowerCase() || "client";
  if (operatorStatus !== "approved" && role !== "admin" && role !== "server" && role !== "server_only") {
    return "Apply Operator Role.";
  }
  if (serverReadiness?.lifecycleActionsUnlocked === false) {
    return "Check Operator Status and refresh Session to unlock server actions.";
  }
  return "Continue in Client or Server tab based on your role.";
}

function computePortalOnboardingState() {
  const sessionToken = byId("session_token").value.trim();
  if (!sessionToken) {
    const challengeId = byId("challenge_id").value.trim();
    const signature = byId("signature").value.trim();
    if (!challengeId) {
      return {
        kind: "warn",
        title: "Signed out",
        detail: "No active session token is loaded."
      };
    }
    if (!signature) {
      return {
        kind: "warn",
        title: "Signed out",
        detail: "Challenge is ready, but signature verification is still pending."
      };
    }
    return {
      kind: "warn",
      title: "Signed out",
      detail: "Challenge and signature are ready, but session verification is still pending."
    };
  }

  const operatorStatus = effectivePortalOperatorApplicationStatus();
  if (operatorStatus === "pending") {
    return {
      kind: "warn",
      title: "Operator pending",
      detail: "Session is active and operator approval is pending."
    };
  }
  if (operatorStatus === "approved") {
    return {
      kind: "good",
      title: "Operator approved",
      detail: "Session is active and operator approval is complete."
    };
  }
  if (operatorStatus === "rejected") {
    return {
      kind: "bad",
      title: "Operator rejected",
      detail: "Session is active, but operator application was rejected."
    };
  }
  return {
    kind: "good",
    title: "Session active",
    detail: "Session token is active. Continue with client registration and operator onboarding."
  };
}

function syncPortalOnboardingStateBanner() {
  const onboardingState = computePortalOnboardingState();
  onboardingStateBannerEl.dataset.kind = onboardingState.kind || "warn";
  onboardingStateLineEl.classList.remove("good", "warn", "bad");
  if (onboardingState.kind) {
    onboardingStateLineEl.classList.add(onboardingState.kind);
  }
  onboardingStateTitleEl.textContent = onboardingState.title;
  onboardingStateDetailEl.textContent = onboardingState.detail;
  onboardingNextActionEl.textContent = `Next recommended action: ${computePortalNextRecommendedAction()}`;
}

function syncSessionDerivedState(result) {
  clientRegistered = extractBootstrapRegistrationMetadata(result).hasBootstrapDirectory;
}

function normalizeClientRegistrationStatus(value) {
  const parsed = nonEmptyString(value);
  if (!parsed) {
    return undefined;
  }
  return parsed.toLowerCase().replace(/[\s-]+/g, "_");
}

function clientRegistrationStatusRequiresReregister(value) {
  const normalized = normalizeClientRegistrationStatus(value);
  if (!normalized) {
    return false;
  }
  if (CLIENT_REGISTRATION_TRUST_DRIFT_STATUS_KEYS.has(normalized)) {
    return true;
  }
  return (
    normalized.includes("trust_drift") ||
    normalized.includes("manifest_drift") ||
    normalized.includes("degraded_trust") ||
    normalized.includes("trust_degraded") ||
    normalized.includes("stale") ||
    normalized.includes("revoked") ||
    normalized.includes("untrusted") ||
    normalized.includes("re_register") ||
    normalized.includes("reregister")
  );
}

function parseClientRegistrationStatus(payload) {
  const registration = payload?.registration;
  if (!registration || typeof registration !== "object") {
    return undefined;
  }
  const normalized = normalizeClientRegistrationStatus(
    firstDefined(registration.status, registration.registration_status, registration.registrationStatus)
  );
  if (!normalized) {
    return undefined;
  }
  if (normalized === "registered") {
    return true;
  }
  if (normalized === "not_registered") {
    return false;
  }
  if (clientRegistrationStatusRequiresReregister(normalized)) {
    return false;
  }
  return undefined;
}

function collectClientRegistrationActionHints(registration, posture) {
  const hints = [];
  for (const scope of [registration, posture]) {
    if (!scope || typeof scope !== "object") {
      continue;
    }
    for (const key of ["next_actions", "nextActions", "unlock_actions", "unlockActions", "recovery_actions", "recoveryActions"]) {
      const value = scope[key];
      if (Array.isArray(value)) {
        for (const entry of value) {
          pushUniqueNonEmptyString(hints, entry);
        }
      } else {
        pushUniqueNonEmptyString(hints, value);
      }
    }
  }
  return hints;
}

function parseClientRegistrationTrustDriftState(payload) {
  const registration = payload?.registration;
  if (!registration || typeof registration !== "object") {
    return {
      trustDrift: false,
      guidanceText: ""
    };
  }
  const postureValue = firstDefined(
    registration.trust_posture,
    registration.trustPosture,
    registration.manifest_posture,
    registration.manifestPosture,
    registration.registration_posture,
    registration.registrationPosture,
    registration.posture
  );
  const posture = postureValue && typeof postureValue === "object" && !Array.isArray(postureValue) ? postureValue : null;
  const normalizedStatus = normalizeClientRegistrationStatus(
    firstDefined(
      registration.status,
      registration.registration_status,
      registration.registrationStatus,
      posture?.status,
      posture?.registration_status,
      posture?.registrationStatus
    )
  );
  const normalizedTrustState = normalizeClientRegistrationStatus(
    firstDefined(
      registration.trust_state,
      registration.trustState,
      registration.trust_status,
      registration.trustStatus,
      registration.manifest_trust_state,
      registration.manifestTrustState,
      posture?.trust_state,
      posture?.trustState,
      posture?.trust_status,
      posture?.trustStatus,
      posture?.manifest_trust_state,
      posture?.manifestTrustState
    )
  );
  const trustDriftFlag = parseBooleanLike(
    firstDefined(
      registration.trust_drift,
      registration.trustDrift,
      registration.manifest_drift,
      registration.manifestDrift,
      registration.registration_drift,
      registration.registrationDrift,
      registration.re_registration_required,
      registration.reRegistrationRequired,
      registration.reregister_required,
      registration.reregisterRequired,
      posture?.trust_drift,
      posture?.trustDrift,
      posture?.manifest_drift,
      posture?.manifestDrift,
      posture?.re_registration_required,
      posture?.reRegistrationRequired
    )
  );
  const trustDegradedFlag = parseBooleanLike(
    firstDefined(
      registration.trust_degraded,
      registration.trustDegraded,
      registration.degraded_trust,
      registration.degradedTrust,
      registration.registration_trust_degraded,
      registration.registrationTrustDegraded,
      registration.stale_readiness,
      registration.staleReadiness,
      registration.registration_stale,
      registration.registrationStale,
      posture?.trust_degraded,
      posture?.trustDegraded,
      posture?.degraded_trust,
      posture?.degradedTrust,
      posture?.stale_readiness,
      posture?.staleReadiness
    )
  );
  const trustDrift =
    trustDriftFlag === true ||
    trustDegradedFlag === true ||
    clientRegistrationStatusRequiresReregister(normalizedStatus) ||
    clientRegistrationStatusRequiresReregister(normalizedTrustState);
  const reason = toDetailText(
    firstDefined(
      registration.trust_reason,
      registration.trustReason,
      registration.manifest_reason,
      registration.manifestReason,
      registration.registration_reason,
      registration.registrationReason,
      registration.lock_reason,
      registration.lockReason,
      registration.reason,
      registration.message,
      posture?.trust_reason,
      posture?.trustReason,
      posture?.manifest_reason,
      posture?.manifestReason,
      posture?.registration_reason,
      posture?.registrationReason,
      posture?.lock_reason,
      posture?.lockReason,
      posture?.reason,
      posture?.message
    )
  );
  const hints = collectClientRegistrationActionHints(registration, posture);
  const guidance = [];
  if (reason) {
    guidance.push(reason);
  }
  if (hints.length > 0) {
    guidance.push(`Next: ${hints.join("; ")}`);
  }
  return {
    trustDrift,
    guidanceText: guidance.join(" ")
  };
}

function setClientRegistrationTrustDriftState(trustDrift, guidanceText = "") {
  clientRegistrationTrustDriftDetected = trustDrift === true;
  clientRegistrationTrustDriftGuidance = clientRegistrationTrustDriftDetected
    ? nonEmptyString(guidanceText) || ""
    : "";
}

function applyClientRegistrationPayload(payload) {
  const registrationStatus = parseClientRegistrationStatus(payload);
  if (registrationStatus !== undefined) {
    clientRegistered = registrationStatus;
  }
  const trustState = parseClientRegistrationTrustDriftState(payload);
  setClientRegistrationTrustDriftState(trustState.trustDrift, trustState.guidanceText);
  refreshSessionBootstrapDirectoryOptions(payload);
  if (trustState.trustDrift) {
    clientRegistered = false;
  }
}

function setOperatorReadiness(kind, statusText, guidanceText) {
  operatorReadinessEl.dataset.kind = kind || "warn";
  operatorReadinessLineEl.classList.remove("good", "warn", "bad");
  if (kind) {
    operatorReadinessLineEl.classList.add(kind);
  }
  operatorReadinessStatusEl.textContent = statusText;
  operatorReadinessGuidanceEl.textContent = guidanceText;
}

function formatEndpointPostureLabel(posture) {
  const normalized = nonEmptyString(posture);
  if (!normalized) {
    return "Unknown";
  }
  const compact = normalized.replace(/[_-]+/g, " ").trim();
  return compact.charAt(0).toUpperCase() + compact.slice(1);
}

function endpointPostureKind(posture) {
  const normalized = nonEmptyString(posture)?.toLowerCase().replace(/[\s-]+/g, "_");
  if (!normalized) {
    return "warn";
  }
  if (
    normalized.includes("untrusted") ||
    normalized.includes("invalid") ||
    normalized.includes("revoked") ||
    normalized.includes("failed") ||
    normalized.includes("blocked")
  ) {
    return "bad";
  }
  if (
    normalized.includes("trusted") ||
    normalized.includes("strict") ||
    normalized.includes("pinned") ||
    normalized.includes("healthy") ||
    normalized === "ok" ||
    normalized === "pass"
  ) {
    return "good";
  }
  return "warn";
}

function parseEndpointPostureObject(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : undefined;
}

function endpointPostureCount(value) {
  const parsed = numberOrUndefined(value);
  return parsed === undefined ? undefined : Math.floor(parsed);
}

function formatEndpointPostureCountSummary(posture) {
  const totalUrls = endpointPostureCount(firstDefined(posture.total_urls, posture.totalUrls));
  const httpUrls = endpointPostureCount(firstDefined(posture.http_urls, posture.httpUrls));
  const httpsUrls = endpointPostureCount(firstDefined(posture.https_urls, posture.httpsUrls));
  if (totalUrls === undefined && httpUrls === undefined && httpsUrls === undefined) {
    return "";
  }
  const totalText = totalUrls !== undefined ? `${totalUrls} total` : "total unknown";
  const httpsText = httpsUrls !== undefined ? `${httpsUrls} HTTPS` : "HTTPS ?";
  const httpText = httpUrls !== undefined ? `${httpUrls} HTTP` : "HTTP ?";
  return `${totalText} (${httpsText} / ${httpText})`;
}

function endpointPostureKindFromObject(posture, warnings) {
  const hasRemoteHTTP = parseBooleanLike(firstDefined(posture.has_remote_http, posture.hasRemoteHttp));
  const mixedScheme = parseBooleanLike(firstDefined(posture.mixed_scheme, posture.mixedScheme));
  const httpUrls = endpointPostureCount(firstDefined(posture.http_urls, posture.httpUrls));
  const httpsUrls = endpointPostureCount(firstDefined(posture.https_urls, posture.httpsUrls));
  if (hasRemoteHTTP === true) {
    return "bad";
  }
  if (mixedScheme === true || warnings.length > 0) {
    return "warn";
  }
  if (httpUrls === 0 && httpsUrls !== undefined && httpsUrls > 0) {
    return "good";
  }
  return "warn";
}

function endpointPostureGuidanceFromObject(posture, warnings) {
  const totalUrls = endpointPostureCount(firstDefined(posture.total_urls, posture.totalUrls));
  const httpUrls = endpointPostureCount(firstDefined(posture.http_urls, posture.httpUrls));
  const httpsUrls = endpointPostureCount(firstDefined(posture.https_urls, posture.httpsUrls));
  const mixedScheme = parseBooleanLike(firstDefined(posture.mixed_scheme, posture.mixedScheme));
  const hasRemoteHTTP = parseBooleanLike(firstDefined(posture.has_remote_http, posture.hasRemoteHttp));
  const guidanceParts = [];
  if (totalUrls !== undefined || httpUrls !== undefined || httpsUrls !== undefined) {
    guidanceParts.push(
      `URL totals: ${totalUrls ?? "?"} total, ${httpsUrls ?? "?"} HTTPS, ${httpUrls ?? "?"} HTTP.`
    );
  }
  if (mixedScheme === true) {
    guidanceParts.push("Mixed HTTP/HTTPS endpoint posture detected; prefer HTTPS for issuer and trust endpoints.");
  } else if (mixedScheme === false && httpUrls === 0 && httpsUrls !== undefined && httpsUrls > 0) {
    guidanceParts.push("All discovered issuer/trust endpoints are HTTPS.");
  }
  if (hasRemoteHTTP === true) {
    guidanceParts.push("Remote HTTP endpoint detected; migrate remote issuer/trust endpoints to HTTPS.");
  } else if (hasRemoteHTTP === false && httpUrls !== undefined) {
    guidanceParts.push("No remote HTTP endpoints detected.");
  }
  if (warnings.length > 0) {
    guidanceParts.push(warnings.join(" "));
  }
  if (guidanceParts.length === 0) {
    return "Endpoint posture object is available. Refresh server status after endpoint changes.";
  }
  return guidanceParts.join(" ");
}

function setEndpointPosture(kind, statusText, guidanceText) {
  endpointPostureEl.dataset.kind = kind || "warn";
  endpointPostureLineEl.classList.remove("good", "warn", "bad");
  if (kind) {
    endpointPostureLineEl.classList.add(kind);
  }
  endpointPostureStatusEl.textContent = statusText;
  endpointPostureGuidanceEl.textContent = guidanceText;
}

function refreshEndpointPosture() {
  const sessionToken = byId("session_token").value.trim();
  if (!sessionToken && !serverReadiness) {
    setEndpointPosture(
      "warn",
      "Not signed in",
      "Sign in and refresh server readiness to load endpoint trust posture."
    );
    return;
  }

  if (!serverReadiness) {
    setEndpointPosture(
      "warn",
      "Unknown",
      "Refresh server readiness to load endpoint trust posture and warnings."
    );
    return;
  }

  const posture = serverReadiness.endpointPosture;
  const postureObject = parseEndpointPostureObject(posture);
  const postureText = nonEmptyString(typeof posture === "string" ? posture : undefined);
  const warnings = Array.isArray(serverReadiness.endpointWarnings)
    ? serverReadiness.endpointWarnings
    : [];
  if (postureObject) {
    const mode = nonEmptyString(firstDefined(postureObject.server_mode, postureObject.serverMode));
    const modeText = mode ? `${formatEndpointPostureLabel(mode)} mode` : "Mode unknown";
    const countSummary = formatEndpointPostureCountSummary(postureObject);
    const statusText = countSummary ? `${modeText} - ${countSummary}` : modeText;
    const guidance = endpointPostureGuidanceFromObject(postureObject, warnings);
    setEndpointPosture(endpointPostureKindFromObject(postureObject, warnings), statusText, guidance);
    return;
  }

  if (postureText) {
    const guidance =
      warnings.length > 0
        ? warnings.join(" ")
        : "No endpoint warnings reported by readiness.";
    setEndpointPosture(endpointPostureKind(postureText), formatEndpointPostureLabel(postureText), guidance);
    return;
  }

  if (warnings.length > 0) {
    setEndpointPosture("warn", "Warnings reported", warnings.join(" "));
    return;
  }

  setEndpointPosture("warn", "Unavailable", "Endpoint posture not provided by readiness payload.");
}

function setClientReadiness(kind, statusText, guidanceText, state) {
  clientReadinessEl.dataset.kind = kind || "warn";
  clientReadinessEl.dataset.state = state || "unknown";
  clientReadinessLineEl.classList.remove("good", "warn", "bad");
  if (kind) {
    clientReadinessLineEl.classList.add(kind);
  }
  clientReadinessStatusEl.textContent = statusText;
  clientReadinessGuidanceEl.textContent = guidanceText;
}

function syncFailClosedMutatingActionState() {
  const isBusy = document.body.classList.contains("is-busy");
  const lockByFailClosed = configEndpointUnavailableFailClosedMode();
  const disabled = isBusy || lockByFailClosed;
  for (const button of [connectBtnEl, applyOperatorBtnEl, approveOperatorBtnEl, rejectOperatorBtnEl]) {
    button.disabled = disabled;
    button.setAttribute("aria-disabled", String(disabled));
    if (lockByFailClosed) {
      button.title = failClosedMutatingActionStatusDetail();
      continue;
    }
    button.removeAttribute("title");
  }
  refreshOperatorApprovalPolicyHint();
}

function syncClientRegistrationAction(readiness) {
  if (!registerClientBtnEl) {
    return;
  }
  const isBusy = document.body.classList.contains("is-busy");
  const lockByFailClosed = configEndpointUnavailableFailClosedMode();
  const lockByState = readiness.state === "role_locked" || readiness.state === "not_signed_in";
  const disabled = isBusy || lockByState || lockByFailClosed;
  registerClientBtnEl.disabled = disabled;
  registerClientBtnEl.setAttribute("aria-disabled", String(disabled));
  if (lockByFailClosed) {
    registerClientBtnEl.title = failClosedMutatingActionStatusDetail();
    return;
  }
  if (lockByState) {
    registerClientBtnEl.title = readiness.guidanceText;
    return;
  }
  registerClientBtnEl.removeAttribute("title");
}

function assertClientRegistrationActionAllowed() {
  if (configEndpointUnavailableFailClosedMode()) {
    throw new Error(`Client registration is unavailable: ${failClosedMutatingActionStatusDetail()}`);
  }
  const readiness = computeClientReadiness();
  if (readiness.state === "not_signed_in" || readiness.state === "role_locked") {
    throw new Error(`Client registration is unavailable: ${readiness.guidanceText}`);
  }
}

function composeClientRegistrationTrustDriftGuidance() {
  const base = "Registration trust is stale or degraded against the current manifest.";
  const next = "Use Register Client to re-register and refresh trusted bootstrap directories.";
  const reason = nonEmptyString(clientRegistrationTrustDriftGuidance);
  return reason ? `${base} ${reason} ${next}` : `${base} ${next}`;
}

function computeClientReadiness() {
  const token = byId("session_token").value.trim();
  const role = (serverReadiness?.role || byId("role").value).trim().toLowerCase() || "client";
  const clientTabVisible = serverReadiness?.clientTabVisible;
  const clientLockReason = serverReadiness?.clientLockReason;

  if (!token) {
    return {
      state: "not_signed_in",
      kind: "warn",
      statusText: "Not signed in",
      guidanceText: "Sign in first to unlock client registration."
    };
  }

  if (isServerOnlyRole(role) || (clientTabVisible === false && !isServerRoleUnlocked(role))) {
    return {
      state: "role_locked",
      kind: "bad",
      statusText: "Role-locked",
      guidanceText:
        clientLockReason ||
        (isServerOnlyRole(role)
          ? "This session is server-only, so the client lane is locked. Continue in Step 3 for server workflow actions."
          : "Client lane is locked for this role.")
    };
  }

  if (clientRegistrationTrustDriftDetected) {
    return {
      state: "re_registration_required",
      kind: "bad",
      statusText: "Re-registration required",
      guidanceText: composeClientRegistrationTrustDriftGuidance()
    };
  }

  if (clientRegistered) {
    return {
      state: "registered",
      kind: "good",
      statusText: "Registered",
      guidanceText: "Client profile is registered for this session and ready for client lane actions."
    };
  }

  if (isServerRoleUnlocked(role) && clientTabVisible === false) {
    return {
      state: "ready_to_register",
      kind: "warn",
      statusText: "Ready to register",
      guidanceText:
        `${clientLockReason || "Client registration is required before this operator/admin session can use the client lane."} ` +
        "Use Register Client to continue."
    };
  }

  return {
    state: "ready_to_register",
    kind: "warn",
    statusText: "Ready to register",
    guidanceText: "Use Register Client to finish Step 2 and unlock client lane actions."
  };
}

function computeOperatorReadiness() {
  const token = byId("session_token").value.trim();
  const role = (serverReadiness?.role || byId("role").value).trim().toLowerCase() || "client";
  const statusLabel = formatOperatorApplicationStatusLabel(
    serverReadiness?.operatorApplicationStatus || operatorApplicationStatus
  );

  if (!token && !serverReadiness) {
    return {
      kind: "warn",
      statusText: "Not signed in",
      guidanceText: `Sign in first to unlock operator onboarding. ${formatDirectActionGuidance(
        "Request Challenge, then run Sign + Verify (Wallet) or Verify + Create Session",
        "active session token"
      )}`
    };
  }

  if (serverReadiness) {
    if (serverReadiness.lifecycleActionsUnlocked === true) {
      if (serverReadiness.serviceMutationsConfigured === false) {
        return {
          kind: "warn",
          statusText: statusLabel,
          guidanceText: appendChainBindingGuidance(
            "Server role is eligible, but lifecycle commands are not configured on the daemon.",
            serverReadiness
          )
        };
      }
      return {
        kind: "good",
        statusText: statusLabel,
        guidanceText: appendChainBindingGuidance(
          "Server controls are unlocked by backend readiness policy.",
          serverReadiness
        )
      };
    }
    const reason = serverReadiness.lockReason || "Server lifecycle actions are locked by backend readiness policy.";
    const nextActions = serverReadiness.unlockActions.length > 0 ? ` Next: ${serverReadiness.unlockActions.join("; ")}` : "";
    const requiredConditions =
      serverReadiness.unlockActions.length > 0
        ? serverReadiness.unlockActions.join("; ")
        : "approved operator application and matching session/application chain_operator_id values";
    return {
      kind:
        serverReadiness.operatorApplicationStatus === "rejected" || serverReadiness.tabVisible === false
          ? "bad"
          : "warn",
      statusText: statusLabel,
      guidanceText: appendChainBindingGuidance(
        `${reason}${nextActions} ${formatDirectActionGuidance(
          "Use Apply Operator Role or Check Operator Status, then Refresh Session",
          requiredConditions
        )}`,
        serverReadiness
      )
    };
  }

  if (role === "admin") {
    return {
      kind: "good",
      statusText: statusLabel,
      guidanceText: "Server controls are eligible for this session role."
    };
  }

  if (role === "operator") {
    switch (operatorApplicationStatus) {
      case "approved":
        return {
          kind: "good",
          statusText: statusLabel,
          guidanceText:
            "Operator application is approved, but server lifecycle unlock still requires strict chain binding (session/app chain_operator_id both present and matching). Refresh readiness/session to confirm."
        };
      case "rejected":
        return {
          kind: "bad",
          statusText: statusLabel,
          guidanceText: `Operator role is not fully eligible. ${formatDirectActionGuidance(
            "Apply Operator Role again, then Check Operator Status and Refresh Session",
            "approved operator application and matching session/application chain_operator_id values"
          )}`
        };
      case "pending":
        return {
          kind: "warn",
          statusText: statusLabel,
          guidanceText: `Operator role is not fully eligible yet. ${formatDirectActionGuidance(
            "Wait for approval, then Check Operator Status and Refresh Session",
            "approved operator application and matching session/application chain_operator_id values"
          )}`
        };
      case "not_submitted":
        return {
          kind: "warn",
          statusText: statusLabel,
          guidanceText: `Operator role is not fully eligible yet. ${formatDirectActionGuidance(
            "Apply Operator Role",
            "approved operator application and matching session/application chain_operator_id values"
          )}`
        };
      default:
        return {
          kind: "warn",
          statusText: statusLabel,
          guidanceText: `Operator role is not fully eligible yet. ${formatDirectActionGuidance(
            "Check Operator Status and refresh Session",
            "approved operator application and matching session/application chain_operator_id values"
          )}`
        };
    }
  }

  switch (operatorApplicationStatus) {
    case "not_submitted":
      return {
        kind: "warn",
        statusText: statusLabel,
        guidanceText: `Apply operator role to start server approval. ${formatDirectActionGuidance(
          "Apply Operator Role",
          "approved operator application and matching session/application chain_operator_id values"
        )}`
      };
    case "pending":
      return {
        kind: "warn",
        statusText: statusLabel,
        guidanceText: `Operator application is pending approval. ${formatDirectActionGuidance(
          "Wait for approval, then Refresh Session",
          "approved operator application and matching session/application chain_operator_id values"
        )}`
      };
    case "rejected":
      return {
        kind: "bad",
        statusText: statusLabel,
        guidanceText: `Operator application was rejected. ${formatDirectActionGuidance(
          "Apply Operator Role again or contact an admin reviewer",
          "approved operator application and matching session/application chain_operator_id values"
        )}`
      };
    case "approved":
      return {
        kind: "warn",
        statusText: statusLabel,
        guidanceText: "Approval detected. Refresh or rotate the session to lift role to operator."
      };
    default:
      return {
        kind: "warn",
        statusText: statusLabel,
        guidanceText: "Check operator status to see the next unlock step."
      };
  }
}

function refreshOperatorReadiness() {
  const readiness = computeOperatorReadiness();
  setOperatorReadiness(readiness.kind, readiness.statusText, readiness.guidanceText);
  refreshEndpointPosture();
  refreshClientReadiness();
}

function refreshClientReadiness() {
  const readiness = computeClientReadiness();
  setClientReadiness(readiness.kind, readiness.statusText, readiness.guidanceText, readiness.state);
  syncClientRegistrationAction(readiness);
  syncFailClosedMutatingActionState();
  refreshSessionBootstrapDirectoryControls();
  refreshOnboardingSteps();
  syncWorkspaceTabLockState();
  syncPortalOnboardingStateBanner();
}

function setOperatorApplicationStatus(value) {
  operatorApplicationStatus = normalizeOperatorApplicationStatus(value);
  refreshOperatorReadiness();
}

function bindReadinessListeners() {
  byId("session_token").addEventListener("input", () => {
    setServerReadiness(null);
    setOperatorApplicationStatus(undefined);
    setSelectedApplicationUpdatedAt("");
    clientRegistered = false;
    setClientRegistrationTrustDriftState(false, "");
    setOperatorListNextCursor("");
    refreshSessionBootstrapDirectoryControls();
  });
  byId("wallet_address").addEventListener("input", () => {
    setSelectedApplicationUpdatedAt("");
  });
  byId("chain_operator_id").addEventListener("input", () => {
    setSelectedApplicationUpdatedAt("");
  });
  byId("challenge_id").addEventListener("input", () => {
    clearWalletSignatureContext();
    syncPortalOnboardingStateBanner();
  });
  byId("signature").addEventListener("input", () => {
    clearWalletSignatureContext();
    syncPortalOnboardingStateBanner();
  });
  challengeMessageEl.addEventListener("input", () => {
    syncPortalOnboardingStateBanner();
  });
  byId("wallet_provider").addEventListener("change", () => {
    syncWalletExtensionReadinessHint();
  });
  walletChainIdEl.addEventListener("input", () => {
    syncWalletExtensionReadinessHint();
  });
}

function bindCompatibilityOverrideListeners() {
  compatOverrideEl.addEventListener("change", () => {
    refreshCompatibilityOverrideControls();
  });
  byId("api_base").addEventListener("change", () => {
    void refreshConnectPolicyConfigBestEffort({ quiet: true });
    void refreshBootstrapTrustStatusBestEffort({ quiet: true });
  });
}

function bindOperatorListFilterListeners() {
  const clearPaginationCursor = () => {
    operatorListActiveFilters = readOperatorListFilters();
    setOperatorListNextCursor("");
  };
  operatorListStatusEl.addEventListener("change", clearPaginationCursor);
  operatorListSearchEl.addEventListener("input", clearPaginationCursor);
  operatorListLimitEl.addEventListener("input", clearPaginationCursor);
}

function setBusy(isBusy) {
  document.body.classList.toggle("is-busy", isBusy);
  for (const button of actionButtons) {
    button.disabled = isBusy;
    button.setAttribute("aria-disabled", String(isBusy));
  }
  syncOperatorListNextPageAction();
  syncManualSignInAction();
  if (!isBusy) {
    refreshClientReadiness();
  }
}

function setStatus(kind, title, detail) {
  statusBannerEl.dataset.kind = kind || "idle";
  statusLineEl.classList.remove("good", "warn", "bad");
  if (kind) {
    statusLineEl.classList.add(kind);
  }
  statusTitleEl.textContent = title;
  statusDetailEl.textContent = detail;
}

function print(label, payload) {
  const displayPayload = sanitizePayloadForDisplay(withBootstrapDirectoryFallbackHint(payload, payload));
  const text = typeof displayPayload === "string" ? displayPayload : JSON.stringify(displayPayload, null, 2);
  const boundedText =
    text.length <= MAX_OUTPUT_CHARS
      ? text
      : `${text.slice(0, MAX_OUTPUT_CHARS)}\n...[TRUNCATED ${text.length - MAX_OUTPUT_CHARS} chars]`;
  outputEl.textContent = `[${new Date().toISOString()}] ${label}\n${boundedText}`;
}

function apiBase() {
  const raw = byId("api_base").value.trim();
  if (!raw) {
    throw new Error("API base URL is required.");
  }
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error("API base URL must be an absolute http(s) URL.");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("API base URL must start with http:// or https://.");
  }
  if (parsed.username || parsed.password) {
    throw new Error("API base URL must not include username or password credentials.");
  }
  if (parsed.search || parsed.hash) {
    throw new Error("API base URL must not include query or fragment values.");
  }
  if (parsed.protocol === "http:" && !isLiteralLoopbackHost(parsed.hostname)) {
    throw new Error("HTTP API base URLs are restricted to literal loopback hosts (127.0.0.1 or [::1]).");
  }
  if (parsed.protocol === "https:" || isLiteralLoopbackHost(parsed.hostname)) {
    // Allowed.
  } else {
    throw new Error("Non-loopback API base URLs must use https.");
  }
  const pathname = parsed.pathname.replace(/\/+$/, "");
  return pathname && pathname !== "/" ? `${parsed.origin}${pathname}` : parsed.origin;
}

function localApiAuthToken() {
  return localApiAuthTokenEl.value.trim();
}

function createApiError(response, json) {
  let message =
    (typeof json?.error === "string" && json.error.trim()) || `${response.status} ${response.statusText}`;
  if (response.status === 401 && !localApiAuthToken()) {
    message = `${message} Local API bearer token is missing. Set Local API auth token in the portal and retry.`;
  }
  const err = new Error(message);
  err.status = response.status;
  err.statusText = response.statusText;
  return err;
}

function isDecisionConflictError(err) {
  if (typeof err?.status === "number") {
    return err.status === 409;
  }
  const message = String(err && err.message ? err.message : err || "");
  return /\b409\b/.test(message);
}

async function post(path, body) {
  const token = localApiAuthToken();
  const headers = {
    "Content-Type": "application/json"
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const response = await fetch(`${apiBase()}${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body || {})
  });
  const text = await response.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    json = { ok: false, error: text || "non-json response" };
  }
  if (!response.ok) {
    throw createApiError(response, json);
  }
  return json;
}

async function get(path) {
  const token = localApiAuthToken();
  const headers = {};
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const response = await fetch(`${apiBase()}${path}`, {
    method: "GET",
    headers
  });
  const text = await response.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    json = { ok: false, error: text || "non-json response" };
  }
  if (!response.ok) {
    throw createApiError(response, json);
  }
  return json;
}

function applySession(result) {
  syncSessionDerivedState(result);
  const token = result.session_token || byId("session_token").value.trim();
  byId("session_token").value = token;
  const role = result.session?.role || result.role || result.profile?.role || "client";
  byId("role").value = role;
  refreshSessionBootstrapDirectoryOptions(result);
  refreshOperatorReadiness();
  persistPortalState();
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

function walletExtensionDetected(walletProvider) {
  const provider = normalizeWalletProviderValue(walletProvider);
  if (!provider) {
    return false;
  }
  const view = window;
  if (provider === "keplr") {
    return Boolean(view.keplr && typeof view.keplr === "object");
  }
  return Boolean(
    (view.leap && typeof view.leap === "object") ||
      (view.leap?.cosmos && typeof view.leap.cosmos === "object")
  );
}

function syncWalletExtensionReadinessHint() {
  if (!walletExtensionHintEl) {
    return;
  }
  const walletProvider = byId("wallet_provider").value;
  const providerLabel = walletProviderDisplayName(walletProvider);
  const chainId = walletChainIdEl.value.trim();
  const extensionDetected = walletExtensionDetected(walletProvider);
  const walletPolicyLocked = gpmProductionMode || strictWalletExtensionSourceRequired();
  const requirementSummary = walletPolicyLocked
    ? "Wallet extension Sign + Verify is required by active policy."
    : "Wallet extension Sign + Verify is available and recommended.";
  const extensionSummary = extensionDetected
    ? `${providerLabel} extension detected in this browser.`
    : `${providerLabel} extension not detected in this browser. Install/enable it and reload before signing.`;
  const chainSummary = chainId
    ? `Chain: ${chainId}.`
    : "Set wallet chain ID before signing with wallet extension.";
  walletExtensionHintEl.textContent = `${requirementSummary} ${extensionSummary} ${chainSummary}`;
  walletExtensionHintEl.classList.toggle("locked", walletPolicyLocked || !extensionDetected || !chainId);
}

function challengeMessageFromPayload(payload) {
  return (
    nonEmptyString(
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
    nonEmptyString(
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
    byId("challenge_id").value = challengeId;
  }
  challengeMessageEl.value = challengeMessageFromPayload(payload);
  syncPortalOnboardingStateBanner();
}

function readWalletPayload() {
  return {
    wallet_address: byId("wallet_address").value.trim(),
    wallet_provider: byId("wallet_provider").value
  };
}

function normalizeWalletAddressForCompare(value) {
  const parsed = nonEmptyString(value);
  if (!parsed) {
    return "";
  }
  return parsed.toLowerCase();
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
  const publicKey = nonEmptyString(
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
  const publicKeyType = nonEmptyString(
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

function setWalletSignatureContext(context) {
  walletSignatureContext = context && typeof context === "object" ? context : null;
}

function clearWalletSignatureContext() {
  walletSignatureContext = null;
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
  const normalizedWalletAddress = nonEmptyString(walletAddress);
  const normalizedChallengeId = nonEmptyString(challengeId);
  const normalizedChallengeMessage = nonEmptyString(challengeMessage);
  const normalizedChainId = nonEmptyString(chainId);
  const normalizedSignature = nonEmptyString(signature);
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
  const requestChallengeId = nonEmptyString(request.challenge_id) || "";
  const requestSignature = nonEmptyString(request.signature) || "";
  if (!requestChallengeId || !requestSignature) {
    return false;
  }
  if (requestChallengeId !== (nonEmptyString(context.challenge_id) || "")) {
    return false;
  }
  if (requestSignature !== (nonEmptyString(context.signature) || "")) {
    return false;
  }
  const currentChallengeMessage = challengeMessageEl.value.trim();
  if (currentChallengeMessage !== (nonEmptyString(context.challenge_message) || "")) {
    return false;
  }
  const currentChainId = walletChainIdEl.value.trim();
  if (currentChainId !== (nonEmptyString(context.chain_id) || "")) {
    return false;
  }
  return true;
}

function authVerifySignatureContext(request) {
  if (!isWalletSignatureContextValidForRequest(walletSignatureContext, request)) {
    return undefined;
  }
  const context = walletSignatureContext?.metadata;
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
    nonEmptyString(firstDefined(accounts[0]?.address, accounts[0]?.bech32Address, accounts[0]?.wallet_address)) ||
    undefined
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
    throw new Error(`${walletProviderDisplayName(provider)} extension was not detected. Install it and reload the page.`);
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
    const bech32Address = nonEmptyString(firstDefined(key?.bech32Address, key?.address, key?.wallet_address));
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

function extractSignArbitrarySignature(payload) {
  return (
    nonEmptyString(
      firstDefined(
        payload?.signature?.signature,
        payload?.signature,
        payload?.result?.signature?.signature,
        payload?.result?.signature
      )
    ) || ""
  );
}

async function signChallengeWithWalletExtension() {
  const challengeId = byId("challenge_id").value.trim();
  const challengeMessage = challengeMessageEl.value.trim();
  const chainId = walletChainIdEl.value.trim();
  if (!challengeId) {
    throw new Error("challenge_id is required. Request challenge first.");
  }
  if (!challengeMessage) {
    throw new Error("challenge_message is required. Request challenge first.");
  }
  if (!chainId) {
    throw new Error("wallet_chain_id is required to sign with wallet extension.");
  }
  const { wallet_provider: walletProvider } = readWalletPayload();
  const { extension, provider } = resolveWalletExtensionClient(walletProvider);
  await extension.enable(chainId);

  let walletAddress = byId("wallet_address").value.trim();
  if (!walletAddress) {
    walletAddress = await resolveWalletAddressFromExtension(extension, chainId);
    if (!walletAddress) {
      throw new Error(
        `Unable to resolve wallet address from ${walletProviderDisplayName(provider)} extension. Enter wallet_address and retry.`
      );
    }
    byId("wallet_address").value = walletAddress;
  }

  const signaturePayload = await extension.signArbitrary(chainId, walletAddress, challengeMessage);
  const signature = extractSignArbitrarySignature(signaturePayload);
  if (!signature) {
    throw new Error("Wallet extension returned an empty signature for signArbitrary.");
  }
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
  byId("signature").value = signature;
  persistPortalState();
  syncPortalOnboardingStateBanner();
  return {
    wallet_provider: provider,
    wallet_address: walletAddress,
    challenge_id: challengeId,
    chain_id: chainId,
    signature
  };
}

async function requestAuthChallenge() {
  const result = await post("/v1/gpm/auth/challenge", readWalletPayload());
  applyChallengePayload(result);
  clearWalletSignatureContext();
  return result;
}

async function requestAuthVerify(options = {}) {
  const source = nonEmptyString(options?.source)?.toLowerCase() || "manual";
  const manualSource = source !== "wallet_extension";
  if (manualSource && gpmProductionMode) {
    throw new Error("Manual verify is disabled in production mode. Use Sign + Verify (Wallet).");
  }
  if (manualSource && strictWalletExtensionSourceRequired()) {
    const policySource = formatPolicySourceLabel(authVerifyRequireWalletExtensionPolicySource);
    throw new Error(
      `Manual verify is disabled by active auth policy (wallet-extension-source required; source: ${policySource}). Use Sign + Verify (Wallet).`
    );
  }
  const request = {
    ...readWalletPayload(),
    challenge_id: byId("challenge_id").value.trim(),
    signature: byId("signature").value.trim()
  };
  const signatureContext = authVerifySignatureContext(request);
  if (signatureContext) {
    Object.assign(request, signatureContext);
  }
  const result = await post("/v1/gpm/auth/verify", request);
  setOperatorApplicationStatus(undefined);
  setSelectedApplicationUpdatedAt("");
  applySession(result);
  await refreshClientRegistrationStatus({ quiet: true });
  await refreshOperatorApplicationStatus({ quiet: true });
  await refreshServerReadinessStatus({ quiet: true });
  await refreshBootstrapTrustStatusBestEffort({ quiet: true });
  return result;
}

async function requestWalletSignIn() {
  await signChallengeWithWalletExtension();
  return requestAuthVerify({ source: "wallet_extension" });
}

function sessionRoleFromResult(result) {
  return result.session?.role || result.role || result.profile?.role || byId("role").value || "client";
}

async function requestSessionLifecycle(action = "status") {
  const token = byId("session_token").value.trim();
  return post("/v1/gpm/session", { session_token: token, action });
}

async function requestOperatorStatus() {
  const request = {
    session_token: byId("session_token").value.trim() || undefined,
    wallet_address: byId("wallet_address").value.trim() || undefined
  };
  return post("/v1/gpm/onboarding/operator/status", request);
}

async function requestClientStatus() {
  const request = {
    session_token: byId("session_token").value.trim() || undefined,
    wallet_address: byId("wallet_address").value.trim() || undefined
  };
  return post("/v1/gpm/onboarding/client/status", request);
}

function applyOnboardingOverviewPayload(payload) {
  if (!payload || typeof payload !== "object") {
    return;
  }
  syncSessionDerivedState(payload);
  refreshSessionBootstrapDirectoryOptions(payload);
  const role = sessionRoleFromResult(payload);
  if (typeof role === "string" && role.trim()) {
    byId("role").value = role;
  }
  applyClientRegistrationPayload(payload);
  applyBootstrapTrustStatusPayload(payload);
  setServerReadiness(parseServerReadiness(payload));
}

async function requestOverview() {
  const sessionToken = byId("session_token").value.trim();
  return post("/v1/gpm/onboarding/overview", { session_token: sessionToken });
}

async function requestServerStatus() {
  const request = {
    session_token: byId("session_token").value.trim() || undefined,
    wallet_address: byId("wallet_address").value.trim() || undefined
  };
  return post("/v1/gpm/onboarding/server/status", request);
}

function connectValidationHint() {
  if (configEndpointUnavailableFailClosedMode()) {
    return failClosedMutatingActionStatusDetail();
  }
  if (gpmProductionMode) {
    return "sign in and register the client profile before connecting (production mode)";
  }
  if (connectRequireSession) {
    return "session_token is required in session-required connect mode; sign in first";
  }
  if (allowLegacyConnectOverride) {
    return "sign in + register client, or provide compatibility bootstrap_directory + invite";
  }
  return "sign in and register the client profile before connecting";
}

function buildConnectRequest() {
  const pathProfile = byId("path_profile").value;
  const sessionToken = byId("session_token").value.trim();
  const request = {
    session_token: sessionToken || undefined,
    path_profile: pathProfile,
    policy_profile: pathProfile,
    interface: nonEmptyString(connectInterfaceEl.value),
    discovery_wait_sec: positiveIntegerOrUndefined(connectDiscoveryWaitSecEl.value),
    ready_timeout_sec: positiveIntegerOrUndefined(connectReadyTimeoutSecEl.value),
    run_preflight: connectRunPreflightEl.checked,
    prod_profile: connectProdProfileEl.checked,
    install_route: connectInstallRouteEl.checked
  };
  if (sessionToken && !compatibilityOverrideEnabled()) {
    const bootstrapDirectory = nonEmptyString(sessionBootstrapDirectoryEl.value);
    const bootstrapDirectoryIsRendered =
      bootstrapDirectory &&
      Array.from(sessionBootstrapDirectoryEl.options).some((option) => option.value === bootstrapDirectory);
    if (bootstrapDirectoryIsRendered) {
      request.session_bootstrap_directory = bootstrapDirectory;
    }
  }
  if (compatibilityOverrideEnabled()) {
    const bootstrap = nonEmptyString(bootstrapDirectoryEl.value);
    const invite = nonEmptyString(inviteKeyEl.value);
    if (bootstrap) {
      request.bootstrap_directory = bootstrap;
    }
    if (invite) {
      request.invite_key = invite;
    }
  }
  return request;
}

function assertConnectActionAllowed(request) {
  if (configEndpointUnavailableFailClosedMode()) {
    throw new Error(`Connect is unavailable: ${failClosedMutatingActionStatusDetail()}`);
  }
  const sessionToken = typeof request?.session_token === "string" ? request.session_token.trim() : "";
  if (!sessionToken) {
    return;
  }
  const readiness = computeClientReadiness();
  if (!isClientTabVisibleRole() || readiness.state === "role_locked") {
    throw new Error(`Connect is unavailable: ${readiness.guidanceText}`);
  }
}

function assertOperatorMutationActionAllowed(actionLabel) {
  if (configEndpointUnavailableFailClosedMode()) {
    throw new Error(`${actionLabel} is unavailable: ${failClosedMutatingActionStatusDetail()}`);
  }
}

function buildOperatorModerationAuthRequest(actionLabel) {
  const sessionToken = byId("session_token").value.trim();
  const adminToken = adminTokenEl.value.trim();

  if (operatorApprovalRequireSession === true) {
    if (!sessionToken) {
      throw new Error(
        `${actionLabel} requires session_token by policy; legacy admin_token fallback is disabled. Sign in with an admin session and retry.`
      );
    }
    return {
      session_token: sessionToken
    };
  }

  if (!sessionToken && !adminToken) {
    throw new Error(`${actionLabel} requires session_token or admin_token.`);
  }

  return {
    session_token: sessionToken || undefined,
    admin_token: adminToken || undefined
  };
}

async function requestConnectControl() {
  const request = buildConnectRequest();
  assertConnectActionAllowed(request);
  if (!request.session_token && (!request.bootstrap_directory || !request.invite_key)) {
    throw new Error(connectValidationHint());
  }
  const result = await post("/v1/connect", request);
  inviteKeyEl.value = "";
  persistPortalState();
  return result;
}

async function requestDisconnectControl() {
  return post("/v1/disconnect", {});
}

async function requestConnectionStatus() {
  return get("/v1/status");
}

async function requestServiceLifecycle(action) {
  const normalizedAction = nonEmptyString(action)?.toLowerCase();
  if (!normalizedAction || !["start", "stop", "restart"].includes(normalizedAction)) {
    throw new Error("service lifecycle action must be start, stop, or restart.");
  }
  assertServiceLifecycleActionAllowed(normalizedAction);
  const sessionToken = byId("session_token").value.trim();
  if (!sessionToken) {
    throw new Error("session_token is required for server lifecycle actions. Sign in first.");
  }
  return post(`/v1/gpm/service/${normalizedAction}`, { session_token: sessionToken });
}

function assertServiceLifecycleActionAllowed(action) {
  const state = computeServerLifecycleControlState();
  if (state.disabled) {
    throw new Error(`${action} is unavailable: ${state.hint || "Server lifecycle controls are locked by policy."}`);
  }
}

async function requestAuditRecent() {
  const filters = readAuditRecentFilters({
    fallbackLimit: AUDIT_RECENT_DEFAULT_LIMIT,
    fallbackOffset: 0,
    fallbackOrder: AUDIT_RECENT_DEFAULT_ORDER
  });
  const { path, request } = buildAuditRecentPath(filters);
  const result = await get(path);
  return {
    result,
    summary: summarizeAuditRecent(result, request)
  };
}

async function requestOperatorList(statusOrOptions, limitValue) {
  const sessionToken = byId("session_token").value.trim();
  if (!sessionToken) {
    throw new Error("session_token is required to list operators. Sign in first.");
  }
  let status = statusOrOptions;
  let limit = limitValue;
  let search = undefined;
  let cursor = undefined;
  if (statusOrOptions && typeof statusOrOptions === "object" && !Array.isArray(statusOrOptions)) {
    status = statusOrOptions.status;
    limit = statusOrOptions.limit;
    search = statusOrOptions.search;
    cursor = statusOrOptions.cursor;
  }
  const request = {
    session_token: sessionToken
  };
  if (status !== undefined) {
    request.status = typeof status === "string" ? status : String(status);
  }
  const normalizedLimit = numberOrUndefined(limit);
  if (normalizedLimit !== undefined && normalizedLimit >= 1) {
    request.limit = Math.floor(normalizedLimit);
  }
  const normalizedSearch = nonEmptyString(search);
  if (normalizedSearch) {
    request.search = normalizedSearch;
  }
  const normalizedCursor = nonEmptyString(cursor);
  if (normalizedCursor) {
    request.cursor = normalizedCursor;
  }
  return post("/v1/gpm/onboarding/operator/list", request);
}

function operatorListSummaryOptions(request = {}) {
  return {
    fallbackStatus: operatorListStatusLabel(request.status),
    fallbackLimit: normalizeOperatorListLimit(request.limit, OPERATOR_LIST_ALL_LIMIT),
    fallbackSearch: normalizeOperatorListSearch(request.search),
    fallbackCursor: normalizeOperatorListSearch(request.cursor)
  };
}

async function runOperatorListQuery(request) {
  const result = await requestOperatorList(request);
  prefillSelectedOperatorFromListPayload(result, { mode: "merge" });
  const pagination = extractOperatorListPagination(result, { fallbackCursor: request?.cursor });
  updateOperatorListContext(
    {
      status: request?.status,
      search: request?.search,
      limit: request?.limit
    },
    pagination.nextCursor || ""
  );
  return {
    result,
    summary: summarizeOperatorList(result, operatorListSummaryOptions(request))
  };
}

async function loadNextPendingOperator() {
  const listResult = await requestOperatorList("pending", OPERATOR_LOAD_NEXT_LIMIT);
  const entries = extractOperatorListEntries(listResult);
  if (entries.length === 0) {
    return withSessionReconciledHint(
      {
        found: false,
        message: "No pending operator applications are currently queued.",
        status: "pending",
        limit: OPERATOR_LOAD_NEXT_LIMIT,
        returned: 0
      },
      listResult
    );
  }
  const nextEntry = entries[0];
  const { walletAddress, chainOperatorId, selectedApplicationUpdatedAtUtc } = extractOperatorPrefillValues(nextEntry);
  applySelectedOperatorPrefill(
    { walletAddress, chainOperatorId, selectedApplicationUpdatedAtUtc },
    { mode: "replace" }
  );
  await refreshServerReadinessStatus({ quiet: true });
  const message =
    walletAddress || chainOperatorId
      ? "Loaded next pending operator into wallet and chain operator fields."
      : "Loaded next pending queue entry, but wallet/chain operator values were empty.";
  return withSessionReconciledHint(
    {
      found: true,
      message,
      wallet_address: walletAddress || null,
      chain_operator_id: chainOperatorId || null,
      selected_application_updated_at: selectedApplicationUpdatedAtUtc || null,
      status: "pending",
      limit: OPERATOR_LOAD_NEXT_LIMIT,
      returned: entries.length
    },
    listResult
  );
}

async function reconcileSessionAfterModerationDecision() {
  const token = byId("session_token").value.trim();
  if (!token) {
    await refreshOperatorApplicationStatus({ quiet: true });
    await refreshServerReadinessStatus({ quiet: true });
    return {
      attempted: false,
      reason: "session token unavailable"
    };
  }
  try {
    const result = await requestSessionLifecycle("status");
    syncSessionDerivedState(result);
    byId("role").value = sessionRoleFromResult(result);
    await refreshClientRegistrationStatus({ quiet: true });
    await refreshOperatorApplicationStatus({ quiet: true });
    await refreshServerReadinessStatus({ quiet: true });
    persistPortalState();
    return {
      attempted: true,
      ok: true,
      session: result
    };
  } catch (err) {
    await refreshOperatorApplicationStatus({ quiet: true });
    await refreshServerReadinessStatus({ quiet: true });
    return {
      attempted: true,
      ok: false,
      error: String(err && err.message ? err.message : err)
    };
  }
}

async function refreshClientRegistrationStatus(options = {}) {
  const { quiet = true } = options;
  const sessionToken = byId("session_token").value.trim();
  if (!sessionToken) {
    clientRegistered = false;
    setClientRegistrationTrustDriftState(false, "");
    refreshClientReadiness();
    return undefined;
  }
  try {
    const overview = await requestOverview();
    applyOnboardingOverviewPayload(overview);
    return overview;
  } catch {
    // Fallback to legacy per-endpoint status refresh for compatibility.
  }
  try {
    const result = await requestClientStatus();
    applyClientRegistrationPayload(result);
    refreshClientReadiness();
    return result;
  } catch (err) {
    if (!quiet) {
      throw err;
    }
    return undefined;
  }
}

async function refreshOperatorApplicationStatus(options = {}) {
  const { quiet = true } = options;
  if (!byId("session_token").value.trim()) {
    setOperatorApplicationStatus(undefined);
    return undefined;
  }
  try {
    const result = await requestOperatorStatus();
    setOperatorApplicationStatus(parseOperatorApplicationStatus(result));
    applySelectedOperatorPrefill(extractOperatorPrefillValues(result), { mode: "merge" });
    return result;
  } catch (err) {
    if (!quiet) {
      throw err;
    }
    return undefined;
  }
}

async function refreshServerReadinessStatus(options = {}) {
  const { quiet = true } = options;
  const sessionToken = byId("session_token").value.trim();
  const walletAddress = byId("wallet_address").value.trim();
  if (!sessionToken && !walletAddress) {
    setServerReadiness(null);
    return undefined;
  }
  if (sessionToken) {
    try {
      const overview = await requestOverview();
      applyOnboardingOverviewPayload(overview);
      return overview;
    } catch {
      // Fallback to legacy per-endpoint status refresh for compatibility.
    }
  }
  try {
    const result = await requestServerStatus();
    setServerReadiness(parseServerReadiness(result));
    return result;
  } catch (err) {
    setServerReadiness(null);
    if (!quiet) {
      throw err;
    }
    return undefined;
  }
}

async function run(label, fn, options = {}) {
  const outputMapper = typeof options.outputMapper === "function" ? options.outputMapper : null;
  const successDetail = typeof options.successDetail === "function" ? options.successDetail : null;
  const successKind = typeof options.successKind === "function" ? options.successKind : null;
  setBusy(true);
  setStatus("warn", `${label} in progress`, "Please wait while the portal completes the request.");
  try {
    const result = await fn();
    const outputPayload = withBootstrapDirectoryFallbackHint(
      withSessionReconciledHint(outputMapper ? outputMapper(result) : result, result),
      result
    );
    print(label, outputPayload);
    const detail = appendBootstrapDirectoryFallbackDetail(
      appendSessionReconciledDetail(successDetail ? successDetail(result) : "The request finished successfully.", result),
      result
    );
    setStatus(successKind ? successKind(result) : "good", `${label} completed`, detail);
    return result;
  } catch (err) {
    print(`${label} (error)`, String(err && err.message ? err.message : err));
    setStatus("bad", `${label} failed`, String(err && err.message ? err.message : err));
    return undefined;
  } finally {
    setBusy(false);
  }
}

tabClientEl.addEventListener("click", () => {
  if (!tabClientEl.disabled) {
    activateWorkspaceTab("client");
  }
});

tabServerEl.addEventListener("click", () => {
  if (!tabServerEl.disabled) {
    activateWorkspaceTab("server");
  }
});

byId("challenge_btn").addEventListener("click", () =>
  run("auth_challenge", requestAuthChallenge)
);

byId("wallet_sign_btn").addEventListener("click", () =>
  run("wallet_sign", signChallengeWithWalletExtension, {
    successDetail: (result) =>
      `Challenge signed with ${walletProviderDisplayName(result?.wallet_provider)} extension for ${result?.wallet_address}.`
  })
);

byId("wallet_signin_btn").addEventListener("click", () =>
  run("wallet_signin", requestWalletSignIn, {
    successDetail: () => "Challenge signed via wallet extension and session verification completed."
  })
);

byId("signin_btn").addEventListener("click", () =>
  run("auth_verify", requestAuthVerify)
);

byId("session_btn").addEventListener("click", () =>
  run("session_status", async () => {
    const result = await requestSessionLifecycle("status");
    applySession(result);
    await refreshClientRegistrationStatus({ quiet: true });
    await refreshOperatorApplicationStatus({ quiet: true });
    await refreshServerReadinessStatus({ quiet: true });
    await refreshBootstrapTrustStatusBestEffort({ quiet: true });
    persistPortalState();
    return result;
  })
);

byId("session_rotate_btn").addEventListener("click", () =>
  run("session_rotate", async () => {
    const result = await requestSessionLifecycle("refresh");
    applySession(result);
    setOperatorApplicationStatus(undefined);
    setSelectedApplicationUpdatedAt("");
    await refreshClientRegistrationStatus({ quiet: true });
    await refreshOperatorApplicationStatus({ quiet: true });
    await refreshServerReadinessStatus({ quiet: true });
    await refreshBootstrapTrustStatusBestEffort({ quiet: true });
    persistPortalState();
    return result;
  })
);

byId("session_revoke_btn").addEventListener("click", () =>
  run("session_revoke", async () => {
    const result = await requestSessionLifecycle("revoke");
    clientRegistered = false;
    setClientRegistrationTrustDriftState(false, "");
    byId("session_token").value = "";
    byId("role").value = "client";
    setOperatorApplicationStatus(undefined);
    setSelectedApplicationUpdatedAt("");
    setServerReadiness(null);
    persistPortalState();
    await refreshBootstrapTrustStatusBestEffort({ quiet: true });
    return result;
  })
);

byId("manifest_btn").addEventListener("click", () =>
  run("bootstrap_manifest", requestBootstrapManifest)
);

byId("audit_recent_btn").addEventListener("click", () =>
  run("audit_recent", requestAuditRecent, {
    outputMapper: (result) => result.summary.output,
    successDetail: (result) => result.summary.detail
  })
);

byId("register_client_btn").addEventListener("click", () =>
  run("client_register", async () => {
    assertClientRegistrationActionAllowed();
    const request = {
      session_token: byId("session_token").value.trim(),
      path_profile: byId("path_profile").value
    };
    if (compatibilityOverrideEnabled()) {
      const bootstrap = bootstrapDirectoryEl.value.trim();
      const invite = inviteKeyEl.value.trim();
      if (bootstrap) {
        request.bootstrap_directory = bootstrap;
      }
      if (invite) {
        request.invite_key = invite;
      }
    }
    const result = await post("/v1/gpm/onboarding/client/register", request);
    applySession(result);
    await refreshClientRegistrationStatus({ quiet: true });
    await refreshServerReadinessStatus({ quiet: true });
    await refreshBootstrapTrustStatusBestEffort({ quiet: true });
    return result;
  })
);

byId("client_status_btn").addEventListener("click", () =>
  run(
    "client_status",
    async () => {
      const result = await requestClientStatus();
      applyClientRegistrationPayload(result);
      refreshClientReadiness();
      return result;
    },
    {
      successDetail: () => "Client onboarding status refreshed."
    }
  )
);

byId("overview_status_btn").addEventListener("click", () =>
  run(
    "onboarding_overview",
    async () => {
      const result = await requestOverview();
      applyOnboardingOverviewPayload(result);
      persistPortalState();
      return result;
    },
    {
      successDetail: () => "Onboarding overview refreshed for client and operator lanes."
    }
  )
);

byId("apply_operator_btn").addEventListener("click", () =>
  run("operator_apply", async () => {
    assertOperatorMutationActionAllowed("Operator apply");
    const request = {
      session_token: byId("session_token").value.trim(),
      chain_operator_id: byId("chain_operator_id").value.trim(),
      server_label: byId("server_label").value.trim() || undefined
    };
    const result = await post("/v1/gpm/onboarding/operator/apply", request);
    const parsedStatus = parseOperatorApplicationStatus(result);
    if (parsedStatus) {
      setOperatorApplicationStatus(parsedStatus);
    } else {
      await refreshOperatorApplicationStatus({ quiet: true });
    }
    await refreshServerReadinessStatus({ quiet: true });
    return result;
  })
);

byId("operator_status_btn").addEventListener("click", () =>
  run("operator_status", async () => {
    const result = await requestOperatorStatus();
    setOperatorApplicationStatus(parseOperatorApplicationStatus(result));
    applySelectedOperatorPrefill(extractOperatorPrefillValues(result), { mode: "merge" });
    await refreshServerReadinessStatus({ quiet: true });
    return result;
  })
);

byId("operator_list_pending_btn").addEventListener("click", () =>
  run(
    "operator_list_pending",
    async () => {
      const filters = readOperatorListFilters({
        fallbackStatus: "pending",
        fallbackLimit: OPERATOR_PENDING_LIST_LIMIT
      });
      return runOperatorListQuery({
        status: "pending",
        search: filters.search,
        limit: OPERATOR_PENDING_LIST_LIMIT
      });
    },
    {
      outputMapper: (result) => result.summary.output,
      successDetail: (result) => result.summary.detail
    }
  )
);

byId("operator_load_next_pending_btn").addEventListener("click", () =>
  run("operator_load_next_pending", loadNextPendingOperator, {
    successDetail: (result) =>
      result?.message || "No pending operator applications are currently queued."
  })
);

byId("operator_list_all_btn").addEventListener("click", () =>
  run(
    "operator_list_all",
    async () => {
      return runOperatorListQuery(readOperatorListFilters({ fallbackLimit: OPERATOR_LIST_ALL_LIMIT }));
    },
    {
      outputMapper: (result) => result.summary.output,
      successDetail: (result) => result.summary.detail
    }
  )
);

byId("operator_list_next_page_btn").addEventListener("click", () =>
  run(
    "operator_list_next_page",
    async () => {
      if (!operatorListNextCursor) {
        throw new Error("No next_cursor is available. Run an operator list query first.");
      }
      return runOperatorListQuery({
        ...operatorListActiveFilters,
        cursor: operatorListNextCursor
      });
    },
    {
      outputMapper: (result) => result.summary.output,
      successDetail: (result) => result.summary.detail
    }
  )
);

byId("approve_operator_btn").addEventListener("click", () =>
  run(
    "operator_approve",
    async () => {
      assertOperatorMutationActionAllowed("Operator approve");
      const moderationAuth = buildOperatorModerationAuthRequest("Operator approve");
      const request = {
        wallet_address: byId("wallet_address").value.trim(),
        approved: true
      };
      if (moderationAuth.session_token) {
        request.session_token = moderationAuth.session_token;
      }
      const ifUpdatedAtUtc = selectedApplicationUpdatedAt();
      if (ifUpdatedAtUtc) {
        request.if_updated_at_utc = ifUpdatedAtUtc;
      }
      if (moderationAuth.admin_token) {
        request.admin_token = moderationAuth.admin_token;
      }
      const reason = operatorModerationReason();
      if (reason) {
        request.reason = reason;
      }
      let moderationResult = null;
      try {
        moderationResult = await post("/v1/gpm/onboarding/operator/approve", request);
      } catch (err) {
        if (isDecisionConflictError(err)) {
          return {
            conflict: true,
            error: String(err && err.message ? err.message : err),
            guidance: OPERATOR_DECISION_CONFLICT_GUIDANCE
          };
        }
        throw err;
      }
      const sessionReconciliation = await reconcileSessionAfterModerationDecision();
      return {
        moderation_result: moderationResult,
        session_reconciliation: sessionReconciliation
      };
    },
    {
      successDetail: (result) => {
        if (result?.conflict) {
          return result.guidance || OPERATOR_DECISION_CONFLICT_GUIDANCE;
        }
        const reconciliation = result?.session_reconciliation;
        if (reconciliation?.attempted === false) {
          return "Operator approved. Session status refresh skipped because no session token was available.";
        }
        if (reconciliation?.ok === false) {
          return `Operator approved. Session status refresh failed (${reconciliation.error}).`;
        }
        return "Operator approved and session status refreshed.";
      },
      successKind: (result) => (result?.conflict ? "warn" : "good")
    }
  )
);

byId("reject_operator_btn").addEventListener("click", () =>
  run(
    "operator_reject",
    async () => {
      assertOperatorMutationActionAllowed("Operator reject");
      const moderationAuth = buildOperatorModerationAuthRequest("Operator reject");
      const reason = operatorModerationReason();
      if (!reason) {
        throw new Error("moderation reason is required to reject an operator.");
      }
      const request = {
        wallet_address: byId("wallet_address").value.trim(),
        approved: false,
        reason
      };
      if (moderationAuth.session_token) {
        request.session_token = moderationAuth.session_token;
      }
      if (moderationAuth.admin_token) {
        request.admin_token = moderationAuth.admin_token;
      }
      const ifUpdatedAtUtc = selectedApplicationUpdatedAt();
      if (ifUpdatedAtUtc) {
        request.if_updated_at_utc = ifUpdatedAtUtc;
      }
      let moderationResult = null;
      try {
        moderationResult = await post("/v1/gpm/onboarding/operator/approve", request);
      } catch (err) {
        if (isDecisionConflictError(err)) {
          return {
            conflict: true,
            error: String(err && err.message ? err.message : err),
            guidance: OPERATOR_DECISION_CONFLICT_GUIDANCE
          };
        }
        throw err;
      }
      const sessionReconciliation = await reconcileSessionAfterModerationDecision();
      return {
        moderation_result: moderationResult,
        session_reconciliation: sessionReconciliation
      };
    },
    {
      successDetail: (result) => {
        if (result?.conflict) {
          return result.guidance || OPERATOR_DECISION_CONFLICT_GUIDANCE;
        }
        const reconciliation = result?.session_reconciliation;
        if (reconciliation?.ok === false) {
          return `Operator rejected. Session status refresh failed (${reconciliation.error}).`;
        }
        return "Operator rejected and session status refreshed.";
      },
      successKind: (result) => (result?.conflict ? "warn" : "good")
    }
  )
);

byId("connect_btn").addEventListener("click", () =>
  run(
    "connect",
    async () => {
      const result = await requestConnectControl();
      updateConnectionDashboard("connect", result);
      return result;
    },
    {
      successDetail: () => "Connect request completed."
    }
  )
);

byId("disconnect_btn").addEventListener("click", () =>
  run(
    "disconnect",
    async () => {
      const result = await requestDisconnectControl();
      updateConnectionDashboard("disconnect", result);
      return result;
    },
    {
      successDetail: () => "Disconnect request completed."
    }
  )
);

byId("status_btn").addEventListener("click", () =>
  run(
    "status",
    async () => {
      const result = await requestConnectionStatus();
      updateConnectionDashboard("status", result);
      return result;
    },
    {
      successDetail: () => "Connection status refreshed."
    }
  )
);

serverStartBtnEl.addEventListener("click", () =>
  run(
    "service_start",
    async () => {
      const result = await requestServiceLifecycle("start");
      await refreshServerReadinessStatus({ quiet: true });
      return result;
    },
    {
      successDetail: () => "Server start request completed."
    }
  )
);

serverStopBtnEl.addEventListener("click", () =>
  run(
    "service_stop",
    async () => {
      const result = await requestServiceLifecycle("stop");
      await refreshServerReadinessStatus({ quiet: true });
      return result;
    },
    {
      successDetail: () => "Server stop request completed."
    }
  )
);

serverRestartBtnEl.addEventListener("click", () =>
  run(
    "service_restart",
    async () => {
      const result = await requestServiceLifecycle("restart");
      await refreshServerReadinessStatus({ quiet: true });
      return result;
    },
    {
      successDetail: () => "Server restart request completed."
    }
  )
);

byId("status_btn_server").addEventListener("click", () =>
  run(
    "status_server",
    async () => {
      const result = await requestConnectionStatus();
      updateConnectionDashboard("status", result);
      return result;
    },
    {
      successDetail: () => "Connection status refreshed."
    }
  )
);

async function restoreSessionStatusBestEffort() {
  const token = byId("session_token").value.trim();
  if (!token) {
    setServerReadiness(null);
    setOperatorApplicationStatus(undefined);
    setSelectedApplicationUpdatedAt("");
    await refreshBootstrapTrustStatusBestEffort({ quiet: true });
    return;
  }
  setStatus("warn", "Restoring session", "Checking stored session token status.");
  try {
    const result = await requestSessionLifecycle("status");
    applySession(result);
    persistPortalState();
    print("session_status (auto)", result);
    setStatus("good", "Session restored", "Stored session token is active.");
  } catch (err) {
    print("session_status (auto, non-fatal)", String(err && err.message ? err.message : err));
    setStatus("warn", "Session check skipped", "Stored session token could not be validated. You can refresh or sign in again.");
  }
  await refreshClientRegistrationStatus({ quiet: true });
  await refreshOperatorApplicationStatus({ quiet: true });
  await refreshServerReadinessStatus({ quiet: true });
  await refreshBootstrapTrustStatusBestEffort({ quiet: true });
}

function initializePortal() {
  restorePortalState();
  restoreWorkspaceTabPreference();
  refreshCompatibilityOverrideControls();
  applyConnectionSnapshot({
    stateKey: "unknown",
    state: CONNECTION_DEFAULT_STATE,
    detail: CONNECTION_DEFAULT_DETAIL
  });
  activateWorkspaceTab(activeWorkspaceTab);
  setSelectedApplicationUpdatedAt(selectedApplicationUpdatedAtEl.value, { persist: false });
  operatorListActiveFilters = readOperatorListFilters({ fallbackLimit: OPERATOR_LIST_ALL_LIMIT });
  writeOperatorListFilters(operatorListActiveFilters);
  setOperatorListNextCursor("");
  bindPersistenceListeners();
  bindCompatibilityOverrideListeners();
  bindReadinessListeners();
  bindOperatorListFilterListeners();
  persistPortalState();
  syncWalletExtensionReadinessHint();
  refreshOperatorReadiness();
  refreshPolicyPostureBanner();
  refreshLegacyAliasWarningBanner();
  setStatus("good", "Portal ready", "Set an absolute API base, then start with a challenge or session refresh.");
  void refreshConnectPolicyConfigBestEffort({ quiet: true });
  void refreshBootstrapTrustStatusBestEffort({ quiet: true });
  void restoreSessionStatusBestEffort();
}

initializePortal();
