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
const sessionFreshnessBannerEl = byId("session_freshness_banner");
const sessionFreshnessLineEl = byId("session_freshness_line");
const sessionFreshnessTitleEl = byId("session_freshness_title");
const sessionFreshnessDetailEl = byId("session_freshness_detail");
const policyPostureEl = byId("policy_posture");
const policyPostureLineEl = byId("policy_posture_line");
const policyConnectPolicyEl = byId("policy_connect_policy");
const policyAuthVerifyEl = byId("policy_auth_verify");
const configEndpointHintEl = byId("config_endpoint_hint");
const legacyAliasWarningEl = byId("legacy_alias_warning");
const legacyAliasWarningLineEl = byId("legacy_alias_warning_line");
const legacyAliasWarningTitleEl = byId("legacy_alias_warning_title");
const legacyAliasWarningDetailEl = byId("legacy_alias_warning_detail");
const localApiAuthTokenEl = byId("local_api_auth_token");
const clientReadinessEl = byId("client_readiness");
const clientReadinessLineEl = byId("client_readiness_line");
const clientReadinessStatusEl = byId("client_readiness_status");
const clientReadinessGuidanceEl = byId("client_readiness_guidance");
const serverReadinessEl = byId("server_readiness");
const serverReadinessLineEl = byId("server_readiness_line");
const serverApplicationStatusEl = byId("server_application_status");
const serverApplicationGuidanceEl = byId("server_application_guidance");
const bootstrapTrustStatusEl = byId("bootstrap_trust_status");
const bootstrapTrustStatusLineEl = byId("bootstrap_trust_status_line");
const bootstrapTrustStateEl = byId("bootstrap_trust_state");
const bootstrapTrustGuidanceEl = byId("bootstrap_trust_guidance");
const bootstrapTrustSummaryEl = byId("bootstrap_trust_summary");
const contributionStatusEl = byId("contribution_status");
const contributionStatusLineEl = byId("contribution_status_line");
const contributionStateEl = byId("contribution_state");
const contributionDetailEl = byId("contribution_detail");
const contributionEligibilitySummaryEl = byId("contribution_eligibility_summary");
const contributionRoleEl = byId("contribution_role");
const contributionStatusBtnEl = byId("contribution_status_btn");
const contributionEnableBtnEl = byId("contribution_enable_btn");
const contributionDisableBtnEl = byId("contribution_disable_btn");
const rewardCurrentWeekBtnEl = byId("reward_current_week_btn");
const rewardHistoryBtnEl = byId("reward_history_btn");
const contributionRewardWeekEl = byId("contribution_reward_week");
const contributionRewardUnitsEl = byId("contribution_reward_units");
const contributionRewardStatusEl = byId("contribution_reward_status");
const contributionRewardSettlementEl = byId("contribution_reward_settlement");
const contributionRewardMeteringEl = byId("contribution_reward_metering");
const contributionHistorySummaryEl = byId("contribution_history_summary");
const contributionHistoryListEl = byId("contribution_history_list");
const walletChainIdEl = byId("wallet_chain_id");
const challengeMessageEl = byId("challenge_message");
const compatOverrideSectionEl = document.getElementById("compat_override_section");
const compatOverrideEl = byId("compat_override");
const compatOverrideHintEl = byId("compat_override_hint");
const bootstrapDirectoryEl = byId("bootstrap_directory");
const sessionBootstrapDirectoryEl = byId("session_bootstrap_directory");
const inviteKeyEl = byId("invite_key");
const registerClientBtnEl = byId("register_client_btn");
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
const panelClientEl = byId("panel_client");
const clientLockHintEl = byId("client_lock_hint");
const tabLockHintEl = document.getElementById("tab_lock_hint");
const workspaceFirstRunHintEl = document.getElementById("workspace_first_run_hint");
const workspacePlatformHintEl = document.getElementById("workspace_platform_hint");
const workspaceNextActionHintEl = document.getElementById("workspace_next_action_hint");
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
const onboardingStepServerEl = document.getElementById("onboarding_step_server");
const actionButtons = Array.from(document.querySelectorAll(".actions button"));
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
const PUBLIC_CONTRIBUTION_ROLES = new Set(["micro-relay", "micro-exit"]);
const WALLET_EXTENSION_PROVIDERS = new Set(["keplr", "leap"]);
const DEFAULT_GPM_WALLET_CHAIN_ID = "gpm-mainnet-1";
const CONNECT_POLICY_MODE_SESSION_REQUIRED = "session_required";
const CONNECT_POLICY_MODE_COMPAT_ALLOWED = "compat_allowed";
const CONNECT_POLICY_SOURCE_RUNTIME_CONFIG = "runtime_config";
const CONNECT_POLICY_SOURCE_ENV_DEFAULT = "env_default";
const CONNECT_POLICY_SOURCE_LEGACY_DERIVED = "legacy_payload";
const CONNECT_POLICY_SOURCE_CONFIG_UNAVAILABLE = "config_unavailable";
const LEGACY_ALIAS_ENV_NAME_REGEX = /\bTDPN_[A-Z0-9_]+\b/gi;
const PORTAL_STORAGE_KEY = "gpm.portal.state.v1";
const SESSION_EXPIRING_SOON_MS = 10 * 60 * 1000;
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
const PRODUCTION_CONNECT_RESERVATION_AMOUNT_MICROS = 200000;
const PRODUCTION_CONNECT_RESERVATION_CURRENCY = "TDPNC";
const PRODUCTION_CONNECT_RESERVATION_MAX_ATTEMPTS = 6;
const PRODUCTION_CONNECT_RESERVATION_RETRY_DELAY_MS = 1500;
const PERSISTED_FIELD_IDS = [
  "api_base",
  "wallet_address",
  "wallet_provider",
  "wallet_chain_id",
  "path_profile",
  "contribution_role",
  "bootstrap_directory",
  "session_bootstrap_directory",
  "connect_interface",
  "connect_discovery_wait_sec",
  "connect_ready_timeout_sec"
];
let publicReadiness = null;
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
let legacyAliasTelemetry = {
  active: false,
  aliases: [],
  migrationHints: []
};
let walletSignatureContext = null;
let activeWorkspaceTab = "client";
let connectionState = CONNECTION_DEFAULT_STATE;
let connectionDetail = CONNECTION_DEFAULT_DETAIL;
let connectionRoutingMode = CONNECTION_DEFAULT_ROUTING_MODE;
let connectionRoutingDetail = CONNECTION_DEFAULT_ROUTING_DETAIL;
let bootstrapTrustTelemetry = null;
let publicContributionStatusPayload = null;
let publicContributionCurrentWeekPayload = null;
let publicContributionHistoryPayload = null;
let productionConnectReservationCache = null;
let sessionExpiryAtMs = undefined;
let sessionExpiryToken = "";

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
  activeWorkspaceTab = "client";
}

function persistWorkspaceTabPreference() {
  activeWorkspaceTab = "client";
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
  return "Restore the daemon config endpoint (/v1/config) first to re-enable Register Client and Connect actions.";
}

function failClosedMutatingActionStatusDetail() {
  return `Restricted fail-closed mode: /v1/config is unavailable. ${failClosedMutatingActionGuidance()} Read-only status/session actions remain available.`;
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
    ? " Manual Verify + Create Session is disabled in production mode; use Connect Wallet."
    : authVerifyRequireWalletExtensionSource
      ? " Manual Verify + Create Session is disabled; use Connect Wallet."
      : authVerifyRequireCryptoProof
        ? " Manual Verify + Create Session is available for compatibility, but cryptographic proof metadata is required by policy; use Connect Wallet when possible."
        : " Manual Verify + Create Session is available for compatibility.";
  policyAuthVerifyEl.textContent =
    `Auth verify strictness: metadata ${metadataRequired} (source: ${metadataSource}); ` +
    `wallet-extension-source ${walletRequired} (source: ${walletSource}); ` +
    `crypto-proof ${cryptoProofRequired} (source: ${cryptoProofSource}).${manualSignInGuidance}`;
  syncManualSignInAction();
  refreshConnectPolicyHint();
  refreshConfigEndpointHint();
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
    ? "Manual verify is disabled in production mode. Use Connect Wallet."
    : authPolicyLocked
      ? "Manual verify is disabled by active auth policy. Use Connect Wallet."
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

function connectProdProfileRequested() {
  return gpmProductionMode === true || connectProdProfileEl.checked === true;
}

function syncConnectRoutePolicy() {
  const prodRequested = connectProdProfileRequested();
  if (prodRequested) {
    connectInstallRouteEl.checked = true;
  }
  connectInstallRouteEl.disabled = prodRequested || gpmProductionMode === true;
  connectInstallRouteEl.setAttribute("aria-disabled", String(connectInstallRouteEl.disabled));
  connectInstallRouteEl.title = prodRequested
    ? "Production profile requires default-route installation so host traffic routes through GPM."
    : "Expert option: install the system default route through GPM.";
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
    legacyAliasTelemetry = parseLegacyAliasTelemetryConfig(config, {
      policySources: [
        connectPolicySource,
        authVerifyRequireMetadataPolicySource,
        authVerifyRequireWalletExtensionPolicySource,
        authVerifyRequireCryptoProofPolicySource
      ]
    });
    refreshCompatibilityOverrideControls();
    syncConnectRoutePolicy();
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

function isTrustedRemoteApiHost(hostname) {
  const normalized = String(hostname || "").trim().toLowerCase();
  return (
    normalized === "globalprivatemesh.net" ||
    normalized.endsWith(".globalprivatemesh.net")
  );
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
  const freshness = computeSessionFreshnessState();
  const hasSessionToken = freshness.state !== "signed_out" && freshness.state !== "expired";
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

function normalizePublicContributionRole(value) {
  const normalized = nonEmptyString(value)?.toLowerCase();
  if (normalized && PUBLIC_CONTRIBUTION_ROLES.has(normalized)) {
    return normalized;
  }
  return undefined;
}

function publicContributionRoleLabel(value) {
  const normalized = normalizePublicContributionRole(value);
  if (normalized === "micro-exit") {
    return "Micro exit";
  }
  if (normalized === "micro-relay") {
    return "Micro relay";
  }
  return "Contribution";
}

function publicContributionSelectedRole() {
  return normalizePublicContributionRole(contributionRoleEl.value) || "micro-relay";
}

function publicContributionObjectField(payload, candidates) {
  if (!payload || typeof payload !== "object") {
    return undefined;
  }
  for (const key of candidates) {
    const value = payload[key];
    if (value && typeof value === "object" && !Array.isArray(value)) {
      return value;
    }
  }
  return undefined;
}

function publicContributionArrayField(payload, candidates) {
  if (!payload || typeof payload !== "object") {
    return [];
  }
  for (const key of candidates) {
    const value = payload[key];
    if (Array.isArray(value)) {
      return value;
    }
  }
  return [];
}

function publicContributionValue(payload, candidates) {
  if (!payload || typeof payload !== "object") {
    return undefined;
  }
  return firstDefined(...candidates.map((key) => payload[key]));
}

function publicContributionNumber(payload, candidates) {
  const value = publicContributionValue(payload, candidates);
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function publicContributionBoolean(payload, candidates) {
  return parseBooleanLike(publicContributionValue(payload, candidates));
}

function publicContributionProfile(payload) {
  return publicContributionObjectField(payload, ["contribution_profile", "contributionProfile", "profile"]) || {};
}

function publicContributionReward(payload) {
  return (
    publicContributionObjectField(payload, ["reward", "current_week_reward", "currentWeekReward", "summary"]) ||
    {}
  );
}

function publicContributionHistoryRewards(payload) {
  return publicContributionArrayField(payload, ["rewards", "reward_history", "rewardHistory", "history"]);
}

function formatPublicContributionNumber(value, digits = 2) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return "0";
  }
  const fixed = parsed.toFixed(digits);
  return fixed.replace(/\.?0+$/, "");
}

function formatPublicContributionBytes(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  let amount = parsed;
  let unitIndex = 0;
  while (amount >= 1024 && unitIndex < units.length - 1) {
    amount /= 1024;
    unitIndex += 1;
  }
  return `${formatPublicContributionNumber(amount, amount >= 10 ? 1 : 2)} ${units[unitIndex]}`;
}

function formatPublicContributionSeconds(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return "0s";
  }
  return formatDurationCompact(parsed * 1000);
}

function formatPublicContributionTimestamp(value) {
  const raw = nonEmptyString(value);
  if (!raw) {
    return "";
  }
  const parsed = parseTimestampMs(raw);
  if (!parsed) {
    return raw;
  }
  return new Date(parsed).toISOString();
}

function formatPublicContributionWeekRange(reward) {
  const start = formatPublicContributionTimestamp(
    publicContributionValue(reward, ["week_start_utc", "weekStartUtc", "week_start", "weekStart"])
  );
  const end = formatPublicContributionTimestamp(
    publicContributionValue(reward, ["week_end_utc", "weekEndUtc", "week_end", "weekEnd"])
  );
  if (start && end) {
    return `${start} to ${end}`;
  }
  return start || "Not loaded";
}

function formatPublicContributionSettlement(reward, payload = {}) {
  const payoutAllowed = publicContributionBoolean(reward, ["payout_allowed", "payoutAllowed"]);
  const payloadPayoutAllowed = publicContributionBoolean(payload, ["payout_allowed", "payoutAllowed"]);
  const settlementState =
    nonEmptyString(
      publicContributionValue(reward, ["settlement_finalization_state", "settlementFinalizationState"])
    ) ||
    nonEmptyString(
      publicContributionValue(payload, ["settlement_finalization_state", "settlementFinalizationState"])
    ) ||
    "pending";
  const allowed = payoutAllowed !== undefined ? payoutAllowed : payloadPayoutAllowed;
  const payoutLabel = allowed === true ? "payout allowed" : "payout locked";
  return `${settlementState.replace(/_/g, " ")} (${payoutLabel})`;
}

function formatPublicContributionRewardMetering(reward) {
  const meteredSeconds = publicContributionNumber(reward, ["metered_seconds", "meteredSeconds"]);
  const validBytes = publicContributionNumber(reward, ["valid_bytes", "validBytes"]);
  const trafficProof =
    nonEmptyString(publicContributionValue(reward, ["traffic_proof_status", "trafficProofStatus"])) ||
    "unknown proof";
  return `${formatPublicContributionSeconds(meteredSeconds)} metered, ${formatPublicContributionBytes(validBytes)} valid, ${trafficProof.replace(/_/g, " ")}`;
}

function selectedContributionRoleEligibility(payload, selectedRole) {
  if (!payload || typeof payload !== "object") {
    return undefined;
  }
  if (selectedRole === "micro-exit") {
    return publicContributionBoolean(payload, ["can_enable_micro_exit", "canEnableMicroExit"]);
  }
  return publicContributionBoolean(payload, ["can_enable_micro_relay", "canEnableMicroRelay"]);
}

function publicContributionLockReason(payload, selectedRole) {
  const selectedRoleLabel = publicContributionRoleLabel(selectedRole).toLowerCase();
  const reason =
    nonEmptyString(publicContributionValue(payload, ["contribution_lock_reason", "contributionLockReason"])) ||
    nonEmptyString(publicContributionProfile(payload).lock_reason) ||
    "";
  return reason || `${selectedRoleLabel} is not eligible for this session.`;
}

function publicContributionSummaryText(payload, selectedRole) {
  if (!payload || typeof payload !== "object") {
    return "Run Contribution Status after sign-in to load tier, eligibility, capacity, and weekly reward estimates.";
  }
  const profile = publicContributionProfile(payload);
  const tier = publicContributionNumber(payload, ["client_tier", "clientTier"]);
  const stake = publicContributionBoolean(payload, ["stake_satisfied", "stakeSatisfied"]);
  const prepaid = publicContributionBoolean(payload, ["prepaid_balance_satisfied", "prepaidBalanceSatisfied"]);
  const canUse = publicContributionBoolean(payload, ["can_use_micro_relays", "canUseMicroRelays"]);
  const canEnable = selectedContributionRoleEligibility(payload, selectedRole);
  const maxSessions = publicContributionNumber(profile, ["max_forwarded_sessions", "maxForwardedSessions"]);
  const maxMbps = publicContributionNumber(profile, ["max_bandwidth_mbps", "maxBandwidthMbps"]);
  const capacityScore = publicContributionNumber(profile, ["capacity_score", "capacityScore"]);
  const healthScore = publicContributionNumber(profile, ["health_score", "healthScore"]);
  const gates = [
    `Tier ${tier !== undefined ? tier : "unknown"}`,
    `stake ${stake === true ? "ok" : "not satisfied"}`,
    `prepaid ${prepaid === true ? "ok" : "not satisfied"}`,
    `micro relay use ${canUse === true ? "allowed" : "locked"}`,
    `${publicContributionRoleLabel(selectedRole).toLowerCase()} opt-in ${canEnable === true ? "eligible" : "locked"}`
  ];
  if (maxSessions !== undefined || maxMbps !== undefined) {
    gates.push(
      `caps ${maxSessions !== undefined ? `${maxSessions} sessions` : "sessions unknown"} / ${
        maxMbps !== undefined ? `${maxMbps} Mbps` : "bandwidth unknown"
      }`
    );
  }
  if (capacityScore !== undefined || healthScore !== undefined) {
    gates.push(
      `scores capacity ${capacityScore !== undefined ? capacityScore : "unknown"} / health ${
        healthScore !== undefined ? healthScore : "unknown"
      }`
    );
  }
  return gates.join(" | ");
}

function setContributionStatus(kind, title, detail, summary) {
  contributionStatusEl.dataset.kind = kind || "warn";
  contributionStatusLineEl.classList.remove("good", "warn", "bad");
  if (kind) {
    contributionStatusLineEl.classList.add(kind);
  }
  contributionStateEl.textContent = title;
  contributionDetailEl.textContent = detail;
  contributionEligibilitySummaryEl.textContent = summary;
}

function renderPublicContributionStatus() {
  const selectedRole = publicContributionSelectedRole();
  const sessionFreshness = computeSessionFreshnessState();
  if (sessionFreshness.state === "signed_out") {
    setContributionStatus(
      "warn",
      "Signed out",
      "Sign in to check contribution eligibility for this device.",
      "Tier, stake, prepaid balance, and local capacity checks appear after status refresh."
    );
    syncContributionActionState();
    return;
  }
  if (sessionFreshness.state === "expired") {
    setContributionStatus(
      "bad",
      "Session expired",
      sessionFreshness.detail,
      "Refresh sign-in before checking or changing contribution state."
    );
    syncContributionActionState();
    return;
  }
  const payload = publicContributionStatusPayload;
  if (!payload || typeof payload !== "object") {
    setContributionStatus(
      "warn",
      "Status not loaded",
      "Run Contribution Status to load signed-in contribution eligibility.",
      "Contribution actions stay locked until status confirms eligibility for the selected role."
    );
    syncContributionActionState();
    return;
  }
  const profile = publicContributionProfile(payload);
  const enabled = publicContributionBoolean(profile, ["enabled"]) === true;
  const activeRole =
    normalizePublicContributionRole(publicContributionValue(profile, ["role", "requested_role", "requestedRole"])) ||
    selectedRole;
  const canEnable = selectedContributionRoleEligibility(payload, selectedRole) === true;
  const demotionState =
    nonEmptyString(publicContributionValue(profile, ["demotion_state", "demotionState"])) || "none";
  const reward = publicContributionReward(payload);
  const rewardUnits = publicContributionNumber(reward, ["reward_units", "rewardUnits"]);
  const summary = publicContributionSummaryText(payload, selectedRole);
  if (enabled) {
    setContributionStatus(
      "good",
      `${publicContributionRoleLabel(activeRole)} enabled`,
      `Contribution is active for this signed-in device. Current pending reward units: ${formatPublicContributionNumber(rewardUnits, 3)}.`,
      summary
    );
  } else if (canEnable) {
    setContributionStatus(
      "good",
      `${publicContributionRoleLabel(selectedRole)} eligible`,
      `Contribution is disabled. You can enable ${publicContributionRoleLabel(selectedRole).toLowerCase()} for this signed-in device.`,
      summary
    );
  } else {
    setContributionStatus(
      "bad",
      "Contribution locked",
      publicContributionLockReason(payload, selectedRole),
      demotionState && demotionState !== "none" ? `${summary} | demotion ${demotionState.replace(/_/g, " ")}` : summary
    );
  }
  syncContributionActionState();
}

function renderPublicCurrentWeekReward(payload = publicContributionCurrentWeekPayload) {
  const reward = publicContributionReward(payload);
  if (!reward || Object.keys(reward).length === 0) {
    contributionRewardWeekEl.textContent = "Not loaded";
    contributionRewardUnitsEl.textContent = "0";
    contributionRewardStatusEl.textContent = "Unknown";
    contributionRewardSettlementEl.textContent = "Pending refresh";
    contributionRewardMeteringEl.textContent = "Pending refresh";
    return;
  }
  contributionRewardWeekEl.textContent = formatPublicContributionWeekRange(reward);
  contributionRewardUnitsEl.textContent = formatPublicContributionNumber(
    publicContributionNumber(reward, ["reward_units", "rewardUnits"]),
    3
  );
  contributionRewardStatusEl.textContent =
    nonEmptyString(publicContributionValue(reward, ["status"]))?.replace(/_/g, " ") || "pending";
  contributionRewardSettlementEl.textContent = formatPublicContributionSettlement(reward, payload);
  contributionRewardMeteringEl.textContent = formatPublicContributionRewardMetering(reward);
}

function renderPublicRewardHistory(payload = publicContributionHistoryPayload) {
  const rewards = publicContributionHistoryRewards(payload);
  const countValue = publicContributionNumber(payload, ["count"]);
  const count = countValue !== undefined ? countValue : rewards.length;
  contributionHistorySummaryEl.textContent =
    count > 0 ? `${count} closed weekly reward${count === 1 ? "" : "s"}` : "No closed weekly rewards yet";
  contributionHistoryListEl.replaceChildren();
  if (rewards.length === 0) {
    const item = document.createElement("li");
    item.textContent = "Closed weekly rewards appear here after a week rolls over.";
    contributionHistoryListEl.append(item);
    return;
  }
  for (const reward of rewards.slice(0, 8)) {
    const item = document.createElement("li");
    const week = formatPublicContributionWeekRange(reward);
    const units = formatPublicContributionNumber(
      publicContributionNumber(reward, ["reward_units", "rewardUnits"]),
      3
    );
    const status =
      nonEmptyString(publicContributionValue(reward, ["status"]))?.replace(/_/g, " ") || "pending";
    const settlement = formatPublicContributionSettlement(reward, payload);
    item.textContent = `${week}: ${units} units, ${status}, ${settlement}`;
    contributionHistoryListEl.append(item);
  }
}

function clearPublicContributionState() {
  publicContributionStatusPayload = null;
  publicContributionCurrentWeekPayload = null;
  publicContributionHistoryPayload = null;
  renderPublicContributionStatus();
  renderPublicCurrentWeekReward();
  renderPublicRewardHistory();
  syncContributionActionState();
}

function applyPublicContributionStatusPayload(payload) {
  publicContributionStatusPayload = payload && typeof payload === "object" ? payload : null;
  if (publicContributionStatusPayload) {
    publicContributionCurrentWeekPayload = {
      ok: true,
      reward: publicContributionReward(publicContributionStatusPayload),
      contribution_profile: publicContributionProfile(publicContributionStatusPayload),
      payout_allowed: publicContributionValue(publicContributionStatusPayload, ["payout_allowed", "payoutAllowed"]),
      settlement_finalization_state: publicContributionValue(publicContributionReward(publicContributionStatusPayload), [
        "settlement_finalization_state",
        "settlementFinalizationState"
      ])
    };
  }
  renderPublicContributionStatus();
  renderPublicCurrentWeekReward();
}

function applyPublicCurrentWeekRewardPayload(payload) {
  publicContributionCurrentWeekPayload = payload && typeof payload === "object" ? payload : null;
  renderPublicCurrentWeekReward();
}

function applyPublicRewardHistoryPayload(payload) {
  publicContributionHistoryPayload = payload && typeof payload === "object" ? payload : null;
  renderPublicRewardHistory();
}

function computeContributionActionState() {
  const sessionToken = byId("session_token").value.trim();
  const sessionFreshness = computeSessionFreshnessState();
  const sessionReady = sessionToken.length > 0 && sessionFreshness.state !== "expired";
  const isBusy = document.body.classList.contains("is-busy");
  const statusLoaded = publicContributionStatusPayload && typeof publicContributionStatusPayload === "object";
  const selectedRole = publicContributionSelectedRole();
  const canEnable = statusLoaded && selectedContributionRoleEligibility(publicContributionStatusPayload, selectedRole) === true;
  const profile = statusLoaded ? publicContributionProfile(publicContributionStatusPayload) : {};
  const enabled = publicContributionBoolean(profile, ["enabled"]) === true;
  let baseHint = "";
  if (!sessionToken) {
    baseHint = "Sign in first to use public contribution and reward controls.";
  } else if (sessionFreshness.state === "expired") {
    baseHint = sessionFreshness.detail;
  } else if (!statusLoaded) {
    baseHint = "Run Contribution Status first to load signed-in eligibility.";
  }
  return {
    isBusy,
    sessionReady,
    statusLoaded,
    canEnable,
    enabled,
    baseHint,
    selectedRole
  };
}

function syncContributionActionState() {
  const state = computeContributionActionState();
  const readDisabled = state.isBusy || !state.sessionReady;
  const enableDisabled = state.isBusy || !state.sessionReady || !state.statusLoaded || state.enabled || !state.canEnable;
  const disableDisabled = state.isBusy || !state.sessionReady || !state.statusLoaded || !state.enabled;
  contributionStatusBtnEl.disabled = readDisabled;
  rewardCurrentWeekBtnEl.disabled = readDisabled;
  rewardHistoryBtnEl.disabled = readDisabled;
  contributionEnableBtnEl.disabled = enableDisabled;
  contributionDisableBtnEl.disabled = disableDisabled;
  contributionRoleEl.disabled = state.isBusy || !state.sessionReady;
  for (const [button, disabled, fallback] of [
    [contributionStatusBtnEl, readDisabled, "Sign in first to check contribution status."],
    [rewardCurrentWeekBtnEl, readDisabled, "Sign in first to load current-week rewards."],
    [rewardHistoryBtnEl, readDisabled, "Sign in first to load reward history."],
    [
      contributionEnableBtnEl,
      enableDisabled,
      state.enabled
        ? "Contribution is already enabled for this signed-in device."
        : state.canEnable
          ? `Enable ${publicContributionRoleLabel(state.selectedRole).toLowerCase()} contribution.`
          : publicContributionLockReason(publicContributionStatusPayload, state.selectedRole)
    ],
    [
      contributionDisableBtnEl,
      disableDisabled,
      state.enabled
        ? "Disable contribution for this signed-in device."
        : "Contribution is not currently enabled for this signed-in device."
    ]
  ]) {
    button.setAttribute("aria-disabled", String(disabled));
    button.title = disabled ? state.baseHint || fallback : fallback;
  }
  contributionRoleEl.setAttribute("aria-disabled", String(contributionRoleEl.disabled));
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

function sessionReauthGuidance() {
  return "Rotate Session if still valid, otherwise Connect Wallet or use advanced Verify + Create Session.";
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
    payload?.profile?.expires_at_utc,
    payload?.profile?.expiresAtUtc
  ];
  for (const candidate of candidates) {
    const parsed = parseTimestampMs(candidate);
    if (parsed !== undefined) {
      return parsed;
    }
  }
  return undefined;
}

function clearSessionFreshnessTelemetry() {
  sessionExpiryAtMs = undefined;
  sessionExpiryToken = "";
}

function refreshSessionFreshnessFromPayload(payload, options = {}) {
  const { clearWhenMissing = false, tokenOverride } = options;
  const token =
    nonEmptyString(
      firstDefined(
        tokenOverride,
        payload?.session_token,
        payload?.session?.session_token,
        payload?.token
      )
    ) || byId("session_token").value.trim();
  if (!token) {
    clearSessionFreshnessTelemetry();
    return;
  }
  sessionExpiryToken = token;
  const expiresAtMs = extractSessionExpiryMs(payload);
  if (expiresAtMs !== undefined) {
    sessionExpiryAtMs = expiresAtMs;
    return;
  }
  if (clearWhenMissing) {
    sessionExpiryAtMs = undefined;
  }
}

function markSessionFreshnessUnknownForCurrentToken() {
  const token = byId("session_token").value.trim();
  if (!token) {
    clearSessionFreshnessTelemetry();
    return;
  }
  sessionExpiryToken = token;
  sessionExpiryAtMs = undefined;
}

function computeSessionFreshnessState() {
  const token = byId("session_token").value.trim();
  if (!token) {
    return {
      state: "signed_out",
      kind: "warn",
      title: "Signed out",
      detail: "No active session token is loaded."
    };
  }
  if (sessionExpiryToken && sessionExpiryToken !== token) {
    return {
      state: "unknown",
      kind: "warn",
      title: "Session expiry unknown",
      detail: "Session token changed. Refresh Session to validate expiry and avoid stale auth."
    };
  }
  if (typeof sessionExpiryAtMs !== "number" || !Number.isFinite(sessionExpiryAtMs) || sessionExpiryAtMs <= 0) {
    return {
      state: "unknown",
      kind: "warn",
      title: "Session expiry unknown",
      detail: "Session token is loaded, but expires_at_utc is unavailable. Refresh Session to validate freshness."
    };
  }
  const deltaMs = sessionExpiryAtMs - Date.now();
  const expiresAtIso = new Date(sessionExpiryAtMs).toISOString();
  if (deltaMs <= 0) {
    return {
      state: "expired",
      kind: "bad",
      title: "Session expired",
      detail: `Session expired ${formatDurationCompact(deltaMs)} ago (${expiresAtIso}). ${sessionReauthGuidance()}`,
      expiresAtMs: sessionExpiryAtMs
    };
  }
  if (deltaMs <= SESSION_EXPIRING_SOON_MS) {
    return {
      state: "expiring_soon",
      kind: "warn",
      title: "Session expiring soon",
      detail: `Session expires in ${formatDurationCompact(deltaMs)} (${expiresAtIso}). Rotate Session now to avoid auth failures.`,
      expiresAtMs: sessionExpiryAtMs
    };
  }
  return {
    state: "active",
    kind: "good",
    title: "Session active",
    detail: `Session expires in ${formatDurationCompact(deltaMs)} (${expiresAtIso}).`,
    expiresAtMs: sessionExpiryAtMs
  };
}

function assertSessionFreshForAction(actionLabel, options = {}) {
  const { requireToken = false } = options;
  const token = byId("session_token").value.trim();
  if (!token) {
    if (requireToken) {
      throw new Error(`${actionLabel} is unavailable: session_token is required. Sign in first.`);
    }
    return;
  }
  const freshness = computeSessionFreshnessState();
  if (freshness.state === "expired") {
    throw new Error(`${actionLabel} is unavailable: ${freshness.detail}`);
  }
}

function optionalFreshSessionToken(actionLabel, options = {}) {
  const { allowWalletFallback = false, walletAddress = "" } = options;
  const token = byId("session_token").value.trim();
  if (!token) {
    return undefined;
  }
  const freshness = computeSessionFreshnessState();
  if (freshness.state !== "expired") {
    return token;
  }
  if (allowWalletFallback && nonEmptyString(walletAddress)) {
    return undefined;
  }
  throw new Error(`${actionLabel} is unavailable: ${freshness.detail}`);
}

function syncSessionFreshnessBanner() {
  const freshness = computeSessionFreshnessState();
  sessionFreshnessBannerEl.dataset.kind = freshness.kind || "warn";
  sessionFreshnessLineEl.classList.remove("good", "warn", "bad");
  if (freshness.kind) {
    sessionFreshnessLineEl.classList.add(freshness.kind);
  }
  sessionFreshnessTitleEl.textContent = freshness.title;
  sessionFreshnessDetailEl.textContent = freshness.detail;
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

function isServerOnlyRole(roleValue) {
  const role = String(roleValue || "").trim().toLowerCase();
  return SERVER_ONLY_ROLES.has(role);
}

function parsePublicReadiness(payload) {
  const readiness = payload?.readiness;
  if (!readiness || typeof readiness !== "object") {
    return null;
  }
  const role = nonEmptyString(readiness.role);
  const clientLockReason = nonEmptyString(firstDefined(readiness.client_lock_reason, readiness.clientLockReason));
  return {
    role: role ? role.toLowerCase() : undefined,
    clientTabVisible: parseBooleanLike(firstDefined(readiness.client_tab_visible, readiness.clientTabVisible)),
    clientLockReason: clientLockReason || undefined
  };
}

function parseServerApplicationStatus(payload) {
  const value =
    payload?.application?.status ||
    payload?.readiness?.operator_application_status ||
    payload?.readiness?.operatorApplicationStatus ||
    payload?.status;
  return typeof value === "string" && value.trim() ? value.trim().toLowerCase() : "";
}

function setServerApplicationStatus(status, guidance = "") {
  const normalized = typeof status === "string" ? status.trim().toLowerCase() : "";
  let kind = "warn";
  let label = "Not checked";
  let detail = guidance || "Connect wallet first, then apply if you want this device reviewed for server mode.";
  if (normalized === "approved") {
    kind = "good";
    label = "Approved";
    detail = guidance || "Server access is approved. This device can continue with server setup.";
  } else if (normalized === "pending") {
    label = "Pending approval";
    detail = guidance || "Your server application is waiting for GPM review.";
  } else if (normalized === "rejected") {
    kind = "bad";
    label = "Refused";
    detail = guidance || "The server application was refused. Update details before applying again.";
  } else if (normalized === "not_submitted") {
    label = "Not applied";
    detail = guidance || "Apply if you want this device reviewed for server mode.";
  }
  serverReadinessEl.dataset.kind = kind;
  serverReadinessEl.dataset.state = normalized || "unknown";
  serverReadinessLineEl.classList.remove("good", "warn", "bad");
  serverReadinessLineEl.classList.add(kind);
  serverApplicationStatusEl.textContent = label;
  serverApplicationGuidanceEl.textContent = detail;
  if (onboardingStepServerEl) {
    setStepState(onboardingStepServerEl, normalized === "approved" ? "done" : normalized === "pending" ? "active" : "idle");
  }
}

function setPublicReadiness(value) {
  publicReadiness = value || null;
  refreshClientReadiness();
}

function isClientTabVisibleRole(roleValue = byId("role").value) {
  if (publicReadiness && typeof publicReadiness.clientTabVisible === "boolean") {
    return publicReadiness.clientTabVisible;
  }
  const role = String(publicReadiness?.role || roleValue || "").trim().toLowerCase();
  if (isServerOnlyRole(role)) {
    return false;
  }
  return true;
}

function computeClientTabLockHintText() {
  const readiness = computeClientReadiness();
  return readiness.guidanceText;
}

function ensureSentence(value) {
  const normalized = typeof value === "string" ? value.trim() : "";
  if (!normalized) {
    return "";
  }
  return /[.!?]$/.test(normalized) ? normalized : `${normalized}.`;
}

function isWindowsRuntimePlatform() {
  const platform = String(
    firstDefined(navigator.userAgentData && navigator.userAgentData.platform, navigator.platform, navigator.userAgent) || ""
  ).toLowerCase();
  return platform.includes("win");
}

function formatWorkspaceTabAvailabilityHint(clientTabVisible) {
  if (!clientTabVisible) {
    return "Client workspace is disabled by role/readiness policy. Use the lock message activation path before retrying.";
  }
  return "Client workspace is available for this session.";
}

function syncWorkspaceNextActionHint(clientTabVisible = isClientTabVisibleRole()) {
  if (!workspaceNextActionHintEl) {
    return;
  }
  const nextAction = ensureSentence(computePortalNextRecommendedAction());
  const lockContext = !clientTabVisible ? ` ${formatWorkspaceTabAvailabilityHint(clientTabVisible)}` : "";
  workspaceNextActionHintEl.textContent = `Workspace next action: ${nextAction}${lockContext}`;
  workspaceNextActionHintEl.classList.toggle("locked", !clientTabVisible);
}

function syncWorkspaceFirstRunHints(clientTabVisible) {
  if (workspaceFirstRunHintEl) {
    workspaceFirstRunHintEl.textContent =
      `Client controls only. ${formatWorkspaceTabAvailabilityHint(clientTabVisible)}`;
    workspaceFirstRunHintEl.classList.toggle("locked", !clientTabVisible);
  }
  if (workspacePlatformHintEl) {
    workspacePlatformHintEl.textContent = isWindowsRuntimePlatform()
      ? "First run: connect wallet, register, connect."
      : "First run: connect wallet, register, connect.";
  }
  syncWorkspaceNextActionHint(clientTabVisible);
}

function inferWorkspaceTabActivationPathHint(tabName, reason) {
  const normalizedReason = typeof reason === "string" ? reason : "";
  const directPathMatch = normalizedReason.match(/Direct path:\s*([^.;]+)\s*[.;]?/i);
  if (directPathMatch && directPathMatch[1]) {
    return directPathMatch[1].trim();
  }
  const hasSessionToken = byId("session_token").value.trim().length > 0;
  if (tabName === "client") {
    if (!hasSessionToken) {
      return "Connect Wallet, then Register Device";
    }
    return "Register Client to unlock client lane actions";
  }
  return "Open the client workspace";
}

function formatWorkspaceLockedTabMessage(tabName, reason) {
  const normalizedReason = ensureSentence(reason) || `${tabName} tab is currently locked by role policy.`;
  const activationPath = ensureSentence(inferWorkspaceTabActivationPathHint(tabName.toLowerCase(), normalizedReason));
  return `${tabName} is locked. ${normalizedReason} Next: ${activationPath}`;
}

function syncWorkspaceTabLockHint(clientTabVisible, clientReason) {
  if (!tabLockHintEl) {
    return;
  }
  const lockMessages = [];
  if (!clientTabVisible && clientReason) {
    lockMessages.push(formatWorkspaceLockedTabMessage("Client", clientReason));
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

function activateWorkspaceTab() {
  tabClientEl.classList.add("active");
  tabClientEl.setAttribute("aria-selected", "true");
  panelClientEl.classList.add("active");
  activeWorkspaceTab = "client";
  persistWorkspaceTabPreference();
}

function syncWorkspaceTabLockState() {
  const clientTabVisible = isClientTabVisibleRole();
  const clientReason = computeClientTabLockHintText();
  const clientLockedMessage = formatWorkspaceLockedTabMessage("Client", clientReason);

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

  activateWorkspaceTab();

  clientLockHintEl.textContent = clientReason;
  clientLockHintEl.classList.toggle("locked", !clientTabVisible);
  syncWorkspaceTabLockHint(clientTabVisible, clientReason);
  syncWorkspaceFirstRunHints(clientTabVisible);
}

function setStepState(el, state) {
  if (!el) {
    return;
  }
  el.dataset.state = state;
}

function refreshOnboardingSteps() {
  const clientReadiness = computeClientReadiness();
  const hasSession = clientReadiness.state !== "not_signed_in" && clientReadiness.state !== "session_expired";

  if (!hasSession) {
    setStepState(onboardingStepSigninEl, "active");
    setStepState(onboardingStepClientEl, "blocked");
    setStepState(onboardingStepServerEl, "blocked");
    return;
  }

  setStepState(onboardingStepSigninEl, "done");
  setStepState(onboardingStepServerEl, "idle");
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
}

function computePortalNextRecommendedAction() {
  const sessionToken = byId("session_token").value.trim();
  if (!sessionToken) {
    const challengeId = byId("challenge_id").value.trim();
    const signature = byId("signature").value.trim();
    if (!challengeId) {
      return "Connect Wallet.";
    }
    if (!signature) {
      return "Use Connect Wallet, or use advanced Sign Challenge.";
    }
      return "Use Connect Wallet.";
  }
  const sessionFreshness = computeSessionFreshnessState();
  if (sessionFreshness.state === "expired") {
    return "Re-authenticate with Connect Wallet or advanced Verify + Create Session.";
  }
  if (sessionFreshness.state === "expiring_soon") {
    return "Rotate Session.";
  }

  const clientReadiness = computeClientReadiness();
  if (
    clientReadiness.state === "ready_to_register" ||
    clientReadiness.state === "re_registration_required"
  ) {
    return "Register Device.";
  }

  if (!publicContributionStatusPayload) {
    return "Run Contribution Status or Status.";
  }
  return "Use Connect, Disconnect, or Status from the client workspace.";
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
  const sessionFreshness = computeSessionFreshnessState();
  if (sessionFreshness.state === "expired") {
    return {
      kind: "bad",
      title: "Session expired",
      detail: sessionFreshness.detail
    };
  }
  if (sessionFreshness.state === "expiring_soon") {
    return {
      kind: "warn",
      title: "Session expiring soon",
      detail: sessionFreshness.detail
    };
  }
  if (sessionFreshness.state === "unknown") {
    return {
      kind: "warn",
      title: "Session expiry unknown",
      detail: sessionFreshness.detail
    };
  }

  return {
    kind: "good",
    title: "Session active",
    detail: "Session token is active. Continue with client registration, contribution status, or client connection controls."
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
  syncWorkspaceNextActionHint(isClientTabVisibleRole());
  syncSessionFreshnessBanner();
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
  refreshSessionFreshnessFromPayload(payload);
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
  const sessionFreshness = computeSessionFreshnessState();
  const sessionToken = byId("session_token").value.trim();
  const lockBySessionExpired = sessionToken.length > 0 && sessionFreshness.state === "expired";
  const disabled = isBusy || lockByFailClosed || lockBySessionExpired;
  connectBtnEl.disabled = disabled;
  connectBtnEl.setAttribute("aria-disabled", String(disabled));
  if (lockByFailClosed) {
    connectBtnEl.title = failClosedMutatingActionStatusDetail();
    return;
  }
  if (lockBySessionExpired) {
    connectBtnEl.title = sessionFreshness.detail;
    return;
  }
  connectBtnEl.removeAttribute("title");
}

function syncClientRegistrationAction(readiness) {
  if (!registerClientBtnEl) {
    return;
  }
  const isBusy = document.body.classList.contains("is-busy");
  const lockByFailClosed = configEndpointUnavailableFailClosedMode();
  const lockByState =
    readiness.state === "role_locked" ||
    readiness.state === "not_signed_in" ||
    readiness.state === "session_expired";
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
  if (
    readiness.state === "not_signed_in" ||
    readiness.state === "role_locked" ||
    readiness.state === "session_expired"
  ) {
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
  const sessionFreshness = computeSessionFreshnessState();
  const role = (publicReadiness?.role || byId("role").value).trim().toLowerCase() || "client";
  const clientTabVisible = publicReadiness?.clientTabVisible;
  const clientLockReason = publicReadiness?.clientLockReason;

  if (sessionFreshness.state === "expired") {
    return {
      state: "session_expired",
      kind: "bad",
      statusText: "Session expired",
      guidanceText: sessionFreshness.detail
    };
  }

  if (!token) {
    return {
      state: "not_signed_in",
      kind: "warn",
      statusText: "Not signed in",
      guidanceText: "Sign in first to unlock client registration."
    };
  }

  if (isServerOnlyRole(role) || clientTabVisible === false) {
    return {
      state: "role_locked",
      kind: "bad",
      statusText: "Role-locked",
      guidanceText:
        clientLockReason ||
        (isServerOnlyRole(role)
          ? "This session is server-only, so the client lane is locked."
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

  return {
    state: "ready_to_register",
    kind: "warn",
    statusText: "Ready to register",
    guidanceText: "Use Register Client to finish Step 2 and unlock client lane actions."
  };
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

function bindReadinessListeners() {
  byId("session_token").addEventListener("input", () => {
    markSessionFreshnessUnknownForCurrentToken();
    setPublicReadiness(null);
    clientRegistered = false;
    setClientRegistrationTrustDriftState(false, "");
    clearPublicContributionState();
    refreshSessionBootstrapDirectoryControls();
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
  contributionRoleEl.addEventListener("change", () => {
    renderPublicContributionStatus();
    syncContributionActionState();
    persistPortalState();
  });
  connectProdProfileEl.addEventListener("change", () => {
    syncConnectRoutePolicy();
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

function setBusy(isBusy) {
  document.body.classList.toggle("is-busy", isBusy);
  for (const button of actionButtons) {
    button.disabled = isBusy;
    button.setAttribute("aria-disabled", String(isBusy));
  }
  syncManualSignInAction();
  syncContributionActionState();
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
  if (
    isLiteralLoopbackHost(parsed.hostname) ||
    (parsed.protocol === "https:" && isTrustedRemoteApiHost(parsed.hostname))
  ) {
    // Allowed.
  } else if (parsed.protocol === "https:") {
    throw new Error("Remote API base URLs are restricted to trusted GPM domains.");
  } else {
    throw new Error("Non-loopback API base URLs must use https.");
  }
  const pathname = parsed.pathname.replace(/\/+$/, "");
  return pathname && pathname !== "/" ? `${parsed.origin}${pathname}` : parsed.origin;
}

function localApiAuthToken() {
  return localApiAuthTokenEl.value.trim();
}

function apiBaseURL() {
  return new URL(apiBase());
}

function apiBaseAllowsBearerToken() {
  return isLiteralLoopbackHost(apiBaseURL().hostname);
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
  err.payload = json;
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
    if (!apiBaseAllowsBearerToken()) {
      throw new Error("Local API bearer token can only be sent to loopback API bases.");
    }
    headers.Authorization = `Bearer ${token}`;
  }
  const response = await fetch(`${apiBaseURL().toString().replace(/\/+$/, "")}${path}`, {
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
    if (!apiBaseAllowsBearerToken()) {
      throw new Error("Local API bearer token can only be sent to loopback API bases.");
    }
    headers.Authorization = `Bearer ${token}`;
  }
  const response = await fetch(`${apiBaseURL().toString().replace(/\/+$/, "")}${path}`, {
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
  const role = result.session?.role || result.role || result.profile?.role;
  if (typeof role === "string" && role.trim()) {
    byId("role").value = role.trim();
  } else if (!byId("role").value.trim()) {
    byId("role").value = "client";
  }
  refreshSessionFreshnessFromPayload(result, { tokenOverride: token, clearWhenMissing: true });
  refreshSessionBootstrapDirectoryOptions(result);
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
  const chainId = walletChainIdEl.value.trim() || DEFAULT_GPM_WALLET_CHAIN_ID;
  const extensionDetected = walletExtensionDetected(walletProvider);
  const walletPolicyLocked = gpmProductionMode || strictWalletExtensionSourceRequired();
  const requirementSummary = walletPolicyLocked
    ? "Connect Wallet is required by active policy."
    : "Connect Wallet is available and recommended.";
  const extensionSummary = extensionDetected
    ? `${providerLabel} extension detected in this browser.`
    : `${providerLabel} extension not detected in this browser. Install/enable it and reload before signing.`;
  const chainSummary = `Network: ${chainId}. GPM fills this automatically.`;
  walletExtensionHintEl.textContent = `${requirementSummary} ${extensionSummary} ${chainSummary}`;
  walletExtensionHintEl.classList.toggle("locked", walletPolicyLocked || !extensionDetected);
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

function challengeChainIdFromPayload(payload) {
  return (
    nonEmptyString(
      firstDefined(
        payload?.chain_id,
        payload?.chainId,
        payload?.challenge?.chain_id,
        payload?.challenge?.chainId
      )
    ) || ""
  );
}

function applyChallengePayload(payload) {
  const challengeId = challengeIdFromPayload(payload);
  if (challengeId) {
    byId("challenge_id").value = challengeId;
  }
  const challengeChainId = challengeChainIdFromPayload(payload);
  if (challengeChainId) {
    walletChainIdEl.value = challengeChainId;
    persistPortalState({ wallet_chain_id: challengeChainId });
  }
  challengeMessageEl.value = challengeMessageFromPayload(payload);
  syncPortalOnboardingStateBanner();
}

function readWalletPayload() {
  return {
    wallet_address: byId("wallet_address").value.trim(),
    wallet_provider: byId("wallet_provider").value,
    chain_id: walletChainIdEl.value.trim()
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
  const chainId = walletChainIdEl.value.trim() || DEFAULT_GPM_WALLET_CHAIN_ID;
  walletChainIdEl.value = chainId;
  if (!challengeId) {
    throw new Error("challenge_id is required. Request challenge first.");
  }
  if (!challengeMessage) {
    throw new Error("challenge_message is required. Request challenge first.");
  }
  const { wallet_provider: walletProvider } = readWalletPayload();
  const { extension, provider } = resolveWalletExtensionClient(walletProvider);
  await extension.enable(chainId);

  let walletAddress = byId("wallet_address").value.trim();
  if (!walletAddress) {
    walletAddress = await resolveWalletAddressFromExtension(extension, chainId);
    if (!walletAddress) {
      throw new Error(
        `Unable to resolve wallet address from ${walletProviderDisplayName(provider)} extension. Open Advanced troubleshooting only if support asks you to enter it manually.`
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
    throw new Error("Manual verify is disabled in production mode. Use Connect Wallet.");
  }
  if (manualSource && strictWalletExtensionSourceRequired()) {
    const policySource = formatPolicySourceLabel(authVerifyRequireWalletExtensionPolicySource);
    throw new Error(
      `Manual verify is disabled by active auth policy (wallet-extension-source required; source: ${policySource}). Use Connect Wallet.`
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
  setPublicReadiness(null);
  applySession(result);
  await refreshClientRegistrationStatus({ quiet: true });
  await refreshBootstrapTrustStatusBestEffort({ quiet: true });
  await refreshPublicContributionBestEffort({ quiet: true });
  return result;
}

async function requestWalletSignIn() {
  if (!walletChainIdEl.value.trim()) {
    walletChainIdEl.value = DEFAULT_GPM_WALLET_CHAIN_ID;
  }
  if (!byId("wallet_address").value.trim()) {
    const { wallet_provider: walletProvider } = readWalletPayload();
    const { extension } = resolveWalletExtensionClient(walletProvider);
    const chainId = walletChainIdEl.value.trim();
    await extension.enable(chainId);
    const walletAddress = await resolveWalletAddressFromExtension(extension, chainId);
    if (walletAddress) {
      byId("wallet_address").value = walletAddress;
      persistPortalState();
    }
  }
  if (!byId("challenge_id").value.trim() || !challengeMessageEl.value.trim()) {
    await requestAuthChallenge();
  }
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

async function requestClientStatus() {
  const walletAddress = byId("wallet_address").value.trim();
  const sessionToken = optionalFreshSessionToken("Client status", {
    allowWalletFallback: true,
    walletAddress
  });
  const request = {
    session_token: sessionToken,
    wallet_address: walletAddress || undefined
  };
  return post("/v1/gpm/onboarding/client/status", request);
}

function publicServerSessionRequest(actionLabel) {
  assertSessionFreshForAction(actionLabel, { requireToken: true });
  const sessionToken = byId("session_token").value.trim();
  const walletAddress = byId("wallet_address").value.trim();
  return {
    session_token: sessionToken,
    wallet_address: walletAddress || undefined
  };
}

async function requestServerStatus() {
  return post("/v1/gpm/onboarding/server/status", publicServerSessionRequest("Server status"));
}

async function requestServerApply() {
  const request = publicServerSessionRequest("Apply to run server");
  const walletAddress = byId("wallet_address").value.trim();
  if (!walletAddress) {
    throw new Error("Connect wallet first so GPM can identify this server application.");
  }
  request.chain_operator_id = walletAddress;
  request.server_label = `gpm-server-${walletAddress.slice(-8) || "device"}`;
  return post("/v1/gpm/onboarding/operator/apply", request);
}

function publicContributionSessionRequest(actionLabel) {
  assertSessionFreshForAction(actionLabel, { requireToken: true });
  return {
    session_token: byId("session_token").value.trim()
  };
}

async function requestPublicContributionStatus() {
  return post("/v1/gpm/contribution/status", publicContributionSessionRequest("Contribution status"));
}

async function requestPublicContributionEnable() {
  const role = publicContributionSelectedRole();
  const request = publicContributionSessionRequest("Enable contribution");
  request.role = role;
  return post("/v1/gpm/contribution/enable", request);
}

async function requestPublicContributionDisable() {
  return post("/v1/gpm/contribution/disable", publicContributionSessionRequest("Disable contribution"));
}

async function requestPublicRewardsCurrentWeek() {
  return post("/v1/gpm/rewards/current-week", publicContributionSessionRequest("Current week reward"));
}

async function requestPublicRewardsHistory() {
  return post("/v1/gpm/rewards/history", publicContributionSessionRequest("Reward history"));
}

function applyOnboardingOverviewPayload(payload) {
  if (!payload || typeof payload !== "object") {
    return;
  }
  refreshSessionFreshnessFromPayload(payload);
  syncSessionDerivedState(payload);
  refreshSessionBootstrapDirectoryOptions(payload);
  const role = sessionRoleFromResult(payload);
  if (typeof role === "string" && role.trim()) {
    byId("role").value = role;
  }
  applyClientRegistrationPayload(payload);
  applyBootstrapTrustStatusPayload(payload);
  setPublicReadiness(parsePublicReadiness(payload));
  setServerApplicationStatus(parseServerApplicationStatus(payload));
}

async function requestOverview() {
  assertSessionFreshForAction("Onboarding overview", { requireToken: true });
  const sessionToken = byId("session_token").value.trim();
  return post("/v1/gpm/onboarding/overview", { session_token: sessionToken });
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
  const prodProfile = connectProdProfileRequested();
  const installRoute = prodProfile || connectInstallRouteEl.checked === true;
  const request = {
    session_token: sessionToken || undefined,
    path_profile: pathProfile,
    policy_profile: pathProfile,
    interface: nonEmptyString(connectInterfaceEl.value),
    discovery_wait_sec: positiveIntegerOrUndefined(connectDiscoveryWaitSecEl.value),
    ready_timeout_sec: positiveIntegerOrUndefined(connectReadyTimeoutSecEl.value),
    run_preflight: connectRunPreflightEl.checked,
    prod_profile: prodProfile
  };
  if (installRoute) {
    request.install_route = true;
  }
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

function productionConnectReservationSessionID() {
  if (window.crypto && typeof window.crypto.randomUUID === "function") {
    return `gpm-vpn-${window.crypto.randomUUID()}`;
  }
  return `gpm-vpn-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function reservationString(payload, key) {
  if (!payload || typeof payload !== "object") {
    return "";
  }
  const value = payload[key];
  return typeof value === "string" ? value.trim() : "";
}

function reservationPayloadObject(payload) {
  return payload && typeof payload.reservation === "object" && payload.reservation
    ? payload.reservation
    : {};
}

function productionReservationConfirmed(payload) {
  const reservation = reservationPayloadObject(payload);
  const chainStatus = reservationString(payload, "reservation_chain_status").toLowerCase();
  const stateLabel = reservationString(payload, "reservation_finalization_state").toLowerCase();
  const reservationStatus = reservationString(reservation, "status").toLowerCase();
  return (
    chainStatus === "confirmed" ||
    chainStatus === "finalized" ||
    stateLabel === "chain_confirmed" ||
    stateLabel === "finalized" ||
    reservationStatus === "confirmed" ||
    reservationStatus === "finalized"
  );
}

function reservationFinalityLabel(payload) {
  const reservation = reservationPayloadObject(payload);
  return (
    reservationString(payload, "reservation_finalization_state") ||
    reservationString(payload, "reservation_chain_status") ||
    reservationString(reservation, "status") ||
    "pending"
  );
}

function delay(ms) {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

async function attachProductionConnectReservation(request) {
  if (!gpmProductionMode || !request || request.reservation_id || request.reservation_session_id) {
    return request;
  }
  const sessionToken = typeof request.session_token === "string" ? request.session_token.trim() : "";
  if (!sessionToken) {
    throw new Error("Production connect requires sign-in before reserving VPN funds.");
  }
  let cached =
    productionConnectReservationCache && productionConnectReservationCache.sessionToken === sessionToken
      ? productionConnectReservationCache
      : null;
  if (!cached) {
    cached = {
      sessionToken,
      sessionID: productionConnectReservationSessionID(),
      reservationID: ""
    };
    productionConnectReservationCache = cached;
  }
  let lastResult = null;
  for (let attempt = 1; attempt <= PRODUCTION_CONNECT_RESERVATION_MAX_ATTEMPTS; attempt += 1) {
    const reserveRequest = {
      session_token: sessionToken,
      session_id: cached.sessionID,
      amount_micros: PRODUCTION_CONNECT_RESERVATION_AMOUNT_MICROS,
      currency: PRODUCTION_CONNECT_RESERVATION_CURRENCY
    };
    if (cached.reservationID) {
      reserveRequest.reservation_id = cached.reservationID;
    }
    lastResult = await post("/v1/gpm/settlement/reserve-funds", reserveRequest);
    const reservation = reservationPayloadObject(lastResult);
    cached.reservationID =
      reservationString(reservation, "reservation_id") ||
      reservationString(lastResult, "reservation_id") ||
      cached.reservationID;
    cached.sessionID =
      reservationString(reservation, "session_id") ||
      reservationString(lastResult, "reservation_session_id") ||
      cached.sessionID;
    if (cached.reservationID && cached.sessionID && productionReservationConfirmed(lastResult)) {
      request.reservation_id = cached.reservationID;
      request.reservation_session_id = cached.sessionID;
      return request;
    }
    if (attempt < PRODUCTION_CONNECT_RESERVATION_MAX_ATTEMPTS) {
      await delay(PRODUCTION_CONNECT_RESERVATION_RETRY_DELAY_MS);
    }
  }
  throw new Error(
    `Production connect fund reservation is not chain-confirmed yet (${reservationFinalityLabel(lastResult)}). Try Connect again in a moment.`
  );
}

function confirmExpertInstallRouteRequest(request) {
  if (!request || request.install_route !== true) {
    return;
  }
  if (connectProdProfileRequested()) {
    return;
  }
  const confirmed = window.confirm(
    "Expert full-tunnel route confirmation\n\n" +
      "This will send install_route=true and install the system default route through GPM. " +
      "Only continue if you intentionally want all device traffic to use the VPN route."
  );
  if (!confirmed) {
    connectInstallRouteEl.checked = false;
    request.install_route = false;
    throw new Error("Connect cancelled: expert full-tunnel route was not confirmed.");
  }
}

function assertConnectActionAllowed(request) {
  if (configEndpointUnavailableFailClosedMode()) {
    throw new Error(`Connect is unavailable: ${failClosedMutatingActionStatusDetail()}`);
  }
  const sessionToken = typeof request?.session_token === "string" ? request.session_token.trim() : "";
  const readiness = computeClientReadiness();
  if (!isClientTabVisibleRole() || readiness.state === "role_locked") {
    throw new Error(`Connect is unavailable: ${readiness.guidanceText}`);
  }
  if (!sessionToken) {
    if (!compatibilityOverrideEnabled()) {
      throw new Error(`Connect is unavailable: ${connectValidationHint()}`);
    }
    return;
  }
  assertSessionFreshForAction("Connect");
}

async function requestConnectControl() {
  const request = buildConnectRequest();
  assertConnectActionAllowed(request);
  if (!request.session_token && (!request.bootstrap_directory || !request.invite_key)) {
    throw new Error(connectValidationHint());
  }
  confirmExpertInstallRouteRequest(request);
  await attachProductionConnectReservation(request);
  const result = await post("/v1/connect", request);
  inviteKeyEl.value = "";
  persistPortalState();
  return result;
}

async function requestDisconnectControl() {
  const sessionToken = byId("session_token").value.trim();
  return post("/v1/disconnect", {
    session_token: sessionToken || undefined
  });
}

async function requestConnectionStatus() {
  return get("/v1/status");
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

async function refreshPublicContributionBestEffort(options = {}) {
  const { quiet = true, includeHistory = false } = options;
  if (!byId("session_token").value.trim()) {
    clearPublicContributionState();
    return undefined;
  }
  try {
    const status = await requestPublicContributionStatus();
    applyPublicContributionStatusPayload(status);
    try {
      const currentWeek = await requestPublicRewardsCurrentWeek();
      applyPublicCurrentWeekRewardPayload(currentWeek);
    } catch {
      // Current-week rewards are additive; keep contribution status usable if this read fails.
    }
    if (includeHistory) {
      try {
        const history = await requestPublicRewardsHistory();
        applyPublicRewardHistoryPayload(history);
      } catch {
        // History is non-critical for the status refresh path.
      }
    }
    return status;
  } catch (err) {
    publicContributionStatusPayload = null;
    renderPublicContributionStatus();
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
    successDetail: () => "Wallet connected and session created."
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
    await refreshBootstrapTrustStatusBestEffort({ quiet: true });
    await refreshPublicContributionBestEffort({ quiet: true });
    persistPortalState();
    return result;
  })
);

byId("session_rotate_btn").addEventListener("click", () =>
  run("session_rotate", async () => {
    const result = await requestSessionLifecycle("refresh");
    applySession(result);
    setPublicReadiness(null);
    await refreshClientRegistrationStatus({ quiet: true });
    await refreshBootstrapTrustStatusBestEffort({ quiet: true });
    await refreshPublicContributionBestEffort({ quiet: true });
    persistPortalState();
    return result;
  })
);

byId("session_revoke_btn").addEventListener("click", () =>
  run("session_revoke", async () => {
    const result = await requestSessionLifecycle("revoke");
    clientRegistered = false;
    setClientRegistrationTrustDriftState(false, "");
    clearSessionFreshnessTelemetry();
    byId("session_token").value = "";
    byId("role").value = "client";
    setPublicReadiness(null);
    setServerApplicationStatus("not_submitted", "Connect wallet first, then apply if you want this device reviewed for server mode.");
    clearPublicContributionState();
    persistPortalState();
    await refreshBootstrapTrustStatusBestEffort({ quiet: true });
    return result;
  })
);

byId("manifest_btn").addEventListener("click", () =>
  run("bootstrap_manifest", requestBootstrapManifest)
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
    await refreshBootstrapTrustStatusBestEffort({ quiet: true });
    await refreshPublicContributionBestEffort({ quiet: true });
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
      successDetail: () => "Onboarding overview refreshed for the public client lane."
    }
  )
);

byId("apply_server_btn").addEventListener("click", () =>
  run(
    "server_apply",
    async () => {
      const result = await requestServerApply();
      setServerApplicationStatus(parseServerApplicationStatus(result), "Server application sent for GPM review.");
      return result;
    },
    {
      successDetail: () => "Server application submitted. GPM must approve it before server mode is available."
    }
  )
);

byId("server_status_btn").addEventListener("click", () =>
  run(
    "server_status",
    async () => {
      const result = await requestServerStatus();
      setServerApplicationStatus(parseServerApplicationStatus(result));
      setPublicReadiness(parsePublicReadiness(result));
      return result;
    },
    {
      successDetail: () => "Server application status refreshed."
    }
  )
);

contributionStatusBtnEl.addEventListener("click", () =>
  run(
    "contribution_status",
    async () => {
      const result = await requestPublicContributionStatus();
      applyPublicContributionStatusPayload(result);
      await refreshPublicContributionBestEffort({ quiet: true });
      return result;
    },
    {
      successDetail: () => "Contribution eligibility refreshed for the signed-in session."
    }
  )
);

contributionEnableBtnEl.addEventListener("click", () =>
  run(
    "contribution_enable",
    async () => {
      const state = computeContributionActionState();
      if (!state.statusLoaded) {
        throw new Error("Enable contribution is unavailable: run Contribution Status first.");
      }
      if (!state.canEnable) {
        throw new Error(`Enable contribution is unavailable: ${publicContributionLockReason(publicContributionStatusPayload, state.selectedRole)}`);
      }
      const result = await requestPublicContributionEnable();
      applyPublicContributionStatusPayload(result);
      await refreshPublicContributionBestEffort({ quiet: true });
      return result;
    },
    {
      successDetail: () => "Contribution enabled for this signed-in device."
    }
  )
);

contributionDisableBtnEl.addEventListener("click", () =>
  run(
    "contribution_disable",
    async () => {
      const state = computeContributionActionState();
      if (!state.enabled) {
        throw new Error("Disable contribution is unavailable: contribution is not currently enabled.");
      }
      const result = await requestPublicContributionDisable();
      applyPublicContributionStatusPayload(result);
      await refreshPublicContributionBestEffort({ quiet: true });
      return result;
    },
    {
      successDetail: () => "Contribution disabled for this signed-in device."
    }
  )
);

rewardCurrentWeekBtnEl.addEventListener("click", () =>
  run(
    "reward_current_week",
    async () => {
      const result = await requestPublicRewardsCurrentWeek();
      applyPublicCurrentWeekRewardPayload(result);
      return result;
    },
    {
      successDetail: () => "Current-week reward summary refreshed for the signed-in session."
    }
  )
);

rewardHistoryBtnEl.addEventListener("click", () =>
  run(
    "reward_history",
    async () => {
      const result = await requestPublicRewardsHistory();
      applyPublicRewardHistoryPayload(result);
      return result;
    },
    {
      successDetail: (result) =>
        `${publicContributionHistoryRewards(result).length} reward history entr${
          publicContributionHistoryRewards(result).length === 1 ? "y" : "ies"
        } loaded for the signed-in session.`
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

async function restoreSessionStatusBestEffort() {
  const token = byId("session_token").value.trim();
  if (!token) {
    clearSessionFreshnessTelemetry();
    setPublicReadiness(null);
    clearPublicContributionState();
    await refreshBootstrapTrustStatusBestEffort({ quiet: true });
    return;
  }
  setStatus("warn", "Restoring session", "Checking stored session token status.");
  try {
    const result = await requestSessionLifecycle("status");
    applySession(result);
    persistPortalState();
    print("session_status (auto)", result);
    const freshness = computeSessionFreshnessState();
    if (freshness.state === "expired") {
      setStatus("bad", "Session expired", freshness.detail);
    } else if (freshness.state === "expiring_soon" || freshness.state === "unknown") {
      setStatus("warn", "Session restored", freshness.detail);
    } else {
      setStatus("good", "Session restored", "Stored session token is active.");
    }
  } catch (err) {
    print("session_status (auto, non-fatal)", String(err && err.message ? err.message : err));
    setStatus("warn", "Session check skipped", "Stored session token could not be validated. You can refresh or sign in again.");
  }
  await refreshClientRegistrationStatus({ quiet: true });
  await refreshBootstrapTrustStatusBestEffort({ quiet: true });
  await refreshPublicContributionBestEffort({ quiet: true });
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
  bindPersistenceListeners();
  bindCompatibilityOverrideListeners();
  bindReadinessListeners();
  persistPortalState();
  syncWalletExtensionReadinessHint();
  syncConnectRoutePolicy();
  refreshClientReadiness();
  refreshPolicyPostureBanner();
  refreshLegacyAliasWarningBanner();
  clearPublicContributionState();
  setStatus("good", "Portal ready", "Connect your wallet to begin.");
  void refreshConnectPolicyConfigBestEffort({ quiet: true });
  void refreshBootstrapTrustStatusBestEffort({ quiet: true });
  void restoreSessionStatusBestEffort();
}

initializePortal();
