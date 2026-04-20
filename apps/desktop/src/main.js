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
const manifestSourceEl = byId("manifest_source");
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
const connectionStateEl = document.getElementById("connection_state");
const connectionDetailEl = document.getElementById("connection_detail");
const signInPolicyHintEl = document.getElementById("signin_policy_hint");

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
const compatAdvancedSectionEl = document.getElementById("legacy_compat_section");
const compatEnableEl = byId("compat_enable");
const bootstrapDirectoryEl = byId("bootstrap_directory");
const inviteKeyEl = byId("invite_key");
const compatAdvancedHintEl = document.querySelector("details.advanced > p");
const desktopStepSessionEl = document.getElementById("desktop_step_session");
const desktopStepClientEl = document.getElementById("desktop_step_client");
const desktopStepOperatorEl = document.getElementById("desktop_step_operator");
const operatorListNextBtnEl = byId("operator_list_next_btn");
const MAX_OUTPUT_CHARS = 64 * 1024;
const OPERATOR_PENDING_LIST_LIMIT = 25;
const OPERATOR_LOAD_NEXT_LIMIT = 1;
const OPERATOR_LIST_ALL_LIMIT = 100;
const OPERATOR_FILTER_DEFAULT_LIMIT = 25;
const OPERATOR_DECISION_CONFLICT_GUIDANCE =
  "Decision conflict detected: the selected application was updated by another reviewer. Reload pending queue with Load Next Pending and retry.";
const CONNECTION_DEFAULT_STATE = "Unknown";
const CONNECTION_DEFAULT_DETAIL = "Not checked yet";
const OPERATOR_APPLICATION_STATUSES = new Set(["not_submitted", "pending", "approved", "rejected"]);
const WALLET_EXTENSION_PROVIDERS = new Set(["keplr", "leap"]);
const COMPAT_ADVANCED_DEFAULT_HINT = "Optional legacy fields for support-only compatibility flows.";
const COMPAT_ADVANCED_LOCKED_HINT =
  "Manual bootstrap/invite overrides are locked by policy; connect uses session token only.";
const COMPAT_ADVANCED_DISABLED_HINT =
  "Legacy bootstrap/invite overrides are disabled by policy in this build.";
const CONNECT_POLICY_SOURCE_ENV_DEFAULT = "env_default";
const CONNECT_POLICY_SOURCE_RUNTIME_CONFIG = "runtime_config";
const CONNECT_POLICY_MODE_SESSION_REQUIRED = "session_required";
const CONNECT_POLICY_MODE_COMPAT_ALLOWED = "compat_allowed";
const AUTH_VERIFY_POLICY_SOURCE_ENV_DEFAULT = "env_default";
const AUTH_VERIFY_POLICY_SOURCE_RUNTIME_CONFIG = "runtime_config";
const WALLET_SIGN_IN_LABEL_RECOMMENDED = "Wallet Sign-In (Recommended)";
const WALLET_SIGN_IN_LABEL_REQUIRED = "Wallet Sign-In (Required)";
const MANUAL_SIGN_IN_LABEL = "Sign In (Manual)";
const MANUAL_SIGN_IN_LABEL_DISABLED = "Sign In (Manual Disabled)";
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

const state = {
  sessionToken: "",
  role: "client",
  operatorApplicationStatus: undefined,
  selectedApplicationUpdatedAtUtc: "",
  serverReadiness: null,
  clientRegistered: false,
  serviceMutationsAllowed: false,
  allowLegacyConnectOverride: false,
  connectRequireSession: false,
  connectPolicySource: CONNECT_POLICY_SOURCE_ENV_DEFAULT,
  connectPolicyMode: CONNECT_POLICY_MODE_COMPAT_ALLOWED,
  authVerifyRequireMetadata: false,
  authVerifyRequireWalletExtensionSource: false,
  authVerifyRuntimeRequireWalletExtensionSource: false,
  authVerifyPolicySource: AUTH_VERIFY_POLICY_SOURCE_ENV_DEFAULT,
  manifest: null,
  connectionState: CONNECTION_DEFAULT_STATE,
  connectionDetail: CONNECTION_DEFAULT_DETAIL,
  operatorListNextCursor: "",
  operatorListRequestContext: null,
  walletSignatureContext: null,
  authChallengeMessage: ""
};

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
  state.clientRegistered = inferClientRegistrationFromPayload(result);
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

  return {
    state: formatConnectionStateLabel(stateKey),
    detail: inferConnectionDetail(payload, source, stateKey, stateHint)
  };
}

function applyConnectionSnapshot(snapshot) {
  state.connectionState = snapshot?.state || state.connectionState || CONNECTION_DEFAULT_STATE;
  state.connectionDetail = snapshot?.detail || state.connectionDetail || CONNECTION_DEFAULT_DETAIL;
  if (connectionStateEl) {
    connectionStateEl.textContent = state.connectionState;
  }
  if (connectionDetailEl) {
    connectionDetailEl.textContent = state.connectionDetail;
  }
}

function updateConnectionDashboard(source, payload) {
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
    authVerifyPolicySource
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

  return {
    apiLine: timeout ? `${product} API: ${baseUrl} (timeout: ${timeout}s)` : `${product} API: ${baseUrl}`,
    hintLine: hints.join(" | "),
    updateMutationsEnabled: updateMutationsEnabled === true,
    serviceMutationsEnabled: serviceMutationsEnabled === true,
    connectRequireSession: connectRequireSession === true,
    allowLegacyConnectOverride: allowLegacyConnectOverride === true,
    authVerifyRequireMetadata: authVerifyRequireMetadata === true,
    authVerifyRequireWalletExtensionSource: authVerifyRequireWalletExtensionSource === true
  };
}

function formatConnectPolicySourceHint(source, mode) {
  return `connect policy: ${formatConnectPolicyModeLabel(mode)} (${formatConnectPolicySourceLabel(source)})`;
}

function formatAuthVerifyPolicyModeLabel(requireMetadata, requireWalletExtensionSource) {
  if (requireMetadata && requireWalletExtensionSource) {
    return "metadata-required + wallet-extension-source-required";
  }
  if (requireMetadata) {
    return "metadata-required";
  }
  if (requireWalletExtensionSource) {
    return "wallet-extension-source-required";
  }
  return "compat";
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
  return "env defaults (GPM_AUTH_VERIFY_REQUIRE_METADATA / GPM_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE; legacy aliases: TDPN_AUTH_VERIFY_REQUIRE_METADATA / TDPN_AUTH_VERIFY_REQUIRE_WALLET_EXTENSION_SOURCE)";
}

function formatAuthVerifyPolicySourceHint(source, requireMetadata, requireWalletExtensionSource) {
  return `auth verify policy: ${formatAuthVerifyPolicyModeLabel(
    requireMetadata,
    requireWalletExtensionSource
  )} (${formatAuthVerifyPolicySourceLabel(source)})`;
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

function inferClientRegistrationFromPayload(payload) {
  return extractBootstrapRegistrationMetadata(payload).hasBootstrapDirectory;
}

function parseClientRegistrationStatus(payload) {
  const status = payload?.registration?.status;
  if (typeof status !== "string") {
    return undefined;
  }
  const normalized = status.trim().toLowerCase();
  if (normalized === "registered") {
    return true;
  }
  if (normalized === "not_registered") {
    return false;
  }
  return undefined;
}

function syncDesktopOnboardingSteps() {
  const hasSession = !!state.sessionToken;
  const backendReadiness = state.serverReadiness;
  const role = (backendReadiness?.role || state.role || "client").toLowerCase();
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
  if (!state.clientRegistered) {
    setDesktopStepState(desktopStepClientEl, "active");
    setDesktopStepState(desktopStepOperatorEl, "blocked");
    return;
  }

  setDesktopStepState(desktopStepClientEl, "done");
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
  const mutationsEnabled = state.serviceMutationsAllowed && isServerMutationRoleEligible();
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
      if (readiness.unlockActions.length > 0) {
        hintText = `${reason} Next: ${readiness.unlockActions.join("; ")}`;
      } else {
        hintText = reason;
      }
    }
    return appendReadinessDiagnosticsHint(appendChainBindingHint(hintText, readiness), readiness);
  }
  if (!state.sessionToken) {
    return "Sign in first to unlock server onboarding.";
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
      return "Operator application pending approval. Server lifecycle actions stay locked until approved.";
    }
    if (state.operatorApplicationStatus === "rejected") {
      return "Operator application rejected; re-apply or contact admin to unlock server lifecycle actions.";
    }
    if (state.operatorApplicationStatus === "not_submitted") {
      return "Operator role detected but no approved application yet. Submit operator application to unlock server lifecycle actions.";
    }
    return "Operator role detected; check operator status and refresh session after approval to unlock server lifecycle actions.";
  }
  if (role === "server" || role === "server_only") {
    if (!state.serviceMutationsAllowed) {
      return "Server-only role detected. Service lifecycle actions are disabled by environment policy.";
    }
    return "Server controls are unlocked for server-only role.";
  }
  return "Apply operator role to start server approval.";
}

function computeClientLockHintText() {
  if (state.serverReadiness) {
    const readiness = state.serverReadiness;
    if (readiness.clientTabVisible === false) {
      return readiness.clientLockReason || "Client controls are locked by backend readiness policy for this role.";
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
      return "Server-capable session detected. Register client profile to unlock the Client tab for dual-role use.";
    }
    if (role === "server" || role === "server_only") {
      return "Client controls are disabled for server-only role.";
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

function syncServerRoleLockState() {
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
      activateTab("client");
    } else if (serverTabVisible) {
      activateTab("server");
    }
  }
  syncServerMutationControls();
  if (clientLockHintEl) {
    clientLockHintEl.textContent = computeClientLockHintText();
    clientLockHintEl.classList.toggle("locked", !clientTabVisible);
  }
  serverLockHintEl.textContent = computeServerLockHintText();
  serverLockHintEl.classList.toggle("locked", !serverTabVisible);
  syncDesktopOnboardingSteps();
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
    clearOperatorListPaginationState();
  }
  state.sessionToken = nextValue;
  sessionTokenEl.value = state.sessionToken;
  if (persist) {
    clearLegacySecretStorage();
  }
  syncServerRoleLockState();
  syncOperatorListPaginationControlState();
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
  const allow = !!enabled && state.allowLegacyConnectOverride && !state.connectRequireSession;
  compatEnableEl.checked = allow;
  compatEnableEl.disabled = !state.allowLegacyConnectOverride || state.connectRequireSession;
  bootstrapDirectoryEl.disabled = !state.allowLegacyConnectOverride || state.connectRequireSession || !allow;
  inviteKeyEl.disabled = !state.allowLegacyConnectOverride || state.connectRequireSession || !allow;
}

function syncCompatAdvancedVisibility() {
  if (!compatAdvancedSectionEl) {
    return;
  }
  const visible = state.allowLegacyConnectOverride;
  compatAdvancedSectionEl.hidden = !visible;
  if (!visible) {
    compatAdvancedSectionEl.open = false;
  }
}

function updateCompatOverrideHint() {
  if (!compatAdvancedHintEl) {
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
  if (state.connectRequireSession) {
    postureHint = "manual bootstrap/invite fields are intentionally locked by production policy.";
  } else if (!state.allowLegacyConnectOverride) {
    postureHint = "manual bootstrap/invite fields are policy-locked in this build.";
  }
  connectPolicyHintEl.textContent = `Connect policy: ${modeLabel} from ${sourceLabel}; ${postureHint}`;
  connectPolicyHintEl.classList.toggle("locked", state.connectRequireSession || !state.allowLegacyConnectOverride);
}

function isManualSignInLockedByRuntimePolicy() {
  return state.authVerifyRuntimeRequireWalletExtensionSource === true;
}

function syncIdentitySignInPolicyControls() {
  const manualSignInLocked = isManualSignInLockedByRuntimePolicy();
  walletSignInBtnEl.disabled = false;
  walletSignInBtnEl.textContent = manualSignInLocked
    ? WALLET_SIGN_IN_LABEL_REQUIRED
    : WALLET_SIGN_IN_LABEL_RECOMMENDED;
  walletSignInBtnEl.title = manualSignInLocked
    ? "Runtime auth policy requires signature_source=wallet_extension."
    : "Recommended sign-in path.";
  signInBtnEl.disabled = manualSignInLocked;
  signInBtnEl.textContent = manualSignInLocked ? MANUAL_SIGN_IN_LABEL_DISABLED : MANUAL_SIGN_IN_LABEL;
  signInBtnEl.title = manualSignInLocked
    ? "Manual Sign In is locked by runtime auth policy requiring signature_source=wallet_extension."
    : "Manual fallback path when policy allows manual source.";
  if (!signInPolicyHintEl) {
    return;
  }
  if (manualSignInLocked) {
    signInPolicyHintEl.textContent =
      "Wallet Sign-In is required by runtime auth policy; manual Sign In is disabled.";
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
  const manualSignInLockedByRuntimePolicy = isManualSignInLockedByRuntimePolicy();
  const modeLabel = formatAuthVerifyPolicyModeLabel(
    state.authVerifyRequireMetadata,
    state.authVerifyRequireWalletExtensionSource
  );
  const sourceLabel = formatAuthVerifyPolicyClientSourceLabel(state.authVerifyPolicySource);
  let postureHint = "signature metadata and signature_source checks are compatibility-optional.";
  if (state.authVerifyRequireMetadata && state.authVerifyRequireWalletExtensionSource) {
    postureHint = manualSignInLockedByRuntimePolicy
      ? "signature metadata is required and signature_source must be wallet_extension; use Wallet Sign-In (manual Sign In is disabled)."
      : "signature metadata is required and signature_source must be wallet_extension.";
  } else if (state.authVerifyRequireMetadata) {
    postureHint = "signature metadata is required (signature_kind, signature_source, signed_message).";
  } else if (state.authVerifyRequireWalletExtensionSource) {
    postureHint = manualSignInLockedByRuntimePolicy
      ? "signature_source must be wallet_extension; use Wallet Sign-In (manual Sign In is disabled)."
      : "signature_source must be wallet_extension.";
  }
  authVerifyPolicyHintEl.textContent = `Auth verify policy: ${modeLabel} from ${sourceLabel}; ${postureHint}`;
  authVerifyPolicyHintEl.classList.toggle(
    "locked",
    state.authVerifyRequireMetadata || state.authVerifyRequireWalletExtensionSource
  );
  syncIdentitySignInPolicyControls();
}

function applyConnectModePolicy(enabled) {
  state.connectRequireSession = !!enabled;
  syncCompatAdvancedVisibility();
  if (state.connectRequireSession) {
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
  panelClientEl.classList.toggle("active", isClient);
  panelServerEl.classList.toggle("active", !isClient);
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
  const registrationStatus = parseClientRegistrationStatus(payload);
  if (registrationStatus !== undefined) {
    state.clientRegistered = registrationStatus;
  } else {
    state.clientRegistered = inferClientRegistrationFromPayload(payload);
  }
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

  if (state.allowLegacyConnectOverride && !state.connectRequireSession && compatEnableEl.checked) {
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

async function loadManifest() {
  const result = await call("gpm_manifest", "control_gpm_bootstrap_manifest");
  state.manifest = result?.manifest || null;
  const source = result?.source || "unknown";
  const sig = result?.signature_verified === true ? "signature verified" : "signature not verified";
  manifestSourceEl.textContent = `Manifest: ${source} (${sig})`;
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
    const status = parseClientRegistrationStatus(result);
    if (status !== undefined) {
      state.clientRegistered = status;
    }
    syncDesktopOnboardingSteps();
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
    setOperatorApplicationStatus(undefined);
    setServerReadiness(null);
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
    return result;
  }
  state.clientRegistered = inferClientRegistrationFromPayload(result);
  setRole(parseSessionRole(result));
  const overview = await requestOnboardingOverview({ quiet: true });
  if (!overview) {
    await refreshClientRegistrationStatus({ quiet: true });
    await refreshServerReadinessStatus({ quiet: true });
  }
  await refreshOperatorApplicationStatus({ quiet: true });
  return result;
}

async function refreshSessionOnInit() {
  if (!state.sessionToken) {
    setServerReadiness(null);
    return;
  }
  let overview;
  try {
    const result = await invoke("control_gpm_session", {
      request: { session_token: state.sessionToken, action: "status" }
    });
    state.clientRegistered = inferClientRegistrationFromPayload(result);
    setRole(parseSessionRole(result));
    overview = await requestOnboardingOverview({ quiet: true });
  } catch {
    // Startup status refresh is best-effort and should not block the scaffold.
  }
  if (!overview) {
    await refreshClientRegistrationStatus({ quiet: true });
    await refreshServerReadinessStatus({ quiet: true });
  }
  await refreshOperatorApplicationStatus({ quiet: true });
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
});
challengeIdEl.addEventListener("input", () => {
  clearWalletSignatureContext();
  state.authChallengeMessage = "";
});
walletSignatureEl.addEventListener("input", () => {
  clearWalletSignatureContext();
});
signatureChainIdEl.addEventListener("input", () => {
  clearWalletSignatureContext();
});
signedMessageEl.addEventListener("input", () => {
  clearWalletSignatureContext();
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
    print(
      "validation",
      "Manual Sign In is disabled by runtime auth policy; use Wallet Sign-In (signature_source must be wallet_extension)."
    );
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
  if (!state.sessionToken) {
    print("validation", "session_token is required; sign in first");
    return;
  }
  const request = {
    session_token: state.sessionToken,
    path_profile: pathProfileEl.value
  };
  if (state.allowLegacyConnectOverride && !state.connectRequireSession && compatEnableEl.checked) {
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
  state.clientRegistered = inferClientRegistrationFromPayload(result) || true;
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
  const request = {
    wallet_address: walletAddressEl.value.trim(),
    approved: true,
    session_token: state.sessionToken || undefined
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
  const request = connectPayload();
  if (!request.session_token && (!request.bootstrap_directory || !request.invite_key)) {
    const hint = state.connectRequireSession
      ? "session_token is required in session-required connect mode; sign in first"
      : state.allowLegacyConnectOverride
        ? "sign in + register client, or provide compatibility bootstrap_directory + invite"
        : "sign in and register the client profile before connecting";
    print("validation", hint);
    return;
  }
  inviteKeyEl.value = "";
  const result = await call("connect", "control_connect", { request });
  updateConnectionDashboard("connect", result);
});

compatEnableEl.addEventListener("change", () => {
  setCompatOverrideEnabled(compatEnableEl.checked);
  if (!compatEnableEl.checked) {
    bootstrapDirectoryEl.value = "";
    inviteKeyEl.value = "";
  }
});

byId("disconnect_btn").addEventListener("click", async () => {
  const result = await call("disconnect", "control_disconnect");
  updateConnectionDashboard("disconnect", result);
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
  const request = { path_profile: byId("set_profile").value };
  await call("set_profile", "control_set_profile", { request });
});

byId("update_btn").addEventListener("click", async () => {
  await call("update", "control_update");
});

byId("service_status_btn").addEventListener("click", async () => {
  await call("service_status", "control_service_status");
});

byId("service_start_btn").addEventListener("click", async () => {
  if (!requireSessionToken("start the service")) {
    return;
  }
  await call("service_start", "control_service_start", { request: serviceLifecycleRequest() });
});

byId("service_stop_btn").addEventListener("click", async () => {
  if (!requireSessionToken("stop the service")) {
    return;
  }
  await call("service_stop", "control_service_stop", { request: serviceLifecycleRequest() });
});

byId("service_restart_btn").addEventListener("click", async () => {
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
  try {
    const cfg = await invoke("control_config");
    const meta = formatConfigMeta(cfg || {});
    let connectRequireSession = meta.connectRequireSession;
    let allowLegacyConnectOverride = meta.allowLegacyConnectOverride;
    let connectPolicySource = CONNECT_POLICY_SOURCE_ENV_DEFAULT;
    let connectPolicyMode = connectPolicyModeFromRequireSession(connectRequireSession);
    let authVerifyRequireMetadata = meta.authVerifyRequireMetadata;
    let authVerifyRequireWalletExtensionSource = meta.authVerifyRequireWalletExtensionSource;
    let authVerifyRuntimeRequireWalletExtensionSource = false;
    let authVerifyPolicySource = AUTH_VERIFY_POLICY_SOURCE_ENV_DEFAULT;
    try {
      const runtimeCfg = await invoke("control_runtime_config");
      const runtimeConnectPolicy = readRuntimeConnectPolicyMetadata(runtimeCfg || {});
      const runtimeAuthVerifyPolicy = readRuntimeAuthVerifyPolicyMetadata(runtimeCfg || {});
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
      if (runtimeAuthVerifyPolicy.authVerifyPolicySource) {
        authVerifyPolicySource = runtimeAuthVerifyPolicy.authVerifyPolicySource;
      } else if (
        runtimeAuthVerifyPolicy.authVerifyRequireMetadata !== undefined ||
        runtimeAuthVerifyPolicy.authVerifyRequireWalletExtensionSource !== undefined
      ) {
        authVerifyPolicySource = AUTH_VERIFY_POLICY_SOURCE_RUNTIME_CONFIG;
      }
    } catch {
      connectPolicySource = CONNECT_POLICY_SOURCE_ENV_DEFAULT;
      connectPolicyMode = connectPolicyModeFromRequireSession(connectRequireSession);
      authVerifyRuntimeRequireWalletExtensionSource = false;
      authVerifyPolicySource = AUTH_VERIFY_POLICY_SOURCE_ENV_DEFAULT;
    }
    state.connectPolicySource = connectPolicySource;
    state.connectPolicyMode = connectPolicyMode;
    state.allowLegacyConnectOverride = !!allowLegacyConnectOverride;
    state.authVerifyRequireMetadata = !!authVerifyRequireMetadata;
    state.authVerifyRequireWalletExtensionSource = !!authVerifyRequireWalletExtensionSource;
    state.authVerifyRuntimeRequireWalletExtensionSource = authVerifyRuntimeRequireWalletExtensionSource;
    state.authVerifyPolicySource = authVerifyPolicySource;
    apiBaseEl.textContent = meta.apiLine;
    apiHintsEl.textContent = [
      meta.hintLine,
      formatConnectPolicySourceHint(connectPolicySource, connectPolicyMode),
      formatAuthVerifyPolicySourceHint(
        authVerifyPolicySource,
        state.authVerifyRequireMetadata,
        state.authVerifyRequireWalletExtensionSource
      )
    ]
      .filter((value) => typeof value === "string" && value.trim().length > 0)
      .join(" | ");
    updateBtnEl.disabled = !meta.updateMutationsEnabled;
    state.serviceMutationsAllowed = meta.serviceMutationsEnabled;
    applyConnectModePolicy(connectRequireSession);
    updateAuthVerifyPolicyHint();
    syncServerRoleLockState();
  } catch (err) {
    apiBaseEl.textContent = "API: unavailable";
    apiHintsEl.textContent = "";
    updateBtnEl.disabled = true;
    state.serviceMutationsAllowed = false;
    state.connectPolicySource = CONNECT_POLICY_SOURCE_ENV_DEFAULT;
    state.connectPolicyMode = CONNECT_POLICY_MODE_COMPAT_ALLOWED;
    state.allowLegacyConnectOverride = false;
    state.authVerifyRequireMetadata = false;
    state.authVerifyRequireWalletExtensionSource = false;
    state.authVerifyRuntimeRequireWalletExtensionSource = false;
    state.authVerifyPolicySource = AUTH_VERIFY_POLICY_SOURCE_ENV_DEFAULT;
    applyConnectModePolicy(false);
    updateAuthVerifyPolicyHint();
    syncServerRoleLockState();
    print("init (error)", err);
  }

  try {
    await loadManifest();
  } catch {
    manifestSourceEl.textContent = "Manifest: unavailable";
  }

  await refreshSessionOnInit();
}

init();
