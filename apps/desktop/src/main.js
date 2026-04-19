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
const chainOperatorIdEl = byId("chain_operator_id");
const pathProfileEl = byId("path_profile");
const serverLockHintEl = byId("server_lock_hint");
const connectionStateEl = document.getElementById("connection_state");
const connectionDetailEl = document.getElementById("connection_detail");

const updateBtnEl = byId("update_btn");
const serviceStartBtnEl = byId("service_start_btn");
const serviceStopBtnEl = byId("service_stop_btn");
const serviceRestartBtnEl = byId("service_restart_btn");
const tabClientEl = byId("tab_client");
const tabServerEl = byId("tab_server");
const panelClientEl = byId("panel_client");
const panelServerEl = byId("panel_server");
const compatEnableEl = byId("compat_enable");
const bootstrapDirectoryEl = byId("bootstrap_directory");
const inviteKeyEl = byId("invite_key");
const MAX_OUTPUT_CHARS = 64 * 1024;
const CONNECTION_DEFAULT_STATE = "Unknown";
const CONNECTION_DEFAULT_DETAIL = "Not checked yet";
const STORAGE_KEYS = Object.freeze({
  sessionToken: "gpm.desktop.session_token",
  role: "gpm.desktop.role",
  walletAddress: "gpm.desktop.wallet_address",
  walletProvider: "gpm.desktop.wallet_provider",
  chainOperatorId: "gpm.desktop.chain_operator_id",
  pathProfile: "gpm.desktop.path_profile"
});

const state = {
  sessionToken: "",
  role: "client",
  manifest: null,
  connectionState: CONNECTION_DEFAULT_STATE,
  connectionDetail: CONNECTION_DEFAULT_DETAIL
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
  const text = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
  if (text.length <= MAX_OUTPUT_CHARS) {
    return text;
  }
  const omitted = text.length - MAX_OUTPUT_CHARS;
  return `${text.slice(0, MAX_OUTPUT_CHARS)}\n...[TRUNCATED ${omitted} chars]`;
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

function firstDefined(...values) {
  for (const value of values) {
    if (value !== undefined && value !== null) {
      return value;
    }
  }
  return undefined;
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
  const raw = firstDefined(...candidates.map((key) => cfg[key]));
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
  const raw = firstDefined(...candidates.map((key) => cfg[key]));
  if (typeof raw === "string") {
    const value = raw.trim();
    if (value) {
      return value;
    }
  }
  return undefined;
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

  return {
    apiLine: timeout ? `${product} API: ${baseUrl} (timeout: ${timeout}s)` : `${product} API: ${baseUrl}`,
    hintLine: hints.join(" | "),
    updateMutationsEnabled: updateMutationsEnabled === true,
    serviceMutationsEnabled: serviceMutationsEnabled === true
  };
}

function setRole(role, options = {}) {
  const { persist = true } = options;
  const normalized = (role || "client").toLowerCase();
  state.role = normalized;
  currentRoleEl.value = normalized;
  if (persist) {
    writePersistedValue(STORAGE_KEYS.role, normalized);
  }
  const serverUnlocked = normalized === "operator" || normalized === "admin";
  tabServerEl.disabled = !serverUnlocked;
  tabServerEl.classList.toggle("locked", !serverUnlocked);
  panelServerEl.classList.toggle("locked", !serverUnlocked);
  if (!serverUnlocked && tabServerEl.classList.contains("active")) {
    activateTab("client");
  }
  serverLockHintEl.textContent = serverUnlocked
    ? "Server controls are unlocked for this role."
    : "Server controls are available only for approved operator/admin roles.";
}

function setSessionToken(value, options = {}) {
  const { persist = true } = options;
  state.sessionToken = (value || "").trim();
  sessionTokenEl.value = state.sessionToken;
  if (persist) {
    writePersistedValue(STORAGE_KEYS.sessionToken, state.sessionToken);
  }
}

function restorePersistedSessionErgonomics() {
  restoreSelectValue(walletProviderEl, readPersistedValue(STORAGE_KEYS.walletProvider));
  walletAddressEl.value = readPersistedValue(STORAGE_KEYS.walletAddress) || "";
  chainOperatorIdEl.value = readPersistedValue(STORAGE_KEYS.chainOperatorId) || "";
  restoreSelectValue(pathProfileEl, readPersistedValue(STORAGE_KEYS.pathProfile));
  setSessionToken(readPersistedValue(STORAGE_KEYS.sessionToken) || "", { persist: false });
  setRole(readPersistedValue(STORAGE_KEYS.role) || "client", { persist: false });
}

function requireSessionToken(actionLabel) {
  if (!state.sessionToken) {
    print("validation", `session_token is required to ${actionLabel}; sign in first`);
    return false;
  }
  return true;
}

function serviceLifecycleRequest() {
  return {
    session_token: state.sessionToken
  };
}

function setCompatOverrideEnabled(enabled) {
  const allow = !!enabled;
  compatEnableEl.checked = allow;
  bootstrapDirectoryEl.disabled = !allow;
  inviteKeyEl.disabled = !allow;
}

function activateTab(name) {
  const isClient = name === "client";
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

async function call(label, command, args = {}) {
  try {
    const result = await invoke(command, args);
    print(label, result);
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

  if (compatEnableEl.checked) {
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

async function refreshSession(action = "status") {
  if (!state.sessionToken) {
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
    return result;
  }
  setRole(parseSessionRole(result));
  return result;
}

async function refreshSessionOnInit() {
  if (!state.sessionToken) {
    return;
  }
  try {
    const result = await invoke("control_gpm_session", {
      request: { session_token: state.sessionToken, action: "status" }
    });
    setRole(parseSessionRole(result));
  } catch {
    // Startup status refresh is best-effort and should not block the scaffold.
  }
}

tabClientEl.addEventListener("click", () => activateTab("client"));
tabServerEl.addEventListener("click", () => {
  if (!tabServerEl.disabled) {
    activateTab("server");
  }
});
sessionTokenEl.addEventListener("input", () => {
  state.sessionToken = sessionTokenEl.value.trim();
  writePersistedValue(STORAGE_KEYS.sessionToken, state.sessionToken);
});
walletProviderEl.addEventListener("change", () => {
  writePersistedValue(STORAGE_KEYS.walletProvider, walletProviderEl.value);
});
walletAddressEl.addEventListener("input", () => {
  writePersistedValue(STORAGE_KEYS.walletAddress, walletAddressEl.value);
});
chainOperatorIdEl.addEventListener("input", () => {
  writePersistedValue(STORAGE_KEYS.chainOperatorId, chainOperatorIdEl.value);
});
pathProfileEl.addEventListener("change", () => {
  writePersistedValue(STORAGE_KEYS.pathProfile, pathProfileEl.value);
});

byId("challenge_btn").addEventListener("click", async () => {
  const wallet_address = walletAddressEl.value.trim();
  const wallet_provider = walletProviderEl.value;
  const result = await call("gpm_auth_challenge", "control_gpm_auth_challenge", {
    request: { wallet_address, wallet_provider }
  });
  if (result?.challenge_id) {
    byId("challenge_id").value = result.challenge_id;
  }
});

byId("signin_btn").addEventListener("click", async () => {
  const request = {
    wallet_address: walletAddressEl.value.trim(),
    wallet_provider: walletProviderEl.value,
    challenge_id: byId("challenge_id").value.trim(),
    signature: byId("wallet_signature").value.trim()
  };
  const result = await call("gpm_auth_verify", "control_gpm_auth_verify", { request });
  setSessionToken(result?.session_token || "");
  setRole(parseSessionRole(result));
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
  await call("gpm_audit_recent", "control_gpm_audit_recent", { limit: 25 });
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
  if (compatEnableEl.checked) {
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
  setRole(parseSessionRole(result));
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
});

byId("operator_status_btn").addEventListener("click", async () => {
  const request = {
    session_token: state.sessionToken || undefined,
    wallet_address: walletAddressEl.value.trim() || undefined
  };
  await call("gpm_operator_status", "control_gpm_operator_status", { request });
});

byId("approve_operator_btn").addEventListener("click", async () => {
  const request = {
    wallet_address: walletAddressEl.value.trim(),
    approved: true
  };
  await call("gpm_operator_approve", "control_gpm_operator_approve", { request });
  await refreshSession();
});

byId("connect_btn").addEventListener("click", async () => {
  const request = connectPayload();
  if (!request.session_token && (!request.bootstrap_directory || !request.invite_key)) {
    print("validation", "sign in + register client, or provide compatibility bootstrap_directory + invite");
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
  setCompatOverrideEnabled(false);
  applyConnectionSnapshot({
    state: CONNECTION_DEFAULT_STATE,
    detail: CONNECTION_DEFAULT_DETAIL
  });
  try {
    const cfg = await invoke("control_config");
    const meta = formatConfigMeta(cfg || {});
    apiBaseEl.textContent = meta.apiLine;
    apiHintsEl.textContent = meta.hintLine;
    updateBtnEl.disabled = !meta.updateMutationsEnabled;
    serviceStartBtnEl.disabled = !meta.serviceMutationsEnabled;
    serviceStopBtnEl.disabled = !meta.serviceMutationsEnabled;
    serviceRestartBtnEl.disabled = !meta.serviceMutationsEnabled;
  } catch (err) {
    apiBaseEl.textContent = "API: unavailable";
    apiHintsEl.textContent = "";
    updateBtnEl.disabled = true;
    serviceStartBtnEl.disabled = true;
    serviceStopBtnEl.disabled = true;
    serviceRestartBtnEl.disabled = true;
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
