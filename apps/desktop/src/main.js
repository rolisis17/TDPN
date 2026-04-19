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
const serverLockHintEl = byId("server_lock_hint");

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

const state = {
  sessionToken: "",
  role: "client",
  manifest: null
};

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

function setRole(role) {
  const normalized = (role || "client").toLowerCase();
  state.role = normalized;
  currentRoleEl.value = normalized;
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

function setSessionToken(value) {
  state.sessionToken = (value || "").trim();
  sessionTokenEl.value = state.sessionToken;
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
    path_profile: byId("path_profile").value,
    policy_profile: byId("path_profile").value,
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

async function refreshSession() {
  if (!state.sessionToken) {
    return;
  }
  const result = await call("gpm_session", "control_gpm_session", {
    request: { session_token: state.sessionToken }
  });
  setRole(parseSessionRole(result));
}

tabClientEl.addEventListener("click", () => activateTab("client"));
tabServerEl.addEventListener("click", () => {
  if (!tabServerEl.disabled) {
    activateTab("server");
  }
});

byId("challenge_btn").addEventListener("click", async () => {
  const wallet_address = byId("wallet_address").value.trim();
  const wallet_provider = byId("wallet_provider").value;
  const result = await call("gpm_auth_challenge", "control_gpm_auth_challenge", {
    request: { wallet_address, wallet_provider }
  });
  if (result?.challenge_id) {
    byId("challenge_id").value = result.challenge_id;
  }
});

byId("signin_btn").addEventListener("click", async () => {
  const request = {
    wallet_address: byId("wallet_address").value.trim(),
    wallet_provider: byId("wallet_provider").value,
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
    path_profile: byId("path_profile").value
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
    chain_operator_id: byId("chain_operator_id").value.trim(),
    server_label: "desktop-operator"
  };
  await call("gpm_operator_apply", "control_gpm_operator_apply", { request });
});

byId("operator_status_btn").addEventListener("click", async () => {
  const request = {
    session_token: state.sessionToken || undefined,
    wallet_address: byId("wallet_address").value.trim() || undefined
  };
  await call("gpm_operator_status", "control_gpm_operator_status", { request });
});

byId("approve_operator_btn").addEventListener("click", async () => {
  const request = {
    wallet_address: byId("wallet_address").value.trim(),
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
  await call("connect", "control_connect", { request });
});

compatEnableEl.addEventListener("change", () => {
  setCompatOverrideEnabled(compatEnableEl.checked);
  if (!compatEnableEl.checked) {
    bootstrapDirectoryEl.value = "";
    inviteKeyEl.value = "";
  }
});

byId("disconnect_btn").addEventListener("click", async () => {
  await call("disconnect", "control_disconnect");
});

byId("status_btn").addEventListener("click", async () => {
  await call("status", "control_status");
});

byId("status_btn_server").addEventListener("click", async () => {
  await call("status_server", "control_status");
});

byId("diagnostics_btn").addEventListener("click", async () => {
  await call("diagnostics", "control_get_diagnostics");
});

byId("health_btn").addEventListener("click", async () => {
  await call("health", "control_health");
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
  setRole("client");
  activateTab("client");
  setCompatOverrideEnabled(false);
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
}

init();
