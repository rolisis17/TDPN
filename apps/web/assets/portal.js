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
const operatorReadinessEl = byId("operator_readiness");
const operatorReadinessLineEl = byId("operator_readiness_line");
const operatorReadinessStatusEl = byId("operator_readiness_status");
const operatorReadinessGuidanceEl = byId("operator_readiness_guidance");
const actionButtons = Array.from(document.querySelectorAll(".actions button"));
const OPERATOR_APPLICATION_STATUSES = new Set(["not_submitted", "pending", "approved", "rejected"]);
const PORTAL_STORAGE_KEY = "gpm.portal.state.v1";
const PERSISTED_FIELD_IDS = [
  "api_base",
  "session_token",
  "role",
  "wallet_address",
  "wallet_provider",
  "chain_operator_id",
  "server_label",
  "path_profile",
  "bootstrap_directory"
];
let operatorApplicationStatus = undefined;

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

function isServerRoleUnlocked(roleValue) {
  const role = String(roleValue || "").trim().toLowerCase();
  return role === "operator" || role === "admin";
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

function setOperatorReadiness(kind, statusText, guidanceText) {
  operatorReadinessEl.dataset.kind = kind || "warn";
  operatorReadinessLineEl.classList.remove("good", "warn", "bad");
  if (kind) {
    operatorReadinessLineEl.classList.add(kind);
  }
  operatorReadinessStatusEl.textContent = statusText;
  operatorReadinessGuidanceEl.textContent = guidanceText;
}

function computeOperatorReadiness() {
  const token = byId("session_token").value.trim();
  const role = byId("role").value.trim().toLowerCase() || "client";
  const statusLabel = formatOperatorApplicationStatusLabel(operatorApplicationStatus);

  if (!token) {
    return {
      kind: "warn",
      statusText: "Not signed in",
      guidanceText: "Sign in first to unlock operator onboarding."
    };
  }

  if (isServerRoleUnlocked(role)) {
    return {
      kind: "good",
      statusText: statusLabel,
      guidanceText: "Server controls are eligible for this session role."
    };
  }

  switch (operatorApplicationStatus) {
    case "not_submitted":
      return {
        kind: "warn",
        statusText: statusLabel,
        guidanceText: "Apply operator role to start server approval."
      };
    case "pending":
      return {
        kind: "warn",
        statusText: statusLabel,
        guidanceText: "Operator application is pending approval."
      };
    case "rejected":
      return {
        kind: "bad",
        statusText: statusLabel,
        guidanceText: "Operator application was rejected. Re-apply or contact an admin."
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
}

function setOperatorApplicationStatus(value) {
  operatorApplicationStatus = normalizeOperatorApplicationStatus(value);
  refreshOperatorReadiness();
}

function bindReadinessListeners() {
  byId("session_token").addEventListener("input", () => {
    setOperatorApplicationStatus(undefined);
  });
}

function setBusy(isBusy) {
  document.body.classList.toggle("is-busy", isBusy);
  for (const button of actionButtons) {
    button.disabled = isBusy;
    button.setAttribute("aria-disabled", String(isBusy));
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
  const text = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
  outputEl.textContent = `[${new Date().toISOString()}] ${label}\n${text}`;
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
  const pathname = parsed.pathname.replace(/\/+$/, "");
  return pathname && pathname !== "/" ? `${parsed.origin}${pathname}` : parsed.origin;
}

async function post(path, body) {
  const token = byId("session_token").value.trim();
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
    throw new Error(json.error || `${response.status} ${response.statusText}`);
  }
  return json;
}

async function get(path) {
  const token = byId("session_token").value.trim();
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
    throw new Error(json.error || `${response.status} ${response.statusText}`);
  }
  return json;
}

function applySession(result) {
  const token = result.session_token || byId("session_token").value.trim();
  byId("session_token").value = token;
  const role = result.session?.role || result.role || result.profile?.role || "client";
  byId("role").value = role;
  refreshOperatorReadiness();
  persistPortalState();
}

function readWalletPayload() {
  return {
    wallet_address: byId("wallet_address").value.trim(),
    wallet_provider: byId("wallet_provider").value
  };
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

async function refreshOperatorApplicationStatus(options = {}) {
  const { quiet = true } = options;
  if (!byId("session_token").value.trim()) {
    setOperatorApplicationStatus(undefined);
    return undefined;
  }
  try {
    const result = await requestOperatorStatus();
    setOperatorApplicationStatus(parseOperatorApplicationStatus(result));
    return result;
  } catch (err) {
    if (!quiet) {
      throw err;
    }
    return undefined;
  }
}

async function run(label, fn) {
  setBusy(true);
  setStatus("warn", `${label} in progress`, "Please wait while the portal completes the request.");
  try {
    const result = await fn();
    print(label, result);
    setStatus("good", `${label} completed`, "The request finished successfully.");
  } catch (err) {
    print(`${label} (error)`, String(err && err.message ? err.message : err));
    setStatus("bad", `${label} failed`, String(err && err.message ? err.message : err));
  } finally {
    setBusy(false);
  }
}

byId("challenge_btn").addEventListener("click", () =>
  run("auth_challenge", async () => {
    const result = await post("/v1/gpm/auth/challenge", readWalletPayload());
    if (result.challenge_id) {
      byId("challenge_id").value = result.challenge_id;
    }
    return result;
  })
);

byId("signin_btn").addEventListener("click", () =>
  run("auth_verify", async () => {
    const request = {
      ...readWalletPayload(),
      challenge_id: byId("challenge_id").value.trim(),
      signature: byId("signature").value.trim()
    };
    const result = await post("/v1/gpm/auth/verify", request);
    setOperatorApplicationStatus(undefined);
    applySession(result);
    await refreshOperatorApplicationStatus({ quiet: true });
    return result;
  })
);

byId("session_btn").addEventListener("click", () =>
  run("session_status", async () => {
    const result = await requestSessionLifecycle("status");
    byId("role").value = sessionRoleFromResult(result);
    refreshOperatorReadiness();
    await refreshOperatorApplicationStatus({ quiet: true });
    persistPortalState();
    return result;
  })
);

byId("session_rotate_btn").addEventListener("click", () =>
  run("session_rotate", async () => {
    const result = await requestSessionLifecycle("refresh");
    if (result.session_token) {
      byId("session_token").value = result.session_token;
    }
    byId("role").value = sessionRoleFromResult(result);
    setOperatorApplicationStatus(undefined);
    await refreshOperatorApplicationStatus({ quiet: true });
    persistPortalState();
    return result;
  })
);

byId("session_revoke_btn").addEventListener("click", () =>
  run("session_revoke", async () => {
    const result = await requestSessionLifecycle("revoke");
    byId("session_token").value = "";
    byId("role").value = "client";
    setOperatorApplicationStatus(undefined);
    persistPortalState();
    return result;
  })
);

byId("manifest_btn").addEventListener("click", () =>
  run("bootstrap_manifest", async () => get("/v1/gpm/bootstrap/manifest"))
);

byId("audit_recent_btn").addEventListener("click", () =>
  run("audit_recent", async () => get("/v1/gpm/audit/recent?limit=25"))
);

byId("register_client_btn").addEventListener("click", () =>
  run("client_register", async () => {
    const request = {
      session_token: byId("session_token").value.trim(),
      path_profile: byId("path_profile").value
    };
    const bootstrap = byId("bootstrap_directory").value.trim();
    const invite = byId("invite_key").value.trim();
    if (bootstrap) {
      request.bootstrap_directory = bootstrap;
    }
    if (invite) {
      request.invite_key = invite;
    }
    const result = await post("/v1/gpm/onboarding/client/register", request);
    applySession(result);
    return result;
  })
);

byId("apply_operator_btn").addEventListener("click", () =>
  run("operator_apply", async () => {
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
    return result;
  })
);

byId("operator_status_btn").addEventListener("click", () =>
  run("operator_status", async () => {
    const result = await requestOperatorStatus();
    setOperatorApplicationStatus(parseOperatorApplicationStatus(result));
    return result;
  })
);

byId("approve_operator_btn").addEventListener("click", () =>
  run("operator_approve", async () => {
    const request = {
      wallet_address: byId("wallet_address").value.trim(),
      approved: true
    };
    const adminToken = byId("admin_token").value.trim();
    if (adminToken) {
      request.admin_token = adminToken;
    }
    const result = await post("/v1/gpm/onboarding/operator/approve", request);
    await refreshOperatorApplicationStatus({ quiet: true });
    return result;
  })
);

async function restoreSessionStatusBestEffort() {
  const token = byId("session_token").value.trim();
  if (!token) {
    setOperatorApplicationStatus(undefined);
    return;
  }
  setStatus("warn", "Restoring session", "Checking stored session token status.");
  try {
    const result = await requestSessionLifecycle("status");
    byId("role").value = sessionRoleFromResult(result);
    refreshOperatorReadiness();
    persistPortalState();
    print("session_status (auto)", result);
    setStatus("good", "Session restored", "Stored session token is active.");
  } catch (err) {
    print("session_status (auto, non-fatal)", String(err && err.message ? err.message : err));
    setStatus("warn", "Session check skipped", "Stored session token could not be validated. You can refresh or sign in again.");
  }
  await refreshOperatorApplicationStatus({ quiet: true });
}

function initializePortal() {
  restorePortalState();
  bindPersistenceListeners();
  bindReadinessListeners();
  persistPortalState();
  refreshOperatorReadiness();
  setStatus("good", "Portal ready", "Set an absolute API base, then start with a challenge or session refresh.");
  void restoreSessionStatusBestEffort();
}

initializePortal();
