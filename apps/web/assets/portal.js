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
const onboardingStepSigninEl = document.getElementById("onboarding_step_signin");
const onboardingStepClientEl = document.getElementById("onboarding_step_client");
const onboardingStepOperatorEl = document.getElementById("onboarding_step_operator");
const actionButtons = Array.from(document.querySelectorAll(".actions button"));
const OPERATOR_APPLICATION_STATUSES = new Set(["not_submitted", "pending", "approved", "rejected"]);
const OPERATOR_PENDING_LIST_LIMIT = 25;
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
let serverReadiness = null;
let clientRegistered = false;

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

function firstDefined(...values) {
  for (const value of values) {
    if (value !== undefined && value !== null) {
      return value;
    }
  }
  return undefined;
}

function nonEmptyString(value) {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed || undefined;
}

function numberOrUndefined(value) {
  const parsed = Number(value);
  if (Number.isFinite(parsed) && parsed >= 0) {
    return parsed;
  }
  return undefined;
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

function summarizeOperatorList(payload, fallbackStatus = "pending", fallbackLimit = OPERATOR_PENDING_LIST_LIMIT) {
  const entries = extractOperatorListEntries(payload);
  const status =
    nonEmptyString(
      firstDefined(
        payload?.status,
        payload?.filter?.status,
        payload?.request?.status,
        payload?.meta?.status
      )
    ) || fallbackStatus;
  const limit =
    numberOrUndefined(
      firstDefined(payload?.limit, payload?.request?.limit, payload?.meta?.limit, payload?.pagination?.limit)
    ) ?? fallbackLimit;
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
  const sample = entries.slice(0, 3).map(formatOperatorListItemLabel);
  const detailParts = [`status=${status}`, `returned=${entries.length}`, `limit=${limit}`, `total=${total}`];
  if (sample.length > 0) {
    detailParts.push(`sample=${sample.join(", ")}`);
  }
  return {
    detail: `Operator queue: ${detailParts.join(" | ")}`,
    output: {
      status,
      returned: entries.length,
      limit,
      total,
      sample
    }
  };
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
  const lockReason = typeof readiness.lock_reason === "string" ? readiness.lock_reason.trim() : "";
  return {
    role: role || undefined,
    tabVisible: parseBooleanLike(readiness.tab_visible),
    lifecycleActionsUnlocked: parseBooleanLike(readiness.lifecycle_actions_unlocked),
    serviceMutationsConfigured: parseBooleanLike(readiness.service_mutations_configured),
    operatorApplicationStatus: normalizeOperatorApplicationStatus(readiness.operator_application_status),
    lockReason: lockReason || undefined,
    unlockActions
  };
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
  const token = byId("session_token").value.trim();
  const role = (serverReadiness?.role || byId("role").value).trim().toLowerCase();
  const backendOperatorStatus = serverReadiness?.operatorApplicationStatus || operatorApplicationStatus;
  const hasSession = token.length > 0;
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
  if (!clientRegistered) {
    setStepState(onboardingStepClientEl, "active");
    setStepState(onboardingStepOperatorEl, "blocked");
    return;
  }

  setStepState(onboardingStepClientEl, "done");
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

function syncSessionDerivedState(result) {
  const session = result && result.session ? result.session : {};
  const bootstrapDirectory = typeof session.bootstrap_directory === "string" ? session.bootstrap_directory.trim() : "";
  const profileBootstrap =
    result && result.profile && typeof result.profile.bootstrap_directory === "string"
      ? result.profile.bootstrap_directory.trim()
      : "";
  clientRegistered = bootstrapDirectory.length > 0 || profileBootstrap.length > 0;
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
  const role = (serverReadiness?.role || byId("role").value).trim().toLowerCase() || "client";
  const statusLabel = formatOperatorApplicationStatusLabel(
    serverReadiness?.operatorApplicationStatus || operatorApplicationStatus
  );

  if (!token && !serverReadiness) {
    return {
      kind: "warn",
      statusText: "Not signed in",
      guidanceText: "Sign in first to unlock operator onboarding."
    };
  }

  if (serverReadiness) {
    if (serverReadiness.lifecycleActionsUnlocked === true) {
      if (serverReadiness.serviceMutationsConfigured === false) {
        return {
          kind: "warn",
          statusText: statusLabel,
          guidanceText: "Server role is eligible, but lifecycle commands are not configured on the daemon."
        };
      }
      return {
        kind: "good",
        statusText: statusLabel,
        guidanceText: "Server controls are unlocked by backend readiness policy."
      };
    }
    const reason = serverReadiness.lockReason || "Server lifecycle actions are locked by backend readiness policy.";
    const nextActions = serverReadiness.unlockActions.length > 0 ? ` Next: ${serverReadiness.unlockActions.join("; ")}` : "";
    return {
      kind:
        serverReadiness.operatorApplicationStatus === "rejected" || serverReadiness.tabVisible === false
          ? "bad"
          : "warn",
      statusText: statusLabel,
      guidanceText: `${reason}${nextActions}`
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
          guidanceText: "Operator application is approved. Server controls are eligible for this session role."
        };
      case "rejected":
        return {
          kind: "bad",
          statusText: statusLabel,
          guidanceText: "Operator role is not fully eligible. Check operator status, then refresh or rotate session after re-approval."
        };
      case "pending":
        return {
          kind: "warn",
          statusText: statusLabel,
          guidanceText: "Operator role is not fully eligible yet. Check operator status and refresh or rotate session after approval."
        };
      case "not_submitted":
        return {
          kind: "warn",
          statusText: statusLabel,
          guidanceText: "Operator role is not fully eligible yet. Submit operator application, then refresh or rotate session after approval."
        };
      default:
        return {
          kind: "warn",
          statusText: statusLabel,
          guidanceText: "Operator role is not fully eligible yet. Check operator status and refresh or rotate session."
        };
    }
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
  refreshOnboardingSteps();
}

function setOperatorApplicationStatus(value) {
  operatorApplicationStatus = normalizeOperatorApplicationStatus(value);
  refreshOperatorReadiness();
}

function bindReadinessListeners() {
  byId("session_token").addEventListener("input", () => {
    setServerReadiness(null);
    setOperatorApplicationStatus(undefined);
    clientRegistered = false;
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
  syncSessionDerivedState(result);
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

async function requestClientStatus() {
  const request = {
    session_token: byId("session_token").value.trim() || undefined,
    wallet_address: byId("wallet_address").value.trim() || undefined
  };
  return post("/v1/gpm/onboarding/client/status", request);
}

async function requestServerStatus() {
  const request = {
    session_token: byId("session_token").value.trim() || undefined,
    wallet_address: byId("wallet_address").value.trim() || undefined
  };
  return post("/v1/gpm/onboarding/server/status", request);
}

async function refreshClientRegistrationStatus(options = {}) {
  const { quiet = true } = options;
  if (!byId("session_token").value.trim()) {
    clientRegistered = false;
    refreshOnboardingSteps();
    return undefined;
  }
  try {
    const result = await requestClientStatus();
    const status = parseClientRegistrationStatus(result);
    if (status !== undefined) {
      clientRegistered = status;
    }
    refreshOnboardingSteps();
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
  setBusy(true);
  setStatus("warn", `${label} in progress`, "Please wait while the portal completes the request.");
  try {
    const result = await fn();
    const outputPayload = outputMapper ? outputMapper(result) : result;
    print(label, outputPayload);
    const detail = successDetail ? successDetail(result) : "The request finished successfully.";
    setStatus("good", `${label} completed`, detail);
    return result;
  } catch (err) {
    print(`${label} (error)`, String(err && err.message ? err.message : err));
    setStatus("bad", `${label} failed`, String(err && err.message ? err.message : err));
    return undefined;
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
    await refreshClientRegistrationStatus({ quiet: true });
    await refreshOperatorApplicationStatus({ quiet: true });
    await refreshServerReadinessStatus({ quiet: true });
    return result;
  })
);

byId("session_btn").addEventListener("click", () =>
  run("session_status", async () => {
    const result = await requestSessionLifecycle("status");
    syncSessionDerivedState(result);
    byId("role").value = sessionRoleFromResult(result);
    refreshOperatorReadiness();
    await refreshClientRegistrationStatus({ quiet: true });
    await refreshOperatorApplicationStatus({ quiet: true });
    await refreshServerReadinessStatus({ quiet: true });
    persistPortalState();
    return result;
  })
);

byId("session_rotate_btn").addEventListener("click", () =>
  run("session_rotate", async () => {
    const result = await requestSessionLifecycle("refresh");
    syncSessionDerivedState(result);
    if (result.session_token) {
      byId("session_token").value = result.session_token;
    }
    byId("role").value = sessionRoleFromResult(result);
    setOperatorApplicationStatus(undefined);
    await refreshClientRegistrationStatus({ quiet: true });
    await refreshOperatorApplicationStatus({ quiet: true });
    await refreshServerReadinessStatus({ quiet: true });
    persistPortalState();
    return result;
  })
);

byId("session_revoke_btn").addEventListener("click", () =>
  run("session_revoke", async () => {
    const result = await requestSessionLifecycle("revoke");
    clientRegistered = false;
    byId("session_token").value = "";
    byId("role").value = "client";
    setOperatorApplicationStatus(undefined);
    setServerReadiness(null);
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
    await refreshClientRegistrationStatus({ quiet: true });
    await refreshServerReadinessStatus({ quiet: true });
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
    await refreshServerReadinessStatus({ quiet: true });
    return result;
  })
);

byId("operator_status_btn").addEventListener("click", () =>
  run("operator_status", async () => {
    const result = await requestOperatorStatus();
    setOperatorApplicationStatus(parseOperatorApplicationStatus(result));
    await refreshServerReadinessStatus({ quiet: true });
    return result;
  })
);

byId("operator_list_pending_btn").addEventListener("click", () =>
  run(
    "operator_list_pending",
    async () => {
      const sessionToken = byId("session_token").value.trim();
      if (!sessionToken) {
        throw new Error("session_token is required to list pending operators. Sign in first.");
      }
      return post("/v1/gpm/onboarding/operator/list", {
        session_token: sessionToken,
        status: "pending",
        limit: OPERATOR_PENDING_LIST_LIMIT
      });
    },
    {
      outputMapper: (result) => summarizeOperatorList(result).output,
      successDetail: (result) => summarizeOperatorList(result).detail
    }
  )
);

byId("approve_operator_btn").addEventListener("click", () =>
  run("operator_approve", async () => {
    const request = {
      wallet_address: byId("wallet_address").value.trim(),
      approved: true,
      session_token: byId("session_token").value.trim() || undefined
    };
    const adminToken = byId("admin_token").value.trim();
    if (adminToken) {
      request.admin_token = adminToken;
    }
    const result = await post("/v1/gpm/onboarding/operator/approve", request);
    await refreshOperatorApplicationStatus({ quiet: true });
    await refreshServerReadinessStatus({ quiet: true });
    return result;
  })
);

async function restoreSessionStatusBestEffort() {
  const token = byId("session_token").value.trim();
  if (!token) {
    setServerReadiness(null);
    setOperatorApplicationStatus(undefined);
    return;
  }
  setStatus("warn", "Restoring session", "Checking stored session token status.");
  try {
    const result = await requestSessionLifecycle("status");
    syncSessionDerivedState(result);
    byId("role").value = sessionRoleFromResult(result);
    refreshOperatorReadiness();
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
