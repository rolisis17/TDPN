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
const clientReadinessEl = byId("client_readiness");
const clientReadinessLineEl = byId("client_readiness_line");
const clientReadinessStatusEl = byId("client_readiness_status");
const clientReadinessGuidanceEl = byId("client_readiness_guidance");
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
const inviteKeyEl = byId("invite_key");
const registerClientBtnEl = byId("register_client_btn");
const onboardingStepSigninEl = document.getElementById("onboarding_step_signin");
const onboardingStepClientEl = document.getElementById("onboarding_step_client");
const onboardingStepOperatorEl = document.getElementById("onboarding_step_operator");
const actionButtons = Array.from(document.querySelectorAll(".actions button"));
const OPERATOR_APPLICATION_STATUSES = new Set(["not_submitted", "pending", "approved", "rejected"]);
const SERVER_ONLY_ROLES = new Set(["server", "server_only"]);
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
const PORTAL_STORAGE_KEY = "gpm.portal.state.v1";
const PERSISTED_FIELD_IDS = [
  "api_base",
  "session_token",
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
  "bootstrap_directory"
];
let operatorApplicationStatus = undefined;
let selectedApplicationUpdatedAtUtc = "";
let serverReadiness = null;
let clientRegistered = false;
let connectRequireSession = false;
let allowLegacyConnectOverride = false;
let operatorListActiveFilters = {
  status: "",
  search: "",
  limit: OPERATOR_LIST_ALL_LIMIT
};
let operatorListNextCursor = "";
let walletSignatureContext = null;

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

function parseConnectRequireSessionConfig(payload) {
  const parsed = parseBooleanLike(
    firstDefined(
      payload?.config?.connect_require_session,
      payload?.connect_require_session,
      payload?.config?.connectRequireSession,
      payload?.connectRequireSession
    )
  );
  return parsed === true;
}

function parseAllowLegacyConnectOverrideConfig(payload) {
  const parsed = parseBooleanLike(
    firstDefined(
      payload?.config?.allow_legacy_connect_override,
      payload?.allow_legacy_connect_override,
      payload?.config?.allowLegacyConnectOverride,
      payload?.allowLegacyConnectOverride
    )
  );
  return parsed === true;
}

function compatibilityOverrideEnabled() {
  return allowLegacyConnectOverride === true && compatOverrideEl.checked === true && connectRequireSession !== true;
}

function refreshCompatibilityOverrideControls() {
  if (!allowLegacyConnectOverride && compatOverrideEl.checked) {
    compatOverrideEl.checked = false;
  }
  if (connectRequireSession && compatOverrideEl.checked) {
    compatOverrideEl.checked = false;
  }
  const policyLocked = connectRequireSession === true;
  const overrideEnabled = compatibilityOverrideEnabled();

  const compatDisabled = !allowLegacyConnectOverride || policyLocked;
  compatOverrideEl.disabled = compatDisabled;
  compatOverrideEl.setAttribute("aria-disabled", String(compatDisabled));

  bootstrapDirectoryEl.disabled = !allowLegacyConnectOverride || !overrideEnabled;
  bootstrapDirectoryEl.setAttribute("aria-disabled", String(!overrideEnabled));
  inviteKeyEl.disabled = !allowLegacyConnectOverride || !overrideEnabled;
  inviteKeyEl.setAttribute("aria-disabled", String(!overrideEnabled));

  if (compatOverrideSectionEl) {
    compatOverrideSectionEl.hidden = !allowLegacyConnectOverride;
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
    refreshCompatibilityOverrideControls();
    persistPortalState();
    return config;
  } catch (err) {
    connectRequireSession = false;
    allowLegacyConnectOverride = false;
    refreshCompatibilityOverrideControls();
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

function appendSessionReconciledDetail(detail, hintSource) {
  const hint = formatSessionReconciledHint(hintSource);
  if (!hint) {
    return detail;
  }
  return `${detail} session_reconciled=${hint}.`;
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
    setStepState(onboardingStepOperatorEl, "blocked");
    return;
  }

  if (clientReadiness.state === "registered") {
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

function syncClientRegistrationAction(readiness) {
  if (!registerClientBtnEl) {
    return;
  }
  const isBusy = document.body.classList.contains("is-busy");
  const lockByState = readiness.state === "role_locked" || readiness.state === "not_signed_in";
  const disabled = isBusy || lockByState;
  registerClientBtnEl.disabled = disabled;
  registerClientBtnEl.setAttribute("aria-disabled", String(disabled));
  if (lockByState) {
    registerClientBtnEl.title = readiness.guidanceText;
    return;
  }
  registerClientBtnEl.removeAttribute("title");
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
      guidanceText: "Sign in first to unlock operator onboarding."
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
    return {
      kind:
        serverReadiness.operatorApplicationStatus === "rejected" || serverReadiness.tabVisible === false
          ? "bad"
          : "warn",
      statusText: statusLabel,
      guidanceText: appendChainBindingGuidance(`${reason}${nextActions}`, serverReadiness)
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
  refreshClientReadiness();
}

function refreshClientReadiness() {
  const readiness = computeClientReadiness();
  setClientReadiness(readiness.kind, readiness.statusText, readiness.guidanceText, readiness.state);
  syncClientRegistrationAction(readiness);
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
    setSelectedApplicationUpdatedAt("");
    clientRegistered = false;
    setOperatorListNextCursor("");
  });
  byId("wallet_address").addEventListener("input", () => {
    setSelectedApplicationUpdatedAt("");
  });
  byId("chain_operator_id").addEventListener("input", () => {
    setSelectedApplicationUpdatedAt("");
  });
}

function bindCompatibilityOverrideListeners() {
  compatOverrideEl.addEventListener("change", () => {
    refreshCompatibilityOverrideControls();
  });
  byId("api_base").addEventListener("change", () => {
    void refreshConnectPolicyConfigBestEffort({ quiet: true });
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

function createApiError(response, json) {
  const message =
    (typeof json?.error === "string" && json.error.trim()) || `${response.status} ${response.statusText}`;
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
    throw createApiError(response, json);
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

async function requestAuthVerify() {
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
  return result;
}

async function requestWalletSignIn() {
  await signChallengeWithWalletExtension();
  return requestAuthVerify();
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
  const role = sessionRoleFromResult(payload);
  if (typeof role === "string" && role.trim()) {
    byId("role").value = role;
  }
  const registrationStatus = parseClientRegistrationStatus(payload);
  if (registrationStatus !== undefined) {
    clientRegistered = registrationStatus;
  }
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
    const status = parseClientRegistrationStatus(result);
    if (status !== undefined) {
      clientRegistered = status;
    }
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
    const outputPayload = withSessionReconciledHint(outputMapper ? outputMapper(result) : result, result);
    print(label, outputPayload);
    const detail = appendSessionReconciledDetail(
      successDetail ? successDetail(result) : "The request finished successfully.",
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
    setSelectedApplicationUpdatedAt("");
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
    setSelectedApplicationUpdatedAt("");
    setServerReadiness(null);
    persistPortalState();
    return result;
  })
);

byId("manifest_btn").addEventListener("click", () =>
  run("bootstrap_manifest", async () => get("/v1/gpm/bootstrap/manifest"))
);

byId("audit_recent_btn").addEventListener("click", () =>
  run("audit_recent", requestAuditRecent, {
    outputMapper: (result) => result.summary.output,
    successDetail: (result) => result.summary.detail
  })
);

byId("register_client_btn").addEventListener("click", () =>
  run("client_register", async () => {
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
      const request = {
        wallet_address: byId("wallet_address").value.trim(),
        approved: true,
        session_token: byId("session_token").value.trim() || undefined
      };
      const ifUpdatedAtUtc = selectedApplicationUpdatedAt();
      if (ifUpdatedAtUtc) {
        request.if_updated_at_utc = ifUpdatedAtUtc;
      }
      const adminToken = byId("admin_token").value.trim();
      if (adminToken) {
        request.admin_token = adminToken;
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
      const sessionToken = byId("session_token").value.trim();
      if (!sessionToken) {
        throw new Error("session_token is required to reject an operator. Sign in first.");
      }
      const reason = operatorModerationReason();
      if (!reason) {
        throw new Error("moderation reason is required to reject an operator.");
      }
      const request = {
        wallet_address: byId("wallet_address").value.trim(),
        approved: false,
        reason,
        session_token: sessionToken
      };
      const ifUpdatedAtUtc = selectedApplicationUpdatedAt();
      if (ifUpdatedAtUtc) {
        request.if_updated_at_utc = ifUpdatedAtUtc;
      }
      const adminToken = byId("admin_token").value.trim();
      if (adminToken) {
        request.admin_token = adminToken;
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

async function restoreSessionStatusBestEffort() {
  const token = byId("session_token").value.trim();
  if (!token) {
    setServerReadiness(null);
    setOperatorApplicationStatus(undefined);
    setSelectedApplicationUpdatedAt("");
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
  refreshCompatibilityOverrideControls();
  setSelectedApplicationUpdatedAt(selectedApplicationUpdatedAtEl.value, { persist: false });
  operatorListActiveFilters = readOperatorListFilters({ fallbackLimit: OPERATOR_LIST_ALL_LIMIT });
  writeOperatorListFilters(operatorListActiveFilters);
  setOperatorListNextCursor("");
  bindPersistenceListeners();
  bindCompatibilityOverrideListeners();
  bindReadinessListeners();
  bindOperatorListFilterListeners();
  persistPortalState();
  refreshOperatorReadiness();
  setStatus("good", "Portal ready", "Set an absolute API base, then start with a challenge or session refresh.");
  void refreshConnectPolicyConfigBestEffort({ quiet: true });
  void restoreSessionStatusBestEffort();
}

initializePortal();
