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

function print(label, payload) {
  const text = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
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

  const authConfigured = readConfigBoolean(cfg, [
    "auth_bearer_configured",
    "auth_configured",
    "authConfigured",
    "api_auth_configured",
    "hardening_auth_configured"
  ]);
  const remoteAllowed = readConfigBoolean(cfg, [
    "remote_allowed",
    "remoteAllowed",
    "allow_remote",
    "hardening_remote_allowed"
  ]);
  const updateChannel = readConfigString(cfg, [
    "update_channel",
    "updateChannel",
    "channel",
    "release_channel"
  ]);
  const updateFeedUrl = readConfigString(cfg, [
    "update_feed_url",
    "updateFeedUrl",
    "feed_url",
    "update_url"
  ]);

  const hints = [];
  if (authConfigured !== undefined) {
    hints.push(authConfigured ? "auth configured" : "auth not configured");
  }
  if (remoteAllowed !== undefined) {
    hints.push(remoteAllowed ? "remote allowed" : "remote local-only");
  }
  if (updateChannel) {
    hints.push(`channel: ${updateChannel}`);
  }
  if (updateFeedUrl) {
    hints.push(`feed: ${updateFeedUrl}`);
  }

  return {
    apiLine: timeout ? `API: ${baseUrl} (timeout: ${timeout}s)` : `API: ${baseUrl}`,
    hintLine: hints.length ? `Hardening/Update: ${hints.join(" · ")}` : ""
  };
}

function readConnectPayload() {
  return {
    bootstrap_directory: byId("bootstrap_directory").value.trim(),
    invite_key: byId("invite_key").value.trim(),
    path_profile: byId("path_profile").value,
    interface: byId("interface").value.trim() || undefined,
    discovery_wait_sec: numberOrUndefined(byId("discovery_wait_sec").value),
    ready_timeout_sec: numberOrUndefined(byId("ready_timeout_sec").value),
    run_preflight: byId("run_preflight").checked,
    prod_profile: byId("prod_profile").checked,
    install_route: byId("install_route").checked
  };
}

async function call(label, command, args = {}) {
  try {
    const result = await invoke(command, args);
    print(label, result);
    return result;
  } catch (err) {
    const message = typeof err === "string" ? err : JSON.stringify(err, null, 2);
    print(`${label} (error)`, message);
    throw err;
  }
}

byId("connect_btn").addEventListener("click", async () => {
  const request = readConnectPayload();
  if (!request.bootstrap_directory || !request.invite_key) {
    print("validation", "bootstrap_directory and invite_key are required");
    return;
  }
  await call("connect", "control_connect", { request });
});

byId("disconnect_btn").addEventListener("click", async () => {
  await call("disconnect", "control_disconnect");
});

byId("status_btn").addEventListener("click", async () => {
  await call("status", "control_status");
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
  await call("service_start", "control_service_start");
});

byId("service_stop_btn").addEventListener("click", async () => {
  await call("service_stop", "control_service_stop");
});

byId("service_restart_btn").addEventListener("click", async () => {
  await call("service_restart", "control_service_restart");
});

async function init() {
  try {
    const cfg = await invoke("control_config");
    const meta = formatConfigMeta(cfg || {});
    apiBaseEl.textContent = meta.apiLine;
    apiHintsEl.textContent = meta.hintLine;
  } catch (err) {
    apiBaseEl.textContent = "API: unavailable";
    apiHintsEl.textContent = "";
    print("init (error)", err);
  }
}

init();
