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

async function init() {
  try {
    const cfg = await invoke("control_config");
    apiBaseEl.textContent = `API: ${cfg.base_url} (timeout: ${cfg.timeout_sec}s)`;
  } catch (err) {
    apiBaseEl.textContent = "API: unavailable";
    print("init (error)", err);
  }
}

init();
