function byId(id) {
  const el = document.getElementById(id);
  if (!el) {
    throw new Error(`missing element: ${id}`);
  }
  return el;
}

const outputEl = byId("output");
const statusLineEl = byId("status_line");

function setStatus(kind, message) {
  statusLineEl.classList.remove("good", "warn", "bad");
  if (kind) {
    statusLineEl.classList.add(kind);
  }
  statusLineEl.textContent = message;
}

function print(label, payload) {
  const text = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
  outputEl.textContent = `[${new Date().toISOString()}] ${label}\n${text}`;
}

function apiBase() {
  return byId("api_base").value.trim().replace(/\/+$/, "");
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
}

function readWalletPayload() {
  return {
    wallet_address: byId("wallet_address").value.trim(),
    wallet_provider: byId("wallet_provider").value
  };
}

async function run(label, fn) {
  setStatus("warn", `Running ${label}...`);
  try {
    const result = await fn();
    print(label, result);
    setStatus("good", `${label} completed`);
  } catch (err) {
    print(`${label} (error)`, String(err && err.message ? err.message : err));
    setStatus("bad", `${label} failed`);
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
    applySession(result);
    return result;
  })
);

byId("session_btn").addEventListener("click", () =>
  run("session_status", async () => {
    const token = byId("session_token").value.trim();
    const result = await post("/v1/gpm/session", { session_token: token });
    if (result.session?.role) {
      byId("role").value = result.session.role;
    }
    return result;
  })
);

byId("manifest_btn").addEventListener("click", () =>
  run("bootstrap_manifest", async () => get("/v1/gpm/bootstrap/manifest"))
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
    return post("/v1/gpm/onboarding/operator/apply", request);
  })
);

byId("operator_status_btn").addEventListener("click", () =>
  run("operator_status", async () => {
    const request = {
      session_token: byId("session_token").value.trim() || undefined,
      wallet_address: byId("wallet_address").value.trim() || undefined
    };
    return post("/v1/gpm/onboarding/operator/status", request);
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
    return result;
  })
);

setStatus("good", "Portal ready");
