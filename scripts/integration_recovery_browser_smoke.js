#!/usr/bin/env node
"use strict";

const childProcess = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const vm = require("vm");

const repoRoot = path.resolve(__dirname, "..");

class Element {
  constructor(tagName, id = "") {
    this.tagName = tagName.toUpperCase();
    this.id = id;
    this.children = [];
    this.parentNode = null;
    this.listeners = {};
    this.dataset = {};
    this.style = {};
    this.className = "";
    this.type = "";
    this.value = "";
    this.href = "";
    this.target = "";
    this.rel = "";
    this.download = "";
    this.disabled = false;
    this.files = [];
    this._textContent = "";
  }

  get firstChild() {
    return this.children[0] || null;
  }

  get textContent() {
    return this._textContent;
  }

  set textContent(value) {
    this._textContent = String(value ?? "");
  }

  append(...nodes) {
    for (const node of nodes) {
      this.appendChild(node);
    }
  }

  appendChild(node) {
    if (typeof node === "string") {
      node = new TextNode(node);
    }
    node.parentNode = this;
    this.children.push(node);
    return node;
  }

  removeChild(node) {
    const index = this.children.indexOf(node);
    if (index >= 0) {
      this.children.splice(index, 1);
      node.parentNode = null;
    }
    return node;
  }

  remove() {
    if (this.parentNode) {
      this.parentNode.removeChild(this);
    }
  }

  addEventListener(type, handler) {
    if (!this.listeners[type]) {
      this.listeners[type] = [];
    }
    this.listeners[type].push(handler);
  }

  async dispatch(type) {
    for (const handler of this.listeners[type] || []) {
      await handler({ target: this, currentTarget: this });
    }
  }

  click() {
    return this.dispatch("click");
  }
}

class TextNode {
  constructor(text) {
    this.textContent = text;
    this.parentNode = null;
  }
}

function makeDocument(ids) {
  const elements = new Map();
  for (const id of ids) {
    elements.set(id, new Element("div", id));
  }
  const body = new Element("body", "body");
  return {
    body,
    createElement(tagName) {
      return new Element(tagName);
    },
    getElementById(id) {
      if (!elements.has(id)) {
        elements.set(id, new Element("div", id));
      }
      return elements.get(id);
    },
    _elements: elements,
  };
}

function makeLocalStorage() {
  const values = new Map();
  return {
    getItem(key) {
      return values.has(key) ? values.get(key) : null;
    },
    setItem(key, value) {
      values.set(key, String(value));
    },
    removeItem(key) {
      values.delete(key);
    },
  };
}

async function main() {
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), "gpm-recovery-browser-smoke-"));
  childProcess.execFileSync(
    "go",
    [
      "run",
      "./cmd/gpmrecover",
      "demo-bundle",
      "--out-dir",
      outDir,
      "--org-id",
      "smoke-org",
      "--org-name",
      "Smoke Org",
      "--base-url",
      "https://smoke.example",
      "--helper-id",
      "helper-smoke",
      "--helper-name",
      "Smoke Helper",
      "--helper-url",
      "https://helper.example/smoke/bootstrap",
      "--helper-contact",
      "mailto:helper-smoke@example.com",
    ],
    { cwd: repoRoot, stdio: "pipe" },
  );

  const trustStore = fs.readFileSync(path.join(outDir, "recovery-trust.json"), "utf8");
  const bridgeInvite = fs.readFileSync(path.join(outDir, "bridge-invite.signed.json"), "utf8");
  const trustStoreText = fs.readFileSync(path.join(outDir, "recovery-trust.txt"), "utf8").trim();
  const bridgeInviteText = fs.readFileSync(path.join(outDir, "bridge-invite.txt"), "utf8").trim();
  const signedRegistryText = fs.readFileSync(path.join(outDir, "bridge-helper-registry.signed.txt"), "utf8").trim();
  const trustedKey = JSON.parse(trustStore).trusted_keys[0];
  if (!trustedKey || !trustedKey.org_id || !trustedKey.key_id) {
    throw new Error("demo trust store did not include an exportable trusted key");
  }
  const trustedKeyTextFile = path.join(outDir, "recovery-trusted-key.txt");
  childProcess.execFileSync(
    "go",
    [
      "run",
      "./cmd/gpmrecover",
      "trust-export-key",
      "--trust-store",
      path.join(outDir, "recovery-trust.json"),
      "--org-id",
      trustedKey.org_id,
      "--key-id",
      trustedKey.key_id,
      "--text-out",
      trustedKeyTextFile,
    ],
    { cwd: repoRoot, stdio: "pipe" },
  );
  const trustedKeyText = fs.readFileSync(trustedKeyTextFile, "utf8").trim();
  const otherOutDir = fs.mkdtempSync(path.join(os.tmpdir(), "gpm-recovery-browser-smoke-other-"));
  childProcess.execFileSync(
    "go",
    [
      "run",
      "./cmd/gpmrecover",
      "demo-bundle",
      "--out-dir",
      otherOutDir,
      "--org-id",
      "other-org",
      "--org-name",
      "Other Org",
      "--base-url",
      "https://other.example",
      "--helper-id",
      "helper-other",
      "--helper-name",
      "Other Helper",
      "--helper-url",
      "https://helper.example/other/bootstrap",
      "--helper-contact",
      "mailto:helper-other@example.com",
    ],
    { cwd: repoRoot, stdio: "pipe" },
  );
  const otherTrustStore = fs.readFileSync(path.join(otherOutDir, "recovery-trust.json"), "utf8");
  const otherSignedRegistry = fs.readFileSync(path.join(otherOutDir, "bridge-helper-registry.signed.json"), "utf8");
  const mergedTrustStore = JSON.stringify({
    version: 1,
    trusted_keys: [
      ...JSON.parse(trustStore).trusted_keys,
      ...JSON.parse(otherTrustStore).trusted_keys,
    ],
  });

  const ids = [
    "pack_input",
    "trust_input",
    "registry_input",
    "pack_file",
    "trust_file",
    "registry_file",
    "trust_org_id",
    "trust_org_name",
    "trust_public_key",
    "trust_expires",
    "trust_source",
    "trust_add_btn",
    "trust_reset_btn",
    "trust_copy_btn",
    "trust_download_btn",
    "trust_key_list",
    "verify_registry_btn",
    "registry_summary",
    "handoff_input",
    "export_pack_text_btn",
    "export_store_text_btn",
    "export_registry_text_btn",
    "render_qr_btn",
    "download_qr_btn",
    "import_text_btn",
    "clear_text_btn",
    "qr_preview",
    "qr_image_file",
    "scan_qr_btn",
    "verify_btn",
    "clear_btn",
    "status_card",
    "status-heading",
    "status_detail",
    "facts_grid",
    "paths_list",
    "path_count",
  ];

  const document = makeDocument(ids);
  const window = {
    atob(value) {
      return Buffer.from(value, "base64").toString("binary");
    },
    btoa(value) {
      return Buffer.from(value, "binary").toString("base64");
    },
    jsQR: () => null,
  };
  const context = {
    Blob,
    Buffer,
    TextDecoder,
    TextEncoder,
    URL,
    Uint8Array,
    console,
    crypto: globalThis.crypto,
    document,
    localStorage: makeLocalStorage(),
    navigator: {
      clipboard: {
        async writeText(value) {
          context.__clipboard = String(value);
        },
      },
    },
    setTimeout,
    window,
  };
  window.document = document;
  window.localStorage = context.localStorage;
  window.navigator = context.navigator;
  window.crypto = context.crypto;

  vm.createContext(context);
  vm.runInContext(fs.readFileSync(path.join(repoRoot, "apps/web/assets/recovery.js"), "utf8"), context, {
    filename: "apps/web/assets/recovery.js",
  });

  async function importTextHandoff(text, expectedStatus) {
    document.getElementById("handoff_input").value = text;
    await document.getElementById("import_text_btn").click();
    const importedStatus = document.getElementById("status-heading").textContent;
    if (importedStatus !== expectedStatus) {
      const importedDetail = document.getElementById("status_detail").textContent;
      throw new Error(`expected ${expectedStatus}, got ${importedStatus}: ${importedDetail}`);
    }
  }

  await importTextHandoff(trustStoreText, "Trust store text imported");
  await document.getElementById("clear_btn").click();
  await importTextHandoff(trustedKeyText, "Trusted key text imported");
  await importTextHandoff(signedRegistryText, "Signed helper registry text imported");
  await document.getElementById("verify_registry_btn").click();

  const registryStatus = document.getElementById("status-heading").textContent;
  if (registryStatus !== "Trusted helper registry") {
    throw new Error(`expected signed registry verification, got ${registryStatus}`);
  }

  await importTextHandoff(bridgeInviteText, "Bridge invite text imported");
  await document.getElementById("verify_btn").click();

  const status = document.getElementById("status-heading").textContent;
  const detail = document.getElementById("status_detail").textContent;
  const pathCount = document.getElementById("path_count").textContent;
  const pathsRendered = document.getElementById("paths_list").children.length;
  if (status !== "Trusted bridge invite") {
    throw new Error(`expected trusted bridge invite, got ${status}: ${detail}`);
  }
  if (!detail.includes("active helper registry entry")) {
    throw new Error(`expected active helper registry detail, got ${detail}`);
  }
  if (pathCount !== "2") {
    throw new Error(`expected 2 verified bridge paths, got ${pathCount}`);
  }
  if (pathsRendered < 3) {
    throw new Error(`expected helper card plus bridge paths, got ${pathsRendered} rendered item(s)`);
  }

  document.getElementById("trust_input").value = mergedTrustStore;
  document.getElementById("registry_input").value = otherSignedRegistry;
  await document.getElementById("verify_registry_btn").click();
  document.getElementById("pack_input").value = bridgeInvite;
  await document.getElementById("verify_btn").click();

  const rejectedStatus = document.getElementById("status-heading").textContent;
  const rejectedDetail = document.getElementById("status_detail").textContent;
  if (rejectedStatus !== "Verification failed") {
    throw new Error(`expected cross-org registry to fail closed, got ${rejectedStatus}: ${rejectedDetail}`);
  }
  if (!rejectedDetail.includes("does not match bridge invite organization")) {
    throw new Error(`expected cross-org mismatch detail, got ${rejectedDetail}`);
  }

  console.log(JSON.stringify({
    status: "ok",
    bundle_dir: outDir,
    cross_org_bundle_dir: otherOutDir,
    browser_status: status,
    cross_org_rejected: true,
    path_count: Number(pathCount),
    rendered_items: pathsRendered,
  }));
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : String(err));
  process.exit(1);
});
