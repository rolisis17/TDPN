#!/usr/bin/env node
"use strict";

const childProcess = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const vm = require("vm");

const repoRoot = path.resolve(__dirname, "..");
const recoveryHtmlPath = path.join(repoRoot, "apps", "web", "recovery.html");
const recoveryAssetPath = path.join(repoRoot, "apps", "web", "assets", "recovery.js");
const recoveryHtml = fs.readFileSync(recoveryHtmlPath, "utf8");
if (!recoveryHtml.includes("Bridge invites trust helper paths only after Verify Signed succeeds")) {
  throw new Error("recovery page must disclose signed helper registry policy");
}
if (!/<script\s+src=["']\.\/assets\/recovery\.js["']\s*><\/script>/u.test(recoveryHtml)) {
  throw new Error("recovery page must load ./assets/recovery.js");
}

function idsFromHtml(html) {
  const ids = new Set();
  const idPattern = /\bid\s*=\s*["']([^"']+)["']/gu;
  let match;
  while ((match = idPattern.exec(html)) !== null) {
    ids.add(match[1]);
  }
  return ids;
}

function assertRecoveryHtmlIds(requiredIds) {
  const htmlIds = idsFromHtml(recoveryHtml);
  const missing = requiredIds.filter((id) => !htmlIds.has(id));
  if (missing.length > 0) {
    throw new Error(`recovery page missing required verifier IDs: ${missing.join(", ")}`);
  }
}

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
    this.width = 0;
    this.height = 0;
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

  getContext() {
    const element = this;
    return {
      fillStyle: "",
      fillRect() {},
      drawImage() {},
      getImageData() {
        return {
          data: new Uint8ClampedArray(4),
          width: element.width || 1,
          height: element.height || 1,
        };
      },
    };
  }

  querySelector(selector) {
    const expected = String(selector || "").toUpperCase();
    const stack = [...this.children];
    while (stack.length > 0) {
      const node = stack.shift();
      if (node && node.tagName === expected) {
        return node;
      }
      if (node && Array.isArray(node.children)) {
        stack.push(...node.children);
      }
    }
    return null;
  }

  toBlob(callback) {
    callback(new Blob(["stub-png"], { type: "image/png" }));
  }
}

class TextNode {
  constructor(text) {
    this.textContent = text;
    this.parentNode = null;
  }
}

function collectText(node) {
  if (!node) {
    return "";
  }
  let text = node.textContent || "";
  if (Array.isArray(node.children)) {
    for (const child of node.children) {
      text += collectText(child);
    }
  }
  return text;
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
      return elements.get(id) || null;
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

function encodeTextEnvelope(kind, payload) {
  const body = JSON.stringify({ v: 1, k: kind, p: payload });
  return `GPMREC1.${Buffer.from(body, "utf8").toString("base64url")}`;
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
      "https://smoke.gpm-pilot.net",
      "--helper-id",
      "helper-smoke",
      "--helper-name",
      "Smoke Helper",
      "--helper-url",
      "https://helper.gpm-pilot.net/smoke/bootstrap",
      "--helper-contact",
      "mailto:helper-smoke@gpm-pilot.net",
    ],
    { cwd: repoRoot, stdio: "pipe" },
  );

  const trustStore = fs.readFileSync(path.join(outDir, "recovery-trust.json"), "utf8");
  const bridgeInvite = fs.readFileSync(path.join(outDir, "bridge-invite.signed.json"), "utf8");
  const unsignedBridgeInvite = fs.readFileSync(path.join(outDir, "bridge-invite.unsigned.json"), "utf8");
  const unsignedRegistry = fs.readFileSync(path.join(outDir, "bridge-helper-registry.json"), "utf8");
  const trustStoreText = fs.readFileSync(path.join(outDir, "recovery-trust.txt"), "utf8").trim();
  const bridgeInviteText = fs.readFileSync(path.join(outDir, "bridge-invite.txt"), "utf8").trim();
  const signedRegistryText = fs.readFileSync(path.join(outDir, "bridge-helper-registry.signed.txt"), "utf8").trim();
  const trustedKeyText = fs.readFileSync(path.join(outDir, "recovery-trusted-key.txt"), "utf8").trim();
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
      "https://other.gpm-pilot.net",
      "--helper-id",
      "helper-other",
      "--helper-name",
      "Other Helper",
      "--helper-url",
      "https://helper.gpm-pilot.net/other/bootstrap",
      "--helper-contact",
      "mailto:helper-other@gpm-pilot.net",
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
    "registry_policy_hint",
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
  assertRecoveryHtmlIds(ids);

  const document = makeDocument(ids);
  let qrScanText = "";
  const window = {
    atob(value) {
      return Buffer.from(value, "base64").toString("binary");
    },
    btoa(value) {
      return Buffer.from(value, "binary").toString("base64");
    },
    qrcode() {
      return {
        addData() {},
        make() {},
        getModuleCount() {
          return 21;
        },
        isDark(row, col) {
          return (row + col) % 2 === 0;
        },
      };
    },
    jsQR: () => (qrScanText ? { data: qrScanText } : null),
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
    async createImageBitmap() {
      return {
        width: 1,
        height: 1,
        close() {},
      };
    },
    setTimeout,
    window,
  };
  window.document = document;
  window.localStorage = context.localStorage;
  window.navigator = context.navigator;
  window.crypto = context.crypto;
  window.createImageBitmap = context.createImageBitmap;

  vm.createContext(context);
  vm.runInContext(fs.readFileSync(recoveryAssetPath, "utf8"), context, {
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

  const laxDateTrustStore = JSON.parse(trustStore);
  laxDateTrustStore.trusted_keys[0].added_at_utc = "2026-05-10";
  document.getElementById("handoff_input").value = encodeTextEnvelope("trust-store", laxDateTrustStore);
  await document.getElementById("import_text_btn").click();
  const laxDateStatus = document.getElementById("status-heading").textContent;
  const laxDateDetail = document.getElementById("status_detail").textContent;
  if (laxDateStatus !== "Text import failed") {
    throw new Error(`expected date-only trust-store handoff rejection, got ${laxDateStatus}: ${laxDateDetail}`);
  }
  if (!laxDateDetail.includes("trusted key added_at_utc must be RFC3339 with timezone")) {
    throw new Error(`expected RFC3339 trust-store rejection detail, got ${laxDateDetail}`);
  }

  await document.getElementById("clear_btn").click();
  await importTextHandoff(trustedKeyText, "Trusted key text imported");

  const trustedEntry = JSON.parse(trustStore).trusted_keys[0];
  document.getElementById("trust_org_id").value = trustedEntry.org_id;
  document.getElementById("trust_org_name").value = trustedEntry.org_name;
  document.getElementById("trust_public_key").value = `${trustedEntry.public_key}=`;
  await document.getElementById("trust_add_btn").click();
  const paddedKeyStatus = document.getElementById("status-heading").textContent;
  const paddedKeyDetail = document.getElementById("status_detail").textContent;
  if (paddedKeyStatus !== "Could not add key") {
    throw new Error(`expected padded public key rejection, got ${paddedKeyStatus}: ${paddedKeyDetail}`);
  }
  if (!paddedKeyDetail.includes("unpadded base64url")) {
    throw new Error(`expected padded public key base64url detail, got ${paddedKeyDetail}`);
  }

  await importTextHandoff(signedRegistryText, "Signed helper registry text imported");
  await document.getElementById("verify_registry_btn").click();

  const registryStatus = document.getElementById("status-heading").textContent;
  if (registryStatus !== "Trusted helper registry") {
    throw new Error(`expected signed registry verification, got ${registryStatus}`);
  }

  await importTextHandoff(bridgeInviteText, "Bridge invite text imported");
  await document.getElementById("render_qr_btn").click();
  const qrStatus = document.getElementById("status-heading").textContent;
  if (qrStatus !== "QR rendered") {
    const qrDetail = document.getElementById("status_detail").textContent;
    throw new Error(`expected QR rendered, got ${qrStatus}: ${qrDetail}`);
  }
  if (!document.getElementById("qr_preview").querySelector("canvas")) {
    throw new Error("expected QR render to append a canvas");
  }
  document.getElementById("qr_image_file").files = [new Blob(["no-qr"], { type: "image/png" })];
  qrScanText = "";
  await document.getElementById("scan_qr_btn").click();
  const emptyQRStatus = document.getElementById("status-heading").textContent;
  const emptyQRDetail = document.getElementById("status_detail").textContent;
  if (emptyQRStatus !== "QR scan failed") {
    throw new Error(`expected empty QR scan to fail closed, got ${emptyQRStatus}: ${emptyQRDetail}`);
  }
  if (!emptyQRDetail.includes("No QR code text was found")) {
    throw new Error(`expected no-code QR scan detail, got ${emptyQRDetail}`);
  }
  document.getElementById("handoff_input").value = "";
  document.getElementById("pack_input").value = "";
  qrScanText = bridgeInviteText;
  await document.getElementById("scan_qr_btn").click();
  const scannedQRStatus = document.getElementById("status-heading").textContent;
  const scannedQRDetail = document.getElementById("status_detail").textContent;
  if (scannedQRStatus !== "Bridge invite text imported") {
    throw new Error(`expected QR scan import, got ${scannedQRStatus}: ${scannedQRDetail}`);
  }
  if (!document.getElementById("pack_input").value.includes("helper-smoke")) {
    throw new Error("expected QR scan import to populate the bridge invite pack input");
  }
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
  const pathsText = collectText(document.getElementById("paths_list"));
  if (!pathsText.includes("Report Abuse")) {
    throw new Error(`expected helper abuse report action, got rendered text: ${pathsText}`);
  }
  if (!pathsText.includes("Rate limits:")) {
    throw new Error(`expected helper rate-limit detail, got rendered text: ${pathsText}`);
  }

  const helperRegistryStorageKey = "gpm_recover_helper_registry_v1";
  const helperRegistryMetaStorageKey = "gpm_recover_helper_registry_meta_v1";
  if (!context.localStorage.getItem(helperRegistryStorageKey)) {
    throw new Error("expected verified helper registry to be saved in localStorage");
  }
  if (!context.localStorage.getItem(helperRegistryMetaStorageKey)) {
    throw new Error("expected verified helper registry metadata to be saved in localStorage");
  }

  const publicMappedInvite = JSON.parse(unsignedBridgeInvite);
  publicMappedInvite.access_paths[0].url = "https://[::ffff:0808:0808]/smoke/bootstrap";
  const publicMappedUnsignedPath = path.join(outDir, "bridge-invite-public-mapped.unsigned.json");
  const publicMappedSignedPath = path.join(outDir, "bridge-invite-public-mapped.signed.json");
  fs.writeFileSync(publicMappedUnsignedPath, `${JSON.stringify(publicMappedInvite, null, 2)}\n`, "utf8");
  childProcess.execFileSync(
    "go",
    [
      "run",
      "./cmd/gpmrecover",
      "bridge-sign",
      "--invite",
      publicMappedUnsignedPath,
      "--private-key-file",
      path.join(outDir, "recovery.key"),
      "--out",
      publicMappedSignedPath,
    ],
    { cwd: repoRoot, stdio: "pipe" },
  );
  document.getElementById("pack_input").value = fs.readFileSync(publicMappedSignedPath, "utf8");
  await document.getElementById("verify_btn").click();
  const publicMappedStatus = document.getElementById("status-heading").textContent;
  const publicMappedDetail = document.getElementById("status_detail").textContent;
  if (publicMappedStatus !== "Trusted bridge invite") {
    throw new Error(`expected public IPv4-mapped IPv6 bridge invite to verify, got ${publicMappedStatus}: ${publicMappedDetail}`);
  }

  async function expectUnsafeBridgeInviteRejected(mutator, expectedDetail, label) {
    const invite = JSON.parse(bridgeInvite);
    mutator(invite);
    document.getElementById("pack_input").value = JSON.stringify(invite);
    await document.getElementById("verify_btn").click();
    const rejectedStatus = document.getElementById("status-heading").textContent;
    const rejectedDetail = document.getElementById("status_detail").textContent;
    const rejectedPathCount = document.getElementById("path_count").textContent;
    const rejectedPathsRendered = document.getElementById("paths_list").children.length;
    if (rejectedStatus !== "Verification failed") {
      throw new Error(`expected ${label} bridge invite rejection, got ${rejectedStatus}: ${rejectedDetail}`);
    }
    if (!rejectedDetail.includes(expectedDetail)) {
      throw new Error(`expected ${label} bridge invite detail ${expectedDetail}, got ${rejectedDetail}`);
    }
    if (rejectedPathCount !== "0" || rejectedPathsRendered !== 0) {
      throw new Error(`expected rejected ${label} bridge invite to render no paths, got count=${rejectedPathCount} rendered=${rejectedPathsRendered}`);
    }
  }

  const userinfoInvite = JSON.parse(bridgeInvite);
  userinfoInvite.access_paths[0].url = "https://helper-smoke:secret@helper.example/smoke/bootstrap";
  document.getElementById("pack_input").value = JSON.stringify(userinfoInvite);
  await document.getElementById("verify_btn").click();
  const userinfoInviteStatus = document.getElementById("status-heading").textContent;
  const userinfoInviteDetail = document.getElementById("status_detail").textContent;
  if (userinfoInviteStatus !== "Verification failed") {
    throw new Error(`expected userinfo bridge invite URL rejection, got ${userinfoInviteStatus}: ${userinfoInviteDetail}`);
  }
  if (!userinfoInviteDetail.includes("access_paths[].url userinfo is not allowed")) {
    throw new Error(`expected userinfo URL rejection detail, got ${userinfoInviteDetail}`);
  }

  const unsupportedSchemeInvite = JSON.parse(bridgeInvite);
  unsupportedSchemeInvite.access_paths[0].url = "ftp://helper.example/smoke/bootstrap";
  document.getElementById("pack_input").value = JSON.stringify(unsupportedSchemeInvite);
  await document.getElementById("verify_btn").click();
  const unsupportedSchemeInviteStatus = document.getElementById("status-heading").textContent;
  const unsupportedSchemeInviteDetail = document.getElementById("status_detail").textContent;
  if (unsupportedSchemeInviteStatus !== "Verification failed") {
    throw new Error(`expected unsupported bridge invite URL scheme rejection, got ${unsupportedSchemeInviteStatus}: ${unsupportedSchemeInviteDetail}`);
  }
  if (!unsupportedSchemeInviteDetail.includes("access_paths[].url scheme must be http, https, or mailto")) {
    throw new Error(`expected unsupported bridge invite URL scheme detail, got ${unsupportedSchemeInviteDetail}`);
  }

  await expectUnsafeBridgeInviteRejected(
    (invite) => { invite.access_paths[0].url = "http://helper.gpm-pilot.net/smoke/bootstrap"; },
    "access_paths[].url serviceable bridge access paths must use https",
    "plain-http",
  );
  await expectUnsafeBridgeInviteRejected(
    (invite) => { invite.access_paths[0].url = "https://10.0.0.5/smoke/bootstrap"; },
    "access_paths[].url host must be public-routable",
    "private-ip",
  );
  await expectUnsafeBridgeInviteRejected(
    (invite) => { invite.access_paths[0].url = "https://100.64.0.10/smoke/bootstrap"; },
    "access_paths[].url host must be public-routable",
    "cgnat-ip",
  );
  await expectUnsafeBridgeInviteRejected(
    (invite) => { invite.access_paths[0].url = "https://[::ffff:7f00:1]/smoke/bootstrap"; },
    "access_paths[].url host must be public-routable",
    "ipv4-mapped-loopback",
  );
  await expectUnsafeBridgeInviteRejected(
    (invite) => { invite.access_paths[0].url = "https://[::ffff:a00:5]/smoke/bootstrap"; },
    "access_paths[].url host must be public-routable",
    "ipv4-mapped-private",
  );
  await expectUnsafeBridgeInviteRejected(
    (invite) => { invite.access_paths[0].url = "https://[::ffff:6440:a]/smoke/bootstrap"; },
    "access_paths[].url host must be public-routable",
    "ipv4-mapped-cgnat",
  );
  await expectUnsafeBridgeInviteRejected(
    (invite) => { invite.access_paths[0].url = "https://[::ffff:c0a8:101]/smoke/bootstrap"; },
    "access_paths[].url host must be public-routable",
    "ipv4-mapped-rfc1918",
  );
  await expectUnsafeBridgeInviteRejected(
    (invite) => { invite.access_paths[0].url = "https://helper.home.arpa/smoke/bootstrap"; },
    "access_paths[].url host must be public-routable",
    "home.arpa",
  );
  await expectUnsafeBridgeInviteRejected(
    (invite) => { invite.access_paths[0].url = "https://helper.tailnet.ts.net/smoke/bootstrap"; },
    "access_paths[].url host must be public-routable",
    "tailscale",
  );
  await expectUnsafeBridgeInviteRejected(
    (invite) => {
      invite.access_paths = [
        {
          path_id: "manual-helper",
          kind: "instructions",
          url: "mailto:helper-smoke@gpm-pilot.net",
          priority: 10,
          requires_external_app: true,
        },
      ];
    },
    "Bridge invite needs at least one public HTTPS bridge access path",
    "manual-only",
  );
  await expectUnsafeBridgeInviteRejected(
    (invite) => {
      invite.access_paths = [
        invite.access_paths[0],
        {
          path_id: "manual-helper-private",
          kind: "instructions",
          url: "https://127.0.0.1/smoke/bootstrap",
          priority: 20,
          requires_external_app: true,
        },
      ];
    },
    "access_paths[].url host must be public-routable",
    "manual-private-with-service-path",
  );
  await expectUnsafeBridgeInviteRejected(
    (invite) => {
      invite.access_paths = [
        invite.access_paths[0],
        {
          path_id: "manual-helper-http",
          kind: "instructions",
          url: "http://helper.gpm-pilot.net/smoke/bootstrap",
          priority: 20,
          requires_external_app: true,
        },
      ];
    },
    "access_paths[].url serviceable bridge access paths must use https",
    "manual-http-with-service-path",
  );
  await expectUnsafeBridgeInviteRejected(
    (invite) => {
      invite.access_paths = [
        invite.access_paths[0],
        {
          path_id: "manual-helper-tailnet",
          kind: "instructions",
          url: "https://helper.tailnet.ts.net/smoke/bootstrap",
          priority: 20,
          requires_external_app: true,
        },
      ];
    },
    "access_paths[].url host must be public-routable",
    "manual-tailnet-with-service-path",
  );
  await expectUnsafeBridgeInviteRejected(
    (invite) => { invite.helper.contact_url = "https://127.0.0.1/support"; },
    "helper.contact_url host must be public-routable",
    "invite-private-contact-url",
  );
  await expectUnsafeBridgeInviteRejected(
    (invite) => { invite.helper.contact_url = "http://helper.gpm-pilot.net/support"; },
    "helper.contact_url must use https or mailto",
    "invite-http-contact-url",
  );

  const userinfoRegistry = JSON.parse(unsignedRegistry);
  userinfoRegistry.helpers[0].abuse_report_url = "https://helper-smoke:secret@helper.example/smoke/abuse";
  document.getElementById("registry_input").value = JSON.stringify(userinfoRegistry);
  await document.getElementById("registry_input").dispatch("input");
  await document.getElementById("export_registry_text_btn").click();
  const userinfoRegistryStatus = document.getElementById("status-heading").textContent;
  const userinfoRegistryDetail = document.getElementById("status_detail").textContent;
  if (userinfoRegistryStatus !== "Registry export failed") {
    throw new Error(`expected userinfo helper registry URL rejection, got ${userinfoRegistryStatus}: ${userinfoRegistryDetail}`);
  }
  if (!userinfoRegistryDetail.includes("helpers[].abuse_report_url userinfo is not allowed")) {
    throw new Error(`expected helper registry userinfo URL rejection detail, got ${userinfoRegistryDetail}`);
  }

  const unsupportedSchemeRegistry = JSON.parse(unsignedRegistry);
  unsupportedSchemeRegistry.helpers[0].abuse_report_url = "ssh://helper.example/smoke/abuse";
  document.getElementById("registry_input").value = JSON.stringify(unsupportedSchemeRegistry);
  await document.getElementById("registry_input").dispatch("input");
  await document.getElementById("export_registry_text_btn").click();
  const unsupportedSchemeRegistryStatus = document.getElementById("status-heading").textContent;
  const unsupportedSchemeRegistryDetail = document.getElementById("status_detail").textContent;
  if (unsupportedSchemeRegistryStatus !== "Registry export failed") {
    throw new Error(`expected unsupported helper registry URL scheme rejection, got ${unsupportedSchemeRegistryStatus}: ${unsupportedSchemeRegistryDetail}`);
  }
  if (!unsupportedSchemeRegistryDetail.includes("helpers[].abuse_report_url scheme must be http, https, or mailto")) {
    throw new Error(`expected unsupported helper registry URL scheme detail, got ${unsupportedSchemeRegistryDetail}`);
  }

  async function expectRegistryExportRejected(mutator, expectedDetail, label) {
    const registry = JSON.parse(unsignedRegistry);
    mutator(registry);
    document.getElementById("registry_input").value = JSON.stringify(registry);
    await document.getElementById("registry_input").dispatch("input");
    await document.getElementById("export_registry_text_btn").click();
    const registryStatus = document.getElementById("status-heading").textContent;
    const registryDetail = document.getElementById("status_detail").textContent;
    if (registryStatus !== "Registry export failed") {
      throw new Error(`expected ${label} helper registry rejection, got ${registryStatus}: ${registryDetail}`);
    }
    if (!registryDetail.includes(expectedDetail)) {
      throw new Error(`expected ${label} helper registry detail ${expectedDetail}, got ${registryDetail}`);
    }
  }

  await expectRegistryExportRejected(
    (registry) => { registry.helpers[0].contact_url = "https://10.0.0.5/support"; },
    "helpers[].contact_url host must be public-routable",
    "private-contact-url",
  );
  await expectRegistryExportRejected(
    (registry) => { registry.helpers[0].contact_url = "http://helper.gpm-pilot.net/support"; },
    "helpers[].contact_url must use https or mailto",
    "http-contact-url",
  );
  await expectRegistryExportRejected(
    (registry) => { registry.helpers[0].abuse_report_url = "https://helper.home.arpa/abuse"; },
    "helpers[].abuse_report_url host must be public-routable",
    "home-arpa-abuse-url",
  );
  await expectRegistryExportRejected(
    (registry) => { registry.helpers[0].abuse_report_url = "https://helper.tailnet.ts.net/abuse"; },
    "helpers[].abuse_report_url host must be public-routable",
    "tailnet-abuse-url",
  );

  const duplicateHelperRegistry = JSON.parse(unsignedRegistry);
  duplicateHelperRegistry.helpers.push({ ...duplicateHelperRegistry.helpers[0] });
  document.getElementById("registry_input").value = JSON.stringify(duplicateHelperRegistry);
  await document.getElementById("registry_input").dispatch("input");
  await document.getElementById("export_registry_text_btn").click();
  const duplicateHelperStatus = document.getElementById("status-heading").textContent;
  const duplicateHelperDetail = document.getElementById("status_detail").textContent;
  if (duplicateHelperStatus !== "Registry export failed") {
    throw new Error(`expected duplicate helper rejection, got ${duplicateHelperStatus}: ${duplicateHelperDetail}`);
  }
  if (!duplicateHelperDetail.includes("helper_id duplicates")) {
    throw new Error(`expected duplicate helper detail, got ${duplicateHelperDetail}`);
  }

  const duplicateOrgRegistry = JSON.parse(unsignedRegistry);
  duplicateOrgRegistry.helpers[0].org_ids.push(duplicateOrgRegistry.helpers[0].org_ids[0]);
  document.getElementById("registry_input").value = JSON.stringify(duplicateOrgRegistry);
  await document.getElementById("registry_input").dispatch("input");
  await document.getElementById("export_registry_text_btn").click();
  const duplicateOrgStatus = document.getElementById("status-heading").textContent;
  const duplicateOrgDetail = document.getElementById("status_detail").textContent;
  if (duplicateOrgStatus !== "Registry export failed") {
    throw new Error(`expected duplicate org rejection, got ${duplicateOrgStatus}: ${duplicateOrgDetail}`);
  }
  if (!duplicateOrgDetail.includes("org_ids duplicates")) {
    throw new Error(`expected duplicate org detail, got ${duplicateOrgDetail}`);
  }

  const registryInput = document.getElementById("registry_input");
  registryInput.value = "{not-json";
  await registryInput.dispatch("input");
  if (context.localStorage.getItem(helperRegistryStorageKey)) {
    throw new Error("expected invalid helper registry edit to clear saved registry");
  }
  if (context.localStorage.getItem(helperRegistryMetaStorageKey)) {
    throw new Error("expected invalid helper registry edit to clear saved registry metadata");
  }

  async function expectBridgeInviteRejected(expectedDetail) {
    document.getElementById("pack_input").value = bridgeInvite;
    await document.getElementById("verify_btn").click();
    const failedStatus = document.getElementById("status-heading").textContent;
    const failedDetail = document.getElementById("status_detail").textContent;
    if (failedStatus !== "Verification failed") {
      throw new Error(`expected bridge invite rejection, got ${failedStatus}: ${failedDetail}`);
    }
    if (!failedDetail.includes(expectedDetail)) {
      throw new Error(`expected rejection detail to include ${expectedDetail}, got ${failedDetail}`);
    }
  }

  document.getElementById("registry_input").value = "";
  await expectBridgeInviteRejected("Verify a signed helper registry");

  const registryInputForUnsigned = document.getElementById("registry_input");
  registryInputForUnsigned.value = unsignedRegistry;
  await registryInputForUnsigned.dispatch("input");
  await expectBridgeInviteRejected("Verify a signed helper registry");

  await importTextHandoff(signedRegistryText, "Signed helper registry text imported");
  await document.getElementById("verify_registry_btn").click();
  const verifiedRegistry = JSON.parse(context.localStorage.getItem(helperRegistryStorageKey));
  verifiedRegistry.helpers[0].display_name = `${verifiedRegistry.helpers[0].display_name} tampered`;
  const tamperedRegistry = JSON.stringify(verifiedRegistry, null, 2);
  context.localStorage.setItem(helperRegistryStorageKey, tamperedRegistry);
  document.getElementById("registry_input").value = tamperedRegistry;
  await expectBridgeInviteRejected("metadata does not match the current registry content");

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
