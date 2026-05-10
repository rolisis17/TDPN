(function () {
  "use strict";

  const els = {
    packInput: document.getElementById("pack_input"),
    trustInput: document.getElementById("trust_input"),
    registryInput: document.getElementById("registry_input"),
    packFile: document.getElementById("pack_file"),
    trustFile: document.getElementById("trust_file"),
    registryFile: document.getElementById("registry_file"),
    trustOrgID: document.getElementById("trust_org_id"),
    trustOrgName: document.getElementById("trust_org_name"),
    trustPublicKey: document.getElementById("trust_public_key"),
    trustExpires: document.getElementById("trust_expires"),
    trustSource: document.getElementById("trust_source"),
    trustAddBtn: document.getElementById("trust_add_btn"),
    trustResetBtn: document.getElementById("trust_reset_btn"),
    trustCopyBtn: document.getElementById("trust_copy_btn"),
    trustDownloadBtn: document.getElementById("trust_download_btn"),
    trustKeyList: document.getElementById("trust_key_list"),
    verifyRegistryBtn: document.getElementById("verify_registry_btn"),
    registrySummary: document.getElementById("registry_summary"),
    handoffInput: document.getElementById("handoff_input"),
    exportPackTextBtn: document.getElementById("export_pack_text_btn"),
    exportStoreTextBtn: document.getElementById("export_store_text_btn"),
    exportRegistryTextBtn: document.getElementById("export_registry_text_btn"),
    renderQRBtn: document.getElementById("render_qr_btn"),
    downloadQRBtn: document.getElementById("download_qr_btn"),
    importTextBtn: document.getElementById("import_text_btn"),
    clearTextBtn: document.getElementById("clear_text_btn"),
    qrPreview: document.getElementById("qr_preview"),
    qrImageFile: document.getElementById("qr_image_file"),
    scanQRBtn: document.getElementById("scan_qr_btn"),
    verifyBtn: document.getElementById("verify_btn"),
    clearBtn: document.getElementById("clear_btn"),
    statusCard: document.getElementById("status_card"),
    statusHeading: document.getElementById("status-heading"),
    statusDetail: document.getElementById("status_detail"),
    factsGrid: document.getElementById("facts_grid"),
    pathsList: document.getElementById("paths_list"),
    pathCount: document.getElementById("path_count"),
  };
  const trustStoreStorageKey = "gpm_recover_trust_store_v1";
  const helperRegistryStorageKey = "gpm_recover_helper_registry_v1";
  const helperRegistryMetaStorageKey = "gpm_recover_helper_registry_meta_v1";
  const textEnvelopePrefix = "GPMREC1";
  const textEnvelopeKinds = [
    "access-pack",
    "bridge-invite",
    "trust-store",
    "trusted-key",
    "bridge-helper-registry",
    "bridge-helper-registry-signed",
  ];
  const maxBridgeInviteLifetimeMS = 14 * 24 * 60 * 60 * 1000;
  const maxBridgeRegistryArtifactLifetimeMS = 30 * 24 * 60 * 60 * 1000;
  let verifiedHelperRegistryMeta = null;

  function setStatus(state, title, detail) {
    els.statusCard.dataset.state = state;
    els.statusHeading.textContent = title;
    els.statusDetail.textContent = detail;
  }

  function clearNode(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function resetQRPreview() {
    clearNode(els.qrPreview);
    const empty = document.createElement("p");
    empty.className = "recover-empty";
    empty.textContent = "Render a QR from the current GPMREC1 text when you need a visual handoff.";
    els.qrPreview.appendChild(empty);
  }

  function trimString(value) {
    return typeof value === "string" ? value.trim() : "";
  }

  function base64URLToBytes(value, label) {
    const raw = trimString(value);
    if (!raw) {
      throw new Error(`${label} is required`);
    }
    const b64 = raw.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    let binary;
    try {
      binary = window.atob(padded);
    } catch (err) {
      throw new Error(`${label} must be base64url`);
    }
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function bytesToBase64URL(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i += 1) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function encodeTextEnvelope(kind, payload) {
    if (!textEnvelopeKinds.includes(kind)) {
      throw new Error(`Unsupported text handoff kind ${kind}`);
    }
    const body = new TextEncoder().encode(JSON.stringify({ v: 1, k: kind, p: payload }));
    return `${textEnvelopePrefix}.${bytesToBase64URL(body)}`;
  }

  function decodeTextEnvelope(text) {
    const raw = trimString(text);
    const prefix = `${textEnvelopePrefix}.`;
    if (!raw.startsWith(prefix)) {
      throw new Error(`Text handoff must start with ${prefix}`);
    }
    const bytes = base64URLToBytes(raw.slice(prefix.length), "text handoff");
    let envelope;
    try {
      envelope = JSON.parse(new TextDecoder().decode(bytes));
    } catch (err) {
      throw new Error("Text handoff is not valid JSON");
    }
    if (!envelope || envelope.v !== 1) {
      throw new Error("Unsupported text handoff version");
    }
    if (!textEnvelopeKinds.includes(envelope.k)) {
      throw new Error(`Unsupported text handoff kind ${envelope.k}`);
    }
    if (envelope.p === null || typeof envelope.p !== "object") {
      throw new Error("Text handoff payload is missing");
    }
    return { kind: envelope.k, payload: envelope.p };
  }

  async function renderQRCode() {
    const text = trimString(els.handoffInput.value);
    const decoded = decodeTextEnvelope(text);
    await validateDecodedTextEnvelopePayload(decoded);
    if (typeof window.qrcode !== "function") {
      throw new Error("QR renderer is not available");
    }
    const qr = window.qrcode(0, "M");
    qr.addData(text, "Byte");
    qr.make();
    const modules = qr.getModuleCount();
    const margin = 4;
    const maxCanvas = 640;
    const cellSize = Math.max(3, Math.floor(maxCanvas / (modules + margin * 2)));
    const size = (modules + margin * 2) * cellSize;
    const canvas = document.createElement("canvas");
    canvas.width = size;
    canvas.height = size;
    canvas.className = "qr-canvas";
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = "#000000";
    for (let row = 0; row < modules; row += 1) {
      for (let col = 0; col < modules; col += 1) {
        if (qr.isDark(row, col)) {
          ctx.fillRect((col + margin) * cellSize, (row + margin) * cellSize, cellSize, cellSize);
        }
      }
    }
    clearNode(els.qrPreview);
    els.qrPreview.appendChild(canvas);
    const caption = document.createElement("p");
    caption.className = "recover-empty";
    caption.textContent = `QR rendered from ${text.length} characters.`;
    els.qrPreview.appendChild(caption);
    return canvas;
  }

  async function downloadRenderedQR() {
    let canvas = els.qrPreview.querySelector("canvas");
    if (!canvas) {
      canvas = await renderQRCode();
    }
    canvas.toBlob((blob) => {
      if (!blob) {
        setStatus("bad", "QR download failed", "The browser could not create the QR image.");
        return;
      }
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "gpm-recovery-handoff-qr.png";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      setStatus("idle", "QR ready", "The current GPMREC1 handoff was rendered as a PNG.");
    }, "image/png");
  }

  async function keyIDFromPublicKey(publicKeyBytes) {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", publicKeyBytes));
    return Array.from(digest.slice(0, 8))
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
  }

  function parseJSONInput(value, label) {
    const raw = trimString(value);
    if (!raw) {
      throw new Error(`${label} is required`);
    }
    try {
      return JSON.parse(raw);
    } catch (err) {
      throw new Error(`${label} is not valid JSON`);
    }
  }

  function readTrustStoreInput() {
    const raw = trimString(els.trustInput.value);
    if (!raw) {
      return { version: 1, trusted_keys: [] };
    }
    return parseJSONInput(raw, "Trust store");
  }

  function readHelperRegistryInput() {
    const raw = trimString(els.registryInput.value);
    if (!raw) {
      return null;
    }
    return parseJSONInput(raw, "Helper registry");
  }

  function normalizeVerifiedHelperRegistryMeta(meta) {
    if (!meta || typeof meta !== "object") {
      return null;
    }
    const normalized = {
      source: trimString(meta.source),
      registry_id: trimString(meta.registry_id),
      org_id: trimString(meta.org_id),
      org_name: trimString(meta.org_name),
      key_id: trimString(meta.key_id),
      expires_at_utc: trimString(meta.expires_at_utc),
      verified_at_utc: trimString(meta.verified_at_utc),
    };
    if (normalized.source !== "signed" || !normalized.registry_id || !normalized.org_id || !normalized.key_id) {
      return null;
    }
    if (normalized.expires_at_utc) {
      parseRFC3339(normalized.expires_at_utc, "verified helper registry expires_at_utc");
    }
    if (normalized.verified_at_utc) {
      parseRFC3339(normalized.verified_at_utc, "verified helper registry verified_at_utc");
    }
    return normalized;
  }

  function setVerifiedHelperRegistryMeta(meta) {
    const normalized = normalizeVerifiedHelperRegistryMeta(meta);
    verifiedHelperRegistryMeta = normalized;
    try {
      if (normalized) {
        localStorage.setItem(helperRegistryMetaStorageKey, JSON.stringify(normalized, null, 2));
      } else {
        localStorage.removeItem(helperRegistryMetaStorageKey);
      }
    } catch (err) {
      // Helper registry provenance is non-secret; storage can still fail in private windows.
    }
    return normalized;
  }

  function clearVerifiedHelperRegistryMeta() {
    verifiedHelperRegistryMeta = null;
    try {
      localStorage.removeItem(helperRegistryMetaStorageKey);
    } catch (err) {
      // Ignore local storage availability issues.
    }
  }

  function readRawHelperRegistryForPolicy(invite) {
    const registry = readHelperRegistryInput();
    if (isBridgeHelperRegistryArtifact(registry)) {
      throw new Error("Verify the signed helper registry before verifying this bridge invite");
    }
    if (registry && verifiedHelperRegistryMeta) {
      const meta = normalizeVerifiedHelperRegistryMeta(verifiedHelperRegistryMeta);
      const inviteOrgID = trimString(invite && invite.organization && invite.organization.org_id);
      if (meta && meta.org_id !== inviteOrgID) {
        throw new Error(`Signed helper registry organization ${meta.org_id} does not match bridge invite organization ${inviteOrgID}`);
      }
      if (meta && meta.expires_at_utc && parseRFC3339(meta.expires_at_utc, "signed helper registry expires_at_utc") <= new Date()) {
        throw new Error("Signed helper registry is expired");
      }
    }
    return registry;
  }

  function writeTrustStore(store) {
    const normalized = normalizeTrustStore(store);
    els.trustInput.value = JSON.stringify(normalized, null, 2);
    try {
      localStorage.setItem(trustStoreStorageKey, els.trustInput.value);
    } catch (err) {
      // Public keys are not secret; storage can still fail in private windows.
    }
    renderTrustKeys(normalized);
  }

  function writeHelperRegistry(registry, meta) {
    const normalized = normalizeHelperRegistry(registry);
    els.registryInput.value = JSON.stringify(normalized, null, 2);
    try {
      localStorage.setItem(helperRegistryStorageKey, els.registryInput.value);
    } catch (err) {
      // Helper registry data is not secret; storage can still fail in private windows.
    }
    if (meta) {
      setVerifiedHelperRegistryMeta(meta);
    } else {
      clearVerifiedHelperRegistryMeta();
    }
    renderHelperRegistrySummary(normalized);
  }

  function isBridgeHelperRegistryArtifact(value) {
    return Boolean(
      value
      && typeof value === "object"
      && Object.prototype.hasOwnProperty.call(value, "registry_id")
      && Object.prototype.hasOwnProperty.call(value, "registry")
      && Object.prototype.hasOwnProperty.call(value, "signature"),
    );
  }

  function parseRFC3339(value, label) {
    const raw = trimString(value);
    if (!raw) {
      throw new Error(`${label} is required`);
    }
    const date = new Date(raw);
    if (!Number.isFinite(date.getTime())) {
      throw new Error(`${label} is not a valid date`);
    }
    return date;
  }

  function trustDateTimeToUTC(value) {
    const raw = trimString(value);
    if (!raw) {
      return "";
    }
    const date = new Date(raw);
    if (!Number.isFinite(date.getTime())) {
      throw new Error("Key expiry is not a valid date");
    }
    return date.toISOString();
  }

  function normalizeTrustStore(store) {
    if (!store || typeof store !== "object") {
      throw new Error("Trust store must be a JSON object");
    }
    if (store.version !== 1) {
      throw new Error(`Unsupported trust store version ${store.version}`);
    }
    const keys = Array.isArray(store.trusted_keys) ? store.trusted_keys : [];
    const normalized = {
      version: 1,
      trusted_keys: keys.map(normalizeTrustedKey).sort((a, b) => {
        if (a.org_id === b.org_id) {
          return a.key_id.localeCompare(b.key_id);
        }
        return a.org_id.localeCompare(b.org_id);
      }),
    };
    return normalized;
  }

  function normalizeTrustedKey(entry) {
    const normalized = {
      org_id: trimString(entry.org_id),
      org_name: trimString(entry.org_name),
      key_id: trimString(entry.key_id),
      public_key: trimString(entry.public_key),
      added_at_utc: trimString(entry.added_at_utc),
    };
    const expires = trimString(entry.expires_at_utc);
    if (expires) {
      normalized.expires_at_utc = expires;
    }
    const source = trimString(entry.source);
    if (source) {
      normalized.source = source;
    }
    const notes = Array.isArray(entry.notes) ? entry.notes.map(trimString).filter(Boolean) : [];
    if (notes.length > 0) {
      normalized.notes = notes;
    }
    if (entry.disabled === true) {
      normalized.disabled = true;
    }
    return normalized;
  }

  async function validateTrustedKeyEntry(entry, options = {}) {
    const normalized = normalizeTrustedKey(entry);
    if (!normalized.org_id) {
      throw new Error("Trusted key org_id is required");
    }
    if (!normalized.org_name) {
      throw new Error("Trusted key org_name is required");
    }
    const publicKeyBytes = base64URLToBytes(normalized.public_key, "trusted public key");
    if (publicKeyBytes.length !== 32) {
      throw new Error("Trusted public key must be 32 bytes");
    }
    const derivedID = await keyIDFromPublicKey(publicKeyBytes);
    if (normalized.key_id && normalized.key_id !== derivedID) {
      throw new Error(`Trusted key id does not match public key: got ${normalized.key_id}, expected ${derivedID}`);
    }
    normalized.key_id = derivedID;
    if (!normalized.added_at_utc) {
      normalized.added_at_utc = new Date().toISOString();
    } else {
      parseRFC3339(normalized.added_at_utc, "trusted key added_at_utc");
    }
    if (normalized.expires_at_utc) {
      const expiresAt = parseRFC3339(normalized.expires_at_utc, "trusted key expires_at_utc");
      if (options.requireUsable !== false && expiresAt <= new Date()) {
        throw new Error("Trusted key is expired");
      }
    }
    return normalized;
  }

  async function validateTrustStoreKeys(store, options = {}) {
    const normalized = normalizeTrustStore(store);
    const keys = [];
    for (const entry of normalized.trusted_keys) {
      keys.push(await validateTrustedKeyEntry(entry, options));
    }
    return { version: 1, trusted_keys: keys };
  }

  function validateHandoffSignature(signature, label) {
    if (!signature || typeof signature !== "object") {
      throw new Error(`${label} signature is required`);
    }
    if (trimString(signature.alg) !== "ed25519") {
      throw new Error(`${label} signature algorithm must be ed25519`);
    }
    if (!trimString(signature.key_id)) {
      throw new Error(`${label} signature key id is required`);
    }
    const signatureBytes = base64URLToBytes(signature.sig, `${label} signature`);
    if (signatureBytes.length !== 64) {
      throw new Error(`${label} signature has invalid length`);
    }
  }

  async function validateDecodedTextEnvelopePayload(decoded) {
    if (!decoded || typeof decoded !== "object") {
      throw new Error("Text handoff is not valid");
    }
    switch (decoded.kind) {
      case "access-pack":
        if (signedArtifactKind(decoded.payload) !== "access-pack") {
          throw new Error("Access-pack handoff payload is not an access pack");
        }
        validatePackShape(decoded.payload);
        validateHandoffSignature(decoded.payload.signature, "Access pack");
        return;
      case "bridge-invite":
        if (signedArtifactKind(decoded.payload) !== "bridge-invite") {
          throw new Error("Bridge-invite handoff payload is not a bridge invite");
        }
        validateBridgeInviteShape(decoded.payload);
        validateHandoffSignature(decoded.payload.signature, "Bridge invite");
        return;
      case "trust-store":
        await validateTrustStoreKeys(decoded.payload, { requireUsable: false });
        return;
      case "trusted-key":
        await validateTrustedKeyEntry(decoded.payload);
        return;
      case "bridge-helper-registry":
        normalizeHelperRegistry(decoded.payload);
        return;
      case "bridge-helper-registry-signed":
        validateBridgeRegistryArtifactShape(decoded.payload);
        validateHandoffSignature(decoded.payload.signature, "Signed helper registry");
        return;
      default:
        throw new Error(`Unsupported text handoff kind ${decoded.kind}`);
    }
  }

  function normalizeHelperRegistry(registry) {
    if (!registry || typeof registry !== "object") {
      throw new Error("Helper registry must be a JSON object");
    }
    if (registry.version !== 1) {
      throw new Error(`Unsupported helper registry version ${registry.version}`);
    }
    const helpers = Array.isArray(registry.helpers) ? registry.helpers : [];
    return {
      version: 1,
      helpers: helpers.map(normalizeHelperRegistration).sort((a, b) => a.helper_id.localeCompare(b.helper_id)),
    };
  }

  function normalizeHelperRegistration(helper) {
    const status = trimString(helper.status).toLowerCase() || "active";
    if (!["active", "quarantined", "disabled"].includes(status)) {
      throw new Error("Helper registry status must be active, quarantined, or disabled");
    }
    const orgIDs = Array.isArray(helper.org_ids)
      ? helper.org_ids.map(trimString).sort()
      : [];
    const normalized = {
      helper_id: trimString(helper.helper_id),
    };
    if (!normalized.helper_id) {
      throw new Error("Helper registry helper_id is required");
    }
    const displayName = trimString(helper.display_name);
    if (displayName) {
      normalized.display_name = displayName;
    }
    normalized.status = status;
    normalized.org_ids = orgIDs;
    if (normalized.org_ids.length === 0) {
      throw new Error("Helper registry org_ids is required");
    }
    if (normalized.org_ids.some((orgID) => !orgID)) {
      throw new Error("Helper registry org_ids cannot contain empty values");
    }
    const contactURL = trimString(helper.contact_url);
    if (contactURL) {
      normalized.contact_url = contactURL;
    }
    for (const field of ["active_from_utc", "active_until_utc", "updated_at_utc"]) {
      const value = trimString(helper[field]);
      if (value) {
        parseRFC3339(value, `helper registry ${field}`);
        normalized[field] = value;
      }
    }
    if (normalized.active_from_utc && normalized.active_until_utc) {
      const activeFrom = parseRFC3339(normalized.active_from_utc, "helper registry active_from_utc");
      const activeUntil = parseRFC3339(normalized.active_until_utc, "helper registry active_until_utc");
      if (activeUntil <= activeFrom) {
        throw new Error("Helper registry active_until_utc must be after active_from_utc");
      }
    }
    const quarantineReason = trimString(helper.quarantine_reason);
    if (status !== "active" && !quarantineReason) {
      throw new Error("Helper registry quarantine_reason is required unless status is active");
    }
    if (status === "active" && quarantineReason) {
      throw new Error("Helper registry quarantine_reason must be empty when status is active");
    }
    if (quarantineReason) {
      normalized.quarantine_reason = quarantineReason;
    }
    return normalized;
  }

  function normalizeBridgeHelperRegistryArtifact(artifact) {
    const normalized = {
      schema_version: artifact && artifact.schema_version,
      registry_id: trimString(artifact && artifact.registry_id),
      organization: {
        org_id: trimString(artifact && artifact.organization && artifact.organization.org_id),
        name: trimString(artifact && artifact.organization && artifact.organization.name),
      },
      issued_at_utc: trimString(artifact && artifact.issued_at_utc),
      expires_at_utc: trimString(artifact && artifact.expires_at_utc),
      registry: normalizeHelperRegistry(artifact && artifact.registry),
    };
    const homeURL = trimString(artifact && artifact.organization && artifact.organization.home_url);
    if (homeURL) {
      normalized.organization.home_url = homeURL;
    }
    if (artifact && artifact.signature) {
      normalized.signature = {
        alg: trimString(artifact.signature.alg),
        key_id: trimString(artifact.signature.key_id),
        sig: trimString(artifact.signature.sig),
      };
    }
    return normalized;
  }

  function bridgeRegistryArtifactCanonicalPayload(artifact) {
    const normalized = normalizeBridgeHelperRegistryArtifact(artifact);
    delete normalized.signature;
    return new TextEncoder().encode(goCompatibleJSONString(normalized));
  }

  function validateBridgeRegistryArtifactShape(artifact) {
    if (!isBridgeHelperRegistryArtifact(artifact)) {
      throw new Error("Signed helper registry must be a JSON artifact with registry_id, registry, and signature");
    }
    if (artifact.schema_version !== 1) {
      throw new Error(`Unsupported helper registry artifact schema_version ${artifact.schema_version}`);
    }
    if (!trimString(artifact.registry_id)) {
      throw new Error("Signed helper registry id is required");
    }
    if (!artifact.signature || typeof artifact.signature !== "object") {
      throw new Error("Signed helper registry signature is required");
    }
    if (trimString(artifact.signature.alg) !== "ed25519") {
      throw new Error("Unsupported helper registry signature algorithm");
    }
    if (!trimString(artifact.signature.key_id)) {
      throw new Error("Signed helper registry key id is required");
    }
    if (!trimString(artifact.signature.sig)) {
      throw new Error("Signed helper registry signature value is required");
    }
    if (!trimString(artifact.organization && artifact.organization.org_id)) {
      throw new Error("Signed helper registry organization id is required");
    }
    if (!trimString(artifact.organization && artifact.organization.name)) {
      throw new Error("Signed helper registry organization name is required");
    }
    const issuedAt = parseRFC3339(artifact.issued_at_utc, "registry issued_at_utc");
    const expiresAt = parseRFC3339(artifact.expires_at_utc, "registry expires_at_utc");
    if (expiresAt <= issuedAt) {
      throw new Error("Signed helper registry expiry must be after issue time");
    }
    if (expiresAt.getTime() - issuedAt.getTime() > maxBridgeRegistryArtifactLifetimeMS) {
      throw new Error("Signed helper registry lifetime must be 30 days or less");
    }
    if (expiresAt <= new Date()) {
      throw new Error("Signed helper registry is expired");
    }
    normalizeHelperRegistry(artifact.registry);
  }

  function normalizePack(pack) {
    const normalized = {
      schema_version: pack.schema_version,
      pack_id: trimString(pack.pack_id),
      organization: {
        org_id: trimString(pack.organization && pack.organization.org_id),
        name: trimString(pack.organization && pack.organization.name),
      },
      issued_at_utc: trimString(pack.issued_at_utc),
      expires_at_utc: trimString(pack.expires_at_utc),
      intended_audience: trimString(pack.intended_audience),
      sources: Array.isArray(pack.sources) ? pack.sources.map(normalizeSource) : [],
      access_paths: Array.isArray(pack.access_paths) ? pack.access_paths.map(normalizePath) : [],
    };
    const homeURL = trimString(pack.organization && pack.organization.home_url);
    if (homeURL) {
      normalized.organization.home_url = homeURL;
    }
    const safetyNotes = Array.isArray(pack.safety_notes)
      ? pack.safety_notes.map(trimString).filter(Boolean)
      : [];
    if (safetyNotes.length > 0) {
      normalized.safety_notes = safetyNotes;
    }
    normalized.sources.sort((a, b) => {
      if ((a.priority || 0) === (b.priority || 0)) {
        return a.source_id.localeCompare(b.source_id);
      }
      return (a.priority || 0) - (b.priority || 0);
    });
    normalized.access_paths.sort((a, b) => {
      if ((a.priority || 0) === (b.priority || 0)) {
        return a.path_id.localeCompare(b.path_id);
      }
      return (a.priority || 0) - (b.priority || 0);
    });
    return normalized;
  }

  function normalizeBridgeInvite(invite) {
    const normalized = {
      schema_version: invite.schema_version,
      invite_id: trimString(invite.invite_id),
      organization: {
        org_id: trimString(invite.organization && invite.organization.org_id),
        name: trimString(invite.organization && invite.organization.name),
      },
      issued_at_utc: trimString(invite.issued_at_utc),
      expires_at_utc: trimString(invite.expires_at_utc),
      intended_audience: trimString(invite.intended_audience),
      helper: {
        helper_id: trimString(invite.helper && invite.helper.helper_id),
        display_name: trimString(invite.helper && invite.helper.display_name),
      },
      access_paths: Array.isArray(invite.access_paths) ? invite.access_paths.map(normalizePath) : [],
    };
    const homeURL = trimString(invite.organization && invite.organization.home_url);
    if (homeURL) {
      normalized.organization.home_url = homeURL;
    }
    const contactURL = trimString(invite.helper && invite.helper.contact_url);
    if (contactURL) {
      normalized.helper.contact_url = contactURL;
    }
    const helperDescription = trimString(invite.helper && invite.helper.description);
    if (helperDescription) {
      normalized.helper.description = helperDescription;
    }
    const safetyNotes = Array.isArray(invite.safety_notes)
      ? invite.safety_notes.map(trimString).filter(Boolean)
      : [];
    if (safetyNotes.length > 0) {
      normalized.safety_notes = safetyNotes;
    }
    normalized.access_paths.sort((a, b) => {
      if ((a.priority || 0) === (b.priority || 0)) {
        return a.path_id.localeCompare(b.path_id);
      }
      return (a.priority || 0) - (b.priority || 0);
    });
    return normalized;
  }

  function signedArtifactKind(artifact) {
    if (artifact && typeof artifact === "object" && Object.prototype.hasOwnProperty.call(artifact, "invite_id")) {
      return "bridge-invite";
    }
    return "access-pack";
  }

  function normalizeSignedArtifact(artifact) {
    if (signedArtifactKind(artifact) === "bridge-invite") {
      return normalizeBridgeInvite(artifact);
    }
    return normalizePack(artifact);
  }

  function normalizeSignedArtifactForHandoff(artifact) {
    const normalized = normalizeSignedArtifact(artifact);
    if (!artifact || !artifact.signature) {
      throw new Error("Signed recovery artifact signature is required");
    }
    normalized.signature = {
      alg: trimString(artifact.signature.alg),
      key_id: trimString(artifact.signature.key_id),
      sig: trimString(artifact.signature.sig),
    };
    return normalized;
  }

  function normalizeSource(source) {
    const normalized = {
      source_id: trimString(source.source_id),
      kind: trimString(source.kind),
      url: trimString(source.url),
    };
    if (Number.isFinite(source.priority) && source.priority !== 0) {
      normalized.priority = source.priority;
    }
    const description = trimString(source.description);
    if (description) {
      normalized.description = description;
    }
    return normalized;
  }

  function normalizePath(path) {
    const normalized = {
      path_id: trimString(path.path_id),
      kind: trimString(path.kind),
      url: trimString(path.url),
    };
    if (Number.isFinite(path.priority) && path.priority !== 0) {
      normalized.priority = path.priority;
    }
    if (path.requires_external_app === true) {
      normalized.requires_external_app = true;
    }
    const launchHint = trimString(path.launch_hint);
    if (launchHint) {
      normalized.launch_hint = launchHint;
    }
    const description = trimString(path.description);
    if (description) {
      normalized.description = description;
    }
    const safetyNotes = Array.isArray(path.safety_notes)
      ? path.safety_notes.map(trimString).filter(Boolean)
      : [];
    if (safetyNotes.length > 0) {
      normalized.safety_notes = safetyNotes;
    }
    return normalized;
  }

  function goCompatibleJSONString(value) {
    return JSON.stringify(value).replace(/[<>&\u2028\u2029]/g, (char) => {
      switch (char) {
        case "<":
          return "\\u003c";
        case ">":
          return "\\u003e";
        case "&":
          return "\\u0026";
        case "\u2028":
          return "\\u2028";
        case "\u2029":
          return "\\u2029";
        default:
          return char;
      }
    });
  }

  function canonicalPayload(artifact) {
    return new TextEncoder().encode(goCompatibleJSONString(normalizeSignedArtifact(artifact)));
  }

  function validatePackShape(pack) {
    if (!pack || typeof pack !== "object") {
      throw new Error("Pack must be a JSON object");
    }
    if (pack.schema_version !== 0) {
      throw new Error(`Unsupported pack schema_version ${pack.schema_version}`);
    }
    if (!pack.signature || typeof pack.signature !== "object") {
      throw new Error("Pack signature is required");
    }
    if (trimString(pack.signature.alg) !== "ed25519") {
      throw new Error("Unsupported signature algorithm");
    }
    if (!trimString(pack.signature.key_id)) {
      throw new Error("Signature key id is required");
    }
    const issuedAt = parseRFC3339(pack.issued_at_utc, "issued_at_utc");
    const expiresAt = parseRFC3339(pack.expires_at_utc, "expires_at_utc");
    if (expiresAt <= issuedAt) {
      throw new Error("Pack expiry must be after issue time");
    }
    if (expiresAt <= new Date()) {
      throw new Error("Pack is expired");
    }
    if (!trimString(pack.organization && pack.organization.org_id)) {
      throw new Error("Organization id is required");
    }
    if (!Array.isArray(pack.access_paths) || pack.access_paths.length === 0) {
      throw new Error("Pack must include access paths");
    }
  }

  function validateBridgeInviteShape(invite) {
    if (!invite || typeof invite !== "object") {
      throw new Error("Bridge invite must be a JSON object");
    }
    if (invite.schema_version !== 0) {
      throw new Error(`Unsupported bridge invite schema_version ${invite.schema_version}`);
    }
    if (!invite.signature || typeof invite.signature !== "object") {
      throw new Error("Bridge invite signature is required");
    }
    if (trimString(invite.signature.alg) !== "ed25519") {
      throw new Error("Unsupported signature algorithm");
    }
    if (!trimString(invite.signature.key_id)) {
      throw new Error("Signature key id is required");
    }
    const issuedAt = parseRFC3339(invite.issued_at_utc, "issued_at_utc");
    const expiresAt = parseRFC3339(invite.expires_at_utc, "expires_at_utc");
    if (expiresAt <= issuedAt) {
      throw new Error("Bridge invite expiry must be after issue time");
    }
    if (expiresAt.getTime() - issuedAt.getTime() > maxBridgeInviteLifetimeMS) {
      throw new Error("Bridge invite lifetime must be 14 days or less");
    }
    if (expiresAt <= new Date()) {
      throw new Error("Bridge invite is expired");
    }
    if (!trimString(invite.organization && invite.organization.org_id)) {
      throw new Error("Organization id is required");
    }
    if (!trimString(invite.helper && invite.helper.helper_id)) {
      throw new Error("Helper id is required");
    }
    if (!trimString(invite.helper && invite.helper.display_name)) {
      throw new Error("Helper display name is required");
    }
    if (!Array.isArray(invite.access_paths) || invite.access_paths.length === 0) {
      throw new Error("Bridge invite must include access paths");
    }
  }

  function validateSignedArtifactShape(artifact) {
    if (signedArtifactKind(artifact) === "bridge-invite") {
      validateBridgeInviteShape(artifact);
      return;
    }
    validatePackShape(artifact);
  }

  function evaluateHelperRegistryPolicy(invite, registry) {
    if (!registry) {
      return {
        status: "skipped",
        label: "Not loaded",
        badges: ["Registry not loaded"],
      };
    }
    const normalizedRegistry = normalizeHelperRegistry(registry);
    const helperID = trimString(invite.helper && invite.helper.helper_id);
    const orgID = trimString(invite.organization && invite.organization.org_id);
    const helper = normalizedRegistry.helpers.find((entry) => entry.helper_id === helperID);
    if (!helper) {
      throw new Error("Helper registry does not include this helper");
    }
    if (helper.status !== "active") {
      const reason = trimString(helper.quarantine_reason);
      throw new Error(reason ? `Helper is ${helper.status}: ${reason}` : `Helper is ${helper.status}`);
    }
    if (!helper.org_ids.includes(orgID)) {
      throw new Error("Helper registry does not allow this organization");
    }
    const inviteContact = trimString(invite.helper && invite.helper.contact_url);
    if (helper.contact_url && helper.contact_url !== inviteContact) {
      throw new Error("Helper contact does not match the registry");
    }
    const now = new Date();
    const issuedAt = parseRFC3339(invite.issued_at_utc, "issued_at_utc");
    const expiresAt = parseRFC3339(invite.expires_at_utc, "expires_at_utc");
    const activeFrom = helper.active_from_utc ? parseRFC3339(helper.active_from_utc, "helper active_from_utc") : null;
    const activeUntil = helper.active_until_utc ? parseRFC3339(helper.active_until_utc, "helper active_until_utc") : null;
    if (activeFrom && now < activeFrom) {
      throw new Error("Helper active window has not started");
    }
    if (activeFrom && issuedAt < activeFrom) {
      throw new Error("Bridge invite was issued before the helper active window");
    }
    if (activeUntil && activeUntil <= now) {
      throw new Error("Helper active window has ended");
    }
    if (activeUntil && expiresAt > activeUntil) {
      throw new Error("Bridge invite expires after the helper active window");
    }
    return {
      status: "pass",
      label: helper.display_name || "Active",
      helper,
      badges: ["Registry active"],
    };
  }

  async function resolveTrustedKeyForArtifact(trustStore, artifactOrgID, artifactKeyID, label) {
    trustStore = normalizeTrustStore(trustStore);
    artifactOrgID = trimString(artifactOrgID);
    artifactKeyID = trimString(artifactKeyID);
    label = trimString(label) || "Artifact";
    if (!artifactKeyID) {
      throw new Error(`${label} signature key id is required`);
    }
    let sawKey = false;
    let sawWrongOrg = false;
    let sawDisabled = false;
    let sawExpired = false;

    for (const entry of trustStore.trusted_keys) {
      const keyID = trimString(entry.key_id);
      if (keyID !== artifactKeyID) {
        continue;
      }
      sawKey = true;
      if (entry.disabled === true) {
        sawDisabled = true;
        continue;
      }
      if (trimString(entry.org_id) !== artifactOrgID) {
        sawWrongOrg = true;
        continue;
      }
      if (trimString(entry.expires_at_utc)) {
        const keyExpiry = parseRFC3339(entry.expires_at_utc, "trusted key expires_at_utc");
        if (keyExpiry <= new Date()) {
          sawExpired = true;
          continue;
        }
      }
      const publicKeyBytes = base64URLToBytes(entry.public_key, "trusted public key");
      if (publicKeyBytes.length !== 32) {
        throw new Error("Trusted public key has invalid length");
      }
      const derivedID = await keyIDFromPublicKey(publicKeyBytes);
      if (derivedID !== keyID) {
        throw new Error("Trusted public key does not match key id");
      }
      return {
        entry: {
          org_id: trimString(entry.org_id),
          org_name: trimString(entry.org_name),
          key_id: keyID,
          public_key: trimString(entry.public_key),
        },
        publicKeyBytes,
      };
    }

    if (sawDisabled) {
      throw new Error("Trusted key is disabled");
    }
    if (sawWrongOrg) {
      throw new Error("Trusted key belongs to a different organization");
    }
    if (sawExpired) {
      throw new Error("Trusted key is expired");
    }
    if (sawKey) {
      throw new Error("Trusted key is not usable");
    }
    throw new Error(`${label} signer is not in the trust store`);
  }

  async function resolveTrustedKey(artifact, trustStore) {
    const artifactKind = signedArtifactKind(artifact);
    const label = artifactKind === "bridge-invite" ? "Bridge invite" : "Pack";
    return resolveTrustedKeyForArtifact(
      trustStore,
      artifact.organization && artifact.organization.org_id,
      artifact.signature && artifact.signature.key_id,
      label,
    );
  }

  async function resolveTrustedRegistryKey(artifact, trustStore) {
    return resolveTrustedKeyForArtifact(
      trustStore,
      artifact.organization && artifact.organization.org_id,
      artifact.signature && artifact.signature.key_id,
      "Signed helper registry",
    );
  }

  async function verifySignaturePayload(signature, publicKeyBytes, payloadBytes, label) {
    if (!crypto || !crypto.subtle) {
      throw new Error("Web Crypto is unavailable in this browser context");
    }
    const signatureBytes = base64URLToBytes(signature && signature.sig, "signature");
    if (signatureBytes.length !== 64) {
      throw new Error("Signature has invalid length");
    }
    let publicKey;
    try {
      publicKey = await crypto.subtle.importKey(
        "raw",
        publicKeyBytes,
        { name: "Ed25519" },
        false,
        ["verify"],
      );
    } catch (err) {
      throw new Error("This browser does not support Ed25519 verification");
    }
    const ok = await crypto.subtle.verify(
      { name: "Ed25519" },
      publicKey,
      signatureBytes,
      payloadBytes,
    );
    if (!ok) {
      throw new Error(`${label} signature verification failed`);
    }
  }

  async function verifySignature(artifact, publicKeyBytes) {
    const label = signedArtifactKind(artifact) === "bridge-invite" ? "Bridge invite" : "Pack";
    await verifySignaturePayload(artifact.signature, publicKeyBytes, canonicalPayload(artifact), label);
  }

  async function verifyBridgeRegistryArtifactSignature(artifact, publicKeyBytes) {
    await verifySignaturePayload(
      artifact.signature,
      publicKeyBytes,
      bridgeRegistryArtifactCanonicalPayload(artifact),
      "Signed helper registry",
    );
  }

  async function buildTrustedKeyEntry(existingStore) {
    const orgID = trimString(els.trustOrgID.value);
    const orgName = trimString(els.trustOrgName.value);
    if (!orgID) {
      throw new Error("Org ID is required");
    }
    if (!orgName) {
      throw new Error("Org name is required");
    }
    const publicKey = trimString(els.trustPublicKey.value);
    const publicKeyBytes = base64URLToBytes(publicKey, "trusted public key");
    if (publicKeyBytes.length !== 32) {
      throw new Error("Trusted public key must be 32 bytes");
    }
    const keyID = await keyIDFromPublicKey(publicKeyBytes);
    const expiresAtUTC = trustDateTimeToUTC(els.trustExpires.value);
    if (expiresAtUTC && new Date(expiresAtUTC) <= new Date()) {
      throw new Error("Key expiry must be in the future");
    }
    const existing = existingStore.trusted_keys.find((entry) => {
      return entry.org_id === orgID && entry.key_id === keyID;
    });
    const entry = {
      org_id: orgID,
      org_name: orgName,
      key_id: keyID,
      public_key: publicKey,
      added_at_utc: existing ? existing.added_at_utc : new Date().toISOString(),
    };
    if (expiresAtUTC) {
      entry.expires_at_utc = expiresAtUTC;
    }
    const source = trimString(els.trustSource.value);
    if (source) {
      entry.source = source;
    }
    return entry;
  }

  function resetTrustFields() {
    els.trustOrgID.value = "";
    els.trustOrgName.value = "";
    els.trustPublicKey.value = "";
    els.trustExpires.value = "";
    els.trustSource.value = "";
  }

  function renderTrustKeys(store) {
    clearNode(els.trustKeyList);
    let normalized;
    try {
      normalized = normalizeTrustStore(store || readTrustStoreInput());
    } catch (err) {
      const message = document.createElement("p");
      message.className = "recover-empty";
      message.textContent = "Trust store JSON is not valid yet.";
      els.trustKeyList.appendChild(message);
      return;
    }
    if (normalized.trusted_keys.length === 0) {
      const empty = document.createElement("p");
      empty.className = "recover-empty";
      empty.textContent = "No trusted keys added.";
      els.trustKeyList.appendChild(empty);
      return;
    }
    for (const entry of normalized.trusted_keys) {
      const item = document.createElement("article");
      item.className = "trust-key-card";
      const meta = document.createElement("div");
      const title = document.createElement("strong");
      title.textContent = entry.org_name || entry.org_id;
      const detail = document.createElement("span");
      detail.textContent = `${entry.org_id} / ${entry.key_id}`;
      meta.append(title, detail);
      const actions = document.createElement("div");
      actions.className = "trust-key-card__actions";
      const fillBtn = document.createElement("button");
      fillBtn.className = "btn secondary";
      fillBtn.type = "button";
      fillBtn.textContent = "Edit";
      fillBtn.addEventListener("click", () => fillTrustFields(entry));
      const removeBtn = document.createElement("button");
      removeBtn.className = "btn secondary";
      removeBtn.type = "button";
      removeBtn.textContent = "Remove";
      removeBtn.addEventListener("click", () => removeTrustedKey(entry.org_id, entry.key_id));
      const copyTextBtn = document.createElement("button");
      copyTextBtn.className = "btn secondary";
      copyTextBtn.type = "button";
      copyTextBtn.textContent = "Copy Text";
      copyTextBtn.addEventListener("click", async () => {
        try {
          await exportTrustedKeyText(entry, copyTextBtn);
        } catch (err) {
          setStatus("bad", "Trusted key export failed", err.message || String(err));
        }
      });
      actions.append(fillBtn, copyTextBtn, removeBtn);
      item.append(meta, actions);
      els.trustKeyList.appendChild(item);
    }
  }

  function renderHelperRegistrySummary(registry) {
    clearNode(els.registrySummary);
    let normalized;
    try {
      normalized = registry || readHelperRegistryInput();
      if (!normalized) {
        const empty = document.createElement("p");
        empty.className = "recover-empty";
        empty.textContent = "No helper registry loaded.";
        els.registrySummary.appendChild(empty);
        return;
      }
      if (isBridgeHelperRegistryArtifact(normalized)) {
        renderSignedHelperRegistryPending(normalized);
        return;
      }
      normalized = normalizeHelperRegistry(normalized);
    } catch (err) {
      const message = document.createElement("p");
      message.className = "recover-empty";
      message.textContent = "Helper registry JSON is not valid yet.";
      els.registrySummary.appendChild(message);
      return;
    }
    const counts = normalized.helpers.reduce((acc, helper) => {
      acc[helper.status] = (acc[helper.status] || 0) + 1;
      return acc;
    }, { active: 0, quarantined: 0, disabled: 0 });
    const countRow = document.createElement("div");
    countRow.className = "registry-summary__counts";
    for (const status of ["active", "quarantined", "disabled"]) {
      const badge = document.createElement("span");
      badge.className = "registry-summary__count";
      badge.dataset.status = status;
      badge.textContent = `${formatRegistryStatus(status)} ${counts[status] || 0}`;
      countRow.appendChild(badge);
    }
    els.registrySummary.appendChild(countRow);
    if (verifiedHelperRegistryMeta) {
      const meta = normalizeVerifiedHelperRegistryMeta(verifiedHelperRegistryMeta);
      if (meta) {
        const provenance = document.createElement("p");
        provenance.className = "recover-empty";
        provenance.textContent = `Verified signed registry ${meta.registry_id} for ${meta.org_name || meta.org_id} with key ${meta.key_id}.`;
        els.registrySummary.appendChild(provenance);
      }
    }
    if (normalized.helpers.length === 0) {
      const empty = document.createElement("p");
      empty.className = "recover-empty";
      empty.textContent = "No helpers registered.";
      els.registrySummary.appendChild(empty);
      return;
    }
    const list = document.createElement("div");
    list.className = "registry-helper-list";
    for (const helper of normalized.helpers.slice(0, 6)) {
      const item = document.createElement("article");
      item.className = "registry-helper-card";
      item.dataset.status = helper.status;
      const title = document.createElement("strong");
      title.textContent = helper.display_name || helper.helper_id;
      const detail = document.createElement("span");
      detail.textContent = `${helper.helper_id} / ${helper.org_ids.join(", ")}`;
      const status = document.createElement("span");
      status.className = "registry-helper-card__status";
      status.textContent = formatRegistryStatus(helper.status);
      item.append(title, detail, status);
      if (helper.quarantine_reason) {
        const reason = document.createElement("p");
        reason.textContent = helper.quarantine_reason;
        item.appendChild(reason);
      }
      list.appendChild(item);
    }
    els.registrySummary.appendChild(list);
    if (normalized.helpers.length > 6) {
      const overflow = document.createElement("p");
      overflow.className = "recover-empty";
      overflow.textContent = `${normalized.helpers.length - 6} more helper entries are loaded.`;
      els.registrySummary.appendChild(overflow);
    }
  }

  function renderSignedHelperRegistryPending(artifact) {
    let normalizedArtifact;
    try {
      normalizedArtifact = normalizeBridgeHelperRegistryArtifact(artifact);
    } catch (err) {
      const message = document.createElement("p");
      message.className = "recover-empty";
      message.textContent = "Signed helper registry JSON is not valid yet.";
      els.registrySummary.appendChild(message);
      return;
    }
    const pending = document.createElement("p");
    pending.className = "recover-empty";
    pending.textContent = `${normalizedArtifact.organization.name || normalizedArtifact.organization.org_id} signed registry ${normalizedArtifact.registry_id}. Verify it before using bridge paths.`;
    els.registrySummary.appendChild(pending);
    const counts = normalizedArtifact.registry.helpers.reduce((acc, helper) => {
      acc[helper.status] = (acc[helper.status] || 0) + 1;
      return acc;
    }, { active: 0, quarantined: 0, disabled: 0 });
    const countRow = document.createElement("div");
    countRow.className = "registry-summary__counts";
    for (const status of ["active", "quarantined", "disabled"]) {
      const badge = document.createElement("span");
      badge.className = "registry-summary__count";
      badge.dataset.status = status;
      badge.textContent = `${formatRegistryStatus(status)} ${counts[status] || 0}`;
      countRow.appendChild(badge);
    }
    els.registrySummary.appendChild(countRow);
  }

  function formatRegistryStatus(status) {
    const normalized = trimString(status).toLowerCase();
    return normalized ? normalized.charAt(0).toUpperCase() + normalized.slice(1) : "Unknown";
  }

  function fillTrustFields(entry) {
    els.trustOrgID.value = entry.org_id;
    els.trustOrgName.value = entry.org_name;
    els.trustPublicKey.value = entry.public_key;
    els.trustSource.value = entry.source || "";
    if (entry.expires_at_utc) {
      const date = new Date(entry.expires_at_utc);
      if (Number.isFinite(date.getTime())) {
        els.trustExpires.value = date.toISOString().slice(0, 16);
      }
    } else {
      els.trustExpires.value = "";
    }
  }

  function removeTrustedKey(orgID, keyID) {
    const store = normalizeTrustStore(readTrustStoreInput());
    store.trusted_keys = store.trusted_keys.filter((entry) => {
      return !(entry.org_id === orgID && entry.key_id === keyID);
    });
    writeTrustStore(store);
    setStatus("idle", "Trusted key removed", "The local trust store JSON has been updated.");
  }

  async function exportTrustedKeyText(entry, button) {
    const text = encodeTextEnvelope("trusted-key", await validateTrustedKeyEntry(entry));
    els.handoffInput.value = text;
    await copyText(text, button);
    setStatus("idle", "Trusted key text ready", "This GPMREC1 text can be pasted into another recovery page.");
  }

  function renderFacts(artifact, trustedKey, helperPolicy) {
    clearNode(els.factsGrid);
    const kind = signedArtifactKind(artifact);
    const normalized = normalizeSignedArtifact(artifact);
    const facts = [
      ["Type", kind === "bridge-invite" ? "Bridge invite" : "Access pack"],
      ["Organization", normalized.organization.name || normalized.organization.org_id],
      ["Org ID", normalized.organization.org_id],
      [kind === "bridge-invite" ? "Invite ID" : "Pack ID", kind === "bridge-invite" ? normalized.invite_id : normalized.pack_id],
      ["Signer", trustedKey.key_id],
      ["Expires", normalized.expires_at_utc],
      ["Audience", normalized.intended_audience],
    ];
    if (kind === "bridge-invite") {
      facts.push(["Helper", normalized.helper.display_name || normalized.helper.helper_id]);
      facts.push(["Helper registry", helperPolicy ? helperPolicy.label : "Not loaded"]);
    }
    for (const [label, value] of facts) {
      const item = document.createElement("article");
      const labelNode = document.createElement("span");
      const valueNode = document.createElement("strong");
      labelNode.textContent = label;
      valueNode.textContent = value || "Not set";
      item.append(labelNode, valueNode);
      els.factsGrid.appendChild(item);
    }
  }

  function renderPaths(artifact, helperPolicy) {
    clearNode(els.pathsList);
    const kind = signedArtifactKind(artifact);
    const normalized = normalizeSignedArtifact(artifact);
    const paths = normalized.access_paths;
    els.pathCount.textContent = String(paths.length);
    if (kind === "bridge-invite") {
      renderBridgeHelperCard(normalized, helperPolicy);
    }
    if (paths.length === 0) {
      const empty = document.createElement("p");
      empty.className = "recover-empty";
      empty.textContent = kind === "bridge-invite" ? "No bridge paths in this invite." : "No access paths in this pack.";
      els.pathsList.appendChild(empty);
      return;
    }
    for (const path of paths) {
      const item = document.createElement("article");
      item.className = "recover-path";

      const head = document.createElement("div");
      head.className = "recover-path__head";
      const title = document.createElement("h3");
      title.textContent = path.description || path.path_id;
      const badges = document.createElement("div");
      badges.className = "recover-badges";
      for (const text of pathBadges(path, kind)) {
        const badge = document.createElement("span");
        badge.textContent = text;
        badges.appendChild(badge);
      }
      head.append(title, badges);

      const url = document.createElement("p");
      url.className = "recover-url";
      url.textContent = path.url;

      const actions = document.createElement("div");
      actions.className = "recover-path__actions";
      const copyBtn = document.createElement("button");
      copyBtn.className = "btn secondary";
      copyBtn.type = "button";
      copyBtn.textContent = "Copy";
      copyBtn.addEventListener("click", () => copyText(path.url, copyBtn));
      actions.appendChild(copyBtn);
      const href = safeHref(path.url);
      if (href) {
        const openLink = document.createElement("a");
        openLink.className = "btn secondary";
        openLink.href = href;
        openLink.target = "_blank";
        openLink.rel = "noreferrer noopener";
        openLink.textContent = "Open";
        actions.appendChild(openLink);
      }

      item.append(head, url, actions);
      if (Array.isArray(path.safety_notes) && path.safety_notes.length > 0) {
        const notes = document.createElement("ul");
        notes.className = "recover-notes";
        for (const note of path.safety_notes) {
          const li = document.createElement("li");
          li.textContent = note;
          notes.appendChild(li);
        }
        item.appendChild(notes);
      }
      els.pathsList.appendChild(item);
    }
  }

  function renderBridgeHelperCard(invite, helperPolicy) {
    const item = document.createElement("article");
    item.className = "recover-path recover-path--helper";

    const head = document.createElement("div");
    head.className = "recover-path__head";
    const title = document.createElement("h3");
    title.textContent = invite.helper.display_name || invite.helper.helper_id;
    const badges = document.createElement("div");
    badges.className = "recover-badges";
    const helperBadges = ["Signed helper", "Org verified"];
    if (helperPolicy && Array.isArray(helperPolicy.badges)) {
      helperBadges.push(...helperPolicy.badges);
    }
    for (const text of helperBadges) {
      const badge = document.createElement("span");
      badge.textContent = text;
      badges.appendChild(badge);
    }
    head.append(title, badges);

    const details = document.createElement("p");
    details.className = "recover-url";
    details.textContent = invite.helper.description || `Helper ID: ${invite.helper.helper_id}`;

    const actions = document.createElement("div");
    actions.className = "recover-path__actions";
    const copyInviteBtn = helperButton("Copy Invite ID", () => copyText(invite.invite_id, copyInviteBtn));
    const copyHelperBtn = helperButton("Copy Helper ID", () => copyText(invite.helper.helper_id, copyHelperBtn));
    actions.append(copyInviteBtn, copyHelperBtn);

    if (invite.helper.contact_url) {
      const copyContactBtn = helperButton("Copy Contact", () => copyText(invite.helper.contact_url, copyContactBtn));
      actions.appendChild(copyContactBtn);
      const href = safeHref(invite.helper.contact_url);
      if (href) {
        const openLink = document.createElement("a");
        openLink.className = "btn secondary";
        openLink.href = href;
        if (href.startsWith("http")) {
          openLink.target = "_blank";
          openLink.rel = "noreferrer noopener";
        }
        openLink.textContent = href.startsWith("mailto:") ? "Email" : "Open Contact";
        actions.appendChild(openLink);
      }
    }

    item.append(head, details, actions);
    if (Array.isArray(invite.safety_notes) && invite.safety_notes.length > 0) {
      const notes = document.createElement("ul");
      notes.className = "recover-notes";
      for (const note of invite.safety_notes) {
        const li = document.createElement("li");
        li.textContent = note;
        notes.appendChild(li);
      }
      item.appendChild(notes);
    }
    els.pathsList.appendChild(item);
  }

  function helperButton(text, onClick) {
    const button = document.createElement("button");
    button.className = "btn secondary";
    button.type = "button";
    button.textContent = text;
    button.addEventListener("click", onClick);
    return button;
  }

  function pathBadges(path, artifactKind) {
    const badges = [artifactKind === "bridge-invite" ? "Signed bridge" : "Trusted", path.kind || "path"];
    if (path.requires_external_app) {
      badges.push("External app");
    }
    if (/\.onion$/i.test(URLSafe(path.url).hostname)) {
      badges.push("Onion");
    }
    return badges;
  }

  function URLSafe(rawURL) {
    try {
      return new URL(rawURL);
    } catch (err) {
      return { protocol: "", hostname: "" };
    }
  }

  function safeHref(rawURL) {
    const parsed = URLSafe(rawURL);
    if (parsed.protocol === "http:" || parsed.protocol === "https:" || parsed.protocol === "mailto:") {
      return rawURL;
    }
    return "";
  }

  async function copyText(value, button) {
    try {
      await navigator.clipboard.writeText(value);
      button.textContent = "Copied";
      setTimeout(() => {
        button.textContent = "Copy";
      }, 1400);
    } catch (err) {
      setStatus("warn", "Copy unavailable", "Select the URL text and copy it manually.");
    }
  }

  async function verifyCurrentInputs() {
    clearNode(els.factsGrid);
    clearNode(els.pathsList);
    els.pathCount.textContent = "0";
    setStatus("idle", "Verifying", "Checking trust store, expiry, key id, and signature.");
    const artifact = parseJSONInput(els.packInput.value, "Signed recovery artifact");
    const trustStore = readTrustStoreInput();
    validateSignedArtifactShape(artifact);
    const trusted = await resolveTrustedKey(artifact, trustStore);
    await verifySignature(artifact, trusted.publicKeyBytes);
    const kind = signedArtifactKind(artifact);
    const normalized = normalizeSignedArtifact(artifact);
    const helperPolicy = kind === "bridge-invite" ? evaluateHelperRegistryPolicy(normalized, readRawHelperRegistryForPolicy(normalized)) : null;
    const helperPolicyDetail = helperPolicy && helperPolicy.status === "pass"
      ? " and an active helper registry entry"
      : "";
    const helperRegistryMissing = helperPolicy && helperPolicy.status === "skipped"
      ? " Helper registry was not loaded."
      : "";
    setStatus(
      "good",
      kind === "bridge-invite" ? "Trusted bridge invite" : "Trusted pack",
      `${normalized.organization.name} signed this ${kind === "bridge-invite" ? "bridge invite" : "pack"} with trusted key ${trusted.entry.key_id}${helperPolicyDetail}.${helperRegistryMissing}`,
    );
    renderFacts(normalized, trusted.entry, helperPolicy);
    renderPaths(normalized, helperPolicy);
  }

  async function verifySignedHelperRegistryInput() {
    const artifact = parseJSONInput(els.registryInput.value, "Signed helper registry");
    if (!isBridgeHelperRegistryArtifact(artifact)) {
      throw new Error("Paste or import a signed helper registry artifact first");
    }
    validateBridgeRegistryArtifactShape(artifact);
    const trusted = await resolveTrustedRegistryKey(artifact, readTrustStoreInput());
    await verifyBridgeRegistryArtifactSignature(artifact, trusted.publicKeyBytes);
    const normalized = normalizeBridgeHelperRegistryArtifact(artifact);
    writeHelperRegistry(normalized.registry, {
      source: "signed",
      registry_id: normalized.registry_id,
      org_id: normalized.organization.org_id,
      org_name: normalized.organization.name,
      key_id: trusted.entry.key_id,
      expires_at_utc: normalized.expires_at_utc,
      verified_at_utc: new Date().toISOString(),
    });
    setStatus(
      "good",
      "Trusted helper registry",
      `${normalized.organization.name} signed helper registry ${normalized.registry_id} with trusted key ${trusted.entry.key_id}.`,
    );
  }

  async function readFileInto(fileInput, target) {
    const file = fileInput.files && fileInput.files[0];
    if (!file) {
      return;
    }
    target.value = await file.text();
  }

  async function addTrustedKeyFromFields() {
    const store = normalizeTrustStore(readTrustStoreInput());
    const entry = await buildTrustedKeyEntry(store);
    const nextKeys = store.trusted_keys.filter((existing) => {
      return !(existing.org_id === entry.org_id && existing.key_id === entry.key_id);
    });
    nextKeys.push(entry);
    writeTrustStore({ version: 1, trusted_keys: nextKeys });
    resetTrustFields();
    setStatus("idle", "Trusted key added", `${entry.org_name} is now in this local trust store.`);
  }

  async function exportTextEnvelope(kind) {
    let payload;
    if (kind === "access-pack") {
      const artifact = parseJSONInput(els.packInput.value, "Signed recovery artifact");
      kind = signedArtifactKind(artifact);
      payload = normalizeSignedArtifactForHandoff(artifact);
      await validateDecodedTextEnvelopePayload({ kind, payload });
    } else if (kind === "trust-store") {
      payload = await validateTrustStoreKeys(readTrustStoreInput(), { requireUsable: false });
    } else if (kind === "bridge-helper-registry") {
      const registry = readHelperRegistryInput();
      if (!registry) {
        throw new Error("Helper registry is empty");
      }
      if (isBridgeHelperRegistryArtifact(registry)) {
        kind = "bridge-helper-registry-signed";
        payload = normalizeBridgeHelperRegistryArtifact(registry);
        await validateDecodedTextEnvelopePayload({ kind, payload });
      } else {
        payload = normalizeHelperRegistry(registry);
      }
    } else {
      throw new Error(`Unsupported export kind ${kind}`);
    }
    const text = encodeTextEnvelope(kind, payload);
    els.handoffInput.value = text;
    return text;
  }

  async function importTextEnvelope() {
    const decoded = decodeTextEnvelope(els.handoffInput.value);
    await validateDecodedTextEnvelopePayload(decoded);
    if (decoded.kind === "access-pack") {
      els.packInput.value = JSON.stringify(decoded.payload, null, 2);
      setStatus("idle", "Pack text imported", "Verify it against the trust store before using any path.");
      return;
    }
    if (decoded.kind === "bridge-invite") {
      els.packInput.value = JSON.stringify(decoded.payload, null, 2);
      setStatus("idle", "Bridge invite text imported", "Verify it against the trust store before using any helper path.");
      return;
    }
    if (decoded.kind === "trust-store") {
      const store = await validateTrustStoreKeys(decoded.payload, { requireUsable: false });
      writeTrustStore(store);
      setStatus("idle", "Trust store text imported", "The local trust store JSON has been updated.");
      return;
    }
    if (decoded.kind === "bridge-helper-registry") {
      writeHelperRegistry(decoded.payload);
      setStatus("idle", "Helper registry text imported", "Bridge invite verification will enforce helper status.");
      return;
    }
    if (decoded.kind === "bridge-helper-registry-signed") {
      els.registryInput.value = JSON.stringify(decoded.payload, null, 2);
      try {
        localStorage.removeItem(helperRegistryStorageKey);
      } catch (err) {
        // Ignore local storage availability issues.
      }
      clearVerifiedHelperRegistryMeta();
      renderHelperRegistrySummary(decoded.payload);
      setStatus("idle", "Signed helper registry text imported", "Verify it against the trust store before using bridge paths.");
      return;
    }
    if (decoded.kind === "trusted-key") {
      const store = await validateTrustStoreKeys(readTrustStoreInput(), { requireUsable: false });
      const entry = await validateTrustedKeyEntry(decoded.payload);
      if (!entry.org_id || !entry.org_name || !entry.key_id || !entry.public_key) {
        throw new Error("Trusted-key handoff is missing required fields");
      }
      const nextKeys = store.trusted_keys.filter((existing) => {
        return !(existing.org_id === entry.org_id && existing.key_id === entry.key_id);
      });
      nextKeys.push(entry);
      writeTrustStore({ version: 1, trusted_keys: nextKeys });
      setStatus("idle", "Trusted key text imported", `${entry.org_name} is now in this local trust store.`);
    }
  }

  async function scanQRCodeWithNativeDetector(file) {
    const detectorCtor = window.BarcodeDetector;
    if (!detectorCtor) {
      return "";
    }
    const detector = new detectorCtor({ formats: ["qr_code"] });
    const bitmap = await createImageBitmap(file);
    let codes;
    try {
      codes = await detector.detect(bitmap);
    } finally {
      if (typeof bitmap.close === "function") {
        bitmap.close();
      }
    }
    if (!codes || codes.length === 0) {
      return "";
    }
    return trimString(codes[0].rawValue);
  }

  async function imageDataFromFile(file) {
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    if (!ctx) {
      throw new Error("Browser canvas support is required for QR scanning");
    }
    if (typeof createImageBitmap === "function") {
      const bitmap = await createImageBitmap(file);
      try {
        canvas.width = bitmap.width;
        canvas.height = bitmap.height;
        ctx.drawImage(bitmap, 0, 0);
        return ctx.getImageData(0, 0, canvas.width, canvas.height);
      } finally {
        if (typeof bitmap.close === "function") {
          bitmap.close();
        }
      }
    }
    const url = URL.createObjectURL(file);
    try {
      const image = await new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = () => resolve(img);
        img.onerror = () => reject(new Error("QR image could not be loaded"));
        img.src = url;
      });
      canvas.width = image.naturalWidth || image.width;
      canvas.height = image.naturalHeight || image.height;
      ctx.drawImage(image, 0, 0);
      return ctx.getImageData(0, 0, canvas.width, canvas.height);
    } finally {
      URL.revokeObjectURL(url);
    }
  }

  async function scanQRCodeWithBundledScanner(file) {
    if (typeof window.jsQR !== "function") {
      return "";
    }
    const imageData = await imageDataFromFile(file);
    const result = window.jsQR(imageData.data, imageData.width, imageData.height, {
      inversionAttempts: "attemptBoth",
    });
    return result ? trimString(result.data) : "";
  }

  async function scanQRCodeImage() {
    const file = els.qrImageFile.files && els.qrImageFile.files[0];
    if (!file) {
      throw new Error("Choose a QR image first");
    }
    let value = "";
    try {
      value = await scanQRCodeWithNativeDetector(file);
    } catch (err) {
      // Fall through to bundled jsQR when the native detector is unavailable
      // for the selected image type or platform.
    }
    if (!value) {
      value = await scanQRCodeWithBundledScanner(file);
    }
    if (!value) {
      throw new Error("No QR code text was found in that image");
    }
    els.handoffInput.value = value;
    await importTextEnvelope();
  }

  els.verifyBtn.addEventListener("click", async () => {
    els.verifyBtn.disabled = true;
    try {
      await verifyCurrentInputs();
    } catch (err) {
      setStatus("bad", "Verification failed", err.message || String(err));
      clearNode(els.factsGrid);
      clearNode(els.pathsList);
      els.pathCount.textContent = "0";
    } finally {
      els.verifyBtn.disabled = false;
    }
  });

  els.clearBtn.addEventListener("click", () => {
    els.packInput.value = "";
    els.trustInput.value = "";
    els.registryInput.value = "";
    els.packFile.value = "";
    els.trustFile.value = "";
    els.registryFile.value = "";
    els.handoffInput.value = "";
    resetQRPreview();
    resetTrustFields();
    try {
      localStorage.removeItem(trustStoreStorageKey);
      localStorage.removeItem(helperRegistryStorageKey);
      localStorage.removeItem(helperRegistryMetaStorageKey);
    } catch (err) {
      // Ignore local storage cleanup errors.
    }
    verifiedHelperRegistryMeta = null;
    renderTrustKeys({ version: 1, trusted_keys: [] });
    renderHelperRegistrySummary(null);
    clearNode(els.factsGrid);
    clearNode(els.pathsList);
    els.pathCount.textContent = "0";
    setStatus("idle", "Waiting for pack", "Import or paste a signed pack and a trusted organization key store.");
  });

  els.packFile.addEventListener("change", async () => {
    await readFileInto(els.packFile, els.packInput);
  });

  els.trustFile.addEventListener("change", async () => {
    await readFileInto(els.trustFile, els.trustInput);
    try {
      const store = await validateTrustStoreKeys(readTrustStoreInput(), { requireUsable: false });
      writeTrustStore(store);
    } catch (err) {
      setStatus("bad", "Trust import failed", err.message || String(err));
    }
  });

  els.registryFile.addEventListener("change", async () => {
    await readFileInto(els.registryFile, els.registryInput);
    try {
      const registry = readHelperRegistryInput();
      if (isBridgeHelperRegistryArtifact(registry)) {
        try {
          localStorage.removeItem(helperRegistryStorageKey);
        } catch (err) {
          // Ignore local storage availability issues.
        }
        clearVerifiedHelperRegistryMeta();
        renderHelperRegistrySummary(registry);
        setStatus("idle", "Signed helper registry imported", "Verify it against the trust store before using bridge paths.");
        return;
      }
      writeHelperRegistry(registry);
      setStatus("idle", "Helper registry imported", "Bridge invite verification will enforce helper status.");
    } catch (err) {
      setStatus("bad", "Registry import failed", err.message || String(err));
    }
  });

  els.trustInput.addEventListener("input", () => {
    renderTrustKeys();
  });

  els.registryInput.addEventListener("input", () => {
    try {
      const registry = readHelperRegistryInput();
      if (registry) {
        if (isBridgeHelperRegistryArtifact(registry)) {
          localStorage.removeItem(helperRegistryStorageKey);
          clearVerifiedHelperRegistryMeta();
          renderHelperRegistrySummary(registry);
          return;
        }
        const normalized = normalizeHelperRegistry(registry);
        localStorage.setItem(helperRegistryStorageKey, JSON.stringify(normalized, null, 2));
        clearVerifiedHelperRegistryMeta();
        renderHelperRegistrySummary(normalized);
      } else {
        localStorage.removeItem(helperRegistryStorageKey);
        clearVerifiedHelperRegistryMeta();
        renderHelperRegistrySummary(null);
      }
    } catch (err) {
      renderHelperRegistrySummary({});
    }
  });

  els.verifyRegistryBtn.addEventListener("click", async () => {
    els.verifyRegistryBtn.disabled = true;
    try {
      setStatus("idle", "Verifying helper registry", "Checking registry signer, expiry, trusted key, and signature.");
      await verifySignedHelperRegistryInput();
    } catch (err) {
      setStatus("bad", "Registry verification failed", err.message || String(err));
    } finally {
      els.verifyRegistryBtn.disabled = false;
    }
  });

  els.trustAddBtn.addEventListener("click", async () => {
    els.trustAddBtn.disabled = true;
    try {
      await addTrustedKeyFromFields();
    } catch (err) {
      setStatus("bad", "Could not add key", err.message || String(err));
    } finally {
      els.trustAddBtn.disabled = false;
    }
  });

  els.trustResetBtn.addEventListener("click", () => {
    resetTrustFields();
  });

  els.trustCopyBtn.addEventListener("click", async () => {
    try {
      const store = await validateTrustStoreKeys(readTrustStoreInput(), { requireUsable: false });
      writeTrustStore(store);
      await copyText(els.trustInput.value, els.trustCopyBtn);
      setStatus("idle", "Trust store copied", "The current trust store JSON is on the clipboard.");
    } catch (err) {
      setStatus("bad", "Copy failed", err.message || String(err));
    }
  });

  els.trustDownloadBtn.addEventListener("click", async () => {
    try {
      const store = await validateTrustStoreKeys(readTrustStoreInput(), { requireUsable: false });
      writeTrustStore(store);
      const blob = new Blob([els.trustInput.value + "\n"], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "gpm-recovery-trust-store.json";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      setStatus("idle", "Trust store ready", "The current trust store JSON was prepared for download.");
    } catch (err) {
      setStatus("bad", "Download failed", err.message || String(err));
    }
  });

  els.exportPackTextBtn.addEventListener("click", async () => {
    try {
      const text = await exportTextEnvelope("access-pack");
      await copyText(text, els.exportPackTextBtn);
      setStatus("idle", "Pack text ready", "The signed pack handoff text is on the clipboard.");
    } catch (err) {
      setStatus("bad", "Pack export failed", err.message || String(err));
    }
  });

  els.exportStoreTextBtn.addEventListener("click", async () => {
    try {
      const text = await exportTextEnvelope("trust-store");
      await copyText(text, els.exportStoreTextBtn);
      setStatus("idle", "Trust store text ready", "The trust-store handoff text is on the clipboard.");
    } catch (err) {
      setStatus("bad", "Store export failed", err.message || String(err));
    }
  });

  els.exportRegistryTextBtn.addEventListener("click", async () => {
    try {
      const text = await exportTextEnvelope("bridge-helper-registry");
      await copyText(text, els.exportRegistryTextBtn);
      setStatus("idle", "Helper registry text ready", "The helper-registry handoff text is on the clipboard.");
    } catch (err) {
      setStatus("bad", "Registry export failed", err.message || String(err));
    }
  });

  els.importTextBtn.addEventListener("click", async () => {
    try {
      await importTextEnvelope();
    } catch (err) {
      setStatus("bad", "Text import failed", err.message || String(err));
    }
  });

  els.clearTextBtn.addEventListener("click", () => {
    els.handoffInput.value = "";
    resetQRPreview();
  });

  els.renderQRBtn.addEventListener("click", async () => {
    try {
      await renderQRCode();
      setStatus("idle", "QR rendered", "The current GPMREC1 text is ready as a local QR image.");
    } catch (err) {
      setStatus("bad", "QR render failed", err.message || String(err));
    }
  });

  els.downloadQRBtn.addEventListener("click", async () => {
    try {
      await downloadRenderedQR();
    } catch (err) {
      setStatus("bad", "QR download failed", err.message || String(err));
    }
  });

  els.scanQRBtn.addEventListener("click", async () => {
    els.scanQRBtn.disabled = true;
    try {
      await scanQRCodeImage();
    } catch (err) {
      setStatus("bad", "QR scan failed", err.message || String(err));
    } finally {
      els.scanQRBtn.disabled = false;
    }
  });

  try {
    const savedTrustStore = localStorage.getItem(trustStoreStorageKey);
    if (savedTrustStore && !trimString(els.trustInput.value)) {
      els.trustInput.value = savedTrustStore;
    }
    const savedHelperRegistry = localStorage.getItem(helperRegistryStorageKey);
    if (savedHelperRegistry && !trimString(els.registryInput.value)) {
      els.registryInput.value = savedHelperRegistry;
    }
    const savedHelperRegistryMeta = localStorage.getItem(helperRegistryMetaStorageKey);
    if (savedHelperRegistryMeta) {
      try {
        verifiedHelperRegistryMeta = normalizeVerifiedHelperRegistryMeta(JSON.parse(savedHelperRegistryMeta));
      } catch (err) {
        clearVerifiedHelperRegistryMeta();
      }
    }
  } catch (err) {
    // Ignore local storage availability issues.
  }
  if (!trimString(els.trustInput.value)) {
    writeTrustStore({ version: 1, trusted_keys: [] });
  } else {
    renderTrustKeys();
  }
  renderHelperRegistrySummary();
})();
