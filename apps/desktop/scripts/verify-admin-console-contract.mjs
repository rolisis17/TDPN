import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(scriptDir, "..");
const repoRoot = path.resolve(appRoot, "..", "..");

const defaultPaths = {
  indexHtml: path.join(appRoot, "index.html"),
  mainJs: path.join(appRoot, "src", "main.js"),
  stylesCss: path.join(appRoot, "src", "styles.css"),
  packageJson: path.join(appRoot, "package.json"),
  buildRenderer: path.join(appRoot, "scripts", "build-renderer.mjs"),
  runAdminConsole: path.join(appRoot, "scripts", "run-admin-console.mjs"),
  tauriMainRs: path.join(appRoot, "src-tauri", "src", "main.rs"),
  localApiRs: path.join(appRoot, "src-tauri", "src", "local_api.rs"),
  cargoToml: path.join(appRoot, "src-tauri", "Cargo.toml"),
  windowsPackagedRun: path.join(repoRoot, "scripts", "windows", "desktop_packaged_run.ps1"),
  windowsNativeBootstrap: path.join(repoRoot, "scripts", "windows", "desktop_native_bootstrap.ps1"),
  windowsReleaseBundle: path.join(repoRoot, "scripts", "windows", "desktop_release_bundle.ps1"),
  linuxPackagedRun: path.join(repoRoot, "scripts", "linux", "desktop_packaged_run.sh"),
  linuxReleaseBundle: path.join(repoRoot, "scripts", "linux", "desktop_release_bundle.sh")
};

const ADMIN_ELEMENT_IDS = new Set([
  "audit_recent_btn",
  "audit_limit",
  "audit_offset",
  "audit_event",
  "audit_wallet_address",
  "audit_order",
  "chain_operator_id",
  "selected_application_updated_at",
  "operator_reason",
  "operator_list_status",
  "operator_list_search",
  "operator_list_limit",
  "operator_list_next_cursor",
  "admin_contribution_status",
  "admin_contribution_role",
  "admin_contribution_wallet",
  "admin_contribution_limit",
  "admin_reward_week_start",
  "admin_reward_hold_source",
  "admin_reward_hold_reason",
  "apply_operator_btn",
  "operator_status_btn",
  "operator_list_filter_btn",
  "operator_list_pending_btn",
  "operator_load_next_pending_btn",
  "operator_list_all_btn",
  "operator_list_next_btn",
  "approve_operator_btn",
  "reject_operator_btn",
  "admin_contribution_list_btn",
  "admin_reward_review_btn",
  "admin_reward_hold_btn",
  "admin_reward_release_btn",
  "admin_reward_finalize_btn",
  "operator_approval_policy_hint",
  "set_profile",
  "set_profile_btn",
  "status_btn_server",
  "service_status_btn",
  "service_start_btn",
  "service_stop_btn",
  "service_restart_btn",
  "update_btn"
]);

const ADMIN_ACTION_BUTTON_IDS = [
  "apply_operator_btn",
  "operator_status_btn",
  "operator_list_filter_btn",
  "operator_list_pending_btn",
  "operator_load_next_pending_btn",
  "operator_list_all_btn",
  "operator_list_next_btn",
  "approve_operator_btn",
  "reject_operator_btn",
  "admin_contribution_list_btn",
  "admin_reward_review_btn",
  "admin_reward_hold_btn",
  "admin_reward_release_btn",
  "admin_reward_finalize_btn",
  "status_btn_server",
  "set_profile_btn",
  "update_btn",
  "service_status_btn",
  "service_start_btn",
  "service_stop_btn",
  "service_restart_btn"
];

const ADMIN_HTML_MARKERS = [
  'id="audit_recent_btn"',
  'id="chain_operator_id"',
  'id="operator_list_filter_btn"',
  'id="approve_operator_btn"',
  'id="admin_contribution_list_btn"',
  'id="admin_reward_hold_btn"',
  'id="admin_reward_finalize_btn"',
  'id="set_profile_btn"',
  'id="service_start_btn"'
];

const ADMIN_TAURI_COMMANDS = [
  "control_set_profile",
  "control_update",
  "control_service_status",
  "control_service_start",
  "control_service_stop",
  "control_service_restart",
  "control_gpm_audit_recent",
  "control_gpm_admin_contribution_list",
  "control_gpm_admin_reward_review",
  "control_gpm_admin_reward_hold",
  "control_gpm_admin_reward_finalize",
  "control_gpm_server_status",
  "control_gpm_operator_apply",
  "control_gpm_operator_status",
  "control_gpm_operator_list",
  "control_gpm_operator_approve"
];

const INTERACTIVE_TAGS = new Set(["button", "input", "select", "textarea", "a"]);
const VOID_TAGS = new Set([
  "area",
  "base",
  "br",
  "col",
  "embed",
  "hr",
  "img",
  "input",
  "link",
  "meta",
  "param",
  "source",
  "track",
  "wbr"
]);

const ADMIN_CONTROL_PATTERNS = [
  { label: "admin wording", pattern: /\badmin\b/i },
  { label: "audit action", pattern: /\brecent\s+audit\b/i },
  { label: "operator apply", pattern: /\bapply\s+operator\s+role\b/i },
  { label: "operator status", pattern: /\boperator\s+status\b/i },
  { label: "operator queue", pattern: /\b(list|next|load)\s+(operator\s+queue|pending\s+operators|all\s+operators|next\s+pending)\b/i },
  { label: "operator moderation", pattern: /\b(approve|reject)\s+operator\b/i },
  { label: "contribution/reward review", pattern: /\b(review\s+(contributions?|weekly\s+reward)|contribution\s+(wallet|limit)|reward\s+(week\s+start|hold\s+(source|reason))|hold\s+weekly\s+reward|release\s+reward\s+hold|finalize\s+weekly\s+reward)\b/i },
  { label: "moderation field", pattern: /\bmoderation\b/i },
  { label: "server profile", pattern: /\bset\s+profile\b/i },
  { label: "service lifecycle", pattern: /\bservice\s+(status|start|stop|restart)\b/i },
  { label: "policy/slashing/settlement/payout", pattern: /\b(policy\s+change|slashing|settlement|payout)\b/i }
];

function parseArgs(argv) {
  const args = { ...defaultPaths };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    }
    const value = argv[i + 1];
    if (!value) {
      throw new Error(`missing value for ${arg}`);
    }
    if (arg === "--index-html") {
      args.indexHtml = path.resolve(value);
    } else if (arg === "--main-js") {
      args.mainJs = path.resolve(value);
    } else if (arg === "--styles-css") {
      args.stylesCss = path.resolve(value);
    } else if (arg === "--package-json") {
      args.packageJson = path.resolve(value);
    } else if (arg === "--build-renderer") {
      args.buildRenderer = path.resolve(value);
    } else if (arg === "--run-admin-console") {
      args.runAdminConsole = path.resolve(value);
    } else if (arg === "--tauri-main-rs") {
      args.tauriMainRs = path.resolve(value);
    } else if (arg === "--cargo-toml") {
      args.cargoToml = path.resolve(value);
    } else {
      throw new Error(`unknown option: ${arg}`);
    }
    i += 1;
  }
  return args;
}

function printHelp() {
  console.log(`Usage: node apps/desktop/scripts/verify-admin-console-contract.mjs [options]

Options:
  --index-html PATH  Override desktop index.html path
  --main-js PATH     Override desktop src/main.js path
  --styles-css PATH  Override desktop src/styles.css path
  --package-json PATH Override desktop package.json path
  --build-renderer PATH Override desktop scripts/build-renderer.mjs path
  --run-admin-console PATH Override desktop scripts/run-admin-console.mjs path
  --tauri-main-rs PATH Override desktop src-tauri/src/main.rs path
  --cargo-toml PATH  Override desktop src-tauri/Cargo.toml path
  Additional packaging guard scripts are checked from the repository defaults.
`);
}

function readUtf8(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function lineStartsFor(content) {
  const starts = [0];
  for (let i = 0; i < content.length; i += 1) {
    if (content[i] === "\n") {
      starts.push(i + 1);
    }
  }
  return starts;
}

function lineAt(lineStarts, index) {
  let low = 0;
  let high = lineStarts.length - 1;
  while (low <= high) {
    const mid = Math.floor((low + high) / 2);
    if (lineStarts[mid] <= index) {
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }
  return high + 1;
}

function parseAttributes(tagSource) {
  const tagNameMatch = /^<\/?\s*([A-Za-z][A-Za-z0-9:-]*)/.exec(tagSource);
  if (!tagNameMatch) {
    return new Map();
  }
  const attrSource = tagSource
    .slice(tagNameMatch[0].length)
    .replace(/\/?>\s*$/, "");
  const attrs = new Map();
  const attrPattern = /([A-Za-z_:][-A-Za-z0-9_:.]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  for (const match of attrSource.matchAll(attrPattern)) {
    const name = match[1].toLowerCase();
    const value = match[2] ?? match[3] ?? match[4] ?? "";
    attrs.set(name, value);
  }
  return attrs;
}

function normalizeText(value) {
  return String(value || "")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .trim();
}

function attrValue(attrs, name) {
  return attrs.get(name.toLowerCase()) || "";
}

function elementDescriptor(node) {
  return normalizeText([
    node.tagName,
    attrValue(node.attrs, "id"),
    attrValue(node.attrs, "name"),
    attrValue(node.attrs, "aria-label"),
    attrValue(node.attrs, "title"),
    attrValue(node.attrs, "placeholder"),
    attrValue(node.attrs, "value"),
    node.text
  ].join(" "));
}

function scanHtml(content) {
  const lineStarts = lineStartsFor(content);
  const elements = [];
  const controls = [];
  const stack = [];
  const tagPattern = /<!--[\s\S]*?-->|<!doctype[^>]*>|<\/?[A-Za-z][^>]*>/gi;
  let cursor = 0;

  function appendText(text) {
    const normalized = normalizeText(text);
    if (!normalized) {
      return;
    }
    for (const node of stack) {
      if (node.captureText) {
        node.text = normalizeText(`${node.text} ${normalized}`);
      }
    }
  }

  function recordControl(node) {
    controls.push({
      tagName: node.tagName,
      attrs: node.attrs,
      id: attrValue(node.attrs, "id"),
      line: node.line,
      adminOnly: node.adminOnly,
      text: node.text,
      descriptor: elementDescriptor(node)
    });
  }

  function closeThrough(tagName) {
    for (let i = stack.length - 1; i >= 0; i -= 1) {
      const node = stack.pop();
      if (node.captureText) {
        recordControl(node);
      }
      if (node.tagName === tagName) {
        return;
      }
    }
  }

  for (const match of content.matchAll(tagPattern)) {
    appendText(content.slice(cursor, match.index));
    cursor = match.index + match[0].length;

    const tagSource = match[0];
    if (tagSource.startsWith("<!--") || /^<!doctype/i.test(tagSource)) {
      continue;
    }

    const tagNameMatch = /^<\/?\s*([A-Za-z][A-Za-z0-9:-]*)/.exec(tagSource);
    if (!tagNameMatch) {
      continue;
    }
    const tagName = tagNameMatch[1].toLowerCase();
    const isClosing = /^<\//.test(tagSource);

    if (isClosing) {
      closeThrough(tagName);
      continue;
    }

    const attrs = parseAttributes(tagSource);
    const parent = stack[stack.length - 1];
    const adminOnly = Boolean(parent?.adminOnly || attrs.has("data-admin-only"));
    const line = lineAt(lineStarts, match.index);
    const node = {
      tagName,
      attrs,
      line,
      adminOnly,
      captureText: INTERACTIVE_TAGS.has(tagName),
      text: ""
    };
    const id = attrValue(attrs, "id");
    if (id) {
      elements.push({
        tagName,
        attrs,
        id,
        line,
        adminOnly,
        descriptor: elementDescriptor(node)
      });
    }

    const selfClosing = /\/>\s*$/.test(tagSource) || VOID_TAGS.has(tagName);
    if (selfClosing) {
      if (node.captureText) {
        recordControl(node);
      }
      continue;
    }

    stack.push(node);
  }

  appendText(content.slice(cursor));
  while (stack.length > 0) {
    const node = stack.pop();
    if (node.captureText) {
      recordControl(node);
    }
  }

  return { elements, controls };
}

function classifyAdminControl(control) {
  if (ADMIN_ELEMENT_IDS.has(control.id)) {
    return `admin id ${control.id}`;
  }
  for (const { label, pattern } of ADMIN_CONTROL_PATTERNS) {
    if (pattern.test(control.descriptor)) {
      return label;
    }
  }
  return "";
}

function requirePattern(pattern, content, label, failures) {
  if (!pattern.test(content)) {
    failures.push(label);
  }
}

function removeAdminOnlyHtml(html) {
  let previous;
  let next = html;
  const adminOnlyElementPattern =
    /[ \t]*<([A-Za-z][A-Za-z0-9:-]*)\b(?=[^>]*\bdata-admin-only\b)[^>]*>[\s\S]*?<\/\1>\s*/gi;
  do {
    previous = next;
    next = next.replace(adminOnlyElementPattern, "");
  } while (next !== previous);
  return next;
}

function htmlHasId(html, id) {
  const escaped = id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`\\bid=["']${escaped}["']`).test(html);
}

function hasGuardedClickHandler(mainJs, id) {
  const marker = `byId("${id}").addEventListener("click"`;
  const start = mainJs.indexOf(marker);
  if (start === -1) {
    return false;
  }
  const guardWindow = mainJs.slice(start, start + 500);
  return /requireAdminConsoleMode\s*\(/.test(guardWindow);
}

function hasGuardedTauriCommand(tauriMainRs, fnName) {
  const marker = `async fn ${fnName}`;
  const start = tauriMainRs.indexOf(marker);
  if (start === -1) {
    return false;
  }
  const nextCommand = tauriMainRs.indexOf("\n#[tauri::command]", start + marker.length);
  const body = tauriMainRs.slice(start, nextCommand === -1 ? start + 1200 : nextCommand);
  if (/ensure_admin_console_state\s*\(/.test(body)) {
    return true;
  }
  if (/control_service_lifecycle\s*\(/.test(body)) {
    return hasGuardedTauriCommand(tauriMainRs, "control_service_lifecycle");
  }
  return false;
}

function extractInvokeHandlerBlock(tauriMainRs, cfgMarker) {
  let searchFrom = 0;
  while (searchFrom < tauriMainRs.length) {
    const markerIndex = tauriMainRs.indexOf(cfgMarker, searchFrom);
    if (markerIndex === -1) {
      return "";
    }
    const handlerIndex = tauriMainRs.indexOf("tauri::generate_handler![", markerIndex);
    if (handlerIndex === -1) {
      return "";
    }
    const between = tauriMainRs.slice(markerIndex + cfgMarker.length, handlerIndex);
    if (/^\s*let\s+builder\s*=\s*builder\.invoke_handler\s*\(\s*$/.test(between)) {
      const endIndex = tauriMainRs.indexOf("]);", handlerIndex);
      if (endIndex === -1) {
        return "";
      }
      return tauriMainRs.slice(handlerIndex, endIndex);
    }
    searchFrom = markerIndex + cfgMarker.length;
  }
  return "";
}

function run() {
  const paths = parseArgs(process.argv.slice(2));
  const failures = [];
  const indexHtml = readUtf8(paths.indexHtml);
  const mainJs = readUtf8(paths.mainJs);
  const stylesCss = readUtf8(paths.stylesCss);
  const packageJson = readUtf8(paths.packageJson);
  const buildRenderer = readUtf8(paths.buildRenderer);
  const runAdminConsole = readUtf8(paths.runAdminConsole);
  const tauriMainRs = readUtf8(paths.tauriMainRs);
  const localApiRs = readUtf8(paths.localApiRs);
  const cargoToml = readUtf8(paths.cargoToml);
  const windowsPackagedRun = readUtf8(paths.windowsPackagedRun);
  const windowsNativeBootstrap = readUtf8(paths.windowsNativeBootstrap);
  const windowsReleaseBundle = readUtf8(paths.windowsReleaseBundle);
  const linuxPackagedRun = readUtf8(paths.linuxPackagedRun);
  const linuxReleaseBundle = readUtf8(paths.linuxReleaseBundle);

  requirePattern(
    /<body\b[^>]*class=["'][^"']*\bpublic-app-mode\b/i,
    indexHtml,
    "index.html body must default to public-app-mode",
    failures
  );
  requirePattern(
    /\bdata-admin-only\b/i,
    indexHtml,
    "index.html must mark Admin Console-only UI with data-admin-only",
    failures
  );
  requirePattern(
    /body\.public-app-mode\s+\[data-admin-only\][^{]*\{[^}]*display\s*:\s*none\s*!important/is,
    stylesCss,
    "styles.css must hide data-admin-only controls in public-app-mode",
    failures
  );
  requirePattern(
    /body\.admin-console-mode\s+\[data-admin-only\][^{]*\{[^}]*display\s*:\s*revert/is,
    stylesCss,
    "styles.css must re-enable data-admin-only controls in admin-console-mode",
    failures
  );
  requirePattern(
    /VITE_GPM_ADMIN_CONSOLE\s*===\s*["']1["']/,
    mainJs,
    "main.js must gate Admin Console renderer bindings on VITE_GPM_ADMIN_CONSOLE=1",
    failures
  );
  requirePattern(
    /function\s+adminById\s*\(/,
    mainJs,
    "main.js must use optional admin element lookup for public renderer builds",
    failures
  );
  requirePattern(
    /if\s*\(\s*ADMIN_CONSOLE_RENDERER\s*\)\s*\{[\s\S]*byId\(["']audit_recent_btn["']\)\.addEventListener/,
    mainJs,
    "main.js must register audit/admin handlers only inside the admin-console renderer branch",
    failures
  );
  requirePattern(
    /if\s*\(\s*ADMIN_CONSOLE_RENDERER\s*\)\s*\{[\s\S]*byId\(["']service_start_btn["']\)\.addEventListener/,
    mainJs,
    "main.js must register server lifecycle handlers only inside the admin-console renderer branch",
    failures
  );
  requirePattern(
    /"build"\s*:\s*"node scripts\/build-renderer\.mjs"/,
    packageJson,
    "package.json build script must use the renderer contract wrapper",
    failures
  );
  requirePattern(
    /"build:admin-console"\s*:\s*"node scripts\/build-renderer\.mjs --admin-console"/,
    packageJson,
    "package.json must expose an admin-console renderer build",
    failures
  );
  requirePattern(
    /VITE_GPM_ADMIN_CONSOLE:\s*adminConsoleRenderer\s*\?\s*["']1["']\s*:\s*["']0["']/,
    buildRenderer,
    "build-renderer.mjs must set VITE_GPM_ADMIN_CONSOLE for public/admin builds",
    failures
  );
  requirePattern(
    /GPM_DESKTOP_BUILD_ADMIN_CONSOLE/,
    buildRenderer,
    "build-renderer.mjs must use an explicit admin build flag instead of inherited renderer env",
    failures
  );
  requirePattern(
    /control_gpm_server_status/,
    buildRenderer,
    "build-renderer.mjs public bundle denylist must include server status admin command",
    failures
  );
  requirePattern(
    /PUBLIC_FORBIDDEN_UI_MARKERS[\s\S]*server lifecycle actions[\s\S]*Server\/admin controls/,
    buildRenderer,
    "build-renderer.mjs must deny public release admin/server lifecycle UI markers",
    failures
  );
  requirePattern(
    /assertAbsent\(prunedHtml,\s*PUBLIC_FORBIDDEN_UI_MARKERS,\s*["']public index\.html["']\)/,
    buildRenderer,
    "build-renderer.mjs must assert public index.html has no admin/server lifecycle UI markers",
    failures
  );
  requirePattern(
    /assertAbsent\(builtJs,\s*PUBLIC_FORBIDDEN_UI_MARKERS,\s*["']public renderer bundle["']\)/,
    buildRenderer,
    "build-renderer.mjs must assert public renderer bundle has no admin/server lifecycle UI markers",
    failures
  );
  requirePattern(
    /tauri\.admin-console\.conf\.json/,
    runAdminConsole,
    "run-admin-console.mjs must use the dedicated Admin Console Tauri config",
    failures
  );
  requirePattern(
    /"--config",\s*adminTauriConfig/,
    runAdminConsole,
    "run-admin-console.mjs must pass --config for Admin Console dev/build",
    failures
  );
  requirePattern(
    /removeAdminOnlyHtml\s*\(/,
    buildRenderer,
    "build-renderer.mjs must prune data-admin-only HTML from public builds",
    failures
  );
  requirePattern(
    /document\.querySelectorAll\(["']\[data-admin-only\]["']\)/,
    mainJs,
    "main.js must enumerate data-admin-only elements",
    failures
  );
  requirePattern(
    /classList\.toggle\(["']public-app-mode["'],\s*!enabled\)/,
    mainJs,
    "main.js must toggle public-app-mode from admin-console state",
    failures
  );
  requirePattern(
    /classList\.toggle\(["']admin-console-mode["'],\s*enabled\)/,
    mainJs,
    "main.js must toggle admin-console-mode from admin-console state",
    failures
  );
  requirePattern(
    /function\s+requireAdminConsoleMode\s*\(/,
    mainJs,
    "main.js must keep a shared requireAdminConsoleMode action guard",
    failures
  );
  requirePattern(
    /fn\s+ensure_admin_console_state\s*\(/,
    tauriMainRs,
    "src-tauri/src/main.rs must keep an admin-console guard for native command surface",
    failures
  );
  requirePattern(
    /\[features\][\s\S]*\badmin-console\s*=/,
    cargoToml,
    "src-tauri/Cargo.toml must define an explicit admin-console feature",
    failures
  );
  requirePattern(
    /cfg!\(feature\s*=\s*"admin-console"\)/,
    tauriMainRs,
    "src-tauri/src/main.rs control_config must gate admin_console_enabled on the admin-console feature",
    failures
  );
  requirePattern(
    /unwrap_or_else\(\|\|\s*cfg!\(feature\s*=\s*"admin-console"\)\)/,
    localApiRs,
    "src-tauri/src/local_api.rs must enable Admin Console by compile feature by default, with env as override/kill switch",
    failures
  );
  requirePattern(
    /#\[cfg\(feature\s*=\s*"admin-console"\)\]/,
    tauriMainRs,
    "src-tauri/src/main.rs must register an admin-console feature invoke handler",
    failures
  );
  requirePattern(
    /#\[cfg\(not\(feature\s*=\s*"admin-console"\)\)\]/,
    tauriMainRs,
    "src-tauri/src/main.rs must register a public-app invoke handler without admin commands",
    failures
  );
  requirePattern(
    /Test-AdminConsoleArtifactPath[\s\S]*\[\s*\\s_\s*\]\+/,
    windowsReleaseBundle,
    "windows desktop release bundle guard must normalize space-separated Admin Console artifact names",
    failures
  );
  requirePattern(
    /is_admin_console_artifact_path[\s\S]*tokenized="\$\{normalized\/\/ \/-\}"[\s\S]*tokenized="\$\{tokenized\/\/_\/-\}"/,
    linuxReleaseBundle,
    "linux desktop release bundle guard must normalize space-separated Admin Console artifact names",
    failures
  );
  requirePattern(
    /Assert-PublicPackagedExecutableNotAdminConsole[\s\S]*tokenized[\s\S]*admin-console[\s\S]*gpm-admin/,
    windowsPackagedRun,
    "windows packaged-run guard must reject space-separated Admin Console executable names",
    failures
  );
  requirePattern(
    /assert_public_packaged_executable_not_admin_console[\s\S]*base_name="\$\{base_name\/\/ \/-\}"[\s\S]*admin-console[\s\S]*gpm-admin/,
    linuxPackagedRun,
    "linux packaged-run guard must reject space-separated Admin Console executable names",
    failures
  );
  requirePattern(
    /Test-AdminConsoleExecutablePath[\s\S]*Get-DesktopPackagedExecutableFallbackCandidate[\s\S]*Test-AdminConsoleExecutablePath[\s\S]*continue[\s\S]*Assert-PublicDesktopExecutableNotAdminConsole/,
    windowsNativeBootstrap,
    "windows native bootstrap fallback discovery must skip/reject Admin Console executables",
    failures
  );

  const { elements, controls } = scanHtml(indexHtml);
  const publicHtml = removeAdminOnlyHtml(indexHtml);
  for (const marker of ADMIN_HTML_MARKERS) {
    if (publicHtml.includes(marker)) {
      failures.push(`public renderer HTML pruning must remove ${marker}`);
    }
    if (!indexHtml.includes(marker)) {
      failures.push(`admin-console source HTML must keep ${marker}`);
    }
  }

  const reported = new Set();
  for (const element of elements) {
    if (!ADMIN_ELEMENT_IDS.has(element.id) || element.adminOnly) {
      continue;
    }
    const key = `element:${element.id}:${element.line}`;
    reported.add(key);
    failures.push(
      `index.html exposes admin-only element #${element.id} at line ${element.line} without data-admin-only on itself or an ancestor`
    );
  }

  for (const control of controls) {
    const reason = classifyAdminControl(control);
    if (!reason || control.adminOnly) {
      continue;
    }
    const key = `element:${control.id}:${control.line}`;
    if (reported.has(key)) {
      continue;
    }
    failures.push(
      `index.html exposes ${reason} control at line ${control.line} without data-admin-only on itself or an ancestor: ${control.descriptor}`
    );
  }

  for (const id of ADMIN_ACTION_BUTTON_IDS) {
    if (!htmlHasId(indexHtml, id)) {
      continue;
    }
    if (!hasGuardedClickHandler(mainJs, id)) {
      failures.push(`main.js click handler for #${id} must call requireAdminConsoleMode before invoking admin action`);
    }
  }

  for (const fnName of ADMIN_TAURI_COMMANDS) {
    if (!hasGuardedTauriCommand(tauriMainRs, fnName)) {
      failures.push(`src-tauri/src/main.rs command ${fnName} must call ensure_admin_console_state`);
    }
  }

  const publicHandler = extractInvokeHandlerBlock(tauriMainRs, '#[cfg(not(feature = "admin-console"))]');
  if (!publicHandler) {
    failures.push("src-tauri/src/main.rs must expose a cfg(not(feature = \"admin-console\")) public invoke handler");
  } else {
    for (const fnName of ADMIN_TAURI_COMMANDS) {
      if (publicHandler.includes(fnName)) {
        failures.push(`public-app invoke handler must not register admin command ${fnName}`);
      }
    }
  }

  const adminHandler = extractInvokeHandlerBlock(tauriMainRs, '#[cfg(feature = "admin-console")]');
  if (!adminHandler) {
    failures.push("src-tauri/src/main.rs must expose a cfg(feature = \"admin-console\") Admin Console invoke handler");
  } else {
    for (const fnName of ADMIN_TAURI_COMMANDS) {
      if (!adminHandler.includes(fnName)) {
        failures.push(`admin-console invoke handler must register admin command ${fnName}`);
      }
    }
  }

  if (failures.length > 0) {
    console.error("admin-console contract check failed:");
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
  }

  console.log("admin-console contract check passed");
}

run();
