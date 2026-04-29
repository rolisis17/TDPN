import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(scriptDir, "..");
const distDir = path.join(appRoot, "dist");
const isWindows = process.platform === "win32";
const viteBin = path.join(appRoot, "node_modules", ".bin", isWindows ? "vite.cmd" : "vite");
const adminConsoleRenderer =
  process.argv.includes("--admin-console") || process.env.GPM_DESKTOP_BUILD_ADMIN_CONSOLE === "1";

const ADMIN_BUNDLE_MARKERS = [
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

const PUBLIC_FORBIDDEN_UI_MARKERS = [
  "Operator Status",
  "Service Status",
  "server lifecycle actions",
  "Server/admin controls",
  "Admin controls live in the separate GPM Admin Console.",
  "separate GPM Admin Console",
  "approvals, lifecycle, policy, slashing, and payouts"
];

const PUBLIC_HTML_REPLACEMENTS = new Map([
  [
    "First run: verify local readiness, sign in, run Session, then run Status before Connect. Use Operator Status and Service Status before server lifecycle actions.",
    "First run: verify local readiness, sign in, run Session, then run Status before Connect."
  ],
  ["Operator Status", "Operator readiness"],
  ["Service Status", "Runtime status"],
  ["server lifecycle actions", "privileged actions"]
]);

const PUBLIC_BUNDLE_REPLACEMENTS = new Map([
  [
    "Windows-native first run: verify local GPM/WireGuard readiness, sign in, run Session, then run Status before Connect. Use Operator Status and Service Status before server lifecycle actions.",
    "Windows-native first run: verify local GPM/WireGuard readiness, sign in, run Session, then run Status before Connect."
  ],
  [
    "First run: verify local GPM readiness, sign in, run Session, then run Status before Connect. Use Operator Status and Service Status before server lifecycle actions.",
    "First run: verify local GPM readiness, sign in, run Session, then run Status before Connect."
  ],
  ["Operator Status", "Operator readiness"],
  ["Service Status", "Runtime status"],
  ["server lifecycle actions", "privileged actions"],
  [
    "Admin controls live in the separate GPM Admin Console.",
    "Privileged controls are unavailable in the public GPM App."
  ],
  [
    "Server/admin controls are intentionally absent from the public GPM App. Use the separate GPM Admin Console for approvals, lifecycle, policy, slashing, and payouts.",
    "Privileged controls are intentionally unavailable in the public GPM App."
  ],
  [
    "Admin controls are not available in the public GPM App. Use the separate GPM Admin Console for approvals and server control.",
    "Privileged controls are not available in the public GPM App."
  ],
  [
    "Use the separate GPM Admin Console for moderation.",
    "Use an operator-only console for moderation."
  ],
  [
    " is available only in the separate GPM Admin Console, not the public GPM App.",
    " is unavailable in the public GPM App."
  ]
]);

function runViteBuild() {
  fs.rmSync(distDir, { recursive: true, force: true });
  const command = isWindows ? `"${viteBin}" build` : viteBin;
  const args = isWindows ? [] : ["build"];
  const result = spawnSync(command, args, {
    cwd: appRoot,
    env: {
      ...process.env,
      VITE_GPM_ADMIN_CONSOLE: adminConsoleRenderer ? "1" : "0"
    },
    shell: isWindows,
    stdio: "inherit"
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

function replaceAllMarkers(content, replacements) {
  let next = content;
  for (const [marker, replacement] of replacements.entries()) {
    next = next.split(marker).join(replacement);
  }
  return next;
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

function readText(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function listBuiltAssets(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listBuiltAssets(fullPath));
    } else {
      files.push(fullPath);
    }
  }
  return files;
}

function prunePublicAdminBundleMarkers(files) {
  for (const filePath of files) {
    if (!filePath.endsWith(".js")) {
      continue;
    }
    const originalContent = readText(filePath);
    let content = originalContent;
    content = replaceAllMarkers(content, PUBLIC_BUNDLE_REPLACEMENTS);
    let changed = false;
    for (const marker of ADMIN_BUNDLE_MARKERS) {
      if (content.includes(marker)) {
        content = content.split(marker).join("__gpm_public_admin_command_pruned__");
        changed = true;
      }
    }
    changed = changed || content !== originalContent;
    if (changed) {
      fs.writeFileSync(filePath, content);
    }
  }
}

function assertAbsent(content, markers, label) {
  const found = markers.filter((marker) => content.includes(marker));
  if (found.length > 0) {
    throw new Error(`${label} still contains public-forbidden admin markers: ${found.join(", ")}`);
  }
}

function assertPresent(content, markers, label) {
  const missing = markers.filter((marker) => !content.includes(marker));
  if (missing.length > 0) {
    throw new Error(`${label} is missing admin-console markers: ${missing.join(", ")}`);
  }
}

function finalizePublicBuild() {
  const indexPath = path.join(distDir, "index.html");
  const prunedHtml = replaceAllMarkers(removeAdminOnlyHtml(readText(indexPath)), PUBLIC_HTML_REPLACEMENTS);
  assertAbsent(prunedHtml, ADMIN_HTML_MARKERS, "public index.html");
  assertAbsent(prunedHtml, PUBLIC_FORBIDDEN_UI_MARKERS, "public index.html");
  fs.writeFileSync(indexPath, prunedHtml);

  const builtAssets = listBuiltAssets(path.join(distDir, "assets"));
  prunePublicAdminBundleMarkers(builtAssets);
  const builtJs = builtAssets
    .filter((filePath) => filePath.endsWith(".js"))
    .map(readText)
    .join("\n");
  assertAbsent(builtJs, ADMIN_BUNDLE_MARKERS, "public renderer bundle");
  assertAbsent(builtJs, PUBLIC_FORBIDDEN_UI_MARKERS, "public renderer bundle");
}

function verifyAdminConsoleBuild() {
  const indexHtml = readText(path.join(distDir, "index.html"));
  assertPresent(indexHtml, ADMIN_HTML_MARKERS, "admin-console index.html");

  const builtJs = listBuiltAssets(path.join(distDir, "assets"))
    .filter((filePath) => filePath.endsWith(".js"))
    .map(readText)
    .join("\n");
  assertPresent(builtJs, ADMIN_BUNDLE_MARKERS, "admin-console renderer bundle");
}

runViteBuild();
if (adminConsoleRenderer) {
  verifyAdminConsoleBuild();
} else {
  finalizePublicBuild();
}
