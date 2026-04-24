import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(scriptDir, "..");
const defaultSourceIconPath = path.join(appRoot, "src-tauri", "icons", "icon.svg");
const defaultOutputIconPath = path.join(appRoot, "src-tauri", "icons", "icon.ico");
const defaultTauriConfigPath = path.join(appRoot, "src-tauri", "tauri.conf.json");
const tauriCliScriptPath = path.join(appRoot, "node_modules", "@tauri-apps", "cli", "tauri.js");

function parseBoolean(value) {
  if (value == null) {
    return false;
  }
  const normalized = String(value).trim().toLowerCase();
  return normalized === "1" || normalized === "true" || normalized === "yes" || normalized === "on";
}

function parseArgs(argv) {
  return {
    dryRun: argv.includes("--dry-run") || parseBoolean(process.env.GPM_DESKTOP_ICON_PREBUILD_DRY_RUN),
    force: argv.includes("--force") || parseBoolean(process.env.GPM_DESKTOP_ICON_PREBUILD_FORCE),
  };
}

function resolvePath(value, fallback) {
  const candidate = value && value.trim() ? value.trim() : fallback;
  return path.isAbsolute(candidate) ? candidate : path.resolve(appRoot, candidate);
}

function readU16LE(buffer, offset) {
  if (offset + 2 > buffer.length) {
    return null;
  }
  return buffer.readUInt16LE(offset);
}

function readU32LE(buffer, offset) {
  if (offset + 4 > buffer.length) {
    return null;
  }
  return buffer.readUInt32LE(offset);
}

function icoBytesAreValid(buffer) {
  if (buffer.length < 22) {
    return false;
  }

  const reserved = readU16LE(buffer, 0);
  const imageType = readU16LE(buffer, 2);
  const imageCount = readU16LE(buffer, 4);
  if (reserved !== 0 || imageType !== 1 || imageCount === 0) {
    return false;
  }

  const imageSize = readU32LE(buffer, 14);
  const imageOffset = readU32LE(buffer, 18);
  if (!imageSize || !imageOffset || imageOffset < 22) {
    return false;
  }

  const imageEnd = imageOffset + imageSize;
  return imageEnd <= buffer.length;
}

async function fileExists(filePath) {
  try {
    await fsp.access(filePath, fs.constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

async function iconState(outputIconPath) {
  if (!(await fileExists(outputIconPath))) {
    return { ready: false, reason: "missing" };
  }

  const contents = await fsp.readFile(outputIconPath);
  if (icoBytesAreValid(contents)) {
    return { ready: true, reason: "already-valid" };
  }

  return { ready: false, reason: "invalid" };
}

function manualRemediationCommand() {
  return "npm run generate:windows-icon";
}

function tauriResourceRemediationCommand() {
  return "powershell -NoProfile -ExecutionPolicy Bypass -File .\\scripts\\windows\\desktop_doctor.ps1 -Mode fix -InstallMissing -EnablePolicyBypass";
}

function printRemediation(sourceIconPath, outputIconPath, reason) {
  const sourceRelative = path.relative(appRoot, sourceIconPath) || sourceIconPath;
  const outputRelative = path.relative(appRoot, outputIconPath) || outputIconPath;
  console.error(`desktop icon prebuild failed (${reason}): ${outputRelative}`);
  console.error(`source icon: ${sourceRelative}`);
  console.error(`manual remediation: cd apps/desktop && ${manualRemediationCommand()}`);
  console.error(`resource remediation: ${tauriResourceRemediationCommand()}`);
  console.error("if the generator reports missing tooling, run `npm install` in apps/desktop first");
}

function normalizePathForCompare(value) {
  return String(value || "").trim().replace(/\\/g, "/").toLowerCase();
}

async function readTauriBundleIconState(tauriConfigPath, expectedIconRelativePath) {
  if (!(await fileExists(tauriConfigPath))) {
    return { configured: false, reason: "missing_tauri_conf" };
  }

  let parsed = null;
  try {
    parsed = JSON.parse(await fsp.readFile(tauriConfigPath, "utf8"));
  } catch {
    return { configured: false, reason: "invalid_tauri_conf_json" };
  }

  const icons = parsed?.bundle?.icon;
  const iconEntries = Array.isArray(icons) ? icons : icons ? [icons] : [];
  const expected = normalizePathForCompare(expectedIconRelativePath);
  const hasExpected = iconEntries.some((entry) => normalizePathForCompare(entry) === expected);
  if (!hasExpected) {
    return { configured: false, reason: "missing_bundle_icon_entry" };
  }

  return { configured: true, reason: "configured" };
}

async function generateIcon(sourceIconPath, outputIconPath) {
  if (!(await fileExists(sourceIconPath))) {
    throw new Error(`missing source icon: ${sourceIconPath}`);
  }

  if (!(await fileExists(tauriCliScriptPath))) {
    throw new Error(`missing Tauri CLI script: ${tauriCliScriptPath}`);
  }

  const tempOutputDir = await fsp.mkdtemp(path.join(os.tmpdir(), "gpm-desktop-icon-"));
  try {
    const runResult = spawnSync(
      process.execPath,
      [tauriCliScriptPath, "icon", sourceIconPath, "--output", tempOutputDir],
      {
        cwd: appRoot,
        encoding: "utf8",
        shell: false,
      }
    );

    if (runResult.error) {
      throw runResult.error;
    }

    if (runResult.status !== 0) {
      const stdout = runResult.stdout ? runResult.stdout.trim() : "";
      const stderr = runResult.stderr ? runResult.stderr.trim() : "";
      const details = [stdout, stderr].filter(Boolean).join("\n");
      throw new Error(
        details
          ? `tauri icon failed with exit code ${runResult.status}\n${details}`
          : `tauri icon failed with exit code ${runResult.status}`
      );
    }

    const generatedIconPath = path.join(tempOutputDir, "icon.ico");
    const generatedIconContents = await fsp.readFile(generatedIconPath);
    if (!icoBytesAreValid(generatedIconContents)) {
      throw new Error(`generated icon was not a valid ico: ${generatedIconPath}`);
    }

    await fsp.mkdir(path.dirname(outputIconPath), { recursive: true });
    await fsp.copyFile(generatedIconPath, outputIconPath);
    return outputIconPath;
  } finally {
    await fsp.rm(tempOutputDir, { recursive: true, force: true });
  }
}

async function main() {
  if (process.platform !== "win32") {
    if (parseArgs(process.argv.slice(2)).dryRun) {
      console.log("desktop icon prebuild: skipped on non-Windows host");
    }
    return;
  }

  const args = parseArgs(process.argv.slice(2));
  const sourceIconPath = resolvePath(
    process.env.GPM_DESKTOP_ICON_SOURCE_PATH,
    defaultSourceIconPath
  );
  const outputIconPath = resolvePath(
    process.env.GPM_DESKTOP_ICON_OUTPUT_PATH,
    defaultOutputIconPath
  );
  const tauriConfigPath = resolvePath(
    process.env.GPM_DESKTOP_TAURI_CONFIG_PATH,
    defaultTauriConfigPath
  );

  const tauriBundleIconState = await readTauriBundleIconState(
    tauriConfigPath,
    "icons/icon.ico"
  );
  if (!tauriBundleIconState.configured) {
    printRemediation(
      sourceIconPath,
      outputIconPath,
      `tauri bundle icon resource ${tauriBundleIconState.reason} (${path.relative(appRoot, tauriConfigPath)})`
    );
    process.exitCode = 1;
    return;
  }

  if (!(await fileExists(sourceIconPath))) {
    if (args.dryRun) {
      printRemediation(sourceIconPath, outputIconPath, "missing source icon");
      process.exitCode = 1;
      return;
    }
    printRemediation(sourceIconPath, outputIconPath, "missing source icon");
    process.exitCode = 1;
    return;
  }

  const currentState = await iconState(outputIconPath);
  if (currentState.ready && !args.force) {
    console.log(`desktop icon prebuild: icon already valid at ${path.relative(appRoot, outputIconPath)}`);
    return;
  }

  if (args.dryRun) {
    console.log(
      `desktop icon prebuild: would generate ${path.relative(appRoot, outputIconPath)} from ${path.relative(appRoot, sourceIconPath)}`
    );
    console.log(`desktop icon prebuild: manual command -> cd apps/desktop && ${manualRemediationCommand()}`);
    return;
  }

  try {
    await generateIcon(sourceIconPath, outputIconPath);
    console.log(
      `desktop icon prebuild: generated ${path.relative(appRoot, outputIconPath)} from ${path.relative(appRoot, sourceIconPath)}`
    );
  } catch (err) {
    printRemediation(sourceIconPath, outputIconPath, err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  }
}

await main();
