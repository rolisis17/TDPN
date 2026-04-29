import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(scriptDir, "..");
const isWindows = process.platform === "win32";
const tauriBin = path.join(appRoot, "node_modules", ".bin", isWindows ? "tauri.cmd" : "tauri");
const adminTauriConfig = path.join(appRoot, "src-tauri", "tauri.admin-console.conf.json");
const command = process.argv[2];

if (command !== "dev" && command !== "build") {
  console.error("Usage: node scripts/run-admin-console.mjs <dev|build>");
  process.exit(1);
}

const tauriArgs = [command, "--features", "admin-console", "--config", adminTauriConfig];
const tauriCommand = isWindows ? `"${tauriBin}" ${tauriArgs.map((arg) => `"${arg}"`).join(" ")}` : tauriBin;
const result = spawnSync(tauriCommand, isWindows ? [] : tauriArgs, {
  cwd: appRoot,
  env: {
    ...process.env,
    GPM_DESKTOP_ADMIN_CONSOLE: "1",
    GPM_LOCAL_API_ADMIN_ROUTES: "1",
    GPM_DESKTOP_BUILD_ADMIN_CONSOLE: "1",
    VITE_GPM_ADMIN_CONSOLE: "1"
  },
  shell: isWindows,
  stdio: "inherit"
});

if (result.error) {
  throw result.error;
}
process.exit(result.status ?? 1);
