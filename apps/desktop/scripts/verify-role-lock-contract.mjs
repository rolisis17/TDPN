import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(scriptDir, "..");
const indexHtmlPath = path.join(appRoot, "index.html");
const mainJsPath = path.join(appRoot, "src", "main.js");

function readUtf8(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function requirePattern(pattern, content, label, failures) {
  if (!pattern.test(content)) {
    failures.push(label);
  }
}

function run() {
  const failures = [];
  const indexHtml = readUtf8(indexHtmlPath);
  const mainJs = readUtf8(mainJsPath);

  requirePattern(/id="tab_client"/, indexHtml, 'index.html missing `tab_client` tab button', failures);
  requirePattern(/id="tab_server"/, indexHtml, 'index.html missing `tab_server` tab button', failures);
  requirePattern(/id="tab_lock_hint"/, indexHtml, 'index.html missing `tab_lock_hint` lock messaging element', failures);

  requirePattern(
    /tabClientEl\.disabled\s*=\s*!clientTabVisible;/,
    mainJs,
    "main.js missing client-tab disabled contract",
    failures
  );
  requirePattern(
    /tabServerEl\.disabled\s*=\s*!serverTabVisible;/,
    mainJs,
    "main.js missing server-tab disabled contract",
    failures
  );
  requirePattern(
    /function\s+formatLockedTabMessage\s*\(/,
    mainJs,
    "main.js missing locked-tab formatter",
    failures
  );
  requirePattern(
    /Lock reason:\s*\$\{normalizedReason\}\s*Activation path:\s*\$\{activationPath\}/,
    mainJs,
    "main.js missing explicit lock reason and activation path wording",
    failures
  );
  requirePattern(
    /function\s+syncTabLockHint\s*\(/,
    mainJs,
    "main.js missing shared tab lock hint renderer",
    failures
  );
  requirePattern(
    /tabClientEl\.addEventListener\("click",\s*\(\)\s*=>\s*\{\s*if\s*\(!tabClientEl\.disabled\)\s*\{/m,
    mainJs,
    "main.js missing client click guard for disabled tab",
    failures
  );
  requirePattern(
    /tabServerEl\.addEventListener\("click",\s*\(\)\s*=>\s*\{\s*if\s*\(!tabServerEl\.disabled\)\s*\{/m,
    mainJs,
    "main.js missing server click guard for disabled tab",
    failures
  );

  if (failures.length > 0) {
    console.error("role-lock contract check failed:");
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
  }

  console.log("role-lock contract check passed");
}

run();
