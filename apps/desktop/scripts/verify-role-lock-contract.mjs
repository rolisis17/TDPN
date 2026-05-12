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
    /id="desktop_step_client_detail"/,
    indexHtml,
    'index.html missing dynamic `desktop_step_client_detail` onboarding detail',
    failures
  );
  requirePattern(/<body[^>]*class="[^"]*public-app-mode/, indexHtml, "index.html missing default public-app-mode body class", failures);
  requirePattern(/data-admin-only/, indexHtml, "index.html missing public-app/admin-console split markers", failures);
  requirePattern(/id="contribution_enable_btn"/, indexHtml, "index.html missing contribution enable control", failures);
  requirePattern(/id="rewards_current_week_btn"/, indexHtml, "index.html missing current-week rewards control", failures);

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
    /function\s+isServerOnlyRole\s*\(/,
    mainJs,
    "main.js missing server-only role helper",
    failures
  );
  requirePattern(
    /Continue in Server lane/,
    mainJs,
    "main.js missing direct server-only activation path",
    failures
  );
  requirePattern(
    /Client lane is locked for this session\./,
    mainJs,
    "main.js missing client onboarding role-lock detail",
    failures
  );
  requirePattern(
    /Use the lock message activation path shown above\./,
    mainJs,
    "main.js missing generic lock-message activation path wording",
    failures
  );
  if (/finish Step 2 and unlock client actions/.test(mainJs)) {
    failures.push("main.js still tells locked server-only users to finish client Step 2");
  }
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
  requirePattern(
    /function\s+syncAdminConsoleMode\s*\(/,
    mainJs,
    "main.js missing admin-console split synchronizer",
    failures
  );
  requirePattern(
    /function\s+requireAdminConsoleMode\s*\(/,
    mainJs,
    "main.js missing admin-only action guard",
    failures
  );
  requirePattern(
    /control_gpm_contribution_enable/,
    mainJs,
    "main.js missing contribution enable command wiring",
    failures
  );
  requirePattern(
    /control_gpm_rewards_current_week/,
    mainJs,
    "main.js missing weekly reward command wiring",
    failures
  );
  requirePattern(
    /function\s+attachProductionConnectReservation\s*\(/,
    mainJs,
    "main.js missing production reserve-before-connect helper",
    failures
  );
  requirePattern(
    /control_gpm_settlement_reserve_funds/,
    mainJs,
    "main.js missing production settlement reserve-funds command wiring",
    failures
  );
  requirePattern(
    /reservation_id[\s\S]*reservation_session_id|reservation_session_id[\s\S]*reservation_id/,
    mainJs,
    "main.js missing reservation_id/reservation_session_id connect payload binding",
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
