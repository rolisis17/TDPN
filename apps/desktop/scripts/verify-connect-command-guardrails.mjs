import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(scriptDir, "..");
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
  const mainJs = readUtf8(mainJsPath);

  requirePattern(
    /connectionMutationInFlight:\s*""/,
    mainJs,
    "state missing connectionMutationInFlight field",
    failures
  );
  requirePattern(
    /function\s+beginConnectionMutation\s*\(/,
    mainJs,
    "beginConnectionMutation helper missing",
    failures
  );
  requirePattern(
    /function\s+endConnectionMutation\s*\(/,
    mainJs,
    "endConnectionMutation helper missing",
    failures
  );
  requirePattern(
    /function\s+describeConnectionMutationInFlight\s*\(/,
    mainJs,
    "describeConnectionMutationInFlight helper missing",
    failures
  );
  requirePattern(
    /const\s+mutationInFlight\s*=\s*normalizeConnectionMutationKind\(state\.connectionMutationInFlight\);/,
    mainJs,
    "syncConnectActionButtons does not read mutation in-flight state",
    failures
  );
  requirePattern(
    /if\s*\(!beginConnectionMutation\("connect"\)\)\s*\{/,
    mainJs,
    "connect handler missing beginConnectionMutation guard",
    failures
  );
  requirePattern(
    /finally\s*\{\s*endConnectionMutation\("connect"\);\s*\}/m,
    mainJs,
    "connect handler missing endConnectionMutation finalizer",
    failures
  );
  requirePattern(
    /if\s*\(!beginConnectionMutation\("disconnect"\)\)\s*\{/,
    mainJs,
    "disconnect handler missing beginConnectionMutation guard",
    failures
  );
  requirePattern(
    /finally\s*\{\s*endConnectionMutation\("disconnect"\);\s*\}/m,
    mainJs,
    "disconnect handler missing endConnectionMutation finalizer",
    failures
  );

  if (failures.length > 0) {
    console.error("connect command guardrail contract check failed:");
    for (const failure of failures) {
      console.error(`- ${failure}`);
    }
    process.exit(1);
  }

  console.log("connect command guardrail contract check passed");
}

run();
