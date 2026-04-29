#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in mktemp cp grep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "desktop admin-console contract failed: missing required command: $cmd"
    exit 2
  fi
done

if command -v node >/dev/null 2>&1; then
  NODE_BIN="node"
elif command -v node.exe >/dev/null 2>&1; then
  NODE_BIN="node.exe"
else
  echo "desktop admin-console contract failed: missing required command: node"
  exit 2
fi

CHECK_SCRIPT="apps/desktop/scripts/verify-admin-console-contract.mjs"
if [[ ! -f "$CHECK_SCRIPT" ]]; then
  echo "desktop admin-console contract failed: missing check script: $CHECK_SCRIPT"
  exit 1
fi

RUN_NATIVE_TESTS="${DESKTOP_ADMIN_CONSOLE_CONTRACT_RUN_NATIVE_TESTS:-1}"
case "$RUN_NATIVE_TESTS" in
  0|1) ;;
  *)
    echo "desktop admin-console contract failed: DESKTOP_ADMIN_CONSOLE_CONTRACT_RUN_NATIVE_TESTS must be 0 or 1"
    exit 2
    ;;
esac
if [[ "$RUN_NATIVE_TESTS" == "1" ]] && ! command -v cargo >/dev/null 2>&1; then
  echo "desktop admin-console contract failed: missing required command: cargo"
  exit 2
fi

mkdir -p .easy-node-logs
TMP_DIR="$(mktemp -d ".easy-node-logs/desktop-admin-console-contract.XXXXXX")"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "[desktop-admin-console] repository contract passes"
"$NODE_BIN" "$CHECK_SCRIPT"

cp apps/desktop/index.html "$TMP_DIR/index.html"
cp apps/desktop/src/main.js "$TMP_DIR/main.js"
cp apps/desktop/src/styles.css "$TMP_DIR/styles.css"

"$NODE_BIN" - "$TMP_DIR/index.html" <<'NODE'
const fs = require("fs");
const target = process.argv[2];
let html = fs.readFileSync(target, "utf8");
html = html.replace(/(<button id="approve_operator_btn"[^>]*?)\sdata-admin-only([^>]*>)/, "$1$2");
fs.writeFileSync(target, html);
NODE

echo "[desktop-admin-console] unguarded admin control fixture fails"
if "$NODE_BIN" "$CHECK_SCRIPT" \
  --index-html "$TMP_DIR/index.html" \
  --main-js "$TMP_DIR/main.js" \
  --styles-css "$TMP_DIR/styles.css" \
  >"$TMP_DIR/unguarded-control.log" 2>&1; then
  echo "desktop admin-console contract failed: expected unguarded approve_operator_btn fixture to fail"
  cat "$TMP_DIR/unguarded-control.log"
  exit 1
fi
if ! grep -q "approve_operator_btn" "$TMP_DIR/unguarded-control.log"; then
  echo "desktop admin-console contract failed: missing approve_operator_btn failure detail"
  cat "$TMP_DIR/unguarded-control.log"
  exit 1
fi

cp apps/desktop/index.html "$TMP_DIR/index-no-public-mode.html"
"$NODE_BIN" - "$TMP_DIR/index-no-public-mode.html" <<'NODE'
const fs = require("fs");
const target = process.argv[2];
let html = fs.readFileSync(target, "utf8");
html = html.replace(/\spublic-app-mode\b/, "");
fs.writeFileSync(target, html);
NODE

echo "[desktop-admin-console] missing public-app-mode fixture fails"
if "$NODE_BIN" "$CHECK_SCRIPT" \
  --index-html "$TMP_DIR/index-no-public-mode.html" \
  --main-js "$TMP_DIR/main.js" \
  --styles-css "$TMP_DIR/styles.css" \
  >"$TMP_DIR/missing-public-mode.log" 2>&1; then
  echo "desktop admin-console contract failed: expected missing public-app-mode fixture to fail"
  cat "$TMP_DIR/missing-public-mode.log"
  exit 1
fi
if ! grep -q "public-app-mode" "$TMP_DIR/missing-public-mode.log"; then
  echo "desktop admin-console contract failed: missing public-app-mode failure detail"
  cat "$TMP_DIR/missing-public-mode.log"
  exit 1
fi

if [[ "$RUN_NATIVE_TESTS" == "1" ]]; then
  echo "[desktop-admin-console] native public/admin command guards pass"
  pushd apps/desktop/src-tauri >/dev/null
  cargo test --no-default-features tests::admin_console_guard_blocks_public_mode_commands -- --exact
  cargo test --features admin-console tests::admin_console_guard_blocks_public_mode_commands -- --exact
  popd >/dev/null
else
  echo "[desktop-admin-console] native public/admin command guards skipped"
fi

echo "desktop admin-console contract integration check ok"
