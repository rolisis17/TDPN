#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq rg sed sort diff awk mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

REQUIRED_FILES=(
  "apps/desktop/README.md"
  "apps/desktop/package.json"
  "apps/desktop/index.html"
  "apps/desktop/src/main.js"
  "apps/desktop/src-tauri/Cargo.toml"
  "apps/desktop/src-tauri/src/main.rs"
  "apps/desktop/src-tauri/src/local_api.rs"
  "apps/desktop/src-tauri/tauri.conf.json"
  "apps/desktop/src-tauri/capabilities/default.json"
)

for path in "${REQUIRED_FILES[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "desktop scaffold contract failed: missing required file: $path"
    exit 1
  fi
done
echo "[desktop-scaffold] required files exist"

RELEASE_SCAFFOLD_FILES=(
  "scripts/windows/desktop_release_bundle.ps1"
  "scripts/windows/desktop_release_bundle.cmd"
)
for path in "${RELEASE_SCAFFOLD_FILES[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "desktop scaffold contract failed: missing release scaffold script: $path"
    exit 1
  fi
done
echo "[desktop-scaffold] release scaffold scripts exist"

WINDOWS_NATIVE_BOOTSTRAP_FILES=(
  "scripts/windows/desktop_native_bootstrap.ps1"
  "scripts/windows/desktop_native_bootstrap.cmd"
  "scripts/windows/local_api_session.ps1"
)
for path in "${WINDOWS_NATIVE_BOOTSTRAP_FILES[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "desktop scaffold contract failed: missing windows-native bootstrap script: $path"
    exit 1
  fi
done
echo "[desktop-scaffold] windows-native bootstrap scripts exist"

JSON_FILES=(
  "apps/desktop/package.json"
  "apps/desktop/src-tauri/tauri.conf.json"
  "apps/desktop/src-tauri/capabilities/default.json"
)
for path in "${JSON_FILES[@]}"; do
  if ! jq empty "$path" >/dev/null 2>&1; then
    echo "desktop scaffold contract failed: invalid JSON: $path"
    exit 1
  fi
done
echo "[desktop-scaffold] JSON files are valid"

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

JS_FILE="apps/desktop/src/main.js"
RUST_FILE="apps/desktop/src-tauri/src/main.rs"

if ! rg -q -- '(invoke\("control_[a-z_]+"|call\("[^"]+",[[:space:]]*"control_[a-z_]+")' "$JS_FILE"; then
  echo "desktop scaffold contract failed: no control_* command calls found in $JS_FILE"
  exit 1
fi

{
  rg -o --no-filename 'invoke\("control_[a-z_]+"' "$JS_FILE" \
    | sed -E 's/invoke\("(control_[a-z_]+)"/\1/' || true
  rg -o --no-filename 'call\("[^"]+",[[:space:]]*"control_[a-z_]+"' "$JS_FILE" \
    | sed -E 's/.*"(control_[a-z_]+)"/\1/' || true
} | sort -u >"$TMP_DIR/js_controls.txt"

if [[ ! -s "$TMP_DIR/js_controls.txt" ]]; then
  echo "desktop scaffold contract failed: no control_* command names could be extracted from $JS_FILE"
  exit 1
fi

rg --no-filename '^(async[[:space:]]+)?fn[[:space:]]+control_[a-z_]+' "$RUST_FILE" \
  | sed -E 's/^(async[[:space:]]+)?fn[[:space:]]+(control_[a-z_]+).*/\2/' \
  | sort -u >"$TMP_DIR/rust_fn_controls.txt"

awk '/generate_handler!\[/,/]/ { print }' "$RUST_FILE" \
  | rg -o --no-filename 'control_[a-z_]+' \
  | sort -u >"$TMP_DIR/rust_handler_controls.txt"

if [[ ! -s "$TMP_DIR/rust_fn_controls.txt" ]]; then
  echo "desktop scaffold contract failed: no Rust control_* bridge functions found in $RUST_FILE"
  exit 1
fi

if [[ ! -s "$TMP_DIR/rust_handler_controls.txt" ]]; then
  echo "desktop scaffold contract failed: no Rust control_* commands found in generate_handler block in $RUST_FILE"
  exit 1
fi

extract_service_lifecycle_controls() {
  local source_file="$1"
  local output_file="$2"
  awk -F'_' '
    BEGIN {
      verbs["install"] = 1
      verbs["uninstall"] = 1
      verbs["start"] = 1
      verbs["stop"] = 1
      verbs["restart"] = 1
      verbs["status"] = 1
      verbs["enable"] = 1
      verbs["disable"] = 1
      verbs["reload"] = 1
    }
    /^control_[a-z0-9_]+$/ {
      has_service_scope = 0
      has_lifecycle_verb = 0
      for (i = 2; i <= NF; i++) {
        if ($i == "service" || $i == "daemon") {
          has_service_scope = 1
        }
        if ($i in verbs) {
          has_lifecycle_verb = 1
        }
      }
      if (has_service_scope && has_lifecycle_verb) {
        print $0
      }
    }
  ' "$source_file" | sort -u >"$output_file"
}

extract_service_lifecycle_controls "$TMP_DIR/js_controls.txt" "$TMP_DIR/js_service_lifecycle_controls.txt"
extract_service_lifecycle_controls "$TMP_DIR/rust_fn_controls.txt" "$TMP_DIR/rust_fn_service_lifecycle_controls.txt"
extract_service_lifecycle_controls "$TMP_DIR/rust_handler_controls.txt" "$TMP_DIR/rust_handler_service_lifecycle_controls.txt"
cat \
  "$TMP_DIR/js_service_lifecycle_controls.txt" \
  "$TMP_DIR/rust_fn_service_lifecycle_controls.txt" \
  "$TMP_DIR/rust_handler_service_lifecycle_controls.txt" \
  | sort -u >"$TMP_DIR/combined_service_lifecycle_controls.txt"

if [[ -s "$TMP_DIR/combined_service_lifecycle_controls.txt" ]]; then
  if ! diff -u "$TMP_DIR/js_service_lifecycle_controls.txt" "$TMP_DIR/rust_fn_service_lifecycle_controls.txt" >/dev/null; then
    echo "desktop scaffold contract failed: JS/Rust service lifecycle control_* command set mismatch"
    echo "--- js service lifecycle controls"
    cat "$TMP_DIR/js_service_lifecycle_controls.txt"
    echo "--- rust function service lifecycle controls"
    cat "$TMP_DIR/rust_fn_service_lifecycle_controls.txt"
    exit 1
  fi

  if ! diff -u "$TMP_DIR/rust_fn_service_lifecycle_controls.txt" "$TMP_DIR/rust_handler_service_lifecycle_controls.txt" >/dev/null; then
    echo "desktop scaffold contract failed: Rust service lifecycle control_* functions are not aligned with generate_handler registration"
    echo "--- rust function service lifecycle controls"
    cat "$TMP_DIR/rust_fn_service_lifecycle_controls.txt"
    echo "--- rust handler service lifecycle controls"
    cat "$TMP_DIR/rust_handler_service_lifecycle_controls.txt"
    exit 1
  fi
  echo "[desktop-scaffold] service lifecycle control_* command names align across JS and Rust bridge"
else
  echo "[desktop-scaffold] service lifecycle control_* commands not present; lifecycle alignment check skipped"
fi

if ! diff -u "$TMP_DIR/js_controls.txt" "$TMP_DIR/rust_fn_controls.txt" >/dev/null; then
  echo "desktop scaffold contract failed: JS invoke control_* command set does not match Rust bridge function set"
  echo "--- js controls"
  cat "$TMP_DIR/js_controls.txt"
  echo "--- rust function controls"
  cat "$TMP_DIR/rust_fn_controls.txt"
  exit 1
fi

if ! diff -u "$TMP_DIR/rust_fn_controls.txt" "$TMP_DIR/rust_handler_controls.txt" >/dev/null; then
  echo "desktop scaffold contract failed: Rust bridge control_* functions are not aligned with generate_handler registration"
  echo "--- rust function controls"
  cat "$TMP_DIR/rust_fn_controls.txt"
  echo "--- rust handler controls"
  cat "$TMP_DIR/rust_handler_controls.txt"
  exit 1
fi
echo "[desktop-scaffold] control_* command names align across JS and Rust bridge"

README_FILE="apps/desktop/README.md"
if ! rg -qi -- 'scaffold' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must clearly mention scaffold status"
  exit 1
fi
if ! rg -qi -- 'not production-ready|intentionally lightweight|does not include yet' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must clearly communicate non-production scaffold nature"
  exit 1
fi
if ! rg -qi -- 'update[[:space:]-]*channel' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must mention update channel behavior"
  exit 1
fi
if ! rg -q -- 'TDPN_[A-Z0-9_]*UPDATE[A-Z0-9_]*CHANNEL[A-Z0-9_]*' "$README_FILE"; then
  echo "desktop scaffold contract failed: README must document update channel env knobs (for example TDPN_*UPDATE*CHANNEL*)"
  exit 1
fi
echo "[desktop-scaffold] README states scaffold/non-production intent"

echo "desktop scaffold contract integration check ok"
