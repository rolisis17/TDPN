#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ADMIN_SCRIPT="${DESKTOP_ADMIN_CONSOLE_RELEASE_BUNDLE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/linux/desktop_admin_console_release_bundle.sh}"
PUBLIC_LINUX_SCRIPT="${DESKTOP_RELEASE_BUNDLE_LINUX_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/linux/desktop_release_bundle.sh}"
ADMIN_CONFIG="${DESKTOP_ADMIN_CONSOLE_TAURI_CONFIG_UNDER_TEST:-$ROOT_DIR/apps/desktop/src-tauri/tauri.admin-console.conf.json}"
PUBLIC_CONFIG="$ROOT_DIR/apps/desktop/src-tauri/tauri.conf.json"
EASY_NODE_SCRIPT="${EASY_NODE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/easy_node.sh}"

for file_path in "$ADMIN_SCRIPT" "$PUBLIC_LINUX_SCRIPT" "$ADMIN_CONFIG" "$PUBLIC_CONFIG" "$EASY_NODE_SCRIPT"; do
  if [[ ! -f "$file_path" ]]; then
    echo "desktop admin console release bundle guardrails failed: missing file: $file_path"
    exit 1
  fi
done

assert_marker_present() {
  local marker="$1"
  local file_path="$2"
  if ! grep -Fq -- "$marker" "$file_path"; then
    echo "desktop admin console release bundle guardrails failed: missing marker '$marker' in $file_path"
    exit 1
  fi
}

assert_marker_absent() {
  local marker="$1"
  local file_path="$2"
  if grep -Fq -- "$marker" "$file_path"; then
    echo "desktop admin console release bundle guardrails failed: forbidden marker '$marker' in $file_path"
    exit 1
  fi
}

assert_distinct_config_value() {
  local label="$1"
  local admin_marker="$2"
  local public_marker="$3"
  assert_marker_present "$admin_marker" "$ADMIN_CONFIG"
  assert_marker_present "$public_marker" "$PUBLIC_CONFIG"
  if [[ "$admin_marker" == "$public_marker" ]]; then
    echo "desktop admin console release bundle guardrails failed: $label is not distinct"
    exit 1
  fi
}

run_expect_pass() {
  local name="$1"
  shift
  local log_path="$TMP_DIR/${name}.log"
  if "$@" >"$log_path" 2>&1; then
    return 0
  fi
  echo "desktop admin console release bundle guardrails failed: expected pass for $name"
  cat "$log_path"
  exit 1
}

run_expect_fail() {
  local name="$1"
  local expected_pattern="$2"
  shift 2
  local log_path="$TMP_DIR/${name}.log"
  if "$@" >"$log_path" 2>&1; then
    echo "desktop admin console release bundle guardrails failed: expected failure for $name"
    cat "$log_path"
    exit 1
  fi
  if ! grep -F -- "$expected_pattern" "$log_path" >/dev/null 2>&1; then
    echo "desktop admin console release bundle guardrails failed: missing expected failure text for $name"
    echo "expected pattern: $expected_pattern"
    cat "$log_path"
    exit 1
  fi
}

assert_forwarded_exact() {
  local capture_file="$1"
  local expected_marker="$2"
  shift 2
  local -a expected_args=("$@")
  local -a fields=()
  local expected_field_count
  local i
  local line

  line="$(sed -n '1p' "$capture_file" || true)"
  if [[ -z "$line" ]]; then
    echo "desktop admin console release bundle guardrails failed: missing easy_node wrapper capture"
    exit 1
  fi

  IFS=$'\t' read -r -a fields <<<"$line"
  if [[ "${fields[0]:-}" != "$expected_marker" ]]; then
    echo "desktop admin console release bundle guardrails failed: wrapper marker mismatch"
    echo "expected marker: $expected_marker"
    echo "$line"
    exit 1
  fi

  expected_field_count=$((1 + ${#expected_args[@]}))
  if [[ "${#fields[@]}" -ne "$expected_field_count" ]]; then
    echo "desktop admin console release bundle guardrails failed: wrapper arg count mismatch"
    echo "expected fields: $expected_field_count"
    echo "actual fields: ${#fields[@]}"
    echo "$line"
    exit 1
  fi

  i=0
  while [[ "$i" -lt "${#expected_args[@]}" ]]; do
    if [[ "${fields[$((i + 1))]:-}" != "${expected_args[$i]}" ]]; then
      echo "desktop admin console release bundle guardrails failed: wrapper arg mismatch at position $i"
      echo "expected: ${expected_args[$i]}"
      echo "actual: ${fields[$((i + 1))]:-}"
      echo "$line"
      exit 1
    fi
    i=$((i + 1))
  done
}

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "[desktop-admin-console-release-bundle-guardrails] dedicated config identity is distinct"
assert_distinct_config_value "productName" '"productName": "GPM Admin Console"' '"productName": "Global Private Mesh Desktop"'
assert_marker_present '"mainBinaryName": "gpm-admin-console"' "$ADMIN_CONFIG"
assert_marker_absent '"mainBinaryName": "gpm-admin-console"' "$PUBLIC_CONFIG"
assert_distinct_config_value "identifier" '"identifier": "com.gpm.admin-console"' '"identifier": "com.gpm.desktop"'
assert_distinct_config_value "window title" '"title": "GPM Admin Console"' '"title": "Global Private Mesh Desktop (Scaffold)"'
assert_marker_present '"beforeBuildCommand": "npm run build:admin-console"' "$ADMIN_CONFIG"
assert_marker_absent '"beforeBuildCommand": "npm run build:admin-console"' "$PUBLIC_CONFIG"

echo "[desktop-admin-console-release-bundle-guardrails] admin script uses admin renderer, feature, and config"
assert_marker_present 'GPM_DESKTOP_ADMIN_CONSOLE="1"' "$ADMIN_SCRIPT"
assert_marker_present 'GPM_DESKTOP_BUILD_ADMIN_CONSOLE="1"' "$ADMIN_SCRIPT"
assert_marker_present 'VITE_GPM_ADMIN_CONSOLE="1"' "$ADMIN_SCRIPT"
assert_marker_present 'npm run build:admin-console' "$ADMIN_SCRIPT"
assert_marker_present '"--features" "$ADMIN_FEATURE"' "$ADMIN_SCRIPT"
assert_marker_present '"--config" "src-tauri/tauri.admin-console.conf.json"' "$ADMIN_SCRIPT"
assert_marker_present 'assert_admin_tauri_args "${tauri_args[@]}"' "$ADMIN_SCRIPT"
assert_marker_present 'refuses missing admin-console feature' "$ADMIN_SCRIPT"
assert_marker_present 'refuses custom Tauri config' "$ADMIN_SCRIPT"
assert_marker_present 'assert_admin_release_artifacts_present' "$ADMIN_SCRIPT"
assert_marker_present 'admin console release bundle build produced no artifacts' "$ADMIN_SCRIPT"
assert_marker_present 'artifact_validation_status=unsigned_scaffold_artifacts' "$ADMIN_SCRIPT"
assert_marker_present 'artifact_validation_status=skipped_no_artifacts' "$ADMIN_SCRIPT"
assert_marker_present 'release_ready=false' "$ADMIN_SCRIPT"

echo "[desktop-admin-console-release-bundle-guardrails] public Linux release remains public-only"
assert_marker_present 'GPM_DESKTOP_ADMIN_CONSOLE="0"' "$PUBLIC_LINUX_SCRIPT"
assert_marker_present 'GPM_DESKTOP_BUILD_ADMIN_CONSOLE="0"' "$PUBLIC_LINUX_SCRIPT"
assert_marker_present 'VITE_GPM_ADMIN_CONSOLE="0"' "$PUBLIC_LINUX_SCRIPT"
assert_marker_present 'assert_public_tauri_args "${tauri_args[@]}"' "$PUBLIC_LINUX_SCRIPT"
assert_marker_present 'public desktop release bundle refuses admin-console feature flags' "$PUBLIC_LINUX_SCRIPT"
assert_marker_present 'public desktop release bundle refuses --all-features' "$PUBLIC_LINUX_SCRIPT"

echo "[desktop-admin-console-release-bundle-guardrails] easy_node wrapper targets admin script"
assert_marker_present './scripts/easy_node.sh desktop-admin-console-release-bundle [desktop_admin_console_release_bundle args...]' "$EASY_NODE_SCRIPT"
assert_marker_present 'desktop_admin_console_release_bundle()' "$EASY_NODE_SCRIPT"
assert_marker_present 'DESKTOP_ADMIN_CONSOLE_RELEASE_BUNDLE_SCRIPT:-$ROOT_DIR/scripts/linux/desktop_admin_console_release_bundle.sh' "$EASY_NODE_SCRIPT"
assert_marker_present 'desktop_admin_console_release_bundle "$@"' "$EASY_NODE_SCRIPT"

EASY_NODE_ADMIN_WRAPPER_CAPTURE="$TMP_DIR/easy_node_admin_wrapper.tsv"
FAKE_ADMIN_WRAPPER="$TMP_DIR/fake_desktop_admin_console_release_bundle.sh"
cat >"$FAKE_ADMIN_WRAPPER" <<'EOF_FAKE_ADMIN_WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${EASY_NODE_ADMIN_CONSOLE_WRAPPER_CAPTURE_FILE:?}"
{
  printf '%s' "desktop_admin_console_release_bundle"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
exit "${FAKE_DESKTOP_ADMIN_CONSOLE_RELEASE_BUNDLE_RC:-0}"
EOF_FAKE_ADMIN_WRAPPER
chmod +x "$FAKE_ADMIN_WRAPPER"
: >"$EASY_NODE_ADMIN_WRAPPER_CAPTURE"
run_expect_pass \
  "easy_node_admin_wrapper_forwarding" \
  env \
    EASY_NODE_ADMIN_CONSOLE_WRAPPER_CAPTURE_FILE="$EASY_NODE_ADMIN_WRAPPER_CAPTURE" \
    DESKTOP_ADMIN_CONSOLE_RELEASE_BUNDLE_SCRIPT="$FAKE_ADMIN_WRAPPER" \
    bash "$EASY_NODE_SCRIPT" \
      desktop-admin-console-release-bundle \
      --skip-build \
      -- \
      --features \
      "admin-console,extra with spaces"
assert_forwarded_exact \
  "$EASY_NODE_ADMIN_WRAPPER_CAPTURE" \
  "desktop_admin_console_release_bundle" \
  --skip-build \
  -- \
  --features \
  "admin-console,extra with spaces"

echo "[desktop-admin-console-release-bundle-guardrails] skip-build path validates admin markers without building"
run_expect_pass \
  "admin_skip_build_pass" \
  bash "$ADMIN_SCRIPT" --skip-build
if ! grep -F -- "artifact_validation_status=" "$TMP_DIR/admin_skip_build_pass.log" >/dev/null 2>&1; then
  echo "desktop admin console release bundle guardrails failed: skip-build output must expose artifact validation status"
  cat "$TMP_DIR/admin_skip_build_pass.log"
  exit 1
fi
if ! grep -F -- "release_ready=" "$TMP_DIR/admin_skip_build_pass.log" >/dev/null 2>&1; then
  echo "desktop admin console release bundle guardrails failed: skip-build output must expose release readiness"
  cat "$TMP_DIR/admin_skip_build_pass.log"
  exit 1
fi

echo "[desktop-admin-console-release-bundle-guardrails] admin script rejects missing admin feature overrides"
run_expect_fail \
  "admin_missing_feature_fail" \
  "refuses missing admin-console feature" \
  bash "$ADMIN_SCRIPT" --skip-build -- --features public-only

run_expect_fail \
  "admin_empty_features_fail" \
  "refuses empty --features value" \
  bash "$ADMIN_SCRIPT" --skip-build -- --features

echo "[desktop-admin-console-release-bundle-guardrails] admin script rejects config override"
run_expect_fail \
  "admin_config_override_fail" \
  "refuses custom Tauri config" \
  bash "$ADMIN_SCRIPT" --skip-build -- --config src-tauri/tauri.conf.json

echo "[desktop-admin-console-release-bundle-guardrails] public script rejects admin-console feature"
run_expect_fail \
  "public_admin_feature_fail" \
  "public desktop release bundle refuses admin-console feature flags" \
  bash "$PUBLIC_LINUX_SCRIPT" --skip-build -- --features admin-console

echo "[desktop-admin-console-release-bundle-guardrails] negative fixture catches public-mode admin config"
NEGATIVE_ADMIN_CONFIG="$TMP_DIR/tauri.admin-console.public-fixture.conf.json"
cp "$ADMIN_CONFIG" "$NEGATIVE_ADMIN_CONFIG"
sed -i.bak \
  -e 's/"productName": "GPM Admin Console"/"productName": "Global Private Mesh Desktop"/' \
  -e 's/"identifier": "com.gpm.admin-console"/"identifier": "com.gpm.desktop"/' \
  -e 's/"title": "GPM Admin Console"/"title": "Global Private Mesh Desktop (Scaffold)"/' \
  "$NEGATIVE_ADMIN_CONFIG"

run_expect_fail \
  "negative_public_identity_fixture_fail" \
  "missing marker" \
  env DESKTOP_ADMIN_CONSOLE_TAURI_CONFIG_UNDER_TEST="$NEGATIVE_ADMIN_CONFIG" bash "$0"

echo "desktop admin console release bundle guardrails integration check ok"
