#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$TMP_DIR/data" "$TMP_DIR/runtime" "$TMP_DIR/bin"
SOURCE_KEY="$TMP_DIR/data/exit.key"
CAPTURE_PATH="$TMP_DIR/captured_path.txt"
CAPTURE_MODE="$TMP_DIR/captured_mode.txt"
CAPTURE_CMP="$TMP_DIR/captured_cmp.txt"

printf '%s\n' 'test-private-key' >"$SOURCE_KEY"
chmod 0644 "$SOURCE_KEY"

cat >"$TMP_DIR/bin/capture-entrypoint-env" <<'EOF_CAPTURE'
#!/usr/bin/env sh
set -eu
printf '%s\n' "$EXIT_WG_PRIVATE_KEY_PATH" >"$CAPTURE_PATH"
stat -c '%a' "$EXIT_WG_PRIVATE_KEY_PATH" >"$CAPTURE_MODE"
cmp "$SOURCE_KEY" "$EXIT_WG_PRIVATE_KEY_PATH" >"$CAPTURE_CMP"
EOF_CAPTURE
chmod +x "$TMP_DIR/bin/capture-entrypoint-env"

cat >"$TMP_DIR/bin/realpath" <<'EOF_REALPATH'
#!/usr/bin/env sh
if [ "${1:-}" = "-m" ]; then
  echo "realpath: -m: No such file or directory" >&2
  exit 1
fi
exit 127
EOF_REALPATH
chmod +x "$TMP_DIR/bin/realpath"

WG_BACKEND=command \
EXIT_WG_PRIVATE_KEY_PATH="$SOURCE_KEY" \
EXIT_WG_PRIVATE_KEY_ROOT="$TMP_DIR/data" \
EXIT_WG_PRIVATE_KEY_RUNTIME_PARENT="$TMP_DIR/runtime" \
EXIT_WG_PRIVATE_KEY_FORCE_RUNTIME_COPY=1 \
PRIVACYNODE_ENTRYPOINT_EXEC="$TMP_DIR/bin/capture-entrypoint-env" \
CAPTURE_PATH="$CAPTURE_PATH" \
CAPTURE_MODE="$CAPTURE_MODE" \
CAPTURE_CMP="$CAPTURE_CMP" \
SOURCE_KEY="$SOURCE_KEY" \
PATH="$TMP_DIR/bin:$PATH" \
sh "$ROOT_DIR/deploy/entrypoint.sh" --exit >/tmp/integration_entrypoint_runtime_copy.log 2>&1

runtime_key="$(cat "$CAPTURE_PATH")"
if [[ "$runtime_key" == "$SOURCE_KEY" ]]; then
  echo "expected entrypoint to switch EXIT_WG_PRIVATE_KEY_PATH to runtime copy"
  cat /tmp/integration_entrypoint_runtime_copy.log
  exit 1
fi
runtime_mode="$(cat "$CAPTURE_MODE")"
case "$runtime_mode" in
  *00) ;;
  *)
    echo "expected runtime key to have owner-only permissions, got $runtime_mode"
    cat /tmp/integration_entrypoint_runtime_copy.log
    exit 1
    ;;
esac
if ! rg -q 'entrypoint: copied EXIT_WG_PRIVATE_KEY_PATH to owner-only runtime secret' /tmp/integration_entrypoint_runtime_copy.log; then
  echo "expected runtime-copy log line"
  cat /tmp/integration_entrypoint_runtime_copy.log
  exit 1
fi
if rg -q 'realpath: -m' /tmp/integration_entrypoint_runtime_copy.log; then
  echo "entrypoint leaked unsupported realpath -m error instead of using fallback"
  cat /tmp/integration_entrypoint_runtime_copy.log
  exit 1
fi

LINK_KEY="$TMP_DIR/data/link.key"
ln -s "$SOURCE_KEY" "$LINK_KEY"
set +e
WG_BACKEND=command \
EXIT_WG_PRIVATE_KEY_PATH="$LINK_KEY" \
EXIT_WG_PRIVATE_KEY_ROOT="$TMP_DIR/data" \
PRIVACYNODE_ENTRYPOINT_EXEC="$TMP_DIR/bin/capture-entrypoint-env" \
PATH="$TMP_DIR/bin:$PATH" \
sh "$ROOT_DIR/deploy/entrypoint.sh" --exit >/tmp/integration_entrypoint_symlink_reject.log 2>&1
symlink_rc=$?
set -e
if [[ "$symlink_rc" -eq 0 ]]; then
  echo "expected entrypoint to reject symlink key path"
  cat /tmp/integration_entrypoint_symlink_reject.log
  exit 1
fi
if ! rg -q 'refusing EXIT_WG_PRIVATE_KEY_PATH symlink target' /tmp/integration_entrypoint_symlink_reject.log; then
  echo "expected symlink rejection message"
  cat /tmp/integration_entrypoint_symlink_reject.log
  exit 1
fi

echo "entrypoint wg key runtime copy integration check ok"
