#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp jq rg tar; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
TMP_BIN="$TMP_DIR/bin"
mkdir -p "$TMP_BIN"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

FAKE_EASY_NODE="$TMP_DIR/fake_easy_node.sh"
CAPTURE="$TMP_DIR/runbook_capture.log"

cat >"$FAKE_EASY_NODE" <<'EOF_FAKE_EASY_NODE'
#!/usr/bin/env bash
set -euo pipefail
cmd="${1:-}"
printf '%s\n' "$*" >>"${CAPTURE_FILE:?}"
case "$cmd" in
  prod-preflight)
    exit "${FAKE_PREFLIGHT_RC:-0}"
    ;;
  rotate-server-secrets)
    exit "${FAKE_ROTATE_RC:-0}"
    ;;
  admin-signing-rotate)
    exit "${FAKE_SIGNING_RC:-0}"
    ;;
  *)
    exit 0
    ;;
esac
EOF_FAKE_EASY_NODE
chmod +x "$FAKE_EASY_NODE"

echo "[prod-key-rotation] apply success path"
SUCCESS_BACKUP="$TMP_DIR/success_backup"
SUCCESS_SUMMARY="$TMP_DIR/success_summary.json"
: >"$CAPTURE"
CAPTURE_FILE="$CAPTURE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
./scripts/prod_key_rotation_runbook.sh \
  --mode authority \
  --backup-dir "$SUCCESS_BACKUP" \
  --summary-json "$SUCCESS_SUMMARY" \
  --preflight-check 1 \
  --preflight-live 0 \
  --preflight-timeout-sec 7 \
  --rotate-server-secrets 1 \
  --rotate-admin-signing 1 \
  --key-history 4 \
  --restart 0 \
  --restart-issuer 0 \
  --show-secrets 0 \
  --rollback-on-fail 1 \
  --restart-after-rollback 0 \
  --print-summary-json 0 >/tmp/integration_prod_key_rotation_runbook_apply_ok.log 2>&1

if [[ ! -f "$SUCCESS_SUMMARY" ]]; then
  echo "prod key-rotation runbook did not produce summary json on success"
  cat /tmp/integration_prod_key_rotation_runbook_apply_ok.log
  exit 1
fi
if [[ ! -f "$SUCCESS_BACKUP/prod_key_rotation_snapshot.tar.gz" ]]; then
  echo "prod key-rotation runbook did not produce backup tarball on success"
  ls -la "$SUCCESS_BACKUP" || true
  exit 1
fi
if [[ "$(jq -r '.status' "$SUCCESS_SUMMARY")" != "ok" ]]; then
  echo "prod key-rotation success summary has unexpected status"
  cat "$SUCCESS_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.action' "$SUCCESS_SUMMARY")" != "apply" ]]; then
  echo "prod key-rotation success summary has unexpected action"
  cat "$SUCCESS_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.policy.key_history' "$SUCCESS_SUMMARY")" != "4" ]]; then
  echo "prod key-rotation success summary missing key_history policy"
  cat "$SUCCESS_SUMMARY"
  exit 1
fi
if [[ "$(rg -c '^prod-preflight' "$CAPTURE")" -ne 2 ]]; then
  echo "prod key-rotation success expected two preflight calls"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^rotate-server-secrets --restart 0 --rotate-issuer-admin 1 --show-secrets 0$' "$CAPTURE"; then
  echo "prod key-rotation success missing rotate-server-secrets call"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^admin-signing-rotate --restart-issuer 0 --key-history 4$' "$CAPTURE"; then
  echo "prod key-rotation success missing admin-signing-rotate call"
  cat "$CAPTURE"
  exit 1
fi

echo "[prod-key-rotation] apply fail path with rollback"
FAIL_BACKUP="$TMP_DIR/fail_backup"
FAIL_SUMMARY="$TMP_DIR/fail_summary.json"
: >"$CAPTURE"
set +e
CAPTURE_FILE="$CAPTURE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
FAKE_ROTATE_RC=37 \
./scripts/prod_key_rotation_runbook.sh \
  --mode authority \
  --backup-dir "$FAIL_BACKUP" \
  --summary-json "$FAIL_SUMMARY" \
  --preflight-check 0 \
  --rotate-server-secrets 1 \
  --rotate-admin-signing 1 \
  --key-history 2 \
  --restart 0 \
  --restart-issuer 0 \
  --rollback-on-fail 1 \
  --restart-after-rollback 0 >/tmp/integration_prod_key_rotation_runbook_apply_fail.log 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 37 ]]; then
  echo "prod key-rotation fail path returned unexpected rc=$fail_rc (expected 37)"
  cat /tmp/integration_prod_key_rotation_runbook_apply_fail.log
  exit 1
fi
if [[ ! -f "$FAIL_SUMMARY" ]]; then
  echo "prod key-rotation fail path did not produce summary json"
  cat /tmp/integration_prod_key_rotation_runbook_apply_fail.log
  exit 1
fi
if [[ "$(jq -r '.status' "$FAIL_SUMMARY")" != "fail" ]]; then
  echo "prod key-rotation fail summary has unexpected status"
  cat "$FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.failure_step' "$FAIL_SUMMARY")" != "rotate_server_secrets" ]]; then
  echo "prod key-rotation fail summary missing rotate_server_secrets failure step"
  cat "$FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.rollback.performed' "$FAIL_SUMMARY")" != "true" ]]; then
  echo "prod key-rotation fail summary did not mark rollback as performed"
  cat "$FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.rollback.restore_rc' "$FAIL_SUMMARY")" != "0" ]]; then
  echo "prod key-rotation fail summary reported rollback restore failure"
  cat "$FAIL_SUMMARY"
  exit 1
fi
if rg -q '^admin-signing-rotate' "$CAPTURE"; then
  echo "prod key-rotation fail path should not invoke admin-signing-rotate after rotate-server-secrets failure"
  cat "$CAPTURE"
  exit 1
fi

echo "[prod-key-rotation] explicit rollback action"
ROLLBACK_SUMMARY="$TMP_DIR/rollback_summary.json"
CAPTURE_FILE="$CAPTURE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
./scripts/prod_key_rotation_runbook.sh \
  --rollback-from "$SUCCESS_BACKUP" \
  --mode authority \
  --restart-after-rollback 0 \
  --summary-json "$ROLLBACK_SUMMARY" >/tmp/integration_prod_key_rotation_runbook_rollback.log 2>&1
if [[ "$(jq -r '.action' "$ROLLBACK_SUMMARY")" != "rollback" ]]; then
  echo "prod key-rotation rollback summary has unexpected action"
  cat "$ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.status' "$ROLLBACK_SUMMARY")" != "ok" ]]; then
  echo "prod key-rotation rollback summary has unexpected status"
  cat "$ROLLBACK_SUMMARY"
  exit 1
fi

cat >"$TMP_BIN/docker" <<'EOF_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "compose" && "${2:-}" == "version" ]]; then
  printf 'Docker Compose version vtest\n'
  exit 0
fi
if [[ "${1:-}" == "compose" ]]; then
  exit 0
fi
if [[ "${1:-}" == "--version" ]]; then
  printf 'Docker version test\n'
  exit 0
fi
if [[ "${1:-}" == "info" ]]; then
  exit 0
fi
exit 0
EOF_DOCKER
chmod +x "$TMP_BIN/docker"

FAKE_RUNBOOK="$TMP_DIR/fake_prod_key_rotation_runbook.sh"
DISPATCH_CAPTURE="$TMP_DIR/dispatch_capture.log"
cat >"$FAKE_RUNBOOK" <<'EOF_FAKE_RUNBOOK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${DISPATCH_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_RUNBOOK
chmod +x "$FAKE_RUNBOOK"

echo "[prod-key-rotation] easy_node command dispatch"
PATH="$TMP_BIN:$PATH" \
DISPATCH_CAPTURE_FILE="$DISPATCH_CAPTURE" \
PROD_KEY_ROTATION_RUNBOOK_SCRIPT="$FAKE_RUNBOOK" \
./scripts/easy_node.sh prod-key-rotation-runbook \
  --mode provider \
  --preflight-check 0 \
  --key-history 6 >/tmp/integration_prod_key_rotation_runbook_dispatch.log 2>&1
if ! rg -q -- '--mode provider' "$DISPATCH_CAPTURE"; then
  echo "easy-node prod-key-rotation-runbook did not forward --mode"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--preflight-check 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node prod-key-rotation-runbook did not forward --preflight-check"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--key-history 6' "$DISPATCH_CAPTURE"; then
  echo "easy-node prod-key-rotation-runbook did not forward --key-history"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi

echo "prod key-rotation runbook integration check ok"
