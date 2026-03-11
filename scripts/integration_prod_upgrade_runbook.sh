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

AUTH_ENV_FILE="$ROOT_DIR/deploy/.env.easy.server"
AUTH_ENV_CREATED=0

cleanup() {
  if [[ "$AUTH_ENV_CREATED" == "1" ]]; then
    rm -f "$AUTH_ENV_FILE"
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

if [[ ! -f "$AUTH_ENV_FILE" ]]; then
  mkdir -p "$(dirname "$AUTH_ENV_FILE")"
  cat >"$AUTH_ENV_FILE" <<'EOF_ENV'
DIRECTORY_PUBLIC_URL=http://127.0.0.1:8081
EOF_ENV
  AUTH_ENV_CREATED=1
fi

FAKE_EASY_NODE="$TMP_DIR/fake_easy_node.sh"
EASY_CAPTURE="$TMP_DIR/easy_capture.log"
cat >"$FAKE_EASY_NODE" <<'EOF_FAKE_EASY_NODE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${EASY_CAPTURE_FILE:?}"
cmd="${1:-}"
if [[ "$cmd" == "prod-preflight" ]]; then
  exit "${FAKE_PREFLIGHT_RC:-0}"
fi
exit 0
EOF_FAKE_EASY_NODE
chmod +x "$FAKE_EASY_NODE"

cat >"$TMP_BIN/docker" <<'EOF_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${DOCKER_CAPTURE_FILE:?}"
if [[ "${1:-}" == "compose" && "${2:-}" == "version" ]]; then
  printf 'Docker Compose version vtest\n'
  exit 0
fi
if [[ "${1:-}" == "--version" ]]; then
  printf 'Docker version test\n'
  exit 0
fi
if [[ "${1:-}" == "info" ]]; then
  exit 0
fi
if [[ "${FAKE_DOCKER_FAIL_ON_ARG:-}" != "" ]]; then
  for arg in "$@"; do
    if [[ "$arg" == "${FAKE_DOCKER_FAIL_ON_ARG}" ]]; then
      exit "${FAKE_DOCKER_FAIL_RC:-66}"
    fi
  done
fi
exit 0
EOF_DOCKER
chmod +x "$TMP_BIN/docker"

echo "[prod-upgrade] apply success path"
SUCCESS_BACKUP="$TMP_DIR/success_backup"
SUCCESS_SUMMARY="$TMP_DIR/success_summary.json"
DOCKER_CAPTURE="$TMP_DIR/docker_success.log"
: >"$DOCKER_CAPTURE"
: >"$EASY_CAPTURE"
PATH="$TMP_BIN:$PATH" \
DOCKER_CAPTURE_FILE="$DOCKER_CAPTURE" \
EASY_CAPTURE_FILE="$EASY_CAPTURE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
PROD_UPGRADE_DOCKER_BIN=docker \
./scripts/prod_upgrade_runbook.sh \
  --mode authority \
  --backup-dir "$SUCCESS_BACKUP" \
  --summary-json "$SUCCESS_SUMMARY" \
  --preflight-check 1 \
  --preflight-live 0 \
  --preflight-timeout-sec 7 \
  --compose-pull 1 \
  --compose-build 1 \
  --restart 1 \
  --rollback-on-fail 1 \
  --restart-after-rollback 0 >/tmp/integration_prod_upgrade_runbook_apply_ok.log 2>&1

if [[ ! -f "$SUCCESS_SUMMARY" ]]; then
  echo "prod-upgrade runbook did not produce summary json on success"
  cat /tmp/integration_prod_upgrade_runbook_apply_ok.log
  exit 1
fi
if [[ ! -f "$SUCCESS_BACKUP/prod_upgrade_snapshot.tar.gz" ]]; then
  echo "prod-upgrade runbook did not produce backup tarball on success"
  ls -la "$SUCCESS_BACKUP" || true
  exit 1
fi
if [[ "$(jq -r '.status' "$SUCCESS_SUMMARY")" != "ok" ]]; then
  echo "prod-upgrade success summary has unexpected status"
  cat "$SUCCESS_SUMMARY"
  exit 1
fi
if [[ "$(rg -c '^prod-preflight' "$EASY_CAPTURE")" -ne 2 ]]; then
  echo "prod-upgrade success expected two preflight calls"
  cat "$EASY_CAPTURE"
  exit 1
fi
if ! rg -q -- 'compose --env-file .* pull directory issuer entry-exit' "$DOCKER_CAPTURE"; then
  echo "prod-upgrade success missing compose pull call"
  cat "$DOCKER_CAPTURE"
  exit 1
fi
if ! rg -q -- 'compose --env-file .* build directory issuer entry-exit' "$DOCKER_CAPTURE"; then
  echo "prod-upgrade success missing compose build call"
  cat "$DOCKER_CAPTURE"
  exit 1
fi
if ! rg -q -- 'compose --env-file .* up -d directory issuer entry-exit' "$DOCKER_CAPTURE"; then
  echo "prod-upgrade success missing compose up call"
  cat "$DOCKER_CAPTURE"
  exit 1
fi

echo "[prod-upgrade] apply fail path with rollback"
FAIL_BACKUP="$TMP_DIR/fail_backup"
FAIL_SUMMARY="$TMP_DIR/fail_summary.json"
DOCKER_CAPTURE_FAIL="$TMP_DIR/docker_fail.log"
: >"$DOCKER_CAPTURE_FAIL"
: >"$EASY_CAPTURE"
set +e
PATH="$TMP_BIN:$PATH" \
DOCKER_CAPTURE_FILE="$DOCKER_CAPTURE_FAIL" \
EASY_CAPTURE_FILE="$EASY_CAPTURE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
PROD_UPGRADE_DOCKER_BIN=docker \
FAKE_DOCKER_FAIL_ON_ARG=build \
FAKE_DOCKER_FAIL_RC=66 \
./scripts/prod_upgrade_runbook.sh \
  --mode authority \
  --backup-dir "$FAIL_BACKUP" \
  --summary-json "$FAIL_SUMMARY" \
  --preflight-check 0 \
  --compose-pull 0 \
  --compose-build 1 \
  --restart 1 \
  --rollback-on-fail 1 \
  --restart-after-rollback 0 >/tmp/integration_prod_upgrade_runbook_apply_fail.log 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 66 ]]; then
  echo "prod-upgrade fail path returned unexpected rc=$fail_rc (expected 66)"
  cat /tmp/integration_prod_upgrade_runbook_apply_fail.log
  exit 1
fi
if [[ "$(jq -r '.status' "$FAIL_SUMMARY")" != "fail" ]]; then
  echo "prod-upgrade fail summary has unexpected status"
  cat "$FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.failure_step' "$FAIL_SUMMARY")" != "compose_upgrade" ]]; then
  echo "prod-upgrade fail summary missing compose_upgrade failure step"
  cat "$FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.rollback.performed' "$FAIL_SUMMARY")" != "true" ]]; then
  echo "prod-upgrade fail summary did not mark rollback as performed"
  cat "$FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.rollback.restore_rc' "$FAIL_SUMMARY")" != "0" ]]; then
  echo "prod-upgrade fail summary reported rollback restore failure"
  cat "$FAIL_SUMMARY"
  exit 1
fi

echo "[prod-upgrade] explicit rollback action"
ROLLBACK_SUMMARY="$TMP_DIR/rollback_summary.json"
PATH="$TMP_BIN:$PATH" \
DOCKER_CAPTURE_FILE="$DOCKER_CAPTURE" \
EASY_CAPTURE_FILE="$EASY_CAPTURE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
PROD_UPGRADE_DOCKER_BIN=docker \
./scripts/prod_upgrade_runbook.sh \
  --rollback-from "$SUCCESS_BACKUP" \
  --mode authority \
  --restart-after-rollback 0 \
  --summary-json "$ROLLBACK_SUMMARY" >/tmp/integration_prod_upgrade_runbook_rollback.log 2>&1
if [[ "$(jq -r '.action' "$ROLLBACK_SUMMARY")" != "rollback" ]]; then
  echo "prod-upgrade rollback summary has unexpected action"
  cat "$ROLLBACK_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.status' "$ROLLBACK_SUMMARY")" != "ok" ]]; then
  echo "prod-upgrade rollback summary has unexpected status"
  cat "$ROLLBACK_SUMMARY"
  exit 1
fi

FAKE_RUNBOOK="$TMP_DIR/fake_prod_upgrade_runbook.sh"
DISPATCH_CAPTURE="$TMP_DIR/dispatch_capture.log"
cat >"$FAKE_RUNBOOK" <<'EOF_FAKE_RUNBOOK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${DISPATCH_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_RUNBOOK
chmod +x "$FAKE_RUNBOOK"

echo "[prod-upgrade] easy_node command dispatch"
PATH="$TMP_BIN:$PATH" \
DOCKER_CAPTURE_FILE="$DOCKER_CAPTURE" \
DISPATCH_CAPTURE_FILE="$DISPATCH_CAPTURE" \
PROD_UPGRADE_RUNBOOK_SCRIPT="$FAKE_RUNBOOK" \
./scripts/easy_node.sh prod-upgrade-runbook \
  --mode provider \
  --compose-pull 0 \
  --compose-build 1 >/tmp/integration_prod_upgrade_runbook_dispatch.log 2>&1
if ! rg -q -- '--mode provider' "$DISPATCH_CAPTURE"; then
  echo "easy-node prod-upgrade-runbook did not forward --mode"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--compose-pull 0' "$DISPATCH_CAPTURE"; then
  echo "easy-node prod-upgrade-runbook did not forward --compose-pull"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--compose-build 1' "$DISPATCH_CAPTURE"; then
  echo "easy-node prod-upgrade-runbook did not forward --compose-build"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi

echo "prod upgrade runbook integration check ok"
