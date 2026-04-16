#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash rg go jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

AUTH_ENV="$ROOT_DIR/deploy/.env.easy.server"
PROVIDER_ENV="$ROOT_DIR/deploy/.env.easy.provider"
MODE_FILE="$ROOT_DIR/deploy/data/easy_node_server_mode.conf"
IDENTITY_FILE="$ROOT_DIR/deploy/data/easy_node_identity.conf"
HOSTS_FILE="$ROOT_DIR/data/easy_mode_hosts.conf"
TMP_DIR="$(mktemp -d)"
TMP_BIN="$TMP_DIR/bin"
mkdir -p "$TMP_BIN"

backup_file() {
  local src="$1"
  local name="$2"
  if [[ -f "$src" ]]; then
    cp "$src" "$TMP_DIR/${name}.bak"
  fi
}

restore_file() {
  local dst="$1"
  local name="$2"
  if [[ -f "$TMP_DIR/${name}.bak" ]]; then
    cp "$TMP_DIR/${name}.bak" "$dst"
  else
    rm -f "$dst"
  fi
}

cleanup() {
  restore_file "$AUTH_ENV" "auth_env"
  restore_file "$PROVIDER_ENV" "provider_env"
  restore_file "$MODE_FILE" "mode_file"
  restore_file "$IDENTITY_FILE" "identity_file"
  restore_file "$HOSTS_FILE" "hosts_file"
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

backup_file "$AUTH_ENV" "auth_env"
backup_file "$PROVIDER_ENV" "provider_env"
backup_file "$MODE_FILE" "mode_file"
backup_file "$IDENTITY_FILE" "identity_file"
backup_file "$HOSTS_FILE" "hosts_file"

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

cat >"$TMP_BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
output_file=""
write_fmt=""
url=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o)
      output_file="${2:-}"
      shift 2
      ;;
    -w)
      write_fmt="${2:-}"
      shift 2
      ;;
    http://*|https://*)
      url="$1"
      shift
      ;;
    *)
      shift
      ;;
  esac
done
if [[ "${FAKE_UPSERT_FAIL:-0}" == "1" && "$url" == *"/v1/admin/subject/upsert" ]]; then
  echo "upsert failed" >&2
  exit 22
fi
payload='{}'
code="200"
case "$url" in
  */v1/pubkeys)
    payload='{"issuer":"issuer-test","pub_keys":["k1"],"key_epoch":1,"min_token_epoch":1}'
    ;;
  */v1/admin/sync-status)
    payload='{"generated_at":1731000001,"peer":{"success":true,"success_sources":1,"source_operators":["op-sync-peer"],"required_operators":1,"quorum_met":true,"last_run_at":1731000000},"issuer":{"success":true,"success_sources":1,"source_operators":["op-sync-issuer"],"required_operators":1,"quorum_met":true,"last_run_at":1731000000}}'
    ;;
  */v1/admin/peer-status)
    payload='{"generated_at":1731000000,"peers":[{"url":"http://seed.local","configured":true,"discovered":false,"eligible":true,"cooling_down":false,"consecutive_failures":0}]}'
    ;;
  */v1/admin/subject/get*)
    payload='{"subject":"ok","kind":"client","tier":1}'
    ;;
  *)
    payload='{}'
    ;;
esac
if [[ -n "$output_file" ]]; then
  printf '%s\n' "$payload" >"$output_file"
else
  printf '%s\n' "$payload"
fi
if [[ -n "$write_fmt" ]]; then
  printf '%s' "$code"
fi
EOF_CURL

cat >"$TMP_BIN/wg" <<'EOF_WG'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "genkey" ]]; then
  echo "test-wg-private-key"
  exit 0
fi
if [[ "${1:-}" == "pubkey" ]]; then
  # server-up derives EXIT_WG_PUBKEY via `wg pubkey`
  cat >/dev/null || true
  echo "test-wg-public-key"
  exit 0
fi
exit 0
EOF_WG

chmod +x "$TMP_BIN/docker" "$TMP_BIN/curl" "$TMP_BIN/wg"

echo "[server-up-auto-invite] authority auto invite success"
AUTH_OK_LOG="$TMP_DIR/authority_auto_invite_ok.log"
PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
./scripts/easy_node.sh server-up \
  --mode authority \
  --public-host 203.0.113.10 \
  --beta-profile 1 \
  --prod-profile 0 \
  --auto-invite 1 \
  --auto-invite-count 1 \
  --auto-invite-tier 2 \
  --auto-invite-wait-sec 1 \
  --auto-invite-fail-open 0 >"$AUTH_OK_LOG" 2>&1

if ! rg -q 'auto invite: generating 1 key\(s\) tier=2 wait=1s' "$AUTH_OK_LOG"; then
  echo "expected authority auto-invite generation banner"
  cat "$AUTH_OK_LOG"
  exit 1
fi
if ! rg -q '^inv-[a-z0-9]+' "$AUTH_OK_LOG"; then
  echo "expected generated invite key in authority auto-invite output"
  cat "$AUTH_OK_LOG"
  exit 1
fi
if ! rg -q 'invite keys generated: 1 \(issuer=http://127.0.0.1:8082\)' "$AUTH_OK_LOG"; then
  echo "expected authority auto-invite summary output"
  cat "$AUTH_OK_LOG"
  exit 1
fi

echo "[server-up-auto-invite] authority federation-wait summary forwarding"
AUTH_FED_WAIT_LOG="$TMP_DIR/authority_federation_wait.log"
AUTH_FED_WAIT_SUMMARY="$TMP_DIR/authority_federation_wait_summary.json"
set +e
PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
./scripts/easy_node.sh server-up \
  --mode authority \
  --public-host 203.0.113.10 \
  --peer-directories http://198.51.100.20:8081 \
  --peer-identity-strict 0 \
  --beta-profile 1 \
  --prod-profile 0 \
  --auto-invite 0 \
  --federation-wait 1 \
  --federation-ready-timeout-sec 3 \
  --federation-poll-sec 1 \
  --federation-wait-summary-json "$AUTH_FED_WAIT_SUMMARY" \
  --federation-wait-print-summary-json 1 >"$AUTH_FED_WAIT_LOG" 2>&1
auth_fed_wait_rc=$?
set -e
if [[ "$auth_fed_wait_rc" -ne 0 ]]; then
  echo "expected authority server-up federation wait summary forwarding scenario to succeed"
  cat "$AUTH_FED_WAIT_LOG"
  exit 1
fi

if ! rg -q 'server-up federation wait: checking local directory federation readiness' "$AUTH_FED_WAIT_LOG"; then
  echo "expected server-up federation wait banner"
  cat "$AUTH_FED_WAIT_LOG"
  exit 1
fi
if ! rg -q '^server-federation-wait: READY' "$AUTH_FED_WAIT_LOG"; then
  echo "expected READY output from server-federation-wait during server-up"
  cat "$AUTH_FED_WAIT_LOG"
  exit 1
fi
if ! rg -q "^  summary_json: $AUTH_FED_WAIT_SUMMARY\$" "$AUTH_FED_WAIT_LOG"; then
  echo "expected federation wait summary artifact path in server-up output"
  cat "$AUTH_FED_WAIT_LOG"
  exit 1
fi
if [[ ! -f "$AUTH_FED_WAIT_SUMMARY" ]]; then
  echo "expected federation wait summary artifact from server-up forwarding"
  cat "$AUTH_FED_WAIT_LOG"
  exit 1
fi
if ! jq -e '.status == "ready" and .state == "ready"' "$AUTH_FED_WAIT_SUMMARY" >/dev/null; then
  echo "expected federation wait summary artifact to report ready state"
  cat "$AUTH_FED_WAIT_SUMMARY"
  exit 1
fi

echo "[server-up-auto-invite] authority auto invite fail-open"
AUTH_FAIL_OPEN_LOG="$TMP_DIR/authority_auto_invite_fail_open.log"
set +e
PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
FAKE_UPSERT_FAIL=1 \
./scripts/easy_node.sh server-up \
  --mode authority \
  --public-host 203.0.113.10 \
  --beta-profile 1 \
  --prod-profile 0 \
  --auto-invite 1 \
  --auto-invite-count 1 \
  --auto-invite-tier 1 \
  --auto-invite-wait-sec 0 \
  --auto-invite-fail-open 1 >"$AUTH_FAIL_OPEN_LOG" 2>&1
auth_fail_open_rc=$?
set -e
if [[ "$auth_fail_open_rc" -ne 0 ]]; then
  echo "expected authority server-up to pass in auto-invite fail-open mode"
  cat "$AUTH_FAIL_OPEN_LOG"
  exit 1
fi

if ! rg -q 'server stack started' "$AUTH_FAIL_OPEN_LOG"; then
  echo "expected authority server-up to complete in auto-invite fail-open mode"
  cat "$AUTH_FAIL_OPEN_LOG"
  exit 1
fi
if ! rg -q 'auto invite: warning: invite generation failed' "$AUTH_FAIL_OPEN_LOG"; then
  echo "expected auto-invite fail-open warning output"
  cat "$AUTH_FAIL_OPEN_LOG"
  exit 1
fi

echo "[server-up-auto-invite] authority auto invite fail-close"
AUTH_FAIL_CLOSE_LOG="$TMP_DIR/authority_auto_invite_fail_close.log"
set +e
PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
FAKE_UPSERT_FAIL=1 \
./scripts/easy_node.sh server-up \
  --mode authority \
  --public-host 203.0.113.10 \
  --beta-profile 1 \
  --prod-profile 0 \
  --auto-invite 1 \
  --auto-invite-count 1 \
  --auto-invite-tier 1 \
  --auto-invite-wait-sec 0 \
  --auto-invite-fail-open 0 >"$AUTH_FAIL_CLOSE_LOG" 2>&1
auth_fail_close_rc=$?
set -e
if [[ "$auth_fail_close_rc" -eq 0 ]]; then
  echo "expected authority server-up to fail in auto-invite fail-close mode"
  cat "$AUTH_FAIL_CLOSE_LOG"
  exit 1
fi
if ! rg -q 'auto invite: invite generation failed \(rc=[0-9]+\); failing because --auto-invite-fail-open=0' "$AUTH_FAIL_CLOSE_LOG"; then
  echo "expected auto-invite fail-close message"
  cat "$AUTH_FAIL_CLOSE_LOG"
  exit 1
fi

echo "[server-up-auto-invite] provider ignores auto invite"
PROVIDER_LOG="$TMP_DIR/provider_auto_invite_ignored.log"
PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
./scripts/easy_node.sh server-up \
  --mode provider \
  --public-host 198.51.100.20 \
  --authority-directory http://203.0.113.10:8081 \
  --authority-issuer http://203.0.113.10:8082 \
  --peer-directories http://203.0.113.10:8081 \
  --beta-profile 1 \
  --prod-profile 0 \
  --auto-invite 1 >"$PROVIDER_LOG" 2>&1

if ! rg -q 'note: --auto-invite is authority-only and is ignored in provider mode\.' "$PROVIDER_LOG"; then
  echo "expected provider-mode auto-invite ignore note"
  cat "$PROVIDER_LOG"
  exit 1
fi
if rg -q 'invite keys generated:' "$PROVIDER_LOG"; then
  echo "provider mode should not generate invite keys"
  cat "$PROVIDER_LOG"
  exit 1
fi

echo "easy-node server-up auto-invite integration check ok"
