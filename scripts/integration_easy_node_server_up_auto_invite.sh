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
EXIT_KEY_FILE="$ROOT_DIR/deploy/data/entry-exit/exit_opperm_wg.key"
HOSTS_FILE="$ROOT_DIR/data/easy_mode_hosts.conf"
TMP_DIR="$(mktemp -d)"
TMP_BIN="$TMP_DIR/bin"
mkdir -p "$TMP_BIN"
WG_PUBKEY_FAIL_STATE="$TMP_DIR/wg_pubkey_fail_state"
REAL_GO="$(command -v go)"

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
  restore_file "$EXIT_KEY_FILE" "exit_key_file"
  restore_file "$HOSTS_FILE" "hosts_file"
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

backup_file "$AUTH_ENV" "auth_env"
backup_file "$PROVIDER_ENV" "provider_env"
backup_file "$MODE_FILE" "mode_file"
backup_file "$IDENTITY_FILE" "identity_file"
backup_file "$EXIT_KEY_FILE" "exit_key_file"
backup_file "$HOSTS_FILE" "hosts_file"

mkdir -p "$(dirname "$EXIT_KEY_FILE")"

cat >"$TMP_BIN/docker" <<'EOF_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "compose" && "${2:-}" == "version" ]]; then
  printf 'Docker Compose version vtest\n'
  exit 0
fi
if [[ "${1:-}" == "compose" ]]; then
  if [[ -n "${FAKE_DOCKER_ENV_CAPTURE:-}" ]]; then
    {
      printf 'CORE_DIRECTORY_URL=%s\n' "${CORE_DIRECTORY_URL-}"
      printf 'CORE_ISSUER_URL=%s\n' "${CORE_ISSUER_URL-}"
      printf 'DIRECTORY_URL=%s\n' "${DIRECTORY_URL-}"
      printf 'DIRECTORY_URLS=%s\n' "${DIRECTORY_URLS-}"
      printf 'ISSUER_URL=%s\n' "${ISSUER_URL-}"
      printf 'ISSUER_URLS=%s\n' "${ISSUER_URLS-}"
    } >>"$FAKE_DOCKER_ENV_CAPTURE"
  fi
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
  if [[ "${FAKE_WG_PUBKEY_FAIL_ONCE:-0}" == "1" && ! -f "${FAKE_WG_PUBKEY_FAIL_STATE_FILE:-}" ]]; then
    : >"${FAKE_WG_PUBKEY_FAIL_STATE_FILE:-$WG_PUBKEY_FAIL_STATE}"
    exit 13
  fi
  cat >/dev/null || true
  echo "test-wg-public-key"
  exit 0
fi
exit 0
EOF_WG

cat >"$TMP_BIN/go" <<EOF_GO
#!/usr/bin/env bash
set -euo pipefail
if [[ "\${1:-}" == "run" && "\${2:-}" == "./cmd/adminsig" ]]; then
  subcmd="\${3:-}"
  shift 3
  case "\$subcmd" in
    gen)
      private_key_out=""
      key_id_out=""
      while [[ \$# -gt 0 ]]; do
        case "\$1" in
          --private-key-out)
            private_key_out="\${2:-}"
            shift 2
            ;;
          --key-id-out)
            key_id_out="\${2:-}"
            shift 2
            ;;
          *)
            shift
            ;;
        esac
      done
      [[ -n "\$private_key_out" ]] && printf 'test-admin-private-key\n' >"\$private_key_out"
      [[ -n "\$key_id_out" ]] && printf 'test-admin-key\n' >"\$key_id_out"
      exit 0
      ;;
    inspect)
      printf '{"key_id":"test-admin-key","public_key":"test-admin-public-key"}\n'
      exit 0
      ;;
  esac
fi
exec "$REAL_GO" "\$@"
EOF_GO

chmod +x "$TMP_BIN/docker" "$TMP_BIN/curl" "$TMP_BIN/wg" "$TMP_BIN/go"

echo "[server-up-auto-invite] authority auto invite success"
AUTH_OK_LOG="$TMP_DIR/authority_auto_invite_ok.log"
AUTH_DOCKER_ENV_CAPTURE="$TMP_DIR/authority_auto_invite_docker_env_capture.log"
PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
FAKE_DOCKER_ENV_CAPTURE="$AUTH_DOCKER_ENV_CAPTURE" \
CORE_DIRECTORY_URL=http://127.0.0.1:18081 \
CORE_ISSUER_URL=http://127.0.0.1:18082 \
DIRECTORY_URL=http://127.0.0.1:28081 \
DIRECTORY_URLS=http://127.0.0.1:38081 \
ISSUER_URL=http://127.0.0.1:28082 \
ISSUER_URLS=http://127.0.0.1:38082 \
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
if ! rg -q '^DIRECTORY_ALLOW_DANGEROUS_INSECURE_ADMIN_PUBLIC_BIND=1$' "$AUTH_ENV"; then
  echo "expected non-prod authority env to explicitly allow lab HTTP directory admin bind"
  cat "$AUTH_ENV"
  exit 1
fi
if ! rg -q '^ISSUER_ADMIN_ALLOW_TOKEN=1$' "$AUTH_ENV" || ! rg -q '^ISSUER_ADMIN_REQUIRE_SIGNED=0$' "$AUTH_ENV"; then
  echo "expected non-prod authority env to use token admin auth instead of signed-only issuer admin"
  cat "$AUTH_ENV"
  exit 1
fi
if ! rg -q '^ISSUER_ALLOW_DANGEROUS_INSECURE_TOKEN_AUTH_PUBLIC_BIND=1$' "$AUTH_ENV"; then
  echo "expected non-prod authority env to explicitly allow lab HTTP issuer token auth bind"
  cat "$AUTH_ENV"
  exit 1
fi
if ! rg -q '^ISSUER_ALLOW_DANGEROUS_PUBLIC_ISSUE_WITHOUT_PAYMENT_PROOF=1$' "$AUTH_ENV"; then
  echo "expected non-prod authority env to explicitly allow lab issuer issuance without payment proof"
  cat "$AUTH_ENV"
  exit 1
fi
if ! rg -q '^CORE_DIRECTORY_URL=http://directory:8081$' "$AUTH_ENV" || ! rg -q '^CORE_ISSUER_URL=http://issuer:8082$' "$AUTH_ENV"; then
  echo "expected authority env to pin Docker-internal core directory/issuer URLs"
  cat "$AUTH_ENV"
  exit 1
fi
if [[ -s "$AUTH_DOCKER_ENV_CAPTURE" ]] && rg -q '127\.0\.0\.1' "$AUTH_DOCKER_ENV_CAPTURE"; then
  echo "compose invocation leaked ambient host endpoint variables into docker compose"
  cat "$AUTH_DOCKER_ENV_CAPTURE"
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

echo "[server-up-auto-invite] non-prod exit key permission self-heal"
printf '%s\n' 'test-private-key' >"$EXIT_KEY_FILE"
chmod 600 "$EXIT_KEY_FILE"
PERM_OK_LOG="$TMP_DIR/authority_exit_key_perm_heal.log"
PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
FAKE_WG_PUBKEY_FAIL_ONCE=1 \
FAKE_WG_PUBKEY_FAIL_STATE_FILE="$WG_PUBKEY_FAIL_STATE" \
./scripts/easy_node.sh server-up \
  --mode authority \
  --public-host 203.0.113.10 \
  --operator-id opperm \
  --beta-profile 1 \
  --prod-profile 0 >"$PERM_OK_LOG" 2>&1

if ! rg -q 'repaired exit wg private-key permissions before deriving EXIT_WG_PUBKEY' "$PERM_OK_LOG"; then
  echo "expected non-prod exit key self-heal note"
  cat "$PERM_OK_LOG"
  exit 1
fi
if ! rg -q 'server stack started' "$PERM_OK_LOG"; then
  echo "expected non-prod server-up to complete after exit key permission repair"
  cat "$PERM_OK_LOG"
  exit 1
fi

echo "[server-up-auto-invite] prod exit key permission failure is fail-closed"
chmod 600 "$EXIT_KEY_FILE"
rm -f "$WG_PUBKEY_FAIL_STATE"
set +e
PATH="$TMP_BIN:$PATH" \
EASY_NODE_VERIFY_PUBLIC=0 \
FAKE_WG_PUBKEY_FAIL_ONCE=1 \
FAKE_WG_PUBKEY_FAIL_STATE_FILE="$WG_PUBKEY_FAIL_STATE" \
./scripts/easy_node.sh server-up \
  --mode authority \
  --public-host 203.0.113.10 \
  --operator-id opperm \
  --peer-directories https://198.51.100.20:8081 \
  --beta-profile 1 \
  --prod-profile 1 >"$TMP_DIR/authority_exit_key_perm_fail.log" 2>&1
perm_fail_rc=$?
set -e
if [[ "$perm_fail_rc" -eq 0 ]]; then
  echo "expected prod server-up to fail closed on unreadable exit key"
  cat "$TMP_DIR/authority_exit_key_perm_fail.log"
  exit 1
fi
if ! rg -q 'server-up refused: could not derive EXIT_WG_PUBKEY from local key in prod profile' "$TMP_DIR/authority_exit_key_perm_fail.log"; then
  echo "expected prod exit key fail-closed message"
  cat "$TMP_DIR/authority_exit_key_perm_fail.log"
  exit 1
fi
if ! rg -q 'fix the file permissions/contents or recreate the key as the current user' "$TMP_DIR/authority_exit_key_perm_fail.log"; then
  echo "expected actionable remediation for unreadable prod exit key"
  cat "$TMP_DIR/authority_exit_key_perm_fail.log"
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
if ! rg -q '^DIRECTORY_ALLOW_DANGEROUS_INSECURE_ADMIN_PUBLIC_BIND=1$' "$PROVIDER_ENV"; then
  echo "expected non-prod provider env to explicitly allow lab HTTP directory admin bind"
  cat "$PROVIDER_ENV"
  exit 1
fi

echo "easy-node server-up auto-invite integration check ok"
