#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash rg mktemp chmod; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
TMP_BIN="$TMP_DIR/bin"
mkdir -p "$TMP_BIN"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.log"
FAKE_EASY="$TMP_DIR/fake_easy_node.sh"

cat >"$TMP_BIN/docker" <<'EOF_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "compose" && "${2:-}" == "version" ]]; then
  echo "Docker Compose version v2.fake"
  exit 0
fi
echo "unexpected docker call: $*" >&2
exit 1
EOF_DOCKER

cat >"$TMP_BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
url="${@: -1}"
case "$url" in
  http://127.0.0.1:18081/v1/relays)
    printf '%s\n' '{"relays":[{"role":"entry","operator_id":"op-a"},{"role":"exit","operator_id":"op-b"}]}'
    ;;
  http://127.0.0.1:28081/v1/relays)
    printf '%s\n' '{"relays":[{"role":"entry","operator_id":"op-a"},{"role":"exit","operator_id":"op-b"}]}'
    ;;
  http://100.113.245.61:8081/v1/relays)
    printf '%s\n' '{"relays":[{"role":"entry","operator_id":"op-a"},{"role":"exit","operator_id":"op-b"}]}'
    ;;
  http://100.64.244.24:8081/v1/relays)
    printf '%s\n' '{"relays":[{"role":"entry","operator_id":"op-a"},{"role":"exit","operator_id":"op-b"}]}'
    ;;
  http://127.0.0.1:18082/v1/pubkeys)
    printf '%s\n' '{"issuer":"issuer-a","pub_keys":["key-a"]}'
    ;;
  http://100.113.245.61:8082/v1/pubkeys)
    printf '%s\n' '{"issuer":"issuer-a","pub_keys":["key-a"]}'
    ;;
  http://127.0.0.1:18083/v1/health|http://127.0.0.1:18084/v1/health)
    printf '%s\n' '{"status":"ok"}'
    ;;
  http://100.113.245.61:8083/v1/health|http://100.113.245.61:8084/v1/health)
    printf '%s\n' '{"status":"ok"}'
    ;;
  *)
    # Health probes include flags before URL; treat unknown endpoints as reachable.
    printf '%s\n' '{}'
    ;;
esac
EOF_CURL

cat >"$FAKE_EASY" <<'EOF_EASY'
#!/usr/bin/env bash
set -euo pipefail
printf 'env_dir=%s\n' "${EASY_NODE_CLIENT_TEST_CONTAINER_DIRECTORY_URLS:-}" >>"${FAKE_CAPTURE_FILE:?}"
printf 'env_issuer=%s\n' "${EASY_NODE_CLIENT_TEST_CONTAINER_ISSUER_URL:-}" >>"${FAKE_CAPTURE_FILE:?}"
printf 'env_entry=%s\n' "${EASY_NODE_CLIENT_TEST_CONTAINER_ENTRY_URL:-}" >>"${FAKE_CAPTURE_FILE:?}"
printf 'env_exit=%s\n' "${EASY_NODE_CLIENT_TEST_CONTAINER_EXIT_URL:-}" >>"${FAKE_CAPTURE_FILE:?}"
printf 'args=%s\n' "$*" >>"${FAKE_CAPTURE_FILE:?}"
allow_insecure_http=0
while [[ $# -gt 0 ]]; do
  case "${1:-}" in
    --allow-insecure-remote-http)
      if [[ "${2:-}" == "1" ]]; then
        allow_insecure_http=1
      fi
      shift 2
      ;;
    --allow-insecure-remote-http=1)
      allow_insecure_http=1
      shift
      ;;
    *)
      shift
      ;;
  esac
done
if [[ "${FAKE_EASY_REJECT_REMOTE_HTTP_WITHOUT_FLAG:-0}" == "1" && "$allow_insecure_http" != "1" ]]; then
  urls="${EASY_NODE_CLIENT_TEST_CONTAINER_DIRECTORY_URLS:-} ${EASY_NODE_CLIENT_TEST_CONTAINER_ISSUER_URL:-} ${EASY_NODE_CLIENT_TEST_CONTAINER_ENTRY_URL:-} ${EASY_NODE_CLIENT_TEST_CONTAINER_EXIT_URL:-}"
  if [[ "$urls" == *"http://100."* ]]; then
    echo "fake client-test refused non-loopback HTTP without allow flag" >&2
    exit 22
  fi
fi
if [[ "${FAKE_EASY_EXIT_AFTER_OK:-0}" == "1" ]]; then
  echo "client test: ok"
  echo "client test log: /tmp/fake_easy_node_client_test.log"
  exit 2
fi
exit 0
EOF_EASY

chmod +x "$TMP_BIN/docker" "$TMP_BIN/curl" "$FAKE_EASY"

echo "[3machine-beta-validate-loopback] rewrite enabled"
FAKE_CAPTURE_FILE="$CAPTURE" \
PATH="$TMP_BIN:$PATH" \
EASY_NODE_SH="$FAKE_EASY" \
./scripts/integration_3machine_beta_validate.sh \
  --directory-a http://127.0.0.1:18081 \
  --directory-b http://127.0.0.1:28081 \
  --issuer-url http://127.0.0.1:18082 \
  --entry-url http://127.0.0.1:18083 \
  --exit-url http://127.0.0.1:18084 \
  --min-sources 1 \
  --min-operators 1 \
  --federation-timeout-sec 5 \
  --timeout-sec 5 \
  --distinct-operators 0 \
  --require-issuer-quorum 0 \
  --beta-profile 0 \
  --prod-profile 0 >/tmp/integration_3machine_beta_validate_loopback_enabled.log 2>&1

if ! rg -q '^env_dir=http://host\.docker\.internal:18081,http://host\.docker\.internal:28081$' "$CAPTURE"; then
  echo "loopback rewrite did not update container directory URLs"
  cat "$CAPTURE"
  cat /tmp/integration_3machine_beta_validate_loopback_enabled.log
  exit 1
fi
if ! rg -q '^env_issuer=http://host\.docker\.internal:18082$' "$CAPTURE"; then
  echo "loopback rewrite did not update container issuer URL"
  cat "$CAPTURE"
  cat /tmp/integration_3machine_beta_validate_loopback_enabled.log
  exit 1
fi
if ! rg -q '^env_entry=http://host\.docker\.internal:18083$' "$CAPTURE"; then
  echo "loopback rewrite did not update container entry URL"
  cat "$CAPTURE"
  cat /tmp/integration_3machine_beta_validate_loopback_enabled.log
  exit 1
fi
if ! rg -q '^env_exit=http://host\.docker\.internal:18084$' "$CAPTURE"; then
  echo "loopback rewrite did not update container exit URL"
  cat "$CAPTURE"
  cat /tmp/integration_3machine_beta_validate_loopback_enabled.log
  exit 1
fi
if ! rg -q 'args=.*--allow-insecure-remote-http 1' "$CAPTURE"; then
  echo "loopback rewrite should opt client-test into explicit lab HTTP"
  cat "$CAPTURE"
  cat /tmp/integration_3machine_beta_validate_loopback_enabled.log
  exit 1
fi

echo "[3machine-beta-validate-loopback] rewrite disabled"
: >"$CAPTURE"
FAKE_CAPTURE_FILE="$CAPTURE" \
PATH="$TMP_BIN:$PATH" \
EASY_NODE_SH="$FAKE_EASY" \
THREE_MACHINE_VALIDATE_REWRITE_LOOPBACK_FOR_DOCKER=0 \
./scripts/integration_3machine_beta_validate.sh \
  --directory-a http://127.0.0.1:18081 \
  --directory-b http://127.0.0.1:28081 \
  --issuer-url http://127.0.0.1:18082 \
  --entry-url http://127.0.0.1:18083 \
  --exit-url http://127.0.0.1:18084 \
  --min-sources 1 \
  --min-operators 1 \
  --federation-timeout-sec 5 \
  --timeout-sec 5 \
  --distinct-operators 0 \
  --require-issuer-quorum 0 \
  --beta-profile 0 \
  --prod-profile 0 >/tmp/integration_3machine_beta_validate_loopback_disabled.log 2>&1

if ! rg -q '^env_dir=http://127\.0\.0\.1:18081,http://127\.0\.0\.1:28081$' "$CAPTURE"; then
  echo "rewrite disabled path should preserve loopback container URLs"
  cat "$CAPTURE"
  cat /tmp/integration_3machine_beta_validate_loopback_disabled.log
  exit 1
fi
if ! rg -q '^env_issuer=http://127\.0\.0\.1:18082$' "$CAPTURE"; then
  echo "rewrite disabled path should preserve loopback issuer URL"
  cat "$CAPTURE"
  cat /tmp/integration_3machine_beta_validate_loopback_disabled.log
  exit 1
fi

echo "[3machine-beta-validate-loopback] explicit lab HTTP opt-in"
: >"$CAPTURE"
FAKE_CAPTURE_FILE="$CAPTURE" \
PATH="$TMP_BIN:$PATH" \
EASY_NODE_SH="$FAKE_EASY" \
THREE_MACHINE_VALIDATE_REWRITE_LOOPBACK_FOR_DOCKER=0 \
THREE_MACHINE_ALLOW_INSECURE_REMOTE_HTTP=1 \
./scripts/integration_3machine_beta_validate.sh \
  --directory-a http://100.113.245.61:8081 \
  --directory-b http://100.64.244.24:8081 \
  --issuer-url http://100.113.245.61:8082 \
  --entry-url http://100.113.245.61:8083 \
  --exit-url http://100.113.245.61:8084 \
  --min-sources 1 \
  --min-operators 1 \
  --federation-timeout-sec 5 \
  --timeout-sec 5 \
  --distinct-operators 0 \
  --require-issuer-quorum 0 \
  --beta-profile 1 \
  --prod-profile 0 >/tmp/integration_3machine_beta_validate_explicit_lab_http.log 2>&1

if ! rg -q 'args=.*--allow-insecure-remote-http 1' "$CAPTURE"; then
  echo "explicit lab HTTP opt-in should opt client-test into insecure remote HTTP"
  cat "$CAPTURE"
  cat /tmp/integration_3machine_beta_validate_explicit_lab_http.log
  exit 1
fi
if ! rg -q '^env_dir=http://100\.113\.245\.61:8081,http://100\.64\.244\.24:8081$' "$CAPTURE"; then
  echo "explicit lab HTTP opt-in should not rewrite non-loopback directory URLs"
  cat "$CAPTURE"
  cat /tmp/integration_3machine_beta_validate_explicit_lab_http.log
  exit 1
fi

echo "[3machine-beta-validate-loopback] non-loopback HTTP remains fail-closed by default"
: >"$CAPTURE"
set +e
FAKE_CAPTURE_FILE="$CAPTURE" \
PATH="$TMP_BIN:$PATH" \
EASY_NODE_SH="$FAKE_EASY" \
FAKE_EASY_REJECT_REMOTE_HTTP_WITHOUT_FLAG=1 \
THREE_MACHINE_VALIDATE_REWRITE_LOOPBACK_FOR_DOCKER=0 \
./scripts/integration_3machine_beta_validate.sh \
  --directory-a http://100.113.245.61:8081 \
  --directory-b http://100.64.244.24:8081 \
  --issuer-url http://100.113.245.61:8082 \
  --entry-url http://100.113.245.61:8083 \
  --exit-url http://100.113.245.61:8084 \
  --min-sources 1 \
  --min-operators 1 \
  --federation-timeout-sec 5 \
  --timeout-sec 5 \
  --distinct-operators 0 \
  --require-issuer-quorum 0 \
  --beta-profile 1 \
  --prod-profile 0 >/tmp/integration_3machine_beta_validate_default_lab_http.log 2>&1
default_lab_http_rc=$?
set -e

if ((default_lab_http_rc == 0)); then
  echo "non-loopback HTTP without explicit lab opt-in should fail closed in client-test"
  cat "$CAPTURE"
  cat /tmp/integration_3machine_beta_validate_default_lab_http.log
  exit 1
fi

if rg -q 'args=.*--allow-insecure-remote-http 1' "$CAPTURE"; then
  echo "non-loopback HTTP without explicit lab opt-in should not pass insecure remote HTTP flag"
  cat "$CAPTURE"
  cat /tmp/integration_3machine_beta_validate_default_lab_http.log
  exit 1
fi

echo "[3machine-beta-validate-loopback] explicit lab HTTP CLI opt-in"
: >"$CAPTURE"
FAKE_CAPTURE_FILE="$CAPTURE" \
PATH="$TMP_BIN:$PATH" \
EASY_NODE_SH="$FAKE_EASY" \
THREE_MACHINE_VALIDATE_REWRITE_LOOPBACK_FOR_DOCKER=0 \
./scripts/integration_3machine_beta_validate.sh \
  --directory-a http://100.113.245.61:8081 \
  --directory-b http://100.64.244.24:8081 \
  --issuer-url http://100.113.245.61:8082 \
  --entry-url http://100.113.245.61:8083 \
  --exit-url http://100.113.245.61:8084 \
  --min-sources 1 \
  --min-operators 1 \
  --federation-timeout-sec 5 \
  --timeout-sec 5 \
  --distinct-operators 0 \
  --require-issuer-quorum 0 \
  --allow-insecure-remote-http 1 \
  --beta-profile 1 \
  --prod-profile 0 >/tmp/integration_3machine_beta_validate_cli_lab_http.log 2>&1

if ! rg -q 'args=.*--allow-insecure-remote-http 1' "$CAPTURE"; then
  echo "explicit lab HTTP CLI opt-in should opt client-test into insecure remote HTTP"
  cat "$CAPTURE"
  cat /tmp/integration_3machine_beta_validate_cli_lab_http.log
  exit 1
fi

echo "[3machine-beta-validate-loopback] mixed Docker rewrite and remote HTTP requires explicit opt-in"
: >"$CAPTURE"
set +e
FAKE_CAPTURE_FILE="$CAPTURE" \
PATH="$TMP_BIN:$PATH" \
EASY_NODE_SH="$FAKE_EASY" \
./scripts/integration_3machine_beta_validate.sh \
  --directory-a http://127.0.0.1:18081 \
  --directory-b http://100.64.244.24:8081 \
  --issuer-url http://127.0.0.1:18082 \
  --entry-url http://127.0.0.1:18083 \
  --exit-url http://127.0.0.1:18084 \
  --min-sources 1 \
  --min-operators 1 \
  --federation-timeout-sec 5 \
  --timeout-sec 5 \
  --distinct-operators 0 \
  --require-issuer-quorum 0 \
  --beta-profile 1 \
  --prod-profile 0 >/tmp/integration_3machine_beta_validate_mixed_rewrite_remote_http_refused.log 2>&1
mixed_rc=$?
set -e
if ((mixed_rc == 0)); then
  echo "mixed Docker rewrite and remote HTTP should require explicit lab HTTP opt-in"
  cat "$CAPTURE"
  cat /tmp/integration_3machine_beta_validate_mixed_rewrite_remote_http_refused.log
  exit 1
fi
if ! rg -q 'THREE_MACHINE_ALLOW_INSECURE_REMOTE_HTTP=1 is required when Docker loopback rewrite is combined with non-loopback HTTP endpoints' /tmp/integration_3machine_beta_validate_mixed_rewrite_remote_http_refused.log; then
  echo "mixed rewrite refusal should explain explicit lab HTTP opt-in"
  cat /tmp/integration_3machine_beta_validate_mixed_rewrite_remote_http_refused.log
  exit 1
fi
if [[ -s "$CAPTURE" ]]; then
  echo "mixed rewrite refusal should happen before client-test"
  cat "$CAPTURE"
  exit 1
fi

echo "[3machine-beta-validate-loopback] prod rejects Docker loopback rewrite"
: >"$CAPTURE"
set +e
FAKE_CAPTURE_FILE="$CAPTURE" \
PATH="$TMP_BIN:$PATH" \
EASY_NODE_SH="$FAKE_EASY" \
./scripts/integration_3machine_beta_validate.sh \
  --directory-a http://127.0.0.1:18081 \
  --directory-b http://127.0.0.1:28081 \
  --issuer-url http://127.0.0.1:18082 \
  --entry-url http://127.0.0.1:18083 \
  --exit-url http://127.0.0.1:18084 \
  --min-sources 1 \
  --min-operators 1 \
  --federation-timeout-sec 5 \
  --timeout-sec 5 \
  --distinct-operators 0 \
  --require-issuer-quorum 0 \
  --beta-profile 1 \
  --prod-profile 1 >/tmp/integration_3machine_beta_validate_prod_rewrite_refused.log 2>&1
prod_rewrite_rc=$?
set -e
if ((prod_rewrite_rc == 0)); then
  echo "prod profile should reject Docker loopback rewrite"
  cat "$CAPTURE"
  cat /tmp/integration_3machine_beta_validate_prod_rewrite_refused.log
  exit 1
fi
if ! rg -q 'loopback Docker endpoint rewrite is not allowed with --prod-profile 1' /tmp/integration_3machine_beta_validate_prod_rewrite_refused.log; then
  echo "prod rewrite rejection should explain the Docker rewrite conflict"
  cat /tmp/integration_3machine_beta_validate_prod_rewrite_refused.log
  exit 1
fi
if [[ -s "$CAPTURE" ]]; then
  echo "prod rewrite rejection should happen before client-test"
  cat "$CAPTURE"
  exit 1
fi

echo "[3machine-beta-validate-loopback] prod rejects explicit lab HTTP opt-in"
: >"$CAPTURE"
set +e
FAKE_CAPTURE_FILE="$CAPTURE" \
PATH="$TMP_BIN:$PATH" \
EASY_NODE_SH="$FAKE_EASY" \
THREE_MACHINE_ALLOW_INSECURE_REMOTE_HTTP=1 \
./scripts/integration_3machine_beta_validate.sh \
  --directory-a http://127.0.0.1:18081 \
  --directory-b http://127.0.0.1:28081 \
  --issuer-url http://127.0.0.1:18082 \
  --entry-url http://127.0.0.1:18083 \
  --exit-url http://127.0.0.1:18084 \
  --min-sources 1 \
  --min-operators 1 \
  --federation-timeout-sec 5 \
  --timeout-sec 5 \
  --distinct-operators 0 \
  --require-issuer-quorum 0 \
  --beta-profile 1 \
  --prod-profile 1 >/tmp/integration_3machine_beta_validate_prod_lab_http_refused.log 2>&1
prod_rc=$?
set -e
if ((prod_rc == 0)); then
  echo "prod profile should reject explicit lab HTTP opt-in"
  cat "$CAPTURE"
  cat /tmp/integration_3machine_beta_validate_prod_lab_http_refused.log
  exit 1
fi
if ! rg -q 'THREE_MACHINE_ALLOW_INSECURE_REMOTE_HTTP=1 is not allowed with --prod-profile 1' /tmp/integration_3machine_beta_validate_prod_lab_http_refused.log; then
  echo "prod rejection should explain the lab HTTP opt-in conflict"
  cat /tmp/integration_3machine_beta_validate_prod_lab_http_refused.log
  exit 1
fi
if [[ -s "$CAPTURE" ]]; then
  echo "prod rejection should happen before client-test"
  cat "$CAPTURE"
  exit 1
fi

echo "[3machine-beta-validate-loopback] client rc after ok is diagnosed"
: >"$CAPTURE"
set +e
FAKE_CAPTURE_FILE="$CAPTURE" \
PATH="$TMP_BIN:$PATH" \
EASY_NODE_SH="$FAKE_EASY" \
FAKE_EASY_EXIT_AFTER_OK=1 \
./scripts/integration_3machine_beta_validate.sh \
  --directory-a http://127.0.0.1:18081 \
  --directory-b http://127.0.0.1:28081 \
  --issuer-url http://127.0.0.1:18082 \
  --entry-url http://127.0.0.1:18083 \
  --exit-url http://127.0.0.1:18084 \
  --min-sources 1 \
  --min-operators 1 \
  --federation-timeout-sec 5 \
  --timeout-sec 5 \
  --distinct-operators 0 \
  --require-issuer-quorum 0 \
  --beta-profile 0 \
  --prod-profile 0 >/tmp/integration_3machine_beta_validate_client_rc_after_ok.log 2>&1
client_rc_after_ok=$?
set -e
if ((client_rc_after_ok != 2)); then
  echo "client rc-after-ok scenario should preserve the client rc"
  cat "$CAPTURE"
  cat /tmp/integration_3machine_beta_validate_client_rc_after_ok.log
  exit 1
fi
if ! rg -q 'client validation command failed rc=2' /tmp/integration_3machine_beta_validate_client_rc_after_ok.log; then
  echo "client rc-after-ok scenario should emit the explicit rc diagnostic"
  cat /tmp/integration_3machine_beta_validate_client_rc_after_ok.log
  exit 1
fi

echo "3-machine beta validate loopback rewrite integration check ok"
