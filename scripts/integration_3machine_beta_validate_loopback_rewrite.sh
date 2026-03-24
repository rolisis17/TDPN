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
    printf '%s\n' '{"relays":[{"role":"entry","operator_id":"op-a"}]}'
    ;;
  http://127.0.0.1:28081/v1/relays)
    printf '%s\n' '{"relays":[{"role":"entry","operator_id":"op-b"}]}'
    ;;
  http://127.0.0.1:18082/v1/pubkeys)
    printf '%s\n' '{"issuer":"issuer-a","pub_keys":["key-a"]}'
    ;;
  http://127.0.0.1:18083/v1/health|http://127.0.0.1:18084/v1/health)
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

echo "3-machine beta validate loopback rewrite integration check ok"
