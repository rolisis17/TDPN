#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash rg jq; do
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

cat >"$TMP_BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
url=""
for arg in "$@"; do
  case "$arg" in
    http://*|https://*)
      url="$arg"
      ;;
  esac
done

case "$url" in
  */v1/health)
    printf '{"ok":true}\n'
    ;;
  */v1/relays)
    # Keep operator-floor healthy to isolate issuer-quorum behavior.
    printf '{"relays":[{"role":"entry","operator_id":"op-a"},{"role":"exit","operator_id":"op-a"},{"role":"entry","operator_id":"op-b"},{"role":"exit","operator_id":"op-b"}]}\n'
    ;;
  */v1/pubkeys)
    if [[ "${FAKE_ISSUER_PROFILE:-same}" == "multi" ]]; then
      case "$url" in
        *issuer-a*|*dir-a*)
          printf '{"issuer":"issuer-a","pub_keys":["k1"]}\n'
          ;;
        *issuer-b*|*dir-b*)
          printf '{"issuer":"issuer-b","pub_keys":["k2"]}\n'
          ;;
        *)
          printf '{"issuer":"issuer-a","pub_keys":["k1"]}\n'
          ;;
      esac
    else
      printf '{"issuer":"issuer-main","pub_keys":["k1"]}\n'
    fi
    ;;
  *)
    printf '{}\n'
    ;;
esac
EOF_CURL

cat >"$TMP_BIN/go" <<'EOF_GO'
#!/usr/bin/env bash
set -euo pipefail
exit 0
EOF_GO

cat >"$TMP_BIN/wg" <<'EOF_WG'
#!/usr/bin/env bash
set -euo pipefail
exit 0
EOF_WG

cat >"$TMP_BIN/ip" <<'EOF_IP'
#!/usr/bin/env bash
set -euo pipefail
exit 0
EOF_IP

cat >"$TMP_BIN/timeout" <<'EOF_TIMEOUT'
#!/usr/bin/env bash
set -euo pipefail
if [[ $# -gt 0 && "$1" =~ ^[0-9]+$ ]]; then
  shift
fi
"$@"
EOF_TIMEOUT

chmod +x "$TMP_BIN/curl" "$TMP_BIN/go" "$TMP_BIN/wg" "$TMP_BIN/ip" "$TMP_BIN/timeout"

MTLS_CA_FILE="$TMP_DIR/ca.crt"
MTLS_CERT_FILE="$TMP_DIR/client.crt"
MTLS_KEY_FILE="$TMP_DIR/client.key"
printf 'test-ca\n' >"$MTLS_CA_FILE"
printf 'test-cert\n' >"$MTLS_CERT_FILE"
printf 'test-key\n' >"$MTLS_KEY_FILE"

COMMON_ARGS=(
  --directory-urls "http://dir-a:8081,http://dir-b:8081"
  --issuer-url "http://issuer-a:8082"
  --issuer-urls "http://issuer-a:8082,http://issuer-b:8082"
  --entry-url "http://entry-a:8083"
  --exit-url "http://exit-a:8084"
  --prod-profile 1
  --require-root 0
  --timeout-sec 2
  --operator-floor-check 0
  --mtls-ca-file "$MTLS_CA_FILE"
  --mtls-client-cert-file "$MTLS_CERT_FILE"
  --mtls-client-key-file "$MTLS_KEY_FILE"
)

OUT_FAIL="$TMP_DIR/preflight_fail.log"
set +e
PATH="$TMP_BIN:$PATH" FAKE_ISSUER_PROFILE="same" ./scripts/easy_node.sh client-vpn-preflight "${COMMON_ARGS[@]}" >"$OUT_FAIL" 2>&1
rc_fail=$?
set -e
if [[ "$rc_fail" -eq 0 ]]; then
  echo "expected prod preflight to fail with single issuer identity"
  cat "$OUT_FAIL"
  exit 1
fi
if ! rg -q 'issuer operator floor not met' "$OUT_FAIL"; then
  echo "missing expected issuer-quorum floor failure signal"
  cat "$OUT_FAIL"
  exit 1
fi

OUT_OVERRIDE="$TMP_DIR/preflight_override.log"
PATH="$TMP_BIN:$PATH" FAKE_ISSUER_PROFILE="same" ./scripts/easy_node.sh client-vpn-preflight "${COMMON_ARGS[@]}" --issuer-quorum-check 0 >"$OUT_OVERRIDE" 2>&1
if ! rg -q 'client-vpn preflight: OK' "$OUT_OVERRIDE"; then
  echo "expected preflight success when issuer-quorum-check is disabled"
  cat "$OUT_OVERRIDE"
  exit 1
fi

OUT_OK="$TMP_DIR/preflight_ok.log"
PATH="$TMP_BIN:$PATH" FAKE_ISSUER_PROFILE="multi" ./scripts/easy_node.sh client-vpn-preflight "${COMMON_ARGS[@]}" --issuer-quorum-check 1 --issuer-min-operators 2 >"$OUT_OK" 2>&1
if ! rg -q 'client-vpn preflight: OK' "$OUT_OK"; then
  echo "expected preflight success with multi-issuer identity feeds"
  cat "$OUT_OK"
  exit 1
fi

echo "client-vpn issuer-quorum integration check ok"
