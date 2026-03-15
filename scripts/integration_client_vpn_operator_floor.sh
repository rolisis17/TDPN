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
  */v1/pubkeys)
    printf '{"issuer":"issuer-main","pub_keys":["k1"]}\n'
    ;;
  */v1/health)
    printf '{"ok":true}\n'
    ;;
  */v1/relays)
    if [[ "${FAKE_RELAY_PROFILE:-single}" == "multi" ]]; then
      printf '{"relays":[{"role":"entry","operator_id":"op-a"},{"role":"exit","operator_id":"op-a"},{"role":"entry","operator_id":"op-b"},{"role":"exit","operator_id":"op-b"}]}\n'
    else
      printf '{"relays":[{"role":"entry","operator_id":"op-a"},{"role":"exit","operator_id":"op-a"}]}\n'
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
  --entry-url "http://entry-a:8083"
  --exit-url "http://exit-a:8084"
  --prod-profile 1
  --require-root 0
  --timeout-sec 2
  --issuer-quorum-check 0
  --mtls-ca-file "$MTLS_CA_FILE"
  --mtls-client-cert-file "$MTLS_CERT_FILE"
  --mtls-client-key-file "$MTLS_KEY_FILE"
)

OUT_FAIL="$TMP_DIR/preflight_fail.log"
set +e
PATH="$TMP_BIN:$PATH" FAKE_RELAY_PROFILE="single" ./scripts/easy_node.sh client-vpn-preflight "${COMMON_ARGS[@]}" >"$OUT_FAIL" 2>&1
rc_fail=$?
set -e
if [[ "$rc_fail" -eq 0 ]]; then
  echo "expected prod preflight to fail with single-operator relay set"
  cat "$OUT_FAIL"
  exit 1
fi
if ! rg -q 'operator floor not met|entry operator floor not met|exit operator floor not met' "$OUT_FAIL"; then
  echo "missing expected operator-floor failure signal"
  cat "$OUT_FAIL"
  exit 1
fi
if ! rg -q 'observed operators: all=op-a entry=op-a exit=op-a' "$OUT_FAIL"; then
  echo "missing observed-operators diagnostics in operator-floor failure output"
  cat "$OUT_FAIL"
  exit 1
fi

OUT_OVERRIDE="$TMP_DIR/preflight_override.log"
PATH="$TMP_BIN:$PATH" FAKE_RELAY_PROFILE="single" ./scripts/easy_node.sh client-vpn-preflight "${COMMON_ARGS[@]}" --operator-floor-check 0 >"$OUT_OVERRIDE" 2>&1
if ! rg -q 'client-vpn preflight: OK' "$OUT_OVERRIDE"; then
  echo "expected preflight success when operator-floor-check is disabled"
  cat "$OUT_OVERRIDE"
  exit 1
fi

OUT_MIN1="$TMP_DIR/preflight_min1.log"
PATH="$TMP_BIN:$PATH" FAKE_RELAY_PROFILE="single" ./scripts/easy_node.sh client-vpn-preflight "${COMMON_ARGS[@]}" \
  --operator-floor-check 1 \
  --operator-min-operators 1 \
  --operator-min-entry-operators 1 \
  --operator-min-exit-operators 1 >"$OUT_MIN1" 2>&1
if ! rg -q 'client-vpn preflight: OK' "$OUT_MIN1"; then
  echo "expected preflight success when operator-floor check is enabled with min floors set to 1"
  cat "$OUT_MIN1"
  exit 1
fi

OUT_ENTRY_FAIL="$TMP_DIR/preflight_entry_floor_fail.log"
set +e
PATH="$TMP_BIN:$PATH" FAKE_RELAY_PROFILE="single" ./scripts/easy_node.sh client-vpn-preflight "${COMMON_ARGS[@]}" \
  --operator-floor-check 1 \
  --operator-min-operators 1 \
  --operator-min-entry-operators 2 \
  --operator-min-exit-operators 1 >"$OUT_ENTRY_FAIL" 2>&1
rc_entry_fail=$?
set -e
if [[ "$rc_entry_fail" -eq 0 ]]; then
  echo "expected preflight failure when entry floor threshold exceeds observed entry operator count"
  cat "$OUT_ENTRY_FAIL"
  exit 1
fi
if ! rg -q 'entry operator floor not met \(need >=2, observed=1\)' "$OUT_ENTRY_FAIL"; then
  echo "missing expected entry-floor failure signal for custom threshold"
  cat "$OUT_ENTRY_FAIL"
  exit 1
fi

OUT_OK="$TMP_DIR/preflight_ok.log"
PATH="$TMP_BIN:$PATH" FAKE_RELAY_PROFILE="multi" ./scripts/easy_node.sh client-vpn-preflight "${COMMON_ARGS[@]}" --operator-floor-check 1 >"$OUT_OK" 2>&1
if ! rg -q 'client-vpn preflight: OK' "$OUT_OK"; then
  echo "expected preflight success with multi-operator relay set"
  cat "$OUT_OK"
  exit 1
fi

echo "client-vpn operator-floor integration check ok"
