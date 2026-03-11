#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp jq rg; do
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
EASY_CAPTURE="$TMP_DIR/easy_capture.log"
FAKE_CURL="$TMP_BIN/curl"
FAKE_RELAYS_FILE="$TMP_DIR/relays.json"

cat >"$FAKE_EASY_NODE" <<'EOF_FAKE_EASY_NODE'
#!/usr/bin/env bash
set -euo pipefail
cmd="${1:-}"
printf '%s\n' "$*" >>"${EASY_CAPTURE_FILE:?}"
case "$cmd" in
  server-preflight)
    exit "${FAKE_PREFLIGHT_RC:-0}"
    ;;
  server-up)
    exit "${FAKE_SERVER_UP_RC:-0}"
    ;;
  server-down)
    exit "${FAKE_SERVER_DOWN_RC:-0}"
    ;;
  *)
    exit 0
    ;;
esac
EOF_FAKE_EASY_NODE
chmod +x "$FAKE_EASY_NODE"

cat >"$FAKE_CURL" <<'EOF_FAKE_CURL'
#!/usr/bin/env bash
set -euo pipefail
url="${@: -1}"
case "$url" in
  */v1/relays)
    cat "${FAKE_RELAYS_FILE:?}"
    ;;
  */v1/pubkeys)
    printf '{"issuer":"issuer-test","pub_keys":["k1"],"key_epoch":1,"min_token_epoch":1}\n'
    ;;
  */v1/health)
    printf '{"ok":true}\n'
    ;;
  *)
    exit 7
    ;;
esac
EOF_FAKE_CURL
chmod +x "$FAKE_CURL"

echo "[prod-operator-lifecycle] onboard success path"
cat >"$FAKE_RELAYS_FILE" <<'EOF_RELAYS_OK'
{"relays":[{"relay_id":"entry-op-test","role":"entry","operator_id":"op-test"},{"relay_id":"exit-op-test","role":"exit","operator_id":"op-test"}]}
EOF_RELAYS_OK

ONBOARD_SUMMARY="$TMP_DIR/onboard_summary.json"
: >"$EASY_CAPTURE"
EASY_CAPTURE_FILE="$EASY_CAPTURE" \
FAKE_RELAYS_FILE="$FAKE_RELAYS_FILE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
PROD_OPERATOR_LIFECYCLE_CURL_BIN="$FAKE_CURL" \
./scripts/prod_operator_lifecycle_runbook.sh \
  --action onboard \
  --mode provider \
  --public-host 127.0.0.1 \
  --operator-id op-test \
  --authority-directory http://127.0.0.1:8081 \
  --authority-issuer http://127.0.0.1:8082 \
  --peer-identity-strict 1 \
  --preflight-check 1 \
  --preflight-timeout-sec 8 \
  --health-check 1 \
  --health-timeout-sec 2 \
  --verify-relays 1 \
  --verify-relay-min-count 2 \
  --verify-relay-timeout-sec 2 \
  --directory-url http://127.0.0.1:8081 \
  --summary-json "$ONBOARD_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_prod_operator_lifecycle_runbook_onboard_ok.log 2>&1

if [[ ! -f "$ONBOARD_SUMMARY" ]]; then
  echo "onboard runbook did not produce summary json"
  cat /tmp/integration_prod_operator_lifecycle_runbook_onboard_ok.log
  exit 1
fi
if [[ "$(jq -r '.status' "$ONBOARD_SUMMARY")" != "ok" ]]; then
  echo "onboard runbook summary has unexpected status"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.action' "$ONBOARD_SUMMARY")" != "onboard" ]]; then
  echo "onboard runbook summary has unexpected action"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.relay_policy.observed_count' "$ONBOARD_SUMMARY")" != "2" ]]; then
  echo "onboard runbook did not report expected relay count"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if ! jq -e '.completed_steps | index("server_preflight") != null' "$ONBOARD_SUMMARY" >/dev/null; then
  echo "onboard runbook missing server_preflight completion step"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if ! jq -e '.completed_steps | index("server_up") != null' "$ONBOARD_SUMMARY" >/dev/null; then
  echo "onboard runbook missing server_up completion step"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if ! jq -e '.completed_steps | index("health_check") != null' "$ONBOARD_SUMMARY" >/dev/null; then
  echo "onboard runbook missing health_check completion step"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if ! jq -e '.completed_steps | index("relay_verify") != null' "$ONBOARD_SUMMARY" >/dev/null; then
  echo "onboard runbook missing relay_verify completion step"
  cat "$ONBOARD_SUMMARY"
  exit 1
fi
if ! rg -q -- '^server-preflight --mode provider' "$EASY_CAPTURE"; then
  echo "onboard runbook missing server-preflight invocation"
  cat "$EASY_CAPTURE"
  exit 1
fi
if ! rg -q -- '^server-up --mode provider' "$EASY_CAPTURE"; then
  echo "onboard runbook missing server-up invocation"
  cat "$EASY_CAPTURE"
  exit 1
fi

echo "[prod-operator-lifecycle] onboard fail path"
ONBOARD_FAIL_SUMMARY="$TMP_DIR/onboard_fail_summary.json"
: >"$EASY_CAPTURE"
set +e
EASY_CAPTURE_FILE="$EASY_CAPTURE" \
FAKE_RELAYS_FILE="$FAKE_RELAYS_FILE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
FAKE_SERVER_UP_RC=27 \
PROD_OPERATOR_LIFECYCLE_CURL_BIN="$FAKE_CURL" \
./scripts/prod_operator_lifecycle_runbook.sh \
  --action onboard \
  --mode provider \
  --operator-id op-test \
  --preflight-check 0 \
  --health-check 0 \
  --verify-relays 0 \
  --summary-json "$ONBOARD_FAIL_SUMMARY" >/tmp/integration_prod_operator_lifecycle_runbook_onboard_fail.log 2>&1
onboard_fail_rc=$?
set -e
if [[ "$onboard_fail_rc" -ne 27 ]]; then
  echo "onboard fail path returned unexpected rc=$onboard_fail_rc (expected 27)"
  cat /tmp/integration_prod_operator_lifecycle_runbook_onboard_fail.log
  exit 1
fi
if [[ "$(jq -r '.status' "$ONBOARD_FAIL_SUMMARY")" != "fail" ]]; then
  echo "onboard fail path summary has unexpected status"
  cat "$ONBOARD_FAIL_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.failure_step' "$ONBOARD_FAIL_SUMMARY")" != "server_up" ]]; then
  echo "onboard fail path summary has unexpected failure_step"
  cat "$ONBOARD_FAIL_SUMMARY"
  exit 1
fi

echo "[prod-operator-lifecycle] offboard success path"
cat >"$FAKE_RELAYS_FILE" <<'EOF_RELAYS_ABSENT'
{"relays":[{"relay_id":"entry-other","role":"entry","operator_id":"op-other"},{"relay_id":"exit-other","role":"exit","operator_id":"op-other"}]}
EOF_RELAYS_ABSENT
OFFBOARD_SUMMARY="$TMP_DIR/offboard_summary.json"
: >"$EASY_CAPTURE"
EASY_CAPTURE_FILE="$EASY_CAPTURE" \
FAKE_RELAYS_FILE="$FAKE_RELAYS_FILE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
PROD_OPERATOR_LIFECYCLE_CURL_BIN="$FAKE_CURL" \
./scripts/prod_operator_lifecycle_runbook.sh \
  --action offboard \
  --operator-id op-test \
  --verify-absent 1 \
  --verify-relay-timeout-sec 2 \
  --directory-url http://127.0.0.1:8081 \
  --summary-json "$OFFBOARD_SUMMARY" >/tmp/integration_prod_operator_lifecycle_runbook_offboard_ok.log 2>&1

if [[ "$(jq -r '.status' "$OFFBOARD_SUMMARY")" != "ok" ]]; then
  echo "offboard runbook summary has unexpected status"
  cat "$OFFBOARD_SUMMARY"
  exit 1
fi
if [[ "$(jq -r '.action' "$OFFBOARD_SUMMARY")" != "offboard" ]]; then
  echo "offboard runbook summary has unexpected action"
  cat "$OFFBOARD_SUMMARY"
  exit 1
fi
if ! jq -e '.completed_steps | index("server_down") != null' "$OFFBOARD_SUMMARY" >/dev/null; then
  echo "offboard runbook missing server_down completion step"
  cat "$OFFBOARD_SUMMARY"
  exit 1
fi
if ! jq -e '.completed_steps | index("relay_absent_verify") != null' "$OFFBOARD_SUMMARY" >/dev/null; then
  echo "offboard runbook missing relay_absent_verify completion step"
  cat "$OFFBOARD_SUMMARY"
  exit 1
fi
if ! rg -q -- '^server-down$' "$EASY_CAPTURE"; then
  echo "offboard runbook missing server-down invocation"
  cat "$EASY_CAPTURE"
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

FAKE_RUNBOOK="$TMP_DIR/fake_prod_operator_lifecycle_runbook.sh"
DISPATCH_CAPTURE="$TMP_DIR/dispatch_capture.log"
cat >"$FAKE_RUNBOOK" <<'EOF_FAKE_RUNBOOK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${DISPATCH_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_RUNBOOK
chmod +x "$FAKE_RUNBOOK"

echo "[prod-operator-lifecycle] easy_node dispatch"
PATH="$TMP_BIN:$PATH" \
DISPATCH_CAPTURE_FILE="$DISPATCH_CAPTURE" \
PROD_OPERATOR_LIFECYCLE_RUNBOOK_SCRIPT="$FAKE_RUNBOOK" \
./scripts/easy_node.sh prod-operator-lifecycle-runbook \
  --action offboard \
  --verify-absent 0 >/tmp/integration_prod_operator_lifecycle_runbook_dispatch.log 2>&1

if ! rg -q -- '--action offboard' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --action"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi
if ! rg -q -- '--verify-absent 0' "$DISPATCH_CAPTURE"; then
  echo "easy_node prod-operator-lifecycle-runbook did not forward --verify-absent"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi

echo "prod operator lifecycle runbook integration check ok"
