#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq rg mktemp chmod; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
TMP_BIN="$TMP_DIR/bin"
mkdir -p "$TMP_BIN"
trap 'rm -rf "$TMP_DIR"' EXIT

DOCKER_CAPTURE="$TMP_DIR/docker_calls.log"
CURL_CAPTURE="$TMP_DIR/curl_calls.log"
VALIDATE_CAPTURE="$TMP_DIR/validate_calls.log"
SOAK_CAPTURE="$TMP_DIR/soak_calls.log"
FORWARD_CAPTURE="$TMP_DIR/forward_calls.log"
SUMMARY_OK="$TMP_DIR/summary_ok.json"
SUMMARY_FAIL="$TMP_DIR/summary_fail.json"
LOG_OK="$TMP_DIR/run_ok.log"
LOG_FAIL="$TMP_DIR/run_fail.log"

cat >"$TMP_BIN/docker" <<'EOF_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_DOCKER_CAPTURE_FILE:?}"
exit 0
EOF_DOCKER

cat >"$TMP_BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_CURL_CAPTURE_FILE:?}"
url="${@: -1}"
case "$url" in
  */v1/relays)
    printf '%s\n' '{"relays":[]}'
    ;;
  */v1/pubkeys)
    printf '%s\n' '{"issuer":"issuer-test","pub_keys":["k1"]}'
    ;;
  */v1/health)
    printf '%s\n' '{"status":"ok"}'
    ;;
  *)
    printf '%s\n' '{}'
    ;;
esac
EOF_CURL

FAKE_VALIDATE="$TMP_DIR/fake_validate.sh"
cat >"$FAKE_VALIDATE" <<'EOF_VALIDATE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_VALIDATE_CAPTURE_FILE:?}"
if [[ "${FAKE_VALIDATE_FAIL:-0}" == "1" ]]; then
  echo "fake validate fail"
  exit 1
fi
echo "3-machine beta validation check ok"
EOF_VALIDATE

FAKE_SOAK="$TMP_DIR/fake_soak.sh"
cat >"$FAKE_SOAK" <<'EOF_SOAK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_SOAK_CAPTURE_FILE:?}"
echo "[3machine-soak] ok"
EOF_SOAK

FAKE_FORWARD="$TMP_DIR/fake_forward.sh"
cat >"$FAKE_FORWARD" <<'EOF_FORWARD'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_FORWARD_CAPTURE_FILE:?}"
EOF_FORWARD

chmod +x \
  "$TMP_BIN/docker" \
  "$TMP_BIN/curl" \
  "$FAKE_VALIDATE" \
  "$FAKE_SOAK" \
  "$FAKE_FORWARD"

echo "[three-machine-docker-readiness] success path"
FAKE_DOCKER_CAPTURE_FILE="$DOCKER_CAPTURE" \
FAKE_CURL_CAPTURE_FILE="$CURL_CAPTURE" \
FAKE_VALIDATE_CAPTURE_FILE="$VALIDATE_CAPTURE" \
FAKE_SOAK_CAPTURE_FILE="$SOAK_CAPTURE" \
THREE_MACHINE_DOCKER_DOCKER_BIN="$TMP_BIN/docker" \
THREE_MACHINE_DOCKER_CURL_BIN="$TMP_BIN/curl" \
THREE_MACHINE_DOCKER_VALIDATE_SCRIPT="$FAKE_VALIDATE" \
THREE_MACHINE_DOCKER_SOAK_SCRIPT="$FAKE_SOAK" \
./scripts/three_machine_docker_readiness.sh \
  --summary-json "$SUMMARY_OK" \
  --print-summary-json 1 >"$LOG_OK"

if ! rg -q '^three-machine-docker-readiness: status=pass$' "$LOG_OK"; then
  echo "success path missing pass status"
  cat "$LOG_OK"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and (.steps[] | select(.step_id == "validate") | .status == "pass")
  and (.steps[] | select(.step_id == "soak") | .status == "pass")
' "$SUMMARY_OK" >/dev/null; then
  echo "success summary missing expected fields"
  cat "$SUMMARY_OK"
  exit 1
fi
if ! rg -q -- '-p pn3a .* up -d --build directory issuer entry-exit' "$DOCKER_CAPTURE"; then
  echo "missing stack A compose up call"
  cat "$DOCKER_CAPTURE"
  exit 1
fi
if ! rg -q -- '-p pn3b .* up -d --build directory issuer entry-exit' "$DOCKER_CAPTURE"; then
  echo "missing stack B compose up call"
  cat "$DOCKER_CAPTURE"
  exit 1
fi
if ! rg -q -- '-p pn3a .* down --remove-orphans' "$DOCKER_CAPTURE"; then
  echo "missing stack A compose down call"
  cat "$DOCKER_CAPTURE"
  exit 1
fi
if ! rg -q -- '-p pn3b .* down --remove-orphans' "$DOCKER_CAPTURE"; then
  echo "missing stack B compose down call"
  cat "$DOCKER_CAPTURE"
  exit 1
fi
if ! rg -q -- '--directory-a http://127.0.0.1:18081' "$VALIDATE_CAPTURE"; then
  echo "validate call missing directory A endpoint"
  cat "$VALIDATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--directory-b http://127.0.0.1:28081' "$VALIDATE_CAPTURE"; then
  echo "validate call missing directory B endpoint"
  cat "$VALIDATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--entry-url http://127.0.0.1:18083' "$VALIDATE_CAPTURE"; then
  echo "validate call missing entry endpoint"
  cat "$VALIDATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--exit-url http://127.0.0.1:18084' "$VALIDATE_CAPTURE"; then
  echo "validate call missing exit endpoint"
  cat "$VALIDATE_CAPTURE"
  exit 1
fi
if [[ ! -s "$SOAK_CAPTURE" ]]; then
  echo "soak call missing in success path"
  exit 1
fi

echo "[three-machine-docker-readiness] validate failure path"
: >"$DOCKER_CAPTURE"
: >"$CURL_CAPTURE"
: >"$VALIDATE_CAPTURE"
: >"$SOAK_CAPTURE"
set +e
FAKE_DOCKER_CAPTURE_FILE="$DOCKER_CAPTURE" \
FAKE_CURL_CAPTURE_FILE="$CURL_CAPTURE" \
FAKE_VALIDATE_CAPTURE_FILE="$VALIDATE_CAPTURE" \
FAKE_SOAK_CAPTURE_FILE="$SOAK_CAPTURE" \
FAKE_VALIDATE_FAIL=1 \
THREE_MACHINE_DOCKER_DOCKER_BIN="$TMP_BIN/docker" \
THREE_MACHINE_DOCKER_CURL_BIN="$TMP_BIN/curl" \
THREE_MACHINE_DOCKER_VALIDATE_SCRIPT="$FAKE_VALIDATE" \
THREE_MACHINE_DOCKER_SOAK_SCRIPT="$FAKE_SOAK" \
./scripts/three_machine_docker_readiness.sh \
  --summary-json "$SUMMARY_FAIL" \
  --print-summary-json 0 >"$LOG_FAIL" 2>&1
rc_fail=$?
set -e
if [[ $rc_fail -eq 0 ]]; then
  echo "failure path should return non-zero"
  cat "$LOG_FAIL"
  cat "$SUMMARY_FAIL"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .failed_step == "validate"
  and (.steps[] | select(.step_id == "validate") | .status == "fail")
  and (.steps[] | select(.step_id == "soak") | .status == "skip")
' "$SUMMARY_FAIL" >/dev/null; then
  echo "failure summary missing expected fields"
  cat "$SUMMARY_FAIL"
  exit 1
fi
if ! rg -q -- '-p pn3a .* down --remove-orphans' "$DOCKER_CAPTURE"; then
  echo "failure path missing stack A compose down call"
  cat "$DOCKER_CAPTURE"
  exit 1
fi
if ! rg -q -- '-p pn3b .* down --remove-orphans' "$DOCKER_CAPTURE"; then
  echo "failure path missing stack B compose down call"
  cat "$DOCKER_CAPTURE"
  exit 1
fi

echo "[three-machine-docker-readiness] easy_node forwarding"
FAKE_FORWARD_CAPTURE_FILE="$FORWARD_CAPTURE" \
THREE_MACHINE_DOCKER_READINESS_SCRIPT="$FAKE_FORWARD" \
./scripts/easy_node.sh three-machine-docker-readiness --run-soak 0 --keep-stacks 1 >/tmp/integration_three_machine_docker_readiness_forward.log 2>&1
if ! rg -q '^--run-soak 0 --keep-stacks 1$' "$FORWARD_CAPTURE"; then
  echo "easy_node forwarding failed for three-machine-docker-readiness"
  cat "$FORWARD_CAPTURE"
  cat /tmp/integration_three_machine_docker_readiness_forward.log
  exit 1
fi

echo "three-machine docker readiness integration check ok"
