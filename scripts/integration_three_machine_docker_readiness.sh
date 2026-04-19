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
DOCKER_STATE_DIR="$TMP_DIR/docker_state"
SUMMARY_OK="$TMP_DIR/summary_ok.json"
SUMMARY_RETRY_OK="$TMP_DIR/summary_retry_ok.json"
SUMMARY_RETRY_EXHAUST="$TMP_DIR/summary_retry_exhaust.json"
SUMMARY_FAIL="$TMP_DIR/summary_fail.json"
LOG_OK="$TMP_DIR/run_ok.log"
LOG_RETRY_OK="$TMP_DIR/run_retry_ok.log"
LOG_RETRY_EXHAUST="$TMP_DIR/run_retry_exhaust.log"
LOG_FAIL="$TMP_DIR/run_fail.log"

mkdir -p "$DOCKER_STATE_DIR"

cat >"$TMP_BIN/docker" <<'EOF_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_DOCKER_CAPTURE_FILE:?}"
step_id=""
fail_attempts=0
if [[ "$*" == *"-p pn3a"* && "$*" == *" up -d --build directory issuer entry-exit"* ]]; then
  step_id="stack_a_up"
  fail_attempts="${FAKE_DOCKER_FAIL_STACK_A_UP_ATTEMPTS:-0}"
elif [[ "$*" == *"-p pn3b"* && "$*" == *" up -d --build directory issuer entry-exit"* ]]; then
  step_id="stack_b_up"
  fail_attempts="${FAKE_DOCKER_FAIL_STACK_B_UP_ATTEMPTS:-0}"
fi
if [[ -n "$step_id" ]]; then
  state_dir="${FAKE_DOCKER_STATE_DIR:?}"
  mkdir -p "$state_dir"
  count_file="$state_dir/${step_id}.count"
  count=0
  if [[ -f "$count_file" ]]; then
    count="$(cat "$count_file" 2>/dev/null || printf '0')"
  fi
  if ! [[ "$count" =~ ^[0-9]+$ ]]; then
    count=0
  fi
  if ! [[ "$fail_attempts" =~ ^[0-9]+$ ]]; then
    fail_attempts=0
  fi
  if (( count < fail_attempts )); then
    count=$((count + 1))
    printf '%s\n' "$count" >"$count_file"
    case "${FAKE_DOCKER_FAIL_MODE:-retryable}" in
      retryable)
        echo 'failed to do request: Head "https://registry-1.docker.io/v2/library/alpine/manifests/3.20": dial tcp: lookup registry-1.docker.io on 127.0.0.53:53: server misbehaving' >&2
        ;;
      *)
        echo 'Dockerfile parse error: unknown instruction: BROKEN' >&2
        ;;
    esac
    exit 1
  fi
fi
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
FAKE_DOCKER_STATE_DIR="$DOCKER_STATE_DIR" \
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

echo "[three-machine-docker-readiness] compose up retry recovery path"
: >"$DOCKER_CAPTURE"
: >"$CURL_CAPTURE"
: >"$VALIDATE_CAPTURE"
: >"$SOAK_CAPTURE"
rm -f "$DOCKER_STATE_DIR"/*.count 2>/dev/null || true
FAKE_DOCKER_CAPTURE_FILE="$DOCKER_CAPTURE" \
FAKE_DOCKER_STATE_DIR="$DOCKER_STATE_DIR" \
FAKE_DOCKER_FAIL_STACK_A_UP_ATTEMPTS=1 \
FAKE_DOCKER_FAIL_MODE=retryable \
FAKE_CURL_CAPTURE_FILE="$CURL_CAPTURE" \
FAKE_VALIDATE_CAPTURE_FILE="$VALIDATE_CAPTURE" \
FAKE_SOAK_CAPTURE_FILE="$SOAK_CAPTURE" \
THREE_MACHINE_DOCKER_DOCKER_BIN="$TMP_BIN/docker" \
THREE_MACHINE_DOCKER_CURL_BIN="$TMP_BIN/curl" \
THREE_MACHINE_DOCKER_VALIDATE_SCRIPT="$FAKE_VALIDATE" \
THREE_MACHINE_DOCKER_SOAK_SCRIPT="$FAKE_SOAK" \
THREE_MACHINE_DOCKER_COMPOSE_UP_MAX_ATTEMPTS=3 \
THREE_MACHINE_DOCKER_COMPOSE_UP_INITIAL_BACKOFF_SEC=0 \
./scripts/three_machine_docker_readiness.sh \
  --summary-json "$SUMMARY_RETRY_OK" \
  --print-summary-json 0 >"$LOG_RETRY_OK" 2>&1

if ! jq -e '
  .status == "pass"
  and .config.compose_up_max_attempts == 3
  and .config.compose_up_initial_backoff_sec == 0
  and (.steps[] | select(.step_id == "stack_a_up") | .status == "pass")
  and (.steps[] | select(.step_id == "stack_a_up") | (.note | contains("recovered after retry attempt=2/3")))
' "$SUMMARY_RETRY_OK" >/dev/null; then
  echo "retry recovery summary missing expected fields"
  cat "$SUMMARY_RETRY_OK"
  exit 1
fi
if ! rg -q '\[docker-retry\] step=stack_a_up attempt=1/3' "$LOG_RETRY_OK"; then
  echo "retry recovery log missing docker-retry marker"
  cat "$LOG_RETRY_OK"
  exit 1
fi
stack_a_up_count="$(rg -c -- '-p pn3a .* up -d --build directory issuer entry-exit' "$DOCKER_CAPTURE" || true)"
if [[ "${stack_a_up_count:-0}" -lt 2 ]]; then
  echo "expected at least two stack A compose up attempts in retry recovery path"
  cat "$DOCKER_CAPTURE"
  exit 1
fi

echo "[three-machine-docker-readiness] compose up retry exhaustion path"
: >"$DOCKER_CAPTURE"
: >"$CURL_CAPTURE"
: >"$VALIDATE_CAPTURE"
: >"$SOAK_CAPTURE"
rm -f "$DOCKER_STATE_DIR"/*.count 2>/dev/null || true
set +e
FAKE_DOCKER_CAPTURE_FILE="$DOCKER_CAPTURE" \
FAKE_DOCKER_STATE_DIR="$DOCKER_STATE_DIR" \
FAKE_DOCKER_FAIL_STACK_A_UP_ATTEMPTS=3 \
FAKE_DOCKER_FAIL_MODE=retryable \
FAKE_CURL_CAPTURE_FILE="$CURL_CAPTURE" \
FAKE_VALIDATE_CAPTURE_FILE="$VALIDATE_CAPTURE" \
FAKE_SOAK_CAPTURE_FILE="$SOAK_CAPTURE" \
THREE_MACHINE_DOCKER_DOCKER_BIN="$TMP_BIN/docker" \
THREE_MACHINE_DOCKER_CURL_BIN="$TMP_BIN/curl" \
THREE_MACHINE_DOCKER_VALIDATE_SCRIPT="$FAKE_VALIDATE" \
THREE_MACHINE_DOCKER_SOAK_SCRIPT="$FAKE_SOAK" \
THREE_MACHINE_DOCKER_COMPOSE_UP_MAX_ATTEMPTS=2 \
THREE_MACHINE_DOCKER_COMPOSE_UP_INITIAL_BACKOFF_SEC=0 \
./scripts/three_machine_docker_readiness.sh \
  --summary-json "$SUMMARY_RETRY_EXHAUST" \
  --print-summary-json 0 >"$LOG_RETRY_EXHAUST" 2>&1
rc_retry_exhaust=$?
set -e
if [[ $rc_retry_exhaust -eq 0 ]]; then
  echo "retry exhaustion path should return non-zero"
  cat "$LOG_RETRY_EXHAUST"
  cat "$SUMMARY_RETRY_EXHAUST"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .failed_step == "stack_a_up"
  and .config.compose_up_max_attempts == 2
  and (.steps[] | select(.step_id == "stack_a_up") | .status == "fail")
  and (.steps[] | select(.step_id == "stack_a_up") | (.note | contains("after retryable errors attempts=2/2")))
  and (([.steps[] | select(.step_id == "stack_b_up")] | length) == 0)
' "$SUMMARY_RETRY_EXHAUST" >/dev/null; then
  echo "retry exhaustion summary missing expected fields"
  cat "$SUMMARY_RETRY_EXHAUST"
  exit 1
fi
stack_a_up_count_exhaust="$(rg -c -- '-p pn3a .* up -d --build directory issuer entry-exit' "$DOCKER_CAPTURE" || true)"
if [[ "${stack_a_up_count_exhaust:-0}" -ne 2 ]]; then
  echo "expected exactly two stack A compose up attempts in retry exhaustion path"
  cat "$DOCKER_CAPTURE"
  exit 1
fi

echo "[three-machine-docker-readiness] validate failure path"
: >"$DOCKER_CAPTURE"
: >"$CURL_CAPTURE"
: >"$VALIDATE_CAPTURE"
: >"$SOAK_CAPTURE"
rm -f "$DOCKER_STATE_DIR"/*.count 2>/dev/null || true
set +e
FAKE_DOCKER_CAPTURE_FILE="$DOCKER_CAPTURE" \
FAKE_DOCKER_STATE_DIR="$DOCKER_STATE_DIR" \
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

: >"$FORWARD_CAPTURE"
FAKE_FORWARD_CAPTURE_FILE="$FORWARD_CAPTURE" \
THREE_MACHINE_DOCKER_READINESS_SCRIPT="$FAKE_FORWARD" \
./scripts/easy_node.sh three-machine-docker-readiness --run-peer-failover 1 --peer-failover-downtime-sec 5 --peer-failover-timeout-sec 20 >/tmp/integration_three_machine_docker_readiness_forward_peer_failover.log 2>&1
if ! rg -q '^--run-peer-failover 1 --peer-failover-downtime-sec 5 --peer-failover-timeout-sec 20$' "$FORWARD_CAPTURE"; then
  echo "easy_node forwarding failed for peer-failover args"
  cat "$FORWARD_CAPTURE"
  cat /tmp/integration_three_machine_docker_readiness_forward_peer_failover.log
  exit 1
fi

echo "three-machine docker readiness integration check ok"
