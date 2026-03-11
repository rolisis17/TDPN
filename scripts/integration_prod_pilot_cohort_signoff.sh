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

SIGNOFF_CAPTURE="$TMP_DIR/signoff_capture.log"
VERIFY_CAPTURE="$TMP_DIR/verify_capture.log"
CHECK_CAPTURE="$TMP_DIR/check_capture.log"

FAKE_VERIFY="$TMP_DIR/fake_verify.sh"
cat >"$FAKE_VERIFY" <<'EOF_FAKE_VERIFY'
#!/usr/bin/env bash
set -euo pipefail
printf 'verify %s\n' "$*" >>"${SIGNOFF_CAPTURE_FILE:?}"
printf '%s\n' "$*" >>"${VERIFY_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_VERIFY
chmod +x "$FAKE_VERIFY"

FAKE_CHECK="$TMP_DIR/fake_check.sh"
cat >"$FAKE_CHECK" <<'EOF_FAKE_CHECK'
#!/usr/bin/env bash
set -euo pipefail
printf 'check %s\n' "$*" >>"${SIGNOFF_CAPTURE_FILE:?}"
printf '%s\n' "$*" >>"${CHECK_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_CHECK
chmod +x "$FAKE_CHECK"

echo "[prod-pilot-cohort-signoff] script orchestration success path"
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
VERIFY_CAPTURE_FILE="$VERIFY_CAPTURE" \
CHECK_CAPTURE_FILE="$CHECK_CAPTURE" \
PROD_PILOT_COHORT_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
PROD_PILOT_COHORT_CHECK_SCRIPT="$FAKE_CHECK" \
./scripts/prod_pilot_cohort_signoff.sh \
  --summary-json /tmp/cohort/summary.json \
  --check-manifest 0 \
  --max-alert-severity OK \
  --require-incident-snapshot-on-fail 0 \
  --require-incident-snapshot-artifacts 0 \
  --show-json 1 >/tmp/integration_prod_pilot_cohort_signoff_pass.log 2>&1

if ! rg -q -- '^verify ' "$SIGNOFF_CAPTURE"; then
  echo "expected verify step invocation not observed"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! rg -q -- '^check ' "$SIGNOFF_CAPTURE"; then
  echo "expected check step invocation not observed"
  cat "$SIGNOFF_CAPTURE"
  exit 1
fi
if ! rg -q -- '--summary-json /tmp/cohort/summary.json' "$VERIFY_CAPTURE"; then
  echo "signoff verify forwarding missing --summary-json"
  cat "$VERIFY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--summary-json /tmp/cohort/summary.json' "$CHECK_CAPTURE"; then
  echo "signoff check forwarding missing --summary-json"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-on-fail 0' "$CHECK_CAPTURE"; then
  echo "signoff check forwarding missing --require-incident-snapshot-on-fail"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-artifacts 0' "$CHECK_CAPTURE"; then
  echo "signoff check forwarding missing --require-incident-snapshot-artifacts"
  cat "$CHECK_CAPTURE"
  exit 1
fi

echo "[prod-pilot-cohort-signoff] fail-close when verify fails"
FAKE_VERIFY_FAIL="$TMP_DIR/fake_verify_fail.sh"
cat >"$FAKE_VERIFY_FAIL" <<'EOF_FAKE_VERIFY_FAIL'
#!/usr/bin/env bash
set -euo pipefail
printf 'verify-fail %s\n' "$*" >>"${SIGNOFF_CAPTURE_FILE:?}"
exit 1
EOF_FAKE_VERIFY_FAIL
chmod +x "$FAKE_VERIFY_FAIL"

CHECK_SHOULD_NOT_RUN="$TMP_DIR/check_should_not_run.log"
FAKE_CHECK_MARK="$TMP_DIR/fake_check_mark.sh"
cat >"$FAKE_CHECK_MARK" <<'EOF_FAKE_CHECK_MARK'
#!/usr/bin/env bash
set -euo pipefail
printf 'unexpected-check %s\n' "$*" >>"${CHECK_SHOULD_NOT_RUN_FILE:?}"
exit 0
EOF_FAKE_CHECK_MARK
chmod +x "$FAKE_CHECK_MARK"

set +e
SIGNOFF_CAPTURE_FILE="$SIGNOFF_CAPTURE" \
CHECK_SHOULD_NOT_RUN_FILE="$CHECK_SHOULD_NOT_RUN" \
PROD_PILOT_COHORT_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY_FAIL" \
PROD_PILOT_COHORT_CHECK_SCRIPT="$FAKE_CHECK_MARK" \
./scripts/prod_pilot_cohort_signoff.sh \
  --summary-json /tmp/cohort/summary.json >/tmp/integration_prod_pilot_cohort_signoff_verify_fail.log 2>&1
verify_fail_rc=$?
set -e
if [[ "$verify_fail_rc" -eq 0 ]]; then
  echo "expected non-zero rc when verify step fails"
  cat /tmp/integration_prod_pilot_cohort_signoff_verify_fail.log
  exit 1
fi
if [[ -f "$CHECK_SHOULD_NOT_RUN" ]]; then
  echo "check step should not run when verify step fails"
  cat "$CHECK_SHOULD_NOT_RUN"
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

echo "[prod-pilot-cohort-signoff] easy_node forwarding"
FAKE_SIGNOFF="$TMP_DIR/fake_signoff.sh"
SIGNOFF_FORWARD_CAPTURE="$TMP_DIR/signoff_forward_capture.log"
cat >"$FAKE_SIGNOFF" <<'EOF_FAKE_SIGNOFF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${SIGNOFF_FORWARD_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_SIGNOFF
chmod +x "$FAKE_SIGNOFF"

PATH="$TMP_BIN:$PATH" \
SIGNOFF_FORWARD_CAPTURE_FILE="$SIGNOFF_FORWARD_CAPTURE" \
PROD_PILOT_COHORT_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
./scripts/easy_node.sh prod-pilot-cohort-signoff \
  --summary-json /tmp/cohort/summary.json \
  --check-manifest 0 \
  --max-alert-severity OK \
  --require-incident-snapshot-on-fail 0 \
  --require-incident-snapshot-artifacts 0 \
  --show-json 1 >/tmp/integration_prod_pilot_cohort_signoff_easy_node.log 2>&1

if ! rg -q -- '--summary-json /tmp/cohort/summary.json' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node cohort signoff forwarding failed: missing --summary-json"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--check-manifest 0' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node cohort signoff forwarding failed: missing --check-manifest"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--max-alert-severity OK' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node cohort signoff forwarding failed: missing --max-alert-severity"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-on-fail 0' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node cohort signoff forwarding failed: missing --require-incident-snapshot-on-fail"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-artifacts 0' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node cohort signoff forwarding failed: missing --require-incident-snapshot-artifacts"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-json 1' "$SIGNOFF_FORWARD_CAPTURE"; then
  echo "easy_node cohort signoff forwarding failed: missing --show-json"
  cat "$SIGNOFF_FORWARD_CAPTURE"
  exit 1
fi

echo "prod pilot cohort signoff integration check ok"
