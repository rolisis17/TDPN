#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp rg; do
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
CAPTURE="$TMP_DIR/prod_pilot_args.log"

cat >"$FAKE_EASY_NODE" <<'EOF_FAKE_EASY_NODE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${CAPTURE_FILE:?}"
exit 0
EOF_FAKE_EASY_NODE
chmod +x "$FAKE_EASY_NODE"

echo "[prod-pilot] wrapper defaults + forwarding"
CAPTURE_FILE="$CAPTURE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
./scripts/prod_pilot_runbook.sh \
  --bootstrap-directory https://dir-a:8081 \
  --subject pilot-client \
  --signoff-check 0 \
  --wg-slo-profile strict >/tmp/integration_prod_pilot_runbook_wrapper.log 2>&1

if ! rg -q -- '^three-machine-prod-bundle' "$CAPTURE"; then
  echo "prod-pilot wrapper did not dispatch three-machine-prod-bundle"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-gate-slo-dashboard' "$CAPTURE"; then
  echo "prod-pilot wrapper did not dispatch prod-gate-slo-dashboard"
  cat "$CAPTURE"
  exit 1
fi

bundle_line="$(sed -n '1p' "$CAPTURE")"
dashboard_line="$(sed -n '2p' "$CAPTURE")"

if [[ -z "$bundle_line" || -z "$dashboard_line" ]]; then
  echo "expected two easy-node dispatch lines (bundle + dashboard)"
  cat "$CAPTURE"
  exit 1
fi

if ! printf '%s\n' "$bundle_line" | rg -q -- '--preflight-check 1'; then
  echo "prod-pilot wrapper missing default --preflight-check 1"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--bundle-verify-check 1'; then
  echo "prod-pilot wrapper missing default --bundle-verify-check 1"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--signoff-check 1'; then
  echo "prod-pilot wrapper missing default --signoff-check 1"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--strict-distinct 1'; then
  echo "prod-pilot wrapper missing default --strict-distinct 1"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--wg-slo-profile recommended'; then
  echo "prod-pilot wrapper missing default --wg-slo-profile recommended"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--bootstrap-directory https://dir-a:8081'; then
  echo "prod-pilot wrapper missing forwarded --bootstrap-directory"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--subject pilot-client'; then
  echo "prod-pilot wrapper missing forwarded --subject"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--signoff-check 0'; then
  echo "prod-pilot wrapper missing caller override --signoff-check 0"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--wg-slo-profile strict'; then
  echo "prod-pilot wrapper missing caller override --wg-slo-profile strict"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--run-report-json '; then
  echo "prod-pilot wrapper missing default --run-report-json dispatch"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$dashboard_line" | rg -q -- '--dashboard-md '; then
  echo "prod-pilot wrapper missing dashboard markdown output flag"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$dashboard_line" | rg -q -- '--reports-dir '; then
  echo "prod-pilot wrapper missing dashboard reports-dir fallback"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$dashboard_line" | rg -q -- '--print-dashboard 1'; then
  echo "prod-pilot wrapper missing default --print-dashboard 1"
  cat "$CAPTURE"
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

FAKE_PROD_PILOT="$TMP_DIR/fake_prod_pilot.sh"
DISPATCH_CAPTURE="$TMP_DIR/prod_pilot_dispatch_args.log"
cat >"$FAKE_PROD_PILOT" <<'EOF_FAKE_PROD_PILOT'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${DISPATCH_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_PROD_PILOT
chmod +x "$FAKE_PROD_PILOT"

echo "[prod-pilot] easy-node command dispatch"
PATH="$TMP_BIN:$PATH" \
DISPATCH_CAPTURE_FILE="$DISPATCH_CAPTURE" \
PROD_PILOT_RUNBOOK_SCRIPT="$FAKE_PROD_PILOT" \
./scripts/easy_node.sh prod-pilot-runbook --bootstrap-directory https://dir-b:8081 >/tmp/integration_prod_pilot_runbook_dispatch.log 2>&1

if ! rg -q -- '--bootstrap-directory https://dir-b:8081' "$DISPATCH_CAPTURE"; then
  echo "easy-node prod-pilot-runbook did not forward command arguments"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi

echo "prod pilot runbook integration check ok"
