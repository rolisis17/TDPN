#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash rg tar; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
TMP_BIN="$TMP_DIR/bin"
SNAPSHOT_DIR="$TMP_DIR/incident_bundle"
mkdir -p "$TMP_BIN"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cat >"$TMP_BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
url="${@: -1}"
case "$url" in
  *"/v1/relays")
    printf '{"relays":[{"relay_id":"entry-op-a","operator_id":"op-a"}]}\n'
    ;;
  *"/v1/peers")
    printf '{"peers":[{"url":"http://peer-a:8081"}]}\n'
    ;;
  *"/v1/pubkeys")
    printf '{"issuer":"issuer-a","pub_keys":["k1"]}\n'
    ;;
  *"/v1/metrics")
    printf '{"accepted_packets":7}\n'
    ;;
  *"/v1/health")
    printf '{"ok":true}\n'
    ;;
  *)
    printf '{}\n'
    ;;
esac
EOF_CURL

cat >"$TMP_BIN/docker" <<'EOF_DOCKER'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "ps" ]]; then
  printf 'CONTAINER ID   IMAGE   STATUS\n'
  printf 'abc123         test    Up 1 minute\n'
  exit 0
fi
if [[ "${1:-}" == "info" ]]; then
  printf 'Server Version: fake\n'
  exit 0
fi
if [[ "${1:-}" == "compose" ]]; then
  shift
  if [[ "${1:-}" == "version" ]]; then
    printf 'Docker Compose version vtest\n'
    exit 0
  fi
  if [[ "${1:-}" == "--project-name" ]]; then
    shift 2
  fi
  if [[ "${1:-}" == "ps" ]]; then
    printf 'NAME                IMAGE               STATUS\n'
    printf 'deploy-directory-1  deploy-directory    Up\n'
    exit 0
  fi
  if [[ "${1:-}" == "logs" ]]; then
    service="${@: -1}"
    printf '[%s] fake log line\n' "$service"
    exit 0
  fi
fi

exit 0
EOF_DOCKER

chmod +x "$TMP_BIN/curl" "$TMP_BIN/docker"

PATH="$TMP_BIN:$PATH" ./scripts/incident_snapshot.sh \
  --bundle-dir "$SNAPSHOT_DIR" \
  --mode authority \
  --directory-url http://dir-a:8081 \
  --issuer-url http://issuer-a:8082 \
  --entry-url http://entry-a:8083 \
  --exit-url http://exit-a:8084 \
  --compose-project deploy \
  --include-docker-logs 1 \
  --docker-log-lines 15 \
  --timeout-sec 4 >/dev/null

if [[ ! -f "$SNAPSHOT_DIR/metadata.txt" ]]; then
  echo "incident snapshot integration failed: metadata missing"
  exit 1
fi
if [[ ! -f "$SNAPSHOT_DIR/endpoints/directory_relays.json" ]]; then
  echo "incident snapshot integration failed: relays snapshot missing"
  exit 1
fi
if ! rg -q '"relay_id":"entry-op-a"' "$SNAPSHOT_DIR/endpoints/directory_relays.json"; then
  echo "incident snapshot integration failed: relays snapshot missing expected payload"
  cat "$SNAPSHOT_DIR/endpoints/directory_relays.json"
  exit 1
fi
if [[ ! -f "$SNAPSHOT_DIR/docker/compose_ps.txt" ]]; then
  echo "incident snapshot integration failed: compose ps snapshot missing"
  exit 1
fi
if ! rg -q 'deploy-directory-1' "$SNAPSHOT_DIR/docker/compose_ps.txt"; then
  echo "incident snapshot integration failed: compose ps snapshot missing expected content"
  cat "$SNAPSHOT_DIR/docker/compose_ps.txt"
  exit 1
fi
if [[ ! -f "$SNAPSHOT_DIR/docker/directory_tail.log" ]]; then
  echo "incident snapshot integration failed: directory log tail missing"
  exit 1
fi
if ! rg -q '\[directory\] fake log line' "$SNAPSHOT_DIR/docker/directory_tail.log"; then
  echo "incident snapshot integration failed: directory log tail missing expected content"
  cat "$SNAPSHOT_DIR/docker/directory_tail.log"
  exit 1
fi
if [[ ! -f "$SNAPSHOT_DIR/manifest.sha256" ]]; then
  echo "incident snapshot integration failed: manifest missing"
  exit 1
fi
if [[ ! -f "${SNAPSHOT_DIR}.tar.gz" ]]; then
  echo "incident snapshot integration failed: bundle tar missing"
  exit 1
fi
if [[ ! -f "${SNAPSHOT_DIR}.tar.gz.sha256" ]]; then
  echo "incident snapshot integration failed: bundle tar sha missing"
  exit 1
fi
if ! tar -tzf "${SNAPSHOT_DIR}.tar.gz" | rg -q 'incident_bundle/metadata.txt'; then
  echo "incident snapshot integration failed: tar missing metadata file"
  tar -tzf "${SNAPSHOT_DIR}.tar.gz"
  exit 1
fi

echo "incident snapshot integration check ok"
