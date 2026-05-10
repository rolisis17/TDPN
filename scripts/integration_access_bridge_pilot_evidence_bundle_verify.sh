#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in awk bash find grep jq mktemp sed sha256sum tar; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "access bridge pilot evidence bundle verifier integration failed: missing required command: $cmd"
    exit 2
  fi
done

PYTHON_BIN="${PYTHON_BIN:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
  else
    echo "access bridge pilot evidence bundle verifier integration failed: missing required command: python3 or python"
    exit 2
  fi
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

BUNDLE_DIR="$TMP_DIR/access_bridge_pilot_evidence_bundle"
SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_summary.json"
BUNDLE_TAR="${BUNDLE_DIR}.tar.gz"
BUNDLE_TAR_SHA256_FILE="${BUNDLE_TAR}.sha256"
mkdir -p "$BUNDLE_DIR/bridge-deploy-pack"
printf '%s\n' '{"status":"pass"}' >"$BUNDLE_DIR/access_bridge_service_smoke_summary.json"
printf '%s\n' 'smoke ok' >"$BUNDLE_DIR/access_bridge_service_smoke.log"
printf '%s\n' '{"status":"pass"}' >"$BUNDLE_DIR/access_bridge_deployment_evidence_summary.json"
printf '%s\n' '{"status":"pass"}' >"$BUNDLE_DIR/access_bridge_host_install_check_summary.json"
printf '%s\n' 'GPM_BRIDGE_ALLOW_QUERY_CODE="false"' >"$BUNDLE_DIR/bridge-deploy-pack/gpm-access-bridge.env"
printf '%s\n' '{"helper_id":"helper-pilot"}' >"$BUNDLE_DIR/bridge-service-config.json"

(
  cd "$BUNDLE_DIR"
  find . -type f -print \
    | sed 's|^\./||' \
    | grep -v '^manifest\.sha256$' \
    | LC_ALL=C sort \
    | while IFS= read -r rel; do
        sha256sum "$rel"
      done
) >"$BUNDLE_DIR/manifest.sha256"

tar -czf "$BUNDLE_TAR" -C "$TMP_DIR" "$(basename "$BUNDLE_DIR")"
printf '%s  %s\n' "$(sha256sum "$BUNDLE_TAR" | awk '{print $1}')" "$(basename "$BUNDLE_TAR")" >"$BUNDLE_TAR_SHA256_FILE"

jq -n \
  --arg bundle_dir "$BUNDLE_DIR" \
  --arg bundle_tar "$BUNDLE_TAR" \
  --arg bundle_tar_sha256_file "$BUNDLE_TAR_SHA256_FILE" \
  --arg manifest_sha256 "$BUNDLE_DIR/manifest.sha256" \
  '{
    schema: {id: "access_bridge_pilot_evidence_bundle_summary"},
    status: "pass",
    artifacts: {
      bundle_dir: $bundle_dir,
      bundle_tar: $bundle_tar,
      bundle_tar_sha256_file: $bundle_tar_sha256_file,
      manifest_sha256: $manifest_sha256
    }
  }' >"$SUMMARY_JSON"

bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --summary-json "$SUMMARY_JSON" >"$TMP_DIR/verify-summary.log"
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-dir "$BUNDLE_DIR" >"$TMP_DIR/verify-dir.log"
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-tar "$BUNDLE_TAR" >"$TMP_DIR/verify-tar.log"

printf '%s\n' 'tampered' >>"$BUNDLE_DIR/access_bridge_service_smoke.log"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-dir "$BUNDLE_DIR" --check-tar-sha256 0 >"$TMP_DIR/tamper.log" 2>&1
tamper_rc=$?
set -e
if [[ "$tamper_rc" -eq 0 ]] || ! grep -Fq 'manifest checksum mismatch' "$TMP_DIR/tamper.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: manifest tamper was not rejected"
  cat "$TMP_DIR/tamper.log"
  exit 1
fi

BAD_SHA="$TMP_DIR/bad.tar.gz.sha256"
printf '%064d  %s\n' 0 "$(basename "$BUNDLE_TAR")" >"$BAD_SHA"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-tar "$BUNDLE_TAR" --bundle-tar-sha256-file "$BAD_SHA" --check-manifest 0 >"$TMP_DIR/bad-sha.log" 2>&1
bad_sha_rc=$?
set -e
if [[ "$bad_sha_rc" -eq 0 ]] || ! grep -Fq 'bundle tar checksum mismatch' "$TMP_DIR/bad-sha.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: tar checksum mismatch was not rejected"
  cat "$TMP_DIR/bad-sha.log"
  exit 1
fi

UNSAFE_TAR="$TMP_DIR/unsafe-path.tar.gz"
UNSAFE_SHA="${UNSAFE_TAR}.sha256"
LINK_TAR="$TMP_DIR/unsafe-link.tar.gz"
LINK_SHA="${LINK_TAR}.sha256"
"$PYTHON_BIN" - "$UNSAFE_TAR" "$LINK_TAR" <<'PY'
import io
import sys
import tarfile

unsafe_tar, link_tar = sys.argv[1], sys.argv[2]

with tarfile.open(unsafe_tar, "w:gz") as tf:
    payload = b"escape\n"
    info = tarfile.TarInfo("../escape.txt")
    info.size = len(payload)
    tf.addfile(info, io.BytesIO(payload))

with tarfile.open(link_tar, "w:gz") as tf:
    payload = b"target\n"
    info = tarfile.TarInfo("bundle/target.txt")
    info.size = len(payload)
    tf.addfile(info, io.BytesIO(payload))
    link = tarfile.TarInfo("bundle/link.txt")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    tf.addfile(link)
PY
printf '%s  %s\n' "$(sha256sum "$UNSAFE_TAR" | awk '{print $1}')" "$(basename "$UNSAFE_TAR")" >"$UNSAFE_SHA"
printf '%s  %s\n' "$(sha256sum "$LINK_TAR" | awk '{print $1}')" "$(basename "$LINK_TAR")" >"$LINK_SHA"

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-tar "$UNSAFE_TAR" --bundle-tar-sha256-file "$UNSAFE_SHA" --check-manifest 0 >"$TMP_DIR/unsafe-path.log" 2>&1
unsafe_path_rc=$?
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-tar "$LINK_TAR" --bundle-tar-sha256-file "$LINK_SHA" --check-manifest 0 >"$TMP_DIR/unsafe-link.log" 2>&1
unsafe_link_rc=$?
set -e
if [[ "$unsafe_path_rc" -eq 0 ]] || ! grep -Fq 'unsafe bundle tar member path' "$TMP_DIR/unsafe-path.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: unsafe tar path was not rejected"
  cat "$TMP_DIR/unsafe-path.log"
  exit 1
fi
if [[ "$unsafe_link_rc" -eq 0 ]] || ! grep -Fq 'unsafe bundle tar link member' "$TMP_DIR/unsafe-link.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: unsafe tar link was not rejected"
  cat "$TMP_DIR/unsafe-link.log"
  exit 1
fi

echo "access bridge pilot evidence bundle verifier integration check ok"
