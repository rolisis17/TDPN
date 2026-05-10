#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in awk bash cp find grep jq mktemp sed sha256sum tar; do
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
    version: 1,
    schema: {id: "access_bridge_pilot_evidence_bundle_summary"},
    status: "pass",
    rc: 0,
    summary: {
      steps_total: 3,
      steps_fail: 0
    },
    steps: [
      {id: "service_smoke", status: "pass", rc: 0},
      {id: "deployment_evidence", status: "pass", rc: 0},
      {id: "host_install_check", status: "pass", rc: 0}
    ],
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

BAD_SUMMARY_JSON="$TMP_DIR/bad_bundle_summary_contract.json"
jq '.status = "fail" | .rc = 1 | .summary.steps_fail = 1 | .steps[0].status = "fail" | .steps[0].rc = 1' "$SUMMARY_JSON" >"$BAD_SUMMARY_JSON"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --summary-json "$BAD_SUMMARY_JSON" --check-tar-sha256 0 --check-manifest 0 >"$TMP_DIR/bad-summary-contract.log" 2>&1
bad_summary_contract_rc=$?
set -e
if [[ "$bad_summary_contract_rc" -eq 0 ]] || ! grep -Fq 'bundle summary status is not pass' "$TMP_DIR/bad-summary-contract.log" || ! grep -Fq 'bundle summary steps_fail is not 0' "$TMP_DIR/bad-summary-contract.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: bad summary contract was not rejected"
  cat "$TMP_DIR/bad-summary-contract.log"
  exit 1
fi

MISSING_STEPS_SUMMARY_JSON="$TMP_DIR/missing_steps_bundle_summary_contract.json"
jq 'del(.steps)' "$SUMMARY_JSON" >"$MISSING_STEPS_SUMMARY_JSON"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --summary-json "$MISSING_STEPS_SUMMARY_JSON" --check-tar-sha256 0 --check-manifest 0 >"$TMP_DIR/missing-steps-summary-contract.log" 2>&1
missing_steps_summary_contract_rc=$?
set -e
if [[ "$missing_steps_summary_contract_rc" -eq 0 ]] || ! grep -Fq 'bundle summary steps array is missing or empty' "$TMP_DIR/missing-steps-summary-contract.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: missing summary steps array was not rejected"
  cat "$TMP_DIR/missing-steps-summary-contract.log"
  exit 1
fi

MANIFEST_UNSAFE_DIR="$TMP_DIR/manifest-unsafe-bundle"
cp -R "$BUNDLE_DIR" "$MANIFEST_UNSAFE_DIR"
printf '%s  %s\n' "$(sha256sum "$MANIFEST_UNSAFE_DIR/access_bridge_service_smoke.log" | awk '{print $1}')" '..\escape.txt' >>"$MANIFEST_UNSAFE_DIR/manifest.sha256"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-dir "$MANIFEST_UNSAFE_DIR" --check-tar-sha256 0 >"$TMP_DIR/unsafe-manifest-path.log" 2>&1
unsafe_manifest_path_rc=$?
set -e
if [[ "$unsafe_manifest_path_rc" -eq 0 ]] || ! grep -Fq 'unsafe manifest entry path' "$TMP_DIR/unsafe-manifest-path.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: unsafe manifest path was not rejected"
  cat "$TMP_DIR/unsafe-manifest-path.log"
  exit 1
fi

EXTRA_TOP_LEVEL_ROOT="$TMP_DIR/extra-top-level-root"
EXTRA_TOP_LEVEL_DIR="$EXTRA_TOP_LEVEL_ROOT/$(basename "$BUNDLE_DIR")"
EXTRA_TOP_LEVEL_TAR="$TMP_DIR/extra-top-level.tar.gz"
EXTRA_TOP_LEVEL_SHA="${EXTRA_TOP_LEVEL_TAR}.sha256"
mkdir -p "$EXTRA_TOP_LEVEL_ROOT"
cp -R "$BUNDLE_DIR" "$EXTRA_TOP_LEVEL_DIR"
printf '%s\n' 'unmanifested sibling data' >"$EXTRA_TOP_LEVEL_ROOT/extra-secret.txt"
tar -czf "$EXTRA_TOP_LEVEL_TAR" -C "$EXTRA_TOP_LEVEL_ROOT" "$(basename "$BUNDLE_DIR")" "extra-secret.txt"
printf '%s  %s\n' "$(sha256sum "$EXTRA_TOP_LEVEL_TAR" | awk '{print $1}')" "$(basename "$EXTRA_TOP_LEVEL_TAR")" >"$EXTRA_TOP_LEVEL_SHA"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-tar "$EXTRA_TOP_LEVEL_TAR" --bundle-tar-sha256-file "$EXTRA_TOP_LEVEL_SHA" >"$TMP_DIR/extra-top-level.log" 2>&1
extra_top_level_rc=$?
set -e
if [[ "$extra_top_level_rc" -eq 0 ]] || ! grep -Fq 'exactly one top-level bundle directory' "$TMP_DIR/extra-top-level.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: extra top-level tar member was not rejected"
  cat "$TMP_DIR/extra-top-level.log"
  exit 1
fi

TAR_TAMPER_ROOT="$TMP_DIR/tar-tamper-root"
TAR_TAMPER_DIR="$TAR_TAMPER_ROOT/$(basename "$BUNDLE_DIR")"
TAR_TAMPER="$TMP_DIR/tar-tamper.tar.gz"
TAR_TAMPER_SHA="${TAR_TAMPER}.sha256"
TAR_TAMPER_SUMMARY="$TMP_DIR/tar-tamper-summary.json"
mkdir -p "$TAR_TAMPER_ROOT"
cp -R "$BUNDLE_DIR" "$TAR_TAMPER_DIR"
printf '%s\n' 'tampered only inside tar' >>"$TAR_TAMPER_DIR/access_bridge_service_smoke.log"
tar -czf "$TAR_TAMPER" -C "$TAR_TAMPER_ROOT" "$(basename "$BUNDLE_DIR")"
printf '%s  %s\n' "$(sha256sum "$TAR_TAMPER" | awk '{print $1}')" "$(basename "$TAR_TAMPER")" >"$TAR_TAMPER_SHA"
jq \
  --arg bundle_tar "$TAR_TAMPER" \
  --arg bundle_tar_sha256_file "$TAR_TAMPER_SHA" \
  '.artifacts.bundle_tar = $bundle_tar | .artifacts.bundle_tar_sha256_file = $bundle_tar_sha256_file' \
  "$SUMMARY_JSON" >"$TAR_TAMPER_SUMMARY"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --summary-json "$TAR_TAMPER_SUMMARY" >"$TMP_DIR/tar-tamper.log" 2>&1
tar_tamper_rc=$?
set -e
if [[ "$tar_tamper_rc" -eq 0 ]] || ! grep -Fq 'manifest checksum mismatch' "$TMP_DIR/tar-tamper.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: tar-only tamper was not rejected"
  cat "$TMP_DIR/tar-tamper.log"
  exit 1
fi

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
WINDOWS_UNSAFE_TAR="$TMP_DIR/windows-unsafe-path.tar.gz"
WINDOWS_UNSAFE_SHA="${WINDOWS_UNSAFE_TAR}.sha256"
LINK_TAR="$TMP_DIR/unsafe-link.tar.gz"
LINK_SHA="${LINK_TAR}.sha256"
"$PYTHON_BIN" - "$UNSAFE_TAR" "$WINDOWS_UNSAFE_TAR" "$LINK_TAR" <<'PY'
import io
import sys
import tarfile

unsafe_tar, windows_unsafe_tar, link_tar = sys.argv[1], sys.argv[2], sys.argv[3]

with tarfile.open(unsafe_tar, "w:gz") as tf:
    payload = b"escape\n"
    info = tarfile.TarInfo("../escape.txt")
    info.size = len(payload)
    tf.addfile(info, io.BytesIO(payload))

with tarfile.open(windows_unsafe_tar, "w:gz") as tf:
    for name in ("C:/escape.txt", r"bundle\evil.txt"):
        payload = b"windows escape\n"
        info = tarfile.TarInfo(name)
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
printf '%s  %s\n' "$(sha256sum "$WINDOWS_UNSAFE_TAR" | awk '{print $1}')" "$(basename "$WINDOWS_UNSAFE_TAR")" >"$WINDOWS_UNSAFE_SHA"
printf '%s  %s\n' "$(sha256sum "$LINK_TAR" | awk '{print $1}')" "$(basename "$LINK_TAR")" >"$LINK_SHA"

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-tar "$UNSAFE_TAR" --bundle-tar-sha256-file "$UNSAFE_SHA" --check-manifest 0 >"$TMP_DIR/unsafe-path.log" 2>&1
unsafe_path_rc=$?
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-tar "$WINDOWS_UNSAFE_TAR" --bundle-tar-sha256-file "$WINDOWS_UNSAFE_SHA" --check-manifest 0 >"$TMP_DIR/windows-unsafe-path.log" 2>&1
windows_unsafe_path_rc=$?
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-tar "$LINK_TAR" --bundle-tar-sha256-file "$LINK_SHA" --check-manifest 0 >"$TMP_DIR/unsafe-link.log" 2>&1
unsafe_link_rc=$?
set -e
if [[ "$unsafe_path_rc" -eq 0 ]] || ! grep -Fq 'unsafe bundle tar member path' "$TMP_DIR/unsafe-path.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: unsafe tar path was not rejected"
  cat "$TMP_DIR/unsafe-path.log"
  exit 1
fi
if [[ "$windows_unsafe_path_rc" -eq 0 ]] || ! grep -Fq 'unsafe bundle tar member path' "$TMP_DIR/windows-unsafe-path.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: Windows-style unsafe tar path was not rejected"
  cat "$TMP_DIR/windows-unsafe-path.log"
  exit 1
fi
if [[ "$unsafe_link_rc" -eq 0 ]] || ! grep -Fq 'unsafe bundle tar link member' "$TMP_DIR/unsafe-link.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: unsafe tar link was not rejected"
  cat "$TMP_DIR/unsafe-link.log"
  exit 1
fi

echo "access bridge pilot evidence bundle verifier integration check ok"
