#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in awk bash cat chmod cp find go grep jq mkdir mktemp sed sha256sum tar; do
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
PROVENANCE_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle.provenance.json"
BAD_PROVENANCE_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_bad.provenance.json"
LOCAL_SCOPE_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_local_scope_summary.json"
LOCAL_SCOPE_PROVENANCE_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_local_scope.provenance.json"
NO_PROVENANCE_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_no_provenance_summary.json"
UNSIGNED_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_unsigned_summary.json"
MISMATCHED_PROVENANCE_PATH_SUMMARY_JSON="$TMP_DIR/access_bridge_pilot_evidence_bundle_mismatched_provenance_path_summary.json"
PRIVATE_KEY_FILE="$TMP_DIR/provenance-private.key"
PUBLIC_KEY_FILE="$TMP_DIR/provenance-public.key"
TRUST_STORE="$TMP_DIR/provenance-trust-store.json"
mkdir -p "$BUNDLE_DIR/bridge-deploy-pack"
go run ./cmd/gpmrecover gen --private-key-out "$PRIVATE_KEY_FILE" --public-key-out "$PUBLIC_KEY_FILE" >/dev/null
go run ./cmd/gpmrecover trust-add --trust-store "$TRUST_STORE" --org-id pilot-org --org-name "Pilot Org" --public-key-file "$PUBLIC_KEY_FILE" >/dev/null
printf '%s\n' '{"status":"pass"}' >"$BUNDLE_DIR/access_bridge_service_smoke_summary.json"
printf '%s\n' 'smoke ok' >"$BUNDLE_DIR/access_bridge_service_smoke.log"
printf '%s\n' '{"status":"pass"}' >"$BUNDLE_DIR/access_bridge_deployment_evidence_summary.json"
printf '%s\n' '{"status":"pass"}' >"$BUNDLE_DIR/access_bridge_host_install_check_summary.json"
printf '%s\n' 'GPM_BRIDGE_ALLOW_QUERY_CODE="false"' >"$BUNDLE_DIR/bridge-deploy-pack/gpm-access-bridge.env"
printf '%s\n' '{"helper_id":"helper-pilot"}' >"$BUNDLE_DIR/bridge-service-config.json"

jq -n \
  --arg bundle_dir "$BUNDLE_DIR" \
  --arg bundle_tar "$BUNDLE_TAR" \
  --arg bundle_tar_sha256_file "$BUNDLE_TAR_SHA256_FILE" \
  --arg manifest_sha256 "$BUNDLE_DIR/manifest.sha256" \
  --arg summary_json "$SUMMARY_JSON" \
  --arg bundled_summary_json "$BUNDLE_DIR/access_bridge_pilot_evidence_bundle_summary.json" \
  --arg provenance_json "$PROVENANCE_JSON" \
  '{
    version: 1,
    schema: {id: "access_bridge_pilot_evidence_bundle_summary"},
    status: "pass",
    rc: 0,
    evidence_scope: "real_helper_https",
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
      manifest_sha256: $manifest_sha256,
      summary_json: $summary_json,
      bundled_summary_json: $bundled_summary_json,
      provenance_json: $provenance_json
    },
    provenance: {
      enabled: true,
      sidecar_json: $provenance_json,
      key_id: "",
      lifetime_hours: null
    }
  }' >"$SUMMARY_JSON"
cp "$SUMMARY_JSON" "$BUNDLE_DIR/access_bridge_pilot_evidence_bundle_summary.json"

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
go run ./cmd/gpmrecover provenance-sign \
  --summary-json "$SUMMARY_JSON" \
  --bundle-tar "$BUNDLE_TAR" \
  --bundle-tar-sha256-file "$BUNDLE_TAR_SHA256_FILE" \
  --private-key-file "$PRIVATE_KEY_FILE" \
  --org-id pilot-org \
  --org-name "Pilot Org" \
  --out "$PROVENANCE_JSON" >/dev/null

bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --summary-json "$SUMMARY_JSON" >"$TMP_DIR/verify-summary.log"
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-dir "$BUNDLE_DIR" >"$TMP_DIR/verify-dir.log"
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-tar "$BUNDLE_TAR" >"$TMP_DIR/verify-tar.log"
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" \
  --provenance-json "$PROVENANCE_JSON" \
  --public-key-file "$PUBLIC_KEY_FILE" >"$TMP_DIR/verify-provenance-public-key.log"
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" \
  --provenance-json "$PROVENANCE_JSON" \
  --trust-store "$TRUST_STORE" >"$TMP_DIR/verify-provenance-trust-store.log"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" \
  --provenance-json "$PROVENANCE_JSON" \
  --trust-store "$TRUST_STORE" \
  --public-key-file "$PUBLIC_KEY_FILE" >"$TMP_DIR/verify-provenance-dual-key-source.log" 2>&1
dual_key_source_rc=$?
set -e
if [[ "$dual_key_source_rc" -eq 0 ]] || ! grep -Fq 'provenance check requires exactly one of --trust-store or --public-key-file' "$TMP_DIR/verify-provenance-dual-key-source.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: provenance verification accepted dual key sources"
  cat "$TMP_DIR/verify-provenance-dual-key-source.log"
  exit 1
fi
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" >"$TMP_DIR/verify-provenance-trusted-policy-autoresolve.log"
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" \
  --provenance-json "$PROVENANCE_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" >"$TMP_DIR/verify-provenance-trusted-policy-explicit.log"

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" \
  --require-trusted-provenance 1 \
  --check-provenance 0 \
  --trust-store "$TRUST_STORE" >"$TMP_DIR/trusted-policy-check-provenance-disabled.log" 2>&1
trusted_check_disabled_rc=$?
set -e
if [[ "$trusted_check_disabled_rc" -eq 0 ]] || ! grep -Fq -- '--require-trusted-provenance requires --check-provenance 1' "$TMP_DIR/trusted-policy-check-provenance-disabled.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted disabled provenance check"
  cat "$TMP_DIR/trusted-policy-check-provenance-disabled.log"
  exit 1
fi

jq 'del(.artifacts.provenance_json)' "$SUMMARY_JSON" >"$NO_PROVENANCE_SUMMARY_JSON"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$NO_PROVENANCE_SUMMARY_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" >"$TMP_DIR/trusted-policy-missing-provenance.log" 2>&1
missing_provenance_rc=$?
set -e
if [[ "$missing_provenance_rc" -eq 0 ]] || ! grep -Fq 'trusted pilot provenance requires external summary artifacts.provenance_json' "$TMP_DIR/trusted-policy-missing-provenance.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted missing provenance"
  cat "$TMP_DIR/trusted-policy-missing-provenance.log"
  exit 1
fi

jq '.provenance.enabled = false' "$SUMMARY_JSON" >"$UNSIGNED_SUMMARY_JSON"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$UNSIGNED_SUMMARY_JSON" \
  --provenance-json "$PROVENANCE_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" >"$TMP_DIR/trusted-policy-unsigned-summary.log" 2>&1
unsigned_summary_rc=$?
set -e
if [[ "$unsigned_summary_rc" -eq 0 ]] || ! grep -Fq 'trusted pilot provenance requires external summary provenance.enabled=true' "$TMP_DIR/trusted-policy-unsigned-summary.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted unsigned summary metadata"
  cat "$TMP_DIR/trusted-policy-unsigned-summary.log"
  exit 1
fi

jq --arg other_provenance "$TMP_DIR/other.provenance.json" '.provenance.sidecar_json = $other_provenance' "$SUMMARY_JSON" >"$MISMATCHED_PROVENANCE_PATH_SUMMARY_JSON"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$MISMATCHED_PROVENANCE_PATH_SUMMARY_JSON" \
  --provenance-json "$PROVENANCE_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" >"$TMP_DIR/trusted-policy-mismatched-provenance-path.log" 2>&1
mismatched_provenance_path_rc=$?
set -e
if [[ "$mismatched_provenance_path_rc" -eq 0 ]] || ! grep -Fq 'trusted pilot provenance requires matching summary provenance paths' "$TMP_DIR/trusted-policy-mismatched-provenance-path.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted mismatched provenance path metadata"
  cat "$TMP_DIR/trusted-policy-mismatched-provenance-path.log"
  exit 1
fi

set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" \
  --provenance-json "$PROVENANCE_JSON" \
  --require-trusted-provenance 1 \
  --public-key-file "$PUBLIC_KEY_FILE" >"$TMP_DIR/trusted-policy-public-key.log" 2>&1
trusted_public_key_rc=$?
set -e
if [[ "$trusted_public_key_rc" -eq 0 ]] || ! grep -Fq 'does not accept --public-key-file' "$TMP_DIR/trusted-policy-public-key.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted raw public key verification"
  cat "$TMP_DIR/trusted-policy-public-key.log"
  exit 1
fi

jq --arg provenance_json "$LOCAL_SCOPE_PROVENANCE_JSON" '.evidence_scope = "local_rehearsal" | .artifacts.provenance_json = $provenance_json' "$SUMMARY_JSON" >"$LOCAL_SCOPE_SUMMARY_JSON"
go run ./cmd/gpmrecover provenance-sign \
  --summary-json "$LOCAL_SCOPE_SUMMARY_JSON" \
  --bundle-tar "$BUNDLE_TAR" \
  --bundle-tar-sha256-file "$BUNDLE_TAR_SHA256_FILE" \
  --private-key-file "$PRIVATE_KEY_FILE" \
  --org-id pilot-org \
  --org-name "Pilot Org" \
  --out "$LOCAL_SCOPE_PROVENANCE_JSON" >/dev/null
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$LOCAL_SCOPE_SUMMARY_JSON" \
  --require-trusted-provenance 1 \
  --trust-store "$TRUST_STORE" >"$TMP_DIR/trusted-policy-local-scope.log" 2>&1
local_scope_rc=$?
set -e
if [[ "$local_scope_rc" -eq 0 ]] || ! grep -Fq 'evidence_scope=real_helper_https' "$TMP_DIR/trusted-policy-local-scope.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: trusted policy accepted local evidence scope"
  cat "$TMP_DIR/trusted-policy-local-scope.log"
  exit 1
fi

jq '.subject.summary_json_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"' "$PROVENANCE_JSON" >"$BAD_PROVENANCE_JSON"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" \
  --provenance-json "$BAD_PROVENANCE_JSON" \
  --public-key-file "$PUBLIC_KEY_FILE" >"$TMP_DIR/bad-provenance.log" 2>&1
bad_provenance_rc=$?
set -e
if [[ "$bad_provenance_rc" -eq 0 ]] || ! grep -Fq 'provenance verification failed' "$TMP_DIR/bad-provenance.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: bad provenance was not rejected"
  cat "$TMP_DIR/bad-provenance.log"
  exit 1
fi

MISMATCH_ROOT="$TMP_DIR/bundled-summary-mismatch-root"
MISMATCH_DIR="$MISMATCH_ROOT/$(basename "$BUNDLE_DIR")"
MISMATCH_TAR="$TMP_DIR/bundled-summary-mismatch.tar.gz"
MISMATCH_SHA="${MISMATCH_TAR}.sha256"
MISMATCH_EXTERNAL_SUMMARY="$TMP_DIR/bundled-summary-mismatch-external.json"
mkdir -p "$MISMATCH_ROOT"
cp -R "$BUNDLE_DIR" "$MISMATCH_DIR"
jq '.status = "fail" | .rc = 1 | .summary.steps_fail = 1 | .steps[0].status = "fail" | .steps[0].rc = 1' \
  "$MISMATCH_DIR/access_bridge_pilot_evidence_bundle_summary.json" \
  >"$MISMATCH_DIR/access_bridge_pilot_evidence_bundle_summary.json.tmp"
mv "$MISMATCH_DIR/access_bridge_pilot_evidence_bundle_summary.json.tmp" "$MISMATCH_DIR/access_bridge_pilot_evidence_bundle_summary.json"
(
  cd "$MISMATCH_DIR"
  find . -type f -print \
    | sed 's|^\./||' \
    | grep -v '^manifest\.sha256$' \
    | LC_ALL=C sort \
    | while IFS= read -r rel; do
        sha256sum "$rel"
      done
) >"$MISMATCH_DIR/manifest.sha256"
tar -czf "$MISMATCH_TAR" -C "$MISMATCH_ROOT" "$(basename "$BUNDLE_DIR")"
printf '%s  %s\n' "$(sha256sum "$MISMATCH_TAR" | awk '{print $1}')" "$(basename "$MISMATCH_TAR")" >"$MISMATCH_SHA"
jq \
  --arg bundle_dir "$MISMATCH_DIR" \
  --arg bundle_tar "$MISMATCH_TAR" \
  --arg bundle_tar_sha256_file "$MISMATCH_SHA" \
  --arg manifest_sha256 "$MISMATCH_DIR/manifest.sha256" \
  '.artifacts.bundle_dir = $bundle_dir
    | .artifacts.bundle_tar = $bundle_tar
    | .artifacts.bundle_tar_sha256_file = $bundle_tar_sha256_file
    | .artifacts.manifest_sha256 = $manifest_sha256' \
  "$SUMMARY_JSON" >"$MISMATCH_EXTERNAL_SUMMARY"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --summary-json "$MISMATCH_EXTERNAL_SUMMARY" >"$TMP_DIR/bundled-summary-mismatch.log" 2>&1
bundled_summary_mismatch_rc=$?
set -e
if [[ "$bundled_summary_mismatch_rc" -eq 0 ]] ||
  ! grep -Eq 'bundled bundle summary status is not pass|external summary does not match bundled summary' "$TMP_DIR/bundled-summary-mismatch.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: mismatched failing bundled summary was not rejected"
  cat "$TMP_DIR/bundled-summary-mismatch.log"
  exit 1
fi

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

WRONG_SHA_NAME="$TMP_DIR/wrong-name.tar.gz.sha256"
printf '%s  %s\n' "$(sha256sum "$BUNDLE_TAR" | awk '{print $1}')" "wrong-bundle-name.tar.gz" >"$WRONG_SHA_NAME"
set +e
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh --bundle-tar "$BUNDLE_TAR" --bundle-tar-sha256-file "$WRONG_SHA_NAME" --check-manifest 0 >"$TMP_DIR/wrong-sha-name.log" 2>&1
wrong_sha_name_rc=$?
set -e
if [[ "$wrong_sha_name_rc" -eq 0 ]] || ! grep -Fq 'bundle tar checksum sidecar filename mismatch' "$TMP_DIR/wrong-sha-name.log"; then
  echo "access bridge pilot evidence bundle verifier integration failed: tar checksum sidecar filename mismatch was not rejected"
  cat "$TMP_DIR/wrong-sha-name.log"
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
