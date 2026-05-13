#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash chmod curl go grep jq mktemp sed sha256sum tar wc; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "easy node access recovery local evidence refresh integration failed: missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.tsv"
FAKE_SCRIPT="$TMP_DIR/fake_access_recovery_local_evidence_refresh.sh"
HELP_OUT="$TMP_DIR/help.txt"

cat >"$FAKE_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${ACCESS_RECOVERY_LOCAL_EVIDENCE_REFRESH_CAPTURE_FILE:?}"
{
  printf 'access_recovery_local_evidence_refresh'
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
exit "${FAKE_ACCESS_RECOVERY_LOCAL_EVIDENCE_REFRESH_RC:-0}"
EOF_FAKE
chmod +x "$FAKE_SCRIPT"

./scripts/easy_node.sh help >"$HELP_OUT"
if ! grep -Fq -- './scripts/easy_node.sh access-recovery-local-evidence-refresh' "$HELP_OUT"; then
  echo "easy_node help missing access-recovery-local-evidence-refresh command"
  cat "$HELP_OUT"
  exit 1
fi
if ! ./scripts/easy_node.sh help --expert | grep -Fq -- 'access-recovery-local-evidence-refresh runs a loopback Access Recovery helper rehearsal'; then
  echo "easy_node expert help missing access recovery local evidence refresh note"
  exit 1
fi

: >"$CAPTURE"
ACCESS_RECOVERY_LOCAL_EVIDENCE_REFRESH_SCRIPT="$FAKE_SCRIPT" \
ACCESS_RECOVERY_LOCAL_EVIDENCE_REFRESH_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh access-recovery-local-evidence-refresh \
  --reports-dir .easy-node-logs/access_recovery_local_evidence_demo \
  --port 19822 \
  --write-canonical 1 \
  --refresh-roadmap 1 \
  --summary-json .easy-node-logs/access_recovery_local_evidence_demo/summary.json \
  --print-summary-json 0

if [[ "$(wc -l <"$CAPTURE" | tr -d '[:space:]')" != "1" ]]; then
  echo "expected exactly one forwarded local evidence refresh invocation"
  cat "$CAPTURE"
  exit 1
fi
line="$(sed -n '1p' "$CAPTURE")"
for token in \
  $'\t--reports-dir\t.easy-node-logs/access_recovery_local_evidence_demo' \
  $'\t--port\t19822' \
  $'\t--write-canonical\t1' \
  $'\t--refresh-roadmap\t1' \
  $'\t--summary-json\t.easy-node-logs/access_recovery_local_evidence_demo/summary.json' \
  $'\t--print-summary-json\t0'
do
  if [[ "$line" != *"$token"* ]]; then
    echo "missing forwarded token: $token"
    echo "$line"
    exit 1
  fi
done

set +e
ACCESS_RECOVERY_LOCAL_EVIDENCE_REFRESH_SCRIPT="$FAKE_SCRIPT" \
ACCESS_RECOVERY_LOCAL_EVIDENCE_REFRESH_CAPTURE_FILE="$CAPTURE" \
FAKE_ACCESS_RECOVERY_LOCAL_EVIDENCE_REFRESH_RC=9 \
./scripts/easy_node.sh access-recovery-local-evidence-refresh --sample boom >/dev/null 2>&1
rc=$?
set -e
if [[ "$rc" -ne 9 ]]; then
  echo "expected fake local evidence refresh exit code 9, got $rc"
  exit 1
fi

REAL_REPORTS="$TMP_DIR/real-refresh"
REAL_SUMMARY="$TMP_DIR/real-refresh-summary.json"
REAL_PORT="$((19880 + (RANDOM % 200)))"
bash ./scripts/access_recovery_local_evidence_refresh.sh \
  --reports-dir "$REAL_REPORTS" \
  --port "$REAL_PORT" \
  --refresh-roadmap 1 \
  --summary-json "$REAL_SUMMARY" \
  --print-summary-json 0

if ! jq -e '
  .schema.id == "access_recovery_local_evidence_refresh_summary"
  and .status == "pass"
  and .rc == 0
  and .pilot_handoff_ready == false
  and .evidence_scope == "local_rehearsal"
  and .inputs.write_canonical == false
  and (.inputs.rehearsal_public_host | test("^helper-local[.]gpm-pilot[.]net$"))
  and .roadmap.refreshed == true
  and .roadmap.rc == 0
  and (.artifacts.pilot_verify_summary_json | length > 0)
  and (.artifacts.host_install_summary_json | length > 0)
  and .artifacts.canonical_service_smoke_summary_json == null
  and .artifacts.canonical_deployment_evidence_summary_json == null
  and .artifacts.canonical_host_install_summary_json == null
  and .artifacts.canonical_pilot_summary_json == null
  and .artifacts.canonical_pilot_verify_summary_json == null
  and (.artifacts.roadmap_summary_json | length > 0)
  and .recommended_next_action.id == "real_helper_https_evidence"
  and ((.recommended_next_action.reason // "") | contains("Local evidence is only a rehearsal"))
  and .recommended_next_action.placeholder_unresolved == true
  and .recommended_next_action.safe_to_execute_as_is == false
  and .recommended_next_action.operator_input_required == true
  and ((.recommended_next_action.placeholder_keys // []) | index("HELPER_PUBLIC_DNS") != null)
  and ((.recommended_next_action.placeholder_keys // []) | index("PRIVATE_CODE_FILE") != null)
  and ((.recommended_next_action.placeholder_keys // []) | index("TRUST_STORE") != null)
  and ((.recommended_next_action.placeholder_resolution // "") | contains("Template command only"))
' "$REAL_SUMMARY" >/dev/null; then
  echo "easy node access recovery local evidence refresh integration failed: real local summary contract mismatch"
  cat "$REAL_SUMMARY"
  exit 1
fi
VERIFY_SUMMARY="$(jq -r '.artifacts.pilot_verify_summary_json' "$REAL_SUMMARY")"
if ! jq -e '
  .schema.id == "access_bridge_pilot_evidence_bundle_verify_summary"
  and .schema.minor >= 6
  and .status == "pass"
  and .trusted_provenance.required == false
  and .pilot_handoff_ready == false
  and .handoff_authority == false
  and .authority_level == "integrity_only"
  and .integrity_only == true
  and ((.status_meaning // "") | contains("not pilot handoff authority"))
  and .inputs.summary_json != ""
  and .checks.summary_contract.status == "pass"
' "$VERIFY_SUMMARY" >/dev/null; then
  echo "easy node access recovery local evidence refresh integration failed: local verifier summary mismatch"
  cat "$VERIFY_SUMMARY"
  exit 1
fi
HOST_INSTALL_SUMMARY="$(jq -r '.artifacts.host_install_summary_json' "$REAL_SUMMARY")"
if ! jq -e '
  .schema.id == "access_bridge_host_install_check_summary"
  and .schema.minor >= 4
  and .status == "pass"
  and .observed.expected_public_host == "helper-local.gpm-pilot.net"
  and .summary.checks_total >= 26
  and (([.checks[] | select(.id == "caddy_public_host_matches_expected" and .status == "pass")] | length) == 1)
  and (([.checks[] | select(.id == "nginx_public_host_matches_expected" and .status == "pass")] | length) == 1)
' "$HOST_INSTALL_SUMMARY" >/dev/null; then
  echo "easy node access recovery local evidence refresh integration failed: local host install summary mismatch"
  cat "$HOST_INSTALL_SUMMARY"
  exit 1
fi
ROADMAP_SUMMARY="$(jq -r '.artifacts.roadmap_summary_json' "$REAL_SUMMARY")"
if ! jq -e '
  .access_recovery_track.status == "local-rehearsal-ready"
  and .access_recovery_track.local_rehearsal_ready == true
  and .access_recovery_track.pilot_handoff_ready == false
  and .access_recovery_track.access_bridge_host_install.available == true
  and .access_recovery_track.access_bridge_host_install.status == "pass"
  and .access_recovery_track.access_bridge_host_install.details.checks_total >= 26
  and .access_recovery_track.evidence_host_policy.real_helper_https_evidence == false
' "$ROADMAP_SUMMARY" >/dev/null; then
  echo "easy node access recovery local evidence refresh integration failed: roadmap local rehearsal summary mismatch"
  cat "$ROADMAP_SUMMARY"
  exit 1
fi

PROTECTED_CANONICAL="$TMP_DIR/protected-canonical"
PROTECTED_VERIFY="$PROTECTED_CANONICAL/access_bridge_pilot_evidence_bundle_verify_summary.json"
mkdir -p "$PROTECTED_CANONICAL"
cat >"$PROTECTED_VERIFY" <<'JSON_PROTECTED_VERIFY'
{
  "schema": {
    "id": "access_bridge_pilot_evidence_bundle_verify_summary",
    "major": 1,
    "minor": 5
  },
  "status": "pass",
  "rc": 0,
  "pilot_handoff_ready": true,
  "trusted_pilot_receipt_ready": true,
  "handoff_authority": true,
  "authority_level": "pilot_handoff",
  "integrity_only": false,
  "trusted_provenance": {
    "evidence_scope": "real_helper_https"
  }
}
JSON_PROTECTED_VERIFY
protected_sha_before="$(sha256sum "$PROTECTED_VERIFY" | awk '{print $1}')"
PROTECTED_REPORTS="$TMP_DIR/protected-refresh"
PROTECTED_SUMMARY="$TMP_DIR/protected-refresh-summary.json"
PROTECTED_PORT="$((20120 + (RANDOM % 200)))"
set +e
bash ./scripts/access_recovery_local_evidence_refresh.sh \
  --reports-dir "$PROTECTED_REPORTS" \
  --port "$PROTECTED_PORT" \
  --write-canonical 1 \
  --canonical-dir "$PROTECTED_CANONICAL" \
  --refresh-roadmap 0 \
  --summary-json "$PROTECTED_SUMMARY" \
  --print-summary-json 0 >"$TMP_DIR/protected-refresh.log" 2>&1
protected_rc=$?
set -e
if [[ "$protected_rc" -ne 2 ]]; then
  echo "expected protected canonical verifier overwrite to fail with rc 2, got $protected_rc"
  cat "$TMP_DIR/protected-refresh.log"
  [[ -f "$PROTECTED_SUMMARY" ]] && cat "$PROTECTED_SUMMARY"
  exit 1
fi
if ! grep -Fq -- "would overwrite existing trusted pilot verifier receipt" "$TMP_DIR/protected-refresh.log"; then
  echo "expected protected canonical overwrite diagnostic"
  cat "$TMP_DIR/protected-refresh.log"
  exit 1
fi
protected_sha_after="$(sha256sum "$PROTECTED_VERIFY" | awk '{print $1}')"
if [[ "$protected_sha_after" != "$protected_sha_before" ]]; then
  echo "protected canonical verifier receipt was modified"
  exit 1
fi
if [[ "$(find "$PROTECTED_CANONICAL" -type f | wc -l | tr -d '[:space:]')" != "1" ]]; then
  echo "protected canonical refresh wrote unexpected canonical files"
  find "$PROTECTED_CANONICAL" -type f -print
  exit 1
fi

run_protected_canonical_child_case() {
  local case_name="$1"
  local canonical_dir="$TMP_DIR/protected-canonical-child-$case_name"
  local reports_dir="$TMP_DIR/protected-child-refresh-$case_name"
  local summary_json="$TMP_DIR/protected-child-refresh-$case_name-summary.json"
  local log_file="$TMP_DIR/protected-child-refresh-$case_name.log"
  local protected_file=""
  local protected_port="$((20380 + (RANDOM % 200)))"

  mkdir -p "$canonical_dir"
  case "$case_name" in
    service-smoke)
      protected_file="$canonical_dir/access_bridge_service_smoke_summary.json"
      cat >"$protected_file" <<'JSON_PROTECTED_CHILD'
{
  "version": 1,
  "schema": {"id": "access_bridge_service_smoke_summary", "major": 1, "minor": 6},
  "status": "pass",
  "base_url": "https://helper.gpm-pilot.net",
  "transport": {
    "https": true,
    "tls": {"verified": true, "ssl_verify_result": "0"}
  }
}
JSON_PROTECTED_CHILD
      ;;
    deployment-evidence)
      protected_file="$canonical_dir/access_bridge_deployment_evidence_summary.json"
      cat >"$protected_file" <<'JSON_PROTECTED_CHILD'
{
  "version": 1,
  "schema": {"id": "access_bridge_deployment_evidence_summary", "major": 1, "minor": 5},
  "status": "pass",
  "evidence_scope": "real_helper_https",
  "pilot_handoff_candidate": true
}
JSON_PROTECTED_CHILD
      ;;
    host-install)
      protected_file="$canonical_dir/access_bridge_host_install_check_summary.json"
      cat >"$protected_file" <<'JSON_PROTECTED_CHILD'
{
  "version": 1,
  "schema": {"id": "access_bridge_host_install_check_summary", "major": 1, "minor": 5},
  "status": "pass",
  "inputs": {
    "evidence_mode": "installed-host",
    "installed_host_mode": true
  }
}
JSON_PROTECTED_CHILD
      ;;
    pilot-bundle)
      protected_file="$canonical_dir/access_bridge_pilot_evidence_bundle_summary.json"
      cat >"$protected_file" <<'JSON_PROTECTED_CHILD'
{
  "version": 1,
  "schema": {"id": "access_bridge_pilot_evidence_bundle_summary", "major": 1, "minor": 7},
  "status": "pass",
  "evidence_scope": "real_helper_https",
  "provenance": {"enabled": true}
}
JSON_PROTECTED_CHILD
      ;;
    *)
      echo "unknown protected canonical child case: $case_name"
      exit 1
      ;;
  esac

  protected_sha_before="$(sha256sum "$protected_file" | awk '{print $1}')"
  set +e
  bash ./scripts/access_recovery_local_evidence_refresh.sh \
    --reports-dir "$reports_dir" \
    --port "$protected_port" \
    --write-canonical 1 \
    --canonical-dir "$canonical_dir" \
    --refresh-roadmap 0 \
    --summary-json "$summary_json" \
    --print-summary-json 0 >"$log_file" 2>&1
  protected_child_rc=$?
  set -e
  if [[ "$protected_child_rc" -ne 2 ]]; then
    echo "expected protected canonical child overwrite case $case_name to fail with rc 2, got $protected_child_rc"
    cat "$log_file"
    [[ -f "$summary_json" ]] && cat "$summary_json"
    exit 1
  fi
  if ! grep -Fq -- "would overwrite existing canonical real-helper/installed-host/trusted child evidence" "$log_file"; then
    echo "expected protected canonical child overwrite diagnostic for $case_name"
    cat "$log_file"
    exit 1
  fi
  protected_sha_after="$(sha256sum "$protected_file" | awk '{print $1}')"
  if [[ "$protected_sha_after" != "$protected_sha_before" ]]; then
    echo "protected canonical child evidence was modified for $case_name"
    exit 1
  fi
  if [[ "$(find "$canonical_dir" -type f | wc -l | tr -d '[:space:]')" != "1" ]]; then
    echo "protected canonical child refresh wrote unexpected canonical files for $case_name"
    find "$canonical_dir" -type f -print
    exit 1
  fi
}

run_protected_canonical_child_case service-smoke
run_protected_canonical_child_case deployment-evidence
run_protected_canonical_child_case host-install
run_protected_canonical_child_case pilot-bundle

echo "easy node access recovery local evidence refresh integration check ok"
