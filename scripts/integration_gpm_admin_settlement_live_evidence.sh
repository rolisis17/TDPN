#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq go; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "[gpm-admin-settlement-live-evidence] syntax"
bash -n ./scripts/gpm_admin_settlement_live_evidence.sh

echo "[gpm-admin-settlement-live-evidence] fail-closed missing bridge config"
MISSING_SUMMARY="$TMP_DIR/missing_summary.json"
set +e
./scripts/gpm_admin_settlement_live_evidence.sh \
  --reports-dir "$TMP_DIR/missing" \
  --summary-json "$MISSING_SUMMARY" \
  --print-summary-json 0 >"$TMP_DIR/missing.stdout" 2>"$TMP_DIR/missing.stderr"
missing_rc=$?
set -e
if [[ "$missing_rc" -eq 0 ]]; then
  echo "expected missing bridge config run to fail closed"
  cat "$TMP_DIR/missing.stdout"
  cat "$TMP_DIR/missing.stderr"
  exit 1
fi
jq -e '
  .schema.id == "gpm_admin_settlement_live_evidence_summary"
  and .status == "fail"
  and .rc != 0
  and ((.failure.reason // "") | contains("bridge URL is required"))
' "$MISSING_SUMMARY" >/dev/null

echo "[gpm-admin-settlement-live-evidence] local tdpnd evidence path"
LOCAL_SUMMARY="$TMP_DIR/local_summary.json"
LOCAL_REPORT="$TMP_DIR/local_report.md"
./scripts/gpm_admin_settlement_live_evidence.sh \
  --start-local-tdpnd 1 \
  --reports-dir "$TMP_DIR/local" \
  --summary-json "$LOCAL_SUMMARY" \
  --report-md "$LOCAL_REPORT" \
  --run-id integration-admin-settlement-live \
  --print-summary-json 0

jq -e '
  .schema.id == "gpm_admin_settlement_live_evidence_summary"
  and .status == "pass"
  and .rc == 0
  and .inputs.bridge_kind == "local_tdpnd"
  and .signals.bridge_health_ok == true
  and .signals.auth_negative_ok == true
  and .signals.missing_proof_fail_closed_ok == true
  and .signals.reward_proof_registered_ok == true
  and .signals.reward_proof_query_ok == true
  and .signals.reservation_confirmed_ok == true
  and .signals.settlement_confirmed_ok == true
  and .signals.weekly_reward_confirmed_ok == true
  and .signals.slash_hold_fail_closed_ok == true
  and .signals.slash_evidence_mismatch_fail_closed_ok == true
  and .signals.slash_evidence_confirmed_ok == true
  and .signals.penalty_after_confirmation_ok == true
  and .signals.query_by_id_ok == true
  and ((.steps // []) | length) >= 20
' "$LOCAL_SUMMARY" >/dev/null

if [[ ! -s "$LOCAL_REPORT" ]]; then
  echo "expected local evidence markdown report"
  exit 1
fi
grep -F "GPM Admin Settlement Live Evidence" "$LOCAL_REPORT" >/dev/null

echo "[gpm-admin-settlement-live-evidence] easy_node dispatch"
FAKE_SCRIPT="$TMP_DIR/fake_gpm_admin_settlement_live_evidence.sh"
CAPTURE="$TMP_DIR/easy_node_dispatch.txt"
cat >"$FAKE_SCRIPT" <<'FAKE'
#!/usr/bin/env bash
printf '%s\n' "$*" >"${DISPATCH_CAPTURE_FILE:?}"
echo "fake gpm admin settlement live evidence: $*"
FAKE
chmod +x "$FAKE_SCRIPT"
DISPATCH_CAPTURE_FILE="$CAPTURE" \
GPM_ADMIN_SETTLEMENT_LIVE_EVIDENCE_SCRIPT="$FAKE_SCRIPT" \
  ./scripts/easy_node.sh gpm-admin-settlement-live-evidence --sample-arg ok >"$TMP_DIR/easy_node.stdout"
grep -F -- '--sample-arg ok' "$CAPTURE" >/dev/null
grep -F -- 'fake gpm admin settlement live evidence:' "$TMP_DIR/easy_node.stdout" >/dev/null

echo "gpm admin settlement live evidence integration ok"
