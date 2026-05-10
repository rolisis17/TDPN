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
  --write-canonical 0 \
  --refresh-roadmap 0 \
  --summary-json "$REAL_SUMMARY" \
  --print-summary-json 0

if ! jq -e '
  .schema.id == "access_recovery_local_evidence_refresh_summary"
  and .status == "pass"
  and .rc == 0
  and .pilot_handoff_ready == false
  and .evidence_scope == "local_rehearsal"
  and .roadmap.refreshed == false
  and .recommended_next_action.id == "real_helper_https_evidence"
  and ((.recommended_next_action.reason // "") | contains("Local evidence is only a rehearsal"))
' "$REAL_SUMMARY" >/dev/null; then
  echo "easy node access recovery local evidence refresh integration failed: real local summary contract mismatch"
  cat "$REAL_SUMMARY"
  exit 1
fi

echo "easy node access recovery local evidence refresh integration check ok"
