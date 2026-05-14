#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq mktemp rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

FAKE_BIN="$TMP_DIR/fake_bin"
mkdir -p "$FAKE_BIN"

cat >"$FAKE_BIN/go" <<'EOF_GO'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *"cmd/adminsig sign"* ]]; then
  cat <<'JSON'
{"headers":{"X-Admin-Key-Id":"test-key","X-Admin-Timestamp":"2026-05-05T00:00:00Z","X-Admin-Nonce":"nonce","X-Admin-Signature":"sig"}}
JSON
  exit 0
fi
echo "unexpected fake go invocation: $*" >&2
exit 1
EOF_GO

cat >"$FAKE_BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *"/v1/admin/subject/upsert"* ]]; then
  printf '{"subject":"inv-upsert-secret","kind":"client","tier":1}\n'
  exit 0
fi
if [[ "$*" == *"/v1/admin/subject/get"* ]]; then
  printf '{"subject":"inv-upsert-secret","kind":"client","tier":1,"reputation":0.5}\n'
  exit 0
fi
echo "unexpected fake curl invocation: $*" >&2
exit 1
EOF_CURL
chmod +x "$FAKE_BIN/go" "$FAKE_BIN/curl"

KEY_FILE="$TMP_DIR/admin.key"
printf 'fake-key' >"$KEY_FILE"

PATH="$FAKE_BIN:$PATH" \
./scripts/beta_subject_upsert.sh \
  --issuer-url http://127.0.0.1:18082 \
  --admin-key-file "$KEY_FILE" \
  --admin-key-id test-key \
  --subject inv-upsert-secret \
  --kind client \
  --tier 1 >"$TMP_DIR/upsert.log" 2>&1

if grep -F -- "inv-upsert-secret" "$TMP_DIR/upsert.log" >/dev/null; then
  echo "beta subject upsert output leaked subject"
  cat "$TMP_DIR/upsert.log"
  exit 1
fi
if ! rg -q 'subject=\[redacted\]' "$TMP_DIR/upsert.log"; then
  echo "expected redacted status line"
  cat "$TMP_DIR/upsert.log"
  exit 1
fi
if [[ "$(grep -F -c '"subject": "[redacted]"' "$TMP_DIR/upsert.log")" -lt 2 ]]; then
  echo "expected redacted subject in upsert and readback JSON"
  cat "$TMP_DIR/upsert.log"
  exit 1
fi

BATCH_SENTINEL_SUBJECT="batch-upsert-sentinel-secret"
BATCH_CSV="$TMP_DIR/batch.csv"
BATCH_TOKEN_FILE="$TMP_DIR/admin.token"
cat >"$BATCH_CSV" <<EOF_CSV
subject,kind,tier,reputation,bond,stake
$BATCH_SENTINEL_SUBJECT,client,2,0.6,7,11
EOF_CSV
printf 'fake-token' >"$BATCH_TOKEN_FILE"

PATH="$FAKE_BIN:$PATH" \
./scripts/beta_subject_batch_upsert.sh \
  --issuer-url http://127.0.0.1:18082 \
  --admin-token-file "$BATCH_TOKEN_FILE" \
  --csv "$BATCH_CSV" >"$TMP_DIR/batch.log" 2>&1

if grep -F -- "$BATCH_SENTINEL_SUBJECT" "$TMP_DIR/batch.log" >/dev/null; then
  echo "beta subject batch upsert output leaked subject"
  cat "$TMP_DIR/batch.log"
  exit 1
fi
if ! rg -q '\[batch-upsert\] row=2 subject=\[redacted\] kind=client tier=2' "$TMP_DIR/batch.log"; then
  echo "expected redacted batch status line"
  cat "$TMP_DIR/batch.log"
  exit 1
fi
if ! rg -q '\[batch-upsert\] summary total=1 ok=1 failed=0' "$TMP_DIR/batch.log"; then
  echo "expected successful redacted batch summary"
  cat "$TMP_DIR/batch.log"
  exit 1
fi

echo "beta subject upsert redaction integration check ok"
