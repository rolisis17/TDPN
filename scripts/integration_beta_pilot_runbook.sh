#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 1
  fi
done

TMP_DIR="$(mktemp -d)"
TMP_BIN="$TMP_DIR/bin"
mkdir -p "$TMP_BIN"
trap 'rm -rf "$TMP_DIR"' EXIT

cat >"$TMP_BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
printf '{}\n'
EOF_CURL

FAKE_VALIDATE="$TMP_DIR/fake_validate.sh"
cat >"$FAKE_VALIDATE" <<'EOF_VALIDATE'
#!/usr/bin/env bash
set -euo pipefail
echo "fake validation args=$*"
echo "fake validation ok"
EOF_VALIDATE

FAKE_SOAK="$TMP_DIR/fake_soak.sh"
cat >"$FAKE_SOAK" <<'EOF_SOAK'
#!/usr/bin/env bash
set -euo pipefail
echo "fake soak args=$*"
echo "[3machine-soak] round=1 result=ok"
echo "[3machine-soak] summary passed=1 failed=0 total=1"
EOF_SOAK

chmod +x "$TMP_BIN/curl" "$FAKE_VALIDATE" "$FAKE_SOAK"

BASE_ARGS=(
  --directory-a "http://user:dirpass@dir-a.example:8081/control?secret=dir-a"
  --directory-b "http://user:dirpass@dir-b.example:8081/control?secret=dir-b"
  --issuer-url "http://issuer-user:issuerpass@issuer.example:8082/issuer?token=issuer"
  --entry-url "http://entry-user:entrypass@entry.example:8083/entry?token=entry"
  --exit-url "http://exit-user:exitpass@exit.example:8084/exit?token=exit"
  --rounds 1
  --pause-sec 0
  --min-sources 2
  --min-operators 2
  --require-issuer-quorum 0
  --allow-insecure-remote-http 1
  --client-test-mode local
  --beta-profile 1
  --prod-profile 0
  --record-result 0
  --manual-validation-report 0
)
COMMON_ARGS=("${BASE_ARGS[@]}" --subject "sentinel-invite-secret")

echo "[beta-pilot-runbook] refuses non-empty explicit bundle dir"
COLLISION_BUNDLE="$TMP_DIR/existing_bundle"
mkdir -p "$COLLISION_BUNDLE"
printf 'existing evidence\n' >"$COLLISION_BUNDLE/old.txt"
set +e
PATH="$TMP_BIN:$PATH" \
THREE_MACHINE_VALIDATE_SCRIPT="$FAKE_VALIDATE" \
THREE_MACHINE_SOAK_SCRIPT="$FAKE_SOAK" \
./scripts/beta_pilot_runbook.sh "${COMMON_ARGS[@]}" --bundle-dir "$COLLISION_BUNDLE" >"$TMP_DIR/collision.log" 2>&1
collision_rc=$?
set -e
if [[ "$collision_rc" -eq 0 ]]; then
  echo "expected non-empty bundle dir refusal"
  cat "$TMP_DIR/collision.log"
  exit 1
fi
if ! rg -q 'refused non-empty bundle dir' "$TMP_DIR/collision.log"; then
  echo "missing non-empty bundle dir refusal message"
  cat "$TMP_DIR/collision.log"
  exit 1
fi

echo "[beta-pilot-runbook] redacts invite and URL secrets in bundle metadata"
BUNDLE_DIR="$TMP_DIR/pilot_bundle"
PATH="$TMP_BIN:$PATH" \
THREE_MACHINE_VALIDATE_SCRIPT="$FAKE_VALIDATE" \
THREE_MACHINE_SOAK_SCRIPT="$FAKE_SOAK" \
./scripts/beta_pilot_runbook.sh "${COMMON_ARGS[@]}" --bundle-dir "$BUNDLE_DIR" >"$TMP_DIR/run.log" 2>&1

for file in "$BUNDLE_DIR/runbook.log" "$BUNDLE_DIR/metadata.txt" "$BUNDLE_DIR/validate.log" "$BUNDLE_DIR/soak.log"; do
  if rg -q 'sentinel-invite-secret|dirpass|issuerpass|entrypass|exitpass|secret=|token=' "$file"; then
    echo "pilot bundle leaked sensitive input in $file"
    cat "$file"
    exit 1
  fi
done
if ! rg -q '^subject=\[redacted\]$' "$BUNDLE_DIR/metadata.txt"; then
  echo "pilot metadata missing redacted subject marker"
  cat "$BUNDLE_DIR/metadata.txt"
  exit 1
fi
if ! rg -q 'directory_a=http://\[redacted\]@dir-a.example:8081/control' "$BUNDLE_DIR/metadata.txt"; then
  echo "pilot metadata missing redacted URL userinfo"
  cat "$BUNDLE_DIR/metadata.txt"
  exit 1
fi
if [[ ! -f "${BUNDLE_DIR}.tar.gz" ]]; then
  echo "pilot runbook did not create tar bundle"
  exit 1
fi
EXTRACT_DIR="$TMP_DIR/extracted_subject_bundle"
mkdir -p "$EXTRACT_DIR"
tar -xzf "${BUNDLE_DIR}.tar.gz" -C "$EXTRACT_DIR"
if rg -q 'sentinel-invite-secret|dirpass|issuerpass|entrypass|exitpass|secret=|token=' "$EXTRACT_DIR"; then
  echo "pilot tar bundle leaked sensitive input"
  rg -n 'sentinel-invite-secret|dirpass|issuerpass|entrypass|exitpass|secret=|token=' "$EXTRACT_DIR" || true
  exit 1
fi

echo "[beta-pilot-runbook] redacts anon credential in bundled helper output"
ANON_BUNDLE_DIR="$TMP_DIR/pilot_anon_bundle"
PATH="$TMP_BIN:$PATH" \
THREE_MACHINE_VALIDATE_SCRIPT="$FAKE_VALIDATE" \
THREE_MACHINE_SOAK_SCRIPT="$FAKE_SOAK" \
./scripts/beta_pilot_runbook.sh "${BASE_ARGS[@]}" --anon-cred "sentinel-anon-credential-secret" --bundle-dir "$ANON_BUNDLE_DIR" >"$TMP_DIR/anon_run.log" 2>&1

for file in "$ANON_BUNDLE_DIR/runbook.log" "$ANON_BUNDLE_DIR/metadata.txt" "$ANON_BUNDLE_DIR/validate.log" "$ANON_BUNDLE_DIR/soak.log"; do
  if rg -q 'sentinel-anon-credential-secret|dirpass|issuerpass|entrypass|exitpass|secret=|token=' "$file"; then
    echo "pilot anon bundle leaked sensitive input in $file"
    cat "$file"
    exit 1
  fi
done

echo "beta pilot runbook integration check ok"
