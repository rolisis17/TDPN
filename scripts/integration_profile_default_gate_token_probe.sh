#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

CAPTURE_FILE="$TMP_DIR/capture.log"
FAKE_SCRIPT="$TMP_DIR/fake_profile_default_gate_token_probe.sh"

cat >"$FAKE_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf 'profile-default-gate-token-probe %s\n' "$*" >>"${PROBE_CAPTURE_FILE:?}"
EOF_FAKE
chmod +x "$FAKE_SCRIPT"

PROBE_CAPTURE_FILE="$CAPTURE_FILE" \
PROFILE_DEFAULT_GATE_TOKEN_PROBE_SCRIPT="$FAKE_SCRIPT" \
./scripts/easy_node.sh profile-default-gate-token-probe \
  --directory-url http://100.113.245.61:8081 \
  --issuer-url http://100.113.245.61:8082 \
  --exit-url http://100.113.245.61:8084 \
  --campaign-subject inv-test \
  --reports-dir .easy-node-logs \
  --print-summary-json 1 \
  --show-json 0

line="$(rg '^profile-default-gate-token-probe ' "$CAPTURE_FILE" | tail -n 1 || true)"
if [[ -z "$line" ]]; then
  echo "missing easy_node forwarding capture for profile-default-gate-token-probe"
  cat "$CAPTURE_FILE"
  exit 1
fi

for expected in \
  '--directory-url http://100.113.245.61:8081' \
  '--issuer-url http://100.113.245.61:8082' \
  '--exit-url http://100.113.245.61:8084' \
  '--campaign-subject inv-test' \
  '--reports-dir .easy-node-logs' \
  '--print-summary-json 1' \
  '--show-json 0'; do
  if ! grep -F -- "$expected" <<<"$line" >/dev/null; then
    echo "easy_node forwarding missing $expected"
    cat "$CAPTURE_FILE"
    exit 1
  fi
done

REAL_SUMMARY="$TMP_DIR/profile_default_gate_token_probe_summary.json"
FAKE_BIN="$TMP_DIR/fake_bin"
mkdir -p "$FAKE_BIN"
cat >"$FAKE_BIN/go" <<'EOF_GO'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *"cmd/tokenpop gen"* ]]; then
  printf '{"private_key":"priv-test","public_key":"pub-test"}\n'
  exit 0
fi
if [[ "$*" == *"cmd/tokenpop sign"* ]]; then
  printf '{"proof":"proof-test"}\n'
  exit 0
fi
echo "unexpected fake go invocation: $*" >&2
exit 1
EOF_GO
cat >"$FAKE_BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
out_file=""
write_code=""
args=("$@")
idx=0
while (( idx < ${#args[@]} )); do
  case "${args[$idx]}" in
    -o|--output)
      out_file="${args[$((idx + 1))]:-}"
      idx=$((idx + 2))
      ;;
    -w)
      write_code="${args[$((idx + 1))]:-}"
      idx=$((idx + 2))
      ;;
    *)
      idx=$((idx + 1))
      ;;
  esac
done
last_arg="${args[$((${#args[@]} - 1))]}"
if [[ "$last_arg" == */v1/relays ]]; then
  cat <<'JSON'
{"relays":[{"role":"exit","relay_id":"exit-a","region":"test"}]}
JSON
  exit 0
fi
if [[ "$*" == *"/v1/token"* ]]; then
  printf '{"token":"e30.sig"}\n' >"$out_file"
  [[ -n "$write_code" ]] && printf '200'
  exit 0
fi
if [[ "$*" == *"/v1/path/open"* ]]; then
  printf '{"reason":"missing session_id"}\n' >"$out_file"
  [[ -n "$write_code" ]] && printf '200'
  exit 0
fi
echo "unexpected fake curl invocation: $*" >&2
exit 1
EOF_CURL
chmod +x "$FAKE_BIN/go" "$FAKE_BIN/curl"

PATH="$FAKE_BIN:$PATH" \
./scripts/profile_default_gate_token_probe.sh \
  --directory-url 'https://user:pw-secret@dir-a.example:8081?token=dir-secret' \
  --issuer-url 'https://user:pw-secret@issuer-a.example:8082?token=issuer-secret' \
  --exit-url 'https://user:pw-secret@exit-a.example:8084?token=exit-secret' \
  --campaign-subject 'inv-token-probe-secret-subject' \
  --reports-dir "$TMP_DIR/reports" \
  --summary-json "$REAL_SUMMARY" \
  --print-summary-json 1 \
  --show-json 1 >"$TMP_DIR/profile_default_gate_token_probe_real.log" 2>&1

for forbidden in 'pw-secret' 'token=' 'inv-token-probe-secret-subject'; do
  if grep -F -- "$forbidden" "$REAL_SUMMARY" "$TMP_DIR/profile_default_gate_token_probe_real.log" >/dev/null; then
    echo "profile default gate token probe leaked forbidden value: $forbidden"
    cat "$REAL_SUMMARY"
    cat "$TMP_DIR/profile_default_gate_token_probe_real.log"
    exit 1
  fi
done
if ! jq -e '
  .status == "pass"
  and .inputs.directory_url == "https://dir-a.example:8081"
  and .inputs.issuer_url == "https://issuer-a.example:8082"
  and .inputs.exit_url == "https://exit-a.example:8084"
  and .inputs.campaign_subject == "[redacted]"
' "$REAL_SUMMARY" >/dev/null; then
  echo "token probe summary missing expected redacted inputs"
  cat "$REAL_SUMMARY"
  exit 1
fi

echo "profile default gate token probe integration ok"
