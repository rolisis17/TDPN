#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

for cmd in go rg timeout sed curl; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

umask 077
TMP_DIR="$(mktemp -d)"
LOG_FILE="$TMP_DIR/integration_client_3hop_runtime.log"
MIDDLE_OBSERVED_FILE="$TMP_DIR/middle_observed"
MIDDLE_READY_FILE="$TMP_DIR/middle_ready"
MIDDLE_ENDPOINT="127.0.0.1:52830"
EXIT_DATA_ENDPOINT="127.0.0.1:51821"
rm -f "$LOG_FILE"
rm -f "$MIDDLE_OBSERVED_FILE"
rm -f "$MIDDLE_READY_FILE"

cleanup() {
  if [[ -n "${node_pid:-}" ]]; then
    kill "$node_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "${middle_pid:-}" ]]; then
    kill "$middle_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}

wait_for_http_ready() {
  local url="$1"
  local label="$2"
  local deadline=$((SECONDS + 15))
  while ((SECONDS < deadline)); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  echo "timed out waiting for ${label} (${url})"
  cat "$LOG_FILE"
  return 1
}

redact_token_json() {
  local payload="$1"
  printf '%s\n' "$payload" | sed -E \
    -e 's/"token":"[^"]*"/"token":"[redacted]"/g' \
    -e 's/"private_key":"[^"]*"/"private_key":"[redacted]"/g'
}

write_sign_provider_upsert_proof_tool() {
  cat >"$TMP_DIR/sign_provider_upsert_proof.go" <<'GO'
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	privateKey := flag.String("private-key", "", "base64url-encoded ed25519 private key")
	tokenID := flag.String("token-id", "", "provider token id")
	subject := flag.String("subject", "", "provider operator subject")
	relayID := flag.String("relay-id", "", "relay id")
	role := flag.String("role", "", "relay role")
	pubKey := flag.String("pub-key", "", "relay pub key")
	endpoint := flag.String("endpoint", "", "relay endpoint")
	controlURL := flag.String("control-url", "", "relay control url")
	nonce := flag.String("nonce", "", "proof nonce")
	flag.Parse()
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(*privateKey))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		exitf("invalid private key")
	}
	normalizedRole := strings.TrimSpace(strings.ToLower(*role))
	switch normalizedRole {
	case "micro_relay", "middle", "relay", "transit", "three-hop-middle":
		normalizedRole = "micro-relay"
	}
	payload := struct {
		Context    string `json:"context"`
		TokenID    string `json:"token_id"`
		Subject    string `json:"subject"`
		RelayID    string `json:"relay_id"`
		Role       string `json:"role"`
		PubKey     string `json:"pub_key"`
		Endpoint   string `json:"endpoint"`
		ControlURL string `json:"control_url"`
		Nonce      string `json:"nonce"`
	}{
		Context:    "provider_relay_upsert_v1",
		TokenID:    strings.TrimSpace(*tokenID),
		Subject:    strings.ToLower(strings.TrimSpace(*subject)),
		RelayID:    strings.TrimSpace(*relayID),
		Role:       normalizedRole,
		PubKey:     strings.TrimSpace(*pubKey),
		Endpoint:   strings.TrimSpace(*endpoint),
		ControlURL: strings.TrimSpace(*controlURL),
		Nonce:      strings.TrimSpace(*nonce),
	}
	msg, err := json.Marshal(payload)
	if err != nil {
		exitf("marshal proof payload: %v", err)
	}
	sig := ed25519.Sign(ed25519.PrivateKey(raw), msg)
	fmt.Println(base64.RawURLEncoding.EncodeToString(sig))
}

func exitf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
GO
}

start_middle() {
  local endpoint="$1"
  local entry_endpoint="$2"
  local exit_endpoint="$3"
  MIDDLE_ADDR=127.0.0.1:9285 \
  MIDDLE_DATA_ADDR="$endpoint" \
  MIDDLE_ENTRY_DATA_ADDR="$entry_endpoint" \
  MIDDLE_EXIT_DATA_ADDR="$exit_endpoint" \
  MIDDLE_OBSERVED_FILE="$MIDDLE_OBSERVED_FILE" \
  MIDDLE_READY_FILE="$MIDDLE_READY_FILE" \
  go run ./cmd/node --middle >>"$LOG_FILE" 2>&1 &
  middle_pid=$!
  local deadline=$((SECONDS + 15))
  while ((SECONDS < deadline)); do
    if [[ -s "$MIDDLE_READY_FILE" ]]; then
      return 0
    fi
    if ! kill -0 "$middle_pid" >/dev/null 2>&1; then
      echo "middle relay exited before becoming ready"
      cat "$LOG_FILE"
      return 1
    fi
    sleep 0.2
  done
  echo "timed out waiting for middle relay readiness"
  cat "$LOG_FILE"
  return 1
}

seed_middle_relay() {
  wait_for_http_ready "http://127.0.0.1:8081/v1/health" "directory health"
  wait_for_http_ready "http://127.0.0.1:8082/v1/health" "issuer health"

  local provider_operator="provider-op-middle"
  local relay_id="middle-provider-3hop"
  local endpoint="$MIDDLE_ENDPOINT"
  local control_url="http://127.0.0.1:9285"
  local nonce="integration-client-3hop-middle-$(date +%s)"

  local key_json relay_pub relay_priv token_json token token_id proof upsert_payload upsert_resp relays_json
  key_json="$(go run ./cmd/tokenpop gen --show-private-key)"
  relay_pub="$(echo "$key_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
  relay_priv="$(echo "$key_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
  if [[ -z "$relay_pub" || -z "$relay_priv" ]]; then
    echo "failed to generate middle relay key material"
    redact_token_json "$key_json"
    return 1
  fi

  token_json="$(curl -fsS -X POST http://127.0.0.1:8082/v1/sponsor/token \
    -H 'Content-Type: application/json' \
    -H 'X-Sponsor-Token: integration-client-3hop-sponsor-token' \
    --data "{\"tier\":2,\"subject\":\"$provider_operator\",\"token_type\":\"provider_role\",\"pop_pub_key\":\"$relay_pub\"}")"
  token="$(echo "$token_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
  token_id="$(echo "$token_json" | sed -n 's/.*"jti":"\([^"]*\)".*/\1/p')"
  if [[ -z "$token" || -z "$token_id" ]]; then
    echo "failed to issue provider token for middle relay"
    redact_token_json "$token_json"
    return 1
  fi

  write_sign_provider_upsert_proof_tool
  proof="$(go run "$TMP_DIR/sign_provider_upsert_proof.go" \
    --private-key "$relay_priv" \
    --token-id "$token_id" \
    --subject "$provider_operator" \
    --relay-id "$relay_id" \
    --role micro-relay \
    --pub-key "$relay_pub" \
    --endpoint "$endpoint" \
    --control-url "$control_url" \
    --nonce "$nonce")"
  if [[ -z "$proof" ]]; then
    echo "failed to sign provider relay upsert proof"
    return 1
  fi

  upsert_payload=$(cat <<JSON
{"relay_id":"$relay_id","role":"micro-relay","pub_key":"$relay_pub","endpoint":"$endpoint","control_url":"$control_url","country_code":"ZZ","geo_confidence":1,"region":"local","capabilities":["wg"],"hop_roles":["middle"],"reputation_score":0.82,"uptime_score":0.91,"capacity_score":0.84,"abuse_penalty":0.10,"bond_score":0.60,"stake_score":0.55,"valid_for_sec":120,"token_proof":"$proof","token_proof_nonce":"$nonce"}
JSON
)

  upsert_resp="$(curl -fsS -X POST http://127.0.0.1:8081/v1/provider/relay/upsert \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $token" \
    --data "$upsert_payload")"
  if ! echo "$upsert_resp" | rg -q '"accepted":true'; then
    echo "expected provider micro-relay upsert to be accepted"
    redact_token_json "$upsert_resp"
    return 1
  fi

  relays_json="$(curl -fsS http://127.0.0.1:8081/v1/relays)"
  if ! echo "$relays_json" | rg -q "\"relay_id\":\"$relay_id\""; then
    echo "expected seeded micro-relay to be advertised by directory"
    echo "$relays_json"
    return 1
  fi
}

CLIENT_PATH_PROFILE=3hop \
CLIENT_BOOTSTRAP_INTERVAL_SEC=1 \
CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC=1 \
CLIENT_BOOTSTRAP_JITTER_PCT=0 \
CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC=5 \
ISSUER_SPONSOR_API_TOKEN=integration-client-3hop-sponsor-token \
DIRECTORY_PROVIDER_ISSUER_URLS=http://127.0.0.1:8082 \
DIRECTORY_ISSUER_TRUST_URLS=http://127.0.0.1:8082 \
DIRECTORY_TRUST_STRICT=0 \
ENTRY_DIRECTORY_TRUST_STRICT=0 \
DIRECTORY_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS=1 \
CLIENT_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS=1 \
ENTRY_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS=1 \
EXIT_ALLOW_DANGEROUS_OUTBOUND_PRIVATE_DNS=1 \
ENTRY_RELAY_ID=entry-local-1 \
EXIT_RELAY_ID=exit-local-1 \
ENTRY_DATA_ADDR=127.0.0.1:51820 \
EXIT_DATA_ADDR="$EXIT_DATA_ENDPOINT" \
timeout 40s go run ./cmd/node --directory --issuer --entry --exit --client >"$LOG_FILE" 2>&1 &
node_pid=$!
trap cleanup EXIT

start_middle "$MIDDLE_ENDPOINT" "127.0.0.1:51820" "$EXIT_DATA_ENDPOINT"

startup_ok=0
for _ in $(seq 1 200); do
  if rg -q "client role enabled: .*path_profile=3hop.*middle_pref=true.*middle_required=true" "$LOG_FILE"; then
    startup_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$startup_ok" -ne 1 ]]; then
  echo "expected 3hop runtime config signal in client startup log"
  cat "$LOG_FILE"
  exit 1
fi

if ! seed_middle_relay; then
  echo "failed to seed advertised provider micro-relay before client bootstrap"
  cat "$LOG_FILE"
  exit 1
fi

selected_with_middle=0
for _ in $(seq 1 200); do
  if rg -q "client selected entry=.* middle=[^ ]+" "$LOG_FILE"; then
    selected_with_middle=1
    break
  fi
  sleep 0.2
done

if [[ "$selected_with_middle" -eq 1 ]]; then
  selected_line="$(rg -N "client selected entry=.* middle=[^ ]+" "$LOG_FILE" | tail -n1)"
  middle_relay="$(echo "$selected_line" | sed -E 's/.* middle=([^ ]+) .*/\1/')"
  if [[ -z "$middle_relay" || "$middle_relay" == "none" ]]; then
    echo "expected selected 3hop path to include non-empty middle relay"
    echo "$selected_line"
    cat "$LOG_FILE"
    exit 1
  fi
  middle_observed=0
  for _ in $(seq 1 100); do
    if [[ -s "$MIDDLE_OBSERVED_FILE" ]]; then
      middle_observed=1
      break
    fi
    sleep 0.2
  done
  if [[ "$middle_observed" -ne 1 ]] || ! rg -q "entry_to_exit=[1-9]" "$MIDDLE_OBSERVED_FILE"; then
    echo "expected advertised middle relay to forward routed UDP traffic toward exit"
    echo "$selected_line"
    [[ -f "$MIDDLE_OBSERVED_FILE" ]] && cat "$MIDDLE_OBSERVED_FILE"
    cat "$LOG_FILE"
    exit 1
  fi
  if ! rg -q "exit accepted (opaque )?packet session=" "$LOG_FILE"; then
    echo "expected exit to accept packet forwarded through middle relay"
    echo "$selected_line"
    cat "$MIDDLE_OBSERVED_FILE"
    cat "$LOG_FILE"
    exit 1
  fi
  middle_observed_summary="$(cat "$MIDDLE_OBSERVED_FILE")"
  echo "client 3hop runtime integration check ok (selected-middle=${middle_relay}; ${middle_observed_summary})"
  exit 0
fi

echo "expected seeded provider micro-relay to produce a middle-hop selection"
cat "$LOG_FILE"
exit 1
