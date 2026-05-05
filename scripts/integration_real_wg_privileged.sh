#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "this script requires Linux (wireguard kernel interface support)"
  exit 2
fi
if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root: sudo ./scripts/integration_real_wg_privileged.sh"
  exit 2
fi
for cmd in go wg ip curl rg perl timeout; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

CLIENT_IFACE="${CLIENT_IFACE:-wgcint0}"
EXIT_IFACE="${EXIT_IFACE:-wgeint0}"
DIRECTORY_ADDR="${DIRECTORY_ADDR:-127.0.0.1:18081}"
ISSUER_ADDR="${ISSUER_ADDR:-127.0.0.1:18082}"
ENTRY_ADDR="${ENTRY_ADDR:-127.0.0.1:18083}"
EXIT_ADDR="${EXIT_ADDR:-127.0.0.1:18084}"
CLIENT_PROXY_ADDR="${CLIENT_PROXY_ADDR:-127.0.0.1:57960}"
ENTRY_DATA_ADDR="${ENTRY_DATA_ADDR:-127.0.0.1:51980}"
EXIT_DATA_ADDR="${EXIT_DATA_ADDR:-127.0.0.1:51981}"
EXIT_WG_PORT="${EXIT_WG_PORT:-51982}"
SCRIPT_TIMEOUT_SEC="${SCRIPT_TIMEOUT_SEC:-120}"
CLIENT_OPAQUE_SESSION_SEC="${CLIENT_OPAQUE_SESSION_SEC:-30}"
CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS="${CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS:-12000}"
CLIENT_BOOTSTRAP_INTERVAL_SEC="${CLIENT_BOOTSTRAP_INTERVAL_SEC:-1}"
CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC="${CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC:-2}"
CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC="${CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC:-1}"
CLIENT_BOOTSTRAP_JITTER_PCT="${CLIENT_BOOTSTRAP_JITTER_PCT:-0}"
CLIENT_STARTUP_SYNC_TIMEOUT_SEC="${CLIENT_STARTUP_SYNC_TIMEOUT_SEC:-0}"
STRICT_BETA_PROFILE="${STRICT_BETA_PROFILE:-0}"
CLIENT_INNER_SOURCE="${CLIENT_INNER_SOURCE:-udp}"
CLIENT_BETA_STRICT="${CLIENT_BETA_STRICT:-0}"
ENTRY_BETA_STRICT="${ENTRY_BETA_STRICT:-0}"
EXIT_BETA_STRICT="${EXIT_BETA_STRICT:-0}"
CLIENT_REQUIRE_DISTINCT_OPERATORS="${CLIENT_REQUIRE_DISTINCT_OPERATORS:-0}"
ENTRY_OPERATOR_ID="${ENTRY_OPERATOR_ID:-op-main}"
EXIT_OPERATOR_ID="${EXIT_OPERATOR_ID:-op-main}"
CLIENT_DISABLE_SYNTHETIC_FALLBACK="${CLIENT_DISABLE_SYNTHETIC_FALLBACK:-1}"
CLIENT_LIVE_WG_MODE="${CLIENT_LIVE_WG_MODE:-0}"
DIRECTORY_TRUST_STRICT="${DIRECTORY_TRUST_STRICT:-0}"
ENTRY_LIVE_WG_MODE="${ENTRY_LIVE_WG_MODE:-0}"
ENTRY_DIRECTORY_TRUST_STRICT="${ENTRY_DIRECTORY_TRUST_STRICT:-0}"
ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR="${ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR:-0}"
ENTRY_REQUIRE_MIDDLE_RELAY="${ENTRY_REQUIRE_MIDDLE_RELAY:-0}"
EXIT_LIVE_WG_MODE="${EXIT_LIVE_WG_MODE:-0}"
EXIT_TOKEN_PROOF_REPLAY_GUARD="${EXIT_TOKEN_PROOF_REPLAY_GUARD:-0}"
EXIT_PEER_REBIND_SEC="${EXIT_PEER_REBIND_SEC:-0}"
EXIT_STARTUP_SYNC_TIMEOUT_SEC="${EXIT_STARTUP_SYNC_TIMEOUT_SEC:-0}"
EXIT_OPAQUE_SINK_ADDR="${EXIT_OPAQUE_SINK_ADDR:-}"
EXIT_OPAQUE_SOURCE_ADDR="${EXIT_OPAQUE_SOURCE_ADDR:-}"
CLIENT_PATH_PROFILE="${CLIENT_PATH_PROFILE:-}"
ENTRY_DIRECTORY_TRUST_TOFU="${ENTRY_DIRECTORY_TRUST_TOFU:-}"
EXIT_EGRESS_BACKEND="${EXIT_EGRESS_BACKEND:-}"
MIDDLE_ADDR="${MIDDLE_ADDR:-}"
MIDDLE_DATA_ADDR="${MIDDLE_DATA_ADDR:-}"
MIDDLE_RELAY_ID="${MIDDLE_RELAY_ID:-middle-local-1}"
MIDDLE_OPERATOR_ID="${MIDDLE_OPERATOR_ID:-op-middle}"
ENTRY_PUZZLE_SECRET="${ENTRY_PUZZLE_SECRET:-integration-entry-secret-0001}"
ENTRY_PUZZLE_DIFFICULTY="${ENTRY_PUZZLE_DIFFICULTY:-1}"
LOG_FILE="${LOG_FILE:-/tmp/integration_real_wg_privileged.log}"
KEY_DIR="$(mktemp -d)"
CLIENT_KEY_FILE="$KEY_DIR/client.key"
EXIT_KEY_FILE="$KEY_DIR/exit.key"
DIRECTORY_KEY_FILE="$KEY_DIR/directory_ed25519.key"
DIRECTORY_PUB_FILE="$DIRECTORY_KEY_FILE.pub"
ISSUER_KEY_FILE="$KEY_DIR/issuer_ed25519.key"
ISSUER_PUB_FILE="$ISSUER_KEY_FILE.pub"
ENTRY_ROUTE_ASSERTION_KEY_FILE="$KEY_DIR/entry_route_assertion.key"
ENTRY_ROUTE_ASSERTION_PUB_FILE="$ENTRY_ROUTE_ASSERTION_KEY_FILE.pub"
MIDDLE_READY_FILE="$KEY_DIR/middle_ready"
DIRECTORY_TRUSTED_KEYS_FILE="${DIRECTORY_TRUSTED_KEYS_FILE:-$KEY_DIR/directory_trusted_keys.txt}"

DIRECTORY_URL="http://${DIRECTORY_ADDR}"
ISSUER_URL="http://${ISSUER_ADDR}"
ENTRY_URL="http://${ENTRY_ADDR}"
EXIT_CONTROL_URL="http://${EXIT_ADDR}"

if [[ "$STRICT_BETA_PROFILE" == "1" ]]; then
  CLIENT_BETA_STRICT=1
  ENTRY_BETA_STRICT=0
  EXIT_BETA_STRICT=1
  CLIENT_REQUIRE_DISTINCT_OPERATORS=1
  CLIENT_DISABLE_SYNTHETIC_FALLBACK=1
  CLIENT_LIVE_WG_MODE=1
  DIRECTORY_TRUST_STRICT=1
  ENTRY_LIVE_WG_MODE=1
  ENTRY_DIRECTORY_TRUST_STRICT=1
  ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR=1
  ENTRY_REQUIRE_MIDDLE_RELAY=1
  ENTRY_OPERATOR_ID=op-entry
  EXIT_OPERATOR_ID=op-exit
  EXIT_LIVE_WG_MODE=1
  EXIT_TOKEN_PROOF_REPLAY_GUARD=1
  EXIT_PEER_REBIND_SEC=0
  if [[ "$CLIENT_STARTUP_SYNC_TIMEOUT_SEC" == "0" ]]; then
    CLIENT_STARTUP_SYNC_TIMEOUT_SEC=8
  fi
  if [[ "$EXIT_STARTUP_SYNC_TIMEOUT_SEC" == "0" ]]; then
    EXIT_STARTUP_SYNC_TIMEOUT_SEC=8
  fi
  CLIENT_INNER_SOURCE=udp
  if [[ -z "$EXIT_OPAQUE_SINK_ADDR" ]]; then
    EXIT_OPAQUE_SINK_ADDR="127.0.0.1:$((EXIT_WG_PORT + 100))"
  fi
  if [[ -z "$EXIT_OPAQUE_SOURCE_ADDR" ]]; then
    EXIT_OPAQUE_SOURCE_ADDR="127.0.0.1:$((EXIT_WG_PORT + 101))"
  fi
  DIRECTORY_TRUST_TOFU=0
  ENTRY_DIRECTORY_TRUST_TOFU=0
  EXIT_EGRESS_BACKEND="${EXIT_EGRESS_BACKEND:-command}"
  if [[ -z "$CLIENT_PATH_PROFILE" ]]; then
    CLIENT_PATH_PROFILE=3hop
  fi
  if [[ "$CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC" =~ ^[0-9]+$ ]] && ((CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC < 15)); then
    CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC=15
  fi
fi

addr_port() {
  local addr="$1"
  local fallback_port="${2:-}"
  local port
  if [[ "$addr" == *:* ]]; then
    port="${addr##*:}"
  else
    port="$fallback_port"
  fi
  if [[ -z "$port" || ! "$port" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  echo "$port"
}

if [[ -z "$MIDDLE_ADDR" ]]; then
  MIDDLE_ADDR="127.0.0.1:$(( $(addr_port "$DIRECTORY_ADDR") + 4 ))"
fi
if [[ -z "$MIDDLE_DATA_ADDR" ]]; then
  MIDDLE_DATA_ADDR="127.0.0.1:$(( $(addr_port "$EXIT_WG_PORT" "$EXIT_WG_PORT") + 1 ))"
fi

assert_port_free() {
  local proto="$1"
  local port="$2"
  local label="$3"
  if ! command -v ss >/dev/null 2>&1; then
    return 0
  fi
  local ss_args
  if [[ "$proto" == "tcp" ]]; then
    ss_args="-H -ltn"
  else
    ss_args="-H -lun"
  fi
  local matches
  matches="$(ss $ss_args | awk -v p=":$port" '$5 ~ p"$" || $5 ~ p"[^0-9]" { print }')"
  if [[ -n "$matches" ]]; then
    echo "preflight failed: ${label} port ${port}/${proto} already in use"
    echo "$matches"
    exit 1
  fi
}

wait_for_http_ready() {
  local url="$1"
  local label="$2"
  local deadline=$((SECONDS + 20))
  while ((SECONDS < deadline)); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  echo "timed out waiting for ${label} (${url})"
  return 1
}

write_sign_provider_upsert_proof_tool() {
  cat >"$KEY_DIR/sign_provider_upsert_proof.go" <<'GO'
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
	fmt.Println(base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(raw), msg)))
}

func exitf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
GO
}

seed_middle_relay() {
  wait_for_http_ready "${DIRECTORY_URL}/v1/health" "directory health" || return 1
  wait_for_http_ready "${ISSUER_URL}/v1/health" "issuer health" || return 1

  local nonce key_json relay_pub relay_priv token_json token token_id proof upsert_payload upsert_resp relays_json
  nonce="integration-real-wg-middle-$(date +%s)"
  key_json="$(GPM_ALLOW_STDOUT_PRIVATE_KEYS=1 go run ./cmd/tokenpop gen --show-private-key)"
  relay_pub="$(echo "$key_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')"
  relay_priv="$(echo "$key_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')"
  if [[ -z "$relay_pub" || -z "$relay_priv" ]]; then
    echo "failed to generate middle relay provider key material"
    return 1
  fi

  token_json="$(curl -fsS -X POST "${ISSUER_URL}/v1/sponsor/token" \
    -H 'Content-Type: application/json' \
    -H 'X-Sponsor-Token: integration-real-wg-sponsor-token' \
    --data "{\"tier\":2,\"subject\":\"$MIDDLE_OPERATOR_ID\",\"token_type\":\"provider_role\",\"pop_pub_key\":\"$relay_pub\"}")"
  token="$(echo "$token_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
  token_id="$(echo "$token_json" | sed -n 's/.*"jti":"\([^"]*\)".*/\1/p')"
  if [[ -z "$token" || -z "$token_id" ]]; then
    echo "failed to issue provider token for middle relay"
    return 1
  fi

  write_sign_provider_upsert_proof_tool
  proof="$(go run "$KEY_DIR/sign_provider_upsert_proof.go" \
    --private-key "$relay_priv" \
    --token-id "$token_id" \
    --subject "$MIDDLE_OPERATOR_ID" \
    --relay-id "$MIDDLE_RELAY_ID" \
    --role micro-relay \
    --pub-key "$relay_pub" \
    --endpoint "$MIDDLE_DATA_ADDR" \
    --control-url "http://$MIDDLE_ADDR" \
    --nonce "$nonce")"
  if [[ -z "$proof" ]]; then
    echo "failed to sign provider relay upsert proof"
    return 1
  fi

  upsert_payload=$(cat <<JSON
{"relay_id":"$MIDDLE_RELAY_ID","role":"micro-relay","pub_key":"$relay_pub","endpoint":"$MIDDLE_DATA_ADDR","control_url":"http://$MIDDLE_ADDR","country_code":"ZZ","geo_confidence":1,"region":"local","capabilities":["wg"],"hop_roles":["middle"],"reputation_score":0.82,"uptime_score":0.91,"capacity_score":0.84,"abuse_penalty":0.10,"bond_score":0.60,"stake_score":0.55,"valid_for_sec":120,"token_proof":"$proof","token_proof_nonce":"$nonce"}
JSON
)
  upsert_resp="$(curl -fsS -X POST "${DIRECTORY_URL}/v1/provider/relay/upsert" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $token" \
    --data "$upsert_payload")"
  if ! echo "$upsert_resp" | rg -q '"accepted":true'; then
    echo "expected provider micro-relay upsert to be accepted"
    return 1
  fi

  relays_json="$(curl -fsS "${DIRECTORY_URL}/v1/relays")"
  if ! echo "$relays_json" | rg -q "\"relay_id\":\"$MIDDLE_RELAY_ID\""; then
    echo "expected seeded micro-relay to be advertised by directory"
    return 1
  fi
}

cleanup() {
  kill "${node_pid:-}" >/dev/null 2>&1 || true
  ip link delete "$CLIENT_IFACE" >/dev/null 2>&1 || true
  ip link delete "$EXIT_IFACE" >/dev/null 2>&1 || true
  rm -rf "$KEY_DIR"
}
trap cleanup EXIT

ip link delete "$CLIENT_IFACE" >/dev/null 2>&1 || true
ip link delete "$EXIT_IFACE" >/dev/null 2>&1 || true

if ! ip link add dev "$CLIENT_IFACE" type wireguard >/dev/null 2>&1; then
  echo "failed to create wireguard interface $CLIENT_IFACE (is wireguard kernel support available?)"
  exit 2
fi
if ! ip link add dev "$EXIT_IFACE" type wireguard >/dev/null 2>&1; then
  echo "failed to create wireguard interface $EXIT_IFACE (is wireguard kernel support available?)"
  exit 2
fi

wg genkey >"$CLIENT_KEY_FILE"
wg genkey >"$EXIT_KEY_FILE"
go run ./cmd/adminsig gen --private-key-out "$DIRECTORY_KEY_FILE" --public-key-out "$DIRECTORY_PUB_FILE" >/dev/null
go run ./cmd/adminsig gen --private-key-out "$ISSUER_KEY_FILE" --public-key-out "$ISSUER_PUB_FILE" >/dev/null
go run ./cmd/adminsig gen --private-key-out "$ENTRY_ROUTE_ASSERTION_KEY_FILE" --public-key-out "$ENTRY_ROUTE_ASSERTION_PUB_FILE" >/dev/null
chmod 600 "$CLIENT_KEY_FILE" "$EXIT_KEY_FILE" "$DIRECTORY_KEY_FILE" "$ISSUER_KEY_FILE" "$ENTRY_ROUTE_ASSERTION_KEY_FILE"
CLIENT_WG_PUB="$(wg pubkey <"$CLIENT_KEY_FILE")"
EXIT_WG_PUB="$(wg pubkey <"$EXIT_KEY_FILE")"
DIRECTORY_PUB="$(tr -d '\r\n[:space:]' <"$DIRECTORY_PUB_FILE")"
ENTRY_ROUTE_ASSERTION_PUB="$(tr -d '\r\n[:space:]' <"$ENTRY_ROUTE_ASSERTION_PUB_FILE")"
if [[ -z "$DIRECTORY_PUB" ]]; then
  echo "failed to prepare directory public key"
  exit 1
fi
if [[ -z "$ENTRY_ROUTE_ASSERTION_PUB" ]]; then
  echo "failed to prepare entry route assertion public key"
  exit 1
fi
mkdir -p "$(dirname "$DIRECTORY_TRUSTED_KEYS_FILE")"
printf '%s\n' "$DIRECTORY_PUB" >"$DIRECTORY_TRUSTED_KEYS_FILE"

rm -f "$LOG_FILE"

assert_port_free tcp "$(addr_port "$DIRECTORY_ADDR")" "DIRECTORY_ADDR"
assert_port_free tcp "$(addr_port "$ISSUER_ADDR")" "ISSUER_ADDR"
assert_port_free tcp "$(addr_port "$ENTRY_ADDR")" "ENTRY_ADDR"
assert_port_free tcp "$(addr_port "$EXIT_ADDR")" "EXIT_ADDR"
assert_port_free udp "$(addr_port "$CLIENT_PROXY_ADDR")" "CLIENT_PROXY_ADDR"
assert_port_free udp "$(addr_port "$ENTRY_DATA_ADDR")" "ENTRY_DATA_ADDR"
assert_port_free udp "$(addr_port "$EXIT_DATA_ADDR")" "EXIT_DATA_ADDR"
assert_port_free udp "$(addr_port "$EXIT_WG_PORT" "$EXIT_WG_PORT")" "EXIT_WG_PORT"
if [[ -n "$EXIT_OPAQUE_SINK_ADDR" ]]; then
  assert_port_free udp "$(addr_port "$EXIT_OPAQUE_SINK_ADDR")" "EXIT_OPAQUE_SINK_ADDR"
fi
if [[ -n "$EXIT_OPAQUE_SOURCE_ADDR" ]]; then
  assert_port_free udp "$(addr_port "$EXIT_OPAQUE_SOURCE_ADDR")" "EXIT_OPAQUE_SOURCE_ADDR"
fi
if [[ "$STRICT_BETA_PROFILE" == "1" ]]; then
  assert_port_free tcp "$(addr_port "$MIDDLE_ADDR")" "MIDDLE_ADDR"
  assert_port_free udp "$(addr_port "$MIDDLE_DATA_ADDR")" "MIDDLE_DATA_ADDR"
fi

node_roles=(--directory --issuer --entry --exit --client)
if [[ "$STRICT_BETA_PROFILE" == "1" ]]; then
  node_roles+=(--middle)
fi

DATA_PLANE_MODE=opaque \
CLIENT_WG_BACKEND=command \
WG_BACKEND=command \
DIRECTORY_PRIVATE_KEY_FILE="$DIRECTORY_KEY_FILE" \
ISSUER_PRIVATE_KEY_FILE="$ISSUER_KEY_FILE" \
DIRECTORY_ADDR="$DIRECTORY_ADDR" \
ISSUER_ADDR="$ISSUER_ADDR" \
ENTRY_ADDR="$ENTRY_ADDR" \
EXIT_ADDR="$EXIT_ADDR" \
DIRECTORY_URL="$DIRECTORY_URL" \
ISSUER_URL="$ISSUER_URL" \
ENTRY_URL="$ENTRY_URL" \
EXIT_CONTROL_URL="$EXIT_CONTROL_URL" \
ISSUER_SPONSOR_API_TOKEN=integration-real-wg-sponsor-token \
DIRECTORY_PROVIDER_ISSUER_URLS="$ISSUER_URL" \
DIRECTORY_ISSUER_TRUST_URLS="$ISSUER_URL" \
DIRECTORY_TRUST_TOFU="${DIRECTORY_TRUST_TOFU:-0}" \
DIRECTORY_TRUSTED_KEYS_FILE="$DIRECTORY_TRUSTED_KEYS_FILE" \
CLIENT_WG_PRIVATE_KEY_PATH="$CLIENT_KEY_FILE" \
CLIENT_WG_PUBLIC_KEY="$CLIENT_WG_PUB" \
EXIT_WG_PRIVATE_KEY_PATH="$EXIT_KEY_FILE" \
EXIT_WG_PUBKEY="$EXIT_WG_PUB" \
CLIENT_WG_INTERFACE="$CLIENT_IFACE" \
EXIT_WG_INTERFACE="$EXIT_IFACE" \
CLIENT_WG_INSTALL_ROUTE=0 \
CLIENT_WG_KERNEL_PROXY=1 \
CLIENT_WG_PROXY_ADDR="$CLIENT_PROXY_ADDR" \
CLIENT_INNER_SOURCE="$CLIENT_INNER_SOURCE" \
CLIENT_BETA_STRICT="$CLIENT_BETA_STRICT" \
ENTRY_BETA_STRICT="$ENTRY_BETA_STRICT" \
EXIT_BETA_STRICT="$EXIT_BETA_STRICT" \
CLIENT_REQUIRE_DISTINCT_OPERATORS="$CLIENT_REQUIRE_DISTINCT_OPERATORS" \
ENTRY_OPERATOR_ID="$ENTRY_OPERATOR_ID" \
ENTRY_RELAY_ID=entry-local-1 \
EXIT_OPERATOR_ID="$EXIT_OPERATOR_ID" \
EXIT_RELAY_ID=exit-local-1 \
CLIENT_DISABLE_SYNTHETIC_FALLBACK="$CLIENT_DISABLE_SYNTHETIC_FALLBACK" \
CLIENT_LIVE_WG_MODE="$CLIENT_LIVE_WG_MODE" \
DIRECTORY_TRUST_STRICT="$DIRECTORY_TRUST_STRICT" \
ENTRY_LIVE_WG_MODE="$ENTRY_LIVE_WG_MODE" \
ENTRY_DIRECTORY_TRUST_STRICT="$ENTRY_DIRECTORY_TRUST_STRICT" \
ENTRY_DIRECTORY_TRUST_TOFU="${ENTRY_DIRECTORY_TRUST_TOFU:-0}" \
ENTRY_DIRECTORY_TRUSTED_KEYS_FILE="$DIRECTORY_TRUSTED_KEYS_FILE" \
ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR="$ENTRY_REQUIRE_DISTINCT_EXIT_OPERATOR" \
ENTRY_REQUIRE_MIDDLE_RELAY="$ENTRY_REQUIRE_MIDDLE_RELAY" \
ENTRY_ROUTE_ASSERTION_PRIVATE_KEY_FILE="$ENTRY_ROUTE_ASSERTION_KEY_FILE" \
ENTRY_ROUTE_ASSERTION_PUBLIC_KEY="$ENTRY_ROUTE_ASSERTION_PUB" \
ENTRY_PUZZLE_SECRET="$ENTRY_PUZZLE_SECRET" \
ENTRY_PUZZLE_DIFFICULTY="$ENTRY_PUZZLE_DIFFICULTY" \
EXIT_LIVE_WG_MODE="$EXIT_LIVE_WG_MODE" \
EXIT_TRUSTED_ENTRY_ROUTE_ASSERTION_PUBKEYS="$ENTRY_ROUTE_ASSERTION_PUB" \
EXIT_TOKEN_PROOF_REPLAY_GUARD="$EXIT_TOKEN_PROOF_REPLAY_GUARD" \
EXIT_PEER_REBIND_SEC="$EXIT_PEER_REBIND_SEC" \
EXIT_EGRESS_BACKEND="$EXIT_EGRESS_BACKEND" \
EXIT_STARTUP_SYNC_TIMEOUT_SEC="$EXIT_STARTUP_SYNC_TIMEOUT_SEC" \
EXIT_OPAQUE_SINK_ADDR="$EXIT_OPAQUE_SINK_ADDR" \
EXIT_OPAQUE_SOURCE_ADDR="$EXIT_OPAQUE_SOURCE_ADDR" \
CLIENT_OPAQUE_SESSION_SEC="$CLIENT_OPAQUE_SESSION_SEC" \
CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS="$CLIENT_OPAQUE_INITIAL_UPLINK_TIMEOUT_MS" \
CLIENT_BOOTSTRAP_INTERVAL_SEC="$CLIENT_BOOTSTRAP_INTERVAL_SEC" \
CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC="$CLIENT_BOOTSTRAP_INITIAL_DELAY_SEC" \
CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC="$CLIENT_BOOTSTRAP_BACKOFF_MAX_SEC" \
CLIENT_BOOTSTRAP_JITTER_PCT="$CLIENT_BOOTSTRAP_JITTER_PCT" \
CLIENT_STARTUP_SYNC_TIMEOUT_SEC="$CLIENT_STARTUP_SYNC_TIMEOUT_SEC" \
CLIENT_PATH_PROFILE="$CLIENT_PATH_PROFILE" \
ENTRY_DATA_ADDR="$ENTRY_DATA_ADDR" \
ENTRY_ENDPOINT="$ENTRY_DATA_ADDR" \
MIDDLE_ADDR="$MIDDLE_ADDR" \
MIDDLE_DATA_ADDR="$MIDDLE_DATA_ADDR" \
MIDDLE_ENTRY_DATA_ADDR="$ENTRY_DATA_ADDR" \
MIDDLE_EXIT_DATA_ADDR="$EXIT_DATA_ADDR" \
MIDDLE_READY_FILE="$MIDDLE_READY_FILE" \
EXIT_DATA_ADDR="$EXIT_DATA_ADDR" \
EXIT_ENDPOINT="$EXIT_DATA_ADDR" \
EXIT_WG_LISTEN_PORT="$EXIT_WG_PORT" \
EXIT_WG_KERNEL_PROXY=1 \
timeout "${SCRIPT_TIMEOUT_SEC}s" go run ./cmd/node "${node_roles[@]}" >"$LOG_FILE" 2>&1 &
node_pid=$!

if [[ "$STRICT_BETA_PROFILE" == "1" ]]; then
  for _ in $(seq 1 100); do
    if [[ -s "$MIDDLE_READY_FILE" ]]; then
      break
    fi
    if ! kill -0 "$node_pid" >/dev/null 2>&1; then
      echo "node exited before middle relay readiness"
      cat "$LOG_FILE"
      exit 1
    fi
    sleep 0.2
  done
  if [[ ! -s "$MIDDLE_READY_FILE" ]]; then
    echo "middle relay did not become ready"
    cat "$LOG_FILE"
    exit 1
  fi
  if ! seed_middle_relay; then
    echo "failed to seed strict beta middle relay"
    cat "$LOG_FILE"
    exit 1
  fi
fi

ready=0
for _ in $(seq 1 200); do
  if ! kill -0 "$node_pid" >/dev/null 2>&1; then
    echo "node exited before client session config"
    cat "$LOG_FILE"
    exit 1
  fi
  if rg -q "client wireguard runtime ready:|client wg-kernel proxy listening:" "$LOG_FILE"; then
    ready=1
    break
  fi
  sleep 0.2
done
if [[ "$ready" -ne 1 ]]; then
  echo "client did not reach wg session config stage"
  cat "$LOG_FILE"
  exit 1
fi

if [[ "$CLIENT_INNER_SOURCE" == "udp" ]]; then
  if ! rg -q "client role enabled: .*source=udp" "$LOG_FILE"; then
    echo "expected client udp inner source configuration was not observed"
    cat "$LOG_FILE"
    exit 1
  fi
fi
if [[ "$CLIENT_DISABLE_SYNTHETIC_FALLBACK" == "1" ]]; then
  if ! rg -q "client role enabled: .*synthetic_fallback=false" "$LOG_FILE"; then
    echo "expected synthetic fallback disablement was not observed"
    cat "$LOG_FILE"
    exit 1
  fi
fi

relay_json="$(curl -fsS "${DIRECTORY_URL}/v1/relays" || true)"
if ! echo "$relay_json" | rg -q "\"endpoint\":\"$ENTRY_DATA_ADDR\""; then
  echo "directory entry endpoint mismatch (expected $ENTRY_DATA_ADDR)"
  echo "$relay_json"
  cat "$LOG_FILE"
  exit 1
fi
if ! echo "$relay_json" | rg -q "\"endpoint\":\"$EXIT_DATA_ADDR\""; then
  echo "directory exit endpoint mismatch (expected $EXIT_DATA_ADDR)"
  echo "$relay_json"
  cat "$LOG_FILE"
  exit 1
fi
if ! echo "$relay_json" | rg -q "\"role\":\"entry\"[^\}]*\"operator_id\":\"$ENTRY_OPERATOR_ID\""; then
  echo "directory entry operator mismatch (expected $ENTRY_OPERATOR_ID)"
  echo "$relay_json"
  cat "$LOG_FILE"
  exit 1
fi
if ! echo "$relay_json" | rg -q "\"role\":\"exit\"[^\}]*\"operator_id\":\"$EXIT_OPERATOR_ID\""; then
  echo "directory exit operator mismatch (expected $EXIT_OPERATOR_ID)"
  echo "$relay_json"
  cat "$LOG_FILE"
  exit 1
fi

iface_ready=0
for _ in $(seq 1 60); do
  if wg show "$CLIENT_IFACE" >/dev/null 2>&1 && wg show "$EXIT_IFACE" >/dev/null 2>&1; then
    iface_ready=1
    break
  fi
  sleep 0.2
done
if [[ "$iface_ready" -ne 1 ]]; then
  echo "wireguard interfaces were not configured"
  ip link show "$CLIENT_IFACE" >/dev/null 2>&1 && ip link show "$CLIENT_IFACE" || true
  ip link show "$EXIT_IFACE" >/dev/null 2>&1 && ip link show "$EXIT_IFACE" || true
  cat "$LOG_FILE"
  exit 1
fi

client_peer_ok=0
for _ in $(seq 1 80); do
  if wg show "$CLIENT_IFACE" peers | grep -Fqx -- "$EXIT_WG_PUB"; then
    client_peer_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$client_peer_ok" -ne 1 ]]; then
  echo "client wireguard interface missing expected exit peer ${EXIT_WG_PUB}"
  wg show "$CLIENT_IFACE" || true
  cat "$LOG_FILE"
  exit 1
fi

client_ep_ok=0
for _ in $(seq 1 80); do
  if wg show "$CLIENT_IFACE" endpoints | awk -v key="$EXIT_WG_PUB" -v endpoint="$CLIENT_PROXY_ADDR" '
    $1 == key && $2 == endpoint { found = 1 }
    END { exit(found ? 0 : 1) }
  '; then
    client_ep_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$client_ep_ok" -ne 1 ]]; then
  echo "client wireguard endpoint not set to kernel proxy address ${CLIENT_PROXY_ADDR}"
  wg show "$CLIENT_IFACE" endpoints || true
  cat "$LOG_FILE"
  exit 1
fi

exit_port="$(wg show "$EXIT_IFACE" listen-port || true)"
if [[ "$exit_port" != "$EXIT_WG_PORT" ]]; then
  echo "exit wireguard listen-port mismatch: got=${exit_port} expected=${EXIT_WG_PORT}"
  wg show "$EXIT_IFACE" || true
  cat "$LOG_FILE"
  exit 1
fi

session_active=0
for _ in $(seq 1 100); do
  metrics_json="$(curl -fsS "${EXIT_CONTROL_URL}/v1/metrics" 2>/dev/null || true)"
  if echo "$metrics_json" | rg -q '"active_sessions"[[:space:]]*:[[:space:]]*[1-9][0-9]*'; then
    session_active=1
    break
  fi
  sleep 0.1
done
if [[ "$session_active" -ne 1 ]]; then
  echo "exit never reported an active session before packet injection"
  if [[ -n "${metrics_json:-}" ]]; then
    echo "latest exit metrics: $metrics_json"
  fi
  cat "$LOG_FILE"
  exit 1
fi

exit_peer_ok=0
for _ in $(seq 1 80); do
  if wg show "$EXIT_IFACE" peers | grep -Fqx -- "$CLIENT_WG_PUB"; then
    exit_peer_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$exit_peer_ok" -ne 1 ]]; then
  echo "exit wireguard interface missing expected client peer ${CLIENT_WG_PUB}"
  wg show "$EXIT_IFACE" || true
  cat "$LOG_FILE"
  exit 1
fi

up_ok=0
exit_ok=0
metrics_ok=0
for _ in $(seq 1 8); do
  if ! perl -MIO::Socket::INET -e '
    my $target = shift @ARGV;
    my $sock = IO::Socket::INET->new(PeerAddr => $target, Proto => "udp") or exit 1;
    my $pkt = pack("C4", 4, 0, 0, 0) . ("\0" x 28);
    print {$sock} $pkt or exit 1;
  ' "$CLIENT_PROXY_ADDR"; then
    echo "failed to inject wg-like packet into client proxy"
    cat "$LOG_FILE"
    exit 1
  fi
  sleep 0.1
done

hs_ok=0
for _ in $(seq 1 80); do
  client_hs="$(wg show "$CLIENT_IFACE" latest-handshakes | awk -v key="$EXIT_WG_PUB" '$1==key {print $2}')"
  exit_hs="$(wg show "$EXIT_IFACE" latest-handshakes | awk -v key="$CLIENT_WG_PUB" '$1==key {print $2}')"
  if [[ "${client_hs:-0}" -gt 0 && "${exit_hs:-0}" -gt 0 ]]; then
    hs_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$hs_ok" -ne 1 ]]; then
  echo "wireguard latest-handshakes did not become active on both interfaces"
  wg show "$CLIENT_IFACE" latest-handshakes || true
  wg show "$EXIT_IFACE" latest-handshakes || true
  cat "$LOG_FILE"
  exit 1
fi

transfer_ok=0
for _ in $(seq 1 80); do
  client_tx="$(wg show "$CLIENT_IFACE" transfer | awk -v key="$EXIT_WG_PUB" '$1==key {print $3}')"
  exit_rx="$(wg show "$EXIT_IFACE" transfer | awk -v key="$CLIENT_WG_PUB" '$1==key {print $2}')"
  if [[ "${client_tx:-0}" -gt 0 && "${exit_rx:-0}" -gt 0 ]]; then
    transfer_ok=1
    break
  fi
  sleep 0.2
done
if [[ "$transfer_ok" -ne 1 ]]; then
  echo "wireguard transfer counters did not advance on client->exit path"
  wg show "$CLIENT_IFACE" transfer || true
  wg show "$EXIT_IFACE" transfer || true
  cat "$LOG_FILE"
  exit 1
fi

for _ in $(seq 1 80); do
  if rg -q "client wg-kernel proxy uplink packets=[1-9][0-9]*" "$LOG_FILE"; then
    up_ok=1
  fi
  if rg -q "exit accepted opaque packet session=.*wg_like=(true|false)" "$LOG_FILE"; then
    exit_ok=1
  fi
  metrics_json="$(curl -fsS "${EXIT_CONTROL_URL}/v1/metrics" 2>/dev/null || true)"
  if echo "$metrics_json" | rg -q '"accepted_packets"[[:space:]]*:[[:space:]]*[1-9][0-9]*' &&
    echo "$metrics_json" | rg -q '"wg_proxy_created"[[:space:]]*:[[:space:]]*[1-9][0-9]*'; then
    metrics_ok=1
  fi
  if [[ "$exit_ok" -eq 1 || "$metrics_ok" -eq 1 ]]; then
    break
  fi
  sleep 0.25
done

if [[ "$exit_ok" -ne 1 && "$metrics_ok" -ne 1 ]]; then
  echo "missing expected real wg integration log signals"
  if [[ -n "${metrics_json:-}" ]]; then
    echo "latest exit metrics: $metrics_json"
  fi
  cat "$LOG_FILE"
  exit 1
fi

if [[ "$up_ok" -ne 1 ]]; then
  echo "note: client uplink summary log not observed before script completion (traffic still verified via exit metrics/logs)"
fi

if [[ "$STRICT_BETA_PROFILE" == "1" ]]; then
  if ! rg -q "client role enabled: .*beta_strict=true" "$LOG_FILE"; then
    echo "strict beta profile: missing client beta_strict=true signal"
    cat "$LOG_FILE"
    exit 1
  fi
  if ! rg -q "entry route discovery: .*trust_strict=true .*live_wg_mode=true .*require_middle_relay=true" "$LOG_FILE"; then
    echo "strict beta profile: missing entry trust/live/middle strict signal"
    cat "$LOG_FILE"
    exit 1
  fi
  if ! rg -q "exit wg backend=.*beta_strict=true" "$LOG_FILE"; then
    echo "strict beta profile: missing exit beta_strict=true signal"
    cat "$LOG_FILE"
    exit 1
  fi
  if rg -q "startup key fetch failed|startup revocation fetch failed" "$LOG_FILE"; then
    echo "strict beta profile: unexpected startup key/revocation fetch failure"
    cat "$LOG_FILE"
    exit 1
  fi
fi

echo "real wg privileged integration check ok"
