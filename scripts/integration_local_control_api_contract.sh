#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
GPM_API_FILE="services/localapi/gpm_api.go"
LOCAL_API_SERVICE_FILE="services/localapi/service.go"

for cmd in go curl jq mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
FAKE_SCRIPT="$TMP_DIR/fake_easy_node.sh"
CALLS_FILE="$TMP_DIR/easy_node_calls.tsv"
SERVER_LOG="$TMP_DIR/local_api_server.log"
MANIFEST_CACHE="$TMP_DIR/gpm_manifest_cache.json"
AUTH_PROOF_HELPER="$TMP_DIR/gpm_auth_contract_proof.go"
LOCAL_API_BASE=""
SERVER_PID=""
LOCAL_API_AUTH_TOKEN="local-api-contract-token"
LOCAL_API_OPERATOR_ADMIN_TOKEN="local-api-contract-admin-token"

cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

ensure_auth_proof_helper() {
  if [[ -f "$AUTH_PROOF_HELPER" ]]; then
    return 0
  fi
  cat >"$AUTH_PROOF_HELPER" <<'EOF_GO'
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	"golang.org/x/crypto/ripemd160"
)

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
const bech32ChecksumLength = 6

var (
	bech32Generator = []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	fieldPrime      = mustBigIntFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	curveOrder      = mustBigIntFromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	generatorX      = mustBigIntFromHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	generatorY      = mustBigIntFromHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
)

type point struct {
	x        *big.Int
	y        *big.Int
	infinity bool
}

func mustBigIntFromHex(raw string) *big.Int {
	value, ok := new(big.Int).SetString(strings.TrimSpace(raw), 16)
	if !ok {
		panic(fmt.Sprintf("invalid bigint literal %q", raw))
	}
	return value
}

func pointInfinity() point {
	return point{infinity: true}
}

func newPoint(x *big.Int, y *big.Int) point {
	return point{x: new(big.Int).Set(x), y: new(big.Int).Set(y)}
}

func pointDouble(p point) point {
	if p.infinity || p.y.Sign() == 0 {
		return pointInfinity()
	}
	num := new(big.Int).Mul(p.x, p.x)
	num.Mul(num, big.NewInt(3))
	num.Mod(num, fieldPrime)
	den := new(big.Int).Mul(p.y, big.NewInt(2))
	den.Mod(den, fieldPrime)
	denInv := new(big.Int).ModInverse(den, fieldPrime)
	if denInv == nil {
		return pointInfinity()
	}
	lambda := new(big.Int).Mul(num, denInv)
	lambda.Mod(lambda, fieldPrime)
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, new(big.Int).Mul(p.x, big.NewInt(2)))
	x3.Mod(x3, fieldPrime)
	y3 := new(big.Int).Sub(p.x, x3)
	y3.Mul(lambda, y3)
	y3.Sub(y3, p.y)
	y3.Mod(y3, fieldPrime)
	return point{x: x3, y: y3}
}

func pointAdd(a point, b point) point {
	if a.infinity {
		return b
	}
	if b.infinity {
		return a
	}
	if a.x.Cmp(b.x) == 0 {
		sumY := new(big.Int).Add(a.y, b.y)
		sumY.Mod(sumY, fieldPrime)
		if sumY.Sign() == 0 {
			return pointInfinity()
		}
		return pointDouble(a)
	}
	num := new(big.Int).Sub(b.y, a.y)
	num.Mod(num, fieldPrime)
	den := new(big.Int).Sub(b.x, a.x)
	den.Mod(den, fieldPrime)
	denInv := new(big.Int).ModInverse(den, fieldPrime)
	if denInv == nil {
		return pointInfinity()
	}
	lambda := new(big.Int).Mul(num, denInv)
	lambda.Mod(lambda, fieldPrime)
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, a.x)
	x3.Sub(x3, b.x)
	x3.Mod(x3, fieldPrime)
	y3 := new(big.Int).Sub(a.x, x3)
	y3.Mul(lambda, y3)
	y3.Sub(y3, a.y)
	y3.Mod(y3, fieldPrime)
	return point{x: x3, y: y3}
}

func scalarMult(p point, scalar *big.Int) point {
	if p.infinity || scalar == nil || scalar.Sign() <= 0 {
		return pointInfinity()
	}
	result := pointInfinity()
	addend := p
	for bit := 0; bit < scalar.BitLen(); bit++ {
		if scalar.Bit(bit) == 1 {
			result = pointAdd(result, addend)
		}
		addend = pointDouble(addend)
	}
	return result
}

func privateKeyScalar() (*big.Int, error) {
	raw := strings.TrimSpace(os.Getenv("GPM_AUTH_CONTRACT_KEY_SCALAR"))
	if raw == "" {
		raw = "1"
	}
	value, ok := new(big.Int).SetString(raw, 10)
	if !ok || value.Sign() <= 0 || value.Cmp(curveOrder) >= 0 {
		return nil, fmt.Errorf("invalid GPM_AUTH_CONTRACT_KEY_SCALAR %q", raw)
	}
	return value, nil
}

func deterministicSecp256k1Proof(message string) (string, string, error) {
	privateKey, err := privateKeyScalar()
	if err != nil {
		return "", "", err
	}
	hash := sha256.Sum256([]byte(message))
	nonceSeed := sha256.Sum256([]byte("gpm-auth-secp256k1-test-nonce:" + message))
	maxNonce := new(big.Int).Sub(new(big.Int).Set(curveOrder), big.NewInt(1))
	nonce := new(big.Int).SetBytes(nonceSeed[:])
	nonce.Mod(nonce, maxNonce)
	nonce.Add(nonce, big.NewInt(1))
	generator := newPoint(generatorX, generatorY)

	var r *big.Int
	var s *big.Int
	for attempts := 0; attempts < 8; attempts++ {
		noncePoint := scalarMult(generator, nonce)
		if !noncePoint.infinity && noncePoint.x != nil {
			candidateR := new(big.Int).Mod(noncePoint.x, curveOrder)
			if candidateR.Sign() != 0 {
				nonceInv := new(big.Int).ModInverse(nonce, curveOrder)
				if nonceInv != nil {
					candidateS := new(big.Int).Mul(candidateR, privateKey)
					candidateS.Add(candidateS, new(big.Int).SetBytes(hash[:]))
					candidateS.Mul(candidateS, nonceInv)
					candidateS.Mod(candidateS, curveOrder)
					if candidateS.Sign() != 0 {
						r = candidateR
						s = candidateS
						break
					}
				}
			}
		}
		nonce.Add(nonce, big.NewInt(1))
		if nonce.Cmp(curveOrder) >= 0 {
			nonce.SetInt64(1)
		}
	}
	if r == nil || s == nil {
		return "", "", errors.New("failed to derive deterministic secp256k1 signature")
	}
	publicKeyPoint := scalarMult(generator, privateKey)
	if publicKeyPoint.infinity || publicKeyPoint.x == nil || publicKeyPoint.y == nil {
		return "", "", errors.New("failed to derive deterministic secp256k1 public key")
	}
	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):], sBytes)
	publicKey := compressedPublicKey(publicKeyPoint)
	return base64.StdEncoding.EncodeToString(signature), base64.StdEncoding.EncodeToString(publicKey), nil
}

func compressedPublicKey(publicKeyPoint point) []byte {
	publicKey := make([]byte, 33)
	publicKey[0] = 0x02
	if publicKeyPoint.y.Bit(0) == 1 {
		publicKey[0] = 0x03
	}
	xBytes := publicKeyPoint.x.Bytes()
	copy(publicKey[33-len(xBytes):], xBytes)
	return publicKey
}

func bech32HRPExpand(hrp string) []byte {
	expanded := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		expanded = append(expanded, hrp[i]>>5)
	}
	expanded = append(expanded, 0)
	for i := 0; i < len(hrp); i++ {
		expanded = append(expanded, hrp[i]&31)
	}
	return expanded
}

func bech32Polymod(values []byte) uint32 {
	chk := uint32(1)
	for _, value := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(value)
		for i := 0; i < len(bech32Generator); i++ {
			if ((top >> uint(i)) & 1) != 0 {
				chk ^= bech32Generator[i]
			}
		}
	}
	return chk
}

func bech32CreateChecksum(hrp string, data []byte) []byte {
	values := append(bech32HRPExpand(hrp), data...)
	values = append(values, make([]byte, bech32ChecksumLength)...)
	polymod := bech32Polymod(values) ^ 1
	checksum := make([]byte, bech32ChecksumLength)
	for i := 0; i < bech32ChecksumLength; i++ {
		checksum[i] = byte((polymod >> uint(5*(5-i))) & 31)
	}
	return checksum
}

func bech32ConvertBits(data []byte, fromBits uint, toBits uint, pad bool) ([]byte, error) {
	acc := uint(0)
	bits := uint(0)
	maxv := uint((1 << toBits) - 1)
	maxAcc := uint((1 << (fromBits + toBits - 1)) - 1)
	out := make([]byte, 0, len(data)*int(fromBits)/int(toBits))
	for _, value := range data {
		v := uint(value)
		if v>>fromBits != 0 {
			return nil, errors.New("bech32 data value exceeds bit group size")
		}
		acc = ((acc << fromBits) | v) & maxAcc
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			out = append(out, byte((acc>>bits)&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte((acc<<(toBits-bits))&maxv))
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxv) != 0 {
		return nil, errors.New("bech32 data has invalid padding")
	}
	return out, nil
}

func encodeBech32Address(hrp string, payload []byte) (string, error) {
	data, err := bech32ConvertBits(payload, 8, 5, true)
	if err != nil {
		return "", err
	}
	combined := append(append([]byte{}, data...), bech32CreateChecksum(hrp, data)...)
	var b strings.Builder
	b.Grow(len(hrp) + 1 + len(combined))
	b.WriteString(hrp)
	b.WriteByte('1')
	for _, value := range combined {
		if int(value) >= len(bech32Charset) {
			return "", errors.New("bech32 data value out of range")
		}
		b.WriteByte(bech32Charset[value])
	}
	return b.String(), nil
}

func deterministicWalletAddress(hrp string) (string, error) {
	privateKey, err := privateKeyScalar()
	if err != nil {
		return "", err
	}
	publicKeyPoint := scalarMult(newPoint(generatorX, generatorY), privateKey)
	publicKey := compressedPublicKey(publicKeyPoint)
	sha := sha256.Sum256(publicKey)
	ripemd := ripemd160.New()
	if _, err := ripemd.Write(sha[:]); err != nil {
		return "", err
	}
	return encodeBech32Address(hrp, ripemd.Sum(nil))
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gpm_auth_contract_proof.go (--address|--proof)")
		os.Exit(2)
	}
	walletAddress, err := deterministicWalletAddress("cosmos")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	switch os.Args[1] {
	case "--address":
		fmt.Println(walletAddress)
	case "--proof":
		messageBytes, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		message := string(messageBytes)
		signature, publicKey, err := deterministicSecp256k1Proof(message)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{
			"wallet_address":              walletAddress,
			"signature":                   signature,
			"signature_public_key":        publicKey,
			"signature_public_key_type":   "secp256k1",
			"signed_message":              message,
		})
	default:
		fmt.Fprintln(os.Stderr, "usage: gpm_auth_contract_proof.go (--address|--proof)")
		os.Exit(2)
	}
}
EOF_GO
}

auth_contract_wallet_address() {
  local scalar="${1:-1}"
  ensure_auth_proof_helper
  GPM_AUTH_CONTRACT_KEY_SCALAR="$scalar" go run "$AUTH_PROOF_HELPER" --address
}

auth_contract_proof_json() {
  local message="$1"
  local scalar="${2:-1}"
  ensure_auth_proof_helper
  printf '%s' "$message" | GPM_AUTH_CONTRACT_KEY_SCALAR="$scalar" go run "$AUTH_PROOF_HELPER" --proof
}

cat >"$FAKE_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail

calls_file="${LOCAL_API_CONTRACT_CALLS_FILE:?}"
cmd="${1:-}"
if [[ -z "$cmd" ]]; then
  echo "missing command" >&2
  exit 2
fi
shift || true

{
  printf '%s' "$cmd"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$calls_file"

case "$cmd" in
  client-vpn-status)
    echo '{"ok":true,"running":false,"interface":"wgvpn0"}'
    ;;
  runtime-doctor)
    echo '{"ok":true,"status":"green","checks":[]}'
    ;;
  *)
    echo "$cmd ok"
    ;;
esac
EOF_FAKE
chmod +x "$FAKE_SCRIPT"

write_manifest_cache() {
  local bootstrap_directory="${1:-http://127.0.0.1:8081}"
  local fetched_at=""
  local generated_at=""
  local expires_at=""
  fetched_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  generated_at="$fetched_at"
  expires_at="$(date -u -d '+24 hour' +"%Y-%m-%dT%H:%M:%SZ")"
  jq -n \
    --arg fetched_at "$fetched_at" \
    --arg generated_at "$generated_at" \
    --arg expires_at "$expires_at" \
    --arg bootstrap_directory "$bootstrap_directory" \
    '{
      version: 1,
      fetched_at_utc: $fetched_at,
      source_url: "https://globalprivatemesh.example/v1/bootstrap/manifest",
      signature_verified: true,
      manifest: {
        version: 1,
        generated_at_utc: $generated_at,
        expires_at_utc: $expires_at,
        bootstrap_directories: [
          $bootstrap_directory
        ]
      }
    }' >"$MANIFEST_CACHE"
}

write_manifest_cache_invalid() {
  printf '{invalid-manifest-json' >"$MANIFEST_CACHE"
}

pick_port() {
  local candidate=""
  local i=0
  for i in $(seq 1 50); do
    candidate="$((20000 + RANDOM % 20000))"
    if ! curl -fsS "http://127.0.0.1:${candidate}/v1/health" >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  echo "failed to pick free local API port" >&2
  return 1
}

wait_for_local_api() {
  local url="$1"
  local i=0
  for i in $(seq 1 120); do
    if curl -fsS "${url}/v1/health" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
      echo "local API process exited before readiness"
      cat "$SERVER_LOG"
      return 1
    fi
    sleep 0.1
  done
  echo "timeout waiting for local API readiness: ${url}"
  cat "$SERVER_LOG"
  return 1
}

start_local_api() {
  local allow_update="$1"
  local operator_approval_require_session="${2:-0}"
  local port=""
  local attempt=0
  local max_attempts=8

  for attempt in $(seq 1 "$max_attempts"); do
    port="$(pick_port)"
    : >"$CALLS_FILE"
    : >"$SERVER_LOG"
    write_manifest_cache

    LOCAL_API_BASE="http://127.0.0.1:${port}"
    LOCAL_CONTROL_API_ADDR="127.0.0.1:${port}" \
    LOCAL_CONTROL_API_SCRIPT="$FAKE_SCRIPT" \
    LOCAL_CONTROL_API_ALLOW_UPDATE="$allow_update" \
    LOCAL_CONTROL_API_ALLOW_UNAUTH_LOOPBACK="1" \
    LOCAL_CONTROL_API_AUTH_TOKEN="$LOCAL_API_AUTH_TOKEN" \
    GPM_OPERATOR_APPROVAL_TOKEN="$LOCAL_API_OPERATOR_ADMIN_TOKEN" \
    GPM_OPERATOR_APPROVAL_REQUIRE_SESSION="$operator_approval_require_session" \
    GPM_LOCAL_API_ADMIN_ROUTES="1" \
    GPM_ADMIN_WALLET_ALLOWLIST="$(auth_contract_wallet_address 2)" \
    GPM_AUTH_VERIFY_COMMAND="printf gpm-auth-verify-ok" \
    LOCAL_CONTROL_API_SERVICE_START_COMMAND="printf gpm-service-start-ok" \
    LOCAL_CONTROL_API_SERVICE_STOP_COMMAND="printf gpm-service-stop-ok" \
    LOCAL_CONTROL_API_SERVICE_RESTART_COMMAND="printf gpm-service-restart-ok" \
    GPM_MAIN_DOMAIN="https://globalprivatemesh.example" \
    GPM_BOOTSTRAP_MANIFEST_URL="https://globalprivatemesh.example/v1/bootstrap/manifest" \
    GPM_BOOTSTRAP_MANIFEST_CACHE_PATH="$MANIFEST_CACHE" \
    GPM_BOOTSTRAP_MANIFEST_CACHE_MAX_AGE_SEC="86400" \
    LOCAL_API_CONTRACT_CALLS_FILE="$CALLS_FILE" \
      go run ./cmd/node --local-api >"$SERVER_LOG" 2>&1 &
    SERVER_PID=$!

    if wait_for_local_api "$LOCAL_API_BASE"; then
      return 0
    fi

    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then
      kill "$SERVER_PID" >/dev/null 2>&1 || true
      wait "$SERVER_PID" >/dev/null 2>&1 || true
    fi
    SERVER_PID=""

    if grep -F 'address already in use' "$SERVER_LOG" >/dev/null 2>&1; then
      if (( attempt < max_attempts )); then
        echo "local API bind conflict on port ${port}; retrying (${attempt}/${max_attempts})"
        sleep 0.1
        continue
      fi
      echo "local API bind conflict persisted after ${max_attempts} attempts"
      cat "$SERVER_LOG"
      return 1
    fi

    return 1
  done

  echo "failed to start local API"
  return 1
}

stop_local_api() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  SERVER_PID=""
}

last_call() {
  local command="$1"
  awk -F '\t' -v cmd="$command" '$1 == cmd { line = $0 } END { if (line != "") print line }' "$CALLS_FILE"
}

assert_line_has() {
  local line="$1"
  local pattern="$2"
  local message="$3"
  if ! printf '%s\n' "$line" | grep -F -- "$pattern" >/dev/null 2>&1; then
    echo "$message"
    echo "line: $line"
    echo "calls:"
    cat "$CALLS_FILE"
    exit 1
  fi
}

require_last_call() {
  local command="$1"
  local line=""
  line="$(last_call "$command")"
  if [[ -z "$line" ]]; then
    echo "missing expected command call: $command"
    cat "$CALLS_FILE"
    exit 1
  fi
  printf '%s\n' "$line"
}

require_gpm_api_marker() {
  local pattern="$1"
  local description="$2"
  if ! grep -qE "$pattern" "$GPM_API_FILE"; then
    echo "local control API contract failed: missing ${description} marker /${pattern}/ in $GPM_API_FILE"
    exit 1
  fi
}

require_localapi_service_marker() {
  local pattern="$1"
  local description="$2"
  if ! grep -qE "$pattern" "$LOCAL_API_SERVICE_FILE"; then
    echo "local control API contract failed: missing ${description} marker /${pattern}/ in $LOCAL_API_SERVICE_FILE"
    exit 1
  fi
}

api_get() {
  local path="$1"
  curl -fsS -H "Authorization: Bearer ${LOCAL_API_AUTH_TOKEN}" "${LOCAL_API_BASE}${path}"
}

api_post_json() {
  local path="$1"
  local payload="$2"
  curl -fsS -X POST -H "Authorization: Bearer ${LOCAL_API_AUTH_TOKEN}" -H 'Content-Type: application/json' --data "$payload" "${LOCAL_API_BASE}${path}"
}

mint_auth_contract_session_json() {
  local scalar="$1"
  local expected_role="${2:-}"
  local wallet_address=""
  local challenge_body=""
  local challenge_json=""
  local challenge_id=""
  local challenge_message=""
  local proof_json=""
  local verify_body=""
  local verify_json=""
  wallet_address="$(auth_contract_wallet_address "$scalar")"
  challenge_body="$(jq -cn --arg wallet_address "$wallet_address" '{wallet_address: $wallet_address, wallet_provider: "keplr"}')"
  challenge_json="$(api_post_json "/v1/gpm/auth/challenge" "$challenge_body")"
  if ! jq -e '.ok == true and (.challenge_id | type == "string" and length > 0) and (.message | type == "string" and length > 0)' <<<"$challenge_json" >/dev/null; then
    echo "auth challenge did not return expected payload" >&2
    echo "$challenge_json" >&2
    exit 1
  fi
  challenge_id="$(jq -r '.challenge_id // ""' <<<"$challenge_json")"
  challenge_message="$(jq -r '.message // ""' <<<"$challenge_json")"
  proof_json="$(auth_contract_proof_json "$challenge_message" "$scalar")"
  verify_body="$(jq -cn \
    --arg wallet_address "$wallet_address" \
    --arg challenge_id "$challenge_id" \
    --arg signature "$(jq -r '.signature // ""' <<<"$proof_json")" \
    --arg signature_public_key "$(jq -r '.signature_public_key // ""' <<<"$proof_json")" \
    --arg signature_public_key_type "$(jq -r '.signature_public_key_type // "secp256k1"' <<<"$proof_json")" \
    --arg signed_message "$(jq -r '.signed_message // ""' <<<"$proof_json")" \
    '{
      wallet_address: $wallet_address,
      wallet_provider: "keplr",
      challenge_id: $challenge_id,
      signature: $signature,
      signature_public_key: $signature_public_key,
      signature_public_key_type: $signature_public_key_type,
      signed_message: $signed_message
    }')"
  verify_json="$(api_post_json "/v1/gpm/auth/verify" "$verify_body")"
  if [[ -n "$expected_role" ]] && ! jq -e --arg wallet_address "$wallet_address" --arg expected_role "$expected_role" '.ok == true and .session.wallet_address == $wallet_address and .session.role == $expected_role and .session.wallet_binding_verified == true and (.session_token | type == "string" and length > 0)' <<<"$verify_json" >/dev/null; then
    echo "auth verify did not return expected ${expected_role} session payload" >&2
    echo "$verify_json" >&2
    exit 1
  fi
  printf '%s\n' "$verify_json"
}

if [[ ! -f "$GPM_API_FILE" ]]; then
  echo "local control API contract failed: missing source file: $GPM_API_FILE"
  exit 1
fi
if [[ ! -f "$LOCAL_API_SERVICE_FILE" ]]; then
  echo "local control API contract failed: missing source file: $LOCAL_API_SERVICE_FILE"
  exit 1
fi

# Verify-request metadata fields remain optional and presence-aware.
VERIFY_REQUEST_METADATA_MARKERS=(
  'SignatureKind[[:space:]]+\*string[[:space:]]+`json:"signature_kind,omitempty"`'
  'SignaturePublicKey[[:space:]]+string[[:space:]]+`json:"signature_public_key,omitempty"`'
  'SignaturePublicKeyType[[:space:]]+\*string[[:space:]]+`json:"signature_public_key_type,omitempty"`'
  'SignatureSource[[:space:]]+\*string[[:space:]]+`json:"signature_source,omitempty"`'
  'ChainID[[:space:]]+string[[:space:]]+`json:"chain_id,omitempty"`'
  'SignedMessage[[:space:]]+\*string[[:space:]]+`json:"signed_message,omitempty"`'
  'SignatureEnvelope[[:space:]]+json\.RawMessage[[:space:]]+`json:"signature_envelope,omitempty"`'
  'if[[:space:]]+in\.SignedMessage[[:space:]]*!=[[:space:]]*nil[[:space:]]*\{'
  'normalizeOptionalJSONStringOrScalar\(in\.SignatureEnvelope\)'
  'HasSignedMessage[[:space:]]*=[[:space:]]*true'
  'HasSignatureEnvelope[[:space:]]*=[[:space:]]*true'
)
for marker in "${VERIFY_REQUEST_METADATA_MARKERS[@]}"; do
  require_gpm_api_marker "$marker" "verify-request optional metadata"
done

# Validation paths: signed_message challenge binding, enum allow-lists, and envelope length bound.
VERIFY_METADATA_VALIDATION_MARKERS=(
  'func[[:space:]]+validateGPMAuthSignatureMetadata\('
  'if[[:space:]]+signatureMetadata\.HasSignedMessage[[:space:]]+&&[[:space:]]+!subtleEqual\(challenge\.Message,[[:space:]]*signatureMetadata\.SignedMessage\)'
  'signed_message does not match issued challenge message'
  'case[[:space:]]+"sign_arbitrary",[[:space:]]*"eip191"'
  'unsupported signature_kind'
  'case[[:space:]]+"wallet_extension",[[:space:]]*"manual"'
  'unsupported signature_source'
  'case[[:space:]]+"secp256k1",[[:space:]]*"ed25519"'
  'unsupported signature_public_key_type'
  'gpmAuthSignatureEnvelopeMaxLen'
  'if[[:space:]]+signatureMetadata\.HasSignatureEnvelope[[:space:]]+&&[[:space:]]+len\(signatureMetadata\.SignatureEnvelope\)[[:space:]]*>[[:space:]]*gpmAuthSignatureEnvelopeMaxLen'
  'signature_envelope is too long'
  'if[[:space:]]+err[[:space:]]*:=[[:space:]]+validateGPMAuthSignatureMetadata\(challenge,[[:space:]]*signatureMetadata\);[[:space:]]+err[[:space:]]*!=[[:space:]]*nil'
)
for marker in "${VERIFY_METADATA_VALIDATION_MARKERS[@]}"; do
  require_gpm_api_marker "$marker" "verify metadata validation"
done

# Auth verifier command must receive metadata in environment for external verifier hooks.
VERIFY_METADATA_ENV_MARKERS=(
  'func[[:space:]]+\(s[[:space:]]+\*Service\)[[:space:]]+runGPMAuthVerifierCommand\([^)]*signatureMetadata[[:space:]]+gpmAuthSignatureMetadata\)'
  'GPM_AUTH_VERIFY_SIGNATURE_KIND='
  'GPM_AUTH_VERIFY_SIGNATURE_PUBLIC_KEY='
  'GPM_AUTH_VERIFY_SIGNATURE_PUBLIC_KEY_TYPE='
  'GPM_AUTH_VERIFY_SIGNATURE_SOURCE='
  'GPM_AUTH_VERIFY_CHAIN_ID='
  'GPM_AUTH_VERIFY_SIGNED_MESSAGE='
  'GPM_AUTH_VERIFY_SIGNATURE_ENVELOPE='
)
for marker in "${VERIFY_METADATA_ENV_MARKERS[@]}"; do
  require_gpm_api_marker "$marker" "verifier metadata env propagation"
done
echo "[local-control-api-contract] gpm auth verify metadata markers in source are present"

# Strict verifier-command policy must be wired end-to-end:
# - env parsing for strict policy toggle
# - /v1/config policy/configured surface
# - fail-closed policy check in verify path
STRICT_VERIFY_POLICY_SERVICE_MARKERS=(
  '"GPM_AUTH_VERIFY_REQUIRE_COMMAND",[[:space:]]*$'
  '"TDPN_AUTH_VERIFY_REQUIRE_COMMAND",[[:space:]]*$'
  '"gpm_auth_verify_require_command":[[:space:]]*s\.gpmAuthVerifyRequireCommand'
  '"gpm_auth_verify_command_configured":[[:space:]]*strings\.TrimSpace\(s\.gpmAuthVerifyCommand\)[[:space:]]*!=[[:space:]]*""'
)
for marker in "${STRICT_VERIFY_POLICY_SERVICE_MARKERS[@]}"; do
  require_localapi_service_marker "$marker" "strict verifier-command policy service wiring"
done
STRICT_VERIFY_POLICY_GPM_MARKERS=(
  'if[[:space:]]+s\.gpmAuthVerifyRequireCommand[[:space:]]+&&[[:space:]]+strings\.TrimSpace\(s\.gpmAuthVerifyCommand\)[[:space:]]*==[[:space:]]*""[[:space:]]*\{'
  'signature verifier command is required by policy'
)
for marker in "${STRICT_VERIFY_POLICY_GPM_MARKERS[@]}"; do
  require_gpm_api_marker "$marker" "strict verifier-command policy fail-closed check"
done
echo "[local-control-api-contract] strict verifier-command policy markers in source are present"

# Strict chain-binding lifecycle unlock checks must remain fail-closed for
# operator sessions (both session/application chain_operator_id must be present
# and matching).
STRICT_CHAIN_BINDING_MARKERS=(
  'func[[:space:]]+gpmStrictOperatorChainBinding\('
  'operator session chain_operator_id is missing'
  'approved operator application chain_operator_id is missing'
  'bound,[[:space:]]*reason[[:space:]]*:=[[:space:]]*gpmStrictOperatorChainBinding'
  'strictChainBound,[[:space:]]*strictChainBindingReason[[:space:]]*=[[:space:]]*gpmStrictOperatorChainBinding'
  'lifecycleActionsUnlocked[[:space:]]*:=[[:space:]]*role[[:space:]]*==[[:space:]]*"admin"[[:space:]]*\|\|'
)
for marker in "${STRICT_CHAIN_BINDING_MARKERS[@]}"; do
  require_gpm_api_marker "$marker" "strict chain-binding lifecycle enforcement"
done
echo "[local-control-api-contract] strict chain-binding lifecycle markers in source are present"

echo "[local-control-api-contract] start local API (update disabled)"
start_local_api 0

echo "[local-control-api-contract] status endpoint forwards client-vpn-status --show-json 1"
status_json="$(api_get "/v1/status")"
if ! jq -e '.ok == true and .status.ok == true' <<<"$status_json" >/dev/null; then
  echo "status endpoint did not return expected payload"
  echo "$status_json"
  exit 1
fi
status_call="$(require_last_call "client-vpn-status")"
assert_line_has "$status_call" $'\t--show-json\t1' "status forwarding missing --show-json 1"

echo "[local-control-api-contract] diagnostics endpoint forwards runtime-doctor --show-json 1"
diag_json="$(api_get "/v1/get_diagnostics")"
if ! jq -e '.ok == true and .diagnostics.ok == true' <<<"$diag_json" >/dev/null; then
  echo "diagnostics endpoint did not return expected payload"
  echo "$diag_json"
  exit 1
fi
diag_call="$(require_last_call "runtime-doctor")"
assert_line_has "$diag_call" $'\t--show-json\t1' "diagnostics forwarding missing --show-json 1"

echo "[local-control-api-contract] config endpoint surfaces manifest resolve policy + refresh interval keys"
config_json="$(api_get "/v1/config")"
if ! jq -e '.ok == true and (.config.gpm_manifest_resolve_policy | type == "string" and length > 0 and test("cache"; "i") and test("refresh"; "i"))' <<<"$config_json" >/dev/null; then
  echo "config endpoint did not expose a valid gpm_manifest_resolve_policy"
  echo "$config_json"
  exit 1
fi
if ! jq -e '.ok == true and (.config.gpm_manifest_cache_max_age_sec | type == "number" and . >= 0)' <<<"$config_json" >/dev/null; then
  echo "config endpoint did not expose a valid gpm_manifest_cache_max_age_sec refresh interval"
  echo "$config_json"
  exit 1
fi
if ! jq -e '.ok == true and (.config.gpm_operator_approval_require_session | type == "boolean")' <<<"$config_json" >/dev/null; then
  echo "config endpoint did not expose gpm_operator_approval_require_session as boolean"
  echo "$config_json"
  exit 1
fi
if ! jq -e '.ok == true and (.config.gpm_operator_approval_require_session_policy_source | type == "string" and length > 0)' <<<"$config_json" >/dev/null; then
  echo "config endpoint did not expose gpm_operator_approval_require_session_policy_source"
  echo "$config_json"
  exit 1
fi

echo "[local-control-api-contract] onboarding overview requires session_token"
overview_missing_body="$TMP_DIR/onboarding_overview_missing_session_token.json"
overview_missing_code="$(curl -sS -o "$overview_missing_body" -w '%{http_code}' -X POST -H "Authorization: Bearer ${LOCAL_API_AUTH_TOKEN}" -H 'Content-Type: application/json' --data '{}' "${LOCAL_API_BASE}/v1/gpm/onboarding/overview")"
if [[ "$overview_missing_code" != "400" ]]; then
  echo "expected /v1/gpm/onboarding/overview to return 400 for missing session_token, got $overview_missing_code"
  cat "$overview_missing_body"
  exit 1
fi
if ! jq -e '.ok == false and (.error | contains("session_token is required"))' "$overview_missing_body" >/dev/null; then
  echo "overview missing-session response payload mismatch"
  cat "$overview_missing_body"
  exit 1
fi

echo "[local-control-api-contract] gpm service start requires session_token (fail-closed)"
gpm_start_missing_body="$TMP_DIR/gpm_service_start_missing_session_token.json"
gpm_start_missing_code="$(curl -sS -o "$gpm_start_missing_body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data '{}' "${LOCAL_API_BASE}/v1/gpm/service/start")"
if [[ "$gpm_start_missing_code" != "401" ]]; then
  echo "expected /v1/gpm/service/start to return 401 for missing session_token, got $gpm_start_missing_code"
  cat "$gpm_start_missing_body"
  exit 1
fi
if ! jq -e '.ok == false and (.error | contains("session token is required"))' "$gpm_start_missing_body" >/dev/null; then
  echo "gpm service start missing-session response payload mismatch"
  cat "$gpm_start_missing_body"
  exit 1
fi

echo "[local-control-api-contract] onboarding overview returns consolidated session + registration + readiness"
overview_wallet_address="$(auth_contract_wallet_address)"
challenge_body="$(jq -cn --arg wallet_address "$overview_wallet_address" '{wallet_address: $wallet_address, wallet_provider: "keplr"}')"
challenge_json="$(api_post_json "/v1/gpm/auth/challenge" "$challenge_body")"
if ! jq -e '.ok == true and (.challenge_id | type == "string" and length > 0) and (.message | type == "string" and length > 0)' <<<"$challenge_json" >/dev/null; then
  echo "auth challenge did not return expected payload"
  echo "$challenge_json"
  exit 1
fi
challenge_id="$(jq -r '.challenge_id // ""' <<<"$challenge_json")"
if [[ -z "$challenge_id" ]]; then
  echo "auth challenge missing challenge_id"
  echo "$challenge_json"
  exit 1
fi
challenge_message="$(jq -r '.message // ""' <<<"$challenge_json")"
if [[ -z "$challenge_message" ]]; then
  echo "auth challenge missing message"
  echo "$challenge_json"
  exit 1
fi
proof_json="$(auth_contract_proof_json "$challenge_message" 1)"
verify_body="$(jq -cn \
  --arg wallet_address "$overview_wallet_address" \
  --arg challenge_id "$challenge_id" \
  --arg signature "$(jq -r '.signature // ""' <<<"$proof_json")" \
  --arg signature_public_key "$(jq -r '.signature_public_key // ""' <<<"$proof_json")" \
  --arg signature_public_key_type "$(jq -r '.signature_public_key_type // "secp256k1"' <<<"$proof_json")" \
  --arg signed_message "$(jq -r '.signed_message // ""' <<<"$proof_json")" \
  '{
    wallet_address: $wallet_address,
    wallet_provider: "keplr",
    challenge_id: $challenge_id,
    signature: $signature,
    signature_public_key: $signature_public_key,
    signature_public_key_type: $signature_public_key_type,
    signed_message: $signed_message
  }')"
verify_json="$(api_post_json "/v1/gpm/auth/verify" "$verify_body")"
if ! jq -e --arg wallet_address "$overview_wallet_address" '.ok == true and .session.wallet_address == $wallet_address and .session.role == "client" and .session.wallet_binding_verified == true and (.session_token | type == "string" and length > 0)' <<<"$verify_json" >/dev/null; then
  echo "auth verify did not return expected session payload"
  echo "$verify_json"
  exit 1
fi
overview_session_token="$(jq -r '.session_token // ""' <<<"$verify_json")"
if [[ -z "$overview_session_token" ]]; then
  echo "auth verify missing session_token"
  echo "$verify_json"
  exit 1
fi

echo "[local-control-api-contract] gpm service start rejects client session role (fail-closed)"
gpm_start_client_body="$TMP_DIR/gpm_service_start_client_forbidden.json"
gpm_start_client_code="$(curl -sS -o "$gpm_start_client_body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data "{\"session_token\":\"${overview_session_token}\"}" "${LOCAL_API_BASE}/v1/gpm/service/start")"
if [[ "$gpm_start_client_code" != "403" ]]; then
  echo "expected /v1/gpm/service/start to return 403 for client session role, got $gpm_start_client_code"
  cat "$gpm_start_client_body"
  exit 1
fi
if ! jq -e '.ok == false and (.error | contains("session role")) and (.error | contains("operator or admin"))' "$gpm_start_client_body" >/dev/null; then
  echo "gpm service start client-role response payload mismatch"
  cat "$gpm_start_client_body"
  exit 1
fi

overview_json="$(api_post_json "/v1/gpm/onboarding/overview" "{\"session_token\":\"${overview_session_token}\"}")"
if ! jq -e --arg wallet_address "$overview_wallet_address" '.ok == true and .session.wallet_address == $wallet_address and .registration.wallet_address == $wallet_address and .registration.status == "not_registered" and .readiness.role == "client" and .readiness.session_present == true and (.readiness.lifecycle_actions_unlocked | type == "boolean")' <<<"$overview_json" >/dev/null; then
  echo "onboarding overview did not return expected consolidated payload"
  echo "$overview_json"
  exit 1
fi
if ! jq -e '.ok == true and .readiness.client_registration_status == "not_registered" and ((.readiness.client_registration_reason // "") == "")' <<<"$overview_json" >/dev/null; then
  echo "onboarding overview missing expected client registration readiness trust fields"
  echo "$overview_json"
  exit 1
fi
if ! jq -e '.ok == true and (.readiness.chain_binding_status == "not_applicable") and (.readiness.chain_binding_ok == false) and ((.readiness.chain_binding_reason // "") == "")' <<<"$overview_json" >/dev/null; then
  echo "onboarding overview missing expected default chain-binding readiness fields"
  echo "$overview_json"
  exit 1
fi

echo "[local-control-api-contract] chain-binding readiness reports bound status after operator approval"
operator_apply_bound_json="$(api_post_json "/v1/gpm/onboarding/operator/apply" "{\"session_token\":\"${overview_session_token}\",\"chain_operator_id\":\"operator-contract-a\",\"server_label\":\"contract-bound\"}")"
if ! jq -e '.ok == true and .application.status == "pending" and .application.chain_operator_id == "operator-contract-a"' <<<"$operator_apply_bound_json" >/dev/null; then
  echo "operator apply (bound setup) did not return expected payload"
  echo "$operator_apply_bound_json"
  exit 1
fi
operator_approve_bound_body="$(jq -cn --arg wallet_address "$overview_wallet_address" --arg admin_token "$LOCAL_API_OPERATOR_ADMIN_TOKEN" '{wallet_address: $wallet_address, approved: true, admin_token: $admin_token}')"
operator_approve_bound_json="$(api_post_json "/v1/gpm/onboarding/operator/approve" "$operator_approve_bound_body")"
if ! jq -e '.ok == true and .decision == "approved" and .decision_auth == "legacy_admin_token" and .application.status == "approved"' <<<"$operator_approve_bound_json" >/dev/null; then
  echo "operator approve (bound setup) did not return expected payload"
  echo "$operator_approve_bound_json"
  exit 1
fi
server_bound_json="$(api_post_json "/v1/gpm/onboarding/server/status" "{\"session_token\":\"${overview_session_token}\"}")"
if ! jq -e '.ok == true and .readiness.role == "operator" and .readiness.operator_application_status == "approved" and .readiness.chain_binding_status == "bound" and .readiness.chain_binding_ok == true and ((.readiness.chain_binding_reason // "") == "")' <<<"$server_bound_json" >/dev/null; then
  echo "server readiness did not report expected bound chain-binding state"
  echo "$server_bound_json"
  exit 1
fi
overview_bound_json="$(api_post_json "/v1/gpm/onboarding/overview" "{\"session_token\":\"${overview_session_token}\"}")"
if ! jq -e '.ok == true and .readiness.chain_binding_status == "bound" and .readiness.chain_binding_ok == true and ((.readiness.chain_binding_reason // "") == "")' <<<"$overview_bound_json" >/dev/null; then
  echo "onboarding overview did not report expected bound chain-binding state"
  echo "$overview_bound_json"
  exit 1
fi

echo "[local-control-api-contract] gpm service start succeeds for approved operator session"
gpm_start_approved_body="$TMP_DIR/gpm_service_start_operator_approved_success.json"
gpm_start_approved_code="$(curl -sS -o "$gpm_start_approved_body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data "{\"session_token\":\"${overview_session_token}\"}" "${LOCAL_API_BASE}/v1/gpm/service/start")"
if [[ "$gpm_start_approved_code" != "200" ]]; then
  echo "expected /v1/gpm/service/start to return 200 for approved operator session, got $gpm_start_approved_code"
  cat "$gpm_start_approved_body"
  exit 1
fi
if ! jq -e '.ok == true and .action == "start"' "$gpm_start_approved_body" >/dev/null; then
  echo "gpm service start did not return expected success payload for approved operator session"
  cat "$gpm_start_approved_body"
  exit 1
fi

echo "[local-control-api-contract] chain-binding readiness reports pending_approval in negative scenario"
operator_apply_pending_json="$(api_post_json "/v1/gpm/onboarding/operator/apply" "{\"session_token\":\"${overview_session_token}\",\"chain_operator_id\":\"operator-contract-b\",\"server_label\":\"contract-pending\"}")"
if ! jq -e '.ok == true and .application.status == "pending" and .application.chain_operator_id == "operator-contract-b"' <<<"$operator_apply_pending_json" >/dev/null; then
  echo "operator apply (negative setup) did not return expected payload"
  echo "$operator_apply_pending_json"
  exit 1
fi
server_pending_json="$(api_post_json "/v1/gpm/onboarding/server/status" "{\"session_token\":\"${overview_session_token}\"}")"
if ! jq -e '.ok == true and .readiness.role == "operator" and .readiness.operator_application_status == "pending" and .readiness.chain_binding_status == "pending_approval" and .readiness.chain_binding_ok == false and (.readiness.chain_binding_reason | type == "string") and (.readiness.chain_binding_reason | contains("pending approval"))' <<<"$server_pending_json" >/dev/null; then
  echo "server readiness did not report expected pending_approval chain-binding state"
  echo "$server_pending_json"
  exit 1
fi
overview_pending_json="$(api_post_json "/v1/gpm/onboarding/overview" "{\"session_token\":\"${overview_session_token}\"}")"
if ! jq -e '.ok == true and .readiness.operator_application_status == "pending" and .readiness.chain_binding_status == "pending_approval" and .readiness.chain_binding_ok == false and (.readiness.chain_binding_reason | contains("pending approval"))' <<<"$overview_pending_json" >/dev/null; then
  echo "onboarding overview did not report expected pending_approval chain-binding state"
  echo "$overview_pending_json"
  exit 1
fi

echo "[local-control-api-contract] gpm service start fails closed for pending operator status"
gpm_start_pending_body="$TMP_DIR/gpm_service_start_pending_forbidden.json"
gpm_start_pending_code="$(curl -sS -o "$gpm_start_pending_body" -w '%{http_code}' -X POST -H 'Content-Type: application/json' --data "{\"session_token\":\"${overview_session_token}\"}" "${LOCAL_API_BASE}/v1/gpm/service/start")"
if [[ "$gpm_start_pending_code" != "403" ]]; then
  echo "expected /v1/gpm/service/start to return 403 for pending operator status, got $gpm_start_pending_code"
  cat "$gpm_start_pending_body"
  exit 1
fi
if ! jq -e '.ok == false and ((.error | contains("not approved")) or (.error | contains("pending")))' "$gpm_start_pending_body" >/dev/null; then
  echo "gpm service start pending-operator response payload mismatch"
  cat "$gpm_start_pending_body"
  exit 1
fi

echo "[local-control-api-contract] set_profile normalizes alias and forwards config-v1-set-profile"
admin_verify_json="$(mint_auth_contract_session_json 2 admin)"
admin_session_token="$(jq -r '.session_token // ""' <<<"$admin_verify_json")"
if [[ -z "$admin_session_token" ]]; then
  echo "admin auth verify missing session_token"
  echo "$admin_verify_json"
  exit 1
fi
set_profile_body="$(jq -cn --arg session_token "$admin_session_token" '{path_profile: "private", session_token: $session_token}')"
set_profile_json="$(api_post_json "/v1/set_profile" "$set_profile_body")"
if ! jq -e '.ok == true and .path_profile == "3hop"' <<<"$set_profile_json" >/dev/null; then
  echo "set_profile endpoint did not normalize to 3hop"
  echo "$set_profile_json"
  exit 1
fi
set_profile_call="$(require_last_call "config-v1-set-profile")"
assert_line_has "$set_profile_call" $'\t--path-profile\t3hop' "set_profile forwarding missing --path-profile 3hop"

echo "[local-control-api-contract] client register seeds session-bound connect secrets"
register_json="$(api_post_json "/v1/gpm/onboarding/client/register" "{\"session_token\":\"${overview_session_token}\",\"bootstrap_directory\":\"http://127.0.0.1:8081\",\"invite_key\":\"inv-contract-2hop\",\"path_profile\":\"2hop\"}")"
if ! jq -e '.ok == true and .profile.bootstrap_directory == "http://127.0.0.1:8081" and .profile.path_profile == "2hop" and .session.bootstrap_directory == "http://127.0.0.1:8081" and .session.path_profile == "2hop"' <<<"$register_json" >/dev/null; then
  echo "client register did not return expected session-bound registration payload"
  echo "$register_json"
  exit 1
fi

echo "[local-control-api-contract] client status reports registered only while trusted bootstrap directories still revalidate"
client_status_registered_json="$(api_post_json "/v1/gpm/onboarding/client/status" "{\"session_token\":\"${overview_session_token}\"}")"
if ! jq -e '.ok == true and .registration.status == "registered" and (.registration.bootstrap_directories | type == "array" and length > 0) and ((.registration.status_reason // "") == "")' <<<"$client_status_registered_json" >/dev/null; then
  echo "client status did not report expected registered trust state"
  echo "$client_status_registered_json"
  exit 1
fi
overview_registered_json="$(api_post_json "/v1/gpm/onboarding/overview" "{\"session_token\":\"${overview_session_token}\"}")"
if ! jq -e '.ok == true and .registration.status == "registered" and .readiness.client_registration_status == "registered" and ((.readiness.client_registration_reason // "") == "")' <<<"$overview_registered_json" >/dev/null; then
  echo "onboarding overview did not mirror expected registered trust state"
  echo "$overview_registered_json"
  exit 1
fi

echo "[local-control-api-contract] trust drift reports not_registered with status_reason"
write_manifest_cache "http://127.0.0.1:18081"
client_status_drift_json="$(api_post_json "/v1/gpm/onboarding/client/status" "{\"session_token\":\"${overview_session_token}\"}")"
if ! jq -e '.ok == true and .registration.status == "not_registered" and (.registration.status_reason | type == "string" and length > 0) and (.registration.bootstrap_directory == "") and (.registration.bootstrap_directories | type == "array" and length == 0)' <<<"$client_status_drift_json" >/dev/null; then
  echo "client status did not report expected trust-drift not_registered state"
  echo "$client_status_drift_json"
  exit 1
fi
overview_drift_json="$(api_post_json "/v1/gpm/onboarding/overview" "{\"session_token\":\"${overview_session_token}\"}")"
if ! jq -e '.ok == true and .registration.status == "not_registered" and (.registration.status_reason | type == "string" and length > 0) and .readiness.client_registration_status == "not_registered" and (.readiness.client_registration_reason | type == "string" and length > 0)' <<<"$overview_drift_json" >/dev/null; then
  echo "onboarding overview did not mirror expected trust-drift not_registered state"
  echo "$overview_drift_json"
  exit 1
fi

echo "[local-control-api-contract] trust revalidation hard failure reports degraded with status_reason"
write_manifest_cache_invalid
client_status_degraded_json="$(api_post_json "/v1/gpm/onboarding/client/status" "{\"session_token\":\"${overview_session_token}\"}")"
if ! jq -e '.ok == true and .registration.status == "degraded" and (.registration.status_reason | type == "string" and length > 0) and (.registration.bootstrap_directory == "") and (.registration.bootstrap_directories | type == "array" and length == 0)' <<<"$client_status_degraded_json" >/dev/null; then
  echo "client status did not report expected trust-failure degraded state"
  echo "$client_status_degraded_json"
  exit 1
fi
overview_degraded_json="$(api_post_json "/v1/gpm/onboarding/overview" "{\"session_token\":\"${overview_session_token}\"}")"
if ! jq -e '.ok == true and .registration.status == "degraded" and (.registration.status_reason | type == "string" and length > 0) and .readiness.client_registration_status == "degraded" and (.readiness.client_registration_reason | type == "string" and length > 0)' <<<"$overview_degraded_json" >/dev/null; then
  echo "onboarding overview did not mirror expected trust-failure degraded state"
  echo "$overview_degraded_json"
  exit 1
fi

echo "[local-control-api-contract] trust recovery restores registered status once bootstrap trust is valid again"
write_manifest_cache "http://127.0.0.1:8081"
client_status_recovered_json="$(api_post_json "/v1/gpm/onboarding/client/status" "{\"session_token\":\"${overview_session_token}\"}")"
if ! jq -e '.ok == true and .registration.status == "registered" and (.registration.bootstrap_directories | type == "array" and length > 0) and ((.registration.status_reason // "") == "")' <<<"$client_status_recovered_json" >/dev/null; then
  echo "client status did not recover to registered after trust restoration"
  echo "$client_status_recovered_json"
  exit 1
fi

echo "[local-control-api-contract] connect (2hop) forwards preflight + up contract flags"
connect_2hop_json="$(api_post_json "/v1/connect" "{\"session_token\":\"${overview_session_token}\",\"path_profile\":\"2hop\",\"interface\":\"wgvpn0\",\"discovery_wait_sec\":17,\"ready_timeout_sec\":40}")"
if ! jq -e '.ok == true and .stage == "connect" and .profile == "2hop"' <<<"$connect_2hop_json" >/dev/null; then
  echo "connect 2hop endpoint did not return expected payload"
  echo "$connect_2hop_json"
  exit 1
fi
preflight_2hop_call="$(require_last_call "client-vpn-preflight")"
assert_line_has "$preflight_2hop_call" $'\t--bootstrap-directory\thttp://127.0.0.1:8081' "connect preflight missing bootstrap directory"
assert_line_has "$preflight_2hop_call" $'\t--discovery-wait-sec\t17' "connect preflight missing discovery wait"
assert_line_has "$preflight_2hop_call" $'\t--operator-floor-check\t1' "connect preflight missing operator floor check default"
assert_line_has "$preflight_2hop_call" $'\t--issuer-quorum-check\t1' "connect preflight missing issuer quorum check default"
up_2hop_call="$(require_last_call "client-vpn-up")"
if ! printf '%s\n' "$up_2hop_call" | grep -F -- $'\t--subject\tinv-contract-2hop' >/dev/null 2>&1 && \
   ! printf '%s\n' "$up_2hop_call" | grep -F -- $'\t--subject-file\t' >/dev/null 2>&1; then
  echo "connect up missing invite subject forwarding (--subject or --subject-file)"
  echo "line: $up_2hop_call"
  echo "calls:"
  cat "$CALLS_FILE"
  exit 1
fi
assert_line_has "$up_2hop_call" $'\t--path-profile\t2hop' "connect up missing --path-profile 2hop"
assert_line_has "$up_2hop_call" $'\t--session-reuse\t1' "connect up missing deterministic --session-reuse 1"
assert_line_has "$up_2hop_call" $'\t--allow-session-churn\t0' "connect up missing deterministic --allow-session-churn 0"
assert_line_has "$up_2hop_call" $'\t--min-operators\t2' "connect up missing 2hop min operators"
assert_line_has "$up_2hop_call" $'\t--operator-floor-check\t1' "connect up missing 2hop operator floor check"
assert_line_has "$up_2hop_call" $'\t--issuer-quorum-check\t1' "connect up missing 2hop issuer quorum check"
assert_line_has "$up_2hop_call" $'\t--force-restart\t1' "connect up missing force restart"
assert_line_has "$up_2hop_call" $'\t--foreground\t0' "connect up missing detached foreground flag"

echo "[local-control-api-contract] client register accepts speed-1hop alias before 1hop connect"
register_1hop_json="$(api_post_json "/v1/gpm/onboarding/client/register" "{\"session_token\":\"${overview_session_token}\",\"bootstrap_directory\":\"http://127.0.0.1:8081\",\"invite_key\":\"inv-contract-1hop\",\"path_profile\":\"speed-1hop\"}")"
if ! jq -e '.ok == true and .profile.path_profile == "1hop" and .session.path_profile == "1hop"' <<<"$register_1hop_json" >/dev/null; then
  echo "client register speed-1hop alias did not normalize to 1hop"
  echo "$register_1hop_json"
  exit 1
fi

echo "[local-control-api-contract] connect (1hop speed-1hop alias) applies direct-exit defaults and can skip preflight"
connect_1hop_json="$(api_post_json "/v1/connect" "{\"session_token\":\"${overview_session_token}\",\"run_preflight\":false}")"
if ! jq -e '.ok == true and .profile == "1hop"' <<<"$connect_1hop_json" >/dev/null; then
  echo "connect 1hop endpoint did not return expected profile"
  echo "$connect_1hop_json"
  exit 1
fi
up_1hop_call="$(require_last_call "client-vpn-up")"
assert_line_has "$up_1hop_call" $'\t--path-profile\t1hop' "connect 1hop missing normalized --path-profile 1hop"
assert_line_has "$up_1hop_call" $'\t--session-reuse\t1' "connect 1hop missing deterministic --session-reuse 1"
assert_line_has "$up_1hop_call" $'\t--allow-session-churn\t0' "connect 1hop missing deterministic --allow-session-churn 0"
assert_line_has "$up_1hop_call" $'\t--min-operators\t1' "connect 1hop missing min-operators 1"
assert_line_has "$up_1hop_call" $'\t--operator-floor-check\t0' "connect 1hop missing operator floor disable"
assert_line_has "$up_1hop_call" $'\t--issuer-quorum-check\t0' "connect 1hop missing issuer quorum disable"
assert_line_has "$up_1hop_call" $'\t--beta-profile\t0' "connect 1hop missing beta-profile 0"
assert_line_has "$up_1hop_call" $'\t--prod-profile\t0' "connect 1hop missing prod-profile 0"
assert_line_has "$up_1hop_call" $'\t--install-route\t0' "connect 1hop missing default install-route 0"

echo "[local-control-api-contract] disconnect endpoint forwards safe public client-vpn-down cleanup"
disconnect_json="$(api_post_json "/v1/disconnect" '{}')"
if ! jq -e '.ok == true and .stage == "disconnect"' <<<"$disconnect_json" >/dev/null; then
  echo "disconnect endpoint did not return expected payload"
  echo "$disconnect_json"
  exit 1
fi
disconnect_call="$(require_last_call "client-vpn-down")"
assert_line_has "$disconnect_call" $'\t--force-iface-cleanup\t0' "disconnect forwarding missing safe --force-iface-cleanup 0"

echo "[local-control-api-contract] update endpoint is fail-closed by default"
: >"$CALLS_FILE"
update_disabled_body="$TMP_DIR/update_disabled.json"
update_disabled_code="$(curl -sS -o "$update_disabled_body" -w '%{http_code}' -X POST -H "Authorization: Bearer ${LOCAL_API_AUTH_TOKEN}" -H 'Content-Type: application/json' --data '{"remote":"origin","branch":"main","allow_dirty":true}' "${LOCAL_API_BASE}/v1/update")"
if [[ "$update_disabled_code" != "403" ]]; then
  echo "expected /v1/update to return 403 when LOCAL_CONTROL_API_ALLOW_UPDATE=0, got $update_disabled_code"
  cat "$update_disabled_body"
  exit 1
fi
if ! jq -e '.ok == false and (.error | contains("update endpoint disabled"))' "$update_disabled_body" >/dev/null; then
  echo "update disabled response payload mismatch"
  cat "$update_disabled_body"
  exit 1
fi
if grep -q '^self-update' "$CALLS_FILE"; then
  echo "update disabled path unexpectedly executed self-update command"
  cat "$CALLS_FILE"
  exit 1
fi

stop_local_api

echo "[local-control-api-contract] strict operator approval policy disables legacy admin token fallback"
start_local_api 0 1
strict_config_json="$(api_get "/v1/config")"
if ! jq -e '.ok == true and .config.gpm_operator_approval_require_session == true and (.config.gpm_operator_approval_require_session_policy_source | type == "string" and length > 0)' <<<"$strict_config_json" >/dev/null; then
  echo "strict policy config did not expose expected operator approval policy fields"
  echo "$strict_config_json"
  exit 1
fi
strict_approve_body="$TMP_DIR/operator_approve_strict_requires_session.json"
strict_approve_code="$(curl -sS -o "$strict_approve_body" -w '%{http_code}' -X POST -H "Authorization: Bearer ${LOCAL_API_AUTH_TOKEN}" -H 'Content-Type: application/json' --data "{\"wallet_address\":\"cosmos1strictpolicy\",\"approved\":true,\"admin_token\":\"${LOCAL_API_OPERATOR_ADMIN_TOKEN}\"}" "${LOCAL_API_BASE}/v1/gpm/onboarding/operator/approve")"
if [[ "$strict_approve_code" != "401" ]]; then
  echo "expected strict operator approval policy to return 401 for admin_token fallback, got $strict_approve_code"
  cat "$strict_approve_body"
  exit 1
fi
if ! jq -e '.ok == false and (.error | contains("required by operator approval policy")) and (.error | contains("legacy admin_token fallback is disabled"))' "$strict_approve_body" >/dev/null; then
  echo "strict operator approval policy response payload mismatch"
  cat "$strict_approve_body"
  exit 1
fi

stop_local_api

echo "[local-control-api-contract] start local API (update enabled)"
start_local_api 1

echo "[local-control-api-contract] update endpoint forwards self-update command form"
admin_update_verify_json="$(mint_auth_contract_session_json 2 admin)"
admin_update_session_token="$(jq -r '.session_token // ""' <<<"$admin_update_verify_json")"
if [[ -z "$admin_update_session_token" ]]; then
  echo "admin auth verify for update missing session_token"
  echo "$admin_update_verify_json"
  exit 1
fi
update_enabled_body="$(jq -cn --arg session_token "$admin_update_session_token" '{remote: "origin", branch: "main", allow_dirty: true, session_token: $session_token}')"
update_enabled_json="$(api_post_json "/v1/update" "$update_enabled_body")"
if ! jq -e '.ok == true' <<<"$update_enabled_json" >/dev/null; then
  echo "update enabled endpoint did not return success"
  echo "$update_enabled_json"
  exit 1
fi
update_call="$(require_last_call "self-update")"
assert_line_has "$update_call" $'\t--show-status\t1' "update forwarding missing --show-status 1"
assert_line_has "$update_call" $'\t--remote\torigin' "update forwarding missing --remote origin"
assert_line_has "$update_call" $'\t--branch\tmain' "update forwarding missing --branch main"
assert_line_has "$update_call" $'\t--allow-dirty\t1' "update forwarding missing --allow-dirty 1"

stop_local_api

echo "local control API contract integration check ok"
